//! Tile-parallel helper for the CPU codecs: `forEach` runs independent items over a process-wide
//! pool of worker threads (a `std.Io.Threaded`) plus the calling thread. Tiles are independent, so
//! RemoteFX and Progressive frames split by tile; the caller then writes the results in tile order,
//! so the output does not depend on the thread count.
//!
//! Loops that stream memory with little arithmetic per byte (the screen diff) use
//! `forEachStreaming` instead: a few dedicated helpers on the fast cores. Such a loop is bound by
//! memory bandwidth, so past a few threads more of them only stall on DRAM, each stalled cycle
//! counted as CPU time, and on a hybrid CPU the efficiency cores stream far less per cycle.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

/// Tasks per `forEach` including the caller: the logical CPUs, at most `max_tasks_cap`.
pub const max_tasks_cap: usize = 16;

var max_tasks_override: ?usize = null;
var threaded: std.Io.Threaded = undefined;
/// 0 not started, 1 starting, 2 ready.
var state = std.atomic.Value(u8).init(0);

/// Starts the pool once; later callers wait for it (microseconds).
fn start() void {
    if (state.cmpxchgStrong(0, 1, .acquire, .acquire)) |seen| {
        while (seen != 2 and state.load(.acquire) != 2) std.Thread.yield() catch {};
        return;
    }
    threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{ .concurrent_limit = .limited(maxTasks() - 1) });
    state.store(2, .release);
}

/// Caps the tasks per `forEach` (1: everything on the calling thread). Takes effect for pools
/// not started yet; tests and `zig build bench -- --threads N` call it first.
pub fn setMaxTasks(n: usize) void {
    max_tasks_override = std.math.clamp(n, 1, max_tasks_cap);
}

pub fn maxTasks() usize {
    if (max_tasks_override) |n| return n;
    const cpus = std.Thread.getCpuCount() catch 1;
    return std.math.clamp(cpus, 1, max_tasks_cap);
}

/// Items 0..n handed out one at a time to whichever task asks next.
fn Loop(comptime Ctx: type, comptime func: fn (Ctx, usize, usize) void) type {
    return struct {
        next: std.atomic.Value(usize),
        n: usize,
        ctx: Ctx,

        fn run(s: *@This(), task: usize) void {
            while (true) {
                const i = s.next.fetchAdd(1, .monotonic);
                if (i >= s.n) return;
                func(s.ctx, task, i);
            }
        }

        fn runErased(p: *anyopaque, task: usize) void {
            run(@ptrCast(@alignCast(p)), task);
        }
    };
}

/// Runs `func(ctx, task, item)` for every item in 0..n, items handed out one at a time to
/// `tasks` tasks (the caller is task 0; `task` < maxTasks()). Returns when all items are done.
/// `func` must be safe to run concurrently for different items; per-task scratch goes by `task`.
pub fn forEach(n: usize, ctx: anytype, comptime func: fn (@TypeOf(ctx), usize, usize) void) void {
    const Shared = Loop(@TypeOf(ctx), func);
    var shared: Shared = .{ .next = .init(0), .n = n, .ctx = ctx };
    const tasks = @min(maxTasks(), n);
    if (tasks <= 1) return shared.run(0);
    start();
    const io = threaded.io();
    var group: std.Io.Group = .init;
    var spawned: usize = 1;
    while (spawned < tasks) : (spawned += 1) {
        group.concurrent(io, Shared.run, .{ &shared, spawned }) catch break;
    }
    shared.run(0);
    // Every task has run once await returns, canceled or not.
    group.await(io) catch {};
}

/// Helpers of `forEachStreaming` besides the caller: four tasks take most of what more could
/// gain on a memory-bound loop.
pub const streaming_helpers: usize = 3;

/// `forEach` for a memory-bound loop: the caller and up to `streaming_helpers` dedicated threads,
/// kept on the performance cores of a hybrid CPU. While another caller's loop has the helpers,
/// this one runs on the caller alone rather than wait. As `forEach`, except that `task` is the
/// helper's fixed number, up to `streaming_helpers`, whatever `maxTasks()` is.
pub fn forEachStreaming(n: usize, ctx: anytype, comptime func: fn (@TypeOf(ctx), usize, usize) void) void {
    const Shared = Loop(@TypeOf(ctx), func);
    var shared: Shared = .{ .next = .init(0), .n = n, .ctx = ctx };
    const tasks = @min(maxTasks(), n, streaming_helpers + 1);
    if (tasks <= 1 or !streaming.ready()) return shared.run(0);
    if (streaming.busy.cmpxchgStrong(false, true, .acquire, .monotonic) != null) return shared.run(0);
    defer streaming.busy.store(false, .release);
    streaming.post(&shared, Shared.runErased, tasks - 1);
    shared.run(0);
    streaming.finish();
}

/// The dedicated helpers: one job at a time (`busy`), announced by bumping `epoch`. A helper that
/// wakes joins the job by counting itself in `joined` unless the caller has closed it, so a
/// helper that wakes late never touches a job that has returned.
const Streaming = struct {
    /// 0 not started, 1 starting, 2 ready, 3 unavailable (no helper could start).
    state: std.atomic.Value(u8) = .init(0),
    busy: std.atomic.Value(bool) = .init(false),
    helpers: usize = 0,
    /// Bumped (release) per job, after the fields below are set; idle helpers wait on it.
    epoch: std.atomic.Value(u32) = .init(0),
    run_fn: *const fn (*anyopaque, usize) void = undefined,
    run_ctx: *anyopaque = undefined,
    /// Helpers wanted for the current job (read by helpers after `joined`, which orders it).
    wanted: std.atomic.Value(u32) = .init(0),
    /// Helpers in the current job, `closed` set once the caller takes no more.
    joined: std.atomic.Value(u32) = .init(0),
    /// Helpers done with the current job.
    done: std.atomic.Value(u32) = .init(0),

    const closed: u32 = 1 << 31;

    fn ready(s: *Streaming) bool {
        switch (s.state.load(.acquire)) {
            2 => return true,
            3 => return false,
            else => {},
        }
        if (s.state.cmpxchgStrong(0, 1, .acquire, .acquire)) |seen| {
            var st = seen;
            while (st == 1) : (st = s.state.load(.acquire)) std.Thread.yield() catch {};
            return st == 2;
        }
        const fast = fastCores();
        var started: usize = 0;
        while (started < streaming_helpers) : (started += 1) {
            const t = std.Thread.spawn(.{}, helper, .{ s, started + 1, fast }) catch break;
            t.detach();
        }
        s.helpers = started;
        s.state.store(if (started > 0) 2 else 3, .release);
        return started > 0;
    }

    fn post(s: *Streaming, ctx: *anyopaque, run_fn: *const fn (*anyopaque, usize) void, wanted: usize) void {
        s.run_fn = run_fn;
        s.run_ctx = ctx;
        s.wanted.store(@intCast(@min(wanted, s.helpers)), .monotonic);
        s.done.store(0, .monotonic);
        s.joined.store(0, .release);
        _ = s.epoch.fetchAdd(1, .release);
        _ = linux.futex_3arg(&s.epoch.raw, .{ .cmd = .WAKE, .private = true }, s.wanted.raw);
    }

    /// Closes the job to helpers not in it yet and waits for those in it.
    fn finish(s: *Streaming) void {
        const in_job = s.joined.fetchOr(closed, .acq_rel) & ~closed;
        while (true) {
            const d = s.done.load(.acquire);
            if (d >= in_job) return;
            _ = linux.futex_4arg(&s.done.raw, .{ .cmd = .WAIT, .private = true }, d, null);
        }
    }

    fn helper(s: *Streaming, task: usize, fast: ?linux.cpu_set_t) void {
        if (fast) |set| linux.sched_setaffinity(0, &set) catch {};
        var seen = s.epoch.load(.acquire);
        while (true) {
            while (s.epoch.load(.acquire) == seen) {
                _ = linux.futex_4arg(&s.epoch.raw, .{ .cmd = .WAIT, .private = true }, seen, null);
            }
            seen = s.epoch.load(.acquire);
            if (!s.join()) continue;
            s.run_fn(s.run_ctx, task);
            _ = s.done.fetchAdd(1, .release);
            _ = linux.futex_3arg(&s.done.raw, .{ .cmd = .WAKE, .private = true }, 1);
        }
    }

    /// Counts the helper into the current job; false once it is closed or has its helpers.
    fn join(s: *Streaming) bool {
        var j = s.joined.load(.acquire);
        while (true) {
            if (j & closed != 0 or j >= s.wanted.load(.monotonic)) return false;
            j = s.joined.cmpxchgWeak(j, j + 1, .acq_rel, .acquire) orelse return true;
        }
    }
};

var streaming: Streaming = .{};

/// The performance cores of an Intel hybrid CPU this process may run on (sysfs `cpu_core`), or
/// null: no hybrid CPU, or nothing to choose.
fn fastCores() ?linux.cpu_set_t {
    if (builtin.os.tag != .linux) return null;
    var core: linux.cpu_set_t = @splat(0);
    var atom: linux.cpu_set_t = @splat(0);
    if (!readCpuList("/sys/devices/cpu_core/cpus", &core) or !readCpuList("/sys/devices/cpu_atom/cpus", &atom)) return null;
    var allowed: linux.cpu_set_t = @splat(0);
    if (linux.sched_getaffinity(0, @sizeOf(linux.cpu_set_t), &allowed) != 0) allowed = @splat(~@as(usize, 0));
    var any = false;
    for (&core, allowed) |*c, a| {
        c.* &= a;
        if (c.* != 0) any = true;
    }
    return if (any) core else null;
}

fn readCpuList(path: [*:0]const u8, set: *linux.cpu_set_t) bool {
    const f = std.c.fopen(path, "r") orelse return false;
    defer _ = std.c.fclose(f);
    var buf: [256]u8 = undefined;
    const n = std.c.fread(&buf, 1, buf.len, f);
    return parseCpuList(buf[0..n], set);
}

/// "0-7,12,14-15" into `set`; false if malformed or empty.
fn parseCpuList(text: []const u8, set: *linux.cpu_set_t) bool {
    const bits = @bitSizeOf(usize);
    var any = false;
    var it = std.mem.tokenizeAny(u8, text, ",\n ");
    while (it.next()) |part| {
        const dash = std.mem.indexOfScalar(u8, part, '-');
        const lo = std.fmt.parseInt(usize, if (dash) |d| part[0..d] else part, 10) catch return false;
        const hi = if (dash) |d| std.fmt.parseInt(usize, part[d + 1 ..], 10) catch return false else lo;
        if (hi < lo or hi >= set.len * bits) return false;
        for (lo..hi + 1) |cpu| set[cpu / bits] |= @as(usize, 1) << @intCast(cpu % bits);
        any = true;
    }
    return any;
}

test "forEach visits every item exactly once, on any task count" {
    for ([_]usize{ 1, 2, 7 }) |tasks| {
        setMaxTasks(tasks);
        defer max_tasks_override = null;
        var hits: [1000]std.atomic.Value(u8) = undefined;
        for (&hits) |*h| h.* = .init(0);
        const Ctx = struct {
            hits: []std.atomic.Value(u8),
            fn f(c: @This(), task: usize, i: usize) void {
                std.debug.assert(task < 7);
                _ = c.hits[i].fetchAdd(1, .monotonic);
            }
        };
        forEach(hits.len, Ctx{ .hits = &hits }, Ctx.f);
        for (hits) |h| try std.testing.expectEqual(@as(u8, 1), h.load(.monotonic));
    }
    forEach(0, @as(u8, 0), struct {
        fn f(_: u8, _: usize, _: usize) void {
            unreachable;
        }
    }.f);
}

test "forEachStreaming visits every item exactly once, from concurrent callers" {
    const Ctx = struct {
        hits: []std.atomic.Value(u8),
        fn f(c: @This(), task: usize, i: usize) void {
            std.debug.assert(task <= streaming_helpers);
            _ = c.hits[i].fetchAdd(1, .monotonic);
        }
    };
    const Caller = struct {
        fn run(rounds: usize) void {
            var hits: [300]std.atomic.Value(u8) = undefined;
            for (0..rounds) |r| {
                for (&hits) |*h| h.* = .init(0);
                const n = 1 + (r * 37) % hits.len;
                forEachStreaming(n, Ctx{ .hits = &hits }, Ctx.f);
                for (hits[0..n]) |h| std.debug.assert(h.load(.monotonic) == 1);
                for (hits[n..]) |h| std.debug.assert(h.load(.monotonic) == 0);
            }
        }
    };
    // Several threads at once: one has the helpers, the others run alone; none waits or loses items.
    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Caller.run, .{2000});
    for (threads) |t| t.join();
    Caller.run(10);
    forEachStreaming(0, @as(u8, 0), struct {
        fn f(_: u8, _: usize, _: usize) void {
            unreachable;
        }
    }.f);
}

test "CPU lists from sysfs" {
    var set: linux.cpu_set_t = @splat(0);
    try std.testing.expect(parseCpuList("0-7\n", &set));
    try std.testing.expectEqual(@as(usize, 0xFF), set[0]);
    set = @splat(0);
    try std.testing.expect(parseCpuList("1,3,8-9,70", &set));
    try std.testing.expectEqual(@as(usize, 0b11_0000_1010), set[0]);
    try std.testing.expectEqual(@as(usize, 1) << 6, set[1]);
    set = @splat(0);
    try std.testing.expect(!parseCpuList("", &set));
    try std.testing.expect(!parseCpuList("3-1", &set));
    try std.testing.expect(!parseCpuList("x", &set));
    try std.testing.expect(!parseCpuList("99999", &set));
}
