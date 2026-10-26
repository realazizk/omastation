//! Tile-parallel helper for the CPU codecs: `forEach` runs independent items over a process-wide
//! pool of worker threads (a `std.Io.Threaded`) plus the calling thread. Tiles are independent, so
//! RemoteFX and Progressive frames split by tile; the caller then writes the results in tile order,
//! so the output does not depend on the thread count.

const std = @import("std");

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
    max_tasks_override = @max(n, 1);
}

pub fn maxTasks() usize {
    if (max_tasks_override) |n| return n;
    const cpus = std.Thread.getCpuCount() catch 1;
    return std.math.clamp(cpus, 1, max_tasks_cap);
}

/// Runs `func(ctx, task, item)` for every item in 0..n, items handed out one at a time to
/// `tasks` tasks (the caller is task 0; `task` < maxTasks()). Returns when all items are done.
/// `func` must be safe to run concurrently for different items; per-task scratch goes by `task`.
pub fn forEach(n: usize, ctx: anytype, comptime func: fn (@TypeOf(ctx), usize, usize) void) void {
    const Ctx = @TypeOf(ctx);
    const Shared = struct {
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
    };
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
