//! Connection-sequence timeout (MS-RDPBCGR 3.3.6.1): a connection still in the
//! connection sequence after 60 s has its socket shut down. The clock starts on
//! accept, restarts at the Connection Confirm (3.3.5.3.1) and stops at the Font Map.

const std = @import("std");
const c = @import("c");

const log = std.log.scoped(.deadline);

pub const timeout_ms: i64 = 60_000;
/// Reaper period: slack on top of the 60 s.
const tick_ms = 250;

/// A connection's table slot; `.{}` when no clock runs. `gen` tells its entry from
/// a later connection's in the same slot once the reaper freed it.
pub const Handle = struct { slot: ?usize = null, gen: u64 = 0 };

/// A full table only means the newest connections run without a deadline.
const max_entries = 1024;
const Entry = struct { fd: c_int, start_ms: i64, gen: u64 };

var entries: [max_entries]?Entry = @splat(null);
var next_gen: u64 = 1;
var mutex: std.atomic.Mutex = .unlocked;
var reaper_running = std.atomic.Value(bool).init(false);

fn lock() void {
    while (!mutex.tryLock()) std.Thread.yield() catch {};
}

fn unlock() void {
    mutex.unlock();
}

pub fn start(fd: c_int, now_ms: i64) Handle {
    ensureReaper();
    lock();
    defer unlock();
    for (&entries, 0..) |*e, i| {
        if (e.* == null) {
            const gen = next_gen;
            next_gen += 1;
            e.* = .{ .fd = fd, .start_ms = now_ms, .gen = gen };
            return .{ .slot = i, .gen = gen };
        }
    }
    log.warn("{d} connections in their connection sequence: no deadline for fd {d}", .{ max_entries, fd });
    return .{};
}

/// Restart the clock (Connection Confirm sent, 3.3.5.3.1).
pub fn restart(h: Handle, now_ms: i64) void {
    const i = h.slot orelse return;
    lock();
    defer unlock();
    const e = mine(h, i) orelse return; // reaped
    e.start_ms = now_ms;
}

/// Must run before the socket is closed, so the reaper never shuts down a reused fd.
pub fn stop(h: *Handle) void {
    const i = h.slot orelse return;
    h.slot = null;
    lock();
    defer unlock();
    if (mine(h.*, i) != null) entries[i] = null;
}

/// The handle's entry in slot `i`, unless the reaper freed it (lock held).
fn mine(h: Handle, i: usize) ?*Entry {
    if (entries[i]) |*e| {
        if (e.gen == h.gen) return e;
    }
    return null;
}

/// Shut down every connection past its deadline; returns how many.
pub fn reap(now_ms: i64) usize {
    lock();
    defer unlock();
    var n: usize = 0;
    for (&entries) |*slot| {
        const e = slot.* orelse continue;
        if (now_ms - e.start_ms <= timeout_ms) continue; // "more than" 60 s
        log.info("fd {d}: connection sequence not finished after {d} s, closing it", .{ e.fd, @divTrunc(now_ms - e.start_ms, 1000) });
        _ = c.shutdown(e.fd, c.SHUT_RDWR);
        slot.* = null;
        n += 1;
    }
    return n;
}

fn ensureReaper() void {
    if (reaper_running.swap(true, .acq_rel)) return;
    const th = std.Thread.spawn(.{}, reaperLoop, .{}) catch |err| {
        log.err("cannot start the connection deadline thread: {t}", .{err});
        reaper_running.store(false, .release);
        return;
    };
    th.detach();
}

fn reaperLoop() void {
    const ts: c.struct_timespec = .{ .tv_sec = 0, .tv_nsec = tick_ms * std.time.ns_per_ms };
    while (true) {
        _ = c.nanosleep(&ts, null);
        _ = reap(nowMs());
    }
}

pub fn nowMs() i64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(i64, ts.tv_sec) * 1000 + @divTrunc(@as(i64, ts.tv_nsec), 1_000_000);
}

test "a connection is reaped only after more than 60 s, and never once stopped" {
    var fds: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), c.socketpair(c.AF_UNIX, c.SOCK_STREAM | c.SOCK_CLOEXEC, 0, &fds));
    defer _ = c.close(fds[0]);
    defer _ = c.close(fds[1]);

    // Times far from the real clock so the background reaper leaves these alone.
    const t0: i64 = std.math.maxInt(i64) / 2;
    var h = start(fds[0], t0);
    try std.testing.expect(h.slot != null);
    try std.testing.expectEqual(@as(usize, 0), reap(t0 + timeout_ms)); // exactly 60 s: not yet
    restart(h, t0 + 1000); // Connection Confirm sent
    try std.testing.expectEqual(@as(usize, 0), reap(t0 + 1000 + timeout_ms));
    try std.testing.expectEqual(@as(usize, 1), reap(t0 + 1001 + timeout_ms));
    var b: [1]u8 = undefined;
    try std.testing.expectEqual(@as(isize, 0), c.read(fds[1], &b, 1));
    stop(&h); // after being reaped: harmless
    try std.testing.expect(h.slot == null);

    var h2 = start(fds[1], t0);
    stop(&h2); // finished in time
    try std.testing.expectEqual(@as(usize, 0), reap(t0 + 10 * timeout_ms));
}

test "late restart or stop on a reaped handle keeps the next connection's deadline" {
    // Far from the real clock, and from the other test's times.
    const t0: i64 = std.math.maxInt(i64) / 4;
    const late = t0 + timeout_ms + 1;
    for ([_]bool{ false, true }) |by_stop| {
        var fds: [4]c_int = undefined;
        try std.testing.expectEqual(@as(c_int, 0), c.socketpair(c.AF_UNIX, c.SOCK_STREAM | c.SOCK_CLOEXEC, 0, fds[0..2]));
        try std.testing.expectEqual(@as(c_int, 0), c.socketpair(c.AF_UNIX, c.SOCK_STREAM | c.SOCK_CLOEXEC, 0, fds[2..4]));
        defer for (fds) |fd| {
            _ = c.close(fd);
        };
        // The reaped connection's thread still holds its handle when a new connection gets the slot.
        var old = start(fds[0], t0);
        _ = reap(late);
        try std.testing.expect(shutDown(fds[1]));
        var new = start(fds[2], t0);
        try std.testing.expectEqual(old.slot, new.slot);
        if (by_stop) stop(&old) else restart(old, t0 + 10 * timeout_ms); // stop: Conn.deinit
        _ = reap(late);
        try std.testing.expect(shutDown(fds[3])); // new's clock ran on
        stop(&new);
        stop(&old);
    }
}

/// The socket's peer was shut down (end of stream), without waiting.
fn shutDown(peer: c_int) bool {
    var pfd: c.struct_pollfd = .{ .fd = peer, .events = c.POLLIN, .revents = 0 };
    if (c.poll(&pfd, 1, 0) != 1) return false;
    var b: [1]u8 = undefined;
    return c.read(peer, &b, 1) == 0;
}
