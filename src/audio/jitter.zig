//! Arrival jitter of a real-time stream: each packet's lateness against the schedule
//! its audio implies, above the recent minimum. The windowed maximum approximates the
//! buffer needed; a pause longer than `reset_ms` starts a new schedule.

const std = @import("std");

/// Min and max of values over the last `buckets * bucket_ms`.
pub const Window = struct {
    pub const buckets = 30;

    bucket_ms: u64,
    /// Start (ms) of the bucket each slot holds; null: empty.
    start: [buckets]?u64 = @splat(null),
    min: [buckets]i64 = @splat(0),
    max: [buckets]i64 = @splat(0),

    pub fn init(window_ms: u64) Window {
        return .{ .bucket_ms = @max(1, window_ms / buckets) };
    }

    pub fn clear(w: *Window) void {
        w.start = @splat(null);
    }

    pub fn add(w: *Window, now_ms: u64, v: i64) void {
        const b = now_ms / w.bucket_ms;
        const slot: usize = @intCast(b % buckets);
        const s = b * w.bucket_ms;
        if (w.start[slot] != s) {
            w.start[slot] = s;
            w.min[slot] = v;
            w.max[slot] = v;
            return;
        }
        w.min[slot] = @min(w.min[slot], v);
        w.max[slot] = @max(w.max[slot], v);
    }

    /// Max minus min over the window ending at `now_ms`; null when empty.
    pub fn spread(w: *const Window, now_ms: u64) ?u64 {
        const lo = w.min_(now_ms) orelse return null;
        return @intCast(w.max_(now_ms).? - lo);
    }

    pub fn min_(w: *const Window, now_ms: u64) ?i64 {
        var lo: ?i64 = null;
        for (w.start, w.min) |s, mn| {
            const st = s orelse continue;
            if (st + w.bucket_ms * buckets <= now_ms) continue; // aged out
            lo = if (lo) |l| @min(l, mn) else mn;
        }
        return lo;
    }

    pub fn max_(w: *const Window, now_ms: u64) ?i64 {
        var hi: ?i64 = null;
        for (w.start, w.max) |s, mx| {
            const st = s orelse continue;
            if (st + w.bucket_ms * buckets <= now_ms) continue;
            hi = if (hi) |h| @max(h, mx) else mx;
        }
        return hi;
    }
};

/// Excess of each value over the minimum of the last `recent_ms`, largest over the
/// window; a slow drift of the norm is not jitter.
pub const Jitter = struct {
    pub const recent_ms = 2000;

    recent: Window,
    window: Window,

    pub fn init(window_ms: u64) Jitter {
        return .{ .recent = Window.init(recent_ms), .window = Window.init(window_ms) };
    }

    pub fn add(j: *Jitter, now_ms: u64, v: i64) void {
        j.recent.add(now_ms, v);
        j.window.add(now_ms, v - j.recent.min_(now_ms).?);
    }

    pub fn maxMs(j: *const Jitter, now_ms: u64) u64 {
        return @intCast(@max(0, j.window.max_(now_ms) orelse 0));
    }

    pub fn clear(j: *Jitter) void {
        j.recent.clear();
        j.window.clear();
    }
};

pub const Lateness = struct {
    rate: u32,
    reset_ms: u64,
    /// When frame 0 was due (us).
    anchor_us: ?u64 = null,
    frames: u64 = 0,
    /// Arrival of the last packet (us), for pauses.
    last_us: u64 = 0,
    jitter: Jitter,

    pub fn init(rate: u32, window_ms: u64, reset_ms: u64) Lateness {
        return .{ .rate = @max(1, rate), .reset_ms = reset_ms, .jitter = Jitter.init(window_ms) };
    }

    pub fn add(l: *Lateness, now_us: u64, frames: u64) void {
        if (l.anchor_us == null or now_us -| l.last_us > l.reset_ms * 1000) {
            l.anchor_us = now_us;
            l.frames = 0;
        }
        l.last_us = now_us;
        const due = l.anchor_us.? + l.frames * 1_000_000 / l.rate;
        const late: i64 = @divFloor(@as(i64, @intCast(now_us)) - @as(i64, @intCast(due)), 1000);
        l.jitter.add(now_us / 1000, late);
        l.frames += frames;
    }

    /// Largest jitter (ms) over the window; 0 before any packet.
    pub fn spreadMs(l: *const Lateness, now_ms: u64) u64 {
        return l.jitter.maxMs(now_ms);
    }

    pub fn reset(l: *Lateness) void {
        l.anchor_us = null;
        l.frames = 0;
        l.jitter.clear();
    }
};

const testing = std.testing;

test "window: spread of what was added in the window, then it ages out" {
    var w = Window.init(3000); // 30 buckets of 100 ms
    try testing.expectEqual(@as(?u64, null), w.spread(0));
    w.add(1000, 5);
    w.add(1050, -3);
    w.add(1500, 20);
    try testing.expectEqual(@as(?u64, 23), w.spread(1500));
    // At 4050 the 1000 bucket (1000..1100) is gone: only 20 is left.
    try testing.expectEqual(@as(?u64, 0), w.spread(4050));
    try testing.expectEqual(@as(?u64, null), w.spread(4600));
}

test "lateness: a steady stream has none; a late packet spreads it" {
    var l = Lateness.init(48000, 15_000, 1000);
    var t: u64 = 1_000_000;
    for (0..100) |_| {
        l.add(t, 480);
        t += 10_000;
    }
    try testing.expectEqual(@as(u64, 0), l.spreadMs(t / 1000));
    l.add(t + 35_000, 480);
    l.add(t + 35_100, 480);
    t += 20_000;
    for (0..10) |_| {
        l.add(t, 480);
        t += 10_000;
    }
    try testing.expectEqual(@as(u64, 35), l.spreadMs(t / 1000));
}

test "lateness: packets faster than real time (a sender catching up) are no jitter" {
    var l = Lateness.init(44100, 15_000, 1000);
    var t: u64 = 0;
    for (0..50) |_| {
        l.add(t, 441); // 10 ms of audio every 0.1 ms
        t += 100;
    }
    try testing.expectEqual(@as(u64, 0), l.spreadMs(t / 1000));
}

test "lateness: a pause is a new schedule, not lateness" {
    var l = Lateness.init(44100, 15_000, 1000);
    var t: u64 = 0;
    for (0..50) |_| {
        l.add(t, 441);
        t += 10_000;
    }
    t += 2_000_000; // 2 s without packets
    for (0..50) |_| {
        l.add(t, 441);
        t += 10_000;
    }
    try testing.expectEqual(@as(u64, 0), l.spreadMs(t / 1000));
}
