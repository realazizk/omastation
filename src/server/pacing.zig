//! Graphics pacing modelled on the Windows server: frame admission (interval, frames in flight,
//! queue drain), byte budgets and H.264 QP levels. Decisions only; flow.zig does the output.

const std = @import("std");

/// Target frame interval (about 32 fps); `--frame-interval` is clamped to [min, max].
pub const default_interval_ms: u32 = 31;
pub const min_interval_ms: u32 = 8;
pub const max_interval_ms: u32 = 200;
/// A frame may start this much before the interval is over.
pub const interval_slack_ms: i64 = 5;
/// Bound on unacknowledged frames, and its floor.
pub const max_frames_in_flight: u32 = 10;
pub const min_frames_in_flight: u32 = 3;
/// The client interval estimate's ceiling (ms).
pub const max_client_interval_ms: f64 = 200;
/// Queue drain time allowed before the network counts as busy (ms).
pub const ttna_allowance_ms: f64 = 25;
/// Queue drain rate before one is measured (B/s).
pub const default_rate: f64 = 262144;
/// The queue model is re-anchored to the flushed byte count at most this often (ms).
pub const metrics_ms: i64 = 15;
/// Highest H.264 bit rate given to the encoder.
pub const max_avc_bps: u64 = 30_000_000;
/// Floor of an H.264 size estimate (bytes).
pub const min_avc_estimate: usize = 700;
/// Windows' H.264 QP range at its default quality; a frame that does not fit at the maximum overshoots.
pub const avc_min_qp: u8 = 22;
pub const avc_max_qp: u8 = 38;
pub const avc_mid_qp: u8 = avc_max_qp - (avc_max_qp - avc_min_qp) / 2;
/// Above `avc_big_mbs` changed macroblocks QP >= `avc_big_qp`; below `avc_small_mbs`, the minimum.
pub const avc_big_mbs: u64 = 5000;
pub const avc_big_qp: u8 = 26;
pub const avc_small_mbs: u64 = 4;
/// Refine delay for lossy blocks; the slow value applies on links under `refine_quiet_slow_bps`.
pub const refine_quiet_ms: i64 = 233;
pub const refine_quiet_slow_ms: i64 = 333;
pub const refine_quiet_slow_bps: f64 = 5_000_000;
/// Smallest lossless frame budget: one piece always goes, so every frame makes progress.
pub const min_piece_bytes: usize = 4096;
/// Lossless pieces are one tile row at most this wide, so a budget is not overshot by a row.
pub const piece_px: u16 = 512;
/// Minimum period of the output log line (ms).
pub const log_interval_ms: i64 = 5000;
pub const slow_pass_ms: u32 = 100;
/// How long the session's last output may wait for the wire when the server ends it.
pub const drain_at_end_ms: i64 = 2000;

/// Piece width for `budget`: whole tiles (1 to 8) of raw planar (3 bytes a pixel, 64 rows).
pub fn pieceWidth(budget: usize) u16 {
    const tiles = budget / (64 * 64 * 3);
    return @intCast(64 * std.math.clamp(tiles, 1, piece_px / 64));
}

/// The interval for `--frame-interval MS`: [8, 200], 0 -> the default.
pub fn clampInterval(ms: u32) u32 {
    if (ms == 0) return default_interval_ms;
    return std.math.clamp(ms, min_interval_ms, max_interval_ms);
}

/// Graphics bytes in the server's channel queue, modelled between metrics updates.
pub const QueueEstimator = struct {
    depth: f64 = 0,
    total: u64 = 0,
    rate: f64 = default_rate,
    last_ms: i64 = 0,
    rate_known: bool = false,

    fn update(q: *QueueEstimator, now_ms: i64) void {
        const el = now_ms - q.last_ms;
        if (el > 0 and q.depth > 0) {
            q.last_ms = now_ms;
            q.depth = @max(0, q.depth - q.rate * @as(f64, @floatFromInt(el)) / 1000.0);
        }
    }

    pub fn queued(q: *QueueEstimator, n: usize, now_ms: i64) void {
        q.update(now_ms);
        q.total += n;
        q.depth += @floatFromInt(n);
    }

    /// Metrics update: `processed` of all bytes ever queued were flushed; `rate` in B/s (0: unknown).
    pub fn metrics(q: *QueueEstimator, rate: f64, processed: u64, now_ms: i64) void {
        q.last_ms = now_ms;
        if (processed <= q.total) {
            q.depth = @floatFromInt(q.total - processed);
        } else {
            q.depth = 0;
            q.total = processed;
        }
        if (rate > 0) {
            q.rate = rate;
            q.rate_known = true;
        }
    }

    /// Ms until the larger of model and `actual` (smaller while the rate is unknown) plus `extra` drain.
    pub fn timeToEmptyMs(q: *const QueueEstimator, actual: usize, extra: usize) f64 {
        const a: f64 = @floatFromInt(actual);
        const d = if (q.rate_known) @max(q.depth, a) else @min(q.depth, a);
        return (d + @as(f64, @floatFromInt(extra))) * 1000.0 / q.rate;
    }
};

pub const Refusal = enum {
    /// The target interval has not passed.
    interval,
    /// Too many frames unacknowledged (or the client's interval estimate).
    client,
    /// The channel queue does not drain within two intervals.
    network,
};

pub const State = struct {
    interval_ms: u32 = default_interval_ms,
    qe: QueueEstimator = .{},
    /// Graphics bytes handed to the channel and not yet taken for sending, and all ever flushed.
    queued_now: usize = 0,
    flushed_total: u64 = 0,
    /// When the queue model was last re-anchored.
    metrics_ms: i64 = 0,
    frame_start_ms: i64 = std.math.minInt(i64) / 2,
    /// The client's frame interval estimate, its last update, and the queue depth it last reported.
    client_ms: f64 = default_interval_ms,
    client_updated_ms: i64 = 0,
    client_depth: u32 = 0,
    /// The last admission check refused (a frame waits), and why.
    refused: bool = false,
    refusal: ?Refusal = null,
    /// When to look again (a refused frame, owed tiles): ms from now.
    retry_ms: ?i64 = null,
    /// H.264 encode time estimate (ms), deducted from H.264 budgets only.
    encode_ms: f64 = 5,
    avc: AvcModel = .{},
    stats: Stats = .{},
    logged_ms: i64 = 0,
    /// Over the connection: frames held for the network, frames cut to their budget.
    held_total: u64 = 0,
    cut_total: u64 = 0,
    /// Over the connection: graphics frames sent, the largest (wire bytes), H.264 frames, QP sum.
    frames_total: u64 = 0,
    max_frame_total: usize = 0,
    avc_total: u64 = 0,
    qp_total: u64 = 0,

    /// A ready frame waits for the client or the network (not for the target interval).
    pub fn held(s: *State) void {
        if (s.refusal == .interval) return;
        s.stats.held += 1;
        if (s.refusal == .network) s.stats.held_network += 1;
        s.held_total += 1;
    }

    pub fn cut(s: *State) void {
        s.stats.cut += 1;
        s.cut_total += 1;
    }

    pub fn queued(s: *State, n: usize, now_ms: i64) void {
        s.queued_now += n;
        s.qe.queued(n, now_ms);
    }

    /// `n` graphics bytes left the queue for the wire; `rate` in B/s (0: unknown).
    pub fn sent(s: *State, n: usize, rate: f64, now_ms: i64) void {
        s.queued_now -|= n;
        s.flushed_total += n;
        s.maybeMetrics(rate, now_ms);
    }

    pub fn maybeMetrics(s: *State, rate: f64, now_ms: i64) void {
        if (now_ms - s.metrics_ms < metrics_ms) return;
        s.metrics_ms = now_ms;
        s.qe.metrics(rate, s.flushed_total, now_ms);
    }

    /// Time until the channel queue drains, less the allowance, ms.
    pub fn ttnaMs(s: *State, now_ms: i64) f64 {
        s.qe.update(now_ms);
        return @max(0, s.qe.timeToEmptyMs(s.queued_now, 0) - ttna_allowance_ms);
    }

    /// The rate the budget is made of (B/s).
    pub fn linkRate(s: *const State) f64 {
        return if (s.qe.rate_known) s.qe.rate else 250_000;
    }

    /// Frame admission: interval passed, frames in flight within bound, queue drains in two intervals.
    /// `unacked` is null while acknowledgements are suspended (MS-RDPEGFX 2.2.2.13).
    pub fn admit(s: *State, now_ms: i64, unacked: ?u32, rtt_ms: ?u32) bool {
        const r = s.check(now_ms, unacked, rtt_ms);
        s.refusal = r;
        s.refused = r != null;
        if (r) |why| {
            // Retry after an interval, or the rest of it; flow.zig retries at once when data goes.
            const ms: i64 = switch (why) {
                .interval => @max(1, @as(i64, s.interval_ms) - (now_ms - s.frame_start_ms) - interval_slack_ms),
                .client, .network => s.interval_ms,
            };
            s.retry_ms = if (s.retry_ms) |x| @min(x, ms) else ms;
            return false;
        }
        return true;
    }

    fn check(s: *State, now_ms: i64, unacked: ?u32, rtt_ms: ?u32) ?Refusal {
        const since = now_ms - s.frame_start_ms;
        if (since + interval_slack_ms < s.interval_ms) return .interval;
        if (unacked) |n| {
            if (!s.clientReady(n, rtt_ms)) return .client;
            // While the client is slower than the target, frames no closer than its interval.
            if (s.client_ms > @as(f64, @floatFromInt(s.interval_ms)) and @as(f64, @floatFromInt(since)) < s.client_ms) return .client;
        }
        if (s.ttnaMs(now_ms) > 2.0 * @as(f64, @floatFromInt(s.interval_ms))) return .network;
        return null;
    }

    /// Not ready with more than 3 and more than min(10, `framesInFlight`) frames unacknowledged.
    pub fn clientReady(s: *const State, unacked: u32, rtt_ms: ?u32) bool {
        return !(unacked > min_frames_in_flight and unacked > @min(max_frames_in_flight, s.framesInFlight(rtt_ms)));
    }

    /// F = max(3, RTT / client interval); 10 while the RTT is unknown.
    pub fn framesInFlight(s: *const State, rtt_ms: ?u32) u32 {
        const rtt = rtt_ms orelse return max_frames_in_flight;
        const f = satUsize(@as(f64, @floatFromInt(rtt)) / @max(1, s.client_ms));
        return @max(min_frames_in_flight, @as(u32, @intCast(@min(f, max_frames_in_flight))));
    }

    pub fn frameStarted(s: *State, now_ms: i64) void {
        s.frame_start_ms = now_ms;
        s.refused = false;
        s.refusal = null;
    }

    /// Bytes the current frame may take: (2 x interval - elapsed - max(queue drain, `min_ms`)) x rate.
    pub fn budget(s: *State, now_ms: i64, min_ms: f64) usize {
        const el: f64 = @floatFromInt(@max(0, now_ms - s.frame_start_ms));
        const win = 2.0 * @as(f64, @floatFromInt(s.interval_ms)) - el;
        const ms = win - @max(s.ttnaMs(now_ms), min_ms);
        if (ms <= 0) return 0;
        return satUsize(ms * s.linkRate() / 1000.0);
    }

    /// The H.264 budget: the frame's, at most `max_avc_bps` over the interval.
    pub fn avcBudget(s: *State, now_ms: i64) usize {
        const cap: usize = @intCast(max_avc_bps / 8 * s.interval_ms / 1000);
        return @min(s.budget(now_ms, s.encode_ms), cap);
    }

    /// An encode took `ms`: the estimate becomes 0.75 new + 0.25 old, at most 10x the old.
    pub fn encoded(s: *State, ms: f64) void {
        s.encode_ms = @min(0.75 * ms + 0.25 * s.encode_ms, 10 * @max(s.encode_ms, 1));
    }

    /// Frame Acknowledge queueDepth (MS-RDPEGFX 2.2.2.13): adjusts the client interval estimate.
    pub fn onFrameAck(s: *State, depth: u32, now_ms: i64) void {
        defer s.client_depth = depth;
        if (@as(f64, @floatFromInt(now_ms - s.client_updated_ms)) < 4 * s.client_ms) return;
        const target: f64 = @floatFromInt(s.interval_ms);
        if (depth == 0) {
            s.client_ms = @max(target, s.client_ms * 0.97);
        } else if (depth > 2 and depth >= s.client_depth) {
            s.client_ms = @min(max_client_interval_ms, s.client_ms * 1.05);
        } else return;
        s.client_updated_ms = now_ms;
    }
};

/// f64 to usize for byte counts from measured rates: negative or NaN is 0, too large saturates.
pub fn satUsize(x: f64) usize {
    if (!(x > 0)) return 0;
    if (x >= 1.8e19) return std.math.maxInt(usize);
    return @intFromFloat(x);
}

/// QP for an encoder quality: ((minQP - 51) x q - minQP + 5100) / 99, in [minQP, 51].
pub fn qpOf(quality: u8, min_qp: u8) u8 {
    const q: i32 = quality;
    const m: i32 = min_qp;
    const v = @divTrunc((m - 51) * q - m + 5100, 99);
    return @intCast(std.math.clamp(v, m, 51));
}

/// H.264's quantizer step for `qp` (doubles every 6).
pub fn qstep(qp: u8) f64 {
    return 0.625 * std.math.pow(f64, 2.0, @as(f64, @floatFromInt(qp)) / 6.0);
}

/// Inverse of `qpOf`: qp clamped to [minQP, maxQP] first, quality in [1, 100].
pub fn qualityOf(qp: u8, min_qp: u8, max_qp: u8) u8 {
    const q: f64 = @floatFromInt(std.math.clamp(qp, min_qp, max_qp));
    const m: f64 = @floatFromInt(min_qp);
    const v: i32 = @intFromFloat((99.0 * q - 5100.0 + m) / (m - 51.0) + 0.5);
    return @intCast(std.math.clamp(v, 1, 100));
}

/// Quality step between QP levels: (quality(min) - quality(max)) / 3 = 18.
pub const avc_quality_step: u8 = (qualityOf(avc_min_qp, avc_min_qp, avc_max_qp) - qualityOf(avc_max_qp, avc_min_qp, avc_max_qp)) / 3;

/// QP of an H.264 frame with new content: the best of three levels that `fits`; the minimum for
/// under `avc_small_mbs` dirty macroblocks, at least `avc_big_qp` above `avc_big_mbs`.
pub fn frameQp(dirty: u64, ctx: anytype, comptime fits: fn (@TypeOf(ctx), u8) bool) u8 {
    if (dirty < avc_small_mbs) return avc_min_qp;
    const lo = if (dirty > avc_big_mbs) @max(avc_min_qp, avc_big_qp) else avc_min_qp;
    if (fits(ctx, lo)) return lo;
    if (lo < avc_mid_qp and fits(ctx, avc_mid_qp)) return avc_mid_qp;
    return avc_max_qp;
}

/// The QP a refinement pass codes a block shown at `qp` with: above mid to mid, else to min.
pub fn refineQp(qp: u8) u8 {
    return if (qp > avc_mid_qp) avc_mid_qp else avc_min_qp;
}

/// Highest quality from 100 down by `step` (at most 30 tries) whose estimate fits; 0 if none.
pub fn bestQuality(budget: usize, step: u8, ctx: anytype, comptime estimate: fn (@TypeOf(ctx), u8) usize) u8 {
    var q: i32 = 100;
    var tries: u32 = 0;
    while (q > step and tries < 30) : (tries += 1) {
        if (estimate(ctx, @intCast(q)) <= budget) return @intCast(q);
        q -= step;
    }
    return 0;
}

/// H.264 size model: bytes = k x macroblocks / QStep, k learned per frame (IDR and P apart).
pub const AvcModel = struct {
    k_p: f64 = 64,
    k_i: f64 = 160,

    /// Estimated bytes of `mbs` updated macroblocks at `qp` (at least 700, at most `raw` / 4).
    pub fn estimate(m: *const AvcModel, mbs: u64, qp: u8, idr: bool, raw: usize) usize {
        const k = if (idr) m.k_i else m.k_p;
        const v = satUsize(k * @as(f64, @floatFromInt(mbs)) / qstep(qp));
        return std.math.clamp(v, min_avc_estimate, @max(min_avc_estimate, raw / 4));
    }

    pub fn learn(m: *AvcModel, mbs: u64, qp: u8, idr: bool, bytes: usize) void {
        if (mbs == 0) return;
        const k = @as(f64, @floatFromInt(bytes)) * qstep(qp) / @as(f64, @floatFromInt(mbs));
        const p = if (idr) &m.k_i else &m.k_p;
        p.* = 0.6 * p.* + 0.4 * k;
    }
};

/// Counters for the periodic output line (Conn.logOutput).
pub const Stats = struct {
    held: u32 = 0,
    cut: u32 = 0,
    /// Of `held`: held for the network (the rest by the client).
    held_network: u32 = 0,
    frames: u32 = 0,
    frame_bytes: u64 = 0,
    max_frame: usize = 0,
    avc_frames: u32 = 0,
    qp_sum: u64 = 0,
    longest_pass_ms: u32 = 0,
};

const testing = std.testing;

test "admission: target interval, frames in flight, queue drain within two intervals" {
    var s: State = .{};
    s.frameStarted(1000);
    try testing.expect(!s.admit(1025, 0, 65));
    try testing.expectEqual(Refusal.interval, s.refusal.?);
    try testing.expectEqual(@as(?i64, 1), s.retry_ms);
    try testing.expect(s.admit(1026, 0, 65));
    try testing.expect(s.admit(1100, 3, 65));
    try testing.expect(!s.admit(1100, 4, 65));
    try testing.expectEqual(Refusal.client, s.refusal.?);
    try testing.expect(s.admit(1100, 6, 200)); // 200 / 31 = 6
    try testing.expect(!s.admit(1100, 11, 1000));
    try testing.expect(s.admit(1100, 10, null)); // RTT unknown: 10
    try testing.expect(s.admit(1100, null, 65)); // suspended: no bound
    // 4 Mbit/s: 500 B/ms; 2 x 31 + 25 = 87 ms of queue = 43.5 KB.
    s.qe.metrics(500_000, 0, 1100);
    s.queued(43_000, 1100);
    try testing.expect(s.admit(1100, 0, 65));
    s.queued(1_000, 1100);
    try testing.expect(!s.admit(1100, 0, 65));
    try testing.expectEqual(Refusal.network, s.refusal.?);
    s.sent(10_000, 500_000, 1120);
    try testing.expect(s.admit(1120, 0, 65));
}

test "QueueEstimator re-anchors to the flushed count and drains at the rate in between" {
    var q: QueueEstimator = .{};
    q.metrics(100_000, 0, 0);
    q.queued(50_000, 0);
    q.update(100);
    try testing.expectApproxEqAbs(@as(f64, 40_000), q.depth, 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 500), q.timeToEmptyMs(50_000, 0), 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 400), q.timeToEmptyMs(10_000, 0), 1e-6);
    q.metrics(100_000, 45_000, 110);
    try testing.expectApproxEqAbs(@as(f64, 5_000), q.depth, 1e-6);
    var u: QueueEstimator = .{};
    u.queued(1_000_000, 0);
    try testing.expectApproxEqAbs(@as(f64, 1000.0 * 1000 / default_rate), u.timeToEmptyMs(1000, 0), 1e-6);
}

test "budget: (2 x interval - elapsed - max(drain, encode)) x rate; H.264 capped at 30 Mbit/s" {
    var s: State = .{};
    s.qe.metrics(500_000, 0, 0); // 4 Mbit/s
    s.frameStarted(0);
    s.encode_ms = 5;
    // (62 - 0 - 5) x 500 = 28500: the frame fits ~one interval of link.
    try testing.expectEqual(@as(usize, 28_500), s.budget(0, s.encode_ms));
    try testing.expectEqual(@as(usize, 28_500 - 10 * 500), s.budget(10, s.encode_ms));
    try testing.expectEqual(@as(usize, 31_000), s.budget(0, 0));
    s.queued(20_000, 0);
    try testing.expectEqual(@as(usize, (62 - 15) * 500), s.budget(0, s.encode_ms));
    try testing.expectEqual(@as(usize, 0), s.budget(70, s.encode_ms));
    var l: State = .{};
    l.qe.metrics(125_000_000, 0, 0);
    l.frameStarted(0);
    try testing.expect(l.budget(0, l.encode_ms) > 7_000_000);
    try testing.expectEqual(@as(usize, 116_250), l.avcBudget(0));
}

test "QP range 22..38, mid 30, quality step 18" {
    try testing.expectEqual(@as(u8, 22), avc_min_qp);
    try testing.expectEqual(@as(u8, 38), avc_max_qp);
    try testing.expectEqual(@as(u8, 30), avc_mid_qp);
    try testing.expectEqual(@as(u8, 100), qualityOf(22, 22, 38));
    try testing.expectEqual(@as(u8, 45), qualityOf(38, 22, 38));
    try testing.expectEqual(@as(u8, 45), qualityOf(51, 22, 38));
    try testing.expectEqual(@as(u8, 97), qualityOf(23, 22, 38));
    try testing.expectEqual(@as(u8, 73), qualityOf(30, 22, 38));
    try testing.expectEqual(@as(u8, 18), avc_quality_step);
    try testing.expectEqual(@as(u8, 22), qpOf(100, 22));
    try testing.expectEqual(@as(u8, 27), qpOf(82, 22));
    try testing.expectEqual(@as(u8, 32), qpOf(64, 22));
    try testing.expectEqual(@as(u8, 37), qpOf(46, 22));
    try testing.expectEqual(@as(u8, 43), qpOf(28, 22));
    try testing.expectEqual(@as(u8, 30), refineQp(38));
    try testing.expectEqual(@as(u8, 22), refineQp(30));
    try testing.expectEqual(@as(u8, 22), refineQp(26));
}

test "frame QP: the best level that fits, never above 38; small updates at 22, big ones at least 26" {
    const Fits = struct {
        limit: u8,
        fn f(c: @This(), q: u8) bool {
            return q >= c.limit;
        }
    };
    try testing.expectEqual(@as(u8, 38), frameQp(10_000, Fits{ .limit = 51 }, Fits.f));
    try testing.expectEqual(@as(u8, 30), frameQp(10_000, Fits{ .limit = 30 }, Fits.f));
    try testing.expectEqual(@as(u8, 26), frameQp(10_000, Fits{ .limit = 0 }, Fits.f));
    try testing.expectEqual(@as(u8, 22), frameQp(4000, Fits{ .limit = 0 }, Fits.f));
    try testing.expectEqual(@as(u8, 30), frameQp(4000, Fits{ .limit = 23 }, Fits.f));
    try testing.expectEqual(@as(u8, 22), frameQp(3, Fits{ .limit = 51 }, Fits.f));
}

test "quality: QP linear in quality (100 -> min QP, 1 -> 51); the highest quality whose estimate fits" {
    try testing.expectEqual(avc_min_qp, qpOf(100, avc_min_qp));
    try testing.expectEqual(@as(u8, 51), qpOf(1, avc_min_qp));
    try testing.expectEqual(@as(u8, 51), qpOf(0, avc_min_qp));
    var m: AvcModel = .{};
    m.learn(32400, 22, false, 300_000);
    const Ctx = struct {
        m: *const AvcModel,
        fn est(c: @This(), q: u8) usize {
            return c.m.estimate(32400, qpOf(q, avc_min_qp), false, 3840 * 2160 * 3 / 2);
        }
    };
    const q = bestQuality(28_500, avc_quality_step, Ctx{ .m = &m }, Ctx.est);
    try testing.expect(q < 100);
    if (q > 0) try testing.expect(Ctx.est(.{ .m = &m }, q) <= 28_500);
    try testing.expectEqual(@as(u8, 100), bestQuality(10_000_000, avc_quality_step, Ctx{ .m = &m }, Ctx.est));
    const e0 = m.estimate(32400, 30, false, 1 << 30);
    m.learn(32400, 30, false, e0 * 2);
    try testing.expect(m.estimate(32400, 30, false, 1 << 30) > e0);
}

test "client interval: +5 % while its queue holds > 2 frames and grows, -3 % (not under the target) when empty" {
    var s: State = .{};
    s.onFrameAck(3, 1000);
    try testing.expectApproxEqAbs(@as(f64, 31 * 1.05), s.client_ms, 1e-9);
    s.onFrameAck(4, 1050);
    try testing.expectApproxEqAbs(@as(f64, 31 * 1.05), s.client_ms, 1e-9);
    s.onFrameAck(4, 1200);
    try testing.expectApproxEqAbs(@as(f64, 31 * 1.05 * 1.05), s.client_ms, 1e-9);
    s.frameStarted(2000);
    try testing.expect(!s.admit(2032, 0, 10));
    try testing.expect(s.admit(2035, 0, 10));
    for (0..50) |i| s.onFrameAck(0, 3000 + @as(i64, @intCast(i)) * 1000);
    try testing.expectEqual(@as(f64, 31), s.client_ms);
}
