//! Network characteristics auto-detection (MS-RDPBCGR 1.3.9, 2.2.14, 3.3.5.14):
//! connect-time rounds before licensing, then continuous detection.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const x224 = @import("../proto/x224.zig");
const mcs = @import("../proto/mcs.zig");
const ad = @import("../proto/session_ext/autodetect.zig");
const flow = @import("flow.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;
const c = @import("c");

const log = std.log.scoped(.autodetect);

/// Longest time connect-time detection may hold the connection sequence.
pub const connect_time_budget_ms: i64 = 5000;
/// Detection ends this long after the connection sequence began at the latest, so the rest of
/// the sequence stays well inside the clients' activation timeouts (FreeRDP: about 10 s from its
/// start), however slow and distant the link...
pub const sequence_budget_ms: i64 = 6000;
/// ...but it runs this long (a round and an RTT sample on a 600 ms link).
pub const min_budget_ms: i64 = 1000;
pub const connect_time_rtt_samples: u32 = 7;
/// Bytes per Bandwidth Measure Payload; keeps each PDU under a 2-byte PER length.
pub const payload_size: usize = 16000;
/// Round sizes in bytes; rounds averaging under `fast_round_ms` double the next size.
pub const first_round: u32 = 4000;
pub const max_round: u32 = 256000;
pub const fast_round_ms: f64 = 20;
pub const settled_rounds: u32 = 7;
/// From this base RTT up a round costs more than a LAN's whole detection (see Plan).
pub const expensive_rtt_ms: u32 = 50;
/// On such a link, this many rounds at one size whose rates are within `stable_spread`
/// (largest over smallest) end detection, with `stable_rtt_samples` RTT samples.
pub const stable_rounds: usize = 3;
pub const stable_spread: f64 = 1.25;
pub const stable_rtt_samples: u32 = 3;

pub const State = struct {
    det: ad.Detector = .{},
    /// Last connect-time Bandwidth Measure Results (timeDelta in ms, byteCount).
    last_results: ?struct { time: u32, bytes: u32 } = null,
};

/// The connect-time rounds: how big each is and when they end (no I/O, so it is unit-tested).
///
/// On a LAN the size doubles from `first_round` after 3 rounds averaging under `fast_round_ms`,
/// and detection ends after `settled_rounds` at one size with `connect_time_rtt_samples` RTT
/// samples, as it always did. Each round waits for its results, an RTT, so on a link from
/// `expensive_rtt_ms` up the size doubles after every round too fast to time, a round takes the
/// longer of the client's clock and the server's (results minus base RTT: a buffering hop hands
/// the client a burst at once), the result is the median of the last rates, and `stable_rounds`
/// agreeing rates end detection. Whatever the link, no round starts that would end after
/// `deadline_ms`.
pub const Plan = struct {
    deadline_ms: i64,
    size: u32 = first_round,
    /// Rounds at `size` and their summed timeDelta.
    at_size: u32 = 0,
    at_size_ms: f64 = 0,
    /// Rates (kbps) of the last timed rounds at `size` on an expensive link, oldest first.
    rates: [stable_rounds]u64 = undefined,
    rates_len: usize = 0,
    /// On an expensive link, the median of `rates` once a round was timed: the result.
    result_kbps: ?u64 = null,
    /// The last timed round was longer on the server's clock than on the client's.
    server_clock: bool = false,
    /// The last rate measured, for whether a round still fits.
    kbps: ?u64 = null,
    rounds: u32 = 0,

    /// `start_ms`: detection starts; `sequence_start_ms`: the connection sequence did.
    pub fn init(start_ms: i64, sequence_start_ms: i64) Plan {
        const by_sequence = @max(start_ms + min_budget_ms, sequence_start_ms + sequence_budget_ms);
        return .{ .deadline_ms = @min(start_ms + connect_time_budget_ms, by_sequence) };
    }

    pub const Round = struct {
        /// The client's Bandwidth Measure Results: timeDelta (ms) and byteCount.
        time_ms: u32,
        bytes: u32,
        /// From the round's Start sent to its results received, on the server's clock.
        elapsed_ms: i64,
    };

    pub const Rtt = struct { base: ?u32, samples: u32 };

    /// Takes a round's results; false when detection is done. The next round is `size` bytes.
    pub fn next(p: *Plan, r: Round, rtt: Rtt, now_ms: i64) bool {
        p.rounds += 1;
        const done = if (rtt.base) |base| (if (base >= expensive_rtt_ms) p.expensiveRound(r, base, rtt.samples) else p.lanRound(r, rtt.samples)) else p.lanRound(r, rtt.samples);
        return !done and p.fits(rtt.base orelse 0, now_ms);
    }

    fn resize(p: *Plan, size: u32) void {
        p.size = size;
        p.at_size = 0;
        p.at_size_ms = 0;
        p.rates_len = 0;
    }

    fn lanRound(p: *Plan, r: Round, rtt_samples: u32) bool {
        p.kbps = ad.bandwidthKbps(r.bytes, @max(r.time_ms, 1)) catch unreachable;
        p.at_size += 1;
        p.at_size_ms += @floatFromInt(r.time_ms);
        if (p.at_size >= 3) {
            const avg = p.at_size_ms / @as(f64, @floatFromInt(p.at_size));
            if (p.size < max_round and avg < fast_round_ms) {
                p.resize(@min(p.size * 2, max_round));
            } else if (avg > 400 and p.size == first_round) {
                p.resize(@max(@as(u32, @intFromFloat(32000.0 / avg * 30.0 * 0.125)), 1600));
            }
        }
        return p.at_size >= settled_rounds and rtt_samples >= connect_time_rtt_samples;
    }

    fn expensiveRound(p: *Plan, r: Round, base_rtt: u32, rtt_samples: u32) bool {
        const drain = @max(r.elapsed_ms - base_rtt, 0);
        const time_ms: u64 = @intCast(@max(@as(i64, r.time_ms), drain));
        if (@as(f64, @floatFromInt(time_ms)) < fast_round_ms) {
            if (p.size < max_round) {
                p.resize(@min(p.size * 2, max_round));
                return false;
            }
            return p.lanRound(r, rtt_samples);
        }
        const kbps = @as(u64, r.bytes) * 8 / time_ms;
        p.kbps = kbps;
        p.server_clock = drain > r.time_ms;
        if (p.rates_len == stable_rounds) {
            std.mem.copyForwards(u64, p.rates[0 .. stable_rounds - 1], p.rates[1..]);
            p.rates_len -= 1;
        }
        p.rates[p.rates_len] = kbps;
        p.rates_len += 1;
        var sorted = p.rates;
        std.mem.sort(u64, sorted[0..p.rates_len], {}, std.sort.asc(u64));
        p.result_kbps = sorted[(p.rates_len - 1) / 2];
        p.at_size += 1;
        p.at_size_ms += @floatFromInt(time_ms);
        if (p.at_size >= settled_rounds and rtt_samples >= connect_time_rtt_samples) return true;
        if (p.rates_len < stable_rounds or rtt_samples < stable_rtt_samples) return false;
        const lo = std.mem.min(u64, p.rates[0..p.rates_len]);
        const hi = std.mem.max(u64, p.rates[0..p.rates_len]);
        return @as(f64, @floatFromInt(hi)) <= @as(f64, @floatFromInt(@max(lo, 1))) * stable_spread;
    }

    /// Whether a round of `size`, an RTT plus its bytes at the last rate, ends before the deadline.
    fn fits(p: *const Plan, base_rtt: u32, now_ms: i64) bool {
        const bytes_ms: u64 = if (p.kbps) |k| @as(u64, p.size) * 8 / @max(k, 1) else 0;
        return now_ms + base_rtt + @as(i64, @intCast(bytes_ms)) < p.deadline_ms;
    }
};

/// Server Auto-Detect Request PDU (MS-RDPBCGR 2.2.14.3).
fn send(conn: *Conn, r: ad.Request) conn_mod.Error!void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(conn.gpa);
    var w = bytes.Writer.init(&body, conn.gpa);
    ad.encodeRequestPdu(&w, r) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => unreachable,
    };
    try conn.sendMcs(conn.msg_channel.?, body.items);
}

fn stamp(now_ms: i64) u64 {
    return @intCast(@max(now_ms, 0));
}

/// One connect-time round of `size` bytes: Start, full Payloads, then a Stop with the rest.
fn sendRound(conn: *Conn, size: u32, payload: []const u8) conn_mod.Error!void {
    const det = &conn.netchar.det;
    try send(conn, det.bwStart() catch unreachable);
    const n: u32 = @intCast((size + payload_size - 1) / payload_size - 1);
    for (0..n) |_| try send(conn, det.bwPayload(payload[0..payload_size]) catch unreachable);
    const rest: usize = size - n * payload_size;
    const stop_len = @max(rest, ad.header_length_payload + 1) - ad.header_length_payload;
    try send(conn, det.bwStop(payload[0..stop_len]) catch unreachable);
}

/// Connect-Time Auto-Detection (MS-RDPBCGR 1.3.1.1 phase 6); no-op unless negotiated.
pub fn connectTime(conn: *Conn) conn_mod.Error!void {
    const s = &conn.netchar;
    s.det = ad.Detector.init(@bitCast(conn.client.early_caps), conn.client.connection_type, conn.msg_channel != null) catch unreachable;
    if (!s.det.enabled) return;

    const start = conn_mod.nowMs();
    var plan = Plan.init(start, if (conn.sequence_start_ms != 0) conn.sequence_start_ms else start);
    // Random so nothing on the path can compress it (MS-RDPBCGR 2.2.14.1.3).
    const payload = try conn.gpa.alloc(u8, payload_size);
    defer conn.gpa.free(payload);
    var prng = std.Random.DefaultPrng.init(@bitCast(start));
    prng.random().bytes(payload);

    var total_rounds: u32 = 0;
    while (true) {
        if (s.det.results.rtt_samples + @as(u32, @intCast(s.det.pendingRtt())) < connect_time_rtt_samples)
            try send(conn, s.det.rttRequest(stamp(conn_mod.nowMs())) catch unreachable);
        s.last_results = null;
        const sent_ms = conn_mod.nowMs();
        try sendRound(conn, plan.size, payload);
        total_rounds += 1;
        while (s.det.bw_stopped != null and !s.det.synced) {
            if (!try waitAnswer(conn, plan.deadline_ms)) break;
        }
        if (s.det.synced) break;
        const r = s.last_results orelse break; // no answer in time
        const now = conn_mod.nowMs();
        const rtt: Plan.Rtt = .{ .base = s.det.results.base_rtt, .samples = s.det.results.rtt_samples };
        if (!plan.next(.{ .time_ms = r.time, .bytes = r.bytes, .elapsed_ms = now - sent_ms }, rtt, now)) break;
    }
    while (s.det.pendingRtt() > 0 and s.det.results.rtt_samples < connect_time_rtt_samples and !s.det.synced) {
        if (!try waitAnswer(conn, plan.deadline_ms)) break;
    }
    if (!s.det.synced) if (plan.result_kbps) |kbps| {
        s.det.results.bandwidth = kbps;
    };

    const r = s.det.getResults() catch unreachable;
    if (s.det.netcharResult()) |res| {
        try send(conn, res);
        const clock = if (plan.result_kbps == null or s.det.synced) "" else if (plan.server_clock) "; median rate, the last on the server's clock" else "; median rate";
        log.info("{s}: network: base RTT {?d} ms, average RTT {?d} ms, bandwidth {?d} kbps ({d} rounds, {d} ms of {d}{s})", .{
            conn.peer, r.base_rtt, r.average_rtt, r.bandwidth, total_rounds, conn_mod.nowMs() - start, plan.deadline_ms - start, clock,
        });
    } else |_| {
        log.info("{s}: network characteristics detection: no result after {d} ms", .{ conn.peer, conn_mod.nowMs() - start });
    }
}

/// Reads one client PDU before `deadline`; false when time is up.
fn waitAnswer(conn: *Conn, deadline: i64) conn_mod.Error!bool {
    const left = deadline - conn_mod.nowMs();
    if (left <= 0) return false;
    if (!conn.t.hasPending()) {
        var fds = [_]c.struct_pollfd{.{ .fd = conn.t.fd, .events = c.POLLIN, .revents = 0 }};
        const n = c.poll(&fds, fds.len, @intCast(left));
        if (n < 0) return true;
        if (n == 0) return false;
    }
    const pdu = try conn.t.next();
    if (pdu.kind != .tpkt) return true; // no fast-path input before activation
    switch (try mcs.parseClientPdu(try x224.parseData(pdu.data))) {
        .send_data_request => |sdr| {
            if (sdr.channel_id == conn.msg_channel.?) {
                onMessageChannel(conn, sdr.data);
            } else {
                log.debug("{s}: {d} bytes on channel {d} during connect-time detection (ignored)", .{ conn.peer, sdr.data.len, sdr.channel_id });
            }
        },
        .disconnect_provider_ultimatum => return error.ClientDisconnected,
        else => return error.ProtocolError,
    }
    return true;
}

/// Auto-Detect Responses (MS-RDPBCGR 2.2.14.4); continuous requests' answers go to flow.
pub fn onMessageChannel(conn: *Conn, user_data: []const u8) void {
    const s = &conn.netchar;
    if (user_data.len >= 2 and std.mem.readInt(u16, user_data[0..2], .little) & ad.sec_autodetect_rsp == 0) {
        log.debug("{s}: {d} bytes on the message channel (ignored)", .{ conn.peer, user_data.len });
        return;
    }
    if (!s.det.enabled) return;
    const rsp = ad.decodeResponsePdu(user_data) catch |err| {
        log.debug("{s}: auto-detect response dropped: {t}", .{ conn.peer, err });
        return;
    };
    switch (rsp) {
        .rtt => |x| if (flow.onRttResponse(conn, x.sequence_number)) return,
        .bw_results => |x| {
            if (x.response_type == ad.bw_results_continuous and flow.onBwResults(conn, x.time_delta, x.byte_count)) return;
            if (x.response_type == ad.bw_results_connect_time) s.last_results = .{ .time = x.time_delta, .bytes = x.byte_count };
        },
        .netchar_sync => {},
    }
    const sample = s.det.onResponse(rsp, stamp(conn_mod.nowMs())) catch |err| {
        log.debug("{s}: auto-detect response dropped: {t}", .{ conn.peer, err });
        return;
    };
    switch (sample) {
        .rtt => |ms| log.debug("{s}: RTT {d} ms (connect time)", .{ conn.peer, ms }),
        .bandwidth => |kbps| log.debug("{s}: bandwidth {d} kbps (connect time)", .{ conn.peer, kbps }),
        .sync => |v| log.debug("{s}: network characteristics sync: {d} kbps, RTT {d} ms", .{ conn.peer, v.bandwidth, v.rtt }),
    }
}

/// Switches the detector to continuous mode once the connection sequence completes.
pub fn tick(conn: *Conn) conn_mod.Error!void {
    const s = &conn.netchar;
    if (!s.det.enabled or !conn.established) return;
    if (s.det.phase == .continuous) return;
    s.det.activated() catch unreachable;
}

/// A link for the tests: `kbps` at the bottleneck and `rtt_ms`; `chunk` > 0 is a hop that holds
/// what it forwards and passes it on in pieces of that many bytes (omastation-bench's slowlink.py).
const TestLink = struct {
    kbps: u64,
    rtt_ms: u32,
    chunk: u32 = 0,

    fn bytesMs(l: TestLink, n: u64) u32 {
        return @intCast(n * 8 / l.kbps);
    }

    fn round(l: TestLink, size: u32) Plan.Round {
        const time = if (l.chunk == 0) l.bytesMs(size) else (std.math.divCeil(u32, size, l.chunk) catch unreachable) * l.bytesMs(l.chunk) - l.bytesMs(l.chunk);
        return .{ .time_ms = time, .bytes = size, .elapsed_ms = l.rtt_ms + l.bytesMs(size) };
    }
};

const Outcome = struct {
    rounds: u32,
    /// Detection time.
    ms: i64,
    /// The result: the plan's, else the client's last.
    kbps: ?u64,
    size: u32,
    /// A round went out that was not answered by the deadline.
    late: bool,
};

/// Connect-time detection over `link`, starting `in_sequence_ms` into the connection sequence:
/// connectTime's loop, an RTT sample answered with every round.
fn simulate(link: TestLink, in_sequence_ms: i64) Outcome {
    const start: i64 = 1_000_000;
    var p = Plan.init(start, start - in_sequence_ms);
    var now = start;
    var samples: u32 = 0;
    var client_kbps: ?u64 = null;
    const late = while (true) {
        const r = link.round(p.size);
        if (now + r.elapsed_ms > p.deadline_ms) break true;
        now += r.elapsed_ms;
        samples = @min(samples + 1, connect_time_rtt_samples);
        client_kbps = ad.bandwidthKbps(r.bytes, r.time_ms) catch client_kbps; // a zero timeDelta is dropped
        if (!p.next(r, .{ .base = link.rtt_ms, .samples = samples }, now)) break false;
    };
    return .{ .rounds = p.rounds, .ms = now - start, .kbps = p.result_kbps orelse client_kbps, .size = p.size, .late = late };
}

test "connect-time detection on a LAN runs its rounds as before: the ladder up to 256 KB, then 7 settled" {
    const lan = simulate(.{ .kbps = 2_048_000, .rtt_ms = 0 }, 100);
    try std.testing.expectEqual(Outcome{ .rounds = 25, .ms = 7, .kbps = 2_048_000, .size = max_round, .late = false }, lan);
    // Cheap rounds (under expensive_rtt_ms) keep the same ladder and settling.
    try std.testing.expectEqual(Outcome{ .rounds = 22, .ms = 304, .kbps = 51_200, .size = 128_000, .late = false }, simulate(.{ .kbps = 50_000, .rtt_ms = 5 }, 200));
    try std.testing.expectEqual(Outcome{ .rounds = 19, .ms = 811, .kbps = 20_480, .size = 64_000, .late = false }, simulate(.{ .kbps = 20_000, .rtt_ms = 30 }, 600));
}

test "connect-time detection on 1 Mbit/s with 150 ms each way ends 6 s into the connection sequence" {
    // 4.75 s of connection sequence before detection starts, and FreeRDP waits 10 s for Demand
    // Active. A proxy passing 16 KB pieces at once delivers rounds under 16 KB in one piece.
    for ([_]u32{ 16384, 0 }) |chunk| {
        const o = simulate(.{ .kbps = 1000, .rtt_ms = 301, .chunk = chunk }, 4750);
        try std.testing.expect(!o.late);
        try std.testing.expect(o.ms <= sequence_budget_ms - 4750);
        try std.testing.expect(o.rounds >= stable_rounds);
        // The client saw each 4 KB burst at once; the server's clock measured it.
        try std.testing.expect(o.kbps.? >= 800 and o.kbps.? <= 1250);
    }
    // Later into the sequence still a round and its answer, never more than min_budget_ms.
    const late = simulate(.{ .kbps = 1000, .rtt_ms = 301, .chunk = 16384 }, 7000);
    try std.testing.expect(!late.late and late.rounds >= 1 and late.ms <= min_budget_ms);
    try std.testing.expect(late.kbps.? >= 800 and late.kbps.? <= 1250);
}

test "connect-time detection on distant links: few rounds once the rate is stable, none that ends late" {
    // 5 Mbit/s, 60 ms each way.
    for ([_]u32{ 16384, 0 }) |chunk| {
        const o = simulate(.{ .kbps = 5000, .rtt_ms = 121, .chunk = chunk }, 1900);
        try std.testing.expect(!o.late and o.ms < 1000);
        try std.testing.expect(o.kbps.? >= 4000 and o.kbps.? <= 6500);
    }
    // Fast and distant: the size doubles after every round too short to time.
    const fast = simulate(.{ .kbps = 100_000, .rtt_ms = 150 }, 2400);
    try std.testing.expect(!fast.late and fast.ms < 2000);
    try std.testing.expect(fast.kbps.? >= 50_000);
    // Slow and distant: a 4 KB round takes 550 ms; the fourth would end after the deadline.
    const slow = simulate(.{ .kbps = 128, .rtt_ms = 300 }, 4000);
    try std.testing.expectEqual(Outcome{ .rounds = 3, .ms = 1650, .kbps = 128, .size = first_round, .late = false }, slow);
}

test "the connect-time deadline: 5 s, cut to end 6 s into the connection sequence, never under 1 s" {
    try std.testing.expectEqual(@as(i64, 10_000 + connect_time_budget_ms), Plan.init(10_000, 9_900).deadline_ms);
    try std.testing.expectEqual(@as(i64, 10_000 + 1250), Plan.init(10_000, 10_000 - 4750).deadline_ms);
    try std.testing.expectEqual(@as(i64, 10_000 + min_budget_ms), Plan.init(10_000, 10_000 - 5500).deadline_ms);
    try std.testing.expectEqual(@as(i64, 10_000 + min_budget_ms), Plan.init(10_000, 0).deadline_ms);
}

test "rates that keep moving on a distant link run until settled_rounds, as on a LAN" {
    var p = Plan.init(0, 0);
    const kbps = [_]u32{ 500, 1000, 500, 1000, 500, 1000, 500 };
    var now: i64 = 0;
    for (kbps, 0..) |k, i| {
        now += 400;
        // 4 KB in 64 or 32 ms on both clocks: no three in a row within stable_spread.
        const go = p.next(.{ .time_ms = 32_000 / k, .bytes = 4000, .elapsed_ms = 300 + 32_000 / k }, .{ .base = 300, .samples = @intCast(i + 1) }, now);
        try std.testing.expectEqual(i + 1 < kbps.len, go);
    }
    try std.testing.expectEqual(first_round, p.size);
    try std.testing.expect(!p.server_clock);
    try std.testing.expectEqual(@as(?u64, 500), p.result_kbps);
}
