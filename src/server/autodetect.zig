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
pub const connect_time_rtt_samples: u32 = 7;
/// Bytes per Bandwidth Measure Payload; keeps each PDU under a 2-byte PER length.
pub const payload_size: usize = 16000;
/// Round sizes in bytes; rounds averaging under `fast_round_ms` double the next size.
pub const first_round: u32 = 4000;
pub const max_round: u32 = 256000;
pub const fast_round_ms: f64 = 20;
pub const settled_rounds: u32 = 7;

pub const State = struct {
    det: ad.Detector = .{},
    /// Last connect-time Bandwidth Measure Results (timeDelta in ms, byteCount).
    last_results: ?struct { time: u32, bytes: u32 } = null,
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
    const deadline = start + connect_time_budget_ms;
    // Random so nothing on the path can compress it (MS-RDPBCGR 2.2.14.1.3).
    const payload = try conn.gpa.alloc(u8, payload_size);
    defer conn.gpa.free(payload);
    var prng = std.Random.DefaultPrng.init(@bitCast(start));
    prng.random().bytes(payload);

    var size: u32 = first_round;
    var rounds: u32 = 0;
    var round_ms: f64 = 0;
    var total_rounds: u32 = 0;
    while (true) {
        if (s.det.results.rtt_samples + @as(u32, @intCast(s.det.pendingRtt())) < connect_time_rtt_samples)
            try send(conn, s.det.rttRequest(stamp(conn_mod.nowMs())) catch unreachable);
        s.last_results = null;
        try sendRound(conn, size, payload);
        total_rounds += 1;
        while (s.det.bw_stopped != null and !s.det.synced) {
            if (!try waitAnswer(conn, deadline)) break;
        }
        if (s.det.synced) break;
        const r = s.last_results orelse break; // no answer in time
        rounds += 1;
        round_ms += @floatFromInt(r.time);
        if (rounds >= 3) {
            const avg = round_ms / @as(f64, @floatFromInt(rounds));
            if (size < max_round and avg < fast_round_ms) {
                size = @min(size * 2, max_round);
                rounds = 0;
                round_ms = 0;
            } else if (avg > 400 and size == first_round) {
                size = @max(@as(u32, @intFromFloat(32000.0 / avg * 30.0 * 0.125)), 1600);
                rounds = 0;
                round_ms = 0;
            }
        }
        if (rounds >= settled_rounds and s.det.results.rtt_samples >= connect_time_rtt_samples) break;
        if (conn_mod.nowMs() >= deadline) break;
    }
    while (s.det.pendingRtt() > 0 and s.det.results.rtt_samples < connect_time_rtt_samples and !s.det.synced) {
        if (!try waitAnswer(conn, deadline)) break;
    }

    const r = s.det.getResults() catch unreachable;
    if (s.det.netcharResult()) |res| {
        try send(conn, res);
        log.info("{s}: network: base RTT {?d} ms, average RTT {?d} ms, bandwidth {?d} kbps ({d} rounds, {d} ms)", .{
            conn.peer, r.base_rtt, r.average_rtt, r.bandwidth, total_rounds, conn_mod.nowMs() - start,
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
