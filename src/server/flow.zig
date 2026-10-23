//! Connection output once the session is active: direct writes, dynamic channel
//! queues flushed within the send window by weighted fair queuing, UDP tunnel
//! queues, and continuous network auto-detection (MS-RDPBCGR 2.2.14).

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const x224 = @import("../proto/x224.zig");
const mcs = @import("../proto/mcs.zig");
const ad = @import("../proto/session_ext/autodetect.zig");
const socket = @import("../net/socket.zig");
const netdetect = @import("netdetect.zig");
const dvcqueue = @import("dvcqueue.zig");
const pacing = @import("pacing.zig");
const vc = @import("vc.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.flow);

/// No dynamic channel data is flushed while the transport holds more than this.
pub const transport_limit: usize = 8_000_000;
/// Total queued bytes beyond which the connection ends; slow readers are otherwise never disconnected.
pub const memory_guard: usize = 128 << 20;
/// No probe answered within this: local mode. Later probes unanswered this long are lost.
pub const answer_timeout_ms: i64 = 10_000;
/// Minimum backlog span of a local-mode drain rate sample.
pub const drain_sample_ns: u64 = 50 * std.time.ns_per_ms;

pub const Mode = enum {
    /// Connection sequence: blocking writes, nothing queued.
    off,
    /// Bytes in flight acknowledged by auto-detect RTT probes.
    probes,
    /// No auto-detect: bytes in flight = the local backlog.
    local,
};

pub const Stats = struct {
    /// Bytes written to the transport, counted or not.
    written: u64 = 0,
    dvc_bytes: u64 = 0,
    window_waits: u32 = 0,
    peak_in_flight: u32 = 0,
    peak_queued: usize = 0,
    peak_local: usize = 0,
};

pub const State = struct {
    mode: Mode = .off,
    nd: netdetect.Detector = .{},
    q: dvcqueue.WriteQueue = .{},
    /// Per-tunnel queues (vc.TunnelKind), flushed within each RDP-UDP window.
    tq: [2]dvcqueue.WriteQueue = .{ .{}, .{} },
    /// Time of the first probe (nowMs; 0: none yet), and whether any was answered.
    first_probe_ms: i64 = 0,
    answered: bool = false,
    drain: Drain = .{},
    /// The memory guard (tests lower it).
    guard: usize = memory_guard,
    peak_queued_total: usize = 0,
    /// The socket took nothing at the last write: wait for POLLOUT.
    blocked: bool = false,
    wait_ms: ?i64 = null,
    stats: Stats = .{},

    pub fn deinit(s: *State, gpa: std.mem.Allocator) void {
        s.q.deinit(gpa);
        for (&s.tq) |*t| t.deinit(gpa);
    }

    pub fn queuedTotal(s: *const State) usize {
        return s.q.total +| s.tq[0].total +| s.tq[1].total;
    }

    pub fn waiting(s: *const State, id: u32) usize {
        return s.q.waiting(id) +| s.tq[0].waiting(id) +| s.tq[1].waiting(id);
    }

    /// The bandwidth graphics are paced to (B/s; 0 unknown).
    pub fn rate(s: *const State) f64 {
        return switch (s.mode) {
            .probes => s.nd.bytesPerSecond(),
            .local => s.drain.bps orelse s.nd.bytesPerSecond(),
            .off => 0,
        };
    }

    pub fn rttMs(s: *const State) ?u32 {
        if (s.mode != .probes or !s.nd.base_known) return null;
        return netdetectRound(s.nd.srtt);
    }
};

fn netdetectRound(x: f64) u32 {
    if (!(x > 0)) return 0;
    return @intFromFloat(@min(x + 0.5, 4.0e9));
}

/// Assumed kbit/s for connectionType when nothing is measured (MS-RDPBCGR 2.2.1.3.2).
pub fn connectionTypeKbps(conn_type: ?u8) u64 {
    return switch (conn_type orelse 0) {
        ad.connection_type_modem => 56,
        ad.connection_type_broadband_low => 1_500,
        ad.connection_type_satellite => 2_000,
        ad.connection_type_broadband_high => 10_000,
        ad.connection_type_wan => 10_000,
        else => 100_000,
    };
}

/// Starting bandwidth (kbit/s) for continuous detection without a connect-time measure.
pub const default_kbps: u64 = 10_000;

/// Connect-time results seed the estimate.
pub fn start(conn: *Conn) void {
    const s = &conn.flow;
    const det = &conn.netchar.det;
    const interval = pacing.clampInterval(conn.vc.opts.frame_interval_ms);
    conn.pacing.interval_ms = interval;
    conn.pacing.client_ms = @floatFromInt(interval);
    if (det.enabled) {
        s.mode = .probes;
        const r = det.results;
        s.nd.seed(r.base_rtt, r.average_rtt, r.bandwidth orelse default_kbps, r.bandwidth != null);
    } else {
        s.mode = .local;
        const ct: ?u8 = if (conn.client.early_caps.valid_connection_type) conn.client.connection_type else null;
        s.nd.seed(null, null, connectionTypeKbps(ct), false);
    }
    log.debug("{s}: output flow: {t}, window {d} bytes, {d:.0} kbit/s", .{ conn.peer, s.mode, s.nd.window, s.nd.published });
}

/// `counted`: counts in flight and may trigger a probe; false for message channel control PDUs.
pub fn commit(conn: *Conn, counted: bool) conn_mod.Error!void {
    const n = conn.out.items.len;
    if (n == 0) return;
    const s = &conn.flow;
    if (conn.sendq.len() + s.queuedTotal() + n > s.guard) return conn.tooSlow();
    conn.sendq.push(conn.gpa, &conn.out) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    s.stats.written += n;
    if (counted) try wrote(conn, n);
}

/// Continuous detection runs once the connection sequence completes (MS-RDPBCGR 2.2.14.1.1).
fn wrote(conn: *Conn, n: usize) conn_mod.Error!void {
    const s = &conn.flow;
    if (s.mode != .probes or !conn.established) return;
    const due = s.nd.onWrite(@intCast(@min(n, std.math.maxInt(u32))));
    s.stats.peak_in_flight = @max(s.stats.peak_in_flight, s.nd.in_flight);
    if (due) try sendProbe(conn);
}

fn sendProbe(conn: *Conn) conn_mod.Error!void {
    const s = &conn.flow;
    const seq = nextSequence(conn);
    try sendRequest(conn, .{ .rtt = .{ .sequence_number = seq, .request_type = ad.rtt_request_continuous } });
    const now = conn_mod.nowMs();
    s.nd.probeSent(seq, conn_mod.nowNs());
    if (s.first_probe_ms == 0) s.first_probe_ms = now;
}

fn nextSequence(conn: *Conn) u16 {
    const d = &conn.netchar.det;
    while (true) {
        const seq = d.next_sequence;
        d.next_sequence +%= 1;
        var taken = false;
        for (d.pending[0..d.pending_len]) |p| {
            if (p.sequence_number == seq) taken = true;
        }
        if (!taken and !conn.flow.nd.probeOutstanding(seq)) return seq;
    }
}

/// Bypasses the queues and does not count in flight.
pub fn sendRequest(conn: *Conn, r: ad.Request) conn_mod.Error!void {
    var buf: [32]u8 = undefined;
    var list = std.ArrayList(u8).initBuffer(&buf);
    var w = bytes.Writer.init(&list, std.mem.Allocator.failing);
    ad.encodeRequestPdu(&w, r) catch unreachable; // valid, and small
    try conn.sendControl(conn.msg_channel.?, list.items);
}

pub fn queueDvc(conn: *Conn, id: u32, class: dvcqueue.Priority, compress: bool, msg: []const u8) conn_mod.Error!void {
    const s = &conn.flow;
    const before = s.q.total;
    if (conn.sendq.len() + s.queuedTotal() + msg.len > s.guard) return conn.tooSlow();
    try s.q.push(conn.gpa, id, class, compress, msg);
    s.stats.peak_queued = @max(s.stats.peak_queued, s.queuedTotal());
    s.peak_queued_total = @max(s.peak_queued_total, s.queuedTotal());
    if (id == graphics_channel) conn.pacing.queued(s.q.total - before, conn_mod.nowMs());
}

/// Sent without bulk compression as the tunnel's window allows.
pub fn queueTunnel(conn: *Conn, k: vc.TunnelKind, id: u32, class: dvcqueue.Priority, msg: []const u8) conn_mod.Error!void {
    const s = &conn.flow;
    const q = &s.tq[@backingInt(k)];
    const before = q.total;
    if (conn.sendq.len() + s.queuedTotal() + msg.len > s.guard) return conn.tooSlow();
    try q.push(conn.gpa, id, class, false, msg);
    s.stats.peak_queued = @max(s.stats.peak_queued, s.queuedTotal());
    s.peak_queued_total = @max(s.peak_queued_total, s.queuedTotal());
    if (id == graphics_channel) conn.pacing.queued(q.total - before, conn_mod.nowMs());
}

pub fn dropDvc(conn: *Conn, id: u32) void {
    var n = conn.flow.q.drop(conn.gpa, id);
    for (&conn.flow.tq) |*q| n += q.drop(conn.gpa, id);
    if (id == graphics_channel) conn.pacing.queued_now -|= n;
}

/// B/s, 0 unknown: the UDP tunnel's while RDPGFX is on one that knows it, else TCP's.
pub fn gfxRate(conn: *Conn) f64 {
    const d = conn.vc.dynamic(graphics_channel) orelse return conn.flow.rate();
    const k = d.tunnel orelse return conn.flow.rate();
    const t = conn.vc.tunnels[@backingInt(k)] orelse return conn.flow.rate();
    const f = t.rate orelse return conn.flow.rate();
    return f(t.ctx) orelse conn.flow.rate();
}

/// Data for a tunnel that is gone is dropped; its channels are back on DRDYNVC.
pub fn flushTunnels(conn: *Conn) conn_mod.Error!void {
    const s = &conn.flow;
    for (&s.tq, 0..) |*q, i| {
        if (q.total == 0) continue;
        const t = conn.vc.tunnels[i] orelse {
            while (q.chans.items.len > 0) _ = q.drop(conn.gpa, q.chans.items[0].id);
            continue;
        };
        var left: usize = if (t.room) |f| f(t.ctx) else std.math.maxInt(usize);
        if (left == 0) {
            s.stats.window_waits +|= 1;
            continue;
        }
        q.beginFlush();
        var gfx_bytes: usize = 0;
        while (left > 0) {
            const it = q.peek() orelse break;
            try t.send(t.ctx, it.pdu);
            const n = it.pdu.len;
            if (it.id == graphics_channel) gfx_bytes += n;
            q.take(it);
            s.stats.dvc_bytes += n;
            left -|= n;
        }
        try t.flush(t.ctx);
        if (gfx_bytes > 0) conn.pacing.sent(gfx_bytes, gfxRate(conn), conn_mod.nowMs());
    }
}

/// RDPGFX's ChannelId, mirroring channels.gfx_channel_id without importing graphics code.
const graphics_channel: u32 = 1;

/// Bytes the next flush may write; in local mode, the window minus the local backlog.
fn available(conn: *Conn, now_ms: i64) u32 {
    const s = &conn.flow;
    return switch (s.mode) {
        .probes => s.nd.availableBytes(now_ms),
        .local => blk: {
            const local = localBacklog(conn);
            s.stats.peak_local = @max(s.stats.peak_local, local);
            break :blk if (local < s.nd.window) @intCast(s.nd.window - local) else 0;
        },
        .off => std.math.maxInt(u32),
    };
}

/// The send queue plus the kernel's unsent bytes.
pub fn localBacklog(conn: *const Conn) usize {
    const info: ?socket.TcpInfo = if (conn.t.nonblocking) socket.tcpInfo(conn.t.fd) else null;
    return conn.sendq.len() + if (info) |i| @as(usize, i.notsent_bytes) else 0;
}

/// PDUs are framed and bulk-compressed only here, so they reach the wire in compression order.
/// `all`: ignore the window (before a Soft-Sync or close).
pub fn flushDvc(conn: *Conn, all: bool) conn_mod.Error!void {
    const s = &conn.flow;
    s.wait_ms = null;
    if (s.q.total == 0) return;
    const drdynvc = conn.vc.drdynvc orelse return;
    // Output built earlier goes first.
    try commit(conn, true);
    if (!all and conn.sendq.len() > transport_limit) return;
    const now = conn_mod.nowMs();
    const avail: u32 = if (all) std.math.maxInt(u32) else available(conn, now);
    if (avail == 0) {
        s.stats.window_waits +|= 1;
        s.wait_ms = waitMs(conn, now);
        return;
    }
    const measured = s.mode == .probes and !all;
    if (measured) s.nd.preFlush(@intCast(@min(avail, s.q.total)));
    s.q.beginFlush();
    var left: u64 = avail;
    var gfx_bytes: usize = 0;
    while (left > 0) {
        const it = s.q.peek() orelse break;
        if (measured and s.nd.preFlushItem()) try sendRequest(conn, .{ .bw_start = .{ .sequence_number = nextSequence(conn), .request_type = ad.bw_start_continuous } });
        try vc.sendStaticChunks(conn, drdynvc, it.pdu, it.compress);
        const n = it.pdu.len;
        if (it.id == graphics_channel) gfx_bytes += n;
        s.q.take(it);
        s.stats.dvc_bytes += n;
        left -|= n;
        try commit(conn, true);
        if (measured and s.nd.postFlushItem(@intCast(n))) try sendRequest(conn, .{ .bw_stop = .{ .sequence_number = nextSequence(conn), .request_type = ad.bw_stop_continuous } });
    }
    if (measured and s.nd.postFlush()) try sendRequest(conn, .{ .bw_stop = .{ .sequence_number = nextSequence(conn), .request_type = ad.bw_stop_continuous } });
    if (gfx_bytes > 0) conn.pacing.sent(gfx_bytes, s.rate(), now);
    if (s.q.total > 0 and !all) s.wait_ms = waitMs(conn, now);
}

/// 1..20 ms until the in-flight estimate drains the excess; probe answers wake the loop sooner.
fn waitMs(conn: *Conn, now_ms: i64) i64 {
    const s = &conn.flow;
    const bif: u64 = switch (s.mode) {
        .probes => s.nd.bytesInFlight(now_ms),
        else => localBacklog(conn),
    };
    const excess = bif -| s.nd.window + netdetect.chunk;
    const bps = @max(s.rate(), 1);
    const ms: i64 = @intFromFloat(@as(f64, @floatFromInt(excess)) * 1000.0 / bps);
    return std.math.clamp(ms, 1, 20);
}

pub fn onRttResponse(conn: *Conn, seq: u16) bool {
    const s = &conn.flow;
    const a = s.nd.onRttResponse(seq, conn_mod.nowNs()) orelse return false;
    s.answered = true;
    log.debug("{s}: RTT {d} ms (queueing {d} ms), {d} probes newer, {d} bytes acknowledged, {d} in flight of {d}", .{ conn.peer, a.rtt_ms, s.nd.queueingDelayMs(), a.newer, a.bytes, s.nd.in_flight, s.nd.window });
    return true;
}

pub fn onBwResults(conn: *Conn, time_delta: u32, byte_count: u32) bool {
    const s = &conn.flow;
    if (s.mode != .probes or s.nd.stops_out <= 0) return false;
    const sample = s.nd.onBwResults(time_delta, byte_count);
    if (sample) |kbps| log.debug("{s}: bandwidth sample {d:.0} kbit/s ({d} bytes in {d} ms): estimate {d:.0}, published {d:.0}", .{ conn.peer, kbps, byte_count, time_delta, s.nd.bw, s.nd.published });
    return true;
}

/// A client that never answers probes falls back to local mode.
pub fn tick(conn: *Conn) conn_mod.Error!void {
    const s = &conn.flow;
    if (s.mode == .probes and !s.answered and s.first_probe_ms != 0 and
        s.nd.outstanding >= netdetect.max_probes and conn_mod.nowMs() - s.first_probe_ms > answer_timeout_ms)
    {
        log.warn("{s}: the client answers no RTT probe: output paced to the local backlog", .{conn.peer});
        s.mode = .local;
    }
    if (s.mode == .probes and s.nd.outstanding > 0) {
        const n = s.nd.expireProbes(conn_mod.nowNs(), @as(u64, answer_timeout_ms) * std.time.ns_per_ms);
        if (n > 0) log.info("{s}: {d} RTT probes unanswered for {d} s: taken as lost", .{ conn.peer, n, @divTrunc(answer_timeout_ms, 1000) });
    }
    if (s.tq[0].total > 0 or s.tq[1].total > 0) try flushTunnels(conn);
    if (s.q.total > 0) return flushDvc(conn, false);
    // Keep evaluating so a probe becomes due when the window is full and none is out.
    if (s.mode == .probes and conn.established and s.nd.in_flight > 0) _ = s.nd.availableBytes(conn_mod.nowMs());
}

/// Shortens poll(2) `timeout` (ms, -1: none) while data waits for the window.
pub fn pollTimeout(conn: *const Conn, timeout: c_int) c_int {
    const ms = conn.flow.wait_ms orelse return timeout;
    const t: c_int = @intCast(ms);
    return if (timeout < 0) t else @min(timeout, t);
}

pub fn socketWrote(conn: *Conn, n: usize, left: usize, now_ns: u64) void {
    const s = &conn.flow;
    if (s.drain.wrote(n, left, now_ns) and s.mode == .local) {
        s.nd.setNewBandwidth(s.drain.bps.? * 8.0 / 1000.0);
        s.nd.adjustWindowSize();
    }
}

pub fn socketFull(conn: *Conn, now_ns: u64) void {
    conn.flow.blocked = true;
    conn.flow.drain.full(now_ns);
}

/// Local-mode B/s: the drain rate while backlogged, a 1/4 moving average of measured samples.
pub const Drain = struct {
    /// Backlog start (ns), and bytes written since.
    since_ns: ?u64 = null,
    bytes: u64 = 0,
    bps: ?f64 = null,

    pub fn wrote(d: *Drain, n: usize, left: usize, now_ns: u64) bool {
        const since = d.since_ns orelse return false;
        d.bytes +|= n;
        const el = now_ns -| since;
        if (left != 0 and el < drain_sample_ns) return false;
        var took = false;
        if (el >= drain_sample_ns / 2) {
            const bps = @as(f64, @floatFromInt(d.bytes)) * 1e9 / @as(f64, @floatFromInt(@max(el, 1)));
            d.bps = if (d.bps) |old| (old * 3 + bps) / 4 else bps;
            took = true;
        }
        d.since_ns = if (left == 0) null else now_ns;
        d.bytes = 0;
        return took;
    }

    pub fn full(d: *Drain, now_ns: u64) void {
        if (d.since_ns == null) {
            d.since_ns = now_ns;
            d.bytes = 0;
        }
    }
};

const testing = std.testing;

test "drain: rate stays at the link speed across busy and idle spells" {
    var d: Drain = .{};
    const ms = std.time.ns_per_ms;
    var now: u64 = 1000 * ms;
    for (0..60) |_| {
        // 5 s backlogged at 2 MB/s: 20 KB every 10 ms.
        d.full(now);
        for (0..500) |i| {
            now += 10 * ms;
            _ = d.wrote(20_000, if (i == 499) 0 else 1, now);
        }
        try testing.expect(d.bps.? > 1.9e6 and d.bps.? < 2.1e6);
        now += 10_000 * ms;
    }
    const r = d.bps.?;
    d.full(now);
    try testing.expect(!d.wrote(1000, 0, now + 1 * ms));
    try testing.expectEqual(r, d.bps.?);
    d.full(now);
    _ = d.wrote(std.math.maxInt(usize), 1, now);
    _ = d.wrote(std.math.maxInt(usize), 0, now + drain_sample_ns);
    try testing.expect(std.math.isFinite(d.bps.?));
}
