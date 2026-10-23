//! Multitransport on a connection (MS-RDPBCGR 1.3.1.1 phase 8, MS-RDPEMT): UDP tunnels requested after
//! licensing, the dynamic channels moved onto them by Soft-Sync (MS-RDPEDYC 3.1.5.3), auto-detect over
//! them (MS-RDPBCGR 1.3.9). A failed tunnel's channels go back to DRDYNVC and Graphics starts over.

const std = @import("std");
const c = @import("c");
const bytes = @import("../core/bytes.zig");
const mt = @import("../net/multitransport.zig");
const ad = @import("../proto/session_ext/autodetect.zig");
const gcc = @import("../proto/gcc.zig");
const vc = @import("vc.zig");
const udp = @import("udp.zig");
const channels = @import("channels.zig");
const features = @import("features.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.multitransport);

/// What the server offers (MS-RDPBCGR 2.2.1.4.6).
pub const server_flags: u32 = mt.transporttype_udpfecr | mt.transporttype_udpfecl | mt.softsync_tcp_to_udp;

/// Soft-Sync waits this long for a tunnel still being built once another is ready.
pub const soft_sync_wait_ms: i64 = 5000;
/// Tunnel Data PDUs held before the Soft-Sync Response (MS-RDPEDYC 3.3.5.3.2); more fail the tunnel.
pub const max_held_pdus = 4096;
/// Tunnel bandwidth measurement period and Start-to-Stop span (MS-RDPBCGR 1.3.9).
pub const bw_period_ms: i64 = 10_000;
pub const bw_window_ms: i64 = 1000;

/// SC_MULTITRANSPORT flags, or null: needs the UDP front end, UDPFECR or UDPFECL with
/// SOFTSYNC_TCP_TO_UDP (MS-RDPEDYC 3.1.5.3), the message channel and DRDYNVC (MS-RDPEMT 1.5).
pub fn serverFlags(conn: *const Conn) ?u32 {
    if (conn.vc.opts.udp == null) return null;
    const cf = conn.client.multitransport_flags orelse return null;
    if (cf & (mt.transporttype_udpfecr | mt.transporttype_udpfecl) == 0) return null;
    if (cf & mt.softsync_tcp_to_udp == 0) return null;
    if (!conn.client.has_msgchannel) return null;
    for (conn.client.channelSlice()) |ch| {
        if (std.ascii.eqlIgnoreCase(ch.nameSlice(), "drdynvc")) return server_flags;
    }
    return null;
}

const wants_lossy = blk: {
    for (features.list) |T| {
        if (@hasDecl(T, "dynamic_channels")) for (T.dynamic_channels) |d| if (d.tunnel == .lossy) break :blk true;
    }
    break :blk false;
};

pub const Stats = struct {
    /// Initiate Multitransport Requests sent, answered S_OK, E_ABORT.
    requested: u8 = 0,
    succeeded: u8 = 0,
    aborted: u8 = 0,
    /// Tunnels handed over by the front end; lost again.
    tunnels: u8 = 0,
    failed: u8 = 0,
    version: u16 = 0,
    tx_pdus: u64 = 0,
    rx_pdus: u64 = 0,
    /// RDP-UDP data packets of the tunnels gone: sent, retransmitted.
    udp_packets: u64 = 0,
    udp_retransmits: u64 = 0,
    /// ACK vectors reaching back before the first datagram.
    udp_odd_acks: u64 = 0,
    bandwidth_kbps: ?u64 = null,
    /// Most bytes an RDP-UDP transfer held beyond its windows (flow.zig leaves no more room).
    peak_unsent: usize = 0,
};

const Req = struct {
    state: enum { none, sent, succeeded, aborted } = .none,
    id: u32 = 0,
};

const Tunnel = struct {
    m: *Multitransport,
    kind: vc.TunnelKind,
    link: *udp.Link,
    failed: bool = false,
    /// Ended by the client (close_notify, its E_ABORT): not lost to it.
    by_client: bool = false,
    /// TLS ciphertext gathered into full datagrams for the RDP-UDP stream.
    staging: std.ArrayList(u8) = .empty,
    rx: []u8,
    det: ad.Detector = .{},
    /// A subheader for the next Tunnel Data PDU (Bandwidth Start / Stop).
    sub: ?[16]u8 = null,
    sub_len: usize = 0,
    next_bw_ms: i64 = 0,
    bw_started_ms: ?i64 = null,
    /// PDUs sent since the Start rode out.
    since_start: u32 = 0,

    fn handle(t: *Tunnel) vc.Tunnel {
        return .{ .ctx = t, .send = send, .flush = flush, .room = room, .rate = rate };
    }

    fn of(ctx: *anyopaque) *Tunnel {
        return @ptrCast(@alignCast(ctx));
    }

    fn transport(t: *const Tunnel) ad.Transport {
        return if (t.kind == .reliable) .tunnel_reliable else .tunnel_lossy;
    }

    /// One DVC PDU per Tunnel Data PDU (MS-RDPEDYC 1.3.1.2), with the waiting subheader.
    fn send(ctx: *anyopaque, pdu: []const u8) vc.Error!void {
        const t = of(ctx);
        if (t.failed) return; // lost, as on the dead tunnel
        var subs: [1]mt.SubHeader = undefined;
        var n: usize = 0;
        if (t.sub) |*s| {
            subs[0] = .{ .sub_type = s[1], .data = s[2..t.sub_len] };
            n = 1;
        }
        t.link.tunnel.sendWith(subs[0..n], pdu) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return t.fail(@errorName(err)),
        };
        if (n > 0) {
            t.sub = null;
            if (t.bw_started_ms == null and t.det.bw_started != null) t.bw_started_ms = conn_mod.nowMs();
        }
        t.since_start +|= 1;
        t.m.stats.tx_pdus += 1;
    }

    /// What the transfer takes without waiting for its windows; a lost tunnel takes anything.
    fn room(ctx: *anyopaque) usize {
        const t = of(ctx);
        if (t.failed) return std.math.maxInt(usize);
        return t.link.conn.sendRoom() -| t.staging.items.len;
    }

    fn rate(ctx: *anyopaque) ?f64 {
        const t = of(ctx);
        if (t.failed) return null;
        return t.link.conn.windowRate();
    }

    fn flush(ctx: *anyopaque) vc.Error!void {
        try of(ctx).pump(udp.nowUs());
    }

    fn pump(t: *Tunnel, now: u64) vc.Error!void {
        if (t.failed) return;
        const k = t.link;
        var buf: [16 * 1024 + 256]u8 = undefined;
        while (k.tunnel.pollTransport(&buf) catch |err| return t.fail(@errorName(err))) |ct| {
            // RDP-UDP-R carries a byte stream in MTU-sized packets; DTLS datagrams go one by one (MS-RDPEMT 1.4).
            if (k.mode == .reliable) {
                try t.staging.appendSlice(t.m.conn.gpa, ct);
            } else {
                k.conn.send(ct) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return t.fail(@errorName(err)),
                };
            }
        }
        if (t.staging.items.len > 0) {
            defer t.staging.clearRetainingCapacity();
            k.conn.send(t.staging.items) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return t.fail(@errorName(err)),
            };
        }
        var out: [mt.max_mtu]u8 = undefined;
        while (k.conn.poll(now, &out) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return t.fail(@errorName(err)),
        }) |d| t.m.session.sendTo(k.addr, d);
        t.m.stats.peak_unsent = @max(t.m.stats.peak_unsent, k.conn.unsentBytes());
        if ((k.conn.state() catch .closed) == .closed) {
            var b: [160]u8 = undefined;
            const r = k.conn.closeReason() orelse return t.fail("RDP-UDP connection closed");
            return t.fail(std.fmt.bufPrint(&b, "RDP-UDP connection closed ({f})", .{r}) catch "RDP-UDP connection closed");
        }
    }

    fn input(t: *Tunnel, d: []const u8, now: u64) vc.Error!void {
        if (t.failed) return;
        const k = t.link;
        // Malformed datagrams change nothing (MS-RDPEUDP 5.1.2).
        k.conn.onDatagram(d, now) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return log.debug("{s}: bad RDP-UDP datagram ignored: {t}", .{ t.m.conn.peer, err }),
        };
        var plain: [16 * 1024 + 256]u8 = undefined;
        while (k.conn.receive(&plain) catch |err| return t.fail(@errorName(err))) |ct| {
            k.tunnel.onTransport(ct) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return t.fail(@errorName(err)),
            };
        }
        if ((k.tunnel.phase() catch .closed) == .closed) return t.failByClient("closed by the client");
        if (!vc.tunnelInputAllowed(t.m.conn) and k.tunnel.receivedCount() > max_held_pdus) return t.fail("too much data before the Soft-Sync Response");
    }

    /// Once they may be read (MS-RDPEDYC 3.3.5.3.2).
    fn deliver(t: *Tunnel) vc.Error!void {
        if (!vc.tunnelInputAllowed(t.m.conn)) return;
        while (!t.failed) {
            const d = (t.link.tunnel.receiveData(t.rx) catch |err| return t.fail(@errorName(err))) orelse break;
            if (d.subheaders.len > 0) t.onSubheaders(d.subheaders);
            if (d.payload.len == 0) continue;
            t.m.stats.rx_pdus += 1;
            try vc.onTunnelPdu(t.m.conn, d.payload);
        }
    }

    /// Refused subheaders are dropped, as on the message channel.
    fn onSubheaders(t: *Tunnel, raw: []const u8) void {
        var it = mt.SubHeaderIterator{ .raw = raw };
        while (it.next() catch null) |sh| {
            const m = ad.fromSubHeader(sh, t.transport()) catch |err| {
                log.debug("{s}: tunnel subheader dropped: {t}", .{ t.m.conn.peer, err });
                continue;
            };
            const r = switch (m) {
                .response => |r| r,
                .request => continue,
            };
            const sample = t.det.onResponse(r, @intCast(@max(conn_mod.nowMs(), 0))) catch |err| {
                log.debug("{s}: tunnel auto-detect response dropped: {t}", .{ t.m.conn.peer, err });
                continue;
            };
            switch (sample) {
                .bandwidth => |kbps| {
                    t.m.stats.bandwidth_kbps = kbps;
                    log.debug("{s}: UDP bandwidth {d} kbps", .{ t.m.conn.peer, kbps });
                },
                else => {},
            }
        }
    }

    /// MS-RDPBCGR 1.3.9, 2.2.14.1.2, 2.2.14.1.4: each rides on the next Tunnel Data PDU.
    fn detect(t: *Tunnel, now_ms: i64) ?i64 {
        if (!t.det.enabled or t.failed or t.m.conn.vc.soft_sync != .done) return null;
        if (t.sub != null) return null; // waiting for a PDU to ride on
        if (t.bw_started_ms) |s| {
            if (now_ms - s < bw_window_ms or t.since_start < 2) return s + bw_window_ms;
            t.bw_started_ms = null;
            t.next_bw_ms = now_ms + bw_period_ms;
            t.queueSub(t.det.bwStop(&.{}) catch return null);
            return t.next_bw_ms;
        }
        if (now_ms < t.next_bw_ms) return t.next_bw_ms;
        t.since_start = 0;
        t.queueSub(t.det.bwStart() catch return null);
        return null;
    }

    fn queueSub(t: *Tunnel, r: ad.Request) void {
        var buf: [16]u8 = undefined;
        var list = std.ArrayList(u8).initBuffer(&buf);
        var w = bytes.Writer.init(&list, std.mem.Allocator.failing);
        ad.encodeTunnelSubHeader(&w, .{ .request = r }, t.transport()) catch return;
        t.sub = buf;
        t.sub_len = list.items.len;
    }

    /// The client ended the tunnel itself: it knows its channels are back on TCP.
    fn failByClient(t: *Tunnel, why: []const u8) void {
        t.by_client = true;
        t.fail(why);
    }

    /// Channels go back to TCP; sweep frees the Link later, as a DVC write may still hold it.
    fn fail(t: *Tunnel, why: []const u8) void {
        if (t.failed) return;
        t.failed = true;
        const m = t.m;
        m.stats.failed +|= 1;
        log.info("{s}: UDP tunnel ({s}) lost: {s}; falling back to TCP", .{ m.conn.peer, @tagName(t.kind), why });
        if (m.conn.vc.tunnels[@backingInt(t.kind)]) |cur| if (cur.ctx == @as(*anyopaque, t)) {
            if (vc.dropTunnel(m.conn, t.kind, channels.gfx_channel_id)) m.resync_gfx = true;
        };
        m.session.forget(t.link.addr);
        // Windows clients cannot move their channels off a lost tunnel; ending now as a network
        // loss lets them reconnect at once and resume.
        const vs = &m.conn.vc;
        const client_on_it = vs.soft_sync == .done and switch (t.kind) {
            .reliable => vs.client_tunnels.reliable,
            .lossy => vs.client_tunnels.lossy,
        };
        if (client_on_it and !t.by_client and !t.link.tunnel.closedByPeer()) m.client_tunnel_lost = true;
    }

    fn destroy(t: *Tunnel, gpa: std.mem.Allocator) void {
        const n = t.link.conn.counters();
        t.m.stats.udp_packets += n.sent;
        t.m.stats.udp_retransmits += n.retransmits;
        t.m.stats.udp_odd_acks += n.odd_acks;
        t.link.deinit(gpa);
        t.staging.deinit(gpa);
        gpa.free(t.rx);
        gpa.destroy(t);
    }
};

pub const Multitransport = struct {
    pub const start_stage: vc.Stage = .licensed;
    pub const Error = error{BadMultitransportPdu};

    conn: *Conn,
    session: *udp.Session,
    /// By TunnelKind.
    reqs: [2]Req = .{ .{}, .{} },
    tunnels: [2]?*Tunnel = .{ null, null },
    items: std.ArrayList(udp.Item) = .empty,
    ready_ms: ?i64 = null,
    resync_gfx: bool = false,
    /// A tunnel carrying the client's channels was lost: the connection ends as a network loss.
    client_tunnel_lost: bool = false,
    stats: Stats = .{},

    pub fn init(c_: *Conn) vc.Error!?Multitransport {
        const sf = serverFlags(c_) orelse return null;
        if (c_.msg_channel == null) return null;
        const l = c_.vc.opts.udp.?;
        const s = l.join(c_.client.multitransport_flags.?, sf, c_.peer) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                log.warn("{s}: no multitransport: {t}", .{ c_.peer, err });
                return null;
            },
        };
        return .{ .conn = c_, .session = s };
    }

    pub fn deinit(m: *Multitransport) void {
        const gpa = m.conn.gpa;
        m.conn.vc.tunnels = .{ null, null };
        for (&m.tunnels) |*t| if (t.*) |x| {
            x.destroy(gpa);
            t.* = null;
        };
        for (m.items.items) |it| it.deinit(gpa);
        m.items.deinit(gpa);
        m.session.leave();
        const st = m.stats;
        if (st.tunnels > 0) log.info("{s}: UDP: {d} DVC PDUs sent, {d} received; {d} RDP-UDP data packets sent, {d} retransmitted", .{ m.conn.peer, st.tx_pdus, st.rx_pdus, st.udp_packets, st.udp_retransmits });
        if (st.udp_odd_acks > 0) log.warn("{s}: UDP: {d} ACK vector(s) reached back before the first datagram: the client codes its ACK runs otherwise than Windows (lost datagrams may be taken as received)", .{ m.conn.peer, st.udp_odd_acks });
    }

    /// MS-RDPBCGR 1.3.1.1 phase 8: Initiate Multitransport Requests (2.2.15.1).
    pub fn start(m: *Multitransport) vc.Error!void {
        const kinds = if (wants_lossy) [_]vc.TunnelKind{ .reliable, .lossy } else [_]vc.TunnelKind{.reliable};
        for (kinds) |k| {
            const proto: u16 = if (k == .reliable) mt.protocol_udpfecr else mt.protocol_udpfecl;
            const r = m.session.request(proto) catch |err| switch (err) {
                error.NotNegotiated => continue, // the client lacks that transport
                error.OutOfMemory => return error.OutOfMemory,
                else => return log.warn("{s}: no multitransport request: {t}", .{ m.conn.peer, err }),
            };
            var buf: [32]u8 = undefined;
            var list = std.ArrayList(u8).initBuffer(&buf);
            var w = bytes.Writer.init(&list, std.mem.Allocator.failing);
            mt.encodeInitiateRequest(&w, r) catch unreachable;
            try m.conn.sendMcs(m.conn.msg_channel.?, list.items);
            std.crypto.secureZero(u8, &buf);
            m.reqs[@backingInt(k)] = .{ .state = .sent, .id = r.request_id };
            m.stats.requested += 1;
            log.info("{s}: multitransport: requested a {s} UDP tunnel (request {d})", .{ m.conn.peer, @tagName(k), r.request_id });
        }
    }

    /// MS-RDPBCGR 2.2.15.2, 3.3.5.15.2; other message channel PDUs are someone else's.
    pub fn message(m: *Multitransport, pdu: []const u8) vc.Error!void {
        if (pdu.len < 2 or std.mem.readInt(u16, pdu[0..2], .little) & mt.sec_transport_rsp == 0) return;
        const r = mt.decodeInitiateResponse(pdu) catch return error.BadMultitransportPdu;
        const k: vc.TunnelKind = for (m.reqs, 0..) |q, i| {
            if (q.state == .sent and q.id == r.request_id) break @fromBackingInt(@intCast(i));
        } else return log.debug("{s}: multitransport response for request {d} (ignored)", .{ m.conn.peer, r.request_id });
        const outcome = m.session.onResponse(r) catch |err| return log.debug("{s}: multitransport response refused: {t}", .{ m.conn.peer, err });
        switch (outcome) {
            .aborted => {
                m.reqs[@backingInt(k)].state = .aborted;
                m.stats.aborted += 1;
                log.info("{s}: the client could not build the {s} UDP tunnel (0x{x:0>8}); staying on TCP", .{ m.conn.peer, @tagName(k), r.hr_response });
                // A tunnel it built anyway is not used.
                if (m.tunnels[@backingInt(k)]) |t| t.failByClient("given up by the client");
            },
            .succeeded => {
                m.reqs[@backingInt(k)].state = .succeeded;
                m.stats.succeeded += 1;
                log.info("{s}: the client has the {s} UDP tunnel", .{ m.conn.peer, @tagName(k) });
            },
        }
        try m.advance();
    }

    pub fn pollFd(m: *Multitransport) ?vc.Poll {
        return .{ .fd = m.session.event_fd };
    }

    pub fn onFd(m: *Multitransport, _: c_short) vc.Error!void {
        const gpa = m.conn.gpa;
        try m.session.take(gpa, &m.items);
        const now = udp.nowUs();
        // Each item is freed as it is used, even when one fails.
        var i: usize = 0;
        defer {
            for (m.items.items[i..]) |it| it.deinit(gpa);
            m.items.clearRetainingCapacity();
        }
        while (i < m.items.items.len) {
            const it = m.items.items[i];
            i += 1;
            switch (it) {
                .link => |k| try m.attach(k),
                .datagram => |d| {
                    defer gpa.free(d.bytes);
                    for (m.tunnels) |t| if (t) |x| if (x.link.addr.eql(d.addr)) {
                        try x.input(d.bytes, now);
                        break;
                    };
                },
            }
        }
        try m.advance();
    }

    pub fn tick(m: *Multitransport, now_ms: i64) vc.Error!?i64 {
        try m.advance();
        if (m.client_tunnel_lost) {
            log.info("{s}: the client's channels were on the lost UDP tunnel: ending the connection for its reconnect", .{m.conn.peer});
            return error.UdpTunnelLost;
        }
        var wake: ?i64 = null;
        for (m.tunnels) |t| if (t) |x| {
            if (x.failed) continue;
            if (x.link.conn.nextTimeout() catch null) |at_us| {
                const at: i64 = @intCast((at_us + 999) / 1000);
                wake = earliest(wake, @max(at, now_ms + 1));
            }
            if (x.detect(now_ms)) |at| wake = earliest(wake, @max(at, now_ms + 1));
        };
        if (m.ready_ms) |r| if (m.conn.vc.soft_sync == .none) {
            wake = earliest(wake, @max(r + soft_sync_wait_ms, now_ms + 1));
        };
        return wake;
    }

    fn earliest(a: ?i64, b: i64) i64 {
        return if (a) |x| @min(x, b) else b;
    }

    fn attach(m: *Multitransport, k: *udp.Link) vc.Error!void {
        const gpa = m.conn.gpa;
        const kind: vc.TunnelKind = if (k.mode == .reliable) .reliable else .lossy;
        const slot = &m.tunnels[@backingInt(kind)];
        if (slot.* != null or m.reqs[@backingInt(kind)].id != k.request_id) {
            // A second tunnel for one request cannot pass the Connection Store.
            m.session.forget(k.addr);
            k.deinit(gpa);
            return;
        }
        const rx = gpa.alloc(u8, 0xFF + 0xFFFF) catch |err| {
            k.deinit(gpa);
            return err;
        };
        const t = gpa.create(Tunnel) catch |err| {
            gpa.free(rx);
            k.deinit(gpa);
            return err;
        };
        t.* = .{ .m = m, .kind = kind, .link = k, .rx = rx };
        t.det = .{ .enabled = m.conn.netchar.det.enabled, .phase = .continuous };
        t.next_bw_ms = conn_mod.nowMs() + bw_window_ms;
        slot.* = t;
        m.stats.tunnels += 1;
        m.stats.version = k.version;
        var abuf: [64]u8 = undefined;
        log.info("{s}: UDP tunnel ({s}, RDP-UDP version {d}) from {s} is up", .{ m.conn.peer, @tagName(kind), k.version, k.addr.text(&abuf) });
        try t.pump(udp.nowUs());
    }

    fn advance(m: *Multitransport) vc.Error!void {
        const now = udp.nowUs();
        for (m.tunnels) |t| if (t) |x| try x.pump(now);
        for (m.tunnels) |t| if (t) |x| try x.deliver();
        m.sweep();
        try m.softSync();
        if (m.resync_gfx) {
            m.resync_gfx = false;
            try channels.resync(m.conn);
        }
    }

    fn sweep(m: *Multitransport) void {
        for (&m.tunnels) |*t| if (t.*) |x| if (x.failed) {
            x.destroy(m.conn.gpa);
            t.* = null;
        };
    }

    /// MS-RDPEDYC 3.3.5.3.1: once every requested tunnel is up, or given up (E_ABORT, failed, or
    /// not ready soft_sync_wait_ms after another), and the dynamic channels are open.
    fn softSync(m: *Multitransport) vc.Error!void {
        const readiness = vc.softSyncReadiness(m.conn);
        if (readiness == .no) return;
        var ts: [2]?vc.Tunnel = .{ null, null };
        var waiting = false;
        for (m.reqs, 0..) |q, i| {
            const t = m.tunnels[i];
            switch (q.state) {
                .none, .aborted => {},
                .sent => waiting = true,
                .succeeded => if (t) |x| {
                    if (!x.failed) ts[i] = x.handle();
                } else {
                    waiting = true; // S_OK came before the tunnel got here
                },
            }
        }
        if (ts[0] == null and ts[1] == null) return;
        const now = conn_mod.nowMs();
        if (m.ready_ms == null) m.ready_ms = now;
        if ((waiting or readiness == .creates_pending) and now - m.ready_ms.? < soft_sync_wait_ms) return;
        _ = try vc.softSync(m.conn, ts);
    }
};
