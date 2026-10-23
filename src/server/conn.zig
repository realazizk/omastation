//! One RDP server connection: the connection sequence (MS-RDPBCGR 1.3.1.1), then the active
//! session loop, which never blocks on the network (output is queued and paced).

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const transport_mod = @import("../net/transport.zig");
const socket = @import("../net/socket.zig");
const sendq_mod = @import("../net/sendq.zig");
pub const pacing = @import("pacing.zig");
pub const flow = @import("flow.zig");
const tls = @import("../net/tls.zig");
const x224 = @import("../proto/x224.zig");
const mcs = @import("../proto/mcs.zig");
const gcc = @import("../proto/gcc.zig");
const rdp = @import("../proto/rdp.zig");
const caps = @import("../proto/caps.zig");
const fastpath = @import("../proto/fastpath.zig");
const framebuffer = @import("framebuffer.zig");
const auth = @import("auth.zig");
const credssp = @import("../sec/credssp.zig");
pub const channels = @import("channels.zig");
pub const surfaces = @import("surfaces.zig");
pub const vc = @import("vc.zig");
const encoder_mod = @import("encoder.zig");
const legacy = @import("legacy.zig");
const pointer_mod = @import("pointer.zig");
const pointer_proto = @import("../proto/pointer.zig");
const deadline = @import("deadline.zig");
pub const autodetect = @import("autodetect.zig");
const compression = @import("compression.zig");
const adapt = @import("adapt.zig");
const bulk = @import("../codec/bulk.zig");
const multitransport = @import("multitransport.zig");
const seat_mod = @import("seat.zig");
const desktop_mod = @import("../session/desktop.zig");
const multimon = @import("../session/multimon.zig");
const hypr = @import("../session/hypr.zig");
const altdrag = @import("../session/altdrag.zig");
const wl_capture = @import("../wl/capture.zig");
const session_info = @import("session_info.zig");
const remoteapp = @import("remoteapp.zig");
pub const flight = @import("flight.zig");
const c = @import("c");

const log = std.log.scoped(.conn);

pub const Error = error{
    ProtocolError,
    ClientDisconnected,
    UnsupportedSecurity,
    AuthenticationFailed,
    /// More output is queued for the client than flow.memory_guard allows.
    ClientTooSlow,
} || transport_mod.Error || x224.Error || mcs.Error || gcc.Error || rdp.Error ||
    fastpath.Error || std.mem.Allocator.Error || @import("../proto/vchan.zig").Error ||
    @import("../proto/dvc.zig").Error || @import("../proto/gfx.zig").Error || @import("../proto/disp.zig").Error ||
    desktop_mod.Error || error{ DesktopFailed, CompositorGone, UdpTunnelLost, UnsupportedPixelFormat, InvalidDimensions } ||
    @import("features.zig").Error || bulk.Error;

/// Desktop takeover settings; null serves a test pattern instead.
pub const DesktopConfig = struct {
    ipc: hypr.Ipc,
    seat: *seat_mod.Seat,
    lock_command: []const u8 = "omarchy-system-lock",
    helper_socket: [:0]const u8 = "/run/omastation/helper.sock",
    require_fence: bool = false,
    /// How long remote mode waits for a dropped client to reconnect, ms; 0 ends it at once.
    reconnect_grace_ms: u32 = 0,
    /// Option + drag twins of the SUPER mouse bindings.
    alt_drag: altdrag.Mode = .auto,
    binds_state_path: ?[:0]const u8 = null,
    console_state_path: ?[:0]const u8 = null,
    capture_backend: wl_capture.Backend = .ext,
    cursor: desktop_mod.CursorMode = .auto,
};

/// Covers clients' auto-reconnect attempts (about 20, 5 s apart) plus drop detection on both sides.
pub const default_reconnect_grace_ms: u32 = 120_000;

/// How clients authenticate. Shared, read-only, by all connections.
pub const AuthConfig = struct {
    store: *const auth.Store,
    /// PAM service that checks the delegated password; null skips PAM (development only).
    pam_service: ?[:0]const u8,
    /// Accept TLS without NLA. Unauthenticated: development only.
    allow_tls_without_nla: bool = false,
    /// Select PROTOCOL_HYBRID_EX when offered (MS-RDPBCGR 2.2.10.2).
    use_hybrid_ex: bool = true,
    /// UTF-16LE NetBIOS / DNS computer name for the NTLM challenge.
    nb_computer: []const u8,
    dns_computer: []const u8,
};

pub const TestSource = struct {
    ctx: *anyopaque,
    pump: *const fn (ctx: *anyopaque, c: *Conn) Error!void,
};

pub const Conn = struct {
    gpa: std.mem.Allocator,
    t: transport_mod.Transport,
    tls_ctx: *tls.Context,
    auth_cfg: *const AuthConfig,
    /// Authenticated user (ASCII, from the verifier store), set after NLA.
    user: ?[]const u8 = null,
    /// PDUs being built; `flush` moves them to `sendq`.
    out: std.ArrayList(u8) = .empty,
    sendq: sendq_mod.SendQueue = .{},
    flow: flow.State = .{},
    pacing: pacing.State = .{},
    longest_pass_ms: u32 = 0,
    peer: []const u8,

    requested_protocols: x224.Protocol = .{},
    /// What the RDP_NEG_RSP selected (the client echoes it in CS_CORE).
    selected_protocol: x224.Protocol = .{},
    client: gcc.ClientData = .{},
    /// Client Info PDU flags (MS-RDPBCGR 2.2.1.11.1.1).
    info_flags: u32 = 0,
    remoteapp: bool = false,
    /// Set Error Info code for a session a feature ended (requestEnd).
    end_errinfo: ?u32 = null,
    client_caps: caps.ClientCaps = .{},
    pointer: pointer_mod.State = .{},
    /// Static channel ids in the order the client listed them.
    channel_ids: [gcc.max_channels]u16 = undefined,
    msg_channel: ?u16 = null,
    /// Allocated after the static and message channels, as Windows does.
    user_id: u16 = 0,
    fb: ?framebuffer.Framebuffer = null,
    output_suppressed: bool = false,
    /// Fast-path output supported; otherwise slow-path Update PDUs.
    fastpath_output: bool = true,
    bpp: u16 = 32,
    /// Deactivation-Reactivation under way: no updates until the Font List.
    reactivating: bool = false,
    /// Since when (nowMs) RDP-1's frames have mismatched the session size.
    odd_size_since_ms: ?i64 = null,
    odd_size_taken: bool = false,
    odd_size_grace_ms: i64 = 2000,
    input_events: u64 = 0,
    ch: channels.State = .{},
    surfaces: surfaces.State = .{},
    vc: vc.State = .{},
    /// Desktop size as told to the client (Demand Active, ResetGraphics).
    width: u16 = 0,
    height: u16 = 0,
    deadline: deadline.Handle = .{},
    netchar: autodetect.State = .{},
    bulk: compression.State = .{},
    /// Finalization done (Font Map sent).
    established: bool = false,
    established_ms: i64 = 0,
    desktop_cfg: ?*const DesktopConfig = null,
    desktop: ?*desktop_mod.Desktop = null,
    /// This connection's place on the seat once NLA passed (desktop mode).
    claim: ?seat_mod.Claim = null,
    seat: ?*seat_mod.Seat = null,
    /// The Client Info names are not the user NLA logged on (3.3.5.10.1).
    logon_names_changed: bool = false,
    arc_valid: bool = false,
    arc_cookie: seat_mod.Seat.Cookie = .none,
    /// The desktop was kept for this reconnect and resumed as it was.
    resumed: bool = false,
    /// Lost to the network without a goodbye: the desktop may wait for a reconnect.
    dropped: bool = false,
    /// Ending with the desktop waiting for a reconnect (decided in deinit).
    lingering: bool = false,
    last_send_ms: i64 = 0,
    /// The NLA password (UTF-8), kept only until it unlocks the lock screen; wiped on use and disconnect.
    secret: ?[]u8 = null,
    enc: encoder_mod.Encoder,
    /// Test pattern mode: animate at 60 fps (load generator).
    animate: bool = false,
    /// Test pattern mode: fine noise over the pattern (load generator).
    test_detail: bool = false,
    /// Test pattern mode with `animate`: a video of this size plays instead.
    test_video: ?[2]u16 = null,
    test_source: ?TestSource = null,
    anim_frame: u32 = 0,
    anim_last_ms: i64 = 0,
    /// Recent traffic, dumped when the connection ends abnormally or on SIGUSR1.
    flight: flight.Recorder = .{},

    pub fn init(gpa: std.mem.Allocator, t: transport_mod.Transport, tls_ctx: *tls.Context, auth_cfg: *const AuthConfig, desktop_cfg: ?*const DesktopConfig, peer: []const u8) Conn {
        return .{ .gpa = gpa, .t = t, .tls_ctx = tls_ctx, .auth_cfg = auth_cfg, .desktop_cfg = desktop_cfg, .seat = if (desktop_cfg) |d| d.seat else null, .peer = peer, .enc = encoder_mod.Encoder.init(gpa) };
    }

    pub fn deinit(self: *Conn) void {
        self.wipeSecret();
        self.lingering = self.mayLinger();
        // The features first: they may use the desktop.
        vc.deinit(self);
        // Hand the desktop to a connection taking over, or lock and give the console back, first.
        if (self.claim) |*cl| {
            const seat = self.desktop_cfg.?.seat;
            if (self.desktop) |d| {
                d.cancelUnlock(); // drop the pending password
                const grace = self.desktop_cfg.?.reconnect_grace_ms;
                if (self.lingering) d.suspendForReconnect();
                switch (seat.release(self.gpa, cl, d, if (self.lingering) grace else null, nowMs())) {
                    .handed_over, .lingering => {},
                    .tear_down => {
                        d.destroy();
                        if (seat.takeDeskAudio()) |da| da.restore(self.gpa);
                        seat.done(cl);
                    },
                }
            } else {
                seat.abandon(cl);
                seat.done(cl);
            }
            cl.deinit();
            self.claim = null;
        }
        self.desktop = null;
        self.enc.deinit();
        self.surfaces.deinit(self.gpa);
        self.ch.deinit(self.gpa);
        self.bulk.deinit();
        if (self.fb) |*fb| fb.deinit(self.gpa);
        self.out.deinit(self.gpa);
        self.sendq.deinit(self.gpa);
        self.flow.deinit(self.gpa);
        deadline.stop(&self.deadline); // before the socket is closed
        self.t.deinit();
        self.flight.deinit(self.gpa);
    }

    fn mayLinger(self: *const Conn) bool {
        const cfg = self.desktop_cfg orelse return false;
        const d = self.desktop orelse return false;
        return self.claim != null and self.dropped and cfg.reconnect_grace_ms > 0 and d.canLinger();
    }

    fn wipeSecret(self: *Conn) void {
        if (self.secret) |sec| {
            std.crypto.secureZero(u8, sec);
            self.gpa.free(sec);
        }
        self.secret = null;
    }

    pub fn writer(self: *Conn) bytes.Writer {
        return bytes.Writer.init(&self.out, self.gpa);
    }

    /// Moves `out` to the send queue and writes what the socket takes now.
    pub fn flush(self: *Conn) Error!void {
        if (self.flow.mode == .off and !self.t.nonblocking and self.sendq.len() == 0) {
            // The connection sequence: straight to the blocking socket.
            try self.t.writeAll(self.out.items);
            self.out.clearRetainingCapacity();
        } else {
            try flow.commit(self, true);
        }
        self.last_send_ms = nowMs();
        try flow.flushDvc(self, false);
        try self.pumpOutput();
        try flow.flushTunnels(self);
        try vc.flushTunnels(self);
    }

    /// A control PDU (auto-detect, heartbeat) written now, not counted as data, as a Windows server does.
    pub fn sendControl(self: *Conn, channel_id: u16, payload: []const u8) Error!void {
        if (self.flow.mode == .off) return self.sendMcs(channel_id, payload);
        try flow.commit(self, true);
        try self.queueMcs(channel_id, payload);
        try flow.commit(self, false);
        self.last_send_ms = nowMs();
        try self.pumpOutput();
    }

    /// Writes what the socket takes now; everything while blocking.
    pub fn pumpOutput(self: *Conn) Error!void {
        const q = &self.sendq;
        if (q.len() == 0) return;
        if (!self.t.nonblocking) {
            try self.t.writeAll(q.bytes());
            q.consume(q.len());
            return;
        }
        // Full at the last try: the next POLLOUT says when there is room.
        if (self.flow.blocked) return;
        while (q.len() > 0) {
            const n = try self.t.writeSome(q.bytes());
            const now = nowNs();
            if (n == 0) {
                flow.socketFull(self, now);
                return;
            }
            q.consume(n);
            flow.socketWrote(self, n, q.len(), now);
        }
    }

    fn drainOutput(self: *Conn, timeout_ms: i64) void {
        if (!self.t.nonblocking) return;
        const until = nowMs() + timeout_ms;
        while (self.sendq.len() > 0) {
            self.flow.blocked = false;
            self.pumpOutput() catch return;
            if (self.sendq.len() == 0) return;
            const left = until - nowMs();
            if (left <= 0) {
                log.info("{s}: {d} bytes of output not sent at the end", .{ self.peer, self.sendq.len() });
                return;
            }
            var fds = [_]c.struct_pollfd{.{ .fd = self.t.fd, .events = c.POLLOUT, .revents = 0 }};
            _ = c.poll(&fds, 1, @intCast(left));
        }
    }

    pub fn tooSlow(self: *Conn) Error {
        const waiting = self.sendq.len() + self.flow.queuedTotal() + self.out.items.len;
        log.warn("{s}: {d} KiB of output waiting for the client (memory guard {d} KiB); ending the connection", .{ self.peer, waiting / 1024, self.flow.guard / 1024 });
        self.flight.note(.backlog, &.{ @intCast(@min(waiting, std.math.maxInt(u32))), @intCast(@min(self.flow.guard, std.math.maxInt(u32))), 0, 1 });
        return error.ClientTooSlow;
    }

    /// Whether a graphics frame may start now; `unacked`: frames not acknowledged (null: not counted).
    pub fn graphicsAdmit(self: *Conn, unacked: ?u32) bool {
        // No session output yet: only the client's bound on frames in flight applies.
        if (self.flow.mode == .off) {
            const n = unacked orelse return true;
            return self.pacing.clientReady(n, null);
        }
        const now = nowMs();
        self.pacing.maybeMetrics(flow.gfxRate(self), now);
        return self.pacing.admit(now, unacked, self.flow.rttMs());
    }

    pub fn gfxBacklog(self: *Conn, channel_id: u32) void {
        self.pacing.queued_now = self.flow.waiting(channel_id);
    }

    /// Bitmap updates have no channel queue: bytes in flight beyond the window stand in for it.
    pub fn legacyBacklog(self: *Conn) void {
        const f = &self.flow;
        const bif: usize = switch (f.mode) {
            .probes => f.nd.bytesInFlight(nowMs()),
            .local => flow.localBacklog(self),
            .off => 0,
        };
        self.pacing.queued_now = bif -| f.nd.window;
        self.pacing.qe.depth = 0;
    }

    /// The current frame's byte budget (pacing.budget), at least one piece.
    pub fn frameBudget(self: *Conn) usize {
        if (self.flow.mode == .off) return std.math.maxInt(usize);
        return @max(pacing.min_piece_bytes, self.pacing.budget(nowMs(), 0));
    }

    fn logOutput(self: *Conn, now_ms: i64) void {
        const p = &self.pacing;
        if (now_ms - p.logged_ms < pacing.log_interval_ms) return;
        const el = now_ms - p.logged_ms;
        p.logged_ms = now_ms;
        const st = p.stats;
        p.stats = .{};
        const fs = self.flow.stats;
        self.flow.stats = .{};
        const nd = &self.flow.nd;
        const ns = nd.stats;
        nd.stats = .{};
        const notable = st.held > 0 or st.cut > 0 or st.longest_pass_ms >= pacing.slow_pass_ms or ns.max_delay_ms > nd.p.ideal_ms or fs.window_waits > 0;
        if (!notable) return;
        log.info("{s}: output: {d:.1} Mbit/s sent; {t}: bandwidth {d:.0} kbit/s, RTT {d:.0} ms (base {d:.0}, queueing up to {d} ms), window {d} KiB, in flight up to {d} KiB, probes {d}/{d} answered (up to {d} newer outstanding), {d} bandwidth samples; channel queues up to {d} KiB; frames: {d} sent, {d} KiB avg, {d} KiB max, {d} H.264 at QP {d:.1} avg, {d} held ({d} for the network), {d} cut; longest loop pass {d} ms", .{
            self.peer,
            @as(f64, @floatFromInt(fs.written)) * 8.0 / 1e3 / @as(f64, @floatFromInt(@max(el, 1))),
            self.flow.mode,
            nd.published,
            nd.srtt,
            if (nd.base_known) nd.base else 0,
            ns.max_delay_ms,
            nd.window / 1024,
            fs.peak_in_flight / 1024,
            ns.answers,
            ns.probes,
            ns.max_newer,
            ns.bw_samples,
            fs.peak_queued / 1024,
            st.frames,
            if (st.frames > 0) st.frame_bytes / st.frames / 1024 else 0,
            st.max_frame / 1024,
            st.avc_frames,
            if (st.avc_frames > 0) @as(f64, @floatFromInt(st.qp_sum)) / @as(f64, @floatFromInt(st.avc_frames)) else 0,
            st.held,
            st.held_network,
            st.cut,
            st.longest_pass_ms,
        });
        self.flight.note(.backlog, &.{ @intCast(@min(fs.peak_queued, std.math.maxInt(u32))), nd.window, @intFromFloat(@min(nd.published, 4.0e9)), 0, st.held, st.longest_pass_ms });
    }

    pub fn sendMcs(self: *Conn, channel_id: u16, payload: []const u8) Error!void {
        try self.queueMcs(channel_id, payload);
        try self.flush();
    }

    /// sendMcs without the flush: the PDU waits in `out` for the next one.
    pub fn queueMcs(self: *Conn, channel_id: u16, payload: []const u8) Error!void {
        if (channel_id == mcs.io_channel_id) {
            self.flight.slowPath(.out, payload);
        } else if (self.msg_channel) |m| if (channel_id == m) self.flight.messageChannel(.out, payload);
        var w = self.writer();
        const f = try x224.beginData(&w);
        try mcs.writeSendDataIndicationHeader(&w, channel_id, payload.len);
        try w.bytes(payload);
        f.finish(&w);
    }

    fn sendIo(self: *Conn, comptime build: anytype, args: anytype) Error!void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.gpa);
        var w = bytes.Writer.init(&body, self.gpa);
        try @call(.auto, build, .{&w} ++ args);
        try self.sendMcs(mcs.io_channel_id, body.items);
    }

    fn nextTpktPayload(self: *Conn) Error![]const u8 {
        const pdu = try self.t.next();
        if (pdu.kind != .tpkt) return error.ProtocolError;
        return x224.parseData(pdu.data);
    }

    /// The next client PDU, serving the features' fds and timers meanwhile.
    fn nextServingFeatures(self: *Conn) Error!transport_mod.Pdu {
        while (!self.t.hasPending()) {
            try vc.tick(self);
            var fds: [1 + vc.max_polled]c.struct_pollfd = undefined;
            fds[0] = .{ .fd = self.t.fd, .events = c.POLLIN, .revents = 0 };
            const n = 1 + vc.pollFds(self, fds[1..]);
            if (c.poll(&fds, @intCast(n), vc.pollTimeout(self, -1)) < 0) continue;
            try vc.onPolled(self, fds[1..n]);
            if (fds[0].revents != 0) break;
        }
        return self.t.next();
    }

    pub fn run(self: *Conn) Error!void {
        self.deadline = deadline.start(self.t.fd, nowMs());
        try self.negotiate();
        try self.mcsConnect();
        try self.channelJoins();
        try self.clientInfo();
        try autodetect.connectTime(self);
        try self.sendIo(rdp.writeLicenseValidClient, .{});
        // Phase 8, multitransport bootstrapping (MS-RDPBCGR 1.3.1.1).
        try vc.startLicensed(self);
        self.capabilities() catch |err| return self.noteLoss(err);
        self.activeLoop() catch |err| {
            if (self.saidGoodbye(err)) return;
            return self.noteLoss(err);
        };
    }

    /// A client that sends its Disconnect Provider Ultimatum and closes with output pending resets
    /// the connection; a goodbye still in the socket makes it the client's disconnect.
    fn saidGoodbye(self: *Conn, err: Error) bool {
        switch (err) {
            error.WriteFailed, error.TlsWriteFailed => {},
            else => return false,
        }
        if (!self.t.nonblocking) return false;
        for (0..max_input_pdus) |_| {
            const pdu = (self.t.tryNext() catch return false) orelse return false;
            if (pdu.kind != .tpkt) continue;
            const mp = mcs.parseClientPdu(x224.parseData(pdu.data) catch return false) catch return false;
            switch (mp) {
                .disconnect_provider_ultimatum => |reason| {
                    self.flight.ultimatum(.in, @backingInt(reason));
                    log.info("{s}: client disconnected ({s}) with output on its way, {d} input events", .{ self.peer, @tagName(reason), self.input_events });
                    return true;
                },
                else => {},
            }
        }
        return false;
    }

    /// Records how the connection ended; dumps the flight ring if not cleanly.
    pub fn flightEnd(self: *Conn, result: Error!void) void {
        const err: ?anyerror = if (result) |_| null else |e| e;
        self.flight.end(err);
        if (!self.flight.worthDumping(err, self.t.closedCleanly())) return;
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        _ = self.flight.dump(self.peer, .end, err, &buf);
    }

    pub fn flightLive(self: *Conn) void {
        if (!self.flight.liveRequested()) return;
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        _ = self.flight.dump(self.peer, .live, null, &buf);
    }

    fn noteLoss(self: *Conn, err: Error) Error {
        if (isNetworkLoss(err) and (self.established or self.resumed) and !self.t.closedCleanly()) self.dropped = true;
        return err;
    }

    /// Hyprland is gone. Its Wayland errors share names with the client's and are not a network drop.
    fn compositorError(self: *Conn, err: Error) Error {
        if (!wlConnectionEnded(err)) return err;
        log.warn("{s}: the compositor's connection ended ({t}): ending the session", .{ self.peer, err });
        return error.CompositorGone;
    }

    fn negotiate(self: *Conn) Error!void {
        const pdu = try self.t.next();
        if (pdu.kind != .tpkt) return error.ProtocolError;
        const cr = try x224.parseConnectionRequest(pdu.data);
        const req = cr.requested orelse x224.Protocol.standard_rdp;
        self.requested_protocols = req;
        log.info("{s}: connection request cookie={s} protocols=0x{x}", .{
            self.peer, cr.cookie orelse "-", req.toInt(),
        });
        var w = self.writer();
        if (cr.requested == null) {
            // No RDP_NEG_REQ selects Standard RDP Security (MS-RDPBCGR 3.3.5.3.1), which is unsupported.
            try x224.writeConnectionConfirm(&w, x224.confirm_src_ref, .none);
            try self.flush();
            return error.UnsupportedSecurity;
        }

        // Prefer NLA; HYBRID_EX lets the client show "access denied" instead of a generic error.
        var selected: x224.Protocol = .{};
        if (req.hybrid_ex and self.auth_cfg.use_hybrid_ex) {
            selected.hybrid_ex = true;
        } else if (req.hybrid) {
            selected.hybrid = true;
        } else if (req.ssl and self.auth_cfg.allow_tls_without_nla) {
            selected.ssl = true;
        }

        if (selected.toInt() == 0) {
            // Never Standard RDP Security; TLS-only only for development (MS-RDPBCGR 2.2.1.2.2).
            const code: x224.FailureCode = if (self.auth_cfg.allow_tls_without_nla) .ssl_required_by_server else .hybrid_required_by_server;
            try x224.writeConnectionConfirm(&w, x224.confirm_src_ref, .{ .failure = code });
            try self.flush();
            return error.UnsupportedSecurity;
        }
        self.selected_protocol = selected;
        self.flight.note(.x224, &.{ req.toInt(), selected.toInt() });
        try x224.writeConnectionConfirm(&w, x224.confirm_src_ref, .{ .selected = .{
            .protocol = selected,
            .flags = .{ .extended_client_data_supported = true, .dynvc_gfx_protocol_supported = self.vc.opts.graphics.rdpgfx },
        } });
        try self.flush();
        deadline.restart(self.deadline, nowMs()); // 3.3.5.3.1
        try self.t.startTls(self.tls_ctx);
        if (selected.hybrid or selected.hybrid_ex) try self.nla(selected.hybrid_ex);
    }

    /// CredSSP inside TLS, then the PAM check of the delegated password.
    fn nla(self: *Conn, early_user_auth: bool) Error!void {
        const cfg = self.auth_cfg;
        var srv = credssp.Server.init(self.gpa, .{
            .public_key = self.tls_ctx.public_key,
            .nb_computer = cfg.nb_computer,
            .dns_computer = cfg.dns_computer,
            .nt_hash = auth.Store.lookup,
            .nt_hash_ctx = @ptrCast(@constCast(cfg.store)),
            .rng = auth.secureRandom(),
            .now_filetime = auth.nowFiletime(),
        });
        defer srv.deinit();

        var creds = while (true) {
            const msg = try self.t.nextDerSequence(64 * 1024);
            switch (srv.step(msg)) {
                .send => |out| {
                    defer self.gpa.free(out);
                    try self.t.writeAll(out);
                },
                .done => |cr| break cr,
                .fail => |f| {
                    if (f.send) |out| {
                        defer self.gpa.free(out);
                        self.t.writeAll(out) catch {};
                    }
                    log.warn("{s}: NLA failed: {t}", .{ self.peer, f.err });
                    return error.AuthenticationFailed;
                },
            }
        };
        defer creds.deinit(self.gpa);

        var ok = false;
        const entry = cfg.store.find(creds.user);
        if (entry) |e| {
            self.user = e.name();
            var ubuf: [128]u8 = undefined;
            var pbuf: [1024]u8 = undefined;
            defer std.crypto.secureZero(u8, &pbuf);
            const user_z = std.mem.printSentinel(&ubuf, "{s}", .{e.name()}, 0) catch unreachable;
            const pw: ?[]u8 = auth.utf16ToUtf8(pbuf[0 .. pbuf.len - 1], creds.password) catch null;
            if (cfg.pam_service) |svc| {
                if (pw) |p| {
                    pbuf[p.len] = 0;
                    ok = auth.pamCheck(svc, user_z, pbuf[0..p.len :0]);
                }
            } else {
                ok = true;
            }
            // The same password unlocks the lock screen (desktop mode only).
            if (ok and self.desktop_cfg != null) if (pw) |p| {
                self.secret = try self.gpa.dupe(u8, p);
            };
        }

        if (early_user_auth) {
            // Early User Authorization Result PDU (MS-RDPBCGR 2.2.10.2).
            var res: [4]u8 = undefined;
            std.mem.writeInt(u32, &res, if (ok) 0x00000000 else 0x00000005, .little);
            try self.t.writeAll(&res);
        }
        if (!ok) {
            log.warn("{s}: NLA user rejected", .{self.peer});
            return error.AuthenticationFailed;
        }
        self.flight.note(.nla, &.{});
        log.info("{s}: NLA ok, user {s}", .{ self.peer, self.user.? });
    }

    pub fn mcsConnect(self: *Conn) Error!void {
        const ci = try mcs.parseConnectInitial(try self.nextTpktPayload());
        self.client = try gcc.parseConferenceCreateRequest(ci.user_data);
        const d = &self.client;
        // A serverSelectedProtocol unlike the negotiation response was tampered with (MS-RDPBCGR 3.3.5.3.3).
        if (d.server_selected_protocol != self.selected_protocol.toInt()) {
            log.warn("{s}: serverSelectedProtocol 0x{x}, but 0x{x} was selected", .{ self.peer, d.server_selected_protocol, self.selected_protocol.toInt() });
            return error.ProtocolError;
        }
        self.flight.note(.mcs_connect, &.{ d.client_build, d.desktop_width, d.desktop_height, @intCast(d.monitor_count), @intCast(d.channel_count), @as(u16, @bitCast(d.early_caps)) });
        log.info("{s}: client build {d}, desktop {d}x{d}, {d} monitor(s), {d} channel(s), scale {d}% (device {d}%), early caps 0x{x}", .{
            self.peer, d.client_build, d.desktop_width, d.desktop_height, d.monitor_count, d.channel_count, d.desktop_scale_factor, d.device_scale_factor, @as(u16, @bitCast(d.early_caps)),
        });
        for (d.channelSlice(), 0..) |ch, i| {
            self.channel_ids[i] = mcs.io_channel_id + 1 + @as(u16, @intCast(i));
            log.debug("  channel {s} -> {d} (options 0x{x})", .{ ch.nameSlice(), self.channel_ids[i], ch.options });
        }
        var next_id: u16 = mcs.io_channel_id + 1 + @as(u16, @intCast(d.channel_count));
        if (d.has_msgchannel) {
            self.msg_channel = next_id;
            next_id += 1;
        }
        self.user_id = next_id;

        var gcc_buf: std.ArrayList(u8) = .empty;
        defer gcc_buf.deinit(self.gpa);
        var gw = bytes.Writer.init(&gcc_buf, self.gpa);
        try gcc.writeConferenceCreateResponse(&gw, .{
            .client_requested_protocols = self.requested_protocols.toInt(),
            .io_channel = mcs.io_channel_id,
            .channel_ids = self.channel_ids[0..d.channel_count],
            .msg_channel = self.msg_channel,
            // UDP side channels, when the client can use them (2.2.1.4.6).
            .multitransport_flags = multitransport.serverFlags(self),
        });
        var w = self.writer();
        const f = try x224.beginData(&w);
        try mcs.writeConnectResponse(&w, ci.merged, gcc_buf.items); // 3.3.5.3.4
        f.finish(&w);
        try self.flush();
    }

    pub fn channelJoins(self: *Conn) Error!void {
        var remaining: usize = 2 + self.client.channel_count + @as(usize, if (self.msg_channel != null) 1 else 0);
        var joined: [gcc.max_channels + 3]u16 = undefined;
        var n_joined: usize = 0;
        var attached = false;
        while (remaining > 0) {
            const pdu = try mcs.parseClientPdu(try self.nextTpktPayload());
            var w = self.writer();
            switch (pdu) {
                .erect_domain_request => {},
                .attach_user_request => {
                    try x224BeginEnd(&w, mcs.writeAttachUserConfirm, .{self.user_id});
                    attached = true;
                },
                .channel_join_request => |j| {
                    if (!attached) return error.ProtocolError;
                    if (j.initiator != self.user_id) return error.ProtocolError;
                    if (!self.isKnownChannel(j.channel_id)) {
                        // MS-RDPBCGR 3.3.5.3.9: "no such MCS channel ID".
                        try x224BeginEnd(&w, mcs.writeChannelJoinResult, .{ mcs.rt_unspecified_failure, j.initiator, j.channel_id });
                    } else if (std.mem.indexOfScalar(u16, joined[0..n_joined], j.channel_id) != null) {
                        continue; // already joined: ignored, no confirm (3.3.5.3.8)
                    } else {
                        try x224BeginEnd(&w, mcs.writeChannelJoinConfirm, .{ j.initiator, j.channel_id });
                        joined[n_joined] = j.channel_id;
                        n_joined += 1;
                        remaining -= 1;
                    }
                },
                .disconnect_provider_ultimatum => |reason| {
                    self.flight.ultimatum(.in, @backingInt(reason));
                    return error.ClientDisconnected;
                },
                .send_data_request => return error.ProtocolError,
            }
            try self.flush();
        }
    }

    fn isKnownChannel(self: *Conn, id: u16) bool {
        if (id == self.user_id or id == mcs.io_channel_id) return true;
        if (self.msg_channel) |m| if (id == m) return true;
        for (self.channel_ids[0..self.client.channel_count]) |ch_id| if (ch_id == id) return true;
        return false;
    }

    pub fn clientInfo(self: *Conn) Error!void {
        const pdu = try mcs.parseClientPdu(try self.nextTpktPayload());
        const sdr = switch (pdu) {
            .send_data_request => |s| s,
            .disconnect_provider_ultimatum => |reason| {
                self.flight.ultimatum(.in, @backingInt(reason));
                return error.ClientDisconnected;
            },
            else => return error.ProtocolError,
        };
        if (sdr.channel_id != mcs.io_channel_id) return error.ProtocolError;
        const info = try rdp.parseClientInfo(sdr.data);
        // Flags only: the names and the password stay out of the record.
        self.flight.note(.client_info, &.{ info.flags, info.performance_flags });
        var name_buf: [128]u8 = undefined;
        log.info("{s}: client info user={s} autologon={} perf=0x{x} rail={} audio={s}{s} flags=0x{x} arc cookie={}", .{
            self.peer,
            asciiFromUtf16(&name_buf, info.user_name),
            info.flags & rdp.info_autologon != 0,
            info.performance_flags,
            info.flags & rdp.info_rail != 0,
            if (info.flags & rdp.info_remoteconsoleaudio != 0) "remote" else if (info.flags & rdp.info_noaudioplayback != 0) "none" else "client",
            if (info.flags & rdp.info_audiocapture != 0) "+mic" else "",
            info.flags,
            info.auto_reconnect_cookie.len > 0,
        });
        try self.bulk.start(self.gpa, info.flags, self.vc.opts.graphics.bulk);
        if (self.bulk.type) |t| log.info("{s}: bulk compression {s}", .{ self.peer, compression.typeName(t) });
        self.info_flags = info.flags;
        // The AlternateShell is not used, also in RemoteApp (MS-RDPERP 1.3.2.1).
        if (info.alternate_shell.len > 0) log.debug("{s}: client info has an alternate shell (not used)", .{self.peer});
        if (self.user) |u| self.logon_names_changed = session_info.namesDiffer(info.user_name, info.domain, u, self.auth_cfg.nb_computer);
        // Auto-reconnect cookie (MS-RDPBCGR 5.5); one that does not verify means a normal logon.
        if (info.auto_reconnect_cookie.len > 0) {
            self.arc_cookie = .invalid;
            if (self.seat) |seat| if (self.user) |u| {
                self.arc_valid = seat.verifyArc(info.auto_reconnect_cookie, u) catch |err| blk: {
                    log.warn("{s}: malformed auto-reconnect cookie ({t})", .{ self.peer, err });
                    break :blk false;
                };
                if (self.arc_valid) self.arc_cookie = .valid;
            };
            log.info("{s}: auto-reconnect cookie {s}", .{ self.peer, if (self.arc_valid) "verified" else "not valid for this session" });
        }
    }

    /// The Demand Active's capability sets, also for a reactivation.
    fn serverCaps(self: *const Conn) caps.ServerCapsOptions {
        return legacy.serverCaps(.{
            .desktop_width = self.width,
            .desktop_height = self.height,
            .color_depth = self.bpp,
            .vc_flags = self.bulk.serverVcFlags(),
            .rail = if (self.remoteapp) remoteapp.server_caps else null,
        }, self.vc.opts.graphics);
    }

    pub fn capabilities(self: *Conn) Error!void {
        const size = self.client.desktopSize();
        self.width = size.width;
        self.height = size.height;
        if (self.desktop_cfg) |cfg| try self.enterDesktop(cfg);
        self.bpp = self.client.sessionColorDepth();
        // RAIL capability sets only if RemoteApp can run (MS-RDPERP 3.3.5.1.3).
        self.remoteapp = remoteapp.wanted(self);
        if (self.info_flags & rdp.info_rail != 0) log.info("{s}: the client asks for RemoteApp: {s}", .{ self.peer, if (self.remoteapp) "RemoteApp session" else "not available, full desktop" });
        try self.sendIo(rdp.writeDemandActive, .{ self.serverCaps(), 0 });
        // Monitor Layout follows the Demand Active (MS-RDPBCGR 1.3.1.1 step 9).
        try session_info.sendMonitorLayout(self);

        // Wait for Confirm Active; the client may interleave nothing else.
        while (true) {
            const tp = try self.nextServingFeatures();
            if (tp.kind != .tpkt) return error.ProtocolError;
            const pdu = try mcs.parseClientPdu(try x224.parseData(tp.data));
            const sdr = switch (pdu) {
                .send_data_request => |s| s,
                .disconnect_provider_ultimatum => |reason| {
                    self.flight.ultimatum(.in, @backingInt(reason));
                    return error.ClientDisconnected;
                },
                else => return error.ProtocolError,
            };
            // Late auto-detect responses and multitransport use the message channel.
            if (self.msg_channel != null and sdr.channel_id == self.msg_channel.?) {
                self.flight.messageChannel(.in, sdr.data);
                autodetect.onMessageChannel(self, sdr.data);
                try vc.onMessage(self, sdr.data);
                continue;
            }
            self.flight.slowPath(.in, sdr.data);
            switch (try rdp.parseShareControl(sdr.data)) {
                .confirm_active => |ca| {
                    if (ca.share_id != rdp.share_id) return error.ProtocolError;
                    self.client_caps = ca.caps;
                    break;
                },
                else => return error.ProtocolError,
            }
        }
        const cc = &self.client_caps;
        log.info("{s}: confirm active: {d}bpp {d}x{d} fastpath-out={} input=0x{x} multifrag={d} surfcmds=0x{x} vc=0x{x} frame-ack={?d} os {d}/{d} extra=0x{x}", .{
            self.peer,
            cc.bpp,
            cc.desktop_width,
            cc.desktop_height,
            cc.fastpathOutput(),
            cc.input_flags,
            cc.multifragment_max_request_size,
            cc.surface_commands,
            cc.vc_flags,
            cc.frame_acknowledge,
            cc.os_major_type,
            cc.os_minor_type,
            cc.general_extra_flags,
        });
        if (self.desktop) |d| if (self.desktop_cfg) |cfg| {
            const apple = altdrag.isAppleClient(cc.os_major_type, cc.os_minor_type);
            if (apple) log.info("{s}: a macOS / iOS client (osMajorType {d}): Option + drag {t}", .{ self.peer, cc.os_major_type, cfg.alt_drag });
            d.setAltDrag(cfg.alt_drag == .on or (cfg.alt_drag == .auto and apple));
        };
        // Without FASTPATH_OUTPUT_SUPPORTED updates go slow-path (2.2.7.1.1).
        self.fastpath_output = cc.fastpathOutput();
        legacy.onConfirmActive(self);
        pointer_mod.reset(&self.pointer, cc, self.fastpath_output);
        log.info("{s}: pointer caps: cache {d}/{d} color {d}, large 0x{x} -> up to {d}x{d}", .{
            self.peer, self.pointer.caps.cache_size, cc.pointer_cache_size, cc.color_pointer_cache_size, cc.large_pointer_flags, self.pointer.caps.max_size, self.pointer.caps.max_size,
        });

        // Server half of finalization (MS-RDPBCGR 1.3.1.1); handleIo answers Request Control.
        try self.sendIo(rdp.writeSynchronize, .{@as(u16, 0)}); // targetUser 0 (3.3.5.3.19)
        try self.sendIo(rdp.writeControl, .{ rdp.ctrlaction_cooperate, 0, 0 });
    }

    /// Takes the console remote before the Demand Active, which carries the resulting size.
    fn enterDesktop(self: *Conn, cfg: *const DesktopConfig) Error!void {
        // TLS without NLA proves nothing about the user.
        if (self.user == null) {
            log.err("{s}: desktop sessions require NLA", .{self.peer});
            return error.AuthenticationFailed;
        }
        const size = self.client.desktopSize();
        // An output per client monitor (MS-RDPBCGR 2.2.1.3.6); unservable layouts are refused first.
        const layout = surfaces.clientLayout(self) catch |err| return self.rejectMonitors(err);
        const opts: desktop_mod.Options = .{
            .width = size.width,
            .height = size.height,
            .scale_percent = self.client.scalePercent(),
            .keyboard_layout = self.client.keyboard_layout,
            .lock_command = cfg.lock_command,
            .helper_socket = cfg.helper_socket,
            .require_fence = cfg.require_fence,
            .binds_state_path = cfg.binds_state_path,
            .console_state_path = cfg.console_state_path,
            .capture_backend = cfg.capture_backend,
            .cursor = cfg.cursor,
            .layout = layout,
        };
        self.claim = seat_mod.Claim.init() catch return error.DesktopFailed;
        const got = cfg.seat.acquireWith(&self.claim.?, 20_000, .{ .cookie = self.arc_cookie, .user = self.user }) catch |err| {
            log.err("{s}: the desktop is busy ({t})", .{ self.peer, err });
            return error.DesktopFailed;
        };
        if (got.desktop) |d| {
            self.desktop = d;
            self.resumed = got.resumed;
            d.adopt(opts) catch |err| {
                log.err("{s}: could not take over the desktop: {t}", .{ self.peer, err });
                return error.DesktopFailed;
            };
        } else {
            const d = try desktop_mod.Desktop.create(self.gpa, cfg.ipc, opts);
            self.desktop = d;
            d.enter() catch |err| {
                log.err("{s}: could not take the desktop remote: {t}", .{ self.peer, err });
                return error.DesktopFailed;
            };
        }
        const d = self.desktop.?;
        self.width = @intCast(d.width());
        self.height = @intCast(d.height());
        if (self.width != self.client.desktop_width or self.height != self.client.desktop_height) {
            log.info("{s}: desktop {d}x{d} (client asked {d}x{d} at {d}%)", .{
                self.peer, self.width, self.height, self.client.desktop_width, self.client.desktop_height, self.client.desktop_scale_factor,
            });
        }
    }

    /// Set Error Info if supported, then disconnect (MS-RDPBCGR 2.2.5.1.1, 1.3.1.4.2).
    fn rejectMonitors(self: *Conn, err: multimon.Error) Error {
        const code = multimon.errInfoCode(err) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.ProtocolError,
        };
        log.warn("{s}: refusing the client's {d} monitors ({t}, error info 0x{x:0>8})", .{ self.peer, self.client.monitor_count, err, code });
        if (self.client.early_caps.support_errinfo_pdu) self.sendIo(rdp.writeSetErrorInfo, .{code}) catch {};
        var w = self.writer();
        self.flight.ultimatum(.out, @backingInt(mcs.DisconnectReason.provider_initiated));
        x224BeginEnd(&w, mcs.writeDisconnectProviderUltimatum, .{mcs.DisconnectReason.provider_initiated}) catch {};
        self.flush() catch {};
        return error.ProtocolError;
    }

    fn activeLoop(self: *Conn) Error!void {
        if (self.desktop == null) {
            var fb = try framebuffer.Framebuffer.init(self.gpa, self.width, self.height);
            framebuffer.drawTestPattern(&fb);
            if (self.test_detail) framebuffer.drawDetail(&fb, 0);
            self.fb = fb;
        }
        var events: [fastpath.max_events]fastpath.InputEvent = undefined;
        // From here on nothing waits on the network.
        try self.t.startNonBlocking();
        flow.start(self);
        self.pacing.logged_ms = nowMs();
        var pass_start = nowNs();
        while (true) {
            // Input first, including PDUs buffered inside TLS that poll() misses; a flood yields.
            var more_input = false;
            var budget: u32 = max_input_pdus;
            while (try self.t.tryNext()) |pdu| {
                if (!try self.handlePdu(pdu, &events)) return;
                budget -= 1;
                if (budget == 0) {
                    more_input = true;
                    break;
                }
            }
            self.pacing.retry_ms = null;
            if (self.desktop) |d| {
                d.dispatch() catch |e| return self.compositorError(e);
                try self.pumpDesktop(d);
                try pointer_mod.pump(self, &d.cursor);
            } else if (self.test_source) |src| {
                try src.pump(src.ctx, self);
            } else if (self.animate) {
                try self.pumpAnimation();
            }
            try channels.refine(self);
            try autodetect.tick(self);
            try vc.tick(self);
            if (self.end_errinfo) |code| {
                log.info("{s}: disconnecting: the session ended (error info 0x{x})", .{ self.peer, code });
                return self.disconnectWith(code);
            }
            self.flightLive();
            try flow.tick(self);
            try self.pumpOutput();
            self.logOutput(nowMs());
            const d = self.desktop;
            const base = 7;
            var fds: [base + vc.max_polled]c.struct_pollfd = undefined;
            const queries: [2]c_int = if (d) |dd| dd.queryFds() else .{ -1, -1 };
            // POLLOUT while output waits (or TLS must write to read on).
            const out_ev: c_short = if (self.sendq.len() > 0 or self.t.readWantsWrite()) c.POLLOUT else 0;
            fds[0..base].* = .{
                .{ .fd = self.t.fd, .events = @as(c_short, c.POLLIN) | out_ev, .revents = 0 },
                .{ .fd = if (d) |dd| dd.waylandFd() else -1, .events = c.POLLIN, .revents = 0 },
                .{ .fd = if (d) |dd| dd.helperFd() else -1, .events = c.POLLIN, .revents = 0 },
                .{ .fd = if (self.claim) |cl| cl.fd else -1, .events = c.POLLIN, .revents = 0 },
                .{ .fd = if (d) |dd| dd.eventsFd() else -1, .events = c.POLLIN, .revents = 0 },
                .{ .fd = queries[0], .events = c.POLLIN, .revents = 0 },
                .{ .fd = queries[1], .events = c.POLLIN, .revents = 0 },
            };
            const nfds = base + vc.pollFds(self, fds[base..]);
            var timeout: c_int = vc.pollTimeout(self, if (self.animate or self.test_source != null) 4 else if (channels.refinePending(self)) 50 else if (d != null) 100 else -1);
            if (self.flight.on()) timeout = if (timeout < 0) flight.live_poll_ms else @min(timeout, flight.live_poll_ms);
            if (self.pacing.retry_ms) |r| timeout = if (timeout < 0) @intCast(r) else @min(timeout, @as(c_int, @intCast(r)));
            timeout = flow.pollTimeout(self, timeout);
            if (more_input) timeout = 0;
            if (d) |dd| if (dd.desk_activity) {
                timeout = 0;
            };
            self.notePass(pass_start);
            const polled = c.poll(&fds, @intCast(nfds), timeout);
            pass_start = nowNs();
            if (polled < 0) continue;
            if (fds[0].revents & (c.POLLOUT | c.POLLERR | c.POLLHUP) != 0) {
                self.flow.blocked = false;
                try self.pumpOutput();
            }
            try vc.onPolled(self, fds[base..nfds]);
            if (fds[2].revents != 0) if (d) |dd| {
                _ = dd.readHelper() catch dd.helperLost();
            };
            // Every pass: Desktop.helperCommand may read a desk report without the socket readable.
            if (d) |dd| if (dd.desk_activity) {
                dd.desk_activity = false;
                dd.deskWantsIn();
            };
            if (fds[4].revents != 0) if (d) |dd| dd.readEvents();
            if (d) |dd| if (dd.tick() == .desk_took_over) {
                log.info("{s}: disconnecting: the session was taken at the desk", .{self.peer});
                return self.disconnectTakenOver();
            };
            if (fds[3].revents != 0) if (self.claim) |cl| if (cl.take()) {
                log.info("{s}: disconnecting: a new connection takes the session", .{self.peer});
                return self.disconnectTakenOver();
            };
        }
    }

    fn disconnectTakenOver(self: *Conn) Error!void {
        return self.disconnectWith(rdp.errinfo_disconnected_by_otherconnection);
    }

    /// Ends the session on the loop's next turn: Set Error Info, then the Ultimatum (MS-RDPBCGR 1.3.1.4.2).
    pub fn requestEnd(self: *Conn, errinfo: u32) void {
        if (self.end_errinfo == null) self.end_errinfo = errinfo;
    }

    fn disconnectWith(self: *Conn, errinfo: u32) Error!void {
        // Set Error Info only to clients that support it (MS-RDPBCGR 3.3.5.7.1).
        if (self.client.early_caps.support_errinfo_pdu)
            try self.sendIo(rdp.writeSetErrorInfo, .{errinfo});
        // A logoff is user-requested (MS-RDPBCGR 3.1.5.1.1), so clients without Set Error Info tell it apart.
        const reason: mcs.DisconnectReason = if (errinfo == rdp.errinfo_logoff_by_user) .user_requested else .provider_initiated;
        self.flight.ultimatum(.out, @backingInt(reason));
        var w = self.writer();
        try x224BeginEnd(&w, mcs.writeDisconnectProviderUltimatum, .{reason});
        try self.flush();
        self.drainOutput(pacing.drain_at_end_ms);
    }

    fn notePass(self: *Conn, start: u64) void {
        const ms: u32 = @intCast(@min((nowNs() -| start) / std.time.ns_per_ms, std.math.maxInt(u32)));
        self.pacing.stats.longest_pass_ms = @max(self.pacing.stats.longest_pass_ms, ms);
        self.longest_pass_ms = @max(self.longest_pass_ms, ms);
    }

    /// Handles one client PDU; false when the client disconnected.
    fn handlePdu(self: *Conn, pdu: transport_mod.Pdu, events: []fastpath.InputEvent) Error!bool {
        return self.dispatchPdu(pdu, events) catch |err| {
            self.flight.failed(if (pdu.kind == .fastpath) .fastpath else .mcs, pdu.data.len, err);
            return err;
        };
    }

    fn dispatchPdu(self: *Conn, pdu: transport_mod.Pdu, events: []fastpath.InputEvent) Error!bool {
        switch (pdu.kind) {
            .fastpath => {
                const evs = fastpath.parseInput(pdu.data, events) catch |err| {
                    log.err("{s}: bad fast-path input ({t}), {d} bytes", .{ self.peer, err, pdu.data.len });
                    return err;
                };
                if (self.flight.on()) self.flight.input(.fastpath, pdu.data.len, .of(evs));
                self.input_events += evs.len;
                for (evs) |ev| try self.onInput(ev);
            },
            .tpkt => {
                const mp = try mcs.parseClientPdu(try x224.parseData(pdu.data));
                switch (mp) {
                    .send_data_request => |sdr| {
                        if (sdr.channel_id == mcs.io_channel_id) {
                            try self.handleIo(sdr.data);
                        } else if (self.msg_channel != null and sdr.channel_id == self.msg_channel.?) {
                            self.flight.messageChannel(.in, sdr.data);
                            autodetect.onMessageChannel(self, sdr.data);
                            try vc.onMessage(self, sdr.data);
                        } else if (!try vc.onStatic(self, sdr.channel_id, sdr.data)) {
                            log.debug("{s}: {d} bytes on channel {d} (ignored)", .{ self.peer, sdr.data.len, sdr.channel_id });
                        }
                    },
                    .disconnect_provider_ultimatum => |reason| {
                        self.flight.ultimatum(.in, @backingInt(reason));
                        log.info("{s}: client disconnected ({s}), {d} input events", .{ self.peer, @tagName(reason), self.input_events });
                        return false;
                    },
                    else => return error.ProtocolError,
                }
            },
        }
        return true;
    }

    pub fn onInput(self: *Conn, ev: fastpath.InputEvent) Error!void {
        logInput(ev);
        session_info.onInput(self, ev);
        const d = self.desktop orelse return;
        switch (ev) {
            .scancode => |k| try d.onScancode(k.code, k.flags),
            .unicode => |u| try d.onUnicode(u.code, u.release),
            .mouse => |m| try d.onPointer(m.flags, m.x, m.y, false),
            .mousex => |m| try d.onPointer(m.flags, m.x, m.y, true),
            .sync => |t| try d.onSync(t),
            .mouse_rel => |m| try d.onPointerRel(m.flags, m.dx, m.dy),
            .qoe_timestamp => {},
        }
    }

    /// Test pattern: 3 s of motion, 2 s still; with `test_video`, a 30 fps video 15 s of every 20.
    fn pumpAnimation(self: *Conn) Error!void {
        if (!self.established or self.output_suppressed or self.reactivating) return;
        if (!channels.graphicsReady(self)) return;
        const now = nowMs();
        if (self.test_video) |v| {
            if (@mod(now, 20_000) >= 15_000) return;
            if (now - self.anim_last_ms < 33) return;
            if (!channels.canSendFrame(self)) {
                if (self.pacing.refused) self.pacing.held();
                return;
            }
            self.anim_last_ms = now;
            self.anim_frame +%= 1;
            framebuffer.drawVideo(&(self.fb orelse return), v[0], v[1], self.anim_frame);
            return channels.sendFramebuffer(self);
        }
        if (@mod(now, 5000) >= 3000) return;
        if (now - self.anim_last_ms < 16) return;
        if (!channels.canSendFrame(self)) {
            if (self.pacing.refused) self.pacing.held();
            return;
        }
        self.anim_last_ms = now;
        const fb = &(self.fb orelse return);
        self.anim_frame +%= 1;
        framebuffer.drawAnimatedPattern(fb, self.anim_frame);
        if (self.test_detail) framebuffer.drawDetail(fb, @as(usize, self.anim_frame) * 6);
        try channels.sendFramebuffer(self);
    }

    pub fn pumpDesktop(self: *Conn, d: *desktop_mod.Desktop) Error!void {
        switch (d.captureState()) {
            .stopped, .failed => {
                log.err("{s}: screen capture ended ({t})", .{ self.peer, d.captureState() });
                return error.CaptureFailed;
            },
            else => {},
        }
        if (!self.established or self.output_suppressed or self.reactivating) return;
        if (!channels.graphicsReady(self)) return;
        if (surfaces.isMulti(self)) {
            if (!try surfaces.pump(self, d)) return;
        } else {
            if (!channels.canSendFrame(self)) {
                if (d.frameReady()) {
                    if (self.pacing.refused) self.pacing.held() else self.ch.stats.blocked += 1;
                }
                return;
            }
            const f = d.takeFrame() orelse return;
            if (f.width != d.width() or f.height != d.height()) {
                // RDP-1 is briefly at another mode (Hyprland's rule after a config reload): skip unless it lasts.
                const now = nowMs();
                const since = self.odd_size_since_ms orelse now;
                self.odd_size_since_ms = since;
                if (now - since < self.odd_size_grace_ms) {
                    log.debug("{s}: skipping a {d}x{d} frame (the session is {d}x{d})", .{ self.peer, f.width, f.height, d.width(), d.height() });
                    return d.requestFrame();
                }
                if (!self.odd_size_taken) {
                    self.odd_size_taken = true;
                    log.info("{s}: RDP-1 stays {d}x{d}, not {d}x{d}: the client gets that size", .{ self.peer, f.width, f.height, d.width(), d.height() });
                }
            } else {
                self.odd_size_since_ms = null;
                self.odd_size_taken = false;
            }
            channels.sendDesktopFrame(self, f) catch |err| switch (err) {
                // A malformed frame is skipped; the client keeps its picture.
                error.InvalidDimensions => log.warn("{s}: skipping a {d}x{d} frame with stride {d} and {d} bytes", .{ self.peer, f.width, f.height, f.stride, f.data.len }),
                else => return err,
            };
            try d.requestFrame();
        }
        if (self.secret) |sec| {
            // The client now sees the lock screen (if any): unlock it.
            defer self.wipeSecret();
            d.beginUnlock(sec) catch |err| log.warn("{s}: unlock failed: {t}", .{ self.peer, err });
        }
    }

    pub fn handleIo(self: *Conn, data: []const u8) Error!void {
        self.flight.slowPath(.in, data);
        const pdu = switch (try rdp.parseShareControl(data)) {
            .data => |d| d,
            .confirm_active => |ca| {
                // Only as the answer to the Demand Active of a reactivation.
                if (!self.reactivating or ca.share_id != rdp.share_id) return error.ProtocolError;
                self.client_caps = ca.caps;
                self.fastpath_output = ca.caps.fastpathOutput();
                legacy.onConfirmActive(self);
                pointer_mod.reset(&self.pointer, &self.client_caps, self.fastpath_output);
                log.info("{s}: reactivated at {d}x{d}", .{ self.peer, self.width, self.height });
                try self.sendIo(rdp.writeSynchronize, .{@as(u16, 0)}); // targetUser 0 (3.3.5.3.19)
                try self.sendIo(rdp.writeControl, .{ rdp.ctrlaction_cooperate, 0, 0 });
                return;
            },
            .other => |t| {
                log.debug("{s}: ignoring share control type {d}", .{ self.peer, @backingInt(t) });
                return;
            },
            .flow => return, // T.128 FlowPDU: ignored (MS-RDPBCGR 2.2.8.1.1.1.1)
        };
        switch (pdu.type2) {
            .synchronize, .bitmapcache_persistent_list => {},
            // MS-RDPRFX 2.2.3.1, for surface commands or bitmaps.
            .frame_acknowledge => try legacy.onFrameAck(self, pdu.body),
            .control => {
                // Request Control is answered with Granted Control (MS-RDPBCGR 3.3.5.3.16).
                const ctl = try rdp.parseControl(pdu.body);
                if (ctl.action == rdp.ctrlaction_request_control)
                    try self.sendIo(rdp.writeControl, .{ rdp.ctrlaction_granted_control, self.user_id, @as(u32, rdp.server_source) });
            },
            .fontlist => {
                if (!self.reactivating and !self.established) {
                    // Established (MS-RDPBCGR 1.3.1.1): the Font Map and post-logon PDUs (3.3.5.10.1) in one write.
                    var body: std.ArrayList(u8) = .empty;
                    defer body.deinit(self.gpa);
                    var bw = bytes.Writer.init(&body, self.gpa);
                    try rdp.writeFontMap(&bw);
                    try self.queueMcs(mcs.io_channel_id, body.items);
                    self.established = true;
                    self.flight.note(.established, &.{});
                    try session_info.onEstablished(self); // flushes
                } else {
                    try self.sendIo(rdp.writeFontMap, .{});
                }
                if (self.reactivating) {
                    // Reactivated (1.3.1.3): the whole picture again.
                    self.reactivating = false;
                    return channels.refresh(self);
                }
                deadline.stop(&self.deadline);
                log.info("{s}: connection established", .{self.peer});
                self.established_ms = nowMs();
                if (self.desktop) |d| {
                    // Hidden while the cursor is painted into frames, else its shape.
                    try pointer_mod.pump(self, &d.cursor);
                    try self.flush();
                } else {
                    try self.sendFullFrame();
                }
                try vc.start(self);
            },
            .refresh_rect => {
                // numberOfAreas is 8-bit: up to 255 areas (2.2.11.2.1).
                var rects: [255]rdp.Rect16 = undefined;
                _ = try rdp.parseRefreshRect(pdu.body, &rects);
                try channels.refresh(self);
            },
            .suppress_output => {
                const allow = try rdp.parseSuppressOutput(pdu.body);
                self.output_suppressed = !allow;
                log.info("{s}: output {s}", .{ self.peer, if (allow) "resumed" else "suppressed" });
                if (allow) try channels.refresh(self);
            },
            .shutdown_request => {
                // Deny shutdown ("don't log off"); the client then disconnects.
                var body: std.ArrayList(u8) = .empty;
                defer body.deinit(self.gpa);
                var w = bytes.Writer.init(&body, self.gpa);
                const p = try rdp.DataPdu.begin(&w, .shutdown_denied, rdp.stream_low);
                p.finish(&w);
                try self.sendMcs(mcs.io_channel_id, body.items);
            },
            .input => {
                var it = try fastpath.SlowInput.init(pdu.body);
                // Counted by type, also when an event is bad.
                var counts: flight.InputCounts = .{};
                defer self.flight.input(.slowpath, data.len, counts);
                while (try it.next()) |ev| {
                    counts.add(ev);
                    self.input_events += 1;
                    try self.onInput(ev);
                }
            },
            else => log.debug("{s}: unhandled data pdu {d}", .{ self.peer, @backingInt(pdu.type2) }),
        }
    }

    /// Update kinds (MS-RDPBCGR 2.2.9.1); surface commands are fast-path only.
    pub const Update = enum { bitmap, surfcmds, ptr_null, ptr_default, ptr_position, ptr_cached, ptr_color, ptr_new, ptr_large };

    fn isPointer(kind: Update) bool {
        return switch (kind) {
            .bitmap, .surfcmds => false,
            else => true,
        };
    }

    /// Queues one update: fast-path, or a slow-path Update or Pointer PDU (MS-RDPBCGR 2.2.9.1.1.3, 2.2.9.1.1.4).
    pub fn queueUpdate(self: *Conn, kind: Update, data: []const u8) Error!void {
        const cmp = self.updateCompressor(kind);
        if (self.fastpath_output) {
            const code: fastpath.UpdateCode = switch (kind) {
                .bitmap => .bitmap,
                .surfcmds => .surfcmds,
                .ptr_null => .ptr_null,
                .ptr_default => .ptr_default,
                .ptr_position => .ptr_position,
                .ptr_cached => .cached,
                .ptr_color => .color,
                .ptr_new => .pointer,
                .ptr_large => .large_pointer,
            };
            return self.queueFastPath(code, data, cmp);
        }
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.gpa);
        var bw = bytes.Writer.init(&body, self.gpa);
        const p = switch (kind) {
            .surfcmds => return error.ProtocolError,
            .bitmap => blk: {
                const p = try rdp.DataPdu.begin(&bw, .update, rdp.stream_low);
                try bw.bytes(data); // updateType UPDATETYPE_BITMAP first
                break :blk p;
            },
            .ptr_null, .ptr_default => blk: {
                const p = try rdp.DataPdu.begin(&bw, .pointer, rdp.stream_low);
                try bw.u16le(@backingInt(pointer_proto.MessageType.system));
                try bw.u16le(0); // pad2Octets
                try bw.u32le(if (kind == .ptr_null) pointer_proto.sysptr_null else pointer_proto.sysptr_default);
                break :blk p;
            },
            .ptr_position, .ptr_cached, .ptr_color, .ptr_new, .ptr_large => blk: {
                const p = try rdp.DataPdu.begin(&bw, .pointer, rdp.stream_low);
                const t: pointer_proto.MessageType = switch (kind) {
                    .ptr_position => .position,
                    .ptr_cached => .cached,
                    .ptr_color => .color,
                    .ptr_new => .pointer,
                    else => .large,
                };
                try bw.u16le(@backingInt(t));
                try bw.u16le(0); // pad2Octets
                try bw.bytes(data);
                break :blk p;
            },
        };
        // Reserve room first so nothing fails between compressing and queueing (one history).
        try self.out.ensureUnusedCapacity(self.gpa, 16 + body.items.len);
        if (cmp) |x| try p.finishCompressed(&bw, x) else p.finish(&bw);
        self.flight.slowPath(.out, body.items);
        self.queueIoBody(body.items);
    }

    /// Writes a Send Data Indication for `body` into `out`; the caller reserved the room.
    fn queueIoBody(self: *Conn, body: []const u8) void {
        var w = self.writer();
        const f = x224.beginData(&w) catch unreachable;
        mcs.writeSendDataIndicationHeader(&w, mcs.io_channel_id, body.len) catch unreachable;
        w.bytes(body) catch unreachable;
        f.finish(&w);
    }

    /// Graphics compress only on links not measured fast; uncompressed packets keep the history (MS-RDPBCGR 3.1.8.3).
    pub fn updateCompressor(self: *Conn, kind: Update) ?*bulk.Compressor {
        const cmp = self.bulk.output() orelse return null;
        if (isPointer(kind)) return cmp;
        const r = self.netchar.det.results;
        return if (adapt.compressGraphics(.{ .base_rtt = r.base_rtt, .average_rtt = r.average_rtt, .bandwidth = r.bandwidth })) cmp else null;
    }

    /// One fast-path update (MS-RDPBCGR 2.2.9.1.2.1) in fragments of at most bulk.maxInput bytes; one
    /// the client cannot reassemble at that size (2.2.7.2.6) goes whole and uncompressed.
    fn queueFastPath(self: *Conn, code: fastpath.UpdateCode, data: []const u8, compressor: ?*bulk.Compressor) Error!void {
        self.flight.fastPathOut(code, data, compressor != null);
        var w = self.writer();
        const cmp = compressor orelse return fastpath.writeUpdateFragmented(&w, code, data);
        const piece = @min(fastpath.max_update_payload, try bulk.maxInput(cmp.type));
        if (data.len > piece and data.len <= fastpath.max_update_payload and
            data.len > self.client_caps.multifragment_max_request_size)
            return fastpath.writeUpdate(&w, code, .single, data);
        var off: usize = 0;
        while (true) {
            const n = @min(piece, data.len - off);
            const frag: fastpath.Fragment = if (n == data.len) .single else if (off == 0) .first else if (off + n == data.len) .last else .next;
            // Reserve room first: a compressed packet must reach `out` (one history).
            try self.out.ensureUnusedCapacity(self.gpa, 8 + n);
            const r = try cmp.compress(data[off..][0..n]);
            fastpath.writeUpdateCompressed(&w, code, frag, r.flags, r.data) catch unreachable;
            off += n;
            if (off == data.len) return;
        }
    }

    /// Queues alternate secondary drawing orders (MS-RDPERP 2.2.1.3) as Orders Updates (MS-RDPBCGR
    /// 2.2.9.1.2.1.2); an order too large for the client's MultifragmentUpdate size is dropped.
    pub fn queueOrders(self: *Conn, orders: []const u8) Error!void {
        // Fast-path adds numberOrders (2); slow-path updateType, pads and numberOrders (8).
        const limit: usize = if (self.fastpath_output) fastpath.max_update_payload - 2 else max_slow_update - 8;
        // A slow-path Share Data PDU is compressed whole (MS-RDPBCGR 3.1.8.1).
        var pack: usize = limit;
        if (!self.fastpath_output) if (self.bulk.output()) |cmp| {
            pack = @min(pack, try bulk.maxInput(cmp.type) - 8);
        };
        var off: usize = 0;
        while (off < orders.len) {
            var end = off;
            var count: u16 = 0;
            while (end < orders.len) {
                if (orders.len - end < 3) return error.ProtocolError;
                const size = std.mem.readInt(u16, orders[end + 1 ..][0..2], .little);
                if (size < 3 or size > orders.len - end) return error.ProtocolError;
                if (count > 0 and end + size - off > pack) break;
                end += size;
                count += 1;
                if (end - off > pack) break; // a large order goes alone
            }
            const batch = orders[off..end];
            off = end;
            if (batch.len > limit) {
                const max = self.client_caps.multifragment_max_request_size;
                if (!self.fastpath_output or batch.len + 2 > max) {
                    log.warn("{s}: dropping a {d}-byte drawing order (client takes {d})", .{ self.peer, batch.len, if (self.fastpath_output) max else limit });
                    continue;
                }
            }
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var bw = bytes.Writer.init(&body, self.gpa);
            if (self.fastpath_output) {
                try bw.u16le(count);
                try bw.bytes(batch);
                try self.queueFastPath(.orders, body.items, self.bulk.output());
                continue;
            }
            const p = try rdp.DataPdu.begin(&bw, .update, rdp.stream_low);
            try bw.u16le(0); // UPDATETYPE_ORDERS
            try bw.u16le(0); // pad2OctetsA
            try bw.u16le(count);
            try bw.u16le(0); // pad2OctetsB
            try bw.bytes(batch);
            try self.out.ensureUnusedCapacity(self.gpa, 16 + body.items.len); // queueUpdate
            if (self.bulk.output()) |cmp| try p.finishCompressed(&bw, cmp) else p.finish(&bw);
            self.flight.slowPath(.out, body.items);
            self.queueIoBody(body.items);
        }
    }

    /// Deactivation-Reactivation Sequence (MS-RDPBCGR 1.3.1.3) for a client without RDPGFX.
    pub fn reactivate(self: *Conn) Error!void {
        log.info("{s}: reactivating for {d}x{d}", .{ self.peer, self.width, self.height });
        self.reactivating = true;
        try self.sendIo(rdp.writeDeactivateAll, .{});
        try self.sendIo(rdp.writeDemandActive, .{ self.serverCaps(), 0 });
        try session_info.sendMonitorLayout(self); // 1.3.1.1 step 9, as at connect
    }

    /// The whole test-pattern framebuffer as one lossless frame, or over RDPGFX once it is up.
    pub fn sendFullFrame(self: *Conn) Error!void {
        if (self.output_suppressed or self.reactivating) return;
        if (self.ch.gfx_ready) return channels.sendGfxFrame(self);
        const fb = &(self.fb orelse return);
        if (self.enc.width != fb.width or self.enc.height != fb.height) try self.enc.reset(fb.width, fb.height);
        self.enc.invalidate();
        _ = try self.enc.diff(fb.pixels, fb.stride);
        try legacy.sendLossless(self);
    }
};

/// Most update data in one slow-path Update PDU (MS-RDPBCGR 2.2.9.1.1.3): PER length <= 0x3FFF.
pub const max_slow_update = 0x3FFF - rdp.data_header_len;

pub fn nowMs() i64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(i64, ts.tv_sec) * 1000 + @divTrunc(@as(i64, ts.tv_nsec), 1_000_000);
}

pub fn nowNs() u64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(u64, @intCast(ts.tv_sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.tv_nsec));
}

/// Input PDUs read per loop pass, so an input flood cannot hold up output.
const max_input_pdus: u32 = 256;

fn x224BeginEnd(w: *bytes.Writer, comptime build: anytype, args: anytype) !void {
    const f = try x224.beginData(w);
    try @call(.auto, build, .{w} ++ args);
    f.finish(w);
}

fn asciiFromUtf16(buf: []u8, s: []const u8) []const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i + 1 < s.len and n < buf.len) : (i += 2) {
        const ch = @as(u16, s[i]) | @as(u16, s[i + 1]) << 8;
        buf[n] = if (ch >= 0x20 and ch < 0x7F) @intCast(ch) else '?';
        n += 1;
    }
    return buf[0..n];
}

fn logInput(ev: fastpath.InputEvent) void {
    switch (ev) {
        .scancode => |k| log.debug("key 0x{x:0>2} flags 0x{x}", .{ k.code, k.flags }),
        .mouse => |m| if (m.flags != fastpath.ptr_move) log.debug("mouse 0x{x:0>4} at {d},{d}", .{ m.flags, m.x, m.y }),
        .unicode => |u| log.debug("unicode U+{x:0>4} release={}", .{ u.code, u.release }),
        .sync => |s| log.debug("sync toggles 0x{x}", .{s}),
        else => {},
    }
}

/// No Ultimatum or TLS close_notify, or the client stopped reading: the session may wait for a reconnect.
fn isNetworkLoss(err: Error) bool {
    return switch (err) {
        error.ConnectionClosed, error.ReadFailed, error.WriteFailed, error.TlsReadFailed, error.TlsWriteFailed, error.ClientTooSlow => true,
        error.UdpTunnelLost => true,
        else => false,
    };
}

fn wlConnectionEnded(err: Error) bool {
    return switch (err) {
        error.ConnectionClosed, error.ReadFailed, error.WriteFailed => true,
        else => false,
    };
}

test "compositor loss is not a network loss" {
    try std.testing.expect(isNetworkLoss(error.ConnectionClosed));
    try std.testing.expect(isNetworkLoss(error.TlsReadFailed));
    try std.testing.expect(!isNetworkLoss(error.CompositorGone));
    try std.testing.expect(isNetworkLoss(error.UdpTunnelLost));
    try std.testing.expect(!isNetworkLoss(error.ProtocolError));
    try std.testing.expect(wlConnectionEnded(error.ConnectionClosed));
    try std.testing.expect(!wlConnectionEnded(error.ProtocolError));
}
