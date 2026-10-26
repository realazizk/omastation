//! RDPGFX graphics pipeline and Display Control (resize) for one connection,
//! with bitmap updates when RDPGFX is unavailable.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const gfx = @import("../proto/gfx.zig");
const disp = @import("../proto/disp.zig");
const fastpath = @import("../proto/fastpath.zig");
const zgfx = @import("../codec/zgfx.zig");
const clear_codec = @import("../codec/clear.zig");
const wl = @import("../wl/wl.zig");
const framebuffer = @import("framebuffer.zig");
const adapt_mod = @import("adapt.zig");
const codec_policy = @import("codec_policy.zig");
const gfx_codecs = @import("gfx_codecs.zig");
const autodetect = @import("autodetect.zig");
const legacy = @import("legacy.zig");
const vc = @import("vc.zig");
const surfaces = @import("surfaces.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.chan);

/// Fixed DVC ChannelIds (vc.Dynamic.id).
pub const gfx_channel_id: u32 = 1;
pub const disp_channel_id: u32 = 2;

/// How long to wait for the graphics pipeline before using bitmap updates.
const gfx_wait_ms = 3000;

/// Graphics pipeline counters, logged and reset every `stats_interval_ms` while frames flow.
pub const Stats = struct {
    since_ms: i64 = 0,
    frames: u64 = 0,
    rects: u64 = 0,
    pixels: u64 = 0,
    /// RDPGFX bytes before ZGFX, and on the wire (DVC framing excluded).
    raw_bytes: u64 = 0,
    wire_bytes: u64 = 0,
    diff_ns: u64 = 0,
    encode_ns: u64 = 0,
    zgfx_ns: u64 = 0,
    send_ns: u64 = 0,
    acks: u64 = 0,
    ack_ns: u64 = 0,
    blocked: u64 = 0,
    avc_frames: u64 = 0,
    avc444_frames: u64 = 0,
    prog_frames: u64 = 0,
    rfx_frames: u64 = 0,
    refines: u64 = 0,
    refine_rects: u64 = 0,
    avc_refines: u64 = 0,
    upgrades: u64 = 0,
    clear_rects: u64 = 0,
    planar_rects: u64 = 0,
    video_frames: u64 = 0,
    h264_bytes: u64 = 0,
};

const stats_interval_ms = 5000;

/// Share of the screen outside the video region that must change in a frame to switch to motion.
pub const avc_min_change = 0.10;
/// Minimum frames on the motion codec once switched, to avoid flapping.
pub const avc_hold_frames = 8;
/// Quiet time after which lossy tiles are re-sent losslessly.
pub const refine_after_ms = 150;

pub const State = struct {
    /// Caps confirmed and a surface mapped: frames go over RDPGFX.
    gfx_ready: bool = false,
    /// No RDPGFX for this client: frames go as bitmap updates.
    gfx_refused: bool = false,
    /// Its history spans the channel's lifetime, so every compressed message must be sent.
    zgfx: ?zgfx.Compressor = null,
    surface_w: u32 = 0,
    surface_h: u32 = 0,
    /// A Display Control resize without RDPGFX: reactivate when frames of the new size arrive.
    reactivate_on_resize: bool = false,
    gfx_caps: gfx.CapSet = .{ .version = 0, .flags = 0 },
    surface_id: ?u16 = null,
    next_surface_id: u16 = 1,
    frame_id: u32 = 0,
    frames_unacked: u32 = 0,
    stats: Stats = .{},
    sent_ns: [32]u64 = @splat(0),
    policy: codec_policy.Gfx = .{},
    codec_off: std.EnumSet(codec_policy.Motion) = .empty,
    surf: gfx_codecs.Surface = .{},
    /// ClearCodec encoder, one per graphics channel (MS-RDPEGFX 3.3.8.1).
    clear: ?clear_codec.Encoder = null,
    next_codec_ctx: u32 = 1,
    /// No H.264 for this connection (client caps, or no VA-API encoder).
    avc_off: bool = false,
    motion_frames: u32 = 0,
    last_frame_ms: i64 = 0,
    acks_suspended: bool = false,
    /// Monitors for RESET_GRAPHICS, relative to the desktop origin.
    monitors: [disp.max_monitors]gfx.Monitor = undefined,
    monitor_count: usize = 0,
    upright: []u8 = &.{},
    adapt: adapt_mod.State = .{},
    legacy: legacy.State = .{},
    /// ZGFX ratio x16 (moving average): budgets are in wire bytes, content is counted before ZGFX.
    zgfx_ratio_x16: u32 = 16,
    /// Recent progressive and RemoteFX cost, hundredths of a bit per pixel.
    prog_bpp_x100: u32 = 50,
    rfx_bpp_x100: u32 = 100,

    /// A wire-byte budget as pre-ZGFX bytes at the recent ratio (1x to 8x).
    pub fn rawBudget(s: *const State, wire: usize) usize {
        if (wire == std.math.maxInt(usize)) return wire;
        return wire / 16 * s.zgfx_ratio_x16;
    }

    pub fn deinit(s: *State, gpa: std.mem.Allocator) void {
        gpa.free(s.upright);
        if (s.zgfx) |*z| z.deinit();
        s.surf.deinit(gpa);
        if (s.clear) |*e| e.deinit();
        s.legacy.deinit(gpa);
    }

    /// Whether the Graphics channel is open. State is always `Conn.ch`.
    pub fn gfxOpen(s: *const State) bool {
        const c: *const Conn = @alignCast(@fieldParentPtr("ch", s));
        return c.vc.isOpen(gfx_channel_id);
    }

    pub fn dispOpen(s: *const State) bool {
        const c: *const Conn = @alignCast(@fieldParentPtr("ch", s));
        return c.vc.isOpen(disp_channel_id);
    }
};

pub const start = vc.start;
pub const onDrdynvc = vc.onDrdynvc;

/// Display Control channel (MS-RDPEDISP): client monitor layouts resize the session.
pub const DisplayControl = struct {
    pub const dynamic_channels = [_]vc.Dynamic{.{ .name = disp.channel_name, .id = disp_channel_id }};

    c: *Conn,

    pub fn init(c: *Conn) vc.Error!?DisplayControl {
        if (c.vc.drdynvc == null) return null;
        return .{ .c = c };
    }

    /// Sends DISPLAYCONTROL_CAPS (MS-RDPEDISP 2.2.2.1) on open (3.1.5.1).
    pub fn open(self: *DisplayControl, ch: vc.Channel) vc.Error!void {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(self.c.gpa);
        var w = bytes.Writer.init(&list, self.c.gpa);
        try disp.writeCaps(&w, disp.max_monitors, disp.max_monitor_area_factor_a, disp.max_monitor_area_factor_b);
        try ch.send(list.items);
    }

    pub fn data(self: *DisplayControl, _: vc.Channel, msg: []const u8) vc.Error!void {
        try onDisp(self.c, msg);
    }
};

/// Graphics pipeline channel (MS-RDPEGFX); without it frames go as bitmap updates.
pub const Graphics = struct {
    /// Already ZGFX-compressed (MS-RDPEGFX 2.2.5), so no bulk compression.
    pub const dynamic_channels = [_]vc.Dynamic{.{ .name = gfx.channel_name, .id = gfx_channel_id, .compress = false }};

    c: *Conn,

    pub fn init(c: *Conn) vc.Error!?Graphics {
        if (c.vc.drdynvc == null) {
            log.info("{s}: client has no drdynvc channel; staying on bitmap updates", .{c.peer});
            c.ch.gfx_refused = true;
            return null;
        }
        if (c.desktop != null) setSingleMonitor(c) else initMonitorsFromClientData(c);
        if (!c.client.early_caps.support_dynvc_gfx_protocol or !c.vc.opts.graphics.rdpgfx) {
            c.ch.gfx_refused = true;
            return null;
        }
        if (c.bpp != 32) {
            // Windows clients render RDPGFX into 32 bpp output only.
            log.info("{s}: {d} bpp session: bitmap updates, no RDPGFX (it needs 32 bpp)", .{ c.peer, c.bpp });
            c.ch.gfx_refused = true;
            return null;
        }
        if (c.remoteapp) {
            // RAIL clients paint windows from the desktop bitmap, not a mapped surface (MS-RDPEGFX 2.2.2.20).
            log.info("{s}: RemoteApp: desktop frames as bitmap updates", .{c.peer});
            c.ch.gfx_refused = true;
            return null;
        }
        return .{ .c = c };
    }

    pub fn data(self: *Graphics, _: vc.Channel, msg: []const u8) vc.Error!void {
        try onGfx(self.c, msg);
    }

    pub fn close(self: *Graphics, _: vc.Channel, why: vc.Closed) void {
        if (why == .refused) {
            self.c.ch.gfx_refused = true;
            return;
        }
        pipelineGone(self.c);
    }
};

/// RDPGFX is gone: fall back to bitmap updates, starting with a full picture.
fn pipelineGone(c: *Conn) void {
    c.ch.gfx_refused = true;
    c.ch.gfx_ready = false;
    c.ch.surface_id = null;
    c.enc.invalidate();
    c.ch.surf.reset();
}

fn sendDvc(c: *Conn, channel_id: u32, msg: []const u8) conn_mod.Error!void {
    try vc.sendDynamic(c, channel_id, msg);
}

/// Queues RDPGFX PDUs as RDP_SEGMENTED_DATA (ZGFX once ready); returns bytes queued.
pub fn sendGfx(c: *Conn, msg: []const u8) conn_mod.Error!usize {
    const pdus = c.flight.gfxOut(msg);
    var seg: std.ArrayList(u8) = .empty;
    defer seg.deinit(c.gpa);
    var w = bytes.Writer.init(&seg, c.gpa);
    if (c.ch.zgfx) |*z| {
        // On a slow link every byte counts; elsewhere segments that barely shrink go raw early.
        z.opts.bail_gain_x16 = if (c.ch.adapt.slow()) 0 else zgfx_bail_gain_x16;
        try z.writeSegmented(&w, msg);
    } else {
        try gfx.writeSegmented(&w, msg);
    }
    try sendDvc(c, gfx_channel_id, seg.items);
    c.flight.gfxWire(msg.len, seg.items.len, pdus);
    if (msg.len >= zgfx_ratio_min_bytes and seg.items.len > 0) {
        const r: u32 = @intCast(std.math.clamp(msg.len * 16 / seg.items.len, 16, 8 * 16));
        c.ch.zgfx_ratio_x16 = (c.ch.zgfx_ratio_x16 * 3 + r) / 4;
    }
    return seg.items.len;
}

const zgfx_ratio_min_bytes = 16 * 1024;
/// ZGFX gives a segment up when it saves under 2/16 (zgfx.Options.bail_gain_x16).
const zgfx_bail_gain_x16: u8 = 2;

fn setSingleMonitor(c: *Conn) void {
    c.ch.monitors[0] = .{ .left = 0, .top = 0, .right = @as(i32, c.width) - 1, .bottom = @as(i32, c.height) - 1, .primary = true };
    c.ch.monitor_count = 1;
}

fn monitorsCover(c: *const Conn, w: u32, h: u32) bool {
    const ms = c.ch.monitors[0..c.ch.monitor_count];
    if (ms.len == 0) return false;
    var x0: i64 = std.math.maxInt(i64);
    var y0: i64 = std.math.maxInt(i64);
    var x1: i64 = std.math.minInt(i64);
    var y1: i64 = std.math.minInt(i64);
    for (ms) |m| {
        x0 = @min(x0, m.left);
        y0 = @min(y0, m.top);
        x1 = @max(x1, m.right);
        y1 = @max(y1, m.bottom);
    }
    return x0 == 0 and y0 == 0 and x1 == @as(i64, w) - 1 and y1 == @as(i64, h) - 1;
}

fn initMonitorsFromClientData(c: *Conn) void {
    const ms = c.client.monitorSlice();
    if (ms.len == 0) {
        c.ch.monitors[0] = .{ .left = 0, .top = 0, .right = @as(i32, c.client.desktop_width) - 1, .bottom = @as(i32, c.client.desktop_height) - 1, .primary = true };
        c.ch.monitor_count = 1;
        return;
    }
    // RESET_GRAPHICS wants monitors relative to the bounding box's top-left.
    var x0: i64 = std.math.maxInt(i64);
    var y0: i64 = std.math.maxInt(i64);
    for (ms) |m| {
        x0 = @min(x0, m.left);
        y0 = @min(y0, m.top);
    }
    for (ms, 0..) |m, i| {
        const r = .{ @as(i64, m.left) - x0, @as(i64, m.top) - y0, @as(i64, m.right) - x0, @as(i64, m.bottom) - y0 };
        inline for (r) |v| if (v > 32766) {
            log.warn("{s}: client monitors span more than 32766 pixels; using the desktop size", .{c.peer});
            c.client.monitor_count = 0;
            return initMonitorsFromClientData(c);
        };
        c.ch.monitors[i] = .{ .left = @intCast(r[0]), .top = @intCast(r[1]), .right = @intCast(r[2]), .bottom = @intCast(r[3]), .primary = m.primary };
    }
    c.ch.monitor_count = ms.len;
}

fn onGfx(c: *Conn, msg: []const u8) conn_mod.Error!void {
    switch (try gfx.parseClientPdu(msg)) {
        .caps_advertise => |body| {
            const cs = (try gfx.chooseCaps(body)) orelse {
                log.warn("{s}: no RDPGFX version in common; staying on bitmap updates", .{c.peer});
                // Close the channel so the client stops waiting (MS-RDPEGFX 3.2.5.19).
                try vc.closeDynamic(c, gfx_channel_id);
                // closeDynamic does not call Graphics.close, so end a running pipeline here.
                pipelineGone(c);
                try c.flush();
                return;
            };
            c.ch.gfx_caps = cs;
            // The client drops its surfaces and codec state on CAPS_ADVERTISE (3.2.5.18).
            c.ch.surface_id = null;
            c.ch.surf.reset();
            log.info("{s}: RDPGFX caps confirmed: version 0x{x:0>8} flags 0x{x}", .{ c.peer, cs.version, cs.flags });
            try gfx_codecs.onCapsConfirmed(c, cs);
            startAdapt(c);
            if (c.ch.zgfx) |*z| z.reset() else c.ch.zgfx = try zgfx.Compressor.init(c.gpa);
            var list: std.ArrayList(u8) = .empty;
            defer list.deinit(c.gpa);
            var w = bytes.Writer.init(&list, c.gpa);
            try gfx.writeCapsConfirm(&w, cs);
            _ = try sendGfx(c, list.items);
            // Earlier bitmap-update frames may have another size: the surface takes it.
            if (c.enc.width != 0 and (c.enc.width != c.width or c.enc.height != c.height)) {
                c.width = @intCast(c.enc.width);
                c.height = @intCast(c.enc.height);
                if (!monitorsCover(c, c.width, c.height)) setSingleMonitor(c);
            }
            try resetGraphics(c);
            c.ch.gfx_ready = true;
            c.ch.gfx_refused = false;
            c.ch.frames_unacked = 0;
            c.enc.invalidate();
            if (c.desktop != null) {
                try refresh(c);
            } else {
                try sendGfxFrame(c);
            }
            // The confirm must go out now, frame or not.
            try c.flush();
        },
        .frame_acknowledge => |fa| {
            log.debug("{s}: frame {d} acknowledged (queue depth {d}, {d} decoded)", .{ c.peer, fa.frame_id, fa.queue_depth, fa.total_decoded });
            const suspend_acks = fa.queue_depth == gfx.suspend_frame_acknowledgement;
            if (suspend_acks != c.ch.acks_suspended) log.info("{s}: frame acknowledgements {s} at frame {d}", .{ c.peer, if (suspend_acks) "suspended" else "resumed", fa.frame_id });
            c.ch.acks_suspended = suspend_acks;
            if (suspend_acks) {
                // MS-RDPEGFX 3.2.5.13: no more acknowledgements are expected.
                c.ch.frames_unacked = 0;
            } else {
                // Acks arrive in order (MS-RDPEGFX 3.3.5.13); per-ack counting would stall after a resumed suspend.
                const after = c.ch.frame_id -% fa.frame_id;
                c.ch.frames_unacked = if (after <= c.ch.frames_unacked) after else c.ch.frames_unacked -| 1;
                c.pacing.onFrameAck(fa.queue_depth, conn_mod.nowMs());
            }
            const sent = c.ch.sent_ns[fa.frame_id % c.ch.sent_ns.len];
            if (sent != 0 and !suspend_acks) {
                const ns = nowNs() -| sent;
                c.ch.stats.acks += 1;
                c.ch.stats.ack_ns += ns;
                c.ch.adapt.onAck(@intCast(@min(ns / std.time.ns_per_ms, std.math.maxInt(u32))));
                c.ch.sent_ns[fa.frame_id % c.ch.sent_ns.len] = 0;
            }
        },
        .cache_import_offer => {
            var list: std.ArrayList(u8) = .empty;
            defer list.deinit(c.gpa);
            var w = bytes.Writer.init(&list, c.gpa);
            try gfx.writeCacheImportReply(&w);
            _ = try sendGfx(c, list.items);
            try c.flush();
        },
        .qoe_frame_acknowledge => {},
        .other => |cmd| log.debug("{s}: RDPGFX cmd 0x{x} from client (ignored)", .{ c.peer, cmd }),
    }
}

pub fn resetGraphics(c: *Conn) conn_mod.Error!void {
    if (surfaces.isMulti(c)) return surfaces.resetGraphics(c);
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(c.gpa);
    var w = bytes.Writer.init(&list, c.gpa);
    if (c.ch.surface_id) |old| {
        // Delete the progressive context with its surface (MS-RDPEGFX 2.2.2.3).
        if (c.ch.surf.prog_live) try gfx_codecs.writeDeleteContext(c, &w, old);
        try gfx.writeDeleteSurface(&w, old);
    }
    try gfx.writeResetGraphics(&w, c.width, c.height, c.ch.monitors[0..c.ch.monitor_count]);
    const sid = c.ch.next_surface_id;
    c.ch.next_surface_id +%= 1;
    try gfx.writeCreateSurface(&w, sid, c.width, c.height);
    try gfx.writeMapSurfaceToOutput(&w, sid, 0, 0);
    c.ch.surface_id = sid;
    c.ch.surface_w = c.width;
    c.ch.surface_h = c.height;
    c.ch.surf.reset();
    _ = try sendGfx(c, list.items);
}

fn startAdapt(c: *Conn) void {
    const r = c.netchar.det.results;
    const a = &c.ch.adapt;
    a.start(.{ .base_rtt = r.base_rtt, .average_rtt = r.average_rtt, .bandwidth = r.bandwidth });
    var rtt_buf: [32]u8 = undefined;
    var bw_buf: [32]u8 = undefined;
    log.info("{s}: link: RTT {s}, bandwidth {s}: {s}; frames {d} ms apart at most, quality and size from the send window{s}", .{
        c.peer,
        if (r.average_rtt) |avg| std.fmt.bufPrint(&rtt_buf, "{d} ms (base {d} ms)", .{ avg, r.base_rtt orelse avg }) catch "?" else "unmeasured",
        if (r.bandwidth) |bw| std.fmt.bufPrint(&bw_buf, "{d} kbit/s", .{bw}) catch "?" else "unmeasured",
        if (a.slow()) "slow (lossy CPU codecs for motion)" else if (a.lan()) "LAN" else "fast",
        c.pacing.interval_ms,
        if (c.bulk.output() == null) "" else if (c.updateCompressor(.bitmap) != null) "; bitmap updates bulk-compressed" else "; bitmap updates not bulk-compressed (fast link)",
    });
}

fn adaptTick(c: *Conn) void {
    const a = &c.ch.adapt;
    if (!a.started) {
        // Bitmap updates adapt too, once RDPGFX is known to be absent.
        if (!c.ch.gfx_refused or !c.established) return;
        startAdapt(c);
    }
    const nd = &c.flow.nd;
    if (c.flow.mode != .probes or !nd.base_known) return;
    a.onLink(.{
        .base_rtt = @intFromFloat(@min(nd.base, 1e9)),
        .average_rtt = @intFromFloat(@min(nd.srtt, 1e9)),
        .bandwidth = @intFromFloat(@min(nd.published, 1e12)),
    });
}

/// Frames may flow: RDPGFX is up, or the client won't use it (none, refused, or `gfx_wait_ms` passed).
pub fn graphicsReady(c: *Conn) bool {
    if (c.ch.gfx_ready or c.ch.gfx_refused) return true;
    if (conn_mod.nowMs() - c.established_ms > gfx_wait_ms) {
        log.warn("{s}: no graphics pipeline after {d} ms; using bitmap updates", .{ c.peer, gfx_wait_ms });
        c.ch.gfx_refused = true;
        return true;
    }
    return false;
}

/// Frame admission (pacing.zig); no ack bound while acks are suspended (MS-RDPEGFX 2.2.2.13).
pub fn canSendFrame(c: *Conn) bool {
    c.pacing.refused = false;
    if (!c.ch.gfx_ready) return legacy.canSendFrame(c);
    c.gfxBacklog(gfx_channel_id);
    return c.graphicsAdmit(if (c.ch.acks_suspended) null else c.ch.frames_unacked);
}

pub fn sendDesktopFrame(c: *Conn, f: *const wl.Frame) conn_mod.Error!void {
    // Reject malformed compositor frames before reading any pixel.
    if (f.width == 0 or f.height == 0 or f.width > disp.max_desktop or f.height > disp.max_desktop) return error.InvalidDimensions;
    if (@as(u64, f.stride) < @as(u64, f.width) * 4) return error.InvalidDimensions;
    if (f.data.len < @as(u64, f.stride) * (f.height - 1) + @as(u64, f.width) * 4) return error.InvalidDimensions;
    const lay = pixelLayout(f.format) orelse {
        log.warn("{s}: capture format {t} not supported", .{ c.peer, f.format });
        return error.UnsupportedPixelFormat;
    };
    const swap = swapsAxes(f.transform) orelse {
        log.warn("{s}: capture transform {d} unknown", .{ c.peer, @backingInt(f.transform) });
        return error.UnsupportedPixelFormat;
    };
    // The client gets the upright output; 90/270 swap width and height.
    const w = if (swap) f.height else f.width;
    const h = if (swap) f.width else f.height;
    if (w != c.enc.width or h != c.enc.height) try resizeSurface(c, w, h);
    if (c.reactivating) return; // no output until the client has finalized
    if (lay.b == 0 and f.transform == .normal and !f.y_invert) return sendFrame(c, f.data, f.stride);
    try sendFrame(c, try upright(c, f, lay), @as(usize, w) * 4);
}

const Layout = struct { b: u2, g: u2, r: u2, x: u2 };

fn pixelLayout(fmt: wl.proto.WlShm.Format) ?Layout {
    return switch (fmt) {
        .xrgb8888, .argb8888 => .{ .b = 0, .g = 1, .r = 2, .x = 3 },
        .xbgr8888, .abgr8888 => .{ .b = 2, .g = 1, .r = 0, .x = 3 },
        else => null,
    };
}

fn swapsAxes(t: wl.proto.WlOutput.Transform) ?bool {
    return switch (t) {
        .normal, .@"180", .flipped, .flipped_180 => false,
        .@"90", .@"270", .flipped_90, .flipped_270 => true,
        _ => null,
    };
}

/// `f` as upright BGRX in `c.ch.upright`: undoes the buffer transform and y_invert.
fn upright(c: *Conn, f: *const wl.Frame, lay: Layout) std.mem.Allocator.Error![]const u8 {
    const swap = swapsAxes(f.transform).?;
    const w: usize = if (swap) f.height else f.width;
    const h: usize = if (swap) f.width else f.height;
    if (c.ch.upright.len != w * h * 4) {
        c.gpa.free(c.ch.upright);
        c.ch.upright = &.{};
        c.ch.upright = try c.gpa.alloc(u8, w * h * 4);
    }
    // Buffer column and row of upright pixel (x, y): bx = x*ax + y*ay + a0,
    // by = x*bx_ + y*by_ + b0.
    const W: i64 = @intCast(w);
    const H: i64 = @intCast(h);
    const m: [6]i64 = switch (f.transform) {
        .normal => .{ 1, 0, 0, 0, 1, 0 },
        .@"90" => .{ 0, 1, 0, -1, 0, W - 1 },
        .@"180" => .{ -1, 0, W - 1, 0, -1, H - 1 },
        .@"270" => .{ 0, -1, H - 1, 1, 0, 0 },
        .flipped => .{ -1, 0, W - 1, 0, 1, 0 },
        .flipped_90 => .{ 0, 1, 0, 1, 0, 0 },
        .flipped_180 => .{ 1, 0, 0, 0, -1, H - 1 },
        .flipped_270 => .{ 0, -1, H - 1, -1, 0, W - 1 },
        _ => unreachable,
    };
    var row_x = m[3];
    var row_y = m[4];
    var row_0 = m[5];
    if (f.y_invert) {
        row_x = -row_x;
        row_y = -row_y;
        row_0 = @as(i64, f.height) - 1 - row_0;
    }
    const stride: i64 = f.stride;
    const dx = m[0] * 4 + row_x * stride;
    const dy = m[1] * 4 + row_y * stride;
    const o0 = m[2] * 4 + row_0 * stride;
    const out = c.ch.upright;
    for (0..h) |y| {
        const dst = out[y * w * 4 ..][0 .. w * 4];
        var o = o0 + dy * @as(i64, @intCast(y));
        if (dx == 4 and lay.b == 0) {
            @memcpy(dst, f.data[@intCast(o)..][0 .. w * 4]);
            continue;
        }
        for (0..w) |x| {
            const p = f.data[@intCast(o)..][0..4];
            dst[x * 4 ..][0..4].* = .{ p[lay.b], p[lay.g], p[lay.r], p[lay.x] };
            o += dx;
        }
    }
    return out;
}

fn resizeSurface(c: *Conn, w: u32, h: u32) conn_mod.Error!void {
    if (c.ch.gfx_ready) {
        if (w != c.width or h != c.height) {
            c.width = @intCast(w);
            c.height = @intCast(h);
            // A Display Control layout of this size stays; otherwise one monitor.
            if (!monitorsCover(c, w, h)) setSingleMonitor(c);
        }
    } else if (w != c.width or h != c.height) {
        if (c.ch.reactivate_on_resize) {
            c.ch.reactivate_on_resize = false;
            c.width = @intCast(w);
            c.height = @intCast(h);
            if (!monitorsCover(c, w, h)) setSingleMonitor(c);
            try c.enc.reset(w, h);
            return c.reactivate();
        }
        // Without RDPGFX the client keeps the Demand Active size (MS-RDPBCGR 2.2.7.1.2) until reactivation.
        log.warn("{s}: desktop is {d}x{d} but the client has {d}x{d}", .{ c.peer, w, h, c.width, c.height });
    }
    try c.enc.reset(w, h);
    if (c.ch.gfx_ready and (c.ch.surface_w != w or c.ch.surface_h != h)) try resetGraphics(c);
}

fn sendFrame(c: *Conn, pixels: []const u8, stride: usize) conn_mod.Error!void {
    // No updates while output is suppressed (MS-RDPBCGR 3.3.5.11.2).
    if (c.output_suppressed) return c.flush();
    if (!c.ch.gfx_ready) {
        // While reactivating, only the shadow is updated.
        const changed = try c.enc.diff(pixels, stride);
        if (c.reactivating or (changed == 0 and !c.enc.hasOwed())) return;
        try c.enc.mergeOwed();
        c.pacing.frameStarted(conn_mod.nowMs());
        try legacy.sendFrame(c);
        return;
    }
    const sid = c.ch.surface_id orelse return;
    const t0 = nowNs();
    if (try c.enc.diff(pixels, stride) == 0 and !c.enc.hasOwed()) return;
    c.enc.touch(conn_mod.nowMs());
    // Changed tiles count toward video regions (video.zig); owed tiles do not.
    try gfx_codecs.trackVideo(c);
    const region = gfx_codecs.videoRegion(c);
    const changed_outside = changesOutside(c, region);
    const owed = c.enc.hasOwed();
    try c.enc.mergeOwed();
    c.pacing.frameStarted(conn_mod.nowMs());
    const t1 = nowNs();
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(c.gpa);
    var w = bytes.Writer.init(&list, c.gpa);
    const fid = c.ch.frame_id +% 1;
    try gfx.writeStartFrame(&w, fid, gfx.frameTimestamp(msOfDay()));
    const screen: f64 = @floatFromInt(@as(u64, c.enc.width) * c.enc.height);
    if (@as(f64, @floatFromInt(areaOutside(c, region))) >= screen * avc_min_change and gfx_codecs.motionCodec(c) != null) c.ch.motion_frames = avc_hold_frames;
    const motion = c.ch.motion_frames > 0;
    if (motion) c.ch.motion_frames -= 1;
    // Lossy tiles elsewhere wait for this to be quiet while a region plays.
    if (changed_outside or region == null or owed) c.ch.surf.outside_ms = conn_mod.nowMs();
    const sent = try gfx_codecs.writeFrame(c, &w, sid, motion, region);
    // Quiet lossy tiles fill what the frame's budget leaves.
    try gfx_codecs.writeRefineWithin(c, &w, sid, list.items.len, gfx_codecs.quietMs(c));
    try gfx.writeEndFrame(&w, fid);
    switch (sent) {
        .lossless => {},
        .avc420 => c.ch.stats.avc_frames += 1,
        .avc444 => c.ch.stats.avc444_frames += 1,
        .progressive => c.ch.stats.prog_frames += 1,
        .remotefx => c.ch.stats.rfx_frames += 1,
    }
    c.ch.last_frame_ms = conn_mod.nowMs();
    c.ch.frame_id = fid;
    const t2 = nowNs();
    if (sent == .avc420 or sent == .avc444) c.pacing.encoded(@as(f64, @floatFromInt(t2 - t1)) / 1e6);
    const wire = try sendGfx(c, list.items);
    const t3 = nowNs();
    c.ch.frames_unacked +|= 1;
    try c.flush();
    const t4 = nowNs();
    c.ch.sent_ns[fid % c.ch.sent_ns.len] = t4;
    noteFrame(c, wire);

    const st = &c.ch.stats;
    st.frames += 1;
    st.rects += @intCast(c.enc.rects.items.len);
    for (c.enc.rects.items) |r| st.pixels += @as(u64, r.right - r.left) * (r.bottom - r.top);
    st.raw_bytes += list.items.len;
    st.wire_bytes += wire;
    st.diff_ns += t1 - t0;
    st.encode_ns += t2 - t1;
    st.zgfx_ns += t3 - t2;
    st.send_ns += t4 - t3;
    logStats(c);
}

fn changesOutside(c: *const Conn, region: ?gfx.Rect16) bool {
    const v = region orelse return c.enc.rects.items.len > 0;
    for (0..c.enc.rects.items.len) |i| {
        const t = c.enc.tightRect(i);
        if (t.left < v.left or t.top < v.top or t.right > v.right or t.bottom > v.bottom) return true;
    }
    return false;
}

fn areaOutside(c: *const Conn, region: ?gfx.Rect16) u64 {
    const v = region orelse return c.enc.changedPixels();
    var n: u64 = 0;
    for (c.enc.rects.items) |r| {
        n += @as(u64, r.right - r.left) * (r.bottom - r.top);
        if (gfx_codecs.intersect(r, v)) |i| n -= @as(u64, i.right - i.left) * (i.bottom - i.top);
    }
    return n;
}

fn noteFrame(c: *Conn, wire: usize) void {
    const p = &c.pacing.stats;
    p.frames += 1;
    p.frame_bytes += wire;
    p.max_frame = @max(p.max_frame, wire);
    c.pacing.frames_total += 1;
    c.pacing.max_frame_total = @max(c.pacing.max_frame_total, wire);
}

pub fn avcAllowed(c: *const Conn) bool {
    if (c.ch.avc_off) return false;
    return codec_policy.avc420Allowed(c.ch.gfx_caps);
}

/// Updates link adaptation, then sends one frame of owed tiles or, once quiet, refinement.
pub fn refine(c: *Conn) conn_mod.Error!void {
    if (!c.surfaces.inside) adaptTick(c);
    if (surfaces.isMulti(c)) return surfaces.refine(c);
    if (!c.ch.gfx_ready) return legacy.refine(c);
    if (try refineStep(c) and refinePending(c)) lookAgain(c);
}

pub fn lookAgain(c: *Conn) void {
    const ms: i64 = c.pacing.interval_ms;
    c.pacing.retry_ms = if (c.pacing.retry_ms) |r| @min(r, ms) else ms;
}

fn refineStep(c: *Conn) conn_mod.Error!bool {
    if (!gfx_codecs.refinePending(c) or c.output_suppressed) return false;
    // A video region can end on a still screen, when no frame runs detection.
    gfx_codecs.tickVideo(c);
    if (c.enc.hasOwed()) {
        if (!canSendFrame(c)) return false;
        try sendOwed(c);
        return true;
    }
    const now = conn_mod.nowMs();
    const region = gfx_codecs.videoRegion(c);
    const still = now - c.ch.last_frame_ms >= refine_after_ms;
    // A still screen becomes exact, the video region included.
    if (still) if (region) |r| gfx_codecs.refineRegion(c, r);
    const quiet_ms = gfx_codecs.quietMs(c);
    // While content flows, refinement rides in content frames so it never delays one.
    const flowing = now - c.ch.last_frame_ms < 2 * @as(i64, c.pacing.interval_ms);
    const tiles = !still and !flowing and c.enc.anyQuietLossy(now, quiet_ms);
    if (!still and !tiles) {
        if (flowing and c.enc.hasLossy()) {
            const ms = @max(1, c.ch.last_frame_ms + 2 * @as(i64, c.pacing.interval_ms) - now);
            c.pacing.retry_ms = if (c.pacing.retry_ms) |r| @min(r, ms) else ms;
        }
        if (c.enc.nextQuietMs(quiet_ms)) |t| {
            const ms = @max(1, t - now);
            c.pacing.retry_ms = if (c.pacing.retry_ms) |r| @min(r, ms) else ms;
        }
        return false;
    }
    if (!canSendFrame(c)) return false;
    const sid = c.ch.surface_id orelse return false;
    c.pacing.frameStarted(conn_mod.nowMs());
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(c.gpa);
    var w = bytes.Writer.init(&list, c.gpa);
    const fid = c.ch.frame_id +% 1;
    try gfx.writeStartFrame(&w, fid, gfx.frameTimestamp(msOfDay()));
    if (!try gfx_codecs.writeRefine(c, &w, sid, now, quiet_ms, still)) return false;
    try gfx.writeEndFrame(&w, fid);
    c.ch.frame_id = fid;
    const wire = try sendGfx(c, list.items);
    c.ch.frames_unacked +|= 1;
    c.ch.motion_frames = 0;
    c.ch.stats.refines += 1;
    c.ch.sent_ns[fid % c.ch.sent_ns.len] = nowNs();
    noteFrame(c, wire);
    try c.flush();
    return true;
}

/// Sends owed tiles alone, lossless and cut to the byte budget; the rest stays owed.
fn sendOwed(c: *Conn) conn_mod.Error!void {
    const sid = c.ch.surface_id orelse return;
    if (try c.enc.takeOwed() == 0) return;
    c.pacing.frameStarted(conn_mod.nowMs());
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(c.gpa);
    var w = bytes.Writer.init(&list, c.gpa);
    const fid = c.ch.frame_id +% 1;
    try gfx.writeStartFrame(&w, fid, gfx.frameTimestamp(msOfDay()));
    try gfx_codecs.writeLossless(c, &w, sid, .owed);
    try gfx.writeEndFrame(&w, fid);
    c.ch.frame_id = fid;
    const wire = try sendGfx(c, list.items);
    c.ch.stats.wire_bytes += wire;
    c.ch.stats.raw_bytes += list.items.len;
    c.ch.stats.frames += 1;
    c.ch.frames_unacked +|= 1;
    c.ch.last_frame_ms = conn_mod.nowMs();
    c.ch.surf.outside_ms = c.ch.last_frame_ms;
    c.ch.sent_ns[fid % c.ch.sent_ns.len] = nowNs();
    noteFrame(c, wire);
    try c.flush();
}

/// Lossy or owed tiles are waiting for a refine step (poll sooner).
pub fn refinePending(c: *const Conn) bool {
    if (surfaces.isMulti(c)) return surfaces.refinePending(c);
    return if (c.ch.gfx_ready) gfx_codecs.refinePending(c) else c.enc.hasLossy() or c.enc.hasOwed();
}

fn logStats(c: *Conn) void {
    const st = &c.ch.stats;
    const now = conn_mod.nowMs();
    if (st.since_ms == 0) st.since_ms = now;
    const el = now - st.since_ms;
    if (el < stats_interval_ms or st.frames == 0) return;
    const f: f64 = @floatFromInt(st.frames);
    const ms = struct {
        fn per(ns: u64, n: f64) f64 {
            return @as(f64, @floatFromInt(ns)) / 1e6 / n;
        }
    }.per;
    const screen: f64 = @floatFromInt(@as(u64, c.enc.width) * c.enc.height);
    const secs = @as(f64, @floatFromInt(el)) / 1000.0;
    var region_buf: [48]u8 = undefined;
    const region: []const u8 = if (gfx_codecs.videoRegion(c)) |r|
        std.fmt.bufPrint(&region_buf, "{d}x{d} at {d},{d}", .{ r.right - r.left, r.bottom - r.top, r.left, r.top }) catch "?"
    else
        "none";
    log.info("{s}: graphics: {d:.1} fps ({d} avc420, {d} avc444, {d} progressive, {d} remotefx, {d} refines, {d} upgrades; {d} planar, {d} clear rects; video region {s}, {d} frames of it, H.264 {d:.1} Mbit/s), {d:.0}% changed/frame, {d:.1} Mbit/s (zgfx {d:.1}x), per frame: diff {d:.2} ms, encode {d:.2} ms, zgfx {d:.2} ms, send {d:.2} ms; ack {d:.1} ms, {d} waits for acks", .{
        c.peer,
        f * 1000.0 / @as(f64, @floatFromInt(el)),
        st.avc_frames,
        st.avc444_frames,
        st.prog_frames,
        st.rfx_frames,
        st.refines,
        st.upgrades,
        st.planar_rects,
        st.clear_rects,
        region,
        st.video_frames,
        @as(f64, @floatFromInt(st.h264_bytes)) * 8.0 / 1e6 / secs,
        @as(f64, @floatFromInt(st.pixels)) / f / screen * 100.0,
        @as(f64, @floatFromInt(st.wire_bytes)) * 8.0 / 1e6 / secs,
        @as(f64, @floatFromInt(st.raw_bytes)) / @max(1.0, @as(f64, @floatFromInt(st.wire_bytes))),
        ms(st.diff_ns, f),
        ms(st.encode_ns, f),
        ms(st.zgfx_ns, f),
        ms(st.send_ns, f),
        ms(st.ack_ns, @max(1.0, @as(f64, @floatFromInt(st.acks)))),
        st.blocked,
    });
    st.* = .{ .since_ms = now };
}

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// After a multitransport tunnel loss: new ZGFX history (MS-RDPEGFX 3.1.9.1), new surface, full frame.
pub fn resync(c: *Conn) conn_mod.Error!void {
    if (!c.ch.gfx_ready) return;
    log.info("{s}: graphics resynchronized after a transport loss", .{c.peer});
    if (c.ch.zgfx) |*z| z.reset();
    // ClearCodec messages may be lost too: a new encoder with CACHE_RESET (MS-RDPEGFX 2.2.4.1).
    if (c.ch.clear) |*e| {
        const seq = e.nextSeq() catch 0;
        e.deinit();
        c.ch.clear = clear_codec.Encoder.init(c.gpa, .{ .first_seq = seq }) catch null;
        if (c.ch.clear) |*n| n.resetCaches() catch {};
    }
    c.ch.frames_unacked = 0;
    try resetGraphics(c);
    c.enc.invalidate();
    if (c.desktop != null) try refresh(c) else try sendGfxFrame(c);
    try c.flush();
}

pub fn refresh(c: *Conn) conn_mod.Error!void {
    if (surfaces.isMulti(c)) return surfaces.refresh(c);
    if (c.desktop == null) {
        c.enc.invalidate();
        return c.sendFullFrame();
    }
    if (c.enc.width == 0 or c.output_suppressed) return; // first frame not captured yet
    if (!c.ch.gfx_ready) {
        c.enc.rects.clearRetainingCapacity();
        try c.enc.rects.append(c.gpa, .{ .left = 0, .top = 0, .right = @intCast(c.enc.width), .bottom = @intCast(c.enc.height) });
        return legacy.sendLossless(c);
    }
    if (c.ch.surface_id == null) return;
    c.enc.oweAll();
    c.enc.valid = true;
    try sendOwed(c);
}

pub fn sendFramebuffer(c: *Conn) conn_mod.Error!void {
    const fb = &(c.fb orelse return);
    if (fb.width != c.enc.width or fb.height != c.enc.height) try resizeSurface(c, fb.width, fb.height);
    try sendFrame(c, fb.pixels, fb.stride);
}

pub fn sendGfxFrame(c: *Conn) conn_mod.Error!void {
    const fb = &(c.fb orelse return);
    if (fb.width != c.enc.width or fb.height != c.enc.height) try resizeSurface(c, fb.width, fb.height);
    // No graphics while updates are suppressed (MS-RDPBCGR 3.3.5.11.2).
    if (c.output_suppressed) return c.flush();
    c.enc.invalidate();
    try sendFrame(c, fb.pixels, fb.stride);
}

fn msOfDay() u32 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @intCast(@mod(ts.sec, 86400) * 1000 + @divTrunc(ts.nsec, 1_000_000));
}

fn onDisp(c: *Conn, msg: []const u8) conn_mod.Error!void {
    // A malformed or unappliable layout is ignored; the session keeps its size (MS-RDPEDISP 1.3).
    const layout = (disp.parseLayout(msg) catch |err| {
        log.warn("{s}: ignoring a malformed monitor layout ({t})", .{ c.peer, err });
        return;
    }) orelse return;
    disp.validate(&layout) catch {
        const b = layout.bounds();
        log.warn("{s}: ignoring a monitor layout that cannot be applied: {d} monitor(s), {d}x{d}", .{ c.peer, layout.count, b.width, b.height });
        return;
    };
    const b = layout.bounds();
    const pm = layout.primary();
    const scale = disp.effectiveScale(pm.desktop_scale_factor, pm.device_scale_factor);
    log.info("{s}: monitor layout: {d} monitor(s), desktop {d}x{d}, scale {d}% (desktop {d}%, device {d}%)", .{
        c.peer, layout.count, b.width, b.height, scale, pm.desktop_scale_factor, pm.device_scale_factor,
    });
    // Several monitors, now or after it: an output each (surfaces.zig).
    if (c.desktop) |d| if (layout.count > 1 or d.outputCount() > 1) return surfaces.onLayout(c, d, &layout);
    const prev = c.ch.monitors;
    const prev_count = c.ch.monitor_count;
    for (layout.slice(), 0..) |m, i| c.ch.monitors[i] = .{
        .left = m.left - b.left,
        .top = m.top - b.top,
        .right = m.left - b.left + @as(i32, @intCast(m.width)) - 1,
        .bottom = m.top - b.top + @as(i32, @intCast(m.height)) - 1,
        .primary = m.primary,
    };
    c.ch.monitor_count = layout.count;
    const rearranged = c.ch.monitor_count != prev_count or for (c.ch.monitors[0..prev_count], prev[0..prev_count]) |m, p| {
        if (!std.meta.eql(m, p)) break true;
    } else false;

    if (c.desktop) |d| {
        // Resize RDP-1; the surface follows with the first frame of the new size.
        d.resize(@intCast(b.width), @intCast(b.height), scale) catch |err| {
            log.warn("{s}: resize failed: {t}", .{ c.peer, err });
            c.ch.monitors = prev;
            c.ch.monitor_count = prev_count;
            return;
        };
        return resized(c, d.width(), d.height(), rearranged);
    }

    if (c.fb) |*old| old.deinit(c.gpa);
    c.fb = null;
    var fb = try framebuffer.Framebuffer.init(c.gpa, @intCast(b.width), @intCast(b.height));
    framebuffer.drawTestPattern(&fb);
    if (c.test_detail) framebuffer.drawDetail(&fb, 0);
    c.fb = fb;
    try resized(c, b.width, b.height, rearranged);
    if (c.ch.gfx_ready) try sendGfxFrame(c);
}

/// Applies a new `w` x `h` desktop (MS-RDPEDISP 1.3): reactivation without RDPGFX, else RESET_GRAPHICS.
fn resized(c: *Conn, w: u32, h: u32, rearranged: bool) conn_mod.Error!void {
    if (!c.ch.gfx_ready) {
        if (w == c.width and h == c.height) return;
        if (!c.ch.gfx_refused) {
            // RDPGFX is coming up: its RESET_GRAPHICS carries the new size.
            if (c.desktop == null) {
                c.width = @intCast(w);
                c.height = @intCast(h);
            }
            return;
        }
        // Reactivate once the capture delivers the new size (resizeSurface).
        if (c.desktop != null) {
            c.ch.reactivate_on_resize = true;
            return;
        }
        c.width = @intCast(w);
        c.height = @intCast(h);
        return c.reactivate();
    }
    if (c.desktop == null) {
        c.width = @intCast(w);
        c.height = @intCast(h);
    }
    if (!rearranged or w != c.ch.surface_w or h != c.ch.surface_h) return;
    // The desktop may be a few pixels smaller than requested (hypr.fitDesktop).
    if (!monitorsCover(c, w, h)) setSingleMonitor(c);
    try resetGraphics(c);
    c.enc.invalidate();
    if (c.desktop != null) try refresh(c) else try c.flush();
}
