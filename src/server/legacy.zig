//! Graphics for clients without RDPGFX: lossless bitmap updates (MS-RDPBCGR 2.2.9.1.1.3.1.2) and,
//! for motion, RemoteFX or NSCodec surface commands (2.2.9.2) with frame-marker flow control.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const caps = @import("../proto/caps.zig");
const fastpath = @import("../proto/fastpath.zig");
const gfx = @import("../proto/gfx.zig");
const rfx = @import("../codec/rfx.zig");
const nsc = @import("../codec/nsc.zig");
const planar = @import("../codec/planar.zig");
const interleaved = @import("../codec/interleaved.zig");
const bulk_codec = @import("../codec/bulk.zig");
const codec_policy = @import("codec_policy.zig");
const adapt = @import("adapt.zig");
const pacing = @import("pacing.zig");
const channels = @import("channels.zig");
const gfx_codecs = @import("gfx_codecs.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.legacy);

pub const tile: u32 = 64;
/// Minimum frames to stay lossy once motion starts, to avoid codec flapping.
pub const hold_frames = 8;

// TS_FRAME_MARKER (MS-RDPBCGR 2.2.9.2.3).
pub const cmdtype_frame_marker: u16 = 0x0004;
pub const frameaction_begin: u16 = 0x0000;
pub const frameaction_end: u16 = 0x0001;
/// TS_FRAME_ACKNOWLEDGE_PDU frameID acknowledging all frames (MS-RDPRFX 2.2.3.1).
pub const ack_all: u32 = 0xFFFF_FFFF;
/// Flow control turns off after this long with a full window and no ack.
pub const ack_stall_ms: i64 = 2000;
/// TS_BITMAP_DATA.flags (MS-RDPBCGR 2.2.9.1.1.3.1.2.2).
pub const bitmap_compression: u16 = 0x0001;
pub const no_bitmap_compression_hdr: u16 = 0x0400;
/// TS_SURFCMD_*_SURF_BITS header (8) + TS_BITMAP_DATA_EX header (12).
pub const surface_bits_header_len: usize = 20;
/// Largest reassembled fast-path update sent, whatever the client allows.
pub const max_update_len: usize = 4 * 1024 * 1024;

/// TS_RFX_CHANNELT limits (MS-RDPRFX 2.2.2.1.3) the panes respect.
pub const max_pane_width: u32 = rfx.max_channel_width;
pub const max_pane_height: u32 = rfx.max_channel_height;

/// RemoteFX channel (pane) layout: one pane when the desktop fits 4096x2048,
/// else equal 64-aligned panes covering it, the last ones reaching past the edge.
pub const Panes = struct {
    width: u32 = 0,
    height: u32 = 0,
    pane_w: u32 = 0,
    pane_h: u32 = 0,
    nx: u32 = 0,
    ny: u32 = 0,

    pub fn init(width: u32, height: u32) Panes {
        if (width <= max_pane_width and height <= max_pane_height)
            return .{ .width = width, .height = height, .pane_w = width, .pane_h = height, .nx = 1, .ny = 1 };
        const nx0 = std.math.divCeil(u32, width, max_pane_width) catch unreachable;
        const ny0 = std.math.divCeil(u32, height, max_pane_height) catch unreachable;
        const pw = @min(max_pane_width, std.mem.alignForward(u32, std.math.divCeil(u32, width, nx0) catch unreachable, tile));
        const ph = @min(max_pane_height, std.mem.alignForward(u32, std.math.divCeil(u32, height, ny0) catch unreachable, tile));
        return .{
            .width = width,
            .height = height,
            .pane_w = pw,
            .pane_h = ph,
            .nx = std.math.divCeil(u32, width, pw) catch unreachable,
            .ny = std.math.divCeil(u32, height, ph) catch unreachable,
        };
    }

    pub fn count(p: Panes) u32 {
        return p.nx * p.ny;
    }

    /// Pane `i` (row-major) in desktop coordinates, clipped to the desktop.
    pub fn rect(p: Panes, i: u32) Rect {
        const x = (i % p.nx) * p.pane_w;
        const y = (i / p.nx) * p.pane_h;
        return .{ .x = x, .y = y, .w = @min(p.pane_w, p.width - x), .h = @min(p.pane_h, p.height - y) };
    }
};

pub const Rect = struct { x: u32, y: u32, w: u32, h: u32 };

/// Cumulative counters since connect; logStats logs the difference every 5 s.
pub const Stats = struct {
    frames: u64 = 0,
    lossy_frames: u64 = 0,
    bitmaps: u64 = 0,
    surface_bits: u64 = 0,
    refines: u64 = 0,
    acks: u64 = 0,
};

pub const State = struct {
    policy: ?codec_policy.Legacy = null,
    /// The client's maxUnacknowledgedFrameCount hint (0: none).
    client_window: u32 = 0,
    rfx_enc: ?rfx.Encoder = null,
    panes: Panes = .{},
    /// Frame marker ids: last sent, unacknowledged count, send times.
    frame_id: u32 = 0,
    unacked: u32 = 0,
    sent_ms: [32]i64 = @splat(0),
    /// A client that stops acknowledging opens the window (`acks_unreliable`).
    last_end_ms: i64 = 0,
    last_ack_ms: i64 = 0,
    acks_unreliable: bool = false,
    motion_frames: u32 = 0,
    last_frame_ms: i64 = 0,
    stats: Stats = .{},
    logged: Stats = .{},
    logged_ms: i64 = 0,
    scratch: std.ArrayList(u8) = .empty,
    enc_buf: std.ArrayList(u8) = .empty,
    upd: std.ArrayList(u8) = .empty,
    upd_rects: u16 = 0,
    /// Bitmap bytes of the current frame, against its byte budget.
    frame_bytes: usize = 0,

    pub fn deinit(s: *State, gpa: std.mem.Allocator) void {
        if (s.rfx_enc) |*e| e.deinit();
        s.scratch.deinit(gpa);
        s.enc_buf.deinit(gpa);
        s.upd.deinit(gpa);
    }
};

/// Demand Active capability sets; codecs are offered at 32 bpp only.
pub fn serverCaps(base: caps.ServerCapsOptions, o: codec_policy.Options) caps.ServerCapsOptions {
    var r = base;
    if (base.color_depth == 32 and (o.remotefx or o.nscodec)) {
        r.bitmap_codecs = .{ .remotefx = o.remotefx, .nscodec = if (o.nscodec) nsc.Caps{} else null };
    }
    r.frame_acknowledge = adapt.max_window;
    return r;
}

/// On Confirm Active: sets the policy, restarts RemoteFX and the ack window.
pub fn onConfirmActive(c: *Conn) void {
    const s = &c.ch.legacy;
    const p = codec_policy.forLegacy(&c.client_caps, c.bpp, c.vc.opts.graphics);
    const first = s.policy == null;
    s.policy = p;
    s.client_window = c.client_caps.frame_acknowledge orelse 0;
    if (s.rfx_enc) |*e| e.deinit();
    s.rfx_enc = null;
    s.unacked = 0;
    s.motion_frames = 0;
    if (!first) return;
    const motion: []const u8 = if (p.motion) |m| switch (m) {
        .remotefx => |r| if (r.mode == .image) "RemoteFX (image mode)" else "RemoteFX",
        .nscodec => "NSCodec",
    } else "none";
    log.info("{s}: bitmap updates: {t} at {d} bpp, lossy motion codec {s} ({t}), frame acknowledgements {s}{s}", .{
        c.peer,                                                 p.lossless,                                                                                        c.bpp, motion, p.lossy_motion,
        if (p.frame_ack and c.fastpath_output) "on" else "off", if (p.motion != null and !c.fastpath_output) "; no fast-path output: no surface commands" else "",
    });
}

fn policyOf(c: *const Conn) codec_policy.Legacy {
    return c.ch.legacy.policy orelse .{ .lossless = if (c.bpp == 32) .planar else .interleaved };
}

/// Only surface-command frames carry frame markers: Windows clients do not
/// acknowledge frames of bitmap updates.
fn markers(c: *const Conn) bool {
    return policyOf(c).frame_ack and c.fastpath_output;
}

/// Frames that may be unacknowledged: as for RDPGFX, capped by the client's hint (MS-RDPRFX 2.2.1.3).
pub fn window(c: *const Conn) u32 {
    var w = @min(pacing.max_frames_in_flight, c.pacing.framesInFlight(c.flow.rttMs()));
    const hint = c.ch.legacy.client_window;
    if (hint > 0) w = @min(w, hint);
    return @max(w, 1);
}

/// Frame admission: the acknowledgement window, then pacing (Conn.legacyBacklog).
pub fn canSendFrame(c: *Conn) bool {
    const s = &c.ch.legacy;
    c.pacing.refused = false;
    if (markers(c) and !s.acks_unreliable and s.unacked >= window(c)) {
        const now = conn_mod.nowMs();
        if (s.last_end_ms == 0 or now - @max(s.last_ack_ms, s.last_end_ms) < ack_stall_ms) return false;
        s.acks_unreliable = true;
        log.info("{s}: no Frame Acknowledge for {d} ms with {d} frames in flight: flow control off until one arrives", .{ c.peer, ack_stall_ms, s.unacked });
    }
    c.legacyBacklog();
    return c.graphicsAdmit(null);
}

/// TS_FRAME_ACKNOWLEDGE_PDU (MS-RDPRFX 2.2.3.1). Acks arrive in order; an unknown id counts as one.
pub fn onFrameAck(c: *Conn, body: []const u8) conn_mod.Error!void {
    var r = bytes.Reader.init(body);
    const id = try r.u32le();
    const s = &c.ch.legacy;
    s.stats.acks += 1;
    s.last_ack_ms = conn_mod.nowMs();
    if (s.acks_unreliable) log.debug("{s}: Frame Acknowledge {d}: flow control on again", .{ c.peer, id });
    s.acks_unreliable = false;
    if (id == ack_all) {
        s.unacked = 0;
        return;
    }
    const after = s.frame_id -% id;
    const known = after < s.unacked;
    s.unacked = if (after <= s.unacked) after else s.unacked -| 1;
    const sent = s.sent_ms[id % s.sent_ms.len];
    if (known and sent != 0) c.ch.adapt.onAck(@intCast(std.math.clamp(conn_mod.nowMs() - sent, 0, std.math.maxInt(u32))));
}

fn lossyAllowed(c: *const Conn, p: codec_policy.Legacy) bool {
    if (p.motion == null or !c.fastpath_output) return false;
    return switch (p.lossy_motion) {
        .always => true,
        .never => false,
        .auto => c.ch.adapt.slow(),
    };
}

pub fn sendFrame(c: *Conn) conn_mod.Error!void {
    const s = &c.ch.legacy;
    const p = policyOf(c);
    if (lossyAllowed(c, p)) {
        const screen: f64 = @floatFromInt(@as(u64, c.enc.width) * c.enc.height);
        if (@as(f64, @floatFromInt(c.enc.changedPixels())) >= screen * channels.avc_min_change) s.motion_frames = hold_frames;
        if (s.motion_frames > 0) {
            s.motion_frames -= 1;
            if (try sendLossy(c, p.motion.?)) return;
        }
    }
    try sendLossless(c);
}

/// Sends c.enc.rects losslessly from the shadow; on a paced link tiles past the byte budget are owed.
pub fn sendLossless(c: *Conn) conn_mod.Error!void {
    return sendLosslessLeaving(c, .owed);
}

fn sendLosslessLeaving(c: *Conn, leftover: gfx_codecs.Leftover) conn_mod.Error!void {
    const s = &c.ch.legacy;
    const p = policyOf(c);
    s.upd.clearRetainingCapacity();
    s.upd_rects = 0;
    s.frame_bytes = 0;
    c.pacing.frameStarted(conn_mod.nowMs());
    const budget = c.frameBudget();
    var rest: std.ArrayList(gfx.Rect16) = .empty;
    defer rest.deinit(c.gpa);
    const vis_w = @min(@as(u32, c.width), c.enc.width);
    const vis_h = @min(@as(u32, c.height), c.enc.height);
    for (c.enc.rects.items) |r| {
        var y: u32 = r.top;
        rows: while (y < r.bottom and y < vis_h) : (y += tile) {
            var x: u32 = r.left;
            while (x < r.right and x < vis_w) : (x += tile) {
                if (s.frame_bytes > 0 and s.frame_bytes >= budget) {
                    const y1 = @min(y + tile, r.bottom, vis_h);
                    try rest.append(c.gpa, .{ .left = @intCast(x), .top = @intCast(y), .right = @intCast(@min(r.right, vis_w)), .bottom = @intCast(y1) });
                    if (y1 < @min(r.bottom, vis_h)) try rest.append(c.gpa, .{ .left = r.left, .top = @intCast(y1), .right = @intCast(@min(r.right, vis_w)), .bottom = @intCast(@min(r.bottom, vis_h)) });
                    break :rows;
                }
                const tw: u16 = @intCast(@min(tile, r.right - x, vis_w - x));
                const th: u16 = @intCast(@min(tile, r.bottom - y, vis_h - y));
                try bitmapTile(c, p.lossless, @intCast(x), @intCast(y), tw, th);
            }
        }
    }
    try flushBitmaps(c);
    c.enc.markLossy(c.enc.rects.items, false);
    if (rest.items.len > 0) {
        switch (leftover) {
            .owed => c.enc.owe(rest.items),
            .lossy => c.enc.markLossy(rest.items, true),
        }
        c.pacing.cut();
    }
    s.stats.frames += 1;
    s.last_frame_ms = conn_mod.nowMs();
    logStats(c);
    try c.flush();
}

/// Owed tiles go as soon as admitted; once the screen is quiet, lossy tiles are re-sent losslessly.
pub fn refine(c: *Conn) conn_mod.Error!void {
    if (c.output_suppressed or c.reactivating or !c.established) return;
    if (try refineStep(c) and (c.enc.hasOwed() or c.enc.hasLossy())) channels.lookAgain(c);
}

/// One owed or refine frame; false when none went.
fn refineStep(c: *Conn) conn_mod.Error!bool {
    const s = &c.ch.legacy;
    if (c.enc.hasOwed()) {
        if (!canSendFrame(c)) return false;
        if (try c.enc.takeOwed() == 0) return false;
        try sendLosslessLeaving(c, .owed);
        return true;
    }
    if (!c.enc.hasLossy()) return false;
    if (conn_mod.nowMs() - s.last_frame_ms < channels.refine_after_ms) return false;
    if (!canSendFrame(c)) return false;
    if (try c.enc.takeLossy() == 0) return false;
    s.motion_frames = 0;
    s.stats.refines += 1;
    try sendLosslessLeaving(c, .lossy);
    return true;
}

fn beginFrame(c: *Conn) conn_mod.Error!void {
    if (!markers(c)) return;
    const s = &c.ch.legacy;
    s.frame_id +%= 1;
    try queueMarker(c, frameaction_begin, s.frame_id);
}

fn endFrame(c: *Conn) conn_mod.Error!void {
    if (!markers(c)) return;
    const s = &c.ch.legacy;
    try queueMarker(c, frameaction_end, s.frame_id);
    s.unacked +|= 1; // grows without acknowledgements once they are unreliable
    s.last_end_ms = conn_mod.nowMs();
    s.sent_ms[s.frame_id % s.sent_ms.len] = s.last_end_ms;
}

fn queueMarker(c: *Conn, action: u16, id: u32) conn_mod.Error!void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], cmdtype_frame_marker, .little);
    std.mem.writeInt(u16, buf[2..4], action, .little);
    std.mem.writeInt(u32, buf[4..8], id, .little);
    try c.queueUpdate(.surfcmds, &buf);
}

const bitmap_data_header_len: usize = 18;

fn noHdr(c: *const Conn) bool {
    return c.client_caps.general_extra_flags & caps.extra_no_bitmap_compression_hdr != 0;
}

fn bitmapTile(c: *Conn, kind: codec_policy.Lossless, x: u16, y: u16, w: u16, h: u16) conn_mod.Error!void {
    const s = &c.ch.legacy;
    const gpa = c.gpa;
    const stride = c.enc.shadowStride();
    const px = c.enc.shadowAt(x, y);
    s.enc_buf.clearRetainingCapacity();
    var bw = bytes.Writer.init(&s.enc_buf, gpa);
    const bpp = c.bpp;
    const bypp: usize = switch (bpp) {
        15, 16 => 2,
        24 => 3,
        else => 4,
    };
    const raw_row = std.mem.alignForward(usize, @as(usize, w) * bypp, 4);
    const raw_len = bitmap_data_header_len + raw_row * h;
    const no_hdr = noHdr(c);
    switch (kind) {
        .planar => {
            // Bottom-up, width padded to a multiple of 4 (cbScanWidth) by repeating the last column.
            const pw: u16 = @intCast(std.mem.alignForward(u32, w, 4));
            try s.scratch.resize(gpa, @as(usize, pw) * h * 4);
            for (0..h) |row| {
                const src = px[(h - 1 - row) * stride ..][0 .. @as(usize, w) * 4];
                const dst = s.scratch.items[row * @as(usize, pw) * 4 ..][0 .. @as(usize, pw) * 4];
                @memcpy(dst[0..src.len], src);
                var i: usize = w;
                while (i < pw) : (i += 1) dst[i * 4 ..][0..4].* = src[src.len - 4 ..][0..4].*;
            }
            try bw.u16le(x);
            try bw.u16le(y);
            try bw.u16le(x + w - 1);
            try bw.u16le(y + h - 1);
            try bw.u16le(pw);
            try bw.u16le(h);
            try bw.u16le(32);
            try bw.u16le(bitmap_compression | if (no_hdr) no_bitmap_compression_hdr else 0);
            const len_at = s.enc_buf.items.len;
            try bw.u16le(0);
            if (!no_hdr) try bw.zeros(8); // TS_CD_HEADER, patched
            const data_at = s.enc_buf.items.len;
            planar.encodePlanar(gpa, &s.enc_buf, s.scratch.items, @as(usize, pw) * 4, pw, h) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.InvalidDimensions => unreachable, // tiles are never empty
            };
            const n = s.enc_buf.items.len - data_at;
            bw.patchU16le(len_at, @intCast(n + if (no_hdr) @as(usize, 0) else 8));
            if (!no_hdr) {
                bw.patchU16le(data_at - 8 + 2, @intCast(n)); // cbCompMainBodySize
                bw.patchU16le(data_at - 8 + 4, pw); // cbScanWidth: pixels, a multiple of 4
                bw.patchU16le(data_at - 8 + 6, @intCast(@as(usize, pw) * h * 4)); // cbUncompressedSize
            }
        },
        .interleaved => {
            const ib: interleaved.Bpp = switch (bpp) {
                15 => .bpp15,
                16 => .bpp16,
                else => .bpp24,
            };
            interleaved.writeBitmapData(gpa, &bw, x, y, px, stride, w, h, ib, null, no_hdr) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => s.enc_buf.clearRetainingCapacity(), // goes uncompressed
            };
        },
    }
    // Planar never expands; interleaved can.
    if (kind == .interleaved and (s.enc_buf.items.len == 0 or s.enc_buf.items.len >= raw_len)) {
        // Compression does not pay off: the raw bitmap (2.2.9.1.1.3.1.2.2).
        s.enc_buf.clearRetainingCapacity();
        bw = bytes.Writer.init(&s.enc_buf, gpa);
        try fastpath.writeBitmapRectBpp(&bw, x, y, w, h, px, stride, bpp);
    }
    if (s.upd.items.len + s.enc_buf.items.len > bitmapBudget(c) or s.upd_rects == 0xFFFF) try flushBitmaps(c);
    if (s.upd.items.len == 0) {
        var uw = bytes.Writer.init(&s.upd, gpa);
        try uw.u16le(1); // UPDATETYPE_BITMAP
        try uw.u16le(0); // numberRectangles, patched
    }
    try s.upd.appendSlice(gpa, s.enc_buf.items);
    s.upd_rects += 1;
    s.frame_bytes += s.enc_buf.items.len;
    s.stats.bitmaps += 1;
}

/// Max bytes of one bitmap update; slow-path is capped by the bulk compressor's input (MS-RDPBCGR 3.1.8.1).
fn bitmapBudget(c: *Conn) usize {
    if (c.fastpath_output) return fastpath.max_update_payload;
    const slow = conn_mod.max_slow_update;
    const cmp = c.updateCompressor(.bitmap) orelse return slow;
    return @min(slow, bulk_codec.maxInput(cmp.type) catch slow);
}

fn flushBitmaps(c: *Conn) conn_mod.Error!void {
    const s = &c.ch.legacy;
    if (s.upd_rects == 0) return;
    std.mem.writeInt(u16, s.upd.items[2..4], s.upd_rects, .little);
    try c.queueUpdate(.bitmap, s.upd.items);
    s.upd.clearRetainingCapacity();
    s.upd_rects = 0;
    if (c.out.items.len > 256 * 1024) try c.flush();
}

/// The client's MultifragmentUpdate size (MS-RDPBCGR 2.2.7.2.6) when above one fast-path PDU's payload.
pub fn maxUpdate(c: *const Conn) usize {
    const mf = c.client_caps.multifragment_max_request_size;
    return if (mf > fastpath.max_update_payload) @min(mf, max_update_len) else fastpath.max_update_payload;
}

/// Encodes everything before queueing, as queued output cannot be taken back; false if not codable.
fn sendLossy(c: *Conn, m: codec_policy.LegacyMotion) conn_mod.Error!bool {
    const s = &c.ch.legacy;
    const gpa = c.gpa;
    switch (m) {
        .remotefx => |r| {
            var cmds = (try encodeRemoteFx(c, r.id, r.mode, r.entropy)) orelse return false;
            defer {
                for (cmds.items) |cmd| gpa.free(cmd);
                cmds.deinit(gpa);
            }
            try beginFrame(c);
            for (cmds.items) |cmd| {
                try c.queueUpdate(.surfcmds, cmd);
                s.stats.surface_bits += 1;
                if (c.out.items.len > 256 * 1024) try c.flush();
            }
        },
        .nscodec => |n| {
            try beginFrame(c);
            try sendNsc(c, n.id, n.caps);
        },
    }
    try endFrame(c);
    c.enc.markLossy(c.enc.rects.items, true);
    s.stats.frames += 1;
    s.stats.lossy_frames += 1;
    s.last_frame_ms = conn_mod.nowMs();
    logStats(c);
    try c.flush();
    return true;
}

fn logStats(c: *Conn) void {
    const s = &c.ch.legacy;
    const now = conn_mod.nowMs();
    if (s.logged_ms == 0) s.logged_ms = now;
    if (now - s.logged_ms < 5000) return;
    const d: Stats = .{
        .frames = s.stats.frames - s.logged.frames,
        .lossy_frames = s.stats.lossy_frames - s.logged.lossy_frames,
        .bitmaps = s.stats.bitmaps - s.logged.bitmaps,
        .surface_bits = s.stats.surface_bits - s.logged.surface_bits,
        .refines = s.stats.refines - s.logged.refines,
        .acks = s.stats.acks - s.logged.acks,
    };
    const secs = @as(f64, @floatFromInt(now - s.logged_ms)) / 1000.0;
    log.info("{s}: bitmap graphics: {d:.1} fps ({d} lossy, {d} refines), {d} bitmap updates, {d} surface bits, {d} frame acknowledgements (latency {?d} ms, window {d}){s}", .{
        c.peer,                                              @as(f64, @floatFromInt(d.frames)) / secs, d.lossy_frames, d.refines, d.bitmaps, d.surface_bits, d.acks, c.ch.adapt.ack_avg, window(c),
        if (s.acks_unreliable) ", flow control off" else "",
    });
    s.logged = s.stats;
    s.logged_ms = now;
}

/// RemoteFX surface bits commands, one per message; null when a tile does not fit an update.
fn encodeRemoteFx(c: *Conn, id: u8, mode: rfx.Mode, entropy: rfx.Entropy) conn_mod.Error!?std.ArrayList([]u8) {
    const s = &c.ch.legacy;
    const gpa = c.gpa;
    const vis_w = @min(@as(u32, c.width), c.enc.width);
    const vis_h = @min(@as(u32, c.height), c.enc.height);
    if (vis_w == 0 or vis_h == 0) return null;
    if (s.rfx_enc) |*e| {
        if (s.panes.width != vis_w or s.panes.height != vis_h or e.opts.mode != mode or e.opts.entropy != entropy) {
            e.deinit();
            s.rfx_enc = null;
        }
    }
    if (s.rfx_enc == null) {
        s.panes = Panes.init(vis_w, vis_h);
        s.rfx_enc = rfx.Encoder.init(gpa, .{ .width = @intCast(s.panes.pane_w), .height = @intCast(s.panes.pane_h), .mode = mode, .entropy = entropy }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
    }
    const e = &s.rfx_enc.?;
    const max_msg = maxUpdate(c) - surface_bits_header_len;
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |cmd| gpa.free(cmd);
        out.deinit(gpa);
    }
    var rects: std.ArrayList(rfx.Rect) = .empty;
    defer rects.deinit(gpa);
    const stride = c.enc.shadowStride();
    var pi: u32 = 0;
    while (pi < s.panes.count()) : (pi += 1) {
        const pane = s.panes.rect(pi);
        rects.clearRetainingCapacity();
        for (c.enc.rects.items) |r| {
            const x0 = @max(@as(u32, r.left), pane.x);
            const y0 = @max(@as(u32, r.top), pane.y);
            const x1 = @min(@as(u32, r.right), pane.x + pane.w);
            const y1 = @min(@as(u32, r.bottom), pane.y + pane.h);
            if (x0 >= x1 or y0 >= y1) continue;
            try rects.append(gpa, .{ .x = @intCast(x0 - pane.x), .y = @intCast(y0 - pane.y), .width = @intCast(x1 - x0), .height = @intCast(y1 - y0) });
        }
        if (rects.items.len == 0) continue;
        // A copy padded with repeated edges where the pane reaches past the shadow.
        var pixels: []const u8 = undefined;
        var pstride: usize = stride;
        if (pane.x + s.panes.pane_w <= c.enc.width and pane.y + s.panes.pane_h <= c.enc.height) {
            pixels = c.enc.shadowAt(pane.x, pane.y);
        } else {
            pstride = @as(usize, s.panes.pane_w) * 4;
            try s.scratch.resize(gpa, pstride * s.panes.pane_h);
            for (0..s.panes.pane_h) |row| {
                const sy = pane.y + @min(@as(u32, @intCast(row)), pane.h - 1);
                const src = c.enc.shadowAt(pane.x, sy)[0 .. @as(usize, pane.w) * 4];
                const dst = s.scratch.items[row * pstride ..][0..pstride];
                @memcpy(dst[0..src.len], src);
                var i: usize = pane.w;
                while (i < s.panes.pane_w) : (i += 1) dst[i * 4 ..][0..4].* = src[src.len - 4 ..][0..4].*;
            }
            pixels = s.scratch.items;
        }
        const msgs = e.encodeFrameSplit(pixels, pstride, rects.items, max_msg) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                log.debug("{s}: RemoteFX frame not encodable ({t}); lossless instead", .{ c.peer, err });
                // Its headers (video mode) may count as sent: a new stream.
                e.deinit();
                s.rfx_enc = null;
                for (out.items) |cmd| gpa.free(cmd);
                out.deinit(gpa);
                return null;
            },
        };
        defer {
            for (msgs) |msg| gpa.free(msg);
            gpa.free(msgs);
        }
        try out.ensureUnusedCapacity(gpa, msgs.len);
        for (msgs) |msg| {
            var cmd: std.ArrayList(u8) = .empty;
            errdefer cmd.deinit(gpa);
            try cmd.ensureTotalCapacity(gpa, surface_bits_header_len + msg.len);
            var w = bytes.Writer.init(&cmd, gpa);
            rfx.writeSurfaceBits(&w, rfx.cmdtype_stream_surface_bits, @intCast(pane.x), @intCast(pane.y), @intCast(pane.w), @intCast(pane.h), id, msg) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => unreachable, // panes are inside the desktop (u16)
            };
            out.appendAssumeCapacity(try cmd.toOwnedSlice(gpa));
        }
    }
    return out;
}

/// NSCodec colour loss 3 and subsampling on a slow link, if the client allows them (MS-RDPNSC 2.2.2).
pub fn nscParams(client: nsc.Caps, slow: bool) nsc.Params {
    const want: nsc.Params = if (slow) .{ .color_loss_level = 3, .subsampling = true } else .{};
    return nsc.chooseParams(client, want) catch .{};
}

/// Widest NSCodec bitmap (a multiple of 64) whose worst case (raw planes, 64 rows) fits in `max`.
pub fn nscChunkWidth(max: usize) u32 {
    const per_col: usize = 3 * tile;
    const w = (max -| (surface_bits_header_len + nsc.header_len)) / per_col;
    return @intCast(@max(tile, @min(4096, w / tile * tile)));
}

fn sendNsc(c: *Conn, id: u8, client: nsc.Caps) conn_mod.Error!void {
    const s = &c.ch.legacy;
    const gpa = c.gpa;
    const params = nscParams(client, c.ch.adapt.slow());
    const vis_w = @min(@as(u32, c.width), c.enc.width);
    const vis_h = @min(@as(u32, c.height), c.enc.height);
    const max = maxUpdate(c);
    const cw = nscChunkWidth(max);
    var upd: std.ArrayList(u8) = .empty;
    defer upd.deinit(gpa);
    var uw = bytes.Writer.init(&upd, gpa);
    for (c.enc.rects.items) |r| {
        var y: u32 = r.top;
        while (y < r.bottom and y < vis_h) : (y += tile) {
            var x: u32 = r.left;
            while (x < r.right and x < vis_w) : (x += cw) {
                const w: u16 = @intCast(@min(cw, r.right - x, vis_w - x));
                const h: u16 = @intCast(@min(tile, r.bottom - y, vis_h - y));
                // NSCodec surface bits are bottom-up.
                const row_len = @as(usize, w) * 4;
                try s.scratch.resize(gpa, row_len * h);
                for (0..h) |row| @memcpy(s.scratch.items[row * row_len ..][0..row_len], c.enc.shadowAt(x, y + h - 1 - @as(u32, @intCast(row)))[0..row_len]);
                const data = nsc.encode(gpa, s.scratch.items, row_len, w, h, params) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    // Not expected for a valid tile; it stays lossy and refine repaints it.
                    else => {
                        log.debug("{s}: NSCodec tile not encodable ({t})", .{ c.peer, err });
                        continue;
                    },
                };
                defer gpa.free(data);
                if (upd.items.len > 0 and upd.items.len + surface_bits_header_len + data.len > max) {
                    try c.queueUpdate(.surfcmds, upd.items);
                    upd.clearRetainingCapacity();
                    if (c.out.items.len > 256 * 1024) try c.flush();
                }
                rfx.writeSurfaceBits(&uw, rfx.cmdtype_set_surface_bits, @intCast(x), @intCast(y), w, h, id, data) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => unreachable, // tiles are inside the desktop (u16)
                };
                s.stats.surface_bits += 1;
            }
        }
    }
    if (upd.items.len > 0) try c.queueUpdate(.surfcmds, upd.items);
}

const testing = std.testing;

test "RemoteFX panes cover the desktop within 4096x2048" {
    var p = Panes.init(1920, 1080);
    try testing.expectEqual(@as(u32, 1), p.count());
    try testing.expectEqual(Rect{ .x = 0, .y = 0, .w = 1920, .h = 1080 }, p.rect(0));
    p = Panes.init(4096, 2048);
    try testing.expectEqual(@as(u32, 1), p.count());
    p = Panes.init(3840, 2160);
    try testing.expectEqual(@as(u32, 2), p.count());
    try testing.expectEqual(@as(u32, 3840), p.pane_w);
    try testing.expectEqual(@as(u32, 1088), p.pane_h);
    try testing.expectEqual(Rect{ .x = 0, .y = 1088, .w = 3840, .h = 1072 }, p.rect(1));
    p = Panes.init(5120, 2880);
    try testing.expectEqual(@as(u32, 4), p.count());
    try testing.expectEqual(@as(u32, 2560), p.pane_w);
    try testing.expectEqual(@as(u32, 1472), p.pane_h);
    try testing.expectEqual(Rect{ .x = 2560, .y = 1472, .w = 2560, .h = 1408 }, p.rect(3));
    for ([_][2]u32{ .{ 8192, 8192 }, .{ 4097, 2049 }, .{ 7680, 4320 }, .{ 32766, 300 } }) |sz| {
        p = Panes.init(sz[0], sz[1]);
        try testing.expect(p.pane_w <= 4096 and p.pane_h <= 2048);
        var area: u64 = 0;
        for (0..p.count()) |i| {
            const r = p.rect(@intCast(i));
            try testing.expect(r.w > 0 and r.h > 0 and r.x + r.w <= sz[0] and r.y + r.h <= sz[1]);
            area += @as(u64, r.w) * r.h;
        }
        try testing.expectEqual(@as(u64, sz[0]) * sz[1], area);
    }
}

test "NSCodec chunks fit one update; parameters follow link and client caps" {
    try testing.expectEqual(@as(u32, 64), nscChunkWidth(fastpath.max_update_payload));
    try testing.expect(nscChunkWidth(fastpath.max_update_payload) * 3 * tile + surface_bits_header_len + nsc.header_len <= fastpath.max_update_payload);
    try testing.expectEqual(@as(u32, 4096), nscChunkWidth(0x3F0000));
    const all: nsc.Caps = .{};
    try testing.expectEqual(nsc.Params{}, nscParams(all, false));
    try testing.expectEqual(nsc.Params{ .color_loss_level = 3, .subsampling = true }, nscParams(all, true));
    try testing.expectEqual(nsc.Params{}, nscParams(.{ .allow_dynamic_fidelity = false, .allow_subsampling = false, .color_loss_level = 7 }, true));
}

test "Demand Active sets: codecs at 32 bpp only, frame acknowledge always" {
    const base: caps.ServerCapsOptions = .{ .desktop_width = 640, .desktop_height = 480 };
    var o = serverCaps(base, .{});
    try testing.expect(o.bitmap_codecs.?.remotefx and o.bitmap_codecs.?.nscodec != null);
    try testing.expectEqual(@as(?u32, adapt.max_window), o.frame_acknowledge);
    o = serverCaps(.{ .desktop_width = 640, .desktop_height = 480, .color_depth = 16 }, .{});
    try testing.expect(o.bitmap_codecs == null);
    o = serverCaps(base, .{ .remotefx = false, .nscodec = false });
    try testing.expect(o.bitmap_codecs == null);
    o = serverCaps(base, .{ .remotefx = false });
    try testing.expect(!o.bitmap_codecs.?.remotefx and o.bitmap_codecs.?.nscodec != null);
}

test "Frame Acknowledge counter does not wrap at 2^32" {
    var fds: [2]c_int = undefined;
    try testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM, 0, &fds));
    defer _ = std.c.close(fds[1]);
    var tls_ctx: @import("../net/tls.zig").Context = undefined;
    var auth_cfg: conn_mod.AuthConfig = undefined;
    var c = Conn.init(testing.allocator, @import("../net/transport.zig").Transport.init(fds[0]), &tls_ctx, &auth_cfg, null, "test");
    defer c.deinit();
    const s = &c.ch.legacy;
    s.stats.acks = std.math.maxInt(u32);
    try onFrameAck(&c, &.{ 0xff, 0xff, 0xff, 0xff }); // 0xFFFFFFFF: all of them
    try testing.expectEqual(@as(u64, 1 << 32), s.stats.acks);
}

test {
    _ = gfx;
}
