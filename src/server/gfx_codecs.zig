//! The RDPGFX codecs of a connection's graphics, per the codec policy and the link: H.264 for video
//! regions and motion (MS-RDPEGFX 2.2.4.4 - 2.2.4.6), progressive or RemoteFX for motion on slow links,
//! ClearCodec or planar losslessly. Lossy tiles are refined once quiet, so a still screen is exact.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const gfx = @import("../proto/gfx.zig");
const policy = @import("codec_policy.zig");
const pacing = @import("pacing.zig");
const avc420 = @import("../codec/avc420.zig");
const avc444 = @import("../codec/avc444.zig");
const vaapi_h264 = @import("../codec/vaapi_h264.zig");
const progressive = @import("../codec/progressive.zig");
const rfx = @import("../codec/rfx.zig");
const clear = @import("../codec/clear.zig");
const encoder_mod = @import("encoder.zig");
const video_mod = @import("video.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.chan);

/// ClearCodec takes a change of at most one tile with at most `clear_max_colours` colours.
pub const clear_max_area: u32 = 64 * 64;
pub const clear_max_colours: usize = 32;

/// Progressive quality levels (2.2.4.2.1.5.2), then 100%: BitPos on the default quantization,
/// quant + BitPos <= 16 for FreeRDP's decoder; below `thin_kbps` a coarser first level.
const level_a: progressive.ComponentQuant = .{ .ll3 = 4, .hl3 = 5, .lh3 = 5, .hh3 = 6, .hl2 = 6, .lh2 = 6, .hh2 = 7, .hl1 = 7, .lh1 = 7, .hh1 = 7 };
const level_b: progressive.ComponentQuant = .{ .ll3 = 2, .hl3 = 2, .lh3 = 2, .hh3 = 3, .hl2 = 3, .lh2 = 3, .hh2 = 4, .hl1 = 4, .lh1 = 4, .hh1 = 4 };
const level_c: progressive.ComponentQuant = .{ .ll3 = 0, .hl3 = 1, .lh3 = 1, .hh3 = 1, .hl2 = 1, .lh2 = 1, .hh2 = 2, .hl1 = 2, .lh1 = 2, .hh1 = 2 };
pub const prog_levels = [_]progressive.ProgQuant{
    .{ .quality = 50, .y = level_b, .cb = level_b, .cr = level_b },
    .{ .quality = 75, .y = level_c, .cb = level_c, .cr = level_c },
};
pub const prog_levels_thin = [_]progressive.ProgQuant{
    .{ .quality = 25, .y = level_a, .cb = level_a, .cr = level_a },
    .{ .quality = 50, .y = level_b, .cb = level_b, .cr = level_b },
    .{ .quality = 75, .y = level_c, .cb = level_c, .cr = level_c },
};
pub const thin_kbps: u64 = 2000;

/// Codec state of one RDPGFX surface; decoders keep theirs per surface.
pub const Surface = struct {
    /// AVC420, or AVC444 when opts.avc444 is set.
    h264: ?vaapi_h264.Encoder = null,
    h264_out: std.ArrayList(u8) = .empty,
    aux_out: std.ArrayList(u8) = .empty,
    need_idr: bool = true,
    /// AVC444 chroma owed after luma-only frames (LC 1, 2.2.4.5).
    chroma: ?avc444.ChromaDebt = null,
    prog: ?progressive.Encoder = null,
    /// codecContextId of `prog` (2.2.2.2), and whether the client has it.
    prog_ctx: u32 = 0,
    prog_live: bool = false,
    /// RemoteFX encoders by pane size class: full, right edge, bottom edge, corner.
    rfx: [4]?rfx.Encoder = @splat(null),
    bitmap: std.ArrayList(u8) = .empty,
    scratch_rects: std.ArrayList(progressive.Rect) = .empty,
    video: video_mod.Detector = .{},
    /// Sent with H.264 since its tiles were last marked lossy (the region is lossy as a whole), and its last QP.
    region_h264: bool = false,
    region_qp: u8 = pacing.avc_max_qp,
    /// Per 64x64 tile, the QP of the H.264 reference there (`no_ref`: not coded yet). A frame at QP q
    /// also codes every block whose reference is worse, refining the client's picture for free.
    ref_qp: []u8 = &.{},
    /// The tiles a frame's H.264 codes as new content (scratch).
    dirty: std.DynamicBitSetUnmanaged = .{},
    /// Quiet time before a lossy tile is refined, chosen by the link rate when H.264 starts, as Windows does.
    quiet_ms: i64 = pacing.refine_quiet_ms,
    /// Scratch: the tiles an H.264 picture refines, and all its region rects.
    refine_rects: std.ArrayList(gfx.Rect16) = .empty,
    avc_region: std.ArrayList(gfx.Rect16) = .empty,
    /// Last change outside the video region; lossy tiles elsewhere are refined once this is quiet.
    outside_ms: i64 = 0,
    /// The shadow, copied in only where a frame is coded with H.264 (whole when `h264_src_ok` is false).
    h264_src: []u8 = &.{},
    h264_src_ok: bool = false,
    /// Scratch for a frame's rects: lossless pieces, H.264 region rects.
    pieces: std.ArrayList(Piece) = .empty,
    avc_rects: std.ArrayList(gfx.Rect16) = .empty,
    piece_rects: std.ArrayList(gfx.Rect16) = .empty,

    pub fn deinit(s: *Surface, gpa: std.mem.Allocator) void {
        if (s.h264) |*h| h.deinit();
        if (s.prog) |*p| p.deinit();
        for (&s.rfx) |*r| if (r.*) |*e| e.deinit();
        s.h264_out.deinit(gpa);
        s.aux_out.deinit(gpa);
        if (s.chroma) |*d| d.deinit();
        s.bitmap.deinit(gpa);
        s.scratch_rects.deinit(gpa);
        s.video.deinit(gpa);
        gpa.free(s.h264_src);
        s.pieces.deinit(gpa);
        s.avc_rects.deinit(gpa);
        s.piece_rects.deinit(gpa);
        gpa.free(s.ref_qp);
        s.dirty.deinit(gpa);
        s.refine_rects.deinit(gpa);
        s.avc_region.deinit(gpa);
        s.* = .{};
    }

    /// The client's decoder state for a (re)created surface is gone (3.3.1.6); ours goes too.
    pub fn reset(s: *Surface) void {
        s.need_idr = true;
        @memset(s.ref_qp, no_ref);
        s.h264_src_ok = false;
        s.video.forget();
        s.region_h264 = false;
        if (s.chroma) |*d| d.rects.clearRetainingCapacity();
        if (s.prog) |*p| p.deinit();
        s.prog = null;
        s.prog_live = false;
        for (&s.rfx) |*r| if (r.*) |*e| {
            e.deinit();
            r.* = null;
        };
    }
};

pub const Sent = enum { lossless, avc444, avc420, progressive, remotefx };

/// Surface.ref_qp of a tile the stream has not coded yet.
const no_ref: u8 = 0xFF;

/// ClearCodec sequence numbers and caches are per channel (3.3.8.1).
pub fn onCapsConfirmed(c: *Conn, cs: gfx.CapSet) conn_mod.Error!void {
    const ch = &c.ch;
    const opts = c.vc.opts.graphics;
    ch.policy = policy.forGfx(cs, opts);
    if (opts.avc444 and !opts.avc444_preferred and !policy.clientAsksAvc444(cs) and (avc444.allowed(.v2, cs.version, cs.flags) catch false))
        log.info("{s}: AVC420, not AVC444: the client does not ask for it (as Windows: 10.1 or AVC_THINCLIENT; --codecs avc444 to force)", .{c.peer});
    if (ch.clear) |*e| e.deinit();
    ch.clear = null;
    if (ch.policy.clearcodec) ch.clear = clear.Encoder.init(c.gpa, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => null,
    };
    // A client that kept its ClearCodec context has its V-Bar storage cursors elsewhere:
    // CACHE_RESET (2.2.4.1) in the first message restarts both sides at 0.
    if (ch.clear) |*e| e.resetCaches() catch {};
    var buf: [128]u8 = undefined;
    var list = std.ArrayList(u8).initBuffer(&buf);
    for (ch.policy.motion(), 0..) |m, i| {
        if (i > 0) list.appendSliceAssumeCapacity(" > ");
        list.appendSliceAssumeCapacity(policy.motionName(m));
    }
    log.info("{s}: codecs: motion {s}; lossless {s}", .{ c.peer, list.items, if (ch.clear != null) "ClearCodec / planar" else "planar" });
}

/// Codecs that cannot be used on this connection (failed, or H.264 off).
fn off(c: *const Conn) std.EnumSet(policy.Motion) {
    var set = c.ch.codec_off;
    if (c.ch.avc_off) {
        set.insert(.avc444v2);
        set.insert(.avc420);
    }
    return set;
}

/// Lossy CPU codecs for motion: forced, or on a slow link (adapt.zig).
pub fn lossyWanted(c: *const Conn) bool {
    return switch (c.ch.policy.lossy_motion) {
        .always => true,
        .never => false,
        .auto => c.ch.adapt.slow(),
    };
}

/// The codec for a frame with motion, or null for lossless.
pub fn motionCodec(c: *const Conn) ?policy.Motion {
    const m = c.ch.policy.pick(off(c));
    if (m == .planar) return null;
    if (m.cpuLossy() and !lossyWanted(c)) return null;
    return m;
}

/// The policy's motion codec when it is H.264 (Windows' AVC pipeline for video needs AVC), or null.
pub fn videoCodec(c: *const Conn) ?policy.Motion {
    const m = motionCodec(c) orelse return null;
    return if (m.h264()) m else null;
}

/// Tests run detections on their own clock.
pub var video_clock: *const fn () i64 = &conn_mod.nowMs;

pub fn videoRegion(c: *const Conn) ?gfx.Rect16 {
    if (videoCodec(c) == null) return null;
    return c.ch.surf.video.region();
}

/// A frame's changes feed the video detector's heat map; then a detection, when due.
pub fn trackVideo(c: *Conn) conn_mod.Error!void {
    const s = &c.ch.surf;
    if (videoCodec(c) == null) return endVideo(c);
    try s.video.resize(c.gpa, c.enc.width, c.enc.height);
    const e = &c.enc;
    s.video.notify(if (e.tight.items.len == e.rects.items.len) e.tight.items else e.rects.items);
    tickVideo(c);
}

/// The refine loop calls this too, so a region ends on a still screen.
pub fn tickVideo(c: *Conn) void {
    const s = &c.ch.surf;
    if (videoCodec(c) == null) return endVideo(c);
    const e = &c.enc;
    if (s.video.width != e.width or s.video.height != e.height or e.width == 0) return;
    const was = s.video.region();
    const ev = s.video.tick(video_clock(), .{ .pixels = e.shadow, .stride = e.shadowStride(), .width = e.width, .height = e.height }) orelse return;
    switch (ev) {
        .started => {
            // A motion hold the video started ends: its changes have the region now.
            c.ch.motion_frames = 0;
            const r = s.video.region().?;
            log.info("{s}: video region {d}x{d} at {d},{d}: {s} for it, lossless around it", .{ c.peer, r.right - r.left, r.bottom - r.top, r.left, r.top, policy.motionName(videoCodec(c).?) });
        },
        .ended => {
            const r = was.?;
            // Refine what its H.264 showed, as Windows refines the old video rect.
            refineRegion(c, r);
            log.info("{s}: video region {d}x{d} at {d},{d} ended; refined", .{ c.peer, r.right - r.left, r.bottom - r.top, r.left, r.top });
        },
    }
}

/// No H.264 any more: no video region; what it showed is refined losslessly.
fn endVideo(c: *Conn) void {
    const s = &c.ch.surf;
    if (s.video.region()) |r| {
        refineRegion(c, r);
        log.info("{s}: video region {d}x{d} at {d},{d} ended: no H.264", .{ c.peer, r.right - r.left, r.bottom - r.top, r.left, r.top });
    }
    s.video.forget();
}

/// The encoder's rects with the motion codec when `motion`; with a video region, H.264 inside it
/// and the rest losslessly (`writeMixed`); else, or if every motion codec fails, losslessly.
pub fn writeFrame(c: *Conn, w: *bytes.Writer, sid: u16, motion: bool, region: ?gfx.Rect16) conn_mod.Error!Sent {
    if (motion) {
        for (0..policy.max_motion) |_| {
            const m = motionCodec(c) orelse break;
            const start = w.len();
            if (writeMotion(c, w, sid, m)) |sent| {
                // AVC420 marked its tiles with their QP (writeAvc420).
                if (sent != .avc420) c.enc.markLossy(c.enc.rects.items, true);
                return sent;
            } else |err| {
                w.list.shrinkRetainingCapacity(start);
                if (err == error.OutOfMemory and !m.h264()) return error.OutOfMemory;
                try dropCodec(c, w, sid, m, err);
            }
        }
    } else if (region) |v| {
        if (videoCodec(c) != null) return writeMixed(c, w, sid, v);
    }
    try writeLossless(c, w, sid, .owed);
    return .lossless;
}

/// Changes inside the video region go with H.264 (region rects: their boxes inside it), the rest losslessly.
fn writeMixed(c: *Conn, w: *bytes.Writer, sid: u16, v: gfx.Rect16) conn_mod.Error!Sent {
    const s = &c.ch.surf;
    const e = &c.enc;
    s.pieces.clearRetainingCapacity();
    s.avc_rects.clearRetainingCapacity();
    for (e.rects.items, 0..) |r, i| {
        const t = e.tightRect(i);
        if (intersect(t, v)) |inside| {
            try s.avc_rects.append(c.gpa, inside);
            // Around the region in the same tiles: pieces whose tiles stay lossy.
            var out: [4]gfx.Rect16 = undefined;
            for (subtract(t, v, &out)) |p| try s.pieces.append(c.gpa, .{ .rect = p, .tight = p, .exact = false });
        } else try s.pieces.append(c.gpa, .{ .rect = r, .tight = t, .exact = true });
    }
    const begin = w.len();
    var sent: Sent = .lossless;
    if (s.avc_rects.items.len > 0) {
        for (0..policy.max_motion) |_| {
            const m = videoCodec(c) orelse break;
            const start = w.len();
            if (writeH264(c, w, sid, m, s.avc_rects.items, .region)) |x| {
                sent = x;
                break;
            } else |err| {
                w.list.shrinkRetainingCapacity(start);
                try dropCodec(c, w, sid, m, err);
            }
        }
        // No H.264 any more: the region's changes go losslessly too.
        if (sent == .lossless) for (s.avc_rects.items) |a| try s.pieces.append(c.gpa, .{ .rect = a, .tight = a, .exact = false });
    }
    try writePieces(c, w, sid, s.pieces.items, .owed, w.len() - begin, null);
    if (sent != .lossless) {
        // The region's H.264 marks no tiles: the region is lossy as a whole (refineRegion), so tile
        // marks keep saying what is lossy outside it.
        s.region_h264 = true;
        if (s.prog) |*p| p.forget(try progRects(c, s.avc_rects.items)) catch {};
        c.ch.stats.video_frames += 1;
    }
    return sent;
}

/// The region's tiles become lossy (refined from its last QP) if it was sent with H.264 since:
/// when it ends, and when the screen is still.
pub fn refineRegion(c: *Conn, region: gfx.Rect16) void {
    const s = &c.ch.surf;
    if (!s.region_h264) return;
    s.region_h264 = false;
    c.enc.markLossyKeepOwed(&.{region}, s.region_qp);
}

/// QP from the frame's byte budget (`chooseQp`); a region's H.264 goes first in a mixed frame.
fn writeH264(c: *Conn, w: *bytes.Writer, sid: u16, m: policy.Motion, rects: []const gfx.Rect16, kind: Avc420Kind) !Sent {
    switch (m) {
        .avc444v2 => {
            try writeAvc444(c, w, sid, rects);
            return .avc444;
        },
        .avc420 => {
            try writeAvc420(c, w, sid, rects, kind);
            return .avc420;
        },
        else => unreachable,
    }
}

pub fn intersect(a: gfx.Rect16, b: gfx.Rect16) ?gfx.Rect16 {
    const r: gfx.Rect16 = .{ .left = @max(a.left, b.left), .top = @max(a.top, b.top), .right = @min(a.right, b.right), .bottom = @min(a.bottom, b.bottom) };
    return if (r.left < r.right and r.top < r.bottom) r else null;
}

/// `a` minus `b`: bands above and below `b`, then left and right (at most four, none empty).
pub fn subtract(a: gfx.Rect16, b: gfx.Rect16, out: *[4]gfx.Rect16) []const gfx.Rect16 {
    const i = intersect(a, b) orelse {
        out[0] = a;
        return out[0..1];
    };
    const parts = [_]gfx.Rect16{
        .{ .left = a.left, .top = a.top, .right = a.right, .bottom = i.top },
        .{ .left = a.left, .top = i.bottom, .right = a.right, .bottom = a.bottom },
        .{ .left = a.left, .top = i.top, .right = i.left, .bottom = i.bottom },
        .{ .left = i.right, .top = i.top, .right = a.right, .bottom = i.bottom },
    };
    var n: usize = 0;
    for (parts) |p| if (p.left < p.right and p.top < p.bottom) {
        out[n] = p;
        n += 1;
    };
    return out[0..n];
}

/// The H.264 picture: the shadow's pixels of `rects` copied in, out to the 16-pixel macroblock
/// grid; the rest keeps what was coded before. Whole after a reset or a new size.
fn h264Source(c: *Conn, rects: []const gfx.Rect16) ![]const u8 {
    const s = &c.ch.surf;
    const e = &c.enc;
    if (s.h264_src.len != e.shadow.len) {
        c.gpa.free(s.h264_src);
        s.h264_src = &.{};
        s.h264_src = try c.gpa.alloc(u8, e.shadow.len);
        s.h264_src_ok = false;
    }
    if (!s.h264_src_ok) {
        @memcpy(s.h264_src, e.shadow);
        s.h264_src_ok = true;
        return s.h264_src;
    }
    const stride = e.shadowStride();
    for (rects) |r| {
        const x0: usize = r.left & ~@as(u16, 15);
        const x1: usize = @min(e.width, (@as(u32, r.right) + 15) & ~@as(u32, 15));
        const y1: usize = @min(e.height, (@as(u32, r.bottom) + 15) & ~@as(u32, 15));
        var y: usize = r.top & ~@as(u16, 15);
        while (y < y1) : (y += 1) {
            const o = y * stride + x0 * 4;
            @memcpy(s.h264_src[o..][0 .. (x1 - x0) * 4], e.shadow[o..][0 .. (x1 - x0) * 4]);
        }
    }
    return s.h264_src;
}

fn writeMotion(c: *Conn, w: *bytes.Writer, sid: u16, m: policy.Motion) !Sent {
    return switch (m) {
        .avc444v2, .avc420 => writeH264(c, w, sid, m, c.enc.rects.items, .motion),
        .progressive => {
            try writeProgressive(c, w, sid);
            return .progressive;
        },
        .remotefx => {
            try writeRemoteFx(c, w, sid);
            return .remotefx;
        },
        .planar => unreachable,
    };
}

/// Off for the rest of the connection, its state dropped on both sides.
fn dropCodec(c: *Conn, w: *bytes.Writer, sid: u16, m: policy.Motion, err: anyerror) conn_mod.Error!void {
    const s = &c.ch.surf;
    c.ch.codec_off.insert(m);
    switch (m) {
        .avc444v2, .avc420 => {
            if (s.h264) |*h| h.deinit();
            s.h264 = null;
            s.need_idr = true;
            // No VA-API H.264 at all: H.264 off (channels.avcAllowed).
            if (m == .avc420 or err == error.OpenDevice or err == error.VaInit) c.ch.avc_off = true;
            log.warn("{s}: {s} unavailable ({t}); next codec", .{ c.peer, policy.motionName(m), err });
        },
        .progressive => {
            if (s.prog_live) progressive.writeDeleteEncodingContext(w, sid, s.prog_ctx) catch |e| return progError(e);
            if (s.prog) |*p| p.deinit();
            s.prog = null;
            s.prog_live = false;
            log.warn("{s}: progressive failed ({t}); next codec", .{ c.peer, err });
        },
        .remotefx => {
            for (&s.rfx) |*r| if (r.*) |*e| {
                e.deinit();
                r.* = null;
            };
            log.warn("{s}: RemoteFX failed ({t}); next codec", .{ c.peer, err });
        },
        .planar => {},
    }
}

/// RDPGFX_DELETE_ENCODING_CONTEXT_PDU (2.2.2.3); the state goes with Surface.reset.
pub fn writeDeleteContext(c: *Conn, w: *bytes.Writer, sid: u16) conn_mod.Error!void {
    progressive.writeDeleteEncodingContext(w, sid, c.ch.surf.prog_ctx) catch |e| return progError(e);
    c.ch.surf.prog_live = false;
}

/// Only out of memory, or a payload beyond 4 GiB.
fn progError(e: progressive.Error) conn_mod.Error {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidDimensions,
    };
}

/// Windows gives its encoder the frame budget x frames a second, at most 30 Mbit/s; the QP sets the real rate.
fn nominal(c: *const Conn) struct { bitrate: u32, fps: u32 } {
    return .{ .bitrate = @intCast(pacing.max_avc_bps), .fps = 1000 / @max(1, c.pacing.interval_ms) };
}

fn updatedMbs(c: *const Conn, rects: []const gfx.Rect16, idr: bool) u64 {
    if (idr) return @as(u64, (c.enc.width + 15) / 16) * ((c.enc.height + 15) / 16);
    var n: u64 = 0;
    for (rects) |r| n += @as(u64, (r.right - r.left + 15) / 16) * ((r.bottom - r.top + 15) / 16);
    return @max(n, 1);
}

/// At QP q the encoder also codes macroblocks whose reference is worse than q.
const QpCtx = struct {
    c: *Conn,
    budget: usize,
    dirty_mbs: u64,
    idr: bool,
    raw: usize,
    views: usize,

    fn fits(q: QpCtx, qp: u8) bool {
        const mbs = if (q.idr) q.dirty_mbs else q.dirty_mbs + refinedMbs(q.c, qp);
        return q.c.pacing.avc.estimate(mbs, qp, q.idr, q.raw) *| q.views <= q.budget;
    }
};

/// Outside the frame's changed tiles, reference worse than `qp` (16 per tile).
fn refinedMbs(c: *const Conn, qp: u8) u64 {
    const s = &c.ch.surf;
    var n: u64 = 0;
    for (s.ref_qp, 0..) |r, i| {
        if (r <= qp or (i < s.dirty.bit_length and s.dirty.isSet(i))) continue;
        n += 16;
    }
    return n;
}

/// `views`: 2 for both AVC444 views. Windows' levels, the best whose estimate fits the byte budget.
fn chooseQp(c: *Conn, dirty_mbs: u64, idr: bool, views: usize) u8 {
    // No session output yet (a Conn driven directly): the best level.
    if (c.flow.mode == .off) return pacing.avc_min_qp;
    const ctx: QpCtx = .{
        .c = c,
        .budget = c.pacing.avcBudget(conn_mod.nowMs()),
        .dirty_mbs = dirty_mbs,
        .idr = idr,
        .raw = @as(usize, c.enc.width) * c.enc.height * 3 / 2,
        .views = views,
    };
    return pacing.frameQp(dirty_mbs, ctx, QpCtx.fits);
}

fn markDirty(c: *Conn, rects: []const gfx.Rect16) !void {
    const s = &c.ch.surf;
    const tx_n = (c.enc.width + 63) / 64;
    const n = tx_n * ((c.enc.height + 63) / 64);
    if (s.dirty.bit_length != n) try s.dirty.resize(c.gpa, n, false);
    s.dirty.unsetAll();
    for (rects) |r| {
        var ty: u32 = r.top / 64;
        while (ty * 64 < r.bottom) : (ty += 1) {
            var tx: u32 = r.left / 64;
            while (tx * 64 < r.right) : (tx += 1) s.dirty.set(ty * tx_n + tx);
        }
    }
}

/// The reference now holds the changed tiles, and every tile it had worse, at `qp`.
fn noteRefs(c: *Conn, qp: u8, idr: bool) void {
    const s = &c.ch.surf;
    for (s.ref_qp, 0..) |*r, i| {
        const changed = i < s.dirty.bit_length and s.dirty.isSet(i);
        if (idr or changed or r.* > qp) r.* = qp;
    }
}

fn avcSent(c: *Conn, mbs: u64, qp: u8, idr: bool, bytes_per_view: usize) void {
    c.pacing.avc.learn(mbs, qp, idr, bytes_per_view);
    c.pacing.stats.avc_frames += 1;
    c.pacing.stats.qp_sum += qp;
    c.pacing.avc_total += 1;
    c.pacing.qp_total += qp;
}

pub const Avc420Kind = union(enum) {
    /// `rects` are its changed tiles (lossy afterwards at the frame's QP).
    motion,
    /// `rects` lie inside the region, which is lossy as a whole (refineRegion).
    region,
    /// No new content: `rects` are the lossy tiles it refines at this QP.
    refine: u8,
};

/// The whole surface is coded (`h264Source`); the region rects say what the client copies (2.2.4.4).
/// Lossy tiles shown worse than the picture's QP are refined for free: their rects join the region.
fn writeAvc420(c: *Conn, w: *bytes.Writer, sid: u16, rects: []const gfx.Rect16, kind: Avc420Kind) !void {
    const s = &c.ch.surf;
    const width = c.enc.width;
    const height = c.enc.height;
    // SPS cropping needs even sizes in 4:2:0; odd ones are coded 16-aligned and the region mask crops (2.2.4.4).
    const crop = width % 2 == 0 and height % 2 == 0;
    if (s.h264) |*h| if (h.opts.crop != crop or h.opts.avc444 != null) {
        h.deinit();
        s.h264 = null;
    };
    const r = nominal(c);
    if (s.h264 == null) {
        s.h264 = try vaapi_h264.Encoder.init(c.gpa, .{ .width = width, .height = height, .bitrate = r.bitrate, .fps = r.fps, .crop = crop, .rate_control = .cqp, .qp = pacing.avc_min_qp });
        s.need_idr = true;
        // The refinement wait is picked once, from the link's rate, as Windows' encoder does.
        const rate = c.flow.rate() * 8;
        s.quiet_ms = if (rate > 0 and rate < pacing.refine_quiet_slow_bps) pacing.refine_quiet_slow_ms else pacing.refine_quiet_ms;
        log.info("{s}: H.264 encoder ready ({d}x{d}, QP {d}..{d} per frame from its byte budget, refined after {d} ms still, {d} fps at most)", .{ c.peer, width, height, pacing.avc_min_qp, pacing.avc_max_qp, s.quiet_ms, r.fps });
    }
    const h = &s.h264.?;
    if (h.opts.width != width or h.opts.height != height) {
        try h.resize(width, height);
        s.need_idr = true;
    }
    const tiles = ((width + 63) / 64) * ((height + 63) / 64);
    if (s.ref_qp.len != tiles) {
        c.gpa.free(s.ref_qp);
        s.ref_qp = &.{};
        s.ref_qp = try c.gpa.alloc(u8, tiles);
        @memset(s.ref_qp, no_ref);
        s.need_idr = true;
    }
    const idr = s.need_idr;
    const content: []const gfx.Rect16 = switch (kind) {
        .refine => &.{},
        else => rects,
    };
    try markDirty(c, content);
    const dirty_mbs = updatedMbs(c, content, idr);
    const qp: u8 = switch (kind) {
        .refine => |q| q,
        else => chooseQp(c, dirty_mbs, idr, 1),
    };
    s.refine_rects.clearRetainingCapacity();
    _ = try c.enc.lossyAboveExcept(qp, &s.dirty, &s.refine_rects);
    s.avc_region.clearRetainingCapacity();
    try s.avc_region.appendSlice(c.gpa, content);
    try s.avc_region.appendSlice(c.gpa, s.refine_rects.items);
    if (s.avc_region.items.len == 0) return error.NothingToRefine;
    h.setQp(qp);
    s.h264_out.clearRetainingCapacity();
    const src = try h264Source(c, content);
    const mbs = if (idr) dirty_mbs else dirty_mbs + refinedMbs(c, qp);
    const info = try h.encode(src, c.enc.shadowStride(), s.need_idr, &s.h264_out);
    s.need_idr = false;
    noteRefs(c, qp, info.idr);
    avcSent(c, mbs, qp, info.idr, info.size);
    s.bitmap.clearRetainingCapacity();
    var bw = bytes.Writer.init(&s.bitmap, c.gpa);
    try avc420.writeAvc420(&bw, s.avc_region.items, qp, s.h264_out.items);
    c.ch.stats.h264_bytes += s.h264_out.items.len;
    const full: gfx.Rect16 = .{ .left = 0, .top = 0, .right = @intCast(width), .bottom = @intCast(height) };
    const p = try gfx.beginWireToSurface1(w, sid, .avc420, full, s.bitmap.items.len);
    try w.bytes(s.bitmap.items);
    p.finish(w);
    // The new content is shown at `qp` too, except a video region's (lossy as a whole).
    c.enc.markLossyQp(s.refine_rects.items, qp);
    switch (kind) {
        .motion, .refine => c.enc.markLossyQp(content, qp),
        .region => s.region_qp = qp,
    }
}

/// AVC444v2 (2.2.4.6): luma and chroma views of the whole surface in one H.264 stream. Without budget
/// for both, only luma goes (LC 1) and the chroma is owed until a frame fits (LC 2).
fn writeAvc444(c: *Conn, w: *bytes.Writer, sid: u16, rects: []const gfx.Rect16) !void {
    const s = &c.ch.surf;
    const width = c.enc.width;
    const height = c.enc.height;
    if (s.h264) |*h| if (h.opts.avc444 == null) {
        h.deinit();
        s.h264 = null;
    };
    const r = nominal(c);
    if (s.h264 == null) {
        // Init probes AVC444 on the device: error.Unsupported drops to AVC420.
        s.h264 = try vaapi_h264.Encoder.init(c.gpa, .{ .width = width, .height = height, .bitrate = r.bitrate, .fps = r.fps, .crop = false, .avc444 = .v2, .rate_control = .cqp, .qp = pacing.avc_min_qp });
        s.need_idr = true;
        log.info("{s}: H.264 AVC444v2 encoder ready ({d}x{d}, QP per frame from its byte budget, {d} fps at most)", .{ c.peer, width, height, r.fps });
    }
    const h = &s.h264.?;
    if (h.opts.width != width or h.opts.height != height) {
        try h.resize(width, height);
        s.need_idr = true;
    }
    if (s.chroma == null) s.chroma = try avc444.ChromaDebt.init(c.gpa);
    const debt = &s.chroma.?;
    const idr = s.need_idr;
    const mbs = updatedMbs(c, rects, idr);
    // Both views at the minimum QP, or luma alone at the level that fits; Windows sends chroma once luma is done.
    try markDirty(c, rects);
    const both_qp = chooseQp(c, mbs, idr, 2);
    const both_fit = both_qp == pacing.avc_min_qp;
    const q: struct { qp: u8 } = .{ .qp = if (both_fit) both_qp else chooseQp(c, mbs, idr, 1) };
    h.setQp(q.qp);
    s.h264_out.clearRetainingCapacity();
    s.aux_out.clearRetainingCapacity();
    const src = try h264Source(c, rects);
    const info = try h.encode444(src, c.enc.shadowStride(), s.need_idr, if (both_fit) .both else .luma, &s.h264_out, &s.aux_out);
    s.need_idr = false;
    // An IDR codes both views whatever was asked.
    const main = info.main orelse return error.BadEncoderOutput;
    const lc: avc444.Lc = if (info.aux != null) .both else .luma;
    avcSent(c, mbs, main.avg_qp, main.idr, main.size);
    try writeAvc444Pdu(c, w, sid, lc, .{ .rects = rects, .qp = main.avg_qp, .h264 = s.h264_out.items }, if (info.aux) |a| .{ .rects = rects, .qp = a.avg_qp, .h264 = s.aux_out.items } else null);
    c.ch.stats.h264_bytes += s.h264_out.items.len + s.aux_out.items.len;
    try debt.sent(lc, rects);
    if (lc != .both or !try debt.pending()) return;
    // Chroma owed from earlier luma-only frames: an LC 2 bitmap.
    var owed_buf: [16]avc420.Rect16 = undefined;
    const owed = try debt.owed(&owed_buf);
    s.aux_out.clearRetainingCapacity();
    const pay = try h.encode444(src, c.enc.shadowStride(), false, .chroma, &s.h264_out, &s.aux_out);
    const aux = pay.aux orelse return error.BadEncoderOutput;
    if (pay.main != null) return error.BadEncoderOutput; // an IDR here would desync the views
    try writeAvc444Pdu(c, w, sid, .chroma, .{ .rects = owed, .qp = aux.avg_qp, .h264 = s.aux_out.items }, null);
    c.ch.stats.h264_bytes += s.aux_out.items.len;
    try debt.sent(.chroma, owed);
}

fn writeAvc444Pdu(c: *Conn, w: *bytes.Writer, sid: u16, lc: avc444.Lc, s1: avc444.SubStream, s2: ?avc444.SubStream) !void {
    const s = &c.ch.surf;
    s.bitmap.clearRetainingCapacity();
    var bw = bytes.Writer.init(&s.bitmap, c.gpa);
    try avc444.writeAvc444(&bw, lc, s1, s2);
    const full: gfx.Rect16 = .{ .left = 0, .top = 0, .right = @intCast(c.enc.width), .bottom = @intCast(c.enc.height) };
    const p = try gfx.beginWireToSurface1(w, sid, .avc444v2, full, s.bitmap.items.len);
    try w.bytes(s.bitmap.items);
    p.finish(w);
}

fn progRects(c: *Conn, rects: []const gfx.Rect16) ![]const progressive.Rect {
    const s = &c.ch.surf;
    s.scratch_rects.clearRetainingCapacity();
    try s.scratch_rects.ensureTotalCapacity(c.gpa, rects.len);
    for (rects) |r| s.scratch_rects.appendAssumeCapacity(.{ .x = r.left, .y = r.top, .width = r.right - r.left, .height = r.bottom - r.top });
    return s.scratch_rects.items;
}

/// One WIRE_TO_SURFACE_PDU_2 with the surface's codecContextId.
fn writeProgressive(c: *Conn, w: *bytes.Writer, sid: u16) !void {
    const s = &c.ch.surf;
    if (s.prog) |p| if (p.width != c.enc.width or p.height != c.enc.height) {
        // A new size is a new surface (resetGraphics); a stale encoder must never code for another size.
        if (s.prog_live) try progressive.writeDeleteEncodingContext(w, sid, s.prog_ctx);
        s.prog.?.deinit();
        s.prog = null;
        s.prog_live = false;
    };
    if (s.prog == null) {
        const bw = c.ch.adapt.link.bandwidth orelse std.math.maxInt(u64);
        const levels: []const progressive.ProgQuant = if (bw < thin_kbps) &prog_levels_thin else &prog_levels;
        s.prog = try progressive.Encoder.init(c.gpa, @intCast(c.enc.width), @intCast(c.enc.height), .{ .levels = levels });
        s.prog_ctx = c.ch.next_codec_ctx;
        c.ch.next_codec_ctx +%= 1;
    }
    // Within the frame's budget; the rest is owed.
    const area = try budgetRects(c, c.ch.prog_bpp_x100);
    const rects = try progRects(c, c.enc.rects.items);
    s.bitmap.clearRetainingCapacity();
    try s.prog.?.encodeFrame(&s.bitmap, c.enc.shadow, c.enc.shadowStride(), rects);
    try progressive.writeWireToSurface2(w, sid, s.prog_ctx, gfx.pixel_format_xrgb8888, s.bitmap.items);
    s.prog_live = true;
    c.ch.prog_bpp_x100 = learnBpp(c.ch.prog_bpp_x100, s.bitmap.items.len, area);
}

/// Moving average of hundredths of a bit per pixel (1 to 2400).
fn learnBpp(old: u32, bytes_: usize, area: u64) u32 {
    if (area == 0) return old;
    const now: u64 = @min(@as(u64, bytes_) * 800 / area, 2400);
    return @intCast(@max(1, (@as(u64, old) * 7 + now * 3) / 10));
}

/// Keeps what fits the frame's byte budget at `bpp_x100`, in pieces of a tile row at most 8 tiles
/// wide (at least one); the rest is owed to the next frames. Returns the pixels kept.
fn budgetRects(c: *Conn, bpp_x100: u32) !u64 {
    const e = &c.enc;
    const budget = c.ch.rawBudget(c.frameBudget());
    var area: u64 = 0;
    if (budget == std.math.maxInt(usize)) {
        for (e.rects.items) |r| area += @as(u64, r.right - r.left) * (r.bottom - r.top);
        return area;
    }
    var kept: std.ArrayList(gfx.Rect16) = .empty;
    defer kept.deinit(c.gpa);
    var rest: std.ArrayList(gfx.Rect16) = .empty;
    defer rest.deinit(c.gpa);
    var est: u64 = 0;
    for (e.rects.items) |r| {
        var x = r.left;
        while (x < r.right) {
            const x1 = @min(r.right, x + pacing.piece_px);
            const piece: gfx.Rect16 = .{ .left = x, .top = r.top, .right = x1, .bottom = r.bottom };
            const px = @as(u64, x1 - x) * (r.bottom - r.top);
            if (kept.items.len > 0 and est >= budget) {
                try rest.append(c.gpa, piece);
            } else {
                try kept.append(c.gpa, piece);
                est += px * bpp_x100 / 800;
                area += px;
            }
            x = x1;
        }
    }
    if (rest.items.len == 0) return area;
    e.owe(rest.items);
    e.rects.clearRetainingCapacity();
    e.tight.clearRetainingCapacity();
    try e.rects.appendSlice(c.gpa, kept.items);
    c.pacing.cut();
    return area;
}

/// n x m RemoteFX panes of at most 4096x2048, as even as possible; the last column/row may be smaller.
const Panes = struct {
    nx: u32,
    ny: u32,
    pw: u32,
    ph: u32,
    w: u32,
    h: u32,

    fn of(w: u32, h: u32) Panes {
        const nx = (w + rfx.max_channel_width - 1) / rfx.max_channel_width;
        const ny = (h + rfx.max_channel_height - 1) / rfx.max_channel_height;
        return .{ .nx = nx, .ny = ny, .pw = (w + nx - 1) / nx, .ph = (h + ny - 1) / ny, .w = w, .h = h };
    }

    fn uniform(p: Panes) bool {
        return p.pw * p.nx == p.w and p.ph * p.ny == p.h;
    }

    /// Pane (i, j): origin, size and size class (index into Surface.rfx).
    fn at(p: Panes, i: u32, j: u32) struct { x: u32, y: u32, w: u32, h: u32, class: usize } {
        const x = i * p.pw;
        const y = j * p.ph;
        const w = @min(p.pw, p.w - x);
        const h = @min(p.ph, p.h - y);
        return .{ .x = x, .y = y, .w = w, .h = h, .class = @as(usize, @intFromBool(w != p.pw)) | @as(usize, @intFromBool(h != p.ph)) << 1 };
    }
};

/// One CAVIDEO WireToSurface1 per pane touched. Uniform panes share one video-mode stream;
/// otherwise each size class codes in image mode, so no pane depends on another's headers.
fn writeRemoteFx(c: *Conn, w: *bytes.Writer, sid: u16) !void {
    const s = &c.ch.surf;
    const area = try budgetRects(c, c.ch.rfx_bpp_x100);
    const begin = w.len();
    defer c.ch.rfx_bpp_x100 = learnBpp(c.ch.rfx_bpp_x100, w.len() - begin, area);
    const panes = Panes.of(c.enc.width, c.enc.height);
    const mode: rfx.Mode = if (panes.uniform()) .video else .image;
    const stride = c.enc.shadowStride();
    var rr: std.ArrayList(rfx.Rect) = .empty;
    defer rr.deinit(c.gpa);
    for (0..panes.ny) |j| for (0..panes.nx) |i| {
        const p = panes.at(@intCast(i), @intCast(j));
        rr.clearRetainingCapacity();
        for (c.enc.rects.items) |r| {
            const x0 = @max(@as(u32, r.left), p.x);
            const x1 = @min(@as(u32, r.right), p.x + p.w);
            const y0 = @max(@as(u32, r.top), p.y);
            const y1 = @min(@as(u32, r.bottom), p.y + p.h);
            if (x0 >= x1 or y0 >= y1) continue;
            try rr.append(c.gpa, .{ .x = @intCast(x0 - p.x), .y = @intCast(y0 - p.y), .width = @intCast(x1 - x0), .height = @intCast(y1 - y0) });
        }
        if (rr.items.len == 0) continue;
        const slot = &s.rfx[p.class];
        if (slot.*) |e| if (e.opts.width != p.w or e.opts.height != p.h or e.opts.mode != mode) {
            slot.*.?.deinit();
            slot.* = null;
        };
        if (slot.* == null) slot.* = try rfx.Encoder.init(c.gpa, .{ .width = @intCast(p.w), .height = @intCast(p.h), .mode = mode });
        s.bitmap.clearRetainingCapacity();
        try slot.*.?.encodeFrame(&s.bitmap, c.enc.shadow[@as(usize, p.y) * stride + @as(usize, p.x) * 4 ..], stride, rr.items);
        const dest: gfx.Rect16 = .{ .left = @intCast(p.x), .top = @intCast(p.y), .right = @intCast(p.x + p.w), .bottom = @intCast(p.y + p.h) };
        const pdu = try gfx.beginWireToSurface1(w, sid, .cavideo, dest, s.bitmap.items.len);
        try w.bytes(s.bitmap.items);
        pdu.finish(w);
    };
}

fn fewColours(c: *const Conn, r: gfx.Rect16, limit: usize) bool {
    var seen: [64]u32 = undefined;
    std.debug.assert(limit <= seen.len);
    var n: usize = 0;
    const stride = c.enc.shadowStride();
    var y: usize = r.top;
    while (y < r.bottom) : (y += 1) {
        const row = c.enc.shadow[y * stride ..];
        var x: usize = r.left;
        var last: ?u32 = null;
        next: while (x < r.right) : (x += 1) {
            const v = std.mem.readInt(u32, row[x * 4 ..][0..4], .little) & 0xFFFFFF;
            if (last == v) continue;
            last = v;
            for (seen[0..n]) |sv| if (sv == v) continue :next;
            if (n == limit) return false;
            seen[n] = v;
            n += 1;
        }
    }
    return true;
}

/// Small, few colours, and no lossy tile in the rect (the rest of it must not be left lossy).
fn clearFor(c: *const Conn, p: Piece) ?gfx.Rect16 {
    if (c.ch.clear == null) return null;
    const t = p.tight;
    if (@as(u32, t.right - t.left) * (t.bottom - t.top) > clear_max_area) return null;
    if (c.enc.anyLossy(p.rect)) return null;
    if (!fewColours(c, t, clear_max_colours)) return null;
    return t;
}

/// What the byte budget leaves: owed (content the client lacks) or still lossy (a refine step).
pub const Leftover = enum { owed, lossy };

/// `tight`: the changed pixels (ClearCodec may send only those). `exact`: the rect is all its
/// tiles hold of the frame, so they are exact once sent; not so beside H.264 (writeMixed).
pub const Piece = struct { rect: gfx.Rect16, tight: gfx.Rect16, exact: bool };

/// ClearCodec where it pays off, planar otherwise. Within the frame budget rects go in pieces of a
/// few tiles; the rest is left as `leftover` (always one piece first, so every frame progresses).
pub fn writeLossless(c: *Conn, w: *bytes.Writer, sid: u16, leftover: Leftover) conn_mod.Error!void {
    const e = &c.enc;
    const s = &c.ch.surf;
    s.pieces.clearRetainingCapacity();
    try s.pieces.ensureTotalCapacity(c.gpa, e.rects.items.len);
    for (e.rects.items, 0..) |r, i| s.pieces.appendAssumeCapacity(.{ .rect = r, .tight = e.tightRect(i), .exact = true });
    try writePieces(c, w, sid, s.pieces.items, leftover, 0, null);
}

/// In a frame that holds `spent` bytes already.
fn writePieces(c: *Conn, w: *bytes.Writer, sid: u16, pieces: []const Piece, leftover: Leftover, spent: usize, limit: ?usize) conn_mod.Error!void {
    const e = &c.enc;
    // Counted before ZGFX, which shrinks them by its recent ratio (or `limit`, the caller's).
    const raw = limit orelse c.ch.rawBudget(c.frameBudget());
    const paced = raw != std.math.maxInt(usize);
    const budget = if (paced) raw -| spent else raw;
    const piece = pacing.pieceWidth(budget);
    const begin = w.len();
    var rest: std.ArrayList(gfx.Rect16) = .empty;
    defer rest.deinit(c.gpa);
    var sent = false;
    for (pieces) |pc| {
        const r = pc.rect;
        if (sent and w.len() - begin >= budget) {
            try rest.append(c.gpa, r);
            continue;
        }
        if (clearFor(c, pc)) |t| {
            const start = w.len();
            if (writeClear(c, w, sid, t)) |_| {
                c.ch.stats.clear_rects += 1;
                sent = true;
                continue;
            } else |err| {
                w.list.shrinkRetainingCapacity(start);
                if (err == error.OutOfMemory) return error.OutOfMemory;
                log.debug("{s}: ClearCodec failed ({t}); planar", .{ c.peer, err });
            }
        }
        if (!paced) {
            try e.writePlanarRect(w, sid, r);
            c.ch.stats.planar_rects += 1;
            sent = true;
            continue;
        }
        var x = r.left;
        while (x < r.right) {
            if (sent and w.len() - begin >= budget) {
                try rest.append(c.gpa, .{ .left = x, .top = r.top, .right = r.right, .bottom = r.bottom });
                break;
            }
            const x1 = @min(r.right, x + piece);
            try e.writePlanarRect(w, sid, .{ .left = x, .top = r.top, .right = x1, .bottom = r.bottom });
            c.ch.stats.planar_rects += 1;
            sent = true;
            x = x1;
        }
    }
    for (pieces) |pc| if (pc.exact) e.markLossy(&.{pc.rect}, false);
    if (rest.items.len > 0) {
        switch (leftover) {
            .owed => e.owe(rest.items),
            .lossy => e.markLossy(rest.items, true),
        }
        c.pacing.cut();
    }
    const s = &c.ch.surf;
    // Lossless rects owe no AVC444 chroma: a later chroma bitmap would put older colours over them.
    if (s.chroma) |*debt| for (pieces) |pc| debt.sent(.both, &.{pc.rect}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {}, // only appends can fail
    };
    if (s.prog != null) {
        s.piece_rects.clearRetainingCapacity();
        for (pieces) |pc| try s.piece_rects.append(c.gpa, pc.rect);
        const pr = try progRects(c, s.piece_rects.items);
        s.prog.?.forget(pr) catch {};
    }
}

fn writeClear(c: *Conn, w: *bytes.Writer, sid: u16, r: gfx.Rect16) !void {
    const s = &c.ch.surf;
    const stride = c.enc.shadowStride();
    s.bitmap.clearRetainingCapacity();
    try c.ch.clear.?.encode(&s.bitmap, c.enc.shadow[@as(usize, r.top) * stride + @as(usize, r.left) * 4 ..], stride, r.right - r.left, r.bottom - r.top);
    const p = try gfx.beginWireToSurface1(w, sid, .clearcodec, r, s.bitmap.items.len);
    try w.bytes(s.bitmap.items);
    p.finish(w);
}

/// Lossy H.264 tiles are refined in H.264 first (AVC444's losslessly).
fn avcRefines(c: *const Conn) bool {
    const m = motionCodec(c) orelse return false;
    return m == .avc420;
}

/// AVC420 tiles once their H.264 refinement is done (the minimum QP); any tile without it.
fn losslessMaxQp(c: *const Conn) u8 {
    return if (avcRefines(c)) pacing.avc_min_qp else encoder_mod.Encoder.lossy_other;
}

pub fn quietMs(c: *const Conn) i64 {
    return c.ch.surf.quiet_ms;
}

/// Lossy tiles quiet for `quiet_ms`, refined losslessly with the budget new content left (paced links only).
pub fn writeRefineWithin(c: *Conn, w: *bytes.Writer, sid: u16, spent: usize, quiet_ms: i64) conn_mod.Error!void {
    const e = &c.enc;
    if (!e.hasLossy()) return;
    // Wire bytes, not scaled by ZGFX's ratio: refined content need not compress like the frame's.
    if (c.flow.mode == .off) return; // unpaced: the refine loop does it
    const raw = c.frameBudget();
    if (raw -| spent < pacing.min_piece_bytes) return;
    const now = conn_mod.nowMs();
    const max_qp = losslessMaxQp(c);
    if (!e.anyQuietLossyAt(now, quiet_ms, max_qp)) return;
    const s = &c.ch.surf;
    s.piece_rects.clearRetainingCapacity();
    _ = try e.takeQuietLossyAt(now, quiet_ms, max_qp, std.math.maxInt(u64), &s.piece_rects);
    var pieces: std.ArrayList(Piece) = .empty;
    defer pieces.deinit(c.gpa);
    try pieces.ensureTotalCapacity(c.gpa, s.piece_rects.items.len);
    for (s.piece_rects.items) |r| pieces.appendAssumeCapacity(.{ .rect = r, .tight = r, .exact = true });
    try writePieces(c, w, sid, pieces.items, .lossy, spent, raw);
    c.ch.stats.refine_rects += pieces.items.len;
}

pub fn refinePending(c: *const Conn) bool {
    return pendingOn(&c.enc, &c.ch.surf);
}

/// Owed or lossy tiles, progressive upgrades, or a video region whose end the refine loop must see.
pub fn pendingOn(enc: *const encoder_mod.Encoder, surf: *const Surface) bool {
    if (enc.hasLossy() or enc.hasOwed() or surf.video.region() != null) return true;
    const p = surf.prog orelse return false;
    return (p.pendingTiles() catch 0) > 0;
}

/// One refine step as its own frame, for lossy tiles quiet for `quiet_ms`: a progressive upgrade
/// (still screen), else an AVC420 pass at the next QP (38 -> 30 -> 22), else losslessly. False: nothing sent.
pub fn writeRefine(c: *Conn, w: *bytes.Writer, sid: u16, now_ms: i64, quiet_ms: i64, still: bool) conn_mod.Error!bool {
    const s = &c.ch.surf;
    if (still) if (s.prog) |*p| {
        s.bitmap.clearRetainingCapacity();
        // Cut to the frame's budget: the other tiles keep their level.
        const up = p.encodeUpgradeWithin(&s.bitmap, c.ch.rawBudget(c.frameBudget())) catch |err| blk: {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            try dropCodec(c, w, sid, .progressive, err);
            break :blk false;
        };
        if (up) {
            progressive.writeWireToSurface2(w, sid, s.prog_ctx, gfx.pixel_format_xrgb8888, s.bitmap.items) catch |e| return progError(e);
            c.ch.stats.upgrades += 1;
            return true;
        }
    };
    const quiet: i64 = if (still) 0 else quiet_ms;
    if (avcRefines(c)) if (c.enc.quietQpAbove(now_ms, quiet, pacing.avc_min_qp, still)) |top| {
        const start = w.len();
        if (writeAvc420(c, w, sid, &.{}, .{ .refine = pacing.refineQp(top) })) |_| {
            c.ch.stats.avc_refines += 1;
            return true;
        } else |err| {
            w.list.shrinkRetainingCapacity(start);
            if (err == error.OutOfMemory) return error.OutOfMemory;
            if (err != error.NothingToRefine) try dropCodec(c, w, sid, .avc420, err);
        }
    };
    const e = &c.enc;
    e.rects.clearRetainingCapacity();
    e.tight.clearRetainingCapacity();
    if (try e.takeQuietLossyAt(now_ms, quiet, losslessMaxQp(c), std.math.maxInt(u64), &e.rects) == 0) return false;
    // Cut to the frame budget: the rest stays lossy for the next step.
    try writeLossless(c, w, sid, .lossy);
    return true;
}

test "RemoteFX panes: at most 4096x2048, as even as possible, size classes" {
    const p = Panes.of(1920, 1080);
    try std.testing.expect(p.nx == 1 and p.ny == 1 and p.uniform());
    const q = Panes.of(3840, 2160);
    try std.testing.expect(q.nx == 1 and q.ny == 2 and q.ph == 1080 and q.uniform());
    const r = Panes.of(5121, 2881);
    try std.testing.expect(r.nx == 2 and r.ny == 2 and !r.uniform());
    try std.testing.expectEqual(@as(usize, 0), r.at(0, 0).class);
    const last = r.at(1, 1);
    try std.testing.expectEqual(@as(usize, 3), last.class);
    try std.testing.expectEqual(@as(u32, 5121), last.x + last.w);
    try std.testing.expectEqual(@as(u32, 2881), last.y + last.h);
    try std.testing.expect(r.pw <= rfx.max_channel_width and r.ph <= rfx.max_channel_height);
}
