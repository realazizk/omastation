//! GPU capture: frames the compositor renders into dmabufs (no copy to RAM) are diffed on the GPU
//! (tilediff.zig) and only their changed tiles reach the CPU, into the encoder's shadow
//! (server/encoder.zig applyTileDiff), with the same rects, tight boxes and shadow as its diff. Anything
//! this path cannot take (no Vulkan device on the capture's GPU, an import or GPU failure, buffers
//! the compositor never fills as on some VM GPUs, a rotated output, a format other than BGRX)
//! switches that output's capture to shm, logged once.

const std = @import("std");
const wl = @import("../wl/wl.zig");
const gbm = @import("gbm.zig");
const vk = @import("vk.zig");
const tilediff = @import("tilediff.zig");
const nv12 = @import("nv12.zig");
const vaapi_h264 = @import("../codec/vaapi_h264.zig");
const gfx = @import("../proto/gfx.zig");

const log = std.log.scoped(.gpucap);

/// Frames in a row still being rendered into (skipped) before the output goes to shm.
const max_busy_frames = 10;

/// Encoder.gpu_token values: unique per diff so a reference never matches another encoder.
var next_token = std.atomic.Value(u64).init(1);

/// Per frame source (a desktop or a test capture): the capture buffers' allocator and the Vulkan
/// device of their GPU, opened on the first frame.
pub const Shared = struct {
    gpa: std.mem.Allocator,
    gbm: gbm.Gbm,
    alloc: wl.dmabuf.Allocator = undefined,
    dev: ?vk.Device = null,
    dev_tried: bool = false,
    /// Why there is no device (fallback messages).
    dev_why: vk.Why = .{},

    pub fn create(gpa: std.mem.Allocator) !*Shared {
        const s = try gpa.create(Shared);
        s.* = .{ .gpa = gpa, .gbm = gbm.Gbm.init(gpa) };
        s.alloc = s.gbm.allocator();
        return s;
    }

    pub fn destroy(s: *Shared) void {
        if (s.dev) |*d| d.deinit();
        s.gbm.deinit();
        s.gpa.destroy(s);
    }

    /// The capture options for dmabuf buffers from this allocator.
    pub fn captureOptions(s: *Shared, base: wl.capture.Options) wl.capture.Options {
        var o = base;
        o.buffers = .dmabuf;
        o.dmabuf_allocator = &s.alloc;
        o.dmabuf_count = 3;
        o.prefer_linear = true;
        return o;
    }

    fn device(s: *Shared) ?*vk.Device {
        if (s.dev) |*d| return d;
        if (s.dev_tried) return null;
        s.dev_tried = true;
        const devt = if (s.gbm.devices.items.len > 0) s.gbm.devices.items[0].dev else return null;
        s.dev = vk.Device.open(devt, &s.dev_why) catch |e| {
            if (s.dev_why.len == 0) s.dev_why.set("{t}", .{e});
            return null;
        };
        return &s.dev.?;
    }
};

/// Ties an encoder's shadow to an output's change detector: the encoder calls it before freeing
/// the shadow (Encoder.shadow_release), so the import goes first, and through it brings in the
/// tiles the detector left on the GPU (Encoder.freshener). Shared by the output and the encoders
/// hooked to it; freed by the last. Without the detector (the output is gone) freshening fails
/// and the encoder sends a whole frame.
const ShadowHook = struct {
    gpa: std.mem.Allocator,
    td: ?*tilediff.TileDiff,
    refs: u32 = 1,

    fn onShadowFree(ctx: *anyopaque, e: *const Encoder) void {
        const h: *ShadowHook = @ptrCast(@alignCast(ctx));
        if (h.td) |td| if (td.shadowIs(e.shadow_mem, e.shadow_gen)) td.dropShadow();
        h.unref();
    }

    /// Encoder.Freshener: `tiles` of the last frame processed into the shadow. Only while the
    /// detector's reference is the frame last diffed into this encoder (another encoder on the
    /// output may have moved it on); the tiles go straight into the shadow only when the import
    /// is this encoder's.
    fn freshen(ctx: *anyopaque, e: *Encoder, tiles: []const u32) bool {
        const h: *ShadowHook = @ptrCast(@alignCast(ctx));
        const td = h.td orelse return false;
        if (e.gpu_token == 0 or e.gpu_token != td.token) return false;
        if (td.width != e.width or td.height != e.height) return false;
        const res = td.freshenTiles(tiles, td.shadowIs(e.shadow_mem, e.shadow_gen)) catch return false;
        if (!res.in_shadow) {
            const tx_n = td.tiles_x;
            for (tiles) |t| {
                const x0 = (t % tx_n) * tilediff.tile;
                const y0 = (t / tx_n) * tilediff.tile;
                const len = @as(usize, @min(tilediff.tile, e.width - x0)) * 4;
                for (y0..@min(e.height, y0 + tilediff.tile)) |y| {
                    const o = y * res.stride + @as(usize, x0) * 4;
                    @memcpy(e.shadow[o..][0..len], res.pixels[o..][0..len]);
                }
            }
        }
        td.freshened += tiles.len;
        td.fresh_passes += 1;
        return true;
    }

    fn unref(h: *ShadowHook) void {
        h.refs -= 1;
        if (h.refs == 0) h.gpa.destroy(h);
    }
};

/// Per captured output (its own ring, reference frame and encoder).
pub const Output = struct {
    shared: *Shared,
    /// The output's name for the log ("RDP-1: ..."), `setName`.
    name_buf: [24]u8 = undefined,
    name_len: usize = 0,
    td: ?*tilediff.TileDiff = null,
    hook: ?*ShadowHook = null,
    /// Given up: this output's capture is on shm.
    off: bool = false,
    empty_frames: u8 = 0,
    busy_frames: u8 = 0,
    /// Frames diffed on the GPU, and of those the full copies (no reference).
    frames: u64 = 0,
    full_frames: u64 = 0,
    /// Changed tiles left on the GPU (lazy readback), summed.
    lazy_tiles: u64 = 0,
    skip_flags: std.ArrayList(bool) = .empty,
    /// Wall time in diff before the GPU run, in it, and after it (summed).
    pre_ns: u64 = 0,
    run_ns: u64 = 0,
    post_ns: u64 = 0,
    /// The H.264 encoder's input surfaces written from the reference frame (`writeH264Input`): a
    /// converter per kind, the surfaces imported (of VA-API encoder `h264_instance`: AVC420's one,
    /// AVC444's main and auxiliary views), the encoder it cannot be done for, and the block mask.
    converters: [2]?*nv12.Converter = .{ null, null },
    h264_targets: [2]nv12.Target = .{ .{}, .{} },
    h264_instance: u64 = 0,
    h264_failed: u64 = 0,
    h264_logged: bool = false,
    blocks: std.ArrayList(bool) = .empty,
    /// Pictures written, and their wall time (summed).
    h264_writes: u64 = 0,
    h264_ns: u64 = 0,

    pub fn init(shared: *Shared) Output {
        return .{ .shared = shared };
    }

    pub fn setName(o: *Output, text: []const u8) void {
        o.name_len = @min(text.len, o.name_buf.len);
        @memcpy(o.name_buf[0..o.name_len], text[0..o.name_len]);
    }

    /// "NAME: " for the log, or nothing.
    fn prefix(o: *const Output, buf: *[32]u8) []const u8 {
        if (o.name_len == 0) return "";
        return std.fmt.bufPrint(buf, "{s}: ", .{o.name_buf[0..o.name_len]}) catch "";
    }

    pub fn deinit(o: *Output) void {
        if (o.hook) |h| {
            // Encoders still hooked find no detector and only drop their reference.
            h.td = null;
            h.unref();
        }
        o.hook = null;
        if (o.td) |t| t.destroy(o.shared.gpa);
        o.td = null;
        o.skip_flags.deinit(o.shared.gpa);
        if (o.shared.dev) |*d| {
            for (&o.converters) |*cv| if (cv.*) |x| x.destroy(o.shared.gpa);
            for (&o.h264_targets) |*t| t.destroy(d);
        }
        o.converters = .{ null, null };
        o.blocks.deinit(o.shared.gpa);
    }

    /// Writes the input surfaces of `va` on the GPU from the frame last diffed into `enc`: AVC420's
    /// NV12 picture, or AVC444 v2's main and auxiliary views (both, whatever the frame codes, so
    /// they always hold the same picture). Only the 16x16 blocks under `rects`, as h264Source
    /// copies the shadow's, or all when null. False when it cannot (that frame is no longer the
    /// reference, VA-API encodes on another GPU, its surfaces do not import here): the caller
    /// codes from the shadow.
    pub fn writeH264Input(o: *Output, va: *vaapi_h264.Encoder, enc: anytype, rects: ?[]const gfx.Rect16) bool {
        const td = o.td orelse return false;
        if (o.off or enc.gpu_token == 0 or enc.gpu_token != td.token or va.instance == o.h264_failed) return false;
        const ref = td.reference() orelse return false;
        if (ref.width != enc.width or ref.height != enc.height) return false;
        const dev = o.shared.device() orelse return false;
        const kind: nv12.Kind = if (va.opts.avc444) |v| switch (v) {
            .v2 => .avc444v2,
            .v1 => return false,
        } else .avc420;
        const t0 = nowNs();
        var why: vk.Why = .{};
        o.prepareH264(dev, va, kind, &why) catch |e| {
            o.h264_failed = va.instance;
            if (!o.h264_logged) log.info("H.264 input from the CPU: {s}", .{switch (e) {
                error.Unsupported => if (why.len > 0) why.text() else "this Vulkan device cannot write the encoder's NV12 surfaces",
                error.WrongDevice => "VA-API encodes on another GPU",
                else => @errorName(e),
            }});
            o.h264_logged = true;
            return false;
        };
        const cv = o.converters[@backingInt(kind)].?;
        const ts = [2]*nv12.Target{ &o.h264_targets[0], &o.h264_targets[1] };
        const targets = ts[0..cv.targets()];
        var mask: ?[]const bool = null;
        if (rects) |rs| if (targets[targets.len - 1].written and targets[0].written) {
            const n = @as(usize, (enc.width + nv12.block - 1) / nv12.block) * ((enc.height + nv12.block - 1) / nv12.block);
            o.blocks.resize(o.shared.gpa, n) catch return false;
            nv12.blocksFor(rs, enc.width, enc.height, o.blocks.items);
            // Nothing new (a refinement, chroma owed): the surfaces hold the picture already.
            if (std.mem.indexOfScalar(bool, o.blocks.items, true) == null) return true;
            mask = o.blocks.items;
        };
        cv.run(.{ .buffer = ref.buffer, .offset = ref.offset, .stride = ref.stride, .width = ref.width, .height = ref.height, .foreign = ref.foreign }, targets, mask) catch |e| {
            log.warn("H.264 input from the CPU from now on: writing it on the GPU failed ({t})", .{e});
            o.h264_logged = true;
            o.h264_failed = va.instance;
            for (targets) |t| t.written = false;
            return false;
        };
        o.h264_writes += 1;
        o.h264_ns += nowNs() - t0;
        return true;
    }

    /// Whether `writeH264Input` may work for `va` (not known to fail).
    pub fn h264Possible(o: *const Output, va: *const vaapi_h264.Encoder) bool {
        if (va.opts.avc444) |v| if (v != .v2) return false;
        return !o.off and o.td != null and va.instance != o.h264_failed;
    }

    /// The converter, and `va`'s input surfaces imported (once per encoder); `why` says why not.
    fn prepareH264(o: *Output, dev: *vk.Device, va: *vaapi_h264.Encoder, kind: nv12.Kind, why: *vk.Why) !void {
        const cv = &o.converters[@backingInt(kind)];
        if (cv.* == null) cv.* = try nv12.Converter.create(o.shared.gpa, dev, kind);
        if (o.h264_instance == va.instance and o.h264_targets[0].image != null) return;
        for (&o.h264_targets) |*t| t.destroy(dev);
        o.h264_instance = 0;
        const node = va.drmDevice() orelse return error.WrongDevice;
        if (!dev.hasNode(node)) return error.WrongDevice;
        const views: []const vaapi_h264.Encoder.View = if (kind == .avc420) &.{.main} else &.{ .main, .aux };
        for (views, 0..) |v, i| {
            const in = try va.exportInput(v);
            defer _ = std.c.close(in.fd);
            o.h264_targets[i] = try nv12.Target.import(dev, .{ .fd = in.fd, .size = in.size, .modifier = in.modifier, .width = in.width, .height = in.height, .offsets = in.offsets, .pitches = in.pitches }, why);
        }
        o.h264_instance = va.instance;
    }

    /// The tiles to leave on the GPU: all changed ones (an H.264 motion frame), those wholly inside
    /// the video region, or none.
    fn skipFor(o: *Output, hint: Hint, enc: anytype) !tilediff.Skip {
        switch (hint) {
            .none => return .none,
            .all => return .all,
            .region => |r| {
                const tx_n = (enc.width + tilediff.tile - 1) / tilediff.tile;
                const ty_n = (enc.height + tilediff.tile - 1) / tilediff.tile;
                try o.skip_flags.resize(o.shared.gpa, @as(usize, tx_n) * ty_n);
                var any = false;
                for (0..ty_n) |ty| for (0..tx_n) |tx| {
                    const x0: u32 = @intCast(tx * tilediff.tile);
                    const y0: u32 = @intCast(ty * tilediff.tile);
                    const x1 = @min(enc.width, x0 + tilediff.tile);
                    const y1 = @min(enc.height, y0 + tilediff.tile);
                    const inside = x0 >= r.left and y0 >= r.top and x1 <= r.right and y1 <= r.bottom;
                    o.skip_flags.items[ty * tx_n + tx] = inside;
                    any = any or inside;
                };
                return if (any) .{ .some = o.skip_flags.items } else .none;
            },
        }
    }

    /// The encoder lets this output's detector release the shadow import before freeing it, and
    /// bring lagging tiles in.
    fn hookEncoder(o: *Output, enc: anytype) !void {
        if (o.hook == null) {
            const h = try o.shared.gpa.create(ShadowHook);
            h.* = .{ .gpa = o.shared.gpa, .td = o.td };
            o.hook = h;
        }
        const h = o.hook.?;
        if (enc.shadow_release) |r| {
            if (r.ctx == @as(*anyopaque, h)) {
                enc.freshener = .{ .ctx = h, .func = ShadowHook.freshen };
                return;
            }
            // Another output's detector imported this shadow: its lagging tiles come in, then it
            // lets go.
            try enc.freshenAll();
            enc.freshener = null;
            enc.shadow_release = null;
            r.func(r.ctx, enc);
        }
        h.refs += 1;
        enc.shadow_release = .{ .ctx = h, .func = ShadowHook.onShadowFree };
        enc.freshener = .{ .ctx = h, .func = ShadowHook.freshen };
    }

    fn unwritten(o: *const Output, px: []const u8, stride: usize, w: u32, h: u32) bool {
        return unwrittenPixels(o.shared.gbm.marked, px, stride, w, h);
    }

    /// GPU capture off for this output: its capture goes to shm (logged once). The tiles `enc`
    /// left on the GPU come in first, while the reference frame is there (else the client gets
    /// a whole frame).
    pub fn fallBack(o: *Output, cap: anytype, enc: anytype, comptime fmt: []const u8, args: anytype) void {
        enc.freshenAll() catch enc.invalidate();
        var pb: [32]u8 = undefined;
        if (!o.off) log.warn("{s}GPU capture off, using shm: " ++ fmt, .{o.prefix(&pb)} ++ args);
        o.off = true;
        cap.unpin();
        cap.useShm();
        if (o.td) |t| t.forget();
    }

    /// Change detection for dmabuf frame `f` of `cap` (a *wl.Capture) into `enc` (the output's
    /// surface encoder, a *server.encoder.Encoder): returns what its diff returns, or null when the frame cannot
    /// go this way (the capture is switched to shm; skip the frame and request the next).
    /// `hint`: changed tiles likely coded with H.264 from the GPU, left there (lazy readback; the
    /// encoder marks them stale and brings them in when something reads them).
    pub fn diff(o: *Output, cap: anytype, enc: anytype, f: *const wl.Frame, hint: Hint) !?usize {
        const bo = f.dmabuf orelse return null;
        if (f.transform != .normal or f.y_invert) {
            o.fallBack(cap, enc, "the output is rotated or flipped ({d})", .{@backingInt(f.transform)});
            return null;
        }
        if (f.format != .xrgb8888 and f.format != .argb8888) {
            o.fallBack(cap, enc, "format {t}", .{f.format});
            return null;
        }
        const dev = o.shared.device() orelse {
            var drv: [64]u8 = undefined;
            const devt = if (o.shared.gbm.devices.items.len > 0) o.shared.gbm.devices.items[0].dev else 0;
            o.fallBack(cap, enc, "no Vulkan compute for {s} ({s}): {s}", .{ o.shared.gbm.node(), gbm.driverName(devt, &drv), o.shared.dev_why.text() });
            return null;
        };
        if (o.td == null) o.td = tilediff.TileDiff.create(o.shared.gpa, dev) catch |e| {
            o.fallBack(cap, enc, "compute pipeline ({t})", .{e});
            return null;
        };
        const td = o.td.?;
        const t0 = nowNs();
        // The reference is the shadow only if this detector wrote it last.
        const stale_ref = !enc.valid or enc.gpu_token == 0 or enc.gpu_token != td.token;
        // A full diff compares the frame with the shadow: tiles left on the GPU come in first,
        // from the reference while there is one (else the encoder is invalidated: a whole frame).
        if (enc.hasStale() and (stale_ref or td.reference() == null)) try enc.freshenAll();
        const full = stale_ref or !enc.valid;
        // Changed tiles straight into the shadow when it imports; room for the runs first, so
        // nothing fails once the GPU has written it.
        var target: tilediff.Target = .staging;
        if (!full) {
            try enc.reserveDiff();
            try o.hookEncoder(enc);
            if (td.useShadow(enc.shadow_mem, enc.shadow_gen)) target = .shadow;
        }
        const t1 = nowNs();
        // Skipping needs the shadow imported (else every tile goes through staging anyway).
        const skip: tilediff.Skip = if (target != .shadow) .none else try o.skipFor(hint, enc);
        const res = td.runDmabuf(bo, f.ring, full, target, skip) catch |e| {
            if (e == error.Busy and o.busy_frames < max_busy_frames) {
                // The compositor is slow to render into it (nothing was submitted): the next frame.
                o.busy_frames += 1;
                return null;
            }
            // The GPU may have written part of the shadow: the client gets a whole frame next.
            if (target == .shadow) enc.invalidate();
            o.fallBack(cap, enc, "{t}", .{e});
            return null;
        };
        o.busy_frames = 0;
        const t2 = nowNs();
        defer {
            const t3 = nowNs();
            o.pre_ns += t1 - t0;
            o.run_ns += t2 - t1;
            o.post_ns += t3 - t2;
        }
        if (res.full and o.unwritten(res.pixels, res.stride, enc.width, enc.height)) {
            td.forget();
            cap.unpin();
            o.empty_frames += 1;
            if (o.empty_frames >= 3) o.fallBack(cap, enc, "the compositor leaves the dmabufs empty", .{});
            return null;
        }
        o.empty_frames = 0;
        // The run lost its reference (a new ring) after the stale tiles were left in place.
        if (res.full and !full and enc.hasStale()) enc.invalidate();
        const n = (if (res.full) enc.diff(res.pixels, res.stride) else if (res.in_shadow) enc.applyTileDiffInShadow(res.boxes) else enc.applyTileDiff(res.boxes, res.pixels, res.stride)) catch |e| {
            td.forget();
            enc.gpu_token = 0;
            cap.unpin();
            return e;
        };
        if (!res.full and res.in_shadow and skip != .none) {
            // Changed tiles left on the GPU now lag in the shadow.
            var lagging: usize = 0;
            for (res.boxes, 0..) |b, i| {
                if (b[2] == 0) continue;
                const skipped = switch (skip) {
                    .none => false,
                    .all => true,
                    .some => |flags| flags[i],
                };
                if (!skipped) continue;
                enc.markStale(i);
                lagging += 1;
            }
            o.lazy_tiles += lagging;
        }
        const t = next_token.fetchAdd(1, .monotonic);
        td.token = t;
        enc.gpu_token = t;
        if (!cap.pin(f.slot)) td.forget();
        if (o.frames == 0) {
            var drv: [64]u8 = undefined;
            const devt = if (o.shared.gbm.devices.items.len > 0) o.shared.gbm.devices.items[0].dev else 0;
            var mod_buf: [24]u8 = undefined;
            const modifier = if (bo.modifier == 0) "LINEAR" else std.fmt.bufPrint(&mod_buf, "0x{x}", .{bo.modifier}) catch "?";
            var pb: [32]u8 = undefined;
            log.info("{s}GPU capture: {d}x{d} dmabufs {s} {s} from {s} ({s}), diffed with Vulkan on {s}", .{
                o.prefix(&pb), bo.width, bo.height, std.mem.asBytes(&bo.format), modifier, o.shared.gbm.node(), gbm.driverName(devt, &drv), dev.name(),
            });
        }
        o.frames += 1;
        if (res.full) o.full_frames += 1;
        return n;
    }
};

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// A frame still holding what the allocator wrote (gbm.unfilled): the compositor never filled the
/// buffer. Without that mark, all zeros (Hyprland writes 0xff into X; a black screen of another
/// compositor would pass for empty then).
fn unwrittenPixels(marked: bool, px: []const u8, stride: usize, w: u32, h: u32) bool {
    if (!marked) return allZero(px);
    for (0..h) |y| {
        const row = std.mem.bytesAsSlice(u32, @as([]align(1) const u8, px[y * stride ..][0 .. @as(usize, w) * 4]));
        for (row, 0..) |v, x| if (v & 0xFFFFFF != gbm.unfilled(@intCast(x), @intCast(y))) return false;
    }
    return true;
}

fn allZero(px: []const u8) bool {
    const words = std.mem.bytesAsSlice(u64, px[0 .. px.len / 8 * 8]);
    for (words) |w| if (w != 0) return false;
    return true;
}

/// Changed tiles likely coded with H.264 from the GPU this frame (left there: lazy readback).
pub const Hint = union(enum) {
    none,
    all,
    /// The video region: tiles wholly inside it.
    region: struct { left: u32, top: u32, right: u32, bottom: u32 },
};

/// A dmabuf frame's way to the GPU path: its output's state and capture.
pub const Handle = struct {
    out: *Output,
    cap: *wl.Capture,
};

// Equivalence with Encoder.diff: two encoders fed the same frames, one through diff, the other
// the way GPU capture feeds it (full frames through diff, the rest through applyTileDiff).

const Encoder = @import("../server/encoder.zig").Encoder;

fn expectSameEncoder(a: *const Encoder, b: *const Encoder) !void {
    try std.testing.expectEqual(a.valid, b.valid);
    try std.testing.expectEqualSlices(gfx.Rect16, a.rects.items, b.rects.items);
    try std.testing.expectEqualSlices(gfx.Rect16, a.tight.items, b.tight.items);
    try std.testing.expect(std.mem.eql(u8, a.shadow, b.shadow));
}

const test_sizes = [_][2]u32{ .{ 1920, 1080 }, .{ 1001, 777 }, .{ 64, 64 }, .{ 65, 1 }, .{ 130, 70 }, .{ 2, 2 } };

test "applyTileDiff with the tile boxes equals Encoder.diff" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xd1ff);
    const rand = prng.random();
    for (test_sizes) |size| {
        const w = size[0];
        const h = size[1];
        const stride = @as(usize, w) * 4;
        var a = Encoder.init(gpa);
        defer a.deinit();
        var b = Encoder.init(gpa);
        defer b.deinit();
        try a.reset(w, h);
        try b.reset(w, h);
        const frame = try gpa.alloc(u8, stride * h);
        defer gpa.free(frame);
        const prev = try gpa.alloc(u8, stride * h);
        defer gpa.free(prev);
        const boxes = try gpa.alloc(tilediff.TileBox, @as(usize, (w + 63) / 64) * ((h + 63) / 64));
        defer gpa.free(boxes);
        rand.bytes(frame);
        for (0..14) |k| {
            if (k > 0) tilediff.mutate(rand, frame, w, h);
            if (k == 6) {
                a.invalidate();
                b.invalidate();
            }
            if (k == 9) @memcpy(frame, prev); // unchanged
            const na = try a.diff(frame, stride);
            const nb = if (!b.valid) try b.diff(frame, stride) else blk: {
                tilediff.tileBoxesCpu(frame, prev, w, h, boxes);
                break :blk try b.applyTileDiff(boxes, frame, stride);
            };
            try std.testing.expectEqual(na, nb);
            try expectSameEncoder(&a, &b);
            @memcpy(prev, frame);
        }
    }
}

test "GPU change detection equals Encoder.diff" {
    try gpuEquivalence(false);
}

test "GPU change detection into the imported shadow equals Encoder.diff" {
    try gpuEquivalence(true);
}

fn gpuEquivalence(into_shadow: bool) !void {
    const gpa = std.testing.allocator;
    var dev = try tilediff.testDevice();
    defer dev.deinit();
    if (into_shadow and dev.get_host_pointer_properties == null) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x6b0);
    const rand = prng.random();
    for (test_sizes ++ [_][2]u32{.{ 3840, 2160 }}) |size| {
        const w = size[0];
        const h = size[1];
        const stride = @as(usize, w) * 4;
        var a = Encoder.init(gpa);
        defer a.deinit();
        var b = Encoder.init(gpa);
        defer b.deinit();
        try a.reset(w, h);
        try b.reset(w, h);
        const td = try tilediff.TileDiff.create(gpa, &dev);
        defer td.destroy(gpa);
        const slots = [3]usize{ try td.addHostSlot(w, h), try td.addHostSlot(w, h), try td.addHostSlot(w, h) };
        const frame = try gpa.alloc(u8, stride * h);
        defer gpa.free(frame);
        rand.bytes(frame);
        var fulls: usize = 0;
        for (0..14) |k| {
            if (k > 0) tilediff.mutate(rand, frame, w, h);
            if (k == 6) {
                a.invalidate();
                b.invalidate();
            }
            const s = slots[k % 3];
            @memcpy(td.hostPixels(s), frame);
            const na = try a.diff(frame, stride);
            // As Output.diff: changed tiles into the imported shadow when `into_shadow`.
            var target: tilediff.Target = .staging;
            if (into_shadow and b.valid) {
                try b.reserveDiff();
                if (td.useShadow(b.shadow_mem, b.shadow_gen)) target = .shadow;
            }
            const res = try td.runHost(s, !b.valid, target);
            if (into_shadow and !res.full) try std.testing.expect(res.in_shadow);
            const nb = if (res.full) try b.diff(res.pixels, res.stride) else if (res.in_shadow) b.applyTileDiffInShadow(res.boxes) else try b.applyTileDiff(res.boxes, res.pixels, res.stride);
            if (res.full) fulls += 1;
            try std.testing.expectEqual(na, nb);
            try expectSameEncoder(&a, &b);
        }
        // The first frame and the invalidated one only.
        try std.testing.expectEqual(2, fulls);
    }
}

test "a resized encoder releases its imported shadow first: later submissions still work" {
    const gpa = std.testing.allocator;
    var dev = try tilediff.testDevice();
    defer dev.deinit();
    if (dev.get_host_pointer_properties == null) return error.SkipZigTest;
    const td = try tilediff.TileDiff.create(gpa, &dev);
    defer td.destroy(gpa);
    const other = try tilediff.TileDiff.create(gpa, &dev);
    defer other.destroy(gpa);
    var enc = Encoder.init(gpa);
    defer enc.deinit();
    try enc.reset(1920, 1080);
    // As Output.diff: the shadow imported, the encoder hooked.
    const hook = try gpa.create(ShadowHook);
    hook.* = .{ .gpa = gpa, .td = td };
    defer {
        hook.td = null;
        hook.unref();
    }
    try std.testing.expect(td.useShadow(enc.shadow_mem, enc.shadow_gen));
    hook.refs += 1;
    enc.shadow_release = .{ .ctx = hook, .func = ShadowHook.onShadowFree };
    // A new size frees the old shadow: the import goes first.
    try enc.reset(1280, 720);
    try std.testing.expect(td.shadow == null and enc.shadow_release == null);
    // Both detectors on this device still submit (a stale import would fail every submission).
    for ([_]*tilediff.TileDiff{ td, other }) |t| {
        const s = try t.addHostSlot(1280, 720);
        const res = try t.runHost(s, true, .staging);
        try std.testing.expect(res.full);
    }
    try std.testing.expect(td.useShadow(enc.shadow_mem, enc.shadow_gen));
    td.dropShadow();
}

test "tiles left on the GPU: Encoder.diff's rects every frame, its shadow once brought in" {
    const gpa = std.testing.allocator;
    var dev = try tilediff.testDevice();
    defer dev.deinit();
    if (dev.get_host_pointer_properties == null) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x1a27);
    const rand = prng.random();
    for ([_][2]u32{ .{ 1920, 1080 }, .{ 1001, 777 }, .{ 130, 70 } }) |size| {
        const w = size[0];
        const h = size[1];
        const stride = @as(usize, w) * 4;
        var a = Encoder.init(gpa);
        defer a.deinit();
        var b = Encoder.init(gpa);
        defer b.deinit();
        try a.reset(w, h);
        try b.reset(w, h);
        const td = try tilediff.TileDiff.create(gpa, &dev);
        defer td.destroy(gpa);
        const hook = try gpa.create(ShadowHook);
        hook.* = .{ .gpa = gpa, .td = td };
        defer {
            hook.td = null;
            hook.unref();
        }
        const slots = [3]usize{ try td.addHostSlot(w, h), try td.addHostSlot(w, h), try td.addHostSlot(w, h) };
        const tiles = @as(usize, (w + 63) / 64) * ((h + 63) / 64);
        const flags = try gpa.alloc(bool, tiles);
        defer gpa.free(flags);
        const frame = try gpa.alloc(u8, stride * h);
        defer gpa.free(frame);
        rand.bytes(frame);
        var stale_seen: usize = 0;
        for (0..16) |k| {
            if (k > 0) tilediff.mutate(rand, frame, w, h);
            const s = slots[k % 3];
            @memcpy(td.hostPixels(s), frame);
            const na = try a.diff(frame, stride);
            var target: tilediff.Target = .staging;
            if (b.valid) {
                try b.reserveDiff();
                if (td.useShadow(b.shadow_mem, b.shadow_gen)) {
                    target = .shadow;
                    if (b.shadow_release == null) {
                        hook.refs += 1;
                        b.shadow_release = .{ .ctx = hook, .func = ShadowHook.onShadowFree };
                    }
                    b.freshener = .{ .ctx = hook, .func = ShadowHook.freshen };
                }
            }
            for (flags) |*f| f.* = rand.boolean();
            const skip: tilediff.Skip = if (target != .shadow) .none else if (k % 4 == 1) .all else .{ .some = flags };
            const res = try td.runHostSkip(s, !b.valid, target, skip);
            td.token = 1 + k;
            b.gpu_token = td.token;
            const nb = if (res.full) try b.diff(res.pixels, res.stride) else b.applyTileDiffInShadow(res.boxes);
            if (!res.full) for (res.boxes, 0..) |bx, i| {
                if (bx[2] == 0) continue;
                const skipped = switch (skip) {
                    .none => false,
                    .all => true,
                    .some => |fl| fl[i],
                };
                if (skipped) b.markStale(i);
            };
            try std.testing.expectEqual(na, nb);
            try std.testing.expectEqualSlices(gfx.Rect16, a.rects.items, b.rects.items);
            try std.testing.expectEqualSlices(gfx.Rect16, a.tight.items, b.tight.items);
            stale_seen += b.stale.count();
            // A reader brings part of it in, as the codecs do.
            if (b.rects.items.len > 0) try b.freshen(b.rects.items[0..1]);
            if (k % 5 == 4) {
                try b.freshenAll();
                try std.testing.expect(std.mem.eql(u8, a.shadow, b.shadow));
            }
        }
        try b.freshenAll();
        try std.testing.expect(std.mem.eql(u8, a.shadow, b.shadow));
        try std.testing.expect(stale_seen > 0);
        td.dropShadow();
    }
}

test "H.264 input written from the reference frame keeps h264Source's picture: masks, refinements, a new encoder, AVC420 then AVC444" {
    const gpa = std.testing.allocator;
    const avc444 = @import("../codec/avc444.zig");
    const shared = try Shared.create(gpa);
    defer shared.destroy();
    shared.dev = try tilediff.testDevice();
    shared.dev_tried = true;
    if (!shared.dev.?.modifier_images) return error.SkipZigTest;
    // One output, its encoder's codec switching as a connection's can.
    var o = Output.init(shared);
    defer o.deinit();
    var prng = std.Random.DefaultPrng.init(0x4230);
    const rand = prng.random();
    const Case = struct { avc444: bool, w: u32, h: u32 };
    var writes: u64 = 0;
    for ([_]Case{ .{ .avc444 = false, .w = 1280, .h = 720 }, .{ .avc444 = true, .w = 1000, .h = 700 } }) |case| {
        const w = case.w;
        const h = case.h;
        const stride = @as(usize, w) * 4;
        const opts: vaapi_h264.Options = .{ .width = w, .height = h, .rate_control = .cqp, .avc444 = if (case.avc444) .v2 else null };
        var va = vaapi_h264.Encoder.init(gpa, opts) catch return error.SkipZigTest;
        defer va.deinit();
        var e = Encoder.init(gpa);
        defer e.deinit();
        try e.reset(w, h);
        if (o.td) |t| t.destroy(gpa);
        o.td = try tilediff.TileDiff.create(gpa, &shared.dev.?);
        const td = o.td.?;
        const slots = [3]usize{ try td.addHostSlot(w, h), try td.addHostSlot(w, h), try td.addHostSlot(w, h) };
        const vs: avc444.ViewSize = if (case.avc444) try avc444.viewSize(.v2, w, h) else .{ .width = w, .height = h };
        const views: usize = if (case.avc444) 2 else 1;
        const frame = try gpa.alloc(u8, stride * h);
        defer gpa.free(frame);
        rand.bytes(frame);
        // h264Source's picture, built on the CPU as it builds it.
        const src = try gpa.alloc(u8, stride * h);
        defer gpa.free(src);
        var bufs: [2][4][]u8 = undefined;
        for (&bufs) |*b| for (b, [4]usize{ vs.width * vs.height, vs.width * vs.height / 2, vs.width * vs.height, vs.width * vs.height / 2 }) |*x, len| {
            x.* = try gpa.alloc(u8, len);
        };
        defer for (&bufs) |*b| for (b) |x| gpa.free(x);
        const scratch = try gpa.alloc(u8, avc444.nv12ScratchLen(w));
        defer gpa.free(scratch);
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        var aux_out: std.ArrayList(u8) = .empty;
        defer aux_out.deinit(gpa);
        var src_ok = false;
        for (0..12) |k| {
            if (k > 0) tilediff.mutate(rand, frame, w, h);
            const s = slots[k % 3];
            @memcpy(td.hostPixels(s), frame);
            _ = try td.runHost(s, k == 0, .staging);
            _ = try e.diff(frame, stride);
            td.token = 100 + k;
            e.gpu_token = td.token;
            if (k == 6) {
                // A new encoder (a resize, a codec restart): its surfaces are imported and written whole.
                va.deinit();
                va = try vaapi_h264.Encoder.init(gpa, opts);
                src_ok = false;
            }
            // Every third frame codes nothing new (a refinement, chroma owed): the surfaces are left as they are.
            const rects: []const gfx.Rect16 = if (k % 3 == 2) &.{} else e.rects.items;
            try std.testing.expect(o.writeH264Input(&va, &e, if (src_ok) rects else null));
            if (!src_ok) {
                @memcpy(src, frame);
            } else for (rects) |r| {
                const x0: usize = r.left & ~@as(u16, 15);
                const x1: usize = @min(w, (@as(u32, r.right) + 15) & ~@as(u32, 15));
                const y1: usize = @min(h, (@as(u32, r.bottom) + 15) & ~@as(u32, 15));
                var yy: usize = r.top & ~@as(u16, 15);
                while (yy < y1) : (yy += 1) @memcpy(src[yy * stride + x0 * 4 ..][0 .. (x1 - x0) * 4], frame[yy * stride + x0 * 4 ..][0 .. (x1 - x0) * 4]);
            }
            src_ok = true;
            out.clearRetainingCapacity();
            aux_out.clearRetainingCapacity();
            if (case.avc444) {
                // Luma alone, both, chroma alone: whatever is coded, both views hold the picture.
                const lc: avc444.Lc = switch (k % 3) {
                    0 => .luma,
                    1 => .both,
                    else => .chroma,
                };
                _ = try va.encode444Written(k == 0, lc, &out, &aux_out);
                try std.testing.expect(out.items.len + aux_out.items.len > 0);
                try avc444.toNv12(.v2, src, stride, w, h, .{ .y = bufs[0][0], .y_pitch = vs.width, .uv = bufs[0][1], .uv_pitch = vs.width }, .{ .y = bufs[1][0], .y_pitch = vs.width, .uv = bufs[1][1], .uv_pitch = vs.width }, scratch);
            } else {
                const info = try va.encodeWritten(k == 0, &out);
                try std.testing.expect(info.size > 0);
                _ = try nv12.referenceNv12(gpa, src, w, h, vs.width, bufs[0][0], bufs[0][1]);
            }
            for (0..views) |i| {
                try va.readInput(if (i == 0) .main else .aux, vs.width, vs.height, bufs[i][2], bufs[i][3]);
                try std.testing.expectEqualSlices(u8, bufs[i][0], bufs[i][2]);
                try std.testing.expectEqualSlices(u8, bufs[i][1], bufs[i][3]);
            }
        }
        // A frame the detector did not diff into this encoder is no source.
        e.gpu_token = 1;
        try std.testing.expect(!o.writeH264Input(&va, &e, null));
        // Refinements wrote nothing.
        writes += 8;
        try std.testing.expectEqual(writes, o.h264_writes);
    }
}

/// Output.diff's view of a capture (tests): pins, falls back, no compositor.
const TestCapture = struct {
    pinned: ?u8 = null,
    shm: bool = false,

    pub fn pin(t: *TestCapture, slot: u8) bool {
        t.pinned = slot;
        return true;
    }

    pub fn unpin(t: *TestCapture) void {
        t.pinned = null;
    }

    pub fn useShm(t: *TestCapture) void {
        t.shm = true;
    }
};

/// LINEAR XRGB dmabufs from the shared allocator, filled as a compositor would (tests; skip
/// without GBM or a render node).
const TestRing = struct {
    shared: *Shared,
    bos: [3]wl.dmabuf.Bo = undefined,
    w: u32,
    h: u32,

    fn init(shared: *Shared, w: u32, h: u32) !TestRing {
        const cc = @import("c");
        var st: cc.struct_stat = undefined;
        if (cc.stat("/dev/dri/renderD128", &st) != 0) return error.SkipZigTest;
        var r: TestRing = .{ .shared = shared, .w = w, .h = h };
        for (&r.bos, 0..) |*bo, i| bo.* = shared.alloc.allocFn(shared.alloc.ctx, @intCast(st.st_rdev), w, h, wl.dmabuf.format_xrgb8888, &.{wl.dmabuf.mod_linear}) catch {
            for (r.bos[0..i]) |*b| shared.alloc.freeFn(shared.alloc.ctx, b);
            return error.SkipZigTest;
        };
        return r;
    }

    fn deinit(r: *TestRing) void {
        for (&r.bos) |*bo| r.shared.alloc.freeFn(r.shared.alloc.ctx, bo);
    }

    /// Slot `slot` as delivered by a compositor that never wrote it.
    fn unwritten(r: *TestRing, slot: u8, seq: u64) wl.Frame {
        const bo = &r.bos[slot];
        return .{ .data = &.{}, .dmabuf = bo, .width = r.w, .height = r.h, .stride = bo.planes[0].stride, .format = .xrgb8888, .transform = .normal, .y_invert = false, .damage = &.{}, .presented_ns = 0, .latency_ns = 0, .seq = seq, .slot = slot, .ring = 1 };
    }

    /// Slot `slot` filled with `px` (w * 4 bytes a row), as the frame the compositor delivers.
    fn frame(r: *TestRing, slot: u8, px: []const u8, seq: u64) !wl.Frame {
        const bo = &r.bos[slot];
        const m = gbm.mapWrite(bo) orelse return error.SkipZigTest;
        for (0..r.h) |y| @memcpy(m.data[y * m.stride ..][0 .. r.w * 4], px[y * r.w * 4 ..][0 .. r.w * 4]);
        gbm.unmap(bo, m.token);
        try std.testing.expect(gbm.waitIdle(bo, 1000));
        return .{ .data = &.{}, .dmabuf = bo, .width = r.w, .height = r.h, .stride = bo.planes[0].stride, .format = .xrgb8888, .transform = .normal, .y_invert = false, .damage = &.{}, .presented_ns = 0, .latency_ns = 0, .seq = seq, .slot = slot, .ring = 1 };
    }
};

test "a full GPU diff compares with the tiles left on the GPU, not with the shadow lagging behind" {
    const gpa = std.testing.allocator;
    const w: u32 = 256;
    const h: u32 = 128;
    // The reference is lost (as after an empty frame), or another detector diffed in between.
    for ([_]bool{ false, true }) |forget| {
        const shared = try Shared.create(gpa);
        defer shared.destroy();
        shared.dev = try tilediff.testDevice();
        shared.dev_tried = true;
        if (shared.dev.?.get_host_pointer_properties == null) return error.SkipZigTest;
        var ring = try TestRing.init(shared, w, h);
        defer ring.deinit();
        var o = Output.init(shared);
        defer o.deinit();
        var enc = Encoder.init(gpa);
        defer enc.deinit();
        try enc.reset(w, h);
        var cap: TestCapture = .{};
        const a = try gpa.alloc(u8, @as(usize, w) * h * 4);
        defer gpa.free(a);
        @memset(a, 0x40);
        const b = try gpa.dupe(u8, a);
        defer gpa.free(b);
        for (0..64) |y| @memset(b[y * w * 4 ..][0 .. 64 * 4], 0x80);
        var f = try ring.frame(0, a, 0);
        _ = (try o.diff(&cap, &enc, &f, .none)).?;
        // Tile 0 changes and H.264 codes it from the GPU: the shadow keeps the old pixels.
        f = try ring.frame(1, b, 1);
        try std.testing.expectEqual(1, (try o.diff(&cap, &enc, &f, .all)).?);
        try std.testing.expect(enc.hasStale());
        // Back to what the shadow holds; the client shows B there.
        if (forget) o.td.?.forget() else enc.gpu_token = 0;
        f = try ring.frame(2, a, 2);
        const n = (try o.diff(&cap, &enc, &f, .none)).?;
        try std.testing.expect(n >= 1);
        try std.testing.expect(enc.rects.items[0].left == 0 and enc.rects.items[0].top == 0);
        try std.testing.expect(!enc.hasStale());
        try std.testing.expect(!cap.shm);
    }
}

test "a black screen (X = 0) is a frame; buffers the compositor never writes switch to shm" {
    const gpa = std.testing.allocator;
    const w: u32 = 256;
    const h: u32 = 128;
    for ([_]bool{ true, false }) |written| {
        const shared = try Shared.create(gpa);
        defer shared.destroy();
        shared.dev = try tilediff.testDevice();
        shared.dev_tried = true;
        var ring = try TestRing.init(shared, w, h);
        defer ring.deinit();
        var o = Output.init(shared);
        defer o.deinit();
        var enc = Encoder.init(gpa);
        defer enc.deinit();
        try enc.reset(w, h);
        var cap: TestCapture = .{};
        const black = try gpa.alloc(u8, @as(usize, w) * h * 4);
        defer gpa.free(black);
        @memset(black, 0);
        for (0..4) |k| {
            const slot: u8 = @intCast(k % 3);
            var f = if (written) try ring.frame(slot, black, k) else ring.unwritten(slot, k);
            const n = try o.diff(&cap, &enc, &f, .none);
            if (written) try std.testing.expect(n != null);
        }
        try std.testing.expectEqual(!written, cap.shm);
        try std.testing.expectEqual(!written, o.off);
    }
}
