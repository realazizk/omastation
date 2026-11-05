//! Software H.264 for RDPGFX AVC420 (MS-RDPEGFX 2.2.4.4) through Cisco's OpenH264, for machines
//! without a VA-API H.264 encoder (NVIDIA, virtual machines). The library is loaded at run time,
//! so it stays an optional dependency. Rate control is off: every picture is coded at the
//! caller's QP (`setQp`), as the VA-API encoder's CQP. Screen content mode, one slice per encoder
//! thread, Baseline profile (no reordering, so decoders show every picture at once), full-range
//! BT.709 like the VA-API path, SPS and PPS before every IDR.

const std = @import("std");
const c = @import("c");
const avc444 = @import("avc444.zig");
const workers = @import("workers.zig");

const Allocator = std.mem.Allocator;
const log = std.log.scoped(.h264);

pub const Options = struct {
    width: u32,
    height: u32,
    /// QP of the first pictures (`setQp` changes it).
    qp: u8 = 26,
    fps: u32 = 30,
    /// Encoder threads, one slice each; 0: the logical CPUs, at most `max_threads`.
    threads: u32 = 0,
    /// OpenH264's motion search effort; low is several times faster on screen content.
    complexity: Complexity = .low,
};

pub const Complexity = enum { low, medium, high };

/// OpenH264 encodes on at most four threads (MAX_THREADS_NUM).
pub const max_threads: u32 = 4;
/// OpenH264 refuses pictures over level 5.1's frame size, 36864 macroblocks (4096x2304,
/// 5120x1792, 8192x1152), and codes nothing under 16 px a side.
pub const max_macroblocks: u32 = 36864;
pub const min_side: u32 = 16;

pub const FrameInfo = struct {
    idr: bool,
    /// Bytes appended to `out`.
    size: usize,
    qp: u8,
    /// BGRX to I420, then the encode.
    convert_ns: u64,
    encode_ns: u64,
};

pub const Error = error{
    /// No usable libopenh264 (missing, or another ABI than the one built against).
    Unavailable,
    Unsupported,
    BadInput,
    BadDimension,
    Encoder,
    OutOfMemory,
};

// --- the library -------------------------------------------------------------------------------

const CreateFn = *const fn (?*?*c.ISVCEncoder) callconv(.c) c_int;
const DestroyFn = *const fn (?*c.ISVCEncoder) callconv(.c) void;
const VersionFn = *const fn (?*c.OpenH264Version) callconv(.c) void;

const Api = struct {
    create: CreateFn,
    destroy: DestroyFn,
    version: c.OpenH264Version,
};

/// The soname of the ABI the headers describe (OpenH264 2.6: libopenh264.so.8), then the
/// development link; the version is checked either way.
const sonames = [_][:0]const u8{ "libopenh264.so.8", "libopenh264.so" };

var api: Api = undefined;
/// The size last found too large (logged once per size).
var too_large_logged = std.atomic.Value(u64).init(0);
/// 0 not loaded, 1 loading, 2 loaded, 3 unavailable.
var api_state = std.atomic.Value(u8).init(0);

/// Loads libopenh264 once per process; null when it is missing or of another ABI.
pub fn library() ?*const Api {
    while (true) switch (api_state.load(.acquire)) {
        2 => return &api,
        3 => return null,
        1 => std.Thread.yield() catch {},
        else => {
            if (api_state.cmpxchgStrong(0, 1, .acquire, .acquire) != null) continue;
            const ok = load();
            api_state.store(if (ok) 2 else 3, .release);
            return if (ok) &api else null;
        },
    };
}

/// Loads the first soname that is OpenH264 of our ABI; each one there but unusable is logged
/// with what is wrong with it.
fn load() bool {
    var broken = false;
    for (sonames) |name| {
        switch (open(name)) {
            .missing => {},
            .unloadable => |why| {
                log.warn("{s} does not load: {s}", .{ name, why });
                broken = true;
            },
            .not_openh264 => |sym| {
                log.warn("{s} loads but has no {s}: not an OpenH264 encoder", .{ name, sym });
                broken = true;
            },
            .other_version => |v| {
                log.warn("{s} is OpenH264 {d}.{d}.{d}, built for {d}.{d}", .{ name, v.uMajor, v.uMinor, v.uRevision, c.OPENH264_MAJOR, c.OPENH264_MINOR });
                broken = true;
            },
            .loaded => |a| {
                // Kept open for the life of the process.
                api = a;
                log.info("software H.264: OpenH264 {d}.{d}.{d} ({s})", .{ a.version.uMajor, a.version.uMinor, a.version.uRevision, name });
                return true;
            },
        }
    }
    if (broken) {
        log.warn("no usable libopenh264: no software H.264", .{});
    } else log.info("no libopenh264 ({s}): no software H.264", .{sonames[0]});
    return false;
}

const Opened = union(enum) {
    missing,
    /// dlopen's error (not "No such file").
    unloadable: []const u8,
    /// The entry point it lacks.
    not_openh264: []const u8,
    other_version: c.OpenH264Version,
    loaded: Api,
};

/// dlopens `name`, closed again unless it is OpenH264 of our ABI.
fn open(name: [:0]const u8) Opened {
    const lib = std.c.dlopen(name, .{ .LAZY = true }) orelse {
        const why: []const u8 = if (std.c.dlerror()) |e| std.mem.span(e) else "dlopen failed";
        // glibc: "NAME: cannot open shared object file: No such file or directory".
        if (std.mem.indexOf(u8, why, "No such file or directory") != null) return .missing;
        return .{ .unloadable = why };
    };
    const create = symbol(CreateFn, lib, "WelsCreateSVCEncoder");
    const destroy = symbol(DestroyFn, lib, "WelsDestroySVCEncoder");
    const version = symbol(VersionFn, lib, "WelsGetCodecVersionEx");
    if (create == null or destroy == null or version == null) {
        _ = std.c.dlclose(lib);
        return .{ .not_openh264 = if (create == null) "WelsCreateSVCEncoder" else if (destroy == null) "WelsDestroySVCEncoder" else "WelsGetCodecVersionEx" };
    }
    var v: c.OpenH264Version = .{};
    version.?(&v);
    if (v.uMajor != c.OPENH264_MAJOR or v.uMinor != c.OPENH264_MINOR) {
        _ = std.c.dlclose(lib);
        return .{ .other_version = v };
    }
    return .{ .loaded = .{ .create = create.?, .destroy = destroy.?, .version = v } };
}

fn symbol(comptime T: type, lib: *anyopaque, name: [:0]const u8) ?T {
    return @ptrCast(@alignCast(std.c.dlsym(lib, name) orelse return null));
}

fn trace(_: ?*anyopaque, level: c_int, msg: [*c]const u8) callconv(.c) void {
    const text = std.mem.trimEnd(u8, std.mem.span(msg), "\n");
    if (level <= c.WELS_LOG_ERROR) log.warn("openh264: {s}", .{text}) else log.debug("openh264: {s}", .{text});
}

// --- the encoder -------------------------------------------------------------------------------

pub const Encoder = struct {
    gpa: Allocator,
    opts: Options,
    lib: *const Api,
    enc: *c.ISVCEncoder,
    param: c.SEncParamExt,
    /// The picture coded: the frame rounded up to even sizes (cropped in the SPS).
    pic_width: u32,
    pic_height: u32,
    /// I420 input, `avc444.i420Size`.
    planes: []u8,
    y_pitch: usize,
    uv_pitch: usize,
    plane_height: usize,
    /// Per conversion task: six rows (`avc444.nv12ScratchLen`).
    scratch: []u8,
    scratch_len: usize,
    bs: *c.SFrameBSInfo,
    need_idr: bool = true,
    /// The QP `param` holds (what the encoder codes at).
    coded_qp: u8,
    frames: u64 = 0,

    pub fn init(gpa: Allocator, opts: Options) Error!Encoder {
        const lib = library() orelse return error.Unavailable;
        if (opts.width == 0 or opts.height == 0) return error.BadDimension;
        const pic_width = std.mem.alignForward(u32, opts.width, 2);
        const pic_height = std.mem.alignForward(u32, opts.height, 2);
        const macroblocks = ((pic_width + 15) / 16) * ((pic_height + 15) / 16);
        if (macroblocks > max_macroblocks or @min(pic_width, pic_height) < min_side) {
            // An expected fallback on big desktops: once per size.
            const size = @as(u64, opts.width) << 32 | opts.height;
            if (too_large_logged.swap(size, .monotonic) != size) log.info("software H.264: {d}x{d} is outside what OpenH264 encodes ({d} macroblocks at most, {d} px a side at least)", .{ opts.width, opts.height, max_macroblocks, min_side });
            return error.Unsupported;
        }
        if (opts.qp > 51 or opts.fps == 0) return error.BadInput;
        const ps = avc444.i420Size(opts.width, opts.height) catch return error.BadDimension;
        const y_pitch: usize = ps.width;
        const uv_pitch: usize = ps.width / 2;
        const plane_height: usize = ps.height;

        const planes = try gpa.alloc(u8, y_pitch * plane_height + 2 * uv_pitch * (plane_height / 2));
        errdefer gpa.free(planes);
        const scratch_len = avc444.nv12ScratchLen(opts.width);
        const scratch = try gpa.alloc(u8, scratch_len * workers.max_tasks_cap);
        errdefer gpa.free(scratch);
        const bs = try gpa.create(c.SFrameBSInfo);
        errdefer gpa.destroy(bs);

        var enc: ?*c.ISVCEncoder = null;
        if (lib.create(&enc) != 0 or enc == null) return error.Encoder;
        errdefer lib.destroy(enc);
        const e = enc.?;
        const vt = e.*.*;

        var level: c_int = c.WELS_LOG_ERROR;
        _ = vt.SetOption.?(e, c.ENCODER_OPTION_TRACE_LEVEL, &level);
        var cb: c.WelsTraceCallback = &trace;
        _ = vt.SetOption.?(e, c.ENCODER_OPTION_TRACE_CALLBACK, @ptrCast(&cb));

        var p: c.SEncParamExt = std.mem.zeroes(c.SEncParamExt);
        if (vt.GetDefaultParams.?(e, &p) != 0) return error.Encoder;
        const n_threads = threadCount(opts, pic_height);
        p.iUsageType = c.SCREEN_CONTENT_REAL_TIME;
        p.iPicWidth = @intCast(pic_width);
        p.iPicHeight = @intCast(pic_height);
        p.iRCMode = c.RC_OFF_MODE;
        // Unused with rate control off, but validated.
        p.iTargetBitrate = 30_000_000;
        p.iMaxBitrate = c.UNSPECIFIED_BIT_RATE;
        p.fMaxFrameRate = @floatFromInt(@min(opts.fps, 60));
        p.iTemporalLayerNum = 1;
        p.iSpatialLayerNum = 1;
        p.iComplexityMode = switch (opts.complexity) {
            .low => c.LOW_COMPLEXITY,
            .medium => c.MEDIUM_COMPLEXITY,
            .high => c.HIGH_COMPLEXITY,
        };
        p.uiIntraPeriod = 0;
        p.eSpsPpsIdStrategy = c.CONSTANT_ID;
        p.bPrefixNalAddingCtrl = false;
        p.bEnableSSEI = false;
        p.iPaddingFlag = 0;
        p.iEntropyCodingModeFlag = 0;
        p.bEnableFrameSkip = false;
        p.bEnableLongTermReference = false;
        p.iMultipleThreadIdc = @intCast(n_threads);
        p.bUseLoadBalancing = false;
        p.iLoopFilterDisableIdc = 0;
        p.bEnableDenoise = false;
        // Off: a still frame coded again at a better QP must refine what the client shows.
        p.bEnableBackgroundDetection = false;
        p.bEnableAdaptiveQuant = false;
        p.bEnableFrameCroppingFlag = true;
        p.bEnableSceneChangeDetect = false;
        const l = &p.sSpatialLayers[0];
        l.iVideoWidth = @intCast(pic_width);
        l.iVideoHeight = @intCast(pic_height);
        l.fFrameRate = p.fMaxFrameRate;
        l.iSpatialBitrate = p.iTargetBitrate;
        l.iMaxSpatialBitrate = c.UNSPECIFIED_BIT_RATE;
        l.uiProfileIdc = c.PRO_BASELINE;
        l.uiLevelIdc = c.LEVEL_UNKNOWN;
        l.iDLayerQp = opts.qp;
        l.sSliceArgument.uiSliceMode = if (n_threads > 1) c.SM_FIXEDSLCNUM_SLICE else c.SM_SINGLE_SLICE;
        l.sSliceArgument.uiSliceNum = n_threads;
        // MS-RDPEGFX 3.3.8.3.1: full-range BT.709, as the VA-API path's SPS says.
        l.bVideoSignalTypePresent = true;
        l.uiVideoFormat = c.VF_UNDEF;
        l.bFullRange = true;
        l.bColorDescriptionPresent = true;
        l.uiColorPrimaries = c.CP_BT709;
        l.uiTransferCharacteristics = c.TRC_BT709;
        l.uiColorMatrix = c.CM_BT709;
        if (vt.InitializeExt.?(e, &p) != 0) {
            log.warn("OpenH264 rejected {d}x{d} ({d} threads)", .{ pic_width, pic_height, n_threads });
            return error.Encoder;
        }
        var fmt: c_int = c.videoFormatI420;
        if (vt.SetOption.?(e, c.ENCODER_OPTION_DATAFORMAT, &fmt) != 0) {
            _ = vt.Uninitialize.?(e);
            return error.Encoder;
        }
        log.debug("OpenH264 {d}x{d}: {d} thread(s), complexity {t}, QP {d}", .{ pic_width, pic_height, n_threads, opts.complexity, opts.qp });
        return .{
            .gpa = gpa,
            .opts = opts,
            .lib = lib,
            .enc = e,
            .param = p,
            .pic_width = pic_width,
            .pic_height = pic_height,
            .planes = planes,
            .y_pitch = y_pitch,
            .uv_pitch = uv_pitch,
            .plane_height = plane_height,
            .scratch = scratch,
            .scratch_len = scratch_len,
            .bs = bs,
            .coded_qp = opts.qp,
        };
    }

    /// One slice per thread, and at least one macroblock row per slice.
    fn threadCount(opts: Options, pic_height: u32) u32 {
        const want = if (opts.threads != 0) opts.threads else @as(u32, @intCast(std.Thread.getCpuCount() catch 1));
        return std.math.clamp(@min(want, (pic_height + 15) / 16), 1, max_threads);
    }

    pub fn deinit(self: *Encoder) void {
        const vt = self.enc.*.*;
        _ = vt.Uninitialize.?(self.enc);
        self.lib.destroy(self.enc);
        self.gpa.destroy(self.bs);
        self.gpa.free(self.scratch);
        self.gpa.free(self.planes);
        self.* = undefined;
    }

    pub fn threads(self: *const Encoder) u32 {
        return @intCast(self.param.iMultipleThreadIdc);
    }

    /// Recreate for a new size (the next picture is an IDR).
    pub fn resize(self: *Encoder, new_width: u32, new_height: u32) Error!void {
        var opts = self.opts;
        opts.width = new_width;
        opts.height = new_height;
        opts.qp = self.coded_qp;
        const next = try Encoder.init(self.gpa, opts);
        self.deinit();
        self.* = next;
    }

    /// QP of the next pictures (no IDR).
    pub fn setQp(self: *Encoder, qp: u8) void {
        self.opts.qp = @min(qp, 51);
    }

    /// One top-down BGRX frame to exactly one Annex-B access unit. On error nothing is appended
    /// and the next picture is an IDR.
    pub fn encode(self: *Encoder, pixels: []const u8, stride: usize, force_idr: bool, out: *std.ArrayList(u8)) Error!FrameInfo {
        const w = self.opts.width;
        const h = self.opts.height;
        if (stride < @as(usize, w) * 4 or pixels.len < (h - 1) * stride + @as(usize, w) * 4) return error.BadInput;
        const start = out.items.len;
        errdefer {
            self.need_idr = true;
            out.shrinkRetainingCapacity(start);
        }
        const t0 = nowNs();
        self.convert(pixels, stride);
        const t1 = nowNs();

        const vt = self.enc.*.*;
        if (self.opts.qp != self.coded_qp) {
            var p = self.param;
            p.sSpatialLayers[0].iDLayerQp = self.opts.qp;
            if (vt.SetOption.?(self.enc, c.ENCODER_OPTION_SVC_ENCODE_PARAM_EXT, &p) != 0) return error.Encoder;
            self.param = p;
            self.coded_qp = self.opts.qp;
        }
        const idr = force_idr or self.need_idr;
        if (idr and vt.ForceIntraFrame.?(self.enc, true) != 0) return error.Encoder;

        const n_y = self.y_pitch * self.plane_height;
        const n_c = self.uv_pitch * (self.plane_height / 2);
        var src: c.SSourcePicture = std.mem.zeroes(c.SSourcePicture);
        src.iColorFormat = c.videoFormatI420;
        src.iPicWidth = @intCast(self.pic_width);
        src.iPicHeight = @intCast(self.pic_height);
        src.iStride[0] = @intCast(self.y_pitch);
        src.iStride[1] = @intCast(self.uv_pitch);
        src.iStride[2] = @intCast(self.uv_pitch);
        src.pData[0] = self.planes.ptr;
        src.pData[1] = self.planes[n_y..].ptr;
        src.pData[2] = self.planes[n_y + n_c ..].ptr;
        // Milliseconds; only orders the pictures (rate control is off).
        src.uiTimeStamp = @intCast(self.frames * 1000 / @max(self.opts.fps, 1));
        self.bs.* = std.mem.zeroes(c.SFrameBSInfo);
        if (vt.EncodeFrame.?(self.enc, &src, self.bs) != 0) return error.Encoder;
        const t2 = nowNs();

        const ft = self.bs.eFrameType;
        if (ft == c.videoFrameTypeSkip or ft == c.videoFrameTypeInvalid) return error.Encoder;
        const layers: usize = @intCast(self.bs.iLayerNum);
        for (self.bs.sLayerInfo[0..layers]) |layer| {
            var n: usize = 0;
            for (0..@intCast(layer.iNalCount)) |i| n += @intCast(layer.pNalLengthInByte[i]);
            try out.appendSlice(self.gpa, layer.pBsBuf[0..n]);
        }
        if (out.items.len == start) return error.Encoder;
        const coded_idr = ft == c.videoFrameTypeIDR;
        if (idr and !coded_idr) return error.Encoder;
        self.need_idr = false;
        self.frames += 1;
        return .{ .idr = coded_idr, .size = out.items.len - start, .qp = self.coded_qp, .convert_ns = t1 - t0, .encode_ns = t2 - t1 };
    }

    /// BGRX to the I420 planes, in bands of row pairs over the codec workers.
    fn convert(self: *Encoder, pixels: []const u8, stride: usize) void {
        const n_y = self.y_pitch * self.plane_height;
        const n_c = self.uv_pitch * (self.plane_height / 2);
        const out: avc444.I420 = .{
            .y = self.planes[0..n_y],
            .y_pitch = self.y_pitch,
            .u = self.planes[n_y..][0..n_c],
            .v = self.planes[n_y + n_c ..][0..n_c],
            .uv_pitch = self.uv_pitch,
        };
        const pairs = self.plane_height / 2;
        const band = 16;
        const Ctx = struct {
            e: *Encoder,
            pixels: []const u8,
            stride: usize,
            out: avc444.I420,
            pairs: usize,

            fn run(ctx: @This(), task: usize, i: usize) void {
                const e = ctx.e;
                const first = i * band;
                const scratch = e.scratch[task * e.scratch_len ..][0..e.scratch_len];
                // Checked by `encode` and `init`: the sizes cannot fail.
                avc444.toI420Rows(ctx.pixels, ctx.stride, e.opts.width, e.opts.height, ctx.out, scratch, first, @min(first + band, ctx.pairs)) catch unreachable;
            }
        };
        workers.forEach((pairs + band - 1) / band, Ctx{ .e = self, .pixels = pixels, .stride = stride, .out = out, .pairs = pairs }, Ctx.run);
    }
};

fn nowNs() u64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(u64, @intCast(ts.tv_sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.tv_nsec));
}

// --- tests ---------------------------------------------------------------------------------------

const testing = std.testing;
const bs_mod = @import("h264_bitstream.zig");

fn testFrame(gpa: Allocator, w: u32, h: u32, seed: u64) ![]u8 {
    const px = try gpa.alloc(u8, @as(usize, w) * h * 4);
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    // Flat blocks and a gradient: something a codec compresses, with detail.
    for (0..h) |y| for (0..w) |x| {
        const o = (y * w + x) * 4;
        px[o] = @truncate(x * 255 / w);
        px[o + 1] = @truncate(y * 255 / h);
        px[o + 2] = if ((x / 16 + y / 16) % 2 == 0) 200 else 40;
        px[o + 3] = 0xFF;
    };
    for (0..64) |_| {
        const x = r.uintLessThan(u32, w);
        const y = r.uintLessThan(u32, h);
        px[(y * w + x) * 4] = r.int(u8);
    }
    return px;
}

/// NAL unit types of an Annex-B stream, in order.
fn nalTypes(buf: []const u8, out: []u8) []u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i + 3 < buf.len) : (i += 1) {
        if (buf[i] == 0 and buf[i + 1] == 0 and buf[i + 2] == 1) {
            if (n < out.len) out[n] = buf[i + 3] & 0x1F;
            n += 1;
            i += 3;
        }
    }
    return out[0..@min(n, out.len)];
}

test "OpenH264 AVC420: IDR with SPS and PPS first, P after, a QP change without an IDR" {
    if (library() == null) return error.SkipZigTest;
    const gpa = testing.allocator;
    const w: u32 = 320;
    const h: u32 = 182; // not a multiple of 16: cropped in the SPS
    var e = try Encoder.init(gpa, .{ .width = w, .height = h, .qp = 30, .fps = 30, .threads = 2 });
    defer e.deinit();
    const px = try testFrame(gpa, w, h, 1);
    defer gpa.free(px);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    const f0 = try e.encode(px, w * 4, false, &out);
    try testing.expect(f0.idr);
    var types: [16]u8 = undefined;
    const t0 = nalTypes(out.items, &types);
    try testing.expectEqual(@as(u8, 7), t0[0]); // SPS
    try testing.expectEqual(@as(u8, 8), t0[1]); // PPS
    try testing.expectEqual(@as(u8, 5), t0[2]); // IDR slice
    var rbsp: [256]u8 = undefined;
    const sps = try bs_mod.parseSps(bs_mod.unescape(spsPayload(out.items) orelse return error.TestUnexpectedResult, &rbsp));
    try testing.expectEqual(w, sps.width);
    try testing.expectEqual(h, sps.height);
    try testing.expectEqual(@as(?bool, true), sps.video_full_range);
    try testing.expectEqual(@as(?[3]u8, .{ 1, 1, 1 }), sps.colour);

    out.clearRetainingCapacity();
    px[1000] +%= 77;
    e.setQp(22);
    const f1 = try e.encode(px, w * 4, false, &out);
    try testing.expect(!f1.idr);
    try testing.expectEqual(@as(u8, 22), f1.qp);
    for (nalTypes(out.items, &types)) |t| try testing.expectEqual(@as(u8, 1), t);

    out.clearRetainingCapacity();
    const f2 = try e.encode(px, w * 4, true, &out);
    try testing.expect(f2.idr);
    try testing.expectEqual(@as(u8, 7), nalTypes(out.items, &types)[0]);
}

/// The SPS NAL payload (after the header byte) of an Annex-B stream.
fn spsPayload(buf: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 3 < buf.len) : (i += 1) {
        if (!(buf[i] == 0 and buf[i + 1] == 0 and buf[i + 2] == 1)) continue;
        if (buf[i + 3] & 0x1F != 7) continue;
        var j = i + 4;
        while (j + 2 < buf.len and !(buf[j] == 0 and buf[j + 1] == 0 and (buf[j + 2] == 1 or buf[j + 2] == 0))) j += 1;
        return buf[i + 4 .. j];
    }
    return null;
}

test "OpenH264 encoders refuse what they cannot code" {
    if (library() == null) return error.SkipZigTest;
    const gpa = testing.allocator;
    try testing.expectError(error.Unsupported, Encoder.init(gpa, .{ .width = 8192, .height = 2304 }));
    try testing.expectError(error.Unsupported, Encoder.init(gpa, .{ .width = 8, .height = 8 }));
    try testing.expectError(error.BadDimension, Encoder.init(gpa, .{ .width = 0, .height = 10 }));
    var wide = try Encoder.init(gpa, .{ .width = 4096, .height = 2160 });
    wide.deinit();
    var e = try Encoder.init(gpa, .{ .width = 33, .height = 17, .threads = 8 });
    defer e.deinit();
    try testing.expectEqual(@as(u32, 34), e.pic_width);
    try testing.expectEqual(@as(u32, 18), e.pic_height);
    try testing.expectEqual(@as(u32, 2), e.threads()); // two macroblock rows
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const px = try testFrame(gpa, 33, 17, 2);
    defer gpa.free(px);
    try testing.expectError(error.BadInput, e.encode(px[0..100], 33 * 4, false, &out));
    _ = try e.encode(px, 33 * 4, false, &out);
}

test "a libopenh264 that is missing, does not load, is not OpenH264 or of another ABI is told apart" {
    try testing.expect(open("libopenh264-not-installed.so.99") == .missing);
    // Not a shared object at all: dlopen's own error is kept.
    switch (open("/dev/null")) {
        .unloadable => |why| try testing.expect(why.len > 0),
        else => return error.TestUnexpectedResult,
    }
    switch (open("libc.so.6")) {
        .not_openh264 => |sym| try testing.expectEqualStrings("WelsCreateSVCEncoder", sym),
        else => return error.TestUnexpectedResult,
    }
    switch (open(sonames[0])) {
        .loaded => |a| try testing.expectEqual(@as(c_uint, c.OPENH264_MAJOR), a.version.uMajor),
        .missing => return error.SkipZigTest,
        else => return error.TestUnexpectedResult,
    }
}

/// OpenH264's decoder, for tests: Annex-B access units in, the Y plane out.
const TestDecoder = struct {
    lib: std.DynLib,
    dec: *c.ISVCDecoder,
    destroy: *const fn (?*c.ISVCDecoder) callconv(.c) void,

    fn init() !TestDecoder {
        var lib = std.DynLib.openZ(sonames[0]) catch return error.SkipZigTest;
        const create = lib.lookup(*const fn (?*?*c.ISVCDecoder) callconv(.c) c_long, "WelsCreateDecoder") orelse return error.SkipZigTest;
        const destroy = lib.lookup(*const fn (?*c.ISVCDecoder) callconv(.c) void, "WelsDestroyDecoder") orelse return error.SkipZigTest;
        var d: ?*c.ISVCDecoder = null;
        if (create(&d) != 0 or d == null) return error.TestUnexpectedResult;
        var p: c.SDecodingParam = std.mem.zeroes(c.SDecodingParam);
        p.sVideoProperty.eVideoBsType = c.VIDEO_BITSTREAM_AVC;
        p.eEcActiveIdc = c.ERROR_CON_DISABLE;
        if (d.?.*.*.Initialize.?(d.?, &p) != 0) return error.TestUnexpectedResult;
        return .{ .lib = lib, .dec = d.?, .destroy = destroy };
    }

    fn deinit(t: *TestDecoder) void {
        _ = t.dec.*.*.Uninitialize.?(t.dec);
        t.destroy(t.dec);
        t.lib.close();
    }

    /// The decoded picture's luma (w x h) into `y`.
    fn decode(t: *TestDecoder, au: []const u8, w: u32, h: u32, y: []u8) !void {
        var dst: [3][*c]u8 = .{ null, null, null };
        var info: c.SBufferInfo = std.mem.zeroes(c.SBufferInfo);
        const st = t.dec.*.*.DecodeFrameNoDelay.?(t.dec, au.ptr, @intCast(au.len), @ptrCast(&dst), &info);
        if (st != 0 or info.iBufferStatus != 1) return error.TestUnexpectedResult;
        const sb = info.UsrData.sSystemBuffer;
        try testing.expectEqual(@as(c_int, @intCast(w)), sb.iWidth);
        try testing.expectEqual(@as(c_int, @intCast(h)), sb.iHeight);
        const stride: usize = @intCast(sb.iStride[0]);
        for (0..h) |row| @memcpy(y[row * w ..][0..w], (info.pDst[0] + row * stride)[0..w]);
    }
};

fn psnr(a: []const u8, b: []const u8) f64 {
    var se: f64 = 0;
    for (a, b) |x, y| {
        const d: f64 = @as(f64, @floatFromInt(x)) - @as(f64, @floatFromInt(y));
        se += d * d;
    }
    if (se == 0) return 100;
    return 10 * std.math.log10(255.0 * 255.0 * @as(f64, @floatFromInt(a.len)) / se);
}

test "OpenH264: a still frame coded again at a better QP refines the picture (no static skip)" {
    if (library() == null) return error.SkipZigTest;
    const gpa = testing.allocator;
    const w: u32 = 256;
    const h: u32 = 144;
    var e = try Encoder.init(gpa, .{ .width = w, .height = h, .qp = 44, .threads = 2 });
    defer e.deinit();
    var d = try TestDecoder.init();
    defer d.deinit();
    const px = try testFrame(gpa, w, h, 3);
    defer gpa.free(px);
    e.convert(px, w * 4);
    const src_y = try gpa.alloc(u8, w * h);
    defer gpa.free(src_y);
    for (0..h) |row| @memcpy(src_y[row * w ..][0..w], e.planes[row * e.y_pitch ..][0..w]);
    const got = try gpa.alloc(u8, w * h);
    defer gpa.free(got);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    _ = try e.encode(px, w * 4, false, &out);
    try d.decode(out.items, w, h, got);
    const coarse = psnr(src_y, got);
    // Unchanged source at QP 44 again: (almost) nothing to code.
    out.clearRetainingCapacity();
    const same = try e.encode(px, w * 4, false, &out);
    try d.decode(out.items, w, h, got);
    // The same source at QP 20: the residual against the coarse reference is coded.
    out.clearRetainingCapacity();
    e.setQp(20);
    const fine = try e.encode(px, w * 4, false, &out);
    try d.decode(out.items, w, h, got);
    const refined = psnr(src_y, got);
    try testing.expect(!fine.idr);
    try testing.expect(fine.size > 4 * same.size);
    try testing.expect(refined > coarse + 6);
}
