//! VA-API H.264 encoder for RDPGFX AVC420 and AVC444 (MS-RDPEGFX 2.2.4.4-2.2.4.6, 3.3.8.3):
//! a low-latency I/P stream, one slice, every picture a reference, SPS/PPS before every IDR.
//! Headers are passed as VA packed headers; radeonsi emits no parameter sets without them.

const std = @import("std");
const c = @import("c");
const bs = @import("h264_bitstream.zig");
const va = @import("h264_va.zig");
const avc444 = @import("avc444.zig");

const Allocator = std.mem.Allocator;
const log = std.log.scoped(.h264);

pub const Profile = bs.Profile;

pub const RateControl = enum { cbr, vbr, cqp };

pub const ColorConversion = enum {
    /// Separate VAEntrypointVideoProc pass (portable VA-API).
    vpp,
    /// Conversion inside the encode picture (Mesa extension). radeonsi's EFC emits studio
    /// range, so init probes the output and falls back to `vpp`.
    fused,
};

pub const Options = struct {
    width: u32,
    height: u32,
    device: [:0]const u8 = "/dev/dri/renderD128",
    profile: Profile = .high,
    rate_control: RateControl = .vbr,
    /// Target bitrate in bit/s (CBR: the rate; VBR: the average).
    bitrate: u32 = 10_000_000,
    /// VBR peak in bit/s; 0 = 2 x bitrate.
    max_bitrate: u32 = 0,
    /// HRD buffer in ms of the peak rate; smaller lowers latency at the cost of IDR quality.
    vbv_ms: u32 = 500,
    fps: u32 = 60,
    /// CQP quantiser; also the initial QP for CBR/VBR.
    qp: u8 = 26,
    min_qp: u8 = 0,
    max_qp: u8 = 51,
    /// Periodic IDR every N frames; 0 = on demand only.
    idr_interval: u32 = 0,
    /// Signal the exact size via SPS frame cropping.
    crop: bool = true,
    /// Driver quality level; Mesa's 0 is the speed preset.
    quality_level: u32 = 0,
    conversion: ColorConversion = .vpp,
    /// Check every access unit holds exactly one picture (+ SPS/PPS on IDR).
    verify: bool = std.debug.runtime_safety,
    /// AVC444 view packing (`encode444`), coded at avc444.viewSize without cropping;
    /// null is AVC420 (`encode`).
    avc444: ?avc444.Version = null,
};

/// The pictures `encode444` coded (null: that view was not coded).
pub const Avc444Info = struct { main: ?FrameInfo, aux: ?FrameInfo };

pub const FrameInfo = struct {
    idr: bool,
    /// Bytes appended to `out`.
    size: usize,
    /// The driver's average QP, else SliceQPY from the emitted slice header.
    avg_qp: u8,
    frame_num: u32,
    upload_ns: u64,
    /// From submission (VPP + encode) until the bitstream is copied out.
    encode_ns: u64,
    total_ns: u64,
};

pub const Error = error{
    OpenDevice,
    VaInit,
    Vaapi,
    Unsupported,
    BadInput,
    OddDimension,
    BadDimension,
    BitWriterOverflow,
    BadBitstream,
    BadEncoderOutput,
    OutOfMemory,
};

pub const Encoder = struct {
    gpa: Allocator,
    opts: Options,
    geo: bs.Geometry,
    sps: bs.Sps,
    pps: bs.Pps,

    fd: c_int,
    dpy: c.VADisplay,
    vendor: []const u8,
    enc_config: c.VAConfigID = c.VA_INVALID_ID,
    enc_ctx: c.VAContextID = c.VA_INVALID_ID,
    vpp_config: c.VAConfigID = c.VA_INVALID_ID,
    vpp_ctx: c.VAContextID = c.VA_INVALID_ID,
    /// [0] BGRX input, [1] NV12 input (AVC444 main view), [2] AVC444 aux view input,
    /// [3..5] reconstructed pictures (`reconCount`).
    surfaces: [6]c.VASurfaceID = @splat(c.VA_INVALID_SURFACE),
    /// Derived image of the BGRX surface, or a standalone one for vaPutImage.
    image: c.VAImage = .{ .image_id = c.VA_INVALID_ID, .buf = c.VA_INVALID_ID },
    image_derived: bool = false,
    /// AVC444: images of the two NV12 input surfaces, derived or standalone.
    view_images: [2]c.VAImage = @splat(.{ .image_id = c.VA_INVALID_ID, .buf = c.VA_INVALID_ID }),
    view_derived: [2]bool = .{ false, false },
    scratch: []u8 = &.{},
    coded_buf: c.VABufferID = c.VA_INVALID_ID,

    bitrate: u32,
    rc_dirty: bool = true,
    need_idr: bool = true,
    frames_since_idr: u32 = 0,
    idr_pic_id: u16 = 0,
    /// Reference pictures (short-term, sliding window), most recent first.
    dpb: [2]?RefPic = .{ null, null },
    /// Parameter sets of the stream as emitted by the driver.
    params: bs.ParamSets = .{},
    hdr: std.ArrayList(u8) = .empty,

    const src_surface = 0;
    const nv12_surface = 1;
    const aux_surface = 2;
    const recon_base = 3;

    /// Which AVC444 view a picture carries (AVC420: always main).
    pub const View = enum(u1) { main, aux };

    const RefPic = struct { slot: usize, frame_num: u32, poc: i32, view: View };

    fn reconCount(self: *const Encoder) usize {
        return @as(usize, self.sps.max_num_ref_frames) + 1;
    }

    fn picturesPerFrame(opts: Options) u32 {
        return if (opts.avc444 != null) 2 else 1;
    }
    /// A hung or reset GPU becomes error.Vaapi instead of a blocked session.
    const sync_timeout_ns: u64 = 2 * std.time.ns_per_s;

    pub fn init(gpa: Allocator, opts: Options) Error!Encoder {
        // AVC444 views are coded whole at avc444.viewSize, uncropped.
        const geo = if (opts.avc444) |ver| blk: {
            const vs = avc444.viewSize(ver, opts.width, opts.height) catch return error.BadDimension;
            break :blk try bs.Geometry.init(vs.width, vs.height, false);
        } else try bs.Geometry.init(opts.width, opts.height, opts.crop);
        if (opts.qp > 51 or opts.min_qp > 51 or opts.max_qp > 51 or opts.min_qp > opts.max_qp) return error.BadInput;
        if (opts.fps == 0 or opts.bitrate == 0) return error.BadInput;

        const fd = c.open(opts.device.ptr, c.O_RDWR | c.O_CLOEXEC);
        if (fd < 0) return error.OpenDevice;
        errdefer _ = c.close(fd);
        const dpy = c.vaGetDisplayDRM(fd) orelse return error.VaInit;
        _ = c.vaSetInfoCallback(dpy, null, null);
        _ = c.vaSetErrorCallback(dpy, vaErrorCallback, null);
        var major: c_int = 0;
        var minor: c_int = 0;
        if (c.vaInitialize(dpy, &major, &minor) != c.VA_STATUS_SUCCESS) return error.VaInit;
        errdefer _ = c.vaTerminate(dpy);

        var e = fresh(gpa, opts, geo, fd, dpy);
        errdefer e.hdr.deinit(gpa);
        errdefer e.releaseVa();
        try e.setup();
        if (opts.avc444 != null) {
            const ok = e.probeViews() catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => false,
            };
            if (!ok) return unsupported("same-view references (ref_pic_list_modification)");
            e.need_idr = true; // the client never saw the probe frames
        } else if (opts.conversion == .fused) {
            const full = e.fusedFullRange() catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => false,
            };
            if (full) {
                e.need_idr = true; // the client never saw the probe frame
            } else {
                // MS-RDPEGFX 3.3.8.3.1 requires full range; radeonsi's EFC emits studio range.
                log.warn("{s}: fused RGB->NV12 conversion is not full range, using vpp", .{e.vendor});
                e.releaseVa();
                e.hdr.deinit(gpa);
                var vpp = opts;
                vpp.conversion = .vpp;
                e = fresh(gpa, vpp, geo, fd, dpy);
                try e.setup();
            }
        }
        log.debug("{s}: {d}x{d} (coded {d}x{d}) {t} level {d}, {t} {d} kbit/s, conversion {t}", .{
            e.vendor,     opts.width,      opts.height,       geo.codedWidth(),    geo.codedHeight(),
            opts.profile, e.sps.level_idc, opts.rate_control, opts.bitrate / 1000, e.opts.conversion,
        });
        return e;
    }

    fn fresh(gpa: Allocator, opts: Options, geo: bs.Geometry, fd: c_int, dpy: c.VADisplay) Encoder {
        const peak = peakBitrate(opts, opts.bitrate);
        const level = bs.chooseLevel(geo, opts.fps * picturesPerFrame(opts), peak, opts.profile);
        return .{
            .gpa = gpa,
            .opts = opts,
            .geo = geo,
            .sps = .{ .profile = opts.profile, .level_idc = level, .geometry = geo, .max_num_ref_frames = if (opts.avc444 != null) 2 else 1 },
            .pps = .{ .cabac = opts.profile.cabac(), .high = opts.profile == .high, .transform_8x8 = opts.profile == .high },
            .fd = fd,
            .dpy = dpy,
            .vendor = std.mem.span(c.vaQueryVendorString(dpy) orelse @as([*c]const u8, "")),
            .bitrate = opts.bitrate,
        };
    }

    /// Encodes a half black, half white frame and checks the NV12 output is full range.
    fn fusedFullRange(e: *Encoder) Error!bool {
        const w = e.opts.width;
        const h = e.opts.height;
        if (w < 4) return false;
        const row_len = @as(usize, w) * 4;
        const px = try e.gpa.alloc(u8, row_len * h);
        defer e.gpa.free(px);
        for (0..h) |y| for (0..w) |x| {
            const v: u8 = if (x < w / 2) 0 else 255;
            px[y * row_len + x * 4 ..][0..4].* = .{ v, v, v, 0 };
        };
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(e.gpa);
        _ = try e.encode(px, row_len, true, &out);

        const nv12 = e.surfaces[nv12_surface];
        try vaCheck(c.vaSyncSurface(e.dpy, nv12), "vaSyncSurface(probe)");
        var fmt: c.VAImageFormat = .{ .fourcc = c.VA_FOURCC_NV12, .byte_order = c.VA_LSB_FIRST, .bits_per_pixel = 12 };
        var img: c.VAImage = undefined;
        try vaCheck(c.vaCreateImage(e.dpy, &fmt, @intCast(w), @intCast(h), &img), "vaCreateImage(probe)");
        defer _ = c.vaDestroyImage(e.dpy, img.image_id);
        try vaCheck(c.vaGetImage(e.dpy, nv12, 0, 0, w, h, img.image_id), "vaGetImage(probe)");
        var p: ?*anyopaque = null;
        try vaCheck(c.vaMapBuffer(e.dpy, img.buf, &p), "vaMapBuffer(probe)");
        defer _ = c.vaUnmapBuffer(e.dpy, img.buf);
        const base: [*]const u8 = @ptrCast(p orelse return error.Vaapi);
        const luma = base + img.offsets[0] + @as(usize, h / 2) * img.pitches[0];
        const black = luma[w / 4];
        const white = luma[w - 1 - w / 4];
        log.debug("{s}: fused conversion probe: black Y {d}, white Y {d}", .{ e.vendor, black, white });
        return black <= 3 and white >= 252;
    }

    pub fn deinit(self: *Encoder) void {
        self.releaseVa();
        _ = c.vaTerminate(self.dpy);
        _ = c.close(self.fd);
        self.hdr.deinit(self.gpa);
        self.* = undefined;
    }

    /// Recreate everything for a new size (contexts are size-bound).
    pub fn resize(self: *Encoder, new_width: u32, new_height: u32) Error!void {
        var opts = self.opts;
        opts.width = new_width;
        opts.height = new_height;
        opts.bitrate = self.bitrate;
        const gpa = self.gpa;
        const next = try Encoder.init(gpa, opts);
        self.deinit();
        self.* = next;
    }

    /// Change the target bitrate; applied from the next frame (no IDR).
    pub fn setBitrate(self: *Encoder, bps: u32) void {
        if (bps == 0 or bps == self.bitrate) return;
        self.bitrate = bps;
        self.rc_dirty = true;
    }

    /// CQP: QP of the next frames, as slice_qp_delta against pic_init_qp (no IDR).
    pub fn setQp(self: *Encoder, qp: u8) void {
        self.opts.qp = @min(qp, 51);
    }

    pub fn requestIdr(self: *Encoder) void {
        self.need_idr = true;
    }

    pub fn width(self: *const Encoder) u32 {
        return self.opts.width;
    }

    pub fn height(self: *const Encoder) u32 {
        return self.opts.height;
    }

    /// One top-down BGRX frame to exactly one Annex-B access unit (AVC420).
    pub fn encode(self: *Encoder, pixels: []const u8, stride: usize, force_idr: bool, out: *std.ArrayList(u8)) Error!FrameInfo {
        if (self.opts.avc444 != null) return error.BadInput;
        const t0 = nowNs();
        try self.upload(pixels, stride);
        const t1 = nowNs();
        var info = try self.encodeSurface(self.surfaces[src_surface], force_idr, out);
        info.upload_ns = t1 - t0;
        info.total_ns = nowNs() - t0;
        return info;
    }

    /// Encode from a BGRX VA surface of the encoder's size.
    pub fn encodeSurface(self: *Encoder, src: c.VASurfaceID, force_idr: bool, out: *std.ArrayList(u8)) Error!FrameInfo {
        if (self.opts.avc444 != null) return error.BadInput;
        const t0 = nowNs();
        if (self.opts.conversion == .vpp) {
            self.convert(src) catch |err| {
                self.need_idr = true;
                return err;
            };
        }
        const fused: ?c.VASurfaceID = if (self.opts.conversion == .fused) src else null;
        var info = try self.codePicture(self.surfaces[nv12_surface], fused, self.idrDue(force_idr), .main, out);
        info.encode_ns = nowNs() - t0;
        info.total_ns = info.encode_ns;
        return info;
    }

    /// Codes the views `lc` asks for (MS-RDPEGFX 2.2.4.5), each into its own list. An IDR
    /// codes both views whatever `lc` says. On error nothing is appended.
    pub fn encode444(self: *Encoder, pixels: []const u8, stride: usize, force_idr: bool, lc: avc444.Lc, main_out: *std.ArrayList(u8), aux_out: *std.ArrayList(u8)) Error!Avc444Info {
        const version = self.opts.avc444 orelse return error.BadInput;
        const t0 = nowNs();
        const idr = self.idrDue(force_idr);
        const do_main = idr or lc != .chroma;
        const do_aux = idr or lc != .luma;
        const main_start = main_out.items.len;
        const aux_start = aux_out.items.len;
        errdefer {
            self.need_idr = true;
            main_out.shrinkRetainingCapacity(main_start);
            aux_out.shrinkRetainingCapacity(aux_start);
        }
        try self.uploadViews(version, pixels, stride, do_main, do_aux);
        const t1 = nowNs();
        var info: Avc444Info = .{ .main = null, .aux = null };
        if (do_main) info.main = try self.codePicture(self.surfaces[nv12_surface], null, idr, .main, main_out);
        if (do_aux) info.aux = try self.codePicture(self.surfaces[aux_surface], null, false, .aux, aux_out);
        const total = nowNs() - t0;
        inline for (.{ &info.main, &info.aux }) |fi| if (fi.*) |*f| {
            f.upload_ns = t1 - t0;
            f.total_ns = total;
        };
        return info;
    }

    fn idrDue(self: *const Encoder, force_idr: bool) bool {
        if (force_idr or self.need_idr) return true;
        if (self.opts.idr_interval != 0 and self.frames_since_idr >= self.opts.idr_interval * picturesPerFrame(self.opts)) return true;
        return self.frames_since_idr >= 1 << 30; // keep POC in range
    }

    fn freeSlot(self: *const Encoder, dpb: []const ?RefPic) usize {
        var slot: usize = 0;
        while (slot < self.reconCount()) : (slot += 1) {
            for (dpb) |r| {
                if (r) |ref| if (ref.slot == slot) break;
            } else return slot;
        }
        unreachable; // reconCount = references + 1
    }

    /// P pictures predict from the latest reference of the same view; with none, the
    /// picture is an I slice.
    fn codePicture(self: *Encoder, input: c.VASurfaceID, fused: ?c.VASurfaceID, idr: bool, view: View, out: *std.ArrayList(u8)) Error!FrameInfo {
        const t0 = nowNs();
        const start = out.items.len;
        // A failed frame may have advanced the driver's references: restart with an IDR.
        errdefer {
            self.need_idr = true;
            out.shrinkRetainingCapacity(start);
        }
        // An IDR empties the DPB (8.2.5.1).
        const dpb: [2]?RefPic = if (idr) .{ null, null } else self.dpb;
        const pictures = if (idr) 0 else self.frames_since_idr;
        const frame_num = pictures % self.sps.maxFrameNum();
        const poc: i32 = @intCast(2 * pictures);
        const cur_slot = self.freeSlot(&dpb);
        const cur = self.surfaces[recon_base + cur_slot];
        // This view's latest picture; its index in the default list decides the modification.
        var ref_index: ?usize = null;
        for (dpb, 0..) |r, i| {
            if (r) |ref| if (ref.view == view) {
                ref_index = i;
                break;
            };
        }
        const slice_type: bs.SliceType = if (idr or ref_index == null) .i else .p;
        if (idr) self.idr_pic_id +%= 1;

        var bufs = BufList{ .dpy = self.dpy, .ctx = self.enc_ctx };
        defer bufs.destroy();

        if (fused) |src| {
            var additional = [1]c.VASurfaceID{input};
            var pp = pipelineParams(src);
            pp.additional_outputs = &additional;
            pp.num_additional_outputs = 1;
            try bufs.add(c.VAProcPipelineParameterBufferType, std.mem.asBytes(&pp));
        }
        if (idr) try bufs.add(c.VAEncSequenceParameterBufferType, std.mem.asBytes(&self.seqParams()));
        if (idr or self.rc_dirty) try self.addRateControl(&bufs);
        if (idr) {
            const fr = va.Misc(va.FrameRate, c.VAEncMiscParameterTypeFrameRate){ .data = .{ .framerate = self.opts.fps * picturesPerFrame(self.opts) } };
            try bufs.add(c.VAEncMiscParameterBufferType, std.mem.asBytes(&fr));
            const ql = va.Misc(va.QualityLevel, c.VAEncMiscParameterTypeQualityLevel){ .data = .{ .quality_level = self.opts.quality_level } };
            try bufs.add(c.VAEncMiscParameterBufferType, std.mem.asBytes(&ql));
        }

        var pic = va.PicParam{
            .CurrPic = .{
                .picture_id = cur,
                .frame_idx = frame_num,
                .flags = 0,
                .TopFieldOrderCnt = poc,
                .BottomFieldOrderCnt = poc,
            },
            .coded_buf = self.coded_buf,
            .frame_num = @intCast(frame_num),
            .pic_init_qp = self.pps.pic_init_qp,
            .pic_fields = .{
                .idr_pic_flag = @intFromBool(idr),
                .reference_pic_flag = 1,
                .entropy_coding_mode_flag = @intFromBool(self.pps.cabac),
                .transform_8x8_mode_flag = @intFromBool(self.pps.high and self.pps.transform_8x8),
                .deblocking_filter_control_present_flag = @intFromBool(self.pps.deblocking_control),
            },
        };
        // Whole DPB, most recent first: radeonsi takes the reference order from here.
        var refs: [2]c.VAPictureH264 = undefined;
        for (dpb, 0..) |r, i| if (r) |ref| {
            refs[i] = .{
                .picture_id = self.surfaces[recon_base + ref.slot],
                .frame_idx = ref.frame_num,
                .flags = c.VA_PICTURE_H264_SHORT_TERM_REFERENCE,
                .TopFieldOrderCnt = ref.poc,
                .BottomFieldOrderCnt = ref.poc,
            };
            pic.ReferenceFrames[i] = refs[i];
        };
        try bufs.add(c.VAEncPictureParameterBufferType, std.mem.asBytes(&pic));

        const qp_delta: i32 = @as(i32, self.opts.qp) - @as(i32, self.pps.pic_init_qp);
        if (idr) {
            var w = bs.BitWriter{};
            try bs.writeSps(&w, self.sps);
            try self.addPackedHeader(&bufs, c.VAEncPackedHeaderSequence, 3, .sps, &w);
            w = .{};
            try bs.writePps(&w, self.pps);
            try self.addPackedHeader(&bufs, c.VAEncPackedHeaderPicture, 3, .pps, &w);
        }
        // 8.2.4.3.1: PicNum = FrameNumWrap, so the difference is the distance in pictures.
        const ref_mod: ?u32 = if (ref_index) |i| (if (i == 0 or slice_type == .i) null else refDistance(dpb[i].?, pictures, self.sps.maxFrameNum()) - 1) else null;
        const sh = bs.SliceHeader{
            .idr = idr,
            .slice_type = slice_type,
            .frame_num = frame_num,
            .idr_pic_id = self.idr_pic_id,
            .qp_delta = qp_delta,
            .l0_abs_diff_pic_num_minus1 = ref_mod,
        };
        {
            var w = bs.BitWriter{};
            try bs.writeSliceHeader(&w, self.sps, self.pps, sh);
            try self.addPackedHeader(&bufs, c.VAEncPackedHeaderSlice, sh.nalRefIdc(), sh.nalType(), &w);
        }

        var slice: c.VAEncSliceParameterBufferH264 = .{};
        slice.macroblock_address = 0;
        slice.num_macroblocks = self.geo.mbs();
        slice.macroblock_info = c.VA_INVALID_ID;
        slice.slice_type = @backingInt(sh.slice_type);
        slice.pic_parameter_set_id = 0;
        slice.idr_pic_id = self.idr_pic_id;
        slice.slice_qp_delta = @intCast(qp_delta);
        slice.RefPicList0 = @splat(va.invalid_picture);
        slice.RefPicList1 = @splat(va.invalid_picture);
        if (slice_type == .p) slice.RefPicList0[0] = refs[ref_index.?];
        try bufs.add(c.VAEncSliceParameterBufferType, std.mem.asBytes(&slice));

        const target = fused orelse input;
        try vaCheck(c.vaBeginPicture(self.dpy, self.enc_ctx, target), "vaBeginPicture(encode)");
        const rs = c.vaRenderPicture(self.dpy, self.enc_ctx, &bufs.ids, @intCast(bufs.n));
        const es = c.vaEndPicture(self.dpy, self.enc_ctx);
        try vaCheck(rs, "vaRenderPicture(encode)");
        try vaCheck(es, "vaEndPicture(encode)");

        const st = c.vaSyncBuffer(self.dpy, self.coded_buf, sync_timeout_ns);
        if (st == c.VA_STATUS_ERROR_UNIMPLEMENTED) {
            try vaCheck(c.vaSyncSurface(self.dpy, target), "vaSyncSurface");
        } else try vaCheck(st, "vaSyncBuffer");

        const driver_qp = try self.readCoded(out);
        const size = out.items.len - start;
        // radeonsi reports no average QP; the slice header carries SliceQPY.
        const au = out.items[start..];
        const hs = bs.scanHeaders(au, if (idr) .{} else self.params);
        const avg_qp = if (driver_qp != 0) driver_qp else hs.qp() orelse 0;
        // The driver re-emits our slice header; another reference would desync the client.
        if (hs.slice) |si| if (si.l0_abs_diff_pic_num_minus1 != ref_mod or si.l0_other_modification) {
            log.err("{s}: driver slice header has list modification {?d}, wanted {?d}", .{ self.vendor, si.l0_abs_diff_pic_num_minus1, ref_mod });
            return error.Unsupported;
        };

        if (self.opts.verify) try self.verifyAccessUnit(au, if (idr) .{} else self.params, idr, frame_num, slice_type);

        // Commit state only once the picture is out (sliding window).
        self.params = hs.params;
        self.need_idr = false;
        self.rc_dirty = false;
        const cur_ref: RefPic = .{ .slot = cur_slot, .frame_num = frame_num, .poc = poc, .view = view };
        self.dpb = if (self.sps.max_num_ref_frames >= 2) .{ cur_ref, dpb[0] } else .{ cur_ref, null };
        self.frames_since_idr = pictures + 1;

        return .{
            .idr = idr,
            .size = size,
            .avg_qp = avg_qp,
            .frame_num = frame_num,
            .upload_ns = 0,
            .encode_ns = nowNs() - t0,
            .total_ns = nowNs() - t0,
        };
    }

    /// Pictures between reference `r` and the current one; frame_num wraps at `max_frame_num`.
    fn refDistance(r: RefPic, pictures: u32, max_frame_num: u32) u32 {
        const cur = pictures % max_frame_num;
        return if (r.frame_num < cur) cur - r.frame_num else cur + max_frame_num - r.frame_num;
    }

    /// False when the driver codes another reference than the one asked for, or fails.
    fn probeViews(e: *Encoder) Error!bool {
        const w = e.opts.width;
        const h = e.opts.height;
        const row = @as(usize, w) * 4;
        const px = try e.gpa.alloc(u8, row * h);
        defer e.gpa.free(px);
        for (0..h) |y| for (0..w) |x| {
            px[y * row + x * 4 ..][0..4].* = .{ @truncate(x), @truncate(y), @truncate(x ^ y), 0 };
        };
        var a: std.ArrayList(u8) = .empty;
        defer a.deinit(e.gpa);
        var b: std.ArrayList(u8) = .empty;
        defer b.deinit(e.gpa);
        for (0..2) |_| {
            const info = e.encode444(px, row, false, .both, &a, &b) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {
                    log.warn("{s}: AVC444 probe failed: {t}", .{ e.vendor, err });
                    return false;
                },
            };
            if (info.main == null or info.aux == null) return false;
        }
        return true;
    }

    fn setup(e: *Encoder) Error!void {
        const profile: c.VAProfile = switch (e.opts.profile) {
            .high => c.VAProfileH264High,
            .main => c.VAProfileH264Main,
            .constrained_baseline => c.VAProfileH264ConstrainedBaseline,
        };
        if (!e.hasEntrypoint(profile, c.VAEntrypointEncSlice)) {
            log.err("{s}: no H.264 {t} EncSlice entrypoint", .{ e.vendor, e.opts.profile });
            return error.Unsupported;
        }

        var attrs = [_]c.VAConfigAttrib{
            .{ .type = c.VAConfigAttribRTFormat },
            .{ .type = c.VAConfigAttribRateControl },
            .{ .type = c.VAConfigAttribEncPackedHeaders },
            .{ .type = c.VAConfigAttribMaxPictureWidth },
            .{ .type = c.VAConfigAttribMaxPictureHeight },
        };
        try vaCheck(c.vaGetConfigAttributes(e.dpy, profile, c.VAEntrypointEncSlice, &attrs, attrs.len), "vaGetConfigAttributes");
        const rc_mode: u32 = switch (e.opts.rate_control) {
            .cbr => c.VA_RC_CBR,
            .vbr => c.VA_RC_VBR,
            .cqp => c.VA_RC_CQP,
        };
        const packed_needed: u32 = c.VA_ENC_PACKED_HEADER_SEQUENCE | c.VA_ENC_PACKED_HEADER_PICTURE | c.VA_ENC_PACKED_HEADER_SLICE;
        if (attrs[0].value & c.VA_RT_FORMAT_YUV420 == 0) return unsupported("4:2:0 encode");
        if (attrs[1].value == c.VA_ATTRIB_NOT_SUPPORTED or attrs[1].value & rc_mode == 0) return unsupported("rate control mode");
        if (attrs[2].value == c.VA_ATTRIB_NOT_SUPPORTED or attrs[2].value & packed_needed != packed_needed) return unsupported("packed SPS/PPS/slice headers");
        if (attrs[3].value != c.VA_ATTRIB_NOT_SUPPORTED and e.geo.codedWidth() > attrs[3].value) return unsupported("width");
        if (attrs[4].value != c.VA_ATTRIB_NOT_SUPPORTED and e.geo.codedHeight() > attrs[4].value) return unsupported("height");

        var cfg_attrs = [_]c.VAConfigAttrib{
            .{ .type = c.VAConfigAttribRTFormat, .value = c.VA_RT_FORMAT_YUV420 },
            .{ .type = c.VAConfigAttribRateControl, .value = rc_mode },
            .{ .type = c.VAConfigAttribEncPackedHeaders, .value = packed_needed },
        };
        try vaCheck(c.vaCreateConfig(e.dpy, profile, c.VAEntrypointEncSlice, &cfg_attrs, cfg_attrs.len, &e.enc_config), "vaCreateConfig(encode)");

        const w = e.opts.width;
        const h = e.opts.height;
        const views = e.opts.avc444 != null;
        // AVC444 views are written whole: their surfaces have the coded size.
        const nw = if (views) e.geo.codedWidth() else w;
        const nh = if (views) e.geo.codedHeight() else h;
        if (!views) try createSurfaces(e.dpy, c.VA_RT_FORMAT_RGB32, c.VA_FOURCC_BGRX, w, h, e.surfaces[src_surface..][0..1]);
        const inputs: usize = if (views) 2 else 1;
        try createSurfaces(e.dpy, c.VA_RT_FORMAT_YUV420, c.VA_FOURCC_NV12, nw, nh, e.surfaces[nv12_surface..][0..inputs]);
        try createSurfaces(e.dpy, c.VA_RT_FORMAT_YUV420, c.VA_FOURCC_NV12, nw, nh, e.surfaces[recon_base..][0..e.reconCount()]);
        var targets: [5]c.VASurfaceID = undefined;
        @memcpy(targets[0..inputs], e.surfaces[nv12_surface..][0..inputs]);
        @memcpy(targets[inputs..][0..e.reconCount()], e.surfaces[recon_base..][0..e.reconCount()]);
        try vaCheck(c.vaCreateContext(e.dpy, e.enc_config, @intCast(nw), @intCast(nh), c.VA_PROGRESSIVE, &targets, @intCast(inputs + e.reconCount()), &e.enc_ctx), "vaCreateContext(encode)");

        if (!views and e.opts.conversion == .vpp) {
            if (!e.hasEntrypoint(c.VAProfileNone, c.VAEntrypointVideoProc)) return unsupported("video processing");
            try vaCheck(c.vaCreateConfig(e.dpy, c.VAProfileNone, c.VAEntrypointVideoProc, null, 0, &e.vpp_config), "vaCreateConfig(vpp)");
            try vaCheck(c.vaCreateContext(e.dpy, e.vpp_config, @intCast(w), @intCast(h), c.VA_PROGRESSIVE, &e.surfaces[nv12_surface], 1, &e.vpp_ctx), "vaCreateContext(vpp)");
        }

        // Worst case: 3200 bits per macroblock (A.3.1) plus headers.
        const coded_size: u32 = e.geo.mbs() * 400 + 64 * 1024;
        try vaCheck(c.vaCreateBuffer(e.dpy, e.enc_ctx, c.VAEncCodedBufferType, coded_size, 1, null, &e.coded_buf), "vaCreateBuffer(coded)");

        if (views) {
            for (&e.view_images, &e.view_derived, 0..) |*img, *derived, i| {
                if (c.vaDeriveImage(e.dpy, e.surfaces[nv12_surface + i], img) == c.VA_STATUS_SUCCESS and img.format.fourcc == c.VA_FOURCC_NV12) {
                    derived.* = true;
                } else {
                    if (img.image_id != c.VA_INVALID_ID) _ = c.vaDestroyImage(e.dpy, img.image_id);
                    var fmt: c.VAImageFormat = .{ .fourcc = c.VA_FOURCC_NV12, .byte_order = c.VA_LSB_FIRST, .bits_per_pixel = 12 };
                    try vaCheck(c.vaCreateImage(e.dpy, &fmt, @intCast(nw), @intCast(nh), img), "vaCreateImage(view)");
                }
                const ok = img.num_planes >= 2 and img.pitches[0] >= nw and img.pitches[1] >= nw and
                    @as(u64, img.offsets[0]) + @as(u64, img.pitches[0]) * nh <= img.data_size and
                    @as(u64, img.offsets[1]) + @as(u64, img.pitches[1]) * (nh / 2) <= img.data_size;
                if (!ok) return unsupported("NV12 image layout");
            }
            e.scratch = try e.gpa.alloc(u8, convertThreads(w, h) * avc444.nv12ScratchLen(w));
            return;
        }
        if (c.vaDeriveImage(e.dpy, e.surfaces[src_surface], &e.image) == c.VA_STATUS_SUCCESS) {
            e.image_derived = true;
        } else {
            var fmt: c.VAImageFormat = .{ .fourcc = c.VA_FOURCC_BGRX, .byte_order = c.VA_LSB_FIRST, .bits_per_pixel = 32 };
            try vaCheck(c.vaCreateImage(e.dpy, &fmt, @intCast(w), @intCast(h), &e.image), "vaCreateImage");
        }
    }

    fn releaseVa(e: *Encoder) void {
        if (e.image.image_id != c.VA_INVALID_ID) _ = c.vaDestroyImage(e.dpy, e.image.image_id);
        e.image.image_id = c.VA_INVALID_ID;
        for (&e.view_images) |*img| {
            if (img.image_id != c.VA_INVALID_ID) _ = c.vaDestroyImage(e.dpy, img.image_id);
            img.image_id = c.VA_INVALID_ID;
        }
        e.gpa.free(e.scratch);
        e.scratch = &.{};
        if (e.coded_buf != c.VA_INVALID_ID) _ = c.vaDestroyBuffer(e.dpy, e.coded_buf);
        e.coded_buf = c.VA_INVALID_ID;
        if (e.vpp_ctx != c.VA_INVALID_ID) _ = c.vaDestroyContext(e.dpy, e.vpp_ctx);
        e.vpp_ctx = c.VA_INVALID_ID;
        if (e.vpp_config != c.VA_INVALID_ID) _ = c.vaDestroyConfig(e.dpy, e.vpp_config);
        e.vpp_config = c.VA_INVALID_ID;
        if (e.enc_ctx != c.VA_INVALID_ID) _ = c.vaDestroyContext(e.dpy, e.enc_ctx);
        e.enc_ctx = c.VA_INVALID_ID;
        if (e.enc_config != c.VA_INVALID_ID) _ = c.vaDestroyConfig(e.dpy, e.enc_config);
        e.enc_config = c.VA_INVALID_ID;
        for (&e.surfaces) |*s| {
            if (s.* != c.VA_INVALID_SURFACE) _ = c.vaDestroySurfaces(e.dpy, s, 1);
            s.* = c.VA_INVALID_SURFACE;
        }
    }

    fn hasEntrypoint(e: *Encoder, profile: c.VAProfile, entrypoint: c.VAEntrypoint) bool {
        var eps: [32]c.VAEntrypoint = undefined;
        var n: c_int = 0;
        if (c.vaQueryConfigEntrypoints(e.dpy, profile, &eps, &n) != c.VA_STATUS_SUCCESS) return false;
        for (eps[0..@intCast(@min(n, eps.len))]) |x| if (x == entrypoint) return true;
        return false;
    }

    fn upload(self: *Encoder, pixels: []const u8, stride: usize) Error!void {
        const w = self.opts.width;
        const h = self.opts.height;
        const row = @as(usize, w) * 4;
        if (stride < row or pixels.len < stride * (h - 1) + row) return error.BadInput;
        var p: ?*anyopaque = null;
        var st = c.vaMapBuffer2(self.dpy, self.image.buf, &p, c.VA_MAPBUFFER_FLAG_WRITE);
        if (st == c.VA_STATUS_ERROR_UNIMPLEMENTED) st = c.vaMapBuffer(self.dpy, self.image.buf, &p);
        try vaCheck(st, "vaMapBuffer(image)");
        const dst: [*]u8 = @ptrCast(p orelse return error.Vaapi);
        const pitch: usize = self.image.pitches[0];
        const base = dst + self.image.offsets[0];
        if (pitch == row and stride == row) {
            @memcpy(base[0 .. row * h], pixels[0 .. row * h]);
        } else {
            for (0..h) |y| @memcpy(base[y * pitch ..][0..row], pixels[y * stride ..][0..row]);
        }
        try vaCheck(c.vaUnmapBuffer(self.dpy, self.image.buf), "vaUnmapBuffer(image)");
        if (!self.image_derived) {
            try vaCheck(c.vaPutImage(self.dpy, self.surfaces[src_surface], self.image.image_id, 0, 0, w, h, 0, 0, w, h), "vaPutImage");
        }
    }

    /// Builds the views in one pass into the mapped NV12 surfaces (write-combined memory).
    fn uploadViews(self: *Encoder, version: avc444.Version, pixels: []const u8, stride: usize, do_main: bool, do_aux: bool) Error!void {
        const w = self.opts.width;
        const h = self.opts.height;
        const row = @as(usize, w) * 4;
        if (stride < row or pixels.len < stride * (h - 1) + row) return error.BadInput;
        const nh: usize = self.geo.codedHeight();
        const want = [2]bool{ do_main, do_aux };
        var views: [2]?avc444.Nv12 = .{ null, null };
        var mapped = [2]bool{ false, false };
        defer for (mapped, self.view_images) |m, img| {
            if (m) _ = c.vaUnmapBuffer(self.dpy, img.buf);
        };
        for (want, self.view_images, &views, &mapped) |on, img, *v, *m| {
            if (!on) continue;
            var p: ?*anyopaque = null;
            var st = c.vaMapBuffer2(self.dpy, img.buf, &p, c.VA_MAPBUFFER_FLAG_WRITE);
            if (st == c.VA_STATUS_ERROR_UNIMPLEMENTED) st = c.vaMapBuffer(self.dpy, img.buf, &p);
            try vaCheck(st, "vaMapBuffer(view)");
            m.* = true;
            const base: [*]u8 = @ptrCast(p orelse return error.Vaapi);
            v.* = .{
                .y = base[img.offsets[0]..][0 .. img.pitches[0] * nh],
                .y_pitch = img.pitches[0],
                .uv = base[img.offsets[1]..][0 .. img.pitches[1] * (nh / 2)],
                .uv_pitch = img.pitches[1],
            };
        }
        try self.convertViews(version, pixels, stride, views);
        for (&mapped, self.view_images, self.view_derived, 0..) |*m, img, derived, i| {
            if (!m.*) continue;
            m.* = false;
            try vaCheck(c.vaUnmapBuffer(self.dpy, img.buf), "vaUnmapBuffer(view)");
            if (!derived) {
                const cw = self.geo.codedWidth();
                try vaCheck(c.vaPutImage(self.dpy, self.surfaces[nv12_surface + i], img.image_id, 0, 0, cw, @intCast(nh), 0, 0, cw, @intCast(nh)), "vaPutImage(view)");
            }
        }
    }

    /// Threads building the views: about one per 2 megapixels (4K: 4).
    fn convertThreads(w: u32, h: u32) usize {
        return std.math.clamp((@as(usize, w) * h + (1 << 21) - 1) >> 21, 1, max_convert_threads);
    }

    const max_convert_threads = 4;

    /// avc444.toNv12 in bands of row pairs; the caller runs the first band and any unstarted one.
    fn convertViews(self: *Encoder, version: avc444.Version, pixels: []const u8, stride: usize, views: [2]?avc444.Nv12) Error!void {
        const w = self.opts.width;
        const h = self.opts.height;
        const n = convertThreads(w, h);
        const pairs = self.geo.codedHeight() / 2;
        const per = avc444.nv12ScratchLen(w);
        const Band = struct {
            fn run(ver: avc444.Version, px: []const u8, st: usize, bw: u32, bh: u32, v: [2]?avc444.Nv12, scratch: []u8, first: usize, end: usize, err: *?avc444.Error) void {
                avc444.toNv12Rows(ver, px, st, bw, bh, v[0], v[1], scratch, first, end) catch |e| {
                    err.* = e;
                };
            }
        };
        var errs: [max_convert_threads]?avc444.Error = @splat(null);
        var threads: [max_convert_threads]?std.Thread = @splat(null);
        for (1..n) |i| {
            threads[i] = std.Thread.spawn(.{}, Band.run, .{ version, pixels, stride, w, h, views, self.scratch[i * per ..][0..per], pairs * i / n, pairs * (i + 1) / n, &errs[i] }) catch null;
        }
        Band.run(version, pixels, stride, w, h, views, self.scratch[0..per], 0, pairs / n, &errs[0]);
        for (1..n) |i| {
            if (threads[i]) |t| t.join() else Band.run(version, pixels, stride, w, h, views, self.scratch[0..per], pairs * i / n, pairs * (i + 1) / n, &errs[i]);
        }
        for (errs[0..n]) |e| if (e) |err| return switch (err) {
            error.InvalidDimensions => error.BadInput,
            else => error.Vaapi,
        };
    }

    /// BGRX surface -> NV12 surface.
    fn convert(self: *Encoder, src: c.VASurfaceID) Error!void {
        var bufs = BufList{ .dpy = self.dpy, .ctx = self.vpp_ctx };
        defer bufs.destroy();
        var pp = pipelineParams(src);
        try bufs.add(c.VAProcPipelineParameterBufferType, std.mem.asBytes(&pp));
        try vaCheck(c.vaBeginPicture(self.dpy, self.vpp_ctx, self.surfaces[nv12_surface]), "vaBeginPicture(vpp)");
        const rs = c.vaRenderPicture(self.dpy, self.vpp_ctx, &bufs.ids, @intCast(bufs.n));
        const es = c.vaEndPicture(self.dpy, self.vpp_ctx);
        try vaCheck(rs, "vaRenderPicture(vpp)");
        try vaCheck(es, "vaEndPicture(vpp)");
    }

    /// Full-range BT.709 matrix only (MS-RDPEGFX 3.3.8.3.1), no transfer-function conversion.
    pub fn pipelineParams(src: c.VASurfaceID) c.VAProcPipelineParameterBuffer {
        var pp: c.VAProcPipelineParameterBuffer = .{};
        pp.surface = src;
        pp.surface_color_standard = c.VAProcColorStandardBT709;
        pp.output_color_standard = c.VAProcColorStandardBT709;
        pp.input_color_properties.color_range = c.VA_SOURCE_RANGE_FULL;
        pp.output_color_properties.color_range = c.VA_SOURCE_RANGE_FULL;
        pp.output_background_color = 0xff000000;
        pp.filter_flags = c.VA_FILTER_SCALING_DEFAULT;
        return pp;
    }

    pub fn peakBitrate(opts: Options, bitrate: u32) u32 {
        return switch (opts.rate_control) {
            .vbr => if (opts.max_bitrate != 0) @max(opts.max_bitrate, bitrate) else bitrate *| 2,
            else => bitrate,
        };
    }

    fn addRateControl(self: *Encoder, bufs: *BufList) Error!void {
        if (self.opts.rate_control == .cqp) return;
        const peak = peakBitrate(self.opts, self.bitrate);
        const rc = va.Misc(va.RateControl, c.VAEncMiscParameterTypeRateControl){ .data = .{
            .bits_per_second = peak,
            .target_percentage = if (self.opts.rate_control == .vbr) @intCast(@max(1, @as(u64, self.bitrate) * 100 / peak)) else 100,
            .window_size = self.opts.vbv_ms,
            .initial_qp = self.opts.qp,
            .min_qp = self.opts.min_qp,
            .max_qp = self.opts.max_qp,
            .rc_flags = .{ .disable_frame_skip = 1, .disable_bit_stuffing = 1 },
        } };
        try bufs.add(c.VAEncMiscParameterBufferType, std.mem.asBytes(&rc));
        if (self.opts.vbv_ms != 0) {
            const size: u32 = @intCast(@max(1, @as(u64, peak) * self.opts.vbv_ms / 1000));
            const hrd = va.Misc(c.VAEncMiscParameterHRD, c.VAEncMiscParameterTypeHRD){ .data = .{
                .buffer_size = size,
                .initial_buffer_fullness = size / 4 * 3,
            } };
            try bufs.add(c.VAEncMiscParameterBufferType, std.mem.asBytes(&hrd));
        }
    }

    pub fn seqParams(self: *const Encoder) va.SeqParam {
        const g = self.geo;
        const gop: u32 = if (self.opts.idr_interval != 0) self.opts.idr_interval else 0xffff;
        return .{
            .seq_parameter_set_id = 0,
            .level_idc = self.sps.level_idc,
            .intra_period = gop,
            .intra_idr_period = gop,
            .ip_period = 1,
            .bits_per_second = if (self.opts.rate_control == .cqp) 0 else peakBitrate(self.opts, self.bitrate),
            .max_num_ref_frames = self.sps.max_num_ref_frames,
            .picture_width_in_mbs = g.width_mbs,
            .picture_height_in_mbs = g.height_mbs,
            .seq_fields = .{
                .chroma_format_idc = 1,
                .frame_mbs_only_flag = 1,
                .direct_8x8_inference_flag = 1,
                .log2_max_frame_num_minus4 = self.sps.log2_max_frame_num_minus4,
                .pic_order_cnt_type = self.sps.poc_type,
                .log2_max_pic_order_cnt_lsb_minus4 = self.sps.log2_max_poc_lsb_minus4,
            },
            .frame_cropping_flag = @intFromBool(g.cropped()),
            .frame_crop_right_offset = g.crop_right,
            .frame_crop_bottom_offset = g.crop_bottom,
            .vui_parameters_present_flag = @intFromBool(self.sps.vui != null),
            .vui_fields = .{
                .bitstream_restriction_flag = 1,
                .log2_max_mv_length_horizontal = 16,
                .log2_max_mv_length_vertical = 16,
                .motion_vectors_over_pic_boundaries_flag = 1,
            },
        };
    }

    /// Parameter sets end in rbsp_trailing_bits (Mesa parses anything after as more_rbsp_data);
    /// the slice header is not byte aligned, so its exact bit length is passed.
    fn addPackedHeader(self: *Encoder, bufs: *BufList, kind: c_uint, ref_idc: u2, nal_type: bs.NalType, w: *const bs.BitWriter) Error!void {
        self.hdr.clearRetainingCapacity();
        const bit_len = try bs.appendNalBits(self.gpa, &self.hdr, ref_idc, nal_type, w);
        var param: c.VAEncPackedHeaderParameterBuffer = .{ .type = kind, .bit_length = @intCast(bit_len), .has_emulation_bytes = 1 };
        try bufs.add(c.VAEncPackedHeaderParameterBufferType, std.mem.asBytes(&param));
        try bufs.add(c.VAEncPackedHeaderDataBufferType, self.hdr.items);
    }

    fn readCoded(self: *Encoder, out: *std.ArrayList(u8)) Error!u8 {
        var p: ?*anyopaque = null;
        try vaCheck(c.vaMapBuffer(self.dpy, self.coded_buf, &p), "vaMapBuffer(coded)");
        defer _ = c.vaUnmapBuffer(self.dpy, self.coded_buf);
        var seg: ?*c.VACodedBufferSegment = @ptrCast(@alignCast(p));
        var avg_qp: u8 = 0;
        var first = true;
        while (seg) |s| : (seg = @ptrCast(@alignCast(s.next))) {
            if (first) avg_qp = @intCast(s.status & c.VA_CODED_BUF_STATUS_PICTURE_AVE_QP_MASK);
            first = false;
            if (s.status & c.VA_CODED_BUF_STATUS_SLICE_OVERFLOW_MASK != 0) {
                log.err("coded buffer overflow", .{});
                return error.BadEncoderOutput;
            }
            if (s.size == 0) continue;
            const data: [*]const u8 = @ptrCast(s.buf orelse return error.BadEncoderOutput);
            try out.appendSlice(self.gpa, data[0..s.size]);
        }
        return avg_qp;
    }

    fn verifyAccessUnit(self: *Encoder, au: []const u8, prev: bs.ParamSets, idr: bool, frame_num: u32, slice_type: bs.SliceType) Error!void {
        const info = bs.inspect(au, prev) catch |err| {
            log.err("unparsable encoder output: {t}", .{err});
            return error.BadEncoderOutput;
        };
        const ok = info.pictures == 1 and info.idr == idr and
            (!idr or (info.sps_count == 1 and info.pps_count == 1)) and
            info.first_slice != null and info.first_slice.?.frame_num == frame_num and
            info.first_slice.?.slice_type == @backingInt(slice_type) and
            (info.sps == null or info.sps.?.max_num_ref_frames == self.sps.max_num_ref_frames);
        if (!ok) {
            log.err("bad access unit: idr={} pictures={d} nals={d} sps={d} pps={d} other={d}", .{
                idr, info.pictures, info.nal_count, info.sps_count, info.pps_count, info.other_count,
            });
            return error.BadEncoderOutput;
        }
        if (info.sps) |s| {
            if (s.width != self.geo.width or s.height != self.geo.height or s.poc_type != self.sps.poc_type) {
                log.err("driver SPS mismatch: {d}x{d} poc {d}", .{ s.width, s.height, s.poc_type });
                return error.BadEncoderOutput;
            }
        }
    }
};

/// Per-picture VA buffers, destroyed after submission.
const BufList = struct {
    dpy: c.VADisplay,
    ctx: c.VAContextID,
    ids: [24]c.VABufferID = undefined,
    n: usize = 0,

    fn add(l: *BufList, kind: c_int, data: []const u8) Error!void {
        if (l.n == l.ids.len) return error.Vaapi;
        var id: c.VABufferID = c.VA_INVALID_ID;
        try vaCheck(c.vaCreateBuffer(l.dpy, l.ctx, @intCast(kind), @intCast(data.len), 1, @constCast(data.ptr), &id), "vaCreateBuffer");
        l.ids[l.n] = id;
        l.n += 1;
    }

    fn destroy(l: *BufList) void {
        for (l.ids[0..l.n]) |id| _ = c.vaDestroyBuffer(l.dpy, id);
        l.n = 0;
    }
};

fn createSurfaces(dpy: c.VADisplay, rt_format: c_int, fourcc: c_int, w: u32, h: u32, out: []c.VASurfaceID) Error!void {
    var attr = [_]c.VASurfaceAttrib{.{
        .type = c.VASurfaceAttribPixelFormat,
        .flags = c.VA_SURFACE_ATTRIB_SETTABLE,
        .value = .{ .type = c.VAGenericValueTypeInteger, .value = .{ .i = fourcc } },
    }};
    try vaCheck(c.vaCreateSurfaces(dpy, @intCast(rt_format), w, h, out.ptr, @intCast(out.len), &attr, attr.len), "vaCreateSurfaces");
}

fn vaCheck(st: c.VAStatus, what: []const u8) Error!void {
    if (st == c.VA_STATUS_SUCCESS) return;
    log.err("{s}: {s} (0x{x})", .{ what, std.mem.span(c.vaErrorStr(st)), st });
    return error.Vaapi;
}

fn unsupported(what: []const u8) Error {
    log.err("VA driver does not support {s}", .{what});
    return error.Unsupported;
}

fn vaErrorCallback(_: ?*anyopaque, msg: [*c]const u8) callconv(.c) void {
    log.warn("libva: {s}", .{std.mem.trimEnd(u8, std.mem.span(msg), "\n")});
}

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// GPU tests, skipped without a render node.

const testing = std.testing;

fn haveGpu() bool {
    return c.access("/dev/dri/renderD128", c.R_OK | c.W_OK) == 0;
}

fn fillTestFrame(buf: []u8, w: u32, h: u32, frame: u32) void {
    for (0..h) |y| for (0..w) |x| {
        const p = buf[(y * w + x) * 4 ..][0..4];
        const in_box = x >= frame * 8 and x < frame * 8 + 64 and y >= 40 and y < 104;
        p.* = if (in_box) .{ 0x20, 0x40, 0xe0, 0 } else .{ @truncate(x), @truncate(y), @truncate(x ^ y), 0 };
    };
}

test "GPU: odd-macroblock size, IDR on demand, cropping, one picture per AU" {
    if (!haveGpu()) return error.SkipZigTest;
    const gpa = testing.allocator;
    const w: u32 = 978;
    const h: u32 = 644;
    var enc = Encoder.init(gpa, .{ .width = w, .height = h, .bitrate = 4_000_000, .conversion = .fused, .verify = true }) catch |err| switch (err) {
        error.Unsupported, error.VaInit, error.OpenDevice => return error.SkipZigTest,
        else => return err,
    };
    defer enc.deinit();
    const pixels = try gpa.alloc(u8, w * h * 4);
    defer gpa.free(pixels);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    var params: bs.ParamSets = .{};
    var prev_idr_id: ?u32 = null;
    for (0..8) |i| {
        fillTestFrame(pixels, w, h, @intCast(i));
        if (i == 3) enc.setBitrate(2_000_000);
        out.clearRetainingCapacity();
        const fi = try enc.encode(pixels, w * 4, i == 5, &out);
        const au = try bs.inspect(out.items, params);
        params = au.params;
        try testing.expectEqual(au.first_slice.?.qp.?, fi.avg_qp);
        try testing.expectEqual(@as(u32, 1), au.pictures);
        try testing.expectEqual(@as(u32, 0), au.other_count);
        const expect_idr = i == 0 or i == 5;
        try testing.expectEqual(expect_idr, fi.idr);
        try testing.expectEqual(expect_idr, au.idr);
        try testing.expectEqual(@as(u32, if (expect_idr) 1 else 0), au.sps_count);
        try testing.expectEqual(@as(u32, if (expect_idr) 1 else 0), au.pps_count);
        const fs = au.first_slice.?;
        try testing.expectEqual(@as(u32, @intCast(if (i < 5) i else i - 5)), fs.frame_num);
        try testing.expectEqual(@as(u32, if (expect_idr) 2 else 0), fs.slice_type);
        if (fs.idr_pic_id) |id| {
            if (prev_idr_id) |p| try testing.expect(p != id);
            prev_idr_id = id;
        }
        if (au.sps) |s| {
            try testing.expectEqual(w, s.width);
            try testing.expectEqual(h, s.height);
            try testing.expectEqual(@as(u32, 62), s.width_mbs);
            try testing.expectEqual(@as(u32, 41), s.height_mbs);
            try testing.expectEqual(@as(u8, 100), s.profile_idc);
            try testing.expectEqual(@as(u32, 2), s.poc_type);
            try testing.expectEqual(@as(u32, 1), s.max_num_ref_frames);
            try testing.expectEqual(true, s.video_full_range.?);
            try testing.expectEqual(@as(u8, 1), s.colour.?[2]);
            try testing.expectEqual(@as(u32, 0), s.max_num_reorder_frames.?);
            const pps = au.pps.?;
            try testing.expect(pps.cabac and pps.extension and pps.transform_8x8);
            try testing.expectEqual(@as(?i32, 0), pps.second_chroma_qp_index_offset);
        }
        try testing.expect(fi.size > 0 and fi.size == out.items.len);
    }
}

test "GPU: 1080p main profile CQP and resize" {
    if (!haveGpu()) return error.SkipZigTest;
    const gpa = testing.allocator;
    var enc = Encoder.init(gpa, .{ .width = 1920, .height = 1080, .profile = .main, .rate_control = .cqp, .qp = 30, .conversion = .vpp, .verify = true }) catch |err| switch (err) {
        error.Unsupported, error.VaInit, error.OpenDevice => return error.SkipZigTest,
        else => return err,
    };
    defer enc.deinit();
    const pixels = try gpa.alloc(u8, 1920 * 1080 * 4);
    defer gpa.free(pixels);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    fillTestFrame(pixels, 1920, 1080, 0);
    var fi = try enc.encode(pixels, 1920 * 4, false, &out);
    try testing.expect(fi.idr);
    const au = try bs.inspect(out.items, .{});
    try testing.expectEqual(@as(u8, 77), au.sps.?.profile_idc);
    // Main decoders ignore a High PPS tail, so a stray one would desync them.
    try testing.expect(au.pps.?.cabac and !au.pps.?.extension and !au.pps.?.transform_8x8);
    try testing.expectEqual(@as(u32, 1080), au.sps.?.height);
    try testing.expectEqual(@as(u32, 68), au.sps.?.height_mbs);
    try testing.expectEqual(@as(u8, 30), fi.avg_qp);

    try enc.resize(1280, 800);
    out.clearRetainingCapacity();
    fi = try enc.encode(pixels, 1280 * 4, false, &out);
    try testing.expect(fi.idr);
    const au2 = try bs.inspect(out.items, .{});
    try testing.expectEqual(@as(u32, 1280), au2.sps.?.width);
    try testing.expectEqual(@as(u32, 800), au2.sps.?.height);
    try testing.expect(!au2.sps.?.timing_info);
}

test "GPU: AVC444 views in one stream, same-view references, LC 1 / LC 2, IDR codes both views" {
    if (!haveGpu()) return error.SkipZigTest;
    const gpa = testing.allocator;
    const w: u32 = 1366;
    const h: u32 = 768;
    for ([_]avc444.Version{ .v1, .v2 }) |ver| {
        var enc = Encoder.init(gpa, .{ .width = w, .height = h, .bitrate = 8_000_000, .avc444 = ver, .verify = true }) catch |err| switch (err) {
            error.Unsupported, error.VaInit, error.OpenDevice => return error.SkipZigTest,
            else => return err,
        };
        defer enc.deinit();
        try testing.expectEqual(@as(u32, 1376), enc.geo.width);
        try testing.expectEqual(@as(u32, 768), enc.geo.height);
        const pixels = try gpa.alloc(u8, w * h * 4);
        defer gpa.free(pixels);
        var main: std.ArrayList(u8) = .empty;
        defer main.deinit(gpa);
        var aux: std.ArrayList(u8) = .empty;
        defer aux.deinit(gpa);
        fillTestFrame(pixels, w, h, 0);
        var params: bs.ParamSets = .{};
        var fi = try enc.encode444(pixels, w * 4, false, .luma, &main, &aux);
        try testing.expect(fi.main.?.idr and fi.aux != null and !fi.aux.?.idr);
        var au = try bs.inspect(main.items, params);
        params = au.params;
        try testing.expectEqual(@as(u32, 2), au.sps.?.max_num_ref_frames);
        try testing.expectEqual(@as(u32, 0), au.first_slice.?.frame_num);
        au = try bs.inspect(aux.items, params);
        try testing.expectEqual(@as(u32, 2), au.first_slice.?.slice_type); // intra: no aux reference yet
        try testing.expectEqual(@as(u32, 1), au.first_slice.?.frame_num);
        const idr_size = fi.main.?.size + fi.aux.?.size;
        for (0..3) |_| {
            main.clearRetainingCapacity();
            aux.clearRetainingCapacity();
            fi = try enc.encode444(pixels, w * 4, false, .both, &main, &aux);
            const m = try bs.inspect(main.items, params);
            const a = try bs.inspect(aux.items, params);
            try testing.expectEqual(@as(u32, 0), m.first_slice.?.slice_type);
            try testing.expectEqual(@as(?u32, 1), m.first_slice.?.l0_abs_diff_pic_num_minus1);
            try testing.expectEqual(@as(?u32, 1), a.first_slice.?.l0_abs_diff_pic_num_minus1);
            // Cross-view prediction would cost about an intra picture.
            try testing.expect(fi.main.?.size + fi.aux.?.size < idr_size / 4);
        }
        // The owed chroma after LC 1 frames is intra: the DPB has no aux picture.
        for (0..2) |i| {
            main.clearRetainingCapacity();
            fillTestFrame(pixels, w, h, @intCast(i + 1));
            fi = try enc.encode444(pixels, w * 4, false, .luma, &main, &aux);
            try testing.expect(fi.aux == null);
        }
        aux.clearRetainingCapacity();
        fi = try enc.encode444(pixels, w * 4, false, .chroma, &main, &aux);
        try testing.expect(fi.main == null);
        try testing.expectEqual(@as(u32, 2), (try bs.inspect(aux.items, params)).first_slice.?.slice_type);
        main.clearRetainingCapacity();
        aux.clearRetainingCapacity();
        fi = try enc.encode444(pixels, w * 4, true, .chroma, &main, &aux);
        try testing.expect(fi.main.?.idr and fi.aux != null);
        try testing.expectError(error.BadInput, enc.encode(pixels, w * 4, false, &main));
        try testing.expectError(error.BadInput, enc.encode444(pixels, w * 4 - 4, false, .both, &main, &aux));
        try testing.expectError(error.BadInput, enc.encode444(pixels[0 .. pixels.len - 1], w * 4, false, .both, &main, &aux));
    }
}

test "GPU: AVC444 at 1710x1074: v2 views coded 1728x1088 (32 wide), v1 1712x1088, uncropped" {
    if (!haveGpu()) return error.SkipZigTest;
    const gpa = testing.allocator;
    const w: u32 = 1710;
    const h: u32 = 1074;
    const pixels = try gpa.alloc(u8, w * h * 4);
    defer gpa.free(pixels);
    fillTestFrame(pixels, w, h, 0);
    for ([_]avc444.Version{ .v1, .v2 }, [_]u32{ 1712, 1728 }) |ver, coded_w| {
        var enc = Encoder.init(gpa, .{ .width = w, .height = h, .bitrate = 8_000_000, .avc444 = ver, .verify = true }) catch |err| switch (err) {
            error.Unsupported, error.VaInit, error.OpenDevice => return error.SkipZigTest,
            else => return err,
        };
        defer enc.deinit();
        var main: std.ArrayList(u8) = .empty;
        defer main.deinit(gpa);
        var aux: std.ArrayList(u8) = .empty;
        defer aux.deinit(gpa);
        _ = try enc.encode444(pixels, w * 4, false, .both, &main, &aux);
        const sps = (try bs.inspect(main.items, .{})).sps.?;
        try testing.expectEqual(coded_w / 16, sps.width_mbs);
        try testing.expectEqual(@as(u32, 1088 / 16), sps.height_mbs);
        try testing.expectEqual(coded_w, sps.width);
        try testing.expectEqual(@as(u32, 1088), sps.height);
    }
}
