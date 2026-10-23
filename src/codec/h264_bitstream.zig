//! H.264 bitstream helpers for the VAAPI encoder: RBSP writer, Annex-B packaging, SPS/PPS/
//! slice header writers (7.3.2, 7.3.3, E.1.1), geometry, levels (Table A-1) and parsers.
//! Mesa re-emits SPS/PPS from the packed headers, iHD inserts them verbatim.

const std = @import("std");

pub const Error = error{ BitWriterOverflow, BadBitstream, OddDimension, BadDimension };

pub const NalType = enum(u5) {
    slice = 1,
    idr = 5,
    sei = 6,
    sps = 7,
    pps = 8,
    aud = 9,
    filler = 12,
    _,
};

pub const profile_idc_baseline: u8 = 66;
pub const profile_idc_main: u8 = 77;
pub const profile_idc_high: u8 = 100;

pub const Profile = enum {
    constrained_baseline,
    main,
    high,

    pub fn idc(p: Profile) u8 {
        return switch (p) {
            .constrained_baseline => profile_idc_baseline,
            .main => profile_idc_main,
            .high => profile_idc_high,
        };
    }

    /// constraint_set0..5 flags, constraint_set0_flag in the MSB.
    pub fn constraintByte(p: Profile) u8 {
        return switch (p) {
            // Constrained Baseline = Baseline with constraint_set0 and set1.
            .constrained_baseline => 0x80 | 0x40,
            .main => 0x40,
            .high => 0,
        };
    }

    pub fn cabac(p: Profile) bool {
        return p != .constrained_baseline;
    }
};

/// MSB-first RBSP writer over a fixed buffer (headers are < 100 bytes).
pub const BitWriter = struct {
    buf: [256]u8 = @splat(0),
    bit_len: usize = 0,

    pub fn bits(w: *BitWriter, value: u64, n: u7) Error!void {
        var i: u7 = n;
        while (i > 0) {
            i -= 1;
            const bit: u8 = @intCast((value >> @intCast(i)) & 1);
            const byte_index = w.bit_len / 8;
            if (byte_index >= w.buf.len) return error.BitWriterOverflow;
            if (bit != 0) w.buf[byte_index] |= @as(u8, 0x80) >> @intCast(w.bit_len % 8);
            w.bit_len += 1;
        }
    }

    pub fn flag(w: *BitWriter, b: bool) Error!void {
        try w.bits(@intFromBool(b), 1);
    }

    /// Unsigned Exp-Golomb, ue(v) (9.1).
    pub fn ue(w: *BitWriter, v: u32) Error!void {
        const x: u64 = @as(u64, v) + 1;
        const len: u7 = @intCast(64 - @clz(x)); // bits in x
        try w.bits(0, len - 1);
        try w.bits(x, len);
    }

    /// Signed Exp-Golomb, se(v) (9.1.1): k>0 -> 2k-1, k<=0 -> -2k.
    pub fn se(w: *BitWriter, v: i32) Error!void {
        const mapped: u32 = if (v > 0) @intCast(2 * @as(i64, v) - 1) else @intCast(-2 * @as(i64, v));
        try w.ue(mapped);
    }

    /// rbsp_trailing_bits(): stop bit then zero bits to the byte boundary.
    pub fn trailing(w: *BitWriter) Error!void {
        try w.bits(1, 1);
        while (w.bit_len % 8 != 0) try w.bits(0, 1);
    }

    pub fn byteAligned(w: *const BitWriter) bool {
        return w.bit_len % 8 == 0;
    }

    /// Written bytes; a partial last byte is zero-padded.
    pub fn bytes(w: *const BitWriter) []const u8 {
        return w.buf[0 .. (w.bit_len + 7) / 8];
    }
};

/// Annex-B start code, NAL header and escaped payload (7.4.1); returns bytes appended.
pub fn appendNal(gpa: std.mem.Allocator, out: *std.ArrayList(u8), nal_ref_idc: u2, nal_type: NalType, rbsp: []const u8) !usize {
    const n = try appendNalPart(gpa, out, nal_ref_idc, nal_type, rbsp);
    // 7.4.1: an RBSP ending in 00 00 gets a final 0x03, or B.2 strips it as
    // trailing_zero_8bits. A lone trailing 0x00 is not a valid RBSP end.
    const esc = out.items[out.items.len - (n - 5) ..];
    if (esc.len >= 2 and esc[esc.len - 1] == 0 and esc[esc.len - 2] == 0) {
        try out.append(gpa, 3);
        return n + 1;
    }
    return n;
}

/// `appendNal` without the final 0x03, for an RBSP that continues elsewhere.
fn appendNalPart(gpa: std.mem.Allocator, out: *std.ArrayList(u8), nal_ref_idc: u2, nal_type: NalType, rbsp: []const u8) !usize {
    const start = out.items.len;
    try out.appendSlice(gpa, &.{ 0, 0, 0, 1, @as(u8, nal_ref_idc) << 5 | @backingInt(nal_type) });
    var zeros: u8 = 0;
    for (rbsp) |b| {
        if (zeros >= 2 and b <= 3) {
            try out.append(gpa, 3);
            zeros = 0;
        }
        try out.append(gpa, b);
        zeros = if (b == 0) zeros + 1 else 0;
    }
    return out.items.len - start;
}

/// Returns the NAL length in bits for VAEncPackedHeaderParameterBuffer.bit_length;
/// a partial last byte counts only its written bits.
pub fn appendNalBits(gpa: std.mem.Allocator, out: *std.ArrayList(u8), nal_ref_idc: u2, nal_type: NalType, w: *const BitWriter) !usize {
    const n = try appendNalPart(gpa, out, nal_ref_idc, nal_type, w.bytes());
    const tail_bits = w.bit_len % 8;
    return if (tail_bits == 0) n * 8 else (n - 1) * 8 + tail_bits;
}

/// Remove emulation_prevention_three_bytes; `out` must hold `escaped.len`.
pub fn unescape(escaped: []const u8, out: []u8) []u8 {
    var n: usize = 0;
    var zeros: u8 = 0;
    for (escaped) |b| {
        if (zeros >= 2 and b == 3) {
            zeros = 0;
            continue;
        }
        out[n] = b;
        n += 1;
        // Saturating: an invalid stream may have any run of zeros (7.4.1).
        zeros = if (b == 0) zeros +| 1 else 0;
    }
    return out[0..n];
}

/// SPS crop offsets are in 2-sample units for 4:2:0 (7.4.2.1.1), so cropping needs even sizes.
pub const Geometry = struct {
    /// Visible (decoded) size.
    width: u16,
    height: u16,
    width_mbs: u16,
    height_mbs: u16,
    /// frame_crop_right/bottom_offset in 2-sample units; left/top are always 0.
    crop_right: u16,
    crop_bottom: u16,

    /// `crop` signals the exact size via SPS cropping; otherwise the size is 16-aligned.
    pub fn init(width: u32, height: u32, crop: bool) Error!Geometry {
        if (width == 0 or height == 0 or width > 16384 or height > 16384) return error.BadDimension;
        // Uncropped streams are cut by the RDPGFX region mask (MS-RDPEGFX 2.2.4.4).
        if (crop and (width % 2 != 0 or height % 2 != 0)) return error.OddDimension;
        const wm: u16 = @intCast((width + 15) / 16);
        const hm: u16 = @intCast((height + 15) / 16);
        return .{
            .width = if (crop) @intCast(width) else wm * 16,
            .height = if (crop) @intCast(height) else hm * 16,
            .width_mbs = wm,
            .height_mbs = hm,
            .crop_right = if (crop) @intCast((@as(u32, wm) * 16 - width) / 2) else 0,
            .crop_bottom = if (crop) @intCast((@as(u32, hm) * 16 - height) / 2) else 0,
        };
    }

    pub fn codedWidth(g: Geometry) u32 {
        return @as(u32, g.width_mbs) * 16;
    }

    pub fn codedHeight(g: Geometry) u32 {
        return @as(u32, g.height_mbs) * 16;
    }

    pub fn mbs(g: Geometry) u32 {
        return @as(u32, g.width_mbs) * g.height_mbs;
    }

    pub fn cropped(g: Geometry) bool {
        return g.crop_right != 0 or g.crop_bottom != 0;
    }
};

const LevelLimits = struct { idc: u8, max_mbps: u32, max_fs: u32, max_br: u32 };

/// MaxBR in 1000 bit/s (cpbBrVclFactor); High multiplies it by 1.25.
const levels = [_]LevelLimits{
    .{ .idc = 10, .max_mbps = 1485, .max_fs = 99, .max_br = 64 },
    .{ .idc = 11, .max_mbps = 3000, .max_fs = 396, .max_br = 192 },
    .{ .idc = 12, .max_mbps = 6000, .max_fs = 396, .max_br = 384 },
    .{ .idc = 13, .max_mbps = 11880, .max_fs = 396, .max_br = 768 },
    .{ .idc = 20, .max_mbps = 11880, .max_fs = 396, .max_br = 2000 },
    .{ .idc = 21, .max_mbps = 19800, .max_fs = 792, .max_br = 4000 },
    .{ .idc = 22, .max_mbps = 20250, .max_fs = 1620, .max_br = 4000 },
    .{ .idc = 30, .max_mbps = 40500, .max_fs = 1620, .max_br = 10000 },
    .{ .idc = 31, .max_mbps = 108000, .max_fs = 3600, .max_br = 14000 },
    .{ .idc = 32, .max_mbps = 216000, .max_fs = 5120, .max_br = 20000 },
    .{ .idc = 40, .max_mbps = 245760, .max_fs = 8192, .max_br = 20000 },
    .{ .idc = 41, .max_mbps = 245760, .max_fs = 8192, .max_br = 50000 },
    .{ .idc = 42, .max_mbps = 522240, .max_fs = 8704, .max_br = 50000 },
    .{ .idc = 50, .max_mbps = 589824, .max_fs = 22080, .max_br = 135000 },
    .{ .idc = 51, .max_mbps = 983040, .max_fs = 36864, .max_br = 240000 },
    .{ .idc = 52, .max_mbps = 2073600, .max_fs = 36864, .max_br = 240000 },
    .{ .idc = 60, .max_mbps = 4177920, .max_fs = 139264, .max_br = 240000 },
    .{ .idc = 61, .max_mbps = 8355840, .max_fs = 139264, .max_br = 480000 },
    .{ .idc = 62, .max_mbps = 16711680, .max_fs = 139264, .max_br = 800000 },
};

/// Lowest level_idc whose frame size, sqrt(8*MaxFS) per dimension, MB rate and bit rate fit.
pub fn chooseLevel(g: Geometry, fps: u32, peak_bitrate_bps: u64, profile: Profile) u8 {
    const fs: u64 = g.mbs();
    const factor: u64 = if (profile == .high) 1250 else 1000;
    for (levels) |l| {
        const dim_limit: u64 = @as(u64, l.max_fs) * 8;
        if (fs > l.max_fs) continue;
        if (@as(u64, g.width_mbs) * g.width_mbs > dim_limit) continue;
        if (@as(u64, g.height_mbs) * g.height_mbs > dim_limit) continue;
        if (fs * fps > l.max_mbps) continue;
        if (peak_bitrate_bps > @as(u64, l.max_br) * factor) continue;
        return l.idc;
    }
    return levels[levels.len - 1].idc;
}

pub const Vui = struct {
    /// MS-RDPEGFX 3.3.8.3.1 mandates full-range BT.709.
    full_range: bool = true,
    colour_primaries: u8 = 1, // BT.709
    transfer_characteristics: u8 = 13, // IEC 61966-2-1 (sRGB): desktop content
    matrix_coefficients: u8 = 1, // BT.709
    /// No reordering and a one-frame DPB: decoders output every picture at once.
    max_num_reorder_frames: u8 = 0,
    max_dec_frame_buffering: u8 = 1,
};

pub const Sps = struct {
    profile: Profile,
    level_idc: u8,
    geometry: Geometry,
    log2_max_frame_num_minus4: u4 = 4,
    /// 2: POC derived from frame_num; valid as every picture is a reference.
    poc_type: u2 = 2,
    log2_max_poc_lsb_minus4: u4 = 4,
    max_num_ref_frames: u8 = 1,
    vui: ?Vui = .{},

    pub fn maxFrameNum(s: Sps) u32 {
        return @as(u32, 1) << (@as(u5, s.log2_max_frame_num_minus4) + 4);
    }
};

pub fn writeSps(w: *BitWriter, s: Sps) Error!void {
    try w.bits(s.profile.idc(), 8);
    try w.bits(s.profile.constraintByte(), 8); // constraint_set0..5 + reserved_zero_2bits
    try w.bits(s.level_idc, 8);
    try w.ue(0); // seq_parameter_set_id
    if (s.profile == .high) {
        try w.ue(1); // chroma_format_idc: 4:2:0
        try w.ue(0); // bit_depth_luma_minus8
        try w.ue(0); // bit_depth_chroma_minus8
        try w.flag(false); // qpprime_y_zero_transform_bypass_flag
        try w.flag(false); // seq_scaling_matrix_present_flag
    }
    try w.ue(s.log2_max_frame_num_minus4);
    try w.ue(s.poc_type);
    if (s.poc_type == 0) try w.ue(s.log2_max_poc_lsb_minus4);
    std.debug.assert(s.poc_type != 1); // not supported by the writer
    try w.ue(s.max_num_ref_frames);
    try w.flag(false); // gaps_in_frame_num_value_allowed_flag
    try w.ue(s.geometry.width_mbs - 1);
    try w.ue(s.geometry.height_mbs - 1); // map units == MBs (frame_mbs_only)
    try w.flag(true); // frame_mbs_only_flag
    try w.flag(true); // direct_8x8_inference_flag
    try w.flag(s.geometry.cropped());
    if (s.geometry.cropped()) {
        try w.ue(0); // frame_crop_left_offset
        try w.ue(s.geometry.crop_right);
        try w.ue(0); // frame_crop_top_offset
        try w.ue(s.geometry.crop_bottom);
    }
    try w.flag(s.vui != null);
    if (s.vui) |v| {
        try w.flag(false); // aspect_ratio_info_present_flag (square pixels)
        try w.flag(false); // overscan_info_present_flag
        try w.flag(true); // video_signal_type_present_flag
        try w.bits(5, 3); // video_format: unspecified
        try w.flag(v.full_range);
        try w.flag(true); // colour_description_present_flag
        try w.bits(v.colour_primaries, 8);
        try w.bits(v.transfer_characteristics, 8);
        try w.bits(v.matrix_coefficients, 8);
        try w.flag(false); // chroma_loc_info_present_flag
        try w.flag(false); // timing_info_present_flag (variable frame rate)
        try w.flag(false); // nal_hrd_parameters_present_flag
        try w.flag(false); // vcl_hrd_parameters_present_flag
        try w.flag(false); // pic_struct_present_flag
        try w.flag(true); // bitstream_restriction_flag
        try w.flag(true); // motion_vectors_over_pic_boundaries_flag
        try w.ue(0); // max_bytes_per_pic_denom (no limit)
        try w.ue(0); // max_bits_per_mb_denom (no limit)
        try w.ue(16); // log2_max_mv_length_horizontal
        try w.ue(16); // log2_max_mv_length_vertical
        try w.ue(v.max_num_reorder_frames);
        try w.ue(@max(v.max_dec_frame_buffering, s.max_num_ref_frames));
    }
    try w.trailing();
}

pub const Pps = struct {
    cabac: bool,
    /// Writes the High PPS extension; only High may use 8x8 transforms.
    high: bool,
    transform_8x8: bool = true,
    pic_init_qp: u8 = 26,
    deblocking_control: bool = true,
};

pub fn writePps(w: *BitWriter, p: Pps) Error!void {
    try w.ue(0); // pic_parameter_set_id
    try w.ue(0); // seq_parameter_set_id
    try w.flag(p.cabac); // entropy_coding_mode_flag
    try w.flag(false); // bottom_field_pic_order_in_frame_present_flag
    try w.ue(0); // num_slice_groups_minus1
    try w.ue(0); // num_ref_idx_l0_default_active_minus1
    try w.ue(0); // num_ref_idx_l1_default_active_minus1
    try w.flag(false); // weighted_pred_flag
    try w.bits(0, 2); // weighted_bipred_idc
    try w.se(@as(i32, p.pic_init_qp) - 26); // pic_init_qp_minus26
    try w.se(0); // pic_init_qs_minus26
    try w.se(0); // chroma_qp_index_offset
    try w.flag(p.deblocking_control); // deblocking_filter_control_present_flag
    try w.flag(false); // constrained_intra_pred_flag
    try w.flag(false); // redundant_pic_cnt_present_flag
    if (p.high) {
        try w.flag(p.transform_8x8);
        try w.flag(false); // pic_scaling_matrix_present_flag
        try w.se(0); // second_chroma_qp_index_offset
    }
    try w.trailing();
}

pub const SliceType = enum(u8) { p = 0, i = 2 };

pub const SliceHeader = struct {
    idr: bool,
    slice_type: SliceType,
    first_mb: u32 = 0,
    frame_num: u32,
    idr_pic_id: u16 = 0,
    poc_lsb: u32 = 0,
    /// slice_qp_delta, relative to the PPS pic_init_qp.
    qp_delta: i32 = 0,
    /// P slices: the picture `value + 1` back goes first in RefPicList0 (7.3.3.1).
    l0_abs_diff_pic_num_minus1: ?u32 = null,

    pub fn nalType(h: SliceHeader) NalType {
        return if (h.idr) .idr else .slice;
    }

    /// Every picture is a reference picture (I/P only).
    pub fn nalRefIdc(h: SliceHeader) u2 {
        return if (h.idr) 3 else 2;
    }
};

/// slice_header() (7.3.3), not byte aligned; slice_type is coded as type+5.
pub fn writeSliceHeader(w: *BitWriter, s: Sps, p: Pps, h: SliceHeader) Error!void {
    try w.ue(h.first_mb);
    try w.ue(@backingInt(h.slice_type) + 5);
    try w.ue(0); // pic_parameter_set_id
    try w.bits(h.frame_num & (s.maxFrameNum() - 1), @as(u7, s.log2_max_frame_num_minus4) + 4);
    if (h.idr) try w.ue(h.idr_pic_id);
    if (s.poc_type == 0) try w.bits(h.poc_lsb, @as(u7, s.log2_max_poc_lsb_minus4) + 4);
    if (h.slice_type == .p) {
        try w.flag(false); // num_ref_idx_active_override_flag
        try w.flag(h.l0_abs_diff_pic_num_minus1 != null); // ref_pic_list_modification_flag_l0
        if (h.l0_abs_diff_pic_num_minus1) |d| {
            try w.ue(0); // modification_of_pic_nums_idc: subtract from picNumPred
            try w.ue(d);
            try w.ue(3); // end of the list
        }
    }
    // dec_ref_pic_marking() (nal_ref_idc != 0 always)
    if (h.idr) {
        try w.flag(false); // no_output_of_prior_pics_flag
        try w.flag(false); // long_term_reference_flag
    } else {
        try w.flag(false); // adaptive_ref_pic_marking_mode_flag: sliding window
    }
    if (p.cabac and h.slice_type != .i) try w.ue(0); // cabac_init_idc
    try w.se(h.qp_delta);
    if (p.deblocking_control) {
        try w.ue(0); // disable_deblocking_filter_idc: filter on
        try w.se(0); // slice_alpha_c0_offset_div2
        try w.se(0); // slice_beta_offset_div2
    }
}

pub const BitReader = struct {
    data: []const u8,
    pos: usize = 0, // in bits of `data`
    /// Skip emulation_prevention_three_bytes (7.4.1) while reading.
    escaped: bool = false,

    pub fn bits(r: *BitReader, n: u7) Error!u64 {
        var v: u64 = 0;
        var i: u7 = 0;
        while (i < n) : (i += 1) {
            if (r.escaped and r.pos % 8 == 0) r.skipEpb();
            if (r.pos / 8 >= r.data.len) return error.BadBitstream;
            const bit = (r.data[r.pos / 8] >> @intCast(7 - r.pos % 8)) & 1;
            v = v << 1 | bit;
            r.pos += 1;
        }
        return v;
    }

    pub fn flag(r: *BitReader) Error!bool {
        return try r.bits(1) != 0;
    }

    pub fn ue(r: *BitReader) Error!u32 {
        var zeros: u7 = 0;
        while (try r.bits(1) == 0) {
            zeros += 1;
            if (zeros > 31) return error.BadBitstream;
        }
        const rest = try r.bits(zeros);
        return @intCast((@as(u64, 1) << @intCast(zeros)) - 1 + rest);
    }

    pub fn se(r: *BitReader) Error!i32 {
        const k = try r.ue();
        const mag: i32 = @intCast((k + 1) / 2);
        return if (k % 2 == 1) mag else -mag;
    }

    /// Steps over a 0x03 after two zero bytes at a byte boundary.
    fn skipEpb(r: *BitReader) void {
        const i = r.pos / 8;
        if (i >= 2 and i < r.data.len and r.data[i] == 3 and r.data[i - 1] == 0 and r.data[i - 2] == 0) r.pos += 8;
    }
};

pub const Nal = struct {
    ref_idc: u2,
    nal_type: NalType,
    payload: []const u8,
};

/// Annex-B NAL units; trailing_zero_8bits are stripped.
pub const NalIterator = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn next(it: *NalIterator) Error!?Nal {
        const start = findStartCode(it.data, it.pos) orelse {
            if (it.pos == 0 and it.data.len > 0) return error.BadBitstream;
            return null;
        };
        const body = start + 3;
        if (body >= it.data.len) return error.BadBitstream;
        var end = if (findStartCode(it.data, body)) |n| n else it.data.len;
        it.pos = end;
        while (end > body and it.data[end - 1] == 0) end -= 1;
        // B.2: a start code must be followed by at least a NAL header byte.
        if (end == body) return error.BadBitstream;
        const hdr = it.data[body];
        if (hdr & 0x80 != 0) return error.BadBitstream; // forbidden_zero_bit
        return .{
            .ref_idc = @intCast(hdr >> 5 & 3),
            .nal_type = @fromBackingInt(@intCast(hdr & 0x1f)),
            .payload = it.data[body + 1 .. end],
        };
    }

    pub fn findStartCode(d: []const u8, from: usize) ?usize {
        var i = from;
        while (i + 2 < d.len) : (i += 1) {
            if (d[i] == 0 and d[i + 1] == 0 and d[i + 2] == 1) return i;
        }
        return null;
    }
};

pub const SpsInfo = struct {
    profile_idc: u8,
    constraint_flags: u8,
    level_idc: u8,
    chroma_format_idc: u32 = 1,
    separate_colour_plane: bool = false,
    log2_max_frame_num: u32,
    poc_type: u32,
    log2_max_poc_lsb: u32 = 0,
    max_num_ref_frames: u32,
    width_mbs: u32,
    height_mbs: u32,
    frame_mbs_only: bool,
    crop: [4]u32 = .{ 0, 0, 0, 0 }, // left, right, top, bottom (crop units)
    /// Decoded (cropped) size in luma samples.
    width: u32,
    height: u32,
    vui_present: bool = false,
    video_full_range: ?bool = null,
    colour: ?[3]u8 = null, // primaries, transfer, matrix
    timing_info: bool = false,
    max_num_reorder_frames: ?u32 = null,
    max_dec_frame_buffering: ?u32 = null,
};

/// Sqrt(MaxFS * 8) for the largest MaxFS of Table A-1 (139264, level 6.x).
const max_mbs_per_dim = 1055;

/// Parse an SPS RBSP (unescaped, without the NAL header byte).
pub fn parseSps(rbsp: []const u8) Error!SpsInfo {
    var r = BitReader{ .data = rbsp };
    const profile: u8 = @intCast(try r.bits(8));
    const constraint: u8 = @intCast(try r.bits(8));
    const level: u8 = @intCast(try r.bits(8));
    // Value ranges are 7.4.2.1.1's; out of range is malformed.
    if (try r.ue() > 31) return error.BadBitstream; // seq_parameter_set_id
    var chroma_format_idc: u32 = 1;
    var separate_colour_plane = false;
    switch (profile) {
        100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135 => {
            chroma_format_idc = try r.ue();
            if (chroma_format_idc > 3) return error.BadBitstream;
            if (chroma_format_idc == 3) separate_colour_plane = try r.flag();
            if (try r.ue() > 6) return error.BadBitstream; // bit_depth_luma_minus8
            if (try r.ue() > 6) return error.BadBitstream; // bit_depth_chroma_minus8
            _ = try r.bits(1); // qpprime_y_zero_transform_bypass_flag
            if (try r.flag()) return error.BadBitstream; // scaling lists unsupported here
        },
        else => {},
    }
    const log2_max_frame_num_minus4 = try r.ue();
    if (log2_max_frame_num_minus4 > 12) return error.BadBitstream;
    const poc_type = try r.ue();
    if (poc_type > 2) return error.BadBitstream;
    var log2_max_poc_lsb: u32 = 0;
    if (poc_type == 0) {
        const lsb_minus4 = try r.ue();
        if (lsb_minus4 > 12) return error.BadBitstream;
        log2_max_poc_lsb = lsb_minus4 + 4;
    } else if (poc_type == 1) {
        _ = try r.bits(1); // delta_pic_order_always_zero_flag
        _ = try r.se(); // offset_for_non_ref_pic
        _ = try r.se(); // offset_for_top_to_bottom_field
        const n = try r.ue(); // num_ref_frames_in_pic_order_cnt_cycle
        if (n > 255) return error.BadBitstream;
        for (0..n) |_| _ = try r.se();
    }
    const max_refs = try r.ue();
    if (max_refs > 16) return error.BadBitstream; // MaxDpbFrames <= 16 (A.3.1)
    _ = try r.bits(1); // gaps_in_frame_num_value_allowed_flag
    const wm = @as(u64, try r.ue()) + 1;
    const hmu = @as(u64, try r.ue()) + 1;
    const frame_mbs_only = try r.flag();
    // A.3.1: at most Sqrt(MaxFS * 8) macroblocks per dimension.
    const hm = hmu * @as(u64, if (frame_mbs_only) 1 else 2);
    if (wm > max_mbs_per_dim or hm > max_mbs_per_dim) return error.BadBitstream;
    if (!frame_mbs_only) _ = try r.bits(1);
    _ = try r.bits(1); // direct_8x8_inference_flag
    var info = SpsInfo{
        .profile_idc = profile,
        .constraint_flags = constraint,
        .level_idc = level,
        .chroma_format_idc = chroma_format_idc,
        .separate_colour_plane = separate_colour_plane,
        .log2_max_frame_num = log2_max_frame_num_minus4 + 4,
        .poc_type = poc_type,
        .log2_max_poc_lsb = log2_max_poc_lsb,
        .max_num_ref_frames = max_refs,
        .width_mbs = @intCast(wm),
        .height_mbs = @intCast(hm),
        .frame_mbs_only = frame_mbs_only,
        .width = 0,
        .height = 0,
    };
    if (try r.flag()) {
        for (&info.crop) |*c| c.* = try r.ue();
    }
    // CropUnitX/Y: 7.4.2.1.1, Table 6-1.
    const chroma_array_type: u32 = if (separate_colour_plane) 0 else chroma_format_idc;
    const crop_x: u64 = if (chroma_array_type == 1 or chroma_array_type == 2) 2 else 1;
    const crop_y: u64 = (if (chroma_array_type == 1) @as(u64, 2) else 1) * (if (frame_mbs_only) @as(u64, 1) else 2);
    const cut_x = crop_x * (@as(u64, info.crop[0]) + info.crop[1]);
    const cut_y = crop_y * (@as(u64, info.crop[2]) + info.crop[3]);
    // At least one crop unit must remain.
    if (cut_x >= wm * 16 or cut_y >= hm * 16) return error.BadBitstream;
    info.width = @intCast(wm * 16 - cut_x);
    info.height = @intCast(hm * 16 - cut_y);
    info.vui_present = try r.flag();
    if (info.vui_present) {
        if (try r.flag()) { // aspect_ratio_info_present_flag
            if (try r.bits(8) == 255) _ = try r.bits(32);
        }
        if (try r.flag()) _ = try r.bits(1); // overscan
        if (try r.flag()) { // video_signal_type_present_flag
            _ = try r.bits(3);
            info.video_full_range = try r.flag();
            if (try r.flag()) {
                info.colour = .{ @intCast(try r.bits(8)), @intCast(try r.bits(8)), @intCast(try r.bits(8)) };
            }
        }
        if (try r.flag()) { // chroma_loc_info_present_flag
            _ = try r.ue();
            _ = try r.ue();
        }
        info.timing_info = try r.flag();
        if (info.timing_info) {
            _ = try r.bits(32);
            _ = try r.bits(32);
            _ = try r.bits(1);
        }
        const nal_hrd = try r.flag();
        if (nal_hrd) try skipHrd(&r);
        const vcl_hrd = try r.flag();
        if (vcl_hrd) try skipHrd(&r);
        if (nal_hrd or vcl_hrd) _ = try r.bits(1); // low_delay_hrd_flag
        _ = try r.bits(1); // pic_struct_present_flag
        if (try r.flag()) { // bitstream_restriction_flag
            _ = try r.bits(1);
            _ = try r.ue();
            _ = try r.ue();
            _ = try r.ue();
            _ = try r.ue();
            info.max_num_reorder_frames = try r.ue();
            info.max_dec_frame_buffering = try r.ue();
        }
    }
    return info;
}

fn skipHrd(r: *BitReader) Error!void {
    const cnt = try r.ue() + 1;
    _ = try r.bits(8);
    for (0..cnt) |_| {
        _ = try r.ue();
        _ = try r.ue();
        _ = try r.bits(1);
    }
    _ = try r.bits(20);
}

pub const PpsInfo = struct {
    id: u8 = 0,
    sps_id: u8 = 0,
    cabac: bool,
    bottom_field_pic_order_in_frame_present: bool,
    num_ref_idx_l0_default_active_minus1: u32,
    weighted_pred: bool,
    pic_init_qp: i32,
    deblocking_control: bool,
    redundant_pic_cnt_present: bool,
    /// The High-profile tail is present.
    extension: bool = false,
    transform_8x8: bool = false,
    second_chroma_qp_index_offset: ?i32 = null,
};

/// Parse a PPS RBSP (unescaped, without the NAL header byte); slice groups are rejected.
pub fn parsePps(rbsp: []const u8) Error!PpsInfo {
    var r = BitReader{ .data = rbsp };
    // Value ranges are 7.4.2.2's; out of range is malformed.
    const id = try r.ue();
    if (id > 255) return error.BadBitstream;
    const sps_id = try r.ue();
    if (sps_id > 31) return error.BadBitstream;
    const cabac = try r.flag();
    const bottom = try r.flag();
    if (try r.ue() != 0) return error.BadBitstream; // num_slice_groups_minus1
    const l0 = try r.ue();
    if (l0 > 31 or try r.ue() > 31) return error.BadBitstream; // num_ref_idx_l0/l1_default_active_minus1
    const wp = try r.flag();
    if (try r.bits(2) == 3) return error.BadBitstream; // weighted_bipred_idc: 0..2
    // pic_init_qp_minus26 >= -(26 + 36): QpBdOffsetY is not known without the SPS.
    const qp_minus26 = try r.se();
    if (qp_minus26 < -(26 + 36) or qp_minus26 > 25) return error.BadBitstream;
    const qs_minus26 = try r.se();
    if (qs_minus26 < -26 or qs_minus26 > 25) return error.BadBitstream;
    const chroma_qp_index_offset = try r.se();
    if (chroma_qp_index_offset < -12 or chroma_qp_index_offset > 12) return error.BadBitstream;
    var info = PpsInfo{
        .id = @intCast(id),
        .sps_id = @intCast(sps_id),
        .cabac = cabac,
        .bottom_field_pic_order_in_frame_present = bottom,
        .num_ref_idx_l0_default_active_minus1 = l0,
        .weighted_pred = wp,
        .pic_init_qp = 26 + qp_minus26,
        .deblocking_control = try r.flag(),
        .redundant_pic_cnt_present = blk: {
            _ = try r.flag(); // constrained_intra_pred_flag
            break :blk try r.flag();
        },
    };
    // more_rbsp_data(): anything but the stop bit and zero padding left?
    if (moreRbspData(&r)) {
        info.extension = true;
        info.transform_8x8 = try r.flag();
        if (try r.flag()) return error.BadBitstream; // scaling matrices: unsupported here
        const second = try r.se();
        if (second < -12 or second > 12) return error.BadBitstream;
        info.second_chroma_qp_index_offset = second;
    }
    if (moreRbspData(&r)) return error.BadBitstream; // junk before the stop bit
    return info;
}

fn moreRbspData(r: *const BitReader) bool {
    const total = r.data.len * 8;
    if (r.pos >= total) return false;
    var last: usize = total; // position of the last 1 bit (the stop bit)
    while (last > r.pos) {
        last -= 1;
        if ((r.data[last / 8] >> @intCast(7 - last % 8)) & 1 != 0) break;
    }
    return last > r.pos;
}

pub const ParamSets = struct {
    sps: ?SpsInfo = null,
    pps: ?PpsInfo = null,
    /// Each slice names the PPS in use (7.4.1.2.1, 7.4.3).
    pps_by_id: [256]?PpsInfo = @splat(null),

    pub fn putPps(ps: *ParamSets, p: PpsInfo) void {
        ps.pps = p;
        ps.pps_by_id[p.id] = p;
    }

    pub fn ppsFor(ps: *const ParamSets, id: u32) ?PpsInfo {
        if (id < ps.pps_by_id.len) {
            if (ps.pps_by_id[id]) |p| return p;
        }
        // `pps` set directly rather than through putPps.
        if (ps.pps) |p| if (p.id == id) return p;
        return null;
    }
};

/// The pic_parameter_set_id a slice names (7.3.3).
pub fn slicePpsId(nal: Nal) Error!u32 {
    var r = BitReader{ .data = nal.payload, .escaped = true };
    _ = try r.ue(); // first_mb_in_slice
    _ = try r.ue(); // slice_type
    const id = try r.ue();
    if (id > 255) return error.BadBitstream; // 7.4.3
    return id;
}

pub const SliceInfo = struct {
    first_mb: u32,
    slice_type: u32, // 0..4 (type % 5)
    frame_num: u32,
    idr_pic_id: ?u32,
    /// SliceQPY = 26 + pic_init_qp_minus26 + slice_qp_delta (needs the PPS).
    qp: ?u8 = null,
    /// abs_diff_pic_num_minus1 of a single "subtract" RefPicList0 modification, the form
    /// `writeSliceHeader` emits. Needs the PPS.
    l0_abs_diff_pic_num_minus1: ?u32 = null,
    l0_other_modification: bool = false,
};

/// Slice header (7.3.3) up to slice_qp_delta; without a PPS only up to idr_pic_id.
pub fn parseSliceHeader(nal: Nal, sps: SpsInfo, pps: ?PpsInfo) Error!SliceInfo {
    // Read in place: slice_header() has no size limit (7.3.3).
    var r = BitReader{ .data = nal.payload, .escaped = true };
    // parseSps keeps these in range; a hand-made SpsInfo may not.
    if (sps.log2_max_frame_num > 16 or sps.log2_max_poc_lsb > 16) return error.BadBitstream;
    const first_mb = try r.ue();
    const slice_type = try r.ue();
    if (slice_type > 9) return error.BadBitstream; // Table 7-6
    const st = slice_type % 5;
    _ = try r.ue(); // pps id (the caller picks the PPS: slicePpsId)
    const frame_num: u32 = @intCast(try r.bits(@intCast(sps.log2_max_frame_num)));
    var field_pic = false;
    if (!sps.frame_mbs_only) {
        field_pic = try r.flag();
        if (field_pic) _ = try r.bits(1); // bottom_field_flag
    }
    const idr_pic_id: ?u32 = if (nal.nal_type == .idr) try r.ue() else null;
    var info = SliceInfo{ .first_mb = first_mb, .slice_type = st, .frame_num = frame_num, .idr_pic_id = idr_pic_id };
    const p = pps orelse return info;
    if (sps.poc_type == 0) {
        _ = try r.bits(@intCast(sps.log2_max_poc_lsb));
        // delta_pic_order_cnt_bottom: frame pictures only.
        if (p.bottom_field_pic_order_in_frame_present and !field_pic) _ = try r.se();
    } else if (sps.poc_type == 1) return info; // delta_pic_order_cnt needs more SPS state
    if (p.redundant_pic_cnt_present) _ = try r.ue();
    const is_p = st == 0 or st == 3;
    const is_b = st == 1;
    if (is_b) _ = try r.bits(1); // direct_spatial_mv_pred_flag
    if (is_p or is_b) {
        if (try r.flag()) { // num_ref_idx_active_override_flag
            _ = try r.ue();
            if (is_b) _ = try r.ue();
        }
    }
    if (st != 2 and st != 4) {
        const m = try readRefPicListModification(&r);
        info.l0_abs_diff_pic_num_minus1 = m.subtract;
        info.l0_other_modification = m.other;
    }
    if (is_b) _ = try readRefPicListModification(&r);
    if ((p.weighted_pred and is_p) or is_b) return info; // pred_weight_table: not parsed
    if (nal.ref_idc != 0) {
        if (nal.nal_type == .idr) {
            _ = try r.bits(2);
        } else if (try r.flag()) { // adaptive_ref_pic_marking_mode_flag
            while (true) {
                const op = try r.ue();
                if (op == 0) break;
                if (op > 6) return error.BadBitstream; // 7.4.3.3: 0..6
                if (op == 1 or op == 3) _ = try r.ue();
                if (op == 2) _ = try r.ue();
                if (op == 3 or op == 6) _ = try r.ue();
                if (op == 4) _ = try r.ue();
            }
        }
    }
    if (p.cabac and st != 2 and st != 4) _ = try r.ue(); // cabac_init_idc
    const qp = @as(i64, p.pic_init_qp) + try r.se();
    if (qp < 0 or qp > 51) return error.BadBitstream;
    info.qp = @intCast(qp);
    return info;
}

const RefMod = struct { subtract: ?u32 = null, other: bool = false };

/// ref_pic_list_modification() of one list (7.3.3.1).
fn readRefPicListModification(r: *BitReader) Error!RefMod {
    if (!try r.flag()) return .{};
    var m: RefMod = .{};
    var ops: u32 = 0;
    while (true) : (ops += 1) {
        if (ops > 32) return error.BadBitstream; // num_ref_idx_l0_active_minus1 + 1 <= 32
        const idc = try r.ue();
        if (idc == 3) break;
        if (idc > 5) return error.BadBitstream;
        const v = try r.ue();
        if (ops == 0 and idc == 0) m.subtract = v else m.other = true;
    }
    if (ops != 1) m.other = true;
    if (m.other) m.subtract = null;
    return m;
}

pub const AccessUnitInfo = struct {
    nal_count: u32 = 0,
    sps_count: u32 = 0,
    pps_count: u32 = 0,
    slice_count: u32 = 0,
    /// Primary coded pictures (slices with first_mb_in_slice == 0).
    pictures: u32 = 0,
    idr: bool = false,
    other_count: u32 = 0, // SEI, AUD, filler, ...
    /// Parameter sets in effect after this access unit.
    params: ParamSets = .{},
    /// Parameter sets carried in this access unit.
    sps: ?SpsInfo = null,
    pps: ?PpsInfo = null,
    first_slice: ?SliceInfo = null,
};

/// `prev` supplies the parameter sets for access units that carry none.
pub fn inspect(annexb: []const u8, prev: ParamSets) Error!AccessUnitInfo {
    var info = AccessUnitInfo{ .params = prev };
    var it = NalIterator{ .data = annexb };
    while (try it.next()) |nal| {
        info.nal_count += 1;
        switch (nal.nal_type) {
            .sps, .pps => {
                var tmp: [512]u8 = undefined;
                if (nal.payload.len > tmp.len) return error.BadBitstream;
                const rbsp = unescape(nal.payload, &tmp);
                if (nal.nal_type == .sps) {
                    info.sps_count += 1;
                    info.sps = try parseSps(rbsp);
                    info.params.sps = info.sps;
                } else {
                    info.pps_count += 1;
                    info.pps = try parsePps(rbsp);
                    info.params.putPps(info.pps.?);
                }
            },
            .slice, .idr => {
                info.slice_count += 1;
                if (nal.nal_type == .idr) info.idr = true;
                if (info.params.sps) |s| {
                    const si = try parseSliceHeader(nal, s, info.params.ppsFor(try slicePpsId(nal)));
                    if (si.first_mb == 0) info.pictures += 1;
                    if (info.first_slice == null) info.first_slice = si;
                }
            },
            else => info.other_count += 1,
        }
    }
    return info;
}

pub const HeaderScan = struct {
    /// Parameter sets in effect for the first slice.
    params: ParamSets,
    slice: ?SliceInfo = null,

    pub fn qp(h: HeaderScan) ?u8 {
        return if (h.slice) |s| s.qp else null;
    }
};

/// Parameter sets and first slice header of an access unit; slice data is not walked.
pub fn scanHeaders(annexb: []const u8, prev: ParamSets) HeaderScan {
    var res = HeaderScan{ .params = prev };
    var pos: usize = 0;
    while (NalIterator.findStartCode(annexb, pos)) |sc| {
        const body = sc + 3;
        if (body >= annexb.len) break;
        const hdr = annexb[body];
        const nal_type: NalType = @fromBackingInt(@intCast(hdr & 0x1f));
        const window = annexb[body + 1 .. @min(annexb.len, body + 1 + 600)];
        const nal = Nal{ .ref_idc = @intCast(hdr >> 5 & 3), .nal_type = nal_type, .payload = window };
        var tmp: [600]u8 = undefined;
        switch (nal_type) {
            .sps => res.params.sps = parseSps(unescape(window, &tmp)) catch null,
            .pps => if (parsePps(trimToNal(unescape(window, &tmp)))) |p| res.params.putPps(p) else |_| {
                // Its id is unknown: no PPS can be trusted.
                res.params.pps = null;
                res.params.pps_by_id = @splat(null);
            },
            .slice, .idr => {
                const s = res.params.sps orelse break;
                const id = slicePpsId(nal) catch break;
                res.slice = parseSliceHeader(nal, s, res.params.ppsFor(id)) catch null;
                break;
            },
            else => {},
        }
        pos = body + 1;
    }
    return res;
}

pub fn firstSliceQp(annexb: []const u8, prev: ParamSets) ?u8 {
    return scanHeaders(annexb, prev).qp();
}

/// Cut a PPS window at the next start code so more_rbsp_data() sees the real end.
fn trimToNal(rbsp: []const u8) []const u8 {
    var end = rbsp.len;
    if (NalIterator.findStartCode(rbsp, 0)) |n| end = n;
    while (end > 0 and rbsp[end - 1] == 0) end -= 1;
    return rbsp[0..end];
}

const testing = std.testing;

test "exp-golomb writer matches reader" {
    var w = BitWriter{};
    const vals = [_]u32{ 0, 1, 2, 3, 7, 8, 255, 1000, 65535 };
    for (vals) |v| try w.ue(v);
    const svals = [_]i32{ 0, 1, -1, 2, -2, 26, -26, 1000 };
    for (svals) |v| try w.se(v);
    try w.trailing();
    var r = BitReader{ .data = w.bytes() };
    for (vals) |v| try testing.expectEqual(v, try r.ue());
    for (svals) |v| try testing.expectEqual(v, try r.se());
    // ue(0) = '1', ue(1) = '010', ue(2) = '011'
    var w2 = BitWriter{};
    try w2.ue(0);
    try w2.ue(1);
    try w2.ue(2);
    try w2.bits(0, 1);
    try testing.expectEqualSlices(u8, &.{0b1010_0110}, w2.bytes());
}

test "appendNalBits counts only written bits" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var w = BitWriter{};
    try w.ue(0);
    try w.ue(7); // 1 + 7 bits = 8 bits
    try w.bits(1, 3);
    try testing.expectEqual(@as(usize, 5 * 8 + 8 + 3), try appendNalBits(gpa, &out, 2, .slice, &w));
    try testing.expectEqual(@as(usize, 7), out.items.len);
    out.clearRetainingCapacity();
    try w.trailing();
    try testing.expectEqual(@as(usize, 7 * 8), try appendNalBits(gpa, &out, 3, .pps, &w));
}

test "emulation prevention round trip" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const rbsp = [_]u8{ 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0xff, 0x00, 0x00 };
    _ = try appendNal(gpa, &out, 3, .sps, &rbsp);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 1, 0x67, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x03, 0xff, 0x00, 0x00, 0x03 }, out.items);
    var buf: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &rbsp, unescape(out.items[5..], &buf));
}

test "geometry: macroblock alignment and cropping" {
    const cases = [_]struct { w: u32, h: u32, wm: u16, hm: u16, cr: u16, cb: u16 }{
        .{ .w = 1920, .h = 1080, .wm = 120, .hm = 68, .cr = 0, .cb = 4 },
        .{ .w = 1280, .h = 800, .wm = 80, .hm = 50, .cr = 0, .cb = 0 },
        .{ .w = 2560, .h = 1440, .wm = 160, .hm = 90, .cr = 0, .cb = 0 },
        .{ .w = 978, .h = 644, .wm = 62, .hm = 41, .cr = 7, .cb = 6 },
        .{ .w = 3840, .h = 2160, .wm = 240, .hm = 135, .cr = 0, .cb = 0 },
        .{ .w = 2, .h = 2, .wm = 1, .hm = 1, .cr = 7, .cb = 7 },
    };
    for (cases) |c| {
        const g = try Geometry.init(c.w, c.h, true);
        try testing.expectEqual(c.wm, g.width_mbs);
        try testing.expectEqual(c.hm, g.height_mbs);
        try testing.expectEqual(c.cr, g.crop_right);
        try testing.expectEqual(c.cb, g.crop_bottom);
        try testing.expectEqual(c.w, g.codedWidth() - 2 * g.crop_right);
        try testing.expectEqual(c.h, g.codedHeight() - 2 * g.crop_bottom);
        const nc = try Geometry.init(c.w, c.h, false);
        try testing.expectEqual(@as(u32, nc.width), nc.codedWidth());
        try testing.expect(!nc.cropped());
    }
    try testing.expectError(error.OddDimension, Geometry.init(977, 644, true));
    try testing.expectError(error.BadDimension, Geometry.init(0, 644, true));
}

test "level selection" {
    const g1080 = try Geometry.init(1920, 1080, true);
    try testing.expectEqual(@as(u8, 42), chooseLevel(g1080, 60, 20_000_000, .high));
    try testing.expectEqual(@as(u8, 40), chooseLevel(g1080, 30, 20_000_000, .high));
    try testing.expectEqual(@as(u8, 41), chooseLevel(g1080, 30, 40_000_000, .high));
    const g4k = try Geometry.init(3840, 2160, true);
    try testing.expectEqual(@as(u8, 52), chooseLevel(g4k, 60, 50_000_000, .high));
    try testing.expectEqual(@as(u8, 51), chooseLevel(g4k, 30, 50_000_000, .high));
    const g1440 = try Geometry.init(2560, 1440, true);
    try testing.expectEqual(@as(u8, 51), chooseLevel(g1440, 60, 30_000_000, .main));
    const small = try Geometry.init(978, 644, true);
    try testing.expectEqual(@as(u8, 32), chooseLevel(small, 60, 8_000_000, .high));
}

test "SPS written with cropping and VUI parses back" {
    const g = try Geometry.init(978, 644, true);
    const sps = Sps{ .profile = .high, .level_idc = 32, .geometry = g };
    var w = BitWriter{};
    try writeSps(&w, sps);
    try testing.expect(w.byteAligned());
    const info = try parseSps(w.bytes());
    try testing.expectEqual(@as(u8, 100), info.profile_idc);
    try testing.expectEqual(@as(u8, 32), info.level_idc);
    try testing.expectEqual(@as(u32, 978), info.width);
    try testing.expectEqual(@as(u32, 644), info.height);
    try testing.expectEqual(@as(u32, 2), info.poc_type);
    try testing.expectEqual(@as(u32, 8), info.log2_max_frame_num);
    try testing.expectEqual(@as(u32, 1), info.max_num_ref_frames);
    try testing.expectEqual(true, info.video_full_range.?);
    try testing.expectEqual([3]u8{ 1, 13, 1 }, info.colour.?);
    try testing.expectEqual(@as(u32, 0), info.max_num_reorder_frames.?);
    try testing.expectEqual(@as(u32, 1), info.max_dec_frame_buffering.?);

    // Main profile omits the High chroma/bit-depth fields; no cropping at 1280x800.
    const g2 = try Geometry.init(1280, 800, true);
    var w2 = BitWriter{};
    try writeSps(&w2, .{ .profile = .main, .level_idc = 31, .geometry = g2, .vui = null });
    const info2 = try parseSps(w2.bytes());
    try testing.expectEqual(@as(u8, 77), info2.profile_idc);
    try testing.expectEqual(@as(u8, 0x40), info2.constraint_flags);
    try testing.expectEqual(@as(u32, 1280), info2.width);
    try testing.expectEqual(@as(u32, 800), info2.height);
    try testing.expect(!info2.vui_present);
}

test "slice header fields parse back; access unit inspection" {
    const gpa = testing.allocator;
    const g = try Geometry.init(1920, 1080, true);
    const sps = Sps{ .profile = .high, .level_idc = 42, .geometry = g };
    const pps = Pps{ .cabac = true, .high = true };
    var au: std.ArrayList(u8) = .empty;
    defer au.deinit(gpa);

    var w = BitWriter{};
    try writeSps(&w, sps);
    _ = try appendNal(gpa, &au, 3, .sps, w.bytes());
    w = .{};
    try writePps(&w, pps);
    _ = try appendNal(gpa, &au, 3, .pps, w.bytes());
    w = .{};
    const hdr = SliceHeader{ .idr = true, .slice_type = .i, .frame_num = 0, .idr_pic_id = 1 };
    try writeSliceHeader(&w, sps, pps, hdr);
    try w.trailing(); // stand-in for slice data
    _ = try appendNal(gpa, &au, hdr.nalRefIdc(), hdr.nalType(), w.bytes());

    const info = try inspect(au.items, .{});
    try testing.expectEqual(@as(u32, 3), info.nal_count);
    try testing.expectEqual(@as(u32, 1), info.sps_count);
    try testing.expectEqual(@as(u32, 1), info.pps_count);
    try testing.expectEqual(@as(u32, 1), info.pictures);
    try testing.expect(info.idr);
    try testing.expectEqual(@as(u32, 2), info.first_slice.?.slice_type);
    try testing.expectEqual(@as(u32, 1), info.first_slice.?.idr_pic_id.?);

    // A P slice with frame_num 300 wraps modulo MaxFrameNum (256).
    var pau: std.ArrayList(u8) = .empty;
    defer pau.deinit(gpa);
    w = .{};
    const ph = SliceHeader{ .idr = false, .slice_type = .p, .frame_num = 300 };
    try writeSliceHeader(&w, sps, pps, ph);
    try w.trailing();
    _ = try appendNal(gpa, &pau, ph.nalRefIdc(), ph.nalType(), w.bytes());
    const pinfo = try inspect(pau.items, info.params);
    try testing.expect(!pinfo.idr);
    try testing.expectEqual(@as(u32, 0), pinfo.first_slice.?.slice_type);
    try testing.expectEqual(@as(u32, 300 % 256), pinfo.first_slice.?.frame_num);
    try testing.expectEqual(@as(?u8, 26), pinfo.first_slice.?.qp);
    try testing.expectEqual(@as(?u8, 26), info.first_slice.?.qp);
    try testing.expectEqual(@as(?u8, 26), firstSliceQp(au.items, .{}));
    try testing.expectEqual(@as(?u8, null), firstSliceQp(pau.items, .{}));
    try testing.expectEqual(@as(?u8, 26), firstSliceQp(pau.items, info.params));
}

test "ref_pic_list_modification (7.3.3.1) round trip; other forms flagged" {
    const gpa = testing.allocator;
    const sps = Sps{ .profile = .high, .level_idc = 42, .geometry = try Geometry.init(1376, 768, false), .max_num_ref_frames = 2 };
    const pps = Pps{ .cabac = true, .high = true };
    var ps: ParamSets = .{ .sps = try parseSpsOf(sps) };
    ps.putPps(try parsePpsOf(pps));
    for ([_]?u32{ null, 0, 1, 5 }) |d| {
        var au: std.ArrayList(u8) = .empty;
        defer au.deinit(gpa);
        var w = BitWriter{};
        const ph = SliceHeader{ .idr = false, .slice_type = .p, .frame_num = 7, .qp_delta = -3, .l0_abs_diff_pic_num_minus1 = d };
        try writeSliceHeader(&w, sps, pps, ph);
        try w.trailing();
        _ = try appendNal(gpa, &au, ph.nalRefIdc(), ph.nalType(), w.bytes());
        const si = (try inspect(au.items, ps)).first_slice.?;
        try testing.expectEqual(d, si.l0_abs_diff_pic_num_minus1);
        try testing.expect(!si.l0_other_modification);
        try testing.expectEqual(@as(?u8, 23), si.qp); // the fields after it still line up
        try testing.expectEqual(@as(u32, 7), si.frame_num);
    }
    // Bits: flag 1, ue(0) "1", ue(1) "010", ue(3) "00100".
    var w = BitWriter{};
    try writeSliceHeader(&w, sps, pps, .{ .idr = false, .slice_type = .p, .frame_num = 0, .l0_abs_diff_pic_num_minus1 = 1 });
    var r = BitReader{ .data = w.bytes() };
    _ = try r.ue(); // first_mb
    _ = try r.ue(); // slice_type
    _ = try r.ue(); // pps id
    _ = try r.bits(8); // frame_num (log2 = 8)
    try testing.expect(!try r.flag()); // num_ref_idx_active_override_flag
    try testing.expect(try r.flag());
    try testing.expectEqual(@as(u32, 0), try r.ue());
    try testing.expectEqual(@as(u32, 1), try r.ue());
    try testing.expectEqual(@as(u32, 3), try r.ue());
    // An "add" operation, or two operations: another form.
    for ([_][]const u32{ &.{ 1, 0 }, &.{ 0, 1, 0, 2 } }) |ops| {
        var x = BitWriter{};
        try x.ue(0);
        try x.ue(5); // P, all slices
        try x.ue(0);
        try x.bits(3, 8);
        try x.flag(false);
        try x.flag(true);
        for (ops) |o| try x.ue(o);
        try x.ue(3);
        try x.flag(false); // adaptive_ref_pic_marking_mode_flag
        try x.ue(0); // cabac_init_idc
        try x.se(0);
        try x.ue(0);
        try x.se(0);
        try x.se(0);
        try x.trailing();
        var au: std.ArrayList(u8) = .empty;
        defer au.deinit(gpa);
        _ = try appendNal(gpa, &au, 2, .slice, x.bytes());
        const si = (try inspect(au.items, ps)).first_slice.?;
        try testing.expect(si.l0_other_modification);
        try testing.expectEqual(@as(?u32, null), si.l0_abs_diff_pic_num_minus1);
    }
}

fn parseSpsOf(s: Sps) Error!SpsInfo {
    var w = BitWriter{};
    try writeSps(&w, s);
    return parseSps(w.bytes());
}

fn parsePpsOf(p: Pps) Error!PpsInfo {
    var w = BitWriter{};
    try writePps(&w, p);
    return parsePps(w.bytes());
}

test "PPS round trip and slice QP across PPS/POC variants" {
    const gpa = testing.allocator;
    const g = try Geometry.init(640, 480, true);
    inline for (.{ Profile.high, Profile.main, Profile.constrained_baseline }) |prof| {
        inline for (.{ @as(u2, 2), @as(u2, 0) }) |poc_type| {
            const sps = Sps{ .profile = prof, .level_idc = 30, .geometry = g, .poc_type = poc_type };
            const pps = Pps{ .cabac = prof.cabac(), .high = prof == .high, .pic_init_qp = 30 };
            var w = BitWriter{};
            try writePps(&w, pps);
            const pi = try parsePps(w.bytes());
            try testing.expectEqual(prof.cabac(), pi.cabac);
            try testing.expectEqual(@as(i32, 30), pi.pic_init_qp);
            try testing.expectEqual(prof == .high, pi.transform_8x8);
            try testing.expectEqual(prof == .high, pi.extension);
            try testing.expectEqual(if (prof == .high) @as(?i32, 0) else null, pi.second_chroma_qp_index_offset);
            try testing.expect(pi.deblocking_control);
            // A doubled rbsp_trailing_bits is junk after a High PPS and parses as a
            // High tail on a Main/Baseline PPS.
            var bad = w;
            try bad.trailing();
            if (prof == .high) {
                try testing.expectError(error.BadBitstream, parsePps(bad.bytes()));
            } else {
                const misread = try parsePps(bad.bytes());
                try testing.expect(misread.extension and misread.transform_8x8);
            }

            var au: std.ArrayList(u8) = .empty;
            defer au.deinit(gpa);
            w = .{};
            try writeSps(&w, sps);
            _ = try appendNal(gpa, &au, 3, .sps, w.bytes());
            w = .{};
            try writePps(&w, pps);
            _ = try appendNal(gpa, &au, 3, .pps, w.bytes());
            for ([_]SliceHeader{
                .{ .idr = true, .slice_type = .i, .frame_num = 0, .idr_pic_id = 7, .poc_lsb = 0, .qp_delta = -8 },
                .{ .idr = false, .slice_type = .p, .frame_num = 9, .poc_lsb = 18, .qp_delta = 5 },
            }) |h| {
                w = .{};
                try writeSliceHeader(&w, sps, pps, h);
                try w.trailing();
                var one: std.ArrayList(u8) = .empty;
                defer one.deinit(gpa);
                try one.appendSlice(gpa, au.items);
                _ = try appendNal(gpa, &one, h.nalRefIdc(), h.nalType(), w.bytes());
                const info = try inspect(one.items, .{});
                const si = info.first_slice.?;
                try testing.expectEqual(h.frame_num, si.frame_num);
                try testing.expectEqual(@as(?u8, @intCast(30 + h.qp_delta)), si.qp);
                try testing.expectEqual(si.qp, firstSliceQp(one.items, .{}));
            }
        }
    }
}
