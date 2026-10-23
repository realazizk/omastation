//! MS-RDPNSC NSCodec encoder and reference decoder, for TS_BITMAP_DATA_EX (MS-RDPBCGR
//! 2.2.9.2.1) and the ClearCodec NSCodec subcodec (MS-RDPEGFX 2.2.4.1.1.3.1). Planes and
//! colour loss follow MS-RDPEGDI 3.1.9.1.2-4; padding repeats the last sample.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

pub const Error = error{
    InvalidDimensions,
    /// ColorLossLevel outside 1..7, or caps that do not allow the request.
    BadParams,
    BadCaps,
    BadRle,
    BufferTooSmall,
} || std.mem.Allocator.Error;

/// TS_NSCODEC_CAPABILITYSET (2.2.1).
pub const Caps = struct {
    allow_dynamic_fidelity: bool = true,
    allow_subsampling: bool = true,
    /// Maximum supported colour loss level, 1..7.
    color_loss_level: u8 = 3,
};

pub const caps_len: usize = 3;
pub const header_len: usize = 20;
/// The codecID NSCodec MUST use in the Bitmap Codecs Capability Set.
pub const codec_id: u8 = 0x01;
/// Bitmaps are taken as 32 bpp (TS_BITMAP_DATA_EX bpp).
pub const bpp: u8 = 32;

fn validCll(cll: u8) bool {
    return cll >= 1 and cll <= 7;
}

/// error.BadCaps when shorter than 3 bytes, a boolean is not 0/1 or colorLossLevel is outside 1..7.
pub fn parseCaps(data: []const u8) Error!Caps {
    if (data.len < caps_len) return error.BadCaps;
    if (data[0] > 1 or data[1] > 1 or !validCll(data[2])) return error.BadCaps;
    return .{ .allow_dynamic_fidelity = data[0] == 1, .allow_subsampling = data[1] == 1, .color_loss_level = data[2] };
}

pub fn writeCaps(w: *bytes.Writer, caps: Caps) Error!void {
    if (!validCll(caps.color_loss_level)) return error.BadParams;
    try w.byte(@intFromBool(caps.allow_dynamic_fidelity));
    try w.byte(@intFromBool(caps.allow_subsampling));
    try w.byte(caps.color_loss_level);
}

pub const Params = struct {
    color_loss_level: u8 = 1,
    subsampling: bool = false,
    /// Otherwise AlphaPlaneByteCount is 0.
    alpha: bool = false,
};

/// Clamps `want` to the client's caps (3.1.5.1): colour loss above 1 needs fAllowDynamicFidelity
/// and stays within colorLossLevel; subsampling needs fAllowSubsampling.
pub fn chooseParams(client: Caps, want: Params) Error!Params {
    if (!validCll(want.color_loss_level)) return error.BadParams;
    const max: u8 = if (client.allow_dynamic_fidelity) std.math.clamp(client.color_loss_level, 1, 7) else 1;
    return .{
        .color_loss_level = @min(want.color_loss_level, max),
        .subsampling = want.subsampling and client.allow_subsampling,
        .alpha = want.alpha,
    };
}

fn roundUp(v: usize, m: usize) usize {
    return (v + m - 1) / m * m;
}

/// 2.2.2: width*height, or ROUND_UP_8(width)*height with subsampling.
pub fn lumaPlaneSize(width: u16, height: u16, subsampling: bool) Error!usize {
    if (width == 0 or height == 0) return error.InvalidDimensions;
    return (if (subsampling) roundUp(width, 8) else width) * @as(usize, height);
}

/// width*height, or (ROUND_UP_8(width)/2) * (ROUND_UP_2(height)/2) with subsampling.
pub fn chromaPlaneSize(width: u16, height: u16, subsampling: bool) Error!usize {
    if (width == 0 or height == 0) return error.InvalidDimensions;
    if (!subsampling) return @as(usize, width) * height;
    return (roundUp(width, 8) / 2) * (roundUp(height, 2) / 2);
}

/// NSCodec RLE (3.1.8.1.1). Returns the encoded length even when not smaller than the input;
/// the last four bytes are copied unencoded (EndData).
pub fn rleEncode(src: []const u8, dst: []u8) Error!usize {
    if (src.len <= 4) {
        if (dst.len < src.len) return error.BufferTooSmall;
        @memcpy(dst[0..src.len], src);
        return src.len;
    }
    const end = src.len - 4;
    var o: usize = 0;
    var i: usize = 0;
    while (i < end) {
        const v = src[i];
        var j = i + 1;
        while (j < end and src[j] == v) j += 1;
        const run = j - i;
        if (run == 1) {
            // rule 2: a literal (the next byte differs, or EndData follows)
            if (o + 1 > dst.len) return error.BufferTooSmall;
            dst[o] = v;
            o += 1;
        } else if (run < 256) {
            // rule 3: short run
            if (o + 3 > dst.len) return error.BufferTooSmall;
            dst[o..][0..3].* = .{ v, v, @intCast(run - 2) };
            o += 3;
        } else {
            // rule 4: long run (NSCODEC_RLE_RUN_SEGMENT with RunLengthFactor2)
            if (o + 7 > dst.len) return error.BufferTooSmall;
            dst[o..][0..3].* = .{ v, v, 0xFF };
            std.mem.writeInt(u32, dst[o + 3 ..][0..4], @intCast(run), .little);
            o += 7;
        }
        i = j;
    }
    if (o + 4 > dst.len) return error.BufferTooSmall;
    @memcpy(dst[o..][0..4], src[end..]);
    return o + 4;
}

/// Decodes exactly `dst.len` bytes; the four EndData bytes MUST end `src`.
pub fn rleDecode(src: []const u8, dst: []u8) Error!void {
    if (dst.len < 4) return error.BadRle;
    var i: usize = 0;
    var o: usize = 0;
    while (dst.len - o > 4) {
        if (i >= src.len) return error.BadRle;
        const v = src[i];
        i += 1;
        if (dst.len - o > 5 and i < src.len and src[i] == v) {
            i += 1;
            if (i >= src.len) return error.BadRle;
            var run: usize = src[i];
            i += 1;
            if (run == 0xFF) {
                if (src.len - i < 4) return error.BadRle;
                run = std.mem.readInt(u32, src[i..][0..4], .little);
                i += 4;
            } else run += 2;
            if (run > dst.len - o - 4) return error.BadRle;
            @memset(dst[o..][0..run], v);
            o += run;
        } else {
            dst[o] = v;
            o += 1;
        }
    }
    if (src.len - i != 4) return error.BadRle;
    @memcpy(dst[o..][0..4], src[i..][0..4]);
}

/// RLE when strictly smaller than the raw plane, else raw. Returns the length written.
pub fn encodePlane(src: []const u8, dst: []u8) Error!usize {
    if (dst.len < src.len) return error.BufferTooSmall;
    if (src.len == 0) return 0;
    if (rleEncode(src, dst[0 .. src.len - 1])) |n| return n else |e| switch (e) {
        error.BufferTooSmall => {},
        else => return e,
    }
    @memcpy(dst[0..src.len], src);
    return src.len;
}

/// The four planes of a bitmap before RLE (owned).
pub const Planes = struct {
    luma: []u8,
    co: []u8,
    cg: []u8,
    alpha: []u8,

    pub fn deinit(p: *Planes, gpa: std.mem.Allocator) void {
        gpa.free(p.luma);
        gpa.free(p.co);
        gpa.free(p.cg);
        gpa.free(p.alpha);
        p.* = undefined;
    }
};

/// Co = R - B and Cg = G - (R + B) / 2 of a B, G, R pixel (9-bit range).
inline fn chroma(p: []const u8) [2]i32 {
    const b: i32 = p[0];
    const g: i32 = p[1];
    const r: i32 = p[2];
    return .{ r - b, (2 * g - r - b) >> 1 };
}

/// Colour loss reduction (MS-RDPEGDI 3.1.9.1.4) of a 9-bit chroma value.
inline fn reduce(v: i32, cll: u3) u8 {
    return @intCast((@as(u32, @bitCast(v)) & 0x1FF) >> cll);
}

/// Colour conversion, colour loss and optional subsampling of a top-down BGRA image.
pub fn convert(gpa: std.mem.Allocator, pixels: []const u8, stride: usize, width: u16, height: u16, params: Params) Error!Planes {
    if (width == 0 or height == 0) return error.InvalidDimensions;
    if (!validCll(params.color_loss_level)) return error.BadParams;
    const w: usize = width;
    const h: usize = height;
    if (stride < w * 4 or pixels.len < (h - 1) * stride + w * 4) return error.InvalidDimensions;
    const cll: u3 = @intCast(params.color_loss_level);
    const ss = params.subsampling;
    const lw = if (ss) roundUp(w, 8) else w;
    const cw = if (ss) lw / 2 else w;
    const ch = if (ss) roundUp(h, 2) / 2 else h;

    const luma = try gpa.alloc(u8, lw * h);
    errdefer gpa.free(luma);
    const co = try gpa.alloc(u8, cw * ch);
    errdefer gpa.free(co);
    const cg = try gpa.alloc(u8, cw * ch);
    errdefer gpa.free(cg);
    const alpha = if (params.alpha) try gpa.alloc(u8, w * h) else try gpa.alloc(u8, 0);
    errdefer gpa.free(alpha);

    for (0..h) |y| {
        const row = pixels[y * stride ..][0 .. w * 4];
        const lrow = luma[y * lw ..][0..lw];
        for (0..w) |x| {
            const p = row[x * 4 ..][0..4];
            lrow[x] = @intCast((@as(u32, p[2]) + 2 * @as(u32, p[1]) + p[0] + 2) >> 2);
            if (params.alpha) alpha[y * w + x] = p[3];
            if (!ss) {
                const c = chroma(p);
                co[y * w + x] = reduce(c[0], cll);
                cg[y * w + x] = reduce(c[1], cll);
            }
        }
        @memset(lrow[w..], lrow[w - 1]);
    }
    if (ss) {
        for (0..ch) |cy| {
            const crow = cy * cw;
            if (2 * cy >= h) {
                @memcpy(co[crow..][0..cw], co[crow - cw ..][0..cw]);
                @memcpy(cg[crow..][0..cw], cg[crow - cw ..][0..cw]);
                continue;
            }
            for (0..cw) |cx| {
                if (2 * cx >= w) {
                    co[crow + cx] = co[crow + cx - 1];
                    cg[crow + cx] = cg[crow + cx - 1];
                    continue;
                }
                var sum: [2]i32 = .{ 0, 0 };
                var count: i32 = 0;
                for (2 * cy..@min(2 * cy + 2, h)) |y| for (2 * cx..@min(2 * cx + 2, w)) |x| {
                    const c = chroma(pixels[y * stride + x * 4 ..][0..4]);
                    sum[0] += c[0];
                    sum[1] += c[1];
                    count += 1;
                };
                co[crow + cx] = reduce(@divFloor(2 * sum[0] + count, 2 * count), cll);
                cg[crow + cx] = reduce(@divFloor(2 * sum[1] + count, 2 * count), cll);
            }
        }
    }
    return .{ .luma = luma, .co = co, .cg = cg, .alpha = alpha };
}

/// Complete NSCODEC_BITMAP_STREAM; caller frees.
pub fn encode(gpa: std.mem.Allocator, pixels: []const u8, stride: usize, width: u16, height: u16, params: Params) Error![]u8 {
    var p = try convert(gpa, pixels, stride, width, height, params);
    defer p.deinit(gpa);
    const planes = [4][]const u8{ p.luma, p.co, p.cg, p.alpha };
    var total: usize = header_len;
    for (planes) |pl| total += pl.len;
    const out = try gpa.alloc(u8, total);
    errdefer gpa.free(out);
    var o: usize = header_len;
    for (planes, 0..) |pl, k| {
        const n = try encodePlane(pl, out[o..]);
        std.mem.writeInt(u32, out[4 * k ..][0..4], @intCast(n), .little);
        o += n;
    }
    out[16] = params.color_loss_level;
    out[17] = @intFromBool(params.subsampling);
    out[18] = 0;
    out[19] = 0;
    return gpa.realloc(out, o);
}

inline fn sext9(v: u32) i32 {
    const x: i32 = @intCast(v & 0x1FF);
    return if (x >= 256) x - 512 else x;
}

inline fn clamp8(v: i32) u8 {
    return @intCast(std.math.clamp(v, 0, 255));
}

/// Reference decoder (3.1.8.4) into BGRA `dst`. error.BadParams for an invalid ColorLossLevel
/// or ChromaSubsamplingLevel, error.BadRle for malformed or truncated planes.
pub fn decode(gpa: std.mem.Allocator, data: []const u8, width: u16, height: u16, dst: []u8, dst_stride: usize) Error!void {
    if (width == 0 or height == 0) return error.InvalidDimensions;
    const w: usize = width;
    const h: usize = height;
    if (dst_stride < w * 4 or dst.len < (h - 1) * dst_stride + w * 4) return error.BufferTooSmall;
    if (data.len < header_len) return error.BadRle;
    const cll = data[16];
    const css = data[17];
    if (!validCll(cll) or css > 1) return error.BadParams;
    const ss = css == 1;
    const sizes = [4]usize{ try lumaPlaneSize(width, height, ss), try chromaPlaneSize(width, height, ss), try chromaPlaneSize(width, height, ss), w * h };
    var counts: [4]usize = undefined;
    var total: usize = header_len;
    for (&counts, sizes, 0..) |*c, size, k| {
        c.* = std.mem.readInt(u32, data[4 * k ..][0..4], .little);
        // The luma and chroma planes MUST be present, none larger than raw.
        if ((k < 3 and c.* == 0) or c.* > size) return error.BadRle;
        total += c.*;
    }
    if (data.len != total) return error.BadRle;

    var planes: [4][]u8 = .{ &.{}, &.{}, &.{}, &.{} };
    defer for (planes) |pl| gpa.free(pl);
    var off: usize = header_len;
    for (&planes, counts, sizes) |*pl, n, size| {
        if (n == 0) continue;
        pl.* = try gpa.alloc(u8, size);
        const src = data[off..][0..n];
        if (n == size) @memcpy(pl.*, src) else try rleDecode(src, pl.*);
        off += n;
    }
    const lw = if (ss) roundUp(w, 8) else w;
    const cw = if (ss) roundUp(w, 8) / 2 else w;
    const shift: u5 = @intCast(cll);
    for (0..h) |y| {
        const row = dst[y * dst_stride ..][0 .. w * 4];
        for (0..w) |x| {
            const ci = if (ss) (y / 2) * cw + x / 2 else y * cw + x;
            const yv: i32 = planes[0][y * lw + x];
            const co = @divFloor(sext9(@as(u32, planes[1][ci]) << shift), 2);
            const cg = @divFloor(sext9(@as(u32, planes[2][ci]) << shift), 2);
            row[x * 4 ..][0..4].* = .{
                clamp8(yv - co - cg),
                clamp8(yv + cg),
                clamp8(yv + co - cg),
                if (counts[3] > 0) planes[3][y * w + x] else 0xFF,
            };
        }
    }
}

test "RLE of the 3.1.8.1 examples" {
    var buf: [64]u8 = undefined;
    const n = try rleEncode("ABCDDDTTTTGFRRRRRRRRRRRABCD", &buf);
    try std.testing.expectEqualSlices(u8, "ABCDD\x01TT\x02GFRR\x09ABCD", buf[0..n]);
    var back: [27]u8 = undefined;
    try rleDecode(buf[0..n], &back);
    try std.testing.expectEqualSlices(u8, "ABCDDDTTTTGFRRRRRRRRRRRABCD", &back);
}
