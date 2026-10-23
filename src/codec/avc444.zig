//! MS-RDPEGFX AVC444/AVC444v2 (2.2.4.5, 2.2.4.6, 3.3.8.3): a YUV444 frame as main and
//! auxiliary YUV420 views plus the bitstream framing. The AVC420 encoder codes both
//! views in one H.264 stream. Colour is full-range BT.709.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const avc420 = @import("avc420.zig");
const gfx = @import("../proto/gfx.zig");

pub const Error = error{
    InvalidDimensions,
    /// LC = 3, or LC inconsistent with the streams given.
    BadLc,
    /// cbAvc420EncodedBitstream1 does not fit in 30 bits.
    StreamTooLarge,
    BufferTooSmall,
} || avc420.Error || std.mem.Allocator.Error;

pub const Version = enum { v1, v2 };

pub const codec_id_avc444: u16 = @backingInt(gfx.CodecId.avc444);
pub const codec_id_avc444v2: u16 = @backingInt(gfx.CodecId.avc444v2);

pub const Lc = enum(u2) {
    /// stream1 = YUV420 (main) view, stream2 = Chroma420 (auxiliary) view.
    both = 0,
    /// stream1 = YUV420 view only; the chroma is owed.
    luma = 1,
    /// stream1 = Chroma420 view only.
    chroma = 2,
};

pub const cb_mask: u32 = 0x3FFF_FFFF;

/// `cb1` must be 0 with LC 2 (2.2.4.5).
pub fn bitstreamInfo(cb1: u32, lc: Lc) Error!u32 {
    if (cb1 > cb_mask) return error.StreamTooLarge;
    if (lc == .chroma and cb1 != 0) return error.BadLc;
    return cb1 | @as(u32, @backingInt(lc)) << 30;
}

pub const Info = struct { cb1: u32, lc: Lc };

pub fn parseBitstreamInfo(v: u32) Error!Info {
    const lc: u2 = @intCast(v >> 30);
    if (lc == 3) return error.BadLc;
    return .{ .cb1 = v & cb_mask, .lc = @fromBackingInt(@intCast(lc)) };
}

pub const SubStream = struct {
    rects: []const avc420.Rect16,
    qp: u8,
    h264: []const u8,
};

/// RFX_AVC444(V2)_BITMAP_STREAM; stream2 is required iff lc == .both.
/// Nothing is appended on error.
pub fn writeAvc444(w: *bytes.Writer, lc: Lc, stream1: SubStream, stream2: ?SubStream) Error!void {
    if ((lc == .both) != (stream2 != null)) return error.BadLc;
    const start = w.len();
    errdefer w.list.shrinkRetainingCapacity(start);
    try w.u32le(0);
    try avc420.writeAvc420(w, stream1.rects, stream1.qp, stream1.h264);
    const cb1 = w.len() - start - 4;
    if (cb1 > cb_mask) return error.StreamTooLarge;
    w.patchU32le(start, try bitstreamInfo(if (lc == .chroma) 0 else @intCast(cb1), lc));
    if (stream2) |s2| try avc420.writeAvc420(w, s2.rects, s2.qp, s2.h264);
}

pub const Planes = struct {
    y: []u8,
    u: []u8,
    v: []u8,
    width: u32,
    height: u32,
    y_stride: usize,
    uv_stride: usize,
};

// Full-range BT.709 (3.3.8.3.1) in 16.16 fixed point; rows sum to 65536 or 0.
const k_yr = 13933; // 0.2126
const k_yg = 46871; // 0.7152
const k_yb = 4732; // 0.0722
const k_ur = -7510; // -0.1146
const k_ug = -25258; // -0.3854
const k_ub = 32768; // 0.5
const k_vr = 32768; // 0.5
const k_vg = -29766; // -0.4542
const k_vb = -3002; // -0.0458

inline fn fix(v: i32) u8 {
    return @intCast(std.math.clamp((v + 32768) >> 16, 0, 255));
}

/// BGRX to full-range BT.709 YUV444; all three `out` planes use `out.y_stride`.
pub fn rgbToYuv444(pixels: []const u8, stride: usize, width: u32, height: u32, out: Planes) Error!void {
    if (width == 0 or height == 0) return error.InvalidDimensions;
    if (stride < @as(usize, width) * 4 or pixels.len < (height - 1) * stride + @as(usize, width) * 4)
        return error.InvalidDimensions;
    const need = (height - 1) * out.y_stride + width;
    if (out.y_stride < width or out.y.len < need or out.u.len < need or out.v.len < need)
        return error.BufferTooSmall;
    for (0..height) |row| {
        const src = pixels[row * stride ..][0 .. @as(usize, width) * 4];
        const o = row * out.y_stride;
        const yo = out.y[o..][0..width];
        const uo = out.u[o..][0..width];
        const vo = out.v[o..][0..width];
        for (0..width) |x| {
            const b: i32 = src[x * 4];
            const g: i32 = src[x * 4 + 1];
            const r: i32 = src[x * 4 + 2];
            yo[x] = fix(k_yr * r + k_yg * g + k_yb * b);
            uo[x] = fix(k_ur * r + k_ug * g + k_ub * b + (128 << 16));
            vo[x] = fix(k_vr * r + k_vg * g + k_vb * b + (128 << 16));
        }
    }
}

pub const ViewSize = struct { width: u32, height: u32 };

/// Height rounded up to 16, width to 16 (v1) or 32 (v2). Windows clients split the v2
/// auxiliary view at W/2 and W/4 of the 32-aligned width and reject 16-aligned views.
pub fn viewSize(version: Version, width: u32, height: u32) Error!ViewSize {
    if (width == 0 or height == 0 or width > 0xFFFF or height > 0xFFFF) return error.InvalidDimensions;
    const wa: u32 = switch (version) {
        .v1 => 16,
        .v2 => 32,
    };
    return .{ .width = std.mem.alignForward(u32, width, wa), .height = std.mem.alignForward(u32, height, 16) };
}

/// Reads outside the frame repeat the last column or row.
const Src = struct {
    p: []const u8,
    stride: usize,
    w: u32,
    h: u32,

    inline fn row(s: Src, y: usize) []const u8 {
        return s.p[@min(y, s.h - 1) * s.stride ..][0..s.w];
    }

    inline fn at(s: Src, r: []const u8, x: usize) u8 {
        _ = s;
        return r[@min(x, r.len - 1)];
    }
};

fn checkView(p: Planes, vs: ViewSize) Error!void {
    if (p.width < vs.width or p.height < vs.height) return error.BufferTooSmall;
    if (p.y_stride < vs.width or p.uv_stride < vs.width / 2) return error.BufferTooSmall;
    if (p.y.len < (vs.height - 1) * p.y_stride + vs.width) return error.BufferTooSmall;
    const cn = (vs.height / 2 - 1) * p.uv_stride + vs.width / 2;
    if (p.u.len < cn or p.v.len < cn) return error.BufferTooSmall;
}

/// YUV444 `src` of any size to the main and auxiliary views (`viewSize`), edge-replicated.
pub fn split(version: Version, src: Planes, main: Planes, aux: Planes) Error!void {
    const vs = try viewSize(version, src.width, src.height);
    const w = src.width;
    const h = src.height;
    if (src.y_stride < w or src.uv_stride < w) return error.BufferTooSmall;
    if (src.y.len < (h - 1) * src.y_stride + w) return error.BufferTooSmall;
    if (src.u.len < (h - 1) * src.uv_stride + w or src.v.len < (h - 1) * src.uv_stride + w) return error.BufferTooSmall;
    try checkView(main, vs);
    try checkView(aux, vs);

    const sy: Src = .{ .p = src.y, .stride = src.y_stride, .w = w, .h = h };
    const su: Src = .{ .p = src.u, .stride = src.uv_stride, .w = w, .h = h };
    const sv: Src = .{ .p = src.v, .stride = src.uv_stride, .w = w, .h = h };
    const vw: usize = vs.width;
    const vh: usize = vs.height;

    // B1: main Y = Y444.
    for (0..vh) |y| copyRow(main.y[y * main.y_stride ..][0..vw], sy.row(y));
    // B2/B3: main U/V = rounded 2x2 averages.
    for (0..vh / 2) |y| {
        inline for (.{ su, sv }, .{ main.u, main.v }) |s, d| {
            const r0 = s.row(2 * y);
            const r1 = s.row(2 * y + 1);
            const o = d[y * main.uv_stride ..][0 .. vw / 2];
            for (o, 0..) |*px, x| {
                const sum: u32 = @as(u32, s.at(r0, 2 * x)) + s.at(r0, 2 * x + 1) + s.at(r1, 2 * x) + s.at(r1, 2 * x + 1);
                px.* = @intCast((sum + 2) / 4);
            }
        }
    }
    switch (version) {
        .v1 => {
            // B4/B5: per 16-row band, 8 odd rows of U444 then 8 of V444.
            for (0..vh) |ay| {
                const k = ay % 16;
                const row = 2 * ((ay / 16) * 8 + k % 8) + 1;
                copyRow(aux.y[ay * aux.y_stride ..][0..vw], if (k < 8) su.row(row) else sv.row(row));
            }
            // B6/B7: U444/V444(2x+1, 2y).
            for (0..vh / 2) |y| {
                inline for (.{ su, sv }, .{ aux.u, aux.v }) |s, d| {
                    const r = s.row(2 * y);
                    const o = d[y * aux.uv_stride ..][0 .. vw / 2];
                    for (o, 0..) |*px, x| px.* = s.at(r, 2 * x + 1);
                }
            }
        },
        .v2 => {
            // B4/B5: Y halves = U444/V444(2x+1, y).
            for (0..vh) |y| {
                const o = aux.y[y * aux.y_stride ..][0..vw];
                const ru = su.row(y);
                const rv = sv.row(y);
                for (0..vw / 2) |x| {
                    o[x] = su.at(ru, 2 * x + 1);
                    o[vw / 2 + x] = sv.at(rv, 2 * x + 1);
                }
            }
            // B6-B9: U quarters = (4x, 2y+1), V quarters = (4x+2, 2y+1).
            for (0..vh / 2) |y| {
                const ru = su.row(2 * y + 1);
                const rv = sv.row(2 * y + 1);
                const ou = aux.u[y * aux.uv_stride ..][0 .. vw / 2];
                const ov = aux.v[y * aux.uv_stride ..][0 .. vw / 2];
                for (0..vw / 4) |x| {
                    ou[x] = su.at(ru, 4 * x);
                    ou[vw / 4 + x] = sv.at(rv, 4 * x);
                    ov[x] = su.at(ru, 4 * x + 2);
                    ov[vw / 4 + x] = sv.at(rv, 4 * x + 2);
                }
            }
        },
    }
}

fn copyRow(dst: []u8, src: []const u8) void {
    const n = @min(dst.len, src.len);
    @memcpy(dst[0..n], src[0..n]);
    @memset(dst[n..], src[src.len - 1]);
}

/// NV12 picture in a mapped VA image: Y plane, then interleaved U/V.
pub const Nv12 = struct {
    y: []u8,
    y_pitch: usize,
    uv: []u8,
    uv_pitch: usize,
};

/// Scratch bytes `toNv12` needs: six rows of the widest view.
pub fn nv12ScratchLen(width: u32) usize {
    return 6 * @as(usize, std.mem.alignForward(u32, @max(width, 1), 32));
}

/// `rgbToYuv444` then `split` in one pass, written as NV12 and bit-exact with both.
/// A null `main` or `aux` is not produced; `scratch` holds nv12ScratchLen(width) bytes.
pub fn toNv12(version: Version, pixels: []const u8, stride: usize, width: u32, height: u32, main: ?Nv12, aux: ?Nv12, scratch: []u8) Error!void {
    const vs = try viewSize(version, width, height);
    return toNv12Rows(version, pixels, stride, width, height, main, aux, scratch, 0, vs.height / 2);
}

/// `toNv12` for source row pairs `first..end` only; disjoint ranges may run in
/// parallel, each with its own `scratch`.
pub fn toNv12Rows(version: Version, pixels: []const u8, stride: usize, width: u32, height: u32, main: ?Nv12, aux: ?Nv12, scratch: []u8, first: usize, end: usize) Error!void {
    const vs = try viewSize(version, width, height);
    if (first > end or end > vs.height / 2) return error.InvalidDimensions;
    if (stride < @as(usize, width) * 4 or pixels.len < (height - 1) * stride + @as(usize, width) * 4)
        return error.InvalidDimensions;
    const vw: usize = vs.width;
    const vh: usize = vs.height;
    if (scratch.len < 6 * vw) return error.BufferTooSmall;
    inline for (.{ main, aux }) |view| if (view) |v| {
        if (v.y_pitch < vw or v.uv_pitch < vw) return error.BufferTooSmall;
        if (v.y.len < (vh - 1) * v.y_pitch + vw or v.uv.len < (vh / 2 - 1) * v.uv_pitch + vw) return error.BufferTooSmall;
    };
    // Rows 2m and 2m+1 as Y, U, V, `vw` samples each (edge replicated).
    const ya = scratch[0..vw];
    const ua = scratch[vw..][0..vw];
    const va = scratch[2 * vw ..][0..vw];
    const yb = scratch[3 * vw ..][0..vw];
    const ub = scratch[4 * vw ..][0..vw];
    const vb = scratch[5 * vw ..][0..vw];
    const w: usize = width;
    var have: ?usize = null; // source row in yb/ub/vb
    for (first..end) |m| {
        const r0 = @min(2 * m, height - 1);
        const r1 = @min(2 * m + 1, height - 1);
        if (have != null and have.? == r0) {
            @memcpy(ya, yb);
            @memcpy(ua, ub);
            @memcpy(va, vb);
        } else convertRow(pixels[r0 * stride ..][0 .. w * 4], ya, ua, va);
        if (r1 == r0) {
            @memcpy(yb, ya);
            @memcpy(ub, ua);
            @memcpy(vb, va);
        } else convertRow(pixels[r1 * stride ..][0 .. w * 4], yb, ub, vb);
        have = r1;

        if (main) |mv| {
            // B1: Y444; B2/B3: rounded 2x2 averages.
            @memcpy(mv.y[2 * m * mv.y_pitch ..][0..vw], ya);
            @memcpy(mv.y[(2 * m + 1) * mv.y_pitch ..][0..vw], yb);
            avgInterleave(mv.uv[m * mv.uv_pitch ..][0..vw], ua, ub, va, vb);
        }
        if (aux) |av| switch (version) {
            .v1 => {
                // B4/B5: odd row 2m+1 into band m / 8; B6/B7: U444/V444(2x+1, 2m).
                const ay = 16 * (m / 8) + m % 8;
                @memcpy(av.y[ay * av.y_pitch ..][0..vw], ub);
                @memcpy(av.y[(ay + 8) * av.y_pitch ..][0..vw], vb);
                oddInterleave(av.uv[m * av.uv_pitch ..][0..vw], ua, va);
            },
            .v2 => {
                // B4/B5: U444/V444(2x+1, y); B6-B9: (4x, 2m+1) into U, (4x+2, 2m+1) into V.
                inline for (.{ 2 * m, 2 * m + 1 }, .{ ua, ub }, .{ va, vb }) |ry, su, sv| {
                    const o = av.y[ry * av.y_pitch ..][0..vw];
                    oddHalves(o, su, sv);
                }
                quarterInterleave(av.uv[m * av.uv_pitch ..][0..vw], ub, vb);
            },
        };
    }
}

const lanes = 16;
const V32 = @Vector(lanes, i32);

inline fn fixV(v: V32) @Vector(lanes, u8) {
    const s = (v + @as(V32, @splat(32768))) >> @splat(16);
    return @intCast(@max(@as(V32, @splat(0)), @min(@as(V32, @splat(255)), s)));
}

/// One BGRX row to Y, U, V; outputs past the row repeat its last sample.
fn convertRow(src: []const u8, yo: []u8, uo: []u8, vo: []u8) void {
    const w = src.len / 4;
    var x: usize = 0;
    while (x + lanes <= w) : (x += lanes) {
        const px: @Vector(lanes, u32) = @as(*align(1) const [lanes]u32, @ptrCast(src[x * 4 ..][0 .. lanes * 4])).*;
        const mask: @Vector(lanes, u32) = @splat(0xFF);
        const b: V32 = @intCast(px & mask);
        const g: V32 = @intCast((px >> @splat(8)) & mask);
        const r: V32 = @intCast((px >> @splat(16)) & mask);
        const c128: V32 = @splat(128 << 16);
        yo[x..][0..lanes].* = fixV(@as(V32, @splat(k_yr)) * r + @as(V32, @splat(k_yg)) * g + @as(V32, @splat(k_yb)) * b);
        uo[x..][0..lanes].* = fixV(@as(V32, @splat(k_ur)) * r + @as(V32, @splat(k_ug)) * g + @as(V32, @splat(k_ub)) * b + c128);
        vo[x..][0..lanes].* = fixV(@as(V32, @splat(k_vr)) * r + @as(V32, @splat(k_vg)) * g + @as(V32, @splat(k_vb)) * b + c128);
    }
    while (x < w) : (x += 1) {
        const b: i32 = src[x * 4];
        const g: i32 = src[x * 4 + 1];
        const r: i32 = src[x * 4 + 2];
        yo[x] = fix(k_yr * r + k_yg * g + k_yb * b);
        uo[x] = fix(k_ur * r + k_ug * g + k_ub * b + (128 << 16));
        vo[x] = fix(k_vr * r + k_vg * g + k_vb * b + (128 << 16));
    }
    @memset(yo[w..], yo[w - 1]);
    @memset(uo[w..], uo[w - 1]);
    @memset(vo[w..], vo[w - 1]);
}

/// vw is a multiple of 16, so rows are whole blocks or end in a scalar tail.
const blk = 32;
const B = @Vector(blk, u8);
const H = @Vector(blk / 2, u8);

inline fn pick(v: B, comptime odd: u1) H {
    comptime var m: [blk / 2]i32 = undefined;
    inline for (&m, 0..) |*x, i| x.* = 2 * i + odd;
    return @shuffle(u8, v, undefined, m);
}

/// a0 b0 a1 b1 ...
inline fn zip(a: H, b: H) B {
    comptime var m: [blk]i32 = undefined;
    inline for (&m, 0..) |*x, i| x.* = if (i % 2 == 0) i / 2 else ~@as(i32, i / 2);
    return @shuffle(u8, a, b, m);
}

inline fn load(s: []const u8, i: usize) B {
    return s[i..][0..blk].*;
}

fn avgInterleave(o: []u8, ua: []const u8, ub: []const u8, va: []const u8, vb: []const u8) void {
    const W = @Vector(blk / 2, u16);
    var i: usize = 0;
    while (i + blk <= o.len) : (i += blk) {
        const a = load(ua, i);
        const b = load(ub, i);
        const c = load(va, i);
        const d = load(vb, i);
        const su = @as(W, pick(a, 0)) + pick(a, 1) + pick(b, 0) + pick(b, 1);
        const sv = @as(W, pick(c, 0)) + pick(c, 1) + pick(d, 0) + pick(d, 1);
        const two: W = @splat(2);
        o[i..][0..blk].* = zip(@intCast((su + two) >> @splat(2)), @intCast((sv + two) >> @splat(2)));
    }
    while (i < o.len) : (i += 2) {
        const su: u16 = @as(u16, ua[i]) + ua[i + 1] + ub[i] + ub[i + 1];
        const sv: u16 = @as(u16, va[i]) + va[i + 1] + vb[i] + vb[i + 1];
        o[i] = @intCast((su + 2) / 4);
        o[i + 1] = @intCast((sv + 2) / 4);
    }
}

fn oddInterleave(o: []u8, u: []const u8, v: []const u8) void {
    var i: usize = 0;
    while (i + blk <= o.len) : (i += blk) o[i..][0..blk].* = zip(pick(load(u, i), 1), pick(load(v, i), 1));
    while (i < o.len) : (i += 2) {
        o[i] = u[i + 1];
        o[i + 1] = v[i + 1];
    }
}

/// `o` = the even (`odd` 0) or odd samples of `u`, then those of `v`.
fn halves(o: []u8, u: []const u8, v: []const u8, comptime odd: u1) void {
    const half = o.len / 2;
    var i: usize = 0;
    while (i + blk <= o.len) : (i += blk) {
        o[i / 2 ..][0 .. blk / 2].* = pick(load(u, i), odd);
        o[half + i / 2 ..][0 .. blk / 2].* = pick(load(v, i), odd);
    }
    while (i < o.len) : (i += 2) {
        o[i / 2] = u[i + odd];
        o[half + i / 2] = v[i + odd];
    }
}

/// v2 aux Y row: odd U samples in the left half, odd V in the right (B4/B5).
fn oddHalves(o: []u8, u: []const u8, v: []const u8) void {
    halves(o, u, v, 1);
}

/// v2 aux U/V row (B6-B9): U plane = U(4x) | V(4x), V plane = U(4x+2) | V(4x+2).
fn quarterInterleave(o: []u8, u: []const u8, v: []const u8) void {
    halves(o, u, v, 0);
}

pub fn chooseLc(luma_changed: bool, chroma_changed: bool, defer_chroma: bool) Error!?Lc {
    if (luma_changed) return if (chroma_changed and !defer_chroma) .both else .luma;
    return if (chroma_changed) .chroma else null;
}

/// Areas whose chroma view is owed after LC 1 frames (2.2.4.5), as disjoint rects;
/// past `max_rects` they merge into their bounding box (owing more is safe).
pub const ChromaDebt = struct {
    gpa: std.mem.Allocator,
    rects: std.ArrayList(avc420.Rect16) = .empty,

    const max_rects = 64;

    pub fn init(gpa: std.mem.Allocator) Error!ChromaDebt {
        return .{ .gpa = gpa };
    }

    pub fn deinit(d: *ChromaDebt) void {
        d.rects.deinit(d.gpa);
    }

    /// LC 1 adds `rects` to the debt; LC 0 and LC 2 pay it off.
    pub fn sent(d: *ChromaDebt, lc: Lc, rects: []const avc420.Rect16) Error!void {
        for (rects) |r| {
            if (r.left >= r.right or r.top >= r.bottom) continue;
            try d.subtract(r);
            if (lc == .luma) try d.rects.append(d.gpa, r);
        }
        if (d.rects.items.len > max_rects) {
            const b = avc420.boundingRect(d.rects.items).?;
            d.rects.clearRetainingCapacity();
            d.rects.appendAssumeCapacity(b);
        }
    }

    fn subtract(d: *ChromaDebt, c: avc420.Rect16) Error!void {
        var i: usize = 0;
        while (i < d.rects.items.len) {
            const r = d.rects.items[i];
            if (c.left >= r.right or c.right <= r.left or c.top >= r.bottom or c.bottom <= r.top) {
                i += 1;
                continue;
            }
            _ = d.rects.swapRemove(i);
            const top = @max(r.top, c.top);
            const bottom = @min(r.bottom, c.bottom);
            const parts = [_]avc420.Rect16{
                .{ .left = r.left, .top = r.top, .right = r.right, .bottom = top },
                .{ .left = r.left, .top = bottom, .right = r.right, .bottom = r.bottom },
                .{ .left = r.left, .top = top, .right = @max(r.left, c.left), .bottom = bottom },
                .{ .left = @min(r.right, c.right), .top = top, .right = r.right, .bottom = bottom },
            };
            for (parts) |p| if (p.left < p.right and p.top < p.bottom) try d.rects.append(d.gpa, p);
        }
    }

    pub fn pending(d: *const ChromaDebt) Error!bool {
        return d.rects.items.len > 0;
    }

    /// When `out` is shorter than the list, its last entry bounds the rest.
    pub fn owed(d: *const ChromaDebt, out: []avc420.Rect16) Error![]avc420.Rect16 {
        const items = d.rects.items;
        if (items.len <= out.len) {
            @memcpy(out[0..items.len], items);
            return out[0..items.len];
        }
        if (out.len == 0) return error.BufferTooSmall;
        @memcpy(out[0 .. out.len - 1], items[0 .. out.len - 1]);
        out[out.len - 1] = avc420.boundingRect(items[out.len - 1 ..]).?;
        return out;
    }
};

/// MS-RDPEGFX 2.2.3: never with 8.x; implied by 10.1; otherwise unless
/// RDPGFX_CAPS_FLAG_AVC_DISABLED is set.
pub fn allowed(version: Version, caps_version: u32, caps_flags: u32) Error!bool {
    _ = version; // both are defined from 10.0 on (2.2.3.3 - 2.2.3.10)
    return switch (caps_version) {
        gfx.capversion_101 => true,
        gfx.capversion_10, gfx.capversion_102, gfx.capversion_103, gfx.capversion_104, gfx.capversion_105, gfx.capversion_106, gfx.capversion_106_err, gfx.capversion_107 => caps_flags & gfx.caps_flag_avc_disabled == 0,
        else => false,
    };
}

test "chroma debt splits a partially paid rect" {
    var d = try ChromaDebt.init(std.testing.allocator);
    defer d.deinit();
    try d.sent(.luma, &.{.{ .left = 0, .top = 0, .right = 64, .bottom = 64 }});
    try d.sent(.chroma, &.{.{ .left = 16, .top = 16, .right = 32, .bottom = 32 }});
    var area: u32 = 0;
    for (d.rects.items) |r| area += @as(u32, r.right - r.left) * (r.bottom - r.top);
    try std.testing.expectEqual(@as(u32, 64 * 64 - 16 * 16), area);
    try d.sent(.both, &.{.{ .left = 0, .top = 0, .right = 64, .bottom = 64 }});
    try std.testing.expect(!try d.pending());
}

test "toNv12 is bit-exact with rgbToYuv444 + split, v1 and v2, aligned and odd sizes" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x444_0ddf);
    const r = prng.random();
    const sizes = [_][2]u32{ .{ 64, 32 }, .{ 33, 17 }, .{ 1, 1 }, .{ 130, 67 }, .{ 48, 100 } };
    for (sizes) |sz| for ([_]Version{ .v1, .v2 }) |ver| {
        const w = sz[0];
        const h = sz[1];
        const stride = w * 4 + 12;
        const px = try gpa.alloc(u8, stride * h);
        defer gpa.free(px);
        r.bytes(px);
        const yuv = try gpa.alloc(u8, 3 * w * h);
        defer gpa.free(yuv);
        const src: Planes = .{ .y = yuv[0 .. w * h], .u = yuv[w * h ..][0 .. w * h], .v = yuv[2 * w * h ..][0 .. w * h], .width = w, .height = h, .y_stride = w, .uv_stride = w };
        try rgbToYuv444(px, stride, w, h, src);
        const vs = try viewSize(ver, w, h);
        const n = vs.width * vs.height;
        const ref = try gpa.alloc(u8, 3 * n);
        defer gpa.free(ref);
        const ref_main: Planes = .{ .y = ref[0..n], .u = ref[n..][0 .. n / 4], .v = ref[n + n / 4 ..][0 .. n / 4], .width = vs.width, .height = vs.height, .y_stride = vs.width, .uv_stride = vs.width / 2 };
        const ref_aux: Planes = .{ .y = ref[n + n / 2 ..][0..n], .u = ref[2 * n + n / 2 ..][0 .. n / 4], .v = ref[2 * n + n / 2 + n / 4 ..][0 .. n / 4], .width = vs.width, .height = vs.height, .y_stride = vs.width, .uv_stride = vs.width / 2 };
        try split(ver, src, ref_main, ref_aux);
        const pitch = vs.width + 32;
        const pic = try gpa.alloc(u8, 2 * (pitch * vs.height + pitch * vs.height / 2));
        defer gpa.free(pic);
        @memset(pic, 0xEE);
        const one = pitch * vs.height + pitch * vs.height / 2;
        const main: Nv12 = .{ .y = pic[0 .. pitch * vs.height], .y_pitch = pitch, .uv = pic[pitch * vs.height .. one], .uv_pitch = pitch };
        const aux: Nv12 = .{ .y = pic[one..][0 .. pitch * vs.height], .y_pitch = pitch, .uv = pic[one + pitch * vs.height ..][0 .. pitch * vs.height / 2], .uv_pitch = pitch };
        const scratch = try gpa.alloc(u8, nv12ScratchLen(w));
        defer gpa.free(scratch);
        try toNv12(ver, px, stride, w, h, main, aux, scratch);
        for ([_]Planes{ ref_main, ref_aux }, [_]Nv12{ main, aux }) |p, q| {
            for (0..vs.height) |y| try std.testing.expectEqualSlices(u8, p.y[y * vs.width ..][0..vs.width], q.y[y * pitch ..][0..vs.width]);
            for (0..vs.height / 2) |y| for (0..vs.width / 2) |x| {
                try std.testing.expectEqual(p.u[y * p.uv_stride + x], q.uv[y * pitch + 2 * x]);
                try std.testing.expectEqual(p.v[y * p.uv_stride + x], q.uv[y * pitch + 2 * x + 1]);
            };
            try std.testing.expectEqual(@as(u8, 0xEE), q.y[vs.width]);
        }
        @memset(pic, 0xEE);
        try toNv12(ver, px, stride, w, h, null, aux, scratch);
        try std.testing.expectEqual(@as(u8, 0xEE), main.y[0]);
        try std.testing.expectEqualSlices(u8, ref_aux.y[0..vs.width], aux.y[0..vs.width]);
    };
}

test "toNv12Rows in bands equals one toNv12" {
    const gpa = std.testing.allocator;
    for ([_]Version{ .v1, .v2 }) |ver| {
        const w: u32 = 100;
        const h: u32 = 75; // views 112x80 (v2: 128x80): 40 row pairs
        const px = try gpa.alloc(u8, w * h * 4);
        defer gpa.free(px);
        var prng = std.Random.DefaultPrng.init(0xBA5D);
        prng.random().bytes(px);
        const vs = try viewSize(ver, w, h);
        const pic = vs.width * vs.height * 3 / 2;
        const buf = try gpa.alloc(u8, 4 * pic);
        defer gpa.free(buf);
        @memset(buf, 0);
        const scratch = try gpa.alloc(u8, nv12ScratchLen(w));
        defer gpa.free(scratch);
        const n = vs.width * vs.height;
        var v: [4]Nv12 = undefined;
        for (&v, 0..) |*x, i| x.* = .{ .y = buf[i * pic ..][0..n], .y_pitch = vs.width, .uv = buf[i * pic + n ..][0 .. n / 2], .uv_pitch = vs.width };
        try toNv12(ver, px, w * 4, w, h, v[0], v[1], scratch);
        for ([_][2]usize{ .{ 0, 13 }, .{ 13, 13 }, .{ 13, 27 }, .{ 27, 40 } }) |r|
            try toNv12Rows(ver, px, w * 4, w, h, v[2], v[3], scratch, r[0], r[1]);
        try std.testing.expectEqualSlices(u8, buf[0 .. 2 * pic], buf[2 * pic ..]);
        try std.testing.expectError(error.InvalidDimensions, toNv12Rows(ver, px, w * 4, w, h, v[2], v[3], scratch, 30, 41));
        try std.testing.expectError(error.InvalidDimensions, toNv12Rows(ver, px, w * 4, w, h, v[2], v[3], scratch, 5, 4));
    }
}

test "toNv12 rejects short inputs, views and scratch" {
    var px: [64 * 4]u8 = undefined;
    var buf: [16 * 16 + 16 * 8]u8 = undefined;
    var buf32: [32 * 16 + 32 * 8]u8 = undefined;
    var scratch: [6 * 32]u8 = undefined;
    const v: Nv12 = .{ .y = buf[0 .. 16 * 16], .y_pitch = 16, .uv = buf[16 * 16 ..], .uv_pitch = 16 };
    const v32: Nv12 = .{ .y = buf32[0 .. 32 * 16], .y_pitch = 32, .uv = buf32[32 * 16 ..], .uv_pitch = 32 };
    try toNv12(.v1, &px, 64, 16, 4, v, null, &scratch);
    try toNv12(.v2, &px, 64, 16, 4, v32, null, &scratch);
    try std.testing.expectError(error.BufferTooSmall, toNv12(.v2, &px, 64, 16, 4, v, null, &scratch));
    try std.testing.expectError(error.InvalidDimensions, toNv12(.v2, &px, 60, 16, 4, v32, null, &scratch));
    try std.testing.expectError(error.InvalidDimensions, toNv12(.v2, px[0..100], 64, 16, 4, v32, null, &scratch));
    try std.testing.expectError(error.BufferTooSmall, toNv12(.v1, &px, 64, 16, 4, v, null, scratch[0..50]));
    try std.testing.expectError(error.BufferTooSmall, toNv12(.v1, &px, 64, 16, 4, .{ .y = buf[0..100], .y_pitch = 16, .uv = buf[16 * 16 ..], .uv_pitch = 16 }, null, &scratch));
    try std.testing.expectError(error.InvalidDimensions, toNv12(.v1, &px, 64, 0, 4, v, null, &scratch));
}

test "view sizes: height to 16, width to 16 (v1) or 32 (v2)" {
    const cases = [_][5]u32{
        .{ 1710, 1074, 1712, 1728, 1088 }, .{ 3420, 2148, 3424, 3424, 2160 }, .{ 1608, 900, 1616, 1632, 912 },
        .{ 1600, 900, 1600, 1600, 912 },   .{ 1632, 900, 1632, 1632, 912 },   .{ 1712, 1074, 1712, 1728, 1088 },
    };
    for (cases) |c| {
        const s1 = try viewSize(.v1, c[0], c[1]);
        const s2 = try viewSize(.v2, c[0], c[1]);
        try std.testing.expectEqual(ViewSize{ .width = c[2], .height = c[4] }, s1);
        try std.testing.expectEqual(ViewSize{ .width = c[3], .height = c[4] }, s2);
    }
}
