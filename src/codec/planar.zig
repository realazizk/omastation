//! Planar codec: RDP 6.0 Bitmap Compression (MS-RDPEGDI 2.2.2.5.1, 3.1.9) for
//! RDPGFX_CODECID_PLANAR (MS-RDPEGFX 2.2.2.1). Lossless and top-down: CLL = 0, no subsampling,
//! no alpha plane; RLE (3.1.9.2) of delta-folded R, G, B planes, or raw planes when smaller.

const std = @import("std");

pub const header_cll_mask: u8 = 0x07;
pub const header_cs: u8 = 0x08;
pub const header_rle: u8 = 0x10;
pub const header_na: u8 = 0x20;

pub const EncodeError = error{InvalidDimensions} || std.mem.Allocator.Error;
pub const DecodeError = error{ BadPlanar, UnsupportedPlanar };

/// Byte offsets of R, G, B in a BGRX/BGRA pixel, in plane order.
pub const plane_channels = [_]usize{ 2, 1, 0 };

pub fn maxEncodedSize(width: u16, height: u16) usize {
    const w: usize = width;
    const h: usize = height;
    const raw = 1 + 3 * w * h + 1;
    const rle = 1 + 3 * h * rowBound(w);
    return @max(raw, rle);
}

/// RAW bytes plus one control byte per 15, plus slack. MUST be an upper bound: the
/// encoder writes into reserved capacity.
pub fn rowBound(w: usize) usize {
    return w + w / 15 + 2;
}

/// Appends planar bitmapData for top-down B, G, R, X pixels `stride` bytes apart.
pub fn encodePlanar(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    pixels: []const u8,
    stride: usize,
    width: u16,
    height: u16,
) EncodeError!void {
    const w: usize = width;
    const h: usize = height;
    if (w == 0 or h == 0) return error.InvalidDimensions;
    if (stride < w * 4 or pixels.len < (h - 1) * stride + w * 4) return error.InvalidDimensions;

    const raw_size = 1 + 3 * w * h + 1;
    try out.ensureUnusedCapacity(gpa, maxEncodedSize(width, height));
    var row_buf: [4096]u8 = undefined;
    const tmp = if (w <= row_buf.len) row_buf[0..w] else try gpa.alloc(u8, w);
    defer if (w > row_buf.len) gpa.free(tmp);
    const buf = out.unusedCapacitySlice();

    buf[0] = header_rle | header_na;
    var o: usize = 1;
    rle: {
        inline for (plane_channels) |ch| {
            // Budget: what is left before RLE stops beating raw planes.
            o += encodePlane(buf[o..], pixels, stride, w, h, 4, ch, tmp, raw_size - o) orelse break :rle;
        }
        if (o < raw_size) {
            out.items.len += o;
            return;
        }
    }

    // RLE does not pay off: raw planes (absolute values) + pad byte.
    buf[0] = header_na;
    o = 1;
    inline for (plane_channels) |ch| {
        for (0..h) |y| {
            const row = pixels[y * stride ..][0 .. w * 4];
            for (buf[o..][0..w], 0..) |*d, x| d.* = row[x * 4 + ch];
            o += w;
        }
    }
    buf[o] = 0;
    out.items.len += o + 1;
}

/// RLE of channel `ch` (pixels `step` bytes apart). Null once the length reaches `limit`.
pub fn encodePlane(
    dst: []u8,
    pixels: []const u8,
    stride: usize,
    w: usize,
    h: usize,
    comptime step: usize,
    comptime ch: usize,
    tmp: []u8,
    limit: usize,
) ?usize {
    var o: usize = 0;
    for (0..h) |y| {
        const cur = pixels[y * stride ..][0 .. w * step];
        if (y == 0) {
            for (tmp[0..w], 0..) |*t, x| t.* = cur[x * step + ch];
        } else {
            const prev = pixels[(y - 1) * stride ..][0 .. w * step];
            deltaRow(tmp[0..w], cur, prev, step, ch);
        }
        o += rleRow(dst[o..], tmp[0..w]);
        if (o >= limit) return null;
    }
    return o;
}

/// tmp[x] = sign-folded (cur - prev) of channel ch.
pub inline fn deltaRow(tmp: []u8, cur: []const u8, prev: []const u8, comptime step: usize, comptime ch: usize) void {
    const V = 16;
    var x: usize = 0;
    if (step == 4) {
        const mask: @Vector(V, i32) = comptime blk: {
            var m: [V]i32 = undefined;
            for (0..V) |k| m[k] = @intCast(k * 4 + ch);
            break :blk m;
        };
        while (x + V <= tmp.len) : (x += V) {
            const c: @Vector(V * 4, u8) = cur[x * 4 ..][0 .. V * 4].*;
            const p: @Vector(V * 4, u8) = prev[x * 4 ..][0 .. V * 4].*;
            const cc = @shuffle(u8, c, undefined, mask);
            const pp = @shuffle(u8, p, undefined, mask);
            const d = cc -% pp;
            const sign = @as(@Vector(V, u8), @bitCast(@as(@Vector(V, i8), @bitCast(d)) >> @splat(7)));
            tmp[x..][0..V].* = (d << @splat(1)) ^ sign;
        }
    }
    while (x < tmp.len) : (x += 1) {
        const d = cur[x * step + ch] -% prev[x * step + ch];
        tmp[x] = (d << 1) ^ (if (d & 0x80 != 0) @as(u8, 0xFF) else 0);
    }
}

pub inline fn runLength(e: []const u8, i: usize) usize {
    const v = e[i];
    var j = i + 1;
    if (j >= e.len or e[j] != v) return 1;
    j += 1;
    const V = 16;
    const vv: @Vector(V, u8) = @splat(v);
    while (j + V <= e.len) : (j += V) {
        const chunk: @Vector(V, u8) = e[j..][0..V].*;
        const ne: u16 = @bitCast(chunk != vv);
        if (ne != 0) return j + @ctz(ne) - i;
    }
    while (j < e.len and e[j] == v) j += 1;
    return j - i;
}

pub fn rleRow(dst: []u8, e: []const u8) usize {
    var o: usize = 0;
    var i: usize = 0;
    // The decoder's run value starts at 0 on every line, so leading zeros need no RAW byte.
    if (e[0] == 0) {
        const l = runLength(e, 0);
        if (l >= 3) {
            o += putRun(dst[o..], l);
            i = l;
        }
    }
    var raw_start = i;
    while (i < e.len) {
        const l = runLength(e, i);
        // A RUN repeats the last RAW byte: l equal values cost one RAW byte plus a RUN of l - 1 (>= 3).
        if (l >= 4) {
            o += putSegment(dst[o..], e[raw_start .. i + 1], l - 1);
            raw_start = i + l;
        }
        i += l;
    }
    if (raw_start < e.len) o += putSegment(dst[o..], e[raw_start..], 0);
    return o;
}

/// RAW bytes (non-empty) followed by a RUN of 0 or >= 3 repeats of the last.
pub fn putSegment(dst: []u8, raw_bytes: []const u8, run: usize) usize {
    std.debug.assert(raw_bytes.len > 0 and (run == 0 or run >= 3));
    var o: usize = 0;
    var raw = raw_bytes;
    while (raw.len > 15) {
        dst[o] = 0xF0;
        @memcpy(dst[o + 1 ..][0..15], raw[0..15]);
        o += 16;
        raw = raw[15..];
    }
    // nRunLength 1 and 2 are the long-run escapes, so never leave 1 or 2 for the next segment.
    const first: usize = if (run <= 15) run else if (run < 18) 13 else 15;
    dst[o] = @intCast(raw.len << 4 | first);
    @memcpy(dst[o + 1 ..][0..raw.len], raw);
    o += 1 + raw.len;
    if (run > first) o += putRun(dst[o..], run - first);
    return o;
}

/// RAW-less RUN segments repeating the current run value `run` (>= 3) times.
pub fn putRun(dst: []u8, run: usize) usize {
    std.debug.assert(run >= 3);
    var n = run;
    var o: usize = 0;
    while (n > 47) {
        // 47 per byte, but never leave 1 or 2 behind.
        const take: usize = if (n - 47 < 3) 45 else 47;
        dst[o] = @intCast((take - 32) << 4 | 2);
        o += 1;
        n -= take;
    }
    dst[o] = @intCast(if (n >= 32) (n - 32) << 4 | 2 else if (n >= 16) (n - 16) << 4 | 1 else n);
    return o + 1;
}

/// Decodes CLL = 0 bitmapData into top-down B, G, R, A. Malformed input yields
/// error.BadPlanar. Returns the bytes of `src` consumed.
pub fn decodePlanar(src: []const u8, width: u16, height: u16, dst: []u8, dst_stride: usize) DecodeError!usize {
    const w: usize = width;
    const h: usize = height;
    if (w == 0 or h == 0) return error.BadPlanar;
    if (dst_stride < w * 4 or dst.len < (h - 1) * dst_stride + w * 4) return error.BadPlanar;
    if (src.len == 0) return error.BadPlanar;
    const header = src[0];
    if (header & header_cll_mask != 0) return error.UnsupportedPlanar; // AYCoCg (lossy)
    if (header & header_cs != 0) return error.BadPlanar; // CS requires CLL > 0
    const rle = header & header_rle != 0;
    const has_alpha = header & header_na == 0;

    var p: usize = 1;
    const channels = [_]usize{ 3, 2, 1, 0 };
    for (channels[if (has_alpha) 0 else 1..]) |ch| {
        if (rle) {
            p += try decodePlane(src[p..], w, h, dst, dst_stride, 4, ch);
        } else {
            if (src.len - p < w * h) return error.BadPlanar;
            for (0..h) |y| {
                const row = dst[y * dst_stride ..][0 .. w * 4];
                for (src[p..][0..w], 0..) |v, x| row[x * 4 + ch] = v;
                p += w;
            }
        }
    }
    if (!has_alpha) {
        for (0..h) |y| {
            const row = dst[y * dst_stride ..][0 .. w * 4];
            for (0..w) |x| row[x * 4 + 3] = 0xFF;
        }
    }
    // Raw planes are followed by a pad byte (optional per spec).
    if (!rle and p < src.len) p += 1;
    return p;
}

/// Returns the bytes consumed.
pub fn decodePlane(src: []const u8, w: usize, h: usize, dst: []u8, stride: usize, comptime step: usize, ch: usize) DecodeError!usize {
    var p: usize = 0;
    for (0..h) |y| {
        const row = dst[y * stride ..][0 .. w * step];
        const prev: ?[]const u8 = if (y == 0) null else dst[(y - 1) * stride ..][0 .. w * step];
        var x: usize = 0;
        var value: u8 = 0; // last RAW value on this line
        while (x < w) {
            if (p >= src.len) return error.BadPlanar;
            const control = src[p];
            p += 1;
            var run: usize = control & 0x0F;
            var raw: usize = control >> 4;
            if (run == 1) {
                run = 16 + raw;
                raw = 0;
            } else if (run == 2) {
                run = 32 + raw;
                raw = 0;
            }
            if (raw + run == 0) return error.BadPlanar; // control byte MUST be nonzero
            if (raw + run > w - x or raw > src.len - p) return error.BadPlanar;
            for (src[p..][0..raw]) |v| {
                value = v;
                row[x * step + ch] = if (prev) |pr| pr[x * step + ch] +% unfold(v) else v;
                x += 1;
            }
            p += raw;
            for (0..run) |_| {
                row[x * step + ch] = if (prev) |pr| pr[x * step + ch] +% unfold(value) else value;
                x += 1;
            }
        }
    }
    return p;
}

/// Inverse of the delta sign folding: even -> v/2, odd -> -(v/2) - 1.
pub inline fn unfold(v: u8) u8 {
    return (v >> 1) ^ (0 -% (v & 1));
}

const testing = std.testing;
const bytes = @import("../core/bytes.zig");

fn testEncodePlane(plane: []const u8, w: usize, h: usize, out: []u8) usize {
    var tmp: [1024]u8 = undefined;
    return encodePlane(out, plane, w, w, h, 1, 0, &tmp, out.len).?;
}

test "spec 3.1.9.2.1 RLE encoding example (6x3 plane)" {
    const plane = [_]u8{
        255, 255, 255, 255, 254, 253,
        254, 192, 132, 96,  75,  25,
        253, 140, 62,  14,  135, 193,
    };
    const expected = bytes.hex("13 FF 20 FE FD 60 01 7D F5 C2 9A 38 60 01 67 8B A3 78 AF");
    var out: [64]u8 = undefined;
    const n = testEncodePlane(&plane, 6, 3, &out);
    try testing.expectEqualSlices(u8, &expected, out[0..n]);

    // 3.1.9.2.3 decodes the same bytes back.
    var dec: [18]u8 = undefined;
    try testing.expectEqual(expected.len, try decodePlane(&expected, 6, 3, &dec, 6, 1, 0));
    try testing.expectEqualSlices(u8, &plane, &dec);
}

test "spec 3.1.9.2.2 extra long run (100 x 'A')" {
    const plane: [100]u8 = @splat('A');
    var out: [16]u8 = undefined;
    const n = testEncodePlane(&plane, 100, 1, &out);
    try testing.expectEqualSlices(u8, &bytes.hex("1F 41 F2 52"), out[0..n]);
    var dec: [100]u8 = undefined;
    _ = try decodePlane(out[0..n], 100, 1, &dec, 100, 1, 0);
    try testing.expectEqualSlices(u8, &plane, &dec);
}

test "spec 3.1.9.2 delta example: unchanged row is a RAW-less run" {
    const plane = [_]u8{ 10, 20, 30, 40, 50, 60, 5, 15, 25, 35, 45, 55, 5, 15, 25, 35, 45, 55 };
    var out: [32]u8 = undefined;
    const n = testEncodePlane(&plane, 6, 3, &out);
    // RAW[10..60]; RAW[-5 -> 0x09] RUN[5]; RUN[6] of 0.
    try testing.expectEqualSlices(u8, &bytes.hex("60 0A 14 1E 28 32 3C 15 09 06"), out[0..n]);
}

test "run splitting covers every length" {
    // Runs of 1..300 after a raw prefix, and of zero at line start, never use a 0 control byte.
    var plane: [400]u8 = undefined;
    var out: [600]u8 = undefined;
    var dec: [400]u8 = undefined;
    for (1..301) |len| {
        for ([_]u8{ 0, 7 }) |v| {
            const w = len + 5;
            @memset(plane[0..len], v);
            for (plane[len..w], 0..) |*b, k| b.* = @intCast(100 + k);
            const n = testEncodePlane(plane[0..w], w, 1, &out);
            try testing.expectEqual(n, try decodePlane(out[0..n], w, 1, &dec, w, 1, 0));
            try testing.expectEqualSlices(u8, plane[0..w], dec[0..w]);
            plane[0] = 200;
            plane[1] = 201;
            const n2 = testEncodePlane(plane[0..w], w, 1, &out);
            try testing.expectEqual(n2, try decodePlane(out[0..n2], w, 1, &dec, w, 1, 0));
            try testing.expectEqualSlices(u8, plane[0..w], dec[0..w]);
        }
    }
}

test "RLE scan line never exceeds rowBound" {
    var prng = std.Random.DefaultPrng.init(15);
    const rnd = prng.random();
    var e: [700]u8 = undefined;
    var out: [800]u8 = undefined;
    var dec: [700]u8 = undefined;
    for (0..20_000) |_| {
        const w = 1 + rnd.uintLessThan(usize, e.len);
        var i: usize = 0;
        while (i < w) {
            const l = @min(w - i, 1 + rnd.uintLessThan(usize, if (rnd.boolean()) 5 else 60));
            @memset(e[i..][0..l], rnd.uintLessThan(u8, 3));
            i += l;
        }
        const n = rleRow(&out, e[0..w]);
        try testing.expect(n <= rowBound(w));
        try testing.expectEqual(n, try decodePlane(out[0..n], w, 1, &dec, w, 1, 0));
        try testing.expectEqualSlices(u8, e[0..w], dec[0..w]);
    }
}

fn checkRoundTrip(gpa: std.mem.Allocator, pixels: []const u8, stride: usize, w: u16, h: u16) !usize {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try encodePlanar(gpa, &out, pixels, stride, w, h);
    try testing.expect(out.items.len <= maxEncodedSize(w, h));
    const dec = try gpa.alloc(u8, @as(usize, w) * h * 4);
    defer gpa.free(dec);
    try testing.expectEqual(out.items.len, try decodePlanar(out.items, w, h, dec, @as(usize, w) * 4));
    for (0..h) |y| for (0..w) |x| {
        const s = pixels[y * stride + x * 4 ..][0..3];
        const d = dec[(y * w + x) * 4 ..][0..4];
        try testing.expectEqualSlices(u8, s, d[0..3]);
        try testing.expectEqual(@as(u8, 0xFF), d[3]);
    };
    return out.items.len;
}

test "round trips: flat, gradient, noise, odd sizes, padded stride" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(11);
    const rnd = prng.random();
    const sizes = [_][2]u16{ .{ 1, 1 }, .{ 1, 7 }, .{ 7, 1 }, .{ 2, 2 }, .{ 15, 3 }, .{ 16, 16 }, .{ 17, 5 }, .{ 64, 64 }, .{ 100, 37 }, .{ 333, 20 } };
    for (sizes) |sz| {
        const w = sz[0];
        const h = sz[1];
        const stride = @as(usize, w) * 4 + 12;
        const px = try gpa.alloc(u8, stride * h);
        defer gpa.free(px);
        for (0..4) |kind| {
            for (0..h) |y| for (0..w) |x| {
                const p = px[y * stride + x * 4 ..][0..4];
                switch (kind) {
                    0 => p.* = .{ 0x30, 0x20, 0x10, 0 },
                    1 => p.* = .{ @truncate(x * 3), @truncate(y * 5), @truncate(x + y), 0xAA },
                    2 => rnd.bytes(p),
                    else => p.* = if ((x / 3 + y / 2) % 3 == 0) .{ 0xFF, 0xFF, 0xFF, 0 } else .{ 0, 0, 0, 0 },
                }
            };
            const n = try checkRoundTrip(gpa, px, stride, w, h);
            const raw = 2 + 3 * @as(usize, w) * h;
            if (kind == 2) try testing.expect(n <= raw);
            if (kind == 0 and w * h > 16) try testing.expect(n < raw / 4);
        }
    }
}

test "noise falls back to raw planes with pad byte" {
    const gpa = testing.allocator;
    var px: [32 * 32 * 4]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(12);
    prng.random().bytes(&px);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try encodePlanar(gpa, &out, &px, 32 * 4, 32, 32);
    try testing.expectEqual(header_na, out.items[0]);
    try testing.expectEqual(@as(usize, 1 + 3 * 32 * 32 + 1), out.items.len);
}

test "encoder rejects bad dimensions" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var px: [64]u8 = @splat(0);
    try testing.expectError(error.InvalidDimensions, encodePlanar(gpa, &out, &px, 16, 0, 1));
    try testing.expectError(error.InvalidDimensions, encodePlanar(gpa, &out, &px, 8, 4, 1));
    try testing.expectError(error.InvalidDimensions, encodePlanar(gpa, &out, &px, 16, 4, 5));
}

test "decoder rejects malformed input without panicking" {
    var dst: [8 * 8 * 4]u8 = undefined;
    const bad = [_][]const u8{
        "",
        &bytes.hex("31"), // CLL = 1
        &bytes.hex("38"), // CS without CLL
        &bytes.hex("30"), // truncated
        &bytes.hex("30 00"), // zero control byte
        &bytes.hex("30 90 01 02 03 04 05 06 07 08 09"), // 9 raw > width 8
        &bytes.hex("30 0F"), // run 15 > width 8
        &bytes.hex("30 80 01 02"), // raw bytes truncated
        &bytes.hex("20 00 01"), // raw planes truncated
        &bytes.hex("30 10 FA 10 FA"), // real encoder's 1x1 output with the B plane missing
    };
    for (bad) |src| {
        if (decodePlanar(src, 8, 8, &dst, 32)) |_| return error.TestUnexpectedSuccess else |_| {}
    }
    try testing.expectError(error.BadPlanar, decodePlanar(&bytes.hex("30"), 8, 8, dst[0..10], 32));
}

test "decoder survives mutated valid streams" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(14);
    const rnd = prng.random();
    const w = 40;
    const h = 30;
    var px: [w * h * 4]u8 = undefined;
    for (0..h) |y| for (0..w) |x| {
        px[(y * w + x) * 4 ..][0..4].* = if ((x / 5 + y / 3) % 4 == 0) .{ 0xFF, 0x80, 0x10, 0 } else .{ @truncate(x * 7), @truncate(y * 3), 0x20, 0 };
    };
    var enc: std.ArrayList(u8) = .empty;
    defer enc.deinit(gpa);
    try encodePlanar(gpa, &enc, &px, w * 4, w, h);
    var dst: [w * h * 4]u8 = undefined;
    const mutated = try gpa.dupe(u8, enc.items);
    defer gpa.free(mutated);
    for (0..20_000) |_| {
        @memcpy(mutated, enc.items);
        for (0..1 + rnd.uintLessThan(usize, 4)) |_| {
            const at = rnd.uintLessThan(usize, mutated.len);
            mutated[at] ^= @as(u8, 1) << rnd.int(u3);
        }
        const n = rnd.uintLessThan(usize, mutated.len + 1);
        _ = decodePlanar(mutated[0..n], w, h, &dst, w * 4) catch {};
    }
}

test "decoder survives random garbage" {
    var prng = std.Random.DefaultPrng.init(13);
    const rnd = prng.random();
    var src: [400]u8 = undefined;
    var dst: [16 * 9 * 4]u8 = undefined;
    for (0..20_000) |iter| {
        const n = rnd.uintLessThan(usize, src.len);
        rnd.bytes(src[0..n]);
        if (n > 0) src[0] = @as(u8, if (iter % 2 == 0) 0x30 else 0x10) | @as(u8, if (iter % 5 == 0) 0x20 else 0);
        _ = decodePlanar(src[0..n], 16, 9, &dst, 64) catch {};
    }
}
