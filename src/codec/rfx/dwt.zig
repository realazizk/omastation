//! 2-D 5/3 DWT of a 64x64 tile component in 11.5 fixed point: the RemoteFX DWT (MS-RDPRFX
//! 3.1.8.1.4) and the Reduce-Extrapolate DWT of RemoteFX Progressive (MS-RDPEGFX 3.2.8.1.2.2).
//! The high band is halved, as RDP decoders double it back; stored coefficients saturate to i16.

const std = @import("std");

inline fn sat(v: i32) i16 {
    return @intCast(std.math.clamp(v, std.math.minInt(i16), std.math.maxInt(i16)));
}

// --- RemoteFX DWT ------------------------------------------------------------------------

/// One forward level on the (2 * sw) x (2 * sw) block at the start of
/// `buf`, writing HL, LH, HH, LL (sw x sw each) in that order.
fn encodeBlock(buf: []i16, tmp: []i16, sw: usize) void {
    const tw = 2 * sw;
    const lo = tmp[0 .. sw * tw];
    const hi = tmp[sw * tw .. 2 * sw * tw];
    for (0..tw) |x| {
        var hp: i32 = 0;
        for (0..sw) |n| {
            const s0: i32 = buf[2 * n * tw + x];
            const s1: i32 = buf[(2 * n + 1) * tw + x];
            const s2: i32 = if (n + 1 < sw) buf[(2 * n + 2) * tw + x] else s0;
            const h: i32 = sat((s1 - ((s0 + s2) >> 1)) >> 1);
            hi[n * tw + x] = @intCast(h);
            lo[n * tw + x] = sat(s0 + (if (n == 0) h else (hp + h) >> 1));
            hp = h;
        }
    }
    const ss = sw * sw;
    for (0..sw) |y| {
        inline for (.{ .{ lo, 0, 3 }, .{ hi, 2, 1 } }) |p| {
            const row = p[0][y * tw ..][0..tw];
            const high = buf[p[1] * ss + y * sw ..][0..sw];
            const low = buf[p[2] * ss + y * sw ..][0..sw];
            var hp: i32 = 0;
            for (0..sw) |n| {
                const s0: i32 = row[2 * n];
                const s1: i32 = row[2 * n + 1];
                const s2: i32 = if (n + 1 < sw) row[2 * n + 2] else s0;
                const h: i32 = sat((s1 - ((s0 + s2) >> 1)) >> 1);
                high[n] = @intCast(h);
                low[n] = sat(s0 + (if (n == 0) h else (hp + h) >> 1));
                hp = h;
            }
        }
    }
}

/// Forward three-level DWT; bands HL1 LH1 HH1 HL2 LH2 HH2 HL3 LH3 HH3 LL3.
pub fn encode(c: *[4096]i16) void {
    var tmp: [4096]i16 = undefined;
    encodeBlock(c[0..], &tmp, 32);
    encodeBlock(c[3072..], &tmp, 16);
    encodeBlock(c[3840..], &tmp, 8);
}

fn decodeBlock(buf: []i16, tmp: []i16, sw: usize) void {
    const tw = 2 * sw;
    const ss = sw * sw;
    for (0..sw) |y| {
        inline for (.{ .{ 3, 0, 0 }, .{ 1, 2, sw } }) |p| {
            const low = buf[p[0] * ss + y * sw ..][0..sw];
            const high = buf[p[1] * ss + y * sw ..][0..sw];
            const dst = tmp[(p[2] + y) * tw ..][0..tw];
            dst[0] = sat(@as(i32, low[0]) - ((@as(i32, high[0]) * 2 + 1) >> 1));
            for (1..sw) |n| dst[2 * n] = sat(@as(i32, low[n]) - ((@as(i32, high[n - 1]) + high[n] + 1) >> 1));
            for (0..sw - 1) |n| dst[2 * n + 1] = sat((@as(i32, high[n]) << 1) + ((@as(i32, dst[2 * n]) + dst[2 * n + 2]) >> 1));
            dst[tw - 1] = sat((@as(i32, high[sw - 1]) << 1) + dst[tw - 2]);
        }
    }
    for (0..tw) |x| {
        const at = struct {
            inline fn f(t: []const i16, row: usize, w: usize, col: usize) i32 {
                return t[row * w + col];
            }
        }.f;
        buf[x] = sat(at(tmp, 0, tw, x) - ((at(tmp, sw, tw, x) * 2 + 1) >> 1));
        for (1..sw) |n| {
            const hp = at(tmp, sw + n - 1, tw, x);
            const h = at(tmp, sw + n, tw, x);
            buf[2 * n * tw + x] = sat(at(tmp, n, tw, x) - ((hp + h + 1) >> 1));
            buf[(2 * n - 1) * tw + x] = sat((hp << 1) + ((at(buf, 2 * n - 2, tw, x) + at(buf, 2 * n, tw, x)) >> 1));
        }
        const h = at(tmp, 2 * sw - 1, tw, x);
        buf[(tw - 1) * tw + x] = sat((h << 1) + ((at(buf, tw - 2, tw, x) * 2) >> 1));
    }
}

/// Inverse of `encode`, rounding as RDP decoders do (MS-RDPRFX 3.1.8.2.4).
pub fn decode(c: *[4096]i16) void {
    var tmp: [4096]i16 = undefined;
    decodeBlock(c[3840..], &tmp, 8);
    decodeBlock(c[3072..], &tmp, 16);
    decodeBlock(c[0..], &tmp, 32);
}

// --- Reduce-Extrapolate DWT (MS-RDPEGFX 3.2.8.1.2.2) ----------------------------------------

/// Low/high band sizes of level 1..3: 33/31, 17/16, 9/8.
pub fn bandL(level: usize) usize {
    return (@as(usize, 64) >> @intCast(level)) + 1;
}

pub fn bandH(level: usize) usize {
    return if (level == 1) 31 else (64 + (@as(usize, 1) << @intCast(level - 1))) >> @intCast(level);
}

/// Offsets of each level's block in the Reduce-Extrapolate layout.
const re_offsets = [3]usize{ 0, 3007, 3807 };

/// Lifts x[0 .. 2m+1] into L[0 .. m+1] and H[0 .. m], mirrored at both ends.
fn liftOdd(x: []const i32, lo: []i32, hi: []i32) void {
    const m = hi.len;
    for (0..m) |n| hi[n] = (x[2 * n + 1] - ((x[2 * n] + x[2 * n + 2]) >> 1)) >> 1;
    lo[0] = x[0] + hi[0];
    for (1..m) |n| lo[n] = x[2 * n] + ((hi[n - 1] + hi[n]) >> 1);
    lo[m] = x[2 * m] + hi[m - 1];
}

/// 64 samples get a 65th, x[64] = 2 x[63] - x[62], whose high value (always 0) is
/// dropped; 33 and 17 samples are already odd.
fn liftRe(x: []const i32, lo: []i32, hi: []i32) void {
    if (x.len == 64) {
        var ext: [65]i32 = undefined;
        @memcpy(ext[0..64], x);
        ext[64] = 2 * x[63] - x[62];
        var h: [32]i32 = undefined;
        liftOdd(&ext, lo[0..33], &h);
        @memcpy(hi[0..31], h[0..31]);
    } else liftOdd(x, lo, hi);
}

/// One forward Reduce-Extrapolate level on the n x n block at the start of
/// `buf` (row step n): HL (nl rows of nh), LH (nh rows of nl), HH, LL.
fn encodeBlockRe(buf: []i16, level: usize) void {
    const n = if (level == 1) 64 else bandL(level - 1);
    const nl = bandL(level);
    const nh = bandH(level);
    var lo_rows: [33 * 64]i32 = undefined; // nl rows of n
    var hi_rows: [31 * 64]i32 = undefined; // nh rows of n
    var col: [64]i32 = undefined;
    var lo: [33]i32 = undefined;
    var hi: [32]i32 = undefined;
    for (0..n) |x| {
        for (0..n) |y| col[y] = buf[y * n + x];
        liftRe(col[0..n], lo[0..nl], hi[0..nh]);
        for (0..nl) |y| lo_rows[y * n + x] = lo[y];
        for (0..nh) |y| hi_rows[y * n + x] = hi[y];
    }
    const hl = 0;
    const lh = nh * nl;
    const hh = 2 * nh * nl;
    const ll = 2 * nh * nl + nh * nh;
    for (0..nl) |y| {
        liftRe(lo_rows[y * n ..][0..n], lo[0..nl], hi[0..nh]);
        for (0..nh) |i| buf[hl + y * nh + i] = sat(hi[i]);
        for (0..nl) |i| buf[ll + y * nl + i] = sat(lo[i]);
    }
    for (0..nh) |y| {
        liftRe(hi_rows[y * n ..][0..n], lo[0..nl], hi[0..nh]);
        for (0..nh) |i| buf[hh + y * nh + i] = sat(hi[i]);
        for (0..nl) |i| buf[lh + y * nl + i] = sat(lo[i]);
    }
}

/// Forward Reduce-Extrapolate DWT; same band order, 3.2.8.1.2.2 band sizes.
pub fn encodeExtrapolate(c: *[4096]i16) void {
    // each level reads its whole input block before writing its bands
    encodeBlockRe(c[re_offsets[0]..], 1);
    encodeBlockRe(c[re_offsets[1]..], 2);
    encodeBlockRe(c[re_offsets[2]..], 3);
}

inline fn div2(v: i32) i32 {
    return @divTrunc(v, 2);
}

/// Inverse DWT of one line: low (nl values, step ls) and high (nh values,
/// step hs) into nl + nh outputs (step ds).
fn idwtLine(low: []const i16, ls: usize, high: []const i16, hs: usize, dst: []i16, ds: usize, nl: usize, nh: usize) void {
    var li: usize = 0;
    var hi: usize = 0;
    var di: usize = 0;
    var h0: i32 = high[0];
    hi += hs;
    var l0: i32 = low[0];
    li += ls;
    var x0: i32 = sat(l0 - h0);
    var x2: i32 = x0;
    for (0..nh - 1) |_| {
        const h1: i32 = high[hi];
        hi += hs;
        l0 = low[li];
        li += ls;
        x2 = sat(l0 - div2(h0 + h1));
        const x1: i32 = sat(div2(x0 + x2) + 2 * h0);
        dst[di] = @intCast(x0);
        dst[di + ds] = @intCast(x1);
        di += 2 * ds;
        x0 = x2;
        h0 = h1;
    }
    if (nl <= nh + 1) {
        if (nl <= nh) {
            dst[di] = @intCast(x2);
            dst[di + ds] = sat(x2 + 2 * h0);
        } else {
            l0 = low[li];
            x0 = sat(l0 - h0);
            dst[di] = @intCast(x2);
            dst[di + ds] = sat(div2(x0 + x2) + 2 * h0);
            dst[di + 2 * ds] = @intCast(x0);
        }
    } else {
        l0 = low[li];
        li += ls;
        x0 = sat(l0 - div2(h0));
        dst[di] = @intCast(x2);
        dst[di + ds] = sat(div2(x0 + x2) + 2 * h0);
        dst[di + 2 * ds] = @intCast(x0);
        l0 = low[li];
        dst[di + 3 * ds] = sat(div2(x0 + l0));
    }
}

fn decodeBlockRe(buf: []i16, level: usize) void {
    const nl = bandL(level);
    const nh = bandH(level);
    const n = nl + nh;
    const hl = buf[0..];
    const lh = buf[nh * nl ..];
    const hh = buf[2 * nh * nl ..];
    const ll = buf[2 * nh * nl + nh * nh ..];
    var tmp: [64 * 64]i16 = undefined;
    const lrows = tmp[0 .. nl * n];
    const hrows = tmp[nl * n ..][0 .. nh * n];
    for (0..nl) |y| idwtLine(ll[y * nl ..], 1, hl[y * nh ..], 1, lrows[y * n ..], 1, nl, nh);
    for (0..nh) |y| idwtLine(lh[y * nl ..], 1, hh[y * nh ..], 1, hrows[y * n ..], 1, nl, nh);
    var out: [64 * 64]i16 = undefined;
    for (0..n) |x| idwtLine(lrows[x..], n, hrows[x..], n, out[x..], n, nl, nh);
    @memcpy(buf[0 .. n * n], out[0 .. n * n]);
}

/// Inverse of `encodeExtrapolate`.
pub fn decodeExtrapolate(c: *[4096]i16) void {
    decodeBlockRe(c[re_offsets[2]..], 3);
    decodeBlockRe(c[re_offsets[1]..], 2);
    decodeBlockRe(c[0..], 1);
}

test "Reduce-Extrapolate band sizes" {
    try std.testing.expectEqual(@as(usize, 33), bandL(1));
    try std.testing.expectEqual(@as(usize, 31), bandH(1));
    try std.testing.expectEqual(@as(usize, 17), bandL(2));
    try std.testing.expectEqual(@as(usize, 16), bandH(2));
    try std.testing.expectEqual(@as(usize, 9), bandL(3));
    try std.testing.expectEqual(@as(usize, 8), bandH(3));
}

test "both transforms invert a ramp within a quarter of an 8-bit level (8 in 11.5)" {
    var c: [4096]i16 = undefined;
    for (&c, 0..) |*v, i| v.* = @intCast(@as(i32, @intCast((i % 64) * 40 + (i / 64) * 20)) - 2000);
    const orig = c;
    encode(&c);
    decode(&c);
    for (c, orig) |a, b| try std.testing.expect(@abs(@as(i32, a) - b) <= 8);
    c = orig;
    encodeExtrapolate(&c);
    decodeExtrapolate(&c);
    for (c, orig) |a, b| try std.testing.expect(@abs(@as(i32, a) - b) <= 8);
}
