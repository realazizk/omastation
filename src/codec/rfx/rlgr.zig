//! RLGR1 / RLGR3 entropy coding (MS-RDPRFX 3.1.8.1.7) for RemoteFX tiles and the first
//! pass of RemoteFX Progressive tiles (MS-RDPEGFX 3.2.8.1.5.1, always RLGR1).

const std = @import("std");
const bits = @import("bits.zig");

pub const Mode = enum { rlgr1, rlgr3 };

const kp_max: u32 = 80;
const lsgr = 3;
const up_gr: u32 = 4;
const dn_gr: u32 = 6;
const uq_gr: u32 = 3;
const dq_gr: u32 = 3;

inline fn up(p: *u32, d: u32) u5 {
    p.* = @min(p.* + d, kp_max);
    return @intCast(p.* >> lsgr);
}

inline fn down(p: *u32, d: u32) u5 {
    p.* -|= d;
    return @intCast(p.* >> lsgr);
}

/// 2 * |v| - (v < 0): Get2MagSign.
inline fn twoMagSign(v: i16) u32 {
    const x: i32 = v;
    return if (x >= 0) @intCast(2 * x) else @intCast(-2 * x - 1);
}

/// GetIntFrom2MagSign; null if outside i16.
inline fn fromTwoMagSign(t: u32) ?i16 {
    if (t > 65535) return null;
    const mag: i32 = @intCast((t + 1) >> 1);
    return @intCast(if (t & 1 != 0) -mag else mag);
}

inline fn minBits(v: u32) u6 {
    return @intCast(32 - @clz(v));
}

inline fn codeGR(w: *bits.Writer, krp: *u32, val: u32) void {
    const kr: u5 = @intCast(krp.* >> lsgr);
    const vk = val >> kr;
    w.ones(vk);
    w.bit(0);
    if (kr != 0) w.bits(kr, val & ((@as(u32, 1) << kr) - 1));
    if (vk == 0) {
        _ = down(krp, 2);
    } else if (vk > 1) {
        _ = up(krp, vk);
    }
}

/// The byte count. Trailing zeros end as full 1 << k escapes plus the terminator, which
/// strict and zero-filling decoders both accept (the spec leaves termination undefined).
pub fn encode(mode: Mode, coeffs: []const i16, out: []u8) error{BufferTooSmall}!usize {
    var w = bits.Writer.init(out);
    var k: u5 = 1;
    var kp: u32 = 1 << lsgr;
    var krp: u32 = 1 << lsgr;
    var i: usize = 0;
    const n = coeffs.len;
    while (i < n) {
        if (k != 0) {
            const start = i;
            while (i < n and coeffs[i] == 0) i += 1;
            var zeros = i - start;
            var runmax: usize = @as(usize, 1) << k;
            while (zeros >= runmax) {
                w.bit(0);
                zeros -= runmax;
                k = up(&kp, up_gr);
                runmax = @as(usize, 1) << k;
            }
            w.bit(1);
            w.bits(k, @intCast(zeros));
            if (i == n) break; // the stream ends in this run
            const v: i32 = coeffs[i];
            i += 1;
            w.bit(@intFromBool(v < 0));
            codeGR(&w, &krp, @intCast(@abs(v) - 1));
            k = down(&kp, dn_gr);
        } else switch (mode) {
            .rlgr1 => {
                const t = twoMagSign(coeffs[i]);
                i += 1;
                codeGR(&w, &krp, t);
                k = if (t == 0) up(&kp, uq_gr) else down(&kp, dq_gr);
            },
            .rlgr3 => {
                const t1 = twoMagSign(coeffs[i]);
                const t2 = if (i + 1 < n) twoMagSign(coeffs[i + 1]) else 0;
                i = @min(i + 2, n);
                const sum = t1 + t2;
                codeGR(&w, &krp, sum);
                w.bits(minBits(sum), t1);
                if (t1 != 0 and t2 != 0) {
                    k = down(&kp, 2 * dq_gr);
                } else if (t1 == 0 and t2 == 0) {
                    k = up(&kp, 2 * uq_gr);
                }
            },
        }
    }
    return w.finish();
}

/// Bound on `encode` output for 4096 coefficients with |v| <= 2048; the worst case stays
/// in GR mode with kr = 0, under 115 bits per value.
pub const max_component_size: usize = 4096 * 120 / 8 + 64;

/// GetGRCode with its kr/krp update.
inline fn grCode(r: *bits.Reader, krp: *u32) error{BadRlgr}!u32 {
    const kr: u5 = @intCast(krp.* >> lsgr);
    const vk = r.run(1, 1 << 17) catch return error.BadRlgr;
    const rem = r.bits(kr) catch return error.BadRlgr;
    if (vk == 0) {
        _ = down(krp, 2);
    } else if (vk != 1) {
        _ = up(krp, @intCast(vk));
    }
    return @intCast((vk << kr) | rem);
}

/// Decode exactly `out.len` values (3.1.8.1.7.3.1). error.BadRlgr when the
/// data ends early, a run overshoots the output or a value overflows i16.
pub fn decode(mode: Mode, data: []const u8, out: []i16) error{BadRlgr}!void {
    var r = bits.Reader.init(data);
    var k: u5 = 1;
    var kp: u32 = 1 << lsgr;
    var krp: u32 = 1 << lsgr;
    var n: usize = 0;
    const total = out.len;
    while (n < total) {
        if (k != 0) {
            while ((r.bit() catch return error.BadRlgr) == 0) {
                const z = @min(@as(usize, 1) << k, total - n);
                @memset(out[n..][0..z], 0);
                n += z;
                k = up(&kp, up_gr);
                if (n == total) return;
            }
            const run = r.bits(k) catch return error.BadRlgr;
            if (run > total - n) return error.BadRlgr;
            @memset(out[n..][0..run], 0);
            n += run;
            if (n == total) return;
            const sign = r.bit() catch return error.BadRlgr;
            const mag = @as(u64, try grCode(&r, &krp)) + 1;
            if (mag > @as(u64, 32767) + sign) return error.BadRlgr;
            const m: i32 = @intCast(mag);
            out[n] = @intCast(if (sign == 1) -m else m);
            n += 1;
            k = down(&kp, dn_gr);
        } else {
            const code = try grCode(&r, &krp);
            switch (mode) {
                .rlgr1 => {
                    out[n] = fromTwoMagSign(code) orelse return error.BadRlgr;
                    n += 1;
                    k = if (code == 0) up(&kp, uq_gr) else down(&kp, dq_gr);
                },
                .rlgr3 => {
                    if (code > 2 * 65535) return error.BadRlgr;
                    const v1 = r.bits(minBits(code)) catch return error.BadRlgr;
                    if (v1 > code) return error.BadRlgr;
                    const v2 = code - v1;
                    if (v1 != 0 and v2 != 0) {
                        k = down(&kp, 2 * dq_gr);
                    } else if (v1 == 0 and v2 == 0) {
                        k = up(&kp, 2 * uq_gr);
                    }
                    out[n] = fromTwoMagSign(v1) orelse return error.BadRlgr;
                    n += 1;
                    if (n < total) {
                        out[n] = fromTwoMagSign(v2) orelse return error.BadRlgr;
                        n += 1;
                    }
                },
            }
        }
    }
}

test "RLGR1 of the MS-RDPEGFX 4.1.2.1.1 entries" {
    var out: [16]u8 = undefined;
    const in = [_]i16{ -2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 1, -7, 6 };
    const n = try encode(.rlgr1, &in, &out);
    try std.testing.expectEqualSlices(u8, &.{ 0xa8, 0x62, 0x6d, 0xff, 0xf7, 0x00 }, out[0..n]);
    var back: [14]i16 = undefined;
    try decode(.rlgr1, out[0..n], &back);
    try std.testing.expectEqualSlices(i16, &in, &back);
}

test "trailing zero runs round-trip exactly in both modes" {
    var c: [300]i16 = @splat(0);
    c[7] = -3;
    var out: [128]u8 = undefined;
    var back: [300]i16 = undefined;
    for ([_]Mode{ .rlgr1, .rlgr3 }) |m| {
        const n = try encode(m, &c, &out);
        try decode(m, out[0..n], &back);
        try std.testing.expectEqualSlices(i16, &c, &back);
    }
}

test "max_component_size holds for adversarial periodic components (|v| <= 2048)" {
    // one big value (or pair) every p, -1 between: -1 keeps GR mode while krp walks down
    var c: [4096]i16 = undefined;
    var out: [max_component_size]u8 = undefined;
    for ([_]Mode{ .rlgr1, .rlgr3 }) |m| for (2..90) |p| for ([_]i16{ 2048, -2048 }) |big| for (1..3) |width| {
        for (&c, 0..) |*v, i| v.* = if (i % p < width) big else -1;
        _ = try encode(m, &c, &out);
    };
}
