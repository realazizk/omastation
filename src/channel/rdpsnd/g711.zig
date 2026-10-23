//! G.711 A-law and mu-law (WAVE_FORMAT_ALAW, WAVE_FORMAT_MULAW; MS-RDPEA 4.1.1).

const std = @import("std");

pub fn alawEncode(x: i16) u8 {
    var ix: u16 = @intCast((if (x < 0) ~@as(i32, x) else @as(i32, x)) >> 4);
    if (ix > 15) {
        var exp: u16 = 1;
        while (ix > 16 + 15) : (exp += 1) ix >>= 1;
        ix = (ix - 16) + (exp << 4);
    }
    if (x >= 0) ix |= 0x80;
    return @as(u8, @truncate(ix)) ^ 0x55;
}

/// Reconstruction level of an A-law code (G.711 Table 1a, 16-bit scale).
pub fn alawDecode(code: u8) i16 {
    const a = code ^ 0x55;
    var t: i32 = @as(i32, a & 0x0F) << 4;
    const seg: u5 = @intCast((a & 0x70) >> 4);
    switch (seg) {
        0 => t += 8,
        1 => t += 0x108,
        else => {
            t += 0x108;
            t <<= seg - 1;
        },
    }
    return @intCast(if (a & 0x80 != 0) t else -t);
}

const ulaw_bias: i32 = 0x84;

pub fn mulawEncode(x: i16) u8 {
    // 14-bit magnitude plus the bias of 33 (0x84 on the 16-bit scale).
    var absno: i32 = (if (x < 0) ~@as(i32, x) else @as(i32, x)) >> 2;
    absno = @min(absno + 33, 0x1FFF);
    var seg: u5 = 1;
    var i = absno >> 6;
    while (i != 0) : (i >>= 1) seg += 1;
    const high: u8 = @intCast(8 - @as(i32, seg));
    const low: u8 = @intCast(0x0F - ((absno >> seg) & 0x0F));
    var v: u8 = (high << 4) | low;
    if (x >= 0) v |= 0x80;
    return v;
}

/// Reconstruction level of a mu-law code (G.711 Table 2a, 16-bit scale).
pub fn mulawDecode(code: u8) i16 {
    const v = ~code;
    var t: i32 = (@as(i32, v & 0x0F) << 3) + ulaw_bias;
    t <<= @intCast((v & 0x70) >> 4);
    return @intCast(if (v & 0x80 != 0) ulaw_bias - t else t - ulaw_bias);
}

test "G.711 anchors" {
    try std.testing.expectEqual(@as(u8, 0xD5), alawEncode(0));
    try std.testing.expectEqual(@as(u8, 0xAA), alawEncode(32767));
    try std.testing.expectEqual(@as(u8, 0x2A), alawEncode(-32768));
    try std.testing.expectEqual(@as(u8, 0xFF), mulawEncode(0));
    try std.testing.expectEqual(@as(u8, 0x80), mulawEncode(32767));
    try std.testing.expectEqual(@as(u8, 0x00), mulawEncode(-32768));
    try std.testing.expectEqual(@as(i16, -32124), mulawDecode(0x00));
    try std.testing.expectEqual(@as(i16, 32256), alawDecode(0xAA));
}
