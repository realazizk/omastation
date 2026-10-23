//! UpperCase for NTOWFv2 (MS-NLMP 3.3.2): the Windows per-code-unit upcase table,
//! generated from FreeRDP 3.31.1's WinPR; surrogates and unmapped units are unchanged.

const std = @import("std");

/// Code units first..last, every `stride`-th, map to cu + delta.
const Run = struct { u16, u16, i32, u2 };

const runs = [_]Run{
    .{ 0x0061, 0x007a, -32, 1 },
    .{ 0x00b5, 0x00b5, 743, 1 },
    .{ 0x00e0, 0x00f6, -32, 1 },
    .{ 0x00f8, 0x00fe, -32, 1 },
    .{ 0x00ff, 0x00ff, 121, 1 },
    .{ 0x0101, 0x012f, -1, 2 },
    .{ 0x0131, 0x0131, -232, 1 },
    .{ 0x0133, 0x0137, -1, 2 },
    .{ 0x013a, 0x0148, -1, 2 },
    .{ 0x014b, 0x0177, -1, 2 },
    .{ 0x017a, 0x017e, -1, 2 },
    .{ 0x017f, 0x017f, -300, 1 },
    .{ 0x0180, 0x0180, 195, 1 },
    .{ 0x0183, 0x0185, -1, 2 },
    .{ 0x0188, 0x0188, -1, 1 },
    .{ 0x018c, 0x018c, -1, 1 },
    .{ 0x0192, 0x0192, -1, 1 },
    .{ 0x0195, 0x0195, 97, 1 },
    .{ 0x0199, 0x0199, -1, 1 },
    .{ 0x019a, 0x019a, 163, 1 },
    .{ 0x019e, 0x019e, 130, 1 },
    .{ 0x01a1, 0x01a5, -1, 2 },
    .{ 0x01a8, 0x01a8, -1, 1 },
    .{ 0x01ad, 0x01ad, -1, 1 },
    .{ 0x01b0, 0x01b0, -1, 1 },
    .{ 0x01b4, 0x01b6, -1, 2 },
    .{ 0x01b9, 0x01b9, -1, 1 },
    .{ 0x01bd, 0x01bd, -1, 1 },
    .{ 0x01bf, 0x01bf, 56, 1 },
    .{ 0x01c5, 0x01c5, -1, 1 },
    .{ 0x01c6, 0x01c6, -2, 1 },
    .{ 0x01c8, 0x01c8, -1, 1 },
    .{ 0x01c9, 0x01c9, -2, 1 },
    .{ 0x01cb, 0x01cb, -1, 1 },
    .{ 0x01cc, 0x01cc, -2, 1 },
    .{ 0x01ce, 0x01dc, -1, 2 },
    .{ 0x01dd, 0x01dd, -79, 1 },
    .{ 0x01df, 0x01ef, -1, 2 },
    .{ 0x01f2, 0x01f2, -1, 1 },
    .{ 0x01f3, 0x01f3, -2, 1 },
    .{ 0x01f5, 0x01f5, -1, 1 },
    .{ 0x01f9, 0x021f, -1, 2 },
    .{ 0x0223, 0x0233, -1, 2 },
    .{ 0x023c, 0x023c, -1, 1 },
    .{ 0x023f, 0x0240, 10815, 1 },
    .{ 0x0242, 0x0242, -1, 1 },
    .{ 0x0247, 0x024f, -1, 2 },
    .{ 0x0250, 0x0250, 10783, 1 },
    .{ 0x0251, 0x0251, 10780, 1 },
    .{ 0x0252, 0x0252, 10782, 1 },
    .{ 0x0253, 0x0253, -210, 1 },
    .{ 0x0254, 0x0254, -206, 1 },
    .{ 0x0256, 0x0257, -205, 1 },
    .{ 0x0259, 0x0259, -202, 1 },
    .{ 0x025b, 0x025b, -203, 1 },
    .{ 0x0260, 0x0260, -205, 1 },
    .{ 0x0263, 0x0263, -207, 1 },
    .{ 0x0265, 0x0265, 42280, 1 },
    .{ 0x0266, 0x0266, 42308, 1 },
    .{ 0x0268, 0x0268, -209, 1 },
    .{ 0x0269, 0x0269, -211, 1 },
    .{ 0x026b, 0x026b, 10743, 1 },
    .{ 0x026f, 0x026f, -211, 1 },
    .{ 0x0271, 0x0271, 10749, 1 },
    .{ 0x0272, 0x0272, -213, 1 },
    .{ 0x0275, 0x0275, -214, 1 },
    .{ 0x027d, 0x027d, 10727, 1 },
    .{ 0x0280, 0x0280, -218, 1 },
    .{ 0x0283, 0x0283, -218, 1 },
    .{ 0x0288, 0x0288, -218, 1 },
    .{ 0x0289, 0x0289, -69, 1 },
    .{ 0x028a, 0x028b, -217, 1 },
    .{ 0x028c, 0x028c, -71, 1 },
    .{ 0x0292, 0x0292, -219, 1 },
    .{ 0x0345, 0x0345, 84, 1 },
    .{ 0x0371, 0x0373, -1, 2 },
    .{ 0x0377, 0x0377, -1, 1 },
    .{ 0x037b, 0x037d, 130, 1 },
    .{ 0x03ac, 0x03ac, -38, 1 },
    .{ 0x03ad, 0x03af, -37, 1 },
    .{ 0x03b1, 0x03c1, -32, 1 },
    .{ 0x03c2, 0x03c2, -31, 1 },
    .{ 0x03c3, 0x03cb, -32, 1 },
    .{ 0x03cc, 0x03cc, -64, 1 },
    .{ 0x03cd, 0x03ce, -63, 1 },
    .{ 0x03d0, 0x03d0, -62, 1 },
    .{ 0x03d1, 0x03d1, -57, 1 },
    .{ 0x03d5, 0x03d5, -47, 1 },
    .{ 0x03d6, 0x03d6, -54, 1 },
    .{ 0x03d7, 0x03d7, -8, 1 },
    .{ 0x03d9, 0x03ef, -1, 2 },
    .{ 0x03f0, 0x03f0, -86, 1 },
    .{ 0x03f1, 0x03f1, -80, 1 },
    .{ 0x03f2, 0x03f2, 7, 1 },
    .{ 0x03f5, 0x03f5, -96, 1 },
    .{ 0x03f8, 0x03f8, -1, 1 },
    .{ 0x03fb, 0x03fb, -1, 1 },
    .{ 0x0430, 0x044f, -32, 1 },
    .{ 0x0450, 0x045f, -80, 1 },
    .{ 0x0461, 0x0481, -1, 2 },
    .{ 0x048b, 0x04bf, -1, 2 },
    .{ 0x04c2, 0x04ce, -1, 2 },
    .{ 0x04cf, 0x04cf, -15, 1 },
    .{ 0x04d1, 0x0527, -1, 2 },
    .{ 0x0561, 0x0586, -48, 1 },
    .{ 0x1d79, 0x1d79, 35332, 1 },
    .{ 0x1d7d, 0x1d7d, 3814, 1 },
    .{ 0x1e01, 0x1e95, -1, 2 },
    .{ 0x1e9b, 0x1e9b, -59, 1 },
    .{ 0x1ea1, 0x1eff, -1, 2 },
    .{ 0x1f00, 0x1f07, 8, 1 },
    .{ 0x1f10, 0x1f15, 8, 1 },
    .{ 0x1f20, 0x1f27, 8, 1 },
    .{ 0x1f30, 0x1f37, 8, 1 },
    .{ 0x1f40, 0x1f45, 8, 1 },
    .{ 0x1f51, 0x1f57, 8, 2 },
    .{ 0x1f60, 0x1f67, 8, 1 },
    .{ 0x1f70, 0x1f71, 74, 1 },
    .{ 0x1f72, 0x1f75, 86, 1 },
    .{ 0x1f76, 0x1f77, 100, 1 },
    .{ 0x1f78, 0x1f79, 128, 1 },
    .{ 0x1f7a, 0x1f7b, 112, 1 },
    .{ 0x1f7c, 0x1f7d, 126, 1 },
    .{ 0x1f80, 0x1f87, 8, 1 },
    .{ 0x1f90, 0x1f97, 8, 1 },
    .{ 0x1fa0, 0x1fa7, 8, 1 },
    .{ 0x1fb0, 0x1fb1, 8, 1 },
    .{ 0x1fb3, 0x1fb3, 9, 1 },
    .{ 0x1fbe, 0x1fbe, -7205, 1 },
    .{ 0x1fc3, 0x1fc3, 9, 1 },
    .{ 0x1fd0, 0x1fd1, 8, 1 },
    .{ 0x1fe0, 0x1fe1, 8, 1 },
    .{ 0x1fe5, 0x1fe5, 7, 1 },
    .{ 0x1ff3, 0x1ff3, 9, 1 },
    .{ 0x214e, 0x214e, -28, 1 },
    .{ 0x2170, 0x217f, -16, 1 },
    .{ 0x2184, 0x2184, -1, 1 },
    .{ 0x24d0, 0x24e9, -26, 1 },
    .{ 0x2c30, 0x2c5e, -48, 1 },
    .{ 0x2c61, 0x2c61, -1, 1 },
    .{ 0x2c65, 0x2c65, -10795, 1 },
    .{ 0x2c66, 0x2c66, -10792, 1 },
    .{ 0x2c68, 0x2c6c, -1, 2 },
    .{ 0x2c73, 0x2c73, -1, 1 },
    .{ 0x2c76, 0x2c76, -1, 1 },
    .{ 0x2c81, 0x2ce3, -1, 2 },
    .{ 0x2cec, 0x2cee, -1, 2 },
    .{ 0x2cf3, 0x2cf3, -1, 1 },
    .{ 0x2d00, 0x2d25, -7264, 1 },
    .{ 0x2d27, 0x2d27, -7264, 1 },
    .{ 0x2d2d, 0x2d2d, -7264, 1 },
    .{ 0xa641, 0xa66d, -1, 2 },
    .{ 0xa681, 0xa697, -1, 2 },
    .{ 0xa723, 0xa72f, -1, 2 },
    .{ 0xa733, 0xa76f, -1, 2 },
    .{ 0xa77a, 0xa77c, -1, 2 },
    .{ 0xa77f, 0xa787, -1, 2 },
    .{ 0xa78c, 0xa78c, -1, 1 },
    .{ 0xa791, 0xa793, -1, 2 },
    .{ 0xa7a1, 0xa7a9, -1, 2 },
    .{ 0xff41, 0xff5a, -32, 1 },
};

pub fn upcase(cu: u16) u16 {
    var lo: usize = 0;
    var hi: usize = runs.len;
    while (lo < hi) { // last run with first <= cu
        const mid = (lo + hi) / 2;
        if (runs[mid][0] <= cu) lo = mid + 1 else hi = mid;
    }
    if (lo == 0) return cu;
    const first, const last, const delta, const stride = runs[lo - 1];
    if (cu > last or (cu - first) % @as(u16, stride) != 0) return cu;
    return @intCast(@as(i32, cu) + delta);
}

pub fn upcaseUtf16LeInto(dst: []u8, src: []const u8) void {
    std.debug.assert(dst.len == src.len);
    var i: usize = 0;
    while (i + 1 < src.len) : (i += 2) {
        std.mem.writeInt(u16, dst[i..][0..2], upcase(std.mem.readInt(u16, src[i..][0..2], .little)), .little);
    }
    if (src.len % 2 == 1) dst[src.len - 1] = src[src.len - 1];
}

test "upcase: ASCII, Latin-1, Latin Extended, Greek, Cyrillic" {
    const cases = [_][2]u16{
        .{ 'a', 'A' },       .{ 'z', 'Z' },       .{ 'A', 'A' },       .{ '0', '0' },
        .{ 0x00fc, 0x00dc }, .{ 0x00e9, 0x00c9 }, .{ 0x00ff, 0x0178 }, .{ 0x00f7, 0x00f7 },
        .{ 0x00df, 0x00df }, .{ 0x0101, 0x0100 }, .{ 0x0100, 0x0100 }, .{ 0x0131, 0x0049 },
        .{ 0x03b1, 0x0391 }, .{ 0x03c2, 0x03a3 }, .{ 0x0438, 0x0418 }, .{ 0x0451, 0x0401 },
        .{ 0xff41, 0xff21 }, .{ 0xd800, 0xd800 }, .{ 0xffff, 0xffff }, .{ 0x0000, 0x0000 },
    };
    for (cases) |c| try std.testing.expectEqual(c[1], upcase(c[0]));
}

test "upcase: runs are sorted, disjoint, and never map to the same code unit" {
    var count: usize = 0;
    for (runs, 0..) |r, i| {
        if (i > 0) try std.testing.expect(runs[i - 1][1] < r[0]);
        try std.testing.expect(r[2] != 0 and r[3] != 0);
        var cu: u32 = r[0];
        while (cu <= r[1]) : (cu += r[3]) count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1011), count);
}
