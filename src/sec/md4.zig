//! MD4 (RFC 1320), only for the NT one-way function NTOWFv1 (MS-NLMP 3.3.1).
//! MD4 is broken; do not use it for anything else.

const std = @import("std");

pub const Md4 = struct {
    pub const digest_length = 16;
    pub const block_length = 64;

    s: [4]u32 = .{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 },
    buf: [64]u8 = undefined,
    buf_len: u8 = 0,
    total_len: u64 = 0,

    pub fn init() Md4 {
        return .{};
    }

    pub fn hash(data: []const u8, out: *[digest_length]u8) void {
        var h = Md4.init();
        h.update(data);
        h.final(out);
    }

    pub fn update(d: *Md4, data: []const u8) void {
        var b = data;
        d.total_len +%= b.len;
        if (d.buf_len != 0) {
            const take = @min(b.len, 64 - @as(usize, d.buf_len));
            @memcpy(d.buf[d.buf_len..][0..take], b[0..take]);
            d.buf_len += @intCast(take);
            b = b[take..];
            if (d.buf_len < 64) return;
            d.round(&d.buf);
            d.buf_len = 0;
        }
        while (b.len >= 64) : (b = b[64..]) d.round(b[0..64]);
        @memcpy(d.buf[0..b.len], b);
        d.buf_len = @intCast(b.len);
    }

    pub fn final(d: *Md4, out: *[digest_length]u8) void {
        const bit_len = d.total_len *% 8;
        var pad: [72]u8 = @splat(0);
        pad[0] = 0x80;
        const used: usize = d.buf_len;
        const pad_len = if (used < 56) 56 - used else 120 - used;
        std.mem.writeInt(u64, pad[pad_len..][0..8], bit_len, .little);
        d.update(pad[0 .. pad_len + 8]);
        std.debug.assert(d.buf_len == 0);
        for (d.s, 0..) |v, i| std.mem.writeInt(u32, out[i * 4 ..][0..4], v, .little);
        std.crypto.secureZero(u8, &d.buf);
        d.s = @splat(0);
    }

    fn round(d: *Md4, block: *const [64]u8) void {
        var x: [16]u32 = undefined;
        for (&x, 0..) |*w, i| w.* = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);
        var a = d.s[0];
        var b = d.s[1];
        var c = d.s[2];
        var e = d.s[3]; // "d" in RFC 1320

        const rotl = std.math.rotl;
        inline for (0..4) |i| {
            a = rotl(u32, a +% ((b & c) | (~b & e)) +% x[i * 4 + 0], 3);
            e = rotl(u32, e +% ((a & b) | (~a & c)) +% x[i * 4 + 1], 7);
            c = rotl(u32, c +% ((e & a) | (~e & b)) +% x[i * 4 + 2], 11);
            b = rotl(u32, b +% ((c & e) | (~c & a)) +% x[i * 4 + 3], 19);
        }
        const k2: u32 = 0x5A827999;
        inline for (0..4) |i| {
            a = rotl(u32, a +% ((b & c) | (b & e) | (c & e)) +% x[i + 0] +% k2, 3);
            e = rotl(u32, e +% ((a & b) | (a & c) | (b & c)) +% x[i + 4] +% k2, 5);
            c = rotl(u32, c +% ((e & a) | (e & b) | (a & b)) +% x[i + 8] +% k2, 9);
            b = rotl(u32, b +% ((c & e) | (c & a) | (e & a)) +% x[i + 12] +% k2, 13);
        }
        const k3: u32 = 0x6ED9EBA1;
        const order = [4]usize{ 0, 2, 1, 3 };
        inline for (order) |i| {
            a = rotl(u32, a +% (b ^ c ^ e) +% x[i + 0] +% k3, 3);
            e = rotl(u32, e +% (a ^ b ^ c) +% x[i + 8] +% k3, 9);
            c = rotl(u32, c +% (e ^ a ^ b) +% x[i + 4] +% k3, 11);
            b = rotl(u32, b +% (c ^ e ^ a) +% x[i + 12] +% k3, 15);
        }
        d.s[0] +%= a;
        d.s[1] +%= b;
        d.s[2] +%= c;
        d.s[3] +%= e;
        std.crypto.secureZero(u32, &x);
    }
};

/// NT hash (NTOWFv1, MS-NLMP 3.3.1): MD4 over the UTF-16LE password bytes.
pub fn ntHash(password_utf16le: []const u8) [16]u8 {
    var out: [16]u8 = undefined;
    Md4.hash(password_utf16le, &out);
    return out;
}

const bytes = @import("../core/bytes.zig");

fn expectMd4(comptime input: []const u8, comptime digest: []const u8) !void {
    var out: [16]u8 = undefined;
    Md4.hash(input, &out);
    try std.testing.expectEqualSlices(u8, &bytes.hex(digest), &out);
}

test "md4 RFC 1320 appendix A.5 test suite" {
    try expectMd4("", "31d6cfe0d16ae931b73c59d7e0c089c0");
    try expectMd4("a", "bde52cb31de33e46245e05fbdbd6fb24");
    try expectMd4("abc", "a448017aaf21d8525fc10ae87aa6729d");
    try expectMd4("message digest", "d9130a8164549fe818874806e1c7014b");
    try expectMd4("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9");
    try expectMd4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4");
    try expectMd4("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536");
}

test "md4 streaming matches one-shot across block boundaries" {
    var data: [300]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    var expect: [16]u8 = undefined;
    Md4.hash(&data, &expect);
    for ([_]usize{ 1, 3, 55, 56, 63, 64, 65, 127 }) |chunk| {
        var h = Md4.init();
        var rest: []const u8 = &data;
        while (rest.len > 0) {
            const n = @min(chunk, rest.len);
            h.update(rest[0..n]);
            rest = rest[n..];
        }
        var got: [16]u8 = undefined;
        h.final(&got);
        try std.testing.expectEqualSlices(u8, &expect, &got);
    }
}

test "NTOWFv1 of \"Password\" (MS-NLMP 4.2.2.1.2)" {
    const h = ntHash(&bytes.hex("50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00"));
    try std.testing.expectEqualSlices(u8, &bytes.hex("a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52"), &h);
}
