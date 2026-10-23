//! RC4 (MS-NLMP 6), only because NTLM key exchange and session security mandate it.

const std = @import("std");

pub const Rc4 = struct {
    s: [256]u8,
    i: u8 = 0,
    j: u8 = 0,

    /// `key` must be 1..256 bytes.
    pub fn init(key: []const u8) Rc4 {
        std.debug.assert(key.len > 0 and key.len <= 256);
        var st: Rc4 = .{ .s = undefined };
        for (&st.s, 0..) |*v, idx| v.* = @intCast(idx);
        var j: u8 = 0;
        for (0..256) |idx| {
            j = j +% st.s[idx] +% key[idx % key.len];
            std.mem.swap(u8, &st.s[idx], &st.s[j]);
        }
        return st;
    }

    pub fn apply(st: *Rc4, buf: []u8) void {
        for (buf) |*b| {
            st.i +%= 1;
            st.j +%= st.s[st.i];
            std.mem.swap(u8, &st.s[st.i], &st.s[st.j]);
            b.* ^= st.s[st.s[st.i] +% st.s[st.j]];
        }
    }

    /// RC4K(key, data) (MS-NLMP 6) into `out`.
    pub fn oneShot(key: []const u8, data: []const u8, out: []u8) void {
        std.debug.assert(out.len == data.len);
        var st = Rc4.init(key);
        defer st.wipe();
        @memcpy(out, data);
        st.apply(out);
    }

    pub fn wipe(st: *Rc4) void {
        std.crypto.secureZero(u8, &st.s);
        st.i = 0;
        st.j = 0;
    }
};

const bytes = @import("../core/bytes.zig");

fn expectRc4(key: []const u8, plain: []const u8, expected: []const u8) !void {
    var out: [64]u8 = undefined;
    Rc4.oneShot(key, plain, out[0..plain.len]);
    try std.testing.expectEqualSlices(u8, expected, out[0..plain.len]);
}

test "rc4 classic vectors" {
    try expectRc4("Key", "Plaintext", &bytes.hex("BBF316E8D940AF0AD3"));
    try expectRc4("Wiki", "pedia", &bytes.hex("1021BF0420"));
    try expectRc4("Secret", "Attack at dawn", &bytes.hex("45A01F645FC35B383552544B9BF5"));
}

test "rc4 RFC 6229 40-bit key, offset 0 keystream" {
    const zeros: [16]u8 = @splat(0);
    try expectRc4(&bytes.hex("0102030405"), &zeros, &bytes.hex("b2 39 63 05 f0 3d c0 27 cc c3 52 4a 0a 11 18 a8"));
}

test "rc4 stream state carries across calls" {
    var a = Rc4.init("Key");
    var buf = "Plaintext".*;
    a.apply(buf[0..4]);
    a.apply(buf[4..]);
    try std.testing.expectEqualSlices(u8, &bytes.hex("BBF316E8D940AF0AD3"), &buf);
}

test "NTLMv2 EncryptedRandomSessionKey (MS-NLMP 4.2.4.2.3)" {
    const kxkey = bytes.hex("8d e4 0c ca db c1 4a 82 f1 5c b0 ad 0d e9 5c a3");
    const rsk: [16]u8 = @splat(0x55);
    try expectRc4(&kxkey, &rsk, &bytes.hex("c5 da d2 54 4f c9 79 90 94 ce 1c e9 0b c9 d0 3e"));
}
