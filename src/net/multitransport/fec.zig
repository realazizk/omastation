//! MS-RDPEUDP 3.1.1.6 forward error correction: GF(2^8) arithmetic, coefficients,
//! the fecIndex rule and recovery of one missing Source Packet.

const std = @import("std");
const mt = @import("../multitransport.zig");

const TransportError = mt.TransportError;

/// GF(2^8), reduction x^8 + x^4 + x^3 + x^2 + 1, generator 2 (3.1.1.6.1.3).
pub const field_size: u16 = 256;
pub const reduction: u8 = 0x1d;

/// Antilog table, doubled so that exp_table[log x + log y] needs no modulo.
const exp_table: [512]u8 = blk: {
    var e: [512]u8 = undefined;
    e[0] = 1;
    for (1..255) |i| {
        const t: u16 = @as(u16, e[i - 1]) << 1;
        e[i] = if (t & 0x100 != 0) @truncate(t ^ (0x100 | @as(u16, reduction))) else @truncate(t);
    }
    for (255..512) |i| e[i] = e[i - 255];
    break :blk e;
};

const log_table: [256]u8 = blk: {
    @setEvalBranchQuota(10_000);
    var l: [256]u8 = @splat(0);
    for (0..255) |i| l[exp_table[i]] = i;
    break :blk l;
};

pub fn exp(i: u8) TransportError!u8 {
    return exp_table[i];
}

/// Discrete log of x for x in 1..255; log(0) is error.InvalidField.
pub fn log(x: u8) TransportError!u8 {
    if (x == 0) return error.InvalidField;
    return log_table[x];
}

pub fn add(x: u8, y: u8) TransportError!u8 {
    return x ^ y;
}

fn mulRaw(x: u8, y: u8) u8 {
    if (x == 0 or y == 0) return 0;
    return exp_table[@as(usize, log_table[x]) + log_table[y]];
}

fn divRaw(x: u8, y: u8) u8 {
    if (x == 0 or y == 0) return 0;
    return exp_table[@as(usize, log_table[x]) + 255 - log_table[y]];
}

/// 3.1.1.6.1.2 Mul (0 when either is 0).
pub fn mul(x: u8, y: u8) TransportError!u8 {
    return mulRaw(x, y);
}

/// 3.1.1.6.1.2 Div: 0 when either is 0 (as the pseudo-code).
pub fn div(x: u8, y: u8) TransportError!u8 {
    return divRaw(x, y);
}

/// 3.1.1.6.4: `fec_index`, or (sn + 1) & 0xff when it falls in the circular
/// range [s1 & 0xff, sn & 0xff].
pub fn nextFecIndex(fec_index: u8, s1: u32, sn: u32) TransportError!u8 {
    const a: u8 = @truncate(s1);
    const b: u8 = @truncate(sn);
    const inside = if (b >= a) fec_index >= a and fec_index <= b else fec_index >= a or fec_index <= b;
    return if (inside) @truncate(sn +% 1) else fec_index;
}

fn coefficient(fec_index: u8, seq: u32) u8 {
    return divRaw(1, fec_index ^ @as(u8, @truncate(seq)));
}

/// 3.1.1.6.4: out[i] = Div(1, fec_index ^ ((s1 + i) & 0xff)).
pub fn coefficients(fec_index: u8, s1: u32, out: []u8) TransportError![]u8 {
    for (out, 0..) |*c, i| c.* = coefficient(fec_index, s1 +% @as(u32, @truncate(i)));
    return out;
}

/// Byte `i` of a payload behind its big-endian RDPUDP_PAYLOAD_PREFIX, zero-padded (3.1.1.6.5).
fn prefixed(src: []const u8, i: usize) u8 {
    return switch (i) {
        0 => @truncate(src.len >> 8),
        1 => @truncate(src.len),
        else => if (i - 2 < src.len) src[i - 2] else 0,
    };
}

/// 1.3.2.2: an FEC Packet covers 1 to 255 Source Packets.
pub const max_block: usize = 255;

/// 3.1.1.6.2 / 3.1.1.6.5: FEC payload of the Source payloads s1, s1+1, ...
/// `fec_index` is used as given (call nextFecIndex first).
pub fn encode(sources: []const []const u8, fec_index: u8, s1: u32, out: []u8) TransportError![]u8 {
    if (sources.len == 0 or sources.len > max_block) return error.InvalidField;
    var longest: usize = 0;
    for (sources) |s| {
        if (s.len > 0xffff) return error.InvalidField;
        longest = @max(longest, s.len);
    }
    const k = longest + 2;
    if (out.len < k) return error.EndOfBuffer;
    @memset(out[0..k], 0);
    for (sources, 0..) |s, j| {
        const c = coefficient(fec_index, s1 +% @as(u32, @intCast(j)));
        if (c == 0) continue;
        for (0..s.len + 2) |i| out[i] ^= mulRaw(c, prefixed(s, i));
    }
    return out[0..k];
}

/// 3.1.1.6.3: rebuilds the missing (null) source of s1 + i into `out`, prefix stripped.
/// None missing: error.InvalidField; two or more or an inconsistent block: error.Unrecoverable.
pub fn recover(fec_payload: []const u8, fec_index: u8, s1: u32, sources: []const ?[]const u8, out: []u8) TransportError![]u8 {
    if (sources.len == 0 or sources.len > max_block) return error.InvalidField;
    var missing: ?usize = null;
    for (sources, 0..) |s, j| {
        if (s) |p| {
            // A source longer than the FEC payload cannot belong to this block.
            if (p.len + 2 > fec_payload.len) return error.Unrecoverable;
        } else {
            if (missing != null) return error.Unrecoverable;
            missing = j;
        }
    }
    const m = missing orelse return error.InvalidField;
    if (fec_payload.len < 2) return error.Unrecoverable;
    const cm = coefficient(fec_index, s1 +% @as(u32, @intCast(m)));
    if (cm == 0) return error.Unrecoverable;
    const inv = divRaw(1, cm);
    // Row byte i of the missing source: Div(F[i] ^ sum of the others, c_m).
    const row = struct {
        fn at(f: []const u8, idx: u8, start: u32, srcs: []const ?[]const u8, inverse: u8, i: usize) u8 {
            var acc = f[i];
            for (srcs, 0..) |s, j| if (s) |p| {
                if (i >= p.len + 2) continue;
                acc ^= mulRaw(coefficient(idx, start +% @as(u32, @intCast(j))), prefixed(p, i));
            };
            return mulRaw(acc, inverse);
        }
    }.at;
    const len = @as(usize, row(fec_payload, fec_index, s1, sources, inv, 0)) << 8 | row(fec_payload, fec_index, s1, sources, inv, 1);
    if (len > fec_payload.len - 2) return error.Unrecoverable;
    if (out.len < len) return error.EndOfBuffer;
    for (0..len) |i| out[i] = row(fec_payload, fec_index, s1, sources, inv, i + 2);
    return out[0..len];
}

test "4.2.2.1 coefficients and the S3 example" {
    var c: [5]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{ 1, 142, 244, 71, 167 }, try coefficients(0, 1, &c));
}
