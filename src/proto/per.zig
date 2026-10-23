//! Aligned PER (X.691) primitives for T.124 GCC and T.125 MCS domain PDUs
//! (MS-RDPBCGR 2.2.1.3 - 2.2.1.9); only the constrained forms RDP emits.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

pub const Error = error{ BadLength, BadValue, BadOid } || bytes.Error;

/// Length determinant: 1 byte (< 0x80) or 2 bytes up to 0x3FFF; RDP never fragments.
pub fn readLength(r: *bytes.Reader) Error!u16 {
    const first = try r.byte();
    if (first & 0x80 == 0) return first;
    if (first & 0x40 != 0) return error.BadLength; // fragmented form
    return @as(u16, first & 0x3F) << 8 | try r.byte();
}

pub fn writeLength(w: *bytes.Writer, len: usize) !void {
    std.debug.assert(len <= 0x3FFF);
    if (len < 0x80) {
        try w.byte(@intCast(len));
    } else {
        try w.u16be(@as(u16, @intCast(len)) | 0x8000);
    }
}

pub fn readChoice(r: *bytes.Reader) Error!u8 {
    return r.byte();
}

pub fn readSelection(r: *bytes.Reader) Error!u8 {
    return r.byte();
}

pub fn readNumberOfSets(r: *bytes.Reader) Error!u8 {
    return r.byte();
}

pub fn readEnumerated(r: *bytes.Reader, count: u8) Error!u8 {
    const v = try r.byte();
    if (v >= count) return error.BadValue;
    return v;
}

/// Constrained whole number with a lower bound, encoded in 2 bytes.
pub fn readInteger16(r: *bytes.Reader, min: u16) Error!u16 {
    const v = try r.u16be();
    return std.math.add(u16, v, min) catch error.BadValue;
}

pub fn writeInteger16(w: *bytes.Writer, v: u16, min: u16) !void {
    std.debug.assert(v >= min);
    try w.u16be(v - min);
}

/// Semi-constrained INTEGER: a length determinant, then 1 to 4 octets (X.691 10.7, 10.3.6).
pub fn readInteger(r: *bytes.Reader) Error!u32 {
    const len = try readLength(r);
    if (len == 0 or len > 4) return error.BadLength;
    var v: u32 = 0;
    for (0..len) |_| v = v << 8 | try r.byte();
    return v;
}

/// Minimum-octet form (X.691 10.3.6).
pub fn writeInteger(w: *bytes.Writer, v: u32) !void {
    const n: usize = if (v <= 0xFF) 1 else if (v <= 0xFFFF) 2 else if (v <= 0xFFFFFF) 3 else 4;
    try writeLength(w, n);
    var i = n;
    while (i > 0) {
        i -= 1;
        try w.byte(@truncate(v >> @intCast(8 * i)));
    }
}

pub fn readOctetString(r: *bytes.Reader, min: u16) Error![]const u8 {
    const len = std.math.add(u16, try readLength(r), min) catch return error.BadLength;
    return r.bytes(len);
}

pub fn writeOctetString(w: *bytes.Writer, s: []const u8, min: usize) !void {
    std.debug.assert(s.len >= min);
    try writeLength(w, s.len - min);
    try w.bytes(s);
}

pub fn readNumericString(r: *bytes.Reader, min: u16) Error!void {
    const len = std.math.add(u16, try readLength(r), min) catch return error.BadLength;
    try r.skip((@as(usize, len) + 1) / 2);
}

pub fn readPadding(r: *bytes.Reader, n: usize) Error!void {
    try r.skip(n);
}

/// OBJECT IDENTIFIER (X.691 24, X.690 8.19): RDP's T.124 OID {0 0 20 124 0 1} is
/// 05 00 14 7c 00 01.
pub fn readObjectIdentifier(r: *bytes.Reader, expected: [6]u8) Error!void {
    const len = try readLength(r);
    if (len != oidLen(expected)) return error.BadOid;
    var cr = bytes.Reader.init(try r.bytes(len));
    var i: usize = 0; // next expected arc
    while (cr.remaining() > 0) {
        const sub = try readSubIdentifier(&cr);
        if (i == 0) {
            // X.690 8.19.4: X is 0 or 1 below 80, otherwise 2 and Y = sub - 80.
            const x: u32 = if (sub < 80) sub / 40 else 2;
            if (x != expected[0] or sub - 40 * x != expected[1]) return error.BadOid;
            i = 2;
        } else {
            if (i >= expected.len or sub != expected[i]) return error.BadOid;
            i += 1;
        }
    }
    if (i != expected.len) return error.BadOid;
}

/// X.690 8.19.2: base 128, minimal (the first octet is not 0x80).
fn readSubIdentifier(r: *bytes.Reader) Error!u32 {
    var v: u32 = 0;
    var first = true;
    while (true) : (first = false) {
        const b = try r.byte();
        if (first and b == 0x80) return error.BadOid;
        if (v > std.math.maxInt(u32) >> 7) return error.BadOid;
        v = v << 7 | (b & 0x7F);
        if (b & 0x80 == 0) return v;
        if (r.remaining() == 0) return error.BadOid; // ends inside a sub-identifier
    }
}

fn subIdentifierLen(v: u32) usize {
    var n: usize = 1;
    var x = v >> 7;
    while (x != 0) : (x >>= 7) n += 1;
    return n;
}

fn writeSubIdentifier(w: *bytes.Writer, v: u32) !void {
    var i = subIdentifierLen(v);
    while (i > 0) {
        i -= 1;
        const b: u8 = @truncate((v >> @intCast(7 * i)) & 0x7F);
        try w.byte(if (i > 0) b | 0x80 else b);
    }
}

fn oidLen(oid: [6]u8) usize {
    var len = subIdentifierLen(@as(u32, oid[0]) * 40 + oid[1]);
    for (oid[2..]) |arc| len += subIdentifierLen(arc);
    return len;
}

pub fn writeObjectIdentifier(w: *bytes.Writer, oid: [6]u8) !void {
    try writeLength(w, oidLen(oid));
    try writeSubIdentifier(w, @as(u32, oid[0]) * 40 + oid[1]);
    for (oid[2..]) |arc| try writeSubIdentifier(w, arc);
}

test "per length forms" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeLength(&w, 0x2A);
    try writeLength(&w, 0x11C);
    try std.testing.expectEqualSlices(u8, &bytes.hex("2a 81 1c"), list.items);
    var r = bytes.Reader.init(list.items);
    try std.testing.expectEqual(@as(u16, 0x2A), try readLength(&r));
    try std.testing.expectEqual(@as(u16, 0x11C), try readLength(&r));
    const frag = bytes.hex("c0");
    var rf = bytes.Reader.init(&frag);
    try std.testing.expectError(error.BadLength, readLength(&rf));
}

test "per oid and integer16" {
    const t124 = [6]u8{ 0, 0, 20, 124, 0, 1 };
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeObjectIdentifier(&w, t124);
    try writeInteger16(&w, 0x79F3, 1001);
    try std.testing.expectEqualSlices(u8, &bytes.hex("05 00 14 7c 00 01 76 0a"), list.items);
    var r = bytes.Reader.init(list.items);
    try readObjectIdentifier(&r, t124);
    try std.testing.expectEqual(@as(u16, 0x79F3), try readInteger16(&r, 1001));
}
