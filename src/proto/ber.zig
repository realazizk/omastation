//! Minimal BER (X.690) for T.125 MCS Connect-Initial and Connect-Response
//! (MS-RDPBCGR 2.2.1.3, 2.2.1.4). Definite lengths only.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

pub const Error = error{ BadTag, BadLength, BadValue } || bytes.Error;

pub const Class = enum(u2) { universal = 0, application = 1, context = 2, private = 3 };

pub const tag_boolean: u8 = 0x01;
pub const tag_integer: u8 = 0x02;
pub const tag_octet_string: u8 = 0x04;
pub const tag_enumerated: u8 = 0x0A;
pub const tag_sequence: u8 = 0x30; // constructed

pub fn readLength(r: *bytes.Reader) Error!usize {
    const first = try r.byte();
    if (first & 0x80 == 0) return first;
    const n = first & 0x7F;
    if (n == 0 or n > 4) return error.BadLength; // indefinite / absurd
    var len: usize = 0;
    for (0..n) |_| len = len << 8 | try r.byte();
    if (len > r.remaining()) return error.BadLength;
    return len;
}

pub fn writeLength(w: *bytes.Writer, len: usize) !void {
    if (len < 0x80) {
        try w.byte(@intCast(len));
    } else if (len <= 0xFF) {
        try w.byte(0x81);
        try w.byte(@intCast(len));
    } else {
        std.debug.assert(len <= 0xFFFF);
        try w.byte(0x82);
        try w.u16be(@intCast(len));
    }
}

/// Tags >= 31 use the high-tag-number form (X.690 8.1.2.4.2): [APPLICATION 101] = 7f 65.
pub fn readApplicationTag(r: *bytes.Reader, number: u8) Error!usize {
    if (number >= 31) {
        if (try r.byte() != 0x7F) return error.BadTag;
        if (number >= 0x80 and try r.byte() != (0x80 | number >> 7)) return error.BadTag;
        if (try r.byte() != number & 0x7F) return error.BadTag;
    } else {
        if (try r.byte() != (0x60 | number)) return error.BadTag;
    }
    return readLength(r);
}

pub fn writeApplicationTag(w: *bytes.Writer, number: u8, len: usize) !void {
    if (number >= 31) {
        try w.byte(0x7F);
        if (number >= 0x80) try w.byte(0x80 | number >> 7);
        try w.byte(number & 0x7F);
    } else {
        try w.byte(0x60 | number);
    }
    try writeLength(w, len);
}

pub fn readTag(r: *bytes.Reader, tag: u8) Error!usize {
    if (try r.byte() != tag) return error.BadTag;
    return readLength(r);
}

pub fn readInteger(r: *bytes.Reader) Error!u32 {
    const len = try readTag(r, tag_integer);
    if (len == 0 or len > 4) {
        // T.125 domain parameters may carry a leading zero byte (5 bytes for 0xFFFFFFFF).
        if (len == 5 and (try r.peek()) == 0) {
            try r.skip(1);
            return r.u32be();
        }
        return error.BadLength;
    }
    var v: u32 = 0;
    for (0..len) |_| v = v << 8 | try r.byte();
    return v;
}

pub fn writeInteger(w: *bytes.Writer, v: u32) !void {
    try w.byte(tag_integer);
    if (v < 0x80) {
        try w.byte(1);
        try w.byte(@intCast(v));
    } else if (v < 0x8000) {
        try w.byte(2);
        try w.u16be(@intCast(v));
    } else if (v < 0x800000) {
        try w.byte(3);
        try w.byte(@intCast(v >> 16));
        try w.u16be(@truncate(v));
    } else if (v < 0x80000000) {
        try w.byte(4);
        try w.u32be(v);
    } else {
        try w.byte(5);
        try w.byte(0);
        try w.u32be(v);
    }
}

pub fn readBoolean(r: *bytes.Reader) Error!bool {
    const len = try readTag(r, tag_boolean);
    if (len != 1) return error.BadLength;
    return try r.byte() != 0;
}

/// Minimal two's complement (X.690 8.4, 8.3.2); negative values are rejected.
pub fn readEnumerated(r: *bytes.Reader) Error!u8 {
    const len = try readTag(r, tag_enumerated);
    switch (len) {
        1 => {
            const v = try r.byte();
            if (v >= 0x80) return error.BadValue; // negative
            return v;
        },
        2 => {
            if (try r.byte() != 0) return error.BadValue; // negative or > 255
            const v = try r.byte();
            if (v < 0x80) return error.BadValue; // not minimal (8.3.2)
            return v;
        },
        else => return error.BadLength,
    }
}

pub fn writeEnumerated(w: *bytes.Writer, v: u8) !void {
    try w.byte(tag_enumerated);
    if (v >= 0x80) {
        try w.byte(2);
        try w.byte(0);
    } else try w.byte(1);
    try w.byte(v);
}

pub fn readOctetString(r: *bytes.Reader) Error![]const u8 {
    const len = try readTag(r, tag_octet_string);
    return r.bytes(len);
}

pub fn writeOctetString(w: *bytes.Writer, s: []const u8) !void {
    try w.byte(tag_octet_string);
    try writeLength(w, s.len);
    try w.bytes(s);
}

test "ber lengths" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeLength(&w, 0x7F);
    try writeLength(&w, 0x80);
    try writeLength(&w, 0x1234);
    try std.testing.expectEqualSlices(u8, &bytes.hex("7f 81 80 82 12 34"), list.items);

    const buf = bytes.hex("82 00 02 aa bb");
    var r = bytes.Reader.init(&buf);
    try std.testing.expectEqual(@as(usize, 2), try readLength(&r));
    const bad = bytes.hex("82 00 05 aa");
    var rb = bytes.Reader.init(&bad);
    try std.testing.expectError(error.BadLength, readLength(&rb));
    const indef = bytes.hex("80");
    var ri = bytes.Reader.init(&indef);
    try std.testing.expectError(error.BadLength, readLength(&ri));
}

test "ber integers round trip" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    const values = [_]u32{ 0, 1, 0x7F, 0x80, 0xFFF8, 0x10000, 0x7FFFFFFF, 0xFFFFFFFF };
    for (values) |v| try writeInteger(&w, v);
    var r = bytes.Reader.init(list.items);
    for (values) |v| try std.testing.expectEqual(v, try readInteger(&r));
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}
