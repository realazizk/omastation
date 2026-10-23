//! Bounds-checked PDU reader and growable writer with explicit little- and big-endian access.

const std = @import("std");

pub const Error = error{EndOfBuffer};

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    pub fn remaining(r: *const Reader) usize {
        return r.buf.len - r.pos;
    }

    pub fn rest(r: *const Reader) []const u8 {
        return r.buf[r.pos..];
    }

    pub fn need(r: *const Reader, n: usize) Error!void {
        if (r.remaining() < n) return error.EndOfBuffer;
    }

    pub fn bytes(r: *Reader, n: usize) Error![]const u8 {
        try r.need(n);
        const s = r.buf[r.pos .. r.pos + n];
        r.pos += n;
        return s;
    }

    pub fn skip(r: *Reader, n: usize) Error!void {
        _ = try r.bytes(n);
    }

    pub fn peek(r: *const Reader) Error!u8 {
        try r.need(1);
        return r.buf[r.pos];
    }

    pub fn byte(r: *Reader) Error!u8 {
        return (try r.bytes(1))[0];
    }

    pub fn u16le(r: *Reader) Error!u16 {
        const b = try r.bytes(2);
        return @as(u16, b[0]) | @as(u16, b[1]) << 8;
    }

    pub fn u16be(r: *Reader) Error!u16 {
        const b = try r.bytes(2);
        return @as(u16, b[0]) << 8 | @as(u16, b[1]);
    }

    pub fn u32le(r: *Reader) Error!u32 {
        const b = try r.bytes(4);
        return @as(u32, b[0]) | @as(u32, b[1]) << 8 | @as(u32, b[2]) << 16 | @as(u32, b[3]) << 24;
    }

    pub fn u32be(r: *Reader) Error!u32 {
        const b = try r.bytes(4);
        return @as(u32, b[0]) << 24 | @as(u32, b[1]) << 16 | @as(u32, b[2]) << 8 | @as(u32, b[3]);
    }

    pub fn u64le(r: *Reader) Error!u64 {
        const lo: u64 = try r.u32le();
        const hi: u64 = try r.u32le();
        return lo | hi << 32;
    }

    /// Sub-reader over the next `n` bytes; advances the parent past them.
    pub fn sub(r: *Reader, n: usize) Error!Reader {
        return Reader.init(try r.bytes(n));
    }
};

pub const Writer = struct {
    list: *std.ArrayList(u8),
    gpa: std.mem.Allocator,

    pub fn init(list: *std.ArrayList(u8), gpa: std.mem.Allocator) Writer {
        return .{ .list = list, .gpa = gpa };
    }

    pub fn len(w: *const Writer) usize {
        return w.list.items.len;
    }

    pub fn bytes(w: *Writer, b: []const u8) !void {
        try w.list.appendSlice(w.gpa, b);
    }

    pub fn zeros(w: *Writer, n: usize) !void {
        try w.list.appendNTimes(w.gpa, 0, n);
    }

    pub fn byte(w: *Writer, v: u8) !void {
        try w.list.append(w.gpa, v);
    }

    pub fn u16le(w: *Writer, v: u16) !void {
        try w.bytes(&.{ @truncate(v), @truncate(v >> 8) });
    }

    pub fn u16be(w: *Writer, v: u16) !void {
        try w.bytes(&.{ @truncate(v >> 8), @truncate(v) });
    }

    pub fn u32le(w: *Writer, v: u32) !void {
        try w.bytes(&.{ @truncate(v), @truncate(v >> 8), @truncate(v >> 16), @truncate(v >> 24) });
    }

    pub fn u32be(w: *Writer, v: u32) !void {
        try w.bytes(&.{ @truncate(v >> 24), @truncate(v >> 16), @truncate(v >> 8), @truncate(v) });
    }

    pub fn u64le(w: *Writer, v: u64) !void {
        try w.u32le(@truncate(v));
        try w.u32le(@truncate(v >> 32));
    }

    pub fn patchU16le(w: *Writer, at: usize, v: u16) void {
        w.list.items[at] = @truncate(v);
        w.list.items[at + 1] = @truncate(v >> 8);
    }

    pub fn patchU16be(w: *Writer, at: usize, v: u16) void {
        w.list.items[at] = @truncate(v >> 8);
        w.list.items[at + 1] = @truncate(v);
    }

    pub fn patchU32le(w: *Writer, at: usize, v: u32) void {
        w.list.items[at] = @truncate(v);
        w.list.items[at + 1] = @truncate(v >> 8);
        w.list.items[at + 2] = @truncate(v >> 16);
        w.list.items[at + 3] = @truncate(v >> 24);
    }
};

/// Whitespace is ignored.
pub fn hex(comptime s: []const u8) [hexLen(s)]u8 {
    const out = comptime blk: {
        @setEvalBranchQuota(100_000);
        var o: [hexLen(s)]u8 = undefined;
        var i: usize = 0;
        var hi: ?u8 = null;
        for (s) |ch| {
            const v: u8 = switch (ch) {
                '0'...'9' => ch - '0',
                'a'...'f' => ch - 'a' + 10,
                'A'...'F' => ch - 'A' + 10,
                ' ', '\n', '\t', '\r' => continue,
                else => @compileError("bad hex char"),
            };
            if (hi) |h| {
                o[i] = h << 4 | v;
                i += 1;
                hi = null;
            } else hi = v;
        }
        break :blk o;
    };
    return out;
}

fn hexLen(comptime s: []const u8) usize {
    @setEvalBranchQuota(100_000);
    var n: usize = 0;
    for (s) |ch| switch (ch) {
        ' ', '\n', '\t', '\r' => {},
        else => n += 1,
    };
    return n / 2;
}

test "reader endianness and bounds" {
    const data = hex("01 02 03 04 05 06 07 08 09");
    var r = Reader.init(&data);
    try std.testing.expectEqual(@as(u8, 1), try r.byte());
    try std.testing.expectEqual(@as(u16, 0x0302), try r.u16le());
    try std.testing.expectEqual(@as(u16, 0x0405), try r.u16be());
    try std.testing.expectEqual(@as(u32, 0x09080706), try r.u32le());
    try std.testing.expectError(error.EndOfBuffer, r.byte());
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "writer round-trips" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = Writer.init(&list, std.testing.allocator);
    try w.byte(0xAA);
    try w.u16le(0x1234);
    try w.u16be(0x1234);
    try w.u32le(0xDEADBEEF);
    try w.u32be(0xDEADBEEF);
    try std.testing.expectEqualSlices(u8, &hex("AA 34 12 12 34 EF BE AD DE DE AD BE EF"), list.items);
    w.patchU16le(1, 0xFFFF);
    try std.testing.expectEqualSlices(u8, &hex("FF FF"), list.items[1..3]);
}
