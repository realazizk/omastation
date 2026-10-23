//! MSB-first bit I/O for the RemoteFX entropy coders: RLGR (MS-RDPRFX 3.1.8.1.7.3) and the
//! Progressive SRL and raw bits (MS-RDPEGFX 3.1.8.1.5, 3.2.8.1.5.2.1).

const std = @import("std");

/// Bit writer into a fixed buffer; an overflow is reported by `finish`.
pub const Writer = struct {
    buf: []u8,
    /// Bytes completed so far (may exceed buf.len after an overflow).
    len: usize = 0,
    /// Pending bits, right-aligned; fewer than 8 between calls.
    acc: u64 = 0,
    n: u6 = 0,
    overflow: bool = false,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    inline fn emit(w: *Writer, b: u8) void {
        if (w.len < w.buf.len) w.buf[w.len] = b else w.overflow = true;
        w.len += 1;
    }

    /// The low `count` bits of `value`, most significant first (count <= 32).
    pub inline fn bits(w: *Writer, count: u6, value: u32) void {
        if (count == 0) return;
        const m: u64 = (@as(u64, 1) << count) - 1;
        w.acc = (w.acc << count) | (value & m);
        w.n += count;
        while (w.n >= 8) {
            w.n -= 8;
            w.emit(@truncate(w.acc >> w.n));
        }
        w.acc &= (@as(u64, 1) << w.n) - 1;
    }

    pub inline fn bit(w: *Writer, b: u1) void {
        w.bits(1, b);
    }

    pub fn ones(w: *Writer, count: usize) void {
        var left = count;
        while (left >= 32) : (left -= 32) w.bits(32, 0xFFFF_FFFF);
        w.bits(@intCast(left), 0xFFFF_FFFF);
    }

    pub fn zeros(w: *Writer, count: usize) void {
        var left = count;
        while (left >= 32) : (left -= 32) w.bits(32, 0);
        w.bits(@intCast(left), 0);
    }

    pub fn bitCount(w: *const Writer) usize {
        return w.len * 8 + w.n;
    }

    /// Flush the zero-padded partial byte; the byte count.
    pub fn finish(w: *Writer) error{BufferTooSmall}!usize {
        if (w.n > 0) {
            const shift: u6 = 8 - w.n;
            w.emit(@truncate(w.acc << shift));
            w.n = 0;
            w.acc = 0;
        }
        if (w.overflow) return error.BufferTooSmall;
        return w.len;
    }
};

pub const Reader = struct {
    data: []const u8,
    /// Bit position.
    pos: usize = 0,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    pub fn remaining(r: *const Reader) usize {
        return r.data.len * 8 - r.pos;
    }

    pub inline fn bit(r: *Reader) error{EndOfData}!u1 {
        if (r.pos >= r.data.len * 8) return error.EndOfData;
        const b: u1 = @truncate(r.data[r.pos >> 3] >> @intCast(7 - (r.pos & 7)));
        r.pos += 1;
        return b;
    }

    /// `count` bits (<= 32) as an unsigned value, most significant first.
    pub fn bits(r: *Reader, count: u6) error{EndOfData}!u32 {
        if (count == 0) return 0;
        if (r.remaining() < count) return error.EndOfData;
        var v: u64 = 0;
        var left: usize = count;
        while (left > 0) {
            const in_byte: usize = 8 - (r.pos & 7);
            const take = @min(in_byte, left);
            const byte: u64 = r.data[r.pos >> 3];
            const chunk = (byte >> @intCast(in_byte - take)) & ((@as(u64, 1) << @intCast(take)) - 1);
            v = (v << @intCast(take)) | chunk;
            r.pos += take;
            left -= take;
        }
        return @intCast(v);
    }

    /// Length of a run of `b` bits; the bit ending the run is consumed too.
    pub fn run(r: *Reader, b: u1, max: usize) error{ EndOfData, TooLong }!usize {
        var count: usize = 0;
        while (true) {
            const x = try r.bit();
            if (x != b) return count;
            count += 1;
            if (count > max) return error.TooLong;
        }
    }
};

test "writer packs MSB first and pads the last byte" {
    var buf: [4]u8 = undefined;
    var w = Writer.init(&buf);
    w.bits(3, 0b101);
    w.bits(4, 0b1100);
    w.bits(5, 0b10101);
    try std.testing.expectEqual(@as(usize, 2), try w.finish());
    try std.testing.expectEqualSlices(u8, &.{ 0xB9, 0x50 }, buf[0..2]);
}

test "writer reports overflow, reader round trip" {
    var small: [1]u8 = undefined;
    var w = Writer.init(&small);
    w.ones(9);
    try std.testing.expectError(error.BufferTooSmall, w.finish());

    var buf: [8]u8 = undefined;
    var w2 = Writer.init(&buf);
    w2.ones(40);
    w2.bits(7, 0x2A);
    const n = try w2.finish();
    var r = Reader.init(buf[0..n]);
    try std.testing.expectEqual(@as(usize, 40), try r.run(1, 100));
    try std.testing.expectEqual(@as(u32, 0x2A), try r.bits(6));
    try std.testing.expectError(error.EndOfData, r.bits(8));
}
