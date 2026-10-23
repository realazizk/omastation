//! Static virtual channel chunking (MS-RDPBCGR 2.2.6.1, 3.1.5.2): each MCS SendData carries a
//! CHANNEL_PDU_HEADER and one chunk; FIRST/LAST flags delimit a message.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const bulk = @import("../codec/bulk.zig");

pub const Error = error{ BadChannelPdu, MessageTooLarge } || bytes.Error || std.mem.Allocator.Error;

pub const flag_first: u32 = 0x00000001;
pub const flag_last: u32 = 0x00000002;
pub const flag_show_protocol: u32 = 0x00000010;
pub const flag_compressed: u32 = 0x00200000;

/// CHANNEL_OPTION_SHOW_PROTOCOL (MS-RDPBCGR 2.2.1.3.4.1).
pub const option_show_protocol: u32 = 0x00200000;

/// Default and minimum chunk size (CHANNEL_CHUNK_LENGTH).
pub const chunk_length: usize = 1600;
pub const header_len = 8;

/// Largest reassembled client message; only what arrives is buffered.
pub const max_message_len: usize = 256 * 1024 * 1024;

pub const Reassembler = struct {
    /// Capacity kept from one message to the next.
    pub const retain_max: usize = 1024 * 1024;

    buf: std.ArrayList(u8) = .empty,
    expected: usize = 0,
    in_progress: bool = false,

    pub fn deinit(r: *Reassembler, gpa: std.mem.Allocator) void {
        r.buf.deinit(gpa);
    }

    /// Returns the complete message on the LAST chunk (valid until the next call), else null.
    /// Compressed chunks are refused.
    pub fn feed(r: *Reassembler, gpa: std.mem.Allocator, data: []const u8) Error!?[]const u8 {
        return r.feedWith(gpa, data, null);
    }

    /// Decompresses client chunks with `dec` before reassembly (MS-RDPBCGR 3.1.5.2.2); the length
    /// field is the uncompressed total. PACKET_FLUSHED alone is accepted without `dec`.
    pub fn feedWith(r: *Reassembler, gpa: std.mem.Allocator, data: []const u8, dec: ?*bulk.Decompressor) Error!?[]const u8 {
        var rd = bytes.Reader.init(data);
        const total = try rd.u32le();
        const flags = try rd.u32le();
        if (total > max_message_len) return error.MessageTooLarge;
        const chunk = try plainChunk(flags, rd.rest(), dec);

        if (flags & flag_first != 0) {
            // A big message's buffer is freed after use; small ones keep capacity.
            if (r.buf.capacity > retain_max) r.buf.clearAndFree(gpa) else r.buf.clearRetainingCapacity();
            r.expected = total;
            r.in_progress = true;
        } else if (!r.in_progress or total != r.expected) {
            return error.BadChannelPdu;
        }
        if (r.buf.items.len + chunk.len > r.expected) return error.BadChannelPdu;
        try r.buf.appendSlice(gpa, chunk);

        if (flags & flag_last != 0) {
            r.in_progress = false;
            if (r.buf.items.len != r.expected) return error.BadChannelPdu;
            return r.buf.items;
        }
        return null;
    }
};

/// Chunk data, decompressed by `dec` when compressed; valid until `dec` is used again. All
/// compressed client chunks share one history, also on unserved channels (3.1.8).
pub fn plainChunk(flags: u32, chunk: []const u8, dec: ?*bulk.Decompressor) Error![]const u8 {
    const cflags: u8 = @truncate(flags >> 16);
    if (flags & flag_compressed != 0) {
        const d = dec orelse return error.BadChannelPdu; // no channel compression advertised
        if (cflags & bulk.compr_type_mask != @backingInt(bulk.Type.mppc_8k)) return error.BadChannelPdu;
        return d.decompress(chunk, cflags) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.BadChannelPdu,
        };
    }
    const d = dec orelse return chunk;
    if (cflags & (bulk.packet_flushed | bulk.packet_at_front) == 0) return chunk;
    // PACKET_FLUSHED / AT_FRONT on uncompressed data still restart the history (3.1.8.2.1).
    return d.decompress(chunk, cflags & ~bulk.compr_type_mask | @backingInt(bulk.Type.mppc_8k)) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.BadChannelPdu,
    };
}

/// Chunk payloads (header + data) of at most `chunk` data bytes, passed to `sink.chunk`.
pub fn writeChunks(msg: []const u8, chunk: usize, extra_flags: u32, sink: anytype) !void {
    var off: usize = 0;
    var hdr: [header_len]u8 = undefined;
    while (true) {
        const n = @min(chunk, msg.len - off);
        var flags = extra_flags;
        if (off == 0) flags |= flag_first;
        if (off + n == msg.len) flags |= flag_last;
        std.mem.writeInt(u32, hdr[0..4], @intCast(msg.len), .little);
        std.mem.writeInt(u32, hdr[4..8], flags, .little);
        try sink.chunk(&hdr, msg[off .. off + n]);
        off += n;
        if (off == msg.len) break;
    }
}

test "chunk and reassemble" {
    const gpa = std.testing.allocator;
    var msg: [4000]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i * 7);

    const Collect = struct {
        list: std.ArrayList([]u8) = .empty,
        gpa: std.mem.Allocator,
        fn chunk(self: *@This(), hdr: []const u8, data: []const u8) !void {
            const p = try self.gpa.alloc(u8, hdr.len + data.len);
            @memcpy(p[0..hdr.len], hdr);
            @memcpy(p[hdr.len..], data);
            try self.list.append(self.gpa, p);
        }
    };
    var col = Collect{ .gpa = gpa };
    defer {
        for (col.list.items) |p| gpa.free(p);
        col.list.deinit(gpa);
    }
    try writeChunks(&msg, chunk_length, 0, &col);
    try std.testing.expectEqual(@as(usize, 3), col.list.items.len);

    var r = Reassembler{};
    defer r.deinit(gpa);
    try std.testing.expect((try r.feed(gpa, col.list.items[0])) == null);
    try std.testing.expect((try r.feed(gpa, col.list.items[1])) == null);
    const out = (try r.feed(gpa, col.list.items[2])).?;
    try std.testing.expectEqualSlices(u8, &msg, out);

    var r2 = Reassembler{};
    defer r2.deinit(gpa);
    try std.testing.expectError(error.BadChannelPdu, r2.feed(gpa, col.list.items[1]));
    var lie = bytes.hex("02 00 00 00 03 00 00 00 aa bb cc");
    try std.testing.expectError(error.BadChannelPdu, r2.feed(gpa, &lie));
    var huge = bytes.hex("ff ff ff 7f 01 00 00 00 aa");
    try std.testing.expectError(error.MessageTooLarge, r2.feed(gpa, &huge));
}

test "compressed client chunks are decompressed before reassembly (VCCAPS_COMPR_CS_8K, MS-RDPBCGR 3.1.5.2.2)" {
    const gpa = std.testing.allocator;
    var cmp = try bulk.Compressor.init(gpa, .mppc_8k);
    defer cmp.deinit();
    var dec = try bulk.Decompressor.init(gpa, .mppc_8k);
    defer dec.deinit();
    const unit = "clipboard text, clipboard text, clipboard text, clipboard text!";
    var msg_buf: [unit.len * 40]u8 = undefined;
    for (0..40) |i| @memcpy(msg_buf[i * unit.len ..][0..unit.len], unit);
    const msg: []const u8 = &msg_buf;
    var r = Reassembler{};
    defer r.deinit(gpa);
    var out: ?[]const u8 = null;
    var off: usize = 0;
    var buf: [8 + chunk_length]u8 = undefined;
    while (off < msg.len) {
        const n = @min(chunk_length, msg.len - off);
        const c = try cmp.compress(msg[off..][0..n]);
        var flags: u32 = @as(u32, c.flags) << 16;
        if (off == 0) flags |= flag_first;
        if (off + n == msg.len) flags |= flag_last;
        std.mem.writeInt(u32, buf[0..4], @intCast(msg.len), .little);
        std.mem.writeInt(u32, buf[4..8], flags, .little);
        @memcpy(buf[8..][0..c.data.len], c.data);
        out = try r.feedWith(gpa, buf[0 .. 8 + c.data.len], &dec);
        off += n;
    }
    try std.testing.expectEqualSlices(u8, msg, out.?);
    // No decompressor: compressed is an error. Only RDP 4.0 is accepted; PACKET_FLUSHED alone is plain data.
    var r2 = Reassembler{};
    defer r2.deinit(gpa);
    var c1 = bytes.hex("04 00 00 00 03 00 20 00 aa bb cc dd");
    try std.testing.expectError(error.BadChannelPdu, r2.feed(gpa, &c1));
    var c2 = bytes.hex("04 00 00 00 03 00 21 00 aa bb cc dd");
    try std.testing.expectError(error.BadChannelPdu, r2.feedWith(gpa, &c2, &dec));
    var c3 = bytes.hex("04 00 00 00 03 00 81 00 aa bb cc dd");
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd }, (try r2.feedWith(gpa, &c3, &dec)).?);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd }, (try r2.feed(gpa, &c3)).?);
}
