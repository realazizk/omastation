//! TPKT framing (RFC 1006, MS-RDPBCGR 2.2.9.1.1) of slow-path RDP PDUs.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

pub const header_len = 4;
/// T.123 section 8: smallest valid TPKT frame (header plus smallest TPDU).
pub const min_len: u16 = 7;
pub const version: u8 = 3;
pub const max_len: u16 = 0xFFFF;

pub const Error = error{ BadVersion, BadLength } || bytes.Error;

/// Total frame length, header included.
pub fn parseHeader(hdr: []const u8) Error!u16 {
    var r = bytes.Reader.init(hdr);
    if (try r.byte() != version) return error.BadVersion;
    _ = try r.byte(); // reserved
    const len = try r.u16be();
    if (len < min_len) return error.BadLength;
    return len;
}

pub fn isTpkt(first: u8) bool {
    return first == version;
}

pub fn writeHeader(w: *bytes.Writer, total_len: u16) !void {
    try w.byte(version);
    try w.byte(0);
    try w.u16be(total_len);
}

/// Reserves a header; `finish` patches in the length.
pub const Frame = struct {
    start: usize,

    pub fn begin(w: *bytes.Writer) !Frame {
        const start = w.len();
        try writeHeader(w, 0);
        return .{ .start = start };
    }

    pub fn finish(f: Frame, w: *bytes.Writer) void {
        const total = w.len() - f.start;
        std.debug.assert(total <= max_len);
        w.patchU16be(f.start + 2, @intCast(total));
    }
};

test "tpkt header parse/write" {
    const h = bytes.hex("03 00 00 2c");
    try std.testing.expectEqual(@as(u16, 44), try parseHeader(&h));
    try std.testing.expectError(error.BadVersion, parseHeader(&bytes.hex("02 00 00 2c")));
    try std.testing.expectError(error.BadLength, parseHeader(&bytes.hex("03 00 00 03")));
    try std.testing.expectError(error.EndOfBuffer, parseHeader(&bytes.hex("03 00 00")));

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    const f = try Frame.begin(&w);
    try w.bytes("hello");
    f.finish(&w);
    try std.testing.expectEqualSlices(u8, &bytes.hex("03 00 00 09 68 65 6c 6c 6f"), list.items);
}
