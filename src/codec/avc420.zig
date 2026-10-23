//! RFX_AVC420_BITMAP_STREAM (MS-RDPEGFX 2.2.4.4): a metablock of region rects and
//! quant/quality values, then one Annex-B H.264 frame. The client decodes every frame,
//! so every encoded frame must be sent to keep its references in sync.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const gfx = @import("../proto/gfx.zig");

pub const Rect16 = gfx.Rect16;
pub const codec_id = gfx.CodecId.avc420;

pub const Error = error{ EmptyRect, RectOutsideSurface, TooManyRects, BadQuantQuality, NotAnnexB, BadAvc420 };

pub const QuantQuality = struct {
    qp: u8,
    progressive: bool = false,
    /// 0..100, informational.
    quality: u8 = 100,

    pub fn fromQp(qp: u8) QuantQuality {
        const q = @min(qp, 51);
        return .{ .qp = q, .quality = @intCast(100 - (@as(u32, q) * 100 + 25) / 51) };
    }

    pub fn qpVal(q: QuantQuality) u8 {
        return (q.qp & 0x3f) | (if (q.progressive) @as(u8, 0x80) else 0);
    }
};

pub const metablock_header_len = 4;
pub const rect_len = 8;
pub const quant_quality_len = 2;

pub fn encodedLen(n_rects: usize, h264_len: usize) usize {
    return metablock_header_len + n_rects * (rect_len + quant_quality_len) + h264_len;
}

pub fn checkRect(r: Rect16, surface_width: ?u16, surface_height: ?u16) Error!void {
    if (r.left >= r.right or r.top >= r.bottom) return error.EmptyRect;
    if (surface_width) |w| if (r.right > w) return error.RectOutsideSurface;
    if (surface_height) |h| if (r.bottom > h) return error.RectOutsideSurface;
}

/// Tags every rect with `qp`, the frame's average QP.
pub fn writeAvc420(w: *bytes.Writer, rects: []const Rect16, qp: u8, h264: []const u8) !void {
    try writeAvc420Ex(w, rects, &.{QuantQuality.fromQp(qp)}, h264);
}

/// `qq` holds one value for all rects or one value per rect.
pub fn writeAvc420Ex(w: *bytes.Writer, rects: []const Rect16, qq: []const QuantQuality, h264: []const u8) !void {
    if (!isAnnexB(h264)) return error.NotAnnexB;
    if (qq.len != 1 and qq.len != rects.len) return error.BadQuantQuality;
    try w.u32le(@intCast(rects.len));
    for (rects) |r| {
        try checkRect(r, null, null);
        try w.u16le(r.left);
        try w.u16le(r.top);
        try w.u16le(r.right);
        try w.u16le(r.bottom);
    }
    for (0..rects.len) |i| {
        const q = if (qq.len == 1) qq[0] else qq[i];
        if (q.qp > 51 or q.quality > 100) return error.BadQuantQuality;
        try w.byte(q.qpVal());
        try w.byte(q.quality);
    }
    try w.bytes(h264);
}

fn isAnnexB(h: []const u8) bool {
    return (h.len >= 4 and h[0] == 0 and h[1] == 0 and h[2] == 0 and h[3] == 1) or
        (h.len >= 3 and h[0] == 0 and h[1] == 0 and h[2] == 1);
}

/// WIRE_TO_SURFACE_1 destRect for AVC codecs is a bounding rect (MS-RDPEGFX 2.2.2.1).
pub fn boundingRect(rects: []const Rect16) ?Rect16 {
    if (rects.len == 0) return null;
    var b = rects[0];
    for (rects[1..]) |r| {
        b.left = @min(b.left, r.left);
        b.top = @min(b.top, r.top);
        b.right = @max(b.right, r.right);
        b.bottom = @max(b.bottom, r.bottom);
    }
    return b;
}

pub fn surfaceRect(width: u16, height: u16) Rect16 {
    return .{ .left = 0, .top = 0, .right = width, .bottom = height };
}

pub const Parsed = struct {
    rects: []const u8, // raw RDPGFX_RECT16 array
    quant: []const u8, // raw quant/quality pairs
    h264: []const u8,

    pub fn count(p: Parsed) usize {
        return p.rects.len / rect_len;
    }

    pub fn rect(p: Parsed, i: usize) Rect16 {
        const b = p.rects[i * rect_len ..][0..rect_len];
        return .{
            .left = std.mem.readInt(u16, b[0..2], .little),
            .top = std.mem.readInt(u16, b[2..4], .little),
            .right = std.mem.readInt(u16, b[4..6], .little),
            .bottom = std.mem.readInt(u16, b[6..8], .little),
        };
    }

    pub fn quantQuality(p: Parsed, i: usize) QuantQuality {
        const v = p.quant[i * 2];
        return .{ .qp = v & 0x3f, .progressive = v & 0x80 != 0, .quality = p.quant[i * 2 + 1] };
    }
};

pub fn parse(data: []const u8) Error!Parsed {
    var r = bytes.Reader.init(data);
    const n = r.u32le() catch return error.BadAvc420;
    if (n > (data.len - 4) / (rect_len + quant_quality_len)) return error.BadAvc420;
    const rects = r.bytes(n * rect_len) catch return error.BadAvc420;
    const quant = r.bytes(n * quant_quality_len) catch return error.BadAvc420;
    const p = Parsed{ .rects = rects, .quant = quant, .h264 = r.rest() };
    for (0..n) |i| {
        checkRect(p.rect(i), null, null) catch return error.BadAvc420;
        const q = p.quant[i * 2];
        if (q & 0x3f > 51 or p.quant[i * 2 + 1] > 100) return error.BadAvc420;
    }
    return p;
}

const testing = std.testing;

test "AVC420 metablock wire layout" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var w = bytes.Writer.init(&list, gpa);
    const rects = [_]Rect16{
        .{ .left = 0, .top = 0, .right = 1920, .bottom = 1080 },
        .{ .left = 16, .top = 32, .right = 48, .bottom = 64 },
    };
    const h264 = [_]u8{ 0, 0, 0, 1, 0x65, 0xaa };
    try writeAvc420(&w, &rects, 22, &h264);
    const q = QuantQuality.fromQp(22);
    try testing.expectEqual(@as(u8, 57), q.quality);
    try testing.expectEqualSlices(u8, &(bytes.hex(
        \\ 02 00 00 00
        \\ 00 00 00 00 80 07 38 04
        \\ 10 00 20 00 30 00 40 00
        \\ 16 39 16 39
        \\ 00 00 00 01 65 aa
    )), list.items);
    try testing.expectEqual(encodedLen(2, h264.len), list.items.len);

    const p = try parse(list.items);
    try testing.expectEqual(@as(usize, 2), p.count());
    try testing.expectEqual(rects[1], p.rect(1));
    try testing.expectEqual(@as(u8, 22), p.quantQuality(0).qp);
    try testing.expectEqualSlices(u8, &h264, p.h264);
}

test "AVC420 qpVal bit layout and per-rect values" {
    const gpa = testing.allocator;
    try testing.expectEqual(@as(u8, 0x80 | 51), (QuantQuality{ .qp = 51, .progressive = true }).qpVal());
    try testing.expectEqual(@as(u8, 100), QuantQuality.fromQp(0).quality);
    try testing.expectEqual(@as(u8, 0), QuantQuality.fromQp(51).quality);
    try testing.expectEqual(@as(u8, 51), QuantQuality.fromQp(70).qp);

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var w = bytes.Writer.init(&list, gpa);
    const rects = [_]Rect16{ surfaceRect(64, 64), .{ .left = 1, .top = 2, .right = 3, .bottom = 4 } };
    const qq = [_]QuantQuality{ .{ .qp = 10, .quality = 90 }, .{ .qp = 30, .progressive = true, .quality = 40 } };
    try writeAvc420Ex(&w, &rects, &qq, &.{ 0, 0, 1, 0x41 });
    try testing.expectEqualSlices(u8, &.{ 10, 90, 0x80 | 30, 40 }, list.items[4 + 16 ..][0..4]);
}

test "AVC420 validation" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var w = bytes.Writer.init(&list, gpa);
    const h264 = [_]u8{ 0, 0, 0, 1, 0x41 };
    try testing.expectError(error.EmptyRect, writeAvc420(&w, &.{.{ .left = 5, .top = 0, .right = 5, .bottom = 9 }}, 20, &h264));
    try testing.expectError(error.NotAnnexB, writeAvc420(&w, &.{surfaceRect(8, 8)}, 20, &.{ 1, 2, 3 }));
    try testing.expectError(error.BadQuantQuality, writeAvc420Ex(&w, &.{ surfaceRect(8, 8), surfaceRect(4, 4) }, &.{ .{ .qp = 1 }, .{ .qp = 2 }, .{ .qp = 3 } }, &h264));
    try testing.expectError(error.RectOutsideSurface, checkRect(surfaceRect(1922, 1080), 1920, 1080));
    try testing.expectError(error.BadAvc420, parse(&.{ 9, 0, 0, 0, 1, 2 }));
    try testing.expectEqual(Rect16{ .left = 1, .top = 2, .right = 30, .bottom = 40 }, boundingRect(&.{
        .{ .left = 1, .top = 20, .right = 30, .bottom = 21 },
        .{ .left = 10, .top = 2, .right = 11, .bottom = 40 },
    }).?);
    try testing.expectEqual(@as(?Rect16, null), boundingRect(&.{}));
}
