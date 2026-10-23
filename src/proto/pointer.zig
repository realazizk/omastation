//! Pointer shapes and updates (MS-RDPBCGR 2.2.9.1.1.4, 2.2.9.1.2.1.4 - 2.2.9.1.2.1.11). Masks are
//! bottom-up: a straight-alpha XOR mask and a 1 bpp AND mask, as Windows servers send them.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const fastpath = @import("fastpath.zig");

/// Largest pointer size (LARGE_POINTER_FLAG_384x384).
pub const max_large: u16 = 384;
/// Largest pointer for clients without large pointer support.
pub const max_legacy: u16 = 32;
/// Largest TS_POINTERATTRIBUTE / TS_COLORPOINTERATTRIBUTE (2.2.9.1.1.4.4).
pub const max_small: u16 = 96;

/// TS_LARGE_POINTER_CAPABILITYSET largePointerSupportFlags (2.2.7.2.7).
pub const large_pointer_96: u16 = 0x0001;
pub const large_pointer_384: u16 = 0x0002;

/// MultifragmentUpdate MaxRequestSize needed for a 384x384 32 bpp pointer.
pub const large_384_request_size: u32 = 0x9482B;

/// TS_POINTER_PDU messageType (2.2.9.1.1.4).
pub const MessageType = enum(u16) {
    system = 0x0001,
    position = 0x0003,
    color = 0x0006,
    cached = 0x0007,
    pointer = 0x0008,
    large = 0x0009,
};

/// TS_SYSTEMPOINTERATTRIBUTE systemPointerType (2.2.9.1.1.4.3).
pub const sysptr_null: u32 = 0x00000000;
pub const sysptr_default: u32 = 0x00007F00;

/// Bytes per XOR scan line: padded to 2 bytes (2.2.9.1.1.4.4).
pub fn xorStride(width: usize, bpp: usize) usize {
    return ((width * bpp + 15) >> 3) & ~@as(usize, 1);
}

/// 1 bpp, padded to 2 bytes (2.2.9.1.1.4.4).
pub fn andStride(width: usize) usize {
    return ((width + 15) >> 3) & ~@as(usize, 1);
}

/// Largest pointer a client takes, decided as a Windows server does.
pub fn maxSize(large_flags: u16, max_request_size: u32) u16 {
    if (large_flags & large_pointer_384 != 0 and max_request_size >= large_384_request_size) return max_large;
    if (large_flags & large_pointer_96 != 0 and max_request_size >= pduSize(max_small, max_small)) return max_small;
    return max_legacy;
}

/// Bytes a 32 bpp w x h pointer update takes, headers included.
pub fn pduSize(w: u32, h: u32) u32 {
    const and_row = ((w + 0x1f) >> 3) & ~@as(u32, 3);
    const body = (and_row + w * 4) * h;
    return if (w <= max_small and h <= max_small) body + 0x27 else body + 0x2b;
}

pub const Shape = struct {
    width: u16,
    height: u16,
    hot_x: u16,
    hot_y: u16,
    xor_bpp: u16,
    xor_mask: []u8,
    and_mask: []u8,

    pub fn deinit(s: *Shape, gpa: std.mem.Allocator) void {
        gpa.free(s.xor_mask);
        gpa.free(s.and_mask);
        s.* = undefined;
    }
};

pub const Look = enum {
    normal,
    /// Hyprland's cursor:invert: a black outline with the screen inverted inside.
    inverted,
};

pub const Source = struct {
    width: u16,
    height: u16,
    stride: usize,
    /// width x height premultiplied ARGB8888 (bytes B, G, R, A), top-down.
    pixels: []const u8,
    hot_x: u16,
    hot_y: u16,
    look: Look = .normal,
};

pub const Error = error{ InvalidSize, OutOfMemory };

/// XOR at `xor_bpp` (32, or 24 for TS_COLORPOINTERATTRIBUTE-only clients) plus the AND mask;
/// caller frees with `Shape.deinit`. The hotspot is clamped into the image (2.2.9.1.1.4.4).
pub fn encode(gpa: std.mem.Allocator, src: Source, xor_bpp: u16) Error!Shape {
    if (src.width == 0 or src.height == 0 or src.width > max_large or src.height > max_large) return error.InvalidSize;
    if (xor_bpp != 24 and xor_bpp != 32) return error.InvalidSize;
    if (src.stride < @as(usize, src.width) * 4 or src.pixels.len < src.stride * (src.height - 1) + @as(usize, src.width) * 4) return error.InvalidSize;
    const w: usize = src.width;
    const h: usize = src.height;
    const xs = xorStride(w, xor_bpp);
    const as = andStride(w);
    const xor_mask = try gpa.alloc(u8, xs * h);
    errdefer gpa.free(xor_mask);
    const and_mask = try gpa.alloc(u8, as * h);
    errdefer gpa.free(and_mask);
    @memset(xor_mask, 0);
    @memset(and_mask, 0);
    const px = @as(usize, xor_bpp) / 8;
    switch (src.look) {
        .normal => for (0..h) |y| {
            const row = src.pixels[y * src.stride ..];
            const xrow = xor_mask[(h - 1 - y) * xs ..];
            const arow = and_mask[(h - 1 - y) * as ..];
            for (0..w) |x| {
                const p = row[x * 4 ..][0..4];
                const a = p[3];
                // AND 1 where alpha < 0x80, as Windows servers do.
                if (a < 0x80) arow[x / 8] |= @as(u8, 0x80) >> @intCast(x % 8);
                if (a == 0) continue;
                const o = xrow[x * px ..];
                o[0] = unpremultiply(p[0], a);
                o[1] = unpremultiply(p[1], a);
                o[2] = unpremultiply(p[2], a);
                if (px == 4) {
                    o[3] = a;
                } else if (a < 0x80) {
                    // No alpha at 24 bpp: pixels the AND mask hides are black.
                    o[0] = 0;
                    o[1] = 0;
                    o[2] = 0;
                }
            }
        },
        .inverted => try encodeInverted(gpa, src, xor_mask, xs, px, and_mask, as),
    }
    return .{
        .width = src.width,
        .height = src.height,
        .hot_x = @min(src.hot_x, src.width - 1),
        .hot_y = @min(src.hot_y, src.height - 1),
        .xor_bpp = xor_bpp,
        .xor_mask = xor_mask,
        .and_mask = and_mask,
    };
}

fn unpremultiply(c: u8, a: u8) u8 {
    if (a == 255) return c;
    const v = (@as(u32, c) * 255 + a / 2) / a;
    return @intCast(@min(v, 255));
}

/// Matches Hyprland's cursor:invert: the edge and a light cursor's dark details are black, the rest
/// inverts. AND 1 + XOR white inverts, AND 1 + XOR black is transparent, AND 0 + XOR black is black.
fn encodeInverted(gpa: std.mem.Allocator, src: Source, xor_mask: []u8, xs: usize, px: usize, and_mask: []u8, as: usize) Error!void {
    const w: usize = src.width;
    const h: usize = src.height;
    const inside = try gpa.alloc(bool, w * h);
    defer gpa.free(inside);
    const light = try gpa.alloc(bool, w * h);
    defer gpa.free(light);
    var n_light: usize = 0;
    var n_dark: usize = 0;
    for (0..h) |y| for (0..w) |x| {
        const p = src.pixels[y * src.stride + x * 4 ..][0..4];
        const a: u32 = p[3];
        const rgb: u32 = @as(u32, p[0]) + p[1] + p[2];
        const i = y * w + x;
        inside[i] = a >= 128;
        light[i] = rgb * 255 >= 384 * a;
        if (inside[i]) {
            if (light[i]) n_light += 1 else n_dark += 1;
        }
    };
    const light_bodied = n_light > n_dark;
    for (0..h) |y| {
        const xrow = xor_mask[(h - 1 - y) * xs ..];
        const arow = and_mask[(h - 1 - y) * as ..];
        for (0..w) |x| {
            const i = y * w + x;
            const bit = @as(u8, 0x80) >> @intCast(x % 8);
            if (!inside[i]) {
                arow[x / 8] |= bit; // transparent: AND 1, XOR black
                continue;
            }
            const edge = x == 0 or !inside[i - 1] or x + 1 == w or !inside[i + 1] or
                y == 0 or !inside[i - w] or y + 1 == h or !inside[i + w];
            if (edge or (light_bodied and !light[i])) continue; // black: AND 0, XOR black
            arow[x / 8] |= bit; // inverts: AND 1, XOR white (alpha 0)
            @memset(xrow[x * px ..][0..3], 0xFF);
        }
    }
}

pub const Kind = enum {
    /// TS_COLORPOINTERATTRIBUTE, 24 bpp: for clients without pointerCacheSize.
    color,
    /// TS_POINTERATTRIBUTE.
    new,
    /// TS_FP_LARGEPOINTERATTRIBUTE / TS_LARGEPOINTERATTRIBUTE.
    large,

    pub fn updateCode(k: Kind) fastpath.UpdateCode {
        return switch (k) {
            .color => .color,
            .new => .pointer,
            .large => .large_pointer,
        };
    }

    pub fn messageType(k: Kind) MessageType {
        return switch (k) {
            .color => .color,
            .new => .pointer,
            .large => .large,
        };
    }
};

/// Pointer attribute body for `kind` (MS-RDPBCGR 2.2.9.1.1.4.4 - 2.2.9.1.1.4.5).
pub fn writeShape(w: *bytes.Writer, kind: Kind, cache_index: u16, s: *const Shape) !void {
    switch (kind) {
        .color => std.debug.assert(s.xor_bpp == 24),
        .new, .large => try w.u16le(s.xor_bpp),
    }
    try w.u16le(cache_index);
    try w.u16le(s.hot_x);
    try w.u16le(s.hot_y);
    try w.u16le(s.width);
    try w.u16le(s.height);
    if (kind == .large) {
        try w.u32le(@intCast(s.and_mask.len));
        try w.u32le(@intCast(s.xor_mask.len));
    } else {
        try w.u16le(@intCast(s.and_mask.len));
        try w.u16le(@intCast(s.xor_mask.len));
    }
    try w.bytes(s.xor_mask);
    try w.bytes(s.and_mask);
}

pub fn shapeSize(kind: Kind, s: *const Shape) usize {
    const head: usize = switch (kind) {
        .color => 14,
        .new => 16,
        .large => 20,
    };
    return head + s.xor_mask.len + s.and_mask.len;
}

pub fn writeCached(w: *bytes.Writer, cache_index: u16) !void {
    try w.u16le(cache_index);
}

pub fn writePosition(w: *bytes.Writer, x: u16, y: u16) !void {
    try w.u16le(x);
    try w.u16le(y);
}

const testing = std.testing;

fn testImage(comptime w: usize, comptime h: usize, px: [w * h][4]u8) [w * h * 4]u8 {
    var out: [w * h * 4]u8 = undefined;
    for (px, 0..) |p, i| out[i * 4 ..][0..4].* = p;
    return out;
}

test "scan lines are padded to 2 bytes (MS-RDPBCGR 2.2.9.1.1.4.4 examples)" {
    try testing.expectEqual(@as(usize, 10), xorStride(3, 24)); // "3x3 ... 10 bytes"
    try testing.expectEqual(@as(usize, 2), andStride(7)); // "7x7 ... 2 bytes"
    try testing.expectEqual(@as(usize, 4), andStride(17));
    try testing.expectEqual(@as(usize, 48 * 4), xorStride(48, 32));
}

test "maxSize from large pointer flags and request size" {
    try testing.expectEqual(@as(u16, 384), maxSize(0x3, 0x9482B));
    try testing.expectEqual(@as(u16, 96), maxSize(0x3, 0x9482A));
    try testing.expectEqual(@as(u16, 96), maxSize(0x1, 38055));
    try testing.expectEqual(@as(u16, 32), maxSize(0x1, 38054));
    try testing.expectEqual(@as(u16, 32), maxSize(0, 0xFFFFFFFF));
    try testing.expectEqual(@as(u32, 38055), pduSize(96, 96));
}

test "alpha cursor: straight XOR, AND where alpha < 0x80, rows bottom-up" {
    // Premultiplied: opaque red, half-transparent white, 25% blue, clear.
    const img = testImage(2, 2, .{
        .{ 0, 0, 255, 255 },   .{ 0x80, 0x80, 0x80, 0x80 },
        .{ 0x40, 0, 0, 0x40 }, .{ 0, 0, 0, 0 },
    });
    var s = try encode(testing.allocator, .{ .width = 2, .height = 2, .stride = 8, .pixels = &img, .hot_x = 1, .hot_y = 0 }, 32);
    defer s.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 16), s.xor_mask.len);
    try testing.expectEqualSlices(u8, &.{ 255, 0, 0, 0x40, 0, 0, 0, 0 }, s.xor_mask[0..8]);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 255, 255, 255, 255, 255, 0x80 }, s.xor_mask[8..16]);
    try testing.expectEqualSlices(u8, &.{ 0xC0, 0, 0x00, 0 }, s.and_mask);
    try testing.expectEqual(@as(u16, 1), s.hot_x);
}

test "24 bpp: what the AND mask hides is black, the rest straight colour" {
    const img = testImage(2, 1, .{ .{ 0x10, 0x20, 0x30, 0x40 }, .{ 0x11, 0x22, 0x33, 0xFF } });
    var s = try encode(testing.allocator, .{ .width = 2, .height = 1, .stride = 8, .pixels = &img, .hot_x = 0, .hot_y = 0 }, 24);
    defer s.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0x11, 0x22, 0x33 }, s.xor_mask);
    try testing.expectEqualSlices(u8, &.{ 0x80, 0 }, s.and_mask);
}

test "the hotspot is clamped into the image" {
    const img = testImage(1, 1, .{.{ 0, 0, 0, 255 }});
    var s = try encode(testing.allocator, .{ .width = 1, .height = 1, .stride = 4, .pixels = &img, .hot_x = 7, .hot_y = 9 }, 32);
    defer s.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 0), s.hot_x);
    try testing.expectEqual(@as(u16, 0), s.hot_y);
}

test "bad sizes are refused" {
    const img: [16]u8 = @splat(0);
    try testing.expectError(error.InvalidSize, encode(testing.allocator, .{ .width = 0, .height = 1, .stride = 4, .pixels = &img, .hot_x = 0, .hot_y = 0 }, 32));
    try testing.expectError(error.InvalidSize, encode(testing.allocator, .{ .width = 2, .height = 2, .stride = 4, .pixels = &img, .hot_x = 0, .hot_y = 0 }, 32));
    try testing.expectError(error.InvalidSize, encode(testing.allocator, .{ .width = 385, .height = 1, .stride = 385 * 4, .pixels = &img, .hot_x = 0, .hot_y = 0 }, 32));
    try testing.expectError(error.InvalidSize, encode(testing.allocator, .{ .width = 1, .height = 1, .stride = 4, .pixels = &img, .hot_x = 0, .hot_y = 0 }, 16));
}

test "inverted: outline black, light inside inverts, outside transparent, XOR alpha 0" {
    const W = [4]u8{ 255, 255, 255, 255 };
    const T = [4]u8{ 0, 0, 0, 0 };
    const img = testImage(5, 5, .{
        T, T, T, T, T,
        T, W, W, W, T,
        T, W, W, W, T,
        T, W, W, W, T,
        T, T, T, T, T,
    });
    var s = try encode(testing.allocator, .{ .width = 5, .height = 5, .stride = 20, .pixels = &img, .hot_x = 2, .hot_y = 2, .look = .inverted }, 32);
    defer s.deinit(testing.allocator);
    const as = andStride(5);
    for (0..5) |y| for (0..5) |x| {
        const wy = 4 - y; // bottom-up
        const and_bit = s.and_mask[wy * as + x / 8] & (@as(u8, 0x80) >> @intCast(x % 8)) != 0;
        const p = s.xor_mask[wy * 20 + x * 4 ..][0..4];
        try testing.expectEqual(@as(u8, 0), p[3]);
        const in = x >= 1 and x <= 3 and y >= 1 and y <= 3;
        if (!in) {
            try testing.expect(and_bit);
            try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, p[0..3]);
        } else if (x == 2 and y == 2) {
            try testing.expect(and_bit); // the only pixel off the edge
            try testing.expectEqualSlices(u8, &.{ 255, 255, 255 }, p[0..3]);
        } else {
            try testing.expect(!and_bit); // edge: black
            try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, p[0..3]);
        }
    };
}

test "inverted: a light-bodied cursor keeps its dark details black" {
    const W = [4]u8{ 255, 255, 255, 255 };
    const D = [4]u8{ 10, 10, 10, 255 };
    const img = testImage(5, 5, .{
        W, W, W, W, W,
        W, W, W, W, W,
        W, W, D, W, W,
        W, W, W, W, W,
        W, W, W, W, W,
    });
    var s = try encode(testing.allocator, .{ .width = 5, .height = 5, .stride = 20, .pixels = &img, .hot_x = 0, .hot_y = 0, .look = .inverted }, 32);
    defer s.deinit(testing.allocator);
    const as = andStride(5);
    const bit = struct {
        fn f(sh: *const Shape, a: usize, x: usize, y: usize) bool {
            return sh.and_mask[(4 - y) * a + x / 8] & (@as(u8, 0x80) >> @intCast(x % 8)) != 0;
        }
    }.f;
    try testing.expect(!bit(&s, as, 2, 2)); // dark detail: black
    try testing.expect(bit(&s, as, 1, 1)); // light inside: inverts
    try testing.expect(!bit(&s, as, 0, 0)); // edge of the image: black
}

test "body layouts: color, new and large" {
    const img = testImage(1, 1, .{.{ 1, 2, 3, 255 }});
    var s32 = try encode(testing.allocator, .{ .width = 1, .height = 1, .stride = 4, .pixels = &img, .hot_x = 0, .hot_y = 0 }, 32);
    defer s32.deinit(testing.allocator);
    var s24 = try encode(testing.allocator, .{ .width = 1, .height = 1, .stride = 4, .pixels = &img, .hot_x = 0, .hot_y = 0 }, 24);
    defer s24.deinit(testing.allocator);
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var w = bytes.Writer.init(&list, testing.allocator);
    try writeShape(&w, .new, 3, &s32);
    try testing.expectEqualSlices(u8, &(bytes.hex(
        \\20 00 03 00 00 00 00 00 01 00 01 00 02 00 04 00
        \\01 02 03 ff 00 00
    )), list.items);
    try testing.expectEqual(list.items.len, shapeSize(.new, &s32));
    list.clearRetainingCapacity();
    try writeShape(&w, .large, 3, &s32);
    try testing.expectEqualSlices(u8, &(bytes.hex(
        \\20 00 03 00 00 00 00 00 01 00 01 00 02 00 00 00 04 00 00 00
        \\01 02 03 ff 00 00
    )), list.items);
    try testing.expectEqual(list.items.len, shapeSize(.large, &s32));
    list.clearRetainingCapacity();
    try writeShape(&w, .color, 0, &s24);
    try testing.expectEqualSlices(u8, &(bytes.hex(
        \\00 00 00 00 00 00 01 00 01 00 02 00 04 00
        \\01 02 03 00 00 00
    )), list.items);
    try testing.expectEqual(list.items.len, shapeSize(.color, &s24));
}
