//! Application icons for RAIL window orders (MS-RDPERP 2.2.1.2.3 TS_ICON_INFO, 2.2.1.3.1.2.2):
//! 32 bpp bottom-up BGRA with straight alpha plus a 1 bpp AND mask (set bit = transparent),
//! scaled by area averaging with the aspect ratio kept and centered.

const std = @import("std");
const cliprdr = @import("../channel/cliprdr.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{ OutOfMemory, InvalidIcon };

/// Largest side: CbBitsColor is 16 bits and the Window Icon order must fit OrderSize.
pub const max_size: u16 = 96;

/// An icon in TS_ICON_INFO form (Bpp 32, no color table).
pub const Bits = struct {
    width: u16,
    height: u16,
    color: []u8,
    mask: []u8,

    pub fn deinit(b: Bits, gpa: Allocator) void {
        gpa.free(b.color);
        gpa.free(b.mask);
    }
};

/// Bytes per mask row: 1 bpp, padded to 4 bytes (DIB rows).
pub fn maskStride(width: u32) usize {
    return ((@as(usize, width) + 7) / 8 + 3) & ~@as(usize, 3);
}

/// Input is straight-alpha, top-down RGBA; alpha below 128 is transparent in the mask.
pub fn fromRgba(gpa: Allocator, rgba: []const u8, width: u32, height: u32, size: u16) Error!Bits {
    if (size == 0 or size > max_size or width == 0 or height == 0) return error.InvalidIcon;
    if (rgba.len != @as(u64, width) * height * 4) return error.InvalidIcon;
    const dw: u32 = if (width >= height) size else @max(1, @as(u32, @intCast((@as(u64, width) * size + height / 2) / height)));
    const dh: u32 = if (height >= width) size else @max(1, @as(u32, @intCast((@as(u64, height) * size + width / 2) / width)));
    const scaled = try scaleRgba(gpa, rgba, width, height, dw, dh);
    defer gpa.free(scaled);
    const ox = (size - dw) / 2;
    const oy = (size - dh) / 2;

    const n: usize = @as(usize, size) * size;
    const color = try gpa.alloc(u8, n * 4);
    errdefer gpa.free(color);
    const stride = maskStride(size);
    const mask = try gpa.alloc(u8, stride * size);
    @memset(color, 0);
    @memset(mask, 0);
    for (0..size) |y| for (0..size) |x| {
        const inside = x >= ox and x < ox + dw and y >= oy and y < oy + dh;
        var px: [4]u8 = .{ 0, 0, 0, 0 };
        if (inside) {
            const s = ((y - oy) * dw + (x - ox)) * 4;
            px = scaled[s..][0..4].*;
        }
        // Bottom-up rows.
        const row = size - 1 - y;
        const d = (row * size + x) * 4;
        color[d + 0] = px[2];
        color[d + 1] = px[1];
        color[d + 2] = px[0];
        color[d + 3] = px[3];
        if (px[3] < 128) mask[row * stride + x / 8] |= @as(u8, 0x80) >> @intCast(x % 8);
    };
    return .{ .width = size, .height = size, .color = color, .mask = mask };
}

/// Area-averaged resampling of straight-alpha RGBA, computed in premultiplied alpha.
pub fn scaleRgba(gpa: Allocator, src: []const u8, sw: u32, sh: u32, dw: u32, dh: u32) Error![]u8 {
    if (sw == 0 or sh == 0 or dw == 0 or dh == 0 or src.len != @as(u64, sw) * sh * 4) return error.InvalidIcon;
    const out = try gpa.alloc(u8, @as(usize, dw) * dh * 4);
    const fx = @as(f64, @floatFromInt(sw)) / @as(f64, @floatFromInt(dw));
    const fy = @as(f64, @floatFromInt(sh)) / @as(f64, @floatFromInt(dh));
    for (0..dh) |dy| {
        const y0 = @as(f64, @floatFromInt(dy)) * fy;
        const y1 = y0 + fy;
        for (0..dw) |dx| {
            const x0 = @as(f64, @floatFromInt(dx)) * fx;
            const x1 = x0 + fx;
            var acc: [4]f64 = .{ 0, 0, 0, 0 };
            var total: f64 = 0;
            var sy: usize = @intFromFloat(@floor(y0));
            while (sy < sh and @as(f64, @floatFromInt(sy)) < y1) : (sy += 1) {
                const cy = @min(y1, @as(f64, @floatFromInt(sy + 1))) - @max(y0, @as(f64, @floatFromInt(sy)));
                if (cy <= 0) continue;
                var sx: usize = @intFromFloat(@floor(x0));
                while (sx < sw and @as(f64, @floatFromInt(sx)) < x1) : (sx += 1) {
                    const cx = @min(x1, @as(f64, @floatFromInt(sx + 1))) - @max(x0, @as(f64, @floatFromInt(sx)));
                    if (cx <= 0) continue;
                    const wgt = cx * cy;
                    const p = src[(sy * sw + sx) * 4 ..][0..4];
                    const a = @as(f64, @floatFromInt(p[3])) / 255.0;
                    acc[0] += @as(f64, @floatFromInt(p[0])) * a * wgt;
                    acc[1] += @as(f64, @floatFromInt(p[1])) * a * wgt;
                    acc[2] += @as(f64, @floatFromInt(p[2])) * a * wgt;
                    acc[3] += a * wgt;
                    total += wgt;
                }
            }
            const o = out[(dy * dw + dx) * 4 ..][0..4];
            if (total == 0 or acc[3] == 0) {
                o.* = .{ 0, 0, 0, 0 };
                continue;
            }
            const alpha = acc[3] / total;
            for (0..3) |k| o[k] = to8(acc[k] / acc[3]);
            o[3] = to8(alpha * 255.0);
        }
    }
    return out;
}

fn to8(v: f64) u8 {
    return @intFromFloat(std.math.clamp(@round(v), 0, 255));
}

/// A PNG file's image as a size x size icon (error.InvalidIcon if it cannot be decoded).
pub fn fromPng(gpa: Allocator, png: []const u8, size: u16) Error!Bits {
    const img = cliprdr.decodePng(gpa, png) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.InvalidIcon;
    defer img.deinit(gpa);
    return fromRgba(gpa, img.rgba, img.width, img.height, size);
}

test "a 2x2 icon: bottom-up BGRA and an AND mask with 4-byte rows" {
    const gpa = std.testing.allocator;
    // Top row: opaque red, transparent; bottom row: opaque green, half blue.
    const rgba = [_]u8{ 255, 0, 0, 255, 0, 0, 0, 0, 0, 255, 0, 255, 0, 0, 255, 128 };
    const b = try fromRgba(gpa, &rgba, 2, 2, 2);
    defer b.deinit(gpa);
    try std.testing.expectEqualSlices(u8, &.{ 0, 255, 0, 255, 255, 0, 0, 128, 0, 0, 255, 255, 0, 0, 0, 0 }, b.color);
    // Row 0 (bottom) all opaque; row 1 (top): second pixel transparent.
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0x40, 0, 0, 0 }, b.mask);
    try std.testing.expectEqual(@as(usize, 4), maskStride(1));
    try std.testing.expectEqual(@as(usize, 8), maskStride(33));
}
