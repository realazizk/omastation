//! A 32bpp BGRX framebuffer (RDP's native little-endian pixel order) and a
//! test pattern that makes orientation and channel-order mistakes obvious.

const std = @import("std");

pub const Framebuffer = struct {
    width: u16,
    height: u16,
    stride: usize,
    pixels: []u8,

    pub fn init(gpa: std.mem.Allocator, width: u16, height: u16) !Framebuffer {
        const stride = @as(usize, width) * 4;
        const pixels = try gpa.alloc(u8, stride * height);
        @memset(pixels, 0);
        return .{ .width = width, .height = height, .stride = stride, .pixels = pixels };
    }

    pub fn deinit(fb: *Framebuffer, gpa: std.mem.Allocator) void {
        gpa.free(fb.pixels);
    }

    pub fn put(fb: *Framebuffer, x: usize, y: usize, r: u8, g: u8, b: u8) void {
        const p = fb.pixels[y * fb.stride + x * 4 ..][0..4];
        p.* = .{ b, g, r, 0xFF };
    }

    pub fn fillRect(fb: *Framebuffer, x0: usize, y0: usize, w: usize, h: usize, r: u8, g: u8, b: u8) void {
        const x1 = @min(x0 + w, fb.width);
        const y1 = @min(y0 + h, fb.height);
        for (y0..y1) |y| for (x0..x1) |x| fb.put(x, y, r, g, b);
    }
};

/// Gradient, red/green/blue/white corner squares (TL, TR, BL, BR), 1px white border.
pub fn drawTestPattern(fb: *Framebuffer) void {
    const w: usize = fb.width;
    const h: usize = fb.height;
    for (0..h) |y| for (0..w) |x| {
        fb.put(x, y, @intCast(x * 255 / @max(w - 1, 1)), @intCast(y * 255 / @max(h - 1, 1)), 0x40);
    };
    const s = @min(w, h) / 6;
    fb.fillRect(0, 0, s, s, 0xFF, 0, 0);
    fb.fillRect(w - s, 0, s, s, 0, 0xFF, 0);
    fb.fillRect(0, h - s, s, s, 0, 0, 0xFF);
    fb.fillRect(w - s, h - s, s, s, 0xFF, 0xFF, 0xFF);
    fb.fillRect(0, 0, w, 1, 0xFF, 0xFF, 0xFF);
    fb.fillRect(0, h - 1, w, 1, 0xFF, 0xFF, 0xFF);
    fb.fillRect(0, 0, 1, h, 0xFF, 0xFF, 0xFF);
    fb.fillRect(w - 1, 0, 1, h, 0xFF, 0xFF, 0xFF);
}

/// Frame `n` of a moving test picture that changes most of the screen every frame.
pub fn drawAnimatedPattern(fb: *Framebuffer, n: u32) void {
    const w: usize = fb.width;
    const h: usize = fb.height;
    const shift: usize = (@as(usize, n) * 6) % @max(w, 1);
    for (0..h) |y| {
        const g: u8 = @intCast(y * 255 / @max(h - 1, 1));
        const row = fb.pixels[y * fb.stride ..][0 .. w * 4];
        for (0..w) |x| {
            const r: u8 = @intCast(((x + shift) % w) * 255 / @max(w - 1, 1));
            row[x * 4 ..][0..4].* = .{ 0x40, g, r, 0xFF };
        }
    }
    const s = @min(w, h) / 6;
    const span = w -| s;
    const bx = if (span == 0) 0 else (@as(usize, n) * 8) % (2 * span);
    fb.fillRect(if (bx < span) bx else 2 * span - bx, (h -| s) / 2, s, s, 0xFF, 0xFF, 0xFF);
}

/// Frame `n` of a synthetic video in a centred `w` x `h` window; nothing outside it changes.
pub fn drawVideo(fb: *Framebuffer, w: usize, h: usize, n: u32) void {
    // usize throughout: @min narrows to u16 here, and u16 * 4 overflows at 4K.
    const vw: usize = @min(w, fb.width);
    const vh: usize = @min(h, fb.height);
    const x0: usize = (fb.width - vw) / 2;
    const y0: usize = (fb.height - vh) / 2;
    const t: usize = n;
    const cx = (t * 7) % @max(vw, 1);
    const cy = vh / 2 + (t * 3) % @max(vh / 2, 1) - vh / 4;
    const rad = @max(vh / 6, 1);
    for (0..vh) |y| {
        const row = fb.pixels[(y0 + y) * fb.stride + x0 * 4 ..][0 .. vw * 4];
        for (0..vw) |x| {
            const grain = noiseAt(@truncate(x + t * 13), @truncate(y + t * 7));
            const dx = @as(isize, @intCast(x)) - @as(isize, @intCast(cx));
            const dy = @as(isize, @intCast(y)) - @as(isize, @intCast(cy));
            const disc = dx * dx + dy * dy < @as(isize, @intCast(rad * rad));
            const b: u8 = @truncate((x * 255 / @max(vw, 1) + t * 3) + (grain & 7));
            const g: u8 = @truncate((y * 255 / @max(vh, 1) + t * 2) + (grain >> 3 & 7));
            const r: u8 = if (disc) @truncate(0xC0 + (grain >> 6 & 15)) else @truncate(((x + y) / 4 + t * 5) + (grain >> 6 & 7));
            row[x * 4 ..][0..4].* = .{ b, g, r, 0xFF };
        }
    }
}

/// Overwrites the low four bits of every channel with noise that compresses poorly.
pub fn drawDetail(fb: *Framebuffer, shift: usize) void {
    for (0..fb.height) |y| {
        const row = fb.pixels[y * fb.stride ..][0 .. @as(usize, fb.width) * 4];
        for (0..fb.width) |x| {
            const n = noiseAt(@truncate(x + shift), @truncate(y));
            const p = row[x * 4 ..][0..3];
            p[0] = (p[0] & 0xF0) | @as(u8, @truncate(n & 0xF));
            p[1] = (p[1] & 0xF0) | @as(u8, @truncate((n >> 4) & 0xF));
            p[2] = (p[2] & 0xF0) | @as(u8, @truncate((n >> 8) & 0xF));
        }
    }
}

fn noiseAt(x: u32, y: u32) u32 {
    var h = (x *% 0x9E3779B1) ^ (y *% 0x85EBCA77);
    h ^= h >> 15;
    h *%= 0x2C1B3C6D;
    h ^= h >> 12;
    return h;
}

test "detail: only the low bits change, the same way every time" {
    var fb = try Framebuffer.init(std.testing.allocator, 70, 40);
    defer fb.deinit(std.testing.allocator);
    drawTestPattern(&fb);
    const before = try std.testing.allocator.dupe(u8, fb.pixels);
    defer std.testing.allocator.free(before);
    drawDetail(&fb, 3);
    var changed: usize = 0;
    for (fb.pixels, before, 0..) |a, b, i| {
        if (i % 4 == 3) continue;
        try std.testing.expectEqual(a & 0xF0, b & 0xF0);
        changed += @intFromBool(a != b);
    }
    try std.testing.expect(changed > fb.pixels.len / 2);
    const once = try std.testing.allocator.dupe(u8, fb.pixels);
    defer std.testing.allocator.free(once);
    drawDetail(&fb, 3);
    try std.testing.expectEqualSlices(u8, once, fb.pixels);
}

test "test pattern corners" {
    var fb = try Framebuffer.init(std.testing.allocator, 120, 60);
    defer fb.deinit(std.testing.allocator);
    drawTestPattern(&fb);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0xFF, 0xFF }, fb.pixels[5 * fb.stride + 5 * 4 ..][0..4]);
    try std.testing.expectEqualSlices(u8, &.{ 0xFF, 0, 0, 0xFF }, fb.pixels[55 * fb.stride + 5 * 4 ..][0..4]);
}
