//! MS-RDPECLIP clipboard images: CF_DIB / CF_DIBV5 (packed DIBs) <-> RGBA, and DIB <->
//! image/bmp (BITMAPFILEHEADER + DIB).

const std = @import("std");
const c = @import("../cliprdr.zig");
const png = @import("png.zig");

const Allocator = std.mem.Allocator;

fn rd16(b: []const u8, off: usize) u16 {
    return std.mem.readInt(u16, b[off..][0..2], .little);
}

fn rd32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], .little);
}

fn wr16(b: []u8, off: usize, v: u16) void {
    std.mem.writeInt(u16, b[off..][0..2], v, .little);
}

fn wr32(b: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, b[off..][0..4], v, .little);
}

/// BITMAPINFOHEADER (40), V2 (52), V3 (56), V4 (108), V5 (124).
fn validHeaderSize(n: u32) bool {
    return switch (n) {
        40, 52, 56, c.bitmap_v4_header_len, c.bitmap_v5_header_len => true,
        else => false,
    };
}

const Layout = struct {
    width: u32,
    /// |biHeight|; up to 2^31.
    height: u64,
    top_down: bool,
    bpp: u16,
    compression: u32,
    /// R, G, B, A (BI_BITFIELDS only; A 0 when there is none).
    masks: [4]u32,
    colors: u64,
    table_off: usize,
    pixels_off: u64,
    /// Bytes per row, padded to 4.
    stride: u64,
};

/// Validate the header and the color table (not the pixels).
fn parseHeader(dib: []const u8) c.Error!Layout {
    if (dib.len < 4) return error.InvalidDib;
    const hs = rd32(dib, 0);
    if (!validHeaderSize(hs) or dib.len < hs) return error.InvalidDib;
    const width: i32 = @bitCast(rd32(dib, 4));
    const height: i32 = @bitCast(rd32(dib, 8));
    const planes = rd16(dib, 12);
    const bpp = rd16(dib, 14);
    const compression = rd32(dib, 16);
    const clr_used = rd32(dib, 32);
    if (width <= 0 or height == 0 or planes != 1) return error.InvalidDib;
    switch (compression) {
        c.BI_RGB, c.BI_BITFIELDS => {},
        c.BI_RLE8, c.BI_RLE4, c.BI_JPEG, c.BI_PNG => return error.UnsupportedDib,
        else => return error.InvalidDib,
    }
    switch (bpp) {
        1, 4, 8, 16, 24, 32 => {},
        else => return error.InvalidDib,
    }
    var masks: [4]u32 = .{ 0, 0, 0, 0 };
    var table_off: usize = hs;
    if (compression == c.BI_BITFIELDS) {
        if (bpp != 16 and bpp != 32) return error.InvalidDib;
        if (hs == c.bitmap_info_header_len) {
            // The three masks follow a BITMAPINFOHEADER.
            if (dib.len < hs + 12) return error.InvalidDib;
            table_off = hs + 12;
        }
        masks[0] = rd32(dib, 40);
        masks[1] = rd32(dib, 44);
        masks[2] = rd32(dib, 48);
        if (hs >= 56) masks[3] = rd32(dib, 52);
        // Windows' synthesized CF_DIBV5 repeats the three masks after the BITMAPV5HEADER;
        // skip them when present and the pixels still fit.
        if (hs > c.bitmap_info_header_len and dib.len >= hs + 12 and
            rd32(dib, hs) == masks[0] and rd32(dib, hs + 4) == masks[1] and rd32(dib, hs + 8) == masks[2])
        {
            const w_px: u64 = @intCast(@max(width, 0));
            const rows: u64 = @abs(@as(i64, height));
            const stride = (w_px * bpp + 31) / 32 * 4;
            if ((@as(u64, hs) + 12) +| (stride *| rows) <= dib.len) table_off = hs + 12;
        }
    }
    var colors: u64 = clr_used;
    if (bpp <= 8) {
        const full = @as(u64, 1) << @intCast(bpp);
        if (colors == 0) colors = full;
        if (colors > full) return error.InvalidDib;
    }
    const pixels_off = @as(u64, table_off) + colors * 4;
    if (pixels_off > dib.len) return error.InvalidDib;
    const w: u32 = @intCast(width);
    const h: u64 = @abs(@as(i64, height));
    return .{
        .width = w,
        .height = h,
        .top_down = height < 0,
        .bpp = bpp,
        .compression = compression,
        .masks = masks,
        .colors = colors,
        .table_off = table_off,
        .pixels_off = pixels_off,
        .stride = (@as(u64, w) * bpp + 31) / 32 * 4,
    };
}

/// One bit field of a pixel, scaled to 0..255.
const Field = struct {
    mask: u32,
    shift: u5,
    max: u32,

    fn init(mask: u32) Field {
        if (mask == 0) return .{ .mask = 0, .shift = 0, .max = 0 };
        const shift: u5 = @intCast(@ctz(mask));
        return .{ .mask = mask, .shift = shift, .max = mask >> shift };
    }

    fn get(f: Field, px: u32) u8 {
        if (f.max == 0) return 0;
        const v: u64 = (px & f.mask) >> f.shift;
        return @intCast((v * 255 + f.max / 2) / f.max);
    }
};

pub fn decodeDib(gpa: Allocator, dib: []const u8) c.Error!c.Image {
    const l = try parseHeader(dib);
    const count = @as(u64, l.width) * l.height;
    if (count > c.max_image_pixels) return error.ImageTooLarge;
    if (l.pixels_off + l.stride * l.height > dib.len) return error.InvalidDib;
    const table = dib[l.table_off..@intCast(l.pixels_off)];
    const pixels = dib[@intCast(l.pixels_off)..];
    const w: usize = l.width;
    const h: usize = @intCast(l.height);
    const stride: usize = @intCast(l.stride);

    const rgba = try gpa.alloc(u8, w * h * 4);
    errdefer gpa.free(rgba);

    var fields: [4]Field = undefined;
    var alpha_from_data = false;
    if (l.compression == c.BI_BITFIELDS) {
        for (&fields, l.masks) |*f, m| f.* = .init(m);
        alpha_from_data = l.masks[3] != 0;
    } else if (l.bpp == 16) {
        // BI_RGB 16 bpp is X1R5G5B5.
        fields = .{ .init(0x7C00), .init(0x03E0), .init(0x001F), .init(0) };
    }
    // 32 bpp BI_RGB: the fourth byte is alpha unless it is 0 everywhere.
    var any_alpha = false;

    for (0..h) |row| {
        const src_row = if (l.top_down) row else h - 1 - row;
        const src = pixels[src_row * stride ..][0..stride];
        const dst = rgba[row * w * 4 ..][0 .. w * 4];
        for (0..w) |x| {
            const o = dst[x * 4 ..][0..4];
            switch (l.bpp) {
                1, 4, 8 => {
                    const bits: usize = l.bpp;
                    const bit = x * bits;
                    const shift: u3 = @intCast(8 - bits - bit % 8);
                    const index = (src[bit / 8] >> shift) & @as(u8, @intCast((@as(u16, 1) << @intCast(bits)) - 1));
                    if (index >= l.colors) return error.InvalidDib;
                    const e = table[@as(usize, index) * 4 ..][0..4];
                    o.* = .{ e[2], e[1], e[0], 255 };
                },
                16 => {
                    const px: u32 = rd16(src, x * 2);
                    o.* = .{ fields[0].get(px), fields[1].get(px), fields[2].get(px), if (alpha_from_data) fields[3].get(px) else 255 };
                },
                24 => {
                    const p = src[x * 3 ..][0..3];
                    o.* = .{ p[2], p[1], p[0], 255 };
                },
                32 => {
                    if (l.compression == c.BI_BITFIELDS) {
                        const px = rd32(src, x * 4);
                        o.* = .{ fields[0].get(px), fields[1].get(px), fields[2].get(px), if (alpha_from_data) fields[3].get(px) else 255 };
                    } else {
                        const p = src[x * 4 ..][0..4];
                        o.* = .{ p[2], p[1], p[0], p[3] };
                        any_alpha = any_alpha or p[3] != 0;
                    }
                },
                else => unreachable,
            }
        }
    }
    if (l.bpp == 32 and l.compression == c.BI_RGB and !any_alpha) {
        var i: usize = 3;
        while (i < rgba.len) : (i += 4) rgba[i] = 255;
    }
    return .{ .width = l.width, .height = @intCast(h), .rgba = rgba };
}

/// Byte length of `img.rgba`; the dimensions must fit a DIB's signed fields.
fn imageBytes(img: c.Image) c.Error!u32 {
    if (img.width == 0 or img.height == 0) return error.InvalidDib;
    if (img.width > std.math.maxInt(i32) or img.height > std.math.maxInt(i32)) return error.InvalidDib;
    const n = @as(u64, img.width) * img.height * 4;
    if (n != img.rgba.len or n > std.math.maxInt(u32)) return error.InvalidDib;
    return @intCast(n);
}

fn writeInfoHeader(d: []u8, header_size: u32, img: c.Image, compression: u32, size_image: u32) void {
    @memset(d[0..header_size], 0);
    wr32(d, 0, header_size);
    wr32(d, 4, img.width);
    wr32(d, 8, img.height); // positive: bottom-up
    wr16(d, 12, 1);
    wr16(d, 14, 32);
    wr32(d, 16, compression);
    wr32(d, 20, size_image);
    wr32(d, 24, 2835); // 72 dpi
    wr32(d, 28, 2835);
}

fn writeBgraBottomUp(dst: []u8, img: c.Image) void {
    const w: usize = img.width;
    const h: usize = img.height;
    for (0..h) |row| {
        const src = img.rgba[(h - 1 - row) * w * 4 ..][0 .. w * 4];
        const out = dst[row * w * 4 ..][0 .. w * 4];
        for (0..w) |x| {
            const p = src[x * 4 ..][0..4];
            out[x * 4 ..][0..4].* = .{ p[2], p[1], p[0], p[3] };
        }
    }
}

pub fn encodeDib(gpa: Allocator, img: c.Image) c.Error![]u8 {
    const n = try imageBytes(img);
    const hs = c.bitmap_info_header_len;
    const d = try gpa.alloc(u8, hs + @as(usize, n));
    writeInfoHeader(d, hs, img, c.BI_RGB, n);
    writeBgraBottomUp(d[hs..], img);
    return d;
}

pub fn encodeDibV5(gpa: Allocator, img: c.Image) c.Error![]u8 {
    const n = try imageBytes(img);
    const hs = c.bitmap_v5_header_len;
    const d = try gpa.alloc(u8, hs + @as(usize, n));
    writeInfoHeader(d, hs, img, c.BI_BITFIELDS, n);
    wr32(d, 40, 0x00FF0000); // bV5RedMask
    wr32(d, 44, 0x0000FF00); // bV5GreenMask
    wr32(d, 48, 0x000000FF); // bV5BlueMask
    wr32(d, 52, 0xFF000000); // bV5AlphaMask
    wr32(d, 56, c.LCS_sRGB); // bV5CSType; endpoints and gamma stay 0
    wr32(d, 108, c.LCS_GM_IMAGES); // bV5Intent; profile data/size, reserved 0
    writeBgraBottomUp(d[hs..], img);
    return d;
}

pub fn dibToBmp(gpa: Allocator, dib: []const u8) c.Error![]u8 {
    const l = try parseHeader(dib);
    const fh = c.bitmap_file_header_len;
    if (dib.len > std.math.maxInt(u32) - fh) return error.InvalidDib;
    const out = try gpa.alloc(u8, fh + dib.len);
    out[0] = 'B';
    out[1] = 'M';
    wr32(out, 2, @intCast(fh + dib.len)); // bfSize
    wr32(out, 6, 0); // bfReserved1, bfReserved2
    wr32(out, 10, @intCast(fh + l.pixels_off)); // bfOffBits
    @memcpy(out[fh..], dib);
    return out;
}

pub fn bmpToDib(gpa: Allocator, bmp: []const u8) c.Error![]u8 {
    const fh = c.bitmap_file_header_len;
    if (bmp.len < fh + c.bitmap_info_header_len) return error.InvalidBmp;
    if (bmp[0] != 'B' or bmp[1] != 'M') return error.InvalidBmp;
    const dib = bmp[fh..];
    const l = parseHeader(dib) catch return error.InvalidBmp;
    const off: u64 = rd32(bmp, 10);
    if (off < fh + l.pixels_off or off > bmp.len) return error.InvalidBmp;
    const head = dib[0..@intCast(l.pixels_off)];
    const pixels = bmp[@intCast(off)..];
    const out = try gpa.alloc(u8, head.len + pixels.len);
    @memcpy(out[0..head.len], head);
    @memcpy(out[head.len..], pixels);
    return out;
}

pub fn dibToPng(gpa: Allocator, dib: []const u8) c.Error![]u8 {
    const img = try decodeDib(gpa, dib);
    defer img.deinit(gpa);
    return png.encodePng(gpa, img);
}

pub fn pngToDib(gpa: Allocator, data: []const u8) c.Error![]u8 {
    const img = try png.decodePng(gpa, data);
    defer img.deinit(gpa);
    return encodeDib(gpa, img);
}
