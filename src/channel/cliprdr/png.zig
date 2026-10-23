//! PNG (W3C PNG 3rd edition) for the clipboard's image/png: a decoder for every conforming
//! datastream and an 8-bit RGBA encoder. zlib (RFC 1950) framing is checked here;
//! std.compress.flate does the deflate (RFC 1951) part.

const std = @import("std");
const c = @import("../cliprdr.zig");

const Allocator = std.mem.Allocator;
const flate = std.compress.flate;
const Crc32 = std.hash.Crc32;

const Ihdr = struct {
    width: u32,
    height: u32,
    depth: u8,
    ctype: u8,
    interlace: bool,

    /// Samples per pixel (PNG 6.1).
    fn channels(h: Ihdr) u32 {
        return switch (h.ctype) {
            0, 3 => 1,
            4 => 2,
            2 => 3,
            6 => 4,
            else => unreachable,
        };
    }

    fn bitsPerPixel(h: Ihdr) u32 {
        return h.channels() * h.depth;
    }

    /// Bytes per complete scanline of `w` pixels (without the filter byte).
    fn rowBytes(h: Ihdr, w: u64) u64 {
        return (w * h.bitsPerPixel() + 7) / 8;
    }
};

/// PNG 11.2.2 table 11.1: allowed colour type / bit depth combinations.
fn validDepth(ctype: u8, depth: u8) bool {
    return switch (ctype) {
        0 => depth == 1 or depth == 2 or depth == 4 or depth == 8 or depth == 16,
        3 => depth == 1 or depth == 2 or depth == 4 or depth == 8,
        2, 4, 6 => depth == 8 or depth == 16,
        else => false,
    };
}

fn parseIhdr(body: []const u8) c.Error!Ihdr {
    if (body.len != 13) return error.InvalidPng;
    const h: Ihdr = .{
        .width = std.mem.readInt(u32, body[0..4], .big),
        .height = std.mem.readInt(u32, body[4..8], .big),
        .depth = body[8],
        .ctype = body[9],
        .interlace = body[12] == 1,
    };
    if (h.width == 0 or h.height == 0 or h.width > std.math.maxInt(i32) or h.height > std.math.maxInt(i32))
        return error.InvalidPng;
    if (!validDepth(h.ctype, h.depth)) return error.InvalidPng;
    if (body[10] != 0 or body[11] != 0 or body[12] > 1) return error.InvalidPng;
    if (@as(u64, h.width) * h.height > c.max_image_pixels) return error.ImageTooLarge;
    return h;
}

/// One reduced image of the interlaced layout (PNG 8.2).
const Pass = struct { x0: u32, y0: u32, dx: u32, dy: u32 };

const adam7 = [7]Pass{
    .{ .x0 = 0, .y0 = 0, .dx = 8, .dy = 8 },
    .{ .x0 = 4, .y0 = 0, .dx = 8, .dy = 8 },
    .{ .x0 = 0, .y0 = 4, .dx = 4, .dy = 8 },
    .{ .x0 = 2, .y0 = 0, .dx = 4, .dy = 4 },
    .{ .x0 = 0, .y0 = 2, .dx = 2, .dy = 4 },
    .{ .x0 = 1, .y0 = 0, .dx = 2, .dy = 2 },
    .{ .x0 = 0, .y0 = 1, .dx = 1, .dy = 2 },
};
const no_interlace = [1]Pass{.{ .x0 = 0, .y0 = 0, .dx = 1, .dy = 1 }};

fn passes(h: Ihdr) []const Pass {
    return if (h.interlace) &adam7 else &no_interlace;
}

fn passDim(full: u32, start: u32, step: u32) u32 {
    return if (full > start) (full - start + step - 1) / step else 0;
}

/// Size of the decompressed image data, filter bytes included.
fn rawLen(h: Ihdr) u64 {
    var n: u64 = 0;
    for (passes(h)) |p| {
        const pw = passDim(h.width, p.x0, p.dx);
        const ph = passDim(h.height, p.y0, p.dy);
        if (pw == 0 or ph == 0) continue;
        n += @as(u64, ph) * (1 + h.rowBytes(pw));
    }
    return n;
}

/// tRNS (PNG 11.3.2.1); a gray / RGB key compares samples at their full bit depth.
const Transparency = union(enum) {
    none,
    palette: []const u8,
    gray: u16,
    rgb: [3]u16,
};

pub fn decodePng(gpa: Allocator, data: []const u8) c.Error!c.Image {
    if (data.len < 8 or !std.mem.eql(u8, data[0..8], &c.png_signature)) return error.InvalidPng;
    var pos: usize = 8;
    var hdr: ?Ihdr = null;
    var plte: ?[]const u8 = null;
    var trns: Transparency = .none;
    var idat: std.ArrayList(u8) = .empty;
    defer idat.deinit(gpa);
    var seen_idat = false;
    var idat_done = false;
    while (true) {
        // PNG 5.3; a stream that ends before IEND is truncated.
        if (data.len - pos < 12) return error.InvalidPng;
        const len = std.mem.readInt(u32, data[pos..][0..4], .big);
        if (len >= 0x8000_0000) return error.InvalidPng;
        if (data.len - pos - 12 < len) return error.InvalidPng;
        const typ = data[pos + 4 ..][0..4];
        const body = data[pos + 8 ..][0..len];
        const crc = std.mem.readInt(u32, data[pos + 8 + len ..][0..4], .big);
        pos += 12 + len;
        var h = Crc32.init();
        h.update(typ);
        h.update(body);
        if (h.final() != crc) return error.InvalidPng;
        for (typ) |b| if (!std.ascii.isAlphabetic(b)) return error.InvalidPng;

        if (hdr == null) {
            if (!std.mem.eql(u8, typ, "IHDR")) return error.InvalidPng;
            hdr = try parseIhdr(body);
            continue;
        }
        const ih = hdr.?;
        if (seen_idat and !std.mem.eql(u8, typ, "IDAT")) idat_done = true;
        if (std.mem.eql(u8, typ, "IHDR")) {
            return error.InvalidPng;
        } else if (std.mem.eql(u8, typ, "IDAT")) {
            // PNG 5.6: IDATs are consecutive; a palette image needs PLTE first.
            if (idat_done) return error.InvalidPng;
            if (ih.ctype == 3 and plte == null) return error.InvalidPng;
            try idat.appendSlice(gpa, body);
            seen_idat = true;
        } else if (std.mem.eql(u8, typ, "PLTE")) {
            if (seen_idat or plte != null) return error.InvalidPng;
            // PNG 11.2.3: only a suggestion in truecolour images, forbidden in greyscale; ignored for both.
            if (ih.ctype == 3) {
                if (len == 0 or len % 3 != 0 or len > 3 * 256) return error.InvalidPng;
                plte = body;
            }
        } else if (std.mem.eql(u8, typ, "IEND")) {
            break;
        } else if (std.mem.eql(u8, typ, "tRNS")) {
            // PNG 11.3.2.1; a misplaced or malformed tRNS is ignored.
            if (seen_idat) continue;
            switch (ih.ctype) {
                0 => if (len == 2) {
                    trns = .{ .gray = std.mem.readInt(u16, body[0..2], .big) };
                },
                2 => if (len == 6) {
                    trns = .{ .rgb = .{
                        std.mem.readInt(u16, body[0..2], .big),
                        std.mem.readInt(u16, body[2..4], .big),
                        std.mem.readInt(u16, body[4..6], .big),
                    } };
                },
                3 => if (plte) |p| {
                    if (len <= p.len / 3) trns = .{ .palette = body };
                },
                else => {},
            }
        } else if (typ[0] & 0x20 == 0) {
            // PNG 5.4: an unknown critical chunk.
            return error.UnsupportedPng;
        }
    }
    if (!seen_idat) return error.InvalidPng;
    const ih = hdr.?;

    const raw_len: usize = @intCast(rawLen(ih));
    const raw = try inflateZlib(gpa, idat.items, raw_len);
    defer gpa.free(raw);

    const w: usize = ih.width;
    const rgba = try gpa.alloc(u8, w * ih.height * 4);
    errdefer gpa.free(rgba);
    try unfilterAndExpand(ih, raw, plte orelse &.{}, trns, rgba);
    return .{ .width = ih.width, .height = ih.height, .rgba = rgba };
}

/// Inflates a zlib stream (RFC 1950) that must produce exactly `expected` bytes; caller frees.
/// The output grows with the inflated data, so a tiny IDAT under a huge IHDR allocates little.
fn inflateZlib(gpa: Allocator, z: []const u8, expected: usize) c.Error![]u8 {
    if (z.len < 2) return error.InvalidPng;
    const cmf = z[0];
    const flg = z[1];
    if (cmf & 0x0F != 8 or cmf >> 4 > 7) return error.InvalidPng;
    if ((@as(u16, cmf) * 256 + flg) % 31 != 0) return error.InvalidPng;
    if (flg & 0x20 != 0) return error.InvalidPng;

    var in: std.Io.Reader = .fixed(z);
    var out: std.Io.Writer.Allocating = try .initCapacity(gpa, @min(expected + 1, 4 * z.len + 4096));
    defer out.deinit();
    var d: flate.Decompress = .init(&in, .zlib, &.{});
    while (true) {
        const room = expected + 1 - out.written().len;
        if (room == 0) return error.InvalidPng; // more data than the image holds
        _ = d.reader.stream(&out.writer, .limited(room)) catch |e| switch (e) {
            error.EndOfStream => break,
            error.ReadFailed => return error.InvalidPng,
            error.WriteFailed => return error.OutOfMemory,
        };
    }
    if (out.written().len != expected) return error.InvalidPng;
    if (std.hash.Adler32.hash(out.written()) != d.container_metadata.zlib.adler) return error.InvalidPng;
    return out.toOwnedSlice();
}

fn paeth(a: u8, b: u8, cc: u8) u8 {
    const p: i16 = @as(i16, a) + b - cc;
    const pa = @abs(p - a);
    const pb = @abs(p - b);
    const pc = @abs(p - cc);
    if (pa <= pb and pa <= pc) return a;
    if (pb <= pc) return b;
    return cc;
}

/// Reverse filtering (PNG 9) in place; `prev` is the previous scanline of the same pass.
fn unfilter(ftype: u8, line: []u8, prev: []const u8, bpp: usize) c.Error!void {
    switch (ftype) {
        0 => {},
        1 => for (bpp..line.len) |i| {
            line[i] +%= line[i - bpp];
        },
        2 => for (line, prev) |*x, b| {
            x.* +%= b;
        },
        3 => for (line, 0..) |*x, i| {
            const a: u16 = if (i >= bpp) line[i - bpp] else 0;
            x.* +%= @intCast((a + prev[i]) / 2);
        },
        4 => for (line, 0..) |*x, i| {
            const a = if (i >= bpp) line[i - bpp] else 0;
            const cc = if (i >= bpp) prev[i - bpp] else 0;
            x.* +%= paeth(a, prev[i], cc);
        },
        else => return error.InvalidPng,
    }
}

fn sample(line: []const u8, i: usize, depth: u8) u16 {
    return switch (depth) {
        8 => line[i],
        16 => std.mem.readInt(u16, line[2 * i ..][0..2], .big),
        else => blk: {
            const bit = i * depth;
            const shift: u3 = @intCast(8 - depth - bit % 8);
            const mask: u8 = @intCast((@as(u16, 1) << @intCast(depth)) - 1);
            break :blk (line[bit / 8] >> shift) & mask;
        },
    };
}

/// PNG 13.12: 16-bit keeps its high byte, lower depths scale so the maximum is 255.
fn to8(v: u16, depth: u8) u8 {
    return switch (depth) {
        16 => @intCast(v >> 8),
        8 => @intCast(v),
        else => @intCast(@as(u32, v) * 255 / ((@as(u32, 1) << @intCast(depth)) - 1)),
    };
}

fn unfilterAndExpand(ih: Ihdr, raw: []u8, plte: []const u8, trns: Transparency, rgba: []u8) c.Error!void {
    const bpp: usize = @max(1, ih.bitsPerPixel() / 8);
    const ch = ih.channels();
    const w: usize = ih.width;
    var pos: usize = 0;
    for (passes(ih)) |p| {
        const pw = passDim(ih.width, p.x0, p.dx);
        const ph = passDim(ih.height, p.y0, p.dy);
        if (pw == 0 or ph == 0) continue;
        const rb: usize = @intCast(ih.rowBytes(pw));
        var prev: ?[]const u8 = null;
        for (0..ph) |j| {
            const ftype = raw[pos];
            const line = raw[pos + 1 ..][0..rb];
            pos += 1 + rb;
            if (prev) |pr| {
                try unfilter(ftype, line, pr, bpp);
            } else {
                // The previous row is zeros: Up adds nothing, Average halves the left byte, Paeth is Sub.
                switch (ftype) {
                    0, 2 => {},
                    1, 4 => for (bpp..line.len) |i| {
                        line[i] +%= line[i - bpp];
                    },
                    3 => for (bpp..line.len) |i| {
                        line[i] +%= line[i - bpp] / 2;
                    },
                    else => return error.InvalidPng,
                }
            }
            prev = line;
            const y: usize = p.y0 + j * p.dy;
            for (0..pw) |i| {
                const x: usize = p.x0 + i * p.dx;
                const o = rgba[(y * w + x) * 4 ..][0..4];
                const s0 = sample(line, i * ch, ih.depth);
                switch (ih.ctype) {
                    0 => {
                        const g = to8(s0, ih.depth);
                        const a: u8 = if (trns == .gray and trns.gray == s0) 0 else 255;
                        o.* = .{ g, g, g, a };
                    },
                    2 => {
                        const s1 = sample(line, i * ch + 1, ih.depth);
                        const s2 = sample(line, i * ch + 2, ih.depth);
                        const a: u8 = if (trns == .rgb and trns.rgb[0] == s0 and trns.rgb[1] == s1 and trns.rgb[2] == s2) 0 else 255;
                        o.* = .{ to8(s0, ih.depth), to8(s1, ih.depth), to8(s2, ih.depth), a };
                    },
                    3 => {
                        if (@as(usize, s0) * 3 >= plte.len) return error.InvalidPng;
                        const e = plte[@as(usize, s0) * 3 ..][0..3];
                        const a: u8 = if (trns == .palette and s0 < trns.palette.len) trns.palette[s0] else 255;
                        o.* = .{ e[0], e[1], e[2], a };
                    },
                    4 => {
                        const g = to8(s0, ih.depth);
                        o.* = .{ g, g, g, to8(sample(line, i * ch + 1, ih.depth), ih.depth) };
                    },
                    6 => o.* = .{
                        to8(s0, ih.depth),
                        to8(sample(line, i * ch + 1, ih.depth), ih.depth),
                        to8(sample(line, i * ch + 2, ih.depth), ih.depth),
                        to8(sample(line, i * ch + 3, ih.depth), ih.depth),
                    },
                    else => unreachable,
                }
            }
        }
    }
}

const idat_chunk_len = 1 << 20;

fn appendChunk(gpa: Allocator, out: *std.ArrayList(u8), typ: *const [4]u8, body: []const u8) Allocator.Error!void {
    var len: [4]u8 = undefined;
    std.mem.writeInt(u32, &len, @intCast(body.len), .big);
    try out.appendSlice(gpa, &len);
    try out.appendSlice(gpa, typ);
    try out.appendSlice(gpa, body);
    var h = Crc32.init();
    h.update(typ);
    h.update(body);
    var crc: [4]u8 = undefined;
    std.mem.writeInt(u32, &crc, h.final(), .big);
    try out.appendSlice(gpa, &crc);
}

fn filterRow(ftype: u8, dst: []u8, line: []const u8, prev: []const u8) void {
    for (dst, line, 0..) |*o, x, i| {
        const a: u8 = if (i >= 4) line[i - 4] else 0;
        const b = prev[i];
        const cc: u8 = if (i >= 4) prev[i - 4] else 0;
        o.* = x -% switch (ftype) {
            0 => 0,
            1 => a,
            2 => b,
            3 => @as(u8, @intCast((@as(u16, a) + b) / 2)),
            else => paeth(a, b, cc),
        };
    }
}

/// Minimum sum of absolute differences, the heuristic for picking a filter.
fn cost(row: []const u8) u64 {
    var s: u64 = 0;
    for (row) |b| s += @abs(@as(i8, @bitCast(b)));
    return s;
}

pub fn encodePng(gpa: Allocator, img: c.Image) c.Error![]u8 {
    if (img.width == 0 or img.height == 0) return error.InvalidPng;
    if (img.width > std.math.maxInt(i32) or img.height > std.math.maxInt(i32)) return error.InvalidPng;
    const stride64 = @as(u64, img.width) * 4;
    if (stride64 * img.height != img.rgba.len) return error.InvalidPng;
    const stride: usize = @intCast(stride64);

    var z: std.Io.Writer.Allocating = try .initCapacity(gpa, @min(img.rgba.len / 2 + 64, 1 << 20));
    defer z.deinit();
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    const comp = try gpa.create(flate.Compress);
    defer gpa.destroy(comp);
    comp.* = flate.Compress.init(&z.writer, window, .zlib, .default) catch return error.OutOfMemory;

    const rows = try gpa.alloc(u8, 2 * (stride + 1) + stride);
    defer gpa.free(rows);
    const best = rows[0 .. stride + 1];
    const trial = rows[stride + 1 ..][0 .. stride + 1];
    const zeros = rows[2 * (stride + 1) ..][0..stride];
    @memset(zeros, 0);

    for (0..img.height) |y| {
        const line = img.rgba[y * stride ..][0..stride];
        const prev = if (y == 0) zeros else img.rgba[(y - 1) * stride ..][0..stride];
        var best_cost: u64 = std.math.maxInt(u64);
        for (0..5) |f| {
            const ftype: u8 = @intCast(f);
            trial[0] = ftype;
            filterRow(ftype, trial[1..], line, prev);
            const k = cost(trial[1..]);
            if (k < best_cost) {
                best_cost = k;
                @memcpy(best, trial);
            }
        }
        comp.writer.writeAll(best) catch return error.OutOfMemory;
    }
    comp.finish() catch return error.OutOfMemory;
    const zdata = z.written();

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, 8 + 25 + zdata.len + 12 * (zdata.len / idat_chunk_len + 1) + 12);
    try out.appendSlice(gpa, &c.png_signature);
    var ihdr: [13]u8 = undefined;
    std.mem.writeInt(u32, ihdr[0..4], img.width, .big);
    std.mem.writeInt(u32, ihdr[4..8], img.height, .big);
    ihdr[8] = 8; // bit depth
    ihdr[9] = 6; // truecolour with alpha
    ihdr[10] = 0; // deflate
    ihdr[11] = 0; // adaptive filtering
    ihdr[12] = 0; // no interlace
    try appendChunk(gpa, &out, "IHDR", &ihdr);
    var off: usize = 0;
    while (off < zdata.len) {
        const n = @min(idat_chunk_len, zdata.len - off);
        try appendChunk(gpa, &out, "IDAT", zdata[off..][0..n]);
        off += n;
    }
    try appendChunk(gpa, &out, "IEND", "");
    return out.toOwnedSlice(gpa);
}
