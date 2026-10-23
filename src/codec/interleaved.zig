//! MS-RDPBCGR interleaved RLE bitmap encoder: TS_BITMAP_DATA (2.2.9.1.1.3.1.2.2) carrying an
//! RLE_BITMAP_STREAM (2.2.9.1.1.3.1.2.4) at 8, 15, 16 and 24 bpp; 32 bpp uses planar instead.
//! RleDecompress (3.1.9) decides "first line" once per order, so no order crosses its end.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

pub const Error = error{
    InvalidDimensions,
    BadBpp,
    /// 8 bpp without a palette, or a colour not in it.
    NoPalette,
    /// A run length the order cannot express (0, or > 0xFFFF).
    BadRun,
    BufferTooSmall,
    /// A length does not fit the u16 fields of TS_BITMAP_DATA / TS_CD_HEADER.
    TooLarge,
} || std.mem.Allocator.Error;

// Order codes (2.2.9.1.1.3.1.2.4).
pub const regular_bg_run: u8 = 0x0;
pub const regular_fg_run: u8 = 0x1;
pub const regular_fgbg_image: u8 = 0x2;
pub const regular_color_run: u8 = 0x3;
pub const regular_color_image: u8 = 0x4;
pub const lite_set_fg_fg_run: u8 = 0xC;
pub const lite_set_fg_fgbg_image: u8 = 0xD;
pub const lite_dithered_run: u8 = 0xE;
pub const mega_mega_bg_run: u8 = 0xF0;
pub const mega_mega_fg_run: u8 = 0xF1;
pub const mega_mega_fgbg_image: u8 = 0xF2;
pub const mega_mega_color_run: u8 = 0xF3;
pub const mega_mega_color_image: u8 = 0xF4;
pub const mega_mega_set_fg_run: u8 = 0xF6;
pub const mega_mega_set_fgbg_image: u8 = 0xF7;
pub const mega_mega_dithered_run: u8 = 0xF8;
pub const special_fgbg_1: u8 = 0xF9;
pub const special_fgbg_2: u8 = 0xFA;
pub const white: u8 = 0xFD;
pub const black: u8 = 0xFE;

/// Bitmasks of SPECIAL_FGBG_1 / SPECIAL_FGBG_2 (8 pixels each).
const mask_special_1: u8 = 0x03;
const mask_special_2: u8 = 0x05;

/// TS_BITMAP_DATA flags.
pub const bitmap_compression: u16 = 0x0001;
pub const no_bitmap_compression_hdr: u16 = 0x0400;
/// TS_UPDATE_BITMAP_DATA updateType.
pub const update_type_bitmap: u16 = 0x0001;
pub const cd_header_len: usize = 8;

pub const Bpp = enum(u8) {
    bpp8 = 8,
    bpp15 = 15,
    bpp16 = 16,
    bpp24 = 24,

    pub fn bytesPerPixel(b: Bpp) u8 {
        return switch (b) {
            .bpp8 => 1,
            .bpp15, .bpp16 => 2,
            .bpp24 => 3,
        };
    }

    /// The WHITE order's value and the initial foreground colour.
    fn whitePel(b: Bpp) u32 {
        return switch (b) {
            .bpp8 => 0xFF,
            .bpp15 => 0x7FFF,
            .bpp16 => 0xFFFF,
            .bpp24 => 0xFF_FFFF,
        };
    }
};

/// The encoder picks the regular / lite / MEGA / MEGA_MEGA form from the run length.
pub const Order = enum { bg_run, fg_run, set_fg_run, dithered_run, color_run, fgbg_image, set_fgbg_image, color_image };

const max_run: usize = 0xFFFF;

const Form = struct { code: u8, mega_mega: u8, lite: bool, fgbg: bool };

fn form(order: Order) Form {
    return switch (order) {
        .bg_run => .{ .code = regular_bg_run << 5, .mega_mega = mega_mega_bg_run, .lite = false, .fgbg = false },
        .fg_run => .{ .code = regular_fg_run << 5, .mega_mega = mega_mega_fg_run, .lite = false, .fgbg = false },
        .fgbg_image => .{ .code = regular_fgbg_image << 5, .mega_mega = mega_mega_fgbg_image, .lite = false, .fgbg = true },
        .color_run => .{ .code = regular_color_run << 5, .mega_mega = mega_mega_color_run, .lite = false, .fgbg = false },
        .color_image => .{ .code = regular_color_image << 5, .mega_mega = mega_mega_color_image, .lite = false, .fgbg = false },
        .set_fg_run => .{ .code = lite_set_fg_fg_run << 4, .mega_mega = mega_mega_set_fg_run, .lite = true, .fgbg = false },
        .set_fgbg_image => .{ .code = lite_set_fg_fgbg_image << 4, .mega_mega = mega_mega_set_fgbg_image, .lite = true, .fgbg = true },
        .dithered_run => .{ .code = lite_dithered_run << 4, .mega_mega = mega_mega_dithered_run, .lite = true, .fgbg = false },
    };
}

/// Bytes of the order header `writeOrderHeader` writes for `run` (1..65535).
fn headerLen(order: Order, run: usize) usize {
    const f = form(order);
    const in_hdr: usize = if (f.lite) 15 else 31;
    if (f.fgbg) {
        if (run % 8 == 0 and run / 8 <= in_hdr) return 1;
        return if (run <= 256) 2 else 3;
    }
    if (run <= in_hdr) return 1;
    return if (run <= in_hdr + 1 + 255) 2 else 3;
}

/// Order header and run length in the shortest form. FGBG images put run/8 in the header
/// only for multiples of 8 up to 248 (lite: 120).
pub fn writeOrderHeader(w: *bytes.Writer, order: Order, run: u32) Error!void {
    if (run == 0 or run > max_run) return error.BadRun;
    const f = form(order);
    const in_hdr: u32 = if (f.lite) 15 else 31;
    if (f.fgbg) {
        if (run % 8 == 0 and run / 8 <= in_hdr) return w.byte(f.code | @as(u8, @intCast(run / 8)));
        if (run <= 256) return w.bytes(&.{ f.code, @intCast(run - 1) });
    } else {
        if (run <= in_hdr) return w.byte(f.code | @as(u8, @intCast(run)));
        if (run <= in_hdr + 1 + 255) return w.bytes(&.{ f.code, @intCast(run - in_hdr - 1) });
    }
    try w.bytes(&.{ f.mega_mega, @truncate(run), @intCast(run >> 8) });
}

/// 24 bpp B, G, R; 16 bpp RGB565 and 15 bpp RGB555 as u16 LE; 8 bpp the palette index.
pub fn pixelValue(bpp: Bpp, b: u8, g: u8, r: u8, palette: ?[]const [3]u8) Error!u32 {
    return switch (bpp) {
        .bpp24 => @as(u32, b) | @as(u32, g) << 8 | @as(u32, r) << 16,
        .bpp16 => (@as(u32, r) >> 3) << 11 | (@as(u32, g) >> 2) << 5 | b >> 3,
        .bpp15 => (@as(u32, r) >> 3) << 10 | (@as(u32, g) >> 3) << 5 | b >> 3,
        .bpp8 => {
            const pal = palette orelse return error.NoPalette;
            for (pal[0..@min(pal.len, 256)], 0..) |e, i| {
                if (e[0] == b and e[1] == g and e[2] == r) return @intCast(i);
            }
            return error.NoPalette;
        },
    };
}

/// Scan line width in pixels: `width` rounded up to a multiple of 4.
pub fn scanWidth(width: u16) Error!u16 {
    if (width == 0 or width > 0xFFFC) return error.InvalidDimensions;
    return std.mem.alignForward(u16, width, 4);
}

/// Bottom-up scan lines of `scan` pixels, padded with each line's last pixel. Caller frees.
fn streamValues(gpa: std.mem.Allocator, pixels: []const u8, stride: usize, width: u16, height: u16, scan: usize, bpp: Bpp, palette: ?[]const [3]u8) Error![]u32 {
    const v = try gpa.alloc(u32, scan * height);
    errdefer gpa.free(v);
    var map: std.AutoHashMapUnmanaged(u32, u8) = .empty;
    defer map.deinit(gpa);
    if (bpp == .bpp8) {
        const pal = palette orelse return error.NoPalette;
        if (pal.len > 256) return error.NoPalette;
        try map.ensureTotalCapacity(gpa, @intCast(pal.len));
        var i = pal.len;
        while (i > 0) { // backwards, so the first index of a duplicate wins
            i -= 1;
            const e = pal[i];
            map.putAssumeCapacity(@as(u32, e[0]) | @as(u32, e[1]) << 8 | @as(u32, e[2]) << 16, @intCast(i));
        }
    }
    for (0..height) |row| {
        const src = pixels[(height - 1 - row) * stride ..][0 .. @as(usize, width) * 4];
        const dst = v[row * scan ..][0..scan];
        for (0..width) |x| {
            const p = src[x * 4 ..][0..3];
            dst[x] = switch (bpp) {
                .bpp8 => map.get(@as(u32, p[0]) | @as(u32, p[1]) << 8 | @as(u32, p[2]) << 16) orelse return error.NoPalette,
                else => pixelValue(bpp, p[0], p[1], p[2], null) catch unreachable,
            };
        }
        @memset(dst[width..], dst[width - 1]);
    }
    return v;
}

/// Mirrors the decoder state: foreground colour and pending foreground-pel insertion.
const Enc = struct {
    v: []const u32,
    scan: usize,
    psize: usize,
    white: u32,
    w: *bytes.Writer,
    fg: u32,
    /// After a background run, the next background run starts with an implicit foreground pel.
    insert: bool = false,
    first: bool = true,
    end: usize = 0,

    /// Shortest order worth breaking a colour image for.
    const min_savings = 3;
    /// A run of this many identical FGBG bits ends the image.
    const fgbg_streak = 24;

    const Kind = enum { bg_run, fg_run, set_fg_run, color_run, dithered_run, fgbg_image, set_fgbg_image };
    const Choice = struct { kind: Kind, len: usize, savings: isize, fg: u32 = 0 };

    inline fn bgPel(e: *const Enc, j: usize) u32 {
        return if (e.first) 0 else e.v[j - e.scan];
    }

    inline fn fgPel(e: *const Enc, j: usize, fg: u32) u32 {
        return if (e.first) fg else e.v[j - e.scan] ^ fg;
    }

    /// The foreground colour that makes pixel j a foreground pel.
    inline fn fgOf(e: *const Enc, j: usize) u32 {
        return if (e.first) e.v[j] else e.v[j] ^ e.v[j - e.scan];
    }

    inline fn limit(e: *const Enc, i: usize) usize {
        return @min(e.end, i + max_run);
    }

    fn bgLen(e: *const Enc, i: usize, insert: bool) usize {
        var k = i;
        const lim = e.limit(i);
        if (insert) {
            if (e.v[k] != e.fgPel(k, e.fg)) return 0;
            k += 1;
        }
        while (k < lim and e.v[k] == e.bgPel(k)) k += 1;
        return k - i;
    }

    fn fgLen(e: *const Enc, i: usize, fg: u32) usize {
        var k = i;
        const lim = e.limit(i);
        while (k < lim and e.v[k] == e.fgPel(k, fg)) k += 1;
        return k - i;
    }

    fn colorLen(e: *const Enc, i: usize) usize {
        var k = i + 1;
        const lim = e.limit(i);
        while (k < lim and e.v[k] == e.v[i]) k += 1;
        return k - i;
    }

    fn ditherPairs(e: *const Enc, i: usize) usize {
        if (i + 1 >= e.end or e.v[i] == e.v[i + 1]) return 0;
        const a = e.v[i];
        const b = e.v[i + 1];
        var n: usize = 1;
        var k = i + 2;
        while (n < max_run and k + 1 < e.end and e.v[k] == a and e.v[k + 1] == b) : (k += 2) n += 1;
        return n;
    }

    /// Longest FGBG image from i for one foreground colour, cut before `fgbg_streak` identical bits.
    fn fgbgScan(e: *const Enc, i: usize) struct { len: usize, fg: ?u32 } {
        var fg: ?u32 = null;
        var k = i;
        const lim = e.limit(i);
        var streak: usize = 0;
        var streak_fg = false;
        while (k < lim) : (k += 1) {
            const is_fg = e.v[k] != e.bgPel(k);
            if (is_fg) {
                const f = e.fgOf(k);
                if (fg) |cur| {
                    if (f != cur) break;
                } else fg = f;
            }
            if (is_fg == streak_fg) streak += 1 else {
                streak = 1;
                streak_fg = is_fg;
            }
            if (streak >= fgbg_streak) {
                k = k + 1 - streak;
                break;
            }
        }
        return .{ .len = k - i, .fg = fg };
    }

    fn savings(e: *const Enc, len: usize, cost: usize) isize {
        return @as(isize, @intCast(len * e.psize)) - @as(isize, @intCast(cost));
    }

    /// Best order at i other than a colour image; null if none saves `min_savings`.
    fn best(e: *const Enc, i: usize, insert: bool) ?Choice {
        var c: Choice = .{ .kind = .bg_run, .len = 0, .savings = min_savings - 1 };
        const consider = struct {
            fn f(cur: *Choice, n: Choice) void {
                if (n.len > 0 and n.savings > cur.savings) cur.* = n;
            }
        }.f;
        const bg = e.bgLen(i, insert);
        if (bg > 0) consider(&c, .{ .kind = .bg_run, .len = bg, .savings = e.savings(bg, headerLen(.bg_run, bg)) });
        const fgr = e.fgLen(i, e.fg);
        if (fgr > 0) consider(&c, .{ .kind = .fg_run, .len = fgr, .savings = e.savings(fgr, headerLen(.fg_run, fgr)) });
        if (!e.first) {
            const nf = e.fgOf(i);
            if (nf != 0 and nf != e.fg) {
                const n = e.fgLen(i, nf);
                consider(&c, .{ .kind = .set_fg_run, .len = n, .fg = nf, .savings = e.savings(n, headerLen(.set_fg_run, n) + e.psize) });
            }
        }
        const cr = e.colorLen(i);
        consider(&c, .{ .kind = .color_run, .len = cr, .savings = e.savings(cr, headerLen(.color_run, cr) + e.psize) });
        const dp = e.ditherPairs(i);
        if (dp >= 2) consider(&c, .{ .kind = .dithered_run, .len = 2 * dp, .savings = e.savings(2 * dp, headerLen(.dithered_run, dp) + 2 * e.psize) });
        const fb = e.fgbgScan(i);
        if (fb.len > 0) {
            const masks = (fb.len + 7) / 8;
            const f = fb.fg orelse e.fg;
            if (f == e.fg) {
                consider(&c, .{ .kind = .fgbg_image, .len = fb.len, .fg = f, .savings = e.savings(fb.len, headerLen(.fgbg_image, fb.len) + masks) });
            } else {
                consider(&c, .{ .kind = .set_fgbg_image, .len = fb.len, .fg = f, .savings = e.savings(fb.len, headerLen(.set_fgbg_image, fb.len) + masks + e.psize) });
            }
        }
        return if (c.len > 0) c else null;
    }

    fn pixel(e: *Enc, v: u32) Error!void {
        const b = [4]u8{ @truncate(v), @truncate(v >> 8), @truncate(v >> 16), 0 };
        try e.w.bytes(b[0..e.psize]);
    }

    fn emit(e: *Enc, c: Choice, i: usize) Error!void {
        const n: u32 = @intCast(c.len);
        switch (c.kind) {
            .bg_run => {
                try writeOrderHeader(e.w, .bg_run, n);
                e.insert = true;
                return;
            },
            .fg_run => try writeOrderHeader(e.w, .fg_run, n),
            .set_fg_run => {
                try writeOrderHeader(e.w, .set_fg_run, n);
                try e.pixel(c.fg);
                e.fg = c.fg;
            },
            .color_run => {
                try writeOrderHeader(e.w, .color_run, n);
                try e.pixel(e.v[i]);
            },
            .dithered_run => {
                try writeOrderHeader(e.w, .dithered_run, n / 2);
                try e.pixel(e.v[i]);
                try e.pixel(e.v[i + 1]);
            },
            .fgbg_image, .set_fgbg_image => {
                const set = c.kind == .set_fgbg_image;
                if (set) e.fg = c.fg;
                if (!set and c.len == 8) {
                    const m = e.mask(i, 8);
                    if (m == mask_special_1 or m == mask_special_2) {
                        try e.w.byte(if (m == mask_special_1) special_fgbg_1 else special_fgbg_2);
                        e.insert = false;
                        return;
                    }
                }
                try writeOrderHeader(e.w, if (set) .set_fgbg_image else .fgbg_image, n);
                if (set) try e.pixel(c.fg);
                var k: usize = 0;
                while (k < c.len) : (k += 8) try e.w.byte(e.mask(i + k, @min(8, c.len - k)));
            },
        }
        e.insert = false;
    }

    /// FGBG bitmask of `n` (<= 8) pixels from i, bit k = pixel i + k.
    fn mask(e: *const Enc, i: usize, n: usize) u8 {
        var m: u8 = 0;
        for (0..n) |k| {
            if (e.v[i + k] != e.bgPel(i + k)) m |= @as(u8, 1) << @intCast(k);
        }
        return m;
    }

    fn colorImage(e: *Enc, i: usize, n: usize) Error!void {
        if (n == 1 and (e.v[i] == e.white or e.v[i] == 0)) {
            try e.w.byte(if (e.v[i] == 0) black else white);
        } else {
            try writeOrderHeader(e.w, .color_image, @intCast(n));
            for (e.v[i..][0..n]) |p| try e.pixel(p);
        }
        e.insert = false;
    }

    fn segment(e: *Enc, start: usize, end: usize, first: bool) Error!void {
        e.first = first;
        e.end = end;
        // RleDecompress clears the insertion flag when it leaves the first line
        if (!first) e.insert = false;
        var i = start;
        while (i < end) {
            if (e.best(i, e.insert)) |c| {
                try e.emit(c, i);
                i += c.len;
                continue;
            }
            var j = i + 1;
            while (j < end and j - i < max_run and e.best(j, false) == null) j += 1;
            try e.colorImage(i, j - i);
            i = j;
        }
    }
};

/// Encodes bottom-up with scan lines padded to `scanWidth(width)`. 8 bpp needs `palette`
/// (256 B, G, R entries). Lossless at the target depth.
pub fn encode(gpa: std.mem.Allocator, pixels: []const u8, stride: usize, width: u16, height: u16, bpp: Bpp, palette: ?[]const [3]u8) Error![]u8 {
    if (width == 0 or height == 0) return error.InvalidDimensions;
    if (stride < @as(usize, width) * 4 or pixels.len < (@as(usize, height) - 1) * stride + @as(usize, width) * 4)
        return error.InvalidDimensions;
    if (bpp == .bpp8 and palette == null) return error.NoPalette;
    const scan: usize = try scanWidth(width);
    const v = try streamValues(gpa, pixels, stride, width, height, scan, bpp, palette);
    defer gpa.free(v);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, v.len / 4 + 16);
    var w = bytes.Writer.init(&out, gpa);
    var e: Enc = .{ .v = v, .scan = scan, .psize = bpp.bytesPerPixel(), .white = bpp.whitePel(), .w = &w, .fg = bpp.whitePel() };
    try e.segment(0, scan, true);
    try e.segment(scan, v.len, false);
    return out.toOwnedSlice(gpa);
}

/// cbCompFirstRowSize is 0.
pub fn writeCdHeader(w: *bytes.Writer, main_body_size: u16, scan_width: u16, uncompressed_size: u16) Error!void {
    try w.u16le(0);
    try w.u16le(main_body_size);
    try w.u16le(scan_width);
    try w.u16le(uncompressed_size);
}

/// destRight/destBottom are inclusive. Adds NO_BITMAP_COMPRESSION_HDR when `no_hdr`, else a
/// TS_CD_HEADER. error.TooLarge when a length does not fit its u16 field.
pub fn writeBitmapData(gpa: std.mem.Allocator, w: *bytes.Writer, x: u16, y: u16, pixels: []const u8, stride: usize, width: u16, height: u16, bpp: Bpp, palette: ?[]const [3]u8, no_hdr: bool) Error!void {
    if (width == 0 or height == 0) return error.InvalidDimensions;
    const right = @as(u32, x) + width - 1;
    const bottom = @as(u32, y) + height - 1;
    if (right > 0xFFFF or bottom > 0xFFFF) return error.InvalidDimensions;
    const scan = try scanWidth(width);
    const stream = try encode(gpa, pixels, stride, width, height, bpp, palette);
    defer gpa.free(stream);
    const uncompressed = @as(usize, scan) * height * bpp.bytesPerPixel();
    const length = stream.len + if (no_hdr) 0 else cd_header_len;
    if (length > 0xFFFF or (!no_hdr and uncompressed > 0xFFFF)) return error.TooLarge;
    try w.u16le(x);
    try w.u16le(y);
    try w.u16le(@intCast(right));
    try w.u16le(@intCast(bottom));
    try w.u16le(scan);
    try w.u16le(height);
    try w.u16le(@backingInt(bpp));
    try w.u16le(bitmap_compression | if (no_hdr) no_bitmap_compression_hdr else 0);
    try w.u16le(@intCast(length));
    if (!no_hdr) try writeCdHeader(w, @intCast(stream.len), scan, @intCast(uncompressed));
    try w.bytes(stream);
}
