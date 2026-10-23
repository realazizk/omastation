//! MS-RDPEGFX ClearCodec encoder (2.2.4.1, 3.3.8.1): residual, bands and subcodec layers.
//! Bitmaps of at most 1024 pixels go through the glyph cache; the payload is the cheapest
//! single layer. V-Bar and glyph storage mirror the client's exactly.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const nsc = @import("nsc.zig");

test {
    _ = nsc;
}

pub const Error = error{
    InvalidDimensions,
    TooManyColors,
    ZeroRun,
    /// A V-Bar or band taller than 52 pixels.
    BandTooTall,
    BadIndex,
    /// bitmapDataByteCount over 3 * width * height (2.2.4.1.1.3.1).
    SubcodecTooLarge,
    BufferTooSmall,
} || std.mem.Allocator.Error;

pub const flag_glyph_index: u8 = 0x01;
pub const flag_glyph_hit: u8 = 0x02;
pub const flag_cache_reset: u8 = 0x04;

pub const glyph_slots: u16 = 4000;
pub const glyph_max_area: u32 = 1024;
pub const vbar_storage_size: u16 = 32768;
pub const short_vbar_storage_size: u16 = 16384;
pub const max_band_height: u16 = 52;
pub const max_rlex_palette: u8 = 127;

pub const subcodec_uncompressed: u8 = 0x00;
pub const subcodec_nscodec: u8 = 0x01;
pub const subcodec_rlex: u8 = 0x02;

pub const gfx_codec_id: u16 = 0x0008;

const composite_header_len = 12;
const subcodec_header_len = 13;
const band_header_len = 11;

/// runLengthFactor form of RGB run and RLEX segments: < 255: 1 byte; < 65535: 0xFF + u16;
/// else 0xFF 0xFF 0xFF + u32. `allow_zero` is for RLEX, whose runLengthFactor1 may be 0.
pub fn writeRunLength(w: *bytes.Writer, run: u32, allow_zero: bool) Error!void {
    if (run == 0 and !allow_zero) return error.ZeroRun;
    if (run < 0xFF) return w.byte(@intCast(run));
    if (run < 0xFFFF) {
        try w.byte(0xFF);
        return w.u16le(@intCast(run));
    }
    try w.bytes(&.{ 0xFF, 0xFF, 0xFF });
    try w.u32le(run);
}

fn runLengthLen(run: usize) usize {
    return if (run < 0xFF) 1 else if (run < 0xFFFF) 3 else 7;
}

/// The bitmap stream header: flags, seqNumber, glyphIndex if GLYPH_INDEX.
pub fn writeHeader(w: *bytes.Writer, flags: u8, seq: u8, glyph_index: ?u16) Error!void {
    if (flags & flag_glyph_hit != 0 and flags & flag_glyph_index == 0) return error.BadIndex;
    try w.byte(flags);
    try w.byte(seq);
    if (flags & flag_glyph_index != 0) {
        const gi = glyph_index orelse return error.BadIndex;
        if (gi >= glyph_slots) return error.BadIndex;
        try w.u16le(gi);
    }
}

/// A BGRX image view; colours are packed B | G << 8 | R << 16.
const Img = struct {
    px: []const u8,
    stride: usize,
    w: usize,
    h: usize,

    fn init(pixels: []const u8, stride: usize, width: u16, height: u16) Error!Img {
        if (width == 0 or height == 0) return error.InvalidDimensions;
        const row_len = @as(usize, width) * 4;
        if (stride < row_len or pixels.len < (@as(usize, height) - 1) * stride + row_len) return error.InvalidDimensions;
        return .{ .px = pixels, .stride = stride, .w = width, .h = height };
    }

    inline fn at(m: Img, x: usize, y: usize) u32 {
        const p = m.px[y * m.stride + x * 4 ..][0..3];
        return @as(u32, p[0]) | @as(u32, p[1]) << 8 | @as(u32, p[2]) << 16;
    }

    fn row(m: Img, y: usize) []const u8 {
        return m.px[y * m.stride ..][0 .. m.w * 4];
    }
};

fn putBgr(w: *bytes.Writer, c: u32) Error!void {
    try w.bytes(&.{ @truncate(c), @truncate(c >> 8), @truncate(c >> 16) });
}

/// CLEARCODEC_RESIDUAL_DATA: maximal RGB runs across row ends, X ignored (3.3.8.1.1).
pub fn encodeResidual(w: *bytes.Writer, pixels: []const u8, stride: usize, width: u16, height: u16) Error!void {
    try residual(w, try Img.init(pixels, stride, width, height));
}

fn residualRuns(img: Img, sink: anytype) Error!void {
    var cur = img.at(0, 0);
    var run: u32 = 0;
    for (0..img.h) |y| {
        const r = img.row(y);
        var x: usize = 0;
        while (x < img.w) : (x += 1) {
            const p = r[x * 4 ..][0..3];
            const c = @as(u32, p[0]) | @as(u32, p[1]) << 8 | @as(u32, p[2]) << 16;
            if (c == cur) {
                run += 1;
            } else {
                try sink.run(cur, run);
                cur = c;
                run = 1;
            }
        }
    }
    try sink.run(cur, run);
}

fn residual(w: *bytes.Writer, img: Img) Error!void {
    const Sink = struct {
        w: *bytes.Writer,
        fn run(s: @This(), c: u32, n: u32) Error!void {
            try putBgr(s.w, c);
            try writeRunLength(s.w, n, false);
        }
    };
    try residualRuns(img, Sink{ .w = w });
}

fn residualSize(img: Img) usize {
    const Sink = struct {
        n: *usize,
        fn run(s: @This(), _: u32, len: u32) Error!void {
            s.n.* += 3 + runLengthLen(len);
        }
    };
    var n: usize = 0;
    residualRuns(img, Sink{ .n = &n }) catch unreachable;
    return n;
}

/// stopIndex bits (2.2.4.1.1.3.1.1): floor(log2(palette_count - 1)) + 1.
pub fn rlexIndexBits(palette_count: u8) Error!u3 {
    if (palette_count == 0) return error.BadIndex;
    if (palette_count > max_rlex_palette) return error.TooManyColors;
    const v = palette_count - 1;
    const log: u8 = if (v == 0) 0 else 7 - @clz(v);
    return @intCast(log + 1);
}

/// Colours in order of first appearance (at most 127).
const Palette = struct {
    keys: [256]u32 = @splat(0),
    vals: [256]u8 = undefined,
    colors: [max_rlex_palette]u32 = undefined,
    count: u8 = 0,
    last: u32 = 0,
    last_index: u8 = 0,

    /// Null once more than 127 colours.
    inline fn index(p: *Palette, c: u32) ?u8 {
        if (p.count > 0 and c == p.last) return p.last_index;
        const key = c | 0x0100_0000;
        var h: usize = @as(u32, @truncate((@as(u64, c) *% 0x9E3779B97F4A7C15) >> 56));
        while (true) : (h = (h + 1) & 0xFF) {
            if (p.keys[h] == key) break;
            if (p.keys[h] == 0) {
                if (p.count == max_rlex_palette) return null;
                p.keys[h] = key;
                p.vals[h] = p.count;
                p.colors[p.count] = c;
                p.count += 1;
                break;
            }
        }
        p.last = c;
        p.last_index = p.vals[h];
        return p.vals[h];
    }
};

/// Fills `idx` (w * h bytes); false above 127 colours.
fn paletteIndexes(img: Img, pal: *Palette, idx: []u8) bool {
    for (0..img.h) |y| {
        const r = img.row(y);
        const o = idx[y * img.w ..][0..img.w];
        for (o, 0..) |*d, x| {
            const p = r[x * 4 ..][0..3];
            d.* = pal.index(@as(u32, p[0]) | @as(u32, p[1]) << 8 | @as(u32, p[2]) << 16) orelse return false;
        }
    }
    return true;
}

fn rlexData(w: *bytes.Writer, pal: *const Palette, idx: []const u8) Error!void {
    try w.byte(pal.count);
    for (pal.colors[0..pal.count]) |c| try putBgr(w, c);
    const bits = try rlexIndexBits(pal.count);
    const max_depth: usize = (@as(usize, 1) << @intCast(8 - @as(u4, bits))) - 1;
    var i: usize = 0;
    while (i < idx.len) {
        const s = idx[i];
        var r: usize = 1;
        while (i + r < idx.len and idx[i + r] == s) r += 1;
        // The suite starts with the run's last pixel.
        const last = i + r - 1;
        var depth: usize = 0;
        while (depth < max_depth and last + depth + 1 < idx.len and idx[last + depth + 1] == s + depth + 1) depth += 1;
        try w.byte(@intCast((s + depth) | depth << @intCast(bits)));
        try writeRunLength(w, @intCast(r - 1), true);
        i = last + depth + 1;
    }
}

/// Palette in first-appearance order, then greedy run + suite segments, as in
/// MS-RDPEGFX 4.1.1.2. error.TooManyColors above 127 colours.
pub fn encodeRlex(w: *bytes.Writer, pixels: []const u8, stride: usize, width: u16, height: u16) Error!void {
    const img = try Img.init(pixels, stride, width, height);
    const idx = try w.gpa.alloc(u8, img.w * img.h);
    defer w.gpa.free(idx);
    var pal: Palette = .{};
    if (!paletteIndexes(img, &pal, idx)) return error.TooManyColors;
    try rlexData(w, &pal, idx);
}

/// error.SubcodecTooLarge when `data` exceeds 3 * width * height bytes.
pub fn writeSubcodec(w: *bytes.Writer, x: u16, y: u16, width: u16, height: u16, subcodec_id: u8, data: []const u8) Error!void {
    if (width == 0 or height == 0) return error.InvalidDimensions;
    if (data.len > 3 * @as(usize, width) * height) return error.SubcodecTooLarge;
    try w.u16le(x);
    try w.u16le(y);
    try w.u16le(width);
    try w.u16le(height);
    try w.u32le(@intCast(data.len));
    try w.byte(subcodec_id);
    try w.bytes(data);
}

/// vBarHeader of a VBAR_CACHE_HIT (u16 LE: index | 0x8000).
pub fn vbarCacheHit(index: u16) Error!u16 {
    if (index >= vbar_storage_size) return error.BadIndex;
    return index | 0x8000;
}

/// SHORT_VBAR_CACHE_HIT: u16 LE (index | 0x4000) then shortVBarYOn.
pub fn shortVbarCacheHit(index: u16, y_on: u8) Error![3]u8 {
    if (index >= short_vbar_storage_size) return error.BadIndex;
    if (y_on > max_band_height) return error.BandTooTall;
    const v = index | 0x4000;
    return .{ @truncate(v), @truncate(v >> 8), y_on };
}

/// SHORT_VBAR_CACHE_MISS header; error.BandTooTall when y_off > 52 or y_off < y_on.
pub fn shortVbarCacheMiss(y_on: u8, y_off: u8) Error![2]u8 {
    if (y_off > max_band_height or y_off < y_on) return error.BandTooTall;
    return .{ y_on, y_off };
}

pub const Layer = enum { residual, bands, subcodec_raw, subcodec_rlex, subcodec_nscodec };

pub const EncoderOptions = struct {
    /// Glyph caching for bitmaps of at most 1024 pixels.
    glyphs: bool = true,
    /// Lossy: ColorLossLevel 1, no chroma subsampling (MS-RDPNSC 2.2.2).
    nscodec: bool = false,
    force: ?Layer = null,
    /// 0 for a new session (2.2.4.1).
    first_seq: u8 = 0,
};

/// Mirror of the client's V-Bar or short V-Bar storage (3.3.1.10-13), with a content-hash index.
const Store = struct {
    data: []u8,
    /// `empty` for a slot the encoder knows nothing of.
    lens: []u8,
    hashes: []u64,
    map: std.AutoHashMapUnmanaged(u64, u16) = .empty,
    cursor: u16 = 0,

    const slot_bytes = @as(usize, max_band_height) * 3;
    const empty: u8 = 0xFF;

    fn create(gpa: std.mem.Allocator, slots: u16) Error!*Store {
        const s = try gpa.create(Store);
        errdefer gpa.destroy(s);
        const data = try gpa.alloc(u8, @as(usize, slots) * slot_bytes);
        errdefer gpa.free(data);
        const lens = try gpa.alloc(u8, slots);
        errdefer gpa.free(lens);
        const hashes = try gpa.alloc(u64, slots);
        @memset(lens, empty);
        s.* = .{ .data = data, .lens = lens, .hashes = hashes };
        return s;
    }

    fn destroy(s: *Store, gpa: std.mem.Allocator) void {
        s.map.deinit(gpa);
        gpa.free(s.data);
        gpa.free(s.lens);
        gpa.free(s.hashes);
        gpa.destroy(s);
    }

    fn content(s: *const Store, i: u16) []const u8 {
        return s.data[@as(usize, i) * slot_bytes ..][0 .. @as(usize, s.lens[i]) * 3];
    }

    fn find(s: *const Store, h: u64, c: []const u8) ?u16 {
        const i = s.map.get(h) orelse return null;
        if (s.lens[i] == empty or @as(usize, s.lens[i]) * 3 != c.len) return null;
        if (!std.mem.eql(u8, s.content(i), c)) return null;
        return i;
    }

    /// Stores at the cursor, as the decoder does.
    fn put(s: *Store, gpa: std.mem.Allocator, h: u64, c: []const u8) Error!void {
        const i = s.cursor;
        s.cursor = @intCast((@as(usize, i) + 1) % s.lens.len);
        if (s.lens[i] != empty) {
            if (s.map.get(s.hashes[i])) |j| if (j == i) {
                _ = s.map.remove(s.hashes[i]);
            };
        }
        @memcpy(s.data[@as(usize, i) * slot_bytes ..][0..c.len], c);
        s.lens[i] = @intCast(c.len / 3);
        s.hashes[i] = h;
        try s.map.put(gpa, h, i);
    }

    /// CACHE_RESET only moves the decoder's cursors; forgetting the contents is always safe.
    fn reset(s: *Store) void {
        s.cursor = 0;
        s.map.clearRetainingCapacity();
        @memset(s.lens, empty);
    }
};

/// Client glyph storage (3.3.1.9) with LRU replacement once all 4000 slots are used.
const Glyphs = struct {
    slots: [glyph_slots]Slot = @splat(.{}),
    map: std.AutoHashMapUnmanaged(u64, u16) = .empty,
    head: u16 = nil,
    tail: u16 = nil,
    used: u16 = 0,

    const nil: u16 = 0xFFFF;
    const Slot = struct { w: u16 = 0, h: u16 = 0, hash: u64 = 0, px: []u8 = &.{}, prev: u16 = nil, next: u16 = nil };

    fn destroy(g: *Glyphs, gpa: std.mem.Allocator) void {
        for (g.slots[0..g.used]) |s| gpa.free(s.px);
        g.map.deinit(gpa);
        gpa.destroy(g);
    }

    fn find(g: *const Glyphs, hash: u64, w: u16, h: u16, px: []const u8) ?u16 {
        const i = g.map.get(hash) orelse return null;
        const s = g.slots[i];
        if (s.w != w or s.h != h or !std.mem.eql(u8, s.px, px)) return null;
        return i;
    }

    fn victim(g: *const Glyphs) u16 {
        return if (g.used < glyph_slots) g.used else g.tail;
    }

    fn unlink(g: *Glyphs, i: u16) void {
        const s = &g.slots[i];
        if (s.prev != nil) g.slots[s.prev].next = s.next else g.head = s.next;
        if (s.next != nil) g.slots[s.next].prev = s.prev else g.tail = s.prev;
        s.prev = nil;
        s.next = nil;
    }

    fn pushFront(g: *Glyphs, i: u16) void {
        g.slots[i].next = g.head;
        g.slots[i].prev = nil;
        if (g.head != nil) g.slots[g.head].prev = i;
        g.head = i;
        if (g.tail == nil) g.tail = i;
    }

    fn touch(g: *Glyphs, i: u16) void {
        g.unlink(i);
        g.pushFront(i);
    }

    fn store(g: *Glyphs, gpa: std.mem.Allocator, i: u16, hash: u64, w: u16, h: u16, px: []const u8) Error!void {
        try g.map.ensureUnusedCapacity(gpa, 1);
        const fresh = i == g.used;
        const s = &g.slots[i];
        const buf = if (fresh) try gpa.alloc(u8, px.len) else if (s.px.len != px.len) try gpa.realloc(s.px, px.len) else s.px;
        if (!fresh) {
            if (g.map.get(s.hash)) |j| if (j == i) {
                _ = g.map.remove(s.hash);
            };
            g.unlink(i);
        } else g.used += 1;
        @memcpy(buf, px);
        s.* = .{ .w = w, .h = h, .hash = hash, .px = buf };
        g.pushFront(i);
        g.map.putAssumeCapacity(hash, i);
    }
};

/// Mirrors the client's sequence number, V-Bar storage and glyph slots.
pub const Encoder = struct {
    gpa: std.mem.Allocator,
    opts: EncoderOptions,
    seq: u8 = 0,
    reset_pending: bool = false,
    vbars: ?*Store = null,
    shorts: ?*Store = null,
    glyphs: ?*Glyphs = null,
    idx: std.ArrayList(u8) = .empty,
    sub: std.ArrayList(u8) = .empty,
    tmp: std.ArrayList(u8) = .empty,
    glyph_px: std.ArrayList(u8) = .empty,
    /// Content hashes of the V-Bars a bands estimate would add.
    est_full: std.AutoHashMapUnmanaged(u64, void) = .empty,
    est_short: std.AutoHashMapUnmanaged(u64, void) = .empty,

    pub fn init(gpa: std.mem.Allocator, opts: EncoderOptions) Error!Encoder {
        return .{ .gpa = gpa, .opts = opts, .seq = opts.first_seq };
    }

    pub fn deinit(e: *Encoder) void {
        if (e.vbars) |s| s.destroy(e.gpa);
        if (e.shorts) |s| s.destroy(e.gpa);
        if (e.glyphs) |g| g.destroy(e.gpa);
        e.idx.deinit(e.gpa);
        e.sub.deinit(e.gpa);
        e.tmp.deinit(e.gpa);
        e.glyph_px.deinit(e.gpa);
        e.est_full.deinit(e.gpa);
        e.est_short.deinit(e.gpa);
        e.* = undefined;
    }

    /// Appends a CLEARCODEC_BITMAP_STREAM; lossless unless NSCodec is enabled. Subcodec data
    /// over 3 * width * height bytes is sent raw (2.2.4.1.1.3.1), even when forced.
    pub fn encode(e: *Encoder, out: *std.ArrayList(u8), pixels: []const u8, stride: usize, width: u16, height: u16) Error!void {
        const img = try Img.init(pixels, stride, width, height);
        const start = out.items.len;
        // Nothing of a failed message reaches the client, so drop its V-Bar state.
        errdefer {
            out.shrinkRetainingCapacity(start);
            e.dropVbars();
        }
        var w = bytes.Writer.init(out, e.gpa);
        var flags: u8 = if (e.reset_pending) flag_cache_reset else 0;
        var glyph: ?struct { slot: u16, hash: u64 } = null;
        if (e.opts.glyphs and img.w * img.h <= glyph_max_area) {
            const g = try e.glyphCache();
            const hash = try e.glyphKey(img);
            if (g.find(hash, width, height, e.glyph_px.items)) |slot| {
                try writeHeader(&w, flags | flag_glyph_index | flag_glyph_hit, e.seq, slot);
                g.touch(slot);
                e.sent();
                return;
            }
            glyph = .{ .slot = g.victim(), .hash = hash };
            flags |= flag_glyph_index;
        }
        try writeHeader(&w, flags, e.seq, if (glyph) |g| g.slot else null);
        try e.payload(&w, img);
        if (glyph) |g| try e.glyphs.?.store(e.gpa, g.slot, g.hash, width, height, e.glyph_px.items);
        e.sent();
    }

    fn sent(e: *Encoder) void {
        e.seq +%= 1;
        e.reset_pending = false;
    }

    /// The next message carries CACHE_RESET and both storage cursors restart at 0.
    pub fn resetCaches(e: *Encoder) Error!void {
        e.dropVbars();
    }

    fn dropVbars(e: *Encoder) void {
        if (e.vbars) |s| s.reset();
        if (e.shorts) |s| s.reset();
        e.reset_pending = true;
    }

    pub fn nextSeq(e: *const Encoder) Error!u8 {
        return e.seq;
    }

    fn glyphCache(e: *Encoder) Error!*Glyphs {
        if (e.glyphs == null) {
            const g = try e.gpa.create(Glyphs);
            g.* = .{};
            e.glyphs = g;
        }
        return e.glyphs.?;
    }

    /// Returns the hash of the image's B, G, R bytes in `glyph_px`.
    fn glyphKey(e: *Encoder, img: Img) Error!u64 {
        e.glyph_px.clearRetainingCapacity();
        const px = try e.glyph_px.addManyAsSlice(e.gpa, img.w * img.h * 3);
        for (0..img.h) |y| {
            const r = img.row(y);
            for (0..img.w) |x| px[(y * img.w + x) * 3 ..][0..3].* = r[x * 4 ..][0..3].*;
        }
        return std.hash.Wyhash.hash(@as(u64, img.w) << 16 | img.h, px);
    }

    const Plan = enum { residual, bands, raw, rlex, nscodec };

    fn payload(e: *Encoder, w: *bytes.Writer, img: Img) Error!void {
        const counts = w.len();
        try w.zeros(composite_header_len);
        const p = try e.plan(img);
        const body = w.len();
        switch (p) {
            .residual => try residual(w, img),
            .bands => _ = try e.bands(w, img),
            .raw, .rlex, .nscodec => {},
        }
        const layer_len: u32 = @intCast(w.len() - body);
        switch (p) {
            .residual => w.patchU32le(counts, layer_len),
            .bands => w.patchU32le(counts + 4, layer_len),
            .raw, .rlex, .nscodec => {
                var id: u8 = subcodec_uncompressed;
                switch (p) {
                    .rlex => id = subcodec_rlex,
                    .nscodec => id = subcodec_nscodec,
                    else => {
                        e.sub.clearRetainingCapacity();
                        const raw = try e.sub.addManyAsSlice(e.gpa, 3 * img.w * img.h);
                        for (0..img.h) |y| {
                            const r = img.row(y);
                            for (0..img.w) |x| raw[(y * img.w + x) * 3 ..][0..3].* = r[x * 4 ..][0..3].*;
                        }
                    },
                }
                try writeSubcodec(w, 0, 0, @intCast(img.w), @intCast(img.h), id, e.sub.items);
                w.patchU32le(counts + 8, @intCast(w.len() - body));
            },
        }
    }

    /// False when the image has too many colours or the data would exceed 3 * w * h bytes.
    fn prepareRlex(e: *Encoder, img: Img) Error!bool {
        const n = img.w * img.h;
        e.idx.clearRetainingCapacity();
        const idx = try e.idx.addManyAsSlice(e.gpa, n);
        var pal: Palette = .{};
        if (!paletteIndexes(img, &pal, idx)) return false;
        e.sub.clearRetainingCapacity();
        var sw = bytes.Writer.init(&e.sub, e.gpa);
        try rlexData(&sw, &pal, idx);
        return e.sub.items.len <= 3 * n;
    }

    /// False when the data would exceed 3 * w * h bytes.
    fn prepareNsc(e: *Encoder, img: Img) Error!bool {
        // Opaque, ColorLossLevel 1, no subsampling: error within 1 per channel (MS-RDPNSC 3.1.8.2).
        const data = nsc.encode(e.gpa, img.px, img.stride, @intCast(img.w), @intCast(img.h), .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return false,
        };
        defer e.gpa.free(data);
        e.sub.clearRetainingCapacity();
        try e.sub.appendSlice(e.gpa, data);
        return e.sub.items.len <= 3 * img.w * img.h;
    }

    /// The forced layer (subcodecs falling back to raw), or the cheapest.
    fn plan(e: *Encoder, img: Img) Error!Plan {
        const n = img.w * img.h;
        if (e.opts.force) |f| return switch (f) {
            .residual => .residual,
            .bands => .bands,
            .subcodec_raw => .raw,
            .subcodec_rlex => if (try e.prepareRlex(img)) .rlex else .raw,
            .subcodec_nscodec => if (try e.prepareNsc(img)) .nscodec else .raw,
        };
        var best: Plan = .raw;
        var cost: usize = subcodec_header_len + 3 * n;
        const rc = residualSize(img);
        if (rc < cost) {
            best = .residual;
            cost = rc;
        }
        const bc = try e.bands(null, img);
        if (bc < cost) {
            best = .bands;
            cost = bc;
        }
        // RLEX / NSCodec last, so the winner's data stays in `sub`.
        var sub_cost: ?usize = null;
        if (e.opts.nscodec and try e.prepareNsc(img)) {
            sub_cost = subcodec_header_len + e.sub.items.len;
        }
        var rlex_better = false;
        std.mem.swap(std.ArrayList(u8), &e.sub, &e.tmp);
        if (try e.prepareRlex(img) and (sub_cost == null or subcodec_header_len + e.sub.items.len <= sub_cost.?)) {
            rlex_better = true;
            sub_cost = subcodec_header_len + e.sub.items.len;
        } else {
            std.mem.swap(std.ArrayList(u8), &e.sub, &e.tmp);
        }
        if (sub_cost) |sc| if (sc < cost) {
            best = if (rlex_better) .rlex else .nscodec;
            cost = sc;
        };
        return best;
    }

    /// Majority colour (Boyer-Moore vote) of a band's top and bottom rows.
    fn bandBackground(img: Img, y0: usize, bh: usize) u32 {
        var cand: u32 = img.at(0, y0);
        var votes: usize = 0;
        for ([_]usize{ y0, y0 + bh - 1 }) |y| for (0..img.w) |x| {
            const c = img.at(x, y);
            if (votes == 0) {
                cand = c;
                votes = 1;
            } else if (c == cand) votes += 1 else votes -= 1;
        };
        return cand;
    }

    fn stores(e: *Encoder) Error!void {
        if (e.vbars == null) e.vbars = try Store.create(e.gpa, vbar_storage_size);
        if (e.shorts == null) e.shorts = try Store.create(e.gpa, short_vbar_storage_size);
    }

    /// Bands of at most 52 rows, one V-Bar per column. With `w` it writes the layer and updates
    /// the storage as the decoder will; without, it only sizes it. Returns the layer size.
    fn bands(e: *Encoder, w: ?*bytes.Writer, img: Img) Error!usize {
        if (w != null) try e.stores();
        if (w == null) {
            e.est_full.clearRetainingCapacity();
            e.est_short.clearRetainingCapacity();
        }
        var size: usize = 0;
        var col: [Store.slot_bytes]u8 = undefined;
        var y0: usize = 0;
        while (y0 < img.h) : (y0 += max_band_height) {
            const bh: usize = @min(max_band_height, img.h - y0);
            const bkg = bandBackground(img, y0, bh);
            const bkg_bgr = [3]u8{ @truncate(bkg), @truncate(bkg >> 8), @truncate(bkg >> 16) };
            size += band_header_len;
            if (w) |o| {
                try o.u16le(0);
                try o.u16le(@intCast(img.w - 1));
                try o.u16le(@intCast(y0));
                try o.u16le(@intCast(y0 + bh - 1));
                try o.bytes(&bkg_bgr);
            }
            for (0..img.w) |x| {
                var y_on: usize = bh;
                var y_off: usize = 0;
                for (0..bh) |k| {
                    const p = img.px[(y0 + k) * img.stride + x * 4 ..][0..3];
                    col[k * 3 ..][0..3].* = p.*;
                    if (!std.mem.eql(u8, p, &bkg_bgr)) {
                        y_on = @min(y_on, k);
                        y_off = k + 1;
                    }
                }
                if (y_off == 0) y_on = 0;
                const vbar = col[0 .. bh * 3];
                const hf = std.hash.Wyhash.hash(0, vbar);
                const sv = col[y_on * 3 .. y_off * 3];
                const hs = std.hash.Wyhash.hash(1, sv);
                if (w) |o| {
                    const full = e.vbars.?;
                    const short = e.shorts.?;
                    if (full.find(hf, vbar)) |i| {
                        try o.u16le(try vbarCacheHit(i));
                        continue;
                    }
                    // An empty short V-Bar is cheaper as a miss (2 bytes).
                    if (if (sv.len > 0) short.find(hs, sv) else null) |i| {
                        try o.bytes(&try shortVbarCacheHit(i, @intCast(y_on)));
                    } else {
                        try o.bytes(&try shortVbarCacheMiss(@intCast(y_on), @intCast(y_off)));
                        try o.bytes(sv);
                        try short.put(e.gpa, hs, sv);
                    }
                    try full.put(e.gpa, hf, vbar);
                } else {
                    if ((if (e.vbars) |f| f.find(hf, vbar) != null else false) or e.est_full.contains(hf)) {
                        size += 2;
                        continue;
                    }
                    if (sv.len > 0 and ((if (e.shorts) |f| f.find(hs, sv) != null else false) or e.est_short.contains(hs))) {
                        size += 3;
                    } else {
                        size += 2 + sv.len;
                        try e.est_short.put(e.gpa, hs, {});
                    }
                    try e.est_full.put(e.gpa, hf, {});
                }
            }
        }
        return size;
    }
};
