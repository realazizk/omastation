//! ZGFX: RDP 8.0 Bulk Compression (MS-RDPEGFX 3.1.9.1) and RDP_SEGMENTED_DATA (2.2.5.1).
//! The client keeps a 2.5 MB history for the channel's lifetime: use one `Compressor` per
//! RDPGFX channel, deliver every message it produces in order, and `reset()` on reopen.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

pub const segmented_single: u8 = 0xE0;
pub const segmented_multipart: u8 = 0xE1;
pub const packet_compr_type_rdp8: u8 = 0x04;
/// RDP8 Lite, for compressed DVC data (MS-RDPEDYC 2.2.3.3).
pub const packet_compr_type_rdp8_lite: u8 = 0x06;
pub const lite_history_size: usize = 8192;
pub const packet_compressed: u8 = 0x20;

/// Maximum number of uncompressed bytes in one segment (3.1.9.1.2).
pub const max_segment_bytes: usize = 65535;
pub const max_segments: usize = 65535;
/// Size of the client's history ring = maximum match distance (3.1.9.1.2).
pub const history_size: usize = 2_500_000;
/// One short of the spec limit, so a client ring of exactly `history_size` never
/// reads the slot it is about to overwrite.
pub const max_distance: usize = history_size - 1;

const max_unencoded_run: usize = 0x7FFF; // 15-bit count

// --- Token tables (3.1.9.1.2.4) ----------------------------------------------

const ShortLiteral = struct { byte: u8, code: u16, len: u5 };

/// Literals with codes shorter than the generic "0" + 8 bits.
const short_literals = [_]ShortLiteral{
    .{ .byte = 0x00, .code = 0b11000, .len = 5 },
    .{ .byte = 0x01, .code = 0b11001, .len = 5 },
    .{ .byte = 0x02, .code = 0b110100, .len = 6 },
    .{ .byte = 0x03, .code = 0b110101, .len = 6 },
    .{ .byte = 0xFF, .code = 0b110110, .len = 6 },
    .{ .byte = 0x04, .code = 0b1101110, .len = 7 },
    .{ .byte = 0x05, .code = 0b1101111, .len = 7 },
    .{ .byte = 0x06, .code = 0b1110000, .len = 7 },
    .{ .byte = 0x07, .code = 0b1110001, .len = 7 },
    .{ .byte = 0x08, .code = 0b1110010, .len = 7 },
    .{ .byte = 0x09, .code = 0b1110011, .len = 7 },
    .{ .byte = 0x0A, .code = 0b1110100, .len = 7 },
    .{ .byte = 0x0B, .code = 0b1110101, .len = 7 },
    .{ .byte = 0x3A, .code = 0b1110110, .len = 7 },
    .{ .byte = 0x3B, .code = 0b1110111, .len = 7 },
    .{ .byte = 0x3C, .code = 0b1111000, .len = 7 },
    .{ .byte = 0x3D, .code = 0b1111001, .len = 7 },
    .{ .byte = 0x3E, .code = 0b1111010, .len = 7 },
    .{ .byte = 0x3F, .code = 0b1111011, .len = 7 },
    .{ .byte = 0x40, .code = 0b1111100, .len = 7 },
    .{ .byte = 0x80, .code = 0b1111101, .len = 7 },
    .{ .byte = 0x0C, .code = 0b11111100, .len = 8 },
    .{ .byte = 0x38, .code = 0b11111101, .len = 8 },
    .{ .byte = 0x39, .code = 0b11111110, .len = 8 },
    .{ .byte = 0x66, .code = 0b11111111, .len = 8 },
};

const DistanceBucket = struct { prefix: u16, plen: u5, vbits: u5, base: u32 };

/// Match-distance tokens. The last three (beyond 4.5 MB) are decoded only to stay
/// in sync; they always exceed the history and are rejected.
const distance_buckets = [_]DistanceBucket{
    .{ .prefix = 0b10001, .plen = 5, .vbits = 5, .base = 0 },
    .{ .prefix = 0b10010, .plen = 5, .vbits = 7, .base = 32 },
    .{ .prefix = 0b10011, .plen = 5, .vbits = 9, .base = 160 },
    .{ .prefix = 0b10100, .plen = 5, .vbits = 10, .base = 672 },
    .{ .prefix = 0b10101, .plen = 5, .vbits = 12, .base = 1696 },
    .{ .prefix = 0b101100, .plen = 6, .vbits = 14, .base = 5792 },
    .{ .prefix = 0b101101, .plen = 6, .vbits = 15, .base = 22176 },
    .{ .prefix = 0b1011100, .plen = 7, .vbits = 18, .base = 54944 },
    .{ .prefix = 0b1011101, .plen = 7, .vbits = 20, .base = 317088 },
    .{ .prefix = 0b10111100, .plen = 8, .vbits = 20, .base = 1365664 },
    .{ .prefix = 0b10111101, .plen = 8, .vbits = 21, .base = 2414240 },
    .{ .prefix = 0b101111100, .plen = 9, .vbits = 22, .base = 4511392 },
    .{ .prefix = 0b101111101, .plen = 9, .vbits = 23, .base = 8705696 },
    .{ .prefix = 0b101111110, .plen = 9, .vbits = 24, .base = 17094304 },
};

/// Encoder: code and bit length of every literal byte.
const literal_code: [256]u16 = blk: {
    var t: [256]u16 = undefined;
    for (0..256) |b| t[b] = b; // "0" prefix + 8 bits = the byte itself in 9 bits
    for (short_literals) |s| t[s.byte] = s.code;
    break :blk t;
};
const literal_len: [256]u8 = blk: {
    var t: [256]u8 = @splat(9);
    for (short_literals) |s| t[s.byte] = s.len;
    break :blk t;
};

/// Decoder: every prefix is at most 9 bits, so the next 9 bits index a table.
const DecodeEntry = struct {
    kind: enum(u8) { invalid, literal8, literal, match } = .invalid,
    plen: u8 = 0,
    vbits: u8 = 0,
    base: u32 = 0,
};
const decode_table: [512]DecodeEntry = blk: {
    var t: [512]DecodeEntry = @splat(.{});
    for (0..256) |i| t[i] = .{ .kind = .literal8, .plen = 1, .vbits = 8 };
    for (short_literals) |s| {
        const free = 9 - s.len;
        for (0..1 << free) |j| {
            const idx = (@as(usize, s.code) << free) | j;
            if (t[idx].kind != .invalid) @compileError("overlapping ZGFX prefixes");
            t[idx] = .{ .kind = .literal, .plen = s.len, .base = s.byte };
        }
    }
    for (distance_buckets) |d| {
        const free = 9 - d.plen;
        for (0..1 << free) |j| {
            const idx = (@as(usize, d.prefix) << free) | j;
            if (t[idx].kind != .invalid) @compileError("overlapping ZGFX prefixes");
            t[idx] = .{ .kind = .match, .plen = d.plen, .vbits = d.vbits, .base = d.base };
        }
    }
    break :blk t;
};

/// Bases of the first 11 buckets (the 9-bit ones lie beyond the history).
const bucket_bases: @Vector(16, u32) = blk: {
    var v: [16]u32 = @splat(std.math.maxInt(u32));
    for (distance_buckets[1..11], 0..) |b, k| v[k] = b.base;
    break :blk v;
};

/// Number of bucket bases <= d, for d in 1..max_distance.
inline fn distanceBucket(d: usize) DistanceBucket {
    std.debug.assert(d >= 1 and d <= max_distance);
    const le: u16 = @bitCast(bucket_bases <= @as(@Vector(16, u32), @splat(@intCast(d))));
    return distance_buckets[@popCount(le)];
}

fn distanceBits(d: usize) u32 {
    const b = distanceBucket(d);
    return @as(u32, b.plen) + b.vbits;
}

/// Match length code: "0" for 3, else (k-1) ones, a zero and k value bits
/// for lengths in [2^k, 2^(k+1)).
fn lengthBits(len: usize) u32 {
    if (len == 3) return 1;
    const k: u32 = std.math.log2_int(usize, len);
    return 2 * k;
}

const BitWriter = struct {
    buf: []u8,
    pos: usize = 0, // whole bytes written to buf
    acc: u64 = 0,
    n: u32 = 0, // pending bits in the low end of acc (< 32 between calls)

    /// Append the low `len` bits of `code`, most significant first.
    inline fn put(w: *BitWriter, code: u32, len: u32) void {
        std.debug.assert(len <= 32);
        w.acc = (w.acc << @intCast(len)) | code;
        w.n += len;
        if (w.n >= 32) {
            w.n -= 32;
            std.mem.writeInt(u32, w.buf[w.pos..][0..4], @truncate(w.acc >> @intCast(w.n)), .big);
            w.pos += 4;
        }
    }

    fn bitPos(w: *const BitWriter) usize {
        return w.pos * 8 + w.n;
    }

    fn flushToByte(w: *BitWriter) void {
        const pad = (8 - w.n % 8) % 8;
        w.put(0, pad);
        while (w.n >= 8) {
            w.n -= 8;
            w.buf[w.pos] = @truncate(w.acc >> @intCast(w.n));
            w.pos += 1;
        }
    }

    fn raw(w: *BitWriter, data: []const u8) void {
        std.debug.assert(w.n == 0);
        @memcpy(w.buf[w.pos..][0..data.len], data);
        w.pos += data.len;
    }

    /// Pads and appends the trailer byte (unused bits in the last byte). Returns the data length.
    fn finish(w: *BitWriter) usize {
        const unused: u8 = @intCast((8 - w.n % 8) % 8);
        w.flushToByte();
        w.buf[w.pos] = unused;
        w.pos += 1;
        return w.pos;
    }
};

/// Match finder: rows of one 64-byte cache line, each a ring of the 8 newest
/// (4-byte value, position) pairs that hash to it. A lookup is one SIMD compare.
const row_bits = 15;
const row_count = 1 << row_bits;
const row_ways = 8;
const Row = [row_ways]u64;
/// Linear history window; slides down to the last `max_distance` bytes when full.
const window_capacity: usize = 8 << 20;
const nil: u32 = std.math.maxInt(u32);
/// Row entry: value << 32 | position; empty entries have position nil.
const empty: u64 = nil;
/// No token costs more than 9 bits per input byte; plus padding and trailer.
const scratch_capacity: usize = max_segment_bytes * 9 / 8 + 64;

pub const Options = struct {
    /// 4-byte match candidates (newest first, at most 8) extended per position.
    max_chain: u32 = 4,
    nice_len: u32 = 96,
    /// Longer matches index only `insert_edge` positions at each end.
    insert_all_len: u32 = 16,
    insert_edge: u32 = 4,
    /// The scan step grows by one after 2^skip_shift positions without a match.
    skip_shift: u5 = 7,
    /// A segment saving less than this many sixteenths of its bytes `bail_after` bytes in goes raw
    /// at once: weakly compressible data (planar bitmaps of noisy pictures) costs the matcher as
    /// much as text that shrinks 10x. 0 never gives up (slow links, where every byte counts).
    bail_gain_x16: u8 = 2,
    bail_after: usize = 8 * 1024,
};

pub const Stats = struct {
    input: u64 = 0,
    /// Includes the RDP_SEGMENTED_DATA framing.
    output: u64 = 0,
    compressed_segments: u64 = 0,
    raw_segments: u64 = 0,
    /// Unencoded-run tokens inside compressed segments.
    unencoded_runs: u64 = 0,
};

pub const Compressor = struct {
    gpa: std.mem.Allocator,
    opts: Options,
    window: []u8,
    /// The end of the window is the newest byte the client has decoded.
    len: usize = 0,
    rows: []align(@sizeOf(Row)) Row,
    /// Slot of the newest entry in each row (newest first, decreasing slot order).
    newest: []u8,
    scratch: []u8,
    stats: Stats = .{},
    seg_unencoded: u64 = 0,

    pub fn init(gpa: std.mem.Allocator) !Compressor {
        return initOptions(gpa, .{});
    }

    pub fn initOptions(gpa: std.mem.Allocator, opts: Options) !Compressor {
        const window = try gpa.alloc(u8, window_capacity);
        errdefer gpa.free(window);
        const rows = try gpa.alignedAlloc(Row, .fromByteUnits(@sizeOf(Row)), row_count);
        errdefer gpa.free(rows);
        const newest = try gpa.alloc(u8, row_count);
        errdefer gpa.free(newest);
        const scratch = try gpa.alloc(u8, scratch_capacity);
        @memset(rows, @splat(empty));
        @memset(newest, 0);
        return .{ .gpa = gpa, .opts = opts, .window = window, .rows = rows, .newest = newest, .scratch = scratch };
    }

    pub fn deinit(self: *Compressor) void {
        self.gpa.free(self.window);
        self.gpa.free(self.rows);
        self.gpa.free(self.newest);
        self.gpa.free(self.scratch);
        self.* = undefined;
    }

    /// For a client that starts a new history (a reopened RDPGFX channel).
    pub fn reset(self: *Compressor) void {
        self.len = 0;
        @memset(self.rows, @splat(empty));
        @memset(self.newest, 0);
        self.stats = .{};
    }

    /// Drop-in for `gfx.writeSegmented` with RDP8-compressed segments.
    pub fn writeSegmented(self: *Compressor, w: *bytes.Writer, msg: []const u8) !void {
        const start = w.len();
        defer self.stats.output += w.len() - start;
        self.stats.input += msg.len;
        if (msg.len <= max_segment_bytes) {
            try w.list.ensureUnusedCapacity(w.gpa, msg.len + 2);
            try w.byte(segmented_single);
            try self.writeSegment(w, msg);
            return;
        }
        const count = (msg.len + max_segment_bytes - 1) / max_segment_bytes;
        if (count > max_segments or msg.len > std.math.maxInt(u32)) return error.MessageTooLarge;
        try w.list.ensureUnusedCapacity(w.gpa, msg.len + 7 + 5 * count);
        try w.byte(segmented_multipart);
        try w.u16le(@intCast(count));
        try w.u32le(@intCast(msg.len));
        var off: usize = 0;
        while (off < msg.len) {
            const n = @min(max_segment_bytes, msg.len - off);
            const size_at = w.len();
            try w.u32le(0);
            try self.writeSegment(w, msg[off..][0..n]);
            w.patchU32le(size_at, @intCast(w.len() - size_at - 4));
            off += n;
        }
    }

    /// One RDP8_BULK_ENCODED_DATA: compressed if that is smaller, else raw.
    fn writeSegment(self: *Compressor, w: *bytes.Writer, chunk: []const u8) !void {
        std.debug.assert(chunk.len <= max_segment_bytes);
        if (chunk.len == 0) {
            // Some decoders reject segments shorter than 2 bytes.
            try w.bytes(&.{ packet_compr_type_rdp8 | packet_compressed, 0 });
            self.stats.compressed_segments += 1;
            return;
        }
        const start = self.append(chunk);
        if (self.compress(start, start + chunk.len)) |n| {
            try w.byte(packet_compr_type_rdp8 | packet_compressed);
            try w.bytes(self.scratch[0..n]);
            self.stats.compressed_segments += 1;
            self.stats.unencoded_runs += self.seg_unencoded;
        } else {
            try w.byte(packet_compr_type_rdp8);
            try w.bytes(chunk);
            self.stats.raw_segments += 1;
        }
    }

    /// Returns the window offset of the chunk.
    fn append(self: *Compressor, chunk: []const u8) usize {
        if (self.len + chunk.len > self.window.len) self.slide();
        const at = self.len;
        @memcpy(self.window[at..][0..chunk.len], chunk);
        self.len += chunk.len;
        return at;
    }

    fn slide(self: *Compressor) void {
        const delta = self.len - max_distance;
        @memmove(self.window[0..max_distance], self.window[delta..self.len]);
        self.len = max_distance;
        for (self.rows) |*r| for (r) |*e| {
            e.* = rebase(e.*, delta);
        };
    }

    fn rebase(e: u64, delta: usize) u64 {
        const p: u32 = @truncate(e);
        return if (p != nil and p >= delta) e - delta else empty;
    }

    inline fn read32(self: *const Compressor, p: usize) u32 {
        return std.mem.readInt(u32, self.window[p..][0..4], .little);
    }

    inline fn rowIndex(v: u32) usize {
        return (v *% 0x9E3779B1) >> (32 - row_bits);
    }

    inline fn push(self: *Compressor, h: usize, e: u64) void {
        const slot = (self.newest[h] -% 1) & (row_ways - 1);
        self.newest[h] = slot;
        self.rows[h][slot] = e;
    }

    inline fn insert(self: *Compressor, p: usize) void {
        const v = self.read32(p);
        self.push(rowIndex(v), @as(u64, v) << 32 | p);
    }

    /// Common prefix of window[a..] and window[b..] (a < b), at most `max`; `known` bytes already match.
    inline fn matchLen(self: *const Compressor, a: usize, b: usize, known: usize, max: usize) usize {
        const win = self.window;
        var n = known;
        while (n + 8 <= max) {
            const x = std.mem.readInt(u64, win[a + n ..][0..8], .little) ^
                std.mem.readInt(u64, win[b + n ..][0..8], .little);
            if (x != 0) return n + @ctz(x) / 8;
            n += 8;
        }
        while (n < max and win[a + n] == win[b + n]) n += 1;
        return n;
    }

    /// Encodes window[start..end] into scratch. Returns the encoded length, or null
    /// when that would not be smaller than the raw chunk.
    fn compress(self: *Compressor, start: usize, end: usize) ?usize {
        const win = self.window;
        const raw_len = end - start;
        var bw: BitWriter = .{ .buf = self.scratch };
        self.seg_unencoded = 0;
        var i = start;
        var lit = start;
        var misses: usize = 0;
        var checked = self.opts.bail_gain_x16 == 0;
        while (i + 4 <= end) {
            if (!checked and i - start >= self.opts.bail_after) {
                checked = true;
                if (!self.gaining(&bw, lit, i, start)) return null;
            }
            const cur = self.read32(i);
            const h = rowIndex(cur);
            if (i + 5 <= end) @prefetch(&self.rows[rowIndex(self.read32(i + 1))], .{});
            const cands: Row = self.rows[h];
            const first = self.newest[h];
            self.push(h, @as(u64, cur) << 32 | i);

            // Empty entries have value 0, so mask them out by position.
            const vec: @Vector(row_ways, u64) = cands;
            const vals: @Vector(row_ways, u32) = @truncate(vec >> @splat(32));
            const poss: @Vector(row_ways, u32) = @truncate(vec);
            const Mask = @Int(.unsigned, row_ways);
            const raw_hits: Mask = @bitCast((vals == @as(@Vector(row_ways, u32), @splat(cur))) &
                (poss != @as(@Vector(row_ways, u32), @splat(nil))));
            var hits = std.math.rotr(Mask, raw_hits, first);

            const max_len = end - i;
            var best_len: usize = 0;
            var best_dist: usize = 0;
            var depth = self.opts.max_chain;
            while (hits != 0 and depth != 0) : (depth -= 1) {
                const k = @ctz(hits);
                hits &= hits - 1;
                const c: usize = @as(u32, @truncate(cands[(first + k) & (row_ways - 1)]));
                const dist = i - c;
                if (dist > max_distance) break; // newest first: the rest are older
                if (win[c + best_len] == win[i + best_len]) {
                    const l = self.matchLen(c, i, 4, max_len);
                    if (l > best_len) {
                        best_len = l;
                        best_dist = dist;
                        if (l >= self.opts.nice_len or l == max_len) break;
                    }
                }
            }

            if (best_len != 0 and self.worthMatch(i, best_len, best_dist)) {
                self.flushLiterals(&bw, lit, i);
                const b = distanceBucket(best_dist);
                bw.put((@as(u32, b.prefix) << b.vbits) | @as(u32, @intCast(best_dist - b.base)), @as(u32, b.plen) + b.vbits);
                putLength(&bw, best_len);
                if (bw.pos + 1 >= raw_len) return null;

                // Index every position of short matches but only the edges of long ones.
                const mend = i + best_len;
                const ins_end = @min(mend, end - 3);
                var p = i + 1;
                if (best_len > self.opts.insert_all_len) {
                    while (p < @min(i + 1 + self.opts.insert_edge, ins_end)) : (p += 1) self.insert(p);
                    p = @max(p, mend -| self.opts.insert_edge);
                }
                while (p < ins_end) : (p += 1) self.insert(p);
                i = mend;
                lit = i;
                misses = 0;
            } else {
                misses += 1;
                i += 1 + (misses >> self.opts.skip_shift);
            }
        }
        self.flushLiterals(&bw, lit, end);
        if (bw.pos + 1 >= raw_len) return null;
        const n = bw.finish();
        return if (n < raw_len) n else null;
    }

    /// Whether the output so far (with the literals pending since `lit`) saves at least
    /// `bail_gain_x16` sixteenths of the input coded so far.
    fn gaining(self: *const Compressor, bw: *const BitWriter, lit: usize, i: usize, start: usize) bool {
        var bits: usize = bw.bitPos();
        for (self.window[lit..i]) |b| bits += literal_len[b];
        const in_bits = (i - start) * 8;
        return bits * 16 <= in_bits * (16 - @as(usize, self.opts.bail_gain_x16));
    }

    inline fn worthMatch(self: *const Compressor, i: usize, len: usize, dist: usize) bool {
        if (len >= 8) return true; // <= 35 bits vs >= 40 for 8 literals
        var lit_bits: u32 = 0;
        for (self.window[i..][0..len]) |b| lit_bits += literal_len[b];
        return distanceBits(dist) + lengthBits(len) < lit_bits;
    }

    inline fn flushLiterals(self: *Compressor, bw: *BitWriter, start: usize, end: usize) void {
        const data = self.window[start..end];
        if (data.len >= 32 and self.flushLong(bw, data)) return;
        for (data) |b| bw.put(literal_code[b], literal_len[b]);
    }

    /// Codes a long literal stretch as unencoded runs if cheaper. Returns whether it did.
    fn flushLong(self: *Compressor, bw: *BitWriter, data: []const u8) bool {
        var lit_bits: usize = 0;
        for (data) |b| lit_bits += literal_len[b];
        // Distance-0 token (10 bits) + 15-bit count, byte padding, then the bytes.
        const tokens = (data.len + max_unencoded_run - 1) / max_unencoded_run;
        const first_pad = (8 - (bw.bitPos() + 25) % 8) % 8;
        const raw_bits = tokens * 25 + first_pad + (tokens - 1) * 7 + data.len * 8;
        if (raw_bits >= lit_bits) return false;
        var rest = data;
        while (rest.len > 0) {
            const n = @min(rest.len, max_unencoded_run);
            bw.put(0b10001_00000, 10);
            bw.put(@intCast(n), 15);
            bw.flushToByte();
            bw.raw(rest[0..n]);
            rest = rest[n..];
            self.seg_unencoded += 1;
        }
        return true;
    }

    inline fn putLength(bw: *BitWriter, len: usize) void {
        if (len == 3) {
            bw.put(0, 1);
            return;
        }
        const k: u5 = @intCast(std.math.log2_int(usize, len));
        const prefix: u32 = ((@as(u32, 1) << (k - 1)) - 1) << 1; // (k-1) ones then 0
        bw.put((prefix << k) | @as(u32, @intCast(len - (@as(usize, 1) << k))), 2 * @as(u32, k));
    }
};

pub const Error = error{BadZgfx} || std.mem.Allocator.Error;

const BitReader = struct {
    data: []const u8,
    nbits: usize,
    pos: usize = 0,

    /// Next `k` (1..32) bits without consuming them; zero-filled past the end.
    fn peek(r: *const BitReader, k: u6) u32 {
        const at = r.pos >> 3;
        var v: u64 = 0;
        if (at + 8 <= r.data.len) {
            v = std.mem.readInt(u64, r.data[at..][0..8], .big);
        } else {
            for (0..8) |j| v = (v << 8) | (if (at + j < r.data.len) r.data[at + j] else 0);
        }
        return @truncate((v << @intCast(r.pos & 7)) >> @intCast(64 - @as(u32, k)));
    }

    fn take(r: *BitReader, k: u6) error{BadZgfx}!u32 {
        if (k == 0) return 0;
        if (r.pos + k > r.nbits) return error.BadZgfx;
        const v = r.peek(k);
        r.pos += k;
        return v;
    }
};

/// Reference decoder and the RDP8 Lite decoder of compressed DVC data.
/// Any malformed input yields error.BadZgfx and leaves the history unusable.
pub const Decompressor = struct {
    history: []u8,
    idx: usize = 0,
    /// Total bytes ever decoded (caps the valid match distance).
    total: u64 = 0,
    /// Its length is the largest segment accepted.
    segment: []u8,
    compr_type: u8 = packet_compr_type_rdp8,

    pub fn init(gpa: std.mem.Allocator) !Decompressor {
        return initSized(gpa, history_size, max_segment_bytes, packet_compr_type_rdp8);
    }

    /// RDP8 Lite (MS-RDPEDYC 2.2.3.3): 8,192-byte segments and history.
    pub fn initLite(gpa: std.mem.Allocator) !Decompressor {
        return initSized(gpa, lite_history_size, lite_history_size, packet_compr_type_rdp8_lite);
    }

    fn initSized(gpa: std.mem.Allocator, history_len: usize, segment_len: usize, compr_type: u8) !Decompressor {
        const history = try gpa.alloc(u8, history_len);
        errdefer gpa.free(history);
        const segment = try gpa.alloc(u8, segment_len);
        @memset(history, 0);
        return .{ .history = history, .segment = segment, .compr_type = compr_type };
    }

    pub fn deinit(self: *Decompressor, gpa: std.mem.Allocator) void {
        gpa.free(self.history);
        gpa.free(self.segment);
        self.* = undefined;
    }

    /// Decode one RDP_SEGMENTED_DATA and append the message to `out`.
    pub fn decompress(self: *Decompressor, gpa: std.mem.Allocator, out: *std.ArrayList(u8), pdu: []const u8) Error!void {
        var r = bytes.Reader.init(pdu);
        const descriptor = r.byte() catch return error.BadZgfx;
        switch (descriptor) {
            segmented_single => {
                const n = try self.decodeSegment(r.rest());
                try out.appendSlice(gpa, self.segment[0..n]);
            },
            segmented_multipart => {
                const count = r.u16le() catch return error.BadZgfx;
                const size = r.u32le() catch return error.BadZgfx;
                if (size > @as(usize, count) * self.segment.len) return error.BadZgfx;
                const start = out.items.len;
                // `size` is untrusted: don't let a tiny PDU reserve gigabytes.
                try out.ensureUnusedCapacity(gpa, @min(size, pdu.len * 64 + self.segment.len));
                for (0..count) |_| {
                    const seg_len = r.u32le() catch return error.BadZgfx;
                    const seg = r.bytes(seg_len) catch return error.BadZgfx;
                    const n = try self.decodeSegment(seg);
                    if (out.items.len - start + n > size) return error.BadZgfx;
                    try out.appendSlice(gpa, self.segment[0..n]);
                }
                if (out.items.len - start != size or r.remaining() != 0) return error.BadZgfx;
            },
            else => return error.BadZgfx,
        }
    }

    inline fn emit(self: *Decompressor, n: *usize, b: u8) void {
        self.segment[n.*] = b;
        n.* += 1;
        self.history[self.idx] = b;
        self.idx += 1;
        if (self.idx == self.history.len) self.idx = 0;
    }

    /// Returns the segment length.
    fn decodeSegment(self: *Decompressor, seg: []const u8) error{BadZgfx}!usize {
        if (seg.len == 0) return error.BadZgfx;
        const header = seg[0];
        if (header & 0x0F != self.compr_type) return error.BadZgfx;
        const max_segment = self.segment.len;
        const history_len = self.history.len;
        const data = seg[1..];
        var n: usize = 0;
        defer self.total += n;
        if (header & packet_compressed == 0) {
            if (data.len > max_segment) return error.BadZgfx;
            for (data) |b| self.emit(&n, b);
            return n;
        }
        if (data.len == 0) return error.BadZgfx;
        const unused = data[data.len - 1];
        if (unused > 7 or (data.len == 1 and unused != 0)) return error.BadZgfx;
        var br: BitReader = .{ .data = data[0 .. data.len - 1], .nbits = (data.len - 1) * 8 - unused };
        while (br.pos < br.nbits) {
            const t = decode_table[br.peek(9)];
            switch (t.kind) {
                .invalid => return error.BadZgfx,
                .literal8, .literal => {
                    _ = try br.take(@intCast(t.plen));
                    const b: u8 = if (t.kind == .literal8) @intCast(try br.take(8)) else @intCast(t.base);
                    if (n == max_segment) return error.BadZgfx;
                    self.emit(&n, b);
                },
                .match => {
                    _ = try br.take(@intCast(t.plen));
                    const dist: usize = t.base + try br.take(@intCast(t.vbits));
                    if (dist == 0) {
                        const count = try br.take(15);
                        br.pos = std.mem.alignForward(usize, br.pos, 8);
                        if (br.pos > br.nbits or count > (br.nbits - br.pos) / 8) return error.BadZgfx;
                        if (count > max_segment - n) return error.BadZgfx;
                        for (br.data[br.pos / 8 ..][0..count]) |b| self.emit(&n, b);
                        br.pos += 8 * @as(usize, count);
                        continue;
                    }
                    var len: usize = 3;
                    if (try br.take(1) == 1) {
                        var k: u6 = 2;
                        while (try br.take(1) == 1) {
                            k += 1;
                            if (k > 15) return error.BadZgfx;
                        }
                        len = (@as(usize, 1) << k) + try br.take(k);
                    }
                    if (dist > history_len or dist > self.total + n) return error.BadZgfx;
                    if (len > max_segment - n) return error.BadZgfx;
                    var src = (self.idx + history_len - dist) % history_len;
                    for (0..len) |_| {
                        self.emit(&n, self.history[src]);
                        src += 1;
                        if (src == history_len) src = 0;
                    }
                },
            }
        }
        return n;
    }
};

const testing = std.testing;

fn roundTrip(c: *Compressor, d: *Decompressor, msg: []const u8) !usize {
    const gpa = testing.allocator;
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    var w = bytes.Writer.init(&wire, gpa);
    try c.writeSegmented(&w, msg);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try d.decompress(gpa, &out, wire.items);
    try testing.expectEqualSlices(u8, msg, out.items);
    return wire.items.len;
}

fn decodeAll(pdu: []const u8) ![]u8 {
    const gpa = testing.allocator;
    var d = try Decompressor.init(gpa);
    defer d.deinit(gpa);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try d.decompress(gpa, &out, pdu);
    return out.toOwnedSlice(gpa);
}

fn compressOne(msg: []const u8) ![]u8 {
    const gpa = testing.allocator;
    var c = try Compressor.init(gpa);
    defer c.deinit();
    var wire: std.ArrayList(u8) = .empty;
    errdefer wire.deinit(gpa);
    var w = bytes.Writer.init(&wire, gpa);
    try c.writeSegmented(&w, msg);
    return wire.toOwnedSlice(gpa);
}

test "spec 4.2.1.1.1 example 1: decode and encode" {
    const pdu = bytes.hex("E0 24 CE 9B 19 62 18 00");
    const msg = bytes.hex("01 02 FF 65 65 65 65 65");
    const got = try decodeAll(&pdu);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &msg, got);
    // Greedy matching finds the same literal/match split as the spec.
    const enc = try compressOne(&msg);
    defer testing.allocator.free(enc);
    try testing.expectEqualSlices(u8, &pdu, enc);
}

test "spec 4.2.1.1.2 example 2: incompressible input stays raw" {
    const text = "The quick brown fox jumps over the lazy dog";
    const enc = try compressOne(text);
    defer testing.allocator.free(enc);
    try testing.expectEqualSlices(u8, &bytes.hex("E0 04"), enc[0..2]);
    try testing.expectEqualSlices(u8, text, enc[2..]);
    const got = try decodeAll(enc);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, text, got);
}

test "spec 4.2.1.1.3 example 3: overlapping match, decode and encode" {
    const pdu = bytes.hex("E0 24 20 90 88 71 1F B2 01");
    const abc: [60]u8 = comptime blk: {
        var a: [60]u8 = undefined;
        for (0..20) |i| @memcpy(a[i * 3 ..][0..3], "ABC");
        break :blk a;
    };
    const msg: []const u8 = &abc;
    const got = try decodeAll(&pdu);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, msg, got);
    const enc = try compressOne(msg);
    defer testing.allocator.free(enc);
    try testing.expectEqualSlices(u8, &pdu, enc);
}

test "spec 4.2.1.1.4 example 4: multipart with raw and compressed segments" {
    const pdu = bytes.hex(
        \\E1 03 00 2B 00 00 00 11 00 00 00 04 54 68 65 20
        \\71 75 69 63 6B 20 62 72 6F 77 6E 20 0E 00 00 00
        \\04 66 6F 78 20 6A 75 6D 70 73 20 6F 76 65 10 00
        \\00 00 24 39 08 0E 91 F8 D8 61 3D 1E 44 06 43 79
        \\9C 02
    );
    const got = try decodeAll(&pdu);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, "The quick brown fox jumps over the lazy dog", got);
}

test "spec 4.2.1.1.5 example 5: unencoded run" {
    var msg: [1002]u8 = undefined;
    const head = "The quick brown fox jumps over the lazy dog";
    @memcpy(msg[0..head.len], head);
    var prng = std.Random.DefaultPrng.init(5);
    prng.random().bytes(msg[head.len..]);
    // 10001 00000 (distance 0) + 15-bit count. The spec's header says 1000 bytes
    // although its text says 1,002; the documented header is used verbatim.
    var pdu: [6 + 1000 + 1]u8 = undefined;
    @memcpy(pdu[0..6], &bytes.hex("E0 24 88 01 F4 00"));
    @memcpy(pdu[6..][0..1000], msg[0..1000]);
    pdu[pdu.len - 1] = 0;
    const got = try decodeAll(&pdu);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, msg[0..1000], got);
}

test "round trips: sizes around segment boundaries and history reuse" {
    const gpa = testing.allocator;
    var c = try Compressor.init(gpa);
    defer c.deinit();
    var d = try Decompressor.init(gpa);
    defer d.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(1);
    const rnd = prng.random();
    const sizes = [_]usize{ 0, 1, 2, 3, 4, 5, 31, 32, 33, 65534, 65535, 65536, 65537, 131070, 131071, 200_000 };
    for (sizes) |n| {
        const buf = try gpa.alloc(u8, n);
        defer gpa.free(buf);
        var i: usize = 0;
        while (i < n) {
            const kind = rnd.uintLessThan(u8, 4);
            const l = @min(n - i, rnd.uintLessThan(usize, 300) + 1);
            switch (kind) {
                0 => @memset(buf[i..][0..l], rnd.int(u8)),
                1 => rnd.bytes(buf[i..][0..l]),
                else => if (i > 0) {
                    const src = rnd.uintLessThan(usize, i);
                    for (0..l) |k| buf[i + k] = buf[src + k];
                } else rnd.bytes(buf[i..][0..l]),
            }
            i += l;
        }
        _ = try roundTrip(&c, &d, buf);
    }
    // Resending a message is almost free thanks to the shared history.
    const msg = try gpa.alloc(u8, 50_000);
    defer gpa.free(msg);
    rnd.bytes(msg);
    const first = try roundTrip(&c, &d, msg);
    const second = try roundTrip(&c, &d, msg);
    try testing.expect(first >= msg.len);
    try testing.expect(second < 64);
}

test "round trip across window slides keeps client and server history in sync" {
    const gpa = testing.allocator;
    var c = try Compressor.init(gpa);
    defer c.deinit();
    var d = try Decompressor.init(gpa);
    defer d.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(2);
    const rnd = prng.random();
    // ~20 MB of re-sent blocks: matches land at every distance up to max_distance.
    const pool = try gpa.alloc(u8, 3 << 20);
    defer gpa.free(pool);
    rnd.bytes(pool);
    var total: usize = 0;
    var wire_total: usize = 0;
    while (total < 20 << 20) {
        const n = rnd.uintLessThan(usize, 150_000) + 1;
        const off = rnd.uintLessThan(usize, pool.len - n);
        wire_total += try roundTrip(&c, &d, pool[off..][0..n]);
        total += n;
    }
    try testing.expect(wire_total < total);
}

test "any option values round-trip" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(9);
    const rnd = prng.random();
    var msg: [70_000]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = if (i % 700 < 400) @truncate(i % 37) else rnd.int(u8);
    const variants = [_]Options{
        .{ .max_chain = 1, .nice_len = 4, .insert_all_len = 0, .insert_edge = 0, .skip_shift = 0 },
        .{ .max_chain = 8, .nice_len = 1 << 20, .insert_all_len = 1 << 20, .insert_edge = 1 << 20, .skip_shift = 31 },
        .{ .max_chain = 100, .nice_len = 0, .insert_all_len = 3, .insert_edge = 1000, .skip_shift = 1 },
    };
    for (variants) |o| {
        var c = try Compressor.initOptions(gpa, o);
        defer c.deinit();
        var d = try Decompressor.init(gpa);
        defer d.deinit(gpa);
        _ = try roundTrip(&c, &d, &msg);
        _ = try roundTrip(&c, &d, msg[0..1234]);
    }
}

test "random data never expands by more than the framing" {
    const gpa = testing.allocator;
    var c = try Compressor.init(gpa);
    defer c.deinit();
    var d = try Decompressor.init(gpa);
    defer d.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(3);
    const buf = try gpa.alloc(u8, 300_000);
    defer gpa.free(buf);
    prng.random().bytes(buf);
    const n = try roundTrip(&c, &d, buf);
    const segs = (buf.len + max_segment_bytes - 1) / max_segment_bytes;
    try testing.expect(n <= buf.len + 7 + 5 * segs);
}

test "long literal stretch inside a compressible segment uses unencoded runs" {
    const gpa = testing.allocator;
    var buf: [4000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(4);
    prng.random().bytes(buf[0..2000]);
    @memset(buf[2000..], 0x42);
    const enc = try compressOne(&buf);
    defer gpa.free(enc);
    try testing.expectEqual(packet_compr_type_rdp8 | packet_compressed, enc[1]);
    // ~2000 raw bytes + a few tokens, not 2000 * 9 bits.
    try testing.expect(enc.len < 2040);
    const got = try decodeAll(enc);
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, &buf, got);
}

test "empty message is a valid compressed segment" {
    const enc = try compressOne("");
    defer testing.allocator.free(enc);
    try testing.expectEqualSlices(u8, &bytes.hex("E0 24 00"), enc);
    const got = try decodeAll(enc);
    defer testing.allocator.free(got);
    try testing.expectEqual(@as(usize, 0), got.len);
}

test "length and distance codes at bucket edges" {
    const gpa = testing.allocator;
    var c = try Compressor.init(gpa);
    defer c.deinit();
    var d = try Decompressor.init(gpa);
    defer d.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(6);
    const rnd = prng.random();
    const edges = [_]usize{ 1, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 1023, 1024, 2047, 2048, 4095, 4096, 8191, 8192, 16383, 16384, 32767, 32768, 65535 };
    for (edges) |len| {
        const msg = try gpa.alloc(u8, len + 3000);
        defer gpa.free(msg);
        rnd.bytes(msg);
        @memmove(msg[msg.len - len ..], msg[0..len]);
        const total = @min(msg.len, max_segment_bytes);
        _ = try roundTrip(&c, &d, msg[0..total]);
    }
    // A unique 16-byte marker followed by zeros, `dist` bytes back.
    var dists: std.ArrayList(usize) = .empty;
    defer dists.deinit(gpa);
    for (distance_buckets[0..11]) |b| {
        for ([_]usize{ b.base, b.base + 1, b.base + (@as(usize, 1) << b.vbits) - 1 }) |dist| {
            if (dist >= 4 and dist <= max_distance) try dists.append(gpa, dist);
        }
    }
    try dists.append(gpa, max_distance);
    for (dists.items) |dist| {
        const prefix = try gpa.alloc(u8, dist);
        defer gpa.free(prefix);
        @memset(prefix, 0);
        rnd.bytes(prefix[0..@min(16, dist)]);
        var off: usize = 0;
        while (off < prefix.len) : (off += max_segment_bytes)
            _ = try roundTrip(&c, &d, prefix[off..@min(prefix.len, off + max_segment_bytes)]);
        const again = prefix[0..@min(prefix.len, 64)];
        const n = try roundTrip(&c, &d, again);
        // descriptor + header + one match token (<= 41 bits) + trailer
        try testing.expect(n <= 9);
    }
}

test "decoder rejects malformed input without panicking" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const bad = [_][]const u8{
        "",
        &bytes.hex("E0"),
        &bytes.hex("E2 04 00"),
        &bytes.hex("E0 05 00"), // wrong compression type
        &bytes.hex("E0 24"), // compressed, no trailer
        &bytes.hex("E0 24 08"), // trailer > 7
        &bytes.hex("E0 24 FF 09"), // trailer > 7
        &bytes.hex("E0 24 80 00"), // reserved prefix 10000
        &bytes.hex("E0 24 88 00"), // truncated match token
        &bytes.hex("E0 24 88 40 05"), // match distance 1 with empty history
        &bytes.hex("E0 24 88 00 02 80 61 00"), // unencoded run of 5, 1 byte present
        &bytes.hex("E0 24 88 08 00"), // truncated unencoded run count
        &bytes.hex("E1 01 00 05 00 00 00 03 00 00 00 04 61 62"), // size mismatch
        &bytes.hex("E1 01 00 02 00 00 00 09 00 00 00 04 61 62"), // segment overruns
        &bytes.hex("E1 00 00 01 00 00 00"), // size exceeds segments
    };
    for (bad) |pdu| {
        var d = try Decompressor.init(gpa);
        defer d.deinit(gpa);
        try testing.expectError(error.BadZgfx, d.decompress(gpa, &out, pdu));
    }
}

test "decoder survives mutated valid streams" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(8);
    const rnd = prng.random();
    var msg: [150_000]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = if (i % 5000 < 3000) @truncate(i / 3) else rnd.int(u8);
    const enc = try compressOne(&msg);
    defer gpa.free(enc);
    const mutated = try gpa.dupe(u8, enc);
    defer gpa.free(mutated);
    var d = try Decompressor.init(gpa);
    defer d.deinit(gpa);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    for (0..300) |_| {
        @memcpy(mutated, enc);
        for (0..1 + rnd.uintLessThan(usize, 4)) |_| {
            const at = rnd.uintLessThan(usize, mutated.len);
            mutated[at] ^= @as(u8, 1) << rnd.int(u3);
        }
        const n = if (rnd.boolean()) mutated.len else rnd.uintLessThan(usize, mutated.len + 1);
        out.clearRetainingCapacity();
        d.decompress(gpa, &out, mutated[0..n]) catch {};
    }
}

test "decoder survives random garbage" {
    const gpa = testing.allocator;
    var d = try Decompressor.init(gpa);
    defer d.deinit(gpa);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    var buf: [600]u8 = undefined;
    for (0..20_000) |iter| {
        const n = rnd.uintLessThan(usize, buf.len);
        rnd.bytes(buf[0..n]);
        if (n > 0) buf[0] = if (iter % 2 == 0) segmented_single else segmented_multipart;
        if (n > 1 and iter % 3 != 0) buf[1] = packet_compr_type_rdp8 | packet_compressed;
        out.clearRetainingCapacity();
        d.decompress(gpa, &out, buf[0..n]) catch {};
    }
}
