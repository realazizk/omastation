//! NCRUSH, RDP 6.0 bulk compression (MS-RDPEGDI 3.1.8.1): 64 KB sliding history,
//! 4-entry OffsetCache and LSB-first Huffman codes (3.1.8.1.4).

const std = @import("std");
const bulk = @import("../bulk.zig");
const lz = @import("lz.zig");
const t = @import("ncrush_tables.zig");

const Error = bulk.Error;

pub const history_size: u32 = 65536;
/// Decoders write no literal at or beyond this offset and take no copy that reaches it.
pub const receiver_end: u32 = 65535;
/// Clients refuse a history filled to receiver_end that ends with a copy.
pub const fill_limit: u32 = receiver_end - 1;
pub const half: u32 = 32768;
pub const min_len = 2;
/// LoMBaseLUT[28] + 2^14 - 1 (3.1.8.1.4.2).
pub const max_len: u32 = 16385;
/// CopyOffsetBaseLUT[31] + 2^14 - 2.
pub const max_offset: u32 = 65535;
const eos: usize = 256;
const lec_offset: usize = 257;
const lec_cache: usize = 289;
/// Cost in bits of the costliest copy-tuple (13 + 14 + 9 + 14).
const max_copy_bits: u32 = 50;

/// Bounded LSB-first bit writer; error.Overflow when `out` is full.
pub const Writer = struct {
    out: []u8,
    len: usize = 0,
    acc: u64 = 0,
    nbits: u6 = 0,

    pub inline fn put(w: *Writer, n: u6, v: u32) error{Overflow}!void {
        w.acc |= @as(u64, v) << w.nbits;
        w.nbits += n;
        while (w.nbits >= 8) {
            if (w.len == w.out.len) return error.Overflow;
            w.out[w.len] = @truncate(w.acc);
            w.len += 1;
            w.acc >>= 8;
            w.nbits -= 8;
        }
    }

    pub fn finish(w: *Writer) error{Overflow}!usize {
        if (w.nbits > 0) try w.put(8 - w.nbits, 0);
        return w.len;
    }

    inline fn lec(w: *Writer, i: usize) error{Overflow}!void {
        try w.put(@intCast(t.huff_length_lec[i]), t.huff_code_lec[i]);
    }

    pub inline fn literal(w: *Writer, b: u8) error{Overflow}!void {
        try w.lec(b);
    }

    pub inline fn end(w: *Writer) error{Overflow}!void {
        try w.lec(eos);
    }

    /// Copy-tuple (3.1.8.1.4.3). A cached offset swaps with entry 0; any other
    /// offset is pushed to the front of the OffsetCache.
    pub inline fn copy(w: *Writer, cache: *[4]u32, off: u32, len: u32) error{Overflow}!void {
        if (cacheIndex(cache, off)) |i| {
            try w.lec(lec_cache + i);
            cache[i] = cache[0];
            cache[0] = off;
        } else {
            const ci = offsetIndex(off);
            try w.lec(lec_offset + ci);
            const nb = t.copy_offset_bits[ci];
            try w.put(@intCast(nb), off & ((@as(u32, 1) << @intCast(nb)) - 1));
            const old = cache.*; // a literal reading cache would alias its destination
            cache.* = .{ off, old[0], old[1], old[2] };
        }
        const li = lomIndex(len);
        try w.put(@intCast(t.huff_length_lom[li]), t.huff_code_lom[li]);
        const nb = t.lom_bits[li];
        try w.put(@intCast(nb), (len - 2) & ((@as(u32, 1) << @intCast(nb)) - 1));
    }
};

pub inline fn cacheIndex(cache: *const [4]u32, off: u32) ?usize {
    inline for (0..4) |i| if (cache[i] == off) return i;
    return null;
}

/// IndexOfEqualOrSmallerEntry(CopyOffset + 1, CopyOffsetBaseLUT), computed from log2.
pub inline fn offsetIndex(off: u32) usize {
    const v = off + 1;
    if (v <= 4) return v - 1;
    const k: u5 = @intCast(31 - @clz(v - 1));
    return 2 * @as(usize, k) + ((v - 1) >> (k - 1) & 1);
}

/// IndexOfEqualOrSmallerEntry(LoM, LoMBaseLUT); index 28 is the 14-bit escape.
pub inline fn lomIndex(len: u32) usize {
    return if (len - 2 >= 768) 28 else lom_index[len];
}

const lom_index = blk: {
    @setEvalBranchQuota(50_000);
    var a: [770]u8 = @splat(0);
    for (2..770) |l| {
        var i: u8 = 0;
        while (i + 1 < 28 and t.lom_base[i + 1] <= l) i += 1;
        a[l] = i;
    }
    break :blk a;
};

inline fn copyBits(cache: *const [4]u32, off: u32, len: u32) u32 {
    var bits: u32 = undefined;
    if (cacheIndex(cache, off)) |i| {
        bits = t.huff_length_lec[lec_cache + i];
    } else {
        const ci = offsetIndex(off);
        bits = @as(u32, t.huff_length_lec[lec_offset + ci]) + t.copy_offset_bits[ci];
    }
    const li = lomIndex(len);
    return bits + t.huff_length_lom[li] + t.lom_bits[li];
}

/// Bits of `len` literals at `p`, counted up to `cap`.
inline fn literalBits(hist: []const u8, p: u32, len: u32, cap: u32) u32 {
    var bits: u32 = 0;
    var k: u32 = 0;
    while (k < len and bits <= cap) : (k += 1) bits += t.huff_length_lec[hist[p + k]];
    return bits;
}

pub const Compressor = struct {
    hist: []u8,
    offset: u32 = 0,
    cache: [4]u32 = .{ 0, 0, 0, 0 },
    chains: lz.Chains,
    out: []u8,
    pending_flush: bool = false,

    const depth = 32;
    const type_bits: u8 = @backingInt(bulk.Type.ncrush);

    pub fn init(gpa: std.mem.Allocator) Error!Compressor {
        const hist = try gpa.alloc(u8, history_size);
        errdefer gpa.free(hist);
        @memset(hist, 0);
        var chains = try lz.Chains.init(gpa, history_size, 15);
        errdefer chains.deinit(gpa);
        const out = try gpa.alloc(u8, history_size - 1);
        return .{ .hist = hist, .chains = chains, .out = out };
    }

    pub fn deinit(c: *Compressor, gpa: std.mem.Allocator) void {
        gpa.free(c.hist);
        c.chains.deinit(gpa);
        gpa.free(c.out);
    }

    /// Reset history and OffsetCache; the next compressed packet carries PACKET_FLUSHED.
    pub fn flush(c: *Compressor) void {
        c.offset = 0;
        c.cache = .{ 0, 0, 0, 0 };
        c.chains.reset();
        c.pending_flush = true;
    }

    /// Move the last 32 KB to the front (3.1.8.1.1).
    fn slide(c: *Compressor) void {
        std.mem.copyForwards(u8, c.hist[0..half], c.hist[c.offset - half .. c.offset]);
        c.offset = half;
        c.chains.reset();
        c.chains.catchUp(c.hist, half, half);
    }

    /// `src` is at most fill_limit bytes; under 4 bytes goes raw, as decoders need 4.
    /// Data that does not fit slides (PACKET_AT_FRONT) or flushes the history.
    pub fn compress(c: *Compressor, src: []const u8) bulk.Result {
        const n: u32 = @intCast(src.len);
        std.debug.assert(n <= fill_limit); // bulk.maxInput
        if (n < 4) return .{ .flags = 0, .data = src };
        var at_front = false;
        if (c.offset + n > fill_limit) {
            if (c.offset > half and half + n <= fill_limit) {
                c.slide();
                at_front = true;
            } else c.flush();
        }
        const base = c.offset;
        const end = base + n;
        @memcpy(c.hist[base..end], src);
        var cache = c.cache;
        var w: Writer = .{ .out = c.out[0..n] };
        var len = c.encode(&w, &cache, base, end) catch {
            c.flush();
            return .{ .flags = type_bits | bulk.packet_flushed, .data = src };
        };
        // decoders read at least 4 bytes; bits after EOS are ignored
        while (len < 4) : (len += 1) c.out[len] = 0;
        c.offset = end;
        c.cache = cache;
        var flags = type_bits | bulk.packet_compressed;
        if (at_front) flags |= bulk.packet_at_front;
        if (c.pending_flush) flags |= bulk.packet_flushed;
        c.pending_flush = false;
        return .{ .flags = flags, .data = c.out[0..len] };
    }

    /// Greedy: cached-offset matches (>= 2 bytes) and the longest chained match (>= 3)
    /// compete on bits saved against the literals they replace.
    fn encode(c: *Compressor, w: *Writer, cache: *[4]u32, base: u32, end: u32) error{Overflow}!usize {
        const hist = c.hist;
        var pos = base;
        while (pos < end) {
            c.chains.catchUp(hist, pos, end);
            const left = end - pos;
            var best_len: u32 = 0;
            var best_off: u32 = 0;
            var best_score: i64 = 0;
            if (left >= min_len) {
                const limit = @min(left, max_len);
                for (cache) |o| {
                    if (o == 0 or o > pos) continue;
                    const l = lz.matchLen(hist, pos - o, pos, limit);
                    if (l < min_len) continue;
                    const score = @as(i64, l) * 8 - copyBits(cache, o, l);
                    if (score > best_score) {
                        best_score = score;
                        best_len = l;
                        best_off = o;
                    }
                }
                const m = c.chains.longest(hist, pos, end, limit, depth);
                if (m.len >= lz.min_len) {
                    const score = @as(i64, m.len) * 8 - copyBits(cache, m.dist, m.len);
                    if (score > best_score) {
                        best_score = score;
                        best_len = m.len;
                        best_off = m.dist;
                    }
                }
            }
            if (best_len > 0) {
                const cost = copyBits(cache, best_off, best_len);
                if (literalBits(hist, pos, best_len, max_copy_bits) > cost) {
                    try w.copy(cache, best_off, best_len);
                    pos += best_len;
                    continue;
                }
            }
            try w.literal(hist[pos]);
            pos += 1;
        }
        try w.end();
        return w.finish();
    }
};

/// Canonical LSB-first decode table: entry = length << 9 | symbol, 0 for no code.
fn decodeTable(comptime n: usize, comptime max_bits: u5, lens: *const [n]u8, codes: *const [n]u16) [1 << max_bits]u16 {
    @setEvalBranchQuota(200_000);
    var tab: [1 << max_bits]u16 = @splat(0);
    for (0..n) |s| {
        const l = lens[s];
        var k: usize = 0;
        while (k < (@as(usize, 1) << (max_bits - l))) : (k += 1) tab[codes[s] | (k << l)] = @as(u16, l) << 9 | @as(u16, s);
    }
    return tab;
}

const lec_bits = 13;
const lom_bits_max = 9;
const lec_table = decodeTable(t.huff_length_lec.len, lec_bits, &t.huff_length_lec, &t.huff_code_lec);
const lom_table = decodeTable(t.huff_length_lom.len, lom_bits_max, &t.huff_length_lom, &t.huff_code_lom);

const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    inline fn left(r: *const Reader) usize {
        return r.data.len * 8 - r.pos;
    }

    inline fn peek(r: *const Reader) u32 {
        const i = r.pos >> 3;
        var v: u64 = 0;
        inline for (0..5) |k| v |= @as(u64, if (i + k < r.data.len) r.data[i + k] else 0) << (8 * k);
        return @truncate(v >> @intCast(r.pos & 7));
    }

    inline fn take(r: *Reader, n: u5) error{BadData}!u32 {
        if (r.left() < n) return error.BadData;
        const v = r.peek() & ((@as(u32, 1) << n) - 1);
        r.pos += n;
        return v;
    }
};

/// NCRUSH decompressor (3.1.8.1.3); writes nothing at receiver_end or beyond.
pub const Decoder = struct {
    hist: []u8,
    offset: u32 = 0,
    cache: [4]u32 = .{ 0, 0, 0, 0 },

    pub fn init(gpa: std.mem.Allocator) Error!Decoder {
        const hist = try gpa.alloc(u8, history_size);
        @memset(hist, 0);
        return .{ .hist = hist };
    }

    pub fn deinit(d: *Decoder, gpa: std.mem.Allocator) void {
        gpa.free(d.hist);
    }

    pub fn decompress(d: *Decoder, src: []const u8, flags: u8) Error![]const u8 {
        if (flags & bulk.packet_at_front != 0) {
            if (d.offset <= half) return error.BadData; // cannot slide without more than 32 KB of history
            std.mem.copyForwards(u8, d.hist[0..half], d.hist[d.offset - half .. d.offset]);
            @memset(d.hist[half..], 0);
            d.offset = half;
        }
        if (flags & bulk.packet_flushed != 0) {
            @memset(d.hist, 0);
            d.offset = 0;
            d.cache = .{ 0, 0, 0, 0 };
        }
        if (flags & bulk.packet_compressed == 0) return src;
        const start = d.offset;
        var pos = d.offset;
        var r: Reader = .{ .data = src };
        while (true) {
            const e = lec_table[r.peek() & ((1 << lec_bits) - 1)];
            const l: u5 = @intCast(e >> 9);
            if (l == 0 or r.left() < l) return error.BadData;
            r.pos += l;
            const s: usize = e & 0x1FF;
            if (s < 256) {
                if (pos >= receiver_end) return error.BadData;
                d.hist[pos] = @intCast(s);
                pos += 1;
                continue;
            }
            if (s == eos) break;
            var off: u32 = undefined;
            const cached = s >= lec_cache;
            if (cached) {
                off = d.cache[s - lec_cache];
            } else {
                const ci = s - lec_offset;
                off = t.copy_offset_base[ci] + try r.take(@intCast(t.copy_offset_bits[ci])) - 1;
            }
            const le = lom_table[r.peek() & ((1 << lom_bits_max) - 1)];
            const ll: u5 = @intCast(le >> 9);
            if (ll == 0 or r.left() < ll) return error.BadData;
            r.pos += ll;
            const li = le & 0x1FF;
            if (li >= t.lom_base.len) return error.BadData;
            const len = t.lom_base[li] + try r.take(@intCast(t.lom_bits[li]));
            if (cached) {
                const i = s - lec_cache;
                d.cache[i] = d.cache[0];
                d.cache[0] = off;
            } else {
                const old = d.cache;
                d.cache = .{ off, old[0], old[1], old[2] };
            }
            if (off == 0 or off > pos or receiver_end - pos <= len) return error.BadData;
            for (0..len) |_| {
                d.hist[pos] = d.hist[pos - off];
                pos += 1;
            }
        }
        d.offset = pos;
        return d.hist[start..pos];
    }
};

test "offset and length LUT indexes match IndexOfEqualOrSmallerEntry" {
    var v: u32 = 1;
    while (v <= 65536) : (v += 1) {
        const i = offsetIndex(v - 1);
        try std.testing.expect(t.copy_offset_base[i] <= v);
        if (i + 1 < 32) try std.testing.expect(t.copy_offset_base[i + 1] > v);
        try std.testing.expect(v - t.copy_offset_base[i] < @as(u32, 1) << @intCast(t.copy_offset_bits[i]));
    }
    for (2..max_len + 1) |l| {
        const i = lomIndex(@intCast(l));
        try std.testing.expectEqual(@as(u32, @intCast(l)), t.lom_base[i] + ((@as(u32, @intCast(l)) - 2) & ((@as(u32, 1) << @intCast(t.lom_bits[i])) - 1)));
    }
}

test "a history filled to its end never emits a copy that reaches offset 65535" {
    const gpa = std.testing.allocator;
    var c = try Compressor.init(gpa);
    defer c.deinit(gpa);
    var d = try Decoder.init(gpa);
    defer d.deinit(gpa);
    var pkt: [13107]u8 = undefined;
    for (&pkt, 0..) |*b, i| b.* = @truncate(i % 7);
    for (0..12) |_| {
        const r = c.compress(&pkt);
        try std.testing.expect(r.flags & bulk.packet_compressed != 0);
        try std.testing.expect(c.offset < receiver_end);
        try std.testing.expectEqualSlices(u8, &pkt, try d.decompress(r.data, r.flags));
    }
    var big: [fill_limit]u8 = undefined;
    @memset(&big, 'z');
    var c2 = try Compressor.init(gpa);
    defer c2.deinit(gpa);
    var d2 = try Decoder.init(gpa);
    defer d2.deinit(gpa);
    const r = c2.compress(&big);
    try std.testing.expectEqualSlices(u8, &big, try d2.decompress(r.data, r.flags));
}

test "compressor round trips through the decoder, slides and flushes" {
    const gpa = std.testing.allocator;
    var c = try Compressor.init(gpa);
    defer c.deinit(gpa);
    var d = try Decoder.init(gpa);
    defer d.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(0x6001);
    var buf: [9000]u8 = undefined;
    for (0..60) |i| {
        const n = 1 + prng.random().uintLessThan(usize, buf.len);
        for (buf[0..n], 0..) |*b, k| b.* = if (i % 7 == 0) prng.random().int(u8) else @truncate((k / 5) % 23 + (k * i) % 3);
        const r = c.compress(buf[0..n]);
        try std.testing.expect(r.data.len <= n);
        try std.testing.expectEqualSlices(u8, buf[0..n], try d.decompress(r.data, r.flags));
    }
}
