//! XCRUSH, RDP 6.1 bulk compression (MS-RDPEGDI 3.1.8.2): level-1 matches over a
//! 2,000,000-byte history (2.2.2.4.1.1) chained into RDP 5.0 MPPC (3.1.8.2.2.2).
//! Matches never overlap the bytes they produce (3.1.8.2.2).

const std = @import("std");
const bulk = @import("../bulk.zig");
const mppc = @import("mppc.zig");
const lz = @import("lz.zig");

const Error = bulk.Error;
const MatchDetails = bulk.MatchDetails;

pub const history_size: u32 = 2_000_000;
/// Blocks MUST be smaller than 16,383 bytes (3.1.8.2.1).
pub const max_input: u32 = 16382;
const hash_bits = 17;
const none: u32 = std.math.maxInt(u32);
const max_match: u32 = 65535;

/// Positions at multiples of `stride` are chained by their `key` bytes, so every
/// match of at least `key + stride - 1` bytes is found.
pub const Level1 = struct {
    gpa: std.mem.Allocator,
    /// History plus 8 bytes of slack for the 8-byte key loads.
    hist: []u8,
    offset: u32 = 0,
    head: []u32,
    prev: []u32,
    key: u32,
    stride: u32,
    min_match: u32,
    allow_expansion: bool,
    ins: u32 = 0,
    /// The next block must restart the history (L1_PACKET_AT_FRONT).
    pending_front: bool = false,
    matches: std.ArrayList(MatchDetails) = .empty,
    literals: std.ArrayList(u8) = .empty,
    /// State before the last `compress`, for `rollback`.
    saved_offset: u32 = 0,
    saved_ins: u32 = 0,
    saved_front: bool = false,

    const depth = 16;

    pub fn init(gpa: std.mem.Allocator, opts: bulk.Level1Options) Error!Level1 {
        // A match costs 8 bytes of RDP61_MATCH_DETAILS.
        var mm: u32 = @intCast(@min(@max(opts.min_match, 2), max_input));
        if (!opts.allow_expansion) mm = @max(mm, 9);
        const key = @min(mm, 8);
        const stride = mm - key + 1;
        const hist = try gpa.alloc(u8, history_size + 8);
        errdefer gpa.free(hist);
        @memset(hist, 0);
        const head = try gpa.alloc(u32, 1 << hash_bits);
        errdefer gpa.free(head);
        @memset(head, none);
        const prev = try gpa.alloc(u32, history_size / stride + 1);
        return .{ .gpa = gpa, .hist = hist, .head = head, .prev = prev, .key = key, .stride = stride, .min_match = mm, .allow_expansion = opts.allow_expansion };
    }

    pub fn deinit(l: *Level1) void {
        l.gpa.free(l.hist);
        l.gpa.free(l.head);
        l.gpa.free(l.prev);
        l.matches.deinit(l.gpa);
        l.literals.deinit(l.gpa);
    }

    inline fn hash(l: *const Level1, p: u32) u32 {
        var v = std.mem.readInt(u64, l.hist[p..][0..8], .little);
        if (l.key < 8) v &= (@as(u64, 1) << @intCast(8 * l.key)) - 1;
        return @intCast((v *% 0x9E37_79B9_7F4A_7C15) >> (64 - hash_bits));
    }

    inline fn insert(l: *Level1, p: u32) void {
        const h = l.hash(p);
        l.prev[p / l.stride] = l.head[h];
        l.head[h] = p;
    }

    fn restart(l: *Level1) void {
        l.offset = 0;
        l.ins = 0;
        @memset(l.head, none);
    }

    /// Restart the history with the next block (L1_PACKET_AT_FRONT).
    pub fn flush(l: *Level1) void {
        l.pending_front = true;
    }

    const Found = struct { len: u32 = 0, src: u32 = 0, back: u32 = 0 };

    /// Longest match for the bytes at `q`, extended back to `lit_start`.
    fn search(l: *const Level1, q: u32, end: u32, lit_start: u32) Found {
        const hist = l.hist;
        var best: Found = .{};
        var c = l.head[l.hash(q)];
        var left: u32 = depth;
        while (c != none and left > 0) : (left -= 1) {
            if (c + l.key <= q) {
                const d = q - c;
                const f = lz.matchLen(hist, c, q, @min(end - q, d, max_match));
                if (f >= l.key) {
                    const max_back = @min(q - lit_start, c, d - f, max_match - f);
                    var b: u32 = 0;
                    while (b < max_back and hist[c - 1 - b] == hist[q - 1 - b]) b += 1;
                    if (f + b > best.len) {
                        best = .{ .len = f + b, .src = c, .back = b };
                        if (q + f == end and b == q - lit_start) break;
                    }
                }
            }
            const next = l.prev[c / l.stride];
            if (next >= c) break;
            c = next;
        }
        return best;
    }

    /// The history restarts when the block does not fit (the decoder never fills the
    /// last byte). The result stays valid until the next call.
    pub fn compress(l: *Level1, src: []const u8) Error!bulk.Level1Result {
        const n: u32 = @intCast(src.len);
        if (n > max_input) return error.TooLarge;
        l.saved_offset = l.offset;
        l.saved_ins = l.ins;
        var flags: u8 = 0;
        l.saved_front = l.pending_front or l.offset + n >= history_size;
        if (l.saved_front) {
            l.restart();
            l.pending_front = false;
            flags |= bulk.l1_packet_at_front;
        }
        const base = l.offset;
        const end = base + n;
        @memcpy(l.hist[base..end], src);
        l.matches.clearRetainingCapacity();
        l.literals.clearRetainingCapacity();
        var lit_start = base;
        var q = base;
        while (q + l.key <= end) {
            while (l.ins < q and l.ins + l.key <= end) : (l.ins += l.stride) l.insert(l.ins);
            const m = l.search(q, end, lit_start);
            if (m.len < l.min_match) {
                q += 1;
                continue;
            }
            const start = q - m.back;
            try l.literals.appendSlice(l.gpa, l.hist[lit_start..start]);
            try l.matches.append(l.gpa, .{ .length = @intCast(m.len), .output_offset = @intCast(start - base), .history_offset = m.src - m.back });
            q = start + m.len;
            lit_start = q;
        }
        try l.literals.appendSlice(l.gpa, l.hist[lit_start..end]);
        l.offset = end;
        if (l.matches.items.len > 0 and !l.allow_expansion and 2 + 8 * l.matches.items.len + l.literals.items.len >= n) {
            l.matches.clearRetainingCapacity();
            l.literals.clearRetainingCapacity();
            try l.literals.appendSlice(l.gpa, src);
        }
        flags |= if (l.matches.items.len > 0) bulk.l1_compressed else bulk.l1_no_compression;
        return .{ .l1_flags = flags, .matches = l.matches.items, .literals = l.literals.items };
    }

    /// Undo the last `compress`, whose block was sent raw. After a restart the old
    /// history is gone, so the next block restarts again.
    pub fn rollback(l: *Level1) void {
        if (l.saved_front) {
            l.restart();
            l.pending_front = true;
            return;
        }
        var p = l.ins;
        while (p > l.saved_ins) {
            p -= l.stride;
            const h = l.hash(p);
            if (l.head[h] == p) l.head[h] = l.prev[p / l.stride];
        }
        l.ins = l.saved_ins;
        l.offset = l.saved_offset;
    }
};

/// RDP61_COMPRESSED_DATA after the flag bytes; MatchDetails only with L1_COMPRESSED.
pub fn writeLevel1Body(out: []u8, r: bulk.Level1Result) usize {
    var i: usize = 0;
    if (r.l1_flags & bulk.l1_compressed != 0) {
        std.mem.writeInt(u16, out[0..2], @intCast(r.matches.len), .little);
        i = 2;
        for (r.matches) |m| {
            std.mem.writeInt(u16, out[i..][0..2], m.length, .little);
            std.mem.writeInt(u16, out[i + 2 ..][0..2], m.output_offset, .little);
            std.mem.writeInt(u32, out[i + 4 ..][0..4], m.history_offset, .little);
            i += 8;
        }
    }
    @memcpy(out[i..][0..r.literals.len], r.literals);
    return i + r.literals.len;
}

/// The chained RDP 6.1 compressor (3.1.8.2.2.2).
pub const Compressor = struct {
    l1: Level1,
    l2: mppc.Compressor,
    body: []u8,
    out: []u8,

    /// Smaller level-1 output skips level 2: MPPC would expand it and flush its history.
    const l2_min = 51;
    const type_bits: u8 = @backingInt(bulk.Type.xcrush);

    pub fn init(gpa: std.mem.Allocator) Error!Compressor {
        var l1 = try Level1.init(gpa, .{});
        errdefer l1.deinit();
        var l2 = try mppc.Compressor.init(gpa, true);
        errdefer l2.deinit(gpa);
        const body = try gpa.alloc(u8, max_input + 16);
        errdefer gpa.free(body);
        const out = try gpa.alloc(u8, max_input + 16);
        return .{ .l1 = l1, .l2 = l2, .body = body, .out = out };
    }

    pub fn deinit(c: *Compressor, gpa: std.mem.Allocator) void {
        c.l1.deinit();
        c.l2.deinit(gpa);
        gpa.free(c.body);
        gpa.free(c.out);
    }

    /// Restart both histories (L1_PACKET_AT_FRONT, PACKET_FLUSHED).
    pub fn flush(c: *Compressor) void {
        c.l1.flush();
        c.l2.flush();
    }

    /// Level 1, then level 2 when worth trying (L1_INNER_COMPRESSION). Output not smaller
    /// than `src` goes raw and both levels forget it: receivers never store raw packets.
    pub fn compress(c: *Compressor, src: []const u8) Error!bulk.Result {
        const n: u32 = @intCast(src.len);
        if (n > max_input) return error.TooLarge;
        if (n < 4) return .{ .flags = 0, .data = src };
        const r1 = try c.l1.compress(src);
        var l1_flags = r1.l1_flags;
        var body: []const u8 = src;
        if (l1_flags & bulk.l1_compressed != 0) body = c.body[0..writeLevel1Body(c.body, r1)];
        var l2_flags: u8 = 0;
        var l2_used = false;
        if (body.len >= l2_min) {
            l1_flags |= bulk.l1_inner_compression;
            const r2 = c.l2.compress(body);
            if (r2.flags & bulk.packet_compressed != 0) {
                body = r2.data;
                l2_flags = r2.flags;
                l2_used = true;
            } else l2_flags = @backingInt(bulk.Type.mppc_64k);
        }
        if (2 + body.len > n) {
            c.l1.rollback();
            if (l2_used) c.l2.flush();
            return .{ .flags = 0, .data = src };
        }
        c.out[0] = l1_flags;
        c.out[1] = l2_flags;
        @memcpy(c.out[2..][0..body.len], body);
        return .{ .flags = type_bits | bulk.packet_compressed, .data = c.out[0 .. 2 + body.len] };
    }
};

/// RDP 6.1 decompressor (3.1.8.2.3): level 2 when L1_INNER_COMPRESSION is set, then level 1.
pub const Decoder = struct {
    l2: mppc.Decoder,
    hist: []u8,
    offset: u32 = 0,

    pub fn init(gpa: std.mem.Allocator) Error!Decoder {
        var l2 = try mppc.Decoder.init(gpa, true);
        errdefer l2.deinit(gpa);
        const hist = try gpa.alloc(u8, history_size);
        @memset(hist, 0);
        return .{ .l2 = l2, .hist = hist };
    }

    pub fn deinit(d: *Decoder, gpa: std.mem.Allocator) void {
        d.l2.deinit(gpa);
        gpa.free(d.hist);
    }

    fn append(d: *Decoder, b: []const u8) Error!void {
        if (history_size - d.offset < b.len) return error.BadData;
        @memcpy(d.hist[d.offset..][0..b.len], b);
        d.offset += @intCast(b.len);
    }

    pub fn decompress(d: *Decoder, src: []const u8, flags: u8) Error![]const u8 {
        if (flags & bulk.packet_compressed == 0) return src;
        if (src.len < 2) return error.BadData;
        const l1 = src[0];
        var data = src[2..];
        if (l1 & bulk.l1_inner_compression != 0) data = try d.l2.decompress(data, src[1]);
        if (l1 & bulk.l1_packet_at_front != 0) {
            @memset(d.hist, 0);
            d.offset = 0;
        }
        const start = d.offset;
        if (l1 & bulk.l1_no_compression != 0) {
            try d.append(data);
            return d.hist[start..d.offset];
        }
        if (l1 & bulk.l1_compressed == 0 or data.len < 2) return error.BadData;
        const count: usize = std.mem.readInt(u16, data[0..2], .little);
        if (count == 0 or data.len < 2 + 8 * count) return error.BadData;
        const lits = data[2 + 8 * count ..];
        var li: usize = 0;
        var out: usize = 0;
        for (0..count) |k| {
            const m = data[2 + 8 * k ..][0..8];
            const len: u32 = std.mem.readInt(u16, m[0..2], .little);
            const at: usize = std.mem.readInt(u16, m[2..4], .little);
            const from = std.mem.readInt(u32, m[4..8], .little);
            if (at < out or at - out > lits.len - li) return error.BadData;
            try d.append(lits[li..][0 .. at - out]);
            li += at - out;
            if (from > d.offset or d.offset - from < len or history_size - d.offset < len) return error.BadData;
            @memcpy(d.hist[d.offset..][0..len], d.hist[from..][0..len]);
            d.offset += len;
            out = at + len;
        }
        try d.append(lits[li..]);
        return d.hist[start..d.offset];
    }
};

test "level 1 reproduces the 3.1.8.2.2.1 example and the decoder agrees" {
    const gpa = std.testing.allocator;
    var l = try Level1.init(gpa, .{ .min_match = 4, .allow_expansion = true });
    defer l.deinit();
    _ = try l.compress("abcdefghij");
    const r = try l.compress("klmnodefghijklabcdu");
    try std.testing.expectEqualSlices(MatchDetails, &.{ .{ .length = 9, .output_offset = 5, .history_offset = 3 }, .{ .length = 4, .output_offset = 14, .history_offset = 0 } }, r.matches);
    try std.testing.expectEqualStrings("klmnou", r.literals);
}

test "chained compressor round trips, including raw blocks and rollback" {
    const gpa = std.testing.allocator;
    var c = try Compressor.init(gpa);
    defer c.deinit(gpa);
    var d = try Decoder.init(gpa);
    defer d.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(0x6101);
    const r = prng.random();
    var block: [3000]u8 = undefined;
    for (&block) |*b| b.* = "acgt"[r.uintLessThan(usize, 4)];
    var buf: [12000]u8 = undefined;
    for (0..60) |i| {
        const n = 1 + r.uintLessThan(usize, buf.len);
        for (buf[0..n], 0..) |*b, k| b.* = switch (i % 3) {
            0 => r.int(u8),
            1 => block[k % block.len],
            else => "acgt"[r.uintLessThan(usize, 4)],
        };
        const res = try c.compress(buf[0..n]);
        try std.testing.expect(res.data.len <= n);
        try std.testing.expectEqualSlices(u8, buf[0..n], try d.decompress(res.data, res.flags));
    }
}
