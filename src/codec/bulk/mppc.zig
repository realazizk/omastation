//! MPPC bulk compression with 8 KB (RDP 4.0) or 64 KB (RDP 5.0) history, MS-RDPBCGR 3.1.8.

const std = @import("std");
const bulk = @import("../bulk.zig");
const lz = @import("lz.zig");

const Error = bulk.Error;

/// Bounded MSB-first bit writer; error.Overflow when `out` is full.
pub const Writer = struct {
    out: []u8,
    len: usize = 0,
    acc: u64 = 0,
    nbits: u6 = 0,

    pub inline fn put(w: *Writer, n: u6, v: u32) error{Overflow}!void {
        w.acc = (w.acc << n) | v;
        w.nbits += n;
        while (w.nbits >= 8) {
            if (w.len == w.out.len) return error.Overflow;
            w.nbits -= 8;
            w.out[w.len] = @truncate(w.acc >> w.nbits);
            w.len += 1;
        }
        w.acc &= (@as(u64, 1) << w.nbits) - 1;
    }

    /// Zero-pad the last byte; returns the byte count.
    pub fn finish(w: *Writer) error{Overflow}!usize {
        if (w.nbits > 0) try w.put(8 - w.nbits, 0);
        return w.len;
    }

    /// Literal (3.1.8.4.1.1): < 0x80 as 8 bits, else 10 + the low 7 bits.
    pub inline fn literal(w: *Writer, b: u8) error{Overflow}!void {
        if (b < 0x80) try w.put(8, b) else try w.put(9, 0x100 | @as(u32, b & 0x7F));
    }

    /// Copy-tuple (3.1.8.4.1.2 / 3.1.8.4.2.2); `checkCopy` must hold.
    pub inline fn copy(w: *Writer, big: bool, off: u32, len: u32) error{Overflow}!void {
        if (big) {
            if (off < 64) {
                try w.put(11, 0x1F << 6 | off);
            } else if (off < 320) {
                try w.put(13, 0x1E << 8 | (off - 64));
            } else if (off < 2368) {
                try w.put(15, 0xE << 11 | (off - 320));
            } else try w.put(19, 0x6 << 16 | (off - 2368));
        } else {
            if (off < 64) {
                try w.put(10, 0xF << 6 | off);
            } else if (off < 320) {
                try w.put(12, 0xE << 8 | (off - 64));
            } else try w.put(16, 0x6 << 13 | (off - 320));
        }
        if (len == 3) return w.put(1, 0);
        // k - 1 ones, a zero, then the k low bits (len in [2^k, 2^(k+1)))
        const k: u5 = @intCast(31 - @clz(len));
        try w.put(k, (@as(u32, 1) << k) - 2);
        try w.put(k, len & ((@as(u32, 1) << k) - 1));
    }
};

/// Offset 1..history-1, length 3..history-1.
pub fn checkCopy(big: bool, off: u32, len: u32) bool {
    const hist: u32 = if (big) 65536 else 8192;
    return off >= 1 and off < hist and len >= 3 and len < hist;
}

pub const Compressor = struct {
    big: bool,
    hist: []u8,
    offset: u32 = 0,
    chains: lz.Chains,
    out: []u8,
    /// The next compressed packet carries PACKET_FLUSHED.
    pending_flush: bool = false,

    const depth = 32;

    pub fn init(gpa: std.mem.Allocator, big: bool) Error!Compressor {
        const size: usize = if (big) 65536 else 8192;
        const hist = try gpa.alloc(u8, size);
        errdefer gpa.free(hist);
        @memset(hist, 0);
        var chains = try lz.Chains.init(gpa, size, if (big) 15 else 13);
        errdefer chains.deinit(gpa);
        const out = try gpa.alloc(u8, size - 1);
        return .{ .big = big, .hist = hist, .chains = chains, .out = out };
    }

    pub fn deinit(c: *Compressor, gpa: std.mem.Allocator) void {
        gpa.free(c.hist);
        c.chains.deinit(gpa);
        gpa.free(c.out);
    }

    fn typeBits(c: *const Compressor) u8 {
        return @backingInt(if (c.big) bulk.Type.mppc_64k else bulk.Type.mppc_8k);
    }

    /// Discard the history; the next compressed packet carries PACKET_FLUSHED.
    pub fn flush(c: *Compressor) void {
        c.offset = 0;
        c.chains.reset();
        c.pending_flush = true;
    }

    /// `src` is 1..history-1 bytes. A packet that does not fit restarts the history
    /// (PACKET_AT_FRONT); expansion sends `src` raw with PACKET_FLUSHED (3.1.8.2).
    pub fn compress(c: *Compressor, src: []const u8) bulk.Result {
        const n: u32 = @intCast(src.len);
        std.debug.assert(n >= 1 and n < c.hist.len);
        const size: u32 = @intCast(c.hist.len);
        const at_front = c.offset == 0 or c.offset + n > size;
        if (at_front) {
            c.offset = 0;
            c.chains.reset();
        }
        const base = c.offset;
        const end = base + n;
        @memcpy(c.hist[base..end], src);
        const max_len: u32 = size - 1;
        var w: Writer = .{ .out = c.out[0..n] };
        const len = c.encode(&w, base, end, max_len) catch {
            c.flush();
            return .{ .flags = c.typeBits() | bulk.packet_flushed, .data = src };
        };
        c.offset = end;
        var flags = c.typeBits() | bulk.packet_compressed;
        if (at_front) flags |= bulk.packet_at_front;
        if (c.pending_flush) flags |= bulk.packet_flushed;
        c.pending_flush = false;
        return .{ .flags = flags, .data = c.out[0..len] };
    }

    fn encode(c: *Compressor, w: *Writer, base: u32, end: u32, max_len: u32) error{Overflow}!usize {
        var pos = base;
        while (pos < end) {
            c.chains.catchUp(c.hist, pos, end);
            const m = c.chains.longest(c.hist, pos, end, max_len, depth);
            if (m.len >= lz.min_len) {
                try w.copy(c.big, m.dist, m.len);
                pos += m.len;
            } else {
                try w.literal(c.hist[pos]);
                pos += 1;
            }
        }
        return w.finish();
    }
};

/// MSB-first reader; bits past the end read as 0 (callers check `left`).
const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    inline fn left(r: *const Reader) usize {
        return r.data.len * 8 - r.pos;
    }

    inline fn peek(r: *const Reader) u32 {
        const i = r.pos >> 3;
        var v: u64 = 0;
        inline for (0..5) |k| v = v << 8 | (if (i + k < r.data.len) r.data[i + k] else 0);
        return @truncate(v >> @intCast(8 - (r.pos & 7)));
    }
};

pub const Decoder = struct {
    big: bool,
    hist: []u8,
    offset: u32 = 0,

    pub fn init(gpa: std.mem.Allocator, big: bool) Error!Decoder {
        const hist = try gpa.alloc(u8, if (big) 65536 else 8192);
        @memset(hist, 0);
        return .{ .big = big, .hist = hist };
    }

    pub fn deinit(d: *Decoder, gpa: std.mem.Allocator) void {
        gpa.free(d.hist);
    }

    /// Copies read the history modulo its size; overruns, invalid codes and truncated
    /// tokens are error.BadData. Fewer than 8 trailing bits are padding.
    pub fn decompress(d: *Decoder, src: []const u8, flags: u8) Error![]const u8 {
        if (flags & bulk.packet_flushed != 0) {
            @memset(d.hist, 0);
            d.offset = 0;
        }
        if (flags & bulk.packet_at_front != 0) d.offset = 0;
        if (flags & bulk.packet_compressed == 0) return src;
        const size: u32 = @intCast(d.hist.len);
        const mask = size - 1;
        const start = d.offset;
        var pos = d.offset;
        var r: Reader = .{ .data = src };
        while (r.left() >= 8) {
            const v = r.peek();
            if (v >> 31 == 0 or v >> 30 == 0b10) {
                const lit: u8 = if (v >> 31 == 0) @truncate(v >> 24) else @as(u8, @truncate(v >> 23)) | 0x80;
                const nb: usize = if (v >> 31 == 0) 8 else 9;
                if (r.left() < nb or pos >= size) return error.BadData;
                r.pos += nb;
                d.hist[pos] = lit;
                pos += 1;
                continue;
            }
            var off: u32 = undefined;
            var nb: usize = undefined;
            if (d.big) {
                if (v >> 27 == 0x1F) {
                    off = (v >> 21) & 0x3F;
                    nb = 11;
                } else if (v >> 27 == 0x1E) {
                    off = ((v >> 19) & 0xFF) + 64;
                    nb = 13;
                } else if (v >> 28 == 0xE) {
                    off = ((v >> 17) & 0x7FF) + 320;
                    nb = 15;
                } else {
                    off = ((v >> 13) & 0xFFFF) + 2368;
                    nb = 19;
                }
            } else {
                if (v >> 28 == 0xF) {
                    off = (v >> 22) & 0x3F;
                    nb = 10;
                } else if (v >> 28 == 0xE) {
                    off = ((v >> 20) & 0xFF) + 64;
                    nb = 12;
                } else {
                    off = ((v >> 16) & 0x1FFF) + 320;
                    nb = 16;
                }
            }
            if (r.left() < nb) return error.BadData;
            r.pos += nb;
            const lv = r.peek();
            const ones: u32 = @clz(~lv);
            if (ones > @as(u32, if (d.big) 14 else 11)) return error.BadData;
            var len: u32 = 3;
            nb = 1;
            if (ones > 0) {
                const k: u5 = @intCast(ones + 1);
                nb = 2 * @as(usize, k);
                len = (@as(u32, 1) << k) | ((lv >> @intCast(32 - nb)) & ((@as(u32, 1) << k) - 1));
            }
            if (r.left() < nb) return error.BadData;
            r.pos += nb;
            if (off == 0 or size - pos < len) return error.BadData;
            var s = pos -% off;
            for (0..len) |_| {
                d.hist[pos] = d.hist[s & mask];
                pos += 1;
                s +%= 1;
            }
        }
        d.offset = pos;
        return d.hist[start..pos];
    }
};

test "writer packs the 3.1.8.4 examples" {
    var buf: [8]u8 = undefined;
    var w: Writer = .{ .out = &buf };
    try w.literal(0x56);
    try w.literal(0xE7);
    const n = try w.finish();
    try std.testing.expectEqualSlices(u8, &.{ 0x56, 0xB3, 0x80 }, buf[0..n]);
}

test "compressor round trips through the decoder (8K and 64K)" {
    const gpa = std.testing.allocator;
    for ([_]bool{ false, true }) |big| {
        var c = try Compressor.init(gpa, big);
        defer c.deinit(gpa);
        var d = try Decoder.init(gpa, big);
        defer d.deinit(gpa);
        var prng = std.Random.DefaultPrng.init(0x3108);
        var buf: [3000]u8 = undefined;
        for (0..40) |i| {
            const n = 1 + prng.random().uintLessThan(usize, buf.len);
            for (buf[0..n], 0..) |*b, k| b.* = if (i % 5 == 0) prng.random().int(u8) else @truncate((k / 3) % 17 + i);
            const r = c.compress(buf[0..n]);
            try std.testing.expect(r.data.len <= n);
            try std.testing.expectEqualSlices(u8, buf[0..n], try d.decompress(r.data, r.flags));
        }
    }
}
