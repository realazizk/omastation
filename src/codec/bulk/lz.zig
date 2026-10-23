//! Hash-chain longest-match finder for the MPPC (MS-RDPBCGR 3.1.8.2) and NCRUSH
//! (MS-RDPEGDI 3.1.8.1.2) compressors. The nearest of equally long matches wins.

const std = @import("std");

pub const none: u32 = std.math.maxInt(u32);
pub const min_len = 3;

pub const Match = struct { len: u32 = 0, dist: u32 = 0 };

pub const Chains = struct {
    /// Latest position per hash bucket, or `none`.
    head: []u32,
    prev: []u32,
    shift: u5,
    ins: u32 = 0,

    pub fn init(gpa: std.mem.Allocator, history: usize, hash_bits: u5) !Chains {
        const head = try gpa.alloc(u32, @as(usize, 1) << hash_bits);
        errdefer gpa.free(head);
        const prev = try gpa.alloc(u32, history);
        @memset(head, none);
        return .{ .head = head, .prev = prev, .shift = @intCast(@as(u6, 32) - hash_bits) };
    }

    pub fn deinit(c: *Chains, gpa: std.mem.Allocator) void {
        gpa.free(c.head);
        gpa.free(c.prev);
    }

    pub fn reset(c: *Chains) void {
        @memset(c.head, none);
        c.ins = 0;
    }

    inline fn hash(c: *const Chains, p: []const u8) u32 {
        const v = @as(u32, p[0]) | @as(u32, p[1]) << 8 | @as(u32, p[2]) << 16;
        return (v *% 0x9E37_79B1) >> c.shift;
    }

    /// Chain every position before `upto` whose 3 bytes lie before `end`.
    pub inline fn catchUp(c: *Chains, hist: []const u8, upto: u32, end: u32) void {
        while (c.ins < upto and c.ins + min_len <= end) : (c.ins += 1) {
            const h = c.hash(hist[c.ins..]);
            c.prev[c.ins] = c.head[h];
            c.head[h] = c.ins;
        }
    }

    /// Longest chained match (`min_len`..`max_len` bytes) at `pos`; len 0 if none.
    pub fn longest(c: *const Chains, hist: []const u8, pos: u32, end: u32, max_len: u32, depth: u32) Match {
        var best: Match = .{};
        if (end - pos < min_len) return best;
        const limit = @min(end - pos, max_len);
        var cand = c.head[c.hash(hist[pos..])];
        var left = depth;
        while (cand != none and cand < pos and left > 0) : (left -= 1) {
            if (best.len == 0 or hist[cand + best.len] == hist[pos + best.len]) {
                const n = matchLen(hist, cand, pos, limit);
                if (n > best.len and n >= min_len) {
                    best = .{ .len = n, .dist = pos - cand };
                    if (n == limit) break;
                }
            }
            const next = c.prev[cand];
            if (next >= cand) break;
            cand = next;
        }
        return best;
    }
};

/// Equal bytes at `a` and `b` (a < b), at most `limit`. Overlap acts as a replicating copy.
pub inline fn matchLen(hist: []const u8, a: u32, b: u32, limit: u32) u32 {
    var n: u32 = 0;
    while (n + 8 <= limit) {
        const x = std.mem.readInt(u64, hist[a + n ..][0..8], .little);
        const y = std.mem.readInt(u64, hist[b + n ..][0..8], .little);
        if (x != y) return n + @as(u32, @ctz(x ^ y) / 8);
        n += 8;
    }
    while (n < limit and hist[a + n] == hist[b + n]) n += 1;
    return n;
}

test "chains find the nearest longest match and respect max_len" {
    const gpa = std.testing.allocator;
    var c = try Chains.init(gpa, 64, 8);
    defer c.deinit(gpa);
    const hist = "abcdXabcdYabcdX".*;
    c.catchUp(&hist, 10, hist.len);
    const m = c.longest(&hist, 10, hist.len, 100, 16);
    try std.testing.expectEqual(Match{ .len = 5, .dist = 10 }, m);
    const m2 = c.longest(&hist, 10, hist.len, 4, 16);
    try std.testing.expectEqual(Match{ .len = 4, .dist = 5 }, m2);
}
