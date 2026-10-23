//! Per-connection outbound byte queue, drained to the non-blocking socket in
//! FIFO order. Unbounded; memory is capped upstream.

const std = @import("std");

/// Compact once this many consumed bytes are at least half the buffer.
const compact_min: usize = 64 << 10;

pub const Error = error{OutOfMemory};

pub const SendQueue = struct {
    buf: std.ArrayList(u8) = .empty,
    /// Bytes of `buf` already written.
    head: usize = 0,
    pushed: u64 = 0,
    consumed: u64 = 0,
    peak: usize = 0,

    pub fn deinit(q: *SendQueue, gpa: std.mem.Allocator) void {
        q.buf.deinit(gpa);
        q.* = .{};
    }

    pub fn len(q: *const SendQueue) usize {
        return q.buf.items.len - q.head;
    }

    pub fn bytes(q: *const SendQueue) []const u8 {
        return q.buf.items[q.head..];
    }

    /// Moves `out`'s bytes to the queue, keeping both capacities; on OutOfMemory `out` is untouched.
    pub fn push(q: *SendQueue, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) Error!void {
        const n = out.items.len;
        if (n == 0) return;
        try q.buf.appendSlice(gpa, out.items);
        out.clearRetainingCapacity();
        q.pushed += n;
        q.peak = @max(q.peak, q.len());
    }

    /// `n` bytes from the front were written.
    pub fn consume(q: *SendQueue, n: usize) void {
        std.debug.assert(n <= q.len());
        q.head += n;
        q.consumed += n;
        if (q.head == q.buf.items.len) {
            q.buf.clearRetainingCapacity();
            q.head = 0;
        } else if (q.head >= compact_min and q.head * 2 >= q.buf.items.len) {
            const rest = q.buf.items.len - q.head;
            std.mem.copyForwards(u8, q.buf.items[0..rest], q.buf.items[q.head..]);
            q.buf.shrinkRetainingCapacity(rest);
            q.head = 0;
        }
    }
};

const testing = std.testing;

fn list(gpa: std.mem.Allocator, s: []const u8) !std.ArrayList(u8) {
    var l: std.ArrayList(u8) = .empty;
    try l.appendSlice(gpa, s);
    return l;
}

test "first in, first out; buffers keep their capacity" {
    const gpa = testing.allocator;
    var q: SendQueue = .{};
    defer q.deinit(gpa);
    var out = try list(gpa, "abc");
    defer out.deinit(gpa);
    const cap = out.capacity;
    try q.push(gpa, &out);
    try testing.expectEqual(@as(usize, 0), out.items.len);
    try testing.expectEqual(cap, out.capacity);
    try out.appendSlice(gpa, "defg");
    try q.push(gpa, &out);
    try testing.expectEqualStrings("abcdefg", q.bytes());
    q.consume(2);
    try testing.expectEqualStrings("cdefg", q.bytes());
    q.consume(5);
    try testing.expectEqual(@as(usize, 0), q.len());
    try testing.expectEqual(@as(u64, 7), q.consumed);
    try testing.expectEqual(@as(usize, 7), q.peak);
}

test "consumed bytes are compacted away, the rest kept in order" {
    const gpa = testing.allocator;
    var q: SendQueue = .{};
    defer q.deinit(gpa);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(0x5e9d_0001);
    const r = prng.random();
    var model: std.ArrayList(u8) = .empty;
    defer model.deinit(gpa);
    var at: usize = 0;
    for (0..2000) |_| {
        const n = r.uintLessThan(usize, 9000);
        for (0..n) |_| try out.append(gpa, r.int(u8));
        try model.appendSlice(gpa, out.items);
        try q.push(gpa, &out);
        const take = r.uintLessThan(usize, q.len() + 1);
        try testing.expectEqualSlices(u8, model.items[at..][0..take], q.bytes()[0..take]);
        q.consume(take);
        at += take;
        try testing.expect(q.buf.items.len <= 2 * q.len() + compact_min + 9000);
    }
    try testing.expectEqualSlices(u8, model.items[at..], q.bytes());
}
