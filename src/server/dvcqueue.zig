//! Dynamic channel output waiting for the send window: per-channel queues of DVC PDUs
//! (MS-RDPEDYC 2.2.3) in four priority classes, sharing each flush by weighted fair queuing
//! as a Windows server does. Compression happens when a PDU is taken, so packets stay in order.

const std = @import("std");
const dvc = @import("../proto/dvc.zig");

/// MS-RDPEDYC 2.2.2.1 Pri: 5, 15, 25 and 55 % of the bandwidth when all classes have data.
pub const Priority = enum(u2) {
    low = 0,
    medium = 1,
    high = 2,
    realtime = 3,
};

const Chan = struct {
    id: u32,
    class: Priority,
    compress: bool,
    /// DVC PDUs back to back; the first `head` bytes are already taken.
    buf: std.ArrayList(u8) = .empty,
    head: usize = 0,
    /// PDU lengths; the first `next` are already taken.
    lens: std.ArrayList(u16) = .empty,
    next: usize = 0,

    fn waiting(ch: *const Chan) usize {
        return ch.buf.items.len - ch.head;
    }

    fn deinit(ch: *Chan, gpa: std.mem.Allocator) void {
        ch.buf.deinit(gpa);
        ch.lens.deinit(gpa);
    }

    fn compact(ch: *Chan) void {
        if (ch.head == ch.buf.items.len) {
            ch.buf.clearRetainingCapacity();
            ch.lens.clearRetainingCapacity();
            ch.head = 0;
            ch.next = 0;
            return;
        }
        if (ch.head < 64 << 10 or ch.head * 2 < ch.buf.items.len) return;
        const rest = ch.buf.items.len - ch.head;
        std.mem.copyForwards(u8, ch.buf.items[0..rest], ch.buf.items[ch.head..]);
        ch.buf.shrinkRetainingCapacity(rest);
        ch.head = 0;
        const n = ch.lens.items.len - ch.next;
        std.mem.copyForwards(u16, ch.lens.items[0..n], ch.lens.items[ch.next..]);
        ch.lens.shrinkRetainingCapacity(n);
        ch.next = 0;
    }
};

/// The next PDU to write (peek), valid until the queue changes.
pub const Item = struct {
    id: u32,
    class: Priority,
    compress: bool,
    pdu: []const u8,
    chan: usize,
};

pub const WriteQueue = struct {
    chans: std.ArrayList(Chan) = .empty,
    /// Per class, the index into `chans` of the channel that sends next.
    turn: [4]usize = @splat(0),
    charges: [4]u64 = @splat(0),
    /// PriorityCharge0..3.
    weights: [4]u16 = dvc.priority_charges,
    total: usize = 0,

    pub fn deinit(q: *WriteQueue, gpa: std.mem.Allocator) void {
        for (q.chans.items) |*ch| ch.deinit(gpa);
        q.chans.deinit(gpa);
        q.* = .{};
    }

    fn find(q: *const WriteQueue, id: u32) ?usize {
        for (q.chans.items, 0..) |ch, i| if (ch.id == id) return i;
        return null;
    }

    pub fn waiting(q: *const WriteQueue, id: u32) usize {
        const i = q.find(id) orelse return 0;
        return q.chans.items[i].waiting();
    }

    pub fn push(q: *WriteQueue, gpa: std.mem.Allocator, id: u32, class: Priority, compress: bool, msg: []const u8) !void {
        const i = q.find(id) orelse blk: {
            try q.chans.append(gpa, .{ .id = id, .class = class, .compress = compress });
            break :blk q.chans.items.len - 1;
        };
        const ch = &q.chans.items[i];
        ch.class = class;
        ch.compress = compress;
        ch.compact();
        const before = ch.buf.items.len;
        const lens_before = ch.lens.items.len;
        const Sink = struct {
            gpa: std.mem.Allocator,
            ch: *Chan,
            pub fn pdu(s: @This(), p: []const u8) !void {
                try s.ch.buf.appendSlice(s.gpa, p);
                try s.ch.lens.append(s.gpa, @intCast(p.len));
            }
        };
        dvc.writeData(gpa, id, msg, Sink{ .gpa = gpa, .ch = ch }) catch |err| {
            // All of the message or none of it.
            ch.buf.shrinkRetainingCapacity(before);
            ch.lens.shrinkRetainingCapacity(lens_before);
            return err;
        };
        q.total += ch.buf.items.len - before;
    }

    pub fn beginFlush(q: *WriteQueue) void {
        q.charges = @splat(0);
    }

    pub fn peek(q: *WriteQueue) ?Item {
        if (q.total == 0) return null;
        // Lowest charge wins; ties go to the higher class.
        var best: ?usize = null;
        for (0..4) |c| {
            if (!q.classWaiting(@intCast(c))) continue;
            if (best == null or q.charges[c] <= q.charges[best.?]) best = c;
        }
        const c = best orelse return null;
        const i = q.nextOfClass(@intCast(c));
        const ch = &q.chans.items[i];
        const len = ch.lens.items[ch.next];
        return .{ .id = ch.id, .class = ch.class, .compress = ch.compress, .pdu = ch.buf.items[ch.head..][0..len], .chan = i };
    }

    /// Charges the class of `it` (from peek) and passes the turn to its next channel.
    pub fn take(q: *WriteQueue, it: Item) void {
        const ch = &q.chans.items[it.chan];
        ch.head += it.pdu.len;
        ch.next += 1;
        q.total -= it.pdu.len;
        const c = @backingInt(it.class);
        q.charges[c] += @as(u64, q.weights[c]) * it.pdu.len;
        q.turn[c] = it.chan + 1;
    }

    fn classWaiting(q: *const WriteQueue, c: u2) bool {
        for (q.chans.items) |ch| if (@backingInt(ch.class) == c and ch.waiting() > 0) return true;
        return false;
    }

    fn nextOfClass(q: *WriteQueue, c: u2) usize {
        const n = q.chans.items.len;
        const start = q.turn[c] % n;
        var k: usize = 0;
        while (k < n) : (k += 1) {
            const i = (start + k) % n;
            const ch = &q.chans.items[i];
            if (@backingInt(ch.class) == c and ch.waiting() > 0) return i;
        }
        unreachable; // classWaiting said so
    }

    /// Drops a closed channel's queued (still uncompressed) data; returns the bytes dropped.
    pub fn drop(q: *WriteQueue, gpa: std.mem.Allocator, id: u32) usize {
        const i = q.find(id) orelse return 0;
        var ch = q.chans.orderedRemove(i);
        const n = ch.waiting();
        ch.deinit(gpa);
        q.total -= n;
        for (&q.turn) |*t| {
            if (t.* > i) t.* -= 1;
        }
        return n;
    }
};

const testing = std.testing;

/// Runs one flush of `budget` bytes; returns bytes taken per channel id (ids < 8).
fn flush(q: *WriteQueue, budget: usize) [8]usize {
    var got: [8]usize = @splat(0);
    q.beginFlush();
    var left = budget;
    while (left > 0) {
        const it = q.peek() orelse break;
        got[it.id] += it.pdu.len;
        left -|= it.pdu.len;
        q.take(it);
    }
    return got;
}

test "WFQ shares a flush 5 / 15 / 25 / 55 % across four busy classes" {
    const gpa = testing.allocator;
    var q: WriteQueue = .{};
    defer q.deinit(gpa);
    const big = try gpa.alloc(u8, 4 << 20);
    defer gpa.free(big);
    @memset(big, 0xab);
    for (0..4) |c| try q.push(gpa, @intCast(c + 1), @fromBackingInt(@intCast(c)), true, big);
    const got = flush(&q, 2_000_000);
    var sum: usize = 0;
    for (got) |g| sum += g;
    const shares = [_]f64{ 0.05, 0.15, 0.25, 0.55 };
    for (shares, 0..) |s, c| {
        const share = @as(f64, @floatFromInt(got[c + 1])) / @as(f64, @floatFromInt(sum));
        try testing.expectApproxEqAbs(s, share, 0.01);
    }
}

test "WFQ: real-time first, a lone class takes the whole flush, channels of a class alternate" {
    const gpa = testing.allocator;
    var q: WriteQueue = .{};
    defer q.deinit(gpa);
    var msg: [5000]u8 = undefined;
    @memset(&msg, 1);
    try q.push(gpa, 1, .low, false, &msg);
    try q.push(gpa, 3, .realtime, false, msg[0..400]);
    q.beginFlush();
    const first = q.peek().?;
    try testing.expectEqual(@as(u32, 3), first.id);
    q.take(first);
    const got = flush(&q, 1 << 20);
    try testing.expect(got[1] > 5000);
    try testing.expectEqual(@as(usize, 0), q.total);
    try q.push(gpa, 4, .medium, true, &msg);
    try q.push(gpa, 5, .medium, true, &msg);
    q.beginFlush();
    var order: [6]u32 = undefined;
    for (&order) |*o| {
        const it = q.peek().?;
        o.* = it.id;
        q.take(it);
    }
    try testing.expectEqualSlices(u32, &.{ 4, 5, 4, 5, 4, 5 }, &order);
}

test "queued messages leave as ordered DVC PDUs; drop discards a closed channel" {
    const gpa = testing.allocator;
    var q: WriteQueue = .{};
    defer q.deinit(gpa);
    var msg: [4000]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i);
    try q.push(gpa, 9, .low, true, &msg);
    try q.push(gpa, 9, .low, true, "short");
    try testing.expectEqual(q.total, q.waiting(9));
    var r = dvc.Reassembler{};
    defer r.deinit(gpa);
    var msgs: usize = 0;
    q.beginFlush();
    while (q.peek()) |it| {
        try testing.expect(it.pdu.len <= dvc.max_pdu);
        const m = switch (try dvc.parseClientPdu(it.pdu)) {
            .data_first => |f| try r.first(gpa, f.total, f.data),
            .data => |d| try r.data(gpa, d.data),
            else => return error.TestUnexpectedResult,
        };
        if (m) |whole| {
            if (msgs == 0) try testing.expectEqualSlices(u8, &msg, whole) else try testing.expectEqualStrings("short", whole);
            msgs += 1;
        }
        q.take(it);
    }
    try testing.expectEqual(@as(usize, 2), msgs);
    try q.push(gpa, 2, .low, true, &msg);
    try q.push(gpa, 7, .high, true, &msg);
    try testing.expect(q.drop(gpa, 2) > 4000);
    try testing.expectEqual(q.waiting(7), q.total);
    try testing.expectEqual(@as(u32, 7), q.peek().?.id);
}
