//! Client pointer updates: shapes, the pointer cache and server-side moves
//! (MS-RDPBCGR 2.2.9.1.1.4, 2.2.9.1.2.1.4 - .11). Shapes go out only on change.

const std = @import("std");
const caps = @import("../proto/caps.zig");
const ptr = @import("../proto/pointer.zig");
const bytes = @import("../core/bytes.zig");
const cursor_mod = @import("../session/cursor.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.pointer);

/// Advertised pointerCacheSize; the effective size is the smaller of both sides.
pub const server_cache_size: u16 = 25;

pub const Caps = struct {
    /// 0: no New Pointer Updates, colour pointers at index 0 (MS-RDPBCGR 2.2.7.1.5).
    cache_size: u16,
    max_size: u16,

    pub fn of(cc: *const caps.ClientCaps, fastpath_output: bool) Caps {
        var max = ptr.maxSize(cc.large_pointer_flags, cc.multifragment_max_request_size);
        // A slow-path Update PDU is not fragmented: no 384x384 pointers.
        if (!fastpath_output) max = @min(max, ptr.max_small);
        return .{ .cache_size = @min(cc.pointer_cache_size, server_cache_size), .max_size = max };
    }

    /// 24 bpp for inverted pointers and colour-only clients, as a Windows server sends them.
    pub fn xorBpp(c: Caps, look: ptr.Look) u16 {
        return if (c.cache_size == 0 or look == .inverted) 24 else 32;
    }
};

/// Server-side mirror of the client's pointer cache, keyed by shape hash, LRU eviction.
pub const Cache = struct {
    pub const max_entries = server_cache_size;
    const Entry = struct { hash: u64 = 0, used: bool = false, stamp: u64 = 0 };

    entries: [max_entries]Entry = @splat(.{}),
    size: u16 = 0,
    clock: u64 = 0,

    pub fn reset(c: *Cache, size: u16) void {
        c.* = .{ .size = @min(size, max_entries) };
    }

    pub fn lookup(c: *Cache, hash: u64) ?u16 {
        for (c.entries[0..c.size], 0..) |*e, i| {
            if (e.used and e.hash == hash) {
                c.clock += 1;
                e.stamp = c.clock;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn insert(c: *Cache, hash: u64) u16 {
        std.debug.assert(c.size > 0);
        var victim: usize = 0;
        for (c.entries[0..c.size], 0..) |*e, i| {
            if (!e.used) {
                victim = i;
                break;
            }
            if (e.stamp < c.entries[victim].stamp) victim = i;
        }
        c.clock += 1;
        c.entries[victim] = .{ .hash = hash, .used = true, .stamp = c.clock };
        return @intCast(victim);
    }

    pub fn drop(c: *Cache, index: u16) void {
        if (index < c.size) c.entries[index] = .{};
    }
};

pub const Shown = enum { unknown, hidden, shape };

pub const State = struct {
    caps: Caps = .{ .cache_size = 0, .max_size = ptr.max_legacy },
    cache: Cache = .{},
    shown: Shown = .unknown,
    shape_serial: u32 = 0,
    warp_serial: u32 = 0,
    sent_shapes: u32 = 0,
    sent_cached: u32 = 0,
    sent_positions: u32 = 0,
    sent_hidden: u32 = 0,
    sent_default: u32 = 0,
};

/// One pointer update; for `.shape` the caller encodes the body.
pub const Decision = union(enum) {
    none,
    hidden,
    default,
    cached: u16,
    shape: struct { kind: ptr.Kind, index: u16 },
};

/// A reactivation clears the client's caches, so the pointer is sent again.
pub fn reset(st: *State, cc: *const caps.ClientCaps, fastpath_output: bool) void {
    st.caps = Caps.of(cc, fastpath_output);
    st.cache.reset(st.caps.cache_size);
    st.shown = .unknown;
}

/// Updates the cache.
pub fn decideShape(st: *State, w: u16, h: u16, hash: u64) Decision {
    if (w > st.caps.max_size or h > st.caps.max_size) return .default;
    if (st.caps.cache_size == 0) return .{ .shape = .{ .kind = .color, .index = 0 } };
    if (st.cache.lookup(hash)) |i| return .{ .cached = i };
    const i = st.cache.insert(hash);
    const kind: ptr.Kind = if (w > ptr.max_small or h > ptr.max_small) .large else .new;
    return .{ .shape = .{ .kind = kind, .index = i } };
}

/// Idle until established, during reactivation and while output is suppressed.
pub fn pump(c: *Conn, t: *const cursor_mod.Tracker) conn_mod.Error!void {
    if (!c.established or c.reactivating or c.output_suppressed) return;
    const st = &c.pointer;
    // Server moves from before (re)activation are not replayed.
    if (st.shown == .unknown) st.warp_serial = t.warp_serial;
    if (t.painting or t.hidden or t.image == null) {
        // Painted into the frames, or hidden: the client draws no pointer.
        st.warp_serial = t.warp_serial;
        if (st.shown != .hidden) {
            try c.queueUpdate(.ptr_null, &.{});
            st.shown = .hidden;
            st.shape_serial = t.shape_serial;
            st.sent_hidden += 1;
            log.debug("{s}: pointer hidden ({s})", .{ c.peer, if (t.painting) "painted into the frames" else "no cursor" });
            try c.flush();
        }
        return;
    }
    var queued = false;
    if (st.shown != .shape or st.shape_serial != t.shape_serial) {
        try sendShape(c, &t.image.?);
        st.shown = .shape;
        st.shape_serial = t.shape_serial;
        queued = true;
    }
    if (st.warp_serial != t.warp_serial) {
        st.warp_serial = t.warp_serial;
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u16, buf[0..2], clamp16(t.warp_x), .little);
        std.mem.writeInt(u16, buf[2..4], clamp16(t.warp_y), .little);
        try c.queueUpdate(.ptr_position, &buf);
        st.sent_positions += 1;
        log.debug("{s}: pointer moved by the server to {d},{d}", .{ c.peer, t.warp_x, t.warp_y });
        queued = true;
    }
    if (queued) try c.flush();
}

fn clamp16(v: i32) u16 {
    return @intCast(std.math.clamp(v, 0, std.math.maxInt(u16)));
}

fn sendShape(c: *Conn, img: *const cursor_mod.Image) conn_mod.Error!void {
    const st = &c.pointer;
    switch (decideShape(st, img.width, img.height, img.hash)) {
        .none, .hidden => unreachable,
        .default => {
            log.debug("{s}: {d}x{d} pointer is too big for the client (max {d}): default pointer", .{ c.peer, img.width, img.height, st.caps.max_size });
            try c.queueUpdate(.ptr_default, &.{});
            st.sent_default += 1;
        },
        .cached => |i| {
            var buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &buf, i, .little);
            try c.queueUpdate(.ptr_cached, &buf);
            st.sent_cached += 1;
            log.debug("{s}: pointer from cache entry {d}", .{ c.peer, i });
        },
        .shape => |s| {
            var shape = ptr.encode(c.gpa, .{
                .width = img.width,
                .height = img.height,
                .stride = img.stride,
                .pixels = img.pixels,
                .hot_x = img.hot_x,
                .hot_y = img.hot_y,
                .look = img.look,
            }, st.caps.xorBpp(img.look)) catch |err| {
                if (s.kind != .color) st.cache.drop(s.index);
                return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    error.InvalidSize => c.queueUpdate(.ptr_default, &.{}),
                };
            };
            defer shape.deinit(c.gpa);
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(c.gpa);
            try body.ensureTotalCapacity(c.gpa, ptr.shapeSize(s.kind, &shape));
            var w = bytes.Writer.init(&body, c.gpa);
            try ptr.writeShape(&w, s.kind, s.index, &shape);
            const kind: Conn.Update = switch (s.kind) {
                .color => .ptr_color,
                .new => .ptr_new,
                .large => .ptr_large,
            };
            c.queueUpdate(kind, body.items) catch |err| {
                if (s.kind != .color) st.cache.drop(s.index);
                return err;
            };
            st.sent_shapes += 1;
            log.debug("{s}: pointer {t} {d}x{d} hot {d},{d} xorBpp {d} -> cache entry {d}", .{ c.peer, s.kind, img.width, img.height, img.hot_x, img.hot_y, shape.xor_bpp, s.index });
        },
    }
}

const testing = std.testing;

test "Caps: cache of the smaller side, colour pointers without pointerCacheSize" {
    var cc: caps.ClientCaps = .{ .pointer_cache_size = 21, .large_pointer_flags = 3, .multifragment_max_request_size = 0x9482B };
    var c = Caps.of(&cc, true);
    try testing.expectEqual(@as(u16, 21), c.cache_size);
    try testing.expectEqual(@as(u16, 384), c.max_size);
    try testing.expectEqual(@as(u16, 32), c.xorBpp(.normal));
    try testing.expectEqual(@as(u16, 24), c.xorBpp(.inverted));
    try testing.expectEqual(@as(u16, 96), Caps.of(&cc, false).max_size);
    cc.pointer_cache_size = 100;
    try testing.expectEqual(@as(u16, 25), Caps.of(&cc, true).cache_size);
    cc.pointer_cache_size = 0;
    c = Caps.of(&cc, true);
    try testing.expectEqual(@as(u16, 0), c.cache_size);
    try testing.expectEqual(@as(u16, 24), c.xorBpp(.normal));
}

test "Cache: hits, free entries first, then the least recently used" {
    var c: Cache = .{};
    c.reset(3);
    try testing.expectEqual(@as(?u16, null), c.lookup(10));
    try testing.expectEqual(@as(u16, 0), c.insert(10));
    try testing.expectEqual(@as(u16, 1), c.insert(11));
    try testing.expectEqual(@as(u16, 2), c.insert(12));
    try testing.expectEqual(@as(?u16, 0), c.lookup(10)); // 10 now most recent
    try testing.expectEqual(@as(u16, 1), c.insert(13)); // evicts 11
    try testing.expectEqual(@as(?u16, null), c.lookup(11));
    try testing.expectEqual(@as(?u16, 1), c.lookup(13));
    c.drop(1);
    try testing.expectEqual(@as(?u16, null), c.lookup(13));
    try testing.expectEqual(@as(u16, 1), c.insert(14)); // the freed entry
}

test "decideShape: new, cached, large, default and colour" {
    var st: State = .{};
    const cc: caps.ClientCaps = .{ .pointer_cache_size = 25, .large_pointer_flags = 3, .multifragment_max_request_size = 0x9482B };
    reset(&st, &cc, true);
    try testing.expectEqualDeep(Decision{ .shape = .{ .kind = .new, .index = 0 } }, decideShape(&st, 48, 48, 1));
    try testing.expectEqualDeep(Decision{ .shape = .{ .kind = .new, .index = 1 } }, decideShape(&st, 32, 32, 2));
    try testing.expectEqualDeep(Decision{ .cached = 0 }, decideShape(&st, 48, 48, 1));
    try testing.expectEqualDeep(Decision{ .shape = .{ .kind = .large, .index = 2 } }, decideShape(&st, 97, 20, 3));
    try testing.expectEqualDeep(Decision.default, decideShape(&st, 385, 20, 4));
    const legacy: caps.ClientCaps = .{ .pointer_cache_size = 25 };
    reset(&st, &legacy, true);
    try testing.expectEqualDeep(Decision.default, decideShape(&st, 33, 32, 5));
    try testing.expectEqualDeep(Decision{ .shape = .{ .kind = .new, .index = 0 } }, decideShape(&st, 32, 32, 5));
    const old: caps.ClientCaps = .{ .large_pointer_flags = 1, .multifragment_max_request_size = 0xFFFF };
    reset(&st, &old, true);
    try testing.expectEqualDeep(Decision{ .shape = .{ .kind = .color, .index = 0 } }, decideShape(&st, 32, 32, 6));
    try testing.expectEqualDeep(Decision{ .shape = .{ .kind = .color, .index = 0 } }, decideShape(&st, 32, 32, 6));
}

test "reset starts the cache over (reactivation)" {
    var st: State = .{};
    const cc: caps.ClientCaps = .{ .pointer_cache_size = 25 };
    reset(&st, &cc, true);
    _ = decideShape(&st, 16, 16, 9);
    st.shown = .shape;
    reset(&st, &cc, true);
    try testing.expectEqual(Shown.unknown, st.shown);
    try testing.expectEqualDeep(Decision{ .shape = .{ .kind = .new, .index = 0 } }, decideShape(&st, 16, 16, 9));
}
