//! The session pointer for the RDP client: cursor image, hidden state and server-side warps.
//! The client draws the pointer; images come from the compositor's per-output cursor capture.

const std = @import("std");
const ptr = @import("../proto/pointer.zig");

const log = std.log.scoped(.cursor);

pub const Mode = enum {
    /// Painted into the frames until the cursor capture gives a real image, then the client draws.
    auto,
    /// The client always draws the pointer; an empty image hides it.
    client,
    /// Painted into the frames, the client's pointer hidden, no capture.
    paint,
};

/// The current cursor image; owns `pixels`.
pub const Image = struct {
    width: u16,
    height: u16,
    stride: usize,
    /// Premultiplied ARGB8888 (B, G, R, A), top-down.
    pixels: []u8,
    /// In image pixels.
    hot_x: u16,
    hot_y: u16,
    look: ptr.Look,
    /// Identifies the shape for the client's pointer cache.
    hash: u64,
};

/// Borrowed, from the output the cursor is on.
pub const Captured = struct {
    width: u32,
    height: u32,
    stride: usize,
    pixels: []const u8,
    hot_x: i32,
    hot_y: i32,
};

/// What Hyprland draws when a cursor image arrives, as reported by the plugin.
pub const Shown = union(enum) {
    /// No plugin: the capture is trusted.
    unknown,
    /// None, hidden, or fully transparent.
    none,
    image: struct { width: u32, height: u32 },
};

/// How long a client position counts as possibly coming back.
pub const echo_ms: i64 = 1000;

pub const max_side = 1024;

/// Wait for a real image before painting a cursor Hyprland draws but its capture gave empty.
pub const fallback_after_ms: i64 = 250;

pub const Tracker = struct {
    gpa: std.mem.Allocator,
    mode: Mode,
    /// A non-transparent image arrived: the capture works.
    works: bool = false,
    /// An image arrived while the cursor was over its output.
    judged: bool = false,
    /// The cursor is painted into the frames and the client's pointer hidden.
    painting: bool,
    /// Auto mode paints because Hyprland draws a cursor its capture gave empty.
    fallback: bool = false,
    logged_fallback: bool = false,
    /// An empty image came while Hyprland drew a cursor of this size; painted unless a real one follows.
    suspect_since_ms: ?i64 = null,
    suspect_size: [2]u32 = .{ 0, 0 },
    image: ?Image = null,
    hidden: bool = false,
    look: ptr.Look = .normal,
    /// Bumped whenever image, hidden or look change.
    shape_serial: u32 = 0,
    /// The last server-side move, in client desktop coordinates.
    warp_x: i32 = 0,
    warp_y: i32 = 0,
    warp_serial: u32 = 0,
    /// Ring of the client's recent absolute positions.
    echoes: [64]Echo = undefined,
    echo_head: u8 = 0,
    echo_len: u8 = 0,
    /// Positions are compared only once the client moved the pointer.
    armed: bool = false,
    /// A warp to the last warp position again is news to the client.
    moved_since_warp: bool = false,
    logged_empty: bool = false,

    const Echo = struct { x: i32, y: i32, ms: i64 };

    pub fn init(gpa: std.mem.Allocator, mode: Mode) Tracker {
        return .{ .gpa = gpa, .mode = mode, .painting = mode != .client };
    }

    pub fn deinit(t: *Tracker) void {
        if (t.image) |img| t.gpa.free(img.pixels);
        t.image = null;
    }

    /// The client cannot draw the pointer. True when `painting` changed.
    pub fn paintForGood(t: *Tracker, comptime why: []const u8, args: anytype) bool {
        if (t.mode == .paint) return false;
        log.info(why ++ ": the cursor is painted into the frames", args);
        t.mode = .paint;
        const was = t.painting;
        t.painting = true;
        return !was;
    }

    /// `shown` is what Hyprland draws meanwhile. True when `painting` changed.
    pub fn onImage(t: *Tracker, img: Captured, shown: Shown, now_ms: i64) std.mem.Allocator.Error!bool {
        if (t.mode == .paint) return false;
        // Larger than any client accepts (384) still counts: it gets the default pointer.
        if (img.width == 0 or img.height == 0 or img.width > max_side or img.height > max_side or
            img.stride < @as(usize, img.width) * 4 or img.pixels.len < img.stride * (img.height - 1) + @as(usize, img.width) * 4)
        {
            log.debug("ignoring a {d}x{d} cursor image", .{ img.width, img.height });
            return false;
        }
        switch (classify(img)) {
            // Hyprland renders opaque black for a cursor not over its output.
            .black => return false,
            .empty => return t.onEmpty(img, shown, now_ms),
            .shape => {},
        }
        t.judged = true;
        t.suspect_since_ms = null;
        try t.store(img);
        t.hidden = false;
        t.shape_serial +%= 1;
        if (!t.works) {
            t.works = true;
            log.info("the compositor's cursor capture works: the client draws the pointer", .{});
        }
        if (t.fallback) log.debug("the cursor capture gives the cursor again: drawn by the client", .{});
        t.fallback = false;
        if (t.painting and t.mode != .paint) {
            t.painting = false;
            return true;
        }
        return false;
    }

    /// Hidden, unless Hyprland draws a cursor its capture failed to render. `shown` is queried after the
    /// image (hide_on_key_press toggles within ~100 ms), so painting waits `fallback_after_ms`.
    fn onEmpty(t: *Tracker, img: Captured, shown: Shown, now_ms: i64) bool {
        if (!t.works and t.mode != .client) {
            // Stock Hyprland's capture, or a hidden cursor.
            t.judged = true;
            if (!t.logged_empty) {
                t.logged_empty = true;
                log.info("the compositor's cursor images are empty so far: the cursor is painted into the frames", .{});
            }
            return false;
        }
        switch (shown) {
            .unknown, .none => {},
            .image => |s| {
                // Another size drawn by now: this image predates a cursor change.
                if (s.width != img.width or s.height != img.height) {
                    log.debug("ignoring an empty {d}x{d} cursor image: Hyprland draws a {d}x{d} one by now", .{ img.width, img.height, s.width, s.height });
                    return false;
                }
                // Never hide a cursor Hyprland draws: auto mode paints it unless its image
                // follows; client mode trusts the capture.
                if (t.mode == .auto) {
                    t.judged = true;
                    if (t.fallback) return false;
                    if (t.suspect_since_ms == null) t.suspect_since_ms = now_ms;
                    t.suspect_size = .{ img.width, img.height };
                    return false;
                }
            },
        }
        t.judged = true;
        t.suspect_since_ms = null;
        if (!t.hidden) {
            t.hidden = true;
            t.shape_serial +%= 1;
        }
        return false;
    }

    /// Call regularly. After `fallback_after_ms` with no real image: paint if Hyprland still draws
    /// that cursor, else hidden. True when `painting` changed.
    pub fn confirmFallback(t: *Tracker, now_ms: i64, shown: Shown) bool {
        const since = t.suspect_since_ms orelse return false;
        if (now_ms - since < fallback_after_ms) return false;
        t.suspect_since_ms = null;
        switch (shown) {
            .image => |s| if (s.width == t.suspect_size[0] and s.height == t.suspect_size[1]) {
                if (!t.logged_fallback) {
                    t.logged_fallback = true;
                    log.info("Hyprland draws a {d}x{d} cursor that its cursor capture gives empty: it is painted into the frames until the capture gives it", .{ s.width, s.height });
                }
                t.fallback = true;
                if (t.painting) return false;
                t.painting = true;
                return true;
            },
            .none => if (!t.hidden) {
                t.hidden = true;
                t.shape_serial +%= 1;
            },
            .unknown => {},
        }
        return false;
    }

    pub fn confirming(t: *const Tracker) bool {
        return t.suspect_since_ms != null;
    }

    /// In image pixels; Hyprland sends it after the image it belongs to.
    pub fn setHotspot(t: *Tracker, x: i32, y: i32) void {
        const img = &(t.image orelse return);
        const hx: u16 = @intCast(std.math.clamp(x, 0, @as(i32, img.width) - 1));
        const hy: u16 = @intCast(std.math.clamp(y, 0, @as(i32, img.height) - 1));
        if (hx == img.hot_x and hy == img.hot_y) return;
        img.hot_x = hx;
        img.hot_y = hy;
        img.hash = hashOf(img.width, img.height, hx, hy, img.look, img.pixels, img.stride);
        if (!t.hidden) t.shape_serial +%= 1;
    }

    /// Hyprland cursor:invert.
    pub fn setLook(t: *Tracker, look: ptr.Look) void {
        if (t.look == look) return;
        t.look = look;
        if (t.image) |*img| {
            img.look = look;
            img.hash = hashOf(img.width, img.height, img.hot_x, img.hot_y, look, img.pixels, img.stride);
            t.shape_serial +%= 1;
        }
    }

    fn store(t: *Tracker, img: Captured) std.mem.Allocator.Error!void {
        const w: u16 = @intCast(img.width);
        const h: u16 = @intCast(img.height);
        const stride = @as(usize, w) * 4;
        const pixels = try t.gpa.alloc(u8, stride * h);
        for (0..h) |y| @memcpy(pixels[y * stride ..][0..stride], img.pixels[y * img.stride ..][0..stride]);
        if (t.image) |old| t.gpa.free(old.pixels);
        const hx: u16 = @intCast(std.math.clamp(img.hot_x, 0, @as(i32, w) - 1));
        const hy: u16 = @intCast(std.math.clamp(img.hot_y, 0, @as(i32, h) - 1));
        t.image = .{
            .width = w,
            .height = h,
            .stride = stride,
            .pixels = pixels,
            .hot_x = hx,
            .hot_y = hy,
            .look = t.look,
            .hash = hashOf(w, h, hx, hy, t.look, pixels, stride),
        };
    }

    /// TS_POINTER_EVENT, in client desktop coordinates.
    pub fn onClientMotion(t: *Tracker, x: i32, y: i32, now_ms: i64) void {
        t.armed = true;
        t.moved_since_warp = true;
        const i = (t.echo_head + t.echo_len) % t.echoes.len;
        t.echoes[i] = .{ .x = x, .y = y, .ms = now_ms };
        if (t.echo_len < t.echoes.len) t.echo_len += 1 else t.echo_head = @intCast((t.echo_head + 1) % t.echoes.len);
    }

    /// The pointer stays where the last client left it, which is not a server-side move.
    pub fn onNewClient(t: *Tracker) void {
        t.armed = false;
        t.echo_len = 0;
    }

    /// TS_RELPOINTER_EVENT: the position that follows is the server's to tell.
    pub fn onClientRelative(t: *Tracker) void {
        t.armed = true;
        t.moved_since_warp = true;
    }

    /// Client desktop coordinates, within `tolerance`. A position not among the client's
    /// recent ones is a server-side move.
    pub fn onPosition(t: *Tracker, x: i32, y: i32, tolerance: i32, now_ms: i64) void {
        if (!t.armed) return;
        while (t.echo_len > 0 and now_ms - t.echoes[t.echo_head].ms > echo_ms) {
            t.echo_head = @intCast((t.echo_head + 1) % t.echoes.len);
            t.echo_len -= 1;
        }
        var k: u8 = 0;
        while (k < t.echo_len) : (k += 1) {
            const e = t.echoes[(t.echo_head + k) % t.echoes.len];
            if (@abs(e.x - x) <= tolerance and @abs(e.y - y) <= tolerance) {
                // Reports come in order: older positions are past.
                t.echo_head = @intCast((t.echo_head + k) % t.echoes.len);
                t.echo_len -= k;
                return;
            }
        }
        // Reported again (another frame): told already, unless the client moved away since
        // (switching back to a window by keyboard warps to the same place).
        if (t.warp_serial != 0 and !t.moved_since_warp and t.warp_x == x and t.warp_y == y) return;
        t.warp_x = x;
        t.warp_y = y;
        t.warp_serial +%= 1;
        t.moved_since_warp = false;
    }
};

const Class = enum { empty, black, shape };

fn classify(img: Captured) Class {
    var all_zero = true;
    var all_black = true;
    for (0..img.height) |y| {
        const row = img.pixels[y * img.stride ..][0 .. @as(usize, img.width) * 4];
        var x: usize = 0;
        while (x < row.len) : (x += 4) {
            const p = row[x..][0..4];
            if (p[0] | p[1] | p[2] | p[3] != 0) all_zero = false;
            if (p[0] | p[1] | p[2] != 0 or p[3] != 0xFF) all_black = false;
            if (!all_zero and !all_black) return .shape;
        }
    }
    return if (all_zero) .empty else .black;
}

fn hashOf(w: u16, h: u16, hx: u16, hy: u16, look: ptr.Look, pixels: []const u8, stride: usize) u64 {
    var hs = std.hash.Wyhash.init(0x6879_7072_6470);
    hs.update(std.mem.asBytes(&[_]u16{ w, h, hx, hy, @backingInt(look) }));
    for (0..h) |y| hs.update(pixels[y * stride ..][0 .. @as(usize, w) * 4]);
    return hs.final();
}

const testing = std.testing;

fn solid(comptime n: usize, px: [4]u8) [n * n * 4]u8 {
    var out: [n * n * 4]u8 = undefined;
    for (0..n * n) |i| out[i * 4 ..][0..4].* = px;
    return out;
}

fn cap(comptime n: usize, pixels: *const [n * n * 4]u8) Captured {
    return .{ .width = n, .height = n, .stride = n * 4, .pixels = pixels, .hot_x = 1, .hot_y = 2 };
}

test "auto: painted until the first real image, then the client draws it" {
    var t = Tracker.init(testing.allocator, .auto);
    defer t.deinit();
    try testing.expect(t.painting);
    const empty = solid(4, .{ 0, 0, 0, 0 });
    try testing.expect(!try t.onImage(cap(4, &empty), .unknown, 0));
    try testing.expect(t.painting); // could be stock Hyprland
    try testing.expect(!t.works);
    try testing.expect(t.judged);
    const white = solid(4, .{ 255, 255, 255, 255 });
    try testing.expect(try t.onImage(cap(4, &white), .unknown, 0));
    try testing.expect(!t.painting);
    try testing.expect(t.works);
    try testing.expectEqual(@as(u16, 1), t.image.?.hot_x);
    // Proven to work: an empty image now means hidden.
    const s = t.shape_serial;
    try testing.expect(!try t.onImage(cap(4, &empty), .unknown, 0));
    try testing.expect(t.hidden);
    try testing.expect(!t.painting);
    try testing.expect(t.shape_serial != s);
}

test "stock Hyprland: every image empty, painted all along" {
    var t = Tracker.init(testing.allocator, .auto);
    defer t.deinit();
    const empty = solid(24, .{ 0, 0, 0, 0 });
    for (0..10) |_| try testing.expect(!try t.onImage(cap(24, &empty), .unknown, 0));
    try testing.expect(t.painting);
    try testing.expect(!t.works);
    try testing.expect(t.image == null);
}

test "an empty image while Hyprland draws that cursor: painted, never hidden" {
    // An X11 window's cursor: Hyprland draws it, its capture gives it empty.
    var t = Tracker.init(testing.allocator, .auto);
    defer t.deinit();
    const white = solid(4, .{ 255, 255, 255, 255 });
    try testing.expect(try t.onImage(cap(4, &white), .{ .image = .{ .width = 4, .height = 4 } }, 0));
    try testing.expect(!t.painting);
    const empty = solid(4, .{ 0, 0, 0, 0 });
    try testing.expect(!try t.onImage(cap(4, &empty), .{ .image = .{ .width = 4, .height = 4 } }, 1000));
    try testing.expect(!t.painting and t.confirming());
    try testing.expect(!t.confirmFallback(1000 + fallback_after_ms - 1, .{ .image = .{ .width = 4, .height = 4 } }));
    try testing.expect(t.confirmFallback(1000 + fallback_after_ms, .{ .image = .{ .width = 4, .height = 4 } }));
    try testing.expect(!t.hidden);
    try testing.expect(t.painting);
    try testing.expect(t.fallback);
    try testing.expect(!try t.onImage(cap(4, &empty), .{ .image = .{ .width = 4, .height = 4 } }, 2000));
    try testing.expect(!t.confirming());
    try testing.expect(t.painting);
    try testing.expect(try t.onImage(cap(4, &white), .unknown, 0));
    try testing.expect(!t.painting);
    try testing.expect(!t.fallback);
    try testing.expect(!t.hidden);
}

test "a stale empty image, taken while the cursor was hidden but queried after it showed, is no failing capture" {
    // With cursor:hide_on_key_press the plugin's answer can lag the image.
    var t = Tracker.init(testing.allocator, .auto);
    defer t.deinit();
    const white = solid(4, .{ 255, 255, 255, 255 });
    const empty = solid(4, .{ 0, 0, 0, 0 });
    try testing.expect(try t.onImage(cap(4, &white), .{ .image = .{ .width = 4, .height = 4 } }, 0));
    for (0..30) |k| {
        const at: i64 = 1000 + @as(i64, @intCast(k)) * 100;
        try testing.expect(!try t.onImage(cap(4, &empty), .{ .image = .{ .width = 4, .height = 4 } }, at));
        try testing.expect(!t.confirmFallback(at + 5, .{ .image = .{ .width = 4, .height = 4 } }));
        try testing.expect(!try t.onImage(cap(4, &white), .{ .image = .{ .width = 4, .height = 4 } }, at + 8));
        try testing.expect(!t.painting and !t.confirming() and !t.hidden);
    }
    try testing.expect(!try t.onImage(cap(4, &empty), .{ .image = .{ .width = 4, .height = 4 } }, 9000));
    try testing.expect(!t.confirmFallback(9000 + fallback_after_ms, .none));
    try testing.expect(t.hidden and !t.painting and !t.fallback);
}

test "an empty image while Hyprland draws no cursor: hidden" {
    var t = Tracker.init(testing.allocator, .auto);
    defer t.deinit();
    const white = solid(4, .{ 255, 255, 255, 255 });
    _ = try t.onImage(cap(4, &white), .unknown, 0);
    const empty = solid(4, .{ 0, 0, 0, 0 });
    try testing.expect(!try t.onImage(cap(4, &empty), .none, 0));
    try testing.expect(t.hidden);
    try testing.expect(!t.painting);
    try testing.expect(!try t.onImage(cap(4, &empty), .{ .image = .{ .width = 4, .height = 4 } }, 0));
    try testing.expect(t.confirmFallback(fallback_after_ms, .{ .image = .{ .width = 4, .height = 4 } }));
    try testing.expect(!try t.onImage(cap(4, &empty), .none, 0));
    try testing.expect(t.hidden);
    try testing.expect(t.painting);
}

test "an empty image of another size than Hyprland draws by now: outdated, ignored" {
    // A cursor surface set before its first buffer gives an empty image of the old size.
    var t = Tracker.init(testing.allocator, .auto);
    defer t.deinit();
    const white = solid(4, .{ 255, 255, 255, 255 });
    _ = try t.onImage(cap(4, &white), .unknown, 0);
    const s = t.shape_serial;
    const empty = solid(4, .{ 0, 0, 0, 0 });
    try testing.expect(!try t.onImage(cap(4, &empty), .{ .image = .{ .width = 9, .height = 16 } }, 0));
    try testing.expect(!t.hidden);
    try testing.expect(!t.painting);
    try testing.expectEqual(s, t.shape_serial);
}

test "client mode trusts the capture: an empty image hides the pointer even while Hyprland draws one" {
    var t = Tracker.init(testing.allocator, .client);
    defer t.deinit();
    const empty = solid(4, .{ 0, 0, 0, 0 });
    try testing.expect(!try t.onImage(cap(4, &empty), .{ .image = .{ .width = 4, .height = 4 } }, 0));
    try testing.expect(t.hidden);
    try testing.expect(!t.painting);
}

test "stock Hyprland with the plugin (every image empty, a cursor drawn): painted all along" {
    var t = Tracker.init(testing.allocator, .auto);
    defer t.deinit();
    const empty = solid(24, .{ 0, 0, 0, 0 });
    for (0..3) |_| try testing.expect(!try t.onImage(cap(24, &empty), .{ .image = .{ .width = 24, .height = 24 } }, 0));
    try testing.expect(t.painting);
    try testing.expect(!t.works);
    try testing.expect(!t.fallback);
}

test "client mode: never painted, an empty image hides the pointer" {
    var t = Tracker.init(testing.allocator, .client);
    defer t.deinit();
    try testing.expect(!t.painting);
    const empty = solid(4, .{ 0, 0, 0, 0 });
    try testing.expect(!try t.onImage(cap(4, &empty), .unknown, 0));
    try testing.expect(t.hidden);
    try testing.expect(!t.painting);
}

test "paint mode ignores images" {
    var t = Tracker.init(testing.allocator, .paint);
    defer t.deinit();
    const white = solid(4, .{ 255, 255, 255, 255 });
    try testing.expect(!try t.onImage(cap(4, &white), .unknown, 0));
    try testing.expect(t.painting);
    try testing.expect(t.image == null);
}

test "an opaque black image (cursor not over the output) is not a shape" {
    var t = Tracker.init(testing.allocator, .auto);
    defer t.deinit();
    const black = solid(4, .{ 0, 0, 0, 255 });
    try testing.expect(!try t.onImage(cap(4, &black), .unknown, 0));
    try testing.expect(!t.judged);
    try testing.expect(t.painting);
}

test "the same shape twice hashes the same; another hotspot or look does not" {
    var t = Tracker.init(testing.allocator, .client);
    defer t.deinit();
    const white = solid(4, .{ 255, 255, 255, 255 });
    _ = try t.onImage(cap(4, &white), .unknown, 0);
    const h1 = t.image.?.hash;
    _ = try t.onImage(cap(4, &white), .unknown, 0);
    try testing.expectEqual(h1, t.image.?.hash);
    var c = cap(4, &white);
    c.hot_x = 3;
    _ = try t.onImage(c, .unknown, 0);
    try testing.expect(h1 != t.image.?.hash);
    const h2 = t.image.?.hash;
    t.setLook(.inverted);
    try testing.expect(h2 != t.image.?.hash);
}

test "positions: the client's own motion is no move, a jump elsewhere is" {
    var t = Tracker.init(testing.allocator, .client);
    defer t.deinit();
    t.onPosition(500, 500, 2, 0);
    try testing.expectEqual(@as(u32, 0), t.warp_serial);
    t.onClientMotion(100, 100, 10);
    t.onClientMotion(110, 105, 20);
    t.onClientMotion(120, 110, 30);
    // Reports lag behind: an older position, then a rounded one.
    t.onPosition(110, 105, 2, 35);
    t.onPosition(119, 111, 2, 40);
    try testing.expectEqual(@as(u32, 0), t.warp_serial);
    t.onPosition(640, 400, 2, 50);
    try testing.expectEqual(@as(u32, 1), t.warp_serial);
    try testing.expectEqual(@as(i32, 640), t.warp_x);
    t.onPosition(640, 400, 2, 60);
    try testing.expectEqual(@as(u32, 1), t.warp_serial);
    t.onPosition(100, 100, 2, 60 + echo_ms + 100);
    try testing.expectEqual(@as(u32, 2), t.warp_serial);
}

test "a warp to where the last one went, after the client moved away: a move again" {
    var t = Tracker.init(testing.allocator, .client);
    defer t.deinit();
    // A keyboard window switch warps the pointer to the window's middle.
    t.onClientMotion(900, 300, 0);
    t.onPosition(322, 373, 2, 10);
    try testing.expectEqual(@as(u32, 1), t.warp_serial);
    // Away and back by keyboard: the same middle, the client's pointer elsewhere.
    t.onClientMotion(600, 300, 20);
    t.onClientMotion(900, 300, 30);
    t.onPosition(900, 300, 2, 35);
    try testing.expectEqual(@as(u32, 1), t.warp_serial);
    t.onPosition(322, 373, 2, 40);
    try testing.expectEqual(@as(u32, 2), t.warp_serial);
    t.onPosition(322, 373, 2, 50);
    try testing.expectEqual(@as(u32, 2), t.warp_serial);
}

test "a new client: positions count only once it moved its pointer" {
    var t = Tracker.init(testing.allocator, .client);
    defer t.deinit();
    t.onClientMotion(10, 10, 0);
    t.onNewClient();
    t.onPosition(500, 500, 2, 5); // where the last client left it
    try testing.expectEqual(@as(u32, 0), t.warp_serial);
    t.onClientMotion(20, 20, 10);
    t.onPosition(20, 20, 2, 15);
    try testing.expectEqual(@as(u32, 0), t.warp_serial);
    t.onPosition(300, 300, 2, 20);
    try testing.expectEqual(@as(u32, 1), t.warp_serial);
}

test "positions after relative motion are the server's" {
    var t = Tracker.init(testing.allocator, .client);
    defer t.deinit();
    t.onClientRelative();
    t.onPosition(10, 10, 2, 0);
    t.onPosition(12, 10, 2, 5);
    try testing.expectEqual(@as(u32, 2), t.warp_serial);
}

test "the echo ring keeps the latest 64 positions" {
    var t = Tracker.init(testing.allocator, .client);
    defer t.deinit();
    for (0..100) |i| t.onClientMotion(@intCast(i * 10), 0, 0);
    t.onPosition(990, 0, 1, 1);
    try testing.expectEqual(@as(u32, 0), t.warp_serial);
    t.onPosition(0, 0, 1, 1); // pushed out of the ring
    try testing.expectEqual(@as(u32, 1), t.warp_serial);
}
