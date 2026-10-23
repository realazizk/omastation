//! Test scenes (`--test-scene`): desktop content at 4K as pure functions of (scene, t, x, y),
//! so a client can recompute any pixel of any frame and compare what it decoded. `t` counts
//! content frames; `busy` scenes keep a small clock ticking after the motion stops.

const std = @import("std");
const conn_mod = @import("conn.zig");
const channels = conn_mod.channels;
const Conn = conn_mod.Conn;

const log = std.log.scoped(.scene);

pub const Kind = enum(u32) {
    /// The page scrolls 6 px a frame under a static toolbar.
    scroll,
    /// A 1600x1000 window moves over the static page.
    window,
    /// A 640x360 video plays in the middle of the static page.
    video_small,
    video_full,
    /// `scroll`, then a clock in the toolbar keeps ticking.
    scroll_busy,
};

pub const Rect = struct {
    x: u32,
    y: u32,
    w: u32,
    h: u32,

    pub fn contains(r: Rect, x: u32, y: u32) bool {
        return x >= r.x and x < r.x + r.w and y >= r.y and y < r.y + r.h;
    }
};

pub const fps: u32 = 30;
pub const frame_ms: u32 = 1000 / fps;

pub const toolbar_h: u32 = 56;
const cell_w: u32 = 9;
const cell_h: u32 = 18;
const scroll_px: u32 = 6;
const window_w: u32 = 1600;
const window_h: u32 = 1000;

pub const Scene = struct {
    kind: Kind,
    width: u32,
    height: u32,

    /// The last frame of the motion.
    pub fn motionFrames(s: Scene) u32 {
        return switch (s.kind) {
            .scroll, .scroll_busy, .window => 2 * fps,
            // The video detector needs 2-3 s before the region exists.
            .video_small => 6 * fps,
            .video_full => 3 * fps,
        };
    }

    /// What keeps changing after the motion (excluded from exactness).
    pub fn busyRect(s: Scene) ?Rect {
        return switch (s.kind) {
            .scroll_busy => .{ .x = s.width - 240, .y = 16, .w = 200, .h = 24 },
            else => null,
        };
    }

    fn videoRect(s: Scene) Rect {
        return switch (s.kind) {
            .video_full => .{ .x = 0, .y = 0, .w = s.width, .h = s.height },
            else => .{ .x = (s.width - 640) / 2 / 16 * 16, .y = (s.height - 360) / 2 / 16 * 16, .w = 640, .h = 360 },
        };
    }

    fn windowAt(s: Scene, t: u32) Rect {
        const span_x = s.width - window_w;
        const span_y = s.height - window_h - toolbar_h;
        return .{ .x = tri(t * 24, span_x), .y = toolbar_h + tri(100 + t * 12, span_y), .w = window_w, .h = window_h };
    }

    /// Pixel (x, y) of frame t as B, G, R.
    pub fn pixel(s: Scene, t: u32, x: u32, y: u32) [3]u8 {
        if (s.busyRect()) |b| if (b.contains(x, y)) return clock(t / 3, x - b.x, y - b.y);
        const m = @min(t, s.motionFrames());
        switch (s.kind) {
            .video_full => return video(m, x, y),
            .video_small => {
                const v = s.videoRect();
                if (v.contains(x, y)) return video(m, x - v.x, y - v.y);
                return page(x, y, 0);
            },
            .scroll, .scroll_busy => return page(x, y, m * scroll_px),
            .window => {
                const r = s.windowAt(m);
                if (r.contains(x, y)) return window(x - r.x, y - r.y);
                return page(x, y, 0);
            },
        }
    }

    /// Rects that may differ between frames `a` and `b` (a < b), at most 4.
    pub fn changed(s: Scene, a: u32, b: u32, out: *[4]Rect) []const Rect {
        var n: usize = 0;
        const ma = @min(a, s.motionFrames());
        const mb = @min(b, s.motionFrames());
        if (ma != mb) switch (s.kind) {
            .video_full => {
                out[n] = .{ .x = 0, .y = 0, .w = s.width, .h = s.height };
                n += 1;
            },
            .video_small => {
                out[n] = s.videoRect();
                n += 1;
            },
            .scroll, .scroll_busy => {
                out[n] = .{ .x = 0, .y = toolbar_h, .w = s.width, .h = s.height - toolbar_h };
                n += 1;
            },
            .window => {
                out[n] = s.windowAt(ma);
                out[n + 1] = s.windowAt(mb);
                n += 2;
            },
        };
        if (s.busyRect()) |r| if (a / 3 != b / 3) {
            out[n] = r;
            n += 1;
        };
        return out[0..n];
    }

    pub fn drawAll(s: Scene, t: u32, px: []u8, stride: usize) void {
        s.drawRect(t, .{ .x = 0, .y = 0, .w = s.width, .h = s.height }, px, stride);
    }

    pub fn drawRect(s: Scene, t: u32, r: Rect, px: []u8, stride: usize) void {
        for (r.y..r.y + r.h) |y| {
            const row = px[y * stride ..];
            for (r.x..r.x + r.w) |x| {
                const p = s.pixel(t, @intCast(x), @intCast(y));
                row[x * 4 ..][0..4].* = .{ p[0], p[1], p[2], 0xFF };
            }
        }
    }

    /// Turns a picture of frame `a` into frame `b`; a scroll moves the rows it keeps.
    pub fn advance(s: Scene, a: u32, b: u32, px: []u8, stride: usize) void {
        const ma = @min(a, s.motionFrames());
        const mb = @min(b, s.motionFrames());
        if ((s.kind == .scroll or s.kind == .scroll_busy) and mb > ma) {
            const d = (mb - ma) * scroll_px;
            const area_h = s.height - toolbar_h;
            if (d < area_h) {
                const top = toolbar_h * stride;
                std.mem.copyForwards(u8, px[top .. top + (area_h - d) * stride], px[top + d * stride .. top + area_h * stride]);
                s.drawRect(b, .{ .x = 0, .y = s.height - d, .w = s.width, .h = d }, px, stride);
                // The clock is in the toolbar, not in the rows moved.
                if (s.busyRect()) |r| if (a / 3 != b / 3) s.drawRect(b, r, px, stride);
                return;
            }
        }
        var buf: [4]Rect = undefined;
        for (s.changed(a, b, &buf)) |r| s.drawRect(b, r, px, stride);
    }
};

fn tri(v: u32, span: u32) u32 {
    const p = v % (2 * span);
    return if (p <= span) p else 2 * span - p;
}

fn hash(x: u32) u32 {
    var h = x *% 0x9E3779B1;
    h ^= h >> 16;
    h *%= 0x85EBCA6B;
    h ^= h >> 13;
    h *%= 0xC2B2AE35;
    h ^= h >> 16;
    return h;
}

const white = [3]u8{ 0xFF, 0xFF, 0xFF };

fn blend(bg: [3]u8, fg: [3]u8, a: u32) [3]u8 {
    var o: [3]u8 = undefined;
    for (0..3) |i| {
        const b: i32 = bg[i];
        const f: i32 = fg[i];
        o[i] = @intCast(b + @divTrunc((f - b) * @as(i32, @intCast(a)), 255));
    }
    return o;
}

/// Ink coverage (0..255) of glyph `g` at (gx, gy) of its 7x12 box.
fn glyph(g: u32, gx: u32, gy: u32) u32 {
    const v1 = g % 3 * 2; // 0, 2, 4
    const v2 = if (g & 8 != 0) v1 + 2 + (g >> 4) % 2 else 99;
    const top: u32 = if (g & 32 != 0) 0 else 4;
    var cov: u32 = 0;
    for ([_]u32{ v1, v2 }) |v| {
        if (v > 6 or gy < top) continue;
        if (gx == v) cov = 255 else if (gx + 1 == v or gx == v + 1) cov = @max(cov, 90);
    }
    const hs = [_]struct { row: u32, bit: u32 }{ .{ .row = 4, .bit = 64 }, .{ .row = 7, .bit = 128 }, .{ .row = 11, .bit = 256 } };
    for (hs) |hh| {
        if (g & hh.bit == 0 or gx > 6) continue;
        if (gy == hh.row) cov = 255 else if (gy + 1 == hh.row or gy == hh.row + 1) cov = @max(cov, 90);
    }
    return cov;
}

/// Text page pixel at page position (x, y + scroll).
fn text(x: u32, py: u32, seed: u32, bg: [3]u8) [3]u8 {
    const line = py / cell_h;
    const ly = py % cell_h;
    const col = x / cell_w;
    const lx = x % cell_w;
    const lh = hash(line ^ seed);
    if (lh % 11 == 0) return bg;
    const indent = (lh >> 4) % 8;
    const len = 20 + (lh >> 8) % 380;
    if (col < indent or col >= indent + len) return bg;
    const ch = hash(line *% 7919 +% col *% 104729 +% seed);
    if (ch % 7 == 0) return bg;
    if (lx < 1 or lx > 7 or ly < 4 or ly > 15) return bg;
    const a = glyph(ch >> 8, lx - 1, ly - 4);
    if (a == 0) return bg;
    const word = hash(line *% 31 +% col / 6 +% seed);
    const fg: [3]u8 = switch (word % 9) {
        0 => .{ 0xC4, 0x4F, 0x1A }, // blue (B, G, R)
        1 => .{ 0x1C, 0x1C, 0xB8 }, // red
        2 => .{ 0x2A, 0x86, 0x22 }, // green
        else => .{ 0x22, 0x22, 0x22 },
    };
    return blend(bg, fg, a);
}

fn toolbar(x: u32, y: u32) [3]u8 {
    const k = x / 120;
    const bx = x % 120;
    if (k < 12 and bx >= 10 and bx < 110 and y >= 12 and y < 44) {
        if (bx == 10 or bx == 109 or y == 12 or y == 43) return .{ 0xA8, 0xA8, 0xA8 };
        return text(bx + 4, y - 6 + k * cell_h, 0x51, .{ 0xE4, 0xE4, 0xE4 });
    }
    const g: u8 = @intCast(0xF2 - y / 4);
    return .{ g, g, g };
}

fn page(x: u32, y: u32, scroll: u32) [3]u8 {
    if (y < toolbar_h) return toolbar(x, y);
    return text(x, y - toolbar_h + scroll, 0, white);
}

fn window(x: u32, y: u32) [3]u8 {
    if (x == 0 or y == 0 or x == window_w - 1 or y == window_h - 1) return .{ 0x70, 0x70, 0x70 };
    if (y < 36) {
        if (y >= 10 and y < 28 and x >= 16 and x < 600) return text(x, y - 10 + 3 * cell_h, 0x77, .{ 0xB0, 0x70, 0x30 });
        return .{ @intCast(0xD8 - x / 16), 0x78, 0x34 };
    }
    if (x < window_w * 3 / 5) return text(x, y - 36, 0x1234, white);
    return photo(x, y);
}

fn photo(x: u32, y: u32) [3]u8 {
    const g: i32 = @intCast(hash(x *% 73856093 ^ y *% 19349663) & 15);
    const b: i32 = @intCast(60 + tri(x + y, 400) / 4);
    const gg: i32 = @intCast(80 + tri(y * 2, 600) / 5);
    const r: i32 = @intCast(100 + tri(x * 3, 500) / 4);
    return .{ clamp8(b + g - 8), clamp8(gg + g - 8), clamp8(r + g - 8) };
}

fn video(t: u32, x: u32, y: u32) [3]u8 {
    const g: i32 = @intCast(hash(x *% 73856093 ^ y *% 19349663 ^ t *% 83492791) & 15);
    const b: i32 = @intCast(tri(x * 2 + t * 9, 256) / 2 + 40);
    const gg: i32 = @intCast(tri(y * 3 + t * 5 + x / 2, 256) / 2 + 30);
    const r: i32 = @intCast(tri(x + y + t * 13, 256) / 2 + 20);
    return .{ clamp8(b + g - 8), clamp8(gg + g - 8), clamp8(r + g - 8) };
}

fn clock(n: u32, x: u32, y: u32) [3]u8 {
    return text(x, y + 3 + (n % 64) * cell_h, 0xC10C, .{ 0xEC, 0xEC, 0xEC });
}

fn clamp8(v: i32) u8 {
    return @intCast(std.math.clamp(v, 0, 255));
}

/// FNV-1a 64 over R, G, B of `r` of frame `t`.
pub fn hashRgb(s: Scene, t: u32, r: Rect) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (r.y..r.y + r.h) |y| for (r.x..r.x + r.w) |x| {
        const p = s.pixel(t, @intCast(x), @intCast(y));
        for ([_]u8{ p[2], p[1], p[0] }) |b| {
            h ^= b;
            h *%= 0x100000001b3;
        }
    };
    return h;
}

/// `--test-scene` player: the still picture until the client has it exact (at least 1 s),
/// the motion, then `still_ms` still; logs the hash of the final picture below the toolbar.
pub const Player = struct {
    kind: Kind,
    scene: ?Scene = null,
    state: enum { init, settle, motion, still } = .init,
    t: u32 = 0,
    dirty: bool = false,
    since: i64 = 0,
    start: i64 = 0,
    cycle: u32 = 0,

    pub const still_ms: i64 = 10_000;

    pub fn pump(ctx: *anyopaque, c: *Conn) conn_mod.Error!void {
        const p: *Player = @ptrCast(@alignCast(ctx));
        try p.step(c, conn_mod.nowMs());
    }

    fn step(p: *Player, c: *Conn, now: i64) conn_mod.Error!void {
        if (!c.established or !c.ch.gfx_ready or c.output_suppressed or c.reactivating) return;
        const fb = &(c.fb orelse return);
        const sc: Scene = .{ .kind = p.kind, .width = fb.width, .height = fb.height };
        // A scene needs room for its window and video.
        if (sc.width < 1920 or sc.height < 1200) return;
        if (p.scene == null or p.scene.?.width != sc.width or p.scene.?.height != sc.height) {
            p.scene = sc;
            p.state = .init;
        }
        const last = sc.motionFrames();
        switch (p.state) {
            .init => {
                sc.drawAll(0, fb.pixels, fb.stride);
                p.t = 0;
                p.dirty = true;
                p.state = .settle;
                p.since = now;
            },
            .settle => if (p.dirty or channels.refinePending(c) or c.flow.queuedTotal() > 0) {
                p.since = now;
            } else if (now - p.since >= 1000) {
                p.state = .motion;
                p.start = now;
                p.cycle += 1;
                log.info("{s}: test scene {t} #{d}: the motion starts ({d} frames, {d} a second)", .{ c.peer, p.kind, p.cycle, last, fps });
            },
            .motion => {
                const want: u32 = @min(last, @as(u32, @intCast(@divTrunc(now - p.start, frame_ms))) + 1);
                if (want != p.t) {
                    sc.advance(p.t, want, fb.pixels, fb.stride);
                    p.t = want;
                    p.dirty = true;
                }
                if (p.t == last) {
                    p.state = .still;
                    p.since = now;
                    const r: Rect = .{ .x = 0, .y = toolbar_h, .w = sc.width, .h = sc.height - toolbar_h };
                    log.info("{s}: test scene {t} #{d}: the motion ended; final picture hash {x:0>16} (compare: hash 0 {d} {d} {d})", .{ c.peer, p.kind, p.cycle, hashRgb(sc, last, r), r.y, r.w, r.h });
                }
            },
            .still => {
                if (sc.busyRect() != null) {
                    const want: u32 = @as(u32, @intCast(@divTrunc(now - p.start, frame_ms))) + 1;
                    if (want / 3 != p.t / 3) {
                        sc.advance(p.t, want, fb.pixels, fb.stride);
                        p.dirty = true;
                    }
                    p.t = want;
                }
                if (now - p.since >= still_ms) p.state = .init;
            },
        }
        if (!p.dirty) return;
        if (!channels.canSendFrame(c)) {
            if (c.pacing.refused) c.pacing.held();
            return;
        }
        try channels.sendFramebuffer(c);
        p.dirty = false;
    }
};

test "scenes: advance draws what drawAll draws" {
    const gpa = std.testing.allocator;
    const w = 1920;
    const h = 1200;
    const a = try gpa.alloc(u8, w * h * 4);
    defer gpa.free(a);
    const b = try gpa.alloc(u8, w * h * 4);
    defer gpa.free(b);
    for ([_]Kind{ .scroll, .window, .video_small, .video_full, .scroll_busy }) |k| {
        const s: Scene = .{ .kind = k, .width = w, .height = h };
        s.drawAll(0, a, w * 4);
        var t: u32 = 0;
        for ([_]u32{ 1, 2, 5, 9 }) |n| {
            s.advance(t, n, a, w * 4);
            t = n;
            s.drawAll(t, b, w * 4);
            try std.testing.expectEqualSlices(u8, b, a);
        }
    }
}
