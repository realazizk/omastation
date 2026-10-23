//! Video region detection on a surface after the Windows server's heuristics: a 32x32-cell heat
//! map, one detection a second, a region once the same hot natural-image rect is seen three times.

const std = @import("std");
const gfx = @import("../proto/gfx.zig");

pub const Rect16 = gfx.Rect16;

/// Side of a heat-map cell, pixels.
pub const cell: u32 = 32;
/// A detection (and heat-map snapshot) runs once more than this has passed since the last.
pub const detection_interval_ms: i64 = 1000;
/// A cell is hot above this many updates a second.
pub const update_rate: f32 = 5.0;
/// A candidate is within bounds of the tracked rect when no edge moved further than this (px).
pub const max_bound_offset: u32 = 32;
/// A candidate is hotter when its hot area exceeds the tracked rect's by more than this percent.
pub const max_bound_area_diff: u32 = 110;
/// Percentage of a rect that must be hot.
pub const min_heatmap_overlap: u32 = 85;
/// Percentage of a candidate that must be natural image.
pub const image_overlap_threshold: u32 = 70;
/// Valid detections after the first sighting before a region starts.
pub const min_valid_hints: u32 = 2;
/// Invalid detections tolerated before a region (or a tracked candidate) is dropped.
pub const max_invalid_hints_active: u32 = 1;
pub const max_invalid_hints_inactive: u32 = 1;

/// Side of a classified block, pixels.
pub const block: u32 = 64;
/// At most this many blocks of a candidate are classified (evenly spread).
pub const max_classified_blocks: u32 = 256;
/// A block is text-like when its `major_colours` top colours cover `major_colour_percent` of it.
pub const major_colours: usize = 4;
pub const major_colour_percent: u32 = 70;

/// A BGRX picture (the encoder's shadow).
pub const Picture = struct {
    pixels: []const u8,
    stride: usize,
    width: u32,
    height: u32,
};

pub const Event = enum { started, ended };

const Rect = struct {
    left: u32,
    top: u32,
    right: u32,
    bottom: u32,

    fn of(r: Rect16) Rect {
        return .{ .left = r.left, .top = r.top, .right = r.right, .bottom = r.bottom };
    }

    fn r16(r: Rect) Rect16 {
        return .{ .left = @intCast(r.left), .top = @intCast(r.top), .right = @intCast(r.right), .bottom = @intCast(r.bottom) };
    }

    fn empty(r: Rect) bool {
        return r.left >= r.right or r.top >= r.bottom;
    }

    fn area(r: Rect) u64 {
        if (r.empty()) return 0;
        return @as(u64, r.right - r.left) * (r.bottom - r.top);
    }

    fn unite(a: Rect, b: Rect) Rect {
        return .{ .left = @min(a.left, b.left), .top = @min(a.top, b.top), .right = @max(a.right, b.right), .bottom = @max(a.bottom, b.bottom) };
    }

    fn intersect(a: Rect, b: Rect) ?Rect {
        const r: Rect = .{ .left = @max(a.left, b.left), .top = @max(a.top, b.top), .right = @min(a.right, b.right), .bottom = @min(a.bottom, b.bottom) };
        return if (r.empty()) null else r;
    }
};

pub const Detector = struct {
    width: u32 = 0,
    height: u32 = 0,
    cols: u32 = 0,
    rows: u32 = 0,
    /// Updates of each cell since the last snapshot.
    counts: []u16 = &.{},
    /// Updates a second at the last snapshot.
    rates: []f32 = &.{},
    hot: std.DynamicBitSetUnmanaged = .{},
    dirty: std.DynamicBitSetUnmanaged = .{},
    dirty_bounds: ?Rect = null,
    hot_cells: u32 = 0,
    /// Scratch for the candidate search: hot cells below each cell.
    down: []u16 = &.{},
    widths: []u16 = &.{},
    last_detect_ms: ?i64 = null,
    last_snap_ms: i64 = 0,
    /// The candidate being tracked, and whether it is the video region.
    tracked: ?Rect = null,
    active: bool = false,
    valid_hints: u32 = 0,
    invalid_hints: u32 = 0,
    regions: u32 = 0,

    pub fn deinit(d: *Detector, gpa: std.mem.Allocator) void {
        gpa.free(d.counts);
        gpa.free(d.rates);
        gpa.free(d.down);
        gpa.free(d.widths);
        d.hot.deinit(gpa);
        d.dirty.deinit(gpa);
        d.* = .{};
    }

    /// The surface is `w` x `h`; another size starts over (no region).
    pub fn resize(d: *Detector, gpa: std.mem.Allocator, w: u32, h: u32) std.mem.Allocator.Error!void {
        if (w == d.width and h == d.height) return;
        const cols = (w + cell - 1) / cell;
        const rows = (h + cell - 1) / cell;
        const n = @as(usize, cols) * rows;
        const counts = try gpa.alloc(u16, n);
        errdefer gpa.free(counts);
        const rates = try gpa.alloc(f32, n);
        errdefer gpa.free(rates);
        const down = try gpa.alloc(u16, n);
        errdefer gpa.free(down);
        const widths = try gpa.alloc(u16, cols + 1);
        errdefer gpa.free(widths);
        var hot = try std.DynamicBitSetUnmanaged.initEmpty(gpa, n);
        errdefer hot.deinit(gpa);
        const dirty = try std.DynamicBitSetUnmanaged.initEmpty(gpa, n);
        d.deinit(gpa);
        @memset(counts, 0);
        @memset(rates, 0);
        d.* = .{ .width = w, .height = h, .cols = cols, .rows = rows, .counts = counts, .rates = rates, .down = down, .widths = widths, .hot = hot, .dirty = dirty };
    }

    /// Forget the region and the tracked candidate; the heat map stays.
    pub fn forget(d: *Detector) void {
        d.tracked = null;
        d.active = false;
        d.valid_hints = 0;
        d.invalid_hints = 0;
    }

    pub fn region(d: *const Detector) ?Rect16 {
        if (!d.active) return null;
        return (d.tracked orelse return null).r16();
    }

    /// Each cell `boxes` touch (right/bottom exclusive) counts an update and is dirty until the next detection.
    pub fn notify(d: *Detector, boxes: []const Rect16) void {
        if (d.cols == 0) return;
        for (boxes) |b| {
            const r = Rect.of(b);
            if (r.empty() or r.left >= d.width or r.top >= d.height) continue;
            const x0 = r.left / cell;
            const y0 = r.top / cell;
            const x1 = @min((@min(r.right, d.width) - 1) / cell, d.cols - 1);
            const y1 = @min((@min(r.bottom, d.height) - 1) / cell, d.rows - 1);
            var y = y0;
            while (y <= y1) : (y += 1) {
                var x = x0;
                while (x <= x1) : (x += 1) {
                    const i = @as(usize, y) * d.cols + x;
                    d.counts[i] +|= 1;
                    d.dirty.set(i);
                }
            }
            const clipped: Rect = .{ .left = r.left, .top = r.top, .right = @min(r.right, d.width), .bottom = @min(r.bottom, d.height) };
            d.dirty_bounds = if (d.dirty_bounds) |db| db.unite(clipped) else clipped;
        }
    }

    /// Runs a detection once the interval has passed; `pic` feeds the natural-image test.
    pub fn tick(d: *Detector, now_ms: i64, pic: Picture) ?Event {
        if (d.cols == 0) return null;
        const last = d.last_detect_ms orelse {
            d.last_detect_ms = now_ms;
            d.last_snap_ms = now_ms;
            return null;
        };
        if (now_ms - last <= detection_interval_ms) return null;
        d.last_detect_ms = now_ms;
        d.snapshot(now_ms);
        const cand = d.candidate();
        const ev = d.update(cand, pic);
        d.dirty.unsetAll();
        d.dirty_bounds = null;
        return ev;
    }

    /// Turns counts into rates; hot means above `update_rate` and dirty since the last detection.
    fn snapshot(d: *Detector, now_ms: i64) void {
        const elapsed: f32 = @floatFromInt(@max(1, now_ms - d.last_snap_ms));
        d.hot_cells = 0;
        for (d.counts, d.rates, 0..) |*n, *rate, i| {
            rate.* = @as(f32, @floatFromInt(n.*)) * 1000.0 / elapsed;
            n.* = 0;
            const h = rate.* > update_rate and d.dirty.isSet(i);
            d.hot.setValue(i, h);
            d.hot_cells += @intFromBool(h);
        }
        d.last_snap_ms = now_ms;
    }

    fn isHot(d: *const Detector, x: u32, y: u32) bool {
        return d.hot.isSet(@as(usize, y) * d.cols + x);
    }

    /// Hot area in pixels of the cells with index in [left/32, right/32) x [top/32, bottom/32).
    fn hotPixels(d: *const Detector, r: Rect) u64 {
        var n: u64 = 0;
        var y = r.top / cell;
        while (y < r.bottom / cell and y < d.rows) : (y += 1) {
            var x = r.left / cell;
            while (x < r.right / cell and x < d.cols) : (x += 1) n += @intFromBool(d.isHot(x, y));
        }
        return n * cell * cell;
    }

    fn snapOut(d: *const Detector, r: Rect) Rect {
        return .{
            .left = r.left / cell * cell,
            .top = r.top / cell * cell,
            .right = @min((r.right + cell - 1) / cell * cell, d.width),
            .bottom = @min((r.bottom + cell - 1) / cell * cell, d.height),
        };
    }

    fn candidate(d: *Detector) ?Rect {
        if (d.hot_cells == 0) return null;
        const n = @as(u64, d.cols) * d.rows;
        if (@as(u64, d.hot_cells) * 100 >= n * min_heatmap_overlap) {
            return d.snapOut(d.dirty_bounds orelse return null);
        }
        if (@as(u64, d.hot_cells) > n * 3 / 4) if (d.dirty_bounds) |b| {
            const a = b.area();
            if (a > @as(u64, d.width) * d.height * 3 / 4 and d.hotPixels(b) * 100 >= a * min_heatmap_overlap) return d.snapOut(b);
        };
        return d.largestHotRect();
    }

    /// Largest rectangle of hot cells; like Windows, one cell taller than the hot block.
    fn largestHotRect(d: *Detector) ?Rect {
        var y = d.rows;
        while (y > 0) {
            y -= 1;
            for (0..d.cols) |xi| {
                const x: u32 = @intCast(xi);
                const i = @as(usize, y) * d.cols + x;
                d.down[i] = if (!d.isHot(x, y)) 0 else if (y + 1 < d.rows) d.down[i + d.cols] + 1 else 1;
            }
        }
        var best: ?Rect = null;
        var best_area: u64 = 0;
        for (0..d.rows) |yi| {
            const cy: u32 = @intCast(yi);
            var cx: u32 = 0;
            while (cx < d.cols) : (cx += 1) {
                if (!d.isHot(cx, cy)) continue;
                // widths[w] = full rows of w hot cells from row cy down.
                var k: u32 = 0;
                var rows_min: u16 = std.math.maxInt(u16);
                while (cx + k < d.cols and d.isHot(cx + k, cy)) : (k += 1) {
                    rows_min = @min(rows_min, d.down[@as(usize, cy) * d.cols + cx + k]);
                    d.widths[k + 1] = rows_min;
                }
                var w = k;
                while (w >= 1) : (w -= 1) {
                    const h: u32 = @as(u32, d.widths[w]) + 1;
                    if (@as(u64, w) * h * cell * cell > best_area) {
                        const r: Rect = .{
                            .left = cx * cell,
                            .top = cy * cell,
                            .right = @min((cx + w) * cell, d.width),
                            .bottom = @min((cy + h) * cell, d.height),
                        };
                        best = r;
                        best_area = r.area();
                    }
                }
            }
        }
        return best;
    }

    /// The largest edge offset from the tracked rect (per axis, the edge that moved most).
    fn withinBounds(t: Rect, r: Rect) struct { within: bool, offset: u32 } {
        const dx = edgeOffset(@as(i64, t.left) - r.left, @as(i64, t.right) - r.right);
        const dy = edgeOffset(@as(i64, t.top) - r.top, @as(i64, t.bottom) - r.bottom);
        const off: u32 = @intCast(@max(dx, dy));
        return .{ .within = off <= max_bound_offset, .offset = off };
    }

    fn edgeOffset(a: i64, b: i64) u64 {
        return if (@abs(a) <= @abs(b)) @abs(b) else @abs(a);
    }

    /// The active region's candidate is away (and the region cooled), hotter with another width, or of another height.
    fn offsetOrHotter(d: *const Detector, cand: Rect, t: Rect) bool {
        const ov = d.hotPixels(t);
        const wb = withinBounds(t, cand);
        if (!wb.within and ov * 100 <= t.area() * min_heatmap_overlap) return true;
        if (wb.offset == 0) return false;
        const cand_ov = d.hotPixels(cand);
        const dw = @abs(@as(i64, cand.right - cand.left) - @as(i64, t.right - t.left));
        const dh = @abs(@as(i64, cand.bottom - cand.top) - @as(i64, t.bottom - t.top));
        if (ov * max_bound_area_diff < cand_ov * 100 and dw > cell) return true;
        return dh > cell;
    }

    /// Region hysteresis for one detection's candidate.
    fn update(d: *Detector, cand: ?Rect, pic: Picture) ?Event {
        if (d.active) {
            const t = d.tracked.?;
            if (cand) |c| {
                if (d.offsetOrHotter(c, t)) d.invalid_hints += 1 else d.invalid_hints = 0;
            } else d.invalid_hints += 2;
            if (d.invalid_hints <= max_invalid_hints_active) return null;
            d.forget();
            return .ended;
        }
        const c = cand orelse {
            d.forget();
            return null;
        };
        const t = d.tracked orelse {
            d.tracked = c; // first sighting
            return null;
        };
        const wb = withinBounds(t, c);
        const away = !wb.within and d.hotPixels(t) * 100 <= t.area() * min_heatmap_overlap;
        if (away or !naturalImage(pic, c)) {
            d.invalid_hints += 1;
            if (d.invalid_hints > max_invalid_hints_inactive) d.forget();
            return null;
        }
        d.valid_hints += 1;
        if (wb.within) d.tracked = t.unite(c);
        if (d.valid_hints < min_valid_hints) return null;
        d.active = true;
        d.invalid_hints = 0;
        d.regions += 1;
        return .started;
    }
};

/// At least `image_overlap_threshold` percent of `r` is natural image (sampled 64x64 blocks).
fn naturalImage(pic: Picture, r: Rect) bool {
    const bx0 = r.left / block;
    const by0 = r.top / block;
    const bx1 = (@min(r.right, pic.width) + block - 1) / block;
    const by1 = (@min(r.bottom, pic.height) + block - 1) / block;
    if (bx0 >= bx1 or by0 >= by1) return false;
    const blocks = (bx1 - bx0) * (by1 - by0);
    var step: u32 = 1;
    while ((blocks + step * step - 1) / (step * step) > max_classified_blocks) step += 1;
    var image: u64 = 0;
    var total: u64 = 0;
    var by = by0;
    while (by < by1) : (by += step) {
        var bx = bx0;
        while (bx < bx1) : (bx += step) {
            const b: Rect = .{ .left = bx * block, .top = by * block, .right = @min((bx + 1) * block, pic.width), .bottom = @min((by + 1) * block, pic.height) };
            const part = (b.intersect(r) orelse continue).area();
            total += part;
            if (classifyBlock(pic, b.r16()) == .image) image += part;
        }
    }
    return total > 0 and image * 100 >= total * image_overlap_threshold;
}

pub const Class = enum { text, image, solid };

/// Solid, text-like (`major_colours` cover `major_colour_percent`) or natural image; approximates Windows.
pub fn classifyBlock(pic: Picture, r: Rect16) Class {
    const w: usize = r.right - r.left;
    const h: usize = r.bottom - r.top;
    if (w == 0 or h == 0) return .solid;
    std.debug.assert(w * h <= block * block);
    var tab: ColourTable = undefined;
    tab.clear();
    var y: usize = r.top;
    while (y < r.bottom) : (y += 1) {
        const row = pic.pixels[y * pic.stride + @as(usize, r.left) * 4 ..][0 .. w * 4];
        var x: usize = 0;
        while (x < w) {
            const v = std.mem.readInt(u32, row[x * 4 ..][0..4], .little) & 0xFFFFFF;
            var n: u16 = 1;
            x += 1;
            while (x < w and std.mem.readInt(u32, row[x * 4 ..][0..4], .little) & 0xFFFFFF == v) : (x += 1) n += 1;
            tab.add(v, n);
        }
    }
    if (tab.used == 1) return .solid;
    var top: [major_colours]u32 = @splat(0);
    for (tab.counts, tab.keys) |n, k| {
        if (k == ColourTable.free) continue;
        var v: u32 = n;
        for (&top) |*t| if (v > t.*) std.mem.swap(u32, &v, t);
    }
    var major: u64 = 0;
    for (top) |t| major += t;
    return if (major * 100 >= @as(u64, w * h) * major_colour_percent) .text else .image;
}

/// Colour counts of one block (at most 4096 colours), open addressing at load <= 1/2.
const ColourTable = struct {
    const size = 2 * block * block;
    const free: u32 = 0xFFFFFFFF;
    keys: [size]u32,
    counts: [size]u16,
    used: usize,

    fn clear(t: *ColourTable) void {
        @memset(&t.keys, free);
        @memset(&t.counts, 0);
        t.used = 0;
    }

    fn add(t: *ColourTable, v: u32, n: u16) void {
        var i: usize = (v *% 0x9E3779B1) >> 19; // 13 bits: size 8192
        while (true) : (i = (i + 1) & (size - 1)) {
            if (t.keys[i] == v) {
                t.counts[i] += n;
                return;
            }
            if (t.keys[i] == free) {
                t.keys[i] = v;
                t.counts[i] = n;
                t.used += 1;
                return;
            }
        }
    }
};

const testing = std.testing;

const TestPic = struct {
    w: u32,
    h: u32,
    px: []u8,

    fn init(gpa: std.mem.Allocator, w: u32, h: u32) !TestPic {
        const px = try gpa.alloc(u8, @as(usize, w) * h * 4);
        var p: TestPic = .{ .w = w, .h = h, .px = px };
        p.fillText(.{ .left = 0, .top = 0, .right = @intCast(w), .bottom = @intCast(h) }, 0);
        return p;
    }

    fn deinit(p: *TestPic, gpa: std.mem.Allocator) void {
        gpa.free(p.px);
    }

    fn pic(p: *const TestPic) Picture {
        return .{ .pixels = p.px, .stride = @as(usize, p.w) * 4, .width = p.w, .height = p.h };
    }

    fn set(p: *TestPic, x: usize, y: usize, v: u32) void {
        std.mem.writeInt(u32, p.px[(y * p.w + x) * 4 ..][0..4], v, .little);
    }

    fn fillText(p: *TestPic, r: Rect16, scroll: u32) void {
        for (r.top..r.bottom) |y| for (r.left..r.right) |x| {
            const ly = (y + scroll) % 16;
            const lx = x % 8;
            const glyph = (x / 8 * 7 + (y + scroll) / 16 * 3) % 5 != 0;
            const v: u32 = if (!glyph or ly >= 12 or lx == 7) 0xFFFFFF else if (lx == 0 or lx == 6 or ly == 0 or ly == 11) 0x9A9A9A else if ((lx + ly) % 3 == 0) 0x202020 else 0xFFFFFF;
            p.set(x, y, v);
        };
    }

    fn fillVideo(p: *TestPic, r: Rect16, t: u32) void {
        var seed: u32 = 0x9E3779B9 *% (t + 1);
        for (r.top..r.bottom) |y| for (r.left..r.right) |x| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            const fx: u32 = @intCast(x - r.left);
            const fy: u32 = @intCast(y - r.top);
            const b: u32 = (fx * 3 + t * 5 + (seed & 7)) & 0xFF;
            const g: u32 = (fy * 2 + t * 3 + (seed >> 3 & 7)) & 0xFF;
            const rr: u32 = ((fx + fy) + t * 7 + (seed >> 6 & 7)) & 0xFF;
            p.set(x, y, b | g << 8 | rr << 16);
        };
    }
};

/// The tight boxes a diff reports for `r`: one per 64-px tile row.
fn tileBoxes(r: Rect16, out: []Rect16) []Rect16 {
    var n: usize = 0;
    var y: u32 = r.top / 64 * 64;
    while (y < r.bottom) : (y += 64) {
        out[n] = .{ .left = r.left, .top = @intCast(@max(y, r.top)), .right = r.right, .bottom = @intCast(@min(y + 64, r.bottom)) };
        n += 1;
    }
    return out[0..n];
}

const Ev = struct { ms: i64, ev: Event };

fn run(d: *Detector, p: *TestPic, start_ms: i64, ms: i64, fps: u32, change: *const fn (*TestPic, u32) ?Rect16, events: *std.ArrayList(Ev), gpa: std.mem.Allocator) !i64 {
    var t = start_ms;
    var frame: u32 = 0;
    const step: i64 = @divTrunc(1000, fps);
    var buf: [64]Rect16 = undefined;
    while (t < start_ms + ms) : (t += step) {
        if (change(p, frame)) |r| d.notify(tileBoxes(r, &buf));
        if (d.tick(t, p.pic())) |ev| try events.append(gpa, .{ .ms = t - start_ms, .ev = ev });
        frame += 1;
    }
    return t;
}

const video_rect: Rect16 = .{ .left = 1600, .top = 900, .right = 2240, .bottom = 1260 }; // 640x360 on 4K

fn playVideo(p: *TestPic, frame: u32) ?Rect16 {
    p.fillVideo(video_rect, frame);
    return video_rect;
}

fn stillScreen(_: *TestPic, _: u32) ?Rect16 {
    return null;
}

test "a 640x360 video on a still 4K screen becomes a region at the third detection" {
    const gpa = testing.allocator;
    var p = try TestPic.init(gpa, 3840, 2160);
    defer p.deinit(gpa);
    var d: Detector = .{};
    defer d.deinit(gpa);
    try d.resize(gpa, 3840, 2160);
    var evs: std.ArrayList(Ev) = .empty;
    defer evs.deinit(gpa);
    _ = try run(&d, &p, 0, 4000, 30, &playVideo, &evs, gpa);
    try testing.expectEqual(@as(usize, 1), evs.items.len);
    try testing.expectEqual(Event.started, evs.items[0].ev);
    // The first detection (~1 s) sights it, the next two validate it.
    try testing.expect(evs.items[0].ms > 3000 and evs.items[0].ms < 3200);
    // Cells 50..69 x 28..39 (y 896..1280), one row taller: to 1312.
    try testing.expectEqual(Rect16{ .left = 1600, .top = 896, .right = 2240, .bottom = 1312 }, d.region().?);
}

test "the region ends at the first detection after the video stops, 1-2 s later" {
    const gpa = testing.allocator;
    var p = try TestPic.init(gpa, 3840, 2160);
    defer p.deinit(gpa);
    var d: Detector = .{};
    defer d.deinit(gpa);
    try d.resize(gpa, 3840, 2160);
    var evs: std.ArrayList(Ev) = .empty;
    defer evs.deinit(gpa);
    const t = try run(&d, &p, 0, 5000, 30, &playVideo, &evs, gpa);
    try testing.expect(d.region() != null);
    evs.clearRetainingCapacity();
    _ = try run(&d, &p, t, 3000, 30, &stillScreen, &evs, gpa);
    try testing.expectEqual(@as(usize, 1), evs.items.len);
    try testing.expectEqual(Event.ended, evs.items[0].ev);
    try testing.expect(evs.items[0].ms >= 1000 and evs.items[0].ms <= 2100);
    try testing.expect(d.region() == null);
}

fn scrollText(p: *TestPic, frame: u32) ?Rect16 {
    const r: Rect16 = .{ .left = 200, .top = 100, .right = 1000, .bottom = 700 };
    p.fillText(r, frame * 3);
    return r;
}

fn typing(p: *TestPic, frame: u32) ?Rect16 {
    if (frame % 4 != 0) return null;
    const ch = frame / 4;
    const x: u16 = @intCast(300 + (ch % 80) * 8);
    const y: u16 = @intCast(400 + (ch / 80) * 16);
    const r: Rect16 = .{ .left = x, .top = y, .right = x + 9, .bottom = y + 16 };
    p.fillVideo(.{ .left = x, .top = y, .right = x + 7, .bottom = y + 12 }, frame);
    return r;
}

fn blinkCursor(p: *TestPic, frame: u32) ?Rect16 {
    if (frame % 16 != 0) return null;
    const r: Rect16 = .{ .left = 700, .top = 700, .right = 702, .bottom = 718 };
    p.fillVideo(r, frame);
    return r;
}

test "scrolling text, typing and a blinking cursor never become a region" {
    const gpa = testing.allocator;
    for ([_]*const fn (*TestPic, u32) ?Rect16{ &scrollText, &typing, &blinkCursor }) |change| {
        var p = try TestPic.init(gpa, 3840, 2160);
        defer p.deinit(gpa);
        var d: Detector = .{};
        defer d.deinit(gpa);
        try d.resize(gpa, 3840, 2160);
        var evs: std.ArrayList(Ev) = .empty;
        defer evs.deinit(gpa);
        _ = try run(&d, &p, 0, 8000, 30, change, &evs, gpa);
        try testing.expectEqual(@as(usize, 0), evs.items.len);
        try testing.expect(d.region() == null);
    }
}

fn fullScreenVideo(p: *TestPic, frame: u32) ?Rect16 {
    const r: Rect16 = .{ .left = 0, .top = 0, .right = 1280, .bottom = 720 };
    p.fillVideo(r, frame);
    return r;
}

test "a full-screen video becomes a whole-screen region" {
    const gpa = testing.allocator;
    var p = try TestPic.init(gpa, 1280, 720);
    defer p.deinit(gpa);
    var d: Detector = .{};
    defer d.deinit(gpa);
    try d.resize(gpa, 1280, 720);
    var evs: std.ArrayList(Ev) = .empty;
    defer evs.deinit(gpa);
    _ = try run(&d, &p, 0, 4000, 24, &fullScreenVideo, &evs, gpa);
    try testing.expectEqual(@as(usize, 1), evs.items.len);
    try testing.expectEqual(Rect16{ .left = 0, .top = 0, .right = 1280, .bottom = 720 }, d.region().?);
}

fn slowSlides(p: *TestPic, frame: u32) ?Rect16 {
    if (frame % 8 != 0) return null;
    p.fillVideo(video_rect, frame);
    return video_rect;
}

test "image content changing 4 times a second is not video" {
    const gpa = testing.allocator;
    var p = try TestPic.init(gpa, 3840, 2160);
    defer p.deinit(gpa);
    var d: Detector = .{};
    defer d.deinit(gpa);
    try d.resize(gpa, 3840, 2160);
    var evs: std.ArrayList(Ev) = .empty;
    defer evs.deinit(gpa);
    _ = try run(&d, &p, 0, 6000, 32, &slowSlides, &evs, gpa);
    try testing.expectEqual(@as(usize, 0), evs.items.len);
}

test "a moved video ends the region and starts a new one where it plays" {
    const gpa = testing.allocator;
    var p = try TestPic.init(gpa, 3840, 2160);
    defer p.deinit(gpa);
    var d: Detector = .{};
    defer d.deinit(gpa);
    try d.resize(gpa, 3840, 2160);
    var evs: std.ArrayList(Ev) = .empty;
    defer evs.deinit(gpa);
    const t = try run(&d, &p, 0, 4000, 30, &playVideo, &evs, gpa);
    try testing.expectEqual(@as(usize, 1), evs.items.len);
    evs.clearRetainingCapacity();
    const moved = struct {
        fn f(pp: *TestPic, frame: u32) ?Rect16 {
            const r: Rect16 = .{ .left = 200, .top = 200, .right = 840, .bottom = 560 };
            pp.fillVideo(r, frame);
            return r;
        }
    }.f;
    _ = try run(&d, &p, t, 6000, 30, &moved, &evs, gpa);
    try testing.expectEqual(@as(usize, 2), evs.items.len);
    try testing.expectEqual(Event.ended, evs.items[0].ev);
    try testing.expectEqual(Event.started, evs.items[1].ev);
    try testing.expectEqual(Rect16{ .left = 192, .top = 192, .right = 864, .bottom = 608 }, d.region().?);
}

test "withinBounds takes the edge that moved most per axis" {
    const t: Rect = .{ .left = 100, .top = 100, .right = 300, .bottom = 200 };
    try testing.expect(Detector.withinBounds(t, .{ .left = 132, .top = 68, .right = 300, .bottom = 200 }).within);
    const far = Detector.withinBounds(t, .{ .left = 100, .top = 100, .right = 333, .bottom = 200 });
    try testing.expect(!far.within);
    try testing.expectEqual(@as(u32, 33), far.offset);
}

test "classifyBlock: one colour is solid, a page of text is text, a photo-like block is image" {
    const gpa = testing.allocator;
    var p = try TestPic.init(gpa, 256, 128);
    defer p.deinit(gpa);
    const r: Rect16 = .{ .left = 64, .top = 0, .right = 128, .bottom = 64 };
    try testing.expectEqual(Class.text, classifyBlock(p.pic(), r));
    p.fillVideo(r, 3);
    try testing.expectEqual(Class.image, classifyBlock(p.pic(), r));
    for (0..64) |y| for (64..128) |x| p.set(x, y, 0x336699);
    try testing.expectEqual(Class.solid, classifyBlock(p.pic(), r));
    try testing.expectEqual(Class.text, classifyBlock(p.pic(), .{ .left = 192, .top = 64, .right = 256, .bottom = 100 }));
}

test "resize to another size forgets the region; notify outside the surface is ignored" {
    const gpa = testing.allocator;
    var d: Detector = .{};
    defer d.deinit(gpa);
    try d.resize(gpa, 100, 70);
    try testing.expectEqual(@as(u32, 4), d.cols);
    try testing.expectEqual(@as(u32, 3), d.rows);
    d.notify(&.{ .{ .left = 99, .top = 69, .right = 300, .bottom = 300 }, .{ .left = 200, .top = 0, .right = 300, .bottom = 10 }, .{ .left = 5, .top = 5, .right = 5, .bottom = 9 } });
    try testing.expectEqual(@as(u16, 1), d.counts[2 * 4 + 3]);
    var sum: u32 = 0;
    for (d.counts) |n| sum += n;
    try testing.expectEqual(@as(u32, 1), sum);
    d.tracked = .{ .left = 0, .top = 0, .right = 32, .bottom = 32 };
    d.active = true;
    try d.resize(gpa, 64, 64);
    try testing.expect(d.region() == null);
}
