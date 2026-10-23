//! Screen to RDPGFX surface updates (MS-RDPEGFX). Hyprland reports every frame fully damaged, so
//! 64x64 tiles are diffed against a shadow of the client's picture and sent as planar runs.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const gfx = @import("../proto/gfx.zig");
const planar = @import("../codec/planar.zig");

pub const tile: u32 = 64;

pub const Encoder = struct {
    gpa: std.mem.Allocator,
    width: u32 = 0,
    height: u32 = 0,
    /// What the client shows, `width * 4` bytes per row (BGRX).
    shadow: []u8 = &.{},
    /// False until the client has been sent a whole frame of this size.
    valid: bool = false,
    bitmap: std.ArrayList(u8) = .empty,
    /// Rects of the last `diff`/`encode` call, surface coordinates.
    rects: std.ArrayList(gfx.Rect16) = .empty,
    /// Per `rects` entry after a `diff` of a valid shadow: bounding box of its changed pixels.
    tight: std.ArrayList(gfx.Rect16) = .empty,
    /// Tiles last sent with a lossy codec; re-sent losslessly once quiet.
    lossy: std.DynamicBitSetUnmanaged = .{},
    /// Tiles not sent at all (frame cut at its byte budget); the shadow holds their content.
    owed: std.DynamicBitSetUnmanaged = .{},
    /// Per tile, when its content last changed (ms, caller's clock).
    changed_ms: []i64 = &.{},
    /// Per lossy tile, the H.264 QP shown there, or `lossy_other`.
    lossy_qp: []u8 = &.{},

    pub fn init(gpa: std.mem.Allocator) Encoder {
        return .{ .gpa = gpa };
    }

    pub fn deinit(e: *Encoder) void {
        e.gpa.free(e.changed_ms);
        e.gpa.free(e.lossy_qp);
        e.owed.deinit(e.gpa);
        e.lossy.deinit(e.gpa);
        e.gpa.free(e.shadow);
        e.bitmap.deinit(e.gpa);
        e.rects.deinit(e.gpa);
        e.tight.deinit(e.gpa);
    }

    /// Sets a new surface size; the next frame is sent whole. On OutOfMemory the old size is kept.
    pub fn reset(e: *Encoder, w: u32, h: u32) !void {
        if (w != e.width or h != e.height) {
            const shadow = try e.gpa.alloc(u8, @as(usize, w) * h * 4);
            errdefer e.gpa.free(shadow);
            const tiles = tilesFor(w) * tilesFor(h);
            const changed = try e.gpa.alloc(i64, tiles);
            errdefer e.gpa.free(changed);
            const qps = try e.gpa.alloc(u8, tiles);
            errdefer e.gpa.free(qps);
            // Grow `owed` first: if `lossy` then fails, `owed` is merely oversized.
            if (tiles > e.owed.bit_length) try e.owed.resize(e.gpa, tiles, false);
            try e.lossy.resize(e.gpa, tiles, false);
            try e.owed.resize(e.gpa, tiles, false);
            e.gpa.free(e.changed_ms);
            e.changed_ms = changed;
            e.gpa.free(e.lossy_qp);
            e.lossy_qp = qps;
            e.gpa.free(e.shadow);
            e.shadow = shadow;
            e.width = w;
            e.height = h;
        }
        e.lossy.unsetAll();
        e.owed.unsetAll();
        @memset(e.changed_ms, 0);
        @memset(e.lossy_qp, lossy_other);
        e.valid = false;
    }

    fn tilesFor(px: u32) u32 {
        return (px + tile - 1) / tile;
    }

    fn tilesX(e: *const Encoder) u32 {
        return tilesFor(e.width);
    }

    fn tilesY(e: *const Encoder) u32 {
        return tilesFor(e.height);
    }

    /// Marks the tiles under `rects` as sent lossy (non-H.264 codec) or exact; either way not owed.
    pub fn markLossy(e: *Encoder, rects: []const gfx.Rect16, lossy: bool) void {
        e.markTiles(rects, lossy, lossy_other);
    }

    pub fn markLossyQp(e: *Encoder, rects: []const gfx.Rect16, qp: u8) void {
        e.markTiles(rects, true, qp);
    }

    fn markTiles(e: *Encoder, rects: []const gfx.Rect16, lossy: bool, qp: u8) void {
        const tx_n = e.tilesX();
        for (rects) |r| {
            var ty = r.top / tile;
            while (ty * tile < r.bottom) : (ty += 1) {
                var tx = r.left / tile;
                while (tx * tile < r.right) : (tx += 1) {
                    e.lossy.setValue(ty * tx_n + tx, lossy);
                    e.lossy_qp[ty * tx_n + tx] = qp;
                    e.owed.unset(ty * tx_n + tx);
                }
            }
        }
    }

    /// QP marker for a lossy tile from a non-H.264 codec or of unknown quality.
    pub const lossy_other: u8 = 0xFF;

    /// Marks the tiles under `rects` lossy at `qp` unless owed (owed supersedes lossy).
    pub fn markLossyKeepOwed(e: *Encoder, rects: []const gfx.Rect16, qp: u8) void {
        const tx_n = e.tilesX();
        for (rects) |r| {
            var ty = r.top / tile;
            while (ty * tile < r.bottom) : (ty += 1) {
                var tx = r.left / tile;
                while (tx * tile < r.right) : (tx += 1) {
                    if (!e.owed.isSet(ty * tx_n + tx)) {
                        e.lossy.set(ty * tx_n + tx);
                        e.lossy_qp[ty * tx_n + tx] = qp;
                    }
                }
            }
        }
    }

    /// Appends runs of H.264 tiles shown above `qp` and not in `except` to `out`; returns the tile count.
    pub fn lossyAboveExcept(e: *const Encoder, qp: u8, except: *const std.DynamicBitSetUnmanaged, out: *std.ArrayList(gfx.Rect16)) !usize {
        const tx_n = e.tilesX();
        var n: usize = 0;
        var ty: u32 = 0;
        while (ty < e.tilesY()) : (ty += 1) {
            var tx: u32 = 0;
            while (tx < tx_n) {
                if (!e.refinableAt(ty * tx_n + tx, qp, except)) {
                    tx += 1;
                    continue;
                }
                const start = tx;
                while (tx < tx_n and e.refinableAt(ty * tx_n + tx, qp, except)) tx += 1;
                try out.append(e.gpa, .{
                    .left = @intCast(start * tile),
                    .top = @intCast(ty * tile),
                    .right = @intCast(@min(tx * tile, e.width)),
                    .bottom = @intCast(@min((ty + 1) * tile, e.height)),
                });
                n += tx - start;
            }
        }
        return n;
    }

    fn refinableAt(e: *const Encoder, i: usize, qp: u8, except: *const std.DynamicBitSetUnmanaged) bool {
        const q = e.lossy_qp[i];
        if (i < except.bit_length and except.isSet(i)) return false;
        return e.lossy.isSet(i) and q != lossy_other and q > qp;
    }

    /// Highest QP above `min_qp` of a lossy H.264 tile quiet for `quiet_ms` (of any, when `all`).
    pub fn quietQpAbove(e: *const Encoder, now_ms: i64, quiet_ms: i64, min_qp: u8, all: bool) ?u8 {
        var best: ?u8 = null;
        var it = e.lossy.iterator(.{});
        while (it.next()) |i| {
            const q = e.lossy_qp[i];
            if (q == lossy_other or q <= min_qp) continue;
            if (!all and now_ms - e.changed_ms[i] < quiet_ms) continue;
            best = @max(best orelse 0, q);
        }
        return best;
    }

    pub fn hasLossy(e: *const Encoder) bool {
        return e.lossy.count() > 0;
    }

    /// Marks the tile-aligned `rects` as not sent (owed); owed supersedes lossy.
    pub fn owe(e: *Encoder, rects: []const gfx.Rect16) void {
        const tx_n = e.tilesX();
        for (rects) |r| {
            var ty = r.top / tile;
            while (ty * tile < r.bottom) : (ty += 1) {
                var tx = r.left / tile;
                while (tx * tile < r.right) : (tx += 1) {
                    e.owed.set(ty * tx_n + tx);
                    e.lossy.unset(ty * tx_n + tx);
                }
            }
        }
    }

    /// Owes the whole surface; the next frames repaint it as the budget allows.
    pub fn oweAll(e: *Encoder) void {
        if (e.width == 0 or e.height == 0) return;
        e.owe(&.{.{ .left = 0, .top = 0, .right = @intCast(e.width), .bottom = @intCast(e.height) }});
    }

    pub fn hasOwed(e: *const Encoder) bool {
        return e.owed.count() > 0;
    }

    /// After `diff`: moves the owed tiles into `rects` as whole-tile runs. On OutOfMemory nothing is lost.
    pub fn mergeOwed(e: *Encoder) !void {
        if (!e.hasOwed()) return;
        var merged = try e.owed.clone(e.gpa);
        defer merged.deinit(e.gpa);
        const tx_n = e.tilesX();
        for (e.rects.items) |r| {
            var ty = r.top / tile;
            while (ty * tile < r.bottom) : (ty += 1) {
                var tx = r.left / tile;
                while (tx * tile < r.right) : (tx += 1) merged.set(ty * tx_n + tx);
            }
        }
        _ = try e.takeTiles(&merged);
        e.owed.unsetAll();
    }

    /// Moves the owed tiles into `rects` as runs. On OutOfMemory nothing is lost.
    pub fn takeOwed(e: *Encoder) !usize {
        return e.takeTiles(&e.owed);
    }

    /// The tiles of the last `diff`'s rects changed at `now_ms`.
    pub fn touch(e: *Encoder, now_ms: i64) void {
        const tx_n = e.tilesX();
        for (e.rects.items) |r| {
            var ty = r.top / tile;
            while (ty * tile < r.bottom) : (ty += 1) {
                var tx = r.left / tile;
                while (tx * tile < r.right) : (tx += 1) e.changed_ms[ty * tx_n + tx] = now_ms;
            }
        }
    }

    /// Appends runs of lossy tiles quiet for `quiet_ms` to `out` and clears them: H.264 tiles at QP
    /// <= `max_qp` (any if `lossy_other`) and all others, at most `max_px` of tile area. Returns the tile count.
    pub fn takeQuietLossyAt(e: *Encoder, now_ms: i64, quiet_ms: i64, max_qp: u8, max_px: u64, out: *std.ArrayList(gfx.Rect16)) !usize {
        const tx_n = e.tilesX();
        var n: usize = 0;
        var px: u64 = 0;
        var ty: u32 = 0;
        while (ty < e.tilesY()) : (ty += 1) {
            var tx: u32 = 0;
            while (tx < tx_n) {
                if (!e.quietLossy(ty * tx_n + tx, now_ms, quiet_ms, max_qp) or px >= max_px) {
                    tx += 1;
                    continue;
                }
                const start = tx;
                while (tx < tx_n and px < max_px and e.quietLossy(ty * tx_n + tx, now_ms, quiet_ms, max_qp)) : (tx += 1) {
                    px += @as(u64, tile) * tile;
                }
                try out.append(e.gpa, .{
                    .left = @intCast(start * tile),
                    .top = @intCast(ty * tile),
                    .right = @intCast(@min(tx * tile, e.width)),
                    .bottom = @intCast(@min((ty + 1) * tile, e.height)),
                });
                for (start..tx) |i| e.lossy.unset(ty * tx_n + i);
                n += tx - start;
            }
        }
        return n;
    }

    fn quietLossy(e: *const Encoder, i: usize, now_ms: i64, quiet_ms: i64, max_qp: u8) bool {
        if (!e.lossy.isSet(i) or now_ms - e.changed_ms[i] < quiet_ms) return false;
        const q = e.lossy_qp[i];
        return max_qp == lossy_other or q == lossy_other or q <= max_qp;
    }

    pub fn anyQuietLossy(e: *const Encoder, now_ms: i64, quiet_ms: i64) bool {
        var it = e.lossy.iterator(.{});
        while (it.next()) |i| if (now_ms - e.changed_ms[i] >= quiet_ms) return true;
        return false;
    }

    pub fn anyQuietLossyAt(e: *const Encoder, now_ms: i64, quiet_ms: i64, max_qp: u8) bool {
        var it = e.lossy.iterator(.{});
        while (it.next()) |i| {
            if (now_ms - e.changed_ms[i] < quiet_ms) continue;
            const q = e.lossy_qp[i];
            if (q == lossy_other or q <= max_qp) return true;
        }
        return false;
    }

    /// Earliest time a lossy tile becomes quiet for `quiet_ms`; null if none is lossy.
    pub fn nextQuietMs(e: *const Encoder, quiet_ms: i64) ?i64 {
        var best: ?i64 = null;
        var it = e.lossy.iterator(.{});
        while (it.next()) |i| {
            const t = e.changed_ms[i] + quiet_ms;
            best = if (best) |b| @min(b, t) else t;
        }
        return best;
    }

    pub fn anyLossy(e: *const Encoder, r: gfx.Rect16) bool {
        const tx_n = e.tilesX();
        var ty = r.top / tile;
        while (ty * tile < r.bottom) : (ty += 1) {
            var tx = r.left / tile;
            while (tx * tile < r.right) : (tx += 1) if (e.lossy.isSet(ty * tx_n + tx)) return true;
        }
        return false;
    }

    /// Bounding box of the changed pixels of `rects[i]`, or the whole rect when none was computed.
    pub fn tightRect(e: *const Encoder, i: usize) gfx.Rect16 {
        return if (e.tight.items.len == e.rects.items.len) e.tight.items[i] else e.rects.items[i];
    }

    /// Moves the lossy tiles into `rects` as runs for a lossless re-send. On OutOfMemory nothing is lost.
    pub fn takeLossy(e: *Encoder) !usize {
        return e.takeTiles(&e.lossy);
    }

    fn takeTiles(e: *Encoder, set: *std.DynamicBitSetUnmanaged) !usize {
        e.rects.clearRetainingCapacity();
        e.tight.clearRetainingCapacity();
        const tx_n = e.tilesX();
        var ty: u32 = 0;
        while (ty < e.tilesY()) : (ty += 1) {
            var tx: u32 = 0;
            while (tx < tx_n) {
                if (!set.isSet(ty * tx_n + tx)) {
                    tx += 1;
                    continue;
                }
                const start = tx;
                while (tx < tx_n and set.isSet(ty * tx_n + tx)) tx += 1;
                try e.rects.append(e.gpa, .{
                    .left = @intCast(start * tile),
                    .top = @intCast(ty * tile),
                    .right = @intCast(@min(tx * tile, e.width)),
                    .bottom = @intCast(@min((ty + 1) * tile, e.height)),
                });
            }
        }
        set.unsetAll();
        return e.rects.items.len;
    }

    pub fn changedPixels(e: *const Encoder) u64 {
        var n: u64 = 0;
        for (e.rects.items) |r| n += @as(u64, r.right - r.left) * (r.bottom - r.top);
        return n;
    }

    /// The client lost its picture; the next frame is sent whole.
    pub fn invalidate(e: *Encoder) void {
        e.valid = false;
    }

    /// Copies the parts of `pixels` (BGRX) that differ from the shadow into it and lists them in
    /// `rects`; returns their count (0: send no frame). On OutOfMemory the shadow is untouched.
    pub fn diff(e: *Encoder, pixels: []const u8, stride: usize) !usize {
        e.rects.clearRetainingCapacity();
        e.tight.clearRetainingCapacity();
        const tiles_x = (e.width + tile - 1) / tile;
        var ty: u32 = 0;
        while (ty * tile < e.height) : (ty += 1) {
            const y0 = ty * tile;
            const th = @min(tile, e.height - y0);
            var run_start: ?u32 = null;
            var run_box: gfx.Rect16 = undefined;
            var tx: u32 = 0;
            while (tx <= tiles_x) : (tx += 1) {
                const box: ?gfx.Rect16 = if (tx == tiles_x) null else if (!e.valid) tileRect(e, tx, y0, th) else e.changedBox(pixels, stride, tx * tile, y0, th);
                if (box) |b| {
                    run_box = if (run_start == null) b else union16(run_box, b);
                    if (run_start == null) run_start = tx;
                    continue;
                }
                const start = run_start orelse continue;
                run_start = null;
                const x0 = start * tile;
                const x1 = @min(tx * tile, e.width);
                try e.rects.ensureUnusedCapacity(e.gpa, 1);
                try e.tight.append(e.gpa, run_box);
                e.rects.appendAssumeCapacity(.{ .left = @intCast(x0), .top = @intCast(y0), .right = @intCast(x1), .bottom = @intCast(y0 + th) });
            }
        }
        // Regions do not overlap, so copying after all comparisons is safe.
        for (e.rects.items) |r| e.copyToShadow(pixels, stride, r.left, r.top, r.right - r.left, r.bottom - r.top);
        // A whole frame covers whatever was owed.
        if (!e.valid) e.owed.unsetAll();
        e.valid = true;
        return e.rects.items.len;
    }

    /// `diff`, then planar WireToSurface1 PDUs for the changed regions.
    pub fn encode(e: *Encoder, w: *bytes.Writer, surface_id: u16, pixels: []const u8, stride: usize) !usize {
        const n = try e.diff(pixels, stride);
        try e.writePlanar(w, surface_id);
        return n;
    }

    pub fn encodeShadow(e: *Encoder, w: *bytes.Writer, surface_id: u16) !usize {
        e.rects.clearRetainingCapacity();
        e.tight.clearRetainingCapacity();
        var y0: u32 = 0;
        while (y0 < e.height) : (y0 += tile) {
            try e.rects.append(e.gpa, .{ .left = 0, .top = @intCast(y0), .right = @intCast(e.width), .bottom = @intCast(@min(y0 + tile, e.height)) });
        }
        try e.writePlanar(w, surface_id);
        e.owed.unsetAll();
        e.valid = true;
        return e.rects.items.len;
    }

    pub fn writePlanar(e: *Encoder, w: *bytes.Writer, surface_id: u16) !void {
        for (e.rects.items) |r| try e.writePlanarRect(w, surface_id, r);
    }

    pub fn writePlanarRect(e: *Encoder, w: *bytes.Writer, surface_id: u16, r: gfx.Rect16) !void {
        const sstride = @as(usize, e.width) * 4;
        e.bitmap.clearRetainingCapacity();
        const first = e.shadow[@as(usize, r.top) * sstride + @as(usize, r.left) * 4 ..];
        try planar.encodePlanar(e.gpa, &e.bitmap, first, sstride, r.right - r.left, r.bottom - r.top);
        const p = try gfx.beginWireToSurface1(w, surface_id, .planar, r, e.bitmap.items.len);
        try w.bytes(e.bitmap.items);
        p.finish(w);
    }

    /// Shadow pixels from (x, y) on, `shadowStride` apart (legacy bitmap path).
    pub fn shadowAt(e: *const Encoder, x: u32, y: u32) []const u8 {
        return e.shadow[(@as(usize, y) * e.width + x) * 4 ..];
    }

    pub fn shadowStride(e: *const Encoder) usize {
        return @as(usize, e.width) * 4;
    }

    fn tileRect(e: *const Encoder, tx: u32, y0: u32, th: u32) gfx.Rect16 {
        const x0 = tx * tile;
        return .{ .left = @intCast(x0), .top = @intCast(y0), .right = @intCast(@min(x0 + tile, e.width)), .bottom = @intCast(y0 + th) };
    }

    fn changedBox(e: *const Encoder, pixels: []const u8, stride: usize, x0: u32, y0: u32, th: u32) ?gfx.Rect16 {
        const tw = @min(tile, e.width - x0);
        const sstride = @as(usize, e.width) * 4;
        const off = @as(usize, x0) * 4;
        const len = @as(usize, tw) * 4;
        var top: ?u32 = null;
        var bottom: u32 = 0;
        var left: u32 = tw;
        var right: u32 = 0;
        var r: u32 = 0;
        while (r < th) : (r += 1) {
            const y = @as(usize, y0 + r);
            const a = pixels[y * stride + off ..][0..len];
            const b = e.shadow[y * sstride + off ..][0..len];
            if (std.mem.eql(u8, a, b)) continue;
            if (top == null) top = r;
            bottom = r + 1;
            var lx: u32 = 0;
            while (lx < left and std.mem.eql(u8, a[lx * 4 ..][0..4], b[lx * 4 ..][0..4])) lx += 1;
            left = lx;
            var rx: u32 = tw;
            while (rx > right and std.mem.eql(u8, a[(rx - 1) * 4 ..][0..4], b[(rx - 1) * 4 ..][0..4])) rx -= 1;
            right = rx;
        }
        const t = top orelse return null;
        return .{ .left = @intCast(x0 + left), .top = @intCast(y0 + t), .right = @intCast(x0 + right), .bottom = @intCast(y0 + bottom) };
    }

    fn copyToShadow(e: *Encoder, pixels: []const u8, stride: usize, x0: u32, y0: u32, rw: u32, rh: u32) void {
        const sstride = @as(usize, e.width) * 4;
        const off = @as(usize, x0) * 4;
        const len = @as(usize, rw) * 4;
        var r: u32 = 0;
        while (r < rh) : (r += 1) {
            const y = @as(usize, y0 + r);
            @memcpy(e.shadow[y * sstride + off ..][0..len], pixels[y * stride + off ..][0..len]);
        }
    }
};

fn union16(a: gfx.Rect16, b: gfx.Rect16) gfx.Rect16 {
    return .{ .left = @min(a.left, b.left), .top = @min(a.top, b.top), .right = @max(a.right, b.right), .bottom = @max(a.bottom, b.bottom) };
}

fn testFrame(gpa: std.mem.Allocator, w: u32, h: u32, stride: usize) ![]u8 {
    const px = try gpa.alloc(u8, stride * h);
    for (0..h) |y| for (0..w) |x| {
        const p = px[y * stride + x * 4 ..][0..4];
        p.* = .{ @truncate(x * 7), @truncate(y * 3), @truncate(x ^ y), 0 };
    };
    return px;
}

test "first frame is sent whole, then only changed tiles" {
    const gpa = std.testing.allocator;
    const w: u32 = 300;
    const h: u32 = 150;
    const stride: usize = 1300; // padded rows, like a real capture
    const px = try testFrame(gpa, w, h, stride);
    defer gpa.free(px);

    var e = Encoder.init(gpa);
    defer e.deinit();
    try e.reset(w, h);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var bw = bytes.Writer.init(&out, gpa);

    try std.testing.expectEqual(@as(usize, 3), try e.encode(&bw, 1, px, stride));
    try std.testing.expectEqual(gfx.Rect16{ .left = 0, .top = 128, .right = 300, .bottom = 150 }, e.rects.items[2]);

    out.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 0), try e.encode(&bw, 1, px, stride));
    try std.testing.expectEqual(@as(usize, 0), out.items.len);

    // One pixel in tile (2,1) and one in tile (4,1): two separate runs.
    px[70 * stride + 130 * 4] ^= 0xFF;
    px[70 * stride + 299 * 4 + 2] ^= 0x01;
    try std.testing.expectEqual(@as(usize, 2), try e.encode(&bw, 1, px, stride));
    try std.testing.expectEqual(gfx.Rect16{ .left = 128, .top = 64, .right = 192, .bottom = 128 }, e.rects.items[0]);
    try std.testing.expectEqual(gfx.Rect16{ .left = 256, .top = 64, .right = 300, .bottom = 128 }, e.rects.items[1]);

    px[10 * stride + 10 * 4] ^= 1;
    px[10 * stride + 70 * 4] ^= 1;
    try std.testing.expectEqual(@as(usize, 1), try e.encode(&bw, 1, px, stride));
    try std.testing.expectEqual(gfx.Rect16{ .left = 0, .top = 0, .right = 128, .bottom = 64 }, e.rects.items[0]);

    for (0..h) |y| try std.testing.expectEqualSlices(u8, px[y * stride ..][0 .. w * 4], e.shadow[y * w * 4 ..][0 .. w * 4]);

    try std.testing.expectEqual(@as(usize, 3), try e.encodeShadow(&bw, 1));
}

test "planar payload decodes back to the frame" {
    const gpa = std.testing.allocator;
    const w: u32 = 100;
    const h: u32 = 70;
    const stride: usize = w * 4;
    const px = try testFrame(gpa, w, h, stride);
    defer gpa.free(px);
    var e = Encoder.init(gpa);
    defer e.deinit();
    try e.reset(w, h);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var bw = bytes.Writer.init(&out, gpa);
    _ = try e.encode(&bw, 7, px, stride);

    const got = try gpa.alloc(u8, stride * h);
    defer gpa.free(got);
    @memset(got, 0xAA);
    var r = bytes.Reader.init(out.items);
    var n: usize = 0;
    while (r.remaining() > 0) : (n += 1) {
        const cmd = try r.u16le();
        _ = try r.u16le(); // flags
        const pdu_len = try r.u32le();
        try std.testing.expectEqual(@as(u16, 0x0001), cmd); // WIRE_TO_SURFACE_1
        var body = bytes.Reader.init(try r.bytes(pdu_len - 8));
        try std.testing.expectEqual(@as(u16, 7), try body.u16le());
        try std.testing.expectEqual(@as(u16, @backingInt(gfx.CodecId.planar)), try body.u16le());
        _ = try body.byte(); // pixel format
        const left = try body.u16le();
        const top = try body.u16le();
        const right = try body.u16le();
        const bottom = try body.u16le();
        const len = try body.u32le();
        const data = try body.bytes(len);
        _ = try planar.decodePlanar(data, right - left, bottom - top, got[@as(usize, top) * stride + @as(usize, left) * 4 ..], stride);
    }
    try std.testing.expectEqual(@as(usize, 2), n);
    for (0..h) |y| for (0..w) |x| {
        // Planar carries no alpha; compare B, G, R.
        try std.testing.expectEqualSlices(u8, px[y * stride + x * 4 ..][0..3], got[y * stride + x * 4 ..][0..3]);
    };
}

test "tight boxes: the changed pixels of each run; whole rects after an invalidation" {
    const gpa = std.testing.allocator;
    const w: u32 = 300;
    const h: u32 = 150;
    const px = try testFrame(gpa, w, h, w * 4);
    defer gpa.free(px);
    var e = Encoder.init(gpa);
    defer e.deinit();
    try e.reset(w, h);
    _ = try e.diff(px, w * 4);
    try std.testing.expectEqual(e.rects.items[1], e.tightRect(1));
    px[70 * w * 4 + 130 * 4] ^= 0xFF;
    px[100 * w * 4 + 140 * 4] ^= 0x01;
    px[66 * w * 4 + 200 * 4 + 2] ^= 0x10;
    try std.testing.expectEqual(@as(usize, 1), try e.diff(px, w * 4));
    try std.testing.expectEqual(gfx.Rect16{ .left = 128, .top = 64, .right = 256, .bottom = 128 }, e.rects.items[0]);
    try std.testing.expectEqual(gfx.Rect16{ .left = 130, .top = 66, .right = 201, .bottom = 101 }, e.tightRect(0));
    px[149 * w * 4 + 299 * 4] ^= 0x01;
    _ = try e.diff(px, w * 4);
    try std.testing.expectEqual(gfx.Rect16{ .left = 299, .top = 149, .right = 300, .bottom = 150 }, e.tightRect(0));
    e.markLossy(&.{.{ .left = 0, .top = 0, .right = 64, .bottom = 64 }}, true);
    try std.testing.expect(e.anyLossy(.{ .left = 10, .top = 10, .right = 20, .bottom = 20 }));
    try std.testing.expect(!e.anyLossy(.{ .left = 64, .top = 0, .right = 128, .bottom = 64 }));
    _ = try e.takeLossy();
    try std.testing.expectEqual(e.rects.items[0], e.tightRect(0));
}

test "lossy tiles are tracked and handed back as runs" {
    const gpa = std.testing.allocator;
    var e = Encoder.init(gpa);
    defer e.deinit();
    try e.reset(300, 150); // 5 x 3 tiles
    e.markLossy(&.{
        .{ .left = 0, .top = 0, .right = 300, .bottom = 64 },
        .{ .left = 128, .top = 64, .right = 192, .bottom = 128 },
    }, true);
    e.markLossy(&.{.{ .left = 128, .top = 0, .right = 192, .bottom = 64 }}, false);
    try std.testing.expect(e.hasLossy());
    try std.testing.expectEqual(@as(usize, 3), try e.takeLossy());
    try std.testing.expectEqual(gfx.Rect16{ .left = 0, .top = 0, .right = 128, .bottom = 64 }, e.rects.items[0]);
    try std.testing.expectEqual(gfx.Rect16{ .left = 192, .top = 0, .right = 300, .bottom = 64 }, e.rects.items[1]);
    try std.testing.expectEqual(gfx.Rect16{ .left = 128, .top = 64, .right = 192, .bottom = 128 }, e.rects.items[2]);
    try std.testing.expect(!e.hasLossy());
}

test "quiet lossy tiles are refined per tile; H.264 tiles keep their QP" {
    const gpa = std.testing.allocator;
    var e = Encoder.init(gpa);
    defer e.deinit();
    try e.reset(256, 128); // 4 x 2 tiles
    const row0: gfx.Rect16 = .{ .left = 0, .top = 0, .right = 256, .bottom = 64 };
    const t5: gfx.Rect16 = .{ .left = 64, .top = 64, .right = 128, .bottom = 128 };
    // Row 0: H.264 at QP 38 at 1000 ms; tile 5: another lossy codec at 1200 ms.
    try e.rects.append(gpa, row0);
    e.touch(1000);
    e.markLossyQp(&.{row0}, 38);
    e.rects.clearRetainingCapacity();
    try e.rects.append(gpa, t5);
    e.touch(1200);
    e.markLossy(&.{t5}, true);
    try std.testing.expectEqual(@as(?i64, 1233), e.nextQuietMs(233));
    // Quiet for 233 ms: nothing at 1100, row 0 at 1300.
    try std.testing.expect(!e.anyQuietLossy(1100, 233));
    try std.testing.expect(e.anyQuietLossy(1300, 233));
    try std.testing.expectEqual(@as(?u8, 38), e.quietQpAbove(1300, 233, 22, false));
    try std.testing.expectEqual(@as(?u8, null), e.quietQpAbove(1100, 233, 22, false));
    try std.testing.expectEqual(@as(?u8, 38), e.quietQpAbove(1100, 233, 22, true));
    var dirty: std.DynamicBitSetUnmanaged = try .initEmpty(gpa, 8);
    defer dirty.deinit(gpa);
    dirty.set(1);
    var out: std.ArrayList(gfx.Rect16) = .empty;
    defer out.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 3), try e.lossyAboveExcept(30, &dirty, &out));
    try std.testing.expectEqual(gfx.Rect16{ .left = 0, .top = 0, .right = 64, .bottom = 64 }, out.items[0]);
    try std.testing.expectEqual(gfx.Rect16{ .left = 128, .top = 0, .right = 256, .bottom = 64 }, out.items[1]);
    e.markLossyQp(&.{row0}, 22);
    try std.testing.expectEqual(@as(?u8, null), e.quietQpAbove(1300, 233, 22, false));
    out.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 4), try e.takeQuietLossyAt(1300, 233, 22, std.math.maxInt(u64), &out));
    try std.testing.expectEqual(row0, out.items[0]);
    try std.testing.expect(e.hasLossy()); // tile 5
    out.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 1), try e.takeQuietLossyAt(1433, 233, 22, std.math.maxInt(u64), &out));
    try std.testing.expectEqual(t5, out.items[0]);
    try std.testing.expect(!e.hasLossy());
}

test "owed tiles join the next frame's changes, supersede lossy, and go with a whole frame" {
    const gpa = std.testing.allocator;
    const w: u32 = 300;
    const h: u32 = 150; // 5 x 3 tiles
    const px = try testFrame(gpa, w, h, w * 4);
    defer gpa.free(px);
    var e = Encoder.init(gpa);
    defer e.deinit();
    try e.reset(w, h);
    _ = try e.diff(px, w * 4);
    // A cut frame sent only the top row.
    e.owe(&.{ .{ .left = 64, .top = 64, .right = 300, .bottom = 128 }, .{ .left = 0, .top = 128, .right = 300, .bottom = 150 } });
    try std.testing.expect(e.hasOwed());
    e.markLossy(&.{.{ .left = 0, .top = 0, .right = 300, .bottom = 64 }}, true);
    e.owe(&.{.{ .left = 0, .top = 0, .right = 64, .bottom = 64 }});
    try std.testing.expect(!e.anyLossy(.{ .left = 0, .top = 0, .right = 64, .bottom = 64 }));
    // One changed pixel in tile (2,0): rects are that tile plus every owed tile.
    px[10 * w * 4 + 130 * 4] ^= 0xFF;
    try std.testing.expectEqual(@as(usize, 1), try e.diff(px, w * 4));
    try e.mergeOwed();
    try std.testing.expect(!e.hasOwed());
    try std.testing.expectEqualSlices(gfx.Rect16, &.{
        .{ .left = 0, .top = 0, .right = 64, .bottom = 64 },
        .{ .left = 128, .top = 0, .right = 192, .bottom = 64 },
        .{ .left = 64, .top = 64, .right = 300, .bottom = 128 },
        .{ .left = 0, .top = 128, .right = 300, .bottom = 150 },
    }, e.rects.items);
    try std.testing.expectEqual(e.rects.items[1], e.tightRect(1));
    px[10 * w * 4 + 10 * 4] ^= 0xFF;
    _ = try e.diff(px, w * 4);
    try e.mergeOwed();
    try std.testing.expectEqual(@as(usize, 1), e.rects.items.len);
    try std.testing.expectEqual(gfx.Rect16{ .left = 10, .top = 10, .right = 11, .bottom = 11 }, e.tightRect(0));
    e.oweAll();
    e.markLossy(&.{.{ .left = 0, .top = 0, .right = 300, .bottom = 64 }}, false);
    try std.testing.expectEqual(@as(usize, 2), try e.takeOwed());
    try std.testing.expectEqual(gfx.Rect16{ .left = 0, .top = 64, .right = 300, .bottom = 128 }, e.rects.items[0]);
    try std.testing.expect(!e.hasOwed());
    e.oweAll();
    e.invalidate();
    _ = try e.diff(px, w * 4);
    try std.testing.expect(!e.hasOwed());
    e.oweAll();
    try e.reset(640, 480);
    try std.testing.expect(!e.hasOwed());
}
