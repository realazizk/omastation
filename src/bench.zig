//! `zig build bench -- [--size WxH] [--reps N] [--threads N] [--only a,b]`: times the graphics
//! pipeline's CPU work on synthetic frames. "video" is moving noise (every tile changes), "scroll"
//! shifts a fine pattern 6 px a frame (text-like). Numbers are per frame, averaged over `reps`.
//! Sections: lossless (tile diff, planar, ClearCodec), zgfx, rfx, prog, legacy (NSCodec,
//! interleaved RLE, bulk compression), h264 (VA-API), kernels.

const std = @import("std");
const builtin = @import("builtin");
const rfx = @import("codec/rfx.zig");
const dwt = @import("codec/rfx/dwt.zig");
const progressive = @import("codec/progressive.zig");
const workers = @import("codec/workers.zig");
const planar = @import("codec/planar.zig");
const clear = @import("codec/clear.zig");
const zgfx = @import("codec/zgfx.zig");
const nsc = @import("codec/nsc.zig");
const interleaved = @import("codec/interleaved.zig");
const bulk = @import("codec/bulk.zig");
const vaapi_h264 = @import("codec/vaapi_h264.zig");
const avc444 = @import("codec/avc444.zig");
const encoder_mod = @import("server/encoder.zig");
const bytes = @import("core/bytes.zig");
const gfx = @import("proto/gfx.zig");
const fbm = @import("server/framebuffer.zig");

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

const Row = struct { name: []const u8, ns: u64, bytes: usize, n: usize };

const Bench = struct {
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    rows: std.ArrayList(Row) = .empty,
    w: u16,
    h: u16,
    reps: usize,
    fb: fbm.Framebuffer,

    fn add(b: *Bench, name: []const u8, ns: u64, bytes_: usize, n: usize) !void {
        try b.rows.append(b.gpa, .{ .name = name, .ns = ns, .bytes = bytes_, .n = n });
    }

    fn addf(b: *Bench, comptime fmt: []const u8, args: anytype, ns: u64, bytes_: usize, n: usize) !void {
        try b.add(try std.fmt.allocPrint(b.arena, fmt, args), ns, bytes_, n);
    }

    fn section(b: *Bench, name: []const u8) !void {
        try b.add(name, 0, 0, 0);
    }

    fn report(b: *Bench) void {
        std.debug.print("{s:<58} {s:>9} {s:>9}\n", .{ "", "ms/frame", "KB/frame" });
        for (b.rows.items) |r| {
            if (r.n == 0) {
                std.debug.print("-- {s}\n", .{r.name});
                continue;
            }
            const n: f64 = @floatFromInt(r.n);
            std.debug.print("{s:<58} {d:9.2} {d:9.0}\n", .{ r.name, @as(f64, @floatFromInt(r.ns)) / 1e6 / n, @as(f64, @floatFromInt(r.bytes)) / 1024.0 / n });
        }
    }
};

const level_b: progressive.ComponentQuant = .{ .ll3 = 2, .hl3 = 2, .lh3 = 2, .hh3 = 3, .hl2 = 3, .lh2 = 3, .hh2 = 4, .hl1 = 4, .lh1 = 4, .hh1 = 4 };
const level_c: progressive.ComponentQuant = .{ .ll3 = 0, .hl3 = 1, .lh3 = 1, .hh3 = 1, .hl2 = 1, .lh2 = 1, .hh2 = 2, .hl1 = 2, .lh1 = 2, .hh1 = 2 };
/// gfx_codecs.prog_levels.
const levels = [_]progressive.ProgQuant{
    .{ .quality = 50, .y = level_b, .cb = level_b, .cr = level_b },
    .{ .quality = 75, .y = level_c, .cb = level_c, .cr = level_c },
};

/// video: moving noise; scroll: a fine pattern shifted 6 px a frame; flat: gradients and
/// solid squares with a moving block (what planar and ZGFX compress well).
const Content = enum { video, scroll, flat };

fn draw(fb: *fbm.Framebuffer, content: Content, t: u32) void {
    switch (content) {
        .video => fbm.drawVideo(fb, fb.width, fb.height, t),
        .scroll => {
            fbm.drawTestPattern(fb);
            fbm.drawDetail(fb, 6 * t);
        },
        .flat => fbm.drawAnimatedPattern(fb, t),
    }
}

pub fn main(init: std.process.Init) !void {
    // As main.zig: libc's allocator outside Debug.
    const gpa = if (builtin.mode == .debug) init.gpa else std.heap.c_allocator;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var w: u16 = 1920;
    var h: u16 = 1080;
    var reps: usize = 10;
    var only: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const val = if (i + 1 < args.len) args[i + 1] else "";
        if (std.mem.eql(u8, args[i], "--size")) {
            const x = std.mem.indexOfScalar(u8, val, 'x') orelse return error.BadSize;
            w = try std.fmt.parseInt(u16, val[0..x], 10);
            h = try std.fmt.parseInt(u16, val[x + 1 ..], 10);
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--reps")) {
            reps = try std.fmt.parseInt(usize, val, 10);
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--threads")) {
            workers.setMaxTasks(try std.fmt.parseInt(usize, val, 10));
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--only")) {
            only = val;
            i += 1;
        } else return error.BadArgument;
    }
    std.debug.print("{d}x{d}, {d} reps, {t}, {s}, {d} task(s)\n", .{ w, h, reps, builtin.mode, builtin.cpu.model.name, workers.maxTasks() });

    var b: Bench = .{ .gpa = gpa, .arena = arena, .w = w, .h = h, .reps = reps, .fb = try fbm.Framebuffer.init(gpa, w, h) };
    defer b.fb.deinit(gpa);
    defer b.rows.deinit(gpa);
    const all = [_]struct { []const u8, *const fn (*Bench) anyerror!void }{
        .{ "lossless", benchLossless }, .{ "zgfx", benchZgfx }, .{ "rfx", benchRfx },         .{ "prog", benchProgressive },
        .{ "legacy", benchLegacy },     .{ "h264", benchH264 }, .{ "kernels", benchKernels }, .{ "zgfxtune", benchZgfxTune },
    };
    for (all) |s| {
        if (only == null and std.mem.eql(u8, s[0], "zgfxtune")) continue;
        if (only) |o| {
            var it = std.mem.tokenizeScalar(u8, o, ',');
            const want = while (it.next()) |n| {
                if (std.mem.eql(u8, n, s[0])) break true;
            } else false;
            if (!want) continue;
        }
        try s[1](&b);
    }
    b.report();
}

// --- the lossless path: every frame's tile diff, planar for what changed, ClearCodec ------

fn benchLossless(b: *Bench) !void {
    const gpa = b.gpa;
    const px = b.fb.pixels;
    const stride = b.fb.stride;
    try b.section("lossless: tile diff against the shadow, then planar (RDPGFX, all clients)");
    var enc = encoder_mod.Encoder.init(gpa);
    defer enc.deinit();
    try enc.reset(b.w, b.h);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var wr = bytes.Writer.init(&out, gpa);

    draw(&b.fb, .scroll, 0);
    var t0 = nowNs();
    _ = try enc.diff(px, stride);
    try b.add("diff: first frame (every tile new)", nowNs() - t0, 0, 1);
    var ns: u64 = 0;
    for (0..b.reps) |_| {
        t0 = nowNs();
        _ = try enc.diff(px, stride);
        ns += nowNs() - t0;
    }
    try b.add("diff: still screen (nothing changed)", ns, 0, b.reps);
    ns = 0;
    for (0..b.reps) |t| {
        draw(&b.fb, .scroll, @intCast(t + 1));
        t0 = nowNs();
        _ = try enc.diff(px, stride);
        ns += nowNs() - t0;
    }
    try b.add("diff: scroll (every tile changed)", ns, 0, b.reps);
    ns = 0;
    for (0..b.reps) |t| {
        b.fb.fillRect(500, 300, 40, 20, @truncate(t * 20), 0, 0);
        t0 = nowNs();
        _ = try enc.diff(px, stride);
        ns += nowNs() - t0;
    }
    try b.add("diff: one small change (40x20 px)", ns, 0, b.reps);

    inline for (.{ Content.flat, Content.scroll, Content.video }) |content| {
        ns = 0;
        var bytes_: usize = 0;
        for (0..b.reps) |t| {
            draw(&b.fb, content, @intCast(t + 20));
            _ = try enc.diff(px, stride);
            out.clearRetainingCapacity();
            t0 = nowNs();
            try enc.writePlanar(&wr, 0);
            ns += nowNs() - t0;
            bytes_ += out.items.len;
        }
        try b.add("planar: whole screen, " ++ @tagName(content), ns, bytes_, b.reps);
    }
    // ClearCodec on what it takes: one tile, few colours (the test pattern's flat corners)
    {
        var ce = try clear.Encoder.init(gpa, .{});
        defer ce.deinit();
        fbm.drawTestPattern(&b.fb);
        ns = 0;
        var bytes_: usize = 0;
        var n: usize = 0;
        for (0..b.reps) |_| for (0..4) |k| {
            const x: usize = if (k % 2 == 0) 8 else b.w - 72;
            const y: usize = if (k < 2) 8 else b.h - 72;
            b.fb.fillRect(x + 10, y + 10, 20, 20, @intCast(k * 60), 0x80, 0x20);
            out.clearRetainingCapacity();
            t0 = nowNs();
            try ce.encode(&out, px[y * stride + x * 4 ..], stride, 64, 64);
            ns += nowNs() - t0;
            bytes_ += out.items.len;
            n += 1;
        };
        try b.add("ClearCodec: one 64x64 tile, 3 colours (per tile)", ns, bytes_, n);
    }
}

// --- ZGFX: every RDPGFX message goes through it ----------------------------------------------

fn benchZgfx(b: *Bench) !void {
    const gpa = b.gpa;
    const px = b.fb.pixels;
    const stride = b.fb.stride;
    try b.section("zgfx: bulk compression of every RDPGFX message (2.5 MB history)");
    var enc = encoder_mod.Encoder.init(gpa);
    defer enc.deinit();
    try enc.reset(b.w, b.h);
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    var wr = bytes.Writer.init(&msg, gpa);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var zw = bytes.Writer.init(&out, gpa);
    inline for (.{ Content.flat, Content.scroll, Content.video }) |content| {
        var z = try zgfx.Compressor.init(gpa);
        defer z.deinit();
        var ns: u64 = 0;
        var in_bytes: usize = 0;
        var out_bytes: usize = 0;
        for (0..b.reps) |t| {
            draw(&b.fb, content, @intCast(t));
            _ = try enc.diff(px, stride);
            msg.clearRetainingCapacity();
            try enc.writePlanar(&wr, 0);
            out.clearRetainingCapacity();
            const t0 = nowNs();
            try z.writeSegmented(&zw, msg.items);
            ns += nowNs() - t0;
            in_bytes += msg.items.len;
            out_bytes += out.items.len;
        }
        try b.addf("zgfx: planar frame, {s} ({d} KB in)", .{ @tagName(content), in_bytes / b.reps / 1024 }, ns, out_bytes, b.reps);
    }
    // H.264 or RemoteFX output is already compressed: ZGFX should give up fast
    {
        var z = try zgfx.Compressor.init(gpa);
        defer z.deinit();
        const noise = try gpa.alloc(u8, 400 * 1024);
        defer gpa.free(noise);
        var prng = std.Random.DefaultPrng.init(1);
        prng.random().bytes(noise);
        var ns: u64 = 0;
        var out_bytes: usize = 0;
        for (0..b.reps) |_| {
            out.clearRetainingCapacity();
            const t0 = nowNs();
            try z.writeSegmented(&zw, noise);
            ns += nowNs() - t0;
            out_bytes += out.items.len;
        }
        try b.add("zgfx: 400 KB of incompressible data (H.264-like)", ns, out_bytes, b.reps);
    }
}

/// Matcher settings against a planar scroll frame (weakly compressible) and a flat one.
fn benchZgfxTune(b: *Bench) !void {
    const gpa = b.gpa;
    const px = b.fb.pixels;
    const stride = b.fb.stride;
    try b.section("zgfx tuning: matcher options on planar frames (not run by default)");
    var enc = encoder_mod.Encoder.init(gpa);
    defer enc.deinit();
    try enc.reset(b.w, b.h);
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    var wr = bytes.Writer.init(&msg, gpa);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var zw = bytes.Writer.init(&out, gpa);
    const variants = [_]struct { []const u8, zgfx.Options }{
        .{ "default (chain 4, nice 96, skip 7)", .{} },
        .{ "chain 1", .{ .max_chain = 1 } },
        .{ "chain 2, nice 32", .{ .max_chain = 2, .nice_len = 32 } },
        .{ "skip 4", .{ .skip_shift = 4 } },
        .{ "skip 2", .{ .skip_shift = 2 } },
        .{ "chain 1, skip 3, insert edges only", .{ .max_chain = 1, .skip_shift = 3, .insert_all_len = 4, .insert_edge = 2 } },
        .{ "chain 8, nice 258", .{ .max_chain = 8, .nice_len = 258 } },
    };
    inline for (.{ Content.scroll, Content.flat }) |content| {
        for (variants) |v| {
            var z = try zgfx.Compressor.initOptions(gpa, v[1]);
            defer z.deinit();
            var ns: u64 = 0;
            var in_bytes: usize = 0;
            var out_bytes: usize = 0;
            for (0..b.reps) |t| {
                draw(&b.fb, content, @intCast(t));
                _ = try enc.diff(px, stride);
                msg.clearRetainingCapacity();
                try enc.writePlanar(&wr, 0);
                out.clearRetainingCapacity();
                const t0 = nowNs();
                try z.writeSegmented(&zw, msg.items);
                ns += nowNs() - t0;
                in_bytes += msg.items.len;
                out_bytes += out.items.len;
            }
            try b.addf("{s}: {s} ({d} KB in)", .{ @tagName(content), v[0], in_bytes / b.reps / 1024 }, ns, out_bytes, b.reps);
        }
    }
}

// --- RemoteFX --------------------------------------------------------------------------------

fn benchRfx(b: *Bench) !void {
    const gpa = b.gpa;
    const px = b.fb.pixels;
    const stride = b.fb.stride;
    try b.section("RemoteFX (RDP 8.0 thin clients, legacy surface bits)");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    inline for (.{ Content.video, Content.scroll }) |content| {
        {
            var enc = try rfx.Encoder.init(gpa, .{ .width = b.w, .height = b.h });
            defer enc.deinit();
            var ns: u64 = 0;
            var bytes_: usize = 0;
            for (0..b.reps) |t| {
                draw(&b.fb, content, @intCast(t));
                out.clearRetainingCapacity();
                const t0 = nowNs();
                try enc.encodeFrame(&out, px, stride, &.{});
                ns += nowNs() - t0;
                bytes_ += out.items.len;
            }
            try b.add("RemoteFX frame, whole screen, " ++ @tagName(content), ns, bytes_, b.reps);
        }
        {
            var enc = try rfx.Encoder.init(gpa, .{ .width = b.w, .height = b.h });
            defer enc.deinit();
            var ns: u64 = 0;
            var bytes_: usize = 0;
            for (0..b.reps) |t| {
                draw(&b.fb, content, @intCast(t));
                const t0 = nowNs();
                const msgs = try enc.encodeFrameSplit(px, stride, &.{}, 64 * 1024);
                ns += nowNs() - t0;
                for (msgs) |m| {
                    bytes_ += m.len;
                    gpa.free(m);
                }
                gpa.free(msgs);
            }
            try b.add("RemoteFX split 64 KB, whole screen, " ++ @tagName(content), ns, bytes_, b.reps);
        }
    }
}

// --- Progressive -----------------------------------------------------------------------------

fn benchProgressive(b: *Bench) !void {
    const gpa = b.gpa;
    const px = b.fb.pixels;
    const stride = b.fb.stride;
    try b.section("RemoteFX Progressive (motion on slow links, no VA-API)");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    inline for (.{ Content.video, Content.scroll }) |content| {
        var enc = try progressive.Encoder.init(gpa, b.w, b.h, .{ .levels = &levels });
        defer enc.deinit();
        draw(&b.fb, content, 0);
        out.clearRetainingCapacity();
        var t0 = nowNs();
        try enc.encodeFrame(&out, px, stride, &.{});
        try b.add("Progressive first frame, " ++ @tagName(content), nowNs() - t0, out.items.len, 1);
        var ns: u64 = 0;
        var bytes_: usize = 0;
        for (0..b.reps) |t| {
            draw(&b.fb, content, @intCast(t + 1));
            out.clearRetainingCapacity();
            t0 = nowNs();
            try enc.encodeFrame(&out, px, stride, &.{});
            ns += nowNs() - t0;
            bytes_ += out.items.len;
        }
        try b.add("Progressive moving frame, " ++ @tagName(content), ns, bytes_, b.reps);
        var pass: usize = 1;
        while (true) : (pass += 1) {
            out.clearRetainingCapacity();
            t0 = nowNs();
            const more = try enc.encodeUpgrade(&out);
            const dt = nowNs() - t0;
            if (!more) break;
            try b.addf("Progressive upgrade pass {d}, {s}", .{ pass, @tagName(content) }, dt, out.items.len, 1);
        }
        const vw: u16 = @min(640, b.w);
        const vh: u16 = @min(360, b.h);
        const region = [_]progressive.Rect{.{ .x = (b.w - vw) / 2, .y = (b.h - vh) / 2, .width = vw, .height = vh }};
        ns = 0;
        bytes_ = 0;
        for (0..b.reps) |t| {
            draw(&b.fb, content, @intCast(t + 100));
            out.clearRetainingCapacity();
            t0 = nowNs();
            try enc.encodeFrame(&out, px, stride, &region);
            ns += nowNs() - t0;
            bytes_ += out.items.len;
        }
        try b.add("Progressive 640x360 region, " ++ @tagName(content), ns, bytes_, b.reps);
    }
}

// --- legacy clients: NSCodec, interleaved RLE, bulk compression ----------------------------------

fn benchLegacy(b: *Bench) !void {
    const gpa = b.gpa;
    const px = b.fb.pixels;
    const stride = b.fb.stride;
    try b.section("legacy (no RDPGFX): NSCodec surface bits, RLE bitmaps, bulk compression");
    inline for (.{ Content.scroll, Content.video }) |content| {
        var ns: u64 = 0;
        var bytes_: usize = 0;
        for (0..b.reps) |t| {
            draw(&b.fb, content, @intCast(t));
            const t0 = nowNs();
            const data = try nsc.encode(gpa, px, stride, b.w, b.h, .{});
            ns += nowNs() - t0;
            bytes_ += data.len;
            gpa.free(data);
        }
        try b.add("NSCodec: whole screen, " ++ @tagName(content), ns, bytes_, b.reps);
    }
    inline for (.{ interleaved.Bpp.bpp16, interleaved.Bpp.bpp24 }) |bpp| {
        draw(&b.fb, .scroll, 3);
        var ns: u64 = 0;
        var bytes_: usize = 0;
        for (0..b.reps) |_| {
            var y: usize = 0;
            while (y < b.h) : (y += 64) {
                const rows: u16 = @intCast(@min(64, b.h - y));
                var x: usize = 0;
                while (x < b.w) : (x += 64) {
                    const cols: u16 = @intCast(@min(64, b.w - x));
                    const t0 = nowNs();
                    const data = try interleaved.encode(gpa, px[y * stride + x * 4 ..], stride, cols, rows, bpp, null);
                    ns += nowNs() - t0;
                    bytes_ += data.len;
                    gpa.free(data);
                }
            }
        }
        try b.add("interleaved RLE " ++ @tagName(bpp) ++ ": whole screen in 64x64 bitmaps, scroll", ns, bytes_, b.reps);
    }
    // Bulk compression of planar output in chunks of the type's maximum input
    {
        var enc = encoder_mod.Encoder.init(gpa);
        defer enc.deinit();
        try enc.reset(b.w, b.h);
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        var wr = bytes.Writer.init(&msg, gpa);
        draw(&b.fb, .scroll, 1);
        _ = try enc.diff(px, stride);
        try enc.writePlanar(&wr, 0);
        inline for (.{ bulk.Type.mppc_64k, bulk.Type.ncrush, bulk.Type.xcrush }) |t| {
            var comp = try bulk.Compressor.init(gpa, t);
            defer comp.deinit();
            const chunk = try bulk.maxInput(t);
            var ns: u64 = 0;
            var out_bytes: usize = 0;
            for (0..b.reps) |_| {
                var off: usize = 0;
                while (off < msg.items.len) : (off += chunk) {
                    const part = msg.items[off..@min(off + chunk, msg.items.len)];
                    const t0 = nowNs();
                    const r = try comp.compress(part);
                    ns += nowNs() - t0;
                    out_bytes += r.data.len;
                }
            }
            try b.addf("bulk {s}: a planar frame in {d} KB chunks ({d} KB in)", .{ @tagName(t), chunk / 1024, msg.items.len / 1024 }, ns, out_bytes, b.reps);
        }
    }
}

// --- H.264 through VA-API --------------------------------------------------------------------

fn benchH264(b: *Bench) !void {
    const gpa = b.gpa;
    const px = b.fb.pixels;
    const stride = b.fb.stride;
    try b.section("H.264 (VA-API): upload + colour conversion + encode, whole frames");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var aux: std.ArrayList(u8) = .empty;
    defer aux.deinit(gpa);
    {
        var enc = vaapi_h264.Encoder.init(gpa, .{ .width = b.w, .height = b.h, .rate_control = .cqp, .qp = 26 }) catch |err| {
            try b.addf("AVC420: no encoder ({t})", .{err}, 0, 0, 1);
            return;
        };
        defer enc.deinit();
        try b.addf("AVC420 on {s} ({s})", .{ enc.node, enc.vendor }, 0, 0, 1);
        inline for (.{ Content.video, Content.scroll }) |content| {
            var up: u64 = 0;
            var en: u64 = 0;
            var bytes_: usize = 0;
            draw(&b.fb, content, 0);
            out.clearRetainingCapacity();
            _ = try enc.encode(px, stride, true, &out);
            for (0..b.reps) |t| {
                draw(&b.fb, content, @intCast(t + 1));
                out.clearRetainingCapacity();
                const fi = try enc.encode(px, stride, false, &out);
                up += fi.upload_ns;
                en += fi.encode_ns;
                bytes_ += out.items.len;
            }
            try b.add("AVC420 P-frame: upload (CPU copy into VA image), " ++ @tagName(content), up, 0, b.reps);
            try b.add("AVC420 P-frame: VPP + encode + copy out, " ++ @tagName(content), en, bytes_, b.reps);
        }
    }
    {
        var enc = vaapi_h264.Encoder.init(gpa, .{ .width = b.w, .height = b.h, .rate_control = .cqp, .qp = 26, .avc444 = .v2 }) catch |err| {
            try b.addf("AVC444: no encoder ({t})", .{err}, 0, 0, 1);
            return;
        };
        defer enc.deinit();
        var up: u64 = 0;
        var en: u64 = 0;
        var bytes_: usize = 0;
        draw(&b.fb, .video, 0);
        out.clearRetainingCapacity();
        aux.clearRetainingCapacity();
        _ = try enc.encode444(px, stride, true, .both, &out, &aux);
        for (0..b.reps) |t| {
            draw(&b.fb, .video, @intCast(t + 1));
            out.clearRetainingCapacity();
            aux.clearRetainingCapacity();
            const fi = try enc.encode444(px, stride, false, .both, &out, &aux);
            if (fi.main) |m| {
                up += m.upload_ns;
                en += m.encode_ns;
            }
            if (fi.aux) |a| en += a.encode_ns;
            bytes_ += out.items.len + aux.items.len;
        }
        try b.add("AVC444v2 P-frame: both views on the CPU (threaded)", up, 0, b.reps);
        try b.add("AVC444v2 P-frame: encode both views", en, bytes_, b.reps);
    }
}

// --- raw kernels -----------------------------------------------------------------------------

fn benchKernels(b: *Bench) !void {
    const px = b.fb.pixels;
    const stride = b.fb.stride;
    try b.section("kernels, one thread, every tile of a video frame");
    draw(&b.fb, .video, 3);
    const tx = (@as(usize, b.w) + 63) / 64;
    const tiles = tx * ((@as(usize, b.h) + 63) / 64);
    var comps: [3]rfx.Component = undefined;
    var rl: [rfx.rlgr.max_component_size]u8 = undefined;
    var ns_col: u64 = 0;
    var ns_dwt: u64 = 0;
    var ns_re: u64 = 0;
    var ns_q: u64 = 0;
    var ns_r1: u64 = 0;
    var ns_r3: u64 = 0;
    for (0..b.reps) |_| for (0..tiles) |t| {
        const x = (t % tx) * 64;
        const y = (t / tx) * 64;
        const vw: u16 = @intCast(@min(64, b.w - x));
        const vh: u16 = @intCast(@min(64, b.h - y));
        var t0 = nowNs();
        try rfx.rgbToYCbCr(px[y * stride + x * 4 ..], stride, vw, vh, &comps[0], &comps[1], &comps[2]);
        ns_col += nowNs() - t0;
        var re = comps;
        t0 = nowNs();
        for (&re) |*c| dwt.encodeExtrapolate(c);
        ns_re += nowNs() - t0;
        t0 = nowNs();
        for (&comps) |*c| dwt.encode(c);
        ns_dwt += nowNs() - t0;
        t0 = nowNs();
        for (&comps) |*c| try rfx.quantize(c, rfx.default_quant);
        ns_q += nowNs() - t0;
        t0 = nowNs();
        for (&comps) |*c| _ = try rfx.rlgrEncode(.rlgr3, c, &rl);
        ns_r3 += nowNs() - t0;
        t0 = nowNs();
        for (&comps) |*c| _ = try rfx.rlgrEncode(.rlgr1, c, &rl);
        ns_r1 += nowNs() - t0;
    };
    try b.add("  rgbToYCbCr", ns_col, 0, b.reps);
    try b.add("  dwt.encode x3", ns_dwt, 0, b.reps);
    try b.add("  dwt.encodeExtrapolate x3", ns_re, 0, b.reps);
    try b.add("  quantize x3", ns_q, 0, b.reps);
    try b.add("  RLGR3 x3", ns_r3, 0, b.reps);
    try b.add("  RLGR1 x3", ns_r1, 0, b.reps);
    // AVC444 colour conversion, one thread
    {
        const gpa = b.gpa;
        const vs = try avc444.viewSize(.v2, b.w, b.h);
        const vy = try gpa.alloc(u8, vs.width * vs.height);
        defer gpa.free(vy);
        const vuv = try gpa.alloc(u8, vs.width * vs.height / 2);
        defer gpa.free(vuv);
        const ay = try gpa.alloc(u8, vs.width * vs.height);
        defer gpa.free(ay);
        const auv = try gpa.alloc(u8, vs.width * vs.height / 2);
        defer gpa.free(auv);
        const scratch = try gpa.alloc(u8, avc444.nv12ScratchLen(b.w));
        defer gpa.free(scratch);
        const main_v: avc444.Nv12 = .{ .y = vy, .y_pitch = vs.width, .uv = vuv, .uv_pitch = vs.width };
        const aux_v: avc444.Nv12 = .{ .y = ay, .y_pitch = vs.width, .uv = auv, .uv_pitch = vs.width };
        var ns: u64 = 0;
        for (0..b.reps) |_| {
            const t0 = nowNs();
            try avc444.toNv12(.v2, px, stride, b.w, b.h, main_v, aux_v, scratch);
            ns += nowNs() - t0;
        }
        try b.add("  avc444.toNv12 main + aux views (SIMD)", ns, 0, b.reps);
    }
}
