//! `zig build capbench -- --output NAME [--mode shm|dmabuf] [--frames N]`: what capturing an
//! output costs, the compositor's side included. Captures continuously (the next frame is
//! requested as soon as one is taken) and reports per frame: request-to-ready and
//! presentation-to-ready latency, for dmabuf ready-to-idle (the compositor's rendering into the
//! buffer finishing), the compositor's CPU time (all its threads, from schedstat; found through
//! the Wayland socket's peer credentials), this process's CPU time and the GPU's busy percent.
//! Point it at a nested compositor (WAYLAND_DISPLAY) with moving content on the output.
//!
//! `--diff cpu|gpu|verify` also runs the server's change detection on every frame and times it:
//! cpu = Encoder.diff on shm frames, gpu = GPU capture's (src/gpu/capture.zig) on dmabuf
//! frames, verify = gpu plus Encoder.diff on a mapped copy of the same buffer, comparing rects,
//! tight boxes and shadow frame by frame (a soak test of their equivalence on real content).
//!
//! `--encode avc420|avc444` then codes every changed frame with H.264 as gfx_codecs does for
//! motion (CQP 26, the frame's rects; AVC444 v2 both views): from the GPU (the input surfaces
//! written there, changed tiles left there) with `--diff gpu`, from the shadow (h264Source, then
//! upload and VPP, or the views built on the CPU) with `--diff cpu` or `--encode avc420-shadow` /
//! `avc444-shadow`; and times it, and diff plus encode.

const std = @import("std");
const c = @import("c");
const omastation = @import("omastation");
const wl = omastation.wl;
const gbm = omastation.gpu.gbm;
const gpucap = omastation.gpu.capture;
const Encoder = omastation.server.encoder.Encoder;
const h264 = omastation.codec.h264;

const Mode = wl.capture.BufferKind;
const Diff = enum { none, cpu, gpu, verify };
const Encode = enum {
    none,
    avc420,
    @"avc420-shadow",
    avc444,
    @"avc444-shadow",

    fn is444(e: Encode) bool {
        return e == .avc444 or e == .@"avc444-shadow";
    }
};

const Opts = struct {
    display: ?[]const u8 = null,
    output: ?[]const u8 = null,
    mode: Mode = .shm,
    frames: usize = 300,
    warmup: usize = 30,
    linear: bool = true,
    ring: u8 = 3,
    check_every: usize = 30,
    gpu_busy: ?[]const u8 = null,
    label: []const u8 = "",
    diff: Diff = .none,
    threads: ?usize = null,
    /// GPU diff: leave every changed tile on the GPU (lazy readback, as for H.264 motion frames).
    lazy: bool = false,
    encode: Encode = .none,
    h264_encoder: h264.Backend = .auto,
};

/// gfx_codecs.writeAvc420's / writeAvc444's coding of a motion frame: the input written on the GPU
/// when it can be, else h264Source's picture (the shadow's rects copied in, out to 16 pixels).
const AvcBench = struct {
    gpa: std.mem.Allocator,
    avc444: bool,
    h: ?h264.Encoder = null,
    aux_out: std.ArrayList(u8) = .empty,
    src: []u8 = &.{},
    src_ok: bool = false,
    gpu_ok: bool = false,
    out: std.ArrayList(u8) = .empty,
    frames: u64 = 0,
    gpu_frames: u64 = 0,
    bytes: u64 = 0,
    wall_ns: u64 = 0,
    cpu_ns: u64 = 0,

    fn deinit(b: *AvcBench) void {
        if (b.h) |*h| h.deinit();
        b.gpa.free(b.src);
        b.out.deinit(b.gpa);
        b.aux_out.deinit(b.gpa);
    }

    fn frame(b: *AvcBench, enc: *Encoder, gout: ?*gpucap.Output, backend: h264.Backend) !void {
        var idr = false;
        if (b.h) |*h| if (h.opts.width != enc.width or h.opts.height != enc.height) {
            h.deinit();
            b.h = null;
        };
        if (b.h == null) {
            b.h = try h264.Encoder.init(b.gpa, .{ .width = enc.width, .height = enc.height, .bitrate = 20_000_000, .fps = 60, .crop = !b.avc444 and enc.width % 2 == 0 and enc.height % 2 == 0, .rate_control = .cqp, .qp = 22, .avc444 = if (b.avc444) .v2 else null }, backend);
            std.debug.print("H.264 on {s}\n", .{b.h.?.node});
            b.src_ok = false;
            b.gpu_ok = false;
            idr = true;
        }
        const h = &b.h.?;
        h.setQp(26);
        b.out.clearRetainingCapacity();
        b.aux_out.clearRetainingCapacity();
        const rects = enc.rects.items;
        b.frames += 1;
        if (gout) |g| if (h.vaapi()) |va| {
            if (g.writeH264Input(va, enc, if (b.gpu_ok) rects else null)) {
                if (b.avc444) {
                    _ = try va.encode444Written(idr, .both, &b.out, &b.aux_out);
                } else _ = try va.encodeWritten(idr, &b.out);
                b.bytes += b.out.items.len + b.aux_out.items.len;
                b.gpu_ok = true;
                b.src_ok = false;
                b.gpu_frames += 1;
                return;
            }
        };
        b.gpu_ok = false;
        if (b.src_ok) try enc.freshen(rects) else try enc.freshenAll();
        if (b.src.len != enc.shadow.len) {
            b.gpa.free(b.src);
            b.src = &.{};
            b.src = try b.gpa.alloc(u8, enc.shadow.len);
            b.src_ok = false;
        }
        const stride = enc.shadowStride();
        if (!b.src_ok) {
            @memcpy(b.src, enc.shadow);
        } else for (rects) |r| {
            const x0: usize = r.left & ~@as(u16, 15);
            const x1: usize = @min(enc.width, (@as(u32, r.right) + 15) & ~@as(u32, 15));
            const y1: usize = @min(enc.height, (@as(u32, r.bottom) + 15) & ~@as(u32, 15));
            var y: usize = r.top & ~@as(u16, 15);
            while (y < y1) : (y += 1) @memcpy(b.src[y * stride + x0 * 4 ..][0 .. (x1 - x0) * 4], enc.shadow[y * stride + x0 * 4 ..][0 .. (x1 - x0) * 4]);
        }
        b.src_ok = true;
        if (b.avc444) {
            _ = try h.encode444(b.src, stride, idr, .both, &b.out, &b.aux_out);
        } else _ = try h.encode(b.src, stride, idr, &b.out);
        b.bytes += b.out.items.len + b.aux_out.items.len;
    }
};

const Sample = struct { latency: u64, present_to_ready: ?u64, ready_to_idle: ?u64, gpu_busy: ?u32 };

fn nowNs() u64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(u64, @intCast(ts.tv_sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.tv_nsec));
}

fn selfCpuNs() u64 {
    var ru: std.c.rusage = undefined;
    _ = std.c.getrusage(0, &ru); // RUSAGE_SELF: every thread of the process
    const u: u64 = @as(u64, @intCast(ru.utime.sec)) * std.time.ns_per_s + @as(u64, @intCast(ru.utime.usec)) * 1000;
    const s: u64 = @as(u64, @intCast(ru.stime.sec)) * std.time.ns_per_s + @as(u64, @intCast(ru.stime.usec)) * 1000;
    return u + s;
}

fn readSmall(path: [:0]const u8, buf: []u8) ?[]const u8 {
    const fd = c.open(path.ptr, c.O_RDONLY | c.O_CLOEXEC);
    if (fd < 0) return null;
    defer _ = c.close(fd);
    const n = c.read(fd, buf.ptr, buf.len);
    if (n <= 0) return null;
    return buf[0..@intCast(n)];
}

/// CPU time of every thread of `pid`, ns (schedstat's first field).
fn procCpuNs(pid: c.pid_t) ?u64 {
    var path_buf: [64]u8 = undefined;
    const dir_path = std.fmt.bufPrintSentinel(&path_buf, "/proc/{d}/task", .{pid}, 0) catch return null;
    const dir = c.opendir(dir_path.ptr) orelse return null;
    defer _ = c.closedir(dir);
    var total: u64 = 0;
    while (c.readdir(dir)) |ent| {
        const name = std.mem.sliceTo(&ent.*.d_name, 0);
        if (name.len == 0 or name[0] == '.') continue;
        var p: [96]u8 = undefined;
        const sp = std.fmt.bufPrintSentinel(&p, "/proc/{d}/task/{s}/schedstat", .{ pid, name }, 0) catch continue;
        var b: [128]u8 = undefined;
        const text = readSmall(sp, &b) orelse continue;
        var it = std.mem.tokenizeAny(u8, text, " \n");
        total += std.fmt.parseInt(u64, it.next() orelse continue, 10) catch continue;
    }
    return total;
}

fn peerPid(fd: c_int) ?c.pid_t {
    var cred: c.struct_ucred = undefined;
    var len: c.socklen_t = @sizeOf(c.struct_ucred);
    if (c.getsockopt(fd, c.SOL_SOCKET, c.SO_PEERCRED, &cred, &len) != 0) return null;
    return cred.pid;
}

fn gpuBusy(path: ?[:0]const u8) ?u32 {
    const p = path orelse return null;
    var b: [16]u8 = undefined;
    const text = readSmall(p, &b) orelse return null;
    return std.fmt.parseInt(u32, std.mem.trim(u8, text, " \n"), 10) catch null;
}

/// The dmabuf frame's raw bytes (an mmap of the buffer: gbm_bo_map's blit need not keep XRGB's
/// X byte), rows `width * 4` apart.
fn rawCopy(gpa: std.mem.Allocator, copy: *[]u8, f: *const wl.Frame) ![]u8 {
    const bo = f.dmabuf orelse return error.NotDmabuf;
    const row = @as(usize, f.width) * 4;
    if (copy.len != row * f.height) {
        gpa.free(copy.*);
        copy.* = try gpa.alloc(u8, row * f.height);
    }
    if (!gbm.waitIdle(bo, 1000)) return error.Timeout;
    if (!gbm.readRaw(bo, copy.*, row)) return error.MapFailed;
    return copy.*;
}

fn pct(sorted: []const u64, p: usize) u64 {
    if (sorted.len == 0) return 0;
    return sorted[@min(sorted.len - 1, sorted.len * p / 100)];
}

fn ms(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1e6;
}

/// Hash of 64 sampled rows (outside timing): is the dmabuf filled, and does it change?
fn sampleHash(bo: *const wl.dmabuf.Bo) ?u64 {
    if (!gbm.waitIdle(bo, 1000)) return null;
    const m = gbm.mapRead(bo) orelse return null;
    defer gbm.unmap(bo, m.token);
    var h = std.hash.Wyhash.init(0);
    var nonzero = false;
    const rows: usize = 64;
    for (0..rows) |k| {
        const y = k * bo.height / rows;
        const row = m.data[y * m.stride ..][0 .. bo.width * 4];
        h.update(row);
        if (!nonzero) for (row) |v| if (v != 0) {
            nonzero = true;
            break;
        };
    }
    return if (nonzero) h.final() else 0;
}

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.c_allocator;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var o: Opts = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const v = if (i + 1 < args.len) args[i + 1] else "";
        if (std.mem.eql(u8, a, "--display")) {
            o.display = v;
        } else if (std.mem.eql(u8, a, "--output")) {
            o.output = v;
        } else if (std.mem.eql(u8, a, "--mode")) {
            o.mode = std.meta.stringToEnum(Mode, v) orelse return error.BadMode;
        } else if (std.mem.eql(u8, a, "--frames")) {
            o.frames = try std.fmt.parseInt(usize, v, 10);
        } else if (std.mem.eql(u8, a, "--warmup")) {
            o.warmup = try std.fmt.parseInt(usize, v, 10);
        } else if (std.mem.eql(u8, a, "--modifier")) {
            o.linear = if (std.mem.eql(u8, v, "linear")) true else if (std.mem.eql(u8, v, "any")) false else return error.BadModifier;
        } else if (std.mem.eql(u8, a, "--ring")) {
            o.ring = try std.fmt.parseInt(u8, v, 10);
        } else if (std.mem.eql(u8, a, "--check-every")) {
            o.check_every = try std.fmt.parseInt(usize, v, 10);
        } else if (std.mem.eql(u8, a, "--gpu-busy")) {
            o.gpu_busy = v;
        } else if (std.mem.eql(u8, a, "--label")) {
            o.label = v;
        } else if (std.mem.eql(u8, a, "--diff")) {
            o.diff = std.meta.stringToEnum(Diff, v) orelse return error.BadDiff;
        } else if (std.mem.eql(u8, a, "--lazy")) {
            o.lazy = if (std.mem.eql(u8, v, "all")) true else if (std.mem.eql(u8, v, "none")) false else return error.BadLazy;
        } else if (std.mem.eql(u8, a, "--encode")) {
            o.encode = std.meta.stringToEnum(Encode, v) orelse return error.BadEncode;
        } else if (std.mem.eql(u8, a, "--h264-encoder")) {
            o.h264_encoder = std.meta.stringToEnum(h264.Backend, v) orelse return error.BadEncoder;
        } else if (std.mem.eql(u8, a, "--threads")) {
            o.threads = try std.fmt.parseInt(usize, v, 10);
        } else return error.BadArgument;
        i += 1;
    }

    const client = try wl.Client.connect(gpa, .{ .display = o.display });
    defer client.deinit();
    const out = if (o.output) |n| client.findOutput(n) orelse {
        std.debug.print("no output {s}; outputs:", .{n});
        for (client.outputs()) |x| if (!x.removed) std.debug.print(" {s}", .{x.name()});
        std.debug.print("\n", .{});
        return error.NoOutput;
    } else client.outputs()[0];
    const comp_pid = peerPid(client.fd());

    if (o.threads) |t| omastation.codec.workers.setMaxTasks(t);
    if (o.diff == .cpu and o.mode != .shm) return error.CpuDiffNeedsShm;
    if ((o.diff == .gpu or o.diff == .verify) and o.mode != .dmabuf) return error.GpuDiffNeedsDmabuf;
    const shared = try gpucap.Shared.create(gpa);
    defer shared.destroy();
    var gout = gpucap.Output.init(shared);
    defer gout.deinit();
    const cap = try wl.Capture.init(client, out, .{
        .backend = .ext,
        .buffers = o.mode,
        .dmabuf_allocator = &shared.alloc,
        .dmabuf_count = o.ring,
        .prefer_linear = o.linear,
    });
    defer cap.deinit();
    var enc = Encoder.init(gpa);
    defer enc.deinit();
    if (o.encode != .none and o.diff == .none) return error.EncodeNeedsDiff;
    // Coding from the GPU leaves the changed tiles there, as the server does for motion.
    const gpu_input = (o.encode == .avc420 or o.encode == .avc444) and (o.diff == .gpu or o.diff == .verify);
    const hint: gpucap.Hint = if (o.lazy or gpu_input) .all else .none;
    var avc: AvcBench = .{ .gpa = gpa, .avc444 = o.encode.is444() };
    defer avc.deinit();
    var ref = Encoder.init(gpa);
    defer ref.deinit();
    var copy: []u8 = &.{};
    defer gpa.free(copy);
    var diff_wall: u64 = 0;
    var diff_cpu: u64 = 0;
    var diff_frames: u64 = 0;
    var diff_skipped: u64 = 0;
    var changed_px: u64 = 0;
    var mismatches: u64 = 0;
    var trace_inside: u64 = 0;

    var busy_buf: [128]u8 = undefined;
    const busy_path: ?[:0]const u8 = if (o.gpu_busy) |p|
        try std.fmt.bufPrintSentinel(&busy_buf, "{s}", .{p}, 0)
    else
        std.fmt.bufPrintSentinel(&busy_buf, "/sys/class/drm/renderD128/device/gpu_busy_percent", .{}, 0) catch null;

    var samples: std.ArrayList(Sample) = .empty;
    defer samples.deinit(gpa);
    try samples.ensureTotalCapacity(gpa, o.frames);
    var checks: usize = 0;
    var check_zero: usize = 0;
    var check_same: usize = 0;
    var check_fail: usize = 0;
    var last_hash: ?u64 = null;

    var comp0: u64 = 0;
    var self0: u64 = 0;
    var t0: u64 = 0;
    var check_ns: u64 = 0;
    var width: u32 = 0;
    var height: u32 = 0;
    var modifier: ?u64 = null;
    const total = o.warmup + o.frames;
    for (0..total) |k| {
        if (k == o.warmup) {
            avc.frames = 0;
            avc.gpu_frames = 0;
            avc.bytes = 0;
            gout.h264_writes = 0;
            gout.h264_ns = 0;
            for (gout.converters) |x| if (x) |cv| {
                cv.gpu_ns = 0;
                cv.runs = 0;
            };
            gout.pre_ns = 0;
            gout.run_ns = 0;
            gout.post_ns = 0;
            gout.frames = 0;
            gout.full_frames = 0;
            if (gout.td) |td| {
                td.gpu_total_ns = 0;
                td.gpu_pass_ns = 0;
                td.cpu_fence_ns = 0;
                td.cpu_prep_ns = 0;
                td.timed_runs = 0;
                td.gpu_waits = 0;
                td.cpu_waits = 0;
                td.freshened = 0;
            }
            comp0 = if (comp_pid) |p| procCpuNs(p) orelse 0 else 0;
            self0 = selfCpuNs();
            t0 = nowNs();
            check_ns = 0;
        }
        const f = try cap.nextFrame(5000);
        width = f.width;
        height = f.height;
        if (k < o.warmup) {
            // Warm-up frames go through the change detection too, untimed: the first one opens
            // the Vulkan device and builds the pipeline (GPU) or diffs a whole frame (CPU).
            if (o.diff != .none) {
                if (enc.width != f.width or enc.height != f.height) {
                    try enc.reset(f.width, f.height);
                    try ref.reset(f.width, f.height);
                }
                const changed = switch (o.diff) {
                    .cpu => try enc.diff(f.data, f.stride),
                    else => try gout.diff(cap, &enc, f, hint),
                };
                if (o.encode != .none and changed != null) try avc.frame(&enc, if (gpu_input) &gout else null, o.h264_encoder);
                // verify: the CPU reference sees every frame too, or its first timed one would be whole.
                if (o.diff == .verify) _ = try ref.diff(try rawCopy(gpa, &copy, f), @as(usize, f.width) * 4);
            }
            continue;
        }
        var s: Sample = .{
            .latency = f.latency_ns,
            .present_to_ready = if (f.presented_ns != 0 and f.presented_ns <= f.ready_ns) f.ready_ns - f.presented_ns else null,
            .ready_to_idle = null,
            .gpu_busy = gpuBusy(busy_path),
        };
        if (f.dmabuf) |bo| {
            modifier = bo.modifier;
            if (gbm.waitIdle(bo, 1000)) s.ready_to_idle = nowNs() -| f.ready_ns;
            if (o.check_every > 0 and (k - o.warmup) % o.check_every == 0) {
                // The check maps the buffer: its CPU time is taken out of this process's total.
                const c0 = selfCpuNs();
                checks += 1;
                if (sampleHash(bo)) |h| {
                    if (h == 0) check_zero += 1;
                    if (last_hash != null and last_hash.? == h) check_same += 1;
                    last_hash = h;
                } else check_fail += 1;
                check_ns += selfCpuNs() - c0;
            }
        }
        samples.appendAssumeCapacity(s);
        if (o.diff != .none) {
            if (enc.width != f.width or enc.height != f.height) {
                try enc.reset(f.width, f.height);
                try ref.reset(f.width, f.height);
            }
            const c0 = selfCpuNs();
            const w0 = nowNs();
            const n: ?usize = switch (o.diff) {
                .cpu => try enc.diff(f.data, f.stride),
                else => try gout.diff(cap, &enc, f, hint),
            };
            const w1 = nowNs();
            diff_wall += w1 - w0;
            diff_cpu += selfCpuNs() - c0;
            if (std.c.getenv("CAPBENCH_TRACE") != null and k % 50 == 0) std.debug.print("trace frame {d}: wall {d:.3} ms, inside {d:.3} ms\n", .{ k, ms(w1 - w0), ms(gout.pre_ns + gout.run_ns + gout.post_ns -| trace_inside) });
            trace_inside = gout.pre_ns + gout.run_ns + gout.post_ns;
            if (n == null) {
                diff_skipped += 1;
            } else {
                diff_frames += 1;
                changed_px += enc.changedPixels();
            }
            if (o.encode != .none and n != null) {
                const c1 = selfCpuNs();
                const e0 = nowNs();
                try avc.frame(&enc, if (gpu_input) &gout else null, o.h264_encoder);
                avc.wall_ns += nowNs() - e0;
                avc.cpu_ns += selfCpuNs() - c1;
            }
            if (o.diff == .verify and n != null) {
                // The same buffer through Encoder.diff (outside the timing).
                const c1 = selfCpuNs();
                _ = try ref.diff(try rawCopy(gpa, &copy, f), @as(usize, f.width) * 4);
                // Tiles left on the GPU come in before the shadows are compared.
                try enc.freshenAll();
                const same = std.mem.eql(u8, std.mem.sliceAsBytes(enc.rects.items), std.mem.sliceAsBytes(ref.rects.items)) and
                    std.mem.eql(u8, std.mem.sliceAsBytes(enc.tight.items), std.mem.sliceAsBytes(ref.tight.items)) and
                    std.mem.eql(u8, enc.shadow, ref.shadow);
                if (!same) {
                    mismatches += 1;
                    if (mismatches <= 3) {
                        const rects_same = std.mem.eql(u8, std.mem.sliceAsBytes(enc.rects.items), std.mem.sliceAsBytes(ref.rects.items));
                        const tight_same = std.mem.eql(u8, std.mem.sliceAsBytes(enc.tight.items), std.mem.sliceAsBytes(ref.tight.items));
                        var first: ?usize = null;
                        var xonly = true;
                        for (enc.shadow, ref.shadow, 0..) |a, b, at| if (a != b) {
                            if (first == null) first = at;
                            if (at % 4 != 3) xonly = false;
                        };
                        std.debug.print("MISMATCH frame {d}: rects {s}, tight {s}, shadow {s}", .{ k, if (rects_same) "same" else "DIFFER", if (tight_same) "same" else "DIFFER", if (first == null) "same" else if (xonly) "differs in the X byte only" else "DIFFERS" });
                        if (first) |at| std.debug.print(" (first at byte {d}: gpu {x:0>2} cpu-map {x:0>2})", .{ at, enc.shadow[at], ref.shadow[at] });
                        std.debug.print("\n", .{});
                    }
                }
                check_ns += selfCpuNs() - c1;
            }
        }
    }
    const wall = nowNs() - t0;
    const comp_ns = if (comp_pid) |p| (procCpuNs(p) orelse comp0) -| comp0 else 0;
    const self_ns = selfCpuNs() -| self0 -| check_ns;
    const n = samples.items.len;

    var lat = try arena.alloc(u64, n);
    var p2r: std.ArrayList(u64) = .empty;
    var r2i: std.ArrayList(u64) = .empty;
    var busy_sum: u64 = 0;
    var busy_n: u64 = 0;
    for (samples.items, 0..) |s, k| {
        lat[k] = s.latency;
        if (s.present_to_ready) |v| try p2r.append(arena, v);
        if (s.ready_to_idle) |v| try r2i.append(arena, v);
        if (s.gpu_busy) |b| {
            busy_sum += b;
            busy_n += 1;
        }
    }
    std.mem.sort(u64, lat, {}, std.sort.asc(u64));
    std.mem.sort(u64, p2r.items, {}, std.sort.asc(u64));
    std.mem.sort(u64, r2i.items, {}, std.sort.asc(u64));
    const nf: f64 = @floatFromInt(n);
    const using = if (cap.usingDmabuf()) "dmabuf" else "shm";
    std.debug.print("{s} {s} {d}x{d} buffers={s}", .{ o.label, out.name(), width, height, using });
    if (modifier) |m| std.debug.print(" modifier=0x{x}", .{m});
    std.debug.print(" frames={d} fps={d:.1}\n", .{ n, nf / (@as(f64, @floatFromInt(wall)) / 1e9) });
    std.debug.print("  request->ready ms   p50 {d:.2}  p95 {d:.2}  max {d:.2}\n", .{ ms(pct(lat, 50)), ms(pct(lat, 95)), ms(lat[n - 1]) });
    if (p2r.items.len > 0) std.debug.print("  present->ready ms   p50 {d:.2}  p95 {d:.2}  ({d} frames)\n", .{ ms(pct(p2r.items, 50)), ms(pct(p2r.items, 95)), p2r.items.len });
    if (r2i.items.len > 0) std.debug.print("  ready->idle ms      p50 {d:.2}  p95 {d:.2}\n", .{ ms(pct(r2i.items, 50)), ms(pct(r2i.items, 95)) });
    std.debug.print("  compositor CPU      {d:.3} ms/frame (pid {?d})\n", .{ ms(comp_ns) / nf, comp_pid });
    std.debug.print("  capture client CPU  {d:.3} ms/frame\n", .{ms(self_ns) / nf});
    if (busy_n > 0) std.debug.print("  GPU busy            {d:.1} % avg (whole GPU, other clients included)\n", .{@as(f64, @floatFromInt(busy_sum)) / @as(f64, @floatFromInt(busy_n))});
    if (checks > 0) std.debug.print("  filled checks       {d}: {d} all-zero, {d} unchanged, {d} unreadable\n", .{ checks, check_zero, check_same, check_fail });
    if (o.diff != .none) {
        const df: f64 = @floatFromInt(@max(diff_frames + diff_skipped, 1));
        std.debug.print("  diff ({t})          {d:.3} ms wall, {d:.3} ms CPU per frame; {d:.0} px changed per frame; {d} frames, {d} skipped, {d} full copies, {d} worker tasks\n", .{ o.diff, ms(diff_wall) / df, ms(diff_cpu) / df, @as(f64, @floatFromInt(changed_px)) / df, diff_frames, diff_skipped, gout.full_frames, omastation.codec.workers.maxTasks() });
        if (o.diff == .verify) std.debug.print("  verify              {d} of {d} frames differ from Encoder.diff\n", .{ mismatches, diff_frames });
        if (gout.frames > 0) {
            const gf: f64 = @floatFromInt(gout.frames);
            std.debug.print("  GPU diff phases     before the run {d:.3} ms, run {d:.3} ms, after {d:.3} ms\n", .{ ms(gout.pre_ns) / gf, ms(gout.run_ns) / gf, ms(gout.post_ns) / gf });
        }
        if (gout.td) |td| if (td.timed_runs > 0) {
            const tr: f64 = @floatFromInt(td.timed_runs);
            std.debug.print("  GPU path            pass {d:.3} ms, waits + pass {d:.3} ms (GPU clock), submit to fence {d:.3} ms, before the submit {d:.3} ms; {d} GPU waits, {d} CPU waits, changed tiles into the shadow: {s}\n", .{ td.gpu_pass_ns / tr / 1e6, td.gpu_total_ns / tr / 1e6, ms(td.cpu_fence_ns) / tr, ms(td.cpu_prep_ns) / tr, td.gpu_waits, td.cpu_waits, if (td.shadow != null) "yes" else "no" });
        };
        if (o.encode != .none) {
            const ef: f64 = @floatFromInt(@max(avc.frames, 1));
            std.debug.print("  encode ({t})     {d:.3} ms wall, {d:.3} ms CPU per frame; diff + encode {d:.3} ms wall, {d:.3} ms CPU; {d} frames, {d} with the input written on the GPU, {d:.1} KB per frame\n", .{ o.encode, ms(avc.wall_ns) / ef, ms(avc.cpu_ns) / ef, ms(diff_wall + avc.wall_ns) / ef, ms(diff_cpu + avc.cpu_ns) / ef, avc.frames, avc.gpu_frames, @as(f64, @floatFromInt(avc.bytes)) / ef / 1024 });
            if (gout.h264_writes > 0) {
                const hw: f64 = @floatFromInt(gout.h264_writes);
                var gpu_ns: f64 = 0;
                var runs: u64 = 0;
                for (gout.converters) |x| if (x) |cv| {
                    gpu_ns += cv.gpu_ns;
                    runs += cv.runs;
                };
                std.debug.print("  NV12 on the GPU     {d:.3} ms wall per write ({d} writes), pass {d:.3} ms (GPU clock); tiles brought in later {d}\n", .{ ms(gout.h264_ns) / hw, gout.h264_writes, if (runs > 0) gpu_ns / @as(f64, @floatFromInt(runs)) / 1e6 else -1, if (gout.td) |td| td.freshened else 0 });
            }
            std.debug.print("ENC,{s},{s},{d},{d},{t},{t},{d:.4},{d:.4},{d:.4},{d:.4},{d},{d},{d:.1}\n", .{ o.label, out.name(), width, height, o.diff, o.encode, ms(avc.wall_ns) / ef, ms(avc.cpu_ns) / ef, ms(diff_wall + avc.wall_ns) / ef, ms(diff_cpu + avc.cpu_ns) / ef, avc.frames, avc.gpu_frames, @as(f64, @floatFromInt(avc.bytes)) / ef / 1024 });
        }
        std.debug.print("DIFF,{s},{s},{d},{d},{t},{d:.4},{d:.4},{d:.0},{d},{d},{d}\n", .{ o.label, out.name(), width, height, o.diff, ms(diff_wall) / df, ms(diff_cpu) / df, @as(f64, @floatFromInt(changed_px)) / df, diff_frames, diff_skipped, mismatches });
    }
    std.debug.print("CSV,{s},{s},{d},{d},{s},{d},{d:.3},{d:.3},{d:.3},{d:.3},{d:.3},{d:.4},{d:.4},{d:.1}\n", .{
        o.label,          out.name(),                                                                                  width,                                                 height,                                                using,                                                 n,
        ms(pct(lat, 50)), ms(pct(lat, 95)),                                                                            if (p2r.items.len > 0) ms(pct(p2r.items, 50)) else -1, if (r2i.items.len > 0) ms(pct(r2i.items, 50)) else -1, if (r2i.items.len > 0) ms(pct(r2i.items, 95)) else -1, ms(comp_ns) / nf,
        ms(self_ns) / nf, if (busy_n > 0) @as(f64, @floatFromInt(busy_sum)) / @as(f64, @floatFromInt(busy_n)) else -1,
    });
}
