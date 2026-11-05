//! `--test-capture OUTPUT` (development only): serves one output of the compositor in
//! WAYLAND_DISPLAY read-only, without --desktop's takeover: no lock, no helper or fence, no
//! plugin, no audio, no input to the compositor. For testing the capture paths end to end (shm,
//! and GPU capture unless --no-gpu-capture) against a nested compositor.

const std = @import("std");
const wl = @import("../wl/wl.zig");
const gpucap = @import("../gpu/capture.zig");
const channels = @import("channels.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.testcap);

pub const TestCapture = struct {
    gpa: std.mem.Allocator,
    output_name: []const u8,
    gpu: bool,
    client: ?*wl.Client = null,
    cap: ?*wl.Capture = null,
    gpu_shared: ?*gpucap.Shared = null,
    gpu_out: gpucap.Output = undefined,
    /// The compositor or the output is gone: nothing more is sent.
    failed: bool = false,

    pub fn deinit(t: *TestCapture) void {
        if (t.gpu_shared != null) {
            const o = &t.gpu_out;
            const lazy = if (o.td) |td| td.freshened else 0;
            const passes = if (o.td) |td| td.fresh_passes else 0;
            log.info("test capture of {s}: {d} frames through GPU capture ({d} full copies){s}; {d} tiles left on the GPU, {d} brought in later in {d} passes; H.264 input written on the GPU {d} times ({d:.2} ms each)", .{
                t.output_name,                                                                                                   o.frames, o.full_frames, if (o.off) ", then shm" else "", o.lazy_tiles, lazy, passes, o.h264_writes,
                if (o.h264_writes > 0) @as(f64, @floatFromInt(o.h264_ns)) / @as(f64, @floatFromInt(o.h264_writes)) / 1e6 else 0,
            });
        }
        if (t.cap) |cap| cap.deinit();
        if (t.gpu_shared) |sh| {
            t.gpu_out.deinit();
            sh.destroy();
        }
        if (t.client) |cl| cl.deinit();
        t.* = undefined;
    }

    fn start(t: *TestCapture) !void {
        const client = try wl.Client.connect(t.gpa, .{});
        t.client = client;
        const out = client.findOutput(t.output_name) orelse {
            log.err("no output {s} in the compositor (WAYLAND_DISPLAY)", .{t.output_name});
            return error.NoOutput;
        };
        const base: wl.capture.Options = .{ .backend = .ext };
        var opts = base;
        if (t.gpu) {
            const sh = try gpucap.Shared.create(t.gpa);
            t.gpu_shared = sh;
            t.gpu_out = gpucap.Output.init(sh);
            t.gpu_out.setName(t.output_name);
            opts = sh.captureOptions(base);
        }
        t.cap = try wl.Capture.init(client, out, opts);
        try t.cap.?.requestFrame();
        log.info("test capture of {s} ({d}x{d}), {s}", .{ t.output_name, out.width, out.height, if (t.gpu) "GPU capture" else "shm" });
    }

    pub fn pump(ctx: *anyopaque, c: *Conn) conn_mod.Error!void {
        const t: *TestCapture = @ptrCast(@alignCast(ctx));
        if (t.failed or !c.established or c.output_suppressed or c.reactivating) return;
        if (!channels.graphicsReady(c)) return;
        if (t.cap == null) t.start() catch |e| {
            log.err("{s}: test capture of {s} failed: {t}", .{ c.peer, t.output_name, e });
            t.failed = true;
            return;
        };
        const cap = t.cap.?;
        _ = t.client.?.dispatch() catch |e| {
            log.err("{s}: compositor connection lost: {t}", .{ c.peer, e });
            t.failed = true;
            return;
        };
        switch (cap.state) {
            .stopped, .failed => {
                log.err("{s}: capture of {s} ended ({t})", .{ c.peer, t.output_name, cap.state });
                t.failed = true;
                return;
            },
            else => {},
        }
        if (!channels.canSendFrame(c)) {
            if (cap.ready_idx != null) {
                if (c.pacing.refused) c.pacing.held() else c.ch.stats.blocked += 1;
            }
            return;
        }
        const f = cap.takeFrame() orelse return;
        const gpu: ?gpucap.Handle = if (t.gpu_shared != null) .{ .out = &t.gpu_out, .cap = cap } else null;
        channels.sendDesktopFrame(c, f, gpu) catch |err| switch (err) {
            error.InvalidDimensions => log.warn("{s}: skipping a {d}x{d} frame with stride {d}", .{ c.peer, f.width, f.height, f.stride }),
            else => return err,
        };
        cap.requestFrame() catch |e| {
            log.err("{s}: capture of {s}: {t}", .{ c.peer, t.output_name, e });
            t.failed = true;
        };
    }
};
