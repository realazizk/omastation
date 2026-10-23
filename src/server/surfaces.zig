//! Multi-monitor sessions: one RDPGFX surface per output (MS-RDPEGFX 2.2.2.9, 2.2.2.14,
//! 2.2.2.20). Without RDPGFX the outputs are composited into one bitmap desktop.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const gfx = @import("../proto/gfx.zig");
const disp = @import("../proto/disp.zig");
const wl = @import("../wl/wl.zig");
const multimon = @import("../session/multimon.zig");
const desktop_mod = @import("../session/desktop.zig");
const encoder_mod = @import("encoder.zig");
const gfx_codecs = @import("gfx_codecs.zig");
const channels = @import("channels.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;
const Desktop = desktop_mod.Desktop;

const log = std.log.scoped(.chan);

pub const Error = conn_mod.Error;

pub const max_outputs = multimon.max_monitors;

/// One output's surface state while it is not swapped in. Per-surface state added to
/// channels.State or Conn must also be added here and to `swap`.
pub const Slot = struct {
    enc: encoder_mod.Encoder,
    surface_id: ?u16 = null,
    surface_w: u32 = 0,
    surface_h: u32 = 0,
    surf: gfx_codecs.Surface = .{},
    motion_frames: u32 = 0,
    last_frame_ms: i64 = 0,
    /// The output's mode; swapped with Conn.width / Conn.height.
    width: u16 = 0,
    height: u16 = 0,
    /// Capture restarted and the first whole frame not sent yet. Not swapped.
    awaiting: bool = false,

    fn deinit(s: *Slot) void {
        s.surf.deinit(s.enc.gpa);
        s.enc.deinit();
    }
};

pub const State = struct {
    slots: [max_outputs]?Slot = @splat(null),
    /// One output's state (or the composite) is swapped in.
    inside: bool = false,
    /// Output whose frame goes first next time (round robin).
    next: usize = 0,
    composite: []u8 = &.{},
    composite_w: u32 = 0,
    composite_h: u32 = 0,
    warned_format: bool = false,
    generation: u32 = 0,

    pub fn deinit(s: *State, gpa: std.mem.Allocator) void {
        for (&s.slots) |*maybe| if (maybe.*) |*slot| {
            slot.deinit();
            maybe.* = null;
        };
        gpa.free(s.composite);
        s.composite = &.{};
    }

    pub fn count(s: *const State) usize {
        var n: usize = 0;
        for (s.slots) |slot| n += @intFromBool(slot != null and slot.?.surface_id != null);
        return n;
    }
};

/// Several outputs and none swapped in: channels.zig and Conn.pumpDesktop hand over here.
pub fn isMulti(c: *const Conn) bool {
    if (c.surfaces.inside) return false;
    const d = c.desktop orelse return false;
    return d.outputCount() > 1;
}

fn swap(c: *Conn, s: *Slot) void {
    std.mem.swap(encoder_mod.Encoder, &c.enc, &s.enc);
    std.mem.swap(?u16, &c.ch.surface_id, &s.surface_id);
    std.mem.swap(u32, &c.ch.surface_w, &s.surface_w);
    std.mem.swap(u32, &c.ch.surface_h, &s.surface_h);
    std.mem.swap(gfx_codecs.Surface, &c.ch.surf, &s.surf);
    std.mem.swap(u32, &c.ch.motion_frames, &s.motion_frames);
    std.mem.swap(i64, &c.ch.last_frame_ms, &s.last_frame_ms);
    std.mem.swap(u16, &c.width, &s.width);
    std.mem.swap(u16, &c.height, &s.height);
}

fn enter(c: *Conn, i: usize) void {
    std.debug.assert(!c.surfaces.inside);
    swap(c, &c.surfaces.slots[i].?);
    c.surfaces.inside = true;
}

fn leave(c: *Conn, i: usize) void {
    swap(c, &c.surfaces.slots[i].?);
    c.surfaces.inside = false;
}

const Old = enum {
    /// The client still has them: DELETE_SURFACE each.
    delete,
    /// The client dropped them on a caps advertise (MS-RDPEGFX 3.3.5.18).
    forget,
};

/// channels.resetGraphics for several outputs, after a CAPS_ADVERTISE.
pub fn resetGraphics(c: *Conn) Error!void {
    return reset(c, .forget);
}

/// RESET_GRAPHICS with a surface per output; live surfaces are deleted first (MS-RDPEGFX 3.2.5.10).
fn reset(c: *Conn, old: Old) Error!void {
    const d = c.desktop.?;
    const plan = d.sessionPlan();
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(c.gpa);
    var w = bytes.Writer.init(&list, c.gpa);
    if (old == .delete) {
        if (c.ch.surface_id) |sid| {
            if (c.ch.surf.prog_live) try gfx_codecs.writeDeleteContext(c, &w, sid);
            try gfx.writeDeleteSurface(&w, sid);
        }
        for (&c.surfaces.slots) |*maybe| if (maybe.*) |*slot| if (slot.surface_id) |sid| {
            if (slot.surf.prog_live) try writeDeleteContext(c, &w, slot, sid);
            try gfx.writeDeleteSurface(&w, sid);
        };
    }
    c.ch.surf.reset();
    c.ch.surface_id = null;
    c.ch.surface_w = 0;
    c.ch.surface_h = 0;
    try gfx.writeResetGraphics(&w, plan.desktop_width, plan.desktop_height, plan.monitors[0..plan.count]);
    for (0..max_outputs) |i| {
        const slot = &c.surfaces.slots[i];
        if (i >= plan.count) {
            if (slot.*) |*s| s.deinit();
            slot.* = null;
            continue;
        }
        if (slot.* == null) slot.* = .{ .enc = encoder_mod.Encoder.init(c.gpa) };
        const s = &slot.*.?;
        const o = plan.outputs[i];
        const ow = std.math.cast(u16, o.width) orelse return error.InvalidDimensions;
        const oh = std.math.cast(u16, o.height) orelse return error.InvalidDimensions;
        try s.enc.reset(o.width, o.height);
        const sid = c.ch.next_surface_id;
        c.ch.next_surface_id +%= 1;
        try gfx.writeCreateSurface(&w, sid, ow, oh);
        try gfx.writeMapSurfaceToOutput(&w, sid, o.origin_x, o.origin_y);
        s.surface_id = sid;
        s.surface_w = o.width;
        s.surface_h = o.height;
        s.width = ow;
        s.height = oh;
        // Client decoders are per surface, so each starts over.
        s.surf.reset();
        s.motion_frames = 0;
        s.awaiting = true;
    }
    _ = try channels.sendGfx(c, list.items);
    try c.flush();
    c.surfaces.generation +%= 1;
    log.info("{s}: {d} surfaces for a {d}x{d} desktop", .{ c.peer, plan.count, plan.desktop_width, plan.desktop_height });
    for (0..plan.count) |i| d.restartCapture(i) catch |err| log.warn("{s}: restarting {s}'s capture failed: {t}", .{ c.peer, d.outputInfo(i).name, err });
}

/// Deletes the surfaces when back to one output; the single-surface path takes over.
fn dropSurfaces(c: *Conn) Error!void {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(c.gpa);
    var w = bytes.Writer.init(&list, c.gpa);
    for (&c.surfaces.slots) |*maybe| if (maybe.*) |*s| {
        if (c.ch.gfx_ready) if (s.surface_id) |sid| {
            if (s.surf.prog_live) try writeDeleteContext(c, &w, s, sid);
            try gfx.writeDeleteSurface(&w, sid);
        };
        s.deinit();
        maybe.* = null;
    };
    if (list.items.len > 0) _ = try channels.sendGfx(c, list.items);
}

/// Sends each output's frame, round robin within the unacknowledged-frames budget.
pub fn pump(c: *Conn, d: *Desktop) Error!bool {
    if (!c.ch.gfx_ready) return pumpComposite(c, d);
    const n = d.outputCount();
    var sent = false;
    for (0..n) |k| {
        const i = (c.surfaces.next + k) % n;
        const src = d.frameSource(i);
        if (c.surfaces.slots[i] == null or c.surfaces.slots[i].?.surface_id == null) continue;
        if (!channels.canSendFrame(c)) {
            if (src.ready()) {
                if (c.pacing.refused) c.pacing.held() else c.ch.stats.blocked += 1;
            }
            break;
        }
        const f = src.take() orelse continue;
        const info = src.info();
        // A frame not of the output's mode (capture renegotiating after a relayout).
        if (uprightWidth(f) != info.width or uprightHeight(f) != info.height) {
            log.debug("{s}: skipping a {d}x{d} frame of {s} ({d}x{d})", .{ c.peer, f.width, f.height, info.name, info.width, info.height });
            try src.request();
            continue;
        }
        {
            enter(c, i);
            defer leave(c, i);
            channels.sendDesktopFrame(c, f) catch |err| switch (err) {
                // A malformed frame is skipped; the client keeps its picture.
                error.InvalidDimensions => log.warn("{s}: skipping a {d}x{d} frame of {s} with stride {d} and {d} bytes", .{ c.peer, f.width, f.height, info.name, f.stride, f.data.len }),
                else => return err,
            };
        }
        try src.request();
        c.surfaces.slots[i].?.awaiting = false;
        sent = true;
    }
    c.surfaces.next = (c.surfaces.next + 1) % n;
    return sent;
}

fn swapsAxes(t: wl.proto.WlOutput.Transform) bool {
    return switch (t) {
        .@"90", .@"270", .flipped_90, .flipped_270 => true,
        else => false,
    };
}

fn uprightWidth(f: *const wl.Frame) u32 {
    return if (swapsAxes(f.transform)) f.height else f.width;
}

fn uprightHeight(f: *const wl.Frame) u32 {
    return if (swapsAxes(f.transform)) f.width else f.height;
}

/// Without RDPGFX: the outputs composited into one picture, sent as bitmap updates (MS-RDPBCGR 2.2.7.1.2).
fn pumpComposite(c: *Conn, d: *Desktop) Error!bool {
    const s = &c.surfaces;
    const dw = d.width();
    const dh = d.height();
    if (s.composite_w != dw or s.composite_h != dh) {
        const buf = try c.gpa.alloc(u8, @as(usize, dw) * dh * 4);
        @memset(buf, 0);
        c.gpa.free(s.composite);
        s.composite = buf;
        s.composite_w = dw;
        s.composite_h = dh;
    }
    const plan = d.sessionPlan();
    var any = false;
    for (0..plan.count) |i| {
        const src = d.frameSource(i);
        const f = src.take() orelse continue;
        blit(c, f, plan.outputs[i].origin_x, plan.outputs[i].origin_y);
        try src.request();
        any = true;
    }
    if (!any) return false;
    var full = [1]wl.Rect{.{ .x = 0, .y = 0, .width = @intCast(dw), .height = @intCast(dh) }};
    const frame: wl.Frame = .{
        .data = s.composite,
        .width = dw,
        .height = dh,
        .stride = dw * 4,
        .format = .xrgb8888,
        .transform = .normal,
        .y_invert = false,
        .damage = &full,
        .presented_ns = 0,
        .latency_ns = 0,
        .seq = 0,
    };
    s.inside = true;
    defer s.inside = false;
    try channels.sendDesktopFrame(c, &frame);
    return true;
}

/// Paints a frame into the composite at (ox, oy), clipped; upright 32-bit frames only.
fn blit(c: *Conn, f: *const wl.Frame, ox: u32, oy: u32) void {
    const s = &c.surfaces;
    const swap_rb = switch (f.format) {
        .xrgb8888, .argb8888 => false,
        .xbgr8888, .abgr8888 => true,
        else => null,
    };
    if (swap_rb == null or f.transform != .normal or f.y_invert or f.width == 0 or f.height == 0 or
        @as(u64, f.stride) < @as(u64, f.width) * 4 or f.data.len < @as(u64, f.stride) * (f.height - 1) + @as(u64, f.width) * 4)
    {
        if (!s.warned_format) log.warn("{s}: a {d}x{d} {t} frame cannot be composited (transform {d})", .{ c.peer, f.width, f.height, f.format, @backingInt(f.transform) });
        s.warned_format = true;
        return;
    }
    if (ox >= s.composite_w or oy >= s.composite_h) return;
    const w = @min(f.width, s.composite_w - ox);
    const h = @min(f.height, s.composite_h - oy);
    const dst_stride = @as(usize, s.composite_w) * 4;
    for (0..h) |y| {
        const src = f.data[y * f.stride ..][0 .. w * 4];
        const dst = s.composite[(oy + y) * dst_stride + @as(usize, ox) * 4 ..][0 .. w * 4];
        if (!swap_rb.?) {
            @memcpy(dst, src);
            continue;
        }
        for (0..w) |x| dst[x * 4 ..][0..4].* = .{ src[x * 4 + 2], src[x * 4 + 1], src[x * 4], src[x * 4 + 3] };
    }
}

/// channels.refresh for several outputs or the composite; an output with no picture is recaptured.
pub fn refresh(c: *Conn) Error!void {
    if (!c.ch.gfx_ready) {
        c.surfaces.inside = true;
        defer c.surfaces.inside = false;
        return channels.refresh(c);
    }
    const d = c.desktop.?;
    for (0..max_outputs) |i| {
        const slot = c.surfaces.slots[i] orelse continue;
        if (slot.surface_id == null) continue;
        if (!slot.enc.valid) {
            if (!slot.awaiting) {
                c.surfaces.slots[i].?.awaiting = true;
                d.restartCapture(i) catch |err| log.warn("{s}: restarting a capture failed: {t}", .{ c.peer, err });
            }
            continue;
        }
        enter(c, i);
        defer leave(c, i);
        try channels.refresh(c);
    }
}

pub fn refine(c: *Conn) Error!void {
    if (!c.ch.gfx_ready) {
        c.surfaces.inside = true;
        defer c.surfaces.inside = false;
        return channels.refine(c);
    }
    for (0..max_outputs) |i| {
        const slot = &(c.surfaces.slots[i] orelse continue);
        if (slot.surface_id == null or !gfx_codecs.pendingOn(&slot.enc, &slot.surf)) continue;
        enter(c, i);
        defer leave(c, i);
        try channels.refine(c);
    }
}

pub fn refinePending(c: *const Conn) bool {
    if (!c.ch.gfx_ready) return c.enc.hasLossy() or c.enc.hasOwed(); // the composite
    for (&c.surfaces.slots) |*maybe| if (maybe.*) |*slot| if (gfx_codecs.pendingOn(&slot.enc, &slot.surf)) return true;
    return false;
}

fn writeDeleteContext(c: *Conn, w: *bytes.Writer, s: *Slot, sid: u16) Error!void {
    std.mem.swap(gfx_codecs.Surface, &c.ch.surf, &s.surf);
    defer std.mem.swap(gfx_codecs.Surface, &c.ch.surf, &s.surf);
    try gfx_codecs.writeDeleteContext(c, w, sid);
}

/// Applies a Display Control layout (MS-RDPEDISP 2.2.2.2); one that fails leaves the session as is.
pub fn onLayout(c: *Conn, d: *Desktop, layout: *const disp.Layout) Error!void {
    const l = multimon.layoutFromDisplayControl(layout) catch |err| {
        log.warn("{s}: ignoring a monitor layout ({t})", .{ c.peer, err });
        return;
    };
    multimon.validateDisplayControlLayout(&l, .{}) catch |err| {
        log.warn("{s}: ignoring a monitor layout that cannot be applied ({t})", .{ c.peer, err });
        return;
    };
    const was_multi = d.outputCount() > 1;
    d.relayout(&l) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            log.warn("{s}: relayout failed: {t}", .{ c.peer, err });
            return;
        },
    };
    const w: u16 = @intCast(d.width());
    const h: u16 = @intCast(d.height());
    log.info("{s}: relayout: {d} output(s), desktop {d}x{d}", .{ c.peer, d.outputCount(), w, h });
    c.surfaces.generation +%= 1;
    c.width = w;
    c.height = h;
    if (d.outputCount() > 1) {
        if (c.ch.gfx_ready) return reset(c, .delete);
        // Without RDPGFX up yet, its RESET_GRAPHICS will carry the layout.
        if (c.ch.gfx_refused) return c.reactivate();
        return;
    }
    if (was_multi) try dropSurfaces(c);
    c.ch.monitors[0] = .{ .left = 0, .top = 0, .right = @as(i32, w) - 1, .bottom = @as(i32, h) - 1, .primary = true };
    c.ch.monitor_count = 1;
    if (c.ch.gfx_ready) {
        try channels.resetGraphics(c);
        try c.enc.reset(w, h);
        try c.flush();
        d.restartCapture(0) catch |err| log.warn("{s}: restarting the capture failed: {t}", .{ c.peer, err });
        return;
    }
    if (c.ch.gfx_refused) return c.reactivate();
}

/// The client's monitors as TS_MONITOR_DEF (MS-RDPBCGR 2.2.1.3.6.1) for the Monitor Layout
/// PDU (2.2.12.1); resend when `layoutGeneration` changes.
pub fn monitorLayout(c: *const Conn, out: *[max_outputs]multimon.MonitorDef) []const multimon.MonitorDef {
    if (c.desktop) |d| {
        const plan = d.sessionPlan();
        for (plan.monitors[0..plan.count], out[0..plan.count]) |m, *o| o.* = .{
            .left = m.left,
            .top = m.top,
            .right = m.right,
            .bottom = m.bottom,
            .flags = if (m.primary) multimon.monitor_primary else 0,
        };
        return out[0..plan.count];
    }
    const n = c.ch.monitor_count;
    if (n == 0) {
        out[0] = .{ .left = 0, .top = 0, .right = @as(i32, c.width) - 1, .bottom = @as(i32, c.height) - 1, .flags = multimon.monitor_primary };
        return out[0..1];
    }
    // Graphics monitors are relative to the desktop's top-left; TS_MONITOR_DEF to the primary's.
    var px: i32 = 0;
    var py: i32 = 0;
    for (c.ch.monitors[0..n]) |m| if (m.primary) {
        px = m.left;
        py = m.top;
    };
    for (c.ch.monitors[0..n], out[0..n]) |m, *o| o.* = .{ .left = m.left - px, .top = m.top - py, .right = m.right - px, .bottom = m.bottom - py, .flags = if (m.primary) multimon.monitor_primary else 0 };
    return out[0..n];
}

pub fn layoutGeneration(c: *const Conn) u32 {
    return c.surfaces.generation;
}

/// Client Monitor Data (MS-RDPBCGR 2.2.1.3.6, 2.2.1.3.10); null for fewer than two monitors.
pub fn clientLayout(c: *const Conn) multimon.Error!?multimon.Layout {
    if (c.client.monitor_count < 2) return null;
    const l = try multimon.layoutFromClientData(&c.client);
    try multimon.validateClientLayout(&l);
    return l;
}
