//! Display Control Virtual Channel (MS-RDPEDISP): client monitor layouts, which drive resize.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

pub const channel_name = "Microsoft::Windows::RDS::DisplayControl";

pub const Error = error{ BadDispPdu, TooManyMonitors } || bytes.Error;

const type_monitor_layout: u32 = 0x00000002;
const type_caps: u32 = 0x00000005;

pub const max_monitors = 16;

pub const Monitor = struct {
    primary: bool,
    left: i32,
    top: i32,
    width: u32,
    height: u32,
    physical_width_mm: u32,
    physical_height_mm: u32,
    orientation: u32,
    desktop_scale_factor: u32,
    device_scale_factor: u32,
};

pub const Layout = struct {
    monitors: [max_monitors]Monitor = undefined,
    count: usize = 0,

    pub fn slice(l: *const Layout) []const Monitor {
        return l.monitors[0..l.count];
    }

    pub fn bounds(l: *const Layout) struct { left: i32, top: i32, width: u32, height: u32 } {
        var x0: i64 = std.math.maxInt(i64);
        var y0: i64 = std.math.maxInt(i64);
        var x1: i64 = std.math.minInt(i64);
        var y1: i64 = std.math.minInt(i64);
        for (l.slice()) |m| {
            x0 = @min(x0, m.left);
            y0 = @min(y0, m.top);
            x1 = @max(x1, @as(i64, m.left) + m.width);
            y1 = @max(y1, @as(i64, m.top) + m.height);
        }
        // parseLayout limits |left|, |top| to 32768 and sizes to 8192.
        return .{ .left = @intCast(x0), .top = @intCast(y0), .width = @intCast(x1 - x0), .height = @intCast(y1 - y0) };
    }

    /// validate guarantees exactly one primary.
    pub fn primary(l: *const Layout) *const Monitor {
        for (l.slice()) |*m| if (m.primary) return m;
        return &l.monitors[0];
    }
};

/// Largest virtual desktop the server can describe (MS-RDPEGFX 2.2.2.14, MS-RDPBCGR 2.2.1.3.6).
pub const max_desktop = 32766;

/// Advertised in the caps (MS-RDPEDISP 2.2.2.1): a layout covers at most 8192 x 8192 pixels,
/// so the framebuffer stays within 256 MiB.
pub const max_monitor_area_factor_a = 4096;
pub const max_monitor_area_factor_b = 1024;
pub const max_area: u64 = @as(u64, max_monitors) * max_monitor_area_factor_a * max_monitor_area_factor_b;

/// DesktopScaleFactor, or 0 when outside 100..500 or DeviceScaleFactor is not 100, 140 or 180
/// (MS-RDPEDISP 2.2.2.2.1, MS-RDPBCGR 2.2.1.3.2).
pub fn effectiveScale(desktop_scale: u32, device_scale: u32) u32 {
    if (desktop_scale < 100 or desktop_scale > 500) return 0;
    return switch (device_scale) {
        100, 140, 180 => desktop_scale,
        else => 0,
    };
}

pub const LayoutError = error{InvalidLayout};

/// MS-RDPEDISP 3.1.5.2, 2.2.2.2.1: one primary at (0,0), no overlaps, each monitor touches
/// another, and the whole fits max_desktop and the advertised area.
pub fn validate(l: *const Layout) LayoutError!void {
    const ms = l.slice();
    var primaries: usize = 0;
    var area: u64 = 0;
    for (ms) |m| {
        if (m.primary) {
            primaries += 1;
            if (m.left != 0 or m.top != 0) return error.InvalidLayout;
        }
        area += @as(u64, m.width) * m.height;
    }
    if (primaries != 1) return error.InvalidLayout;
    if (area > max_area) return error.InvalidLayout;
    const b = l.bounds();
    if (b.width > max_desktop or b.height > max_desktop) return error.InvalidLayout;
    if (@as(u64, b.width) * b.height > max_area) return error.InvalidLayout;
    for (ms, 0..) |a, i| {
        var touches = ms.len == 1;
        for (ms, 0..) |o, j| {
            if (i == j) continue;
            const ax1 = @as(i64, a.left) + a.width;
            const ay1 = @as(i64, a.top) + a.height;
            const ox1 = @as(i64, o.left) + o.width;
            const oy1 = @as(i64, o.top) + o.height;
            const x_overlap = a.left < ox1 and o.left < ax1;
            const y_overlap = a.top < oy1 and o.top < ay1;
            if (x_overlap and y_overlap) return error.InvalidLayout;
            // Adjacent "even if only at a single point": the closed rectangles meet.
            if (a.left <= ox1 and o.left <= ax1 and a.top <= oy1 and o.top <= ay1) touches = true;
        }
        if (!touches) return error.InvalidLayout;
    }
}

pub fn writeCaps(w: *bytes.Writer, max_num_monitors: u32, factor_a: u32, factor_b: u32) !void {
    try w.u32le(type_caps);
    try w.u32le(20);
    try w.u32le(max_num_monitors);
    try w.u32le(factor_a);
    try w.u32le(factor_b);
}

/// Null for unhandled message types.
pub fn parseLayout(msg: []const u8) Error!?Layout {
    var r = bytes.Reader.init(msg);
    const t = try r.u32le();
    const len = try r.u32le();
    if (len != msg.len) return error.BadDispPdu;
    if (t != type_monitor_layout) return null;
    const entry_size = try r.u32le();
    if (entry_size != 40) return error.BadDispPdu;
    const n = try r.u32le();
    if (n == 0 or n > max_monitors) return error.TooManyMonitors;
    var l = Layout{ .count = n };
    for (l.monitors[0..n]) |*m| {
        m.* = .{
            .primary = (try r.u32le()) & 1 != 0,
            .left = @bitCast(try r.u32le()),
            .top = @bitCast(try r.u32le()),
            .width = try r.u32le(),
            .height = try r.u32le(),
            .physical_width_mm = try r.u32le(),
            .physical_height_mm = try r.u32le(),
            .orientation = try r.u32le(),
            .desktop_scale_factor = try r.u32le(),
            .device_scale_factor = try r.u32le(),
        };
        // MS-RDPEDISP 2.2.2.2.1. Rejected, not clamped: a malformed layout never resizes the desktop.
        if (m.width < 200 or m.width > 8192 or m.width % 2 != 0) return error.BadDispPdu;
        if (m.height < 200 or m.height > 8192) return error.BadDispPdu;
        if (@abs(m.left) > 32768 or @abs(m.top) > 32768) return error.BadDispPdu;
    }
    if (r.remaining() != 0) return error.BadDispPdu;
    return l;
}

test "caps pdu" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeCaps(&w, 16, 3840, 2160);
    try std.testing.expectEqualSlices(u8, &bytes.hex("05 00 00 00 14 00 00 00 10 00 00 00 00 0f 00 00 70 08 00 00"), list.items);
}

fn layoutMsg(comptime n: u32, w_: u32, h_: u32) [16 + 40 * n]u8 {
    var m: [16 + 40 * n]u8 = undefined;
    std.mem.writeInt(u32, m[0..4], type_monitor_layout, .little);
    std.mem.writeInt(u32, m[4..8], m.len, .little);
    std.mem.writeInt(u32, m[8..12], 40, .little);
    std.mem.writeInt(u32, m[12..16], n, .little);
    for (0..n) |i| {
        const e = m[16 + 40 * i ..][0..40];
        @memset(e, 0);
        std.mem.writeInt(u32, e[0..4], if (i == 0) 1 else 0, .little);
        std.mem.writeInt(i32, e[4..8], @intCast(i * w_), .little);
        std.mem.writeInt(u32, e[12..16], w_, .little);
        std.mem.writeInt(u32, e[16..20], h_, .little);
        std.mem.writeInt(u32, e[32..36], 150, .little);
        std.mem.writeInt(u32, e[36..40], 140, .little);
    }
    return m;
}

test "monitor layout parse and bounds" {
    const msg = layoutMsg(2, 1920, 1080);
    const l = (try parseLayout(&msg)).?;
    try std.testing.expectEqual(@as(usize, 2), l.count);
    try std.testing.expect(l.monitors[0].primary);
    try std.testing.expectEqual(@as(u32, 150), l.monitors[1].desktop_scale_factor);
    const b = l.bounds();
    try std.testing.expectEqual(@as(u32, 3840), b.width);
    try std.testing.expectEqual(@as(u32, 1080), b.height);
}

test "monitor layout validation" {
    var odd = layoutMsg(1, 1921, 1080);
    try std.testing.expectError(error.BadDispPdu, parseLayout(&odd));
    var tiny = layoutMsg(1, 100, 1080);
    try std.testing.expectError(error.BadDispPdu, parseLayout(&tiny));
    var ok = layoutMsg(1, 1280, 800);
    std.mem.writeInt(u32, ok[4..8], 999, .little); // length mismatch
    try std.testing.expectError(error.BadDispPdu, parseLayout(&ok));
    var none = layoutMsg(1, 1280, 800);
    std.mem.writeInt(u32, none[12..16], 0, .little);
    try std.testing.expectError(error.TooManyMonitors, parseLayout(&none));
}
