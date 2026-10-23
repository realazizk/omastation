//! Multiple monitors: client monitor data (MS-RDPBCGR 2.2.1.3.6, 2.2.1.3.10), the
//! Monitor Layout PDU (2.2.12.1), layout validation (MS-RDPEDISP 2.2.2.2), and the
//! session plan: one Hyprland output (RDP-n) and one RDPGFX surface per monitor.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const gcc = @import("../proto/gcc.zig");
const disp = @import("../proto/disp.zig");
const gfx = @import("../proto/gfx.zig");
const rdp = @import("../proto/rdp.zig");
const hypr = @import("../session/hypr.zig");
const console = @import("../session/console.zig");
const rdpei = @import("../channel/rdpei.zig");

pub const Error = error{
    EndOfBuffer,
    BadBlockType,
    BadBlockLength,
    TrailingBytes,
    /// monitorCount above 16 (or above MaxNumMonitors for Display Control).
    TooManyMonitors,
    NoMonitors,
    /// TS_UD_CS_MONITOR_EX.monitorAttributeSize is not 20.
    BadAttributeSize,
    /// TS_UD_CS_MONITOR_EX.monitorCount differs from TS_UD_CS_MONITOR's.
    CountMismatch,
    InvalidRect,
    NoPrimary,
    MultiplePrimaries,
    PrimaryNotAtOrigin,
    Overlap,
    /// A monitor touches no other monitor (MS-RDPEDISP 3.1.5.2).
    NotAdjacent,
    /// Virtual desktop side above 32766 (2.2.1.3.6).
    DesktopTooLarge,
    /// Virtual desktop smaller than 200 x 200 (2.2.1.3.6).
    DesktopTooSmall,
    /// Display Control monitor side outside 200..8192, or an odd width (MS-RDPEDISP 2.2.2.2.1).
    BadMonitorSize,
    /// Layout area above MaxNumMonitors * FactorA * FactorB (MS-RDPEDISP 2.2.2.2).
    AreaTooLarge,
    OutOfMemory,
    NoSpaceLeft,
};

pub const max_monitors = 16;

pub const cs_monitor: u16 = 0xC005;
pub const cs_monitor_ex: u16 = 0xC008;
/// TS_MONITOR_DEF.flags / DISPLAYCONTROL_MONITOR_PRIMARY
pub const monitor_primary: u32 = 0x0000_0001;
pub const monitor_def_size: usize = 20;
pub const monitor_attributes_size: u32 = 20;

/// Virtual desktop limits (2.2.1.3.6).
pub const max_desktop_size: u32 = 32766;
pub const min_desktop_size: u32 = 200;
/// Display Control monitor limits (MS-RDPEDISP 2.2.2.2.1).
pub const disp_min_monitor_size: u32 = 200;
pub const disp_max_monitor_size: u32 = 8192;

pub const orientation_landscape: u32 = 0;
pub const orientation_portrait: u32 = 90;
pub const orientation_landscape_flipped: u32 = 180;
pub const orientation_portrait_flipped: u32 = 270;

/// Share Data Header pduType2 of the Monitor Layout PDU (2.2.8.1.1.1.2).
pub const pdutype2_monitor_layout: u8 = 55;

/// Set Error Info codes for rejected client monitor data (2.2.5.1.1).
pub const errinfo_badmonitordata: u32 = 0x0000_1129;
pub const errinfo_virtualdesktoptoolarge: u32 = 0x0000_1134;
pub const errinfo_monitorgeometryvalidationfailed: u32 = 0x0000_1135;
pub const errinfo_invalidmonitorcount: u32 = 0x0000_1136;

/// TS_MONITOR_DEF (2.2.1.3.6.1): inclusive right/bottom.
pub const MonitorDef = struct {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    flags: u32 = 0,
};

/// TS_MONITOR_ATTRIBUTES (2.2.1.3.10.1), raw.
pub const MonitorAttributes = struct {
    physical_width: u32 = 0,
    physical_height: u32 = 0,
    orientation: u32 = 0,
    desktop_scale_factor: u32 = 0,
    device_scale_factor: u32 = 0,
};

pub const ClientMonitorData = struct {
    flags: u32 = 0,
    count: usize = 0,
    defs: [max_monitors]MonitorDef = undefined,
};

pub const ClientMonitorExData = struct {
    flags: u32 = 0,
    count: usize = 0,
    attributes: [max_monitors]MonitorAttributes = undefined,
};

/// Body of a client data block (TS_UD_HEADER, 2.2.1.3.1); header length must equal block length.
fn blockBody(block: []const u8, block_type: u16) Error!bytes.Reader {
    var r = bytes.Reader.init(block);
    const t = try r.u16le();
    const len = try r.u16le();
    if (t != block_type) return error.BadBlockType;
    if (len < 4 or len != block.len) return error.BadBlockLength;
    return r;
}

/// monitorCount TS_MONITOR_DEFs (2.2.1.3.6.1), each rect checked.
fn readMonitorDefs(r: *bytes.Reader, d: *ClientMonitorData) Error!void {
    const count = try r.u32le();
    if (count > max_monitors) return error.TooManyMonitors;
    for (d.defs[0..count]) |*m| {
        m.* = .{
            .left = @bitCast(try r.u32le()),
            .top = @bitCast(try r.u32le()),
            .right = @bitCast(try r.u32le()),
            .bottom = @bitCast(try r.u32le()),
            .flags = try r.u32le(),
        };
        if (m.right < m.left or m.bottom < m.top) return error.InvalidRect;
    }
    if (r.remaining() != 0) return error.TrailingBytes;
    d.count = count;
}

fn writeMonitorDefs(w: *bytes.Writer, defs: []const MonitorDef) Error!void {
    try w.u32le(@intCast(defs.len));
    for (defs) |m| {
        try w.u32le(@bitCast(m.left));
        try w.u32le(@bitCast(m.top));
        try w.u32le(@bitCast(m.right));
        try w.u32le(@bitCast(m.bottom));
        try w.u32le(m.flags);
    }
}

/// Whole TS_UD_CS_MONITOR block; layout rules are checked by `validateClientLayout`.
pub fn decodeClientMonitorData(block: []const u8) Error!ClientMonitorData {
    var r = try blockBody(block, cs_monitor);
    var d = ClientMonitorData{ .flags = try r.u32le() };
    try readMonitorDefs(&r, &d);
    return d;
}

pub fn encodeClientMonitorData(w: *bytes.Writer, defs: []const MonitorDef) Error!void {
    if (defs.len > max_monitors) return error.TooManyMonitors;
    try w.u16le(cs_monitor);
    try w.u16le(@intCast(12 + monitor_def_size * defs.len));
    try w.u32le(0); // flags
    try writeMonitorDefs(w, defs);
}

/// Whole TS_UD_CS_MONITOR_EX block; monitorCount must equal TS_UD_CS_MONITOR's (`monitor_count`).
pub fn decodeClientMonitorExData(block: []const u8, monitor_count: usize) Error!ClientMonitorExData {
    var r = try blockBody(block, cs_monitor_ex);
    var x = ClientMonitorExData{ .flags = try r.u32le() };
    if (try r.u32le() != monitor_attributes_size) return error.BadAttributeSize;
    const count = try r.u32le();
    if (count > max_monitors) return error.TooManyMonitors;
    if (count != monitor_count) return error.CountMismatch;
    for (x.attributes[0..count]) |*a| a.* = .{
        .physical_width = try r.u32le(),
        .physical_height = try r.u32le(),
        .orientation = try r.u32le(),
        .desktop_scale_factor = try r.u32le(),
        .device_scale_factor = try r.u32le(),
    };
    if (r.remaining() != 0) return error.TrailingBytes;
    x.count = count;
    return x;
}

pub fn encodeClientMonitorExData(w: *bytes.Writer, attrs: []const MonitorAttributes) Error!void {
    if (attrs.len > max_monitors) return error.TooManyMonitors;
    try w.u16le(cs_monitor_ex);
    try w.u16le(@intCast(16 + monitor_attributes_size * attrs.len));
    try w.u32le(0); // flags
    try w.u32le(monitor_attributes_size);
    try w.u32le(@intCast(attrs.len));
    for (attrs) |a| {
        try w.u32le(a.physical_width);
        try w.u32le(a.physical_height);
        try w.u32le(a.orientation);
        try w.u32le(a.desktop_scale_factor);
        try w.u32le(a.device_scale_factor);
    }
}

/// Attributes after the ignore rules of 2.2.1.3.10.1 and MS-RDPEDISP 2.2.2.2.1: null = ignored.
pub const EffectiveAttributes = struct {
    /// Both or neither: each must be 10..10000 mm.
    physical_width_mm: ?u32 = null,
    physical_height_mm: ?u32 = null,
    orientation: ?u32 = null,
    /// Both or neither: desktop 100..500 and device 100, 140 or 180.
    desktop_scale_factor: ?u32 = null,
    device_scale_factor: ?u32 = null,
};

pub fn effectiveAttributes(a: MonitorAttributes) Error!EffectiveAttributes {
    var e = EffectiveAttributes{};
    const mm_ok = struct {
        fn f(v: u32) bool {
            return v >= 10 and v <= 10000;
        }
    }.f;
    if (mm_ok(a.physical_width) and mm_ok(a.physical_height)) {
        e.physical_width_mm = a.physical_width;
        e.physical_height_mm = a.physical_height;
    }
    switch (a.orientation) {
        orientation_landscape, orientation_portrait, orientation_landscape_flipped, orientation_portrait_flipped => e.orientation = a.orientation,
        else => {},
    }
    if (disp.effectiveScale(a.desktop_scale_factor, a.device_scale_factor) != 0) {
        e.desktop_scale_factor = a.desktop_scale_factor;
        e.device_scale_factor = a.device_scale_factor;
    }
    return e;
}

/// monitorCount + monitorDefArray (the part after the Share Data Header).
pub fn encodeMonitorLayoutBody(w: *bytes.Writer, defs: []const MonitorDef) Error!void {
    if (defs.len > max_monitors) return error.TooManyMonitors;
    try writeMonitorDefs(w, defs);
}

pub fn decodeMonitorLayoutBody(body: []const u8) Error!ClientMonitorData {
    var r = bytes.Reader.init(body);
    var d = ClientMonitorData{};
    try readMonitorDefs(&r, &d);
    return d;
}

/// Whole Monitor Layout PDU (2.2.12.1): Share Control and Share Data Headers + body.
pub fn writeMonitorLayoutPdu(w: *bytes.Writer, defs: []const MonitorDef) Error!void {
    if (defs.len > max_monitors) return error.TooManyMonitors;
    const p = try rdp.DataPdu.begin(w, .monitor_layout_pdu, rdp.stream_low);
    // pduSource must be 0 (2.2.12.1).
    w.patchU16le(p.start + 4, 0);
    try encodeMonitorLayoutBody(w, defs);
    p.finish(w);
}

/// 3.3.5.12.1: only to clients with RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU.
pub fn serverMaySendMonitorLayout(early_caps: gcc.EarlyCaps) Error!bool {
    return early_caps.support_monitor_layout_pdu;
}

pub const Monitor = struct {
    left: i32,
    top: i32,
    width: u32,
    height: u32,
    primary: bool = false,
    attributes: MonitorAttributes = .{},
};

pub const Layout = struct {
    count: usize = 0,
    monitors: [max_monitors]Monitor = undefined,
};

/// Exclusive right/bottom.
pub const Rect = struct {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
};

fn slice(l: *const Layout) Error![]const Monitor {
    if (l.count > max_monitors) return error.TooManyMonitors;
    return l.monitors[0..l.count];
}

fn defSize(lo: i32, hi: i32) Error!u32 {
    if (hi < lo) return error.InvalidRect;
    const n = @as(i64, hi) - lo + 1;
    if (n > max_desktop_size) return error.DesktopTooLarge;
    return @intCast(n);
}

pub fn layoutFromMonitorDefs(defs: []const MonitorDef, attrs: ?[]const MonitorAttributes) Error!Layout {
    if (defs.len > max_monitors) return error.TooManyMonitors;
    if (attrs) |a| if (a.len != defs.len) return error.CountMismatch;
    var l = Layout{ .count = defs.len };
    for (defs, l.monitors[0..defs.len], 0..) |d, *m, i| m.* = .{
        .left = d.left,
        .top = d.top,
        .width = try defSize(d.left, d.right),
        .height = try defSize(d.top, d.bottom),
        .primary = d.flags & monitor_primary != 0,
        .attributes = if (attrs) |a| a[i] else .{},
    };
    return l;
}

/// The GCC monitors if any, else one primary desktopWidth x desktopHeight monitor at (0, 0).
pub fn layoutFromClientData(d: *const gcc.ClientData) Error!Layout {
    if (d.monitor_count > max_monitors) return error.TooManyMonitors;
    if (d.monitor_count == 0) {
        var l = Layout{ .count = 1 };
        l.monitors[0] = .{
            .left = 0,
            .top = 0,
            .width = d.desktop_width,
            .height = d.desktop_height,
            .primary = true,
            .attributes = .{
                .physical_width = d.desktop_physical_width,
                .physical_height = d.desktop_physical_height,
                .orientation = d.desktop_orientation,
                .desktop_scale_factor = d.desktop_scale_factor,
                .device_scale_factor = d.device_scale_factor,
            },
        };
        return l;
    }
    var l = Layout{ .count = d.monitor_count };
    for (d.monitors[0..d.monitor_count], l.monitors[0..d.monitor_count]) |g, *m| m.* = .{
        .left = g.left,
        .top = g.top,
        .width = try defSize(g.left, g.right),
        .height = try defSize(g.top, g.bottom),
        .primary = g.primary,
        .attributes = .{
            .physical_width = g.physical_width_mm,
            .physical_height = g.physical_height_mm,
            .orientation = g.orientation,
            .desktop_scale_factor = g.desktop_scale_factor,
            .device_scale_factor = g.device_scale_factor,
        },
    };
    return l;
}

pub fn layoutFromDisplayControl(l: *const disp.Layout) Error!Layout {
    if (l.count > max_monitors) return error.TooManyMonitors;
    var out = Layout{ .count = l.count };
    for (l.monitors[0..l.count], out.monitors[0..l.count]) |d, *m| m.* = .{
        .left = d.left,
        .top = d.top,
        .width = d.width,
        .height = d.height,
        .primary = d.primary,
        .attributes = .{
            .physical_width = d.physical_width_mm,
            .physical_height = d.physical_height_mm,
            .orientation = d.orientation,
            .desktop_scale_factor = d.desktop_scale_factor,
            .device_scale_factor = d.device_scale_factor,
        },
    };
    return out;
}

/// Primary flag, inclusive right/bottom; error.InvalidRect for a zero-size or i32-overflowing monitor.
pub fn monitorDefs(l: *const Layout, out: *[max_monitors]MonitorDef) Error![]const MonitorDef {
    const ms = try slice(l);
    for (ms, out[0..ms.len]) |m, *d| {
        const e = try edges(m);
        d.* = .{
            .left = m.left,
            .top = m.top,
            .right = std.math.cast(i32, e.right - 1) orelse return error.InvalidRect,
            .bottom = std.math.cast(i32, e.bottom - 1) orelse return error.InvalidRect,
            .flags = if (m.primary) monitor_primary else 0,
        };
    }
    return out[0..ms.len];
}

fn edges(m: Monitor) Error!struct { right: i64, bottom: i64 } {
    if (m.width == 0 or m.height == 0) return error.InvalidRect;
    return .{ .right = @as(i64, m.left) + m.width, .bottom = @as(i64, m.top) + m.height };
}

const WideRect = struct { left: i64, top: i64, right: i64, bottom: i64 };

fn wideBounds(ms: []const Monitor) WideRect {
    var b = WideRect{ .left = std.math.maxInt(i64), .top = std.math.maxInt(i64), .right = std.math.minInt(i64), .bottom = std.math.minInt(i64) };
    for (ms) |m| {
        b.left = @min(b.left, m.left);
        b.top = @min(b.top, m.top);
        b.right = @max(b.right, @as(i64, m.left) + m.width);
        b.bottom = @max(b.bottom, @as(i64, m.top) + m.height);
    }
    return b;
}

/// Bounding box; error.DesktopTooLarge when its edges do not fit an i32.
pub fn bounds(l: *const Layout) Error!Rect {
    const ms = try slice(l);
    if (ms.len == 0) return error.NoMonitors;
    const b = wideBounds(ms);
    return .{
        .left = @intCast(b.left),
        .top = @intCast(b.top),
        .right = std.math.cast(i32, b.right) orelse return error.DesktopTooLarge,
        .bottom = std.math.cast(i32, b.bottom) orelse return error.DesktopTooLarge,
    };
}

pub fn overlaps(a: Monitor, b: Monitor) Error!bool {
    const ax1 = @as(i64, a.left) + a.width;
    const ay1 = @as(i64, a.top) + a.height;
    const bx1 = @as(i64, b.left) + b.width;
    const by1 = @as(i64, b.top) + b.height;
    return a.left < bx1 and b.left < ax1 and a.top < by1 and b.top < ay1;
}

/// Touching along an edge or at a corner without overlapping (MS-RDPEDISP 3.1.5.2).
pub fn adjacent(a: Monitor, b: Monitor) Error!bool {
    if (try overlaps(a, b)) return false;
    const ax1 = @as(i64, a.left) + a.width;
    const ay1 = @as(i64, a.top) + a.height;
    const bx1 = @as(i64, b.left) + b.width;
    const by1 = @as(i64, b.top) + b.height;
    return a.left <= bx1 and b.left <= ax1 and a.top <= by1 and b.top <= ay1;
}

/// Exactly one primary monitor, at (0, 0) (2.2.1.3.6.1, MS-RDPEDISP 2.2.2.2.1).
fn checkPrimary(ms: []const Monitor) Error!void {
    var primary: ?Monitor = null;
    for (ms) |m| {
        if (!m.primary) continue;
        if (primary != null) return error.MultiplePrimaries;
        primary = m;
    }
    const p = primary orelse return error.NoPrimary;
    if (p.left != 0 or p.top != 0) return error.PrimaryNotAtOrigin;
}

fn checkOverlap(ms: []const Monitor) Error!void {
    for (ms, 0..) |a, i| for (ms[i + 1 ..]) |b| {
        if (try overlaps(a, b)) return error.Overlap;
    };
}

/// MS-RDPBCGR 2.2.1.3.6, 2.2.1.3.6.1: 1..16 monitors, one primary at (0, 0), no overlap,
/// bounding box 200..32766 per side. Adjacency is not required.
pub fn validateClientLayout(l: *const Layout) Error!void {
    const ms = try slice(l);
    if (ms.len == 0) return error.NoMonitors;
    for (ms) |m| _ = try edges(m);
    try checkPrimary(ms);
    try checkOverlap(ms);
    const b = wideBounds(ms);
    if (b.right - b.left > max_desktop_size or b.bottom - b.top > max_desktop_size) return error.DesktopTooLarge;
    if (b.right - b.left < min_desktop_size or b.bottom - b.top < min_desktop_size) return error.DesktopTooSmall;
}

/// Set Error Info code (2.2.5.1.1) for `err`; errors without a code are returned.
pub fn errInfoCode(err: Error) Error!u32 {
    return switch (err) {
        error.EndOfBuffer, error.BadBlockType, error.BadBlockLength, error.TrailingBytes, error.BadAttributeSize, error.CountMismatch => errinfo_badmonitordata,
        error.TooManyMonitors => errinfo_invalidmonitorcount,
        error.DesktopTooLarge => errinfo_virtualdesktoptoolarge,
        error.NoMonitors, error.InvalidRect, error.NoPrimary, error.MultiplePrimaries, error.PrimaryNotAtOrigin, error.Overlap, error.NotAdjacent, error.DesktopTooSmall, error.BadMonitorSize, error.AreaTooLarge => errinfo_monitorgeometryvalidationfailed,
        error.OutOfMemory, error.NoSpaceLeft => err,
    };
}

/// DISPLAYCONTROL_CAPS_PDU values the server advertised (2.2.2.1).
pub const DisplayControlCaps = struct {
    max_num_monitors: u32 = 16,
    max_monitor_area_factor_a: u32 = 8192,
    max_monitor_area_factor_b: u32 = 8192,
};

/// MS-RDPEDISP 2.2.2.2, 2.2.2.2.1, 3.1.5.2: 1..MaxNumMonitors monitors of 200..8192 with even
/// width, one primary at (0, 0), no overlap, each adjacent to another, capped total area.
pub fn validateDisplayControlLayout(l: *const Layout, caps: DisplayControlCaps) Error!void {
    const ms = try slice(l);
    if (ms.len == 0) return error.NoMonitors;
    if (ms.len > caps.max_num_monitors) return error.TooManyMonitors;
    for (ms) |m| {
        if (m.width < disp_min_monitor_size or m.width > disp_max_monitor_size or m.width % 2 != 0) return error.BadMonitorSize;
        if (m.height < disp_min_monitor_size or m.height > disp_max_monitor_size) return error.BadMonitorSize;
    }
    try checkPrimary(ms);
    try checkOverlap(ms);
    if (ms.len > 1) for (ms, 0..) |a, i| {
        const touches = for (ms, 0..) |b, j| {
            if (i != j and try adjacent(a, b)) break true;
        } else false;
        if (!touches) return error.NotAdjacent;
    };
    var area: u128 = 0;
    for (ms) |m| area += @as(u128, m.width) * m.height;
    const max_area = @as(u128, caps.max_num_monitors) * caps.max_monitor_area_factor_a * caps.max_monitor_area_factor_b;
    if (area > max_area) return error.AreaTooLarge;
}

pub const OutputPlan = struct {
    /// "RDP-1".."RDP-16" (name_buf[0..name_len]).
    name_buf: [8]u8 = undefined,
    name_len: u8 = 0,
    monitor: u8,
    /// Output mode in pixels (the monitor's size, fitted to the scale).
    width: u32,
    height: u32,
    /// Hyprland scale = scale_k / 120.
    scale_k: u32,
    /// Hyprland layout position (logical pixels).
    x: i32,
    y: i32,
    /// MAP_SURFACE_TO_OUTPUT origin in the Graphics Output Buffer.
    origin_x: u32,
    origin_y: u32,

    pub fn name(o: *const OutputPlan) []const u8 {
        return o.name_buf[0..o.name_len];
    }
};

pub const SessionPlan = struct {
    /// RESET_GRAPHICS width/height: the layout's bounding box.
    desktop_width: u32 = 0,
    desktop_height: u32 = 0,
    count: usize = 0,
    /// Outputs: the primary's first (RDP-1), then layout order.
    outputs: [max_monitors]OutputPlan = undefined,
    /// RESET_GRAPHICS monitorDefArray: layout order, primary-relative (MS-RDPEGFX 2.2.2.14).
    monitors: [max_monitors]gfx.Monitor = undefined,
};

pub const PlanOptions = struct {
    /// Origin of the RDP outputs in Hyprland's layout (right of the physical monitors).
    base_x: i32 = 0,
    base_y: i32 = 0,
};

/// DesktopScaleFactor; 100 when the attributes are ignored (2.2.1.3.10.1).
fn scalePercent(m: Monitor) u32 {
    return (effectiveAttributes(m.attributes) catch unreachable).desktop_scale_factor orelse 100;
}

/// Layout index per output: the first primary (else first) monitor as RDP-1, then layout order.
pub fn planOrder(l: *const Layout) [max_monitors]usize {
    var order: [max_monitors]usize = @splat(0);
    var primary: usize = 0;
    for (l.monitors[0..@min(l.count, max_monitors)], 0..) |m, i| if (m.primary) {
        primary = i;
        break;
    };
    order[0] = primary;
    var n: usize = 1;
    for (0..@min(l.count, max_monitors)) |i| if (i != primary) {
        order[n] = i;
        n += 1;
    };
    return order;
}

/// One output per monitor at its DesktopScaleFactor; bounding box <= 32766 (MS-RDPEGFX 2.2.2.14).
pub fn planSession(l: *const Layout, opts: PlanOptions) Error!SessionPlan {
    const ms = try slice(l);
    if (ms.len == 0) return error.NoMonitors;
    for (ms) |m| _ = try edges(m);
    const b = wideBounds(ms);
    if (b.right - b.left > max_desktop_size or b.bottom - b.top > max_desktop_size) return error.DesktopTooLarge;
    if (b.right > std.math.maxInt(i32) or b.bottom > std.math.maxInt(i32)) return error.DesktopTooLarge;

    var p = SessionPlan{ .desktop_width = @intCast(b.right - b.left), .desktop_height = @intCast(b.bottom - b.top), .count = ms.len };
    for (ms, p.monitors[0..ms.len]) |m, *d| d.* = .{
        .left = m.left,
        .top = m.top,
        .right = @intCast(@as(i64, m.left) + m.width - 1),
        .bottom = @intCast(@as(i64, m.top) + m.height - 1),
        .primary = m.primary,
    };

    const order = planOrder(l);

    var uniform = true;
    for (order[0..ms.len], p.outputs[0..ms.len], 0..) |mi, *o, i| {
        const m = ms[mi];
        const fit = hypr.fitDesktop(m.width, m.height, scalePercent(m));
        o.* = .{
            .monitor = @intCast(mi),
            .width = fit.width,
            .height = fit.height,
            .scale_k = fit.k,
            .x = 0,
            .y = 0,
            .origin_x = @intCast(m.left - b.left),
            .origin_y = @intCast(m.top - b.top),
        };
        o.name_len = @intCast((try outputName(&o.name_buf, i)).len);
        if (fit.k != p.outputs[0].scale_k) uniform = false;
    }
    if (uniform) {
        for (p.outputs[0..ms.len]) |*o| {
            o.x = try logicalCoord(opts.base_x, @divFloor(@as(i64, o.origin_x) * 120, o.scale_k));
            o.y = try logicalCoord(opts.base_y, @divFloor(@as(i64, o.origin_y) * 120, o.scale_k));
        }
    } else {
        try placeMixed(ms, p.outputs[0..ms.len], opts);
    }
    return p;
}

fn logicalCoord(base: i32, offset: i64) Error!i32 {
    return std.math.cast(i32, base + offset) orelse error.DesktopTooLarge;
}

/// Mixed scales, per axis: start at the largest logical end of monitors wholly before this one.
fn placeMixed(ms: []const Monitor, outs: []OutputPlan, opts: PlanOptions) Error!void {
    const Axis = enum { x, y };
    inline for (.{ Axis.x, Axis.y }) |axis| {
        var idx: [max_monitors]usize = undefined;
        for (idx[0..outs.len], 0..) |*v, i| v.* = i;
        const Ctx = struct {
            ms: []const Monitor,
            outs: []const OutputPlan,
            fn start(c: @This(), i: usize) i64 {
                const m = c.ms[c.outs[i].monitor];
                return if (axis == .x) m.left else m.top;
            }
            fn less(c: @This(), a: usize, b: usize) bool {
                return c.start(a) < c.start(b);
            }
        };
        const ctx = Ctx{ .ms = ms, .outs = outs };
        std.mem.sort(usize, idx[0..outs.len], ctx, Ctx.less);
        var pos: [max_monitors]i64 = undefined;
        var end: [max_monitors]i64 = undefined;
        for (idx[0..outs.len], 0..) |i, k| {
            const o = outs[i];
            const px: u32 = if (axis == .x) o.width else o.height;
            const start = ctx.start(i);
            var at: i64 = if (axis == .x) opts.base_x else opts.base_y;
            for (idx[0..k]) |j| {
                const mj = ms[outs[j].monitor];
                const end_px = ctx.start(j) + (if (axis == .x) mj.width else mj.height);
                if (end_px <= start) at = @max(at, end[j]);
            }
            pos[i] = at;
            end[i] = at + (std.math.divCeil(i64, @as(i64, px) * 120, o.scale_k) catch unreachable);
        }
        for (outs, 0..) |*o, i| {
            const v = std.math.cast(i32, pos[i]) orelse return error.DesktopTooLarge;
            if (axis == .x) o.x = v else o.y = v;
        }
    }
}

pub fn outputName(buf: []u8, index: usize) Error![]const u8 {
    return std.fmt.bufPrint(buf, "RDP-{d}", .{index + 1});
}

/// RDPGFX_RESET_GRAPHICS_PDU (340 bytes) for the plan.
pub fn writeResetGraphics(w: *bytes.Writer, plan: *const SessionPlan) Error!void {
    if (plan.count > max_monitors) return error.TooManyMonitors;
    try gfx.writeResetGraphics(w, plan.desktop_width, plan.desktop_height, plan.monitors[0..plan.count]);
}

/// CREATE_SURFACE (id first_surface_id + i) and MAP_SURFACE_TO_OUTPUT per output, plan order.
pub fn writeSurfaces(w: *bytes.Writer, plan: *const SessionPlan, first_surface_id: u16) Error!void {
    if (plan.count > max_monitors) return error.TooManyMonitors;
    if (@as(usize, first_surface_id) + plan.count > 0x10000) return error.NoSpaceLeft;
    for (plan.outputs[0..plan.count], 0..) |o, i| {
        const id: u16 = @intCast(first_surface_id + i);
        // planSession keeps every mode within 32766 x 32766.
        try gfx.writeCreateSurface(w, id, std.math.cast(u16, o.width) orelse return error.DesktopTooLarge, std.math.cast(u16, o.height) orelse return error.DesktopTooLarge);
        try gfx.writeMapSurfaceToOutput(w, id, o.origin_x, o.origin_y);
    }
}

fn hasOutput(current: []const hypr.MonitorState, name: []const u8) bool {
    for (current) |c| if (std.mem.eql(u8, c.name, name)) return true;
    return false;
}

/// Rules, then creation if missing (critical); unplanned RDP-n outputs removed (best effort).
pub fn planOutputCommands(arena: std.mem.Allocator, plan: *const SessionPlan, current: []const hypr.MonitorState) Error![]console.Step {
    if (plan.count > max_monitors) return error.TooManyMonitors;
    var steps: std.ArrayList(console.Step) = .empty;
    var buf: [512]u8 = undefined;
    for (plan.outputs[0..plan.count]) |*o| {
        const name = o.name();
        // The rule first: the output then appears in its final mode.
        const rule = try hypr.formatMonitorRule(&buf, name, o.width, o.height, 60, o.x, o.y, @as(f64, @floatFromInt(o.scale_k)) / 120.0, 0);
        try steps.append(arena, .{ .cmd = try arena.dupe(u8, rule), .critical = true });
        if (!hasOutput(current, name))
            try steps.append(arena, .{ .cmd = try std.fmt.allocPrint(arena, "output create headless {s}", .{name}), .critical = true });
    }
    for (current) |c| {
        if (!hypr.isRdpOutput(c.name)) continue;
        const planned = for (plan.outputs[0..plan.count]) |*o| {
            if (std.mem.eql(u8, o.name(), c.name)) break true;
        } else false;
        if (planned) continue;
        try steps.append(arena, .{ .cmd = try std.fmt.allocPrint(arena, "output remove {s}", .{c.name}), .critical = false });
    }
    return steps.toOwnedSlice(arena);
}

/// Pointer/touch outputs for rdpei.Emulator: one per monitor, layout order.
pub fn pointerOutputs(l: *const Layout, out: *[max_monitors]rdpei.Output) Error![]const rdpei.Output {
    const ms = try slice(l);
    for (ms, out[0..ms.len]) |m, *o| o.* = .{ .left = m.left, .top = m.top, .width = m.width, .height = m.height };
    return out[0..ms.len];
}

test {
    refAll(@This());
}

fn refAll(comptime T: type) void {
    inline for (comptime std.meta.declarations(T)) |name| {
        const d = @field(T, name);
        if (@TypeOf(d) == type) {
            switch (@typeInfo(d)) {
                .@"struct" => refAll(d),
                else => {},
            }
        } else _ = &d;
    }
}
