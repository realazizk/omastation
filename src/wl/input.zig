//! Input injection: zwp_virtual_keyboard_v1 (XKB keymap via memfd, evdev keycodes) and
//! zwlr_virtual_pointer_v1 (absolute motion on one output, buttons, scroll).

const std = @import("std");
const wire = @import("wire.zig");
const sys = @import("sys.zig");
const client_mod = @import("client.zig");
const Client = client_mod.Client;
const Output = client_mod.Output;
const P = wire.proto;

pub const Error = wire.Error;

/// linux/input-event-codes.h pointer buttons.
pub const BTN_LEFT: u32 = 0x110;
pub const BTN_RIGHT: u32 = 0x111;
pub const BTN_MIDDLE: u32 = 0x112;
pub const BTN_SIDE: u32 = 0x113;
pub const BTN_EXTRA: u32 = 0x114;

/// Expanded by libxkbcommon in the compositor from system XKB data: evdev keycodes, US layout.
pub const keymap_us =
    \\xkb_keymap {
    \\    xkb_keycodes { include "evdev+aliases(qwerty)" };
    \\    xkb_types    { include "complete" };
    \\    xkb_compat   { include "complete" };
    \\    xkb_symbols  { include "pc+us+inet(evdev)" };
    \\};
    \\
;

/// Keymap text for one XKB layout/variant, written into `buf`. Names are restricted to
/// [A-Za-z0-9_-] so client input cannot inject keymap syntax.
pub fn keymapForLayout(buf: []u8, layout: []const u8, variant: []const u8) error{ InvalidArgument, NoSpaceLeft }![]const u8 {
    const ok = struct {
        fn f(s: []const u8) bool {
            for (s) |ch| if (!(std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '-')) return false;
            return true;
        }
    }.f;
    if (layout.len == 0 or !ok(layout) or !ok(variant)) return error.InvalidArgument;
    return std.fmt.bufPrint(buf,
        \\xkb_keymap {{
        \\    xkb_keycodes {{ include "evdev+aliases(qwerty)" }};
        \\    xkb_types    {{ include "complete" }};
        \\    xkb_compat   {{ include "complete" }};
        \\    xkb_symbols  {{ include "pc+{s}{s}{s}{s}+inet(evdev)" }};
        \\}};
        \\
    , .{ layout, if (variant.len > 0) "(" else "", variant, if (variant.len > 0) ")" else "" }) catch error.NoSpaceLeft;
}

pub const VirtualKeyboard = struct {
    client: *Client,
    proxy: P.ZwpVirtualKeyboardV1,
    has_keymap: bool = false,

    pub fn init(client: *Client) Error!VirtualKeyboard {
        const mgr = client.virtual_keyboard_manager orelse return error.Unsupported;
        const seat = client.seat orelse return error.Unsupported;
        return .{ .client = client, .proxy = try mgr.createVirtualKeyboard(client.conn, seat) };
    }

    pub fn deinit(vk: *VirtualKeyboard) void {
        vk.proxy.destroy(vk.client.conn) catch {};
        vk.client.conn.flush() catch {};
    }

    /// Upload an XKB (text v1) keymap. Must precede key events.
    pub fn setKeymap(vk: *VirtualKeyboard, text: []const u8) Error!void {
        const m = try sys.memfdWithText("omastation-keymap", text);
        defer sys.close(m.fd);
        try vk.proxy.keymap(vk.client.conn, .xkb_v1, m.fd, @intCast(m.size));
        try vk.client.conn.flush();
        vk.has_keymap = true;
    }

    /// `code` is a Linux evdev keycode (KEY_*), not an XKB keycode.
    pub fn key(vk: *VirtualKeyboard, code: u32, pressed: bool) Error!void {
        if (!vk.has_keymap) return error.Unsupported;
        try vk.proxy.key(vk.client.conn, sys.nowMs(), code, @intFromBool(pressed));
    }

    pub fn modifiers(vk: *VirtualKeyboard, depressed: u32, latched: u32, locked: u32, group: u32) Error!void {
        if (!vk.has_keymap) return error.Unsupported;
        try vk.proxy.modifiers(vk.client.conn, depressed, latched, locked, group);
    }
};

pub const VirtualPointer = struct {
    client: *Client,
    proxy: P.ZwlrVirtualPointerV1,

    /// With `output` (manager v2), absolute motion maps onto that output; else the whole layout.
    pub fn init(client: *Client, output: ?*Output) Error!VirtualPointer {
        const mgr = client.virtual_pointer_manager orelse return error.Unsupported;
        const conn = client.conn;
        const proxy = if (output) |o| blk: {
            if (conn.version(mgr.id) < 2) return error.Unsupported;
            break :blk try mgr.createVirtualPointerWithOutput(conn, client.seat, o.proxy);
        } else try mgr.createVirtualPointer(conn, client.seat);
        return .{ .client = client, .proxy = proxy };
    }

    pub fn deinit(vp: *VirtualPointer) void {
        vp.proxy.destroy(vp.client.conn) catch {};
        vp.client.conn.flush() catch {};
    }

    /// Position within a `width` x `height` extent spanning the bound output; follow with frame().
    pub fn motionAbsolute(vp: *VirtualPointer, x: u32, y: u32, width: u32, height: u32) Error!void {
        try vp.proxy.motionAbsolute(vp.client.conn, sys.nowMs(), @min(x, width), @min(y, height), width, height);
    }

    pub fn motion(vp: *VirtualPointer, dx: f64, dy: f64) Error!void {
        try vp.proxy.motion(vp.client.conn, sys.nowMs(), wire.Fixed.fromFloat(dx), wire.Fixed.fromFloat(dy));
    }

    pub fn button(vp: *VirtualPointer, btn: u32, pressed: bool) Error!void {
        try vp.proxy.button(vp.client.conn, sys.nowMs(), btn, if (pressed) .pressed else .released);
    }

    pub fn axis(vp: *VirtualPointer, which: P.WlPointer.Axis, value: f64) Error!void {
        try vp.proxy.axis(vp.client.conn, sys.nowMs(), which, wire.Fixed.fromFloat(value));
    }

    pub fn axisSource(vp: *VirtualPointer, source: P.WlPointer.AxisSource) Error!void {
        try vp.proxy.axisSource(vp.client.conn, source);
    }

    pub fn axisStop(vp: *VirtualPointer, which: P.WlPointer.Axis) Error!void {
        try vp.proxy.axisStop(vp.client.conn, sys.nowMs(), which);
    }

    pub fn axisDiscrete(vp: *VirtualPointer, which: P.WlPointer.Axis, value: f64, discrete: i32) Error!void {
        try vp.proxy.axisDiscrete(vp.client.conn, sys.nowMs(), which, wire.Fixed.fromFloat(value), discrete);
    }

    /// Rotation in 1/120 notch (WHEEL_DELTA units, positive down/right): whole notches as
    /// discrete steps, fractions as smooth motion. Follow with frame().
    pub fn wheel(vp: *VirtualPointer, which: P.WlPointer.Axis, value120: i32) Error!void {
        if (value120 == 0) return;
        try vp.axisSource(.wheel);
        // 15 units per notch, as libinput reports wheel clicks.
        const value = @as(f64, @floatFromInt(value120)) * 15.0 / 120.0;
        if (@rem(value120, 120) == 0) {
            try vp.axisDiscrete(which, value, @divTrunc(value120, 120));
        } else {
            try vp.axis(which, value);
        }
    }

    pub fn frame(vp: *VirtualPointer) Error!void {
        try vp.proxy.frame(vp.client.conn);
    }
};

test "keymap for layout" {
    var buf: [512]u8 = undefined;
    const km = try keymapForLayout(&buf, "de", "nodeadkeys");
    try std.testing.expect(std.mem.indexOf(u8, km, "pc+de(nodeadkeys)+inet(evdev)") != null);
    const km2 = try keymapForLayout(&buf, "us", "");
    try std.testing.expect(std.mem.indexOf(u8, km2, "pc+us+inet(evdev)") != null);
    try std.testing.expectError(error.InvalidArgument, keymapForLayout(&buf, "us\" }; evil", ""));
    try std.testing.expectError(error.InvalidArgument, keymapForLayout(&buf, "", ""));
}
