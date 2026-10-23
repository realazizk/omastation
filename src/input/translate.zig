//! RDP input to Linux input: set-1 scancodes (MS-RDPBCGR 2.2.8.1.2.2.1) become evdev
//! keycodes for a keyboard with the session's XKB keymap, as clients send key positions,
//! not characters. Pointer buttons become BTN_*, wheel deltas value120 units.

const std = @import("std");
const fastpath = @import("../proto/fastpath.zig");

// evdev codes named explicitly (linux/input-event-codes.h).
pub const KEY_RESERVED: u16 = 0;
pub const KEY_102ND: u16 = 86;
pub const KEY_F11: u16 = 87;
pub const KEY_F12: u16 = 88;
pub const KEY_RO: u16 = 89;
pub const KEY_KATAKANAHIRAGANA: u16 = 93;
pub const KEY_HENKAN: u16 = 92;
pub const KEY_MUHENKAN: u16 = 94;
pub const KEY_KPJPCOMMA: u16 = 95;
pub const KEY_KPENTER: u16 = 96;
pub const KEY_RIGHTCTRL: u16 = 97;
pub const KEY_KPSLASH: u16 = 98;
pub const KEY_SYSRQ: u16 = 99;
pub const KEY_RIGHTALT: u16 = 100;
pub const KEY_HOME: u16 = 102;
pub const KEY_UP: u16 = 103;
pub const KEY_PAGEUP: u16 = 104;
pub const KEY_LEFT: u16 = 105;
pub const KEY_RIGHT: u16 = 106;
pub const KEY_END: u16 = 107;
pub const KEY_DOWN: u16 = 108;
pub const KEY_PAGEDOWN: u16 = 109;
pub const KEY_INSERT: u16 = 110;
pub const KEY_DELETE: u16 = 111;
pub const KEY_MUTE: u16 = 113;
pub const KEY_VOLUMEDOWN: u16 = 114;
pub const KEY_VOLUMEUP: u16 = 115;
pub const KEY_POWER: u16 = 116;
pub const KEY_KPEQUAL: u16 = 117;
pub const KEY_PAUSE: u16 = 119;
pub const KEY_KPCOMMA: u16 = 121;
pub const KEY_HANGEUL: u16 = 122;
pub const KEY_HANJA: u16 = 123;
pub const KEY_YEN: u16 = 124;
pub const KEY_LEFTMETA: u16 = 125;
pub const KEY_RIGHTMETA: u16 = 126;
pub const KEY_COMPOSE: u16 = 127;
pub const KEY_STOP: u16 = 128;
pub const KEY_CALC: u16 = 140;
pub const KEY_SLEEP: u16 = 142;
pub const KEY_WAKEUP: u16 = 143;
pub const KEY_MAIL: u16 = 155;
pub const KEY_BOOKMARKS: u16 = 156;
pub const KEY_COMPUTER: u16 = 157;
pub const KEY_BACK: u16 = 158;
pub const KEY_FORWARD: u16 = 159;
pub const KEY_NEXTSONG: u16 = 163;
pub const KEY_PLAYPAUSE: u16 = 164;
pub const KEY_PREVIOUSSONG: u16 = 165;
pub const KEY_STOPCD: u16 = 166;
pub const KEY_HOMEPAGE: u16 = 172;
pub const KEY_REFRESH: u16 = 173;
pub const KEY_F13: u16 = 183;
pub const KEY_SEARCH: u16 = 217;
pub const KEY_MEDIA: u16 = 226;

/// Set-1 scancode → evdev: 0x01..0x58 map 1:1, the rest follows the Linux atkbd table.
pub fn scancodeToEvdev(code: u8, extended: bool) u16 {
    if (!extended) {
        return switch (code) {
            // Alt+Print Screen; evdev 84 would be <LVL3> (AltGr).
            0x54 => KEY_SYSRQ,
            0x01...0x53, 0x55...0x58 => code,
            0x59 => KEY_KPEQUAL,
            0x64...0x6E => KEY_F13 + (code - 0x64), // F13..F23
            0x70 => KEY_KATAKANAHIRAGANA,
            0x71 => KEY_HANJA,
            0x72 => KEY_HANGEUL,
            0x73 => KEY_RO,
            0x76 => KEY_F13 + 11, // F24
            0x79 => KEY_HENKAN,
            0x7B => KEY_MUHENKAN,
            0x7D => KEY_YEN,
            0x7E => KEY_KPCOMMA, // VK_ABNT_C2, HID Keypad Comma (atkbd, hid-input)
            else => KEY_RESERVED,
        };
    }
    return switch (code) {
        0x10 => KEY_PREVIOUSSONG,
        0x19 => KEY_NEXTSONG,
        0x1C => KEY_KPENTER,
        0x1D => KEY_RIGHTCTRL,
        0x20 => KEY_MUTE,
        0x21 => KEY_CALC, // VK_LAUNCH_APP2 (HID AL Calculator)
        0x22 => KEY_PLAYPAUSE,
        0x24 => KEY_STOPCD,
        0x2E => KEY_VOLUMEDOWN,
        0x30 => KEY_VOLUMEUP,
        0x32 => KEY_HOMEPAGE,
        0x35 => KEY_KPSLASH,
        0x37 => KEY_SYSRQ,
        0x38 => KEY_RIGHTALT,
        0x46 => KEY_PAUSE, // Ctrl+Break
        0x47 => KEY_HOME,
        0x48 => KEY_UP,
        0x49 => KEY_PAGEUP,
        0x4B => KEY_LEFT,
        0x4D => KEY_RIGHT,
        0x4F => KEY_END,
        0x50 => KEY_DOWN,
        0x51 => KEY_PAGEDOWN,
        0x52 => KEY_INSERT,
        0x53 => KEY_DELETE,
        0x5B => KEY_LEFTMETA,
        0x5C => KEY_RIGHTMETA,
        0x5D => KEY_COMPOSE,
        0x5E => KEY_POWER,
        0x5F => KEY_SLEEP,
        0x63 => KEY_WAKEUP,
        0x65 => KEY_SEARCH,
        0x66 => KEY_BOOKMARKS,
        0x67 => KEY_REFRESH,
        0x68 => KEY_STOP,
        0x69 => KEY_FORWARD,
        0x6A => KEY_BACK,
        0x6B => KEY_COMPUTER,
        0x6C => KEY_MAIL,
        0x6D => KEY_MEDIA,
        else => KEY_RESERVED,
    };
}

pub const KeyEvent = struct { evdev: u16, pressed: bool };

/// Windows clients send Pause as E1 0x1D then 0x45; the trailing 0x45 is dropped.
/// E1 is only used for Pause (MS-RDPBCGR 2.2.8.1.2.2.1).
pub const KeyDecoder = struct {
    after_e1: bool = false,

    pub fn decode(d: *KeyDecoder, code: u8, flags: u8) ?KeyEvent {
        const pressed = flags & fastpath.kbd_release == 0;
        if (flags & fastpath.kbd_extended1 != 0) {
            d.after_e1 = code == 0x1D;
            if (code != 0x1D) return null;
            return .{ .evdev = KEY_PAUSE, .pressed = pressed };
        }
        if (d.after_e1 and code == 0x45) {
            d.after_e1 = false;
            return null;
        }
        d.after_e1 = false;
        const ev = scancodeToEvdev(code, flags & fastpath.kbd_extended != 0);
        if (ev == KEY_RESERVED) return null;
        return .{ .evdev = ev, .pressed = pressed };
    }
};

pub const BTN_LEFT: u32 = 0x110;
pub const BTN_RIGHT: u32 = 0x111;
pub const BTN_MIDDLE: u32 = 0x112;
pub const BTN_SIDE: u32 = 0x113;
pub const BTN_EXTRA: u32 = 0x114;

pub const PointerEvent = union(enum) {
    motion: struct { x: u16, y: u16 },
    /// Relative motion in client pixels (TS_RELPOINTER_EVENT).
    motion_rel: struct { dx: i16, dy: i16 },
    button: struct { button: u32, pressed: bool },
    /// 120 = one notch; vertical positive = down (Wayland), horizontal positive = right.
    axis: struct { vertical: bool, value120: i32 },
};

/// TS_POINTER_EVENT (or MOUSEX): a motion plus at most one button, or one axis event.
pub fn pointerEvents(flags: u16, x: u16, y: u16, extended: bool, out: *[2]PointerEvent) []PointerEvent {
    var n: usize = 0;
    if (extended) {
        out[n] = .{ .motion = .{ .x = x, .y = y } };
        n += 1;
        const pressed = flags & fastpath.ptrx_down != 0;
        if (flags & fastpath.ptrx_button1 != 0) {
            out[n] = .{ .button = .{ .button = BTN_SIDE, .pressed = pressed } };
            n += 1;
        } else if (flags & fastpath.ptrx_button2 != 0) {
            out[n] = .{ .button = .{ .button = BTN_EXTRA, .pressed = pressed } };
            n += 1;
        }
        return out[0..n];
    }
    if (flags & (fastpath.ptr_wheel | fastpath.ptr_hwheel) != 0) {
        // Wheel events carry no meaningful position.
        const d = fastpath.wheelDelta(flags);
        if (flags & fastpath.ptr_wheel != 0) {
            // Windows: positive = away from the user (scroll up); Wayland: negative = up.
            out[n] = .{ .axis = .{ .vertical = true, .value120 = -@as(i32, d) } };
        } else {
            out[n] = .{ .axis = .{ .vertical = false, .value120 = d } };
        }
        n += 1;
        return out[0..n];
    }
    out[n] = .{ .motion = .{ .x = x, .y = y } };
    n += 1;
    const pressed = flags & fastpath.ptr_down != 0;
    if (flags & fastpath.ptr_button1 != 0) {
        out[n] = .{ .button = .{ .button = BTN_LEFT, .pressed = pressed } };
        n += 1;
    } else if (flags & fastpath.ptr_button2 != 0) {
        out[n] = .{ .button = .{ .button = BTN_RIGHT, .pressed = pressed } };
        n += 1;
    } else if (flags & fastpath.ptr_button3 != 0) {
        out[n] = .{ .button = .{ .button = BTN_MIDDLE, .pressed = pressed } };
        n += 1;
    }
    return out[0..n];
}

/// TS_RELPOINTER_EVENT (MS-RDPBCGR 2.2.8.1.1.3.1.1.7): a press happens at the position
/// after the deltas, so the motion comes first.
pub fn relPointerEvents(flags: u16, dx: i16, dy: i16, out: *[2]PointerEvent) []PointerEvent {
    var n: usize = 0;
    if (flags & fastpath.ptr_move != 0 or dx != 0 or dy != 0) {
        out[n] = .{ .motion_rel = .{ .dx = dx, .dy = dy } };
        n += 1;
    }
    const pressed = flags & fastpath.ptr_down != 0;
    const btn: ?u32 = if (flags & fastpath.ptr_button1 != 0)
        BTN_LEFT
    else if (flags & fastpath.ptr_button2 != 0)
        BTN_RIGHT
    else if (flags & fastpath.ptr_button3 != 0)
        BTN_MIDDLE
    else if (flags & fastpath.ptrx_button1 != 0)
        BTN_SIDE
    else if (flags & fastpath.ptrx_button2 != 0)
        BTN_EXTRA
    else
        null;
    if (btn) |b| {
        out[n] = .{ .button = .{ .button = b, .pressed = pressed } };
        n += 1;
    }
    return out[0..n];
}

/// SYNC lock state as XKB locked modifiers. Mod3 = ScrollLock is not universal, so
/// only Caps (Lock) and NumLock (Mod2) apply.
pub fn lockedMods(sync_flags: u8) u32 {
    var m: u32 = 0;
    if (sync_flags & fastpath.sync_caps_lock != 0) m |= 1 << 1; // Lock
    if (sync_flags & fastpath.sync_num_lock != 0) m |= 1 << 4; // Mod2
    return m;
}

test "scancode mapping basics" {
    try std.testing.expectEqual(@as(u16, 30), scancodeToEvdev(0x1E, false)); // A
    try std.testing.expectEqual(@as(u16, 1), scancodeToEvdev(0x01, false)); // Esc
    try std.testing.expectEqual(KEY_F12, scancodeToEvdev(0x58, false));
    try std.testing.expectEqual(KEY_102ND, scancodeToEvdev(0x56, false)); // ISO <> key (AZERTY/QWERTZ)
    try std.testing.expectEqual(KEY_RIGHTALT, scancodeToEvdev(0x38, true)); // AltGr
    try std.testing.expectEqual(KEY_LEFTMETA, scancodeToEvdev(0x5B, true)); // Windows/Super
    try std.testing.expectEqual(KEY_KPENTER, scancodeToEvdev(0x1C, true));
    try std.testing.expectEqual(@as(u16, 28), scancodeToEvdev(0x1C, false)); // Enter
    try std.testing.expectEqual(KEY_DELETE, scancodeToEvdev(0x53, true));
    try std.testing.expectEqual(@as(u16, 83), scancodeToEvdev(0x53, false)); // KP .
    try std.testing.expectEqual(KEY_RESERVED, scancodeToEvdev(0x7F, true));
}

test "extended release event decodes to a key release" {
    var d = KeyDecoder{};
    const ev = d.decode(0x38, fastpath.kbd_release | fastpath.kbd_extended).?;
    try std.testing.expectEqual(KEY_RIGHTALT, ev.evdev);
    try std.testing.expect(!ev.pressed);
}

test "pause key sequence" {
    var d = KeyDecoder{};
    const p = d.decode(0x1D, fastpath.kbd_extended1).?;
    try std.testing.expectEqual(KEY_PAUSE, p.evdev);
    try std.testing.expect(p.pressed);
    try std.testing.expect(d.decode(0x45, 0) == null);
    try std.testing.expectEqual(@as(u16, 69), d.decode(0x45, 0).?.evdev);
}

test "pointer translation" {
    var buf: [2]PointerEvent = undefined;
    const down = pointerEvents(fastpath.ptr_button1 | fastpath.ptr_down, 10, 20, false, &buf);
    try std.testing.expectEqual(@as(usize, 2), down.len);
    try std.testing.expectEqual(@as(u16, 20), down[0].motion.y);
    try std.testing.expectEqual(BTN_LEFT, down[1].button.button);
    try std.testing.expect(down[1].button.pressed);

    const wheel_up = pointerEvents(fastpath.ptr_wheel | 0x78, 0, 0, false, &buf);
    try std.testing.expectEqual(@as(i32, -120), wheel_up[0].axis.value120);
    const wheel_down = pointerEvents(fastpath.ptr_wheel | fastpath.ptr_wheel_negative | 0x88, 0, 0, false, &buf);
    try std.testing.expectEqual(@as(i32, 120), wheel_down[0].axis.value120);

    const back = pointerEvents(fastpath.ptrx_button1 | fastpath.ptrx_down, 5, 5, true, &buf);
    try std.testing.expectEqual(BTN_SIDE, back[1].button.button);

    const move = pointerEvents(fastpath.ptr_move, 300, 400, false, &buf);
    try std.testing.expectEqual(@as(usize, 1), move.len);
}

test "relative pointer translation" {
    var buf: [2]PointerEvent = undefined;
    const mv = relPointerEvents(fastpath.ptr_move, 5, -3, &buf);
    try std.testing.expectEqual(@as(usize, 1), mv.len);
    try std.testing.expectEqual(@as(i16, -3), mv[0].motion_rel.dy);
    const press = relPointerEvents(fastpath.ptr_down | fastpath.ptr_button3, 0, 0, &buf);
    try std.testing.expectEqual(@as(usize, 1), press.len);
    try std.testing.expectEqual(BTN_MIDDLE, press[0].button.button);
    try std.testing.expect(press[0].button.pressed);
    const back = relPointerEvents(fastpath.ptrx_button1, 2, 0, &buf);
    try std.testing.expectEqual(@as(usize, 2), back.len);
    try std.testing.expectEqual(BTN_SIDE, back[1].button.button);
    try std.testing.expect(!back[1].button.pressed);
}

test "lock key sync" {
    try std.testing.expectEqual(@as(u32, 0b10010), lockedMods(fastpath.sync_caps_lock | fastpath.sync_num_lock));
    try std.testing.expectEqual(@as(u32, 0), lockedMods(fastpath.sync_scroll_lock));
}
