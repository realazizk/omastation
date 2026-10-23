//! Input fence: which physical input devices are grabbed (EVIOCGRAB) for the remote session
//! and which presses mean someone is at the desk, decided from sysfs capability bitmaps.
//! Power/sleep buttons, lid and jack switches and the PC speaker are left alone.

const std = @import("std");

pub const EV_SYN: u5 = 0x00;
pub const EV_KEY: u5 = 0x01;
pub const EV_REL: u5 = 0x02;
pub const EV_ABS: u5 = 0x03;
pub const EV_SW: u5 = 0x05;

const KEY_Q: u16 = 16;
const KEY_A: u16 = 30;
const KEY_Z: u16 = 44;
const KEY_SPACE: u16 = 57;
const BTN_LEFT: u16 = 0x110;
const BTN_TOUCH: u16 = 0x14a;
const BTN_TOOL_PEN: u16 = 0x140;
const BTN_TOOL_FINGER: u16 = 0x145;
const REL_X: u16 = 0;
const REL_Y: u16 = 1;
const ABS_X: u16 = 0;
const ABS_Y: u16 = 1;
const ABS_MT_POSITION_X: u16 = 0x35;

pub const max_key_bits = 768;

/// Capability bitmaps as exposed under /sys/class/input/eventN/device/capabilities.
pub const Caps = struct {
    ev: u64 = 0,
    key: std.StaticBitSet(max_key_bits) = .empty,
    rel: u64 = 0,
    abs: u64 = 0,

    fn hasKey(c: *const Caps, k: u16) bool {
        return k < max_key_bits and c.key.isSet(k);
    }
};

pub const Kind = enum { keyboard, pointer, touch, other };

pub fn classify(c: *const Caps) Kind {
    const has_key = c.ev & (@as(u64, 1) << EV_KEY) != 0;
    const has_rel = c.ev & (@as(u64, 1) << EV_REL) != 0;
    const has_abs = c.ev & (@as(u64, 1) << EV_ABS) != 0;
    if (has_rel and c.rel & 0b11 == 0b11 and c.hasKey(BTN_LEFT)) return .pointer;
    if (has_abs and c.abs & 0b11 == 0b11 and (c.hasKey(BTN_TOUCH) or c.hasKey(BTN_TOOL_FINGER) or c.hasKey(BTN_TOOL_PEN) or c.hasKey(BTN_LEFT)))
        return .touch;
    if (has_abs and c.abs & (@as(u64, 1) << ABS_MT_POSITION_X) != 0) return .touch;
    if (has_key and c.hasKey(KEY_Q) and c.hasKey(KEY_A) and c.hasKey(KEY_Z) and c.hasKey(KEY_SPACE)) return .keyboard;
    return .other;
}

/// Keys left with logind/the desk while fenced: power management only.
const exempt_keys = [_]u16{ 116, 142, 143, 205, 0x164, 0x198 }; // POWER, SLEEP, WAKEUP, SUSPEND, POWER2, RESTART

/// Media-key and headset-button nodes are fenced too: they can fire desktop key bindings.
pub fn shouldFence(c: *const Caps) bool {
    const has_rel = c.ev & (@as(u64, 1) << EV_REL) != 0 and c.rel & 0b11 != 0;
    const has_abs = c.ev & (@as(u64, 1) << EV_ABS) != 0 and c.abs & 0b11 == 0b11;
    if (has_rel or has_abs) return true;
    if (c.ev & (@as(u64, 1) << EV_KEY) == 0) return false;
    var it = c.key.iterator(.{});
    while (it.next()) |k| {
        if (std.mem.indexOfScalar(u16, &exempt_keys, @intCast(k)) == null) return true;
    }
    return false;
}

/// Only keyboards, pointers and touch devices: a Bluetooth headset sends AVRCP events on its own.
pub fn signalsPresence(c: *const Caps) bool {
    return classify(c) != .other;
}

/// Sysfs bitmap: hex words of a kernel `long`, most significant first. Returns the word count.
pub fn parseBitmapWords(text: []const u8, out: []u64) !usize {
    var words: [16]u64 = undefined;
    var n: usize = 0;
    var it = std.mem.tokenizeAny(u8, text, " \n");
    while (it.next()) |tok| {
        if (n == words.len) return error.BitmapTooLong;
        words[n] = std.fmt.parseInt(u64, tok, 16) catch return error.BadBitmap;
        n += 1;
    }
    const m = @min(n, out.len);
    for (0..m) |i| out[i] = words[n - 1 - i];
    for (m..out.len) |i| out[i] = 0;
    return n;
}

pub fn capsFromSysfs(ev: []const u8, key: []const u8, rel: []const u8, abs: []const u8) !Caps {
    var c = Caps{};
    var w: [12]u64 = undefined;
    _ = try parseBitmapWords(ev, w[0..1]);
    c.ev = w[0];
    _ = try parseBitmapWords(rel, w[0..1]);
    c.rel = w[0];
    _ = try parseBitmapWords(abs, w[0..1]);
    c.abs = w[0];
    _ = try parseBitmapWords(key, w[0..12]);
    for (0..12) |wi| {
        var word = w[wi];
        while (word != 0) {
            const b: u6 = @intCast(@ctz(word));
            const bit = wi * 64 + b;
            if (bit < max_key_bits) c.key.set(bit);
            word &= word - 1;
        }
    }
    return c;
}

/// EVIOCGRAB = _IOW('E', 0x90, int).
pub const EVIOCGRAB: u32 = 0x40044590;

/// N from "inputN" or a sysfs link to it ("../../input42" -> 42). The helper's uinput devices
/// are excluded by this number, never by name: a USB device can call itself anything.
pub fn inputNumber(link: []const u8) ?u32 {
    const base = if (std.mem.lastIndexOfScalar(u8, link, '/')) |i| link[i + 1 ..] else link;
    if (!std.mem.startsWith(u8, base, "input")) return null;
    const digits = base["input".len..];
    if (digits.len == 0 or digits.len > 9) return null;
    for (digits) |ch| if (ch < '0' or ch > '9') return null;
    if (digits.len > 1 and digits[0] == '0') return null;
    return std.fmt.parseInt(u32, digits, 10) catch null;
}

fn fullKeyboardKeyBitmap() []const u8 {
    // A typical full keyboard: bits 1..127 set plus media keys.
    return "1f 3ff 0 0 0 0 483ffff17aff32d bfd4444600000000 1 130ff38b17c007 ffff7ffffe7bfffe fffffffffffffffe";
}

test "power and sleep buttons are left alone" {
    // power is bit 116, sleep bit 142.
    const power = try capsFromSysfs("3", "10000000000000 0", "0", "0");
    try std.testing.expectEqual(Kind.other, classify(&power));
    const sleep = try capsFromSysfs("3", "4000 0 0", "0", "0");
    try std.testing.expectEqual(Kind.other, classify(&sleep));
    try std.testing.expect(!shouldFence(&power));
    try std.testing.expect(!shouldFence(&sleep));
}

test "audio jack, pc speaker, headset media buttons are left alone" {
    const jack = try capsFromSysfs("21", "0", "0", "0"); // EV_SYN|EV_SW
    try std.testing.expect(!shouldFence(&jack));
    const speaker = try capsFromSysfs("40001", "0", "0", "0");
    try std.testing.expect(!shouldFence(&speaker));
    // Headset AVRCP buttons are fenced: media keys can fire desktop key bindings.
    const avrcp = try capsFromSysfs("3", "68 0 0 0 0 0 0 0", "0", "0");
    try std.testing.expect(shouldFence(&avrcp));
}

test "keyboards and mice are fenced" {
    const kbd = try capsFromSysfs("12001f", fullKeyboardKeyBitmap(), "1040", "100000000");
    try std.testing.expectEqual(Kind.keyboard, classify(&kbd));
    // A mouse: ev=120017, rel=1943, buttons 0x110..0x117 set.
    const mouse = try capsFromSysfs("120017", "ffff0000 0 0 0 0", "1943", "0");
    try std.testing.expectEqual(Kind.pointer, classify(&mouse));
    // Absolute pointer / tablet-like device: ABS_X|ABS_Y with BTN_LEFT.
    const absptr = try capsFromSysfs("1b", "1f0000 0 0 0 0", "0", "3f");
    try std.testing.expectEqual(Kind.touch, classify(&absptr));
}

test "bitmap parsing order" {
    var out: [3]u64 = undefined;
    const n = try parseBitmapWords("1 2 3\n", &out);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u64, 3), out[0]);
    try std.testing.expectEqual(@as(u64, 1), out[2]);
    try std.testing.expectError(error.BadBitmap, parseBitmapWords("zz", &out));
}
