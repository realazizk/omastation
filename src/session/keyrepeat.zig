//! Client key repeats through Hyprland's bindings. A repeat is replayed as a release and a press
//! (Hyprland drops a second press of a held key), so repeats go on only when no binding matches or
//! every match is a plain repeating (binde) binding. Bindings are matched as Hyprland does.

const std = @import("std");
const c = @import("c");
const hypr = @import("hypr.zig");

/// One binding as `j/binds` lists it.
pub const Bind = struct {
    modmask: u32 = 0,
    submap: []const u8 = "",
    /// "true" or "false" (a string in `j/binds`).
    submap_universal: []const u8 = "false",
    key: []const u8 = "",
    keycode: u32 = 0,
    catch_all: bool = false,
    mouse: bool = false,
    release: bool = false,
    repeat: bool = false,
    longPress: bool = false,
    non_consuming: bool = false,
};

pub fn parseBinds(arena: std.mem.Allocator, json: []const u8) hypr.Error![]Bind {
    const J = struct {
        modmask: hypr.JsonNum(u32) = .{ .v = 0 },
        submap: hypr.JsonStr = .{},
        submap_universal: hypr.JsonStr = .{ .s = "false" },
        key: hypr.JsonStr = .{},
        keycode: hypr.JsonNum(u32) = .{ .v = 0 },
        catch_all: bool = false,
        mouse: bool = false,
        release: bool = false,
        repeat: bool = false,
        longPress: bool = false,
        non_consuming: bool = false,
    };
    const parsed = std.json.parseFromSliceLeaky([]J, arena, json, .{ .ignore_unknown_fields = true }) catch return error.BadResponse;
    const out = arena.alloc(Bind, parsed.len) catch return error.BadResponse;
    for (parsed, out) |j, *o| o.* = .{
        .modmask = j.modmask.v,
        .submap = j.submap.s,
        .submap_universal = j.submap_universal.s,
        .key = j.key.s,
        .keycode = j.keycode.v,
        .catch_all = j.catch_all,
        .mouse = j.mouse,
        .release = j.release,
        .repeat = j.repeat,
        .longPress = j.longPress,
        .non_consuming = j.non_consuming,
    };
    return out;
}

/// Current submap from `j/submap` ("default" becomes ""; bindings of no submap list "").
pub fn parseSubmap(arena: std.mem.Allocator, json: []const u8) hypr.Error![]const u8 {
    const name = (std.json.parseFromSliceLeaky(hypr.JsonStr, arena, json, .{}) catch return error.BadResponse).s;
    return if (std.mem.eql(u8, name, "default")) "" else name;
}

/// A held key as Hyprland's bindings see it.
pub const Key = struct {
    /// XKB keycode (evdev + 8): what `code:` bindings name.
    keycode: u32,
    /// First-level keysyms in the configured layout, then the client's; NoSymbol for none.
    syms: [2]u32,
    /// keyboard.State.bindMods.
    mods: u32,
};

pub fn matches(b: Bind, submap: []const u8, k: Key) bool {
    if (b.mouse or std.mem.startsWith(u8, b.key, "mouse") or std.mem.startsWith(u8, b.key, "switch:")) return false;
    if (!std.mem.eql(u8, b.submap, submap) and !std.mem.eql(u8, b.submap_universal, "true")) return false;
    if (b.modmask != k.mods) return false;
    if (b.catch_all) return true;
    if (b.keycode != 0) return b.keycode == k.keycode;
    var buf: [128]u8 = undefined;
    if (b.key.len == 0 or b.key.len >= buf.len) return false;
    @memcpy(buf[0..b.key.len], b.key);
    buf[b.key.len] = 0;
    const name: [*:0]const u8 = @ptrCast(&buf);
    const exact = c.xkb_keysym_from_name(name, c.XKB_KEYSYM_NO_FLAGS);
    const folded = c.xkb_keysym_from_name(name, c.XKB_KEYSYM_CASE_INSENSITIVE);
    for (k.syms) |s| {
        if (s == c.XKB_KEY_NoSymbol) continue;
        if (s == exact or s == folded) return true;
    }
    return false;
}

/// True when no binding fires, or only plain repeating ones (not release, long-press, non-consuming).
pub fn repeatAllowed(binds: []const Bind, submap: []const u8, k: Key) bool {
    for (binds) |b| {
        if (!matches(b, submap, k)) continue;
        if (!b.repeat or b.release or b.longPress or b.non_consuming) return false;
    }
    return true;
}

pub fn query(ipc: *const hypr.Ipc, gpa: std.mem.Allocator, k: Key) hypr.Error!bool {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const binds = try parseBinds(a, try ipc.request(a, "j/binds"));
    const submap = parseSubmap(a, try ipc.request(a, "j/submap")) catch "";
    return repeatAllowed(binds, submap, k);
}

const testing = std.testing;
const sup: u32 = 1 << 6;
const alt: u32 = 1 << 3;
const shift: u32 = 1 << 0;

fn key(keycode: u32, sym: u32, mods: u32) Key {
    return .{ .keycode = keycode, .syms = .{ sym, sym }, .mods = mods };
}

test "parseBinds reads j/binds, ignoring unknown fields" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // j/binds JSON (Hyprland 0.56).
    const json =
        \\[{"locked": true, "mouse": false, "release": false, "repeat": true, "longPress": false, "non_consuming": false, "auto_consuming": false, "has_description": true, "modmask": 0, "submap": "", "submap_universal": "false", "key": "XF86AudioRaiseVolume", "keycode": 0, "catch_all": false, "description": "Volume up", "allow_input_capture": false, "dispatcher": "__lua", "arg": "7"},
        \\{"locked": false, "mouse": false, "release": true, "repeat": false, "longPress": false, "non_consuming": false, "auto_consuming": false, "has_description": true, "modmask": 0, "submap": "", "submap_universal": "false", "key": "F9", "keycode": 0, "catch_all": false, "description": "Stop dictation", "allow_input_capture": false, "dispatcher": "__lua", "arg": "9"},
        \\{"locked": false, "mouse": true, "release": false, "repeat": false, "longPress": false, "non_consuming": false, "auto_consuming": false, "has_description": true, "modmask": 64, "submap": "", "submap_universal": "false", "key": "mouse:272", "keycode": 0, "catch_all": false, "description": "Move window", "allow_input_capture": false, "dispatcher": "__lua", "arg": "197"}]
    ;
    const binds = try parseBinds(arena.allocator(), json);
    try testing.expectEqual(@as(usize, 3), binds.len);
    try testing.expect(binds[0].repeat and !binds[0].release);
    try testing.expect(binds[1].release and !binds[1].repeat);
    try testing.expect(binds[2].mouse);
    try testing.expectEqualStrings("F9", binds[1].key);
    try testing.expectError(error.BadResponse, parseBinds(arena.allocator(), "not json"));
    try testing.expectEqualStrings("", try parseSubmap(arena.allocator(), "\"default\"\n"));
    try testing.expectEqualStrings("resize", try parseSubmap(arena.allocator(), "\"resize\"\n"));
}

test "repeats go on for keys no binding takes, and for repeating bindings only" {
    const binds = [_]Bind{
        .{ .modmask = sup, .key = "W" }, // close window
        .{ .modmask = sup, .key = "Return" },
        .{ .modmask = 0, .key = "XF86AudioRaiseVolume", .repeat = true },
        .{ .modmask = 0, .key = "XF86AudioMute" },
        .{ .modmask = 0, .key = "F9" }, // push-to-talk: start ...
        .{ .modmask = 0, .key = "F9", .release = true }, // ... and stop
        .{ .modmask = alt, .key = "SPACE" },
        .{ .modmask = sup, .key = "mouse:272", .mouse = true },
        .{ .modmask = 0, .key = "mouse_down" },
        .{ .modmask = sup | alt, .key = "code:113", .keycode = 113 },
        .{ .modmask = 0, .key = "switch:on:Lid Switch" },
    };
    // typing: no binding
    try testing.expect(repeatAllowed(&binds, "", key(38, 'a', 0)));
    try testing.expect(repeatAllowed(&binds, "", key(22, c.XKB_KEY_BackSpace, 0)));
    try testing.expect(repeatAllowed(&binds, "", key(25, 'w', shift))); // Shift+W is not SUPER+W
    try testing.expect(repeatAllowed(&binds, "", key(65, ' ', 0)));
    // SUPER + W (the key name is upper case, the keysym lower case)
    try testing.expect(!repeatAllowed(&binds, "", key(25, 'w', sup)));
    try testing.expect(!repeatAllowed(&binds, "", key(36, c.XKB_KEY_Return, sup)));
    try testing.expect(!repeatAllowed(&binds, "", key(65, ' ', alt)));
    // volume up repeats (binde); mute, push-to-talk do not
    try testing.expect(repeatAllowed(&binds, "", key(123, c.XKB_KEY_XF86AudioRaiseVolume, 0)));
    try testing.expect(!repeatAllowed(&binds, "", key(121, c.XKB_KEY_XF86AudioMute, 0)));
    try testing.expect(!repeatAllowed(&binds, "", key(75, c.XKB_KEY_F9, 0)));
    // by keycode, whatever the keysym
    try testing.expect(!repeatAllowed(&binds, "", key(113, c.XKB_KEY_Left, sup | alt)));
    try testing.expect(repeatAllowed(&binds, "", key(113, c.XKB_KEY_Left, sup)));
}

test "submaps: a binding counts in its own submap, or everywhere when universal; a catch-all takes every key there" {
    const binds = [_]Bind{
        .{ .modmask = 0, .key = "h", .submap = "resize", .repeat = true },
        .{ .modmask = 0, .key = "Escape", .submap = "resize" },
        .{ .modmask = 0, .key = "", .submap = "passthru", .catch_all = true },
        .{ .modmask = sup, .key = "q", .submap = "x", .submap_universal = "true" },
    };
    try testing.expect(repeatAllowed(&binds, "", key(9, c.XKB_KEY_Escape, 0)));
    try testing.expect(!repeatAllowed(&binds, "resize", key(9, c.XKB_KEY_Escape, 0)));
    try testing.expect(repeatAllowed(&binds, "resize", key(43, 'h', 0)));
    try testing.expect(!repeatAllowed(&binds, "passthru", key(38, 'a', 0)));
    try testing.expect(repeatAllowed(&binds, "", key(38, 'a', 0)));
    try testing.expect(!repeatAllowed(&binds, "", key(24, 'q', sup)));
}

test "the key's keysym in either layout: the configured one (Hyprland's translation) or the client's" {
    const binds = [_]Bind{.{ .modmask = sup, .key = "Q" }};
    // An AZERTY client (its 'A' key is evdev 16, US 'q'): SUPER + that key is SUPER + Q for Hyprland.
    try testing.expect(!repeatAllowed(&binds, "", .{ .keycode = 24, .syms = .{ 'q', 'a' }, .mods = sup }));
    try testing.expect(repeatAllowed(&binds, "", .{ .keycode = 38, .syms = .{ 'a', 'w' }, .mods = sup }));
    // A name that is no keysym never matches (e.g. yen, ro).
    const odd = [_]Bind{.{ .modmask = 0, .key = "nosuchkey" }};
    try testing.expect(repeatAllowed(&odd, "", .{ .keycode = 38, .syms = .{ c.XKB_KEY_NoSymbol, c.XKB_KEY_NoSymbol }, .mods = 0 }));
}
