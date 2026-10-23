//! Hyprland device rules for omastation's virtual keyboards: key bindings off
//! for the text keyboards, and key repeat driven by the client only.

const std = @import("std");
const hypr = @import("hypr.zig");
const keyboard = @import("../input/keyboard.zig");

const log = std.log.scoped(.textbinds);

/// At most two text keyboards (used in turn), plus room.
pub const max_names = 4;

const Devices = struct { keyboards: []const struct { name: hypr.JsonStr = .{}, active_keymap: hypr.JsonStr = .{} } = &.{} };
const Kb = struct { name: []const u8, active_keymap: []const u8 };

/// Virtual keyboards are named after their process, so only `active_keymap` identifies text ones.
pub fn parseTextKeyboards(arena: std.mem.Allocator, json: []const u8) hypr.Error![]const []const u8 {
    const parsed = std.json.parseFromSliceLeaky(Devices, arena, json, .{ .ignore_unknown_fields = true }) catch return error.BadResponse;
    var out: std.ArrayList([]const u8) = .empty;
    for (parsed.keyboards) |kb| {
        const k: Kb = .{ .name = kb.name.s, .active_keymap = kb.active_keymap.s };
        if (std.mem.eql(u8, k.active_keymap, keyboard.TextKeymap.layout_name)) try out.append(arena, k.name);
    }
    return out.toOwnedSlice(arena);
}

pub fn formatRuleOff(buf: []u8, name: []const u8) error{NoSpaceLeft}![]const u8 {
    var q: [160]u8 = undefined;
    return std.fmt.bufPrint(buf, "eval hl.device({{ name = {s}, keybinds = false, repeat_rate = 0 }})", .{try hypr.luaString(&q, name)});
}

/// Restores bindings and the configured `input:repeat_rate` and `input:repeat_delay`.
pub fn formatRuleOn(buf: []u8, name: []const u8, repeat: Repeat) error{NoSpaceLeft}![]const u8 {
    var q: [160]u8 = undefined;
    return std.fmt.bufPrint(buf, "eval hl.device({{ name = {s}, keybinds = true, repeat_rate = {d}, repeat_delay = {d} }})", .{ try hypr.luaString(&q, name), repeat.rate, repeat.delay });
}

pub const Repeat = struct { rate: i64, delay: i64 };

/// `input:repeat_rate` and `input:repeat_delay`, or Hyprland's defaults when unreadable.
fn globalRepeat(ipc: *const hypr.Ipc, gpa: std.mem.Allocator) Repeat {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    return .{
        .rate = hypr.getOptionInt(ipc, arena.allocator(), "input:repeat_rate") catch 25,
        .delay = hypr.getOptionInt(ipc, arena.allocator(), "input:repeat_delay") catch 600,
    };
}

/// Hyprland matches bindings through the configured layout, not the sending keyboard's keymap,
/// so a text key could fire any binding. A config reload drops run-time device rules.
pub const State = struct {
    names: [max_names][96]u8 = undefined,
    lens: [max_names]u8 = @splat(0),
    count: u8 = 0,
    /// The rules are in force for every text keyboard since the last reload.
    applied: bool = false,
    warned: bool = false,
    /// Earliest retry after a failure (ms, CLOCK_MONOTONIC), so a stuck Hyprland does not stall typing.
    retry_ms: i64 = 0,

    pub fn name(s: *const State, i: usize) []const u8 {
        return s.names[i][0..s.lens[i]];
    }

    /// After a new text keyboard or a config reload.
    pub fn invalidate(s: *State) void {
        s.applied = false;
    }

    pub fn due(s: *const State, now_ms: i64) bool {
        return !s.applied and now_ms >= s.retry_ms;
    }

    pub const retry_interval_ms = 2000;

    pub fn failedAt(s: *State, now_ms: i64) void {
        s.retry_ms = now_ms + retry_interval_ms;
    }

    /// False when a text keyboard is missing or a rule is refused; text then uses ordinary keys only.
    pub fn ensure(s: *State, ipc: *const hypr.Ipc, gpa: std.mem.Allocator, want: usize) bool {
        if (s.applied) return true;
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const json = ipc.request(a, "j/devices") catch |err| return s.fail("cannot list Hyprland's devices", err);
        const found = parseTextKeyboards(a, json) catch |err| return s.fail("cannot read Hyprland's device list", err);
        for (found) |n| {
            var buf: [256]u8 = undefined;
            const cmd = formatRuleOff(&buf, n) catch continue;
            ipc.command(gpa, cmd) catch |err| return s.fail("Hyprland refused the keybinds rule", err);
            s.record(n);
        }
        // Rules apply from an idle callback; the next request is read after it.
        if (ipc.request(a, "j/devices")) |_| {} else |err| return s.fail("Hyprland did not answer after the keybinds rule", err);
        if (found.len < want) {
            if (!s.warned) log.warn("{d} of {d} text keyboard(s) in Hyprland's device list: key bindings may see text typed through the others", .{ found.len, want });
            s.warned = true;
            return false;
        }
        s.applied = true;
        log.debug("key bindings off for {d} text keyboard(s)", .{found.len});
        return true;
    }

    fn fail(s: *State, what: []const u8, err: anyerror) bool {
        if (!s.warned) log.warn("{s} ({t}): key bindings may see text typed through omastation's text keyboard (it uses ordinary keys only)", .{ what, err });
        s.warned = true;
        return false;
    }

    fn record(s: *State, n: []const u8) void {
        for (0..s.count) |i| if (std.mem.eql(u8, s.name(i), n)) return;
        if (s.count == max_names or n.len > s.names[0].len) return;
        @memcpy(s.names[s.count][0..n.len], n);
        s.lens[s.count] = @intCast(n.len);
        s.count += 1;
    }

    /// Restores bindings and repeat on the recorded names, which Hyprland reuses for the next keyboards.
    pub fn release(s: *State, ipc: *const hypr.Ipc, gpa: std.mem.Allocator) void {
        if (s.count == 0) {
            s.applied = false;
            return;
        }
        const repeat = globalRepeat(ipc, gpa);
        for (0..s.count) |i| {
            var buf: [256]u8 = undefined;
            const cmd = formatRuleOn(&buf, s.name(i), repeat) catch continue;
            ipc.command(gpa, cmd) catch {};
        }
        s.count = 0;
        s.applied = false;
    }
};

/// Hyprland's longest repeat delay (`repeat_delay`: 0 .. 2000 ms).
pub const repeat_delay_ms = 2000;

/// Never a rate of 0 unless configured: Hyprland 0.56 divides by the rate for a repeating binding.
pub fn sessionRepeat(configured: Repeat) Repeat {
    return .{ .rate = @min(configured.rate, 1), .delay = repeat_delay_ms };
}

/// Every virtual keyboard but the text ones: the main keyboard and an input method's.
pub fn parseRepeatKeyboards(arena: std.mem.Allocator, json: []const u8) hypr.Error![]const []const u8 {
    const parsed = std.json.parseFromSliceLeaky(Devices, arena, json, .{ .ignore_unknown_fields = true }) catch return error.BadResponse;
    var out: std.ArrayList([]const u8) = .empty;
    for (parsed.keyboards) |kb| {
        const k: Kb = .{ .name = kb.name.s, .active_keymap = kb.active_keymap.s };
        if (!std.mem.startsWith(u8, k.name, "hl-virtual-keyboard")) continue;
        if (std.mem.eql(u8, k.active_keymap, keyboard.TextKeymap.layout_name)) continue;
        try out.append(arena, k.name);
    }
    return out.toOwnedSlice(arena);
}

pub fn formatRepeatRule(buf: []u8, name: []const u8, repeat: Repeat) error{NoSpaceLeft}![]const u8 {
    var q: [160]u8 = undefined;
    return std.fmt.bufPrint(buf, "eval hl.device({{ name = {s}, repeat_rate = {d}, repeat_delay = {d} }})", .{ try hypr.luaString(&q, name), repeat.rate, repeat.delay });
}

/// Chromium, Electron and Xwayland ignore the keymap's no-repeat and use the settings Hyprland
/// announces; the client's repeats keep restarting the long delay.
pub const RepeatRules = struct {
    names: Names = .{},
    /// In force for every virtual keyboard since the last config reload.
    applied: bool = false,
    warned: bool = false,
    retry_ms: i64 = 0,

    pub fn invalidate(s: *RepeatRules) void {
        s.applied = false;
    }

    pub fn due(s: *const RepeatRules, now_ms: i64) bool {
        return !s.applied and now_ms >= s.retry_ms;
    }

    pub fn failedAt(s: *RepeatRules, now_ms: i64) void {
        s.retry_ms = now_ms + State.retry_interval_ms;
    }

    /// False (logged once) when Hyprland does not answer or lists no virtual keyboard yet.
    pub fn ensure(s: *RepeatRules, ipc: *const hypr.Ipc, gpa: std.mem.Allocator) bool {
        if (s.applied) return true;
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const json = ipc.request(a, "j/devices") catch |err| return s.fail("cannot list Hyprland's devices", err);
        const found = parseRepeatKeyboards(a, json) catch |err| return s.fail("cannot read Hyprland's device list", err);
        if (found.len == 0) return s.fail("no virtual keyboard in Hyprland's device list", error.BadResponse);
        const repeat = sessionRepeat(globalRepeat(ipc, gpa));
        for (found) |n| {
            var buf: [256]u8 = undefined;
            const cmd = formatRepeatRule(&buf, n, repeat) catch continue;
            ipc.command(gpa, cmd) catch |err| return s.fail("Hyprland refused the repeat rule", err);
            s.names.record(n);
        }
        // Applied from an idle callback after that request.
        if (ipc.request(a, "j/devices")) |_| {} else |err| return s.fail("Hyprland did not answer after the repeat rule", err);
        s.applied = true;
        log.debug("key repeat from the client only on {d} virtual keyboard(s)", .{found.len});
        return true;
    }

    fn fail(s: *RepeatRules, what: []const u8, err: anyerror) bool {
        if (!s.warned) log.warn("{s} ({t}): applications may repeat a key whose release comes late", .{ what, err });
        s.warned = true;
        return false;
    }

    /// Whether an `activelayout` event ("NAME,LAYOUT") names a virtual keyboard without the session's
    /// settings, e.g. fcitx5's. Hyprland announces repeat settings at a keyboard's first key.
    pub fn isNewKeyboard(s: *const RepeatRules, data: []const u8) bool {
        const comma = std.mem.indexOfScalar(u8, data, ',') orelse return false;
        const name = data[0..comma];
        if (!std.mem.startsWith(u8, name, "hl-virtual-keyboard")) return false;
        // The main keyboard is set up already; a text one announces itself before its keymap.
        if (std.mem.startsWith(u8, name, own_names_base)) return false;
        if (std.mem.eql(u8, data[comma + 1 ..], keyboard.TextKeymap.layout_name)) return false;
        for (0..s.names.count) |i| if (std.mem.eql(u8, s.names.name(i), name)) return false;
        return true;
    }

    pub fn release(s: *RepeatRules, ipc: *const hypr.Ipc, gpa: std.mem.Allocator) void {
        s.applied = false;
        if (s.names.count == 0) return;
        const repeat = globalRepeat(ipc, gpa);
        for (0..s.names.count) |i| {
            var buf: [256]u8 = undefined;
            const cmd = formatRepeatRule(&buf, s.names.name(i), repeat) catch continue;
            ipc.command(gpa, cmd) catch {};
        }
        s.names.count = 0;
    }
};

/// Device names, to restore what was set.
pub const Names = struct {
    pub const max = 8;
    buf: [max][96]u8 = undefined,
    lens: [max]u8 = @splat(0),
    count: u8 = 0,

    pub fn name(s: *const Names, i: usize) []const u8 {
        return s.buf[i][0..s.lens[i]];
    }

    pub fn record(s: *Names, n: []const u8) void {
        for (0..s.count) |i| if (std.mem.eql(u8, s.name(i), n)) return;
        if (s.count == max or n.len > s.buf[0].len) return;
        @memcpy(s.buf[s.count][0..n.len], n);
        s.lens[s.count] = @intCast(n.len);
        s.count += 1;
    }
};

/// With misc:name_vk_after_proc (the default); text keyboards add `-1`, `-2`, ...
pub const own_names_base = "hl-virtual-keyboard-omastation";
pub const own_names = 9;

/// At startup: restores bindings and repeat on every own keyboard name left by a run that died
/// mid-session; if its RDP outputs remain, other virtual keyboards get the configured repeat too.
pub fn resetStale(ipc: *const hypr.Ipc, gpa: std.mem.Allocator) void {
    const repeat = globalRepeat(ipc, gpa);
    for (0..own_names) |i| {
        var nb: [64]u8 = undefined;
        const n = (if (i == 0) std.fmt.bufPrint(&nb, "{s}", .{own_names_base}) else std.fmt.bufPrint(&nb, "{s}-{d}", .{ own_names_base, i })) catch continue;
        var buf: [256]u8 = undefined;
        const cmd = formatRuleOn(&buf, n, repeat) catch continue;
        ipc.command(gpa, cmd) catch |err| {
            log.debug("cannot reset the keybinds rule of {s}: {t}", .{ n, err });
            return;
        };
    }
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const ms = hypr.monitors(ipc, a) catch return;
    for (ms) |m| {
        if (hypr.isRdpOutput(m.name)) break;
    } else return;
    const json = ipc.request(a, "j/devices") catch return;
    const found = parseRepeatKeyboards(a, json) catch return;
    for (found) |n| {
        if (std.mem.startsWith(u8, n, own_names_base)) continue; // done above
        var buf: [256]u8 = undefined;
        const cmd = formatRepeatRule(&buf, n, repeat) catch continue;
        ipc.command(gpa, cmd) catch return;
        log.info("{s}: the configured key repeat back (a previous run ended during a session)", .{n});
    }
}

test "the text keyboards are those whose layout is the text keymap's" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const json =
        \\{"mice": [], "keyboards": [
        \\ {"address": "0x55aa01", "name": "at-translated-set-2-keyboard", "rules": "", "model": "", "layout": "us", "variant": "", "options": "", "active_keymap": "English (US)", "capsLock": false, "numLock": false, "main": true},
        \\ {"address": "0x55aa02", "name": "hl-virtual-keyboard-omastation", "rules": "", "model": "", "layout": "us", "variant": "", "options": "", "active_keymap": "English (US)", "capsLock": false, "numLock": false, "main": false},
        \\ {"address": "0x55aa03", "name": "hl-virtual-keyboard-omastation-1", "rules": "", "model": "", "layout": "us", "variant": "", "options": "", "active_keymap": "omastation text", "capsLock": false, "numLock": false, "main": false},
        \\ {"address": "0x55aa04", "name": "hl-virtual-keyboard-fcitx5", "rules": "", "model": "", "layout": "us", "variant": "", "options": "", "active_keymap": "omastation text", "capsLock": false, "numLock": false, "main": false}
        \\], "tablets": [], "touch": [], "switches": []}
    ;
    const names = try parseTextKeyboards(arena.allocator(), json);
    // fcitx5 forwards text keys with the text keymap; the rule there is harmless.
    try std.testing.expectEqual(@as(usize, 2), names.len);
    try std.testing.expectEqualStrings("hl-virtual-keyboard-omastation-1", names[0]);
    try std.testing.expectError(error.BadResponse, parseTextKeyboards(arena.allocator(), "not json"));
}

test "the rule is a Lua device rule, the name quoted" {
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("eval hl.device({ name = \"hl-virtual-keyboard-omastation-1\", keybinds = false, repeat_rate = 0 })", try formatRuleOff(&buf, "hl-virtual-keyboard-omastation-1"));
    try std.testing.expectEqualStrings("eval hl.device({ name = \"a\\\"b\", keybinds = true, repeat_rate = 40, repeat_delay = 250 })", try formatRuleOn(&buf, "a\"b", .{ .rate = 40, .delay = 250 }));
    try std.testing.expectEqualStrings("eval hl.device({ name = \"hl-virtual-keyboard-fcitx5\", repeat_rate = 1, repeat_delay = 2000 })", try formatRepeatRule(&buf, "hl-virtual-keyboard-fcitx5", sessionRepeat(.{ .rate = 40, .delay = 250 })));
}

test "session repeat: longest delay, rate 1, a configured 0 kept" {
    try std.testing.expectEqual(Repeat{ .rate = 1, .delay = 2000 }, sessionRepeat(.{ .rate = 40, .delay = 250 }));
    try std.testing.expectEqual(Repeat{ .rate = 1, .delay = 2000 }, sessionRepeat(.{ .rate = 1, .delay = 2000 }));
    try std.testing.expectEqual(Repeat{ .rate = 0, .delay = 2000 }, sessionRepeat(.{ .rate = 0, .delay = 600 }));
}

test "repeat rules cover every virtual keyboard but the text ones" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const json =
        \\{"mice": [], "keyboards": [
        \\ {"address": "0x55aa01", "name": "at-translated-set-2-keyboard", "active_keymap": "English (US)", "main": true},
        \\ {"address": "0x55aa02", "name": "hl-virtual-keyboard-omastation", "active_keymap": "French"},
        \\ {"address": "0x55aa03", "name": "hl-virtual-keyboard-omastation-1", "active_keymap": "omastation text"},
        \\ {"address": "0x55aa04", "name": "hl-virtual-keyboard-fcitx5", "active_keymap": "French"},
        \\ {"address": "0x55aa05", "name": "power-button", "active_keymap": "English (US)"}
        \\], "tablets": [], "touch": [], "switches": []}
    ;
    const names = try parseRepeatKeyboards(arena.allocator(), json);
    try std.testing.expectEqual(@as(usize, 2), names.len);
    try std.testing.expectEqualStrings("hl-virtual-keyboard-omastation", names[0]);
    try std.testing.expectEqualStrings("hl-virtual-keyboard-fcitx5", names[1]);
}

test "activelayout: only virtual keyboards without session repeat settings are new" {
    var s: RepeatRules = .{};
    s.names.record("hl-virtual-keyboard-omastation");
    try std.testing.expect(s.isNewKeyboard("hl-virtual-keyboard-fcitx5,English (US)"));
    try std.testing.expect(!s.isNewKeyboard("hl-virtual-keyboard-omastation,French"));
    try std.testing.expect(!s.isNewKeyboard("hl-virtual-keyboard-omastation-1,omastation text"));
    try std.testing.expect(!s.isNewKeyboard("hl-virtual-keyboard-omastation-2,English (US)")); // before its keymap
    try std.testing.expect(s.isNewKeyboard("hl-virtual-keyboard-1,English (US)")); // name_vk_after_proc off
    try std.testing.expect(!s.isNewKeyboard("at-translated-set-2-keyboard,English (US)"));
    try std.testing.expect(!s.isNewKeyboard("garbage"));
    s.names.record("hl-virtual-keyboard-fcitx5");
    try std.testing.expect(!s.isNewKeyboard("hl-virtual-keyboard-fcitx5,English (US)"));
}

test "Names: each once, at most eight, too long ones skipped" {
    var n: Names = .{};
    n.record("a");
    n.record("a");
    n.record("b");
    try std.testing.expectEqual(@as(u8, 2), n.count);
    try std.testing.expectEqualStrings("b", n.name(1));
    const long: [97]u8 = @splat('x');
    n.record(&long);
    try std.testing.expectEqual(@as(u8, 2), n.count);
    for (0..10) |i| {
        var b: [8]u8 = undefined;
        n.record(std.fmt.bufPrint(&b, "k{d}", .{i}) catch unreachable);
    }
    try std.testing.expectEqual(@as(u8, Names.max), n.count);
}
