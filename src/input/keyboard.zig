//! Keyboard state behind the virtual keyboard. Hyprland does not derive modifiers from
//! zwp_virtual_keyboard_v1 keys, so a private xkb_state computes and sends them. Key repeat
//! comes from the client only, as on Windows; the uploaded keymap repeats no key.

const std = @import("std");
const c = @import("c");

const log = std.log.scoped(.keyboard);

pub const Error = error{ XkbContext, XkbKeymap, XkbState, OutOfMemory };

/// XKB rule names (RMLVO). Empty means the libxkbcommon default.
pub const Names = struct {
    rules: [:0]const u8 = "",
    model: [:0]const u8 = "",
    layout: [:0]const u8 = "",
    variant: [:0]const u8 = "",
    options: [:0]const u8 = "",
};

/// XKB keycode = evdev keycode + 8.
const evdev_offset = 8;
pub const max_keys = 256;

pub const KEY_ENTER: u16 = 28;
pub const KEY_LEFTSHIFT: u16 = 42;
pub const KEY_CAPSLOCK: u16 = 58;
pub const KEY_NUMLOCK: u16 = 69;
pub const KEY_SCROLLLOCK: u16 = 70;
pub const KEY_RIGHTALT: u16 = 100;
pub const KEY_RIGHTMETA: u16 = 126;

pub const Keymap = struct {
    ctx: *c.struct_xkb_context,
    keymap: *c.struct_xkb_keymap,
    /// XKB_KEYMAP_FORMAT_TEXT_V1 serialization of `keymap`.
    text: [:0]const u8,
    /// `text` with no key repeating (`makeUpload`); owned.
    upload: ?[:0]u8 = null,

    pub fn fromNames(names: Names) Error!Keymap {
        const ctx = c.xkb_context_new(c.XKB_CONTEXT_NO_FLAGS) orelse return error.XkbContext;
        errdefer c.xkb_context_unref(ctx);
        const rmlvo: c.struct_xkb_rule_names = .{
            .rules = orNull(names.rules),
            .model = orNull(names.model),
            .layout = orNull(names.layout),
            .variant = orNull(names.variant),
            .options = orNull(names.options),
        };
        const km = c.xkb_keymap_new_from_names(ctx, &rmlvo, c.XKB_KEYMAP_COMPILE_NO_FLAGS) orelse return error.XkbKeymap;
        var k = try finish(ctx, km);
        if (std.mem.indexOf(u8, names.options, "compose:rwin") == null and k.rwinIsCompose()) {
            if (k.withSuperRwin()) |fixed| {
                k.deinit();
                return fixed;
            }
        }
        return k;
    }

    /// Irish layouts make RWIN Multi_key (compose(rwin)), so SUPER bindings would not fire
    /// from it; unless the options ask for that, it goes back to Super_R as in `pc`.
    fn rwinIsCompose(k: *const Keymap) bool {
        const kc = KEY_RIGHTMETA + evdev_offset;
        var syms: [*c]const c.xkb_keysym_t = undefined;
        const n = c.xkb_keymap_key_get_syms_by_level(k.keymap, kc, 0, 0, &syms);
        return n == 1 and syms[0] == c.XKB_KEY_Multi_key;
    }

    /// Null if the serialized keymap does not look as expected.
    fn withSuperRwin(k: *const Keymap) ?Keymap {
        const sym_start = std.mem.indexOf(u8, k.text, "xkb_symbols") orelse return null;
        const key_start = std.mem.indexOfPos(u8, k.text, sym_start, "key <RWIN>") orelse return null;
        const end = (std.mem.indexOfPos(u8, k.text, key_start, "};") orelse return null) + 2;
        const repl = "key <RWIN> { [ Super_R ] };\n\tmodifier_map Mod4 { <RWIN> };";
        var buf = std.heap.c_allocator.allocSentinel(u8, k.text.len - (end - key_start) + repl.len, 0) catch return null;
        defer std.heap.c_allocator.free(buf);
        @memcpy(buf[0..key_start], k.text[0..key_start]);
        @memcpy(buf[key_start..][0..repl.len], repl);
        @memcpy(buf[key_start + repl.len ..], k.text[end..]);
        var fixed = fromString(buf) catch return null;
        if (fixed.rwinIsCompose()) {
            fixed.deinit();
            return null;
        }
        return fixed;
    }

    pub fn fromString(text: [:0]const u8) Error!Keymap {
        const ctx = c.xkb_context_new(c.XKB_CONTEXT_NO_FLAGS) orelse return error.XkbContext;
        errdefer c.xkb_context_unref(ctx);
        const km = c.xkb_keymap_new_from_string(ctx, text.ptr, c.XKB_KEYMAP_FORMAT_TEXT_V1, c.XKB_KEYMAP_COMPILE_NO_FLAGS) orelse
            return error.XkbKeymap;
        return finish(ctx, km);
    }

    fn finish(ctx: *c.struct_xkb_context, km: *c.struct_xkb_keymap) Error!Keymap {
        errdefer c.xkb_keymap_unref(km);
        const s = c.xkb_keymap_get_as_string(km, c.XKB_KEYMAP_FORMAT_TEXT_V1) orelse return error.OutOfMemory;
        return .{ .ctx = ctx, .keymap = km, .text = std.mem.span(s) };
    }

    pub fn deinit(k: *Keymap) void {
        if (k.upload) |u| std.heap.c_allocator.free(u);
        c.free(@constCast(k.text.ptr));
        c.xkb_keymap_unref(k.keymap);
        c.xkb_context_unref(k.ctx);
    }

    pub fn uploadText(k: *const Keymap) [:0]const u8 {
        return k.upload orelse k.text;
    }

    /// Whether the key repeats on a physical keyboard; only such keys pass client repeats.
    pub fn repeats(k: *const Keymap, evdev: u16) bool {
        return c.xkb_keymap_key_repeats(k.keymap, evdev + evdev_offset) != 0;
    }

    /// Level 1 of the first layout, as a fresh xkb_state gives it; Hyprland matches key
    /// bindings this way. NoSymbol for none or several.
    pub fn levelOneSym(k: *const Keymap, evdev: u16) u32 {
        var syms: [*c]const c.xkb_keysym_t = undefined;
        const n = c.xkb_keymap_key_get_syms_by_level(k.keymap, evdev + evdev_offset, 0, 0, &syms);
        return if (n == 1) syms[0] else c.XKB_KEY_NoSymbol;
    }

    /// Mark every key `repeat= false` so Wayland clients never repeat keys themselves. If the
    /// result does not type exactly what `keymap` types, the keymap goes out unchanged.
    pub fn makeUpload(k: *Keymap) void {
        if (k.upload != null) return;
        const out = noRepeatText(std.heap.c_allocator, k.text) catch null;
        const u = out orelse {
            log.warn("keymap: cannot mark its keys as not repeating; applications may repeat keys themselves", .{});
            return;
        };
        if (!k.sameKeysNoRepeat(u)) {
            std.heap.c_allocator.free(u);
            log.warn("keymap: the keymap without key repeat differs; applications may repeat keys themselves", .{});
            return;
        }
        k.upload = u;
    }

    /// `text` compiles to the keys of `k.keymap`, none of them repeating.
    fn sameKeysNoRepeat(k: *const Keymap, text: [:0]const u8) bool {
        const km = c.xkb_keymap_new_from_string(k.ctx, text.ptr, c.XKB_KEYMAP_FORMAT_TEXT_V1, c.XKB_KEYMAP_COMPILE_NO_FLAGS) orelse return false;
        defer c.xkb_keymap_unref(km);
        const lo = c.xkb_keymap_min_keycode(k.keymap);
        const hi = c.xkb_keymap_max_keycode(k.keymap);
        if (c.xkb_keymap_min_keycode(km) != lo or c.xkb_keymap_max_keycode(km) != hi) return false;
        if (c.xkb_keymap_num_layouts(km) != c.xkb_keymap_num_layouts(k.keymap)) return false;
        if (c.xkb_keymap_num_mods(km) != c.xkb_keymap_num_mods(k.keymap)) return false;
        var kc = lo;
        while (kc <= hi) : (kc += 1) {
            const layouts = c.xkb_keymap_num_layouts_for_key(k.keymap, kc);
            if (c.xkb_keymap_num_layouts_for_key(km, kc) != layouts) return false;
            if (c.xkb_keymap_key_repeats(km, kc) != 0) return false;
            for (0..layouts) |l| {
                const levels = c.xkb_keymap_num_levels_for_key(k.keymap, kc, @intCast(l));
                if (c.xkb_keymap_num_levels_for_key(km, kc, @intCast(l)) != levels) return false;
                for (0..levels) |lv| {
                    var a: [*c]const c.xkb_keysym_t = undefined;
                    var b: [*c]const c.xkb_keysym_t = undefined;
                    const na = c.xkb_keymap_key_get_syms_by_level(k.keymap, kc, @intCast(l), @intCast(lv), &a);
                    const nb = c.xkb_keymap_key_get_syms_by_level(km, kc, @intCast(l), @intCast(lv), &b);
                    if (na != nb) return false;
                    for (0..@intCast(@max(na, 0))) |i| if (a[i] != b[i]) return false;
                }
            }
            const sa = c.xkb_state_new(k.keymap) orelse return false;
            defer c.xkb_state_unref(sa);
            const sb = c.xkb_state_new(km) orelse return false;
            defer c.xkb_state_unref(sb);
            _ = c.xkb_state_update_key(sa, kc, c.XKB_KEY_DOWN);
            _ = c.xkb_state_update_key(sb, kc, c.XKB_KEY_DOWN);
            if (c.xkb_state_serialize_mods(sa, c.XKB_STATE_MODS_EFFECTIVE) != c.xkb_state_serialize_mods(sb, c.XKB_STATE_MODS_EFFECTIVE)) return false;
            if (c.xkb_state_serialize_layout(sa, c.XKB_STATE_LAYOUT_EFFECTIVE) != c.xkb_state_serialize_layout(sb, c.XKB_STATE_LAYOUT_EFFECTIVE)) return false;
            if (kc == std.math.maxInt(c.xkb_keycode_t)) break;
        }
        return true;
    }

    /// Locked modifiers a tap of the lock key sets, retried with Shift (Japanese Caps Lock is
    /// Shift+CapsLock); 0 when it locks nothing, e.g. under `ctrl:nocaps`.
    fn lockMask(k: *const Keymap, evdev: u16) u32 {
        for ([_]bool{ false, true }) |shift| {
            const st = c.xkb_state_new(k.keymap) orelse return 0;
            defer c.xkb_state_unref(st);
            if (shift) _ = c.xkb_state_update_key(st, KEY_LEFTSHIFT + evdev_offset, c.XKB_KEY_DOWN);
            _ = c.xkb_state_update_key(st, evdev + evdev_offset, c.XKB_KEY_DOWN);
            _ = c.xkb_state_update_key(st, evdev + evdev_offset, c.XKB_KEY_UP);
            if (shift) _ = c.xkb_state_update_key(st, KEY_LEFTSHIFT + evdev_offset, c.XKB_KEY_UP);
            const locked = c.xkb_state_serialize_mods(st, c.XKB_STATE_MODS_LOCKED);
            if (locked != 0) return locked;
        }
        return 0;
    }
};

fn orNull(s: [:0]const u8) ?[*:0]const u8 {
    return if (s.len == 0) null else s.ptr;
}

/// Adds `repeat= false,` to every xkb_symbols `key <NAME> {` that does not set `repeat`;
/// the per-key flag wins over compat `interpret`. Null without xkb_symbols.
pub fn noRepeatText(gpa: std.mem.Allocator, text: []const u8) error{OutOfMemory}!?[:0]u8 {
    const sym = std.mem.indexOf(u8, text, "xkb_symbols") orelse return null;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, text.len + text.len / 4);
    try out.appendSlice(gpa, text[0..sym]);
    var pos = sym;
    while (pos < text.len) {
        const eol = if (std.mem.indexOfScalarPos(u8, text, pos, '\n')) |e| e + 1 else text.len;
        const line = text[pos..eol];
        const body = std.mem.trimStart(u8, line, " \t");
        const brace = std.mem.indexOfScalar(u8, line, '{');
        if (!std.mem.startsWith(u8, body, "key <") or brace == null) {
            try out.appendSlice(gpa, line);
            pos = eol;
            continue;
        }
        const end = if (std.mem.indexOfPos(u8, text, pos, "};")) |e| e + 2 else text.len;
        const stmt = text[pos..end];
        if (std.mem.indexOf(u8, stmt, "repeat") != null) {
            try out.appendSlice(gpa, stmt);
        } else {
            try out.appendSlice(gpa, stmt[0 .. brace.? + 1]);
            try out.appendSlice(gpa, " repeat= false,");
            try out.appendSlice(gpa, stmt[brace.? + 1 ..]);
        }
        pos = end;
    }
    return try out.toOwnedSliceSentinel(gpa, 0);
}

/// Arguments of zwp_virtual_keyboard_v1.modifiers / wl_keyboard.modifiers.
pub const Mods = struct {
    depressed: u32 = 0,
    latched: u32 = 0,
    locked: u32 = 0,
    group: u32 = 0,

    pub fn eql(a: Mods, b: Mods) bool {
        return a.depressed == b.depressed and a.latched == b.latched and a.locked == b.locked and a.group == b.group;
    }
};

/// Toggle keys from an RDP Synchronize event.
pub const Locks = struct { caps: bool = false, num: bool = false, scroll: bool = false };

pub const State = struct {
    keymap: *const Keymap,
    state: *c.struct_xkb_state,
    down: std.StaticBitSet(max_keys) = .empty,
    sent: Mods = .{},
    caps_mask: u32,
    num_mask: u32,
    scroll_mask: u32,

    pub fn init(keymap: *const Keymap) Error!State {
        return .{
            .keymap = keymap,
            .state = c.xkb_state_new(keymap.keymap) orelse return error.XkbState,
            .caps_mask = keymap.lockMask(KEY_CAPSLOCK),
            .num_mask = keymap.lockMask(KEY_NUMLOCK),
            .scroll_mask = keymap.lockMask(KEY_SCROLLLOCK),
        };
    }

    pub fn deinit(s: *State) void {
        c.xkb_state_unref(s.state);
    }

    /// The key, then `mods` if set. `repeat` is the client's repeat of a held key, sent as a
    /// release and a press: Hyprland drops a second press of a held key.
    pub const Change = struct { mods: ?Mods, repeat: bool = false };

    /// A press of a key already down is the client's repeat (fast-path has no repeat flag).
    /// Stray releases are dropped: Windows clients release every modifier on focus.
    pub fn key(s: *State, evdev: u16, pressed: bool) ?Change {
        if (evdev >= max_keys) return null;
        if (pressed == s.down.isSet(evdev)) {
            if (pressed and s.keymap.repeats(evdev)) return .{ .mods = null, .repeat = true };
            return null;
        }
        s.down.setValue(evdev, pressed);
        _ = c.xkb_state_update_key(s.state, evdev + evdev_offset, if (pressed) c.XKB_KEY_DOWN else c.XKB_KEY_UP);
        return .{ .mods = s.takeMods() };
    }

    /// Depressed and latched modifiers in Hyprland's bind modmask bits.
    pub fn bindMods(s: *const State) u32 {
        const names = [_][:0]const u8{ "Shift", "Lock", "Control", "Mod1", "Mod2", "Mod3", "Mod4", "Mod5" };
        var out: u32 = 0;
        for (names, 0..) |n, i| {
            const idx = c.xkb_keymap_mod_get_index(s.keymap.keymap, n.ptr);
            if (idx == c.XKB_MOD_INVALID) continue;
            if (c.xkb_state_mod_index_is_active(s.state, idx, c.XKB_STATE_MODS_DEPRESSED | c.XKB_STATE_MODS_LATCHED) > 0) out |= @as(u32, 1) << @intCast(i);
        }
        return out;
    }

    pub const Sync = struct {
        /// Keys that were down: send a release for each, then `mods`.
        released: std.StaticBitSet(max_keys),
        mods: ?Mods,
    };

    /// MS-RDPBCGR 2.2.8.1.1.3.1.1.5: every key up, toggles as given. Lock bits are what this
    /// keymap's lock keys set; the locked layout group is kept.
    pub fn sync(s: *State, toggles: Locks) Error!Sync {
        const released = s.down;
        s.down = .empty;
        const group = c.xkb_state_serialize_layout(s.state, c.XKB_STATE_LAYOUT_LOCKED);
        const fresh = c.xkb_state_new(s.keymap.keymap) orelse return error.XkbState;
        c.xkb_state_unref(s.state);
        s.state = fresh;
        var locked: u32 = 0;
        if (toggles.caps) locked |= s.caps_mask;
        if (toggles.num) locked |= s.num_mask;
        if (toggles.scroll) locked |= s.scroll_mask;
        _ = c.xkb_state_update_mask(s.state, 0, 0, locked, 0, 0, group);
        return .{ .released = released, .mods = s.takeMods() };
    }

    /// All keys up, for a disconnect: same as a sync that keeps lock state.
    pub fn releaseAll(s: *State) Error!Sync {
        return s.sync(s.locks());
    }

    /// For Synchronize or Set Keyboard Indicators; a lock this keymap cannot set is off.
    pub fn locks(s: *const State) Locks {
        const locked = c.xkb_state_serialize_mods(s.state, c.XKB_STATE_MODS_LOCKED);
        return .{
            .caps = s.caps_mask != 0 and locked & s.caps_mask == s.caps_mask,
            .num = s.num_mask != 0 and locked & s.num_mask == s.num_mask,
            .scroll = s.scroll_mask != 0 and locked & s.scroll_mask == s.scroll_mask,
        };
    }

    /// The toggle keys this keymap can lock at all.
    pub fn lockSupport(s: *const State) Locks {
        return .{ .caps = s.caps_mask != 0, .num = s.num_mask != 0, .scroll = s.scroll_mask != 0 };
    }

    pub fn current(s: *const State) Mods {
        return .{
            .depressed = c.xkb_state_serialize_mods(s.state, c.XKB_STATE_MODS_DEPRESSED),
            .latched = c.xkb_state_serialize_mods(s.state, c.XKB_STATE_MODS_LATCHED),
            .locked = c.xkb_state_serialize_mods(s.state, c.XKB_STATE_MODS_LOCKED),
            .group = c.xkb_state_serialize_layout(s.state, c.XKB_STATE_LAYOUT_EFFECTIVE),
        };
    }

    fn takeMods(s: *State) ?Mods {
        const m = s.current();
        if (m.eql(s.sent)) return null;
        s.sent = m;
        return m;
    }

    /// The keysym a key currently produces (for tests and logging).
    pub fn keysym(s: *const State, evdev: u16) u32 {
        return c.xkb_state_key_get_one_sym(s.state, evdev + evdev_offset);
    }
};

/// Ordinary keys in every xkeyboard-config layout: Hyprland translates bindings through the
/// configured layout, not the sender's keymap. Xwayland sees only keycodes up to 255.
pub const text_keys = [_]u16{
    28, 14, 15, 41, // Enter, BackSpace, Tab, grave: Return, BackSpace, Tab, Escape
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, // 1..0, minus, equal
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, // Q..P, brackets
    30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 43, // A..L, semicolon, apostrophe, backslash
    44, 45, 46, 47, 48, 49, 50, 51, 52, 53, // Z..M, comma, dot, slash
    55, 57, 86, // keypad asterisk, space, 102nd (<LSGT>)
    71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, // keypad 7..dot
    96, 98, 117, 118, 121, 179, 180, // keypad enter, slash, equal, plusminus, comma, parentheses
    102, 103, 104, 105, 106, 107, 108, 109, 110, 111, // Home..Delete, arrows
};

/// `level2`: typed with `TextKeymap.level2_mask` depressed.
pub const TextKey = struct {
    code: u16,
    level2: bool = false,
};

/// Keysyms needed to type text, two per text key. Level 2 is on Mod3 alone, so modifiers
/// Hyprland shares from other keyboards never change what a key types.
pub const TextKeymap = struct {
    /// syms[s] is on slot s (`slotKey`).
    syms: std.ArrayList(u32) = .empty,
    /// Bumped whenever `render()` output changes (re-upload the keymap).
    generation: u32 = 0,
    /// When each learned slot was last typed (a counter).
    used: [capacity]u32 = @splat(0),
    clock: u32 = 0,

    /// Level 1 of every text key, then level 2 of every text key.
    pub const capacity = text_keys.len * 2;
    /// Editing keys and printable ASCII are fixed: an ASCII password never changes the keymap.
    pub const fixed = seed.len;
    /// How the server finds its text keyboards in Hyprland's device list.
    pub const layout_name = "omastation text";
    /// Mod3 (real modifier index 5): depressed while a level-2 key is typed.
    pub const level2_mask: u32 = 1 << 5;

    /// Return, BackSpace, Tab, Escape, then printable ASCII, the rarest last (level 2).
    const seed = blk: {
        var syms: [4 + 0x5f]u32 = undefined;
        syms[0] = c.XKB_KEY_Return;
        syms[1] = c.XKB_KEY_BackSpace;
        syms[2] = c.XKB_KEY_Tab;
        syms[3] = c.XKB_KEY_Escape;
        const order = "etaoinsrhldcumfpgwybvkxjqz ETAOINSRHLDCUMFPGWYBVKXJQZ0123456789.,'\"-:;!?()/_@=+*&#%$~<>[]{}|\\^`";
        if (order.len != 0x5f) @compileError("printable ASCII, each once");
        for (order, 4..) |ch, i| syms[i] = ch; // Latin-1 keysyms equal their code point
        break :blk syms;
    };

    pub fn slotKey(slot: usize) TextKey {
        return if (slot < text_keys.len) .{ .code = text_keys[slot] } else .{ .code = text_keys[slot - text_keys.len], .level2 = true };
    }

    pub fn init(gpa: std.mem.Allocator) Error!TextKeymap {
        var t: TextKeymap = .{};
        errdefer t.syms.deinit(gpa);
        try t.syms.ensureTotalCapacity(gpa, capacity);
        t.syms.appendSliceAssumeCapacity(&seed);
        return t;
    }

    pub fn deinit(t: *TextKeymap, gpa: std.mem.Allocator) void {
        t.syms.deinit(gpa);
    }

    /// Learns a new keysym (bumps `generation`); when full, evicts the least recently typed.
    pub fn keyForSym(t: *TextKeymap, sym: u32) TextKey {
        t.clock +%= 1;
        if (std.mem.indexOfScalar(u32, t.syms.items, sym)) |i| {
            t.used[i] = t.clock;
            return slotKey(i);
        }
        const i = if (t.syms.items.len < capacity) blk: {
            t.syms.appendAssumeCapacity(sym);
            break :blk t.syms.items.len - 1;
        } else blk: {
            var lru: usize = fixed;
            for (fixed..capacity) |k| {
                if (t.clock -% t.used[k] > t.clock -% t.used[lru]) lru = k;
            }
            t.syms.items[lru] = sym;
            break :blk lru;
        };
        t.used[i] = t.clock;
        t.generation +%= 1;
        return slotKey(i);
    }

    /// Wipe learned keysyms so the keymap never lists a typed password; bumps `generation`.
    pub fn forgetOnDemand(t: *TextKeymap) void {
        if (t.syms.items.len <= fixed) return;
        std.crypto.secureZero(u32, t.syms.items[fixed..]);
        t.syms.shrinkRetainingCapacity(fixed);
        @memset(t.used[fixed..], 0);
        t.generation +%= 1;
    }

    /// Null if XKB has no keysym for `cp`.
    pub fn keyForCodepoint(t: *TextKeymap, cp: u21) ?TextKey {
        const sym = c.xkb_utf32_to_keysym(cp);
        if (sym == c.XKB_KEY_NoSymbol) return null;
        return t.keyForSym(sym);
    }

    /// Keymap text for zwp_virtual_keyboard_v1.keymap.
    pub fn render(t: *const TextKeymap, gpa: std.mem.Allocator) Error![:0]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        const n = t.syms.items.len;
        const keys = @min(n, text_keys.len);
        try out.appendSlice(gpa, "xkb_keymap {\nxkb_keycodes \"omastation-text\" {\nminimum = 8;\nmaximum = 255;\n");
        for (text_keys[0..keys], 0..) |key, i| try out.print(gpa, "<K{d}> = {d};\n", .{ i + 1, key + evdev_offset });
        try out.print(gpa,
            \\}};
            \\xkb_types "omastation-text" {{
            \\include "complete"
            \\type "OMASTATION_TEXT" {{ modifiers = Mod3; map[Mod3] = Level2; level_name[Level1] = "Text"; level_name[Level2] = "Text2"; }};
            \\}};
            \\xkb_compat "omastation-text" {{ include "complete" }};
            \\xkb_symbols "omastation-text" {{
            \\name[Group1] = "{s}";
            \\
        , .{layout_name});
        for (0..keys) |k| {
            var n1: [64]u8 = undefined;
            const l1 = symName(t.syms.items[k], &n1) orelse "NoSymbol";
            if (k + text_keys.len < n) {
                var n2: [64]u8 = undefined;
                const l2 = symName(t.syms.items[k + text_keys.len], &n2) orelse "NoSymbol";
                try out.print(gpa, "key <K{d}> {{ type = \"OMASTATION_TEXT\", [ {s}, {s} ] }};\n", .{ k + 1, l1, l2 });
            } else {
                try out.print(gpa, "key <K{d}> {{ type = \"ONE_LEVEL\", [ {s} ] }};\n", .{ k + 1, l1 });
            }
        }
        try out.appendSlice(gpa, "};\n};\n");
        return out.toOwnedSliceSentinel(gpa, 0);
    }

    fn symName(sym: u32, buf: *[64]u8) ?[]const u8 {
        const len = c.xkb_keysym_get_name(sym, buf, buf.len);
        if (len <= 0 or len >= buf.len) return null;
        return buf[0..@intCast(len)];
    }
};

/// Level-1 symbol, or level-2 with TextKeymap.level2_mask depressed.
pub fn textKeysym(km: *const Keymap, k: TextKey) u32 {
    const st = c.xkb_state_new(km.keymap) orelse return c.XKB_KEY_NoSymbol;
    defer c.xkb_state_unref(st);
    if (k.level2) _ = c.xkb_state_update_mask(st, TextKeymap.level2_mask, 0, 0, 0, 0, 0);
    return c.xkb_state_key_get_one_sym(st, k.code + evdev_offset);
}

/// Joins surrogate pairs from RDP Unicode keyboard events into code points.
pub const Utf16Decoder = struct {
    high: ?u16 = null,

    pub fn feed(d: *Utf16Decoder, unit: u16) ?u21 {
        if (std.unicode.utf16IsHighSurrogate(unit)) {
            d.high = unit;
            return null;
        }
        if (std.unicode.utf16IsLowSurrogate(unit)) {
            const hi = d.high orelse return null;
            d.high = null;
            return std.unicode.utf16DecodeSurrogatePair(&.{ hi, unit }) catch null;
        }
        d.high = null;
        return unit;
    }
};

const KEY_Q: u16 = 16;
const KEY_E: u16 = 18;
const KEY_A: u16 = 30;
const KEY_0: u16 = 11;
const KEY_LEFTCTRL: u16 = 29;

test "shift and altgr produce modifiers and the right keysyms" {
    var km = try Keymap.fromNames(.{ .layout = "fr" });
    defer km.deinit();
    var st = try State.init(&km);
    defer st.deinit();

    // AZERTY: the key at evdev KEY_Q types 'a'.
    try std.testing.expectEqual(@as(u32, 'a'), st.keysym(KEY_Q));
    const sh = st.key(KEY_LEFTSHIFT, true).?;
    try std.testing.expect(sh.mods.?.depressed != 0);
    try std.testing.expectEqual(@as(u32, 'A'), st.keysym(KEY_Q));
    try std.testing.expectEqual(@as(u32, 0), st.key(KEY_LEFTSHIFT, false).?.mods.?.depressed);

    // AltGr+0 is '@' and AltGr+e is the euro sign.
    try std.testing.expect(st.key(KEY_RIGHTALT, true).?.mods != null);
    try std.testing.expectEqual(@as(u32, c.XKB_KEY_at), st.keysym(KEY_0));
    try std.testing.expectEqual(@as(u32, c.XKB_KEY_EuroSign), st.keysym(KEY_E));
    _ = st.key(KEY_RIGHTALT, false);
    try std.testing.expectEqual(Mods{}, st.current());
}

test "a press of a held key is the client's repeat; stray releases are dropped; plain keys send no modifiers" {
    var km = try Keymap.fromNames(.{ .layout = "us" });
    defer km.deinit();
    var st = try State.init(&km);
    defer st.deinit();
    try std.testing.expect(st.key(KEY_LEFTCTRL, false) == null); // client focus-in release
    const a = st.key(KEY_A, true).?;
    try std.testing.expect(a.mods == null and !a.repeat);
    for (0..3) |_| {
        const r = st.key(KEY_A, true).?;
        try std.testing.expect(r.repeat and r.mods == null);
    }
    try std.testing.expectEqual(@as(u32, 'a'), st.keysym(KEY_A));
    const up = st.key(KEY_A, false).?;
    try std.testing.expect(!up.repeat);
    try std.testing.expect(st.key(KEY_A, false) == null);
}

test "repeats of modifiers and lock keys are dropped (they do not repeat on a physical keyboard)" {
    var km = try Keymap.fromNames(.{ .layout = "us" });
    defer km.deinit();
    var st = try State.init(&km);
    defer st.deinit();
    for ([_]u16{ KEY_LEFTSHIFT, KEY_LEFTCTRL, KEY_RIGHTALT, KEY_RIGHTMETA, KEY_CAPSLOCK, KEY_NUMLOCK }) |k| {
        _ = st.key(k, true);
        try std.testing.expect(st.key(k, true) == null);
        _ = st.key(k, false);
    }
    _ = try st.sync(.{}); // Caps and Num Lock were toggled above
    _ = st.key(KEY_LEFTSHIFT, true);
    _ = st.key(KEY_Q, true);
    try std.testing.expect(st.key(KEY_Q, true).?.repeat);
    try std.testing.expectEqual(@as(u32, 1), st.current().depressed);
    try std.testing.expectEqual(@as(u32, 'Q'), st.keysym(KEY_Q));
}

test "sync and releaseAll after a repeat release the key once; it is a fresh press afterwards" {
    var km = try Keymap.fromNames(.{ .layout = "us" });
    defer km.deinit();
    var st = try State.init(&km);
    defer st.deinit();
    _ = st.key(KEY_A, true);
    _ = st.key(KEY_A, true);
    const s = try st.sync(.{});
    try std.testing.expect(s.released.isSet(KEY_A));
    try std.testing.expectEqual(@as(usize, 1), s.released.count());
    try std.testing.expect(!st.key(KEY_A, true).?.repeat);
    _ = st.key(KEY_A, true);
    const r = try st.releaseAll();
    try std.testing.expectEqual(@as(usize, 1), r.released.count());
}

test "bindMods: Hyprland's modifier bits (Super 64, Alt 8, Ctrl 4, Shift 1), depressed and latched only" {
    var km = try Keymap.fromNames(.{ .layout = "us" });
    defer km.deinit();
    var st = try State.init(&km);
    defer st.deinit();
    try std.testing.expectEqual(@as(u32, 0), st.bindMods());
    _ = st.key(KEY_RIGHTMETA, true);
    try std.testing.expectEqual(@as(u32, 64), st.bindMods());
    _ = st.key(KEY_LEFTCTRL, true);
    _ = st.key(KEY_LEFTSHIFT, true);
    try std.testing.expectEqual(@as(u32, 64 | 4 | 1), st.bindMods());
    _ = st.key(KEY_RIGHTMETA, false);
    _ = st.key(KEY_LEFTCTRL, false);
    _ = st.key(KEY_LEFTSHIFT, false);
    _ = try st.sync(.{ .caps = true, .num = true });
    try std.testing.expectEqual(@as(u32, 0), st.bindMods());
    _ = st.key(56, true); // left Alt
    try std.testing.expectEqual(@as(u32, 8), st.bindMods());
}

test "the uploaded keymap repeats no key and types exactly what the keymap types" {
    for ([_]Names{ .{ .layout = "us" }, .{ .layout = "fr" }, .{ .layout = "de", .options = "ctrl:nocaps" }, .{ .layout = "jp" }, .{ .layout = "ie" }, .{ .layout = "us,ru", .options = "grp:alt_shift_toggle" } }) |names| {
        var km = try Keymap.fromNames(names);
        defer km.deinit();
        try std.testing.expect(km.upload == null);
        try std.testing.expectEqual(km.text.ptr, km.uploadText().ptr);
        km.makeUpload();
        const up = km.uploadText();
        try std.testing.expect(up.ptr != km.text.ptr);
        var seen = try Keymap.fromString(up);
        defer seen.deinit();
        var kc: u32 = c.xkb_keymap_min_keycode(seen.keymap);
        var repeating: usize = 0;
        while (kc <= c.xkb_keymap_max_keycode(seen.keymap)) : (kc += 1) {
            try std.testing.expectEqual(@as(c_int, 0), c.xkb_keymap_key_repeats(seen.keymap, kc));
            if (c.xkb_keymap_key_repeats(km.keymap, kc) != 0) repeating += 1;
        }
        try std.testing.expect(repeating > 50);
        try std.testing.expect(km.repeats(KEY_A) and km.repeats(KEY_ENTER) and !km.repeats(KEY_LEFTSHIFT) and !km.repeats(KEY_CAPSLOCK));
        try std.testing.expect(km.sameKeysNoRepeat(up));
        var a = try State.init(&km);
        defer a.deinit();
        var b = try State.init(&seen);
        defer b.deinit();
        for ([_]u16{ KEY_LEFTSHIFT, KEY_RIGHTALT, KEY_A, KEY_Q, KEY_0 }) |k| {
            _ = a.key(k, true);
            _ = b.key(k, true);
            try std.testing.expectEqual(a.current(), b.current());
            for ([_]u16{ KEY_A, KEY_E, KEY_Q, KEY_0 }) |t| try std.testing.expectEqual(a.keysym(t), b.keysym(t));
        }
        try std.testing.expectEqualStrings(std.mem.sliceTo(c.xkb_keymap_layout_get_name(km.keymap, 0), 0), std.mem.sliceTo(c.xkb_keymap_layout_get_name(seen.keymap, 0), 0));
        km.makeUpload();
        try std.testing.expectEqual(up.ptr, km.uploadText().ptr);
    }
}

test "noRepeatText: one-line and multi-line key statements, keys saying repeat themselves kept" {
    const gpa = std.testing.allocator;
    const text =
        \\xkb_keymap {
        \\xkb_keycodes "k" { <AE01> = 10; };
        \\xkb_symbols "s" {
        \\    key <AE01> {    [ 0x31, 0x21 ] };
        \\    key <KPDV> {
        \\        type= "CTRL+ALT",
        \\        symbols[1]= [ 0xffaf, 0xffaf ]
        \\    };
        \\    key <LFSH> { repeat= Yes, [ 0xffe1 ] };
        \\    modifier_map Shift { <LFSH> };
        \\};
        \\};
    ;
    const out = (try noRepeatText(gpa, text)).?;
    defer gpa.free(out);
    try std.testing.expectEqualStrings(
        \\xkb_keymap {
        \\xkb_keycodes "k" { <AE01> = 10; };
        \\xkb_symbols "s" {
        \\    key <AE01> { repeat= false,    [ 0x31, 0x21 ] };
        \\    key <KPDV> { repeat= false,
        \\        type= "CTRL+ALT",
        \\        symbols[1]= [ 0xffaf, 0xffaf ]
        \\    };
        \\    key <LFSH> { repeat= Yes, [ 0xffe1 ] };
        \\    modifier_map Shift { <LFSH> };
        \\};
        \\};
    , out);
    try std.testing.expect((try noRepeatText(gpa, "xkb_keymap { };")) == null);
}

test "levelOneSym: the first level of the first layout (what Hyprland matches bindings with)" {
    var km = try Keymap.fromNames(.{ .layout = "fr" });
    defer km.deinit();
    try std.testing.expectEqual(@as(u32, 'a'), km.levelOneSym(KEY_Q));
    try std.testing.expectEqual(@as(u32, c.XKB_KEY_agrave), km.levelOneSym(KEY_0));
    try std.testing.expectEqual(@as(u32, c.XKB_KEY_Return), km.levelOneSym(KEY_ENTER));
}

test "sync releases held keys and sets lock state from the keymap" {
    var km = try Keymap.fromNames(.{ .layout = "us" });
    defer km.deinit();
    var st = try State.init(&km);
    defer st.deinit();
    try std.testing.expect(st.caps_mask != 0 and st.num_mask != 0);
    _ = st.key(KEY_LEFTSHIFT, true);
    _ = st.key(KEY_A, true);
    const s = try st.sync(.{ .caps = true, .num = true });
    try std.testing.expect(s.released.isSet(KEY_LEFTSHIFT) and s.released.isSet(KEY_A));
    try std.testing.expectEqual(@as(usize, 2), s.released.count());
    const m = s.mods.?;
    try std.testing.expectEqual(@as(u32, 0), m.depressed);
    try std.testing.expectEqual(st.caps_mask | st.num_mask, m.locked);
    try std.testing.expectEqual(@as(u32, 'A'), st.keysym(KEY_A)); // Caps on
    // Pressing Caps Lock afterwards unlocks it, as it would locally.
    _ = st.key(KEY_CAPSLOCK, true);
    _ = st.key(KEY_CAPSLOCK, false);
    try std.testing.expectEqual(st.num_mask, st.current().locked);
    // Disconnect keeps the lock state.
    _ = st.key(KEY_A, true);
    const r = try st.releaseAll();
    try std.testing.expect(r.released.isSet(KEY_A));
    try std.testing.expectEqual(st.num_mask, st.current().locked);
}

test "ctrl:nocaps: caps key is a control key and never locks" {
    var km = try Keymap.fromNames(.{ .layout = "fr", .options = "ctrl:nocaps" });
    defer km.deinit();
    var st = try State.init(&km);
    defer st.deinit();
    try std.testing.expectEqual(@as(u32, 0), st.caps_mask);
    const s = try st.sync(.{ .caps = true });
    try std.testing.expect(s.mods == null); // nothing locked
    const ctrl = st.key(KEY_CAPSLOCK, true).?.mods.?;
    try std.testing.expect(ctrl.depressed != 0 and ctrl.locked == 0);
}

test "the right Windows key stays Super under ie unless the options ask for Compose" {
    var ie = try Keymap.fromNames(.{ .layout = "ie" });
    defer ie.deinit();
    try std.testing.expect(!ie.rwinIsCompose());
    var st = try State.init(&ie);
    defer st.deinit();
    try std.testing.expect(st.key(KEY_RIGHTMETA, true).?.mods.?.depressed != 0);
    var opt = try Keymap.fromNames(.{ .layout = "us", .options = "compose:rwin" });
    defer opt.deinit();
    try std.testing.expect(opt.rwinIsCompose());
}

test "Japanese Caps Lock (Shift+CapsLock) is the caps lock mask" {
    var km = try Keymap.fromNames(.{ .layout = "jp" });
    defer km.deinit();
    var st = try State.init(&km);
    defer st.deinit();
    try std.testing.expectEqual(@as(u32, 1 << 1), st.caps_mask);
}

test "text keymap types any character, whatever other keyboards' modifiers are" {
    const gpa = std.testing.allocator;
    var tk = try TextKeymap.init(gpa);
    defer tk.deinit(gpa);
    const text = "P@ss w0rd!~`\u{20AC}\u{1F600}";
    var keys: [16]TextKey = undefined;
    var n: usize = 0;
    const view = try std.unicode.Utf8View.init(text);
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| : (n += 1) keys[n] = tk.keyForCodepoint(cp).?;
    const ret = tk.keyForSym(c.XKB_KEY_Return);
    try std.testing.expectEqual(@as(u32, 2), tk.generation);

    const src = try tk.render(gpa);
    defer gpa.free(src);
    var km = try Keymap.fromString(src);
    defer km.deinit();
    it = view.iterator();
    var i: usize = 0;
    while (it.nextCodepoint()) |cp| : (i += 1) {
        try std.testing.expectEqual(c.xkb_utf32_to_keysym(cp), textKeysym(&km, keys[i]));
    }
    try std.testing.expectEqual(@as(u32, c.XKB_KEY_Return), textKeysym(&km, ret));
    try std.testing.expect(!ret.level2);
    // Hyprland shares other keyboards' depressed modifiers; only Mod3 selects level 2.
    const st = c.xkb_state_new(km.keymap).?;
    defer c.xkb_state_unref(st);
    for ([_]u32{ 1 << 0, 1 << 2, 1 << 3, 1 << 4, 1 << 6, 1 << 7, 0xdd }) |other| {
        for (keys[0..n], 0..) |k, j| {
            _ = c.xkb_state_update_mask(st, other | (if (k.level2) TextKeymap.level2_mask else 0), 0, 0, 0, 0, 0);
            try std.testing.expectEqual(textKeysym(&km, keys[j]), c.xkb_state_key_get_one_sym(st, k.code + evdev_offset));
        }
    }
    try std.testing.expectEqualStrings(TextKeymap.layout_name, std.mem.sliceTo(c.xkb_keymap_layout_get_name(km.keymap, 0), 0));
}

test "text keymap: printable ASCII and the editing keys are fixed, each once" {
    const gpa = std.testing.allocator;
    var tk = try TextKeymap.init(gpa);
    defer tk.deinit(gpa);
    try std.testing.expectEqual(TextKeymap.fixed, tk.syms.items.len);
    var ch: u21 = 0x20;
    while (ch <= 0x7e) : (ch += 1) {
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u32, tk.syms.items, &.{ch}));
        _ = tk.keyForCodepoint(ch).?;
    }
    try std.testing.expectEqual(@as(u32, 0), tk.generation);
    try std.testing.expectEqual(TextKey{ .code = text_keys[0] }, tk.keyForCodepoint(0x0D).?);
    try std.testing.expectEqual(TextKey{ .code = text_keys[3] }, tk.keyForCodepoint(0x1B).?);
}

test "a full text keymap gives the least recently typed learned key to a new character" {
    const gpa = std.testing.allocator;
    var tk = try TextKeymap.init(gpa);
    defer tk.deinit(gpa);
    var cp: u21 = 0x4E00; // CJK ideographs
    while (tk.syms.items.len < TextKeymap.capacity) : (cp += 1) _ = tk.keyForCodepoint(cp).?;
    const first = TextKeymap.slotKey(TextKeymap.fixed);
    const second = TextKeymap.slotKey(TextKeymap.fixed + 1);
    try std.testing.expectEqual(first, tk.keyForCodepoint(0x4E00).?);
    const gen = tk.generation;
    try std.testing.expectEqual(second, tk.keyForCodepoint(0x9FA0).?);
    try std.testing.expectEqual(gen + 1, tk.generation);
    try std.testing.expectEqual(first, tk.keyForCodepoint(0x4E00).?);
    try std.testing.expectEqual(gen + 1, tk.generation);
    try std.testing.expectEqual(TextKey{ .code = text_keys[0] }, tk.keyForSym(c.XKB_KEY_Return));
    _ = tk.keyForCodepoint('a').?;
    try std.testing.expectEqual(gen + 1, tk.generation);
}

test "text keys: distinct, below the X11 keycode limit, ordinary keys in many layouts" {
    for (text_keys, 0..) |k, i| {
        try std.testing.expect(k >= 1 and k + evdev_offset <= 255);
        for (text_keys[0..i]) |o| try std.testing.expect(o != k);
    }
    // Every text key gives a keysym no unmodified shortcut is likely to use.
    const layouts_to_check = [_]Names{
        .{ .layout = "us" },                           .{ .layout = "de" },
        .{ .layout = "fr" },                           .{ .layout = "gb" },
        .{ .layout = "ru" },                           .{ .layout = "jp" },
        .{ .layout = "kr" },                           .{ .layout = "ara" },
        .{ .layout = "us", .variant = "dvorak" },      .{ .layout = "ch", .variant = "fr" },
        .{ .layout = "us", .options = "caps:escape" }, .{ .layout = "de", .options = "compose:ralt,grp:alt_shift_toggle" },
    };
    for (layouts_to_check) |names| {
        var km = try Keymap.fromNames(names);
        defer km.deinit();
        var st = try State.init(&km);
        defer st.deinit();
        for (text_keys) |k| {
            const sym = st.keysym(k);
            var buf: [64]u8 = undefined;
            const len = c.xkb_keysym_get_name(sym, &buf, buf.len);
            const name = if (len > 0) buf[0..@intCast(len)] else "";
            const bad = std.mem.startsWith(u8, name, "XF86") or (sym >= c.XKB_KEY_F1 and sym <= c.XKB_KEY_F35) or
                (sym >= c.XKB_KEY_Shift_L and sym <= c.XKB_KEY_Hyper_R) or
                (sym >= c.XKB_KEY_ISO_Lock and sym <= c.XKB_KEY_ISO_Last_Group_Lock) or
                sym == c.XKB_KEY_Print or sym == c.XKB_KEY_Sys_Req or sym == c.XKB_KEY_Pause or sym == c.XKB_KEY_Break or
                sym == c.XKB_KEY_Escape or sym == c.XKB_KEY_Menu or sym == c.XKB_KEY_Scroll_Lock or sym == c.XKB_KEY_Num_Lock or
                sym == c.XKB_KEY_Mode_switch or sym == c.XKB_KEY_Multi_key;
            if (bad) {
                std.debug.print("layout {s} {s}: evdev {d} is {s}\n", .{ names.layout, names.variant, k, name });
                return error.TestUnexpectedResult;
            }
        }
    }
}

test "utf16 surrogate pairs" {
    var d = Utf16Decoder{};
    try std.testing.expectEqual(@as(?u21, 'x'), d.feed('x'));
    try std.testing.expectEqual(@as(?u21, null), d.feed(0xD83D));
    try std.testing.expectEqual(@as(?u21, 0x1F600), d.feed(0xDE00));
    try std.testing.expectEqual(@as(?u21, null), d.feed(0xDE00)); // lone low surrogate
}
