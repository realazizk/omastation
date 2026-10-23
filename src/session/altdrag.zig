//! Option+drag for macOS clients: each SUPER+mouse window binding gets an ALT twin.
//! The macOS Windows App sends Command only on release when held alone, and RDP mouse
//! events carry no modifier state (MS-RDPBCGR 2.2.8.1.1.3.1.1.3).

const std = @import("std");
const c = @import("c");
const hypr = @import("hypr.zig");
const fastpath = @import("../proto/fastpath.zig");

/// Hyprland modifier-mask bits, as `j/binds` reports them and `hl.bind` names them.
pub const mod_names = [_]struct { bit: u32, name: []const u8 }{
    .{ .bit = 1 << 6, .name = "SUPER" },
    .{ .bit = 1 << 0, .name = "SHIFT" },
    .{ .bit = 1 << 2, .name = "CTRL" },
    .{ .bit = 1 << 3, .name = "ALT" },
    .{ .bit = 1 << 1, .name = "CAPS" },
    .{ .bit = 1 << 4, .name = "MOD2" },
    .{ .bit = 1 << 5, .name = "MOD3" },
    .{ .bit = 1 << 7, .name = "MOD5" },
};
pub const mod_super: u32 = 1 << 6;
pub const mod_alt: u32 = 1 << 3;

/// osMajorType / osMinorType values (MS-RDPBCGR 2.2.7.1.1).
pub const osmajortype_unspecified: u16 = 0x0000;
pub const osmajortype_macintosh: u16 = 0x0003;
pub const osmajortype_ios: u16 = 0x0005;
pub const osmajortype_osx: u16 = 0x0006;
pub const osminortype_macintosh: u16 = 0x0006;

/// The client reports an Apple platform (General Capability Set).
pub fn isAppleClient(os_major: u16, os_minor: u16) bool {
    return switch (os_major) {
        osmajortype_macintosh, osmajortype_ios, osmajortype_osx => true,
        else => os_minor == osminortype_macintosh,
    };
}

/// Detect the lazy Command key from input only when the client omits its platform.
pub fn guessFromKeys(os_major: u16) bool {
    return os_major == osmajortype_unspecified;
}

pub const Mode = enum {
    /// Only for recognised Apple clients.
    auto,
    /// For every client.
    on,
    off,
};

/// One binding as `j/binds` lists it.
pub const Bind = struct {
    modmask: u32 = 0,
    submap: []const u8 = "",
    key: []const u8 = "",
    dispatcher: []const u8 = "",
    arg: []const u8 = "",
    description: []const u8 = "",
};

pub fn parseBinds(arena: std.mem.Allocator, json: []const u8) hypr.Error![]Bind {
    const J = struct {
        modmask: hypr.JsonNum(u32) = .{ .v = 0 },
        submap: hypr.JsonStr = .{},
        key: hypr.JsonStr = .{},
        dispatcher: hypr.JsonStr = .{},
        arg: hypr.JsonStr = .{},
        description: hypr.JsonStr = .{},
    };
    const parsed = std.json.parseFromSliceLeaky([]J, arena, json, .{ .ignore_unknown_fields = true }) catch return error.BadResponse;
    const out = arena.alloc(Bind, parsed.len) catch return error.BadResponse;
    for (parsed, out) |j, *o| o.* = .{ .modmask = j.modmask.v, .submap = j.submap.s, .key = j.key.s, .dispatcher = j.dispatcher.s, .arg = j.arg.s, .description = j.description.s };
    return out;
}

/// An Option twin to add: its `hl.bind` key string and the handler's registry reference.
pub const Twin = struct {
    keys: []const u8,
    ref: u32,
};

fn mouseButton(key: []const u8) ?u32 {
    if (!std.mem.startsWith(u8, key, "mouse:")) return null;
    return std.fmt.parseInt(u32, key["mouse:".len..], 10) catch null;
}

/// `hl.bind` key string for `modmask` + mouse `button`, e.g. "ALT + SHIFT + mouse:272".
pub fn keyString(buf: []u8, modmask: u32, button: u32) error{NoSpaceLeft}![]const u8 {
    var n: usize = 0;
    for (mod_names) |m| {
        if (modmask & m.bit == 0) continue;
        const s = try std.fmt.bufPrint(buf[n..], "{s} + ", .{m.name});
        n += s.len;
    }
    const s = try std.fmt.bufPrint(buf[n..], "mouse:{d}", .{button});
    return buf[0 .. n + s.len];
}

/// One twin per SUPER (non-ALT) mouse binding with a Lua handler, unless already bound.
pub fn plan(arena: std.mem.Allocator, binds: []const Bind) error{OutOfMemory}![]Twin {
    var out: std.ArrayList(Twin) = .empty;
    for (binds) |b| {
        if (b.modmask & mod_super == 0 or b.modmask & mod_alt != 0) continue;
        const button = mouseButton(b.key) orelse continue;
        if (!std.mem.eql(u8, b.dispatcher, "__lua")) continue;
        const ref = std.fmt.parseInt(u32, b.arg, 10) catch continue;
        const want = (b.modmask & ~mod_super) | mod_alt;
        const taken = for (binds) |o| {
            if (o.modmask == want and mouseButton(o.key) == button) break true;
        } else false;
        if (taken) continue;
        var kb: [80]u8 = undefined;
        const keys = keyString(&kb, want, button) catch continue;
        const dup = for (out.items) |t| {
            if (std.mem.eql(u8, t.keys, keys)) break true;
        } else false;
        if (dup) continue;
        try out.append(arena, .{ .keys = try arena.dupe(u8, keys), .ref = ref });
    }
    return out.items;
}

pub const description = "omastation: Option + drag (macOS client)";

/// The handler is re-resolved when it runs, so a stale registry reference binds nothing.
pub fn formatBind(buf: []u8, t: Twin) error{NoSpaceLeft}![]const u8 {
    var q: [128]u8 = undefined;
    var dq: [96]u8 = undefined;
    return std.fmt.bufPrint(buf, "eval local f = debug.getregistry()[{d}]; if type(f) == \"function\" then hl.bind({s}, f, {{ description = {s} }}) end", .{
        t.ref, try hypr.luaString(&q, t.keys), try hypr.luaString(&dq, description),
    });
}

pub fn formatUnbind(buf: []u8, keys: []const u8) error{NoSpaceLeft}![]const u8 {
    var q: [128]u8 = undefined;
    return std.fmt.bufPrint(buf, "eval hl.unbind({s})", .{try hypr.luaString(&q, keys)});
}

/// Removes bindings a previous run left in the state file, then deletes the file.
pub fn removeStale(ipc: *const hypr.Ipc, gpa: std.mem.Allocator, state_path: [:0]const u8) void {
    var buf: [1024]u8 = undefined;
    const fd = c.open(state_path.ptr, c.O_RDONLY | c.O_CLOEXEC);
    if (fd < 0) return;
    const n = c.read(fd, &buf, buf.len);
    _ = c.close(fd);
    if (n > 0) {
        var it = std.mem.tokenizeScalar(u8, buf[0..@intCast(n)], '\n');
        while (it.next()) |keys| {
            if (keys.len > 96 or std.mem.indexOf(u8, keys, "mouse:") == null) continue;
            var cmd: [256]u8 = undefined;
            ipc.command(gpa, formatUnbind(&cmd, keys) catch continue) catch {};
            std.log.scoped(.altdrag).info("removed the binding {s} left by a previous run", .{keys});
        }
    }
    _ = c.unlink(state_path.ptr);
}

/// Lazy Command key: a Windows key (E0 5B / E0 5C) pressed and released within `window_ms`, nothing between.
pub const LazyCommand = struct {
    pub const window_ms = 5;

    down_ms: ?i64 = null,

    /// Scancode event (MS-RDPBCGR 2.2.8.1.2.2.1); true when it completes the lazy pattern.
    pub fn key(l: *LazyCommand, code: u8, flags: u8, now_ms: i64) bool {
        const win = flags & fastpath.kbd_extended != 0 and (code == 0x5B or code == 0x5C);
        if (!win) {
            l.down_ms = null;
            return false;
        }
        if (flags & fastpath.kbd_release == 0) {
            l.down_ms = now_ms;
            return false;
        }
        const down = l.down_ms orelse return false;
        l.down_ms = null;
        return now_ms - down <= window_ms;
    }

    /// Call on any other input event.
    pub fn other(l: *LazyCommand) void {
        l.down_ms = null;
    }
};

test "plan adds twins only for SUPER mouse bindings, keeping other modifiers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const binds = [_]Bind{
        .{ .modmask = 64, .key = "mouse:272", .dispatcher = "__lua", .arg = "197" },
        .{ .modmask = 64, .key = "mouse:273", .dispatcher = "__lua", .arg = "199" },
        .{ .modmask = 65, .key = "mouse:274", .dispatcher = "__lua", .arg = "201" },
        .{ .modmask = 64, .key = "mouse_down", .dispatcher = "__lua", .arg = "193" },
        .{ .modmask = 72, .key = "mouse:272", .dispatcher = "__lua", .arg = "221" },
        .{ .modmask = 64, .key = "Return", .dispatcher = "__lua", .arg = "5" },
        .{ .modmask = 8, .key = "mouse:273", .dispatcher = "__lua", .arg = "300" }, // existing ALT + right drag
    };
    const twins = try plan(arena.allocator(), &binds);
    try std.testing.expectEqual(2, twins.len);
    try std.testing.expectEqualStrings("ALT + mouse:272", twins[0].keys);
    try std.testing.expectEqual(197, twins[0].ref);
    try std.testing.expectEqualStrings("SHIFT + ALT + mouse:274", twins[1].keys);
}

test "lazy command: press and release together, nothing in between" {
    var l = LazyCommand{};
    try std.testing.expect(!l.key(0x5B, 0x02, 100));
    try std.testing.expect(l.key(0x5B, 0x03, 100));
    try std.testing.expect(!l.key(0x5B, 0x02, 200));
    try std.testing.expect(!l.key(0x5B, 0x03, 300)); // held 100 ms
    try std.testing.expect(!l.key(0x5B, 0x02, 400));
    try std.testing.expect(!l.key(0x1E, 0x00, 400)); // Command + A
    try std.testing.expect(!l.key(0x5B, 0x03, 401));
    try std.testing.expect(!l.key(0x5B, 0x00, 500)); // not extended: not the Windows key
    try std.testing.expect(!l.key(0x5B, 0x01, 500));
}
