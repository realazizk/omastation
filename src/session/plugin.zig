//! Loads omastation's optional Hyprland plugin over the IPC: protected windows in the capture, a
//! hardware cursor for absolute motion, frames without the software cursor, `omastation-cursor`.

const std = @import("std");
const c = @import("c");
const hypr = @import("hypr.zig");

const log = std.log.scoped(.plugin);

pub const default_path = "/usr/lib/omastation/omastation-plugin.so";

pub const Outcome = union(enum) {
    loaded,
    already_loaded,
    /// A plugin from an unknown path (handle, hex); Hyprland refuses a second hook on a function.
    other_loaded: []const u8,
    missing,
    /// Not absolute, or not one word.
    bad_path,
    refused: []const u8,
    ipc_failed: hypr.Error,
};

/// Hyprland's reply to `plugin load`: "ok", "Cannot load a plugin twice!", or an error.
pub fn parseLoadReply(reply: []const u8) Outcome {
    const r = std.mem.trim(u8, reply, " \r\n");
    if (std.mem.eql(u8, r, "ok")) return .loaded;
    if (std.mem.indexOf(u8, r, "Cannot load a plugin twice") != null) return .already_loaded;
    return .{ .refused = r };
}

/// `plugin load PATH`; the space before '/' keeps Hyprland's flag parser off the path.
pub fn formatLoad(buf: []u8, path: []const u8) error{ NoSpaceLeft, BadPath }![]const u8 {
    try checkPath(path);
    return std.fmt.bufPrint(buf, "plugin load {s}", .{path});
}

pub fn formatUnload(buf: []u8, path: []const u8) error{ NoSpaceLeft, BadPath }![]const u8 {
    try checkPath(path);
    return std.fmt.bufPrint(buf, "plugin unload {s}", .{path});
}

fn checkPath(path: []const u8) error{BadPath}!void {
    // Hyprland splits requests on spaces: the path must be one word.
    if (path.len == 0 or path[0] != '/') return error.BadPath;
    for (path) |ch| if (ch <= ' ' or ch == 0x7f) return error.BadPath;
}

/// `reply_buf` backs the `.refused` text.
pub fn load(ipc: *const hypr.Ipc, gpa: std.mem.Allocator, path: [:0]const u8, reply_buf: []u8) Outcome {
    var buf: [512]u8 = undefined;
    const req = formatLoad(&buf, path) catch return .bad_path;
    if (c.access(path.ptr, c.R_OK) != 0) return .missing;
    const reply = ipc.request(gpa, req) catch |err| return .{ .ipc_failed = err };
    defer gpa.free(reply);
    return switch (parseLoadReply(reply)) {
        .refused => |r| .{ .refused = reply_buf[0..copyInto(reply_buf, r)] },
        else => |o| o,
    };
}

fn copyInto(dst: []u8, s: []const u8) usize {
    const n = @min(dst.len, s.len);
    @memcpy(dst[0..n], s[0..n]);
    return n;
}

pub fn loadAndReport(ipc: *const hypr.Ipc, gpa: std.mem.Allocator, path: [:0]const u8) Outcome {
    var reply_buf: [400]u8 = undefined;
    const o = load(ipc, gpa, path, &reply_buf);
    report(o, path, path);
    return o;
}

fn report(o: Outcome, src: []const u8, path: []const u8) void {
    var as_buf: [std.fs.max_path_bytes + 8]u8 = undefined;
    const as: []const u8 = if (std.mem.eql(u8, src, path)) "" else std.fmt.bufPrint(&as_buf, " (as {s})", .{path}) catch "";
    switch (o) {
        .loaded => log.info("Hyprland plugin {s} loaded{s}: protected windows show over RDP", .{ src, as }),
        .already_loaded => log.info("Hyprland plugin {s} was loaded already{s}", .{ src, as }),
        .other_loaded => |h| log.warn("a omastation plugin from a path omastation does not know is loaded in Hyprland (handle {s}): {s} not loaded next to it; " ++
            "find its path in /proc/$(pgrep -x Hyprland)/maps, `hyprctl plugin unload PATH`, then restart omastation", .{ h, src }),
        .missing => log.warn("no Hyprland plugin at {s}: protected windows (no_screen_share) stay black over RDP", .{src}),
        .bad_path => log.warn("Hyprland plugin path {s}: must be absolute, without spaces; not loaded", .{path}),
        .refused => |r| log.warn("Hyprland did not load {s}{s}: {s}; protected windows (no_screen_share) stay black over RDP", .{ src, as, r }),
        .ipc_failed => |e| log.warn("Hyprland plugin {s} not loaded: IPC {t}", .{ src, e }),
    }
}

/// Hyprland never truly unloads the first plugin loaded from a path (glibc makes it NODELETE),
/// so each build is loaded from a copy named after its content.
pub const Staging = struct {
    /// $XDG_RUNTIME_DIR/omastation/plugin (0700), copies 0600.
    dir: [:0]const u8,
    /// The loaded path, one line; omastation-recover unloads it.
    state: [:0]const u8,

    pub fn inRuntimeDir(arena: std.mem.Allocator, runtime_dir: []const u8) error{OutOfMemory}!Staging {
        return .{
            .dir = try std.mem.concatWithSentinel(arena, u8, &.{ runtime_dir, "/omastation/plugin" }, 0),
            .state = try std.mem.concatWithSentinel(arena, u8, &.{ runtime_dir, "/omastation/plugin-loaded" }, 0),
        };
    }
};

pub const copy_prefix = "omastation-plugin-";
pub const copy_suffix = ".so";
const digest_hex_len = 32;
pub const copy_name_len = copy_prefix.len + digest_hex_len + copy_suffix.len;
const max_plugin_bytes = 64 * 1024 * 1024;

/// omastation-plugin-<SHA-256 of the content, first 16 bytes, hex>.so
pub fn copyName(buf: *[copy_name_len]u8, content: []const u8) []const u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(content, &digest, .{});
    const hex = std.fmt.bytesToHex(digest[0 .. digest_hex_len / 2], .lower);
    _ = std.fmt.bufPrint(buf, "{s}{s}{s}", .{ copy_prefix, &hex, copy_suffix }) catch unreachable;
    return buf;
}

pub fn isCopyName(name: []const u8) bool {
    if (name.len != copy_name_len or !std.mem.startsWith(u8, name, copy_prefix) or !std.mem.endsWith(u8, name, copy_suffix)) return false;
    for (name[copy_prefix.len..][0..digest_hex_len]) |ch| if (!std.ascii.isDigit(ch) and !(ch >= 'a' and ch <= 'f')) return false;
    return true;
}

pub fn isPluginFileName(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "omastation-plugin") and std.mem.endsWith(u8, name, copy_suffix);
}

pub const StageError = error{ OutOfMemory, DirFailed, NotPrivate, NoExec, ReadFailed, TooBig, WriteFailed };

/// Atomic copy into `dir` under its content name, reusing an identical one; caller frees.
pub fn stage(gpa: std.mem.Allocator, src: [:0]const u8, dir: [:0]const u8) StageError![:0]u8 {
    try makePrivateDir(dir);
    // dlopen maps the plugin executable: not from a noexec mount.
    var vfs: c.struct_statvfs = undefined;
    if (c.statvfs(dir.ptr, &vfs) == 0 and (vfs.f_flag & @as(c_ulong, c.ST_NOEXEC)) != 0) return error.NoExec;
    const data = try readFile(gpa, src, max_plugin_bytes);
    defer gpa.free(data);
    var name_buf: [copy_name_len]u8 = undefined;
    const name = copyName(&name_buf, data);
    const path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ dir, name }, 0);
    errdefer gpa.free(path);
    // An identical copy stays untouched: Hyprland may have it mapped.
    if (!sameFile(gpa, path, data)) try writeFileAtomic(path, data);
    return path;
}

fn sameFile(gpa: std.mem.Allocator, path: [:0]const u8, data: []const u8) bool {
    var st: c.struct_stat = undefined;
    if (c.lstat(path.ptr, &st) != 0 or (st.st_mode & c.S_IFMT) != c.S_IFREG or st.st_uid != c.geteuid()) return false;
    if (st.st_size != @as(@TypeOf(st.st_size), @intCast(data.len))) return false;
    const have = readFile(gpa, path, max_plugin_bytes) catch return false;
    defer gpa.free(have);
    return std.mem.eql(u8, have, data);
}

/// Mode 0700, owned by this user, not a symlink.
pub fn makePrivateDir(path: [:0]const u8) error{ DirFailed, NotPrivate }!void {
    if (c.mkdir(path.ptr, 0o700) != 0 and c.__errno_location().* != c.EEXIST) return error.DirFailed;
    var st: c.struct_stat = undefined;
    if (c.lstat(path.ptr, &st) != 0) return error.DirFailed;
    if ((st.st_mode & c.S_IFMT) != c.S_IFDIR or st.st_uid != c.geteuid()) return error.NotPrivate;
    if ((st.st_mode & 0o077) != 0 and c.chmod(path.ptr, 0o700) != 0) return error.DirFailed;
}

fn readFile(gpa: std.mem.Allocator, path: [:0]const u8, max: usize) error{ OutOfMemory, ReadFailed, TooBig }![]u8 {
    const fd = c.open(path.ptr, c.O_RDONLY | c.O_CLOEXEC);
    if (fd < 0) return error.ReadFailed;
    defer _ = c.close(fd);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    while (true) {
        try out.ensureUnusedCapacity(gpa, 64 * 1024);
        const spare = out.unusedCapacitySlice();
        const n = c.read(fd, spare.ptr, spare.len);
        if (n < 0) {
            if (c.__errno_location().* == c.EINTR) continue;
            return error.ReadFailed;
        }
        if (n == 0) break;
        out.items.len += @intCast(n);
        if (out.items.len > max) return error.TooBig;
    }
    return out.toOwnedSlice(gpa);
}

/// Mode 0600: written next to `path`, synced, renamed over it.
pub fn writeFileAtomic(path: [:0]const u8, data: []const u8) error{WriteFailed}!void {
    var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp = std.fmt.bufPrintSentinel(&tmp_buf, "{s}.{d}.tmp", .{ path, c.getpid() }, 0) catch return error.WriteFailed;
    _ = c.unlink(tmp.ptr);
    const fd = c.open(tmp.ptr, c.O_WRONLY | c.O_CREAT | c.O_EXCL | c.O_CLOEXEC | c.O_NOFOLLOW, @as(c_uint, 0o600));
    if (fd < 0) return error.WriteFailed;
    var done = false;
    defer if (!done) {
        _ = c.unlink(tmp.ptr);
    };
    {
        defer _ = c.close(fd);
        var off: usize = 0;
        while (off < data.len) {
            const n = c.write(fd, data[off..].ptr, data.len - off);
            if (n < 0 and c.__errno_location().* == c.EINTR) continue;
            if (n <= 0) return error.WriteFailed;
            off += @intCast(n);
        }
        if (c.fchmod(fd, 0o600) != 0 or c.fsync(fd) != 0) return error.WriteFailed;
    }
    if (c.rename(tmp.ptr, path.ptr) != 0) return error.WriteFailed;
    done = true;
}

/// Removes copies and leftover temporary files in `dir` except `keep`; returns the count.
pub fn removeCopies(dir: [:0]const u8, keep: ?[]const u8) usize {
    const d = c.opendir(dir.ptr) orelse return 0;
    defer _ = c.closedir(d);
    var removed: usize = 0;
    while (c.readdir(d)) |ent| {
        const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.*.d_name)), 0);
        const ours = isCopyName(name) or (std.mem.startsWith(u8, name, copy_prefix) and std.mem.endsWith(u8, name, ".tmp"));
        if (!ours) continue;
        if (keep) |k| if (std.mem.eql(u8, name, k)) continue;
        var z: [256]u8 = undefined;
        const nz = std.fmt.bufPrintSentinel(&z, "{s}", .{name}, 0) catch continue;
        if (c.unlinkat(c.dirfd(d), nz.ptr, 0) == 0) removed += 1;
    }
    return removed;
}

/// The path recorded in the state file; null unless it is one absolute, space-free line.
pub fn readState(state_path: [:0]const u8, buf: []u8) ?[]const u8 {
    const fd = c.open(state_path.ptr, c.O_RDONLY | c.O_CLOEXEC);
    if (fd < 0) return null;
    defer _ = c.close(fd);
    const n = c.read(fd, buf.ptr, buf.len);
    if (n <= 0 or @as(usize, @intCast(n)) == buf.len) return null;
    return parseState(buf[0..@intCast(n)]);
}

pub fn parseState(text: []const u8) ?[]const u8 {
    const p = if (std.mem.endsWith(u8, text, "\n")) text[0 .. text.len - 1] else text;
    checkPath(p) catch return null;
    return p;
}

pub fn writeState(state_path: [:0]const u8, loaded: []const u8) error{WriteFailed}!void {
    var buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "{s}\n", .{loaded}) catch return error.WriteFailed;
    return writeFileAtomic(state_path, line);
}

/// Plugin file paths in a /proc/PID/maps text, deleted or not, each once. Slices of `maps`.
pub fn mappedPluginPaths(arena: std.mem.Allocator, maps: []const u8) error{OutOfMemory}![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, maps, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        for (0..5) |_| _ = fields.next() orelse break;
        const rest = std.mem.trimStart(u8, fields.rest(), " ");
        if (rest.len == 0 or rest[0] != '/') continue;
        const path = if (std.mem.endsWith(u8, rest, " (deleted)")) rest[0 .. rest.len - " (deleted)".len] else rest;
        if (!isPluginFileName(std.fs.path.basename(path))) continue;
        try appendNew(arena, &out, path);
    }
    return out.items;
}

fn appendNew(arena: std.mem.Allocator, list: *std.ArrayList([]const u8), path: []const u8) error{OutOfMemory}!void {
    for (list.items) |p| if (std.mem.eql(u8, p, path)) return;
    try list.append(arena, path);
}

pub const Loaded = struct { count: usize, handle: []const u8 };

pub fn parseLoaded(arena: std.mem.Allocator, json: []const u8) ?Loaded {
    const P = struct { name: []const u8 = "", handle: []const u8 = "" };
    const list = std.json.parseFromSliceLeaky([]const P, arena, json, .{ .ignore_unknown_fields = true }) catch return null;
    var l: Loaded = .{ .count = 0, .handle = "" };
    for (list) |p| if (std.mem.eql(u8, p.name, "omastation")) {
        l.count += 1;
        l.handle = p.handle;
    };
    return l;
}

/// `plugin list` gives no paths, so every path an earlier run may have loaded is tried.
/// Returns the plugins still loaded, or null if the IPC failed.
fn unloadEarlier(ipc: *const hypr.Ipc, gpa: std.mem.Allocator, arena: std.mem.Allocator, src: []const u8, staging: ?Staging) ?Loaded {
    var pid: c.pid_t = 0;
    const before_json = ipc.requestPeer(arena, "j/plugin list", &pid) catch return null;
    const before = parseLoaded(arena, before_json) orelse return null;
    if (before.count == 0) return before;

    var paths: std.ArrayList([]const u8) = .empty;
    var state_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    if (staging) |s| if (readState(s.state, &state_buf)) |p| appendNew(arena, &paths, p) catch {};
    appendNew(arena, &paths, default_path) catch {};
    appendNew(arena, &paths, src) catch {};
    if (staging) |s| if (c.opendir(s.dir.ptr)) |d| {
        defer _ = c.closedir(d);
        while (c.readdir(d)) |ent| {
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.*.d_name)), 0);
            if (!isCopyName(name)) continue;
            const p = std.fmt.allocPrint(arena, "{s}/{s}", .{ s.dir, name }) catch continue;
            appendNew(arena, &paths, p) catch {};
        }
    };
    if (pid > 0) {
        var maps_path: [64]u8 = undefined;
        const mp = std.fmt.bufPrintSentinel(&maps_path, "/proc/{d}/maps", .{pid}, 0) catch unreachable;
        if (readFile(arena, mp, 16 * 1024 * 1024)) |maps| {
            const mapped = mappedPluginPaths(arena, maps) catch &.{};
            for (mapped) |p| appendNew(arena, &paths, p) catch {};
        } else |_| {}
    }
    for (paths.items) |p| {
        if (unload(ipc, gpa, p) catch false) log.info("unloaded the Hyprland plugin {s} (loaded before this run)", .{p});
    }
    const after_json = ipc.request(arena, "j/plugin list") catch return null;
    return parseLoaded(arena, after_json);
}

/// Unloads earlier plugins, then loads and records a content-named copy of `src`.
/// `text_buf` backs the `.refused` and `.other_loaded` text.
pub fn activate(ipc: *const hypr.Ipc, gpa: std.mem.Allocator, src: [:0]const u8, staging: ?Staging, text_buf: []u8) Outcome {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    checkPath(src) catch {
        report(.bad_path, src, src);
        return .bad_path;
    };
    if (unloadEarlier(ipc, gpa, arena, src, staging)) |left| if (left.count > 0) {
        const o: Outcome = .{ .other_loaded = text_buf[0..copyInto(text_buf, left.handle)] };
        report(o, src, src);
        if (staging) |s| _ = c.unlink(s.state.ptr);
        return o;
    };
    if (c.access(src.ptr, c.R_OK) != 0) {
        report(.missing, src, src);
        if (staging) |s| {
            _ = c.unlink(s.state.ptr);
            _ = removeCopies(s.dir, null);
        }
        return .missing;
    }
    const s = staging orelse {
        const o = load(ipc, gpa, src, text_buf);
        report(o, src, src);
        return o;
    };

    var path: [:0]const u8 = src;
    if (stage(arena, src, s.dir)) |copy| path = copy else |err| {
        log.warn("cannot copy the Hyprland plugin {s} to {s} ({t}): loaded from where it is (Hyprland then keeps running the first build it loaded from there)", .{ src, s.dir, err });
    }
    const o = load(ipc, gpa, path, text_buf);
    report(o, src, path);
    const loaded = o == .loaded or o == .already_loaded;
    if (loaded) {
        writeState(s.state, path) catch |err| log.warn("cannot record the loaded plugin in {s} ({t}): omastation-recover will not unload it", .{ s.state, err });
    } else _ = c.unlink(s.state.ptr);
    const keep: ?[]const u8 = if (loaded and path.ptr != src.ptr) std.fs.path.basename(path) else null;
    const removed = removeCopies(s.dir, keep);
    if (removed > 0) log.debug("removed {d} older plugin copies from {s}", .{ removed, s.dir });
    return o;
}

/// In the plugin's description when RDP frames leave out the software cursor.
pub const rdp_cursor_marker = "[rdp-frames-without-cursor]";

pub fn framesWithoutCursor(ipc: *const hypr.Ipc, gpa: std.mem.Allocator) bool {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const reply = ipc.request(arena.allocator(), "j/plugin list") catch return false;
    return parseFramesWithoutCursor(arena.allocator(), reply);
}

pub fn parseFramesWithoutCursor(arena: std.mem.Allocator, json: []const u8) bool {
    const P = struct { name: []const u8 = "", description: []const u8 = "" };
    const list = std.json.parseFromSliceLeaky([]const P, arena, json, .{ .ignore_unknown_fields = true }) catch return false;
    for (list) |p| {
        if (std.mem.eql(u8, p.name, "omastation") and std.mem.indexOf(u8, p.description, rdp_cursor_marker) != null) return true;
    }
    return false;
}

test "framesWithoutCursor reads the plugin description" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expect(parseFramesWithoutCursor(a,
        \\[
        \\{
        \\    "name": "omastation",
        \\    "author": "omastation",
        \\    "handle": "55d0c3a0",
        \\    "version": "1",
        \\    "description": "protected windows; RDP outputs' frames without the cursor [rdp-frames-without-cursor]"
        \\}]
    ));
    try std.testing.expect(!parseFramesWithoutCursor(a, "[{\"name\": \"omastation\", \"description\": \"protected windows\"}]"));
    try std.testing.expect(!parseFramesWithoutCursor(a, "[{\"name\": \"other\", \"description\": \"[rdp-frames-without-cursor]\"}]"));
    try std.testing.expect(!parseFramesWithoutCursor(a, "[]"));
    try std.testing.expect(!parseFramesWithoutCursor(a, "no plugins loaded"));
}

/// The cursor image Hyprland holds (`hyprctl omastation-cursor`); hotspot in image pixels.
pub const CursorInfo = struct {
    scale: f64,
    hot_x: f64,
    hot_y: f64,
    width: u32,
    height: u32,
    /// False when Hyprland draws no cursor (size then stale); null from an older plugin.
    shown: ?bool = null,
};

pub fn cursorInfo(ipc: *const hypr.Ipc, gpa: std.mem.Allocator) ?CursorInfo {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const reply = ipc.request(arena.allocator(), "j/omastation-cursor") catch return null;
    return parseCursorInfo(reply);
}

/// Parses "SCALE HOTSPOT_X HOTSPOT_Y WIDTH HEIGHT [SHOWN]", SHOWN being 1 or 0.
pub fn parseCursorInfo(reply: []const u8) ?CursorInfo {
    var it = std.mem.tokenizeAny(u8, reply, " \r\n");
    var v: [5]f64 = undefined;
    for (&v) |*x| x.* = std.fmt.parseFloat(f64, it.next() orelse return null) catch return null;
    const shown: ?bool = if (it.next()) |s|
        (if (std.mem.eql(u8, s, "1")) true else if (std.mem.eql(u8, s, "0")) false else return null)
    else
        null;
    if (it.next() != null) return null;
    for (v) |x| if (!std.math.isFinite(x) or @abs(x) > 1e6) return null;
    if (!(v[0] > 0 and v[0] <= 16) or v[3] < 0 or v[4] < 0 or v[3] > 4096 or v[4] > 4096) return null;
    return .{ .scale = v[0], .hot_x = v[1], .hot_y = v[2], .width = @intFromFloat(v[3]), .height = @intFromFloat(v[4]), .shown = shown };
}

test "parseCursorInfo: the plugin's answer, or nothing" {
    // At scale 1.5 the Xcursor theme is loaded at 2.
    const i = parseCursorInfo("2 6 2 48 48").?;
    try std.testing.expectEqual(@as(f64, 2), i.scale);
    try std.testing.expectEqual(@as(f64, 6), i.hot_x);
    try std.testing.expectEqual(@as(u32, 48), i.height);
    try std.testing.expectEqual(@as(f64, 1.5), parseCursorInfo("1.5 4.5 1.5 36 36\n").?.scale);
    try std.testing.expect(parseCursorInfo("unknown request") == null);
    try std.testing.expect(parseCursorInfo("error") == null);
    try std.testing.expect(parseCursorInfo("2 6 2 48") == null);
    try std.testing.expect(parseCursorInfo("0 6 2 48 48") == null);
    try std.testing.expect(parseCursorInfo("nan 6 2 48 48") == null);
    try std.testing.expectEqual(@as(?bool, null), i.shown);
    const x = parseCursorInfo("1 4 8 9 16 1").?;
    try std.testing.expectEqual(@as(?bool, true), x.shown);
    try std.testing.expectEqual(@as(u32, 9), x.width);
    try std.testing.expectEqual(@as(?bool, false), parseCursorInfo("1 0 0 9 16 0\n").?.shown);
    try std.testing.expect(parseCursorInfo("1 4 8 9 16 2") == null);
    try std.testing.expect(parseCursorInfo("1 4 8 9 16 1 7") == null);
}

/// `plugin unload PATH`; true if it was loaded.
pub fn unload(ipc: *const hypr.Ipc, gpa: std.mem.Allocator, path: []const u8) hypr.Error!bool {
    var buf: [512]u8 = undefined;
    const req = formatUnload(&buf, path) catch return false;
    const reply = try ipc.request(gpa, req);
    defer gpa.free(reply);
    return std.mem.eql(u8, std.mem.trim(u8, reply, " \r\n"), "ok");
}

test "Hyprland's answers to plugin load" {
    try std.testing.expect(parseLoadReply("ok") == .loaded);
    try std.testing.expect(parseLoadReply("ok\n") == .loaded);
    try std.testing.expect(parseLoadReply("Cannot load a plugin twice!") == .already_loaded);
    const r = parseLoadReply("Plugin /x.so could not be loaded: plugin crashed/threw in main: omastation plugin: built for another Hyprland");
    try std.testing.expect(r == .refused);
    try std.testing.expect(std.mem.startsWith(u8, r.refused, "Plugin /x.so"));
}

test "plugin requests keep the path one word" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("plugin load /usr/lib/omastation/omastation-plugin.so", try formatLoad(&buf, default_path));
    try std.testing.expectEqualStrings("plugin unload /usr/lib/omastation/omastation-plugin.so", try formatUnload(&buf, default_path));
    try std.testing.expectError(error.BadPath, formatLoad(&buf, "/home/me/my plugins/x.so"));
    try std.testing.expectError(error.BadPath, formatLoad(&buf, "x.so"));
    try std.testing.expectError(error.BadPath, formatLoad(&buf, ""));
    try std.testing.expectError(error.BadPath, formatLoad(&buf, "/a\nb.so"));
}

test "copies are named after their content" {
    var a: [copy_name_len]u8 = undefined;
    var b: [copy_name_len]u8 = undefined;
    try std.testing.expectEqualStrings("omastation-plugin-e3b0c44298fc1c149afbf4c8996fb924.so", copyName(&a, ""));
    try std.testing.expect(isCopyName(copyName(&a, "build 1")));
    try std.testing.expect(!std.mem.eql(u8, copyName(&a, "build 1"), copyName(&b, "build 2")));
    try std.testing.expectEqualStrings(copyName(&a, "build 1"), copyName(&b, "build 1"));
    try std.testing.expect(!isCopyName("omastation-plugin.so"));
    try std.testing.expect(!isCopyName("omastation-plugin-r425-6a1a272.so"));
    try std.testing.expect(!isCopyName("omastation-plugin-E3B0C44298FC1C149AFBF4C8996FB924.so"));
    try std.testing.expect(isPluginFileName("omastation-plugin.so"));
    try std.testing.expect(isPluginFileName("omastation-plugin-r425-6a1a272.so"));
    try std.testing.expect(!isPluginFileName("libomastation-plugin.so"));
    try std.testing.expect(!isPluginFileName("omastation-plugin.so.tmp"));
}

test "the state file: one absolute path, or nothing" {
    try std.testing.expectEqualStrings("/run/user/1000/omastation/plugin/x.so", parseState("/run/user/1000/omastation/plugin/x.so\n").?);
    try std.testing.expectEqualStrings("/a.so", parseState("/a.so").?);
    try std.testing.expect(parseState("") == null);
    try std.testing.expect(parseState("\n") == null);
    try std.testing.expect(parseState("a.so\n") == null);
    try std.testing.expect(parseState("/a b.so\n") == null);
    try std.testing.expect(parseState("/a.so\n/b.so\n") == null);
}

test "mappedPluginPaths lists each plugin file once" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const maps =
        \\5616a0000000-5616a0100000 r--p 00000000 00:1f 1234 /usr/bin/Hyprland
        \\7f0000000000-7f0000010000 r--p 00000000 00:1f 99 /usr/lib/omastation/omastation-plugin.so (deleted)
        \\7f0000010000-7f0000020000 r-xp 00010000 00:1f 99 /usr/lib/omastation/omastation-plugin.so (deleted)
        \\7f0000100000-7f0000110000 r--p 00000000 00:2a 77 /home/u/.local/share/omastation/plugin/omastation-plugin-r425-6a1a272.so
        \\7f0000200000-7f0000210000 r--p 00000000 00:2b 78 /run/user/1000/omastation/plugin/omastation-plugin-e3b0c44298fc1c149afbf4c8996fb924.so
        \\7f0000300000-7f0000310000 r--p 00000000 00:1f 55 /usr/lib/libomastation-plugin.so
        \\7f0000400000-7f0000410000 rw-p 00000000 00:00 0
        \\7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0                          [stack]
        \\7f0000500000-7f0000510000 r--p 00000000 00:1f 56 /opt/my plugins/omastation-plugin.so
    ;
    const got = try mappedPluginPaths(arena.allocator(), maps);
    try std.testing.expectEqual(@as(usize, 4), got.len);
    try std.testing.expectEqualStrings("/usr/lib/omastation/omastation-plugin.so", got[0]);
    try std.testing.expectEqualStrings("/home/u/.local/share/omastation/plugin/omastation-plugin-r425-6a1a272.so", got[1]);
    try std.testing.expectEqualStrings("/run/user/1000/omastation/plugin/omastation-plugin-e3b0c44298fc1c149afbf4c8996fb924.so", got[2]);
    try std.testing.expectEqualStrings("/opt/my plugins/omastation-plugin.so", got[3]);
}

test "omastation plugins in the plugin list" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const one = parseLoaded(a,
        \\[{"name": "hyprbars", "author": "x", "handle": "11", "version": "1", "description": ""},
        \\{"name": "omastation", "author": "omastation", "handle": "55d0c3a0", "version": "1", "description": "old"}]
    ).?;
    try std.testing.expectEqual(@as(usize, 1), one.count);
    try std.testing.expectEqualStrings("55d0c3a0", one.handle);
    try std.testing.expectEqual(@as(usize, 0), parseLoaded(a, "[]").?.count);
    try std.testing.expect(parseLoaded(a, "no plugins loaded") == null);
}

const TestDir = struct {
    tmp: std.testing.TmpDir,
    abs: [std.fs.max_path_bytes:0]u8 = undefined,
    len: usize = 0,

    fn init() !TestDir {
        var d: TestDir = .{ .tmp = std.testing.tmpDir(.{}) };
        var rel: [64]u8 = undefined;
        const r = try std.fmt.bufPrintSentinel(&rel, ".zig-cache/tmp/{s}", .{&d.tmp.sub_path}, 0);
        if (c.realpath(r.ptr, &d.abs) == null) return error.RealpathFailed;
        d.len = std.mem.len(@as([*:0]u8, &d.abs));
        return d;
    }

    fn path(d: *const TestDir, buf: []u8, name: []const u8) ![:0]u8 {
        return std.fmt.bufPrintSentinel(buf, "{s}/{s}", .{ d.abs[0..d.len], name }, 0);
    }

    fn deinit(d: *TestDir) void {
        d.tmp.cleanup();
    }
};

fn statOf(path: [:0]const u8) !c.struct_stat {
    var st: c.struct_stat = undefined;
    if (c.lstat(path.ptr, &st) != 0) return error.StatFailed;
    return st;
}

test "stage makes a private content-named copy and reuses an identical one" {
    var d = try TestDir.init();
    defer d.deinit();
    var b1: [std.fs.max_path_bytes]u8 = undefined;
    var b2: [std.fs.max_path_bytes]u8 = undefined;
    const src = try d.path(&b1, "omastation-plugin.so");
    const dir = try d.path(&b2, "plugin");
    try writeFileAtomic(src, "build 1");

    const p1 = try stage(std.testing.allocator, src, dir);
    defer std.testing.allocator.free(p1);
    var nb: [copy_name_len]u8 = undefined;
    try std.testing.expectEqualStrings(copyName(&nb, "build 1"), std.fs.path.basename(p1));
    try std.testing.expectEqualStrings(dir, std.fs.path.dirname(p1).?);
    const st1 = try statOf(p1);
    try std.testing.expectEqual(@as(c_uint, 0o600), st1.st_mode & 0o777);
    try std.testing.expectEqual(@as(c_uint, 0o700), (try statOf(dir)).st_mode & 0o777);
    const got = try readFile(std.testing.allocator, p1, 1024);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("build 1", got);

    const p2 = try stage(std.testing.allocator, src, dir);
    defer std.testing.allocator.free(p2);
    try std.testing.expectEqualStrings(p1, p2);
    try std.testing.expectEqual(st1.st_ino, (try statOf(p2)).st_ino);

    // An upgrade (a new file renamed over src): another path.
    try writeFileAtomic(src, "build 2");
    const p3 = try stage(std.testing.allocator, src, dir);
    defer std.testing.allocator.free(p3);
    try std.testing.expect(!std.mem.eql(u8, p1, p3));
    try std.testing.expectEqualStrings(copyName(&nb, "build 2"), std.fs.path.basename(p3));

    // A damaged copy under the right name is written again.
    try writeFileAtomic(p3, "build");
    const p4 = try stage(std.testing.allocator, src, dir);
    defer std.testing.allocator.free(p4);
    const again = try readFile(std.testing.allocator, p4, 1024);
    defer std.testing.allocator.free(again);
    try std.testing.expectEqualStrings("build 2", again);

    var b3: [std.fs.max_path_bytes]u8 = undefined;
    try writeFileAtomic(try d.path(&b3, "plugin/omastation-plugin-0123456789abcdef0123456789abcdef.so.77.tmp"), "half");
    try writeFileAtomic(try d.path(&b3, "plugin/notes.txt"), "mine");
    try std.testing.expectEqual(@as(usize, 2), removeCopies(dir, std.fs.path.basename(p3)));
    try std.testing.expect(c.access(p3.ptr, c.F_OK) == 0);
    try std.testing.expect(c.access(p1.ptr, c.F_OK) != 0);
    try std.testing.expect(c.access((try d.path(&b3, "plugin/notes.txt")).ptr, c.F_OK) == 0);
    try std.testing.expectEqual(@as(usize, 1), removeCopies(dir, null));
    try std.testing.expect(c.access(p3.ptr, c.F_OK) != 0);

    var b4: [std.fs.max_path_bytes]u8 = undefined;
    try std.testing.expectError(error.ReadFailed, stage(std.testing.allocator, try d.path(&b4, "missing.so"), dir));
}

test "makePrivateDir fixes the mode and rejects links" {
    var d = try TestDir.init();
    defer d.deinit();
    var b: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try d.path(&b, "plugin");
    try std.testing.expectEqual(@as(c_int, 0), c.mkdir(dir.ptr, 0o755));
    try makePrivateDir(dir);
    try std.testing.expectEqual(@as(c_uint, 0o700), (try statOf(dir)).st_mode & 0o777);
    var l: [std.fs.max_path_bytes]u8 = undefined;
    const link = try d.path(&l, "link");
    try std.testing.expectEqual(@as(c_int, 0), c.symlink(dir.ptr, link.ptr));
    try std.testing.expectError(error.NotPrivate, makePrivateDir(link));
}

test "the state file is written whole and read back" {
    var d = try TestDir.init();
    defer d.deinit();
    var b: [std.fs.max_path_bytes]u8 = undefined;
    const state = try d.path(&b, "plugin-loaded");
    var buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    try std.testing.expect(readState(state, &buf) == null);
    try writeState(state, "/run/user/1000/omastation/plugin/omastation-plugin-e3b0c44298fc1c149afbf4c8996fb924.so");
    try std.testing.expectEqualStrings("/run/user/1000/omastation/plugin/omastation-plugin-e3b0c44298fc1c149afbf4c8996fb924.so", readState(state, &buf).?);
    try std.testing.expectEqual(@as(c_uint, 0o600), (try statOf(state)).st_mode & 0o777);
    try writeState(state, "/b.so");
    try std.testing.expectEqualStrings("/b.so", readState(state, &buf).?);
}
