//! Hyprland control over its IPC socket: one request per connection, response
//! read until EOF. Creates and sizes the headless RDP outputs and switches the
//! physical monitors off and back on.

const std = @import("std");
const c = @import("c");

const log = std.log.scoped(.hypr);

pub const Error = error{ NoHyprland, IpcFailed, BadResponse, CommandFailed, OutOfMemory };

pub const Ipc = struct {
    path_buf: [256]u8 = undefined,
    path_len: usize = 0,
    /// Deadline for a whole `request`, from connect to the last response byte.
    timeout_ms: u32 = 5000,

    pub fn fromEnv(env: *const std.process.Environ.Map) Error!Ipc {
        const rt = env.get("XDG_RUNTIME_DIR") orelse return error.NoHyprland;
        const sig = env.get("HYPRLAND_INSTANCE_SIGNATURE") orelse return error.NoHyprland;
        var ipc = Ipc{};
        const p = std.fmt.bufPrint(&ipc.path_buf, "{s}/hypr/{s}/.socket.sock", .{ rt, sig }) catch return error.NoHyprland;
        ipc.path_len = p.len;
        return ipc;
    }

    /// Connect to the event socket (.socket2.sock): one line per event, `name>>data`.
    pub fn connectEvents(ipc: *const Ipc) Error!c_int {
        const path = ipc.path_buf[0..ipc.path_len];
        const dir_end = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.IpcFailed;
        var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
        addr.sun_family = c.AF_UNIX;
        const sun_path: []u8 = @as([*]u8, @ptrCast(&addr.sun_path))[0 .. addr.sun_path.len - 1];
        _ = std.fmt.bufPrint(sun_path, "{s}/.socket2.sock", .{path[0..dir_end]}) catch return error.IpcFailed;
        const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM | c.SOCK_CLOEXEC | c.SOCK_NONBLOCK, 0);
        if (fd < 0) return error.IpcFailed;
        if (c.connect(fd, .{ .__sockaddr__ = @ptrCast(&addr) }, @sizeOf(c.struct_sockaddr_un)) != 0) {
            _ = c.close(fd);
            return error.IpcFailed;
        }
        return fd;
    }

    /// Send one command; returns the full response (caller frees).
    pub fn request(ipc: *const Ipc, gpa: std.mem.Allocator, cmd: []const u8) Error![]u8 {
        return ipc.requestFrom(gpa, cmd, null);
    }

    /// `request`, plus the answering process (SO_PEERCRED: the running Hyprland) in `peer_pid`.
    pub fn requestPeer(ipc: *const Ipc, gpa: std.mem.Allocator, cmd: []const u8, peer_pid: *c.pid_t) Error![]u8 {
        return ipc.requestFrom(gpa, cmd, peer_pid);
    }

    fn requestFrom(ipc: *const Ipc, gpa: std.mem.Allocator, cmd: []const u8, peer_pid: ?*c.pid_t) Error![]u8 {
        // connect() blocks on a full accept backlog, bounded only by SO_SNDTIMEO.
        const deadline = nowMs() + ipc.timeout_ms;
        const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM | c.SOCK_CLOEXEC, 0);
        if (fd < 0) return error.IpcFailed;
        defer _ = c.close(fd);
        var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
        addr.sun_family = c.AF_UNIX;
        if (ipc.path_len >= addr.sun_path.len) return error.IpcFailed;
        @memcpy(addr.sun_path[0..ipc.path_len], ipc.path_buf[0..ipc.path_len]);
        try sendTimeout(fd, deadline);
        if (c.connect(fd, .{ .__sockaddr__ = @ptrCast(&addr) }, @sizeOf(c.struct_sockaddr_un)) != 0) return error.IpcFailed;
        if (peer_pid) |p| {
            var cred: c.struct_ucred = undefined;
            var len: c.socklen_t = @sizeOf(c.struct_ucred);
            p.* = if (c.getsockopt(fd, c.SOL_SOCKET, c.SO_PEERCRED, &cred, &len) == 0) cred.pid else 0;
        }
        try sendTimeout(fd, deadline);
        if (c.send(fd, cmd.ptr, cmd.len, c.MSG_NOSIGNAL) != @as(isize, @intCast(cmd.len))) return error.IpcFailed;
        // Hyprland reads in 1024-byte chunks and waits for more when a read fills its buffer.
        _ = c.shutdown(fd, c.SHUT_WR);

        const max_len = 16 * 1024 * 1024;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        while (true) {
            if (out.items.len == out.capacity) {
                if (out.items.len > max_len) return error.BadResponse;
                try out.ensureTotalCapacityPrecise(gpa, @min(max_len + 1, @max(16384, out.capacity * 2)));
            }
            const left = deadline - nowMs();
            if (left <= 0) return error.IpcFailed;
            var pfd: c.struct_pollfd = .{ .fd = fd, .events = c.POLLIN, .revents = 0 };
            const ready = c.poll(&pfd, 1, @intCast(@min(left, std.math.maxInt(c_int))));
            if (ready < 0 and c.__errno_location().* == c.EINTR) continue;
            if (ready <= 0) return error.IpcFailed; // no answer in time
            const spare = out.unusedCapacitySlice();
            const n = c.recv(fd, spare.ptr, spare.len, 0);
            if (n < 0) return error.IpcFailed;
            if (n == 0) break;
            out.items.len += @intCast(n);
        }
        if (out.items.len > max_len) return error.BadResponse;
        return out.toOwnedSlice(gpa);
    }

    fn sendTimeout(fd: c_int, deadline: i64) Error!void {
        const left = deadline - nowMs();
        if (left <= 0) return error.IpcFailed;
        const tv: c.struct_timeval = .{ .tv_sec = @intCast(@divTrunc(left, 1000)), .tv_usec = @intCast(@mod(left, 1000) * 1000) };
        if (c.setsockopt(fd, c.SOL_SOCKET, c.SO_SNDTIMEO, &tv, @sizeOf(c.struct_timeval)) != 0) return error.IpcFailed;
    }

    /// A command whose success response is "ok".
    pub fn command(ipc: *const Ipc, gpa: std.mem.Allocator, cmd: []const u8) Error!void {
        const resp = try ipc.request(gpa, cmd);
        defer gpa.free(resp);
        if (!std.mem.eql(u8, std.mem.trim(u8, resp, " \n"), "ok")) {
            log.err("hyprland rejected `{s}`: {s}", .{ cmd, resp[0..@min(resp.len, 200)] });
            return error.CommandFailed;
        }
    }

    /// Non-blocking `request`: sent at once, the response is read with Pending.poll.
    pub fn begin(ipc: *const Ipc, cmd: []const u8) Error!Pending {
        const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM | c.SOCK_CLOEXEC | c.SOCK_NONBLOCK, 0);
        if (fd < 0) return error.IpcFailed;
        errdefer _ = c.close(fd);
        var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
        addr.sun_family = c.AF_UNIX;
        if (ipc.path_len == 0 or ipc.path_len >= addr.sun_path.len) return error.IpcFailed;
        @memcpy(addr.sun_path[0..ipc.path_len], ipc.path_buf[0..ipc.path_len]);
        // A Unix socket connects at once, or fails (EAGAIN: a full backlog).
        if (c.connect(fd, .{ .__sockaddr__ = @ptrCast(&addr) }, @sizeOf(c.struct_sockaddr_un)) != 0) return error.IpcFailed;
        // A short request fits the socket buffer: sent whole or not at all.
        if (c.send(fd, cmd.ptr, cmd.len, c.MSG_NOSIGNAL) != @as(isize, @intCast(cmd.len))) return error.IpcFailed;
        _ = c.shutdown(fd, c.SHUT_WR); // end of request, as `request`
        return .{ .fd = fd };
    }
};

pub const Pending = struct {
    fd: c_int,
    out: std.ArrayList(u8) = .empty,

    /// The whole response once Hyprland closes (valid until deinit), null while it is coming; never waits.
    pub fn poll(p: *Pending, gpa: std.mem.Allocator) Error!?[]const u8 {
        const max_len = 16 * 1024 * 1024;
        while (true) {
            if (p.out.items.len == p.out.capacity) {
                if (p.out.items.len > max_len) return error.BadResponse;
                try p.out.ensureTotalCapacityPrecise(gpa, @min(max_len + 1, @max(16384, p.out.capacity * 2)));
            }
            const spare = p.out.unusedCapacitySlice();
            const n = c.recv(p.fd, spare.ptr, spare.len, 0);
            if (n == 0) break;
            if (n < 0) {
                const e = c.__errno_location().*;
                if (e == c.EINTR) continue;
                if (e == c.EAGAIN) return null;
                return error.IpcFailed;
            }
            p.out.items.len += @intCast(n);
        }
        if (p.out.items.len > max_len) return error.BadResponse;
        return p.out.items;
    }

    pub fn deinit(p: *Pending, gpa: std.mem.Allocator) void {
        _ = c.close(p.fd);
        p.out.deinit(gpa);
    }
};

fn nowMs() i64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(i64, ts.tv_sec) * 1000 + @divTrunc(@as(i64, ts.tv_nsec), 1_000_000);
}

pub const MonitorState = struct {
    name: []const u8,
    width: u32,
    height: u32,
    refresh: f64,
    x: i32,
    y: i32,
    scale: f64,
    transform: u8,
    disabled: bool,
    workspace: []const u8,
    workspace_id: i64 = 0,
    focused: bool = false,
    dpms: bool = true,
    /// Monitor id (what `j/clients` reports as a window's "monitor").
    id: i64 = -1,
    /// Special workspace shown over the active one (id 0: none).
    special_workspace: []const u8 = "",
    special_workspace_id: i64 = 0,
};

/// Must be a JSON number: std.json also parses strings with parseFloat, which can panic.
pub fn JsonNum(comptime T: type) type {
    return struct {
        v: T,

        pub fn jsonParse(gpa: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !@This() {
            if (try source.peekNextTokenType() != .number) return error.UnexpectedToken;
            return .{ .v = try std.json.innerParse(T, gpa, source, options) };
        }
    };
}

/// A string field that must be a JSON string (std.json would also accept an array of numbers).
pub const JsonStr = struct {
    s: []const u8 = "",

    pub fn jsonParse(gpa: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !JsonStr {
        if (try source.peekNextTokenType() != .string) return error.UnexpectedToken;
        return .{ .s = try std.json.innerParse([]const u8, gpa, source, options) };
    }
};

const JsonMonitor = struct {
    id: JsonNum(i64) = .{ .v = -1 },
    name: JsonStr,
    width: JsonNum(u32),
    height: JsonNum(u32),
    refreshRate: JsonNum(f64),
    x: JsonNum(i32),
    y: JsonNum(i32),
    scale: JsonNum(f64),
    transform: JsonNum(u8) = .{ .v = 0 },
    disabled: bool = false,
    activeWorkspace: struct { id: JsonNum(i64) = .{ .v = 0 }, name: JsonStr = .{} } = .{},
    specialWorkspace: struct { id: JsonNum(i64) = .{ .v = 0 }, name: JsonStr = .{} } = .{},
    focused: bool = false,
    dpmsStatus: bool = true,
};

/// Replaces invalid UTF-8 with '?': Hyprland's JSON can carry raw bytes (Latin-1 X11 titles).
fn utf8Clean(arena: std.mem.Allocator, json: []const u8) Error![]const u8 {
    if (std.unicode.utf8ValidateSlice(json)) return json;
    var out = try arena.alloc(u8, json.len);
    var i: usize = 0;
    while (i < json.len) {
        const n = std.unicode.utf8ByteSequenceLength(json[i]) catch 0;
        if (n != 0 and i + n <= json.len and std.unicode.utf8ValidateSlice(json[i .. i + n])) {
            @memcpy(out[i .. i + n], json[i .. i + n]);
            i += n;
        } else {
            out[i] = '?';
            i += 1;
        }
    }
    return out;
}

fn jsonError(err: anyerror) Error {
    return if (err == error.OutOfMemory) error.OutOfMemory else error.BadResponse;
}

/// Parse `j/monitors all`. The result's strings live in `arena`.
pub fn parseMonitors(arena: std.mem.Allocator, json_in: []const u8) Error![]MonitorState {
    const json = try utf8Clean(arena, json_in);
    const parsed = std.json.parseFromSliceLeaky([]JsonMonitor, arena, json, .{ .ignore_unknown_fields = true }) catch |err| return jsonError(err);
    const out = try arena.alloc(MonitorState, parsed.len);
    for (parsed, out) |m, *o| o.* = .{
        .name = m.name.s,
        .width = m.width.v,
        .height = m.height.v,
        .refresh = m.refreshRate.v,
        .x = m.x.v,
        .y = m.y.v,
        .scale = m.scale.v,
        .transform = m.transform.v,
        .disabled = m.disabled,
        .workspace = m.activeWorkspace.name.s,
        .workspace_id = m.activeWorkspace.id.v,
        .focused = m.focused,
        .dpms = m.dpmsStatus,
        .id = m.id.v,
        .special_workspace = m.specialWorkspace.name.s,
        .special_workspace_id = m.specialWorkspace.id.v,
    };
    return out;
}

pub fn monitors(ipc: *const Ipc, arena: std.mem.Allocator) Error![]MonitorState {
    const resp = try ipc.request(arena, "j/monitors all");
    return parseMonitors(arena, resp);
}

/// Outputs this server creates (never treated as physical).
pub fn isRdpOutput(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "RDP-");
}

/// Hyprland's built-in placeholder when no real output is enabled.
pub fn isFallback(name: []const u8) bool {
    return std.mem.eql(u8, name, "FALLBACK");
}

pub const WorkspaceState = struct {
    id: i64,
    name: []const u8,
    monitor: []const u8,
    windows: u32 = 0,

    /// Special (scratchpad) workspaces follow their monitor and are left alone.
    pub fn isSpecial(w: WorkspaceState) bool {
        return std.mem.startsWith(u8, w.name, "special:");
    }
};

const JsonWorkspace = struct { id: JsonNum(i64), name: JsonStr, monitor: JsonStr = .{}, windows: JsonNum(u32) = .{ .v = 0 } };

/// Parse `j/workspaces`. The result's strings live in `arena`.
pub fn parseWorkspaces(arena: std.mem.Allocator, json_in: []const u8) Error![]WorkspaceState {
    const json = try utf8Clean(arena, json_in);
    const parsed = std.json.parseFromSliceLeaky([]JsonWorkspace, arena, json, .{ .ignore_unknown_fields = true }) catch |err| return jsonError(err);
    const out = try arena.alloc(WorkspaceState, parsed.len);
    for (parsed, out) |w, *o| o.* = .{ .id = w.id.v, .name = w.name.s, .monitor = w.monitor.s, .windows = w.windows.v };
    return out;
}

pub fn workspaces(ipc: *const Ipc, arena: std.mem.Allocator) Error![]WorkspaceState {
    const resp = try ipc.request(arena, "j/workspaces");
    return parseWorkspaces(arena, resp);
}

/// One `j/clients` entry; geometry is the layout's goal in global logical coordinates, no border.
pub const ClientState = struct {
    /// The window's address: event data and `address:0x...` selectors.
    address: u64,
    /// Tells a new window from an old one at a reused address.
    stable_id: u64 = 0,
    mapped: bool = true,
    /// Grouped windows other than the group's current tab.
    hidden: bool = false,
    x: i32 = 0,
    y: i32 = 0,
    width: i32 = 0,
    height: i32 = 0,
    workspace_id: i64 = 0,
    workspace: []const u8 = "",
    floating: bool = false,
    monitor: i64 = -1,
    class: []const u8 = "",
    title: []const u8 = "",
    initial_class: []const u8 = "",
    initial_title: []const u8 = "",
    pid: i64 = 0,
    xwayland: bool = false,
    pinned: bool = false,
    /// 0 none, 1 maximized, 2 fullscreen.
    fullscreen: u8 = 0,
    /// Position in the focus history, 0 = most recently focused.
    focus_history_id: i64 = -1,
};

const JsonClient = struct {
    address: JsonStr,
    mapped: bool = true,
    hidden: bool = false,
    at: [2]JsonNum(i64) = .{ .{ .v = 0 }, .{ .v = 0 } },
    size: [2]JsonNum(i64) = .{ .{ .v = 0 }, .{ .v = 0 } },
    workspace: struct { id: JsonNum(i64) = .{ .v = 0 }, name: JsonStr = .{} } = .{},
    floating: bool = false,
    monitor: JsonNum(i64) = .{ .v = -1 },
    class: JsonStr = .{},
    title: JsonStr = .{},
    initialClass: JsonStr = .{},
    initialTitle: JsonStr = .{},
    pid: JsonNum(i64) = .{ .v = 0 },
    xwayland: bool = false,
    pinned: bool = false,
    fullscreen: JsonNum(i64) = .{ .v = 0 },
    focusHistoryID: JsonNum(i64) = .{ .v = -1 },
    stableId: JsonStr = .{ .s = "0" },
};

/// `0x` + lowercase hex in `j/clients`, bare hex in event data; null for anything else.
pub fn parseAddress(s: []const u8) ?u64 {
    const digits = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    if (digits.len == 0 or digits.len > 16) return null;
    for (digits) |ch| if (!std.ascii.isHex(ch)) return null;
    return std.fmt.parseInt(u64, digits, 16) catch null;
}

fn clampI32(v: i64) i32 {
    return @intCast(std.math.clamp(v, std.math.minInt(i32), std.math.maxInt(i32)));
}

fn clientFromJson(j: JsonClient) Error!ClientState {
    return .{
        .address = parseAddress(j.address.s) orelse return error.BadResponse,
        .stable_id = parseAddress(j.stableId.s) orelse 0,
        .mapped = j.mapped,
        .hidden = j.hidden,
        .x = clampI32(j.at[0].v),
        .y = clampI32(j.at[1].v),
        .width = clampI32(j.size[0].v),
        .height = clampI32(j.size[1].v),
        .workspace_id = j.workspace.id.v,
        .workspace = j.workspace.name.s,
        .floating = j.floating,
        .monitor = j.monitor.v,
        .class = j.class.s,
        .title = j.title.s,
        .initial_class = j.initialClass.s,
        .initial_title = j.initialTitle.s,
        .pid = j.pid.v,
        .xwayland = j.xwayland,
        .pinned = j.pinned,
        .fullscreen = @intCast(std.math.clamp(j.fullscreen.v, 0, 2)),
        .focus_history_id = j.focusHistoryID.v,
    };
}

/// Parse `j/clients` (window list order); strings live in `arena`.
pub fn parseClients(arena: std.mem.Allocator, json_in: []const u8) Error![]ClientState {
    const json = try utf8Clean(arena, json_in);
    const parsed = std.json.parseFromSliceLeaky([]JsonClient, arena, json, .{ .ignore_unknown_fields = true }) catch |err| return jsonError(err);
    const out = try arena.alloc(ClientState, parsed.len);
    for (parsed, out) |j, *o| o.* = try clientFromJson(j);
    return out;
}

/// Parse `j/activewindow` (`{}` when nothing has focus). Returns the address.
pub fn parseActiveWindow(arena: std.mem.Allocator, json_in: []const u8) Error!?u64 {
    const json = try utf8Clean(arena, json_in);
    const A = struct { address: ?JsonStr = null };
    const a = std.json.parseFromSliceLeaky(A, arena, json, .{ .ignore_unknown_fields = true }) catch |err| return jsonError(err);
    const s = a.address orelse return null;
    return parseAddress(s.s) orelse error.BadResponse;
}

pub fn clients(ipc: *const Ipc, arena: std.mem.Allocator) Error![]ClientState {
    const resp = try ipc.request(arena, "j/clients");
    return parseClients(arena, resp);
}

pub fn activeWindow(ipc: *const Ipc, arena: std.mem.Allocator) Error!?u64 {
    const resp = try ipc.request(arena, "j/activewindow");
    return parseActiveWindow(arena, resp);
}

/// Followed events ("name>>data", data cut at 1024 bytes); strings point into the line.
pub const Event = union(enum) {
    /// openwindow>>ADDR,... (only the address is unambiguous: names may contain commas).
    open_window: u64,
    /// closewindow>>ADDR
    close_window: u64,
    /// movewindowv2>>ADDR,WSID,WSNAME
    move_window: struct { address: u64, workspace_id: i64, workspace: []const u8 },
    /// activewindowv2>>ADDR, or empty when nothing has focus.
    active_window: ?u64,
    /// windowtitlev2>>ADDR,TITLE
    window_title: struct { address: u64, title: []const u8 },
    /// changefloatingmode>>ADDR,0|1
    floating: struct { address: u64, floating: bool },
    /// fullscreen>>0|1 (the focused window's workspace).
    fullscreen: bool,
    /// minimized>>ADDR,0|1 (a foreign-toplevel request Hyprland does not act on).
    minimized: struct { address: u64, minimized: bool },
    /// pin>>ADDR,0|1
    pin: struct { address: u64, pinned: bool },
    /// Workspace, monitor and group changes that move windows in or out of view.
    layout: []const u8,
    /// Anything else (v1 duplicates of the v2 events included): the name.
    other: []const u8,
};

const layout_events = [_][]const u8{
    "workspacev2",       "focusedmonv2",       "moveworkspacev2", "activespecialv2",
    "createworkspacev2", "destroyworkspacev2", "renameworkspace", "changeworkspaceid",
    "monitoraddedv2",    "monitorremovedv2",   "moveintogroup",   "moveoutofgroup",
    "togglegroup",       "configreloaded",     "monitoradded",    "monitorremoved",
};

/// One event line without its newline; error.BadResponse when malformed.
pub fn parseEvent(line: []const u8) Error!Event {
    const sep = std.mem.indexOf(u8, line, ">>") orelse return error.BadResponse;
    const name = line[0..sep];
    const data = line[sep + 2 ..];
    const eql = std.mem.eql;
    if (eql(u8, name, "openwindow")) return .{ .open_window = try addressField(data) };
    if (eql(u8, name, "closewindow")) return .{ .close_window = try addressField(data) };
    if (eql(u8, name, "activewindowv2")) {
        if (data.len == 0) return .{ .active_window = null };
        return .{ .active_window = try addressField(data) };
    }
    if (eql(u8, name, "windowtitlev2")) {
        const comma = std.mem.indexOfScalar(u8, data, ',') orelse return error.BadResponse;
        return .{ .window_title = .{ .address = try addressField(data[0..comma]), .title = data[comma + 1 ..] } };
    }
    if (eql(u8, name, "movewindowv2")) {
        const c1 = std.mem.indexOfScalar(u8, data, ',') orelse return error.BadResponse;
        const rest = data[c1 + 1 ..];
        const c2 = std.mem.indexOfScalar(u8, rest, ',') orelse return error.BadResponse;
        const id = std.fmt.parseInt(i64, rest[0..c2], 10) catch return error.BadResponse;
        return .{ .move_window = .{ .address = try addressField(data[0..c1]), .workspace_id = id, .workspace = rest[c2 + 1 ..] } };
    }
    if (eql(u8, name, "changefloatingmode")) {
        const f = try addressFlag(data);
        return .{ .floating = .{ .address = f.address, .floating = f.flag } };
    }
    if (eql(u8, name, "minimized")) {
        const f = try addressFlag(data);
        return .{ .minimized = .{ .address = f.address, .minimized = f.flag } };
    }
    if (eql(u8, name, "pin")) {
        const f = try addressFlag(data);
        return .{ .pin = .{ .address = f.address, .pinned = f.flag } };
    }
    if (eql(u8, name, "fullscreen")) return .{ .fullscreen = try flagField(data) };
    for (layout_events) |l| if (eql(u8, name, l)) return .{ .layout = name };
    return .{ .other = name };
}

fn addressField(data: []const u8) Error!u64 {
    const end = std.mem.indexOfScalar(u8, data, ',') orelse data.len;
    return parseAddress(data[0..end]) orelse error.BadResponse;
}

fn flagField(s: []const u8) Error!bool {
    if (std.mem.eql(u8, s, "1")) return true;
    if (std.mem.eql(u8, s, "0")) return false;
    return error.BadResponse;
}

fn addressFlag(data: []const u8) Error!struct { address: u64, flag: bool } {
    const comma = std.mem.indexOfScalar(u8, data, ',') orelse return error.BadResponse;
    return .{ .address = parseAddress(data[0..comma]) orelse return error.BadResponse, .flag = try flagField(data[comma + 1 ..]) };
}

pub fn windowSelector(buf: []u8, address: u64) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buf, "address:0x{x}", .{address});
}

/// `fields`: Lua table content ending in ", " (or empty), strings already luaString literals.
fn formatWindowAction(buf: []u8, action: []const u8, fields: []const u8, address: u64) error{NoSpaceLeft}![]const u8 {
    var sel_buf: [40]u8 = undefined;
    var q: [64]u8 = undefined;
    const sel = try luaString(&q, try windowSelector(&sel_buf, address));
    return std.fmt.bufPrint(buf, "eval hl.dispatch(hl.dsp.{s}({{ {s}window = {s} }}))", .{ action, fields, sel });
}

pub fn formatFocusWindow(buf: []u8, address: u64) error{NoSpaceLeft}![]const u8 {
    return formatWindowAction(buf, "focus", "", address);
}

/// Ask a window to close (`hl.dsp.window.close`: xdg_toplevel.close).
pub fn formatCloseWindow(buf: []u8, address: u64) error{NoSpaceLeft}![]const u8 {
    return formatWindowAction(buf, "window.close", "", address);
}

/// Without following it; `workspace` is a selector (an id, `name:...` or `special:...`).
pub fn formatMoveWindowToWorkspace(buf: []u8, address: u64, workspace: []const u8) error{NoSpaceLeft}![]const u8 {
    var q: [600]u8 = undefined;
    var f: [700]u8 = undefined;
    const fields = try std.fmt.bufPrint(&f, "workspace = {s}, follow = false, ", .{try luaString(&q, workspace)});
    return formatWindowAction(buf, "window.move", fields, address);
}

pub const FullscreenMode = enum { maximized, fullscreen };
pub const FullscreenAction = enum { set, unset };

pub fn formatFullscreenWindow(buf: []u8, address: u64, mode: FullscreenMode, action: FullscreenAction) error{NoSpaceLeft}![]const u8 {
    var f: [64]u8 = undefined;
    const fields = try std.fmt.bufPrint(&f, "mode = \"{t}\", action = \"{t}\", ", .{ mode, action });
    return formatWindowAction(buf, "window.fullscreen", fields, address);
}

pub fn formatFloatWindow(buf: []u8, address: u64, floating: bool) error{NoSpaceLeft}![]const u8 {
    return formatWindowAction(buf, "window.float", if (floating) "action = \"enable\", " else "action = \"disable\", ", address);
}

/// Absolute, global logical coordinates of the top-left corner.
pub fn formatMoveWindowPixel(buf: []u8, address: u64, x: i32, y: i32) error{NoSpaceLeft}![]const u8 {
    var f: [64]u8 = undefined;
    return formatWindowAction(buf, "window.move", try std.fmt.bufPrint(&f, "x = {d}, y = {d}, ", .{ x, y }), address);
}

pub fn formatResizeWindowPixel(buf: []u8, address: u64, w: i32, h: i32) error{NoSpaceLeft}![]const u8 {
    var f: [64]u8 = undefined;
    return formatWindowAction(buf, "window.resize", try std.fmt.bufPrint(&f, "x = {d}, y = {d}, ", .{ w, h }), address);
}

/// Empty when unset; the result lives in `arena`.
pub fn getOptionStr(ipc: *const Ipc, arena: std.mem.Allocator, name: []const u8) Error![]const u8 {
    var buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&buf, "j/getoption {s}", .{name}) catch return error.BadResponse;
    return parseOptionStr(arena, try ipc.request(arena, cmd));
}

pub fn getOptionInt(ipc: *const Ipc, arena: std.mem.Allocator, name: []const u8) Error!i64 {
    var buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&buf, "j/getoption {s}", .{name}) catch return error.BadResponse;
    const json = try utf8Clean(arena, try ipc.request(arena, cmd));
    const O = struct { int: ?i64 = null };
    const o = std.json.parseFromSliceLeaky(O, arena, json, .{ .ignore_unknown_fields = true }) catch |err| return jsonError(err);
    return o.int orelse error.BadResponse;
}

/// Hyprland 0.56 answers a Lua config's booleans as "bool", older ones as "int".
pub fn getOptionBool(ipc: *const Ipc, arena: std.mem.Allocator, name: []const u8) Error!bool {
    var buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&buf, "j/getoption {s}", .{name}) catch return error.BadResponse;
    return parseOptionBool(arena, try ipc.request(arena, cmd));
}

pub fn parseOptionBool(arena: std.mem.Allocator, json_in: []const u8) Error!bool {
    const json = try utf8Clean(arena, json_in);
    const O = struct { bool: ?bool = null, int: ?i64 = null };
    const o = std.json.parseFromSliceLeaky(O, arena, json, .{ .ignore_unknown_fields = true }) catch |err| return jsonError(err);
    if (o.bool) |b| return b;
    if (o.int) |i| return i != 0;
    return error.BadResponse;
}

test "parseOptionBool: Hyprland's bool and int answers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expect(!try parseOptionBool(a, "{\"option\": \"cursor:invert\", \"bool\": false, \"set\": false }"));
    try std.testing.expect(try parseOptionBool(a, "{\"option\": \"cursor:invert\", \"bool\": true, \"set\": true }"));
    try std.testing.expect(try parseOptionBool(a, "{\"option\": \"cursor:invert\", \"int\": 1, \"set\": true }"));
    try std.testing.expectError(error.BadResponse, parseOptionBool(a, "{\"option\": \"x\", \"str\": \"1\"}"));
}

fn parseOptionStr(arena: std.mem.Allocator, json_in: []const u8) Error![]const u8 {
    const json = try utf8Clean(arena, json_in);
    const O = struct { str: JsonStr = .{} };
    const o = std.json.parseFromSliceLeaky(O, arena, json, .{ .ignore_unknown_fields = true }) catch |err| return jsonError(err);
    return o.str.s;
}

/// Hyprland reports no lock state directly: an active ext-session-lock shows as "LOCK" in a
/// monitor's solitaryBlockedBy, and stays set if the lock client dies.
pub fn lockedFromMonitorsJson(arena: std.mem.Allocator, json_in: []const u8) Error!bool {
    const json = try utf8Clean(arena, json_in);
    const M = struct { solitaryBlockedBy: ?[]const JsonStr = null };
    const ms = std.json.parseFromSliceLeaky([]M, arena, json, .{ .ignore_unknown_fields = true }) catch |err| return jsonError(err);
    for (ms) |m| {
        for (m.solitaryBlockedBy orelse continue) |r| if (std.mem.eql(u8, r.s, "LOCK")) return true;
    }
    return false;
}

pub fn isLocked(ipc: *const Ipc, gpa: std.mem.Allocator) Error!bool {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const resp = try ipc.request(arena.allocator(), "j/monitors");
    return lockedFromMonitorsJson(arena.allocator(), resp);
}

/// The scale k/120 nearest `desired` that Hyprland accepts unchanged for a `w`x`h` output:
/// a whole logical size that Hyprland keeps (`KeptScale`).
pub fn chooseScaleK(w: u32, h: u32, desired: f64) u32 {
    const target: f64 = std.math.clamp(desired, 0.5, 4.0) * 120.0;
    const g: u64 = std.math.gcd(@as(u64, w), @as(u64, h)) * 120;
    var best: u32 = 120;
    var best_err: f64 = std.math.floatMax(f64);
    var k: u32 = 60;
    while (k <= 480) : (k += 1) {
        if (g % k != 0 or !KeptScale.init(k).keeps(w, h)) continue;
        const err = @abs(@as(f64, @floatFromInt(k)) - target);
        // Prefer the larger scale on ties (text stays readable).
        if (err < best_err or (err == best_err and k > best)) {
            best = k;
            best_err = err;
        }
    }
    return best;
}

/// Client DesktopScaleFactor (percent, 100..500) → Hyprland scale.
pub fn scaleForClient(w: u32, h: u32, desktop_scale_percent: u32) f64 {
    const pct: f64 = if (desktop_scale_percent >= 100 and desktop_scale_percent <= 500) @floatFromInt(desktop_scale_percent) else 100.0;
    return @as(f64, @floatFromInt(chooseScaleK(w, h, pct / 100.0))) / 120.0;
}

/// Hyprland parses the rule's scale ("{d:.6}") as a float and keeps it only if pixels/scale is whole
/// in double, else tries round(scale*120)/120: 1274 / 1.4 is 910.0000000000001 in double.
pub const KeptScale = struct {
    /// The rule's scale (a float) and its 1/120 rounding (a double).
    rule: f64,
    rounded: f64,
    /// Either one, if used, is k/120 as a float.
    rule_is_k: bool,
    rounded_is_k: bool,

    pub fn init(k: u32) KeptScale {
        const exact = @as(f64, @floatFromInt(k)) / 120.0;
        const want: f32 = @floatCast(exact);
        var buf: [32]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "{d:.6}", .{exact}) catch unreachable;
        const rule: f32 = std.fmt.parseFloat(f32, text) catch unreachable;
        const search: f32 = @floatCast(@round(@as(f64, rule) * 120.0));
        const rounded = @as(f64, search) / 120.0;
        return .{ .rule = rule, .rounded = rounded, .rule_is_k = rule == want, .rounded_is_k = @as(f32, @floatCast(rounded)) == want };
    }

    pub fn keeps(s: KeptScale, w: u32, h: u32) bool {
        if (whole(w, s.rule) and whole(h, s.rule)) return s.rule_is_k;
        return s.rounded_is_k and whole(w, s.rounded) and whole(h, s.rounded);
    }

    fn whole(px: u32, scale: f64) bool {
        const l = @as(f64, @floatFromInt(px)) / scale;
        return l == @round(l);
    }
};

pub const Fit = struct {
    width: u32,
    height: u32,
    /// Hyprland scale = k / 120.
    k: u32,

    pub fn scale(f: Fit) f64 {
        return @as(f64, @floatFromInt(f.k)) / 120.0;
    }
};

/// Keeps the client's scale by shrinking the desktop up to 8 pixels (the client shows a thin
/// border); otherwise `chooseScaleK` picks the nearest valid scale.
pub fn fitDesktop(w_in: u32, h_in: u32, scale_percent: u32) Fit {
    // Nothing larger than RDPGFX can describe (MS-RDPEGFX 2.2.2.14).
    const w = @min(w_in, 32766);
    const h = @min(h_in, 32766);
    const pct: u32 = if (scale_percent >= 100 and scale_percent <= 500) scale_percent else 100;
    const k = pct * 120 / 100;
    if (pct * 120 % 100 == 0) {
        // w*120/k is whole iff w is a multiple of k/gcd(k,120); Hyprland must also find it whole.
        const kept = KeptScale.init(k);
        var dw: u32 = 0;
        while (dw < 9 and dw < w) : (dw += 1) {
            const fw = w - dw;
            if (fw * 120 % k != 0) continue;
            var dh: u32 = 0;
            while (dh < 9 and dh < h) : (dh += 1) {
                const fh = h - dh;
                if (fh * 120 % k == 0 and kept.keeps(fw, fh)) return .{ .width = fw, .height = fh, .k = k };
            }
        }
    }
    return .{ .width = w, .height = h, .k = chooseScaleK(w, h, @as(f64, @floatFromInt(pct)) / 100.0) };
}

pub fn createHeadless(ipc: *const Ipc, gpa: std.mem.Allocator, name: []const u8) Error!void {
    var buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&buf, "output create headless {s}", .{name}) catch return error.CommandFailed;
    try ipc.command(gpa, cmd);
}

pub fn removeOutput(ipc: *const Ipc, gpa: std.mem.Allocator, name: []const u8) Error!void {
    var buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&buf, "output remove {s}", .{name}) catch return error.CommandFailed;
    try ipc.command(gpa, cmd);
}

/// Monitor rule via the Lua API (Hyprland 0.56); the name is quoted as headless outputs can be named freely.
pub fn formatMonitorRule(buf: []u8, name: []const u8, w: u32, h: u32, refresh: f64, x: i32, y: i32, scale: f64, transform: u8) ![]u8 {
    var q: [1024]u8 = undefined;
    return std.fmt.bufPrint(buf, "eval hl.monitor({{ output = {s}, disabled = false, mode = \"{d}x{d}@{d:.3}\", position = \"{d}x{d}\", scale = {d:.6}, transform = {d} }})", .{ try luaString(&q, name), w, h, refresh, x, y, scale, transform });
}

/// Wraps Lua's `hl.monitor` so a rule setting an RDP output's scale posts `custom>>omastation-rule NAME SCALE`,
/// catching other tools' scale changes. A config reload drops the wrapper; installing twice is harmless.
pub const scale_watch_install = "eval if not omastation_monitor then omastation_monitor = hl.monitor end " ++
    "hl.monitor = function(r) local res = omastation_monitor(r) " ++
    "if type(r) == \"table\" and type(r.output) == \"string\" and string.match(r.output, \"^RDP%-%d+$\") and r.scale ~= nil then " ++
    "hl.dispatch(hl.dsp.event(\"omastation-rule \" .. r.output .. \" \" .. tostring(r.scale))) end " ++
    "return res end";
pub const scale_watch_remove = "eval if omastation_monitor then hl.monitor = omastation_monitor omastation_monitor = nil end";

pub const RuleReport = struct {
    /// RDP-1 is 0.
    index: usize,
    /// The scale in percent, rounded (1.6 -> 160).
    percent: u32,
};

/// A scale watch report (the event line, `custom>>omastation-rule RDP-2 1.6`).
pub fn parseRuleReport(line: []const u8) ?RuleReport {
    const prefix = "custom>>omastation-rule RDP-";
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    const rest = line[prefix.len..];
    const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    const n = std.fmt.parseInt(usize, rest[0..sp], 10) catch return null;
    if (n == 0) return null;
    const v = std.fmt.parseFloat(f64, std.mem.trim(u8, rest[sp + 1 ..], " \r")) catch return null;
    return .{ .index = n - 1, .percent = percentOf(v) orelse return null };
}

/// Output index and scale of one of formatMonitorRule's RDP output rules (what the scale watch reports).
pub fn ruleOfCommand(cmd: []const u8) ?RuleReport {
    const prefix = "eval hl.monitor({ output = \"RDP-";
    if (!std.mem.startsWith(u8, cmd, prefix)) return null;
    const rest = cmd[prefix.len..];
    const q = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
    const n = std.fmt.parseInt(usize, rest[0..q], 10) catch return null;
    if (n == 0) return null;
    const at = std.mem.indexOf(u8, rest, "scale = ") orelse return null;
    const v = rest[at + "scale = ".len ..];
    const end = std.mem.indexOfAny(u8, v, ", }") orelse v.len;
    const f = std.fmt.parseFloat(f64, v[0..end]) catch return null;
    return .{ .index = n - 1, .percent = percentOf(f) orelse return null };
}

/// A scale as a percent (rounded); null outside 0 < scale <= 10.
pub fn percentOf(scale: f64) ?u32 {
    if (!(scale > 0 and scale <= 10)) return null;
    return @intFromFloat(@round(scale * 100.0));
}

/// The percent a scale of k/120 reads as (percentOf of the rule's scale).
pub fn percentOfK(k: u32) u32 {
    return @intFromFloat(@round(@as(f64, @floatFromInt(k)) * 100.0 / 120.0));
}

pub fn formatMonitorOff(buf: []u8, name: []const u8) error{NoSpaceLeft}![]u8 {
    var q: [1024]u8 = undefined;
    return std.fmt.bufPrint(buf, "eval hl.monitor({{ output = {s}, disabled = true }})", .{try luaString(&q, name)});
}

pub fn setMonitor(ipc: *const Ipc, gpa: std.mem.Allocator, name: []const u8, w: u32, h: u32, refresh: f64, x: i32, y: i32, scale: f64) Error!void {
    var buf: [1400]u8 = undefined;
    const cmd = formatMonitorRule(&buf, name, w, h, refresh, x, y, scale, 0) catch return error.CommandFailed;
    try ipc.command(gpa, cmd);
}

pub fn disableMonitor(ipc: *const Ipc, gpa: std.mem.Allocator, name: []const u8) Error!void {
    var buf: [1100]u8 = undefined;
    const cmd = formatMonitorOff(&buf, name) catch return error.CommandFailed;
    try ipc.command(gpa, cmd);
}

/// Exactly as captured; without explicit disabled = false Hyprland keeps the output off.
pub fn restoreMonitor(ipc: *const Ipc, gpa: std.mem.Allocator, m: MonitorState) Error!void {
    var buf: [1400]u8 = undefined;
    const cmd = formatMonitorRule(&buf, m.name, m.width, m.height, m.refresh, m.x, m.y, m.scale, m.transform) catch return error.CommandFailed;
    try ipc.command(gpa, cmd);
}

/// A Lua string literal (IPC `eval` is Lua); workspace names are user-chosen, so quote everything.
pub fn luaString(buf: []u8, s: []const u8) error{NoSpaceLeft}![]const u8 {
    var n: usize = 0;
    const put = struct {
        fn f(b: []u8, i: *usize, bytes: []const u8) error{NoSpaceLeft}!void {
            if (i.* + bytes.len > b.len) return error.NoSpaceLeft;
            @memcpy(b[i.*..][0..bytes.len], bytes);
            i.* += bytes.len;
        }
    }.f;
    try put(buf, &n, "\"");
    for (s) |ch| {
        if (ch == '"' or ch == '\\') {
            try put(buf, &n, &.{ '\\', ch });
        } else if (ch < 0x20 or ch == 0x7f) {
            var esc: [4]u8 = undefined;
            try put(buf, &n, std.fmt.bufPrint(&esc, "\\{d:0>3}", .{ch}) catch unreachable);
        } else {
            try put(buf, &n, &.{ch});
        }
    }
    try put(buf, &n, "\"");
    return buf[0..n];
}

/// The id for normal workspaces, `name:` for named ones (negative ids read as relative).
pub fn workspaceSelector(buf: []u8, w: WorkspaceState) error{NoSpaceLeft}![]const u8 {
    if (w.id > 0) return std.fmt.bufPrint(buf, "{d}", .{w.id});
    return std.fmt.bufPrint(buf, "name:{s}", .{w.name});
}

/// With a Lua config, `hyprctl dispatch moveworkspacetomonitor` is not valid.
pub fn formatWorkspaceMove(buf: []u8, w: WorkspaceState, monitor: []const u8) error{NoSpaceLeft}![]const u8 {
    var sel_buf: [256]u8 = undefined;
    var ws_q: [600]u8 = undefined;
    var mon_q: [300]u8 = undefined;
    const sel = try workspaceSelector(&sel_buf, w);
    return std.fmt.bufPrint(buf, "eval hl.dispatch(hl.dsp.workspace.move({{ workspace = {s}, monitor = {s} }}))", .{
        try luaString(&ws_q, sel), try luaString(&mon_q, monitor),
    });
}

pub fn formatFocusMonitor(buf: []u8, monitor: []const u8) error{NoSpaceLeft}![]const u8 {
    var q: [300]u8 = undefined;
    return std.fmt.bufPrint(buf, "eval hl.dispatch(hl.dsp.focus({{ monitor = {s} }}))", .{try luaString(&q, monitor)});
}

/// Recreates `w` if it was destroyed (Hyprland drops empty workspaces that are not shown).
pub fn formatFocusWorkspaceHere(buf: []u8, w: WorkspaceState) error{NoSpaceLeft}![]const u8 {
    var sel_buf: [256]u8 = undefined;
    var q: [600]u8 = undefined;
    const sel = try workspaceSelector(&sel_buf, w);
    return std.fmt.bufPrint(buf, "eval hl.dispatch(hl.dsp.focus({{ workspace = {s}, on_current_monitor = true }}))", .{try luaString(&q, sel)});
}

/// Hyprland maps a touch device or tablet onto its `output`; `device` is Hyprland's name for it.
pub fn formatDeviceOutput(buf: []u8, device: []const u8, output: []const u8) error{NoSpaceLeft}![]const u8 {
    var dq: [300]u8 = undefined;
    var oq: [300]u8 = undefined;
    return std.fmt.bufPrint(buf, "eval hl.device({{ name = {s}, output = {s} }})", .{ try luaString(&dq, device), try luaString(&oq, output) });
}

/// Runs in the compositor's environment: the session's PATH and variables.
pub fn formatExec(buf: []u8, command: []const u8) error{NoSpaceLeft}![]const u8 {
    var q: [1024]u8 = undefined;
    return std.fmt.bufPrint(buf, "eval hl.exec_cmd({s})", .{try luaString(&q, command)});
}

test "scale snapping matches Hyprland" {
    // 1.5 at 2560x1440 snaps to 1.6.
    try std.testing.expectEqual(@as(u32, 192), chooseScaleK(2560, 1440, 1.5));
    try std.testing.expectEqual(@as(u32, 150), chooseScaleK(1920, 1080, 1.25));
    try std.testing.expectEqual(@as(u32, 180), chooseScaleK(1920, 1080, 1.5));
    try std.testing.expectEqual(@as(u32, 120), chooseScaleK(1366, 768, 1.0));
    // Whatever is chosen yields an integral logical size.
    const sizes = [_][2]u32{ .{ 2560, 1440 }, .{ 1366, 768 }, .{ 3440, 1440 }, .{ 978, 644 }, .{ 3840, 2160 } };
    for (sizes) |s| for ([_]f64{ 1.0, 1.25, 1.4, 1.5, 1.75, 2.0 }) |d| {
        const k = chooseScaleK(s[0], s[1], d);
        try std.testing.expect((s[0] * 120) % k == 0 and (s[1] * 120) % k == 0);
    };
}

test "client scale factor mapping" {
    try std.testing.expectApproxEqAbs(@as(f64, 1.5), scaleForClient(1920, 1080, 150), 1e-9);
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), scaleForClient(1920, 1080, 0), 1e-9); // absent → 100%
}

test "monitor rule formatting" {
    var buf: [512]u8 = undefined;
    const s = try formatMonitorRule(&buf, "RDP-1", 1920, 1080, 60, 0, 0, 1.25, 0);
    try std.testing.expectEqualStrings(
        "eval hl.monitor({ output = \"RDP-1\", disabled = false, mode = \"1920x1080@60.000\", position = \"0x0\", scale = 1.250000, transform = 0 })",
        s,
    );
}

test "parse monitors json" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const json =
        \\[{"id":1,"name":"DP-1","description":"x","width":3840,"height":2160,"refreshRate":160.0,
        \\  "x":0,"y":0,"activeWorkspace":{"id":1,"name":"1"},"scale":1.5,"transform":0,"disabled":false,"vrr":false},
        \\ {"id":2,"name":"RDP-1","width":1920,"height":1080,"refreshRate":60.0,"x":2560,"y":0,
        \\  "activeWorkspace":{"id":2,"name":"2"},"scale":1.25,"disabled":false}]
    ;
    const ms = try parseMonitors(arena.allocator(), json);
    try std.testing.expectEqual(@as(usize, 2), ms.len);
    try std.testing.expectEqualStrings("DP-1", ms[0].name);
    try std.testing.expectEqual(@as(f64, 1.5), ms[0].scale);
    try std.testing.expect(isRdpOutput(ms[1].name));
    try std.testing.expectEqualStrings("2", ms[1].workspace);
    try std.testing.expectError(error.BadResponse, parseMonitors(arena.allocator(), "not json"));
}

test "desktop fitting keeps the client's scale" {
    const f = fitDesktop(3468, 1990, 150);
    try std.testing.expectEqual(@as(u32, 180), f.k);
    try std.testing.expectEqual(@as(u32, 3468), f.width);
    try std.testing.expectEqual(@as(u32, 1989), f.height);
    const steps = [_]u32{ 100, 125, 150, 175, 200, 225, 250, 300 };
    const sizes = [_][2]u32{ .{ 1920, 1080 }, .{ 3468, 1990 }, .{ 1366, 768 }, .{ 978, 644 }, .{ 2559, 1439 }, .{ 3840, 2160 } };
    for (sizes) |sz| for (steps) |pct| {
        const r = fitDesktop(sz[0], sz[1], pct);
        try std.testing.expectEqual(pct * 120 / 100, r.k);
        try std.testing.expect(sz[0] - r.width < 9 and sz[1] - r.height < 9);
        try std.testing.expect((r.width * 120) % r.k == 0 and (r.height * 120) % r.k == 0);
    };
    // Absent or odd values fall back to 100% / the nearest valid scale.
    try std.testing.expectEqual(@as(u32, 120), fitDesktop(1920, 1080, 0).k);
    const odd = fitDesktop(1920, 1080, 133);
    try std.testing.expect((odd.width * 120) % odd.k == 0);
}

test "workspace moves and exec are valid, quoted Lua" {
    var buf: [512]u8 = undefined;
    try std.testing.expectEqualStrings(
        "eval hl.dispatch(hl.dsp.workspace.move({ workspace = \"3\", monitor = \"RDP-1\" }))",
        try formatWorkspaceMove(&buf, .{ .id = 3, .name = "3", .monitor = "DP-1" }, "RDP-1"),
    );
    try std.testing.expectEqualStrings(
        "eval hl.dispatch(hl.dsp.workspace.move({ workspace = \"name:a\\\"b\", monitor = \"DP-1\" }))",
        try formatWorkspaceMove(&buf, .{ .id = -1337, .name = "a\"b", .monitor = "RDP-1" }, "DP-1"),
    );
    try std.testing.expectEqualStrings("eval hl.exec_cmd(\"omarchy-system-lock\")", try formatExec(&buf, "omarchy-system-lock"));
    var q: [32]u8 = undefined;
    try std.testing.expectEqualStrings("\"a\\010b\"", try luaString(&q, "a\nb"));
}

test "parse workspaces and lock state" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ws = try parseWorkspaces(arena.allocator(),
        \\[{"id":1,"name":"1","monitor":"DP-1","windows":2},{"id":-98,"name":"special:magic","monitor":"DP-1"}]
    );
    try std.testing.expectEqual(@as(usize, 2), ws.len);
    try std.testing.expect(!ws[0].isSpecial() and ws[1].isSpecial());
    try std.testing.expect(try lockedFromMonitorsJson(arena.allocator(),
        \\[{"name":"DP-1","solitaryBlockedBy":["WINDOWED","LOCK"]}]
    ));
    try std.testing.expect(!try lockedFromMonitorsJson(arena.allocator(),
        \\[{"name":"DP-1","solitaryBlockedBy":["WINDOWED","CANDIDATE"]},{"name":"RDP-1"}]
    ));
}

test "window addresses, events and dispatches" {
    try std.testing.expectEqual(@as(?u64, 0x55d0a1b2c3d0), parseAddress("0x55d0a1b2c3d0"));
    try std.testing.expectEqual(@as(?u64, 0x55d0a1b2c3d0), parseAddress("55d0a1b2c3d0"));
    for ([_][]const u8{ "", "0x", "0x12345678901234567", "xyz", "0x-1", " 1" }) |s| try std.testing.expectEqual(@as(?u64, null), parseAddress(s));
    const e = try parseEvent("windowtitlev2>>55d0,a, b,c");
    try std.testing.expectEqual(@as(u64, 0x55d0), e.window_title.address);
    try std.testing.expectEqualStrings("a, b,c", e.window_title.title);
    try std.testing.expectEqual(@as(?u64, null), (try parseEvent("activewindowv2>>")).active_window);
    try std.testing.expectError(error.BadResponse, parseEvent("closewindow>>zz"));
    try std.testing.expectError(error.BadResponse, parseEvent("no separator"));
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        "eval hl.dispatch(hl.dsp.window.fullscreen({ mode = \"maximized\", action = \"unset\", window = \"address:0x55d0\" }))",
        try formatFullscreenWindow(&buf, 0x55d0, .maximized, .unset),
    );
}

test "string option" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("fr", try parseOptionStr(arena.allocator(),
        \\{"option":"input:kb_layout","str":"fr","set":true}
    ));
    try std.testing.expectEqualStrings("", try parseOptionStr(arena.allocator(),
        \\{"option":"input:kb_variant","str":"","set":false}
    ));
}

test "scale watch reports and own rules parse to an output index and a percent" {
    const r = parseRuleReport("custom>>omastation-rule RDP-1 3").?;
    try std.testing.expectEqual(@as(usize, 0), r.index);
    try std.testing.expectEqual(@as(u32, 300), r.percent);
    try std.testing.expectEqual(@as(u32, 160), parseRuleReport("custom>>omastation-rule RDP-2 1.6").?.percent);
    try std.testing.expectEqual(@as(usize, 1), parseRuleReport("custom>>omastation-rule RDP-2 1.6").?.index);
    try std.testing.expectEqual(@as(u32, 200), parseRuleReport("custom>>omastation-rule RDP-1 2.0").?.percent);
    try std.testing.expect(parseRuleReport("custom>>omastation-rule RDP-0 2") == null);
    try std.testing.expect(parseRuleReport("custom>>omastation-rule RDP-1 auto") == null);
    try std.testing.expect(parseRuleReport("custom>>something else") == null);
    var buf: [1400]u8 = undefined;
    const cmd = try formatMonitorRule(&buf, "RDP-3", 1920, 1080, 60, 2560, 0, 1608.0 / 1000.0, 0);
    const own = ruleOfCommand(cmd).?;
    try std.testing.expectEqual(@as(usize, 2), own.index);
    try std.testing.expectEqual(@as(u32, 161), own.percent);
    try std.testing.expect(ruleOfCommand("eval hl.monitor({ output = \"DP-1\", disabled = true })") == null);
    // Both sides agree on a fitted scale (k/120, printed with 6 digits).
    for ([_]u32{ 120, 150, 180, 192, 193, 240, 360, 480 }) |k| {
        const c2 = try formatMonitorRule(&buf, "RDP-1", 100, 100, 60, 0, 0, @as(f64, @floatFromInt(k)) / 120.0, 0);
        try std.testing.expectEqual(percentOfK(k), ruleOfCommand(c2).?.percent);
    }
}
