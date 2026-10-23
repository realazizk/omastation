//! Hyprland's toplevel windows as a RAIL server describes them (MS-RDPERP 2.2.1.3.1,
//! 2.2.1.3.3.2.1): windows on visible workspaces with RDP geometry, show state and stacking.

const std = @import("std");
const c = @import("c");
const hypr = @import("hypr.zig");
const console = @import("console.zig");

const Allocator = std.mem.Allocator;
const log = std.log.scoped(.toplevels);

pub const Error = hypr.Error;

/// Hyprland has no minimized state; a special workspace stays hidden until toggled.
pub const minimized_workspace = "special:omastation-minimized";

pub const Output = struct {
    name: []const u8,
    /// Top-left in the RDP virtual desktop (MS-RDPBCGR 2.2.1.3.6.1).
    rdp_x: i32 = 0,
    rdp_y: i32 = 0,
};

pub const HiddenPolicy = enum {
    omit,
    /// Activating one focuses it, which switches Hyprland to its workspace.
    minimized,
};

pub const Options = struct {
    outputs: []const Output = &.{.{ .name = console.rdp_output_name }},
    hidden_workspaces: HiddenPolicy = .omit,
    resync_ms: i64 = 250,
};

/// RDP desktop pixels (MS-RDPERP "screen coordinates").
pub const Rect = struct {
    x: i32,
    y: i32,
    width: i32,
    height: i32,

    pub fn intersect(a: Rect, b: Rect) ?Rect {
        const x0 = @max(a.x, b.x);
        const y0 = @max(a.y, b.y);
        const x1 = @min(@as(i64, a.x) + a.width, @as(i64, b.x) + b.width);
        const y1 = @min(@as(i64, a.y) + a.height, @as(i64, b.y) + b.height);
        if (x1 <= x0 or y1 <= y0) return null;
        return .{ .x = x0, .y = y0, .width = @intCast(x1 - x0), .height = @intCast(y1 - y0) };
    }

    pub fn contains(r: Rect, x: i32, y: i32) bool {
        return x >= r.x and y >= r.y and @as(i64, x) < @as(i64, r.x) + r.width and @as(i64, y) < @as(i64, r.y) + r.height;
    }
};

pub const Show = enum { normal, minimized, maximized, fullscreen };

pub const Window = struct {
    address: u64,
    stable_id: u64,
    title: []const u8,
    /// xdg_toplevel app id, or the X11 class.
    class: []const u8,
    initial_class: []const u8,
    pid: i64,
    rect: Rect,
    /// The part of `rect` on its output; null when minimized or scrolled off.
    visible: ?Rect,
    show: Show,
    floating: bool,
    pinned: bool,
    xwayland: bool,
    workspace_id: i64,
    workspace: []const u8,
    /// Index into Options.outputs.
    output: usize,
    /// Hyprland's IPC does not report it.
    owner: ?u64 = null,
};

pub const Model = struct {
    /// Topmost first (MS-RDPERP 2.2.1.3.3.2.1).
    windows: []Window = &.{},
    /// The focused window, if it is one of `windows` and not minimized.
    active: ?u64 = null,

    pub fn find(m: *const Model, address: u64) ?*const Window {
        for (m.windows) |*w| if (w.address == address) return w;
        return null;
    }

    fn indexOf(m: *const Model, address: u64) ?usize {
        for (m.windows, 0..) |w, i| if (w.address == address) return i;
        return null;
    }

    pub fn eql(a: *const Model, b: *const Model) bool {
        if (a.active != b.active or a.windows.len != b.windows.len) return false;
        for (a.windows, b.windows) |x, y| if (!windowEql(x, y)) return false;
        return true;
    }
};

fn windowEql(a: Window, b: Window) bool {
    const S = std.mem.eql;
    return a.address == b.address and a.stable_id == b.stable_id and S(u8, a.title, b.title) and
        S(u8, a.class, b.class) and S(u8, a.initial_class, b.initial_class) and a.pid == b.pid and
        std.meta.eql(a.rect, b.rect) and std.meta.eql(a.visible, b.visible) and a.show == b.show and
        a.floating == b.floating and a.pinned == b.pinned and a.xwayland == b.xwayland and
        a.workspace_id == b.workspace_id and S(u8, a.workspace, b.workspace) and a.output == b.output and
        a.owner == b.owner;
}

pub const Placed = struct {
    output: Output,
    index: usize,
    monitor: hypr.MonitorState,

    pub fn rdpRect(p: Placed) Rect {
        return .{ .x = p.output.rdp_x, .y = p.output.rdp_y, .width = clampI32(p.monitor.width), .height = clampI32(p.monitor.height) };
    }

    /// Logical layout to RDP desktop pixels.
    pub fn toRdp(p: Placed, lx: i32, ly: i32, lw: i32, lh: i32) Rect {
        const s = p.monitor.scale;
        return .{
            .x = p.output.rdp_x +| roundI32(@as(f64, @floatFromInt(@as(i64, lx) - p.monitor.x)) * s),
            .y = p.output.rdp_y +| roundI32(@as(f64, @floatFromInt(@as(i64, ly) - p.monitor.y)) * s),
            .width = @max(0, roundI32(@as(f64, @floatFromInt(lw)) * s)),
            .height = @max(0, roundI32(@as(f64, @floatFromInt(lh)) * s)),
        };
    }

    pub fn toLogical(p: Placed, r: Rect) Rect {
        const s = if (p.monitor.scale > 0) p.monitor.scale else 1;
        return .{
            .x = clampI32(p.monitor.x) +| roundI32(@as(f64, @floatFromInt(@as(i64, r.x) - p.output.rdp_x)) / s),
            .y = clampI32(p.monitor.y) +| roundI32(@as(f64, @floatFromInt(@as(i64, r.y) - p.output.rdp_y)) / s),
            .width = roundI32(@as(f64, @floatFromInt(r.width)) / s),
            .height = roundI32(@as(f64, @floatFromInt(r.height)) / s),
        };
    }
};

fn roundI32(v: f64) i32 {
    if (std.math.isNan(v)) return 0;
    return @intFromFloat(std.math.clamp(@round(v), -2147483648.0, 2147483647.0));
}

fn clampI32(v: anytype) i32 {
    return @intCast(std.math.clamp(@as(i64, v), std.math.minInt(i32), std.math.maxInt(i32)));
}

/// Enabled remote outputs, in Options.outputs order.
pub fn placeOutputs(arena: Allocator, monitors: []const hypr.MonitorState, outputs: []const Output) Error![]Placed {
    var list: std.ArrayList(Placed) = .empty;
    for (outputs, 0..) |o, i| for (monitors) |m| {
        if (!std.mem.eql(u8, m.name, o.name) or m.disabled) continue;
        try list.append(arena, .{ .output = o, .index = i, .monitor = m });
        break;
    };
    return list.toOwnedSlice(arena);
}

fn outputOf(placed: []const Placed, cl: hypr.ClientState) ?*const Placed {
    for (placed) |*p| if (p.monitor.id == cl.monitor) return p;
    return null;
}

fn isSpecial(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "special:");
}

/// On its output's active or special workspace, or pinned.
fn shownOn(p: *const Placed, cl: hypr.ClientState) bool {
    if (cl.pinned) return true;
    if (cl.workspace_id == p.monitor.workspace_id) return true;
    return p.monitor.special_workspace_id != 0 and cl.workspace_id == p.monitor.special_workspace_id;
}

fn minimizedWorkspaceShown(placed: []const Placed) bool {
    for (placed) |p| if (std.mem.eql(u8, p.monitor.special_workspace, minimized_workspace)) return true;
    return false;
}

/// Bottom to top as Hyprland renders: tiled (focused last), floating, fullscreen;
/// special workspaces above regular; pinned on top.
fn rank(w: Window, active: ?u64, special: bool) u8 {
    if (w.show == .minimized) return 0;
    const group: u8 = if (w.pinned) 3 else if (special) 2 else 1;
    const plane: u8 = if (w.show == .fullscreen or w.show == .maximized)
        3
    else if (w.floating)
        2
    else if (active == w.address)
        1
    else
        0;
    return group * 10 + plane;
}

/// `clients` in `j/clients` order; the model points into their strings.
pub fn build(arena: Allocator, clients: []const hypr.ClientState, monitors: []const hypr.MonitorState, active: ?u64, opts: Options) Error!Model {
    const placed = try placeOutputs(arena, monitors, opts.outputs);
    if (placed.len == 0) return .{};
    const min_shown = minimizedWorkspaceShown(placed);

    const Entry = struct { w: Window, rank: u8 };
    var entries: std.ArrayList(Entry) = .empty;
    for (clients) |cl| {
        if (!cl.mapped or cl.hidden) continue;
        const own = outputOf(placed, cl);
        var show: Show = switch (cl.fullscreen) {
            1 => .maximized,
            2 => .fullscreen,
            else => .normal,
        };
        if (std.mem.eql(u8, cl.workspace, minimized_workspace) and !min_shown) {
            show = .minimized;
        } else if (own != null and shownOn(own.?, cl)) {
            // Shown as it is.
        } else if (opts.hidden_workspaces == .minimized and (own != null or isSpecial(cl.workspace))) {
            show = .minimized;
        } else continue;

        const p = own orelse &placed[0];
        const rect = p.toRdp(cl.x, cl.y, cl.width, cl.height);
        const w: Window = .{
            .address = cl.address,
            .stable_id = cl.stable_id,
            .title = cl.title,
            .class = cl.class,
            .initial_class = cl.initial_class,
            .pid = cl.pid,
            .rect = rect,
            .visible = if (show == .minimized) null else rect.intersect(p.rdpRect()),
            .show = show,
            .floating = cl.floating,
            .pinned = cl.pinned,
            .xwayland = cl.xwayland,
            .workspace_id = cl.workspace_id,
            .workspace = cl.workspace,
            .output = p.index,
        };
        try entries.append(arena, .{ .w = w, .rank = 0 });
    }
    const focused: ?u64 = blk: {
        const a = active orelse break :blk null;
        for (entries.items) |e| if (e.w.address == a and e.w.show != .minimized) break :blk a;
        break :blk null;
    };
    for (entries.items) |*e| e.rank = rank(e.w, focused, isSpecial(e.w.workspace) and !e.w.pinned);
    // Stable: equal ranks keep the window-list order.
    std.mem.sort(Entry, entries.items, {}, struct {
        fn lt(_: void, a: Entry, b: Entry) bool {
            return a.rank < b.rank;
        }
    }.lt);
    const windows = try arena.alloc(Window, entries.items.len);
    for (entries.items, 0..) |e, i| windows[windows.len - 1 - i] = e.w;
    return .{ .windows = windows, .active = focused };
}

/// Follows Hyprland's event socket; a periodic resync catches geometry changes, which send no event.
pub const Tracker = struct {
    gpa: Allocator,
    ipc: hypr.Ipc,
    opts: Options,
    /// Owns `model`, `outputs` and their strings.
    arena: std.heap.ArenaAllocator,
    model: Model = .{},
    outputs: []const Placed = &.{},
    events_fd: c_int = -1,
    events_buf: [8192]u8 = undefined,
    events_len: usize = 0,
    /// Inside a line longer than events_buf: drop it up to its newline.
    events_skip: bool = false,
    started: bool = false,
    dirty: bool = true,
    last_resync_ms: ?i64 = null,
    /// Bumped on every change of `model`.
    generation: u64 = 0,
    failures: u32 = 0,
    events_missing: bool = false,

    pub fn init(gpa: Allocator, ipc: hypr.Ipc, opts: Options) Tracker {
        return .{ .gpa = gpa, .ipc = ipc, .opts = opts, .arena = .init(gpa) };
    }

    pub fn deinit(t: *Tracker) void {
        t.stop();
        t.arena.deinit();
    }

    /// Subscribes to events before the first snapshot so none are missed.
    pub fn start(t: *Tracker) Error!void {
        t.started = true;
        t.connectEvents();
        t.dirty = true;
        _ = try t.resync();
    }

    pub fn stop(t: *Tracker) void {
        if (t.events_fd >= 0) _ = c.close(t.events_fd);
        t.events_fd = -1;
        t.events_len = 0;
        t.events_skip = false;
        t.started = false;
    }

    fn connectEvents(t: *Tracker) void {
        if (t.events_fd >= 0) return;
        t.events_fd = t.ipc.connectEvents() catch -1;
        t.events_len = 0;
        t.events_skip = false;
        if (t.events_fd >= 0) {
            t.events_missing = false;
        } else if (!t.events_missing) {
            t.events_missing = true;
            log.warn("no Hyprland event socket: windows follow the periodic resync only", .{});
        }
    }

    pub fn eventsFd(t: *const Tracker) c_int {
        return t.events_fd;
    }

    /// Non-blocking; true if the model changed.
    pub fn readEvents(t: *Tracker) error{OutOfMemory}!bool {
        var changed = false;
        while (t.events_fd >= 0) {
            const n = c.recv(t.events_fd, t.events_buf[t.events_len..].ptr, t.events_buf.len - t.events_len, c.MSG_DONTWAIT);
            if (n == 0) {
                log.warn("Hyprland event socket closed", .{});
                _ = c.close(t.events_fd);
                t.events_fd = -1;
                t.dirty = true;
                break;
            }
            if (n < 0) break;
            t.events_len += @intCast(n);
            var from: usize = 0;
            while (std.mem.indexOfScalarPos(u8, t.events_buf[0..t.events_len], from, '\n')) |nl| {
                if (t.events_skip) {
                    t.events_skip = false;
                } else if (try t.handleEvent(t.events_buf[from..nl])) changed = true;
                from = nl + 1;
            }
            std.mem.copyForwards(u8, t.events_buf[0 .. t.events_len - from], t.events_buf[from..t.events_len]);
            t.events_len -= from;
            if (t.events_len == t.events_buf.len) {
                // Hyprland cuts event data at 1024 bytes: drop the line, resync.
                t.events_len = 0;
                t.events_skip = true;
                t.dirty = true;
            }
        }
        return changed;
    }

    /// `line` without its newline; true if the model changed.
    pub fn handleEvent(t: *Tracker, line: []const u8) error{OutOfMemory}!bool {
        const ev = hypr.parseEvent(line) catch {
            log.debug("ignoring malformed Hyprland event `{s}`", .{line[0..@min(line.len, 80)]});
            return false;
        };
        switch (ev) {
            .close_window => |a| {
                t.dirty = true;
                const i = t.model.indexOf(a) orelse return false;
                const ws = t.arena.allocator().alloc(Window, t.model.windows.len - 1) catch |e| return e;
                @memcpy(ws[0..i], t.model.windows[0..i]);
                @memcpy(ws[i..], t.model.windows[i + 1 ..]);
                t.model.windows = ws;
                if (t.model.active == a) t.model.active = null;
                t.generation += 1;
                return true;
            },
            .active_window => |a| {
                // Focus restacks: the focused tiled window is drawn last, floating ones are raised.
                t.dirty = true;
                const want: ?u64 = if (a) |addr| (if (t.model.find(addr)) |w| (if (w.show != .minimized) addr else null) else null) else null;
                if (want == t.model.active) return false;
                t.model.active = want;
                t.generation += 1;
                return true;
            },
            .window_title => |wt| {
                const i = t.model.indexOf(wt.address) orelse return false;
                if (std.mem.eql(u8, t.model.windows[i].title, wt.title)) return false;
                t.model.windows[i].title = try t.arena.allocator().dupe(u8, wt.title);
                t.generation += 1;
                return true;
            },
            .open_window, .move_window, .floating, .fullscreen, .minimized, .pin, .layout => {
                t.dirty = true;
                return false;
            },
            .other => return false,
        }
    }

    /// True if the model changed; Hyprland errors keep the last model and are retried.
    pub fn tick(t: *Tracker, now_ms: i64) error{OutOfMemory}!bool {
        if (!t.started) return false;
        const due = t.dirty or t.last_resync_ms == null or now_ms - t.last_resync_ms.? >= t.opts.resync_ms;
        if (!due) return false;
        t.last_resync_ms = now_ms;
        // Reconnect at the resync pace, not on every call.
        if (t.events_fd < 0) t.connectEvents();
        return t.resync() catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                if (t.failures == 0) log.warn("window resync failed: {t}", .{err});
                t.failures += 1;
                return false;
            },
        };
    }

    pub fn resync(t: *Tracker) Error!bool {
        var next = std.heap.ArenaAllocator.init(t.gpa);
        errdefer next.deinit();
        const a = next.allocator();
        const cls = try hypr.clients(&t.ipc, a);
        const mons = try hypr.monitors(&t.ipc, a);
        const active = try hypr.activeWindow(&t.ipc, a);
        const model = try build(a, cls, mons, active, t.opts);
        const outputs = try placeOutputs(a, mons, t.opts.outputs);
        t.dirty = false;
        if (t.failures > 0) log.info("window resync works again", .{});
        t.failures = 0;
        const changed = !model.eql(&t.model) or !samePlacement(outputs, t.outputs);
        t.arena.deinit();
        t.arena = next;
        t.model = model;
        t.outputs = outputs;
        if (changed) t.generation += 1;
        return changed;
    }

    pub fn output(t: *const Tracker, index: usize) ?Placed {
        for (t.outputs) |p| if (p.index == index) return p;
        return null;
    }

    pub fn outputAt(t: *const Tracker, x: i32, y: i32) ?Placed {
        for (t.outputs) |p| if (p.rdpRect().contains(x, y)) return p;
        return null;
    }
};

fn samePlacement(a: []const Placed, b: []const Placed) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x.index != y.index or x.monitor.x != y.monitor.x or x.monitor.y != y.monitor.y or
            x.monitor.width != y.monitor.width or x.monitor.height != y.monitor.height or
            x.monitor.scale != y.monitor.scale or x.monitor.workspace_id != y.monitor.workspace_id or
            x.monitor.special_workspace_id != y.monitor.special_workspace_id) return false;
    }
    return true;
}

test "geometry: logical to RDP pixels and back at 125%" {
    const p: Placed = .{
        .output = .{ .name = "RDP-1" },
        .index = 0,
        .monitor = .{ .name = "RDP-1", .width = 1920, .height = 1080, .refresh = 60, .x = 1280, .y = 0, .scale = 1.25, .transform = 0, .disabled = false, .workspace = "1", .id = 1 },
    };
    const r = p.toRdp(1280 + 100, 40, 800, 600);
    try std.testing.expectEqual(Rect{ .x = 125, .y = 50, .width = 1000, .height = 750 }, r);
    try std.testing.expectEqual(Rect{ .x = 1380, .y = 40, .width = 800, .height = 600 }, p.toLogical(r));
    try std.testing.expectEqual(@as(?Rect, .{ .x = 1000, .y = 0, .width = 920, .height = 100 }), (Rect{ .x = 1000, .y = -50, .width = 2000, .height = 150 }).intersect(p.rdpRect()));
    try std.testing.expectEqual(@as(?Rect, null), (Rect{ .x = 1920, .y = 0, .width = 10, .height = 10 }).intersect(p.rdpRect()));
}
