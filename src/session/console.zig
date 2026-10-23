//! Console fencing: physical monitors go dark while a remote session is
//! connected, and the session is locked before they come back. Planners are
//! pure functions producing ordered Hyprland IPC commands from a snapshot.

const std = @import("std");
const hypr = @import("hypr.zig");
const multimon = @import("multimon.zig");
const uinput = @import("uinput.zig");

pub const rdp_output_name = "RDP-1";

pub const RemoteOutput = struct {
    width: u32,
    height: u32,
    refresh: f64 = 60,
    scale: f64,
};

/// A failed critical step aborts entering remote mode; other steps are best effort.
pub const Step = struct {
    cmd: []const u8,
    critical: bool,
    /// Wait for monitor `cmd` to be enabled: Hyprland applies monitor rules asynchronously.
    wait_on: bool = false,
};

/// Size (or create) the RDP output, move workspaces onto it, disable the physical monitors, then
/// show the desk's workspace. Workspaces move first so no window is stranded on a dark output.
pub fn planEnter(arena: std.mem.Allocator, monitors: []const hypr.MonitorState, workspaces: []const hypr.WorkspaceState, out: RemoteOutput) ![]Step {
    var steps: std.ArrayList(Step) = .empty;
    var have_rdp = false;
    for (monitors) |m| {
        if (std.mem.eql(u8, m.name, rdp_output_name)) have_rdp = true;
    }
    // Rule first, so a new headless output starts in its final mode.
    var buf: [1400]u8 = undefined;
    try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatMonitorRule(&buf, rdp_output_name, out.width, out.height, out.refresh, rdpX(monitors), 0, out.scale, 0)), .critical = true });
    if (!have_rdp) try steps.append(arena, .{ .cmd = try std.fmt.allocPrint(arena, "output create headless {s}", .{rdp_output_name}), .critical = true });
    for (workspaces) |w| {
        if (!movable(monitors, w)) continue;
        try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatWorkspaceMove(&buf, w, rdp_output_name)), .critical = false });
    }
    for (monitors) |m| {
        if (!isPhysical(m) or m.disabled) continue;
        try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatMonitorOff(&buf, m.name)), .critical = true });
    }
    if (deskWorkspace(monitors)) |ws| {
        try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatFocusMonitor(&buf, rdp_output_name)), .critical = false });
        try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatFocusWorkspaceHere(&buf, ws)), .critical = false });
    }
    return steps.toOwnedSlice(arena);
}

/// The focused enabled physical monitor's workspace, else the leftmost one's; never a special one.
fn deskWorkspace(monitors: []const hypr.MonitorState) ?hypr.WorkspaceState {
    var pick: ?hypr.MonitorState = null;
    for (monitors) |m| {
        if (!isPhysical(m) or m.disabled or m.workspace.len == 0) continue;
        const cur = pick orelse {
            pick = m;
            continue;
        };
        const first = m.x < cur.x or (m.x == cur.x and m.y < cur.y);
        if (m.focused or (!cur.focused and first)) pick = m;
    }
    const m = pick orelse return null;
    const ws: hypr.WorkspaceState = .{ .id = m.workspace_id, .name = m.workspace, .monitor = m.name };
    return if (ws.isSpecial()) null else ws;
}

pub fn planResize(arena: std.mem.Allocator, monitors: []const hypr.MonitorState, out: RemoteOutput) ![]Step {
    var buf: [1400]u8 = undefined;
    const steps = try arena.alloc(Step, 1);
    steps[0] = .{ .cmd = try arena.dupe(u8, try hypr.formatMonitorRule(&buf, rdp_output_name, out.width, out.height, out.refresh, rdpX(monitors), 0, out.scale, 0)), .critical = true };
    return steps;
}

/// Right of every physical monitor: Hyprland warns about overlaps on screen.
fn rdpX(monitors: []const hypr.MonitorState) i32 {
    const all_lit = allOff(monitors);
    var x: i32 = 0;
    for (monitors) |m| {
        if (!isPhysical(m) or (m.disabled and !all_lit)) continue;
        const rotated = m.transform % 2 == 1;
        const px: f64 = @floatFromInt(if (rotated) m.height else m.width);
        const logical: i32 = @intFromFloat(@ceil(px / m.scale));
        x = @max(x, m.x + logical);
    }
    return x;
}

/// Run only once the session lock is confirmed (`Leave`). Restores monitors as captured,
/// moves workspaces back (active ones last), then removes the RDP output.
pub fn planRestore(arena: std.mem.Allocator, monitors_in: []const hypr.MonitorState, workspaces: []const hypr.WorkspaceState) ![]Step {
    return planRestoreOutputs(arena, monitors_in, workspaces, &.{rdp_output_name});
}

/// Removes `rdp_outputs` in order (callers pass RDP-1, the primary, last).
pub fn planRestoreOutputs(arena: std.mem.Allocator, monitors_in: []const hypr.MonitorState, workspaces: []const hypr.WorkspaceState, rdp_outputs: []const []const u8) ![]Step {
    const monitors = try neverDark(arena, monitors_in);
    var steps: std.ArrayList(Step) = .empty;
    var buf: [1400]u8 = undefined;
    for (monitors) |m| {
        if (!isPhysical(m) or m.disabled) continue;
        try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatMonitorRule(&buf, m.name, m.width, m.height, m.refresh, m.x, m.y, m.scale, m.transform)), .critical = true });
    }
    for (monitors) |m| {
        if (!isPhysical(m) or m.disabled) continue;
        try steps.append(arena, .{ .cmd = m.name, .critical = false, .wait_on = true });
    }
    for ([_]bool{ false, true }) |active_pass| {
        for (workspaces) |w| {
            if (!movable(monitors, w)) continue;
            if (isActiveOn(monitors, w) != active_pass) continue;
            try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatWorkspaceMove(&buf, w, w.monitor)), .critical = false });
        }
    }
    // Focused monitor last so it keeps the focus; an empty, dropped workspace is recreated.
    for ([_]bool{ false, true }) |focused_pass| {
        for (monitors) |m| {
            if (!isPhysical(m) or m.disabled or m.workspace.len == 0 or m.focused != focused_pass) continue;
            const ws: hypr.WorkspaceState = .{ .id = m.workspace_id, .name = m.workspace, .monitor = m.name };
            if (ws.isSpecial()) continue;
            try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatFocusMonitor(&buf, m.name)), .critical = false });
            try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatFocusWorkspaceHere(&buf, ws)), .critical = false });
        }
    }
    for (rdp_outputs) |name|
        try steps.append(arena, .{ .cmd = try std.fmt.allocPrint(arena, "output remove {s}", .{name}), .critical = false });
    return steps.toOwnedSlice(arena);
}

pub fn rdpBaseX(monitors: []const hypr.MonitorState) i32 {
    return rdpX(monitors);
}

/// Output (plan index) for each monitor's workspaces; null for non-physical or disabled monitors.
/// Physical monitors map in reading order onto the client's monitors; extras go to RDP-1.
pub fn workspaceTargets(monitors: []const hypr.MonitorState, plan: *const multimon.SessionPlan, out: []?u8) void {
    std.debug.assert(out.len >= monitors.len);
    const Pos = struct { i: usize, x: i64, y: i64 };
    const less = struct {
        fn f(_: void, a: Pos, b: Pos) bool {
            return a.x < b.x or (a.x == b.x and (a.y < b.y or (a.y == b.y and a.i < b.i)));
        }
    }.f;
    var phys: [64]Pos = undefined;
    var np: usize = 0;
    for (monitors, 0..) |m, i| {
        out[i] = null;
        if (!isPhysical(m) or m.disabled or np == phys.len) continue;
        phys[np] = .{ .i = i, .x = m.x, .y = m.y };
        np += 1;
    }
    std.mem.sort(Pos, phys[0..np], {}, less);
    var outs: [multimon.max_monitors]Pos = undefined;
    const n = @min(plan.count, multimon.max_monitors);
    for (plan.outputs[0..n], outs[0..n], 0..) |o, *p, i| {
        const m = plan.monitors[o.monitor];
        p.* = .{ .i = i, .x = m.left, .y = m.top };
    }
    std.mem.sort(Pos, outs[0..n], {}, less);
    for (phys[0..np], 0..) |p, k| out[p.i] = if (k < n) @intCast(outs[k].i) else 0;
}

/// One output is exactly planEnter; with several, each output shows its workspace, the focused last.
pub fn planEnterOutputs(arena: std.mem.Allocator, monitors: []const hypr.MonitorState, workspaces: []const hypr.WorkspaceState, plan: *const multimon.SessionPlan) ![]Step {
    if (plan.count == 0 or plan.count > multimon.max_monitors) return error.InvalidPlan;
    if (plan.count == 1) {
        const o = plan.outputs[0];
        return planEnter(arena, monitors, workspaces, .{ .width = o.width, .height = o.height, .scale = @as(f64, @floatFromInt(o.scale_k)) / 120.0 });
    }
    var steps: std.ArrayList(Step) = .empty;
    try steps.appendSlice(arena, try multimon.planOutputCommands(arena, plan, monitors));
    const targets = try arena.alloc(?u8, monitors.len);
    workspaceTargets(monitors, plan, targets);
    var buf: [1400]u8 = undefined;
    for ([_]bool{ false, true }) |active_pass| {
        for (workspaces) |w| {
            if (!movable(monitors, w) or isActiveOn(monitors, w) != active_pass) continue;
            const t = targetOf(monitors, targets, w.monitor) orelse continue;
            try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatWorkspaceMove(&buf, w, plan.outputs[t].name())), .critical = false });
        }
    }
    for (monitors) |m| {
        if (!isPhysical(m) or m.disabled) continue;
        try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatMonitorOff(&buf, m.name)), .critical = true });
    }
    // Each output shows its first monitor's workspace (left to right), or the focused one's.
    var shown: [multimon.max_monitors]?usize = @splat(null);
    var focused_out: ?usize = null;
    for (monitors, targets, 0..) |m, t, i| {
        const o = t orelse continue;
        if (m.workspace.len == 0) continue;
        if (m.focused) focused_out = o;
        const prev = shown[o] orelse {
            shown[o] = i;
            continue;
        };
        const cur = monitors[prev];
        const first = m.x < cur.x or (m.x == cur.x and m.y < cur.y);
        if (m.focused or (!cur.focused and first)) shown[o] = i;
    }
    for ([_]bool{ false, true }) |focused_pass| {
        for (shown[0..plan.count], 0..) |maybe, o| {
            const i = maybe orelse continue;
            if ((focused_out == o) != focused_pass) continue;
            const m = monitors[i];
            const ws: hypr.WorkspaceState = .{ .id = m.workspace_id, .name = m.workspace, .monitor = m.name };
            if (ws.isSpecial()) continue;
            try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatFocusMonitor(&buf, plan.outputs[o].name())), .critical = false });
            try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatFocusWorkspaceHere(&buf, ws)), .critical = false });
        }
    }
    return steps.toOwnedSlice(arena);
}

fn targetOf(monitors: []const hypr.MonitorState, targets: []const ?u8, name: []const u8) ?u8 {
    for (monitors, targets) |m, t| {
        if (std.mem.eql(u8, m.name, name)) return t;
    }
    return null;
}

/// Secondary outputs first, RDP-1 (the primary) last, for `output remove`.
pub fn rdpOutputNames(arena: std.mem.Allocator, plan: *const multimon.SessionPlan) ![]const []const u8 {
    if (plan.count == 0 or plan.count > multimon.max_monitors) return error.InvalidPlan;
    const names = try arena.alloc([]const u8, plan.count);
    for (names, 0..) |*n, k| n.* = try arena.dupe(u8, plan.outputs[plan.count - 1 - k].name());
    return names;
}

/// Each output's monitor rule again; a config reload drops runtime rules.
pub fn planRules(arena: std.mem.Allocator, plan: *const multimon.SessionPlan) ![]Step {
    if (plan.count > multimon.max_monitors) return error.InvalidPlan;
    var steps: std.ArrayList(Step) = .empty;
    var buf: [1400]u8 = undefined;
    for (plan.outputs[0..plan.count]) |*o| {
        const rule = try hypr.formatMonitorRule(&buf, o.name(), o.width, o.height, 60, o.x, o.y, @as(f64, @floatFromInt(o.scale_k)) / 120.0, 0);
        try steps.append(arena, .{ .cmd = try arena.dupe(u8, rule), .critical = true });
    }
    return steps.toOwnedSlice(arena);
}

/// A new client layout (MS-RDPEDISP 2.2.2.2): workspaces of vanishing RDP outputs move to RDP-1.
pub fn planRelayout(arena: std.mem.Allocator, plan: *const multimon.SessionPlan, current: []const hypr.MonitorState, workspaces: []const hypr.WorkspaceState) ![]Step {
    if (plan.count == 0 or plan.count > multimon.max_monitors) return error.InvalidPlan;
    var steps: std.ArrayList(Step) = .empty;
    var buf: [1400]u8 = undefined;
    for (workspaces) |w| {
        if (w.isSpecial() or w.windows == 0 or !hypr.isRdpOutput(w.monitor) or planned(plan, w.monitor)) continue;
        try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatWorkspaceMove(&buf, w, plan.outputs[0].name())), .critical = false });
    }
    for (current) |c| {
        if (!hypr.isRdpOutput(c.name) or planned(plan, c.name)) continue;
        try steps.append(arena, .{ .cmd = try std.fmt.allocPrint(arena, "output remove {s}", .{c.name}), .critical = false });
    }
    try steps.appendSlice(arena, try orderedOutputSteps(arena, plan, current));
    return steps.toOwnedSlice(arena);
}

fn planned(plan: *const multimon.SessionPlan, name: []const u8) bool {
    for (plan.outputs[0..plan.count]) |*o| {
        if (std.mem.eql(u8, o.name(), name)) return true;
    }
    return false;
}

/// Position, mode / scale, sides swapped by a 90/270 degree transform.
const LayoutBox = struct {
    x: f64,
    y: f64,
    w: f64,
    h: f64,

    fn of(x: i32, y: i32, width: u32, height: u32, scale: f64, transform: u8) LayoutBox {
        const sw = @as(f64, @floatFromInt(width)) / scale;
        const sh = @as(f64, @floatFromInt(height)) / scale;
        const swap = transform % 2 == 1;
        return .{ .x = @floatFromInt(x), .y = @floatFromInt(y), .w = if (swap) sh else sw, .h = if (swap) sw else sh };
    }

    /// More than touching (half a pixel of rounding is not an overlap).
    fn overlaps(a: LayoutBox, b: LayoutBox) bool {
        const e = 0.5;
        return a.x < b.x + b.w - e and b.x < a.x + a.w - e and a.y < b.y + b.h - e and b.y < a.y + a.h - e;
    }
};

/// Ordered so Hyprland never sees two monitors overlap: it warns after any IPC command.
/// Swapping outputs park one right of everything first; unplanned RDP outputs count as removed.
pub fn orderedOutputSteps(arena: std.mem.Allocator, plan: *const multimon.SessionPlan, current: []const hypr.MonitorState) ![]Step {
    const n = plan.count;
    if (n > multimon.max_monitors) return error.InvalidPlan;
    var fixed: std.ArrayList(LayoutBox) = .empty;
    var now: [multimon.max_monitors]?LayoutBox = @splat(null);
    var exists: [multimon.max_monitors]bool = @splat(false);
    var goal: [multimon.max_monitors]LayoutBox = undefined;
    var right: f64 = 0;
    for (plan.outputs[0..n], 0..) |*o, i| {
        goal[i] = LayoutBox.of(o.x, o.y, o.width, o.height, scaleOf(o), 0);
        right = @max(right, goal[i].x + goal[i].w);
    }
    for (current) |c| {
        const b = LayoutBox.of(c.x, c.y, c.width, c.height, if (c.scale > 0) c.scale else 1, c.transform);
        const idx = for (plan.outputs[0..n], 0..) |*o, i| {
            if (std.mem.eql(u8, o.name(), c.name)) break i;
        } else null;
        if (idx) |i| {
            exists[i] = true;
            if (!c.disabled) now[i] = b;
        } else if (!c.disabled and !hypr.isRdpOutput(c.name)) {
            try fixed.append(arena, b);
        } else continue;
        if (!c.disabled) right = @max(right, b.x + b.w);
    }
    var steps: std.ArrayList(Step) = .empty;
    var done: [multimon.max_monitors]bool = @splat(false);
    var parked: [multimon.max_monitors]bool = @splat(false);
    var left = n;
    while (left > 0) {
        var progress = false;
        for (0..n) |i| {
            if (done[i] or !free(goal[i], i, fixed.items, now[0..n])) continue;
            try place(arena, &steps, &plan.outputs[i], plan.outputs[i].x, exists[i]);
            exists[i] = true;
            now[i] = goal[i];
            done[i] = true;
            left -= 1;
            progress = true;
        }
        if (progress or left == 0) continue;
        const i = for (0..n) |k| {
            if (!done[k] and !parked[k]) break k;
        } else {
            // Every waiting output is parked and the blocker cannot move: place them anyway.
            for (0..n) |k| if (!done[k]) {
                try place(arena, &steps, &plan.outputs[k], plan.outputs[k].x, exists[k]);
                done[k] = true;
            };
            break;
        };
        const park_x: i32 = @intFromFloat(@min(@ceil(right), @as(f64, std.math.maxInt(i32) / 2)));
        try place(arena, &steps, &plan.outputs[i], park_x, exists[i]);
        exists[i] = true;
        now[i] = .{ .x = @floatFromInt(park_x), .y = goal[i].y, .w = goal[i].w, .h = goal[i].h };
        right = now[i].?.x + now[i].?.w;
        parked[i] = true;
    }
    return steps.toOwnedSlice(arena);
}

fn scaleOf(o: *const multimon.OutputPlan) f64 {
    return @as(f64, @floatFromInt(o.scale_k)) / 120.0;
}

fn free(b: LayoutBox, self: usize, fixed: []const LayoutBox, now: []const ?LayoutBox) bool {
    for (fixed) |f| if (b.overlaps(f)) return false;
    for (now, 0..) |maybe, j| {
        const o = maybe orelse continue;
        if (j != self and b.overlaps(o)) return false;
    }
    return true;
}

/// The rule at x (planned y, mode, scale), then `output create` if missing.
fn place(arena: std.mem.Allocator, steps: *std.ArrayList(Step), o: *const multimon.OutputPlan, x: i32, exists: bool) !void {
    var buf: [512]u8 = undefined;
    const rule = try hypr.formatMonitorRule(&buf, o.name(), o.width, o.height, 60, x, o.y, scaleOf(o), 0);
    try steps.append(arena, .{ .cmd = try arena.dupe(u8, rule), .critical = true });
    if (!exists) try steps.append(arena, .{ .cmd = try std.fmt.allocPrint(arena, "output create headless {s}", .{o.name()}), .critical = true });
}

/// Best effort: an unbound touch device acts on the focused monitor instead.
pub fn planDeviceBindings(arena: std.mem.Allocator, plan: *const multimon.SessionPlan, pen: bool) ![]Step {
    if (plan.count > multimon.max_monitors) return error.InvalidPlan;
    var steps: std.ArrayList(Step) = .empty;
    var buf: [700]u8 = undefined;
    var name: [32]u8 = undefined;
    for (plan.outputs[0..plan.count], 0..) |*o, i| {
        for ([_]uinput.Kind{ .touch, .pen }) |kind| {
            if (kind == .pen and !pen) continue;
            const dev = try uinput.deviceName(&name, kind, i);
            try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatDeviceOutput(&buf, dev, o.name())), .critical = false });
        }
    }
    return steps.toOwnedSlice(arena);
}

/// Normal workspaces with windows on an enabled physical monitor (Hyprland drops empty ones).
fn movable(monitors: []const hypr.MonitorState, w: hypr.WorkspaceState) bool {
    return !w.isSpecial() and w.windows > 0 and onEnabledPhysical(monitors, w.monitor);
}

/// A desk look: physical monitors back as captured while the session stays connected.
pub fn planPhysicalOn(arena: std.mem.Allocator, monitors_in: []const hypr.MonitorState) ![]Step {
    const monitors = try neverDark(arena, monitors_in);
    var steps: std.ArrayList(Step) = .empty;
    var buf: [1400]u8 = undefined;
    for (monitors) |m| {
        if (!isPhysical(m) or m.disabled) continue;
        try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatMonitorRule(&buf, m.name, m.width, m.height, m.refresh, m.x, m.y, m.scale, m.transform)), .critical = true });
    }
    try steps.append(arena, .{ .cmd = "eval hl.dispatch(hl.dsp.dpms({ action = \"on\" }))", .critical = false });
    return steps.toOwnedSlice(arena);
}

/// The desk is never left dark: with no enabled physical monitor in the snapshot, every
/// physical monitor Hyprland knows comes back in its last mode.
fn neverDark(arena: std.mem.Allocator, monitors: []const hypr.MonitorState) ![]const hypr.MonitorState {
    if (!allOff(monitors)) return monitors;
    const out = try arena.dupe(hypr.MonitorState, monitors);
    for (out) |*m| {
        if (isPhysical(m.*)) m.disabled = false;
    }
    return out;
}

fn allOff(monitors: []const hypr.MonitorState) bool {
    var any_on = false;
    var any_off = false;
    for (monitors) |m| {
        if (!isPhysical(m)) continue;
        if (m.disabled) any_off = true else any_on = true;
    }
    return any_off and !any_on;
}

/// Those enabled before the session, or all if the never-dark rule lit them.
pub fn planPhysicalOff(arena: std.mem.Allocator, monitors_in: []const hypr.MonitorState) ![]Step {
    const monitors = try neverDark(arena, monitors_in);
    var steps: std.ArrayList(Step) = .empty;
    var buf: [1100]u8 = undefined;
    for (monitors) |m| {
        if (!isPhysical(m) or m.disabled) continue;
        try steps.append(arena, .{ .cmd = try arena.dupe(u8, try hypr.formatMonitorOff(&buf, m.name)), .critical = true });
    }
    return steps.toOwnedSlice(arena);
}

fn onEnabledPhysical(monitors: []const hypr.MonitorState, name: []const u8) bool {
    for (monitors) |m| {
        if (std.mem.eql(u8, m.name, name)) return isPhysical(m) and !m.disabled;
    }
    return false;
}

fn isActiveOn(monitors: []const hypr.MonitorState, w: hypr.WorkspaceState) bool {
    for (monitors) |m| {
        if (std.mem.eql(u8, m.name, w.monitor)) return std.mem.eql(u8, m.workspace, w.name);
    }
    return false;
}

fn isPhysical(m: hypr.MonitorState) bool {
    return !hypr.isRdpOutput(m.name) and !hypr.isFallback(m.name);
}

/// Disconnect: restore only after the lock is observed and settled, so the desk never shows the desktop.
pub const Leave = struct {
    state: State = .need_lock,
    attempts: u32 = 0,

    pub const State = enum { need_lock, waiting_for_lock, restore, done };

    pub const Action = union(enum) {
        request_lock,
        poll_lock,
        restore,
        /// Lock never confirmed: keep the physical monitors dark and retry.
        keep_dark_and_retry,
        finished,
    };

    pub const max_poll_attempts = 50; // e.g. 100 ms apart

    pub fn next(l: *Leave, locked: bool) Action {
        switch (l.state) {
            .need_lock => {
                if (locked) {
                    l.state = .restore;
                    return .restore;
                }
                l.state = .waiting_for_lock;
                l.attempts = 0;
                return .request_lock;
            },
            .waiting_for_lock => {
                if (locked) {
                    l.state = .restore;
                    return .restore;
                }
                l.attempts += 1;
                if (l.attempts >= max_poll_attempts) {
                    l.state = .need_lock;
                    return .keep_dark_and_retry;
                }
                return .poll_lock;
            },
            .restore => {
                l.state = .done;
                return .finished;
            },
            .done => return .finished,
        }
    }
};

/// When an observed lock can be trusted after keys were sent: Omarchy's lock unlocks whenever
/// a password check in flight succeeds, and a lock request does not stop it.
pub const Settle = struct {
    started_ms: i64,
    keys_ms: i64,
    /// The compositor processed every key (a round trip after them).
    delivered: bool,
    stable: u32 = 0,
    /// Since when the lock screen says it holds no lock.
    released_ms: ?i64 = null,

    /// Keys older than this started no check that is still running.
    pub const window_ms = 30_000;
    pub const quiet_ms = 3000;
    pub const release_ms = 1000;
    pub const max_ms = 5000;
    pub const poll_ms = 150;

    pub const Screen = enum {
        /// Holds its lock and checks no password.
        idle,
        checking,
        /// Holds its lock; whether it checks a password is not known.
        unknown,
        /// Holds no lock (an unlock under way, or another locker's lock).
        released,
        silent,
    };

    pub const Verdict = enum { wait, unlocked, settled, gave_up };

    /// `locked`: Hyprland's session lock (null: unknown); `screen` is ignored when false.
    pub fn next(s: *Settle, now: i64, locked: ?bool, screen: Screen) Verdict {
        if (locked == false) return .unlocked;
        const quiet = now >= s.keys_ms + quiet_ms;
        if (screen != .released) s.released_ms = null;
        if (screen == .idle) s.stable += 1 else s.stable = 0;
        const settled = switch (screen) {
            .idle => s.stable >= 2 and (s.delivered or quiet),
            .checking => false,
            .unknown, .silent => quiet,
            .released => blk: {
                const since = s.released_ms orelse now;
                s.released_ms = since;
                break :blk quiet and now >= since + release_ms;
            },
        };
        if (settled) return .settled;
        if (now >= s.started_ms + max_ms) return .gave_up;
        return .wait;
    }
};

fn snapshotFixture() [3]hypr.MonitorState {
    return .{
        .{ .name = "eDP-1", .width = 2880, .height = 1800, .refresh = 120, .x = 0, .y = 0, .scale = 2, .transform = 0, .disabled = false, .workspace = "1", .workspace_id = 1, .focused = true },
        .{ .name = "DP-1", .width = 3840, .height = 2160, .refresh = 160, .x = 1440, .y = 0, .scale = 1.5, .transform = 0, .disabled = false, .workspace = "2", .workspace_id = 2 },
        .{ .name = "HDMI-A-1", .width = 1920, .height = 1080, .refresh = 60, .x = 0, .y = 0, .scale = 1, .transform = 0, .disabled = true, .workspace = "" },
    };
}

fn workspacesFixture() [6]hypr.WorkspaceState {
    return .{
        .{ .id = 1, .name = "1", .monitor = "eDP-1", .windows = 3 },
        .{ .id = 2, .name = "2", .monitor = "DP-1", .windows = 1 },
        .{ .id = 4, .name = "4", .monitor = "eDP-1", .windows = 2 },
        .{ .id = -1337, .name = "notes", .monitor = "DP-1", .windows = 1 },
        .{ .id = -98, .name = "special:magic", .monitor = "eDP-1", .windows = 1 },
        .{ .id = 5, .name = "5", .monitor = "eDP-1", .windows = 0 }, // empty: Hyprland drops it
    };
}

fn indexOf(steps: []const Step, needle: []const u8) ?usize {
    for (steps, 0..) |st, i| if (std.mem.indexOf(u8, st.cmd, needle) != null) return i;
    return null;
}

test "enter: create, move every workspace, then darken physical monitors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const mons = snapshotFixture();
    const wss = workspacesFixture();
    const steps = try planEnter(arena.allocator(), &mons, &wss, .{ .width = 1920, .height = 1080, .scale = 1.25 });
    try std.testing.expectEqual(@as(usize, 10), steps.len);
    try std.testing.expectEqualStrings("eval hl.dispatch(hl.dsp.focus({ monitor = \"RDP-1\" }))", steps[8].cmd);
    try std.testing.expectEqualStrings("eval hl.dispatch(hl.dsp.focus({ workspace = \"1\", on_current_monitor = true }))", steps[9].cmd);
    try std.testing.expectEqualStrings("output create headless RDP-1", steps[1].cmd);
    try std.testing.expect(steps[0].critical and steps[1].critical);
    try std.testing.expect(std.mem.indexOf(u8, steps[0].cmd, "output = \"RDP-1\"") != null);
    // Right of DP-1 (x 1440, 3840 px at 1.5 = 2560 logical).
    try std.testing.expect(std.mem.indexOf(u8, steps[0].cmd, "position = \"4000x0\"") != null);
    for ([_][]const u8{ "\"1\"", "\"2\"", "\"4\"", "\"name:notes\"" }) |sel| {
        const i = indexOf(steps, sel).?;
        try std.testing.expect(!steps[i].critical);
        try std.testing.expect(std.mem.endsWith(u8, steps[i].cmd, "monitor = \"RDP-1\" }))"));
        // Every move happens before any monitor goes dark.
        try std.testing.expect(i < indexOf(steps, "disabled = true").?);
    }
    try std.testing.expect(indexOf(steps, "special:") == null);
    try std.testing.expect(indexOf(steps, "\"5\"") == null);
    const off = indexOf(steps, "\"eDP-1\", disabled = true").?;
    try std.testing.expect(steps[off].critical);
    try std.testing.expect(indexOf(steps, "\"DP-1\", disabled = true") != null);
    // A monitor that was already off is left alone.
    try std.testing.expect(indexOf(steps, "HDMI-A-1") == null);
}

test "restore: exact modes with disabled=false, workspaces back (active last), RDP output removed last" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const mons = snapshotFixture();
    const wss = workspacesFixture();
    const steps = try planRestore(arena.allocator(), &mons, &wss);
    try std.testing.expectEqual(@as(usize, 13), steps.len);
    for (steps[2..4]) |st| try std.testing.expect(st.wait_on);
    try std.testing.expect(indexOf(steps, "workspace.move").? > 3);
    try std.testing.expectEqualStrings(
        "eval hl.monitor({ output = \"DP-1\", disabled = false, mode = \"3840x2160@160.000\", position = \"1440x0\", scale = 1.500000, transform = 0 })",
        steps[1].cmd,
    );
    // Inactive workspaces first, then each monitor's active one.
    try std.testing.expect(indexOf(steps, "\"4\", monitor = \"eDP-1\"").? < indexOf(steps, "\"1\", monitor = \"eDP-1\"").?);
    try std.testing.expect(indexOf(steps, "\"name:notes\", monitor = \"DP-1\"").? < indexOf(steps, "\"2\", monitor = \"DP-1\"").?);
    // Then each monitor shows its workspace again, the focused one last.
    const dp = indexOf(steps, "focus({ monitor = \"DP-1\" })").?;
    const edp = indexOf(steps, "focus({ monitor = \"eDP-1\" })").?;
    try std.testing.expect(dp < edp);
    try std.testing.expectEqualStrings("eval hl.dispatch(hl.dsp.focus({ workspace = \"1\", on_current_monitor = true }))", steps[edp + 1].cmd);
    try std.testing.expect(indexOf(steps, "\"5\"") == null);
    try std.testing.expectEqualStrings("output remove RDP-1", steps[steps.len - 1].cmd);
    try std.testing.expect(indexOf(steps, "HDMI-A-1") == null);
}

test "desk look: physical monitors on and off, RDP-1 untouched" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const mons = snapshotFixture();
    const on = try planPhysicalOn(arena.allocator(), &mons);
    try std.testing.expectEqual(@as(usize, 3), on.len);
    try std.testing.expect(indexOf(on, "\"eDP-1\", disabled = false").? < indexOf(on, "dpms").?);
    const off = try planPhysicalOff(arena.allocator(), &mons);
    try std.testing.expectEqual(@as(usize, 2), off.len);
    for ([_][]const Step{ on, off }) |plan| {
        try std.testing.expect(indexOf(plan, "RDP-1") == null);
        try std.testing.expect(indexOf(plan, "HDMI-A-1") == null);
    }
}

test "restore never leaves the desk dark" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // Snapshot taken while the only physical monitor was off.
    const mons = [_]hypr.MonitorState{
        .{ .name = "Virtual-1", .width = 1280, .height = 800, .refresh = 75, .x = 0, .y = 0, .scale = 1, .transform = 0, .disabled = true, .workspace = "" },
        .{ .name = "FALLBACK", .width = 1920, .height = 1080, .refresh = 60, .x = 0, .y = 0, .scale = 1, .transform = 0, .disabled = false, .workspace = "2" },
    };
    const steps = try planRestore(arena.allocator(), &mons, &.{});
    try std.testing.expect(indexOf(steps, "\"Virtual-1\", disabled = false").? < indexOf(steps, "output remove RDP-1").?);
    try std.testing.expect(indexOf(steps, "FALLBACK") == null);
    // A deliberately disabled second monitor stays off when another is on.
    const two = [_]hypr.MonitorState{
        .{ .name = "DP-1", .width = 1920, .height = 1080, .refresh = 60, .x = 0, .y = 0, .scale = 1, .transform = 0, .disabled = false, .workspace = "1" },
        .{ .name = "DP-2", .width = 1920, .height = 1080, .refresh = 60, .x = 1920, .y = 0, .scale = 1, .transform = 0, .disabled = true, .workspace = "" },
    };
    const steps2 = try planRestore(arena.allocator(), &two, &.{});
    try std.testing.expect(indexOf(steps2, "DP-2") == null);
}

test "leave never restores before the lock is observed" {
    var l = Leave{};
    try std.testing.expectEqual(Leave.Action.request_lock, l.next(false));
    for (0..Leave.max_poll_attempts - 1) |_| try std.testing.expectEqual(Leave.Action.poll_lock, l.next(false));
    // Lock never came: stay dark and ask again.
    try std.testing.expectEqual(Leave.Action.keep_dark_and_retry, l.next(false));
    try std.testing.expectEqual(Leave.Action.request_lock, l.next(false));
    try std.testing.expectEqual(Leave.Action.poll_lock, l.next(false));
    try std.testing.expectEqual(Leave.Action.restore, l.next(true));
    try std.testing.expectEqual(Leave.Action.finished, l.next(true));

    // Already locked at disconnect time (idle lock): restore immediately.
    var l2 = Leave{};
    try std.testing.expectEqual(Leave.Action.restore, l2.next(true));
}

test "settle: a lock is trusted only once the lock screen has been idle twice in a row" {
    var s = Settle{ .started_ms = 1000, .keys_ms = 900, .delivered = true };
    try std.testing.expectEqual(Settle.Verdict.wait, s.next(1000, true, .idle));
    try std.testing.expectEqual(Settle.Verdict.settled, s.next(1150, true, .idle));
    // Checking in between: twice in a row again.
    var t = Settle{ .started_ms = 1000, .keys_ms = 900, .delivered = true };
    try std.testing.expectEqual(Settle.Verdict.wait, t.next(1000, true, .idle));
    try std.testing.expectEqual(Settle.Verdict.wait, t.next(1150, true, .checking));
    try std.testing.expectEqual(Settle.Verdict.wait, t.next(1300, true, .idle));
    try std.testing.expectEqual(Settle.Verdict.settled, t.next(1450, true, .idle));
    // No answer from Hyprland: the lock screen decides; Leave still needs the lock observed.
    var u = Settle{ .started_ms = 1000, .keys_ms = 900, .delivered = true };
    try std.testing.expectEqual(Settle.Verdict.wait, u.next(1000, null, .idle));
    try std.testing.expectEqual(Settle.Verdict.settled, u.next(1150, null, .idle));
}

test "settle: a password check that unlocks is waited for, whatever the lock screen said before" {
    var s = Settle{ .started_ms = 0, .keys_ms = 0, .delivered = true };
    for (0..20) |i| try std.testing.expectEqual(Settle.Verdict.wait, s.next(@intCast(i * 150), true, .checking));
    try std.testing.expectEqual(Settle.Verdict.unlocked, s.next(3100, false, .checking));
    // An unlock under way: the lock screen released, Hyprland still locked; never settled.
    var r = Settle{ .started_ms = 0, .keys_ms = 0, .delivered = true };
    try std.testing.expectEqual(Settle.Verdict.wait, r.next(100, true, .checking));
    try std.testing.expectEqual(Settle.Verdict.wait, r.next(250, true, .released));
    try std.testing.expectEqual(Settle.Verdict.unlocked, r.next(400, false, .released));
}

test "settle: keys the compositor has not confirmed count only after the quiet time" {
    var s = Settle{ .started_ms = 100, .keys_ms = 0, .delivered = false };
    try std.testing.expectEqual(Settle.Verdict.wait, s.next(100, true, .idle));
    try std.testing.expectEqual(Settle.Verdict.wait, s.next(250, true, .idle));
    try std.testing.expectEqual(Settle.Verdict.wait, s.next(2999, true, .idle));
    try std.testing.expectEqual(Settle.Verdict.settled, s.next(3000, true, .idle));
}

test "settle: without status, or with a fingerprint check always running, the quiet time after the last key" {
    for ([_]Settle.Screen{ .silent, .unknown }) |screen| {
        var s = Settle{ .started_ms = 500, .keys_ms = 400, .delivered = true };
        try std.testing.expectEqual(Settle.Verdict.wait, s.next(500, true, screen));
        try std.testing.expectEqual(Settle.Verdict.wait, s.next(3399, true, screen));
        try std.testing.expectEqual(Settle.Verdict.settled, s.next(3400, true, screen));
    }
    var old = Settle{ .started_ms = 10_000, .keys_ms = 0, .delivered = false };
    try std.testing.expectEqual(Settle.Verdict.settled, old.next(10_000, true, .silent));
}

test "settle: a lock that is not the lock screen's (another locker) counts after release_ms, as without status" {
    var s = Settle{ .started_ms = 5000, .keys_ms = 0, .delivered = true };
    try std.testing.expectEqual(Settle.Verdict.wait, s.next(5000, true, .released));
    try std.testing.expectEqual(Settle.Verdict.wait, s.next(5999, true, .released));
    // Idle in between starts it over.
    try std.testing.expectEqual(Settle.Verdict.wait, s.next(6000, true, .idle));
    try std.testing.expectEqual(Settle.Verdict.wait, s.next(6150, true, .released));
    try std.testing.expectEqual(Settle.Verdict.wait, s.next(7149, true, .released));
    try std.testing.expectEqual(Settle.Verdict.settled, s.next(7150, true, .released));
}

test "settle: still checking when the wait ends gives up (the desk stays dark)" {
    var s = Settle{ .started_ms = 0, .keys_ms = 0, .delivered = true };
    var now: i64 = 0;
    while (now < Settle.max_ms) : (now += Settle.poll_ms) try std.testing.expectEqual(Settle.Verdict.wait, s.next(now, true, .checking));
    try std.testing.expectEqual(Settle.Verdict.gave_up, s.next(Settle.max_ms, true, .checking));
    var t = Settle{ .started_ms = 0, .keys_ms = 0, .delivered = true };
    try std.testing.expectEqual(Settle.Verdict.unlocked, t.next(Settle.max_ms + 100, false, .checking));
}
