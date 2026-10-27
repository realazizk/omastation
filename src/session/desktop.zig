//! The live desktop behind one RDP session: `enter` fences the desk and moves the workspaces onto
//! headless RDP-N outputs (one per client monitor, MS-RDPBCGR 2.2.1.3.6); `leave` locks before giving the desk back.

const std = @import("std");
const c = @import("c");
const wl = @import("../wl/wl.zig");
const hypr = @import("hypr.zig");
const console = @import("console.zig");
const altdrag = @import("altdrag.zig");
const textbinds = @import("textbinds.zig");
const keyrepeat = @import("keyrepeat.zig");
const probe = @import("probe.zig");
const multimon = @import("multimon.zig");
const plugin = @import("plugin.zig");
const touch = @import("touch.zig");
const uinput = @import("uinput.zig");
const helper_proto = @import("helper_proto.zig");
const rdpei = @import("../channel/rdpei.zig");
const keyboard = @import("../input/keyboard.zig");
const layouts = @import("../input/layouts.zig");
const translate = @import("../input/translate.zig");
const fastpath = @import("../proto/fastpath.zig");
const cursor_mod = @import("cursor.zig");

const log = std.log.scoped(.desktop);

pub const Error = error{
    EnterFailed,
    OutputMissing,
    FenceUnavailable,
    LockFailed,
    NoSpaceLeft,
    BadLayout,
    HelperRefused,
} || hypr.Error || wl.Error || keyboard.Error;

/// Per step of a helper exchange: connect, send, reply.
const helper_timeout_ms = 2000;

pub const default_locker_status_command = "LANG=C.UTF-8 OMARCHY_PATH=${OMARCHY_PATH:-/usr/share/omarchy} PATH=/usr/share/omarchy/bin:$PATH exec omarchy-shell lock status";

pub const CursorMode = cursor_mod.Mode;

pub const Options = struct {
    width: u32,
    height: u32,
    scale_percent: u32 = 100,
    /// TS_UD_CS_CORE.keyboardLayout (Windows KLID); 0 = unknown.
    keyboard_layout: u32 = 0,
    lock_command: []const u8 = "omarchy-system-lock",
    /// Prints the lock screen's status as JSON; exit 127 means another locker, given a fixed settle time.
    locker_status_command: [:0]const u8 = default_locker_status_command,
    helper_socket: [:0]const u8 = "/run/omastation/helper.sock",
    require_fence: bool = false,
    cursor: cursor_mod.Mode = .auto,
    capture_backend: wl.capture.Backend = .ext,
    /// Option + drag bindings added, for omastation-recover after a crash; null: none.
    binds_state_path: ?[:0]const u8 = null,
    /// Console restore plan while remote, for omastation-recover after a crash; null: none.
    console_state_path: ?[:0]const u8 = null,
    /// Validated. Null or one monitor: a single RDP-1 of width x height at scale_percent.
    layout: ?multimon.Layout = null,
};

pub const OutputInfo = struct {
    /// Plan order: 0 is RDP-1, the primary monitor.
    index: u8,
    /// "RDP-<index+1>"; valid until the next relayout.
    name: []const u8,
    /// Index of the client monitor (TS_MONITOR_DEF order) it shows.
    monitor: u8,
    /// Also the RDPGFX surface size.
    width: u32,
    height: u32,
    /// Hyprland scale = scale_k / 120.
    scale_k: u32,
    /// MAP_SURFACE_TO_OUTPUT origin (MS-RDPEGFX 2.2.2.20).
    origin_x: u32,
    origin_y: u32,
};

pub const TouchMode = enum {
    off,
    devices,
    /// No helper: contacts drive the virtual pointers (rdpei.Emulator).
    emulated,
};

pub const TouchOptions = struct {
    /// Also create pen tablets (MS-RDPEI V200 or later).
    pen: bool = true,
};

/// Outputs after RDP-1, which is Desktop.output/capture/vp.
const More = struct {
    output: ?*wl.Output = null,
    capture: ?*wl.Capture = null,
    vp: ?wl.VirtualPointer = null,
};

pub const max_twins = 8;

pub const Desktop = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    ipc: hypr.Ipc,
    opts: Options,
    fit: hypr.Fit,
    plan: multimon.SessionPlan,
    /// Null with a single monitor.
    layout: ?multimon.Layout = null,
    /// The client's last requested layout; `plan` is it with `user_scale` applied.
    client_layout: multimon.Layout,
    /// Scales set in the session, kept while the client asks for the same scale, as Windows does.
    user_scale: [multimon.max_monitors]?UserScale = @splat(null),
    /// Reinstalled after every config reload.
    scale_watch: bool = false,
    /// Own RDP output rules not yet reported back by the watch, by output.
    own_rules: [multimon.max_monitors]RuleQueue = @splat(.{}),

    monitors: []const hypr.MonitorState = &.{},
    workspaces: []const hypr.WorkspaceState = &.{},
    /// Remote mode: the physical monitors are off.
    entered: bool = false,

    client: ?*wl.Client = null,
    output: ?*wl.Output = null,
    capture: ?*wl.Capture = null,
    more: [multimon.max_monitors - 1]More = @splat(.{}),
    vk: ?wl.VirtualKeyboard = null,
    keymap: ?keyboard.Keymap = null,
    kstate: ?keyboard.State = null,
    carry_locks: ?keyboard.Locks = null,
    keys: translate.KeyDecoder = .{},
    /// Text keyboards (unlock, Unicode events), used in turn: Hyprland forwards a
    /// keymap only when the active keyboard changes, so a grown keymap goes to the other.
    tvk: [2]?wl.VirtualKeyboard = .{ null, null },
    tvk_generation: [2]?u32 = .{ null, null },
    tvk_current: u1 = 0,
    text: keyboard.TextKeymap = .{},
    text_binds: textbinds.State = .{},
    /// Key repeat from the client only.
    repeat_rules: textbinds.RepeatRules = .{},
    /// The configured keymap Hyprland's bindings read keycodes with; null if it does not compile.
    bind_keymap: ?keyboard.Keymap = null,
    /// The key the client repeats, its modifiers, and whether repeats pass.
    rep_key: ?u16 = null,
    rep_mods: u32 = 0,
    rep_ok: bool = false,
    /// No repeat query before this after a failure (CLOCK_MONOTONIC).
    rep_retry_ms: i64 = 0,
    utf16: keyboard.Utf16Decoder = .{},
    vp: ?wl.VirtualPointer = null,
    cursors: [multimon.max_monitors]?*wl.Cursor = @splat(null),
    cursor_seen: [multimon.max_monitors]u32 = @splat(0),
    cursor_inside: [multimon.max_monitors]bool = @splat(false),
    /// An image came while the cursor was not over the output.
    cursor_missed: [multimon.max_monitors]bool = @splat(false),
    cursor_probes: [multimon.max_monitors]u8 = @splat(0),
    /// Sessions reopened after stopping before their first image.
    cursor_restarts: [multimon.max_monitors]u8 = @splat(0),
    cursor_hot_seen: [multimon.max_monitors]u32 = @splat(0),
    /// The plugin lacks `hyprctl omastation-cursor`; asked again next session.
    cursor_info_missing: bool = false,
    cursor: cursor_mod.Tracker,
    /// The cursor went into or out of the frames: the captures must restart.
    captures_stale: bool = false,
    /// Buttons held per output's virtual pointer (bit i: held_button_codes[i]).
    held_buttons: [multimon.max_monitors]u8 = @splat(0),
    /// Buttons and wheel go to this output's pointer.
    pointer_on: u8 = 0,

    events_fd: c_int = -1,
    events_buf: [4096]u8 = undefined,
    events_len: usize = 0,
    helper_fd: c_int = -1,
    helper_buf: [64]u8 = undefined,
    helper_len: usize = 0,
    /// After the helper went away: when to fence again (touch_lost: whether touch had devices).
    refence_at_ms: ?i64 = null,
    touch_lost: bool = false,
    helper_refused: bool = false,
    desk_activity: bool = false,
    /// The desk has a look (`deskWantsIn`) until this time.
    contested_until_ms: ?i64 = null,
    /// Signed in at the desk: leaving must not lock again.
    desk_owns: bool = false,
    unlocking: ?Unlock = null,
    next_dpms_check_ms: i64 = 0,
    /// xdg-system-bell-v1 bells since the connection last looked.
    bells: u32 = 0,
    /// Option + drag bindings for a macOS client.
    alt_drag: bool = false,
    twin_keys: [max_twins][80]u8 = undefined,
    twin_lens: [max_twins]u8 = @splat(0),
    twin_count: u8 = 0,
    /// Null: not asked; an IPC failure counts as locked.
    lock_seen: ?bool = null,
    next_lock_check_ms: i64 = 0,
    lock_query: ?hypr.Pending = null,
    lock_query_ms: i64 = 0,
    lock_seen_ms: i64 = 0,
    lock_failed: bool = false,
    locker_probe: ?probe.Probe = null,
    locker_silence_logged: bool = false,
    /// Last key press sent: it may be a password's Return the lock screen is still checking.
    keys_ms: ?i64 = null,
    keys_delivered: bool = false,

    touch_mode: TouchMode = .off,
    touch_pen: bool = false,
    /// Bit i: the helper has output i's touchscreen (pen_devs: pen tablet).
    touch_devs: u16 = 0,
    pen_devs: u16 = 0,
    injector: ?touch.Injector = null,
    emulator: ?rdpei.Emulator = null,

    pub fn create(gpa: std.mem.Allocator, ipc: hypr.Ipc, opts: Options) Error!*Desktop {
        const d = try gpa.create(Desktop);
        errdefer gpa.destroy(d);
        var fit = hypr.fitDesktop(opts.width, opts.height, opts.scale_percent);
        var plan = singlePlan(fit, 0);
        var layout: ?multimon.Layout = null;
        if (opts.layout) |l| if (l.count > 1) {
            plan = multimon.planSession(&l, .{}) catch return error.BadLayout;
            fit = outputFit(&plan, 0);
            layout = l;
        };
        const text = try keyboard.TextKeymap.init(gpa);
        d.* = .{
            .gpa = gpa,
            .arena = std.heap.ArenaAllocator.init(gpa),
            .ipc = ipc,
            .opts = opts,
            .fit = fit,
            .plan = plan,
            .layout = layout,
            .client_layout = layout orelse singleLayout(opts.width, opts.height, opts.scale_percent),
            .text = text,
            .cursor = cursor_mod.Tracker.init(gpa, opts.cursor),
        };
        return d;
    }

    pub fn destroy(d: *Desktop) void {
        d.endUnlock();
        d.leave();
        d.cursor.deinit();
        d.text.deinit(d.gpa);
        d.arena.deinit();
        d.gpa.destroy(d);
    }

    /// May be a few pixels under the request so the scale is exact; with several monitors, the bounding box.
    pub fn width(d: *const Desktop) u32 {
        return if (d.multi()) d.plan.desktop_width else d.fit.width;
    }
    pub fn height(d: *const Desktop) u32 {
        return if (d.multi()) d.plan.desktop_height else d.fit.height;
    }

    fn multi(d: *const Desktop) bool {
        return d.plan.count > 1;
    }

    pub fn outputCount(d: *const Desktop) usize {
        return d.plan.count;
    }

    pub fn outputInfo(d: *const Desktop, i: usize) OutputInfo {
        const o = &d.plan.outputs[i];
        return .{
            .index = @intCast(i),
            .name = o.name(),
            .monitor = o.monitor,
            .width = o.width,
            .height = o.height,
            .scale_k = o.scale_k,
            .origin_x = o.origin_x,
            .origin_y = o.origin_y,
        };
    }

    pub fn sessionPlan(d: *const Desktop) *const multimon.SessionPlan {
        return &d.plan;
    }

    fn outputAt(d: *const Desktop, i: usize) ?*wl.Output {
        return if (i == 0) d.output else d.more[i - 1].output;
    }

    fn setOutput(d: *Desktop, i: usize, o: ?*wl.Output) void {
        if (i == 0) d.output = o else d.more[i - 1].output = o;
    }

    fn captureSlot(d: *Desktop, i: usize) *?*wl.Capture {
        return if (i == 0) &d.capture else &d.more[i - 1].capture;
    }

    fn captureAt(d: *const Desktop, i: usize) ?*wl.Capture {
        return if (i == 0) d.capture else d.more[i - 1].capture;
    }

    fn vpSlot(d: *Desktop, i: usize) *?wl.VirtualPointer {
        return if (i == 0) &d.vp else &d.more[i - 1].vp;
    }

    fn outputSize(d: *const Desktop, i: usize) [2]u32 {
        if (!d.multi()) return .{ d.fit.width, d.fit.height };
        return .{ d.plan.outputs[i].width, d.plan.outputs[i].height };
    }

    fn ownsOutput(d: *const Desktop, name: []const u8) bool {
        for (d.plan.outputs[0..d.plan.count]) |*o| {
            if (std.mem.eql(u8, o.name(), name)) return true;
        }
        return false;
    }

    pub fn enter(d: *Desktop) Error!void {
        std.debug.assert(!d.entered);
        const arena = d.arena.allocator();
        d.fenceDesk() catch |err| {
            if (d.opts.require_fence) return err;
            log.warn("desk input is NOT fenced ({t}): start `omastation helper` as root", .{err});
            // The helper may still be starting.
            d.refence_at_ms = nowMs() + refence_retry_ms;
        };
        errdefer d.unfenceDesk();

        // Listen first: Omarchy reloads the config on some monitor events.
        d.events_fd = d.ipc.connectEvents() catch -1;
        if (d.events_fd < 0) log.warn("no Hyprland event socket: config reloads during a session will not be undone", .{});
        d.monitors = try hypr.monitors(&d.ipc, arena);
        d.workspaces = try hypr.workspaces(&d.ipc, arena);
        const steps = if (d.layout) |*l| blk: {
            d.plan = multimon.planSession(l, .{ .base_x = console.rdpBaseX(d.monitors) }) catch return error.BadLayout;
            break :blk console.planEnterOutputs(arena, d.monitors, d.workspaces, &d.plan) catch |err| return planError(err);
        } else blk: {
            d.plan = singlePlan(d.fit, console.rdpBaseX(d.monitors));
            break :blk try console.planEnter(arena, d.monitors, d.workspaces, .{
                .width = d.fit.width,
                .height = d.fit.height,
                .scale = d.fit.scale(),
            });
        };
        for (steps) |st| {
            d.hyprCommand(st.cmd) catch |err| {
                if (st.critical) {
                    // Nothing was shown remotely yet: restore without locking.
                    log.err("entering remote mode failed at `{s}`: {t}", .{ st.cmd, err });
                    d.restoreConsole();
                    return error.EnterFailed;
                }
                log.warn("`{s}` failed: {t}", .{ st.cmd, err });
            };
        }
        d.entered = true; // from here on, leave() locks before restoring
        errdefer d.leave();
        d.writeRestoreFile();
        d.installScaleWatch();
        if (d.multi()) {
            for (d.plan.outputs[0..d.plan.count]) |*o| log.info("remote mode: {s} {d}x{d} scale {d:.4} at {d},{d}", .{
                o.name(), o.width, o.height, @as(f64, @floatFromInt(o.scale_k)) / 120.0, o.x, o.y,
            });
            log.info("remote mode: {d} outputs, {d} physical monitor(s) off", .{ d.plan.count, countPhysicalOn(d.monitors) });
        } else log.info("remote mode: {s} {d}x{d} scale {d:.4}, {d} physical monitor(s) off", .{
            console.rdp_output_name, d.fit.width, d.fit.height, d.fit.scale(), countPhysicalOn(d.monitors),
        });

        try d.connectWayland();
    }

    fn connectWayland(d: *Desktop) Error!void {
        const client = try wl.Client.connect(d.gpa, .{});
        d.client = client;
        // The new outputs' globals arrive asynchronously.
        var waited: i32 = 0;
        while (!d.outputsAnnounced(client, 0)) : (waited += 20) {
            if (waited >= 3000) return error.OutputMissing;
            _ = try client.dispatchTimeout(20);
        }
        for (0..d.plan.count) |i| d.setOutput(i, client.findOutput(d.plan.outputs[i].name()).?);
        // A cursor session needs the seat's pointer.
        for (0..d.plan.count) |i| d.vpSlot(i).* = try wl.VirtualPointer.init(client, d.outputAt(i).?);
        try d.startCursors();
        try d.startCapture();
        try d.setupKeyboard();
        try client.flush();
    }

    fn outputsAnnounced(d: *const Desktop, client: *wl.Client, first: usize) bool {
        for (d.plan.outputs[first..d.plan.count]) |*o| {
            if (client.findOutput(o.name()) == null) return false;
        }
        return true;
    }

    fn startCapture(d: *Desktop) Error!void {
        for (0..d.plan.count) |i| try d.startCaptureAt(i);
    }

    /// Restart output i's capture so a whole first frame arrives even on a still screen.
    pub fn restartCapture(d: *Desktop, i: usize) Error!void {
        if (d.client == null or i >= d.plan.count or d.outputAt(i) == null) return;
        try d.startCaptureAt(i);
        try d.client.?.flush();
    }

    /// Waits for the fitted mode: a new headless output starts at 1920x1080 and resizes a moment later.
    fn startCaptureAt(d: *Desktop, i: usize) Error!void {
        const client = d.client.?;
        const out = d.outputAt(i).?;
        const size = d.outputSize(i);
        var waited: i32 = 0;
        while (out.width != @as(i32, @intCast(size[0])) or out.height != @as(i32, @intCast(size[1]))) : (waited += 20) {
            if (waited >= 2000) {
                log.warn("{s} is {d}x{d}, expected {d}x{d}", .{ d.plan.outputs[i].name(), out.width, out.height, size[0], size[1] });
                break;
            }
            _ = try client.dispatchTimeout(20);
        }
        const slot = d.captureSlot(i);
        if (slot.*) |cap| cap.deinit();
        slot.* = null;
        slot.* = try wl.Capture.init(client, out, .{ .backend = d.opts.capture_backend, .paint_cursors = d.cursor.painting });
        if (slot.*.?.kind == .wlr) log.info("{s}: capturing with wlr-screencopy", .{d.plan.outputs[i].name()});
        try slot.*.?.requestFrame();
    }

    /// Hands the live desktop to a new client; the session stays unlocked and the desk fenced.
    pub fn adopt(d: *Desktop, opts: Options) Error!void {
        d.endUnlock(); // the previous connection's password, if still here
        d.stopQueries();
        d.forgetLock();
        d.closeTouch(); // its touch devices: the new client opens its own
        d.releaseKeys();
        d.releaseButtons() catch {};
        d.carry_locks = if (d.kstate) |*ks| ks.locks() else null;
        if (d.kstate) |*ks| ks.deinit();
        d.kstate = null;
        if (d.vk) |*vk| retireKeyboard(vk);
        d.vk = null;
        if (d.keymap) |*km| km.deinit();
        d.keymap = null;
        if (d.bind_keymap) |*km| km.deinit();
        d.bind_keymap = null;
        d.keys = .{};
        d.bells = 0; // rung while nobody listened
        d.utf16 = .{};
        d.opts = opts;
        const several = if (opts.layout) |l| l.count > 1 else false;
        d.client_layout = if (several) opts.layout.? else singleLayout(opts.width, opts.height, opts.scale_percent);
        // A scale set in the session stays for a client asking for the same one.
        const eff = d.effectiveLayout();
        if (several or d.multi()) {
            try d.relayoutTo(&eff);
        } else {
            const m = eff.monitors[0];
            const fit = hypr.fitDesktop(m.width, m.height, scalePercent(m));
            if (fit.width != d.fit.width or fit.height != d.fit.height or fit.k != d.fit.k) {
                try d.resizeTo(m.width, m.height, scalePercent(m));
            }
        }
        try d.setupKeyboard();
        d.cursor.onNewClient();
        d.refreshCursorLook();
        try d.startCapture();
        try d.client.?.flush();
        log.info("desktop handed over to the new connection ({d}x{d})", .{ d.width(), d.height() });
    }

    fn numlockByDefault(d: *Desktop) bool {
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        return hypr.getOptionBool(&d.ipc, arena.allocator(), "input:numlock_by_default") catch false;
    }

    fn setupKeyboard(d: *Desktop) Error!void {
        const arena = d.arena.allocator();
        const session: layouts.Session = .{
            .rules = hypr.getOptionStr(&d.ipc, arena, "input:kb_rules") catch "",
            .model = hypr.getOptionStr(&d.ipc, arena, "input:kb_model") catch "",
            .layout = hypr.getOptionStr(&d.ipc, arena, "input:kb_layout") catch "",
            .variant = hypr.getOptionStr(&d.ipc, arena, "input:kb_variant") catch "",
            .options = hypr.getOptionStr(&d.ipc, arena, "input:kb_options") catch "",
        };
        const ch = layouts.choose(d.opts.keyboard_layout, session);
        const names: keyboard.Names = .{
            .rules = try arena.dupeSentinel(u8, ch.rules, 0),
            .model = try arena.dupeSentinel(u8, ch.model, 0),
            .layout = try arena.dupeSentinel(u8, ch.layout, 0),
            .variant = try arena.dupeSentinel(u8, ch.variant, 0),
            .options = try arena.dupeSentinel(u8, ch.options, 0),
        };
        log.info("keyboard: client layout 0x{x:0>8} -> xkb {s}({s}) options '{s}'{s}", .{
            d.opts.keyboard_layout, names.layout, names.variant, names.options, if (ch.from_client) "" else " (session default)",
        });
        d.keymap = keyboard.Keymap.fromNames(names) catch |err| blk: {
            log.warn("keymap {s}({s}) failed ({t}); using the session's", .{ names.layout, names.variant, err });
            break :blk try keyboard.Keymap.fromNames(.{
                .layout = try arena.dupeSentinel(u8, session.layout, 0),
                .variant = try arena.dupeSentinel(u8, session.variant, 0),
                .options = try arena.dupeSentinel(u8, session.options, 0),
            });
        };
        d.kstate = try keyboard.State.init(&d.keymap.?);
        // Applications never repeat a key of this keyboard: the client does.
        d.keymap.?.makeUpload();
        d.vk = try wl.VirtualKeyboard.init(d.client.?);
        try d.vk.?.setKeymap(d.keymap.?.uploadText());
        // Clients follow Set Keyboard Indicators: start from the last connection's locks, else Hyprland's Num Lock default.
        const initial = d.carry_locks orelse keyboard.Locks{ .num = d.numlockByDefault() };
        d.carry_locks = null;
        if (initial.caps or initial.num or initial.scroll) {
            const synced = try d.kstate.?.sync(initial);
            if (synced.mods) |m| try d.vk.?.modifiers(m.depressed, m.latched, m.locked, m.group);
        }
        d.rep_key = null;
        d.bind_keymap = sessionKeymap(d.gpa, session);
        // Hyprland knows the new keyboard once its keymap went through.
        d.repeat_rules.invalidate();
        d.client.?.roundtrip(2000) catch {};
        d.repeatRulesOn();
    }

    fn repeatRulesOn(d: *Desktop) void {
        const now = nowMs();
        if (!d.repeat_rules.due(now)) return;
        if (!d.repeat_rules.ensure(&d.ipc, d.gpa)) d.repeat_rules.failedAt(now);
    }

    /// Locks, restores monitors and workspaces, removes the RDP outputs and releases the desk. Without an
    /// observed lock, or while a password may still be checked, the physical monitors stay off.
    pub fn leave(d: *Desktop) void {
        d.stopQueries();
        d.removeTwins();
        d.alt_drag = false;
        d.closeTouch();
        d.releaseInput();
        // Settle while the compositor connection can still confirm the keys.
        const settled = if (d.entered and !d.desk_owns) d.settleLockScreen() else true;
        for (0..d.plan.count) |i| {
            const slot = d.captureSlot(i);
            if (slot.*) |cap| cap.deinit();
            slot.* = null;
            d.stopCursorAt(i);
        }
        if (d.client) |client| client.deinit();
        d.client = null;
        for (0..d.plan.count) |i| d.setOutput(i, null);

        if (d.events_fd >= 0) _ = c.close(d.events_fd);
        d.events_fd = -1;
        if (d.entered) d.removeScaleWatch();
        d.user_scale = @splat(null);
        if (d.entered and d.desk_owns) {
            d.restoreConsole();
            d.entered = false;
        } else if (d.entered) {
            if (settled and d.lockAndWait()) {
                d.restoreConsole();
                d.entered = false;
            } else {
                // An unlocked desktop at the desk is worse than a dark one.
                log.err("session lock never observed: physical monitors stay OFF; reconnect, or lock and run `hyprctl reload`", .{});
            }
        }
        d.unfenceDesk();
    }

    fn releaseKeys(d: *Desktop) void {
        d.rep_key = null;
        const ks = &(d.kstate orelse return);
        const vk = &(d.vk orelse return);
        const s = ks.releaseAll() catch return;
        var it = s.released.iterator(.{});
        while (it.next()) |k| vk.key(@intCast(k), false) catch {};
        if (s.mods) |m| vk.modifiers(m.depressed, m.latched, m.locked, m.group) catch {};
        if (d.client) |client| client.flush() catch {};
    }

    fn releaseInput(d: *Desktop) void {
        d.releaseKeys();
        d.releaseButtons() catch {};
        if (d.kstate) |*ks| ks.deinit();
        d.kstate = null;
        if (d.vk) |*vk| retireKeyboard(vk);
        d.vk = null;
        if (d.keymap) |*km| km.deinit();
        d.keymap = null;
        if (d.bind_keymap) |*km| km.deinit();
        d.bind_keymap = null;
        for (&d.tvk, &d.tvk_generation) |*t, *g| {
            if (t.*) |*vk| retireKeyboard(vk);
            t.* = null;
            g.* = null;
        }
        if (d.client) |client| client.flush() catch {};
        d.text_binds.release(&d.ipc, d.gpa);
        d.repeat_rules.release(&d.ipc, d.gpa);
        if (d.vp) |*vp| vp.deinit();
        d.vp = null;
        for (&d.more) |*m| {
            if (m.vp) |*vp| vp.deinit();
            m.vp = null;
        }
        if (d.client) |client| client.flush() catch {};
    }

    fn lockAndWait(d: *Desktop) bool {
        if (!d.settleLockScreen()) return false;
        var l = console.Leave{};
        var lock_requests: u32 = 0;
        while (true) {
            const locked = hypr.isLocked(&d.ipc, d.gpa) catch false;
            switch (l.next(locked)) {
                .request_lock => {
                    if (lock_requests == 3) return false;
                    lock_requests += 1;
                    d.requestLock(lock_requests);
                    sleepMs(100);
                },
                .poll_lock => sleepMs(100),
                .keep_dark_and_retry => {},
                .restore => return true,
                .finished => return true,
            }
        }
    }

    /// After recent keys, waits until the lock screen can no longer unlock. False: it still may.
    fn settleLockScreen(d: *Desktop) bool {
        const keys = d.keys_ms orelse return true;
        const start = nowMs();
        if (start - keys >= console.Settle.window_ms) {
            d.keys_ms = null;
            return true;
        }
        d.deliverKeys();
        var s = console.Settle{ .started_ms = start, .keys_ms = keys, .delivered = d.keys_delivered };
        while (true) {
            const locked: ?bool = hypr.isLocked(&d.ipc, d.gpa) catch null;
            const screen: console.Settle.Screen = if (locked == false) .silent else d.lockScreenNow();
            const now = nowMs();
            const verdict = s.next(now, locked, screen);
            switch (verdict) {
                .wait => sleepMs(console.Settle.poll_ms),
                .unlocked, .settled => {
                    log.debug("lock screen settled ({t}, {t}) {d} ms after the last key", .{ verdict, screen, now - keys });
                    d.keys_ms = null;
                    return true;
                },
                .gave_up => {
                    log.err("the lock screen was still checking a password {d} ms after the last key: it may still unlock the session", .{now - keys});
                    return false;
                },
            }
        }
    }

    /// Round trip so the compositor has handed the lock screen every key sent.
    fn deliverKeys(d: *Desktop) void {
        if (d.keys_delivered) return;
        const cl = d.client orelse return;
        cl.roundtrip(console.Settle.max_ms) catch |err| {
            log.warn("the compositor did not confirm the last keys ({t})", .{err});
            return;
        };
        d.keys_delivered = true;
    }

    fn lockScreenNow(d: *Desktop) console.Settle.Screen {
        while (true) {
            switch (d.pollLocker(nowMs())) {
                .pending => {
                    var pfd = [_]c.struct_pollfd{.{ .fd = if (d.locker_probe) |*pr| pr.pollFd() else -1, .events = c.POLLIN, .revents = 0 }};
                    _ = c.poll(&pfd, 1, 20);
                },
                .silent, .busy => return .silent,
                .status => |st| return lockScreenOf(st),
            }
        }
    }

    fn lockScreenOf(st: LockerStatus) console.Settle.Screen {
        // Omarchy clears `requested` before Hyprland's lock goes.
        if (!(st.requested orelse st.locked)) return .released;
        if (!st.authenticating) return .idle;
        // An enrolled fingerprint's check runs for as long as it is locked.
        return if (st.fingerprint) .unknown else .checking;
    }

    fn noteKey(d: *Desktop) void {
        d.keys_ms = nowMs();
        d.keys_delivered = false;
    }

    fn requestLock(d: *Desktop, attempt: u32) void {
        var buf: [1100]u8 = undefined;
        // logind's lock signal is the fallback for lockers that listen to it.
        const command = if (attempt == 1) d.opts.lock_command else "loginctl lock-session";
        const cmd = hypr.formatExec(&buf, command) catch return;
        log.info("locking the session: {s}", .{command});
        d.ipc.command(d.gpa, cmd) catch |err| log.warn("lock command failed: {t}", .{err});
    }

    fn restoreSteps(d: *const Desktop, a: std.mem.Allocator) ![]console.Step {
        return if (d.multi())
            console.planRestoreOutputs(a, d.monitors, d.workspaces, console.rdpOutputNames(a, &d.plan) catch &.{console.rdp_output_name})
        else
            console.planRestore(a, d.monitors, d.workspaces);
    }

    fn restoreConsole(d: *Desktop) void {
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        const steps = d.restoreSteps(arena.allocator()) catch |err| {
            log.err("restore plan failed: {t}", .{err});
            return;
        };
        for (steps) |st| d.runStep(st);
        if (d.opts.console_state_path) |path| _ = c.unlink(path.ptr);
        log.info("console restored ({d} monitor(s))", .{countPhysicalOn(d.monitors)});
    }

    /// Atomically write the restore plan for omastation-recover.
    fn writeRestoreFile(d: *const Desktop) void {
        const path = d.opts.console_state_path orelse return;
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const steps = d.restoreSteps(a) catch return;
        var text: std.ArrayList(u8) = .empty;
        for (steps) |st| {
            if (std.mem.indexOfScalar(u8, st.cmd, '\n') != null) return;
            text.appendSlice(a, if (st.wait_on) "wait " else "") catch return;
            text.appendSlice(a, st.cmd) catch return;
            text.append(a, '\n') catch return;
        }
        const tmp = std.mem.concatWithSentinel(a, u8, &.{ path, ".new" }, 0) catch return;
        const fd = c.open(tmp.ptr, c.O_WRONLY | c.O_CREAT | c.O_TRUNC | c.O_CLOEXEC, @as(c_uint, 0o600));
        if (fd < 0) return log.warn("cannot write {s}", .{tmp});
        const n = c.write(fd, text.items.ptr, text.items.len);
        _ = c.close(fd);
        if (n != @as(isize, @intCast(text.items.len)) or c.rename(tmp.ptr, path.ptr) != 0) {
            _ = c.unlink(tmp.ptr);
            log.warn("cannot write {s}", .{path});
        }
    }

    pub const max_event_reads = 16;

    pub fn eventsFd(d: *const Desktop) c_int {
        return d.events_fd;
    }

    /// A config reload lights the physical monitors and resets RDP-1, so remote mode is re-applied.
    pub fn readEvents(d: *Desktop) void {
        // Bounded so a flood of events cannot hold the session's thread.
        var reads: usize = 0;
        while (reads < max_event_reads) : (reads += 1) {
            const n = c.recv(d.events_fd, d.events_buf[d.events_len..].ptr, d.events_buf.len - d.events_len, c.MSG_DONTWAIT);
            if (n == 0) {
                log.warn("Hyprland event socket closed", .{});
                _ = c.close(d.events_fd);
                d.events_fd = -1;
                return;
            }
            if (n < 0) break;
            d.events_len += @intCast(n);
            while (std.mem.indexOfScalar(u8, d.events_buf[0..d.events_len], '\n')) |nl| {
                const line = d.events_buf[0..nl];
                if (std.mem.startsWith(u8, line, "monitor") or std.mem.startsWith(u8, line, "configreloaded")) log.debug("hyprland event: {s}", .{line});
                if (hypr.parseRuleReport(line)) |r| d.onRuleReport(r);
                if (std.mem.startsWith(u8, line, "configreloaded>>")) {
                    // A reload drops the keybind rules and repeat settings.
                    d.text_binds.invalidate();
                    d.repeat_rules.invalidate();
                    // A fresh Lua state: no watch, no pending reports.
                    d.scale_watch = false;
                    d.own_rules = @splat(.{});
                    d.reapplyRemoteMode();
                    // cursor:invert may have changed.
                    if (d.client != null) d.refreshCursorLook();
                }
                if (std.mem.startsWith(u8, line, "monitoradded>>")) d.onMonitorAdded(line["monitoradded>>".len..]);
                if (std.mem.startsWith(u8, line, "bell>>")) d.bells +|= 1;
                if (std.mem.startsWith(u8, line, "activelayout>>") and d.repeat_rules.isNewKeyboard(line["activelayout>>".len..])) {
                    // A new virtual keyboard (an input method's) needs the repeat rules.
                    d.repeat_rules.invalidate();
                    if (d.kstate != null and d.remoteInputAllowed()) d.repeatRulesOn();
                }
                std.mem.copyForwards(u8, d.events_buf[0 .. d.events_len - nl - 1], d.events_buf[nl + 1 .. d.events_len]);
                d.events_len -= nl + 1;
            }
            if (d.events_len == d.events_buf.len) d.events_len = 0; // overlong line: drop
        }
    }

    fn reapplyRemoteMode(d: *Desktop) void {
        if (!d.entered or d.desk_owns) return;
        log.warn("Hyprland config reloaded: re-applying remote mode", .{});
        // A reload drops runtime bindings too.
        defer if (d.alt_drag) d.refreshTwins();
        // The desk only gets its monitors while it has a look.
        if (d.contested_until_ms == null) {
            d.runPlan(console.planPhysicalOff);
            if (!d.darkenDesk()) d.deskNotDark();
        }
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        // Before the rules, so a scale set from now on is seen.
        d.installScaleWatch();
        const steps = (if (d.multi())
            console.planRules(arena.allocator(), &d.plan)
        else
            console.planResize(arena.allocator(), d.monitors, .{ .width = d.fit.width, .height = d.fit.height, .scale = d.fit.scale() })) catch return;
        for (steps) |st| d.hyprCommand(st.cmd) catch |err| log.err("`{s}` failed: {t}", .{ st.cmd, err });
        // The reload dropped the devices' output bindings too.
        if (d.touch_devs != 0) d.bindDevices();
    }

    /// Hyprland's rules light a physical monitor added in remote mode (hotplug, DisplayPort link return).
    fn onMonitorAdded(d: *Desktop, name: []const u8) void {
        if (!d.entered or d.desk_owns or d.contested_until_ms != null) return;
        if (hypr.isRdpOutput(name) or hypr.isFallback(name)) return;
        if (!d.darkenDesk()) d.deskNotDark();
    }

    /// Records unknown monitors in the snapshot. False if one may still be lit.
    fn darkenDesk(d: *Desktop) bool {
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        const now = hypr.monitors(&d.ipc, arena.allocator()) catch |err| {
            log.err("the monitors cannot be listed ({t}): one lit since the session started may show it at the desk", .{err});
            return false;
        };
        var dark = true;
        for (now) |m| {
            if (m.disabled or hypr.isRdpOutput(m.name) or hypr.isFallback(m.name)) continue;
            d.recordMonitor(m) catch {};
            var buf: [1100]u8 = undefined;
            const cmd = hypr.formatMonitorOff(&buf, m.name) catch {
                dark = false;
                continue;
            };
            d.ipc.command(d.gpa, cmd) catch |err| {
                log.err("{s} is lit during the session and could not be switched off ({t})", .{ m.name, err });
                dark = false;
                continue;
            };
            log.info("{s} was lit during the session: switched off until it ends", .{m.name});
        }
        return dark;
    }

    fn deskNotDark(d: *Desktop) void {
        if (d.contested_until_ms != null) return;
        log.err("a monitor at the desk could not be switched off: the desk gets a look (locked) rather than the remote session", .{});
        d.deskWantsIn();
    }

    /// Adds `m` to the snapshot if missing, so leaving lights it again.
    fn recordMonitor(d: *Desktop, m: hypr.MonitorState) std.mem.Allocator.Error!void {
        for (d.monitors) |k| {
            if (std.mem.eql(u8, k.name, m.name)) return;
        }
        const a = d.arena.allocator();
        const more = try a.alloc(hypr.MonitorState, d.monitors.len + 1);
        @memcpy(more[0..d.monitors.len], d.monitors);
        more[d.monitors.len] = m;
        more[d.monitors.len].name = try a.dupe(u8, m.name);
        more[d.monitors.len].workspace = "";
        more[d.monitors.len].special_workspace = "";
        more[d.monitors.len].focused = false;
        d.monitors = more;
        d.writeRestoreFile();
    }

    /// Option twins of the SUPER mouse bindings (altdrag.zig), remote mode only.
    pub fn setAltDrag(d: *Desktop, on: bool) void {
        if (on == d.alt_drag) return;
        d.alt_drag = on;
        if (on) d.refreshTwins() else d.removeTwins();
    }

    pub fn twins(d: *const Desktop, i: usize) []const u8 {
        return d.twin_keys[i][0..d.twin_lens[i]];
    }

    fn refreshTwins(d: *Desktop) void {
        if (!d.entered) return;
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const json = d.ipc.request(a, "j/binds") catch |err| {
            log.warn("cannot list Hyprland bindings ({t}): no Option + drag", .{err});
            return;
        };
        const binds = altdrag.parseBinds(a, json) catch |err| {
            log.warn("cannot parse Hyprland bindings ({t}): no Option + drag", .{err});
            return;
        };
        d.twin_count = 0;
        for (binds) |b| {
            if (!std.mem.eql(u8, b.description, altdrag.description)) continue;
            const button = std.fmt.parseInt(u32, if (std.mem.startsWith(u8, b.key, "mouse:")) b.key[6..] else "x", 10) catch continue;
            var kb: [80]u8 = undefined;
            d.recordTwin(altdrag.keyString(&kb, b.modmask, button) catch continue);
        }
        const plan = altdrag.plan(a, binds) catch return;
        for (plan) |t| {
            var buf: [512]u8 = undefined;
            const cmd = altdrag.formatBind(&buf, t) catch continue;
            d.ipc.command(d.gpa, cmd) catch |err| {
                log.warn("adding `{s}` failed: {t}", .{ t.keys, err });
                continue;
            };
            d.recordTwin(t.keys);
            log.info("added the binding {s} (Option + drag for a macOS client)", .{t.keys});
        }
        if (d.twin_count == 0) log.info("no SUPER mouse bindings to give an Option twin", .{});
        d.writeTwinsFile();
    }

    fn recordTwin(d: *Desktop, keys: []const u8) void {
        if (d.twin_count == max_twins or keys.len > d.twin_keys[0].len) return;
        for (0..d.twin_count) |i| if (std.mem.eql(u8, d.twins(i), keys)) return;
        @memcpy(d.twin_keys[d.twin_count][0..keys.len], keys);
        d.twin_lens[d.twin_count] = @intCast(keys.len);
        d.twin_count += 1;
    }

    fn removeTwins(d: *Desktop) void {
        if (d.twin_count == 0) return;
        for (0..d.twin_count) |i| {
            var buf: [256]u8 = undefined;
            const cmd = altdrag.formatUnbind(&buf, d.twins(i)) catch continue;
            d.ipc.command(d.gpa, cmd) catch |err| log.warn("removing `{s}` failed: {t}", .{ d.twins(i), err });
            log.info("removed the binding {s}", .{d.twins(i)});
        }
        d.twin_count = 0;
        d.writeTwinsFile();
    }

    /// The state file omastation-recover reads; removed when empty.
    fn writeTwinsFile(d: *Desktop) void {
        const path = d.opts.binds_state_path orelse return;
        if (d.twin_count == 0) {
            _ = c.unlink(path.ptr);
            return;
        }
        var buf: [max_twins * 81]u8 = undefined;
        var n: usize = 0;
        for (0..d.twin_count) |i| {
            const k = d.twins(i);
            @memcpy(buf[n..][0..k.len], k);
            buf[n + k.len] = '\n';
            n += k.len + 1;
        }
        const fd = c.open(path.ptr, c.O_WRONLY | c.O_CREAT | c.O_TRUNC | c.O_CLOEXEC, @as(c_uint, 0o600));
        if (fd < 0) return log.warn("cannot write {s}", .{path});
        defer _ = c.close(fd);
        _ = c.write(fd, &buf, n);
    }

    /// Time for the desk to sign in before the console goes remote again.
    pub const desk_look_ms = 60_000;
    /// Extension of a look whose end could not darken the desk.
    pub const look_retry_ms = 5_000;

    /// As on Windows, whoever signs in at the console gets the session: lock, light the desk, ignore remote input.
    pub fn deskWantsIn(d: *Desktop) void {
        if (d.contested_until_ms != null or !d.entered) return;
        log.info("key pressed at the desk: showing the lock screen there", .{});
        // Never type the remote password into a lock screen the desk can see.
        if (d.unlocking != null) {
            log.info("the remote unlock is cancelled: the desk has the console", .{});
            d.endUnlock();
        }
        d.releaseKeys();
        d.releaseButtons() catch {};
        d.releaseTouch();
        // The desk's keys may go through the input method's keyboard too.
        d.repeat_rules.release(&d.ipc, d.gpa);
        if (!d.lockAndWait()) {
            log.err("could not lock the session; the desk stays dark", .{});
            return;
        }
        d.runPlan(console.planPhysicalOn);
        d.unfenceDesk();
        // The helper destroyed the touch devices with the fence.
        d.touch_devs = 0;
        d.pen_devs = 0;
        d.contested_until_ms = nowMs() + desk_look_ms;
    }

    pub const Tick = enum { none, desk_took_over };

    /// How stale the lock state may be while the desk has a look.
    const contested_check_ms = 200;

    pub fn tick(d: *Desktop) Tick {
        d.refenceIfLost();
        d.keepAwake();
        d.pumpLock(nowMs());
        d.stepUnlock() catch |err| {
            log.warn("unlock failed: {t}", .{err});
            d.endUnlock();
        };
        const until = d.contested_until_ms orelse return .none;
        const locked = if (d.lockSince(nowMs() - contested_check_ms)) |a| a != .unlocked else true;
        if (!locked) {
            // Remote input is ignored during a look, so this was the desk.
            log.info("signed in at the desk: the desk takes the session", .{});
            d.desk_owns = true;
            d.contested_until_ms = null;
            return .desk_took_over;
        }
        if (nowMs() >= until) {
            // Let a password check started at the desk finish first.
            switch (d.pollLocker(nowMs())) {
                .pending => return .none,
                .status => |st| if (st.authenticating and !st.fingerprint) {
                    d.contested_until_ms = nowMs() + contested_check_ms;
                    return .none;
                },
                .busy, .silent => {},
            }
            d.runPlan(console.planPhysicalOff);
            if (!d.darkenDesk()) {
                log.err("a monitor at the desk did not switch off: the desk's look goes on", .{});
                d.contested_until_ms = nowMs() + look_retry_ms;
                return .none;
            }
            log.info("nobody signed in at the desk: back to remote mode", .{});
            d.fenceDesk() catch |err| {
                log.warn("desk input is NOT fenced ({t})", .{err});
                if (err == error.FenceUnavailable) d.refence_at_ms = nowMs() + refence_retry_ms;
            };
            d.contested_until_ms = null;
            if (d.touch_mode == .devices) d.reopenTouch();
        }
        return .none;
    }

    /// Lockers blank every output and Hyprland renders nothing on a blanked one, so RDP outputs are re-enabled.
    fn keepAwake(d: *Desktop) void {
        if (!d.entered) return;
        const now = nowMs();
        if (now < d.next_dpms_check_ms) return;
        d.next_dpms_check_ms = now + 1000;
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        const ms = hypr.monitors(&d.ipc, arena.allocator()) catch return;
        for (ms) |m| {
            if (!d.ownsOutput(m.name) or m.dpms) continue;
            log.info("{s} was blanked; turning it back on", .{m.name});
            var buf: [256]u8 = undefined;
            const cmd = std.fmt.bufPrint(&buf, "eval hl.dispatch(hl.dsp.dpms({{ action = \"enable\", monitor = \"{s}\" }}))", .{m.name}) catch return;
            d.ipc.command(d.gpa, cmd) catch |err| log.warn("dpms enable failed: {t}", .{err});
        }
    }

    pub const LingerWake = enum {
        none,
        /// A connection wants the seat.
        woken,
        expired,
        desk,
        lost,
    };

    /// A connection taking over may adopt this desktop only in remote mode, before the desk signed in.
    pub fn handable(d: *const Desktop) bool {
        return d.entered and !d.desk_owns;
    }

    pub fn canLinger(d: *const Desktop) bool {
        if (!d.entered or d.desk_owns or d.contested_until_ms != null) return false;
        return switch (d.captureState()) {
            .stopped, .failed => false,
            else => true,
        };
    }

    pub fn suspendForReconnect(d: *Desktop) void {
        d.stopQueries();
        d.forgetLock();
        d.releaseKeys();
        d.releaseButtons() catch {};
        d.releaseTouch();
        for (0..d.plan.count) |i| {
            const slot = d.captureSlot(i);
            if (slot.*) |cap| cap.deinit();
            slot.* = null;
        }
        if (d.client) |cl| cl.flush() catch {};
    }

    /// Waits at most a second, still serving Hyprland's events and the Wayland connection.
    pub fn waitLingering(d: *Desktop, wake_fd: c_int, until_ms: i64) LingerWake {
        const now = nowMs();
        if (now >= until_ms) return .expired;
        if (d.desk_activity) {
            d.desk_activity = false;
            return .desk;
        }
        var fds = [_]c.struct_pollfd{
            .{ .fd = wake_fd, .events = c.POLLIN, .revents = 0 },
            .{ .fd = d.helper_fd, .events = c.POLLIN, .revents = 0 },
            .{ .fd = d.events_fd, .events = c.POLLIN, .revents = 0 },
            .{ .fd = d.waylandFd(), .events = c.POLLIN, .revents = 0 },
        };
        if (c.poll(&fds, fds.len, @intCast(@min(until_ms - now, 1000))) < 0) return .none;
        if (fds[0].revents != 0) return .woken;
        d.refenceIfLost();
        if (fds[1].revents != 0) _ = d.readHelper() catch d.helperLost();
        // helperCommand may have read a desk report too.
        if (d.desk_activity) {
            d.desk_activity = false;
            return .desk;
        }
        if (fds[2].revents != 0) d.readEvents();
        if (fds[3].revents != 0) d.dispatch() catch return .lost;
        return if (nowMs() >= until_ms) .expired else .none;
    }

    pub fn keyboardLocks(d: *const Desktop) ?struct { on: keyboard.Locks, known: keyboard.Locks } {
        const ks = &(d.kstate orelse return null);
        return .{ .on = ks.locks(), .known = ks.lockSupport() };
    }

    pub const lock_check_ms = 1000;

    /// As clipboard redirection requires; an IPC failure counts as locked.
    pub fn remoteUnlocked(d: *Desktop) bool {
        if (!d.entered or d.desk_owns or d.contested_until_ms != null) return false;
        const now = nowMs();
        if (d.lock_seen == null or now >= d.next_lock_check_ms) {
            d.next_lock_check_ms = now + lock_check_ms;
            d.askLock(now);
        }
        d.pumpLock(now);
        return !(d.lock_seen orelse true);
    }

    pub const lock_query_timeout_ms = 2000;

    pub const LockAnswer = enum { locked, unlocked, failed };

    /// From a query sent at `since_ms` or later; null while pending.
    fn lockSince(d: *Desktop, since_ms: i64) ?LockAnswer {
        const now = nowMs();
        d.pumpLock(now);
        if (d.lockAnswerSince(since_ms)) |a| return a;
        if (now < since_ms) return null;
        d.askLock(now);
        return d.lockAnswerSince(since_ms);
    }

    fn lockAnswerSince(d: *const Desktop, since_ms: i64) ?LockAnswer {
        const l = d.lock_seen orelse return null;
        if (d.lock_seen_ms < since_ms) return null;
        return if (d.lock_failed) .failed else if (l) .locked else .unlocked;
    }

    fn askLock(d: *Desktop, now: i64) void {
        if (d.lock_query != null) return;
        d.lock_query = d.ipc.begin("j/monitors") catch {
            d.setLock(true, true, now);
            return;
        };
        d.lock_query_ms = now;
    }

    fn pumpLock(d: *Desktop, now: i64) void {
        const q = &(d.lock_query orelse return);
        const sent = d.lock_query_ms;
        const got = q.poll(d.gpa) catch return d.setLock(true, true, sent);
        const resp = got orelse {
            if (now - sent < lock_query_timeout_ms) return;
            log.warn("Hyprland did not answer within {d} ms whether the session is locked", .{lock_query_timeout_ms});
            return d.setLock(true, true, sent);
        };
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        const locked = hypr.lockedFromMonitorsJson(arena.allocator(), resp) catch return d.setLock(true, true, sent);
        d.setLock(locked, false, sent);
    }

    fn setLock(d: *Desktop, locked: bool, failed: bool, sent_ms: i64) void {
        d.lock_seen = locked;
        d.lock_failed = failed;
        d.lock_seen_ms = sent_ms;
        if (d.lock_query) |*q| q.deinit(d.gpa);
        d.lock_query = null;
    }

    pub fn queryFds(d: *const Desktop) [2]c_int {
        return .{
            if (d.lock_query) |q| q.fd else -1,
            if (d.locker_probe) |*pr| pr.pollFd() else -1,
        };
    }

    fn stopQueries(d: *Desktop) void {
        if (d.lock_query) |*q| q.deinit(d.gpa);
        d.lock_query = null;
        if (d.locker_probe) |*pr| pr.cancel();
        d.locker_probe = null;
    }

    /// The session may have locked meanwhile: locked until asked again.
    fn forgetLock(d: *Desktop) void {
        d.lock_seen = null;
        d.lock_seen_ms = 0;
        d.next_lock_check_ms = 0;
    }

    /// Remote input is ignored while the desk has a look.
    fn remoteInputAllowed(d: *const Desktop) bool {
        return d.contested_until_ms == null;
    }

    /// Clients may be told to suspend input meanwhile (MS-RDPEI 3.2.5.4).
    pub fn inputSuspended(d: *const Desktop) bool {
        return !d.remoteInputAllowed();
    }

    /// Remote keystrokes would interleave with the password being typed.
    fn remoteKeysAllowed(d: *const Desktop) bool {
        if (!d.remoteInputAllowed()) return false;
        const u = d.unlocking orelse return true;
        return u.state == .wait_frame;
    }

    fn runPlan(d: *Desktop, comptime plan: fn (std.mem.Allocator, []const hypr.MonitorState) anyerror![]console.Step) void {
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        const steps = plan(arena.allocator(), d.monitors) catch |err| {
            log.err("plan failed: {t}", .{err});
            return;
        };
        for (steps) |st| d.runStep(st);
    }

    fn runStep(d: *Desktop, st: console.Step) void {
        if (st.wait_on) return d.waitMonitorOn(st.cmd);
        d.ipc.command(d.gpa, st.cmd) catch |err| {
            if (st.critical) log.err("`{s}` failed: {t}", .{ st.cmd, err }) else log.warn("`{s}` failed: {t}", .{ st.cmd, err });
        };
    }

    /// Hyprland reports a monitor enabled before every client has its wl_output: the lock screen
    /// (omarchy-shell) that sees the RDP output go before the physical one arrives is left with a
    /// placeholder screen and never draws a lock surface on the monitor that then appears
    /// (Hyprland shows "the lockscreen app died"). Give clients this long to catch up.
    const monitor_on_settle_ms = 500;

    fn waitMonitorOn(d: *Desktop, name: []const u8) void {
        var waited: u32 = 0;
        while (waited < 2000) : (waited += 50) {
            var arena = std.heap.ArenaAllocator.init(d.gpa);
            defer arena.deinit();
            const ms = hypr.monitors(&d.ipc, arena.allocator()) catch return;
            for (ms) |m| {
                if (std.mem.eql(u8, m.name, name) and !m.disabled) {
                    log.info("{s} is back after {d} ms; {d} ms for clients to see it", .{ name, waited, monitor_on_settle_ms });
                    sleepMs(monitor_on_settle_ms);
                    return;
                }
            }
            sleepMs(50);
        }
        log.warn("{s} did not come back within 2 s", .{name});
    }

    /// A remote unlock, stepped from `tick` without blocking.
    const Unlock = struct {
        /// The NLA password (UTF-8); wiped when done.
        secret: []u8,
        state: enum { wait_frame, wait_ready, check } = .wait_frame,
        /// A lock that lands just as the client connects still counts until then.
        grace_until_ms: i64,
        attempt: u32 = 0,
        deadline_ms: i64,
        next_ms: i64 = 0,
        stable: u32 = 0,
        /// The next step needs a lock answer from a query sent at this time or later.
        asked_ms: i64,
        ready_wait_ms: i64 = 0,
        locker_answers: bool = true,
        ready: bool = false,
        /// Answers in a row with the session locked but no lock screen lock.
        orphaned: u32 = 0,
        relocked: bool = false,
    };

    pub const locker_status_timeout_ms = 1000;
    /// A lock screen without status gets this long to settle.
    pub const locker_settle_ms = 800;

    /// If locked, types `password` and Enter once the lock screen is ready, one retry; the copy is wiped.
    pub fn beginUnlock(d: *Desktop, password: []const u8) Error!void {
        d.endUnlock();
        // Copied first so `unlocking` is never set with an undefined secret.
        const secret = try d.gpa.dupe(u8, password);
        const now = nowMs();
        d.unlocking = .{ .secret = secret, .deadline_ms = now + 1500, .grace_until_ms = now + 3000, .asked_ms = now };
    }

    pub fn cancelUnlock(d: *Desktop) void {
        d.endUnlock();
    }

    fn endUnlock(d: *Desktop) void {
        const u = &(d.unlocking orelse return);
        std.crypto.secureZero(u8, u.secret);
        d.gpa.free(u.secret);
        d.unlocking = null;
        if (d.locker_probe) |*pr| pr.cancel();
        d.locker_probe = null;
        // The text keymap learned the password's non-ASCII characters.
        d.text.forgetOnDemand();
    }

    fn unlockLock(d: *Desktop, u: *const Unlock) Error!?bool {
        const a = d.lockSince(u.asked_ms) orelse return null;
        return switch (a) {
            .failed => error.IpcFailed,
            .locked => true,
            .unlocked => false,
        };
    }

    fn stepUnlock(d: *Desktop) Error!void {
        const u = &(d.unlocking orelse return);
        // Never type while the desk has the console.
        if (d.contested_until_ms != null or d.desk_owns) return d.endUnlock();
        const now = nowMs();
        if (now < u.next_ms) return;
        switch (u.state) {
            // Once the output renders, the locker has had a chance to map on it.
            .wait_frame => {
                const locked = try d.unlockLock(u) orelse return;
                if (!locked) {
                    if (now >= u.grace_until_ms) return d.endUnlock();
                    u.asked_ms = now + 200;
                    return;
                }
                if (d.capture.?.seq == 0 and now < u.deadline_ms) return;
                log.debug("unlock step: wait_ready (attempt {d})", .{u.attempt});
                d.startReadyWait(u, now);
            },
            // Ready: locked, secure, idle twice in a row (or a fixed settle time).
            .wait_ready => {
                if (!u.ready) {
                    const ready = if (u.locker_answers) blk: {
                        const st = switch (d.pollLocker(now)) {
                            .pending => return,
                            .status => |st| st,
                            .busy => {
                                u.stable = 0;
                                break :blk false;
                            },
                            .silent => {
                                u.locker_answers = false;
                                break :blk now >= u.ready_wait_ms + locker_settle_ms;
                            },
                        };
                        log.debug("locker: locked={} secure={} pending={} authenticating={}", .{ st.locked, st.secure, st.pending, st.authenticating });
                        // The lock screen died with the session locked: lock again so a new one takes over.
                        if (!(st.requested orelse st.locked)) u.orphaned += 1 else u.orphaned = 0;
                        if (u.orphaned >= 3 and !u.relocked) {
                            u.relocked = true;
                            log.warn("the session is locked but the lock screen holds no lock (it died?): locking again so there is one to unlock", .{});
                            d.requestLock(1);
                            u.deadline_ms = now + 4000;
                        }
                        if (st.locked and st.secure and !st.pending and !st.authenticating) u.stable += 1 else u.stable = 0;
                        break :blk u.stable >= 2;
                    } else now >= u.ready_wait_ms + locker_settle_ms;
                    if (!ready and now < u.deadline_ms) {
                        u.next_ms = now + 150;
                        return;
                    }
                    if (!ready) log.warn("lock screen not ready; typing anyway", .{});
                    u.ready = true;
                    u.asked_ms = now;
                }
                // Never type into an app.
                const locked = try d.unlockLock(u) orelse return;
                if (!locked) return d.endUnlock();
                // Escape clears anything half-typed (Omarchy's lock, hyprlock).
                try d.typeKeysym(c.XKB_KEY_Escape);
                const view = std.unicode.Utf8View.init(u.secret) catch return d.endUnlock();
                var it = view.iterator();
                while (it.nextCodepoint()) |cp| try d.typeCodepoint(cp);
                try d.typeKeysym(c.XKB_KEY_Return);
                if (d.client) |cl| try cl.flush();
                u.attempt += 1;
                u.state = .check;
                u.deadline_ms = now + 3000;
                u.asked_ms = now + 100;
                log.debug("unlock step: check (attempt {d})", .{u.attempt});
            },
            .check => {
                const locked = try d.unlockLock(u) orelse return;
                if (!locked) {
                    log.info("session unlocked with the NLA credentials", .{});
                    return d.endUnlock();
                }
                if (now < u.deadline_ms) {
                    u.asked_ms = now + 100;
                    return;
                }
                log.warn("session still locked after typing the password (attempt {d})", .{u.attempt});
                if (u.attempt >= 2) {
                    log.warn("the lock screen did not take the password; the user can unlock it", .{});
                    return d.endUnlock();
                }
                d.startReadyWait(u, now);
            },
        }
    }

    fn startReadyWait(d: *Desktop, u: *Unlock, now: i64) void {
        _ = d;
        u.state = .wait_ready;
        u.deadline_ms = now + 4000;
        u.ready_wait_ms = now;
        u.stable = 0;
        u.ready = false;
        u.next_ms = 0;
    }

    const LockerStatus = struct {
        locked: bool = false,
        secure: bool = false,
        pending: bool = false,
        authenticating: bool = false,
        /// The lock screen holds a lock it took (null: not reported).
        requested: ?bool = null,
        /// A fingerprint is enrolled: its check counts as authenticating.
        fingerprint: bool = false,
    };

    const LockerPoll = union(enum) {
        pending,
        status: LockerStatus,
        busy,
        /// No such command (another locker), or unparsable output.
        silent,
    };

    fn pollLocker(d: *Desktop, now: i64) LockerPoll {
        if (d.locker_probe == null) {
            d.locker_probe = probe.Probe.start(d.opts.locker_status_command, now) catch {
                d.lockerSilent("cannot be run", null);
                return .silent;
            };
        }
        const pr = &d.locker_probe.?;
        switch (pr.poll(now, locker_status_timeout_ms)) {
            .pending => return .pending,
            .timed_out => {
                d.locker_probe = null;
                log.info("the lock screen's status command did not answer within {d} ms (busy?): asking again", .{locker_status_timeout_ms});
                return .busy;
            },
            .done => |r| {
                const st = parseLockerStatus(d.gpa, r.output);
                d.locker_probe = null;
                if (st) |status| {
                    d.locker_silence_logged = false;
                    return .{ .status = status };
                }
                d.lockerSilent("gave no status", r.code);
                return .silent;
            },
        }
    }

    fn lockerSilent(d: *Desktop, what: []const u8, code: ?u8) void {
        if (d.locker_silence_logged) return;
        d.locker_silence_logged = true;
        if (code == 127) {
            log.info("no lock screen status command (not Omarchy's lock): going by time (the password is typed after {d} ms; a lock is trusted {d} ms after the last key)", .{ locker_settle_ms, console.Settle.quiet_ms });
            return;
        }
        var eb: [16]u8 = undefined;
        const exit = if (code) |e| std.fmt.bufPrint(&eb, " (exit {d})", .{e}) catch "" else "";
        log.warn("the lock screen's status command {s}{s}: the lock screen may have died; going by time (the password is typed after {d} ms; a lock is trusted {d} ms after the last key)", .{ what, exit, locker_settle_ms, console.Settle.quiet_ms });
    }

    fn parseLockerStatus(gpa: std.mem.Allocator, out: []const u8) ?LockerStatus {
        const start = std.mem.indexOfScalar(u8, out, '{') orelse return null;
        const end = std.mem.lastIndexOfScalar(u8, out, '}') orelse return null;
        if (end < start) return null;
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        return std.json.parseFromSliceLeaky(LockerStatus, arena.allocator(), out[start .. end + 1], .{ .ignore_unknown_fields = true }) catch null;
    }

    pub fn waylandFd(d: *const Desktop) c_int {
        return if (d.client) |cl| cl.fd() else -1;
    }

    pub fn dispatch(d: *Desktop) Error!void {
        if (d.client) |cl| _ = try cl.dispatch();
        try d.pollCursors();
    }

    /// Valid until the next call; call `requestFrame` once done with it.
    pub fn takeFrame(d: *Desktop) ?*const wl.Frame {
        return d.frameSource(0).take();
    }

    pub fn frameReady(d: *const Desktop) bool {
        const cap = d.capture orelse return false;
        return cap.ready_idx != null;
    }

    pub fn requestFrame(d: *Desktop) Error!void {
        return d.frameSource(0).request();
    }

    /// With several outputs, the worst state.
    pub fn captureState(d: *const Desktop) wl.capture.State {
        var stopped = false;
        for (0..d.plan.count) |i| switch (d.frameSourceConst(i).state()) {
            .failed => return .failed,
            .stopped => stopped = true,
            else => {},
        };
        return if (stopped) .stopped else d.frameSourceConst(0).state();
    }

    pub const FrameSource = struct {
        d: *Desktop,
        index: u8,

        /// Valid until the next call; then call `request`.
        pub fn take(s: FrameSource) ?*const wl.Frame {
            const cap = s.d.captureAt(s.index) orelse return null;
            return cap.takeFrame();
        }

        pub fn ready(s: FrameSource) bool {
            const cap = s.d.captureAt(s.index) orelse return false;
            return cap.ready_idx != null;
        }

        pub fn request(s: FrameSource) Error!void {
            const cap = s.d.captureAt(s.index) orelse return;
            try cap.requestFrame();
        }

        pub fn state(s: FrameSource) wl.capture.State {
            return s.d.frameSourceConst(s.index).state();
        }

        pub fn info(s: FrameSource) OutputInfo {
            return s.d.outputInfo(s.index);
        }
    };

    const ConstSource = struct {
        d: *const Desktop,
        index: usize,
        fn state(s: ConstSource) wl.capture.State {
            return if (s.d.captureAt(s.index)) |cap| cap.state else .stopped;
        }
    };

    fn frameSourceConst(d: *const Desktop, i: usize) ConstSource {
        return .{ .d = d, .index = i };
    }

    pub fn frameSource(d: *Desktop, i: usize) FrameSource {
        std.debug.assert(i < d.plan.count);
        return .{ .d = d, .index = @intCast(i) };
    }

    /// How long a new session waits for the first cursor image.
    const cursor_probe_ms = 150;
    /// Reopens per output for an image taken while the cursor was elsewhere.
    const max_cursor_probes = 4;

    fn startCursors(d: *Desktop) Error!void {
        if (d.cursor.mode == .paint) return;
        // Without the plugin, Hyprland draws the cursor into headless outputs' frames.
        if (d.cursor.mode == .auto and !plugin.framesWithoutCursor(&d.ipc, d.gpa)) {
            if (d.cursor.paintForGood("client-drawn pointers need omastation's Hyprland plugin (it keeps the cursor out of RDP outputs' frames)", .{})) d.captures_stale = true;
            return;
        }
        d.refreshCursorLook();
        d.cursor_info_missing = false;
        for (0..d.plan.count) |i| d.startCursorAt(i);
        const client = d.client orelse return;
        var waited: i32 = 0;
        while (!d.cursor.judged and d.cursor.mode != .paint and waited < cursor_probe_ms) : (waited += 10) {
            _ = try client.dispatchTimeout(10);
            try d.pollCursors();
        }
    }

    /// A new cursor session delivers the current image at once.
    fn startCursorAt(d: *Desktop, i: usize) void {
        if (d.cursor.mode == .paint) return;
        const client = d.client orelse return;
        const out = d.outputAt(i) orelse return;
        d.stopCursorAt(i);
        d.cursors[i] = wl.Cursor.init(client, out) catch |err| {
            if (d.cursor.paintForGood("no cursor capture ({t})", .{err})) d.captures_stale = true;
            for (0..d.plan.count) |k| d.stopCursorAt(k);
            return;
        };
        d.cursor_seen[i] = 0;
        d.cursor_inside[i] = false;
        d.cursor_missed[i] = false;
        d.cursor_hot_seen[i] = 0;
    }

    fn stopCursorAt(d: *Desktop, i: usize) void {
        if (d.cursors[i]) |cur| cur.deinit();
        d.cursors[i] = null;
        d.cursor_inside[i] = false;
    }

    fn refreshCursorLook(d: *Desktop) void {
        if (d.cursor.mode == .paint) return;
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        const on = hypr.getOptionBool(&d.ipc, arena.allocator(), "cursor:invert") catch false;
        d.cursor.setLook(if (on) .inverted else .normal);
    }

    fn pollCursors(d: *Desktop) Error!void {
        if (d.cursor.mode != .paint) for (0..d.plan.count) |i| {
            const cur = d.cursors[i] orelse continue;
            switch (cur.image_capture.state) {
                .stopped, .failed => {
                    // Hyprland stops a cursor capture started while the cursor is hidden; a new one gets the image.
                    if (cur.image_capture.state == .stopped and !d.cursor.works and d.cursor_restarts[i] < max_cursor_probes) {
                        d.cursor_restarts[i] += 1;
                        log.info("{s}: the cursor capture stopped before its first image (started while the cursor was hidden?): opened again", .{d.plan.outputs[i].name()});
                        d.startCursorAt(i);
                        continue;
                    }
                    log.warn("{s}: the cursor capture ended ({t})", .{ d.plan.outputs[i].name(), cur.image_capture.state });
                    if (!d.cursor.works and d.cursor.paintForGood("the cursor capture ended", .{})) d.captures_stale = true;
                    d.stopCursorAt(i);
                    continue;
                },
                else => {},
            }
            if (cur.position_serial != d.cursor_seen[i]) {
                d.cursor_seen[i] = cur.position_serial;
                d.cursor_inside[i] = cur.inside;
                if (cur.inside) {
                    const p = d.cursorClientPoint(i, cur.x, cur.y);
                    d.cursor.onPosition(p.x, p.y, p.tolerance, nowMs());
                    if (d.cursor_missed[i] and !d.cursor.judged and d.cursor_probes[i] < max_cursor_probes) {
                        // The image came while the cursor was elsewhere: capture it again.
                        d.cursor_probes[i] += 1;
                        d.startCursorAt(i);
                        continue;
                    }
                }
            }
            const img = (try cur.takeImage()) orelse {
                if (cur.inside and cur.hotspot_serial != d.cursor_hot_seen[i]) {
                    d.cursor_hot_seen[i] = cur.hotspot_serial;
                    if (d.cursor.image) |im| {
                        const hot = d.cursorHotspot(cur, im.width, im.height, d.cursorInfo());
                        d.cursor.setHotspot(hot[0], hot[1]);
                    }
                }
                continue;
            };
            // Captured while the cursor is elsewhere: no shape.
            if (!cur.inside or img.frame.format != .argb8888) {
                d.cursor_missed[i] = true;
                continue;
            }
            // A stale image from before a size change; the next frame has the new one.
            if (cur.image_capture.constraints) |cc| if (cc.width != img.frame.width or cc.height != img.frame.height) {
                log.debug("{s}: a {d}x{d} cursor image of before the size changed to {d}x{d}: the next one follows", .{ d.plan.outputs[i].name(), img.frame.width, img.frame.height, cc.width, cc.height });
                continue;
            };
            d.cursor_hot_seen[i] = cur.hotspot_serial;
            const info = d.cursorInfo();
            const hot = d.cursorHotspot(cur, img.frame.width, img.frame.height, info);
            if (try d.cursor.onImage(.{
                .width = img.frame.width,
                .height = img.frame.height,
                .stride = img.frame.stride,
                .pixels = img.frame.data,
                .hot_x = hot[0],
                .hot_y = hot[1],
            }, shownOf(info), nowMs())) d.captures_stale = true;
            if (!d.cursor.judged) d.cursor_missed[i] = true;
        };
        if (d.cursor.suspect_since_ms) |since| if (nowMs() - since >= cursor_mod.fallback_after_ms) {
            if (d.cursor.confirmFallback(nowMs(), shownOf(d.cursorInfo()))) d.captures_stale = true;
        };
        if (d.captures_stale) {
            d.captures_stale = false;
            log.info("the cursor is {s} from now on", .{if (d.cursor.painting) "painted into the frames" else "drawn by the client"});
            for (0..d.plan.count) |i| if (d.captureAt(i) != null) try d.restartCapture(i);
        }
    }

    fn cursorInfo(d: *Desktop) ?plugin.CursorInfo {
        if (d.cursor_info_missing) return null;
        if (plugin.cursorInfo(&d.ipc, d.gpa)) |info| return info;
        d.cursor_info_missing = true;
        log.info("no `hyprctl omastation-cursor` (an older omastation plugin): cursor hotspots are estimated, empty cursor images taken as hidden", .{});
        return null;
    }

    fn shownOf(info: ?plugin.CursorInfo) cursor_mod.Shown {
        const i = info orelse return .unknown;
        const shown = i.shown orelse return .unknown;
        return if (shown) .{ .image = .{ .width = i.width, .height = i.height } } else .none;
    }

    /// The plugin's if it matches the size, else the cursor session's scaled by cursorImageScale.
    fn cursorHotspot(d: *Desktop, cur: *const wl.Cursor, w: u32, h: u32, info: ?plugin.CursorInfo) [2]i32 {
        if (info) |in| {
            if (in.width == w and in.height == h)
                return .{ @intFromFloat(@round(in.hot_x)), @intFromFloat(@round(in.hot_y)) };
        }
        const s = d.cursorImageScale();
        return .{ scaleCoord(cur.latest_hotspot[0], s), scaleCoord(cur.latest_hotspot[1], s) };
    }

    /// The highest output scale (Xcursor themes at fractional scales are missed); hotspots are logical.
    fn cursorImageScale(d: *const Desktop) f64 {
        var k: u32 = 120;
        for (d.plan.outputs[0..d.plan.count]) |o| k = @max(k, o.scale_k);
        return @as(f64, @floatFromInt(k)) / 120.0;
    }

    /// In client desktop coordinates, with a tolerance since the logical position is truncated.
    fn cursorClientPoint(d: *const Desktop, i: usize, lx: i32, ly: i32) struct { x: i32, y: i32, tolerance: i32 } {
        const o = d.plan.outputs[i];
        const s = @as(f64, @floatFromInt(o.scale_k)) / 120.0;
        var x = scaleCoord(lx, s);
        var y = scaleCoord(ly, s);
        if (d.multi()) {
            const m = d.plan.monitors[o.monitor];
            const b = planBounds(&d.plan);
            x += m.left - b.left;
            y += m.top - b.top;
        }
        return .{ .x = x, .y = y, .tolerance = @as(i32, @intFromFloat(@ceil(s))) + 1 };
    }

    /// RDP output rules sent with the scale watch on are remembered so their reports are not user scales.
    fn hyprCommand(d: *Desktop, cmd: []const u8) hypr.Error!void {
        const own = if (d.scale_watch) hypr.ruleOfCommand(cmd) else null;
        if (own) |r| if (r.index < multimon.max_monitors) d.own_rules[r.index].push(r.percent);
        d.ipc.command(d.gpa, cmd) catch |err| {
            // No rule, no report.
            if (own) |r| if (r.index < multimon.max_monitors) d.own_rules[r.index].dropLast();
            return err;
        };
    }

    fn installScaleWatch(d: *Desktop) void {
        d.ipc.command(d.gpa, hypr.scale_watch_install) catch |err| {
            log.warn("scale watch not installed ({t}): a scale set on an RDP output in the session is undone by the next config reload", .{err});
            return;
        };
        d.scale_watch = true;
    }

    fn removeScaleWatch(d: *Desktop) void {
        d.scale_watch = false;
        d.own_rules = @splat(.{});
        d.ipc.command(d.gpa, hypr.scale_watch_remove) catch |err| log.warn("scale watch not removed: {t}", .{err});
    }

    /// Session-set scales apply while the client still asks for the earlier scale; stale ones are forgotten.
    fn effectiveLayout(d: *Desktop) multimon.Layout {
        var l = d.client_layout;
        const order = multimon.planOrder(&l);
        for (0..multimon.max_monitors) |i| {
            const us = d.user_scale[i] orelse continue;
            if (i >= l.count) {
                d.user_scale[i] = null;
                continue;
            }
            const m = &l.monitors[order[i]];
            if (scalePercent(m.*) != us.client_percent) {
                log.info("RDP-{d}: the client asks for scale {d}% now (was {d}%): the scale set in the session ({d}%) goes", .{ i + 1, scalePercent(m.*), us.client_percent, us.percent });
                d.user_scale[i] = null;
                continue;
            }
            m.attributes.desktop_scale_factor = us.percent;
            m.attributes.device_scale_factor = 100;
        }
        return l;
    }

    /// A scale watch report: omastation's own rule, or a user scale kept for the session.
    fn onRuleReport(d: *Desktop, r: hypr.RuleReport) void {
        if (r.index >= multimon.max_monitors) return;
        if (d.own_rules[r.index].popIf(r.percent)) return;
        if (!d.entered or d.desk_owns or r.index >= d.plan.count) return;
        const current = hypr.percentOfK(d.plan.outputs[r.index].scale_k);
        if (r.percent == current) return;
        if (multimon.effectiveAttributes(.{ .desktop_scale_factor = r.percent, .device_scale_factor = 100 }) catch null) |e| {
            if (e.desktop_scale_factor == null) {
                log.warn("RDP-{d} set to scale {d}% in the session: outside 100-500%, put back to {d}%", .{ r.index + 1, r.percent, current });
                d.applyEffective();
                return;
            }
        }
        const order = multimon.planOrder(&d.client_layout);
        const client_percent = if (r.index < d.client_layout.count) scalePercent(d.client_layout.monitors[order[r.index]]) else return;
        d.user_scale[r.index] = if (r.percent == client_percent) null else .{ .percent = r.percent, .client_percent = client_percent };
        log.info("RDP-{d} set to scale {d}% in the session (the client asks for {d}%): kept while it does", .{ r.index + 1, r.percent, client_percent });
        d.applyEffective();
    }

    fn applyEffective(d: *Desktop) void {
        const eff = d.effectiveLayout();
        if (eff.count > 1 or d.multi()) {
            d.relayoutTo(&eff) catch |err| log.warn("applying the session's scales failed: {t}", .{err});
        } else {
            const m = eff.monitors[0];
            d.resizeTo(m.width, m.height, scalePercent(m)) catch |err| log.warn("applying the session's scale failed: {t}", .{err});
        }
    }

    /// Display Control resize of RDP-1; on failure the size stays (MS-RDPEDISP 1.3).
    pub fn resize(d: *Desktop, w: u32, h: u32, scale_percent: u32) Error!void {
        d.client_layout = singleLayout(w, h, scale_percent);
        const eff = d.effectiveLayout();
        if (d.multi()) return d.relayoutTo(&eff);
        const m = eff.monitors[0];
        return d.resizeTo(m.width, m.height, scalePercent(m));
    }

    fn resizeTo(d: *Desktop, w: u32, h: u32, scale_percent: u32) Error!void {
        if (d.multi()) {
            const l = singleLayout(w, h, scale_percent);
            return d.relayoutTo(&l);
        }
        const fit = hypr.fitDesktop(w, h, scale_percent);
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        const steps = try console.planResize(arena.allocator(), d.monitors, .{ .width = fit.width, .height = fit.height, .scale = fit.scale() });
        for (steps) |st| try d.hyprCommand(st.cmd);
        d.fit = fit;
        d.plan = singlePlan(fit, d.plan.outputs[0].x);
        log.info("resized {s} to {d}x{d} scale {d:.4}", .{ console.rdp_output_name, fit.width, fit.height, fit.scale() });
        if (d.touch_mode != .off) d.reopenTouch();
    }

    /// DISPLAYCONTROL_MONITOR_LAYOUT_PDU; outputs keep names by position and stay as they were on failure.
    pub fn relayout(d: *Desktop, l: *const multimon.Layout) Error!void {
        if (l.count == 0 or l.count > multimon.max_monitors) return error.BadLayout;
        d.client_layout = l.*;
        const eff = d.effectiveLayout();
        return d.relayoutTo(&eff);
    }

    fn relayoutTo(d: *Desktop, l: *const multimon.Layout) Error!void {
        if (l.count == 0 or l.count > multimon.max_monitors) return error.BadLayout;
        if (l.count == 1 and !d.multi()) {
            const m = l.monitors[0];
            return d.resizeTo(m.width, m.height, scalePercent(m));
        }
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const base_x = if (d.entered) console.rdpBaseX(d.monitors) else d.plan.outputs[0].x;
        const plan = multimon.planSession(l, .{ .base_x = base_x }) catch return error.BadLayout;
        if (d.entered) {
            const current = try hypr.monitors(&d.ipc, a);
            const wss: []const hypr.WorkspaceState = hypr.workspaces(&d.ipc, a) catch &.{};
            const steps = console.planRelayout(a, &plan, current, wss) catch |err| return planError(err);
            for (steps) |st| {
                if (st.critical) {
                    try d.hyprCommand(st.cmd);
                } else d.hyprCommand(st.cmd) catch |err| log.warn("`{s}` failed: {t}", .{ st.cmd, err });
            }
        }
        const old_count = d.plan.count;
        if (old_count > plan.count) for (plan.count..old_count) |i| {
            const slot = d.captureSlot(i);
            if (slot.*) |cap| cap.deinit();
            slot.* = null;
            const vp = d.vpSlot(i);
            if (vp.*) |*p| p.deinit();
            vp.* = null;
            d.stopCursorAt(i);
            d.setOutput(i, null);
        };
        d.plan = plan;
        d.fit = outputFit(&plan, 0);
        d.layout = if (l.count > 1) l.* else null;
        if (d.pointer_on >= plan.count) d.pointer_on = 0;
        if (d.entered) d.writeRestoreFile();
        for (plan.outputs[0..plan.count]) |*o| log.info("relayout: {s} {d}x{d} scale {d:.4} at {d},{d}", .{
            o.name(), o.width, o.height, @as(f64, @floatFromInt(o.scale_k)) / 120.0, o.x, o.y,
        });
        if (d.client) |client| if (plan.count > old_count) {
            var waited: i32 = 0;
            while (!d.outputsAnnounced(client, old_count)) : (waited += 20) {
                if (waited >= 3000) return error.OutputMissing;
                _ = try client.dispatchTimeout(20);
            }
            for (old_count..plan.count) |i| {
                d.setOutput(i, client.findOutput(plan.outputs[i].name()).?);
                d.vpSlot(i).* = try wl.VirtualPointer.init(client, d.outputAt(i).?);
                d.startCursorAt(i);
                try d.startCaptureAt(i);
            }
            try client.flush();
        };
        if (d.touch_mode != .off) d.reopenTouch();
    }

    pub fn onScancode(d: *Desktop, code: u8, flags: u8) Error!void {
        if (!d.remoteInputAllowed()) return;
        const ev = d.keys.decode(code, flags) orelse return;
        // While the password is typed only releases pass, so no key stays down.
        if (ev.pressed and !d.remoteKeysAllowed()) return;
        const ks = &(d.kstate orelse return);
        const vk = &(d.vk orelse return);
        const change = ks.key(ev.evdev, ev.pressed) orelse return;
        // A config reload or a desk look may have dropped the repeat rules.
        d.repeatRulesOn();
        if (change.repeat) return d.repeatKey(vk, ks, ev.evdev);
        d.rep_key = null;
        if (ev.pressed) d.noteKey();
        try vk.key(ev.evdev, ev.pressed);
        if (change.mods) |m| try vk.modifiers(m.depressed, m.latched, m.locked, m.group);
    }

    /// Release and press, as Hyprland drops a second press of a held key; skipped where Hyprland would not repeat.
    fn repeatKey(d: *Desktop, vk: *wl.VirtualKeyboard, ks: *const keyboard.State, evdev: u16) Error!void {
        const mods = ks.bindMods();
        if (d.rep_key != evdev or d.rep_mods != mods) {
            d.rep_key = evdev;
            d.rep_mods = mods;
            d.rep_ok = d.repeatAllowed(ks, evdev, mods);
        }
        if (!d.rep_ok) return;
        d.noteKey();
        try vk.key(evdev, false);
        try vk.key(evdev, true);
    }

    fn repeatAllowed(d: *Desktop, ks: *const keyboard.State, evdev: u16, mods: u32) bool {
        const now = nowMs();
        // After a failed query, drop repeats rather than run a binding per repeat.
        if (now < d.rep_retry_ms) return false;
        const client_sym = ks.keymap.levelOneSym(evdev);
        const k: keyrepeat.Key = .{
            .keycode = evdev + 8,
            .syms = .{ if (d.bind_keymap) |*km| km.levelOneSym(evdev) else client_sym, client_sym },
            .mods = mods,
        };
        return keyrepeat.query(&d.ipc, d.gpa, k) catch |err| {
            log.warn("cannot read Hyprland's key bindings ({t}): the client's repeats of this key are dropped", .{err});
            d.rep_retry_ms = now + textbinds.State.retry_interval_ms;
            return false;
        };
    }

    /// TS_UNICODE_KEYBOARD_EVENT: one UTF-16 unit per event, typed on the press.
    pub fn onUnicode(d: *Desktop, unit: u16, release: bool) Error!void {
        if (release or !d.remoteKeysAllowed()) return;
        const cp = d.utf16.feed(unit) orelse return;
        try d.typeCodepoint(cp);
    }

    pub fn onSync(d: *Desktop, toggles: u8) Error!void {
        // Not held back during an unlock, or the client's lock keys would be lost.
        if (!d.remoteInputAllowed()) return;
        const ks = &(d.kstate orelse return);
        const vk = &(d.vk orelse return);
        d.rep_key = null;
        const s = try ks.sync(.{
            .caps = toggles & fastpath.sync_caps_lock != 0,
            .num = toggles & fastpath.sync_num_lock != 0,
            .scroll = toggles & fastpath.sync_scroll_lock != 0,
        });
        var it = s.released.iterator(.{});
        while (it.next()) |k| try vk.key(@intCast(k), false);
        if (s.mods) |m| try vk.modifiers(m.depressed, m.latched, m.locked, m.group);
        // All keys up, buttons included (MS-RDPBCGR 2.2.8.1.1.3.1.1.5).
        try d.releaseButtons();
    }

    /// TS_POINTER_EVENT (MS-RDPBCGR 2.2.8.1.1.3.1.1.3), relative to the layout bounding box.
    pub fn onPointer(d: *Desktop, flags: u16, x: u16, y: u16, extended: bool) Error!void {
        if (!d.remoteInputAllowed()) return;
        var buf: [2]translate.PointerEvent = undefined;
        const evs = translate.pointerEvents(flags, x, y, extended, &buf);
        // So the client's own positions coming back are not taken for warps.
        for (evs) |ev| if (ev == .motion) d.cursor.onClientMotion(ev.motion.x, ev.motion.y, nowMs());
        if (d.multi()) return d.injectPointerMulti(evs);
        try d.injectPointer(0, evs);
    }

    /// TS_RELPOINTER_EVENT, as relative motion (MS-RDPBCGR 2.2.8.1.1.3.1.1.7).
    pub fn onPointerRel(d: *Desktop, flags: u16, dx: i16, dy: i16) Error!void {
        if (!d.remoteInputAllowed()) return;
        var buf: [2]translate.PointerEvent = undefined;
        const evs = translate.relPointerEvents(flags, dx, dy, &buf);
        for (evs) |ev| if (ev == .motion_rel) d.cursor.onClientRelative();
        try d.injectPointer(d.pointer_on, evs);
    }

    fn injectPointer(d: *Desktop, slot: usize, evs: []const translate.PointerEvent) Error!void {
        const vp = &(d.vpSlot(slot).* orelse return);
        for (evs) |ev| switch (ev) {
            .motion => |m| try vp.motionAbsolute(m.x, m.y, d.fit.width, d.fit.height),
            .motion_rel => |m| try vp.motion(@floatFromInt(m.dx), @floatFromInt(m.dy)),
            .button => |b| {
                d.noteButton(slot, b.button, b.pressed);
                try vp.button(b.button, b.pressed);
            },
            .axis => |a| try vp.wheel(if (a.vertical) .vertical_scroll else .horizontal_scroll, a.value120),
        };
        try vp.frame();
    }

    fn releaseButtons(d: *Desktop) Error!void {
        for (&d.held_buttons, 0..) |*held, slot| {
            if (held.* == 0) continue;
            const bits = held.*;
            held.* = 0;
            const vp = &(d.vpSlot(slot).* orelse continue);
            for (held_button_codes, 0..) |code, i| {
                if (bits & (@as(u8, 1) << @intCast(i)) != 0) try vp.button(code, false);
            }
            try vp.frame();
        }
    }

    fn noteButton(d: *Desktop, slot: usize, code: u32, pressed: bool) void {
        const bit = buttonBit(code);
        if (pressed) d.held_buttons[slot] |= bit else d.held_buttons[slot] &= ~bit;
    }

    /// Motion moves the pointer of the output under (or nearest to) the point; buttons and wheel follow it.
    fn injectPointerMulti(d: *Desktop, evs: []const translate.PointerEvent) Error!void {
        for (evs) |ev| if (ev == .motion) {
            const b = planBounds(&d.plan);
            const at = d.locate(b.left + @as(i32, ev.motion.x), b.top + @as(i32, ev.motion.y)) orelse return;
            const vp = &(d.vpSlot(at.output).* orelse return);
            try vp.motionAbsolute(at.x, at.y, d.plan.outputs[at.output].width, d.plan.outputs[at.output].height);
            d.pointer_on = at.output;
        };
        const vp = &(d.vpSlot(d.pointer_on).* orelse return);
        for (evs) |ev| switch (ev) {
            .motion, .motion_rel => {},
            .button => |bt| {
                d.noteButton(d.pointer_on, bt.button, bt.pressed);
                try vp.button(bt.button, bt.pressed);
            },
            .axis => |a| try vp.wheel(if (a.vertical) .vertical_scroll else .horizontal_scroll, a.value120),
        };
        try vp.frame();
    }

    fn locate(d: *const Desktop, x: i32, y: i32) ?struct { output: u8, x: u32, y: u32 } {
        var rects: [multimon.max_monitors]rdpei.Output = undefined;
        for (d.plan.outputs[0..d.plan.count], rects[0..d.plan.count]) |o, *r| {
            const m = d.plan.monitors[o.monitor];
            r.* = .{ .left = m.left, .top = m.top, .width = @intCast(@as(i64, m.right) - m.left + 1), .height = @intCast(@as(i64, m.bottom) - m.top + 1) };
        }
        const loc = rdpei.locate(rects[0..d.plan.count], x, y) catch return null;
        const o = d.plan.outputs[loc.output];
        return .{ .output = loc.output, .x = @min(loc.x, o.width - 1), .y = @min(loc.y, o.height - 1) };
    }

    fn typeCodepoint(d: *Desktop, cp: u21) Error!void {
        const sym = c.xkb_utf32_to_keysym(cp);
        if (sym == c.XKB_KEY_NoSymbol) return;
        try d.typeKeysym(sym);
    }

    fn typeKeysym(d: *Desktop, sym: u32) Error!void {
        const client = d.client orelse return;
        const key = d.text.keyForSym(sym);
        var cur = d.tvk_current;
        if (d.tvk_generation[cur] != d.text.generation) {
            cur ^= 1;
            if (d.tvk[cur] == null) {
                d.tvk[cur] = try wl.VirtualKeyboard.init(client);
                d.text_binds.invalidate();
            }
            if (d.tvk_generation[cur] != d.text.generation) {
                const km = try d.text.render(d.gpa);
                defer d.gpa.free(km);
                try d.tvk[cur].?.setKeymap(km);
                d.tvk_generation[cur] = d.text.generation;
            }
            d.tvk_current = cur;
        }
        try d.textBindsOff(client);
        const vk = &d.tvk[cur].?;
        // Level 2 is Mod3 around the key.
        if (key.level2) try vk.modifiers(keyboard.TextKeymap.level2_mask, 0, 0, 0);
        d.noteKey();
        try vk.key(key.code, true);
        try vk.key(key.code, false);
        if (key.level2) try vk.modifiers(0, 0, 0, 0);
    }

    /// Without the event socket the no-bind rules are set again before every key.
    fn textBindsOff(d: *Desktop, client: *wl.Client) Error!void {
        if (d.events_fd >= 0) d.readEvents() else d.text_binds.invalidate();
        const now = nowMs();
        if (!d.text_binds.due(now)) return;
        // Hyprland must know the keyboards before it lists its devices.
        try client.roundtrip(2000);
        var want: usize = 0;
        for (d.tvk) |t| {
            if (t != null) want += 1;
        }
        if (!d.text_binds.ensure(&d.ipc, d.gpa, want)) d.text_binds.failedAt(now);
    }

    /// MS-RDPEI 3.2.5.2: a uinput touchscreen (and pen) per output through the helper, else emulated.
    pub fn openTouch(d: *Desktop, o: TouchOptions) Error!TouchMode {
        d.closeTouch();
        var outs: [touch.max_outputs]touch.Output = undefined;
        d.injector = touch.Injector.init(d.touchOutputs(&outs)) catch return error.BadLayout;
        d.touch_pen = o.pen;
        if (d.helper_fd < 0) {
            d.useEmulator();
            return d.touch_mode;
        }
        d.openDevices() catch |err| {
            log.warn("touch devices unavailable ({t}): emulating touch with the pointer", .{err});
            d.useEmulator();
            return d.touch_mode;
        };
        d.touch_mode = .devices;
        log.info("touch: {d} touchscreen(s){s} through the helper", .{ d.plan.count, if (o.pen) " and pen tablet(s)" else "" });
        return .devices;
    }

    fn useEmulator(d: *Desktop) void {
        var outs: [touch.max_outputs]touch.Output = undefined;
        var rects: [touch.max_outputs]rdpei.Output = undefined;
        const ts = d.touchOutputs(&outs);
        for (ts, rects[0..ts.len]) |t, *r| r.* = .{ .left = t.left, .top = t.top, .width = t.width, .height = t.height };
        d.emulator = rdpei.Emulator.init(rects[0..ts.len]) catch null;
        d.touch_mode = if (d.emulator != null) .emulated else .off;
    }

    pub fn closeTouch(d: *Desktop) void {
        d.releaseTouch();
        if (d.helper_fd >= 0) for (0..uinput.max_devices) |i| {
            const bit = @as(u16, 1) << @intCast(i);
            if (d.touch_devs & bit != 0) d.helperDeviceCommand(.{ .close = .{ .kind = .touch, .dev = @intCast(i) } }) catch {};
            if (d.pen_devs & bit != 0) d.helperDeviceCommand(.{ .close = .{ .kind = .pen, .dev = @intCast(i) } }) catch {};
        };
        d.touch_devs = 0;
        d.pen_devs = 0;
        d.injector = null;
        d.emulator = null;
        d.touch_mode = .off;
        d.touch_lost = false;
    }

    /// Lift every contact and the pen, keeping the devices (MS-RDPEI 3.2.5.4).
    pub fn releaseTouch(d: *Desktop) void {
        switch (d.touch_mode) {
            .off => {},
            .devices => {
                var w: std.Io.Writer.Allocating = .init(d.gpa);
                defer w.deinit();
                d.injector.?.releaseAll(&w.writer) catch {};
                if (d.touch_devs | d.pen_devs != 0) d.helperSend(w.written());
            },
            .emulated => {
                var out: [rdpei.max_events_per_contact]rdpei.PointerEvent = undefined;
                const evs = d.emulator.?.releaseAll(&out) catch return;
                d.injectEmulated(evs) catch {};
                if (d.client) |cl| cl.flush() catch {};
            },
        }
    }

    /// RDPINPUT_TOUCH_EVENT_PDU (MS-RDPEI 2.2.3.3).
    pub fn onTouch(d: *Desktop, ev: *const rdpei.TouchEvent) Error!void {
        if (!d.remoteInputAllowed()) return;
        switch (d.touch_mode) {
            .off => {},
            .devices => {
                if (d.touch_devs == 0) return;
                var w: std.Io.Writer.Allocating = .init(d.gpa);
                defer w.deinit();
                for (ev.frames) |f| d.injector.?.touchFrame(f, &w.writer) catch |err| try touchFailed(err);
                d.helperSend(w.written());
            },
            .emulated => for (ev.frames) |f| for (f.contacts) |ct| {
                var out: [rdpei.max_events_per_contact]rdpei.PointerEvent = undefined;
                const evs = d.emulator.?.touchContact(ct, &out) catch continue;
                try d.injectEmulated(evs);
            },
        }
    }

    /// RDPINPUT_PEN_EVENT_PDU (MS-RDPEI 2.2.3.7).
    pub fn onPen(d: *Desktop, ev: *const rdpei.PenEvent) Error!void {
        if (!d.remoteInputAllowed()) return;
        switch (d.touch_mode) {
            .off => {},
            .devices => {
                if (d.pen_devs == 0) return;
                var w: std.Io.Writer.Allocating = .init(d.gpa);
                defer w.deinit();
                for (ev.frames) |f| d.injector.?.penFrame(f, &w.writer) catch |err| try touchFailed(err);
                d.helperSend(w.written());
            },
            .emulated => for (ev.frames) |f| for (f.contacts) |ct| {
                var out: [rdpei.max_events_per_contact]rdpei.PointerEvent = undefined;
                const evs = d.emulator.?.penContact(ct, &out) catch continue;
                try d.injectEmulated(evs);
            },
        }
    }

    /// RDPINPUT_DISMISS_HOVERING_TOUCH_CONTACT_PDU (MS-RDPEI 3.2.5.6).
    pub fn onDismissHovering(d: *Desktop, contact_id: u8) Error!void {
        switch (d.touch_mode) {
            .off => {},
            .devices => d.injector.?.dismissHovering(contact_id) catch {},
            .emulated => d.emulator.?.dismissHovering(contact_id) catch {},
        }
    }

    pub fn touchMode(d: *const Desktop) TouchMode {
        return d.touch_mode;
    }

    /// Out of memory is an error; anything else drops the frame.
    fn touchFailed(err: touch.Error) Error!void {
        switch (err) {
            error.OutOfMemory, error.WriteFailed => return error.OutOfMemory,
            else => log.warn("touch frame dropped: {t}", .{err}),
        }
    }

    fn injectEmulated(d: *Desktop, evs: []const rdpei.PointerEvent) Error!void {
        for (evs) |ev| switch (ev) {
            .motion => |m| {
                const vp = &(d.vpSlot(m.output).* orelse continue);
                const size = d.outputSize(m.output);
                try vp.motionAbsolute(@min(m.x, size[0] - 1), @min(m.y, size[1] - 1), size[0], size[1]);
                d.pointer_on = m.output;
            },
            .button => |b| if (d.vpSlot(d.pointer_on).*) |*vp| try vp.button(b.code, b.pressed),
            .frame => if (d.vpSlot(d.pointer_on).*) |*vp| try vp.frame(),
        };
    }

    fn touchOutputs(d: *const Desktop, buf: *[touch.max_outputs]touch.Output) []const touch.Output {
        for (d.plan.outputs[0..d.plan.count], buf[0..d.plan.count]) |o, *t| {
            const m = d.plan.monitors[o.monitor];
            t.* = .{
                .left = m.left,
                .top = m.top,
                .width = @intCast(@as(i64, m.right) - m.left + 1),
                .height = @intCast(@as(i64, m.bottom) - m.top + 1),
                .mode_width = o.width,
                .mode_height = o.height,
            };
        }
        return buf[0..d.plan.count];
    }

    /// The mode at the monitor's pixel density (MS-RDPBCGR 2.2.1.3.10.1), else 4 units per mm (96 dpi).
    fn touchGeometry(d: *const Desktop, i: usize) uinput.Geometry {
        const o = d.plan.outputs[i];
        var res: u32 = 4;
        if (d.layout) |l| {
            const m = l.monitors[o.monitor];
            const e = multimon.effectiveAttributes(m.attributes) catch multimon.EffectiveAttributes{};
            if (e.physical_width_mm) |mm| res = std.math.clamp((m.width + mm / 2) / mm, 1, uinput.max_resolution);
        }
        return .{ .width = o.width, .height = o.height, .resolution = res };
    }

    fn bindDevices(d: *Desktop) void {
        var arena = std.heap.ArenaAllocator.init(d.gpa);
        defer arena.deinit();
        const steps = console.planDeviceBindings(arena.allocator(), &d.plan, d.touch_pen) catch return;
        for (steps) |st| d.runStep(st);
    }

    fn openDevices(d: *Desktop) Error!void {
        d.bindDevices();
        errdefer d.closeDevices();
        for (0..d.plan.count) |i| {
            const g = d.touchGeometry(i);
            const bit = @as(u16, 1) << @intCast(i);
            try d.helperDeviceCommand(.{ .open = .{ .kind = .touch, .dev = @intCast(i), .geometry = g } });
            d.touch_devs |= bit;
            if (!d.touch_pen) continue;
            try d.helperDeviceCommand(.{ .open = .{ .kind = .pen, .dev = @intCast(i), .geometry = g } });
            d.pen_devs |= bit;
        }
    }

    fn closeDevices(d: *Desktop) void {
        for (0..uinput.max_devices) |i| {
            const bit = @as(u16, 1) << @intCast(i);
            if (d.touch_devs & bit != 0) d.helperDeviceCommand(.{ .close = .{ .kind = .touch, .dev = @intCast(i) } }) catch {};
            if (d.pen_devs & bit != 0) d.helperDeviceCommand(.{ .close = .{ .kind = .pen, .dev = @intCast(i) } }) catch {};
        }
        d.touch_devs = 0;
        d.pen_devs = 0;
    }

    fn reopenTouch(d: *Desktop) void {
        const mode = d.touch_mode;
        d.releaseTouch();
        var outs: [touch.max_outputs]touch.Output = undefined;
        d.injector = touch.Injector.init(d.touchOutputs(&outs)) catch null;
        if (mode == .devices and d.injector != null and d.helper_fd >= 0) {
            for (d.plan.count..uinput.max_devices) |i| {
                const bit = @as(u16, 1) << @intCast(i);
                if (d.touch_devs & bit != 0) d.helperDeviceCommand(.{ .close = .{ .kind = .touch, .dev = @intCast(i) } }) catch {};
                if (d.pen_devs & bit != 0) d.helperDeviceCommand(.{ .close = .{ .kind = .pen, .dev = @intCast(i) } }) catch {};
                d.touch_devs &= ~bit;
                d.pen_devs &= ~bit;
            }
            d.openDevices() catch |err| {
                log.warn("touch devices unavailable ({t}): emulating touch with the pointer", .{err});
                d.useEmulator();
                return;
            };
            return;
        }
        d.useEmulator();
    }

    pub fn fenceDesk(d: *Desktop) Error!void {
        const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM | c.SOCK_CLOEXEC, 0);
        if (fd < 0) return error.FenceUnavailable;
        errdefer _ = c.close(fd);
        var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
        addr.sun_family = c.AF_UNIX;
        const path = d.opts.helper_socket;
        if (path.len >= addr.sun_path.len) return error.FenceUnavailable;
        @memcpy(addr.sun_path[0..path.len], path);
        // Bounds connect() and send() so a stuck helper cannot stall the session.
        const tv: c.struct_timeval = .{ .tv_sec = @divTrunc(helper_timeout_ms, 1000), .tv_usec = @mod(helper_timeout_ms, 1000) * 1000 };
        if (c.setsockopt(fd, c.SOL_SOCKET, c.SO_SNDTIMEO, &tv, @sizeOf(c.struct_timeval)) != 0) return error.FenceUnavailable;
        if (c.connect(fd, .{ .__sockaddr__ = @ptrCast(&addr) }, @sizeOf(c.struct_sockaddr_un)) != 0) return error.FenceUnavailable;
        d.helper_fd = fd;
        errdefer d.helper_fd = -1;
        try d.helperCommand("fence\n");
        log.info("desk input fenced", .{});
    }

    fn unfenceDesk(d: *Desktop) void {
        if (d.helper_fd < 0) return;
        d.helperCommand("unfence\n") catch {};
        _ = c.close(d.helper_fd);
        d.helper_fd = -1;
        log.info("desk input released", .{});
    }

    /// Waits up to helper_timeout_ms for "ok"; activity lines meanwhile are noted.
    fn helperCommand(d: *Desktop, cmd: []const u8) Error!void {
        if (c.send(d.helper_fd, cmd.ptr, cmd.len, c.MSG_NOSIGNAL) != @as(isize, @intCast(cmd.len))) return error.FenceUnavailable;
        d.helper_refused = false;
        var waited: i32 = 0;
        while (waited < helper_timeout_ms) : (waited += 50) {
            var pfd: c.struct_pollfd = .{ .fd = d.helper_fd, .events = c.POLLIN, .revents = 0 };
            if (c.poll(&pfd, 1, 50) <= 0) continue;
            if (try d.readHelper()) return;
            if (d.helper_refused) return error.HelperRefused;
        }
        return error.FenceUnavailable;
    }

    fn helperDeviceCommand(d: *Desktop, cmd: helper_proto.Command) Error!void {
        if (d.helper_fd < 0) return error.FenceUnavailable;
        var buf: [helper_proto.max_line + 1]u8 = undefined;
        const line = helper_proto.format(&buf, cmd) catch return error.BadLayout;
        d.helperCommand(line) catch |err| {
            if (err == error.FenceUnavailable) d.helperLost();
            return err;
        };
    }

    /// Contact frames are not answered; a helper 100 ms behind loses them, the next carries the full state.
    fn helperSend(d: *Desktop, data: []const u8) void {
        if (d.helper_fd < 0 or data.len == 0) return;
        var off: usize = 0;
        var waited: i32 = 0;
        while (off < data.len) {
            const n = c.send(d.helper_fd, data[off..].ptr, data.len - off, c.MSG_NOSIGNAL | c.MSG_DONTWAIT);
            if (n > 0) {
                off += @intCast(n);
                continue;
            }
            if (n < 0 and c.__errno_location().* == c.EAGAIN and waited < 100) {
                var pfd: c.struct_pollfd = .{ .fd = d.helper_fd, .events = c.POLLOUT, .revents = 0 };
                _ = c.poll(&pfd, 1, 10);
                waited += 10;
                continue;
            }
            log.warn("touch frames to the helper failed ({d} of {d} bytes sent)", .{ off, data.len });
            return;
        }
    }

    pub fn helperLost(d: *Desktop) void {
        if (d.helper_fd < 0) return;
        _ = c.close(d.helper_fd);
        d.helper_fd = -1;
        log.warn("desk helper connection lost: desk input is no longer fenced", .{});
        if (d.touch_mode == .devices) {
            d.touch_devs = 0;
            d.pen_devs = 0;
            if (d.injector) |*inj| {
                var w: std.Io.Writer.Discarding = .init(&.{});
                inj.releaseAll(&w.writer) catch {};
            }
            d.useEmulator();
            d.touch_lost = true;
        }
        if (d.entered and !d.desk_owns and d.contested_until_ms == null) d.refence_at_ms = nowMs() + refence_retry_ms;
    }

    pub const refence_retry_ms = 500;

    /// Fences the desk again once a lost helper answers, and restores touch devices.
    fn refenceIfLost(d: *Desktop) void {
        const at = d.refence_at_ms orelse return;
        if (!d.entered or d.desk_owns or d.contested_until_ms != null or d.helper_fd >= 0) {
            d.refence_at_ms = null;
            return;
        }
        const now = nowMs();
        if (now < at) return;
        d.fenceDesk() catch {
            d.refence_at_ms = now + refence_retry_ms;
            return;
        };
        d.refence_at_ms = null;
        log.info("the desk helper is back: desk input fenced again", .{});
        if (d.touch_lost) {
            d.touch_lost = false;
            d.touch_mode = .devices;
            d.reopenTouch();
        }
    }

    pub fn helperFd(d: *const Desktop) c_int {
        return d.helper_fd;
    }

    /// True if an "ok" was among the lines read.
    pub fn readHelper(d: *Desktop) Error!bool {
        const n = c.recv(d.helper_fd, d.helper_buf[d.helper_len..].ptr, d.helper_buf.len - d.helper_len, c.MSG_DONTWAIT);
        if (n == 0) return error.FenceUnavailable;
        if (n < 0) return false;
        d.helper_len += @intCast(n);
        var got_ok = false;
        while (std.mem.indexOfScalar(u8, d.helper_buf[0..d.helper_len], '\n')) |nl| {
            const line = d.helper_buf[0..nl];
            switch (helper_proto.parseReply(line)) {
                .ok => got_ok = true,
                .activity => d.desk_activity = true,
                .err => {
                    log.warn("helper: {s}", .{line});
                    d.helper_refused = true;
                },
                else => {},
            }
            std.mem.copyForwards(u8, d.helper_buf[0 .. d.helper_len - nl - 1], d.helper_buf[nl + 1 .. d.helper_len]);
            d.helper_len -= nl + 1;
        }
        if (d.helper_len == d.helper_buf.len) d.helper_len = 0;
        return got_ok;
    }
};

const held_button_codes = [_]u32{ translate.BTN_LEFT, translate.BTN_RIGHT, translate.BTN_MIDDLE, translate.BTN_SIDE, translate.BTN_EXTRA };

fn buttonBit(code: u32) u8 {
    for (held_button_codes, 0..) |b, i| if (b == code) return @as(u8, 1) << @intCast(i);
    return 0;
}

/// The session's configured keymap, as Hyprland's bindings read keycodes.
fn sessionKeymap(gpa: std.mem.Allocator, s: layouts.Session) ?keyboard.Keymap {
    var tmp = std.heap.ArenaAllocator.init(gpa);
    defer tmp.deinit();
    const t = tmp.allocator();
    const names: keyboard.Names = .{
        .rules = t.dupeSentinel(u8, s.rules, 0) catch return null,
        .model = t.dupeSentinel(u8, s.model, 0) catch return null,
        .layout = t.dupeSentinel(u8, s.layout, 0) catch return null,
        .variant = t.dupeSentinel(u8, s.variant, 0) catch return null,
        .options = t.dupeSentinel(u8, s.options, 0) catch return null,
    };
    return keyboard.Keymap.fromNames(names) catch null;
}

/// Hyprland keeps a removed keyboard's modifiers until the next modifiers event.
fn retireKeyboard(vk: *wl.VirtualKeyboard) void {
    vk.modifiers(0, 0, 0, 0) catch {};
    vk.deinit();
}

pub fn singlePlan(fit: hypr.Fit, base_x: i32) multimon.SessionPlan {
    var p: multimon.SessionPlan = .{ .desktop_width = fit.width, .desktop_height = fit.height, .count = 1 };
    p.outputs[0] = .{ .monitor = 0, .width = fit.width, .height = fit.height, .scale_k = fit.k, .x = base_x, .y = 0, .origin_x = 0, .origin_y = 0 };
    p.outputs[0].name_len = @intCast((multimon.outputName(&p.outputs[0].name_buf, 0) catch unreachable).len);
    p.monitors[0] = .{ .left = 0, .top = 0, .right = @as(i32, @intCast(fit.width)) - 1, .bottom = @as(i32, @intCast(fit.height)) - 1, .primary = true };
    return p;
}

pub const UserScale = struct {
    percent: u32,
    /// The client's DesktopScaleFactor for that monitor when it was set.
    client_percent: u32,
};

/// Percents of omastation's own rules awaiting their scale watch reports.
pub const RuleQueue = struct {
    items: [16]u32 = undefined,
    len: usize = 0,

    fn push(q: *RuleQueue, v: u32) void {
        if (q.len == q.items.len) {
            std.mem.copyForwards(u32, q.items[0 .. q.len - 1], q.items[1..q.len]);
            q.len -= 1;
        }
        q.items[q.len] = v;
        q.len += 1;
    }

    fn dropLast(q: *RuleQueue) void {
        if (q.len > 0) q.len -= 1;
    }

    fn popIf(q: *RuleQueue, v: u32) bool {
        if (q.len == 0 or q.items[0] != v) return false;
        std.mem.copyForwards(u32, q.items[0 .. q.len - 1], q.items[1..q.len]);
        q.len -= 1;
        return true;
    }
};

pub fn singleLayout(w: u32, h: u32, scale_percent: u32) multimon.Layout {
    var l: multimon.Layout = .{ .count = 1 };
    l.monitors[0] = .{ .left = 0, .top = 0, .width = w, .height = h, .primary = true, .attributes = .{ .desktop_scale_factor = scale_percent, .device_scale_factor = 100 } };
    return l;
}

fn outputFit(plan: *const multimon.SessionPlan, i: usize) hypr.Fit {
    const o = plan.outputs[i];
    return .{ .width = o.width, .height = o.height, .k = o.scale_k };
}

fn scalePercent(m: multimon.Monitor) u32 {
    const e = multimon.effectiveAttributes(m.attributes) catch return 100;
    return e.desktop_scale_factor orelse 100;
}

fn scaleCoord(v: i32, s: f64) i32 {
    return @intFromFloat(@round(@as(f64, @floatFromInt(v)) * s));
}

/// Top-left of the layout's bounding box, in virtual-desktop coordinates.
fn planBounds(plan: *const multimon.SessionPlan) struct { left: i32, top: i32 } {
    var left: i32 = std.math.maxInt(i32);
    var top: i32 = std.math.maxInt(i32);
    for (plan.monitors[0..plan.count]) |m| {
        left = @min(left, m.left);
        top = @min(top, m.top);
    }
    return .{ .left = left, .top = top };
}

fn planError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.NoSpaceLeft => error.NoSpaceLeft,
        else => error.BadLayout,
    };
}

fn countPhysicalOn(ms: []const hypr.MonitorState) usize {
    var n: usize = 0;
    for (ms) |m| {
        if (!m.disabled and !hypr.isRdpOutput(m.name) and !hypr.isFallback(m.name)) n += 1;
    }
    return n;
}

fn nowMs() i64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(i64, ts.tv_sec) * 1000 + @divTrunc(@as(i64, ts.tv_nsec), 1_000_000);
}

fn sleepMs(ms: u32) void {
    var ts: c.struct_timespec = .{ .tv_sec = @intCast(ms / 1000), .tv_nsec = @intCast(@as(u64, ms % 1000) * std.time.ns_per_ms) };
    _ = c.nanosleep(&ts, null);
}

test "desktop compiles" {
    std.testing.refAllDecls(Desktop);
}
