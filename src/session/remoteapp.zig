//! RemoteApp (MS-RDPERP) on Hyprland: window, icon and desktop orders for Hyprland's toplevels,
//! and the client's requests applied to Hyprland. Window orders mark rectangles in the desktop stream.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const rail = @import("../channel/rail.zig");
const hypr = @import("hypr.zig");
const toplevels = @import("toplevels.zig");
const xdg = @import("xdg.zig");
const icon = @import("icon.zig");
const clipboard = @import("clipboard.zig");

const Allocator = std.mem.Allocator;
const Window = toplevels.Window;
const Rect = toplevels.Rect;
const log = std.log.scoped(.remoteapp);

pub const Options = struct {
    windows: toplevels.Options = .{},
    /// Desktop entry and icon lookup; null: no icons, and Execute requests are refused.
    xdg: ?xdg.Dirs = null,
    /// Prefixed to every launched command.
    launcher: []const []const u8 = &.{},
    /// Runs Terminal=true applications.
    terminal: []const []const u8 = &.{"xdg-terminal-exec"},
    /// Opens TS_RAIL_EXEC_FLAG_FILE documents.
    opener: []const []const u8 = &.{"xdg-open"},
    /// Checked before launching (missing: RAIL_EXEC_E_FILE_NOT_FOUND); null: not checked.
    path: ?[]const u8 = null,
    /// Ids are never reused.
    first_window_id: u32 = 0x100,
    /// Null: $XDG_RUNTIME_DIR/omastation. Client paths into these mounts are never touched:
    /// this connection's thread serves them and would deadlock.
    private_root: ?[]const u8 = null,
};

/// Negotiated in capability sets and the Client Information PDU.
pub const Client = struct {
    /// 2.2.1.1.2; TS_WINDOW_LEVEL_SUPPORTED_EX adds the ClientAreaSize field.
    wnd_support_level: u32 = rail.window_level_supported,
    /// 3.3.5.1.5; 0: icons are sent uncached.
    num_icon_caches: u8 = 0,
    num_icon_cache_entries: u16 = 0,
    /// Cleared by TS_RAIL_CLIENTSTATUS_SUPPRESS_ICON_ORDERS (3.3.5.1.6).
    icons: bool = true,
    /// Title bar and taskbar; `icon_big` is Alt-Tab (2.2.1.3.1.2.2).
    icon_small: u16 = 16,
    icon_big: u16 = 32,
    /// 3.3.1.3: active when no remote window is; null: no ActiveWindowId then.
    marker_window_id: ?u32 = null,
};

/// 16 and 32 pixels, scaled if the client set TS_RAIL_CLIENTSTATUS_HIGH_DPI_ICONS_SUPPORTED (2.2.2.2.2).
pub fn iconSizes(client_status: u32, desktop_scale_percent: u32) struct { small: u16, big: u16 } {
    if (client_status & rail.clientstatus_high_dpi_icons_supported == 0) return .{ .small = 16, .big = 32 };
    const pct: u32 = std.math.clamp(desktop_scale_percent, 100, 500);
    return .{
        .small = @intCast(@min(icon.max_size, (16 * pct + 50) / 100)),
        .big = @intCast(@min(icon.max_size, (32 * pct + 50) / 100)),
    };
}

/// Window orders with the memory they point to; icon bitmaps belong to the RemoteApp.
pub const Batch = struct {
    arena: std.heap.ArenaAllocator,
    orders: std.ArrayList(rail.WindowOrder) = .empty,

    pub fn init(gpa: Allocator) Batch {
        return .{ .arena = .init(gpa) };
    }

    pub fn deinit(b: *Batch) void {
        b.arena.deinit();
    }

    pub fn reset(b: *Batch) void {
        _ = b.arena.reset(.retain_capacity);
        b.orders = .empty;
    }

    fn add(b: *Batch, o: rail.WindowOrder) error{OutOfMemory}!void {
        try b.orders.append(b.arena.allocator(), o);
    }

    pub fn encode(b: *const Batch, w: *bytes.Writer, wnd_support_level: u32) !void {
        for (b.orders.items) |o| try rail.encodeWindowOrder(w, o, wnd_support_level);
    }
};

pub const Outcome = union(enum) {
    done,
    /// No such window: "the server SHOULD ignore the PDU" (3.3.5.2.5.1-4, 3.3.5.2.6.3).
    ignored,
    /// Hyprland has nothing like it.
    unsupported,
    failed,
    /// SC_MOVE / SC_SIZE as Local Move/Size (3.3.5.2.6.1-2) via rail.Server.beginLocalMoveSize;
    /// the client's Window Move PDU then goes to `windowMove`.
    local_move_size: struct { info: rail.MinMaxInfo, move_size_type: u16, pos_x: i16, pos_y: i16 },
};

/// Execute Result fields (2.2.2.3.2).
pub const ExecOutcome = struct {
    result: u16,
    /// Win32 error code, as Windows servers report.
    raw: u32 = 0,
};

/// Win32 error codes for ExecOutcome.raw.
pub const error_file_not_found: u32 = 2;
pub const error_access_denied: u32 = 5;
pub const error_gen_failure: u32 = 31;
pub const error_invalid_parameter: u32 = 87;
pub const error_no_unicode_translation: u32 = 1113;

// Window styles (2.2.1.3.1.2.1 Style / ExtendedStyle, [MSDN-WINSTYLE]).
pub const ws_popup: u32 = 0x80000000;
pub const ws_minimize: u32 = 0x20000000;
pub const ws_visible: u32 = 0x10000000;
pub const ws_clipsiblings: u32 = 0x04000000;
pub const ws_maximize: u32 = 0x01000000;
pub const ws_caption: u32 = 0x00C00000;
pub const ws_sysmenu: u32 = 0x00080000;
pub const ws_thickframe: u32 = 0x00040000;
pub const ws_minimizebox: u32 = 0x00020000;
pub const ws_maximizebox: u32 = 0x00010000;
/// The overlapped window of the 4.1.1.1 capture (0x14CF0000).
pub const ws_overlapped_visible: u32 = ws_visible | ws_clipsiblings | ws_caption | ws_sysmenu | ws_thickframe | ws_minimizebox | ws_maximizebox;
pub const ws_ex_topmost: u32 = 0x00000008;
pub const ws_ex_windowedge: u32 = 0x00000100;

pub fn styleOf(w: *const Window) struct { style: u32, ex: u32, show: u8 } {
    const ex: u32 = ws_ex_windowedge | (if (w.pinned) ws_ex_topmost else 0);
    return switch (w.show) {
        .normal => .{ .style = ws_overlapped_visible, .ex = ex, .show = rail.show_show },
        .minimized => .{ .style = ws_overlapped_visible | ws_minimize, .ex = ex, .show = rail.show_minimized },
        .maximized => .{ .style = ws_overlapped_visible | ws_maximize, .ex = ex, .show = rail.show_maximized },
        // Borderless; WS_SYSMENU keeps FreeRDP from treating a captionless popup as a menu.
        .fullscreen => .{ .style = ws_popup | ws_visible | ws_clipsiblings | ws_sysmenu | ws_minimizebox | ws_maximizebox, .ex = ex & ~ws_ex_windowedge, .show = rail.show_show },
    };
}

const Key = struct { address: u64, stable_id: u64 };

/// What the client was last told about a window.
const Sent = struct {
    title: []u8,
    rect: Rect,
    visible: Rect,
    show_state: u8,
    style: u32,
    ex: u32,
    owner: u32,
    /// Hash of the app id its icons came from (0: none).
    icon: u64,
};

const AppIcons = struct { small: icon.Bits, big: icon.Bits, key: u64 };

/// Which icon each slot of the client's icon caches holds; FIFO.
const IconCache = struct {
    slots: []?Slot = &.{},
    next: usize = 0,
    entries: u16 = 0,

    const Slot = struct { key: u64, big: bool };

    fn reset(ic: *IconCache, gpa: Allocator, caches: u8, entries: u16) void {
        gpa.free(ic.slots);
        ic.* = .{};
        const n = @as(usize, caches) * entries;
        if (n == 0) return;
        ic.slots = gpa.alloc(?Slot, n) catch return;
        @memset(ic.slots, null);
        ic.entries = entries;
    }

    fn clear(ic: *IconCache) void {
        @memset(ic.slots, null);
        ic.next = 0;
    }

    fn info(ic: *const IconCache, i: usize) rail.CachedIconInfo {
        return .{ .cache_id = @intCast(i / ic.entries), .cache_entry = @intCast(i % ic.entries) };
    }

    fn lookup(ic: *const IconCache, s: Slot) ?rail.CachedIconInfo {
        for (ic.slots, 0..) |x, i| if (x != null and x.?.key == s.key and x.?.big == s.big) return ic.info(i);
        return null;
    }

    /// Replaces the oldest; null without caches.
    fn assign(ic: *IconCache, s: Slot) ?rail.CachedIconInfo {
        if (ic.slots.len == 0) return null;
        const i = ic.next;
        ic.next = (ic.next + 1) % ic.slots.len;
        ic.slots[i] = s;
        return ic.info(i);
    }
};

pub const RemoteApp = struct {
    gpa: Allocator,
    tracker: toplevels.Tracker,
    opts: Options,
    client: Client = .{},
    ids: std.AutoHashMapUnmanaged(Key, u32) = .empty,
    next_id: u32,
    sent: std.AutoArrayHashMapUnmanaged(u32, Sent) = .empty,
    sent_z: std.ArrayList(u32) = .empty,
    sent_active: ?u32 = null,
    /// desktopSync done: changes go out as updates.
    synced: bool = false,
    seen_generation: u64 = 0,
    /// Workspace selectors of the windows omastation minimized, by address.
    minimized_from: std.AutoHashMapUnmanaged(u64, []u8) = .empty,
    xdg_arena: std.heap.ArenaAllocator,
    apps: ?xdg.AppIndex = null,
    themes: ?xdg.IconThemes = null,
    resolved: std.StringHashMapUnmanaged(?*AppIcons) = .empty,
    icon_list: std.ArrayList(*AppIcons) = .empty,
    cache: IconCache = .{},

    pub fn init(gpa: Allocator, ipc: hypr.Ipc, opts: Options) RemoteApp {
        return .{
            .gpa = gpa,
            .tracker = .init(gpa, ipc, opts.windows),
            .opts = opts,
            .next_id = @max(1, opts.first_window_id),
            .xdg_arena = .init(gpa),
        };
    }

    /// Stops first if still started.
    pub fn deinit(ra: *RemoteApp) void {
        ra.stop();
        ra.clearSent();
        ra.sent.deinit(ra.gpa);
        ra.sent_z.deinit(ra.gpa);
        ra.ids.deinit(ra.gpa);
        var it = ra.minimized_from.valueIterator();
        while (it.next()) |v| ra.gpa.free(v.*);
        ra.minimized_from.deinit(ra.gpa);
        for (ra.icon_list.items) |a| {
            a.small.deinit(ra.gpa);
            a.big.deinit(ra.gpa);
            ra.gpa.destroy(a);
        }
        ra.icon_list.deinit(ra.gpa);
        ra.resolved.deinit(ra.gpa);
        ra.gpa.free(ra.cache.slots);
        ra.xdg_arena.deinit();
        ra.tracker.deinit();
    }

    pub fn start(ra: *RemoteApp) hypr.Error!void {
        try ra.tracker.start();
    }

    /// Returns minimized windows to a visible workspace; call before Desktop.leave.
    pub fn stop(ra: *RemoteApp) void {
        if (ra.tracker.started) {
            _ = ra.tracker.resync() catch false;
            for (ra.tracker.model.windows) |*w| {
                if (std.mem.eql(u8, w.workspace, toplevels.minimized_workspace)) _ = ra.unminimize(w);
            }
        }
        ra.tracker.stop();
    }

    pub fn eventsFd(ra: *const RemoteApp) c_int {
        return ra.tracker.eventsFd();
    }

    pub fn readEvents(ra: *RemoteApp) error{OutOfMemory}!void {
        _ = try ra.tracker.readEvents();
    }

    /// Forgets what the client's icon caches held.
    pub fn setClient(ra: *RemoteApp, cl: Client) void {
        const small = std.math.clamp(cl.icon_small, 1, icon.max_size);
        const big = std.math.clamp(cl.icon_big, 1, icon.max_size);
        if (small != ra.client.icon_small or big != ra.client.icon_big) ra.resolved.clearRetainingCapacity();
        ra.client = cl;
        ra.client.icon_small = small;
        ra.client.icon_big = big;
        ra.cache.reset(ra.gpa, cl.num_icon_caches, cl.num_icon_cache_entries);
    }

    pub fn windowId(ra: *const RemoteApp, address: u64) ?u32 {
        const w = ra.tracker.model.find(address) orelse return null;
        return ra.ids.get(.{ .address = w.address, .stable_id = w.stable_id });
    }

    pub fn window(ra: *const RemoteApp, id: u32) ?*const Window {
        var it = ra.ids.iterator();
        while (it.next()) |e| if (e.value_ptr.* == id) {
            const w = ra.tracker.model.find(e.key_ptr.address) orelse return null;
            return if (w.stable_id == e.key_ptr.stable_id) w else null;
        };
        return null;
    }

    /// Desktop synchronization (3.3.5.1.8): every window as new, then the z-order and active window.
    pub fn desktopSync(ra: *RemoteApp, out: *Batch) !void {
        // 3.2.5.1.8: after ARC_BEGAN the client discards every window.
        ra.clearSent();
        ra.sent_z.clearRetainingCapacity();
        ra.sent_active = null;
        ra.cache.clear();
        ra.synced = true;
        ra.seen_generation = ra.tracker.generation;
        try ra.collect(out, true);
    }

    /// Orders for what changed since the client was last told (3.3.5.1.6); none before desktopSync.
    pub fn update(ra: *RemoteApp, now_ms: i64, out: *Batch) !bool {
        _ = try ra.tracker.tick(now_ms);
        if (!ra.synced or ra.tracker.generation == ra.seen_generation) return false;
        ra.seen_generation = ra.tracker.generation;
        const before = out.orders.items.len;
        try ra.collect(out, false);
        return out.orders.items.len > before;
    }

    fn clearSent(ra: *RemoteApp) void {
        for (ra.sent.values()) |s| ra.gpa.free(s.title);
        ra.sent.clearRetainingCapacity();
    }

    fn idFor(ra: *RemoteApp, w: *const Window) error{OutOfMemory}!u32 {
        const key: Key = .{ .address = w.address, .stable_id = w.stable_id };
        if (ra.ids.get(key)) |id| return id;
        var id = ra.next_id;
        if (ra.client.marker_window_id) |m| {
            if (id == m) id += 1;
        }
        ra.next_id = id +% 1;
        if (ra.next_id == 0) ra.next_id = 1;
        try ra.ids.put(ra.gpa, key, id);
        return id;
    }

    fn collect(ra: *RemoteApp, out: *Batch, full: bool) !void {
        const a = out.arena.allocator();
        const model = &ra.tracker.model;
        const ids = try a.alloc(u32, model.windows.len);
        for (model.windows, ids) |*w, *id| id.* = try ra.idFor(w);

        // Deleted windows (2.2.1.3.1.2.4).
        var gone: std.ArrayList(u32) = .empty;
        for (ra.sent.keys()) |id| {
            if (std.mem.indexOfScalar(u32, ids, id) == null) try gone.append(a, id);
        }
        for (gone.items) |id| {
            try out.add(.{ .window_deleted = .{ .window_id = id } });
            const s = ra.sent.fetchSwapRemove(id).?;
            ra.gpa.free(s.value.title);
        }
        var stale: std.ArrayList(Key) = .empty;
        var it = ra.ids.iterator();
        while (it.next()) |e| if (std.mem.indexOfScalar(u32, ids, e.value_ptr.*) == null) try stale.append(a, e.key_ptr.*);
        for (stale.items) |k| _ = ra.ids.remove(k);

        var i = model.windows.len;
        while (i > 0) {
            i -= 1;
            try ra.describe(out, &model.windows[i], ids[i]);
        }

        // NumWindowIds is one byte (2.2.1.3.3.2.1): at most the 255 topmost.
        const z = ids[0..@min(ids.len, 255)];
        const active: ?u32 = if (model.active) |addr| blk: {
            for (model.windows, ids) |w, id| if (w.address == addr) break :blk id;
            break :blk null;
        } else ra.client.marker_window_id;
        const z_changed = full or !std.mem.eql(u32, z, ra.sent_z.items);
        const active_changed = active != null and (full or active != ra.sent_active);
        if (z_changed or active_changed) {
            try out.add(.{ .desktop = .{
                .active_window_id = if (active_changed) active else null,
                .z_order = if (z_changed) try a.dupe(u32, z) else null,
            } });
        }
        ra.sent_z.clearRetainingCapacity();
        try ra.sent_z.appendSlice(ra.gpa, z);
        ra.sent_active = active;
    }

    /// Only changed fields once the client has the window (2.2.1.3.1.2.1); minimized keeps its geometry.
    fn describe(ra: *RemoteApp, out: *Batch, w: *const Window, id: u32) !void {
        const a = out.arena.allocator();
        const st = styleOf(w);
        const title = try titleUtf16(a, if (w.title.len > 0) w.title else w.class);
        const level_ex = ra.client.wnd_support_level == rail.window_level_supported_ex;
        const vis = w.visible orelse (if (w.show == .minimized) w.rect else Rect{ .x = w.rect.x, .y = w.rect.y, .width = 0, .height = 0 });
        const icon_key = appKey(w);
        const owner: u32 = if (w.owner) |o| (ra.windowId(o) orelse 0) else 0;

        const prev = ra.sent.getPtr(id);
        var s: rail.WindowState = .{};
        if (prev == null) {
            s = .{
                .owner_window_id = owner,
                .style = .{ .style = st.style, .extended_style = st.ex },
                .show_state = st.show,
                .title = title,
                .client_offset = .{ .x = w.rect.x, .y = w.rect.y },
                .client_area_size = if (level_ex) .{ .width = @intCast(w.rect.width), .height = @intCast(w.rect.height) } else null,
                .window_offset = .{ .x = w.rect.x, .y = w.rect.y },
                .client_delta = .{ .x = 0, .y = 0 },
                .window_size = .{ .width = @intCast(w.rect.width), .height = @intCast(w.rect.height) },
                .window_rects = try rects(a, w.rect),
                .visible_offset = .{ .x = vis.x, .y = vis.y },
                .visibility_rects = try rects(a, vis),
            };
            try out.add(.{ .window = .{ .window_id = id, .new = true, .state = s } });
            const copy = try ra.gpa.dupe(u8, title);
            errdefer ra.gpa.free(copy);
            try ra.sent.put(ra.gpa, id, .{
                .title = copy,
                .rect = w.rect,
                .visible = vis,
                .show_state = st.show,
                .style = st.style,
                .ex = st.ex,
                .owner = owner,
                .icon = icon_key,
            });
            try ra.sendIcons(out, w, id, true);
            return;
        }
        const p = prev.?;
        var any = false;
        if (!std.mem.eql(u8, p.title, title)) {
            const copy = try ra.gpa.dupe(u8, title);
            ra.gpa.free(p.title);
            p.title = copy;
            s.title = title;
            any = true;
        }
        if (p.style != st.style or p.ex != st.ex) {
            s.style = .{ .style = st.style, .extended_style = st.ex };
            p.style = st.style;
            p.ex = st.ex;
            any = true;
        }
        // Fullscreen and normal are both SW_SHOW on the wire.
        if (p.show_state != st.show) {
            s.show_state = st.show;
            p.show_state = st.show;
            any = true;
        }
        if (p.owner != owner) {
            s.owner_window_id = owner;
            p.owner = owner;
            any = true;
        }
        if (w.show != .minimized) {
            if (p.rect.x != w.rect.x or p.rect.y != w.rect.y) {
                s.window_offset = .{ .x = w.rect.x, .y = w.rect.y };
                s.client_offset = .{ .x = w.rect.x, .y = w.rect.y };
                any = true;
            }
            if (p.rect.width != w.rect.width or p.rect.height != w.rect.height) {
                s.window_size = .{ .width = @intCast(w.rect.width), .height = @intCast(w.rect.height) };
                s.window_rects = try rects(a, w.rect);
                if (level_ex) s.client_area_size = .{ .width = @intCast(w.rect.width), .height = @intCast(w.rect.height) };
                any = true;
            }
            p.rect = w.rect;
            // VisibilityRects are relative to VisibleOffset: a move only changes the offset.
            if (p.visible.x != vis.x or p.visible.y != vis.y) {
                s.visible_offset = .{ .x = vis.x, .y = vis.y };
                any = true;
            }
            if (p.visible.width != vis.width or p.visible.height != vis.height) {
                s.visibility_rects = try rects(a, vis);
                any = true;
            }
            p.visible = vis;
        }
        if (any) try out.add(.{ .window = .{ .window_id = id, .state = s } });
        if (p.icon != icon_key) {
            p.icon = icon_key;
            try ra.sendIcons(out, w, id, false);
        }
    }

    /// Window Icon (2.2.1.3.1.2.2) or Cached Icon (2.2.1.3.1.2.3) orders, small then big.
    /// For a new window the first carries WINDOW_ORDER_STATE_NEW: FreeRDP replaces icons on it, appends the next.
    fn sendIcons(ra: *RemoteApp, out: *Batch, w: *const Window, id: u32, new: bool) !void {
        if (!ra.client.icons) return;
        const icons = (try ra.appIcons(w)) orelse return;
        for ([_]bool{ false, true }) |big| {
            const bits = if (big) &icons.big else &icons.small;
            const first = new and !big;
            const slot: IconCache.Slot = .{ .key = icons.key, .big = big };
            if (ra.cache.lookup(slot)) |cached| {
                try out.add(.{ .window_cached_icon = .{ .window_id = id, .new = first, .big = big, .cached = cached } });
                continue;
            }
            // CacheId 0xFF: "the icon SHOULD NOT be cached" (2.2.1.2.3).
            const where = ra.cache.assign(slot) orelse rail.CachedIconInfo{ .cache_id = 0xFF, .cache_entry = 0xFFFF };
            try out.add(.{ .window_icon = .{ .window_id = id, .new = first, .big = big, .icon = .{
                .cache_entry = where.cache_entry,
                .cache_id = where.cache_id,
                .bpp = 32,
                .width = bits.width,
                .height = bits.height,
                .bits_mask = bits.mask,
                .bits_color = bits.color,
            } } });
        }
    }

    /// Desktop entry Icon=, else the app id as an icon name; resolved once per app.
    fn appIcons(ra: *RemoteApp, w: *const Window) error{OutOfMemory}!?*AppIcons {
        const dirs = ra.opts.xdg orelse return null;
        const class = if (w.class.len > 0) w.class else w.initial_class;
        if (class.len == 0) return null;
        const xa = ra.xdg_arena.allocator();
        const gop = try ra.resolved.getOrPut(ra.gpa, class);
        if (gop.found_existing) return gop.value_ptr.*;
        gop.key_ptr.* = try xa.dupe(u8, class);
        gop.value_ptr.* = null;
        if (ra.apps == null) ra.apps = try xdg.AppIndex.load(xa, dirs);
        if (ra.themes == null) ra.themes = try xdg.IconThemes.load(xa, dirs);
        const name = if (ra.apps.?.forClass(xa, class)) |e| (if (e.icon.len > 0) e.icon else class) else class;
        const small = try ra.loadIcon(name, ra.client.icon_small);
        const big = try ra.loadIcon(name, ra.client.icon_big);
        if (small == null and big == null) {
            log.debug("no PNG icon for {s} (icon {s})", .{ class, name });
            return null;
        }
        const ai = try ra.gpa.create(AppIcons);
        ai.* = .{ .small = undefined, .big = undefined, .key = std.hash.Wyhash.hash(0, class) | 1 };
        ai.small = small orelse (try ra.reloadAs(big.?, ra.client.icon_small));
        ai.big = big orelse (try ra.reloadAs(small.?, ra.client.icon_big));
        try ra.icon_list.append(ra.gpa, ai);
        gop.value_ptr.* = ai;
        return ai;
    }

    fn loadIcon(ra: *RemoteApp, name: []const u8, px: u16) error{OutOfMemory}!?icon.Bits {
        const xa = ra.xdg_arena.allocator();
        const path = (try ra.themes.?.find(xa, name, px)) orelse return null;
        var scratch = std.heap.ArenaAllocator.init(ra.gpa);
        defer scratch.deinit();
        const png = xdg.readFile(scratch.allocator(), path, 8 << 20) orelse return null;
        return icon.fromPng(ra.gpa, png, px) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidIcon => {
                log.debug("icon {s} is not a PNG omastation can read", .{path});
                return null;
            },
        };
    }

    fn reloadAs(ra: *RemoteApp, b: icon.Bits, px: u16) error{OutOfMemory}!icon.Bits {
        const n = @as(usize, b.width) * b.height;
        const rgba = try ra.gpa.alloc(u8, n * 4);
        defer ra.gpa.free(rgba);
        for (0..b.height) |y| for (0..b.width) |x| {
            const s = ((b.height - 1 - y) * b.width + x) * 4;
            const d = (y * b.width + x) * 4;
            rgba[d..][0..4].* = .{ b.color[s + 2], b.color[s + 1], b.color[s], b.color[s + 3] };
        };
        return icon.fromRgba(ra.gpa, rgba, b.width, b.height, px) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidIcon => unreachable, // sizes checked by setClient
        };
    }

    fn run(ra: *RemoteApp, cmd: []const u8) bool {
        const resp = ra.tracker.ipc.request(ra.gpa, cmd) catch |err| {
            log.warn("hyprland unreachable for `{s}`: {t}", .{ cmd[0..@min(cmd.len, 200)], err });
            return false;
        };
        defer ra.gpa.free(resp);
        if (std.mem.eql(u8, std.mem.trim(u8, resp, " \n"), "ok")) {
            ra.tracker.dirty = true;
            return true;
        }
        log.warn("hyprland refused `{s}`: {s}", .{ cmd[0..@min(cmd.len, 200)], resp[0..@min(resp.len, 200)] });
        return false;
    }

    fn done(ok: bool) Outcome {
        return if (ok) .done else .failed;
    }

    /// Activate PDU (3.3.5.2.5.1): focuses the window, restoring it first if minimized.
    pub fn activate(ra: *RemoteApp, a: rail.Activate) Outcome {
        const w = ra.window(a.window_id) orelse return .ignored;
        if (!a.enabled) return .done;
        if (isOurMinimized(w) and !ra.unminimize(w)) return .failed;
        return done(ra.focus(w.address));
    }

    /// System Command PDU (3.3.5.2.5.3).
    pub fn sysCommand(ra: *RemoteApp, cmd: rail.SysCommand) Outcome {
        const w = ra.window(cmd.window_id) orelse return .ignored;
        var buf: [512]u8 = undefined;
        switch (cmd.command) {
            rail.sc_minimize => {
                if (w.show == .minimized) return .done;
                return done(ra.minimize(w));
            },
            rail.sc_maximize => {
                if (isOurMinimized(w) and !ra.unminimize(w)) return .failed;
                if (w.show == .maximized) return .done;
                if (w.show == .fullscreen and !ra.run(hypr.formatFullscreenWindow(&buf, w.address, .fullscreen, .unset) catch return .failed)) return .failed;
                return done(ra.run(hypr.formatFullscreenWindow(&buf, w.address, .maximized, .set) catch return .failed));
            },
            rail.sc_restore => switch (w.show) {
                .minimized => {
                    if (isOurMinimized(w) and !ra.unminimize(w)) return .failed;
                    return done(ra.focus(w.address));
                },
                .maximized => return done(ra.run(hypr.formatFullscreenWindow(&buf, w.address, .maximized, .unset) catch return .failed)),
                .fullscreen => return done(ra.run(hypr.formatFullscreenWindow(&buf, w.address, .fullscreen, .unset) catch return .failed)),
                .normal => return .done,
            },
            rail.sc_close => return done(ra.run(hypr.formatCloseWindow(&buf, w.address) catch return .failed)),
            rail.sc_move, rail.sc_size => {
                const p = ra.tracker.output(w.output) orelse return .failed;
                const o = p.rdpRect();
                return .{ .local_move_size = .{
                    .info = .{
                        .window_id = cmd.window_id,
                        .max_width = clampI16(o.width),
                        .max_height = clampI16(o.height),
                        .max_pos_x = clampI16(o.x),
                        .max_pos_y = clampI16(o.y),
                        .min_track_width = 1,
                        .min_track_height = 1,
                        .max_track_width = clampI16(o.width),
                        .max_track_height = clampI16(o.height),
                    },
                    .move_size_type = if (cmd.command == rail.sc_move) rail.wmsz_keymove else rail.wmsz_keysize,
                    .pos_x = clampI16(w.rect.x),
                    .pos_y = clampI16(w.rect.y),
                } };
            },
            else => return .unsupported, // SC_KEYMENU, SC_DEFAULT
        }
    }

    /// System Menu PDU (3.3.5.2.5.2): Hyprland windows have no system menu.
    pub fn sysMenu(ra: *RemoteApp, m: rail.SysMenu) Outcome {
        return if (ra.window(m.window_id) == null) .ignored else .unsupported;
    }

    /// Notify Event PDU (3.3.5.2.5.4): no notification icons are sent, so it is ignored.
    pub fn notifyEvent(ra: *RemoteApp, n: rail.NotifyEvent) Outcome {
        _ = ra;
        _ = n;
        return .ignored;
    }

    /// Window Cloak State Change (3.3.5.2.9.1): Hyprland cannot cloak.
    pub fn cloak(ra: *RemoteApp, cl: rail.Cloak) Outcome {
        return if (ra.window(cl.window_id) == null) .ignored else .unsupported;
    }

    /// Window Move (3.3.5.2.6.3) and Snap (3.3.5.2.6.5), right/bottom exclusive. Tiled windows are
    /// floated first; sized before moved since Hyprland resizes about the center.
    pub fn windowMove(ra: *RemoteApp, m: rail.WindowMove) Outcome {
        const w = ra.window(m.window_id) orelse return .ignored;
        if (w.show == .minimized) return .done;
        const target: Rect = .{ .x = m.left, .y = m.top, .width = @as(i32, m.right) - m.left, .height = @as(i32, m.bottom) - m.top };
        if (target.width <= 0 or target.height <= 0) return .ignored;
        if (near(target, w.rect)) return .done;
        const p = ra.tracker.outputAt(target.x, target.y) orelse ra.tracker.output(w.output) orelse return .failed;
        const l = p.toLogical(target);
        var buf: [512]u8 = undefined;
        if (w.show == .maximized and !ra.run(hypr.formatFullscreenWindow(&buf, w.address, .maximized, .unset) catch return .failed)) return .failed;
        if (w.show == .fullscreen and !ra.run(hypr.formatFullscreenWindow(&buf, w.address, .fullscreen, .unset) catch return .failed)) return .failed;
        if (!w.floating and !ra.run(hypr.formatFloatWindow(&buf, w.address, true) catch return .failed)) return .failed;
        if (!ra.run(hypr.formatResizeWindowPixel(&buf, w.address, @max(1, l.width), @max(1, l.height)) catch return .failed)) return .failed;
        return done(ra.run(hypr.formatMoveWindowPixel(&buf, w.address, l.x, l.y) catch return .failed));
    }

    /// Get Application ID (3.3.5.2.7.1, 2.2.2.8.1): groups taskbar buttons; null for an unknown window.
    pub fn appId(ra: *const RemoteApp, arena: Allocator, window_id: u32) error{OutOfMemory}!?rail.GetAppIdResp {
        const w = ra.window(window_id) orelse return null;
        const class = if (w.class.len > 0) w.class else w.initial_class;
        // 259 WCHARs and the terminator fill the 520-byte field.
        var id = try toUtf16(arena, class, rail.appid_field_size - 2);
        if (id.len == 0) id = try toUtf16(arena, "omastation", 64);
        return .{ .window_id = window_id, .application_id = id };
    }

    fn focus(ra: *RemoteApp, address: u64) bool {
        var buf: [256]u8 = undefined;
        return ra.run(hypr.formatFocusWindow(&buf, address) catch return false);
    }

    fn isOurMinimized(w: *const Window) bool {
        return std.mem.eql(u8, w.workspace, toplevels.minimized_workspace);
    }

    /// Moves the window to a hidden special workspace, remembering where it was.
    fn minimize(ra: *RemoteApp, w: *const Window) bool {
        var sel_buf: [300]u8 = undefined;
        const sel = hypr.workspaceSelector(&sel_buf, .{ .id = w.workspace_id, .name = w.workspace, .monitor = "" }) catch return false;
        var buf: [1024]u8 = undefined;
        if (!ra.run(hypr.formatMoveWindowToWorkspace(&buf, w.address, toplevels.minimized_workspace) catch return false)) return false;
        const copy = ra.gpa.dupe(u8, sel) catch return true;
        const gop = ra.minimized_from.getOrPut(ra.gpa, w.address) catch {
            ra.gpa.free(copy);
            return true;
        };
        if (gop.found_existing) ra.gpa.free(gop.value_ptr.*);
        gop.value_ptr.* = copy;
        return true;
    }

    /// Back to its workspace if a remote output shows it, else its output's active one.
    fn unminimize(ra: *RemoteApp, w: *const Window) bool {
        var sel_buf: [300]u8 = undefined;
        const target: []const u8 = blk: {
            if (ra.minimized_from.get(w.address)) |from| {
                for (ra.tracker.outputs) |p| {
                    var b2: [300]u8 = undefined;
                    const s = hypr.workspaceSelector(&b2, .{ .id = p.monitor.workspace_id, .name = p.monitor.workspace, .monitor = "" }) catch continue;
                    if (std.mem.eql(u8, s, from)) break :blk from;
                }
            }
            const p = ra.tracker.output(w.output) orelse (if (ra.tracker.outputs.len > 0) ra.tracker.outputs[0] else return false);
            break :blk hypr.workspaceSelector(&sel_buf, .{ .id = p.monitor.workspace_id, .name = p.monitor.workspace, .monitor = "" }) catch return false;
        };
        var buf: [1024]u8 = undefined;
        if (!ra.run(hypr.formatMoveWindowToWorkspace(&buf, w.address, target) catch return false)) return false;
        if (ra.minimized_from.fetchRemove(w.address)) |kv| ra.gpa.free(kv.value);
        return true;
    }

    /// Execute PDU (2.2.2.3.1, 3.3.5.2.2.1): only desktop entries (by alias or program) or existing files,
    /// else RAIL_EXEC_E_NOT_IN_ALLOWLIST. Arguments never start with '-' and reach /bin/sh single-quoted.
    pub fn exec(ra: *RemoteApp, e: rail.Exec) ExecOutcome {
        var arena_state = std.heap.ArenaAllocator.init(ra.gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const cmd = ra.execCommand(a, e) catch |err| return switch (err) {
            error.OutOfMemory => .{ .result = rail.exec_e_fail, .raw = error_gen_failure },
            error.DecodeFailed => .{ .result = rail.exec_e_decode_failed, .raw = error_no_unicode_translation },
            error.NotInAllowList => .{ .result = rail.exec_e_not_in_allowlist, .raw = error_access_denied },
            error.FileNotFound => .{ .result = rail.exec_e_file_not_found, .raw = error_file_not_found },
            error.BadArguments => .{ .result = rail.exec_e_fail, .raw = error_invalid_parameter },
        };
        // RAIL_EXEC_E_SESSION_LOCKED: nothing starts behind the lock screen.
        const locked = hypr.isLocked(&ra.tracker.ipc, ra.gpa) catch return .{ .result = rail.exec_e_fail, .raw = error_gen_failure };
        if (locked) return .{ .result = rail.exec_e_session_locked };
        const req = formatExecCmd(a, cmd) catch return .{ .result = rail.exec_e_fail, .raw = error_gen_failure };
        if (!ra.run(req)) return .{ .result = rail.exec_e_fail, .raw = error_gen_failure };
        return .{ .result = rail.exec_s_ok };
    }

    pub const ExecError = error{ OutOfMemory, DecodeFailed, NotInAllowList, FileNotFound, BadArguments };

    pub fn execCommand(ra: *RemoteApp, a: Allocator, e: rail.Exec) ExecError![]const u8 {
        const exe_raw = try fromUtf16(a, e.exe_or_file);
        const dir_raw = try fromUtf16(a, e.working_dir);
        const args_raw = try fromUtf16(a, e.arguments);
        const exe = std.mem.trim(u8, exe_raw, " \t\"");
        if (exe.len == 0 or hasControl(exe)) return error.NotInAllowList;
        const args = try splitArguments(a, args_raw);
        for (args) |arg| if (arg.len == 0 or arg[0] == '-' or hasControl(arg)) return error.BadArguments;

        var argv: std.ArrayList([]const u8) = .empty;
        const own = try clipboard.ownMountsRoot(a, ra.opts.private_root);
        var workdir: ?[]const u8 = null;
        if (posixDir(a, dir_raw, own)) |d| workdir = d;

        if (e.flags & rail.exec_flag_file != 0) {
            if (exe[0] != '/' or intoOwnMounts(exe, own) or !fileExists(a, exe)) return error.FileNotFound;
            if (args.len > 0) return error.BadArguments;
            try ra.checkPrograms(a, ra.opts.opener);
            try argv.appendSlice(a, ra.opts.launcher);
            try argv.appendSlice(a, ra.opts.opener);
            try argv.append(a, exe);
            return shellCommand(a, workdir, argv.items);
        }

        const dirs = ra.opts.xdg orelse return error.NotInAllowList;
        const xa = ra.xdg_arena.allocator();
        if (ra.apps == null) ra.apps = try xdg.AppIndex.load(xa, dirs);
        const apps = &ra.apps.?;
        const by_alias = std.mem.startsWith(u8, exe, "||") or e.flags & rail.exec_flag_app_user_model_id != 0;
        const name = if (std.mem.startsWith(u8, exe, "||")) exe[2..] else exe;
        if (name.len == 0 or std.mem.indexOfScalar(u8, name, '\\') != null) return error.NotInAllowList;
        const entry = if (by_alias)
            apps.forClass(a, name) orelse return error.NotInAllowList
        else
            apps.byId(name) orelse apps.forProgram(a, name) orelse return error.NotInAllowList;

        switch (xdg.execTakes(a, entry.exec) catch return error.NotInAllowList) {
            .nothing => if (args.len > 0) return error.BadArguments,
            .one => if (args.len > 1) return error.BadArguments,
            .many => {},
        }
        const expanded = xdg.expandExec(a, entry.exec, .{ .args = args, .icon = entry.icon, .name = entry.name, .location = entry.path }) catch return error.NotInAllowList;
        if (ra.opts.path) |path| {
            if (entry.try_exec.len > 0 and xdg.findProgram(a, entry.try_exec, path) == null) return error.FileNotFound;
            if (xdg.findProgram(a, expanded[0], path) == null) return error.FileNotFound;
        }
        if (workdir == null and entry.working_dir.len > 0 and entry.working_dir[0] == '/' and xdg.isDir(a, entry.working_dir)) workdir = entry.working_dir;
        try argv.appendSlice(a, ra.opts.launcher);
        if (entry.terminal) {
            try ra.checkPrograms(a, ra.opts.terminal);
            try argv.appendSlice(a, ra.opts.terminal);
        }
        try argv.appendSlice(a, expanded);
        return shellCommand(a, workdir, argv.items);
    }

    fn checkPrograms(ra: *RemoteApp, a: Allocator, argv: []const []const u8) ExecError!void {
        const path = ra.opts.path orelse return;
        if (argv.len > 0 and xdg.findProgram(a, argv[0], path) == null) return error.FileNotFound;
    }
};

fn near(a: Rect, b: Rect) bool {
    const d = struct {
        fn f(x: i32, y: i32) bool {
            return @abs(@as(i64, x) - y) <= 1;
        }
    }.f;
    return d(a.x, b.x) and d(a.y, b.y) and d(a.width, b.width) and d(a.height, b.height);
}

fn clampI16(v: i32) i16 {
    return @intCast(std.math.clamp(v, std.math.minInt(i16), std.math.maxInt(i16)));
}

fn clampU16(v: i64) u16 {
    return @intCast(std.math.clamp(v, 0, std.math.maxInt(u16)));
}

fn rects(a: Allocator, r: Rect) error{OutOfMemory}![]const rail.Rect16 {
    if (r.width <= 0 or r.height <= 0) return &.{};
    const out = try a.alloc(rail.Rect16, 1);
    out[0] = .{ .left = 0, .top = 0, .right = clampU16(r.width), .bottom = clampU16(r.height) };
    return out;
}

fn appKey(w: *const Window) u64 {
    const class = if (w.class.len > 0) w.class else w.initial_class;
    if (class.len == 0) return 0;
    return std.hash.Wyhash.hash(0, class) | 1;
}

/// At most `max_bytes`, never splitting a surrogate pair; invalid UTF-8 (X11 titles) becomes U+FFFD.
pub fn toUtf16(a: Allocator, s: []const u8, max_bytes: usize) error{OutOfMemory}![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) {
        var cp: u21 = 0xFFFD;
        var n: usize = 1;
        if (std.unicode.utf8ByteSequenceLength(s[i])) |len| {
            if (i + len <= s.len) {
                if (std.unicode.utf8Decode(s[i .. i + len])) |v| {
                    cp = v;
                    n = len;
                } else |_| {}
            }
        } else |_| {}
        i += n;
        var units: [2]u16 = undefined;
        const k: usize = if (cp >= 0x10000) blk: {
            const v = cp - 0x10000;
            units = .{ @intCast(0xD800 + (v >> 10)), @intCast(0xDC00 + (v & 0x3FF)) };
            break :blk 2;
        } else blk: {
            units[0] = @intCast(cp);
            break :blk 1;
        };
        if (out.items.len + 2 * k > max_bytes) break;
        for (units[0..k]) |u| {
            try out.append(a, @truncate(u));
            try out.append(a, @truncate(u >> 8));
        }
    }
    return out.items;
}

/// TitleInfo: at most 520 bytes (2.2.1.3.1.2.1).
pub fn titleUtf16(a: Allocator, s: []const u8) error{OutOfMemory}![]u8 {
    return toUtf16(a, s, rail.max_title_len);
}

/// Strict: an odd length or unpaired surrogate is error.DecodeFailed (RAIL_EXEC_E_DECODE_FAILED).
pub fn fromUtf16(a: Allocator, b: []const u8) error{ OutOfMemory, DecodeFailed }![]u8 {
    if (b.len % 2 != 0) return error.DecodeFailed;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < b.len) : (i += 2) {
        const u = std.mem.readInt(u16, b[i..][0..2], .little);
        var cp: u21 = u;
        if (u >= 0xD800 and u <= 0xDBFF) {
            if (i + 4 > b.len) return error.DecodeFailed;
            const lo = std.mem.readInt(u16, b[i + 2 ..][0..2], .little);
            if (lo < 0xDC00 or lo > 0xDFFF) return error.DecodeFailed;
            cp = 0x10000 + ((@as(u21, u) - 0xD800) << 10) + (lo - 0xDC00);
            i += 2;
        } else if (u >= 0xDC00 and u <= 0xDFFF) return error.DecodeFailed;
        if (cp == 0) return error.DecodeFailed;
        var tmp: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(cp, &tmp) catch return error.DecodeFailed;
        try out.appendSlice(a, tmp[0..n]);
    }
    return out.items;
}

fn hasControl(s: []const u8) bool {
    for (s) |ch| if (ch < 0x20 or ch == 0x7f) return true;
    return false;
}

fn fileExists(a: Allocator, path: []const u8) bool {
    const z = a.dupeSentinel(u8, path, 0) catch return false;
    return std.c.access(z.ptr, std.c.F_OK) == 0;
}

/// An existing absolute directory outside omastation's own mounts; Windows paths are ignored.
fn posixDir(a: Allocator, d: []const u8, own: ?[]const u8) ?[]const u8 {
    if (d.len == 0 or d[0] != '/' or hasControl(d)) return null;
    if (intoOwnMounts(d, own)) return null;
    return if (xdg.isDir(a, d)) d else null;
}

/// Checked without touching the mounts.
fn intoOwnMounts(path: []const u8, own: ?[]const u8) bool {
    const root = own orelse return false;
    if (!clipboard.leadsInto(path, root)) return false;
    log.warn("Execute: not looking at a path in omastation's own mounts", .{});
    return true;
}

/// As CommandLineToArgvW: 2n backslashes before a quote are n and the quote toggles, 2n+1 are n
/// and a literal quote; other backslashes are literal.
pub fn splitArguments(a: Allocator, s: []const u8) error{ OutOfMemory, BadArguments }![]const []const u8 {
    var words: std.ArrayList([]const u8) = .empty;
    var cur: std.ArrayList(u8) = .empty;
    var in_word = false;
    var quoted = false;
    var i: usize = 0;
    while (i < s.len) {
        const ch = s[i];
        if (!quoted and (ch == ' ' or ch == '\t')) {
            if (in_word) {
                try words.append(a, cur.items);
                cur = .empty;
                in_word = false;
            }
            i += 1;
            continue;
        }
        in_word = true;
        if (ch == '\\') {
            var n: usize = 0;
            while (i < s.len and s[i] == '\\') : (i += 1) n += 1;
            if (i < s.len and s[i] == '"') {
                try cur.appendNTimes(a, '\\', n / 2);
                if (n % 2 == 1) {
                    try cur.append(a, '"');
                    i += 1;
                }
            } else try cur.appendNTimes(a, '\\', n);
            continue;
        }
        if (ch == '"') {
            quoted = !quoted;
            i += 1;
            continue;
        }
        try cur.append(a, ch);
        i += 1;
    }
    if (quoted) return error.BadArguments;
    if (in_word) try words.append(a, cur.items);
    if (words.items.len > 64) return error.BadArguments;
    return words.items;
}

/// `cd '<dir>' && exec 'argv0' 'argv1' ...`: every word single-quoted.
pub fn shellCommand(a: Allocator, workdir: ?[]const u8, argv: []const []const u8) error{OutOfMemory}![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    if (workdir) |d| {
        try out.appendSlice(a, "cd ");
        try out.appendSlice(a, try xdg.shellQuote(a, d));
        try out.appendSlice(a, " && ");
    }
    try out.appendSlice(a, "exec");
    for (argv) |w| {
        try out.append(a, ' ');
        try out.appendSlice(a, try xdg.shellQuote(a, w));
    }
    return out.items;
}

/// `eval hl.exec_cmd("<cmd>")` with the command as a Lua string literal.
pub fn formatExecCmd(a: Allocator, cmd: []const u8) error{ OutOfMemory, NoSpaceLeft }![]const u8 {
    const lit = try a.alloc(u8, cmd.len * 4 + 2);
    const q = try hypr.luaString(lit, cmd);
    return std.fmt.allocPrint(a, "eval hl.exec_cmd({s})", .{q});
}

test "UTF-16 titles are cut whole and invalid UTF-8 becomes U+FFFD" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualSlices(u8, &.{ 'a', 0, 0xFD, 0xFF, 'b', 0 }, try toUtf16(a, "a\xffb", 100));
    // U+1F600 is a surrogate pair: it does not fit in 2 bytes.
    try std.testing.expectEqualSlices(u8, &.{ 'x', 0 }, try toUtf16(a, "x\u{1F600}", 4));
    try std.testing.expectEqualStrings("x\u{1F600}", try fromUtf16(a, &.{ 'x', 0, 0x3D, 0xD8, 0x00, 0xDE }));
    try std.testing.expectError(error.DecodeFailed, fromUtf16(a, &.{ 0x3D, 0xD8 }));
    const w = try splitArguments(a, "a \"b c\" d\\\"e \\\\\\\\\"f g\"");
    try std.testing.expectEqual(@as(usize, 4), w.len);
    try std.testing.expectEqualStrings("b c", w[1]);
    try std.testing.expectEqualStrings("d\"e", w[2]);
    try std.testing.expectEqualStrings("\\\\f g", w[3]);
}
