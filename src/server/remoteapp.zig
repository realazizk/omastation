//! RemoteApp (MS-RDPERP) for clients that set INFO_RAIL: serves the rail static channel
//! and sends Hyprland's windows as window orders.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const rail = @import("../channel/rail.zig");
const rdp = @import("../proto/rdp.zig");
const caps = @import("../proto/caps.zig");
const hypr = @import("../session/hypr.zig");
const session_ra = @import("../session/remoteapp.zig");
const vc = @import("vc.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.remoteapp);

/// Demand Active capability sets (MS-RDPERP 3.3.5.1.4); icon caches match a Windows server's.
pub const server_caps: caps.RailCaps = .{
    .rail_support_level = rail.rail_level_supported | rail.rail_level_handshake_ex_supported,
    .wnd_support_level = rail.window_level_supported_ex,
    .num_icon_caches = 3,
    .num_icon_cache_entries = 12,
};

/// buildNumber of the server Handshake (MS-RDPERP 3.1.5.1); Windows clients ignore it.
pub const build_number: u32 = 0x4A64;

/// Longest time an Execute waits for the lock screen to unlock.
pub const exec_unlock_wait_ms = 30_000;

pub const max_early_pdus = 16;

/// Whether a connection is a RemoteApp session, decided before the Demand Active.
pub fn wanted(c: *const Conn) bool {
    if (c.info_flags & rdp.info_rail == 0) return false;
    if (!c.vc.opts.remoteapp) return false;
    return ipcOf(c) != null;
}

fn ipcOf(c: *const Conn) ?hypr.Ipc {
    if (c.desktop) |d| return d.ipc;
    return c.vc.opts.remoteapp_ipc;
}

fn railServerCaps() rail.ServerCaps {
    return .{
        .rail = .{ .rail_support_level = server_caps.rail_support_level },
        .window = .{ .wnd_support_level = server_caps.wnd_support_level, .num_icon_caches = server_caps.num_icon_caches, .num_icon_cache_entries = server_caps.num_icon_cache_entries },
    };
}

/// One RAIL PDU per channel message: FreeRDP reads only one PDU per message.
fn sendPdus(ch: vc.Channel, pdus: []const u8) vc.Error!void {
    var off: usize = 0;
    while (off < pdus.len) {
        const h = try rail.decodeHeader(pdus[off..]);
        try ch.send(pdus[off..][0..h.order_length]);
        off += h.order_length;
    }
}

const Pending = struct {
    flags: u16,
    /// ExeOrFile, WorkingDir and Arguments in one allocation.
    buf: []u8,
    exe_len: usize,
    dir_len: usize,
    since_ms: i64,

    fn exec(p: *const Pending) rail.Exec {
        return .{
            .flags = p.flags,
            .exe_or_file = p.buf[0..p.exe_len],
            .working_dir = p.buf[p.exe_len..][0..p.dir_len],
            .arguments = p.buf[p.exe_len + p.dir_len ..],
        };
    }
};

pub const RemoteApp = struct {
    pub const static_channels = [_][]const u8{rail.channel_name};
    pub const Error = rail.Error;

    conn: *Conn,
    srv: rail.Server,
    app: session_ra.RemoteApp,
    batch: session_ra.Batch,
    ch: ?vc.Channel = null,
    synced: bool = false,
    pending: std.ArrayList(Pending) = .empty,
    /// Server-started Local Move/Size, ended by the client's Window Move (MS-RDPERP 3.3.5.2.6.4).
    moving: ?struct { id: u32, kind: u16 } = null,
    /// PDUs before the Handshake, replayed after it (MS-RDPERP 3.1.5.2); Windows clients send it late.
    early: std.ArrayList([]u8) = .empty,
    had_window: bool = false,
    empty_since: ?i64 = null,

    pub fn init(c: *Conn) vc.Error!?RemoteApp {
        if (!c.remoteapp) return null;
        const cc = &c.client_caps;
        const client_rail: ?rail.RailCapabilitySet = if (cc.rail_support_level) |l| .{ .rail_support_level = l } else null;
        const client_window: ?rail.WindowListCapabilitySet = if (cc.window_list) |w| .{ .wnd_support_level = w.wnd_support_level, .num_icon_caches = w.num_icon_caches, .num_icon_cache_entries = w.num_icon_cache_entries } else null;
        // MS-RDPERP 3.3.5.1.5: the server MUST drop the connection.
        const negotiated = rail.negotiate(railServerCaps(), client_rail, client_window) catch |err| {
            log.warn("{s}: RemoteApp: the client's Confirm Active has no usable Remote Programs / Window List capability sets ({t})", .{ c.peer, err });
            return err;
        };
        // No HIDEF or SNAP_ARRANGE: Hyprland has no snap that restores the size.
        const srv = try rail.Server.init(.{
            .build_number = build_number,
            .caps = railServerCaps(),
            .handshake_ex_flags = 0,
            .hidef_supported = false,
            .local_move_size_supported = true,
        }, negotiated, c.info_flags);
        const o = &c.vc.opts;
        log.info("{s}: RemoteApp: rail level 0x{x}, window level {d}, icon caches {d}x{d}", .{ c.peer, negotiated.rail_support_level, negotiated.wnd_support_level, negotiated.num_icon_caches, negotiated.num_icon_cache_entries });
        return .{
            .conn = c,
            .srv = srv,
            .app = session_ra.RemoteApp.init(c.gpa, ipcOf(c).?, .{
                .xdg = o.remoteapp_xdg,
                .launcher = o.remoteapp_launcher,
                .path = o.remoteapp_path,
            }),
            .batch = session_ra.Batch.init(c.gpa),
        };
    }

    pub fn deinit(self: *RemoteApp) void {
        // Restores minimized windows before the desktop is left (vc.deinit runs first).
        self.app.deinit();
        self.batch.deinit();
        for (self.pending.items) |p| self.conn.gpa.free(p.buf);
        self.pending.deinit(self.conn.gpa);
        for (self.early.items) |p| self.conn.gpa.free(p);
        self.early.deinit(self.conn.gpa);
    }

    pub fn start(self: *RemoteApp) vc.Error!void {
        self.app.start() catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => log.warn("{s}: RemoteApp: Hyprland does not answer yet ({t})", .{ self.conn.peer, err }),
        };
    }

    /// Sends the server Handshake (MS-RDPERP 3.1.5.1); desktop sync follows the client's.
    pub fn open(self: *RemoteApp, ch: vc.Channel) vc.Error!void {
        self.ch = ch;
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(self.conn.gpa);
        var w = bytes.Writer.init(&list, self.conn.gpa);
        try self.srv.start(&w);
        try sendPdus(ch, list.items);
    }

    fn applyClient(self: *RemoteApp) vc.Error!void {
        const status = self.srv.client_status orelse 0;
        const sizes = session_ra.iconSizes(status, self.conn.client.scalePercent());
        self.app.setClient(.{
            .wnd_support_level = self.srv.negotiated.wnd_support_level,
            .num_icon_caches = self.srv.negotiated.num_icon_caches,
            .num_icon_cache_entries = self.srv.negotiated.num_icon_cache_entries,
            .icons = try self.srv.sendWindowIcons(),
            .icon_small = sizes.small,
            .icon_big = sizes.big,
        });
    }

    /// Desktop synchronization (MS-RDPERP 3.3.5.1.8).
    fn sync(self: *RemoteApp) vc.Error!void {
        const gpa = self.conn.gpa;
        try self.applyClient();
        _ = self.app.tracker.resync() catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => log.warn("{s}: RemoteApp: no window list from Hyprland ({t})", .{ self.conn.peer, err }),
        };
        self.batch.reset();
        try self.app.desktopSync(&self.batch);
        var orders: std.ArrayList(u8) = .empty;
        defer orders.deinit(gpa);
        var ow = bytes.Writer.init(&orders, gpa);
        try self.srv.desktopSync(&ow, self.batch.orders.items);
        try self.conn.queueOrders(orders.items);
        self.synced = true;
        self.checkLastWindow(conn_mod.nowMs());
        log.info("{s}: RemoteApp: desktop synchronized, {d} window(s)", .{ self.conn.peer, self.app.tracker.model.windows.len });
    }

    pub fn data(self: *RemoteApp, ch: vc.Channel, msg: []const u8) vc.Error!void {
        const gpa = self.conn.gpa;
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        var w = bytes.Writer.init(&list, gpa);
        const had_handshake = self.srv.client_build != null;
        const ev = self.srv.receive(msg, &w) catch |err| switch (err) {
            error.NotNegotiated => {
                log.debug("{s}: RemoteApp: ignoring a PDU of type 0x{x} ({t})", .{ self.conn.peer, std.mem.readInt(u16, msg[0..2], .little), err });
                return;
            },
            error.HandshakeNotReceived => {
                const t = std.mem.readInt(u16, msg[0..2], .little);
                if (self.early.items.len >= max_early_pdus) {
                    log.debug("{s}: RemoteApp: ignoring a PDU of type 0x{x} before the Handshake", .{ self.conn.peer, t });
                    return;
                }
                try self.early.ensureUnusedCapacity(gpa, 1);
                self.early.appendAssumeCapacity(try gpa.dupe(u8, msg));
                log.debug("{s}: RemoteApp: a PDU of type 0x{x} before the Handshake, kept", .{ self.conn.peer, t });
                return;
            },
            else => return err,
        };
        if (!had_handshake and self.srv.client_build != null) {
            // Server System Parameters right after the handshake (MS-RDPERP 1.3.2.4).
            try rail.encode(&w, .{ .sysparam = .{ .param = rail.spi_setscreensaveactive, .value = .{ .boolean = false } } });
            try rail.encode(&w, .{ .sysparam = .{ .param = rail.spi_setscreensavesecure, .value = .{ .boolean = false } } });
            try sendPdus(ch, list.items);
            list.clearRetainingCapacity();
            // FreeRDP sends Client Information only after ARC_COMPLETED.
            try self.sync();
            var early = self.early;
            self.early = .empty;
            defer {
                for (early.items) |p| gpa.free(p);
                early.deinit(gpa);
            }
            for (early.items) |p| try self.data(ch, p);
            return;
        }
        if (list.items.len > 0) try sendPdus(ch, list.items);
        list.clearRetainingCapacity();
        const now = conn_mod.nowMs();
        switch (ev) {
            .ready => {
                try self.applyClient();
                log.info("{s}: RemoteApp: client ready (status 0x{x})", .{ self.conn.peer, self.srv.client_status orelse 0 });
            },
            .exec => |e| try self.queueExec(e, now),
            .activate => |a| _ = self.app.activate(a),
            .syscommand => |cmd| switch (self.app.sysCommand(cmd)) {
                .local_move_size => |l| {
                    self.srv.beginLocalMoveSize(&w, l.info, l.move_size_type, l.pos_x, l.pos_y) catch |err| switch (err) {
                        error.NotNegotiated => return,
                        else => return err,
                    };
                    self.moving = .{ .id = cmd.window_id, .kind = l.move_size_type };
                    try sendPdus(ch, list.items);
                },
                else => {},
            },
            .window_move, .snap_arrange => |m| {
                _ = self.app.windowMove(m);
                if (self.moving) |mv| if (mv.id == m.window_id) {
                    self.moving = null;
                    self.srv.endLocalMoveSize(&w, m.window_id, mv.kind, m.left, m.top) catch |err| switch (err) {
                        error.NotNegotiated => {},
                        else => return err,
                    };
                    try sendPdus(ch, list.items);
                };
            },
            .sysmenu => |m| _ = self.app.sysMenu(m),
            .notify_event => |n| _ = self.app.notifyEvent(n),
            .cloak => |cl| _ = self.app.cloak(cl),
            .get_appid_req => |g| {
                var arena = std.heap.ArenaAllocator.init(gpa);
                defer arena.deinit();
                const resp = (try self.app.appId(arena.allocator(), g.window_id)) orelse return;
                try rail.encode(&w, .{ .get_appid_resp = resp });
                try sendPdus(ch, list.items);
            },
            .sysparam => |p| log.debug("{s}: RemoteApp: client system parameter 0x{x}", .{ self.conn.peer, p.param }),
            else => {},
        }
        try self.pushOrders(now);
    }

    fn pushOrders(self: *RemoteApp, now: i64) vc.Error!void {
        if (!self.synced) return;
        defer self.checkLastWindow(now);
        self.batch.reset();
        if (!try self.app.update(now, &self.batch)) return;
        var orders: std.ArrayList(u8) = .empty;
        defer orders.deinit(self.conn.gpa);
        var w = bytes.Writer.init(&orders, self.conn.gpa);
        try self.batch.encode(&w, self.srv.negotiated.wnd_support_level);
        try self.conn.queueOrders(orders.items);
    }

    /// Ends the session after its last window closes, as a Windows server logs off RemoteApp.
    fn checkLastWindow(self: *RemoteApp, now: i64) void {
        if (!self.synced) return;
        if (self.app.tracker.model.windows.len > 0) {
            self.had_window = true;
            self.empty_since = null;
            return;
        }
        if (!self.had_window) return;
        const end_ms = self.conn.vc.opts.remoteapp_end_ms orelse return;
        const since = self.empty_since orelse {
            self.empty_since = now;
            return;
        };
        if (now - since < end_ms) return;
        if (self.conn.end_errinfo == null) log.info("{s}: RemoteApp: the last window closed {d} ms ago: ending the session", .{ self.conn.peer, now - since });
        self.conn.requestEnd(rdp.errinfo_logoff_by_user);
    }

    fn queueExec(self: *RemoteApp, e: rail.Exec, now: i64) vc.Error!void {
        const gpa = self.conn.gpa;
        const buf = try gpa.alloc(u8, e.exe_or_file.len + e.working_dir.len + e.arguments.len);
        errdefer gpa.free(buf);
        @memcpy(buf[0..e.exe_or_file.len], e.exe_or_file);
        @memcpy(buf[e.exe_or_file.len..][0..e.working_dir.len], e.working_dir);
        @memcpy(buf[e.exe_or_file.len + e.working_dir.len ..], e.arguments);
        try self.pending.append(gpa, .{ .flags = e.flags, .buf = buf, .exe_len = e.exe_or_file.len, .dir_len = e.working_dir.len, .since_ms = now });
        try self.runPending(now);
    }

    /// An app started while unlocking would be refused (RAIL_EXEC_E_SESSION_LOCKED).
    fn unlocking(self: *const RemoteApp) bool {
        if (self.conn.secret != null) return true;
        const d = self.conn.desktop orelse return false;
        return d.unlocking != null;
    }

    fn runPending(self: *RemoteApp, now: i64) vc.Error!void {
        const gpa = self.conn.gpa;
        while (self.pending.items.len > 0) {
            const p = self.pending.items[0];
            if (self.unlocking() and now - p.since_ms < exec_unlock_wait_ms) return;
            _ = self.pending.orderedRemove(0);
            defer gpa.free(p.buf);
            const e = p.exec();
            const r = self.app.exec(e);
            log.info("{s}: RemoteApp: execute: result {d} (raw {d})", .{ self.conn.peer, r.result, r.raw });
            const ch = self.ch orelse continue;
            var list: std.ArrayList(u8) = .empty;
            defer list.deinit(gpa);
            var w = bytes.Writer.init(&list, gpa);
            try self.srv.execResult(&w, e, r.result, r.raw);
            try sendPdus(ch, list.items);
        }
    }

    pub fn tick(self: *RemoteApp, now_ms: i64) vc.Error!?i64 {
        try self.runPending(now_ms);
        if (self.synced) {
            try self.pushOrders(now_ms);
        } else {
            _ = try self.app.tracker.tick(now_ms);
        }
        var next = now_ms + self.app.tracker.opts.resync_ms;
        if (self.pending.items.len > 0) next = @min(next, now_ms + 100);
        if (self.empty_since) |since| next = @min(next, since + (self.conn.vc.opts.remoteapp_end_ms orelse 0));
        return next;
    }

    pub fn pollFd(self: *RemoteApp) ?vc.Poll {
        const fd = self.app.eventsFd();
        if (fd < 0) return null;
        return .{ .fd = fd };
    }

    /// Title and focus changes go out at once, the rest after a resync.
    pub fn onFd(self: *RemoteApp, _: c_short) vc.Error!void {
        try self.app.readEvents();
        try self.pushOrders(conn_mod.nowMs());
    }
};
