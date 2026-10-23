//! Clipboard redirection (MS-RDPECLIP) on the cliprdr static channel. Carries the
//! session Bridge's PDUs and tells it when the session is remote and unlocked.

const std = @import("std");
const vc = @import("vc.zig");
const conn_mod = @import("conn.zig");
const cliprdr = @import("../channel/cliprdr.zig");
const bridge_mod = @import("../session/clipboard.zig");
const Conn = conn_mod.Conn;
const Bridge = bridge_mod.Bridge;

pub const Files = bridge_mod.Files;

const log = std.log.scoped(.clipboard);
const linux = std.os.linux;

/// Most pipes (plus the FUSE fd) the bridge waits on.
const max_pipes = 32;

pub const Clipboard = struct {
    pub const static_channels = [_][]const u8{cliprdr.channel_name};
    /// Any of these ends the connection.
    pub const Error = bridge_mod.Error;

    conn: *Conn,
    bridge: ?*Bridge = null,
    ch: ?vc.Channel = null,
    /// epoll fd over the bridge's pipes, while there are any.
    epfd: c_int = -1,

    pub fn init(cn: *Conn) vc.Error!?Clipboard {
        if (!cn.vc.opts.clipboard) return null;
        for (cn.client.channelSlice()) |ch| {
            if (cliprdr.isChannelName(ch.nameSlice())) return .{ .conn = cn };
        }
        return null;
    }

    pub fn deinit(self: *Clipboard) void {
        if (self.bridge) |b| b.destroy();
        self.bridge = null;
        self.closeEpoll();
    }

    pub fn open(self: *Clipboard, ch: vc.Channel) vc.Error!void {
        if (self.bridge != null) return;
        self.ch = ch;
        const cn = self.conn;
        const client = if (cn.desktop) |d| d.client else null;
        const b = try Bridge.create(cn.gpa, client, .{
            .io = cn.vc.opts.io orelse std.Io.Threaded.global_single_threaded.io(),
            .files = cn.vc.opts.clipboard_files,
        });
        self.bridge = b;
        log.info("{s}: clipboard redirection on {s}", .{ cn.peer, if (client != null) "the desktop" else "no desktop (requests fail)" });
        try b.start();
        try self.sync();
    }

    pub fn data(self: *Clipboard, _: vc.Channel, msg: []const u8) vc.Error!void {
        const b = self.bridge orelse return;
        b.handleMessage(msg) catch |err| {
            if (err == error.Truncated) log.warn("{s}: clipboard PDU with an inconsistent dataLen: dropping the connection (MS-RDPECLIP 3.1.5.1)", .{self.conn.peer});
            return err;
        };
        try self.sync();
    }

    pub fn partial(self: *Clipboard, _: vc.Channel) vc.Error!void {
        const b = self.bridge orelse return;
        b.clientProgress();
    }

    pub fn tick(self: *Clipboard, now_ms: i64) vc.Error!?i64 {
        const b = self.bridge orelse return null;
        try self.sync();
        const t = b.timeoutMs();
        return if (t >= 0) now_ms + t else null;
    }

    pub fn pollFd(self: *Clipboard) ?vc.Poll {
        const b = self.bridge orelse return null;
        var buf: [max_pipes]bridge_mod.PollFd = undefined;
        const pipes = b.pollFds(&buf);
        // Rebuilt every pass: a closed and reused fd number would otherwise go unwatched.
        self.closeEpoll();
        if (pipes.len == 0) return null;
        const ep = std.c.epoll_create1(linux.EPOLL.CLOEXEC);
        if (ep < 0) {
            log.warn("{s}: epoll_create1 failed; clipboard pipes go by timer", .{self.conn.peer});
            return null;
        }
        self.epfd = ep;
        for (pipes) |p| {
            var ev: linux.epoll_event = .{ .events = if (p.write) linux.EPOLL.OUT else linux.EPOLL.IN, .data = .{ .fd = p.fd } };
            _ = std.c.epoll_ctl(ep, linux.EPOLL.CTL_ADD, p.fd, &ev);
        }
        return .{ .fd = ep };
    }

    pub fn onFd(self: *Clipboard, _: c_short) vc.Error!void {
        try self.sync();
    }

    /// Push remote/unlocked state to the bridge, run its work, flush its PDUs.
    fn sync(self: *Clipboard) vc.Error!void {
        const b = self.bridge orelse return;
        const want = if (self.conn.desktop) |d| d.remoteUnlocked() else false;
        if (want != b.isActive()) {
            log.info("{s}: clipboard {s}", .{ self.conn.peer, if (want) "active (remote, unlocked)" else "inactive (locked or not remote)" });
            try b.setActive(want);
        }
        try b.service();
        const ch = self.ch orelse return;
        var it: bridge_mod.Messages = .{ .rest = b.outgoing() };
        while (it.next()) |m| try ch.send(m);
        b.clearOutgoing();
    }

    fn closeEpoll(self: *Clipboard) void {
        if (self.epfd >= 0) _ = std.c.close(self.epfd);
        self.epfd = -1;
    }
};
