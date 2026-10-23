//! Client drive redirection (MS-RDPEFS) on the rdpdr static channel: each accepted
//! drive is a FUSE file system under $XDG_RUNTIME_DIR. Desktop sessions with an NLA
//! user only; a protocol error (3.1.5.2) ends redirection, not the connection.

const std = @import("std");
const c = @import("c");
const rdpdr = @import("../channel/rdpdr.zig");
const drives_mod = @import("../drives/drives.zig");
const fuse = drives_mod.fuse;
const vc = @import("vc.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.drives);

/// Tests only: replaces the kernel; `make` and `free` run on the connection's thread.
pub const TestBackend = struct {
    ctx: ?*anyopaque = null,
    make: *const fn (ctx: ?*anyopaque, conn: *Conn) anyerror!drives_mod.Backend,
    free: *const fn (ctx: ?*anyopaque, b: drives_mod.Backend) void,
};

/// ClientId of the Server Announce Request, unique per connection (3.3.5.1.2).
var next_client_id = std.atomic.Value(u32).init(1);

/// Wake-up period while the kernel side waits on time (busy unmount, reaping).
const busy_period_ms = 100;

pub const Rdpdr = struct {
    pub const static_channels = [_][]const u8{rdpdr.channel_name};

    conn: *Conn,
    session: rdpdr.Session,
    out: rdpdr.Outbox,
    /// Set up in start (they hold pointers into this struct).
    kernel: ?*fuse.Kernel = null,
    test_backend: ?TestBackend = null,
    backend: ?drives_mod.Backend = null,
    drives: ?drives_mod.Drives = null,
    config: drives_mod.Config,
    ch: ?vc.Channel = null,
    /// The client broke the protocol: the channel is ignored.
    broken: bool = false,
    next_ms: i64 = 0,

    pub fn init(c_: *Conn) vc.Error!?Rdpdr {
        const o = &c_.vc.opts;
        if (!o.drives) return null;
        if (c_.user == null) return null;
        if (c_.desktop == null and o.drives_test_backend == null) return null;
        if (!declared(c_)) return null;
        const rd = o.drives_runtime_dir orelse {
            // main.zig warns once at start.
            log.debug("{s}: no XDG_RUNTIME_DIR: client drives are not redirected", .{c_.peer});
            return null;
        };
        const id = next_client_id.fetchAdd(1, .monotonic);
        const session = rdpdr.Session.init(c_.gpa, .{ .client_id = id }) catch return error.OutOfMemory;
        return .{
            .conn = c_,
            .session = session,
            .out = rdpdr.Outbox.init(c_.gpa),
            .test_backend = o.drives_test_backend,
            .config = .{
                .runtime_dir = rd,
                .link_dir = o.drives_link_dir,
                .uid = c.getuid(),
                .gid = c.getgid(),
                .read_only = o.drives_read_only,
            },
        };
    }

    /// The client declared the rdpdr static channel (Client Network Data).
    fn declared(c_: *const Conn) bool {
        for (c_.client.channelSlice()) |ch| {
            if (std.ascii.eqlIgnoreCase(ch.nameSlice(), rdpdr.channel_name)) return true;
        }
        return false;
    }

    pub fn start(self: *Rdpdr) vc.Error!void {
        const gpa = self.conn.gpa;
        const b: drives_mod.Backend = if (self.test_backend) |tb|
            tb.make(tb.ctx, self.conn) catch |e| {
                log.warn("{s}: drive backend: {t}", .{ self.conn.peer, e });
                self.broken = true;
                return;
            }
        else blk: {
            const k = try gpa.create(fuse.Kernel);
            k.* = fuse.Kernel.init(gpa) catch |e| {
                gpa.destroy(k);
                log.warn("{s}: client drives off: {t}", .{ self.conn.peer, e });
                self.broken = true;
                return;
            };
            self.kernel = k;
            break :blk k.backend();
        };
        self.backend = b;
        self.drives = drives_mod.Drives.init(gpa, &self.session, &self.out, b, self.config);
    }

    pub fn deinit(self: *Rdpdr) void {
        // Pending requests fail with EIO, the drives unmount; nothing is sent.
        if (self.drives) |*d| d.deinit();
        if (self.kernel) |k| {
            k.deinit();
            self.conn.gpa.destroy(k);
        }
        if (self.test_backend) |tb| if (self.backend) |b| tb.free(tb.ctx, b);
        self.session.deinit();
        self.out.deinit();
    }

    /// 3.1.3 step 1: the Server Announce Request once the channel is joined.
    pub fn open(self: *Rdpdr, ch: vc.Channel) vc.Error!void {
        self.ch = ch;
        if (self.broken) return;
        self.session.start(&self.out) catch |e| return self.fail(e);
        try self.flush();
    }

    pub fn data(self: *Rdpdr, _: vc.Channel, msg: []const u8) vc.Error!void {
        if (self.broken) return;
        const events = self.session.receive(msg, &self.out) catch |e| {
            // PacketId and size only: names and paths are the user's.
            if (msg.len >= 4) log.warn("{s}: rdpdr: {t} in PDU 0x{x:0>4} of {d} bytes", .{ self.conn.peer, e, std.mem.readInt(u16, msg[2..4], .little), msg.len });
            return self.fail(e);
        };
        if (self.drives) |*d| d.handleEvents(events);
        try self.flush();
    }

    pub fn pollFd(self: *Rdpdr) ?vc.Poll {
        if (self.broken) return null;
        const d = if (self.drives) |*d| d else return null;
        const fd = d.pollFd();
        return if (fd >= 0) .{ .fd = fd } else null;
    }

    pub fn onFd(self: *Rdpdr, _: c_short) vc.Error!void {
        const d = if (self.drives) |*d| d else return;
        d.dispatch();
        try self.flush();
    }

    pub fn tick(self: *Rdpdr, now_ms: i64) vc.Error!?i64 {
        const d = if (self.drives) |*d| d else return null;
        const busy = if (self.kernel) |k| k.busy() else d.count() > 0;
        if (!busy) return null;
        if (now_ms >= self.next_ms) {
            d.dispatch();
            try self.flush();
            self.next_ms = now_ms + busy_period_ms;
        }
        return self.next_ms;
    }

    fn flush(self: *Rdpdr) vc.Error!void {
        const ch = self.ch orelse return;
        defer self.out.clear();
        for (self.out.items()) |m| try ch.send(m);
    }

    /// 3.1.5.2: drive redirection ends for this connection; the channel is ignored.
    fn fail(self: *Rdpdr, e: rdpdr.Error) vc.Error!void {
        log.warn("{s}: rdpdr: {t}; client drives are no longer served", .{ self.conn.peer, e });
        self.broken = true;
        self.out.clear();
        const events = self.session.reset() catch &.{};
        if (self.drives) |*d| {
            d.handleEvents(events);
            d.shutdown();
        }
        self.out.clear();
    }

    /// Accepted drives (tests, diagnostics).
    pub fn driveCount(self: *const Rdpdr) usize {
        return if (self.drives) |*d| d.count() else 0;
    }
};
