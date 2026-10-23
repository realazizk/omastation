//! `omastation helper`: the root process owning the input fence and, while fenced, the uinput
//! touch and pen devices (helper_proto.zig). One client of `allow_uid`; a disconnect releases all.

const std = @import("std");
const c = @import("c");
const fence_daemon = @import("fence_daemon.zig");
const proto = @import("helper_proto.zig");
const uinput = @import("uinput.zig");

const log = std.log.scoped(.helper);

pub const Options = struct {
    socket_path: [:0]const u8 = "/run/omastation/helper.sock",
    allow_uid: u32,
    /// Null: EVIOCGRAB and /dev/uinput.
    backend: ?Backend = null,
};

/// Contact frames applied per second per client.
pub const frame_per_s = 1000;
pub const frame_burst = 200;
/// Device creations per second; the burst covers every output's touchscreen and pen.
pub const open_per_s = 1;
pub const open_burst = 2 * uinput.max_devices;

/// The desk's fence and the uinput devices; handles are chosen by the backend.
pub const Backend = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        engage: *const fn (ctx: *anyopaque) void,
        release: *const fn (ctx: *anyopaque) void,
        fenced: *const fn (ctx: *anyopaque) bool,
        /// Devices with a key held are released once the key is up. Null: `release`.
        unfence: ?*const fn (ctx: *anyopaque, now_ms: i64) void = null,
        create: *const fn (ctx: *anyopaque, spec: *const uinput.Spec) uinput.Error!u32,
        write: *const fn (ctx: *anyopaque, handle: u32, events: []const uinput.Event) uinput.Error!void,
        destroy: *const fn (ctx: *anyopaque, handle: u32) void,
    };

    fn engage(b: Backend) void {
        b.vtable.engage(b.ctx);
    }
    fn release(b: Backend) void {
        b.vtable.release(b.ctx);
    }
    fn fenced(b: Backend) bool {
        return b.vtable.fenced(b.ctx);
    }
    fn unfence(b: Backend, now_ms: i64) void {
        if (b.vtable.unfence) |f| f(b.ctx, now_ms) else b.vtable.release(b.ctx);
    }
};

/// Token bucket counted in thousandths of a token; starts full.
pub const Bucket = struct {
    burst: u32,
    per_s: u32,
    milli: u64,
    last_ms: ?i64 = null,

    pub fn init(burst: u32, per_s: u32) Bucket {
        return .{ .burst = burst, .per_s = per_s, .milli = @as(u64, burst) * 1000 };
    }

    fn refill(b: *Bucket, now_ms: i64) void {
        if (b.last_ms) |last| {
            const elapsed: u64 = @intCast(@max(now_ms - last, 0));
            b.milli = @min(@as(u64, b.burst) * 1000, b.milli +| elapsed *| b.per_s);
        }
        if (b.last_ms == null or now_ms > b.last_ms.?) b.last_ms = now_ms;
    }

    pub fn take(b: *Bucket, now_ms: i64) bool {
        b.refill(now_ms);
        if (b.milli < 1000) return false;
        b.milli -= 1000;
        return true;
    }
};

/// One client's devices and budgets; devices exist only while the desk is fenced.
pub const Session = struct {
    backend: Backend,
    devs: [2][uinput.max_devices]?Dev = .{ @splat(null), @splat(null) },
    frames: Bucket = .init(frame_burst, frame_per_s),
    opens: Bucket = .init(open_burst, open_per_s),
    stats: Stats = .{},

    pub const Stats = struct {
        /// `coalesced`: frames replaced by a newer one while waiting for the budget.
        applied: u64 = 0,
        coalesced: u64 = 0,
        invalid: u64 = 0,
    };

    const Dev = struct {
        handle: u32,
        geometry: uinput.Geometry,
        state: union(uinput.Kind) { touch: uinput.Touch, pen: uinput.Pen },
        staged: [uinput.max_slots]uinput.Contact = undefined,
        staged_len: usize = 0,
        staged_bad: bool = false,
        pending: ?Frame = null,
    };

    const Frame = union(uinput.Kind) {
        touch: struct { contacts: [uinput.max_slots]uinput.Contact, len: usize },
        pen: uinput.PenState,
    };

    pub fn init(backend: Backend) Session {
        return .{ .backend = backend };
    }

    /// `line` excludes the newline; the reply includes it.
    pub fn handleLine(s: *Session, line: []const u8, now_ms: i64) ?[]const u8 {
        const cmd = proto.parse(line) catch |err| switch (err) {
            error.Unknown => return null,
            error.Invalid => {
                if (proto.answers(line)) return "error invalid\n";
                s.stats.invalid += 1;
                return null;
            },
        };
        switch (cmd) {
            .fence => {
                s.backend.engage();
                return "ok\n";
            },
            .unfence => {
                s.closeAll();
                s.backend.unfence(now_ms);
                return "ok\n";
            },
            .status => return if (s.backend.fenced()) "fenced\n" else "unfenced\n",
            .open => |o| return s.open(o, now_ms),
            .close => |o| {
                s.close(o.kind, o.dev);
                return "ok\n";
            },
            .touch => |st| {
                const d = &(s.devs[@backingInt(uinput.Kind.touch)][st.dev] orelse {
                    s.stats.invalid += 1;
                    return null;
                });
                if (d.staged_len == d.staged.len) {
                    d.staged_bad = true;
                } else {
                    d.staged[d.staged_len] = st.contact;
                    d.staged_len += 1;
                }
                return null;
            },
            .touch_frame => |dev| {
                const d = &(s.devs[@backingInt(uinput.Kind.touch)][dev] orelse {
                    s.stats.invalid += 1;
                    return null;
                });
                defer {
                    d.staged_len = 0;
                    d.staged_bad = false;
                }
                if (d.staged_bad) {
                    s.stats.invalid += 1;
                    return null;
                }
                var f: Frame = .{ .touch = .{ .contacts = undefined, .len = d.staged_len } };
                @memcpy(f.touch.contacts[0..d.staged_len], d.staged[0..d.staged_len]);
                s.submit(d, f, now_ms);
                return null;
            },
            .pen => |p| {
                const d = &(s.devs[@backingInt(uinput.Kind.pen)][p.dev] orelse {
                    s.stats.invalid += 1;
                    return null;
                });
                s.submit(d, .{ .pen = p.state }, now_ms);
                return null;
            },
        }
    }

    fn open(s: *Session, o: proto.Open, now_ms: i64) []const u8 {
        if (!s.backend.fenced()) return "error unfenced\n";
        const slot = &s.devs[@backingInt(o.kind)][o.dev];
        if (slot.*) |d| if (std.meta.eql(d.geometry, o.geometry)) return "ok\n";
        if (!s.opens.take(now_ms)) return "error busy\n";
        s.close(o.kind, o.dev);
        const sp = uinput.spec(o.kind, o.dev, o.geometry) catch return "error invalid\n";
        const handle = s.backend.vtable.create(s.backend.ctx, &sp) catch |err| {
            log.warn("creating {s} failed: {t}", .{ sp.name(), err });
            return "error device\n";
        };
        slot.* = .{
            .handle = handle,
            .geometry = o.geometry,
            .state = switch (o.kind) {
                .touch => .{ .touch = .init(o.geometry) },
                .pen => .{ .pen = .init(o.geometry) },
            },
        };
        log.info("created {s} ({d}x{d})", .{ sp.name(), o.geometry.width, o.geometry.height });
        return "ok\n";
    }

    fn close(s: *Session, kind: uinput.Kind, dev: u8) void {
        const slot = &s.devs[@backingInt(kind)][dev];
        const d = &(slot.* orelse return);
        var evs: uinput.Events = .{};
        switch (d.state) {
            .touch => |*t| t.liftAll(&evs) catch {},
            .pen => |*p| p.leaveAll(&evs) catch {},
        }
        s.write(d, &evs);
        s.backend.vtable.destroy(s.backend.ctx, d.handle);
        slot.* = null;
    }

    pub fn closeAll(s: *Session) void {
        for (0..uinput.max_devices) |i| {
            s.close(.touch, @intCast(i));
            s.close(.pen, @intCast(i));
        }
    }

    /// Frames carry complete state, so one over budget is replaced by any newer one.
    fn submit(s: *Session, d: *Dev, f: Frame, now_ms: i64) void {
        if (d.pending == null and s.frames.take(now_ms)) return s.apply(d, f);
        if (d.pending != null) s.stats.coalesced += 1;
        d.pending = f;
    }

    fn apply(s: *Session, d: *Dev, f: Frame) void {
        var evs: uinput.Events = .{};
        const ok = switch (f) {
            .touch => |t| d.state.touch.frame(t.contacts[0..t.len], &evs),
            .pen => |p| d.state.pen.frame(p, &evs),
        };
        ok catch {
            s.stats.invalid += 1;
            return;
        };
        s.stats.applied += 1;
        s.write(d, &evs);
    }

    fn write(s: *Session, d: *const Dev, evs: *const uinput.Events) void {
        if (evs.len == 0) return;
        s.backend.vtable.write(s.backend.ctx, d.handle, evs.slice()) catch |err| log.warn("writing input events failed: {t}", .{err});
    }

    pub fn tick(s: *Session, now_ms: i64) void {
        for (&s.devs) |*kind| for (kind) |*slot| {
            const d = &(slot.* orelse continue);
            const f = d.pending orelse continue;
            if (!s.frames.take(now_ms)) return;
            d.pending = null;
            s.apply(d, f);
        };
    }

    pub fn pendingFrames(s: *const Session) usize {
        var n: usize = 0;
        for (s.devs) |kind| for (kind) |slot| {
            if (slot) |d| n += @intFromBool(d.pending != null);
        };
        return n;
    }

    pub fn device(s: *const Session, kind: uinput.Kind, dev: u8) ?u32 {
        const d = s.devs[@backingInt(kind)][dev] orelse return null;
        return d.handle;
    }

    pub fn end(s: *Session) void {
        s.closeAll();
        s.backend.release();
    }
};

/// The fence is told about every uinput device so it never grabs one.
const KernelBackend = struct {
    fence: *fence_daemon.Fence,
    devs: [2 * uinput.max_devices]?uinput.Kernel = @splat(null),

    const vtable: Backend.VTable = .{
        .engage = engage,
        .release = release,
        .fenced = fenced,
        .unfence = unfence,
        .create = create,
        .write = write,
        .destroy = destroy,
    };

    fn backend(k: *KernelBackend) Backend {
        return .{ .ctx = k, .vtable = &vtable };
    }

    fn self(ctx: *anyopaque) *KernelBackend {
        return @ptrCast(@alignCast(ctx));
    }

    fn engage(ctx: *anyopaque) void {
        self(ctx).fence.engage();
    }
    fn release(ctx: *anyopaque) void {
        self(ctx).fence.release();
    }
    fn fenced(ctx: *anyopaque) bool {
        return self(ctx).fence.active;
    }
    fn unfence(ctx: *anyopaque, now_ms: i64) void {
        self(ctx).fence.unfence(now_ms);
    }

    fn create(ctx: *anyopaque, spec: *const uinput.Spec) uinput.Error!u32 {
        const k = self(ctx);
        const i = for (k.devs, 0..) |d, i| {
            if (d == null) break i;
        } else return error.DeviceFailed;
        var dev = try uinput.Kernel.create(spec);
        k.fence.exempt(dev.input) catch {
            dev.destroy();
            return error.DeviceFailed;
        };
        k.devs[i] = dev;
        return @intCast(i);
    }

    fn write(ctx: *anyopaque, handle: u32, events: []const uinput.Event) uinput.Error!void {
        const k = self(ctx);
        const d = &(k.devs[handle] orelse return error.WriteFailed);
        try d.write(events);
    }

    fn destroy(ctx: *anyopaque, handle: u32) void {
        const k = self(ctx);
        const d = &(k.devs[handle] orelse return);
        d.destroy();
        k.fence.unexempt(d.input);
        k.devs[handle] = null;
    }
};

fn listenUnix(path: [:0]const u8) !c_int {
    const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM | c.SOCK_CLOEXEC, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer _ = c.close(fd);
    var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
    addr.sun_family = c.AF_UNIX;
    if (path.len >= addr.sun_path.len) return error.PathTooLong;
    @memcpy(addr.sun_path[0..path.len], path);
    _ = c.unlink(path.ptr);
    if (c.bind(fd, .{ .__sockaddr__ = @ptrCast(&addr) }, @sizeOf(c.struct_sockaddr_un)) != 0) return error.BindFailed;
    // Anyone may connect; SO_PEERCRED decides who is served.
    _ = c.chmod(path.ptr, 0o666);
    if (c.listen(fd, 2) != 0) return error.ListenFailed;
    return fd;
}

fn peerUid(fd: c_int) ?u32 {
    var cred: c.struct_ucred = undefined;
    var len: c.socklen_t = @sizeOf(c.struct_ucred);
    if (c.getsockopt(fd, c.SOL_SOCKET, c.SO_PEERCRED, &cred, &len) != 0) return null;
    return cred.uid;
}

fn sendLine(fd: c_int, s: []const u8) bool {
    return c.send(fd, s.ptr, s.len, c.MSG_NOSIGNAL) == @as(isize, @intCast(s.len));
}

/// New devices are grabbed at least this often.
const fence_tick_ms = 50;

pub fn run(o: Options) !void {
    const lfd = try listenUnix(o.socket_path);
    defer _ = c.close(lfd);
    log.info("helper listening on {s} for uid {d}", .{ o.socket_path, o.allow_uid });

    var f = fence_daemon.Fence{};
    defer f.release();
    var kernel = KernelBackend{ .fence = &f };
    const backend = o.backend orelse kernel.backend();
    var session = Session.init(backend);
    defer session.end();
    var client: c_int = -1;
    var lines: proto.LineBuffer = .{};
    var last_activity_ms: i64 = 0;
    var last_tick_ms: i64 = 0;

    while (true) {
        var fds: [3]c.struct_pollfd = .{
            .{ .fd = lfd, .events = c.POLLIN, .revents = 0 },
            .{ .fd = client, .events = c.POLLIN, .revents = 0 },
            .{ .fd = f.inotify_fd, .events = c.POLLIN, .revents = 0 },
        };
        _ = c.poll(&fds, fds.len, fence_tick_ms);
        const now = nowMs();

        if (fds[0].revents & c.POLLIN != 0) {
            const nfd = c.accept4(lfd, .{ .__sockaddr__ = null }, null, c.SOCK_CLOEXEC);
            if (nfd >= 0) {
                if (peerUid(nfd) != o.allow_uid or client >= 0) {
                    log.warn("refusing helper client (uid {?d})", .{peerUid(nfd)});
                    _ = c.close(nfd);
                } else {
                    client = nfd;
                    lines.clear();
                    session = Session.init(backend);
                }
            }
        }

        if (client >= 0 and fds[1].revents != 0) {
            var buf: [4096]u8 = undefined;
            const n = c.recv(client, &buf, buf.len, 0);
            if (n <= 0) {
                // Agent gone: never leave the desk fenced or a finger down.
                if (backend.fenced()) log.warn("session agent disconnected while fenced; releasing", .{});
                session.end();
                _ = c.close(client);
                client = -1;
                continue;
            }
            var in: []const u8 = buf[0..@intCast(n)];
            while (lines.next(&in)) |line| {
                if (session.handleLine(line, now)) |reply| _ = sendLine(client, reply);
            }
        }
        session.tick(now);

        if (f.draining()) f.tickDrain(now);
        if (f.active and (fds[2].revents != 0 or now - last_tick_ms >= fence_tick_ms)) {
            last_tick_ms = now;
            f.tick();
            if (f.drainActivity() and client >= 0) {
                if (now - last_activity_ms > 1000) {
                    last_activity_ms = now;
                    if (f.pressed_on) |i| log.info("a key or button pressed at the desk (event{d})", .{i});
                    _ = sendLine(client, "activity\n");
                }
            }
        }
    }
}

fn nowMs() i64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(i64, ts.tv_sec) * 1000 + @divTrunc(@as(i64, ts.tv_nsec), 1_000_000);
}

test "helper compiles" {
    _ = &run;
    std.testing.refAllDecls(KernelBackend);
}
