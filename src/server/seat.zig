//! The console seat shared by all connection threads: one remote user at a time, a newer
//! connection takes over the live desktop, and a desktop lost to the network lingers for a
//! reconnect (MS-RDPBCGR 1.3.1.5, 5.5) with the desk speakers still muted.

const std = @import("std");
const c = @import("c");
const session_ext = @import("../proto/session_ext.zig");
const desktop_mod = @import("../session/desktop.zig");
const audio = @import("../audio/audio.zig");
const Desktop = desktop_mod.Desktop;

const log = std.log.scoped(.seat);

/// MS-RDPBCGR 2.2.4.2 LogonId and 2.2.10.1.1 SessionId; 1 is the console session on Windows.
pub const session_id: u32 = 1;

/// A connection's handle on the seat; the seat writes to `fd` to kick it out or wake it.
pub const Claim = struct {
    fd: c_int,

    pub fn init() error{SystemResources}!Claim {
        const fd = c.eventfd(0, c.EFD_CLOEXEC | c.EFD_NONBLOCK);
        if (fd < 0) return error.SystemResources;
        return .{ .fd = fd };
    }

    pub fn deinit(cl: *Claim) void {
        _ = c.close(cl.fd);
        cl.fd = -1;
    }

    fn signal(cl: *const Claim) void {
        const one: u64 = 1;
        _ = c.write(cl.fd, &one, @sizeOf(u64));
    }

    pub fn take(cl: *const Claim) bool {
        var v: u64 = 0;
        return c.read(cl.fd, &v, @sizeOf(u64)) == @sizeOf(u64);
    }
};

pub const Wake = Desktop.LingerWake;

pub const DesktopOps = struct {
    /// Waits up to 1 s for `wake_fd`, desk input, `until_ms` or the session's end.
    wait: *const fn (d: *Desktop, wake_fd: c_int, until_ms: i64) Wake = Desktop.waitLingering,
    destroy: *const fn (d: *Desktop) void = Desktop.destroy,
};

/// Desk speakers a connection left muted for the session.
pub const DeskAudio = struct {
    /// Where the mute was made; null for the desktop's own PipeWire.
    backend: ?audio.Backend = null,

    pub fn restore(da: DeskAudio, gpa: std.mem.Allocator) void {
        if (da.backend) |b| return b.deskMute(.restore) catch |e| log.warn("cannot give the desk its speakers back ({t})", .{e});
        const pw = audio.PipeWire.create(gpa, .{}) catch |e| {
            log.warn("cannot reach PipeWire to give the desk its speakers back ({t}); omastation-recover will", .{e});
            return;
        };
        defer pw.destroy();
        pw.backend().deskMute(.restore) catch |e| log.warn("cannot give the desk its speakers back ({t}); omastation-recover will", .{e});
    }
};

pub const Seat = struct {
    mutex: std.atomic.Mutex = .unlocked,
    owner: ?*const Claim = null,
    /// The connection waiting to take over, with its cookie and NLA user.
    waiter: ?*const Claim = null,
    waiter_cookie: Cookie = .none,
    waiter_user: User = .{},
    /// NLA user of the current owner, or of the last one while the desktop lingers.
    session_user: User = .{},
    /// A live desktop parked for the waiter; `parked_resumed` if kept for a reconnect.
    parked: ?*Desktop = null,
    parked_resumed: bool = false,
    arc: ?session_ext.AutoReconnect = null,
    arc_user: [64]u8 = undefined,
    arc_user_len: usize = 0,
    desk_audio: ?DeskAudio = null,
    ops: DesktopOps = .{},

    fn lock(s: *Seat) void {
        while (!s.mutex.tryLock()) std.Thread.yield() catch {};
    }

    fn unlock(s: *Seat) void {
        s.mutex.unlock();
    }

    pub const AcquireError = error{ SeatBusy, Superseded };

    /// Auto-reconnect cookie in Client Info (MS-RDPBCGR 2.2.1.11.1.1.1).
    pub const Cookie = enum(u8) { none, valid, invalid };

    /// An NLA user name (ASCII); longer names never match.
    pub const User = struct {
        buf: [64]u8 = undefined,
        len: ?u8 = null,

        pub fn of(name: ?[]const u8) User {
            const n = name orelse return .{};
            var u: User = .{};
            if (n.len > u.buf.len) return u;
            @memcpy(u.buf[0..n.len], n);
            u.len = @intCast(n.len);
            return u;
        }

        fn get(u: *const User) ?[]const u8 {
            return u.buf[0 .. u.len orelse return null];
        }

        /// ASCII case-insensitive, as `verifyArc` compares.
        pub fn same(a: *const User, b: *const User) bool {
            const x = a.get() orelse return false;
            const y = b.get() orelse return false;
            return std.ascii.eqlIgnoreCase(x, y);
        }
    };

    /// Returns the live desktop to adopt, or null to create one; a newer waiter supersedes this one.
    pub fn acquire(s: *Seat, cl: *const Claim, timeout_ms: i32) AcquireError!?*Desktop {
        return (try s.acquireWith(cl, timeout_ms, .{})).desktop;
    }

    pub const AcquireOptions = struct {
        cookie: Cookie = .none,
        user: ?[]const u8 = null,
    };

    pub const Acquired = struct {
        desktop: ?*Desktop = null,
        /// Kept for a reconnect and returned unchanged.
        resumed: bool = false,
    };

    /// A desktop kept for a reconnect is resumed unchanged only if `resumes` allows.
    pub fn acquireWith(s: *Seat, cl: *const Claim, timeout_ms: i32, opts: AcquireOptions) AcquireError!Acquired {
        const user = User.of(opts.user);
        s.lock();
        // A newer connection supersedes any waiter, even one promised a parked desktop.
        if (s.waiter) |old| old.signal();
        s.waiter = cl;
        s.waiter_cookie = opts.cookie;
        s.waiter_user = user;
        if (s.takeFree(cl)) |got| return got;
        s.owner.?.signal(); // kick the owner
        s.unlock();
        log.info("a new connection is taking the session over", .{});

        var waited: i32 = 0;
        while (waited < timeout_ms) : (waited += 50) {
            var pfd: c.struct_pollfd = .{ .fd = cl.fd, .events = c.POLLIN, .revents = 0 };
            _ = c.poll(&pfd, 1, 50);
            _ = cl.take();
            s.lock();
            if (s.waiter != cl) {
                s.unlock();
                return error.Superseded;
            }
            if (s.takeFree(cl)) |got| return got;
            s.unlock();
        }
        // The owner may have handed over since the last look; a parked desktop needs an owner.
        s.lock();
        if (s.waiter == cl) {
            if (s.takeFree(cl)) |got| return got;
            s.clearWaiter();
        }
        s.unlock();
        return error.SeatBusy;
    }

    /// Lock held, `cl` the waiter: if the seat is free, makes `cl` the owner and unlocks.
    fn takeFree(s: *Seat, cl: *const Claim) ?Acquired {
        if (s.owner != null) return null;
        const resumed = s.parked_resumed and s.resumes().yes;
        s.owner = cl;
        s.session_user = s.waiter_user;
        s.clearWaiter();
        const got = Acquired{ .desktop = s.parked, .resumed = resumed };
        s.parked = null;
        s.parked_resumed = false;
        s.unlock();
        return got;
    }

    /// With the lock held.
    fn clearWaiter(s: *Seat) void {
        s.waiter = null;
        s.waiter_cookie = .none;
        s.waiter_user = .{};
    }

    /// Lock held. Without a cookie the session's own NLA user qualifies, as on Windows:
    /// Windows clients reconnecting over NLA send no cookie.
    fn resumes(s: *const Seat) struct { yes: bool, why: []const u8 } {
        return switch (s.waiter_cookie) {
            .valid => .{ .yes = true, .why = "the client reconnected with the session's reconnect cookie" },
            .invalid => .{ .yes = false, .why = "a new connection with a reconnect cookie that is not this session's" },
            .none => if (s.waiter_user.same(&s.session_user))
                .{ .yes = true, .why = "the session's user signed in again (NLA, no reconnect cookie)" }
            else if (s.waiter_user.len == null)
                .{ .yes = false, .why = "a new connection with no NLA user" }
            else
                .{ .yes = false, .why = "another user's connection" },
        };
    }

    /// A connection waits to take over, so the ending owner hands the desktop on.
    pub fn takeoverPending(s: *Seat) bool {
        s.lock();
        defer s.unlock();
        return s.waiter != null;
    }

    /// Keeps the desk mute of a connection that ends while the session goes on.
    pub fn keepDeskAudio(s: *Seat, da: DeskAudio) void {
        s.lock();
        defer s.unlock();
        s.desk_audio = da;
    }

    /// Takes the kept desk mute, if any; the caller adopts or restores it.
    pub fn takeDeskAudio(s: *Seat) ?DeskAudio {
        s.lock();
        defer s.unlock();
        const da = s.desk_audio;
        s.desk_audio = null;
        return da;
    }

    pub fn abandon(s: *Seat, cl: *const Claim) void {
        s.lock();
        defer s.unlock();
        if (s.waiter == cl) s.clearWaiter();
    }

    /// True if the desktop was parked for a waiting connection; else the caller tears it down and calls `done`.
    pub fn handOver(s: *Seat, cl: *const Claim, d: *Desktop) bool {
        s.lock();
        defer s.unlock();
        std.debug.assert(s.owner == cl);
        const w = s.waiter orelse return false;
        // Only a desktop in remote mode is handed on; otherwise the waiter starts afresh.
        if (!d.handable()) return false;
        s.parked = d;
        s.parked_resumed = false;
        s.owner = null;
        w.signal();
        return true;
    }

    pub const Release = enum {
        handed_over,
        /// Kept in remote mode for a reconnect, under a watcher thread.
        lingering,
        /// The caller tears it down (lock, restore), then calls `done`.
        tear_down,
    };

    /// With `linger_ms` the desktop stays in remote mode under a watcher thread that owns the seat.
    /// After .handed_over or .lingering the caller must not touch `d`.
    pub fn release(s: *Seat, gpa: std.mem.Allocator, cl: *const Claim, d: *Desktop, linger_ms: ?u32, now_ms: i64) Release {
        const ms = linger_ms orelse return if (s.handOver(cl, d)) .handed_over else .tear_down;
        const l = gpa.create(Linger) catch return if (s.handOver(cl, d)) .handed_over else .tear_down;
        l.* = .{
            .gpa = gpa,
            .seat = s,
            .d = d,
            .claim = Claim.init() catch {
                gpa.destroy(l);
                return if (s.handOver(cl, d)) .handed_over else .tear_down;
            },
            .until_ms = now_ms + ms,
        };
        s.lock();
        std.debug.assert(s.owner == cl);
        if (s.waiter) |w| if (d.handable()) {
            s.parked = d;
            s.parked_resumed = false;
            s.owner = null;
            w.signal();
            s.unlock();
            l.claim.deinit();
            gpa.destroy(l);
            return .handed_over;
        };
        s.owner = &l.claim;
        s.unlock();
        log.info("connection lost: keeping the remote session for {d} s for a reconnect", .{ms / 1000});
        const th = std.Thread.spawn(.{}, Linger.run, .{l}) catch {
            log.warn("no thread to keep the session: leaving remote mode now", .{});
            l.finish();
            return .lingering;
        };
        th.detach();
        return .lingering;
    }

    pub fn done(s: *Seat, cl: *const Claim) void {
        s.lock();
        defer s.unlock();
        if (s.owner != cl) return;
        s.owner = null;
        if (s.waiter) |w| w.signal();
    }

    /// For the Save Session Info PDU (5.5 step 1); replaces the previous cookie (1.3.1.5).
    pub fn issueArc(s: *Seat, user: []const u8, random_bits: [16]u8) session_ext.ArcScPacket {
        s.lock();
        defer s.unlock();
        s.forgetArc();
        const n = @min(user.len, s.arc_user.len);
        @memcpy(s.arc_user[0..n], user[0..n]);
        s.arc_user_len = n;
        s.arc = session_ext.AutoReconnect.init(session_id, random_bits) catch unreachable;
        return .{ .logon_id = session_id, .arc_random_bits = random_bits };
    }

    /// ARC_CS_PRIVATE_PACKET (2.2.1.11.1.1.1) for NLA user `user`. Malformed cookies are an error.
    pub fn verifyArc(s: *Seat, cookie: []const u8, user: []const u8) session_ext.Error!bool {
        s.lock();
        defer s.unlock();
        const ar = &(s.arc orelse {
            _ = try session_ext.decodeArcCsPacket(cookie); // still reject malformed ones
            return false;
        });
        const user_ok = std.ascii.eqlIgnoreCase(s.arc_user[0..s.arc_user_len], user);
        const ok = try ar.verify(cookie, null);
        if (!ok) return false;
        // Used up (5.5). Another user's session is never resumed.
        std.crypto.secureZero(u8, &ar.arc_random_bits);
        return user_ok;
    }

    fn forgetArc(s: *Seat) void {
        if (s.arc) |*ar| std.crypto.secureZero(u8, &ar.arc_random_bits);
        s.arc = null;
        s.arc_user_len = 0;
    }
};

/// A desktop kept for a reconnect, and the thread watching it.
const Linger = struct {
    gpa: std.mem.Allocator,
    seat: *Seat,
    d: *Desktop,
    /// Owns the seat meanwhile, so a new connection kicks it like any owner.
    claim: Claim,
    until_ms: i64,

    fn run(l: *Linger) void {
        const s = l.seat;
        while (true) {
            switch (s.ops.wait(l.d, l.claim.fd, l.until_ms)) {
                .none => continue,
                .woken => {
                    _ = l.claim.take();
                    s.lock();
                    const w = s.waiter orelse {
                        s.unlock();
                        continue; // a waiter that gave up meanwhile
                    };
                    const r = s.resumes();
                    if (r.yes) {
                        s.parked = l.d;
                        s.parked_resumed = true;
                        s.owner = null;
                        w.signal();
                        s.unlock();
                        log.info("{s}: the session is resumed as it was", .{r.why});
                        l.claim.deinit();
                        l.gpa.destroy(l);
                        return;
                    }
                    s.unlock();
                    log.info("{s}: leaving remote mode first", .{r.why});
                    break;
                },
                .expired => {
                    log.info("nobody reconnected in time: leaving remote mode", .{});
                    break;
                },
                .desk => {
                    log.info("key pressed at the desk while waiting for a reconnect: leaving remote mode", .{});
                    break;
                },
                .lost => {
                    log.warn("the compositor connection broke while waiting for a reconnect", .{});
                    break;
                },
            }
        }
        l.finish();
    }

    fn finish(l: *Linger) void {
        const s = l.seat;
        s.ops.destroy(l.d);
        if (s.takeDeskAudio()) |da| {
            da.restore(l.gpa);
            log.info("the desk's speakers are restored", .{});
        }
        s.done(&l.claim);
        l.claim.deinit();
        l.gpa.destroy(l);
    }
};

test "takeover hands the desktop to the newest connection" {
    var seat = Seat{};
    var a = try Claim.init();
    defer a.deinit();
    var b = try Claim.init();
    defer b.deinit();

    try std.testing.expect(try seat.acquire(&a, 0) == null);
    try std.testing.expectError(error.SeatBusy, seat.acquire(&b, 100));
    try std.testing.expect(a.take());

    var fake: Desktop = undefined;
    fake.entered = true; // in remote mode (Desktop.handable)
    fake.desk_owns = false;
    const T = struct {
        fn run(st: *Seat, owner: *Claim, d: *Desktop) void {
            var pfd: c.struct_pollfd = .{ .fd = owner.fd, .events = c.POLLIN, .revents = 0 };
            _ = c.poll(&pfd, 1, 2000);
            _ = owner.take();
            while (!st.handOver(owner, d)) std.Thread.yield() catch {};
        }
    };
    const th = try std.Thread.spawn(.{}, T.run, .{ &seat, &a, &fake });
    const got = try seat.acquire(&b, 3000);
    th.join();
    try std.testing.expectEqual(@as(?*Desktop, &fake), got);
    try std.testing.expectEqual(@as(?*const Claim, &b), seat.owner);

    try std.testing.expect(!seat.handOver(&b, &fake));
    seat.done(&b);
    try std.testing.expect(seat.owner == null);
}

test "an auto-reconnect cookie verifies once, for its user, and a new one replaces it" {
    var seat = Seat{};
    const bits: [16]u8 = @splat(0x5a);
    const sc = seat.issueArc("alice", bits);
    try std.testing.expectEqual(session_id, sc.logon_id);
    var buf: [28]u8 = undefined;
    var list = std.ArrayList(u8).initBuffer(&buf);
    var w = @import("../core/bytes.zig").Writer.init(&list, std.mem.Allocator.failing);
    try session_ext.encodeArcCsPacket(&w, .{ .logon_id = session_id, .security_verifier = try session_ext.securityVerifier(bits, null) });
    try std.testing.expect(!try seat.verifyArc(&buf, "bob"));
    _ = seat.issueArc("alice", bits);
    try std.testing.expect(try seat.verifyArc(&buf, "ALICE"));
    try std.testing.expect(!try seat.verifyArc(&buf, "alice")); // used up
    _ = seat.issueArc("alice", @splat(0x11));
    try std.testing.expect(!try seat.verifyArc(&buf, "alice")); // replaced
    try std.testing.expectError(error.EndOfBuffer, seat.verifyArc(buf[0..20], "alice"));
}
