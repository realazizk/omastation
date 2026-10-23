//! FUSE side of the drives: libfuse3's low-level API on /dev/fuse, served from the
//! connection's poll loop. fusermount3 mounts without root (auto_unmount, fd passed
//! via _FUSE_COMMFD); no allow_other, so only the session user sees a drive.

const std = @import("std");
const c = @import("c");
const sys = @import("../wl/sys.zig");
const fs = @import("fs.zig");
const drives = @import("drives.zig");

const log = std.log.scoped(.drives);
const Allocator = std.mem.Allocator;

/// struct fuse_file_info (fuse_common.h; translate-c cannot see through
/// its bitfields): the flag bits are one u32 at offset 4.
pub const FileInfo = extern struct {
    flags: i32 = 0,
    bits: u32 = 0,
    padding2: u32 = 0,
    padding3: u32 = 0,
    fh: u64 = 0,
    lock_owner: u64 = 0,
    poll_events: u32 = 0,
    backing_id: i32 = 0,
    compat_flags: u64 = 0,
    reserved: [2]u64 = .{ 0, 0 },

    pub const direct_io: u32 = 1 << 1;
    pub const keep_cache: u32 = 1 << 2;

    comptime {
        std.debug.assert(@sizeOf(FileInfo) == 64);
        std.debug.assert(@offsetOf(FileInfo, "fh") == 16);
    }
};

pub fn mountOptions(read_only: bool) []const u8 {
    return if (read_only)
        "ro,nosuid,nodev,noatime,default_permissions,fsname=omastation,subtype=omastation,auto_unmount"
    else
        "rw,nosuid,nodev,noatime,default_permissions,fsname=omastation,subtype=omastation,auto_unmount";
}

/// Requests served per mount per `dispatch`; the rest wait so the RDP connection is served.
const budget = 64;

/// How long the end of a connection waits for its unmounts.
const settle_ms = 1000;

const fusermount = "/usr/bin/fusermount3";

/// Process-wide mount points: one Kernel holds a mount point at a time, and it is not
/// re-mounted until its unmounting fusermount3 exits (else auto_unmount could detach it).
pub const registry = struct {
    const max_slots = 64;
    const max_path = 512;

    const State = enum { free, live, unmounting };

    const Slot = struct {
        state: State = .free,
        /// The Kernel that has it mounted (live).
        owner: usize = 0,
        /// fusermount3 still running for it (unmounting); 0: none.
        pid: c.pid_t = 0,
        len: u16 = 0,
        path: [max_path]u8 = undefined,

        fn is(s: *const Slot, path: []const u8) bool {
            return s.state != .free and std.mem.eql(u8, s.path[0..s.len], path);
        }
    };

    var mutex: std.atomic.Mutex = .unlocked;
    var slots: [max_slots]Slot = @splat(.{});

    fn lock() void {
        while (!mutex.tryLock()) std.Thread.yield() catch {};
    }

    /// Takes `path` for `owner` unless it is mounted or being unmounted.
    pub fn claim(path: []const u8, owner: usize) bool {
        if (path.len > max_path) return false;
        lock();
        defer mutex.unlock();
        var free: ?*Slot = null;
        for (&slots) |*s| {
            if (s.is(path)) return false;
            if (s.state == .free and free == null) free = s;
        }
        const s = free orelse return false;
        s.* = .{ .state = .live, .owner = owner, .len = @intCast(path.len) };
        @memcpy(s.path[0..path.len], path);
        return true;
    }

    /// `pid` (the unmounting fusermount3, or 0) is reaped later by any Kernel.
    pub fn release(path: []const u8, owner: usize, pid: c.pid_t) void {
        lock();
        defer mutex.unlock();
        for (&slots) |*s| {
            if (!s.is(path) or s.state != .live or s.owner != owner) continue;
            if (pid == 0) {
                s.* = .{};
            } else {
                s.state = .unmounting;
                s.owner = 0;
                s.pid = pid;
            }
            return;
        }
        // Not claimed (a stale mount cleared before mounting): track the pid.
        if (pid == 0) return;
        for (&slots) |*s| if (s.state == .free) {
            s.* = .{ .state = .unmounting, .pid = pid, .len = @intCast(@min(path.len, max_path)) };
            @memcpy(s.path[0..s.len], path[0..s.len]);
            return;
        };
    }

    /// Reaps finished unmount processes and removes their mount points.
    pub fn reap() void {
        lock();
        defer mutex.unlock();
        for (&slots) |*s| {
            if (s.state != .unmounting) continue;
            if (s.pid != 0 and c.waitpid(s.pid, null, c.WNOHANG) == 0) continue;
            var z: [max_path + 1]u8 = undefined;
            @memcpy(z[0..s.len], s.path[0..s.len]);
            z[s.len] = 0;
            _ = c.rmdir(@ptrCast(&z));
            s.* = .{};
        }
    }

    /// Waits up to `timeout_ms` for running unmounts, reaping them (end of a connection).
    pub fn settle(timeout_ms: u32) void {
        var waited: u32 = 0;
        while (true) {
            reap();
            if (unmounting() == 0 or waited >= timeout_ms) return;
            var ts: c.struct_timespec = .{ .tv_sec = 0, .tv_nsec = 10 * std.time.ns_per_ms };
            _ = c.nanosleep(&ts, null);
            waited += 10;
        }
    }

    pub fn unmounting() usize {
        lock();
        defer mutex.unlock();
        var n: usize = 0;
        for (&slots) |*s| n += @intFromBool(s.state == .unmounting);
        return n;
    }

    pub fn busy(path: []const u8) bool {
        lock();
        defer mutex.unlock();
        for (&slots) |*s| if (s.is(path)) return true;
        return false;
    }
};

const Phase = enum {
    /// The mount point is in use (an earlier mount, or its unmount).
    waiting,
    /// fusermount3 started, the /dev/fuse fd not received yet.
    spawning,
    serving,
};

const Mount = struct {
    k: *Kernel,
    id: u32,
    handler: fs.Handler,
    path: [:0]u8,
    read_only: bool,
    notify: drives.Notify,
    phase: Phase = .waiting,
    /// Our end of the fusermount3 socket.
    comm: i32 = -1,
    /// fusermount3: mounting, then the auto_unmount watcher; 0 once gone.
    pid: c.pid_t = 0,
    pidfd: i32 = -1,
    se: ?*c.struct_fuse_session = null,
    fd: i32 = -1,
    buf: c.struct_fuse_buf = .{},
    /// Only a request still open may get an interrupt callback.
    current: usize = 0,
    current_done: bool = false,
    /// Interrupted requests, answered after fuse_session_process_buf.
    interrupts: std.ArrayList(u64) = .empty,
};

const Ev = struct { id: u32, ev: drives.MountEvent, notify: drives.Notify };

/// The mounts of one connection, served on its thread.
pub const Kernel = struct {
    gpa: Allocator,
    epfd: i32,
    mounts: std.ArrayList(*Mount) = .empty,
    events: std.ArrayList(Ev) = .empty,

    pub fn init(gpa: Allocator) !Kernel {
        const ep = c.epoll_create1(c.EPOLL_CLOEXEC);
        if (ep < 0) return error.EpollFailed;
        registry.reap();
        return .{ .gpa = gpa, .epfd = ep };
    }

    /// Unmounts everything lazily, then briefly waits to reap the fusermount3 processes.
    pub fn deinit(k: *Kernel) void {
        while (k.mounts.items.len > 0) k.unmountOne(k.mounts.items[k.mounts.items.len - 1]);
        registry.settle(settle_ms);
        k.mounts.deinit(k.gpa);
        k.events.deinit(k.gpa);
        _ = c.close(k.epfd);
    }

    pub fn backend(k: *Kernel) drives.Backend {
        return .{ .ptr = k, .vtable = &vtable };
    }

    /// Waiting on time, not the fd (a mount point in use, fusermount3 to reap).
    pub fn busy(k: *const Kernel) bool {
        for (k.mounts.items) |m| if (m.phase == .waiting) return true;
        return registry.unmounting() > 0;
    }

    const vtable: drives.Backend.VTable = .{
        .mount = mountFn,
        .unmount = unmountFn,
        .fd = fdFn,
        .dispatch = dispatchFn,
    };

    fn mountFn(ptr: *anyopaque, args: drives.MountArgs) anyerror!void {
        const k: *Kernel = @ptrCast(@alignCast(ptr));
        const m = try k.gpa.create(Mount);
        errdefer k.gpa.destroy(m);
        const path = try k.gpa.dupeSentinel(u8, args.path, 0);
        errdefer k.gpa.free(path);
        m.* = .{ .k = k, .id = args.id, .handler = args.handler, .path = path, .read_only = args.read_only, .notify = args.notify };
        try k.mounts.append(k.gpa, m);
        // A dead mount from a crash is in the way: detach it first.
        if (args.stale and !registry.busy(path)) {
            if (spawnUnmount(path)) |pid| registry.release(path, 0, pid);
        }
        k.advance(m);
    }

    fn unmountFn(ptr: *anyopaque, id: u32) void {
        const k: *Kernel = @ptrCast(@alignCast(ptr));
        for (k.mounts.items) |m| if (m.id == id) return k.unmountOne(m);
    }

    fn fdFn(ptr: *anyopaque) i32 {
        const k: *Kernel = @ptrCast(@alignCast(ptr));
        return k.epfd;
    }

    fn dispatchFn(ptr: *anyopaque) void {
        const k: *Kernel = @ptrCast(@alignCast(ptr));
        k.dispatch();
    }

    pub fn dispatch(k: *Kernel) void {
        // Readiness is taken from each fd below; this only refreshes the set.
        var evs: [16]c.struct_epoll_event = undefined;
        _ = c.epoll_wait(k.epfd, &evs, evs.len, 0);
        registry.reap();
        var i: usize = 0;
        while (i < k.mounts.items.len) : (i += 1) k.advance(k.mounts.items[i]);
        // Reported after the walk: a handler may unmount.
        while (k.events.items.len > 0) {
            const e = k.events.orderedRemove(0);
            e.notify.f(e.notify.ctx, e.id, e.ev);
        }
    }

    fn report(k: *Kernel, m: *Mount, ev: drives.MountEvent) void {
        k.events.append(k.gpa, .{ .id = m.id, .ev = ev, .notify = m.notify }) catch {};
    }

    fn advance(k: *Kernel, m: *Mount) void {
        switch (m.phase) {
            .waiting => if (registry.claim(m.path, @intFromPtr(k))) k.spawnMount(m),
            .spawning => k.receiveFd(m),
            .serving => k.serve(m),
        }
    }

    fn spawn(argv: []const ?[*:0]const u8, envp: []const ?[*:0]const u8) !c.pid_t {
        // No signal blocked in the child: exec keeps the mask and threads block SIGUSR1.
        var attr: c.posix_spawnattr_t = undefined;
        if (c.posix_spawnattr_init(&attr) != 0) return error.SpawnFailed;
        defer _ = c.posix_spawnattr_destroy(&attr);
        var no_signals: c.sigset_t = undefined;
        _ = c.sigemptyset(&no_signals);
        if (c.posix_spawnattr_setflags(&attr, c.POSIX_SPAWN_SETSIGMASK) != 0 or
            c.posix_spawnattr_setsigmask(&attr, &no_signals) != 0) return error.SpawnFailed;
        var pid: c.pid_t = 0;
        const rc = c.posix_spawn(&pid, fusermount, null, &attr, @ptrCast(@constCast(argv.ptr)), @ptrCast(@constCast(envp.ptr)));
        if (rc == 0) return pid;
        if (c.posix_spawnp(&pid, "fusermount3", null, &attr, @ptrCast(@constCast(argv.ptr)), @ptrCast(@constCast(envp.ptr))) == 0) return pid;
        return error.SpawnFailed;
    }

    fn spawnMount(k: *Kernel, m: *Mount) void {
        k.startMount(m) catch |e| {
            log.warn("drive {s}: cannot run {s}: {t}", .{ m.path, fusermount, e });
            registry.release(m.path, @intFromPtr(k), 0);
            m.phase = .waiting;
            k.report(m, .failed);
            return;
        };
        m.phase = .spawning;
    }

    fn startMount(k: *Kernel, m: *Mount) !void {
        // An unmount that ended may have removed the directory.
        _ = c.mkdir(m.path.ptr, 0o700);
        var sv: [2]c_int = undefined;
        if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM | c.SOCK_CLOEXEC, 0, &sv) != 0) return error.SocketFailed;
        // The child's end must survive exec.
        if (c.fcntl(sv[1], c.F_SETFD, @as(c_int, 0)) != 0) {
            _ = c.close(sv[0]);
            _ = c.close(sv[1]);
            return error.SocketFailed;
        }
        defer _ = c.close(sv[1]);
        errdefer _ = c.close(sv[0]);
        var env_buf: [32]u8 = undefined;
        const env = try std.fmt.bufPrintSentinel(&env_buf, "_FUSE_COMMFD={d}", .{sv[1]}, 0);
        const opts = try k.gpa.dupeSentinel(u8, mountOptions(m.read_only), 0);
        defer k.gpa.free(opts);
        const argv = [_:null]?[*:0]const u8{ "fusermount3", "-o", opts.ptr, "--", m.path.ptr };
        const envp = [_:null]?[*:0]const u8{env.ptr};
        const pid = try spawn(&argv, &envp);
        m.pid = pid;
        m.comm = sv[0];
        m.pidfd = c.pidfd_open(pid, 0);
        k.watch(m.comm);
        if (m.pidfd >= 0) k.watch(m.pidfd);
    }

    /// `fusermount3 -u -z -q -- path`; null if it cannot run.
    fn spawnUnmount(path: [:0]const u8) ?c.pid_t {
        const argv = [_:null]?[*:0]const u8{ "fusermount3", "-u", "-z", "-q", "--", path.ptr };
        const envp = [_:null]?[*:0]const u8{};
        return spawn(&argv, &envp) catch |e| {
            log.warn("{s}: cannot run {s} -u: {t}", .{ path, fusermount, e });
            return null;
        };
    }

    fn watch(k: *Kernel, fd: i32) void {
        var ev: c.struct_epoll_event = .{ .events = c.EPOLLIN, .data = .{ .fd = fd } };
        _ = c.epoll_ctl(k.epfd, c.EPOLL_CTL_ADD, fd, &ev);
    }

    fn unwatch(k: *Kernel, fd: i32) void {
        _ = c.epoll_ctl(k.epfd, c.EPOLL_CTL_DEL, fd, null);
    }

    /// The /dev/fuse fd from fusermount3, or a failure if the socket closes without one.
    fn receiveFd(k: *Kernel, m: *Mount) void {
        var byte: [1]u8 = undefined;
        const got = sys.recvMsg(m.comm, &byte, true) catch |e| switch (e) {
            error.WouldBlock => return,
            else => {
                log.warn("drive {s}: fusermount3 did not mount it", .{m.path});
                k.unwatch(m.comm);
                k.report(m, .failed);
                return;
            },
        };
        if (got.nfds == 0) {
            log.warn("drive {s}: fusermount3 sent no descriptor", .{m.path});
            k.unwatch(m.comm);
            k.report(m, .failed);
            return;
        }
        for (got.fds[1..got.nfds]) |extra| _ = c.close(extra);
        // fusermount3 now waits on the socket (auto_unmount): stop polling it.
        k.unwatch(m.comm);
        k.startSession(m, got.fds[0]) catch |e| {
            log.warn("drive {s}: libfuse: {t}", .{ m.path, e });
            _ = c.close(got.fds[0]);
            k.report(m, .failed);
            return;
        };
        m.phase = .serving;
        k.report(m, .mounted);
    }

    fn startSession(k: *Kernel, m: *Mount, fd: i32) !void {
        var argv0 = "omastation".*;
        var argv = [_:null]?[*:0]u8{&argv0};
        var args: c.struct_fuse_args = .{ .argc = 1, .argv = @ptrCast(&argv), .allocated = 0 };
        var version: c.struct_libfuse_version = .{ .major = c.FUSE_MAJOR_VERSION, .minor = c.FUSE_MINOR_VERSION, .hotfix = c.FUSE_HOTFIX_VERSION };
        const se = c.fuse_session_new_versioned(&args, &ops, @sizeOf(c.struct_fuse_lowlevel_ops), &version, m);
        // Option parsing may have copied the arguments.
        c.fuse_opt_free_args(&args);
        if (se == null) return error.SessionFailed;
        errdefer c.fuse_session_destroy(se);
        var name_buf: [32]u8 = undefined;
        const dev = try std.fmt.bufPrintSentinel(&name_buf, "/dev/fd/{d}", .{fd}, 0);
        if (c.fuse_session_mount(se, dev.ptr) != 0) return error.SessionFailed;
        const fl = c.fcntl(fd, c.F_GETFL);
        _ = c.fcntl(fd, c.F_SETFL, fl | c.O_NONBLOCK);
        m.se = se;
        m.fd = fd;
        k.watch(fd);
        m.handler.setReplier(.{ .ptr = m, .vtable = &replier_vtable });
    }

    fn serve(k: *Kernel, m: *Mount) void {
        // The auto_unmount watcher exited: keep serving, unmount with `-u -z` at the end.
        if (m.pid != 0 and c.waitpid(m.pid, null, c.WNOHANG) != 0) {
            m.pid = 0;
            if (m.pidfd >= 0) {
                k.unwatch(m.pidfd);
                _ = c.close(m.pidfd);
            }
            m.pidfd = -1;
        }
        const se = m.se orelse return;
        var n: usize = 0;
        while (n < budget) : (n += 1) {
            const rc = c.fuse_session_receive_buf(se, &m.buf);
            if (rc == -@as(c_int, @intCast(@backingInt(std.os.linux.E.AGAIN)))) return;
            if (rc == -@as(c_int, @intCast(@backingInt(std.os.linux.E.INTR)))) continue;
            if (rc <= 0 or c.fuse_session_exited(se) != 0) {
                // Unmounted from outside, or the connection was aborted.
                k.unwatch(m.fd);
                k.report(m, .gone);
                return;
            }
            c.fuse_session_process_buf(se, &m.buf);
            k.interrupted(m);
        }
    }

    fn interrupted(k: *Kernel, m: *Mount) void {
        _ = k;
        while (m.interrupts.items.len > 0) {
            const r = m.interrupts.orderedRemove(0);
            m.handler.interrupt(r);
        }
    }

    fn unmountOne(k: *Kernel, m: *Mount) void {
        if (std.mem.indexOfScalar(*Mount, k.mounts.items, m)) |i| _ = k.mounts.orderedRemove(i);
        if (m.se) |se| {
            // Every request was answered (Fs.abort); closing /dev/fuse aborts the connection.
            k.unwatch(m.fd);
            m.handler.setReplier(null);
            c.fuse_session_destroy(se);
        }
        if (m.buf.mem) |mem| std.c.free(mem);
        if (m.pidfd >= 0) {
            k.unwatch(m.pidfd);
            _ = c.close(m.pidfd);
        }
        if (m.comm >= 0) {
            k.unwatch(m.comm);
            // auto_unmount: fusermount3 sees the socket close and unmounts lazily.
            _ = c.close(m.comm);
        }
        if (m.phase != .waiting) {
            // Without a watcher (it died, or no auto_unmount), unmount here.
            var pid = m.pid;
            if (pid == 0 and m.phase == .serving) pid = spawnUnmount(m.path) orelse 0;
            registry.release(m.path, @intFromPtr(k), pid);
        }
        m.interrupts.deinit(k.gpa);
        k.gpa.free(m.path);
        k.gpa.destroy(m);
    }
};

// Replies (fs.Replier over fuse_reply_*)

const replier_vtable: fs.Replier.VTable = .{
    .err = replyErr,
    .entry = replyEntry,
    .create = replyCreate,
    .attr = replyAttr,
    .open = replyOpen,
    .data = replyData,
    .written = replyWritten,
    .statfs = replyStatfs,
    .dir = replyDir,
};

fn reqOf(r: fs.Req) c.fuse_req_t {
    return @ptrFromInt(@as(usize, @intCast(r)));
}

fn answered(ptr: *anyopaque, r: fs.Req) void {
    const m: *Mount = @ptrCast(@alignCast(ptr));
    if (m.current == r) m.current_done = true;
}

fn replyErr(ptr: *anyopaque, r: fs.Req, err: u16) void {
    answered(ptr, r);
    _ = c.fuse_reply_err(reqOf(r), err);
}

fn replyEntry(ptr: *anyopaque, r: fs.Req, e: *const fs.Entry) void {
    answered(ptr, r);
    const p = entryParam(e);
    _ = c.fuse_reply_entry(reqOf(r), &p);
}

fn replyCreate(ptr: *anyopaque, r: fs.Req, e: *const fs.Entry, f: fs.FileReply) void {
    answered(ptr, r);
    const p = entryParam(e);
    const fi = fileInfo(f);
    _ = c.fuse_reply_create(reqOf(r), &p, @ptrCast(&fi));
}

fn replyAttr(ptr: *anyopaque, r: fs.Req, a: *const fs.Attr, timeout: f64) void {
    answered(ptr, r);
    const st = statOf(a);
    _ = c.fuse_reply_attr(reqOf(r), &st, timeout);
}

fn replyOpen(ptr: *anyopaque, r: fs.Req, f: fs.FileReply) void {
    answered(ptr, r);
    const fi = fileInfo(f);
    _ = c.fuse_reply_open(reqOf(r), @ptrCast(&fi));
}

fn replyData(ptr: *anyopaque, r: fs.Req, data: []const u8) void {
    answered(ptr, r);
    _ = c.fuse_reply_buf(reqOf(r), data.ptr, data.len);
}

fn replyWritten(ptr: *anyopaque, r: fs.Req, n: usize) void {
    answered(ptr, r);
    _ = c.fuse_reply_write(reqOf(r), n);
}

fn replyStatfs(ptr: *anyopaque, r: fs.Req, s: *const fs.StatFs) void {
    answered(ptr, r);
    const v: c.struct_statvfs = .{
        .f_bsize = s.bsize,
        .f_frsize = s.frsize,
        .f_blocks = s.blocks,
        .f_bfree = s.bfree,
        .f_bavail = s.bavail,
        .f_files = s.files,
        .f_ffree = s.ffree,
        .f_favail = s.ffree,
        .f_namemax = s.namemax,
    };
    _ = c.fuse_reply_statfs(reqOf(r), &v);
}

fn replyDir(ptr: *anyopaque, r: fs.Req, plus: bool, size: usize, entries: []const fs.DirEntry) void {
    answered(ptr, r);
    const m: *Mount = @ptrCast(@alignCast(ptr));
    const req = reqOf(r);
    const buf = m.k.gpa.alloc(u8, size) catch {
        _ = c.fuse_reply_err(req, fs.errno(.NOMEM));
        return;
    };
    defer m.k.gpa.free(buf);
    const used = packDir(req, buf, plus, entries);
    _ = c.fuse_reply_buf(req, buf.ptr, used);
}

/// Packs `entries` with fuse_add_direntry(_plus); stops at the first that
/// does not fit (the request layer sized them with `fs.direntSize`).
pub fn packDir(req: c.fuse_req_t, buf: []u8, plus: bool, entries: []const fs.DirEntry) usize {
    var used: usize = 0;
    var name_buf: [1025]u8 = undefined;
    for (entries) |e| {
        if (e.name.len >= name_buf.len) break;
        @memcpy(name_buf[0..e.name.len], e.name);
        name_buf[e.name.len] = 0;
        const rest = buf[used..];
        const off: c.off_t = @intCast(e.off);
        const need = if (plus) blk: {
            const p = entryParam(&e.entry);
            break :blk c.fuse_add_direntry_plus(req, rest.ptr, rest.len, &name_buf, &p, off);
        } else blk: {
            const st = statOf(&e.entry.attr);
            break :blk c.fuse_add_direntry(req, rest.ptr, rest.len, &name_buf, &st, off);
        };
        if (need > rest.len) break;
        used += need;
    }
    return used;
}

pub fn statOf(a: *const fs.Attr) c.struct_stat {
    return .{
        .st_ino = a.ino,
        .st_mode = a.mode,
        .st_nlink = a.nlink,
        .st_uid = a.uid,
        .st_gid = a.gid,
        .st_size = @intCast(@min(a.size, std.math.maxInt(i64))),
        .st_blocks = @intCast(@min(a.blocks, std.math.maxInt(i64))),
        .st_blksize = a.blksize,
        .st_atim = .{ .tv_sec = a.atime.sec, .tv_nsec = a.atime.nsec },
        .st_mtim = .{ .tv_sec = a.mtime.sec, .tv_nsec = a.mtime.nsec },
        .st_ctim = .{ .tv_sec = a.ctime.sec, .tv_nsec = a.ctime.nsec },
    };
}

fn entryParam(e: *const fs.Entry) c.struct_fuse_entry_param {
    return .{
        .ino = e.ino,
        .generation = 0,
        .attr = statOf(&e.attr),
        .attr_timeout = e.attr_timeout,
        .entry_timeout = e.entry_timeout,
    };
}

fn fileInfo(f: fs.FileReply) FileInfo {
    var fi: FileInfo = .{ .fh = f.fh };
    if (f.keep_cache) fi.bits |= FileInfo.keep_cache;
    if (f.direct_io) fi.bits |= FileInfo.direct_io;
    return fi;
}

// Requests (struct fuse_lowlevel_ops)

const ops: c.struct_fuse_lowlevel_ops = .{
    .init = opInit,
    .lookup = opLookup,
    .forget = opForget,
    .forget_multi = opForgetMulti,
    .getattr = opGetattr,
    .setattr = opSetattr,
    .mkdir = opMkdir,
    .unlink = opUnlink,
    .rmdir = opRmdir,
    .rename = opRename,
    .open = opOpen,
    .read = opRead,
    .write = opWrite,
    .flush = opFlush,
    .release = opRelease,
    .fsync = opFsync,
    .opendir = opOpendir,
    .readdir = opReaddir,
    .readdirplus = opReaddirplus,
    .releasedir = opReleasedir,
    .fsyncdir = opFsyncdir,
    .statfs = opStatfs,
    .create = opCreate,
};

fn mountOf(req: c.fuse_req_t) *Mount {
    return @ptrCast(@alignCast(c.fuse_req_userdata(req).?));
}

fn info(fi: ?*c.struct_fuse_file_info) ?*FileInfo {
    return @ptrCast(@alignCast(fi));
}

fn fhOf(fi: ?*c.struct_fuse_file_info) u64 {
    return if (info(fi)) |f| f.fh else 0;
}

fn flagsOf(fi: ?*c.struct_fuse_file_info) u32 {
    return if (info(fi)) |f| @bitCast(f.flags) else 0;
}

/// Hands a request to the drive; one still open afterwards can be interrupted.
fn handle(req: c.fuse_req_t, r: fs.Request) void {
    const m = mountOf(req);
    const id: fs.Req = @intFromPtr(req.?);
    m.current = @intCast(id);
    m.current_done = false;
    m.handler.handle(id, r);
    if (!m.current_done) c.fuse_req_interrupt_func(req, onInterrupt, m);
    m.current = 0;
}

fn onInterrupt(req: c.fuse_req_t, data: ?*anyopaque) callconv(.c) void {
    const m: *Mount = @ptrCast(@alignCast(data.?));
    // Answered after fuse_session_process_buf returns: libfuse holds the request lock here.
    m.interrupts.append(m.k.gpa, @intFromPtr(req.?)) catch {};
}

fn opInit(userdata: ?*anyopaque, conn: ?*c.struct_fuse_conn_info) callconv(.c) void {
    _ = userdata;
    // Write-through: every write reaches the client when it happens.
    c.fuse_unset_feature_flag(conn, c.FUSE_CAP_WRITEBACK_CACHE);
    // Cached pages go when the client's size or mtime changes.
    _ = c.fuse_set_feature_flag(conn, c.FUSE_CAP_AUTO_INVAL_DATA);
    _ = c.fuse_set_feature_flag(conn, c.FUSE_CAP_READDIRPLUS);
    _ = c.fuse_set_feature_flag(conn, c.FUSE_CAP_READDIRPLUS_AUTO);
    // O_TRUNC comes with open (FILE_OVERWRITE) instead of a setattr.
    _ = c.fuse_set_feature_flag(conn, c.FUSE_CAP_ATOMIC_O_TRUNC);
}

fn name(p: [*c]const u8) []const u8 {
    return std.mem.span(@as([*:0]const u8, @ptrCast(p)));
}

fn opLookup(req: c.fuse_req_t, parent: c.fuse_ino_t, n: [*c]const u8) callconv(.c) void {
    handle(req, .{ .lookup = .{ .parent = parent, .name = name(n) } });
}

fn opForget(req: c.fuse_req_t, ino: c.fuse_ino_t, nlookup: u64) callconv(.c) void {
    mountOf(req).handler.forget(ino, nlookup);
    c.fuse_reply_none(req);
}

fn opForgetMulti(req: c.fuse_req_t, count: usize, forgets: [*c]c.struct_fuse_forget_data) callconv(.c) void {
    const m = mountOf(req);
    for (forgets[0..count]) |f| m.handler.forget(f.ino, f.nlookup);
    c.fuse_reply_none(req);
}

fn opGetattr(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    handle(req, .{ .getattr = .{ .ino = ino, .fh = if (info(fi)) |f| f.fh else null } });
}

fn nsOf(ts: c.struct_timespec) i128 {
    return @as(i128, ts.tv_sec) * std.time.ns_per_s + ts.tv_nsec;
}

fn opSetattr(req: c.fuse_req_t, ino: c.fuse_ino_t, attr: [*c]c.struct_stat, to_set: c_int, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    const a = attr.*;
    const set: u32 = @bitCast(to_set);
    var s: fs.SetAttr = .{};
    if (set & c.FUSE_SET_ATTR_SIZE != 0) s.size = @intCast(@max(a.st_size, 0));
    if (set & c.FUSE_SET_ATTR_ATIME_NOW != 0) s.atime = .now else if (set & c.FUSE_SET_ATTR_ATIME != 0) s.atime = .{ .ns = nsOf(a.st_atim) };
    if (set & c.FUSE_SET_ATTR_MTIME_NOW != 0) s.mtime = .now else if (set & c.FUSE_SET_ATTR_MTIME != 0) s.mtime = .{ .ns = nsOf(a.st_mtim) };
    if (set & c.FUSE_SET_ATTR_MODE != 0) s.mode = a.st_mode;
    if (set & c.FUSE_SET_ATTR_UID != 0) s.uid = a.st_uid;
    if (set & c.FUSE_SET_ATTR_GID != 0) s.gid = a.st_gid;
    handle(req, .{ .setattr = .{ .ino = ino, .fh = if (info(fi)) |f| f.fh else null, .set = s } });
}

fn opMkdir(req: c.fuse_req_t, parent: c.fuse_ino_t, n: [*c]const u8, mode: c.mode_t) callconv(.c) void {
    handle(req, .{ .mkdir = .{ .parent = parent, .name = name(n), .mode = mode } });
}

fn opUnlink(req: c.fuse_req_t, parent: c.fuse_ino_t, n: [*c]const u8) callconv(.c) void {
    handle(req, .{ .unlink = .{ .parent = parent, .name = name(n) } });
}

fn opRmdir(req: c.fuse_req_t, parent: c.fuse_ino_t, n: [*c]const u8) callconv(.c) void {
    handle(req, .{ .rmdir = .{ .parent = parent, .name = name(n) } });
}

fn opRename(req: c.fuse_req_t, parent: c.fuse_ino_t, n: [*c]const u8, newparent: c.fuse_ino_t, newname: [*c]const u8, flags: c_uint) callconv(.c) void {
    handle(req, .{ .rename = .{ .parent = parent, .name = name(n), .newparent = newparent, .newname = name(newname), .flags = flags } });
}

fn opOpen(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    handle(req, .{ .open = .{ .ino = ino, .flags = flagsOf(fi) } });
}

fn opCreate(req: c.fuse_req_t, parent: c.fuse_ino_t, n: [*c]const u8, mode: c.mode_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    handle(req, .{ .create = .{ .parent = parent, .name = name(n), .mode = mode, .flags = flagsOf(fi) } });
}

fn opRead(req: c.fuse_req_t, ino: c.fuse_ino_t, size: usize, off: c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    handle(req, .{ .read = .{ .ino = ino, .fh = fhOf(fi), .size = size, .offset = off } });
}

fn opWrite(req: c.fuse_req_t, ino: c.fuse_ino_t, buf: [*c]const u8, size: usize, off: c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    handle(req, .{ .write = .{ .ino = ino, .fh = fhOf(fi), .data = buf[0..size], .offset = off } });
}

fn opFlush(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    handle(req, .{ .flush = .{ .ino = ino, .fh = fhOf(fi) } });
}

fn opRelease(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    handle(req, .{ .release = .{ .ino = ino, .fh = fhOf(fi) } });
}

fn opFsync(req: c.fuse_req_t, ino: c.fuse_ino_t, datasync: c_int, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = datasync;
    handle(req, .{ .fsync = .{ .ino = ino, .fh = fhOf(fi) } });
}

fn opOpendir(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    handle(req, .{ .opendir = .{ .ino = ino, .flags = flagsOf(fi) } });
}

fn opReaddir(req: c.fuse_req_t, ino: c.fuse_ino_t, size: usize, off: c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    handle(req, .{ .readdir = .{ .ino = ino, .fh = fhOf(fi), .size = size, .offset = off, .plus = false } });
}

fn opReaddirplus(req: c.fuse_req_t, ino: c.fuse_ino_t, size: usize, off: c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    handle(req, .{ .readdir = .{ .ino = ino, .fh = fhOf(fi), .size = size, .offset = off, .plus = true } });
}

fn opReleasedir(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    handle(req, .{ .releasedir = .{ .ino = ino, .fh = fhOf(fi) } });
}

fn opFsyncdir(req: c.fuse_req_t, ino: c.fuse_ino_t, datasync: c_int, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = datasync;
    handle(req, .{ .fsyncdir = .{ .ino = ino, .fh = fhOf(fi) } });
}

fn opStatfs(req: c.fuse_req_t, ino: c.fuse_ino_t) callconv(.c) void {
    handle(req, .{ .statfs = .{ .ino = ino } });
}

test "fuse_add_direntry(_plus) sizes match what the request layer budgets" {
    // libfuse only measures when the buffer is too small; no session needed.
    var buf: [8]u8 = undefined;
    const st: c.struct_stat = .{};
    const p: c.struct_fuse_entry_param = .{};
    const long: [255:0]u8 = @splat('x');
    for ([_][:0]const u8{ "a", "ab", "seven77", "eight888", "a.longer-name.txt", &long }) |n| {
        try std.testing.expectEqual(fs.direntSize(false, n.len), c.fuse_add_direntry(null, &buf, 0, n.ptr, &st, 1));
        try std.testing.expectEqual(fs.direntSize(true, n.len), c.fuse_add_direntry_plus(null, &buf, 0, n.ptr, &p, 1));
    }
}

test "fusermount3 options: read-only or not, kernel permission checks, no allow_other, auto_unmount" {
    for ([_]bool{ false, true }) |ro| {
        const o = mountOptions(ro);
        var it = std.mem.splitScalar(u8, o, ',');
        try std.testing.expectEqualStrings(if (ro) "ro" else "rw", it.first());
        for ([_][]const u8{ "nosuid", "nodev", "default_permissions", "auto_unmount", "subtype=omastation" }) |want| {
            try std.testing.expect(std.mem.indexOf(u8, o, want) != null);
        }
        try std.testing.expect(std.mem.indexOf(u8, o, "allow_other") == null);
        try std.testing.expect(std.mem.indexOf(u8, o, "allow_root") == null);
    }
}

test "statOf: every Attr field lands in struct stat" {
    const a: fs.Attr = .{
        .ino = 77,
        .mode = std.posix.S.IFREG | 0o444,
        .nlink = 2,
        .uid = 1000,
        .gid = 100,
        .size = 12345,
        .blocks = 32,
        .blksize = 65536,
        .atime = .{ .sec = 1, .nsec = 2 },
        .mtime = .{ .sec = 3, .nsec = 4 },
        .ctime = .{ .sec = -5, .nsec = 6 },
    };
    const st = statOf(&a);
    try std.testing.expectEqual(@as(u64, 77), st.st_ino);
    try std.testing.expectEqual(a.mode, st.st_mode);
    try std.testing.expectEqual(@as(u64, 2), st.st_nlink);
    try std.testing.expectEqual(@as(u32, 1000), st.st_uid);
    try std.testing.expectEqual(@as(u32, 100), st.st_gid);
    try std.testing.expectEqual(@as(i64, 12345), st.st_size);
    try std.testing.expectEqual(@as(i64, 32), st.st_blocks);
    try std.testing.expectEqual(@as(i64, 65536), st.st_blksize);
    try std.testing.expectEqual(@as(i64, 3), st.st_mtim.tv_sec);
    try std.testing.expectEqual(@as(i64, 4), st.st_mtim.tv_nsec);
    try std.testing.expectEqual(@as(i64, -5), st.st_ctim.tv_sec);
    // A size beyond off_t is clamped, not wrapped negative.
    const huge: fs.Attr = .{ .size = std.math.maxInt(u64) };
    try std.testing.expectEqual(@as(i64, std.math.maxInt(i64)), statOf(&huge).st_size);
}

test "every operation the request layer serves is in the low-level ops table" {
    inline for (.{ "init", "lookup", "forget", "forget_multi", "getattr", "setattr", "mkdir", "unlink", "rmdir", "rename", "open", "read", "write", "flush", "release", "fsync", "opendir", "readdir", "readdirplus", "releasedir", "fsyncdir", "statfs", "create" }) |op| {
        try std.testing.expect(@field(ops, op) != null);
    }
    // Not served: the kernel answers locks itself, links and xattrs are refused.
    try std.testing.expect(ops.write_buf == null);
    try std.testing.expect(ops.setlk == null);
    try std.testing.expect(ops.symlink == null);
}

test "Kernel without mounts: one pollable fd, dispatch does nothing, unmount of an unknown drive is harmless" {
    var k = try Kernel.init(std.testing.allocator);
    defer k.deinit();
    const b = k.backend();
    const fd = b.vtable.fd(b.ptr);
    try std.testing.expect(fd >= 0);
    var pfd = [_]c.struct_pollfd{.{ .fd = fd, .events = c.POLLIN, .revents = 0 }};
    try std.testing.expectEqual(@as(c_int, 0), c.poll(&pfd, 1, 0));
    b.vtable.dispatch(b.ptr);
    b.vtable.unmount(b.ptr, 42);
    try std.testing.expectEqual(@as(usize, 0), k.mounts.items.len);
}

test "registry: one owner per mount point, none while it is being unmounted; reaped, it is free again" {
    const a = "/nonexistent/omastation-registry-test/A";
    const b = "/nonexistent/omastation-registry-test/B";
    try std.testing.expect(registry.claim(a, 1));
    try std.testing.expect(!registry.claim(a, 2));
    try std.testing.expect(registry.claim(b, 2));
    try std.testing.expect(registry.busy(a));
    // Released without an unmount process: free at once.
    registry.release(b, 2, 0);
    try std.testing.expect(!registry.busy(b));
    // Only its owner releases it.
    registry.release(a, 2, 0);
    try std.testing.expect(registry.busy(a));
    // Released with an unmount running (waitpid fails, which counts as gone): busy until reaped.
    registry.release(a, 1, std.math.maxInt(i32));
    try std.testing.expect(registry.busy(a));
    try std.testing.expect(!registry.claim(a, 3));
    registry.reap();
    try std.testing.expect(!registry.busy(a));
    try std.testing.expect(registry.claim(a, 3));
    registry.release(a, 3, 0);
    // A stale mount cleared before anyone claimed it is tracked too.
    registry.release(b, 0, std.math.maxInt(i32));
    try std.testing.expect(registry.busy(b));
    registry.reap();
    try std.testing.expect(!registry.busy(b));
}

test "FileInfo matches struct fuse_file_info" {
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(FileInfo));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(FileInfo, "fh"));
}

test {
    refAll(@This());
}

/// References every declaration, nested types included, for `zig build test`.
fn refAll(comptime T: type) void {
    inline for (comptime std.meta.declarations(T)) |d| {
        const f = @field(T, d);
        if (@TypeOf(f) == type) {
            switch (@typeInfo(f)) {
                .@"struct", .@"union", .@"enum" => refAll(f),
                else => {},
            }
        } else {
            _ = &@field(T, d);
        }
    }
}
