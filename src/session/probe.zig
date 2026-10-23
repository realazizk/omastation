//! Runs a shell command in its own process group and collects up to `max_output`
//! bytes of its stdout without blocking; a timeout kills the whole group.

const std = @import("std");
const c = @import("c");

const log = std.log.scoped(.probe);

extern "c" var environ: [*:null]?[*:0]u8;

pub const Error = error{SpawnFailed};

pub const max_output = 4096;

pub const Result = union(enum) {
    pending,
    /// `code` is null if killed by a signal or reaped elsewhere.
    done: struct { output: []const u8, code: ?u8 },
    timed_out,
};

pub const Probe = struct {
    pid: c.pid_t,
    /// Read end of its stdout; -1 at end of file.
    fd: c_int,
    /// Readable once it has exited (-1: no pidfd, then a later poll sees it).
    pidfd: c_int = -1,
    started_ms: i64,
    buf: [max_output]u8 = undefined,
    len: usize = 0,

    pub fn start(cmd: [*:0]const u8, now_ms: i64) Error!Probe {
        reapStragglers();
        var p: [2]c_int = undefined;
        if (c.pipe2(&p, c.O_CLOEXEC) != 0) return error.SpawnFailed;
        defer _ = c.close(p[1]);
        errdefer _ = c.close(p[0]);
        if (c.fcntl(p[0], c.F_SETFL, c.O_NONBLOCK) != 0) return error.SpawnFailed;

        var fa: c.posix_spawn_file_actions_t = undefined;
        if (c.posix_spawn_file_actions_init(&fa) != 0) return error.SpawnFailed;
        defer _ = c.posix_spawn_file_actions_destroy(&fa);
        var attr: c.posix_spawnattr_t = undefined;
        if (c.posix_spawnattr_init(&attr) != 0) return error.SpawnFailed;
        defer _ = c.posix_spawnattr_destroy(&attr);
        // Server threads block SIGUSR1 and exec keeps the mask.
        var no_signals: c.sigset_t = undefined;
        _ = c.sigemptyset(&no_signals);
        // dup2 clears close-on-exec on the child's stdout.
        if (c.posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", c.O_RDONLY, 0) != 0 or
            c.posix_spawn_file_actions_adddup2(&fa, p[1], 1) != 0 or
            c.posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", c.O_WRONLY, 0) != 0 or
            // Own process group so a timeout also kills its children.
            c.posix_spawnattr_setflags(&attr, c.POSIX_SPAWN_SETPGROUP | c.POSIX_SPAWN_SETSIGMASK) != 0 or
            c.posix_spawnattr_setpgroup(&attr, 0) != 0 or
            c.posix_spawnattr_setsigmask(&attr, &no_signals) != 0) return error.SpawnFailed;

        const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", cmd };
        var pid: c.pid_t = 0;
        if (c.posix_spawn(&pid, "/bin/sh", &fa, &attr, @ptrCast(@constCast(&argv)), @ptrCast(environ)) != 0) return error.SpawnFailed;
        return .{ .pid = pid, .fd = p[0], .pidfd = c.pidfd_open(pid, 0), .started_ms = now_ms };
    }

    /// Never waits. After `.done` or `.timed_out` the probe is finished.
    pub fn poll(pr: *Probe, now_ms: i64, timeout_ms: i64) Result {
        pr.drain();
        if (pr.fd < 0) {
            var status: c_int = 0;
            const r = c.waitpid(pr.pid, &status, c.WNOHANG);
            if (r == pr.pid or r < 0) {
                pr.pid = 0;
                pr.closePidfd();
                const code: ?u8 = if (r < 0 or status & 0x7f != 0) null else @intCast((status >> 8) & 0xff);
                return .{ .done = .{ .output = pr.buf[0..pr.len], .code = code } };
            }
        }
        if (now_ms - pr.started_ms >= timeout_ms) {
            pr.cancel();
            return .timed_out;
        }
        return .pending;
    }

    /// Kills the process group; an unreaped child is reaped by a later start.
    pub fn cancel(pr: *Probe) void {
        pr.closePidfd();
        if (pr.pid > 0) {
            _ = c.kill(-pr.pid, c.SIGKILL);
            if (c.waitpid(pr.pid, null, c.WNOHANG) == 0) remember(pr.pid);
            pr.pid = 0;
        }
        if (pr.fd >= 0) _ = c.close(pr.fd);
        pr.fd = -1;
    }

    pub fn pollFd(pr: *const Probe) c_int {
        return if (pr.fd >= 0) pr.fd else pr.pidfd;
    }

    fn closePidfd(pr: *Probe) void {
        if (pr.pidfd >= 0) _ = c.close(pr.pidfd);
        pr.pidfd = -1;
    }

    fn drain(pr: *Probe) void {
        while (pr.fd >= 0) {
            var scratch: [512]u8 = undefined;
            const dst: []u8 = if (pr.len < pr.buf.len) pr.buf[pr.len..] else &scratch;
            const n = c.read(pr.fd, dst.ptr, dst.len);
            if (n > 0) {
                if (pr.len < pr.buf.len) pr.len += @intCast(n);
                continue;
            }
            if (n < 0 and c.__errno_location().* == c.EINTR) continue;
            if (n < 0 and c.__errno_location().* == c.EAGAIN) return;
            _ = c.close(pr.fd); // end of file, or an error: nothing more
            pr.fd = -1;
        }
    }
};

/// Killed children not reaped yet.
var stragglers: [8]c.pid_t = @splat(0);

fn remember(pid: c.pid_t) void {
    reapStragglers();
    for (&stragglers) |*s| if (s.* == 0) {
        s.* = pid;
        return;
    };
    // Children stuck in uninterruptible sleep can outlive SIGKILL; never wait
    // on the session thread. This one is not tracked.
    log.warn("killed probe {d} has not exited, nor have {d} before it: not waiting for it", .{ pid, stragglers.len });
}

fn reapStragglers() void {
    for (&stragglers) |*s| {
        if (s.* == 0) continue;
        if (c.waitpid(s.*, null, c.WNOHANG) != 0) s.* = 0;
    }
}

fn nowMs() i64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(i64, ts.tv_sec) * 1000 + @divTrunc(@as(i64, ts.tv_nsec), 1_000_000);
}

fn finish(pr: *Probe, timeout_ms: i64) Result {
    while (true) {
        const r = pr.poll(nowMs(), timeout_ms);
        if (r != .pending) return r;
        var pfd: c.struct_pollfd = .{ .fd = pr.pollFd(), .events = c.POLLIN, .revents = 0 };
        _ = c.poll(&pfd, if (pfd.fd >= 0) 1 else 0, 5);
    }
}

test "output and exit status" {
    var pr = try Probe.start("printf 'hello'; exit 3", nowMs());
    const r = finish(&pr, 5000);
    try std.testing.expectEqualStrings("hello", r.done.output);
    try std.testing.expectEqual(@as(?u8, 3), r.done.code);
}

test "a slow command is pending without waiting, then killed with what it started" {
    var pr = try Probe.start("sleep 30 & sleep 30; echo late", nowMs());
    const t0 = nowMs();
    try std.testing.expect(pr.poll(nowMs(), 200) == .pending);
    try std.testing.expect(nowMs() - t0 < 50);
    try std.testing.expect(finish(&pr, 200) == .timed_out);
    try std.testing.expect(nowMs() - t0 < 2000);
}

test "the command starts with no signal blocked, whatever the caller blocks" {
    var usr1: c.sigset_t = undefined;
    _ = c.sigemptyset(&usr1);
    _ = c.sigaddset(&usr1, c.SIGUSR1);
    var old: c.sigset_t = undefined;
    _ = c.pthread_sigmask(c.SIG_BLOCK, &usr1, &old);
    defer _ = c.pthread_sigmask(c.SIG_SETMASK, &old, null);
    var pr = try Probe.start("sed -n 's/^SigBlk:[[:space:]]*//p' /proc/self/status", nowMs());
    const r = finish(&pr, 5000);
    try std.testing.expectEqualStrings("0000000000000000\n", r.done.output);
}

test "output past max_output is dropped, not kept" {
    var pr = try Probe.start("head -c 20000 /dev/zero", nowMs());
    const r = finish(&pr, 5000);
    try std.testing.expectEqual(@as(usize, max_output), r.done.output.len);
}

test "with eight killed children not gone yet, cancelling another never waits for it" {
    // Live children stand in for ones stuck in the kernel after SIGKILL.
    const deadline = nowMs() + 2000;
    while (std.mem.indexOfNone(c.pid_t, &stragglers, &.{0}) != null and nowMs() < deadline) {
        reapStragglers();
        var ts: c.struct_timespec = .{ .tv_sec = 0, .tv_nsec = 5_000_000 };
        _ = c.nanosleep(&ts, null);
    }
    var probes: [stragglers.len + 1]Probe = undefined;
    for (&probes) |*pr| pr.* = try Probe.start("exec sleep 3", nowMs());
    defer for (&probes) |*pr| {
        _ = c.kill(-pr.pid, c.SIGKILL);
        _ = c.waitpid(pr.pid, null, 0);
        _ = c.close(pr.fd);
        if (pr.pidfd >= 0) _ = c.close(pr.pidfd);
    };
    defer stragglers = @splat(0);
    for (&stragglers, probes[0..stragglers.len]) |*s, pr| s.* = pr.pid;
    const t0 = nowMs();
    remember(probes[stragglers.len].pid);
    try std.testing.expect(nowMs() - t0 < 1000);
}
