//! libc helpers for the Wayland client: Unix sockets with SCM_RIGHTS, memfd + mmap, poll,
//! pipes and the monotonic clock, via `std.c` rather than the moving std.posix surface.

const std = @import("std");
const c = std.c;

pub const Fd = c.fd_t;

pub const Error = error{
    SocketFailed,
    ConnectFailed,
    NameTooLong,
    ReadFailed,
    WriteFailed,
    WouldBlock,
    ConnectionClosed,
    ShmFailed,
    PollFailed,
};

/// Max fds accepted in one recvmsg (libwayland sends at most 28).
pub const max_fds_in = 32;
/// Max fds per sendmsg, as in libwayland.
pub const max_fds_out = 28;

pub fn close(fd: Fd) void {
    if (fd >= 0) _ = c.close(fd);
}

/// Close-on-exec; null on failure.
pub fn dup(fd: Fd) ?Fd {
    const rc = c.fcntl(fd, c.F.DUPFD_CLOEXEC, @as(c_int, 0));
    return if (rc < 0) null else rc;
}

pub fn connectUnix(path: []const u8) Error!Fd {
    var addr: c.sockaddr.un = .{ .family = c.AF.UNIX, .path = @splat(0) };
    if (path.len >= addr.path.len) return error.NameTooLong;
    @memcpy(addr.path[0..path.len], path);
    const fd = c.socket(c.AF.UNIX, c.SOCK.STREAM | c.SOCK.CLOEXEC, 0);
    if (fd < 0) return error.SocketFailed;
    while (true) {
        if (c.connect(fd, @ptrCast(&addr), @sizeOf(c.sockaddr.un)) == 0) return fd;
        if (c.errno(@as(c_int, -1)) == .INTR) continue;
        close(fd);
        return error.ConnectFailed;
    }
}

pub fn socketPair() Error![2]Fd {
    var fds: [2]Fd = undefined;
    if (c.socketpair(c.AF.UNIX, c.SOCK.STREAM | c.SOCK.CLOEXEC, 0, &fds) != 0) return error.SocketFailed;
    return fds;
}

const cmsg_hdr_len = cmsgAlign(@sizeOf(c.cmsghdr));

fn cmsgAlign(n: usize) usize {
    return std.mem.alignForward(usize, n, c.cmsg_align);
}

fn cmsgSpace(n: usize) usize {
    return cmsg_hdr_len + cmsgAlign(n);
}

fn cmsgLen(n: usize) usize {
    return cmsg_hdr_len + n;
}

/// One sendmsg that never waits (WouldBlock when full); `fds` ride as SCM_RIGHTS.
pub fn sendMsg(fd: Fd, data: []const u8, fds: []const Fd) Error!usize {
    std.debug.assert(fds.len <= max_fds_out);
    var iov = [1]c.iovec_const{.{ .base = data.ptr, .len = data.len }};
    var cbuf: [cmsgSpace(max_fds_out * @sizeOf(Fd))]u8 align(@alignOf(c.cmsghdr)) = undefined;
    var msg: c.msghdr_const = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    if (fds.len > 0) {
        const payload = fds.len * @sizeOf(Fd);
        @memset(cbuf[0..cmsgSpace(payload)], 0);
        const hdr: *c.cmsghdr = @ptrCast(&cbuf);
        hdr.* = .{ .len = @intCast(cmsgLen(payload)), .level = c.SOL.SOCKET, .type = c.SCM.RIGHTS };
        @memcpy(cbuf[cmsg_hdr_len..][0..payload], std.mem.sliceAsBytes(fds));
        msg.control = &cbuf;
        msg.controllen = @intCast(cmsgSpace(payload));
    }
    while (true) {
        const rc = c.sendmsg(fd, &msg, c.MSG.NOSIGNAL | c.MSG.DONTWAIT);
        if (rc >= 0) return @intCast(rc);
        switch (c.errno(rc)) {
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .PIPE, .CONNRESET => return error.ConnectionClosed,
            else => return error.WriteFailed,
        }
    }
}

pub const Received = struct {
    len: usize,
    fds: [max_fds_in]Fd = undefined,
    nfds: usize = 0,
    /// Some fds were lost (control buffer too small): the stream is desynced.
    truncated: bool = false,
};

pub fn recvMsg(fd: Fd, buf: []u8, nonblock: bool) Error!Received {
    var iov = [1]c.iovec{.{ .base = buf.ptr, .len = buf.len }};
    var cbuf: [cmsgSpace(max_fds_in * @sizeOf(Fd))]u8 align(@alignOf(c.cmsghdr)) = undefined;
    var msg: c.msghdr = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &cbuf,
        .controllen = @intCast(cbuf.len),
        .flags = 0,
    };
    const flags: u32 = c.MSG.CMSG_CLOEXEC | (if (nonblock) @as(u32, c.MSG.DONTWAIT) else 0);
    const n: usize = while (true) {
        const rc = c.recvmsg(fd, &msg, flags);
        if (rc >= 0) break @intCast(rc);
        switch (c.errno(rc)) {
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET => return error.ConnectionClosed,
            else => return error.ReadFailed,
        }
    };
    var res: Received = .{ .len = n };
    // Walk the control messages even on EOF so no fd leaks.
    const clen: usize = @intCast(msg.controllen);
    var off: usize = 0;
    while (off + @sizeOf(c.cmsghdr) <= clen) {
        const hdr: *align(1) const c.cmsghdr = @ptrCast(&cbuf[off]);
        const len: usize = @intCast(hdr.len);
        if (len < cmsg_hdr_len or off + len > clen) break;
        if (hdr.level == c.SOL.SOCKET and hdr.type == c.SCM.RIGHTS) {
            const count = (len - cmsg_hdr_len) / @sizeOf(Fd);
            for (0..count) |k| {
                const p = cbuf[off + cmsg_hdr_len + k * @sizeOf(Fd) ..][0..@sizeOf(Fd)];
                const got = std.mem.readInt(Fd, p, .little);
                if (res.nfds < res.fds.len) {
                    res.fds[res.nfds] = got;
                    res.nfds += 1;
                } else {
                    close(got);
                    res.truncated = true;
                }
            }
        }
        off += cmsgAlign(len);
    }
    if (msg.flags & c.MSG.CTRUNC != 0) res.truncated = true;
    if (n == 0 and buf.len > 0) {
        for (res.fds[0..res.nfds]) |f| close(f);
        return error.ConnectionClosed;
    }
    return res;
}

pub const PollResult = enum { ready, timeout, hangup };

/// Wait until `fd` is readable (writable with `out`); `timeout_ms` < 0 waits forever.
pub fn pollFd(fd: Fd, out: bool, timeout_ms: i32) error{PollFailed}!PollResult {
    var pfd = [1]c.pollfd{.{ .fd = fd, .events = if (out) c.POLL.OUT else c.POLL.IN, .revents = 0 }};
    while (true) {
        const rc = c.poll(&pfd, 1, timeout_ms);
        if (rc < 0) {
            if (c.errno(rc) == .INTR) continue;
            return error.PollFailed;
        }
        if (rc == 0) return .timeout;
        const want: i16 = if (out) c.POLL.OUT else c.POLL.IN;
        if (pfd[0].revents & want != 0) return .ready;
        if (pfd[0].revents & (c.POLL.HUP | c.POLL.ERR | c.POLL.NVAL) != 0) return .hangup;
        return .ready;
    }
}

/// Monotonic milliseconds, truncated to u32 like Wayland input timestamps.
pub fn nowMs() u32 {
    return @truncate(nowNs() / std.time.ns_per_ms);
}

pub fn nowNs() u64 {
    var ts: c.timespec = undefined;
    _ = c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub fn getenv(name: [*:0]const u8) ?[]const u8 {
    const v = c.getenv(name) orelse return null;
    return std.mem.sliceTo(v, 0);
}

/// Anonymous shared memory: a sealed-against-shrink memfd mapped read/write.
pub const SharedMemory = struct {
    fd: Fd,
    data: []align(std.heap.page_size_min) u8,

    pub fn create(name: [*:0]const u8, size: usize) Error!SharedMemory {
        if (size == 0) return error.ShmFailed;
        const fd = c.memfd_create(name, std.os.linux.MFD.CLOEXEC | std.os.linux.MFD.ALLOW_SEALING);
        if (fd < 0) return error.ShmFailed;
        errdefer close(fd);
        while (c.ftruncate(fd, @intCast(size)) != 0) {
            if (c.errno(@as(c_int, -1)) != .INTR) return error.ShmFailed;
        }
        // The compositor maps this too; forbid shrinking so it cannot SIGBUS.
        _ = c.fcntl(fd, c.F.ADD_SEALS, @as(c_int, c.F.SEAL_SHRINK));
        const ptr = c.mmap(null, size, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, fd, 0);
        if (ptr == c.MAP_FAILED) return error.ShmFailed;
        const base: [*]align(std.heap.page_size_min) u8 = @ptrCast(@alignCast(ptr));
        return .{ .fd = fd, .data = base[0..size] };
    }

    pub fn destroy(s: *SharedMemory) void {
        _ = c.munmap(@ptrCast(s.data.ptr), s.data.len);
        close(s.fd);
        s.* = undefined;
    }
};

pub fn writeAll(fd: Fd, data: []const u8) Error!void {
    var off: usize = 0;
    while (off < data.len) {
        const rc = c.write(fd, data.ptr + off, data.len - off);
        if (rc < 0) {
            if (c.errno(rc) == .INTR) continue;
            return error.WriteFailed;
        }
        off += @intCast(rc);
    }
}

pub const PipeError = error{PipeFailed};

/// [0] read end, [1] write end, close-on-exec. Only the read end is non-blocking: O_NONBLOCK
/// is shared with the other client that gets the write end and may expect blocking writes.
pub fn pipe() PipeError![2]Fd {
    var fds: [2]Fd = undefined;
    if (c.pipe2(&fds, .{ .CLOEXEC = true }) != 0) return error.PipeFailed;
    setNonBlocking(fds[0]) catch {
        close(fds[0]);
        close(fds[1]);
        return error.PipeFailed;
    };
    return fds;
}

pub fn setNonBlocking(fd: Fd) PipeError!void {
    const fl = c.fcntl(fd, c.F.GETFL);
    if (fl < 0) return error.PipeFailed;
    const nonblock: c_int = @bitCast(@as(u32, @bitCast(c.O{ .NONBLOCK = true })));
    if (c.fcntl(fd, c.F.SETFL, fl | nonblock) < 0) return error.PipeFailed;
}

/// Bytes read (0 at end of file), null when nothing is available yet.
pub fn readNonBlock(fd: Fd, buf: []u8) error{ReadFailed}!?usize {
    while (true) {
        const rc = c.read(fd, buf.ptr, buf.len);
        if (rc >= 0) return @intCast(rc);
        switch (c.errno(rc)) {
            .INTR => continue,
            .AGAIN => return null,
            else => return error.ReadFailed,
        }
    }
}

/// Bytes written, null when the pipe is full; ConnectionClosed on EPIPE (see ignoreSigpipe).
pub fn writeNonBlock(fd: Fd, data: []const u8) error{ WriteFailed, ConnectionClosed }!?usize {
    while (true) {
        const rc = c.write(fd, data.ptr, data.len);
        if (rc >= 0) return @intCast(rc);
        switch (c.errno(rc)) {
            .INTR => continue,
            .AGAIN => return null,
            .PIPE => return error.ConnectionClosed,
            else => return error.WriteFailed,
        }
    }
}

/// SIGPIPE kills the process by default; ignore it unless a handler is installed.
pub fn ignoreSigpipe() void {
    const posix = std.posix;
    var old: posix.Sigaction = undefined;
    posix.sigaction(.PIPE, null, &old);
    if (old.handler.handler != posix.SIG.DFL) return;
    const act: posix.Sigaction = .{
        .handler = .{ .handler = posix.SIG.IGN },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(.PIPE, &act, null);
}

pub fn pread(fd: Fd, buf: []u8, offset: u64) Error!usize {
    const rc = c.pread(fd, buf.ptr, buf.len, @intCast(offset));
    if (rc < 0) return error.ReadFailed;
    return @intCast(rc);
}

pub fn memfdWithData(name: [*:0]const u8, data: []const u8) Error!Fd {
    const fd = c.memfd_create(name, std.os.linux.MFD.CLOEXEC | std.os.linux.MFD.ALLOW_SEALING);
    if (fd < 0) return error.ShmFailed;
    errdefer close(fd);
    try writeAll(fd, data);
    _ = c.fcntl(fd, c.F.ADD_SEALS, @as(c_int, c.F.SEAL_SHRINK | c.F.SEAL_GROW | c.F.SEAL_WRITE));
    return fd;
}

/// NUL-terminated (keymap convention); `size` includes the terminator.
pub fn memfdWithText(name: [*:0]const u8, text: []const u8) Error!struct { fd: Fd, size: usize } {
    const fd = c.memfd_create(name, std.os.linux.MFD.CLOEXEC | std.os.linux.MFD.ALLOW_SEALING);
    if (fd < 0) return error.ShmFailed;
    errdefer close(fd);
    try writeAll(fd, text);
    var size = text.len;
    if (text.len == 0 or text[text.len - 1] != 0) {
        try writeAll(fd, &.{0});
        size += 1;
    }
    _ = c.fcntl(fd, c.F.ADD_SEALS, @as(c_int, c.F.SEAL_SHRINK | c.F.SEAL_GROW | c.F.SEAL_WRITE));
    return .{ .fd = fd, .size = size };
}

test "socketpair passes fds" {
    const sp = try socketPair();
    defer close(sp[0]);
    defer close(sp[1]);
    const mfd = try memfdWithData("t", "hello");
    defer close(mfd);
    _ = try sendMsg(sp[0], "abcd", &.{ mfd, mfd });
    var buf: [16]u8 = undefined;
    const r = try recvMsg(sp[1], &buf, false);
    try std.testing.expectEqualStrings("abcd", buf[0..r.len]);
    try std.testing.expectEqual(2, r.nfds);
    defer for (r.fds[0..r.nfds]) |f| close(f);
    var got: [5]u8 = undefined;
    try std.testing.expectEqual(5, try pread(r.fds[1], &got, 0));
    try std.testing.expectEqualStrings("hello", &got);
    try std.testing.expectError(error.WouldBlock, recvMsg(sp[1], &buf, true));
}

test "shared memory" {
    var shm = try SharedMemory.create("t", 8192);
    defer shm.destroy();
    shm.data[8191] = 7;
    var b: [1]u8 = undefined;
    _ = try pread(shm.fd, &b, 8191);
    try std.testing.expectEqual(7, b[0]);
}

test "pipe: non-blocking read end, blocking write end, EOF and EPIPE" {
    ignoreSigpipe();
    const p = try pipe();
    defer close(p[0]);
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try readNonBlock(p[0], &buf));
    try std.testing.expect(c.fcntl(p[1], c.F.GETFL) & @as(c_int, @bitCast(@as(u32, @bitCast(c.O{ .NONBLOCK = true })))) == 0);
    try std.testing.expectEqual(@as(?usize, 3), try writeNonBlock(p[1], "abc"));
    close(p[1]);
    try std.testing.expectEqual(@as(?usize, 3), try readNonBlock(p[0], &buf));
    try std.testing.expectEqual(@as(?usize, 0), try readNonBlock(p[0], &buf));

    const q = try pipe();
    defer close(q[1]);
    close(q[0]);
    try std.testing.expectError(error.ConnectionClosed, writeNonBlock(q[1], "x"));
}
