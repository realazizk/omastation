//! Thin libc socket helpers, used instead of std.Io so file descriptors
//! can be handed straight to OpenSSL.

const std = @import("std");
const c = @import("c");

pub const Error = error{
    SocketFailed,
    BindFailed,
    ListenFailed,
    AcceptFailed,
    ReadFailed,
    WriteFailed,
    ConnectionClosed,
    /// A non-blocking socket has nothing to read, or no room to write.
    WouldBlock,
};

pub const Fd = c_int;

pub fn listenTcp(port: u16, backlog: c_int) Error!Fd {
    const fd = c.socket(c.AF_INET6, c.SOCK_STREAM | c.SOCK_CLOEXEC, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer _ = c.close(fd);

    const one: c_int = 1;
    _ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_REUSEADDR, &one, @sizeOf(c_int));
    const zero: c_int = 0; // dual-stack: accept IPv4-mapped too
    _ = c.setsockopt(fd, c.IPPROTO_IPV6, c.IPV6_V6ONLY, &zero, @sizeOf(c_int));

    var addr: c.sockaddr_in6 = std.mem.zeroes(c.sockaddr_in6);
    addr.sin6_family = c.AF_INET6;
    addr.sin6_port = c.htons(port);
    addr.sin6_addr = c.in6addr_any;
    if (c.bind(fd, .{ .__sockaddr__ = @ptrCast(&addr) }, @sizeOf(c.sockaddr_in6)) != 0) return error.BindFailed;
    if (c.listen(fd, backlog) != 0) return error.ListenFailed;
    return fd;
}

pub const Peer = struct {
    fd: Fd,
    addr: [64]u8,
    addr_len: usize,

    pub fn addrText(p: *const Peer) []const u8 {
        return p.addr[0..p.addr_len];
    }
};

pub fn accept(listen_fd: Fd) Error!Peer {
    var addr: c.sockaddr_in6 = undefined;
    var len: c.socklen_t = @sizeOf(c.sockaddr_in6);
    const fd = c.accept4(listen_fd, .{ .__sockaddr__ = @ptrCast(&addr) }, &len, c.SOCK_CLOEXEC);
    if (fd < 0) return error.AcceptFailed;

    const one: c_int = 1;
    _ = c.setsockopt(fd, c.IPPROTO_TCP, c.TCP_NODELAY, &one, @sizeOf(c_int));
    // A vanished client must not hold the desktop: probe idle peers after 20 s, drop after 4 misses.
    const idle: c_int = 20;
    const intvl: c_int = 5;
    const cnt: c_int = 4;
    const user_timeout: c_uint = 30_000;
    _ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_KEEPALIVE, &one, @sizeOf(c_int));
    _ = c.setsockopt(fd, c.IPPROTO_TCP, c.TCP_KEEPIDLE, &idle, @sizeOf(c_int));
    _ = c.setsockopt(fd, c.IPPROTO_TCP, c.TCP_KEEPINTVL, &intvl, @sizeOf(c_int));
    _ = c.setsockopt(fd, c.IPPROTO_TCP, c.TCP_KEEPCNT, &cnt, @sizeOf(c_int));
    _ = c.setsockopt(fd, c.IPPROTO_TCP, c.TCP_USER_TIMEOUT, &user_timeout, @sizeOf(c_uint));

    var p = Peer{ .fd = fd, .addr = undefined, .addr_len = 0 };
    var ip: [c.INET6_ADDRSTRLEN]u8 = undefined;
    if (c.inet_ntop(c.AF_INET6, &addr.sin6_addr, &ip, ip.len) != null) {
        const ip_s = std.mem.sliceTo(&ip, 0);
        const port = c.ntohs(addr.sin6_port);
        const s = std.fmt.bufPrint(&p.addr, "[{s}]:{d}", .{ ip_s, port }) catch "?";
        p.addr_len = s.len;
    }
    return p;
}

pub fn close(fd: Fd) void {
    _ = c.close(fd);
}

pub fn readSome(fd: Fd, buf: []u8) Error!usize {
    while (true) {
        const n = c.recv(fd, buf.ptr, buf.len, 0);
        if (n < 0) {
            const e = c.__errno_location().*;
            if (e == c.EINTR) continue;
            if (e == c.EAGAIN or e == c.EWOULDBLOCK) return error.WouldBlock;
            return error.ReadFailed;
        }
        if (n == 0) return error.ConnectionClosed;
        return @intCast(n);
    }
}

/// At least one byte, or error.WouldBlock when the send buffer is full.
pub fn writeSome(fd: Fd, data: []const u8) Error!usize {
    while (true) {
        const n = c.send(fd, data.ptr, data.len, c.MSG_NOSIGNAL);
        if (n < 0) {
            const e = c.__errno_location().*;
            if (e == c.EINTR) continue;
            if (e == c.EAGAIN or e == c.EWOULDBLOCK) return error.WouldBlock;
            return error.WriteFailed;
        }
        return @intCast(n);
    }
}

pub fn setNonBlocking(fd: Fd, on: bool) Error!void {
    const fl = c.fcntl(fd, c.F_GETFL, @as(c_int, 0));
    if (fl < 0) return error.SocketFailed;
    const want = if (on) fl | c.O_NONBLOCK else fl & ~@as(c_int, c.O_NONBLOCK);
    if (want != fl and c.fcntl(fd, c.F_SETFL, want) < 0) return error.SocketFailed;
}

/// The kernel stops taking data once `bytes` wait to be sent, so the backlog stays
/// visible to the application. False for a socket that is not TCP.
pub fn setNotSentLowat(fd: Fd, bytes: u32) bool {
    const v: c_int = @intCast(bytes);
    return c.setsockopt(fd, c.IPPROTO_TCP, c.TCP_NOTSENT_LOWAT, &v, @sizeOf(c_int)) == 0;
}

/// Prefix of Linux's struct tcp_info, declared by hand because the C struct starts with bit fields.
pub const TcpInfo = extern struct {
    state: u8,
    ca_state: u8,
    retransmits: u8,
    probes: u8,
    backoff: u8,
    options: u8,
    wscale: u8,
    /// Bit 0: tcpi_delivery_rate_app_limited (Linux 4.9).
    flags: u8,
    rto: u32,
    ato: u32,
    snd_mss: u32,
    rcv_mss: u32,
    unacked: u32,
    sacked: u32,
    lost: u32,
    retrans: u32,
    fackets: u32,
    last_data_sent: u32,
    last_ack_sent: u32,
    last_data_recv: u32,
    last_ack_recv: u32,
    pmtu: u32,
    rcv_ssthresh: u32,
    /// Smoothed RTT and its variance, microseconds.
    rtt: u32,
    rttvar: u32,
    snd_ssthresh: u32,
    snd_cwnd: u32,
    advmss: u32,
    reordering: u32,
    rcv_rtt: u32,
    rcv_space: u32,
    total_retrans: u32,
    pacing_rate: u64,
    max_pacing_rate: u64,
    bytes_acked: u64,
    bytes_received: u64,
    segs_out: u32,
    segs_in: u32,
    notsent_bytes: u32,
    min_rtt: u32,
    data_segs_in: u32,
    data_segs_out: u32,
    /// Latest goodput sample, bytes per second (Linux 4.9).
    delivery_rate: u64,

    /// The rate was measured while the sender had too little to send.
    pub fn appLimited(t: *const TcpInfo) bool {
        return t.flags & 1 != 0;
    }
};

comptime {
    std.debug.assert(@offsetOf(TcpInfo, "rtt") == 68);
    std.debug.assert(@offsetOf(TcpInfo, "notsent_bytes") == 144);
    std.debug.assert(@offsetOf(TcpInfo, "delivery_rate") == 160);
}

/// Null for a non-TCP socket or a kernel without tcpi_delivery_rate.
pub fn tcpInfo(fd: Fd) ?TcpInfo {
    var t: TcpInfo = std.mem.zeroes(TcpInfo);
    var len: c.socklen_t = @sizeOf(TcpInfo);
    if (c.getsockopt(fd, c.IPPROTO_TCP, c.TCP_INFO, &t, &len) != 0) return null;
    if (len < @offsetOf(TcpInfo, "delivery_rate") + @sizeOf(u64)) return null;
    return t;
}

pub fn writeAll(fd: Fd, data: []const u8) Error!void {
    var off: usize = 0;
    while (off < data.len) {
        const n = c.send(fd, data.ptr + off, data.len - off, c.MSG_NOSIGNAL);
        if (n < 0) {
            if (c.__errno_location().* == c.EINTR) continue;
            return error.WriteFailed;
        }
        off += @intCast(n);
    }
}
