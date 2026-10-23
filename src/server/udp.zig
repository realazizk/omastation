//! The server's multitransport front end (MS-RDPEMT 3.2.1, MS-RDPEUDP 3.1.3): one UDP socket on the TCP
//! listener's port with its own thread, shared by every connection. It runs RDP-UDP handshakes and tunnel
//! setup, then hands each accepted tunnel (a Link) to its connection's thread. One mutex guards its state.

const std = @import("std");
const c = @import("c");
const mt = @import("../net/multitransport.zig");
const auth = @import("auth.zig");

const log = std.log.scoped(.udp);

pub const Error = error{ SocketFailed, BindFailed, SystemResources } || std.mem.Allocator.Error;

pub const Config = struct {
    /// PEM files (MS-RDPEMT 5.1: the main connection's), read for every tunnel.
    cert_path: [:0]const u8,
    key_path: [:0]const u8,
    /// MS-RDPEUDP 1.7: 1, 2, or 3 (RDPUDP_PROTOCOL_VERSION_3, MS-RDPEUDP2).
    max_version: u16 = mt.rdpudp_protocol_version_2,
    /// uReceiveWindowSize (MS-RDPEUDP 2.2.2.1): datagrams buffered.
    receive_window_size: u16 = 256,
    /// Bind to ::ffff:127.0.0.1 only (tests).
    loopback_only: bool = false,
};

/// Handshakes, tunnels, and recently closed addresses.
pub const max_peers = 64;
/// Per connection; more datagrams are dropped, as the network could.
pub const max_inbox = 4096;
/// Deadline after the SYN for the TLS / DTLS handshake and the Tunnel Create Request.
pub const setup_timeout_us: u64 = 15 * mt.us_per_s;
/// A closed address's stray datagrams are ignored this long, unless it sends a new SYN.
pub const closed_linger_us: u64 = 10 * mt.us_per_s;
/// RFC 6347 4.2.4.1: OpenSSL keeps the retransmission timer; checked this often.
const dtls_tick_us: u64 = 250 * mt.us_per_ms;
/// The largest datagram read: anything above max_mtu is not RDP-UDP.
const max_datagram = 2048;
const plain_chunk = 16 * 1024 + 256;

/// CLOCK_MONOTONIC, as conn.nowMs.
pub fn nowUs() u64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(u64, @intCast(ts.tv_sec)) * mt.us_per_s + @as(u64, @intCast(ts.tv_nsec)) / 1000;
}

/// IPv4 addresses are v4-mapped: the socket is dual-stack.
pub const Addr = struct {
    sa: c.sockaddr_in6,

    pub fn eql(a: Addr, b: Addr) bool {
        return a.sa.sin6_port == b.sa.sin6_port and a.sa.sin6_scope_id == b.sa.sin6_scope_id and
            std.mem.eql(u8, std.mem.asBytes(&a.sa.sin6_addr), std.mem.asBytes(&b.sa.sin6_addr));
    }

    pub fn text(a: *const Addr, buf: []u8) []const u8 {
        var ip: [c.INET6_ADDRSTRLEN]u8 = undefined;
        if (c.inet_ntop(c.AF_INET6, &a.sa.sin6_addr, &ip, ip.len) == null) return "?";
        return std.fmt.bufPrint(buf, "[{s}]:{d}", .{ std.mem.sliceTo(&ip, 0), c.ntohs(a.sa.sin6_port) }) catch "?";
    }
};

/// An accepted tunnel in the Established phase, handed to its connection's thread.
pub const Link = struct {
    addr: Addr,
    mode: mt.Mode,
    version: u16,
    request_id: u32,
    conn: mt.Connection,
    tunnel: mt.TunnelServer,

    pub fn deinit(k: *Link, gpa: std.mem.Allocator) void {
        k.tunnel.deinit();
        k.conn.deinit();
        gpa.destroy(k);
    }
};

pub const Item = union(enum) {
    link: *Link,
    datagram: struct { addr: Addr, bytes: []u8 },

    pub fn deinit(it: Item, gpa: std.mem.Allocator) void {
        switch (it) {
            .link => |k| k.deinit(gpa),
            .datagram => |d| gpa.free(d.bytes),
        }
    }
};

/// One connection's side of the front end (owned by the multitransport feature).
pub const Session = struct {
    listener: *Listener,
    /// The Connection Store (MS-RDPEMT 3.2.1); under the mutex.
    bootstrap: mt.Bootstrap,
    /// Readable when the inbox has something (eventfd).
    event_fd: c_int,
    /// Under the mutex.
    inbox: std.ArrayList(Item) = .empty,
    peer: []const u8,

    /// MS-RDPBCGR 2.2.15.1: a random requestId and securityCookie, kept in the Connection Store.
    pub fn request(s: *Session, protocol: u16) mt.Error!mt.InitiateRequest {
        var rnd = auth.secureRandom();
        var cookie: [16]u8 = undefined;
        rnd.bytes(&cookie);
        defer std.crypto.secureZero(u8, &cookie);
        const l = s.listener;
        l.lock();
        defer l.unlock();
        // The front end finds a tunnel's connection by requestId, so it is unique server-wide.
        const id = while (true) {
            const id = rnd.int(u32);
            if (!l.requestIdTaken(id)) break id;
        };
        return s.bootstrap.request(protocol, id, cookie);
    }

    /// An Initiate Multitransport Response (MS-RDPBCGR 3.3.5.15.2).
    pub fn onResponse(s: *Session, r: mt.InitiateResponse) mt.Error!mt.ResponseOutcome {
        s.listener.lock();
        defer s.listener.unlock();
        return s.bootstrap.onResponse(r);
    }

    /// Appends to `out`; the caller owns the items.
    pub fn take(s: *Session, gpa: std.mem.Allocator, out: *std.ArrayList(Item)) std.mem.Allocator.Error!void {
        var v: u64 = 0;
        _ = c.read(s.event_fd, &v, @sizeOf(u64));
        s.listener.lock();
        defer s.listener.unlock();
        try out.ensureUnusedCapacity(gpa, s.inbox.items.len);
        out.appendSliceAssumeCapacity(s.inbox.items);
        s.inbox.clearRetainingCapacity();
    }

    pub fn sendTo(s: *Session, addr: Addr, datagram: []const u8) void {
        s.listener.sendTo(addr, datagram);
    }

    /// Datagrams from `addr` are ignored from now on.
    pub fn forget(s: *Session, addr: Addr) void {
        const l = s.listener;
        l.lock();
        defer l.unlock();
        if (l.findPeer(addr)) |p| if (p.state == .attached and p.state.attached == s) l.closePeer(p, nowUs());
    }

    /// The connection ends: its requests and tunnels go, `s` is freed.
    pub fn leave(s: *Session) void {
        const l = s.listener;
        const gpa = l.gpa;
        {
            l.lock();
            defer l.unlock();
            for (l.sessions.items, 0..) |x, i| if (x == s) {
                _ = l.sessions.swapRemove(i);
                break;
            };
            const now = nowUs();
            for (l.peers.items) |p| {
                if (p.session == s) p.session = null;
                switch (p.state) {
                    .attached => |a| if (a == s) l.closePeer(p, now),
                    else => {},
                }
            }
        }
        for (s.inbox.items) |it| it.deinit(gpa);
        s.inbox.deinit(gpa);
        _ = c.close(s.event_fd);
        gpa.destroy(s);
    }
};

const Securing = struct {
    conn: mt.Connection,
    tunnel: mt.TunnelServer,
};

const Peer = struct {
    listener: *Listener,
    addr: Addr,
    state: union(enum) {
        handshake: mt.ServerHandshake,
        securing: Securing,
        attached: *Session,
        closed,
    },
    /// From a version 3 cookieHash or the Tunnel Create Request.
    session: ?*Session = null,
    mode: mt.Mode = .reliable,
    version: u16 = 0,
    request_id: u32 = 0,
    /// When a handshake / securing / closed entry goes (nowUs clock).
    expires_us: u64,
    next_dtls_us: u64 = 0,

    fn deinitState(p: *Peer) void {
        switch (p.state) {
            .securing => |*x| {
                x.tunnel.deinit();
                x.conn.deinit();
            },
            else => {},
        }
        p.state = .closed;
    }
};

pub const Listener = struct {
    gpa: std.mem.Allocator,
    cfg: Config,
    fd: c_int,
    wake_fd: c_int,
    port: u16,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),
    mutex: std.atomic.Mutex = .unlocked,
    sessions: std.ArrayList(*Session) = .empty,
    peers: std.ArrayList(*Peer) = .empty,

    /// Binds on the TCP listener's port and starts the front end's thread.
    pub fn start(gpa: std.mem.Allocator, port: u16, cfg: Config) Error!*Listener {
        const fd = c.socket(c.AF_INET6, c.SOCK_DGRAM | c.SOCK_CLOEXEC | c.SOCK_NONBLOCK, 0);
        if (fd < 0) return error.SocketFailed;
        errdefer _ = c.close(fd);
        const zero: c_int = 0; // dual-stack, as socket.listenTcp
        _ = c.setsockopt(fd, c.IPPROTO_IPV6, c.IPV6_V6ONLY, &zero, @sizeOf(c_int));
        // Bursts of a frame's datagrams and their acknowledgements.
        const buf_size: c_int = 4 << 20;
        _ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_RCVBUF, &buf_size, @sizeOf(c_int));
        _ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_SNDBUF, &buf_size, @sizeOf(c_int));
        var addr: c.sockaddr_in6 = std.mem.zeroes(c.sockaddr_in6);
        addr.sin6_family = c.AF_INET6;
        addr.sin6_port = c.htons(port);
        if (cfg.loopback_only) {
            const mapped = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 };
            @memcpy(std.mem.asBytes(&addr.sin6_addr), &mapped);
        } else {
            addr.sin6_addr = c.in6addr_any;
        }
        if (c.bind(fd, .{ .__sockaddr__ = @ptrCast(&addr) }, @sizeOf(c.sockaddr_in6)) != 0) return error.BindFailed;
        const wake_fd = c.eventfd(0, c.EFD_CLOEXEC | c.EFD_NONBLOCK);
        if (wake_fd < 0) return error.SystemResources;
        errdefer _ = c.close(wake_fd);
        const l = try gpa.create(Listener);
        errdefer gpa.destroy(l);
        l.* = .{ .gpa = gpa, .cfg = cfg, .fd = fd, .wake_fd = wake_fd, .port = port };
        l.thread = std.Thread.spawn(.{}, run, .{l}) catch return error.SystemResources;
        return l;
    }

    /// Stops the thread and frees everything. The sessions must have left.
    pub fn deinit(l: *Listener) void {
        l.stopping.store(true, .release);
        const one: u64 = 1;
        _ = c.write(l.wake_fd, &one, @sizeOf(u64));
        if (l.thread) |t| t.join();
        for (l.peers.items) |p| {
            p.deinitState();
            l.gpa.destroy(p);
        }
        l.peers.deinit(l.gpa);
        std.debug.assert(l.sessions.items.len == 0);
        l.sessions.deinit(l.gpa);
        _ = c.close(l.fd);
        _ = c.close(l.wake_fd);
        l.gpa.destroy(l);
    }

    fn lock(l: *Listener) void {
        while (!l.mutex.tryLock()) std.Thread.yield() catch {};
    }

    fn unlock(l: *Listener) void {
        l.mutex.unlock();
    }

    /// Flags of the Multitransport Channel Data (MS-RDPBCGR 2.2.1.3.8, 2.2.1.4.6).
    pub fn join(l: *Listener, client_flags: u32, server_flags: u32, peer: []const u8) Error!*Session {
        const efd = c.eventfd(0, c.EFD_CLOEXEC | c.EFD_NONBLOCK);
        if (efd < 0) return error.SystemResources;
        errdefer _ = c.close(efd);
        const s = try l.gpa.create(Session);
        errdefer l.gpa.destroy(s);
        s.* = .{ .listener = l, .bootstrap = mt.Bootstrap.init(client_flags, server_flags) catch unreachable, .event_fd = efd, .peer = peer };
        l.lock();
        defer l.unlock();
        try l.sessions.append(l.gpa, s);
        return s;
    }

    fn requestIdTaken(l: *const Listener, id: u32) bool {
        for (l.sessions.items) |s| {
            for (s.bootstrap.store) |slot| if (slot.state != .unused and slot.request_id == id) return true;
        }
        return false;
    }

    fn anyPending(l: *const Listener) bool {
        for (l.sessions.items) |s| {
            for (s.bootstrap.store) |slot| if (slot.state == .pending) return true;
        }
        return false;
    }

    fn sendTo(l: *Listener, addr: Addr, datagram: []const u8) void {
        while (true) {
            const n = c.sendto(l.fd, datagram.ptr, datagram.len, c.MSG_DONTWAIT | c.MSG_NOSIGNAL, .{ .__sockaddr__ = @ptrCast(&addr.sa) }, @sizeOf(c.sockaddr_in6));
            if (n >= 0) return;
            if (c.__errno_location().* == c.EINTR) continue;
            return; // a full buffer or an unreachable client: as a lost datagram
        }
    }

    fn findPeer(l: *Listener, addr: Addr) ?*Peer {
        for (l.peers.items) |p| if (p.addr.eql(addr)) return p;
        return null;
    }

    fn closePeer(l: *Listener, p: *Peer, now: u64) void {
        _ = l;
        p.deinitState();
        p.session = null;
        p.expires_us = now + closed_linger_us;
    }

    fn run(l: *Listener) void {
        var buf: [max_datagram]u8 = undefined;
        while (!l.stopping.load(.acquire)) {
            const timeout = l.pollTimeout();
            var fds = [2]c.struct_pollfd{
                .{ .fd = l.fd, .events = c.POLLIN, .revents = 0 },
                .{ .fd = l.wake_fd, .events = c.POLLIN, .revents = 0 },
            };
            _ = c.poll(&fds, 2, timeout);
            if (fds[1].revents != 0) {
                var v: u64 = 0;
                _ = c.read(l.wake_fd, &v, @sizeOf(u64));
            }
            // Bounded per pass, so timers run under a flood.
            var n: usize = 0;
            while (n < 256) : (n += 1) {
                var from: c.sockaddr_in6 = undefined;
                var flen: c.socklen_t = @sizeOf(c.sockaddr_in6);
                const r = c.recvfrom(l.fd, &buf, buf.len, c.MSG_DONTWAIT | c.MSG_TRUNC, .{ .__sockaddr__ = @ptrCast(&from) }, &flen);
                if (r < 0) break;
                const len: usize = @intCast(r);
                if (len > buf.len or from.sin6_family != c.AF_INET6) continue; // not RDP-UDP
                l.lock();
                defer l.unlock();
                l.onDatagram(.{ .sa = from }, buf[0..len], nowUs());
            }
            l.lock();
            defer l.unlock();
            l.runTimers(nowUs());
        }
    }

    fn pollTimeout(l: *Listener) c_int {
        l.lock();
        defer l.unlock();
        var at: ?u64 = null;
        for (l.peers.items) |p| {
            const t: ?u64 = switch (p.state) {
                .handshake => |*h| h.nextTimeout() catch null,
                .securing => |*x| blk: {
                    var t = x.conn.nextTimeout() catch null;
                    if (p.mode == .lossy) t = if (t) |v| @min(v, p.next_dtls_us) else p.next_dtls_us;
                    break :blk t;
                },
                else => null,
            };
            const e = if (p.state == .attached) null else @as(?u64, p.expires_us);
            for ([_]?u64{ t, e }) |x| if (x) |v| {
                at = if (at) |a| @min(a, v) else v;
            };
        }
        const a = at orelse return -1;
        const now = nowUs();
        if (a <= now) return 0;
        return @intCast(@min((a - now + 999) / 1000, 60_000));
    }

    pub fn onDatagram(l: *Listener, addr: Addr, d: []const u8, now: u64) void {
        if (l.findPeer(addr)) |p| switch (p.state) {
            .attached => |s| return l.deliver(s, addr, d),
            .handshake => return l.handshakeStep(p, d, now),
            .securing => return l.securingStep(p, d, now),
            .closed => if (!isSyn(d)) return else {
                l.removePeer(p);
            },
        };
        if (!isSyn(d)) return;
        l.newPeer(addr, d, now);
    }

    fn isSyn(d: []const u8) bool {
        return d.len >= 8 and std.mem.readInt(u16, d[6..8], .big) & mt.rdpudp_flag_syn != 0;
    }

    fn deliver(l: *Listener, s: *Session, addr: Addr, d: []const u8) void {
        if (s.inbox.items.len >= max_inbox) return;
        const copy = l.gpa.dupe(u8, d) catch return;
        s.inbox.append(l.gpa, .{ .datagram = .{ .addr = addr, .bytes = copy } }) catch {
            l.gpa.free(copy);
            return;
        };
        signal(s);
    }

    fn signal(s: *Session) void {
        const one: u64 = 1;
        _ = c.write(s.event_fd, &one, @sizeOf(u64));
    }

    fn newPeer(l: *Listener, addr: Addr, d: []const u8, now: u64) void {
        var abuf: [64]u8 = undefined;
        // Nobody waits for a tunnel: the port stays silent.
        if (!l.anyPending()) return;
        const syn = mt.decodeSyn(d) catch |err| return log.debug("{s}: bad SYN: {t}", .{ addr.text(&abuf), err });
        // 3.1.5.1.1 step 6: the SYN is padded to its smaller MTU, so the SYN+ACK is no larger.
        if (d.len < @min(syn.syn_data.up_stream_mtu, syn.syn_data.down_stream_mtu)) return log.debug("{s}: SYN of {d} bytes, not padded (ignored)", .{ addr.text(&abuf), d.len });
        // A full table evicts a closed entry, else the oldest handshake; never a client that answered
        // the SYN+ACK (it owns its address, which a spoofed SYN flood does not).
        if (l.peers.items.len >= max_peers) {
            var victim: ?*Peer = null;
            for (l.peers.items) |p| {
                const rank: u8 = switch (p.state) {
                    .closed => 0,
                    .handshake => 1,
                    else => continue,
                };
                if (victim) |v| {
                    const vr: u8 = if (v.state == .closed) 0 else 1;
                    if (rank > vr or (rank == vr and p.expires_us >= v.expires_us)) continue;
                }
                victim = p;
            }
            const v = victim orelse return log.debug("{s}: {d} UDP clients in setup or tunnels already; SYN ignored", .{ addr.text(&abuf), max_peers });
            l.removePeer(v);
        }
        // A version 3 SYN names its request with the cookie's hash.
        var session: ?*Session = null;
        var cookie: [16]u8 = @splat(0);
        defer std.crypto.secureZero(u8, &cookie);
        if (syn.synex) |x| if (x.cookie_hash) |h| for (l.sessions.items) |s| {
            if (s.bootstrap.cookieForHash(h)) |ck| {
                session = s;
                cookie = ck;
                break;
            }
        };
        var rnd = auth.secureRandom();
        var h = mt.ServerHandshake.init(.{
            .receive_window_size = l.cfg.receive_window_size,
            .initial_sequence_number = rnd.int(u32),
            // Version 3 only for a SYN that named its connection (3.1.5.1.1 step 5).
            .max_version = if (session != null) l.cfg.max_version else @min(l.cfg.max_version, mt.rdpudp_protocol_version_2),
        }, cookie) catch return;
        h.onDatagram(d, now) catch |err| return log.debug("{s}: SYN refused: {t}", .{ addr.text(&abuf), err });
        const p = l.gpa.create(Peer) catch return;
        p.* = .{ .listener = l, .addr = addr, .state = .{ .handshake = h }, .session = session, .mode = if (syn.lossy) .lossy else .reliable, .expires_us = now + setup_timeout_us };
        l.peers.append(l.gpa, p) catch {
            l.gpa.destroy(p);
            return;
        };
        log.info("{s}: RDP-UDP SYN ({s}, version {d}{s})", .{ addr.text(&abuf), @tagName(p.mode), announced(syn), if (session != null) ", cookie hash known" else "" });
        l.flushHandshake(p, now);
    }

    fn announced(syn: mt.Syn) u16 {
        const x = syn.synex orelse return mt.rdpudp_protocol_version_1;
        return if (x.flags & mt.rdpudp_version_info_valid != 0) x.version else mt.rdpudp_protocol_version_1;
    }

    fn removePeer(l: *Listener, p: *Peer) void {
        for (l.peers.items, 0..) |x, i| if (x == p) {
            _ = l.peers.swapRemove(i);
            break;
        };
        p.deinitState();
        l.gpa.destroy(p);
    }

    fn flushHandshake(l: *Listener, p: *Peer, now: u64) void {
        var out: [mt.max_mtu]u8 = undefined;
        while (p.state.handshake.poll(now, &out) catch null) |d| l.sendTo(p.addr, d);
    }

    fn handshakeStep(l: *Listener, p: *Peer, d: []const u8, now: u64) void {
        const h = &p.state.handshake;
        h.onDatagram(d, now) catch return; // malformed: ignored
        if ((h.state() catch .closed) != .established) return l.flushHandshake(p, now);
        var abuf: [64]u8 = undefined;
        const n = h.negotiated() catch return l.closePeer(p, now);
        p.version = n.version;
        // 3.1.5.2 step 4: the ACK that completed the handshake may carry data.
        var conn = mt.Connection.init(l.gpa, n) catch |err| {
            log.info("{s}: RDP-UDP version {d} not served: {t}", .{ peerText(p, &abuf), n.version, err });
            return l.closePeer(p, now);
        };
        conn.onDatagram(d, now) catch {};
        const max_dtls: usize = switch (conn) {
            .rdpudp => |*e| e.maxPayload() catch mt.min_mtu,
            .rdpudp2 => mt.min_mtu, // reliable only: TLS
        };
        const proto = mt.securityFor(n.mode) catch unreachable;
        const tunnel = mt.TunnelServer.initAccepting(l.gpa, proto, l.cfg.cert_path, l.cfg.key_path, .{ .lookup = .{ .ctx = p, .accept = accept } }, max_dtls) catch |err| {
            conn.deinit();
            log.warn("{s}: no {s} for the tunnel: {t}", .{ peerText(p, &abuf), @tagName(proto), err });
            return l.closePeer(p, now);
        };
        log.info("{s}: RDP-UDP established, version {d} ({s}), {s} handshake", .{ peerText(p, &abuf), n.version, @tagName(n.phase), @tagName(proto) });
        p.state = .{ .securing = .{ .conn = conn, .tunnel = tunnel } };
        p.next_dtls_us = now + dtls_tick_us;
        l.securingPump(p, now);
    }

    fn peerText(p: *const Peer, buf: []u8) []const u8 {
        return p.addr.text(buf);
    }

    fn securingStep(l: *Listener, p: *Peer, d: []const u8, now: u64) void {
        const x = &p.state.securing;
        x.conn.onDatagram(d, now) catch return; // malformed: ignored (MS-RDPEUDP 5.1.2)
        l.securingPump(p, now);
    }

    /// Pumps RDP-UDP and TLS / DTLS; hands the tunnel over once accepted.
    fn securingPump(l: *Listener, p: *Peer, now: u64) void {
        var abuf: [64]u8 = undefined;
        const x = &p.state.securing;
        var plain: [plain_chunk]u8 = undefined;
        while (x.conn.receive(&plain) catch null) |ct| {
            x.tunnel.onTransport(ct) catch |err| {
                log.info("{s}: tunnel refused: {t}", .{ peerText(p, &abuf), err });
                // The alert (if any) still goes out.
                l.securingOut(p, now);
                return l.closePeer(p, now);
            };
        }
        l.securingOut(p, now);
        if ((x.conn.state() catch .closed) == .closed) {
            log.info("{s}: RDP-UDP connection lost during setup", .{peerText(p, &abuf)});
            return l.closePeer(p, now);
        }
        if ((x.tunnel.phase() catch .closed) != .established) return;
        const s = p.session orelse return l.closePeer(p, now);
        const k = l.gpa.create(Link) catch return l.closePeer(p, now);
        k.* = .{ .addr = p.addr, .mode = p.mode, .version = p.version, .request_id = p.request_id, .conn = x.conn, .tunnel = x.tunnel };
        s.inbox.append(l.gpa, .{ .link = k }) catch {
            l.gpa.destroy(k);
            return l.closePeer(p, now);
        };
        // The Link owns them now.
        p.state = .{ .attached = s };
        log.info("{s}: tunnel for {s} (request {d}) established", .{ peerText(p, &abuf), s.peer, p.request_id });
        signal(s);
    }

    fn securingOut(l: *Listener, p: *Peer, now: u64) void {
        const x = &p.state.securing;
        var buf: [plain_chunk]u8 = undefined;
        while (x.tunnel.pollTransport(&buf) catch null) |ct| x.conn.send(ct) catch break;
        var out: [mt.max_mtu]u8 = undefined;
        while (x.conn.poll(now, &out) catch null) |d| l.sendTo(p.addr, d);
    }

    /// TunnelServer.Lookup (MS-RDPEMT 3.2.1); the mode must be the requested protocol's
    /// (MS-RDPBCGR 2.2.15.1). Called with the mutex held.
    fn accept(ctx: *anyopaque, r: mt.TunnelCreateRequest) mt.TransportError!u32 {
        const p: *Peer = @ptrCast(@alignCast(ctx));
        const l = p.listener;
        for (l.sessions.items) |s| {
            if (p.session) |named| if (named != s) continue;
            const proto = s.bootstrap.pendingProtocol(r.request_id) orelse continue;
            if (try mt.modeOfProtocol(proto) != p.mode) return error.InvalidField;
            const hr = try s.bootstrap.onTunnelCreate(r);
            p.session = s;
            p.request_id = r.request_id;
            return hr;
        }
        return error.UnknownRequest;
    }

    pub fn runTimers(l: *Listener, now: u64) void {
        var i: usize = 0;
        while (i < l.peers.items.len) {
            const p = l.peers.items[i];
            switch (p.state) {
                .handshake => |*h| {
                    l.flushHandshake(p, now);
                    if ((h.state() catch .closed) == .closed) l.closePeer(p, now);
                },
                .securing => |*x| {
                    if (p.mode == .lossy and now >= p.next_dtls_us) {
                        p.next_dtls_us = now + dtls_tick_us;
                        x.tunnel.sc.onTimeout(now) catch {};
                    }
                    l.securingPump(p, now);
                },
                else => {},
            }
            if (p.state != .attached and now >= p.expires_us) {
                if (p.state != .closed) {
                    var abuf: [64]u8 = undefined;
                    log.info("{s}: tunnel setup timed out", .{peerText(p, &abuf)});
                }
                l.removePeer(p);
                continue;
            }
            i += 1;
        }
    }
};
