//! MS-RDPEMT 5.1: TLS (reliable) or DTLS (lossy) security for a multitransport
//! connection with the main connection's certificate, and the tunnel inside it
//! (3.1.5.5, 3.2.5.1). Sans-IO OpenSSL over memory BIOs.

const std = @import("std");
const c = @import("c");
const bytes = @import("../../core/bytes.zig");
const mt = @import("../multitransport.zig");

const TransportError = mt.TransportError;

pub const SecurityProtocol = enum { tls, dtls };

// SSL_OP_* bits; the SSL_OP_BIT macro does not survive translate-c.
const ssl_op_cleanse_plaintext: u64 = 1 << 1;
const ssl_op_no_query_mtu: u64 = 1 << 12;
const ssl_op_no_compression: u64 = 1 << 17;
const ssl_op_no_renegotiation: u64 = 1 << 30;

fn clearErrors() void {
    c.ERR_clear_error();
}

/// Server end of the TLS / DTLS session. Ciphertext goes in with feed() and out of
/// pollOutgoing(); for DTLS each is one datagram of at most `max_datagram` bytes.
pub const SecureChannel = struct {
    gpa: std.mem.Allocator,
    protocol: SecurityProtocol,
    ctx: *c.SSL_CTX,
    ssl: *c.SSL,
    /// Ciphertext from the peer (read by OpenSSL).
    rbio: *c.BIO,
    /// Ciphertext for the peer (written by OpenSSL).
    wbio: *c.BIO,
    max_datagram: usize,
    failed: bool = false,

    pub fn init(gpa: std.mem.Allocator, protocol: SecurityProtocol, cert_path: [:0]const u8, key_path: [:0]const u8, max_datagram: usize) TransportError!SecureChannel {
        const dtls = protocol == .dtls;
        const ctx = c.SSL_CTX_new(if (dtls) c.DTLS_server_method() else c.TLS_server_method()) orelse return error.SecurityHandshakeFailed;
        errdefer c.SSL_CTX_free(ctx);
        if (c.SSL_CTX_set_min_proto_version(ctx, if (dtls) c.DTLS1_2_VERSION else c.TLS1_2_VERSION) != 1) return error.SecurityHandshakeFailed;
        _ = c.SSL_CTX_set_options(ctx, ssl_op_no_compression | ssl_op_no_renegotiation | ssl_op_cleanse_plaintext);
        // No session tickets (RDP never resumes).
        _ = c.SSL_CTX_set_num_tickets(ctx, 0);
        // MS-RDPEMT 5.1: the main connection's certificate.
        if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_path.ptr) != 1 or
            c.SSL_CTX_use_PrivateKey_file(ctx, key_path.ptr, c.SSL_FILETYPE_PEM) != 1 or
            c.SSL_CTX_check_private_key(ctx) != 1)
        {
            clearErrors();
            return error.SecurityHandshakeFailed;
        }
        const ssl = c.SSL_new(ctx) orelse return error.SecurityHandshakeFailed;
        errdefer c.SSL_free(ssl);
        const method = if (dtls) c.BIO_s_dgram_mem() else c.BIO_s_mem();
        const rbio = c.BIO_new(method) orelse return error.OutOfMemory;
        const wbio = c.BIO_new(method) orelse {
            _ = c.BIO_free(rbio);
            return error.OutOfMemory;
        };
        c.SSL_set_bio(ssl, rbio, wbio);
        if (dtls) {
            // The datagram size is set here, not discovered by the BIO.
            _ = c.SSL_set_options(ssl, ssl_op_no_query_mtu);
            if (c.SSL_ctrl(ssl, c.SSL_CTRL_SET_MTU, @intCast(max_datagram), null) == 0) {
                clearErrors();
                return error.InvalidField;
            }
        }
        c.SSL_set_accept_state(ssl);
        return .{ .gpa = gpa, .protocol = protocol, .ctx = ctx, .ssl = ssl, .rbio = rbio, .wbio = wbio, .max_datagram = max_datagram };
    }

    pub fn deinit(s: *SecureChannel) void {
        c.SSL_free(s.ssl); // frees the BIOs
        c.SSL_CTX_free(s.ctx);
    }

    fn step(s: *SecureChannel) TransportError!void {
        if (s.failed) return error.SecurityHandshakeFailed;
        if (c.SSL_is_init_finished(s.ssl) == 1) return;
        const r = c.SSL_do_handshake(s.ssl);
        if (r == 1) return;
        const e = c.SSL_get_error(s.ssl, r);
        if (e == c.SSL_ERROR_WANT_READ or e == c.SSL_ERROR_WANT_WRITE) return;
        clearErrors();
        s.failed = true;
        return error.SecurityHandshakeFailed;
    }

    /// Ciphertext from the RDP-UDP layer.
    pub fn feed(s: *SecureChannel, data: []const u8) TransportError!void {
        if (s.failed) return error.SecurityHandshakeFailed;
        if (data.len == 0) return;
        if (data.len > std.math.maxInt(c_int)) return error.MessageTooLarge;
        if (c.BIO_write(s.rbio, data.ptr, @intCast(data.len)) != @as(c_int, @intCast(data.len))) {
            clearErrors();
            return error.OutOfMemory;
        }
        try s.step();
    }

    /// Ciphertext for the RDP-UDP layer, or null.
    pub fn pollOutgoing(s: *SecureChannel, out: []u8) TransportError!?[]u8 {
        const pending = c.BIO_ctrl(s.wbio, c.BIO_CTRL_PENDING, 0, null);
        if (pending <= 0) return null;
        // A datagram is read whole or not at all.
        if (s.protocol == .dtls and out.len < @as(usize, @intCast(pending))) return error.EndOfBuffer;
        if (out.len == 0) return error.EndOfBuffer;
        const n = c.BIO_read(s.wbio, out.ptr, @intCast(@min(out.len, std.math.maxInt(c_int))));
        if (n <= 0) return null;
        return out[0..@intCast(n)];
    }

    pub fn handshakeDone(s: *const SecureChannel) TransportError!bool {
        return !s.failed and c.SSL_is_init_finished(s.ssl) == 1;
    }

    /// error.NotEstablished before the handshake; DTLS: error.MessageTooLarge past one datagram.
    pub fn write(s: *SecureChannel, plaintext: []const u8) TransportError!void {
        if (!try s.handshakeDone()) return error.NotEstablished;
        // RFC 6347 4.1.1: a record fits one datagram; OpenSSL does not enforce it for application data.
        if (s.protocol == .dtls and plaintext.len > c.DTLS_get_data_mtu(s.ssl)) return error.MessageTooLarge;
        var n: usize = 0;
        if (c.SSL_write_ex(s.ssl, plaintext.ptr, plaintext.len, &n) != 1 or n != plaintext.len) {
            clearErrors();
            return if (s.protocol == .dtls) error.MessageTooLarge else error.ConnectionClosed;
        }
    }

    /// The peer sent its close_notify.
    pub fn peerClosed(s: *const SecureChannel) bool {
        return c.SSL_get_shutdown(s.ssl) & c.SSL_RECEIVED_SHUTDOWN != 0;
    }

    /// Decrypted application data, or null.
    pub fn read(s: *SecureChannel, out: []u8) TransportError!?[]u8 {
        if (!try s.handshakeDone()) return null;
        if (out.len == 0) return error.EndOfBuffer;
        var n: usize = 0;
        const r = c.SSL_read_ex(s.ssl, out.ptr, out.len, &n);
        if (r == 1) return out[0..n];
        const e = c.SSL_get_error(s.ssl, r);
        if (e == c.SSL_ERROR_WANT_READ or e == c.SSL_ERROR_WANT_WRITE) return null;
        clearErrors();
        return error.ConnectionClosed;
    }

    /// DTLS retransmission timer (RFC 6347 4.2.4); OpenSSL keeps its own clock.
    pub fn onTimeout(s: *SecureChannel, now_us: u64) TransportError!void {
        _ = now_us;
        if (s.protocol != .dtls) return;
        if (c.SSL_ctrl(s.ssl, c.DTLS_CTRL_HANDLE_TIMEOUT, 0, null) < 0) {
            clearErrors();
            s.failed = true;
            return error.SecurityHandshakeFailed;
        }
    }

    /// Sends a close_notify alert (best effort).
    pub fn shutdown(s: *SecureChannel) void {
        if (c.SSL_is_init_finished(s.ssl) == 1) _ = c.SSL_shutdown(s.ssl);
        clearErrors();
    }
};

/// Server side of a multitransport tunnel: the TLS / DTLS handshake, the Tunnel Create
/// Request checked against the Connection Store (MS-RDPEMT 3.2.5.1), then Tunnel Data (3.1.5.5).
pub const TunnelServer = struct {
    pub const Phase = enum { security_handshake, awaiting_create_request, established, closed };

    /// Checks the Tunnel Create Request (MS-RDPEMT 3.2.1): one connection's Bootstrap, or a
    /// server-wide lookup when the transport carries no cookie before it (RDP-UDP 1 and 2).
    pub const Acceptor = union(enum) {
        bootstrap: *mt.Bootstrap,
        lookup: Lookup,
    };

    pub const Lookup = struct {
        ctx: *anyopaque,
        accept: *const fn (ctx: *anyopaque, r: mt.TunnelCreateRequest) TransportError!u32,
    };

    /// Raw SubHeaders field (MS-RDPEMT 2.2.1.1, see SubHeaderIterator) and payload.
    pub const Data = struct { subheaders: []u8, payload: []u8 };

    const Held = struct {
        /// SubHeaders, then the payload.
        buf: []u8,
        sub_len: usize,
    };

    gpa: std.mem.Allocator,
    sc: SecureChannel,
    acceptor: Acceptor,
    phase_: Phase = .security_handshake,
    request_id: ?u32 = null,
    /// TLS: plaintext not yet a whole tunnel PDU.
    pending: std.ArrayList(u8) = .empty,
    received: std.ArrayList(Held) = .empty,
    received_head: usize = 0,

    /// `max_datagram`: largest DTLS datagram (Engine.maxPayload()); ignored for TLS.
    pub fn init(gpa: std.mem.Allocator, protocol: SecurityProtocol, cert_path: [:0]const u8, key_path: [:0]const u8, bootstrap: *mt.Bootstrap, max_datagram: usize) TransportError!TunnelServer {
        return initAccepting(gpa, protocol, cert_path, key_path, .{ .bootstrap = bootstrap }, max_datagram);
    }

    pub fn initAccepting(gpa: std.mem.Allocator, protocol: SecurityProtocol, cert_path: [:0]const u8, key_path: [:0]const u8, acceptor: Acceptor, max_datagram: usize) TransportError!TunnelServer {
        return .{ .gpa = gpa, .sc = try SecureChannel.init(gpa, protocol, cert_path, key_path, max_datagram), .acceptor = acceptor };
    }

    pub fn deinit(t: *TunnelServer) void {
        t.sc.deinit();
        t.pending.deinit(t.gpa);
        for (t.received.items[t.received_head..]) |p| t.gpa.free(p.buf);
        t.received.deinit(t.gpa);
    }

    fn close(t: *TunnelServer) void {
        if (t.phase_ == .closed) return;
        t.phase_ = .closed;
        t.sc.shutdown();
    }

    /// Queues a close_notify for pollTransport; MS-RDPEMT 1.3.3 has no termination PDU.
    pub fn shutdown(t: *TunnelServer) void {
        t.close();
    }

    /// Ciphertext from the RDP-UDP layer (one datagram for DTLS).
    pub fn onTransport(t: *TunnelServer, data: []const u8) TransportError!void {
        if (t.phase_ == .closed) return;
        t.sc.feed(data) catch |err| {
            t.close();
            return err;
        };
        if (t.phase_ == .security_handshake) {
            if (!try t.sc.handshakeDone()) return;
            t.phase_ = .awaiting_create_request;
        }
        var buf: [16 * 1024 + 256]u8 = undefined;
        while (t.phase_ != .closed) {
            const plain = (t.sc.read(&buf) catch |err| {
                t.close();
                return err;
            }) orelse break;
            t.onPlaintext(plain) catch |err| {
                t.close();
                return err;
            };
        }
    }

    /// Tunnel PDUs: a byte stream over TLS; each DTLS record holds whole PDUs.
    fn onPlaintext(t: *TunnelServer, plain: []const u8) TransportError!void {
        if (t.sc.protocol == .dtls) {
            var rest = plain;
            while (rest.len > 0) {
                const d = try mt.decodeTunnelPdu(rest);
                try t.onPdu(d.pdu);
                rest = rest[d.size..];
            }
            return;
        }
        try t.pending.appendSlice(t.gpa, plain);
        var off: usize = 0;
        defer {
            const left = t.pending.items.len - off;
            std.mem.copyForwards(u8, t.pending.items[0..left], t.pending.items[off..]);
            t.pending.shrinkRetainingCapacity(left);
        }
        while (off < t.pending.items.len) {
            const d = mt.decodeTunnelPdu(t.pending.items[off..]) catch |err| switch (err) {
                error.EndOfBuffer => break, // the rest of the PDU follows
                else => return err,
            };
            try t.onPdu(d.pdu);
            if (t.phase_ == .closed) return;
            off += d.size;
        }
    }

    fn onPdu(t: *TunnelServer, pdu: mt.TunnelPdu) TransportError!void {
        switch (t.phase_) {
            .awaiting_create_request => switch (pdu) {
                .create_request => |r| {
                    // 3.2.5.1: RequestID and SecurityCookie must match; Windows closes otherwise.
                    _ = switch (t.acceptor) {
                        .bootstrap => |b| try b.onTunnelCreate(r),
                        .lookup => |l| try l.accept(l.ctx, r),
                    };
                    t.request_id = r.request_id;
                    var o: [8]u8 = undefined;
                    try t.sc.write(try encodeInto(&o, mt.encodeTunnelCreateResponse, mt.TunnelCreateResponse{ .hr_response = mt.s_ok }));
                    t.phase_ = .established;
                },
                // 3.1.5.5: the Create Request comes first.
                else => return error.OutOfSequence,
            },
            .established => switch (pdu) {
                .data => |d| {
                    const copy = try t.gpa.alloc(u8, d.subheaders.len + d.payload.len);
                    errdefer t.gpa.free(copy);
                    @memcpy(copy[0..d.subheaders.len], d.subheaders);
                    @memcpy(copy[d.subheaders.len..], d.payload);
                    try t.received.append(t.gpa, .{ .buf = copy, .sub_len = d.subheaders.len });
                },
                // A repeated Create Request or a Create Response is ignored.
                else => {},
            },
            else => return error.OutOfSequence,
        }
    }

    /// Ciphertext for the RDP-UDP layer, or null.
    pub fn pollTransport(t: *TunnelServer, out: []u8) TransportError!?[]u8 {
        return t.sc.pollOutgoing(out);
    }

    pub fn phase(t: *const TunnelServer) TransportError!Phase {
        return t.phase_;
    }

    /// The client sent its close_notify.
    pub fn closedByPeer(t: *const TunnelServer) bool {
        return t.sc.peerClosed();
    }

    pub fn requestId(t: *const TunnelServer) TransportError!?u32 {
        return t.request_id;
    }

    /// The payload of the next Tunnel Data PDU (subheaders dropped).
    pub fn receive(t: *TunnelServer, out: []u8) TransportError!?[]u8 {
        if (t.received_head == t.received.items.len) return null;
        const p = t.received.items[t.received_head];
        const n = p.buf.len - p.sub_len;
        if (out.len < n) return error.EndOfBuffer;
        @memcpy(out[0..n], p.buf[p.sub_len..]);
        t.drop();
        return out[0..n];
    }

    /// error.EndOfBuffer, with nothing consumed, when the PDU does not fit `out`.
    pub fn receiveData(t: *TunnelServer, out: []u8) TransportError!?Data {
        if (t.received_head == t.received.items.len) return null;
        const p = t.received.items[t.received_head];
        if (out.len < p.buf.len) return error.EndOfBuffer;
        @memcpy(out[0..p.buf.len], p.buf);
        t.drop();
        return .{ .subheaders = out[0..p.sub_len], .payload = out[p.sub_len..p.buf.len] };
    }

    fn drop(t: *TunnelServer) void {
        t.gpa.free(t.received.items[t.received_head].buf);
        t.received_head += 1;
        if (t.received_head == t.received.items.len) {
            t.received.clearRetainingCapacity();
            t.received_head = 0;
        }
    }

    pub fn receivedCount(t: *const TunnelServer) usize {
        return t.received.items.len - t.received_head;
    }

    /// error.NotEstablished before the Create Response went out.
    pub fn send(t: *TunnelServer, payload: []const u8) TransportError!void {
        return t.sendWith(&.{}, payload);
    }

    /// send with RDP_TUNNEL_SUBHEADERs (MS-RDPEMT 2.2.1.1.1); the payload may be empty.
    pub fn sendWith(t: *TunnelServer, subheaders: []const mt.SubHeader, payload: []const u8) TransportError!void {
        if (t.phase_ != .established) return error.NotEstablished;
        if (payload.len > 0xffff) return error.MessageTooLarge;
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(t.gpa);
        var w = bytes.Writer.init(&list, t.gpa);
        mt.encodeTunnelData(&w, subheaders, payload) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.MessageTooLarge,
        };
        try t.sc.write(list.items);
    }
};

fn encodeInto(out: []u8, comptime f: anytype, v: anytype) TransportError![]u8 {
    var fba = std.heap.FixedBufferAllocator.init(out);
    var list = std.ArrayList(u8).initCapacity(fba.allocator(), out.len) catch return error.OutOfMemory;
    var w = bytes.Writer.init(&list, fba.allocator());
    f(&w, v) catch return error.InvalidField;
    return list.items;
}
