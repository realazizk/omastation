//! TLS server via OpenSSL, and the server certificate: a self-signed RSA-2048/SHA-256
//! certificate (serverAuth EKU, host name as CN and SAN) generated on first run.

const std = @import("std");
const c = @import("c");
const socket = @import("socket.zig");

const log = std.log.scoped(.tls);

pub const Error = error{
    TlsInitFailed,
    CertificateFailed,
    HandshakeFailed,
    TlsReadFailed,
    TlsWriteFailed,
    ConnectionClosed,
    OutOfMemory,
    /// SSL_ERROR_WANT_READ/WRITE: call again with the same data once the socket is ready.
    WouldBlock,
};

fn logErrors(what: []const u8) void {
    var buf: [256]u8 = undefined;
    while (true) {
        const e = c.ERR_get_error();
        if (e == 0) break;
        c.ERR_error_string_n(e, &buf, buf.len);
        log.err("{s}: {s}", .{ what, std.mem.sliceTo(&buf, 0) });
    }
}

pub const Context = struct {
    ctx: *c.SSL_CTX,
    /// DER PKCS#1 RSAPublicKey, for CredSSP's public-key binding.
    public_key: []u8,
    gpa: std.mem.Allocator,

    /// Loads `cert_path`/`key_path`, creating a self-signed pair if absent.
    pub fn init(gpa: std.mem.Allocator, cert_path: [:0]const u8, key_path: [:0]const u8, hostname: [:0]const u8) Error!Context {
        if (c.access(cert_path.ptr, c.R_OK) != 0 or c.access(key_path.ptr, c.R_OK) != 0) {
            log.info("generating self-signed certificate for {s} at {s}", .{ hostname, cert_path });
            try generateSelfSigned(cert_path, key_path, hostname);
        }

        const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse {
            logErrors("SSL_CTX_new");
            return error.TlsInitFailed;
        };
        errdefer c.SSL_CTX_free(ctx);
        // TLS 1.2 is the floor Windows clients negotiate; 1.3 is allowed when both sides support it.
        if (c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION) != 1) return error.TlsInitFailed;
        if (c.getenv("OMASTATION_TLS12_ONLY") != null) _ = c.SSL_CTX_set_max_proto_version(ctx, c.TLS1_2_VERSION);
        // SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION | SSL_OP_CLEANSE_PLAINTEXT (wipes decrypted
        // passwords and keystrokes); the SSL_OP_BIT macro does not survive translate-c.
        _ = c.SSL_CTX_set_options(ctx, (@as(u64, 1) << 17) | (@as(u64, 1) << 30) | (@as(u64, 1) << 1));
        // No TLS 1.3 session tickets: Windows clients take NewSessionTicket before the first TSRequest
        // as a renegotiation, and RDP never resumes TLS sessions.
        _ = c.SSL_CTX_set_num_tickets(ctx, 0);
        if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_path.ptr) != 1) {
            logErrors("load certificate");
            return error.CertificateFailed;
        }
        if (c.SSL_CTX_use_PrivateKey_file(ctx, key_path.ptr, c.SSL_FILETYPE_PEM) != 1 or c.SSL_CTX_check_private_key(ctx) != 1) {
            logErrors("load private key");
            return error.CertificateFailed;
        }

        const cert = c.SSL_CTX_get0_certificate(ctx) orelse return error.CertificateFailed;
        const pkey = c.X509_get0_pubkey(cert) orelse return error.CertificateFailed;
        const len = c.i2d_PublicKey(pkey, null);
        if (len <= 0) return error.CertificateFailed;
        const pk = try gpa.alloc(u8, @intCast(len));
        errdefer gpa.free(pk);
        var p: [*c]u8 = pk.ptr;
        if (c.i2d_PublicKey(pkey, &p) != len) return error.CertificateFailed;

        return .{ .ctx = ctx, .public_key = pk, .gpa = gpa };
    }

    pub fn deinit(self: *Context) void {
        self.gpa.free(self.public_key);
        c.SSL_CTX_free(self.ctx);
    }

    pub fn accept(self: *Context, fd: socket.Fd) Error!Session {
        const ssl = c.SSL_new(self.ctx) orelse return error.TlsInitFailed;
        errdefer c.SSL_free(ssl);
        if (c.SSL_set_fd(ssl, fd) != 1) return error.TlsInitFailed;
        // writeSome may retry from a moved buffer: the send queue grows and compacts.
        _ = c.SSL_set_mode(ssl, c.SSL_MODE_ENABLE_PARTIAL_WRITE | c.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        if (c.SSL_accept(ssl) != 1) {
            logErrors("handshake");
            return error.HandshakeFailed;
        }
        log.info("handshake done: {s} {s}", .{ c.SSL_get_version(ssl), c.SSL_get_cipher_name(ssl) });
        return .{ .ssl = ssl };
    }
};

pub const Session = struct {
    ssl: *c.SSL,
    /// The peer sent close_notify (RFC 8446 6.1): a deliberate close, not a network loss.
    closed_cleanly: bool = false,
    /// A read hit SSL_ERROR_WANT_WRITE: poll for POLLOUT, then read again.
    read_wants_write: bool = false,

    /// error.WouldBlock while no whole record is buffered.
    pub fn readSome(self: *Session, buf: []u8) Error!usize {
        var n: usize = 0;
        self.read_wants_write = false;
        if (c.SSL_read_ex(self.ssl, buf.ptr, buf.len, &n) == 1) return n;
        return switch (c.SSL_get_error(self.ssl, 0)) {
            c.SSL_ERROR_WANT_READ => error.WouldBlock,
            c.SSL_ERROR_WANT_WRITE => blk: {
                self.read_wants_write = true;
                break :blk error.WouldBlock;
            },
            c.SSL_ERROR_ZERO_RETURN => blk: {
                self.closed_cleanly = true;
                break :blk error.ConnectionClosed;
            },
            c.SSL_ERROR_SYSCALL => error.ConnectionClosed,
            else => blk: {
                // EOF without close_notify is a lost connection (OpenSSL 3 reports it here, 1.1 as SYSCALL).
                if (unexpectedEof()) {
                    c.ERR_clear_error();
                    break :blk error.ConnectionClosed;
                }
                logErrors("read");
                break :blk error.TlsReadFailed;
            },
        };
    }

    /// Bytes of `data` sent as records (at least one), or error.WouldBlock. After WouldBlock the next
    /// call must pass data starting with the same bytes (SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER).
    pub fn writeSome(self: *Session, data: []const u8) Error!usize {
        std.debug.assert(data.len > 0);
        var n: usize = 0;
        if (c.SSL_write_ex(self.ssl, data.ptr, data.len, &n) == 1) return n;
        return switch (c.SSL_get_error(self.ssl, 0)) {
            // WANT_READ is not expected with renegotiation off; the session loop retries on its next pass.
            c.SSL_ERROR_WANT_WRITE, c.SSL_ERROR_WANT_READ => error.WouldBlock,
            c.SSL_ERROR_ZERO_RETURN, c.SSL_ERROR_SYSCALL => blk: {
                c.ERR_clear_error();
                break :blk error.TlsWriteFailed;
            },
            else => blk: {
                logErrors("write");
                break :blk error.TlsWriteFailed;
            },
        };
    }

    fn unexpectedEof() bool {
        const e = c.ERR_peek_error();
        return e != 0 and c.ERR_GET_LIB(e) == c.ERR_LIB_SSL and c.ERR_GET_REASON(e) == c.SSL_R_UNEXPECTED_EOF_WHILE_READING;
    }

    /// Decrypted bytes buffered inside OpenSSL (poll() can't see them).
    pub fn pending(self: *const Session) bool {
        return c.SSL_pending(self.ssl) > 0;
    }

    /// Blocking socket only (the connection sequence).
    pub fn writeAll(self: *Session, data: []const u8) Error!void {
        var off: usize = 0;
        while (off < data.len) {
            var n: usize = 0;
            if (c.SSL_write_ex(self.ssl, data.ptr + off, data.len - off, &n) != 1) {
                logErrors("write");
                return error.TlsWriteFailed;
            }
            off += n;
        }
    }

    pub fn deinit(self: *Session) void {
        // The close_notify may not fit on a non-blocking socket; nothing to report.
        _ = c.SSL_shutdown(self.ssl);
        c.ERR_clear_error();
        c.SSL_free(self.ssl);
    }
};

pub fn generateSelfSigned(cert_path: [:0]const u8, key_path: [:0]const u8, hostname: [:0]const u8) Error!void {
    const kctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null) orelse return error.CertificateFailed;
    defer c.EVP_PKEY_CTX_free(kctx);
    var pkey: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_keygen_init(kctx) != 1 or
        c.EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) != 1 or
        c.EVP_PKEY_keygen(kctx, &pkey) != 1)
    {
        logErrors("keygen");
        return error.CertificateFailed;
    }
    defer c.EVP_PKEY_free(pkey);

    const x = c.X509_new() orelse return error.CertificateFailed;
    defer c.X509_free(x);
    _ = c.X509_set_version(x, 2); // v3
    var serial: [16]u8 = undefined;
    if (c.RAND_bytes(&serial, serial.len) != 1) return error.CertificateFailed;
    serial[0] &= 0x7F; // positive
    const bn = c.BN_bin2bn(&serial, serial.len, null) orelse return error.CertificateFailed;
    defer c.BN_free(bn);
    _ = c.BN_to_ASN1_INTEGER(bn, c.X509_get_serialNumber(x));
    _ = c.X509_gmtime_adj(c.X509_getm_notBefore(x), -3600);
    _ = c.X509_gmtime_adj(c.X509_getm_notAfter(x), 10 * 365 * 24 * 3600);
    _ = c.X509_set_pubkey(x, pkey);

    const name = c.X509_get_subject_name(x);
    _ = c.X509_NAME_add_entry_by_txt(name, "CN", c.MBSTRING_ASC, hostname.ptr, -1, -1, 0);
    _ = c.X509_set_issuer_name(x, name);

    var v3: c.X509V3_CTX = undefined;
    c.X509V3_set_ctx(&v3, x, x, null, null, 0);
    // SAN: host name, its mDNS name and every current IP address; Windows clients delegate saved
    // credentials only to a server whose trusted certificate matches the typed address.
    var san_buf: [2048]u8 = undefined;
    const san = buildSan(&san_buf, hostname) catch return error.CertificateFailed;
    inline for (.{
        .{ c.NID_subject_alt_name, san.ptr },
        .{ c.NID_ext_key_usage, "serverAuth" },
        .{ c.NID_key_usage, "critical,digitalSignature,keyEncipherment" },
    }) |e| {
        const ext = c.X509V3_EXT_conf_nid(null, &v3, e[0], e[1]) orelse {
            logErrors("extension");
            return error.CertificateFailed;
        };
        defer c.X509_EXTENSION_free(ext);
        _ = c.X509_add_ext(x, ext, -1);
    }
    if (c.X509_sign(x, pkey, c.EVP_sha256()) <= 0) {
        logErrors("sign");
        return error.CertificateFailed;
    }

    // Private key: owner-only before any bytes are written.
    const kfd = c.open(key_path.ptr, c.O_WRONLY | c.O_CREAT | c.O_TRUNC | c.O_CLOEXEC, @as(c_uint, 0o600));
    if (kfd < 0) return error.CertificateFailed;
    // O_CREAT's mode only applies to a new file.
    const mode_ok = c.fchmod(kfd, 0o600) == 0;
    _ = c.close(kfd);
    if (!mode_ok) return error.CertificateFailed;
    const kbio = c.BIO_new_file(key_path.ptr, "w") orelse return error.CertificateFailed;
    defer _ = c.BIO_free(kbio);
    if (c.PEM_write_bio_PrivateKey(kbio, pkey, null, null, 0, null, null) != 1) return error.CertificateFailed;

    const cbio = c.BIO_new_file(cert_path.ptr, "w") orelse return error.CertificateFailed;
    defer _ = c.BIO_free(cbio);
    if (c.PEM_write_bio_X509(cbio, x) != 1) return error.CertificateFailed;
}

pub fn buildSan(buf: []u8, hostname: []const u8) ![:0]u8 {
    var n = (try std.fmt.bufPrint(buf, "DNS:{s},DNS:{s}.local", .{ hostname, hostname })).len;
    var ifs: ?*c.struct_ifaddrs = null;
    if (c.getifaddrs(&ifs) == 0) {
        defer c.freeifaddrs(ifs);
        var it = ifs;
        while (it) |ifa| : (it = ifa.ifa_next) {
            const sa = ifa.ifa_addr orelse continue;
            var txt: [c.INET6_ADDRSTRLEN]u8 = undefined;
            const ok = switch (sa.*.sa_family) {
                c.AF_INET => c.inet_ntop(c.AF_INET, &@as(*const c.struct_sockaddr_in, @ptrCast(@alignCast(sa))).sin_addr, &txt, txt.len) != null,
                c.AF_INET6 => blk: {
                    const a6: *const c.struct_sockaddr_in6 = @ptrCast(@alignCast(sa));
                    if (a6.sin6_scope_id != 0) break :blk false; // link-local: not routable by name
                    break :blk c.inet_ntop(c.AF_INET6, &a6.sin6_addr, &txt, txt.len) != null;
                },
                else => false,
            };
            if (!ok) continue;
            const ip = std.mem.sliceTo(&txt, 0);
            n += (try std.fmt.bufPrint(buf[n..], ",IP:{s}", .{ip})).len;
        }
    }
    if (n >= buf.len) return error.NoSpaceLeft;
    buf[n] = 0;
    return buf[0..n :0];
}

test "generate certificate and load context" {
    var tmp_buf: [64]u8 = undefined;
    const dir = try std.mem.printSentinel(&tmp_buf, "/tmp/omastation-tls-test-{d}", .{c.getpid()}, 0);
    _ = c.mkdir(dir.ptr, 0o700);
    var cbuf: [96]u8 = undefined;
    var kbuf: [96]u8 = undefined;
    const cert = try std.mem.printSentinel(&cbuf, "{s}/tls.crt", .{dir}, 0);
    const key = try std.mem.printSentinel(&kbuf, "{s}/tls.key", .{dir}, 0);
    defer {
        _ = c.unlink(cert.ptr);
        _ = c.unlink(key.ptr);
        _ = c.rmdir(dir.ptr);
    }
    var ctx = try Context.init(std.testing.allocator, cert, key, "omastation-test");
    defer ctx.deinit();
    try std.testing.expectEqual(@as(u8, 0x30), ctx.public_key[0]);
    try std.testing.expect(ctx.public_key.len > 256);

    var st: c.struct_stat = undefined;
    try std.testing.expectEqual(@as(c_int, 0), c.stat(key.ptr, &st));
    try std.testing.expectEqual(@as(c_uint, 0o600), st.st_mode & 0o777);

    // Loading an existing pair must not regenerate it.
    var ctx2 = try Context.init(std.testing.allocator, cert, key, "omastation-test");
    defer ctx2.deinit();
    try std.testing.expectEqualSlices(u8, ctx.public_key, ctx2.public_key);
}
