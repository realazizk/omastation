//! CredSSP (MS-CSSP) server: the TSRequest exchange of RDP Network Level Authentication
//! inside TLS (2.2.1, 3.1.5): NEGOTIATE/CHALLENGE, AUTHENTICATE with the public-key binding,
//! then the sealed TSCredentials. Secrets are zeroed after use.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const der = @import("der.zig");
const ntlm = @import("ntlm.zig");
const spnego = @import("spnego.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// STATUS_LOGON_FAILURE (MS-ERREF 2.3.1), returned on auth failure for v3+.
pub const status_logon_failure: u32 = 0xC000006D;
pub const status_not_supported: u32 = 0xC00000BB;

pub const client_to_server_magic = "CredSSP Client-To-Server Binding Hash\x00";
pub const server_to_client_magic = "CredSSP Server-To-Client Binding Hash\x00";

/// Constant-time comparison for byte slices (the length is public).
fn ctEqlSlice(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var acc: u8 = 0;
    for (a, b) |x, y| acc |= x ^ y;
    return acc == 0;
}

pub const Error = error{
    MalformedTsRequest,
    UnsupportedVersion,
    MissingField,
    PubKeyMismatch,
    UnsupportedCredType,
    RestrictedAdminUnsupported,
    UnexpectedState,
} || der.Error || spnego.Error || ntlm.Error || Allocator.Error;

// TSRequest wire format (MS-CSSP 2.2.1)

pub const TsRequest = struct {
    version: i64,
    nego_token: ?[]const u8 = null, // first NegoData.negoToken
    auth_info: ?[]const u8 = null,
    pub_key_auth: ?[]const u8 = null,
    error_code: ?i64 = null,
    client_nonce: ?[]const u8 = null,

    pub fn parse(buf: []const u8) Error!TsRequest {
        var top = der.Reader.init(buf);
        const seq = try top.expect(der.tag.sequence);
        try top.finish();
        var r = seq.reader();

        const ver_el = try r.explicit(der.tag.context(0));
        if (ver_el.tag != der.tag.integer) return error.MalformedTsRequest;
        var out = TsRequest{ .version = try der.decodeInteger(ver_el.content) };

        while (!r.atEnd()) {
            const t = r.peekTag().?;
            switch (t) {
                der.tag.context(1) => { // negoTokens: NegoData = SEQ OF SEQ { [0] OCTET STRING }
                    const nd = try r.explicit(der.tag.context(1));
                    if (nd.tag != der.tag.sequence) return error.MalformedTsRequest;
                    var ndr = nd.reader();
                    const first = try ndr.expect(der.tag.sequence);
                    var fr = first.reader();
                    const tok = try fr.explicit(der.tag.context(0));
                    if (tok.tag != der.tag.octet_string) return error.MalformedTsRequest;
                    out.nego_token = tok.content;
                },
                der.tag.context(2) => {
                    const e = try r.explicit(der.tag.context(2));
                    if (e.tag != der.tag.octet_string) return error.MalformedTsRequest;
                    out.auth_info = e.content;
                },
                der.tag.context(3) => {
                    const e = try r.explicit(der.tag.context(3));
                    if (e.tag != der.tag.octet_string) return error.MalformedTsRequest;
                    out.pub_key_auth = e.content;
                },
                der.tag.context(4) => {
                    const e = try r.explicit(der.tag.context(4));
                    if (e.tag != der.tag.integer) return error.MalformedTsRequest;
                    out.error_code = try der.decodeInteger(e.content);
                },
                der.tag.context(5) => {
                    const e = try r.explicit(der.tag.context(5));
                    if (e.tag != der.tag.octet_string) return error.MalformedTsRequest;
                    out.client_nonce = e.content;
                },
                else => return error.MalformedTsRequest,
            }
        }
        return out;
    }
};

pub const TsRequestOut = struct {
    version: i64,
    nego_token: ?[]const u8 = null,
    auth_info: ?[]const u8 = null,
    pub_key_auth: ?[]const u8 = null,
    error_code: ?u32 = null,
    client_nonce: ?[]const u8 = null,
};

pub fn encodeTsRequest(gpa: Allocator, req: TsRequestOut) Error![]u8 {
    var w = der.Writer.init(gpa);
    errdefer w.deinit();
    try w.begin(der.tag.sequence);

    try w.begin(der.tag.context(0));
    try w.integer(req.version);
    try w.end();

    if (req.nego_token) |tok| {
        try w.begin(der.tag.context(1)); // negoTokens
        try w.begin(der.tag.sequence); // NegoData
        try w.begin(der.tag.sequence); // NegoData element
        try w.begin(der.tag.context(0)); // negoToken
        try w.octetString(tok);
        try w.end();
        try w.end();
        try w.end();
        try w.end();
    }
    if (req.auth_info) |ai| {
        try w.begin(der.tag.context(2));
        try w.octetString(ai);
        try w.end();
    }
    if (req.pub_key_auth) |pk| {
        try w.begin(der.tag.context(3));
        try w.octetString(pk);
        try w.end();
    }
    if (req.error_code) |ec| {
        try w.begin(der.tag.context(4));
        // NTSTATUS as a signed 32-bit INTEGER (MS-CSSP 2.2.1); FreeRDP rejects INTEGERs over 4 bytes.
        try w.integer(@as(i32, @bitCast(ec)));
        try w.end();
    }
    if (req.client_nonce) |cn| {
        try w.begin(der.tag.context(5));
        try w.octetString(cn);
        try w.end();
    }
    try w.end();
    return w.toOwnedSlice();
}

// TSCredentials (MS-CSSP 2.2.1.2)

pub const Credentials = struct {
    domain: []u8,
    user: []u8,
    password: []u8,

    pub fn deinit(c: *Credentials, gpa: Allocator) void {
        std.crypto.secureZero(u8, c.password);
        gpa.free(c.domain);
        gpa.free(c.user);
        gpa.free(c.password);
    }
};

/// Parse a decrypted TSCredentials, requiring credType 1 (TSPasswordCreds).
pub fn parseCredentials(gpa: Allocator, buf: []const u8) Error!Credentials {
    var top = der.Reader.init(buf);
    const seq = try top.expect(der.tag.sequence);
    try top.finish();
    var r = seq.reader();

    const ct_el = try r.explicit(der.tag.context(0));
    if (ct_el.tag != der.tag.integer) return error.MalformedTsRequest;
    const cred_type = try der.decodeInteger(ct_el.content);
    const creds_el = try r.explicit(der.tag.context(1));
    if (creds_el.tag != der.tag.octet_string) return error.MalformedTsRequest;

    if (cred_type != 1) return error.UnsupportedCredType; // 2 smartcard, 6 remote guard

    // TSPasswordCreds ::= SEQUENCE { [0] domainName, [1] userName, [2] password }
    var pr = der.Reader.init(creds_el.content);
    const pw_seq = try pr.expect(der.tag.sequence);
    try pr.finish();
    var f = pw_seq.reader();
    const domain = try f.explicit(der.tag.context(0));
    const user = try f.explicit(der.tag.context(1));
    const password = try f.explicit(der.tag.context(2));
    if (domain.tag != der.tag.octet_string or user.tag != der.tag.octet_string or password.tag != der.tag.octet_string)
        return error.MalformedTsRequest;

    // Reject restricted-admin / empty-password logons.
    if (user.content.len == 0 and password.content.len == 0) return error.RestrictedAdminUnsupported;

    const d = try gpa.dupe(u8, domain.content);
    errdefer gpa.free(d);
    const u = try gpa.dupe(u8, user.content);
    errdefer gpa.free(u);
    const p = try gpa.dupe(u8, password.content);
    return .{ .domain = d, .user = u, .password = p };
}

pub const Options = struct {
    /// The subjectPublicKey BIT STRING contents of the certificate (RFC 3280 4.1.2), without the unused-bits octet.
    public_key: []const u8,
    nb_computer: []const u8,
    nb_domain: ?[]const u8 = null,
    dns_computer: ?[]const u8 = null,
    dns_domain: ?[]const u8 = null,
    dns_tree: ?[]const u8 = null,
    version: ntlm.Version = .{},
    nt_hash: ntlm.NtHashFn,
    nt_hash_ctx: ?*anyopaque = null,
    rng: std.Random,
    now_filetime: u64,
    /// Highest CredSSP version this server implements (2..6).
    max_version: u32 = 6,
};

pub const StepResult = union(enum) {
    /// Send this TSRequest to the client; more input is expected.
    send: []u8,
    /// Authentication succeeded; the credentials are owned by the caller.
    done: Credentials,
    /// `send`, if present, is a TSRequest carrying the NTSTATUS to send before closing.
    fail: Fail,
};

pub const Fail = struct {
    send: ?[]u8,
    err: anyerror,
};

const Phase = enum { expect_negotiate, expect_authenticate, expect_authinfo, finished };

pub const Server = struct {
    gpa: Allocator,
    opts: Options,
    spnego_server: spnego.Server,
    phase: Phase = .expect_negotiate,
    version: u32 = 0, // negotiated
    keys: ?ntlm.SessionKeys = null,
    from_client: ?ntlm.SealingState = null,
    to_client: ?ntlm.SealingState = null,
    nonce: [32]u8 = undefined,
    have_nonce: bool = false,
    result: ?ntlm.AuthResult = null,

    pub fn init(gpa: Allocator, opts: Options) Server {
        return .{
            .gpa = gpa,
            .opts = opts,
            .spnego_server = spnego.Server.init(gpa, .{
                .nb_computer = opts.nb_computer,
                .nb_domain = opts.nb_domain,
                .dns_computer = opts.dns_computer,
                .dns_domain = opts.dns_domain,
                .dns_tree = opts.dns_tree,
                .version = opts.version,
                .nt_hash = opts.nt_hash,
                .nt_hash_ctx = opts.nt_hash_ctx,
                .rng = opts.rng,
                .now_filetime = opts.now_filetime,
            }),
        };
    }

    pub fn deinit(s: *Server) void {
        s.spnego_server.deinit();
        if (s.from_client) |*h| h.deinit();
        if (s.to_client) |*h| h.deinit();
        if (s.keys) |*k| k.wipe();
        if (s.result) |*r| r.deinit(s.gpa);
    }

    pub fn step(s: *Server, input: []const u8) StepResult {
        return s.stepInner(input) catch |err| s.failWith(err);
    }

    fn failWith(s: *Server, err: anyerror) StepResult {
        s.phase = .finished;
        // errorCode only for versions 3, 4 and 6 (MS-CSSP 2.2.1); FreeRDP skips version 5 too.
        if (s.version >= 3 and s.version != 5) {
            const status: u32 = switch (err) {
                error.UnsupportedVersion => status_not_supported,
                else => status_logon_failure,
            };
            const msg = encodeTsRequest(s.gpa, .{ .version = s.version, .error_code = status }) catch
                return .{ .fail = .{ .send = null, .err = err } };
            return .{ .fail = .{ .send = msg, .err = err } };
        }
        return .{ .fail = .{ .send = null, .err = err } };
    }

    fn stepInner(s: *Server, input: []const u8) Error!StepResult {
        const req = try TsRequest.parse(input);

        if (s.phase == .expect_negotiate) {
            if (req.version < 2) return error.UnsupportedVersion;
            s.version = @min(@as(u32, @intCast(@min(req.version, std.math.maxInt(u32)))), s.opts.max_version);
            if (s.version < 2) return error.UnsupportedVersion;
        }

        switch (s.phase) {
            .expect_negotiate, .expect_authenticate => return s.handleNego(req),
            .expect_authinfo => return s.handleAuthInfo(req),
            .finished => return error.UnexpectedState,
        }
    }

    fn handleNego(s: *Server, req: TsRequest) Error!StepResult {
        const tok = req.nego_token orelse return error.MissingField;
        const outcome = try s.spnego_server.step(tok);
        switch (outcome) {
            .reply => |reply| {
                defer s.gpa.free(reply);
                s.phase = .expect_authenticate;
                const msg = try encodeTsRequest(s.gpa, .{ .version = s.version, .nego_token = reply });
                return .{ .send = msg };
            },
            .done => |done| {
                // The AUTHENTICATE arrived; it MUST be accompanied by pubKeyAuth.
                var d = done;
                defer if (d.final_token) |ft| s.gpa.free(ft);
                errdefer d.result.deinit(s.gpa);

                const pub_key_auth = req.pub_key_auth orelse return error.MissingField;

                s.keys = d.result.keys;
                s.from_client = d.result.keys.fromClient();
                s.to_client = d.result.keys.toClient();

                if (s.version >= 5) {
                    const cn = req.client_nonce orelse return error.MissingField;
                    if (cn.len != 32) return error.MalformedTsRequest;
                    @memcpy(&s.nonce, cn);
                    s.have_nonce = true;
                }

                try s.verifyClientPubKey(pub_key_auth);
                const server_pka = try s.makeServerPubKey();
                defer s.gpa.free(server_pka);

                const msg = try encodeTsRequest(s.gpa, .{
                    .version = s.version,
                    .nego_token = d.final_token, // present for SPNEGO, null for raw NTLM
                    .pub_key_auth = server_pka,
                });
                // Commit only after every fallible step, so the errdefer cannot double-free with deinit.
                s.result = d.result;
                s.phase = .expect_authinfo;
                return .{ .send = msg };
            },
        }
    }

    /// The client's first signed message: from_client at sequence 0.
    fn verifyClientPubKey(s: *Server, pub_key_auth: []const u8) Error!void {
        if (pub_key_auth.len < ntlm.signature_len) return error.MalformedTsRequest;
        const sig = pub_key_auth[0..ntlm.signature_len];
        const sealed = pub_key_auth[ntlm.signature_len..];
        const plain = try s.gpa.dupe(u8, sealed);
        defer {
            std.crypto.secureZero(u8, plain);
            s.gpa.free(plain);
        }
        try s.from_client.?.unseal(plain, sig);

        if (s.version >= 5) {
            var expected: [32]u8 = undefined;
            var h = Sha256.init(.{});
            h.update(client_to_server_magic);
            h.update(&s.nonce);
            h.update(s.opts.public_key);
            h.final(&expected);
            if (plain.len != 32 or !std.crypto.timing_safe.eql([32]u8, expected, plain[0..32].*))
                return error.PubKeyMismatch;
        } else {
            if (!ctEqlSlice(plain, s.opts.public_key)) return error.PubKeyMismatch;
        }
    }

    /// Build the server's pubKeyAuth response (sealed with to_client, seq 0).
    fn makeServerPubKey(s: *Server) Error![]u8 {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(s.gpa);

        if (s.version >= 5) {
            var hash: [32]u8 = undefined;
            var h = Sha256.init(.{});
            h.update(server_to_client_magic);
            h.update(&s.nonce);
            h.update(s.opts.public_key);
            h.final(&hash);
            try payload.appendSlice(s.gpa, &hash);
        } else {
            try payload.appendSlice(s.gpa, s.opts.public_key);
            payload.items[0] +%= 1; // first byte + 1 (anti-replay, MS-CSSP 3.1.5 step 4)
        }

        var sig: [ntlm.signature_len]u8 = undefined;
        s.to_client.?.seal(payload.items, &sig);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(s.gpa);
        try out.appendSlice(s.gpa, &sig);
        try out.appendSlice(s.gpa, payload.items);
        return out.toOwnedSlice(s.gpa);
    }

    fn handleAuthInfo(s: *Server, req: TsRequest) Error!StepResult {
        const auth_info = req.auth_info orelse return error.MissingField;
        if (auth_info.len < ntlm.signature_len) return error.MalformedTsRequest;
        const sig = auth_info[0..ntlm.signature_len];
        const sealed = auth_info[ntlm.signature_len..];
        const plain = try s.gpa.dupe(u8, sealed);
        defer {
            std.crypto.secureZero(u8, plain);
            s.gpa.free(plain);
        }
        // authInfo is the client's second signed message: from_client at seq 1.
        try s.from_client.?.unseal(plain, sig);

        const creds = try parseCredentials(s.gpa, plain);
        s.phase = .finished;
        return .{ .done = creds };
    }
};

const testing = std.testing;
const hex = bytes.hex;
const md4 = @import("md4.zig");
const Rc4 = @import("rc4.zig").Rc4;

const tc = struct {
    const user = hex("55 00 73 00 65 00 72 00");
    const domain = hex("44 00 6f 00 6d 00 61 00 69 00 6e 00");
    const server_name = hex("53 00 65 00 72 00 76 00 65 00 72 00");
    const password = hex("50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00");
    const public_key = hex("30 82 01 0a 02 82 01 01 00 c0 fe ed de ad be ef"); // opaque stand-in
};

fn testNtHash(_: ?*anyopaque, u: []const u8, d: []const u8) ?[16]u8 {
    if (std.mem.eql(u8, u, &tc.user) and std.mem.eql(u8, d, &tc.domain))
        return md4.ntHash(&tc.password);
    return null;
}

const FixedRandom = struct {
    b: u8,
    fn fill(self: *FixedRandom, buf: []u8) void {
        @memset(buf, self.b);
    }
    fn r(self: *FixedRandom) std.Random {
        return std.Random.init(self, fill);
    }
};

/// A full CredSSP client (raw NTLM in negoTokens), used to drive the server.
const Client = struct {
    gpa: Allocator,
    version: u32,
    public_key: []const u8,
    nonce: [32]u8 = @splat(0x5a),
    keys: ?ntlm.SessionKeys = null,
    to_server: ?ntlm.SealingState = null, // client->server sealing
    from_server: ?ntlm.SealingState = null,
    negotiate_msg: ?[]u8 = null,

    fn deinit(c: *Client) void {
        if (c.to_server) |*h| h.deinit();
        if (c.from_server) |*h| h.deinit();
        if (c.keys) |*k| k.wipe();
        if (c.negotiate_msg) |m| c.gpa.free(m);
    }

    fn negotiate(c: *Client) ![]u8 {
        var list: std.ArrayList(u8) = .empty;
        var bw = bytes.Writer.init(&list, c.gpa);
        try bw.bytes(ntlm.signature);
        try bw.u32le(1);
        const flags = ntlm.Flags{
            .unicode = true,
            .sign = true,
            .seal = true,
            .ntlm = true,
            .always_sign = true,
            .extended_session_security = true,
            .negotiate_128 = true,
            .key_exch = true,
            .negotiate_56 = true,
            .request_target = true,
        };
        try bw.u32le(flags.toInt());
        try bw.zeros(16);
        c.negotiate_msg = try list.toOwnedSlice(c.gpa);

        return encodeTsRequest(c.gpa, .{ .version = c.version, .nego_token = c.negotiate_msg.? });
    }

    /// Given the server's CHALLENGE TSRequest, build AUTHENTICATE + pubKeyAuth.
    fn authenticate(c: *Client, server_msg: []const u8) ![]u8 {
        const sreq = try TsRequest.parse(server_msg);
        const challenge = sreq.nego_token.?;

        const built = try buildAuthenticate(c.gpa, c.negotiate_msg.?, challenge);
        defer c.gpa.free(built.msg);
        c.keys = ntlm.SessionKeys.derive(built.esk);
        c.to_server = c.keys.?.fromClient(); // client uses "client" keys to send
        c.from_server = c.keys.?.toClient();

        // pubKeyAuth: seal the binding value with to_server at seq 0.
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(c.gpa);
        if (c.version >= 5) {
            var hash: [32]u8 = undefined;
            var h = Sha256.init(.{});
            h.update(client_to_server_magic);
            h.update(&c.nonce);
            h.update(c.public_key);
            h.final(&hash);
            try payload.appendSlice(c.gpa, &hash);
        } else {
            try payload.appendSlice(c.gpa, c.public_key);
        }
        var sig: [16]u8 = undefined;
        c.to_server.?.seal(payload.items, &sig);

        var pka: std.ArrayList(u8) = .empty;
        defer pka.deinit(c.gpa);
        try pka.appendSlice(c.gpa, &sig);
        try pka.appendSlice(c.gpa, payload.items);

        return encodeTsRequest(c.gpa, .{
            .version = c.version,
            .nego_token = built.msg,
            .pub_key_auth = pka.items,
            .client_nonce = if (c.version >= 5) &c.nonce else null,
        });
    }

    fn verifyServer(c: *Client, server_msg: []const u8) !void {
        const sreq = try TsRequest.parse(server_msg);
        const pka = sreq.pub_key_auth.?;
        const sig = pka[0..16];
        const sealed = pka[16..];
        const plain = try c.gpa.dupe(u8, sealed);
        defer c.gpa.free(plain);
        try c.from_server.?.unseal(plain, sig);
        if (c.version >= 5) {
            var expected: [32]u8 = undefined;
            var h = Sha256.init(.{});
            h.update(server_to_client_magic);
            h.update(&c.nonce);
            h.update(c.public_key);
            h.final(&expected);
            try testing.expectEqualSlices(u8, &expected, plain);
        } else {
            var expected = try c.gpa.dupe(u8, c.public_key);
            defer c.gpa.free(expected);
            expected[0] +%= 1;
            try testing.expectEqualSlices(u8, expected, plain);
        }
    }

    /// Seal TSCredentials into an authInfo TSRequest (to_server at seq 1).
    fn sendCredentials(c: *Client) ![]u8 {
        const creds = try encodeTsPasswordCreds(c.gpa);
        defer c.gpa.free(creds);
        var sig: [16]u8 = undefined;
        c.to_server.?.seal(creds, &sig);
        var ai: std.ArrayList(u8) = .empty;
        defer ai.deinit(c.gpa);
        try ai.appendSlice(c.gpa, &sig);
        try ai.appendSlice(c.gpa, creds);
        return encodeTsRequest(c.gpa, .{ .version = c.version, .auth_info = ai.items });
    }
};

fn encodeTsPasswordCreds(gpa: Allocator) ![]u8 {
    var w = der.Writer.init(gpa);
    errdefer w.deinit();
    try w.begin(der.tag.sequence); // TSCredentials
    try w.begin(der.tag.context(0));
    try w.integer(1); // credType = password
    try w.end();
    // credentials OCTET STRING wrapping TSPasswordCreds
    var inner = der.Writer.init(gpa);
    defer inner.deinit();
    try inner.begin(der.tag.sequence);
    try inner.begin(der.tag.context(0));
    try inner.octetString(&tc.domain);
    try inner.end();
    try inner.begin(der.tag.context(1));
    try inner.octetString(&tc.user);
    try inner.end();
    try inner.begin(der.tag.context(2));
    try inner.octetString(&tc.password);
    try inner.end();
    try inner.end();
    const inner_bytes = inner.list.items;
    try w.begin(der.tag.context(1));
    try w.octetString(inner_bytes);
    try w.end();
    try w.end();
    return w.toOwnedSlice();
}

const Built = struct { msg: []u8, esk: [16]u8 };

fn buildAuthenticate(gpa: Allocator, negotiate_msg: []const u8, challenge_msg: []const u8) !Built {
    var r = bytes.Reader.init(challenge_msg);
    _ = try r.bytes(12);
    _ = try r.u16le();
    _ = try r.u16le();
    _ = try r.u32le();
    _ = try r.u32le();
    const server_challenge: [8]u8 = (try r.bytes(8))[0..8].*;
    _ = try r.bytes(8);
    const ti_len = try r.u16le();
    _ = try r.u16le();
    const ti_off = try r.u32le();
    const target_info = challenge_msg[ti_off .. ti_off + ti_len];

    const nt = md4.ntHash(&tc.password);
    const key = try ntlm.ntowfv2(nt, &tc.user, &tc.domain);
    const client_challenge: [8]u8 = @splat(0xaa);
    const random_session_key: [16]u8 = @splat(0x55);

    var temp: std.ArrayList(u8) = .empty;
    defer temp.deinit(gpa);
    var tw = bytes.Writer.init(&temp, gpa);
    try tw.bytes(&[_]u8{ 1, 1, 0, 0, 0, 0, 0, 0 });
    try tw.u64le(0);
    try tw.bytes(&client_challenge);
    try tw.zeros(4);
    try tw.bytes(target_info[0 .. target_info.len - 4]);
    try tw.u16le(@backingInt(ntlm.AvId.flags));
    try tw.u16le(4);
    try tw.u32le(ntlm.av_flag_mic_present);
    try tw.bytes(&[_]u8{ 0, 0, 0, 0 });
    try tw.zeros(4);

    const proof = ntlm.ntProofStr(key, server_challenge, temp.items);
    const sbk = ntlm.sessionBaseKey(key, proof);
    var ersk: [16]u8 = undefined;
    Rc4.oneShot(&sbk, &random_session_key, &ersk);
    const lm = ntlm.lmv2Response(key, server_challenge, client_challenge);

    const nt_resp_len: u16 = @intCast(16 + temp.items.len);
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    var w = bytes.Writer.init(&msg, gpa);
    try w.bytes(ntlm.signature);
    try w.u32le(3);
    var off: u32 = 88;
    try w.u16le(24);
    try w.u16le(24);
    try w.u32le(off);
    off += 24;
    try w.u16le(nt_resp_len);
    try w.u16le(nt_resp_len);
    try w.u32le(off);
    off += nt_resp_len;
    try w.u16le(@intCast(tc.domain.len));
    try w.u16le(@intCast(tc.domain.len));
    try w.u32le(off);
    off += @intCast(tc.domain.len);
    try w.u16le(@intCast(tc.user.len));
    try w.u16le(@intCast(tc.user.len));
    try w.u32le(off);
    off += @intCast(tc.user.len);
    try w.u16le(0);
    try w.u16le(0);
    try w.u32le(off);
    try w.u16le(16);
    try w.u16le(16);
    try w.u32le(off);
    const flags_out = ntlm.Flags{
        .unicode = true,
        .request_target = true,
        .sign = true,
        .seal = true,
        .ntlm = true,
        .always_sign = true,
        .extended_session_security = true,
        .target_info = true,
        .negotiate_128 = true,
        .key_exch = true,
        .negotiate_56 = true,
        .version = true,
    };
    try w.u32le(flags_out.toInt());
    try (ntlm.Version{}).write(&w);
    try w.zeros(16);
    try w.bytes(&lm);
    try w.bytes(&proof);
    try w.bytes(temp.items);
    try w.bytes(&tc.domain);
    try w.bytes(&tc.user);
    try w.bytes(&ersk);

    var ctx = std.crypto.auth.hmac.HmacMd5.init(&random_session_key);
    ctx.update(negotiate_msg);
    ctx.update(challenge_msg);
    ctx.update(msg.items);
    var mic: [16]u8 = undefined;
    ctx.final(&mic);
    @memcpy(msg.items[72..88], &mic);

    return .{ .msg = try msg.toOwnedSlice(gpa), .esk = random_session_key };
}

fn runHandshake(version: u32) !void {
    const gpa = testing.allocator;
    var fr = FixedRandom{ .b = 0x11 };
    var srv = Server.init(gpa, .{
        .public_key = &tc.public_key,
        .nb_computer = &tc.server_name,
        .nb_domain = &tc.domain,
        .nt_hash = testNtHash,
        .rng = fr.r(),
        .now_filetime = 0,
    });
    defer srv.deinit();

    var client = Client{ .gpa = gpa, .version = version, .public_key = &tc.public_key };
    defer client.deinit();

    // 1. NEGOTIATE -> CHALLENGE
    const neg = try client.negotiate();
    defer gpa.free(neg);
    const r1 = srv.step(neg);
    try testing.expect(r1 == .send);
    defer gpa.free(r1.send);

    // 2. AUTHENTICATE + pubKeyAuth -> server pubKeyAuth
    const auth = try client.authenticate(r1.send);
    defer gpa.free(auth);
    const r2 = srv.step(auth);
    if (r2 == .fail) {
        if (r2.fail.send) |m| gpa.free(m);
        return r2.fail.err;
    }
    try testing.expect(r2 == .send);
    defer gpa.free(r2.send);
    try client.verifyServer(r2.send);

    // 3. authInfo -> credentials
    const ai = try client.sendCredentials();
    defer gpa.free(ai);
    var r3 = srv.step(ai);
    try testing.expect(r3 == .done);
    defer r3.done.deinit(gpa);
    try testing.expectEqualSlices(u8, &tc.domain, r3.done.domain);
    try testing.expectEqualSlices(u8, &tc.user, r3.done.user);
    try testing.expectEqualSlices(u8, &tc.password, r3.done.password);
    // Negotiated version is min(client, 6).
    try testing.expectEqual(@min(version, @as(u32, 6)), srv.version);
}

test "CredSSP full handshake v2" {
    try runHandshake(2);
}
test "CredSSP full handshake v5" {
    try runHandshake(5);
}
test "CredSSP full handshake v6" {
    try runHandshake(6);
}
test "CredSSP clamps a v9 client down to v6" {
    try runHandshake(9);
}

test "CredSSP wrong password fails with STATUS_LOGON_FAILURE" {
    const gpa = testing.allocator;
    var fr = FixedRandom{ .b = 0x22 };
    var srv = Server.init(gpa, .{
        .public_key = &tc.public_key,
        .nb_computer = &tc.server_name,
        .nb_domain = &tc.domain,
        .nt_hash = struct {
            fn f(_: ?*anyopaque, _: []const u8, _: []const u8) ?[16]u8 {
                // Return a hash for a DIFFERENT password so the proof mismatches.
                return md4.ntHash(&hex("57 00 72 00 6f 00 6e 00 67 00"));
            }
        }.f,
        .rng = fr.r(),
        .now_filetime = 0,
    });
    defer srv.deinit();
    var client = Client{ .gpa = gpa, .version = 6, .public_key = &tc.public_key };
    defer client.deinit();

    const neg = try client.negotiate();
    defer gpa.free(neg);
    const r1 = srv.step(neg);
    defer gpa.free(r1.send);
    const auth = try client.authenticate(r1.send);
    defer gpa.free(auth);
    const r2 = srv.step(auth);
    try testing.expect(r2 == .fail);
    try testing.expectEqual(@as(anyerror, error.ProofMismatch), r2.fail.err);
    // v6 -> an errorCode TSRequest is produced.
    const fm = r2.fail.send.?;
    defer gpa.free(fm);
    const parsed = try TsRequest.parse(fm);
    try testing.expectEqual(@as(i64, @as(i32, @bitCast(status_logon_failure))), parsed.error_code.?);
}

test "CredSSP tampered pubKeyAuth is detected (MITM)" {
    const gpa = testing.allocator;
    var fr = FixedRandom{ .b = 0x33 };
    var srv = Server.init(gpa, .{
        .public_key = &tc.public_key,
        .nb_computer = &tc.server_name,
        .nb_domain = &tc.domain,
        .nt_hash = testNtHash,
        .rng = fr.r(),
        .now_filetime = 0,
    });
    defer srv.deinit();
    var client = Client{ .gpa = gpa, .version = 6, .public_key = &tc.public_key };
    defer client.deinit();

    const neg = try client.negotiate();
    defer gpa.free(neg);
    const r1 = srv.step(neg);
    defer gpa.free(r1.send);

    // The client binds a different public key, as a TLS-terminating MITM would.
    const other_key = hex("30 82 01 0a 02 82 01 01 00 AA BB CC DD EE FF 11");
    client.public_key = &other_key;
    const auth = try client.authenticate(r1.send);
    defer gpa.free(auth);
    const r2 = srv.step(auth);
    try testing.expect(r2 == .fail);
    try testing.expectEqual(@as(anyerror, error.PubKeyMismatch), r2.fail.err);
    if (r2.fail.send) |m| gpa.free(m);
}

test "CredSSP rejects malformed TSRequest" {
    const gpa = testing.allocator;
    var fr = FixedRandom{ .b = 0x44 };
    var srv = Server.init(gpa, .{
        .public_key = &tc.public_key,
        .nb_computer = &tc.server_name,
        .nt_hash = testNtHash,
        .rng = fr.r(),
        .now_filetime = 0,
    });
    defer srv.deinit();
    // Not a SEQUENCE.
    const r = srv.step(&hex("02 01 06"));
    try testing.expect(r == .fail);
    if (r.fail.send) |m| gpa.free(m);
    // Truncated.
    const r2 = srv.step(&hex("30 03 a0 01"));
    try testing.expect(r2 == .fail);
    if (r2.fail.send) |m| gpa.free(m);
}

test "CredSSP rejects smartcard credType" {
    const gpa = testing.allocator;
    // credType 2 should be refused by parseCredentials.
    var w = der.Writer.init(gpa);
    defer w.deinit();
    try w.begin(der.tag.sequence);
    try w.begin(der.tag.context(0));
    try w.integer(2);
    try w.end();
    try w.begin(der.tag.context(1));
    try w.octetString(&hex("30 00"));
    try w.end();
    try w.end();
    try testing.expectError(error.UnsupportedCredType, parseCredentials(gpa, w.list.items));
}

test "TSRequest encode/parse round trip" {
    const gpa = testing.allocator;
    const tok = hex("4e 54 4c 4d 53 53 50 00");
    const msg = try encodeTsRequest(gpa, .{ .version = 6, .nego_token = &tok, .error_code = status_logon_failure });
    defer gpa.free(msg);
    const p = try TsRequest.parse(msg);
    try testing.expectEqual(@as(i64, 6), p.version);
    try testing.expectEqualSlices(u8, &tok, p.nego_token.?);
    try testing.expectEqual(@as(i64, @as(i32, @bitCast(status_logon_failure))), p.error_code.?);
}
