//! SPNEGO acceptor (RFC 4178 4.2, MS-SPNG) carrying NTLM only. A client leading with another
//! mech (Kerberos) gets accept-incomplete with supportedMech NTLM (RFC 4178 4.2.2); a raw NTLM
//! negoToken without SPNEGO is accepted too (MS-SPNG 3.1.5.1).

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const der = @import("der.zig");
const ntlm = @import("ntlm.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{
    MalformedToken,
    NoAcceptableMech,
    UnexpectedState,
    MechListMicMismatch,
    MechListMicMissing,
    NestingTooDeep,
} || der.Error || ntlm.Error || Allocator.Error;

/// DER-encoded OID *content* octets (without the 0x06 tag/length).
pub const oid = struct {
    pub const spnego = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 }; // 1.3.6.1.5.5.2
    pub const ntlm = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a }; // 1.3.6.1.4.1.311.2.2.10
    pub const kerberos = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 }; // 1.2.840.113554.1.2.2
    pub const kerberos_u2u = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x03 };
    pub const ms_kerberos = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e }; // 1.3.6.1.4.1.311.2.2.30
};

pub const NegState = enum(u8) {
    accept_completed = 0,
    accept_incomplete = 1,
    reject = 2,
    request_mic = 3,
};

pub fn isRawNtlm(token: []const u8) bool {
    return token.len >= 8 and std.mem.eql(u8, token[0..8], ntlm.signature);
}

// Parsing

pub const NegTokenInit = struct {
    /// Raw DER of the MechTypeList SEQUENCE (0x30 ...), for mechListMIC.
    mech_types_der: []const u8,
    offers_ntlm: bool,
    first_mech_is_ntlm: bool,
    mech_token: ?[]const u8,
    mech_list_mic: ?[]const u8,

    /// GSS-API-wrapped (RFC 2743 3.1): [APPLICATION 0] { OID(spnego), [0] NegTokenInit }.
    pub fn parse(token: []const u8) Error!NegTokenInit {
        var top = der.Reader.init(token);
        const app = try top.expect(der.tag.application(0));
        try top.finish();
        var w = app.reader();
        const mech_oid = try w.oid();
        if (!std.mem.eql(u8, mech_oid, &oid.spnego)) return error.MalformedToken;
        const init_el = try w.explicit(der.tag.context(0)); // [0] NegTokenInit
        try w.finish();
        if (init_el.tag != der.tag.sequence) return error.MalformedToken;

        var seq = init_el.reader();
        // mechTypes [0] MechTypeList
        const mt = try seq.explicit(der.tag.context(0));
        if (mt.tag != der.tag.sequence) return error.MalformedToken;
        var offers_ntlm = false;
        var first_ntlm = false;
        var ml = mt.reader();
        var idx: usize = 0;
        while (!ml.atEnd()) : (idx += 1) {
            const m = try ml.next();
            if (m.tag != der.tag.oid) return error.MalformedToken;
            try validateOidContent(m.content);
            if (std.mem.eql(u8, m.content, &oid.ntlm)) {
                offers_ntlm = true;
                if (idx == 0) first_ntlm = true;
            }
        }

        var mech_token: ?[]const u8 = null;
        var mech_list_mic: ?[]const u8 = null;
        // [1] reqFlags (ignored), [2] mechToken, [3] mechListMIC (RFC 4178); in NegTokenInit2
        // (MS-SPNG 2.2.1) [3] is negHints, to be ignored (MS-SPNG 3.2.5), and mechListMIC is [4].
        while (!seq.atEnd()) {
            const t = seq.peekTag().?;
            if (t == der.tag.context(2)) {
                const e = try seq.explicit(der.tag.context(2));
                if (e.tag != der.tag.octet_string) return error.MalformedToken;
                mech_token = e.content;
            } else if (t == der.tag.context(3) or t == der.tag.context(4)) {
                const e = try seq.explicit(t);
                if (t == der.tag.context(3) and e.tag == der.tag.sequence) continue; // negHints
                if (e.tag != der.tag.octet_string) return error.MalformedToken;
                mech_list_mic = e.content;
            } else {
                _ = try seq.next(); // skip reqFlags [1] etc.
            }
        }

        return .{
            .mech_types_der = mt.raw,
            .offers_ntlm = offers_ntlm,
            .first_mech_is_ntlm = first_ntlm,
            .mech_token = mech_token,
            .mech_list_mic = mech_list_mic,
        };
    }
};

pub const NegTokenResp = struct {
    neg_state: ?NegState,
    supported_mech: ?[]const u8,
    response_token: ?[]const u8,
    mech_list_mic: ?[]const u8,

    /// [1] SEQUENCE { [0] ENUMERATED, [1] OID, [2] OCTET STRING, [3] OCTET STRING }, all optional.
    pub fn parse(token: []const u8) Error!NegTokenResp {
        var top = der.Reader.init(token);
        const resp = try top.explicit(der.tag.context(1)); // [1] NegTokenResp
        try top.finish();
        if (resp.tag != der.tag.sequence) return error.MalformedToken;

        var neg_state: ?NegState = null;
        var supported_mech: ?[]const u8 = null;
        var response_token: ?[]const u8 = null;
        var mech_list_mic: ?[]const u8 = null;

        var seq = resp.reader();
        while (!seq.atEnd()) {
            const t = seq.peekTag().?;
            switch (t) {
                der.tag.context(0) => {
                    const e = try seq.explicit(der.tag.context(0));
                    const v = try der.decodeInteger(e.content);
                    if (e.tag != der.tag.enumerated or v < 0 or v > 3) return error.MalformedToken;
                    neg_state = @fromBackingInt(@intCast(@as(u8, @intCast(v))));
                },
                der.tag.context(1) => {
                    const e = try seq.explicit(der.tag.context(1));
                    if (e.tag != der.tag.oid) return error.MalformedToken;
                    supported_mech = e.content;
                },
                der.tag.context(2) => {
                    const e = try seq.explicit(der.tag.context(2));
                    if (e.tag != der.tag.octet_string) return error.MalformedToken;
                    response_token = e.content;
                },
                der.tag.context(3) => {
                    const e = try seq.explicit(der.tag.context(3));
                    if (e.tag != der.tag.octet_string) return error.MalformedToken;
                    mech_list_mic = e.content;
                },
                else => return error.MalformedToken,
            }
        }
        return .{
            .neg_state = neg_state,
            .supported_mech = supported_mech,
            .response_token = response_token,
            .mech_list_mic = mech_list_mic,
        };
    }
};

fn validateOidContent(c: []const u8) Error!void {
    if (c.len == 0 or c[c.len - 1] & 0x80 != 0) return error.MalformedToken;
}

// Building

/// Null fields are omitted.
pub fn buildNegTokenResp(
    gpa: Allocator,
    neg_state: ?NegState,
    supported_mech: ?[]const u8,
    response_token: ?[]const u8,
    mech_list_mic: ?[]const u8,
) Error![]u8 {
    var w = der.Writer.init(gpa);
    errdefer w.deinit();
    try w.begin(der.tag.context(1)); // [1] NegTokenResp
    try w.begin(der.tag.sequence);
    if (neg_state) |ns| {
        try w.begin(der.tag.context(0));
        try w.enumerated(@backingInt(ns));
        try w.end();
    }
    if (supported_mech) |m| {
        try w.begin(der.tag.context(1));
        try w.oid(m);
        try w.end();
    }
    if (response_token) |rt| {
        try w.begin(der.tag.context(2));
        try w.octetString(rt);
        try w.end();
    }
    if (mech_list_mic) |mic| {
        try w.begin(der.tag.context(3));
        try w.octetString(mic);
        try w.end();
    }
    try w.end();
    try w.end();
    return w.toOwnedSlice();
}

/// Used by the test client.
pub fn buildNegTokenInit(
    gpa: Allocator,
    mech_oids: []const []const u8,
    mech_token: ?[]const u8,
    mech_list_mic: ?[]const u8,
) Error![]u8 {
    var w = der.Writer.init(gpa);
    errdefer w.deinit();
    try w.begin(der.tag.application(0));
    try w.oid(&oid.spnego);
    try w.begin(der.tag.context(0)); // [0] NegTokenInit
    try w.begin(der.tag.sequence);
    try w.begin(der.tag.context(0)); // mechTypes [0]
    try w.begin(der.tag.sequence); // MechTypeList
    for (mech_oids) |m| try w.oid(m);
    try w.end();
    try w.end();
    if (mech_token) |mt| {
        try w.begin(der.tag.context(2));
        try w.octetString(mt);
        try w.end();
    }
    if (mech_list_mic) |mic| {
        try w.begin(der.tag.context(3));
        try w.octetString(mic);
        try w.end();
    }
    try w.end();
    try w.end();
    try w.end();
    return w.toOwnedSlice();
}

// mechListMIC (MS-SPNG 3.2.5.1): NTLM signature over the MechTypeList DER.

/// Computed on a throwaway copy of the sealing state, so the real traffic stream is not perturbed.
pub fn computeMechListMic(keys: ntlm.SessionKeys, mode: ntlm.Mode, mech_types_der: []const u8) [16]u8 {
    var st = switch (mode) {
        .client => keys.fromClient(),
        .server => keys.toClient(),
    };
    defer st.deinit();
    var sig: [16]u8 = undefined;
    // GSS_GetMICEx (sign only): MAC over the MechTypeList, no encryption.
    st.sign(mech_types_der, &sig);
    return sig;
}

/// The client's MIC is a GSS_GetMIC signature, re-derived and compared in constant time.
pub fn verifyMechListMic(keys: ntlm.SessionKeys, mech_types_der: []const u8, received: []const u8) Error!void {
    if (received.len != ntlm.signature_len) return error.MechListMicMismatch;
    const expected = computeMechListMic(keys, .client, mech_types_der);
    if (!std.crypto.timing_safe.eql([16]u8, expected, received[0..16].*)) return error.MechListMicMismatch;
}

// Acceptor state machine

pub const Outcome = union(enum) {
    /// Owned; free with gpa.
    reply: []u8,
    /// `final_token` (owned; null for raw NTLM) goes with pubKeyAuth.
    done: Done,
};

pub const Done = struct {
    final_token: ?[]u8,
    result: ntlm.AuthResult,
};

const Phase = enum { start, sent_challenge, awaiting_ntlm_negotiate };

pub const Server = struct {
    gpa: Allocator,
    ntlm_server: ntlm.Server,
    phase: Phase = .start,
    raw_mode: bool = false,
    /// DER of the MechTypeList, duplicated for later mechListMIC checks.
    mech_types_der: ?[]u8 = null,
    client_sent_mic: bool = false,
    /// NTLM was not the initiator's first choice: mechListMIC is mandatory (RFC 4178 5).
    mic_required: bool = false,

    pub fn init(gpa: Allocator, opts: ntlm.ServerOptions) Server {
        return .{ .gpa = gpa, .ntlm_server = ntlm.Server.init(gpa, opts) };
    }

    pub fn deinit(s: *Server) void {
        s.ntlm_server.deinit();
        if (s.mech_types_der) |m| s.gpa.free(m);
    }

    pub fn step(s: *Server, token: []const u8) Error!Outcome {
        switch (s.phase) {
            .start => return s.handleFirst(token),
            .sent_challenge => return s.handleAuthenticate(token),
            .awaiting_ntlm_negotiate => return s.handleNtlmNegotiate(token),
        }
    }

    fn handleFirst(s: *Server, token: []const u8) Error!Outcome {
        if (isRawNtlm(token)) {
            s.raw_mode = true;
            const challenge = try s.ntlm_server.consumeNegotiate(token);
            s.phase = .sent_challenge;
            return .{ .reply = try s.gpa.dupe(u8, challenge) };
        }

        const nti = try NegTokenInit.parse(token);
        if (!nti.offers_ntlm) return error.NoAcceptableMech;
        if (s.mech_types_der) |m| s.gpa.free(m);
        s.mech_types_der = try s.gpa.dupe(u8, nti.mech_types_der);
        s.mic_required = !nti.first_mech_is_ntlm;

        if (nti.mech_token) |mt| {
            if (nti.first_mech_is_ntlm and isRawNtlm(mt)) {
                // Optimistic NTLM NEGOTIATE: answer with the CHALLENGE.
                const challenge = try s.ntlm_server.consumeNegotiate(mt);
                const reply = try buildNegTokenResp(s.gpa, .accept_incomplete, &oid.ntlm, challenge, null);
                s.phase = .sent_challenge;
                return .{ .reply = reply };
            }
            // A non-NTLM optimistic token (Kerberos): ask the client to restart with NTLM.
            const reply = try buildNegTokenResp(s.gpa, .accept_incomplete, &oid.ntlm, null, null);
            s.phase = .awaiting_ntlm_negotiate;
            return .{ .reply = reply };
        }

        // No optimistic token: select NTLM and wait for its NEGOTIATE.
        const reply = try buildNegTokenResp(s.gpa, .accept_incomplete, &oid.ntlm, null, null);
        s.phase = .awaiting_ntlm_negotiate;
        return .{ .reply = reply };
    }

    fn handleNtlmNegotiate(s: *Server, token: []const u8) Error!Outcome {
        const resp = try NegTokenResp.parse(token);
        const inner = resp.response_token orelse return error.MalformedToken;
        if (!isRawNtlm(inner)) return error.MalformedToken;
        const challenge = try s.ntlm_server.consumeNegotiate(inner);
        const reply = try buildNegTokenResp(s.gpa, .accept_incomplete, null, challenge, null);
        s.phase = .sent_challenge;
        return .{ .reply = reply };
    }

    fn handleAuthenticate(s: *Server, token: []const u8) Error!Outcome {
        var auth_bytes: []const u8 = undefined;
        var client_mic: ?[]const u8 = null;
        if (s.raw_mode) {
            if (!isRawNtlm(token)) return error.MalformedToken;
            auth_bytes = token;
        } else {
            const resp = try NegTokenResp.parse(token);
            auth_bytes = resp.response_token orelse return error.MalformedToken;
            client_mic = resp.mech_list_mic;
        }

        var result = try s.ntlm_server.consumeAuthenticate(auth_bytes);
        errdefer result.deinit(s.gpa);

        // Verify the client's mechListMIC (MS-SPNG 3.2.5.1); it is required when NTLM was not the
        // initiator's first choice, else negotiation terminates (RFC 4178 5).
        if (client_mic) |mic| {
            s.client_sent_mic = true;
            try verifyMechListMic(result.keys, s.mech_types_der.?, mic);
        } else if (s.mic_required and !s.raw_mode) return error.MechListMicMissing;

        if (s.raw_mode) {
            return .{ .done = .{ .final_token = null, .result = result } };
        }

        // accept-completed, with a server mechListMIC when the client sent one.
        var server_mic: ?[16]u8 = null;
        if (s.client_sent_mic) server_mic = computeMechListMic(result.keys, .server, s.mech_types_der.?);
        const final = try buildNegTokenResp(
            s.gpa,
            .accept_completed,
            null,
            null,
            if (server_mic) |*m| m else null,
        );
        return .{ .done = .{ .final_token = final, .result = result } };
    }
};

const testing = std.testing;
const hex = bytes.hex;
const md4 = @import("md4.zig");

test "NTLM OID encodes to 1.3.6.1.4.1.311.2.2.10" {
    try testing.expectEqualSlices(u8, &hex("2b 06 01 04 01 82 37 02 02 0a"), &oid.ntlm);
}

test "isRawNtlm detects NTLMSSP signature" {
    try testing.expect(isRawNtlm(&hex("4e 54 4c 4d 53 53 50 00 01 00 00 00")));
    try testing.expect(!isRawNtlm(&hex("60 06 06 04 2b 06 01 05")));
    try testing.expect(!isRawNtlm("short"));
}

test "NegTokenResp build/parse round trip" {
    const gpa = testing.allocator;
    const rt = hex("aa bb cc dd");
    const mic = hex("01 00 00 00 11 22 33 44 55 66 77 88 00 00 00 00");
    const tok = try buildNegTokenResp(gpa, .accept_incomplete, &oid.ntlm, &rt, &mic);
    defer gpa.free(tok);
    const p = try NegTokenResp.parse(tok);
    try testing.expectEqual(NegState.accept_incomplete, p.neg_state.?);
    try testing.expectEqualSlices(u8, &oid.ntlm, p.supported_mech.?);
    try testing.expectEqualSlices(u8, &rt, p.response_token.?);
    try testing.expectEqualSlices(u8, &mic, p.mech_list_mic.?);
}

test "NegTokenInit build/parse round trip (Kerberos preferred, NTLM offered)" {
    const gpa = testing.allocator;
    const mechs = [_][]const u8{ &oid.kerberos, &oid.ntlm };
    const ntlm_neg = hex("4e 54 4c 4d 53 53 50 00 01 00 00 00");
    const tok = try buildNegTokenInit(gpa, &mechs, &ntlm_neg, null);
    defer gpa.free(tok);
    const p = try NegTokenInit.parse(tok);
    try testing.expect(p.offers_ntlm);
    try testing.expect(!p.first_mech_is_ntlm);
    try testing.expectEqualSlices(u8, &ntlm_neg, p.mech_token.?);
}

test "NegTokenInit parse rejects token without SPNEGO OID" {
    // APPLICATION 0 wrapping a bogus OID.
    const bad = hex("60 08 06 06 2b 06 01 05 05 03");
    try testing.expectError(error.MalformedToken, NegTokenInit.parse(&bad));
}

// --- end-to-end SPNEGO handshake driven by a test NTLM client -------------

const common = struct {
    const user = hex("55 00 73 00 65 00 72 00");
    const domain = hex("44 00 6f 00 6d 00 61 00 69 00 6e 00");
    const server_name = hex("53 00 65 00 72 00 76 00 65 00 72 00");
    const password = hex("50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00");
};

fn testNtHash(_: ?*anyopaque, u: []const u8, d: []const u8) ?[16]u8 {
    if (std.mem.eql(u8, u, &common.user) and std.mem.eql(u8, d, &common.domain))
        return md4.ntHash(&common.password);
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

fn makeServer(fr: *FixedRandom) Server {
    return Server.init(testing.allocator, .{
        .nb_computer = &common.server_name,
        .nb_domain = &common.domain,
        .nt_hash = testNtHash,
        .rng = fr.r(),
        .now_filetime = 0,
    });
}

// Reuse the ntlm module's internal test client via its public primitives.
fn clientNtlmNegotiate(gpa: Allocator) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    var bw = bytes.Writer.init(&list, gpa);
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
    return list.toOwnedSlice(gpa);
}

test "raw NTLM path end to end" {
    const gpa = testing.allocator;
    var fr = FixedRandom{ .b = 0x11 };
    var srv = makeServer(&fr);
    defer srv.deinit();

    const neg = try clientNtlmNegotiate(gpa);
    defer gpa.free(neg);
    const out1 = try srv.step(neg);
    const challenge = out1.reply;
    defer gpa.free(challenge);
    try testing.expect(isRawNtlm(challenge));

    const auth = try buildAuthenticate(gpa, neg, challenge);
    defer gpa.free(auth.msg);
    var out2 = try srv.step(auth.msg);
    try testing.expect(out2 == .done);
    try testing.expect(out2.done.final_token == null);
    defer out2.done.result.deinit(gpa);
    try testing.expectEqualSlices(u8, &common.user, out2.done.result.user);
    try testing.expectEqualSlices(u8, &auth.esk, &out2.done.result.keys.exported_session_key);
}

test "SPNEGO path with Kerberos-first fallback to NTLM and mechListMIC" {
    const gpa = testing.allocator;
    var fr = FixedRandom{ .b = 0x22 };
    var srv = makeServer(&fr);
    defer srv.deinit();

    // Client offers [Kerberos, NTLM] with an optimistic (bogus) Kerberos token.
    const krb_token = hex("6e 05 aa bb cc dd ee"); // opaque; not NTLM
    const mechs = [_][]const u8{ &oid.kerberos, &oid.ntlm };
    const init = try buildNegTokenInit(gpa, &mechs, &krb_token, null);
    defer gpa.free(init);

    const out1 = try srv.step(init);
    const r1 = out1.reply;
    defer gpa.free(r1);
    const p1 = try NegTokenResp.parse(r1);
    try testing.expectEqual(NegState.accept_incomplete, p1.neg_state.?);
    try testing.expectEqualSlices(u8, &oid.ntlm, p1.supported_mech.?);
    try testing.expect(p1.response_token == null); // asks client to restart with NTLM

    // Client restarts with NTLM NEGOTIATE wrapped in a NegTokenResp.
    const neg = try clientNtlmNegotiate(gpa);
    defer gpa.free(neg);
    const neg_wrapped = try buildNegTokenResp(gpa, null, null, neg, null);
    defer gpa.free(neg_wrapped);
    const out2 = try srv.step(neg_wrapped);
    const r2 = out2.reply;
    defer gpa.free(r2);
    const p2 = try NegTokenResp.parse(r2);
    const challenge = p2.response_token.?;
    try testing.expect(isRawNtlm(challenge));

    // Client sends AUTHENTICATE + a mechListMIC in the final NegTokenResp.
    const auth = try buildAuthenticate(gpa, neg, challenge);
    defer gpa.free(auth.msg);
    const keys = ntlm.SessionKeys.derive(auth.esk);
    const mech_der = try mechTypeListDer(gpa, &mechs);
    defer gpa.free(mech_der);
    const client_mic = computeMechListMic(keys, .client, mech_der);
    const auth_wrapped = try buildNegTokenResp(gpa, null, null, auth.msg, &client_mic);
    defer gpa.free(auth_wrapped);

    var out3 = try srv.step(auth_wrapped);
    try testing.expect(out3 == .done);
    defer out3.done.result.deinit(gpa);
    const final = out3.done.final_token.?;
    defer gpa.free(final);
    const pf = try NegTokenResp.parse(final);
    try testing.expectEqual(NegState.accept_completed, pf.neg_state.?);
    // The server echoes its own mechListMIC.
    try testing.expect(pf.mech_list_mic != null);
    try testing.expectEqualSlices(u8, &common.user, out3.done.result.user);
}

test "SPNEGO rejects a bad client mechListMIC" {
    const gpa = testing.allocator;
    var fr = FixedRandom{ .b = 0x33 };
    var srv = makeServer(&fr);
    defer srv.deinit();
    const mechs = [_][]const u8{&oid.ntlm};
    const neg = try clientNtlmNegotiate(gpa);
    defer gpa.free(neg);
    const init = try buildNegTokenInit(gpa, &mechs, neg, null);
    defer gpa.free(init);
    const out1 = try srv.step(init);
    const r1 = out1.reply;
    defer gpa.free(r1);
    const p1 = try NegTokenResp.parse(r1);
    const challenge = p1.response_token.?;

    const auth = try buildAuthenticate(gpa, neg, challenge);
    defer gpa.free(auth.msg);
    const bad_mic = hex("01 00 00 00 de ad be ef de ad be ef 00 00 00 00");
    const auth_wrapped = try buildNegTokenResp(gpa, null, null, auth.msg, &bad_mic);
    defer gpa.free(auth_wrapped);
    try testing.expectError(error.MechListMicMismatch, srv.step(auth_wrapped));
}

// --- minimal NTLMv2 client used by the SPNEGO tests ------------------------

const Built = struct { msg: []u8, esk: [16]u8 };

fn mechTypeListDer(gpa: Allocator, mechs: []const []const u8) ![]u8 {
    var w = der.Writer.init(gpa);
    errdefer w.deinit();
    try w.begin(der.tag.sequence);
    for (mechs) |m| try w.oid(m);
    try w.end();
    return w.toOwnedSlice();
}

fn buildAuthenticate(gpa: Allocator, negotiate_msg: []const u8, challenge_msg: []const u8) !Built {
    var r = bytes.Reader.init(challenge_msg);
    _ = try r.bytes(12);
    const tn_len = try r.u16le();
    _ = try r.u16le();
    _ = try r.u32le();
    _ = tn_len;
    _ = try r.u32le(); // flags
    const server_challenge: [8]u8 = (try r.bytes(8))[0..8].*;
    _ = try r.bytes(8);
    const ti_len = try r.u16le();
    _ = try r.u16le();
    const ti_off = try r.u32le();
    const target_info = challenge_msg[ti_off .. ti_off + ti_len];

    const nt = md4.ntHash(&common.password);
    const key = try ntlm.ntowfv2(nt, &common.user, &common.domain);
    const client_challenge: [8]u8 = @splat(0xaa);
    const random_session_key: [16]u8 = @splat(0x55);

    var temp: std.ArrayList(u8) = .empty;
    defer temp.deinit(gpa);
    var tw = bytes.Writer.init(&temp, gpa);
    try tw.bytes(&[_]u8{ 1, 1, 0, 0, 0, 0, 0, 0 });
    try tw.u64le(0);
    try tw.bytes(&client_challenge);
    try tw.zeros(4);
    // echo target info minus EOL, add MsvAvFlags(MIC), re-add EOL
    try tw.bytes(target_info[0 .. target_info.len - 4]);
    try tw.u16le(@backingInt(ntlm.AvId.flags));
    try tw.u16le(4);
    try tw.u32le(ntlm.av_flag_mic_present);
    try tw.bytes(&[_]u8{ 0, 0, 0, 0 });
    try tw.zeros(4);

    const proof = ntlm.ntProofStr(key, server_challenge, temp.items);
    const sbk = ntlm.sessionBaseKey(key, proof);
    var ersk: [16]u8 = undefined;
    @import("rc4.zig").Rc4.oneShot(&sbk, &random_session_key, &ersk);
    const lm = ntlm.lmv2Response(key, server_challenge, client_challenge);

    const nt_resp_len: u16 = @intCast(16 + temp.items.len);
    const payload_base: u32 = 88;
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    var w = bytes.Writer.init(&msg, gpa);
    try w.bytes(ntlm.signature);
    try w.u32le(3);
    var off = payload_base;
    try w.u16le(24);
    try w.u16le(24);
    try w.u32le(off);
    off += 24;
    try w.u16le(nt_resp_len);
    try w.u16le(nt_resp_len);
    try w.u32le(off);
    off += nt_resp_len;
    try w.u16le(@intCast(common.domain.len));
    try w.u16le(@intCast(common.domain.len));
    try w.u32le(off);
    off += @intCast(common.domain.len);
    try w.u16le(@intCast(common.user.len));
    try w.u16le(@intCast(common.user.len));
    try w.u32le(off);
    off += @intCast(common.user.len);
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
    try w.zeros(16); // MIC placeholder

    try w.bytes(&lm);
    try w.bytes(&proof);
    try w.bytes(temp.items);
    try w.bytes(&common.domain);
    try w.bytes(&common.user);
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
