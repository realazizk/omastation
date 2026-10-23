//! NTLM (MS-NLMP) server side, NTLMv2 only: the flags Windows negotiates for NLA are
//! required (extended session security, 128-bit, key exchange, seal, sign, Unicode) and
//! LM / NTLMv1 responses are rejected. NTProofStr and the MIC compare in constant time.

const std = @import("std");
const log = std.log.scoped(.ntlm);
const bytes = @import("../core/bytes.zig");
const md4 = @import("md4.zig");
const rc4 = @import("rc4.zig");
const upcase = @import("upcase.zig");

const Md5 = std.crypto.hash.Md5;
const HmacMd5 = std.crypto.auth.hmac.HmacMd5;
const Allocator = std.mem.Allocator;

pub const signature = "NTLMSSP\x00";

pub const Error = error{
    NotNtlmssp,
    BadMessageType,
    Truncated,
    BadOffset,
    WeakFlags,
    NotNtlmV2,
    LmOrNtlmV1Rejected,
    UnknownUser,
    ProofMismatch,
    MicMismatch,
    MissingKeyExchange,
    BadSignature,
    SequenceMismatch,
    NameTooLong,
} || Allocator.Error;

pub const MessageType = enum(u32) {
    negotiate = 1,
    challenge = 2,
    authenticate = 3,
};

/// NegotiateFlags (MS-NLMP 2.2.2.5). Bit positions per the field figure.
pub const Flags = packed struct(u32) {
    unicode: bool = false, // 0x00000001 NTLMSSP_NEGOTIATE_UNICODE
    oem: bool = false, // 0x00000002 NTLM_NEGOTIATE_OEM
    request_target: bool = false, // 0x00000004 NTLMSSP_REQUEST_TARGET
    _r0: bool = false, // 0x00000008
    sign: bool = false, // 0x00000010 NTLMSSP_NEGOTIATE_SIGN
    seal: bool = false, // 0x00000020 NTLMSSP_NEGOTIATE_SEAL
    datagram: bool = false, // 0x00000040 NTLMSSP_NEGOTIATE_DATAGRAM
    lm_key: bool = false, // 0x00000080 NTLMSSP_NEGOTIATE_LM_KEY
    _r1: bool = false, // 0x00000100
    ntlm: bool = false, // 0x00000200 NTLMSSP_NEGOTIATE_NTLM
    _r2: bool = false, // 0x00000400
    anonymous: bool = false, // 0x00000800 NTLMSSP_NEGOTIATE_ANONYMOUS
    oem_domain_supplied: bool = false, // 0x00001000
    oem_workstation_supplied: bool = false, // 0x00002000
    _r3: bool = false, // 0x00004000
    always_sign: bool = false, // 0x00008000 NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    target_type_domain: bool = false, // 0x00010000
    target_type_server: bool = false, // 0x00020000
    _r4: bool = false, // 0x00040000
    extended_session_security: bool = false, // 0x00080000 (NTLM2)
    identify: bool = false, // 0x00100000
    _r5: bool = false, // 0x00200000
    request_non_nt_session_key: bool = false, // 0x00400000
    target_info: bool = false, // 0x00800000 NTLMSSP_NEGOTIATE_TARGET_INFO
    _r6: bool = false, // 0x01000000
    version: bool = false, // 0x02000000 NTLMSSP_NEGOTIATE_VERSION
    _r7: bool = false, // 0x04000000
    _r8: bool = false, // 0x08000000
    _r9: bool = false, // 0x10000000
    negotiate_128: bool = false, // 0x20000000 NTLMSSP_NEGOTIATE_128
    key_exch: bool = false, // 0x40000000 NTLMSSP_NEGOTIATE_KEY_EXCH
    negotiate_56: bool = false, // 0x80000000 NTLMSSP_NEGOTIATE_56

    pub fn toInt(f: Flags) u32 {
        return @bitCast(f);
    }
    pub fn fromInt(v: u32) Flags {
        return @bitCast(v);
    }
};

/// AV_PAIR identifiers (MS-NLMP 2.2.2.1).
pub const AvId = enum(u16) {
    eol = 0x0000,
    nb_computer_name = 0x0001,
    nb_domain_name = 0x0002,
    dns_computer_name = 0x0003,
    dns_domain_name = 0x0004,
    dns_tree_name = 0x0005,
    flags = 0x0006,
    timestamp = 0x0007,
    single_host = 0x0008,
    target_name = 0x0009,
    channel_bindings = 0x000A,
    _,
};

/// MsvAvFlags bit 0x2: the client provides a MIC in the AUTHENTICATE message.
pub const av_flag_mic_present: u32 = 0x00000002;

/// VERSION (MS-NLMP 2.2.2.10). Debug-only on the wire; a plausible value is emitted.
pub const Version = struct {
    major: u8 = 10,
    minor: u8 = 0,
    build: u16 = 19041,
    ntlm_revision: u8 = 0x0F, // NTLMSSP_REVISION_W2K3

    pub fn write(v: Version, w: *bytes.Writer) !void {
        try w.byte(v.major);
        try w.byte(v.minor);
        try w.u16le(v.build);
        try w.zeros(3);
        try w.byte(v.ntlm_revision);
    }
};

// NTLMv2 cryptographic primitives (MS-NLMP 3.3.2 / 3.4.5)

fn hmacMd5(key: []const u8, msg: []const u8) [16]u8 {
    var out: [16]u8 = undefined;
    HmacMd5.create(&out, msg, key);
    return out;
}

/// NTOWFv2 = HMAC_MD5(ntHash, UTF-16LE(Uppercase(user) ++ domain)); names are UTF-16LE bytes.
pub fn ntowfv2(nt_hash: [16]u8, user_utf16: []const u8, domain_utf16: []const u8) Error![16]u8 {
    var buf: [512]u8 = undefined;
    if (user_utf16.len + domain_utf16.len > buf.len) return error.NameTooLong;
    upcase.upcaseUtf16LeInto(buf[0..user_utf16.len], user_utf16);
    @memcpy(buf[user_utf16.len..][0..domain_utf16.len], domain_utf16);
    const n = user_utf16.len + domain_utf16.len;
    defer std.crypto.secureZero(u8, buf[0..n]);
    return hmacMd5(&nt_hash, buf[0..n]);
}

/// NTProofStr = HMAC_MD5(responseKeyNT, ServerChallenge ++ temp) (MS-NLMP 3.3.2).
pub fn ntProofStr(response_key_nt: [16]u8, server_challenge: [8]u8, temp: []const u8) [16]u8 {
    var ctx = HmacMd5.init(&response_key_nt);
    ctx.update(&server_challenge);
    ctx.update(temp);
    var out: [16]u8 = undefined;
    ctx.final(&out);
    return out;
}

/// SessionBaseKey = HMAC_MD5(responseKeyNT, NTProofStr); for NTLMv2 it is the KeyExchangeKey.
pub fn sessionBaseKey(response_key_nt: [16]u8, nt_proof: [16]u8) [16]u8 {
    return hmacMd5(&response_key_nt, &nt_proof);
}

/// LMv2 = HMAC_MD5(responseKeyLM, ServerChallenge ++ ClientChallenge) ++ ClientChallenge (3.3.2).
pub fn lmv2Response(response_key_lm: [16]u8, server_challenge: [8]u8, client_challenge: [8]u8) [24]u8 {
    var msg: [16]u8 = undefined;
    @memcpy(msg[0..8], &server_challenge);
    @memcpy(msg[8..16], &client_challenge);
    var out: [24]u8 = undefined;
    out[0..16].* = hmacMd5(&response_key_lm, &msg);
    @memcpy(out[16..24], &client_challenge);
    return out;
}

pub const Mode = enum { client, server };

const sign_magic_c2s = "session key to client-to-server signing key magic constant\x00";
const sign_magic_s2c = "session key to server-to-client signing key magic constant\x00";
const seal_magic_c2s = "session key to client-to-server sealing key magic constant\x00";
const seal_magic_s2c = "session key to server-to-client sealing key magic constant\x00";

/// SIGNKEY (MS-NLMP 3.4.5.2), extended-session-security variant.
pub fn signKey(exported_session_key: [16]u8, mode: Mode) [16]u8 {
    var h = Md5.init(.{});
    h.update(&exported_session_key);
    h.update(if (mode == .client) sign_magic_c2s else sign_magic_s2c);
    var out: [16]u8 = undefined;
    h.final(&out);
    return out;
}

/// SEALKEY (MS-NLMP 3.4.5.3) for the 128-bit extended-session-security case.
pub fn sealKey(exported_session_key: [16]u8, mode: Mode) [16]u8 {
    var h = Md5.init(.{});
    h.update(&exported_session_key);
    h.update(if (mode == .client) seal_magic_c2s else seal_magic_s2c);
    var out: [16]u8 = undefined;
    h.final(&out);
    return out;
}

// Session security: SEAL + MAC (MS-NLMP 3.4.3 / 3.4.4.2), connection-oriented.

pub const signature_len = 16;

/// One direction of NTLM session security; the RC4 stream and SeqNum (from 0, +1 per message)
/// carry across messages (connection-oriented, MS-NLMP 3.4.4).
pub const SealingState = struct {
    rc4: rc4.Rc4,
    sign_key: [16]u8,
    seq: u32 = 0,

    pub fn init(sealing_key: [16]u8, sign_key_: [16]u8) SealingState {
        return .{ .rc4 = rc4.Rc4.init(&sealing_key), .sign_key = sign_key_ };
    }

    pub fn deinit(s: *SealingState) void {
        s.rc4.wipe();
        std.crypto.secureZero(u8, &s.sign_key);
    }

    /// MAC with ESS and key exchange (3.4.4.2): Version(1) ++ RC4(HMAC_MD5(signKey, seq ++ msg)[0..8])
    /// ++ seq; consumes 8 bytes of keystream and advances `seq`.
    fn mac(s: *SealingState, message: []const u8, out_sig: *[signature_len]u8) void {
        s.finishMac(s.checksum(message), out_sig);
    }

    /// HMAC_MD5(SigningKey, SeqNum ++ Message)[0..8]; no keystream, so it can run before sealing.
    fn checksum(s: *const SealingState, message: []const u8) [8]u8 {
        var ctx = HmacMd5.init(&s.sign_key);
        var seq_le: [4]u8 = undefined;
        std.mem.writeInt(u32, &seq_le, s.seq, .little);
        ctx.update(&seq_le);
        ctx.update(message);
        var full: [16]u8 = undefined;
        ctx.final(&full);
        defer std.crypto.secureZero(u8, &full);
        return full[0..8].*;
    }

    fn finishMac(s: *SealingState, checksum_: [8]u8, out_sig: *[signature_len]u8) void {
        var cs = checksum_;
        s.rc4.apply(&cs);
        std.mem.writeInt(u32, out_sig[0..4], 1, .little); // Version
        @memcpy(out_sig[4..12], &cs);
        std.mem.writeInt(u32, out_sig[12..16], s.seq, .little); // SeqNum (not XORed in ESS variant)
        s.seq +%= 1;
    }

    /// GSS_GetMICEx (MS-NLMP 3.4.8): sign without encrypting; consumes 8 keystream bytes, advances `seq`.
    pub fn sign(s: *SealingState, message: []const u8, out_sig: *[signature_len]u8) void {
        s.mac(message, out_sig);
    }

    /// Constant-time on the checksum; advances `seq` on a sequence match.
    pub fn verify(s: *SealingState, message: []const u8, sig: []const u8) Error!void {
        if (sig.len != signature_len) return error.BadSignature;
        const seq_before = s.seq;
        var expect: [signature_len]u8 = undefined;
        s.mac(message, &expect);
        if (std.mem.readInt(u32, sig[0..4], .little) != 1) {
            s.seq = seq_before;
            return error.BadSignature;
        }
        if (std.mem.readInt(u32, sig[12..16], .little) != seq_before) {
            s.seq = seq_before;
            return error.SequenceMismatch;
        }
        if (!std.crypto.timing_safe.eql([8]u8, expect[4..12].*, sig[4..12].*)) return error.BadSignature;
    }

    /// GSS_WrapEx (MS-NLMP 3.4.6): seal `data` in place and sign the plaintext with the continuing
    /// RC4 stream (message, then checksum); any length (3.4.1).
    pub fn seal(s: *SealingState, data: []u8, out_sig: *[signature_len]u8) void {
        const cs = s.checksum(data); // MAC over the plaintext
        s.rc4.apply(data); // Sealed = RC4(Handle, Message)
        s.finishMac(cs, out_sig);
    }

    /// GSS_UnwrapEx (MS-NLMP 3.4.7); error on checksum or sequence mismatch.
    pub fn unseal(s: *SealingState, data: []u8, sig: []const u8) Error!void {
        if (sig.len != signature_len) return error.BadSignature;
        s.rc4.apply(data); // decrypt in place -> plaintext
        var expect: [signature_len]u8 = undefined;
        // Re-run MAC over the recovered plaintext; mac() advances seq, so snapshot.
        const seq_before = s.seq;
        s.mac(data, &expect);
        if (std.mem.readInt(u32, sig[0..4], .little) != 1) {
            s.seq = seq_before;
            return error.BadSignature;
        }
        if (std.mem.readInt(u32, sig[12..16], .little) != seq_before) {
            s.seq = seq_before;
            return error.SequenceMismatch;
        }
        if (!std.crypto.timing_safe.eql([8]u8, expect[4..12].*, sig[4..12].*)) {
            return error.BadSignature;
        }
    }
};

/// Session keys after a successful AUTHENTICATE (MS-NLMP 3.2.5.1.2): `to_client` for
/// server->client traffic, `from_client` for client->server.
pub const SessionKeys = struct {
    exported_session_key: [16]u8,
    client_signing_key: [16]u8,
    server_signing_key: [16]u8,
    client_sealing_key: [16]u8,
    server_sealing_key: [16]u8,

    pub fn derive(exported_session_key: [16]u8) SessionKeys {
        return .{
            .exported_session_key = exported_session_key,
            .client_signing_key = signKey(exported_session_key, .client),
            .server_signing_key = signKey(exported_session_key, .server),
            .client_sealing_key = sealKey(exported_session_key, .client),
            .server_sealing_key = sealKey(exported_session_key, .server),
        };
    }

    pub fn toClient(k: SessionKeys) SealingState {
        return SealingState.init(k.server_sealing_key, k.server_signing_key);
    }
    pub fn fromClient(k: SessionKeys) SealingState {
        return SealingState.init(k.client_sealing_key, k.client_signing_key);
    }

    pub fn wipe(k: *SessionKeys) void {
        std.crypto.secureZero(u8, std.mem.asBytes(k));
    }
};

// Message parsing

/// A (len, offset) payload descriptor, resolved against the full message.
const FieldRef = struct {
    len: u16,
    offset: u32,

    fn read(r: *bytes.Reader) Error!FieldRef {
        const len = r.u16le() catch return error.Truncated;
        _ = r.u16le() catch return error.Truncated; // MaxLen, ignored
        const off = r.u32le() catch return error.Truncated;
        return .{ .len = len, .offset = off };
    }

    fn slice(fr: FieldRef, msg: []const u8) Error![]const u8 {
        // An empty field's offset means nothing; some clients send 0.
        if (fr.len == 0) return msg[0..0];
        const end = @as(usize, fr.offset) + fr.len;
        if (fr.offset > msg.len or end > msg.len) return error.BadOffset;
        return msg[fr.offset..end];
    }
};

fn checkSignature(r: *bytes.Reader, want_type: MessageType) Error!void {
    const sig = r.bytes(8) catch return error.Truncated;
    if (!std.mem.eql(u8, sig, signature)) return error.NotNtlmssp;
    const mt = r.u32le() catch return error.Truncated;
    if (mt != @backingInt(want_type)) return error.BadMessageType;
}

pub const NegotiateMessage = struct {
    flags: Flags,
    raw: []const u8,

    pub fn parse(msg: []const u8) Error!NegotiateMessage {
        var r = bytes.Reader.init(msg);
        try checkSignature(&r, .negotiate);
        const flags = Flags.fromInt(r.u32le() catch return error.Truncated);
        // DomainNameFields, WorkstationFields and Version may follow; the server needs none.
        return .{ .flags = flags, .raw = msg };
    }
};

pub const AuthenticateMessage = struct {
    raw: []const u8,
    flags: Flags,
    lm_challenge_response: []const u8,
    nt_challenge_response: []const u8,
    domain_name: []const u8,
    user_name: []const u8,
    workstation: []const u8,
    encrypted_random_session_key: []const u8,
    /// Offset of the 16-byte MIC field (always 72 when present), or null.
    mic_offset: ?usize,

    pub fn parse(msg: []const u8) Error!AuthenticateMessage {
        var r = bytes.Reader.init(msg);
        try checkSignature(&r, .authenticate);
        var f: [6]FieldRef = undefined; // lm, nt, domain, user, workstation, key
        for (&f) |*fr| fr.* = try FieldRef.read(&r);
        const flags = Flags.fromInt(r.u32le() catch return error.Truncated);
        return resolve(msg, flags, f) catch |err| {
            // Interop diagnostics: the layout only (lengths and offsets).
            log.warn("AUTHENTICATE rejected ({t}): {d} bytes; len@offset lm {d}@{d} nt {d}@{d} domain {d}@{d} user {d}@{d} workstation {d}@{d} key {d}@{d}", .{
                err,      msg.len,     f[0].len, f[0].offset, f[1].len, f[1].offset, f[2].len, f[2].offset,
                f[3].len, f[3].offset, f[4].len, f[4].offset, f[5].len, f[5].offset,
            });
            return err;
        };
    }

    fn resolve(msg: []const u8, flags: Flags, f: [6]FieldRef) Error!AuthenticateMessage {
        const lm_resp = try f[0].slice(msg);
        const nt_resp = try f[1].slice(msg);

        // MsvAvFlags 0x2 in the client's AvPairs means a MIC at [72..88] (MS-NLMP 3.2.5.1.2).
        var mic_off: ?usize = null;
        if (nt_resp.len > 24) {
            const cc = try ClientChallenge.parse(nt_resp);
            if (cc.mic_requested) {
                if (msg.len < 88) return error.Truncated;
                // Payload must not overlap the MIC; empty fields carry none, whatever their offset.
                for (f) |fr| {
                    if (fr.len != 0 and fr.offset < 88) return error.BadOffset;
                }
                mic_off = 72;
            }
        }

        return .{
            .raw = msg,
            .flags = flags,
            .lm_challenge_response = lm_resp,
            .nt_challenge_response = nt_resp,
            .domain_name = try f[2].slice(msg),
            .user_name = try f[3].slice(msg),
            .workstation = try f[4].slice(msg),
            .encrypted_random_session_key = try f[5].slice(msg),
            .mic_offset = mic_off,
        };
    }
};

/// NTLMv2_RESPONSE = NTProofStr(16) ++ temp (MS-NLMP 2.2.2.7): RespType(1) HiRespType(1)
/// Reserved1(2) Reserved2(4) Timestamp(8) ChallengeFromClient(8) Reserved3(4) AvPairs Reserved(4).
pub const ClientChallenge = struct {
    nt_proof: [16]u8,
    temp: []const u8,
    timestamp: u64,
    challenge_from_client: [8]u8,
    av_pairs: []const u8,
    mic_requested: bool,

    pub fn parse(nt_response: []const u8) Error!ClientChallenge {
        if (nt_response.len < 16 + 28) return error.NotNtlmV2; // proof + min header
        const nt_proof = nt_response[0..16].*;
        const temp = nt_response[16..];
        var r = bytes.Reader.init(temp);
        const resp_type = r.byte() catch return error.Truncated;
        const hi_resp_type = r.byte() catch return error.Truncated;
        if (resp_type != 1 or hi_resp_type != 1) return error.NotNtlmV2;
        _ = r.u16le() catch return error.Truncated; // Reserved1
        _ = r.u32le() catch return error.Truncated; // Reserved2
        const timestamp = r.u64le() catch return error.Truncated;
        const cfc = r.bytes(8) catch return error.Truncated;
        _ = r.u32le() catch return error.Truncated; // Reserved3
        const av_pairs = r.rest();

        var mic_requested = false;
        var av = bytes.Reader.init(av_pairs);
        while (true) {
            const id = av.u16le() catch return error.Truncated;
            const len = av.u16le() catch return error.Truncated;
            const val = av.bytes(len) catch return error.Truncated;
            if (@as(AvId, @fromBackingInt(@intCast(id))) == .eol) {
                if (len != 0) return error.Truncated;
                break;
            }
            if (@as(AvId, @fromBackingInt(@intCast(id))) == .flags and len >= 4) {
                const f = std.mem.readInt(u32, val[0..4], .little);
                if (f & av_flag_mic_present != 0) mic_requested = true;
            }
        }

        return .{
            .nt_proof = nt_proof,
            .temp = temp,
            .timestamp = timestamp,
            .challenge_from_client = cfc[0..8].*,
            .av_pairs = av_pairs,
            .mic_requested = mic_requested,
        };
    }
};

// CHALLENGE_MESSAGE construction (MS-NLMP 3.2.5.1.1)

/// Name slices are UTF-16LE bytes (even length).
pub const TargetInfo = struct {
    nb_domain: ?[]const u8 = null,
    nb_computer: ?[]const u8 = null,
    dns_domain: ?[]const u8 = null,
    dns_computer: ?[]const u8 = null,
    dns_tree: ?[]const u8 = null,
    timestamp: ?u64 = null,
};

pub const ChallengeConfig = struct {
    /// UTF-16LE TargetName (typically the NetBIOS computer or domain name).
    target_name: []const u8,
    server_challenge: [8]u8,
    flags: Flags,
    target_info: TargetInfo,
    version: Version = .{},
};

fn writeAvPair(w: *bytes.Writer, id: AvId, value: []const u8) !void {
    try w.u16le(@backingInt(id));
    try w.u16le(@intCast(value.len));
    try w.bytes(value);
}

/// TargetInfo AV pairs skip absent names and end with MsvAvEOL.
pub fn buildChallenge(gpa: Allocator, out: *std.ArrayList(u8), cfg: ChallengeConfig) !void {
    var w = bytes.Writer.init(out, gpa);
    try w.bytes(signature);
    try w.u32le(@backingInt(MessageType.challenge));

    const tn_fields = w.len();
    try w.u16le(@intCast(cfg.target_name.len));
    try w.u16le(@intCast(cfg.target_name.len));
    try w.u32le(0);

    try w.u32le(cfg.flags.toInt());
    try w.bytes(&cfg.server_challenge);
    try w.zeros(8); // Reserved

    const ti_fields = w.len();
    try w.u16le(0); // TargetInfoLen (back-filled)
    try w.u16le(0);
    try w.u32le(0);

    try cfg.version.write(&w);

    const tn_off = w.len();
    try w.bytes(cfg.target_name);
    w.patchU32le(tn_fields + 4, @intCast(tn_off));

    const ti_off = w.len();
    const ti = cfg.target_info;
    if (ti.nb_domain) |v| try writeAvPair(&w, .nb_domain_name, v);
    if (ti.nb_computer) |v| try writeAvPair(&w, .nb_computer_name, v);
    if (ti.dns_domain) |v| try writeAvPair(&w, .dns_domain_name, v);
    if (ti.dns_computer) |v| try writeAvPair(&w, .dns_computer_name, v);
    if (ti.dns_tree) |v| try writeAvPair(&w, .dns_tree_name, v);
    if (ti.timestamp) |t| {
        try w.u16le(@backingInt(AvId.timestamp));
        try w.u16le(8);
        try w.u64le(t);
    }
    try writeAvPair(&w, .eol, "");
    const ti_len = w.len() - ti_off;
    w.patchU16le(ti_fields, @intCast(ti_len));
    w.patchU16le(ti_fields + 2, @intCast(ti_len));
    w.patchU32le(ti_fields + 4, @intCast(ti_off));
}

// Server state machine

/// MD4(UTF-16LE(password)) for the UTF-16LE user/domain; null for an unknown user.
pub const NtHashFn = *const fn (ctx: ?*anyopaque, user_utf16: []const u8, domain_utf16: []const u8) ?[16]u8;

pub const ServerOptions = struct {
    /// UTF-16LE names used for TargetName and TargetInfo AvPairs.
    nb_computer: []const u8,
    nb_domain: ?[]const u8 = null,
    dns_computer: ?[]const u8 = null,
    dns_domain: ?[]const u8 = null,
    dns_tree: ?[]const u8 = null,
    version: Version = .{},
    nt_hash: NtHashFn,
    nt_hash_ctx: ?*anyopaque = null,
    /// Injected randomness and clock (so tests are deterministic).
    rng: std.Random,
    /// Current time as a Windows FILETIME (100 ns ticks since 1601-01-01 UTC).
    now_filetime: u64,
};

pub const AuthResult = struct {
    /// UTF-16LE, owned by the caller's allocator.
    user: []u8,
    domain: []u8,
    workstation: []u8,
    keys: SessionKeys,

    pub fn deinit(self: *AuthResult, gpa: Allocator) void {
        gpa.free(self.user);
        gpa.free(self.domain);
        gpa.free(self.workstation);
        self.keys.wipe();
    }
};

pub const Server = struct {
    gpa: Allocator,
    opts: ServerOptions,
    negotiate_msg: ?[]u8 = null,
    challenge_msg: ?[]u8 = null,
    server_challenge: [8]u8 = undefined,
    challenge_flags: Flags = .{},

    pub fn init(gpa: Allocator, opts: ServerOptions) Server {
        return .{ .gpa = gpa, .opts = opts };
    }

    pub fn deinit(s: *Server) void {
        if (s.negotiate_msg) |m| s.gpa.free(m);
        if (s.challenge_msg) |m| s.gpa.free(m);
    }

    /// The strong-security set derived from the client's request; rejects a client too weak for NLA.
    fn challengeFlags(req: Flags) Error!Flags {
        if (!req.unicode) return error.WeakFlags;
        if (!req.extended_session_security) return error.WeakFlags;
        if (!(req.sign or req.seal)) return error.WeakFlags;
        if (!req.key_exch) return error.WeakFlags;
        if (!req.negotiate_128) return error.WeakFlags;
        return .{
            .unicode = true,
            .request_target = true,
            .sign = true,
            .seal = true,
            .ntlm = true,
            .always_sign = true,
            .target_type_server = true,
            .extended_session_security = true,
            .target_info = true,
            .version = true,
            .negotiate_128 = true,
            .key_exch = true,
            .negotiate_56 = req.negotiate_56,
        };
    }

    /// Returns the CHALLENGE_MESSAGE, owned by this Server until deinit.
    pub fn consumeNegotiate(s: *Server, negotiate: []const u8) Error![]const u8 {
        const neg = try NegotiateMessage.parse(negotiate);
        const flags = try challengeFlags(neg.flags);

        // Nothing is kept unless the whole CHALLENGE is built, so a retry after OutOfMemory does not leak.
        const neg_copy = try s.gpa.dupe(u8, negotiate);
        errdefer s.gpa.free(neg_copy);
        var server_challenge: [8]u8 = undefined;
        s.opts.rng.bytes(&server_challenge);

        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(s.gpa);
        try buildChallenge(s.gpa, &list, .{
            .target_name = s.opts.nb_computer,
            .server_challenge = server_challenge,
            .flags = flags,
            .version = s.opts.version,
            .target_info = .{
                // MsvAvNbDomainName MUST be present (MS-NLMP 2.2.2.1); Windows clients reject the CHALLENGE
                // without it. A workgroup machine uses its own name, as Windows does.
                .nb_domain = s.opts.nb_domain orelse s.opts.nb_computer,
                .nb_computer = s.opts.nb_computer,
                .dns_domain = s.opts.dns_domain orelse s.opts.dns_computer,
                .dns_computer = s.opts.dns_computer,
                .dns_tree = s.opts.dns_tree,
                .timestamp = s.opts.now_filetime,
            },
        });
        const challenge = try list.toOwnedSlice(s.gpa);
        if (s.negotiate_msg) |m| s.gpa.free(m);
        if (s.challenge_msg) |m| s.gpa.free(m);
        s.negotiate_msg = neg_copy;
        s.challenge_msg = challenge;
        s.server_challenge = server_challenge;
        s.challenge_flags = flags;
        return challenge;
    }

    /// On failure no secret escapes.
    pub fn consumeAuthenticate(s: *Server, authenticate: []const u8) Error!AuthResult {
        if (s.challenge_msg == null or s.negotiate_msg == null) return error.BadMessageType;
        const auth = try AuthenticateMessage.parse(authenticate);

        // Enforce NTLMv2: NtChallengeResponse must be an NTLMv2_RESPONSE.
        if (auth.nt_challenge_response.len <= 24) return error.LmOrNtlmV1Rejected;
        if (auth.flags.lm_key) return error.LmOrNtlmV1Rejected;
        if (!auth.flags.extended_session_security) return error.NotNtlmV2;
        if (!auth.flags.key_exch) return error.MissingKeyExchange;

        const cc = try ClientChallenge.parse(auth.nt_challenge_response);

        // An unknown user takes the wrong-password path with a placeholder hash, rejected after the
        // proof check, so timing does not reveal which accounts exist (MS-NLMP 3.2.5.1.2).
        const known = s.opts.nt_hash(s.opts.nt_hash_ctx, auth.user_name, auth.domain_name);
        var nt_hash: [16]u8 = known orelse @splat(0x5a);
        defer std.crypto.secureZero(u8, &nt_hash);

        var response_key = try ntowfv2(nt_hash, auth.user_name, auth.domain_name);
        defer std.crypto.secureZero(u8, &response_key);

        // Verify NTProofStr over ServerChallenge ++ temp (constant time).
        const expected = ntProofStr(response_key, s.server_challenge, cc.temp);
        const proof_ok = std.crypto.timing_safe.eql([16]u8, expected, cc.nt_proof);

        // Servers SHOULD accept a ResponseKeyNT computed with a NIL domain (MS-NLMP 3.2.5.1.2); always
        // computed so timing does not tell which proof matched.
        var response_key_nil = try ntowfv2(nt_hash, auth.user_name, &.{});
        defer std.crypto.secureZero(u8, &response_key_nil);
        const expected_nil = ntProofStr(response_key_nil, s.server_challenge, cc.temp);
        const nil_ok = std.crypto.timing_safe.eql([16]u8, expected_nil, cc.nt_proof);
        if (known == null) return error.UnknownUser;
        if (!proof_ok) {
            if (!nil_ok) return error.ProofMismatch;
            response_key = response_key_nil;
        }

        var session_base = sessionBaseKey(response_key, cc.nt_proof);
        defer std.crypto.secureZero(u8, &session_base);
        // NTLMv2: KeyExchangeKey == SessionBaseKey.

        // ExportedSessionKey = RC4K(KeyExchangeKey, EncryptedRandomSessionKey).
        if (auth.encrypted_random_session_key.len != 16) return error.MissingKeyExchange;
        var esk: [16]u8 = undefined;
        rc4.Rc4.oneShot(&session_base, auth.encrypted_random_session_key, &esk);
        defer std.crypto.secureZero(u8, &esk);

        // MIC verification (MS-NLMP 3.2.5.1.2), if the client provided one.
        if (auth.mic_offset) |mic_off| {
            const received_mic: [16]u8 = authenticate[mic_off..][0..16].*;
            // HMAC over NEGOTIATE ++ CHALLENGE ++ AUTHENTICATE(MIC zeroed).
            var ctx = HmacMd5.init(&esk);
            ctx.update(s.negotiate_msg.?);
            ctx.update(s.challenge_msg.?);
            ctx.update(authenticate[0..mic_off]);
            const zero_mic: [16]u8 = @splat(0);
            ctx.update(&zero_mic);
            ctx.update(authenticate[mic_off + 16 ..]);
            var computed: [16]u8 = undefined;
            ctx.final(&computed);
            if (!std.crypto.timing_safe.eql([16]u8, computed, received_mic)) return error.MicMismatch;
        }

        const keys = SessionKeys.derive(esk);

        const user = try s.gpa.dupe(u8, auth.user_name);
        errdefer s.gpa.free(user);
        const domain = try s.gpa.dupe(u8, auth.domain_name);
        errdefer s.gpa.free(domain);
        const ws = try s.gpa.dupe(u8, auth.workstation);

        return .{ .user = user, .domain = domain, .workstation = ws, .keys = keys };
    }
};

const testing = std.testing;
const hex = bytes.hex;

// MS-NLMP 4.2.1 common values.
const common = struct {
    const user = hex("55 00 73 00 65 00 72 00"); // "User"
    const domain = hex("44 00 6f 00 6d 00 61 00 69 00 6e 00"); // "Domain"
    const server_name = hex("53 00 65 00 72 00 76 00 65 00 72 00"); // "Server"
    const password = hex("50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00"); // "Password"
    const random_session_key: [16]u8 = @splat(0x55);
    const client_challenge: [8]u8 = @splat(0xaa);
    const server_challenge = hex("01 23 45 67 89 ab cd ef");
    const time: u64 = 0;
};

test "NTOWFv2 (MS-NLMP 4.2.4.1.1)" {
    const nt = md4.ntHash(&common.password);
    const key = try ntowfv2(nt, &common.user, &common.domain);
    try testing.expectEqualSlices(u8, &hex("0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f"), &key);
}

/// Build the "temp" blob (NTLMv2_CLIENT_CHALLENGE) used by 4.2.4.
fn specTemp() [68]u8 {
    // 01 01 00 00 00 00 00 00 | Time(8) | ClientChallenge(8) | 00 00 00 00
    // | AvPairs: NbDomainName "Domain", NbComputerName "Server", EOL | 00 00 00 00
    return hex(
        "01 01 00 00 00 00 00 00" ++
            "00 00 00 00 00 00 00 00" ++
            "aa aa aa aa aa aa aa aa" ++
            "00 00 00 00" ++
            "02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00" ++
            "01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00" ++
            "00 00 00 00" ++
            "00 00 00 00",
    );
}

test "NTProofStr and NTChallengeResponse (MS-NLMP 4.2.4.2.2)" {
    const nt = md4.ntHash(&common.password);
    const key = try ntowfv2(nt, &common.user, &common.domain);
    const temp = specTemp();
    const proof = ntProofStr(key, common.server_challenge, &temp);
    try testing.expectEqualSlices(u8, &hex("68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c"), &proof);
}

test "LMv2 response (MS-NLMP 4.2.4.2.1)" {
    const nt = md4.ntHash(&common.password);
    const key = try ntowfv2(nt, &common.user, &common.domain);
    const lm = lmv2Response(key, common.server_challenge, common.client_challenge);
    try testing.expectEqualSlices(u8, &hex("86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa"), &lm);
}

test "SessionBaseKey (MS-NLMP 4.2.4.1.2)" {
    const nt = md4.ntHash(&common.password);
    const key = try ntowfv2(nt, &common.user, &common.domain);
    const temp = specTemp();
    const proof = ntProofStr(key, common.server_challenge, &temp);
    const sbk = sessionBaseKey(key, proof);
    try testing.expectEqualSlices(u8, &hex("8d e4 0c ca db c1 4a 82 f1 5c b0 ad 0d e9 5c a3"), &sbk);
}

test "EncryptedSessionKey (MS-NLMP 4.2.4.2.3)" {
    // ExportedSessionKey encrypt: RC4K(KeyExchangeKey=SessionBaseKey, RandomSessionKey)
    const sbk = hex("8d e4 0c ca db c1 4a 82 f1 5c b0 ad 0d e9 5c a3");
    var out: [16]u8 = undefined;
    rc4.Rc4.oneShot(&sbk, &common.random_session_key, &out);
    try testing.expectEqualSlices(u8, &hex("c5 da d2 54 4f c9 79 90 94 ce 1c e9 0b c9 d0 3e"), &out);
}

test "SIGNKEY and SEALKEY client-to-server (MS-NLMP 4.2.4.4)" {
    const esk = common.random_session_key; // RandomSessionKey is the ExportedSessionKey here
    const sign = signKey(esk, .client);
    const seal = sealKey(esk, .client);
    try testing.expectEqualSlices(u8, &hex("47 88 dc 86 1b 47 82 f3 5d 43 fd 98 fe 1a 2d 39"), &sign);
    try testing.expectEqualSlices(u8, &hex("59 f6 00 97 3c c4 96 0a 25 48 0a 7c 19 6e 4c 58"), &seal);
}

test "GSS_WrapEx seal + signature (MS-NLMP 4.2.4.4)" {
    const esk = common.random_session_key;
    var st = SealingState.init(sealKey(esk, .client), signKey(esk, .client));
    defer st.deinit();
    var data = hex("50 00 6c 00 61 00 69 00 6e 00 74 00 65 00 78 00 74 00"); // "Plaintext" UTF-16LE
    var sig: [16]u8 = undefined;
    st.seal(&data, &sig);
    try testing.expectEqualSlices(u8, &hex("54 e5 01 65 bf 19 36 dc 99 60 20 c1 81 1b 0f 06 fb 5f"), &data);
    try testing.expectEqualSlices(u8, &hex("01 00 00 00 7f b3 8e c5 c5 5d 49 76 00 00 00 00"), &sig);
}

test "unseal round trip and tamper detection" {
    const esk: [16]u8 = @splat(0x55);
    const keys = SessionKeys.derive(esk);
    var enc = keys.toClient();
    defer enc.deinit();
    var dec = SealingState.init(keys.server_sealing_key, keys.server_signing_key);
    defer dec.deinit();

    var msg = "hello wire".*;
    var sig: [16]u8 = undefined;
    enc.seal(&msg, &sig);
    try dec.unseal(&msg, &sig);
    try testing.expectEqualStrings("hello wire", &msg);

    // Tamper with a byte -> checksum mismatch.
    var enc2 = keys.toClient();
    defer enc2.deinit();
    var dec2 = SealingState.init(keys.server_sealing_key, keys.server_signing_key);
    defer dec2.deinit();
    var msg2 = "hello wire".*;
    enc2.seal(&msg2, &sig);
    msg2[0] ^= 0xFF;
    try testing.expectError(error.BadSignature, dec2.unseal(&msg2, &sig));
}

test "challenge message reproduces MS-NLMP 4.2.4.3 bytes" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try buildChallenge(testing.allocator, &list, .{
        .target_name = &common.server_name,
        .server_challenge = common.server_challenge,
        .flags = Flags.fromInt(0xe28a8233),
        .version = .{ .major = 6, .minor = 0, .build = 6000, .ntlm_revision = 0x0F },
        .target_info = .{ .nb_domain = &common.domain, .nb_computer = &common.server_name },
    });
    const expected = hex(
        "4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00" ++
            "38 00 00 00 33 82 8a e2 01 23 45 67 89 ab cd ef" ++
            "00 00 00 00 00 00 00 00 24 00 24 00 44 00 00 00" ++
            "06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00" ++
            "65 00 72 00 02 00 0c 00 44 00 6f 00 6d 00 61 00" ++
            "69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00" ++
            "65 00 72 00 00 00 00 00",
    );
    try testing.expectEqualSlices(u8, &expected, list.items);
}

test "parse AUTHENTICATE from MS-NLMP 4.2.4.3" {
    const auth_bytes = hex(
        "4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00" ++
            "6c 00 00 00 54 00 54 00 84 00 00 00 0c 00 0c 00" ++
            "48 00 00 00 08 00 08 00 54 00 00 00 10 00 10 00" ++
            "5c 00 00 00 10 00 10 00 d8 00 00 00 35 82 88 e2" ++
            "05 01 28 0a 00 00 00 0f 44 00 6f 00 6d 00 61 00" ++
            "69 00 6e 00 55 00 73 00 65 00 72 00 43 00 4f 00" ++
            "4d 00 50 00 55 00 54 00 45 00 52 00 86 c3 50 97" ++
            "ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa" ++
            "aa aa aa aa 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b" ++
            "eb ef 6a 1c 01 01 00 00 00 00 00 00 00 00 00 00" ++
            "00 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 00" ++
            "02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00" ++
            "01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00" ++
            "00 00 00 00 00 00 00 00 c5 da d2 54 4f c9 79 90" ++
            "94 ce 1c e9 0b c9 d0 3e",
    );
    const auth = try AuthenticateMessage.parse(&auth_bytes);
    try testing.expectEqualSlices(u8, &common.domain, auth.domain_name);
    try testing.expectEqualSlices(u8, &common.user, auth.user_name);
    try testing.expectEqual(@as(usize, 84), auth.nt_challenge_response.len);
    try testing.expectEqual(@as(usize, 16), auth.encrypted_random_session_key.len);
    try testing.expect(auth.mic_offset == null); // this historical example carries no MIC

    const cc = try ClientChallenge.parse(auth.nt_challenge_response);
    try testing.expectEqualSlices(u8, &hex("68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c"), &cc.nt_proof);
    try testing.expectEqual(@as(u64, 0), cc.timestamp);
    try testing.expectEqualSlices(u8, &common.client_challenge, &cc.challenge_from_client);

    const nt = md4.ntHash(&common.password);
    const key = try ntowfv2(nt, auth.user_name, auth.domain_name);
    const proof = ntProofStr(key, common.server_challenge, cc.temp);
    try testing.expectEqualSlices(u8, &cc.nt_proof, &proof);
}

test "parse rejects malformed AUTHENTICATE" {
    // the rejections below log their layout on purpose
    testing.log_level = .err;
    defer testing.log_level = .warn;
    // Bad signature.
    try testing.expectError(error.NotNtlmssp, AuthenticateMessage.parse(&hex("00 00 00 00 00 00 00 00 03 00 00 00")));
    // Truncated header.
    try testing.expectError(error.Truncated, AuthenticateMessage.parse(&hex("4e 54 4c 4d 53 53 50 00 03 00 00 00")));
    // Offset pointing past the buffer.
    var good: [64]u8 = @splat(0);
    @memcpy(good[0..8], signature);
    std.mem.writeInt(u32, good[8..12], 3, .little);
    // NtChallengeResponse len=4 at offset=0x1000 (out of range).
    std.mem.writeInt(u16, good[20..22], 4, .little);
    std.mem.writeInt(u16, good[22..24], 4, .little);
    std.mem.writeInt(u32, good[24..28], 0x1000, .little);
    try testing.expectError(error.BadOffset, AuthenticateMessage.parse(&good));
}

test "AUTHENTICATE: empty fields may have any offset" {
    // the rejections below log their layout on purpose
    testing.log_level = .err;
    defer testing.log_level = .warn;
    // Empty fields (Workstation, LmChallengeResponse) with offset 0 next to a MIC, as some clients send.
    const gpa = testing.allocator;
    var fixed = FixedRandom{ .fill_byte = 0x11 };
    var srv = Server.init(gpa, .{
        .nb_computer = &common.server_name,
        .nb_domain = &common.domain,
        .nt_hash = testNtHash,
        .rng = fixed.random(),
        .now_filetime = 0,
    });
    defer srv.deinit();
    var neg: std.ArrayList(u8) = .empty;
    defer neg.deinit(gpa);
    try TestClient.negotiate(gpa, &neg);
    const challenge = try gpa.dupe(u8, try srv.consumeNegotiate(neg.items));
    defer gpa.free(challenge);
    var built = try TestClient.authenticate(gpa, neg.items, challenge, &common.password, @splat(0xaa), @splat(0x55), true);
    defer gpa.free(built.msg);

    // Workstation (descriptor at 44): empty, offset 0.
    std.mem.writeInt(u32, built.msg[48..52], 0, .little);
    // LmChallengeResponse (descriptor at 12): empty, offset 0.
    std.mem.writeInt(u16, built.msg[12..14], 0, .little);
    std.mem.writeInt(u16, built.msg[14..16], 0, .little);
    std.mem.writeInt(u32, built.msg[16..20], 0, .little);

    const auth = try AuthenticateMessage.parse(built.msg);
    try testing.expectEqual(@as(usize, 0), auth.workstation.len);
    try testing.expectEqual(@as(usize, 0), auth.lm_challenge_response.len);
    try testing.expectEqualSlices(u8, &common.user, auth.user_name);
    try testing.expectEqual(@as(?usize, 72), auth.mic_offset);

    // A non-empty field inside the MIC region is still rejected.
    std.mem.writeInt(u32, built.msg[40..44], 80, .little); // UserName offset
    try testing.expectError(error.BadOffset, AuthenticateMessage.parse(built.msg));
}

// Deterministic CHALLENGE generation: returns the configured server challenge.
const FixedRandom = struct {
    fill_byte: u8,
    fn fillFn(self: *FixedRandom, buf: []u8) void {
        @memset(buf, self.fill_byte);
    }
    fn random(self: *FixedRandom) std.Random {
        return std.Random.init(self, fillFn);
    }
};

fn testNtHash(ctx: ?*anyopaque, user_utf16: []const u8, domain_utf16: []const u8) ?[16]u8 {
    _ = ctx;
    // Single known user: "User" / "Domain" with password "Password".
    if (std.mem.eql(u8, user_utf16, &common.user) and std.mem.eql(u8, domain_utf16, &common.domain)) {
        return md4.ntHash(&common.password);
    }
    return null;
}

/// Minimal NTLMv2 client used to drive a full server handshake in tests.
const TestClient = struct {
    fn negotiate(gpa: Allocator, out: *std.ArrayList(u8)) !void {
        var w = bytes.Writer.init(out, gpa);
        try w.bytes(signature);
        try w.u32le(@backingInt(MessageType.negotiate));
        const flags = Flags{
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
        try w.u32le(flags.toInt());
        try w.zeros(8); // DomainNameFields
        try w.zeros(8); // WorkstationFields
    }

    const Built = struct {
        msg: []u8,
        esk: [16]u8,
    };

    fn authenticate(
        gpa: Allocator,
        negotiate_msg: []const u8,
        challenge_msg: []const u8,
        password_utf16: []const u8,
        client_challenge: [8]u8,
        random_session_key: [16]u8,
        with_mic: bool,
    ) !Built {
        var r = bytes.Reader.init(challenge_msg);
        _ = try r.bytes(12);
        _ = try FieldRef.read(&r); // TargetNameFields
        const flags = Flags.fromInt(try r.u32le());
        _ = flags;
        const server_challenge: [8]u8 = (try r.bytes(8))[0..8].*;
        _ = try r.bytes(8); // Reserved
        const ti = try FieldRef.read(&r);
        const target_info = try ti.slice(challenge_msg);

        const nt = md4.ntHash(password_utf16);
        const key = try ntowfv2(nt, &common.user, &common.domain);

        // temp = 01 01 00*6 | Time(8) | ClientChallenge | 00*4 | TargetInfo | 00*4
        var temp: std.ArrayList(u8) = .empty;
        defer temp.deinit(gpa);
        var tw = bytes.Writer.init(&temp, gpa);
        try tw.bytes(&[_]u8{ 1, 1, 0, 0, 0, 0, 0, 0 });
        try tw.u64le(0); // Time
        try tw.bytes(&client_challenge);
        try tw.zeros(4);
        if (with_mic) {
            // Echo the server AvPairs minus MsvAvEOL, add MsvAvFlags (MIC present), re-add EOL.
            try tw.bytes(target_info[0 .. target_info.len - 4]);
            try tw.u16le(@backingInt(AvId.flags));
            try tw.u16le(4);
            try tw.u32le(av_flag_mic_present);
            try tw.bytes(&[_]u8{ 0, 0, 0, 0 }); // MsvAvEOL
        } else {
            try tw.bytes(target_info);
        }
        try tw.zeros(4);

        const proof = ntProofStr(key, server_challenge, temp.items);
        const sbk = sessionBaseKey(key, proof);
        var ersk: [16]u8 = undefined;
        rc4.Rc4.oneShot(&sbk, &random_session_key, &ersk);
        const lm = lmv2Response(key, server_challenge, client_challenge);

        const nt_resp_len: u16 = @intCast(16 + temp.items.len);
        const payload_base: u32 = if (with_mic) 88 else 72;

        var msg: std.ArrayList(u8) = .empty;
        errdefer msg.deinit(gpa);
        var w = bytes.Writer.init(&msg, gpa);
        try w.bytes(signature);
        try w.u32le(@backingInt(MessageType.authenticate));

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
        off += 16;

        const flags_out = Flags{
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
        try (Version{}).write(&w);
        if (with_mic) try w.zeros(16); // MIC placeholder

        try w.bytes(&lm);
        try w.bytes(&proof);
        try w.bytes(temp.items);
        try w.bytes(&common.domain);
        try w.bytes(&common.user);
        try w.bytes(&ersk);

        if (with_mic) {
            // MIC = HMAC_MD5(ExportedSessionKey = RandomSessionKey, NEG ++ CHAL ++ AUTH[MIC=0]).
            var ctx = HmacMd5.init(&random_session_key);
            ctx.update(negotiate_msg);
            ctx.update(challenge_msg);
            ctx.update(msg.items);
            var mic: [16]u8 = undefined;
            ctx.final(&mic);
            @memcpy(msg.items[72..88], &mic);
        }

        return .{ .msg = try msg.toOwnedSlice(gpa), .esk = random_session_key };
    }
};

test "challenge always carries domain AV pairs (Windows SSPI requires them)" {
    // Windows clients reject a CHALLENGE without MsvAvNbDomainName (MS-NLMP 2.2.2.1).
    const gpa = testing.allocator;
    var fixed = FixedRandom{ .fill_byte = 0x11 };
    var srv = Server.init(gpa, .{
        .nb_computer = &common.server_name,
        .dns_computer = &common.server_name,
        .nt_hash = testNtHash,
        .rng = fixed.random(),
        .now_filetime = 0,
    });
    defer srv.deinit();
    var neg: std.ArrayList(u8) = .empty;
    defer neg.deinit(gpa);
    try TestClient.negotiate(gpa, &neg);
    const challenge = try srv.consumeNegotiate(neg.items);

    var r = bytes.Reader.init(challenge);
    try r.skip(40);
    const ti_len = try r.u16le();
    try r.skip(2);
    const ti_off = try r.u32le();
    var ti = bytes.Reader.init(challenge[ti_off..][0..ti_len]);
    var seen: u32 = 0;
    while (true) {
        const id = try ti.u16le();
        const len = try ti.u16le();
        const val = try ti.bytes(len);
        if (id == 0) break;
        seen |= @as(u32, 1) << @intCast(id);
        if (id == @backingInt(AvId.nb_domain_name)) try testing.expectEqualSlices(u8, &common.server_name, val);
    }
    for ([_]AvId{ .nb_computer_name, .nb_domain_name, .dns_computer_name, .dns_domain_name, .timestamp }) |id|
        try testing.expect(seen & (@as(u32, 1) << @intCast(@backingInt(id))) != 0);
}

test "full server handshake round trip (with MIC)" {
    const gpa = testing.allocator;
    var fixed = FixedRandom{ .fill_byte = 0x11 };

    var srv = Server.init(gpa, .{
        .nb_computer = &common.server_name,
        .nb_domain = &common.domain,
        .nt_hash = testNtHash,
        .rng = fixed.random(),
        .now_filetime = 0,
    });
    defer srv.deinit();

    var neg: std.ArrayList(u8) = .empty;
    defer neg.deinit(gpa);
    try TestClient.negotiate(gpa, &neg);

    const challenge = try srv.consumeNegotiate(neg.items);
    const challenge_copy = try gpa.dupe(u8, challenge);
    defer gpa.free(challenge_copy);

    var built = try TestClient.authenticate(gpa, neg.items, challenge_copy, &common.password, @splat(0xaa), @splat(0x55), true);
    defer gpa.free(built.msg);

    var result = try srv.consumeAuthenticate(built.msg);
    defer result.deinit(gpa);
    try testing.expectEqualSlices(u8, &common.user, result.user);
    try testing.expectEqualSlices(u8, &common.domain, result.domain);
    // The session key derived by the server matches the client's.
    try testing.expectEqualSlices(u8, &built.esk, &result.keys.exported_session_key);

    // A sealed message from the server is unsealable by the client's keys.
    var to_client = result.keys.toClient();
    defer to_client.deinit();
    var peer = SealingState.init(result.keys.server_sealing_key, result.keys.server_signing_key);
    defer peer.deinit();
    var payload = "pubkeyauth".*;
    var sig: [16]u8 = undefined;
    to_client.seal(&payload, &sig);
    try peer.unseal(&payload, &sig);
    try testing.expectEqualStrings("pubkeyauth", &payload);
}

test "full handshake without MIC" {
    const gpa = testing.allocator;
    var fixed = FixedRandom{ .fill_byte = 0x22 };
    var srv = Server.init(gpa, .{
        .nb_computer = &common.server_name,
        .nb_domain = &common.domain,
        .nt_hash = testNtHash,
        .rng = fixed.random(),
        .now_filetime = 0,
    });
    defer srv.deinit();

    var neg: std.ArrayList(u8) = .empty;
    defer neg.deinit(gpa);
    try TestClient.negotiate(gpa, &neg);
    const challenge = try srv.consumeNegotiate(neg.items);
    const challenge_copy = try gpa.dupe(u8, challenge);
    defer gpa.free(challenge_copy);

    const built = try TestClient.authenticate(gpa, neg.items, challenge_copy, &common.password, @splat(0xbb), @splat(0x55), false);
    defer gpa.free(built.msg);
    var result = try srv.consumeAuthenticate(built.msg);
    defer result.deinit(gpa);
    try testing.expectEqualSlices(u8, &common.user, result.user);
}

test "wrong password is rejected" {
    const gpa = testing.allocator;
    var fixed = FixedRandom{ .fill_byte = 0x33 };
    var srv = Server.init(gpa, .{
        .nb_computer = &common.server_name,
        .nb_domain = &common.domain,
        .nt_hash = testNtHash,
        .rng = fixed.random(),
        .now_filetime = 0,
    });
    defer srv.deinit();

    var neg: std.ArrayList(u8) = .empty;
    defer neg.deinit(gpa);
    try TestClient.negotiate(gpa, &neg);
    const challenge = try srv.consumeNegotiate(neg.items);
    const challenge_copy = try gpa.dupe(u8, challenge);
    defer gpa.free(challenge_copy);

    // Client authenticates with the WRONG password.
    const wrong_pw = hex("57 00 72 00 6f 00 6e 00 67 00"); // "Wrong"
    const built = try TestClient.authenticate(gpa, neg.items, challenge_copy, &wrong_pw, @splat(0xaa), @splat(0x55), true);
    defer gpa.free(built.msg);
    try testing.expectError(error.ProofMismatch, srv.consumeAuthenticate(built.msg));
}

test "tampered MIC is rejected" {
    const gpa = testing.allocator;
    var fixed = FixedRandom{ .fill_byte = 0x44 };
    var srv = Server.init(gpa, .{
        .nb_computer = &common.server_name,
        .nb_domain = &common.domain,
        .nt_hash = testNtHash,
        .rng = fixed.random(),
        .now_filetime = 0,
    });
    defer srv.deinit();
    var neg: std.ArrayList(u8) = .empty;
    defer neg.deinit(gpa);
    try TestClient.negotiate(gpa, &neg);
    const challenge = try srv.consumeNegotiate(neg.items);
    const challenge_copy = try gpa.dupe(u8, challenge);
    defer gpa.free(challenge_copy);
    var built = try TestClient.authenticate(gpa, neg.items, challenge_copy, &common.password, @splat(0xaa), @splat(0x55), true);
    defer gpa.free(built.msg);
    built.msg[72] ^= 0xFF; // corrupt the MIC
    try testing.expectError(error.MicMismatch, srv.consumeAuthenticate(built.msg));
}

test "weak client flags rejected at negotiate" {
    const gpa = testing.allocator;
    var fixed = FixedRandom{ .fill_byte = 0x55 };
    var srv = Server.init(gpa, .{
        .nb_computer = &common.server_name,
        .nt_hash = testNtHash,
        .rng = fixed.random(),
        .now_filetime = 0,
    });
    defer srv.deinit();

    // NEGOTIATE without extended session security.
    var neg: std.ArrayList(u8) = .empty;
    defer neg.deinit(gpa);
    var w = bytes.Writer.init(&neg, gpa);
    try w.bytes(signature);
    try w.u32le(@backingInt(MessageType.negotiate));
    try w.u32le((Flags{ .unicode = true, .ntlm = true }).toInt());
    try w.zeros(16);
    try testing.expectError(error.WeakFlags, srv.consumeNegotiate(neg.items));
}

test "unknown user rejected" {
    const gpa = testing.allocator;
    var fixed = FixedRandom{ .fill_byte = 0x66 };
    var srv = Server.init(gpa, .{
        .nb_computer = &common.server_name,
        .nb_domain = &common.domain,
        .nt_hash = struct {
            fn f(_: ?*anyopaque, _: []const u8, _: []const u8) ?[16]u8 {
                return null;
            }
        }.f,
        .rng = fixed.random(),
        .now_filetime = 0,
    });
    defer srv.deinit();
    var neg: std.ArrayList(u8) = .empty;
    defer neg.deinit(gpa);
    try TestClient.negotiate(gpa, &neg);
    const challenge = try srv.consumeNegotiate(neg.items);
    const challenge_copy = try gpa.dupe(u8, challenge);
    defer gpa.free(challenge_copy);
    const built = try TestClient.authenticate(gpa, neg.items, challenge_copy, &common.password, @splat(0xaa), @splat(0x55), true);
    defer gpa.free(built.msg);
    try testing.expectError(error.UnknownUser, srv.consumeAuthenticate(built.msg));
}

test "NTLMv1-length response rejected" {
    const gpa = testing.allocator;
    var fixed = FixedRandom{ .fill_byte = 0x77 };
    var srv = Server.init(gpa, .{
        .nb_computer = &common.server_name,
        .nt_hash = testNtHash,
        .rng = fixed.random(),
        .now_filetime = 0,
    });
    defer srv.deinit();
    var neg: std.ArrayList(u8) = .empty;
    defer neg.deinit(gpa);
    try TestClient.negotiate(gpa, &neg);
    _ = try srv.consumeNegotiate(neg.items);

    // Craft an AUTHENTICATE whose NtChallengeResponse is exactly 24 bytes (NTLMv1).
    var msg: [160]u8 = @splat(0);
    @memcpy(msg[0..8], signature);
    std.mem.writeInt(u32, msg[8..12], 3, .little);
    std.mem.writeInt(u16, msg[20..22], 24, .little); // NtChallengeResponse len
    std.mem.writeInt(u16, msg[22..24], 24, .little);
    std.mem.writeInt(u32, msg[24..28], 72, .little); // offset
    const flags = Flags{ .unicode = true, .extended_session_security = true, .key_exch = true };
    std.mem.writeInt(u32, msg[60..64], flags.toInt(), .little);
    try testing.expectError(error.LmOrNtlmV1Rejected, srv.consumeAuthenticate(&msg));
}
