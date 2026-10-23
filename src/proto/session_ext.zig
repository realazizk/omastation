//! MS-RDPBCGR session extras: auto-reconnect (2.2.4, 5.5), Save Session Info (2.2.10.1),
//! Server Redirection (2.2.13), Heartbeat (2.2.16), keyboard status (2.2.8.2),
//! Monitor Layout (2.2.12.1), Play Sound (2.2.9.1.1.5). Enhanced RDP Security only.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

pub const Error = error{
    EndOfBuffer,
    BadLength,
    BadVersion,
    UnknownInfoType,
    UnexpectedPdu,
    /// A field violates a MUST (odd UTF-16 length, missing terminator, nonzero reserved).
    InvalidField,
    TooLong,
    /// The client did not advertise the PDU in earlyCapabilityFlags.
    NotSupported,
    TooManyMonitors,
    OutOfMemory,
};

// Share Data PDU framing (2.2.8.1.1.1)

pub const pdutype_datapdu: u16 = 0x7;
pub const pdutype_server_redir_pkt: u16 = 0xA;
pub const ts_protocol_version: u16 = 0x10;

pub const pdutype2_play_sound: u8 = 34;
pub const pdutype2_save_session_info: u8 = 38;
pub const pdutype2_set_keyboard_indicators: u8 = 41;
pub const pdutype2_set_keyboard_ime_status: u8 = 45;
pub const pdutype2_arc_status_pdu: u8 = 50;
pub const pdutype2_monitor_layout_pdu: u8 = 55;

pub const stream_undefined: u8 = 0;
pub const stream_low: u8 = 1;
pub const stream_med: u8 = 2;
pub const stream_hi: u8 = 4;

/// TS_SHARECONTROLHEADER (6) + TS_SHAREDATAHEADER (12).
const share_data_header_size: usize = 18;
const packet_compressed: u8 = 0x20;

/// The fields of TS_SHARECONTROLHEADER/TS_SHAREDATAHEADER a sender chooses.
pub const ShareDataHeader = struct {
    share_id: u32,
    pdu_source: u16 = 1002,
    stream_id: u8 = stream_low,
    pdu_type2: u8,
};

/// TS_SHARECONTROLHEADER + uncompressed TS_SHAREDATAHEADER + `body`.
pub fn encodeShareDataPdu(w: *bytes.Writer, hdr: ShareDataHeader, body: []const u8) !void {
    if (body.len > std.math.maxInt(u16) - share_data_header_size) return error.TooLong;
    const total: u16 = @intCast(share_data_header_size + body.len);
    try w.u16le(total); // totalLength
    try w.u16le(ts_protocol_version | pdutype_datapdu);
    try w.u16le(hdr.pdu_source);
    try w.u32le(hdr.share_id);
    try w.byte(0); // pad1
    try w.byte(hdr.stream_id);
    try w.u16le(total); // uncompressedLength: totalLength, as Windows (4.3)
    try w.byte(hdr.pdu_type2);
    try w.byte(0); // compressedType
    try w.u16le(0); // compressedLength
    try w.bytes(body);
}

pub const ShareDataPdu = struct { header: ShareDataHeader, body: []const u8 };

/// Splits a Share Data PDU (totalLength must fit `pdu`).
pub fn decodeShareDataPdu(pdu: []const u8) Error!ShareDataPdu {
    var r = bytes.Reader.init(pdu);
    const total = try r.u16le();
    if (total < share_data_header_size) return error.BadLength;
    if (total > pdu.len) return error.EndOfBuffer;
    r = bytes.Reader.init(pdu[0..total]);
    try r.skip(2);
    if (try r.u16le() & 0xF != pdutype_datapdu) return error.UnexpectedPdu;
    const source = try r.u16le();
    const sid = try r.u32le();
    _ = try r.byte(); // pad1
    const stream = try r.byte();
    _ = try r.u16le(); // uncompressedLength
    const type2 = try r.byte();
    // These PDUs are never bulk-compressed.
    if (try r.byte() & packet_compressed != 0) return error.InvalidField;
    _ = try r.u16le(); // compressedLength
    return .{
        .header = .{ .share_id = sid, .pdu_source = source, .stream_id = stream, .pdu_type2 = type2 },
        .body = r.rest(),
    };
}

// 2.2.4 Auto-reconnect, 5.5

pub const auto_reconnect_version_1: u32 = 0x00000001;
/// cbLen of both auto-reconnect packets.
pub const arc_packet_len: u32 = 28;

/// ARC_SC_PRIVATE_PACKET (2.2.4.2).
pub const ArcScPacket = struct { logon_id: u32, arc_random_bits: [16]u8 };

/// Both packets: cbLen, Version, LogonId, then 16 bytes (2.2.4.2, 2.2.4.3).
fn encodeArcPacket(w: *bytes.Writer, logon_id: u32, tail: [16]u8) !void {
    try w.u32le(arc_packet_len);
    try w.u32le(auto_reconnect_version_1);
    try w.u32le(logon_id);
    try w.bytes(&tail);
}

const ArcFields = struct { logon_id: u32, tail: [16]u8 };

fn decodeArcPacket(buf: []const u8) Error!ArcFields {
    var r = bytes.Reader.init(buf);
    if (try r.u32le() != arc_packet_len) return error.BadLength;
    if (try r.u32le() != auto_reconnect_version_1) return error.BadVersion;
    const logon_id = try r.u32le();
    const tail = (try r.bytes(16))[0..16].*;
    if (r.remaining() != 0) return error.BadLength;
    return .{ .logon_id = logon_id, .tail = tail };
}

pub fn encodeArcScPacket(w: *bytes.Writer, p: ArcScPacket) !void {
    try encodeArcPacket(w, p.logon_id, p.arc_random_bits);
}

pub fn decodeArcScPacket(buf: []const u8) Error!ArcScPacket {
    const f = try decodeArcPacket(buf);
    return .{ .logon_id = f.logon_id, .arc_random_bits = f.tail };
}

/// ARC_CS_PRIVATE_PACKET (2.2.4.3): the client's autoReconnectCookie (2.2.1.11.1.1.1).
pub const ArcCsPacket = struct { logon_id: u32, security_verifier: [16]u8 };

pub fn encodeArcCsPacket(w: *bytes.Writer, p: ArcCsPacket) !void {
    try encodeArcPacket(w, p.logon_id, p.security_verifier);
}

pub fn decodeArcCsPacket(buf: []const u8) Error!ArcCsPacket {
    const f = try decodeArcPacket(buf);
    return .{ .logon_id = f.logon_id, .security_verifier = f.tail };
}

/// HMAC-MD5(key = ArcRandomBits, data = ClientRandom) (5.5 step 4). A null `client_random`
/// (Enhanced RDP Security) means 32 zero bytes.
pub fn securityVerifier(arc_random_bits: [16]u8, client_random: ?*const [32]u8) Error![16]u8 {
    const zeros: [32]u8 = @splat(0);
    const data: *const [32]u8 = client_random orelse &zeros;
    var out: [16]u8 = undefined;
    std.crypto.auth.hmac.HmacMd5.create(&out, data, &arc_random_bits);
    return out;
}

/// Per-session auto-reconnect cookie (5.5); a cookie is single-use.
pub const AutoReconnect = struct {
    logon_id: u32,
    arc_random_bits: [16]u8,
    valid: bool = true,

    pub fn init(logon_id: u32, arc_random_bits: [16]u8) Error!AutoReconnect {
        return .{ .logon_id = logon_id, .arc_random_bits = arc_random_bits };
    }

    /// The ARC_SC_PRIVATE_PACKET to send in the Save Session Info PDU.
    pub fn cookie(a: *const AutoReconnect) Error!ArcScPacket {
        return .{ .logon_id = a.logon_id, .arc_random_bits = a.arc_random_bits };
    }

    /// Checks the client's autoReconnectCookie (5.5 step 5); a match consumes it.
    pub fn verify(a: *AutoReconnect, client_cookie: []const u8, client_random: ?*const [32]u8) Error!bool {
        const p = try decodeArcCsPacket(client_cookie);
        if (!a.valid) return false;
        const expected = try securityVerifier(a.arc_random_bits, client_random);
        const verifier_ok = std.crypto.timing_safe.eql([16]u8, expected, p.security_verifier);
        if (!verifier_ok or p.logon_id != a.logon_id) return false;
        a.valid = false;
        return true;
    }

    /// New random bits (after a connection, or the hourly refresh of 5.5).
    pub fn regenerate(a: *AutoReconnect, arc_random_bits: [16]u8) Error!void {
        a.arc_random_bits = arc_random_bits;
        a.valid = true;
    }
};

/// Auto-Reconnect Status PDU (2.2.4.1.1): pduSource zero, arcStatus zero.
pub fn encodeArcStatusPdu(w: *bytes.Writer, share_id: u32) !void {
    var body: [4]u8 = @splat(0); // arcStatus: MUST be zero
    try encodeShareDataPdu(w, .{ .share_id = share_id, .pdu_source = 0, .pdu_type2 = pdutype2_arc_status_pdu }, &body);
}

// 2.2.10.1 Save Session Info

pub const infotype_logon: u32 = 0x00000000;
pub const infotype_logon_long: u32 = 0x00000001;
pub const infotype_logon_plainnotify: u32 = 0x00000002;
pub const infotype_logon_extended_info: u32 = 0x00000003;

pub const save_session_pdu_version_one: u16 = 0x0001;
pub const logon_ex_autoreconnectcookie: u32 = 0x00000001;
pub const logon_ex_logonerrors: u32 = 0x00000002;

/// Fixed field sizes (2.2.10.1.1.1 - 2.2.10.1.1.4).
pub const logon_v1_domain_size: usize = 52;
pub const logon_v1_user_name_size: usize = 512;
pub const logon_v2_pad_size: usize = 558;
pub const plain_notify_pad_size: usize = 576;
pub const logon_extended_pad_size: usize = 570;

/// TS_LOGON_INFO_VERSION_2 up to Pad. Windows sends this as Size (4.3.1), the spec's total
/// is 576 (2.2.10.1.1.2); both are accepted.
const logon_v2_header_size: u32 = 18;
const logon_v2_total_size: u32 = logon_v2_header_size + logon_v2_pad_size;
/// cbFieldData of TS_LOGON_ERRORS_INFO (2.2.10.1.1.4.1).
const logon_errors_size: u32 = 8;

pub const logon_msg_session_busy_options: u32 = 0xFFFFFFF8;
pub const logon_msg_disconnect_refused: u32 = 0xFFFFFFF9;
pub const logon_msg_no_permission: u32 = 0xFFFFFFFA;
pub const logon_msg_bump_options: u32 = 0xFFFFFFFB;
pub const logon_msg_reconnect_options: u32 = 0xFFFFFFFC;
pub const logon_msg_session_terminate: u32 = 0xFFFFFFFD;
pub const logon_msg_session_continue: u32 = 0xFFFFFFFE;
pub const error_code_access_denied: u32 = 0xFFFFFFFF;
pub const logon_failed_bad_password: u32 = 0x00000000;
pub const logon_failed_update_password: u32 = 0x00000001;
pub const logon_failed_other: u32 = 0x00000002;
pub const logon_warning: u32 = 0x00000003;

/// INFO_LOGONNOTIFY of the Client Info PDU flags (2.2.1.11.1.1).
const info_logonnotify: u32 = 0x00000040;

/// TS_LOGON_ERRORS_INFO (2.2.10.1.1.4.1.1).
pub const LogonErrors = struct { error_notification_type: u32, error_notification_data: u32 };

/// UTF-16LE names without the null terminator; the encoder adds it.
pub const LogonNames = struct { domain: []const u8, user_name: []const u8, session_id: u32 };

/// TS_SAVE_SESSION_INFO_PDU_DATA infoData, by infoType.
pub const LogonInfo = union(enum) {
    /// INFOTYPE_LOGON: TS_LOGON_INFO (2.2.10.1.1.1).
    logon: LogonNames,
    /// INFOTYPE_LOGON_LONG: TS_LOGON_INFO_VERSION_2 (2.2.10.1.1.2).
    logon_long: LogonNames,
    /// INFOTYPE_LOGON_PLAINNOTIFY: TS_PLAIN_NOTIFY (2.2.10.1.1.3).
    plain_notify,
    /// INFOTYPE_LOGON_EXTENDED_INFO: TS_LOGON_INFO_EXTENDED (2.2.10.1.1.4).
    extended: struct { auto_reconnect: ?ArcScPacket = null, errors: ?LogonErrors = null },
};

/// cbDomain / cbUserName: UTF-16LE bytes plus terminator; `max` is the fixed field size.
fn nameSize(s: []const u8, max: ?usize) Error!u32 {
    if (s.len % 2 != 0) return error.InvalidField;
    const n = std.math.add(usize, s.len, 2) catch return error.TooLong;
    if (max) |m| if (n > m) return error.TooLong;
    return std.math.cast(u32, n) orelse error.TooLong;
}

/// Strips the UTF-16 null terminator; a zero-length field is an empty name.
fn decodeName(field: []const u8) Error![]const u8 {
    if (field.len == 0) return field;
    if (field.len % 2 != 0) return error.InvalidField;
    if (field[field.len - 2] != 0 or field[field.len - 1] != 0) return error.InvalidField;
    return field[0 .. field.len - 2];
}

/// Writes infoType + infoData (the body after the share data header).
pub fn encodeSaveSessionInfoData(w: *bytes.Writer, info: LogonInfo) !void {
    switch (info) {
        .logon => |n| {
            const cb_domain = try nameSize(n.domain, logon_v1_domain_size);
            const cb_user = try nameSize(n.user_name, logon_v1_user_name_size);
            try w.u32le(infotype_logon);
            try w.u32le(cb_domain);
            try w.bytes(n.domain);
            try w.zeros(logon_v1_domain_size - n.domain.len);
            try w.u32le(cb_user);
            try w.bytes(n.user_name);
            try w.zeros(logon_v1_user_name_size - n.user_name.len);
            try w.u32le(n.session_id);
        },
        .logon_long => |n| {
            const cb_domain = try nameSize(n.domain, null);
            const cb_user = try nameSize(n.user_name, null);
            try w.u32le(infotype_logon_long);
            try w.u16le(save_session_pdu_version_one);
            try w.u32le(logon_v2_header_size); // Size, as Windows sends it (4.3.1)
            try w.u32le(n.session_id);
            try w.u32le(cb_domain);
            try w.u32le(cb_user);
            try w.zeros(logon_v2_pad_size);
            try w.bytes(n.domain);
            try w.zeros(2);
            try w.bytes(n.user_name);
            try w.zeros(2);
        },
        .plain_notify => {
            try w.u32le(infotype_logon_plainnotify);
            try w.zeros(plain_notify_pad_size);
        },
        .extended => |e| {
            var present: u32 = 0;
            var length: u16 = 6; // Length + FieldsPresent
            if (e.auto_reconnect != null) {
                present |= logon_ex_autoreconnectcookie;
                length += 4 + arc_packet_len;
            }
            if (e.errors != null) {
                present |= logon_ex_logonerrors;
                length += 4 + logon_errors_size;
            }
            try w.u32le(infotype_logon_extended_info);
            try w.u16le(length);
            try w.u32le(present);
            // 2.2.10.1.1.4: the fields are ordered by their FieldsPresent bit.
            if (e.auto_reconnect) |c| {
                try w.u32le(arc_packet_len); // cbFieldData
                try encodeArcScPacket(w, c);
            }
            if (e.errors) |le| {
                try w.u32le(logon_errors_size); // cbFieldData
                try w.u32le(le.error_notification_type);
                try w.u32le(le.error_notification_data);
            }
            try w.zeros(logon_extended_pad_size);
        },
    }
}

/// Parses infoType + infoData; strings point into `body`.
pub fn decodeSaveSessionInfoData(body: []const u8) Error!LogonInfo {
    var r = bytes.Reader.init(body);
    switch (try r.u32le()) {
        infotype_logon => {
            const cb_domain = try r.u32le();
            const domain_field = try r.bytes(logon_v1_domain_size);
            const cb_user = try r.u32le();
            const user_field = try r.bytes(logon_v1_user_name_size);
            const session_id = try r.u32le();
            if (cb_domain > logon_v1_domain_size or cb_user > logon_v1_user_name_size) return error.TooLong;
            return .{ .logon = .{
                .domain = try decodeName(domain_field[0..cb_domain]),
                .user_name = try decodeName(user_field[0..cb_user]),
                .session_id = session_id,
            } };
        },
        infotype_logon_long => {
            if (try r.u16le() != save_session_pdu_version_one) return error.BadVersion;
            const size = try r.u32le();
            if (size != logon_v2_header_size and size != logon_v2_total_size) return error.BadLength;
            const session_id = try r.u32le();
            const cb_domain = try r.u32le();
            const cb_user = try r.u32le();
            try r.skip(logon_v2_pad_size);
            const domain = try decodeName(try r.bytes(cb_domain));
            const user_name = try decodeName(try r.bytes(cb_user));
            return .{ .logon_long = .{ .domain = domain, .user_name = user_name, .session_id = session_id } };
        },
        infotype_logon_plainnotify => {
            try r.skip(plain_notify_pad_size);
            return .plain_notify;
        },
        infotype_logon_extended_info => {
            const length = try r.u16le();
            const present = try r.u32le();
            if (length < 6) return error.BadLength;
            var fr = try r.sub(length - 6);
            var out: LogonInfo = .{ .extended = .{} };
            if (present & logon_ex_autoreconnectcookie != 0) {
                const cb = try fr.u32le();
                if (cb != arc_packet_len) return error.BadLength;
                out.extended.auto_reconnect = try decodeArcScPacket(try fr.bytes(cb));
            }
            if (present & logon_ex_logonerrors != 0) {
                const cb = try fr.u32le();
                if (cb != logon_errors_size) return error.BadLength;
                out.extended.errors = .{ .error_notification_type = try fr.u32le(), .error_notification_data = try fr.u32le() };
            }
            // Leftover bytes are allowed only for unknown FieldsPresent bits.
            const known = logon_ex_autoreconnectcookie | logon_ex_logonerrors;
            if (fr.remaining() != 0 and present & ~known == 0) return error.BadLength;
            try r.skip(logon_extended_pad_size);
            return out;
        },
        else => return error.UnknownInfoType,
    }
}

/// The logon notification (3.3.5.10.1): names when the client set INFO_LOGONNOTIFY or the
/// names changed, plain notify otherwise.
pub fn logonNotification(client_info_flags: u32, client_long_credentials: bool, names_changed: bool, names: LogonNames) Error!LogonInfo {
    if (client_info_flags & info_logonnotify == 0 and !names_changed) return .plain_notify;
    return if (client_long_credentials) .{ .logon_long = names } else .{ .logon = names };
}

/// The whole Save Session Info PDU (pduType2 38).
pub fn encodeSaveSessionInfoPdu(w: *bytes.Writer, share_id: u32, pdu_source: u16, info: LogonInfo) !void {
    var body: std.ArrayList(u8) = .empty;
    defer {
        // It may hold an auto-reconnect cookie's random bits.
        std.crypto.secureZero(u8, body.allocatedSlice());
        body.deinit(w.gpa);
    }
    var bw = bytes.Writer.init(&body, w.gpa);
    try encodeSaveSessionInfoData(&bw, info);
    try encodeShareDataPdu(w, .{ .share_id = share_id, .pdu_source = pdu_source, .pdu_type2 = pdutype2_save_session_info }, body.items);
}

// 2.2.13 Server Redirection

pub const sec_redirection_pkt: u16 = 0x0400;

pub const lb_target_net_address: u32 = 0x00000001;
pub const lb_load_balance_info: u32 = 0x00000002;
pub const lb_username: u32 = 0x00000004;
pub const lb_domain: u32 = 0x00000008;
pub const lb_password: u32 = 0x00000010;
pub const lb_dontstoreusername: u32 = 0x00000020;
pub const lb_smartcard_logon: u32 = 0x00000040;
pub const lb_noredirect: u32 = 0x00000080;
pub const lb_target_fqdn: u32 = 0x00000100;
pub const lb_target_netbios_name: u32 = 0x00000200;
pub const lb_target_net_addresses: u32 = 0x00000800;
pub const lb_client_tsv_url: u32 = 0x00001000;
pub const lb_server_tsv_capable: u32 = 0x00002000;
pub const lb_password_is_pk_encrypted: u32 = 0x00004000;
pub const lb_redirection_guid: u32 = 0x00008000;
pub const lb_target_certificate: u32 = 0x00010000;

pub const element_type_certificate: u32 = 32;
pub const encoding_type_asn1_der: u32 = 1;

/// RDP_SERVER_REDIRECTION_PACKET (2.2.13.1). Non-null fields are sent with their LB_* flag;
/// Unicode fields include the null terminator. `flags` holds the other RedirFlags bits.
pub const Redirection = struct {
    session_id: u32,
    flags: u32 = 0,
    target_net_address: ?[]const u8 = null,
    load_balance_info: ?[]const u8 = null,
    user_name: ?[]const u8 = null,
    domain: ?[]const u8 = null,
    password: ?[]const u8 = null,
    target_fqdn: ?[]const u8 = null,
    target_netbios_name: ?[]const u8 = null,
    tsv_url: ?[]const u8 = null,
    redirection_guid: ?[]const u8 = null,
    target_certificate: ?[]const u8 = null,
    /// Raw TARGET_NET_ADDRESSES (2.2.13.1.1), built by `encodeTargetNetAddresses`.
    target_net_addresses: ?[]const u8 = null,
    /// The optional 8-byte Pad (written as zeros).
    pad: bool = true,
};

/// Flags, Length, SessionID and RedirFlags.
const redirection_fixed_size: usize = 12;
const redirection_pad_size: usize = 8;

const FieldKind = enum {
    blob,
    /// "in Unicode format, including a null-terminator".
    unicode_z,
    /// Unicode with terminator unless LB_PASSWORD_IS_PK_ENCRYPTED.
    password,
};

/// The optional fields in wire order (2.2.13.1).
const redirection_fields = [_]struct { flag: u32, name: []const u8, kind: FieldKind }{
    .{ .flag = lb_target_net_address, .name = "target_net_address", .kind = .unicode_z },
    .{ .flag = lb_load_balance_info, .name = "load_balance_info", .kind = .blob },
    .{ .flag = lb_username, .name = "user_name", .kind = .unicode_z },
    .{ .flag = lb_domain, .name = "domain", .kind = .unicode_z },
    .{ .flag = lb_password, .name = "password", .kind = .password },
    .{ .flag = lb_target_fqdn, .name = "target_fqdn", .kind = .unicode_z },
    .{ .flag = lb_target_netbios_name, .name = "target_netbios_name", .kind = .unicode_z },
    .{ .flag = lb_client_tsv_url, .name = "tsv_url", .kind = .blob },
    .{ .flag = lb_redirection_guid, .name = "redirection_guid", .kind = .blob },
    .{ .flag = lb_target_certificate, .name = "target_certificate", .kind = .blob },
    .{ .flag = lb_target_net_addresses, .name = "target_net_addresses", .kind = .blob },
};

fn checkUnicodeZ(s: []const u8) Error!void {
    if (s.len < 2 or s.len % 2 != 0) return error.InvalidField;
    if (s[s.len - 2] != 0 or s[s.len - 1] != 0) return error.InvalidField;
}

fn checkField(kind: FieldKind, flags: u32, s: []const u8) Error!void {
    switch (kind) {
        .blob => {},
        .unicode_z => try checkUnicodeZ(s),
        .password => if (flags & lb_password_is_pk_encrypted == 0) try checkUnicodeZ(s),
    }
}

/// Length counts the whole packet, Pad included.
pub fn encodeRedirectionPacket(w: *bytes.Writer, r: Redirection) !void {
    var flags = r.flags;
    var size: usize = redirection_fixed_size;
    inline for (redirection_fields) |fd| {
        flags &= ~fd.flag;
        if (@field(r, fd.name) != null) flags |= fd.flag;
    }
    inline for (redirection_fields) |fd| {
        if (@field(r, fd.name)) |s| {
            try checkField(fd.kind, flags, s);
            if (s.len > std.math.maxInt(u32)) return error.TooLong;
            size += 4 + s.len;
        }
    }
    if (r.pad) size += redirection_pad_size;
    if (size > std.math.maxInt(u16)) return error.TooLong;
    try w.u16le(sec_redirection_pkt);
    try w.u16le(@intCast(size));
    try w.u32le(r.session_id);
    try w.u32le(flags);
    inline for (redirection_fields) |fd| {
        if (@field(r, fd.name)) |s| {
            try w.u32le(@intCast(s.len));
            try w.bytes(s);
        }
    }
    if (r.pad) try w.zeros(redirection_pad_size);
}

/// Flags MUST be SEC_REDIRECTION_PKT; Length must fit `buf`.
pub fn decodeRedirectionPacket(buf: []const u8) Error!Redirection {
    var r = bytes.Reader.init(buf);
    if (try r.u16le() != sec_redirection_pkt) return error.UnexpectedPdu;
    const length = try r.u16le();
    if (length < redirection_fixed_size) return error.BadLength;
    if (length > buf.len) return error.EndOfBuffer;
    r = bytes.Reader.init(buf[4..length]);
    var out: Redirection = .{ .session_id = try r.u32le(), .pad = false };
    out.flags = try r.u32le();
    inline for (redirection_fields) |fd| {
        if (out.flags & fd.flag != 0) {
            const n = try r.u32le();
            const s = try r.bytes(n);
            try checkField(fd.kind, out.flags, s);
            @field(out, fd.name) = s;
        }
    }
    // Pad (8 bytes) is optional: some Windows versions omit it.
    switch (r.remaining()) {
        0 => {},
        redirection_pad_size => out.pad = true,
        else => return error.BadLength,
    }
    return out;
}

/// TARGET_NET_ADDRESSES (2.2.13.1.1); each address is UTF-16LE with its null terminator.
pub fn encodeTargetNetAddresses(w: *bytes.Writer, addresses: []const []const u8) !void {
    if (addresses.len > std.math.maxInt(u32)) return error.TooLong;
    for (addresses) |a| {
        try checkUnicodeZ(a);
        if (a.len > std.math.maxInt(u32)) return error.TooLong;
    }
    try w.u32le(@intCast(addresses.len));
    for (addresses) |a| {
        try w.u32le(@intCast(a.len));
        try w.bytes(a);
    }
}

/// Fills `out` with slices into `raw`; returns the used part.
pub fn decodeTargetNetAddresses(raw: []const u8, out: [][]const u8) Error![][]const u8 {
    var r = bytes.Reader.init(raw);
    const count = try r.u32le();
    if (count > out.len) return error.TooLong;
    for (out[0..count]) |*a| {
        const n = try r.u32le();
        a.* = try r.bytes(n);
        try checkUnicodeZ(a.*);
    }
    // TargetNetAddressesLength is the size of this structure.
    if (r.remaining() != 0) return error.BadLength;
    return out[0..count];
}

/// CERTIFICATE_META_ELEMENT (2.2.13.1.2.1).
pub const CertificateElement = struct { element_type: u32, encoding: u32, data: []const u8 };

/// The DER certificate of a Base64-decoded TARGET_CERTIFICATE_CONTAINER (2.2.13.1.2).
pub fn findTargetCertificate(container: []const u8) Error!?[]const u8 {
    var r = bytes.Reader.init(container);
    while (r.remaining() != 0) {
        const e = CertificateElement{
            .element_type = try r.u32le(),
            .encoding = try r.u32le(),
            .data = try r.bytes(try r.u32le()),
        };
        if (e.element_type == element_type_certificate and e.encoding == encoding_type_asn1_der) return e.data;
    }
    return null;
}

/// TS_SHARECONTROLHEADER + pad2Octets in front of the packet (2.2.13.3.1).
const enhanced_redirection_header_size: usize = 8;

/// Enhanced Security Server Redirection PDU (2.2.13.3.1) as MCS userData, with the
/// trailing pad1Octet Windows sends (4.6).
pub fn encodeEnhancedSecurityRedirectionPdu(w: *bytes.Writer, pdu_source: u16, r: Redirection) !void {
    const start = w.len();
    errdefer w.list.shrinkRetainingCapacity(start);
    try w.u16le(0); // totalLength, patched
    try w.u16le(pdutype_server_redir_pkt);
    try w.u16le(pdu_source);
    try w.zeros(2); // pad2Octets
    try encodeRedirectionPacket(w, r);
    try w.byte(0); // pad1Octet
    const total = w.len() - start;
    if (total > std.math.maxInt(u16)) return error.TooLong;
    w.patchU16le(start, @intCast(total));
}

pub fn decodeEnhancedSecurityRedirectionPdu(user_data: []const u8) Error!Redirection {
    var r = bytes.Reader.init(user_data);
    const total = try r.u16le();
    if (total < enhanced_redirection_header_size) return error.BadLength;
    if (total > user_data.len) return error.EndOfBuffer;
    if (try r.u16le() & 0xF != pdutype_server_redir_pkt) return error.UnexpectedPdu;
    _ = try r.u16le(); // pduSource
    _ = try r.u16le(); // pad2Octets: ignored
    const packet = user_data[enhanced_redirection_header_size..total];
    const red = try decodeRedirectionPacket(packet);
    // What follows the packet is the optional pad1Octet.
    const packet_len = std.mem.readInt(u16, packet[2..4], .little);
    if (packet.len - packet_len > 1) return error.BadLength;
    return red;
}

// 2.2.16 Heartbeat

pub const sec_heartbeat: u16 = 0x4000;
/// earlyCapabilityFlags of the Client Core Data (2.2.1.3.2).
pub const rns_ud_cs_support_monitor_layout_pdu: u16 = 0x0040;
pub const rns_ud_cs_support_heartbeat_pdu: u16 = 0x0400;

/// Server Heartbeat PDU fields (2.2.16.1).
pub const Heartbeat = struct { period: u8, count1: u8, count2: u8 };

const heartbeat_pdu_size: usize = 8;

/// The MCS userData on the message channel.
pub fn encodeHeartbeatPdu(w: *bytes.Writer, h: Heartbeat) !void {
    try w.u16le(sec_heartbeat); // flags
    try w.u16le(0); // flagsHi
    try w.byte(0); // reserved
    try w.byte(h.period);
    try w.byte(h.count1);
    try w.byte(h.count2);
}

pub fn decodeHeartbeatPdu(user_data: []const u8) Error!Heartbeat {
    var r = bytes.Reader.init(user_data);
    const flags = try r.u16le();
    _ = try r.u16le(); // flagsHi: ignored (2.2.8.1.1.2.1)
    if (flags & sec_heartbeat == 0) return error.UnexpectedPdu;
    _ = try r.byte(); // reserved
    const h = Heartbeat{ .period = try r.byte(), .count1 = try r.byte(), .count2 = try r.byte() };
    if (r.remaining() != 0) return error.BadLength;
    return h;
}

/// Heartbeats go only to clients with RNS_UD_CS_SUPPORT_HEARTBEAT_PDU, on the message
/// channel, after `period` idle seconds (2.2.16.1).
pub const HeartbeatScheduler = struct {
    heartbeat: Heartbeat,
    enabled: bool,
    last_sent_ms: u64 = 0,

    pub fn init(client_early_capability_flags: u16, message_channel: bool, heartbeat: Heartbeat, now_ms: u64) Error!HeartbeatScheduler {
        return .{
            .heartbeat = heartbeat,
            // A zero period would mean a heartbeat on every check.
            .enabled = client_early_capability_flags & rns_ud_cs_support_heartbeat_pdu != 0 and
                message_channel and heartbeat.period != 0,
            .last_sent_ms = now_ms,
        };
    }

    /// Any PDU was sent to the client at `now_ms`.
    pub fn noteSent(s: *HeartbeatScheduler, now_ms: u64) Error!void {
        s.last_sent_ms = @max(s.last_sent_ms, now_ms);
    }

    pub fn due(s: *const HeartbeatScheduler, now_ms: u64) Error!bool {
        if (!s.enabled) return false;
        return now_ms -| s.last_sent_ms >= @as(u64, s.heartbeat.period) * std.time.ms_per_s;
    }
};

// 2.2.8.2 Keyboard status

pub const ts_sync_scroll_lock: u16 = 0x0001;
pub const ts_sync_num_lock: u16 = 0x0002;
pub const ts_sync_caps_lock: u16 = 0x0004;
pub const ts_sync_kana_lock: u16 = 0x0008;

pub const ime_state_closed: u32 = 0x00000000;
pub const ime_state_open: u32 = 0x00000001;

/// Body of TS_SET_KEYBOARD_INDICATORS_PDU: UnitId (zero) + LedFlags.
pub fn encodeSetKeyboardIndicatorsData(w: *bytes.Writer, led_flags: u16) !void {
    try w.u16le(0); // UnitId: MUST be zero
    try w.u16le(led_flags);
}

pub fn decodeSetKeyboardIndicatorsData(body: []const u8) Error!u16 {
    var r = bytes.Reader.init(body);
    _ = try r.u16le(); // UnitId: SHOULD be ignored by the client
    return r.u16le();
}

pub const ImeStatus = struct { ime_state: u32, ime_conv_mode: u32 };

/// Body of TS_SET_KEYBOARD_IME_STATUS_PDU: UnitId (zero) + ImeState + ImeConvMode.
pub fn encodeSetKeyboardImeStatusData(w: *bytes.Writer, s: ImeStatus) !void {
    try w.u16le(0); // UnitId: MUST be zero
    try w.u32le(s.ime_state);
    try w.u32le(s.ime_conv_mode);
}

pub fn decodeSetKeyboardImeStatusData(body: []const u8) Error!ImeStatus {
    var r = bytes.Reader.init(body);
    _ = try r.u16le(); // UnitId: SHOULD be ignored by the client
    return .{ .ime_state = try r.u32le(), .ime_conv_mode = try r.u32le() };
}

// 2.2.12.1 Monitor Layout

pub const ts_monitor_primary: u32 = 0x00000001;
pub const max_monitors: usize = 16;

const monitor_def_size: usize = 20;

/// TS_MONITOR_DEF (2.2.1.3.6.1): right and bottom are inclusive.
pub const MonitorDef = struct { left: i32, top: i32, right: i32, bottom: i32, flags: u32 };

pub fn monitorDef(x: i32, y: i32, width: u32, height: u32, primary: bool) Error!MonitorDef {
    if (width == 0 or height == 0) return error.InvalidField;
    const right = @as(i64, x) + width - 1;
    const bottom = @as(i64, y) + height - 1;
    return .{
        .left = x,
        .top = y,
        .right = std.math.cast(i32, right) orelse return error.InvalidField,
        .bottom = std.math.cast(i32, bottom) orelse return error.InvalidField,
        .flags = if (primary) ts_monitor_primary else 0,
    };
}

/// The whole Monitor Layout PDU (pduType2 55); error.NotSupported unless the client set
/// RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU (3.3.5.12.1).
pub fn encodeMonitorLayoutPdu(w: *bytes.Writer, client_early_capability_flags: u16, share_id: u32, monitors: []const MonitorDef) !void {
    if (client_early_capability_flags & rns_ud_cs_support_monitor_layout_pdu == 0) return error.NotSupported;
    if (monitors.len > max_monitors) return error.TooManyMonitors;
    var body: [4 + max_monitors * monitor_def_size]u8 = undefined;
    std.mem.writeInt(u32, body[0..4], @intCast(monitors.len), .little);
    for (monitors, 0..) |m, i| {
        const d = body[4 + i * monitor_def_size ..][0..monitor_def_size];
        std.mem.writeInt(i32, d[0..4], m.left, .little);
        std.mem.writeInt(i32, d[4..8], m.top, .little);
        std.mem.writeInt(i32, d[8..12], m.right, .little);
        std.mem.writeInt(i32, d[12..16], m.bottom, .little);
        std.mem.writeInt(u32, d[16..20], m.flags, .little);
    }
    // 2.2.12.1: pduSource MUST be zero.
    try encodeShareDataPdu(w, .{ .share_id = share_id, .pdu_source = 0, .pdu_type2 = pdutype2_monitor_layout_pdu }, body[0 .. 4 + monitors.len * monitor_def_size]);
}

/// monitorCount + monitorDefArray (the body); fills `out`.
pub fn decodeMonitorLayoutData(body: []const u8, out: []MonitorDef) Error![]MonitorDef {
    var r = bytes.Reader.init(body);
    const count = try r.u32le();
    if (count > max_monitors or count > out.len) return error.TooManyMonitors;
    for (out[0..count]) |*m| m.* = .{
        .left = @bitCast(try r.u32le()),
        .top = @bitCast(try r.u32le()),
        .right = @bitCast(try r.u32le()),
        .bottom = @bitCast(try r.u32le()),
        .flags = try r.u32le(),
    };
    return out[0..count];
}

// 2.2.9.1.1.5 Play Sound

pub const PlaySound = struct { duration: u32, frequency: u32 };

/// Body of TS_PLAY_SOUND_PDU_DATA: duration then frequency.
pub fn encodePlaySoundData(w: *bytes.Writer, p: PlaySound) !void {
    try w.u32le(p.duration);
    try w.u32le(p.frequency);
}

pub fn decodePlaySoundData(body: []const u8) Error!PlaySound {
    var r = bytes.Reader.init(body);
    return .{ .duration = try r.u32le(), .frequency = try r.u32le() };
}

// 2.2.14 Network Characteristics Detection (auto-detect), 1.3.9, 3.3.5.14

/// Network characteristics detection (2.2.14, 3.3.5.14).
pub const autodetect = @import("session_ext/autodetect.zig");

test "autodetect API compiles" {
    std.testing.refAllDecls(autodetect);
    std.testing.refAllDecls(autodetect.Detector);
}

test {
    std.testing.refAllDecls(@This());
}
