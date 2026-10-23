//! Network characteristics detection (MS-RDPBCGR 2.2.14): RTT and bandwidth messages in the
//! Auto-Detect PDUs (2.2.14.3, 2.2.14.4) or MS-RDPEMT 2.2.1.1.1 tunnel subheaders, and the
//! server's detector (3.3.1.13, 3.3.5.14).

const std = @import("std");
const bytes = @import("../../core/bytes.zig");
const multitransport = @import("../../net/multitransport.zig");

pub const AutodetectError = error{
    Unimplemented,
    EndOfBuffer,
    BadHeaderLength,
    BadHeaderType,
    UnknownType,
    /// payloadLength violates 2.2.14.1.3 / 2.2.14.1.4 or exceeds 16 bits.
    BadPayloadLength,
    TrailingData,
    MissingSecurityFlag,
    /// The other direction's flag, another message channel PDU's flag, or SEC_ENCRYPT.
    InvalidSecurityFlags,
    /// A NETCHAR_RESULTS field combination 2.2.14.1.5 does not define.
    InvalidField,
    /// The message is not allowed in this phase or on this transport (1.3.9).
    WrongContext,
    /// sequenceNumber not in the RTT Measure Request Data store (3.3.1.13).
    UnknownSequence,
    /// A response with no matching outstanding request.
    Unsolicited,
    /// Bandwidth Measure Payload or Stop without a prior Start.
    OutOfOrder,
    ZeroTimeDelta,
    /// Auto-detect was not negotiated (2.2.1.3.2, 2.2.1.4.5).
    NotNegotiated,
    /// Nothing measured yet, so no NETCHAR_RESULTS can be built.
    NoResults,
    OutOfMemory,
};

// --- Basic Security Header flags (2.2.8.1.1.2.1) -------------------------

pub const sec_encrypt: u16 = 0x0008;
pub const sec_reset_seqno: u16 = 0x0010;
pub const sec_ignore_seqno: u16 = 0x0020;
pub const sec_autodetect_req: u16 = 0x1000;
pub const sec_autodetect_rsp: u16 = 0x2000;
pub const sec_flagshi_valid: u16 = 0x8000;
/// TS_SECURITY_HEADER: flags + flagsHi.
pub const basic_security_header_size: usize = 4;

/// Flags of the other message channel PDUs (2.2.15, 2.2.16.1); never on an auto-detect PDU.
const sec_transport_req: u16 = 0x0002;
const sec_transport_rsp: u16 = 0x0004;
const sec_heartbeat: u16 = 0x4000;
const sec_forbidden: u16 = sec_encrypt | sec_transport_req | sec_transport_rsp | sec_heartbeat;

// --- Client Core Data (2.2.1.3.2) -----------------------------------------

pub const rns_ud_cs_valid_connection_type: u16 = 0x0020;
pub const rns_ud_cs_support_netchar_autodetect: u16 = 0x0080;

pub const connection_type_modem: u8 = 0x01;
pub const connection_type_broadband_low: u8 = 0x02;
pub const connection_type_satellite: u8 = 0x03;
pub const connection_type_broadband_high: u8 = 0x04;
pub const connection_type_wan: u8 = 0x05;
pub const connection_type_lan: u8 = 0x06;
pub const connection_type_autodetect: u8 = 0x07;

// --- 2.2.14 header -------------------------------------------------------

pub const type_id_autodetect_request: u8 = 0x00;
pub const type_id_autodetect_response: u8 = 0x01;

/// RDP_RTT_REQUEST requestType (2.2.14.1.1): continuous, connect-time.
pub const rtt_request_continuous: u16 = 0x0001;
pub const rtt_request_connect_time: u16 = 0x1001;
/// RDP_BW_START requestType (2.2.14.1.2): continuous or reliable UDP, lossy UDP, connect-time.
pub const bw_start_continuous: u16 = 0x0014;
pub const bw_start_lossy_udp: u16 = 0x0114;
pub const bw_start_connect_time: u16 = 0x1014;
/// RDP_BW_PAYLOAD requestType (2.2.14.1.3).
pub const bw_payload: u16 = 0x0002;
/// RDP_BW_STOP requestType (2.2.14.1.4): connect-time (with payload), continuous or reliable
/// UDP, lossy UDP.
pub const bw_stop_connect_time: u16 = 0x002B;
pub const bw_stop_continuous: u16 = 0x0429;
pub const bw_stop_lossy_udp: u16 = 0x0629;
/// RDP_NETCHAR_RESULTS requestType (2.2.14.1.5): which optional fields are present.
pub const netchar_result_base_rtt_avg_rtt: u16 = 0x0840;
pub const netchar_result_bw_avg_rtt: u16 = 0x0880;
pub const netchar_result_base_rtt_bw_avg_rtt: u16 = 0x08C0;

/// RDP_RTT_RESPONSE responseType (2.2.14.2.1).
pub const rtt_response: u16 = 0x0000;
/// RDP_BW_RESULTS responseType (2.2.14.2.2): connect-time, continuous.
pub const bw_results_connect_time: u16 = 0x0003;
pub const bw_results_continuous: u16 = 0x000B;
/// RDP_NETCHAR_SYNC responseType (2.2.14.2.3).
pub const netchar_sync: u16 = 0x0018;

pub const header_length_short: u8 = 0x06;
pub const header_length_payload: u8 = 0x08;
pub const header_length_results: u8 = 0x0E;
pub const header_length_netchar_all: u8 = 0x12;

/// payloadLength is a 16-bit field (2.2.14.1.3, 2.2.14.1.4).
const max_payload: usize = 0xFFFF;

// --- messages ------------------------------------------------------------

/// Connect-time (phase 6, 1.3.1.1) or continuous (after the connection sequence, 1.3.9).
pub const Phase = enum { connect_time, continuous };

/// Main RDP connection or a reliable / lossy UDP multitransport tunnel (MS-RDPEMT 1.3).
pub const Transport = enum { main, tunnel_reliable, tunnel_lossy };

/// RDP_RTT_REQUEST (2.2.14.1.1).
pub const RttRequest = struct { sequence_number: u16, request_type: u16 };
/// RDP_BW_START (2.2.14.1.2).
pub const BwStart = struct { sequence_number: u16, request_type: u16 };
/// RDP_BW_PAYLOAD (2.2.14.1.3): payloadLength = payload.len.
pub const BwPayload = struct { sequence_number: u16, payload: []const u8 };
/// RDP_BW_STOP (2.2.14.1.4): a payload only with requestType 0x002B, and then non-empty.
pub const BwStop = struct { sequence_number: u16, request_type: u16, payload: []const u8 = &.{} };
/// RDP_NETCHAR_RESULTS (2.2.14.1.5); requestType follows from the optional fields set.
/// RTTs in ms, bandwidth in kbps.
pub const NetcharResult = struct {
    sequence_number: u16,
    base_rtt: ?u32 = null,
    bandwidth: ?u32 = null,
    average_rtt: u32,
};

/// A server-to-client request message (2.2.14.1).
pub const Request = union(enum) {
    rtt: RttRequest,
    bw_start: BwStart,
    bw_payload: BwPayload,
    bw_stop: BwStop,
    netchar_result: NetcharResult,
};

/// RDP_RTT_RESPONSE (2.2.14.2.1).
pub const RttResponse = struct { sequence_number: u16 };
/// RDP_BW_RESULTS (2.2.14.2.2): timeDelta in ms, byteCount in bytes.
pub const BwResults = struct { sequence_number: u16, response_type: u16, time_delta: u32, byte_count: u32 };
/// RDP_NETCHAR_SYNC (2.2.14.2.3): bandwidth in kbps, rtt in ms.
pub const NetcharSync = struct { sequence_number: u16, bandwidth: u32, rtt: u32 };

/// A client-to-server response message (2.2.14.2).
pub const Response = union(enum) {
    rtt: RttResponse,
    bw_results: BwResults,
    netchar_sync: NetcharSync,
};

/// The message kind and headerLength a requestType stands for.
const RequestInfo = struct { kind: std.meta.Tag(Request), header_length: u8 };

fn requestInfo(request_type: u16) AutodetectError!RequestInfo {
    return switch (request_type) {
        rtt_request_continuous, rtt_request_connect_time => .{ .kind = .rtt, .header_length = header_length_short },
        bw_start_continuous, bw_start_lossy_udp, bw_start_connect_time => .{ .kind = .bw_start, .header_length = header_length_short },
        bw_payload => .{ .kind = .bw_payload, .header_length = header_length_payload },
        bw_stop_connect_time => .{ .kind = .bw_stop, .header_length = header_length_payload },
        bw_stop_continuous, bw_stop_lossy_udp => .{ .kind = .bw_stop, .header_length = header_length_short },
        netchar_result_base_rtt_avg_rtt, netchar_result_bw_avg_rtt => .{ .kind = .netchar_result, .header_length = header_length_results },
        netchar_result_base_rtt_bw_avg_rtt => .{ .kind = .netchar_result, .header_length = header_length_netchar_all },
        else => error.UnknownType,
    };
}

const ResponseInfo = struct { kind: std.meta.Tag(Response), header_length: u8 };

fn responseInfo(response_type: u16) AutodetectError!ResponseInfo {
    return switch (response_type) {
        rtt_response => .{ .kind = .rtt, .header_length = header_length_short },
        bw_results_connect_time, bw_results_continuous => .{ .kind = .bw_results, .header_length = header_length_results },
        netchar_sync => .{ .kind = .netchar_sync, .header_length = header_length_results },
        else => error.UnknownType,
    };
}

/// headerLength 2.2.14.1 requires for a requestType.
pub fn requestHeaderLength(request_type: u16) AutodetectError!u8 {
    return (try requestInfo(request_type)).header_length;
}

/// headerLength 2.2.14.2 requires for a responseType.
pub fn responseHeaderLength(response_type: u16) AutodetectError!u8 {
    return (try responseInfo(response_type)).header_length;
}

/// Tunnels carry only continuous detection (1.3.9, MS-RDPEMT 2.2.1.1.1).
pub fn requestAllowed(request_type: u16, phase: Phase, transport: Transport) AutodetectError!bool {
    _ = try requestInfo(request_type);
    return switch (transport) {
        .main => switch (phase) {
            .connect_time => switch (request_type) {
                rtt_request_connect_time, bw_start_connect_time, bw_payload, bw_stop_connect_time => true,
                netchar_result_base_rtt_avg_rtt, netchar_result_bw_avg_rtt, netchar_result_base_rtt_bw_avg_rtt => true,
                else => false,
            },
            .continuous => switch (request_type) {
                rtt_request_continuous, bw_start_continuous, bw_stop_continuous => true,
                else => false,
            },
        },
        // 1.3.9: sideband channels use their own transport's requestType.
        .tunnel_reliable, .tunnel_lossy => phase == .continuous and switch (request_type) {
            bw_start_continuous, bw_stop_continuous => transport == .tunnel_reliable,
            bw_start_lossy_udp, bw_stop_lossy_udp => transport == .tunnel_lossy,
            netchar_result_base_rtt_avg_rtt, netchar_result_bw_avg_rtt, netchar_result_base_rtt_bw_avg_rtt => true,
            else => false,
        },
    };
}

/// The same for a responseType (2.2.14.2.x).
pub fn responseAllowed(response_type: u16, phase: Phase, transport: Transport) AutodetectError!bool {
    _ = try responseInfo(response_type);
    return switch (transport) {
        .main => switch (phase) {
            .connect_time => response_type == rtt_response or response_type == bw_results_connect_time or response_type == netchar_sync,
            .continuous => response_type == rtt_response or response_type == bw_results_continuous,
        },
        .tunnel_reliable, .tunnel_lossy => phase == .continuous and response_type == bw_results_continuous,
    };
}

/// The requestType of a request whose fields follow 2.2.14.1.3 - 2.2.14.1.5.
fn validateRequest(r: Request) AutodetectError!u16 {
    switch (r) {
        .rtt => |x| return checkKind(x.request_type, .rtt),
        .bw_start => |x| return checkKind(x.request_type, .bw_start),
        .bw_payload => |x| {
            if (x.payload.len > max_payload) return error.BadPayloadLength;
            return bw_payload;
        },
        .bw_stop => |x| {
            const t = try checkKind(x.request_type, .bw_stop);
            if (t == bw_stop_connect_time) {
                if (x.payload.len == 0 or x.payload.len > max_payload) return error.BadPayloadLength;
            } else if (x.payload.len != 0) return error.BadPayloadLength;
            return t;
        },
        .netchar_result => |x| return netcharType(x),
    }
}

fn checkKind(request_type: u16, kind: std.meta.Tag(Request)) AutodetectError!u16 {
    const info = requestInfo(request_type) catch return error.UnknownType;
    if (info.kind != kind) return error.UnknownType;
    return request_type;
}

fn netcharType(x: NetcharResult) AutodetectError!u16 {
    if (x.base_rtt != null and x.bandwidth != null) return netchar_result_base_rtt_bw_avg_rtt;
    if (x.base_rtt != null) return netchar_result_base_rtt_avg_rtt;
    if (x.bandwidth != null) return netchar_result_bw_avg_rtt;
    return error.InvalidField;
}

fn validateResponse(r: Response) AutodetectError!u16 {
    return switch (r) {
        .rtt => rtt_response,
        .bw_results => |x| switch (x.response_type) {
            bw_results_connect_time, bw_results_continuous => x.response_type,
            else => error.UnknownType,
        },
        .netchar_sync => netchar_sync,
    };
}

fn writeHeader(w: *bytes.Writer, header_length: u8, type_id: u8, seq: u16, typ: u16) !void {
    try w.byte(header_length);
    try w.byte(type_id);
    try w.u16le(seq);
    try w.u16le(typ);
}

/// Writes an already validated request of type `t`.
fn writeRequest(w: *bytes.Writer, r: Request, t: u16) !void {
    const hl = requestHeaderLength(t) catch unreachable;
    switch (r) {
        .rtt => |x| try writeHeader(w, hl, type_id_autodetect_request, x.sequence_number, t),
        .bw_start => |x| try writeHeader(w, hl, type_id_autodetect_request, x.sequence_number, t),
        .bw_payload => |x| {
            try writeHeader(w, hl, type_id_autodetect_request, x.sequence_number, t);
            try w.u16le(@intCast(x.payload.len));
            try w.bytes(x.payload);
        },
        .bw_stop => |x| {
            try writeHeader(w, hl, type_id_autodetect_request, x.sequence_number, t);
            if (t == bw_stop_connect_time) {
                try w.u16le(@intCast(x.payload.len));
                try w.bytes(x.payload);
            }
        },
        .netchar_result => |x| {
            try writeHeader(w, hl, type_id_autodetect_request, x.sequence_number, t);
            if (x.base_rtt) |v| try w.u32le(v);
            if (x.bandwidth) |v| try w.u32le(v);
            try w.u32le(x.average_rtt);
        },
    }
}

fn writeResponse(w: *bytes.Writer, r: Response, t: u16) !void {
    const hl = responseHeaderLength(t) catch unreachable;
    switch (r) {
        .rtt => |x| try writeHeader(w, hl, type_id_autodetect_response, x.sequence_number, t),
        .bw_results => |x| {
            try writeHeader(w, hl, type_id_autodetect_response, x.sequence_number, t);
            try w.u32le(x.time_delta);
            try w.u32le(x.byte_count);
        },
        .netchar_sync => |x| {
            try writeHeader(w, hl, type_id_autodetect_response, x.sequence_number, t);
            try w.u32le(x.bandwidth);
            try w.u32le(x.rtt);
        },
    }
}

/// Writes one request message (no security header); rejects what the decoder rejects.
pub fn encodeRequest(w: *bytes.Writer, r: Request) !void {
    try writeRequest(w, r, try validateRequest(r));
}

fn parseRequest(header_length: u8, type_id: u8, rest: []const u8) AutodetectError!Request {
    if (rest.len < 4) return error.EndOfBuffer;
    if (type_id != type_id_autodetect_request) return error.BadHeaderType;
    var r = bytes.Reader.init(rest);
    const seq = try r.u16le();
    const t = try r.u16le();
    const info = try requestInfo(t);
    if (header_length != info.header_length) return error.BadHeaderLength;
    const req: Request = switch (info.kind) {
        .rtt => .{ .rtt = .{ .sequence_number = seq, .request_type = t } },
        .bw_start => .{ .bw_start = .{ .sequence_number = seq, .request_type = t } },
        .bw_payload => .{ .bw_payload = .{ .sequence_number = seq, .payload = try r.bytes(try r.u16le()) } },
        .bw_stop => if (t == bw_stop_connect_time) blk: {
            const len = try r.u16le();
            if (len == 0) return error.BadPayloadLength;
            break :blk .{ .bw_stop = .{ .sequence_number = seq, .request_type = t, .payload = try r.bytes(len) } };
        } else .{ .bw_stop = .{ .sequence_number = seq, .request_type = t } },
        .netchar_result => blk: {
            const base: ?u32 = if (t != netchar_result_bw_avg_rtt) try r.u32le() else null;
            const bw: ?u32 = if (t != netchar_result_base_rtt_avg_rtt) try r.u32le() else null;
            break :blk .{ .netchar_result = .{ .sequence_number = seq, .base_rtt = base, .bandwidth = bw, .average_rtt = try r.u32le() } };
        },
    };
    if (r.remaining() != 0) return error.TrailingData;
    return req;
}

fn parseResponse(header_length: u8, type_id: u8, rest: []const u8) AutodetectError!Response {
    if (rest.len < 4) return error.EndOfBuffer;
    if (type_id != type_id_autodetect_response) return error.BadHeaderType;
    var r = bytes.Reader.init(rest);
    const seq = try r.u16le();
    const t = try r.u16le();
    const info = try responseInfo(t);
    if (header_length != info.header_length) return error.BadHeaderLength;
    const rsp: Response = switch (info.kind) {
        .rtt => .{ .rtt = .{ .sequence_number = seq } },
        .bw_results => .{ .bw_results = .{ .sequence_number = seq, .response_type = t, .time_delta = try r.u32le(), .byte_count = try r.u32le() } },
        .netchar_sync => .{ .netchar_sync = .{ .sequence_number = seq, .bandwidth = try r.u32le(), .rtt = try r.u32le() } },
    };
    if (r.remaining() != 0) return error.TrailingData;
    return rsp;
}

/// Parses exactly one request message; payloads point into `msg`.
pub fn decodeRequest(msg: []const u8) AutodetectError!Request {
    if (msg.len < 6) return error.EndOfBuffer;
    return parseRequest(msg[0], msg[1], msg[2..]);
}

/// Writes one response message (no security header).
pub fn encodeResponse(w: *bytes.Writer, r: Response) !void {
    try writeResponse(w, r, try validateResponse(r));
}

/// Parses exactly one response message.
pub fn decodeResponse(msg: []const u8) AutodetectError!Response {
    if (msg.len < 6) return error.EndOfBuffer;
    return parseResponse(msg[0], msg[1], msg[2..]);
}

fn writeSecurityHeader(w: *bytes.Writer, flags: u16) !void {
    try w.u16le(flags);
    try w.u16le(0); // flagsHi
}

/// flagsHi, SEC_RESET_SEQNO, SEC_IGNORE_SEQNO and SEC_FLAGSHI_VALID are ignored (2.2.8.1.1.2.1).
fn checkSecurityHeader(user_data: []const u8, required: u16, opposite: u16) AutodetectError![]const u8 {
    if (user_data.len < basic_security_header_size) return error.EndOfBuffer;
    const flags = std.mem.readInt(u16, user_data[0..2], .little);
    if (flags & required == 0) return error.MissingSecurityFlag;
    if (flags & (opposite | sec_forbidden) != 0) return error.InvalidSecurityFlags;
    return user_data[basic_security_header_size..];
}

/// Server Auto-Detect Request PDU (2.2.14.3) as MCS userData.
pub fn encodeRequestPdu(w: *bytes.Writer, r: Request) !void {
    const t = try validateRequest(r);
    try writeSecurityHeader(w, sec_autodetect_req);
    try writeRequest(w, r, t);
}

/// Parses a Server Auto-Detect Request PDU's userData (the client's view).
pub fn decodeRequestPdu(user_data: []const u8) AutodetectError!Request {
    return decodeRequest(try checkSecurityHeader(user_data, sec_autodetect_req, sec_autodetect_rsp));
}

/// Client Auto-Detect Response PDU (2.2.14.4) as MCS userData.
pub fn encodeResponsePdu(w: *bytes.Writer, r: Response) !void {
    const t = try validateResponse(r);
    try writeSecurityHeader(w, sec_autodetect_rsp);
    try writeResponse(w, r, t);
}

/// Parses a Client Auto-Detect Response PDU's userData.
pub fn decodeResponsePdu(user_data: []const u8) AutodetectError!Response {
    return decodeResponse(try checkSecurityHeader(user_data, sec_autodetect_rsp, sec_autodetect_req));
}

// --- MS-RDPEMT tunnel subheaders -----------------------------------------

pub const TunnelMessage = union(enum) { request: Request, response: Response };

fn tunnelAllowed(m: TunnelMessage, t: u16, transport: Transport) AutodetectError!void {
    if (transport == .main) return error.WrongContext;
    const ok = switch (m) {
        .request => try requestAllowed(t, .continuous, transport),
        .response => try responseAllowed(t, .continuous, transport),
    };
    if (!ok) return error.WrongContext;
}

/// One RDP_TUNNEL_SUBHEADER (MS-RDPEMT 2.2.1.1.1); only messages 1.3.9 allows on `transport`.
pub fn encodeTunnelSubHeader(w: *bytes.Writer, m: TunnelMessage, transport: Transport) !void {
    switch (m) {
        .request => |r| {
            const t = try validateRequest(r);
            try tunnelAllowed(m, t, transport);
            try writeRequest(w, r, t);
        },
        .response => |r| {
            const t = try validateResponse(r);
            try tunnelAllowed(m, t, transport);
            try writeResponse(w, r, t);
        },
    }
}

fn tunnelMessage(m: TunnelMessage, transport: Transport) AutodetectError!TunnelMessage {
    const t = switch (m) {
        .request => |r| validateRequest(r) catch unreachable,
        .response => |r| validateResponse(r) catch unreachable,
    };
    try tunnelAllowed(m, t, transport);
    return m;
}

fn parseSubHeader(sub_length: u8, sub_type: u8, data: []const u8, transport: Transport) AutodetectError!TunnelMessage {
    const m: TunnelMessage = switch (sub_type) {
        type_id_autodetect_request => .{ .request = try parseRequest(sub_length, sub_type, data) },
        type_id_autodetect_response => .{ .response = try parseResponse(sub_length, sub_type, data) },
        else => return error.BadHeaderType,
    };
    return tunnelMessage(m, transport);
}

/// Parses one subheader; SubHeaderType selects request or response.
pub fn decodeTunnelSubHeader(raw: []const u8, transport: Transport) AutodetectError!TunnelMessage {
    if (raw.len < 2) return error.EndOfBuffer;
    switch (raw[1]) {
        type_id_autodetect_request, type_id_autodetect_response => {},
        else => return error.BadHeaderType,
    }
    return parseSubHeader(raw[0], raw[1], raw[2..], transport);
}

/// The same from a multitransport.SubHeader (SubHeaderLength = data.len + 2).
pub fn fromSubHeader(sh: multitransport.SubHeader, transport: Transport) AutodetectError!TunnelMessage {
    switch (sh.sub_type) {
        type_id_autodetect_request, type_id_autodetect_response => {},
        else => return error.BadHeaderType,
    }
    // SubHeaderLength is 8 bits (MS-RDPEMT 2.2.1.1.1).
    if (sh.data.len > 0xFF - 2) return error.BadHeaderLength;
    return parseSubHeader(@intCast(sh.data.len + 2), sh.sub_type, sh.data, transport);
}

// --- negotiation and sequencing ------------------------------------------

/// Needs RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT, RNS_UD_CS_VALID_CONNECTION_TYPE and
/// CONNECTION_TYPE_AUTODETECT (2.2.1.3.2), and a joined message channel (2.2.1.4.5).
pub fn negotiated(early_capability_flags: u16, connection_type: u8, message_channel_joined: bool) AutodetectError!bool {
    const want = rns_ud_cs_support_netchar_autodetect | rns_ud_cs_valid_connection_type;
    return early_capability_flags & want == want and
        connection_type == connection_type_autodetect and
        message_channel_joined;
}

/// Points of the server's connection sequence (1.3.1.1).
pub const SequencePoint = enum {
    /// Phases 1-5, up to the Client Info PDU.
    before_client_info,
    /// Client Info received, Demand Active not sent (phases 6-8).
    after_client_info,
    /// Demand Active sent (phases 9-10).
    capabilities_exchange,
    /// Font Map sent.
    active,
};

/// Which detection may run at `point` (1.3.1.1, 1.3.9).
pub fn phaseAt(point: SequencePoint) AutodetectError!?Phase {
    return switch (point) {
        .before_client_info, .capabilities_exchange => null,
        .after_client_info => .connect_time,
        .active => .continuous,
    };
}

/// (byteCount * 8) / timeDelta: kbps from bytes and ms (3.3.5.14 step 3).
pub fn bandwidthKbps(byte_count: u32, time_delta_ms: u32) AutodetectError!u64 {
    if (time_delta_ms == 0) return error.ZeroTimeDelta;
    return @as(u64, byte_count) * 8 / time_delta_ms;
}

// --- the server's detector -----------------------------------------------

/// What a response yielded (3.3.5.14 steps 2-4).
pub const Sample = union(enum) {
    /// RTT in ms.
    rtt: u32,
    /// Bandwidth in kbps.
    bandwidth: u64,
    /// Network Characteristics Sync values replace measuring.
    sync: struct { bandwidth: u32, rtt: u32 },
};

pub const Results = struct {
    /// Lowest RTT sample (ms).
    base_rtt: ?u32 = null,
    /// Average RTT (ms).
    average_rtt: ?u32 = null,
    /// Last bandwidth (kbps).
    bandwidth: ?u64 = null,
    rtt_samples: u32 = 0,
};

/// Server side of auto-detect (3.3.1.13, 3.3.5.14); calls fail with error.NotNegotiated unless
/// `negotiated` holds. averageRTT is a moving average giving a new sample 1/8 weight.
pub const Detector = struct {
    /// RTT Measure Request Data store size; when full, a new request evicts the oldest.
    pub const max_pending_rtt: usize = 16;
    pub const PendingRtt = struct { sequence_number: u16, sent_ms: u64 };
    /// Weight of a new RTT sample in the moving average: 1/avg_window.
    const avg_window: u64 = 8;
    /// averageRTT is kept in 1/256 ms so integer division keeps small changes.
    const avg_scale: u64 = 256;

    enabled: bool = false,
    phase: Phase = .connect_time,
    next_sequence: u16 = 0,
    /// The RTT Measure Request Data store, oldest first.
    pending: [max_pending_rtt]PendingRtt = undefined,
    pending_len: usize = 0,
    /// Bandwidth Measure Start sent (sequenceNumber), no Stop yet.
    bw_started: ?u16 = null,
    /// Bandwidth Measure Stop sent, results not received yet.
    bw_stopped: ?struct { sequence_number: u16, request_type: u16 } = null,
    results: Results = .{},
    /// averageRTT in 1/avg_scale ms; valid when results.average_rtt is.
    avg_rtt_scaled: u64 = 0,
    synced: bool = false,
    connect_time_done: bool = false,

    pub fn init(early_capability_flags: u16, connection_type: u8, message_channel_joined: bool) AutodetectError!Detector {
        return .{ .enabled = try negotiated(early_capability_flags, connection_type, message_channel_joined) };
    }

    pub fn isEnabled(d: *const Detector) AutodetectError!bool {
        return d.enabled;
    }

    /// Switches to continuous detection. A running connect-time measurement can no longer stop;
    /// an outstanding connect-time Stop still takes its results.
    pub fn activated(d: *Detector) AutodetectError!void {
        d.phase = .continuous;
        d.bw_started = null;
    }

    pub fn currentPhase(d: *const Detector) AutodetectError!Phase {
        return d.phase;
    }

    fn isPending(d: *const Detector, seq: u16) bool {
        for (d.pending[0..d.pending_len]) |p| if (p.sequence_number == seq) return true;
        return false;
    }

    /// Skips sequenceNumbers of outstanding RTT requests, the store's key.
    fn nextSequence(d: *Detector) u16 {
        while (true) {
            const seq = d.next_sequence;
            d.next_sequence +%= 1;
            if (!d.isPending(seq)) return seq;
        }
    }

    /// Saves (sequenceNumber, now_ms) in the RTT Measure Request Data store (3.3.5.14 step 1).
    pub fn rttRequest(d: *Detector, now_ms: u64) AutodetectError!Request {
        if (!d.enabled) return error.NotNegotiated;
        const seq = d.nextSequence();
        if (d.pending_len == max_pending_rtt) {
            std.mem.copyForwards(PendingRtt, d.pending[0 .. max_pending_rtt - 1], d.pending[1..max_pending_rtt]);
            d.pending_len -= 1;
        }
        d.pending[d.pending_len] = .{ .sequence_number = seq, .sent_ms = now_ms };
        d.pending_len += 1;
        return .{ .rtt = .{
            .sequence_number = seq,
            .request_type = if (d.phase == .connect_time) rtt_request_connect_time else rtt_request_continuous,
        } };
    }

    /// Restarts a running measurement.
    pub fn bwStart(d: *Detector) AutodetectError!Request {
        if (!d.enabled) return error.NotNegotiated;
        const seq = d.nextSequence();
        d.bw_started = seq;
        d.bw_stopped = null;
        return .{ .bw_start = .{
            .sequence_number = seq,
            .request_type = if (d.phase == .connect_time) bw_start_connect_time else bw_start_continuous,
        } };
    }

    /// A Bandwidth Measure Payload (connect-time only, after a Start).
    pub fn bwPayload(d: *Detector, payload: []const u8) AutodetectError!Request {
        if (!d.enabled) return error.NotNegotiated;
        if (d.phase != .connect_time) return error.WrongContext;
        if (d.bw_started == null) return error.OutOfOrder;
        if (payload.len > max_payload) return error.BadPayloadLength;
        return .{ .bw_payload = .{ .sequence_number = d.nextSequence(), .payload = payload } };
    }

    /// A connect-time Stop carries a non-empty payload, a continuous one none.
    pub fn bwStop(d: *Detector, payload: []const u8) AutodetectError!Request {
        if (!d.enabled) return error.NotNegotiated;
        if (d.bw_started == null) return error.OutOfOrder;
        const t = switch (d.phase) {
            .connect_time => blk: {
                if (payload.len == 0 or payload.len > max_payload) return error.BadPayloadLength;
                break :blk bw_stop_connect_time;
            },
            .continuous => blk: {
                if (payload.len != 0) return error.BadPayloadLength;
                break :blk bw_stop_continuous;
            },
        };
        const seq = d.nextSequence();
        d.bw_started = null;
        d.bw_stopped = .{ .sequence_number = seq, .request_type = t };
        return .{ .bw_stop = .{ .sequence_number = seq, .request_type = t, .payload = payload } };
    }

    /// The Network Characteristics Result ending connect-time detection; bandwidth clamps to 32 bits.
    pub fn netcharResult(d: *Detector) AutodetectError!Request {
        if (!d.enabled) return error.NotNegotiated;
        // 1.3.9: on the main connection it is a connect-time message.
        if (d.phase != .connect_time) return error.WrongContext;
        // Every requestType carries averageRTT (2.2.14.1.5).
        const avg = d.results.average_rtt orelse return error.NoResults;
        const bw: ?u32 = if (d.results.bandwidth) |b| @intCast(@min(b, std.math.maxInt(u32))) else null;
        if (d.results.base_rtt == null and bw == null) return error.NoResults;
        return .{ .netchar_result = .{
            .sequence_number = d.nextSequence(),
            .base_rtt = d.results.base_rtt,
            .bandwidth = bw,
            .average_rtt = avg,
        } };
    }

    fn addRttSample(d: *Detector, rtt: u32) void {
        const r = &d.results;
        r.rtt_samples +|= 1;
        r.base_rtt = if (r.base_rtt) |b| @min(b, rtt) else rtt;
        const sample = @as(u64, rtt) * avg_scale;
        if (r.average_rtt == null) {
            d.avg_rtt_scaled = sample;
        } else {
            const n = @min(@as(u64, r.rtt_samples), avg_window);
            const avg: i128 = d.avg_rtt_scaled;
            d.avg_rtt_scaled = @intCast(avg + @divTrunc(@as(i128, sample) - avg, n));
        }
        r.average_rtt = @intCast((d.avg_rtt_scaled + avg_scale / 2) / avg_scale);
    }

    fn onRtt(d: *Detector, seq: u16, now_ms: u64) AutodetectError!Sample {
        const i = for (d.pending[0..d.pending_len], 0..) |p, i| {
            if (p.sequence_number == seq) break i;
        } else return error.UnknownSequence;
        const sent = d.pending[i].sent_ms;
        std.mem.copyForwards(PendingRtt, d.pending[i .. d.pending_len - 1], d.pending[i + 1 .. d.pending_len]);
        d.pending_len -= 1;
        // A clock going backwards gives 0, an absurd delay saturates.
        const rtt: u32 = @intCast(@min(now_ms -| sent, std.math.maxInt(u32)));
        d.addRttSample(rtt);
        return .{ .rtt = rtt };
    }

    fn onBwResults(d: *Detector, x: BwResults) AutodetectError!Sample {
        const stop = d.bw_stopped orelse return error.Unsolicited;
        // sequenceNumber SHOULD echo the Stop's (2.2.14.2.2); not checked.
        const want: u16 = if (stop.request_type == bw_stop_connect_time) bw_results_connect_time else bw_results_continuous;
        if (x.response_type != want) return error.WrongContext;
        d.bw_stopped = null;
        if (want == bw_results_connect_time) d.connect_time_done = true;
        const kbps = try bandwidthKbps(x.byte_count, x.time_delta);
        d.results.bandwidth = kbps;
        return .{ .bandwidth = kbps };
    }

    fn onSync(d: *Detector, x: NetcharSync) AutodetectError!Sample {
        // The client's answer to a connect-time request instead of measuring (2.2.14.2.3).
        if (!(try responseAllowed(netchar_sync, d.phase, .main))) return error.WrongContext;
        if (d.pending_len == 0 and d.bw_started == null and d.bw_stopped == null) return error.Unsolicited;
        // 3.3.5.14 step 4: stop measuring, use these values.
        d.pending_len = 0;
        d.bw_started = null;
        d.bw_stopped = null;
        d.synced = true;
        d.connect_time_done = true;
        d.results.bandwidth = x.bandwidth;
        d.results.average_rtt = x.rtt;
        d.avg_rtt_scaled = @as(u64, x.rtt) * avg_scale;
        if (d.results.base_rtt) |b| d.results.base_rtt = @min(b, x.rtt);
        return .{ .sync = .{ .bandwidth = x.bandwidth, .rtt = x.rtt } };
    }

    /// A decoded Client Auto-Detect Response (3.3.5.14).
    pub fn onResponse(d: *Detector, r: Response, now_ms: u64) AutodetectError!Sample {
        if (!d.enabled) return error.NotNegotiated;
        return switch (r) {
            .rtt => |x| d.onRtt(x.sequence_number, now_ms),
            .bw_results => |x| d.onBwResults(x),
            .netchar_sync => |x| d.onSync(x),
        };
    }

    /// A Client Auto-Detect Response PDU's userData from the message channel.
    pub fn onResponsePdu(d: *Detector, user_data: []const u8, now_ms: u64) AutodetectError!Sample {
        if (!d.enabled) return error.NotNegotiated;
        return d.onResponse(try decodeResponsePdu(user_data), now_ms);
    }

    pub fn getResults(d: *const Detector) AutodetectError!Results {
        return d.results;
    }

    /// Connect-time bandwidth results or a Network Characteristics Sync arrived.
    pub fn connectTimeComplete(d: *const Detector) AutodetectError!bool {
        return d.connect_time_done;
    }

    /// RTT Measure Requests sent and not answered yet.
    pub fn pendingRtt(d: *const Detector) usize {
        return d.pending_len;
    }
};

test "a Detector's moving average follows a step change and stays between the samples" {
    var d = try Detector.init(rns_ud_cs_support_netchar_autodetect | rns_ud_cs_valid_connection_type, connection_type_autodetect, true);
    var t: u64 = 0;
    for (0..40) |i| {
        const rtt: u64 = if (i < 20) 10 else 100;
        const seq = (try d.rttRequest(t)).rtt.sequence_number;
        _ = try d.onResponse(.{ .rtt = .{ .sequence_number = seq } }, t + rtt);
        t += 1000;
        const r = try d.getResults();
        try std.testing.expect(r.average_rtt.? >= 10 and r.average_rtt.? <= 100);
    }
    const r = try d.getResults();
    try std.testing.expectEqual(@as(?u32, 10), r.base_rtt);
    // 20 samples at 1/8 weight after the step: within 10% of the new level.
    try std.testing.expect(r.average_rtt.? >= 90);
}
