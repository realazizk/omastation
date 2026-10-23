//! Multitransport (UDP side channels): MS-RDPBCGR 2.2.15 bootstrap PDUs, MS-RDPEMT tunnel PDUs,
//! MS-RDPEUDP datagrams and data transfer, MS-RDPEUDP2 and the TLS/DTLS layering.
//! MS-RDPBCGR and MS-RDPEMT are little-endian, MS-RDPEUDP big-endian, MS-RDPEUDP2 little-endian.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

pub const Error = error{
    EndOfBuffer,
    MissingSecurityFlag,
    /// A field violates a MUST.
    InvalidField,
    UnknownAction,
    /// RDP_TUNNEL_HEADER HeaderLength disagrees with the PDU or its subheaders.
    BadHeaderLength,
    BadPayloadLength,
    NotNegotiated,
    /// MS-RDPBCGR 3.3.5.15.1: one request per sideband type, each with its own requestId.
    AlreadyRequested,
    /// A requestId the server never issued or already consumed.
    UnknownRequest,
    /// MS-RDPEMT 3.2.5.1.
    CookieMismatch,
    /// S_OK although the server did not advertise SOFTSYNC_TCP_TO_UDP (MS-RDPBCGR 2.2.15.2).
    UnexpectedSuccess,
    /// MTU outside [1132, 1232] (MS-RDPEUDP 2.2.2.5).
    BadMtu,
    /// Flags or size do not match the datagram's headers.
    BadDatagram,
    OutOfMemory,
};

// MS-RDPBCGR 2.2.1.3.8 / 2.2.1.4.6 multitransport channel data flags

pub const transporttype_udpfecr: u32 = 0x00000001;
pub const transporttype_udpfecl: u32 = 0x00000004;
pub const transporttype_udp_preferred: u32 = 0x00000100;
pub const softsync_tcp_to_udp: u32 = 0x00000200;

// MS-RDPBCGR 2.2.15 Initiate Multitransport Request / Response

pub const sec_transport_req: u16 = 0x0002;
pub const sec_transport_rsp: u16 = 0x0004;

/// requestedProtocol (2.2.15.1).
pub const protocol_udpfecr: u16 = 0x0001;
pub const protocol_udpfecl: u16 = 0x0002;

pub const s_ok: u32 = 0x00000000;
pub const e_abort: u32 = 0x80004004;

/// Server Initiate Multitransport Request PDU (2.2.15.1).
pub const InitiateRequest = struct {
    request_id: u32,
    requested_protocol: u16,
    security_cookie: [16]u8,
};

fn validProtocol(p: u16) bool {
    return p == protocol_udpfecr or p == protocol_udpfecl;
}

/// 28 bytes of MCS userData on the message channel.
pub fn encodeInitiateRequest(w: *bytes.Writer, r: InitiateRequest) !void {
    if (!validProtocol(r.requested_protocol)) return error.InvalidField;
    try w.u16le(sec_transport_req);
    try w.u16le(0); // flagsHi
    try w.u32le(r.request_id);
    try w.u16le(r.requested_protocol);
    try w.u16le(0); // reserved: MUST be zero
    try w.bytes(&r.security_cookie);
}

pub fn decodeInitiateRequest(user_data: []const u8) Error!InitiateRequest {
    var r = bytes.Reader.init(user_data);
    // 2.2.8.1.1.2.1: flagsHi is ignored without SEC_FLAGSHI_VALID.
    const flags = try r.u16le();
    _ = try r.u16le();
    try r.need(24);
    if (flags & sec_transport_req == 0) return error.MissingSecurityFlag;
    const id = try r.u32le();
    const proto = try r.u16le();
    if (!validProtocol(proto)) return error.InvalidField;
    // reserved: not checked (newer Windows servers send 1 and append data).
    _ = try r.u16le();
    var out = InitiateRequest{ .request_id = id, .requested_protocol = proto, .security_cookie = undefined };
    @memcpy(&out.security_cookie, try r.bytes(16));
    return out;
}

/// Client Initiate Multitransport Response PDU (2.2.15.2).
pub const InitiateResponse = struct { request_id: u32, hr_response: u32 };

pub fn encodeInitiateResponse(w: *bytes.Writer, r: InitiateResponse) !void {
    try w.u16le(sec_transport_rsp);
    try w.u16le(0);
    try w.u32le(r.request_id);
    try w.u32le(r.hr_response);
}

pub fn decodeInitiateResponse(user_data: []const u8) Error!InitiateResponse {
    var r = bytes.Reader.init(user_data);
    const flags = try r.u16le();
    _ = try r.u16le();
    try r.need(8);
    if (flags & sec_transport_rsp == 0) return error.MissingSecurityFlag;
    return .{ .request_id = try r.u32le(), .hr_response = try r.u32le() };
}

pub const ResponseOutcome = enum {
    /// E_ABORT: the client could not build the side channel; stay on TCP.
    aborted,
    /// S_OK (soft-sync servers only).
    succeeded,
};

/// Server side of multitransport bootstrapping: the Connection Store of MS-RDPEMT 3.2.1
/// (requestId + securityCookie per request) and the checks of MS-RDPEMT 3.2.5.1.
pub const Bootstrap = struct {
    client_flags: u32,
    server_flags: u32,
    /// MS-RDPBCGR 3.3.1.14, one slot per sideband type (UDPFECR, UDPFECL).
    store: [2]Slot = .{ .{}, .{} },

    const SlotState = enum {
        unused,
        /// Requested; waiting for the Tunnel Create Request.
        pending,
        /// The Tunnel Create Request matched: the request is consumed.
        tunnel_created,
        aborted,
    };

    const Slot = struct {
        state: SlotState = .unused,
        request_id: u32 = 0,
        cookie: [16]u8 = @splat(0),
    };

    pub fn init(client_flags: u32, server_flags: u32) Error!Bootstrap {
        return .{ .client_flags = client_flags, .server_flags = server_flags };
    }

    fn transportFlag(protocol: u16) u32 {
        return if (protocol == protocol_udpfecr) transporttype_udpfecr else transporttype_udpfecl;
    }

    fn negotiated(b: *const Bootstrap, protocol: u16) bool {
        const f = transportFlag(protocol);
        return b.client_flags & f != 0 and b.server_flags & f != 0;
    }

    /// Protocols both sides advertise, UDPFECR first. Fills `out`.
    pub fn protocols(b: *const Bootstrap, out: []u16) Error![]u16 {
        var n: usize = 0;
        for ([_]u16{ protocol_udpfecr, protocol_udpfecl }) |p| {
            if (!b.negotiated(p)) continue;
            if (n == out.len) return error.EndOfBuffer;
            out[n] = p;
            n += 1;
        }
        return out[0..n];
    }

    /// Records a request in the Connection Store (MS-RDPBCGR 3.3.5.15.1).
    pub fn request(b: *Bootstrap, protocol: u16, request_id: u32, security_cookie: [16]u8) Error!InitiateRequest {
        if (!validProtocol(protocol)) return error.InvalidField;
        if (!b.negotiated(protocol)) return error.NotNegotiated;
        const slot = &b.store[protocol - 1];
        if (slot.state != .unused) return error.AlreadyRequested;
        for (b.store) |s| if (s.state != .unused and s.request_id == request_id) return error.AlreadyRequested;
        slot.* = .{ .state = .pending, .request_id = request_id, .cookie = security_cookie };
        return .{ .request_id = request_id, .requested_protocol = protocol, .security_cookie = security_cookie };
    }

    fn find(b: *Bootstrap, request_id: u32) ?*Slot {
        for (&b.store) |*s| {
            if ((s.state == .pending or s.state == .tunnel_created) and s.request_id == request_id) return s;
        }
        return null;
    }

    /// MS-RDPBCGR 3.3.5.15.2: a failure HRESULT forgets the request.
    pub fn onResponse(b: *Bootstrap, r: InitiateResponse) Error!ResponseOutcome {
        const slot = b.find(r.request_id) orelse return error.UnknownRequest;
        if (r.hr_response == s_ok) {
            if (b.server_flags & softsync_tcp_to_udp == 0) return error.UnexpectedSuccess;
            return .succeeded;
        }
        slot.state = .aborted;
        return .aborted;
    }

    /// requestedProtocol of the request `request_id` awaiting its Tunnel Create Request.
    pub fn pendingProtocol(b: *const Bootstrap, request_id: u32) ?u16 {
        for (b.store, 0..) |s, i| {
            if (s.state == .pending and s.request_id == request_id) return @intCast(i + 1);
        }
        return null;
    }

    /// Cookie of a pending request whose SHA-256 is `hash` (cookieHash, MS-RDPEUDP 2.2.2.9).
    pub fn cookieForHash(b: *const Bootstrap, hash: [32]u8) ?[16]u8 {
        for (b.store) |s| {
            if (s.state != .pending) continue;
            const h = cookieHash(s.cookie) catch unreachable;
            if (std.crypto.timing_safe.eql([32]u8, h, hash)) return s.cookie;
        }
        return null;
    }

    /// MS-RDPEMT 3.2.5.1: RequestID and SecurityCookie must match a pending request, which is
    /// consumed. Returns the HrResponse to send.
    pub fn onTunnelCreate(b: *Bootstrap, r: TunnelCreateRequest) Error!u32 {
        const slot = b.find(r.request_id) orelse return error.UnknownRequest;
        if (slot.state != .pending) return error.UnknownRequest;
        var diff: u8 = 0;
        for (slot.cookie, r.security_cookie) |x, y| diff |= x ^ y;
        if (diff != 0) return error.CookieMismatch;
        slot.state = .tunnel_created;
        return s_ok;
    }
};

// MS-RDPEMT tunnel PDUs

pub const action_create_request: u4 = 0x0;
pub const action_create_response: u4 = 0x1;
pub const action_data: u4 = 0x2;

pub const subheader_type_autodetect_request: u8 = 0x00;
pub const subheader_type_autodetect_response: u8 = 0x01;

pub const tunnel_header_size: usize = 4;

/// RDP_TUNNEL_CREATEREQUEST payload: RequestID, Reserved, SecurityCookie.
const create_request_payload: u16 = 24;
const create_response_payload: u16 = 4;

/// RDP_TUNNEL_HEADER (2.2.1.1): Action in the low nibble, Flags in the high nibble.
pub const TunnelHeader = struct {
    action: u4,
    flags: u4 = 0,
    /// Bytes after the header and subheaders.
    payload_length: u16,
    header_length: u8,
    subheaders: []const u8 = &.{},
};

pub fn encodeTunnelHeader(w: *bytes.Writer, h: TunnelHeader) !void {
    if (h.header_length != tunnel_header_size + h.subheaders.len) return error.BadHeaderLength;
    try w.byte(@as(u8, h.action) | @as(u8, h.flags) << 4);
    try w.u16le(h.payload_length);
    try w.byte(h.header_length);
    try w.bytes(h.subheaders);
}

/// 2.2.1.1 / 3.1.5.3: Flags zero, HeaderLength >= 4 and exactly 4 for create request/response.
pub fn decodeTunnelHeader(pdu: []const u8) Error!TunnelHeader {
    var r = bytes.Reader.init(pdu);
    const b0 = try r.byte();
    const payload_length = try r.u16le();
    const header_length = try r.byte();
    const action: u4 = @truncate(b0);
    const flags: u4 = @truncate(b0 >> 4);
    if (flags != 0) return error.InvalidField;
    if (action > action_data) return error.UnknownAction;
    if (header_length < tunnel_header_size) return error.BadHeaderLength;
    if (action != action_data and header_length != tunnel_header_size) return error.BadHeaderLength;
    const subheaders = try r.bytes(header_length - tunnel_header_size);
    return .{ .action = action, .flags = flags, .payload_length = payload_length, .header_length = header_length, .subheaders = subheaders };
}

/// RDP_TUNNEL_SUBHEADER (2.2.1.1.1).
pub const SubHeader = struct { sub_type: u8, data: []const u8 };

pub const SubHeaderIterator = struct {
    raw: []const u8,
    pos: usize = 0,

    /// SubHeaderLength < 2 or overrunning the field is error.BadHeaderLength.
    pub fn next(it: *SubHeaderIterator) Error!?SubHeader {
        if (it.pos >= it.raw.len) return null;
        const rest = it.raw[it.pos..];
        if (rest.len < 2) return error.BadHeaderLength;
        const len = rest[0];
        if (len < 2 or len > rest.len) return error.BadHeaderLength;
        it.pos += len;
        return .{ .sub_type = rest[1], .data = rest[2..len] };
    }
};

/// RDP_TUNNEL_CREATEREQUEST (2.2.2.1).
pub const TunnelCreateRequest = struct { request_id: u32, security_cookie: [16]u8 };

pub fn encodeTunnelCreateRequest(w: *bytes.Writer, r: TunnelCreateRequest) !void {
    try encodeTunnelHeader(w, .{ .action = action_create_request, .payload_length = create_request_payload, .header_length = tunnel_header_size });
    try w.u32le(r.request_id);
    try w.u32le(0); // Reserved
    try w.bytes(&r.security_cookie);
}

/// RDP_TUNNEL_CREATERESPONSE (2.2.2.2).
pub const TunnelCreateResponse = struct { hr_response: u32 };

pub fn encodeTunnelCreateResponse(w: *bytes.Writer, r: TunnelCreateResponse) !void {
    try encodeTunnelHeader(w, .{ .action = action_create_response, .payload_length = create_response_payload, .header_length = tunnel_header_size });
    try w.u32le(r.hr_response);
}

/// RDP_TUNNEL_DATA (2.2.2.3): subheaders then the higher-layer data.
pub fn encodeTunnelData(w: *bytes.Writer, subheaders: []const SubHeader, payload: []const u8) !void {
    var header_length: usize = tunnel_header_size;
    for (subheaders) |s| {
        if (s.data.len + 2 > 0xff) return error.BadHeaderLength;
        header_length += 2 + s.data.len;
    }
    if (header_length > 0xff) return error.BadHeaderLength;
    if (payload.len > 0xffff) return error.BadPayloadLength;
    try w.byte(action_data);
    try w.u16le(@intCast(payload.len));
    try w.byte(@intCast(header_length));
    for (subheaders) |s| {
        try w.byte(@intCast(s.data.len + 2));
        try w.byte(s.sub_type);
        try w.bytes(s.data);
    }
    try w.bytes(payload);
}

pub const TunnelPdu = union(enum) {
    create_request: TunnelCreateRequest,
    create_response: TunnelCreateResponse,
    data: struct { subheaders: []const u8, payload: []const u8 },
};

/// `size` is HeaderLength + PayloadLength (message mode, 3.1.5.2).
pub const DecodedTunnelPdu = struct { pdu: TunnelPdu, size: usize };

pub fn decodeTunnelPdu(stream: []const u8) Error!DecodedTunnelPdu {
    const h = try decodeTunnelHeader(stream);
    switch (h.action) {
        action_create_request => if (h.payload_length != create_request_payload) return error.BadPayloadLength,
        action_create_response => if (h.payload_length != create_response_payload) return error.BadPayloadLength,
        else => {},
    }
    const size = @as(usize, h.header_length) + h.payload_length;
    if (stream.len < size) return error.EndOfBuffer;
    var r = bytes.Reader.init(stream[h.header_length..size]);
    switch (h.action) {
        action_create_request => {
            const id = try r.u32le();
            if (try r.u32le() != 0) return error.InvalidField; // Reserved
            var req = TunnelCreateRequest{ .request_id = id, .security_cookie = undefined };
            @memcpy(&req.security_cookie, try r.bytes(16));
            return .{ .pdu = .{ .create_request = req }, .size = size };
        },
        action_create_response => return .{ .pdu = .{ .create_response = .{ .hr_response = try r.u32le() } }, .size = size },
        else => {
            // 3.1.5.3: the subheaders add up to HeaderLength exactly.
            var it = SubHeaderIterator{ .raw = h.subheaders };
            while (try it.next()) |_| {}
            return .{ .pdu = .{ .data = .{ .subheaders = h.subheaders, .payload = r.rest() } }, .size = size };
        },
    }
}

// MS-RDPEUDP datagrams

pub const rdpudp_flag_syn: u16 = 0x0001;
pub const rdpudp_flag_fin: u16 = 0x0002;
pub const rdpudp_flag_ack: u16 = 0x0004;
pub const rdpudp_flag_data: u16 = 0x0008;
pub const rdpudp_flag_fec: u16 = 0x0010;
pub const rdpudp_flag_cn: u16 = 0x0020;
pub const rdpudp_flag_cwr: u16 = 0x0040;
pub const rdpudp_flag_sack_option: u16 = 0x0080;
pub const rdpudp_flag_ack_of_acks: u16 = 0x0100;
pub const rdpudp_flag_synlossy: u16 = 0x0200;
pub const rdpudp_flag_ackdelayed: u16 = 0x0400;
pub const rdpudp_flag_correlation_id: u16 = 0x0800;
pub const rdpudp_flag_synex: u16 = 0x1000;

pub const min_mtu: u16 = 1132;
pub const max_mtu: u16 = 1232;

pub const rdpudp_version_info_valid: u16 = 0x0001;
pub const rdpudp_protocol_version_1: u16 = 0x0001;
pub const rdpudp_protocol_version_2: u16 = 0x0002;
pub const rdpudp_protocol_version_3: u16 = 0x0101;

/// RDPUDP_FEC_HEADER (2.2.2.1).
pub const FecHeader = struct { sn_source_ack: u32, receive_window_size: u16, flags: u16 };

/// RDPUDP_SYNDATA_PAYLOAD (2.2.2.5).
pub const SynData = struct { initial_sequence_number: u32, up_stream_mtu: u16, down_stream_mtu: u16 };

/// RDPUDP_SYNDATAEX_PAYLOAD (2.2.2.9). `cookie_hash` iff version 3.
pub const SynDataEx = struct { flags: u16, version: u16, cookie_hash: ?[32]u8 = null };

/// A SYN (3.1.5.1.1) or SYN+ACK (3.1.5.1.3) datagram.
pub const Syn = struct {
    /// 0xFFFFFFFF in a SYN; the peer's snInitialSequenceNumber in a SYN+ACK.
    sn_source_ack: u32 = 0xFFFFFFFF,
    receive_window_size: u16,
    ack: bool = false,
    lossy: bool = false,
    syn_data: SynData,
    /// uCorrelationId (big-endian bytes).
    correlation_id: ?[16]u8 = null,
    synex: ?SynDataEx = null,
};

/// RDPUDP_FEC_HEADER (8) + RDPUDP_SYNDATA_PAYLOAD (8).
const syn_fixed_size = 16;

fn definedVersion(v: u16) bool {
    return v == rdpudp_protocol_version_1 or v == rdpudp_protocol_version_2 or v == rdpudp_protocol_version_3;
}

fn mtuValid(m: u16) bool {
    return m >= min_mtu and m <= max_mtu;
}

/// 2.2.2.9 / 3.1.5.1.1 step 5: cookieHash only in a client's version 3 SYN.
fn cookieHashExpected(ack: bool, version: u16) bool {
    return !ack and version == rdpudp_protocol_version_3;
}

/// Zero-padded to min(uUpStreamMtu, uDownStreamMtu) (3.1.5.1.1 step 6).
pub fn encodeSyn(w: *bytes.Writer, s: Syn) !void {
    var buf: [max_mtu]u8 = undefined;
    try w.bytes(try encodeSynInto(s, &buf));
}

pub fn encodeSynInto(s: Syn, out: []u8) Error![]u8 {
    const sd = s.syn_data;
    if (!mtuValid(sd.up_stream_mtu) or !mtuValid(sd.down_stream_mtu)) return error.BadMtu;
    if (s.synex) |x| {
        // 2.2.2.9: a valid uUdpVer is one of the defined versions.
        if (x.flags & rdpudp_version_info_valid != 0 and !definedVersion(x.version)) return error.InvalidField;
        if ((x.cookie_hash != null) != cookieHashExpected(s.ack, x.version)) return error.InvalidField;
    }
    const total: usize = @min(sd.up_stream_mtu, sd.down_stream_mtu);
    if (out.len < total) return error.EndOfBuffer;
    var flags: u16 = rdpudp_flag_syn;
    if (s.ack) flags |= rdpudp_flag_ack;
    if (s.lossy) flags |= rdpudp_flag_synlossy;
    if (s.correlation_id != null) flags |= rdpudp_flag_correlation_id;
    if (s.synex != null) flags |= rdpudp_flag_synex;
    @memset(out[0..total], 0);
    var c = Cursor{ .buf = out };
    c.be32(s.sn_source_ack);
    c.be16(s.receive_window_size);
    c.be16(flags);
    c.be32(sd.initial_sequence_number);
    c.be16(sd.up_stream_mtu);
    c.be16(sd.down_stream_mtu);
    if (s.correlation_id) |id| {
        c.slice(&id);
        c.n += 16; // uReserved, zero
    }
    if (s.synex) |x| {
        c.be16(x.flags);
        c.be16(x.version);
        if (x.cookie_hash) |h| c.slice(&h);
    }
    return out[0..total];
}

pub fn decodeSyn(datagram: []const u8) Error!Syn {
    var r = bytes.Reader.init(datagram);
    try r.need(syn_fixed_size);
    const ack = try r.u32be();
    const window = try r.u16be();
    const flags = try r.u16be();
    if (flags & rdpudp_flag_syn == 0) return error.BadDatagram;
    var s = Syn{
        .sn_source_ack = ack,
        .receive_window_size = window,
        .ack = flags & rdpudp_flag_ack != 0,
        .lossy = flags & rdpudp_flag_synlossy != 0,
        .syn_data = .{ .initial_sequence_number = try r.u32be(), .up_stream_mtu = try r.u16be(), .down_stream_mtu = try r.u16be() },
    };
    if (!mtuValid(s.syn_data.up_stream_mtu) or !mtuValid(s.syn_data.down_stream_mtu)) return error.BadMtu;
    if (flags & rdpudp_flag_correlation_id != 0) {
        var id: [16]u8 = undefined;
        @memcpy(&id, try r.bytes(16));
        try r.skip(16); // uReserved
        s.correlation_id = id;
    }
    if (flags & rdpudp_flag_synex != 0) {
        var x = SynDataEx{ .flags = try r.u16be(), .version = try r.u16be() };
        if (cookieHashExpected(s.ack, x.version)) {
            var h: [32]u8 = undefined;
            @memcpy(&h, try r.bytes(32));
            x.cookie_hash = h;
        }
        s.synex = x;
    }
    return s;
}

/// SHA-256 of the Initiate Multitransport Request's securityCookie (2.2.2.9).
pub fn cookieHash(security_cookie: [16]u8) Error![32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&security_cookie, &out, .{});
    return out;
}

pub const ServerUdpConfig = struct {
    receive_window_size: u16 = 1024,
    initial_sequence_number: u32,
    up_stream_mtu: u16 = max_mtu,
    down_stream_mtu: u16 = max_mtu,
    max_version: u16 = rdpudp_protocol_version_2,
};

/// 1 without SYNDATAEX or RDPUDP_VERSION_INFO_VALID (3.1.5.1.1 step 4, 2.2.2.9).
fn announcedVersion(x: ?SynDataEx) u16 {
    const v = x orelse return rdpudp_protocol_version_1;
    if (v.flags & rdpudp_version_info_valid == 0) return rdpudp_protocol_version_1;
    return v.version;
}

/// The SYN+ACK for a client SYN (3.1.5.1.3): the highest common version, 3 only with a
/// valid cookieHash of `security_cookie`.
pub fn answerSyn(syn: Syn, server: ServerUdpConfig, security_cookie: [16]u8) Error!Syn {
    const sd = syn.syn_data;
    if (!mtuValid(sd.up_stream_mtu) or !mtuValid(sd.down_stream_mtu)) return error.BadMtu;
    // 3.1.1.3: the client's upstream MTU bounds what the server receives, and vice versa.
    const up = @min(sd.up_stream_mtu, server.down_stream_mtu, max_mtu);
    const down = @min(sd.down_stream_mtu, server.up_stream_mtu, max_mtu);
    if (!mtuValid(up) or !mtuValid(down)) return error.BadMtu;
    var a = Syn{
        .sn_source_ack = sd.initial_sequence_number,
        .receive_window_size = server.receive_window_size,
        .ack = true,
        .syn_data = .{ .initial_sequence_number = server.initial_sequence_number, .up_stream_mtu = up, .down_stream_mtu = down },
    };
    if (syn.synex) |x| {
        var v = @min(announcedVersion(x), server.max_version);
        if (v == rdpudp_protocol_version_3) {
            // 3.1.5.1.1 step 5: a wrong or missing hash falls back to 2; RDP-UDP2 is reliable only.
            const want = try cookieHash(security_cookie);
            const good = if (x.cookie_hash) |h| std.crypto.timing_safe.eql([32]u8, h, want) else false;
            if (!good or syn.lossy) v = rdpudp_protocol_version_2;
        } else if (v > rdpudp_protocol_version_2) {
            v = rdpudp_protocol_version_2;
        }
        a.synex = .{ .flags = rdpudp_version_info_valid, .version = v };
    }
    return a;
}

/// VECTOR_ELEMENT_STATE (2.2.1.1).
pub const ElementState = enum(u2) {
    received = 0,
    reserved_1 = 1,
    reserved_2 = 2,
    not_yet_received = 3,
};

pub const max_ack_run: usize = 64;

/// ACK Vector Element (2.2.2.7.1). Windows codes a run of `count` datagrams as count - 1
/// (0x3f is sixty-four), not the spec's plain count; the wire format follows Windows.
pub const AckElement = struct {
    state: ElementState,
    /// 1 to max_ack_run.
    count: u7,

    pub fn length(e: AckElement) usize {
        return e.count;
    }
};

/// error.InvalidField for a run of 0 or more than max_ack_run datagrams.
pub fn packAckElement(e: AckElement) Error!u8 {
    if (e.count == 0 or e.count > max_ack_run) return error.InvalidField;
    return @as(u8, @backingInt(e.state)) << 6 | @as(u8, e.count - 1);
}

pub fn unpackAckElement(b: u8) Error!AckElement {
    return .{ .state = @fromBackingInt(@intCast(@as(u2, @truncate(b >> 6)))), .count = @as(u7, @as(u6, @truncate(b))) + 1 };
}

/// Run-length codes per-datagram states (oldest first) into ACK vector elements.
pub fn encodeAckVector(states: []const ElementState, out: []u8) Error![]u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < states.len) {
        var j = i + 1;
        while (j < states.len and states[j] == states[i] and j - i < max_ack_run) j += 1;
        if (n == out.len) return error.EndOfBuffer;
        out[n] = try packAckElement(.{ .state = states[i], .count = @intCast(j - i) });
        n += 1;
        i = j;
    }
    return out[0..n];
}

/// RDPUDP_PAYLOAD header sizes.
pub const fec_header_size: usize = 8;
pub const source_header_size: usize = 8;
pub const fec_payload_header_size: usize = 12;
pub const ack_of_acks_size: usize = 4;

/// RDPUDP_FEC_PAYLOAD_HEADER (2.2.2.2).
pub const FecPayloadHeader = struct { sn_coded: u32, sn_source_start: u32, range: u8, fec_index: u8 };

/// RDPUDP_SOURCE_PAYLOAD_HEADER (2.2.2.4).
pub const SourcePayloadHeader = struct { sn_coded: u32, sn_source_start: u32 };

/// A non-SYN datagram (2.2.2.1): FEC header, the structures its flags announce, then the
/// payload. `header.flags` is written as given.
pub const Datagram = struct {
    header: FecHeader,
    /// AckVector elements, padded to a DWORD on the wire.
    ack_vector: ?[]const u8 = null,
    ack_of_acks: ?u32 = null,
    source: ?SourcePayloadHeader = null,
    fec: ?FecPayloadHeader = null,
    payload: []const u8 = &.{},
};

/// 2.2.2.7: the padding after uAckVectorSize + AckVector to a DWORD.
pub fn ackVectorPadding(n: usize) usize {
    return (4 - (2 + n) % 4) % 4;
}

pub fn ackVectorHeaderSize(n: usize) usize {
    return 2 + n + ackVectorPadding(n);
}

pub fn datagramSize(d: Datagram) usize {
    var n: usize = fec_header_size;
    if (d.ack_vector) |v| n += ackVectorHeaderSize(v.len);
    if (d.ack_of_acks != null) n += ack_of_acks_size;
    if (d.source != null) n += source_header_size;
    if (d.fec != null) n += fec_payload_header_size;
    return n + d.payload.len;
}

/// The flags must announce exactly the structures present (2.2.2.1).
fn checkDatagram(d: Datagram) Error!void {
    const f = d.header.flags;
    if (f & rdpudp_flag_syn != 0) return error.InvalidField;
    if ((f & rdpudp_flag_ack != 0) != (d.ack_vector != null)) return error.InvalidField;
    if ((f & rdpudp_flag_ack_of_acks != 0) != (d.ack_of_acks != null)) return error.InvalidField;
    if (d.ack_vector) |v| if (v.len > max_ack_vector_size) return error.InvalidField;
    const data = f & rdpudp_flag_data != 0;
    const fec_flag = f & rdpudp_flag_fec != 0;
    if (d.source != null and d.fec != null) return error.InvalidField;
    if (d.source != null and (!data or fec_flag)) return error.InvalidField;
    if (d.fec != null and (!data or !fec_flag)) return error.InvalidField;
    if (data and d.source == null and d.fec == null) return error.InvalidField;
    if (!data and (fec_flag or d.payload.len != 0)) return error.InvalidField;
}

pub fn encodeDatagram(w: *bytes.Writer, d: Datagram) !void {
    try checkDatagram(d);
    try w.u32be(d.header.sn_source_ack);
    try w.u16be(d.header.receive_window_size);
    try w.u16be(d.header.flags);
    if (d.ack_vector) |v| {
        try w.u16be(@intCast(v.len));
        try w.bytes(v);
        try w.zeros(ackVectorPadding(v.len));
    }
    if (d.ack_of_acks) |a| try w.u32be(a);
    if (d.source) |s| {
        try w.u32be(s.sn_coded);
        try w.u32be(s.sn_source_start);
    }
    if (d.fec) |x| {
        try w.u32be(x.sn_coded);
        try w.u32be(x.sn_source_start);
        try w.byte(x.range);
        try w.byte(x.fec_index);
        try w.u16be(0); // uPadding
    }
    try w.bytes(d.payload);
}

pub fn encodeDatagramInto(d: Datagram, out: []u8) Error![]u8 {
    try checkDatagram(d);
    const n = datagramSize(d);
    if (n > out.len) return error.EndOfBuffer;
    var c = Cursor{ .buf = out };
    c.be32(d.header.sn_source_ack);
    c.be16(d.header.receive_window_size);
    c.be16(d.header.flags);
    if (d.ack_vector) |v| {
        c.be16(@intCast(v.len));
        c.slice(v);
        for (0..ackVectorPadding(v.len)) |_| c.byte(0);
    }
    if (d.ack_of_acks) |a| c.be32(a);
    if (d.source) |s| {
        c.be32(s.sn_coded);
        c.be32(s.sn_source_start);
    }
    if (d.fec) |x| {
        c.be32(x.sn_coded);
        c.be32(x.sn_source_start);
        c.byte(x.range);
        c.byte(x.fec_index);
        c.be16(0);
    }
    c.slice(d.payload);
    return out[0..c.n];
}

/// A write cursor over a buffer known to be large enough.
pub const Cursor = struct {
    buf: []u8,
    n: usize = 0,

    pub fn byte(c: *Cursor, v: u8) void {
        c.buf[c.n] = v;
        c.n += 1;
    }
    pub fn be16(c: *Cursor, v: u16) void {
        std.mem.writeInt(u16, c.buf[c.n..][0..2], v, .big);
        c.n += 2;
    }
    pub fn be32(c: *Cursor, v: u32) void {
        std.mem.writeInt(u32, c.buf[c.n..][0..4], v, .big);
        c.n += 4;
    }
    pub fn le16(c: *Cursor, v: u16) void {
        std.mem.writeInt(u16, c.buf[c.n..][0..2], v, .little);
        c.n += 2;
    }
    pub fn le24(c: *Cursor, v: u24) void {
        std.mem.writeInt(u24, c.buf[c.n..][0..3], v, .little);
        c.n += 3;
    }
    pub fn slice(c: *Cursor, s: []const u8) void {
        @memcpy(c.buf[c.n .. c.n + s.len], s);
        c.n += s.len;
    }
};

/// 5.1.2: every header is validated; an ACK-only datagram carries nothing after its headers.
pub fn decodeDatagram(datagram: []const u8) Error!Datagram {
    var r = bytes.Reader.init(datagram);
    var d = Datagram{ .header = .{ .sn_source_ack = try r.u32be(), .receive_window_size = try r.u16be(), .flags = try r.u16be() } };
    const f = d.header.flags;
    if (f & rdpudp_flag_syn != 0) return error.BadDatagram;
    if (f & rdpudp_flag_ack != 0) {
        const n = try r.u16be();
        if (n > max_ack_vector_size) return error.InvalidField;
        d.ack_vector = try r.bytes(n);
        try r.skip(ackVectorPadding(n));
    }
    if (f & rdpudp_flag_ack_of_acks != 0) d.ack_of_acks = try r.u32be();
    if (f & rdpudp_flag_data != 0) {
        if (f & rdpudp_flag_fec != 0) {
            const coded = try r.u32be();
            const start = try r.u32be();
            const range = try r.byte();
            const index = try r.byte();
            _ = try r.u16be(); // uPadding: ignored by the receiver
            d.fec = .{ .sn_coded = coded, .sn_source_start = start, .range = range, .fec_index = index };
        } else {
            const coded = try r.u32be();
            d.source = .{ .sn_coded = coded, .sn_source_start = try r.u32be() };
        }
        d.payload = r.rest();
    } else {
        if (f & rdpudp_flag_fec != 0) return error.BadDatagram;
        if (r.remaining() != 0) return error.BadDatagram;
    }
    return d;
}

// RDP-UDP data transfer, sans-IO: datagrams in via onDatagram(), out of poll(); `now_us` is
// microseconds on any monotonic clock; nextTimeout() says when to poll() again.

/// Errors of the data transfer, handshake, FEC and secure tunnel.
pub const TransportError = Error || error{
    /// No room in the peer's receive window (MS-RDPEUDP 3.1.1.7) or RDP-UDP2 active range.
    WindowFull,
    /// A lossy or RDP-UDP2 write larger than one datagram (MS-RDPEUDP 3.1.5.3.1).
    MessageTooLarge,
    /// The endpoint is not in the Established state (MS-RDPEUDP 3.1.4.2).
    NotEstablished,
    /// The endpoint is Closed (retransmit limit, keepalive timeout, close()).
    ConnectionClosed,
    /// MS-RDPEUDP 3.1.1.6.3.
    Unrecoverable,
    SecurityHandshakeFailed,
    /// MS-RDPEMT 3.1.5.5: tunnel PDUs before the security handshake, data before Tunnel Create.
    OutOfSequence,
};

/// MS-RDPEUDP 1.3.1: RDP-UDP-R (reliable) or RDP-UDP-L (best effort, no retransmits, order kept).
pub const Mode = enum { reliable, lossy };

/// The mode a SYN asks for: RDPUDP_FLAG_SYNLOSSY means lossy (3.1.5.1.1).
pub fn modeOfSyn(syn: Syn) TransportError!Mode {
    return if (syn.lossy) .lossy else .reliable;
}

/// MS-RDPBCGR 2.2.15.1: UDPFECR is reliable, UDPFECL lossy.
pub fn modeOfProtocol(requested_protocol: u16) TransportError!Mode {
    return switch (requested_protocol) {
        protocol_udpfecr => .reliable,
        protocol_udpfecl => .lossy,
        else => error.InvalidField,
    };
}

/// MS-RDPEUDP2 1.3.1 / MS-RDPEUDP 1.3.2.2: the data-transfer protocol of a version.
pub const DataPhase = enum {
    /// MS-RDPEUDP 3.1.5.3 (versions 1 and 2).
    rdpudp,
    /// MS-RDPEUDP2 (versions above 2).
    rdpudp2,
};

pub fn dataPhaseFor(version: u16) TransportError!DataPhase {
    if (version == 0) return error.InvalidField;
    return if (version <= rdpudp_protocol_version_2) .rdpudp else .rdpudp2;
}

/// Version after a SYN and its SYN+ACK (MS-RDPEUDP 1.7, 3.1.5.1.3): 1 unless both carry a valid
/// SYNEX, else the SYN+ACK's uUdpVer, which may not exceed the SYN's.
pub fn negotiatedVersion(syn: Syn, syn_ack: Syn) TransportError!u16 {
    const offered = syn.synex orelse return rdpudp_protocol_version_1;
    const answered = syn_ack.synex orelse return rdpudp_protocol_version_1;
    if (offered.flags & rdpudp_version_info_valid == 0 or answered.flags & rdpudp_version_info_valid == 0) return rdpudp_protocol_version_1;
    if (answered.version == 0 or answered.version > offered.version) return error.InvalidField;
    return answered.version;
}

// MS-RDPEUDP timers (3.1.1.9, 3.1.2, 3.1.6)

pub const us_per_ms: u64 = 1000;
pub const us_per_s: u64 = 1_000_000;

/// 3.1.1.9 / 3.1.6.2: silence from the peer this long closes the connection.
pub const keepalive_timeout_us: u64 = 65 * us_per_s;
/// 2.2.2.6: RDPUDP_ACK_OF_ACKVECTOR_HEADER SHOULD be sent every 20 packets.
pub const ack_of_acks_interval: u32 = 20;
/// 2.2.2.7: largest AckVector.
pub const max_ack_vector_size: u16 = 2048;
/// 3.1.5.2 <7>/<8>: Windows retransmits SYN and SYN+ACK three times, 800 ms apart.
pub const windows_syn_retransmit_timeout_us: u64 = 800 * us_per_ms;

/// 3.1.6.1: 500 ms (version 1), 300 ms (version 2).
pub fn minRetransmitTimeoutUs(version: u16) TransportError!u64 {
    return switch (version) {
        rdpudp_protocol_version_1 => 500 * us_per_ms,
        rdpudp_protocol_version_2 => 300 * us_per_ms,
        else => error.InvalidField,
    };
}

/// 3.1.6.1: the larger of the minimum and twice the RTT.
pub fn retransmitTimeoutUs(version: u16, rtt_us: u64) TransportError!u64 {
    return @max(try minRetransmitTimeoutUs(version), 2 * rtt_us);
}

/// 3.1.6.3: 200 ms (version 1); version 2: half the RTT within [50, 200] ms.
pub fn delayedAckTimeoutUs(version: u16, rtt_us: u64) TransportError!u64 {
    return switch (version) {
        rdpudp_protocol_version_1 => 200 * us_per_ms,
        rdpudp_protocol_version_2 => @min(@max(50 * us_per_ms, rtt_us / 2), 200 * us_per_ms),
        else => error.InvalidField,
    };
}

// MS-RDPEUDP 3.1.1.4 / 2.2.2.7: ACK vectors as the sender reads them

/// Per-datagram states of an ACK vector, oldest first, ending at snSourceAck; everything
/// before it counts as received, as a Windows sender does.
pub fn ackVectorStates(elements: []const u8, out: []ElementState) TransportError![]ElementState {
    var n: usize = 0;
    for (elements) |b| {
        const e = try unpackAckElement(b);
        if (e.state != .received and e.state != .not_yet_received) return error.InvalidField;
        if (out.len - n < e.length()) return error.EndOfBuffer;
        @memset(out[n .. n + e.length()], e.state);
        n += e.length();
    }
    return out[0..n];
}

/// Sequence number of ackVectorStates()[i], wrapping at 32 bits (3.1.1.2).
pub fn ackVectorSeq(sn_source_ack: u32, n: usize, i: usize) TransportError!u32 {
    if (i >= n) return error.InvalidField;
    return sn_source_ack -% @as(u32, @truncate(n - 1 - i));
}

pub const fec = @import("multitransport/fec.zig");

// MS-RDPEUDP connection state machine (3.1.5, 3.1.5.2): the server side

/// MS-RDPEUDP 3.1.5 states.
pub const ConnState = enum { closed, listen, syn_sent, syn_received, established };

/// Why a data transfer went Closed (3.1.5.4).
pub const CloseReason = union(enum) {
    /// 3.1.5.4.1: a Source Packet (offset from the local ISN) hit max_retransmits.
    retransmit_limit: struct { offset: u64, retransmits: u8 },
    /// 3.1.5.4.2 / 3.1.6.2 (MS-RDPEUDP2 3.1.1.3): nothing from the peer.
    keepalive_timeout,
    /// 3.1.4.4: close().
    closed_locally,

    pub fn format(r: CloseReason, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (r) {
            .retransmit_limit => |x| try w.print("retransmit limit: Source Packet {d} unacknowledged after {d} retransmissions", .{ x.offset, x.retransmits }),
            .keepalive_timeout => try w.writeAll("keepalive timeout: nothing from the client"),
            .closed_locally => try w.writeAll("closed locally"),
        }
    }
};

/// What the connection sequence settled (3.1.1.3, 3.1.5.1.3, 1.7).
pub const Negotiated = struct {
    mode: Mode,
    version: u16,
    phase: DataPhase,
    local_isn: u32,
    peer_isn: u32,
    receive_window_size: u16,
    peer_receive_window_size: u16,
    /// From the SYN+ACK.
    up_stream_mtu: u16,
    down_stream_mtu: u16,
    correlation_id: ?[16]u8 = null,
    /// SYN+ACK round trip, 0 if retransmitted: the first RTT estimate (3.1.6.1).
    handshake_rtt_us: u64 = 0,
};

const handshake = @import("multitransport/handshake.zig");

pub const ServerHandshake = handshake.ServerHandshake;

// MS-RDPEUDP 3.1.5.3: the version 1/2 data transfer engine

const engine = @import("multitransport/engine.zig");

pub const EngineConfig = engine.EngineConfig;

pub const EngineStats = engine.EngineStats;

pub const Engine = engine.Engine;

/// MS-RDPEUDP2: the version 3 data transfer.
pub const udp2 = @import("multitransport/udp2.zig");

pub const Connection = handshake.Connection;

// MS-RDPEMT 1.3.1 / 1.4 / 5.1: TLS over reliable, DTLS over lossy RDP-UDP

const secure = @import("multitransport/secure.zig");

pub const SecurityProtocol = secure.SecurityProtocol;

/// MS-RDPEMT 1.3.1: TLS secures reliable RDP-UDP, DTLS lossy RDP-UDP.
pub fn securityFor(mode: Mode) TransportError!SecurityProtocol {
    return switch (mode) {
        .reliable => .tls,
        .lossy => .dtls,
    };
}

pub const SecureChannel = secure.SecureChannel;

pub const TunnelServer = secure.TunnelServer;

test {
    refAll(@This());
    _ = fec;
    _ = engine;
    _ = udp2;
    _ = handshake;
    _ = secure;
}

fn refAll(comptime T: type) void {
    inline for (comptime std.meta.declarations(T)) |d| {
        const f = @field(T, d);
        if (@TypeOf(f) == type) {
            switch (@typeInfo(f)) {
                .@"struct", .@"union", .@"enum" => refAll(f),
                else => {},
            }
        } else {
            _ = &@field(T, d);
        }
    }
}
