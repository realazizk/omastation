//! X.224 class 0 TPDUs (MS-RDPBCGR 2.2.1.1, 2.2.1.2, 2.2.9.1.1): Connection Request/Confirm
//! negotiate the security protocol; Data TPDUs carry everything after.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const tpkt = @import("tpkt.zig");

pub const Code = enum(u8) {
    connection_request = 0xE0,
    connection_confirm = 0xD0,
    disconnect_request = 0x80,
    data = 0xF0,
    _,
};

/// RDP_NEG_REQ.requestedProtocols / RDP_NEG_RSP.selectedProtocol bits.
pub const Protocol = packed struct(u32) {
    ssl: bool = false, // PROTOCOL_SSL      0x00000001 TLS
    hybrid: bool = false, // PROTOCOL_HYBRID   0x00000002 CredSSP (NLA)
    rdstls: bool = false, // PROTOCOL_RDSTLS   0x00000004
    hybrid_ex: bool = false, // PROTOCOL_HYBRID_EX 0x00000008 CredSSP + Early User Auth
    rdsaad: bool = false, // PROTOCOL_RDSAAD   0x00000010 Entra ID
    _pad: u27 = 0,

    pub const standard_rdp: Protocol = .{}; // PROTOCOL_RDP 0

    pub fn toInt(p: Protocol) u32 {
        return @bitCast(p);
    }
    pub fn fromInt(v: u32) Protocol {
        return @bitCast(v);
    }
};

/// RDP_NEG_REQ.flags
pub const ReqFlags = packed struct(u8) {
    restricted_admin_mode_required: bool = false, // 0x01
    redirected_authentication_mode_required: bool = false, // 0x02
    _r: u1 = 0,
    correlation_info_present: bool = false, // 0x08
    _pad: u4 = 0,
};

/// RDP_NEG_RSP.flags
pub const RspFlags = packed struct(u8) {
    extended_client_data_supported: bool = false, // 0x01
    dynvc_gfx_protocol_supported: bool = false, // 0x02
    negrsp_reserved: bool = false, // 0x04
    restricted_admin_mode_supported: bool = false, // 0x08
    redirected_authentication_mode_supported: bool = false, // 0x10
    _pad: u3 = 0,
};

/// RDP_NEG_FAILURE.failureCode
pub const FailureCode = enum(u32) {
    ssl_required_by_server = 0x01,
    ssl_not_allowed_by_server = 0x02,
    ssl_cert_not_on_server = 0x03,
    inconsistent_flags = 0x04,
    hybrid_required_by_server = 0x05,
    ssl_with_user_auth_required_by_server = 0x06,
};

const neg_type_req: u8 = 0x01;
const neg_type_rsp: u8 = 0x02;
const neg_type_failure: u8 = 0x03;
const neg_type_correlation: u8 = 0x06;
const neg_len: u16 = 8;
const correlation_len: u16 = 36;

pub const ConnectionRequest = struct {
    src_ref: u16,
    /// "Cookie: mstshash=<user>" value, without CR LF; points into the parsed buffer.
    cookie: ?[]const u8 = null,
    routing_token: ?[]const u8 = null,
    /// Null without an RDP_NEG_REQ: Standard RDP security only.
    requested: ?Protocol = null,
    flags: ReqFlags = .{},
    correlation_id: ?[16]u8 = null,
};

pub const Error = error{
    BadTpdu,
    BadNegotiation,
    UnterminatedCookie,
} || bytes.Error || tpkt.Error;

/// `frame` is the whole TPKT frame.
pub fn parseConnectionRequest(frame: []const u8) Error!ConnectionRequest {
    const total = try tpkt.parseHeader(frame);
    if (total != frame.len) return error.BadLength;
    var r = bytes.Reader.init(frame[tpkt.header_len..]);

    const li = try r.byte();
    if (try r.byte() != @backingInt(Code.connection_request)) return error.BadTpdu;
    // MS-RDPBCGR 3.3.5.3.1: DST-REF, SRC-REF and class "SHOULD be ignored".
    _ = try r.u16be(); // dst-ref
    const src_ref = try r.u16be();
    _ = try r.byte(); // class option (0 for RDP)
    if (li < 6) return error.BadTpdu;
    // LI counts everything after the LI byte, the variable part included.
    if (r.remaining() != li - 6) return error.BadLength;

    var cr = ConnectionRequest{ .src_ref = src_ref };

    // Optional routingToken and/or cookie, CR LF terminated; negotiation structures start with a
    // non-printable type byte (MS-RDPBCGR 3.3.5.3.1).
    while (r.remaining() > 0 and (try r.peek()) >= 0x20) {
        const rest = r.rest();
        const idx = std.mem.indexOf(u8, rest, "\r\n") orelse return error.UnterminatedCookie;
        const line = rest[0..idx];
        try r.skip(idx + 2);
        if (std.mem.startsWith(u8, line, "Cookie: mstshash=")) {
            cr.cookie = line["Cookie: mstshash=".len..];
        } else {
            cr.routing_token = line;
        }
    }

    while (r.remaining() > 0) {
        const t = try r.byte();
        const flags = try r.byte();
        const len = try r.u16le();
        switch (t) {
            neg_type_req => {
                if (len != neg_len) return error.BadNegotiation;
                cr.flags = @bitCast(flags);
                cr.requested = Protocol.fromInt(try r.u32le());
            },
            neg_type_correlation => {
                if (len != correlation_len) return error.BadNegotiation;
                const id = try r.bytes(16);
                try r.skip(16); // reserved
                cr.correlation_id = id[0..16].*;
            },
            else => return error.BadNegotiation,
        }
    }
    return cr;
}

pub const ConnectionConfirm = union(enum) {
    selected: struct { protocol: Protocol, flags: RspFlags = .{} },
    failure: FailureCode,
    /// No negotiation structure (Standard RDP security).
    none,
};

/// MS-RDPBCGR 3.3.5.3.2, 4.1.2.
pub const confirm_src_ref: u16 = 0x1234;

pub fn writeConnectionConfirm(w: *bytes.Writer, src_ref: u16, cc: ConnectionConfirm) !void {
    const f = try tpkt.Frame.begin(w);
    const li: u8 = switch (cc) {
        .none => 6,
        else => 6 + @as(u8, @intCast(neg_len)),
    };
    try w.byte(li);
    try w.byte(@backingInt(Code.connection_confirm));
    try w.u16be(0); // dst-ref
    try w.u16be(src_ref);
    try w.byte(0); // class 0
    switch (cc) {
        .none => {},
        .selected => |s| {
            try w.byte(neg_type_rsp);
            try w.byte(@bitCast(s.flags));
            try w.u16le(neg_len);
            try w.u32le(s.protocol.toInt());
        },
        .failure => |code| {
            try w.byte(neg_type_failure);
            try w.byte(0);
            try w.u16le(neg_len);
            try w.u32le(@backingInt(code));
        },
    }
    f.finish(w);
}

pub fn beginData(w: *bytes.Writer) !tpkt.Frame {
    const f = try tpkt.Frame.begin(w);
    try w.byte(2); // LI
    try w.byte(@backingInt(Code.data));
    try w.byte(0x80); // EOT
    return f;
}

pub fn parseData(frame: []const u8) Error![]const u8 {
    const total = try tpkt.parseHeader(frame);
    if (total != frame.len) return error.BadLength;
    var r = bytes.Reader.init(frame[tpkt.header_len..]);
    if (try r.byte() != 2) return error.BadTpdu;
    if (try r.byte() != @backingInt(Code.data)) return error.BadTpdu;
    if (try r.byte() != 0x80) return error.BadTpdu;
    return r.rest();
}

// MS-RDPBCGR 4.1.1: cookie "eltons", requesting Standard RDP security.
const spec_cr = bytes.hex(
    \\03 00 00 2c 27 e0 00 00 00 00 00 43 6f 6f 6b 69
    \\65 3a 20 6d 73 74 73 68 61 73 68 3d 65 6c 74 6f
    \\6e 73 0d 0a 01 00 08 00 00 00 00 00
);

test "parse spec connection request" {
    const cr = try parseConnectionRequest(&spec_cr);
    try std.testing.expectEqualStrings("eltons", cr.cookie.?);
    try std.testing.expectEqual(@as(u16, 0), cr.src_ref);
    try std.testing.expectEqual(@as(u32, 0), cr.requested.?.toInt());
    try std.testing.expect(cr.correlation_id == null);
}

test "parse connection request with TLS|HYBRID and correlation info" {
    const frame = bytes.hex(
        \\03 00 00 4d 48 e0 00 00 00 00 00
        \\43 6f 6f 6b 69 65 3a 20 6d 73 74 73 68 61 73 68 3d 62 6f 62 0d 0a
        \\01 08 08 00 0b 00 00 00
        \\06 00 24 00 0102030405060708090a0b0c0d0e0f10 00000000000000000000000000000000
    );
    const cr = try parseConnectionRequest(&frame);
    try std.testing.expectEqualStrings("bob", cr.cookie.?);
    const p = cr.requested.?;
    try std.testing.expect(p.ssl and p.hybrid and p.hybrid_ex and !p.rdstls);
    try std.testing.expect(cr.flags.correlation_info_present);
    try std.testing.expectEqual(@as(u8, 0x10), cr.correlation_id.?[15]);
}

test "reject malformed requests" {
    var bad = spec_cr;
    bad[5] = 0xD0; // wrong TPDU code
    try std.testing.expectError(error.BadTpdu, parseConnectionRequest(&bad));
    try std.testing.expectError(error.BadLength, parseConnectionRequest(spec_cr[0 .. spec_cr.len - 1]));
    const no_crlf = bytes.hex("03 00 00 0e 09 e0 00 00 00 00 00 43 6f 6f");
    try std.testing.expectError(error.UnterminatedCookie, parseConnectionRequest(&no_crlf));
}

test "write connection confirm" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeConnectionConfirm(&w, 0x1234, .{ .selected = .{
        .protocol = .{ .ssl = true },
        .flags = .{ .extended_client_data_supported = true, .dynvc_gfx_protocol_supported = true },
    } });
    try std.testing.expectEqualSlices(u8, &bytes.hex("03 00 00 13 0e d0 00 00 12 34 00 02 03 08 00 01 00 00 00"), list.items);

    list.clearRetainingCapacity();
    try writeConnectionConfirm(&w, 0, .{ .failure = .ssl_required_by_server });
    try std.testing.expectEqualSlices(u8, &bytes.hex("03 00 00 13 0e d0 00 00 00 00 00 03 00 08 00 01 00 00 00"), list.items);
}

test "data tpdu round trip" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    const f = try beginData(&w);
    try w.bytes("payload");
    f.finish(&w);
    try std.testing.expectEqualStrings("payload", try parseData(list.items));
}
