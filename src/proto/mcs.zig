//! T.125 MCS as profiled by RDP (MS-RDPBCGR 2.2.1.3 - 2.2.1.9, 2.2.8.1.1.1.2): BER for
//! Connect-Initial/Response, aligned PER (first byte `choice << 2`) for domain PDUs.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const ber = @import("ber.zig");
const per = @import("per.zig");

pub const Error = error{ BadMcs, UnexpectedPdu } || ber.Error || per.Error;

pub const user_id_base: u16 = 1001;
/// Windows numbering: 1002 is the server's own user channel, the I/O channel is 1003.
pub const server_user_id: u16 = 1002;
pub const io_channel_id: u16 = 1003;

const app_connect_initial: u8 = 101;
const app_connect_response: u8 = 102;

pub const DomainParameters = struct {
    max_channel_ids: u32,
    max_user_ids: u32,
    max_token_ids: u32,
    num_priorities: u32,
    min_throughput: u32,
    max_height: u32,
    max_mcspdu_size: u32,
    protocol_version: u32,

    /// What Windows answers with (MS-RDPBCGR 4.1.4).
    pub const server_default: DomainParameters = .{
        .max_channel_ids = 34,
        .max_user_ids = 3,
        .max_token_ids = 0,
        .num_priorities = 1,
        .min_throughput = 0,
        .max_height = 1,
        .max_mcspdu_size = 65528,
        .protocol_version = 2,
    };

    /// MergeDomainParameters (MS-RDPBCGR 3.3.5.3.3); null when the proposal cannot be reconciled.
    pub fn merge(target: DomainParameters, minimum: DomainParameters, maximum: DomainParameters) ?DomainParameters {
        var out: DomainParameters = undefined;
        out.max_channel_ids = if (target.max_channel_ids >= 4)
            target.max_channel_ids
        else if (maximum.max_channel_ids >= 4) 4 else return null;
        out.max_user_ids = if (target.max_user_ids >= 3)
            target.max_user_ids
        else if (maximum.max_user_ids >= 3) 3 else return null;
        out.max_token_ids = target.max_token_ids;
        if (minimum.num_priorities > 1) return null;
        out.num_priorities = 1;
        out.min_throughput = target.min_throughput;
        if (target.max_height != 1 and minimum.max_height > 1) return null;
        out.max_height = 1;
        if (target.max_mcspdu_size >= 124) {
            out.max_mcspdu_size = if (target.max_mcspdu_size <= 65528)
                target.max_mcspdu_size
            else if (minimum.max_mcspdu_size >= 124 and minimum.max_mcspdu_size <= 65528) 65528 else return null;
        } else {
            if (maximum.max_mcspdu_size < 124) return null;
            out.max_mcspdu_size = maximum.max_mcspdu_size;
        }
        if (target.protocol_version != 2 and !(minimum.protocol_version <= 2 and maximum.protocol_version >= 2)) return null;
        out.protocol_version = 2;
        return out;
    }
};

fn readDomainParameters(r: *bytes.Reader) Error!DomainParameters {
    const len = try ber.readTag(r, ber.tag_sequence);
    var s = try r.sub(len);
    return .{
        .max_channel_ids = try ber.readInteger(&s),
        .max_user_ids = try ber.readInteger(&s),
        .max_token_ids = try ber.readInteger(&s),
        .num_priorities = try ber.readInteger(&s),
        .min_throughput = try ber.readInteger(&s),
        .max_height = try ber.readInteger(&s),
        .max_mcspdu_size = try ber.readInteger(&s),
        .protocol_version = try ber.readInteger(&s),
    };
}

fn writeDomainParameters(w: *bytes.Writer, p: DomainParameters) !void {
    var tmp: std.ArrayList(u8) = .empty;
    defer tmp.deinit(w.gpa);
    var tw = bytes.Writer.init(&tmp, w.gpa);
    inline for (.{
        p.max_channel_ids, p.max_user_ids, p.max_token_ids,   p.num_priorities,
        p.min_throughput,  p.max_height,   p.max_mcspdu_size, p.protocol_version,
    }) |v| try ber.writeInteger(&tw, v);
    try w.byte(ber.tag_sequence);
    try ber.writeLength(w, tmp.items.len);
    try w.bytes(tmp.items);
}

pub const ConnectInitial = struct {
    target: DomainParameters,
    /// The merge of target, minimum and maximum (MS-RDPBCGR 3.3.5.3.3).
    merged: DomainParameters,
    /// GCC Conference Create Request, pointing into the input.
    user_data: []const u8,
};

pub fn parseConnectInitial(payload: []const u8) Error!ConnectInitial {
    var r = bytes.Reader.init(payload);
    const len = try ber.readApplicationTag(&r, app_connect_initial);
    var s = try r.sub(len);
    _ = try ber.readOctetString(&s); // callingDomainSelector
    _ = try ber.readOctetString(&s); // calledDomainSelector
    _ = try ber.readBoolean(&s); // upwardFlag
    const target = try readDomainParameters(&s);
    const minimum = try readDomainParameters(&s);
    const maximum = try readDomainParameters(&s);
    const user_data = try ber.readOctetString(&s);
    // The encoded lengths must match the data received (MS-RDPBCGR 3.3.5.3.3).
    if (s.remaining() != 0 or r.remaining() != 0) return error.BadMcs;
    const merged = DomainParameters.merge(target, minimum, maximum) orelse return error.BadMcs;
    return .{ .target = target, .merged = merged, .user_data = user_data };
}

/// Without TPKT/X.224 framing.
pub fn writeConnectResponse(w: *bytes.Writer, params: DomainParameters, gcc_response: []const u8) !void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(w.gpa);
    var bw = bytes.Writer.init(&body, w.gpa);
    try ber.writeEnumerated(&bw, 0); // rt-successful
    try ber.writeInteger(&bw, 0); // calledConnectId
    try writeDomainParameters(&bw, params);
    try ber.writeOctetString(&bw, gcc_response);
    try ber.writeApplicationTag(w, app_connect_response, body.items.len);
    try w.bytes(body.items);
}

/// DomainMCSPDU choice indices.
pub const DomainPdu = enum(u6) {
    erect_domain_request = 1,
    disconnect_provider_ultimatum = 8,
    attach_user_request = 10,
    attach_user_confirm = 11,
    channel_join_request = 14,
    channel_join_confirm = 15,
    send_data_request = 25,
    send_data_indication = 26,
    _,
};

pub fn domainPduType(first: u8) DomainPdu {
    return @fromBackingInt(@intCast(first >> 2));
}

pub const DisconnectReason = enum(u3) {
    domain_disconnected = 0,
    provider_initiated = 1,
    token_purged = 2,
    user_requested = 3,
    channel_purged = 4,
};

pub const ClientPdu = union(enum) {
    erect_domain_request,
    attach_user_request,
    channel_join_request: struct { initiator: u16, channel_id: u16 },
    send_data_request: struct { initiator: u16, channel_id: u16, data: []const u8 },
    disconnect_provider_ultimatum: DisconnectReason,
};

pub fn parseClientPdu(payload: []const u8) Error!ClientPdu {
    var r = bytes.Reader.init(payload);
    const first = try r.byte();
    switch (domainPduType(first)) {
        .erect_domain_request => {
            _ = try per.readInteger(&r); // subHeight
            _ = try per.readInteger(&r); // subInterval
            return .erect_domain_request;
        },
        .attach_user_request => return .attach_user_request,
        .channel_join_request => return .{ .channel_join_request = .{
            .initiator = try per.readInteger16(&r, user_id_base),
            .channel_id = try r.u16be(),
        } },
        .send_data_request => {
            const initiator = try per.readInteger16(&r, user_id_base);
            const channel_id = try r.u16be();
            _ = try r.byte(); // dataPriority + segmentation
            const len = try per.readLength(&r);
            const data = try r.bytes(len);
            return .{ .send_data_request = .{ .initiator = initiator, .channel_id = channel_id, .data = data } };
        },
        .disconnect_provider_ultimatum => {
            // reason (3 bits) spans the low 2 bits of byte 0 and the top bit of byte 1.
            const second = try r.byte();
            const reason: u3 = @truncate((first & 0x03) << 1 | second >> 7);
            return .{ .disconnect_provider_ultimatum = std.enums.fromInt(DisconnectReason, reason) orelse .provider_initiated };
        },
        else => return error.UnexpectedPdu,
    }
}

pub fn writeAttachUserConfirm(w: *bytes.Writer, user_id: u16) !void {
    try w.byte(@as(u8, @backingInt(DomainPdu.attach_user_confirm)) << 2 | 0x02); // initiator present
    try w.byte(0); // result: rt-successful
    try per.writeInteger16(w, user_id, user_id_base);
}

/// T.125 Result values RDP uses.
pub const rt_successful: u8 = 0;
pub const rt_unspecified_failure: u8 = 14;

pub fn writeChannelJoinConfirm(w: *bytes.Writer, user_id: u16, channel_id: u16) !void {
    try writeChannelJoinResult(w, rt_successful, user_id, channel_id);
}

/// initiator, requested and channelId copy the request (MS-RDPBCGR 3.3.5.3.9).
pub fn writeChannelJoinResult(w: *bytes.Writer, result: u8, initiator: u16, channel_id: u16) !void {
    try w.byte(@as(u8, @backingInt(DomainPdu.channel_join_confirm)) << 2 | 0x02); // channelId present
    try w.byte(result);
    try per.writeInteger16(w, initiator, user_id_base);
    try w.u16be(channel_id); // requested
    try w.u16be(channel_id); // channelId
}

pub fn writeDisconnectProviderUltimatum(w: *bytes.Writer, reason: DisconnectReason) !void {
    const r: u8 = @backingInt(reason);
    try w.byte(@as(u8, @backingInt(DomainPdu.disconnect_provider_ultimatum)) << 2 | r >> 1);
    try w.byte((r & 0x01) << 7);
}

/// The caller appends exactly `len` payload bytes.
pub fn writeSendDataIndicationHeader(w: *bytes.Writer, channel_id: u16, len: usize) !void {
    try w.byte(@as(u8, @backingInt(DomainPdu.send_data_indication)) << 2);
    try per.writeInteger16(w, server_user_id, user_id_base);
    try w.u16be(channel_id);
    try w.byte(0x70); // priority high, segmentation begin|end
    try per.writeLength(w, len);
}

const x224 = @import("x224.zig");

test "parse spec connect initial (MS-RDPBCGR 4.1.3)" {
    const frame = @embedFile("../testdata/bcgr-4.1.3-mcs-ci.bin");
    const ci = try parseConnectInitial(try x224.parseData(frame));
    try std.testing.expectEqual(@as(u32, 34), ci.target.max_channel_ids);
    try std.testing.expectEqual(@as(u32, 2), ci.target.max_user_ids);
    try std.testing.expectEqual(@as(u32, 0xFFFF), ci.target.max_mcspdu_size);
    try std.testing.expectEqual(@as(u32, 2), ci.target.protocol_version);
    try std.testing.expectEqual(@as(usize, 0x133), ci.user_data.len);
}

test "connect response matches spec framing (MS-RDPBCGR 4.1.4)" {
    const spec = @embedFile("../testdata/bcgr-4.1.4-mcs-cr.bin");
    const spec_payload = try x224.parseData(spec);
    // Re-encoded with the spec's own GCC blob, the result must be byte-identical.
    var r = bytes.Reader.init(spec_payload);
    const len = try ber.readApplicationTag(&r, app_connect_response);
    var s = try r.sub(len);
    _ = try ber.readEnumerated(&s);
    _ = try ber.readInteger(&s);
    const params = try readDomainParameters(&s);
    const gcc = try ber.readOctetString(&s);
    try std.testing.expectEqualDeep(DomainParameters.server_default, params);

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeConnectResponse(&w, params, gcc);
    try std.testing.expectEqualSlices(u8, spec_payload, list.items);
}

test "domain pdus (MS-RDPBCGR 4.1.5 - 4.1.8)" {
    try std.testing.expectEqual(ClientPdu.erect_domain_request, try parseClientPdu(&bytes.hex("04 01 00 01 00")));
    try std.testing.expectEqual(ClientPdu.attach_user_request, try parseClientPdu(&bytes.hex("28")));
    const cj = (try parseClientPdu(&bytes.hex("38 00 06 03 ef"))).channel_join_request;
    try std.testing.expectEqual(@as(u16, 1007), cj.initiator);
    try std.testing.expectEqual(@as(u16, 1007), cj.channel_id);

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeAttachUserConfirm(&w, 1007);
    try std.testing.expectEqualSlices(u8, &bytes.hex("2e 00 00 06"), list.items);
    list.clearRetainingCapacity();
    try writeChannelJoinConfirm(&w, 1007, 1003);
    try std.testing.expectEqualSlices(u8, &bytes.hex("3e 00 00 06 03 eb 03 eb"), list.items);
    list.clearRetainingCapacity();
    try writeDisconnectProviderUltimatum(&w, .user_requested);
    try std.testing.expectEqualSlices(u8, &bytes.hex("21 80"), list.items);
    try std.testing.expectEqual(DisconnectReason.user_requested, (try parseClientPdu(list.items)).disconnect_provider_ultimatum);
}

test "send data request parse and indication header" {
    const sdr = (try parseClientPdu(&bytes.hex("64 00 06 03 eb 70 03 aa bb cc"))).send_data_request;
    try std.testing.expectEqual(@as(u16, 1007), sdr.initiator);
    try std.testing.expectEqual(@as(u16, 1003), sdr.channel_id);
    try std.testing.expectEqualSlices(u8, &bytes.hex("aa bb cc"), sdr.data);
    try std.testing.expectError(error.EndOfBuffer, parseClientPdu(&bytes.hex("64 00 06 03 eb 70 05 aa")));

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeSendDataIndicationHeader(&w, 1003, 0x14);
    try std.testing.expectEqualSlices(u8, &bytes.hex("68 00 01 03 eb 70 14"), list.items);
}
