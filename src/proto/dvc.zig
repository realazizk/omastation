//! Dynamic virtual channels over the `drdynvc` static channel (MS-RDPEDYC). A PDU fits one
//! 1600-byte static chunk; larger messages split into DATA_FIRST + DATA.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

pub const Error = error{ BadDvcPdu, MessageTooLarge } || bytes.Error || std.mem.Allocator.Error;

pub const Cmd = enum(u4) {
    create = 0x01,
    data_first = 0x02,
    data = 0x03,
    close = 0x04,
    capabilities = 0x05,
    data_first_compressed = 0x06,
    data_compressed = 0x07,
    soft_sync_request = 0x08,
    soft_sync_response = 0x09,
    _,
};

/// Largest DVC PDU (one static channel chunk).
pub const max_pdu = 1600;
pub const max_message_len: usize = 64 * 1024 * 1024;

fn fieldSize(v: u32) u2 {
    if (v <= 0xFF) return 0;
    if (v <= 0xFFFF) return 1;
    return 2;
}

fn writeVar(w: *bytes.Writer, size: u2, v: u32) !void {
    switch (size) {
        0 => try w.byte(@intCast(v)),
        1 => try w.u16le(@intCast(v)),
        else => try w.u32le(v),
    }
}

fn readVar(r: *bytes.Reader, size: u2) Error!u32 {
    return switch (size) {
        0 => try r.byte(),
        1 => try r.u16le(),
        2 => try r.u32le(),
        3 => error.BadDvcPdu,
    };
}

fn header(cmd: Cmd, sp: u2, cb_id: u2) u8 {
    return @as(u8, @backingInt(cmd)) << 4 | @as(u8, sp) << 2 | cb_id;
}

/// PriorityCharge0..3 as a Windows server sends them: 5%, 15%, 25% and 55% of the bandwidth
/// for priority classes 0 to 3 (MS-RDPEDYC 2.2.1.1.2).
pub const priority_charges = [4]u16{ 0x3333, 0x1111, 0x0a3d, 0x04a7 };

/// DYNVC_CAPS_VERSION1, or VERSION2/3 with `priority_charges`.
pub fn writeCapsRequest(w: *bytes.Writer, version: u16) !void {
    try w.byte(header(.capabilities, 0, 0));
    try w.byte(0); // pad
    try w.u16le(version);
    if (version >= 2) for (priority_charges) |c| try w.u16le(c);
}

pub fn writeCreateRequest(w: *bytes.Writer, channel_id: u32, name: []const u8) !void {
    return writeCreateRequestPri(w, channel_id, name, 0);
}

/// DYNVC_CREATE_REQ (2.2.2.1); `pri` indexes PriorityCharge (ignored by version 1 clients).
pub fn writeCreateRequestPri(w: *bytes.Writer, channel_id: u32, name: []const u8, pri: u2) !void {
    const cb = fieldSize(channel_id);
    try w.byte(header(.create, pri, cb));
    try writeVar(w, cb, channel_id);
    try w.bytes(name);
    try w.byte(0);
}

pub fn writeClose(w: *bytes.Writer, channel_id: u32) !void {
    const cb = fieldSize(channel_id);
    try w.byte(header(.close, 0, cb));
    try writeVar(w, cb, channel_id);
}

/// TunnelType (MS-RDPEDYC 2.2.5.1.1): the reliable and the lossy multitransport tunnel.
pub const tunneltype_udpfecr: u32 = 0x00000001;
pub const tunneltype_udpfecl: u32 = 0x00000003;
/// Soft-Sync Request Flags (2.2.5.1).
pub const soft_sync_tcp_flushed: u16 = 0x01;
pub const soft_sync_channel_list_present: u16 = 0x02;

/// One DYNVC_SOFT_SYNC_CHANNEL_LIST (2.2.5.1.1).
pub const SoftSyncList = struct { tunnel_type: u32, channel_ids: []const u32 };

/// DYNVC_SOFT_SYNC_REQUEST (2.2.5.1); SOFT_SYNC_TCP_FLUSHED is always set (3.3.5.3.1).
/// error.BadDvcPdu for a TunnelType in two lists, or more than 65535 lists or channels.
pub fn writeSoftSyncRequest(w: *bytes.Writer, lists: []const SoftSyncList) !void {
    if (lists.len > 0xFFFF) return error.BadDvcPdu;
    var length: usize = 8;
    for (lists, 0..) |l, i| {
        if (l.channel_ids.len > 0xFFFF) return error.BadDvcPdu;
        for (lists[0..i]) |o| if (o.tunnel_type == l.tunnel_type) return error.BadDvcPdu;
        length += 6 + 4 * l.channel_ids.len;
    }
    try w.byte(header(.soft_sync_request, 0, 0));
    try w.byte(0); // Pad
    try w.u32le(@intCast(length));
    try w.u16le(soft_sync_tcp_flushed | if (lists.len > 0) soft_sync_channel_list_present else 0);
    try w.u16le(@intCast(lists.len));
    for (lists) |l| {
        try w.u32le(l.tunnel_type);
        try w.u16le(@intCast(l.channel_ids.len));
        for (l.channel_ids) |id| try w.u32le(id);
    }
}

/// TunnelsToSwitch of a DYNVC_SOFT_SYNC_RESPONSE (2.2.5.2); unknown TunnelTypes are BadDvcPdu.
pub const SoftSyncTunnels = struct { reliable: bool = false, lossy: bool = false };

pub fn parseSoftSyncResponse(pdu: []const u8) Error!SoftSyncTunnels {
    var r = bytes.Reader.init(pdu);
    const h = try r.byte();
    if (h >> 4 != @backingInt(Cmd.soft_sync_response)) return error.BadDvcPdu;
    try r.skip(1); // Pad
    const n = try r.u32le();
    if (r.remaining() != @as(usize, n) * 4) return error.BadDvcPdu;
    var out: SoftSyncTunnels = .{};
    for (0..n) |_| switch (try r.u32le()) {
        tunneltype_udpfecr => out.reliable = true,
        tunneltype_udpfecl => out.lossy = true,
        else => return error.BadDvcPdu,
    };
    return out;
}

/// Largest message sent as a single DYNVC_DATA (MS-RDPEDYC 2.2.3).
pub const max_single_data = 1590;

/// Splits a message into PDUs of at most `max_pdu` bytes, passed to `sink.pdu`.
pub fn writeData(gpa: std.mem.Allocator, channel_id: u32, msg: []const u8, sink: anytype) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    const cb = fieldSize(channel_id);
    const id_len: usize = switch (cb) {
        0 => 1,
        1 => 2,
        else => 4,
    };

    if (msg.len <= max_single_data) {
        var w = bytes.Writer.init(&buf, gpa);
        try w.byte(header(.data, 0, cb));
        try writeVar(&w, cb, channel_id);
        try w.bytes(msg);
        return sink.pdu(buf.items);
    }

    const len_size = fieldSize(@intCast(msg.len));
    const len_len: usize = switch (len_size) {
        0 => 1,
        1 => 2,
        else => 4,
    };
    var off: usize = 0;
    {
        var w = bytes.Writer.init(&buf, gpa);
        try w.byte(header(.data_first, len_size, cb));
        try writeVar(&w, cb, channel_id);
        try writeVar(&w, len_size, @intCast(msg.len));
        const n = @min(max_pdu - 1 - id_len - len_len, msg.len);
        try w.bytes(msg[0..n]);
        off = n;
        try sink.pdu(buf.items);
    }
    while (off < msg.len) {
        buf.clearRetainingCapacity();
        var w = bytes.Writer.init(&buf, gpa);
        try w.byte(header(.data, 0, cb));
        try writeVar(&w, cb, channel_id);
        const n = @min(max_pdu - 1 - id_len, msg.len - off);
        try w.bytes(msg[off .. off + n]);
        off += n;
        try sink.pdu(buf.items);
    }
}

pub const ClientPdu = union(enum) {
    caps_response: u16,
    create_response: struct { channel_id: u32, status: i32 },
    data_first: struct { channel_id: u32, total: u32, data: []const u8 },
    data: struct { channel_id: u32, data: []const u8 },
    /// Version 3 (2.2.3.3, 2.2.3.4): `data` is an RDP_SEGMENTED_DATA holding one RDP8 Lite
    /// segment; `total` is the uncompressed length.
    data_first_compressed: struct { channel_id: u32, total: u32, data: []const u8 },
    data_compressed: struct { channel_id: u32, data: []const u8 },
    close: u32,
    soft_sync_response,
};

pub fn parseClientPdu(pdu: []const u8) Error!ClientPdu {
    var r = bytes.Reader.init(pdu);
    const h = try r.byte();
    const cmd: Cmd = @fromBackingInt(@intCast(@as(u4, @truncate(h >> 4))));
    const sp: u2 = @truncate(h >> 2);
    const cb: u2 = @truncate(h);
    switch (cmd) {
        .capabilities => {
            try r.skip(1);
            return .{ .caps_response = try r.u16le() };
        },
        .create => {
            const id = try readVar(&r, cb);
            return .{ .create_response = .{ .channel_id = id, .status = @bitCast(try r.u32le()) } };
        },
        .data_first => {
            const id = try readVar(&r, cb);
            const total = try readVar(&r, sp);
            if (total > max_message_len) return error.MessageTooLarge;
            return .{ .data_first = .{ .channel_id = id, .total = total, .data = r.rest() } };
        },
        .data => {
            const id = try readVar(&r, cb);
            return .{ .data = .{ .channel_id = id, .data = r.rest() } };
        },
        .data_first_compressed => {
            const id = try readVar(&r, cb);
            const total = try readVar(&r, sp);
            if (total > max_message_len) return error.MessageTooLarge;
            return .{ .data_first_compressed = .{ .channel_id = id, .total = total, .data = r.rest() } };
        },
        .data_compressed => {
            const id = try readVar(&r, cb);
            return .{ .data_compressed = .{ .channel_id = id, .data = r.rest() } };
        },
        .close => return .{ .close = try readVar(&r, cb) },
        .soft_sync_response => return .soft_sync_response,
        else => return error.BadDvcPdu,
    }
}

/// Reassembles DATA_FIRST + DATA sequences for one channel.
pub const Reassembler = struct {
    buf: std.ArrayList(u8) = .empty,
    expected: usize = 0,
    in_progress: bool = false,

    pub fn deinit(r: *Reassembler, gpa: std.mem.Allocator) void {
        r.buf.deinit(gpa);
    }

    pub fn first(r: *Reassembler, gpa: std.mem.Allocator, total: u32, chunk: []const u8) Error!?[]const u8 {
        if (chunk.len > total) return error.BadDvcPdu;
        r.buf.clearRetainingCapacity();
        r.expected = total;
        r.in_progress = true;
        try r.buf.appendSlice(gpa, chunk);
        return r.finishIfComplete();
    }

    /// A DATA PDU: either a whole message, or a continuation.
    pub fn data(r: *Reassembler, gpa: std.mem.Allocator, d: []const u8) Error!?[]const u8 {
        if (!r.in_progress) return d;
        if (r.buf.items.len + d.len > r.expected) return error.BadDvcPdu;
        try r.buf.appendSlice(gpa, d);
        return r.finishIfComplete();
    }

    fn finishIfComplete(r: *Reassembler) ?[]const u8 {
        if (r.buf.items.len != r.expected) return null;
        r.in_progress = false;
        return r.buf.items;
    }
};

test "caps and create request encoding (MS-RDPEDYC 4.1)" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeCapsRequest(&w, 3);
    try std.testing.expectEqualSlices(u8, &bytes.hex("50 00 03 00 33 33 11 11 3d 0a a7 04"), list.items);
    list.clearRetainingCapacity();
    try writeCreateRequest(&w, 3, "Microsoft::Windows::RDS::Graphics");
    try std.testing.expectEqual(@as(u8, 0x10), list.items[0]);
    try std.testing.expectEqual(@as(u8, 3), list.items[1]);
    try std.testing.expectEqual(@as(u8, 0), list.items[list.items.len - 1]);
    list.clearRetainingCapacity();
    try writeCreateRequestPri(&w, 3, "AUDIO_PLAYBACK_DVC", 3);
    try std.testing.expectEqual(@as(u8, 0x1c), list.items[0]); // Cmd 1, Pri 3
}

test "soft-sync request and response (MS-RDPEDYC 2.2.5)" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeSoftSyncRequest(&w, &.{.{ .tunnel_type = tunneltype_udpfecr, .channel_ids = &.{ 1, 2 } }});
    try std.testing.expectEqualSlices(u8, &bytes.hex("80 00 16 00 00 00 03 00 01 00 01 00 00 00 02 00 01 00 00 00 02 00 00 00"), list.items);
    const t = try parseSoftSyncResponse(&bytes.hex("90 00 01 00 00 00 01 00 00 00"));
    try std.testing.expect(t.reliable and !t.lossy);
    try std.testing.expectError(error.BadDvcPdu, parseSoftSyncResponse(&bytes.hex("90 00 02 00 00 00 01 00 00 00")));
}

test "parse client pdus" {
    try std.testing.expectEqual(@as(u16, 3), (try parseClientPdu(&bytes.hex("50 00 03 00"))).caps_response);
    const cr = (try parseClientPdu(&bytes.hex("10 03 00 00 00 00"))).create_response;
    try std.testing.expectEqual(@as(u32, 3), cr.channel_id);
    try std.testing.expectEqual(@as(i32, 0), cr.status);
    const failed = (try parseClientPdu(&bytes.hex("10 05 01 00 00 c0"))).create_response;
    try std.testing.expect(failed.status < 0);
    const d = (try parseClientPdu(&bytes.hex("30 07 aa bb"))).data;
    try std.testing.expectEqual(@as(u32, 7), d.channel_id);
    try std.testing.expectEqualSlices(u8, &bytes.hex("aa bb"), d.data);
    const df = (try parseClientPdu(&bytes.hex("25 01 01 00 10 cc"))).data_first;
    try std.testing.expectEqual(@as(u32, 0x101), df.channel_id);
    try std.testing.expectEqual(@as(u32, 0x1000), df.total);
    // MS-RDPEDYC 4.3.4: DYNVC_DATA_COMPRESSED on channel 3.
    const dc = (try parseClientPdu(&bytes.hex("70 03 e0 26 88 7f e8 f4 02"))).data_compressed;
    try std.testing.expectEqual(@as(u32, 3), dc.channel_id);
    try std.testing.expectEqual(@as(u8, 0xe0), dc.data[0]);
    try std.testing.expectError(error.BadDvcPdu, parseClientPdu(&bytes.hex("a0 01 00")));
    try std.testing.expectError(error.EndOfBuffer, parseClientPdu(&bytes.hex("12 01")));
}

test "large message splits into DATA_FIRST + DATA and reassembles" {
    const gpa = std.testing.allocator;
    const msg = try gpa.alloc(u8, 5000);
    defer gpa.free(msg);
    for (msg, 0..) |*b, i| b.* = @truncate(i);

    const Collect = struct {
        list: std.ArrayList([]u8) = .empty,
        gpa: std.mem.Allocator,
        fn pdu(self: *@This(), p: []const u8) !void {
            try std.testing.expect(p.len <= max_pdu);
            try self.list.append(self.gpa, try self.gpa.dupe(u8, p));
        }
    };
    var col = Collect{ .gpa = gpa };
    defer {
        for (col.list.items) |p| gpa.free(p);
        col.list.deinit(gpa);
    }
    try writeData(gpa, 9, msg, &col);
    try std.testing.expect(col.list.items.len == 4);

    var r = Reassembler{};
    defer r.deinit(gpa);
    var out: ?[]const u8 = null;
    for (col.list.items) |p| {
        switch (try parseClientPdu(p)) {
            .data_first => |f| out = try r.first(gpa, f.total, f.data),
            .data => |dd| out = try r.data(gpa, dd.data),
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqualSlices(u8, msg, out.?);
}
