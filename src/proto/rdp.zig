//! Slow-path PDUs on the MCS I/O channel (MS-RDPBCGR 2.2.1.11 - 2.2.1.22, 2.2.8): security
//! header, Client Info, licensing, share control/data framing and connection finalization.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const caps = @import("caps.zig");
const bulk = @import("../codec/bulk.zig");

pub const Error = error{ BadPdu, UnexpectedPdu, StringTooLong } || bytes.Error || caps.Error;

pub const sec_exchange_pkt: u16 = 0x0001;
pub const sec_encrypt: u16 = 0x0008;
pub const sec_info_pkt: u16 = 0x0040;
pub const sec_license_pkt: u16 = 0x0080;

/// SEC_ENCRYPT is ignored at ENCRYPTION_LEVEL_NONE (MS-RDPBCGR 3.3.5.3.11).
pub fn readSecurityFlags(r: *bytes.Reader) Error!u16 {
    const flags = try r.u16le();
    _ = try r.u16le(); // flagsHi
    return flags;
}

// Client Info PDU (MS-RDPBCGR 2.2.1.11)

pub const info_mouse: u32 = 0x00000001;
pub const info_autologon: u32 = 0x00000008;
pub const info_unicode: u32 = 0x00000010;
pub const info_logonnotify: u32 = 0x00000040;
pub const info_compression: u32 = 0x00000080;
pub const info_enablewindowskey: u32 = 0x00000100;
pub const info_remoteconsoleaudio: u32 = 0x00002000;
pub const info_rail: u32 = 0x00008000;
pub const info_logonerrors: u32 = 0x00010000;
pub const info_mouse_has_wheel: u32 = 0x00020000;
pub const info_noaudioplayback: u32 = 0x00080000;
pub const info_using_saved_creds: u32 = 0x00100000;
pub const info_audiocapture: u32 = 0x00200000;
pub const info_video_disable: u32 = 0x00400000;
pub const info_hidef_rail_supported: u32 = 0x02000000;

pub const max_credential_len = 512; // bytes of UTF-16 (256 chars, LONG_CREDENTIALS)

pub const ClientInfo = struct {
    code_page: u32,
    flags: u32,
    /// UTF-16LE strings, pointing into the parsed buffer, without terminator.
    domain: []const u8,
    user_name: []const u8,
    password: []const u8,
    alternate_shell: []const u8,
    working_dir: []const u8,
    // TS_EXTENDED_INFO_PACKET (optional)
    client_address: []const u8 = &.{},
    client_dir: []const u8 = &.{},
    client_session_id: u32 = 0,
    performance_flags: u32 = 0,
    auto_reconnect_cookie: []const u8 = &.{},
};

/// Truncated to 512 bytes including the terminator (MS-RDPBCGR 2.2.1.11.1.1, 3.3.5.3.11).
fn readInfoString(r: *bytes.Reader, len: u16, unicode: bool) Error![]const u8 {
    if (unicode and len % 2 != 0) return error.BadPdu;
    const s = try r.bytes(len);
    const term_len: usize = if (unicode) 2 else 1;
    for (try r.bytes(term_len)) |b| if (b != 0) return error.BadPdu;
    return s[0..@min(s.len, max_credential_len - term_len)];
}

pub fn parseClientInfo(data: []const u8) Error!ClientInfo {
    var r = bytes.Reader.init(data);
    const sec = try readSecurityFlags(&r);
    if (sec & sec_info_pkt == 0) return error.UnexpectedPdu;

    const code_page = try r.u32le();
    const flags = try r.u32le();
    const unicode = flags & info_unicode != 0;
    const cb_domain = try r.u16le();
    const cb_user = try r.u16le();
    const cb_password = try r.u16le();
    const cb_shell = try r.u16le();
    const cb_dir = try r.u16le();
    var info = ClientInfo{
        .code_page = code_page,
        .flags = flags,
        .domain = try readInfoString(&r, cb_domain, unicode),
        .user_name = try readInfoString(&r, cb_user, unicode),
        .password = try readInfoString(&r, cb_password, unicode),
        .alternate_shell = try readInfoString(&r, cb_shell, unicode),
        .working_dir = try readInfoString(&r, cb_dir, unicode),
    };
    if (r.remaining() == 0) return info;

    // Extended info: the cb fields here *include* the terminator.
    _ = try r.u16le(); // clientAddressFamily
    const cb_addr = try r.u16le();
    if (cb_addr > 80) return error.StringTooLong;
    info.client_address = try r.bytes(cb_addr);
    const cb_cdir = try r.u16le();
    if (cb_cdir > 512) return error.StringTooLong;
    info.client_dir = try r.bytes(cb_cdir);
    // Optional fields are whole or absent along with all later ones (2.2.1.11.1.1.1).
    if (r.remaining() == 0) return info;
    try r.skip(172); // clientTimeZone
    if (r.remaining() == 0) return info;
    info.client_session_id = try r.u32le();
    if (r.remaining() == 0) return info;
    info.performance_flags = try r.u32le();
    if (r.remaining() == 0) return info;
    const cb_cookie = try r.u16le();
    if (cb_cookie != 0 and cb_cookie != 28) return error.BadPdu;
    info.auto_reconnect_cookie = try r.bytes(cb_cookie);
    return info;
}

/// License Error PDU, Valid Client (MS-RDPBCGR 2.2.1.12, 4.1.11): no licensing exchange.
pub fn writeLicenseValidClient(w: *bytes.Writer) !void {
    try w.u16le(sec_license_pkt);
    try w.u16le(0);
    try w.byte(0xFF); // ERROR_ALERT
    try w.byte(0x03); // PREAMBLE_VERSION_3_0
    try w.u16le(16); // wMsgSize
    try w.u32le(0x00000007); // STATUS_VALID_CLIENT
    try w.u32le(0x00000002); // ST_NO_TRANSITION
    try w.u16le(0x0004); // BB_ERROR_BLOB
    try w.u16le(0);
}

// share control / data headers (MS-RDPBCGR 2.2.8.1.1.1)

pub const PduType = enum(u4) {
    demand_active = 1,
    confirm_active = 3,
    deactivate_all = 6,
    data = 7,
    server_redir = 10,
    _,
};

pub const PduType2 = enum(u8) {
    update = 2,
    control = 20,
    pointer = 27,
    input = 28,
    synchronize = 31,
    refresh_rect = 33,
    play_sound = 34,
    suppress_output = 35,
    shutdown_request = 36,
    shutdown_denied = 37,
    save_session_info = 38,
    fontlist = 39,
    fontmap = 40,
    set_keyboard_indicators = 41,
    bitmapcache_persistent_list = 43,
    bitmapcache_error_pdu = 44,
    set_keyboard_ime_status = 45,
    offscrcache_error_pdu = 46,
    set_error_info_pdu = 47,
    drawninegrid_error_pdu = 48,
    drawgdiplus_error_pdu = 49,
    arc_status_pdu = 50,
    status_info_pdu = 54,
    monitor_layout_pdu = 55,
    frame_acknowledge = 56,
    _,
};

pub const share_id: u32 = 0x000103EA;
pub const server_source: u16 = 1002;

pub const stream_low: u8 = 1;
pub const stream_med: u8 = 2;

pub const Incoming = union(enum) {
    confirm_active: struct { share_id: u32, caps: caps.ClientCaps },
    data: struct { type2: PduType2, body: []const u8 },
    other: PduType,
    /// T.128 FlowPDU (totalLength 0x8000), ignored (MS-RDPBCGR 2.2.8.1.1.1.1).
    flow: u8,
};

pub fn parseShareControl(data: []const u8) Error!Incoming {
    var r = bytes.Reader.init(data);
    const total = try r.u16le();
    if (total == 0x8000) {
        const flow = try r.byte();
        try r.skip(5);
        return .{ .flow = flow };
    }
    if (total < 6 or total > data.len) return error.BadPdu;
    r = bytes.Reader.init(data[0..total]);
    try r.skip(2);
    const pdu_type: PduType = @fromBackingInt(@intCast(@as(u4, @truncate(try r.u16le()))));
    _ = try r.u16le(); // pduSource
    switch (pdu_type) {
        .confirm_active => {
            const sid = try r.u32le();
            _ = try r.u16le(); // originatorId
            const len_src = try r.u16le();
            const len_caps = try r.u16le();
            try r.skip(len_src); // sourceDescriptor
            var cr = try r.sub(len_caps);
            const count = try cr.u16le();
            try cr.skip(2); // pad
            return .{ .confirm_active = .{ .share_id = sid, .caps = try caps.parseClientCaps(cr.rest(), count) } };
        },
        .data => {
            _ = try r.u32le(); // shareId
            try r.skip(2); // pad1, streamId
            _ = try r.u16le(); // uncompressedLength
            const t2: PduType2 = @fromBackingInt(@intCast(try r.byte()));
            const compressed_type = try r.byte();
            _ = try r.u16le(); // compressedLength
            if (compressed_type & 0x20 != 0) return error.BadPdu; // PACKET_COMPRESSED: never advertised
            return .{ .data = .{ .type2 = t2, .body = r.rest() } };
        },
        else => return .{ .other = pdu_type },
    }
}

/// Write the body after `begin`, then call `finish`.
pub const DataPdu = struct {
    start: usize,

    pub fn begin(w: *bytes.Writer, t2: PduType2, stream: u8) !DataPdu {
        const start = w.len();
        try w.u16le(0); // totalLength, patched
        try w.u16le(0x10 | @as(u16, @backingInt(PduType.data)));
        try w.u16le(server_source);
        try w.u32le(share_id);
        try w.byte(0); // pad1
        try w.byte(stream);
        try w.u16le(0); // uncompressedLength, patched
        try w.byte(@backingInt(t2));
        try w.byte(0); // compressedType
        try w.u16le(0); // compressedLength
        return .{ .start = start };
    }

    pub fn finish(p: DataPdu, w: *bytes.Writer) void {
        const total: u16 = @intCast(w.len() - p.start);
        w.patchU16le(p.start, total);
        // Windows sets uncompressedLength = totalLength (MS-RDPBCGR 4.1.19).
        w.patchU16le(p.start + 12, total);
    }

    /// Bulk-compresses the body (MS-RDPBCGR 3.1.8, 2.2.8.1.1.1.2); a body too large for one
    /// packet is sent uncompressed.
    pub fn finishCompressed(p: DataPdu, w: *bytes.Writer, cmp: *bulk.Compressor) !void {
        const body_start = p.start + data_header_len;
        const body_len = w.len() - body_start;
        if (body_len > try bulk.maxInput(cmp.type)) return p.finish(w);
        const uncompressed: u16 = @intCast(w.len() - p.start);
        const r = try cmp.compress(w.list.items[body_start..]);
        if (r.flags == 0) return p.finish(w);
        if (r.flags & bulk.packet_compressed != 0) {
            w.list.shrinkRetainingCapacity(body_start);
            try w.bytes(r.data);
        }
        const total: u16 = @intCast(w.len() - p.start);
        w.patchU16le(p.start, total);
        w.patchU16le(p.start + 12, uncompressed);
        w.list.items[p.start + 15] = r.flags;
        w.patchU16le(p.start + 16, total);
    }
};

pub const data_header_len = 18;

pub fn writeDemandActive(w: *bytes.Writer, o: caps.ServerCapsOptions, session_id: u32) !void {
    const start = w.len();
    try w.u16le(0); // totalLength
    try w.u16le(0x10 | @as(u16, @backingInt(PduType.demand_active)));
    try w.u16le(server_source);
    try w.u32le(share_id);
    try w.u16le(4); // lengthSourceDescriptor
    const len_caps_at = w.len();
    try w.u16le(0); // lengthCombinedCapabilities, patched
    try w.bytes("RDP\x00");
    const caps_start = w.len();
    const count_at = w.len();
    try w.u16le(0); // numberCapabilities, patched
    try w.u16le(0); // pad
    const n = try caps.writeServerCaps(w, o);
    w.patchU16le(count_at, n);
    w.patchU16le(len_caps_at, @intCast(w.len() - caps_start));
    try w.u32le(session_id);
    w.patchU16le(start, @intCast(w.len() - start));
}

pub fn writeDeactivateAll(w: *bytes.Writer) !void {
    const start = w.len();
    try w.u16le(0);
    try w.u16le(0x10 | @as(u16, @backingInt(PduType.deactivate_all)));
    try w.u16le(server_source);
    try w.u32le(share_id);
    try w.u16le(1); // lengthSourceDescriptor
    try w.byte(0);
    w.patchU16le(start, @intCast(w.len() - start));
}

pub fn writeSynchronize(w: *bytes.Writer, target_user: u16) !void {
    const p = try DataPdu.begin(w, .synchronize, stream_low);
    try w.u16le(1); // SYNCMSGTYPE_SYNC
    try w.u16le(target_user);
    p.finish(w);
}

pub const ctrlaction_request_control: u16 = 1;
pub const ctrlaction_granted_control: u16 = 2;
pub const ctrlaction_detach: u16 = 3;
pub const ctrlaction_cooperate: u16 = 4;

pub fn writeControl(w: *bytes.Writer, action: u16, grant_id: u16, control_id: u32) !void {
    const p = try DataPdu.begin(w, .control, stream_med);
    try w.u16le(action);
    try w.u16le(grant_id);
    try w.u32le(control_id);
    p.finish(w);
}

pub fn writeFontMap(w: *bytes.Writer) !void {
    const p = try DataPdu.begin(w, .fontmap, stream_med);
    try w.u16le(0); // numberEntries
    try w.u16le(0); // totalNumEntries
    try w.u16le(0x0003); // FONTMAP_FIRST | FONTMAP_LAST
    try w.u16le(0x0004); // entrySize
    p.finish(w);
}

pub fn writeSetErrorInfo(w: *bytes.Writer, code: u32) !void {
    const p = try DataPdu.begin(w, .set_error_info_pdu, stream_low);
    w.patchU16le(p.start + 4, 0); // pduSource "MUST be set to zero" (2.2.5.1.1)
    try w.u32le(code);
    p.finish(w);
}

/// Set Error Info codes (MS-RDPBCGR 2.2.5.1.1).
pub const errinfo_disconnected_by_otherconnection: u32 = 0x00000005;
pub const errinfo_logoff_by_user: u32 = 0x0000000C;

pub const Control = struct { action: u16, grant_id: u16, control_id: u32 };

pub fn parseControl(body: []const u8) Error!Control {
    var r = bytes.Reader.init(body);
    return .{ .action = try r.u16le(), .grant_id = try r.u16le(), .control_id = try r.u32le() };
}

pub const Rect16 = struct { left: u16, top: u16, right: u16, bottom: u16 };

/// Refresh Rect PDU (2.2.11.2): inclusive rectangles the client wants redrawn.
pub fn parseRefreshRect(body: []const u8, out: []Rect16) Error![]Rect16 {
    var r = bytes.Reader.init(body);
    const n = try r.byte();
    try r.skip(3);
    if (n > out.len) return error.BadPdu;
    for (out[0..n]) |*rect| rect.* = .{
        .left = try r.u16le(),
        .top = try r.u16le(),
        .right = try r.u16le(),
        .bottom = try r.u16le(),
    };
    return out[0..n];
}

/// False while the client window is minimised (MS-RDPBCGR 2.2.11.3).
pub fn parseSuppressOutput(body: []const u8) Error!bool {
    var r = bytes.Reader.init(body);
    const allow = try r.byte() != 0;
    try r.skip(3); // pad3Octets
    if (allow) try r.skip(8); // desktopRect
    return allow;
}

fn utf16(comptime s: []const u8) [s.len * 2]u8 {
    var out: [s.len * 2]u8 = undefined;
    for (s, 0..) |ch, i| {
        out[2 * i] = ch;
        out[2 * i + 1] = 0;
    }
    return out;
}

test "client info round trip" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try w.u16le(sec_info_pkt);
    try w.u16le(0);
    try w.u32le(0); // codepage
    try w.u32le(info_unicode | info_mouse | info_autologon);
    const dom = utf16("WORK");
    const user = utf16("alice");
    const pw = utf16("s3cret");
    try w.u16le(dom.len);
    try w.u16le(user.len);
    try w.u16le(pw.len);
    try w.u16le(0);
    try w.u16le(0);
    inline for (.{ &dom, &user, &pw }) |s| {
        try w.bytes(s);
        try w.u16le(0);
    }
    try w.u16le(0); // shell terminator
    try w.u16le(0); // dir terminator

    const info = try parseClientInfo(list.items);
    try std.testing.expectEqualSlices(u8, &user, info.user_name);
    try std.testing.expectEqualSlices(u8, &dom, info.domain);
    try std.testing.expectEqualSlices(u8, &pw, info.password);
    try std.testing.expect(info.flags & info_autologon != 0);

    for (0..list.items.len - 1) |n| {
        _ = parseClientInfo(list.items[0..n]) catch continue;
        return error.TestUnexpectedSuccess;
    }
}

test "client info rejects odd unicode lengths and encrypted packets" {
    const odd = bytes.hex("40 00 00 00 00 00 00 00 10 00 00 00 03 00 00 00 00 00 00 00 00 00 41 00 42 00 00");
    try std.testing.expectError(error.BadPdu, parseClientInfo(&odd));
    // SEC_ENCRYPT is ignored (3.3.5.3.11): this is a truncated Client Info.
    const enc = bytes.hex("48 00 00 00");
    try std.testing.expectError(error.EndOfBuffer, parseClientInfo(&enc));
}

test "license valid client matches spec 4.1.11 payload" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeLicenseValidClient(&w);
    try std.testing.expectEqualSlices(u8, &bytes.hex("80 00 00 00 ff 03 10 00 07 00 00 00 02 00 00 00 04 00 00 00"), list.items);
}

test "server synchronize and control match spec 4.1.19/4.1.20 layout" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeSynchronize(&w, 0x03EF);
    try std.testing.expectEqualSlices(u8, &bytes.hex("16 00 17 00 ea 03 ea 03 01 00 00 01 16 00 1f 00 00 00 01 00 ef 03"), list.items);
    list.clearRetainingCapacity();
    try writeControl(&w, ctrlaction_cooperate, 0, 0);
    try std.testing.expectEqualSlices(u8, &bytes.hex("1a 00 17 00 ea 03 ea 03 01 00 00 02 1a 00 14 00 00 00 04 00 00 00 00 00 00 00"), list.items);
    const parsed = try parseShareControl(list.items);
    try std.testing.expectEqual(PduType2.control, parsed.data.type2);
    const ctl = try parseControl(parsed.data.body);
    try std.testing.expectEqual(ctrlaction_cooperate, ctl.action);
}

test "demand active is self-consistent" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeDemandActive(&w, .{ .desktop_width = 1280, .desktop_height = 720 }, 0);
    var r = bytes.Reader.init(list.items);
    try std.testing.expectEqual(@as(u16, @intCast(list.items.len)), try r.u16le());
    try std.testing.expectEqual(@as(u16, 0x11), try r.u16le());

    const caps_off = 6 + 4 + 2 + 2 + 4;
    var ca: std.ArrayList(u8) = .empty;
    defer ca.deinit(std.testing.allocator);
    var cw = bytes.Writer.init(&ca, std.testing.allocator);
    const caps_blob = list.items[caps_off .. list.items.len - 4];
    try cw.u16le(@intCast(6 + 4 + 2 + 2 + 2 + 6 + caps_blob.len));
    try cw.u16le(0x13);
    try cw.u16le(1007);
    try cw.u32le(share_id);
    try cw.u16le(1002);
    try cw.u16le(6);
    try cw.u16le(@intCast(caps_blob.len));
    try cw.bytes("MSTSC\x00");
    try cw.bytes(caps_blob);
    const parsed = try parseShareControl(ca.items);
    try std.testing.expectEqual(@as(u16, 1280), parsed.confirm_active.caps.desktop_width);
}

test "share control rejects bogus lengths" {
    try std.testing.expectError(error.BadPdu, parseShareControl(&bytes.hex("ff 00 17 00 ea 03")));
    try std.testing.expectError(error.BadPdu, parseShareControl(&bytes.hex("02 00 17 00")));
}

test "compressed Share Data PDU header and round trip (2.2.8.1.1.1.2, 3.1.8)" {
    const gpa = std.testing.allocator;
    var cmp = try bulk.Compressor.init(gpa, .mppc_64k);
    defer cmp.deinit();
    var dec = try bulk.Decompressor.init(gpa, .mppc_64k);
    defer dec.deinit();
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var w = bytes.Writer.init(&list, gpa);
    const unit = "UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE";
    var body_buf: [unit.len * 8]u8 = undefined;
    for (0..8) |i| @memcpy(body_buf[i * unit.len ..][0..unit.len], unit);
    const body: []const u8 = &body_buf;
    const p = try DataPdu.begin(&w, .update, stream_low);
    try w.bytes(body);
    try p.finishCompressed(&w, &cmp);
    const pdu = list.items;
    try std.testing.expectEqual(@as(usize, std.mem.readInt(u16, pdu[0..2], .little)), pdu.len);
    try std.testing.expect(pdu.len < 18 + body.len);
    try std.testing.expectEqual(@as(u16, @intCast(18 + body.len)), std.mem.readInt(u16, pdu[12..14], .little));
    try std.testing.expectEqual(@as(u8, @backingInt(PduType2.update)), pdu[14]);
    try std.testing.expect(pdu[15] & bulk.packet_compressed != 0);
    try std.testing.expectEqual(@as(u8, 1), pdu[15] & bulk.compr_type_mask);
    try std.testing.expectEqual(@as(usize, std.mem.readInt(u16, pdu[16..18], .little)), pdu.len);
    try std.testing.expectEqualSlices(u8, body, try dec.decompress(pdu[18..], pdu[15]));
    var cmp8 = try bulk.Compressor.init(gpa, .mppc_8k);
    defer cmp8.deinit();
    list.clearRetainingCapacity();
    const p2 = try DataPdu.begin(&w, .update, stream_low);
    try w.zeros(9000);
    try p2.finishCompressed(&w, &cmp8);
    try std.testing.expectEqual(@as(u8, 0), list.items[15]);
    try std.testing.expectEqual(@as(usize, 18 + 9000), list.items.len);
}
