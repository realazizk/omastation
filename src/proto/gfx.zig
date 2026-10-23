//! Graphics Pipeline Extension (MS-RDPEGFX) on the Graphics dynamic channel. Server messages are
//! RDP_SEGMENTED_DATA (2.2.5.1), optionally ZGFX-compressed; client messages are raw (1.3).

const std = @import("std");
const bytes = @import("../core/bytes.zig");

pub const channel_name = "Microsoft::Windows::RDS::Graphics";

pub const Error = error{BadGfxPdu} || bytes.Error;

pub const CmdId = enum(u16) {
    wire_to_surface_1 = 0x0001,
    wire_to_surface_2 = 0x0002,
    delete_encoding_context = 0x0003,
    solid_fill = 0x0004,
    surface_to_surface = 0x0005,
    surface_to_cache = 0x0006,
    cache_to_surface = 0x0007,
    evict_cache_entry = 0x0008,
    create_surface = 0x0009,
    delete_surface = 0x000A,
    start_frame = 0x000B,
    end_frame = 0x000C,
    frame_acknowledge = 0x000D,
    reset_graphics = 0x000E,
    map_surface_to_output = 0x000F,
    cache_import_offer = 0x0010,
    cache_import_reply = 0x0011,
    caps_advertise = 0x0012,
    caps_confirm = 0x0013,
    map_surface_to_window = 0x0015,
    qoe_frame_acknowledge = 0x0016,
    map_surface_to_scaled_output = 0x0017,
    map_surface_to_scaled_window = 0x0018,
    _,
};

pub const CodecId = enum(u16) {
    uncompressed = 0x0000,
    cavideo = 0x0003,
    clearcodec = 0x0008,
    caprogressive = 0x0009,
    planar = 0x000A,
    avc420 = 0x000B,
    alpha = 0x000C,
    avc444 = 0x000E,
    avc444v2 = 0x000F,
};

pub const pixel_format_xrgb8888: u8 = 0x20;
pub const pixel_format_argb8888: u8 = 0x21;

pub const capversion_8: u32 = 0x00080004;
pub const capversion_81: u32 = 0x00080105;
pub const capversion_10: u32 = 0x000A0002;
pub const capversion_101: u32 = 0x000A0100;
pub const capversion_102: u32 = 0x000A0200;
pub const capversion_103: u32 = 0x000A0301;
pub const capversion_104: u32 = 0x000A0400;
pub const capversion_105: u32 = 0x000A0502;
pub const capversion_106: u32 = 0x000A0600;
pub const capversion_106_err: u32 = 0x000A0601;
pub const capversion_107: u32 = 0x000A0701;

pub const caps_flag_thinclient: u32 = 0x01;
pub const caps_flag_small_cache: u32 = 0x02;
pub const caps_flag_avc420_enabled: u32 = 0x10; // v8.1
pub const caps_flag_avc_disabled: u32 = 0x20; // v10+
pub const caps_flag_avc_thinclient: u32 = 0x40;
pub const caps_flag_scaledmap_disable: u32 = 0x80; // v10.7

const known_versions = [_]u32{
    capversion_107, capversion_106, capversion_105, capversion_104, capversion_103,
    capversion_102, capversion_101, capversion_10,  capversion_81,  capversion_8,
};

pub const CapSet = struct { version: u32, flags: u32 };

/// Newest known version in a CAPS_ADVERTISE body; unknown sets may come first (3.2.5.19).
pub fn chooseCaps(body: []const u8) Error!?CapSet {
    var r = bytes.Reader.init(body);
    const n = try r.u16le();
    var best: ?CapSet = null;
    var best_rank: usize = known_versions.len;
    for (0..n) |_| {
        const version = try r.u32le();
        const len = try r.u32le();
        var d = try r.sub(len);
        const flags = if (d.remaining() >= 4) try d.u32le() else 0;
        const rank = std.mem.indexOfScalar(u32, &known_versions, version) orelse continue;
        if (rank < best_rank) {
            best_rank = rank;
            best = .{ .version = version, .flags = flags };
        }
    }
    return best;
}

/// Header + body builder: writes cmdId/flags/pduLength, patching the length.
pub const Pdu = struct {
    start: usize,

    pub fn begin(w: *bytes.Writer, cmd: CmdId) !Pdu {
        const start = w.len();
        try w.u16le(@backingInt(cmd));
        try w.u16le(0);
        try w.u32le(0);
        return .{ .start = start };
    }

    pub fn finish(p: Pdu, w: *bytes.Writer) void {
        w.patchU32le(p.start + 4, @intCast(w.len() - p.start));
    }
};

pub fn writeCapsConfirm(w: *bytes.Writer, cs: CapSet) !void {
    const p = try Pdu.begin(w, .caps_confirm);
    try w.u32le(cs.version);
    if (cs.version == capversion_101) {
        // RDPGFX_CAPSET_VERSION101 (2.2.3.4): 16 reserved zero bytes.
        try w.u32le(16);
        try w.zeros(16);
    } else {
        try w.u32le(4);
        try w.u32le(cs.flags);
    }
    p.finish(w);
}

pub const Monitor = struct { left: i32, top: i32, right: i32, bottom: i32, primary: bool };

/// RESET_GRAPHICS is always exactly 340 bytes (2.2.2.14).
pub fn writeResetGraphics(w: *bytes.Writer, width: u32, height: u32, monitors: []const Monitor) !void {
    std.debug.assert(monitors.len <= 16);
    const p = try Pdu.begin(w, .reset_graphics);
    try w.u32le(width);
    try w.u32le(height);
    try w.u32le(@intCast(monitors.len));
    for (monitors) |m| {
        try w.u32le(@bitCast(m.left));
        try w.u32le(@bitCast(m.top));
        try w.u32le(@bitCast(m.right));
        try w.u32le(@bitCast(m.bottom));
        try w.u32le(if (m.primary) 1 else 0);
    }
    try w.zeros(340 - (w.len() - p.start));
    p.finish(w);
}

pub fn writeCreateSurface(w: *bytes.Writer, surface_id: u16, width: u16, height: u16) !void {
    const p = try Pdu.begin(w, .create_surface);
    try w.u16le(surface_id);
    try w.u16le(width);
    try w.u16le(height);
    try w.byte(pixel_format_xrgb8888);
    p.finish(w);
}

pub fn writeDeleteSurface(w: *bytes.Writer, surface_id: u16) !void {
    const p = try Pdu.begin(w, .delete_surface);
    try w.u16le(surface_id);
    p.finish(w);
}

pub fn writeMapSurfaceToOutput(w: *bytes.Writer, surface_id: u16, x: u32, y: u32) !void {
    const p = try Pdu.begin(w, .map_surface_to_output);
    try w.u16le(surface_id);
    try w.u16le(0);
    try w.u32le(x);
    try w.u32le(y);
    p.finish(w);
}

pub fn writeStartFrame(w: *bytes.Writer, frame_id: u32, timestamp: u32) !void {
    const p = try Pdu.begin(w, .start_frame);
    try w.u32le(timestamp);
    try w.u32le(frame_id);
    p.finish(w);
}

pub fn writeEndFrame(w: *bytes.Writer, frame_id: u32) !void {
    const p = try Pdu.begin(w, .end_frame);
    try w.u32le(frame_id);
    p.finish(w);
}

pub const Rect16 = struct { left: u16, top: u16, right: u16, bottom: u16 }; // right/bottom exclusive

/// WIRE_TO_SURFACE_1 header; the caller appends exactly `data_len` bytes.
pub fn beginWireToSurface1(w: *bytes.Writer, surface_id: u16, codec: CodecId, rect: Rect16, data_len: usize) !Pdu {
    const p = try Pdu.begin(w, .wire_to_surface_1);
    try w.u16le(surface_id);
    try w.u16le(@backingInt(codec));
    try w.byte(pixel_format_xrgb8888);
    try w.u16le(rect.left);
    try w.u16le(rect.top);
    try w.u16le(rect.right);
    try w.u16le(rect.bottom);
    try w.u32le(@intCast(data_len));
    return p;
}

/// Timestamp field of START_FRAME (2.2.2.11): hh:mm:ss.ms packed.
pub fn frameTimestamp(ms_of_day: u32) u32 {
    const ms = ms_of_day % 1000;
    const s = ms_of_day / 1000 % 60;
    const m = ms_of_day / 60000 % 60;
    const h = ms_of_day / 3600000 % 24;
    return h << 22 | m << 16 | s << 10 | ms;
}

pub const ClientPdu = union(enum) {
    caps_advertise: []const u8, // body
    frame_acknowledge: struct { queue_depth: u32, frame_id: u32, total_decoded: u32 },
    cache_import_offer,
    qoe_frame_acknowledge: struct { frame_id: u32, timestamp: u32, time_diff_se: u16, time_diff_edr: u16 },
    other: u16,
};

/// Client messages are not segmented.
pub fn parseClientPdu(msg: []const u8) Error!ClientPdu {
    var r = bytes.Reader.init(msg);
    const cmd: CmdId = @fromBackingInt(@intCast(try r.u16le()));
    _ = try r.u16le(); // flags
    const len = try r.u32le();
    if (len < 8 or len > msg.len) return error.BadGfxPdu;
    var b = bytes.Reader.init(msg[8..len]);
    return switch (cmd) {
        .caps_advertise => .{ .caps_advertise = b.rest() },
        .frame_acknowledge => .{ .frame_acknowledge = .{
            .queue_depth = try b.u32le(),
            .frame_id = try b.u32le(),
            .total_decoded = try b.u32le(),
        } },
        .cache_import_offer => .cache_import_offer,
        .qoe_frame_acknowledge => .{ .qoe_frame_acknowledge = .{
            .frame_id = try b.u32le(),
            .timestamp = try b.u32le(),
            .time_diff_se = try b.u16le(),
            .time_diff_edr = try b.u16le(),
        } },
        else => .{ .other = @backingInt(cmd) },
    };
}

/// QueueDepth value meaning "client suspended frame acknowledgement".
pub const suspend_frame_acknowledgement: u32 = 0xFFFFFFFF;

pub fn writeCacheImportReply(w: *bytes.Writer) !void {
    const p = try Pdu.begin(w, .cache_import_reply);
    try w.u16le(0); // importedEntriesCount
    p.finish(w);
}

const segmented_single: u8 = 0xE0;
const segmented_multipart: u8 = 0xE1;
const packet_compr_type_rdp8: u8 = 0x04;
const max_segment: usize = 65535;

/// Wraps one or more RDPGFX PDUs as RDP_SEGMENTED_DATA with uncompressed RDP8 segments.
pub fn writeSegmented(w: *bytes.Writer, msg: []const u8) !void {
    if (msg.len + 1 <= max_segment) {
        try w.byte(segmented_single);
        try w.byte(packet_compr_type_rdp8);
        try w.bytes(msg);
        return;
    }
    const seg_payload = max_segment - 1;
    const count = (msg.len + seg_payload - 1) / seg_payload;
    try w.byte(segmented_multipart);
    try w.u16le(@intCast(count));
    try w.u32le(@intCast(msg.len));
    var off: usize = 0;
    while (off < msg.len) {
        const n = @min(seg_payload, msg.len - off);
        try w.u32le(@intCast(n + 1));
        try w.byte(packet_compr_type_rdp8);
        try w.bytes(msg[off .. off + n]);
        off += n;
    }
}

test "caps negotiation picks newest common version" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try w.u16le(3);
    inline for (.{ capversion_8, capversion_107, 0x000A0801 }) |v| {
        try w.u32le(v);
        try w.u32le(4);
        try w.u32le(caps_flag_small_cache);
    }
    const cs = (try chooseCaps(list.items)).?;
    try std.testing.expectEqual(capversion_107, cs.version);
    try std.testing.expectEqual(caps_flag_small_cache, cs.flags);
    try std.testing.expectError(error.EndOfBuffer, chooseCaps(list.items[0..10]));
}

test "reset graphics is 340 bytes" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeResetGraphics(&w, 1920, 1080, &.{.{ .left = 0, .top = 0, .right = 1919, .bottom = 1079, .primary = true }});
    try std.testing.expectEqual(@as(usize, 340), list.items.len);
    try std.testing.expectEqual(@as(u32, 340), std.mem.readInt(u32, list.items[4..8], .little));
}

test "segmented single and multipart" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeSegmented(&w, "abc");
    try std.testing.expectEqualSlices(u8, &bytes.hex("e0 04 61 62 63"), list.items);

    list.clearRetainingCapacity();
    const big = try std.testing.allocator.alloc(u8, 70000);
    defer std.testing.allocator.free(big);
    @memset(big, 0x5a);
    try writeSegmented(&w, big);
    var r = bytes.Reader.init(list.items);
    try std.testing.expectEqual(segmented_multipart, try r.byte());
    try std.testing.expectEqual(@as(u16, 2), try r.u16le());
    try std.testing.expectEqual(@as(u32, 70000), try r.u32le());
    var total: usize = 0;
    for (0..2) |_| {
        const sz = try r.u32le();
        try std.testing.expectEqual(packet_compr_type_rdp8, try r.byte());
        try r.skip(sz - 1);
        total += sz - 1;
    }
    try std.testing.expectEqual(@as(usize, 70000), total);
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "client frame acknowledge parse" {
    const msg = bytes.hex("0d 00 00 00 14 00 00 00 01 00 00 00 07 00 00 00 08 00 00 00");
    const fa = (try parseClientPdu(&msg)).frame_acknowledge;
    try std.testing.expectEqual(@as(u32, 7), fa.frame_id);
    try std.testing.expectError(error.BadGfxPdu, parseClientPdu(&bytes.hex("0d 00 00 00 ff 00 00 00")));
}

test "frame timestamp packing" {
    const t = frameTimestamp(((13 * 60 + 45) * 60 + 30) * 1000 + 250);
    try std.testing.expectEqual(@as(u32, 13), t >> 22);
    try std.testing.expectEqual(@as(u32, 45), (t >> 16) & 0x3F);
    try std.testing.expectEqual(@as(u32, 30), (t >> 10) & 0x3F);
    try std.testing.expectEqual(@as(u32, 250), t & 0x3FF);
}
