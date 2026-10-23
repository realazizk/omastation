//! Capability sets of Demand Active / Confirm Active (MS-RDPBCGR 2.2.7): what Windows
//! advertises (MS-RDPBCGR 4.1.12) plus the sets current clients expect.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const rfx = @import("../codec/rfx.zig");

pub const Error = error{BadCapability} || bytes.Error;

pub const Type = enum(u16) {
    general = 1,
    bitmap = 2,
    order = 3,
    bitmapcache = 4,
    control = 5,
    activation = 7,
    pointer = 8,
    share = 9,
    colorcache = 10,
    sound = 12,
    input = 13,
    font = 14,
    brush = 15,
    glyphcache = 16,
    offscreencache = 17,
    bitmapcache_hostsupport = 18,
    bitmapcache_rev2 = 19,
    virtualchannel = 20,
    drawninegridcache = 21,
    drawgdiplus = 22,
    rail = 23,
    window = 24,
    compdesk = 25,
    multifragmentupdate = 26,
    large_pointer = 27,
    surface_commands = 28,
    bitmap_codecs = 29,
    frame_acknowledge = 30,
    _,
};

/// TS_GENERAL_CAPABILITYSET.extraFlags
pub const extra_fastpath_output_supported: u16 = 0x0001;
pub const extra_long_credentials_supported: u16 = 0x0004;
pub const extra_autoreconnect_supported: u16 = 0x0008;
pub const extra_enc_salted_checksum: u16 = 0x0010;
pub const extra_no_bitmap_compression_hdr: u16 = 0x0400;

/// TS_INPUT_CAPABILITYSET.inputFlags
pub const input_scancodes: u16 = 0x0001;
pub const input_mousex: u16 = 0x0004;
pub const input_fastpath_input: u16 = 0x0008;
pub const input_unicode: u16 = 0x0010;
pub const input_fastpath_input2: u16 = 0x0020;
pub const input_mouse_relative: u16 = 0x0080;
pub const input_mouse_hwheel: u16 = 0x0100;
pub const input_qoe_timestamps: u16 = 0x0200;

/// TS_SURFCMDS_CAPABILITYSET.cmdFlags
pub const surfcmds_set_surface_bits: u32 = 0x02;
pub const surfcmds_frame_marker: u32 = 0x10;
pub const surfcmds_stream_surface_bits: u32 = 0x40;

pub const ServerCapsOptions = struct {
    desktop_width: u16,
    desktop_height: u16,
    /// TS_SHARE_CAPABILITYSET.nodeID: the server MCS user channel.
    node_id: u16 = 1002,
    multifragment_max_request_size: u32 = 0x3F0000,
    /// preferredBitsPerPixel (MS-RDPBCGR 2.2.7.1.2).
    color_depth: u16 = 32,
    /// VCCAPS_NO_COMPR, or VCCAPS_COMPR_CS_8K to accept compressed client channel data (2.2.7.1.10).
    vc_flags: u32 = 0,
    /// Codecs offered for surface bits (MS-RDPBCGR 2.2.7.2.10); null: not sent.
    bitmap_codecs: ?rfx.ServerCodecs = null,
    /// maxUnacknowledgedFrameCount (MS-RDPRFX 2.2.1.3); null: not sent.
    frame_acknowledge: ?u32 = null,
    /// RemoteApp sets (MS-RDPERP 2.2.1.1.1, 2.2.1.1.2), for a client that asked for RAIL.
    rail: ?RailCaps = null,
};

/// MS-RDPERP 2.2.1.1.1 RailSupportLevel and 2.2.1.1.2 Window List fields.
pub const RailCaps = struct {
    rail_support_level: u32,
    wnd_support_level: u32,
    num_icon_caches: u8,
    num_icon_cache_entries: u16,
};

fn capHeader(w: *bytes.Writer, t: Type, len: u16) !void {
    try w.u16le(@backingInt(t));
    try w.u16le(len);
}

/// Returns the number of sets written.
pub fn writeServerCaps(w: *bytes.Writer, o: ServerCapsOptions) !u16 {
    var n: u16 = 0;

    try capHeader(w, .share, 8);
    try w.u16le(o.node_id);
    try w.u16le(0);
    n += 1;

    try capHeader(w, .general, 24);
    try w.u16le(1); // OSMAJORTYPE_WINDOWS
    try w.u16le(3); // OSMINORTYPE_WINDOWS_NT
    try w.u16le(0x0200); // TS_CAPS_PROTOCOLVERSION
    try w.u16le(0);
    try w.u16le(0); // compressionTypes
    try w.u16le(extra_fastpath_output_supported | extra_no_bitmap_compression_hdr |
        extra_long_credentials_supported | extra_autoreconnect_supported | extra_enc_salted_checksum);
    try w.u16le(0); // updateCapabilityFlag
    try w.u16le(0); // remoteUnshareFlag
    try w.u16le(0); // compressionLevel
    try w.byte(1); // refreshRectSupport
    try w.byte(1); // suppressOutputSupport
    n += 1;

    try capHeader(w, .virtualchannel, 8);
    try w.u32le(o.vc_flags);
    n += 1;

    try capHeader(w, .font, 4);
    n += 1;

    try capHeader(w, .bitmap, 28);
    try w.u16le(o.color_depth); // preferredBitsPerPixel: "the color depth of the session"
    try w.u16le(1); // receive1BitPerPixel
    try w.u16le(1); // receive4BitsPerPixel
    try w.u16le(1); // receive8BitsPerPixel
    try w.u16le(o.desktop_width);
    try w.u16le(o.desktop_height);
    try w.u16le(0);
    try w.u16le(1); // desktopResizeFlag
    try w.u16le(1); // bitmapCompressionFlag
    try w.byte(0); // highColorFlags
    try w.byte(0); // drawingFlags
    try w.u16le(1); // multipleRectangleSupport
    try w.u16le(0);
    n += 1;

    // Order caps: no drawing orders are sent, but the set must be present.
    try capHeader(w, .order, 88);
    try w.zeros(16); // terminalDescriptor
    try w.u32le(0x000F4240);
    try w.u16le(1); // desktopSaveXGranularity
    try w.u16le(20); // desktopSaveYGranularity
    try w.u16le(0);
    try w.u16le(1); // maximumOrderLevel
    try w.u16le(0); // numberFonts
    try w.u16le(0x0022); // NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT
    try w.zeros(32); // orderSupport: none
    try w.u16le(0); // textFlags
    try w.u16le(0); // orderSupportExFlags
    try w.u32le(0x000F4240);
    try w.u32le(0x000F4240); // desktopSaveSize
    try w.u16le(1);
    try w.u16le(0);
    try w.u16le(0); // textANSICodePage
    try w.u16le(0);
    n += 1;

    try capHeader(w, .pointer, 10);
    try w.u16le(1); // colorPointerFlag
    try w.u16le(25); // colorPointerCacheSize
    try w.u16le(25); // pointerCacheSize
    n += 1;

    try capHeader(w, .input, 88);
    try w.u16le(input_scancodes | input_mousex | input_unicode | input_fastpath_input2 |
        input_mouse_relative | input_mouse_hwheel);
    try w.u16le(0);
    try w.zeros(16); // keyboardLayout/Type/SubType/FunctionKey: unused by the server
    try w.zeros(64); // imeFileName
    n += 1;

    try capHeader(w, .multifragmentupdate, 8);
    try w.u32le(o.multifragment_max_request_size);
    n += 1;

    try capHeader(w, .large_pointer, 6);
    try w.u16le(0x0001 | 0x0002); // 96x96 and 384x384
    n += 1;

    try capHeader(w, .surface_commands, 12);
    try w.u32le(surfcmds_set_surface_bits | surfcmds_frame_marker | surfcmds_stream_surface_bits);
    try w.u32le(0);
    n += 1;

    if (o.bitmap_codecs) |codecs| {
        rfx.writeServerBitmapCodecsCapset(w, codecs) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.BadCapability,
        };
        n += 1;
    }
    if (o.frame_acknowledge) |max| {
        rfx.writeFrameAckCapset(w, max) catch return error.OutOfMemory;
        n += 1;
    }
    if (o.rail) |r| {
        try capHeader(w, .rail, 8);
        try w.u32le(r.rail_support_level);
        try capHeader(w, .window, 11);
        try w.u32le(r.wnd_support_level);
        try w.byte(r.num_icon_caches);
        try w.u16le(r.num_icon_cache_entries);
        n += 2;
    }

    return n;
}

pub const ClientCaps = struct {
    /// Client platform (osMajorType, e.g. OSMAJORTYPE_OSX 6 for a Mac).
    os_major_type: u16 = 0,
    os_minor_type: u16 = 0,
    general_extra_flags: u16 = 0,
    refresh_rect: bool = false,
    suppress_output: bool = false,
    bpp: u16 = 0,
    desktop_width: u16 = 0,
    desktop_height: u16 = 0,
    desktop_resize: bool = false,
    input_flags: u16 = 0,
    color_pointer_cache_size: u16 = 0,
    pointer_cache_size: u16 = 0,
    multifragment_max_request_size: u32 = 0,
    large_pointer_flags: u16 = 0,
    surface_commands: u32 = 0,
    frame_acknowledge: ?u32 = null,
    vc_flags: u32 = 0,
    vc_chunk_size: u32 = 1600,
    bitmap_codecs: []const u8 = &.{},
    rail_support_level: ?u32 = null,
    window_list: ?struct { wnd_support_level: u32, num_icon_caches: u8, num_icon_cache_entries: u16 } = null,
    /// Bit n set when capability set type n was present.
    seen: u32 = 0,

    pub fn has(c: *const ClientCaps, t: Type) bool {
        const v = @backingInt(t);
        return v < 32 and c.seen & (@as(u32, 1) << @intCast(v)) != 0;
    }

    pub fn fastpathOutput(c: *const ClientCaps) bool {
        return c.general_extra_flags & extra_fastpath_output_supported != 0;
    }
};

pub fn parseClientCaps(data: []const u8, count: u16) Error!ClientCaps {
    var c = ClientCaps{};
    var r = bytes.Reader.init(data);
    for (0..count) |_| {
        const t: Type = @fromBackingInt(@intCast(try r.u16le()));
        const len = try r.u16le();
        if (len < 4) return error.BadCapability;
        var b = try r.sub(len - 4);
        if (@backingInt(t) < 32) c.seen |= @as(u32, 1) << @intCast(@backingInt(t));
        switch (t) {
            .general => {
                c.os_major_type = try b.u16le();
                c.os_minor_type = try b.u16le();
                try b.skip(6);
                c.general_extra_flags = try b.u16le();
                try b.skip(6);
                c.refresh_rect = try b.byte() != 0;
                c.suppress_output = try b.byte() != 0;
            },
            .bitmap => {
                c.bpp = try b.u16le();
                try b.skip(6);
                c.desktop_width = try b.u16le();
                c.desktop_height = try b.u16le();
                try b.skip(2);
                c.desktop_resize = try b.u16le() != 0;
            },
            .input => c.input_flags = try b.u16le(),
            .pointer => {
                _ = try b.u16le(); // colorPointerFlag
                c.color_pointer_cache_size = try b.u16le();
                // pointerCacheSize is optional (older clients send 8 bytes).
                if (b.remaining() >= 2) c.pointer_cache_size = try b.u16le();
            },
            .virtualchannel => {
                c.vc_flags = try b.u32le();
                if (b.remaining() >= 4) c.vc_chunk_size = try b.u32le();
            },
            .multifragmentupdate => c.multifragment_max_request_size = try b.u32le(),
            .large_pointer => c.large_pointer_flags = try b.u16le(),
            .surface_commands => c.surface_commands = try b.u32le(),
            .frame_acknowledge => c.frame_acknowledge = try b.u32le(),
            .bitmap_codecs => c.bitmap_codecs = b.rest(),
            .rail => c.rail_support_level = try b.u32le(),
            .window => {
                const level = try b.u32le();
                const n = try b.byte();
                c.window_list = .{ .wnd_support_level = level, .num_icon_caches = n, .num_icon_cache_entries = try b.u16le() };
            },
            else => {},
        }
    }
    return c;
}

test "server caps are well formed and parse back" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    const n = try writeServerCaps(&w, .{ .desktop_width = 1920, .desktop_height = 1080 });
    try std.testing.expectEqual(@as(u16, 11), n);

    var r = bytes.Reader.init(list.items);
    for (0..n) |_| {
        _ = try r.u16le();
        const len = try r.u16le();
        try r.skip(len - 4);
    }
    try std.testing.expectEqual(@as(usize, 0), r.remaining());

    const c = try parseClientCaps(list.items, n);
    try std.testing.expectEqual(@as(u16, 1920), c.desktop_width);
    try std.testing.expectEqual(@as(u16, 1080), c.desktop_height);
    try std.testing.expect(c.fastpathOutput());
    try std.testing.expect(c.refresh_rect and c.suppress_output);
    try std.testing.expectEqual(@as(u16, 25), c.pointer_cache_size);
    try std.testing.expectEqual(@as(u32, 0x3F0000), c.multifragment_max_request_size);
}

test "server Bitmap Codecs and Frame Acknowledge sets when asked for (MS-RDPBCGR 2.2.7.2.10, MS-RDPRFX 2.2.1.3)" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    const n = try writeServerCaps(&w, .{ .desktop_width = 800, .desktop_height = 600, .bitmap_codecs = .{}, .frame_acknowledge = 16 });
    try std.testing.expectEqual(@as(u16, 13), n);
    const c = try parseClientCaps(list.items, n);
    try std.testing.expect(c.has(.bitmap_codecs) and c.has(.frame_acknowledge));
    try std.testing.expectEqual(@as(?u32, 16), c.frame_acknowledge);
    var codecs: [4]rfx.BitmapCodec = undefined;
    const got = try rfx.parseBitmapCodecs(c.bitmap_codecs, &codecs);
    try std.testing.expectEqual(@as(usize, 2), got.len);
    try std.testing.expectEqualSlices(u8, &rfx.guid_remotefx, &got[0].guid);
    try std.testing.expectEqualSlices(u8, &rfx.guid_nscodec, &got[1].guid);
    try std.testing.expectEqual(@as(u8, 1), got[1].id); // NSCodec's ID is always 1
}

test "client caps parser rejects bad lengths" {
    try std.testing.expectError(error.BadCapability, parseClientCaps(&bytes.hex("01 00 02 00"), 1));
    try std.testing.expectError(error.EndOfBuffer, parseClientCaps(&bytes.hex("01 00 18 00 00"), 1));
    try std.testing.expectError(error.EndOfBuffer, parseClientCaps(&bytes.hex("02 00 06 00 20 00"), 1));
}
