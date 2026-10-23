//! T.124 GCC Conference Create Request/Response and the RDP client/server
//! data blocks they carry (MS-RDPBCGR 2.2.1.3.x and 2.2.1.4.x).

const std = @import("std");
const disp = @import("disp.zig");
const bytes = @import("../core/bytes.zig");
const per = @import("per.zig");

pub const Error = error{ BadGcc, BadDataBlock, TooManyChannels, TooManyMonitors } || per.Error;

const t124_02_98_oid = [6]u8{ 0, 0, 20, 124, 0, 1 };
const h221_cs_key = "Duca";
const h221_sc_key = "McDn";

pub const cs_core: u16 = 0xC001;
pub const cs_security: u16 = 0xC002;
pub const cs_net: u16 = 0xC003;
pub const cs_cluster: u16 = 0xC004;
pub const cs_monitor: u16 = 0xC005;
pub const cs_mcs_msgchannel: u16 = 0xC006;
pub const cs_monitor_ex: u16 = 0xC008;
pub const cs_unused1: u16 = 0xC00C;
pub const cs_multitransport: u16 = 0xC00A;

pub const sc_core: u16 = 0x0C01;
pub const sc_security: u16 = 0x0C02;
pub const sc_net: u16 = 0x0C03;
pub const sc_mcs_msgchannel: u16 = 0x0C04;
pub const sc_multitransport: u16 = 0x0C08;

/// TS_UD_CS_CORE.earlyCapabilityFlags
pub const EarlyCaps = packed struct(u16) {
    support_errinfo_pdu: bool = false, // 0x0001
    want_32bpp_session: bool = false, // 0x0002
    support_statusinfo_pdu: bool = false, // 0x0004
    strong_asymmetric_keys: bool = false, // 0x0008
    relative_mouse_input: bool = false, // 0x0010
    valid_connection_type: bool = false, // 0x0020
    support_monitor_layout_pdu: bool = false, // 0x0040
    support_netchar_autodetect: bool = false, // 0x0080
    support_dynvc_gfx_protocol: bool = false, // 0x0100
    support_dynamic_time_zone: bool = false, // 0x0200
    support_heartbeat_pdu: bool = false, // 0x0400
    support_skip_channeljoin: bool = false, // 0x0800
    _pad: u4 = 0,
};

pub const max_channels = 31; // MS-RDPBCGR: at most 31 static channels
pub const max_monitors = 16;

pub const Channel = struct {
    name: [8]u8, // ANSI, NUL-padded
    options: u32,

    pub fn nameSlice(c: *const Channel) []const u8 {
        return std.mem.sliceTo(&c.name, 0);
    }
};

pub const Monitor = struct {
    left: i32,
    top: i32,
    right: i32, // inclusive
    bottom: i32, // inclusive
    primary: bool,
    // From TS_UD_CS_MONITOR_EX when present.
    physical_width_mm: u32 = 0,
    physical_height_mm: u32 = 0,
    orientation: u32 = 0,
    desktop_scale_factor: u32 = 0,
    device_scale_factor: u32 = 0,

    pub fn width(m: *const Monitor) u32 {
        return @intCast(m.right - m.left + 1);
    }
    pub fn height(m: *const Monitor) u32 {
        return @intCast(m.bottom - m.top + 1);
    }
};

pub const ClientData = struct {
    // TS_UD_CS_CORE
    version: u32 = 0,
    desktop_width: u16 = 0,
    desktop_height: u16 = 0,
    keyboard_layout: u32 = 0,
    client_build: u32 = 0,
    client_name: [16]u16 = @splat(0),
    keyboard_type: u32 = 0,
    keyboard_subtype: u32 = 0,
    keyboard_function_keys: u32 = 0,
    /// colorDepth and postBeta2ColorDepth (RNS_UD_COLOR_*, 0 when absent).
    color_depth: u16 = 0,
    post_beta2_color_depth: u16 = 0,
    high_color_depth: u16 = 0,
    supported_color_depths: u16 = 0,
    early_caps: EarlyCaps = .{},
    connection_type: u8 = 0,
    server_selected_protocol: u32 = 0,
    desktop_physical_width: u32 = 0,
    desktop_physical_height: u32 = 0,
    desktop_orientation: u16 = 0,
    desktop_scale_factor: u32 = 0,
    device_scale_factor: u32 = 0,
    encryption_methods: u32 = 0,
    channels: [max_channels]Channel = undefined,
    channel_count: usize = 0,
    cluster_flags: u32 = 0,
    monitors: [max_monitors]Monitor = undefined,
    monitor_count: usize = 0,
    has_msgchannel: bool = false,
    multitransport_flags: ?u32 = null,

    pub fn channelSlice(d: *const ClientData) []const Channel {
        return d.channels[0..d.channel_count];
    }

    /// Negotiated as a Windows server does: 32 bpp for a graphics pipeline client that supports it
    /// (Windows clients reject GFX below 32), else the request stepped down (MS-RDPBCGR 2.2.1.3.2).
    pub fn sessionColorDepth(d: *const ClientData) u16 {
        const s = d.supported_color_depths;
        if (s != 0) {
            if (d.early_caps.support_dynvc_gfx_protocol and s & 0x0008 != 0) return 32; // RNS_UD_32BPP_SUPPORT
            var want: u16 = switch (d.high_color_depth) {
                15, 16, 24, 32 => d.high_color_depth,
                else => 16,
            };
            if (want == 24 or d.early_caps.want_32bpp_session) want = 32;
            const steps = [_]struct { bpp: u16, bit: u16 }{
                .{ .bpp = 32, .bit = 0x0008 }, // RNS_UD_32BPP_SUPPORT
                .{ .bpp = 24, .bit = 0x0001 }, // RNS_UD_24BPP_SUPPORT
                .{ .bpp = 16, .bit = 0x0002 }, // RNS_UD_16BPP_SUPPORT
                .{ .bpp = 15, .bit = 0x0004 }, // RNS_UD_15BPP_SUPPORT
            };
            for (steps) |st| if (st.bpp <= want and s & st.bit != 0) return st.bpp;
            var i: usize = steps.len;
            while (i > 0) {
                i -= 1;
                if (s & steps[i].bit != 0) return steps[i].bpp;
            }
        }
        const requested: u16 = if (d.high_color_depth != 0) blk: {
            if (d.early_caps.want_32bpp_session) break :blk 32;
            break :blk switch (d.high_color_depth) {
                15, 16, 24 => d.high_color_depth,
                else => 8,
            };
        } else switch (if (d.post_beta2_color_depth != 0) d.post_beta2_color_depth else d.color_depth) {
            0xCA02 => 15, // RNS_UD_COLOR_16BPP_555
            0xCA03 => 16, // RNS_UD_COLOR_16BPP_565
            0xCA04 => 24, // RNS_UD_COLOR_24BPP
            else => 8, // RNS_UD_COLOR_4BPP / _8BPP
        };
        return if (requested < 15) 16 else requested;
    }
    /// Desktop size clamped to 8192 each way (MS-RDPBCGR 2.2.1.3.2).
    pub fn desktopSize(d: *const ClientData) struct { width: u16, height: u16 } {
        return .{ .width = @min(d.desktop_width, 8192), .height = @min(d.desktop_height, 8192) };
    }

    /// Usable desktopScaleFactor, or 0 when it must be ignored (MS-RDPBCGR 2.2.1.3.2).
    pub fn scalePercent(d: *const ClientData) u32 {
        return disp.effectiveScale(d.desktop_scale_factor, d.device_scale_factor);
    }

    pub fn monitorSlice(d: *const ClientData) []const Monitor {
        return d.monitors[0..d.monitor_count];
    }
};

/// Largest request accepted with Extended Client Data Blocks (MS-RDPBCGR 3.3.5.3.3).
pub const max_request_len = 4096;

pub fn parseConferenceCreateRequest(user_data: []const u8) Error!ClientData {
    if (user_data.len > max_request_len) return error.BadGcc;
    var r = bytes.Reader.init(user_data);
    // ConnectData
    if (try per.readChoice(&r) != 0) return error.BadGcc;
    try per.readObjectIdentifier(&r, t124_02_98_oid);
    _ = try per.readLength(&r); // connectPDU length (not trusted)
    // ConnectGCCPDU: conferenceCreateRequest
    if (try per.readChoice(&r) != 0) return error.BadGcc;
    if (try per.readSelection(&r) != 0x08) return error.BadGcc; // userData present
    try per.readNumericString(&r, 1); // conferenceName
    try per.readPadding(&r, 1);
    if (try per.readNumberOfSets(&r) != 1) return error.BadGcc;
    if (try per.readChoice(&r) != 0xC0) return error.BadGcc; // h221NonStandard
    const key = try per.readOctetString(&r, 4);
    if (!std.mem.eql(u8, key, h221_cs_key)) return error.BadGcc;
    const blocks_len = try per.readLength(&r);
    const blocks = try r.bytes(blocks_len);
    if (r.remaining() != 0) return error.BadGcc; // 3.3.5.3.3: lengths consistent
    return parseClientDataBlocks(blocks);
}

pub fn parseClientDataBlocks(data: []const u8) Error!ClientData {
    var d = ClientData{};
    var monitors_ex: ?bytes.Reader = null;
    var r = bytes.Reader.init(data);
    while (r.remaining() >= 4) {
        const t = try r.u16le();
        const len = try r.u16le();
        if (len < 4) return error.BadDataBlock;
        var b = try r.sub(len - 4);
        switch (t) {
            cs_core => try parseCore(&b, &d),
            cs_security => {
                d.encryption_methods = try b.u32le();
            },
            cs_net => {
                const count = try b.u32le();
                if (count > max_channels) return error.TooManyChannels;
                for (0..count) |i| {
                    d.channels[i].name = (try b.bytes(8))[0..8].*;
                    d.channels[i].name[7] = 0; // force termination
                    d.channels[i].options = try b.u32le();
                }
                d.channel_count = count;
            },
            cs_cluster => d.cluster_flags = try b.u32le(),
            cs_monitor => {
                _ = try b.u32le(); // flags (unused)
                const count = try b.u32le();
                if (count == 0 or count > max_monitors) return error.TooManyMonitors;
                for (0..count) |i| {
                    d.monitors[i] = .{
                        .left = @bitCast(try b.u32le()),
                        .top = @bitCast(try b.u32le()),
                        .right = @bitCast(try b.u32le()),
                        .bottom = @bitCast(try b.u32le()),
                        .primary = (try b.u32le()) & 0x1 != 0,
                    };
                    const m = &d.monitors[i];
                    if (m.right < m.left or m.bottom < m.top) return error.BadDataBlock;
                }
                // MS-RDPBCGR 2.2.1.3.6: the monitor union is 200..32766 each way.
                var x0: i64 = std.math.maxInt(i64);
                var y0: i64 = std.math.maxInt(i64);
                var x1: i64 = std.math.minInt(i64);
                var y1: i64 = std.math.minInt(i64);
                for (d.monitors[0..count]) |m| {
                    x0 = @min(x0, m.left);
                    y0 = @min(y0, m.top);
                    x1 = @max(x1, m.right);
                    y1 = @max(y1, m.bottom);
                }
                const uw = x1 - x0 + 1;
                const uh = y1 - y0 + 1;
                if (uw < 200 or uh < 200 or uw > 32766 or uh > 32766) return error.BadDataBlock;
                d.monitor_count = count;
            },
            cs_mcs_msgchannel => {
                _ = try b.u32le();
                d.has_msgchannel = true;
            },
            cs_monitor_ex => monitors_ex = b,
            cs_multitransport => d.multitransport_flags = try b.u32le(),
            else => {}, // unknown blocks are skipped, as Windows does
        }
    }
    if (r.remaining() != 0) return error.BadDataBlock;

    // TS_UD_CS_MONITOR_EX entries pair up with TS_UD_CS_MONITOR by index.
    if (monitors_ex) |*b| {
        _ = try b.u32le(); // flags
        const attr_size = try b.u32le();
        const count = try b.u32le();
        // MS-RDPBCGR 2.2.1.3.10: monitorAttributeSize "MUST be set to 20".
        if (attr_size != 20) return error.BadDataBlock;
        if (count != d.monitor_count) return error.BadDataBlock;
        for (0..count) |i| {
            var e = try b.sub(attr_size);
            d.monitors[i].physical_width_mm = try e.u32le();
            d.monitors[i].physical_height_mm = try e.u32le();
            d.monitors[i].orientation = try e.u32le();
            d.monitors[i].desktop_scale_factor = try e.u32le();
            d.monitors[i].device_scale_factor = try e.u32le();
        }
    }
    if (d.desktop_width == 0 or d.desktop_height == 0) return error.BadDataBlock;
    return d;
}

fn parseCore(b: *bytes.Reader, d: *ClientData) Error!void {
    d.version = try b.u32le();
    d.desktop_width = try b.u16le();
    d.desktop_height = try b.u16le();
    const color_depth = try b.u16le(); // legacy
    d.color_depth = color_depth;
    _ = try b.u16le(); // SASSequence
    d.keyboard_layout = try b.u32le();
    d.client_build = try b.u32le();
    const name = try b.bytes(32);
    for (0..16) |i| d.client_name[i] = @as(u16, name[2 * i]) | @as(u16, name[2 * i + 1]) << 8;
    d.client_name[15] = 0;
    d.keyboard_type = try b.u32le();
    d.keyboard_subtype = try b.u32le();
    d.keyboard_function_keys = try b.u32le();
    try b.skip(64); // imeFileName
    // The rest is optional; an invalid depth with no later depth field is fatal (MS-RDPBCGR 3.3.5.3.3).
    if (b.remaining() < 2) {
        if (color_depth != 0xCA00 and color_depth != 0xCA01) return error.BadDataBlock;
        return;
    }
    const post_beta2_color_depth = try b.u16le();
    d.post_beta2_color_depth = post_beta2_color_depth;
    if (b.remaining() < 2 + 4 + 2 and (post_beta2_color_depth < 0xCA00 or post_beta2_color_depth > 0xCA04))
        return error.BadDataBlock; // highColorDepth absent
    if (b.remaining() < 2) return;
    _ = try b.u16le(); // clientProductId
    if (b.remaining() < 4) return;
    _ = try b.u32le(); // serialNumber
    if (b.remaining() < 2) return;
    d.high_color_depth = try b.u16le();
    if (b.remaining() < 2) return;
    d.supported_color_depths = try b.u16le();
    if (b.remaining() < 2) return;
    d.early_caps = @bitCast(try b.u16le());
    if (b.remaining() < 64) return;
    try b.skip(64); // clientDigProductId
    if (b.remaining() < 1) return;
    d.connection_type = try b.byte();
    if (b.remaining() < 1) return;
    try b.skip(1); // pad1octet
    if (b.remaining() < 4) return;
    d.server_selected_protocol = try b.u32le();
    if (b.remaining() < 4) return;
    d.desktop_physical_width = try b.u32le();
    if (b.remaining() < 4) return;
    d.desktop_physical_height = try b.u32le();
    if (b.remaining() < 2) return;
    d.desktop_orientation = try b.u16le();
    if (b.remaining() < 4) return;
    d.desktop_scale_factor = try b.u32le();
    if (b.remaining() < 4) return;
    d.device_scale_factor = try b.u32le();
}

/// RDP version advertised in TS_UD_SC_CORE.
pub const rdp_version_10_12: u32 = 0x00080011;
pub const rdp_version_5_plus: u32 = 0x00080004;

pub const ServerData = struct {
    version: u32 = rdp_version_10_12,
    client_requested_protocols: u32,
    early_caps: u32 = 0,
    io_channel: u16,
    channel_ids: []const u16,
    msg_channel: ?u16 = null,
    multitransport_flags: ?u32 = null,
};

pub fn writeConferenceCreateResponse(w: *bytes.Writer, sd: ServerData) !void {
    var blocks: std.ArrayList(u8) = .empty;
    defer blocks.deinit(w.gpa);
    var bw = bytes.Writer.init(&blocks, w.gpa);

    try bw.u16le(sc_core);
    try bw.u16le(16);
    try bw.u32le(sd.version);
    try bw.u32le(sd.client_requested_protocols);
    try bw.u32le(sd.early_caps);

    const padded = sd.channel_ids.len % 2 == 1;
    try bw.u16le(sc_net);
    try bw.u16le(@intCast(8 + 2 * sd.channel_ids.len + @as(usize, if (padded) 2 else 0)));
    try bw.u16le(sd.io_channel);
    try bw.u16le(@intCast(sd.channel_ids.len));
    for (sd.channel_ids) |id| try bw.u16le(id);
    if (padded) try bw.u16le(0);

    // SC_SECURITY: TLS/CredSSP carry the encryption, so no RDP-level crypto.
    try bw.u16le(sc_security);
    try bw.u16le(12);
    try bw.u32le(0); // ENCRYPTION_METHOD_NONE
    try bw.u32le(0); // ENCRYPTION_LEVEL_NONE

    if (sd.msg_channel) |id| {
        try bw.u16le(sc_mcs_msgchannel);
        try bw.u16le(6);
        try bw.u16le(id);
    }
    if (sd.multitransport_flags) |f| {
        try bw.u16le(sc_multitransport);
        try bw.u16le(8);
        try bw.u32le(f);
    }

    try w.byte(0); // choice
    try per.writeObjectIdentifier(w, t124_02_98_oid);
    // connectPDU length is ignored by clients; Windows always writes 0x2A (MS-RDPBCGR 4.1.4).
    try per.writeLength(w, 0x2A);
    try w.byte(0x14);
    try per.writeInteger16(w, 0x79F3, 1001); // nodeID
    try per.writeInteger(w, 1); // tag
    try w.byte(0); // result: success
    try w.byte(1); // number of UserData sets
    try w.byte(0xC0); // h221NonStandard
    try per.writeOctetString(w, h221_sc_key, 4);
    try per.writeOctetString(w, blocks.items, 0);
}

// MS-RDPBCGR 4.1.3 Client MCS Connect Initial; GCC userData starts at 0x6d.
const spec_ci_frame = @embedFile("../testdata/bcgr-4.1.3-mcs-ci.bin");
const spec_gcc_request = spec_ci_frame[0x6d..];

test "parse spec conference create request" {
    try std.testing.expectEqual(@as(usize, 0x133), spec_gcc_request.len);
    const d = try parseConferenceCreateRequest(spec_gcc_request);
    try std.testing.expectEqual(@as(u32, 0x00080004), d.version);
    try std.testing.expectEqual(@as(u16, 1280), d.desktop_width);
    try std.testing.expectEqual(@as(u16, 1024), d.desktop_height);
    try std.testing.expectEqual(@as(u32, 0x409), d.keyboard_layout);
    try std.testing.expectEqual(@as(u32, 3790), d.client_build);
    try std.testing.expectEqual(@as(u16, 'E'), d.client_name[0]);
    try std.testing.expectEqual(@as(u16, '2'), d.client_name[10]);
    try std.testing.expectEqual(@as(u32, 4), d.keyboard_type);
    try std.testing.expectEqual(@as(u32, 12), d.keyboard_function_keys);
    try std.testing.expectEqual(@as(u16, 0x18), d.high_color_depth);
    try std.testing.expectEqual(@as(u16, 7), d.supported_color_depths);
    try std.testing.expect(d.early_caps.support_errinfo_pdu);
    try std.testing.expect(!d.early_caps.support_dynvc_gfx_protocol);
    try std.testing.expectEqual(@as(u32, 0), d.server_selected_protocol);
    try std.testing.expectEqual(@as(u32, 0x1b), d.encryption_methods);
    try std.testing.expectEqual(@as(usize, 3), d.channel_count);
    try std.testing.expectEqualStrings("rdpdr", d.channels[0].nameSlice());
    try std.testing.expectEqualStrings("cliprdr", d.channels[1].nameSlice());
    try std.testing.expectEqualStrings("rdpsnd", d.channels[2].nameSlice());
    try std.testing.expectEqual(@as(u32, 0x80800000), d.channels[0].options);
    try std.testing.expectEqual(@as(u32, 0xc0a00000), d.channels[1].options);
    try std.testing.expectEqual(@as(u32, 0x0d), d.cluster_flags);
    try std.testing.expectEqual(@as(usize, 0), d.monitor_count);
}

test "reject malformed client data" {
    try std.testing.expectError(error.EndOfBuffer, parseConferenceCreateRequest(spec_gcc_request[0 .. spec_gcc_request.len - 5]));
    for (0..spec_gcc_request.len) |n| {
        _ = parseConferenceCreateRequest(spec_gcc_request[0..n]) catch continue;
        return error.TestUnexpectedSuccess;
    }
    const too_many = bytes.hex("03 c0 08 00 ff 00 00 00");
    try std.testing.expectError(error.TooManyChannels, parseClientDataBlocks(&too_many));
    const tiny = bytes.hex("01 c0 02 00");
    try std.testing.expectError(error.BadDataBlock, parseClientDataBlocks(&tiny));
}

test "server conference create response layout" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeConferenceCreateResponse(&w, .{
        .version = rdp_version_5_plus,
        .client_requested_protocols = 0,
        .io_channel = 1003,
        .channel_ids = &.{ 1004, 1005, 1006 },
    });
    // Header matches MS-RDPBCGR 4.1.4 byte for byte up to the blocks length.
    try std.testing.expectEqualSlices(u8, &bytes.hex("00 05 00 14 7c 00 01 2a 14 76 0a 01 01 00 01 c0 00 4d 63 44 6e 2c"), list.items[0..22]);
    // SC_CORE, SC_NET (odd count -> padded), SC_SECURITY.
    try std.testing.expectEqualSlices(u8, &bytes.hex(
        \\01 0c 10 00 04 00 08 00 00 00 00 00 00 00 00 00
        \\03 0c 10 00 eb 03 03 00 ec 03 ed 03 ee 03 00 00
        \\02 0c 0c 00 00 00 00 00 00 00 00 00
    ), list.items[22..]);
}

test "session color depth: 32 with the graphics pipeline, else the request stepped down" {
    var d: ClientData = .{};
    d.supported_color_depths = 0x000F;
    d.early_caps.support_dynvc_gfx_protocol = true;
    for ([_]u16{ 24, 16, 15, 32 }) |hcd| {
        d.high_color_depth = hcd;
        try std.testing.expectEqual(@as(u16, 32), d.sessionColorDepth());
    }
    // The pipeline without 32 bpp support: the best at or below the request.
    d.supported_color_depths = 0x0001 | 0x0002;
    d.high_color_depth = 24;
    try std.testing.expectEqual(@as(u16, 24), d.sessionColorDepth());
    // Without the pipeline: 24 promoted to 32, 16 stays 16, WANT_32BPP gives 32.
    d.early_caps.support_dynvc_gfx_protocol = false;
    d.supported_color_depths = 0x000F;
    d.high_color_depth = 24;
    try std.testing.expectEqual(@as(u16, 32), d.sessionColorDepth());
    d.high_color_depth = 16;
    try std.testing.expectEqual(@as(u16, 16), d.sessionColorDepth());
    d.early_caps.want_32bpp_session = true;
    try std.testing.expectEqual(@as(u16, 32), d.sessionColorDepth());
    d.early_caps.want_32bpp_session = false;
    d.supported_color_depths = 0x0001 | 0x0002 | 0x0004;
    d.high_color_depth = 24;
    try std.testing.expectEqual(@as(u16, 24), d.sessionColorDepth());
    d.supported_color_depths = 0x0001 | 0x0002;
    d.high_color_depth = 15;
    try std.testing.expectEqual(@as(u16, 16), d.sessionColorDepth());
}
