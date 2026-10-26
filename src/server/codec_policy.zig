//! The codec policy: which codecs a connection's graphics use, decided per
//! client from what it negotiated and from the server's options.
//!
//! RDPGFX clients, by confirmed capability set (MS-RDPEGFX 2.2.3; all decode planar and ClearCodec, 1.7):
//!
//!   confirmed caps                          motion (>= 10% of the screen)        lossless
//!   10.x asking for AVC444 (10.1, or        AVC444v2 > AVC420 > progressive* >   ClearCodec where
//!     AVC_THINCLIENT: FreeRDP /gfx:AVC444     planar                             it pays off, else
//!     with thin client), or --codecs avc444                                      planar
//!   10.x, AVC not disabled (Windows and     AVC420 > progressive* > planar          "
//!     macOS clients)
//!   10.x with AVC_DISABLED (FreeRDP /gfx)   progressive* > planar                   "
//!   8.1 with AVC420_ENABLED                 AVC420 > progressive* > planar          "
//!     (FreeRDP /gfx:AVC420)
//!   8.0 / 8.1 with THINCLIENT               [AVC420 >] RemoteFX (CAVIDEO)* >        "
//!                                             planar
//!   8.0 / 8.1                               progressive* > planar                   "
//!
//! AVC444v2 only when the client asks (10.1, or AVC_THINCLIENT in 10.x) or with --codecs avc444 / h264,
//! as the Windows server does: Windows clients that do not ask fail to decode it.
//!
//! Clients without RDPGFX (MS-RDPBCGR 2.2.9.1), by colour depth and Bitmap Codecs (2.2.7.2.10, 2.2.7.2.9):
//!
//!   32 bpp, RemoteFX + Stream Surface Bits  RemoteFX surface bits*      planar bitmaps (RDP 6.0)
//!   32 bpp, NSCodec + Set Surface Bits      NSCodec surface bits*       planar bitmaps
//!   32 bpp, no codec                        -                           planar bitmaps
//!   15/16/24 bpp                            -                           interleaved RLE bitmaps
//!
//! *: CPU lossy codecs take motion only on a slow or distant link (adapt.zig) or when forced
//! (Options.lossy_motion). Lossy output is re-sent losslessly once the screen is quiet.

const std = @import("std");
const gfx = @import("../proto/gfx.zig");
const caps = @import("../proto/caps.zig");
const rfx = @import("../codec/rfx.zig");
const nsc = @import("../codec/nsc.zig");
const bulk_codec = @import("../codec/bulk.zig");
const progressive = @import("../codec/progressive.zig");
const avc444 = @import("../codec/avc444.zig");

pub const LossyMotion = enum {
    /// When the link is slow or distant (adapt.zig).
    auto,
    always,
    never,
};

pub const Options = struct {
    /// Off (`--no-gfx`): every client gets bitmap updates and surface commands instead.
    rdpgfx: bool = true,
    avc444: bool = true,
    /// AVC444 for every 10.x client that takes AVC, like Windows' AVC444ModePreferred policy.
    avc444_preferred: bool = false,
    avc420: bool = true,
    progressive: bool = true,
    remotefx: bool = true,
    nscodec: bool = true,
    clearcodec: bool = true,
    lossy_motion: LossyMotion = .auto,
    /// Highest bulk compression type (MS-RDPBCGR 3.1.8), capped by the client's; null: none.
    bulk: ?bulk_codec.Type = .xcrush,
    /// DRM render node for H.264 (`--gpu`); null: the first whose driver encodes H.264.
    vaapi_device: ?[:0]const u8 = null,

    /// Deterministic pipelines for tests that model planar frames.
    pub const planar_avc420: Options = .{ .avc444 = false, .progressive = false, .remotefx = false, .nscodec = false, .clearcodec = false };

    /// Comma-separated; h264 means both AVC codecs, "none" leaves planar and bitmaps only.
    pub fn parseCodecs(o: *Options, list: []const u8) error{UnknownCodec}!void {
        o.avc444 = false;
        o.avc444_preferred = false;
        o.avc420 = false;
        o.progressive = false;
        o.remotefx = false;
        o.nscodec = false;
        o.clearcodec = false;
        var it = std.mem.tokenizeScalar(u8, list, ',');
        while (it.next()) |name| {
            if (std.mem.eql(u8, name, "all")) {
                const keep = o.*;
                o.* = .{ .lossy_motion = keep.lossy_motion, .bulk = keep.bulk, .rdpgfx = keep.rdpgfx, .vaapi_device = keep.vaapi_device };
            } else if (std.mem.eql(u8, name, "none") or std.mem.eql(u8, name, "planar")) {} else if (std.mem.eql(u8, name, "avc444")) {
                o.avc444 = true;
                o.avc444_preferred = true;
            } else if (std.mem.eql(u8, name, "avc420")) {
                o.avc420 = true;
            } else if (std.mem.eql(u8, name, "h264")) {
                o.avc444 = true;
                o.avc444_preferred = true;
                o.avc420 = true;
            } else if (std.mem.eql(u8, name, "progressive")) {
                o.progressive = true;
            } else if (std.mem.eql(u8, name, "remotefx")) {
                o.remotefx = true;
            } else if (std.mem.eql(u8, name, "nscodec")) {
                o.nscodec = true;
            } else if (std.mem.eql(u8, name, "clear")) {
                o.clearcodec = true;
            } else return error.UnknownCodec;
        }
    }
};

/// `--bulk`: none, 8k, 64k, rdp6 or rdp61 (MS-RDPBCGR 3.1.8 types).
pub fn parseBulk(name: []const u8) error{UnknownBulk}!?bulk_codec.Type {
    const names = [_]struct { []const u8, ?bulk_codec.Type }{
        .{ "none", null },    .{ "8k", .mppc_8k },   .{ "64k", .mppc_64k },
        .{ "rdp6", .ncrush }, .{ "rdp61", .xcrush },
    };
    for (names) |n| if (std.mem.eql(u8, name, n[0])) return n[1];
    return error.UnknownBulk;
}

pub const Motion = enum {
    avc444v2,
    avc420,
    progressive,
    /// RemoteFX in WIRE_TO_SURFACE_PDU_1 (RDPGFX_CODECID_CAVIDEO).
    remotefx,
    planar,

    pub fn h264(m: Motion) bool {
        return m == .avc444v2 or m == .avc420;
    }

    pub fn cpuLossy(m: Motion) bool {
        return m == .progressive or m == .remotefx;
    }
};

pub const max_motion = @typeInfo(Motion).@"enum".field_names.len;

pub const Gfx = struct {
    /// Motion codecs, most preferred first; always ends with planar.
    motion_buf: [max_motion]Motion = undefined,
    motion_len: usize = 0,
    clearcodec: bool = false,
    lossy_motion: LossyMotion = .auto,

    pub fn motion(p: *const Gfx) []const Motion {
        return p.motion_buf[0..p.motion_len];
    }

    fn add(p: *Gfx, m: Motion) void {
        p.motion_buf[p.motion_len] = m;
        p.motion_len += 1;
    }

    /// The preferred motion codec not in `off` (codecs that failed on this connection).
    pub fn pick(p: *const Gfx, off: std.EnumSet(Motion)) Motion {
        for (p.motion()) |m| if (!off.contains(m)) return m;
        return .planar;
    }
};

/// 8.1 with AVC420_ENABLED (2.2.3.2), 10.x unless AVC_DISABLED, 10.1 always (2.2.3.4, 1.7).
pub fn avc420Allowed(cs: gfx.CapSet) bool {
    return switch (cs.version) {
        gfx.capversion_8 => false,
        gfx.capversion_81 => cs.flags & gfx.caps_flag_avc420_enabled != 0,
        gfx.capversion_101 => true,
        else => cs.flags & gfx.caps_flag_avc_disabled == 0,
    };
}

pub fn clientAsksAvc444(cs: gfx.CapSet) bool {
    return cs.version == gfx.capversion_101 or cs.flags & gfx.caps_flag_avc_thinclient != 0;
}

pub fn forGfx(cs: gfx.CapSet, o: Options) Gfx {
    var p: Gfx = .{ .clearcodec = o.clearcodec, .lossy_motion = o.lossy_motion };
    if (o.avc444 and (o.avc444_preferred or clientAsksAvc444(cs)) and (avc444.allowed(.v2, cs.version, cs.flags) catch false)) p.add(.avc444v2);
    if (o.avc420 and avc420Allowed(cs)) p.add(.avc420);
    const thin = (cs.version == gfx.capversion_8 or cs.version == gfx.capversion_81) and cs.flags & gfx.caps_flag_thinclient != 0;
    if (thin) {
        if (o.remotefx) p.add(.remotefx);
    } else if (o.progressive and (progressive.allowed(cs.version, cs.flags) catch false)) {
        p.add(.progressive);
    }
    p.add(.planar);
    return p;
}

pub const LegacyMotion = union(enum) {
    /// TS_SURFCMD_STREAM_SURF_BITS with this codecID and RemoteFX mode.
    remotefx: struct { id: u8, mode: rfx.Mode, entropy: rfx.Entropy },
    /// TS_SURFCMD_SET_SURF_BITS with NSCodec (codecID 1).
    nscodec: struct { id: u8, caps: nsc.Caps },
};

pub const Lossless = enum {
    /// RDP 6.0 planar bitmaps (32 bpp, MS-RDPEGDI 2.2.2.5.1).
    planar,
    /// Interleaved RLE bitmaps (15/16/24 bpp, MS-RDPBCGR 2.2.9.1.1.3.1.2.4).
    interleaved,
};

pub const Legacy = struct {
    motion: ?LegacyMotion = null,
    lossless: Lossless,
    lossy_motion: LossyMotion = .auto,
    /// Frame markers and Frame Acknowledge PDUs (MS-RDPBCGR 2.2.7.2.11).
    frame_ack: bool = false,
};

/// Malformed Bitmap Codecs data means no codec.
pub fn forLegacy(cc: *const caps.ClientCaps, bpp: u16, o: Options) Legacy {
    var p: Legacy = .{ .lossless = if (bpp == 32) .planar else .interleaved, .lossy_motion = o.lossy_motion };
    p.frame_ack = cc.frame_acknowledge != null and cc.surface_commands & caps.surfcmds_frame_marker != 0;
    if (bpp != 32 or !cc.has(.bitmap_codecs)) return p;
    const codecs = clientCodecs(cc.bitmap_codecs);
    if (o.remotefx and cc.surface_commands & caps.surfcmds_stream_surface_bits != 0) {
        if (codecs.remotefx) |n| {
            const id = (if (n.mode == .image and codecs.remotefx_id == null) codecs.image_remotefx_id else codecs.remotefx_id) orelse return p;
            p.motion = .{ .remotefx = .{ .id = id, .mode = n.mode, .entropy = n.entropy } };
            return p;
        }
    }
    if (o.nscodec and cc.surface_commands & caps.surfcmds_set_surface_bits != 0) {
        if (codecs.nscodec_id) |id| p.motion = .{ .nscodec = .{ .id = id, .caps = codecs.nscodec_caps.? } };
    }
    return p;
}

/// Like rfx.negotiateBitmapCodecs, but an unusable RemoteFX entry (MS-RDPRFX 3.1.5.1) drops only RemoteFX.
pub fn clientCodecs(body: []const u8) rfx.ClientCodecs {
    if (rfx.negotiateBitmapCodecs(body)) |c| return c else |_| {}
    var list: [255]rfx.BitmapCodec = undefined;
    const entries = rfx.parseBitmapCodecs(body, &list) catch return .{};
    var c: rfx.ClientCodecs = .{};
    for (entries) |e| {
        if (!std.mem.eql(u8, &e.guid, &rfx.guid_nscodec) or e.id != nsc.codec_id) continue;
        c.nscodec_caps = nsc.parseCaps(e.properties) catch continue;
        c.nscodec_id = e.id;
    }
    return c;
}

pub fn motionName(m: Motion) []const u8 {
    return switch (m) {
        .avc444v2 => "AVC444v2",
        .avc420 => "AVC420",
        .progressive => "progressive",
        .remotefx => "RemoteFX",
        .planar => "planar",
    };
}

const testing = std.testing;

fn expectMotion(cs: gfx.CapSet, o: Options, want: []const Motion) !void {
    const p = forGfx(cs, o);
    try testing.expectEqualSlices(Motion, want, p.motion());
}

test "RDPGFX policy per confirmed caps" {
    const all: Options = .{};
    try expectMotion(.{ .version = gfx.capversion_107, .flags = 0 }, all, &.{ .avc420, .progressive, .planar });
    try expectMotion(.{ .version = gfx.capversion_106, .flags = 0 }, all, &.{ .avc420, .progressive, .planar });
    // Asking for AVC444: AVC_THINCLIENT, or 10.1 (which implies AVC444v2, 1.7).
    try expectMotion(.{ .version = gfx.capversion_106, .flags = gfx.caps_flag_avc_thinclient }, all, &.{ .avc444v2, .avc420, .progressive, .planar });
    try expectMotion(.{ .version = gfx.capversion_101, .flags = 0 }, all, &.{ .avc444v2, .avc420, .progressive, .planar });
    try expectMotion(.{ .version = gfx.capversion_107, .flags = gfx.caps_flag_avc_disabled }, all, &.{ .progressive, .planar });
    try expectMotion(.{ .version = gfx.capversion_81, .flags = gfx.caps_flag_avc420_enabled }, all, &.{ .avc420, .progressive, .planar });
    // Thin clients: RemoteFX instead of progressive (2.2.3.1).
    try expectMotion(.{ .version = gfx.capversion_8, .flags = gfx.caps_flag_thinclient }, all, &.{ .remotefx, .planar });
    try expectMotion(.{ .version = gfx.capversion_81, .flags = gfx.caps_flag_thinclient | gfx.caps_flag_avc420_enabled }, all, &.{ .avc420, .remotefx, .planar });
    try expectMotion(.{ .version = gfx.capversion_8, .flags = 0 }, all, &.{ .progressive, .planar });
    try expectMotion(.{ .version = gfx.capversion_81, .flags = gfx.caps_flag_small_cache }, all, &.{ .progressive, .planar });
}

test "server options restrict the RDPGFX codecs; planar always remains" {
    var o: Options = .{};
    try o.parseCodecs("avc420,clear");
    try expectMotion(.{ .version = gfx.capversion_107, .flags = 0 }, o, &.{ .avc420, .planar });
    try testing.expect(forGfx(.{ .version = gfx.capversion_107, .flags = 0 }, o).clearcodec);
    try o.parseCodecs("none");
    try expectMotion(.{ .version = gfx.capversion_107, .flags = 0 }, o, &.{.planar});
    try testing.expect(!forGfx(.{ .version = gfx.capversion_107, .flags = 0 }, o).clearcodec);
    try o.parseCodecs("all");
    try expectMotion(.{ .version = gfx.capversion_8, .flags = gfx.caps_flag_thinclient }, o, &.{ .remotefx, .planar });
    try testing.expectError(error.UnknownCodec, o.parseCodecs("avc444,bogus"));
}

test "AVC444 only for clients that ask or with --codecs avc444/h264; other clients get AVC420" {
    const mac: gfx.CapSet = .{ .version = gfx.capversion_107, .flags = 0x82 }; // macOS client
    const win11: gfx.CapSet = .{ .version = gfx.capversion_106, .flags = 0 }; // Windows 11
    const thin: gfx.CapSet = .{ .version = gfx.capversion_107, .flags = gfx.caps_flag_avc_thinclient };
    const v101: gfx.CapSet = .{ .version = gfx.capversion_101, .flags = 0 };
    const o: Options = .{};
    try testing.expectEqual(Motion.avc420, forGfx(mac, o).pick(.empty));
    try testing.expectEqual(Motion.avc420, forGfx(win11, o).pick(.empty));
    try testing.expectEqual(Motion.avc444v2, forGfx(thin, o).pick(.empty));
    try testing.expectEqual(Motion.avc444v2, forGfx(v101, o).pick(.empty));
    var x: Options = .{};
    for ([_][]const u8{ "avc444,avc420", "h264", "avc444" }) |list| {
        try x.parseCodecs(list);
        try testing.expectEqual(Motion.avc444v2, forGfx(mac, x).pick(.empty));
        try testing.expectEqual(Motion.avc444v2, forGfx(win11, x).pick(.empty));
    }
    for ([_][]const u8{ "all", "avc420,progressive,clear" }) |list| {
        try x.parseCodecs(list);
        try testing.expectEqual(Motion.avc420, forGfx(mac, x).pick(.empty));
        try testing.expectEqual(Motion.avc420, forGfx(win11, x).pick(.empty));
    }
    try x.parseCodecs("h264,progressive");
    try testing.expectEqual(Motion.progressive, forGfx(.{ .version = gfx.capversion_107, .flags = gfx.caps_flag_avc_disabled | gfx.caps_flag_avc_thinclient }, x).pick(.empty));
}

test "pick skips codecs that failed on this connection" {
    const p = forGfx(.{ .version = gfx.capversion_107, .flags = gfx.caps_flag_avc_thinclient }, .{});
    try testing.expectEqual(Motion.avc444v2, p.pick(.empty));
    try testing.expectEqual(Motion.avc420, p.pick(.initMany(&.{.avc444v2})));
    try testing.expectEqual(Motion.progressive, p.pick(.initMany(&.{ .avc444v2, .avc420 })));
    try testing.expectEqual(Motion.planar, p.pick(.initMany(&.{ .avc444v2, .avc420, .progressive })));
}

fn bitmapCodecsBody(gpa: std.mem.Allocator, with_rfx: bool, icap_entropy: u8, with_nsc: bool) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const bytes = @import("../core/bytes.zig");
    var w = bytes.Writer.init(&list, gpa);
    try w.byte(@as(u8, @intFromBool(with_rfx)) + @intFromBool(with_nsc));
    if (with_rfx) {
        try w.bytes(&rfx.guid_remotefx);
        try w.byte(3); // the client's codecID
        // TS_RFX_CLNT_CAPS_CONTAINER with one ICAP (MS-RDPRFX 2.2.1.1).
        try w.u16le(49);
        try w.u32le(49);
        try w.u32le(rfx.cardp_caps_capture_non_cac);
        try w.u32le(37);
        try w.u16le(rfx.cby_caps);
        try w.u32le(8);
        try w.u16le(1);
        try w.u16le(rfx.cby_capset);
        try w.u32le(29);
        try w.byte(rfx.codec_id);
        try w.u16le(rfx.cly_capset);
        try w.u16le(2);
        try w.u16le(8);
        for ([_]u8{ 0, rfx.codec_mode }) |flags| {
            try w.u16le(rfx.clw_version_1_0);
            try w.u16le(rfx.tile_size);
            try w.byte(flags);
            try w.byte(rfx.col_conv_ict);
            try w.byte(rfx.clw_xform_dwt_53_a);
            try w.byte(icap_entropy);
        }
    }
    if (with_nsc) {
        try w.bytes(&rfx.guid_nscodec);
        try w.byte(nsc.codec_id);
        try w.u16le(3);
        try w.bytes(&.{ 1, 1, 3 });
    }
    return list.toOwnedSlice(gpa);
}

test "legacy policy: colour depth, Bitmap Codecs and surface commands decide" {
    const gpa = testing.allocator;
    const both = try bitmapCodecsBody(gpa, true, rfx.clw_entropy_rlgr3, true);
    defer gpa.free(both);
    var cc: caps.ClientCaps = .{ .bitmap_codecs = both, .surface_commands = caps.surfcmds_set_surface_bits | caps.surfcmds_stream_surface_bits | caps.surfcmds_frame_marker, .frame_acknowledge = 2 };
    cc.seen |= 1 << @backingInt(caps.Type.bitmap_codecs);
    var p = forLegacy(&cc, 32, .{});
    try testing.expectEqual(Lossless.planar, p.lossless);
    try testing.expect(p.frame_ack);
    try testing.expectEqual(@as(u8, 3), p.motion.?.remotefx.id);
    try testing.expectEqual(rfx.Mode.video, p.motion.?.remotefx.mode);
    try testing.expectEqual(rfx.Entropy.rlgr3, p.motion.?.remotefx.entropy);
    cc.surface_commands = caps.surfcmds_set_surface_bits;
    p = forLegacy(&cc, 32, .{});
    try testing.expectEqual(@as(u8, 1), p.motion.?.nscodec.id);
    try testing.expect(!p.frame_ack); // no frame marker support
    p = forLegacy(&cc, 16, .{});
    try testing.expectEqual(Lossless.interleaved, p.lossless);
    try testing.expect(p.motion == null);
    cc.surface_commands = caps.surfcmds_set_surface_bits | caps.surfcmds_stream_surface_bits;
    p = forLegacy(&cc, 32, .{ .remotefx = false, .nscodec = false });
    try testing.expect(p.motion == null);
}

test "an ICAP the server cannot honour drops RemoteFX only (MS-RDPRFX 3.1.5.1); malformed data drops everything" {
    const gpa = testing.allocator;
    const body = try bitmapCodecsBody(gpa, true, 0x7F, true); // unknown entropy
    defer gpa.free(body);
    var cc: caps.ClientCaps = .{ .bitmap_codecs = body, .surface_commands = caps.surfcmds_set_surface_bits | caps.surfcmds_stream_surface_bits };
    cc.seen |= 1 << @backingInt(caps.Type.bitmap_codecs);
    const p = forLegacy(&cc, 32, .{});
    try testing.expectEqual(@as(u8, 1), p.motion.?.nscodec.id);
    cc.bitmap_codecs = body[0 .. body.len - 2];
    try testing.expect(forLegacy(&cc, 32, .{}).motion == null);
    cc.bitmap_codecs = &.{};
    try testing.expect(forLegacy(&cc, 32, .{}).motion == null);
}
