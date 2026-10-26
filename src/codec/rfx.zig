//! MS-RDPRFX RemoteFX encoder, plus the reference decoder that predicts what a client shows,
//! in 11.5 fixed point. Sent in Stream Surface Bits commands (MS-RDPBCGR 2.2.9.2.2) and in
//! RDPGFX WIRE_TO_SURFACE_PDU_1 with codecId CAVIDEO (MS-RDPEGFX 2.2.2.1).

const std = @import("std");
/// Hot loops over our own frame data: checked in Debug (tests), unchecked in release builds.
const kernel_safety = @import("builtin").mode == .debug;
const bytes = @import("../core/bytes.zig");
const nsc = @import("nsc.zig");
const workers = @import("workers.zig");
pub const bits = @import("rfx/bits.zig");
pub const rlgr = @import("rfx/rlgr.zig");
pub const dwt = @import("rfx/dwt.zig");

pub const Error = error{
    /// width/height of 0, or larger than the channel/frame.
    InvalidDimensions,
    /// A TS_RFX_RECT that is empty or not inside the frame.
    BadRect,
    /// A quantization factor outside 6..15 (2.2.2.1.5).
    BadQuant,
    BadQuantIndex,
    /// Malformed TS_RFX_CLNT_CAPS_CONTAINER / TS_BITMAPCODECS.
    BadCaps,
    /// No TS_RFX_ICAP the server can honour (3.1.5.1): the connection ends.
    NoCompatibleIcap,
    BadRlgr,
    BufferTooSmall,
    /// More than 0xFFFF tiles / rects in one message.
    TooMany,
    MessageTooLarge,
} || std.mem.Allocator.Error;

// --- constants (2.2.1, 2.2.2) --------------------------------------------------------

pub const wbt_sync: u16 = 0xCCC0;
pub const wbt_codec_versions: u16 = 0xCCC1;
pub const wbt_channels: u16 = 0xCCC2;
pub const wbt_context: u16 = 0xCCC3;
pub const wbt_frame_begin: u16 = 0xCCC4;
pub const wbt_frame_end: u16 = 0xCCC5;
pub const wbt_region: u16 = 0xCCC6;
pub const wbt_extension: u16 = 0xCCC7;
pub const cbt_region: u16 = 0xCAC1;
pub const cbt_tileset: u16 = 0xCAC2;
pub const cbt_tile: u16 = 0xCAC3;
pub const cby_caps: u16 = 0xCBC0;
pub const cby_capset: u16 = 0xCBC1;
pub const cly_capset: u16 = 0xCFC0;

pub const wf_magic: u32 = 0xCACCACCA;
pub const wf_version_1_0: u16 = 0x0100;
pub const clw_version_1_0: u16 = 0x0100;
pub const ct_tile_64x64: u16 = 0x0040;
pub const tile_size: u16 = 64;
pub const tile_coeffs: usize = 64 * 64;

/// TS_RFX_ICAP / TS_RFX_CONTEXT / TS_RFX_TILESET flags: image mode.
pub const codec_mode: u8 = 0x02;
pub const col_conv_ict: u8 = 0x1;
pub const clw_xform_dwt_53_a: u8 = 0x1;
pub const clw_entropy_rlgr1: u8 = 0x01;
pub const clw_entropy_rlgr3: u8 = 0x04;
pub const scalar_quantization: u8 = 0x1;
/// codecId of TS_RFX_CODEC_CHANNELT / TS_RFX_CAPSET / TS_RFX_CODEC_VERSIONT.
pub const codec_id: u8 = 0x01;
/// channelId of TS_RFX_CONTEXT; every other channel block uses 0x00.
pub const context_channel_id: u8 = 0xFF;
/// TS_RFX_CLNT_CAPS_CONTAINER captureFlags.
pub const cardp_caps_capture_non_cac: u32 = 0x00000001;
pub const region_flag_lrf: u8 = 0x01;
pub const tileset_flag_lt: u16 = 0x0001;
/// RDPGFX_CODECID_CAVIDEO (MS-RDPEGFX 2.2.2.1).
pub const gfx_codec_id: u16 = 0x0003;

pub const sync_len: usize = 12;
pub const codec_versions_len: usize = 10;
pub const context_len: usize = 13;
pub const frame_begin_len: usize = 14;
pub const frame_end_len: usize = 8;
/// TS_RFX_CHANNELS with one channel.
pub const channels_len: usize = 12;
/// TS_RFX_REGION without rects.
pub const region_fixed_len: usize = 15;
/// TS_RFX_TILESET without quantVals and tiles.
pub const tileset_fixed_len: usize = 22;
/// TS_RFX_TILE without component data.
pub const tile_header_len: usize = 19;
pub const headers_len: usize = sync_len + context_len + codec_versions_len + channels_len;

/// TS_RFX_CHANNELT limits (2.2.2.1.3).
pub const max_channel_width: u16 = 4096;
pub const max_channel_height: u16 = 2048;

// --- Bitmap Codecs Capability Set (MS-RDPBCGR 2.2.7.2.10) ------------------------------

pub const capset_type_bitmap_codecs: u16 = 0x001D;

/// Codec GUIDs in wire order (codecGUID1 u32 LE, codecGUID2/3 u16 LE, then
/// bytes 4..11), MS-RDPBCGR 2.2.7.2.10.1.1.1.
pub const guid_nscodec = [16]u8{ 0xB9, 0x1B, 0x8D, 0xCA, 0x0F, 0x00, 0x4F, 0x15, 0x58, 0x9F, 0xAE, 0x2D, 0x1A, 0x87, 0xE2, 0xD6 };
pub const guid_remotefx = [16]u8{ 0x12, 0x2F, 0x77, 0x76, 0x72, 0xBD, 0x63, 0x44, 0xAF, 0xB3, 0xB7, 0x3C, 0x9C, 0x6F, 0x78, 0x86 };
pub const guid_image_remotefx = [16]u8{ 0xD4, 0xCC, 0x44, 0x27, 0x8A, 0x9D, 0x74, 0x4E, 0x80, 0x3C, 0x0E, 0xCB, 0xEE, 0xA1, 0x9C, 0x54 };
pub const guid_ignore = [16]u8{ 0xA6, 0x51, 0x43, 0x9C, 0x35, 0x35, 0xAE, 0x42, 0x91, 0x0C, 0xCD, 0xFC, 0xE5, 0x76, 0x0B, 0x58 };

/// One TS_BITMAPCODEC (properties borrowed from the parsed buffer).
pub const BitmapCodec = struct {
    guid: [16]u8,
    id: u8,
    properties: []const u8,
};

/// Parse a client's TS_BITMAPCODECS into `out`; error.BadCaps on truncation or overflow of `out`.
pub fn parseBitmapCodecs(body: []const u8, out: []BitmapCodec) Error![]BitmapCodec {
    var r = bytes.Reader.init(body);
    const count = r.byte() catch return error.BadCaps;
    if (count > out.len) return error.BadCaps;
    for (out[0..count]) |*c| {
        const guid = r.bytes(16) catch return error.BadCaps;
        const id = r.byte() catch return error.BadCaps;
        const len = r.u16le() catch return error.BadCaps;
        const props = r.bytes(len) catch return error.BadCaps;
        c.* = .{ .guid = guid[0..16].*, .id = id, .properties = props };
    }
    return out[0..count];
}

/// What the server puts in its Demand Active TS_BITMAPCODECS_CAPABILITYSET.
pub const ServerCodecs = struct {
    remotefx: bool = true,
    image_remotefx: bool = false,
    nscodec: ?nsc.Caps = .{},
};

/// TS_RFX_SRVR_CAPS_CONTAINER size: one reserved u32, as Windows servers send.
pub const server_caps_container_len: usize = 4;

/// RemoteFX entries carry codecID 0: the client picks its own, and 0x01 is reserved
/// for NSCodec (MS-RDPBCGR 2.2.7.2.10.1.1).
pub fn writeServerBitmapCodecsCapset(w: *bytes.Writer, codecs: ServerCodecs) Error!void {
    const start = w.len();
    try w.u16le(capset_type_bitmap_codecs);
    try w.u16le(0); // lengthCapability, patched below
    const count: u8 = @as(u8, @intFromBool(codecs.remotefx)) + @intFromBool(codecs.image_remotefx) + @intFromBool(codecs.nscodec != null);
    try w.byte(count);
    if (codecs.remotefx) {
        try w.bytes(&guid_remotefx);
        try w.byte(0);
        try w.u16le(server_caps_container_len);
        try writeServerCapsContainer(w, server_caps_container_len);
    }
    if (codecs.image_remotefx) {
        try w.bytes(&guid_image_remotefx);
        try w.byte(0);
        try w.u16le(server_caps_container_len);
        try writeServerCapsContainer(w, server_caps_container_len);
    }
    if (codecs.nscodec) |caps| {
        try w.bytes(&guid_nscodec);
        try w.byte(nsc.codec_id);
        try w.u16le(nsc.caps_len);
        nsc.writeCaps(w, caps) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.BadCaps,
        };
    }
    w.patchU16le(start + 2, @intCast(w.len() - start));
}

/// Client codecs and the codecIDs it assigned; CODEC_GUID_IGNORE and unknown GUIDs are skipped.
pub const ClientCodecs = struct {
    remotefx_id: ?u8 = null,
    image_remotefx_id: ?u8 = null,
    nscodec_id: ?u8 = null,
    nscodec_caps: ?nsc.Caps = null,
    remotefx: ?Negotiated = null,
};

/// NSCodec entries must use codecID 0x01. An IMAGE_REMOTEFX entry is used only without a
/// REMOTEFX entry and ignored when malformed, as Windows servers do (MS-RDPBCGR <31>).
pub fn negotiateBitmapCodecs(body: []const u8) Error!ClientCodecs {
    var list: [255]BitmapCodec = undefined;
    const entries = try parseBitmapCodecs(body, &list);
    var c: ClientCodecs = .{};
    var image: ?Negotiated = null;
    for (entries) |e| {
        if (std.mem.eql(u8, &e.guid, &guid_nscodec)) {
            if (e.id != nsc.codec_id) return error.BadCaps;
            c.nscodec_id = e.id;
            c.nscodec_caps = nsc.parseCaps(e.properties) catch return error.BadCaps;
        } else if (std.mem.eql(u8, &e.guid, &guid_remotefx)) {
            var icaps: [512]Icap = undefined;
            c.remotefx_id = e.id;
            c.remotefx = try negotiate(try parseClientCapsContainer(e.properties, &icaps), .rlgr3);
        } else if (std.mem.eql(u8, &e.guid, &guid_image_remotefx)) {
            var icaps: [512]Icap = undefined;
            c.image_remotefx_id = e.id;
            const got = parseClientCapsContainer(e.properties, &icaps) catch continue;
            if (negotiate(got, .rlgr3)) |n| {
                image = .{ .mode = .image, .entropy = n.entropy };
            } else |_| {}
        }
    }
    if (c.remotefx == null) c.remotefx = image;
    return c;
}

// --- RemoteFX capabilities (2.2.1, 3.1.5.1) ---------------------------------------------

pub const Entropy = enum(u8) { rlgr1 = clw_entropy_rlgr1, rlgr3 = clw_entropy_rlgr3 };
pub const Mode = enum { video, image };

fn rlgrMode(e: Entropy) rlgr.Mode {
    return switch (e) {
        .rlgr1 => .rlgr1,
        .rlgr3 => .rlgr3,
    };
}

/// TS_RFX_ICAP.
pub const Icap = struct {
    version: u16,
    tile_size: i16,
    flags: u8,
    col_conv: u8,
    transform: u8,
    entropy: u8,
};

pub const Negotiated = struct { mode: Mode, entropy: Entropy };

/// Parse a TS_RFX_CLNT_CAPS_CONTAINER (2.2.1.1) into `out`; error.BadCaps on any mismatch.
pub fn parseClientCapsContainer(data: []const u8, out: []Icap) Error![]Icap {
    var r = bytes.Reader.init(data);
    const length = r.u32le() catch return error.BadCaps;
    if (length < 12 or length > data.len) return error.BadCaps;
    r = bytes.Reader.init(data[0..length]);
    r.skip(8) catch return error.BadCaps; // length, captureFlags
    const caps_len = r.u32le() catch return error.BadCaps;
    if (caps_len != length - 12) return error.BadCaps;
    // TS_RFX_CAPS (2.2.1.1.1)
    if ((r.u16le() catch return error.BadCaps) != cby_caps) return error.BadCaps;
    if ((r.u32le() catch return error.BadCaps) != 8) return error.BadCaps;
    if ((r.u16le() catch return error.BadCaps) != 1) return error.BadCaps;
    // TS_RFX_CAPSET (2.2.1.1.1.1)
    if ((r.u16le() catch return error.BadCaps) != cby_capset) return error.BadCaps;
    const block_len = r.u32le() catch return error.BadCaps;
    if ((r.byte() catch return error.BadCaps) != codec_id) return error.BadCaps;
    if ((r.u16le() catch return error.BadCaps) != cly_capset) return error.BadCaps;
    const num = r.u16le() catch return error.BadCaps;
    const icap_len = r.u16le() catch return error.BadCaps;
    if (icap_len < 8) return error.BadCaps;
    if (block_len != 13 + @as(usize, num) * icap_len) return error.BadCaps;
    if (caps_len != 8 + block_len) return error.BadCaps;
    if (num > out.len) return error.BadCaps;
    for (out[0..num]) |*ic| {
        const b = r.bytes(icap_len) catch return error.BadCaps;
        ic.* = .{
            .version = std.mem.readInt(u16, b[0..2], .little),
            .tile_size = std.mem.readInt(i16, b[2..4], .little),
            .flags = b[4],
            .col_conv = b[5],
            .transform = b[6],
            .entropy = b[7],
        };
    }
    return out[0..num];
}

fn icapEntropy(ic: Icap) ?Entropy {
    if (ic.version != clw_version_1_0 or ic.tile_size != tile_size) return null;
    if (ic.col_conv != col_conv_ict or ic.transform != clw_xform_dwt_53_a) return null;
    return switch (ic.entropy) {
        clw_entropy_rlgr1 => .rlgr1,
        clw_entropy_rlgr3 => .rlgr3,
        else => null,
    };
}

/// Pick a supported TS_RFX_ICAP (3.1.5.1): version 1.0, 64x64 tiles, ICT, DWT 5/3, RLGR1
/// or RLGR3; `prefer` breaks ties. Image mode when the ICAP has CODEC_MODE.
pub fn negotiate(icaps: []const Icap, prefer: Entropy) Error!Negotiated {
    var pick: ?Negotiated = null;
    for (icaps) |ic| {
        const e = icapEntropy(ic) orelse continue;
        const n: Negotiated = .{ .mode = if (ic.flags & codec_mode != 0) .image else .video, .entropy = e };
        if (e == prefer) return n;
        if (pick == null) pick = n;
    }
    return pick orelse error.NoCompatibleIcap;
}

/// TS_RFX_SRVR_CAPS_CONTAINER (2.2.1.2): `len` reserved bytes, all zero.
pub fn writeServerCapsContainer(w: *bytes.Writer, len: usize) Error!void {
    try w.zeros(len);
}

/// TS_FRAME_ACKNOWLEDGE_CAPABILITYSET (2.2.1.3).
pub const capset_type_frame_acknowledge: u16 = 0x001E;
pub fn writeFrameAckCapset(w: *bytes.Writer, max_unacknowledged: u32) Error!void {
    try w.u16le(capset_type_frame_acknowledge);
    try w.u16le(8);
    try w.u32le(max_unacknowledged);
}

// --- quantization tables (2.2.2.1.5) ----------------------------------------------------

/// TS_RFX_CODEC_QUANT: one factor per sub-band, each 6..15.
pub const Quant = struct {
    ll3: u4,
    lh3: u4,
    hl3: u4,
    hh3: u4,
    lh2: u4,
    hl2: u4,
    hh2: u4,
    lh1: u4,
    hl1: u4,
    hh1: u4,

    fn wireOrder(q: Quant) [10]u4 {
        return .{ q.ll3, q.lh3, q.hl3, q.hh3, q.lh2, q.hl2, q.hh2, q.lh1, q.hl1, q.hh1 };
    }

    /// 5 bytes, two factors per byte, LL3 in the low nibble of byte 0.
    pub fn pack(q: Quant) Error![5]u8 {
        const v = q.wireOrder();
        for (v) |f| if (f < 6) return error.BadQuant;
        var out: [5]u8 = undefined;
        for (&out, 0..) |*b, i| b.* = @as(u8, v[2 * i]) | @as(u8, v[2 * i + 1]) << 4;
        return out;
    }

    pub fn unpack(b: [5]u8) Error!Quant {
        var v: [10]u4 = undefined;
        for (b, 0..) |x, i| {
            v[2 * i] = @truncate(x);
            v[2 * i + 1] = @truncate(x >> 4);
        }
        for (v) |f| if (f < 6) return error.BadQuant;
        return .{ .ll3 = v[0], .lh3 = v[1], .hl3 = v[2], .hh3 = v[3], .lh2 = v[4], .hl2 = v[5], .hh2 = v[6], .lh1 = v[7], .hl1 = v[8], .hh1 = v[9] };
    }

    /// The factors in linearized band order (HL1 .. HH3, LL3).
    pub fn bandOrder(q: Quant) [10]u4 {
        return .{ q.hl1, q.lh1, q.hh1, q.hl2, q.lh2, q.hh2, q.hl3, q.lh3, q.hh3, q.ll3 };
    }
};

/// The table of MS-RDPRFX 4.2.3/4.2.4.1 (66 66 77 88 98).
pub const default_quant = Quant{ .ll3 = 6, .lh3 = 6, .hl3 = 6, .hh3 = 6, .lh2 = 7, .hl2 = 7, .hh2 = 8, .lh1 = 8, .hl1 = 8, .hh1 = 9 };

// --- encode messages (2.2.2.2, 2.2.2.3) -------------------------------------------------

pub const Rect = struct { x: u16, y: u16, width: u16, height: u16 };

pub fn writeSync(w: *bytes.Writer) Error!void {
    try w.u16le(wbt_sync);
    try w.u32le(sync_len);
    try w.u32le(wf_magic);
    try w.u16le(wf_version_1_0);
}

pub fn writeCodecVersions(w: *bytes.Writer) Error!void {
    try w.u16le(wbt_codec_versions);
    try w.u32le(codec_versions_len);
    try w.byte(1);
    try w.byte(codec_id);
    try w.u16le(wf_version_1_0);
}

/// TS_RFX_CHANNELS with one channel (channelId 0) of the frame size (2.2.2.1.3).
pub fn writeChannels(w: *bytes.Writer, width: u16, height: u16) Error!void {
    if (width == 0 or height == 0 or width > max_channel_width or height > max_channel_height) return error.InvalidDimensions;
    try w.u16le(wbt_channels);
    try w.u32le(channels_len);
    try w.byte(1);
    try w.byte(0);
    try w.u16le(width);
    try w.u16le(height);
}

/// TS_RFX_CONTEXT properties (2.2.2.2.4): flags, cct, xft, et, qt (r = 0).
fn contextProperties(mode: Mode, entropy: Entropy) u16 {
    const flags: u16 = if (mode == .image) codec_mode else 0;
    return flags | @as(u16, col_conv_ict) << 3 | @as(u16, clw_xform_dwt_53_a) << 5 |
        @as(u16, @backingInt(entropy)) << 9 | @as(u16, scalar_quantization) << 13;
}

pub fn writeContext(w: *bytes.Writer, mode: Mode, entropy: Entropy) Error!void {
    try w.u16le(wbt_context);
    try w.u32le(context_len);
    try w.byte(codec_id);
    try w.byte(context_channel_id);
    try w.byte(0);
    try w.u16le(ct_tile_64x64);
    try w.u16le(contextProperties(mode, entropy));
}

/// Header messages in the order of MS-RDPRFX 4.2.2.
pub fn writeHeaders(w: *bytes.Writer, width: u16, height: u16, mode: Mode, entropy: Entropy) Error!void {
    if (width == 0 or height == 0 or width > max_channel_width or height > max_channel_height) return error.InvalidDimensions;
    try writeSync(w);
    try writeContext(w, mode, entropy);
    try writeCodecVersions(w);
    try writeChannels(w, width, height);
}

pub fn writeFrameBegin(w: *bytes.Writer, frame_idx: u32, num_regions: u16) Error!void {
    try w.u16le(wbt_frame_begin);
    try w.u32le(frame_begin_len);
    try w.byte(codec_id);
    try w.byte(0);
    try w.u32le(frame_idx);
    try w.u16le(num_regions);
}

pub fn writeFrameEnd(w: *bytes.Writer) Error!void {
    try w.u16le(wbt_frame_end);
    try w.u32le(frame_end_len);
    try w.byte(codec_id);
    try w.byte(0);
}

/// An empty `rects` writes numRects = 0: the whole channel frame (2.2.2.3.3).
pub fn writeRegion(w: *bytes.Writer, rects: []const Rect) Error!void {
    if (rects.len > 0xFFFF) return error.TooMany;
    try w.u16le(wbt_region);
    try w.u32le(@intCast(region_fixed_len + 8 * rects.len));
    try w.byte(codec_id);
    try w.byte(0);
    try w.byte(region_flag_lrf);
    try w.u16le(@intCast(rects.len));
    for (rects) |r| {
        try w.u16le(r.x);
        try w.u16le(r.y);
        try w.u16le(r.width);
        try w.u16le(r.height);
    }
    try w.u16le(cbt_region);
    try w.u16le(1);
}

/// One encoded tile: TS_RFX_TILE fields.
pub const EncodedTile = struct {
    quant_idx_y: u8 = 0,
    quant_idx_cb: u8 = 0,
    quant_idx_cr: u8 = 0,
    x_idx: u16,
    y_idx: u16,
    y_data: []const u8,
    cb_data: []const u8,
    cr_data: []const u8,

    fn wireLen(t: EncodedTile) usize {
        return tile_header_len + t.y_data.len + t.cb_data.len + t.cr_data.len;
    }
};

pub fn writeTile(w: *bytes.Writer, tile: EncodedTile) Error!void {
    if (tile.y_data.len > 0xFFFF or tile.cb_data.len > 0xFFFF or tile.cr_data.len > 0xFFFF) return error.MessageTooLarge;
    try w.u16le(cbt_tile);
    try w.u32le(@intCast(tile.wireLen()));
    try w.byte(tile.quant_idx_y);
    try w.byte(tile.quant_idx_cb);
    try w.byte(tile.quant_idx_cr);
    try w.u16le(tile.x_idx);
    try w.u16le(tile.y_idx);
    try w.u16le(@intCast(tile.y_data.len));
    try w.u16le(@intCast(tile.cb_data.len));
    try w.u16le(@intCast(tile.cr_data.len));
    try w.bytes(tile.y_data);
    try w.bytes(tile.cb_data);
    try w.bytes(tile.cr_data);
}

/// TS_RFX_TILESET; error.BadQuantIndex when a tile refers to a table not in `quants`.
pub fn writeTileset(w: *bytes.Writer, mode: Mode, entropy: Entropy, quants: []const Quant, tiles: []const EncodedTile) Error!void {
    if (quants.len > 0xFF or tiles.len > 0xFFFF) return error.TooMany;
    var data_len: usize = 0;
    for (tiles) |t| {
        if (t.quant_idx_y >= quants.len or t.quant_idx_cb >= quants.len or t.quant_idx_cr >= quants.len) return error.BadQuantIndex;
        data_len += t.wireLen();
    }
    const block_len = tileset_fixed_len + 5 * quants.len + data_len;
    if (block_len > std.math.maxInt(u32)) return error.MessageTooLarge;
    const flags: u16 = if (mode == .image) codec_mode else 0;
    const props: u16 = tileset_flag_lt | flags << 1 | @as(u16, col_conv_ict) << 4 | @as(u16, clw_xform_dwt_53_a) << 6 |
        @as(u16, @backingInt(entropy)) << 10 | @as(u16, scalar_quantization) << 14;
    try w.u16le(wbt_extension);
    try w.u32le(@intCast(block_len));
    try w.byte(codec_id);
    try w.byte(0);
    try w.u16le(cbt_tileset);
    try w.u16le(0);
    try w.u16le(props);
    try w.byte(@intCast(quants.len));
    try w.byte(@intCast(tile_size));
    try w.u16le(@intCast(tiles.len));
    try w.u32le(@intCast(data_len));
    for (quants) |q| try w.bytes(&try q.pack());
    for (tiles) |t| try writeTile(w, t);
}

// --- tile pipeline (3.1.8.1) --------------------------------------------------------------

/// 64x64 values: row-major spatial, or after `dwtEncode` the linearized sub-bands
/// HL1 LH1 HH1 (1024 each), HL2 LH2 HH2 (256), HL3 LH3 HH3 LL3 (64).
pub const Component = [tile_coeffs]i16;

/// Offsets of the sub-bands in the linearized layout (3.1.8.1.6).
pub const band_hl1: usize = 0;
pub const band_lh1: usize = 1024;
pub const band_hh1: usize = 2048;
pub const band_hl2: usize = 3072;
pub const band_lh2: usize = 3328;
pub const band_hh2: usize = 3584;
pub const band_hl3: usize = 3840;
pub const band_lh3: usize = 3904;
pub const band_hh3: usize = 3968;
pub const band_ll3: usize = 4032;

pub const band_lens = [10]usize{ 1024, 1024, 1024, 256, 256, 256, 64, 64, 64, 64 };

/// RGB -> level-shifted 11.5 YCbCr (3.1.8.1.3) of the tile at `pixels[0]` (BGRX, rows
/// `stride` apart); pixels beyond `width` x `height` replicate the edge.
pub fn rgbToYCbCr(pixels: []const u8, stride: usize, width: u16, height: u16, y: *Component, cb: *Component, cr: *Component) Error!void {
    @setRuntimeSafety(kernel_safety);
    if (width == 0 or height == 0) return error.InvalidDimensions;
    const w: usize = @min(width, tile_size);
    const h: usize = @min(height, tile_size);
    if (stride < w * 4 or pixels.len < (h - 1) * stride + w * 4) return error.InvalidDimensions;
    for (0..h) |ty| {
        const row = pixels[ty * stride ..][0 .. w * 4];
        const o = ty * 64;
        for (0..w) |tx| {
            const b: i32 = row[tx * 4];
            const g: i32 = row[tx * 4 + 1];
            const r: i32 = row[tx * 4 + 2];
            const yv = ((r * 9798 + g * 19235 + b * 3735 + 512) >> 10) - 4096;
            const cbv = (r * -5535 + g * -10868 + b * 16403 + 512) >> 10;
            const crv = (r * 16377 + g * -13714 + b * -2663 + 512) >> 10;
            y[o + tx] = @intCast(std.math.clamp(yv, -4096, 4095));
            cb[o + tx] = @intCast(std.math.clamp(cbv, -4096, 4095));
            cr[o + tx] = @intCast(std.math.clamp(crv, -4096, 4095));
        }
        if (w < 64) {
            @memset(y[o + w .. o + 64], y[o + w - 1]);
            @memset(cb[o + w .. o + 64], cb[o + w - 1]);
            @memset(cr[o + w .. o + 64], cr[o + w - 1]);
        }
    }
    for (h..64) |ty| {
        inline for (.{ y, cb, cr }) |c| @memcpy(c[ty * 64 ..][0..64], c[(h - 1) * 64 ..][0..64]);
    }
}

/// Forward 5/3 DWT (3.1.8.1.4) in place: spatial -> linearized sub-bands.
pub fn dwtEncode(c: *Component) Error!void {
    dwt.encode(c);
}

/// Inverse of `dwtEncode` (3.1.8.2.4): linearized sub-bands -> spatial.
pub fn dwtDecode(c: *Component) Error!void {
    dwt.decode(c);
}

/// Divide each band by 2^(f-1) in 11.5 fixed point, rounded (3.1.8.1.5); `factors` 6..15.
pub fn quantizeBands(c: []i16, lens: []const usize, factors: []const u4) Error!void {
    @setRuntimeSafety(kernel_safety);
    for (factors) |f| if (f < 6) return error.BadQuant;
    var off: usize = 0;
    for (lens, factors) |len, f| {
        const shift: u5 = @as(u5, f) - 1;
        const half: i32 = @as(i32, 1) << (shift - 1);
        for (c[off..][0..len]) |*v| v.* = @intCast((@as(i32, v.*) + half) >> shift);
        off += len;
    }
}

/// Multiply by 2^(f-1), wrapping like the 16-bit shifts of RDP decoders.
pub fn dequantizeBands(c: []i16, lens: []const usize, factors: []const u4) Error!void {
    for (factors) |f| if (f < 6) return error.BadQuant;
    var off: usize = 0;
    for (lens, factors) |len, f| {
        const shift: u5 = @as(u5, f) - 1;
        for (c[off..][0..len]) |*v| v.* = @truncate(@as(i32, v.*) << shift);
        off += len;
    }
}

/// Scalar quantization (3.1.8.1.5): scale 2^(q-6) plus the 5 fraction bits.
pub fn quantize(c: *Component, q: Quant) Error!void {
    try quantizeBands(c, &band_lens, &q.bandOrder());
}

/// Dequantization (3.1.8.2.3): multiply by 2^(q-1) back to 11.5 fixed point.
pub fn dequantize(c: *Component, q: Quant) Error!void {
    try dequantizeBands(c, &band_lens, &q.bandOrder());
}

/// LL3 differential coding (3.1.8.1.6), in place.
pub fn differentialEncode(ll3: []i16) Error!void {
    @setRuntimeSafety(kernel_safety);
    var i = ll3.len;
    while (i > 1) {
        i -= 1;
        ll3[i] -%= ll3[i - 1];
    }
}

/// Inverse of `differentialEncode` (3.1.8.2.2).
pub fn differentialDecode(ll3: []i16) Error!void {
    for (1..ll3.len) |i| ll3[i] +%= ll3[i - 1];
}

/// RLGR encoding (3.1.8.1.7.3.2); the byte count.
pub fn rlgrEncode(entropy: Entropy, coeffs: []const i16, out: []u8) Error!usize {
    return rlgr.encode(rlgrMode(entropy), coeffs, out);
}

/// RLGR decoding (3.1.8.1.7.3.1) of exactly `out.len` values.
pub fn rlgrDecode(entropy: Entropy, data: []const u8, out: []i16) Error!void {
    return rlgr.decode(rlgrMode(entropy), data, out);
}

/// Upper bound on the RLGR output for one component (for buffer sizing).
pub fn maxComponentSize() Error!usize {
    return rlgr.max_component_size;
}

/// Quantize, difference LL3 and entropy-code a transformed component onto `out`.
fn codeComponent(gpa: std.mem.Allocator, out: *std.ArrayList(u8), c: *Component, q: Quant, entropy: Entropy) Error!usize {
    try quantize(c, q);
    try differentialEncode(c[band_ll3..]);
    try out.ensureUnusedCapacity(gpa, rlgr.max_component_size);
    const n = try rlgrEncode(entropy, c, out.unusedCapacitySlice());
    out.items.len += n;
    return n;
}

/// Encode one tile, appending Y, Cb, Cr to `out`; the three lengths.
pub fn encodeTile(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    pixels: []const u8,
    stride: usize,
    width: u16,
    height: u16,
    quant_y: Quant,
    quant_cb: Quant,
    quant_cr: Quant,
    entropy: Entropy,
) Error![3]usize {
    // validate the tables before any output
    _ = try quant_y.pack();
    _ = try quant_cb.pack();
    _ = try quant_cr.pack();
    var comps: [3]Component = undefined;
    try rgbToYCbCr(pixels, stride, width, height, &comps[0], &comps[1], &comps[2]);
    var lens: [3]usize = undefined;
    for (&comps, [3]Quant{ quant_y, quant_cb, quant_cr }, &lens) |*c, q, *len| {
        dwt.encode(c);
        len.* = try codeComponent(gpa, out, c, q, entropy);
    }
    return lens;
}

/// YCbCr -> RGB as RDP clients do it (3.1.8.2.5); coefficients scaled by 2^16.
inline fn ycbcrToRgb(y: i16, cb: i16, cr: i16) [3]u8 {
    const yy: i64 = (@as(i64, y) + 4096) << 16;
    const r = ((@as(i64, cr) * 91916 + yy) >> 16) >> 5;
    const g = ((yy - @as(i64, cb) * 22527 - @as(i64, cr) * 46819) >> 16) >> 5;
    const b = ((@as(i64, cb) * 115992 + yy) >> 16) >> 5;
    return .{ @intCast(std.math.clamp(b, 0, 255)), @intCast(std.math.clamp(g, 0, 255)), @intCast(std.math.clamp(r, 0, 255)) };
}

/// Reference reconstruction of one tile (3.1.8.2) into 64x64 BGRX pixels at `dst`.
pub fn decodeTile(entropy: Entropy, y_data: []const u8, cb_data: []const u8, cr_data: []const u8, quant_y: Quant, quant_cb: Quant, quant_cr: Quant, dst: []u8, dst_stride: usize) Error!void {
    if (dst_stride < 64 * 4 or dst.len < 63 * dst_stride + 64 * 4) return error.BufferTooSmall;
    var comps: [3]Component = undefined;
    for (&comps, [3][]const u8{ y_data, cb_data, cr_data }, [3]Quant{ quant_y, quant_cb, quant_cr }) |*c, data, q| {
        try rlgrDecode(entropy, data, c);
        try differentialDecode(c[band_ll3..]);
        try dequantize(c, q);
        dwt.decode(c);
    }
    for (0..64) |ty| {
        const row = dst[ty * dst_stride ..][0 .. 64 * 4];
        for (0..64) |tx| {
            const i = ty * 64 + tx;
            const p = ycbcrToRgb(comps[0][i], comps[1][i], comps[2][i]);
            row[tx * 4 ..][0..4].* = .{ p[0], p[1], p[2], 0xFF };
        }
    }
}

// --- tiling and the encoder state machine (3.1.1.1, 3.1.8.1.1) ------------------------

pub const TileIndex = struct { x: u16, y: u16 };

fn rectCoversTile(r: Rect, tx: u32, ty: u32) bool {
    const x0: u32 = r.x;
    const y0: u32 = r.y;
    const x1 = x0 + r.width; // exclusive
    const y1 = y0 + r.height;
    return x0 < (tx + 1) * 64 and tx * 64 < x1 and y0 < (ty + 1) * 64 and ty * 64 < y1;
}

/// Tiles meeting any of `rects`, each once, in raster order (3.1.8.1.1, figure 19).
pub fn tilesForRects(rects: []const Rect, out: []TileIndex) Error![]TileIndex {
    if (rects.len == 0) return out[0..0];
    var tx0: u32 = std.math.maxInt(u32);
    var ty0: u32 = std.math.maxInt(u32);
    var tx1: u32 = 0;
    var ty1: u32 = 0;
    for (rects) |r| {
        if (r.width == 0 or r.height == 0) return error.BadRect;
        tx0 = @min(tx0, r.x / 64);
        ty0 = @min(ty0, r.y / 64);
        tx1 = @max(tx1, (@as(u32, r.x) + r.width - 1) / 64);
        ty1 = @max(ty1, (@as(u32, r.y) + r.height - 1) / 64);
    }
    var n: usize = 0;
    var ty = ty0;
    while (ty <= ty1) : (ty += 1) {
        var tx = tx0;
        while (tx <= tx1) : (tx += 1) {
            for (rects) |r| {
                if (!rectCoversTile(r, tx, ty)) continue;
                if (n == out.len) return error.BufferTooSmall;
                out[n] = .{ .x = @intCast(tx), .y = @intCast(ty) };
                n += 1;
                break;
            }
        }
    }
    return out[0..n];
}

fn clipToTile(r: Rect, t: TileIndex) ?Rect {
    const x0 = @max(@as(u32, r.x), @as(u32, t.x) * 64);
    const y0 = @max(@as(u32, r.y), @as(u32, t.y) * 64);
    const x1 = @min(@as(u32, r.x) + r.width, (@as(u32, t.x) + 1) * 64);
    const y1 = @min(@as(u32, r.y) + r.height, (@as(u32, t.y) + 1) * 64);
    if (x0 >= x1 or y0 >= y1) return null;
    return .{ .x = @intCast(x0), .y = @intCast(y0), .width = @intCast(x1 - x0), .height = @intCast(y1 - y0) };
}

pub const EncoderOptions = struct {
    width: u16,
    height: u16,
    mode: Mode = .video,
    entropy: Entropy = .rlgr3,
    quant: Quant = default_quant,
};

/// Server state machine (3.1.1.1): image mode resends the headers before every frame,
/// video mode only once.
pub const Encoder = struct {
    gpa: std.mem.Allocator,
    opts: EncoderOptions,
    frame_idx: u32 = 0,
    headers_sent: bool = false,

    pub fn init(gpa: std.mem.Allocator, opts: EncoderOptions) Error!Encoder {
        if (opts.width == 0 or opts.height == 0 or opts.width > max_channel_width or opts.height > max_channel_height) return error.InvalidDimensions;
        _ = try opts.quant.pack();
        return .{ .gpa = gpa, .opts = opts };
    }

    pub fn deinit(e: *Encoder) void {
        e.* = undefined;
    }

    fn headersDue(e: *const Encoder) bool {
        return e.opts.mode == .image or !e.headers_sent;
    }

    fn check(e: *const Encoder, pixels: []const u8, stride: usize, rects: []const Rect) Error!void {
        const w: usize = e.opts.width;
        const h: usize = e.opts.height;
        if (stride < w * 4 or pixels.len < (h - 1) * stride + w * 4) return error.InvalidDimensions;
        if (rects.len > 0xFFFF) return error.TooMany;
        for (rects) |r| {
            if (r.width == 0 or r.height == 0) return error.BadRect;
            if (@as(usize, r.x) + r.width > w or @as(usize, r.y) + r.height > h) return error.BadRect;
        }
    }

    /// Encode every tile touching `rects` into `data`; the tiles, whose
    /// component slices point into `data` (caller frees both).
    fn encodeTiles(e: *Encoder, data: *std.ArrayList(u8), pixels: []const u8, stride: usize, rects: []const Rect) Error![]EncodedTile {
        const gpa = e.gpa;
        const tw = (@as(usize, e.opts.width) + 63) / 64;
        const th = (@as(usize, e.opts.height) + 63) / 64;
        const idx = try gpa.alloc(TileIndex, tw * th);
        defer gpa.free(idx);
        const tiles = try tilesForRects(rects, idx);
        if (tiles.len > 0xFFFF) return error.TooMany;
        const lens = try gpa.alloc([3]usize, tiles.len);
        defer gpa.free(lens);
        // Tiles are coded in parallel, each task appending to its own buffer; `at` says where a
        // tile landed. The gather below puts them into `data` in tile order.
        const At = struct { task: usize, off: usize };
        const at = try gpa.alloc(At, tiles.len);
        defer gpa.free(at);
        const ntasks = workers.maxTasks();
        const bufs = try gpa.alloc(std.ArrayList(u8), ntasks);
        defer {
            for (bufs) |*b| b.deinit(gpa);
            gpa.free(bufs);
        }
        @memset(bufs, .empty);
        const errs = try gpa.alloc(?Error, ntasks);
        defer gpa.free(errs);
        @memset(errs, null);
        const Job = struct {
            e: *const Encoder,
            pixels: []const u8,
            stride: usize,
            tiles: []const TileIndex,
            lens: [][3]usize,
            at: []At,
            bufs: []std.ArrayList(u8),
            errs: []?Error,

            fn run(j: @This(), task: usize, i: usize) void {
                if (j.errs[task] != null) return;
                const t = j.tiles[i];
                const x: usize = @as(usize, t.x) * 64;
                const y: usize = @as(usize, t.y) * 64;
                const vw: u16 = @intCast(@min(64, j.e.opts.width - x));
                const vh: u16 = @intCast(@min(64, j.e.opts.height - y));
                const q = j.e.opts.quant;
                const buf = &j.bufs[task];
                j.at[i] = .{ .task = task, .off = buf.items.len };
                j.lens[i] = encodeTile(j.e.gpa, buf, j.pixels[y * j.stride + x * 4 ..], j.stride, vw, vh, q, q, q, j.e.opts.entropy) catch |err| {
                    j.errs[task] = err;
                    return;
                };
            }
        };
        workers.forEach(tiles.len, Job{ .e = e, .pixels = pixels, .stride = stride, .tiles = tiles, .lens = lens, .at = at, .bufs = bufs, .errs = errs }, Job.run);
        for (errs) |m| if (m) |err| return err;

        var total: usize = 0;
        for (lens) |l| total += l[0] + l[1] + l[2];
        try data.ensureUnusedCapacity(gpa, total);
        const out = try gpa.alloc(EncodedTile, tiles.len);
        for (tiles, lens, at, out) |t, l, a, *o| {
            const n = l[0] + l[1] + l[2];
            const off = data.items.len;
            data.appendSliceAssumeCapacity(bufs[a.task].items[a.off..][0..n]);
            o.* = .{
                .x_idx = t.x,
                .y_idx = t.y,
                .y_data = data.items[off..][0..l[0]],
                .cb_data = data.items[off + l[0] ..][0..l[1]],
                .cr_data = data.items[off + l[0] + l[1] ..][0..l[2]],
            };
        }
        return out;
    }

    fn writeFrame(e: *const Encoder, w: *bytes.Writer, headers: bool, frame_idx: u32, rects: []const Rect, tiles: []const EncodedTile) Error!void {
        if (headers) try writeHeaders(w, e.opts.width, e.opts.height, e.opts.mode, e.opts.entropy);
        try writeFrameBegin(w, frame_idx, 1);
        try writeRegion(w, rects);
        try writeTileset(w, e.opts.mode, e.opts.entropy, &.{e.opts.quant}, tiles);
        try writeFrameEnd(w);
    }

    /// Encode one frame (BGRX top-down, rows `stride` apart) restricted to `rects`, appending
    /// to `out`. An empty `rects` means the whole frame.
    pub fn encodeFrame(e: *Encoder, out: *std.ArrayList(u8), pixels: []const u8, stride: usize, rects: []const Rect) Error!void {
        const full = [1]Rect{.{ .x = 0, .y = 0, .width = e.opts.width, .height = e.opts.height }};
        const rs = if (rects.len == 0) &full else rects;
        try e.check(pixels, stride, rs);
        var data: std.ArrayList(u8) = .empty;
        defer data.deinit(e.gpa);
        const tiles = try e.encodeTiles(&data, pixels, stride, rs);
        defer e.gpa.free(tiles);
        var w = bytes.Writer.init(out, e.gpa);
        try e.writeFrame(&w, e.headersDue(), e.frame_idx, rs, tiles);
        e.headers_sent = true;
        e.frame_idx +%= 1;
    }

    /// Like `encodeFrame`, split into complete frames of at most `max_size` bytes for surface
    /// command limits. Caller frees each message and the slice.
    pub fn encodeFrameSplit(e: *Encoder, pixels: []const u8, stride: usize, rects: []const Rect, max_size: usize) Error![][]u8 {
        const gpa = e.gpa;
        const full = [1]Rect{.{ .x = 0, .y = 0, .width = e.opts.width, .height = e.opts.height }};
        const rs = if (rects.len == 0) &full else rects;
        try e.check(pixels, stride, rs);
        var data: std.ArrayList(u8) = .empty;
        defer data.deinit(gpa);
        const tiles = try e.encodeTiles(&data, pixels, stride, rs);
        defer gpa.free(tiles);

        var msgs: std.ArrayList([]u8) = .empty;
        errdefer {
            for (msgs.items) |m| gpa.free(m);
            msgs.deinit(gpa);
        }
        var region: std.ArrayList(Rect) = .empty;
        defer region.deinit(gpa);
        // frames are only committed once all of them are built
        var frame_idx = e.frame_idx;
        var headers_sent = e.headers_sent;
        var i: usize = 0;
        while (i < tiles.len) {
            const hdr: usize = if (e.opts.mode == .image or !headers_sent) headers_len else 0;
            const fixed = hdr + frame_begin_len + region_fixed_len + tileset_fixed_len + 5 + frame_end_len;
            region.clearRetainingCapacity();
            var tiles_len: usize = 0;
            var j = i;
            while (j < tiles.len) : (j += 1) {
                const keep_len = region.items.len;
                const keep_last = if (keep_len > 0) region.items[keep_len - 1] else undefined;
                for (rs) |r| {
                    const c = clipToTile(r, .{ .x = tiles[j].x_idx, .y = tiles[j].y_idx }) orelse continue;
                    if (region.items.len > 0) {
                        const last = &region.items[region.items.len - 1];
                        if (last.y == c.y and last.height == c.height and @as(u32, last.x) + last.width == c.x) {
                            last.width += c.width;
                            continue;
                        }
                    }
                    try region.append(gpa, c);
                }
                const size = fixed + 8 * region.items.len + tiles_len + tiles[j].wireLen();
                if (size > max_size or region.items.len > 0xFFFF or j - i == 0xFFFF) {
                    if (j == i) return error.MessageTooLarge;
                    region.items.len = keep_len;
                    if (keep_len > 0) region.items[keep_len - 1] = keep_last;
                    break;
                }
                tiles_len += tiles[j].wireLen();
            }
            var msg: std.ArrayList(u8) = .empty;
            errdefer msg.deinit(gpa);
            try msg.ensureTotalCapacity(gpa, fixed + 8 * region.items.len + tiles_len);
            var w = bytes.Writer.init(&msg, gpa);
            try e.writeFrame(&w, hdr > 0, frame_idx, region.items, tiles[i..j]);
            frame_idx +%= 1;
            headers_sent = true;
            const owned = try msg.toOwnedSlice(gpa);
            msgs.append(gpa, owned) catch |err| {
                gpa.free(owned);
                return err;
            };
            i = j;
        }
        e.frame_idx = frame_idx;
        e.headers_sent = headers_sent;
        return msgs.toOwnedSlice(gpa);
    }

    /// The next frame starts with the headers and FrameIndex 0 (3.1.1).
    pub fn reset(e: *Encoder) Error!void {
        e.headers_sent = false;
        e.frame_idx = 0;
    }

    pub fn frameIndex(e: *const Encoder) Error!u32 {
        return e.frame_idx;
    }
};

// --- surface commands (MS-RDPBCGR 2.2.9.2) ------------------------------------------------

pub const cmdtype_set_surface_bits: u16 = 0x0001;
pub const cmdtype_stream_surface_bits: u16 = 0x0006;
pub const ex_compressed_bitmap_header_present: u8 = 0x01;

/// TS_SURFCMD_STREAM_SURF_BITS / SET_SURF_BITS with a 32 bpp TS_BITMAP_DATA_EX.
pub fn writeSurfaceBits(w: *bytes.Writer, cmd_type: u16, left: u16, top: u16, width: u16, height: u16, codec: u8, data: []const u8) Error!void {
    if (@as(u32, left) + width > 0xFFFF or @as(u32, top) + height > 0xFFFF) return error.InvalidDimensions;
    if (data.len > std.math.maxInt(u32)) return error.MessageTooLarge;
    try w.u16le(cmd_type);
    try w.u16le(left);
    try w.u16le(top);
    try w.u16le(left + width);
    try w.u16le(top + height);
    try w.byte(32);
    try w.byte(0);
    try w.byte(0);
    try w.byte(codec);
    try w.u16le(width);
    try w.u16le(height);
    try w.u32le(@intCast(data.len));
    try w.bytes(data);
}

test {
    _ = bits;
    _ = rlgr;
    _ = dwt;
}
