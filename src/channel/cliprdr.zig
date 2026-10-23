//! MS-RDPECLIP clipboard virtual channel ("cliprdr"): PDUs, the mapping
//! between clipboard formats and Wayland mime types, and the server state
//! machine. Wire strings are UTF-16LE; this API takes and returns UTF-8.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const text_impl = @import("cliprdr/text.zig");
const html_impl = @import("cliprdr/html.zig");
const image_impl = @import("cliprdr/image.zig");
const png_impl = @import("cliprdr/png.zig");
const files_impl = @import("cliprdr/files.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Error = error{
    /// Shorter than the header, its dataLen or a fixed-size body; drop the connection (3.1.5.1).
    Truncated,
    UnknownMsgType,
    UnexpectedMsgType,
    /// A field breaks a MUST of 2.2 not covered below.
    InvalidPdu,
    /// Capability set lengths inconsistent with the data (2.2.2.1).
    InvalidCapabilitySet,
    /// Long name without a null, or a short list not a multiple of 36 bytes (2.2.3.1).
    InvalidFormatList,
    /// cItems inconsistent with the data, or a fileName without a null (2.2.5.2.3).
    InvalidFileList,
    NameTooLong,
    /// 2.2.5.3 FILECONTENTS_SIZE / FILECONTENTS_RANGE rules broken.
    InvalidFileContentsRequest,
    /// A file of 4 GiB or more without CB_HUGE_FILE_SUPPORT_ENABLED.
    FileTooLarge,
    /// A remote file name that is absolute, escapes its directory or is invalid on Windows.
    InvalidFileName,
    InvalidUri,
    UnsupportedUriScheme,
    /// file: URI naming another host (RFC 8089 2).
    NotLocalFile,
    InvalidHtmlFormat,
    InvalidDib,
    /// Valid DIB this converter does not handle (RLE, JPEG/PNG inside DIB).
    UnsupportedDib,
    InvalidBmp,
    InvalidPng,
    UnsupportedPng,
    ImageTooLarge,
    InvalidPalette,
    InvalidMetafile,
    UnsupportedConversion,
    NotReady,
    /// The feature needs a general capability flag both sides did not set.
    NotNegotiated,
    /// A format the peer did not advertise (2.2.5.1).
    UnknownFormat,
    /// Responses carry no format ID, so only one Format Data Request can be in flight.
    RequestPending,
    NoPendingRequest,
    NotLocked,
    OutOfMemory,
};

// Channel (2.1)

/// Clients send the name in lower case; names compare case-insensitively.
pub const channel_name = "cliprdr";

/// `name`: a Client Network Data channel name, possibly null-padded.
pub fn isChannelName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(std.mem.sliceTo(name, 0), channel_name);
}

// Header (2.2.1)

pub const header_len = 8;

pub const MsgType = enum(u16) {
    monitor_ready = 0x0001, // CB_MONITOR_READY
    format_list = 0x0002, // CB_FORMAT_LIST
    format_list_response = 0x0003, // CB_FORMAT_LIST_RESPONSE
    format_data_request = 0x0004, // CB_FORMAT_DATA_REQUEST
    format_data_response = 0x0005, // CB_FORMAT_DATA_RESPONSE
    temp_directory = 0x0006, // CB_TEMP_DIRECTORY
    clip_caps = 0x0007, // CB_CLIP_CAPS
    filecontents_request = 0x0008, // CB_FILECONTENTS_REQUEST
    filecontents_response = 0x0009, // CB_FILECONTENTS_RESPONSE
    lock_clipdata = 0x000A, // CB_LOCK_CLIPDATA
    unlock_clipdata = 0x000B, // CB_UNLOCK_CLIPDATA
    _,
};

/// msgFlags (2.2.1).
pub const CB_RESPONSE_OK: u16 = 0x0001;
pub const CB_RESPONSE_FAIL: u16 = 0x0002;
pub const CB_ASCII_NAMES: u16 = 0x0004;

pub const Header = struct {
    msg_type: MsgType,
    msg_flags: u16,
    data_len: u32,
};

pub const Split = struct {
    header: Header,
    body: []const u8,
};

/// Bytes past dataLen are ignored (some Windows servers append four); unknown msgType
/// values are returned as is (3.1.5.1).
pub fn decodeHeader(msg: []const u8) Error!Split {
    if (msg.len < header_len) return error.Truncated;
    const data_len = rd32(msg, 4);
    if (msg.len - header_len < data_len) return error.Truncated;
    return .{
        .header = .{ .msg_type = @fromBackingInt(@intCast(rd16(msg, 0))), .msg_flags = rd16(msg, 2), .data_len = data_len },
        .body = msg[header_len..][0..data_len],
    };
}

pub fn encodeHeader(w: *bytes.Writer, msg_type: MsgType, msg_flags: u16, data_len: u32) !void {
    try w.u16le(@backingInt(msg_type));
    try w.u16le(msg_flags);
    try w.u32le(data_len);
}

// Capabilities (2.2.2.1)

pub const CB_CAPSTYPE_GENERAL: u16 = 0x0001;
pub const CB_CAPSTYPE_GENERAL_LEN: u16 = 12;

pub const CB_CAPS_VERSION_1: u32 = 0x00000001;
pub const CB_CAPS_VERSION_2: u32 = 0x00000002;

/// generalFlags (2.2.2.1.1.1).
pub const CB_USE_LONG_FORMAT_NAMES: u32 = 0x00000002;
pub const CB_STREAM_FILECLIP_ENABLED: u32 = 0x00000004;
pub const CB_FILECLIP_NO_FILE_PATHS: u32 = 0x00000008;
pub const CB_CAN_LOCK_CLIPDATA: u32 = 0x00000010;
pub const CB_HUGE_FILE_SUPPORT_ENABLED: u32 = 0x00000020;
pub const all_general_flags: u32 = CB_USE_LONG_FORMAT_NAMES | CB_STREAM_FILECLIP_ENABLED |
    CB_FILECLIP_NO_FILE_PATHS | CB_CAN_LOCK_CLIPDATA | CB_HUGE_FILE_SUPPORT_ENABLED;

/// CLIPRDR_GENERAL_CAPABILITY (2.2.2.1.1.1); `version` must not drive capability decisions.
pub const GeneralCapability = struct {
    version: u32 = CB_CAPS_VERSION_2,
    flags: u32 = 0,
};

pub const Caps = struct {
    /// null: no General Capability Set, generalFlags 0 (2.2.2.1.1.1).
    general: ?GeneralCapability,
};

pub fn encodeCaps(w: *bytes.Writer, general: GeneralCapability) !void {
    try encodeHeader(w, .clip_caps, 0, 4 + CB_CAPSTYPE_GENERAL_LEN);
    try w.u16le(1); // cCapabilitiesSets
    try w.u16le(0); // pad1
    try w.u16le(CB_CAPSTYPE_GENERAL);
    try w.u16le(CB_CAPSTYPE_GENERAL_LEN);
    try w.u32le(general.version);
    try w.u32le(general.flags);
}

pub fn decodeCaps(msg: []const u8) Error!Caps {
    const body = try expectBody(msg, .clip_caps);
    if (body.len < 4) return error.Truncated;
    const count = rd16(body, 0);
    var general: ?GeneralCapability = null;
    var pos: usize = 4;
    for (0..count) |_| {
        if (body.len - pos < 4) return error.InvalidCapabilitySet;
        const set_type = rd16(body, pos);
        const len = rd16(body, pos + 2);
        if (len < 4 or len > body.len - pos) return error.InvalidCapabilitySet;
        if (set_type == CB_CAPSTYPE_GENERAL) {
            if (len != CB_CAPSTYPE_GENERAL_LEN) return error.InvalidCapabilitySet;
            general = .{ .version = rd32(body, pos + 4), .flags = rd32(body, pos + 8) };
        }
        pos += len;
    }
    return .{ .general = general };
}

/// 0 without a Capabilities PDU or General set (3.2.1.1, 3.3.1.1).
pub fn peerFlags(caps: ?Caps) u32 {
    const c = caps orelse return 0;
    const g = c.general orelse return 0;
    return g.flags;
}

/// A feature is used only when both sides set it (2.2.2.1.1.1, 3.2.5.1.3).
pub fn negotiate(local: u32, peer: ?Caps) u32 {
    return local & peerFlags(peer) & all_general_flags;
}

// Monitor Ready (2.2.2.2), Temporary Directory (2.2.2.3)

pub fn encodeMonitorReady(w: *bytes.Writer) !void {
    try encodeHeader(w, .monitor_ready, 0, 0);
}

pub fn decodeMonitorReady(msg: []const u8) Error!void {
    _ = try expectBody(msg, .monitor_ready);
}

/// wszTempDir is a 520-byte field: at most 259 UTF-16 code units + null.
pub const temp_dir_field_len = 520;

pub fn encodeTempDirectory(w: *bytes.Writer, path: []const u8) !void {
    var field: [temp_dir_field_len]u8 = @splat(0);
    try utf16Into(&field, path, temp_dir_field_len / 2 - 1);
    try encodeHeader(w, .temp_directory, 0, temp_dir_field_len);
    try w.bytes(&field);
}

/// The path as UTF-8; caller frees. error.InvalidPdu without a null.
pub fn decodeTempDirectory(gpa: Allocator, msg: []const u8) Error![]u8 {
    const body = try expectBody(msg, .temp_directory);
    if (body.len < temp_dir_field_len) return error.Truncated;
    const end = nullUnit(body[0..temp_dir_field_len]) orelse return error.InvalidPdu;
    return utf16ToUtf8Alloc(gpa, body[0..end]);
}

// Clipboard formats (1.3.1.2) and Format List (2.2.3.1)

/// Standard clipboard format IDs (Windows winuser.h).
pub const CF_TEXT: u32 = 1;
pub const CF_BITMAP: u32 = 2;
pub const CF_METAFILEPICT: u32 = 3;
pub const CF_SYLK: u32 = 4;
pub const CF_DIF: u32 = 5;
pub const CF_TIFF: u32 = 6;
pub const CF_OEMTEXT: u32 = 7;
pub const CF_DIB: u32 = 8;
pub const CF_PALETTE: u32 = 9;
pub const CF_PENDATA: u32 = 10;
pub const CF_RIFF: u32 = 11;
pub const CF_WAVE: u32 = 12;
pub const CF_UNICODETEXT: u32 = 13;
pub const CF_ENHMETAFILE: u32 = 14;
pub const CF_HDROP: u32 = 15;
pub const CF_LOCALE: u32 = 16;
pub const CF_DIBV5: u32 = 17;
pub const registered_format_first: u32 = 0xC000;

pub const name_html_format = "HTML Format";
pub const name_file_group_descriptor_w = "FileGroupDescriptorW";
pub const name_file_contents = "FileContents";
pub const name_png = "PNG";
pub const name_rich_text_format = "Rich Text Format";
/// Windows keeps data offering this out of clipboard history; password managers set it.
pub const name_exclude_from_monitor = "ExcludeClipboardContentFromMonitorProcessing";

pub const Format = struct {
    id: u32,
    name: []const u8 = "",
};

pub const FormatList = struct {
    formats: []Format,

    pub fn deinit(self: FormatList, gpa: Allocator) void {
        for (self.formats) |f| gpa.free(f.name);
        gpa.free(self.formats);
    }
};

/// Which formatListData variant to write (2.2.3.1.1, 2.2.3.1.2).
pub const NameEncoding = enum {
    long,
    short_unicode,
    /// CLIPRDR_SHORT_FORMAT_NAMES, 32-byte ASCII names, truncated (CB_ASCII_NAMES).
    short_ascii,
};

/// The variant 3.1.5.2.1 requires for the negotiated generalFlags.
pub fn nameEncodingFor(negotiated_flags: u32) NameEncoding {
    return if (negotiated_flags & CB_USE_LONG_FORMAT_NAMES != 0) .long else .short_unicode;
}

/// Short format name field size (2.2.3.1.1.1) and one entry's size.
pub const short_format_name_len = 32;
pub const short_format_entry_len = 36;

pub fn encodeFormatList(w: *bytes.Writer, formats: []const Format, encoding: NameEncoding) !void {
    switch (encoding) {
        .long => {
            var len: u64 = 0;
            for (formats) |f| len += 4 + 2 * (utf16Len(wireName(f.name)) + 1);
            if (len > std.math.maxInt(u32)) return error.InvalidPdu;
            try encodeHeader(w, .format_list, 0, @intCast(len));
            for (formats) |f| {
                try w.u32le(f.id);
                try writeUtf16(w, wireName(f.name));
                try w.u16le(0);
            }
        },
        .short_unicode, .short_ascii => {
            // Names are truncated so a terminating null always fits.
            const len = @as(u64, short_format_entry_len) * formats.len;
            if (len > std.math.maxInt(u32)) return error.InvalidPdu;
            const ascii = encoding == .short_ascii;
            try encodeHeader(w, .format_list, if (ascii) CB_ASCII_NAMES else 0, @intCast(len));
            for (formats) |f| {
                var field: [short_format_name_len]u8 = @splat(0);
                if (ascii) asciiInto(&field, wireName(f.name)) else _ = utf16Truncated(&field, wireName(f.name), short_format_name_len / 2 - 1);
                try w.u32le(f.id);
                try w.bytes(&field);
            }
        },
    }
}

/// `long_names`: CB_USE_LONG_FORMAT_NAMES is in effect. A short name filling all 32 bytes
/// without a null is accepted; Windows sends "Rich Text Format" that way.
pub fn decodeFormatList(gpa: Allocator, msg: []const u8, long_names: bool) Error!FormatList {
    const s = try decodeHeader(msg);
    if (s.header.msg_type != .format_list) return error.UnexpectedMsgType;
    const body = s.body;
    var list: std.ArrayList(Format) = .empty;
    errdefer {
        for (list.items) |f| gpa.free(f.name);
        list.deinit(gpa);
    }
    if (long_names) {
        // 3.1.5.2.1: Unicode names whatever CB_ASCII_NAMES says; a tail shorter than a formatId is padding.
        var pos: usize = 0;
        while (body.len - pos >= 4) {
            const id = rd32(body, pos);
            pos += 4;
            const end = pos + (nullUnit(body[pos..]) orelse return error.InvalidFormatList);
            const name = try utf16ToUtf8Alloc(gpa, body[pos..end]);
            errdefer gpa.free(name);
            try list.append(gpa, .{ .id = id, .name = name });
            pos = end + 2;
        }
    } else {
        if (body.len % short_format_entry_len != 0) return error.InvalidFormatList;
        const ascii = s.header.msg_flags & CB_ASCII_NAMES != 0;
        try list.ensureTotalCapacityPrecise(gpa, body.len / short_format_entry_len);
        var pos: usize = 0;
        while (pos < body.len) : (pos += short_format_entry_len) {
            const field = body[pos + 4 ..][0..short_format_name_len];
            const name = if (ascii)
                try latin1ToUtf8Alloc(gpa, std.mem.sliceTo(field, 0))
            else
                try utf16ToUtf8Alloc(gpa, field[0 .. nullUnit(field) orelse field.len]);
            list.appendAssumeCapacity(.{ .id = rd32(body, pos), .name = name });
        }
    }
    return .{ .formats = try list.toOwnedSlice(gpa) };
}

pub fn encodeFormatListResponse(w: *bytes.Writer, ok: bool) !void {
    try encodeHeader(w, .format_list_response, if (ok) CB_RESPONSE_OK else CB_RESPONSE_FAIL, 0);
}

/// msgFlags with neither response flag is error.InvalidPdu (2.2.3.2).
pub fn decodeFormatListResponse(msg: []const u8) Error!bool {
    const s = try decodeHeader(msg);
    if (s.header.msg_type != .format_list_response) return error.UnexpectedMsgType;
    return switch (s.header.msg_flags & (CB_RESPONSE_OK | CB_RESPONSE_FAIL)) {
        CB_RESPONSE_OK => true,
        CB_RESPONSE_FAIL => false,
        else => error.InvalidPdu,
    };
}

// Lock / Unlock (2.2.4)

pub fn encodeLockClipdata(w: *bytes.Writer, clip_data_id: u32) !void {
    try encodeHeader(w, .lock_clipdata, 0, 4);
    try w.u32le(clip_data_id);
}

pub fn decodeLockClipdata(msg: []const u8) Error!u32 {
    return decodeU32Pdu(msg, .lock_clipdata);
}

pub fn encodeUnlockClipdata(w: *bytes.Writer, clip_data_id: u32) !void {
    try encodeHeader(w, .unlock_clipdata, 0, 4);
    try w.u32le(clip_data_id);
}

pub fn decodeUnlockClipdata(msg: []const u8) Error!u32 {
    return decodeU32Pdu(msg, .unlock_clipdata);
}

// Format Data Request / Response (2.2.5.1, 2.2.5.2)

pub fn encodeFormatDataRequest(w: *bytes.Writer, format_id: u32) !void {
    try encodeHeader(w, .format_data_request, 0, 4);
    try w.u32le(format_id);
}

pub fn decodeFormatDataRequest(msg: []const u8) Error!u32 {
    return decodeU32Pdu(msg, .format_data_request);
}

/// `data` null sends CB_RESPONSE_FAIL (3.1.5.4.3).
pub fn encodeFormatDataResponse(w: *bytes.Writer, data: ?[]const u8) !void {
    const d = data orelse return encodeHeader(w, .format_data_response, CB_RESPONSE_FAIL, 0);
    if (d.len > std.math.maxInt(u32)) return error.InvalidPdu;
    try encodeHeader(w, .format_data_response, CB_RESPONSE_OK, @intCast(d.len));
    try w.bytes(d);
}

pub const DataResponse = struct {
    ok: bool,
    /// requestedFormatData (slice of the message); empty on failure.
    data: []const u8,
};

/// A failure carries no data even if bytes follow the header (3.1.5.4.3).
pub fn decodeFormatDataResponse(msg: []const u8) Error!DataResponse {
    const s = try decodeHeader(msg);
    if (s.header.msg_type != .format_data_response) return error.UnexpectedMsgType;
    const ok = isOk(s.header.msg_flags);
    return .{ .ok = ok, .data = if (ok) s.body else s.body[0..0] };
}

// File Contents Request / Response (2.2.5.3, 2.2.5.4)

pub const FILECONTENTS_SIZE: u32 = 0x00000001;
pub const FILECONTENTS_RANGE: u32 = 0x00000002;

pub const FileContentsRequest = struct {
    stream_id: u32,
    lindex: i32,
    /// FILECONTENTS_SIZE or FILECONTENTS_RANGE (exactly one).
    flags: u32,
    position: u64 = 0,
    cb_requested: u32,
    /// Optional clipDataId (dataLen 28 instead of 24).
    clip_data_id: ?u32 = null,
};

pub fn encodeFileContentsRequest(w: *bytes.Writer, req: FileContentsRequest) !void {
    try validateFileContentsRequest(req);
    try encodeHeader(w, .filecontents_request, 0, if (req.clip_data_id != null) 28 else 24);
    try w.u32le(req.stream_id);
    try w.u32le(@bitCast(req.lindex));
    try w.u32le(req.flags);
    try w.u32le(@truncate(req.position)); // nPositionLow
    try w.u32le(@truncate(req.position >> 32)); // nPositionHigh
    try w.u32le(req.cb_requested);
    if (req.clip_data_id) |id| try w.u32le(id);
}

pub fn decodeFileContentsRequest(msg: []const u8) Error!FileContentsRequest {
    const body = try expectBody(msg, .filecontents_request);
    if (body.len < 24) return error.Truncated;
    const req: FileContentsRequest = .{
        .stream_id = rd32(body, 0),
        .lindex = @bitCast(rd32(body, 4)),
        .flags = rd32(body, 8),
        .position = @as(u64, rd32(body, 16)) << 32 | rd32(body, 12),
        .cb_requested = rd32(body, 20),
        .clip_data_id = if (body.len >= 28) rd32(body, 24) else null,
    };
    try validateFileContentsRequest(req);
    return req;
}

/// `data` null: CB_RESPONSE_FAIL, dataLen 4 (streamId only).
pub fn encodeFileContentsResponse(w: *bytes.Writer, stream_id: u32, data: ?[]const u8) !void {
    const d = data orelse {
        try encodeHeader(w, .filecontents_response, CB_RESPONSE_FAIL, 4);
        return w.u32le(stream_id);
    };
    if (d.len > std.math.maxInt(u32) - 4) return error.InvalidPdu;
    try encodeHeader(w, .filecontents_response, CB_RESPONSE_OK, @intCast(4 + d.len));
    try w.u32le(stream_id);
    try w.bytes(d);
}

pub fn encodeFileSizeResponse(w: *bytes.Writer, stream_id: u32, size: u64) !void {
    try encodeHeader(w, .filecontents_response, CB_RESPONSE_OK, 12);
    try w.u32le(stream_id);
    try w.u32le(@truncate(size));
    try w.u32le(@truncate(size >> 32));
}

pub const FileContentsResponse = struct {
    stream_id: u32,
    ok: bool,
    data: []const u8,
};

pub fn decodeFileContentsResponse(msg: []const u8) Error!FileContentsResponse {
    const s = try decodeHeader(msg);
    if (s.header.msg_type != .filecontents_response) return error.UnexpectedMsgType;
    if (s.body.len < 4) return error.Truncated;
    const ok = isOk(s.header.msg_flags);
    return .{ .stream_id = rd32(s.body, 0), .ok = ok, .data = if (ok) s.body[4..] else s.body[4..4] };
}

/// The size in a FILECONTENTS_SIZE response (3.1.5.4.8); error.InvalidPdu unless 8 bytes.
pub fn fileSizeFromResponse(resp: FileContentsResponse) Error!u64 {
    if (!resp.ok or resp.data.len != 8) return error.InvalidPdu;
    return std.mem.readInt(u64, resp.data[0..8], .little);
}

pub const Pdu = union(enum) {
    monitor_ready,
    format_list: FormatList,
    format_list_response: bool,
    format_data_request: u32,
    format_data_response: DataResponse,
    temp_directory: []u8,
    clip_caps: Caps,
    filecontents_request: FileContentsRequest,
    filecontents_response: FileContentsResponse,
    lock_clipdata: u32,
    unlock_clipdata: u32,

    pub fn deinit(self: Pdu, gpa: Allocator) void {
        switch (self) {
            .format_list => |l| l.deinit(gpa),
            .temp_directory => |p| gpa.free(p),
            else => {},
        }
    }
};

pub const DecodeOptions = struct {
    /// CB_USE_LONG_FORMAT_NAMES in effect (for Format List PDUs).
    long_format_names: bool = false,
};

pub fn decode(gpa: Allocator, msg: []const u8, opts: DecodeOptions) Error!Pdu {
    const s = try decodeHeader(msg);
    return switch (s.header.msg_type) {
        .monitor_ready => .monitor_ready,
        .format_list => .{ .format_list = try decodeFormatList(gpa, msg, opts.long_format_names) },
        .format_list_response => .{ .format_list_response = try decodeFormatListResponse(msg) },
        .format_data_request => .{ .format_data_request = try decodeFormatDataRequest(msg) },
        .format_data_response => .{ .format_data_response = try decodeFormatDataResponse(msg) },
        .temp_directory => .{ .temp_directory = try decodeTempDirectory(gpa, msg) },
        .clip_caps => .{ .clip_caps = try decodeCaps(msg) },
        .filecontents_request => .{ .filecontents_request = try decodeFileContentsRequest(msg) },
        .filecontents_response => .{ .filecontents_response = try decodeFileContentsResponse(msg) },
        .lock_clipdata => .{ .lock_clipdata = try decodeLockClipdata(msg) },
        .unlock_clipdata => .{ .unlock_clipdata = try decodeUnlockClipdata(msg) },
        _ => error.UnknownMsgType,
    };
}

// Format Data payloads (2.2.5.2.1 - 2.2.5.2.3)

/// Mapping modes of CLIPRDR_MFPICT.
pub const MM_TEXT: u32 = 0x00000001;
pub const MM_LOMETRIC: u32 = 0x00000002;
pub const MM_HIMETRIC: u32 = 0x00000003;
pub const MM_LOENGLISH: u32 = 0x00000004;
pub const MM_HIENGLISH: u32 = 0x00000005;
pub const MM_TWIPS: u32 = 0x00000006;
pub const MM_ISOTROPIC: u32 = 0x00000007;
pub const MM_ANISOTROPIC: u32 = 0x00000008;

/// CLIPRDR_MFPICT (2.2.5.2.1); MM_ISOTROPIC uses negative extents for an aspect ratio.
pub const MetafilePict = struct {
    mapping_mode: u32,
    x_ext: i32,
    y_ext: i32,
    /// metaFileData ([MS-WMF] records), slice of the input.
    data: []const u8,
};

pub fn decodeMetafilePict(payload: []const u8) Error!MetafilePict {
    if (payload.len < 12) return error.InvalidMetafile;
    return .{
        .mapping_mode = rd32(payload, 0),
        .x_ext = @bitCast(rd32(payload, 4)),
        .y_ext = @bitCast(rd32(payload, 8)),
        .data = payload[12..],
    };
}

/// Appends the payload only (no CLIPRDR_HEADER).
pub fn encodeMetafilePict(w: *bytes.Writer, mf: MetafilePict) !void {
    try w.u32le(mf.mapping_mode);
    try w.u32le(@bitCast(mf.x_ext));
    try w.u32le(@bitCast(mf.y_ext));
    try w.bytes(mf.data);
}

/// PALETTEENTRY (2.2.5.2.2.1).
pub const PaletteEntry = struct {
    red: u8,
    green: u8,
    blue: u8,
    extra: u8 = 0,
};

/// CLIPRDR_PALETTE (2.2.5.2.2); caller frees.
pub fn decodePalette(gpa: Allocator, payload: []const u8) Error![]PaletteEntry {
    if (payload.len % 4 != 0) return error.InvalidPalette;
    const entries = try gpa.alloc(PaletteEntry, payload.len / 4);
    for (entries, 0..) |*e, i| {
        const p = payload[4 * i ..][0..4];
        e.* = .{ .red = p[0], .green = p[1], .blue = p[2], .extra = p[3] };
    }
    return entries;
}

pub fn encodePalette(w: *bytes.Writer, entries: []const PaletteEntry) !void {
    for (entries) |e| try w.bytes(&.{ e.red, e.green, e.blue, e.extra });
}

/// CLIPRDR_FILEDESCRIPTOR flags (2.2.5.2.3.1).
pub const FD_ATTRIBUTES: u32 = 0x00000004;
pub const FD_WRITESTIME: u32 = 0x00000020;
pub const FD_FILESIZE: u32 = 0x00000040;
pub const FD_SHOWPROGRESSUI: u32 = 0x00004000;

pub const FILE_ATTRIBUTE_READONLY: u32 = 0x00000001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x00000002;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x00000004;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x00000020;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;

pub const file_descriptor_len = 592;
/// fileName holds at most 259 UTF-16 code units + null.
pub const file_name_field_len = 520;

pub const FileDescriptor = struct {
    flags: u32 = FD_ATTRIBUTES | FD_FILESIZE | FD_WRITESTIME | FD_SHOWPROGRESSUI,
    attributes: u32 = FILE_ATTRIBUTE_NORMAL,
    /// FILETIME: 100 ns intervals since 1601-01-01 UTC.
    last_write_time: u64 = 0,
    size: u64 = 0,
    /// UTF-8, relative to the selection, with '\\' separators.
    name: []const u8,
};

pub const FileList = struct {
    files: []FileDescriptor,

    pub fn deinit(self: FileList, gpa: Allocator) void {
        for (self.files) |f| gpa.free(f.name);
        gpa.free(self.files);
    }
};

/// CLIPRDR_FILELIST (2.2.5.2.3); names are not validated (see remoteNameToRelativePath).
pub fn decodeFileList(gpa: Allocator, payload: []const u8) Error!FileList {
    return files_impl.decodeFileList(gpa, payload);
}

/// error.FileTooLarge for sizes past 32 bits without CB_HUGE_FILE_SUPPORT_ENABLED.
pub fn encodeFileList(w: *bytes.Writer, files: []const FileDescriptor, negotiated_flags: u32) !void {
    return files_impl.encodeFileList(w, files, negotiated_flags);
}

pub const filetime_unix_epoch: u64 = 116444736000000000;

/// Unix nanoseconds -> FILETIME; times before 1601 clamp to 0.
pub fn filetimeFromUnixNs(ns: i128) u64 {
    return files_impl.filetimeFromUnixNs(ns);
}

pub fn unixNsFromFiletime(ft: u64) i128 {
    return files_impl.unixNsFromFiletime(ft);
}

/// CF_UNICODETEXT -> UTF-8 with LF line breaks, up to the first null; caller frees.
pub fn unicodeTextToUtf8(gpa: Allocator, data: []const u8) Error![]u8 {
    return text_impl.unicodeTextToUtf8(gpa, data);
}

/// UTF-8 -> CF_UNICODETEXT with CRLF line breaks and a terminating null; caller frees.
pub fn utf8ToUnicodeText(gpa: Allocator, text: []const u8) Error![]u8 {
    return text_impl.utf8ToUnicodeText(gpa, text);
}

/// Windows uses the code pages of CF_LOCALE: 1252 and 437 for en-US.
pub const Codepage = enum {
    cp1252,
    cp437,
};

pub fn codepageTextToUtf8(gpa: Allocator, data: []const u8, cp: Codepage) Error![]u8 {
    return text_impl.codepageTextToUtf8(gpa, data, cp);
}

/// Characters the code page lacks become '?'.
pub fn utf8ToCodepageText(gpa: Allocator, text: []const u8, cp: Codepage) Error![]u8 {
    return text_impl.utf8ToCodepageText(gpa, text, cp);
}

/// Parsed "HTML Format" data; slices point into the input.
pub const HtmlFormat = struct {
    version: []const u8,
    /// StartHTML..EndHTML; null when absent or -1.
    html: ?[]const u8,
    fragment: []const u8,
    source_url: ?[]const u8 = null,
};

pub fn parseHtmlFormat(data: []const u8) Error!HtmlFormat {
    return html_impl.parseHtmlFormat(data);
}

/// The StartHTML..EndHTML context when present, else the fragment; caller frees.
pub fn htmlFormatToHtml(gpa: Allocator, data: []const u8) Error![]u8 {
    return html_impl.htmlFormatToHtml(gpa, data);
}

/// The fragment is the <body> content, or the whole HTML wrapped; caller frees.
pub fn htmlToHtmlFormat(gpa: Allocator, html: []const u8) Error![]u8 {
    return html_impl.htmlToHtmlFormat(gpa, html);
}

/// Largest width * height converted; guards allocations from hostile headers.
pub const max_image_pixels: u64 = 1 << 26;

/// Top-down rows of straight-alpha RGBA.
pub const Image = struct {
    width: u32,
    height: u32,
    rgba: []u8,

    pub fn deinit(self: Image, gpa: Allocator) void {
        gpa.free(self.rgba);
    }
};

/// biCompression.
pub const BI_RGB: u32 = 0;
pub const BI_RLE8: u32 = 1;
pub const BI_RLE4: u32 = 2;
pub const BI_BITFIELDS: u32 = 3;
pub const BI_JPEG: u32 = 4;
pub const BI_PNG: u32 = 5;

pub const bitmap_info_header_len = 40; // BITMAPINFOHEADER
pub const bitmap_v4_header_len = 108; // BITMAPV4HEADER
pub const bitmap_v5_header_len = 124; // BITMAPV5HEADER
pub const bitmap_file_header_len = 14; // BITMAPFILEHEADER

pub const LCS_sRGB: u32 = 0x73524742;
pub const LCS_GM_IMAGES: u32 = 0x00000004;

/// BITMAPINFOHEADER/V4/V5, 1 to 32 bpp, BI_RGB or BI_BITFIELDS; biSizeImage is not trusted.
pub fn decodeDib(gpa: Allocator, dib: []const u8) Error!Image {
    return image_impl.decodeDib(gpa, dib);
}

/// CF_DIB: BITMAPINFOHEADER, 32 bpp BI_RGB, bottom-up, 72 dpi.
pub fn encodeDib(gpa: Allocator, img: Image) Error![]u8 {
    return image_impl.encodeDib(gpa, img);
}

/// CF_DIBV5: BITMAPV5HEADER, 32 bpp BI_BITFIELDS with alpha, sRGB, bottom-up.
pub fn encodeDibV5(gpa: Allocator, img: Image) Error![]u8 {
    return image_impl.encodeDibV5(gpa, img);
}

pub fn dibToBmp(gpa: Allocator, dib: []const u8) Error![]u8 {
    return image_impl.dibToBmp(gpa, dib);
}

/// CF_DIB from image/bmp; pixels move up when bfOffBits leaves a gap.
pub fn bmpToDib(gpa: Allocator, bmp: []const u8) Error![]u8 {
    return image_impl.bmpToDib(gpa, bmp);
}

pub const png_signature = [8]u8{ 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n' };

/// 8-bit RGBA, non-interlaced PNG.
pub fn encodePng(gpa: Allocator, img: Image) Error![]u8 {
    return png_impl.encodePng(gpa, img);
}

/// Any conforming PNG; 16-bit samples keep their high byte.
pub fn decodePng(gpa: Allocator, png: []const u8) Error!Image {
    return png_impl.decodePng(gpa, png);
}

pub fn dibToPng(gpa: Allocator, dib: []const u8) Error![]u8 {
    return image_impl.dibToPng(gpa, dib);
}

pub fn pngToDib(gpa: Allocator, png: []const u8) Error![]u8 {
    return image_impl.pngToDib(gpa, png);
}

/// Local paths (UTF-8, absolute), allocated.
pub const PathList = struct {
    paths: [][]u8,

    pub fn deinit(self: PathList, gpa: Allocator) void {
        for (self.paths) |p| gpa.free(p);
        gpa.free(self.paths);
    }
};

/// Percent-escapes are decoded; other bytes are taken as is, as some clients leave spaces unescaped.
pub fn uriToLocalPath(gpa: Allocator, uri: []const u8) Error![]u8 {
    return files_impl.uriToLocalPath(gpa, uri);
}

/// All but unreserved characters and '/' are percent-encoded (RFC 3986 2.3).
pub fn localPathToUri(gpa: Allocator, path: []const u8) Error![]u8 {
    return files_impl.localPathToUri(gpa, path);
}

/// text/uri-list (RFC 2483 5); a URI uriToLocalPath refuses fails the whole list.
pub fn parseUriList(gpa: Allocator, data: []const u8) Error!PathList {
    return files_impl.parseUriList(gpa, data);
}

pub fn formatUriList(gpa: Allocator, paths: []const []const u8) Error![]u8 {
    return files_impl.formatUriList(gpa, paths);
}

/// x-special/gnome-copied-files: "copy" or "cut", then one URI per line.
pub const CopiedFiles = struct {
    cut: bool,
    list: PathList,
};

pub fn parseGnomeCopiedFiles(gpa: Allocator, data: []const u8) Error!CopiedFiles {
    return files_impl.parseGnomeCopiedFiles(gpa, data);
}

pub fn formatGnomeCopiedFiles(gpa: Allocator, paths: []const []const u8, cut: bool) Error![]u8 {
    return files_impl.formatGnomeCopiedFiles(gpa, paths, cut);
}

/// Valid on Windows: no reserved characters or device names, no trailing space or dot.
pub fn isValidRemoteNameComponent(name: []const u8) bool {
    return files_impl.isValidRemoteNameComponent(name);
}

/// '\\' becomes '/'; error.InvalidFileName for absolute names or invalid components.
pub fn remoteNameToRelativePath(gpa: Allocator, name: []const u8) Error![]u8 {
    return files_impl.remoteNameToRelativePath(gpa, name);
}

/// Descriptors for a "FileGroupDescriptorW" response and each one's local path.
pub const LocalFiles = struct {
    list: FileList,
    paths: [][]u8,

    pub fn deinit(self: LocalFiles, gpa: Allocator) void {
        self.list.deinit(gpa);
        for (self.paths) |p| gpa.free(p);
        gpa.free(self.paths);
    }
};

/// Directories recursively, parents first; `paths` is the lindex map (3.1.1.2). A symlink
/// is followed only when it stays inside the selected directory.
pub fn describeLocalFiles(gpa: Allocator, io: Io, paths: []const []const u8) anyerror!LocalFiles {
    return files_impl.describeLocalFiles(gpa, io, paths, null, std.math.maxInt(usize));
}

/// Paths not to stat or open, such as the server's own FUSE mounts (they would deadlock).
pub const PathGuard = struct {
    ctx: *const anyopaque,
    refuse: *const fn (ctx: *const anyopaque, path: []const u8) bool,
};

/// A refused selected path is error.AccessDenied, a refused entry below it
/// is skipped; more than `max_files` entries is error.InvalidFileList.
pub fn describeLocalFilesGuarded(gpa: Allocator, io: Io, paths: []const []const u8, guard: PathGuard, max_files: usize) anyerror!LocalFiles {
    return files_impl.describeLocalFiles(gpa, io, paths, guard, max_files);
}

/// 3.1.5.4.6; null (CB_RESPONSE_FAIL) for a bad lindex, a directory or a position past the end.
pub fn readFileContents(gpa: Allocator, io: Io, files: *const LocalFiles, req: FileContentsRequest) anyerror!?[]u8 {
    return files_impl.readFileContents(gpa, io, files, req);
}

/// text/uri-list of the top-level entries of received files staged under `base_dir`.
pub fn fileListToUriList(gpa: Allocator, base_dir: []const u8, files: []const FileDescriptor) Error![]u8 {
    return files_impl.fileListToUriList(gpa, base_dir, files);
}

pub const mime_text_utf8 = "text/plain;charset=utf-8";
pub const mime_text_plain = "text/plain";
pub const mime_utf8_string = "UTF8_STRING";
pub const mime_text = "TEXT";
pub const mime_string = "STRING";
pub const mime_html = "text/html";
pub const mime_png = "image/png";
pub const mime_bmp = "image/bmp";
pub const mime_uri_list = "text/uri-list";
pub const mime_gnome_copied_files = "x-special/gnome-copied-files";
/// Marks a selection as a password; clipboard managers skip it.
pub const mime_password_hint = "x-kde-passwordManagerHint";
pub const password_hint_data = "secret";

/// Text mime types offered for remote text, most preferred first.
pub const text_mimes = [_][]const u8{ mime_text_utf8, mime_utf8_string, mime_text_plain, mime_text, mime_string };

pub const MimeOffer = struct {
    mime: []const u8,
    format_id: u32,
};

/// Mime types for the peer's Format List, most preferred first; caller frees.
pub fn offersForRemoteFormats(gpa: Allocator, formats: []const Format, negotiated_flags: u32) Error![]MimeOffer {
    var text: ?u32 = null;
    var text_rank: u8 = 0;
    var html: ?u32 = null;
    var png: ?u32 = null;
    var dibv5: ?u32 = null;
    var dib: ?u32 = null;
    var files: ?u32 = null;
    var concealed: ?u32 = null;
    for (formats) |f| {
        const k = kindOf(f);
        switch (k) {
            .unicode_text, .ansi_text, .oem_text => {
                const rank: u8 = switch (k) {
                    .unicode_text => 3,
                    .ansi_text => 2,
                    else => 1,
                };
                if (rank > text_rank) {
                    text = f.id;
                    text_rank = rank;
                }
            },
            .html => html = html orelse f.id,
            .png => png = png orelse f.id,
            .dibv5 => dibv5 = dibv5 orelse f.id,
            .dib => dib = dib orelse f.id,
            .file_list => files = files orelse f.id,
            .concealed => concealed = concealed orelse f.id,
            .other => {},
        }
    }
    var offers: std.ArrayList(MimeOffer) = .empty;
    errdefer offers.deinit(gpa);
    if (text) |id| for (text_mimes) |m| try offers.append(gpa, .{ .mime = m, .format_id = id });
    if (html) |id| try offers.append(gpa, .{ .mime = mime_html, .format_id = id });
    if (png orelse dibv5 orelse dib) |id| try offers.append(gpa, .{ .mime = mime_png, .format_id = id });
    if (dibv5 orelse dib) |id| try offers.append(gpa, .{ .mime = mime_bmp, .format_id = id });
    if (files) |id| if (negotiated_flags & CB_STREAM_FILECLIP_ENABLED != 0) {
        try offers.append(gpa, .{ .mime = mime_uri_list, .format_id = id });
        try offers.append(gpa, .{ .mime = mime_gnome_copied_files, .format_id = id });
    };
    if (concealed) |id| if (offers.items.len > 0) try offers.append(gpa, .{ .mime = mime_password_hint, .format_id = id });
    return offers.toOwnedSlice(gpa);
}

/// Text is only CF_UNICODETEXT: Windows synthesizes CF_TEXT, CF_OEMTEXT and CF_LOCALE.
/// Caller frees the slice; names are static.
pub fn formatsForMimeTypes(gpa: Allocator, mimes: []const []const u8, negotiated_flags: u32) Error![]Format {
    var text = false;
    var html = false;
    var png = false;
    var bmp = false;
    var files = false;
    var concealed = false;
    for (mimes) |m| {
        if (mimeEql(m, mime_password_hint)) concealed = true;
        if (isTextMime(m)) text = true;
        if (mimeEql(m, mime_html)) html = true;
        if (mimeEql(m, mime_png)) png = true;
        if (mimeEql(m, mime_bmp)) bmp = true;
        if (mimeEql(m, mime_uri_list) or mimeEql(m, mime_gnome_copied_files)) files = true;
    }
    if (negotiated_flags & CB_STREAM_FILECLIP_ENABLED == 0) files = false;
    var out: std.ArrayList(Format) = .empty;
    errdefer out.deinit(gpa);
    if (text) try out.append(gpa, .{ .id = CF_UNICODETEXT });
    if (html) try out.append(gpa, .{ .id = local_id_html, .name = name_html_format });
    if (png or bmp) {
        try out.append(gpa, .{ .id = CF_DIB });
        try out.append(gpa, .{ .id = CF_DIBV5 });
    }
    if (png) try out.append(gpa, .{ .id = local_id_png, .name = name_png });
    if (files) try out.append(gpa, .{ .id = local_id_file_group_descriptor_w, .name = name_file_group_descriptor_w });
    if (concealed and out.items.len > 0) try out.append(gpa, .{ .id = local_id_exclude_from_monitor, .name = name_exclude_from_monitor });
    return out.toOwnedSlice(gpa);
}

pub fn mimeForFormat(format: Format, offered: []const []const u8) ?[]const u8 {
    return switch (kindOf(format)) {
        .unicode_text, .ansi_text, .oem_text => firstOffered(offered, &text_mimes),
        .dib, .dibv5, .png => firstOffered(offered, &.{ mime_png, mime_bmp }),
        .html => firstOffered(offered, &.{mime_html}),
        .file_list => firstOffered(offered, &.{ mime_uri_list, mime_gnome_copied_files }),
        .concealed => firstOffered(offered, &.{mime_password_hint}),
        .other => null,
    };
}

pub fn convertToRemote(gpa: Allocator, format: Format, mime: []const u8, data: []const u8) Error![]u8 {
    const k = kindOf(format);
    if (mimeEql(mime, mime_password_hint)) return switch (k) {
        .concealed => gpa.dupe(u8, data),
        else => error.UnsupportedConversion,
    };
    if (isTextMime(mime)) return switch (k) {
        .unicode_text => utf8ToUnicodeText(gpa, data),
        .ansi_text => utf8ToCodepageText(gpa, data, .cp1252),
        .oem_text => utf8ToCodepageText(gpa, data, .cp437),
        else => error.UnsupportedConversion,
    };
    if (mimeEql(mime, mime_html)) return switch (k) {
        .html => htmlToHtmlFormat(gpa, data),
        else => error.UnsupportedConversion,
    };
    if (mimeEql(mime, mime_png)) return switch (k) {
        .dib => pngToDib(gpa, data),
        .dibv5 => {
            const img = try decodePng(gpa, data);
            defer img.deinit(gpa);
            return encodeDibV5(gpa, img);
        },
        .png => gpa.dupe(u8, data),
        else => error.UnsupportedConversion,
    };
    if (mimeEql(mime, mime_bmp)) return switch (k) {
        .dib => bmpToDib(gpa, data),
        .dibv5, .png => {
            const dib = try bmpToDib(gpa, data);
            defer gpa.free(dib);
            if (k == .png) return dibToPng(gpa, dib);
            const img = try decodeDib(gpa, dib);
            defer img.deinit(gpa);
            return encodeDibV5(gpa, img);
        },
        else => error.UnsupportedConversion,
    };
    return error.UnsupportedConversion;
}

pub fn convertFromRemote(gpa: Allocator, format: Format, mime: []const u8, data: []const u8) Error![]u8 {
    const k = kindOf(format);
    switch (k) {
        .unicode_text, .ansi_text, .oem_text => {
            if (!isTextMime(mime)) return error.UnsupportedConversion;
            return switch (k) {
                .unicode_text => unicodeTextToUtf8(gpa, data),
                .ansi_text => codepageTextToUtf8(gpa, data, .cp1252),
                else => codepageTextToUtf8(gpa, data, .cp437),
            };
        },
        .html => {
            if (!mimeEql(mime, mime_html)) return error.UnsupportedConversion;
            return htmlFormatToHtml(gpa, data);
        },
        .dib, .dibv5 => {
            if (mimeEql(mime, mime_png)) return dibToPng(gpa, data);
            if (mimeEql(mime, mime_bmp)) return dibToBmp(gpa, data);
            return error.UnsupportedConversion;
        },
        .png => {
            if (!mimeEql(mime, mime_png)) return error.UnsupportedConversion;
            return gpa.dupe(u8, data);
        },
        .concealed => {
            if (!mimeEql(mime, mime_password_hint)) return error.UnsupportedConversion;
            return gpa.dupe(u8, password_hint_data);
        },
        .file_list, .other => return error.UnsupportedConversion,
    }
}

// Server state machine (3.1, 3.3)

pub const ServerOptions = struct {
    /// generalFlags advertised in the server Clipboard Capabilities PDU.
    flags: u32 = all_general_flags,
    version: u32 = CB_CAPS_VERSION_2,
};

pub const Event = union(enum) {
    none,
    caps: struct { negotiated_flags: u32 },
    /// Client Temporary Directory PDU (3.3.5.1.4).
    temp_directory: []const u8,
    /// The client clipboard changed; the response is already queued.
    remote_formats: []const Format,
    format_list_response: bool,
    /// The client pastes this local format ID; answer with sendData.
    data_request: u32,
    /// Answer to requestData.
    data_response: struct { format_id: u32, ok: bool, data: []const u8 },
    /// Answer with sendFileContents or sendFileSize.
    file_contents_request: FileContentsRequest,
    file_contents_response: FileContentsResponse,
    /// The client locks / unlocks local file stream data (3.1.5.3.2, 3.1.5.3.4).
    lock: u32,
    unlock: u32,
};

pub const Server = struct {
    gpa: Allocator,
    opts: ServerOptions,
    /// generalFlags in effect; 0 until the client's Capabilities PDU (3.3.1.1).
    negotiated: u32 = 0,
    temp_dir: ?[]u8 = null,
    /// The client's last Format List: the Clipboard Format ID Map (3.1.1.1).
    remote: ?FormatList = null,
    /// The client's first Format List ended initialization (1.3.2.1).
    initialized: bool = false,
    /// A local Format List set before that, sent after its response.
    deferred: ?[]Format = null,
    local: ?[]Format = null,
    responses_due: u32 = 0,
    /// The client failed the last local Format List (3.1.5.2.4).
    local_failed: bool = false,
    data_request: ?u32 = null,
    client_data_requests: u32 = 0,
    client_streams: std.ArrayList(u32) = .empty,
    our_streams: std.ArrayList(u32) = .empty,
    /// clipDataIds the client locked (3.1.5.3.2).
    client_locks: std.ArrayList(u32) = .empty,
    /// clipDataIds the server locked on the client (3.1.5.3.1).
    our_locks: std.ArrayList(u32) = .empty,

    pub fn init(gpa: Allocator, opts: ServerOptions) Server {
        return .{ .gpa = gpa, .opts = opts };
    }

    pub fn deinit(s: *Server) void {
        if (s.temp_dir) |p| s.gpa.free(p);
        if (s.remote) |l| l.deinit(s.gpa);
        if (s.deferred) |f| freeFormats(s.gpa, f);
        if (s.local) |f| freeFormats(s.gpa, f);
        s.client_streams.deinit(s.gpa);
        s.our_streams.deinit(s.gpa);
        s.client_locks.deinit(s.gpa);
        s.our_locks.deinit(s.gpa);
        s.* = undefined;
    }

    /// Queues the Capabilities and Monitor Ready PDUs (3.3.5.1.1, 3.3.5.1.2).
    pub fn start(s: *Server, out: *std.ArrayList(u8)) Error!void {
        var w = bytes.Writer.init(out, s.gpa);
        try encodeCaps(&w, .{ .version = s.opts.version, .flags = s.opts.flags });
        try encodeMonitorReady(&w);
    }

    /// Unexpected PDUs are ignored and unservable requests failed (3.1.5); error.Truncated means
    /// drop the connection. Event slices stay valid until the next call.
    pub fn handle(s: *Server, msg: []const u8, out: *std.ArrayList(u8)) Error!Event {
        if (msg.len < header_len) return error.Truncated;
        // 3.1.5.1: an unexpected PDU is ignored before dataLen is checked.
        const msg_type: MsgType = @fromBackingInt(@intCast(rd16(msg, 0)));
        if (!s.expected(msg_type)) return .none;
        const split = try decodeHeader(msg);
        var w = bytes.Writer.init(out, s.gpa);
        switch (msg_type) {
            .clip_caps => {
                // Undecodable: the defaults stay in effect.
                const caps = decodeCaps(msg) catch return .none;
                s.negotiated = negotiate(s.opts.flags, caps);
                return .{ .caps = .{ .negotiated_flags = s.negotiated } };
            },
            .temp_directory => {
                const path = decodeTempDirectory(s.gpa, msg) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return .none,
                };
                if (s.temp_dir) |old| s.gpa.free(old);
                s.temp_dir = path;
                return .{ .temp_directory = path };
            },
            .format_list => return s.handleFormatList(msg, &w),
            .format_list_response => {
                s.responses_due -= 1;
                const ok = decodeFormatListResponse(msg) catch false;
                // Only the response to the latest list decides (3.1.5.2.4).
                if (s.responses_due == 0) s.local_failed = !ok;
                return .{ .format_list_response = ok };
            },
            .format_data_request => {
                const id = decodeFormatDataRequest(msg) catch {
                    try encodeFormatDataResponse(&w, null);
                    return .none;
                };
                if (!s.canServeFormat(id)) {
                    try encodeFormatDataResponse(&w, null);
                    return .none;
                }
                s.client_data_requests += 1;
                return .{ .data_request = id };
            },
            .format_data_response => {
                const format_id = s.data_request.?;
                s.data_request = null;
                const r = try decodeFormatDataResponse(msg);
                return .{ .data_response = .{ .format_id = format_id, .ok = r.ok, .data = r.data } };
            },
            .filecontents_request => {
                // Without a streamId there is nothing to answer.
                if (split.body.len < 4) return .none;
                const stream_id = rd32(split.body, 0);
                const req = decodeFileContentsRequest(msg) catch {
                    try encodeFileContentsResponse(&w, stream_id, null);
                    return .none;
                };
                if (!s.canServeFileContents(req)) {
                    try encodeFileContentsResponse(&w, stream_id, null);
                    return .none;
                }
                try s.client_streams.append(s.gpa, stream_id);
                return .{ .file_contents_request = req };
            },
            .filecontents_response => {
                const r = decodeFileContentsResponse(msg) catch return .none;
                const i = std.mem.indexOfScalar(u32, s.our_streams.items, r.stream_id) orelse return .none;
                _ = s.our_streams.orderedRemove(i);
                return .{ .file_contents_response = r };
            },
            .lock_clipdata => {
                const id = decodeLockClipdata(msg) catch return .none;
                // 3.1.5.3.2: only local File Stream data can be locked.
                if (!s.localHasFiles()) return .none;
                if (std.mem.indexOfScalar(u32, s.client_locks.items, id) == null) try s.client_locks.append(s.gpa, id);
                return .{ .lock = id };
            },
            .unlock_clipdata => {
                const id = decodeUnlockClipdata(msg) catch return .none;
                // 3.1.5.3.4: an id with no stored data is ignored.
                const i = std.mem.indexOfScalar(u32, s.client_locks.items, id) orelse return .none;
                _ = s.client_locks.orderedRemove(i);
                return .{ .unlock = id };
            },
            else => return .none,
        }
    }

    pub fn negotiatedFlags(s: *const Server) u32 {
        return s.negotiated;
    }

    pub fn tempDirectory(s: *const Server) ?[]const u8 {
        return s.temp_dir;
    }

    /// The client's ID for a format name in its last Format List (3.1.1.1).
    pub fn remoteFormatId(s: *const Server, name: []const u8) ?u32 {
        const l = s.remote orelse return null;
        for (l.formats) |f| if (std.mem.eql(u8, f.name, name)) return f.id;
        return null;
    }

    /// 3.1.4.1; before the client's first Format List, the list waits until that one is answered.
    pub fn setLocalFormats(s: *Server, formats: []const Format, out: *std.ArrayList(u8)) Error!void {
        if (!s.initialized) {
            const copy = try cloneFormats(s.gpa, formats);
            if (s.deferred) |old| freeFormats(s.gpa, old);
            s.deferred = copy;
            return;
        }
        var w = bytes.Writer.init(out, s.gpa);
        try s.sendFormatList(formats, &w);
    }

    /// Paste from the client (3.1.4.2, 3.1.5.4.1).
    pub fn requestData(s: *Server, format_id: u32, out: *std.ArrayList(u8)) Error!void {
        if (s.data_request != null) return error.RequestPending;
        if (!s.remoteHas(format_id)) return error.UnknownFormat;
        var w = bytes.Writer.init(out, s.gpa);
        try encodeFormatDataRequest(&w, format_id);
        s.data_request = format_id;
    }

    pub fn sendData(s: *Server, data: ?[]const u8, out: *std.ArrayList(u8)) Error!void {
        if (s.client_data_requests == 0) return error.NoPendingRequest;
        var w = bytes.Writer.init(out, s.gpa);
        try encodeFormatDataResponse(&w, data);
        s.client_data_requests -= 1;
    }

    /// Needs CB_STREAM_FILECLIP_ENABLED, and CB_CAN_LOCK_CLIPDATA for a clip_data_id.
    pub fn requestFileContents(s: *Server, req: FileContentsRequest, out: *std.ArrayList(u8)) Error!void {
        if (s.negotiated & CB_STREAM_FILECLIP_ENABLED == 0) return error.NotNegotiated;
        if (req.clip_data_id != null and s.negotiated & CB_CAN_LOCK_CLIPDATA == 0) return error.NotNegotiated;
        try validateFileContentsRequest(req);
        // 2.2.2.1.1.1: without huge file support no file reaches 4 GiB.
        if (s.negotiated & CB_HUGE_FILE_SUPPORT_ENABLED == 0 and req.position >> 32 != 0) return error.FileTooLarge;
        try s.our_streams.ensureUnusedCapacity(s.gpa, 1);
        var w = bytes.Writer.init(out, s.gpa);
        try encodeFileContentsRequest(&w, req);
        s.our_streams.appendAssumeCapacity(req.stream_id);
    }

    pub fn sendFileContents(s: *Server, stream_id: u32, data: ?[]const u8, out: *std.ArrayList(u8)) Error!void {
        const i = std.mem.indexOfScalar(u32, s.client_streams.items, stream_id) orelse return error.NoPendingRequest;
        var w = bytes.Writer.init(out, s.gpa);
        try encodeFileContentsResponse(&w, stream_id, data);
        _ = s.client_streams.orderedRemove(i);
    }

    pub fn sendFileSize(s: *Server, stream_id: u32, size: u64, out: *std.ArrayList(u8)) Error!void {
        const i = std.mem.indexOfScalar(u32, s.client_streams.items, stream_id) orelse return error.NoPendingRequest;
        var w = bytes.Writer.init(out, s.gpa);
        try encodeFileSizeResponse(&w, stream_id, size);
        _ = s.client_streams.orderedRemove(i);
    }

    /// A late response is taken for any newer request: responses carry no format ID (2.2.5.2).
    pub fn cancelDataRequest(s: *Server) void {
        s.data_request = null;
    }

    /// A late response is ignored.
    pub fn cancelFileContentsRequest(s: *Server, stream_id: u32) void {
        const i = std.mem.indexOfScalar(u32, s.our_streams.items, stream_id) orelse return;
        _ = s.our_streams.orderedRemove(i);
    }

    pub fn lock(s: *Server, clip_data_id: u32, out: *std.ArrayList(u8)) Error!void {
        if (s.negotiated & CB_CAN_LOCK_CLIPDATA == 0) return error.NotNegotiated;
        const known = std.mem.indexOfScalar(u32, s.our_locks.items, clip_data_id) != null;
        if (!known) try s.our_locks.ensureUnusedCapacity(s.gpa, 1);
        var w = bytes.Writer.init(out, s.gpa);
        try encodeLockClipdata(&w, clip_data_id);
        if (!known) s.our_locks.appendAssumeCapacity(clip_data_id);
    }

    /// error.NotLocked unless `clip_data_id` is locked (3.1.5.3.3).
    pub fn unlock(s: *Server, clip_data_id: u32, out: *std.ArrayList(u8)) Error!void {
        const i = std.mem.indexOfScalar(u32, s.our_locks.items, clip_data_id) orelse return error.NotLocked;
        var w = bytes.Writer.init(out, s.gpa);
        try encodeUnlockClipdata(&w, clip_data_id);
        _ = s.our_locks.orderedRemove(i);
    }

    /// PDUs the client may send now (3.1.5.1).
    fn expected(s: *const Server, t: MsgType) bool {
        return switch (t) {
            .clip_caps, .temp_directory, .format_list, .format_data_request, .filecontents_request => true,
            .format_list_response => s.responses_due > 0,
            .format_data_response => s.data_request != null,
            .filecontents_response => s.our_streams.items.len > 0,
            .lock_clipdata, .unlock_clipdata => s.negotiated & CB_CAN_LOCK_CLIPDATA != 0,
            .monitor_ready => false,
            _ => false,
        };
    }

    /// 3.1.5.2.2; the client's first Format List releases a deferred local one.
    fn handleFormatList(s: *Server, msg: []const u8, w: *bytes.Writer) Error!Event {
        const first = !s.initialized;
        s.initialized = true;
        const decoded = decodeFormatList(s.gpa, msg, s.negotiated & CB_USE_LONG_FORMAT_NAMES != 0);
        // The ID Map is rebuilt from this list; an undecodable one empties it.
        if (s.remote) |l| l.deinit(s.gpa);
        s.remote = null;
        const list = decoded catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                try encodeFormatListResponse(w, false);
                if (first) try s.sendDeferred(w);
                return .none;
            },
        };
        s.remote = list;
        try encodeFormatListResponse(w, true);
        if (first) try s.sendDeferred(w);
        return .{ .remote_formats = list.formats };
    }

    fn sendDeferred(s: *Server, w: *bytes.Writer) Error!void {
        const d = s.deferred orelse return;
        defer {
            freeFormats(s.gpa, d);
            s.deferred = null;
        }
        try s.sendFormatList(d, w);
    }

    /// 3.1.4.1, 3.1.5.2.1: the Format List in the negotiated variant.
    fn sendFormatList(s: *Server, formats: []const Format, w: *bytes.Writer) Error!void {
        const copy = try cloneFormats(s.gpa, formats);
        errdefer freeFormats(s.gpa, copy);
        try encodeFormatList(w, formats, nameEncodingFor(s.negotiated));
        if (s.local) |old| freeFormats(s.gpa, old);
        s.local = copy;
        s.responses_due += 1;
        s.local_failed = false;
    }

    fn remoteHas(s: *const Server, id: u32) bool {
        const l = s.remote orelse return false;
        for (l.formats) |f| if (f.id == id) return true;
        return false;
    }

    pub fn localFormat(s: *const Server, id: u32) ?Format {
        for (s.local orelse return null) |f| if (f.id == id) return f;
        return null;
    }

    pub fn remoteFormat(s: *const Server, id: u32) ?Format {
        const l = s.remote orelse return null;
        for (l.formats) |f| if (f.id == id) return f;
        return null;
    }

    /// The initialization sequence is over (1.3.2.1).
    pub fn isInitialized(s: *const Server) bool {
        return s.initialized;
    }

    fn localHasFiles(s: *const Server) bool {
        for (s.local orelse return false) |f| if (std.mem.eql(u8, f.name, name_file_group_descriptor_w)) return true;
        return false;
    }

    /// 2.2.5.1, 3.1.5.2.4; a File List only with file streams (3.1.1.3).
    fn canServeFormat(s: *const Server, id: u32) bool {
        if (s.local_failed) return false;
        const f = s.localFormat(id) orelse return false;
        if (std.mem.eql(u8, f.name, name_file_group_descriptor_w) and s.negotiated & CB_STREAM_FILECLIP_ENABLED == 0) return false;
        return true;
    }

    /// 3.1.5.4.6: locked data by clipDataId, else the files of the current local list.
    fn canServeFileContents(s: *const Server, req: FileContentsRequest) bool {
        if (s.negotiated & CB_STREAM_FILECLIP_ENABLED == 0) return false;
        if (s.negotiated & CB_HUGE_FILE_SUPPORT_ENABLED == 0 and req.position >> 32 != 0) return false;
        if (req.clip_data_id) |id| return std.mem.indexOfScalar(u32, s.client_locks.items, id) != null;
        return !s.local_failed and s.localHasFiles();
    }
};

/// Registered format IDs of local Format Lists; clients map them by name (3.1.1.1).
const local_id_html: u32 = 0xC001;
const local_id_png: u32 = 0xC002;
const local_id_file_group_descriptor_w: u32 = 0xC003;
const local_id_exclude_from_monitor: u32 = 0xC004;

fn rd16(b: []const u8, off: usize) u16 {
    return std.mem.readInt(u16, b[off..][0..2], .little);
}

fn rd32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], .little);
}

fn expectBody(msg: []const u8, t: MsgType) Error![]const u8 {
    const s = try decodeHeader(msg);
    if (s.header.msg_type != t) return error.UnexpectedMsgType;
    return s.body;
}

fn decodeU32Pdu(msg: []const u8, t: MsgType) Error!u32 {
    const body = try expectBody(msg, t);
    if (body.len < 4) return error.Truncated;
    return rd32(body, 0);
}

/// CB_RESPONSE_OK without CB_RESPONSE_FAIL.
fn isOk(msg_flags: u16) bool {
    return msg_flags & (CB_RESPONSE_OK | CB_RESPONSE_FAIL) == CB_RESPONSE_OK;
}

/// 2.2.5.3: exactly one of SIZE / RANGE; a SIZE request asks 8 bytes at 0.
fn validateFileContentsRequest(req: FileContentsRequest) Error!void {
    switch (req.flags & (FILECONTENTS_SIZE | FILECONTENTS_RANGE)) {
        FILECONTENTS_SIZE => if (req.cb_requested != 8 or req.position != 0) return error.InvalidFileContentsRequest,
        FILECONTENTS_RANGE => {},
        else => return error.InvalidFileContentsRequest,
    }
}

fn cloneFormats(gpa: Allocator, formats: []const Format) Allocator.Error![]Format {
    const out = try gpa.alloc(Format, formats.len);
    var n: usize = 0;
    errdefer {
        for (out[0..n]) |f| gpa.free(f.name);
        gpa.free(out);
    }
    for (formats) |f| {
        out[n] = .{ .id = f.id, .name = try gpa.dupe(u8, f.name) };
        n += 1;
    }
    return out;
}

fn freeFormats(gpa: Allocator, formats: []Format) void {
    for (formats) |f| gpa.free(f.name);
    gpa.free(formats);
}

/// Standard formats are known by ID, registered ones by name (1.3.1.2).
const FormatKind = enum { unicode_text, ansi_text, oem_text, dib, dibv5, png, html, file_list, concealed, other };

fn kindOf(f: Format) FormatKind {
    if (f.id < registered_format_first) return switch (f.id) {
        CF_UNICODETEXT => .unicode_text,
        CF_TEXT => .ansi_text,
        CF_OEMTEXT => .oem_text,
        CF_DIB => .dib,
        CF_DIBV5 => .dibv5,
        else => .other,
    };
    if (std.mem.eql(u8, f.name, name_html_format)) return .html;
    if (std.mem.eql(u8, f.name, name_png)) return .png;
    if (std.mem.eql(u8, f.name, name_file_group_descriptor_w)) return .file_list;
    if (std.mem.eql(u8, f.name, name_exclude_from_monitor)) return .concealed;
    return .other;
}

/// Mime types compare case-insensitively (RFC 2045 5.1).
fn mimeEql(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn isTextMime(m: []const u8) bool {
    for (text_mimes) |t| if (mimeEql(m, t)) return true;
    return false;
}

fn firstOffered(offered: []const []const u8, wanted: []const []const u8) ?[]const u8 {
    for (wanted) |want| for (offered) |o| if (mimeEql(o, want)) return o;
    return null;
}

/// A format name as sent: it ends at an embedded null.
fn wireName(name: []const u8) []const u8 {
    return std.mem.sliceTo(name, 0);
}

fn unitsOf(cp: u21) usize {
    return if (cp >= 0x10000) 2 else 1;
}

/// UTF-16 code units of UTF-8 `s` (ill-formed sequences count as U+FFFD).
fn utf16Len(s: []const u8) usize {
    var n: usize = 0;
    var it: text_impl.Utf8Iter = .{ .s = s };
    while (it.next()) |cp| n += unitsOf(cp);
    return n;
}

fn putCodepoint(buf: []u8, unit: usize, cp: u21) void {
    if (cp >= 0x10000) {
        const v = cp - 0x10000;
        std.mem.writeInt(u16, buf[2 * unit ..][0..2], @intCast(0xD800 + (v >> 10)), .little);
        std.mem.writeInt(u16, buf[2 * unit + 2 ..][0..2], @intCast(0xDC00 + (v & 0x3FF)), .little);
    } else std.mem.writeInt(u16, buf[2 * unit ..][0..2], @intCast(cp), .little);
}

/// error.NameTooLong when `s` needs more than `max_units` UTF-16 code units.
fn utf16Into(buf: []u8, s: []const u8, max_units: usize) Error!void {
    if (!utf16Truncated(buf, s, max_units)) return error.NameTooLong;
}

/// Never splits a surrogate pair; false when something was left out.
fn utf16Truncated(buf: []u8, s: []const u8, max_units: usize) bool {
    var units: usize = 0;
    var it: text_impl.Utf8Iter = .{ .s = s };
    while (it.next()) |cp| {
        if (units + unitsOf(cp) > max_units) return false;
        putCodepoint(buf, units, cp);
        units += unitsOf(cp);
    }
    return true;
}

fn writeUtf16(w: *bytes.Writer, s: []const u8) !void {
    var it: text_impl.Utf8Iter = .{ .s = s };
    while (it.next()) |cp| {
        var tmp: [4]u8 = undefined;
        putCodepoint(&tmp, 0, cp);
        try w.bytes(tmp[0 .. 2 * unitsOf(cp)]);
    }
}

/// 32-byte ASCII name field: up to 31 characters, others as '?'.
fn asciiInto(field: *[short_format_name_len]u8, s: []const u8) void {
    var it: text_impl.Utf8Iter = .{ .s = s };
    for (field[0 .. short_format_name_len - 1]) |*b| {
        const cp = it.next() orelse return;
        b.* = if (cp < 0x80) @intCast(cp) else '?';
    }
}

fn nullUnit(b: []const u8) ?usize {
    var i: usize = 0;
    while (b.len - i >= 2) : (i += 2) if (rd16(b, i) == 0) return i;
    return null;
}

fn utf16ToUtf8Alloc(gpa: Allocator, b: []const u8) Allocator.Error![]u8 {
    return text_impl.utf16ToUtf8(gpa, b, false);
}

/// 8-bit names (CB_ASCII_NAMES) -> UTF-8, bytes above 0x7F as Latin-1.
fn latin1ToUtf8Alloc(gpa: Allocator, b: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (b) |ch| try text_impl.appendUtf8(gpa, &out, ch);
    return out.toOwnedSlice(gpa);
}
