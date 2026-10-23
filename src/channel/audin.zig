//! MS-RDPEAI audio input (AUDIO_INPUT dynamic channel): PDU codecs and the server
//! state machine. Audio is passed on undecoded with its format index.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const rdpsnd = @import("rdpsnd.zig");

const Allocator = std.mem.Allocator;

pub const AudioFormat = rdpsnd.AudioFormat;

pub const Error = error{
    EndOfBuffer,
    UnexpectedMessageId,
    /// A field violates a MUST of MS-RDPEAI 2.2.
    InvalidPdu,
    FormatIndexOutOfRange,
    NoCommonFormat,
    NotReady,
    /// MS-RDPEAI 3.3.5.3.1: AAC with a version 1 client.
    FormatChangeNotAllowed,
    TooLarge,
    OutOfMemory,
};

pub const channel_name = "AUDIO_INPUT";

/// SNDIN_PDU MessageId (2.2.1).
pub const MessageId = enum(u8) {
    version = 0x01, // MSG_SNDIN_VERSION
    formats = 0x02, // MSG_SNDIN_FORMATS
    open = 0x03, // MSG_SNDIN_OPEN
    open_reply = 0x04, // MSG_SNDIN_OPEN_REPLY
    data_incoming = 0x05, // MSG_SNDIN_DATA_INCOMING
    data = 0x06, // MSG_SNDIN_DATA
    format_change = 0x07, // MSG_SNDIN_FORMATCHANGE
    _,
};

pub const version_1: u32 = 0x00000001;
pub const version_2: u32 = 0x00000002;
pub const server_version: u32 = version_2;

pub fn messageId(msg: []const u8) Error!MessageId {
    if (msg.len < 1) return error.EndOfBuffer;
    return @fromBackingInt(@intCast(msg[0]));
}

fn expectBody(msg: []const u8, id: MessageId) Error![]const u8 {
    if (try messageId(msg) != id) return error.UnexpectedMessageId;
    return msg[1..];
}

fn decodeU32Pdu(msg: []const u8, id: MessageId) Error!u32 {
    const b = try expectBody(msg, id);
    if (b.len < 4) return error.EndOfBuffer;
    return std.mem.readInt(u32, b[0..4], .little);
}

fn encodeU32Pdu(w: *bytes.Writer, id: MessageId, v: u32) !void {
    try w.byte(@backingInt(id));
    try w.u32le(v);
}

pub fn encodeVersion(w: *bytes.Writer, version: u32) !void {
    try encodeU32Pdu(w, .version, version);
}

pub fn decodeVersion(msg: []const u8) Error!u32 {
    return decodeU32Pdu(msg, .version);
}

/// Sound Formats PDU (MSG_SNDIN_FORMATS, 2.2.2.2).
pub const Formats = struct {
    /// Client: PDU size without ExtraData. Server: reserved.
    cb_size_formats_packet: u32,
    formats: []const AudioFormat,
    extra_data: []const u8 = &.{},

    pub fn deinit(self: Formats, gpa: Allocator) void {
        gpa.free(self.formats);
    }
};

const formats_fixed_size = 9;

/// A null `cb_size_formats_packet` writes the size without ExtraData, as a client must.
pub fn encodeFormats(w: *bytes.Writer, formats: []const AudioFormat, cb_size_formats_packet: ?u32, extra_data: []const u8) !void {
    var size: usize = formats_fixed_size;
    for (formats) |f| size += rdpsnd.audio_format_fixed_size + f.extra.len;
    const cb = cb_size_formats_packet orelse (std.math.cast(u32, size) orelse return error.TooLarge);
    try w.byte(@backingInt(MessageId.formats));
    try w.u32le(std.math.cast(u32, formats.len) orelse return error.TooLarge);
    try w.u32le(cb);
    for (formats) |f| try rdpsnd.encodeAudioFormat(w, f);
    try w.bytes(extra_data);
}

/// Formats are allocated; `extra` and `extra_data` point into `msg`. ExtraData
/// is located by parsing the formats, not from cbSizeFormatsPacket.
pub fn decodeFormats(gpa: Allocator, msg: []const u8) Error!Formats {
    var r = bytes.Reader.init(try expectBody(msg, .formats));
    const count = try r.u32le();
    const cb = try r.u32le();
    if (@as(u64, count) * rdpsnd.audio_format_fixed_size > r.remaining()) return error.EndOfBuffer;
    const list = try gpa.alloc(AudioFormat, count);
    errdefer gpa.free(list);
    for (list) |*f| f.* = rdpsnd.decodeAudioFormat(&r) catch |e| return switch (e) {
        error.EndOfBuffer => error.EndOfBuffer,
        else => error.InvalidPdu,
    };
    return .{ .cb_size_formats_packet = cb, .formats = list, .extra_data = r.rest() };
}

/// KSDATAFORMAT_SUBTYPE_PCM in wire layout (Data1..Data3 little-endian).
pub const KSDATAFORMAT_SUBTYPE_PCM = [16]u8{
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
};

/// Speaker positions of dwChannelMask (2.2.2.3.1).
pub const SPEAKER_FRONT_LEFT: u32 = 0x00000001;
pub const SPEAKER_FRONT_RIGHT: u32 = 0x00000002;
pub const SPEAKER_FRONT_CENTER: u32 = 0x00000004;
pub const SPEAKER_LOW_FREQUENCY: u32 = 0x00000008;
pub const SPEAKER_BACK_LEFT: u32 = 0x00000010;
pub const SPEAKER_BACK_RIGHT: u32 = 0x00000020;
pub const SPEAKER_FRONT_LEFT_OF_CENTER: u32 = 0x00000040;
pub const SPEAKER_FRONT_RIGHT_OF_CENTER: u32 = 0x00000080;
pub const SPEAKER_BACK_CENTER: u32 = 0x00000100;
pub const SPEAKER_SIDE_LEFT: u32 = 0x00000200;
pub const SPEAKER_SIDE_RIGHT: u32 = 0x00000400;
pub const SPEAKER_TOP_CENTER: u32 = 0x00000800;
pub const SPEAKER_TOP_FRONT_LEFT: u32 = 0x00001000;
pub const SPEAKER_TOP_FRONT_CENTER: u32 = 0x00002000;
pub const SPEAKER_TOP_FRONT_RIGHT: u32 = 0x00004000;
pub const SPEAKER_TOP_BACK_LEFT: u32 = 0x00008000;
pub const SPEAKER_TOP_BACK_CENTER: u32 = 0x00010000;
pub const SPEAKER_TOP_BACK_RIGHT: u32 = 0x00020000;
pub const SPEAKER_ALL: u32 = 0x0003FFFF;

pub const wave_format_extensible_size = 22;

/// Extended Wave Format Structure (WAVEFORMAT_EXTENSIBLE, 2.2.2.3.1).
pub const WaveFormatExtensible = struct {
    /// wValidBitsPerSample or wSamplesPerBlock.
    valid_bits_per_sample: u16,
    channel_mask: u32,
    sub_format: [16]u8 = KSDATAFORMAT_SUBTYPE_PCM,
};

pub fn encodeWaveFormatExtensible(e: WaveFormatExtensible) Error![wave_format_extensible_size]u8 {
    var b: [wave_format_extensible_size]u8 = undefined;
    std.mem.writeInt(u16, b[0..2], e.valid_bits_per_sample, .little);
    std.mem.writeInt(u32, b[2..6], e.channel_mask, .little);
    b[6..22].* = e.sub_format;
    return b;
}

/// Checks the 2.2.2.3.1 MUSTs: valid bits, channel mask, PCM SubFormat.
pub fn decodeWaveFormatExtensible(capture: AudioFormat) Error!WaveFormatExtensible {
    if (capture.tag != rdpsnd.WAVE_FORMAT_EXTENSIBLE or capture.extra.len != wave_format_extensible_size)
        return error.InvalidPdu;
    const b = capture.extra;
    const e: WaveFormatExtensible = .{
        .valid_bits_per_sample = std.mem.readInt(u16, b[0..2], .little),
        .channel_mask = std.mem.readInt(u32, b[2..6], .little),
        .sub_format = b[6..22].*,
    };
    if (e.valid_bits_per_sample > capture.bits_per_sample) return error.InvalidPdu;
    if (e.channel_mask & ~SPEAKER_ALL != 0) return error.InvalidPdu;
    if (!std.mem.eql(u8, &e.sub_format, &KSDATAFORMAT_SUBTYPE_PCM)) return error.InvalidPdu;
    return e;
}

/// Open PDU (MSG_SNDIN_OPEN, 2.2.2.3).
pub const Open = struct {
    frames_per_packet: u32,
    /// Index into the negotiated (client) format list.
    initial_format: u32,
    capture: AudioFormat,
};

pub fn encodeOpen(w: *bytes.Writer, open: Open) !void {
    if (open.capture.tag == rdpsnd.WAVE_FORMAT_EXTENSIBLE and open.capture.extra.len != wave_format_extensible_size)
        return error.InvalidPdu;
    try w.byte(@backingInt(MessageId.open));
    try w.u32le(open.frames_per_packet);
    try w.u32le(open.initial_format);
    try rdpsnd.encodeAudioFormat(w, open.capture);
}

pub fn decodeOpen(msg: []const u8) Error!Open {
    var r = bytes.Reader.init(try expectBody(msg, .open));
    const frames = try r.u32le();
    const initial = try r.u32le();
    const capture = rdpsnd.decodeAudioFormat(&r) catch |e| return switch (e) {
        error.EndOfBuffer => error.EndOfBuffer,
        else => error.InvalidPdu,
    };
    if (r.remaining() != 0) return error.InvalidPdu;
    if (capture.tag == rdpsnd.WAVE_FORMAT_EXTENSIBLE and capture.extra.len != wave_format_extensible_size)
        return error.InvalidPdu;
    return .{ .frames_per_packet = frames, .initial_format = initial, .capture = capture };
}

/// 16-bit PCM bytes per Data PDU: nChannels * 2 * FramesPerPacket (2.2.2.3).
pub fn pcmPacketSize(open: Open) Error!usize {
    return std.math.cast(usize, @as(u64, open.capture.channels) * 2 * open.frames_per_packet) orelse error.TooLarge;
}

/// HRESULTs of the Open Reply PDU (MS-ERREF 2.1).
pub const S_OK: u32 = 0x00000000;
pub const E_FAIL: u32 = 0x80004005;
pub const E_OUTOFMEMORY: u32 = 0x8007000E;

pub fn isSuccess(hresult: u32) Error!bool {
    return hresult & 0x80000000 == 0;
}

pub fn encodeOpenReply(w: *bytes.Writer, result: u32) !void {
    try encodeU32Pdu(w, .open_reply, result);
}

pub fn decodeOpenReply(msg: []const u8) Error!u32 {
    return decodeU32Pdu(msg, .open_reply);
}

pub fn encodeIncomingData(w: *bytes.Writer) !void {
    try w.byte(@backingInt(MessageId.data_incoming));
}

pub fn decodeIncomingData(msg: []const u8) Error!void {
    _ = try expectBody(msg, .data_incoming);
}

pub fn encodeData(w: *bytes.Writer, data: []const u8) !void {
    try w.byte(@backingInt(MessageId.data));
    try w.bytes(data);
}

pub fn decodeData(msg: []const u8) Error![]const u8 {
    return expectBody(msg, .data);
}

pub fn encodeFormatChange(w: *bytes.Writer, new_format: u32) !void {
    try encodeU32Pdu(w, .format_change, new_format);
}

pub fn decodeFormatChange(msg: []const u8) Error!u32 {
    return decodeU32Pdu(msg, .format_change);
}

pub const State = enum {
    idle,
    wait_version,
    wait_formats,
    /// Open PDU sent (3.3.5.1.6); a Format Change then the Open Reply follow.
    wait_open_reply,
    /// Open Reply with an error HRESULT: the server MAY send another Open.
    open_failed,
    recording,
    /// Timeout (3.3.2 <2> <3> <4>) or channel closed.
    terminated,
};

pub const Config = struct {
    /// Formats offered in the server Sound Formats PDU, preferred first.
    formats: []const AudioFormat,
    version: u32 = server_version,
    frames_per_packet: u32 = 441,
    /// Capture format of the Open PDU (null: the negotiated format).
    capture: ?AudioFormat = null,
    /// 3.3.2 <2>-<4>: Windows waits 5 s for each client reply.
    reply_timeout_ms: u32 = 5_000,
};

pub const Event = union(enum) {
    none,
    /// Malformed, unrecognized or out-of-sequence: ignored (3.1.5).
    ignored,
    client_version: u32,
    /// Open sent; `initial_format` is the client-list index of the most preferred
    /// server format the client kept. No common format gives .terminated.
    formats_negotiated: struct { initial_format: u32 },
    format_confirmed: u32,
    open_result: u32,
    data_incoming,
    /// `format` is a client-list index; `data` is valid until the next handle().
    /// One Data PDU per Incoming Data PDU is accepted (3.2.5.2.1).
    audio: struct { format: u32, data: []const u8 },
    terminated,
};

pub const Outbox = rdpsnd.Outbox;

pub const Server = struct {
    gpa: Allocator,
    cfg: Config,
    st: State = .idle,
    client_version: ?u32 = null,
    client: rdpsnd.OwnedFormats = .{},
    initial: ?u32 = null,
    current: ?u32 = null,
    /// Format index the client has yet to confirm with a Format Change PDU.
    pending: ?u32 = null,
    /// The previous message was an Incoming Data PDU (3.2.5.2.1).
    incoming: bool = false,
    /// Reply timer deadline in ms (3.3.2).
    deadline: ?u64 = null,
    audio: std.ArrayList(u8) = .empty,

    pub fn init(gpa: Allocator, cfg: Config) Server {
        return .{ .gpa = gpa, .cfg = cfg };
    }

    pub fn deinit(self: *Server) void {
        self.client.deinit(self.gpa);
        self.audio.deinit(self.gpa);
    }

    /// Sends the Version PDU (3.1.5.1); also restarts the protocol on a reopened channel.
    pub fn start(self: *Server, now_ms: u64, out: *Outbox) Error!void {
        if (self.cfg.formats.len == 0) return error.NoCommonFormat;
        try out.build(encodeVersion, .{self.cfg.version});
        const gpa = self.gpa;
        const cfg = self.cfg;
        var audio = self.audio;
        audio.clearRetainingCapacity();
        self.client.deinit(gpa);
        self.* = .{ .gpa = gpa, .cfg = cfg, .audio = audio };
        self.st = .wait_version;
        self.deadline = now_ms +| self.cfg.reply_timeout_ms;
    }

    pub fn handle(self: *Server, msg: []const u8, now_ms: u64, out: *Outbox) Error!Event {
        const after_incoming = self.incoming;
        self.incoming = false;
        if (self.st == .idle or self.st == .terminated) return .ignored;
        const id = messageId(msg) catch return .ignored;
        switch (id) {
            .version => {
                if (self.st != .wait_version) return .ignored;
                const v = decodeVersion(msg) catch return .ignored;
                try out.build(encodeFormats, .{ self.cfg.formats, @as(?u32, null), @as([]const u8, &.{}) });
                self.client_version = v;
                self.st = .wait_formats;
                self.deadline = now_ms +| self.cfg.reply_timeout_ms;
                return .{ .client_version = v };
            },
            .formats => {
                if (self.st != .wait_formats) return .ignored;
                const f = decodeFormats(self.gpa, msg) catch |e| switch (e) {
                    error.OutOfMemory => return e,
                    else => return .ignored,
                };
                defer f.deinit(self.gpa);
                const copy = try rdpsnd.OwnedFormats.dupe(self.gpa, f.formats);
                self.client.deinit(self.gpa);
                self.client = copy;
                const initial = self.initialFormat() orelse {
                    self.terminate();
                    return .terminated;
                };
                try self.sendOpen(initial, now_ms, out);
                return .{ .formats_negotiated = .{ .initial_format = initial } };
            },
            .format_change => {
                switch (self.st) {
                    .wait_open_reply, .recording => {},
                    else => return .ignored,
                }
                const idx = decodeFormatChange(msg) catch return .ignored;
                if (self.pending != idx) return .ignored;
                self.pending = null;
                self.current = idx;
                return .{ .format_confirmed = idx };
            },
            .open_reply => {
                if (self.st != .wait_open_reply) return .ignored;
                const hr = decodeOpenReply(msg) catch return .ignored;
                self.st = if (try isSuccess(hr)) .recording else .open_failed;
                self.deadline = null;
                return .{ .open_result = hr };
            },
            .data_incoming => {
                self.incoming = true;
                return .data_incoming;
            },
            .data => {
                if (self.st != .recording or !after_incoming) return .ignored;
                self.audio.clearRetainingCapacity();
                try self.audio.appendSlice(self.gpa, msg[1..]);
                return .{ .audio = .{ .format = self.current.?, .data = self.audio.items } };
            },
            else => return .ignored,
        }
    }

    /// First server format the client kept (3.2.5.1.5).
    fn initialFormat(self: *const Server) ?u32 {
        for (self.cfg.formats) |sf| {
            for (self.client.list, 0..) |cf, i| {
                if (i > std.math.maxInt(u32)) break;
                if (sf.eql(cf) catch false) return @intCast(i);
            }
        }
        return null;
    }

    fn sendOpen(self: *Server, initial: u32, now_ms: u64, out: *Outbox) Error!void {
        try out.build(encodeOpen, .{Open{
            .frames_per_packet = self.cfg.frames_per_packet,
            .initial_format = initial,
            .capture = self.cfg.capture orelse self.client.list[initial],
        }});
        self.initial = initial;
        self.current = initial;
        self.pending = initial;
        self.st = .wait_open_reply;
        self.deadline = now_ms +| self.cfg.reply_timeout_ms;
    }

    fn terminate(self: *Server) void {
        self.st = .terminated;
        self.deadline = null;
        self.pending = null;
    }

    /// Reply timeouts (3.3.2) for Version, Sound Formats and Open Reply.
    pub fn tick(self: *Server, now_ms: u64, out: *Outbox) Error!Event {
        _ = out;
        const deadline = self.deadline orelse return .none;
        if (now_ms < deadline) return .none;
        switch (self.st) {
            .wait_version, .wait_formats, .wait_open_reply => {
                self.terminate();
                return .terminated;
            },
            else => {
                self.deadline = null;
                return .none;
            },
        }
    }

    pub fn state(self: *const Server) Error!State {
        return self.st;
    }

    pub fn clientVersion(self: *const Server) Error!?u32 {
        return self.client_version;
    }

    pub fn clientFormats(self: *const Server) Error![]const AudioFormat {
        return self.client.list;
    }

    /// Format of incoming Data PDUs: the Open's initialFormat, then each confirmed
    /// Format Change (3.1.1). Null before the Open.
    pub fn currentFormat(self: *const Server) Error!?u32 {
        return self.current;
    }

    /// MS-RDPEAI 3.3.5.3.1. Data stays in the old format until the client confirms.
    pub fn requestFormatChange(self: *Server, new_format: u32, out: *Outbox) Error!void {
        if (self.st != .recording) return error.NotReady;
        if (new_format >= self.client.list.len) return error.FormatIndexOutOfRange;
        if ((self.client_version orelse 0) < version_2) {
            for ([_]?u32{ self.initial, self.current }) |i| {
                if (i) |idx| if (self.client.list[idx].tag == rdpsnd.WAVE_FORMAT_AAC_MS) return error.FormatChangeNotAllowed;
            }
        }
        try out.build(encodeFormatChange, .{new_format});
        self.pending = new_format;
    }

    /// Resends the Open PDU after a failed Open Reply (3.3.5.1.8).
    pub fn reopen(self: *Server, now_ms: u64, out: *Outbox) Error!void {
        if (self.st != .open_failed) return error.NotReady;
        try self.sendOpen(self.initial.?, now_ms, out);
    }
};

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(Formats);
    std.testing.refAllDecls(Server);
}
