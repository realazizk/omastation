//! MS-RDPEA audio output over the rdpsnd static channel and the AUDIO_PLAYBACK_DVC /
//! AUDIO_PLAYBACK_LOSSY_DVC dynamic channels: PDUs, UDP path, encoders, server state machine (3.3.5).
//! Each channel message holds one whole PDU; decoders check BodySize against it.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const Rc4 = @import("../sec/rc4.zig").Rc4;
const g711 = @import("rdpsnd/g711.zig");
const adpcm = @import("rdpsnd/adpcm.zig");
const opus = @import("rdpsnd/opus.zig");
const aac = @import("rdpsnd/aac.zig");
const gsm = @import("rdpsnd/gsm.zig");

const Allocator = std.mem.Allocator;
const Sha1 = std.crypto.hash.Sha1;
const rdpsnd = @This();

pub const Error = error{
    EndOfBuffer,
    UnexpectedMsgType,
    /// BodySize disagrees with the message length.
    BadBodySize,
    /// A field violates a MUST of MS-RDPEA 2.2 (wPackSize, cbSize, ...).
    InvalidPdu,
    /// Does not fit a 16-bit size field.
    TooLarge,
    /// The audio sample MUST exceed four bytes (3.3.5.2.1.1).
    SampleTooShort,
    FormatIndexOutOfRange,
    UnsupportedFormat,
    /// The initialization sequence has not completed (3.1.4.1, 3.3.5.2).
    NotReady,
    /// After Close only Training and Server Audio Formats may follow (3.2.5.2.1.7).
    Closed,
    /// TSSNDCAPS_ALIVE / _VOLUME / _PITCH not advertised (2.2.3, 3.3.5.3.1).
    CapabilityNotNegotiated,
    /// cFragNo has 15 bits (2.2.3.6).
    FragmentNumberTooLarge,
    OutOfMemory,
};

// MS-RDPEA 2.1 Transport

/// Compared case-insensitively (2.1).
pub const static_channel_name = "rdpsnd";
pub const dvc_channel_name = "AUDIO_PLAYBACK_DVC";
/// Over an unreliable UDP transport (2.1 <2>).
pub const lossy_dvc_channel_name = "AUDIO_PLAYBACK_LOSSY_DVC";

pub const Transport = enum {
    static,
    dvc,
    dvc_lossy,
};

pub const TransportOffer = struct {
    /// MS-RDPBCGR 2.2.1.3.4, 2.2.1.8.
    static_joined: bool,
    dvc_ready: bool,
    udp_lossy_ready: bool = false,
};

/// Channel to open first: a DVC, else the static channel (3.1.3 <11>); null
/// for no audio. The lossy DVC needs version 8 and AAC, known only later.
pub fn chooseTransport(offer: TransportOffer) Error!?Transport {
    if (offer.dvc_ready) return .dvc;
    if (offer.static_joined) return .static;
    return null;
}

pub fn channelName(t: Transport) Error![]const u8 {
    return switch (t) {
        .static => static_channel_name,
        .dvc => dvc_channel_name,
        .dvc_lossy => lossy_dvc_channel_name,
    };
}

/// Static names compare case-insensitively (MS-RDPBCGR 2.2.1.3.4.1), DVC names exactly.
pub fn isAudioOutputChannel(name: []const u8) Error!?Transport {
    if (std.ascii.eqlIgnoreCase(name, static_channel_name)) return .static;
    if (std.mem.eql(u8, name, dvc_channel_name)) return .dvc;
    if (std.mem.eql(u8, name, lossy_dvc_channel_name)) return .dvc_lossy;
    return null;
}

/// MS-RDPEA 2.1 <2>: lossy UDP up, both versions at least 8, and AAC.
pub fn useLossyDvc(udp_lossy_ready: bool, client_version: u16, srv_version: u16, format_tag: u16) Error!bool {
    return udp_lossy_ready and client_version >= version_win8 and srv_version >= version_win8 and
        format_tag == WAVE_FORMAT_AAC_MS;
}

// MS-RDPEA 2.2.1 SNDPROLOG

pub const MsgType = enum(u8) {
    close = 0x01, // SNDC_CLOSE
    wave = 0x02, // SNDC_WAVE (WaveInfo PDU)
    set_volume = 0x03, // SNDC_SETVOLUME
    set_pitch = 0x04, // SNDC_SETPITCH
    wave_confirm = 0x05, // SNDC_WAVECONFIRM
    training = 0x06, // SNDC_TRAINING (Training and Training Confirm)
    formats = 0x07, // SNDC_FORMATS (server and client formats)
    crypt_key = 0x08, // SNDC_CRYPTKEY
    wave_encrypt = 0x09, // SNDC_WAVEENCRYPT
    udp_wave = 0x0A, // SNDC_UDPWAVE
    udp_wave_last = 0x0B, // SNDC_UDPWAVELAST
    quality_mode = 0x0C, // SNDC_QUALITYMODE
    wave2 = 0x0D, // SNDC_WAVE2
    _,
};

pub const header_size = 4;

/// RDPSND PDU Header (SNDPROLOG, 2.2.1).
pub const Header = struct {
    msg_type: MsgType,
    /// bPad: MUST be ignored on receipt.
    pad: u8 = 0,
    /// Size of the data after the header (for SNDC_WAVE: see 2.2.3.3).
    body_size: u16,
};

pub fn encodeHeader(w: *bytes.Writer, h: Header) !void {
    try w.byte(@backingInt(h.msg_type));
    try w.byte(h.pad);
    try w.u16le(h.body_size);
}

pub fn decodeHeader(msg: []const u8) Error!Header {
    if (msg.len < header_size) return error.EndOfBuffer;
    return .{ .msg_type = @fromBackingInt(@intCast(msg[0])), .pad = msg[1], .body_size = std.mem.readInt(u16, msg[2..4], .little) };
}

fn writeHeader(w: *bytes.Writer, t: MsgType, pad: u8, body_size: usize) !void {
    if (body_size > 0xFFFF) return error.TooLarge;
    try encodeHeader(w, .{ .msg_type = t, .pad = pad, .body_size = @intCast(body_size) });
}

const Pdu = struct { h: Header, body: []const u8 };

/// BodySize must cover the rest of the message (2.2.1).
fn expectPdu(msg: []const u8, t: MsgType) Error!Pdu {
    const h = try decodeHeader(msg);
    if (h.msg_type != t) return error.UnexpectedMsgType;
    if (h.body_size != msg.len - header_size) return error.BadBodySize;
    return .{ .h = h, .body = msg[header_size..] };
}

fn expectFixedPdu(msg: []const u8, t: MsgType, size: usize) Error!Pdu {
    const p = try expectPdu(msg, t);
    if (p.body.len != size) return error.BadBodySize;
    return p;
}

// Capabilities, versions, quality (2.2.2.2, 2.2.2.3, <3>, <6>)

/// dwFlags of the Client Audio Formats and Version PDU (2.2.2.2).
pub const TSSNDCAPS_ALIVE: u32 = 0x00000001;
pub const TSSNDCAPS_VOLUME: u32 = 0x00000002;
pub const TSSNDCAPS_PITCH: u32 = 0x00000004;

/// Protocol versions (2.2.2.1 <3>, 2.2.2.2 <6>).
pub const version_xp: u16 = 0x02;
pub const version_xp_sp1: u16 = 0x05; // also Server 2003, Vista, Server 2008
pub const version_win7: u16 = 0x06; // Windows 7, Server 2008 R2
pub const version_win8: u16 = 0x08; // Windows 8 .. Server 2019
pub const server_version: u16 = version_win8;

/// wQualityMode (2.2.2.3).
pub const QualityMode = enum(u16) {
    dynamic = 0x0000, // DYNAMIC_QUALITY
    medium = 0x0001, // MEDIUM_QUALITY
    high = 0x0002, // HIGH_QUALITY
    _,
};

/// Both versions at least 6 (2.2.2.3, 3.1.1.4).
pub fn qualityModeUsed(client_version: u16, srv_version: u16) Error!bool {
    return client_version >= version_win7 and srv_version >= version_win7;
}

/// Wave2 replaces WaveInfo + Wave when both versions are at least 8 (1.3.2.2).
pub fn wave2Used(client_version: u16, srv_version: u16) Error!bool {
    return client_version >= version_win8 and srv_version >= version_win8;
}

// AUDIO_FORMAT (2.2.2.1.1) and WAVE format tags (RFC 2361, <4>)

pub const WAVE_FORMAT_UNKNOWN: u16 = 0x0000;
pub const WAVE_FORMAT_PCM: u16 = 0x0001;
pub const WAVE_FORMAT_ADPCM: u16 = 0x0002;
pub const WAVE_FORMAT_IEEE_FLOAT: u16 = 0x0003;
pub const WAVE_FORMAT_ALAW: u16 = 0x0006;
pub const WAVE_FORMAT_MULAW: u16 = 0x0007;
pub const WAVE_FORMAT_DVI_ADPCM: u16 = 0x0011;
pub const WAVE_FORMAT_DSPGROUP_TRUESPEECH: u16 = 0x0022;
pub const WAVE_FORMAT_GSM610: u16 = 0x0031;
pub const WAVE_FORMAT_MSG723: u16 = 0x0042;
pub const WAVE_FORMAT_MPEGLAYER3: u16 = 0x0055;
pub const WAVE_FORMAT_WMAUDIO2: u16 = 0x0161;
/// Microsoft AAC (<4>; Windows 8 and later).
pub const WAVE_FORMAT_AAC_MS: u16 = 0xA106;
/// Opus (FreeRDP extension, not used by Windows).
pub const WAVE_FORMAT_OPUS: u16 = 0x704F;
pub const WAVE_FORMAT_EXTENSIBLE: u16 = 0xFFFE;

pub const audio_format_fixed_size = 18;

/// AUDIO_FORMAT (2.2.2.1.1), a WAVEFORMATEX.
pub const AudioFormat = struct {
    tag: u16,
    channels: u16,
    samples_per_sec: u32,
    avg_bytes_per_sec: u32,
    block_align: u16,
    bits_per_sample: u16,
    /// cbSize bytes; decoded formats point into the message.
    extra: []const u8 = &.{},

    pub fn encodedSize(f: AudioFormat) Error!usize {
        return audio_format_fixed_size + f.extra.len;
    }

    pub fn eql(a: AudioFormat, b: AudioFormat) Error!bool {
        return a.tag == b.tag and a.channels == b.channels and a.samples_per_sec == b.samples_per_sec and
            a.avg_bytes_per_sec == b.avg_bytes_per_sec and a.block_align == b.block_align and
            a.bits_per_sample == b.bits_per_sample and std.mem.eql(u8, a.extra, b.extra);
    }
};

pub fn encodeAudioFormat(w: *bytes.Writer, f: AudioFormat) !void {
    if (f.extra.len > 0xFFFF) return error.TooLarge;
    try w.u16le(f.tag);
    try w.u16le(f.channels);
    try w.u32le(f.samples_per_sec);
    try w.u32le(f.avg_bytes_per_sec);
    try w.u16le(f.block_align);
    try w.u16le(f.bits_per_sample);
    try w.u16le(@intCast(f.extra.len));
    try w.bytes(f.extra);
}

/// Read one AUDIO_FORMAT; `extra` points into the reader's buffer.
pub fn decodeAudioFormat(r: *bytes.Reader) Error!AudioFormat {
    try r.need(audio_format_fixed_size);
    var f: AudioFormat = .{
        .tag = try r.u16le(),
        .channels = try r.u16le(),
        .samples_per_sec = try r.u32le(),
        .avg_bytes_per_sec = try r.u32le(),
        .block_align = try r.u16le(),
        .bits_per_sample = try r.u16le(),
    };
    const cb = try r.u16le();
    f.extra = try r.bytes(cb);
    return f;
}

pub fn pcmFormat(channels: u16, samples_per_sec: u32, bits_per_sample: u16) Error!AudioFormat {
    if (channels == 0 or samples_per_sec == 0 or bits_per_sample == 0 or bits_per_sample % 8 != 0)
        return error.UnsupportedFormat;
    const ba = std.math.cast(u16, @as(u32, channels) * (bits_per_sample / 8)) orelse return error.UnsupportedFormat;
    const avg = std.math.cast(u32, @as(u64, samples_per_sec) * ba) orelse return error.UnsupportedFormat;
    return .{ .tag = WAVE_FORMAT_PCM, .channels = channels, .samples_per_sec = samples_per_sec, .avg_bytes_per_sec = avg, .block_align = ba, .bits_per_sample = bits_per_sample };
}

pub fn g711Format(tag: u16, channels: u16, samples_per_sec: u32) Error!AudioFormat {
    if (tag != WAVE_FORMAT_ALAW and tag != WAVE_FORMAT_MULAW) return error.UnsupportedFormat;
    if (channels == 0 or samples_per_sec == 0) return error.UnsupportedFormat;
    const avg = std.math.cast(u32, @as(u64, samples_per_sec) * channels) orelse return error.UnsupportedFormat;
    return .{ .tag = tag, .channels = channels, .samples_per_sec = samples_per_sec, .avg_bytes_per_sec = avg, .block_align = channels, .bits_per_sample = 8 };
}

/// wSamplesPerBlock, wNumCoef and the 7 standard coefficient pairs.
pub const MsAdpcmExtra = [32]u8;

/// Truncated, as in MS-RDPEA 4.1.1.
fn blockAvgBytes(samples_per_sec: u32, block_align: u16, spb: usize) Error!u32 {
    return std.math.cast(u32, @as(u64, samples_per_sec) * block_align / spb) orelse error.UnsupportedFormat;
}

/// As Windows sends it (4.1.1); `extra_buf` receives the extra data the format points to.
pub fn msAdpcmFormat(channels: u16, samples_per_sec: u32, block_align: u16, extra_buf: *MsAdpcmExtra) Error!AudioFormat {
    if (samples_per_sec == 0) return error.UnsupportedFormat;
    _ = try MsAdpcmEncoder.init(channels, block_align);
    const spb = std.math.cast(u16, adpcm.msSamplesPerBlock(channels, block_align)) orelse return error.UnsupportedFormat;
    std.mem.writeInt(u16, extra_buf[0..2], spb, .little);
    std.mem.writeInt(u16, extra_buf[2..4], adpcm.ms_coef1.len, .little);
    for (adpcm.ms_coef1, adpcm.ms_coef2, 0..) |c1, c2, i| {
        std.mem.writeInt(i16, extra_buf[4 + 4 * i ..][0..2], c1, .little);
        std.mem.writeInt(i16, extra_buf[6 + 4 * i ..][0..2], c2, .little);
    }
    return .{
        .tag = WAVE_FORMAT_ADPCM,
        .channels = channels,
        .samples_per_sec = samples_per_sec,
        .avg_bytes_per_sec = try blockAvgBytes(samples_per_sec, block_align, spb),
        .block_align = block_align,
        .bits_per_sample = 4,
        .extra = extra_buf,
    };
}

/// As Windows sends it (4.1.1).
pub fn imaAdpcmFormat(channels: u16, samples_per_sec: u32, block_align: u16, extra_buf: *[2]u8) Error!AudioFormat {
    if (samples_per_sec == 0) return error.UnsupportedFormat;
    _ = try ImaAdpcmEncoder.init(channels, block_align);
    const spb = std.math.cast(u16, adpcm.imaSamplesPerBlock(channels, block_align)) orelse return error.UnsupportedFormat;
    std.mem.writeInt(u16, extra_buf, spb, .little);
    return .{
        .tag = WAVE_FORMAT_DVI_ADPCM,
        .channels = channels,
        .samples_per_sec = samples_per_sec,
        .avg_bytes_per_sec = try blockAvgBytes(samples_per_sec, block_align, spb),
        .block_align = block_align,
        .bits_per_sample = 4,
        .extra = extra_buf,
    };
}

/// From the extra data, else computed from nBlockAlign for ADPCM.
pub fn samplesPerBlock(f: AudioFormat) Error!u32 {
    const spb: u32 = switch (f.tag) {
        WAVE_FORMAT_ADPCM, WAVE_FORMAT_DVI_ADPCM, WAVE_FORMAT_GSM610 => if (f.extra.len >= 2)
            std.mem.readInt(u16, f.extra[0..2], .little)
        else switch (f.tag) {
            WAVE_FORMAT_ADPCM => blk: {
                if (f.channels == 0 or f.block_align <= 7 * @as(u32, f.channels)) return error.UnsupportedFormat;
                break :blk @intCast(adpcm.msSamplesPerBlock(f.channels, f.block_align));
            },
            WAVE_FORMAT_DVI_ADPCM => blk: {
                if (f.channels == 0 or f.block_align <= 4 * @as(u32, f.channels)) return error.UnsupportedFormat;
                break :blk @intCast(adpcm.imaSamplesPerBlock(f.channels, f.block_align));
            },
            else => return error.UnsupportedFormat,
        },
        else => return error.UnsupportedFormat,
    };
    if (spb == 0) return error.UnsupportedFormat;
    return spb;
}

/// Play time in milliseconds (truncated); block codecs count whole blocks.
pub fn durationMs(f: AudioFormat, size: usize) Error!u32 {
    if (f.samples_per_sec == 0) return error.UnsupportedFormat;
    const ms: u64 = switch (f.tag) {
        WAVE_FORMAT_ADPCM, WAVE_FORMAT_DVI_ADPCM, WAVE_FORMAT_GSM610 => blk: {
            if (f.block_align == 0) return error.UnsupportedFormat;
            const frames = @as(u64, size / f.block_align) * try samplesPerBlock(f);
            break :blk frames * 1000 / f.samples_per_sec;
        },
        else => blk: {
            if (f.bits_per_sample == 0 or f.channels == 0) return error.UnsupportedFormat;
            const den = @as(u64, f.bits_per_sample) * f.channels * f.samples_per_sec;
            break :blk @as(u64, size) * 8000 / den;
        },
    };
    return std.math.cast(u32, ms) orelse std.math.maxInt(u32);
}

/// Rounded down to whole nBlockAlign blocks.
pub fn pcmBytesFor(f: AudioFormat, ms: u32) Error!usize {
    if (f.samples_per_sec == 0 or f.block_align == 0) return error.UnsupportedFormat;
    const frames = @as(u64, f.samples_per_sec) * ms / 1000;
    return std.math.cast(usize, frames * f.block_align) orelse error.TooLarge;
}

/// MS-RDPEA 2.2.2.2 <5>: AAC only at nAvgBytesPerSec 12000.
pub fn isAacUsable(f: AudioFormat) Error!bool {
    return f.tag == WAVE_FORMAT_AAC_MS and f.avg_bytes_per_sec == 12000;
}

/// Bounds the resampler's allocations.
pub const min_sample_rate: u32 = 1000;
pub const max_sample_rate: u32 = 384000;

/// nBlockAlign and wSamplesPerBlock must match how the client decodes. Opus is excluded: one
/// packet per wave does not fit 186 ms waves.
pub fn canEncode(f: AudioFormat) Error!bool {
    if (f.channels == 0 or f.block_align == 0 or f.samples_per_sec == 0) return false;
    if (f.channels > 2) return false;
    if (f.samples_per_sec < min_sample_rate or f.samples_per_sec > max_sample_rate) return false;
    switch (f.tag) {
        WAVE_FORMAT_PCM => return (f.bits_per_sample == 8 or f.bits_per_sample == 16) and
            f.block_align == f.channels * f.bits_per_sample / 8,
        WAVE_FORMAT_ALAW, WAVE_FORMAT_MULAW => return f.bits_per_sample == 8 and f.block_align == f.channels,
        WAVE_FORMAT_ADPCM => {
            var extra: MsAdpcmExtra = undefined;
            const want = msAdpcmFormat(f.channels, f.samples_per_sec, f.block_align, &extra) catch return false;
            // The client decodes with the coefficients of the extra data.
            return f.extra.len == 0 or std.mem.eql(u8, f.extra, want.extra);
        },
        WAVE_FORMAT_DVI_ADPCM => {
            var extra: [2]u8 = undefined;
            const want = imaAdpcmFormat(f.channels, f.samples_per_sec, f.block_align, &extra) catch return false;
            return f.extra.len == 0 or std.mem.startsWith(u8, f.extra, want.extra);
        },
        WAVE_FORMAT_GSM610 => return f.channels == 1 and f.block_align == gsm610_block_align and
            (f.extra.len < 2 or std.mem.readInt(u16, f.extra[0..2], .little) == gsm610_samples_per_block),
        WAVE_FORMAT_AAC_MS => return aac.isAacSampleRate(f.samples_per_sec) and
            f.avg_bytes_per_sec >= aac.min_bytes_per_sec and f.avg_bytes_per_sec <= aac.max_bytes_per_sec,
        else => return false,
    }
}

/// GSM 6.10 as Windows describes it: two WAV49 frames per block, mono.
pub const gsm610_block_align: u16 = 65;
pub const gsm610_samples_per_block: u16 = 320;

// The formats a Windows server offers, and how it picks one

fn msExtra(comptime spb: u16) [32]u8 {
    var e: [32]u8 = undefined;
    std.mem.writeInt(u16, e[0..2], spb, .little);
    std.mem.writeInt(u16, e[2..4], adpcm.ms_coef1.len, .little);
    for (adpcm.ms_coef1, adpcm.ms_coef2, 0..) |c1, c2, i| {
        std.mem.writeInt(i16, e[4 + 4 * i ..][0..2], c1, .little);
        std.mem.writeInt(i16, e[6 + 4 * i ..][0..2], c2, .little);
    }
    return e;
}

fn le16(comptime v: u16) [2]u8 {
    return .{ @truncate(v), @truncate(v >> 8) };
}

const ms_extra_2036 = msExtra(2036);
const ms_extra_1012 = msExtra(1012);
const ms_extra_500 = msExtra(500);
const ima_extra_2041 = le16(2041);
const ima_extra_1017 = le16(1017);
const ima_extra_505 = le16(505);
const gsm_extra_320 = le16(gsm610_samples_per_block);

fn af(tag: u16, channels: u16, rate: u32, avg: u32, block_align: u16, bits: u16, extra: []const u8) AudioFormat {
    return .{ .tag = tag, .channels = channels, .samples_per_sec = rate, .avg_bytes_per_sec = avg, .block_align = block_align, .bits_per_sample = bits, .extra = extra };
}

fn aacFormat(avg: u32) AudioFormat {
    return af(WAVE_FORMAT_AAC_MS, 2, 44100, avg, 4, 16, &.{});
}

/// The mix format every block is cut from, as on a Windows server.
pub const engine_format = af(WAVE_FORMAT_PCM, 2, 44100, 176400, 4, 16, &.{});

/// The AAC formats a Windows server offers first when it has an AAC encoder.
pub const aac_server_formats = [_]AudioFormat{
    aacFormat(24000), aacFormat(20000), aacFormat(16000), aacFormat(12000),
    aacFormat(8000),  aacFormat(6000),  aacFormat(4000),  aacFormat(2000),
};

/// The rest of a Windows server's list, byte for byte, by nAvgBytesPerSec descending.
pub const acm_server_formats = [_]AudioFormat{
    engine_format,
    af(WAVE_FORMAT_ADPCM, 2, 44100, 44359, 2048, 4, &ms_extra_2036),
    af(WAVE_FORMAT_DVI_ADPCM, 2, 44100, 44251, 2048, 4, &ima_extra_2041),
    af(WAVE_FORMAT_ALAW, 2, 22050, 44100, 2, 8, &.{}),
    af(WAVE_FORMAT_ADPCM, 2, 22050, 22311, 1024, 4, &ms_extra_1012),
    af(WAVE_FORMAT_DVI_ADPCM, 2, 22050, 22201, 1024, 4, &ima_extra_1017),
    af(WAVE_FORMAT_ADPCM, 1, 44100, 22179, 1024, 4, &ms_extra_2036),
    af(WAVE_FORMAT_DVI_ADPCM, 1, 44100, 22125, 1024, 4, &ima_extra_2041),
    af(WAVE_FORMAT_ADPCM, 2, 11025, 11289, 512, 4, &ms_extra_500),
    af(WAVE_FORMAT_DVI_ADPCM, 2, 11025, 11177, 512, 4, &ima_extra_505),
    af(WAVE_FORMAT_ADPCM, 1, 22050, 11155, 512, 4, &ms_extra_1012),
    af(WAVE_FORMAT_DVI_ADPCM, 1, 22050, 11100, 512, 4, &ima_extra_1017),
    af(WAVE_FORMAT_GSM610, 1, 44100, 8957, 65, 0, &gsm_extra_320),
    af(WAVE_FORMAT_ADPCM, 2, 8000, 8192, 512, 4, &ms_extra_500),
    af(WAVE_FORMAT_DVI_ADPCM, 2, 8000, 8110, 512, 4, &ima_extra_505),
    af(WAVE_FORMAT_ADPCM, 1, 11025, 5644, 256, 4, &ms_extra_500),
    af(WAVE_FORMAT_DVI_ADPCM, 1, 11025, 5588, 256, 4, &ima_extra_505),
    af(WAVE_FORMAT_GSM610, 1, 22050, 4478, 65, 0, &gsm_extra_320),
    af(WAVE_FORMAT_ADPCM, 1, 8000, 4096, 256, 4, &ms_extra_500),
    af(WAVE_FORMAT_DVI_ADPCM, 1, 8000, 4055, 256, 4, &ima_extra_505),
    af(WAVE_FORMAT_GSM610, 1, 11025, 2239, 65, 0, &gsm_extra_320),
    af(WAVE_FORMAT_GSM610, 1, 8000, 1625, 65, 0, &gsm_extra_320),
};

/// Windows' whole Server Audio Formats list (with the AAC encoder): 30
/// formats. No 48 kHz, no Opus, no mu-law; PCM only at 44.1 kHz stereo.
pub const windows_server_formats = aac_server_formats ++ acm_server_formats;

pub const default_server_formats = windows_server_formats;

/// Windows' list without the AAC encoder.
pub const server_formats_without_aac = acm_server_formats;

/// Windows' default RdpsndMaxBandwidth: Dynamic mode never rates the client above it.
pub const default_max_bandwidth: u32 = 22201;

/// AllowedAudioQualityMode policy: the best mode a client may ask for; others get
/// DYNAMIC_QUALITY. Windows allows Dynamic only by default.
pub const QualityLimit = enum {
    dynamic,
    medium,
    high,

    pub fn allows(limit: QualityLimit, mode: QualityMode) bool {
        return switch (mode) {
            .dynamic => true,
            .medium => limit != .dynamic,
            .high => limit == .high,
            _ => false,
        };
    }
};

/// Values of 3 and above count as Dynamic.
pub fn effectiveQuality(requested: QualityMode, limit: QualityLimit) QualityMode {
    if (@backingInt(requested) >= 3) return .dynamic;
    return if (limit.allows(requested)) requested else .dynamic;
}

/// Frames of 44.1 kHz audio per wave: 8192 (186 ms) in Dynamic mode, 2205
/// (50 ms) in Medium and High, 1024 (one AAC frame) with AAC.
pub const dynamic_block_frames: u32 = 8192;
pub const fixed_block_frames: u32 = 2205;
pub const aac_block_frames: u32 = 1024;

/// Medium sends MS-ADPCM 44.1 kHz mono, High PCM 44.1 kHz stereo.
pub fn preferredFormat(mode: QualityMode) ?AudioFormat {
    return switch (mode) {
        .medium => acm_server_formats[6],
        .high => engine_format,
        else => null,
    };
}

/// Windows' filter, from the last entry: drop a format a later one beats on rate (then channels),
/// keep AAC, drop MP3 when WMA follows. Indices stay (wFormatNo is the client's).
pub fn keepClientFormats(formats: []const AudioFormat, kept: []bool) void {
    std.debug.assert(kept.len == formats.len);
    var max_rate: u32 = 0;
    var max_ch: u16 = 0;
    var wma = false;
    var i = formats.len;
    while (i > 0) {
        i -= 1;
        const f = formats[i];
        kept[i] = true;
        if (f.tag == WAVE_FORMAT_AAC_MS) continue;
        if (f.tag == WAVE_FORMAT_MPEGLAYER3) {
            if (wma) {
                kept[i] = false;
                continue;
            }
        } else if (f.tag == WAVE_FORMAT_WMAUDIO2) wma = true;
        if (max_rate > f.samples_per_sec or (max_rate == f.samples_per_sec and max_ch > f.channels)) {
            kept[i] = false;
            continue;
        }
        max_ch = f.channels;
        max_rate = f.samples_per_sec;
    }
}

/// A kept format a converter can produce (AAC is chosen separately).
fn convertible(formats: []const AudioFormat, kept: []const bool, i: usize) bool {
    const f = formats[i];
    return kept[i] and f.tag != WAVE_FORMAT_AAC_MS and (canEncode(f) catch false);
}

fn index(i: usize) ?u16 {
    return std.math.cast(u16, i);
}

/// AAC at 12000 B/s (2.2.2.2 <5>) and 44.1 kHz, so a 1024-frame block is one access unit.
pub fn chooseAac(formats: []const AudioFormat, kept: []const bool) ?u16 {
    for (formats, 0..) |f, i| {
        if (!kept[i] or !(isAacUsable(f) catch false) or !(canEncode(f) catch false)) continue;
        if (f.samples_per_sec != engine_format.samples_per_sec) continue;
        return index(i);
    }
    return null;
}

/// The first usable format within `bandwidth` B/s, else the last usable one.
pub fn chooseProperFormat(formats: []const AudioFormat, kept: []const bool, bandwidth: u32) ?u16 {
    var last: ?u16 = null;
    for (formats, 0..) |f, i| {
        if (!convertible(formats, kept, i)) continue;
        last = index(i) orelse break;
        if (f.avg_bytes_per_sec <= bandwidth) return last;
    }
    return last;
}

/// Medium and High: the client format matching the mode's preferred format.
pub fn findFormatForQuality(formats: []const AudioFormat, kept: []const bool, mode: QualityMode) ?u16 {
    const want = preferredFormat(mode) orelse return null;
    for (formats, 0..) |f, i| {
        if (!convertible(formats, kept, i)) continue;
        if (f.tag == want.tag and f.channels == want.channels and f.samples_per_sec == want.samples_per_sec and
            f.avg_bytes_per_sec == want.avg_bytes_per_sec and f.block_align == want.block_align) return index(i);
    }
    return null;
}

/// Windows' fallback when a converter cannot be opened.
pub fn findNativeFormat(formats: []const AudioFormat) ?u16 {
    for (formats, 0..) |f, i| {
        if (f.tag == WAVE_FORMAT_PCM and f.channels == 2 and f.samples_per_sec == 44100 and
            f.avg_bytes_per_sec == 176400 and f.block_align == 4 and f.bits_per_sample == 16 and f.extra.len == 0) return index(i);
    }
    return null;
}

// Initialization sequence PDUs (2.2.2)

pub const formats_fixed_body = 20;

/// Server Audio Formats and Version PDU (2.2.2.1); unused fields are sent as 0.
pub const ServerFormats = struct {
    header_pad: u8 = 0,
    flags: u32 = 0,
    volume: u32 = 0,
    pitch: u32 = 0,
    dgram_port: u16 = 0,
    /// cLastBlockConfirmed: the first data PDU uses this + 1 (3.3.5.2.1.1).
    last_block_confirmed: u8,
    version: u16,
    pad: u8 = 0,
    formats: []const AudioFormat,

    /// Frees `formats` of a decoded PDU.
    pub fn deinit(self: ServerFormats, gpa: Allocator) void {
        gpa.free(self.formats);
    }
};

/// Client Audio Formats and Version PDU (2.2.2.2).
pub const ClientFormats = struct {
    header_pad: u8 = 0,
    /// TSSNDCAPS_* (ALIVE must be set for audio data to be sent).
    flags: u32,
    /// Initial volume, valid with TSSNDCAPS_VOLUME (low word left).
    volume: u32 = 0,
    /// Valid with TSSNDCAPS_PITCH; unused by the server (3.3.5.1.1.2).
    pitch: u32 = 0,
    /// wDGramPort, big-endian on the wire; 0 = no UDP.
    dgram_port: u16 = 0,
    last_block_confirmed: u8 = 0,
    version: u16,
    pad: u8 = 0,
    /// Subset of the server list; wFormatNo indexes this list.
    formats: []const AudioFormat,

    pub fn deinit(self: ClientFormats, gpa: Allocator) void {
        gpa.free(self.formats);
    }
};

/// Shared layout of both formats PDUs; wDGramPort is big-endian in both.
const FormatsPdu = struct {
    header_pad: u8,
    flags: u32,
    volume: u32,
    pitch: u32,
    dgram_port: u16,
    last_block_confirmed: u8,
    version: u16,
    pad: u8,
    formats: []const AudioFormat,
};

fn formatListSize(formats: []const AudioFormat) Error!usize {
    if (formats.len > 0xFFFF) return error.TooLarge;
    var n: usize = 0;
    for (formats) |f| {
        if (f.extra.len > 0xFFFF) return error.TooLarge;
        n += try f.encodedSize();
    }
    return n;
}

fn encodeFormatsPdu(w: *bytes.Writer, p: FormatsPdu) !void {
    try writeHeader(w, .formats, p.header_pad, formats_fixed_body + try formatListSize(p.formats));
    try w.u32le(p.flags);
    try w.u32le(p.volume);
    try w.u32le(p.pitch);
    try w.u16be(p.dgram_port);
    try w.u16le(@intCast(p.formats.len));
    try w.byte(p.last_block_confirmed);
    try w.u16le(p.version);
    try w.byte(p.pad);
    for (p.formats) |f| try encodeAudioFormat(w, f);
}

/// Bytes after the format list are ignored (nothing defines them).
fn decodeFormatsPdu(gpa: Allocator, msg: []const u8) Error!FormatsPdu {
    const p = try expectPdu(msg, .formats);
    var r = bytes.Reader.init(p.body);
    const flags = try r.u32le();
    const volume = try r.u32le();
    const pitch = try r.u32le();
    const port = try r.u16be();
    const count = try r.u16le();
    const lbc = try r.byte();
    const version = try r.u16le();
    const pad = try r.byte();
    if (@as(usize, count) * audio_format_fixed_size > r.remaining()) return error.EndOfBuffer;
    const list = try gpa.alloc(AudioFormat, count);
    errdefer gpa.free(list);
    for (list) |*f| f.* = try decodeAudioFormat(&r);
    return .{ .header_pad = p.h.pad, .flags = flags, .volume = volume, .pitch = pitch, .dgram_port = port, .last_block_confirmed = lbc, .version = version, .pad = pad, .formats = list };
}

pub fn encodeServerFormats(w: *bytes.Writer, pdu: ServerFormats) !void {
    try encodeFormatsPdu(w, .{ .header_pad = pdu.header_pad, .flags = pdu.flags, .volume = pdu.volume, .pitch = pdu.pitch, .dgram_port = pdu.dgram_port, .last_block_confirmed = pdu.last_block_confirmed, .version = pdu.version, .pad = pdu.pad, .formats = pdu.formats });
}

/// Client side and tests; formats are allocated, their `extra` points into `msg`.
pub fn decodeServerFormats(gpa: Allocator, msg: []const u8) Error!ServerFormats {
    const p = try decodeFormatsPdu(gpa, msg);
    return .{ .header_pad = p.header_pad, .flags = p.flags, .volume = p.volume, .pitch = p.pitch, .dgram_port = p.dgram_port, .last_block_confirmed = p.last_block_confirmed, .version = p.version, .pad = p.pad, .formats = p.formats };
}

pub fn encodeClientFormats(w: *bytes.Writer, pdu: ClientFormats) !void {
    try encodeFormatsPdu(w, .{ .header_pad = pdu.header_pad, .flags = pdu.flags, .volume = pdu.volume, .pitch = pdu.pitch, .dgram_port = pdu.dgram_port, .last_block_confirmed = pdu.last_block_confirmed, .version = pdu.version, .pad = pdu.pad, .formats = pdu.formats });
}

/// The formats are allocated; their `extra` points into `msg`.
pub fn decodeClientFormats(gpa: Allocator, msg: []const u8) Error!ClientFormats {
    const p = try decodeFormatsPdu(gpa, msg);
    return .{ .header_pad = p.header_pad, .flags = p.flags, .volume = p.volume, .pitch = p.pitch, .dgram_port = p.dgram_port, .last_block_confirmed = p.last_block_confirmed, .version = p.version, .pad = p.pad, .formats = p.formats };
}

/// Quality Mode PDU (2.2.2.3).
pub const QualityModePdu = struct {
    header_pad: u8 = 0,
    mode: QualityMode,
    reserved: u16 = 0,
};

pub fn encodeQualityMode(w: *bytes.Writer, pdu: QualityModePdu) !void {
    try writeHeader(w, .quality_mode, pdu.header_pad, 4);
    try w.u16le(@backingInt(pdu.mode));
    try w.u16le(pdu.reserved);
}

pub fn decodeQualityMode(msg: []const u8) Error!QualityModePdu {
    const p = try expectFixedPdu(msg, .quality_mode, 4);
    return .{ .header_pad = p.h.pad, .mode = @fromBackingInt(@intCast(std.mem.readInt(u16, p.body[0..2], .little))), .reserved = std.mem.readInt(u16, p.body[2..4], .little) };
}

/// Crypt Key PDU (SNDCRYPT, 2.2.2.4).
pub const CryptKey = struct {
    header_pad: u8 = 0,
    reserved: u32 = 0,
    seed: [32]u8,
};

pub fn encodeCryptKey(w: *bytes.Writer, pdu: CryptKey) !void {
    try writeHeader(w, .crypt_key, pdu.header_pad, 4 + 32);
    try w.u32le(pdu.reserved);
    try w.bytes(&pdu.seed);
}

pub fn decodeCryptKey(msg: []const u8) Error!CryptKey {
    const p = try expectFixedPdu(msg, .crypt_key, 4 + 32);
    return .{ .header_pad = p.h.pad, .reserved = std.mem.readInt(u32, p.body[0..4], .little), .seed = p.body[4..36].* };
}

// Data sequence PDUs (2.2.3)

/// Training PDU (SNDTRAINING, 2.2.3.1).
pub const Training = struct {
    header_pad: u8 = 0,
    timestamp: u16,
    /// Size of the whole PDU when `data` is not empty, else 0 (MUST).
    pack_size: u16,
    data: []const u8 = &.{},
};

const max_training_data = 0xFFFF - 8;

fn trainingPackSize(data_len: usize) u16 {
    return if (data_len == 0) 0 else @intCast(header_size + 4 + data_len);
}

pub fn encodeTraining(w: *bytes.Writer, header_pad: u8, timestamp: u16, data: []const u8) !void {
    if (data.len > max_training_data) return error.TooLarge;
    try writeHeader(w, .training, header_pad, 4 + data.len);
    try w.u16le(timestamp);
    try w.u16le(trainingPackSize(data.len));
    try w.bytes(data);
}

pub fn decodeTraining(msg: []const u8) Error!Training {
    const p = try expectPdu(msg, .training);
    if (p.body.len < 4) return error.EndOfBuffer;
    const t: Training = .{
        .header_pad = p.h.pad,
        .timestamp = std.mem.readInt(u16, p.body[0..2], .little),
        .pack_size = std.mem.readInt(u16, p.body[2..4], .little),
        .data = p.body[4..],
    };
    if (t.pack_size != trainingPackSize(t.data.len)) return error.InvalidPdu;
    return t;
}

/// Training Confirm PDU (2.2.3.2): echoes wTimeStamp and wPackSize.
pub const TrainingConfirm = struct {
    header_pad: u8 = 0,
    timestamp: u16,
    pack_size: u16,
};

pub fn encodeTrainingConfirm(w: *bytes.Writer, pdu: TrainingConfirm) !void {
    try writeHeader(w, .training, pdu.header_pad, 4);
    try w.u16le(pdu.timestamp);
    try w.u16le(pdu.pack_size);
}

pub fn decodeTrainingConfirm(msg: []const u8) Error!TrainingConfirm {
    const p = try expectFixedPdu(msg, .training, 4);
    return .{ .header_pad = p.h.pad, .timestamp = std.mem.readInt(u16, p.body[0..2], .little), .pack_size = std.mem.readInt(u16, p.body[2..4], .little) };
}

/// WaveInfo PDU fields (SNDWAVINFO, 2.2.3.3).
pub const WaveInfo = struct {
    header_pad: u8 = 0,
    timestamp: u16,
    format_no: u16,
    block_no: u8,
    pad: u24 = 0,
};

pub const WaveInfoPdu = struct {
    info: WaveInfo,
    /// BodySize = audio sample size + 8 (3.3.5.2.1.1).
    body_size: u16,
    first4: [4]u8,

    pub fn sampleSize(self: WaveInfoPdu) Error!usize {
        if (self.body_size <= 8 + 4) return error.InvalidPdu;
        return self.body_size - 8;
    }
};

pub const wave_info_size = 16;

const max_wave_sample = 0xFFFF - 8;

/// The rest of the sample goes in the Wave PDU that MUST follow (encodeWave).
pub fn encodeWaveInfo(w: *bytes.Writer, info: WaveInfo, sample: []const u8) !void {
    if (sample.len <= 4) return error.SampleTooShort;
    if (sample.len > max_wave_sample) return error.TooLarge;
    try writeHeader(w, .wave, info.header_pad, sample.len + 8);
    try w.u16le(info.timestamp);
    try w.u16le(info.format_no);
    try w.byte(info.block_no);
    try writeU24(w, info.pad);
    try w.bytes(sample[0..4]);
}

fn writeU24(w: *bytes.Writer, v: u24) !void {
    try w.bytes(&.{ @truncate(v), @truncate(v >> 8), @truncate(v >> 16) });
}

fn readU24(b: *const [3]u8) u24 {
    return std.mem.readInt(u24, b, .little);
}

/// Exactly 16 bytes; BodySize announces a sample of more than four bytes (3.3.5.2.1.1).
pub fn decodeWaveInfo(msg: []const u8) Error!WaveInfoPdu {
    const h = try decodeHeader(msg);
    if (h.msg_type != .wave) return error.UnexpectedMsgType;
    if (msg.len < wave_info_size) return error.EndOfBuffer;
    if (msg.len > wave_info_size) return error.InvalidPdu;
    const p: WaveInfoPdu = .{
        .info = .{
            .header_pad = h.pad,
            .timestamp = std.mem.readInt(u16, msg[4..6], .little),
            .format_no = std.mem.readInt(u16, msg[6..8], .little),
            .block_no = msg[8],
            .pad = readU24(msg[9..12]),
        },
        .body_size = h.body_size,
        .first4 = msg[12..16].*,
    };
    _ = try p.sampleSize();
    return p;
}

/// Wave PDU (2.2.3.4): bPad 0x00000000, then sample[4..].
pub fn encodeWave(w: *bytes.Writer, sample: []const u8) !void {
    if (sample.len <= 4) return error.SampleTooShort;
    if (sample.len > max_wave_sample) return error.TooLarge;
    try w.zeros(4);
    try w.bytes(sample[4..]);
}

/// The WaveInfo's four bytes replace the Wave's bPad (3.2.5.2.1.1).
pub fn joinWave(info: WaveInfoPdu, wave_msg: []const u8, out: []u8) Error![]u8 {
    const n = try info.sampleSize();
    if (wave_msg.len != n) return error.BadBodySize;
    if (out.len < n) return error.EndOfBuffer;
    @memcpy(out[0..4], &info.first4);
    @memcpy(out[4..n], wave_msg[4..]);
    return out[0..n];
}

/// Wave2 PDU fields (SNDWAVE2, 2.2.3.10).
pub const Wave2 = struct {
    header_pad: u8 = 0,
    timestamp: u16,
    format_no: u16,
    block_no: u8,
    pad: u24 = 0,
    /// dwAudioTimeStamp: ms since system start when the audio was captured.
    audio_timestamp: u32,
};

pub const Wave2Pdu = struct {
    wave: Wave2,
    data: []const u8,
};

const wave2_fixed_body = 12;

pub fn encodeWave2(w: *bytes.Writer, wave: Wave2, data: []const u8) !void {
    try writeHeader(w, .wave2, wave.header_pad, wave2_fixed_body + data.len);
    try w.u16le(wave.timestamp);
    try w.u16le(wave.format_no);
    try w.byte(wave.block_no);
    try writeU24(w, wave.pad);
    try w.u32le(wave.audio_timestamp);
    try w.bytes(data);
}

pub fn decodeWave2(msg: []const u8) Error!Wave2Pdu {
    const p = try expectPdu(msg, .wave2);
    if (p.body.len < wave2_fixed_body) return error.EndOfBuffer;
    const b = p.body;
    return .{
        .wave = .{
            .header_pad = p.h.pad,
            .timestamp = std.mem.readInt(u16, b[0..2], .little),
            .format_no = std.mem.readInt(u16, b[2..4], .little),
            .block_no = b[4],
            .pad = readU24(b[5..8]),
            .audio_timestamp = std.mem.readInt(u32, b[8..12], .little),
        },
        .data = b[wave2_fixed_body..],
    };
}

/// Wave Confirm PDU (SNDWAV_CONFIRM, 2.2.3.8).
pub const WaveConfirm = struct {
    header_pad: u8 = 0,
    timestamp: u16,
    block_no: u8,
    pad: u8 = 0,
};

pub fn encodeWaveConfirm(w: *bytes.Writer, pdu: WaveConfirm) !void {
    try writeHeader(w, .wave_confirm, pdu.header_pad, 4);
    try w.u16le(pdu.timestamp);
    try w.byte(pdu.block_no);
    try w.byte(pdu.pad);
}

pub fn decodeWaveConfirm(msg: []const u8) Error!WaveConfirm {
    const p = try expectFixedPdu(msg, .wave_confirm, 4);
    return .{ .header_pad = p.h.pad, .timestamp = std.mem.readInt(u16, p.body[0..2], .little), .block_no = p.body[2], .pad = p.body[3] };
}

/// Close PDU (SNDCLOSE, 2.2.3.9): a header with BodySize 0.
pub fn encodeClose(w: *bytes.Writer) !void {
    try writeHeader(w, .close, 0, 0);
}

pub fn decodeClose(msg: []const u8) Error!void {
    _ = try expectFixedPdu(msg, .close, 0);
}

// Audio setting transfer PDUs (2.2.4)

/// dwVolume (2.2.2.2, 2.2.4.1): low word left, high word right; 0xFFFF full, logarithmic.
pub const Volume = packed struct(u32) {
    left: u16,
    right: u16,
};

pub fn encodeVolume(w: *bytes.Writer, v: Volume) !void {
    try writeHeader(w, .set_volume, 0, 4);
    try w.u32le(@bitCast(v));
}

pub fn decodeVolume(msg: []const u8) Error!Volume {
    const p = try expectFixedPdu(msg, .set_volume, 4);
    return @bitCast(std.mem.readInt(u32, p.body[0..4], .little));
}

/// Pitch PDU (SNDPITCH, 2.2.4.2); the client MUST ignore it.
pub fn encodePitch(w: *bytes.Writer, pitch: u32) !void {
    try writeHeader(w, .set_pitch, 0, 4);
    try w.u32le(pitch);
}

pub fn decodePitch(msg: []const u8) Error!u32 {
    const p = try expectFixedPdu(msg, .set_pitch, 4);
    return std.mem.readInt(u32, p.body[0..4], .little);
}

/// dwPitch (2.2.2.2): signed 16.16 fixed point, 0x00010000 = 1.0.
pub fn pitchMultiplier(pitch: u32) Error!f64 {
    const fixed: i32 = @bitCast(pitch);
    return @as(f64, @floatFromInt(fixed)) / 65536.0;
}

// UDP data path (2.2.3.5 - 2.2.3.7, 3.3.5.2.1.3)

fn seedHash(seed: *const [32]u8, block_no: u8, data: []const u8) [Sha1.digest_length]u8 {
    var h = Sha1.init(.{});
    h.update(seed);
    h.update(&.{ block_no, 0, 0, 0 });
    h.update(data);
    var d: [Sha1.digest_length]u8 = undefined;
    h.final(&d);
    return d;
}

/// SHA-1 of (Seed, cBlockNo, 0x000000, data), first 8 bytes (3.3.5.2.1.3). Without a Crypt Key
/// PDU the seed is 32 zero bytes.
pub fn waveSignature(seed: *const [32]u8, block_no: u8, data: []const u8) Error![8]u8 {
    return seedHash(seed, block_no, data)[0..8].*;
}

/// RC4 key (3.3.5.2.1.3); the data is not hashed, the client needs the key to read it.
pub fn waveEncryptKey(seed: *const [32]u8, block_no: u8) Error![20]u8 {
    return seedHash(seed, block_no, &.{});
}

pub const WaveEncrypt = struct {
    header_pad: u8 = 0,
    timestamp: u16,
    format_no: u16,
    block_no: u8,
    pad: u24 = 0,
};

pub const WaveEncryptPdu = struct {
    wave: WaveEncrypt,
    /// Present only when both versions are at least 5 (2.2.3.5).
    signature: ?[8]u8,
    data: []const u8,
};

/// The signature covers the plaintext, as for AUDIO_FRAGDATA (2.2.3.6.1).
pub fn encodeWaveEncrypt(w: *bytes.Writer, wave: WaveEncrypt, seed: *const [32]u8, signed: bool, sample: []const u8) !void {
    const sig_len: usize = if (signed) 8 else 0;
    try writeHeader(w, .wave_encrypt, wave.header_pad, 8 + sig_len + sample.len);
    try w.u16le(wave.timestamp);
    try w.u16le(wave.format_no);
    try w.byte(wave.block_no);
    try writeU24(w, wave.pad);
    if (signed) {
        const sig = try waveSignature(seed, wave.block_no, sample);
        try w.bytes(&sig);
    }
    const at = w.len();
    try w.bytes(sample);
    const key = try waveEncryptKey(seed, wave.block_no);
    var rc4 = Rc4.init(&key);
    defer rc4.wipe();
    rc4.apply(w.list.items[at..]);
}

pub fn decodeWaveEncrypt(msg: []const u8, signed: bool) Error!WaveEncryptPdu {
    const p = try expectPdu(msg, .wave_encrypt);
    const sig_len: usize = if (signed) 8 else 0;
    if (p.body.len < 8 + sig_len) return error.EndOfBuffer;
    const b = p.body;
    return .{
        .wave = .{
            .header_pad = p.h.pad,
            .timestamp = std.mem.readInt(u16, b[0..2], .little),
            .format_no = std.mem.readInt(u16, b[2..4], .little),
            .block_no = b[4],
            .pad = readU24(b[5..8]),
        },
        .signature = if (signed) b[8..16].* else null,
        .data = b[8 + sig_len ..],
    };
}

pub fn decryptWave(seed: *const [32]u8, block_no: u8, data: []const u8, out: []u8) Error!void {
    if (out.len != data.len) return error.InvalidPdu;
    const key = try waveEncryptKey(seed, block_no);
    var rc4 = Rc4.init(&key);
    defer rc4.wipe();
    @memcpy(out, data);
    rc4.apply(out);
}

/// Largest cFragNo (15 bits, 2.2.3.6).
pub const max_frag_no: u16 = 0x7FFF;

pub const UdpWave = struct {
    block_no: u8,
    frag_no: u16,
    data: []const u8,
};

fn udpWaveHeaderSize(frag_no: u16) usize {
    return if (frag_no < 0x80) 3 else 4;
}

/// UDP Wave PDU (2.2.3.6): cFragNo is 1 byte below 0x80, else 2 (0x80 | high 7 bits, low 8).
pub fn encodeUdpWave(w: *bytes.Writer, pdu: UdpWave) !void {
    if (pdu.frag_no > max_frag_no) return error.FragmentNumberTooLarge;
    try w.byte(@backingInt(MsgType.udp_wave));
    try w.byte(pdu.block_no);
    if (pdu.frag_no < 0x80) {
        try w.byte(@intCast(pdu.frag_no));
    } else {
        try w.byte(0x80 | @as(u8, @intCast(pdu.frag_no >> 8)));
        try w.byte(@truncate(pdu.frag_no));
    }
    try w.bytes(pdu.data);
}

pub fn decodeUdpWave(msg: []const u8) Error!UdpWave {
    if (msg.len < 1) return error.EndOfBuffer;
    if (msg[0] != @backingInt(MsgType.udp_wave)) return error.UnexpectedMsgType;
    if (msg.len < 3) return error.EndOfBuffer;
    if (msg[2] & 0x80 == 0) return .{ .block_no = msg[1], .frag_no = msg[2], .data = msg[3..] };
    if (msg.len < 4) return error.EndOfBuffer;
    return .{ .block_no = msg[1], .frag_no = @as(u16, msg[2] & 0x7F) << 8 | msg[3], .data = msg[4..] };
}

pub const UdpWaveLast = struct {
    /// Size of the whole AUDIO_FRAGDATA (8-byte signature + sample).
    total_size: u16,
    timestamp: u16,
    format_no: u16,
    block_no: u8,
    pad: u24 = 0,
    data: []const u8,
};

const udp_wave_last_header = 11;

/// UDP Wave Last PDU (2.2.3.7).
pub fn encodeUdpWaveLast(w: *bytes.Writer, pdu: UdpWaveLast) !void {
    if (pdu.data.len > pdu.total_size) return error.InvalidPdu;
    try w.byte(@backingInt(MsgType.udp_wave_last));
    try w.u16le(pdu.total_size);
    try w.u16le(pdu.timestamp);
    try w.u16le(pdu.format_no);
    try w.byte(pdu.block_no);
    try writeU24(w, pdu.pad);
    try w.bytes(pdu.data);
}

pub fn decodeUdpWaveLast(msg: []const u8) Error!UdpWaveLast {
    if (msg.len < 1) return error.EndOfBuffer;
    if (msg[0] != @backingInt(MsgType.udp_wave_last)) return error.UnexpectedMsgType;
    if (msg.len < udp_wave_last_header) return error.EndOfBuffer;
    const p: UdpWaveLast = .{
        .total_size = std.mem.readInt(u16, msg[1..3], .little),
        .timestamp = std.mem.readInt(u16, msg[3..5], .little),
        .format_no = std.mem.readInt(u16, msg[5..7], .little),
        .block_no = msg[7],
        .pad = readU24(msg[8..11]),
        .data = msg[udp_wave_last_header..],
    };
    if (p.data.len > p.total_size) return error.InvalidPdu;
    return p;
}

/// UDP Wave PDUs plus a final UDP Wave Last PDU (3.3.5.2.1.4/5), each at most `max_datagram`
/// bytes; caller frees each datagram and the slice.
pub fn fragmentUdp(
    gpa: Allocator,
    seed: *const [32]u8,
    timestamp: u16,
    format_no: u16,
    block_no: u8,
    sample: []const u8,
    max_datagram: usize,
) Error![][]u8 {
    if (max_datagram <= udp_wave_last_header) return error.InvalidPdu;
    const total = 8 + sample.len;
    if (total > 0xFFFF) return error.TooLarge;

    // AUDIO_FRAGDATA (2.2.3.6.1): signature of the sample, then the sample.
    const frag = try gpa.alloc(u8, total);
    defer gpa.free(frag);
    const sig = try waveSignature(seed, block_no, sample);
    @memcpy(frag[0..8], &sig);
    @memcpy(frag[8..], sample);

    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |d| gpa.free(d);
        out.deinit(gpa);
    }
    const last_cap = max_datagram - udp_wave_last_header;
    var off: usize = 0;
    var frag_no: u16 = 0;
    while (total - off > last_cap) : (frag_no += 1) {
        if (frag_no > max_frag_no) return error.FragmentNumberTooLarge;
        // Leave at least one byte for the UDP Wave Last PDU.
        const n = @min(max_datagram - udpWaveHeaderSize(frag_no), total - off - 1);
        try out.append(gpa, try buildMsg(gpa, encodeUdpWave, .{UdpWave{ .block_no = block_no, .frag_no = frag_no, .data = frag[off..][0..n] }}));
        off += n;
    }
    try out.append(gpa, try buildMsg(gpa, encodeUdpWaveLast, .{UdpWaveLast{ .total_size = @intCast(total), .timestamp = timestamp, .format_no = format_no, .block_no = block_no, .data = frag[off..] }}));
    return out.toOwnedSlice(gpa);
}

// Software codecs

/// Input truncated to 13 bits, as ITU-T G.191 does.
pub fn alawEncode(sample: i16) Error!u8 {
    return g711.alawEncode(sample);
}

pub fn alawDecode(code: u8) Error!i16 {
    return g711.alawDecode(code);
}

/// Negative inputs are one's-complemented, as ITU-T G.191 does.
pub fn mulawEncode(sample: i16) Error!u8 {
    return g711.mulawEncode(sample);
}

pub fn mulawDecode(code: u8) Error!i16 {
    return g711.mulawDecode(code);
}

pub const ImaAdpcmEncoder = adpcm.ImaAdpcmEncoder;
pub const ImaAdpcmDecoder = adpcm.ImaAdpcmDecoder;
pub const MsAdpcmEncoder = adpcm.MsAdpcmEncoder;
pub const MsAdpcmDecoder = adpcm.MsAdpcmDecoder;

/// Opus sample rates (RFC 6716 2): 8, 12, 16, 24, 48 kHz.
pub fn isOpusSampleRate(rate: u32) Error!bool {
    return opus.isOpusSampleRate(rate);
}

pub const OpusEncoder = opus.OpusEncoder;
pub const OpusDecoder = opus.OpusDecoder;
pub const AacEncoder = aac.AacEncoder;
pub const AacDecoder = aac.AacDecoder;
pub const aac_frame_length = aac.frame_length;
pub const aac_max_access_unit = aac.max_access_unit;
pub const GsmEncoder = gsm.GsmEncoder;
pub const GsmDecoder = gsm.GsmDecoder;

// Server state machine (3.1.5, 3.3.5), as a Windows server runs it

pub const State = enum {
    idle,
    /// Server Audio Formats sent (transition 1).
    wait_client_formats,
    /// Both versions >= 6: waiting for the Quality Mode PDU (5).
    wait_quality_mode,
    /// Training PDU sent over the virtual channel (17).
    wait_training_confirm,
    /// Data can flow, also after a Close (Windows streams again without new Formats or Training).
    ready,
    /// No Client Audio Formats or an empty list: messages are ignored, sends fail with NotReady.
    terminated,
};

pub const Config = struct {
    formats: []const AudioFormat = &default_server_formats,
    version: u16 = server_version,
    /// Windows sends 0xFF, so the first wave is block 0.
    last_block_confirmed: u8 = 0xFF,
    /// 0 gives wPackSize 0; Windows sends 1016 bytes of random data (wPackSize 1024).
    training_data_len: u16 = 1016,
    /// <14>: Windows waits 10 s for the Client Audio Formats PDU.
    client_formats_timeout_ms: u32 = 10_000,
    /// Each other PDU restarts the wait; then DYNAMIC_QUALITY.
    quality_mode_timeout_ms: u32 = 10_000,
    /// Each other PDU restarts the wait; without a confirm the bandwidth is 0.
    training_timeout_ms: u32 = 5_000,
    quality_limit: QualityLimit = .dynamic,
    /// RdpsndMaxBandwidth / RdpsndMinBandwidth (B/s): bounds of the measured bandwidth.
    max_bandwidth: u32 = default_max_bandwidth,
    min_bandwidth: u32 = 0,
    /// Seed of the Training PDU's random data (null: from the clock).
    seed: ?u64 = null,
};

pub const Event = union(enum) {
    none,
    /// Malformed, unrecognized, out-of-sequence or stale message (3.1.5).
    ignored,
    client_formats,
    /// Received or timed out (DYNAMIC_QUALITY); untrained clients may already be ready.
    quality_mode: QualityMode,
    /// Training Confirm, its timeout, or no training. Also the answer to a ping or a diagnostic
    /// Training while streaming.
    ready,
    /// Blocks up to it count as confirmed. Duplicates (mstsc and FreeRDP confirm each block
    /// twice), stale and unknown blocks are .ignored.
    wave_confirmed: struct {
        block_no: u8,
        /// Confirm wTimeStamp minus the block's (mod 2^16): the client's hold time (3.2.5.2.1.6).
        client_delay_ms: u16,
    },
    /// Protocol terminated (transition 3: no Client Audio Formats).
    terminated,
};

/// Messages to send on the channel, in order, one per entry.
pub const Outbox = struct {
    gpa: Allocator,
    msgs: std.ArrayList([]u8) = .empty,

    pub fn init(gpa: Allocator) Outbox {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Outbox) void {
        self.clear();
        self.msgs.deinit(self.gpa);
    }

    pub fn clear(self: *Outbox) void {
        for (self.msgs.items) |m| self.gpa.free(m);
        self.msgs.clearRetainingCapacity();
    }

    /// `msg` must come from this outbox's allocator; it is freed on failure.
    pub fn push(self: *Outbox, msg: []u8) Allocator.Error!void {
        self.msgs.append(self.gpa, msg) catch |e| {
            self.gpa.free(msg);
            return e;
        };
    }

    pub fn build(self: *Outbox, comptime f: anytype, args: anytype) !void {
        try self.push(try buildMsg(self.gpa, f, args));
    }
};

/// Caller frees.
pub fn buildMsg(gpa: Allocator, comptime f: anytype, args: anytype) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    var w = bytes.Writer.init(&list, gpa);
    try @call(.auto, f, .{&w} ++ args);
    return list.toOwnedSlice(gpa);
}

/// Owned copy of a peer's format list and its extra data; shared with audin.zig.
pub const OwnedFormats = struct {
    list: []AudioFormat = &.{},
    extra: []u8 = &.{},

    pub fn dupe(gpa: Allocator, formats: []const AudioFormat) Allocator.Error!OwnedFormats {
        var extra_len: usize = 0;
        for (formats) |f| extra_len += f.extra.len;
        const list = try gpa.alloc(AudioFormat, formats.len);
        errdefer gpa.free(list);
        const extra = try gpa.alloc(u8, extra_len);
        var off: usize = 0;
        for (formats, list) |f, *g| {
            g.* = f;
            g.extra = extra[off..][0..f.extra.len];
            @memcpy(extra[off..][0..f.extra.len], f.extra);
            off += f.extra.len;
        }
        return .{ .list = list, .extra = extra };
    }

    pub fn deinit(self: *OwnedFormats, gpa: Allocator) void {
        gpa.free(self.list);
        gpa.free(self.extra);
        self.* = .{};
    }
};

/// Dynamic mode's measurements.
pub const Stats = struct {
    /// Wave Confirm delay (now - the block's wTimeStamp), smoothed 0.7 / 0.3.
    delay_ms: u32 = 0,
    /// Round trip of the pings, smoothed 7/10 / 3/10.
    rtt_ms: u32 = 0,
    confirms: u32 = 0,
    last_wave_bytes: u32 = 0,
    /// Blocks the client is thought to hold (computed, unused).
    window: u32 = 0,
};

/// A confirm more than this many blocks behind the next one is stale.
pub const confirm_window: u8 = 12;

/// MS-RDPEA server over one virtual channel (static or DVC), as a Windows server runs it.
/// Waves never wait for confirms.
pub const Server = struct {
    gpa: Allocator,
    cfg: Config,
    st: State = .idle,
    client_version: ?u16 = null,
    client_flags: u32 = 0,
    client_volume: u32 = 0,
    client: OwnedFormats = .{},
    /// keepClientFormats of the client's list.
    kept: []bool = &.{},
    quality: QualityMode = .dynamic,
    mode: QualityMode = .dynamic,
    current: ?u16 = null,
    aac: bool = false,
    /// B/s: the training's measure, then the current format's rate or the last throughput estimate.
    bw: u32 = 0,
    next_block: u8 = 0,
    /// Blocks before this one count as confirmed.
    up_to: u8 = 0,
    /// Since the start or the last Close.
    streaming: bool = false,
    /// Timer of the current state (3.3.2).
    deadline: ?u64 = null,
    /// The outstanding Training PDU (3.3.5.1.1.5).
    training: ?struct { timestamp: u16, pack_size: u16 } = null,
    stats: Stats = .{},
    prng: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0),
    /// wTimeStamp of each block sent.
    flight_ts: [256]u16 = @splat(0),

    pub fn init(gpa: Allocator, cfg: Config) Server {
        return .{ .gpa = gpa, .cfg = cfg };
    }

    pub fn deinit(self: *Server) void {
        self.client.deinit(self.gpa);
        if (self.kept.len > 0) self.gpa.free(self.kept);
        self.kept = &.{};
    }

    /// Sends the Server Audio Formats PDU (3.3.5.1.1.1) and restarts negotiation. UnsupportedFormat
    /// without a PCM entry in cfg.formats (2.2.2.1.1: servers MUST support PCM).
    pub fn start(self: *Server, now_ms: u64, out: *Outbox) Error!void {
        for (self.cfg.formats) |f| {
            if (f.tag == WAVE_FORMAT_PCM) break;
        } else return error.UnsupportedFormat;
        if (self.cfg.training_data_len > max_training_data) return error.TooLarge;
        try out.build(encodeServerFormats, .{ServerFormats{
            .last_block_confirmed = self.cfg.last_block_confirmed,
            .version = self.cfg.version,
            .formats = self.cfg.formats,
        }});
        const gpa = self.gpa;
        const cfg = self.cfg;
        const stats = self.stats;
        self.deinit();
        self.* = .{ .gpa = gpa, .cfg = cfg, .stats = stats };
        self.prng = std.Random.DefaultPrng.init(cfg.seed orelse now_ms *% 0x9E37_79B9_7F4A_7C15);
        self.st = .wait_client_formats;
        self.next_block = self.cfg.last_block_confirmed +% 1;
        // Nothing sent, nothing owed.
        self.up_to = self.next_block;
        self.deadline = now_ms +| self.cfg.client_formats_timeout_ms;
    }

    /// Malformed, out-of-sequence and stale messages give .ignored, never an error (3.1.5).
    pub fn handle(self: *Server, msg: []const u8, now_ms: u64, out: *Outbox) Error!Event {
        if (self.st == .idle or self.st == .terminated) return .ignored;
        const h = decodeHeader(msg) catch return self.other(now_ms);
        switch (h.msg_type) {
            .formats => {
                if (self.st != .wait_client_formats) return self.other(now_ms);
                const cf = decodeClientFormats(self.gpa, msg) catch |e| switch (e) {
                    error.OutOfMemory => return e,
                    else => return .ignored,
                };
                defer cf.deinit(self.gpa);
                if (cf.formats.len == 0) {
                    self.terminate();
                    return .terminated;
                }
                const copy = try OwnedFormats.dupe(self.gpa, cf.formats);
                errdefer {
                    var c = copy;
                    c.deinit(self.gpa);
                }
                const kept = try self.gpa.alloc(bool, cf.formats.len);
                keepClientFormats(cf.formats, kept);
                self.client.deinit(self.gpa);
                if (self.kept.len > 0) self.gpa.free(self.kept);
                self.client = copy;
                self.kept = kept;
                self.client_version = cf.version;
                self.client_flags = cf.flags;
                self.client_volume = cf.volume;
                if (try qualityModeUsed(cf.version, self.cfg.version)) {
                    self.st = .wait_quality_mode;
                    self.deadline = now_ms +| self.cfg.quality_mode_timeout_ms;
                } else {
                    try self.afterQuality(now_ms, out);
                }
                return .client_formats;
            },
            .quality_mode => {
                if (self.st != .wait_quality_mode) return self.other(now_ms);
                // Any body of 4 bytes or more is accepted, as a Windows server does.
                if (h.body_size < 4 or msg.len < header_size + 4) return self.other(now_ms);
                const q: QualityMode = @fromBackingInt(std.mem.readInt(u16, msg[4..6], .little));
                self.quality = q;
                self.mode = effectiveQuality(q, self.cfg.quality_limit);
                try self.afterQuality(now_ms, out);
                return .{ .quality_mode = q };
            },
            .training => {
                if (h.body_size < 4 or msg.len < header_size + 4) return self.other(now_ms);
                const ts = std.mem.readInt(u16, msg[4..6], .little);
                const pack = std.mem.readInt(u16, msg[6..8], .little);
                switch (self.st) {
                    .wait_training_confirm => {
                        // Bandwidth: echoed wPackSize + 8 over the round trip of the echoed wTimeStamp.
                        self.training = null;
                        const rtt: u64 = @as(u64, @as(u16, @truncate(now_ms)) -% ts) + 1;
                        const bw = (@as(u64, pack) + 8) * 1000 / rtt + 1;
                        self.bw = std.math.clamp(@as(u32, @intCast(@min(bw, std.math.maxInt(u32)))), self.cfg.min_bandwidth, @max(self.cfg.min_bandwidth, self.cfg.max_bandwidth));
                        self.negotiated();
                        return .ready;
                    },
                    .ready => {
                        if (pack == 0) {
                            // A ping's answer.
                            const rtt: u32 = @as(u16, @truncate(now_ms)) -% ts;
                            self.stats.rtt_ms = if (self.stats.rtt_ms == 0) rtt else (7 * self.stats.rtt_ms + 3 * rtt) / 10;
                            return .ready;
                        }
                        const t = self.training orelse return .ignored;
                        if (t.timestamp != ts or t.pack_size != pack) return .ignored;
                        self.training = null;
                        return .ready;
                    },
                    else => return self.other(now_ms),
                }
            },
            .wave_confirm => {
                if (self.st != .ready) return self.other(now_ms);
                const c = decodeWaveConfirm(msg) catch return .ignored;
                self.statsCollect(c.timestamp, now_ms);
                // Stale: more than 12 blocks behind the next, or the next itself (not
                // sent yet). A confirm under 12 past the confirmed point moves it.
                const behind = self.next_block -% c.block_no;
                if (behind == 0 or behind > confirm_window) return .ignored;
                if (c.block_no -% self.up_to >= confirm_window) return .ignored;
                self.up_to = c.block_no +% 1;
                return .{ .wave_confirmed = .{ .block_no = c.block_no, .client_delay_ms = c.timestamp -% self.flight_ts[c.block_no] } };
            },
            else => return self.other(now_ms),
        }
    }

    /// Ignored; the wait starts over, as Windows' per-receive waits do.
    fn other(self: *Server, now_ms: u64) Event {
        switch (self.st) {
            .wait_quality_mode => self.deadline = now_ms +| self.cfg.quality_mode_timeout_ms,
            .wait_training_confirm => self.deadline = now_ms +| self.cfg.training_timeout_ms,
            else => {},
        }
        return .ignored;
    }

    fn terminate(self: *Server) void {
        self.st = .terminated;
        self.deadline = null;
        self.training = null;
    }

    /// Timers (3.3.2): formats terminate, quality mode falls back to Dynamic, training to 0 B/s.
    pub fn tick(self: *Server, now_ms: u64, out: *Outbox) Error!Event {
        const deadline = self.deadline orelse return .none;
        if (now_ms < deadline) return .none;
        switch (self.st) {
            .wait_client_formats => {
                self.terminate();
                return .terminated;
            },
            .wait_quality_mode => {
                self.quality = .dynamic;
                self.mode = .dynamic;
                try self.afterQuality(now_ms, out);
                return if (self.st == .ready) .ready else .{ .quality_mode = .dynamic };
            },
            .wait_training_confirm => {
                // A failed training forgets the client's flags; negotiation still succeeds.
                self.training = null;
                self.client_flags = 0;
                self.bw = 0;
                self.negotiated();
                return .ready;
            },
            else => {
                self.deadline = null;
                return .none;
            },
        }
    }

    fn afterQuality(self: *Server, now_ms: u64, out: *Outbox) Error!void {
        if (self.client_flags & TSSNDCAPS_ALIVE != 0) {
            try self.sendTraining(now_ms, out);
            self.st = .wait_training_confirm;
            self.deadline = now_ms +| self.cfg.training_timeout_ms;
        } else {
            self.bw = 0;
            self.negotiated();
        }
    }

    /// Dynamic mode takes AAC at 96 kbit/s if listed, else the first usable format within the
    /// bandwidth; Medium and High their own format, else PCM 44.1 kHz stereo.
    fn negotiated(self: *Server) void {
        self.st = .ready;
        self.deadline = null;
        const list = self.client.list;
        self.aac = false;
        if (self.mode == .dynamic) {
            if (chooseAac(list, self.kept)) |i| {
                self.current = i;
                self.aac = true;
                return;
            }
            self.current = chooseProperFormat(list, self.kept, self.bw);
        } else {
            self.current = findFormatForQuality(list, self.kept, self.mode) orelse findNativeFormat(list) orelse
                chooseProperFormat(list, self.kept, self.bw);
        }
        if (self.current) |i| self.bw = list[i].avg_bytes_per_sec;
    }

    fn sendTraining(self: *Server, now_ms: u64, out: *Outbox) Error!void {
        const n = self.cfg.training_data_len;
        const data = try self.gpa.alloc(u8, n);
        defer self.gpa.free(data);
        // Random content (2.2.3.1) so a compressing transport does not shrink it.
        const r = self.prng.random();
        r.bytes(data);
        const ts: u16 = @truncate(now_ms);
        try out.build(encodeTraining, .{ r.int(u8), ts, @as([]const u8, data) });
        self.training = .{ .timestamp = ts, .pack_size = trainingPackSize(n) };
    }

    /// Dynamic mode only; a delay of 0 or over 0xF000 counts as 1.
    fn statsCollect(self: *Server, ts: u16, now_ms: u64) void {
        if (self.mode != .dynamic) return;
        var d: u32 = @as(u16, @truncate(now_ms)) -% ts;
        if (d == 0 or d > 0xF000) d = 1;
        self.stats.delay_ms = if (self.stats.delay_ms == 0) d else @intFromFloat(@as(f64, @floatFromInt(self.stats.delay_ms)) * 0.7 + @as(f64, @floatFromInt(d)) * 0.3);
        self.stats.confirms +%= 1;
    }

    /// Dynamic mode without AAC, before each wave: a ping at the 5th of every 10 confirms; from 10
    /// confirms on, re-pick the format for a quarter of the throughput. True when it changed.
    pub fn checkResample(self: *Server, now_ms: u64, out: *Outbox) Error!bool {
        if (self.st != .ready or self.mode != .dynamic or self.aac) return false;
        const cur = self.current orelse return false;
        if (self.stats.confirms % 10 == 5) try out.build(encodeTraining, .{ @as(u8, 0), @as(u16, @truncate(now_ms)), @as([]const u8, &.{}) });
        if (self.stats.confirms < 10) return false;
        defer {
            self.stats.delay_ms = 0;
            self.stats.confirms = 0;
        }
        const delay = self.stats.delay_ms;
        if (self.stats.rtt_ms >= delay) self.stats.rtt_ms = delay -% 1;
        const transfer = delay -% (self.stats.rtt_ms >> 1);
        if (self.stats.last_wave_bytes == 0 or transfer == 0) return false;
        const r: u32 = @intCast(@as(u64, self.stats.last_wave_bytes) * 1000 / transfer);
        if (r == 0) return false;
        const block_ms = @max(1, @as(u32, @intCast(@as(u64, self.blockFrames()) * 4 * 1000 / 176400)));
        self.stats.window = @min(12, (delay +% block_ms / 2) / block_ms + 2);
        const list = self.client.list;
        const cur_avg = list[cur].avg_bytes_per_sec;
        const rf: f64 = @floatFromInt(r);
        if (!(@as(f64, @floatFromInt(cur_avg)) > rf * 0.5 or @as(u64, r) > 7 * @as(u64, cur_avg))) return false;
        var bw: u32 = @intFromFloat(rf * 0.25);
        bw = @max(@min(bw, self.cfg.max_bandwidth), self.cfg.min_bandwidth);
        const want = chooseProperFormat(list, self.kept, bw) orelse return false;
        if (want == cur) return false;
        var next = want;
        if (want < cur) {
            // Heavier: one usable step up only.
            var k = cur - 1;
            while (k != want and !convertible(list, self.kept, k)) k -= 1;
            next = k;
        }
        if (next == cur) return false;
        self.current = next;
        self.bw = r;
        return true;
    }

    /// After the 5 s idle wait: unconfirmed blocks count as confirmed, each a 5000 ms delay sample.
    pub fn expireUnconfirmed(self: *Server, now_ms: u64) void {
        if (self.next_block == self.up_to) return;
        const n = @as(usize, self.next_block -% self.up_to) + 1;
        for (0..n) |_| self.statsCollect(@truncate(now_ms -% 5000), now_ms);
        self.up_to = self.next_block;
    }

    pub fn allConfirmed(self: *const Server) bool {
        return self.next_block == self.up_to;
    }

    pub fn unconfirmed(self: *const Server) u8 {
        return self.next_block -% self.up_to;
    }

    pub fn isStreaming(self: *const Server) bool {
        return self.streaming;
    }

    pub fn state(self: *const Server) Error!State {
        return self.st;
    }

    pub fn clientVersion(self: *const Server) Error!?u16 {
        return self.client_version;
    }

    /// TSSNDCAPS_*; 0 after a failed training.
    pub fn clientFlags(self: *const Server) Error!u32 {
        return self.client_flags;
    }

    /// What wFormatNo indexes.
    pub fn clientFormats(self: *const Server) Error![]const AudioFormat {
        return self.client.list;
    }

    pub fn clientVolume(self: *const Server) Error!?Volume {
        if (self.client_flags & TSSNDCAPS_VOLUME == 0) return null;
        return @as(Volume, @bitCast(self.client_volume));
    }

    /// As received (DYNAMIC_QUALITY until a Quality Mode PDU, 3.3.5.1.1.3).
    pub fn qualityMode(self: *const Server) Error!QualityMode {
        return self.quality;
    }

    pub fn effectiveMode(self: *const Server) QualityMode {
        return self.mode;
    }

    /// B/s.
    pub fn bandwidth(self: *const Server) u32 {
        return self.bw;
    }

    pub fn isAac(self: *const Server) bool {
        return self.aac;
    }

    /// Frames of 44.1 kHz audio in each wave of the current mode.
    pub fn blockFrames(self: *const Server) u32 {
        if (self.aac) return aac_block_frames;
        return if (self.mode == .dynamic) dynamic_block_frames else fixed_block_frames;
    }

    /// Index into clientFormats(); UnsupportedFormat when canEncode() says no.
    pub fn selectFormat(self: *Server, format_no: u16) Error!void {
        if (format_no >= self.client.list.len) return error.FormatIndexOutOfRange;
        const f = self.client.list[format_no];
        if (!try canEncode(f)) return error.UnsupportedFormat;
        self.current = format_no;
        self.aac = f.tag == WAVE_FORMAT_AAC_MS;
    }

    /// Chosen when negotiation ends; null when no client format is usable.
    pub fn currentFormat(self: *const Server) Error!?u16 {
        return self.current;
    }

    fn checkNegotiated(self: *const Server) Error!void {
        switch (self.st) {
            .idle, .wait_client_formats, .terminated => return error.NotReady,
            .wait_quality_mode, .wait_training_confirm, .ready => {},
        }
    }

    /// Wave2 when both versions are at least 8, else WaveInfo + Wave (1.3.2.2). Returns the
    /// cBlockNo; nothing is queued on error.
    pub fn sendSample(self: *Server, sample: []const u8, now_ms: u64, audio_ts_ms: u32, out: *Outbox) Error!u8 {
        if (self.st != .ready) return error.NotReady;
        const format_no = self.current orelse return error.NotReady;
        const block = self.next_block;
        const ts: u16 = @truncate(now_ms);
        try out.msgs.ensureUnusedCapacity(out.gpa, 2);
        var bytes_sent: usize = 0;
        if (try wave2Used(self.client_version orelse 0, self.cfg.version)) {
            const m = try buildMsg(out.gpa, encodeWave2, .{ Wave2{ .timestamp = ts, .format_no = format_no, .block_no = block, .audio_timestamp = audio_ts_ms }, sample });
            out.msgs.appendAssumeCapacity(m);
            bytes_sent = m.len;
        } else {
            const info = try buildMsg(out.gpa, encodeWaveInfo, .{ WaveInfo{ .timestamp = ts, .format_no = format_no, .block_no = block }, sample });
            errdefer out.gpa.free(info);
            const wave = try buildMsg(out.gpa, encodeWave, .{sample});
            out.msgs.appendAssumeCapacity(info);
            out.msgs.appendAssumeCapacity(wave);
            // Counted as BodySize + 12, as a Windows server does.
            bytes_sent = sample.len + 20;
        }
        self.stats.last_wave_bytes = @intCast(@min(bytes_sent, std.math.maxInt(u32)));
        self.flight_ts[block] = ts;
        self.next_block +%= 1;
        self.streaming = true;
        return block;
    }

    /// A block without a wave (AAC look-ahead): Windows counts its number all the same.
    pub fn skipBlock(self: *Server) void {
        self.next_block +%= 1;
        self.streaming = true;
    }

    /// Needs TSSNDCAPS_VOLUME (3.3.5.3.1.1); Windows never sends one.
    pub fn setVolume(self: *Server, v: Volume, out: *Outbox) Error!void {
        try self.checkNegotiated();
        if (self.client_flags & TSSNDCAPS_VOLUME == 0) return error.CapabilityNotNegotiated;
        try out.build(encodeVolume, .{v});
    }

    /// Needs TSSNDCAPS_PITCH (3.3.5.3.1.2); Windows never sends one.
    pub fn setPitch(self: *Server, pitch: u32, out: *Outbox) Error!void {
        try self.checkNegotiated();
        if (self.client_flags & TSSNDCAPS_PITCH == 0) return error.CapabilityNotNegotiated;
        try out.build(encodePitch, .{pitch});
    }

    /// Any time after version exchange (3.3.5.1.1.4); its confirm gives .ready while streaming.
    pub fn train(self: *Server, now_ms: u64, out: *Outbox) Error!void {
        switch (self.st) {
            .idle, .wait_client_formats, .terminated => return error.NotReady,
            else => {},
        }
        try self.sendTraining(now_ms, out);
        if (self.st == .wait_training_confirm) self.deadline = now_ms +| self.cfg.training_timeout_ms;
    }

    /// Close PDU (2.2.3.9). Block numbers restart at 0; the next wave reuses the negotiated format
    /// without new Formats or Training.
    pub fn close(self: *Server, out: *Outbox) Error!void {
        switch (self.st) {
            .idle, .terminated => return error.NotReady,
            else => {},
        }
        try out.build(encodeClose, .{});
        self.next_block = 0;
        self.up_to = 0;
        self.streaming = false;
    }
};

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(AudioFormat);
    std.testing.refAllDecls(ServerFormats);
    std.testing.refAllDecls(ClientFormats);
    std.testing.refAllDecls(WaveInfoPdu);
    std.testing.refAllDecls(ImaAdpcmEncoder);
    std.testing.refAllDecls(ImaAdpcmDecoder);
    std.testing.refAllDecls(MsAdpcmEncoder);
    std.testing.refAllDecls(MsAdpcmDecoder);
    std.testing.refAllDecls(OpusEncoder);
    std.testing.refAllDecls(OpusDecoder);
    std.testing.refAllDecls(AacEncoder);
    std.testing.refAllDecls(AacDecoder);
    std.testing.refAllDecls(GsmEncoder);
    std.testing.refAllDecls(GsmDecoder);
    std.testing.refAllDecls(QualityLimit);
    std.testing.refAllDecls(Outbox);
    std.testing.refAllDecls(Server);
    _ = g711;
    _ = aac;
    _ = gsm;
}
