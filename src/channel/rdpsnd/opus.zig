//! Opus (RFC 6716) through libopus, for WAVE_FORMAT_OPUS: one packet per
//! Wave2/Wave PDU on rdpsnd, one per Data PDU on AUDIO_INPUT.

const std = @import("std");
const c = @import("c");
const rdpsnd = @import("../rdpsnd.zig");

const Error = rdpsnd.Error;

/// Opus sample rates (RFC 6716 2): 8, 12, 16, 24, 48 kHz.
pub fn isOpusSampleRate(rate: u32) bool {
    return switch (rate) {
        8000, 12000, 16000, 24000, 48000 => true,
        else => false,
    };
}

fn check(rate: u32, channels: u16) Error!void {
    if (!isOpusSampleRate(rate) or channels < 1 or channels > 2) return error.UnsupportedFormat;
}

/// True for an Opus frame duration (RFC 6716 2): 2.5, 5, 10, 20, 40 or 60 ms.
fn isFrameSize(rate: u32, frames: usize) bool {
    const units_x_rate = @as(u64, frames) * 400; // frames / (rate / 400)
    if (units_x_rate % rate != 0) return false;
    return switch (units_x_rate / rate) {
        1, 2, 4, 8, 16, 24 => true,
        else => false,
    };
}

pub const OpusEncoder = struct {
    channels: u16,
    samples_per_sec: u32,
    enc: ?*c.OpusEncoder = null,

    /// `bitrate` in bits per second (0: libopus' default for the format).
    pub fn init(samples_per_sec: u32, channels: u16, bitrate: u32) Error!OpusEncoder {
        try check(samples_per_sec, channels);
        var err: c_int = 0;
        const enc = c.opus_encoder_create(@intCast(samples_per_sec), channels, c.OPUS_APPLICATION_AUDIO, &err);
        if (enc == null or err != c.OPUS_OK) return if (err == c.OPUS_ALLOC_FAIL) error.OutOfMemory else error.UnsupportedFormat;
        errdefer c.opus_encoder_destroy(enc);
        if (bitrate != 0) {
            const b: c_int = @intCast(@min(bitrate, std.math.maxInt(c_int)));
            if (c.opus_encoder_ctl(enc, c.OPUS_SET_BITRATE_REQUEST, b) != c.OPUS_OK) return error.UnsupportedFormat;
        }
        return .{ .channels = channels, .samples_per_sec = samples_per_sec, .enc = enc };
    }

    pub fn deinit(self: *OpusEncoder) void {
        if (self.enc) |e| c.opus_encoder_destroy(e);
        self.enc = null;
    }

    /// UnsupportedFormat unless `pcm` is one Opus frame duration; TooLarge if `out` is short.
    pub fn encode(self: *OpusEncoder, pcm: []const i16, out: []u8) Error![]u8 {
        const enc = self.enc orelse return error.NotReady;
        if (pcm.len % self.channels != 0) return error.UnsupportedFormat;
        const frames = pcm.len / self.channels;
        if (!isFrameSize(self.samples_per_sec, frames)) return error.UnsupportedFormat;
        const cap: i32 = @intCast(@min(out.len, std.math.maxInt(i32)));
        const n = c.opus_encode(enc, pcm.ptr, @intCast(frames), out.ptr, cap);
        if (n < 0) return if (n == c.OPUS_BUFFER_TOO_SMALL) error.TooLarge else error.InvalidPdu;
        return out[0..@intCast(n)];
    }
};

pub const OpusDecoder = struct {
    channels: u16,
    samples_per_sec: u32,
    dec: ?*c.OpusDecoder = null,

    pub fn init(samples_per_sec: u32, channels: u16) Error!OpusDecoder {
        try check(samples_per_sec, channels);
        var err: c_int = 0;
        const dec = c.opus_decoder_create(@intCast(samples_per_sec), channels, &err);
        if (dec == null or err != c.OPUS_OK) return if (err == c.OPUS_ALLOC_FAIL) error.OutOfMemory else error.UnsupportedFormat;
        return .{ .channels = channels, .samples_per_sec = samples_per_sec, .dec = dec };
    }

    pub fn deinit(self: *OpusDecoder) void {
        if (self.dec) |d| c.opus_decoder_destroy(d);
        self.dec = null;
    }

    /// Returns the interleaved samples written. A TOC-only packet (RFC 6716 3.2.1) decodes to
    /// one frame of packet loss concealment.
    pub fn decode(self: *OpusDecoder, packet: []const u8, out: []i16) Error![]i16 {
        const dec = self.dec orelse return error.NotReady;
        if (packet.len == 0 or packet.len > std.math.maxInt(i32)) return error.InvalidPdu;
        const cap = @min(out.len / self.channels, std.math.maxInt(c_int));
        const n = c.opus_decode(dec, packet.ptr, @intCast(packet.len), out.ptr, @intCast(cap), 0);
        if (n < 0) return if (n == c.OPUS_BUFFER_TOO_SMALL) error.EndOfBuffer else error.InvalidPdu;
        return out[0 .. @as(usize, @intCast(n)) * self.channels];
    }
};
