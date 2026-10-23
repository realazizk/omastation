//! AAC-LC (libfdk-aac) for WAVE_FORMAT_AAC_MS (0xA106): raw access units without ADTS header
//! or format extra data, one 1024-frame access unit per wave.

const std = @import("std");
const c = @import("c");
const rdpsnd = @import("../rdpsnd.zig");

const Error = rdpsnd.Error;

/// Frames per AAC-LC access unit.
pub const frame_length: usize = 1024;

/// nAvgBytesPerSec range accepted (8 to 640 kbit/s); Windows clients use 2000 to 24000.
pub const min_bytes_per_sec: u32 = 1000;
pub const max_bytes_per_sec: u32 = 80000;

/// MPEG-4 sampling frequencies up to 96 kHz (ISO/IEC 14496-3 Table 1.18).
pub fn isAacSampleRate(rate: u32) bool {
    return switch (rate) {
        8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000, 64000, 88200, 96000 => true,
        else => false,
    };
}

/// 6144 bits per channel (ISO/IEC 14496-3 4.5.3.1), two channels.
pub const max_access_unit: usize = 2 * 6144 / 8;

pub const AacEncoder = struct {
    h: c.HANDLE_AACENCODER = null,
    channels: u16,
    /// The encoder's AudioSpecificConfig (for decoders that need one).
    asc: [64]u8 = undefined,
    asc_len: usize = 0,
    /// Codec delay in frames.
    delay: u32 = 0,

    /// AAC-LC, raw access units, at `bytes_per_sec` * 8 bit/s (CBR).
    pub fn init(samples_per_sec: u32, channels: u16, bytes_per_sec: u32) Error!AacEncoder {
        if (!isAacSampleRate(samples_per_sec) or channels < 1 or channels > 2) return error.UnsupportedFormat;
        if (bytes_per_sec < min_bytes_per_sec or bytes_per_sec > max_bytes_per_sec) return error.UnsupportedFormat;
        var self: AacEncoder = .{ .channels = channels };
        if (c.aacEncOpen(&self.h, 0, channels) != c.AACENC_OK) return error.OutOfMemory;
        errdefer _ = c.aacEncClose(&self.h);
        const params = [_][2]c_uint{
            .{ c.AACENC_AOT, c.AOT_AAC_LC },
            .{ c.AACENC_SAMPLERATE, samples_per_sec },
            .{ c.AACENC_CHANNELMODE, if (channels == 2) c.MODE_2 else c.MODE_1 },
            .{ c.AACENC_CHANNELORDER, 1 }, // WAV order (L, R)
            .{ c.AACENC_BITRATEMODE, 0 }, // CBR
            .{ c.AACENC_BITRATE, bytes_per_sec * 8 },
            .{ c.AACENC_TRANSMUX, c.TT_MP4_RAW },
            .{ c.AACENC_GRANULE_LENGTH, frame_length },
            .{ c.AACENC_AFTERBURNER, 1 },
        };
        for (params) |p| {
            if (c.aacEncoder_SetParam(self.h, @intCast(p[0]), p[1]) != c.AACENC_OK) return error.UnsupportedFormat;
        }
        if (c.aacEncEncode(self.h, null, null, null, null) != c.AACENC_OK) return error.UnsupportedFormat;
        var info: c.AACENC_InfoStruct = std.mem.zeroes(c.AACENC_InfoStruct);
        if (c.aacEncInfo(self.h, &info) != c.AACENC_OK) return error.UnsupportedFormat;
        if (info.frameLength != frame_length) return error.UnsupportedFormat;
        self.asc_len = @min(info.confSize, self.asc.len);
        @memcpy(self.asc[0..self.asc_len], info.confBuf[0..self.asc_len]);
        self.delay = info.nDelay;
        return self;
    }

    pub fn deinit(self: *AacEncoder) void {
        if (self.h != null) _ = c.aacEncClose(&self.h);
        self.h = null;
    }

    pub fn audioSpecificConfig(self: *const AacEncoder) []const u8 {
        return self.asc[0..self.asc_len];
    }

    /// Returns the access unit, empty while the encoder fills its look-ahead.
    pub fn encode(self: *AacEncoder, pcm: []const i16, out: []u8) Error![]u8 {
        if (self.h == null) return error.NotReady;
        if (pcm.len != frame_length * self.channels) return error.UnsupportedFormat;
        var in_ptr: ?*anyopaque = @ptrCast(@constCast(pcm.ptr));
        var in_id: c.INT = c.IN_AUDIO_DATA;
        var in_size: c.INT = @intCast(pcm.len * 2);
        var in_el: c.INT = 2;
        var in_desc: c.AACENC_BufDesc = .{ .numBufs = 1, .bufs = @ptrCast(&in_ptr), .bufferIdentifiers = &in_id, .bufSizes = &in_size, .bufElSizes = &in_el };
        var out_ptr: ?*anyopaque = @ptrCast(out.ptr);
        var out_id: c.INT = c.OUT_BITSTREAM_DATA;
        var out_size: c.INT = @intCast(@min(out.len, std.math.maxInt(c.INT)));
        var out_el: c.INT = 1;
        var out_desc: c.AACENC_BufDesc = .{ .numBufs = 1, .bufs = @ptrCast(&out_ptr), .bufferIdentifiers = &out_id, .bufSizes = &out_size, .bufElSizes = &out_el };
        var in_args: c.AACENC_InArgs = .{ .numInSamples = @intCast(pcm.len), .numAncBytes = 0 };
        var out_args: c.AACENC_OutArgs = std.mem.zeroes(c.AACENC_OutArgs);
        const r = c.aacEncEncode(self.h, &in_desc, &out_desc, &in_args, &out_args);
        if (r != c.AACENC_OK) return error.InvalidPdu;
        if (out_args.numInSamples != in_args.numInSamples) return error.InvalidPdu;
        return out[0..@intCast(out_args.numOutBytes)];
    }
};

pub const AacDecoder = struct {
    h: c.HANDLE_AACDECODER = null,
    channels: u16,

    pub fn init(asc: []const u8, channels: u16) Error!AacDecoder {
        const h = c.aacDecoder_Open(c.TT_MP4_RAW, 1);
        if (h == null) return error.OutOfMemory;
        errdefer c.aacDecoder_Close(h);
        var conf: [*c]c.UCHAR = @constCast(asc.ptr);
        var len: c.UINT = @intCast(asc.len);
        if (c.aacDecoder_ConfigRaw(h, &conf, &len) != c.AAC_DEC_OK) return error.InvalidPdu;
        return .{ .h = h, .channels = channels };
    }

    pub fn deinit(self: *AacDecoder) void {
        if (self.h != null) c.aacDecoder_Close(self.h);
        self.h = null;
    }

    pub fn decode(self: *AacDecoder, au: []const u8, out: []i16) Error![]i16 {
        if (self.h == null) return error.NotReady;
        var ptr: [*c]c.UCHAR = @constCast(au.ptr);
        var size: c.UINT = @intCast(au.len);
        var valid: c.UINT = size;
        if (c.aacDecoder_Fill(self.h, &ptr, &size, &valid) != c.AAC_DEC_OK) return error.InvalidPdu;
        const n = frame_length * self.channels;
        if (out.len < n) return error.EndOfBuffer;
        if (c.aacDecoder_DecodeFrame(self.h, out.ptr, @intCast(out.len), 0) != c.AAC_DEC_OK) return error.InvalidPdu;
        return out[0..n];
    }
};

/// Amplitude of `freq` in `x` by correlation, and the RMS of the residual.
fn fit(x: []const i16, rate: f64, freq: f64) struct { amp: f64, resid: f64 } {
    var s: f64 = 0;
    var co: f64 = 0;
    for (x, 0..) |v, i| {
        const t = 2 * std.math.pi * freq * @as(f64, @floatFromInt(i)) / rate;
        s += @as(f64, @floatFromInt(v)) * @sin(t);
        co += @as(f64, @floatFromInt(v)) * @cos(t);
    }
    const n: f64 = @floatFromInt(x.len);
    const a = 2 * s / n;
    const b = 2 * co / n;
    var r: f64 = 0;
    for (x, 0..) |v, i| {
        const t = 2 * std.math.pi * freq * @as(f64, @floatFromInt(i)) / rate;
        const e = @as(f64, @floatFromInt(v)) - (a * @sin(t) + b * @cos(t));
        r += e * e;
    }
    return .{ .amp = @sqrt(a * a + b * b), .resid = @sqrt(r / n) };
}

test "AAC-LC 44.1 kHz stereo encodes 1024-frame access units and decodes the tone" {
    const gpa = std.testing.allocator;
    var enc = try AacEncoder.init(44100, 2, 12000);
    defer enc.deinit();
    var dec = try AacDecoder.init(enc.audioSpecificConfig(), 2);
    defer dec.deinit();
    // AAC-LC (object type 2), 44.1 kHz (index 4), two channels.
    try std.testing.expectEqualSlices(u8, &.{ 0x12, 0x10 }, enc.audioSpecificConfig()[0..2]);
    var left: std.ArrayList(i16) = .empty;
    defer left.deinit(gpa);
    var pcm: [frame_length * 2]i16 = undefined;
    var au_buf: [max_access_unit]u8 = undefined;
    var dec_buf: [frame_length * 2]i16 = undefined;
    var empty: usize = 0;
    var total: usize = 0;
    var n: usize = 0;
    for (0..80) |k| {
        for (0..frame_length) |i| {
            const t = @as(f64, @floatFromInt(k * frame_length + i)) / 44100.0;
            const v: i16 = @intFromFloat(12000 * @sin(2 * std.math.pi * 440 * t));
            pcm[2 * i] = v;
            pcm[2 * i + 1] = v;
        }
        const au = try enc.encode(&pcm, &au_buf);
        if (au.len == 0) {
            empty += 1;
            continue;
        }
        total += au.len;
        n += 1;
        const d = try dec.decode(au, &dec_buf);
        for (0..frame_length) |i| try left.append(gpa, d[2 * i]);
    }
    try std.testing.expect(empty <= 3);
    // CBR 96 kbit/s: 12000 B/s is 278 bytes a frame on average.
    const avg = total / n;
    try std.testing.expect(avg > 240 and avg < 320);
    const f = fit(left.items[4096..], 44100, 440);
    try std.testing.expect(f.amp > 11000 and f.amp < 13000);
    try std.testing.expect(f.resid < 400);
}
