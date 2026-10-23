//! Client microphone data (MS-RDPEAI 2.2.3.2) decoded to the virtual microphone's
//! format: PCM 8/16-bit, WAVE_FORMAT_EXTENSIBLE PCM, A-law/mu-law, DVI/MS ADPCM,
//! and Opus (one packet per Data PDU).

const std = @import("std");
const rdpsnd = @import("../channel/rdpsnd.zig");
const audin = @import("../channel/audin.zig");
const resample = @import("resample.zig");

const Allocator = std.mem.Allocator;
const AudioFormat = rdpsnd.AudioFormat;

pub const Error = error{ UnsupportedFormat, InvalidData, OutOfMemory };

/// The virtual microphone's sample format (16-bit interleaved).
pub const MicFormat = struct {
    rate: u32 = 48000,
    channels: u16 = 1,
};

const Codec = union(enum) {
    pcm16,
    pcm8,
    alaw,
    mulaw,
    ima: rdpsnd.ImaAdpcmDecoder,
    ms: rdpsnd.MsAdpcmDecoder,
    opus: rdpsnd.OpusDecoder,
};

/// RFC 6716: a packet holds at most 120 ms of audio.
const max_opus_frames_per_channel = 48000 * 120 / 1000;

pub fn canDecode(f: AudioFormat) bool {
    return codecFor(f) != null;
}

fn codecFor(f: AudioFormat) ?std.meta.Tag(Codec) {
    if (f.channels == 0 or f.channels > 2 or f.samples_per_sec < resample.min_rate or f.samples_per_sec > resample.max_rate)
        return null;
    switch (f.tag) {
        rdpsnd.WAVE_FORMAT_PCM => {
            const codec: std.meta.Tag(Codec) = switch (f.bits_per_sample) {
                16 => .pcm16,
                8 => .pcm8,
                else => return null,
            };
            // Checked after the bit depth: the client's wBitsPerSample may be anything.
            if (f.block_align != f.channels * f.bits_per_sample / 8) return null;
            return codec;
        },
        rdpsnd.WAVE_FORMAT_EXTENSIBLE => {
            const e = audin.decodeWaveFormatExtensible(f) catch return null;
            if (f.bits_per_sample != 16 or e.valid_bits_per_sample != 16 or f.block_align != f.channels * 2) return null;
            return .pcm16;
        },
        rdpsnd.WAVE_FORMAT_ALAW, rdpsnd.WAVE_FORMAT_MULAW => {
            if (f.bits_per_sample != 8 or f.block_align != f.channels) return null;
            return if (f.tag == rdpsnd.WAVE_FORMAT_ALAW) .alaw else .mulaw;
        },
        rdpsnd.WAVE_FORMAT_DVI_ADPCM, rdpsnd.WAVE_FORMAT_ADPCM => {
            // Same check as for encoding (wSamplesPerBlock, coefficients).
            if (!(rdpsnd.canEncode(f) catch false)) return null;
            return if (f.tag == rdpsnd.WAVE_FORMAT_ADPCM) .ms else .ima;
        },
        rdpsnd.WAVE_FORMAT_OPUS => return if (rdpsnd.isOpusSampleRate(f.samples_per_sec) catch false) .opus else null,
        else => return null,
    }
}

pub const MicDecoder = struct {
    gpa: Allocator,
    format: AudioFormat,
    codec: Codec,
    conv: resample.Converter,
    pcm: std.ArrayList(i16) = .empty,
    out: std.ArrayList(i16) = .empty,

    /// UnsupportedFormat unless canDecode(format) and the converter handles `mic`.
    pub fn init(gpa: Allocator, format: AudioFormat, mic: MicFormat) Error!MicDecoder {
        const tag = codecFor(format) orelse return error.UnsupportedFormat;
        var codec: Codec = switch (tag) {
            .pcm16 => .pcm16,
            .pcm8 => .pcm8,
            .alaw => .alaw,
            .mulaw => .mulaw,
            .ima => .{ .ima = rdpsnd.ImaAdpcmDecoder.init(format.channels, format.block_align) catch return error.UnsupportedFormat },
            .ms => .{ .ms = rdpsnd.MsAdpcmDecoder.init(format.channels, format.block_align) catch return error.UnsupportedFormat },
            .opus => .{ .opus = rdpsnd.OpusDecoder.init(format.samples_per_sec, format.channels) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.UnsupportedFormat,
            } },
        };
        errdefer if (codec == .opus) codec.opus.deinit();
        const conv = resample.Converter.init(gpa, format.samples_per_sec, format.channels, mic.rate, mic.channels) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.UnsupportedFormat => error.UnsupportedFormat,
        };
        var f = format;
        f.extra = &.{};
        return .{ .gpa = gpa, .format = f, .codec = codec, .conv = conv };
    }

    pub fn deinit(self: *MicDecoder) void {
        if (self.codec == .opus) self.codec.opus.deinit();
        self.conv.deinit();
        self.pcm.deinit(self.gpa);
        self.out.deinit(self.gpa);
        self.* = undefined;
    }

    /// Frames in the mic format, valid until the next call; InvalidData leaves the state unchanged.
    pub fn decode(self: *MicDecoder, data: []const u8) Error![]const i16 {
        self.pcm.clearRetainingCapacity();
        const ch: usize = self.format.channels;
        switch (self.codec) {
            .pcm16 => {
                if (data.len % (2 * ch) != 0) return error.InvalidData;
                try self.pcm.ensureUnusedCapacity(self.gpa, data.len / 2);
                var i: usize = 0;
                while (i < data.len) : (i += 2) self.pcm.appendAssumeCapacity(std.mem.readInt(i16, data[i..][0..2], .little));
            },
            .pcm8 => {
                if (data.len % ch != 0) return error.InvalidData;
                try self.pcm.ensureUnusedCapacity(self.gpa, data.len);
                for (data) |b| self.pcm.appendAssumeCapacity(@intCast((@as(i32, b) - 128) << 8));
            },
            .alaw, .mulaw => {
                if (data.len % ch != 0) return error.InvalidData;
                try self.pcm.ensureUnusedCapacity(self.gpa, data.len);
                for (data) |b| self.pcm.appendAssumeCapacity(if (self.codec == .alaw)
                    rdpsnd.alawDecode(b) catch unreachable
                else
                    rdpsnd.mulawDecode(b) catch unreachable);
            },
            .ima, .ms => {
                const ba: usize = self.format.block_align;
                if (data.len == 0 or data.len % ba != 0) return error.InvalidData;
                const spb = rdpsnd.samplesPerBlock(self.format) catch return error.InvalidData;
                var off: usize = 0;
                while (off < data.len) : (off += ba) {
                    const dst = try self.pcm.addManyAsSlice(self.gpa, spb * ch);
                    const r = switch (self.codec) {
                        .ima => |*d| d.decodeBlock(data[off..][0..ba], dst),
                        .ms => |*d| d.decodeBlock(data[off..][0..ba], dst),
                        else => unreachable,
                    };
                    _ = r catch return error.InvalidData;
                }
            },
            .opus => |*d| {
                const dst = try self.pcm.addManyAsSlice(self.gpa, max_opus_frames_per_channel * ch);
                const got = d.decode(data, dst) catch return error.InvalidData;
                self.pcm.shrinkRetainingCapacity(got.len);
            },
        }
        self.out.clearRetainingCapacity();
        try self.conv.process(self.pcm.items, &self.out);
        return self.out.items;
    }
};
