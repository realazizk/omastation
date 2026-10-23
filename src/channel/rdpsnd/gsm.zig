//! GSM 06.10 full rate (libgsm) for WAVE_FORMAT_GSM610: mono 65-byte blocks of two
//! 160-sample frames in Microsoft WAV49 bit order.

const std = @import("std");
const c = @import("c");
const rdpsnd = @import("../rdpsnd.zig");

const Error = rdpsnd.Error;

pub const frame_samples: usize = 160;
pub const block_samples: usize = 2 * frame_samples;
pub const block_bytes: usize = 65;

fn create() Error!c.gsm {
    const g = c.gsm_create();
    if (g == null) return error.OutOfMemory;
    var one: c_int = 1;
    if (c.gsm_option(g, c.GSM_OPT_WAV49, &one) < 0) {
        c.gsm_destroy(g);
        return error.UnsupportedFormat;
    }
    return g;
}

pub const GsmEncoder = struct {
    g: c.gsm = null,

    pub fn init() Error!GsmEncoder {
        return .{ .g = try create() };
    }

    pub fn deinit(self: *GsmEncoder) void {
        if (self.g != null) c.gsm_destroy(self.g);
        self.g = null;
    }

    pub fn encodeBlock(self: *GsmEncoder, pcm: []const i16, out: []u8) Error!void {
        if (self.g == null) return error.NotReady;
        if (pcm.len != block_samples) return error.InvalidPdu;
        if (out.len < block_bytes) return error.EndOfBuffer;
        var frame: [frame_samples]c.gsm_signal = undefined;
        @memcpy(&frame, pcm[0..frame_samples]);
        // WAV49: the first frame takes 32.5 bytes; libgsm carries the half byte.
        c.gsm_encode(self.g, &frame, out.ptr);
        @memcpy(&frame, pcm[frame_samples..block_samples]);
        c.gsm_encode(self.g, &frame, out.ptr + 32);
    }
};

pub const GsmDecoder = struct {
    g: c.gsm = null,

    pub fn init() Error!GsmDecoder {
        return .{ .g = try create() };
    }

    pub fn deinit(self: *GsmDecoder) void {
        if (self.g != null) c.gsm_destroy(self.g);
        self.g = null;
    }

    pub fn decodeBlock(self: *GsmDecoder, block: []const u8, out: []i16) Error![]i16 {
        if (self.g == null) return error.NotReady;
        if (block.len != block_bytes) return error.InvalidPdu;
        if (out.len < block_samples) return error.EndOfBuffer;
        var buf: [block_bytes]u8 = undefined;
        @memcpy(&buf, block);
        if (c.gsm_decode(self.g, &buf, out.ptr) < 0) return error.InvalidPdu;
        if (c.gsm_decode(self.g, buf[33..].ptr, out.ptr + frame_samples) < 0) return error.InvalidPdu;
        return out[0..block_samples];
    }
};

test "GSM 06.10 WAV49 round-trips a 440 Hz tone" {
    var enc = try GsmEncoder.init();
    defer enc.deinit();
    var dec = try GsmDecoder.init();
    defer dec.deinit();
    var pcm: [block_samples]i16 = undefined;
    var blk: [block_bytes]u8 = undefined;
    var out: [block_samples]i16 = undefined;
    var s: f64 = 0;
    var co: f64 = 0;
    var energy: f64 = 0;
    var count: f64 = 0;
    for (0..50) |k| {
        for (&pcm, 0..) |*p, i| {
            const t = @as(f64, @floatFromInt(k * block_samples + i)) / 8000.0;
            p.* = @intFromFloat(10000 * @sin(2 * std.math.pi * 440 * t));
        }
        try enc.encodeBlock(&pcm, &blk);
        const d = try dec.decodeBlock(&blk, &out);
        if (k < 5) continue;
        for (d, 0..) |v, i| {
            const t = 2 * std.math.pi * 440 * @as(f64, @floatFromInt(k * block_samples + i)) / 8000.0;
            const x: f64 = @floatFromInt(v);
            s += x * @sin(t);
            co += x * @cos(t);
            energy += x * x;
            count += 1;
        }
    }
    const a = 2 * s / count;
    const b = 2 * co / count;
    const amp = @sqrt(a * a + b * b);
    // GSM is a speech codec: the level is close, the waveform roughly kept.
    try std.testing.expect(amp > 6000 and amp < 14000);
    try std.testing.expect(amp * amp / 2 > 0.7 * energy / count);
}
