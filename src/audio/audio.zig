//! Desktop audio for the session: playback to the client (MS-RDPEA) and the
//! client's microphone as a desktop audio source (MS-RDPEAI).

const std = @import("std");
const rdpsnd = @import("../channel/rdpsnd.zig");

pub const ring = @import("ring.zig");
pub const resample = @import("resample.zig");
pub const exchange = @import("exchange.zig");
pub const bridge = @import("bridge.zig");
pub const playback = @import("playback.zig");
pub const mic = @import("mic.zig");
pub const jitter = @import("jitter.zig");
pub const fake = @import("fake.zig");
pub const pod = @import("pod.zig");
pub const pipewire = @import("pipewire.zig");

pub const Error = bridge.Error;
pub const Ring = ring.Ring;
pub const Resampler = resample.Resampler;
pub const Converter = resample.Converter;
pub const Exchange = exchange.Exchange;
pub const MicQueue = exchange.MicQueue;
pub const Backend = bridge.Backend;
pub const Bridge = bridge.Bridge;
pub const Config = bridge.Config;
pub const Chunk = bridge.Chunk;
pub const StreamState = bridge.StreamState;
pub const Playback = playback.Playback;
pub const PcmQueue = playback.PcmQueue;
pub const Engine = playback.Engine;
pub const WaveEncoder = playback.WaveEncoder;
pub const MicDecoder = mic.MicDecoder;
pub const MicFormat = mic.MicFormat;
pub const FakeBackend = fake.FakeBackend;
pub const PipeWire = pipewire.PipeWire;

pub const capture_rate = exchange.capture_rate;
pub const capture_channels = exchange.capture_channels;
pub const chunk_ms = exchange.chunk_ms;
pub const chunk_frames = exchange.chunk_frames;
pub const chunk_samples = exchange.chunk_samples;
pub const canDecode = mic.canDecode;

/// Sound Formats PDU offer, most preferred first; PCM 44.1 kHz 16-bit stereo first, as Windows (MS-RDPEAI 4.1.3).
pub const mic_formats = [_]rdpsnd.AudioFormat{
    .{ .tag = rdpsnd.WAVE_FORMAT_PCM, .channels = 2, .samples_per_sec = 44100, .avg_bytes_per_sec = 176400, .block_align = 4, .bits_per_sample = 16 },
    .{ .tag = rdpsnd.WAVE_FORMAT_PCM, .channels = 1, .samples_per_sec = 44100, .avg_bytes_per_sec = 88200, .block_align = 2, .bits_per_sample = 16 },
    .{ .tag = rdpsnd.WAVE_FORMAT_PCM, .channels = 2, .samples_per_sec = 22050, .avg_bytes_per_sec = 88200, .block_align = 4, .bits_per_sample = 16 },
    .{ .tag = rdpsnd.WAVE_FORMAT_PCM, .channels = 1, .samples_per_sec = 22050, .avg_bytes_per_sec = 44100, .block_align = 2, .bits_per_sample = 16 },
    .{ .tag = rdpsnd.WAVE_FORMAT_OPUS, .channels = 1, .samples_per_sec = 48000, .avg_bytes_per_sec = 8000, .block_align = 2, .bits_per_sample = 16 },
    .{ .tag = rdpsnd.WAVE_FORMAT_ALAW, .channels = 1, .samples_per_sec = 22050, .avg_bytes_per_sec = 22050, .block_align = 1, .bits_per_sample = 8 },
    .{ .tag = rdpsnd.WAVE_FORMAT_MULAW, .channels = 1, .samples_per_sec = 22050, .avg_bytes_per_sec = 22050, .block_align = 1, .bits_per_sample = 8 },
};

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(Ring);
    std.testing.refAllDecls(Resampler);
    std.testing.refAllDecls(Converter);
    std.testing.refAllDecls(Exchange);
    std.testing.refAllDecls(MicQueue);
    std.testing.refAllDecls(jitter);
    std.testing.refAllDecls(Backend);
    std.testing.refAllDecls(Bridge);
    std.testing.refAllDecls(Playback);
    std.testing.refAllDecls(PcmQueue);
    std.testing.refAllDecls(Engine);
    std.testing.refAllDecls(WaveEncoder);
    std.testing.refAllDecls(MicDecoder);
    std.testing.refAllDecls(FakeBackend);
    std.testing.refAllDecls(PipeWire);
}
