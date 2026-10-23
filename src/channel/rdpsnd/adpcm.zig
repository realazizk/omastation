//! Block ADPCM codecs of MS-RDPEA 4.1.1: IMA (WAVE_FORMAT_DVI_ADPCM) and Microsoft ADPCM
//! (WAVE_FORMAT_ADPCM), 4 bits a sample in nBlockAlign blocks that decode independently.

const std = @import("std");
const rdpsnd = @import("../rdpsnd.zig");

const Error = rdpsnd.Error;

// IMA (DVI) ADPCM

const ima_index_table = [16]i8{ -1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8 };
const ima_step_table = [89]i32{
    7,     8,     9,     10,    11,    12,    13,    14,    16,    17,
    19,    21,    23,    25,    28,    31,    34,    37,    41,    45,
    50,    55,    60,    66,    73,    80,    88,    97,    107,   118,
    130,   143,   157,   173,   190,   209,   230,   253,   279,   307,
    337,   371,   408,   449,   494,   544,   598,   658,   724,   796,
    876,   963,   1060,  1166,  1282,  1411,  1552,  1707,  1878,  2066,
    2272,  2499,  2749,  3024,  3327,  3660,  4026,  4428,  4871,  5358,
    5894,  6484,  7132,  7845,  8630,  9493,  10442, 11487, 12635, 13899,
    15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
};
const ima_max_index = ima_step_table.len - 1;

const ImaChannel = struct {
    pred: i32 = 0,
    index: u8 = 0,

    fn adapt(s: *ImaChannel, nib: u4) void {
        const i = @as(i32, s.index) + ima_index_table[nib];
        s.index = @intCast(std.math.clamp(i, 0, ima_max_index));
    }

    fn decode(s: *ImaChannel, nib: u4) i16 {
        const step = ima_step_table[s.index];
        var diff = step >> 3;
        if (nib & 4 != 0) diff += step;
        if (nib & 2 != 0) diff += step >> 1;
        if (nib & 1 != 0) diff += step >> 2;
        s.pred = std.math.clamp(if (nib & 8 != 0) s.pred - diff else s.pred + diff, -32768, 32767);
        s.adapt(nib);
        return @intCast(s.pred);
    }

    /// Reference quantizer; the predictor tracks the decoder's reconstruction.
    fn encode(s: *ImaChannel, sample: i16) u4 {
        var step = ima_step_table[s.index];
        var diff = @as(i32, sample) - s.pred;
        var nib: u4 = 0;
        if (diff < 0) {
            nib = 8;
            diff = -diff;
        }
        var vpdiff = step >> 3;
        if (diff >= step) {
            nib |= 4;
            diff -= step;
            vpdiff += step;
        }
        step >>= 1;
        if (diff >= step) {
            nib |= 2;
            diff -= step;
            vpdiff += step;
        }
        step >>= 1;
        if (diff >= step) {
            nib |= 1;
            vpdiff += step;
        }
        s.pred = std.math.clamp(if (nib & 8 != 0) s.pred - vpdiff else s.pred + vpdiff, -32768, 32767);
        s.adapt(nib);
        return nib;
    }
};

/// MS-RDPEA 4.1.1 IMA ADPCM layout: 4-byte headers plus whole 4-byte groups per channel.
fn imaCheck(channels: u16, block_align: u16) Error!void {
    if (channels < 1 or channels > 2) return error.UnsupportedFormat;
    const group = 4 * @as(usize, channels);
    if (block_align <= group or block_align % group != 0) return error.UnsupportedFormat;
}

/// The header sample, then 8 samples per 4-byte group.
pub fn imaSamplesPerBlock(channels: u16, block_align: u16) usize {
    const ch: usize = channels;
    return (@as(usize, block_align) - 4 * ch) * 8 / (4 * ch) + 1;
}

/// Per channel a 4-byte header (first sample i16, step index u8, 0), then per channel 4-byte
/// groups of 8 samples, low nibble first. The step index carries over between blocks.
pub const ImaAdpcmEncoder = struct {
    channels: u16,
    block_align: u16,
    state: [2]ImaChannel = .{ .{}, .{} },

    pub fn init(channels: u16, block_align: u16) Error!ImaAdpcmEncoder {
        try imaCheck(channels, block_align);
        return .{ .channels = channels, .block_align = block_align };
    }

    /// Interleaved samples per channel in one block (wSamplesPerBlock).
    pub fn samplesPerBlock(self: *const ImaAdpcmEncoder) Error!usize {
        return imaSamplesPerBlock(self.channels, self.block_align);
    }

    /// `pcm` holds samplesPerBlock() * channels interleaved samples; writes block_align bytes.
    pub fn encodeBlock(self: *ImaAdpcmEncoder, pcm: []const i16, out: []u8) Error!void {
        const ch: usize = self.channels;
        const ba: usize = self.block_align;
        if (pcm.len != imaSamplesPerBlock(self.channels, self.block_align) * ch) return error.InvalidPdu;
        if (out.len < ba) return error.EndOfBuffer;
        for (0..ch) |c| {
            const st = &self.state[c];
            st.pred = pcm[c];
            std.mem.writeInt(i16, out[4 * c ..][0..2], pcm[c], .little);
            out[4 * c + 2] = st.index;
            out[4 * c + 3] = 0;
        }
        var pos: usize = 4 * ch;
        var frame: usize = 1;
        while (pos < ba) : ({
            pos += 4 * ch;
            frame += 8;
        }) {
            for (0..ch) |c| {
                const st = &self.state[c];
                for (0..4) |k| {
                    const lo = st.encode(pcm[(frame + 2 * k) * ch + c]);
                    const hi = st.encode(pcm[(frame + 2 * k + 1) * ch + c]);
                    out[pos + 4 * c + k] = @as(u8, lo) | (@as(u8, hi) << 4);
                }
            }
        }
    }
};

pub const ImaAdpcmDecoder = struct {
    channels: u16,
    block_align: u16,

    pub fn init(channels: u16, block_align: u16) Error!ImaAdpcmDecoder {
        try imaCheck(channels, block_align);
        return .{ .channels = channels, .block_align = block_align };
    }

    /// `block` must be exactly block_align bytes; returns the interleaved samples written.
    pub fn decodeBlock(self: *ImaAdpcmDecoder, block: []const u8, out: []i16) Error![]i16 {
        const ch: usize = self.channels;
        const ba: usize = self.block_align;
        if (block.len < ba) return error.EndOfBuffer;
        if (block.len > ba) return error.InvalidPdu;
        const n = imaSamplesPerBlock(self.channels, self.block_align) * ch;
        if (out.len < n) return error.EndOfBuffer;
        var st: [2]ImaChannel = undefined;
        for (0..ch) |c| {
            if (block[4 * c + 2] > ima_max_index) return error.InvalidPdu;
            st[c] = .{ .pred = std.mem.readInt(i16, block[4 * c ..][0..2], .little), .index = block[4 * c + 2] };
            out[c] = @intCast(st[c].pred);
        }
        var pos: usize = 4 * ch;
        var frame: usize = 1;
        while (pos < ba) : ({
            pos += 4 * ch;
            frame += 8;
        }) {
            for (0..ch) |c| {
                for (0..4) |k| {
                    const b = block[pos + 4 * c + k];
                    out[(frame + 2 * k) * ch + c] = st[c].decode(@intCast(b & 0x0F));
                    out[(frame + 2 * k + 1) * ch + c] = st[c].decode(@intCast(b >> 4));
                }
            }
        }
        return out[0..n];
    }
};

// Microsoft ADPCM

const ms_adapt = [16]i32{ 230, 230, 230, 230, 307, 409, 512, 614, 768, 614, 512, 409, 307, 230, 230, 230 };
/// The 7 standard coefficient pairs (MS-RDPEA 4.1.1 format extra data).
pub const ms_coef1 = [7]i16{ 256, 512, 0, 192, 240, 460, 392 };
pub const ms_coef2 = [7]i16{ 0, -256, 0, 64, 0, -208, -232 };
const ms_min_delta: i32 = 16;
/// Keeps 768 * iDelta within i32 on garbage input.
const ms_max_delta: i32 = std.math.maxInt(i32) / 768;

const MsChannel = struct {
    pred: u8 = 0,
    delta: i32 = ms_min_delta,
    s1: i32 = 0,
    s2: i32 = 0,

    fn predict(s: *const MsChannel) i32 {
        return @divTrunc(s.s1 * ms_coef1[s.pred] + s.s2 * ms_coef2[s.pred], 256);
    }

    /// Decode one nibble (also the encoder's reconstruction).
    fn step(s: *MsChannel, nib: u4) i16 {
        const sn: i32 = if (nib & 8 != 0) @as(i32, nib) - 16 else nib;
        const v = std.math.clamp(s.predict() + sn * s.delta, -32768, 32767);
        s.s2 = s.s1;
        s.s1 = v;
        s.delta = std.math.clamp(@divTrunc(ms_adapt[nib] * s.delta, 256), ms_min_delta, ms_max_delta);
        return @intCast(v);
    }

    /// Nearest nibble: error / iDelta rounded half away from zero, clamped to -8..7.
    fn encode(s: *MsChannel, sample: i16) u4 {
        const e = @as(i32, sample) - s.predict();
        const bias = @divTrunc(s.delta, 2);
        const q = std.math.clamp(@divTrunc(if (e >= 0) e + bias else e - bias, s.delta), -8, 7);
        const nib: u4 = @intCast(q & 0x0F);
        _ = s.step(nib);
        return nib;
    }
};

fn msCheck(channels: u16, block_align: u16) Error!void {
    if (channels < 1 or channels > 2) return error.UnsupportedFormat;
    if (block_align <= 7 * @as(usize, channels)) return error.UnsupportedFormat;
}

/// The two header samples, then two nibbles a byte.
pub fn msSamplesPerBlock(channels: u16, block_align: u16) usize {
    const ch: usize = channels;
    return (@as(usize, block_align) - 7 * ch) * 2 / ch + 2;
}

/// Per channel bPredictor, iDelta, iSamp1, iSamp2, then nibbles, high first. The encoder picks
/// the predictor that reconstructs each block best; iDelta carries over between blocks.
pub const MsAdpcmEncoder = struct {
    channels: u16,
    block_align: u16,
    delta: [2]i32 = .{ ms_min_delta, ms_min_delta },

    pub fn init(channels: u16, block_align: u16) Error!MsAdpcmEncoder {
        try msCheck(channels, block_align);
        return .{ .channels = channels, .block_align = block_align };
    }

    pub fn samplesPerBlock(self: *const MsAdpcmEncoder) Error!usize {
        return msSamplesPerBlock(self.channels, self.block_align);
    }

    /// `pcm` holds samplesPerBlock() * channels interleaved samples; writes block_align bytes.
    pub fn encodeBlock(self: *MsAdpcmEncoder, pcm: []const i16, out: []u8) Error!void {
        const ch: usize = self.channels;
        const ba: usize = self.block_align;
        const spb = msSamplesPerBlock(self.channels, self.block_align);
        if (pcm.len != spb * ch) return error.InvalidPdu;
        if (out.len < ba) return error.EndOfBuffer;

        var st: [2]MsChannel = undefined;
        for (0..ch) |c| {
            // The header iDelta is 16 bits.
            const delta = std.math.clamp(self.delta[c], ms_min_delta, std.math.maxInt(i16));
            const start = MsChannel{ .delta = delta, .s1 = pcm[ch + c], .s2 = pcm[c] };
            var best: MsChannel = start;
            var best_err: u64 = std.math.maxInt(u64);
            for (0..ms_coef1.len) |p| {
                var trial = start;
                trial.pred = @intCast(p);
                var err: u64 = 0;
                var f: usize = 2;
                while (f < spb and err < best_err) : (f += 1) {
                    const x = pcm[f * ch + c];
                    _ = trial.encode(x);
                    const d: i64 = @as(i64, x) - trial.s1;
                    err += @intCast(d * d);
                }
                if (err < best_err) {
                    best_err = err;
                    best = start;
                    best.pred = @intCast(p);
                }
            }
            st[c] = best;
        }

        for (0..ch) |c| out[c] = st[c].pred;
        for (0..ch) |c| std.mem.writeInt(i16, out[ch + 2 * c ..][0..2], @intCast(st[c].delta), .little);
        for (0..ch) |c| std.mem.writeInt(i16, out[3 * ch + 2 * c ..][0..2], @intCast(st[c].s1), .little);
        for (0..ch) |c| std.mem.writeInt(i16, out[5 * ch + 2 * c ..][0..2], @intCast(st[c].s2), .little);

        var i: usize = 2 * ch;
        var pos: usize = 7 * ch;
        while (pos < ba) : (pos += 1) {
            const hi = st[i % ch].encode(pcm[i]);
            const lo = st[(i + 1) % ch].encode(pcm[i + 1]);
            out[pos] = (@as(u8, hi) << 4) | lo;
            i += 2;
        }
        for (0..ch) |c| self.delta[c] = st[c].delta;
    }
};

pub const MsAdpcmDecoder = struct {
    channels: u16,
    block_align: u16,

    pub fn init(channels: u16, block_align: u16) Error!MsAdpcmDecoder {
        try msCheck(channels, block_align);
        return .{ .channels = channels, .block_align = block_align };
    }

    /// `block` must be exactly block_align bytes; a predictor index >= 7 is InvalidPdu.
    pub fn decodeBlock(self: *MsAdpcmDecoder, block: []const u8, out: []i16) Error![]i16 {
        const ch: usize = self.channels;
        const ba: usize = self.block_align;
        if (block.len < ba) return error.EndOfBuffer;
        if (block.len > ba) return error.InvalidPdu;
        const n = msSamplesPerBlock(self.channels, self.block_align) * ch;
        if (out.len < n) return error.EndOfBuffer;
        var st: [2]MsChannel = undefined;
        for (0..ch) |c| {
            if (block[c] >= ms_coef1.len) return error.InvalidPdu;
            st[c] = .{
                .pred = block[c],
                .delta = std.mem.readInt(i16, block[ch + 2 * c ..][0..2], .little),
                .s1 = std.mem.readInt(i16, block[3 * ch + 2 * c ..][0..2], .little),
                .s2 = std.mem.readInt(i16, block[5 * ch + 2 * c ..][0..2], .little),
            };
            out[c] = @intCast(st[c].s2);
            out[ch + c] = @intCast(st[c].s1);
        }
        var o: usize = 2 * ch;
        for (block[7 * ch .. ba]) |b| {
            out[o] = st[o % ch].step(@intCast(b >> 4));
            out[o + 1] = st[(o + 1) % ch].step(@intCast(b & 0x0F));
            o += 2;
        }
        return out[0..n];
    }
};
