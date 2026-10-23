//! Sample-rate and channel conversion: band-limited sinc resampling (J. O. Smith, "Digital
//! Audio Resampling") with rational positions and state carried across calls, so chunking
//! does not change the output. Kaiser filter for the lower rate: 0.9 Nyquist, 100 dB stopband.

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Error = error{
    /// Rate outside [min_rate, max_rate] or channels outside [1, max_channels].
    UnsupportedFormat,
    OutOfMemory,
};

/// The rates rdpsnd.canEncode accepts (min_sample_rate, max_sample_rate).
pub const min_rate: u32 = 1000;
pub const max_rate: u32 = 384000;
pub const max_channels: u16 = 8;

/// Exact phase rows up to this denominator; beyond it, interp_phases rows linearly interpolated.
pub const max_exact_phases: u64 = 512;
pub const interp_phases: usize = 256;
/// Stopband attenuation of the filter (dB).
const stopband_db: f64 = 100;
/// Transition band, as a fraction of the lower Nyquist frequency.
const transition: f64 = 0.1;
/// Extreme ratios get a wider transition band instead of a longer filter.
const max_taps: usize = 2048;

pub const Resampler = struct {
    gpa: Allocator,
    channels: usize,
    in_rate: u32,
    out_rate: u32,
    /// Input samples per output sample: num / den, reduced.
    num: u64,
    den: u64,
    /// Taps on each side of the output position (the filter has 2 * half).
    half: usize,
    taps: usize,
    phases: usize,
    exact: bool,
    /// (phases + 1) rows of `taps`; row p is the filter at position p / phases (the last for interpolation).
    coef: []f32,
    /// Planar input history scaled to [-1, 1); sample i is input frame base + i.
    hist: []std.ArrayList(f32),
    base: i64,
    /// Position of the next output: input frame ipos + frac / den.
    ipos: i64 = 0,
    frac: u64 = 0,

    pub fn init(gpa: Allocator, in_rate: u32, out_rate: u32, channels: u16) Error!Resampler {
        try checkRate(in_rate);
        try checkRate(out_rate);
        if (channels == 0 or channels > max_channels) return error.UnsupportedFormat;
        const g = std.math.gcd(in_rate, out_rate);
        const num: u64 = in_rate / g;
        const den: u64 = out_rate / g;

        // Kaiser design for the lower rate (cycles per input sample).
        const ratio = @min(1.0, @as(f64, @floatFromInt(out_rate)) / @as(f64, @floatFromInt(in_rate)));
        const nyq = 0.5 * ratio;
        var tw = transition * nyq;
        var n_taps: usize = @intFromFloat(@ceil((stopband_db - 7.95) / (14.36 * tw)));
        if (n_taps > max_taps) {
            n_taps = max_taps;
            tw = (stopband_db - 7.95) / (14.36 * @as(f64, @floatFromInt(n_taps)));
        }
        const half = n_taps / 2 + 1;
        const taps = 2 * half;
        const fc = nyq - tw / 2;
        const beta = 0.1102 * (stopband_db - 8.7);

        const exact = den <= max_exact_phases;
        const phases: usize = if (exact) @intCast(den) else interp_phases;
        const coef = try gpa.alloc(f32, (phases + 1) * taps);
        errdefer gpa.free(coef);
        const i0_beta = besselI0(beta);
        for (0..phases + 1) |p| {
            const phase = @as(f64, @floatFromInt(p)) / @as(f64, @floatFromInt(phases));
            const row = coef[p * taps ..][0..taps];
            var sum: f64 = 0;
            var tmp: [max_taps + 2]f64 = undefined;
            for (0..taps) |m| {
                // Distance from the output position to input frame ipos - half + 1 + m.
                const x = phase + @as(f64, @floatFromInt(half)) - 1 - @as(f64, @floatFromInt(m));
                const v = kernel(x, fc, @floatFromInt(half), beta, i0_beta);
                tmp[m] = v;
                sum += v;
            }
            // Unity gain at DC for every phase.
            for (row, tmp[0..taps]) |*c, v| c.* = @floatCast(v / sum);
        }

        const hist = try gpa.alloc(std.ArrayList(f32), channels);
        errdefer gpa.free(hist);
        for (hist) |*h| h.* = .empty;
        var self: Resampler = .{
            .gpa = gpa,
            .channels = channels,
            .in_rate = in_rate,
            .out_rate = out_rate,
            .num = num,
            .den = den,
            .half = half,
            .taps = taps,
            .phases = phases,
            .exact = exact,
            .coef = coef,
            .hist = hist,
            .base = 0,
        };
        errdefer self.deinit();
        try self.reset();
        return self;
    }

    pub fn deinit(self: *Resampler) void {
        for (self.hist) |*h| h.deinit(self.gpa);
        self.gpa.free(self.hist);
        self.gpa.free(self.coef);
        self.* = undefined;
    }

    /// Silence before the next input.
    pub fn reset(self: *Resampler) Allocator.Error!void {
        for (self.hist) |*h| {
            h.clearRetainingCapacity();
            // Silence before frame 0 so the first output has its full window.
            try h.appendNTimes(self.gpa, 0, self.half - 1);
        }
        self.base = -@as(i64, @intCast(self.half - 1));
        self.ipos = 0;
        self.frac = 0;
    }

    /// Output delay behind the input, in input frames.
    pub fn latencyFrames(self: *const Resampler) usize {
        return self.half;
    }

    /// Appends the outputs the input so far determines (a trailing partial frame is ignored).
    pub fn process(self: *Resampler, in: []const i16, out: *std.ArrayList(i16)) Allocator.Error!void {
        const ch = self.channels;
        const frames = in.len / ch;
        for (self.hist, 0..) |*h, c| {
            try h.ensureUnusedCapacity(self.gpa, frames);
            for (0..frames) |i| h.appendAssumeCapacity(@as(f32, @floatFromInt(in[i * ch + c])) * (1.0 / 32768.0));
        }
        const held: i64 = @intCast(self.hist[0].items.len);
        const last = self.base + held - 1;
        const half: i64 = @intCast(self.half);
        if (self.ipos + half > last) return;
        // Outputs this call: positions up to last - half.
        const span: u64 = @intCast(last - half - self.ipos);
        const n_out: usize = @intCast((span * self.den + (self.den - 1 - self.frac)) / self.num + 1);
        try out.ensureUnusedCapacity(self.gpa, n_out * ch);
        while (self.ipos + half <= last) {
            const start: usize = @intCast(self.ipos - half + 1 - self.base);
            if (self.exact) {
                const row = self.coef[@as(usize, @intCast(self.frac)) * self.taps ..][0..self.taps];
                for (self.hist) |h| out.appendAssumeCapacity(toI16(dot(row, h.items[start..][0..self.taps])));
            } else {
                const pf = self.frac * self.phases;
                const p0: usize = @intCast(pf / self.den);
                const a: f32 = @floatCast(@as(f64, @floatFromInt(pf % self.den)) / @as(f64, @floatFromInt(self.den)));
                const r0 = self.coef[p0 * self.taps ..][0..self.taps];
                const r1 = self.coef[(p0 + 1) * self.taps ..][0..self.taps];
                for (self.hist) |h| {
                    const x = h.items[start..][0..self.taps];
                    out.appendAssumeCapacity(toI16((1 - a) * dot(r0, x) + a * dot(r1, x)));
                }
            }
            self.frac += self.num;
            self.ipos += @intCast(self.frac / self.den);
            self.frac %= self.den;
        }
        // Keep what the next output needs: frames from ipos - half + 1.
        const drop_to = self.ipos - half + 1 - self.base;
        if (drop_to > 0) {
            const d: usize = @intCast(@min(drop_to, held));
            for (self.hist) |*h| {
                const rest = h.items.len - d;
                std.mem.copyForwards(f32, h.items[0..rest], h.items[d..]);
                h.shrinkRetainingCapacity(rest);
            }
            self.base += @intCast(d);
        }
    }
};

fn checkRate(rate: u32) Error!void {
    if (rate < min_rate or rate > max_rate) return error.UnsupportedFormat;
}

/// Kaiser-windowed sinc low-pass, cutoff `fc` cycles per sample, half-width `half`.
fn kernel(x: f64, fc: f64, half: f64, beta: f64, i0_beta: f64) f64 {
    if (@abs(x) >= half) return 0;
    const t = x / half;
    const w = besselI0(beta * @sqrt(1 - t * t)) / i0_beta;
    const arg = 2 * fc * x;
    const sinc = if (@abs(arg) < 1e-12) 1.0 else @sin(std.math.pi * arg) / (std.math.pi * arg);
    return 2 * fc * sinc * w;
}

/// Modified Bessel function of the first kind, order 0 (power series).
fn besselI0(x: f64) f64 {
    var sum: f64 = 1;
    var term: f64 = 1;
    const h = x / 2;
    var k: f64 = 1;
    while (k < 200) : (k += 1) {
        term *= (h / k) * (h / k);
        sum += term;
        if (term < sum * 1e-17) break;
    }
    return sum;
}

fn dot(a: []const f32, b: []const f32) f32 {
    const V = @Vector(8, f32);
    var acc: V = @splat(0);
    var i: usize = 0;
    while (i + 8 <= a.len) : (i += 8) {
        const va: V = a[i..][0..8].*;
        const vb: V = b[i..][0..8].*;
        acc += va * vb;
    }
    var s = @reduce(.Add, acc);
    while (i < a.len) : (i += 1) s += a[i] * b[i];
    return s;
}

fn toI16(v: f32) i16 {
    const s = @round(v * 32768.0);
    return @intFromFloat(std.math.clamp(s, -32768.0, 32767.0));
}

/// Channel remix appended to `out`: to mono averages, from mono duplicates; otherwise channel
/// k is input k, or k mod in (front left/right come first in WAVE and SPA order alike).
pub fn remix(gpa: Allocator, in: []const i16, in_ch: u16, out_ch: u16, out: *std.ArrayList(i16)) Allocator.Error!void {
    const frames = in.len / in_ch;
    try out.ensureUnusedCapacity(gpa, frames * out_ch);
    if (in_ch == out_ch) {
        out.appendSliceAssumeCapacity(in[0 .. frames * in_ch]);
    } else if (out_ch == 1) {
        for (0..frames) |f| {
            var sum: i32 = 0;
            for (in[f * in_ch ..][0..in_ch]) |s| sum += s;
            out.appendAssumeCapacity(@intCast(@divFloor(sum * 2 + in_ch, 2 * @as(i32, in_ch))));
        }
    } else {
        for (0..frames) |f| {
            for (0..out_ch) |k| out.appendAssumeCapacity(in[f * in_ch + k % in_ch]);
        }
    }
}

pub const Converter = struct {
    gpa: Allocator,
    in_rate: u32,
    in_channels: u16,
    out_rate: u32,
    out_channels: u16,
    /// Null when the rates are equal.
    rs: ?Resampler,
    tmp: std.ArrayList(i16) = .empty,

    pub fn init(gpa: Allocator, in_rate: u32, in_channels: u16, out_rate: u32, out_channels: u16) Error!Converter {
        try checkRate(in_rate);
        try checkRate(out_rate);
        if (in_channels == 0 or in_channels > max_channels or out_channels == 0 or out_channels > max_channels)
            return error.UnsupportedFormat;
        const rs: ?Resampler = if (in_rate == out_rate) null else try Resampler.init(gpa, in_rate, out_rate, @min(in_channels, out_channels));
        return .{ .gpa = gpa, .in_rate = in_rate, .in_channels = in_channels, .out_rate = out_rate, .out_channels = out_channels, .rs = rs };
    }

    pub fn deinit(self: *Converter) void {
        if (self.rs) |*r| r.deinit();
        self.tmp.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn reset(self: *Converter) Allocator.Error!void {
        if (self.rs) |*r| try r.reset();
    }

    pub fn process(self: *Converter, in: []const i16, out: *std.ArrayList(i16)) Allocator.Error!void {
        const r = if (self.rs) |*rs| rs else return remix(self.gpa, in, self.in_channels, self.out_channels, out);
        self.tmp.clearRetainingCapacity();
        if (self.out_channels < self.in_channels) {
            try remix(self.gpa, in, self.in_channels, self.out_channels, &self.tmp);
            try r.process(self.tmp.items, out);
        } else if (self.out_channels > self.in_channels) {
            try r.process(in, &self.tmp);
            try remix(self.gpa, self.tmp.items, self.in_channels, self.out_channels, out);
        } else {
            try r.process(in, out);
        }
    }
};

test "resampler: chunked and one-piece input give the same samples" {
    const gpa = std.testing.allocator;
    var in: [3000]i16 = undefined;
    for (&in, 0..) |*s, i| s.* = @intFromFloat(12000 * @sin(@as(f64, @floatFromInt(i)) * 0.05));
    var a = try Resampler.init(gpa, 48000, 44100, 1);
    defer a.deinit();
    var b = try Resampler.init(gpa, 48000, 44100, 1);
    defer b.deinit();
    var oa: std.ArrayList(i16) = .empty;
    defer oa.deinit(gpa);
    var ob: std.ArrayList(i16) = .empty;
    defer ob.deinit(gpa);
    try a.process(&in, &oa);
    var at: usize = 0;
    var step: usize = 1;
    while (at < in.len) : (step = step * 7 % 401 + 1) {
        const n = @min(step, in.len - at);
        try b.process(in[at..][0..n], &ob);
        at += n;
    }
    try std.testing.expectEqualSlices(i16, oa.items, ob.items);
}

test "remix: mono mean rounds, mono duplicates" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(i16) = .empty;
    defer out.deinit(gpa);
    try remix(gpa, &.{ 1, 2, -3, -4, 32767, 32767 }, 2, 1, &out);
    try std.testing.expectEqualSlices(i16, &.{ 2, -3, 32767 }, out.items);
    out.clearRetainingCapacity();
    try remix(gpa, &.{ 5, -6 }, 1, 2, &out);
    try std.testing.expectEqualSlices(i16, &.{ 5, 5, -6, -6 }, out.items);
}
