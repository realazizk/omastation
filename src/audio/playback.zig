//! Desktop audio to the client (MS-RDPEA) as a Windows server sends it: the capture is
//! resampled to 44.1 kHz stereo, encoded to the client's format and sent as blocks fill,
//! never waiting for Wave Confirms. An idle stream ends with a Close after idle_close_ms.

const std = @import("std");
const rdpsnd = @import("../channel/rdpsnd.zig");
const resample = @import("resample.zig");
const ring_mod = @import("ring.zig");
const xch = @import("exchange.zig");
const bridge = @import("bridge.zig");

const Allocator = std.mem.Allocator;
const AudioFormat = rdpsnd.AudioFormat;

const log = std.log.scoped(.audio);

pub const Error = error{ UnsupportedFormat, OutOfMemory };

/// The endpoint's format: PCM 44.1 kHz stereo 16-bit (rdpsnd.engine_format).
pub const engine_rate: u32 = 44100;
pub const engine_channels: u16 = 2;
pub const queue_blocks: usize = 16;
/// Windows' audio I/O thread wakes at least every 5 s; an idle wake-up while streaming sends Close.
pub const idle_close_ms: u32 = 5000;
/// Capture kept while nothing plays: the lead-in of the next sound, covering the audio
/// system's start report delay (about the 100 ms Windows primes its endpoint with).
pub const lead_in_ms: u32 = 100;

/// 44.1 kHz stereo frames, oldest dropped past capacity, with each write's capture time.
pub const PcmQueue = struct {
    gpa: Allocator,
    ring: ring_mod.Ring,
    /// Capture time (ms) of frame `pos` of each write still held.
    marks: std.ArrayList(Mark) = .empty,
    /// Frames dropped because the queue was full.
    dropped: u64 = 0,

    const Mark = struct { pos: u64, ts_ms: u64 };

    pub fn init(gpa: Allocator, capacity_frames: usize) Error!PcmQueue {
        const r = ring_mod.Ring.init(gpa, engine_channels, capacity_frames) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidArgument => error.UnsupportedFormat,
        };
        return .{ .gpa = gpa, .ring = r };
    }

    pub fn deinit(self: *PcmQueue) void {
        self.ring.deinit(self.gpa);
        self.marks.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn len(self: *const PcmQueue) usize {
        return self.ring.len();
    }

    pub fn capacity(self: *const PcmQueue) usize {
        return self.ring.capacity;
    }

    /// Keeps what is held (its newest frames when it no longer fits).
    pub fn setCapacity(self: *PcmQueue, frames: usize) Error!void {
        if (frames == self.ring.capacity) return;
        var r = ring_mod.Ring.init(self.gpa, engine_channels, frames) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidArgument => error.UnsupportedFormat,
        };
        errdefer r.deinit(self.gpa);
        const held = self.ring.len();
        const tmp = try self.gpa.alloc(i16, held * engine_channels);
        defer self.gpa.free(tmp);
        _ = self.ring.peek(tmp);
        // Positions keep counting so the marks stay valid.
        r.rpos = self.ring.rpos;
        r.wpos = self.ring.rpos;
        self.dropped += r.write(tmp);
        self.ring.deinit(self.gpa);
        self.ring = r;
        self.pruneMarks();
    }

    /// Frames whose first was captured at `ts_ms`; the oldest go when they do not fit.
    pub fn write(self: *PcmQueue, pcm: []const i16, ts_ms: u64) Allocator.Error!void {
        if (pcm.len < engine_channels) return;
        try self.marks.append(self.gpa, .{ .pos = self.ring.wpos, .ts_ms = ts_ms });
        self.dropped += self.ring.write(pcm);
        self.pruneMarks();
    }

    /// Keeps the mark the oldest held frame counts from.
    fn pruneMarks(self: *PcmQueue) void {
        var keep: usize = 0;
        while (keep + 1 < self.marks.items.len and self.marks.items[keep + 1].pos <= self.ring.rpos) keep += 1;
        if (keep == 0) return;
        const rest = self.marks.items.len - keep;
        std.mem.copyForwards(Mark, self.marks.items[0..rest], self.marks.items[keep..]);
        self.marks.shrinkRetainingCapacity(rest);
    }

    /// Capture time of the oldest frame held.
    pub fn headTime(self: *const PcmQueue) u64 {
        const rpos = self.ring.rpos;
        var ts: u64 = 0;
        for (self.marks.items) |m| {
            if (m.pos > rpos) break;
            ts = m.ts_ms + (rpos - m.pos) * 1000 / engine_rate;
        }
        return ts;
    }

    /// Returns the frames taken into `out` and the capture time of the first.
    pub fn take(self: *PcmQueue, out: []i16) struct { frames: usize, ts_ms: u64 } {
        const ts = self.headTime();
        const n = self.ring.read(out);
        self.pruneMarks();
        return .{ .frames = n, .ts_ms = ts };
    }

    pub fn clear(self: *PcmQueue) void {
        self.ring.clear();
        self.marks.clearRetainingCapacity();
    }
};

/// Resamples the 48 kHz stereo capture to 44.1 kHz into the queue.
pub const Engine = struct {
    gpa: Allocator,
    conv: resample.Converter,
    out: std.ArrayList(i16) = .empty,

    pub fn init(gpa: Allocator) Error!Engine {
        const conv = resample.Converter.init(gpa, xch.capture_rate, xch.capture_channels, engine_rate, engine_channels) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.UnsupportedFormat => error.UnsupportedFormat,
        };
        return .{ .gpa = gpa, .conv = conv };
    }

    pub fn deinit(self: *Engine) void {
        self.conv.deinit();
        self.out.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn feed(self: *Engine, pcm48: []const i16, ts_ms: u64, q: *PcmQueue) Allocator.Error!void {
        self.out.clearRetainingCapacity();
        try self.conv.process(pcm48, &self.out);
        try q.write(self.out.items, ts_ms);
    }

    /// The converter's history becomes silence.
    pub fn reset(self: *Engine) Allocator.Error!void {
        try self.conv.reset();
    }
};

const Codec = union(enum) {
    pcm16,
    pcm8,
    alaw,
    mulaw,
    ima: rdpsnd.ImaAdpcmEncoder,
    ms: rdpsnd.MsAdpcmEncoder,
    gsm: rdpsnd.GsmEncoder,
    aac: rdpsnd.AacEncoder,
};

/// Blocks of the endpoint's audio to waves in one client format.
pub const WaveEncoder = struct {
    gpa: Allocator,
    /// The client's format (extra data not kept) and its wFormatNo.
    format: AudioFormat,
    format_no: u16,
    /// Null when the format is 44.1 kHz stereo (nothing to convert).
    conv: ?resample.Converter,
    codec: Codec,
    /// Frames per codec unit (1 for PCM and G.711).
    unit: usize,
    pcm: std.ArrayList(i16) = .empty,
    /// Audio came since the last flush; a flush is under way.
    dirty: bool = false,
    flushing: bool = false,
    conv_out: std.ArrayList(i16) = .empty,
    out: std.ArrayList(u8) = .empty,

    /// UnsupportedFormat unless rdpsnd.canEncode(format).
    pub fn init(gpa: Allocator, format: AudioFormat, format_no: u16) Error!WaveEncoder {
        if (!(rdpsnd.canEncode(format) catch false)) return error.UnsupportedFormat;
        var codec: Codec = undefined;
        var unit: usize = 1;
        switch (format.tag) {
            rdpsnd.WAVE_FORMAT_PCM => codec = if (format.bits_per_sample == 16) .pcm16 else .pcm8,
            rdpsnd.WAVE_FORMAT_ALAW => codec = .alaw,
            rdpsnd.WAVE_FORMAT_MULAW => codec = .mulaw,
            rdpsnd.WAVE_FORMAT_DVI_ADPCM => {
                const e = rdpsnd.ImaAdpcmEncoder.init(format.channels, format.block_align) catch return error.UnsupportedFormat;
                unit = e.samplesPerBlock() catch return error.UnsupportedFormat;
                codec = .{ .ima = e };
            },
            rdpsnd.WAVE_FORMAT_ADPCM => {
                const e = rdpsnd.MsAdpcmEncoder.init(format.channels, format.block_align) catch return error.UnsupportedFormat;
                unit = e.samplesPerBlock() catch return error.UnsupportedFormat;
                codec = .{ .ms = e };
            },
            rdpsnd.WAVE_FORMAT_GSM610 => {
                codec = .{ .gsm = rdpsnd.GsmEncoder.init() catch |e| return switch (e) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.UnsupportedFormat,
                } };
                unit = rdpsnd.gsm610_samples_per_block;
            },
            rdpsnd.WAVE_FORMAT_AAC_MS => {
                codec = .{ .aac = rdpsnd.AacEncoder.init(format.samples_per_sec, format.channels, format.avg_bytes_per_sec) catch |e| return switch (e) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.UnsupportedFormat,
                } };
                unit = rdpsnd.aac_frame_length;
            },
            else => return error.UnsupportedFormat,
        }
        errdefer switch (codec) {
            .gsm => |*g| g.deinit(),
            .aac => |*a| a.deinit(),
            else => {},
        };
        const same = format.samples_per_sec == engine_rate and format.channels == engine_channels;
        const conv: ?resample.Converter = if (same) null else resample.Converter.init(gpa, engine_rate, engine_channels, format.samples_per_sec, format.channels) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.UnsupportedFormat => error.UnsupportedFormat,
        };
        var f = format;
        f.extra = &.{};
        return .{ .gpa = gpa, .format = f, .format_no = format_no, .conv = conv, .codec = codec, .unit = unit };
    }

    pub fn deinit(self: *WaveEncoder) void {
        switch (self.codec) {
            .gsm => |*g| g.deinit(),
            .aac => |*a| a.deinit(),
            else => {},
        }
        if (self.conv) |*cv| cv.deinit();
        self.pcm.deinit(self.gpa);
        self.conv_out.deinit(self.gpa);
        self.out.deinit(self.gpa);
        self.* = undefined;
    }

    /// Encodes the whole codec units of one 44.1 kHz stereo block (the rest waits); valid until
    /// the next call, empty when no unit is whole or while AAC fills its look-ahead.
    pub fn encode(self: *WaveEncoder, block: []const i16) Error![]const u8 {
        if (self.conv) |*cv| {
            self.conv_out.clearRetainingCapacity();
            try cv.process(block, &self.conv_out);
            try self.pcm.appendSlice(self.gpa, self.conv_out.items);
        } else {
            try self.pcm.appendSlice(self.gpa, block);
        }
        if (block.len > 0) self.dirty = true;
        // One AAC access unit per wave.
        return self.encodeUnits(if (self.codec == .aac) 1 else std.math.maxInt(usize));
    }

    /// Flushes what the codec holds as waves, one per call (null when done), padding with silence,
    /// so a decoder that outlives a Close holds nothing that would play at the next sound's start.
    pub fn flushNext(self: *WaveEncoder) Error!?[]const u8 {
        if (self.unit == 1) return null; // PCM, G.711: nothing held
        const ch: usize = self.format.channels;
        if (!self.flushing) {
            if (!self.dirty) return null;
            self.dirty = false;
            const have = self.pcm.items.len / ch;
            // AAC: the encoder's delay (2048 frames with fdk-aac), and as much again for the client's decoder.
            const delay: usize = switch (self.codec) {
                .aac => |*e| 2 * e.delay,
                else => 0,
            };
            const look_ahead = (delay + self.unit - 1) / self.unit * self.unit;
            const pad = (self.unit - have % self.unit) % self.unit + look_ahead;
            if (pad == 0 and have == 0) return null;
            try self.pcm.appendNTimes(self.gpa, 0, pad * ch);
            self.flushing = true;
        }
        if (self.pcm.items.len / ch < self.unit) {
            self.flushing = false;
            return null;
        }
        return try self.encodeUnits(if (self.codec == .aac) 1 else std.math.maxInt(usize));
    }

    fn encodeUnits(self: *WaveEncoder, max: usize) Error![]const u8 {
        const ch: usize = self.format.channels;
        const units = @min(max, self.pcm.items.len / ch / self.unit);
        const n = units * self.unit * ch;
        const pcm = self.pcm.items[0..n];
        self.out.clearRetainingCapacity();
        switch (self.codec) {
            .pcm16 => {
                try self.out.ensureUnusedCapacity(self.gpa, 2 * n);
                for (pcm) |s| {
                    var b: [2]u8 = undefined;
                    std.mem.writeInt(i16, &b, s, .little);
                    self.out.appendSliceAssumeCapacity(&b);
                }
            },
            .pcm8 => {
                try self.out.ensureUnusedCapacity(self.gpa, n);
                for (pcm) |s| self.out.appendAssumeCapacity(@intCast((@as(i32, s) + 32768) >> 8));
            },
            .alaw, .mulaw => {
                try self.out.ensureUnusedCapacity(self.gpa, n);
                for (pcm) |s| self.out.appendAssumeCapacity(if (self.codec == .alaw)
                    rdpsnd.alawEncode(s) catch unreachable
                else
                    rdpsnd.mulawEncode(s) catch unreachable);
            },
            .ima => |*e| for (0..units) |k| {
                const blk = try self.out.addManyAsSlice(self.gpa, self.format.block_align);
                e.encodeBlock(pcm[k * self.unit * ch ..][0 .. self.unit * ch], blk) catch return error.UnsupportedFormat;
            },
            .ms => |*e| for (0..units) |k| {
                const blk = try self.out.addManyAsSlice(self.gpa, self.format.block_align);
                e.encodeBlock(pcm[k * self.unit * ch ..][0 .. self.unit * ch], blk) catch return error.UnsupportedFormat;
            },
            .gsm => |*e| for (0..units) |k| {
                const blk = try self.out.addManyAsSlice(self.gpa, rdpsnd.gsm610_block_align);
                e.encodeBlock(pcm[k * self.unit ..][0..self.unit], blk) catch return error.UnsupportedFormat;
            },
            .aac => |*e| for (0..units) |k| {
                const at = self.out.items.len;
                const buf = try self.out.addManyAsSlice(self.gpa, rdpsnd.aac_max_access_unit);
                const au = e.encode(pcm[k * self.unit * ch ..][0 .. self.unit * ch], buf) catch return error.UnsupportedFormat;
                self.out.shrinkRetainingCapacity(at + au.len);
            },
        }
        const rest = self.pcm.items.len - n;
        std.mem.copyForwards(i16, self.pcm.items[0..rest], self.pcm.items[n..]);
        self.pcm.shrinkRetainingCapacity(rest);
        return self.out.items;
    }
};

pub const Stats = struct {
    waves: u64 = 0,
    /// Blocks that produced no wave (AAC look-ahead): numbered all the same.
    skipped: u64 = 0,
    closes: u64 = 0,
    /// Streams started (first wave after start or a Close), and the cBlockNo the last one started with.
    streams: u64 = 0,
    stream_block: u8 = 0,
    /// Dynamic mode's format changes.
    switches: u64 = 0,
    /// Waves of what the codec held when a stream stopped.
    flushed: u64 = 0,
    confirms: u64 = 0,
};

pub const Playback = struct {
    gpa: Allocator,
    srv: rdpsnd.Server,
    engine: Engine,
    queue: PcmQueue,
    enc: ?WaveEncoder = null,
    block: std.ArrayList(i16) = .empty,
    /// A stream plays to the captured sink: every block is sent, silence included.
    active: bool = false,
    /// The channel takes a wave now; while false, blocks wait in the queue.
    writable: bool = true,
    /// When Windows' audio I/O thread would last have woken: a client message, a block queued, a stop.
    wake_ms: u64 = 0,
    /// The negotiated state was seen (queue sized for the block).
    configured: bool = false,
    /// A channel write failed: the stream is over for good.
    failed: bool = false,
    /// Capture time just past the last block sent (the flush waves').
    end_ts_ms: u64 = 0,
    stats: Stats = .{},

    pub fn init(gpa: Allocator, cfg: rdpsnd.Config) Error!Playback {
        var engine = try Engine.init(gpa);
        errdefer engine.deinit();
        // Until the block size is known: Dynamic mode's.
        const queue = try PcmQueue.init(gpa, queue_blocks * rdpsnd.dynamic_block_frames);
        return .{ .gpa = gpa, .srv = rdpsnd.Server.init(gpa, cfg), .engine = engine, .queue = queue };
    }

    pub fn deinit(self: *Playback) void {
        if (self.enc) |*e| e.deinit();
        self.block.deinit(self.gpa);
        self.queue.deinit();
        self.engine.deinit();
        self.srv.deinit();
        self.* = undefined;
    }

    /// The channel is open: Server Audio Formats and Version.
    pub fn start(self: *Playback, now_ms: u64, out: *rdpsnd.Outbox) rdpsnd.Error!void {
        try self.srv.start(now_ms, out);
        self.wake_ms = now_ms;
    }

    pub fn handle(self: *Playback, msg: []const u8, now_ms: u64, out: *rdpsnd.Outbox) (rdpsnd.Error || Error)!rdpsnd.Event {
        self.wake_ms = now_ms;
        const ev = try self.srv.handle(msg, now_ms, out);
        if (ev == .wave_confirmed) self.stats.confirms += 1;
        try self.afterServer(now_ms, out);
        return ev;
    }

    /// The negotiation's timers and the idle Close; returns when to be called next.
    pub fn tick(self: *Playback, now_ms: u64, out: *rdpsnd.Outbox) (rdpsnd.Error || Error)!?u64 {
        _ = try self.srv.tick(now_ms, out);
        try self.afterServer(now_ms, out);
        if (self.srv.st == .ready and self.srv.isStreaming() and now_ms >= self.wake_ms +| idle_close_ms) {
            // A wait that timed out while streaming.
            self.srv.expireUnconfirmed(now_ms);
            if (self.srv.allConfirmed() and self.queue.len() < self.srv.blockFrames()) {
                try self.srv.close(out);
                if (self.enc) |*e| e.deinit();
                self.enc = null;
                self.queue.clear();
                self.stats.closes += 1;
                log.debug("audio: Close after {d} ms without data ({d} waves so far)", .{ idle_close_ms, self.stats.waves });
            }
            self.wake_ms = now_ms;
        }
        return self.deadline();
    }

    pub fn deadline(self: *const Playback) ?u64 {
        var next: ?u64 = self.srv.deadline;
        if (self.srv.st == .ready and self.srv.isStreaming()) {
            const at = self.wake_ms +| idle_close_ms;
            next = if (next) |n| @min(n, at) else at;
        }
        return next;
    }

    fn afterServer(self: *Playback, now_ms: u64, out: *rdpsnd.Outbox) (rdpsnd.Error || Error)!void {
        if (self.srv.st != .ready) return;
        if (!self.configured) {
            self.configured = true;
            try self.queue.setCapacity(queue_blocks * self.srv.blockFrames());
        }
        try self.pump(now_ms, out);
    }

    /// Stopping sends the partial block.
    pub fn setActive(self: *Playback, on: bool, now_ms: u64, out: *rdpsnd.Outbox) (rdpsnd.Error || Error)!void {
        if (on == self.active) return;
        self.active = on;
        if (on) {
            try self.engine.reset();
        } else {
            self.wake_ms = now_ms;
            try self.pump(now_ms, out);
        }
    }

    /// Captured 48 kHz stereo frames, queued while active and sent as blocks fill.
    pub fn feed(self: *Playback, pcm48: []const i16, ts_ms: u64, now_ms: u64, out: *rdpsnd.Outbox) (rdpsnd.Error || Error)!void {
        if (!self.active) return;
        try self.engine.feed(pcm48, ts_ms, &self.queue);
        if (self.queue.len() >= self.srv.blockFrames()) self.wake_ms = now_ms;
        try self.pump(now_ms, out);
    }

    /// The session loop's audio step after Bridge.process(): while a stream plays every chunk is
    /// queued and sent as blocks fill; otherwise the partial block goes and only the lead-in is kept.
    pub fn pumpBridge(self: *Playback, br: *bridge.Bridge, now_ms: u64, out: *rdpsnd.Outbox) (rdpsnd.Error || Error)!void {
        const playing = br.sinkPlaying();
        if (playing and !self.active) try self.setActive(true, now_ms, out);
        if (self.active) {
            var chunk: bridge.Chunk = undefined;
            while (br.readChunk(&chunk)) try self.feed(&chunk.pcm, chunk.ts_ms, now_ms, out);
        }
        if (!playing and self.active) try self.setActive(false, now_ms, out);
        if (!self.active) _ = br.skipCapture(lead_in_ms);
    }

    /// Sends every whole block, and the partial one once the stream stopped, while the channel takes it.
    pub fn pump(self: *Playback, now_ms: u64, out: *rdpsnd.Outbox) (rdpsnd.Error || Error)!void {
        if (self.srv.st != .ready or self.failed) return;
        while (self.writable) {
            const bf: usize = self.srv.blockFrames();
            const avail = self.queue.len();
            const n = if (avail >= bf) bf else if (!self.active and avail > 0) avail else break;
            try self.block.resize(self.gpa, n * engine_channels);
            const t = self.queue.take(self.block.items);
            try self.sendBlock(self.block.items[0 .. t.frames * engine_channels], t.ts_ms, now_ms, out);
            if (self.failed) return;
            self.end_ts_ms = t.ts_ms + @as(u64, t.frames) * 1000 / engine_rate;
        }
        // The stream stopped and its last block went: flush the codec.
        if (!self.active and self.writable and self.queue.len() == 0) {
            const e = if (self.enc) |*e| e else return;
            while (try e.flushNext()) |data| {
                if (data.len == 0) continue;
                _ = self.srv.sendSample(data, now_ms, @truncate(self.end_ts_ms), out) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    else => {
                        log.warn("audio: a wave of {d} bytes cannot be sent ({t}): audio stops", .{ data.len, err });
                        self.failed = true;
                        return;
                    },
                };
                self.stats.waves += 1;
                self.stats.flushed += 1;
            }
        }
    }

    fn sendBlock(self: *Playback, pcm: []const i16, ts_ms: u64, now_ms: u64, out: *rdpsnd.Outbox) (rdpsnd.Error || Error)!void {
        if (try self.srv.checkResample(now_ms, out)) {
            self.stats.switches += 1;
            if (self.enc) |*e| e.deinit();
            self.enc = null;
        }
        const format_no = (try self.srv.currentFormat()) orelse return;
        if (self.enc == null or self.enc.?.format_no != format_no) {
            if (self.enc) |*e| e.deinit();
            self.enc = null;
            const f = (try self.srv.clientFormats())[format_no];
            self.enc = WaveEncoder.init(self.gpa, f, format_no) catch |e| switch (e) {
                error.OutOfMemory => return e,
                error.UnsupportedFormat => {
                    log.warn("audio: cannot encode format {d} (0x{x:0>4}, {d} Hz, {d} ch)", .{ format_no, f.tag, f.samples_per_sec, f.channels });
                    self.failed = true;
                    return;
                },
            };
        }
        const was_streaming = self.srv.isStreaming();
        const data = try self.enc.?.encode(pcm);
        if (data.len == 0) {
            // The AAC encoder's look-ahead: the block is numbered all the same.
            if (self.srv.isAac()) {
                if (!was_streaming) self.streamStarts();
                self.srv.skipBlock();
                self.stats.skipped += 1;
            }
            return;
        }
        if (!was_streaming) self.streamStarts();
        _ = self.srv.sendSample(data, now_ms, @truncate(ts_ms), out) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => {
                log.warn("audio: a wave of {d} bytes cannot be sent ({t}): audio stops", .{ data.len, e });
                self.failed = true;
                return;
            },
        };
        self.stats.waves += 1;
    }

    fn streamStarts(self: *Playback) void {
        self.stats.streams += 1;
        self.stats.stream_block = self.srv.next_block;
    }
};

test "PcmQueue: drops the oldest past capacity, keeps the capture time of the head" {
    const gpa = std.testing.allocator;
    var q = try PcmQueue.init(gpa, 8);
    defer q.deinit();
    var a: [10]i16 = @splat(1);
    try q.write(&a, 1000); // 5 frames at t = 1000
    var b: [10]i16 = @splat(2);
    try q.write(&b, 2000); // 5 more: 2 of the first dropped
    try std.testing.expectEqual(@as(usize, 8), q.len());
    try std.testing.expectEqual(@as(u64, 2), q.dropped);
    var out: [6]i16 = undefined;
    const t = q.take(&out);
    try std.testing.expectEqual(@as(usize, 3), t.frames);
    try std.testing.expectEqual(@as(u64, 1000 + 2 * 1000 / engine_rate), t.ts_ms);
    try std.testing.expectEqual(@as(u64, 2000), q.headTime());
}
