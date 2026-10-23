//! Session audio: desktop playback captured for the client (MS-RDPEA) and the client's
//! microphone as a desktop source (MS-RDPEAI), through a Backend that reports via Exchange.
//! Audio is sent exactly while a stream plays to the captured sink, as Windows does.

const std = @import("std");
const xch = @import("exchange.zig");
const mic_mod = @import("mic.zig");
const jitter = @import("jitter.zig");
const rdpsnd = @import("../channel/rdpsnd.zig");

const Allocator = std.mem.Allocator;
const Exchange = xch.Exchange;
const MicFormat = mic_mod.MicFormat;
const MicDecoder = mic_mod.MicDecoder;
const AudioFormat = rdpsnd.AudioFormat;

const log = std.log.scoped(.audio);

pub const Error = error{
    Unavailable,
    StreamFailed,
    UnsupportedFormat,
    InvalidData,
    /// pushMic without startMic.
    NotStarted,
    /// No eventfd.
    SystemResources,
    OutOfMemory,
};

pub const DeskMute = enum {
    /// Mute every sink (later ones too), recording those that were not muted.
    mute,
    /// Unmute exactly the recorded sinks; forget the record.
    restore,
    /// Leave the sinks muted and the record in place for the connection taking over.
    hand_over,
};

/// The audio system, as the Bridge drives it: calls come from the session thread;
/// the backend reports from any thread through the attached Exchange.
pub const Backend = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const StartError = error{ Unavailable, StreamFailed, OutOfMemory };

    pub const VTable = struct {
        attach: *const fn (ctx: *anyopaque, ex: *Exchange) void,
        /// Stop every stream; returns once no callback can touch the Exchange.
        detach: *const fn (ctx: *anyopaque) void,
        /// Capture the monitor of sink `target` (null: default) as 48 kHz S16LE stereo into
        /// Exchange.captured, reporting Exchange.setPlaying; replaces a running capture.
        startCapture: *const fn (ctx: *anyopaque, target: ?[]const u8) StartError!void,
        stopCapture: *const fn (ctx: *anyopaque) void,
        /// Create the virtual microphone (an Audio/Source node), fed from Exchange.micPull.
        startMic: *const fn (ctx: *anyopaque, format: MicFormat) StartError!void,
        stopMic: *const fn (ctx: *anyopaque) void,
        /// Only .mute can fail.
        deskMute: *const fn (ctx: *anyopaque, action: DeskMute) StartError!void,
    };

    pub fn attach(b: Backend, ex: *Exchange) void {
        b.vtable.attach(b.ctx, ex);
    }
    pub fn detach(b: Backend) void {
        b.vtable.detach(b.ctx);
    }
    pub fn startCapture(b: Backend, target: ?[]const u8) StartError!void {
        return b.vtable.startCapture(b.ctx, target);
    }
    pub fn stopCapture(b: Backend) void {
        b.vtable.stopCapture(b.ctx);
    }
    pub fn startMic(b: Backend, format: MicFormat) StartError!void {
        return b.vtable.startMic(b.ctx, format);
    }
    pub fn stopMic(b: Backend) void {
        b.vtable.stopMic(b.ctx);
    }
    pub fn deskMute(b: Backend, action: DeskMute) StartError!void {
        return b.vtable.deskMute(b.ctx, action);
    }
};

pub const Config = struct {
    /// Capture latency bound; older audio is dropped (rounded up to whole chunks).
    capture_max_ms: u32 = 200,
    mic: MicFormat = .{},
    /// Playing starts with at least this much buffered (more with pushMicAt, as the link needs).
    mic_prebuffer_ms: u32 = 40,
    /// Microphone latency bound: mic_max_ms - mic_prebuffer_ms above the jitter buffer.
    mic_max_ms: u32 = 200,
    /// Jitter buffer cap (pushMicAt): lateness spread over mic_jitter_window_ms plus
    /// mic_jitter_margin_ms, never below mic_prebuffer_ms.
    mic_max_target_ms: u32 = 300,
    mic_jitter_window_ms: u32 = 15_000,
    mic_jitter_margin_ms: u32 = 25,
    /// Quiet audio is skipped while more than this above the jitter buffer.
    mic_trim_slack_ms: u32 = 20,
    /// Fade at the edges of a microphone underrun.
    mic_fade_ms: u32 = 2,
    retry_ms: u32 = 2000,
};

pub const StreamState = enum {
    off,
    running,
    /// Wanted, not running: the backend failed; retried every retry_ms.
    retrying,
};

/// 20 ms of captured audio: 48 kHz S16 stereo interleaved.
pub const Chunk = struct {
    pcm: [xch.chunk_samples]i16,
    /// When its first frame was captured (monotonic ms).
    ts_ms: u64,
};

pub const Bridge = struct {
    gpa: Allocator,
    backend: Backend,
    cfg: Config,
    ex: *Exchange,

    capture: StreamState = .off,
    capture_retry_at: u64 = 0,
    /// null: the audio system's default at the time.
    capture_target: ?[]u8 = null,
    default_sink: ?[]u8 = null,
    sink_gen: u64 = 0,
    playing: bool = false,

    mic: StreamState = .off,
    mic_retry_at: u64 = 0,
    mic_dec: ?MicDecoder = null,
    /// Lateness of the client's packets (pushMicAt).
    mic_late: ?jitter.Lateness = null,
    mic_target_ms: u32 = 0,
    mic_target_peak_ms: u32 = 0,

    desk: StreamState = .off,
    desk_retry_at: u64 = 0,

    pub fn init(gpa: Allocator, backend: Backend, cfg: Config) Error!Bridge {
        const chunks = std.math.divCeil(u32, @max(cfg.capture_max_ms, xch.chunk_ms), xch.chunk_ms) catch unreachable;
        const ex = Exchange.create(gpa, @as(usize, chunks) * xch.chunk_frames) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.SystemResources => error.SystemResources,
            error.InvalidArgument => unreachable,
        };
        backend.attach(ex);
        return .{ .gpa = gpa, .backend = backend, .cfg = cfg, .ex = ex };
    }

    /// Restores the desk (unless releaseDesk handed it over) and detaches the backend, which the caller still owns.
    pub fn deinit(self: *Bridge) void {
        self.stopMic();
        self.stopCapture();
        self.releaseDesk(false);
        self.backend.detach();
        self.ex.destroy();
        if (self.default_sink) |s| self.gpa.free(s);
        self.* = undefined;
    }

    /// Poll for POLLIN; call process() when it is readable.
    pub fn fd(self: *const Bridge) i32 {
        return self.ex.efd;
    }

    /// Milliseconds until process() has a retry due (-1: none).
    pub fn timeoutMs(self: *const Bridge, now_ms: u64) i32 {
        var t: ?u64 = null;
        if (self.capture == .retrying) t = self.capture_retry_at;
        if (self.mic == .retrying) t = if (t) |x| @min(x, self.mic_retry_at) else self.mic_retry_at;
        if (self.desk == .retrying) t = if (t) |x| @min(x, self.desk_retry_at) else self.desk_retry_at;
        const at = t orelse return -1;
        return @intCast(@min(at -| now_ms, std.math.maxInt(i32)));
    }

    /// Handles backend reports and runs due retries; cheap when idle.
    pub fn process(self: *Bridge, now_ms: u64) Allocator.Error!void {
        self.ex.drainSignal();
        var buf: [xch.max_sink_name]u8 = undefined;
        const n = self.ex.takeNotices(&buf);
        self.playing = n.playing and self.capture == .running;
        if (n.capture_failed and self.capture == .running) {
            log.warn("audio capture stopped by the audio system; retrying every {d} ms", .{self.cfg.retry_ms});
            self.backend.stopCapture();
            self.capture = .retrying;
            self.capture_retry_at = now_ms +| self.cfg.retry_ms;
        }
        if (n.mic_failed and self.mic == .running) {
            log.warn("virtual microphone stopped by the audio system; retrying every {d} ms", .{self.cfg.retry_ms});
            self.backend.stopMic();
            self.mic = .retrying;
            self.mic_retry_at = now_ms +| self.cfg.retry_ms;
        }
        if (n.desk_failed and self.desk == .running) {
            log.warn("the desk's sinks are out of reach (audio system restarted?); muting them again every {d} ms", .{self.cfg.retry_ms});
            self.desk = .retrying;
            self.desk_retry_at = now_ms +| self.cfg.retry_ms;
        }
        if (n.sink_gen != self.sink_gen) {
            self.sink_gen = n.sink_gen;
            try self.defaultSinkIs(n.sink, now_ms);
        }
        if (self.capture == .retrying and now_ms >= self.capture_retry_at) try self.connectCapture(now_ms);
        if (self.mic == .retrying and now_ms >= self.mic_retry_at) self.connectMic(now_ms);
        if (self.desk == .retrying and now_ms >= self.desk_retry_at) self.applyDeskMute(now_ms);
    }

    fn defaultSinkIs(self: *Bridge, sink: ?[]const u8, now_ms: u64) Allocator.Error!void {
        const copy: ?[]u8 = if (sink) |s| try self.gpa.dupe(u8, s) else null;
        if (self.default_sink) |old| self.gpa.free(old);
        self.default_sink = copy;
        const d = sink orelse return;
        switch (self.capture) {
            .off, .retrying => return, // the next connect uses it
            .running => {},
        }
        if (self.capture_target) |t| {
            if (std.mem.eql(u8, t, d)) return;
            log.info("default sink is now {s}: capture follows", .{d});
            try self.connectCapture(now_ms);
        } else {
            // Connected before any report: the audio system linked it to the default this report names.
            self.capture_target = try self.gpa.dupe(u8, d);
        }
    }

    /// Logs a backend failure and retries every retry_ms (captureState() is .retrying).
    pub fn startCapture(self: *Bridge, now_ms: u64) Allocator.Error!void {
        if (self.capture != .off) return;
        self.ex.setCapture(true);
        try self.connectCapture(now_ms);
    }

    fn connectCapture(self: *Bridge, now_ms: u64) Allocator.Error!void {
        const target: ?[]u8 = if (self.default_sink) |d| try self.gpa.dupe(u8, d) else null;
        if (self.capture_target) |t| self.gpa.free(t);
        self.capture_target = target;
        if (self.capture == .running) self.backend.stopCapture();
        self.backend.startCapture(target) catch |e| {
            log.warn("cannot capture the desktop audio ({t}); retrying in {d} ms", .{ e, self.cfg.retry_ms });
            self.capture = .retrying;
            self.capture_retry_at = now_ms +| self.cfg.retry_ms;
            return;
        };
        self.capture = .running;
    }

    pub fn stopCapture(self: *Bridge) void {
        if (self.capture == .running) self.backend.stopCapture();
        self.capture = .off;
        self.playing = false;
        self.ex.setCapture(false);
        if (self.capture_target) |t| self.gpa.free(t);
        self.capture_target = null;
    }

    pub fn captureState(self: *const Bridge) StreamState {
        return self.capture;
    }

    /// null for the audio system's default or when not capturing.
    pub fn captureTarget(self: *const Bridge) ?[]const u8 {
        return self.capture_target;
    }

    pub fn defaultSink(self: *const Bridge) ?[]const u8 {
        return self.default_sink;
    }

    /// The next 20 ms chunk, oldest first; false when none is ready. Silence counts as audio.
    pub fn readChunk(self: *Bridge, out: *Chunk) bool {
        const ts = self.ex.readChunk(&out.pcm) orelse return false;
        out.ts_ms = ts;
        return true;
    }

    /// As of the last process().
    pub fn sinkPlaying(self: *const Bridge) bool {
        return self.playing;
    }

    /// Drop captured audio beyond the newest `keep_ms`; returns frames dropped (counted in captureStats).
    pub fn trimCapture(self: *Bridge, keep_ms: u32) usize {
        return self.ex.trimCapture(framesOf(xch.capture_rate, keep_ms));
    }

    /// Discard captured audio beyond the newest `keep_ms` while nothing plays (the monitor
    /// carries silence; the rest leads into the next sound). Not counted as dropped.
    pub fn skipCapture(self: *Bridge, keep_ms: u32) usize {
        return self.ex.skipCapture(framesOf(xch.capture_rate, keep_ms));
    }

    pub fn captureStats(self: *Bridge) Exchange.CaptureStats {
        return self.ex.captureStats();
    }

    /// Mute the desk's sinks while the session is remote; failures are retried every retry_ms.
    pub fn muteDesk(self: *Bridge, now_ms: u64) void {
        if (self.desk != .off) return;
        self.applyDeskMute(now_ms);
    }

    fn applyDeskMute(self: *Bridge, now_ms: u64) void {
        self.backend.deskMute(.mute) catch |e| {
            log.warn("cannot mute the desk's speakers ({t}); retrying in {d} ms", .{ e, self.cfg.retry_ms });
            self.desk = .retrying;
            self.desk_retry_at = now_ms +| self.cfg.retry_ms;
            return;
        };
        self.desk = .running;
    }

    /// Restore the desk's sinks, or with `hand_over` leave them muted for the next connection.
    pub fn releaseDesk(self: *Bridge, hand_over: bool) void {
        if (self.desk == .off) return;
        self.desk = .off;
        self.backend.deskMute(if (hand_over) .hand_over else .restore) catch {};
    }

    pub fn deskState(self: *const Bridge) StreamState {
        return self.desk;
    }

    /// Create the virtual microphone for audin `format`, or switch to it. UnsupportedFormat
    /// when it cannot be decoded; a backend failure is logged and retried.
    pub fn startMic(self: *Bridge, format: AudioFormat, now_ms: u64) Error!void {
        if (self.mic != .off) return self.setMicFormat(format);
        var dec = try MicDecoder.init(self.gpa, format, self.cfg.mic);
        errdefer dec.deinit();
        const rate = self.cfg.mic.rate;
        const target = framesOf(rate, self.cfg.mic_prebuffer_ms);
        const max = @max(target, framesOf(rate, self.cfg.mic_max_ms));
        const max_target = @max(target, framesOf(rate, self.cfg.mic_max_target_ms));
        const q = xch.MicQueue.initAdaptive(self.gpa, self.cfg.mic.channels, target, max, framesOf(rate, self.cfg.mic_fade_ms), max_target, framesOf(rate, @max(1, self.cfg.mic_trim_slack_ms))) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidArgument => error.UnsupportedFormat,
        };
        self.mic_late = jitter.Lateness.init(format.samples_per_sec, self.cfg.mic_jitter_window_ms, mic_pause_ms);
        self.mic_target_ms = self.cfg.mic_prebuffer_ms;
        self.mic_target_peak_ms = self.cfg.mic_prebuffer_ms;
        if (self.ex.swapMic(q)) |old| {
            var o = old;
            o.deinit(self.gpa);
        }
        self.mic_dec = dec;
        self.connectMic(now_ms);
    }

    fn connectMic(self: *Bridge, now_ms: u64) void {
        self.backend.startMic(self.cfg.mic) catch |e| {
            log.warn("cannot create the virtual microphone ({t}); retrying in {d} ms", .{ e, self.cfg.retry_ms });
            self.mic = .retrying;
            self.mic_retry_at = now_ms +| self.cfg.retry_ms;
            return;
        };
        self.mic = .running;
    }

    /// An audin Format Change.
    pub fn setMicFormat(self: *Bridge, format: AudioFormat) Error!void {
        if (self.mic == .off) return error.NotStarted;
        const dec = try MicDecoder.init(self.gpa, format, self.cfg.mic);
        if (self.mic_dec) |*old| old.deinit();
        self.mic_dec = dec;
        // Another rate: a new schedule (the jitter seen stays).
        if (self.mic_late) |*l| {
            l.rate = @max(1, format.samples_per_sec);
            l.anchor_us = null;
        }
    }

    /// One audin Data PDU. InvalidData when it does not decode (nothing queued); NotStarted before startMic.
    pub fn pushMic(self: *Bridge, data: []const u8) Error!void {
        const dec = if (self.mic_dec) |*d| d else return error.NotStarted;
        const pcm = try dec.decode(data);
        self.ex.micPush(pcm);
    }

    /// pushMic with the arrival time; the jitter buffer follows the client's packet timing.
    pub fn pushMicAt(self: *Bridge, data: []const u8, now_ms: u64) Error!void {
        const dec = if (self.mic_dec) |*d| d else return error.NotStarted;
        const pcm = try dec.decode(data);
        self.ex.micPush(pcm);
        const l = if (self.mic_late) |*l| l else return;
        l.add(now_ms *| 1000, dec.pcm.items.len / dec.format.channels);
        const want: u32 = @intCast(std.math.clamp(l.spreadMs(now_ms) + self.cfg.mic_jitter_margin_ms, self.cfg.mic_prebuffer_ms, @max(self.cfg.mic_prebuffer_ms, self.cfg.mic_max_target_ms)));
        if (want == self.mic_target_ms) return;
        if (want > self.mic_target_peak_ms + 9 or (want < self.mic_target_ms and want == self.cfg.mic_prebuffer_ms))
            log.debug("microphone jitter buffer {d} ms (packets late by up to {d} ms)", .{ want, l.spreadMs(now_ms) });
        self.mic_target_ms = want;
        self.mic_target_peak_ms = @max(self.mic_target_peak_ms, want);
        self.ex.setMicTarget(framesOf(self.cfg.mic.rate, want));
    }

    pub fn stopMic(self: *Bridge) void {
        if (self.mic == .running) self.backend.stopMic();
        self.mic = .off;
        if (self.ex.swapMic(null)) |old| {
            var o = old;
            o.deinit(self.gpa);
        }
        if (self.mic_dec) |*d| d.deinit();
        self.mic_dec = null;
        self.mic_late = null;
    }

    /// ms; pushMicAt.
    pub fn micJitterMs(self: *const Bridge, now_ms: u64) u64 {
        const l = if (self.mic_late) |*l| l else return 0;
        return l.spreadMs(now_ms);
    }

    pub fn micState(self: *const Bridge) StreamState {
        return self.mic;
    }

    pub fn micStats(self: *Bridge) ?Exchange.MicStats {
        return self.ex.micStats();
    }
};

/// Silence this long is a client pause (muted, reconnected): a new schedule, not lateness.
const mic_pause_ms = 1000;

fn framesOf(rate: u32, ms: u32) usize {
    return @max(1, @as(usize, rate) * ms / 1000);
}
