//! State shared by the audio backend's thread (captured, micPull, defaultSink,
//! streamFailed) and the session thread. One spin lock guards bounded copies that never
//! allocate; an eventfd wakes the session on a ready 20 ms chunk or a notice.

const std = @import("std");
const c = @import("c");
const Ring = @import("ring.zig").Ring;

const Allocator = std.mem.Allocator;

/// Capture format: 48 kHz, 16-bit, stereo, interleaved.
pub const capture_rate: u32 = 48000;
pub const capture_channels: u16 = 2;
pub const chunk_ms: u32 = 20;
pub const chunk_frames: usize = capture_rate / 1000 * chunk_ms;
pub const chunk_samples: usize = chunk_frames * capture_channels;

/// Longest default sink name kept (PipeWire node names are far shorter).
pub const max_sink_name = 256;

/// A failure notice's subject: capture, virtual microphone, or the desk's muted sinks.
pub const Stream = enum { capture, mic, desk };

/// Virtual microphone jitter buffer: plays once `target` frames are buffered, fades over
/// `fade` frames on underrun, bounded to `max`; adaptive mode skips quiet frames to shed latency.
pub const MicQueue = struct {
    ring: Ring,
    target: usize,
    max: usize,
    fade: usize,
    /// max - target (setTarget keeps it).
    headroom: usize,
    /// 0: not adaptive (no quiet skipping).
    trim_slack: usize = 0,
    quiet_level: u16 = 64,
    skipped: u64 = 0,
    playing: bool = false,
    fade_in: usize = 0,
    /// Frames of fade-out still to play (from `last`).
    fade_out: usize = 0,
    last: [8]i16 = @splat(0),
    underruns: u64 = 0,
    dropped: u64 = 0,
    /// Frames pushed since the last pull, and in the last push.
    unread: usize = 0,
    last_push: usize = 0,

    /// `max` >= `target` >= 1 frames; `fade` >= 1 frame; at most 8 channels.
    pub fn init(gpa: Allocator, channels: u16, target: usize, max: usize, fade: usize) (Allocator.Error || error{InvalidArgument})!MicQueue {
        if (channels == 0 or channels > 8 or target == 0 or max < target or fade == 0) return error.InvalidArgument;
        return .{ .ring = try Ring.init(gpa, channels, max), .target = target, .max = max, .fade = fade, .headroom = max - target };
    }

    /// init, with room for the target to grow to `max_target`; quiet frames are skipped above target + `trim_slack`.
    pub fn initAdaptive(gpa: Allocator, channels: u16, target: usize, max: usize, fade: usize, max_target: usize, trim_slack: usize) (Allocator.Error || error{InvalidArgument})!MicQueue {
        if (channels == 0 or channels > 8 or target == 0 or max < target or fade == 0 or max_target < target or trim_slack == 0) return error.InvalidArgument;
        const headroom = max - target;
        return .{ .ring = try Ring.init(gpa, channels, max_target + headroom), .target = target, .max = max, .fade = fade, .headroom = headroom, .trim_slack = trim_slack };
    }

    /// A new target (frames), within what the ring holds; `max` follows.
    pub fn setTarget(self: *MicQueue, frames: usize) void {
        self.target = std.math.clamp(frames, 1, self.ring.capacity - self.headroom);
        self.max = self.target + self.headroom;
    }

    pub fn deinit(self: *MicQueue, gpa: Allocator) void {
        self.ring.deinit(gpa);
    }

    /// Returns the frames dropped to keep the latency bound.
    pub fn push(self: *MicQueue, samples: []const i16) usize {
        const frames = samples.len / self.ring.channels;
        var dropped: usize = 0;
        if (self.ring.len() + frames > self.max) {
            dropped += self.ring.discard(self.ring.len() + frames -| self.target);
        }
        dropped += self.ring.write(samples);
        self.unread +|= frames;
        self.last_push = frames;
        if (self.unread > self.max) dropped += self.ring.discard(self.ring.len() -| self.target);
        self.dropped += dropped;
        return dropped;
    }

    pub fn pull(self: *MicQueue, out: []i16) void {
        // No pull while all of it arrived: a recorder (re)starts.
        const fresh = self.unread >= self.ring.len();
        self.unread = 0;
        const ch: usize = self.ring.channels;
        if (self.playing and self.trim_slack > 0 and self.ring.len() > self.target + self.trim_slack) {
            const n = self.ring.quietPrefix(self.ring.len() - self.target, self.quiet_level);
            self.skipped += self.ring.discard(n);
        }
        const n = out.len / ch;
        var i: usize = 0;
        while (i < n) {
            if (!self.playing) {
                if (self.ring.len() >= self.target) {
                    if (fresh) self.dropped += self.ring.discard(self.ring.len() -| @max(self.target, self.last_push));
                    self.playing = true;
                    self.fade_in = self.fade;
                    self.fade_out = 0;
                    continue;
                }
                while (i < n) : (i += 1) {
                    const frame = out[i * ch ..][0..ch];
                    if (self.fade_out > 0) {
                        self.fade_out -= 1;
                        for (frame, self.last[0..ch]) |*s, l| s.* = scale(l, self.fade_out, self.fade);
                    } else {
                        @memset(frame, 0);
                    }
                }
                break;
            }
            const got = self.ring.read(out[i * ch .. n * ch]);
            var f = i;
            while (f < i + got and self.fade_in > 0) : (f += 1) {
                const k = self.fade - self.fade_in + 1;
                for (out[f * ch ..][0..ch]) |*s| s.* = scale(s.*, k, self.fade);
                self.fade_in -= 1;
            }
            i += got;
            if (got > 0) @memcpy(self.last[0..ch], out[(i - 1) * ch ..][0..ch]);
            if (i < n) {
                self.playing = false;
                self.underruns += 1;
                self.fade_out = self.fade;
            }
        }
    }

    fn scale(s: i16, num: usize, den: usize) i16 {
        return @intCast(@divTrunc(@as(i64, s) * @as(i64, @intCast(num)), @as(i64, @intCast(den))));
    }
};

pub const Notices = struct {
    /// An application's playback stream is linked to the captured sink and running.
    playing: bool,
    /// Bumped on every default sink report.
    sink_gen: u64,
    /// Last reported default sink (null: none), copied into the caller's buffer.
    sink: ?[]const u8,
    capture_failed: bool,
    mic_failed: bool,
    desk_failed: bool,
};

pub const Exchange = struct {
    gpa: Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    /// eventfd (EFD_NONBLOCK): readable when there is something to do.
    efd: c_int,

    // Capture (latency bound: the ring's capacity).
    cap: Ring,
    cap_on: bool = false,
    /// Monotonic ms at which frame cap.wpos - 1 was captured.
    cap_end_ms: u64 = 0,
    cap_dropped: u64 = 0,
    playing: bool = false,

    mic: ?MicQueue = null,

    sink_gen: u64 = 0,
    sink_buf: [max_sink_name]u8 = undefined,
    sink_len: ?usize = null,
    capture_failed: bool = false,
    mic_failed: bool = false,
    desk_failed: bool = false,

    /// `capture_max_frames`: capture latency bound; older frames are dropped.
    pub fn create(gpa: Allocator, capture_max_frames: usize) (Allocator.Error || error{ SystemResources, InvalidArgument })!*Exchange {
        const self = try gpa.create(Exchange);
        errdefer gpa.destroy(self);
        var cap = try Ring.init(gpa, capture_channels, capture_max_frames);
        errdefer cap.deinit(gpa);
        const efd = c.eventfd(0, c.EFD_CLOEXEC | c.EFD_NONBLOCK);
        if (efd < 0) return error.SystemResources;
        self.* = .{ .gpa = gpa, .efd = efd, .cap = cap };
        return self;
    }

    /// Only once no backend can call in any more (Backend.detach).
    pub fn destroy(self: *Exchange) void {
        const gpa = self.gpa;
        if (self.mic) |*m| m.deinit(gpa);
        self.cap.deinit(gpa);
        _ = c.close(self.efd);
        gpa.destroy(self);
    }

    fn lock(self: *Exchange) void {
        while (!self.mutex.tryLock()) std.Thread.yield() catch {};
    }

    fn unlock(self: *Exchange) void {
        self.mutex.unlock();
    }

    fn signal(self: *Exchange) void {
        const one: u64 = 1;
        _ = c.write(self.efd, &one, @sizeOf(u64));
    }

    // Backend side (any thread).

    /// S16LE stereo at 48 kHz, last frame captured at `now_ms`; ignored while capture is off.
    pub fn captured(self: *Exchange, pcm: []const u8, now_ms: u64) void {
        self.lock();
        if (!self.cap_on) {
            self.unlock();
            return;
        }
        self.cap_dropped += self.cap.writeBytes(pcm);
        self.cap_end_ms = now_ms;
        const ready = self.cap.len() >= chunk_frames;
        self.unlock();
        if (ready) self.signal();
    }

    /// Fills `out` with mic-format S16LE frames; silence when the mic is off or starved.
    pub fn micPull(self: *Exchange, out: []u8) void {
        var tmp: [512]i16 = undefined;
        var at: usize = 0;
        self.lock();
        defer self.unlock();
        const q = if (self.mic) |*m| m else {
            @memset(out, 0);
            return;
        };
        const ch: usize = q.ring.channels;
        const step = tmp.len / ch * ch;
        const total = out.len / (2 * ch) * ch;
        while (at < total) {
            const n = @min(step, total - at);
            q.pull(tmp[0..n]);
            for (tmp[0..n], 0..) |s, k| std.mem.writeInt(i16, out[2 * (at + k) ..][0..2], s, .little);
            at += n;
        }
        @memset(out[2 * total ..], 0);
    }

    /// null: there is none.
    pub fn defaultSink(self: *Exchange, name: ?[]const u8) void {
        self.lock();
        if (name) |n| {
            const len = @min(n.len, max_sink_name);
            @memcpy(self.sink_buf[0..len], n[0..len]);
            self.sink_len = len;
        } else {
            self.sink_len = null;
        }
        self.sink_gen += 1;
        self.unlock();
        self.signal();
    }

    /// A playback stream is linked to the captured sink and running (when Windows runs its RDP endpoint).
    pub fn setPlaying(self: *Exchange, on: bool) void {
        self.lock();
        const changed = self.playing != on;
        self.playing = on;
        self.unlock();
        if (changed) self.signal();
    }

    /// Error state, or the audio system went away.
    pub fn streamFailed(self: *Exchange, which: Stream) void {
        self.lock();
        switch (which) {
            .capture => self.capture_failed = true,
            .mic => self.mic_failed = true,
            .desk => self.desk_failed = true,
        }
        self.unlock();
        self.signal();
    }

    // Session side.

    pub fn drainSignal(self: *Exchange) void {
        var v: u64 = 0;
        _ = c.read(self.efd, &v, @sizeOf(u64));
    }

    /// Take the pending notices, clearing failures; the sink name goes into `buf`.
    pub fn takeNotices(self: *Exchange, buf: *[max_sink_name]u8) Notices {
        self.lock();
        defer self.unlock();
        const n: Notices = .{
            .playing = self.playing,
            .sink_gen = self.sink_gen,
            .sink = if (self.sink_len) |len| blk: {
                @memcpy(buf[0..len], self.sink_buf[0..len]);
                break :blk buf[0..len];
            } else null,
            .capture_failed = self.capture_failed,
            .mic_failed = self.mic_failed,
            .desk_failed = self.desk_failed,
        };
        self.capture_failed = false;
        self.mic_failed = false;
        self.desk_failed = false;
        return n;
    }

    /// Accept capture data (from an empty ring) or not.
    pub fn setCapture(self: *Exchange, on: bool) void {
        self.lock();
        defer self.unlock();
        self.cap_on = on;
        self.cap.clear();
    }

    /// Oldest whole chunk into `out`; returns its first frame's capture time (ms), null when under a chunk.
    pub fn readChunk(self: *Exchange, out: *[chunk_samples]i16) ?u64 {
        self.lock();
        defer self.unlock();
        if (self.cap.len() < chunk_frames) return null;
        const behind = self.cap.wpos - self.cap.rpos;
        const ts = self.cap_end_ms -| (behind * 1000 / capture_rate);
        _ = self.cap.read(out);
        return ts;
    }

    /// Drop capture beyond the newest `keep_frames` (counted as dropped); returns the count.
    pub fn trimCapture(self: *Exchange, keep_frames: usize) usize {
        self.lock();
        defer self.unlock();
        const n = self.cap.discard(self.cap.len() -| keep_frames);
        self.cap_dropped += n;
        return n;
    }

    /// Discard capture beyond the newest `keep_frames` while nothing plays (not counted as dropped).
    pub fn skipCapture(self: *Exchange, keep_frames: usize) usize {
        self.lock();
        defer self.unlock();
        return self.cap.discard(self.cap.len() -| keep_frames);
    }

    pub const CaptureStats = struct { buffered_frames: usize, dropped_frames: u64 };

    pub fn captureStats(self: *Exchange) CaptureStats {
        self.lock();
        defer self.unlock();
        return .{ .buffered_frames = self.cap.len(), .dropped_frames = self.cap_dropped };
    }

    /// Returns the previous queue for the caller to free outside the lock.
    pub fn swapMic(self: *Exchange, q: ?MicQueue) ?MicQueue {
        self.lock();
        defer self.unlock();
        const old = self.mic;
        self.mic = q;
        return old;
    }

    /// Queue microphone frames (dropped when there is no queue).
    pub fn micPush(self: *Exchange, samples: []const i16) void {
        self.lock();
        defer self.unlock();
        if (self.mic) |*m| _ = m.push(samples);
    }

    pub fn setMicTarget(self: *Exchange, frames: usize) void {
        self.lock();
        defer self.unlock();
        if (self.mic) |*m| m.setTarget(frames);
    }

    pub const MicStats = struct { buffered_frames: usize, underruns: u64, dropped_frames: u64, playing: bool, target_frames: usize, skipped_frames: u64 = 0 };

    pub fn micStats(self: *Exchange) ?MicStats {
        self.lock();
        defer self.unlock();
        const m = if (self.mic) |*m| m else return null;
        return .{ .buffered_frames = m.ring.len(), .underruns = m.underruns, .dropped_frames = m.dropped, .playing = m.playing, .target_frames = m.target, .skipped_frames = m.skipped };
    }
};

test "mic queue: prebuffers, fades out on underrun, then silence" {
    const gpa = std.testing.allocator;
    var q = try MicQueue.init(gpa, 1, 4, 16, 2);
    defer q.deinit(gpa);
    var out: [8]i16 = undefined;
    _ = q.push(&.{ 100, 100, 100 });
    q.pull(&out); // 3 < target: silence
    try std.testing.expectEqualSlices(i16, &.{ 0, 0, 0, 0, 0, 0, 0, 0 }, &out);
    _ = q.push(&.{100});
    q.pull(&out); // fade-in over 2 frames, 2 more, fade-out over 2, zeros
    try std.testing.expectEqualSlices(i16, &.{ 50, 100, 100, 100, 50, 0, 0, 0 }, &out);
    try std.testing.expectEqual(@as(u64, 1), q.underruns);
}

test "mic queue: a recorder starting on unread audio gets the newest frames" {
    const gpa = std.testing.allocator;
    var q = try MicQueue.init(gpa, 1, 2, 8, 1);
    defer q.deinit(gpa);
    for ([_]i16{ 1, 2, 3, 4, 5 }) |v| _ = q.push(&.{v});
    var out: [2]i16 = undefined;
    q.pull(&out);
    try std.testing.expectEqualSlices(i16, &.{ 4, 5 }, &out);
    try std.testing.expectEqual(@as(u64, 3), q.dropped);
    // A packet larger than the prebuffer is kept whole.
    var q2 = try MicQueue.init(gpa, 1, 2, 8, 1);
    defer q2.deinit(gpa);
    _ = q2.push(&.{ 1, 2 });
    _ = q2.push(&.{ 3, 4, 5 });
    var out3: [3]i16 = undefined;
    q2.pull(&out3);
    try std.testing.expectEqualSlices(i16, &.{ 3, 4, 5 }, &out3);
    // A recorder that was pulling (silence while buffering) loses nothing.
    var q3 = try MicQueue.init(gpa, 1, 2, 8, 1);
    defer q3.deinit(gpa);
    _ = q3.push(&.{1});
    var one: [1]i16 = undefined;
    q3.pull(&one);
    _ = q3.push(&.{ 2, 3 });
    q3.pull(&out3);
    try std.testing.expectEqualSlices(i16, &.{ 1, 2, 3 }, &out3);
}

test "mic queue: past max, the oldest frames go down to target" {
    const gpa = std.testing.allocator;
    var q = try MicQueue.init(gpa, 1, 2, 4, 1);
    defer q.deinit(gpa);
    _ = q.push(&.{ 1, 2, 3 });
    try std.testing.expectEqual(@as(usize, 3), q.push(&.{ 4, 5 }));
    var out: [2]i16 = undefined;
    q.pull(&out);
    try std.testing.expectEqualSlices(i16, &.{ 4, 5 }, &out);
}
