//! Fixed-capacity ring of interleaved S16 PCM frames. Positions are absolute
//! frame counters (u64); a write that does not fit drops the oldest frames, so
//! capacity bounds latency. Not thread-safe; Exchange guards its rings.

const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;

pub const Ring = struct {
    /// capacity * channels samples.
    buf: []i16,
    channels: u16,
    capacity: usize,
    rpos: u64 = 0,
    /// Absolute position one past the newest frame.
    wpos: u64 = 0,

    /// InvalidArgument for 0 channels or 0 frames.
    pub fn init(gpa: Allocator, channels: u16, capacity_frames: usize) (Allocator.Error || error{InvalidArgument})!Ring {
        if (channels == 0 or capacity_frames == 0) return error.InvalidArgument;
        const n = std.math.mul(usize, capacity_frames, channels) catch return error.OutOfMemory;
        const buf = try gpa.alloc(i16, n);
        @memset(buf, 0);
        return .{ .buf = buf, .channels = channels, .capacity = capacity_frames };
    }

    pub fn deinit(self: *Ring, gpa: Allocator) void {
        gpa.free(self.buf);
        self.* = undefined;
    }

    pub fn len(self: *const Ring) usize {
        return @intCast(self.wpos - self.rpos);
    }

    pub fn clear(self: *Ring) void {
        self.rpos = self.wpos;
    }

    /// Count of the oldest frames, up to `max_frames`, with every sample within +-level.
    pub fn quietPrefix(self: *const Ring, max_frames: usize, level: u16) usize {
        const n = @min(max_frames, self.len());
        const ch: usize = self.channels;
        var k: usize = 0;
        while (k < n) : (k += 1) {
            const at: usize = @intCast((self.rpos + k) % self.capacity);
            for (self.buf[at * ch ..][0..ch]) |s| if (@abs(s) > level) return k;
        }
        return n;
    }

    pub fn discard(self: *Ring, frames: usize) usize {
        const n = @min(frames, self.len());
        self.rpos += n;
        return n;
    }

    /// Appends interleaved frames, dropping the oldest when full (a trailing partial
    /// frame is ignored). Returns the number of frames dropped.
    pub fn write(self: *Ring, samples: []const i16) usize {
        return self.writeBytes(std.mem.sliceAsBytes(samples));
    }

    /// write() of little-endian S16 bytes (any alignment).
    pub fn writeBytes(self: *Ring, data: []const u8) usize {
        const frame_bytes = 2 * @as(usize, self.channels);
        var frames = data.len / frame_bytes;
        var src = data[0 .. frames * frame_bytes];
        var dropped: usize = 0;
        if (frames > self.capacity) {
            const skip = frames - self.capacity;
            dropped += self.len() + skip;
            self.wpos += skip;
            self.rpos = self.wpos;
            src = src[skip * frame_bytes ..];
            frames = self.capacity;
        } else {
            const over = (self.len() + frames) -| self.capacity;
            dropped += over;
            self.rpos += over;
        }
        var at: usize = @intCast(self.wpos % self.capacity);
        var left = frames;
        while (left > 0) {
            const n = @min(left, self.capacity - at);
            const dst = std.mem.sliceAsBytes(self.buf[at * self.channels ..][0 .. n * self.channels]);
            copyLe(dst, src[0 .. n * frame_bytes]);
            src = src[n * frame_bytes ..];
            left -= n;
            at = 0;
        }
        self.wpos += frames;
        return dropped;
    }

    /// Consumes up to out.len / channels of the oldest frames; returns frames read.
    pub fn read(self: *Ring, out: []i16) usize {
        const frames = self.peek(out);
        self.rpos += frames;
        return frames;
    }

    pub fn peek(self: *const Ring, out: []i16) usize {
        const ch: usize = self.channels;
        const frames = @min(out.len / ch, self.len());
        var at: usize = @intCast(self.rpos % self.capacity);
        var done: usize = 0;
        while (done < frames) {
            const n = @min(frames - done, self.capacity - at);
            @memcpy(out[done * ch ..][0 .. n * ch], self.buf[at * ch ..][0 .. n * ch]);
            done += n;
            at = 0;
        }
        return frames;
    }
};

fn copyLe(dst: []u8, src: []const u8) void {
    if (builtin.cpu.arch.endian() == .little) {
        @memcpy(dst, src);
    } else {
        var i: usize = 0;
        while (i + 1 < src.len) : (i += 2) {
            dst[i] = src[i + 1];
            dst[i + 1] = src[i];
        }
    }
}

test "ring: wraps, keeps order, drops the oldest on overflow" {
    const gpa = std.testing.allocator;
    var r = try Ring.init(gpa, 2, 4);
    defer r.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 0), r.write(&.{ 1, 1, 2, 2, 3, 3 }));
    var out: [8]i16 = undefined;
    try std.testing.expectEqual(@as(usize, 2), r.read(out[0..4]));
    try std.testing.expectEqualSlices(i16, &.{ 1, 1, 2, 2 }, out[0..4]);
    // 3 held; 3 more: 2 fit, the oldest (3) is dropped.
    try std.testing.expectEqual(@as(usize, 1), r.write(&.{ 4, 4, 5, 5, 6, 6, 7, 7 }));
    try std.testing.expectEqual(@as(usize, 4), r.len());
    try std.testing.expectEqual(@as(usize, 4), r.read(&out));
    try std.testing.expectEqualSlices(i16, &.{ 4, 4, 5, 5, 6, 6, 7, 7 }, &out);
    try std.testing.expectEqual(@as(u64, 7), r.wpos);
}

test "ring: a write larger than the ring keeps its newest frames" {
    const gpa = std.testing.allocator;
    var r = try Ring.init(gpa, 1, 3);
    defer r.deinit(gpa);
    _ = r.write(&.{9});
    try std.testing.expectEqual(@as(usize, 3), r.write(&.{ 1, 2, 3, 4, 5 }));
    var out: [3]i16 = undefined;
    try std.testing.expectEqual(@as(usize, 3), r.read(&out));
    try std.testing.expectEqualSlices(i16, &.{ 3, 4, 5 }, &out);
    try std.testing.expectEqual(@as(u64, 6), r.wpos);
}
