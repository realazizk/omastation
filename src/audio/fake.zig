//! Synchronous audio backend for tests: the test plays the audio system's part
//! and checks what the Bridge asked for.

const std = @import("std");
const bridge = @import("bridge.zig");
const xch = @import("exchange.zig");
const MicFormat = @import("mic.zig").MicFormat;

const Allocator = std.mem.Allocator;
const Exchange = xch.Exchange;
const Backend = bridge.Backend;

pub const FakeBackend = struct {
    gpa: Allocator,
    ex: ?*Exchange = null,

    capture_on: bool = false,
    /// A stream plays to the captured sink (an application keeps one open by default).
    playing: bool = true,
    /// null: the default sink.
    capture_target: ?[]u8 = null,
    capture_starts: usize = 0,
    capture_stops: usize = 0,
    /// Every startCapture target, in order ("" for null).
    capture_history: std.ArrayList([]u8) = .empty,

    mic: ?MicFormat = null,
    mic_starts: usize = 0,
    mic_stops: usize = 0,

    /// The desk's sinks: muted by the bridge, and every deskMute call.
    desk_muted: bool = false,
    desk_calls: std.ArrayList(bridge.DeskMute) = .empty,

    /// The next N startCapture / startMic / deskMute(.mute) calls fail with this error.
    fail_capture: usize = 0,
    fail_mic: usize = 0,
    fail_desk: usize = 0,
    fail_with: Backend.StartError = error.Unavailable,

    pub fn init(gpa: Allocator) FakeBackend {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *FakeBackend) void {
        if (self.capture_target) |t| self.gpa.free(t);
        for (self.capture_history.items) |h| self.gpa.free(h);
        self.capture_history.deinit(self.gpa);
        self.desk_calls.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn backend(self: *FakeBackend) Backend {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable: Backend.VTable = .{
        .attach = attach,
        .detach = detach,
        .startCapture = startCapture,
        .stopCapture = stopCapture,
        .startMic = startMic,
        .stopMic = stopMic,
        .deskMute = deskMute,
    };

    fn from(ctx: *anyopaque) *FakeBackend {
        return @ptrCast(@alignCast(ctx));
    }

    fn attach(ctx: *anyopaque, ex: *Exchange) void {
        from(ctx).ex = ex;
    }

    fn detach(ctx: *anyopaque) void {
        const self = from(ctx);
        self.capture_on = false;
        self.mic = null;
        self.ex = null;
    }

    fn startCapture(ctx: *anyopaque, target: ?[]const u8) Backend.StartError!void {
        const self = from(ctx);
        try self.capture_history.ensureUnusedCapacity(self.gpa, 1);
        self.capture_history.appendAssumeCapacity(try self.gpa.dupe(u8, target orelse ""));
        if (self.fail_capture > 0) {
            self.fail_capture -= 1;
            return self.fail_with;
        }
        const copy: ?[]u8 = if (target) |t| try self.gpa.dupe(u8, t) else null;
        if (self.capture_target) |t| self.gpa.free(t);
        self.capture_target = copy;
        self.capture_on = true;
        self.capture_starts += 1;
        if (self.ex) |ex| ex.setPlaying(self.playing);
    }

    fn stopCapture(ctx: *anyopaque) void {
        const self = from(ctx);
        if (self.capture_on) self.capture_stops += 1;
        if (self.capture_on) if (self.ex) |ex| ex.setPlaying(false);
        self.capture_on = false;
        if (self.capture_target) |t| self.gpa.free(t);
        self.capture_target = null;
    }

    fn startMic(ctx: *anyopaque, format: MicFormat) Backend.StartError!void {
        const self = from(ctx);
        if (self.fail_mic > 0) {
            self.fail_mic -= 1;
            return self.fail_with;
        }
        self.mic = format;
        self.mic_starts += 1;
    }

    fn stopMic(ctx: *anyopaque) void {
        const self = from(ctx);
        if (self.mic != null) self.mic_stops += 1;
        self.mic = null;
    }

    fn deskMute(ctx: *anyopaque, action: bridge.DeskMute) Backend.StartError!void {
        const self = from(ctx);
        try self.desk_calls.append(self.gpa, action);
        switch (action) {
            .mute => {
                if (self.fail_desk > 0) {
                    self.fail_desk -= 1;
                    return self.fail_with;
                }
                self.desk_muted = true;
            },
            .restore => self.desk_muted = false,
            .hand_over => {}, // stays muted for the next connection
        }
    }

    /// The desktop plays `pcm` (48 kHz stereo); a running capture gets it, last frame at `now_ms`.
    pub fn play(self: *FakeBackend, pcm: []const i16, now_ms: u64) void {
        if (!self.capture_on) return;
        if (self.ex) |ex| ex.captured(std.mem.sliceAsBytes(pcm), now_ms);
    }

    /// Fills `out` from the virtual microphone; false (untouched) when there is none.
    pub fn record(self: *FakeBackend, out: []i16) bool {
        if (self.mic == null) return false;
        const ex = self.ex orelse return false;
        ex.micPull(std.mem.sliceAsBytes(out));
        return true;
    }

    pub fn setPlaying(self: *FakeBackend, on: bool) void {
        self.playing = on;
        if (!self.capture_on) return;
        if (self.ex) |ex| ex.setPlaying(on);
    }

    pub fn setDefaultSink(self: *FakeBackend, name: ?[]const u8) void {
        if (self.ex) |ex| ex.defaultSink(name);
    }

    /// The stream goes to the error state.
    pub fn breakStream(self: *FakeBackend, which: xch.Stream) void {
        switch (which) {
            .capture => self.capture_on = false,
            .mic => self.mic = null,
            .desk => {},
        }
        if (self.ex) |ex| ex.streamFailed(which);
    }
};
