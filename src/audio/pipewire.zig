//! The audio Backend on the desktop user's PipeWire (libpipewire-0.3), native rather than
//! libpulse so the virtual microphone is its own Audio/Source stream that dies with the
//! connection. Callbacks run on a pw_thread_loop and only copy under the Exchange lock.

const std = @import("std");
const c = @import("c");
const bridge = @import("bridge.zig");
const xch = @import("exchange.zig");
const pod = @import("pod.zig");
const MicFormat = @import("mic.zig").MicFormat;

const Allocator = std.mem.Allocator;
const Exchange = xch.Exchange;
const Backend = bridge.Backend;
const StartError = Backend.StartError;

const log = std.log.scoped(.audio);

pub const Options = struct {
    /// null: $PIPEWIRE_REMOTE, else the session's default socket.
    remote: ?[:0]const u8 = null,
    /// node.latency of both streams, in frames at 48 kHz (10 ms).
    latency_frames: u32 = 480,
    /// Make the virtual microphone the configured default source while it exists, as Windows' "Remote Audio".
    mic_default: bool = true,
    /// Seconds to wait for the daemon's replies when connecting.
    timeout_s: c_int = 2,
    /// Names of the sinks muted here, one per line, for a takeover and for omastation-recover.
    /// Null: $XDG_RUNTIME_DIR/omastation/desk-muted.
    desk_state: ?[:0]const u8 = null,
};

/// Under $XDG_RUNTIME_DIR; omastation-recover reads it too.
pub const desk_state_name = "omastation/desk-muted";
/// The desk mute record, also held in-process: the state file may be unwritable, and the
/// instance that unmutes after a reconnect's grace period is not the one that muted.
const SharedRecord = struct {
    const max = 16;
    mu: std.atomic.Mutex = .unlocked,
    names: [max][256]u8 = undefined,
    lens: [max]usize = undefined,
    count: usize = 0,

    fn lock(r: *SharedRecord) void {
        while (!r.mu.tryLock()) std.Thread.yield() catch {};
    }

    fn unlock(r: *SharedRecord) void {
        r.mu.unlock();
    }

    fn set(r: *SharedRecord, names: []const []const u8) void {
        r.lock();
        defer r.unlock();
        r.count = 0;
        for (names) |n| {
            if (r.count == max or n.len > r.names[0].len) continue;
            @memcpy(r.names[r.count][0..n.len], n);
            r.lens[r.count] = n.len;
            r.count += 1;
        }
    }
};
var shared_record: SharedRecord = .{};

/// Same directory, while the microphone is the default source: the replaced
/// default.configured.audio.source JSON (empty: none), for omastation-recover.
pub const mic_state_name = "mic-default";

pub const capture_node_name = "omastation_capture";
pub const mic_node_name = "omastation_microphone";
pub const mic_description = "omastation microphone";
const key_default_sink = "default.audio.sink";
const key_configured_source = "default.configured.audio.source";
const mic_default_value = "{ \"name\": \"" ++ mic_node_name ++ "\" }";

pub const PipeWire = struct {
    gpa: Allocator,
    opts: Options,
    loop: *c.struct_pw_thread_loop,

    // The connection: null before the first start and after it broke.
    context: ?*c.struct_pw_context = null,
    core: ?*c.struct_pw_core = null,
    core_hook: c.struct_spa_hook = std.mem.zeroes(c.struct_spa_hook),
    registry: ?*c.struct_pw_registry = null,
    registry_hook: c.struct_spa_hook = std.mem.zeroes(c.struct_spa_hook),
    metadata: ?*c.struct_pw_metadata = null,
    metadata_id: u32 = 0,
    metadata_hook: c.struct_spa_hook = std.mem.zeroes(c.struct_spa_hook),
    broken: bool = false,
    sync_seq: c_int = 0,
    sync_done: bool = false,

    ex: ?*Exchange = null,

    capture: ?*c.struct_pw_stream = null,
    capture_hook: c.struct_spa_hook = std.mem.zeroes(c.struct_spa_hook),
    capture_node: ?u32 = null,
    /// Application playback streams and every link (for `playing`).
    streams: std.ArrayList(*OutStream) = .empty,
    links: std.ArrayList(Link) = .empty,
    playing: ?bool = null,
    /// The last capture callback (monotonic ms), for the late-callback log.
    capture_last_ms: u64 = 0,
    mic: ?*c.struct_pw_stream = null,
    mic_hook: c.struct_spa_hook = std.mem.zeroes(c.struct_spa_hook),
    mic_format: MicFormat = .{},

    /// The value of default.configured.audio.source (JSON), as last seen.
    configured_source: ?[]u8 = null,
    /// Its value before the microphone became the default (valid while mic_is_default).
    saved_source: ?[]u8 = null,
    mic_is_default: bool = false,

    /// The desk's sinks and sound cards (bound while connected).
    sinks: std.ArrayList(*Sink) = .empty,
    devices: std.ArrayList(*Device) = .empty,
    /// Every sink is kept muted.
    desk_muted: bool = false,
    /// node.names of the sinks omastation muted, as in the state file.
    record: std.ArrayList([]u8) = .empty,
    /// Owned.
    desk_path: [:0]u8,
    /// The default source the microphone replaced (mic_state_name, owned).
    mic_path: [:0]u8,

    /// Starts PipeWire's thread; nothing connects until a stream starts.
    pub fn create(gpa: Allocator, opts: Options) (Allocator.Error || error{Unavailable})!*PipeWire {
        const self = try gpa.create(PipeWire);
        errdefer gpa.destroy(self);
        c.pw_init(null, null);
        errdefer c.pw_deinit();
        const loop = c.pw_thread_loop_new("omastation-audio", null) orelse return error.Unavailable;
        errdefer c.pw_thread_loop_destroy(loop);
        if (c.pw_thread_loop_start(loop) < 0) return error.Unavailable;
        const path = if (opts.desk_state) |d| try gpa.dupeSentinel(u8, d, 0) else blk: {
            const rt = c.getenv("XDG_RUNTIME_DIR");
            const dir: []const u8 = if (rt != null) std.mem.span(rt) else "/tmp";
            break :blk try std.fmt.allocPrintSentinel(gpa, "{s}/" ++ desk_state_name, .{dir}, 0);
        };
        errdefer gpa.free(path);
        const dir = if (std.mem.lastIndexOfScalar(u8, path, '/')) |slash| path[0..slash] else ".";
        const mic_path = try std.fmt.allocPrintSentinel(gpa, "{s}/" ++ mic_state_name, .{dir}, 0);
        self.* = .{ .gpa = gpa, .opts = opts, .loop = loop, .desk_path = path, .mic_path = mic_path };
        return self;
    }

    /// After Bridge.deinit (which detaches).
    pub fn destroy(self: *PipeWire) void {
        c.pw_thread_loop_lock(self.loop);
        self.stopCaptureLocked();
        self.stopMicLocked();
        self.ex = null;
        self.disconnect();
        c.pw_thread_loop_unlock(self.loop);
        c.pw_thread_loop_stop(self.loop);
        c.pw_thread_loop_destroy(self.loop);
        c.pw_deinit();
        if (self.configured_source) |s| self.gpa.free(s);
        if (self.saved_source) |s| self.gpa.free(s);
        self.clearRecord();
        self.record.deinit(self.gpa);
        self.sinks.deinit(self.gpa);
        self.devices.deinit(self.gpa);
        self.streams.deinit(self.gpa);
        self.links.deinit(self.gpa);
        self.gpa.free(self.desk_path);
        self.gpa.free(self.mic_path);
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    pub fn backend(self: *PipeWire) Backend {
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

    fn from(ctx: ?*anyopaque) *PipeWire {
        return @ptrCast(@alignCast(ctx.?));
    }

    // --- Backend --------------------------------------------------------------

    fn attach(ctx: *anyopaque, ex: *Exchange) void {
        const self = from(ctx);
        c.pw_thread_loop_lock(self.loop);
        defer c.pw_thread_loop_unlock(self.loop);
        self.ex = ex;
    }

    fn detach(ctx: *anyopaque) void {
        const self = from(ctx);
        c.pw_thread_loop_lock(self.loop);
        defer c.pw_thread_loop_unlock(self.loop);
        self.stopCaptureLocked();
        self.stopMicLocked();
        self.desk_muted = false;
        self.ex = null;
    }

    fn deskMute(ctx: *anyopaque, action: bridge.DeskMute) StartError!void {
        const self = from(ctx);
        c.pw_thread_loop_lock(self.loop);
        defer c.pw_thread_loop_unlock(self.loop);
        switch (action) {
            .mute => {
                try self.connect();
                self.loadRecord();
                self.desk_muted = true;
                // After a round trip the cards' Routes and sinks' Props are in: a card without a route has none.
                if (!self.roundtrip()) return error.Unavailable;
                for (self.devices.items) |d| d.routes_known = true;
                for (self.sinks.items) |sink| {
                    if (sink.device_id == null) log.info("not muting {s}: no sound card (muting it would silence what is recorded from it)", .{sink.name});
                    self.enforce(sink);
                }
                // The mutes are set before the session goes on.
                if (!self.roundtrip()) return error.Unavailable;
            },
            .restore => {
                self.desk_muted = false;
                self.loadRecord();
                if (self.record.items.len == 0) return;
                self.connect() catch {
                    log.warn("cannot reach PipeWire to unmute the desk; omastation-recover will", .{});
                    return;
                };
                // A connection of its own; a card's sink is muted on its Route, known after a round trip.
                if (!self.roundtrip()) return;
                for (self.devices.items) |d| d.routes_known = true;
                // WirePlumber applies a card's route only after a round trip with the daemon: wait (at most
                // a second, re-sending) until every recorded sink reports unmuted.
                var still: usize = 0;
                var attempt: u32 = 0;
                while (true) : (attempt += 1) {
                    still = 0;
                    for (self.sinks.items) |sink| {
                        if (!self.recorded(sink.name)) continue;
                        if (attempt > 0 and self.sinkMuted(sink) == false) continue;
                        still += 1;
                        if (attempt % 5 != 0) continue;
                        switch (self.muteOf(sink)) {
                            .route => |rt| log.debug("unmuting {s} (card route {d}, device {d}, muted {any})", .{ sink.name, rt.r.index, rt.r.device, rt.r.mute }),
                            .props => log.debug("unmuting {s} (its props)", .{sink.name}),
                            .unknown => log.debug("unmuting {s} (how: unknown yet)", .{sink.name}),
                        }
                        self.setMute(sink, false);
                    }
                    if (attempt > 0 and still == 0) break;
                    if (attempt == 20) break;
                    for (self.devices.items) |d| _ = c.pw_device_enum_params(d.proxy, 0, c.SPA_PARAM_Route, 0, std.math.maxInt(u32), null);
                    if (!self.roundtrip()) return;
                    if (attempt > 0) self.sleepUnlocked(50);
                }
                if (still > 0) log.warn("{d} of the desk's sinks still report muted after the restore", .{still});
                self.clearRecord();
                shared_record.set(&.{});
                _ = c.unlink(self.desk_path.ptr);
            },
            .hand_over => {
                // The next connection's mute reads the record back.
                self.desk_muted = false;
                self.clearRecord();
            },
        }
    }

    fn startCapture(ctx: *anyopaque, target: ?[]const u8) StartError!void {
        const self = from(ctx);
        c.pw_thread_loop_lock(self.loop);
        defer c.pw_thread_loop_unlock(self.loop);
        self.stopCaptureLocked();
        try self.connect();
        const props = c.pw_properties_new(
            c.PW_KEY_MEDIA_TYPE,
            "Audio",
            c.PW_KEY_MEDIA_CATEGORY,
            "Capture",
            c.PW_KEY_STREAM_CAPTURE_SINK,
            "true",
            c.PW_KEY_NODE_NAME,
            capture_node_name,
            c.PW_KEY_NODE_DESCRIPTION,
            "omastation: desktop audio for the remote client",
            c.PW_KEY_APP_NAME,
            "omastation",
            @as(?*const u8, null),
        ) orelse return error.OutOfMemory;
        if (target) |t| {
            const z = self.gpa.dupeSentinel(u8, t, 0) catch {
                c.pw_properties_free(props);
                return error.OutOfMemory;
            };
            defer self.gpa.free(z);
            _ = c.pw_properties_set(props, c.PW_KEY_TARGET_OBJECT, z.ptr);
        }
        self.setLatency(props);
        // pw_stream_new takes the properties, failure included.
        const s = c.pw_stream_new(self.core, "omastation capture", props) orelse return error.StreamFailed;
        self.capture_hook = std.mem.zeroes(c.struct_spa_hook);
        c.pw_stream_add_listener(s, &self.capture_hook, &capture_events, self);
        self.capture = s;
        var buf: [pod.max_size]u8 align(8) = undefined;
        const fmt = pod.audioRawS16(&buf, xch.capture_rate, xch.capture_channels) catch unreachable;
        var params = [_][*c]const c.struct_spa_pod{@ptrCast(fmt.ptr)};
        const flags = c.PW_STREAM_FLAG_AUTOCONNECT | c.PW_STREAM_FLAG_MAP_BUFFERS;
        if (c.pw_stream_connect(s, c.PW_DIRECTION_INPUT, c.PW_ID_ANY, flags, &params, params.len) < 0) {
            self.stopCaptureLocked();
            return error.StreamFailed;
        }
    }

    fn stopCapture(ctx: *anyopaque) void {
        const self = from(ctx);
        c.pw_thread_loop_lock(self.loop);
        defer c.pw_thread_loop_unlock(self.loop);
        self.stopCaptureLocked();
    }

    fn startMic(ctx: *anyopaque, format: MicFormat) StartError!void {
        const self = from(ctx);
        c.pw_thread_loop_lock(self.loop);
        defer c.pw_thread_loop_unlock(self.loop);
        self.stopMicLocked();
        try self.connect();
        var buf: [pod.max_size]u8 align(8) = undefined;
        const fmt = pod.audioRawS16(&buf, format.rate, format.channels) catch return error.StreamFailed;
        const props = c.pw_properties_new(
            c.PW_KEY_MEDIA_TYPE,
            "Audio",
            c.PW_KEY_MEDIA_CLASS,
            "Audio/Source",
            c.PW_KEY_NODE_NAME,
            mic_node_name,
            c.PW_KEY_NODE_DESCRIPTION,
            mic_description,
            c.PW_KEY_DEVICE_ICON_NAME,
            "audio-input-microphone",
            c.PW_KEY_APP_NAME,
            "omastation",
            @as(?*const u8, null),
        ) orelse return error.OutOfMemory;
        self.setLatency(props);
        const s = c.pw_stream_new(self.core, mic_description, props) orelse return error.StreamFailed;
        self.mic_hook = std.mem.zeroes(c.struct_spa_hook);
        c.pw_stream_add_listener(s, &self.mic_hook, &mic_events, self);
        self.mic = s;
        self.mic_format = format;
        var params = [_][*c]const c.struct_spa_pod{@ptrCast(fmt.ptr)};
        const flags = c.PW_STREAM_FLAG_AUTOCONNECT | c.PW_STREAM_FLAG_MAP_BUFFERS;
        if (c.pw_stream_connect(s, c.PW_DIRECTION_OUTPUT, c.PW_ID_ANY, flags, &params, params.len) < 0) {
            self.stopMicLocked();
            return error.StreamFailed;
        }
        if (self.opts.mic_default) self.makeMicDefault();
    }

    fn stopMic(ctx: *anyopaque) void {
        const self = from(ctx);
        c.pw_thread_loop_lock(self.loop);
        defer c.pw_thread_loop_unlock(self.loop);
        self.stopMicLocked();
    }

    // --- connection (thread loop locked) ---------------------------------------

    fn setLatency(self: *PipeWire, props: *c.struct_pw_properties) void {
        var b: [32]u8 = undefined;
        const s = std.fmt.bufPrintSentinel(&b, "{d}/{d}", .{ self.opts.latency_frames, xch.capture_rate }, 0) catch return;
        _ = c.pw_properties_set(props, c.PW_KEY_NODE_LATENCY, s.ptr);
    }

    /// Connects unless connected (tearing down a broken connection) and waits for the default metadata.
    fn connect(self: *PipeWire) StartError!void {
        if (self.broken) self.disconnect();
        if (self.core != null) return;
        const context = c.pw_context_new(c.pw_thread_loop_get_loop(self.loop), null, 0) orelse return error.Unavailable;
        var props: ?*c.struct_pw_properties = null;
        if (self.opts.remote) |r| {
            props = c.pw_properties_new(c.PW_KEY_REMOTE_NAME, r.ptr, @as(?*const u8, null)) orelse {
                c.pw_context_destroy(context);
                return error.OutOfMemory;
            };
        }
        const core = c.pw_context_connect(context, props, 0) orelse {
            c.pw_context_destroy(context);
            return error.Unavailable;
        };
        self.context = context;
        self.core = core;
        self.broken = false;
        self.core_hook = std.mem.zeroes(c.struct_spa_hook);
        _ = c.pw_core_add_listener(core, &self.core_hook, &core_events, self);
        const registry = c.pw_core_get_registry(core, c.PW_VERSION_REGISTRY, 0) orelse {
            self.disconnect();
            return error.Unavailable;
        };
        self.registry = registry;
        self.registry_hook = std.mem.zeroes(c.struct_spa_hook);
        _ = c.pw_registry_add_listener(registry, &self.registry_hook, &registry_events, self);
        // First round trip: the globals and the metadata bind; second: the metadata's properties.
        if (!self.roundtrip() or !self.roundtrip()) {
            self.disconnect();
            return error.Unavailable;
        }
    }

    /// Let PipeWire's thread run for `ms` (the loop is locked by the caller).
    fn sleepUnlocked(self: *PipeWire, ms: u32) void {
        c.pw_thread_loop_unlock(self.loop);
        defer c.pw_thread_loop_lock(self.loop);
        var ts: c.struct_timespec = .{ .tv_sec = 0, .tv_nsec = @as(c_long, ms) * 1_000_000 };
        _ = c.nanosleep(&ts, null);
    }

    fn roundtrip(self: *PipeWire) bool {
        const core = self.core orelse return false;
        self.sync_done = false;
        self.sync_seq = c.pw_core_sync(core, c.PW_ID_CORE, self.sync_seq);
        while (!self.sync_done) {
            if (self.broken) return false;
            if (c.pw_thread_loop_timed_wait(self.loop, self.opts.timeout_s) != 0) return false;
        }
        return true;
    }

    fn disconnect(self: *PipeWire) void {
        self.stopCaptureLocked();
        self.stopMicLocked();
        for (self.sinks.items) |sink| sink.destroy();
        self.sinks.clearRetainingCapacity();
        for (self.devices.items) |d| d.destroy();
        self.devices.clearRetainingCapacity();
        for (self.streams.items) |st| st.destroy();
        self.streams.clearRetainingCapacity();
        self.links.clearRetainingCapacity();
        if (self.metadata) |m| {
            c.spa_hook_remove(&self.metadata_hook);
            c.pw_proxy_destroy(@ptrCast(m));
            self.metadata = null;
        }
        if (self.registry) |r| {
            c.spa_hook_remove(&self.registry_hook);
            c.pw_proxy_destroy(@ptrCast(r));
            self.registry = null;
        }
        if (self.core) |core| {
            c.spa_hook_remove(&self.core_hook);
            _ = c.pw_core_disconnect(core);
            self.core = null;
        }
        if (self.context) |ctx| {
            c.pw_context_destroy(ctx);
            self.context = null;
        }
        self.broken = false;
        if (self.configured_source) |s| self.gpa.free(s);
        self.configured_source = null;
    }

    fn stopCaptureLocked(self: *PipeWire) void {
        const s = self.capture orelse return;
        c.spa_hook_remove(&self.capture_hook);
        if (!self.broken) _ = c.pw_stream_disconnect(s);
        c.pw_stream_destroy(s);
        self.capture = null;
        self.capture_node = null;
        self.playing = null;
    }

    // --- playing (thread loop locked) -------------------------------------------

    /// Whether a running application stream is linked into a captured sink; reported on change.
    fn updatePlaying(self: *PipeWire) void {
        const cap = self.capture_node orelse return;
        var on = false;
        outer: for (self.links.items) |l| {
            if (l.in_node != cap) continue;
            // l.out_node: a sink whose monitor the capture records.
            for (self.links.items) |m| {
                if (m.in_node != l.out_node) continue;
                for (self.streams.items) |st| {
                    if (st.id == m.out_node and st.running) {
                        on = true;
                        break :outer;
                    }
                }
            }
        }
        if (self.playing == on) return;
        self.playing = on;
        log.debug("a stream {s} to the captured sink", .{if (on) "plays" else "no longer plays"});
        if (self.ex) |ex| ex.setPlaying(on);
    }

    /// Bound if it is an application's playback stream.
    fn addStream(self: *PipeWire, id: u32, props: [*c]const c.struct_spa_dict) void {
        const class = c.spa_dict_lookup(props, c.PW_KEY_MEDIA_CLASS);
        if (class == null or !std.mem.eql(u8, std.mem.span(class), "Stream/Output/Audio")) return;
        const reg = self.registry orelse return;
        self.streams.ensureUnusedCapacity(self.gpa, 1) catch return;
        const st = self.gpa.create(OutStream) catch return;
        const node: *c.struct_pw_node = @ptrCast(c.pw_registry_bind(reg, id, c.PW_TYPE_INTERFACE_Node, c.PW_VERSION_NODE, 0) orelse {
            self.gpa.destroy(st);
            return;
        });
        st.* = .{ .pw = self, .id = id, .node = node };
        _ = c.pw_node_add_listener(node, &st.hook, &OutStream.events, st);
        self.streams.appendAssumeCapacity(st);
    }

    fn addLink(self: *PipeWire, id: u32, props: [*c]const c.struct_spa_dict) void {
        const out_node = dictInt(u32, props, c.PW_KEY_LINK_OUTPUT_NODE) orelse return;
        const in_node = dictInt(u32, props, c.PW_KEY_LINK_INPUT_NODE) orelse return;
        self.links.append(self.gpa, .{ .id = id, .out_node = out_node, .in_node = in_node }) catch return;
        self.updatePlaying();
    }

    /// Session thread only: a restored default source waits for the daemon so a disconnect cannot drop it.
    fn stopMicLocked(self: *PipeWire) void {
        const s = self.mic orelse return;
        if (self.mic_is_default) {
            self.restoreDefaultSource();
            _ = self.roundtrip();
        }
        c.spa_hook_remove(&self.mic_hook);
        if (!self.broken) _ = c.pw_stream_disconnect(s);
        c.pw_stream_destroy(s);
        self.mic = null;
    }

    // --- default source --------------------------------------------------------

    fn makeMicDefault(self: *PipeWire) void {
        const m = self.metadata orelse return;
        if (self.mic_is_default) return;
        // Ours already (a previous run died): restore what its record says; without one, clearing
        // lets the session manager pick its best source.
        var rec_buf: [512]u8 = undefined;
        const prev: ?[]const u8 = if (self.configured_source) |s| (if (isMicDefault(s)) self.readMicRecord(&rec_buf) else s) else null;
        const saved: ?[]u8 = if (prev) |s| (self.gpa.dupe(u8, s) catch return) else null;
        const ours = self.gpa.dupe(u8, mic_default_value) catch {
            if (saved) |s| self.gpa.free(s);
            return;
        };
        if (c.pw_metadata_set_property(m, c.PW_ID_CORE, key_configured_source, "Spa:String:JSON", mic_default_value) < 0) {
            if (saved) |s| self.gpa.free(s);
            self.gpa.free(ours);
            return;
        }
        self.saved_source = saved;
        self.mic_is_default = true;
        self.writeMicRecord(saved);
        // Set before the metadata echoes it back, so a stop before the echo still restores.
        if (self.configured_source) |s| self.gpa.free(s);
        self.configured_source = ours;
    }

    /// Unless someone changed it meanwhile.
    fn restoreDefaultSource(self: *PipeWire) void {
        self.mic_is_default = false;
        const saved = self.saved_source;
        self.saved_source = null;
        defer if (saved) |s| self.gpa.free(s);
        const m = self.metadata orelse return;
        if (self.broken) return;
        _ = c.unlink(self.mic_path.ptr);
        const ours = if (self.configured_source) |cur| isMicDefault(cur) else false;
        if (!ours) return;
        if (saved) |s| {
            const z = self.gpa.dupeSentinel(u8, s, 0) catch return;
            defer self.gpa.free(z);
            _ = c.pw_metadata_set_property(m, c.PW_ID_CORE, key_configured_source, "Spa:String:JSON", z.ptr);
        } else {
            _ = c.pw_metadata_set_property(m, c.PW_ID_CORE, key_configured_source, null, null);
        }
    }

    /// Written to a temporary file, renamed over it.
    fn writeMicRecord(self: *PipeWire, prev: ?[]const u8) void {
        var tmp: [520]u8 = undefined;
        const tmp_z = std.fmt.bufPrintSentinel(&tmp, "{s}.tmp", .{self.mic_path}, 0) catch return;
        const f = c.fopen(tmp_z.ptr, "w") orelse return log.warn("cannot write {s}: after a crash omastation-recover will not know the default source", .{self.mic_path});
        const v = prev orelse "";
        const wrote = c.fwrite(v.ptr, 1, v.len, f) == v.len;
        if (c.fclose(f) != 0 or !wrote) {
            _ = c.unlink(tmp_z.ptr);
            return log.warn("cannot write {s}: after a crash omastation-recover will not know the default source", .{self.mic_path});
        }
        _ = c.rename(tmp_z.ptr, self.mic_path.ptr);
    }

    /// What a run that died had replaced (null: no record, or none).
    fn readMicRecord(self: *PipeWire, buf: []u8) ?[]const u8 {
        const f = c.fopen(self.mic_path.ptr, "r") orelse return null;
        defer _ = c.fclose(f);
        const n = c.fread(buf.ptr, 1, buf.len, f);
        const v = std.mem.trim(u8, buf[0..n], " \r\n");
        if (v.len == 0 or n == buf.len or isMicDefault(v)) return null;
        return v;
    }

    fn isMicDefault(json: []const u8) bool {
        var buf: [64]u8 = undefined;
        const name = pod.defaultNodeName(json, &buf) orelse return false;
        return std.mem.eql(u8, name, mic_node_name);
    }

    // --- callbacks (PipeWire's thread, loop locked) -----------------------------

    const core_events: c.struct_pw_core_events = .{
        .version = c.PW_VERSION_CORE_EVENTS,
        .done = onCoreDone,
        .@"error" = onCoreError,
    };

    fn onCoreDone(data: ?*anyopaque, id: u32, seq: c_int) callconv(.c) void {
        const self = from(data);
        if (id == c.PW_ID_CORE and seq == self.sync_seq) {
            self.sync_done = true;
            c.pw_thread_loop_signal(self.loop, false);
        }
    }

    fn onCoreError(data: ?*anyopaque, id: u32, seq: c_int, res: c_int, message: [*c]const u8) callconv(.c) void {
        _ = seq;
        const self = from(data);
        if (id != c.PW_ID_CORE) return;
        log.warn("PipeWire: {s} ({d})", .{ if (message != null) std.mem.span(message) else "error", res });
        if (res == -c.EPIPE) {
            self.broken = true;
            if (self.ex) |ex| {
                if (self.capture != null) ex.streamFailed(.capture);
                if (self.mic != null) ex.streamFailed(.mic);
                if (self.desk_muted) ex.streamFailed(.desk);
            }
            c.pw_thread_loop_signal(self.loop, false);
        }
    }

    const registry_events: c.struct_pw_registry_events = .{
        .version = c.PW_VERSION_REGISTRY_EVENTS,
        .global = onGlobal,
        .global_remove = onGlobalRemove,
    };

    fn onGlobal(data: ?*anyopaque, id: u32, permissions: u32, ty: [*c]const u8, version: u32, props: [*c]const c.struct_spa_dict) callconv(.c) void {
        _ = permissions;
        _ = version;
        const self = from(data);
        if (ty == null or props == null) return;
        if (std.mem.eql(u8, std.mem.span(ty), c.PW_TYPE_INTERFACE_Node)) {
            self.addStream(id, props);
            return self.addSink(id, props);
        }
        if (std.mem.eql(u8, std.mem.span(ty), c.PW_TYPE_INTERFACE_Link)) return self.addLink(id, props);
        if (std.mem.eql(u8, std.mem.span(ty), c.PW_TYPE_INTERFACE_Device)) return self.addDevice(id, props);
        if (self.metadata != null) return;
        if (!std.mem.eql(u8, std.mem.span(ty), c.PW_TYPE_INTERFACE_Metadata)) return;
        const name = c.spa_dict_lookup(props, c.PW_KEY_METADATA_NAME);
        if (name == null or !std.mem.eql(u8, std.mem.span(name), "default")) return;
        const reg = self.registry orelse return;
        const m: *c.struct_pw_metadata = @ptrCast(c.pw_registry_bind(reg, id, ty, c.PW_VERSION_METADATA, 0) orelse return);
        self.metadata = m;
        self.metadata_id = id;
        self.metadata_hook = std.mem.zeroes(c.struct_spa_hook);
        _ = c.pw_metadata_add_listener(m, &self.metadata_hook, &metadata_events, self);
    }

    fn onGlobalRemove(data: ?*anyopaque, id: u32) callconv(.c) void {
        const self = from(data);
        for (self.links.items, 0..) |l, i| {
            if (l.id != id) continue;
            _ = self.links.swapRemove(i);
            return self.updatePlaying();
        }
        for (self.streams.items, 0..) |st, i| {
            if (st.id != id) continue;
            st.destroy();
            _ = self.streams.swapRemove(i);
            return self.updatePlaying();
        }
        for (self.sinks.items, 0..) |sink, i| {
            if (sink.id != id) continue;
            sink.destroy();
            _ = self.sinks.swapRemove(i);
            return;
        }
        for (self.devices.items, 0..) |d, i| {
            if (d.id != id) continue;
            d.destroy();
            _ = self.devices.swapRemove(i);
            return;
        }
        const m = self.metadata orelse return;
        if (id != self.metadata_id) return;
        c.spa_hook_remove(&self.metadata_hook);
        c.pw_proxy_destroy(@ptrCast(m));
        self.metadata = null;
        if (self.ex) |ex| ex.defaultSink(null);
    }

    const metadata_events: c.struct_pw_metadata_events = .{
        .version = c.PW_VERSION_METADATA_EVENTS,
        .property = onProperty,
    };

    fn onProperty(data: ?*anyopaque, subject: u32, key: [*c]const u8, ty: [*c]const u8, value: [*c]const u8) callconv(.c) c_int {
        _ = ty;
        const self = from(data);
        if (subject != c.PW_ID_CORE) return 0;
        if (key == null) {
            // Every property removed.
            self.setConfiguredSource(null);
            if (self.ex) |ex| ex.defaultSink(null);
            return 0;
        }
        const k = std.mem.span(key);
        const v: ?[]const u8 = if (value != null) std.mem.span(value) else null;
        if (std.mem.eql(u8, k, key_default_sink)) {
            var buf: [xch.max_sink_name]u8 = undefined;
            const name = if (v) |json| pod.defaultNodeName(json, &buf) else null;
            if (self.ex) |ex| ex.defaultSink(name);
        } else if (std.mem.eql(u8, k, key_configured_source)) {
            self.setConfiguredSource(v);
        }
        return 0;
    }

    fn setConfiguredSource(self: *PipeWire, v: ?[]const u8) void {
        const copy: ?[]u8 = if (v) |s| (self.gpa.dupe(u8, s) catch null) else null;
        if (self.configured_source) |s| self.gpa.free(s);
        self.configured_source = copy;
    }

    // --- the desk (thread loop locked) -------------------------------------------

    /// Bound if it is an Audio/Sink.
    fn addSink(self: *PipeWire, id: u32, props: [*c]const c.struct_spa_dict) void {
        const class = c.spa_dict_lookup(props, c.PW_KEY_MEDIA_CLASS);
        if (class == null or !std.mem.eql(u8, std.mem.span(class), "Audio/Sink")) return;
        const name_z = c.spa_dict_lookup(props, c.PW_KEY_NODE_NAME);
        if (name_z == null) return;
        const reg = self.registry orelse return;
        self.sinks.ensureUnusedCapacity(self.gpa, 1) catch return;
        const name = self.gpa.dupe(u8, std.mem.span(name_z)) catch return;
        const sink = self.gpa.create(Sink) catch {
            self.gpa.free(name);
            return;
        };
        const node: *c.struct_pw_node = @ptrCast(c.pw_registry_bind(reg, id, c.PW_TYPE_INTERFACE_Node, c.PW_VERSION_NODE, 0) orelse {
            self.gpa.free(name);
            self.gpa.destroy(sink);
            return;
        });
        sink.* = .{ .pw = self, .id = id, .name = name, .node = node, .device_id = dictInt(u32, props, "device.id"), .profile_device = dictInt(i32, props, "card.profile.device") };
        _ = c.pw_node_add_listener(node, &sink.hook, &Sink.events, sink);
        var ids = [_]u32{c.SPA_PARAM_Props};
        _ = c.pw_node_subscribe_params(node, &ids, ids.len);
        self.sinks.appendAssumeCapacity(sink);
    }

    /// A sound card (Audio/Device): bound to watch and set its Routes.
    fn addDevice(self: *PipeWire, id: u32, props: [*c]const c.struct_spa_dict) void {
        const class = c.spa_dict_lookup(props, c.PW_KEY_MEDIA_CLASS);
        if (class == null or !std.mem.eql(u8, std.mem.span(class), "Audio/Device")) return;
        const reg = self.registry orelse return;
        self.devices.ensureUnusedCapacity(self.gpa, 1) catch return;
        const d = self.gpa.create(Device) catch return;
        const proxy: *c.struct_pw_device = @ptrCast(c.pw_registry_bind(reg, id, c.PW_TYPE_INTERFACE_Device, c.PW_VERSION_DEVICE, 0) orelse {
            self.gpa.destroy(d);
            return;
        });
        d.* = .{ .pw = self, .id = id, .proxy = proxy };
        _ = c.pw_device_add_listener(proxy, &d.hook, &Device.events, d);
        var ids = [_]u32{c.SPA_PARAM_Route};
        _ = c.pw_device_subscribe_params(proxy, &ids, ids.len);
        self.devices.appendAssumeCapacity(d);
    }

    fn deviceOf(self: *PipeWire, sink: *const Sink) ?*Device {
        const did = sink.device_id orelse return null;
        for (self.devices.items) |d| if (d.id == did) return d;
        return null;
    }

    /// How a sink is muted: its card's output Route, or its own Props.
    const Mute = union(enum) { route: struct { dev: *Device, r: pod.Route }, props, unknown };

    fn muteOf(self: *PipeWire, sink: *const Sink) Mute {
        if (self.deviceOf(sink)) |d| {
            if (sink.profile_device) |pd| {
                for (d.routes.items) |r| if (r.output and r.device == pd) return .{ .route = .{ .dev = d, .r = r } };
            }
            if (!d.routes_known) return .unknown;
        }
        return .props;
    }

    /// The sink's mute as the desk hears it; null while unknown.
    fn sinkMuted(self: *PipeWire, sink: *const Sink) ?bool {
        return switch (self.muteOf(sink)) {
            .route => |rt| rt.r.mute,
            .props => sink.mute,
            .unknown => null,
        };
    }

    /// While muting: a sink that is not muted gets muted, recorded first.
    /// A muted sink not in the record was muted by the user: left alone.
    fn enforce(self: *PipeWire, sink: *Sink) void {
        if (!self.desk_muted) return;
        // No sound card: not a desk speaker (muting would silence its monitor).
        if (sink.device_id == null) return;
        const muted = self.sinkMuted(sink) orelse return;
        if (muted) return;
        const first = !self.recorded(sink.name);
        if (first) {
            const copy = self.gpa.dupe(u8, sink.name) catch return;
            self.record.append(self.gpa, copy) catch {
                self.gpa.free(copy);
                return;
            };
            self.saveRecord();
        }
        // Repeats (WirePlumber restoring the route, or before the mute echoed) log at debug.
        const level: std.log.Level = if (first) .info else .debug;
        switch (self.muteOf(sink)) {
            .route => |rt| logAt(level, "muting {s} while the session is remote (card route {d}, device {d})", .{ sink.name, rt.r.index, rt.r.device }),
            else => logAt(level, "muting {s} while the session is remote", .{sink.name}),
        }
        self.setMute(sink, true);
    }

    fn setMute(self: *PipeWire, sink: *Sink, mute: bool) void {
        var buf: [pod.max_size]u8 align(8) = undefined;
        switch (self.muteOf(sink)) {
            .route => |rt| {
                const p = pod.routeMute(&buf, rt.r.index, rt.r.device, mute);
                _ = c.pw_device_set_param(rt.dev.proxy, c.SPA_PARAM_Route, 0, @ptrCast(p.ptr));
            },
            .props, .unknown => {
                const p = pod.propsMute(&buf, mute);
                _ = c.pw_node_set_param(sink.node, c.SPA_PARAM_Props, 0, @ptrCast(p.ptr));
            },
        }
    }

    fn recorded(self: *const PipeWire, name: []const u8) bool {
        for (self.record.items) |r| if (std.mem.eql(u8, r, name)) return true;
        return false;
    }

    fn clearRecord(self: *PipeWire) void {
        for (self.record.items) |r| self.gpa.free(r);
        self.record.clearRetainingCapacity();
    }

    fn addRecorded(self: *PipeWire, name: []const u8) void {
        if (name.len == 0 or self.recorded(name)) return;
        const copy = self.gpa.dupe(u8, name) catch return;
        self.record.append(self.gpa, copy) catch self.gpa.free(copy);
    }

    /// Merges into the record what this process muted (a handed-over desk) and the state file (a crash).
    fn loadRecord(self: *PipeWire) void {
        {
            shared_record.lock();
            defer shared_record.unlock();
            for (shared_record.names[0..shared_record.count], shared_record.lens[0..shared_record.count]) |*n, len| self.addRecorded(n[0..len]);
        }
        const f = c.fopen(self.desk_path.ptr, "r") orelse return;
        defer _ = c.fclose(f);
        var line: [512]u8 = undefined;
        while (c.fgets(&line, line.len, f) != null) {
            self.addRecorded(std.mem.trimEnd(u8, std.mem.sliceTo(&line, 0), "\r\n"));
        }
    }

    /// This process's copy, then the state file (a temporary file renamed over it).
    fn saveRecord(self: *PipeWire) void {
        shared_record.set(self.record.items);
        if (std.mem.lastIndexOfScalar(u8, self.desk_path, '/')) |slash| {
            var dir: [512]u8 = undefined;
            if (slash < dir.len) {
                @memcpy(dir[0..slash], self.desk_path[0..slash]);
                dir[slash] = 0;
                _ = c.mkdir(@ptrCast(&dir), 0o700);
            }
        }
        var tmp: [520]u8 = undefined;
        const tmp_z = std.fmt.bufPrintSentinel(&tmp, "{s}.tmp", .{self.desk_path}, 0) catch return;
        const f = c.fopen(tmp_z.ptr, "w") orelse {
            log.warn("cannot write {s}: omastation-recover will not know the muted sinks", .{self.desk_path});
            return;
        };
        var wrote = true;
        for (self.record.items) |r| {
            if (c.fwrite(r.ptr, 1, r.len, f) != r.len or c.fwrite("\n", 1, 1, f) != 1) wrote = false;
        }
        // A full $XDG_RUNTIME_DIR: keep the previous record rather than a truncated one.
        if (c.fclose(f) != 0 or !wrote) {
            _ = c.unlink(tmp_z.ptr);
            log.warn("cannot write {s}: omastation-recover will not know the muted sinks", .{self.desk_path});
            return;
        }
        _ = c.rename(tmp_z.ptr, self.desk_path.ptr);
    }

    const capture_events: c.struct_pw_stream_events = .{
        .version = c.PW_VERSION_STREAM_EVENTS,
        .state_changed = onCaptureState,
        .process = onCaptureProcess,
    };

    fn onCaptureState(data: ?*anyopaque, old: c.enum_pw_stream_state, state: c.enum_pw_stream_state, err: [*c]const u8) callconv(.c) void {
        _ = old;
        const self = from(data);
        if (state == c.PW_STREAM_STATE_PAUSED or state == c.PW_STREAM_STATE_STREAMING) {
            if (self.capture) |s| {
                const id = c.pw_stream_get_node_id(s);
                if (id != c.SPA_ID_INVALID and self.capture_node != id) {
                    self.capture_node = id;
                    self.updatePlaying();
                }
            }
        }
        if (state != c.PW_STREAM_STATE_ERROR) return;
        log.warn("PipeWire capture stream: {s}", .{if (err != null) std.mem.span(err) else "error"});
        if (self.ex) |ex| ex.streamFailed(.capture);
    }

    fn onCaptureProcess(data: ?*anyopaque) callconv(.c) void {
        const self = from(data);
        const s = self.capture orelse return;
        const b = c.pw_stream_dequeue_buffer(s);
        if (b == null) return;
        defer _ = c.pw_stream_queue_buffer(s, b);
        const buf = b.*.buffer;
        if (buf == null or buf.*.n_datas < 1) return;
        const d = &buf.*.datas[0];
        if (d.data == null or d.chunk == null) return;
        const ch = d.chunk.*;
        if (ch.flags & c.SPA_CHUNK_FLAG_CORRUPTED != 0 or d.maxsize == 0) return;
        const off = ch.offset % d.maxsize;
        const size = @min(ch.size, d.maxsize - off);
        const bytes: [*]const u8 = @ptrCast(d.data.?);
        const now = monotonicMs();
        // A late callback can mean lost buffers (diagnostics).
        if (self.capture_last_ms != 0 and now - self.capture_last_ms > 60)
            log.debug("capture callback {d} ms after the last one ({d} frames)", .{ now - self.capture_last_ms, size / 4 });
        self.capture_last_ms = now;
        if (self.ex) |ex| ex.captured(bytes[off..][0..size], now);
    }

    const mic_events: c.struct_pw_stream_events = .{
        .version = c.PW_VERSION_STREAM_EVENTS,
        .state_changed = onMicState,
        .process = onMicProcess,
    };

    fn onMicState(data: ?*anyopaque, old: c.enum_pw_stream_state, state: c.enum_pw_stream_state, err: [*c]const u8) callconv(.c) void {
        _ = old;
        const self = from(data);
        if (state != c.PW_STREAM_STATE_ERROR) return;
        log.warn("PipeWire microphone stream: {s}", .{if (err != null) std.mem.span(err) else "error"});
        if (self.ex) |ex| ex.streamFailed(.mic);
    }

    fn onMicProcess(data: ?*anyopaque) callconv(.c) void {
        const self = from(data);
        const s = self.mic orelse return;
        const b = c.pw_stream_dequeue_buffer(s);
        if (b == null) return;
        defer _ = c.pw_stream_queue_buffer(s, b);
        const buf = b.*.buffer;
        if (buf == null or buf.*.n_datas < 1) return;
        const d = &buf.*.datas[0];
        if (d.data == null or d.chunk == null) return;
        const stride: u32 = 2 * @as(u32, self.mic_format.channels);
        var frames: u64 = d.maxsize / stride;
        if (b.*.requested != 0) frames = @min(frames, b.*.requested);
        const n: u32 = @intCast(frames * stride);
        const bytes: [*]u8 = @ptrCast(d.data.?);
        if (self.ex) |ex| ex.micPull(bytes[0..n]) else @memset(bytes[0..n], 0);
        d.chunk.*.offset = 0;
        d.chunk.*.stride = @intCast(stride);
        d.chunk.*.size = n;
    }
};

fn dictInt(comptime T: type, props: [*c]const c.struct_spa_dict, key: [*:0]const u8) ?T {
    const v = c.spa_dict_lookup(props, key);
    if (v == null) return null;
    return std.fmt.parseInt(T, std.mem.span(v), 10) catch null;
}

const Link = struct { id: u32, out_node: u32, in_node: u32 };

/// An application's playback stream (Stream/Output/Audio); running means it plays.
const OutStream = struct {
    pw: *PipeWire,
    id: u32,
    node: *c.struct_pw_node,
    hook: c.struct_spa_hook = std.mem.zeroes(c.struct_spa_hook),
    running: bool = false,

    const events: c.struct_pw_node_events = .{
        .version = c.PW_VERSION_NODE_EVENTS,
        .info = onInfo,
    };

    fn onInfo(data: ?*anyopaque, info: [*c]const c.struct_pw_node_info) callconv(.c) void {
        const st: *OutStream = @ptrCast(@alignCast(data.?));
        if (info == null) return;
        const running = info.*.state == c.PW_NODE_STATE_RUNNING;
        if (running == st.running) return;
        st.running = running;
        st.pw.updatePlaying();
    }

    fn destroy(st: *OutStream) void {
        c.spa_hook_remove(&st.hook);
        c.pw_proxy_destroy(@ptrCast(st.node));
        st.pw.gpa.destroy(st);
    }
};

/// A sound card: its output Routes (what its sinks are muted on).
const Device = struct {
    pw: *PipeWire,
    id: u32,
    proxy: *c.struct_pw_device,
    hook: c.struct_spa_hook = std.mem.zeroes(c.struct_spa_hook),
    routes: std.ArrayList(pod.Route) = .empty,
    /// Its Routes have been reported (or it has none).
    routes_known: bool = false,

    const events: c.struct_pw_device_events = .{
        .version = c.PW_VERSION_DEVICE_EVENTS,
        .info = onInfo,
        .param = onParam,
    };

    /// The subscription alone reports only the Routes a card had when bound; a card created
    /// later (WirePlumber restart) announces its Routes in its info.
    fn onInfo(data: ?*anyopaque, info: [*c]const c.struct_pw_device_info) callconv(.c) void {
        const d: *Device = @ptrCast(@alignCast(data.?));
        if (info == null or info.*.change_mask & c.PW_DEVICE_CHANGE_MASK_PARAMS == 0 or info.*.params == null) return;
        for (info.*.params[0..info.*.n_params]) |pi| {
            if (pi.id != c.SPA_PARAM_Route or pi.flags & c.SPA_PARAM_INFO_READ == 0) continue;
            _ = c.pw_device_enum_params(d.proxy, 0, c.SPA_PARAM_Route, 0, std.math.maxInt(u32), null);
            return;
        }
    }

    fn destroy(d: *Device) void {
        c.spa_hook_remove(&d.hook);
        c.pw_proxy_destroy(@ptrCast(d.proxy));
        const gpa = d.pw.gpa;
        d.routes.deinit(gpa);
        gpa.destroy(d);
    }

    fn onParam(data: ?*anyopaque, seq: c_int, id: u32, index: u32, next: u32, param: [*c]const c.struct_spa_pod) callconv(.c) void {
        _ = seq;
        _ = index;
        _ = next;
        const d: *Device = @ptrCast(@alignCast(data.?));
        if (id != c.SPA_PARAM_Route or param == null) return;
        const bytes: [*]const u8 = @ptrCast(param);
        const r = pod.routeOf(bytes[0 .. 8 + @as(usize, param.*.size)]) orelse return;
        d.routes_known = true;
        // One active route per profile device and direction: a new port replaces it, so no stale route is muted.
        for (d.routes.items) |*old| {
            if (old.device == r.device and old.output == r.output) {
                old.* = r;
                break;
            }
        } else d.routes.append(d.pw.gpa, r) catch return;
        for (d.pw.sinks.items) |sink| {
            if (sink.device_id == d.id) d.pw.enforce(sink);
        }
    }
};

/// A sink of the desk: its node bound to watch and set its mute (Props).
const Sink = struct {
    pw: *PipeWire,
    id: u32,
    name: []u8,
    node: *c.struct_pw_node,
    /// Its sound card and the card's profile device (from its props).
    device_id: ?u32 = null,
    profile_device: ?i32 = null,
    hook: c.struct_spa_hook = std.mem.zeroes(c.struct_spa_hook),
    /// Its mute, once its Props arrived.
    mute: ?bool = null,

    const events: c.struct_pw_node_events = .{
        .version = c.PW_VERSION_NODE_EVENTS,
        .info = onInfo,
        .param = onParam,
    };

    /// The registry's properties are a filtered subset without card.profile.device.
    fn onInfo(data: ?*anyopaque, info: [*c]const c.struct_pw_node_info) callconv(.c) void {
        const sink: *Sink = @ptrCast(@alignCast(data.?));
        if (info == null or info.*.props == null) return;
        if (dictInt(u32, info.*.props, "device.id")) |d| sink.device_id = d;
        if (dictInt(i32, info.*.props, "card.profile.device")) |d| sink.profile_device = d;
        sink.pw.enforce(sink);
    }

    fn destroy(sink: *Sink) void {
        c.spa_hook_remove(&sink.hook);
        c.pw_proxy_destroy(@ptrCast(sink.node));
        const gpa = sink.pw.gpa;
        gpa.free(sink.name);
        gpa.destroy(sink);
    }

    fn onParam(data: ?*anyopaque, seq: c_int, id: u32, index: u32, next: u32, param: [*c]const c.struct_spa_pod) callconv(.c) void {
        _ = seq;
        _ = index;
        _ = next;
        const sink: *Sink = @ptrCast(@alignCast(data.?));
        if (id != c.SPA_PARAM_Props or param == null) return;
        const bytes: [*]const u8 = @ptrCast(param);
        const mute = pod.propsMuteOf(bytes[0 .. 8 + @as(usize, param.*.size)]) orelse return;
        sink.mute = mute;
        sink.pw.enforce(sink);
    }
};

fn logAt(level: std.log.Level, comptime fmt: []const u8, args: anytype) void {
    switch (level) {
        .info => log.info(fmt, args),
        else => log.debug(fmt, args),
    }
}

fn monotonicMs() u64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(u64, @intCast(ts.tv_sec)) * 1000 + @as(u64, @intCast(ts.tv_nsec)) / 1_000_000;
}
