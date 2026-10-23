//! Output frame capture into shared memory with damage tracking, via ext-image-copy-capture-v1
//! (preferred) or zwlr_screencopy_manager_v1. Double-buffered: a taken frame stays valid until
//! the next takeFrame()/deinit; `Frame.damage` is relative to the previously taken frame.

const std = @import("std");
const wire = @import("wire.zig");
const sys = @import("sys.zig");
const shm = @import("shm.zig");
const client_mod = @import("client.zig");
const Client = client_mod.Client;
const Output = client_mod.Output;
const P = wire.proto;

const log = std.log.scoped(.wl);

pub const Error = wire.Error;

pub const Rect = struct {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
};

/// Fixed-capacity damage region; overflow collapses into a bounding box.
pub const Damage = struct {
    pub const capacity = 32;
    rects: [capacity]Rect = undefined,
    len: usize = 0,
    full: bool = false,
    collapsed: bool = false,

    pub fn clear(d: *Damage) void {
        d.* = .{};
    }

    pub fn setFull(d: *Damage) void {
        d.* = .{ .full = true };
    }

    /// Add `r` clipped to a `w`x`h` buffer.
    pub fn add(d: *Damage, r: Rect, w: u32, h: u32) void {
        if (d.full) return;
        const x0: i64 = @max(r.x, 0);
        const y0: i64 = @max(r.y, 0);
        const x1: i64 = @min(@as(i64, r.x) + r.width, w);
        const y1: i64 = @min(@as(i64, r.y) + r.height, h);
        if (x1 <= x0 or y1 <= y0) return;
        if (x0 == 0 and y0 == 0 and x1 == w and y1 == h) return d.setFull();
        const c: Rect = .{ .x = @intCast(x0), .y = @intCast(y0), .width = @intCast(x1 - x0), .height = @intCast(y1 - y0) };
        if (d.collapsed or d.len == capacity) {
            var bb = if (d.len > 0) d.rects[0] else c;
            if (!d.collapsed) for (d.rects[1..d.len]) |o| {
                bb = unionRect(bb, o);
            };
            d.rects[0] = unionRect(bb, c);
            d.len = 1;
            d.collapsed = true;
            return;
        }
        d.rects[d.len] = c;
        d.len += 1;
    }

    pub fn merge(d: *Damage, o: *const Damage, w: u32, h: u32) void {
        if (o.full) return d.setFull();
        for (o.rects[0..o.len]) |r| d.add(r, w, h);
    }

    pub fn isEmpty(d: *const Damage) bool {
        return !d.full and d.len == 0;
    }
};

fn unionRect(a: Rect, b: Rect) Rect {
    const x0 = @min(a.x, b.x);
    const y0 = @min(a.y, b.y);
    const x1 = @max(a.x + a.width, b.x + b.width);
    const y1 = @max(a.y + a.height, b.y + b.height);
    return .{ .x = x0, .y = y0, .width = x1 - x0, .height = y1 - y0 };
}

pub const Frame = struct {
    /// Rows `stride` bytes apart; XRGB8888/ARGB8888 are B,G,R,X/A bytes in memory.
    data: []const u8,
    width: u32,
    height: u32,
    stride: u32,
    format: P.WlShm.Format,
    /// Transform the compositor applied to the buffer contents.
    transform: P.WlOutput.Transform,
    /// Rows are bottom-up (wlr-screencopy only).
    y_invert: bool,
    /// Changed regions since the previously taken frame, buffer coordinates.
    damage: []const Rect,
    /// CLOCK_MONOTONIC presentation time in ns, 0 if unknown.
    presented_ns: u64,
    /// Request-to-ready time of this frame.
    latency_ns: u64,
    seq: u64,
};

pub const Backend = enum { auto, ext, wlr };

pub const Options = struct {
    backend: Backend = .auto,
    /// Composite the cursor into frames (RDP normally draws it client-side).
    paint_cursors: bool = false,
};

pub const State = enum {
    /// ext: waiting for the session's buffer constraints.
    negotiating,
    idle,
    capturing,
    /// Session ended by the compositor (output gone, capture revoked).
    stopped,
    /// Repeated capture failures; see `last_failure`.
    failed,
};

const Constraints = struct {
    width: u32 = 0,
    height: u32 = 0,
    formats: [16]u32 = undefined,
    nformats: usize = 0,

    fn addFormat(c: *Constraints, f: u32) void {
        if (c.nformats < c.formats.len) {
            c.formats[c.nformats] = f;
            c.nformats += 1;
        }
    }

    fn choose(c: *const Constraints) ?P.WlShm.Format {
        return chooseFormat(c.formats[0..c.nformats]);
    }
};

/// XRGB8888 (BGRX in memory, what RDP wants), then ARGB8888, then any 32-bit RGB (consumer swizzles).
fn chooseFormat(formats: []const u32) ?P.WlShm.Format {
    const prefs = [_]P.WlShm.Format{ .xrgb8888, .argb8888, .xbgr8888, .abgr8888 };
    for (prefs) |p| for (formats) |f| if (f == @backingInt(p)) return p;
    return null;
}

const Hook = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque) void,
};

pub const Capture = struct {
    client: *Client,
    output: ?*Output,
    kind: enum { ext, wlr },
    paint_cursors: bool,
    state: State,
    want_frame: bool = false,
    consecutive_failures: u32 = 0,
    last_failure: ?u32 = null,

    // ext-image-copy-capture
    owned_source: ?P.ExtImageCaptureSourceV1 = null,
    session: ?P.ExtImageCopyCaptureSessionV1 = null,
    ext_frame: ?P.ExtImageCopyCaptureFrameV1 = null,
    pending: Constraints = .{},
    constraints: ?Constraints = null,

    // wlr-screencopy
    wlr_frame: ?P.ZwlrScreencopyFrameV1 = null,
    wlr_formats: [8]u32 = undefined,
    wlr_nformats: usize = 0,
    wlr_size: [3]u32 = .{ 0, 0, 0 }, // width, height, stride

    // `retired` keeps the previous set alive while the consumer holds a frame in it after a resize.
    cur: ?*shm.BufferSet = null,
    retired: ?*shm.BufferSet = null,
    buf_damage: [2]Damage = .{ .{}, .{} },
    buf_valid: [2]bool = .{ false, false },
    front: ?u8 = null,
    front_set: ?*shm.BufferSet = null,
    target: ?u8 = null,
    ready_idx: ?u8 = null,
    ready_set: ?*shm.BufferSet = null,

    frame_damage: Damage = .{},
    frame_transform: P.WlOutput.Transform = .normal,
    frame_y_invert: bool = false,
    frame_present_ns: u64 = 0,
    request_ns: u64 = 0,

    ready_damage: Damage = .{},
    ready_meta: struct { transform: P.WlOutput.Transform, y_invert: bool, present_ns: u64, latency_ns: u64 } = undefined,
    out: Frame = undefined,
    out_rect: [1]Rect = undefined,
    out_damage: Damage = .{},
    last_taken: ?[4]u32 = null, // width, height, stride, format
    seq: u64 = 0,
    on_ready: ?Hook = null,

    /// ext needs a roundtrip for the constraints before the first frame; requestFrame() works at once.
    pub fn init(client: *Client, output: *Output, opts: Options) Error!*Capture {
        const has_ext = client.ext_capture != null and client.ext_output_source != null;
        const kind: @FieldType(Capture, "kind") = switch (opts.backend) {
            .auto => if (has_ext) .ext else if (client.screencopy != null) .wlr else return error.Unsupported,
            .ext => if (has_ext) .ext else return error.Unsupported,
            .wlr => if (client.screencopy != null) .wlr else return error.Unsupported,
        };
        if (output.removed) return error.Stopped;
        if (client.shm == null) return error.Unsupported;
        const conn = client.conn;
        const cap = try client.gpa.create(Capture);
        errdefer client.gpa.destroy(cap);
        cap.* = .{
            .client = client,
            .output = output,
            .kind = kind,
            .paint_cursors = opts.paint_cursors,
            .state = if (kind == .ext) .negotiating else .idle,
        };
        if (kind == .ext) {
            const src = try client.ext_output_source.?.createSource(conn, output.proxy);
            cap.owned_source = src;
            const opt_bits: u32 = if (opts.paint_cursors) P.ExtImageCopyCaptureManagerV1.Options.paint_cursors else 0;
            cap.session = try client.ext_capture.?.createSession(conn, src, opt_bits);
            conn.setHandler(cap.session.?.id, wire.Handler.init(Capture, cap, onSession));
        }
        try conn.flush();
        return cap;
    }

    /// Wrap an existing ext session (used for the cursor image session).
    pub fn initSession(client: *Client, session: P.ExtImageCopyCaptureSessionV1) Error!*Capture {
        if (client.shm == null) return error.Unsupported;
        const cap = try client.gpa.create(Capture);
        cap.* = .{ .client = client, .output = null, .kind = .ext, .paint_cursors = false, .state = .negotiating, .session = session };
        client.conn.setHandler(session.id, wire.Handler.init(Capture, cap, onSession));
        return cap;
    }

    pub fn deinit(cap: *Capture) void {
        const conn = cap.client.conn;
        if (cap.ext_frame) |f| f.destroy(conn) catch {};
        if (cap.wlr_frame) |f| f.destroy(conn) catch {};
        if (cap.session) |s| s.destroy(conn) catch {};
        if (cap.owned_source) |s| s.destroy(conn) catch {};
        for ([_]?*shm.BufferSet{ cap.cur, cap.retired }) |maybe| if (maybe) |set| {
            set.destroy(conn);
            cap.client.gpa.destroy(set);
        };
        conn.flush() catch {};
        cap.client.gpa.destroy(cap);
    }

    /// Completes once the content changed (at once for the first frame). No-op while one is in
    /// flight or a completed frame is not taken yet.
    pub fn requestFrame(cap: *Capture) Error!void {
        switch (cap.state) {
            .stopped => return error.Stopped,
            .failed => return error.CaptureFailed,
            else => {},
        }
        cap.want_frame = true;
        try cap.kick();
    }

    /// The completed frame, if any; it stays valid until the next call.
    pub fn takeFrame(cap: *Capture) ?*const Frame {
        const idx = cap.ready_idx orelse return null;
        const set = cap.ready_set.?;
        cap.front = idx;
        cap.front_set = set;
        cap.ready_idx = null;
        cap.ready_set = null;
        if (cap.retired) |r| if (r != set) {
            r.destroy(cap.client.conn);
            cap.client.gpa.destroy(r);
            cap.retired = null;
        };
        const shape = [4]u32{ set.width, set.height, set.stride, @backingInt(set.format) };
        const same_shape = if (cap.last_taken) |lt| std.mem.eql(u32, &lt, &shape) else false;
        cap.last_taken = shape;
        cap.out_damage = cap.ready_damage;
        if (!same_shape) cap.out_damage.setFull();
        cap.out_rect[0] = .{ .x = 0, .y = 0, .width = @intCast(set.width), .height = @intCast(set.height) };
        cap.out = .{
            .data = set.buffers[idx].data,
            .width = set.width,
            .height = set.height,
            .stride = set.stride,
            .format = set.format,
            .transform = cap.ready_meta.transform,
            .y_invert = cap.ready_meta.y_invert,
            .damage = if (cap.out_damage.full) &cap.out_rect else cap.out_damage.rects[0..cap.out_damage.len],
            .presented_ns = cap.ready_meta.present_ns,
            .latency_ns = cap.ready_meta.latency_ns,
            .seq = cap.seq,
        };
        cap.seq += 1;
        return &cap.out;
    }

    pub fn nextFrame(cap: *Capture, timeout_ms: i32) Error!*const Frame {
        try cap.requestFrame();
        const start = sys.nowMs();
        while (true) {
            if (cap.takeFrame()) |f| return f;
            switch (cap.state) {
                .stopped => return error.Stopped,
                .failed => return error.CaptureFailed,
                else => {},
            }
            var wait: i32 = -1;
            if (timeout_ms >= 0) {
                const el: i32 = @intCast(sys.nowMs() -% start);
                if (el >= timeout_ms) return error.Timeout;
                wait = timeout_ms - el;
            }
            _ = try cap.client.dispatchTimeout(wait);
        }
    }

    fn kick(cap: *Capture) Error!void {
        if (!cap.want_frame or cap.state != .idle or cap.ready_idx != null) return;
        switch (cap.kind) {
            .ext => try cap.startExt(),
            .wlr => try cap.startWlr(),
        }
    }

    fn pickTarget(cap: *const Capture) u8 {
        if (cap.front_set != null and cap.front_set == cap.cur and cap.front.? == 0) return 1;
        return 0;
    }

    fn ensureBuffers(cap: *Capture, w: u32, h: u32, stride: u32, format: P.WlShm.Format) Error!void {
        if (cap.cur) |s| if (s.matches(w, h, stride, format)) return;
        const gpa = cap.client.gpa;
        const conn = cap.client.conn;
        const ns = try gpa.create(shm.BufferSet);
        errdefer gpa.destroy(ns);
        ns.* = try shm.BufferSet.create(conn, cap.client.shm.?, 2, w, h, stride, format);
        if (cap.cur) |old| {
            if (cap.ready_set == old) {
                // Stale size; a fresh frame (with full damage) follows.
                cap.ready_idx = null;
                cap.ready_set = null;
                cap.want_frame = true;
            }
            if (cap.front_set == old) {
                if (cap.retired) |r| {
                    r.destroy(conn);
                    gpa.destroy(r);
                }
                cap.retired = old;
            } else {
                old.destroy(conn);
                gpa.destroy(old);
            }
        }
        cap.cur = ns;
        cap.buf_valid = .{ false, false };
        cap.buf_damage = .{ .{}, .{} };
        log.debug("capture buffers {d}x{d} stride {d} format {t}", .{ w, h, stride, format });
    }

    fn beginFrame(cap: *Capture) void {
        cap.state = .capturing;
        cap.want_frame = false;
        cap.frame_damage.clear();
        cap.frame_transform = if (cap.output) |o| o.transform else .normal;
        cap.frame_y_invert = false;
        cap.frame_present_ns = 0;
        cap.request_ns = sys.nowNs();
    }

    fn finishFrame(cap: *Capture) void {
        const set = cap.cur.?;
        const idx = cap.target.?;
        // Other buffers miss this frame's changes; hint them next time.
        for (0..set.count) |j| if (j != idx) cap.buf_damage[j].merge(&cap.frame_damage, set.width, set.height);
        cap.buf_damage[idx].clear();
        cap.buf_valid[idx] = true;
        cap.ready_damage = cap.frame_damage;
        cap.ready_meta = .{
            .transform = cap.frame_transform,
            .y_invert = cap.frame_y_invert,
            .present_ns = cap.frame_present_ns,
            .latency_ns = sys.nowNs() -% cap.request_ns,
        };
        cap.ready_idx = idx;
        cap.ready_set = set;
        cap.target = null;
        cap.state = .idle;
        cap.consecutive_failures = 0;
        if (cap.on_ready) |h| h.func(h.ctx);
    }

    fn frameFailed(cap: *Capture, reason: u32, stopped: bool) Error!void {
        cap.target = null;
        cap.last_failure = reason;
        if (stopped) {
            cap.state = .stopped;
            return;
        }
        cap.consecutive_failures += 1;
        if (cap.consecutive_failures >= 10) {
            log.warn("capture failing repeatedly (reason {d}); giving up", .{reason});
            cap.state = .failed;
            return;
        }
        cap.state = if (cap.kind == .ext and cap.constraints == null) .negotiating else .idle;
        cap.want_frame = true;
        try cap.kick();
    }

    fn startExt(cap: *Capture) Error!void {
        const c = cap.constraints orelse return;
        const format = c.choose() orelse {
            log.warn("no usable shm format offered", .{});
            cap.state = .failed;
            return;
        };
        try cap.ensureBuffers(c.width, c.height, c.width * 4, format);
        const conn = cap.client.conn;
        const set = cap.cur.?;
        const idx = cap.pickTarget();
        const frame = try cap.session.?.createFrame(conn);
        conn.setHandler(frame.id, wire.Handler.init(Capture, cap, onExtFrame));
        try frame.attachBuffer(conn, set.buffers[idx].proxy);
        const d = &cap.buf_damage[idx];
        if (!cap.buf_valid[idx] or d.full) {
            try frame.damageBuffer(conn, 0, 0, @intCast(set.width), @intCast(set.height));
        } else for (d.rects[0..d.len]) |r| {
            try frame.damageBuffer(conn, r.x, r.y, r.width, r.height);
        }
        try frame.capture(conn);
        cap.ext_frame = frame;
        cap.target = idx;
        cap.beginFrame();
    }

    fn onSession(cap: *Capture, msg: *wire.Message) Error!void {
        switch (try msg.decode(P.ExtImageCopyCaptureSessionV1)) {
            .buffer_size => |b| {
                cap.pending.width = b.width;
                cap.pending.height = b.height;
            },
            .shm_format => |f| cap.pending.addFormat(@backingInt(f.format)),
            .dmabuf_device, .dmabuf_format => {},
            .done => {
                cap.constraints = cap.pending;
                cap.pending.nformats = 0;
                if (cap.state == .negotiating) cap.state = .idle;
                try cap.kick();
            },
            .stopped => {
                log.info("capture session stopped", .{});
                cap.state = .stopped;
            },
        }
    }

    fn onExtFrame(cap: *Capture, msg: *wire.Message) Error!void {
        const conn = cap.client.conn;
        switch (try msg.decode(P.ExtImageCopyCaptureFrameV1)) {
            .transform => |t| cap.frame_transform = t.transform,
            .damage => |d| if (cap.cur) |set| cap.frame_damage.add(.{ .x = d.x, .y = d.y, .width = d.width, .height = d.height }, set.width, set.height),
            .presentation_time => |p| {
                const sec = @as(u64, p.tv_sec_hi) << 32 | p.tv_sec_lo;
                cap.frame_present_ns = sec *% std.time.ns_per_s +% p.tv_nsec;
            },
            .ready => {
                if (cap.ext_frame) |f| try f.destroy(conn);
                cap.ext_frame = null;
                if (cap.target == null) return;
                cap.finishFrame();
            },
            .failed => |f| {
                if (cap.ext_frame) |fr| try fr.destroy(conn);
                cap.ext_frame = null;
                log.debug("ext capture failed: {t}", .{f.reason});
                try cap.frameFailed(@backingInt(f.reason), f.reason == .stopped);
            },
        }
    }

    fn startWlr(cap: *Capture) Error!void {
        const out = cap.output orelse return error.Unsupported;
        if (out.removed) {
            cap.state = .stopped;
            return;
        }
        const conn = cap.client.conn;
        const frame = try cap.client.screencopy.?.captureOutput(conn, @intFromBool(cap.paint_cursors), out.proxy);
        conn.setHandler(frame.id, wire.Handler.init(Capture, cap, onWlrFrame));
        cap.wlr_frame = frame;
        cap.wlr_nformats = 0;
        cap.target = null;
        cap.beginFrame();
    }

    fn wlrCopy(cap: *Capture) Error!void {
        const frame = cap.wlr_frame orelse return;
        if (cap.target != null) return; // already copying
        const conn = cap.client.conn;
        const format = chooseFormat(cap.wlr_formats[0..cap.wlr_nformats]) orelse {
            log.warn("screencopy offered no usable shm format", .{});
            try frame.destroy(conn);
            cap.wlr_frame = null;
            cap.state = .failed;
            return;
        };
        try cap.ensureBuffers(cap.wlr_size[0], cap.wlr_size[1], cap.wlr_size[2], format);
        const idx = cap.pickTarget();
        cap.target = idx;
        const buf = cap.cur.?.buffers[idx].proxy;
        if (conn.version(frame.id) >= 2) try frame.copyWithDamage(conn, buf) else try frame.copy(conn, buf);
    }

    fn onWlrFrame(cap: *Capture, msg: *wire.Message) Error!void {
        const conn = cap.client.conn;
        const frame_version = conn.version(msg.object);
        switch (try msg.decode(P.ZwlrScreencopyFrameV1)) {
            .buffer => |b| {
                // All 32bpp formats share one size/stride.
                if (cap.wlr_nformats < cap.wlr_formats.len) {
                    cap.wlr_formats[cap.wlr_nformats] = @backingInt(b.format);
                    cap.wlr_nformats += 1;
                }
                cap.wlr_size = .{ b.width, b.height, b.stride };
                if (frame_version < 3) try cap.wlrCopy();
            },
            .linux_dmabuf => {},
            .buffer_done => try cap.wlrCopy(),
            .flags => |f| cap.frame_y_invert = f.flags & P.ZwlrScreencopyFrameV1.Flags.y_invert != 0,
            .damage => |d| if (cap.cur) |set| cap.frame_damage.add(.{
                .x = std.math.cast(i32, d.x) orelse std.math.maxInt(i32),
                .y = std.math.cast(i32, d.y) orelse std.math.maxInt(i32),
                .width = std.math.cast(i32, d.width) orelse std.math.maxInt(i32),
                .height = std.math.cast(i32, d.height) orelse std.math.maxInt(i32),
            }, set.width, set.height),
            .ready => |r| {
                if (cap.wlr_frame) |f| try f.destroy(conn);
                cap.wlr_frame = null;
                const sec = @as(u64, r.tv_sec_hi) << 32 | r.tv_sec_lo;
                cap.frame_present_ns = sec *% std.time.ns_per_s +% r.tv_nsec;
                if (cap.target == null) return;
                // copy_with_damage reports damage; plain copy does not.
                if (frame_version < 2) cap.frame_damage.setFull();
                cap.finishFrame();
            },
            .failed => {
                if (cap.wlr_frame) |f| try f.destroy(conn);
                cap.wlr_frame = null;
                try cap.frameFailed(0, false);
            },
        }
    }
};

test "damage clipping, merging and overflow" {
    var d: Damage = .{};
    d.add(.{ .x = -5, .y = -5, .width = 10, .height = 10 }, 100, 100);
    try std.testing.expectEqual(1, d.len);
    try std.testing.expectEqual(Rect{ .x = 0, .y = 0, .width = 5, .height = 5 }, d.rects[0]);
    d.add(.{ .x = 200, .y = 0, .width = 10, .height = 10 }, 100, 100); // outside
    d.add(.{ .x = 0, .y = 0, .width = 0, .height = 10 }, 100, 100); // empty
    d.add(.{ .x = std.math.maxInt(i32), .y = 0, .width = std.math.maxInt(i32), .height = 1 }, 100, 100);
    try std.testing.expectEqual(1, d.len);
    for (0..Damage.capacity + 5) |k| d.add(.{ .x = @intCast(k), .y = @intCast(k), .width = 1, .height = 1 }, 100, 100);
    try std.testing.expect(d.collapsed);
    try std.testing.expectEqual(1, d.len);
    try std.testing.expectEqual(Rect{ .x = 0, .y = 0, .width = Damage.capacity + 5, .height = Damage.capacity + 5 }, d.rects[0]);
    var e: Damage = .{};
    e.add(.{ .x = 0, .y = 0, .width = 100, .height = 100 }, 100, 100);
    try std.testing.expect(e.full);
    d.merge(&e, 100, 100);
    try std.testing.expect(d.full);
}

test "format preference" {
    try std.testing.expectEqual(P.WlShm.Format.xrgb8888, chooseFormat(&.{ 0x34324241, 0, 1 }).?);
    try std.testing.expectEqual(P.WlShm.Format.argb8888, chooseFormat(&.{0}).?);
    try std.testing.expectEqual(null, chooseFormat(&.{0x30335241}));
}
