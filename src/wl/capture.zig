//! Output frame capture into shared memory with damage tracking, via ext-image-copy-capture-v1
//! (preferred) or zwlr_screencopy_manager_v1; with ext, optionally into dmabufs (GPU memory, no
//! copy to RAM; src/wl/dmabuf.zig). Double-buffered (shm) or a ring (dmabuf): a taken frame
//! stays valid until the next takeFrame()/deinit; `Frame.damage` is relative to the previously
//! taken frame.

const std = @import("std");
const wire = @import("wire.zig");
const sys = @import("sys.zig");
const shm = @import("shm.zig");
const dmabuf = @import("dmabuf.zig");
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
    /// Rows `stride` bytes apart; XRGB8888/ARGB8888 are B,G,R,X/A bytes in memory. Empty for a
    /// dmabuf frame (`dmabuf`).
    data: []const u8,
    /// The GPU buffer holding a dmabuf frame. The compositor's rendering may still be in flight
    /// at `ready`: importers wait on its implicit fence (poll the plane fd for POLLIN).
    dmabuf: ?*const dmabuf.Bo = null,
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
    /// CLOCK_MONOTONIC ns at `ready` (0: not captured, e.g. a synthetic frame).
    ready_ns: u64 = 0,
    seq: u64,
    /// The buffer's index in its ring (`Capture.pin`), and the ring's generation: a new one (new
    /// size or format) has new buffers.
    slot: u8 = 0,
    ring: u32 = 0,
};

pub const Backend = enum { auto, ext, wlr };

pub const BufferKind = enum { shm, dmabuf };

pub const Options = struct {
    backend: Backend = .auto,
    /// Composite the cursor into frames (RDP normally draws it client-side).
    paint_cursors: bool = false,
    /// Where the compositor writes frames: shm (RAM) or dmabuf (GPU memory allocated by
    /// `dmabuf_allocator`). dmabuf needs the ext backend and falls back to shm for good when the
    /// compositor offers none or allocation fails.
    buffers: BufferKind = .shm,
    dmabuf_allocator: ?*const dmabuf.Allocator = null,
    /// Ring size for dmabuf buffers (2..4).
    dmabuf_count: u8 = 3,
    /// LINEAR when the compositor offers it (any importer reads it); else its explicit tilings.
    prefer_linear: bool = true,
};

const max_ring = dmabuf.BufferSet.max_buffers;

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

const DmabufFormat = struct {
    format: u32,
    mods: [32]u64 = undefined,
    nmods: usize = 0,
};

const Constraints = struct {
    width: u32 = 0,
    height: u32 = 0,
    formats: [16]u32 = undefined,
    nformats: usize = 0,
    dmabuf_device: ?u64 = null,
    /// The 32-bit RGB dmabuf formats offered, with their modifiers.
    dmabuf: [4]DmabufFormat = undefined,
    ndmabuf: usize = 0,

    fn addFormat(c: *Constraints, f: u32) void {
        if (c.nformats < c.formats.len) {
            c.formats[c.nformats] = f;
            c.nformats += 1;
        }
    }

    fn choose(c: *const Constraints) ?P.WlShm.Format {
        return chooseFormat(c.formats[0..c.nformats]);
    }

    /// Whether buffers made for `c` fit `o` (same size, same formats chosen).
    fn sameBuffers(c: *const Constraints, o: *const Constraints) bool {
        const df: ?u32 = if (c.chooseDmabuf()) |f| f.format else null;
        const odf: ?u32 = if (o.chooseDmabuf()) |f| f.format else null;
        return c.width == o.width and c.height == o.height and c.choose() == o.choose() and df == odf;
    }

    /// `modifiers`: an array of u64 in host order.
    fn addDmabuf(c: *Constraints, format: u32, modifiers: []const u8) void {
        switch (format) {
            dmabuf.format_xrgb8888, dmabuf.format_argb8888, dmabuf.format_xbgr8888, dmabuf.format_abgr8888 => {},
            else => return,
        }
        const e = for (c.dmabuf[0..c.ndmabuf]) |*e| {
            if (e.format == format) break e;
        } else blk: {
            if (c.ndmabuf == c.dmabuf.len) return;
            c.dmabuf[c.ndmabuf] = .{ .format = format };
            c.ndmabuf += 1;
            break :blk &c.dmabuf[c.ndmabuf - 1];
        };
        var i: usize = 0;
        while (i + 8 <= modifiers.len and e.nmods < e.mods.len) : (i += 8) {
            e.mods[e.nmods] = std.mem.bytesToValue(u64, modifiers[i..][0..8]);
            e.nmods += 1;
        }
    }

    /// Same preference as shm: BGRX first.
    fn chooseDmabuf(c: *const Constraints) ?*const DmabufFormat {
        const prefs = [_]u32{ dmabuf.format_xrgb8888, dmabuf.format_argb8888, dmabuf.format_xbgr8888, dmabuf.format_abgr8888 };
        for (prefs) |p| for (c.dmabuf[0..c.ndmabuf]) |*e| if (e.format == p and e.nmods > 0) return e;
        return null;
    }
};

/// The capture's buffers: shm (the compositor copies into RAM) or dmabuf (GPU memory).
const Set = union(enum) {
    shm: shm.BufferSet,
    dmabuf: dmabuf.BufferSet,

    fn count(s: *const Set) usize {
        return switch (s.*) {
            inline else => |*x| x.count,
        };
    }

    fn width(s: *const Set) u32 {
        return switch (s.*) {
            inline else => |*x| x.width,
        };
    }

    fn height(s: *const Set) u32 {
        return switch (s.*) {
            inline else => |*x| x.height,
        };
    }

    fn stride(s: *const Set) u32 {
        return switch (s.*) {
            .shm => |*x| x.stride,
            .dmabuf => |*x| x.stride(),
        };
    }

    /// The format as wl_shm names it (dmabuf: the same layout).
    fn shmFormat(s: *const Set) P.WlShm.Format {
        return switch (s.*) {
            .shm => |*x| x.format,
            .dmabuf => |*x| dmabuf.shmFormat(x.format),
        };
    }

    fn proxy(s: *const Set, i: usize) P.WlBuffer {
        return switch (s.*) {
            .shm => |*x| x.buffers[i].proxy,
            .dmabuf => |*x| x.proxies[i],
        };
    }

    fn destroy(s: *Set, conn: *wire.Connection) void {
        switch (s.*) {
            inline else => |*x| x.destroy(conn),
        }
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
    /// Changes of the session's buffer constraints (ext), and their count when the frame in
    /// flight was requested: a frame failing across a change failed because of it.
    constraint_changes: u32 = 0,
    frame_constraint_changes: u32 = 0,

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
    cur: ?*Set = null,
    retired: ?*Set = null,
    buf_damage: [max_ring]Damage = @splat(.{}),
    buf_valid: [max_ring]bool = @splat(false),
    front: ?u8 = null,
    front_set: ?*Set = null,
    target: ?u8 = null,
    last_target: u8 = 0,
    /// A dmabuf the consumer keeps reading (its change detection's reference): never a target.
    pinned: ?u8 = null,
    ring: u32 = 0,
    ready_idx: ?u8 = null,
    ready_set: ?*Set = null,

    buffers: BufferKind = .shm,
    dmabuf_allocator: ?*const dmabuf.Allocator = null,
    dmabuf_count: u8 = 3,
    prefer_linear: bool = true,
    /// dmabuf was asked for but cannot work here: shm from now on.
    dmabuf_off: bool = false,

    frame_damage: Damage = .{},
    frame_transform: P.WlOutput.Transform = .normal,
    frame_y_invert: bool = false,
    frame_present_ns: u64 = 0,
    request_ns: u64 = 0,

    ready_damage: Damage = .{},
    ready_meta: struct { transform: P.WlOutput.Transform, y_invert: bool, present_ns: u64, latency_ns: u64, ready_ns: u64 } = undefined,
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
            .buffers = opts.buffers,
            .dmabuf_allocator = opts.dmabuf_allocator,
            .dmabuf_count = std.math.clamp(opts.dmabuf_count, 2, max_ring),
            .prefer_linear = opts.prefer_linear,
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
        if (cap.ext_frame) |f| if (!cap.unsendFrame()) f.destroy(conn) catch {};
        if (cap.wlr_frame) |f| f.destroy(conn) catch {};
        if (cap.session) |s| s.destroy(conn) catch {};
        if (cap.owned_source) |s| s.destroy(conn) catch {};
        for ([_]?*Set{ cap.cur, cap.retired }) |maybe| if (maybe) |set| {
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
        const shape = [4]u32{ set.width(), set.height(), set.stride(), @backingInt(set.shmFormat()) };
        const same_shape = if (cap.last_taken) |lt| std.mem.eql(u32, &lt, &shape) else false;
        cap.last_taken = shape;
        cap.out_damage = cap.ready_damage;
        if (!same_shape) cap.out_damage.setFull();
        cap.out_rect[0] = .{ .x = 0, .y = 0, .width = @intCast(set.width()), .height = @intCast(set.height()) };
        cap.out = .{
            .data = switch (set.*) {
                .shm => |*x| x.buffers[idx].data,
                .dmabuf => &.{},
            },
            .dmabuf = switch (set.*) {
                .shm => null,
                .dmabuf => |*x| &x.bos[idx],
            },
            .width = set.width(),
            .height = set.height(),
            .stride = set.stride(),
            .format = set.shmFormat(),
            .transform = cap.ready_meta.transform,
            .y_invert = cap.ready_meta.y_invert,
            .damage = if (cap.out_damage.full) &cap.out_rect else cap.out_damage.rects[0..cap.out_damage.len],
            .presented_ns = cap.ready_meta.present_ns,
            .latency_ns = cap.ready_meta.latency_ns,
            .ready_ns = cap.ready_meta.ready_ns,
            .seq = cap.seq,
            .slot = idx,
            .ring = cap.ring,
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

    /// Whether frames go to dmabufs (asked for, and not given up on).
    pub fn usingDmabuf(cap: *const Capture) bool {
        return if (cap.cur) |s| s.* == .dmabuf else false;
    }

    /// Give up on dmabuf (e.g. the consumer found the buffers never filled, as with some VM
    /// GPUs): the next frame and all after go to shm.
    pub fn useShm(cap: *Capture) void {
        if (cap.dmabuf_off) return;
        cap.dmabuf_off = true;
        log.info("capture: dmabuf off, using shm", .{});
    }

    /// Keep the compositor off dmabuf `slot` (of the current ring) until `unpin` or a new ring:
    /// the consumer compares later frames with it. False (nothing pinned) unless the ring has 3
    /// or more buffers, so one stays free.
    pub fn pin(cap: *Capture, slot: u8) bool {
        if (cap.cur) |s| if (s.* == .dmabuf and slot < s.count() and s.count() >= 3) {
            cap.pinned = slot;
            return true;
        };
        cap.pinned = null;
        return false;
    }

    pub fn unpin(cap: *Capture) void {
        cap.pinned = null;
    }

    /// shm: the buffer the consumer does not hold. dmabuf: round robin over the ring, skipping
    /// the held and the pinned one, so a buffer is reused as late as possible.
    fn pickTarget(cap: *Capture) u8 {
        const set = cap.cur.?;
        const held: ?u8 = if (cap.front_set == set) cap.front else null;
        const n: u8 = @intCast(set.count());
        if (set.* == .shm) return if (held == 0) 1 else 0;
        // A ring has 2 or more buffers and a pin needs 3 (`pin`; a new ring drops it): one of
        // them is neither held nor pinned.
        std.debug.assert(n >= 2 and (cap.pinned == null or n >= 3));
        var k: u8 = 1;
        while (k <= n) : (k += 1) {
            const idx = (cap.last_target + k) % n;
            if (idx != held and idx != cap.pinned) {
                cap.last_target = idx;
                return idx;
            }
        }
        unreachable;
    }

    fn ensureBuffers(cap: *Capture, w: u32, h: u32, stride: u32, format: P.WlShm.Format) Error!void {
        if (cap.cur) |s| if (s.* == .shm and s.shm.matches(w, h, stride, format)) return;
        const gpa = cap.client.gpa;
        const ns = try gpa.create(Set);
        errdefer gpa.destroy(ns);
        ns.* = .{ .shm = try shm.BufferSet.create(cap.client.conn, cap.client.shm.?, 2, w, h, stride, format) };
        cap.install(ns);
        log.debug("capture buffers {d}x{d} stride {d} format {t}", .{ w, h, stride, format });
    }

    fn ensureDmabuf(cap: *Capture, c: *const Constraints, f: *const DmabufFormat) dmabuf.Error!void {
        if (cap.cur) |s| if (s.* == .dmabuf and s.dmabuf.matches(c.width, c.height, f.format)) return;
        var mods_buf: [32]u64 = undefined;
        const mods = dmabuf.chooseModifiers(f.mods[0..f.nmods], cap.prefer_linear, &mods_buf);
        if (mods.len == 0) return error.Unsupported;
        const gpa = cap.client.gpa;
        const ns = try gpa.create(Set);
        errdefer gpa.destroy(ns);
        ns.* = .{ .dmabuf = try dmabuf.BufferSet.create(cap.client.conn, cap.client.linux_dmabuf.?, cap.dmabuf_allocator.?, c.dmabuf_device.?, cap.dmabuf_count, c.width, c.height, f.format, mods) };
        cap.install(ns);
        log.info("capture dmabufs {d}x{d} format 0x{x} modifier 0x{x} stride {d}, {d} buffers", .{ c.width, c.height, f.format, ns.dmabuf.modifier(), ns.dmabuf.stride(), ns.dmabuf.count });
    }

    /// Make `ns` current; the old set is freed, or retired while the consumer holds a frame in it.
    fn install(cap: *Capture, ns: *Set) void {
        const gpa = cap.client.gpa;
        const conn = cap.client.conn;
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
        cap.buf_valid = @splat(false);
        cap.buf_damage = @splat(.{});
        cap.last_target = 0;
        cap.pinned = null;
        cap.ring +%= 1;
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
        for (0..set.count()) |j| if (j != idx) cap.buf_damage[j].merge(&cap.frame_damage, set.width(), set.height());
        cap.buf_damage[idx].clear();
        cap.buf_valid[idx] = true;
        cap.ready_damage = cap.frame_damage;
        const now = sys.nowNs();
        cap.ready_meta = .{
            .transform = cap.frame_transform,
            .y_invert = cap.frame_y_invert,
            .present_ns = cap.frame_present_ns,
            .latency_ns = now -% cap.request_ns,
            .ready_ns = now,
        };
        cap.ready_idx = idx;
        cap.ready_set = set;
        cap.target = null;
        // A frame in flight at the stop still completes; the session stays stopped.
        if (cap.state != .stopped) cap.state = .idle;
        cap.consecutive_failures = 0;
        if (cap.on_ready) |h| h.func(h.ctx);
    }

    fn frameFailed(cap: *Capture, reason: u32, stopped: bool) Error!void {
        const into_dmabuf = cap.target != null and cap.usingDmabuf();
        cap.target = null;
        cap.last_failure = reason;
        if (stopped or cap.state == .stopped) {
            cap.state = .stopped;
            return;
        }
        if (cap.constraint_changes != cap.frame_constraint_changes) {
            // The output changed under the frame (a mode change, a rotation): Hyprland sends the
            // new constraints, then fails the frame (buffer_constraints, or unknown when the frame
            // was made before they went out). Retried in buffers of the new size; neither the
            // capture nor its dmabufs failed, so a burst of mode changes gives up on neither.
            log.debug("capture: frame failed (reason {d}) as the output changed; retrying", .{reason});
        } else {
            cap.consecutive_failures += 1;
            if (into_dmabuf and !cap.dmabuf_off and cap.consecutive_failures >= dmabuf_failures) {
                log.warn("capture: {d} frames into dmabufs failed (reason {d}); using shm", .{ cap.consecutive_failures, reason });
                cap.dmabuf_off = true;
                cap.consecutive_failures = 0;
            } else if (cap.consecutive_failures >= 10) {
                log.warn("capture failing repeatedly (reason {d}); giving up", .{reason});
                cap.state = .failed;
                return;
            }
        }
        cap.state = if (cap.kind == .ext and cap.constraints == null) .negotiating else .idle;
        cap.want_frame = true;
        try cap.kick();
    }

    /// Consecutive failed frames into dmabufs before capture goes to shm for good.
    const dmabuf_failures = 3;

    /// dmabuf when asked for and possible; on any failure, shm for good.
    fn ensureExtBuffers(cap: *Capture, c: *const Constraints) Error!bool {
        if (cap.buffers == .dmabuf and !cap.dmabuf_off) dma: {
            const why: []const u8 = if (cap.dmabuf_allocator == null)
                "no allocator"
            else if (cap.client.linux_dmabuf == null)
                "no zwp_linux_dmabuf_v1"
            else if (c.dmabuf_device == null)
                "no dmabuf device offered"
            else if (c.chooseDmabuf() == null)
                "no usable dmabuf format offered"
            else {
                cap.ensureDmabuf(c, c.chooseDmabuf().?) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => {
                        if (cap.dmabuf_allocator.?.why()) |why| {
                            log.warn("dmabuf capture failed: {s}; using shm", .{why});
                        } else log.warn("dmabuf capture failed ({t}); using shm", .{e});
                        cap.dmabuf_off = true;
                        break :dma;
                    },
                };
                return true;
            };
            log.warn("dmabuf capture unavailable: {s}; using shm", .{why});
            cap.dmabuf_off = true;
        }
        const format = c.choose() orelse {
            log.warn("no usable shm format offered", .{});
            cap.state = .failed;
            return false;
        };
        try cap.ensureBuffers(c.width, c.height, c.width * 4, format);
        return true;
    }

    fn startExt(cap: *Capture) Error!void {
        const c = cap.constraints orelse return;
        if (!try cap.ensureExtBuffers(&c)) return;
        const conn = cap.client.conn;
        const set = cap.cur.?;
        const idx = cap.pickTarget();
        const frame = try cap.session.?.createFrame(conn);
        conn.setHandler(frame.id, wire.Handler.init(Capture, cap, onExtFrame));
        try frame.attachBuffer(conn, set.proxy(idx));
        const d = &cap.buf_damage[idx];
        if (!cap.buf_valid[idx] or d.full) {
            try frame.damageBuffer(conn, 0, 0, @intCast(set.width()), @intCast(set.height()));
        } else for (d.rects[0..d.len]) |r| {
            try frame.damageBuffer(conn, r.x, r.y, r.width, r.height);
        }
        try frame.capture(conn);
        cap.ext_frame = frame;
        cap.target = idx;
        cap.frame_constraint_changes = cap.constraint_changes;
        cap.beginFrame();
    }

    fn onSession(cap: *Capture, msg: *wire.Message) Error!void {
        switch (try msg.decode(P.ExtImageCopyCaptureSessionV1)) {
            .buffer_size => |b| {
                cap.pending.width = b.width;
                cap.pending.height = b.height;
            },
            .shm_format => |f| cap.pending.addFormat(@backingInt(f.format)),
            .dmabuf_device => |d| cap.pending.dmabuf_device = dmabuf.parseDevice(d.device),
            .dmabuf_format => |f| cap.pending.addDmabuf(f.format, f.modifiers),
            .done => {
                if (cap.constraints) |*old| if (!old.sameBuffers(&cap.pending)) {
                    cap.constraint_changes +%= 1;
                };
                cap.constraints = cap.pending;
                cap.pending.nformats = 0;
                cap.pending.ndmabuf = 0;
                cap.pending.dmabuf_device = null;
                if (cap.state == .negotiating) cap.state = .idle;
                try cap.kick();
            },
            .stopped => {
                log.info("capture session stopped", .{});
                cap.state = .stopped;
                // No frame for a stopped session reaches the compositor (Hyprland 0.56 crashes on
                // one whose output is gone): a frame still queued is taken back.
                if (cap.unsendFrame()) log.info("capture: the frame queued before the stop is not sent", .{});
            },
        }
    }

    /// create_frame is ext_image_copy_capture_session_v1's first request.
    const create_frame_opcode = 0;

    /// Takes back the frame if none of its requests went out yet (its requests carry no fds and
    /// only the frame names it): true if so.
    fn unsendFrame(cap: *Capture) bool {
        const f = cap.ext_frame orelse return false;
        const s = cap.session orelse return false;
        if (!cap.client.conn.unsendObject(s.id, create_frame_opcode, f.id)) return false;
        cap.ext_frame = null;
        cap.target = null;
        return true;
    }

    fn onExtFrame(cap: *Capture, msg: *wire.Message) Error!void {
        const conn = cap.client.conn;
        switch (try msg.decode(P.ExtImageCopyCaptureFrameV1)) {
            .transform => |t| cap.frame_transform = t.transform,
            .damage => |d| if (cap.cur) |set| cap.frame_damage.add(.{ .x = d.x, .y = d.y, .width = d.width, .height = d.height }, set.width(), set.height()),
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
        const buf = cap.cur.?.proxy(idx);
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
            }, set.width(), set.height()),
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
