//! Client + Capture tests against an in-process fake compositor on a socketpair. For
//! ext-image-copy-capture it copies only the client's damage hints plus its own damage,
//! so wrong double-buffer bookkeeping shows as stale pixels.

const std = @import("std");
const wire = @import("wire.zig");
const sys = @import("sys.zig");
const Client = @import("client.zig").Client;
const capture = @import("capture.zig");
const dmabuf = @import("dmabuf.zig");
const P = wire.proto;
const Rect = capture.Rect;

const testing = std.testing;

const Buf = struct { pool: u32, offset: usize, w: u32, h: u32, stride: u32, dmabuf: bool = false };
const PoolMem = []align(std.heap.page_size_min) u8;

/// What fakes saw, in order across their threads: a fake compositor's requests, a fake
/// Hyprland's commands (src/session/desktop.zig's tests).
pub const Journal = struct {
    mutex: std.atomic.Mutex = .unlocked,
    lines: [256][64]u8 = undefined,
    lens: [256]u8 = undefined,
    n: usize = 0,

    pub fn add(j: *Journal, comptime fmt: []const u8, args: anytype) void {
        while (!j.mutex.tryLock()) std.Thread.yield() catch {};
        defer j.mutex.unlock();
        if (j.n == j.lines.len) return;
        const line = std.fmt.bufPrint(&j.lines[j.n], fmt, args) catch return;
        j.lens[j.n] = @intCast(line.len);
        j.n += 1;
    }

    /// Where `line` first is.
    pub fn find(j: *Journal, line: []const u8) ?usize {
        while (!j.mutex.tryLock()) std.Thread.yield() catch {};
        defer j.mutex.unlock();
        for (0..j.n) |k| if (std.mem.eql(u8, j.lines[k][0..j.lens[k]], line)) return k;
        return null;
    }

    pub fn dump(j: *Journal) void {
        while (!j.mutex.tryLock()) std.Thread.yield() catch {};
        defer j.mutex.unlock();
        for (0..j.n) |k| std.debug.print("  {d}: {s}\n", .{ k, j.lines[k][0..j.lens[k]] });
    }
};

/// FAKE-2, announced and removed by `Fake.hotplug`.
const hotplug_global = 99;
/// `Fake.output_names[k]` is global first_output_global + k.
const first_output_global = 200;

pub const Fake = struct {
    gpa: std.mem.Allocator,
    fd: sys.Fd,
    tx: *wire.Connection,
    inbuf: [1 << 16]u8 = undefined,
    in_len: usize = 0,
    fdq: [64]sys.Fd = undefined,
    nfdq: usize = 0,
    objects: std.AutoHashMapUnmanaged(u32, P.Interface) = .empty,
    pools: std.AutoHashMapUnmanaged(u32, PoolMem) = .empty,
    buffers: std.AutoHashMapUnmanaged(u32, Buf) = .empty,
    width: u32 = 64,
    height: u32 = 48,
    screen: []u32 = &.{},
    frame_no: u32 = 0,
    full_next: bool = true,
    session: u32 = 0,
    frame_buffer: u32 = 0,
    hints: [64]Rect = undefined,
    nhints: usize = 0,
    /// Capacity reserved up front so the test thread can read while the fake appends.
    snapshots: std.ArrayListUnmanaged([]u32) = .empty,
    damages: std.ArrayListUnmanaged(Rect) = .empty,
    resize_at: ?u32 = null,
    resize_to: [2]u32 = .{ 0, 0 },
    /// Set by the test thread: the output changes size at each of the next N captures (mode
    /// changes faster than the client follows). As Hyprland, the fake sends the new constraints,
    /// then fails the frame: buffer_constraints, or unknown every other time (Hyprland's answer to
    /// a frame made before the new size went out).
    resize_burst: std.atomic.Value(u32) = .init(0),
    /// Outputs announced at bind, all `width`x`height`.
    output_names: []const []const u8 = &.{"FAKE-1"},
    /// The output (index in `output_names`, hotplug_global for FAKE-2) of each wl_output,
    /// capture source and session.
    output_of: std.AutoHashMapUnmanaged(u32, u32) = .empty,
    /// Stop every capture session now, as Hyprland does when their output goes.
    stop_session: std.atomic.Value(bool) = .init(false),
    /// Set once `stop_session` stopped them and the events went out.
    session_stopped: std.atomic.Value(bool) = .init(false),
    /// Set by another thread: remove output `output_names[k - 1]` (stop its capture sessions,
    /// then its global), as Hyprland's `output remove`; `removed` counts the removals done.
    remove_output: std.atomic.Value(u32) = .init(0),
    removed: std.atomic.Value(u32) = .init(0),
    /// Stop the session just before the next frame is ready (a stop while a frame is in flight).
    stop_before_ready: bool = false,
    stopped_sessions: std.AutoHashMapUnmanaged(u32, void) = .empty,
    /// create_frame requests on a stopped session (Hyprland 0.56.2 crashes on the first:
    /// CImageCopyCaptureFrame's constructor reads the transform of the output that is gone).
    frames_after_stop: std.atomic.Value(u32) = .init(0),
    journal: ?*Journal = null,
    failed_sent: u32 = 0,
    stop: std.atomic.Value(bool) = .init(false),
    err: ?anyerror = null,
    registry: u32 = 0,
    /// Set by the test thread: announce (1) or remove (2) output FAKE-2.
    hotplug: std.atomic.Value(u8) = .init(0),
    /// Offer dmabuf in the capture constraints (device 226:128, XR24 tiled + LINEAR).
    offer_dmabuf: bool = false,
    /// Fail every frame into a dmabuf (a compositor that takes our buffers, then cannot fill them),
    /// with this reason (0 unknown, 1 buffer_constraints although the buffer fits them).
    fail_dmabuf_frames: bool = false,
    fail_dmabuf_reason: u32 = 0,
    /// Pool keys for dmabufs, apart from wl_shm_pool ids.
    next_dmabuf_pool: u32 = 0x8000_0000,
    param_planes: std.AutoHashMapUnmanaged(u32, [3]u32) = .empty, // params id -> fd slot, offset, stride
    param_fds: [64]sys.Fd = undefined,
    nparam_fds: usize = 0,
    dmabuf_modifier: u64 = 0,
    dmabuf_format: u32 = 0,
    dmabuf_buffers: u32 = 0,
    used_buffers: std.AutoHashMapUnmanaged(u32, void) = .empty,

    keymap: [512]u8 = undefined,
    keymap_len: usize = 0,
    keymap_format: u32 = 0,
    keys: [64][2]u32 = undefined,
    nkeys: usize = 0,
    mods: [4]u32 = .{ 0, 0, 0, 0 },
    abs: [4]u32 = .{ 0, 0, 0, 0 },
    abs_output: u32 = 0,
    buttons: [8][2]u32 = undefined,
    nbuttons: usize = 0,
    discrete: i32 = 0,
    axis_source: u32 = 99,
    pointer_frames: u32 = 0,

    pub const Config = struct {
        output_names: []const []const u8 = &.{"FAKE-1"},
        width: u32 = 64,
        height: u32 = 48,
        journal: ?*Journal = null,
    };

    fn init(gpa: std.mem.Allocator, fd: sys.Fd, cfg: Config) !*Fake {
        const f = try gpa.create(Fake);
        f.* = .{ .gpa = gpa, .fd = fd, .tx = try wire.Connection.initFd(gpa, fd), .output_names = cfg.output_names, .width = cfg.width, .height = cfg.height, .journal = cfg.journal };
        f.screen = try gpa.alloc(u32, f.width * f.height);
        @memset(f.screen, 0xff000000);
        try f.snapshots.ensureTotalCapacity(gpa, 64);
        try f.damages.ensureTotalCapacity(gpa, 64);
        return f;
    }

    fn deinit(f: *Fake) void {
        var it = f.pools.valueIterator();
        while (it.next()) |m| _ = std.c.munmap(@ptrCast(m.ptr), m.len);
        f.pools.deinit(f.gpa);
        f.param_planes.deinit(f.gpa);
        f.used_buffers.deinit(f.gpa);
        for (f.param_fds[0..f.nparam_fds]) |x| sys.close(x);
        f.buffers.deinit(f.gpa);
        f.output_of.deinit(f.gpa);
        f.stopped_sessions.deinit(f.gpa);
        f.objects.deinit(f.gpa);
        for (f.snapshots.items) |s| f.gpa.free(s);
        f.snapshots.deinit(f.gpa);
        f.damages.deinit(f.gpa);
        f.gpa.free(f.screen);
        for (f.fdq[0..f.nfdq]) |x| sys.close(x);
        f.tx.deinit(); // closes fd
        f.gpa.destroy(f);
    }

    fn run(f: *Fake) void {
        f.loop() catch |e| switch (e) {
            // The client hung up while the fake was replying: normal teardown.
            error.ConnectionClosed => {},
            else => f.err = e,
        };
    }

    fn loop(f: *Fake) !void {
        while (!f.stop.load(.acquire)) {
            try f.checkHotplug();
            switch (try sys.pollFd(f.fd, false, 5)) {
                .timeout => continue,
                .hangup, .ready => {},
            }
            const res = sys.recvMsg(f.fd, f.inbuf[f.in_len..], false) catch |e| switch (e) {
                error.ConnectionClosed => return,
                else => return e,
            };
            for (res.fds[0..res.nfds]) |x| {
                f.fdq[f.nfdq] = x;
                f.nfdq += 1;
            }
            f.in_len += res.len;
            var off: usize = 0;
            while (f.in_len - off >= 8) {
                const id = std.mem.readInt(u32, f.inbuf[off..][0..4], .little);
                const word = std.mem.readInt(u32, f.inbuf[off + 4 ..][0..4], .little);
                const size: usize = word >> 16;
                if (size < 8) return error.BadRequest;
                if (f.in_len - off < size) break;
                try f.handle(id, @truncate(word), f.inbuf[off + 8 .. off + size]);
                off += size;
            }
            std.mem.copyForwards(u8, f.inbuf[0 .. f.in_len - off], f.inbuf[off..f.in_len]);
            f.in_len -= off;
            try f.tx.flush();
        }
    }

    fn popFd(f: *Fake) !sys.Fd {
        if (f.nfdq == 0) return error.MissingFd;
        const x = f.fdq[0];
        std.mem.copyForwards(sys.Fd, f.fdq[0 .. f.nfdq - 1], f.fdq[1..f.nfdq]);
        f.nfdq -= 1;
        return x;
    }

    fn send(f: *Fake, id: u32, opcode: u16, args: []const wire.Arg) !void {
        try f.tx.request(id, opcode, args);
    }

    fn deleteId(f: *Fake, id: u32) !void {
        _ = f.objects.remove(id);
        try f.send(1, 1, &.{.{ .uint = id }});
    }

    fn globals(f: *Fake, reg: u32) !void {
        const list = [_]struct { []const u8, u32 }{
            .{ "wl_shm", 1 },
            .{ "wl_seat", 7 },
            .{ "ext_image_copy_capture_manager_v1", 1 },
            .{ "ext_output_image_capture_source_manager_v1", 1 },
            .{ "zwlr_screencopy_manager_v1", 3 },
            .{ "some_unknown_global_v9", 3 },
            .{ "zwp_virtual_keyboard_manager_v1", 1 },
            .{ "zwlr_virtual_pointer_manager_v1", 2 },
            .{ "zwp_linux_dmabuf_v1", 4 },
        };
        for (list, 1..) |g, name| try f.send(reg, 0, &.{ .{ .uint = @intCast(name) }, .{ .string = g[0] }, .{ .uint = g[1] } });
        for (0..f.output_names.len) |k| try f.send(reg, 0, &.{ .{ .uint = @intCast(first_output_global + k) }, .{ .string = "wl_output" }, .{ .uint = 4 } });
    }

    fn outputName(f: *const Fake, output: u32) []const u8 {
        return if (output == hotplug_global) "FAKE-2" else f.output_names[output];
    }

    /// What the journal calls `object`'s output.
    fn outputOf(f: *const Fake, object: u32) []const u8 {
        return if (f.output_of.get(object)) |o| f.outputName(o) else "?";
    }

    fn stopSession(f: *Fake, session: u32) !void {
        if (f.stopped_sessions.contains(session)) return;
        try f.send(session, 5, &.{}); // stopped
        try f.stopped_sessions.put(f.gpa, session, {});
    }

    fn sendConstraints(f: *Fake) !void {
        try f.send(f.session, 0, &.{ .{ .uint = f.width }, .{ .uint = f.height } });
        try f.send(f.session, 1, &.{.{ .uint = 0 }}); // argb8888
        try f.send(f.session, 1, &.{.{ .uint = 1 }}); // xrgb8888
        if (f.offer_dmabuf) {
            try f.send(f.session, 2, &.{.{ .array = &std.mem.toBytes(@as(u64, 0xe280)) }}); // 226:128
            const mods = [_]u64{ 0x0200_0000_0001_2345, dmabuf.mod_linear };
            try f.send(f.session, 3, &.{ .{ .uint = dmabuf.format_xrgb8888 }, .{ .array = std.mem.sliceAsBytes(&mods) } });
        }
        try f.send(f.session, 4, &.{}); // done
    }

    fn frameDamage(f: *const Fake) Rect {
        if (f.full_next) return .{ .x = 0, .y = 0, .width = @intCast(f.width), .height = @intCast(f.height) };
        const k = f.frame_no;
        return .{
            .x = @intCast((k * 13) % (f.width - 8)),
            .y = @intCast((k * 7) % (f.height - 6)),
            .width = 8,
            .height = 6,
        };
    }

    fn advance(f: *Fake, d: Rect) !void {
        const v: u32 = 0xff000000 | (f.frame_no + 1) *% 0x00102030;
        f.paint(d, v);
        f.snapshots.appendAssumeCapacity(try f.gpa.dupe(u32, f.screen));
        f.damages.appendAssumeCapacity(d);
        f.full_next = false;
    }

    fn paint(f: *Fake, d: Rect, v: u32) void {
        var y: usize = @intCast(d.y);
        while (y < d.y + d.height) : (y += 1) {
            @memset(f.screen[y * f.width + @as(usize, @intCast(d.x)) ..][0..@intCast(d.width)], v);
        }
    }

    fn copyRect(f: *Fake, b: Buf, d: Rect) void {
        const mem = f.pools.get(b.pool).?;
        var y: usize = @intCast(@max(d.y, 0));
        const y1: usize = @intCast(@min(d.y + d.height, @as(i32, @intCast(b.h))));
        const x0: usize = @intCast(@max(d.x, 0));
        const x1: usize = @intCast(@min(d.x + d.width, @as(i32, @intCast(b.w))));
        while (y < y1) : (y += 1) {
            for (x0..x1) |x| std.mem.writeInt(u32, mem[b.offset + y * b.stride + x * 4 ..][0..4], f.screen[y * f.width + x], .little);
        }
    }

    fn handle(f: *Fake, id: u32, opcode: u16, body: []const u8) !void {
        var r: wire.ArgReader = .{ .body = body };
        const iface = if (id == 1) P.Interface.wl_display else f.objects.get(id) orelse return error.UnknownObject;
        switch (iface) {
            .wl_display => switch (opcode) {
                0 => { // sync
                    const cb = try r.newId();
                    try f.send(cb, 0, &.{.{ .uint = 7 }});
                    try f.send(1, 1, &.{.{ .uint = cb }});
                },
                1 => {
                    const reg = try r.newId();
                    f.registry = reg;
                    try f.objects.put(f.gpa, reg, .wl_registry);
                    try f.globals(reg);
                },
                else => return error.BadRequest,
            },
            .wl_registry => {
                const gname = try r.uint();
                const name = try r.string();
                _ = try r.uint();
                const nid = try r.newId();
                const bi = P.Interface.fromName(name) orelse return error.BadBind;
                try f.objects.put(f.gpa, nid, bi);
                switch (bi) {
                    .wl_shm => {
                        try f.send(nid, 0, &.{.{ .uint = 0 }});
                        try f.send(nid, 0, &.{.{ .uint = 1 }});
                    },
                    .wl_seat => {
                        try f.send(nid, 0, &.{.{ .uint = 3 }});
                        try f.send(nid, 1, &.{.{ .string = "seat0" }});
                    },
                    .wl_output => {
                        const output = if (gname == hotplug_global) hotplug_global else gname - first_output_global;
                        try f.output_of.put(f.gpa, nid, output);
                        try f.send(nid, 0, &.{ .{ .int = 0 }, .{ .int = 0 }, .{ .int = 300 }, .{ .int = 200 }, .{ .int = 0 }, .{ .string = "make" }, .{ .string = "model" }, .{ .int = 0 } });
                        try f.send(nid, 1, &.{ .{ .uint = 3 }, .{ .int = @intCast(f.width) }, .{ .int = @intCast(f.height) }, .{ .int = 60000 } });
                        try f.send(nid, 3, &.{.{ .int = 1 }});
                        try f.send(nid, 4, &.{.{ .string = f.outputName(output) }});
                        try f.send(nid, 5, &.{.{ .string = "Fake output" }});
                        try f.send(nid, 2, &.{});
                    },
                    else => {},
                }
            },
            .wl_shm => if (opcode == 0) {
                const nid = try r.newId();
                const size: usize = @intCast(try r.int());
                const pfd = try f.popFd();
                defer sys.close(pfd);
                const ptr = std.c.mmap(null, size, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, pfd, 0);
                if (ptr == std.c.MAP_FAILED) return error.MmapFailed;
                const base: [*]align(std.heap.page_size_min) u8 = @ptrCast(@alignCast(ptr));
                try f.pools.put(f.gpa, nid, base[0..size]);
                try f.objects.put(f.gpa, nid, .wl_shm_pool);
            },
            .wl_shm_pool => switch (opcode) {
                0 => {
                    const nid = try r.newId();
                    const off: usize = @intCast(try r.int());
                    const w: u32 = @intCast(try r.int());
                    const h: u32 = @intCast(try r.int());
                    const stride: u32 = @intCast(try r.int());
                    _ = try r.uint();
                    if (off + @as(usize, stride) * h > f.pools.get(id).?.len) return error.BufferOutOfPool;
                    try f.buffers.put(f.gpa, nid, .{ .pool = id, .offset = off, .w = w, .h = h, .stride = stride });
                    try f.objects.put(f.gpa, nid, .wl_buffer);
                },
                1 => try f.deleteId(id), // pool memory stays mapped for its buffers
                else => {},
            },
            .wl_buffer => if (opcode == 0) {
                _ = f.buffers.remove(id);
                try f.deleteId(id);
            },
            .zwp_linux_dmabuf_v1 => if (opcode == 1) {
                try f.objects.put(f.gpa, try r.newId(), .zwp_linux_buffer_params_v1);
            },
            .zwp_linux_buffer_params_v1 => switch (opcode) {
                0 => try f.deleteId(id),
                1 => { // add: one plane
                    const pfd = try f.popFd();
                    if (try r.uint() != 0) return error.MultiPlane;
                    const off = try r.uint();
                    const stride = try r.uint();
                    f.dmabuf_modifier = @as(u64, try r.uint()) << 32 | try r.uint();
                    f.param_fds[f.nparam_fds] = pfd;
                    try f.param_planes.put(f.gpa, id, .{ @intCast(f.nparam_fds), off, stride });
                    f.nparam_fds += 1;
                },
                3 => { // create_immed
                    const nid = try r.newId();
                    const w: u32 = @intCast(try r.int());
                    const h: u32 = @intCast(try r.int());
                    f.dmabuf_format = try r.uint();
                    const pl = f.param_planes.get(id) orelse return error.Incomplete;
                    const size: usize = pl[1] + @as(usize, pl[2]) * h;
                    const ptr = std.c.mmap(null, size, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, f.param_fds[pl[0]], 0);
                    if (ptr == std.c.MAP_FAILED) return error.MmapFailed;
                    const base: [*]align(std.heap.page_size_min) u8 = @ptrCast(@alignCast(ptr));
                    const key = f.next_dmabuf_pool;
                    f.next_dmabuf_pool += 1;
                    try f.pools.put(f.gpa, key, base[0..size]);
                    try f.buffers.put(f.gpa, nid, .{ .pool = key, .offset = pl[1], .w = w, .h = h, .stride = pl[2], .dmabuf = true });
                    try f.objects.put(f.gpa, nid, .wl_buffer);
                    f.dmabuf_buffers += 1;
                },
                else => return error.BadRequest,
            },
            .ext_output_image_capture_source_manager_v1 => if (opcode == 0) {
                const src = try r.newId();
                try f.objects.put(f.gpa, src, .ext_image_capture_source_v1);
                if (f.output_of.get(try r.object())) |o| try f.output_of.put(f.gpa, src, o);
            },
            .ext_image_copy_capture_manager_v1 => switch (opcode) {
                0 => {
                    f.session = try r.newId();
                    try f.objects.put(f.gpa, f.session, .ext_image_copy_capture_session_v1);
                    if (f.output_of.get(try r.object())) |o| try f.output_of.put(f.gpa, f.session, o);
                    try f.sendConstraints();
                },
                1 => { // create_pointer_cursor_session; its image session is captured as an output is
                    const cs = try r.newId();
                    try f.objects.put(f.gpa, cs, .ext_image_copy_capture_cursor_session_v1);
                    if (f.output_of.get(try r.object())) |o| try f.output_of.put(f.gpa, cs, o);
                },
                else => {},
            },
            .ext_image_copy_capture_cursor_session_v1 => switch (opcode) {
                0 => {
                    if (f.journal) |j| j.add("destroy cursor session {s}", .{f.outputOf(id)});
                    _ = f.output_of.remove(id);
                    try f.deleteId(id);
                },
                1 => {
                    f.session = try r.newId();
                    try f.objects.put(f.gpa, f.session, .ext_image_copy_capture_session_v1);
                    if (f.output_of.get(id)) |o| try f.output_of.put(f.gpa, f.session, o);
                    try f.sendConstraints();
                },
                else => return error.BadRequest,
            },
            .ext_image_copy_capture_session_v1 => switch (opcode) {
                0 => {
                    if (f.journal) |j| j.add("create_frame {s}", .{f.outputOf(id)});
                    if (f.stopped_sessions.contains(id)) _ = f.frames_after_stop.fetchAdd(1, .acq_rel);
                    const nid = try r.newId();
                    try f.objects.put(f.gpa, nid, .ext_image_copy_capture_frame_v1);
                    f.nhints = 0;
                    f.frame_buffer = 0;
                },
                1 => {
                    if (f.journal) |j| j.add("destroy session {s}", .{f.outputOf(id)});
                    _ = f.stopped_sessions.remove(id);
                    _ = f.output_of.remove(id);
                    try f.deleteId(id);
                },
                else => return error.BadRequest,
            },
            .ext_image_capture_source_v1 => if (opcode == 0) {
                _ = f.output_of.remove(id);
                try f.deleteId(id);
            },
            .ext_image_copy_capture_frame_v1 => switch (opcode) {
                0 => try f.deleteId(id),
                1 => f.frame_buffer = try r.object(),
                2 => {
                    const d: Rect = .{ .x = try r.int(), .y = try r.int(), .width = try r.int(), .height = try r.int() };
                    if (d.x < 0 or d.y < 0 or d.width <= 0 or d.height <= 0) return error.InvalidBufferDamage;
                    f.hints[f.nhints] = d;
                    f.nhints += 1;
                },
                3 => try f.extCapture(id),
                else => return error.BadRequest,
            },
            .zwlr_screencopy_manager_v1 => if (opcode == 0) {
                const nid = try r.newId();
                try f.objects.put(f.gpa, nid, .zwlr_screencopy_frame_v1);
                try f.send(nid, 0, &.{ .{ .uint = 1 }, .{ .uint = f.width }, .{ .uint = f.height }, .{ .uint = f.width * 4 } });
                try f.send(nid, 6, &.{}); // buffer_done
            },
            .zwlr_screencopy_frame_v1 => switch (opcode) {
                0, 2 => {
                    const b = f.buffers.get(try r.object()) orelse return error.BadBuffer;
                    const d = f.frameDamage();
                    try f.advance(d);
                    f.copyRect(b, .{ .x = 0, .y = 0, .width = @intCast(f.width), .height = @intCast(f.height) });
                    f.frame_no += 1;
                    try f.send(id, 1, &.{.{ .uint = 0 }}); // flags
                    if (opcode == 2) try f.send(id, 4, &.{ .{ .uint = @intCast(d.x) }, .{ .uint = @intCast(d.y) }, .{ .uint = @intCast(d.width) }, .{ .uint = @intCast(d.height) } });
                    try f.send(id, 2, &.{ .{ .uint = 0 }, .{ .uint = 1 }, .{ .uint = 2 } }); // ready
                },
                1 => try f.deleteId(id),
                else => {},
            },
            .wl_seat => if (opcode == 0) try f.objects.put(f.gpa, try r.newId(), .wl_pointer), // get_pointer
            .wl_pointer => if (opcode == 1) try f.deleteId(id), // release
            .wl_output => if (opcode == 0) { // release
                _ = f.output_of.remove(id);
                try f.deleteId(id);
            },
            .zwp_virtual_keyboard_manager_v1 => if (opcode == 0) {
                _ = try r.object(); // seat
                try f.objects.put(f.gpa, try r.newId(), .zwp_virtual_keyboard_v1);
            },
            .zwp_virtual_keyboard_v1 => switch (opcode) {
                0 => {
                    f.keymap_format = try r.uint();
                    const kfd = try f.popFd();
                    defer sys.close(kfd);
                    const size = try r.uint();
                    if (size > f.keymap.len) return error.KeymapTooBig;
                    f.keymap_len = try sys.pread(kfd, f.keymap[0..size], 0);
                },
                1 => {
                    _ = try r.uint();
                    f.keys[f.nkeys] = .{ try r.uint(), try r.uint() };
                    f.nkeys += 1;
                },
                2 => f.mods = .{ try r.uint(), try r.uint(), try r.uint(), try r.uint() },
                else => {},
            },
            .zwlr_virtual_pointer_manager_v1 => if (opcode == 2) {
                _ = try r.object(); // seat
                f.abs_output = try r.object();
                try f.objects.put(f.gpa, try r.newId(), .zwlr_virtual_pointer_v1);
            },
            .zwlr_virtual_pointer_v1 => switch (opcode) {
                1 => {
                    _ = try r.uint();
                    f.abs = .{ try r.uint(), try r.uint(), try r.uint(), try r.uint() };
                },
                2 => {
                    _ = try r.uint();
                    f.buttons[f.nbuttons] = .{ try r.uint(), try r.uint() };
                    f.nbuttons += 1;
                },
                4 => f.pointer_frames += 1,
                5 => f.axis_source = try r.uint(),
                7 => {
                    _ = try r.uint();
                    _ = try r.uint();
                    _ = try r.fixed();
                    f.discrete = try r.int();
                },
                else => {},
            },
            else => {},
        }
    }

    fn checkHotplug(f: *Fake) !void {
        if (f.stop_session.swap(false, .acq_rel)) {
            var it = f.objects.iterator();
            while (it.next()) |e| if (e.value_ptr.* == .ext_image_copy_capture_session_v1) try f.stopSession(e.key_ptr.*);
            try f.tx.flush();
            // On the socket before the test thread hears of it (waitStopped, then dispatch).
            f.session_stopped.store(true, .release);
        }
        const remove = f.remove_output.swap(0, .acq_rel);
        if (remove != 0) {
            // Hyprland stops the output's capture sessions as it goes, then removes its global.
            var it = f.output_of.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.* == remove - 1 and f.objects.get(e.key_ptr.*) == .ext_image_copy_capture_session_v1) try f.stopSession(e.key_ptr.*);
            }
            try f.send(f.registry, 1, &.{.{ .uint = first_output_global + remove - 1 }});
            try f.tx.flush();
            _ = f.removed.fetchAdd(1, .acq_rel);
        }
        switch (f.hotplug.swap(0, .acq_rel)) {
            1 => try f.send(f.registry, 0, &.{ .{ .uint = hotplug_global }, .{ .string = "wl_output" }, .{ .uint = 4 } }),
            2 => try f.send(f.registry, 1, &.{.{ .uint = hotplug_global }}),
            else => return,
        }
        try f.tx.flush();
    }

    /// From another thread: remove output `k` as Hyprland's `output remove` does, and wait
    /// until it is done.
    pub fn removeOutput(f: *Fake, k: usize) !void {
        const before = f.removed.load(.acquire);
        f.remove_output.store(@intCast(k + 1), .release);
        const t0 = sys.nowMs();
        while (f.removed.load(.acquire) == before) {
            if (sys.nowMs() -% t0 > 2000) return error.TestTimeout;
            std.Thread.yield() catch {};
        }
    }

    fn resize(f: *Fake, w: u32, h: u32) !void {
        f.width = w;
        f.height = h;
        f.gpa.free(f.screen);
        f.screen = try f.gpa.alloc(u32, f.width * f.height);
        @memset(f.screen, 0xff000000);
        f.full_next = true;
        try f.sendConstraints();
    }

    fn extCapture(f: *Fake, frame: u32) !void {
        if (f.resize_at != null and f.resize_at.? == f.frame_no) {
            f.resize_at = null;
            try f.resize(f.resize_to[0], f.resize_to[1]);
        }
        const burst = f.resize_burst.load(.acquire);
        if (burst > 0) {
            f.resize_burst.store(burst - 1, .release);
            if (f.width == 64) try f.resize(40, 30) else try f.resize(64, 48);
            f.failed_sent += 1;
            return f.send(frame, 4, &.{.{ .uint = burst % 2 }}); // failed: buffer_constraints / unknown
        }
        const b = f.buffers.get(f.frame_buffer) orelse return error.NoBuffer;
        try f.used_buffers.put(f.gpa, f.frame_buffer, {});
        if (b.w != f.width or b.h != f.height) {
            f.failed_sent += 1;
            return f.send(frame, 4, &.{.{ .uint = 1 }}); // failed: buffer_constraints
        }
        if (b.dmabuf and f.fail_dmabuf_frames) {
            f.failed_sent += 1;
            return f.send(frame, 4, &.{.{ .uint = f.fail_dmabuf_reason }});
        }
        const d = f.frameDamage();
        try f.advance(d);
        for (f.hints[0..f.nhints]) |h| f.copyRect(b, h);
        f.copyRect(b, d);
        f.frame_no += 1;
        if (f.stop_before_ready) {
            f.stop_before_ready = false;
            try f.stopSession(f.session);
        }
        try f.send(frame, 0, &.{.{ .uint = 0 }}); // transform normal
        try f.send(frame, 1, &.{ .{ .int = d.x }, .{ .int = d.y }, .{ .int = d.width }, .{ .int = d.height } });
        try f.send(frame, 2, &.{ .{ .uint = 0 }, .{ .uint = 5 }, .{ .uint = 6 } }); // presentation_time
        try f.send(frame, 3, &.{}); // ready
    }
};

fn expectFrame(f: *const capture.Frame, snap: []const u32, damage: Rect) !void {
    try testing.expectEqual(f.width * f.height, snap.len);
    for (0..f.height) |y| for (0..f.width) |x| {
        const got = std.mem.readInt(u32, f.data[y * f.stride + x * 4 ..][0..4], .little);
        if (got != snap[y * f.width + x]) {
            std.debug.print("frame {d}: pixel {d},{d} = {x}, want {x}\n", .{ f.seq, x, y, got, snap[y * f.width + x] });
            return error.TestStalePixel;
        }
    };
    try testing.expectEqual(1, f.damage.len);
    try testing.expectEqual(damage, f.damage[0]);
}

pub const Harness = struct {
    fake: *Fake,
    thread: std.Thread,
    client: *Client,

    pub fn start() !Harness {
        return startWith(.{});
    }

    pub fn startWith(cfg: Fake.Config) !Harness {
        const sp = try sys.socketPair();
        const fake = try Fake.init(testing.allocator, sp[1], cfg);
        errdefer fake.deinit();
        const th = try std.Thread.spawn(.{}, Fake.run, .{fake});
        const client = Client.connectFd(testing.allocator, sp[0], .{ .timeout_ms = 2000 }) catch |e| {
            fake.stop.store(true, .release);
            th.join();
            return e;
        };
        return .{ .fake = fake, .thread = th, .client = client };
    }

    pub fn stop(h: *Harness) !void {
        h.client.deinit();
        h.fake.stop.store(true, .release);
        h.thread.join();
        const err = h.fake.err;
        h.fake.deinit();
        if (err) |e| return e;
    }
};

test "client sees globals and outputs from a fake compositor" {
    var h = try Harness.start();
    defer h.stop() catch |e| std.debug.panic("fake compositor: {t}", .{e});
    const c = h.client;
    try testing.expect(c.shm != null and c.seat != null and c.ext_capture != null and c.screencopy != null);
    try testing.expect(c.hasShmFormat(.xrgb8888));
    try testing.expectEqual(3, c.seat_caps);
    const o = c.findOutput("FAKE-1").?;
    try testing.expectEqualStrings("Fake output", o.description());
    try testing.expectEqual(64, o.width);
    try testing.expectEqual(1, o.done_count);
    try testing.expectEqual(3, c.conn.version(c.screencopy.?.id));
}

test "ext capture: double-buffered damage hints and resize against a fake compositor" {
    var h = try Harness.start();
    defer h.stop() catch |e| std.debug.panic("fake compositor: {t}", .{e});
    const fake = h.fake;
    fake.resize_at = 5;
    fake.resize_to = .{ 40, 30 };
    const out = h.client.findOutput("FAKE-1").?;
    const cap = try capture.Capture.init(h.client, out, .{ .backend = .ext });
    defer cap.deinit();

    var held: capture.Frame = undefined;
    for (0..5) |k| {
        const f = try cap.nextFrame(2000);
        try testing.expectEqual(k, f.seq);
        try expectFrame(f, fake.snapshots.items[k], fake.damages.items[k]);
        if (k == 4) held = f.*;
    }
    // Frame 5 hits the resize; the frame still held must stay mapped and intact.
    try cap.requestFrame();
    var spins: usize = 0;
    while (cap.ready_idx == null) : (spins += 1) {
        if (spins > 20) return error.TestTimeout;
        _ = try h.client.dispatchTimeout(500);
    }
    try testing.expectEqual(1, fake.failed_sent);
    try testing.expect(cap.retired != null);
    try expectFrame(&held, fake.snapshots.items[4], fake.damages.items[4]);
    const f5 = cap.takeFrame().?;
    try testing.expect(cap.retired == null);
    try testing.expectEqual(40, f5.width);
    try expectFrame(f5, fake.snapshots.items[5], .{ .x = 0, .y = 0, .width = 40, .height = 30 });
    for (6..9) |k| {
        const f = try cap.nextFrame(2000);
        try expectFrame(f, fake.snapshots.items[k], fake.damages.items[k]);
    }
}

test "wlr screencopy capture against a fake compositor" {
    var h = try Harness.start();
    defer h.stop() catch |e| std.debug.panic("fake compositor: {t}", .{e});
    const out = h.client.findOutput("FAKE-1").?;
    const cap = try capture.Capture.init(h.client, out, .{ .backend = .wlr });
    defer cap.deinit();
    for (0..4) |k| {
        const f = try cap.nextFrame(2000);
        try testing.expectEqual(P.WlShm.Format.xrgb8888, f.format);
        try expectFrame(f, h.fake.snapshots.items[k], h.fake.damages.items[k]);
    }
}

test "virtual keyboard and pointer requests reach the compositor intact" {
    var h = try Harness.start();
    defer h.stop() catch |e| std.debug.panic("fake compositor: {t}", .{e});
    const input = @import("input.zig");
    const out = h.client.findOutput("FAKE-1").?;

    var kbd = try input.VirtualKeyboard.init(h.client);
    defer kbd.deinit();
    try testing.expectError(error.Unsupported, kbd.key(30, true)); // no keymap yet
    try kbd.setKeymap(input.keymap_us);
    try kbd.key(30, true);
    try kbd.key(30, false);
    try kbd.modifiers(1, 0, 2, 0);

    var ptr = try input.VirtualPointer.init(h.client, out);
    defer ptr.deinit();
    try ptr.motionAbsolute(10, 20, 64, 48);
    try ptr.frame();
    try ptr.button(input.BTN_RIGHT, true);
    try ptr.button(input.BTN_RIGHT, false);
    try ptr.frame();
    try ptr.wheel(.vertical_scroll, -240);
    try ptr.frame();
    try h.client.roundtrip(2000);

    const f = h.fake;
    try testing.expectEqual(1, f.keymap_format); // xkb_v1
    try testing.expectEqual(input.keymap_us.len + 1, f.keymap_len); // NUL-terminated
    try testing.expectEqualStrings(input.keymap_us, f.keymap[0..input.keymap_us.len]);
    try testing.expectEqual(0, f.keymap[input.keymap_us.len]);
    try testing.expectEqual(2, f.nkeys);
    try testing.expectEqual([2]u32{ 30, 1 }, f.keys[0]);
    try testing.expectEqual([2]u32{ 30, 0 }, f.keys[1]);
    try testing.expectEqual([4]u32{ 1, 0, 2, 0 }, f.mods);
    try testing.expectEqual(out.proxy.id, f.abs_output);
    try testing.expectEqual([4]u32{ 10, 20, 64, 48 }, f.abs);
    try testing.expectEqual(2, f.nbuttons);
    try testing.expectEqual([2]u32{ input.BTN_RIGHT, 1 }, f.buttons[0]);
    try testing.expectEqual(-2, f.discrete);
    try testing.expectEqual(0, f.axis_source); // wheel
    try testing.expectEqual(3, f.pointer_frames);
}

test "output hotplug: announce and remove" {
    var h = try Harness.start();
    defer h.stop() catch |e| std.debug.panic("fake compositor: {t}", .{e});
    const c = h.client;
    try testing.expect(c.findOutput("FAKE-2") == null);
    h.fake.hotplug.store(1, .release);
    var spins: usize = 0;
    while (c.findOutput("FAKE-2") == null) : (spins += 1) {
        if (spins > 100) return error.TestTimeout;
        _ = try c.dispatchTimeout(20);
    }
    const o2 = c.findOutput("FAKE-2").?;
    try testing.expectEqual(2, c.outputs().len);
    h.fake.hotplug.store(2, .release);
    spins = 0;
    while (!o2.removed) : (spins += 1) {
        if (spins > 100) return error.TestTimeout;
        _ = try c.dispatchTimeout(20);
    }
    try testing.expect(c.findOutput("FAKE-2") == null);
    try testing.expect(c.findOutput("FAKE-1") != null);
    try c.roundtrip(2000); // release reached the compositor without error
}

/// memfd "dmabufs": one plane, stride width*4, the first modifier offered.
const FakeAlloc = struct {
    fail: bool = false,
    allocated: usize = 0,
    freed: usize = 0,
    modifiers_seen: [8]u64 = undefined,
    nmods: usize = 0,

    fn alloc(ctx: *anyopaque, device: u64, w: u32, h: u32, format: u32, mods: []const u64) dmabuf.AllocError!dmabuf.Bo {
        const a: *FakeAlloc = @ptrCast(@alignCast(ctx));
        if (a.fail) return error.AllocFailed;
        if (device != 0xe280) return error.NoDevice;
        a.nmods = @min(mods.len, a.modifiers_seen.len);
        @memcpy(a.modifiers_seen[0..a.nmods], mods[0..a.nmods]);
        var mem = sys.SharedMemory.create("fake-dmabuf", @as(usize, w) * 4 * h) catch return error.AllocFailed;
        const fd = sys.dup(mem.fd) orelse return error.AllocFailed;
        mem.destroy();
        a.allocated += 1;
        var bo: dmabuf.Bo = .{ .width = w, .height = h, .format = format, .modifier = mods[0], .nplanes = 1 };
        bo.planes[0] = .{ .fd = fd, .offset = 0, .stride = w * 4 };
        return bo;
    }

    fn free(ctx: *anyopaque, bo: *dmabuf.Bo) void {
        const a: *FakeAlloc = @ptrCast(@alignCast(ctx));
        for (bo.planes[0..bo.nplanes]) |p| sys.close(p.fd);
        a.freed += 1;
    }

    fn why(ctx: *anyopaque) []const u8 {
        const a: *FakeAlloc = @ptrCast(@alignCast(ctx));
        return if (a.fail) "the fake allocator refuses" else "";
    }

    fn interface(a: *FakeAlloc) dmabuf.Allocator {
        return .{ .ctx = a, .allocFn = alloc, .freeFn = free, .whyFn = why };
    }
};

/// A dmabuf frame read back through its fd (the fake renders into the memfd).
fn expectDmabufFrame(f: *const capture.Frame, snap: []const u32, damage: Rect) !void {
    try testing.expectEqual(0, f.data.len);
    const bo = f.dmabuf orelse return error.TestNotDmabuf;
    const pixels = try testing.allocator.alloc(u8, @as(usize, f.stride) * f.height);
    defer testing.allocator.free(pixels);
    try testing.expectEqual(pixels.len, try sys.pread(bo.planes[0].fd, pixels, bo.planes[0].offset));
    var copy = f.*;
    copy.data = pixels;
    try expectFrame(&copy, snap, damage);
}

test "ext capture into a dmabuf ring: LINEAR chosen, buffers used round robin" {
    var h = try Harness.start();
    defer h.stop() catch |e| std.debug.panic("fake compositor: {t}", .{e});
    const fake = h.fake;
    fake.offer_dmabuf = true;
    var fa: FakeAlloc = .{};
    const ai = fa.interface();
    const out = h.client.findOutput("FAKE-1").?;
    const cap = try capture.Capture.init(h.client, out, .{ .backend = .ext, .buffers = .dmabuf, .dmabuf_allocator = &ai, .dmabuf_count = 3 });
    for (0..7) |k| {
        const f = try cap.nextFrame(2000);
        try expectDmabufFrame(f, fake.snapshots.items[k], fake.damages.items[k]);
        try testing.expectEqual(P.WlShm.Format.xrgb8888, f.format);
        try testing.expect(f.ready_ns >= f.latency_ns);
    }
    try testing.expect(cap.usingDmabuf());
    try testing.expectEqual(3, fa.allocated);
    try testing.expectEqualSlices(u64, &.{dmabuf.mod_linear}, fa.modifiers_seen[0..fa.nmods]);
    try h.client.roundtrip(2000);
    try testing.expectEqual(dmabuf.mod_linear, fake.dmabuf_modifier);
    try testing.expectEqual(dmabuf.format_xrgb8888, fake.dmabuf_format);
    try testing.expectEqual(3, fake.dmabuf_buffers);
    try testing.expectEqual(3, fake.used_buffers.count());
    cap.deinit();
    try testing.expectEqual(3, fa.freed);
}

test "ext capture falls back to shm: no dmabuf offered, or allocation fails" {
    for ([_]bool{ false, true }) |offer| {
        var h = try Harness.start();
        defer h.stop() catch |e| std.debug.panic("fake compositor: {t}", .{e});
        h.fake.offer_dmabuf = offer;
        var fa: FakeAlloc = .{ .fail = true };
        const ai = fa.interface();
        const out = h.client.findOutput("FAKE-1").?;
        const cap = try capture.Capture.init(h.client, out, .{ .backend = .ext, .buffers = .dmabuf, .dmabuf_allocator = &ai });
        defer cap.deinit();
        for (0..3) |k| {
            const f = try cap.nextFrame(2000);
            try testing.expect(f.dmabuf == null);
            try expectFrame(f, h.fake.snapshots.items[k], h.fake.damages.items[k]);
        }
        try testing.expect(!cap.usingDmabuf());
        try testing.expect(cap.dmabuf_off);
        try testing.expectEqualStrings("the fake allocator refuses", ai.why().?);
        try testing.expectEqual(0, h.fake.dmabuf_buffers);
    }
}

test "ext capture falls back to shm when the compositor fails every frame into our dmabufs" {
    // Whatever the reason given: buffer_constraints too, while the buffers fit the constraints.
    for ([_]u32{ 0, 1 }) |reason| {
        var h = try Harness.start();
        defer h.stop() catch |e| std.debug.panic("fake compositor: {t}", .{e});
        h.fake.offer_dmabuf = true;
        h.fake.fail_dmabuf_frames = true;
        h.fake.fail_dmabuf_reason = reason;
        var fa: FakeAlloc = .{};
        const ai = fa.interface();
        const out = h.client.findOutput("FAKE-1").?;
        const cap = try capture.Capture.init(h.client, out, .{ .backend = .ext, .buffers = .dmabuf, .dmabuf_allocator = &ai, .dmabuf_count = 3 });
        defer cap.deinit();
        const f = try cap.nextFrame(2000);
        try testing.expect(f.dmabuf == null);
        try expectFrame(f, h.fake.snapshots.items[0], h.fake.damages.items[0]);
        try testing.expect(!cap.usingDmabuf());
        try testing.expect(h.fake.failed_sent > 0 and h.fake.failed_sent < 10);
    }
}

test "ext capture: a burst of output mode changes keeps the capture, on dmabufs or shm" {
    // Mode changes back to back fail dmabuf frames with buffer_constraints; that is not the
    // compositor refusing dmabufs.
    for ([_]capture.BufferKind{ .dmabuf, .shm }) |kind| {
        var h = try Harness.start();
        defer h.stop() catch |e| std.debug.panic("fake compositor: {t}", .{e});
        const fake = h.fake;
        fake.offer_dmabuf = true;
        var fa: FakeAlloc = .{};
        const ai = fa.interface();
        const out = h.client.findOutput("FAKE-1").?;
        const cap = try capture.Capture.init(h.client, out, .{ .backend = .ext, .buffers = kind, .dmabuf_allocator = &ai, .dmabuf_count = 3 });
        defer cap.deinit();
        for (0..2) |_| _ = try cap.nextFrame(2000);
        // More changes than the dmabuf fallback (3) and the give-up (10) count, one per frame.
        fake.resize_burst.store(12, .release);
        const f = try cap.nextFrame(2000);
        try testing.expectEqual(12, fake.failed_sent);
        try testing.expectEqual(kind == .dmabuf, cap.usingDmabuf());
        try testing.expectEqual(64, f.width);
        const full: Rect = .{ .x = 0, .y = 0, .width = 64, .height = 48 };
        if (kind == .dmabuf) try expectDmabufFrame(f, fake.snapshots.items[2], full) else try expectFrame(f, fake.snapshots.items[2], full);
    }
}

test "ext capture: dmabufs the compositor cannot fill still go to shm after a burst of mode changes" {
    var h = try Harness.start();
    defer h.stop() catch |e| std.debug.panic("fake compositor: {t}", .{e});
    const fake = h.fake;
    fake.offer_dmabuf = true;
    fake.fail_dmabuf_frames = true;
    fake.resize_burst.store(5, .release);
    var fa: FakeAlloc = .{};
    const ai = fa.interface();
    const out = h.client.findOutput("FAKE-1").?;
    const cap = try capture.Capture.init(h.client, out, .{ .backend = .ext, .buffers = .dmabuf, .dmabuf_allocator = &ai, .dmabuf_count = 3 });
    defer cap.deinit();
    const f = try cap.nextFrame(2000);
    // The 5 resizes are not counted; 3 failures at a steady size are.
    try testing.expectEqual(5 + 3, fake.failed_sent);
    try testing.expect(!cap.usingDmabuf());
    try expectFrame(f, fake.snapshots.items[0], fake.damages.items[0]);
}

/// Waits (without reading the client's socket) until the fake stopped a session.
fn waitStopped(fake: *Fake) !void {
    const t0 = sys.nowMs();
    while (!fake.session_stopped.load(.acquire)) {
        if (sys.nowMs() -% t0 > 2000) return error.TestTimeout;
        std.Thread.yield() catch {};
    }
}

test "ext capture: a stopped session gets no frame request, not even one queued before the stop" {
    var h = try Harness.start();
    defer h.stop() catch |e| std.debug.panic("fake compositor: {t}", .{e});
    const fake = h.fake;
    const out = h.client.findOutput("FAKE-1").?;
    const cap = try capture.Capture.init(h.client, out, .{ .backend = .ext });
    defer cap.deinit();
    _ = try cap.nextFrame(2000);
    try cap.requestFrame(); // queued, as a consumer leaves it until the next dispatch
    fake.stop_session.store(true, .release); // the output removed meanwhile
    try waitStopped(fake);
    _ = try h.client.dispatch(); // sees the stop before it sends the frame
    try testing.expectEqual(capture.State.stopped, cap.state);
    try testing.expectError(error.Stopped, cap.requestFrame());
    try h.client.roundtrip(2000);
    try testing.expectEqual(0, fake.frames_after_stop.load(.acquire));
}

test "ext capture: a frame in flight at the stop completes, and the session stays stopped" {
    var h = try Harness.start();
    defer h.stop() catch |e| std.debug.panic("fake compositor: {t}", .{e});
    const fake = h.fake;
    const out = h.client.findOutput("FAKE-1").?;
    const cap = try capture.Capture.init(h.client, out, .{ .backend = .ext });
    defer cap.deinit();
    _ = try cap.nextFrame(2000);
    fake.stop_before_ready = true;
    const f = try cap.nextFrame(2000);
    try expectFrame(f, fake.snapshots.items[1], fake.damages.items[1]);
    try testing.expectEqual(capture.State.stopped, cap.state);
    try testing.expectError(error.Stopped, cap.requestFrame());
    try h.client.roundtrip(2000);
    try testing.expectEqual(0, fake.frames_after_stop.load(.acquire));
}

test "ext capture: torn down after its output was removed, a capture sends no frame after the stop" {
    // The frame requested in the previous pass is still queued when the output goes: flushed
    // after the stop, it crashed Hyprland 0.56.2.
    var h = try Harness.start();
    defer h.stop() catch |e| std.debug.panic("fake compositor: {t}", .{e});
    const fake = h.fake;
    const out = h.client.findOutput("FAKE-1").?;
    const cap = try capture.Capture.init(h.client, out, .{ .backend = .ext });
    _ = try cap.nextFrame(2000);
    try cap.requestFrame(); // as pumpDesktop does after sending a frame; not flushed yet
    fake.stop_session.store(true, .release); // `output remove`
    try waitStopped(fake); // not read: relayoutTo does not dispatch in between
    cap.deinit();
    try h.client.roundtrip(2000);
    try testing.expectEqual(0, fake.frames_after_stop.load(.acquire));
}
