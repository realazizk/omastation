//! Client + Capture tests against an in-process fake compositor on a socketpair. For
//! ext-image-copy-capture it copies only the client's damage hints plus its own damage,
//! so wrong double-buffer bookkeeping shows as stale pixels.

const std = @import("std");
const wire = @import("wire.zig");
const sys = @import("sys.zig");
const Client = @import("client.zig").Client;
const capture = @import("capture.zig");
const P = wire.proto;
const Rect = capture.Rect;

const testing = std.testing;

const Buf = struct { pool: u32, offset: usize, w: u32, h: u32, stride: u32 };
const PoolMem = []align(std.heap.page_size_min) u8;

const Fake = struct {
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
    failed_sent: u32 = 0,
    stop: std.atomic.Value(bool) = .init(false),
    err: ?anyerror = null,
    registry: u32 = 0,
    /// Set by the test thread: announce (1) or remove (2) output FAKE-2.
    hotplug: std.atomic.Value(u8) = .init(0),

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

    fn init(gpa: std.mem.Allocator, fd: sys.Fd) !*Fake {
        const f = try gpa.create(Fake);
        f.* = .{ .gpa = gpa, .fd = fd, .tx = try wire.Connection.initFd(gpa, fd) };
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
        f.buffers.deinit(f.gpa);
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
            .{ "wl_output", 4 },
            .{ "ext_image_copy_capture_manager_v1", 1 },
            .{ "ext_output_image_capture_source_manager_v1", 1 },
            .{ "zwlr_screencopy_manager_v1", 3 },
            .{ "some_unknown_global_v9", 3 },
            .{ "zwp_virtual_keyboard_manager_v1", 1 },
            .{ "zwlr_virtual_pointer_manager_v1", 2 },
        };
        for (list, 1..) |g, name| try f.send(reg, 0, &.{ .{ .uint = @intCast(name) }, .{ .string = g[0] }, .{ .uint = g[1] } });
    }

    fn sendConstraints(f: *Fake) !void {
        try f.send(f.session, 0, &.{ .{ .uint = f.width }, .{ .uint = f.height } });
        try f.send(f.session, 1, &.{.{ .uint = 0 }}); // argb8888
        try f.send(f.session, 1, &.{.{ .uint = 1 }}); // xrgb8888
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
                        try f.send(nid, 0, &.{ .{ .int = 0 }, .{ .int = 0 }, .{ .int = 300 }, .{ .int = 200 }, .{ .int = 0 }, .{ .string = "make" }, .{ .string = "model" }, .{ .int = 0 } });
                        try f.send(nid, 1, &.{ .{ .uint = 3 }, .{ .int = @intCast(f.width) }, .{ .int = @intCast(f.height) }, .{ .int = 60000 } });
                        try f.send(nid, 3, &.{.{ .int = 1 }});
                        try f.send(nid, 4, &.{.{ .string = if (gname == 99) "FAKE-2" else "FAKE-1" }});
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
            .ext_output_image_capture_source_manager_v1 => if (opcode == 0) {
                try f.objects.put(f.gpa, try r.newId(), .ext_image_capture_source_v1);
            },
            .ext_image_copy_capture_manager_v1 => if (opcode == 0) {
                f.session = try r.newId();
                try f.objects.put(f.gpa, f.session, .ext_image_copy_capture_session_v1);
                try f.sendConstraints();
            },
            .ext_image_copy_capture_session_v1 => if (opcode == 0) {
                const nid = try r.newId();
                try f.objects.put(f.gpa, nid, .ext_image_copy_capture_frame_v1);
                f.nhints = 0;
                f.frame_buffer = 0;
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
            .wl_output => if (opcode == 0) try f.deleteId(id), // release
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
        switch (f.hotplug.swap(0, .acq_rel)) {
            1 => try f.send(f.registry, 0, &.{ .{ .uint = 99 }, .{ .string = "wl_output" }, .{ .uint = 4 } }),
            2 => try f.send(f.registry, 1, &.{.{ .uint = 99 }}),
            else => return,
        }
        try f.tx.flush();
    }

    fn extCapture(f: *Fake, frame: u32) !void {
        if (f.resize_at != null and f.resize_at.? == f.frame_no) {
            f.resize_at = null;
            f.width = f.resize_to[0];
            f.height = f.resize_to[1];
            f.gpa.free(f.screen);
            f.screen = try f.gpa.alloc(u32, f.width * f.height);
            @memset(f.screen, 0xff000000);
            f.full_next = true;
            try f.sendConstraints();
        }
        const b = f.buffers.get(f.frame_buffer) orelse return error.NoBuffer;
        if (b.w != f.width or b.h != f.height) {
            f.failed_sent += 1;
            return f.send(frame, 4, &.{.{ .uint = 1 }}); // failed: buffer_constraints
        }
        const d = f.frameDamage();
        try f.advance(d);
        for (f.hints[0..f.nhints]) |h| f.copyRect(b, h);
        f.copyRect(b, d);
        f.frame_no += 1;
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

const Harness = struct {
    fake: *Fake,
    thread: std.Thread,
    client: *Client,

    fn start() !Harness {
        const sp = try sys.socketPair();
        const fake = try Fake.init(testing.allocator, sp[1]);
        errdefer fake.deinit();
        const th = try std.Thread.spawn(.{}, Fake.run, .{fake});
        const client = Client.connectFd(testing.allocator, sp[0], .{ .timeout_ms = 2000 }) catch |e| {
            fake.stop.store(true, .release);
            th.join();
            return e;
        };
        return .{ .fake = fake, .thread = th, .client = client };
    }

    fn stop(h: *Harness) !void {
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
