//! Root side of the input fence: grabs the devices fence.zig selects (EVIOCGRAB), follows hot-plug
//! and reports desk activity. Grabs and releases happen with no key held, so Hyprland never sees half a press.

const std = @import("std");
const c = @import("c");
const fence = @import("fence.zig");

const log = std.log.scoped(.fence);

/// evdev nodes go up to event1023 (INPUT_MAX_CHAR_DEVICES).
pub const max_devices = 1024;

/// _IOC(_IOC_READ, 'E', 0x18, len): current key state bitmap.
fn eviocgkey(len: u32) u32 {
    return 0x80000000 | (len << 16) | (@as(u32, 'E') << 8) | 0x18;
}

pub const Grabbed = struct {
    fd: c_int,
    index: u16,
    /// A press here counts as someone at the desk (fence.signalsPresence).
    presence: bool,
    held: u16 = 0,
};

/// Upper bound on how long `unfence` waits for held keys to be released.
pub const drain_ms: i64 = 5000;

/// A touchscreen and a pen per output.
pub const max_exempt = 32;

pub const Fence = struct {
    devices: [max_devices]?Grabbed = @splat(null),
    /// Devices not grabbed yet because a key was down.
    pending: std.StaticBitSet(max_devices) = .empty,
    inotify_fd: c_int = -1,
    active: bool = false,
    drain_until_ms: ?i64 = null,
    exempt_inputs: [max_exempt]u32 = undefined,
    exempt_len: usize = 0,
    pressed_on: ?u16 = null,

    /// Never grab input device N (a helper uinput device; matched by number, not name).
    pub fn exempt(f: *Fence, input: u32) error{NoSpaceLeft}!void {
        if (f.isExempt(input)) return;
        if (f.exempt_len == f.exempt_inputs.len) return error.NoSpaceLeft;
        f.exempt_inputs[f.exempt_len] = input;
        f.exempt_len += 1;
    }

    pub fn unexempt(f: *Fence, input: u32) void {
        for (f.exempt_inputs[0..f.exempt_len], 0..) |n, i| {
            if (n != input) continue;
            f.exempt_inputs[i] = f.exempt_inputs[f.exempt_len - 1];
            f.exempt_len -= 1;
            return;
        }
    }

    pub fn isExempt(f: *const Fence, input: u32) bool {
        return std.mem.indexOfScalar(u32, f.exempt_inputs[0..f.exempt_len], input) != null;
    }

    pub fn engage(f: *Fence) void {
        if (f.active) return;
        f.active = true;
        f.drain_until_ms = null; // devices still draining stay grabbed
        f.inotify_fd = c.inotify_init1(c.IN_NONBLOCK | c.IN_CLOEXEC);
        if (f.inotify_fd >= 0) _ = c.inotify_add_watch(f.inotify_fd, "/dev/input", c.IN_CREATE | c.IN_ATTRIB);
        f.scan();
    }

    fn scan(f: *Fence) void {
        const dir = c.open("/dev/input", c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
        if (dir < 0) return;
        defer _ = c.close(dir);
        var buf: [4096]u8 align(@alignOf(std.os.linux.dirent64)) = undefined;
        while (true) {
            const rc = std.os.linux.getdents64(dir, &buf, buf.len);
            if (std.os.linux.errno(rc) != .SUCCESS or rc == 0) return;
            var off: usize = 0;
            while (off < rc) {
                const d: *const std.os.linux.dirent64 = @ptrCast(@alignCast(&buf[off]));
                off += d.reclen;
                const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&d.name)), 0);
                if (eventIndex(name)) |i| {
                    if (f.devices[i] == null) f.consider(i);
                }
            }
        }
    }

    pub fn release(f: *Fence) void {
        const was_active = f.active;
        for (&f.devices) |*d| {
            if (d.*) |g| {
                _ = c.ioctl(g.fd, fence.EVIOCGRAB, @as(c_int, 0));
                _ = c.close(g.fd);
                d.* = null;
            }
        }
        f.pending = .empty;
        if (f.inotify_fd >= 0) _ = c.close(f.inotify_fd);
        f.inotify_fd = -1;
        f.active = false;
        f.drain_until_ms = null;
        if (was_active) log.info("fence released", .{});
    }

    /// Devices with a key held stay grabbed, input discarded, until idle or `drain_ms` passes.
    pub fn unfence(f: *Fence, now_ms: i64) void {
        if (!f.active) return;
        _ = f.drainActivity(); // the latest presses and releases count
        f.pending = .empty;
        if (f.inotify_fd >= 0) _ = c.close(f.inotify_fd);
        f.inotify_fd = -1;
        f.active = false;
        var kept: usize = 0;
        for (&f.devices) |*d| {
            const g = d.* orelse continue;
            if (keysHeld(g)) {
                kept += 1;
                continue;
            }
            ungrab(d);
        }
        if (kept == 0) {
            log.info("fence released", .{});
            return;
        }
        f.drain_until_ms = now_ms + drain_ms;
        log.info("fence released; {d} device(s) once their held keys are up", .{kept});
    }

    pub fn draining(f: *const Fence) bool {
        return f.drain_until_ms != null;
    }

    /// Call every poll tick while draining.
    pub fn tickDrain(f: *Fence, now_ms: i64) void {
        const until = f.drain_until_ms orelse return;
        _ = f.drainActivity();
        var left: usize = 0;
        for (&f.devices) |*d| {
            const g = d.* orelse continue;
            if (keysHeld(g) and now_ms < until) {
                left += 1;
                continue;
            }
            if (keysHeld(g)) log.warn("event{d}: a key is still held; releasing anyway", .{g.index});
            ungrab(d);
        }
        if (left == 0) {
            f.drain_until_ms = null;
            log.info("held keys released: every device is back", .{});
        }
    }

    fn consider(f: *Fence, i: u16) void {
        if (f.devices[i] != null) return;
        if (f.exempt_len > 0) if (inputOfEvent(i)) |n| if (f.isExempt(n)) return;
        const caps = capsOfIndex(i) orelse return;
        if (!fence.shouldFence(&caps)) return;
        var path_buf: [64]u8 = undefined;
        const path = std.mem.printSentinel(&path_buf, "/dev/input/event{d}", .{i}, 0) catch return;
        const fd = c.open(path.ptr, c.O_RDONLY | c.O_NONBLOCK | c.O_CLOEXEC);
        if (fd < 0) return;
        if (anyKeyDown(fd)) {
            _ = c.close(fd);
            f.pending.set(i);
            return;
        }
        if (!f.active) {
            _ = c.close(fd);
            return;
        }
        if (c.ioctl(fd, fence.EVIOCGRAB, @as(c_int, 1)) != 0) {
            log.warn("EVIOCGRAB failed for {s}", .{path});
            _ = c.close(fd);
            return;
        }
        f.pending.unset(i);
        const presence = fence.signalsPresence(&caps);
        f.devices[i] = .{ .fd = fd, .index = i, .presence = presence };
        log.info("grabbed {s}{s}", .{ path, if (presence) "" else " (its presses are no one at the desk)" });
    }

    /// Call on every poll tick and inotify event.
    pub fn tick(f: *Fence) void {
        if (!f.active) return;
        if (f.inotify_fd >= 0) {
            var buf: [4096]u8 align(@alignOf(c.struct_inotify_event)) = undefined;
            while (c.read(f.inotify_fd, &buf, buf.len) > 0) {} // drain; rescan below
        }
        f.scan();
    }

    /// Discards grabbed input; true if a presence device saw a key or button press.
    pub fn drainActivity(f: *Fence) bool {
        var active = false;
        for (&f.devices) |*dev| {
            const g = if (dev.*) |*gr| gr else continue;
            var evs: [64]c.struct_input_event = undefined;
            while (true) {
                const n = c.read(g.fd, &evs, @sizeOf(@TypeOf(evs)));
                if (n <= 0) break;
                const count: usize = @as(usize, @intCast(n)) / @sizeOf(c.struct_input_event);
                for (evs[0..count]) |e| {
                    if (e.type != fence.EV_KEY) continue;
                    switch (e.value) {
                        1 => {
                            if (g.presence) {
                                active = true;
                                f.pressed_on = g.index;
                            }
                            g.held +|= 1;
                        },
                        0 => g.held -|= 1,
                        else => {}, // autorepeat
                    }
                }
            }
        }
        return active;
    }
};

fn eventIndex(name: []const u8) ?u16 {
    if (!std.mem.startsWith(u8, name, "event")) return null;
    const digits = name["event".len..];
    if (digits.len == 0 or digits.len > 4 or digits[0] == '+') return null;
    const i = std.fmt.parseInt(u16, digits, 10) catch return null;
    return if (i < max_devices) i else null;
}

/// A press read since the grab and not released, or a key down per EVIOCGKEY.
fn keysHeld(g: Grabbed) bool {
    return g.held > 0 or anyKeyDown(g.fd);
}

fn ungrab(d: *?Grabbed) void {
    const g = d.* orelse return;
    _ = c.ioctl(g.fd, fence.EVIOCGRAB, @as(c_int, 0));
    _ = c.close(g.fd);
    d.* = null;
}

/// Read from the /sys/class/input/event<i>/device link.
fn inputOfEvent(i: u16) ?u32 {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrintSentinel(&path_buf, "/sys/class/input/event{d}/device", .{i}, 0) catch return null;
    var link: [256]u8 = undefined;
    const n = c.readlink(path.ptr, &link, link.len);
    if (n <= 0 or n >= link.len) return null;
    return fence.inputNumber(link[0..@intCast(n)]);
}

fn anyKeyDown(fd: c_int) bool {
    var bits: [96]u8 = @splat(0); // 768 keys
    if (c.ioctl(fd, eviocgkey(bits.len), &bits) < 0) return false;
    for (bits) |b| if (b != 0) return true;
    return false;
}

fn capsOfIndex(i: u16) ?fence.Caps {
    var arena_buf: [16384]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    const a = fba.allocator();
    const base = std.fmt.allocPrint(a, "/sys/class/input/event{d}/device/capabilities", .{i}) catch return null;
    const ev = readSysfs(a, base, "ev") orelse return null;
    const key = readSysfs(a, base, "key") orelse return null;
    const rel = readSysfs(a, base, "rel") orelse return null;
    const abs = readSysfs(a, base, "abs") orelse return null;
    return fence.capsFromSysfs(ev, key, rel, abs) catch null;
}

fn readSysfs(a: std.mem.Allocator, base: []const u8, leaf: []const u8) ?[]const u8 {
    const path = std.fmt.allocPrintSentinel(a, "{s}/{s}", .{ base, leaf }, 0) catch return null;
    const fd = c.open(path.ptr, c.O_RDONLY | c.O_CLOEXEC);
    if (fd < 0) return null;
    defer _ = c.close(fd);
    const buf = a.alloc(u8, 1024) catch return null;
    const n = c.read(fd, buf.ptr, buf.len);
    if (n <= 0) return null;
    return buf[0..@intCast(n)];
}

test "EVIOCGKEY encoding" {
    // _IOC(_IOC_READ, 'E', 0x18, 96)
    try std.testing.expectEqual(@as(u32, 0x80604518), eviocgkey(96));
}

test "event node names" {
    try std.testing.expectEqual(@as(?u16, 0), eventIndex("event0"));
    try std.testing.expectEqual(@as(?u16, 256), eventIndex("event256"));
    try std.testing.expectEqual(@as(?u16, 1023), eventIndex("event1023"));
    for ([_][]const u8{ "event1024", "event", "mouse0", "event+1", "event-1", "by-id" }) |n|
        try std.testing.expectEqual(@as(?u16, null), eventIndex(n));
}

test "exempt inputs: added once, removed, bounded" {
    var f = Fence{};
    try f.exempt(42);
    try f.exempt(42);
    try std.testing.expectEqual(@as(usize, 1), f.exempt_len);
    try std.testing.expect(f.isExempt(42) and !f.isExempt(4));
    f.unexempt(42);
    try std.testing.expect(!f.isExempt(42));
    for (0..max_exempt) |i| try f.exempt(@intCast(i));
    try std.testing.expectError(error.NoSpaceLeft, f.exempt(1000));
    f.unexempt(7);
    try f.exempt(1000);
}

test "fence methods compile" {
    std.testing.refAllDecls(Fence);
}
