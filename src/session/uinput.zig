//! uinput touchscreens and pen tablets for remote touch and pen (MS-RDPEI), one of each per
//! RDP output since Hyprland maps a touch or tablet device onto a single monitor.
//! Touch uses multi-touch protocol B with ABS_X/ABS_Y following the oldest contact.

const std = @import("std");
const c = @import("c");
const fence = @import("fence.zig");

pub const Error = error{
    /// Slot, id or coordinates out of range, or a slot or tracking id twice.
    InvalidFrame,
    NoSpaceLeft,
    DeviceFailed,
    WriteFailed,
};

// linux/input-event-codes.h

pub const EV_SYN: u16 = c.EV_SYN;
pub const EV_KEY: u16 = c.EV_KEY;
pub const EV_ABS: u16 = c.EV_ABS;
pub const SYN_REPORT: u16 = c.SYN_REPORT;
pub const BTN_TOOL_PEN: u16 = c.BTN_TOOL_PEN;
pub const BTN_TOOL_RUBBER: u16 = c.BTN_TOOL_RUBBER;
pub const BTN_TOUCH: u16 = c.BTN_TOUCH;
pub const BTN_STYLUS: u16 = c.BTN_STYLUS;
pub const ABS_X: u16 = c.ABS_X;
pub const ABS_Y: u16 = c.ABS_Y;
pub const ABS_PRESSURE: u16 = c.ABS_PRESSURE;
pub const ABS_TILT_X: u16 = c.ABS_TILT_X;
pub const ABS_TILT_Y: u16 = c.ABS_TILT_Y;
pub const ABS_MT_SLOT: u16 = c.ABS_MT_SLOT;
pub const ABS_MT_POSITION_X: u16 = c.ABS_MT_POSITION_X;
pub const ABS_MT_POSITION_Y: u16 = c.ABS_MT_POSITION_Y;
pub const ABS_MT_TRACKING_ID: u16 = c.ABS_MT_TRACKING_ID;
pub const INPUT_PROP_DIRECT: u16 = c.INPUT_PROP_DIRECT;
pub const BUS_VIRTUAL: u16 = c.BUS_VIRTUAL;

/// One input event as written to uinput (the kernel stamps the time).
pub const Event = struct {
    type: u16,
    code: u16,
    value: i32,
};

pub const Kind = enum { touch, pen };

/// One touchscreen and one pen per output: RDP-1..RDP-16 (multimon.max_monitors).
pub const max_devices = 16;
pub const max_slots = 16;
/// Axes up to the largest RDP desktop (MS-RDPBCGR 2.2.1.3.6: 32766).
pub const max_axis: u32 = 32766;
pub const max_resolution: u32 = 1000;

/// Axes span 0..width-1 and 0..height-1 at `resolution` units per mm.
pub const Geometry = struct {
    width: u32,
    height: u32,
    resolution: u32,
};

pub fn validGeometry(g: Geometry) bool {
    return g.width >= 1 and g.width <= max_axis and g.height >= 1 and g.height <= max_axis and
        g.resolution >= 1 and g.resolution <= max_resolution;
}

/// "omastation-touch-N" / "omastation-pen-N": the uinput and Hyprland name for the device of RDP-N.
pub fn deviceName(buf: []u8, kind: Kind, index: usize) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buf, "omastation-{t}-{d}", .{ kind, index + 1 });
}

/// A contact reports at least pen_contact_floor (10%), above libinput's tip threshold.
pub const pen_pressure_max: i32 = 4095;
pub const pen_contact_floor: i32 = 410;
/// Tilt in degrees (MS-RDPEI 2.2.3.7.1.1); resolution in units per radian.
pub const pen_tilt_max: i32 = 90;
pub const pen_tilt_resolution: i32 = 57;
/// MS-RDPEI pressure range (2.2.3.7.1.1).
pub const rdpei_pressure_max: u16 = 1024;

pub const vendor: u16 = 0x6870; // not a real vendor, so no libwacom match
pub const product_touch: u16 = 0x0001;
pub const product_pen: u16 = 0x0002;

pub const AbsAxis = struct {
    code: u16,
    min: i32,
    max: i32,
    resolution: i32 = 0,
};

/// Everything UI_DEV_SETUP, UI_SET_*BIT and UI_ABS_SETUP get.
pub const Spec = struct {
    kind: Kind,
    name_buf: [24]u8 = undefined,
    name_len: usize = 0,
    keys: []const u16,
    abs_buf: [8]AbsAxis = undefined,
    abs_len: usize = 0,
    props: []const u16,
    bustype: u16 = BUS_VIRTUAL,
    vendor: u16 = vendor,
    product: u16,
    version: u16 = 1,

    pub fn name(s: *const Spec) []const u8 {
        return s.name_buf[0..s.name_len];
    }

    pub fn abs(s: *const Spec) []const AbsAxis {
        return s.abs_buf[0..s.abs_len];
    }

    fn addAbs(s: *Spec, a: AbsAxis) void {
        s.abs_buf[s.abs_len] = a;
        s.abs_len += 1;
    }
};

const touch_keys = [_]u16{BTN_TOUCH};
const pen_keys = [_]u16{ BTN_TOOL_PEN, BTN_TOOL_RUBBER, BTN_TOUCH, BTN_STYLUS };
const direct = [_]u16{INPUT_PROP_DIRECT};

fn checkIndex(index: usize, g: Geometry) error{InvalidFrame}!void {
    if (index >= max_devices or !validGeometry(g)) return error.InvalidFrame;
}

pub fn touchSpec(index: usize, g: Geometry) error{InvalidFrame}!Spec {
    try checkIndex(index, g);
    var s: Spec = .{ .kind = .touch, .keys = &touch_keys, .props = &direct, .product = product_touch };
    s.name_len = (deviceName(&s.name_buf, .touch, index) catch unreachable).len;
    const w: i32 = @intCast(g.width - 1);
    const h: i32 = @intCast(g.height - 1);
    const r: i32 = @intCast(g.resolution);
    s.addAbs(.{ .code = ABS_X, .min = 0, .max = w, .resolution = r });
    s.addAbs(.{ .code = ABS_Y, .min = 0, .max = h, .resolution = r });
    s.addAbs(.{ .code = ABS_MT_SLOT, .min = 0, .max = max_slots - 1 });
    s.addAbs(.{ .code = ABS_MT_TRACKING_ID, .min = 0, .max = 0xFFFF });
    s.addAbs(.{ .code = ABS_MT_POSITION_X, .min = 0, .max = w, .resolution = r });
    s.addAbs(.{ .code = ABS_MT_POSITION_Y, .min = 0, .max = h, .resolution = r });
    return s;
}

pub fn penSpec(index: usize, g: Geometry) error{InvalidFrame}!Spec {
    try checkIndex(index, g);
    var s: Spec = .{ .kind = .pen, .keys = &pen_keys, .props = &direct, .product = product_pen };
    s.name_len = (deviceName(&s.name_buf, .pen, index) catch unreachable).len;
    const r: i32 = @intCast(g.resolution);
    s.addAbs(.{ .code = ABS_X, .min = 0, .max = @intCast(g.width - 1), .resolution = r });
    s.addAbs(.{ .code = ABS_Y, .min = 0, .max = @intCast(g.height - 1), .resolution = r });
    s.addAbs(.{ .code = ABS_PRESSURE, .min = 0, .max = pen_pressure_max });
    s.addAbs(.{ .code = ABS_TILT_X, .min = -pen_tilt_max, .max = pen_tilt_max, .resolution = pen_tilt_resolution });
    s.addAbs(.{ .code = ABS_TILT_Y, .min = -pen_tilt_max, .max = pen_tilt_max, .resolution = pen_tilt_resolution });
    return s;
}

pub fn spec(kind: Kind, index: usize, g: Geometry) error{InvalidFrame}!Spec {
    return switch (kind) {
        .touch => touchSpec(index, g),
        .pen => penSpec(index, g),
    };
}

/// Two reports of 16 slots with 4 events each, plus the pen's proximity changes.
pub const max_events = 160;

pub const Events = struct {
    buf: [max_events]Event = undefined,
    len: usize = 0,
    /// Index after the last SYN_REPORT.
    synced: usize = 0,

    pub fn slice(e: *const Events) []const Event {
        return e.buf[0..e.len];
    }

    fn put(e: *Events, t: u16, code: u16, value: i32) Error!void {
        if (e.len == e.buf.len) return error.NoSpaceLeft;
        e.buf[e.len] = .{ .type = t, .code = code, .value = value };
        e.len += 1;
    }

    fn pending(e: *const Events) bool {
        return e.len > e.synced;
    }

    fn syn(e: *Events) Error!void {
        try e.put(EV_SYN, SYN_REPORT, 0);
        e.synced = e.len;
    }
};

pub const Contact = struct {
    slot: u8,
    id: u16,
    x: u32,
    y: u32,
};

/// A touchscreen's state as its listeners know it.
pub const Touch = struct {
    width: u32,
    height: u32,
    slots: [max_slots]?Slot = @splat(null),
    /// ABS_MT_SLOT as the kernel has it (0 when the device is created).
    cur_slot: u8 = 0,
    touching: bool = false,
    /// ABS_X/ABS_Y as last written.
    st_x: u32 = 0,
    st_y: u32 = 0,
    /// Order of arrival, for the single-touch pointer (oldest contact).
    age: u64 = 0,

    const Slot = struct { id: u16, x: u32, y: u32, age: u64 };

    pub fn init(g: Geometry) Touch {
        return .{ .width = g.width, .height = g.height };
    }

    /// Events from the current state to `next`, all contacts down; on error nothing changes.
    /// A replaced slot is lifted in its own frame first: libinput drops a new id in a live slot.
    pub fn frame(t: *Touch, next: []const Contact, out: *Events) Error!void {
        var want: [max_slots]?Contact = @splat(null);
        for (next, 0..) |ct, i| {
            if (ct.slot >= max_slots or ct.x >= t.width or ct.y >= t.height) return error.InvalidFrame;
            if (want[ct.slot] != null) return error.InvalidFrame;
            for (next[0..i]) |o| if (o.id == ct.id) return error.InvalidFrame;
            want[ct.slot] = ct;
        }
        var replaced = false;
        for (&t.slots, want, 0..) |*s, w, i| {
            const old = s.* orelse continue;
            if (w) |nw| if (nw.id == old.id) continue;
            try t.select(@intCast(i), out);
            try out.put(EV_ABS, ABS_MT_TRACKING_ID, -1);
            s.* = null;
            if (w != null) replaced = true;
        }
        if (replaced) try t.report(out);
        for (&t.slots, want, 0..) |*s, maybe, i| {
            const w = maybe orelse continue;
            if (s.*) |*old| {
                if (w.x != old.x) {
                    try t.select(@intCast(i), out);
                    try out.put(EV_ABS, ABS_MT_POSITION_X, @intCast(w.x));
                }
                if (w.y != old.y) {
                    try t.select(@intCast(i), out);
                    try out.put(EV_ABS, ABS_MT_POSITION_Y, @intCast(w.y));
                }
                old.x = w.x;
                old.y = w.y;
            } else {
                try t.select(@intCast(i), out);
                try out.put(EV_ABS, ABS_MT_TRACKING_ID, w.id);
                try out.put(EV_ABS, ABS_MT_POSITION_X, @intCast(w.x));
                try out.put(EV_ABS, ABS_MT_POSITION_Y, @intCast(w.y));
                t.age += 1;
                s.* = .{ .id = w.id, .x = w.x, .y = w.y, .age = t.age };
            }
        }
        if (out.pending()) try t.report(out);
    }

    pub fn liftAll(t: *Touch, out: *Events) Error!void {
        return t.frame(&.{}, out);
    }

    pub fn activeCount(t: *const Touch) usize {
        var n: usize = 0;
        for (t.slots) |s| n += @intFromBool(s != null);
        return n;
    }

    fn select(t: *Touch, slot: u8, out: *Events) Error!void {
        if (t.cur_slot == slot) return;
        try out.put(EV_ABS, ABS_MT_SLOT, slot);
        t.cur_slot = slot;
    }

    /// BTN_TOUCH, the single-touch position (oldest contact), SYN_REPORT.
    fn report(t: *Touch, out: *Events) Error!void {
        var oldest: ?Slot = null;
        for (t.slots) |maybe| {
            const s = maybe orelse continue;
            if (oldest == null or s.age < oldest.?.age) oldest = s;
        }
        const active = oldest != null;
        if (active != t.touching) {
            try out.put(EV_KEY, BTN_TOUCH, @intFromBool(active));
            t.touching = active;
        }
        if (oldest) |o| {
            if (o.x != t.st_x) try out.put(EV_ABS, ABS_X, @intCast(o.x));
            if (o.y != t.st_y) try out.put(EV_ABS, ABS_Y, @intCast(o.y));
            t.st_x = o.x;
            t.st_y = o.y;
        }
        try out.syn();
    }
};

pub const Presence = enum(u2) { out = 0, hover = 1, contact = 2 };

/// The pen's complete state (helper protocol `pen` line).
pub const PenState = struct {
    presence: Presence = .out,
    x: u32 = 0,
    y: u32 = 0,
    /// MS-RDPEI pressure, 0..1024; used in contact only.
    pressure: u16 = 0,
    /// Degrees, -90..90.
    tilt_x: i8 = 0,
    tilt_y: i8 = 0,
    barrel: bool = false,
    /// The eraser end (PEN_FLAG_INVERTED / PEN_FLAG_ERASER_PRESSED).
    eraser: bool = false,
};

/// ABS_PRESSURE for an MS-RDPEI contact pressure (0..1024).
pub fn devicePressure(p: u16) i32 {
    const v: i32 = @min(p, rdpei_pressure_max);
    return pen_contact_floor + @divTrunc((pen_pressure_max - pen_contact_floor) * v, rdpei_pressure_max);
}

pub const Pen = struct {
    width: u32,
    height: u32,
    tool: ?Tool = null,
    touching: bool = false,
    barrel: bool = false,
    x: i32 = 0,
    y: i32 = 0,
    pressure: i32 = 0,
    tilt_x: i32 = 0,
    tilt_y: i32 = 0,

    pub const Tool = enum { pen, rubber };

    pub fn init(g: Geometry) Pen {
        return .{ .width = g.width, .height = g.height };
    }

    /// Entering range reports the tool at pressure 0 in its own frame, as libinput takes tip
    /// contact from pressure thresholds. Switching pen/eraser leaves and re-enters.
    pub fn frame(p: *Pen, next: PenState, out: *Events) Error!void {
        if (next.presence != .out) {
            if (next.x >= p.width or next.y >= p.height) return error.InvalidFrame;
            if (next.pressure > rdpei_pressure_max) return error.InvalidFrame;
            if (@abs(next.tilt_x) > pen_tilt_max or @abs(next.tilt_y) > pen_tilt_max) return error.InvalidFrame;
        }
        const tool: Tool = if (next.eraser) .rubber else .pen;
        if (p.tool) |cur| if (next.presence == .out or cur != tool) try p.leave(out);
        if (next.presence == .out) return;
        const entering = p.tool == null;
        try p.axes(next, out);
        if (entering) {
            try p.setPressure(0, out);
            try out.put(EV_KEY, toolKey(tool), 1);
            p.tool = tool;
            try out.syn();
        }
        const touch = next.presence == .contact;
        try p.setPressure(if (touch) devicePressure(next.pressure) else 0, out);
        if (touch != p.touching) {
            try out.put(EV_KEY, BTN_TOUCH, @intFromBool(touch));
            p.touching = touch;
        }
        if (out.pending()) try out.syn();
    }

    fn toolKey(t: Tool) u16 {
        return if (t == .pen) BTN_TOOL_PEN else BTN_TOOL_RUBBER;
    }

    fn axes(p: *Pen, next: PenState, out: *Events) Error!void {
        try setAbs(&p.x, ABS_X, @intCast(next.x), out);
        try setAbs(&p.y, ABS_Y, @intCast(next.y), out);
        try setAbs(&p.tilt_x, ABS_TILT_X, next.tilt_x, out);
        try setAbs(&p.tilt_y, ABS_TILT_Y, next.tilt_y, out);
        if (next.barrel != p.barrel) {
            try out.put(EV_KEY, BTN_STYLUS, @intFromBool(next.barrel));
            p.barrel = next.barrel;
        }
    }

    fn setPressure(p: *Pen, v: i32, out: *Events) Error!void {
        try setAbs(&p.pressure, ABS_PRESSURE, v, out);
    }

    fn setAbs(cur: *i32, code: u16, v: i32, out: *Events) Error!void {
        if (cur.* == v) return;
        try out.put(EV_ABS, code, v);
        cur.* = v;
    }

    /// Tip up, barrel released, tool out of proximity, one frame.
    fn leave(p: *Pen, out: *Events) Error!void {
        const tool = p.tool orelse return;
        try p.setPressure(0, out);
        if (p.touching) try out.put(EV_KEY, BTN_TOUCH, 0);
        if (p.barrel) try out.put(EV_KEY, BTN_STYLUS, 0);
        try out.put(EV_KEY, toolKey(tool), 0);
        try out.syn();
        p.touching = false;
        p.barrel = false;
        p.tool = null;
    }

    pub fn leaveAll(p: *Pen, out: *Events) Error!void {
        return p.frame(.{}, out);
    }
};

/// _IOC(dir, 'U', nr, size) (asm-generic/ioctl.h: write 1, read 2).
fn ioc(dir: u32, nr: u32, size: u32) u32 {
    return dir << 30 | size << 16 | @as(u32, 'U') << 8 | nr;
}

pub const UI_DEV_CREATE = ioc(0, 1, 0);
pub const UI_DEV_DESTROY = ioc(0, 2, 0);
pub const UI_DEV_SETUP = ioc(1, 3, @sizeOf(c.struct_uinput_setup));
pub const UI_ABS_SETUP = ioc(1, 4, @sizeOf(c.struct_uinput_abs_setup));
pub const UI_SET_EVBIT = ioc(1, 100, @sizeOf(c_int));
pub const UI_SET_KEYBIT = ioc(1, 101, @sizeOf(c_int));
pub const UI_SET_ABSBIT = ioc(1, 103, @sizeOf(c_int));
pub const UI_SET_PROPBIT = ioc(1, 110, @sizeOf(c_int));
pub fn UI_GET_SYSNAME(len: u32) u32 {
    return ioc(2, 44, len);
}

/// A device created through /dev/uinput. Root only: the helper's.
pub const Kernel = struct {
    fd: c_int,
    /// N of /sys/devices/virtual/input/inputN (UI_GET_SYSNAME).
    input: u32,

    pub fn create(s: *const Spec) Error!Kernel {
        const fd = c.open("/dev/uinput", c.O_WRONLY | c.O_NONBLOCK | c.O_CLOEXEC);
        if (fd < 0) return error.DeviceFailed;
        errdefer _ = c.close(fd);
        try setBit(fd, UI_SET_EVBIT, EV_KEY);
        try setBit(fd, UI_SET_EVBIT, EV_ABS);
        for (s.keys) |k| try setBit(fd, UI_SET_KEYBIT, k);
        for (s.props) |p| try setBit(fd, UI_SET_PROPBIT, p);
        for (s.abs()) |a| {
            try setBit(fd, UI_SET_ABSBIT, a.code);
            var as = std.mem.zeroes(c.struct_uinput_abs_setup);
            as.code = a.code;
            as.absinfo.minimum = a.min;
            as.absinfo.maximum = a.max;
            as.absinfo.resolution = a.resolution;
            if (c.ioctl(fd, UI_ABS_SETUP, &as) != 0) return error.DeviceFailed;
        }
        var setup = std.mem.zeroes(c.struct_uinput_setup);
        setup.id.bustype = s.bustype;
        setup.id.vendor = s.vendor;
        setup.id.product = s.product;
        setup.id.version = s.version;
        @memcpy(setup.name[0..s.name_len], s.name());
        if (c.ioctl(fd, UI_DEV_SETUP, &setup) != 0) return error.DeviceFailed;
        if (c.ioctl(fd, UI_DEV_CREATE) != 0) return error.DeviceFailed;
        errdefer _ = c.ioctl(fd, UI_DEV_DESTROY);
        var sys: [32]u8 = @splat(0);
        if (c.ioctl(fd, UI_GET_SYSNAME(sys.len), &sys) < 0) return error.DeviceFailed;
        const n = fence.inputNumber(std.mem.sliceTo(&sys, 0)) orelse return error.DeviceFailed;
        return .{ .fd = fd, .input = n };
    }

    fn setBit(fd: c_int, req: u32, bit: u16) Error!void {
        if (c.ioctl(fd, req, @as(c_int, bit)) != 0) return error.DeviceFailed;
    }

    pub fn write(k: *const Kernel, evs: []const Event) Error!void {
        var buf: [max_events]c.struct_input_event = undefined;
        if (evs.len > buf.len) return error.NoSpaceLeft;
        for (evs, buf[0..evs.len]) |e, *o| {
            o.* = std.mem.zeroes(c.struct_input_event);
            o.type = e.type;
            o.code = e.code;
            o.value = e.value;
        }
        const size = evs.len * @sizeOf(c.struct_input_event);
        if (c.write(k.fd, &buf, size) != @as(isize, @intCast(size))) return error.WriteFailed;
    }

    pub fn destroy(k: *Kernel) void {
        _ = c.ioctl(k.fd, UI_DEV_DESTROY);
        _ = c.close(k.fd);
        k.fd = -1;
    }
};

test "uinput ioctl numbers match linux/uinput.h" {
    try std.testing.expectEqual(@as(u32, 0x5501), UI_DEV_CREATE);
    try std.testing.expectEqual(@as(u32, 0x5502), UI_DEV_DESTROY);
    // sizeof(struct uinput_setup) = 92, sizeof(struct uinput_abs_setup) = 28
    try std.testing.expectEqual(@as(u32, 0x405c5503), UI_DEV_SETUP);
    try std.testing.expectEqual(@as(u32, 0x401c5504), UI_ABS_SETUP);
    try std.testing.expectEqual(@as(u32, 0x40045564), UI_SET_EVBIT);
    try std.testing.expectEqual(@as(u32, 0x40045565), UI_SET_KEYBIT);
    try std.testing.expectEqual(@as(u32, 0x40045567), UI_SET_ABSBIT);
    try std.testing.expectEqual(@as(u32, 0x4004556e), UI_SET_PROPBIT);
    try std.testing.expectEqual(@as(u32, 0x8020552c), UI_GET_SYSNAME(32));
}

test "kernel device compiles" {
    std.testing.refAllDecls(Kernel);
}
