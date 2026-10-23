//! Remote touch and pen (MS-RDPEI) injected into the root helper's uinput touchscreens and pen
//! tablets, one of each per output. Contacts follow the MS-RDPEI 3.1.1.1 state machine, only engaged
//! contacts are down (no hover on a Linux touchscreen), and a contact stays on its output until lifted.

const std = @import("std");
const rdpei = @import("../channel/rdpei.zig");
const uinput = @import("uinput.zig");
const proto = @import("helper_proto.zig");

pub const Error = rdpei.Error || std.Io.Writer.Error || error{InvalidOutput};

pub const max_outputs = uinput.max_devices;

/// Client monitor in virtual-desktop coordinates; the mode sets the device axes.
pub const Output = struct {
    left: i32,
    top: i32,
    width: u32,
    height: u32,
    mode_width: u32,
    mode_height: u32,
};

/// Pressure for a pen contact that carries none: libinput clients draw nothing at 0.
pub const default_pressure: u16 = 512;

pub const Injector = struct {
    outputs: [max_outputs]Output = undefined,
    count: usize = 0,
    /// For rdpei.locate (monitor rectangles only).
    rects: [max_outputs]rdpei.Output = undefined,
    touch: rdpei.Tracker = .{},
    pen_tracker: rdpei.Tracker = .{},
    /// RDPEI contactId -> where it is down.
    down: [256]?Down = @splat(null),
    /// Output -> slot -> contactId.
    slots: [max_outputs][uinput.max_slots]?u8 = @splat(@splat(null)),
    /// Engaged contacts that found every slot taken; they stay up until they leave engaged.
    overflow: std.StaticBitSet(256) = .empty,
    next_id: u16 = 0,
    dirty: std.StaticBitSet(max_outputs) = .empty,
    /// The pen's output while in range, and its last state there.
    pen: ?PenAt = null,

    const Down = struct { output: u8, slot: u8, id: u16, x: u32, y: u32 };
    const PenAt = struct { output: u8, state: uinput.PenState };

    /// error.NoOutputs for none, error.ValueOutOfRange for more than 16, error.InvalidOutput
    /// for a zero-size monitor or mode, or a mode beyond the device axes.
    pub fn init(outputs: []const Output) Error!Injector {
        if (outputs.len == 0) return error.NoOutputs;
        if (outputs.len > max_outputs) return error.ValueOutOfRange;
        var inj: Injector = .{ .count = outputs.len };
        for (outputs, inj.outputs[0..outputs.len], inj.rects[0..outputs.len]) |o, *d, *r| {
            if (o.width == 0 or o.height == 0 or o.mode_width == 0 or o.mode_height == 0) return error.InvalidOutput;
            if (o.mode_width > uinput.max_axis or o.mode_height > uinput.max_axis) return error.InvalidOutput;
            d.* = o;
            r.* = .{ .left = o.left, .top = o.top, .width = o.width, .height = o.height };
        }
        return inj;
    }

    /// rdpei.locate (or the output `on`), clamped to that output's mode.
    fn place(inj: *const Injector, x: i32, y: i32, on: ?u8) Error!struct { output: u8, x: u32, y: u32 } {
        const i: u8 = on orelse (try rdpei.locate(inj.rects[0..inj.count], x, y)).output;
        const o = inj.outputs[i];
        const lx = std.math.clamp(@as(i64, x) - o.left, 0, @as(i64, o.mode_width) - 1);
        const ly = std.math.clamp(@as(i64, y) - o.top, 0, @as(i64, o.mode_height) - 1);
        return .{ .output = i, .x = @intCast(lx), .y = @intCast(ly) };
    }

    /// A tracking id unused on `output`: the counter wraps and a frame must not list an id twice.
    fn freshId(inj: *Injector, output: u8) u16 {
        while (true) {
            const cand = inj.next_id;
            inj.next_id +%= 1;
            const taken = for (inj.slots[output]) |s| {
                const cid = s orelse continue;
                if (inj.down[cid].?.id == cand) break true;
            } else false;
            if (!taken) return cand;
        }
    }

    /// Writes the complete state of every output whose contacts changed.
    pub fn touchFrame(inj: *Injector, frame: rdpei.TouchFrame, w: *std.Io.Writer) Error!void {
        for (frame.contacts) |ct| try inj.touchContact(ct);
        try inj.flushTouch(w);
    }

    fn touchContact(inj: *Injector, ct: rdpei.TouchContact) Error!void {
        const id = ct.contact_id;
        switch (try inj.touch.apply(id, ct.contact_flags, ct.x, ct.y)) {
            .ignored => {},
            .canceled => inj.lift(id),
            .accepted => switch (try inj.touch.stateOf(id)) {
                .engaged => {
                    if (inj.down[id]) |*d| {
                        const p = try inj.place(ct.x, ct.y, d.output);
                        if (p.x != d.x or p.y != d.y) inj.dirty.set(d.output);
                        d.x = p.x;
                        d.y = p.y;
                        return;
                    }
                    if (inj.overflow.isSet(id)) return;
                    const p = try inj.place(ct.x, ct.y, null);
                    const slot = for (inj.slots[p.output], 0..) |s, i| {
                        if (s == null) break i;
                    } else {
                        inj.overflow.set(id);
                        return;
                    };
                    const tracking = inj.freshId(p.output);
                    inj.slots[p.output][slot] = id;
                    inj.down[id] = .{ .output = p.output, .slot = @intCast(slot), .id = tracking, .x = p.x, .y = p.y };
                    inj.dirty.set(p.output);
                },
                .hovering, .out_of_range => inj.lift(id),
            },
        }
    }

    fn lift(inj: *Injector, id: u8) void {
        inj.overflow.unset(id);
        const d = inj.down[id] orelse return;
        inj.slots[d.output][d.slot] = null;
        inj.down[id] = null;
        inj.dirty.set(d.output);
    }

    fn flushTouch(inj: *Injector, w: *std.Io.Writer) Error!void {
        var it = inj.dirty.iterator(.{});
        while (it.next()) |o| {
            for (inj.slots[o]) |maybe| {
                const d = inj.down[maybe orelse continue].?;
                try writeLine(w, .{ .touch = .{ .dev = @intCast(o), .contact = .{ .slot = d.slot, .id = d.id, .x = d.x, .y = d.y } } });
            }
            try writeLine(w, .{ .touch_frame = @intCast(o) });
        }
        inj.dirty = .empty;
    }

    /// DISMISS_HOVERING_TOUCH_CONTACT (MS-RDPEI 3.2.5.6). Hovering contacts are not down: nothing is sent.
    pub fn dismissHovering(inj: *Injector, id: u8) Error!void {
        _ = try inj.touch.dismissHovering(id);
    }

    /// Ignores deviceId other than 0 (no multipen) and pressure or tilt out of range (MS-RDPEI 2.2.3.7.1.1).
    /// An invalid flag transition takes the pen out of range.
    pub fn penFrame(inj: *Injector, frame: rdpei.PenFrame, w: *std.Io.Writer) Error!void {
        for (frame.contacts) |ct| try inj.penContact(ct, w);
    }

    fn penContact(inj: *Injector, ct: rdpei.PenContact, w: *std.Io.Writer) Error!void {
        if (ct.device_id != 0) return;
        if (ct.pressure) |p| if (p > rdpei.max_pressure) return;
        for ([_]?i16{ ct.tilt_x, ct.tilt_y }) |t| if (t) |v| if (v < -rdpei.max_tilt or v > rdpei.max_tilt) return;
        const presence: uinput.Presence = switch (try inj.pen_tracker.apply(ct.device_id, ct.contact_flags, ct.x, ct.y)) {
            .ignored => return,
            .canceled => .out,
            .accepted => switch (try inj.pen_tracker.stateOf(ct.device_id)) {
                .engaged => .contact,
                .hovering => .hover,
                .out_of_range => .out,
            },
        };
        if (presence == .out) return inj.penOut(w);
        const flags = ct.pen_flags orelse 0;
        // In contact the pen stays on its output; hovering it follows.
        const stay: ?u8 = if (inj.pen) |p| (if (presence == .contact and p.state.presence == .contact) p.output else null) else null;
        const at = try inj.place(ct.x, ct.y, stay);
        if (inj.pen) |p| if (p.output != at.output) try inj.penOut(w);
        const state: uinput.PenState = .{
            .presence = presence,
            .x = at.x,
            .y = at.y,
            .pressure = if (presence == .contact) @intCast(ct.pressure orelse default_pressure) else 0,
            .tilt_x = @intCast(ct.tilt_x orelse 0),
            .tilt_y = @intCast(ct.tilt_y orelse 0),
            .barrel = flags & rdpei.pen_flag_barrel_pressed != 0,
            .eraser = flags & (rdpei.pen_flag_eraser_pressed | rdpei.pen_flag_inverted) != 0,
        };
        if (inj.pen) |p| if (p.output == at.output and std.meta.eql(p.state, state)) return;
        inj.pen = .{ .output = at.output, .state = state };
        try writeLine(w, .{ .pen = .{ .dev = at.output, .state = state } });
    }

    fn penOut(inj: *Injector, w: *std.Io.Writer) Error!void {
        const p = inj.pen orelse return;
        inj.pen = null;
        try writeLine(w, .{ .pen = .{ .dev = p.output, .state = .{} } });
    }

    /// Forgets all state (SUSPEND_INPUT 3.2.5.4, channel close, desk takeover, disconnect).
    pub fn releaseAll(inj: *Injector, w: *std.Io.Writer) Error!void {
        for (0..256) |id| inj.lift(@intCast(id));
        try inj.flushTouch(w);
        try inj.penOut(w);
        try inj.touch.reset();
        try inj.pen_tracker.reset();
    }

    pub fn downCount(inj: *const Injector, o: usize) usize {
        var n: usize = 0;
        for (inj.slots[o]) |s| n += @intFromBool(s != null);
        return n;
    }
};

fn writeLine(w: *std.Io.Writer, cmd: proto.Command) Error!void {
    var buf: [proto.max_line + 1]u8 = undefined;
    // The injector only builds values the protocol accepts.
    const line = proto.format(&buf, cmd) catch unreachable;
    try w.writeAll(line);
}
