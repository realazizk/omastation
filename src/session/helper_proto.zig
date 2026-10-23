//! Line protocol between the session agent and the root helper (helper.zig): one
//! command per line, single-space separated, strict decimal numbers.

const std = @import("std");
const uinput = @import("uinput.zig");

pub const max_line = 63;

pub const ParseError = error{
    /// Not a command of this protocol; the helper does not answer.
    Unknown,
    Invalid,
};

pub const Open = struct { kind: uinput.Kind, dev: u8, geometry: uinput.Geometry };
pub const Close = struct { kind: uinput.Kind, dev: u8 };
pub const Stage = struct { dev: u8, contact: uinput.Contact };
pub const Pen = struct { dev: u8, state: uinput.PenState };

pub const Command = union(enum) {
    fence,
    unfence,
    status,
    /// "touch-open|pen-open D W H R": device for output D, axes 0..W-1 x 0..H-1, R units per mm.
    open: Open,
    close: Close,
    /// "touch D S I X Y": stage contact slot S, tracking id I, at (X, Y). Not answered.
    touch: Stage,
    /// "touch-frame D": the staged contacts are all that is down now. Not answered.
    touch_frame: u8,
    /// "pen D P X Y Z TX TY B": presence 0-2, pressure 0..1024 (MS-RDPEI 2.2.3.7.1.1), tilt -90..90, B 1 barrel | 2 eraser. Not answered.
    pen: Pen,

    pub fn answered(cmd: Command) bool {
        return switch (cmd) {
            .touch, .touch_frame, .pen => false,
            else => true,
        };
    }
};

pub const pen_barrel: u32 = 1;
pub const pen_eraser: u32 = 2;

const Words = struct {
    it: std.mem.SplitIterator(u8, .scalar),

    fn next(w: *Words) ParseError![]const u8 {
        const t = w.it.next() orelse return error.Invalid;
        if (t.len == 0) return error.Invalid;
        return t;
    }

    fn end(w: *Words) ParseError!void {
        if (w.it.next() != null) return error.Invalid;
    }

    fn unsigned(w: *Words, max: u32) ParseError!u32 {
        return parseUnsigned(try w.next(), max);
    }

    fn device(w: *Words) ParseError!u8 {
        return @intCast(try w.unsigned(uinput.max_devices - 1));
    }

    fn tilt(w: *Words) ParseError!i8 {
        const t = try w.next();
        if (t[0] == '-') {
            const v = try parseUnsigned(t[1..], uinput.pen_tilt_max);
            if (v == 0) return error.Invalid; // "-0"
            return -@as(i8, @intCast(v));
        }
        return @intCast(try parseUnsigned(t, uinput.pen_tilt_max));
    }
};

pub fn parseUnsigned(t: []const u8, max: u32) ParseError!u32 {
    if (t.len == 0 or t.len > 10) return error.Invalid;
    if (t.len > 1 and t[0] == '0') return error.Invalid;
    var v: u64 = 0;
    for (t) |ch| {
        if (ch < '0' or ch > '9') return error.Invalid;
        v = v * 10 + (ch - '0');
    }
    if (v > max) return error.Invalid;
    return @intCast(v);
}

pub fn parse(raw: []const u8) ParseError!Command {
    const line = std.mem.trim(u8, raw, " \r");
    if (std.mem.eql(u8, line, "fence")) return .fence;
    if (std.mem.eql(u8, line, "unfence")) return .unfence;
    if (std.mem.eql(u8, line, "status")) return .status;
    var w: Words = .{ .it = std.mem.splitScalar(u8, line, ' ') };
    const verb = w.it.next() orelse return error.Unknown;
    const Verb = enum { @"touch-open", @"pen-open", @"touch-close", @"pen-close", touch, @"touch-frame", pen };
    const v = std.meta.stringToEnum(Verb, verb) orelse return error.Unknown;
    if (line.len > max_line) return error.Invalid;
    const cmd: Command = switch (v) {
        .@"touch-open", .@"pen-open" => blk: {
            const dev = try w.device();
            const g: uinput.Geometry = .{
                .width = try w.unsigned(uinput.max_axis),
                .height = try w.unsigned(uinput.max_axis),
                .resolution = try w.unsigned(uinput.max_resolution),
            };
            if (!uinput.validGeometry(g)) return error.Invalid;
            break :blk .{ .open = .{ .kind = if (v == .@"touch-open") .touch else .pen, .dev = dev, .geometry = g } };
        },
        .@"touch-close", .@"pen-close" => .{ .close = .{ .kind = if (v == .@"touch-close") .touch else .pen, .dev = try w.device() } },
        .touch => blk: {
            const dev = try w.device();
            const slot: u8 = @intCast(try w.unsigned(uinput.max_slots - 1));
            const id: u16 = @intCast(try w.unsigned(0xFFFF));
            const x = try w.unsigned(uinput.max_axis - 1);
            const y = try w.unsigned(uinput.max_axis - 1);
            break :blk .{ .touch = .{ .dev = dev, .contact = .{ .slot = slot, .id = id, .x = x, .y = y } } };
        },
        .@"touch-frame" => .{ .touch_frame = try w.device() },
        .pen => blk: {
            const dev = try w.device();
            const presence: uinput.Presence = @fromBackingInt(@intCast(try w.unsigned(2)));
            const x = try w.unsigned(uinput.max_axis - 1);
            const y = try w.unsigned(uinput.max_axis - 1);
            const pressure: u16 = @intCast(try w.unsigned(uinput.rdpei_pressure_max));
            const tx = try w.tilt();
            const ty = try w.tilt();
            const b = try w.unsigned(pen_barrel | pen_eraser);
            break :blk .{ .pen = .{ .dev = dev, .state = .{
                .presence = presence,
                .x = x,
                .y = y,
                .pressure = pressure,
                .tilt_x = tx,
                .tilt_y = ty,
                .barrel = b & pen_barrel != 0,
                .eraser = b & pen_eraser != 0,
            } } };
        },
    };
    try w.end();
    return cmd;
}

/// The line's command is answered even with bad arguments, so the agent waits for the reply.
pub fn answers(raw: []const u8) bool {
    const line = std.mem.trim(u8, raw, " \r");
    const verb = line[0 .. std.mem.indexOfScalar(u8, line, ' ') orelse line.len];
    for ([_][]const u8{ "touch-open", "pen-open", "touch-close", "pen-close" }) |v| {
        if (std.mem.eql(u8, verb, v)) return true;
    }
    return false;
}

/// Newline included; error.Invalid for values `parse` would refuse.
pub fn format(buf: []u8, cmd: Command) (ParseError || error{NoSpaceLeft})![]const u8 {
    const line = switch (cmd) {
        .fence => try std.fmt.bufPrint(buf, "fence\n", .{}),
        .unfence => try std.fmt.bufPrint(buf, "unfence\n", .{}),
        .status => try std.fmt.bufPrint(buf, "status\n", .{}),
        .open => |o| blk: {
            if (o.dev >= uinput.max_devices or !uinput.validGeometry(o.geometry)) return error.Invalid;
            break :blk try std.fmt.bufPrint(buf, "{t}-open {d} {d} {d} {d}\n", .{ o.kind, o.dev, o.geometry.width, o.geometry.height, o.geometry.resolution });
        },
        .close => |o| blk: {
            if (o.dev >= uinput.max_devices) return error.Invalid;
            break :blk try std.fmt.bufPrint(buf, "{t}-close {d}\n", .{ o.kind, o.dev });
        },
        .touch => |s| blk: {
            const ct = s.contact;
            if (s.dev >= uinput.max_devices or ct.slot >= uinput.max_slots or ct.x >= uinput.max_axis or ct.y >= uinput.max_axis) return error.Invalid;
            break :blk try std.fmt.bufPrint(buf, "touch {d} {d} {d} {d} {d}\n", .{ s.dev, ct.slot, ct.id, ct.x, ct.y });
        },
        .touch_frame => |dev| blk: {
            if (dev >= uinput.max_devices) return error.Invalid;
            break :blk try std.fmt.bufPrint(buf, "touch-frame {d}\n", .{dev});
        },
        .pen => |p| blk: {
            const s = p.state;
            if (p.dev >= uinput.max_devices or s.x >= uinput.max_axis or s.y >= uinput.max_axis or s.pressure > uinput.rdpei_pressure_max or
                @abs(s.tilt_x) > uinput.pen_tilt_max or @abs(s.tilt_y) > uinput.pen_tilt_max) return error.Invalid;
            const b: u32 = (if (s.barrel) pen_barrel else 0) | (if (s.eraser) pen_eraser else 0);
            break :blk try std.fmt.bufPrint(buf, "pen {d} {d} {d} {d} {d} {d} {d} {d}\n", .{ p.dev, @backingInt(s.presence), s.x, s.y, s.pressure, s.tilt_x, s.tilt_y, b });
        },
    };
    std.debug.assert(line.len <= max_line + 1);
    return line;
}

/// "activity" is unsolicited: a key was pressed at the fenced desk.
pub const Reply = enum { ok, fenced, unfenced, activity, err, other };

pub fn parseReply(line: []const u8) Reply {
    if (std.mem.eql(u8, line, "ok")) return .ok;
    if (std.mem.eql(u8, line, "fenced")) return .fenced;
    if (std.mem.eql(u8, line, "unfenced")) return .unfenced;
    if (std.mem.eql(u8, line, "activity")) return .activity;
    if (std.mem.eql(u8, line, "error") or std.mem.startsWith(u8, line, "error ")) return .err;
    return .other;
}

/// Splits a byte stream into lines; an overlong line is dropped.
pub const LineBuffer = struct {
    buf: [max_line + 1]u8 = undefined,
    len: usize = 0,

    /// Consumes `in` through the newline; the line is valid until the next call.
    pub fn next(lb: *LineBuffer, in: *[]const u8) ?[]const u8 {
        while (in.len > 0) {
            const ch = in.*[0];
            in.* = in.*[1..];
            if (ch == '\n') {
                const line = lb.buf[0..lb.len];
                lb.len = 0;
                return line;
            }
            lb.buf[lb.len] = ch;
            lb.len += 1;
            if (lb.len == lb.buf.len) lb.len = 0;
        }
        return null;
    }

    pub fn clear(lb: *LineBuffer) void {
        lb.len = 0;
    }
};

test "every command formats to a line that parses back to it" {
    var buf: [128]u8 = undefined;
    const cmds = [_]Command{
        .fence,
        .unfence,
        .status,
        .{ .open = .{ .kind = .touch, .dev = 0, .geometry = .{ .width = 1920, .height = 1080, .resolution = 4 } } },
        .{ .open = .{ .kind = .pen, .dev = 15, .geometry = .{ .width = 32766, .height = 32766, .resolution = 1000 } } },
        .{ .close = .{ .kind = .pen, .dev = 3 } },
        .{ .touch = .{ .dev = 15, .contact = .{ .slot = 15, .id = 65535, .x = 32765, .y = 32765 } } },
        .{ .touch_frame = 7 },
        .{ .pen = .{ .dev = 15, .state = .{ .presence = .contact, .x = 32765, .y = 32765, .pressure = 1024, .tilt_x = -90, .tilt_y = 90, .barrel = true, .eraser = true } } },
    };
    for (cmds) |cmd| {
        const line = try format(&buf, cmd);
        try std.testing.expect(line.len <= max_line + 1);
        try std.testing.expectEqual(cmd, try parse(line[0 .. line.len - 1]));
    }
}
