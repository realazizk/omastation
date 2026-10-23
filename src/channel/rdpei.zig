//! MS-RDPEI touch and pen input (Microsoft::Windows::RDS::Input dynamic channel):
//! PDU codecs, the contact state machine (3.1.1.1) and pointer emulation.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

pub const channel_name = "Microsoft::Windows::RDS::Input";

pub const Error = error{
    EndOfBuffer,
    BadLength,
    UnexpectedEvent,
    TrailingBytes,
    ValueOutOfRange,
    OutOfMemory,
    InvalidContactFlags,
    OrientationOutOfRange,
    PressureOutOfRange,
    RotationOutOfRange,
    TiltOutOfRange,
    DeviceIdNotNegotiated,
    InvalidTransition,
    /// Not expected in the current protocol state; ignored (3.1.5.1).
    UnexpectedPdu,
    NoOutputs,
};

// --- variable-length integers (2.2.2.1 - 2.2.2.5) -----------------------------------

pub const two_byte_unsigned_max: u16 = 0x7FFF;
pub const two_byte_signed_max: i16 = 0x3FFF;
pub const two_byte_signed_min: i16 = -0x3FFF;
pub const four_byte_unsigned_max: u32 = 0x3FFF_FFFF;
pub const four_byte_signed_max: i32 = 0x1FFF_FFFF;
pub const four_byte_signed_min: i32 = -0x1FFF_FFFF;
pub const eight_byte_unsigned_max: u64 = 0x1FFF_FFFF_FFFF_FFFF;

/// First byte: `len_bits` of (byte count - 1), an optional sign bit, then the
/// top magnitude bits; the remaining bytes follow big-endian.
const VarLayout = struct {
    len_bits: u3,
    sign_bits: u1,

    fn val1Bits(comptime l: VarLayout) u4 {
        return 8 - @as(u4, l.len_bits) - l.sign_bits;
    }
    fn maxLen(comptime l: VarLayout) usize {
        return @as(usize, 1) << l.len_bits;
    }
    fn limit(comptime l: VarLayout, n: usize) u64 {
        const bits: u6 = @intCast(l.val1Bits() + 8 * (n - 1));
        return (@as(u64, 1) << bits) - 1;
    }
};

const two_u_layout = VarLayout{ .len_bits = 1, .sign_bits = 0 };
const two_s_layout = VarLayout{ .len_bits = 1, .sign_bits = 1 };
const four_u_layout = VarLayout{ .len_bits = 2, .sign_bits = 0 };
const four_s_layout = VarLayout{ .len_bits = 2, .sign_bits = 1 };
const eight_u_layout = VarLayout{ .len_bits = 3, .sign_bits = 0 };

/// Magnitude and sign of any valid encoding; FreeRDP writes non-minimal ones.
fn readVar(r: *bytes.Reader, comptime l: VarLayout) Error!struct { m: u64, neg: bool } {
    const b0 = try r.byte();
    const n = @as(usize, b0 >> @intCast(8 - @as(u4, l.len_bits))) + 1;
    const neg = l.sign_bits == 1 and (b0 >> @intCast(l.val1Bits())) & 1 != 0;
    var m: u64 = b0 & ((@as(u8, 1) << @intCast(l.val1Bits())) - 1);
    for (try r.bytes(n - 1)) |b| m = m << 8 | b;
    return .{ .m = m, .neg = neg };
}

fn sizeVar(comptime l: VarLayout, m: u64) Error!usize {
    var n: usize = 1;
    while (n <= l.maxLen()) : (n += 1) {
        if (m <= l.limit(n)) return n;
    }
    return error.ValueOutOfRange;
}

fn writeVar(w: *bytes.Writer, comptime l: VarLayout, m: u64, neg: bool) Error!void {
    const n = try sizeVar(l, m);
    var buf: [8]u8 = undefined;
    var v = m;
    var i = n;
    while (i > 1) : (i -= 1) {
        buf[i - 1] = @truncate(v);
        v >>= 8;
    }
    const sign: u8 = if (l.sign_bits == 1 and neg and m != 0) @as(u8, 1) << @intCast(l.val1Bits()) else 0;
    buf[0] = @as(u8, @intCast(n - 1)) << @intCast(8 - @as(u4, l.len_bits)) | sign | @as(u8, @intCast(v));
    try w.bytes(buf[0..n]);
}

pub fn readTwoByteUnsigned(r: *bytes.Reader) Error!u16 {
    return @intCast((try readVar(r, two_u_layout)).m);
}

pub fn readTwoByteSigned(r: *bytes.Reader) Error!i16 {
    const v = try readVar(r, two_s_layout);
    const m: i16 = @intCast(v.m);
    return if (v.neg) -m else m;
}

pub fn readFourByteUnsigned(r: *bytes.Reader) Error!u32 {
    return @intCast((try readVar(r, four_u_layout)).m);
}

pub fn readFourByteSigned(r: *bytes.Reader) Error!i32 {
    const v = try readVar(r, four_s_layout);
    const m: i32 = @intCast(v.m);
    return if (v.neg) -m else m;
}

pub fn readEightByteUnsigned(r: *bytes.Reader) Error!u64 {
    return (try readVar(r, eight_u_layout)).m;
}

pub fn writeTwoByteUnsigned(w: *bytes.Writer, v: u16) Error!void {
    try writeVar(w, two_u_layout, v, false);
}

pub fn writeTwoByteSigned(w: *bytes.Writer, v: i16) Error!void {
    try writeVar(w, two_s_layout, @abs(v), v < 0);
}

pub fn writeFourByteUnsigned(w: *bytes.Writer, v: u32) Error!void {
    try writeVar(w, four_u_layout, v, false);
}

pub fn writeFourByteSigned(w: *bytes.Writer, v: i32) Error!void {
    try writeVar(w, four_s_layout, @abs(v), v < 0);
}

pub fn writeEightByteUnsigned(w: *bytes.Writer, v: u64) Error!void {
    try writeVar(w, eight_u_layout, v, false);
}

pub fn sizeTwoByteUnsigned(v: u16) Error!usize {
    return sizeVar(two_u_layout, v);
}

pub fn sizeTwoByteSigned(v: i16) Error!usize {
    return sizeVar(two_s_layout, @abs(v));
}

pub fn sizeFourByteUnsigned(v: u32) Error!usize {
    return sizeVar(four_u_layout, v);
}

pub fn sizeFourByteSigned(v: i32) Error!usize {
    return sizeVar(four_s_layout, @abs(v));
}

pub fn sizeEightByteUnsigned(v: u64) Error!usize {
    return sizeVar(eight_u_layout, v);
}

// --- RDPINPUT_HEADER (2.2.2.6) -----------------------------------------------------------

pub const header_size: usize = 6;

pub const EventId = enum(u16) {
    sc_ready = 0x0001,
    cs_ready = 0x0002,
    touch = 0x0003,
    suspend_input = 0x0004,
    resume_input = 0x0005,
    dismiss_hovering_touch_contact = 0x0006,
    pen = 0x0008,
    _,
};

pub const Header = struct {
    event_id: EventId,
    pdu_length: u32,
};

/// pduLength must be >= 6 and equal `msg.len` (3.1.5.1).
pub fn decodeHeader(msg: []const u8) Error!Header {
    var r = bytes.Reader.init(msg);
    const id = try r.u16le();
    const len = try r.u32le();
    if (len < header_size or len != msg.len) return error.BadLength;
    return .{ .event_id = @fromBackingInt(@intCast(id)), .pdu_length = len };
}

pub fn encodeHeader(w: *bytes.Writer, event_id: EventId, pdu_length: u32) Error!void {
    try w.u16le(@backingInt(event_id));
    try w.u32le(pdu_length);
}

fn body(msg: []const u8, id: EventId) Error!bytes.Reader {
    const h = try decodeHeader(msg);
    if (h.event_id != id) return error.UnexpectedEvent;
    return bytes.Reader.init(msg[header_size..]);
}

fn beginPdu(w: *bytes.Writer, id: EventId) Error!usize {
    const at = w.len();
    try encodeHeader(w, id, 0);
    return at;
}

fn finishPdu(w: *bytes.Writer, at: usize) Error!void {
    const n = w.len() - at;
    if (n > std.math.maxInt(u32)) return error.ValueOutOfRange;
    w.patchU32le(at + 2, @intCast(n));
}

// --- RDPINPUT_SC_READY_PDU (2.2.3.1) -----------------------------------------------------

pub const protocol_v100: u32 = 0x0001_0000;
pub const protocol_v101: u32 = 0x0001_0001;
pub const protocol_v200: u32 = 0x0002_0000;
pub const protocol_v300: u32 = 0x0003_0000;

pub const sc_ready_multipen_injection_supported: u32 = 0x0000_0001;

pub const ScReady = struct {
    protocol_version: u32,
    /// Present only in the 14-byte form; SHOULD be present with V300.
    supported_features: ?u32 = null,
};

pub fn encodeScReady(w: *bytes.Writer, pdu: ScReady) Error!void {
    try encodeHeader(w, .sc_ready, if (pdu.supported_features == null) 10 else 14);
    try w.u32le(pdu.protocol_version);
    if (pdu.supported_features) |f| try w.u32le(f);
}

pub fn decodeScReady(msg: []const u8) Error!ScReady {
    var r = try body(msg, .sc_ready);
    return switch (r.remaining()) {
        4 => .{ .protocol_version = try r.u32le() },
        8 => .{ .protocol_version = try r.u32le(), .supported_features = try r.u32le() },
        else => error.BadLength,
    };
}

// --- RDPINPUT_CS_READY_PDU (2.2.3.2) -----------------------------------------------------

pub const cs_ready_flags_show_touch_visuals: u32 = 0x0000_0001;
pub const cs_ready_flags_disable_timestamp_injection: u32 = 0x0000_0002;
pub const cs_ready_flags_enable_multipen_injection: u32 = 0x0000_0004;

pub const CsReady = struct {
    flags: u32,
    protocol_version: u32,
    max_touch_contacts: u16,
};

pub fn encodeCsReady(w: *bytes.Writer, pdu: CsReady) Error!void {
    try encodeHeader(w, .cs_ready, 16);
    try w.u32le(pdu.flags);
    try w.u32le(pdu.protocol_version);
    try w.u16le(pdu.max_touch_contacts);
}

pub fn decodeCsReady(msg: []const u8) Error!CsReady {
    var r = try body(msg, .cs_ready);
    if (r.remaining() != 10) return error.BadLength;
    return .{ .flags = try r.u32le(), .protocol_version = try r.u32le(), .max_touch_contacts = try r.u16le() };
}

pub const contact_flag_down: u32 = 0x0001;
pub const contact_flag_update: u32 = 0x0002;
pub const contact_flag_up: u32 = 0x0004;
pub const contact_flag_inrange: u32 = 0x0008;
pub const contact_flag_incontact: u32 = 0x0010;
pub const contact_flag_canceled: u32 = 0x0020;

/// The only contactFlags values allowed (2.2.3.3.1.1 and 2.2.3.7.1.1).
pub const valid_contact_flags = [8]u32{
    contact_flag_up,
    contact_flag_up | contact_flag_canceled,
    contact_flag_update,
    contact_flag_update | contact_flag_canceled,
    contact_flag_down | contact_flag_inrange | contact_flag_incontact,
    contact_flag_update | contact_flag_inrange | contact_flag_incontact,
    contact_flag_up | contact_flag_inrange,
    contact_flag_update | contact_flag_inrange,
};

pub const touch_contact_contactrect_present: u16 = 0x0001;
pub const touch_contact_orientation_present: u16 = 0x0002;
pub const touch_contact_pressure_present: u16 = 0x0004;

pub const max_orientation: u32 = 359;
pub const max_pressure: u32 = 1024;
pub const max_rotation: u16 = 359;
pub const max_tilt: i16 = 90;

/// Exclusive rectangle relative to (x, y), before rotation by `orientation` (2.2.3.3.1.1, 4.1).
pub const ContactRect = struct {
    left: i16,
    top: i16,
    right: i16,
    bottom: i16,
};

pub const TouchContact = struct {
    contact_id: u8,
    /// Relative to the primary monitor's top-left; negative left of or above it.
    x: i32,
    y: i32,
    contact_flags: u32,
    contact_rect: ?ContactRect = null,
    /// Degrees counter-clockwise, 0..359; absent means 0.
    orientation: ?u32 = null,
    pressure: ?u32 = null,
};

pub const TouchFrame = struct {
    /// Microseconds since the previous frame (0 for the first frame).
    frame_offset: u64 = 0,
    contacts: []const TouchContact,
};

pub const TouchEvent = struct {
    /// Milliseconds from the oldest frame to encoding.
    encode_time: u32 = 0,
    frames: []const TouchFrame,
};

pub const pen_contact_penflags_present: u16 = 0x0001;
pub const pen_contact_pressure_present: u16 = 0x0002;
pub const pen_contact_rotation_present: u16 = 0x0004;
pub const pen_contact_tiltx_present: u16 = 0x0008;
pub const pen_contact_tilty_present: u16 = 0x0010;

pub const pen_flag_barrel_pressed: u32 = 0x0001;
pub const pen_flag_eraser_pressed: u32 = 0x0002;
pub const pen_flag_inverted: u32 = 0x0004;

pub const PenContact = struct {
    /// 0 unless multipen injection was negotiated.
    device_id: u8 = 0,
    x: i32,
    y: i32,
    contact_flags: u32,
    pen_flags: ?u32 = null,
    pressure: ?u32 = null,
    /// Clockwise twist in degrees, 0..359 (TWO_BYTE_UNSIGNED_INTEGER).
    rotation: ?u16 = null,
    tilt_x: ?i16 = null,
    tilt_y: ?i16 = null,
};

pub const PenFrame = struct {
    frame_offset: u64 = 0,
    contacts: []const PenContact,
};

pub const PenEvent = struct {
    encode_time: u32 = 0,
    frames: []const PenFrame,
};

pub const Point = struct { x: f64, y: f64 };

/// Rectangle corners (left-top, right-top, right-bottom, left-bottom) rotated counter-clockwise
/// by `orientation` about the centre (2.2.3.3.1.1, 4.1); all equal (x, y) without a rectangle.
pub fn contactGeometry(c: TouchContact) Error![4]Point {
    const tx: f64 = @floatFromInt(c.x);
    const ty: f64 = @floatFromInt(c.y);
    const rc = c.contact_rect orelse return @splat(.{ .x = tx, .y = ty });
    const o = c.orientation orelse 0;
    if (o > max_orientation) return error.OrientationOutOfRange;
    // Counter-clockwise with y down; quarter turns are exact.
    const cs: [2]f64 = switch (o) {
        0 => .{ 1, 0 },
        90 => .{ 0, 1 },
        180 => .{ -1, 0 },
        270 => .{ 0, -1 },
        else => blk: {
            const th = @as(f64, @floatFromInt(o)) * std.math.pi / 180.0;
            break :blk .{ @cos(th), @sin(th) };
        },
    };
    const l: f64 = @floatFromInt(rc.left);
    const t: f64 = @floatFromInt(rc.top);
    const r: f64 = @floatFromInt(rc.right);
    const b: f64 = @floatFromInt(rc.bottom);
    const hx = (r - l) / 2;
    const hy = (b - t) / 2;
    const mx = tx + (l + r) / 2;
    const my = ty + (t + b) / 2;
    const rel = [4][2]f64{ .{ -hx, -hy }, .{ hx, -hy }, .{ hx, hy }, .{ -hx, hy } };
    var out: [4]Point = undefined;
    for (rel, &out) |d, *p| p.* = .{
        .x = mx + d[0] * cs[0] + d[1] * cs[1],
        .y = my + d[1] * cs[0] - d[0] * cs[1],
    };
    return out;
}

// --- RDPINPUT_TOUCH_EVENT_PDU (2.2.3.3) ---------------------------------------------------

const min_frame_size = 2;
const min_contact_size = 5;

fn writeCount(w: *bytes.Writer, n: usize) Error!void {
    if (n > two_byte_unsigned_max) return error.ValueOutOfRange;
    try writeTwoByteUnsigned(w, @intCast(n));
}

fn readCount(r: *bytes.Reader, min_size: usize) Error!usize {
    const n: usize = try readTwoByteUnsigned(r);
    if (n * min_size > r.remaining()) return error.EndOfBuffer;
    return n;
}

fn writeTouchContact(w: *bytes.Writer, c: TouchContact) Error!void {
    var fp: u16 = 0;
    if (c.contact_rect != null) fp |= touch_contact_contactrect_present;
    if (c.orientation != null) fp |= touch_contact_orientation_present;
    if (c.pressure != null) fp |= touch_contact_pressure_present;
    try w.byte(c.contact_id);
    try writeTwoByteUnsigned(w, fp);
    try writeFourByteSigned(w, c.x);
    try writeFourByteSigned(w, c.y);
    try writeFourByteUnsigned(w, c.contact_flags);
    if (c.contact_rect) |rc| {
        try writeTwoByteSigned(w, rc.left);
        try writeTwoByteSigned(w, rc.top);
        try writeTwoByteSigned(w, rc.right);
        try writeTwoByteSigned(w, rc.bottom);
    }
    if (c.orientation) |o| try writeFourByteUnsigned(w, o);
    if (c.pressure) |p| try writeFourByteUnsigned(w, p);
}

fn readTouchContact(r: *bytes.Reader) Error!TouchContact {
    var c: TouchContact = .{ .contact_id = try r.byte(), .x = 0, .y = 0, .contact_flags = 0 };
    const fp = try readTwoByteUnsigned(r);
    c.x = try readFourByteSigned(r);
    c.y = try readFourByteSigned(r);
    c.contact_flags = try readFourByteUnsigned(r);
    if (fp & touch_contact_contactrect_present != 0) {
        const left = try readTwoByteSigned(r);
        const top = try readTwoByteSigned(r);
        const right = try readTwoByteSigned(r);
        const bottom = try readTwoByteSigned(r);
        c.contact_rect = .{ .left = left, .top = top, .right = right, .bottom = bottom };
    }
    if (fp & touch_contact_orientation_present != 0) c.orientation = try readFourByteUnsigned(r);
    if (fp & touch_contact_pressure_present != 0) c.pressure = try readFourByteUnsigned(r);
    return c;
}

fn writePenContact(w: *bytes.Writer, c: PenContact) Error!void {
    var fp: u16 = 0;
    if (c.pen_flags != null) fp |= pen_contact_penflags_present;
    if (c.pressure != null) fp |= pen_contact_pressure_present;
    if (c.rotation != null) fp |= pen_contact_rotation_present;
    if (c.tilt_x != null) fp |= pen_contact_tiltx_present;
    if (c.tilt_y != null) fp |= pen_contact_tilty_present;
    try w.byte(c.device_id);
    try writeTwoByteUnsigned(w, fp);
    try writeFourByteSigned(w, c.x);
    try writeFourByteSigned(w, c.y);
    try writeFourByteUnsigned(w, c.contact_flags);
    if (c.pen_flags) |v| try writeFourByteUnsigned(w, v);
    if (c.pressure) |v| try writeFourByteUnsigned(w, v);
    if (c.rotation) |v| try writeTwoByteUnsigned(w, v);
    if (c.tilt_x) |v| try writeTwoByteSigned(w, v);
    if (c.tilt_y) |v| try writeTwoByteSigned(w, v);
}

fn readPenContact(r: *bytes.Reader) Error!PenContact {
    var c: PenContact = .{ .device_id = try r.byte(), .x = 0, .y = 0, .contact_flags = 0 };
    const fp = try readTwoByteUnsigned(r);
    c.x = try readFourByteSigned(r);
    c.y = try readFourByteSigned(r);
    c.contact_flags = try readFourByteUnsigned(r);
    if (fp & pen_contact_penflags_present != 0) c.pen_flags = try readFourByteUnsigned(r);
    if (fp & pen_contact_pressure_present != 0) c.pressure = try readFourByteUnsigned(r);
    if (fp & pen_contact_rotation_present != 0) c.rotation = try readTwoByteUnsigned(r);
    if (fp & pen_contact_tiltx_present != 0) c.tilt_x = try readTwoByteSigned(r);
    if (fp & pen_contact_tilty_present != 0) c.tilt_y = try readTwoByteSigned(r);
    return c;
}

/// TOUCH_EVENT and PEN_EVENT share a layout (2.2.3.3, 2.2.3.7); on error the writer is unchanged.
fn encodeFrames(
    w: *bytes.Writer,
    id: EventId,
    encode_time: u32,
    frames: anytype,
    comptime writeContact: anytype,
) Error!void {
    const start = w.len();
    errdefer w.list.shrinkRetainingCapacity(start);
    const at = try beginPdu(w, id);
    try writeFourByteUnsigned(w, encode_time);
    try writeCount(w, frames.len);
    for (frames) |f| {
        try writeCount(w, f.contacts.len);
        try writeEightByteUnsigned(w, f.frame_offset);
        for (f.contacts) |c| try writeContact(w, c);
    }
    try finishPdu(w, at);
}

fn decodeFrames(
    comptime Ev: type,
    arena: std.mem.Allocator,
    msg: []const u8,
    id: EventId,
    comptime readContact: anytype,
) Error!Ev {
    const Frame = @typeInfo(@FieldType(Ev, "frames")).pointer.child;
    const Contact = @typeInfo(@FieldType(Frame, "contacts")).pointer.child;
    var r = try body(msg, id);
    const encode_time = try readFourByteUnsigned(&r);
    const frames = try arena.alloc(Frame, try readCount(&r, min_frame_size));
    for (frames) |*f| {
        const n = try readTwoByteUnsigned(&r);
        const offset = try readEightByteUnsigned(&r);
        if (@as(usize, n) * min_contact_size > r.remaining()) return error.EndOfBuffer;
        const contacts = try arena.alloc(Contact, n);
        for (contacts) |*c| c.* = try readContact(&r);
        f.* = .{ .frame_offset = offset, .contacts = contacts };
    }
    if (r.remaining() != 0) return error.TrailingBytes;
    return .{ .encode_time = encode_time, .frames = frames };
}

pub fn encodeTouchEvent(w: *bytes.Writer, ev: TouchEvent) Error!void {
    try encodeFrames(w, .touch, ev.encode_time, ev.frames, writeTouchContact);
}

/// Frames and contacts are allocated from `arena` (free by resetting it).
pub fn decodeTouchEvent(arena: std.mem.Allocator, msg: []const u8) Error!TouchEvent {
    return decodeFrames(TouchEvent, arena, msg, .touch, readTouchContact);
}

pub fn encodePenEvent(w: *bytes.Writer, ev: PenEvent) Error!void {
    try encodeFrames(w, .pen, ev.encode_time, ev.frames, writePenContact);
}

pub fn decodePenEvent(arena: std.mem.Allocator, msg: []const u8) Error!PenEvent {
    return decodeFrames(PenEvent, arena, msg, .pen, readPenContact);
}

// --- SUSPEND / RESUME / DISMISS_HOVERING (2.2.3.4 - 2.2.3.6) -------------------------------

pub fn encodeSuspendInput(w: *bytes.Writer) Error!void {
    try encodeHeader(w, .suspend_input, header_size);
}

pub fn encodeResumeInput(w: *bytes.Writer) Error!void {
    try encodeHeader(w, .resume_input, header_size);
}

fn decodeBare(msg: []const u8, id: EventId) Error!void {
    const r = try body(msg, id);
    if (r.remaining() != 0) return error.BadLength;
}

pub fn decodeSuspendInput(msg: []const u8) Error!void {
    return decodeBare(msg, .suspend_input);
}

pub fn decodeResumeInput(msg: []const u8) Error!void {
    return decodeBare(msg, .resume_input);
}

pub fn encodeDismissHoveringTouchContact(w: *bytes.Writer, contact_id: u8) Error!void {
    try encodeHeader(w, .dismiss_hovering_touch_contact, header_size + 1);
    try w.byte(contact_id);
}

pub fn decodeDismissHoveringTouchContact(msg: []const u8) Error!u8 {
    var r = try body(msg, .dismiss_hovering_touch_contact);
    if (r.remaining() != 1) return error.BadLength;
    return r.byte();
}

pub const ClientPdu = union(enum) {
    cs_ready: CsReady,
    touch: TouchEvent,
    dismiss_hovering_touch_contact: u8,
    pen: PenEvent,
};

pub fn decodeClientPdu(arena: std.mem.Allocator, msg: []const u8) Error!ClientPdu {
    const h = try decodeHeader(msg);
    return switch (h.event_id) {
        .cs_ready => .{ .cs_ready = try decodeCsReady(msg) },
        .touch => .{ .touch = try decodeTouchEvent(arena, msg) },
        .dismiss_hovering_touch_contact => .{ .dismiss_hovering_touch_contact = try decodeDismissHoveringTouchContact(msg) },
        .pen => .{ .pen = try decodePenEvent(arena, msg) },
        else => error.UnexpectedEvent,
    };
}

pub const ServerPdu = union(enum) {
    sc_ready: ScReady,
    suspend_input,
    resume_input,
};

pub fn decodeServerPdu(msg: []const u8) Error!ServerPdu {
    const h = try decodeHeader(msg);
    switch (h.event_id) {
        .sc_ready => return .{ .sc_ready = try decodeScReady(msg) },
        .suspend_input => {
            try decodeSuspendInput(msg);
            return .suspend_input;
        },
        .resume_input => {
            try decodeResumeInput(msg);
            return .resume_input;
        },
        else => return error.UnexpectedEvent,
    }
}

pub fn validateContactFlags(flags: u32) Error!void {
    if (std.mem.indexOfScalar(u32, &valid_contact_flags, flags) == null) return error.InvalidContactFlags;
}

/// Contact flags, orientation <= 359, pressure <= 1024 (2.2.3.3.1.1).
pub fn validateTouchContact(c: TouchContact) Error!void {
    try validateContactFlags(c.contact_flags);
    if (c.orientation) |o| if (o > max_orientation) return error.OrientationOutOfRange;
    if (c.pressure) |p| if (p > max_pressure) return error.PressureOutOfRange;
}

/// Flags and ranges of 2.2.3.7.1.1; deviceId must be 0 unless `multipen`.
pub fn validatePenContact(c: PenContact, multipen: bool) Error!void {
    try validateContactFlags(c.contact_flags);
    if (c.device_id != 0 and !multipen) return error.DeviceIdNotNegotiated;
    if (c.pressure) |p| if (p > max_pressure) return error.PressureOutOfRange;
    if (c.rotation) |v| if (v > max_rotation) return error.RotationOutOfRange;
    if (c.tilt_x) |t| if (t < -max_tilt or t > max_tilt) return error.TiltOutOfRange;
    if (c.tilt_y) |t| if (t < -max_tilt or t > max_tilt) return error.TiltOutOfRange;
}

pub const ContactState = enum { out_of_range, hovering, engaged };

/// Contact state transition per figure 2 of 3.1.1.1.
pub fn transition(from: ContactState, flags: u32) Error!ContactState {
    const engage = contact_flag_down | contact_flag_inrange | contact_flag_incontact;
    const hover = contact_flag_update | contact_flag_inrange;
    const drag = contact_flag_update | contact_flag_inrange | contact_flag_incontact;
    const lift = contact_flag_up | contact_flag_inrange;
    const up = contact_flag_up;
    const up_canceled = contact_flag_up | contact_flag_canceled;
    const update = contact_flag_update;
    const update_canceled = contact_flag_update | contact_flag_canceled;
    return switch (from) {
        .out_of_range => switch (flags) {
            engage => .engaged,
            hover => .hovering,
            else => error.InvalidTransition,
        },
        .hovering => switch (flags) {
            hover => .hovering,
            engage => .engaged,
            update, update_canceled => .out_of_range,
            else => error.InvalidTransition,
        },
        .engaged => switch (flags) {
            drag => .engaged,
            lift => .hovering,
            up, up_canceled => .out_of_range,
            else => error.InvalidTransition,
        },
    };
}

pub const Outcome = enum {
    accepted,
    /// Broke the state machine (3.1.1.1): canceled (3.2.5.3), out of range until a new transaction.
    canceled,
    /// Out of range and the flags do not start a transaction.
    ignored,
};

/// Server-side state of every contact id (touch contactId or pen deviceId).
pub const Tracker = struct {
    state: [256]ContactState = @splat(.out_of_range),
    x: [256]i32 = @splat(0),
    y: [256]i32 = @splat(0),

    pub fn apply(t: *Tracker, id: u8, flags: u32, x: i32, y: i32) Error!Outcome {
        const from = t.state[id];
        const to = transition(from, flags) catch {
            if (from == .out_of_range) return .ignored;
            t.state[id] = .out_of_range;
            return .canceled;
        };
        // 3.1.1.1: a contact leaving the engaged state must not move.
        if (from == .engaged and to != .engaged and (x != t.x[id] or y != t.y[id])) {
            t.state[id] = .out_of_range;
            return .canceled;
        }
        t.state[id] = to;
        t.x[id] = x;
        t.y[id] = y;
        return .accepted;
    }

    /// 3.2.5.6: true when a hovering contact goes out of range.
    pub fn dismissHovering(t: *Tracker, id: u8) Error!bool {
        if (t.state[id] != .hovering) return false;
        t.state[id] = .out_of_range;
        return true;
    }

    pub fn stateOf(t: *const Tracker, id: u8) Error!ContactState {
        return t.state[id];
    }

    pub fn activeCount(t: *const Tracker) Error!usize {
        var n: usize = 0;
        for (t.state) |s| n += @intFromBool(s != .out_of_range);
        return n;
    }

    pub fn reset(t: *Tracker) Error!void {
        t.state = @splat(.out_of_range);
    }
};

// --- server endpoint (3.2) ---------------------------------------------------------------

pub const ServerOptions = struct {
    protocol_version: u32 = protocol_v300,
    /// One pen (deviceId 0) is injected, so no multipen injection.
    supported_features: ?u32 = 0,
};

pub const Event = union(enum) {
    ready: CsReady,
    touch: TouchEvent,
    pen: PenEvent,
    dismiss_hovering: u8,
};

pub const Server = struct {
    opts: ServerOptions = .{},
    state: State = .closed,
    client: ?CsReady = null,
    suspended: bool = false,

    pub const State = enum { closed, waiting_cs_ready, ready };

    /// Writes SC_READY (3.2.3, 3.2.5.1). error.UnexpectedPdu unless closed.
    pub fn start(s: *Server, w: *bytes.Writer) Error!void {
        if (s.state != .closed) return error.UnexpectedPdu;
        try encodeScReady(w, .{ .protocol_version = s.opts.protocol_version, .supported_features = s.opts.supported_features });
        s.state = .waiting_cs_ready;
    }

    /// Out-of-sequence or server-to-client PDUs are error.UnexpectedPdu (ignored,
    /// 3.1.5.1); PEN needs V200 on both sides. Errors leave the state unchanged.
    pub fn receive(s: *Server, arena: std.mem.Allocator, msg: []const u8) Error!Event {
        const h = try decodeHeader(msg);
        switch (h.event_id) {
            .cs_ready => {
                if (s.state != .waiting_cs_ready) return error.UnexpectedPdu;
                const c = try decodeCsReady(msg);
                s.client = c;
                s.state = .ready;
                return .{ .ready = c };
            },
            .touch => {
                if (s.state != .ready) return error.UnexpectedPdu;
                return .{ .touch = try decodeTouchEvent(arena, msg) };
            },
            .dismiss_hovering_touch_contact => {
                if (s.state != .ready) return error.UnexpectedPdu;
                return .{ .dismiss_hovering = try decodeDismissHoveringTouchContact(msg) };
            },
            .pen => {
                if (s.state != .ready or !try s.penAllowed()) return error.UnexpectedPdu;
                return .{ .pen = try decodePenEvent(arena, msg) };
            },
            else => return error.UnexpectedPdu,
        }
    }

    /// SUSPEND_INPUT (3.2.5.4); false if already suspended.
    pub fn suspendInput(s: *Server, w: *bytes.Writer) Error!bool {
        if (s.state != .ready) return error.UnexpectedPdu;
        if (s.suspended) return false;
        try encodeSuspendInput(w);
        s.suspended = true;
        return true;
    }

    /// RESUME_INPUT (3.2.5.5); false if not suspended.
    pub fn resumeInput(s: *Server, w: *bytes.Writer) Error!bool {
        if (s.state != .ready) return error.UnexpectedPdu;
        if (!s.suspended) return false;
        try encodeResumeInput(w);
        s.suspended = false;
        return true;
    }

    fn ready(s: *const Server) Error!CsReady {
        if (s.state != .ready) return error.UnexpectedPdu;
        return s.client orelse error.UnexpectedPdu;
    }

    /// min(server, client) protocol version; error.UnexpectedPdu before CS_READY.
    pub fn negotiatedVersion(s: *const Server) Error!u32 {
        return @min(s.opts.protocol_version, (try s.ready()).protocol_version);
    }

    /// Pen frames are allowed: both sides at least V200 (3.2.5.1, 3.3.5.1).
    pub fn penAllowed(s: *const Server) Error!bool {
        return try s.negotiatedVersion() >= protocol_v200;
    }

    /// The server advertised multipen injection with V300 and the client enabled it.
    pub fn multipen(s: *const Server) Error!bool {
        const c = try s.ready();
        if (try s.negotiatedVersion() < protocol_v300) return false;
        const features = s.opts.supported_features orelse return false;
        return features & sc_ready_multipen_injection_supported != 0 and
            c.flags & cs_ready_flags_enable_multipen_injection != 0;
    }

    /// frameOffset and encodeTime MUST be ignored (2.2.3.2).
    pub fn timestampsIgnored(s: *const Server) Error!bool {
        return (try s.ready()).flags & cs_ready_flags_disable_timestamp_injection != 0;
    }
};

/// One output (monitor) in virtual-desktop coordinates (primary at 0,0).
pub const Output = struct {
    left: i32,
    top: i32,
    width: u32,
    height: u32,
};

pub const Location = struct {
    output: u8,
    x: u32,
    y: u32,
};

fn axisDistance(v: i64, lo: i64, len: u32) i64 {
    if (v < lo) return lo - v;
    const hi = lo + len - 1;
    return if (v > hi) v - hi else 0;
}

/// Output containing (x, y) and the point relative to it; outside points clamp
/// onto the nearest output. Empty outputs are skipped; only the first 256 count.
pub fn locate(outputs: []const Output, x: i32, y: i32) Error!Location {
    var best: ?usize = null;
    var best_d: u128 = 0;
    for (outputs[0..@min(outputs.len, 256)], 0..) |o, i| {
        if (o.width == 0 or o.height == 0) continue;
        const dx: u128 = @intCast(axisDistance(x, o.left, o.width));
        const dy: u128 = @intCast(axisDistance(y, o.top, o.height));
        const d = dx * dx + dy * dy;
        if (best == null or d < best_d) {
            best = i;
            best_d = d;
            if (d == 0) break;
        }
    }
    const i = best orelse return error.NoOutputs;
    const o = outputs[i];
    const cx = std.math.clamp(@as(i64, x), o.left, @as(i64, o.left) + o.width - 1);
    const cy = std.math.clamp(@as(i64, y), o.top, @as(i64, o.top) + o.height - 1);
    return .{ .output = @intCast(i), .x = @intCast(cx - o.left), .y = @intCast(cy - o.top) };
}

/// linux/input-event-codes.h
pub const btn_left: u32 = 0x110;
pub const btn_right: u32 = 0x111;

pub const PointerEvent = union(enum) {
    /// zwlr_virtual_pointer_v1.motion_absolute on the pointer bound to `output`.
    motion: struct { output: u8, x: u32, y: u32, width: u32, height: u32 },
    button: struct { code: u32, pressed: bool },
    frame,
};

pub const max_events_per_contact = 3;

/// Pointer emulation when the uinput helper is unavailable (Hyprland has no virtual touch or
/// tablet protocol). The first active contact drives the pointer; pen barrel maps to BTN_RIGHT.
pub const Emulator = struct {
    outputs: [16]Output = undefined,
    output_count: usize = 0,
    touch: Tracker = .{},
    pen: Tracker = .{},
    owner: ?Owner = null,
    held: ?u32 = null,

    pub const Owner = struct { kind: Kind, id: u8 };
    pub const Kind = enum { touch, pen };

    /// error.NoOutputs without a usable output; at most 16 outputs.
    pub fn init(outputs: []const Output) Error!Emulator {
        if (outputs.len > 16) return error.ValueOutOfRange;
        _ = try locate(outputs, 0, 0);
        var e = Emulator{ .output_count = outputs.len };
        @memcpy(e.outputs[0..outputs.len], outputs);
        return e;
    }

    pub fn touchContact(e: *Emulator, c: TouchContact, out: *[max_events_per_contact]PointerEvent) Error![]const PointerEvent {
        return e.contact(.touch, c.contact_id, c.contact_flags, c.x, c.y, btn_left, out);
    }

    pub fn penContact(e: *Emulator, c: PenContact, out: *[max_events_per_contact]PointerEvent) Error![]const PointerEvent {
        const barrel = (c.pen_flags orelse 0) & pen_flag_barrel_pressed != 0;
        return e.contact(.pen, c.device_id, c.contact_flags, c.x, c.y, if (barrel) btn_right else btn_left, out);
    }

    fn isOwner(e: *const Emulator, kind: Kind, id: u8) bool {
        const o = e.owner orelse return false;
        return o.kind == kind and o.id == id;
    }

    fn contact(e: *Emulator, kind: Kind, id: u8, flags: u32, x: i32, y: i32, button: u32, out: *[max_events_per_contact]PointerEvent) Error![]const PointerEvent {
        const tr = if (kind == .touch) &e.touch else &e.pen;
        const from = tr.state[id];
        const nobody_active = try e.touch.activeCount() + try e.pen.activeCount() == 0;
        var n: usize = 0;
        switch (try tr.apply(id, flags, x, y)) {
            .ignored => return out[0..0],
            .canceled => {
                if (!e.isOwner(kind, id)) return out[0..0];
                e.owner = null;
                e.release(out, &n);
                return out[0..n];
            },
            .accepted => {},
        }
        const to = tr.state[id];
        if (e.owner == null and from == .out_of_range and to != .out_of_range and nobody_active)
            e.owner = .{ .kind = kind, .id = id };
        if (!e.isOwner(kind, id)) return out[0..0];
        switch (to) {
            .engaged => {
                try e.motion(out, &n, x, y);
                if (from != .engaged and e.held == null) {
                    out[n] = .{ .button = .{ .code = button, .pressed = true } };
                    n += 1;
                    e.held = button;
                }
                out[n] = .frame;
                n += 1;
            },
            .hovering => if (from == .engaged) {
                e.release(out, &n);
            } else {
                try e.motion(out, &n, x, y);
                out[n] = .frame;
                n += 1;
            },
            .out_of_range => {
                e.owner = null;
                if (from == .engaged) e.release(out, &n);
            },
        }
        return out[0..n];
    }

    fn motion(e: *const Emulator, out: *[max_events_per_contact]PointerEvent, n: *usize, x: i32, y: i32) Error!void {
        const outputs = e.outputs[0..e.output_count];
        const loc = try locate(outputs, x, y);
        const o = outputs[loc.output];
        out[n.*] = .{ .motion = .{ .output = loc.output, .x = loc.x, .y = loc.y, .width = o.width, .height = o.height } };
        n.* += 1;
    }

    fn release(e: *Emulator, out: *[max_events_per_contact]PointerEvent, n: *usize) void {
        const code = e.held orelse return;
        e.held = null;
        out[n.*] = .{ .button = .{ .code = code, .pressed = false } };
        out[n.* + 1] = .frame;
        n.* += 2;
    }

    /// DISMISS_HOVERING_TOUCH_CONTACT (3.2.5.6): a hovering owner loses the pointer.
    pub fn dismissHovering(e: *Emulator, id: u8) Error!void {
        if (try e.touch.dismissHovering(id) and e.isOwner(.touch, id)) e.owner = null;
    }

    /// Releases a held button and forgets every contact (suspend, close, disconnect).
    pub fn releaseAll(e: *Emulator, out: *[max_events_per_contact]PointerEvent) Error![]const PointerEvent {
        var n: usize = 0;
        e.release(out, &n);
        try e.touch.reset();
        try e.pen.reset();
        e.owner = null;
        return out[0..n];
    }
};

test {
    refAll(@This());
}

fn refAll(comptime T: type) void {
    inline for (comptime std.meta.declarations(T)) |name| {
        const d = @field(T, name);
        if (@TypeOf(d) == type) {
            switch (@typeInfo(d)) {
                .@"struct" => refAll(d),
                else => {},
            }
        } else _ = &d;
    }
}
