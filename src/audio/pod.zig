//! SPA PODs for PipeWire: the raw-audio EnumFormat (as spa_format_audio_raw_build
//! would; translate-c cannot use libspa's variadic inline builder) and mute params.
//! A POD is { u32 size; u32 type; } plus a body padded to 8 bytes, host byte order.

const std = @import("std");
const c = @import("c");

/// Room for any format built here (8 channel positions).
pub const max_size = 256;

pub const Error = error{
    /// 0 or more than 8 channels, or rate 0.
    InvalidArgument,
};

/// SPA channel positions (spa/param/audio/raw.h) for 1..8 channels, WAVE / SMPTE order.
pub fn positions(channels: u16) Error![]const u32 {
    const table = [_]u32{ c.SPA_AUDIO_CHANNEL_FL, c.SPA_AUDIO_CHANNEL_FR, c.SPA_AUDIO_CHANNEL_FC, c.SPA_AUDIO_CHANNEL_LFE, c.SPA_AUDIO_CHANNEL_RL, c.SPA_AUDIO_CHANNEL_RR, c.SPA_AUDIO_CHANNEL_SL, c.SPA_AUDIO_CHANNEL_SR };
    const mono = [_]u32{c.SPA_AUDIO_CHANNEL_MONO};
    return switch (channels) {
        1 => &mono,
        2...8 => table[0..channels],
        else => error.InvalidArgument,
    };
}

const Builder = struct {
    buf: []align(8) u8,
    len: usize = 0,

    fn put(b: *Builder, v: u32) void {
        std.mem.writeInt(u32, b.buf[b.len..][0..4], v, .native);
        b.len += 4;
    }

    fn pad(b: *Builder) void {
        while (b.len % 8 != 0) : (b.len += 1) b.buf[b.len] = 0;
    }

    fn propHeader(b: *Builder, key: u32, body_size: u32, ty: u32) void {
        b.put(key);
        b.put(0); // flags
        b.put(body_size);
        b.put(ty);
    }

    fn propId(b: *Builder, key: u32, v: u32) void {
        b.propHeader(key, 4, c.SPA_TYPE_Id);
        b.put(v);
        b.pad();
    }

    fn propInt(b: *Builder, key: u32, v: i32) void {
        b.propHeader(key, 4, c.SPA_TYPE_Int);
        b.put(@bitCast(v));
        b.pad();
    }
};

/// EnumFormat POD of S16LE raw audio, written to `buf`; returns the 8-aligned slice.
pub fn audioRawS16(buf: *align(8) [max_size]u8, rate: u32, channels: u16) Error![]align(8) const u8 {
    if (rate == 0 or rate > std.math.maxInt(i32)) return error.InvalidArgument;
    const pos = try positions(channels);
    var b: Builder = .{ .buf = buf };
    b.put(0); // object size, patched below
    b.put(c.SPA_TYPE_Object);
    b.put(c.SPA_TYPE_OBJECT_Format);
    b.put(c.SPA_PARAM_EnumFormat);
    b.propId(c.SPA_FORMAT_mediaType, c.SPA_MEDIA_TYPE_audio);
    b.propId(c.SPA_FORMAT_mediaSubtype, c.SPA_MEDIA_SUBTYPE_raw);
    b.propId(c.SPA_FORMAT_AUDIO_format, c.SPA_AUDIO_FORMAT_S16_LE);
    b.propInt(c.SPA_FORMAT_AUDIO_rate, @intCast(rate));
    b.propInt(c.SPA_FORMAT_AUDIO_channels, channels);
    b.propHeader(c.SPA_FORMAT_AUDIO_position, @intCast(8 + 4 * pos.len), c.SPA_TYPE_Array);
    b.put(4); // child: Id
    b.put(c.SPA_TYPE_Id);
    for (pos) |p| b.put(p);
    b.pad();
    std.mem.writeInt(u32, buf[0..4], @intCast(b.len - 8), .native);
    return buf[0..b.len];
}

/// The "name" of a default-node metadata value ({"name":"..."}, as
/// WirePlumber writes default.audio.sink), unescaped into `buf`; null when malformed or too long.
pub fn defaultNodeName(json: []const u8, buf: []u8) ?[]const u8 {
    var i = std.mem.indexOf(u8, json, "\"name\"") orelse return null;
    i += "\"name\"".len;
    while (i < json.len and (json[i] == ' ' or json[i] == '\t' or json[i] == '\n' or json[i] == '\r')) i += 1;
    if (i >= json.len or json[i] != ':') return null;
    i += 1;
    while (i < json.len and (json[i] == ' ' or json[i] == '\t' or json[i] == '\n' or json[i] == '\r')) i += 1;
    if (i >= json.len or json[i] != '"') return null;
    i += 1;
    var n: usize = 0;
    while (i < json.len) : (i += 1) {
        var ch = json[i];
        if (ch == '"') return if (n == 0) null else buf[0..n];
        if (ch == '\\') {
            i += 1;
            if (i >= json.len) return null;
            ch = switch (json[i]) {
                '"', '\\', '/' => json[i],
                else => return null, // \uXXXX and controls: not in node names
            };
        }
        if (n >= buf.len) return null;
        buf[n] = ch;
        n += 1;
    }
    return null;
}

test "defaultNodeName: WirePlumber's value, escapes, garbage" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("alsa_output.pci-0000_00_1f.3.analog-stereo", defaultNodeName("{ \"name\": \"alsa_output.pci-0000_00_1f.3.analog-stereo\" }", &buf).?);
    try std.testing.expectEqualStrings("a\"b", defaultNodeName("{\"name\":\"a\\\"b\"}", &buf).?);
    try std.testing.expectEqual(@as(?[]const u8, null), defaultNodeName("{\"name\":\"unterminated", &buf));
    try std.testing.expectEqual(@as(?[]const u8, null), defaultNodeName("{\"name\":42}", &buf));
    try std.testing.expectEqual(@as(?[]const u8, null), defaultNodeName("", &buf));
    try std.testing.expectEqual(@as(?[]const u8, null), defaultNodeName("{\"name\":\"\"}", &buf));
}

/// Props POD setting a node's mute (SPA_PROP_mute), for pw_node_set_param.
pub fn propsMute(buf: *align(8) [max_size]u8, mute: bool) []align(8) const u8 {
    var b: Builder = .{ .buf = buf };
    b.put(0); // object size, patched below
    b.put(c.SPA_TYPE_Object);
    b.put(c.SPA_TYPE_OBJECT_Props);
    b.put(c.SPA_PARAM_Props);
    b.propHeader(c.SPA_PROP_mute, 4, c.SPA_TYPE_Bool);
    b.put(@intFromBool(mute));
    b.pad();
    std.mem.writeInt(u32, buf[0..4], @intCast(b.len - 8), .native);
    return buf[0..b.len];
}

/// Value POD of property `key` of an Object of `obj_type`; null when absent or malformed.
pub fn objectProp(p: []const u8, obj_type: u32, key: u32) ?[]const u8 {
    if (p.len < 16) return null;
    const size = std.mem.readInt(u32, p[0..4], .native);
    if (std.mem.readInt(u32, p[4..8], .native) != c.SPA_TYPE_Object) return null;
    if (size < 8 or size > p.len - 8) return null;
    if (std.mem.readInt(u32, p[8..12], .native) != obj_type) return null;
    const end = 8 + @as(usize, size);
    var at: usize = 16;
    while (at + 16 <= end) {
        const k = std.mem.readInt(u32, p[at..][0..4], .native);
        const vsize = std.mem.readInt(u32, p[at + 8 ..][0..4], .native);
        const body = at + 16;
        if (vsize > end - body) return null;
        if (k == key) return p[at + 8 .. body + vsize];
        at = body + std.mem.alignForward(usize, vsize, 8);
    }
    return null;
}

fn scalar(v: ?[]const u8, ty: u32) ?u32 {
    const pod = v orelse return null;
    if (pod.len < 12) return null;
    if (std.mem.readInt(u32, pod[4..8], .native) != ty or std.mem.readInt(u32, pod[0..4], .native) < 4) return null;
    return std.mem.readInt(u32, pod[8..12], .native);
}

/// SPA_PROP_mute of a Props POD; null when absent.
pub fn propsMuteOf(p: []const u8) ?bool {
    const v = scalar(objectProp(p, c.SPA_TYPE_OBJECT_Props, c.SPA_PROP_mute), c.SPA_TYPE_Bool) orelse return null;
    return v != 0;
}

/// Fields of a Route parameter (spa/param/route.h).
pub const Route = struct {
    index: i32,
    /// The card profile device it serves (a sink's card.profile.device).
    device: i32,
    output: bool,
    mute: ?bool,
};

/// null when malformed or without index/device.
pub fn routeOf(p: []const u8) ?Route {
    const ty = c.SPA_TYPE_OBJECT_ParamRoute;
    const index = scalar(objectProp(p, ty, c.SPA_PARAM_ROUTE_index), c.SPA_TYPE_Int) orelse return null;
    const device = scalar(objectProp(p, ty, c.SPA_PARAM_ROUTE_device), c.SPA_TYPE_Int) orelse return null;
    const dir = scalar(objectProp(p, ty, c.SPA_PARAM_ROUTE_direction), c.SPA_TYPE_Id) orelse return null;
    const mute = if (objectProp(p, ty, c.SPA_PARAM_ROUTE_props)) |props| propsMuteOf(props) else null;
    return .{ .index = @bitCast(index), .device = @bitCast(device), .output = dir == c.SPA_DIRECTION_OUTPUT, .mute = mute };
}

/// Route POD setting the mute of route `index` on profile device `device` for
/// pw_device_set_param, with save false (desktop mixers set save true).
pub fn routeMute(buf: *align(8) [max_size]u8, index: i32, device: i32, mute: bool) []align(8) const u8 {
    var b: Builder = .{ .buf = buf };
    b.put(0); // object size, patched below
    b.put(c.SPA_TYPE_Object);
    b.put(c.SPA_TYPE_OBJECT_ParamRoute);
    b.put(c.SPA_PARAM_Route);
    b.propInt(c.SPA_PARAM_ROUTE_index, index);
    b.propInt(c.SPA_PARAM_ROUTE_device, device);
    b.propHeader(c.SPA_PARAM_ROUTE_props, 8 + 24, c.SPA_TYPE_Object);
    b.put(c.SPA_TYPE_OBJECT_Props);
    b.put(c.SPA_PARAM_Route);
    b.propHeader(c.SPA_PROP_mute, 4, c.SPA_TYPE_Bool);
    b.put(@intFromBool(mute));
    b.pad();
    b.propHeader(c.SPA_PARAM_ROUTE_save, 4, c.SPA_TYPE_Bool);
    b.put(0);
    b.pad();
    std.mem.writeInt(u32, buf[0..4], @intCast(b.len - 8), .native);
    return buf[0..b.len];
}

test "routeMute reads back as a Route with that mute (no direction: not a full Route)" {
    var buf: [max_size]u8 align(8) = undefined;
    const r = routeMute(&buf, 1, 3, true);
    try std.testing.expectEqual(@as(?u32, 1), scalar(objectProp(r, c.SPA_TYPE_OBJECT_ParamRoute, c.SPA_PARAM_ROUTE_index), c.SPA_TYPE_Int));
    try std.testing.expectEqual(@as(?bool, true), propsMuteOf(objectProp(r, c.SPA_TYPE_OBJECT_ParamRoute, c.SPA_PARAM_ROUTE_props).?));
    try std.testing.expectEqual(@as(?Route, null), routeOf(r));
    for (0..r.len) |n| _ = routeOf(r[0..n]); // never out of bounds
}

test "propsMute round trip; malformed Props give null" {
    var buf: [max_size]u8 align(8) = undefined;
    try std.testing.expectEqual(@as(?bool, true), propsMuteOf(propsMute(&buf, true)));
    try std.testing.expectEqual(@as(?bool, false), propsMuteOf(propsMute(&buf, false)));
    const good = propsMute(&buf, true);
    for (0..good.len) |n| _ = propsMuteOf(good[0..n]); // never out of bounds
    try std.testing.expectEqual(@as(?bool, null), propsMuteOf(good[0..20]));
    var fmt_buf: [max_size]u8 align(8) = undefined;
    try std.testing.expectEqual(@as(?bool, null), propsMuteOf(try audioRawS16(&fmt_buf, 48000, 2)));
}
