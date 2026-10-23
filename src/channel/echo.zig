//! MS-RDPEECO echo and MS-RDPEGT geometry tracking dynamic channels.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{
    EndOfBuffer,
    /// An Echo Response that matches no outstanding Echo Request.
    UnexpectedResponse,
    /// cbGeometryData or cbGeometryBuffer disagrees with the message length.
    BadLength,
    /// A field violates MS-RDPEGT 2.2.1.1.
    InvalidField,
    BadRegion,
    /// GEOMETRY_CLEAR for an unknown mapping (MS-RDPEGT 3.1.3).
    UnknownMapping,
    OutOfMemory,
};

pub const channel_name = "ECHO";

pub fn encodeEchoRequest(w: *bytes.Writer, payload: []const u8) !void {
    try w.bytes(payload);
}

pub fn decodeEchoResponse(msg: []const u8) Error![]const u8 {
    return msg;
}

/// Responses must echo the oldest outstanding request.
pub const EchoServer = struct {
    gpa: Allocator,
    outstanding: std.ArrayList(struct { payload: []u8, sent_ms: u64 }) = .empty,

    pub fn init(gpa: Allocator) Error!EchoServer {
        return .{ .gpa = gpa };
    }

    pub fn deinit(s: *EchoServer) void {
        for (s.outstanding.items) |o| s.gpa.free(o.payload);
        s.outstanding.deinit(s.gpa);
    }

    pub fn request(s: *EchoServer, w: *bytes.Writer, payload: []const u8, now_ms: u64) !void {
        const copy = try s.gpa.dupe(u8, payload);
        errdefer s.gpa.free(copy);
        try s.outstanding.append(s.gpa, .{ .payload = copy, .sent_ms = now_ms });
        errdefer _ = s.outstanding.pop();
        try encodeEchoRequest(w, payload);
    }

    /// Returns the round-trip time in milliseconds.
    pub fn onResponse(s: *EchoServer, msg: []const u8, now_ms: u64) Error!u64 {
        const echoed = try decodeEchoResponse(msg);
        if (s.outstanding.items.len == 0) return error.UnexpectedResponse;
        const oldest = s.outstanding.items[0];
        if (!std.mem.eql(u8, oldest.payload, echoed)) return error.UnexpectedResponse;
        _ = s.outstanding.orderedRemove(0);
        s.gpa.free(oldest.payload);
        return now_ms -| oldest.sent_ms;
    }

    pub fn pending(s: *const EchoServer) Error!usize {
        return s.outstanding.items.len;
    }
};

pub const geometry_channel_name = "Microsoft::Windows::RDS::Geometry::v08.01";

pub const geometry_version: u32 = 0x00000001;
pub const geometry_update: u32 = 0x00000001;
pub const geometry_clear: u32 = 0x00000002;
pub const geometry_type_region: u32 = 0x00000002;

/// RGNDATAHEADER (MSDN): dwSize 32, iType RDH_RECTANGLES.
pub const rgndataheader_size: u32 = 32;
pub const rdh_rectangles: u32 = 1;

/// MAPPED_GEOMETRY_PACKET without pGeometryBuffer and Reserved.
pub const fixed_size: usize = 72;

const rect_size: usize = 16;

pub const Rect32 = struct { left: i32, top: i32, right: i32, bottom: i32 };

/// RGNDATA: rcBound and the rectangles (relative to the tracked rectangle).
pub const Region = struct { bound: Rect32, rects: []const Rect32 };

pub const GeometryUpdate = struct {
    mapping_id: u64,
    /// The top-level window (0 outside window tracking mode).
    top_level_id: u64,
    /// Tracked rectangle, relative to the top-level rectangle.
    rect: Rect32,
    /// In virtual desktop coordinates.
    top_level: Rect32,
    region: ?Region,
};

pub const MappedGeometry = union(enum) {
    update: GeometryUpdate,
    clear: struct { mapping_id: u64 },
};

fn validRect(r: Rect32) bool {
    return r.left <= r.right and r.top <= r.bottom;
}

fn writeRect(w: *bytes.Writer, r: Rect32) !void {
    try w.u32le(@bitCast(r.left));
    try w.u32le(@bitCast(r.top));
    try w.u32le(@bitCast(r.right));
    try w.u32le(@bitCast(r.bottom));
}

fn readRect(r: *bytes.Reader) Error!Rect32 {
    return .{
        .left = @bitCast(try r.u32le()),
        .top = @bitCast(try r.u32le()),
        .right = @bitCast(try r.u32le()),
        .bottom = @bitCast(try r.u32le()),
    };
}

fn regionSize(r: Region) error{BadLength}!u32 {
    const n = std.math.mul(usize, r.rects.len, rect_size) catch return error.BadLength;
    const total = std.math.add(usize, n, rgndataheader_size) catch return error.BadLength;
    // cbGeometryData (u32) also counts the fixed fields.
    if (total > std.math.maxInt(u32) - fixed_size) return error.BadLength;
    return @intCast(total);
}

pub fn encodeMappedGeometry(w: *bytes.Writer, g: MappedGeometry) !void {
    switch (g) {
        .update => |u| {
            if (!validRect(u.rect) or !validRect(u.top_level)) return error.InvalidField;
            const cb_buffer: u32 = if (u.region) |r| try regionSize(r) else 0;
            try w.u32le(@as(u32, fixed_size) + cb_buffer); // cbGeometryData
            try w.u32le(geometry_version);
            try w.u64le(u.mapping_id);
            try w.u32le(geometry_update);
            try w.u32le(0); // Flags
            try w.u64le(u.top_level_id);
            try writeRect(w, u.rect);
            try writeRect(w, u.top_level);
            try w.u32le(geometry_type_region);
            try w.u32le(cb_buffer);
            if (u.region) |r| try encodeRegion(w, r);
            try w.byte(0); // Reserved
        },
        .clear => |c| {
            try w.u32le(@intCast(fixed_size));
            try w.u32le(geometry_version);
            try w.u64le(c.mapping_id);
            try w.u32le(geometry_clear);
            try w.zeros(fixed_size - 20 + 1); // Flags .. cbGeometryBuffer, Reserved
        },
    }
}

/// A decoded packet; region rectangles are allocated (free with deinit).
pub const DecodedGeometry = struct {
    geometry: MappedGeometry,

    pub fn deinit(d: *DecodedGeometry, gpa: Allocator) void {
        switch (d.geometry) {
            .update => |u| if (u.region) |r| gpa.free(r.rects),
            .clear => {},
        }
        d.* = undefined;
    }
};

pub fn decodeMappedGeometry(gpa: Allocator, msg: []const u8) Error!DecodedGeometry {
    var r = bytes.Reader.init(msg);
    const cb_data = try r.u32le();
    // cbGeometryData is the message without the Reserved byte (4.1, 4.2).
    if (cb_data < fixed_size or @as(u64, cb_data) + 1 != msg.len) return error.BadLength;
    const version = try r.u32le();
    const mapping_id = try r.u64le();
    const update_type = try r.u32le();
    if (version != geometry_version) return error.InvalidField;
    switch (update_type) {
        geometry_clear => return .{ .geometry = .{ .clear = .{ .mapping_id = mapping_id } } },
        geometry_update => {},
        else => return error.InvalidField,
    }
    if (try r.u32le() != 0) return error.InvalidField; // Flags
    const top_level_id = try r.u64le();
    const rect = try readRect(&r);
    const top_level = try readRect(&r);
    if (try r.u32le() != geometry_type_region) return error.InvalidField;
    if (!validRect(rect) or !validRect(top_level)) return error.InvalidField;
    const cb_buffer = try r.u32le();
    if (@as(u64, fixed_size) + cb_buffer != cb_data) return error.BadLength;
    const region: ?Region = if (cb_buffer == 0) null else try decodeRegion(gpa, try r.bytes(cb_buffer));
    return .{ .geometry = .{ .update = .{
        .mapping_id = mapping_id,
        .top_level_id = top_level_id,
        .rect = rect,
        .top_level = top_level,
        .region = region,
    } } };
}

fn decodeRegion(gpa: Allocator, buf: []const u8) Error!Region {
    var r = bytes.Reader.init(buf);
    if (buf.len < rgndataheader_size) return error.BadRegion;
    if (try r.u32le() != rgndataheader_size) return error.BadRegion;
    if (try r.u32le() != rdh_rectangles) return error.BadRegion;
    const count = try r.u32le();
    _ = try r.u32le(); // nRgnSize: a size hint, zero in 4.1.1
    const bound = try readRect(&r);
    if (@as(u64, count) * rect_size > r.remaining()) return error.BadRegion;
    const rects = try gpa.alloc(Rect32, count);
    errdefer gpa.free(rects);
    for (rects) |*rc| rc.* = try readRect(&r);
    return .{ .bound = bound, .rects = rects };
}

/// RGNDATA on its own (header with nRgnSize zero, as MS-RDPEGT 4.1.1).
pub fn encodeRegion(w: *bytes.Writer, r: Region) !void {
    _ = try regionSize(r);
    try w.u32le(rgndataheader_size);
    try w.u32le(rdh_rectangles);
    try w.u32le(@intCast(r.rects.len));
    try w.u32le(0); // nRgnSize
    try writeRect(w, r.bound);
    for (r.rects) |rc| try writeRect(w, rc);
}

/// Tracks active mapping IDs; clears are sent only for known IDs (MS-RDPEGT 2.2.1.1, 3.1.3).
pub const GeometryTracker = struct {
    gpa: Allocator,
    active: std.AutoHashMapUnmanaged(u64, void) = .empty,

    pub fn init(gpa: Allocator) Error!GeometryTracker {
        return .{ .gpa = gpa };
    }

    pub fn deinit(t: *GeometryTracker) void {
        t.active.deinit(t.gpa);
    }

    pub fn update(t: *GeometryTracker, w: *bytes.Writer, u: GeometryUpdate) !void {
        try t.active.ensureUnusedCapacity(t.gpa, 1);
        try encodeMappedGeometry(w, .{ .update = u });
        t.active.putAssumeCapacity(u.mapping_id, {});
    }

    pub fn clear(t: *GeometryTracker, w: *bytes.Writer, mapping_id: u64) !void {
        if (!t.active.contains(mapping_id)) return error.UnknownMapping;
        try encodeMappedGeometry(w, .{ .clear = .{ .mapping_id = mapping_id } });
        _ = t.active.remove(mapping_id);
    }

    pub fn isActive(t: *const GeometryTracker, mapping_id: u64) Error!bool {
        return t.active.contains(mapping_id);
    }
};

test {
    std.testing.refAllDecls(@This());
}
