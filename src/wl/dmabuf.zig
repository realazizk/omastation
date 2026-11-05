//! Dmabuf capture buffers: the compositor renders the frame into GPU memory the client allocated,
//! so it never copies the frame to RAM. Allocation is injected (`Allocator`): the GPU library
//! (GBM, src/gpu/gbm.zig) stays outside this pure-Zig client, and tests pass memfds.

const std = @import("std");
const wire = @import("wire.zig");
const sys = @import("sys.zig");
const P = wire.proto;

pub const Error = wire.Error || AllocError;
pub const AllocError = error{ AllocFailed, NoDevice, Unsupported };

/// DRM fourcc codes (drm_fourcc.h) of the 32-bit RGB formats capture accepts.
pub const format_xrgb8888: u32 = 0x34325258; // XR24: B,G,R,X bytes
pub const format_argb8888: u32 = 0x34325241; // AR24: B,G,R,A bytes
pub const format_xbgr8888: u32 = 0x34324258; // XB24: R,G,B,X bytes
pub const format_abgr8888: u32 = 0x34324241; // AB24: R,G,B,A bytes

pub const mod_linear: u64 = 0;
/// DRM_FORMAT_MOD_INVALID: "implicit layout". Never allocate with it: a buffer whose layout the
/// importer has to guess is how a GPU page fault happens.
pub const mod_invalid: u64 = 0x00ff_ffff_ffff_ffff;

/// The wl_shm format with the same memory layout (wl_shm's two legacy codes differ from DRM's).
pub fn shmFormat(drm: u32) P.WlShm.Format {
    return switch (drm) {
        format_xrgb8888 => .xrgb8888,
        format_argb8888 => .argb8888,
        else => @fromBackingInt(@intCast(drm)),
    };
}

pub const Plane = struct {
    fd: sys.Fd,
    offset: u32,
    stride: u32,
};

/// One allocated buffer. The allocator owns `handle` and the plane fds.
pub const Bo = struct {
    handle: ?*anyopaque = null,
    width: u32,
    height: u32,
    format: u32,
    modifier: u64,
    planes: [4]Plane = undefined,
    nplanes: u8,
};

pub const Allocator = struct {
    ctx: *anyopaque,
    /// `device`: the dev_t the compositor named (dmabuf_device); `modifiers`: those it accepts
    /// for `format`, never empty and never containing `mod_invalid`.
    allocFn: *const fn (ctx: *anyopaque, device: u64, width: u32, height: u32, format: u32, modifiers: []const u64) AllocError!Bo,
    freeFn: *const fn (ctx: *anyopaque, bo: *Bo) void,
    /// Why the last allocFn failed, in words (device, driver, what was asked); null: no detail.
    whyFn: ?*const fn (ctx: *anyopaque) []const u8 = null,

    pub fn why(a: *const Allocator) ?[]const u8 {
        const f = a.whyFn orelse return null;
        const text = f(a.ctx);
        return if (text.len == 0) null else text;
    }
};

/// The modifiers to allocate with: LINEAR alone when offered and preferred (every importer reads
/// it), else every explicit one offered (the allocator picks); none if only implicit is offered.
pub fn chooseModifiers(offered: []const u64, prefer_linear: bool, out: []u64) []const u64 {
    if (prefer_linear) for (offered) |m| if (m == mod_linear) {
        out[0] = mod_linear;
        return out[0..1];
    };
    var n: usize = 0;
    for (offered) |m| {
        if (m == mod_invalid or n == out.len) continue;
        out[n] = m;
        n += 1;
    }
    return out[0..n];
}

pub const BufferSet = struct {
    alloc: *const Allocator,
    bos: [max_buffers]Bo = undefined,
    proxies: [max_buffers]P.WlBuffer = undefined,
    count: usize,
    width: u32,
    height: u32,
    format: u32,

    pub const max_buffers = 4;

    pub fn create(
        conn: *wire.Connection,
        linux_dmabuf: P.ZwpLinuxDmabufV1,
        alloc: *const Allocator,
        device: u64,
        count: usize,
        width: u32,
        height: u32,
        format: u32,
        modifiers: []const u64,
    ) Error!BufferSet {
        std.debug.assert(count >= 1 and count <= max_buffers);
        if (width == 0 or height == 0 or width > 16384 or height > 16384 or modifiers.len == 0) return error.InvalidArgument;
        var set: BufferSet = .{ .alloc = alloc, .count = 0, .width = width, .height = height, .format = format };
        var nproxies: usize = 0;
        errdefer {
            for (set.proxies[0..nproxies]) |p| p.destroy(conn) catch {};
            for (set.bos[0..set.count]) |*bo| alloc.freeFn(alloc.ctx, bo);
        }
        for (0..count) |k| {
            set.bos[k] = try alloc.allocFn(alloc.ctx, device, width, height, format, modifiers);
            set.count = k + 1;
            const bo = &set.bos[k];
            if (bo.modifier == mod_invalid or bo.nplanes == 0 or bo.nplanes > 4) return error.AllocFailed;
            const params = try linux_dmabuf.createParams(conn);
            for (bo.planes[0..bo.nplanes], 0..) |p, i| {
                try params.add(conn, p.fd, @intCast(i), p.offset, p.stride, @truncate(bo.modifier >> 32), @truncate(bo.modifier));
            }
            // Only formats and modifiers the capture session advertised get here, so create_immed
            // (no failure event to wait for) is safe.
            set.proxies[k] = try params.createImmed(conn, @intCast(width), @intCast(height), format, 0);
            nproxies = k + 1;
            try params.destroy(conn);
        }
        return set;
    }

    pub fn stride(set: *const BufferSet) u32 {
        return set.bos[0].planes[0].stride;
    }

    pub fn modifier(set: *const BufferSet) u64 {
        return set.bos[0].modifier;
    }

    pub fn matches(set: *const BufferSet, width: u32, height: u32, format: u32) bool {
        return set.width == width and set.height == height and set.format == format;
    }

    pub fn destroy(set: *BufferSet, conn: *wire.Connection) void {
        for (set.proxies[0..set.count]) |p| p.destroy(conn) catch {};
        for (set.bos[0..set.count]) |*bo| set.alloc.freeFn(set.alloc.ctx, bo);
        set.* = undefined;
    }
};

/// dmabuf_device carries a dev_t as raw bytes in host order.
pub fn parseDevice(bytes: []const u8) ?u64 {
    if (bytes.len != @sizeOf(u64)) return null;
    return std.mem.bytesToValue(u64, bytes[0..8]);
}

/// glibc's major()/minor() for a Linux dev_t.
pub fn devMajor(dev: u64) u32 {
    return @truncate(((dev >> 8) & 0xfff) | ((dev >> 32) & ~@as(u64, 0xfff)));
}

pub fn devMinor(dev: u64) u32 {
    return @truncate((dev & 0xff) | ((dev >> 12) & ~@as(u64, 0xff)));
}

test "modifier choice: linear first, never implicit" {
    var out: [8]u64 = undefined;
    const tiled: u64 = 0x0200_0000_1234_5678;
    try std.testing.expectEqualSlices(u64, &.{mod_linear}, chooseModifiers(&.{ tiled, mod_linear }, true, &out));
    try std.testing.expectEqualSlices(u64, &.{ tiled, mod_linear }, chooseModifiers(&.{ tiled, mod_invalid, mod_linear }, false, &out));
    try std.testing.expectEqual(0, chooseModifiers(&.{mod_invalid}, true, &out).len);
}

test "dev_t split and shm format mapping" {
    // makedev(226, 128) = 0xe280
    try std.testing.expectEqual(226, devMajor(0xe280));
    try std.testing.expectEqual(128, devMinor(0xe280));
    try std.testing.expectEqual(0xe280, parseDevice(&std.mem.toBytes(@as(u64, 0xe280))).?);
    try std.testing.expectEqual(null, parseDevice(&.{ 1, 2, 3 }));
    try std.testing.expectEqual(P.WlShm.Format.xrgb8888, shmFormat(format_xrgb8888));
    try std.testing.expectEqual(P.WlShm.Format.argb8888, shmFormat(format_argb8888));
    try std.testing.expectEqual(P.WlShm.Format.xbgr8888, shmFormat(format_xbgr8888));
}
