//! Shared-memory buffers: one memfd-backed wl_shm_pool split into equal wl_buffers.

const std = @import("std");
const wire = @import("wire.zig");
const sys = @import("sys.zig");
const P = wire.proto;

pub const Error = wire.Error;

pub const Buffer = struct {
    proxy: P.WlBuffer,
    data: []u8,
};

pub const BufferSet = struct {
    mem: sys.SharedMemory,
    pool: P.WlShmPool,
    buffers: [max_buffers]Buffer = undefined,
    count: usize,
    width: u32,
    height: u32,
    stride: u32,
    format: P.WlShm.Format,

    pub const max_buffers = 2;

    pub fn create(
        conn: *wire.Connection,
        shm: P.WlShm,
        count: usize,
        width: u32,
        height: u32,
        stride: u32,
        format: P.WlShm.Format,
    ) Error!BufferSet {
        std.debug.assert(count >= 1 and count <= max_buffers);
        if (width == 0 or height == 0 or width > 16384 or height > 16384 or stride < width * 4) return error.InvalidArgument;
        const one: usize = @as(usize, stride) * height;
        const total = one * count;
        if (total > std.math.maxInt(i32)) return error.InvalidArgument;
        var mem = try sys.SharedMemory.create("omastation-wl-shm", total);
        errdefer mem.destroy();
        const pool = try shm.createPool(conn, mem.fd, @intCast(total));
        var set: BufferSet = .{
            .mem = mem,
            .pool = pool,
            .count = count,
            .width = width,
            .height = height,
            .stride = stride,
            .format = format,
        };
        for (0..count) |k| {
            const off = k * one;
            set.buffers[k] = .{
                .proxy = try pool.createBuffer(conn, @intCast(off), @intCast(width), @intCast(height), @intCast(stride), format),
                .data = mem.data[off..][0..one],
            };
        }
        // Buffers keep the pool's memory alive on the compositor side.
        try pool.destroy(conn);
        return set;
    }

    pub fn matches(set: *const BufferSet, width: u32, height: u32, stride: u32, format: P.WlShm.Format) bool {
        return set.width == width and set.height == height and set.stride == stride and set.format == format;
    }

    pub fn destroy(set: *BufferSet, conn: *wire.Connection) void {
        for (set.buffers[0..set.count]) |b| b.proxy.destroy(conn) catch {};
        set.mem.destroy();
        set.* = undefined;
    }
};
