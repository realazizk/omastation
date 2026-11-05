//! Dmabuf allocation with libgbm for GPU capture (wl.dmabuf.Allocator): the compositor names a
//! device (dev_t) and the modifiers it takes; buffers get explicit modifiers only.

const std = @import("std");
const c = @import("c");
const wl = @import("../wl/wl.zig");
const dmabuf = wl.dmabuf;

const log = std.log.scoped(.gbm);

const Device = struct {
    dev: u64,
    fd: c_int,
    gbm: *c.struct_gbm_device,
};

pub const Gbm = struct {
    gpa: std.mem.Allocator,
    devices: std.ArrayList(Device) = .empty,
    /// Render node of the last device opened (logs, matching the encoder's node).
    node_buf: [32]u8 = undefined,
    node_len: usize = 0,
    /// Every buffer allocated holds the `unfilled` pattern until the compositor writes it (false
    /// when one could not be filled).
    marked: bool = true,
    /// Why the last allocation failed (`why`).
    why_buf: [200]u8 = undefined,
    why_len: usize = 0,

    pub fn init(gpa: std.mem.Allocator) Gbm {
        return .{ .gpa = gpa };
    }

    pub fn deinit(g: *Gbm) void {
        for (g.devices.items) |d| {
            c.gbm_device_destroy(d.gbm);
            _ = c.close(d.fd);
        }
        g.devices.deinit(g.gpa);
    }

    pub fn allocator(g: *Gbm) dmabuf.Allocator {
        return .{ .ctx = g, .allocFn = allocFn, .freeFn = freeFn, .whyFn = whyFn };
    }

    fn whyFn(ctx: *anyopaque) []const u8 {
        const g: *Gbm = @ptrCast(@alignCast(ctx));
        return g.why_buf[0..g.why_len];
    }

    fn fail(g: *Gbm, comptime fmt: []const u8, args: anytype) void {
        const text = std.fmt.bufPrint(&g.why_buf, fmt, args) catch g.why_buf[0..];
        g.why_len = text.len;
    }

    pub fn node(g: *const Gbm) []const u8 {
        return g.node_buf[0..g.node_len];
    }

    fn device(g: *Gbm, dev: u64) dmabuf.AllocError!*c.struct_gbm_device {
        for (g.devices.items) |d| if (d.dev == dev) return d.gbm;
        var path_buf: [64]u8 = undefined;
        var drv_buf: [64]u8 = undefined;
        const drv = driverName(dev, &drv_buf);
        const path = renderNode(dev, &path_buf) orelse {
            g.fail("no DRM render node for device {d}:{d} ({s})", .{ dmabuf.devMajor(dev), dmabuf.devMinor(dev), drv });
            return error.NoDevice;
        };
        const fd = c.open(path.ptr, c.O_RDWR | c.O_CLOEXEC);
        if (fd < 0) {
            g.fail("cannot open {s} ({s})", .{ path, drv });
            return error.NoDevice;
        }
        errdefer _ = c.close(fd);
        const gd = c.gbm_create_device(fd) orelse {
            g.fail("GBM cannot use {s} ({s})", .{ path, drv });
            return error.NoDevice;
        };
        errdefer c.gbm_device_destroy(gd);
        g.devices.append(g.gpa, .{ .dev = dev, .fd = fd, .gbm = gd }) catch return error.AllocFailed;
        g.node_len = @min(path.len, g.node_buf.len);
        @memcpy(g.node_buf[0..g.node_len], path[0..g.node_len]);
        log.info("dmabuf allocation on {s} ({s})", .{ path, std.mem.span(c.gbm_device_get_backend_name(gd)) });
        return gd;
    }

    fn allocFn(ctx: *anyopaque, dev: u64, width: u32, height: u32, format: u32, modifiers: []const u64) dmabuf.AllocError!dmabuf.Bo {
        const g: *Gbm = @ptrCast(@alignCast(ctx));
        for (modifiers) |m| if (m == dmabuf.mod_invalid) return error.Unsupported;
        const gd = try g.device(dev);
        // The compositor renders into it; LINEAR (when that is all we pass) also lets VA-API,
        // Vulkan and the CPU read it without a detiling blit.
        const bo = c.gbm_bo_create_with_modifiers2(gd, width, height, format, modifiers.ptr, @intCast(modifiers.len), c.GBM_BO_USE_RENDERING) orelse {
            var drv_buf: [64]u8 = undefined;
            const fourcc: [4]u8 = @bitCast(format);
            g.fail("GBM could not allocate a {d}x{d} {s} render buffer ({s}) on {s} ({s})", .{
                width,                                                                               height,   &fourcc,
                if (modifiers.len == 1 and modifiers[0] == dmabuf.mod_linear) "LINEAR" else "tiled", g.node(), driverName(dev, &drv_buf),
            });
            return error.AllocFailed;
        };
        errdefer c.gbm_bo_destroy(bo);
        const n = c.gbm_bo_get_plane_count(bo);
        if (n < 1 or n > 4) return error.AllocFailed;
        var out: dmabuf.Bo = .{
            .handle = bo,
            .width = width,
            .height = height,
            .format = format,
            .modifier = c.gbm_bo_get_modifier(bo),
            .nplanes = 0,
        };
        errdefer for (out.planes[0..out.nplanes]) |p| {
            _ = c.close(p.fd);
        };
        if (out.modifier == dmabuf.mod_invalid) {
            g.fail("GBM gave a buffer without an explicit layout on {s}", .{g.node()});
            return error.AllocFailed;
        }
        for (0..@intCast(n)) |i| {
            const fd = c.gbm_bo_get_fd_for_plane(bo, @intCast(i));
            if (fd < 0) return error.AllocFailed;
            out.planes[i] = .{ .fd = fd, .offset = c.gbm_bo_get_offset(bo, @intCast(i)), .stride = c.gbm_bo_get_stride_for_plane(bo, @intCast(i)) };
            out.nplanes += 1;
        }
        if (!mark(&out)) g.marked = false;
        return out;
    }

    fn freeFn(ctx: *anyopaque, bo: *dmabuf.Bo) void {
        _ = ctx;
        for (bo.planes[0..bo.nplanes]) |p| _ = c.close(p.fd);
        if (bo.handle) |h| c.gbm_bo_destroy(@ptrCast(@alignCast(h)));
        bo.nplanes = 0;
        bo.handle = null;
    }
};

/// The RGB of pixel (x, y) in a 32-bit buffer just allocated: a frame of only these is one the
/// compositor never wrote (some VM GPUs), and no real screen. The X byte is the driver's.
pub fn unfilled(x: u32, y: u32) u32 {
    return ((x *% 0x9E3779B1) ^ (y *% 0x85EBCA6B)) >> 8;
}

/// Fills a new 32-bit single-plane `bo` with the `unfilled` pattern; false if it cannot.
fn mark(bo: *const dmabuf.Bo) bool {
    if (bo.nplanes != 1 or (bo.format != dmabuf.format_xrgb8888 and bo.format != dmabuf.format_argb8888)) return false;
    const m = mapWrite(bo) orelse return false;
    defer unmap(bo, m.token);
    for (0..bo.height) |y| {
        const row = std.mem.bytesAsSlice(u32, @as([]align(1) u8, m.data[y * m.stride ..][0 .. @as(usize, bo.width) * 4]));
        for (row, 0..) |*px, x| px.* = unfilled(@intCast(x), @intCast(y));
    }
    return true;
}

/// Wait for the compositor's rendering into `bo` (its implicit write fence).
pub fn waitIdle(bo: *const dmabuf.Bo, timeout_ms: c_int) bool {
    var p: c.struct_pollfd = .{ .fd = bo.planes[0].fd, .events = c.POLLIN, .revents = 0 };
    return c.poll(&p, 1, timeout_ms) == 1;
}

/// Map `bo` for reading (slow for tiled or VRAM buffers: checks only, never per frame).
/// Returns the mapping and its stride; call `unmap` with the token.
pub fn mapRead(bo: *const dmabuf.Bo) ?struct { data: []const u8, stride: u32, token: ?*anyopaque } {
    const h: *c.struct_gbm_bo = @ptrCast(@alignCast(bo.handle orelse return null));
    var stride: u32 = 0;
    var token: ?*anyopaque = null;
    const p = c.gbm_bo_map(h, 0, 0, bo.width, bo.height, c.GBM_BO_TRANSFER_READ, &stride, &token) orelse return null;
    const base: [*]const u8 = @ptrCast(p);
    return .{ .data = base[0 .. @as(usize, stride) * bo.height], .stride = stride, .token = token };
}

/// Map `bo` for writing (tests: fill a buffer as a compositor would). Wait for the write with
/// `waitIdle` after `unmap`: drivers may finish it with a blit.
pub fn mapWrite(bo: *const dmabuf.Bo) ?struct { data: []u8, stride: u32, token: ?*anyopaque } {
    const h: *c.struct_gbm_bo = @ptrCast(@alignCast(bo.handle orelse return null));
    var stride: u32 = 0;
    var token: ?*anyopaque = null;
    const p = c.gbm_bo_map(h, 0, 0, bo.width, bo.height, c.GBM_BO_TRANSFER_WRITE, &stride, &token) orelse return null;
    const base: [*]u8 = @ptrCast(p);
    return .{ .data = base[0 .. @as(usize, stride) * bo.height], .stride = stride, .token = token };
}

/// The raw bytes of plane 0 through an mmap of the dmabuf itself (no driver blit, so the X byte
/// is what was written; slow for VRAM: checks only). Bracketed by DMA_BUF_IOCTL_SYNC.
pub fn readRaw(bo: *const dmabuf.Bo, out: []u8, row_bytes: usize) bool {
    const p = bo.planes[0];
    const size = @as(usize, p.offset) + @as(usize, p.stride) * bo.height;
    const m = std.c.mmap(null, size, .{ .READ = true }, .{ .TYPE = .SHARED }, p.fd, 0);
    if (m == std.c.MAP_FAILED) return false;
    defer _ = std.c.munmap(@alignCast(m), size);
    const sync_ioctl: c_ulong = 0x40086200; // DMA_BUF_IOCTL_SYNC
    var sync: u64 = 1; // DMA_BUF_SYNC_READ | DMA_BUF_SYNC_START
    _ = c.ioctl(p.fd, sync_ioctl, &sync);
    const base: [*]const u8 = @ptrCast(m);
    for (0..bo.height) |y| @memcpy(out[y * row_bytes ..][0..row_bytes], base[p.offset + y * p.stride ..][0..row_bytes]);
    sync = 1 | 4; // READ | END
    _ = c.ioctl(p.fd, sync_ioctl, &sync);
    return true;
}

pub fn unmap(bo: *const dmabuf.Bo, token: ?*anyopaque) void {
    const h: *c.struct_gbm_bo = @ptrCast(@alignCast(bo.handle orelse return));
    c.gbm_bo_unmap(h, token);
}

/// The kernel driver of a DRM device (amdgpu, i915, virtio_gpu...), "unknown driver" if unreadable.
pub fn driverName(dev: u64, buf: []u8) []const u8 {
    var path_buf: [80]u8 = undefined;
    const path = std.fmt.bufPrintSentinel(&path_buf, "/sys/dev/char/{d}:{d}/device/driver", .{ dmabuf.devMajor(dev), dmabuf.devMinor(dev) }, 0) catch return "unknown driver";
    const n = c.readlink(path.ptr, buf.ptr, buf.len);
    if (n <= 0) return "unknown driver";
    const link = buf[0..@intCast(n)];
    return if (std.mem.lastIndexOfScalar(u8, link, '/')) |i| link[i + 1 ..] else link;
}

/// /dev/dri/renderD<minor> for a render node dev_t; for a primary node (cardN), the render
/// node of the same GPU from sysfs.
pub fn renderNode(dev: u64, buf: []u8) ?[:0]const u8 {
    const major = dmabuf.devMajor(dev);
    const minor = dmabuf.devMinor(dev);
    if (major != 226) return null;
    if (minor >= 128) return std.fmt.bufPrintSentinel(buf, "/dev/dri/renderD{d}", .{minor}, 0) catch null;
    var dir_buf: [64]u8 = undefined;
    const dir_path = std.fmt.bufPrintSentinel(&dir_buf, "/sys/dev/char/{d}:{d}/device/drm", .{ major, minor }, 0) catch return null;
    const dir = c.opendir(dir_path.ptr) orelse return null;
    defer _ = c.closedir(dir);
    while (c.readdir(dir)) |ent| {
        const name = std.mem.sliceTo(&ent.*.d_name, 0);
        if (std.mem.startsWith(u8, name, "renderD")) return std.fmt.bufPrintSentinel(buf, "/dev/dri/{s}", .{name}, 0) catch null;
    }
    return null;
}

test "render node from a dev_t" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("/dev/dri/renderD129", renderNode(226 << 8 | 129, &buf).?);
    try std.testing.expectEqual(null, renderNode(8 << 8 | 1, &buf)); // not a DRM device
}
