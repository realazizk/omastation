//! Change detection on the GPU for frames captured into dmabufs, the twin of Encoder.diff: per
//! 64x64 tile, the exact bounding box of the pixels that differ from the previously processed
//! frame, and the changed tiles copied into host-visible (cached) memory, the only pixels that
//! reach the CPU. Encoder.applyTileDiff turns that into the encoder's runs and shadow.
//!
//! The capture ring's buffers are imported once each (keyed by the dmabuf's inode); the last
//! processed one stays the reference, so the capture must not write it while it is (see
//! wl.Capture.pin). A run without a reference (first frame, new ring or size, `forget`) or asked
//! `full` copies every tile and reports nothing: the caller diffs that copy on the CPU.

const std = @import("std");
const c = @import("c");
const vk = @import("vk.zig");
const dmabuf = @import("../wl/dmabuf.zig");
const sys = @import("../wl/sys.zig");

const log = std.log.scoped(.gpu);

pub const Error = vk.Error;

pub const tile: u32 = 64;

/// left, top, right, bottom of the changed pixels relative to the tile; right == 0: unchanged.
pub const TileBox = [4]u32;

/// One pixel a thread; and four (16-byte accesses) for 16-byte aligned rows.
const spv = vk.spirv(@embedFile("shaders/tilediff.spv"));
const spv4 = vk.spirv(@embedFile("shaders/tilediff4.spv"));

const Params = extern struct {
    width: u32,
    height: u32,
    cur_offset: u32,
    cur_stride: u32,
    prev_offset: u32,
    prev_stride: u32,
    tiles_x: u32,
    mode: u32,
};

/// The pass's job: diff against the reference, copy every tile, or copy the tiles a mask flags
/// (bringing lagging shadow tiles in).
const Mode = enum(u32) { diff = 0, full = 1, fresh = 2 };

/// Changed tiles not to copy (lazy readback: H.264 codes them from the GPU), per tile.
pub const Skip = union(enum) {
    none,
    all,
    some: []const bool,
};

const Input = union(enum) {
    dmabuf: vk.DmabufBuffer,
    /// Tests: a frame the CPU writes.
    host: vk.HostBuffer,

    fn buffer(i: *const Input) c.VkBuffer {
        return switch (i.*) {
            inline else => |*b| b.buffer,
        };
    }
};

const Slot = struct {
    /// st_dev, st_ino of the dmabuf (0, index for host slots).
    key: [2]u64,
    input: Input,
    /// In 32-bit words.
    offset: u32,
    stride: u32,
};

/// Where changed tiles go: host-visible staging, or the encoder's shadow imported as host memory
/// (`useShadow`; then the CPU copies nothing). A full copy always goes to staging: diffing it
/// needs the old shadow.
pub const Target = enum { staging, shadow };

pub const Result = struct {
    /// Every tile was copied and `boxes` is empty: diff `pixels` on the CPU.
    full: bool,
    /// The changed tiles were written into the shadow (`pixels` is not theirs).
    in_shadow: bool,
    boxes: []const TileBox,
    /// The frame's changed tiles (all of them when `full`) at their place; rows `stride` apart.
    pixels: []const u8,
    stride: usize,
};

pub const TileDiff = struct {
    dev: *const vk.Device,
    shader: c.VkShaderModule = null,
    shader4: c.VkShaderModule = null,
    set_layout: c.VkDescriptorSetLayout = null,
    layout: c.VkPipelineLayout = null,
    pipeline: c.VkPipeline = null,
    pipeline4: c.VkPipeline = null,
    cmd_pool: c.VkCommandPool = null,
    cmd: c.VkCommandBuffer = null,
    fence: c.VkFence = null,
    width: u32 = 0,
    height: u32 = 0,
    tiles_x: u32 = 0,
    tiles_y: u32 = 0,
    boxes: vk.HostBuffer = .{},
    staging: vk.HostBuffer = .{},
    /// Per tile u32: diff skips copying it; fresh copies it.
    mask: vk.HostBuffer = .{},
    slots: [max_slots]Slot = undefined,
    nslots: usize = 0,
    /// Generation of the capture ring the slots belong to.
    ring: ?u32 = null,
    /// The slot of the last frame processed: what the next one is compared with.
    prev: ?usize = null,
    /// Set by the caller after the encoder took a result (Encoder.gpu_token); 0: none yet.
    token: u64 = 0,
    /// The encoder's shadow imported as host memory, for (address, length, generation) `shadow_key`;
    /// a key that failed to import is not tried again.
    shadow: ?vk.HostPointerBuffer = null,
    shadow_key: [3]usize = .{ 0, 0, 0 },
    shadow_failed: bool = false,
    /// Waits for the compositor's rendering on the GPU (sync_file); else on the CPU (poll).
    wait_sem: c.VkSemaphore = null,
    gpu_waits: u64 = 0,
    cpu_waits: u64 = 0,
    /// Timing (when the queue has timestamps): GPU time of the waits plus the pass, of the pass
    /// alone, and submit to fence on the CPU, summed over runs.
    queries: c.VkQueryPool = null,
    gpu_total_ns: f64 = 0,
    gpu_pass_ns: f64 = 0,
    cpu_fence_ns: u64 = 0,
    timed_runs: u64 = 0,
    /// Tiles brought into the shadow by `freshenTiles`, summed.
    freshened: u64 = 0,
    /// The passes that brought them in.
    fresh_passes: u64 = 0,
    /// CPU time in runDmabuf before the submit (import lookup, fence export, recording).
    cpu_prep_ns: u64 = 0,
    prep_start: u64 = 0,

    pub const max_slots = 6;

    pub fn create(gpa: std.mem.Allocator, dev: *const vk.Device) Error!*TileDiff {
        const td = try gpa.create(TileDiff);
        errdefer gpa.destroy(td);
        td.* = .{ .dev = dev };
        errdefer td.release();
        const d = dev.dev;

        td.shader = try vk.shaderModule(dev, &spv);
        td.shader4 = try vk.shaderModule(dev, &spv4);
        const sb = c.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        try vk.passLayouts(dev, &.{ sb, sb, sb, sb, sb }, @sizeOf(Params), &td.set_layout, &td.layout);
        td.pipeline = try vk.computePipeline(dev, td.shader, td.layout);
        td.pipeline4 = try vk.computePipeline(dev, td.shader4, td.layout);
        try vk.passCommands(dev, &td.cmd_pool, &td.cmd, &td.fence, &td.queries, 3);
        if (dev.import_semaphore_fd != null) {
            var sci = std.mem.zeroes(c.VkSemaphoreCreateInfo);
            sci.sType = c.VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
            try vk.check(c.vkCreateSemaphore(d, &sci, null, &td.wait_sem), "vkCreateSemaphore");
        }
        return td;
    }

    pub fn destroy(td: *TileDiff, gpa: std.mem.Allocator) void {
        td.release();
        gpa.destroy(td);
    }

    fn release(td: *TileDiff) void {
        const d = td.dev.dev;
        _ = c.vkQueueWaitIdle(td.dev.queue);
        td.dropSlots();
        td.dropShadow();
        td.boxes.destroy(td.dev);
        td.staging.destroy(td.dev);
        td.mask.destroy(td.dev);
        if (td.wait_sem != null) c.vkDestroySemaphore(d, td.wait_sem, null);
        if (td.queries != null) c.vkDestroyQueryPool(d, td.queries, null);
        if (td.fence != null) c.vkDestroyFence(d, td.fence, null);
        if (td.cmd_pool != null) c.vkDestroyCommandPool(d, td.cmd_pool, null);
        if (td.pipeline != null) c.vkDestroyPipeline(d, td.pipeline, null);
        if (td.pipeline4 != null) c.vkDestroyPipeline(d, td.pipeline4, null);
        if (td.layout != null) c.vkDestroyPipelineLayout(d, td.layout, null);
        if (td.set_layout != null) c.vkDestroyDescriptorSetLayout(d, td.set_layout, null);
        if (td.shader != null) c.vkDestroyShaderModule(d, td.shader, null);
        if (td.shader4 != null) c.vkDestroyShaderModule(d, td.shader4, null);
    }

    fn dropSlots(td: *TileDiff) void {
        for (td.slots[0..td.nslots]) |*s| switch (s.input) {
            .dmabuf => |*b| b.destroy(td.dev),
            .host => |*b| b.destroy(td.dev),
        };
        td.nslots = 0;
        td.prev = null;
    }

    /// The next run has no reference (copies everything).
    pub fn forget(td: *TileDiff) void {
        td.prev = null;
    }

    /// Release the shadow import (before its memory is freed).
    pub fn dropShadow(td: *TileDiff) void {
        if (td.shadow) |*b| {
            _ = c.vkQueueWaitIdle(td.dev.queue);
            b.destroy(td.dev);
        }
        td.shadow = null;
        td.shadow_key = .{ 0, 0, 0 };
    }

    /// Import the encoder's shadow allocation `mem` (generation `gen`) as the `.shadow` target;
    /// false when this device or this memory cannot (then use `.staging`). A new allocation
    /// replaces the old import before any further GPU work.
    pub fn useShadow(td: *TileDiff, mem: []u8, gen: u32) bool {
        const key = [3]usize{ @intFromPtr(mem.ptr), mem.len, gen };
        if (std.mem.eql(usize, &key, &td.shadow_key)) return td.shadow != null;
        td.dropShadow();
        td.shadow_key = key;
        td.shadow_failed = false;
        td.shadow = vk.HostPointerBuffer.import(td.dev, mem) catch |e| {
            if (!td.shadow_failed) log.info("changed tiles go through staging: the shadow cannot be imported ({t})", .{e});
            td.shadow_failed = true;
            return false;
        };
        return true;
    }

    /// Output buffers for `w`x`h`; a new size drops the imports and the reference.
    fn ensureSize(td: *TileDiff, w: u32, h: u32) Error!void {
        if (w == td.width and h == td.height) return;
        _ = c.vkQueueWaitIdle(td.dev.queue);
        td.dropSlots();
        td.boxes.destroy(td.dev);
        td.staging.destroy(td.dev);
        td.mask.destroy(td.dev);
        td.width = 0;
        td.height = 0;
        const tx = (w + tile - 1) / tile;
        const ty = (h + tile - 1) / tile;
        td.boxes = try vk.HostBuffer.create(td.dev, @as(usize, tx) * ty * @sizeOf(TileBox), c.VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);
        td.staging = try vk.HostBuffer.create(td.dev, @as(usize, w) * h * 4, c.VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);
        td.mask = try vk.HostBuffer.create(td.dev, @as(usize, tx) * ty * 4, c.VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);
        td.width = w;
        td.height = h;
        td.tiles_x = tx;
        td.tiles_y = ty;
    }

    /// Diff a buffer of capture ring generation `ring` (LINEAR, one plane, 32-bit pixels)
    /// against the previous frame processed. Waits for the compositor's rendering into it first
    /// (its implicit fence).
    pub fn runDmabuf(td: *TileDiff, bo: *const dmabuf.Bo, ring: u32, full: bool, target: Target, skip: Skip) Error!Result {
        td.prep_start = nowNs();
        if (bo.nplanes != 1 or bo.modifier != dmabuf.mod_linear) return error.Unsupported;
        const p = bo.planes[0];
        if (p.offset % 4 != 0 or p.stride % 4 != 0 or p.stride < bo.width * 4) return error.Unsupported;
        try td.ensureSize(bo.width, bo.height);
        if (td.ring != ring) {
            // A new ring: the old buffers (and the reference among them) are gone.
            _ = c.vkQueueWaitIdle(td.dev.queue);
            td.dropSlots();
            td.ring = ring;
        }
        var st: c.struct_stat = undefined;
        if (c.fstat(p.fd, &st) != 0) return error.VulkanFailed;
        const key = [2]u64{ @intCast(st.st_dev), @intCast(st.st_ino) };
        const idx = for (td.slots[0..td.nslots], 0..) |s, i| {
            if (s.key[0] == key[0] and s.key[1] == key[1]) break i;
        } else blk: {
            if (td.nslots == max_slots) td.dropSlots();
            const size = @as(usize, p.offset) + @as(usize, p.stride) * bo.height;
            td.slots[td.nslots] = .{ .key = key, .input = .{ .dmabuf = try vk.DmabufBuffer.import(td.dev, p.fd, size) }, .offset = p.offset / 4, .stride = p.stride / 4 };
            td.nslots += 1;
            break :blk td.nslots - 1;
        };
        // The compositor may still be rendering into it: wait on its fence, on the GPU when the
        // kernel exports it as a sync_file, else here.
        var sync_fd: ?c_int = null;
        if (td.wait_sem != null) sync_fd = vk.exportSyncFile(p.fd);
        if (sync_fd == null) {
            // Still rendering after 200 ms: the frame is skipped.
            switch (sys.pollFd(p.fd, false, 200) catch return error.VulkanFailed) {
                .ready, .hangup => {},
                .timeout => return error.Busy,
            }
            td.cpu_waits += 1;
        } else td.gpu_waits += 1;
        return td.runSlot(idx, if (full) .full else .diff, target, sync_fd, skip, &.{});
    }

    /// Tests: an input frame in host memory (`w` * 4 bytes a row), to fill through `hostPixels`.
    pub fn addHostSlot(td: *TileDiff, w: u32, h: u32) Error!usize {
        try td.ensureSize(w, h);
        if (td.nslots == max_slots) return error.Unsupported;
        const b = try vk.HostBuffer.create(td.dev, @as(usize, w) * h * 4, c.VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);
        td.slots[td.nslots] = .{ .key = .{ 0, td.nslots }, .input = .{ .host = b }, .offset = 0, .stride = w };
        td.nslots += 1;
        return td.nslots - 1;
    }

    pub fn hostPixels(td: *TileDiff, slot: usize) []u8 {
        return td.slots[slot].input.host.map;
    }

    pub fn runHost(td: *TileDiff, slot: usize, full: bool, target: Target) Error!Result {
        return td.runHostSkip(slot, full, target, .none);
    }

    pub fn runHostSkip(td: *TileDiff, slot: usize, full: bool, target: Target, skip: Skip) Error!Result {
        try td.slots[slot].input.host.flush(td.dev);
        return td.runSlot(slot, if (full) .full else .diff, target, null, skip, &.{});
    }

    /// The last frame processed (the reference), as a picture other passes read (NV12 for the
    /// H.264 encoder); null before the first run or after `forget`.
    pub fn reference(td: *const TileDiff) ?struct { buffer: c.VkBuffer, offset: u32, stride: u32, width: u32, height: u32, foreign: bool } {
        const i = td.prev orelse return null;
        const sl = &td.slots[i];
        return .{ .buffer = sl.input.buffer(), .offset = sl.offset, .stride = sl.stride, .width = td.width, .height = td.height, .foreign = sl.input == .dmabuf };
    }

    /// Copy `tiles` (indices) of the last frame processed, which the diff left out, into the
    /// shadow when it is imported (`in_shadow`), else into staging for the caller to copy.
    pub fn freshenTiles(td: *TileDiff, tiles: []const u32, to_shadow: bool) Error!Result {
        const cur = td.prev orelse return error.Unsupported;
        return td.runSlot(cur, .fresh, if (to_shadow) .shadow else .staging, null, .none, tiles);
    }

    /// Whether the imported shadow is the allocation `mem` (generation `gen`).
    pub fn shadowIs(td: *const TileDiff, mem: []const u8, gen: u32) bool {
        const key = [3]usize{ @intFromPtr(mem.ptr), mem.len, gen };
        return td.shadow != null and std.mem.eql(usize, &key, &td.shadow_key);
    }

    /// `sync_fd`: a sync_file to wait for on the GPU (taken).
    fn runSlot(td: *TileDiff, cur: usize, asked: Mode, target: Target, sync_fd: ?c_int, skip: Skip, fresh_tiles: []const u32) Error!Result {
        const prev = td.prev;
        const mode: Mode = if (asked == .diff and (prev == null or prev.? == cur)) .full else asked;
        const full = mode == .full;
        const in_shadow = !full and target == .shadow and td.shadow != null;
        const mask: []u32 = @as([*]u32, @ptrCast(@alignCast(td.mask.map.ptr)))[0 .. @as(usize, td.tiles_x) * td.tiles_y];
        switch (mode) {
            .full => @memset(mask, 0),
            .diff => switch (skip) {
                .none => @memset(mask, 0),
                .all => @memset(mask, 1),
                .some => |flags| for (mask, flags) |*m, f| {
                    m.* = @intFromBool(f);
                },
            },
            .fresh => {
                @memset(mask, 0);
                for (fresh_tiles) |t| mask[t] = 1;
            },
        }
        td.mask.flush(td.dev) catch |e| {
            if (sync_fd) |fd| _ = c.close(fd);
            return e;
        };
        var wait = false;
        if (sync_fd) |fd| {
            var imp = std.mem.zeroes(c.VkImportSemaphoreFdInfoKHR);
            imp.sType = c.VK_STRUCTURE_TYPE_IMPORT_SEMAPHORE_FD_INFO_KHR;
            imp.semaphore = td.wait_sem;
            imp.flags = c.VK_SEMAPHORE_IMPORT_TEMPORARY_BIT;
            imp.handleType = c.VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT;
            imp.fd = fd;
            vk.check(td.dev.import_semaphore_fd.?(td.dev.dev, &imp), "vkImportSemaphoreFdKHR") catch |e| {
                _ = c.close(fd);
                return e;
            };
            wait = true;
        }
        const ps = &td.slots[if (mode == .diff) prev.? else cur];
        const cs = &td.slots[cur];
        const d = td.dev;
        const cmd = td.cmd;
        try vk.check(c.vkResetCommandBuffer(cmd, 0), "vkResetCommandBuffer");
        var bi = std.mem.zeroes(c.VkCommandBufferBeginInfo);
        bi.sType = c.VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        bi.flags = c.VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        try vk.check(c.vkBeginCommandBuffer(cmd, &bi), "vkBeginCommandBuffer");
        if (td.queries != null) {
            c.vkCmdResetQueryPool(cmd, td.queries, 0, 3);
            c.vkCmdWriteTimestamp(cmd, c.VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, td.queries, 0);
        }

        // Dmabufs come from the compositor (the foreign queue family) and go back to it.
        var own: [2]c.VkBufferMemoryBarrier = undefined;
        var nown: u32 = 0;
        for ([_]*const Slot{ cs, ps }, 0..) |s, k| {
            if (k == 1 and s == cs) break;
            if (s.input != .dmabuf) continue;
            own[nown] = vk.bufferBarrier(s.input.buffer(), c.VK_QUEUE_FAMILY_FOREIGN_EXT, d.family, 0, c.VK_ACCESS_SHADER_READ_BIT);
            nown += 1;
        }
        if (nown > 0) c.vkCmdPipelineBarrier(cmd, c.VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, c.VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 0, null, nown, &own, 0, null);

        const wide = td.width % 4 == 0 and cs.offset % 4 == 0 and cs.stride % 4 == 0 and ps.offset % 4 == 0 and ps.stride % 4 == 0;
        const unit: u32 = if (wide) 4 else 1;
        c.vkCmdBindPipeline(cmd, c.VK_PIPELINE_BIND_POINT_COMPUTE, if (wide) td.pipeline4 else td.pipeline);
        var infos: [5]c.VkDescriptorBufferInfo = .{
            .{ .buffer = cs.input.buffer(), .offset = 0, .range = c.VK_WHOLE_SIZE },
            .{ .buffer = ps.input.buffer(), .offset = 0, .range = c.VK_WHOLE_SIZE },
            .{ .buffer = td.boxes.buffer, .offset = 0, .range = c.VK_WHOLE_SIZE },
            .{ .buffer = if (in_shadow) td.shadow.?.buffer else td.staging.buffer, .offset = 0, .range = c.VK_WHOLE_SIZE },
            .{ .buffer = td.mask.buffer, .offset = 0, .range = c.VK_WHOLE_SIZE },
        };
        var writes: [5]c.VkWriteDescriptorSet = undefined;
        for (&writes, 0..) |*w, i| {
            w.* = std.mem.zeroes(c.VkWriteDescriptorSet);
            w.sType = c.VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
            w.dstBinding = @intCast(i);
            w.descriptorCount = 1;
            w.descriptorType = c.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
            w.pBufferInfo = &infos[i];
        }
        d.cmd_push_descriptor_set.?(cmd, c.VK_PIPELINE_BIND_POINT_COMPUTE, td.layout, 0, writes.len, &writes);
        const params: Params = .{
            .width = td.width,
            .height = td.height,
            .cur_offset = cs.offset / unit,
            .cur_stride = cs.stride / unit,
            .prev_offset = ps.offset / unit,
            .prev_stride = ps.stride / unit,
            .tiles_x = td.tiles_x,
            .mode = @backingInt(mode),
        };
        c.vkCmdPushConstants(cmd, td.layout, c.VK_SHADER_STAGE_COMPUTE_BIT, 0, @sizeOf(Params), &params);
        if (td.queries != null) c.vkCmdWriteTimestamp(cmd, c.VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, td.queries, 1);
        c.vkCmdDispatch(cmd, td.tiles_x, td.tiles_y, 1);
        if (td.queries != null) c.vkCmdWriteTimestamp(cmd, c.VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, td.queries, 2);

        var to_host = std.mem.zeroes(c.VkMemoryBarrier);
        to_host.sType = c.VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        to_host.srcAccessMask = c.VK_ACCESS_SHADER_WRITE_BIT;
        to_host.dstAccessMask = c.VK_ACCESS_HOST_READ_BIT;
        c.vkCmdPipelineBarrier(cmd, c.VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, c.VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &to_host, 0, null, 0, null);
        for (own[0..nown]) |*b| b.* = vk.bufferBarrier(b.buffer, d.family, c.VK_QUEUE_FAMILY_FOREIGN_EXT, c.VK_ACCESS_SHADER_READ_BIT, 0);
        if (nown > 0) c.vkCmdPipelineBarrier(cmd, c.VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, c.VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, 0, 0, null, nown, &own, 0, null);
        try vk.check(c.vkEndCommandBuffer(cmd), "vkEndCommandBuffer");

        var si = std.mem.zeroes(c.VkSubmitInfo);
        si.sType = c.VK_STRUCTURE_TYPE_SUBMIT_INFO;
        si.commandBufferCount = 1;
        si.pCommandBuffers = &td.cmd;
        const wait_stage: c.VkPipelineStageFlags = c.VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT;
        if (wait) {
            si.waitSemaphoreCount = 1;
            si.pWaitSemaphores = &td.wait_sem;
            si.pWaitDstStageMask = &wait_stage;
        }
        // From here the reference is in doubt until the fence says the run finished (a fresh
        // pass reads it and leaves it).
        if (mode != .fresh) td.prev = null;
        const t_submit = nowNs();
        if (td.prep_start != 0) td.cpu_prep_ns += t_submit - td.prep_start;
        td.prep_start = 0;
        try vk.check(c.vkQueueSubmit(d.queue, 1, &si, td.fence), "vkQueueSubmit");
        try vk.waitFence(d, td.fence);
        td.cpu_fence_ns += nowNs() - t_submit;
        if (td.queries != null) {
            var ts: [3]u64 = undefined;
            if (c.vkGetQueryPoolResults(d.dev, td.queries, 0, 3, @sizeOf(@TypeOf(ts)), &ts, 8, c.VK_QUERY_RESULT_64_BIT) == c.VK_SUCCESS) {
                td.gpu_total_ns += @as(f64, @floatFromInt(ts[2] -% ts[0])) * d.timestamp_ns;
                td.gpu_pass_ns += @as(f64, @floatFromInt(ts[2] -% ts[1])) * d.timestamp_ns;
                td.timed_runs += 1;
            }
        }
        try td.boxes.invalidate(d);
        try td.staging.invalidate(d);
        if (mode != .fresh) td.prev = cur;
        const boxes: [*]const TileBox = @ptrCast(@alignCast(td.boxes.map.ptr));
        return .{
            .full = full,
            .in_shadow = in_shadow,
            .boxes = if (mode != .diff) &.{} else boxes[0 .. @as(usize, td.tiles_x) * td.tiles_y],
            .pixels = td.staging.map,
            .stride = @as(usize, td.width) * 4,
        };
    }
};

fn nowNs() u64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(u64, @intCast(ts.tv_sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.tv_nsec));
}

/// What the shader computes, on the CPU (tests): boxes of `cur` against `prev`, both
/// `width * 4` bytes a row.
pub fn tileBoxesCpu(cur: []const u8, prev: []const u8, width: u32, height: u32, out: []TileBox) void {
    const tx_n = (width + tile - 1) / tile;
    const ty_n = (height + tile - 1) / tile;
    for (0..ty_n) |ty| for (0..tx_n) |tx| {
        const x0: u32 = @intCast(tx * tile);
        const y0: u32 = @intCast(ty * tile);
        const tw = @min(tile, width - x0);
        const th = @min(tile, height - y0);
        var b: TileBox = .{ tile, tile, 0, 0 };
        for (0..th) |r| for (0..tw) |lx| {
            const o = ((y0 + r) * width + x0 + lx) * 4;
            if (std.mem.eql(u8, cur[o..][0..4], prev[o..][0..4])) continue;
            b[0] = @min(b[0], @as(u32, @intCast(lx)));
            b[1] = @min(b[1], @as(u32, @intCast(r)));
            b[2] = @max(b[2], @as(u32, @intCast(lx + 1)));
            b[3] = @max(b[3], @as(u32, @intCast(r + 1)));
        };
        out[ty * tx_n + tx] = if (b[2] == 0) .{ 0, 0, 0, 0 } else b;
    };
}

/// The first render node's Vulkan device; tests skip without Vulkan or that GPU.
pub fn testDevice() !vk.Device {
    var st: c.struct_stat = undefined;
    if (c.stat("/dev/dri/renderD128", &st) != 0) return error.SkipZigTest;
    return vk.Device.open(@intCast(st.st_rdev), null) catch return error.SkipZigTest;
}

/// Changes a test frame as a desktop does: one of a few patterns, and always a pixel or two at
/// tile edges and in the X byte alone.
pub fn mutate(rand: std.Random, px: []u8, width: u32, height: u32) void {
    const stride = @as(usize, width) * 4;
    switch (rand.uintLessThan(u8, 5)) {
        0 => {}, // edges only
        1 => { // a typed character
            const x = rand.uintLessThan(u32, width);
            const y = rand.uintLessThan(u32, height);
            for (y..@min(height, y + 20)) |yy| for (x..@min(width, x + 9)) |xx| {
                px[yy * stride + xx * 4 + 1] +%= 37;
            };
        },
        2 => { // scroll by 40 rows
            const n = @min(height, 40);
            std.mem.copyForwards(u8, px[0 .. (height - n) * stride], px[n * stride ..]);
            rand.bytes(px[(height - n) * stride ..]);
        },
        3 => { // a video region
            const x = rand.uintLessThan(u32, width);
            const y = rand.uintLessThan(u32, height);
            for (y..@min(height, y + 300)) |yy| rand.bytes(px[yy * stride + x * 4 .. yy * stride + @min(width, x + 500) * 4]);
        },
        else => rand.bytes(px), // everything
    }
    for (0..3) |_| {
        const x = @min(width - 1, rand.uintLessThan(u32, (width + 63) / 64) * 64 + if (rand.boolean()) @as(u32, 63) else 0);
        const y = @min(height - 1, rand.uintLessThan(u32, (height + 63) / 64) * 64 + if (rand.boolean()) @as(u32, 63) else 0);
        px[y * stride + x * 4 + rand.uintLessThan(usize, 4)] ^= 0x80;
    }
    px[rand.uintLessThan(usize, height) * stride + rand.uintLessThan(usize, width) * 4 + 3] +%= 1;
}

fn expectRun(td: *TileDiff, res: Result, cur: []const u8, prev: []const u8, w: u32, h: u32) !void {
    const gpa = std.testing.allocator;
    const tx_n = (w + tile - 1) / tile;
    const ty_n = (h + tile - 1) / tile;
    const want = try gpa.alloc(TileBox, tx_n * ty_n);
    defer gpa.free(want);
    tileBoxesCpu(cur, prev, w, h, want);
    try std.testing.expect(!res.full);
    try std.testing.expectEqualSlices(TileBox, want, res.boxes);
    const stride = @as(usize, w) * 4;
    for (want, 0..) |b, i| {
        if (b[2] == 0) continue;
        const x0 = (i % tx_n) * tile;
        const y0 = (i / tx_n) * tile;
        for (y0..@min(h, y0 + tile)) |y| {
            const row = y * stride + x0 * 4;
            const len = @as(usize, @min(tile, w - x0)) * 4;
            try std.testing.expectEqualSlices(u8, cur[row..][0..len], res.pixels[row..][0..len]);
        }
    }
    _ = td;
}

test "GPU tile diff: boxes and copied tiles equal the CPU reference" {
    const gpa = std.testing.allocator;
    var dev = try testDevice();
    defer dev.deinit();
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rand = prng.random();
    for ([_][2]u32{ .{ 1920, 1080 }, .{ 1001, 777 }, .{ 64, 64 }, .{ 65, 1 }, .{ 130, 70 }, .{ 3840, 2160 } }) |size| {
        const w = size[0];
        const h = size[1];
        const td = try TileDiff.create(gpa, &dev);
        defer td.destroy(gpa);
        const slots = [2]usize{ try td.addHostSlot(w, h), try td.addHostSlot(w, h) };
        const prev = try gpa.alloc(u8, @as(usize, w) * h * 4);
        defer gpa.free(prev);
        rand.bytes(prev);
        @memcpy(td.hostPixels(slots[0]), prev);
        // No reference yet: a full copy.
        const first = try td.runHost(slots[0], false, .staging);
        try std.testing.expect(first.full and first.boxes.len == 0);
        try std.testing.expectEqualSlices(u8, prev, first.pixels);
        for (0..8) |k| {
            const s = slots[(k + 1) % 2];
            const cur = td.hostPixels(s);
            @memcpy(cur, prev);
            mutate(rand, cur, w, h);
            if (k == 5) @memcpy(cur, prev); // nothing changed
            const res = try td.runHost(s, false, .staging);
            try expectRun(td, res, cur, prev, w, h);
            @memcpy(prev, cur);
        }
        // Asked full: every tile copied, no boxes.
        const s = slots[1];
        const res = try td.runHost(s, true, .staging);
        try std.testing.expect(res.full);
        try std.testing.expectEqualSlices(u8, td.hostPixels(s), res.pixels);
    }
}

test "GPU tile diff: two detectors of different sizes interleaved" {
    const gpa = std.testing.allocator;
    var dev = try testDevice();
    defer dev.deinit();
    var prng = std.Random.DefaultPrng.init(42);
    const rand = prng.random();
    const sizes = [2][2]u32{ .{ 1280, 720 }, .{ 800, 1280 } };
    var tds: [2]*TileDiff = undefined;
    var prevs: [2][]u8 = undefined;
    var slots: [2][2]usize = undefined;
    for (0..2) |i| {
        tds[i] = try TileDiff.create(gpa, &dev);
        prevs[i] = try gpa.alloc(u8, @as(usize, sizes[i][0]) * sizes[i][1] * 4);
        rand.bytes(prevs[i]);
        slots[i] = .{ try tds[i].addHostSlot(sizes[i][0], sizes[i][1]), try tds[i].addHostSlot(sizes[i][0], sizes[i][1]) };
        @memcpy(tds[i].hostPixels(slots[i][0]), prevs[i]);
        _ = try tds[i].runHost(slots[i][0], false, .staging);
    }
    defer for (0..2) |i| {
        tds[i].destroy(gpa);
        gpa.free(prevs[i]);
    };
    for (0..10) |k| {
        const i = k % 2;
        const s = slots[i][(k / 2 + 1) % 2];
        const cur = tds[i].hostPixels(s);
        @memcpy(cur, prevs[i]);
        mutate(rand, cur, sizes[i][0], sizes[i][1]);
        try expectRun(tds[i], try tds[i].runHost(s, false, .staging), cur, prevs[i], sizes[i][0], sizes[i][1]);
        @memcpy(prevs[i], cur);
    }
}

test "GPU tile diff on imported LINEAR dmabufs (GBM)" {
    const gpa = std.testing.allocator;
    var dev = try testDevice();
    defer dev.deinit();
    const gbm_mod = @import("gbm.zig");
    var g = gbm_mod.Gbm.init(gpa);
    defer g.deinit();
    const alloc = g.allocator();
    var st: c.struct_stat = undefined;
    if (c.stat("/dev/dri/renderD128", &st) != 0) return error.SkipZigTest;
    const w: u32 = 1920;
    const h: u32 = 1080;
    var bos: [3]dmabuf.Bo = undefined;
    for (&bos) |*bo| bo.* = alloc.allocFn(alloc.ctx, @intCast(st.st_rdev), w, h, dmabuf.format_xrgb8888, &.{dmabuf.mod_linear}) catch return error.SkipZigTest;
    defer for (&bos) |*bo| alloc.freeFn(alloc.ctx, bo);
    const td = try TileDiff.create(gpa, &dev);
    defer td.destroy(gpa);
    var prng = std.Random.DefaultPrng.init(7);
    const rand = prng.random();
    const prev = try gpa.alloc(u8, @as(usize, w) * h * 4);
    defer gpa.free(prev);
    const cur = try gpa.alloc(u8, @as(usize, w) * h * 4);
    defer gpa.free(cur);
    rand.bytes(prev);
    for (0..7) |k| {
        const bo = &bos[k % 3];
        if (k > 0) {
            @memcpy(cur, prev);
            mutate(rand, cur, w, h);
        } else @memcpy(cur, prev);
        const m = gbm_mod.mapWrite(bo) orelse return error.SkipZigTest;
        for (0..h) |y| @memcpy(m.data[y * m.stride ..][0 .. w * 4], cur[y * w * 4 ..][0 .. w * 4]);
        gbm_mod.unmap(bo, m.token);
        // What the buffer holds: the driver's write blit need not keep XRGB's X byte.
        try std.testing.expect(gbm_mod.waitIdle(bo, 1000));
        const r = gbm_mod.mapRead(bo) orelse return error.SkipZigTest;
        for (0..h) |y| @memcpy(cur[y * w * 4 ..][0 .. w * 4], r.data[y * r.stride ..][0 .. w * 4]);
        gbm_mod.unmap(bo, r.token);
        const res = try td.runDmabuf(bo, 1, false, .staging, .none);
        if (k == 0) {
            try std.testing.expect(res.full);
            try std.testing.expectEqualSlices(u8, cur, res.pixels);
        } else try expectRun(td, res, cur, prev, w, h);
        @memcpy(prev, cur);
    }
    // The writes' fences were waited for on the GPU when the driver imports sync_files.
    if (dev.import_semaphore_fd != null) try std.testing.expect(td.gpu_waits > 0);
}
