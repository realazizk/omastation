//! The H.264 encoder's NV12 input surface written on the GPU (GPU capture): the VA-API driver
//! allocates the surface and exports it (it encodes only its own surfaces), Vulkan imports it as
//! a two-plane image with the explicit modifier and writes both planes through R8 / R8G8 storage
//! views, straight from the captured frame (shaders/nv12.comp, bit-exact with avc444.toI420Rows).
//! AVC444 v2's main and auxiliary views go into the encoder's two input surfaces the same way
//! (shaders/avc444v2.comp, bit-exact with avc444.toNv12(.v2)). Only the 16x16 blocks a mask flags
//! are written; the rest of the surfaces keeps its picture, as h264Source keeps the H.264 source
//! outside the coded rects.

const std = @import("std");
const c = @import("c");
const vk = @import("vk.zig");

pub const Error = vk.Error;

pub const block: u32 = 16;

const spv420 = vk.spirv(@embedFile("shaders/nv12.spv"));
const spv444v2 = vk.spirv(@embedFile("shaders/avc444v2.spv"));

/// What a converter writes: AVC420's one surface (nv12.comp), or AVC444 v2's main and auxiliary
/// views (avc444v2.comp).
pub const Kind = enum { avc420, avc444v2 };

const Params420 = extern struct {
    width: u32,
    height: u32,
    src_offset: u32,
    src_stride: u32,
    blocks_x: u32,
    all: u32,
    out_w: u32,
    out_h: u32,
};

const Params444 = extern struct {
    width: u32,
    height: u32,
    src_offset: u32,
    src_stride: u32,
    blocks_x: u32,
    blocks_y: u32,
    all: u32,
    view_w: u32,
};

/// An exported NV12 surface: one dmabuf object holding both planes.
pub const Surface = struct {
    fd: c_int,
    size: u64,
    modifier: u64,
    width: u32,
    height: u32,
    offsets: [2]u32,
    pitches: [2]u32,
};

const nv12_format = c.VK_FORMAT_G8_B8R8_2PLANE_420_UNORM;
const view_formats = [_]c.VkFormat{ nv12_format, c.VK_FORMAT_R8_UNORM, c.VK_FORMAT_R8G8_UNORM };

/// The imported surface. `written`: it has been written whole once (its old contents are kept
/// from then on; before, they are undefined).
pub const Target = struct {
    image: c.VkImage = null,
    memory: c.VkDeviceMemory = null,
    view_y: c.VkImageView = null,
    view_uv: c.VkImageView = null,
    width: u32 = 0,
    height: u32 = 0,
    written: bool = false,

    /// Imports `s` (the fd stays the caller's). Unsupported, and `why` says why, when this
    /// device cannot write such an image (no modifier support, no storage for that layout) or
    /// it has an odd side (Vulkan's NV12 images have even sides).
    pub fn import(d: *const vk.Device, s: Surface, why: ?*vk.Why) Error!Target {
        if (s.width % 2 != 0 or s.height % 2 != 0) {
            vk.Why.set(why, "the encoder's NV12 surface is {d}x{d}, and Vulkan writes NV12 only with even sides", .{ s.width, s.height });
            return error.Unsupported;
        }
        if (!d.modifier_images) {
            vk.Why.set(why, "this Vulkan device has no DRM format modifier images", .{});
            return error.Unsupported;
        }
        checkSupport(d, s.modifier) catch |e| {
            vk.Why.set(why, "this Vulkan device cannot import NV12 storage images with modifier 0x{x}", .{s.modifier});
            return e;
        };
        var layouts: [2]c.VkSubresourceLayout = undefined;
        for (&layouts, 0..) |*l, i| l.* = .{ .offset = s.offsets[i], .size = 0, .rowPitch = s.pitches[i], .arrayPitch = 0, .depthPitch = 0 };
        var explicit = std.mem.zeroes(c.VkImageDrmFormatModifierExplicitCreateInfoEXT);
        explicit.sType = c.VK_STRUCTURE_TYPE_IMAGE_DRM_FORMAT_MODIFIER_EXPLICIT_CREATE_INFO_EXT;
        explicit.drmFormatModifier = s.modifier;
        explicit.drmFormatModifierPlaneCount = 2;
        explicit.pPlaneLayouts = &layouts;
        var list = std.mem.zeroes(c.VkImageFormatListCreateInfo);
        list.sType = c.VK_STRUCTURE_TYPE_IMAGE_FORMAT_LIST_CREATE_INFO;
        list.pNext = &explicit;
        list.viewFormatCount = view_formats.len;
        list.pViewFormats = &view_formats;
        var ext = std.mem.zeroes(c.VkExternalMemoryImageCreateInfo);
        ext.sType = c.VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_IMAGE_CREATE_INFO;
        ext.pNext = &list;
        ext.handleTypes = c.VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT;
        var ici = std.mem.zeroes(c.VkImageCreateInfo);
        ici.sType = c.VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
        ici.pNext = &ext;
        ici.flags = c.VK_IMAGE_CREATE_MUTABLE_FORMAT_BIT | c.VK_IMAGE_CREATE_EXTENDED_USAGE_BIT;
        ici.imageType = c.VK_IMAGE_TYPE_2D;
        ici.format = nv12_format;
        ici.extent = .{ .width = s.width, .height = s.height, .depth = 1 };
        ici.mipLevels = 1;
        ici.arrayLayers = 1;
        ici.samples = c.VK_SAMPLE_COUNT_1_BIT;
        ici.tiling = c.VK_IMAGE_TILING_DRM_FORMAT_MODIFIER_EXT;
        ici.usage = c.VK_IMAGE_USAGE_STORAGE_BIT;
        ici.sharingMode = c.VK_SHARING_MODE_EXCLUSIVE;
        ici.initialLayout = c.VK_IMAGE_LAYOUT_UNDEFINED;
        var t: Target = .{ .width = s.width, .height = s.height };
        try vk.check(c.vkCreateImage(d.dev, &ici, null, &t.image), "vkCreateImage(NV12)");
        errdefer t.destroy(d);
        var req: c.VkMemoryRequirements = undefined;
        c.vkGetImageMemoryRequirements(d.dev, t.image, &req);
        if (req.size > s.size) {
            vk.Why.set(why, "the encoder's NV12 surface has {d} bytes, Vulkan's image needs {d}", .{ s.size, req.size });
            return error.Unsupported;
        }
        var fdp = std.mem.zeroes(c.VkMemoryFdPropertiesKHR);
        fdp.sType = c.VK_STRUCTURE_TYPE_MEMORY_FD_PROPERTIES_KHR;
        try vk.check(d.get_memory_fd_properties.?(d.dev, c.VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT, s.fd, &fdp), "vkGetMemoryFdPropertiesKHR(NV12)");
        const ty = d.memoryType(req.memoryTypeBits & fdp.memoryTypeBits, 0, 0) orelse {
            vk.Why.set(why, "no Vulkan memory type takes the encoder's NV12 surface", .{});
            return error.Unsupported;
        };
        const own = c.fcntl(s.fd, c.F_DUPFD_CLOEXEC, @as(c_int, 0));
        if (own < 0) return error.VulkanFailed;
        var imp = std.mem.zeroes(c.VkImportMemoryFdInfoKHR);
        imp.sType = c.VK_STRUCTURE_TYPE_IMPORT_MEMORY_FD_INFO_KHR;
        imp.handleType = c.VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT;
        imp.fd = own;
        var ded = std.mem.zeroes(c.VkMemoryDedicatedAllocateInfo);
        ded.sType = c.VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO;
        ded.pNext = &imp;
        ded.image = t.image;
        var mai = std.mem.zeroes(c.VkMemoryAllocateInfo);
        mai.sType = c.VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        mai.pNext = &ded;
        mai.allocationSize = req.size;
        mai.memoryTypeIndex = ty;
        vk.check(c.vkAllocateMemory(d.dev, &mai, null, &t.memory), "vkAllocateMemory(NV12)") catch |e| {
            _ = c.close(own);
            return e;
        };
        try vk.check(c.vkBindImageMemory(d.dev, t.image, t.memory, 0), "vkBindImageMemory(NV12)");
        t.view_y = try planeView(d, t.image, c.VK_FORMAT_R8_UNORM, c.VK_IMAGE_ASPECT_PLANE_0_BIT);
        t.view_uv = try planeView(d, t.image, c.VK_FORMAT_R8G8_UNORM, c.VK_IMAGE_ASPECT_PLANE_1_BIT);
        return t;
    }

    pub fn destroy(t: *Target, d: *const vk.Device) void {
        if (t.view_y != null) c.vkDestroyImageView(d.dev, t.view_y, null);
        if (t.view_uv != null) c.vkDestroyImageView(d.dev, t.view_uv, null);
        if (t.image != null) c.vkDestroyImage(d.dev, t.image, null);
        if (t.memory != null) c.vkFreeMemory(d.dev, t.memory, null);
        t.* = .{};
    }
};

fn planeView(d: *const vk.Device, image: c.VkImage, format: c.VkFormat, aspect: c.VkImageAspectFlags) Error!c.VkImageView {
    var usage = std.mem.zeroes(c.VkImageViewUsageCreateInfo);
    usage.sType = c.VK_STRUCTURE_TYPE_IMAGE_VIEW_USAGE_CREATE_INFO;
    usage.usage = c.VK_IMAGE_USAGE_STORAGE_BIT;
    var vci = std.mem.zeroes(c.VkImageViewCreateInfo);
    vci.sType = c.VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    vci.pNext = &usage;
    vci.image = image;
    vci.viewType = c.VK_IMAGE_VIEW_TYPE_2D;
    vci.format = format;
    vci.subresourceRange = .{ .aspectMask = aspect, .baseMipLevel = 0, .levelCount = 1, .baseArrayLayer = 0, .layerCount = 1 };
    var v: c.VkImageView = null;
    try vk.check(c.vkCreateImageView(d.dev, &vci, null, &v), "vkCreateImageView(NV12 plane)");
    return v;
}

/// Whether an NV12 image with `modifier` can be imported and written as storage.
fn checkSupport(d: *const vk.Device, modifier: u64) Error!void {
    var mod_info = std.mem.zeroes(c.VkPhysicalDeviceImageDrmFormatModifierInfoEXT);
    mod_info.sType = c.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_DRM_FORMAT_MODIFIER_INFO_EXT;
    mod_info.drmFormatModifier = modifier;
    mod_info.sharingMode = c.VK_SHARING_MODE_EXCLUSIVE;
    var list = std.mem.zeroes(c.VkImageFormatListCreateInfo);
    list.sType = c.VK_STRUCTURE_TYPE_IMAGE_FORMAT_LIST_CREATE_INFO;
    list.pNext = &mod_info;
    list.viewFormatCount = view_formats.len;
    list.pViewFormats = &view_formats;
    var ext = std.mem.zeroes(c.VkPhysicalDeviceExternalImageFormatInfo);
    ext.sType = c.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_IMAGE_FORMAT_INFO;
    ext.pNext = &list;
    ext.handleType = c.VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT;
    var info = std.mem.zeroes(c.VkPhysicalDeviceImageFormatInfo2);
    info.sType = c.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_FORMAT_INFO_2;
    info.pNext = &ext;
    info.format = nv12_format;
    info.type = c.VK_IMAGE_TYPE_2D;
    info.tiling = c.VK_IMAGE_TILING_DRM_FORMAT_MODIFIER_EXT;
    info.usage = c.VK_IMAGE_USAGE_STORAGE_BIT;
    info.flags = c.VK_IMAGE_CREATE_MUTABLE_FORMAT_BIT | c.VK_IMAGE_CREATE_EXTENDED_USAGE_BIT;
    var ext_props = std.mem.zeroes(c.VkExternalImageFormatProperties);
    ext_props.sType = c.VK_STRUCTURE_TYPE_EXTERNAL_IMAGE_FORMAT_PROPERTIES;
    var props = std.mem.zeroes(c.VkImageFormatProperties2);
    props.sType = c.VK_STRUCTURE_TYPE_IMAGE_FORMAT_PROPERTIES_2;
    props.pNext = &ext_props;
    if (c.vkGetPhysicalDeviceImageFormatProperties2(d.phys, &info, &props) != c.VK_SUCCESS) return error.Unsupported;
    if (ext_props.externalMemoryProperties.externalMemoryFeatures & c.VK_EXTERNAL_MEMORY_FEATURE_IMPORTABLE_BIT == 0) return error.Unsupported;
}

/// The picture to convert: a buffer of 32-bit BGRX pixels (a capture slot).
pub const Source = struct {
    buffer: c.VkBuffer,
    /// In 32-bit words.
    offset: u32,
    stride: u32,
    width: u32,
    height: u32,
    /// A dmabuf of another queue family (the compositor's): owned for the pass, then given back.
    foreign: bool,
};

pub const Converter = struct {
    dev: *const vk.Device,
    kind: Kind,
    shader: c.VkShaderModule = null,
    set_layout: c.VkDescriptorSetLayout = null,
    layout: c.VkPipelineLayout = null,
    pipeline: c.VkPipeline = null,
    cmd_pool: c.VkCommandPool = null,
    cmd: c.VkCommandBuffer = null,
    fence: c.VkFence = null,
    blocks: vk.HostBuffer = .{},
    /// GPU time of the passes (when the queue has timestamps), summed, and their count.
    queries: c.VkQueryPool = null,
    gpu_ns: f64 = 0,
    runs: u64 = 0,

    pub fn create(gpa: std.mem.Allocator, dev: *const vk.Device, kind: Kind) Error!*Converter {
        const cv = try gpa.create(Converter);
        errdefer gpa.destroy(cv);
        cv.* = .{ .dev = dev, .kind = kind };
        errdefer cv.release();
        const code: []const u32 = switch (kind) {
            .avc420 => &spv420,
            .avc444v2 => &spv444v2,
        };
        cv.shader = try vk.shaderModule(dev, code);
        const sb = c.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        const si = c.VK_DESCRIPTOR_TYPE_STORAGE_IMAGE;
        const types = [2 + 2 * max_targets]c.VkDescriptorType{ sb, sb, si, si, si, si };
        comptime std.debug.assert(@sizeOf(Params420) == @sizeOf(Params444));
        try vk.passLayouts(dev, types[0 .. 2 + 2 * cv.targets()], @sizeOf(Params420), &cv.set_layout, &cv.layout);
        cv.pipeline = try vk.computePipeline(dev, cv.shader, cv.layout);
        try vk.passCommands(dev, &cv.cmd_pool, &cv.cmd, &cv.fence, &cv.queries, 2);
        return cv;
    }

    pub fn destroy(cv: *Converter, gpa: std.mem.Allocator) void {
        cv.release();
        gpa.destroy(cv);
    }

    fn release(cv: *Converter) void {
        const d = cv.dev.dev;
        _ = c.vkQueueWaitIdle(cv.dev.queue);
        cv.blocks.destroy(cv.dev);
        if (cv.queries != null) c.vkDestroyQueryPool(d, cv.queries, null);
        if (cv.fence != null) c.vkDestroyFence(d, cv.fence, null);
        if (cv.cmd_pool != null) c.vkDestroyCommandPool(d, cv.cmd_pool, null);
        if (cv.pipeline != null) c.vkDestroyPipeline(d, cv.pipeline, null);
        if (cv.layout != null) c.vkDestroyPipelineLayout(d, cv.layout, null);
        if (cv.set_layout != null) c.vkDestroyDescriptorSetLayout(d, cv.set_layout, null);
        if (cv.shader != null) c.vkDestroyShaderModule(d, cv.shader, null);
    }

    const max_targets = 2;

    /// Surfaces a run writes: AVC420's one, AVC444's main and auxiliary views.
    pub fn targets(cv: *const Converter) usize {
        return switch (cv.kind) {
            .avc420 => 1,
            .avc444v2 => 2,
        };
    }

    /// Writes `dst` (`targets` surfaces) from `src`: the 16x16 blocks of the picture `blocks`
    /// flags (row-major, blocksFor), or all when null; surfaces not yet written get everything.
    /// AVC420's surface is the picture's size, AVC444's views their viewSize (columns and rows
    /// past the picture follow its last block). Waits for the GPU.
    pub fn run(cv: *Converter, src: Source, dst: []const *Target, blocks: ?[]const bool) Error!void {
        const d = cv.dev;
        if (dst.len != cv.targets()) return error.Unsupported;
        const bx = (src.width + block - 1) / block;
        const by = (src.height + block - 1) / block;
        const n = @as(usize, bx) * by;
        const out = dst[0];
        const groups: [2]u32 = switch (cv.kind) {
            .avc420 => blk: {
                if ((out.width + block - 1) / block != bx or (out.height + block - 1) / block != by) return error.Unsupported;
                break :blk .{ bx, by };
            },
            .avc444v2 => blk: {
                const aux = dst[1];
                if (out.width % 32 != 0 or out.height % block != 0 or out.width < src.width or out.height < src.height or aux.width != out.width or aux.height != out.height) return error.Unsupported;
                break :blk .{ out.width / block, out.height / block };
            },
        };
        if (cv.blocks.size < n * 4) {
            cv.blocks.destroy(d);
            cv.blocks = try vk.HostBuffer.create(d, n * 4, c.VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);
        }
        var all = blocks == null;
        for (dst) |t| all = all or !t.written;
        if (!all) {
            const flags = blocks.?;
            if (flags.len != n) return error.Unsupported;
            const m: [*]u32 = @ptrCast(@alignCast(cv.blocks.map.ptr));
            for (flags, 0..) |f, i| m[i] = @intFromBool(f);
            try cv.blocks.flush(d);
        }
        const cmd = cv.cmd;
        try vk.check(c.vkResetCommandBuffer(cmd, 0), "vkResetCommandBuffer(NV12)");
        var bi = std.mem.zeroes(c.VkCommandBufferBeginInfo);
        bi.sType = c.VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        bi.flags = c.VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        try vk.check(c.vkBeginCommandBuffer(cmd, &bi), "vkBeginCommandBuffer(NV12)");
        if (cv.queries != null) {
            c.vkCmdResetQueryPool(cmd, cv.queries, 0, 2);
            c.vkCmdWriteTimestamp(cmd, c.VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, cv.queries, 0);
        }
        // The surfaces come from VA-API (another queue family) with their pictures kept, except
        // the first time (nothing to keep); the source from the compositor when it is a dmabuf.
        var imgs: [max_targets]c.VkImageMemoryBarrier = undefined;
        for (dst, 0..) |t, i| imgs[i] = imageBarrier(t.image, if (t.written) c.VK_IMAGE_LAYOUT_GENERAL else c.VK_IMAGE_LAYOUT_UNDEFINED, c.VK_QUEUE_FAMILY_FOREIGN_EXT, d.family, 0, c.VK_ACCESS_SHADER_WRITE_BIT);
        var buf = vk.bufferBarrier(src.buffer, c.VK_QUEUE_FAMILY_FOREIGN_EXT, d.family, 0, c.VK_ACCESS_SHADER_READ_BIT);
        c.vkCmdPipelineBarrier(cmd, c.VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, c.VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 0, null, if (src.foreign) 1 else 0, &buf, @intCast(dst.len), &imgs);
        c.vkCmdBindPipeline(cmd, c.VK_PIPELINE_BIND_POINT_COMPUTE, cv.pipeline);
        const binfo = [2]c.VkDescriptorBufferInfo{
            .{ .buffer = src.buffer, .offset = 0, .range = c.VK_WHOLE_SIZE },
            .{ .buffer = cv.blocks.buffer, .offset = 0, .range = c.VK_WHOLE_SIZE },
        };
        var iinfo: [2 * max_targets]c.VkDescriptorImageInfo = undefined;
        for (dst, 0..) |t, i| {
            iinfo[2 * i] = .{ .sampler = null, .imageView = t.view_y, .imageLayout = c.VK_IMAGE_LAYOUT_GENERAL };
            iinfo[2 * i + 1] = .{ .sampler = null, .imageView = t.view_uv, .imageLayout = c.VK_IMAGE_LAYOUT_GENERAL };
        }
        var writes: [2 + 2 * max_targets]c.VkWriteDescriptorSet = undefined;
        const nw = 2 + 2 * dst.len;
        for (writes[0..nw], 0..) |*w, i| {
            w.* = std.mem.zeroes(c.VkWriteDescriptorSet);
            w.sType = c.VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
            w.dstBinding = @intCast(i);
            w.descriptorCount = 1;
            if (i < 2) {
                w.descriptorType = c.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
                w.pBufferInfo = &binfo[i];
            } else {
                w.descriptorType = c.VK_DESCRIPTOR_TYPE_STORAGE_IMAGE;
                w.pImageInfo = &iinfo[i - 2];
            }
        }
        d.cmd_push_descriptor_set.?(cmd, c.VK_PIPELINE_BIND_POINT_COMPUTE, cv.layout, 0, @intCast(nw), &writes);
        switch (cv.kind) {
            .avc420 => {
                const params: Params420 = .{ .width = src.width, .height = src.height, .src_offset = src.offset, .src_stride = src.stride, .blocks_x = bx, .all = @intFromBool(all), .out_w = out.width, .out_h = out.height };
                c.vkCmdPushConstants(cmd, cv.layout, c.VK_SHADER_STAGE_COMPUTE_BIT, 0, @sizeOf(Params420), &params);
            },
            .avc444v2 => {
                const params: Params444 = .{ .width = src.width, .height = src.height, .src_offset = src.offset, .src_stride = src.stride, .blocks_x = bx, .blocks_y = by, .all = @intFromBool(all), .view_w = out.width };
                c.vkCmdPushConstants(cmd, cv.layout, c.VK_SHADER_STAGE_COMPUTE_BIT, 0, @sizeOf(Params444), &params);
            },
        }
        c.vkCmdDispatch(cmd, groups[0], groups[1], 1);
        if (cv.queries != null) c.vkCmdWriteTimestamp(cmd, c.VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, cv.queries, 1);
        for (dst, 0..) |t, i| imgs[i] = imageBarrier(t.image, c.VK_IMAGE_LAYOUT_GENERAL, d.family, c.VK_QUEUE_FAMILY_FOREIGN_EXT, c.VK_ACCESS_SHADER_WRITE_BIT, 0);
        buf = vk.bufferBarrier(src.buffer, d.family, c.VK_QUEUE_FAMILY_FOREIGN_EXT, c.VK_ACCESS_SHADER_READ_BIT, 0);
        c.vkCmdPipelineBarrier(cmd, c.VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, c.VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, 0, 0, null, if (src.foreign) 1 else 0, &buf, @intCast(dst.len), &imgs);
        try vk.check(c.vkEndCommandBuffer(cmd), "vkEndCommandBuffer(NV12)");
        var si = std.mem.zeroes(c.VkSubmitInfo);
        si.sType = c.VK_STRUCTURE_TYPE_SUBMIT_INFO;
        si.commandBufferCount = 1;
        si.pCommandBuffers = &cv.cmd;
        try vk.check(c.vkQueueSubmit(d.queue, 1, &si, cv.fence), "vkQueueSubmit(NV12)");
        try vk.waitFence(d, cv.fence);
        if (cv.queries != null) {
            var ts: [2]u64 = undefined;
            if (c.vkGetQueryPoolResults(d.dev, cv.queries, 0, 2, @sizeOf(@TypeOf(ts)), &ts, 8, c.VK_QUERY_RESULT_64_BIT) == c.VK_SUCCESS) {
                cv.gpu_ns += @as(f64, @floatFromInt(ts[1] -% ts[0])) * d.timestamp_ns;
                cv.runs += 1;
            }
        }
        for (dst) |t| t.written = true;
    }
};

fn imageBarrier(image: c.VkImage, old: c.VkImageLayout, from: u32, to: u32, src: c.VkAccessFlags, dst: c.VkAccessFlags) c.VkImageMemoryBarrier {
    var b = std.mem.zeroes(c.VkImageMemoryBarrier);
    b.sType = c.VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    b.srcAccessMask = src;
    b.dstAccessMask = dst;
    b.oldLayout = old;
    b.newLayout = c.VK_IMAGE_LAYOUT_GENERAL;
    b.srcQueueFamilyIndex = from;
    b.dstQueueFamilyIndex = to;
    b.image = image;
    b.subresourceRange = .{ .aspectMask = c.VK_IMAGE_ASPECT_COLOR_BIT, .baseMipLevel = 0, .levelCount = 1, .baseArrayLayer = 0, .layerCount = 1 };
    return b;
}

/// The 16x16 blocks `h264Source` refreshes for `rects` (each widened to 16-pixel edges, clipped).
pub fn blocksFor(rects: anytype, width: u32, height: u32, out: []bool) void {
    const bx_n = (width + block - 1) / block;
    @memset(out, false);
    for (rects) |r| {
        if (r.right <= r.left or r.bottom <= r.top) continue;
        const x0: u32 = r.left / block;
        const y0: u32 = r.top / block;
        const x1: u32 = (@min(width, (@as(u32, r.right) + block - 1) / block * block) + block - 1) / block;
        const y1: u32 = (@min(height, (@as(u32, r.bottom) + block - 1) / block * block) + block - 1) / block;
        for (y0..y1) |by| for (x0..x1) |bx| {
            out[by * bx_n + bx] = true;
        };
    }
}

// Bit-exactness with the CPU path, on the encoder's real input surfaces (skipped without VA-API or
// a Vulkan device).

const tilediff = @import("tilediff.zig");
const vaapi_h264 = @import("../codec/vaapi_h264.zig");
const avc444 = @import("../codec/avc444.zig");

const TestRig = struct {
    dev: vk.Device,
    enc: vaapi_h264.Encoder,
    targets: [2]Target = .{ .{}, .{} },
    n: usize,
    cv: *Converter = undefined,
    td: *tilediff.TileDiff = undefined,

    fn init(gpa: std.mem.Allocator, kind: Kind, w: u32, h: u32) !*TestRig {
        var dev = try tilediff.testDevice();
        errdefer dev.deinit();
        if (!dev.modifier_images) return error.SkipZigTest;
        // As gfx_codecs: odd AVC420 sizes are not cropped.
        const crop = kind == .avc420 and w % 2 == 0 and h % 2 == 0;
        var enc = vaapi_h264.Encoder.init(gpa, .{ .width = w, .height = h, .crop = crop, .rate_control = .cqp, .avc444 = if (kind == .avc444v2) .v2 else null }) catch return error.SkipZigTest;
        errdefer enc.deinit();
        const rig = try gpa.create(TestRig);
        errdefer gpa.destroy(rig);
        rig.* = .{ .dev = dev, .enc = enc, .n = if (kind == .avc420) 1 else 2 };
        errdefer for (&rig.targets) |*t| t.destroy(&rig.dev);
        const views = [2]vaapi_h264.Encoder.View{ .main, .aux };
        for (rig.targets[0..rig.n], views[0..rig.n]) |*t, v| {
            const s = try rig.enc.exportInput(v);
            defer _ = c.close(s.fd);
            t.* = Target.import(&rig.dev, .{ .fd = s.fd, .size = s.size, .modifier = s.modifier, .width = s.width, .height = s.height, .offsets = s.offsets, .pitches = s.pitches }, null) catch |e| {
                if (e == error.Unsupported) return error.SkipZigTest;
                return e;
            };
        }
        rig.cv = try Converter.create(gpa, &rig.dev, kind);
        errdefer rig.cv.destroy(gpa);
        rig.td = try tilediff.TileDiff.create(gpa, &rig.dev);
        return rig;
    }

    fn deinit(rig: *TestRig, gpa: std.mem.Allocator) void {
        rig.cv.destroy(gpa);
        rig.td.destroy(gpa);
        for (&rig.targets) |*t| t.destroy(&rig.dev);
        rig.enc.deinit();
        rig.dev.deinit();
        gpa.destroy(rig);
    }

    /// Converts the picture last run through `td` into the surfaces.
    fn convert(rig: *TestRig, blocks: ?[]const bool) !void {
        const ref = rig.td.reference().?;
        const ts = [2]*Target{ &rig.targets[0], &rig.targets[1] };
        try rig.cv.run(.{ .buffer = ref.buffer, .offset = ref.offset, .stride = ref.stride, .width = ref.width, .height = ref.height, .foreign = ref.foreign }, ts[0..rig.n], blocks);
    }

    /// The surfaces read back equal what the CPU path makes of `px` (w x h).
    fn expectSurfaces(rig: *TestRig, gpa: std.mem.Allocator, px: []const u8, w: u32, h: u32) !void {
        const vw = rig.targets[0].width;
        const vh = rig.targets[0].height;
        var bufs: [2][4][]u8 = undefined;
        for (&bufs) |*b| for (b, [4]usize{ vw * vh, vw * vh / 2, vw * vh, vw * vh / 2 }) |*x, len| {
            x.* = try gpa.alloc(u8, len);
        };
        defer for (&bufs) |*b| for (b) |x| gpa.free(x);
        // AVC420: the rows toI420Rows makes (the picture's, even); the surface may have more.
        var rows = vh;
        if (rig.n == 1) {
            rows = try referenceNv12(gpa, px, w, h, vw, bufs[0][0], bufs[0][1]);
        } else {
            const scratch = try gpa.alloc(u8, avc444.nv12ScratchLen(w));
            defer gpa.free(scratch);
            try avc444.toNv12(.v2, px, @as(usize, w) * 4, w, h, .{ .y = bufs[0][0], .y_pitch = vw, .uv = bufs[0][1], .uv_pitch = vw }, .{ .y = bufs[1][0], .y_pitch = vw, .uv = bufs[1][1], .uv_pitch = vw }, scratch);
        }
        for (0..rig.n) |i| {
            try rig.enc.readInput(if (i == 0) .main else .aux, vw, vh, bufs[i][2], bufs[i][3]);
            try std.testing.expectEqualSlices(u8, bufs[i][0][0 .. vw * rows], bufs[i][2][0 .. vw * rows]);
            try std.testing.expectEqualSlices(u8, bufs[i][1][0 .. vw * rows / 2], bufs[i][3][0 .. vw * rows / 2]);
        }
    }
};

/// The NV12 the CPU path gives `px` (toI420Rows), as Y and interleaved UV rows `pitch` wide (the
/// surface's width: the picture's, or at an odd size the coded one, past which toI420Rows
/// replicates the edge too). Returns the luma rows written: the picture's height made even.
pub fn referenceNv12(gpa: std.mem.Allocator, px: []const u8, w: u32, h: u32, pitch: u32, y_out: []u8, uv_out: []u8) !u32 {
    const ps = try avc444.i420Size(w, h);
    const y = try gpa.alloc(u8, @as(usize, ps.width) * ps.height);
    defer gpa.free(y);
    const u = try gpa.alloc(u8, @as(usize, ps.width / 2) * (ps.height / 2));
    defer gpa.free(u);
    const v = try gpa.alloc(u8, u.len);
    defer gpa.free(v);
    const scratch = try gpa.alloc(u8, avc444.nv12ScratchLen(w));
    defer gpa.free(scratch);
    try avc444.toI420Rows(px, @as(usize, w) * 4, w, h, .{ .y = y, .u = u, .v = v, .y_pitch = ps.width, .uv_pitch = ps.width / 2 }, scratch, 0, ps.height / 2);
    if (pitch < w or pitch > ps.width or pitch % 2 != 0) return error.InvalidDimensions;
    for (0..ps.height) |r| @memcpy(y_out[r * pitch ..][0..pitch], y[r * ps.width ..][0..pitch]);
    for (0..ps.height / 2) |r| for (0..pitch / 2) |x| {
        uv_out[r * pitch + 2 * x] = u[r * (ps.width / 2) + x];
        uv_out[r * pitch + 2 * x + 1] = v[r * (ps.width / 2) + x];
    };
    return ps.height;
}

test "NV12 written on the GPU into the encoder's surface equals avc444.toI420Rows" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x4220);
    const rand = prng.random();
    // Odd sizes: the surface has the coded size (vaapi_h264 paddedInput), past the picture's
    // edge as toI420Rows replicates it.
    for ([_][2]u32{ .{ 1920, 1080 }, .{ 1280, 720 }, .{ 646, 358 }, .{ 3840, 2160 }, .{ 1001, 777 }, .{ 333, 211 }, .{ 1000, 777 }, .{ 1001, 700 } }) |size| {
        const w = size[0];
        const h = size[1];
        const rig = try TestRig.init(gpa, .avc420, w, h);
        defer rig.deinit(gpa);
        const slot = try rig.td.addHostSlot(w, h);
        const px = rig.td.hostPixels(slot);
        rand.bytes(px);
        _ = try rig.td.runHost(slot, true, .staging);
        try rig.convert(null);
        try rig.expectSurfaces(gpa, px, w, h);
    }
}

test "AVC444 v2 views written on the GPU into the encoder's surfaces equal avc444.toNv12" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x4440);
    const rand = prng.random();
    // Aligned, then sizes whose views pad: columns to 32, rows to 16, odd ones.
    for ([_][2]u32{ .{ 1920, 1080 }, .{ 1000, 700 }, .{ 646, 358 }, .{ 333, 211 }, .{ 3840, 2160 } }) |size| {
        const w = size[0];
        const h = size[1];
        const rig = try TestRig.init(gpa, .avc444v2, w, h);
        defer rig.deinit(gpa);
        const slot = try rig.td.addHostSlot(w, h);
        const px = rig.td.hostPixels(slot);
        rand.bytes(px);
        _ = try rig.td.runHost(slot, true, .staging);
        try rig.convert(null);
        try rig.expectSurfaces(gpa, px, w, h);
    }
}

test "the GPU keeps h264Source's semantics: only the coded rects change, in AVC420's picture and AVC444's views" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x4221);
    const rand = prng.random();
    const Rect = struct { left: u16, top: u16, right: u16, bottom: u16 };
    for ([_]Kind{ .avc420, .avc444v2 }) |kind| for ([_][2]u32{ .{ 1920, 1080 }, .{ 1000, 700 } }) |size| {
        const w = size[0];
        const h = size[1];
        const rig = try TestRig.init(gpa, kind, w, h);
        defer rig.deinit(gpa);
        const slots = [2]usize{ try rig.td.addHostSlot(w, h), try rig.td.addHostSlot(w, h) };
        // h264Source's picture: frame A, then frame B copied into the rects widened to 16 pixels.
        const src = try gpa.alloc(u8, @as(usize, w) * h * 4);
        defer gpa.free(src);
        const a = rig.td.hostPixels(slots[0]);
        rand.bytes(a);
        @memcpy(src, a);
        _ = try rig.td.runHost(slots[0], true, .staging);
        try rig.convert(null);
        // Inside, across block edges, and the last column and row (the views' padding follows).
        const rects = [_]Rect{ .{ .left = 3, .top = 5, .right = 77, .bottom = 40 }, .{ .left = 500, .top = 300, .right = 700, .bottom = @intCast(h) }, .{ .left = @intCast(w - 10), .top = 0, .right = @intCast(w), .bottom = 17 } };
        const b = rig.td.hostPixels(slots[1]);
        rand.bytes(b);
        _ = try rig.td.runHost(slots[1], true, .staging);
        for (rects) |r| {
            const x0: usize = r.left & ~@as(u16, 15);
            const x1: usize = @min(w, (@as(u32, r.right) + 15) & ~@as(u32, 15));
            var yy: usize = r.top & ~@as(u16, 15);
            const y1: usize = @min(h, (@as(u32, r.bottom) + 15) & ~@as(u32, 15));
            while (yy < y1) : (yy += 1) @memcpy(src[(yy * w + x0) * 4 ..][0 .. (x1 - x0) * 4], b[(yy * w + x0) * 4 ..][0 .. (x1 - x0) * 4]);
        }
        const blocks = try gpa.alloc(bool, @as(usize, (w + 15) / 16) * ((h + 15) / 16));
        defer gpa.free(blocks);
        blocksFor(&rects, w, h, blocks);
        try rig.convert(blocks);
        try rig.expectSurfaces(gpa, src, w, h);
    };
}
