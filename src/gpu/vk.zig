//! A Vulkan compute device on the GPU a dmabuf lives on (matched by DRM node through
//! VK_EXT_physical_device_drm), with dmabuf import and push descriptors; when the driver has them,
//! host memory import (the encoder's shadow as a GPU-writable buffer) and sync_file semaphores
//! (waiting for the compositor on the GPU). Robust buffer access is on: a shader indexing past a
//! buffer reads zeros instead of faulting the GPU.

const std = @import("std");
const c = @import("c");
const dmabuf = @import("../wl/dmabuf.zig");

const log = std.log.scoped(.vk);

/// Busy: a dmabuf is still being rendered into (no sync_file to wait on the GPU); the frame waits.
pub const Error = error{ VulkanFailed, NoDevice, OutOfMemory, Unsupported, Timeout, Busy };

pub fn check(r: c.VkResult, what: []const u8) Error!void {
    if (r == c.VK_SUCCESS) return;
    log.debug("{s}: VkResult {d}", .{ what, r });
    return switch (r) {
        c.VK_ERROR_OUT_OF_HOST_MEMORY, c.VK_ERROR_OUT_OF_DEVICE_MEMORY => error.OutOfMemory,
        c.VK_TIMEOUT => error.Timeout,
        else => error.VulkanFailed,
    };
}

/// SPIR-V embedded with @embedFile, as the words Vulkan takes.
pub fn spirv(comptime bytes: []const u8) [bytes.len / 4]u32 {
    const a: [bytes.len]u8 = bytes[0..bytes.len].*;
    return @bitCast(a);
}

pub fn shaderModule(d: *const Device, code: []const u32) Error!c.VkShaderModule {
    var smci = std.mem.zeroes(c.VkShaderModuleCreateInfo);
    smci.sType = c.VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    smci.codeSize = code.len * 4;
    smci.pCode = code.ptr;
    var m: c.VkShaderModule = null;
    try check(c.vkCreateShaderModule(d.dev, &smci, null, &m), "vkCreateShaderModule");
    return m;
}

pub fn computePipeline(d: *const Device, module: c.VkShaderModule, layout: c.VkPipelineLayout) Error!c.VkPipeline {
    var stage = std.mem.zeroes(c.VkPipelineShaderStageCreateInfo);
    stage.sType = c.VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stage.stage = c.VK_SHADER_STAGE_COMPUTE_BIT;
    stage.module = module;
    stage.pName = "main";
    var cpci = std.mem.zeroes(c.VkComputePipelineCreateInfo);
    cpci.sType = c.VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    cpci.stage = stage;
    cpci.layout = layout;
    var p: c.VkPipeline = null;
    try check(c.vkCreateComputePipelines(d.dev, null, 1, &cpci, null, &p), "vkCreateComputePipelines");
    return p;
}

/// A compute pass's layouts: binding i of a push-descriptor set is `types[i]`, and `push` bytes
/// of push constants.
pub fn passLayouts(d: *const Device, types: []const c.VkDescriptorType, push: u32, set_layout: *c.VkDescriptorSetLayout, layout: *c.VkPipelineLayout) Error!void {
    var bindings: [8]c.VkDescriptorSetLayoutBinding = undefined;
    if (types.len > bindings.len) return error.Unsupported;
    for (bindings[0..types.len], types, 0..) |*b, t, i| {
        b.* = std.mem.zeroes(c.VkDescriptorSetLayoutBinding);
        b.binding = @intCast(i);
        b.descriptorType = t;
        b.descriptorCount = 1;
        b.stageFlags = c.VK_SHADER_STAGE_COMPUTE_BIT;
    }
    var dslci = std.mem.zeroes(c.VkDescriptorSetLayoutCreateInfo);
    dslci.sType = c.VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    dslci.flags = c.VK_DESCRIPTOR_SET_LAYOUT_CREATE_PUSH_DESCRIPTOR_BIT_KHR;
    dslci.bindingCount = @intCast(types.len);
    dslci.pBindings = &bindings;
    try check(c.vkCreateDescriptorSetLayout(d.dev, &dslci, null, set_layout), "vkCreateDescriptorSetLayout");
    var pcr = std.mem.zeroes(c.VkPushConstantRange);
    pcr.stageFlags = c.VK_SHADER_STAGE_COMPUTE_BIT;
    pcr.size = push;
    var plci = std.mem.zeroes(c.VkPipelineLayoutCreateInfo);
    plci.sType = c.VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    plci.setLayoutCount = 1;
    plci.pSetLayouts = set_layout;
    plci.pushConstantRangeCount = 1;
    plci.pPushConstantRanges = &pcr;
    try check(c.vkCreatePipelineLayout(d.dev, &plci, null, layout), "vkCreatePipelineLayout");
}

/// A pass's command buffer (reset and re-recorded each run) on the device's queue family, its
/// fence, and `timestamps` timestamp queries when the queue has them.
pub fn passCommands(d: *const Device, pool: *c.VkCommandPool, cmd: *c.VkCommandBuffer, fence: *c.VkFence, queries: *c.VkQueryPool, timestamps: u32) Error!void {
    var cpi = std.mem.zeroes(c.VkCommandPoolCreateInfo);
    cpi.sType = c.VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    cpi.flags = c.VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    cpi.queueFamilyIndex = d.family;
    try check(c.vkCreateCommandPool(d.dev, &cpi, null, pool), "vkCreateCommandPool");
    var cbai = std.mem.zeroes(c.VkCommandBufferAllocateInfo);
    cbai.sType = c.VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cbai.commandPool = pool.*;
    cbai.level = c.VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cbai.commandBufferCount = 1;
    try check(c.vkAllocateCommandBuffers(d.dev, &cbai, cmd), "vkAllocateCommandBuffers");
    var fci = std.mem.zeroes(c.VkFenceCreateInfo);
    fci.sType = c.VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    try check(c.vkCreateFence(d.dev, &fci, null, fence), "vkCreateFence");
    if (d.timestamp_ns > 0) {
        var qpci = std.mem.zeroes(c.VkQueryPoolCreateInfo);
        qpci.sType = c.VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
        qpci.queryType = c.VK_QUERY_TYPE_TIMESTAMP;
        qpci.queryCount = timestamps;
        try check(c.vkCreateQueryPool(d.dev, &qpci, null, queries), "vkCreateQueryPool");
    }
}

/// A whole buffer's queue family ownership transfer (FOREIGN for a dmabuf) with its accesses.
pub fn bufferBarrier(buffer: c.VkBuffer, from: u32, to: u32, src: c.VkAccessFlags, dst: c.VkAccessFlags) c.VkBufferMemoryBarrier {
    var b = std.mem.zeroes(c.VkBufferMemoryBarrier);
    b.sType = c.VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    b.srcAccessMask = src;
    b.dstAccessMask = dst;
    b.srcQueueFamilyIndex = from;
    b.dstQueueFamilyIndex = to;
    b.buffer = buffer;
    b.offset = 0;
    b.size = c.VK_WHOLE_SIZE;
    return b;
}

/// Waits for the work `fence` signals, then resets it for the next submission. Past 2 s it logs
/// and waits on: until the work ends, the fence and what the work writes (an imported shadow, a
/// surface) must not be reset, reused or freed. A hung GPU is reset by the kernel and the wait
/// ends with the device lost.
pub fn waitFence(d: *const Device, fence: c.VkFence) Error!void {
    var r = c.vkWaitForFences(d.dev, 1, &fence, c.VK_TRUE, 2 * std.time.ns_per_s);
    if (r == c.VK_TIMEOUT) {
        log.warn("a GPU pass has not finished in 2 s; waiting for it", .{});
        r = c.vkWaitForFences(d.dev, 1, &fence, c.VK_TRUE, std.math.maxInt(u64));
    }
    try check(r, "vkWaitForFences");
    try check(c.vkResetFences(d.dev, 1, &fence), "vkResetFences");
}

const api_1_2: u32 = (1 << 22) | (2 << 12);

const required_exts = [_][*:0]const u8{
    "VK_KHR_external_memory_fd",
    "VK_EXT_external_memory_dma_buf",
    "VK_EXT_queue_family_foreign",
    "VK_KHR_push_descriptor",
};

const host_ext: [*:0]const u8 = "VK_EXT_external_memory_host";
const sync_fd_ext: [*:0]const u8 = "VK_KHR_external_semaphore_fd";
const modifier_ext: [*:0]const u8 = "VK_EXT_image_drm_format_modifier";

/// Why `Device.open` found no device, in words.
pub const Why = struct {
    buf: [200]u8 = undefined,
    len: usize = 0,

    pub fn set(w: ?*Why, comptime fmt: []const u8, args: anytype) void {
        const self = w orelse return;
        const t = std.fmt.bufPrint(&self.buf, fmt, args) catch self.buf[0..];
        self.len = t.len;
    }

    pub fn text(w: *const Why) []const u8 {
        return w.buf[0..w.len];
    }
};

fn isNode(drm: c.VkPhysicalDeviceDrmPropertiesEXT, devt: u64) bool {
    const major = dmabuf.devMajor(devt);
    const minor = dmabuf.devMinor(devt);
    const render = drm.hasRender != 0 and drm.renderMajor == major and drm.renderMinor == minor;
    const primary = drm.hasPrimary != 0 and drm.primaryMajor == major and drm.primaryMinor == minor;
    return render or primary;
}

pub const Device = struct {
    instance: c.VkInstance,
    phys: c.VkPhysicalDevice,
    dev: c.VkDevice,
    queue: c.VkQueue,
    family: u32,
    mem_props: c.VkPhysicalDeviceMemoryProperties,
    get_memory_fd_properties: c.PFN_vkGetMemoryFdPropertiesKHR,
    cmd_push_descriptor_set: c.PFN_vkCmdPushDescriptorSetKHR,
    /// Host memory import, and the alignment its pointer and size need.
    get_host_pointer_properties: c.PFN_vkGetMemoryHostPointerPropertiesEXT = null,
    host_align: u64 = 0,
    /// sync_file payloads can be imported into semaphores.
    import_semaphore_fd: c.PFN_vkImportSemaphoreFdKHR = null,
    /// ns per timestamp tick, 0: the queue has no timestamps.
    timestamp_ns: f64 = 0,
    /// Images import dmabufs with explicit modifiers and NV12 images exist (the H.264 encoder's
    /// input surfaces written on the GPU).
    modifier_images: bool = false,
    /// Its DRM nodes (VK_EXT_physical_device_drm).
    drm: c.VkPhysicalDeviceDrmPropertiesEXT = undefined,
    name_buf: [c.VK_MAX_PHYSICAL_DEVICE_NAME_SIZE]u8 = undefined,
    name_len: usize = 0,

    /// The device whose DRM primary or render node is `devt` (a dev_t). NoDevice when there is no
    /// Vulkan, no such device, or it lacks dmabuf import.
    pub fn open(devt: u64, why: ?*Why) Error!Device {
        var app = std.mem.zeroes(c.VkApplicationInfo);
        app.sType = c.VK_STRUCTURE_TYPE_APPLICATION_INFO;
        app.pApplicationName = "omastation";
        app.apiVersion = api_1_2;
        var ici = std.mem.zeroes(c.VkInstanceCreateInfo);
        ici.sType = c.VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
        ici.pApplicationInfo = &app;
        var instance: c.VkInstance = null;
        if (c.vkCreateInstance(&ici, null, &instance) != c.VK_SUCCESS) {
            Why.set(why, "no Vulkan (the loader or a driver is missing)", .{});
            return error.NoDevice;
        }
        errdefer c.vkDestroyInstance(instance, null);

        var n: u32 = 0;
        try check(c.vkEnumeratePhysicalDevices(instance, &n, null), "vkEnumeratePhysicalDevices");
        var physs: [16]c.VkPhysicalDevice = undefined;
        n = @min(n, physs.len);
        const enumerated = c.vkEnumeratePhysicalDevices(instance, &n, &physs);
        if (enumerated != c.VK_INCOMPLETE) try check(enumerated, "vkEnumeratePhysicalDevices");
        const major = dmabuf.devMajor(devt);
        const minor = dmabuf.devMinor(devt);
        var drm = std.mem.zeroes(c.VkPhysicalDeviceDrmPropertiesEXT);
        const phys = for (physs[0..n]) |p| {
            if (!hasExtension(p, "VK_EXT_physical_device_drm")) continue;
            drm = std.mem.zeroes(c.VkPhysicalDeviceDrmPropertiesEXT);
            drm.sType = c.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRM_PROPERTIES_EXT;
            var props2 = std.mem.zeroes(c.VkPhysicalDeviceProperties2);
            props2.sType = c.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
            props2.pNext = &drm;
            c.vkGetPhysicalDeviceProperties2(p, &props2);
            if (isNode(drm, devt)) break p;
        } else {
            Why.set(why, "no Vulkan driver for DRM device {d}:{d} ({d} Vulkan devices, none of them it)", .{ major, minor, n });
            return error.NoDevice;
        };
        for (required_exts) |e| if (!hasExtension(phys, std.mem.span(e))) {
            Why.set(why, "the Vulkan driver for DRM device {d}:{d} lacks {s}", .{ major, minor, e });
            return error.NoDevice;
        };

        var nq: u32 = 0;
        c.vkGetPhysicalDeviceQueueFamilyProperties(phys, &nq, null);
        var qprops: [16]c.VkQueueFamilyProperties = undefined;
        nq = @min(nq, qprops.len);
        c.vkGetPhysicalDeviceQueueFamilyProperties(phys, &nq, &qprops);
        // The first compute-capable family (the graphics one on AMD): an async compute family is
        // no faster end to end.
        const fam: u32 = for (qprops[0..nq], 0..) |q, i| {
            if (q.queueFlags & c.VK_QUEUE_COMPUTE_BIT != 0) break @intCast(i);
        } else {
            Why.set(why, "the Vulkan device for DRM device {d}:{d} has no compute queue", .{ major, minor });
            return error.NoDevice;
        };

        var exts: [required_exts.len + 3][*:0]const u8 = undefined;
        @memcpy(exts[0..required_exts.len], &required_exts);
        var next = required_exts.len;
        const has_host = hasExtension(phys, std.mem.span(host_ext));
        if (has_host) {
            exts[next] = host_ext;
            next += 1;
        }
        const has_sync_fd = hasExtension(phys, std.mem.span(sync_fd_ext)) and syncFdImportable(phys);
        if (has_sync_fd) {
            exts[next] = sync_fd_ext;
            next += 1;
        }

        var have11 = std.mem.zeroes(c.VkPhysicalDeviceVulkan11Features);
        have11.sType = c.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_1_FEATURES;
        var have = std.mem.zeroes(c.VkPhysicalDeviceFeatures2);
        have.sType = c.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;
        have.pNext = &have11;
        c.vkGetPhysicalDeviceFeatures2(phys, &have);
        const feats = have.features;
        const has_modifiers = have11.samplerYcbcrConversion != 0 and hasExtension(phys, std.mem.span(modifier_ext));
        if (has_modifiers) {
            exts[next] = modifier_ext;
            next += 1;
        }
        var want11 = std.mem.zeroes(c.VkPhysicalDeviceVulkan11Features);
        want11.sType = c.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_1_FEATURES;
        want11.samplerYcbcrConversion = @intFromBool(has_modifiers);
        var want = std.mem.zeroes(c.VkPhysicalDeviceFeatures2);
        want.sType = c.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;
        want.pNext = &want11;
        want.features.robustBufferAccess = feats.robustBufferAccess;
        const prio: f32 = 1.0;
        var qci = std.mem.zeroes(c.VkDeviceQueueCreateInfo);
        qci.sType = c.VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
        qci.queueFamilyIndex = fam;
        qci.queueCount = 1;
        qci.pQueuePriorities = &prio;
        var dci = std.mem.zeroes(c.VkDeviceCreateInfo);
        dci.sType = c.VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
        dci.queueCreateInfoCount = 1;
        dci.pQueueCreateInfos = &qci;
        dci.pNext = &want;
        dci.enabledExtensionCount = @intCast(next);
        dci.ppEnabledExtensionNames = &exts;
        var dev: c.VkDevice = null;
        try check(c.vkCreateDevice(phys, &dci, null, &dev), "vkCreateDevice");
        errdefer c.vkDestroyDevice(dev, null);
        var queue: c.VkQueue = null;
        c.vkGetDeviceQueue(dev, fam, 0, &queue);

        var d: Device = .{
            .instance = instance,
            .phys = phys,
            .dev = dev,
            .queue = queue,
            .family = fam,
            .mem_props = undefined,
            .get_memory_fd_properties = @ptrCast(c.vkGetDeviceProcAddr(dev, "vkGetMemoryFdPropertiesKHR")),
            .cmd_push_descriptor_set = @ptrCast(c.vkGetDeviceProcAddr(dev, "vkCmdPushDescriptorSetKHR")),
            .drm = drm,
        };
        d.drm.pNext = null;
        if (d.get_memory_fd_properties == null or d.cmd_push_descriptor_set == null) return error.NoDevice;
        if (has_host) {
            var hp = std.mem.zeroes(c.VkPhysicalDeviceExternalMemoryHostPropertiesEXT);
            hp.sType = c.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_MEMORY_HOST_PROPERTIES_EXT;
            var p2 = std.mem.zeroes(c.VkPhysicalDeviceProperties2);
            p2.sType = c.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
            p2.pNext = &hp;
            c.vkGetPhysicalDeviceProperties2(phys, &p2);
            d.host_align = hp.minImportedHostPointerAlignment;
            d.get_host_pointer_properties = @ptrCast(c.vkGetDeviceProcAddr(dev, "vkGetMemoryHostPointerPropertiesEXT"));
        }
        if (has_sync_fd) d.import_semaphore_fd = @ptrCast(c.vkGetDeviceProcAddr(dev, "vkImportSemaphoreFdKHR"));
        d.modifier_images = has_modifiers;
        c.vkGetPhysicalDeviceMemoryProperties(phys, &d.mem_props);
        var props = std.mem.zeroes(c.VkPhysicalDeviceProperties);
        c.vkGetPhysicalDeviceProperties(phys, &props);
        if (qprops[fam].timestampValidBits != 0) d.timestamp_ns = props.limits.timestampPeriod;
        const dev_name = std.mem.sliceTo(&props.deviceName, 0);
        d.name_len = dev_name.len;
        @memcpy(d.name_buf[0..dev_name.len], dev_name);
        log.info("Vulkan compute on {s} ({d}:{d}), robust buffer access {s}, host import {s}, sync_file waits {s}", .{
            dev_name,                                                   major,                                                              minor,
            if (feats.robustBufferAccess != 0) "on" else "unavailable", if (d.get_host_pointer_properties != null) "on" else "unavailable", if (d.import_semaphore_fd != null) "on" else "unavailable",
        });
        return d;
    }

    pub fn deinit(d: *Device) void {
        _ = c.vkDeviceWaitIdle(d.dev);
        c.vkDestroyDevice(d.dev, null);
        c.vkDestroyInstance(d.instance, null);
        d.* = undefined;
    }

    /// Whether `devt` (a dev_t) is this device's DRM primary or render node.
    pub fn hasNode(d: *const Device, devt: u64) bool {
        return isNode(d.drm, devt);
    }

    pub fn name(d: *const Device) []const u8 {
        return d.name_buf[0..d.name_len];
    }

    /// A memory type in `bits` with all of `want`, preferring one that also has `prefer`.
    pub fn memoryType(d: *const Device, bits: u32, want: c.VkMemoryPropertyFlags, prefer: c.VkMemoryPropertyFlags) ?u32 {
        var fallback: ?u32 = null;
        for (0..d.mem_props.memoryTypeCount) |i| {
            if (bits & (@as(u32, 1) << @intCast(i)) == 0) continue;
            const f = d.mem_props.memoryTypes[i].propertyFlags;
            if (f & want != want) continue;
            if (f & prefer == prefer) return @intCast(i);
            if (fallback == null) fallback = @intCast(i);
        }
        return fallback;
    }
};

/// Whether binary semaphores take sync_file payloads (the compositor's dmabuf fences).
fn syncFdImportable(phys: c.VkPhysicalDevice) bool {
    var info = std.mem.zeroes(c.VkPhysicalDeviceExternalSemaphoreInfo);
    info.sType = c.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_SEMAPHORE_INFO;
    info.handleType = c.VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT;
    var props = std.mem.zeroes(c.VkExternalSemaphoreProperties);
    props.sType = c.VK_STRUCTURE_TYPE_EXTERNAL_SEMAPHORE_PROPERTIES;
    c.vkGetPhysicalDeviceExternalSemaphoreProperties(phys, &info, &props);
    return props.externalSemaphoreFeatures & c.VK_EXTERNAL_SEMAPHORE_FEATURE_IMPORTABLE_BIT != 0;
}

fn hasExtension(phys: c.VkPhysicalDevice, ext: []const u8) bool {
    var n: u32 = 0;
    if (c.vkEnumerateDeviceExtensionProperties(phys, null, &n, null) != c.VK_SUCCESS) return false;
    var props: [512]c.VkExtensionProperties = undefined;
    n = @min(n, props.len);
    const enumerated = c.vkEnumerateDeviceExtensionProperties(phys, null, &n, &props);
    if (enumerated != c.VK_SUCCESS and enumerated != c.VK_INCOMPLETE) return false;
    for (props[0..n]) |p| if (std.mem.eql(u8, std.mem.sliceTo(&p.extensionName, 0), ext)) return true;
    return false;
}

/// A buffer in host-visible memory, mapped for its lifetime.
pub const HostBuffer = struct {
    buffer: c.VkBuffer = null,
    memory: c.VkDeviceMemory = null,
    size: usize = 0,
    map: []u8 = &.{},
    coherent: bool = true,

    /// Host-visible, cached when the device has such memory (CPU reads at RAM speed).
    pub fn create(d: *const Device, size: usize, usage: c.VkBufferUsageFlags) Error!HostBuffer {
        var bci = std.mem.zeroes(c.VkBufferCreateInfo);
        bci.sType = c.VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        bci.size = size;
        bci.usage = usage;
        bci.sharingMode = c.VK_SHARING_MODE_EXCLUSIVE;
        var b: HostBuffer = .{ .size = size };
        try check(c.vkCreateBuffer(d.dev, &bci, null, &b.buffer), "vkCreateBuffer(host)");
        errdefer c.vkDestroyBuffer(d.dev, b.buffer, null);
        var req: c.VkMemoryRequirements = undefined;
        c.vkGetBufferMemoryRequirements(d.dev, b.buffer, &req);
        const ty = d.memoryType(req.memoryTypeBits, c.VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT, c.VK_MEMORY_PROPERTY_HOST_CACHED_BIT | c.VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) orelse return error.Unsupported;
        b.coherent = d.mem_props.memoryTypes[ty].propertyFlags & c.VK_MEMORY_PROPERTY_HOST_COHERENT_BIT != 0;
        var mai = std.mem.zeroes(c.VkMemoryAllocateInfo);
        mai.sType = c.VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        mai.allocationSize = req.size;
        mai.memoryTypeIndex = ty;
        try check(c.vkAllocateMemory(d.dev, &mai, null, &b.memory), "vkAllocateMemory(host)");
        errdefer c.vkFreeMemory(d.dev, b.memory, null);
        try check(c.vkBindBufferMemory(d.dev, b.buffer, b.memory, 0), "vkBindBufferMemory(host)");
        var p: ?*anyopaque = null;
        try check(c.vkMapMemory(d.dev, b.memory, 0, c.VK_WHOLE_SIZE, 0, &p), "vkMapMemory");
        b.map = @as([*]u8, @ptrCast(p.?))[0..size];
        return b;
    }

    /// Makes GPU writes visible to the CPU on non-coherent memory.
    pub fn invalidate(b: *const HostBuffer, d: *const Device) Error!void {
        if (b.coherent) return;
        var r = std.mem.zeroes(c.VkMappedMemoryRange);
        r.sType = c.VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE;
        r.memory = b.memory;
        r.size = c.VK_WHOLE_SIZE;
        try check(c.vkInvalidateMappedMemoryRanges(d.dev, 1, &r), "vkInvalidateMappedMemoryRanges");
    }

    /// Makes CPU writes visible to the GPU on non-coherent memory.
    pub fn flush(b: *const HostBuffer, d: *const Device) Error!void {
        if (b.coherent) return;
        var r = std.mem.zeroes(c.VkMappedMemoryRange);
        r.sType = c.VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE;
        r.memory = b.memory;
        r.size = c.VK_WHOLE_SIZE;
        try check(c.vkFlushMappedMemoryRanges(d.dev, 1, &r), "vkFlushMappedMemoryRanges");
    }

    pub fn destroy(b: *HostBuffer, d: *const Device) void {
        if (b.memory != null) {
            c.vkUnmapMemory(d.dev, b.memory);
            c.vkFreeMemory(d.dev, b.memory, null);
        }
        if (b.buffer != null) c.vkDestroyBuffer(d.dev, b.buffer, null);
        b.* = .{};
    }
};

/// A dmabuf imported as a storage buffer (LINEAR layouts only: offset + row stride address it).
/// Vulkan holds its own reference to the dmabuf.
pub const DmabufBuffer = struct {
    buffer: c.VkBuffer = null,
    memory: c.VkDeviceMemory = null,

    pub fn import(d: *const Device, fd: c_int, size: usize) Error!DmabufBuffer {
        var ext = std.mem.zeroes(c.VkExternalMemoryBufferCreateInfo);
        ext.sType = c.VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_BUFFER_CREATE_INFO;
        ext.handleTypes = c.VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT;
        var bci = std.mem.zeroes(c.VkBufferCreateInfo);
        bci.sType = c.VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        bci.pNext = &ext;
        bci.size = size;
        bci.usage = c.VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
        bci.sharingMode = c.VK_SHARING_MODE_EXCLUSIVE;
        var b: DmabufBuffer = .{};
        try check(c.vkCreateBuffer(d.dev, &bci, null, &b.buffer), "vkCreateBuffer(dmabuf)");
        errdefer c.vkDestroyBuffer(d.dev, b.buffer, null);
        var req: c.VkMemoryRequirements = undefined;
        c.vkGetBufferMemoryRequirements(d.dev, b.buffer, &req);
        const dmabuf_size = c.lseek(fd, 0, c.SEEK_END);
        if (dmabuf_size < 0 or req.size > @as(u64, @intCast(dmabuf_size))) return error.Unsupported;
        var fdp = std.mem.zeroes(c.VkMemoryFdPropertiesKHR);
        fdp.sType = c.VK_STRUCTURE_TYPE_MEMORY_FD_PROPERTIES_KHR;
        try check(d.get_memory_fd_properties.?(d.dev, c.VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT, fd, &fdp), "vkGetMemoryFdPropertiesKHR");
        const ty = d.memoryType(req.memoryTypeBits & fdp.memoryTypeBits, 0, 0) orelse return error.Unsupported;
        // Vulkan takes the fd on success.
        const own = c.fcntl(fd, c.F_DUPFD_CLOEXEC, @as(c_int, 0));
        if (own < 0) return error.VulkanFailed;
        var imp = std.mem.zeroes(c.VkImportMemoryFdInfoKHR);
        imp.sType = c.VK_STRUCTURE_TYPE_IMPORT_MEMORY_FD_INFO_KHR;
        imp.handleType = c.VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT;
        imp.fd = own;
        var ded = std.mem.zeroes(c.VkMemoryDedicatedAllocateInfo);
        ded.sType = c.VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO;
        ded.pNext = &imp;
        ded.buffer = b.buffer;
        var mai = std.mem.zeroes(c.VkMemoryAllocateInfo);
        mai.sType = c.VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        mai.pNext = &ded;
        mai.allocationSize = req.size;
        mai.memoryTypeIndex = ty;
        check(c.vkAllocateMemory(d.dev, &mai, null, &b.memory), "vkAllocateMemory(dmabuf)") catch |e| {
            _ = c.close(own);
            return e;
        };
        errdefer c.vkFreeMemory(d.dev, b.memory, null);
        try check(c.vkBindBufferMemory(d.dev, b.buffer, b.memory, 0), "vkBindBufferMemory(dmabuf)");
        return b;
    }

    pub fn destroy(b: *DmabufBuffer, d: *const Device) void {
        if (b.buffer != null) c.vkDestroyBuffer(d.dev, b.buffer, null);
        if (b.memory != null) c.vkFreeMemory(d.dev, b.memory, null);
        b.* = .{};
    }
};

/// Host memory (page-aligned, whole pages: the encoder's shadow) imported as a storage buffer the
/// GPU writes; coherent, so the CPU sees the writes once the fence signals. The memory must stay
/// allocated until `destroy`.
pub const HostPointerBuffer = struct {
    buffer: c.VkBuffer = null,
    memory: c.VkDeviceMemory = null,

    pub fn import(d: *const Device, mem: []u8) Error!HostPointerBuffer {
        const props_fn = d.get_host_pointer_properties orelse return error.Unsupported;
        if (d.host_align == 0 or @intFromPtr(mem.ptr) % d.host_align != 0 or mem.len % d.host_align != 0 or mem.len == 0) return error.Unsupported;
        var ext = std.mem.zeroes(c.VkExternalMemoryBufferCreateInfo);
        ext.sType = c.VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_BUFFER_CREATE_INFO;
        ext.handleTypes = c.VK_EXTERNAL_MEMORY_HANDLE_TYPE_HOST_ALLOCATION_BIT_EXT;
        var bci = std.mem.zeroes(c.VkBufferCreateInfo);
        bci.sType = c.VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        bci.pNext = &ext;
        bci.size = mem.len;
        bci.usage = c.VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
        bci.sharingMode = c.VK_SHARING_MODE_EXCLUSIVE;
        var b: HostPointerBuffer = .{};
        try check(c.vkCreateBuffer(d.dev, &bci, null, &b.buffer), "vkCreateBuffer(host pointer)");
        errdefer c.vkDestroyBuffer(d.dev, b.buffer, null);
        var req: c.VkMemoryRequirements = undefined;
        c.vkGetBufferMemoryRequirements(d.dev, b.buffer, &req);
        if (req.size > mem.len) return error.Unsupported;
        var hp = std.mem.zeroes(c.VkMemoryHostPointerPropertiesEXT);
        hp.sType = c.VK_STRUCTURE_TYPE_MEMORY_HOST_POINTER_PROPERTIES_EXT;
        try check(props_fn(d.dev, c.VK_EXTERNAL_MEMORY_HANDLE_TYPE_HOST_ALLOCATION_BIT_EXT, mem.ptr, &hp), "vkGetMemoryHostPointerPropertiesEXT");
        const want = c.VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | c.VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
        const ty = d.memoryType(req.memoryTypeBits & hp.memoryTypeBits, want, c.VK_MEMORY_PROPERTY_HOST_CACHED_BIT) orelse return error.Unsupported;
        var imp = std.mem.zeroes(c.VkImportMemoryHostPointerInfoEXT);
        imp.sType = c.VK_STRUCTURE_TYPE_IMPORT_MEMORY_HOST_POINTER_INFO_EXT;
        imp.handleType = c.VK_EXTERNAL_MEMORY_HANDLE_TYPE_HOST_ALLOCATION_BIT_EXT;
        imp.pHostPointer = mem.ptr;
        var mai = std.mem.zeroes(c.VkMemoryAllocateInfo);
        mai.sType = c.VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        mai.pNext = &imp;
        mai.allocationSize = mem.len;
        mai.memoryTypeIndex = ty;
        try check(c.vkAllocateMemory(d.dev, &mai, null, &b.memory), "vkAllocateMemory(host pointer)");
        errdefer c.vkFreeMemory(d.dev, b.memory, null);
        try check(c.vkBindBufferMemory(d.dev, b.buffer, b.memory, 0), "vkBindBufferMemory(host pointer)");
        return b;
    }

    pub fn destroy(b: *HostPointerBuffer, d: *const Device) void {
        if (b.buffer != null) c.vkDestroyBuffer(d.dev, b.buffer, null);
        if (b.memory != null) c.vkFreeMemory(d.dev, b.memory, null);
        b.* = .{};
    }
};

/// The fences a reader of dmabuf `fd` must wait for (its writers), as a sync_file; null when the
/// kernel cannot export them (DMA_BUF_IOCTL_EXPORT_SYNC_FILE, Linux 6.0).
pub fn exportSyncFile(fd: c_int) ?c_int {
    const Arg = extern struct { flags: u32, fd: i32 };
    var arg: Arg = .{ .flags = 1, .fd = -1 }; // DMA_BUF_SYNC_READ
    const export_sync_file: c_ulong = 0xC0086202; // _IOWR('b', 2, struct dma_buf_export_sync_file)
    if (c.ioctl(fd, export_sync_file, &arg) != 0 or arg.fd < 0) return null;
    return arg.fd;
}

test "no device for a DRM node without a Vulkan driver says why" {
    var why: Why = .{};
    try std.testing.expectError(error.NoDevice, Device.open(226 << 8 | 250, &why));
    const t = why.text();
    // Either no Vulkan at all here, or no driver for that node.
    try std.testing.expect(std.mem.startsWith(u8, t, "no Vulkan"));
    if (std.mem.indexOf(u8, t, "DRM device") != null) try std.testing.expect(std.mem.indexOf(u8, t, "226:250") != null);
}
