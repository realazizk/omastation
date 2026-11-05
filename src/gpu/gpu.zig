//! GPU helpers outside the pure-Zig Wayland client: dmabuf allocation (libgbm), Vulkan compute
//! on captured frames (change detection), and their use by capture.

pub const gbm = @import("gbm.zig");
pub const vk = @import("vk.zig");
pub const tilediff = @import("tilediff.zig");
pub const nv12 = @import("nv12.zig");
pub const capture = @import("capture.zig");

test {
    _ = gbm;
    _ = vk;
    _ = tilediff;
    _ = nv12;
    _ = capture;
}
