//! Server side: connection state machine, auth, framebuffer.

pub const Conn = @import("conn.zig").Conn;
pub const conn = @import("conn.zig");
pub const vc = @import("vc.zig");
pub const features = @import("features.zig");
pub const framebuffer = @import("framebuffer.zig");
pub const encoder = @import("encoder.zig");
pub const codec_policy = @import("codec_policy.zig");
pub const adapt = @import("adapt.zig");
pub const pacing = @import("pacing.zig");
pub const netdetect = @import("netdetect.zig");
pub const dvcqueue = @import("dvcqueue.zig");
pub const gfx_codecs = @import("gfx_codecs.zig");
pub const video = @import("video.zig");
pub const scene = @import("scene.zig");
pub const compression = @import("compression.zig");
pub const legacy = @import("legacy.zig");
pub const pointer = @import("pointer.zig");
pub const seat = @import("seat.zig");
pub const deadline = @import("deadline.zig");
pub const auth = @import("auth.zig");
pub const sspi_harness = @import("sspi_harness.zig");
pub const udp = @import("udp.zig");
pub const multitransport = @import("multitransport.zig");
pub const flight = @import("flight.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
