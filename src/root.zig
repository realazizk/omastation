//! omastation library root. Every module is re-exported here so `zig build test`
//! reaches all unit tests.

pub const bytes = @import("core/bytes.zig");
pub const logging = @import("core/logging.zig");
pub const tpkt = @import("proto/tpkt.zig");
pub const x224 = @import("proto/x224.zig");
pub const ber = @import("proto/ber.zig");
pub const per = @import("proto/per.zig");
pub const gcc = @import("proto/gcc.zig");
pub const mcs = @import("proto/mcs.zig");
pub const caps = @import("proto/caps.zig");
pub const rdp = @import("proto/rdp.zig");
pub const fastpath = @import("proto/fastpath.zig");
pub const pointer = @import("proto/pointer.zig");
pub const vchan = @import("proto/vchan.zig");
pub const dvc = @import("proto/dvc.zig");
pub const gfx = @import("proto/gfx.zig");
pub const disp = @import("proto/disp.zig");
pub const session_ext = @import("proto/session_ext.zig");
pub const socket = @import("net/socket.zig");
pub const tls = @import("net/tls.zig");
pub const transport = @import("net/transport.zig");
pub const sendq = @import("net/sendq.zig");
pub const multitransport = @import("net/multitransport.zig");
pub const server = @import("server/server.zig");
pub const session = @import("session/session.zig");
pub const codec = @import("codec/codec.zig");
pub const input = @import("input/input.zig");
pub const sec = @import("sec/sec.zig");
pub const wl = @import("wl/wl.zig");
pub const audio = @import("audio/audio.zig");
pub const channel = @import("channel/channel.zig");
pub const drives = @import("drives/drives.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
