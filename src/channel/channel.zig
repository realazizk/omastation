//! Virtual channel protocols: message formats and server-side state machines.

pub const cliprdr = @import("cliprdr.zig");
pub const rdpsnd = @import("rdpsnd.zig");
pub const audin = @import("audin.zig");
pub const rdpdr = @import("rdpdr.zig");
pub const rail = @import("rail.zig");
pub const echo = @import("echo.zig");
pub const rdpei = @import("rdpei.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
