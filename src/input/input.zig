pub const translate = @import("translate.zig");
pub const keyboard = @import("keyboard.zig");
pub const layouts = @import("layouts.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
