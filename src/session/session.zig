//! Desktop session integration: Hyprland outputs, console fencing, locking, clipboard, RemoteApp.

pub const hypr = @import("hypr.zig");
pub const console = @import("console.zig");
pub const fence = @import("fence.zig");
pub const fence_daemon = @import("fence_daemon.zig");
pub const helper = @import("helper.zig");
pub const helper_proto = @import("helper_proto.zig");
pub const uinput = @import("uinput.zig");
pub const touch = @import("touch.zig");
pub const desktop = @import("desktop.zig");
pub const cursor = @import("cursor.zig");
pub const altdrag = @import("altdrag.zig");
pub const plugin = @import("plugin.zig");
pub const textbinds = @import("textbinds.zig");
pub const keyrepeat = @import("keyrepeat.zig");
pub const probe = @import("probe.zig");
pub const multimon = @import("multimon.zig");
pub const clipboard = @import("clipboard.zig");
pub const clipfs = @import("clipfs.zig");
pub const toplevels = @import("toplevels.zig");
pub const xdg = @import("xdg.zig");
pub const icon = @import("icon.zig");
pub const remoteapp = @import("remoteapp.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
