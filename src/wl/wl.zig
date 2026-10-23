//! Pure-Zig Wayland client: outputs, frame and cursor capture (ext-image-copy-capture-v1
//! or wlr-screencopy), virtual keyboard and pointer, clipboard (ext-data-control-v1).
//! Errors from dispatch() are fatal for the connection; reconnect from scratch.

pub const sys = @import("sys.zig");
pub const wire = @import("wire.zig");
pub const proto = wire.proto;
pub const scanner = @import("scanner.zig");
pub const client = @import("client.zig");
pub const shm = @import("shm.zig");
pub const capture = @import("capture.zig");
pub const cursor = @import("cursor.zig");
pub const input = @import("input.zig");
pub const data_control = @import("data_control.zig");

pub const Error = wire.Error;
pub const Client = client.Client;
pub const Output = client.Output;
pub const Capture = capture.Capture;
pub const Frame = capture.Frame;
pub const Rect = capture.Rect;
pub const Cursor = cursor.Cursor;
pub const VirtualKeyboard = input.VirtualKeyboard;
pub const VirtualPointer = input.VirtualPointer;
pub const DataControl = data_control.DataControl;

test {
    _ = sys;
    _ = wire;
    _ = scanner;
    _ = client;
    _ = shm;
    _ = capture;
    _ = cursor;
    _ = input;
    _ = data_control;
    _ = @import("fake_test.zig");
}
