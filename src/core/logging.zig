//! Run-time log level filter. Debug is opt-in: it logs every key event.
const std = @import("std");

pub var level: std.log.Level = .info;

pub fn enabled(l: std.log.Level) bool {
    return @backingInt(l) <= @backingInt(level);
}

/// "err", "warn", "info" or "debug".
pub fn parseLevel(name: []const u8) ?std.log.Level {
    return std.meta.stringToEnum(std.log.Level, name);
}

test "debug output is off unless asked for" {
    try std.testing.expectEqual(std.log.Level.info, level);
    try std.testing.expect(enabled(.err) and enabled(.warn) and enabled(.info));
    try std.testing.expect(!enabled(.debug));
    try std.testing.expectEqual(std.log.Level.debug, parseLevel("debug").?);
    try std.testing.expectEqual(@as(?std.log.Level, null), parseLevel("verbose"));
}
