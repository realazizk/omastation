//! Touch and pen input (MS-RDPEI) on the RDPEI dynamic channel. Malformed or
//! out-of-sequence PDUs are ignored (3.1.5.1); input is suspended while the desk
//! has a look. Touch positions are never logged.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const rdpei = @import("../channel/rdpei.zig");
const desktop_mod = @import("../session/desktop.zig");
const vc = @import("vc.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.touch);

/// How often a ready channel checks whether the desk has a look.
const suspend_check_ms = 250;

pub const Mode = enum {
    /// Desktop sessions only.
    auto,
    /// Also without a desktop (contacts are counted and dropped).
    on,
    off,
};

pub const Touch = struct {
    pub const dynamic_channels = [_]vc.Dynamic{.{ .name = rdpei.channel_name }};

    conn: *Conn,
    srv: rdpei.Server = .{},
    arena: std.heap.ArenaAllocator,
    ch: ?vc.Channel = null,
    mode: desktop_mod.TouchMode = .off,
    stats: Stats = .{},

    pub const Stats = struct {
        touch_frames: u64 = 0,
        pen_frames: u64 = 0,
        dismissed: u64 = 0,
        /// Malformed or out-of-sequence PDUs ignored.
        ignored: u64 = 0,
        suspends: u32 = 0,
    };

    pub fn init(c: *Conn) vc.Error!?Touch {
        if (c.vc.drdynvc == null) return null;
        switch (c.vc.opts.touch) {
            .off => return null,
            .auto => if (c.desktop == null) return null,
            .on => {},
        }
        return .{ .conn = c, .arena = .init(c.gpa) };
    }

    pub fn deinit(t: *Touch) void {
        t.closeDesktop();
        t.arena.deinit();
    }

    /// SC_READY at once (MS-RDPEI 3.2.5.1).
    pub fn open(t: *Touch, ch: vc.Channel) vc.Error!void {
        t.ch = ch;
        t.srv = .{};
        var buf: [16]u8 = undefined;
        var list = std.ArrayList(u8).initBuffer(&buf);
        var w = bytes.Writer.init(&list, std.mem.Allocator.failing);
        t.srv.start(&w) catch |err| return mapErr(err);
        try ch.send(list.items);
    }

    pub fn data(t: *Touch, _: vc.Channel, msg: []const u8) vc.Error!void {
        _ = t.arena.reset(.retain_capacity);
        const ev = t.srv.receive(t.arena.allocator(), msg) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                t.stats.ignored += 1;
                log.debug("{s}: ignoring an input channel PDU ({t}, {d} bytes)", .{ t.conn.peer, err, msg.len });
                return;
            },
        };
        const d = t.conn.desktop;
        switch (ev) {
            .ready => |cs| {
                const pen = t.srv.penAllowed() catch false;
                log.info("{s}: touch input ready: protocol 0x{x:0>8}, up to {d} contacts, pen {s}", .{ t.conn.peer, cs.protocol_version, cs.max_touch_contacts, if (pen) "yes" else "no" });
                if (d) |dd| {
                    t.mode = try dd.openTouch(.{ .pen = pen });
                    log.info("{s}: touch input goes {s}", .{ t.conn.peer, switch (t.mode) {
                        .devices => "to the helper's touchscreens",
                        .emulated => "to the pointer (no helper)",
                        .off => "nowhere",
                    } });
                }
            },
            .touch => |te| {
                t.stats.touch_frames += te.frames.len;
                if (d) |dd| try dd.onTouch(&te);
            },
            .pen => |pe| {
                t.stats.pen_frames += pe.frames.len;
                if (d) |dd| try dd.onPen(&pe);
            },
            .dismiss_hovering => |id| {
                t.stats.dismissed += 1;
                if (d) |dd| try dd.onDismissHovering(id);
            },
        }
    }

    pub fn close(t: *Touch, _: vc.Channel, _: vc.Closed) void {
        t.ch = null;
        t.srv = .{};
        t.closeDesktop();
    }

    /// SUSPEND_INPUT while the desk has a look, RESUME_INPUT after.
    pub fn tick(t: *Touch, now_ms: i64) vc.Error!?i64 {
        const ch = t.ch orelse return null;
        if (t.srv.state != .ready) return null;
        const d = t.conn.desktop orelse return null;
        const want = d.inputSuspended();
        if (want != t.srv.suspended) {
            var buf: [8]u8 = undefined;
            var list = std.ArrayList(u8).initBuffer(&buf);
            var w = bytes.Writer.init(&list, std.mem.Allocator.failing);
            if (want) {
                _ = t.srv.suspendInput(&w) catch |err| return mapErr(err);
                d.releaseTouch();
                t.stats.suspends += 1;
                log.info("{s}: touch input suspended (the desk has a look)", .{t.conn.peer});
            } else {
                _ = t.srv.resumeInput(&w) catch |err| return mapErr(err);
                log.info("{s}: touch input resumed", .{t.conn.peer});
            }
            try ch.send(list.items);
        }
        return now_ms + suspend_check_ms;
    }

    fn closeDesktop(t: *Touch) void {
        if (t.mode == .off) return;
        t.mode = .off;
        if (t.conn.desktop) |d| d.closeTouch();
    }
};

/// rdpei encoders fail only for values omastation never writes.
fn mapErr(err: rdpei.Error) vc.Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.ProtocolError,
    };
}
