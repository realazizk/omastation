//! ECHO dynamic channel (MS-RDPEECO): periodic Echo Requests when Options.echo_period_ms is set.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const proto = @import("../channel/echo.zig");
const vc = @import("vc.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.echo);

pub const Echo = struct {
    pub const dynamic_channels = [_]vc.Dynamic{.{ .name = proto.channel_name }};

    conn: *Conn,
    period_ms: i64,
    srv: proto.EchoServer,
    ch: ?vc.Channel = null,
    /// When the next request is due; null while one is outstanding.
    next_ms: ?i64 = null,
    seq: u32 = 0,
    answered: u32 = 0,
    last_rtt_ms: u64 = 0,

    pub fn init(c: *Conn) vc.Error!?Echo {
        const period = c.vc.opts.echo_period_ms orelse return null;
        return .{ .conn = c, .period_ms = period, .srv = .{ .gpa = c.gpa } };
    }

    pub fn deinit(e: *Echo) void {
        e.srv.deinit();
    }

    pub fn open(e: *Echo, ch: vc.Channel) vc.Error!void {
        e.ch = ch;
        try e.request(conn_mod.nowMs());
    }

    pub fn data(e: *Echo, _: vc.Channel, msg: []const u8) vc.Error!void {
        const now = conn_mod.nowMs();
        const rtt = e.srv.onResponse(msg, stamp(now)) catch {
            log.debug("{s}: echo response that matches no request (ignored)", .{e.conn.peer});
            return;
        };
        e.answered +|= 1;
        e.last_rtt_ms = rtt;
        log.debug("{s}: echo round trip {d} ms", .{ e.conn.peer, rtt });
        if (e.srv.outstanding.items.len == 0) e.next_ms = now + e.period_ms;
    }

    pub fn close(e: *Echo, _: vc.Channel, _: vc.Closed) void {
        e.ch = null;
        e.next_ms = null;
    }

    pub fn tick(e: *Echo, now_ms: i64) vc.Error!?i64 {
        const due = e.next_ms orelse return null;
        if (now_ms < due) return due;
        e.next_ms = null;
        try e.request(now_ms);
        return null;
    }

    /// ECHO_REQUEST_PDU (MS-RDPEECO 2.2.1).
    fn request(e: *Echo, now_ms: i64) vc.Error!void {
        const ch = e.ch orelse return;
        e.seq +%= 1;
        var payload: [14]u8 = "omastation\x00\x00\x00\x00".*;
        std.mem.writeInt(u32, payload[10..14], e.seq, .little);
        var buf: [payload.len]u8 = undefined;
        var list = std.ArrayList(u8).initBuffer(&buf);
        var w = bytes.Writer.init(&list, std.mem.Allocator.failing);
        try e.srv.request(&w, &payload, stamp(now_ms));
        try ch.send(list.items);
    }
};

fn stamp(now_ms: i64) u64 {
    return @intCast(@max(now_ms, 0));
}

test "answered counter saturates" {
    var fds: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM, 0, &fds));
    defer _ = std.c.close(fds[1]);
    var tls_ctx: @import("../net/tls.zig").Context = undefined;
    var auth_cfg: conn_mod.AuthConfig = undefined;
    var c = Conn.init(std.testing.allocator, @import("../net/transport.zig").Transport.init(fds[0]), &tls_ctx, &auth_cfg, null, "test");
    defer c.deinit();
    var e: Echo = .{ .conn = &c, .period_ms = 0, .srv = .{ .gpa = std.testing.allocator }, .answered = std.math.maxInt(u32) };
    defer e.deinit();
    var buf: [32]u8 = undefined;
    var list = std.ArrayList(u8).initBuffer(&buf);
    var w = bytes.Writer.init(&list, std.mem.Allocator.failing);
    try e.srv.request(&w, "omastation\x01\x00\x00\x00", 1);
    try e.data(undefined, list.items);
    try std.testing.expectEqual(@as(u32, std.math.maxInt(u32)), e.answered);
    try std.testing.expectEqual(@as(usize, 0), e.srv.outstanding.items.len);
}
