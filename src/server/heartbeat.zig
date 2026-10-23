//! Server Heartbeat PDU (MS-RDPBCGR 1.3.10, 2.2.16.1) on the MCS message channel, for clients
//! that set RNS_UD_CS_SUPPORT_HEARTBEAT_PDU. Sent outside the send window.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const se = @import("../proto/session_ext.zig");
const vc = @import("vc.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.heartbeat);

/// Windows server defaults.
pub const default_period_s: u8 = 1;
pub const count1: u8 = 8;
pub const count2: u8 = 12;

pub const Heartbeat = struct {
    conn: *Conn,
    period_ms: i64,
    hb: se.Heartbeat,
    next_ms: ?i64 = null,
    sent: u32 = 0,

    pub fn init(c: *Conn) vc.Error!?Heartbeat {
        const period = c.vc.opts.heartbeat_period_s;
        if (period == 0 or !c.client.early_caps.support_heartbeat_pdu or c.msg_channel == null) return null;
        return .{ .conn = c, .period_ms = @as(i64, period) * 1000, .hb = .{ .period = period, .count1 = count1, .count2 = count2 } };
    }

    pub fn tick(h: *Heartbeat, now_ms: i64) vc.Error!?i64 {
        const due = h.next_ms orelse {
            h.next_ms = now_ms + h.period_ms;
            return h.next_ms;
        };
        if (now_ms < due) return due;
        var buf: [8]u8 = undefined;
        var list = std.ArrayList(u8).initBuffer(&buf);
        var w = bytes.Writer.init(&list, std.mem.Allocator.failing);
        try se.encodeHeartbeatPdu(&w, h.hb);
        try h.conn.sendControl(h.conn.msg_channel.?, list.items);
        h.sent += 1;
        if (h.sent == 1) log.debug("{s}: heartbeats every {d} s (warning after {d}, reconnect after {d} more)", .{ h.conn.peer, h.hb.period, count1, count2 });
        // A late tick does not bunch up the following ones.
        h.next_ms = @max(due + h.period_ms, now_ms + @divTrunc(h.period_ms, 2));
        return h.next_ms;
    }
};
