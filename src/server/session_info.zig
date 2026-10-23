//! What the server tells the client about its session (MS-RDPBCGR): the logon notification (3.3.5.10.1),
//! the auto-reconnect cookie (1.3.1.5, 5.5), Set Keyboard Indicators (2.2.8.2.1), the Monitor Layout PDU
//! (2.2.12.1) and Play Sound (2.2.9.1.1.5) for the bell. Only Play Sound is bulk-compressed (3.1.8).

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const se = @import("../proto/session_ext.zig");
const rdp = @import("../proto/rdp.zig");
const mcs = @import("../proto/mcs.zig");
const caps = @import("../proto/caps.zig");
const fastpath = @import("../proto/fastpath.zig");
const auth = @import("auth.zig");
const seat_mod = @import("seat.zig");
const altdrag = @import("../session/altdrag.zig");
const vc = @import("vc.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.session);

/// The auto-reconnect cookie is replaced this often (1.3.1.5).
pub const arc_refresh_ms: i64 = 60 * 60 * 1000;

/// Linux console bell: 750 Hz, 125 ms.
pub const bell: se.PlaySound = .{ .duration = 125, .frequency = 750 };
pub const bell_gap_ms: i64 = 250;

/// The LedFlags / toggleFlags bits (2.2.8.1.1.3.1.1.5).
pub const led_scroll: u16 = se.ts_sync_scroll_lock;
pub const led_num: u16 = se.ts_sync_num_lock;
pub const led_caps: u16 = se.ts_sync_caps_lock;
pub const led_kana: u16 = se.ts_sync_kana_lock;

pub const SessionInfo = struct {
    /// Licensed, so it exists when its PDUs go out with the Font Map, before vc.start.
    pub const start_stage: vc.Stage = .licensed;

    conn: *Conn,
    arc_next_ms: ?i64 = null,
    leds: Leds = .{},
    lazy: altdrag.LazyCommand = .{},
    next_bell_ms: i64 = 0,

    pub fn init(c: *Conn) vc.Error!?SessionInfo {
        return .{ .conn = c };
    }

    /// Queued after the Font Map.
    pub fn established(s: *SessionInfo) vc.Error!void {
        try queueLogonNotification(s.conn);
        try s.queueCookie(conn_mod.nowMs());
        try s.leds.activate(s.conn, sessionLeds(s.conn));
    }

    pub fn tick(s: *SessionInfo, now_ms: i64) vc.Error!?i64 {
        try s.leds.check(s.conn, sessionLeds(s.conn));
        if (s.conn.desktop) |d| if (d.bells > 0) {
            d.bells = 0;
            if (now_ms >= s.next_bell_ms and s.conn.established) {
                try sendPlaySound(s.conn, bell);
                s.next_bell_ms = now_ms + bell_gap_ms;
            }
        };
        const due = s.arc_next_ms orelse return null;
        if (now_ms < due) return due;
        try s.queueCookie(now_ms);
        try s.conn.flush();
        wipeOut(s.conn);
        return s.arc_next_ms;
    }

    /// Needs an authenticated user and a seat.
    fn queueCookie(s: *SessionInfo, now_ms: i64) vc.Error!void {
        const c = s.conn;
        const seat = c.seat orelse return;
        const user = c.user orelse return;
        var bits: [16]u8 = undefined;
        auth.secureRandom().bytes(&bits);
        var packet = seat.issueArc(user, bits);
        std.crypto.secureZero(u8, &bits);
        defer std.crypto.secureZero(u8, &packet.arc_random_bits);
        try queueSaveSessionInfo(c, .{ .extended = .{ .auto_reconnect = packet } });
        s.arc_next_ms = now_ms + arc_refresh_ms;
        log.debug("{s}: auto-reconnect cookie sent", .{c.peer});
    }
};

/// Sent in the same write as the Font Map. Flushes.
pub fn onEstablished(c: *Conn) conn_mod.Error!void {
    if (vc.find(c, SessionInfo)) |s| try s.established();
    try c.flush();
    wipeOut(c);
}

/// The cookie's random bits must not linger in the connection's buffer.
fn wipeOut(c: *Conn) void {
    std.crypto.secureZero(u8, c.out.allocatedSlice());
}

/// Tracks the client's LEDs and the macOS lazy ⌘ (altdrag.zig).
pub fn onInput(c: *Conn, ev: fastpath.InputEvent) void {
    const s = vc.find(c, SessionInfo) orelse return;
    s.leds.input(ev);
    macKeys(s, ev);
}

/// `--alt-drag auto`: a client sending ⌘ the macOS way gets the Option twins.
fn macKeys(s: *SessionInfo, ev: fastpath.InputEvent) void {
    const c = s.conn;
    const cfg = c.desktop_cfg orelse return;
    if (cfg.alt_drag != .auto) return;
    if (!altdrag.guessFromKeys(c.client_caps.os_major_type)) return;
    const d = c.desktop orelse return;
    if (d.alt_drag) return;
    switch (ev) {
        .scancode => |k| if (s.lazy.key(k.code, k.flags, conn_mod.nowMs())) {
            log.info("{s}: the Windows key came pressed and released at once, as the Windows App for macOS sends ⌘: adding Option + drag", .{c.peer});
            d.setAltDrag(true);
        },
        .qoe_timestamp => {},
        else => s.lazy.other(),
    }
}

/// Play Sound PDU (3.3.5.9.4.1).
pub fn sendPlaySound(c: *Conn, p: se.PlaySound) conn_mod.Error!void {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(c.gpa);
    var w = bytes.Writer.init(&list, c.gpa);
    const pdu = try rdp.DataPdu.begin(&w, .play_sound, rdp.stream_low);
    try se.encodePlaySoundData(&w, p);
    // Slow-path output: bulk-compressed with the rest of the output (3.1.8).
    if (c.bulk.output()) |cmp| try pdu.finishCompressed(&w, cmp) else pdu.finish(&w);
    try c.sendMcs(mcs.io_channel_id, list.items);
    log.debug("{s}: bell", .{c.peer});
}

fn queueSaveSessionInfo(c: *Conn, info: se.LogonInfo) vc.Error!void {
    var list: std.ArrayList(u8) = .empty;
    defer {
        std.crypto.secureZero(u8, list.allocatedSlice());
        list.deinit(c.gpa);
    }
    var w = bytes.Writer.init(&list, c.gpa);
    se.encodeSaveSessionInfoPdu(&w, rdp.share_id, rdp.server_source, info) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            log.warn("{s}: Save Session Info not sent ({t})", .{ c.peer, err });
            return;
        },
    };
    try c.queueMcs(mcs.io_channel_id, list.items);
}

/// The logon notification for this connection (3.3.5.10.1), queued.
pub fn queueLogonNotification(c: *Conn) vc.Error!void {
    const long = c.client_caps.general_extra_flags & caps.extra_long_credentials_supported != 0;
    var ubuf: [128]u8 = undefined;
    const user = c.user orelse "";
    const n = @min(user.len, ubuf.len / 2);
    for (user[0..n], 0..) |ch, i| {
        ubuf[2 * i] = ch;
        ubuf[2 * i + 1] = 0;
    }
    // Without NLA (TLS-only development mode) nobody logged on by name.
    const info = if (c.user == null) se.LogonInfo.plain_notify else blk: {
        const domain = c.auth_cfg.nb_computer;
        break :blk se.logonNotification(c.info_flags, long, c.logon_names_changed, .{
            .domain = domain[0..@min(domain.len, se.logon_v1_domain_size - 2)],
            .user_name = ubuf[0 .. 2 * n],
            .session_id = seat_mod.session_id,
        }) catch .plain_notify;
    };
    try queueSaveSessionInfo(c, info);
    log.info("{s}: logon notification sent ({t})", .{ c.peer, info });
}

/// `user` is ASCII from the verifier store; an empty client domain matches.
pub fn namesDiffer(client_user: []const u8, client_domain: []const u8, user: []const u8, domain: []const u8) bool {
    return !utf16EqlIgnoreCase(client_user, user, false) or
        (client_domain.len != 0 and !utf16EqlIgnoreCase(client_domain, domain, true));
}

fn utf16EqlIgnoreCase(a: []const u8, b: []const u8, b_utf16: bool) bool {
    const blen = if (b_utf16) b.len / 2 else b.len;
    if (a.len % 2 != 0 or a.len / 2 != blen) return false;
    for (0..blen) |i| {
        const x = std.mem.readInt(u16, a[2 * i ..][0..2], .little);
        const y: u16 = if (b_utf16) std.mem.readInt(u16, b[2 * i ..][0..2], .little) else b[i];
        if (x == y) continue;
        if (x > 0x7f or y > 0x7f) return false;
        if (std.ascii.toLower(@intCast(x)) != std.ascii.toLower(@intCast(y))) return false;
    }
    return true;
}

/// Bits the desktop's keyboard cannot set follow the client; null: all of them do.
pub const SessionLeds = struct { on: u16, known: u16 };

fn sessionLeds(c: *const Conn) ?SessionLeds {
    const d = c.desktop orelse return null;
    const l = d.keyboardLocks() orelse return null;
    return .{ .on = ledFlags(l.on), .known = ledFlags(l.known) };
}

pub fn ledFlags(l: anytype) u16 {
    var f: u16 = 0;
    if (l.caps) f |= led_caps;
    if (l.num) f |= led_num;
    if (l.scroll) f |= led_scroll;
    return f;
}

/// What the client's toggle-key LEDs show, and when to tell it otherwise.
pub const Leds = struct {
    /// The client's LEDs as far as known (null until activation).
    client: ?u16 = null,
    sent: ?u16 = null,
    /// A Synchronize may have crossed `sent`: send the state again.
    resend: bool = false,
    /// Lock keys held (no toggle on typematic repeats).
    held: u16 = 0,
    /// After E1 1D, 45 is Pause, not Num Lock (MS-RDPBCGR 2.2.8.1.2.2.1).
    after_e1: bool = false,

    /// The session state: `ses` where known, the client's elsewhere.
    pub fn target(l: *const Leds, ses: ?SessionLeds) u16 {
        const client = l.client orelse 0;
        const s = ses orelse return client;
        return (s.on & s.known) | (client & ~s.known);
    }

    pub fn activate(l: *Leds, c: *Conn, ses: ?SessionLeds) vc.Error!void {
        try l.send(c, l.target(ses));
    }

    /// Not while a lock key is down: XKB locks on the press but unlocks on the release (LockMods),
    /// so the session catches up with the client's own toggle only then.
    pub fn check(l: *Leds, c: *Conn, ses: ?SessionLeds) vc.Error!void {
        const client = l.client orelse return; // not activated yet
        if (l.held != 0) return;
        const want = l.target(ses);
        if (want != client or l.resend) try l.send(c, want);
    }

    fn send(l: *Leds, c: *Conn, flags: u16) vc.Error!void {
        var body: [4]u8 = undefined;
        var list = std.ArrayList(u8).initBuffer(&body);
        var w = bytes.Writer.init(&list, std.mem.Allocator.failing);
        try se.encodeSetKeyboardIndicatorsData(&w, flags);
        var buf: [32]u8 = undefined;
        var pl = std.ArrayList(u8).initBuffer(&buf);
        var pw = bytes.Writer.init(&pl, std.mem.Allocator.failing);
        // 22 bytes into 32: cannot fail.
        se.encodeShareDataPdu(&pw, .{ .share_id = rdp.share_id, .pdu_source = rdp.server_source, .pdu_type2 = se.pdutype2_set_keyboard_indicators }, list.items) catch unreachable;
        try c.queueMcs(mcs.io_channel_id, pl.items); // flushed by the caller (onEstablished, vc.tick)
        log.debug("{s}: keyboard indicators 0x{x}", .{ c.peer, flags });
        l.sent = flags;
        l.client = flags;
        l.resend = false;
    }

    pub fn input(l: *Leds, ev: fastpath.InputEvent) void {
        switch (ev) {
            .sync => |t| {
                const flags = @as(u16, t) & (led_caps | led_num | led_scroll | led_kana);
                // An earlier indicators PDU may reach the client after this Synchronize.
                if (l.sent) |s| if (s != flags) {
                    l.resend = true;
                };
                l.client = flags;
                l.held = 0;
                l.after_e1 = false;
            },
            .scancode => |k| {
                const e1 = k.flags & fastpath.kbd_extended1 != 0;
                defer l.after_e1 = e1 and k.code == 0x1D;
                if (k.flags & (fastpath.kbd_extended | fastpath.kbd_extended1) != 0) return;
                const bit: u16 = switch (k.code) {
                    0x3A => led_caps,
                    0x45 => if (l.after_e1) return else led_num,
                    0x46 => led_scroll,
                    else => return,
                };
                if (k.flags & fastpath.kbd_release != 0) {
                    l.held &= ~bit;
                    return;
                }
                if (l.held & bit != 0) return; // typematic repeat
                l.held |= bit;
                if (l.client) |*cl| cl.* ^= bit; // the client toggled its own LED
            },
            else => {},
        }
    }
};

/// TS_MONITOR_DEFs (2.2.1.3.6.1, right and bottom inclusive): the desktop's outputs, or in
/// test-pattern mode the client's own monitors.
pub fn sessionMonitors(c: *const Conn, out: *[se.max_monitors]se.MonitorDef) []const se.MonitorDef {
    if (c.desktop) |d| {
        const plan = d.sessionPlan();
        if (plan.count > 0 and plan.count <= out.len) {
            for (plan.monitors[0..plan.count], 0..) |m, i| out[i] = .{ .left = m.left, .top = m.top, .right = m.right, .bottom = m.bottom, .flags = if (m.primary) se.ts_monitor_primary else 0 };
            return out[0..plan.count];
        }
    }
    const ms = c.client.monitorSlice();
    if (c.desktop == null and ms.len > 0 and ms.len <= out.len) {
        for (ms, 0..) |m, i| out[i] = .{ .left = m.left, .top = m.top, .right = m.right, .bottom = m.bottom, .flags = if (m.primary) se.ts_monitor_primary else 0 };
        return out[0..ms.len];
    }
    out[0] = se.monitorDef(0, 0, c.width, c.height, true) catch return out[0..0];
    return out[0..1];
}

/// Only to clients that indicated support (3.3.5.12.1); FreeRDP accepts one per Demand Active.
pub fn sendMonitorLayout(c: *Conn) conn_mod.Error!void {
    if (!c.client.early_caps.support_monitor_layout_pdu) return;
    var defs: [se.max_monitors]se.MonitorDef = undefined;
    const ms = sessionMonitors(c, &defs);
    if (ms.len == 0) return;
    var buf: [32 + se.max_monitors * 20]u8 = undefined;
    var list = std.ArrayList(u8).initBuffer(&buf);
    var w = bytes.Writer.init(&list, std.mem.Allocator.failing);
    se.encodeMonitorLayoutPdu(&w, @bitCast(c.client.early_caps), rdp.share_id, ms) catch |err| {
        log.warn("{s}: Monitor Layout PDU not sent ({t})", .{ c.peer, err });
        return;
    };
    try c.sendMcs(mcs.io_channel_id, list.items);
    log.debug("{s}: monitor layout: {d} monitor(s)", .{ c.peer, ms.len });
}

test "Leds: the client's Synchronize is not echoed; lock keys toggle the client's LEDs once per press" {
    var l = Leds{ .client = 0, .sent = 0 };
    l.input(.{ .sync = @intCast(led_num) });
    try std.testing.expectEqual(@as(?u16, led_num), l.client);
    try std.testing.expect(l.resend); // the sent 0 may have crossed it
    l.resend = false;
    l.sent = led_num;
    l.input(.{ .scancode = .{ .code = 0x3A, .flags = 0 } });
    l.input(.{ .scancode = .{ .code = 0x3A, .flags = 0 } }); // repeat
    try std.testing.expectEqual(@as(?u16, led_num | led_caps), l.client);
    l.input(.{ .scancode = .{ .code = 0x3A, .flags = fastpath.kbd_release } });
    l.input(.{ .scancode = .{ .code = 0x1D, .flags = fastpath.kbd_extended1 } });
    l.input(.{ .scancode = .{ .code = 0x45, .flags = 0 } }); // Pause, not Num Lock
    try std.testing.expectEqual(@as(?u16, led_num | led_caps), l.client);
    try std.testing.expectEqual(led_caps, l.target(.{ .on = led_caps, .known = led_caps | led_num }));
    l.input(.{ .scancode = .{ .code = 0x46, .flags = 0 } });
    try std.testing.expectEqual(led_caps | led_scroll, l.target(.{ .on = led_caps, .known = led_caps | led_num }));
    try std.testing.expectEqual(led_num | led_caps | led_scroll, l.target(null));
}

test "names differ: case-insensitive user, empty client domain matches" {
    const u16le = struct {
        fn f(comptime s: []const u8) [s.len * 2]u8 {
            var o: [s.len * 2]u8 = undefined;
            for (s, 0..) |ch, i| {
                o[2 * i] = ch;
                o[2 * i + 1] = 0;
            }
            return o;
        }
    }.f;
    try std.testing.expect(!namesDiffer(&u16le("Alice"), "", "alice", &u16le("HOST")));
    try std.testing.expect(!namesDiffer(&u16le("alice"), &u16le("host"), "alice", &u16le("HOST")));
    try std.testing.expect(namesDiffer(&u16le("bob"), "", "alice", &u16le("HOST")));
    try std.testing.expect(namesDiffer(&u16le("alice"), &u16le("CORP"), "alice", &u16le("HOST")));
}
