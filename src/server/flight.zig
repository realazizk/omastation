//! Per-connection flight recorder: a ring of metadata-only events (PDU types, sizes, ids),
//! written to $XDG_RUNTIME_DIR/omastation/flight/ on an abnormal end, on SIGUSR1 or on a panic.
//! Only fixed header offsets are read: never keystrokes, clipboard data, file names or pixels.

const std = @import("std");
const c = @import("c");
const fastpath = @import("../proto/fastpath.zig");

const log = std.log.scoped(.flight);

/// Events per connection (a power of two): 192 KiB.
pub const default_capacity: u32 = 4096;
pub const default_keep: usize = 20;
pub const journal_events: usize = 15;
/// Longest connection-loop sleep while recording; bounds SIGUSR1 dump latency.
pub const live_poll_ms: c_int = 500;

pub const Mode = enum {
    /// On an abnormal end.
    errors,
    always,
    off,
};

pub const Config = struct {
    /// Created 0700, with its parent, on first use.
    dir: []const u8,
    mode: Mode = .errors,
    /// Newest files kept; older ones are deleted after each dump.
    keep: usize = default_keep,
    capacity: u32 = default_capacity,
};

pub const Dir = enum(u8) { none, in, out };

pub const Where = enum(u8) {
    conn,
    /// Disconnect Provider Ultimatum.
    mcs,
    fastpath,
    slowpath,
    /// Auto-detect, heartbeat, multitransport.
    msgchannel,
    drdynvc,
    rdpsnd,
    cliprdr,
    rdpdr,
    rail,
    static,
    rdpgfx,
    disp,
    rdpsnd_dvc,
    audin,
    rdpei,
    echo,
    dvc,

    pub fn label(w: Where) []const u8 {
        return switch (w) {
            .conn => "conn",
            .mcs => "mcs",
            .fastpath => "fast-path",
            .slowpath => "slow-path",
            .msgchannel => "msgchannel",
            .drdynvc => "drdynvc",
            .rdpsnd => "rdpsnd",
            .cliprdr => "cliprdr",
            .rdpdr => "rdpdr",
            .rail => "rail",
            .static => "static",
            .rdpgfx => "rdpgfx",
            .disp => "disp",
            .rdpsnd_dvc => "rdpsnd-dvc",
            .audin => "audin",
            .rdpei => "rdpei",
            .echo => "echo",
            .dvc => "dvc",
        };
    }
};

/// Static channel names match case-insensitively.
pub fn staticWhere(name: []const u8) Where {
    const known = [_]struct { []const u8, Where }{
        .{ "drdynvc", .drdynvc }, .{ "rdpsnd", .rdpsnd }, .{ "cliprdr", .cliprdr },
        .{ "rdpdr", .rdpdr },     .{ "rail", .rail },
    };
    for (known) |k| if (std.ascii.eqlIgnoreCase(name, k[0])) return k[1];
    return .static;
}

pub fn dvcWhere(name: []const u8) Where {
    const known = [_]struct { []const u8, Where }{
        .{ "Microsoft::Windows::RDS::Graphics", .rdpgfx },
        .{ "Microsoft::Windows::RDS::DisplayControl", .disp },
        .{ "AUDIO_PLAYBACK_DVC", .rdpsnd_dvc },
        .{ "AUDIO_PLAYBACK_LOSSY_DVC", .rdpsnd_dvc },
        .{ "AUDIO_INPUT", .audin },
        .{ "Microsoft::Windows::RDS::Input", .rdpei },
        .{ "ECHO", .echo },
    };
    for (known) |k| if (std.mem.eql(u8, name, k[0])) return k[1];
    return .dvc;
}

/// One recorded event; `code` and `f` depend on `where` and `dir` (see `describe`).
pub const Event = extern struct {
    /// CLOCK_MONOTONIC, nanoseconds.
    ns: u64,
    /// Bytes, before bulk compression.
    size: u32,
    code: u16,
    where: Where,
    dir: Dir,
    f: [8]u32,
};

comptime {
    std.debug.assert(@sizeOf(Event) == 48);
}

/// Events of the connection itself (Where.conn).
pub const Milestone = enum(u16) {
    start,
    /// f0 protocols requested, f1 selected.
    x224,
    nla,
    /// f0 client build, f1/f2 desktop size, f3 monitors, f4 static channels, f5 early caps.
    mcs_connect,
    /// f0 Client Info flags, f1 performance flags.
    client_info,
    established,
    /// f0 dump number.
    live_dump,
    /// f0 @intFromError (0: none); f1 1 with f2 the Set Error Info sent;
    /// f3 the Disconnect Provider Ultimatum's Dir (0: none), f4 its reason.
    end,
    /// f0 @intFromError, f1 the PDU's Where; the connection ends.
    failed,
    /// At most every 5 s while graphics are held: f0 peak queued bytes, f1 pacing window, f2 link kB/s,
    /// f4 frames held, f5 longest pass (ms). f3 1: the queue passed its cap (f1); the connection ends.
    backlog,
    _,
};

/// Input events by type; never which keys or characters.
pub const InputCounts = struct {
    keyboard: u32 = 0,
    unicode: u32 = 0,
    mouse: u32 = 0,
    mousex: u32 = 0,
    relative: u32 = 0,
    sync: u32 = 0,
    qoe: u32 = 0,

    pub fn add(n: *InputCounts, ev: fastpath.InputEvent) void {
        switch (ev) {
            .scancode => n.keyboard += 1,
            .unicode => n.unicode += 1,
            .mouse => n.mouse += 1,
            .mousex => n.mousex += 1,
            .mouse_rel => n.relative += 1,
            .sync => n.sync += 1,
            .qoe_timestamp => n.qoe += 1,
        }
    }

    pub fn of(evs: []const fastpath.InputEvent) InputCounts {
        var n: InputCounts = .{};
        for (evs) |ev| n.add(ev);
        return n;
    }
};

/// Something the client did that makes even a clean end worth a dump.
pub const Anomaly = union(enum) {
    error_pdu: u8,
    /// Disconnect Provider Ultimatum reason other than rn-user-requested.
    ultimatum: u3,
};

var live_requests = std.atomic.Value(u32).init(0);

fn onSigusr1(_: std.posix.SIG) callconv(.c) void {
    _ = live_requests.fetchAdd(1, .monotonic);
}

/// SIGUSR1 asks every live connection for a `-live` dump.
pub fn installSignalHandler() void {
    const posix = std.posix;
    const act: posix.Sigaction = .{
        .handler = .{ .handler = onSigusr1 },
        .mask = posix.sigemptyset(),
        .flags = posix.SA.RESTART,
    };
    posix.sigaction(.USR1, &act, null);
}

/// SIGUSR1 stays blocked except around accept(), so connection threads' poll() is not cut short.
pub fn blockSignal(block: bool) void {
    const posix = std.posix;
    var set = posix.sigemptyset();
    posix.sigaddset(&set, .USR1);
    posix.sigprocmask(if (block) posix.SIG.BLOCK else posix.SIG.UNBLOCK, &set, null);
}

threadlocal var serving_rec: ?*Recorder = null;
threadlocal var serving_peer: []const u8 = "";
threadlocal var panicked: bool = false;
threadlocal var panic_msg: []const u8 = "";

pub fn serving(rec: ?*Recorder, peer: []const u8) void {
    serving_rec = rec;
    serving_peer = peer;
}

/// Dumps the serving connection's ring to a `-panic` file before the default handler; once only.
pub fn onPanic(msg: []const u8) void {
    if (panicked) return;
    panicked = true;
    const r = serving_rec orelse return;
    panic_msg = msg;
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = r.dump(serving_peer, .panic, null, &buf) orelse return;
    var line: [std.fs.max_path_bytes + 128]u8 = undefined;
    const text = std.fmt.bufPrint(&line, "{s}: flight record of the connection that panicked: {s}\n", .{ serving_peer, path }) catch return;
    _ = c.write(2, text.ptr, text.len);
}

/// One connection's ring. Records nothing until `start`.
pub const Recorder = struct {
    events: []Event = &.{},
    /// Events recorded so far; the newest is events[(n - 1) % len].
    n: u64 = 0,
    start_ns: u64 = 0,
    start_wall_ms: i64 = 0,
    /// null: no dumps.
    cfg: ?*const Config = null,
    live_seen: u32 = 0,
    /// Past MCS Connect Initial: failures are worth a dump, a port scan's are not.
    session: bool = false,
    errinfo: ?u32 = null,
    dpu: ?struct { dir: Dir, reason: u3 } = null,
    anomaly: ?Anomaly = null,
    live_dumps: u32 = 0,

    /// `capacity` must be a power of two. The recorder's only allocation.
    pub fn start(r: *Recorder, gpa: std.mem.Allocator, capacity: u32, cfg: ?*const Config) std.mem.Allocator.Error!void {
        std.debug.assert(std.math.isPowerOfTwo(capacity) and !r.on());
        r.events = try gpa.alloc(Event, capacity);
        r.n = 0;
        r.cfg = cfg;
        r.start_ns = nowNs();
        r.start_wall_ms = wallMs();
        r.live_seen = live_requests.load(.monotonic);
        r.note(.start, &.{});
    }

    pub fn deinit(r: *Recorder, gpa: std.mem.Allocator) void {
        gpa.free(r.events);
        r.events = &.{};
    }

    pub inline fn on(r: *const Recorder) bool {
        return r.events.len != 0;
    }

    pub fn count(r: *const Recorder) usize {
        return @intCast(@min(r.n, r.events.len));
    }

    /// 0 is the oldest.
    pub fn get(r: *const Recorder, i: usize) *const Event {
        std.debug.assert(i < r.count());
        const first = r.n - r.count();
        return &r.events[@intCast((first + i) & (r.events.len - 1))];
    }

    fn add(r: *Recorder, ns: u64, where: Where, dir: Dir, code: u32, size: usize) *Event {
        const e = &r.events[@intCast(r.n & (r.events.len - 1))];
        r.n += 1;
        e.* = .{ .ns = ns, .size = sat32(size), .code = @truncate(code), .where = where, .dir = dir, .f = @splat(0) };
        return e;
    }

    pub fn note(r: *Recorder, m: Milestone, fields: []const u32) void {
        if (!r.on()) return;
        const e = r.add(nowNs(), .conn, .none, @backingInt(m), 0);
        @memcpy(e.f[0..fields.len], fields);
        if (m == .mcs_connect) r.session = true;
    }

    /// One whole channel message (outgoing RDPGFX: gfxOut); unknown protocols record the channel `id`.
    pub fn channel(r: *Recorder, where: Where, dir: Dir, id: u32, msg: []const u8) void {
        if (!r.on()) return;
        const e = r.add(nowNs(), where, dir, 0, msg.len);
        switch (where) {
            .rdpsnd, .rdpsnd_dvc => rdpsnd(e, msg),
            .audin => audin(e, msg),
            .cliprdr => cliprdr(e, msg),
            .rdpdr => rdpdr(e, msg),
            .rail => rail(e, msg),
            .rdpei => rdpei(e, msg),
            .disp => displayControl(e, msg),
            .rdpgfx => gfxPdu(e, msg),
            else => e.f[0] = id,
        }
    }

    /// One event per RDPGFX PDU of an outgoing message, before ZGFX. Returns how many.
    pub fn gfxOut(r: *Recorder, msg: []const u8) u32 {
        if (!r.on()) return 0;
        const ns = nowNs();
        var off: usize = 0;
        var n: u32 = 0;
        while (msg.len - off >= 8) : (n += 1) {
            const len = rd32(msg, off + 4);
            if (len < 8 or len > msg.len - off) {
                r.add(ns, .rdpgfx, .out, gfx_malformed, msg.len - off).f[0] = rd16(msg, off);
                return n + 1;
            }
            const e = r.add(ns, .rdpgfx, .out, rd16(msg, off), len);
            gfxPdu(e, msg[off..][0..len]);
            off += len;
        }
        return n;
    }

    /// `wire`: bytes of RDP_SEGMENTED_DATA (ZGFX-compressed once negotiated).
    pub fn gfxWire(r: *Recorder, raw: usize, wire: usize, pdus: u32) void {
        if (!r.on()) return;
        const e = r.add(nowNs(), .rdpgfx, .out, gfx_message, raw);
        e.f[0] = pdus;
        e.f[1] = sat32(wire);
    }

    /// Before fragmentation and bulk compression; each surface command is its own event.
    pub fn fastPathOut(r: *Recorder, code: fastpath.UpdateCode, data: []const u8, compressed: bool) void {
        if (!r.on()) return;
        const ns = nowNs();
        if (code == .surfcmds) return surfaceCommands(r, ns, data, compressed);
        const e = r.add(ns, .fastpath, .out, @backingInt(code), data.len);
        e.f[7] = @intFromBool(compressed);
        switch (code) {
            .orders => e.f[0] = rd16(data, 0),
            .bitmap => {
                e.f[0] = rd16(data, 2); // numberRectangles
                e.f[1] = rd16(data, 4) | rd16(data, 6) << 16; // the first one
                e.f[2] = rd16(data, 8) | rd16(data, 10) << 16;
                e.f[3] = rd16(data, 16); // bitsPerPixel
            },
            else => {},
        }
    }

    fn surfaceCommands(r: *Recorder, ns: u64, data: []const u8, compressed: bool) void {
        var off: usize = 0;
        while (data.len - off >= 2) {
            const cmd = data[off..];
            const t = rd16(cmd, 0);
            const len: usize = switch (t) {
                cmdtype_frame_marker => 8,
                cmdtype_set_surface_bits, cmdtype_stream_surface_bits => @as(usize, 22) + rd32(cmd, 18) + @as(usize, if (rd8(cmd, 11) & 0x01 != 0) 24 else 0),
                else => cmd.len,
            };
            const e = r.add(ns, .fastpath, .out, surfcmd_base | t, @min(len, cmd.len));
            e.f[7] = @intFromBool(compressed);
            switch (t) {
                cmdtype_frame_marker => {
                    e.f[0] = rd16(cmd, 2); // frameAction
                    e.f[1] = rd32(cmd, 4); // frameId
                },
                cmdtype_set_surface_bits, cmdtype_stream_surface_bits => {
                    e.f[0] = rd16(cmd, 2) | rd16(cmd, 4) << 16;
                    e.f[1] = rd16(cmd, 6) | rd16(cmd, 8) << 16;
                    e.f[2] = rd8(cmd, 10); // bpp
                    e.f[3] = rd8(cmd, 13); // codecID
                    e.f[4] = rd16(cmd, 14) | rd16(cmd, 16) << 16;
                    e.f[5] = rd32(cmd, 18); // bitmapDataLength
                },
                else => return,
            }
            if (len > cmd.len) return;
            off += len;
        }
    }

    pub fn input(r: *Recorder, where: Where, size: usize, n: InputCounts) void {
        if (!r.on()) return;
        const e = r.add(nowNs(), where, .in, if (where == .slowpath) slow_input else 0, size);
        e.f[0..7].* = .{ n.keyboard, n.unicode, n.mouse, n.mousex, n.relative, n.sync, n.qoe };
    }

    /// A Share Control PDU (MS-RDPBCGR 2.2.8.1.1.1) or licensing PDU; received input goes to `input`.
    pub fn slowPath(r: *Recorder, dir: Dir, pdu: []const u8) void {
        if (!r.on()) return;
        const total = rd16(pdu, 0);
        if (total == 0x8000) {
            r.add(nowNs(), .slowpath, dir, slow_flow, pdu.len).f[0] = rd8(pdu, 2);
            return;
        }
        if (total < 6 or total > pdu.len) {
            r.add(nowNs(), .slowpath, dir, slow_security, pdu.len).f[0] = total;
            return;
        }
        const ptype = rd16(pdu, 2) & 0x0F;
        if (ptype != share_data) {
            const e = r.add(nowNs(), .slowpath, dir, slow_control | ptype, pdu.len);
            switch (ptype) {
                1 => e.f[0] = rd16(pdu, 14 + @as(usize, rd16(pdu, 10))),
                3 => e.f[0] = rd16(pdu, 16 + @as(usize, rd16(pdu, 12))),
                else => {},
            }
            return;
        }
        const t2 = rd8(pdu, 14);
        if (dir == .in and t2 == pdutype2_input) return;
        const e = r.add(nowNs(), .slowpath, dir, t2, pdu.len);
        const ctype = rd8(pdu, 15);
        e.f[7] = ctype;
        switch (t2) {
            44, 46, 48, 49 => if (dir == .in and r.anomaly == null) {
                r.anomaly = .{ .error_pdu = @intCast(t2) };
            },
            else => {},
        }
        // A compressed body (PACKET_COMPRESSED) is not read.
        if (ctype & 0x20 != 0) return;
        switch (t2) {
            2 => { // Update: updateType, then the count
                e.f[0] = rd16(pdu, 18);
                e.f[1] = switch (rd16(pdu, 18)) {
                    0 => rd16(pdu, 22), // numberOrders
                    1 => rd16(pdu, 20), // numberRectangles
                    else => 0,
                };
            },
            20, 27 => e.f[0] = rd16(pdu, 18), // action, messageType
            38, 54, 55, 56 => e.f[0] = rd32(pdu, 18), // infoType, statusCode, monitorCount, frameID
            33, 35 => e.f[0] = rd8(pdu, 18), // numberOfAreas, allowDisplayUpdates
            34 => {
                e.f[0] = rd32(pdu, 18); // duration
                e.f[1] = rd32(pdu, 22); // frequency
            },
            47 => {
                e.f[0] = rd32(pdu, 18);
                if (dir == .out) r.errinfo = e.f[0];
            },
            else => {},
        }
    }

    pub fn messageChannel(r: *Recorder, dir: Dir, pdu: []const u8) void {
        if (!r.on()) return;
        const flags = rd16(pdu, 0);
        const kind: u32 = for ([_]u32{ sec_autodetect_req, sec_autodetect_rsp, sec_heartbeat, sec_transport_req, sec_transport_rsp }) |k| {
            if (flags & k != 0) break k;
        } else flags;
        const e = r.add(nowNs(), .msgchannel, dir, kind, pdu.len);
        switch (kind) {
            sec_autodetect_req, sec_autodetect_rsp => {
                e.f[0] = rd16(pdu, 8); // requestType / responseType
                e.f[1] = rd16(pdu, 6); // sequenceNumber
            },
            sec_heartbeat => e.f[0..3].* = .{ rd8(pdu, 5), rd8(pdu, 6), rd8(pdu, 7) },
            sec_transport_req, sec_transport_rsp => {
                e.f[0] = rd32(pdu, 4); // requestId
                e.f[1] = if (kind == sec_transport_req) rd16(pdu, 8) else rd32(pdu, 8);
            },
            else => {},
        }
    }

    /// A DRDYNVC control PDU (MS-RDPEDYC 2.2) for channel `chan`; data PDUs go to `channel`.
    pub fn dvc(r: *Recorder, dir: Dir, pdu: []const u8, chan: Where) void {
        if (!r.on()) return;
        const cmd = rd8(pdu, 0) >> 4;
        const e = r.add(nowNs(), .drdynvc, dir, cmd, pdu.len);
        const id_len: usize = switch (rd8(pdu, 0) & 0x03) {
            0 => 1,
            1 => 2,
            else => 4,
        };
        const id = switch (id_len) {
            1 => rd8(pdu, 1),
            2 => rd16(pdu, 1),
            else => rd32(pdu, 1),
        };
        switch (cmd) {
            dvc_caps => e.f[0] = rd16(pdu, 2),
            dvc_create, dvc_close => {
                e.f[0] = id;
                e.f[1] = @backingInt(chan);
                if (cmd == dvc_create and dir == .in) e.f[2] = rd32(pdu, 1 + id_len); // CreationStatus
            },
            dvc_soft_sync_request => e.f[0..2].* = .{ rd16(pdu, 6), rd16(pdu, 8) },
            dvc_soft_sync_response => e.f[0] = rd32(pdu, 2),
            else => {},
        }
    }

    pub fn ultimatum(r: *Recorder, dir: Dir, reason: u3) void {
        if (!r.on()) return;
        r.add(nowNs(), .mcs, dir, 0, 0).f[0] = reason;
        r.dpu = .{ .dir = dir, .reason = reason };
        // MS-RDPBCGR 3.1.5.1.1: a user's disconnect is rn-user-requested.
        if (dir == .in and reason != reason_user_requested and r.anomaly == null) r.anomaly = .{ .ultimatum = reason };
    }

    pub fn end(r: *Recorder, err: ?anyerror) void {
        if (!r.on()) return;
        const e = r.add(nowNs(), .conn, .none, @backingInt(Milestone.end), 0);
        e.f[0] = if (err) |x| @intFromError(x) else 0;
        if (r.errinfo) |code| e.f[1..3].* = .{ 1, code };
        if (r.dpu) |d| e.f[3..5].* = .{ @backingInt(d.dir), d.reason };
    }

    pub fn failed(r: *Recorder, where: Where, size: usize, err: anyerror) void {
        if (!r.on()) return;
        const e = r.add(nowNs(), .conn, .in, @backingInt(Milestone.failed), size);
        e.f[0..2].* = .{ @intFromError(err), @backingInt(where) };
    }

    pub fn liveRequested(r: *Recorder) bool {
        if (!r.on()) return false;
        const g = live_requests.load(.monotonic);
        if (g == r.live_seen) return false;
        r.live_seen = g;
        return true;
    }

    pub fn worthDumping(r: *const Recorder, err: ?anyerror, clean_close: bool) bool {
        const cfg = r.cfg orelse return false;
        if (!r.on() or cfg.mode == .off) return false;
        if (cfg.mode == .always) return true;
        if (r.anomaly != null) return true;
        const e = err orelse return false;
        // Port scans and failed logons end before there is a session.
        if (!r.session) return false;
        return !(e == error.ConnectionClosed and clean_close);
    }

    pub const Kind = enum { end, live, panic };

    /// Writes the ring to a new file and rotates old files; errors are logged. Returns the path or null.
    pub fn dump(r: *Recorder, peer: []const u8, kind: Kind, err: ?anyerror, path_buf: []u8) ?[]const u8 {
        const cfg = r.cfg orelse return null;
        if (!r.on() or r.count() == 0) return null;
        if (kind == .live) {
            r.live_dumps += 1;
            r.note(.live_dump, &.{r.live_dumps});
        }
        const path = r.writeFile(cfg, peer, kind, err, path_buf) catch |e| {
            if (kind != .panic) log.warn("{s}: could not write the flight record to {s}: {t}", .{ peer, cfg.dir, e });
            return null;
        };
        rotate(cfg.dir, cfg.keep);
        // No logging on panic: the panic may hold stderr's lock.
        if (kind == .panic) return path;
        const span = r.get(r.count() - 1).ns -| r.get(0).ns;
        log.warn("{s}: flight record of the last {d}.{d:0>3} s: {s}", .{ peer, span / std.time.ns_per_s, span % std.time.ns_per_s / std.time.ns_per_ms, path });
        const k = @min(journal_events, r.count());
        for (r.count() - k..r.count()) |i| {
            var buf: [512]u8 = undefined;
            var w = std.Io.Writer.fixed(&buf);
            formatEvent(&w, r.get(i), r.start_ns) catch {};
            log.warn("{s}:   {s}", .{ peer, w.buffered() });
        }
        return path;
    }

    fn writeFile(r: *const Recorder, cfg: *const Config, peer: []const u8, kind: Kind, err: ?anyerror, path_buf: []u8) ![]const u8 {
        try ensureDir(cfg.dir);
        const wall = wallMs();
        var peer_buf: [64]u8 = undefined;
        const p = sanitize(&peer_buf, peer);
        const suffix: []const u8 = switch (kind) {
            .end => "",
            .live => "-live",
            .panic => "-panic",
        };
        var path: [:0]const u8 = undefined;
        const fd = for (0..1000) |_| {
            var stamp_buf: [32]u8 = undefined;
            const stamp = try fileStamp(&stamp_buf, nextStamp(wall));
            path = try std.mem.printSentinel(path_buf, "{s}/{s}-{s}{s}.log", .{ cfg.dir, stamp, p, suffix }, 0);
            const fd = c.open(path.ptr, c.O_WRONLY | c.O_CREAT | c.O_EXCL | c.O_CLOEXEC | c.O_NOFOLLOW, @as(c_uint, 0o600));
            if (fd >= 0) break fd;
            if (c.__errno_location().* != c.EEXIST) return error.CreateFailed;
        } else return error.CreateFailed;
        defer _ = c.close(fd);
        var out: FileOut = .{ .fd = fd };
        try r.writeHeader(&out, peer, kind, err, wall);
        for (0..r.count()) |i| {
            var buf: [512]u8 = undefined;
            var w = std.Io.Writer.fixed(&buf);
            formatEvent(&w, r.get(i), r.start_ns) catch {};
            out.line(w.buffered());
        }
        out.flush();
        if (out.failed) return error.WriteFailed;
        return path;
    }

    fn writeHeader(r: *const Recorder, out: *FileOut, peer: []const u8, kind: Kind, err: ?anyerror, wall: i64) !void {
        var buf: [1024]u8 = undefined;
        var t0: [32]u8 = undefined;
        var t1: [32]u8 = undefined;
        const n = r.count();
        const span = r.get(n - 1).ns -| r.get(0).ns;
        const now_rel = nowNs() -| r.start_ns;
        out.line(try std.fmt.bufPrint(&buf, "# omastation flight record of {s} ({s})", .{ peer, switch (kind) {
            .end => "the connection ended",
            .live => "live dump on SIGUSR1; the session goes on",
            .panic => "the server panicked",
        } }));
        if (kind == .panic) out.line(try std.fmt.bufPrint(&buf, "# panic: {s}", .{panic_msg}));
        out.line(try std.fmt.bufPrint(&buf, "# connection from {s} UTC, written {s} UTC, {d}.{d:0>3} s later", .{
            try humanStamp(&t0, r.start_wall_ms), try humanStamp(&t1, wall), now_rel / std.time.ns_per_s, now_rel % std.time.ns_per_s / std.time.ns_per_ms,
        }));
        if (kind == .end) {
            if (err) |e| {
                out.line(try std.fmt.bufPrint(&buf, "# ended with {t}{s}", .{ e, errorHint(e) }));
            } else {
                out.line("# ended cleanly");
            }
        }
        var a: [64]u8 = undefined;
        var u: [64]u8 = undefined;
        out.line(try std.fmt.bufPrint(&buf, "# Set Error Info sent: {s}; Disconnect Provider Ultimatum: {s}", .{
            if (r.errinfo) |code| try std.fmt.bufPrint(&a, "0x{x:0>8}", .{code}) else "none",
            if (r.dpu) |ult| try std.fmt.bufPrint(&u, "{s} the client ({s})", .{ if (ult.dir == .in) "from" else "to", reasonName(ult.reason) }) else "none",
        }));
        if (r.anomaly) |an| out.line(switch (an) {
            .error_pdu => |t2| try std.fmt.bufPrint(&buf, "# the client sent a {s} PDU", .{pduType2Name(t2) orelse "error"}),
            .ultimatum => |reason| try std.fmt.bufPrint(&buf, "# the client disconnected with reason {s}, not user-requested", .{reasonName(reason)}),
        });
        out.line(try std.fmt.bufPrint(&buf, "# {d} events of {d}{s}, the last {d}.{d:0>3} s", .{
            n, r.n, if (r.n > n) " (the older ones were overwritten)" else "", span / std.time.ns_per_s, span % std.time.ns_per_s / std.time.ns_per_ms,
        }));
        out.line("# seconds since the connection began, direction, where (fast-path, slow-path, msgchannel,");
        out.line("# static channels by name; dynamic: rdpgfx, disp, rdpsnd-dvc, audin, rdpei, echo), bytes, event");
        out.line("# metadata only: no keystrokes, characters, clipboard data, file names, pixels or samples");
    }
};

/// RDPGFX pseudo-codes: a whole message, and a malformed remainder.
pub const gfx_message: u16 = 0xF000;
pub const gfx_malformed: u16 = 0xF001;
/// Fast-path surface commands are `surfcmd_base | cmdType`.
pub const surfcmd_base: u16 = 0x100;
/// Slow-path codes besides pduType2: Share Control (`slow_control | pduType`), flow, licensing, input.
pub const slow_control: u16 = 0x100;
pub const slow_flow: u16 = 0x200;
pub const slow_security: u16 = 0x300;
pub const slow_input: u16 = 0x400;

const share_data: u32 = 7;
const pdutype2_input: u32 = 28;
const cmdtype_set_surface_bits: u32 = 0x0001;
const cmdtype_frame_marker: u32 = 0x0004;
const cmdtype_stream_surface_bits: u32 = 0x0006;
const sec_transport_req: u32 = 0x0002;
const sec_transport_rsp: u32 = 0x0004;
const sec_autodetect_req: u32 = 0x1000;
const sec_autodetect_rsp: u32 = 0x2000;
const sec_heartbeat: u32 = 0x4000;
const dvc_create: u32 = 1;
const dvc_close: u32 = 4;
const dvc_caps: u32 = 5;
const dvc_soft_sync_request: u32 = 8;
const dvc_soft_sync_response: u32 = 9;
const reason_user_requested: u3 = 3;

fn rd8(m: []const u8, off: usize) u32 {
    return if (off < m.len) m[off] else 0;
}

fn rd16(m: []const u8, off: usize) u32 {
    return if (m.len >= 2 and off <= m.len - 2) std.mem.readInt(u16, m[off..][0..2], .little) else 0;
}

fn rd32(m: []const u8, off: usize) u32 {
    return if (m.len >= 4 and off <= m.len - 4) std.mem.readInt(u32, m[off..][0..4], .little) else 0;
}

fn sat32(v: usize) u32 {
    return @intCast(@min(v, std.math.maxInt(u32)));
}

fn gfxPdu(e: *Event, p: []const u8) void {
    const cmd = rd16(p, 0);
    e.code = @intCast(cmd);
    switch (cmd) {
        0x01 => { // WireToSurface1
            e.f[0] = rd16(p, 8) | rd8(p, 12) << 16; // surfaceId, pixelFormat
            const codec = rd16(p, 10);
            e.f[1] = codec;
            e.f[2] = rd16(p, 13) | rd16(p, 15) << 16; // destRect
            e.f[3] = rd16(p, 17) | rd16(p, 19) << 16;
            const len = rd32(p, 21);
            e.f[4] = len;
            const b = if (p.len > 25) p[25..] else p[p.len..];
            switch (codec) {
                0x0B => { // AVC420: RFX_AVC420_METABLOCK, then the H.264 stream
                    const n = rd32(b, 0);
                    e.f[5] = n;
                    const meta = 4 + @as(u64, n) * 10;
                    e.f[6] = if (meta <= len) @intCast(len - meta) else 0;
                },
                0x0E, 0x0F => { // AVC444(v2): LC, the first stream's regions and size
                    const info = rd32(b, 0);
                    e.f[5] = info >> 30;
                    e.f[6] = rd32(b, 4);
                    e.f[7] = info & 0x3FFF_FFFF;
                },
                0x08 => e.f[5..7].* = .{ rd8(b, 0), rd8(b, 1) }, // ClearCodec glyphFlags, seqNumber
                0x0A => e.f[5] = rd8(b, 0), // planar FormatHeader
                0x0C => e.f[5] = rd16(b, 2), // alpha: compressed
                else => {},
            }
        },
        0x02 => { // WireToSurface2
            e.f[0] = rd16(p, 8) | rd8(p, 16) << 16;
            e.f[1] = rd16(p, 10);
            e.f[2] = rd32(p, 12); // codecContextId
            e.f[4] = rd32(p, 17);
        },
        0x03 => e.f[0..3].* = .{ rd16(p, 8), 0, rd32(p, 10) }, // DeleteEncodingContext
        0x04 => e.f[0..6].* = .{ rd16(p, 8), 0, 0, 0, 0, rd16(p, 14) }, // SolidFill: no colour
        0x05 => e.f[0..6].* = .{ rd16(p, 8), rd16(p, 10), rd16(p, 12) | rd16(p, 14) << 16, rd16(p, 16) | rd16(p, 18) << 16, 0, rd16(p, 20) },
        0x06 => e.f[0..6].* = .{ rd16(p, 8), 0, rd16(p, 20) | rd16(p, 22) << 16, rd16(p, 24) | rd16(p, 26) << 16, 0, rd16(p, 18) },
        0x07 => e.f[0..7].* = .{ rd16(p, 10), 0, 0, 0, 0, rd16(p, 8), rd16(p, 12) },
        0x08 => e.f[5] = rd16(p, 8), // EvictCacheEntry
        0x09 => e.f[0..4].* = .{ rd16(p, 8) | rd8(p, 14) << 16, 0, rd16(p, 10), rd16(p, 12) }, // CreateSurface
        0x0A => e.f[0] = rd16(p, 8), // DeleteSurface
        0x0B => e.f[0..2].* = .{ rd32(p, 12), rd32(p, 8) }, // StartFrame: frameId, timestamp
        0x0C => e.f[0] = rd32(p, 8), // EndFrame
        0x0D => e.f[0..3].* = .{ rd32(p, 12), rd32(p, 8), rd32(p, 16) }, // FrameAcknowledge: frameId, queueDepth, decoded
        0x0E => e.f[0..3].* = .{ rd32(p, 8), rd32(p, 12), rd32(p, 16) }, // ResetGraphics
        0x0F => e.f[0..3].* = .{ rd16(p, 8), rd32(p, 12), rd32(p, 16) }, // MapSurfaceToOutput
        0x10, 0x11 => e.f[0] = rd16(p, 8), // CacheImportOffer / Reply: entries
        0x12 => { // CapsAdvertise: the versions offered (up to 7)
            const n = rd16(p, 8);
            e.f[0] = n;
            var off: usize = 10;
            for (0..@min(n, 7)) |i| {
                e.f[1 + i] = rd32(p, off);
                off += 8 + @as(usize, rd32(p, off + 4));
            }
        },
        0x13 => e.f[0..2].* = .{ rd32(p, 8), rd32(p, 16) }, // CapsConfirm: version, flags
        0x15 => e.f[0..4].* = .{ rd16(p, 8), rd32(p, 10), rd32(p, 18), rd32(p, 22) }, // MapSurfaceToWindow
        0x16 => e.f[0..4].* = .{ rd32(p, 8), rd32(p, 12), rd16(p, 16), rd16(p, 18) }, // QoE Frame Acknowledge
        0x17 => e.f[0..5].* = .{ rd16(p, 8), rd32(p, 12), rd32(p, 16), rd32(p, 20), rd32(p, 24) },
        0x18 => e.f[0..6].* = .{ rd16(p, 8), rd32(p, 10), rd32(p, 18), rd32(p, 22), rd32(p, 26), rd32(p, 30) },
        else => {},
    }
}

/// MS-RDPEA. A Wave PDU starts with 4 padding bytes, so it records as type 0.
fn rdpsnd(e: *Event, m: []const u8) void {
    const t = rd8(m, 0);
    e.code = @intCast(t);
    switch (t) {
        0x02 => e.f[0..3].* = .{ rd16(m, 4), rd16(m, 6), rd8(m, 8) }, // WaveInfo: wTimeStamp, wFormatNo, cBlockNo
        0x0D => e.f[0..4].* = .{ rd16(m, 4), rd16(m, 6), rd8(m, 8), rd32(m, 12) }, // Wave2: + dwAudioTimeStamp
        0x05 => e.f[0..2].* = .{ rd16(m, 4), rd8(m, 6) }, // WaveConfirm: wTimeStamp, cConfirmedBlockNo
        0x06 => e.f[0..2].* = .{ rd16(m, 4), rd16(m, 6) }, // Training (Confirm): wTimeStamp, wPackSize
        0x07 => e.f[0..3].* = .{ rd16(m, 18), rd16(m, 21), rd32(m, 4) }, // Formats: count, wVersion, dwFlags
        0x03 => e.f[0] = rd32(m, 4), // SetVolume
        0x0C => e.f[0] = rd16(m, 4), // QualityMode
        else => {},
    }
}

fn audin(e: *Event, m: []const u8) void {
    const t = rd8(m, 0);
    e.code = @intCast(t);
    switch (t) {
        0x01, 0x04, 0x07 => e.f[0] = rd32(m, 1), // Version, OpenReply Result, FormatChange NewFormat
        0x02 => e.f[0] = rd32(m, 1), // Formats: NumFormats
        0x03 => e.f[0..5].* = .{ rd32(m, 1), rd32(m, 5), rd16(m, 9), rd16(m, 11), rd32(m, 13) }, // Open
        else => {},
    }
}

/// MS-RDPECLIP CLIPRDR_HEADER only; format names and data are never read.
fn cliprdr(e: *Event, m: []const u8) void {
    e.code = @intCast(rd16(m, 0));
    e.f[0..2].* = .{ rd16(m, 2), rd32(m, 4) };
}

/// MS-RDPEFS RDPDR_HEADER and I/O ids; never paths or file data.
fn rdpdr(e: *Event, m: []const u8) void {
    const id = rd16(m, 2);
    e.code = @intCast(id);
    e.f[0] = rd16(m, 0);
    switch (id) {
        0x4952 => { // Device I/O Request: DeviceId, FileId, CompletionId, Major, Minor
            e.f[1..6].* = .{ rd32(m, 4), rd32(m, 8), rd32(m, 12), rd32(m, 16), rd32(m, 20) };
            const major = rd32(m, 16);
            if (major == 3 or major == 4) e.f[6] = rd32(m, 24); // Read / Write Length
        },
        0x4943 => e.f[1..4].* = .{ rd32(m, 4), rd32(m, 8), rd32(m, 12) }, // Completion: DeviceId, CompletionId, IoStatus
        0x4441, 0x444D => e.f[1] = rd32(m, 4), // device list announce / remove: DeviceCount
        0x6472 => e.f[1..3].* = .{ rd32(m, 4), rd32(m, 8) }, // device reply: DeviceId, ResultCode
        0x496E, 0x4343 => e.f[1..3].* = .{ rd16(m, 4), rd16(m, 6) }, // VersionMajor, VersionMinor
        0x5350, 0x4350 => e.f[1] = rd16(m, 4), // numCapabilities
        else => {},
    }
}

fn rail(e: *Event, m: []const u8) void {
    e.code = @intCast(rd16(m, 0));
    e.f[0] = rd16(m, 2);
}

fn rdpei(e: *Event, m: []const u8) void {
    const t = rd16(m, 0);
    e.code = @intCast(t);
    e.f[0] = rd32(m, 2);
    switch (t) {
        0x01 => e.f[1] = rd32(m, 6), // SC_READY protocolVersion
        0x02 => e.f[1..4].* = .{ rd32(m, 6), rd32(m, 10), rd16(m, 14) }, // CS_READY flags, version, maxTouchContacts
        else => {},
    }
}

fn displayControl(e: *Event, m: []const u8) void {
    const t = rd32(m, 0);
    e.code = @truncate(t);
    switch (t) {
        0x05 => e.f[0..3].* = .{ rd32(m, 8), rd32(m, 12), rd32(m, 16) },
        0x02 => e.f[0] = rd32(m, 12),
        else => {},
    }
}

/// One line, no newline: seconds since `base_ns`, direction, where, bytes, description.
pub fn formatEvent(w: *std.Io.Writer, e: *const Event, base_ns: u64) std.Io.Writer.Error!void {
    const rel = e.ns -| base_ns;
    try w.print("{d:>5}.{d:0>6} {s:<3} {s:<10} ", .{ rel / std.time.ns_per_s, rel % std.time.ns_per_s / std.time.ns_per_us, switch (e.dir) {
        .none => "--",
        .in => "in",
        .out => "out",
    }, e.where.label() });
    if (e.where == .conn and e.size == 0) try w.writeAll("      -  ") else try w.print("{d:>7}  ", .{e.size});
    try describe(w, e);
}

pub fn describe(w: *std.Io.Writer, e: *const Event) std.Io.Writer.Error!void {
    const f = e.f;
    switch (e.where) {
        .conn => try describeMilestone(w, e),
        .mcs => try w.print("Disconnect Provider Ultimatum ({s})", .{reasonName(@truncate(f[0]))}),
        .fastpath => if (e.dir == .in) try describeInput(w, f) else try describeFastPath(w, e),
        .slowpath => try describeSlowPath(w, e),
        .msgchannel => try describeMessage(w, e),
        .drdynvc => try describeDvc(w, e),
        .rdpsnd, .rdpsnd_dvc => try describeRdpsnd(w, e),
        .audin => try describeAudin(w, e),
        .cliprdr => {
            try named(w, cliprdrName(e.code), e.code);
            try w.print(" flags=0x{x} dataLen={d}", .{ f[0], f[1] });
        },
        .rdpdr => try describeRdpdr(w, e),
        .rail => {
            try named(w, railName(e.code), e.code);
            try w.print(" orderLength={d}", .{f[0]});
        },
        .rdpei => {
            try named(w, rdpeiName(e.code), e.code);
            try w.print(" pduLength={d}", .{f[0]});
            switch (e.code) {
                0x01 => try w.print(" version=0x{x}", .{f[1]}),
                0x02 => try w.print(" flags=0x{x} version=0x{x} maxTouchContacts={d}", .{ f[1], f[2], f[3] }),
                else => {},
            }
        },
        .disp => switch (e.code) {
            0x05 => try w.print("Caps maxMonitors={d} areaFactor={d}x{d}", .{ f[0], f[1], f[2] }),
            0x02 => try w.print("Monitor Layout monitors={d}", .{f[0]}),
            else => try w.print("type 0x{x}", .{e.code}),
        },
        .echo => try w.writeAll(if (e.dir == .out) "Echo Request" else "Echo Response"),
        .rdpgfx => try describeGfx(w, e),
        .static, .dvc => try w.print("channel {d}", .{f[0]}),
    }
}

fn named(w: *std.Io.Writer, name: ?[]const u8, code: u16) !void {
    if (name) |n| try w.writeAll(n) else try w.print("type 0x{x}", .{code});
}

fn rect(w: *std.Io.Writer, tl: u32, br: u32) !void {
    try w.print("{d},{d}-{d},{d}", .{ tl & 0xFFFF, tl >> 16, br & 0xFFFF, br >> 16 });
}

fn describeMilestone(w: *std.Io.Writer, e: *const Event) !void {
    const f = e.f;
    switch (@as(Milestone, @fromBackingInt(e.code))) {
        .start => try w.writeAll("recording started"),
        .x224 => try w.print("X.224 Connection Request: protocols 0x{x}, selected 0x{x}", .{ f[0], f[1] }),
        .nla => try w.writeAll("NLA: user authenticated"),
        .mcs_connect => try w.print("MCS Connect Initial: client build {d}, desktop {d}x{d}, {d} monitor(s), {d} static channel(s), early caps 0x{x}", .{ f[0], f[1], f[2], f[3], f[4], f[5] }),
        .client_info => try w.print("Client Info: flags 0x{x}, performance flags 0x{x}", .{ f[0], f[1] }),
        .established => try w.writeAll("connection established"),
        .live_dump => try w.print("live dump {d} (SIGUSR1)", .{f[0]}),
        .end => {
            if (f[0] == 0) try w.writeAll("connection ended cleanly") else try w.print("connection ended: {t}", .{errorOf(f[0])});
            if (f[1] != 0) try w.print("; Set Error Info 0x{x:0>8}", .{f[2]});
            if (f[3] != 0) try w.print("; Disconnect Provider Ultimatum {s} the client ({s})", .{ if (f[3] == @backingInt(Dir.in)) "from" else "to", reasonName(@truncate(f[4])) });
        },
        .failed => try w.print("handling this {s} PDU failed: {t}", .{ if (f[1] == @backingInt(Where.fastpath)) "fast-path" else "X.224", errorOf(f[0]) }),
        .backlog => if (f[3] != 0)
            try w.print("send queue over its cap: {d} bytes waiting (cap {d}): the client does not keep up", .{ f[0], f[1] })
        else
            try w.print("output: up to {d} bytes waiting for the wire (window {d}, link {d} kB/s), {d} frames held for the network, longest loop pass {d} ms", .{ f[0], f[1], f[2], f[4], f[5] }),
        _ => try w.print("milestone {d}", .{e.code}),
    }
}

fn describeInput(w: *std.Io.Writer, f: [8]u32) !void {
    const names = [_][]const u8{ "keyboard", "unicode", "mouse", "mouse-x", "relative mouse", "sync", "QoE timestamp" };
    try w.writeAll("input:");
    var any = false;
    for (names, 0..) |n, i| {
        if (f[i] == 0) continue;
        try w.print("{s} {d} {s}", .{ if (any) "," else "", f[i], n });
        any = true;
    }
    if (!any) try w.writeAll(" no events");
}

fn describeFastPath(w: *std.Io.Writer, e: *const Event) !void {
    const f = e.f;
    if (e.code & surfcmd_base != 0) {
        switch (e.code & 0xFF) {
            cmdtype_frame_marker => try w.print("Frame Marker {s} frame={d}", .{ if (f[0] == 0) "begin" else "end", f[1] }),
            cmdtype_set_surface_bits, cmdtype_stream_surface_bits => {
                try w.print("{s} codec-id={d} rect=", .{ if (e.code & 0xFF == cmdtype_set_surface_bits) "Set Surface Bits" else "Stream Surface Bits", f[3] });
                try rect(w, f[0], f[1]);
                try w.print(" {d}bpp {d}x{d} bitmap={d}", .{ f[2], f[4] & 0xFFFF, f[4] >> 16, f[5] });
            },
            else => try w.print("surface command 0x{x}", .{e.code & 0xFF}),
        }
    } else {
        switch (e.code) {
            0x0 => try w.print("Orders orders={d}", .{f[0]}),
            0x1 => {
                try w.print("Bitmap rects={d} first=", .{f[0]});
                try rect(w, f[1], f[2]);
                try w.print(" {d}bpp", .{f[3]});
            },
            0x2 => try w.writeAll("Palette"),
            0x3 => try w.writeAll("Synchronize"),
            0x5 => try w.writeAll("Pointer hidden"),
            0x6 => try w.writeAll("Pointer default"),
            0x8 => try w.writeAll("Pointer position"),
            0x9 => try w.writeAll("Color Pointer"),
            0xA => try w.writeAll("Cached Pointer"),
            0xB => try w.writeAll("New Pointer"),
            0xC => try w.writeAll("Large Pointer"),
            else => try w.print("update 0x{x}", .{e.code}),
        }
    }
    if (f[7] != 0) try w.writeAll(" (bulk-compressed)");
}

fn pduType2Name(t: u32) ?[]const u8 {
    return switch (t) {
        2 => "Update",
        20 => "Control",
        27 => "Pointer",
        28 => "Input",
        31 => "Synchronize",
        33 => "Refresh Rect",
        34 => "Play Sound",
        35 => "Suppress Output",
        36 => "Shutdown Request",
        37 => "Shutdown Request Denied",
        38 => "Save Session Info",
        39 => "Font List",
        40 => "Font Map",
        41 => "Set Keyboard Indicators",
        43 => "Persistent Key List",
        44 => "Bitmap Cache Error",
        45 => "Set Keyboard IME Status",
        46 => "Offscreen Bitmap Cache Error",
        47 => "Set Error Info",
        48 => "DrawNineGrid Cache Error",
        49 => "GDI+ Error",
        50 => "Auto-Reconnect Status",
        54 => "Status Info",
        55 => "Monitor Layout",
        56 => "Frame Acknowledge",
        else => null,
    };
}

fn describeSlowPath(w: *std.Io.Writer, e: *const Event) !void {
    const f = e.f;
    switch (e.code) {
        slow_flow => return w.print("Flow PDU type {d}", .{f[0]}),
        slow_security => return w.print("security header flags 0x{x} (licensing)", .{f[0]}),
        slow_input => return describeInput(w, f),
        slow_control | 1 => return w.print("Demand Active capabilities={d}", .{f[0]}),
        slow_control | 3 => return w.print("Confirm Active capabilities={d}", .{f[0]}),
        slow_control | 6 => return w.writeAll("Deactivate All"),
        slow_control | 10 => return w.writeAll("Server Redirection"),
        else => {},
    }
    if (e.code & slow_control != 0) return w.print("Share Control type {d}", .{e.code & 0xF});
    try w.writeAll(pduType2Name(e.code) orelse "Share Data");
    if (pduType2Name(e.code) == null) try w.print(" type {d}", .{e.code});
    if (f[7] & 0x20 != 0) return w.print(" (bulk-compressed 0x{x})", .{f[7]});
    switch (e.code) {
        2 => try w.print(" {s} count={d}", .{ switch (f[0]) {
            0 => "orders",
            1 => "bitmap",
            2 => "palette",
            3 => "synchronize",
            else => "?",
        }, f[1] }),
        20 => try w.print(" {s}", .{switch (f[0]) {
            1 => "request control",
            2 => "granted control",
            3 => "detach",
            4 => "cooperate",
            else => "?",
        }}),
        27 => try w.print(" messageType={d}", .{f[0]}),
        33 => try w.print(" areas={d}", .{f[0]}),
        34 => try w.print(" duration={d}ms frequency={d}Hz", .{ f[0], f[1] }),
        35 => try w.writeAll(if (f[0] != 0) " allow" else " suppress"),
        38 => try w.print(" infoType={d}", .{f[0]}),
        47 => try w.print(" 0x{x:0>8}", .{f[0]}),
        54 => try w.print(" status=0x{x}", .{f[0]}),
        55 => try w.print(" monitors={d}", .{f[0]}),
        56 => try w.print(" frame={d}", .{f[0]}),
        else => {},
    }
}

fn autodetectName(t: u32, rsp: bool) ?[]const u8 {
    if (rsp) return switch (t) {
        0x0000 => "RTT Response",
        0x0003 => "Bandwidth Results (connect-time)",
        0x000B => "Bandwidth Results (continuous)",
        0x0018 => "Network Characteristics Sync",
        else => null,
    };
    return switch (t) {
        0x0001 => "RTT Request (continuous)",
        0x1001 => "RTT Request (connect-time)",
        0x0014 => "Bandwidth Start (continuous)",
        0x0114 => "Bandwidth Start (lossy UDP)",
        0x1014 => "Bandwidth Start (connect-time)",
        0x0002 => "Bandwidth Payload",
        0x002B => "Bandwidth Stop (connect-time)",
        0x0429 => "Bandwidth Stop (continuous)",
        0x0629 => "Bandwidth Stop (lossy UDP)",
        0x0840, 0x0880, 0x08C0 => "Network Characteristics Result",
        else => null,
    };
}

fn describeMessage(w: *std.Io.Writer, e: *const Event) !void {
    const f = e.f;
    switch (e.code) {
        sec_autodetect_req, sec_autodetect_rsp => {
            const rsp = e.code == sec_autodetect_rsp;
            try w.print("Auto-Detect {s} ", .{if (rsp) "Response" else "Request"});
            try named(w, autodetectName(f[0], rsp), @intCast(f[0]));
            try w.print(" seq={d}", .{f[1]});
        },
        sec_heartbeat => try w.print("Heartbeat period={d}s count1={d} count2={d}", .{ f[0], f[1], f[2] }),
        sec_transport_req => try w.print("Initiate Multitransport Request id={d} protocol=0x{x}", .{ f[0], f[1] }),
        sec_transport_rsp => try w.print("Initiate Multitransport Response id={d} hr=0x{x:0>8}", .{ f[0], f[1] }),
        else => try w.print("security flags 0x{x}", .{e.code}),
    }
}

fn describeDvc(w: *std.Io.Writer, e: *const Event) !void {
    const f = e.f;
    const chan: Where = if (f[1] <= @backingInt(Where.dvc)) @fromBackingInt(@as(u8, @intCast(f[1]))) else .dvc;
    switch (e.code) {
        dvc_caps => try w.print("Capabilities version={d}", .{f[0]}),
        dvc_create => if (e.dir == .out)
            try w.print("Create Request channel {d} ({s})", .{ f[0], chan.label() })
        else
            try w.print("Create Response channel {d} ({s}) status=0x{x:0>8}", .{ f[0], chan.label(), f[2] }),
        dvc_close => try w.print("Close channel {d} ({s})", .{ f[0], chan.label() }),
        dvc_soft_sync_request => try w.print("Soft-Sync Request flags=0x{x} tunnels={d}", .{ f[0], f[1] }),
        dvc_soft_sync_response => try w.print("Soft-Sync Response tunnels={d}", .{f[0]}),
        else => try w.print("cmd {d}", .{e.code}),
    }
}

fn describeRdpsnd(w: *std.Io.Writer, e: *const Event) !void {
    const f = e.f;
    const name: ?[]const u8 = switch (e.code) {
        0x00 => "Wave (data)",
        0x01 => "Close",
        0x02 => "WaveInfo",
        0x03 => "Volume",
        0x04 => "Pitch",
        0x05 => "Wave Confirm",
        0x06 => if (e.dir == .out) "Training" else "Training Confirm",
        0x07 => if (e.dir == .out) "Server Formats" else "Client Formats",
        0x08 => "Crypt Key",
        0x09 => "Wave Encrypt",
        0x0A => "UDP Wave",
        0x0B => "UDP Wave Last",
        0x0C => "Quality Mode",
        0x0D => "Wave2",
        else => null,
    };
    try named(w, name, e.code);
    switch (e.code) {
        0x02 => try w.print(" timestamp={d} format={d} block={d}", .{ f[0], f[1], f[2] }),
        0x0D => try w.print(" timestamp={d} format={d} block={d} audioTimestamp={d}", .{ f[0], f[1], f[2], f[3] }),
        0x05 => try w.print(" timestamp={d} block={d}", .{ f[0], f[1] }),
        0x06 => try w.print(" timestamp={d} packSize={d}", .{ f[0], f[1] }),
        0x07 => try w.print(" formats={d} version={d} flags=0x{x}", .{ f[0], f[1], f[2] }),
        0x03 => try w.print(" 0x{x:0>8}", .{f[0]}),
        0x0C => try w.print(" mode={d}", .{f[0]}),
        else => {},
    }
}

fn describeAudin(w: *std.Io.Writer, e: *const Event) !void {
    const f = e.f;
    switch (e.code) {
        0x01 => try w.print("Version {d}", .{f[0]}),
        0x02 => try w.print("Formats count={d}", .{f[0]}),
        0x03 => try w.print("Open framesPerPacket={d} format={d} tag=0x{x} channels={d} rate={d}", .{ f[0], f[1], f[2], f[3], f[4] }),
        0x04 => try w.print("Open Reply result=0x{x:0>8}", .{f[0]}),
        0x05 => try w.writeAll("Incoming Data"),
        0x06 => try w.writeAll("Data"),
        0x07 => try w.print("Format Change format={d}", .{f[0]}),
        else => try w.print("message 0x{x}", .{e.code}),
    }
}

fn cliprdrName(t: u16) ?[]const u8 {
    return switch (t) {
        0x01 => "Monitor Ready",
        0x02 => "Format List",
        0x03 => "Format List Response",
        0x04 => "Format Data Request",
        0x05 => "Format Data Response",
        0x06 => "Temporary Directory",
        0x07 => "Capabilities",
        0x08 => "File Contents Request",
        0x09 => "File Contents Response",
        0x0A => "Lock Clipboard Data",
        0x0B => "Unlock Clipboard Data",
        else => null,
    };
}

fn describeRdpdr(w: *std.Io.Writer, e: *const Event) !void {
    const f = e.f;
    const name: ?[]const u8 = switch (e.code) {
        0x496E => "Server Announce",
        0x4343 => if (e.dir == .out) "Client ID Confirm" else "Client Announce Reply",
        0x434E => "Client Name",
        0x4441 => "Device List Announce",
        0x6472 => "Device Announce Response",
        0x4952 => "I/O Request",
        0x4943 => "I/O Completion",
        0x5350 => "Server Capabilities",
        0x4350 => "Client Capabilities",
        0x444D => "Device List Remove",
        0x5043 => "Printer Cache Data",
        0x554C => "User Logged On",
        0x5543 => "Printer Using XPS",
        else => null,
    };
    try named(w, name, e.code);
    switch (e.code) {
        0x4952 => {
            const major = f[4];
            const major_name: ?[]const u8 = switch (major) {
                0x00 => "create",
                0x02 => "close",
                0x03 => "read",
                0x04 => "write",
                0x05 => "query information",
                0x06 => "set information",
                0x0A => "query volume information",
                0x0B => "set volume information",
                0x0C => "directory control",
                0x0E => "device control",
                0x11 => "lock control",
                else => null,
            };
            if (major_name) |n| try w.print(" {s}", .{n}) else try w.print(" major=0x{x}", .{major});
            try w.print(" minor={d} device={d} file={d} completion={d}", .{ f[5], f[1], f[2], f[3] });
            if (major == 3 or major == 4) try w.print(" length={d}", .{f[6]});
        },
        0x4943 => try w.print(" device={d} completion={d} status=0x{x:0>8}", .{ f[1], f[2], f[3] }),
        0x4441, 0x444D => try w.print(" devices={d}", .{f[1]}),
        0x6472 => try w.print(" device={d} result=0x{x:0>8}", .{ f[1], f[2] }),
        0x496E, 0x4343 => try w.print(" version={d}.{d}", .{ f[1], f[2] }),
        0x5350, 0x4350 => try w.print(" capabilities={d}", .{f[1]}),
        else => {},
    }
}

fn railName(t: u16) ?[]const u8 {
    return switch (t) {
        0x01 => "Exec",
        0x02 => "Activate",
        0x03 => "System Parameters",
        0x04 => "System Command",
        0x05 => "Handshake",
        0x06 => "Notify Event",
        0x08 => "Window Move",
        0x09 => "Local Move/Size",
        0x0A => "Min/Max Info",
        0x0B => "Client Status",
        0x0C => "System Menu",
        0x0D => "Language Bar Info",
        0x0E => "Get AppID Request",
        0x0F => "Get AppID Response",
        0x10 => "Taskbar Info",
        0x11 => "Language IME Info",
        0x12 => "Compartment Info",
        0x13 => "HandshakeEx",
        0x14 => "Z-Order Sync",
        0x15 => "Cloak",
        0x16 => "Power Display Request",
        0x17 => "Snap Arrange",
        0x18 => "Get AppID Response Ex",
        0x19 => "Text Scale Info",
        0x1A => "Caret Blink Info",
        0x80 => "Exec Result",
        else => null,
    };
}

fn rdpeiName(t: u16) ?[]const u8 {
    return switch (t) {
        0x01 => "SC Ready",
        0x02 => "CS Ready",
        0x03 => "Touch",
        0x04 => "Suspend Input",
        0x05 => "Resume Input",
        0x06 => "Dismiss Hovering Touch Contact",
        0x08 => "Pen",
        else => null,
    };
}

fn gfxName(cmd: u16) ?[]const u8 {
    return switch (cmd) {
        0x01 => "WireToSurface1",
        0x02 => "WireToSurface2",
        0x03 => "DeleteEncodingContext",
        0x04 => "SolidFill",
        0x05 => "SurfaceToSurface",
        0x06 => "SurfaceToCache",
        0x07 => "CacheToSurface",
        0x08 => "EvictCacheEntry",
        0x09 => "CreateSurface",
        0x0A => "DeleteSurface",
        0x0B => "StartFrame",
        0x0C => "EndFrame",
        0x0D => "FrameAcknowledge",
        0x0E => "ResetGraphics",
        0x0F => "MapSurfaceToOutput",
        0x10 => "CacheImportOffer",
        0x11 => "CacheImportReply",
        0x12 => "CapsAdvertise",
        0x13 => "CapsConfirm",
        0x15 => "MapSurfaceToWindow",
        0x16 => "QoeFrameAcknowledge",
        0x17 => "MapSurfaceToScaledOutput",
        0x18 => "MapSurfaceToScaledWindow",
        else => null,
    };
}

fn codecName(id: u32) ?[]const u8 {
    return switch (id) {
        0x00 => "uncompressed",
        0x03 => "RemoteFX",
        0x08 => "ClearCodec",
        0x09 => "progressive",
        0x0A => "planar",
        0x0B => "AVC420",
        0x0C => "alpha",
        0x0E => "AVC444",
        0x0F => "AVC444v2",
        else => null,
    };
}

fn formatName(f: u32) []const u8 {
    return switch (f) {
        0x20 => "XRGB",
        0x21 => "ARGB",
        else => "?",
    };
}

fn capsVersion(w: *std.Io.Writer, v: u32) !void {
    const name: ?[]const u8 = switch (v) {
        0x00080004 => "8.0",
        0x00080105 => "8.1",
        0x000A0002 => "10.0",
        0x000A0100 => "10.1",
        0x000A0200 => "10.2",
        0x000A0301 => "10.3",
        0x000A0400 => "10.4",
        0x000A0502 => "10.5",
        0x000A0600 => "10.6",
        0x000A0601 => "10.6err",
        0x000A0701 => "10.7",
        else => null,
    };
    if (name) |n| try w.writeAll(n) else try w.print("0x{x:0>8}", .{v});
}

fn describeGfx(w: *std.Io.Writer, e: *const Event) !void {
    const f = e.f;
    switch (e.code) {
        gfx_message => return w.print("message: {d} PDU(s), {d} bytes on the wire", .{ f[0], f[1] }),
        gfx_malformed => return w.print("malformed PDU cmd 0x{x}", .{f[0]}),
        else => {},
    }
    try named(w, gfxName(e.code), e.code);
    switch (e.code) {
        0x01, 0x02 => {
            try w.print(" surface={d} codec=", .{f[0] & 0xFFFF});
            if (codecName(f[1])) |n| try w.writeAll(n) else try w.print("0x{x}", .{f[1]});
            try w.print(" format={s}", .{formatName(f[0] >> 16)});
            if (e.code == 0x02) return w.print(" context={d} bitmap={d}", .{ f[2], f[4] });
            try w.writeAll(" rect=");
            try rect(w, f[2], f[3]);
            try w.print(" bitmap={d}", .{f[4]});
            switch (f[1]) {
                0x0B => try w.print(" regions={d} h264={d}", .{ f[5], f[6] }),
                0x0E, 0x0F => try w.print(" LC={d} ({s}) regions={d} stream1={d}", .{ f[5], switch (f[5]) {
                    0 => "luma+chroma",
                    1 => "luma",
                    2 => "chroma",
                    else => "?",
                }, f[6], f[7] }),
                0x08 => try w.print(" glyphFlags=0x{x} seq={d}", .{ f[5], f[6] }),
                0x0A => try w.print(" header=0x{x}", .{f[5]}),
                0x0C => try w.print(" compressed={d}", .{f[5]}),
                else => {},
            }
        },
        0x03 => try w.print(" surface={d} context={d}", .{ f[0], f[2] }),
        0x04 => try w.print(" surface={d} rects={d}", .{ f[0], f[5] }),
        0x05 => {
            try w.print(" src={d} dst={d} rect=", .{ f[0], f[1] });
            try rect(w, f[2], f[3]);
            try w.print(" points={d}", .{f[5]});
        },
        0x06 => {
            try w.print(" surface={d} slot={d} rect=", .{ f[0], f[5] });
            try rect(w, f[2], f[3]);
        },
        0x07 => try w.print(" surface={d} slot={d} points={d}", .{ f[0], f[5], f[6] }),
        0x08 => try w.print(" slot={d}", .{f[5]}),
        0x09 => try w.print(" surface={d} {d}x{d} format={s}", .{ f[0] & 0xFFFF, f[2], f[3], formatName(f[0] >> 16) }),
        0x0A => try w.print(" surface={d}", .{f[0]}),
        0x0B => try w.print(" frame={d} timestamp=0x{x}", .{ f[0], f[1] }),
        0x0C => try w.print(" frame={d}", .{f[0]}),
        0x0D => if (f[1] == 0xFFFF_FFFF)
            try w.print(" frame={d} queueDepth=suspend decoded={d}", .{ f[0], f[2] })
        else
            try w.print(" frame={d} queueDepth={d} decoded={d}", .{ f[0], f[1], f[2] }),
        0x0E => try w.print(" {d}x{d} monitors={d}", .{ f[0], f[1], f[2] }),
        0x0F => try w.print(" surface={d} origin={d},{d}", .{ f[0], f[1], f[2] }),
        0x10, 0x11 => try w.print(" entries={d}", .{f[0]}),
        0x12 => {
            try w.print(" sets={d} versions=", .{f[0]});
            for (0..@min(f[0], 7)) |i| {
                if (i > 0) try w.writeAll(",");
                try capsVersion(w, f[1 + i]);
            }
        },
        0x13 => {
            try w.writeAll(" version=");
            try capsVersion(w, f[0]);
            try w.print(" flags=0x{x}", .{f[1]});
        },
        0x15 => try w.print(" surface={d} window=0x{x} {d}x{d}", .{ f[0], f[1], f[2], f[3] }),
        0x16 => try w.print(" frame={d} timestamp={d} diffSE={d} diffEDR={d}", .{ f[0], f[1], f[2], f[3] }),
        0x17 => try w.print(" surface={d} origin={d},{d} target={d}x{d}", .{ f[0], f[1], f[2], f[3], f[4] }),
        0x18 => try w.print(" surface={d} window=0x{x} {d}x{d} target={d}x{d}", .{ f[0], f[1], f[2], f[3], f[4], f[5] }),
        else => {},
    }
}

fn errorOf(v: u32) anyerror {
    return @errorFromInt(@as(@Int(.unsigned, @bitSizeOf(anyerror)), @intCast(v)));
}

fn reasonName(r: u3) []const u8 {
    return switch (r) {
        0 => "domain disconnected",
        1 => "provider initiated",
        2 => "token purged",
        3 => "user requested",
        4 => "channel purged",
        else => "?",
    };
}

fn errorHint(err: anyerror) []const u8 {
    return switch (err) {
        error.TlsReadFailed => ": the TLS stream broke off without a close_notify (a crashed or killed client, or the network)",
        error.ConnectionClosed => ": the connection was closed or reset without a goodbye",
        error.ReadFailed, error.WriteFailed, error.TlsWriteFailed => ": the network failed",
        error.ClientDisconnected => ": the client gave up during the connection sequence",
        error.ClientTooSlow => ": the client stopped taking the session's output (the send queue went over its cap)",
        error.ProtocolError => ": a PDU the server could not accept",
        else => "",
    };
}

const FileOut = struct {
    fd: c_int,
    buf: [16 * 1024]u8 = undefined,
    len: usize = 0,
    failed: bool = false,

    fn line(o: *FileOut, s: []const u8) void {
        if (o.len + s.len + 1 > o.buf.len) o.flush();
        const n = @min(s.len, o.buf.len - 1);
        @memcpy(o.buf[o.len..][0..n], s[0..n]);
        o.buf[o.len + n] = '\n';
        o.len += n + 1;
    }

    fn flush(o: *FileOut) void {
        var off: usize = 0;
        while (off < o.len and !o.failed) {
            const rc = c.write(o.fd, o.buf[off..].ptr, o.len - off);
            if (rc < 0) {
                if (c.__errno_location().* == c.EINTR) continue;
                o.failed = true;
            } else off += @intCast(rc);
        }
        o.len = 0;
    }
};

fn ensureDir(dir: []const u8) !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    if (dir.len == 0 or dir.len >= buf.len) return error.NameTooLong;
    if (std.fs.path.dirname(dir)) |parent| {
        const pz = try std.mem.printSentinel(&buf, "{s}", .{parent}, 0);
        _ = c.mkdir(pz.ptr, 0o700);
    }
    const dz = try std.mem.printSentinel(&buf, "{s}", .{dir}, 0);
    if (c.mkdir(dz.ptr, 0o700) != 0 and c.__errno_location().* != c.EEXIST) return error.MkdirFailed;
    if (c.chmod(dz.ptr, 0o700) != 0) return error.MkdirFailed;
}

var last_stamp_ms = std.atomic.Value(i64).init(0);

/// `now`, or 1 ms past the last stamp, so file names are unique and sort by time.
fn nextStamp(now: i64) i64 {
    var prev = last_stamp_ms.load(.monotonic);
    while (true) {
        const next = @max(now, prev + 1);
        prev = last_stamp_ms.cmpxchgWeak(prev, next, .monotonic, .monotonic) orelse return next;
    }
}

fn isRecordName(name: []const u8) bool {
    if (name.len < 25 or !std.mem.endsWith(u8, name, ".log")) return false;
    for (name[0..8]) |ch| if (!std.ascii.isDigit(ch)) return false;
    return name[8] == 'T' and name[19] == 'Z' and name[20] == '-';
}

/// Keeps the newest `keep` records in `dir` (names sort by time); other files are left alone.
fn rotate(dir: []const u8, keep: usize) void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const dz = std.mem.printSentinel(&buf, "{s}", .{dir}, 0) catch return;
    const d = c.opendir(dz.ptr) orelse return;
    defer _ = c.closedir(d);
    const Name = struct { len: u8, b: [128]u8 };
    var names: [256]Name = undefined;
    var n: usize = 0;
    while (c.readdir(d)) |ent| {
        const name = std.mem.sliceTo(&ent.*.d_name, 0);
        if (!isRecordName(name) or name.len > 128) continue;
        if (n == names.len) break;
        names[n].len = @intCast(name.len);
        @memcpy(names[n].b[0..name.len], name);
        n += 1;
    }
    if (n <= keep) return;
    const less = struct {
        fn lt(_: void, a: Name, b: Name) bool {
            return std.mem.lessThan(u8, a.b[0..a.len], b.b[0..b.len]);
        }
    }.lt;
    std.mem.sort(Name, names[0..n], {}, less);
    for (names[0 .. n - keep]) |*old| {
        var z: [129]u8 = undefined;
        @memcpy(z[0..old.len], old.b[0..old.len]);
        z[old.len] = 0;
        _ = c.unlinkat(c.dirfd(d), &z, 0);
    }
}

fn sanitize(buf: []u8, peer: []const u8) []const u8 {
    var tmp: [64]u8 = undefined;
    var p = peer;
    const mapped = "[::ffff:";
    if (std.mem.startsWith(u8, peer, mapped)) if (std.mem.indexOfPos(u8, peer, mapped.len, "]:")) |end| {
        p = std.fmt.bufPrint(&tmp, "{s}:{s}", .{ peer[mapped.len..end], peer[end + 2 ..] }) catch peer;
    };
    const n = @min(p.len, buf.len);
    for (p[0..n], buf[0..n]) |ch, *o| o.* = if (std.ascii.isAlphanumeric(ch) or ch == '.' or ch == '-') ch else '_';
    return buf[0..n];
}

const Utc = struct { y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8, ms: u16 };

fn utc(wall_ms: i64) Utc {
    const ms: u64 = @intCast(@max(wall_ms, 0));
    const es: std.time.epoch.EpochSeconds = .{ .secs = ms / 1000 };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return .{ .y = yd.year, .mo = md.month.numeric(), .d = @as(u8, md.day_index) + 1, .h = ds.getHoursIntoDay(), .mi = ds.getMinutesIntoHour(), .s = ds.getSecondsIntoMinute(), .ms = @intCast(ms % 1000) };
}

fn fileStamp(buf: []u8, wall_ms: i64) ![]const u8 {
    const t = utc(wall_ms);
    return std.fmt.bufPrint(buf, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}.{d:0>3}Z", .{ t.y, t.mo, t.d, t.h, t.mi, t.s, t.ms });
}

fn humanStamp(buf: []u8, wall_ms: i64) ![]const u8 {
    const t = utc(wall_ms);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}", .{ t.y, t.mo, t.d, t.h, t.mi, t.s, t.ms });
}

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn wallMs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

fn testLine(r: *const Recorder, i: usize, buf: []u8) []const u8 {
    var w = std.Io.Writer.fixed(buf);
    describe(&w, r.get(i)) catch {};
    return w.buffered();
}

test "the ring keeps the newest events in order" {
    const gpa = std.testing.allocator;
    var r: Recorder = .{};
    defer r.deinit(gpa);
    try r.start(gpa, 8, null);
    for (0..20) |i| r.channel(.dvc, .in, @intCast(i), &.{});
    try std.testing.expectEqual(@as(usize, 8), r.count());
    try std.testing.expectEqual(@as(u64, 21), r.n); // the start milestone too
    for (0..8) |i| try std.testing.expectEqual(@as(u32, @intCast(12 + i)), r.get(i).f[0]);
    for (1..8) |i| try std.testing.expect(r.get(i).ns >= r.get(i - 1).ns);
}

test "a recorder that is off records nothing" {
    var r: Recorder = .{};
    r.channel(.dvc, .in, 1, "x");
    r.note(.established, &.{});
    const pdu = [_]u8{ 0x0b, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectEqual(@as(u32, 0), r.gfxOut(&pdu));
    try std.testing.expectEqual(@as(usize, 0), r.count());
    try std.testing.expect(!r.liveRequested());
}

test "input is counted by type, never by key" {
    const gpa = std.testing.allocator;
    var r: Recorder = .{};
    defer r.deinit(gpa);
    try r.start(gpa, 8, null);
    const evs = [_]fastpath.InputEvent{
        .{ .scancode = .{ .code = 0x1E, .flags = 0 } },
        .{ .unicode = .{ .code = 0x263A, .release = false } },
        .{ .mouse = .{ .flags = 0x0800, .x = 10, .y = 20 } },
        .{ .mouse = .{ .flags = 0x0800, .x = 11, .y = 21 } },
    };
    r.input(.fastpath, 21, InputCounts.of(&evs));
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("input: 1 keyboard, 1 unicode, 2 mouse", testLine(&r, 1, &buf));
    for (r.get(1).f) |v| try std.testing.expect(v != 0x1E and v != 0x263A and v != 10 and v != 20);
}

test "file stamps sort by time and peers are safe in a name" {
    var b: [32]u8 = undefined;
    try std.testing.expectEqualStrings("20261019T210312.345Z", try fileStamp(&b, 1792443792345));
    var p: [64]u8 = undefined;
    try std.testing.expectEqualStrings("192.168.21.128_50123", sanitize(&p, "192.168.21.128:50123"));
    try std.testing.expectEqualStrings("192.168.21.128_50123", sanitize(&p, "[::ffff:192.168.21.128]:50123"));
    try std.testing.expectEqualStrings("_fd7a_115c_a1e0__1__3389", sanitize(&p, "[fd7a:115c:a1e0::1]:3389"));
    try std.testing.expectEqualStrings("___1__3389", sanitize(&p, "[::1]:3389"));
    try std.testing.expect(isRecordName("20261019T210312.345Z-10.0.0.1_1.log"));
    try std.testing.expect(!isRecordName("notes.log"));
}
