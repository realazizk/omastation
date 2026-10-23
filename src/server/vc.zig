//! Virtual channels of one connection and the features serving them, all on the connection's
//! thread: static channels (MS-RDPBCGR 2.2.6, 3.1.5.2), dynamic channels on drdynvc
//! (MS-RDPEDYC), and their move to multitransport tunnels by Soft-Sync (MS-RDPEDYC 3.1.5.3).

const std = @import("std");
const c = @import("c");
const bytes = @import("../core/bytes.zig");
const x224 = @import("../proto/x224.zig");
const mcs = @import("../proto/mcs.zig");
const gcc = @import("../proto/gcc.zig");
const vchan = @import("../proto/vchan.zig");
const dvc = @import("../proto/dvc.zig");
const zgfx = @import("../codec/zgfx.zig");
const bulk = @import("../codec/bulk.zig");
const channels = @import("channels.zig");
const dvcqueue = @import("dvcqueue.zig");
const flow = @import("flow.zig");
const conn_mod = @import("conn.zig");
const features = @import("features.zig");
const flight = @import("flight.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.chan);

pub const Error = conn_mod.Error;

/// Create Requests stop if the Capabilities Response is this late (MS-RDPEDYC 3.3.3.1.4).
pub const dvc_caps_timeout_ms = 10_000;
/// Lower ChannelIds are pinned (Dynamic.id); ids are never reused (MS-RDPEDYC 2.2.2.1).
pub const first_free_id: u32 = 3;
pub const max_polled = 16;

pub const Dynamic = struct {
    /// ChannelName of the Create Request (MS-RDPEDYC 2.2.2.1).
    name: []const u8,
    /// Fixed ChannelId below first_free_id (Graphics 1, DisplayControl 2), or null for the next free one.
    id: ?u32 = null,
    /// Tunnel used after Soft-Sync (MS-RDPEDYC 3.1.5.3); null stays on DRDYNVC.
    tunnel: ?TunnelKind = .reliable,
    /// Create Request Pri (MS-RDPEDYC 2.2.2.1); Windows servers open audio playback as realtime.
    priority: Priority = .low,
    /// False for audio, as Windows servers do, and for already compressed data (RDPGFX's ZGFX).
    compress: bool = true,
};

pub const Priority = dvcqueue.Priority;

/// Multitransport tunnels (MS-RDPEMT 1.3): RDP-UDP reliable and lossy.
pub const TunnelKind = enum(u1) {
    reliable,
    lossy,

    /// TunnelType (MS-RDPEDYC 2.2.5.1.1).
    pub fn tunnelType(k: TunnelKind) u32 {
        return switch (k) {
            .reliable => dvc.tunneltype_udpfecr,
            .lossy => dvc.tunneltype_udpfecl,
        };
    }
};

/// DVC PDUs go out in Tunnel Data PDUs (MS-RDPEDYC 1.3.1.2) instead of DRDYNVC.
pub const Tunnel = struct {
    ctx: *anyopaque,
    /// Queues one DVC PDU; a failed tunnel drops it and reports itself via dropTunnel.
    send: *const fn (ctx: *anyopaque, pdu: []const u8) Error!void,
    flush: *const fn (ctx: *anyopaque) Error!void,
    /// Bytes it takes now without waiting for its congestion window; null for no limit.
    room: ?*const fn (ctx: *anyopaque) usize = null,
    /// Its rate in B/s for graphics pacing; null if unknown (the TCP rate is used).
    rate: ?*const fn (ctx: *anyopaque) ?f64 = null,
};

/// No drdynvc, or no Capabilities Response in time (MS-RDPEDYC 3.3.3.1.4).
pub fn dvcUnavailable(conn: *const Conn) bool {
    const s = &conn.vc;
    if (s.drdynvc == null) return true;
    if (s.dvc_ready) return false;
    return s.caps_sent_ms != 0 and conn_mod.nowMs() - s.caps_sent_ms > dvc_caps_timeout_ms;
}

pub const SoftSync = enum {
    none,
    /// Soft-Sync Request sent: the channels it lists send on their tunnel.
    requested,
    /// Soft-Sync Response received: tunnel input may be read (3.3.5.3.2).
    done,
};

pub const Closed = enum {
    /// CreationStatus < 0 (MS-RDPEDYC 2.2.2.2).
    refused,
    /// DYNVC_CLOSE from the client (2.2.4).
    client,
};

pub const Poll = struct { fd: c_int, events: c_short = c.POLLIN };

pub const Stage = enum {
    idle,
    /// MS-RDPBCGR 1.3.1.1 phase 8: `.licensed` features start before the capabilities exchange.
    licensed,
    /// Font Map sent: the other features start, static channels open, the DVC capabilities exchange begins.
    established,
};

/// What a feature implements; every entry is optional. Errors end the connection.
pub const VTable = struct {
    start: ?*const fn (ctx: *anyopaque) Error!void = null,
    /// Static channels once established, dynamic ones once the client accepts them.
    open: ?*const fn (ctx: *anyopaque, ch: Channel) Error!void = null,
    /// One whole client message; the slice is valid during the call only.
    data: ?*const fn (ctx: *anyopaque, ch: Channel, msg: []const u8) Error!void = null,
    /// A non-final static chunk, so features timing out on client answers know more is coming.
    partial: ?*const fn (ctx: *anyopaque, ch: Channel) Error!void = null,
    /// The client refused or closed a dynamic channel (not called for Channel.close).
    close: ?*const fn (ctx: *anyopaque, ch: Channel, why: Closed) void = null,
    /// Returns the next deadline (conn.nowMs clock), or null.
    tick: ?*const fn (ctx: *anyopaque, now_ms: i64) Error!?i64 = null,
    pollFd: ?*const fn (ctx: *anyopaque) ?Poll = null,
    onFd: ?*const fn (ctx: *anyopaque, revents: c_short) Error!void = null,
    /// MCS message channel PDUs (MS-RDPBCGR 2.2.1.4.5) from the security header on, to every started feature.
    message: ?*const fn (ctx: *anyopaque, pdu: []const u8) Error!void = null,
    /// The connection ends: frees everything, `ctx` too if owned; no sending.
    deinit: ?*const fn (ctx: *anyopaque) void = null,
};

pub const Handler = struct { ctx: *anyopaque, vtable: *const VTable };

/// A feature and what it serves. Slices and names must outlive the connection.
pub const Registration = struct {
    handler: Handler,
    /// Matched case-insensitively; names the client did not declare are skipped.
    static: []const []const u8 = &.{},
    dynamic: []const Dynamic = &.{},
    /// CHANNEL_FLAG_SHOW_PROTOCOL (MS-RDPBCGR 2.2.6.1.1); Windows clients do not expect the header.
    show_protocol: bool = false,
};

pub const Channel = struct {
    conn: *Conn,
    ref: Ref,

    pub const Ref = union(enum) {
        static: u8,
        dynamic: u32,
    };

    /// Flushed after the current callback or by Conn.flush; dropped if the channel is not open.
    pub fn send(ch: Channel, msg: []const u8) Error!void {
        return switch (ch.ref) {
            .static => |i| sendStatic(ch.conn, i, msg),
            .dynamic => |id| sendDynamic(ch.conn, id, msg),
        };
    }

    /// DYNVC_CLOSE (MS-RDPEDYC 3.3.5.2); static channels stay open.
    pub fn close(ch: Channel) Error!void {
        switch (ch.ref) {
            .static => {},
            .dynamic => |id| try closeDynamic(ch.conn, id),
        }
    }

    pub fn isOpen(ch: Channel) bool {
        return switch (ch.ref) {
            .static => true,
            .dynamic => |id| ch.conn.vc.isOpen(id),
        };
    }

    pub fn name(ch: Channel) []const u8 {
        const s = &ch.conn.vc;
        return switch (ch.ref) {
            .static => |i| ch.conn.client.channels[s.statics[i].client_index].nameSlice(),
            .dynamic => |id| if (s.dynamicConst(id)) |d| d.name else "",
        };
    }
};

pub const Static = struct {
    mcs_id: u16,
    options: u32,
    client_index: u8,
    /// Index into State.feats; null for drdynvc.
    owner: ?u16,
    show_protocol: bool = false,
    reasm: vchan.Reassembler = .{},
    where: flight.Where = .static,
};

pub const DvcState = enum {
    waiting,
    /// Only in this state is a Create Response acted on (MS-RDPEDYC 3.1).
    create_sent,
    open,
    refused,
    closed,
};

pub const Dvc = struct {
    id: u32,
    name: []const u8,
    owner: u16,
    state: DvcState = .waiting,
    wants: ?TunnelKind = .reliable,
    priority: Priority = .low,
    compress: bool = true,
    tunnel: ?TunnelKind = null,
    reasm: dvc.Reassembler = .{},
    /// RDP8 Lite decoder for version 3 compressed data, created on use.
    lite: ?zgfx.Decompressor = null,
    where: flight.Where = .dvc,

    fn release(d: *Dvc, gpa: std.mem.Allocator) void {
        d.reasm.deinit(gpa);
        d.reasm = .{};
        if (d.lite) |*l| l.deinit(gpa);
        d.lite = null;
    }
};

const Feat = struct {
    handler: Handler,
    static: []const []const u8,
    show_protocol: bool,
    /// .licensed once started; .established once its static channels are open.
    stage: Stage = .idle,
};

pub const State = struct {
    opts: features.Options = .{},
    stage: Stage = .idle,
    feats: std.ArrayList(Feat) = .empty,
    statics: [gcc.max_channels]Static = undefined,
    static_count: u8 = 0,
    drdynvc: ?u8 = null,
    dvcs: std.ArrayList(Dvc) = .empty,
    next_id: u32 = first_free_id,
    dvc_ready: bool = false,
    caps_sent_ms: i64 = 0,
    wake_ms: ?i64 = null,
    /// Owners of the fds pollFds returned, in order.
    polled: [max_polled]u16 = undefined,
    polled_count: u8 = 0,
    tunnels: [2]?Tunnel = .{ null, null },
    soft_sync: SoftSync = .none,
    /// Tunnels the client's Soft-Sync Response says it sends on.
    client_tunnels: dvc.SoftSyncTunnels = .{},

    pub fn drdynvcId(s: *const State) ?u16 {
        return s.statics[s.drdynvc orelse return null].mcs_id;
    }

    pub fn dynamic(s: *State, id: u32) ?*Dvc {
        for (s.dvcs.items) |*d| if (d.id == id) return d;
        return null;
    }

    fn dynamicConst(s: *const State, id: u32) ?*const Dvc {
        for (s.dvcs.items) |*d| if (d.id == id) return d;
        return null;
    }

    pub fn isOpen(s: *const State, id: u32) bool {
        const d = s.dynamicConst(id) orelse return false;
        return d.state == .open;
    }
};

/// Takes ownership: on error the handler's deinit has run. A late feature starts at once.
pub fn register(conn: *Conn, r: Registration) Error!void {
    const s = &conn.vc;
    {
        errdefer if (r.handler.vtable.deinit) |d| d(r.handler.ctx);
        try s.feats.ensureUnusedCapacity(conn.gpa, 1);
        try s.dvcs.ensureUnusedCapacity(conn.gpa, r.dynamic.len);
    }
    const fi: u16 = @intCast(s.feats.items.len);
    s.feats.appendAssumeCapacity(.{ .handler = r.handler, .static = r.static, .show_protocol = r.show_protocol });
    for (r.dynamic) |d| {
        std.debug.assert(d.name.len > 0);
        if (d.id) |pinned| std.debug.assert(pinned < first_free_id);
        const id = d.id orelse id: {
            s.next_id += 1;
            break :id s.next_id - 1;
        };
        std.debug.assert(s.dynamic(id) == null);
        s.dvcs.appendAssumeCapacity(.{ .id = id, .name = d.name, .owner = fi, .wants = d.tunnel, .priority = d.priority, .compress = d.compress, .where = flight.dvcWhere(d.name) });
    }
    if (s.stage != .idle) {
        try advance(conn, fi);
        try flushPending(conn);
    }
}

pub fn find(conn: *const Conn, comptime T: type) ?*T {
    for (conn.vc.feats.items) |f| {
        if (f.handler.vtable == &Box(T).vtable) return &Box(T).of(f.handler.ctx).v;
    }
    return null;
}

fn Box(comptime T: type) type {
    return struct {
        gpa: std.mem.Allocator,
        v: T,

        const Self = @This();
        pub const vtable: VTable = .{
            .start = if (@hasDecl(T, "start")) callStart else null,
            .open = if (@hasDecl(T, "open")) callOpen else null,
            .data = if (@hasDecl(T, "data")) callData else null,
            .partial = if (@hasDecl(T, "partial")) callPartial else null,
            .close = if (@hasDecl(T, "close")) callClose else null,
            .tick = if (@hasDecl(T, "tick")) callTick else null,
            .pollFd = if (@hasDecl(T, "pollFd")) callPollFd else null,
            .onFd = if (@hasDecl(T, "onFd")) callOnFd else null,
            .message = if (@hasDecl(T, "message")) callMessage else null,
            .deinit = callDeinit,
        };

        fn of(ctx: *anyopaque) *Self {
            return @ptrCast(@alignCast(ctx));
        }
        fn callStart(ctx: *anyopaque) Error!void {
            return of(ctx).v.start();
        }
        fn callOpen(ctx: *anyopaque, ch: Channel) Error!void {
            return of(ctx).v.open(ch);
        }
        fn callData(ctx: *anyopaque, ch: Channel, msg: []const u8) Error!void {
            return of(ctx).v.data(ch, msg);
        }
        fn callPartial(ctx: *anyopaque, ch: Channel) Error!void {
            return of(ctx).v.partial(ch);
        }
        fn callClose(ctx: *anyopaque, ch: Channel, why: Closed) void {
            of(ctx).v.close(ch, why);
        }
        fn callTick(ctx: *anyopaque, now_ms: i64) Error!?i64 {
            return of(ctx).v.tick(now_ms);
        }
        fn callPollFd(ctx: *anyopaque) ?Poll {
            return of(ctx).v.pollFd();
        }
        fn callOnFd(ctx: *anyopaque, revents: c_short) Error!void {
            return of(ctx).v.onFd(revents);
        }
        fn callMessage(ctx: *anyopaque, pdu: []const u8) Error!void {
            return of(ctx).v.message(pdu);
        }
        fn callDeinit(ctx: *anyopaque) void {
            const b = of(ctx);
            if (@hasDecl(T, "deinit")) b.v.deinit();
            b.gpa.destroy(b);
        }
    };
}

fn startStage(comptime T: type) Stage {
    const st: Stage = if (@hasDecl(T, "start_stage")) T.start_stage else .established;
    comptime std.debug.assert(st != .idle);
    return st;
}

fn instantiate(conn: *Conn, comptime T: type) Error!void {
    var v = (try T.init(conn)) orelse return;
    const b = conn.gpa.create(Box(T)) catch |err| {
        if (@hasDecl(T, "deinit")) v.deinit();
        return err;
    };
    b.* = .{ .gpa = conn.gpa, .v = v };
    try register(conn, .{
        .handler = .{ .ctx = b, .vtable = &Box(T).vtable },
        .static = if (@hasDecl(T, "static_channels")) &T.static_channels else &.{},
        .dynamic = if (@hasDecl(T, "dynamic_channels")) &T.dynamic_channels else &.{},
        .show_protocol = if (@hasDecl(T, "static_show_protocol")) T.static_show_protocol else false,
    });
}

pub fn startLicensed(conn: *Conn) Error!void {
    const s = &conn.vc;
    if (s.stage != .idle) return;
    inline for (features.list) |T| if (comptime startStage(T) == .licensed) try instantiate(conn, T);
    s.stage = .licensed;
    for (0..s.feats.items.len) |fi| try advance(conn, @intCast(fi));
    try flushPending(conn);
}

/// Font Map sent; ends with the DVC Capabilities Request (MS-RDPEDYC 3.3.3.1).
pub fn start(conn: *Conn) Error!void {
    const s = &conn.vc;
    if (s.stage == .established) return;
    if (s.stage == .idle) try startLicensed(conn);
    for (conn.client.channelSlice(), 0..) |ch, i| {
        if (!std.ascii.eqlIgnoreCase(ch.nameSlice(), "drdynvc")) continue;
        s.drdynvc = s.static_count;
        s.statics[s.static_count] = .{ .mcs_id = conn.channel_ids[i], .options = ch.options, .client_index = @intCast(i), .owner = null, .where = .drdynvc };
        s.static_count += 1;
        break;
    }
    inline for (features.list) |T| if (comptime startStage(T) == .established) try instantiate(conn, T);
    s.stage = .established;
    for (0..s.feats.items.len) |fi| try advance(conn, @intCast(fi));
    if (s.drdynvc != null) {
        var buf: [16]u8 = undefined;
        var list = std.ArrayList(u8).initBuffer(&buf);
        var w = bytes.Writer.init(&list, std.mem.Allocator.failing);
        try dvc.writeCapsRequest(&w, 3);
        conn.flight.dvc(.out, list.items, .dvc);
        try sendStatic(conn, s.drdynvc.?, list.items);
        s.caps_sent_ms = conn_mod.nowMs();
    }
    try flushPending(conn);
}

fn advance(conn: *Conn, fi: u16) Error!void {
    const s = &conn.vc;
    // By index: a callback may register a feature (feats grows).
    const h = s.feats.items[fi].handler;
    if (s.feats.items[fi].stage == .idle) {
        s.feats.items[fi].stage = .licensed;
        if (h.vtable.start) |f| try f(h.ctx);
    }
    if (s.stage != .established or s.feats.items[fi].stage == .established) return;
    s.feats.items[fi].stage = .established;
    for (s.feats.items[fi].static) |want| {
        for (conn.client.channelSlice(), 0..) |ch, i| {
            if (!std.ascii.eqlIgnoreCase(ch.nameSlice(), want)) continue;
            if (staticIndex(s, conn.channel_ids[i]) != null) {
                log.debug("{s}: static channel {s} is served already", .{ conn.peer, ch.nameSlice() });
                break;
            }
            s.statics[s.static_count] = .{ .mcs_id = conn.channel_ids[i], .options = ch.options, .client_index = @intCast(i), .owner = fi, .show_protocol = s.feats.items[fi].show_protocol, .where = flight.staticWhere(ch.nameSlice()) };
            s.static_count += 1;
            break;
        }
    }
    if (h.vtable.open) |f| {
        for (s.statics[0..s.static_count], 0..) |st, i| {
            if (st.owner == fi) try f(h.ctx, .{ .conn = conn, .ref = .{ .static = @intCast(i) } });
        }
    }
    if (s.dvc_ready) try sendCreates(conn, fi);
}

pub fn onMessage(conn: *Conn, pdu: []const u8) Error!void {
    const s = &conn.vc;
    var i: usize = 0;
    while (i < s.feats.items.len) : (i += 1) {
        const f = s.feats.items[i];
        if (f.stage == .idle) continue;
        if (f.handler.vtable.message) |m| try m(f.handler.ctx, pdu);
    }
    try flushPending(conn);
}

pub fn deinit(conn: *Conn) void {
    const s = &conn.vc;
    const gpa = conn.gpa;
    for (s.feats.items) |f| if (f.handler.vtable.deinit) |d| d(f.handler.ctx);
    s.feats.deinit(gpa);
    for (s.statics[0..s.static_count]) |*st| st.reasm.deinit(gpa);
    for (s.dvcs.items) |*d| d.release(gpa);
    s.dvcs.deinit(gpa);
    s.* = .{ .opts = s.opts };
}

fn flushPending(conn: *Conn) Error!void {
    if (conn.out.items.len > 0 or conn.flow.queuedTotal() > 0) try conn.flush();
}

fn staticIndex(s: *const State, mcs_id: u16) ?u8 {
    for (s.statics[0..s.static_count], 0..) |st, i| if (st.mcs_id == mcs_id) return @intCast(i);
    return null;
}

/// One chunk on static channel `mcs_id`. Returns false if the channel is not served.
pub fn onStatic(conn: *Conn, mcs_id: u16, data: []const u8) Error!bool {
    const s = &conn.vc;
    const i = staticIndex(s, mcs_id) orelse {
        // Unserved compressed chunks still pass through the shared history (MS-RDPBCGR 3.1.8).
        if (data.len >= vchan.header_len) if (try conn.bulk.channelInput(conn.gpa)) |d| {
            const flags = std.mem.readInt(u32, data[4..8], .little);
            if (flags & 0x00E00000 != 0) _ = try vchan.plainChunk(flags, data[vchan.header_len..], d);
        };
        conn.flight.channel(.static, .in, mcs_id, data);
        return false;
    };
    const st = &s.statics[i];
    // Client chunks may be compressed (VCCAPS_COMPR_CS_8K).
    const msg = (try st.reasm.feedWith(conn.gpa, data, try conn.bulk.channelInput(conn.gpa))) orelse {
        if (st.owner) |fi| {
            const h = s.feats.items[fi].handler;
            if (h.vtable.partial) |f| try f(h.ctx, .{ .conn = conn, .ref = .{ .static = i } });
            try flushPending(conn);
        }
        return true;
    };
    if (st.owner) |fi| {
        conn.flight.channel(st.where, .in, st.mcs_id, msg);
        const h = s.feats.items[fi].handler;
        if (h.vtable.data) |f| try f(h.ctx, .{ .conn = conn, .ref = .{ .static = i } }, msg);
    } else {
        try onDvcPdu(conn, msg);
    }
    try flushPending(conn);
    return true;
}

pub fn onDrdynvc(conn: *Conn, data: []const u8) Error!void {
    const id = conn.vc.drdynvcId() orelse return;
    _ = try onStatic(conn, id, data);
}

/// VCChunkSize capped at 1600, as the server advertises none (MS-RDPBCGR 3.1.5.2.1, 2.2.7.1.10).
pub fn chunkSize(conn: *const Conn) usize {
    const v = conn.client_caps.vc_chunk_size;
    return if (v == 0) vchan.chunk_length else @min(v, vchan.chunk_length);
}

/// CHANNEL_OPTION_COMPRESS_RDP (MS-RDPBCGR 2.2.1.3.4.1).
pub const channel_option_compress_rdp: u32 = 0x00800000;

/// Only with COMPRESS_RDP, as a Windows server decides; Windows clients set it on drdynvc, rdpdr
/// and cliprdr, not rdpsnd.
pub fn channelCompressed(options: u32) bool {
    return options & channel_option_compress_rdp != 0;
}

pub fn sendStatic(conn: *Conn, i: u8, msg: []const u8) Error!void {
    return sendStaticChunks(conn, i, msg, true);
}

/// With `compress`, chunks are bulk-compressed into Conn.out if the client accepts it (VCCAPS_COMPR_SC).
pub fn sendStaticChunks(conn: *Conn, i: u8, msg: []const u8, compress: bool) Error!void {
    const st = &conn.vc.statics[i];
    // DRDYNVC PDUs are recorded where they are built (flight.dvc, sendDynamic).
    if (st.owner != null) conn.flight.channel(st.where, .out, st.mcs_id, msg);
    const extra: u32 = if (st.show_protocol) vchan.flag_show_protocol else 0;
    const cmp = if (compress and channelCompressed(st.options)) conn.bulk.channelOutput(conn.client_caps.vc_flags) else null;
    try vchan.writeChunks(msg, chunkSize(conn), extra, ChunkSink{ .conn = conn, .mcs_id = st.mcs_id, .cmp = cmp });
}

const ChunkSink = struct {
    conn: *Conn,
    mcs_id: u16,
    cmp: ?*bulk.Compressor = null,

    /// Whole or not at all; a compressed chunk keeps the uncompressed total length (3.1.5.2.2.1).
    pub fn chunk(k: ChunkSink, hdr: []const u8, data: []const u8) Error!void {
        var h: [vchan.header_len]u8 = hdr[0..vchan.header_len].*;
        var payload = data;
        // Reserve first: compressed data must reach `out` (one shared history) and is never larger.
        try k.conn.out.ensureUnusedCapacity(k.conn.gpa, 16 + h.len + data.len);
        if (k.cmp) |cmp| {
            const r = try cmp.compress(data);
            const flags = std.mem.readInt(u32, h[4..8], .little) | (bulk.channelFlags(r) catch unreachable);
            std.mem.writeInt(u32, h[4..8], flags, .little);
            payload = r.data;
        }
        var w = k.conn.writer();
        const f = x224.beginData(&w) catch unreachable;
        mcs.writeSendDataIndicationHeader(&w, k.mcs_id, h.len + payload.len) catch unreachable;
        w.bytes(&h) catch unreachable;
        w.bytes(payload) catch unreachable;
        f.finish(&w);
    }
};

fn onDvcPdu(conn: *Conn, msg: []const u8) Error!void {
    const s = &conn.vc;
    const gpa = conn.gpa;
    switch (try dvc.parseClientPdu(msg)) {
        .caps_response => |v| {
            conn.flight.dvc(.in, msg, .dvc);
            try onCapsResponse(conn, v);
        },
        .create_response => |cr| {
            conn.flight.dvc(.in, msg, dvcWhere(s, cr.channel_id));
            try onCreateResponse(conn, cr.channel_id, cr.status);
        },
        .data_first => |df| {
            const r = openReasm(s, df.channel_id) orelse return;
            if (try r.first(gpa, df.total, df.data)) |m| try deliver(conn, df.channel_id, m);
        },
        .data => |d| {
            const r = openReasm(s, d.channel_id) orelse return;
            if (try r.data(gpa, d.data)) |m| try deliver(conn, d.channel_id, m);
        },
        // Version 3 compressed data (MS-RDPEDYC 2.2.3.3, 2.2.3.4) replaces the DATA_FIRST / DATA payload.
        .data_first_compressed => |df| {
            const r = openReasm(s, df.channel_id) orelse return;
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(gpa);
            try decompressLite(conn, df.channel_id, df.data, &block);
            if (try r.first(gpa, df.total, block.items)) |m| try deliver(conn, df.channel_id, m);
        },
        .data_compressed => |d| {
            const r = openReasm(s, d.channel_id) orelse return;
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(gpa);
            try decompressLite(conn, d.channel_id, d.data, &block);
            if (try r.data(gpa, block.items)) |m| try deliver(conn, d.channel_id, m);
        },
        .close => |id| {
            conn.flight.dvc(.in, msg, dvcWhere(s, id));
            onClose(conn, id);
        },
        .soft_sync_response => {
            conn.flight.dvc(.in, msg, .dvc);
            try onSoftSyncResponse(conn, msg);
        },
    }
}

fn dvcWhere(s: *const State, id: u32) flight.Where {
    return if (s.dynamicConst(id)) |d| d.where else .dvc;
}

fn onCapsResponse(conn: *Conn, v: u16) Error!void {
    const s = &conn.vc;
    // Versions 1-3 only (MS-RDPEDYC 2.2.1.2); others end the connection (3.1.5.2.4).
    if (v < 1 or v > 3) {
        log.warn("{s}: DVC caps response with version {d}", .{ conn.peer, v });
        return error.BadDvcPdu;
    }
    // The exchange happens once (2.2.1), so channel ids stay unique.
    if (s.dvc_ready) return log.debug("{s}: repeated DVC caps response (ignored)", .{conn.peer});
    if (conn_mod.nowMs() - s.caps_sent_ms > dvc_caps_timeout_ms) {
        log.warn("{s}: DVC caps response after {d} ms; no dynamic channels", .{ conn.peer, dvc_caps_timeout_ms });
        return;
    }
    log.info("{s}: DVC version {d}", .{ conn.peer, v });
    s.dvc_ready = true;
    for (0..s.feats.items.len) |fi| try sendCreates(conn, @intCast(fi));
}

/// Create Requests (2.2.2.1) for feature `fi`'s waiting channels, one drdynvc message each.
fn sendCreates(conn: *Conn, fi: u16) Error!void {
    const s = &conn.vc;
    if (s.feats.items[fi].stage != .established) return;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(conn.gpa);
    for (s.dvcs.items) |*d| {
        if (d.owner != fi or d.state != .waiting) continue;
        list.clearRetainingCapacity();
        var w = bytes.Writer.init(&list, conn.gpa);
        try dvc.writeCreateRequestPri(&w, d.id, d.name, @backingInt(d.priority));
        conn.flight.dvc(.out, list.items, d.where);
        try sendStatic(conn, s.drdynvc.?, list.items);
        d.state = .create_sent;
    }
}

fn onCreateResponse(conn: *Conn, id: u32, status: i32) Error!void {
    const s = &conn.vc;
    // Only an answer to a sent Create Request counts; others are ignored.
    const d = s.dynamic(id) orelse return;
    if (d.state != .create_sent) return log.debug("{s}: create response for channel {d} not expected (ignored)", .{ conn.peer, id });
    const h = s.feats.items[d.owner].handler;
    const ch: Channel = .{ .conn = conn, .ref = .{ .dynamic = id } };
    // A negative HRESULT fails; S_FALSE and other positive values succeed (MS-RDPEDYC 2.2.2.2).
    if (status >= 0) {
        d.state = .open;
        log.info("{s}: dynamic channel {s} ({d}) open", .{ conn.peer, d.name, id });
        if (h.vtable.open) |f| try f(h.ctx, ch);
    } else {
        d.state = .refused;
        log.info("{s}: dynamic channel {s} ({d}) refused (0x{x:0>8})", .{ conn.peer, d.name, id, @as(u32, @bitCast(status)) });
        if (h.vtable.close) |f| f(h.ctx, ch, .refused);
    }
}

fn onClose(conn: *Conn, id: u32) void {
    const s = &conn.vc;
    log.info("{s}: client closed dynamic channel {d}", .{ conn.peer, id });
    const d = s.dynamic(id) orelse return;
    switch (d.state) {
        .create_sent, .open => {},
        else => return,
    }
    d.state = .closed;
    d.release(conn.gpa);
    // Its queued data is dropped; it was never compressed, so no history is affected.
    flow.dropDvc(conn, id);
    const h = s.feats.items[d.owner].handler;
    if (h.vtable.close) |f| f(h.ctx, .{ .conn = conn, .ref = .{ .dynamic = id } }, .client);
}

/// The reassembler of an open channel; null (data ignored) otherwise (MS-RDPEDYC 3.1).
fn openReasm(s: *State, id: u32) ?*dvc.Reassembler {
    const d = s.dynamic(id) orelse return null;
    return if (d.state == .open) &d.reasm else null;
}

fn decompressLite(conn: *Conn, id: u32, data: []const u8, out: *std.ArrayList(u8)) Error!void {
    const d = conn.vc.dynamic(id).?; // openReasm admitted it
    if (d.lite == null) d.lite = try zgfx.Decompressor.initLite(conn.gpa);
    d.lite.?.decompress(conn.gpa, out, data) catch |err| switch (err) {
        error.BadZgfx => {
            log.warn("{s}: bad compressed data on dynamic channel {d}", .{ conn.peer, id });
            return error.BadDvcPdu;
        },
        error.OutOfMemory => return error.OutOfMemory,
    };
}

fn deliver(conn: *Conn, id: u32, msg: []const u8) Error!void {
    const d = conn.vc.dynamic(id).?;
    conn.flight.channel(d.where, .in, id, msg);
    const h = conn.vc.feats.items[d.owner].handler;
    if (h.vtable.data) |f| try f(h.ctx, .{ .conn = conn, .ref = .{ .dynamic = id } }, msg);
}

/// DATA, or DATA_FIRST + DATA above 1590 bytes (MS-RDPEDYC 2.2.3); dropped if not open (3.1.1).
pub fn sendDynamic(conn: *Conn, id: u32, msg: []const u8) Error!void {
    if (!conn.vc.isOpen(id)) return log.debug("{s}: {d} bytes for dynamic channel {d}, which is not open (dropped)", .{ conn.peer, msg.len, id });
    const d = conn.vc.dynamic(id).?;
    // RDPGFX is recorded per PDU before ZGFX (channels.sendGfx).
    if (d.where != .rdpgfx) conn.flight.channel(d.where, .out, id, msg);
    if (d.tunnel) |k| if (conn.vc.tunnels[@backingInt(k)] != null) {
        return flow.queueTunnel(conn, k, id, d.priority, msg);
    };
    try flow.queueDvc(conn, id, d.priority, d.compress, msg);
}

pub const SoftSyncReadiness = enum {
    /// Before the capabilities exchange, or after Soft-Sync (once per connection).
    no,
    /// A Create Request is unanswered; Soft-Sync now would miss that channel.
    creates_pending,
    ready,
};

pub fn softSyncReadiness(conn: *const Conn) SoftSyncReadiness {
    const s = &conn.vc;
    if (!s.dvc_ready or s.soft_sync != .none) return .no;
    for (s.dvcs.items) |d| if (d.state == .create_sent) return .creates_pending;
    return .ready;
}

/// Requires softSyncReadiness != .no; lists the open channels per tunnel (3.3.5.3.1), returns how many moved.
pub fn softSync(conn: *Conn, tunnels: [2]?Tunnel) Error!usize {
    const s = &conn.vc;
    std.debug.assert(softSyncReadiness(conn) != .no);
    var ids: [2]std.ArrayList(u32) = .{ .empty, .empty };
    defer for (&ids) |*l| l.deinit(conn.gpa);
    for (s.dvcs.items) |d| {
        if (d.state != .open) continue;
        const k = d.wants orelse continue;
        if (tunnels[@backingInt(k)] == null) continue;
        try ids[@backingInt(k)].append(conn.gpa, d.id);
    }
    for (&ids) |*l| std.mem.sort(u32, l.items, {}, std.sort.asc(u32));
    var lists: [2]dvc.SoftSyncList = undefined;
    var n: usize = 0;
    for (ids, 0..) |l, i| {
        if (l.items.len == 0) continue;
        lists[n] = .{ .tunnel_type = @as(TunnelKind, @fromBackingInt(@intCast(i))).tunnelType(), .channel_ids = l.items };
        n += 1;
    }
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(conn.gpa);
    var w = bytes.Writer.init(&list, conn.gpa);
    try dvc.writeSoftSyncRequest(&w, lists[0..n]);
    // SOFT_SYNC_TCP_FLUSHED: data queued on DRDYNVC goes before the request, whatever the window.
    try flow.flushDvc(conn, true);
    conn.flight.dvc(.out, list.items, .dvc);
    try sendStatic(conn, s.drdynvc.?, list.items);
    // From here each channel uses one transport consistently (3.3.5.3.1).
    s.tunnels = tunnels;
    s.soft_sync = .requested;
    var moved: usize = 0;
    for (ids, 0..) |l, i| for (l.items) |id| {
        s.dynamic(id).?.tunnel = @fromBackingInt(@intCast(i));
        moved += 1;
    };
    log.info("{s}: soft-sync: {d} dynamic channel(s) moved to UDP", .{ conn.peer, moved });
    try flushPending(conn);
    return moved;
}

/// Channels on tunnel `k` return to DRDYNVC; true if `watch` was among them (its data may be lost).
pub fn dropTunnel(conn: *Conn, k: TunnelKind, watch: u32) bool {
    const s = &conn.vc;
    s.tunnels[@backingInt(k)] = null;
    var hit = false;
    var n: usize = 0;
    for (s.dvcs.items) |*d| {
        if (d.tunnel != k) continue;
        d.tunnel = null;
        n += 1;
        if (d.id == watch) hit = true;
    }
    if (n > 0) log.info("{s}: {d} dynamic channel(s) back on TCP", .{ conn.peer, n });
    return hit;
}

/// Tunnel input may be read only after the client's Soft-Sync Response (3.3.5.3.2).
pub fn tunnelInputAllowed(conn: *const Conn) bool {
    return conn.vc.soft_sync == .done;
}

pub fn onTunnelPdu(conn: *Conn, pdu: []const u8) Error!void {
    try onDvcPdu(conn, pdu);
    try flushPending(conn);
}

pub fn flushTunnels(conn: *Conn) Error!void {
    for (conn.vc.tunnels) |t| if (t) |x| try x.flush(x.ctx);
}

fn onSoftSyncResponse(conn: *Conn, msg: []const u8) Error!void {
    const s = &conn.vc;
    if (s.soft_sync != .requested) return log.debug("{s}: soft-sync response without a request (ignored)", .{conn.peer});
    s.client_tunnels = try dvc.parseSoftSyncResponse(msg);
    s.soft_sync = .done;
    log.info("{s}: soft-sync response: the client sends on {s}", .{ conn.peer, if (s.client_tunnels.reliable or s.client_tunnels.lossy) "UDP" else "TCP" });
}

/// DYNVC_CLOSE (MS-RDPEDYC 2.2.4, 3.3.5.2) if open or opening, without calling the feature.
pub fn closeDynamic(conn: *Conn, id: u32) Error!void {
    const d = conn.vc.dynamic(id) orelse return;
    switch (d.state) {
        .create_sent, .open => {},
        else => return,
    }
    // Queued data goes before the close (MS-RDPEDYC 3.3.5.2).
    try flow.flushDvc(conn, true);
    var buf: [8]u8 = undefined;
    var list = std.ArrayList(u8).initBuffer(&buf);
    var w = bytes.Writer.init(&list, std.mem.Allocator.failing);
    try dvc.writeClose(&w, id);
    conn.flight.dvc(.out, list.items, d.where);
    try sendStatic(conn, conn.vc.drdynvc.?, list.items);
    d.state = .closed;
    d.release(conn.gpa);
}

pub fn tick(conn: *Conn) Error!void {
    const s = &conn.vc;
    s.wake_ms = null;
    const now = conn_mod.nowMs();
    // By index: a feature may register another one.
    var i: usize = 0;
    while (i < s.feats.items.len) : (i += 1) {
        if (s.feats.items[i].stage == .idle) continue;
        const h = s.feats.items[i].handler;
        const f = h.vtable.tick orelse continue;
        if (try f(h.ctx, now)) |at| s.wake_ms = if (s.wake_ms) |w| @min(w, at) else at;
    }
    try flushPending(conn);
}

pub fn pollTimeout(conn: *const Conn, timeout: c_int) c_int {
    const at = conn.vc.wake_ms orelse return timeout;
    const left: c_int = @intCast(std.math.clamp(at - conn_mod.nowMs(), 0, std.math.maxInt(c_int)));
    return if (timeout < 0) left else @min(timeout, left);
}

pub fn pollFds(conn: *Conn, out: []c.struct_pollfd) usize {
    const s = &conn.vc;
    s.polled_count = 0;
    for (s.feats.items, 0..) |f, fi| {
        if (f.stage == .idle) continue;
        const get = f.handler.vtable.pollFd orelse continue;
        const p = get(f.handler.ctx) orelse continue;
        if (s.polled_count == @min(out.len, max_polled)) {
            log.warn("{s}: more than {d} feature fds; not all are polled", .{ conn.peer, s.polled_count });
            break;
        }
        out[s.polled_count] = .{ .fd = p.fd, .events = p.events, .revents = 0 };
        s.polled[s.polled_count] = @intCast(fi);
        s.polled_count += 1;
    }
    return s.polled_count;
}

pub fn onPolled(conn: *Conn, fds: []const c.struct_pollfd) Error!void {
    const s = &conn.vc;
    for (fds[0..@min(fds.len, s.polled_count)], 0..) |p, k| {
        if (p.revents == 0) continue;
        const h = s.feats.items[s.polled[k]].handler;
        if (h.vtable.onFd) |f| try f(h.ctx, p.revents);
    }
    try flushPending(conn);
}

pub fn Errors(comptime list: anytype) type {
    var E: type = error{};
    inline for (list) |T| {
        if (@hasDecl(T, "Error")) E = E || T.Error;
    }
    return E;
}

test "Errors merges the features' error sets" {
    const A = struct {
        pub const Error = error{ BadA, Shared };
    };
    const B = struct {};
    const C = struct {
        pub const Error = error{ BadC, Shared };
    };
    const E = Errors(.{ A, B, C });
    try std.testing.expectEqual(3, @typeInfo(E).error_set.error_names.?.len);
    const all = [_]E{ error.BadA, error.BadC, error.Shared };
    try std.testing.expectEqual(3, all.len);
}
