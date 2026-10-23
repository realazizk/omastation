//! Wayland wire protocol, client side: byte/fd queues, the object id table (zombies for
//! destroyed objects, as libwayland) and per-object event dispatch. Every event is checked
//! against its wire signature before a handler sees it; malformed input is InvalidMessage.

const std = @import("std");
const sys = @import("sys.zig");
pub const proto = @import("wl_protocols");

const log = std.log.scoped(.wl);

pub const Fd = sys.Fd;
pub const Fixed = proto.Fixed;
pub const Arg = proto.Arg;
pub const ArgSpec = proto.ArgSpec;
pub const Interface = proto.Interface;

pub const Error = error{
    SocketFailed,
    ConnectFailed,
    NameTooLong,
    NoRuntimeDir,
    ReadFailed,
    WriteFailed,
    WouldBlock,
    ConnectionClosed,
    PollFailed,
    ShmFailed,
    OutOfMemory,
    /// Malformed or out-of-sync incoming data.
    InvalidMessage,
    InvalidOpcode,
    /// Outgoing message would exceed `max_request_size`.
    MessageTooLarge,
    /// Request argument that cannot be encoded (e.g. string with NUL).
    InvalidArgument,
    TooManyObjects,
    /// The compositor sent wl_display.error; see `Connection.protocol_error`.
    ProtocolError,
    Timeout,
    /// A required global is missing or too old.
    Unsupported,
    /// The compositor refused or stopped a capture/input session.
    Stopped,
    /// Captures keep failing (e.g. permission denied).
    CaptureFailed,
};

pub const header_size = 8;
/// libwayland's limit for one message; compositors may reject larger.
pub const max_request_size = 4096;
const out_capacity = 4 * max_request_size;
/// The size field is 16 bits, so any event fits.
const in_capacity = 1 << 16;
pub const server_id_start: u32 = 0xff00_0000;
const display_id: u32 = 1;
const fd_queue_capacity = 256;
const max_event_fds = 8;
const max_event_new_ids = 4;

pub const Handler = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque, msg: *Message) Error!void,

    pub fn init(comptime T: type, ctx: *T, comptime f: fn (*T, *Message) Error!void) Handler {
        const Thunk = struct {
            fn call(p: *anyopaque, m: *Message) Error!void {
                return f(@ptrCast(@alignCast(p)), m);
            }
        };
        return .{ .ctx = ctx, .func = Thunk.call };
    }
};

pub const Object = struct {
    state: enum(u8) { free, live, zombie } = .free,
    interface: ?Interface = null,
    version: u32 = 0,
    handler: ?Handler = null,
};

/// One incoming event, valid only during the handler call.
pub const Message = struct {
    object: u32,
    opcode: u16,
    interface: Interface,
    body: []const u8,
    /// In argument order; taken ones become -1 and belong to the taker, the rest close after the handler.
    fds: []Fd,

    pub fn reader(m: *Message) ArgReader {
        return .{ .body = m.body, .fds = m.fds };
    }

    pub fn decode(m: *Message, comptime T: type) Error!T.Event {
        var r = m.reader();
        return T.decodeEvent(m.opcode, &r);
    }

    pub fn eventName(m: *const Message) []const u8 {
        const names = m.interface.eventNames();
        return if (m.opcode < names.len) names[m.opcode] else "?";
    }
};

fn pad4(n: usize) usize {
    return (n + 3) & ~@as(usize, 3);
}

pub const ArgReader = struct {
    body: []const u8,
    pos: usize = 0,
    fds: []Fd = &.{},
    fd_pos: usize = 0,

    fn word(r: *ArgReader) Error!u32 {
        if (r.body.len - r.pos < 4) return error.InvalidMessage;
        const v = std.mem.readInt(u32, r.body[r.pos..][0..4], .little);
        r.pos += 4;
        return v;
    }

    pub fn int(r: *ArgReader) Error!i32 {
        return @bitCast(try r.word());
    }

    pub fn uint(r: *ArgReader) Error!u32 {
        return r.word();
    }

    pub fn fixed(r: *ArgReader) Error!Fixed {
        return @fromBackingInt(try r.int());
    }

    pub fn stringOpt(r: *ArgReader) Error!?[:0]const u8 {
        const len: usize = try r.word();
        if (len == 0) return null;
        const avail = r.body.len - r.pos;
        if (len > avail or pad4(len) > avail) return error.InvalidMessage;
        const s = r.body[r.pos..][0..len];
        // NUL-terminated, no interior NUL (libwayland: "embedded nul").
        if (std.mem.indexOfScalar(u8, s, 0) != len - 1) return error.InvalidMessage;
        r.pos += pad4(len);
        return s[0 .. len - 1 :0];
    }

    pub fn string(r: *ArgReader) Error![:0]const u8 {
        return (try r.stringOpt()) orelse error.InvalidMessage;
    }

    pub fn object(r: *ArgReader) Error!u32 {
        return r.word();
    }

    pub fn newId(r: *ArgReader) Error!u32 {
        const id = try r.word();
        if (id == 0) return error.InvalidMessage;
        return id;
    }

    pub fn array(r: *ArgReader) Error![]const u8 {
        const len: usize = try r.word();
        const avail = r.body.len - r.pos;
        if (len > avail or pad4(len) > avail) return error.InvalidMessage;
        const a = r.body[r.pos..][0..len];
        r.pos += pad4(len);
        return a;
    }

    /// Take ownership of the next fd argument.
    pub fn fd(r: *ArgReader) Error!Fd {
        if (r.fd_pos >= r.fds.len) return error.InvalidMessage;
        const f = r.fds[r.fd_pos];
        if (f < 0) return error.InvalidMessage;
        r.fds[r.fd_pos] = -1;
        r.fd_pos += 1;
        return f;
    }
};

/// Runs before any handler, so handlers only see structurally valid events.
fn validate(sig: []const ArgSpec, body: []const u8, new_ids: *[max_event_new_ids]u32) Error!usize {
    var r: ArgReader = .{ .body = body };
    var n_new: usize = 0;
    for (sig) |a| switch (a.kind) {
        .int, .uint, .fixed => _ = try r.word(),
        // Null only where the protocol allows it.
        .object => if (try r.word() == 0 and !a.nullable) return error.InvalidMessage,
        .string => if (a.nullable) {
            _ = try r.stringOpt();
        } else {
            _ = try r.string();
        },
        .new_id => {
            const id = try r.newId();
            if (n_new == new_ids.len) return error.InvalidMessage;
            new_ids[n_new] = id;
            n_new += 1;
        },
        .array => _ = try r.array(),
        .fd => {},
    };
    if (r.pos != body.len) return error.InvalidMessage;
    return n_new;
}

fn fdCount(sig: []const ArgSpec) usize {
    var n: usize = 0;
    for (sig) |a| {
        if (a.kind == .fd) n += 1;
    }
    return n;
}

const FdQueue = struct {
    buf: [fd_queue_capacity]Fd = undefined,
    head: usize = 0,
    len: usize = 0,

    fn push(q: *FdQueue, fd: Fd) bool {
        if (q.len == q.buf.len) return false;
        q.buf[(q.head + q.len) % q.buf.len] = fd;
        q.len += 1;
        return true;
    }

    fn pop(q: *FdQueue) ?Fd {
        if (q.len == 0) return null;
        const fd = q.buf[q.head];
        q.head = (q.head + 1) % q.buf.len;
        q.len -= 1;
        return fd;
    }

    fn closeAll(q: *FdQueue) void {
        while (q.pop()) |fd| sys.close(fd);
    }
};

pub const ProtocolError = struct {
    object_id: u32,
    interface: ?Interface,
    code: u32,
    message_buf: [256]u8 = undefined,
    message_len: usize = 0,

    pub fn message(e: *const ProtocolError) []const u8 {
        return e.message_buf[0..e.message_len];
    }
};

pub const Connection = struct {
    gpa: std.mem.Allocator,
    fd: Fd,
    owns_fd: bool = true,

    out: [out_capacity]u8 = undefined,
    out_len: usize = 0,
    /// Duplicated fds waiting to be sent with the bytes in `out`.
    out_fds: [sys.max_fds_out]Fd = undefined,
    out_fds_len: usize = 0,

    in: [in_capacity]u8 = undefined,
    in_start: usize = 0,
    in_end: usize = 0,
    in_fds: FdQueue = .{},

    /// Client-allocated ids, indexed by id (0 = null, 1 = wl_display).
    objects: std.ArrayList(Object) = .empty,
    /// Server-allocated ids, indexed by id - server_id_start.
    server_objects: std.ArrayList(Object) = .empty,
    free_ids: std.ArrayList(u32) = .empty,

    dispatching: bool = false,
    protocol_error: ?ProtocolError = null,
    /// Set once the stream is unusable (malformed data, closed socket).
    broken: bool = false,
    /// The most `flush` waits for the compositor to make room.
    send_timeout_ms: u32 = 5000,

    /// `display`: a socket name or absolute path; default `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`.
    pub fn connect(gpa: std.mem.Allocator, display_name: ?[]const u8) Error!*Connection {
        const name = display_name orelse sys.getenv("WAYLAND_DISPLAY") orelse "wayland-0";
        var path_buf: [256]u8 = undefined;
        const path = if (name.len > 0 and name[0] == '/')
            name
        else blk: {
            const dir = sys.getenv("XDG_RUNTIME_DIR") orelse return error.NoRuntimeDir;
            break :blk std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir, name }) catch return error.NameTooLong;
        };
        const fd = try sys.connectUnix(path);
        errdefer sys.close(fd);
        return initFd(gpa, fd);
    }

    /// The connection owns `fd`.
    pub fn initFd(gpa: std.mem.Allocator, fd: Fd) Error!*Connection {
        const conn = try gpa.create(Connection);
        errdefer gpa.destroy(conn);
        conn.* = .{ .gpa = gpa, .fd = fd };
        try conn.objects.appendSlice(gpa, &.{
            .{},
            .{ .state = .live, .interface = .wl_display, .version = 1 },
        });
        return conn;
    }

    pub fn deinit(conn: *Connection) void {
        for (conn.out_fds[0..conn.out_fds_len]) |f| sys.close(f);
        conn.in_fds.closeAll();
        if (conn.owns_fd) sys.close(conn.fd);
        conn.objects.deinit(conn.gpa);
        conn.server_objects.deinit(conn.gpa);
        conn.free_ids.deinit(conn.gpa);
        conn.gpa.destroy(conn);
    }

    pub fn display(conn: *Connection) proto.WlDisplay {
        _ = conn;
        return .{ .id = display_id };
    }

    pub fn object(conn: *Connection, id: u32) ?*Object {
        if (id >= server_id_start) {
            const idx = id - server_id_start;
            return if (idx < conn.server_objects.items.len) &conn.server_objects.items[idx] else null;
        }
        return if (id < conn.objects.items.len and id != 0) &conn.objects.items[id] else null;
    }

    fn allocId(conn: *Connection) Error!u32 {
        if (conn.free_ids.pop()) |id| return id;
        const id: u32 = @intCast(conn.objects.items.len);
        if (id >= server_id_start) return error.TooManyObjects;
        try conn.objects.append(conn.gpa, .{});
        return id;
    }

    /// Allocate a client id for a child of `parent` (inherits its version).
    pub fn newId(conn: *Connection, iface: Interface, parent: u32) Error!u32 {
        const ver = if (conn.object(parent)) |p| p.version else 1;
        return conn.newIdVersioned(iface, ver);
    }

    pub fn newIdVersioned(conn: *Connection, iface: Interface, ver: u32) Error!u32 {
        const id = try conn.allocId();
        conn.objects.items[id] = .{ .state = .live, .interface = iface, .version = ver };
        return id;
    }

    /// Keeps the id reserved until the compositor's delete_id, swallowing late events.
    pub fn destroyed(conn: *Connection, id: u32) void {
        const obj = conn.object(id) orelse return;
        if (id >= server_id_start) {
            obj.* = .{};
        } else {
            obj.state = .zombie;
            obj.handler = null;
        }
    }

    pub fn setHandler(conn: *Connection, id: u32, handler: ?Handler) void {
        if (conn.object(id)) |o| {
            if (o.state == .live) o.handler = handler;
        }
    }

    pub fn version(conn: *Connection, id: u32) u32 {
        return if (conn.object(id)) |o| o.version else 0;
    }

    fn freeId(conn: *Connection, id: u32) void {
        if (id < 2 or id >= server_id_start) return;
        const obj = conn.object(id) orelse return;
        if (obj.state == .free) return;
        obj.* = .{};
        conn.free_ids.append(conn.gpa, id) catch {
            // Leak the id rather than fail; ids are plentiful.
        };
    }

    fn registerServerObject(conn: *Connection, id: u32, iface: ?Interface, ver: u32) Error!void {
        if (id < server_id_start) return error.InvalidMessage;
        const idx = id - server_id_start;
        // Server ids are dense: N is used only after N-1 (Wayland "Creating Objects").
        if (idx > 1 << 20 or idx > conn.server_objects.items.len) return error.InvalidMessage;
        if (idx == conn.server_objects.items.len) try conn.server_objects.append(conn.gpa, .{});
        const slot = &conn.server_objects.items[idx];
        if (slot.state == .live) return error.InvalidMessage;
        slot.* = .{ .state = .live, .interface = iface, .version = ver };
    }

    /// fd arguments are duplicated, so callers keep ownership of theirs.
    pub fn request(conn: *Connection, id: u32, opcode: u16, args: []const Arg) Error!void {
        if (conn.broken) return error.ConnectionClosed;
        var size: usize = header_size;
        var nfds: usize = 0;
        for (args) |a| switch (a) {
            .int, .uint, .fixed, .object, .new_id => size += 4,
            .string => |s| {
                size += 4;
                if (s) |str| {
                    if (std.mem.indexOfScalar(u8, str, 0) != null) return error.InvalidArgument;
                    size += pad4(str.len + 1);
                }
            },
            .array => |arr| size += 4 + pad4(arr.len),
            .fd => nfds += 1,
        };
        if (size > max_request_size) return error.MessageTooLarge;
        if (nfds > sys.max_fds_out) return error.InvalidArgument;
        if (conn.out_len + size > conn.out.len or conn.out_fds_len + nfds > conn.out_fds.len) try conn.flush();

        // Duplicate fds first so a failure leaves the queue untouched.
        var dups: [sys.max_fds_out]Fd = undefined;
        var ndup: usize = 0;
        errdefer for (dups[0..ndup]) |f| sys.close(f);
        for (args) |a| if (a == .fd) {
            dups[ndup] = sys.dup(a.fd) orelse return error.InvalidArgument;
            ndup += 1;
        };

        var w = conn.out_len;
        putU32(&conn.out, &w, id);
        putU32(&conn.out, &w, @as(u32, @intCast(size)) << 16 | opcode);
        for (args) |a| switch (a) {
            .int => |v| putU32(&conn.out, &w, @bitCast(v)),
            .uint, .object, .new_id => |v| putU32(&conn.out, &w, v),
            .fixed => |v| putU32(&conn.out, &w, @bitCast(@backingInt(v))),
            .string => |s| if (s) |str| {
                putU32(&conn.out, &w, @intCast(str.len + 1));
                putBytesPadded(&conn.out, &w, str, str.len + 1);
            } else putU32(&conn.out, &w, 0),
            .array => |arr| {
                putU32(&conn.out, &w, @intCast(arr.len));
                putBytesPadded(&conn.out, &w, arr, arr.len);
            },
            .fd => {},
        };
        std.debug.assert(w - conn.out_len == size);
        conn.out_len = w;
        @memcpy(conn.out_fds[conn.out_fds_len..][0..ndup], dups[0..ndup]);
        conn.out_fds_len += ndup;
    }

    fn putU32(buf: []u8, w: *usize, v: u32) void {
        std.mem.writeInt(u32, buf[w.*..][0..4], v, .little);
        w.* += 4;
    }

    fn putBytesPadded(buf: []u8, w: *usize, data: []const u8, len: usize) void {
        @memcpy(buf[w.*..][0..data.len], data);
        @memset(buf[w.* + data.len ..][0 .. pad4(len) - data.len], 0);
        w.* += pad4(len);
    }

    /// Waits while the socket is full, at most `send_timeout_ms` in all; past that the
    /// connection is broken (a request may be half sent) and WriteFailed is returned.
    pub fn flush(conn: *Connection) Error!void {
        if (conn.broken) return error.ConnectionClosed;
        var sent: usize = 0;
        var deadline: ?u64 = null;
        while (sent < conn.out_len) {
            const n = sys.sendMsg(conn.fd, conn.out[sent..conn.out_len], conn.out_fds[0..conn.out_fds_len]) catch |err| switch (err) {
                error.WouldBlock => {
                    const now = sys.nowNs() / std.time.ns_per_ms;
                    const end = deadline orelse now + conn.send_timeout_ms;
                    deadline = end;
                    const ready = if (now < end) try sys.pollFd(conn.fd, true, @intCast(@min(end - now, std.math.maxInt(i32)))) else .timeout;
                    if (ready == .timeout) {
                        conn.broken = true;
                        return error.WriteFailed;
                    }
                    continue;
                },
                else => |e| {
                    conn.broken = true;
                    return e;
                },
            };
            if (conn.out_fds_len > 0) {
                for (conn.out_fds[0..conn.out_fds_len]) |f| sys.close(f);
                conn.out_fds_len = 0;
            }
            sent += n;
        }
        conn.out_len = 0;
    }

    /// Returns false if nothing was available (non-blocking mode).
    pub fn readSome(conn: *Connection, nonblock: bool) Error!bool {
        if (conn.broken) return error.ConnectionClosed;
        if (conn.in_start > 0) {
            const live = conn.in_end - conn.in_start;
            std.mem.copyForwards(u8, conn.in[0..live], conn.in[conn.in_start..conn.in_end]);
            conn.in_start = 0;
            conn.in_end = live;
        }
        if (conn.in_end == conn.in.len) return conn.fail(error.InvalidMessage);
        const res = sys.recvMsg(conn.fd, conn.in[conn.in_end..], nonblock) catch |err| switch (err) {
            error.WouldBlock => return false,
            else => |e| return conn.fail(e),
        };
        var lost = res.truncated;
        for (res.fds[0..res.nfds]) |f| {
            if (!conn.in_fds.push(f)) {
                sys.close(f);
                lost = true;
            }
        }
        conn.in_end += res.len;
        if (lost) return conn.fail(error.InvalidMessage);
        return true;
    }

    fn fail(conn: *Connection, err: Error) Error {
        conn.broken = true;
        return err;
    }

    /// Returns the number of messages processed, dropped ones included.
    pub fn dispatchPending(conn: *Connection) Error!usize {
        if (conn.protocol_error != null) return error.ProtocolError;
        if (conn.broken) return error.ConnectionClosed;
        std.debug.assert(!conn.dispatching); // no re-entrant dispatch from handlers
        conn.dispatching = true;
        defer conn.dispatching = false;
        var count: usize = 0;
        while (conn.in_end - conn.in_start >= header_size) {
            const hdr = conn.in[conn.in_start..][0..header_size];
            const id = std.mem.readInt(u32, hdr[0..4], .little);
            const word = std.mem.readInt(u32, hdr[4..8], .little);
            const size: usize = word >> 16;
            const opcode: u16 = @truncate(word);
            if (size < header_size or size % 4 != 0) return conn.fail(error.InvalidMessage);
            if (conn.in_end - conn.in_start < size) break;
            const body = conn.in[conn.in_start + header_size .. conn.in_start + size];
            conn.in_start += size;
            conn.handleMessage(id, opcode, body) catch |err| switch (err) {
                error.ProtocolError => return err,
                error.InvalidMessage, error.InvalidOpcode => return conn.fail(err),
                else => return err,
            };
            count += 1;
        }
        return count;
    }

    fn handleMessage(conn: *Connection, id: u32, opcode: u16, body: []const u8) Error!void {
        const obj = conn.object(id) orelse {
            log.debug("event {d} for unknown object {d} dropped", .{ opcode, id });
            return;
        };
        if (obj.state == .free) {
            log.debug("event {d} for free object {d} dropped", .{ opcode, id });
            return;
        }
        const iface = obj.interface orelse return;
        const sigs = iface.eventSignatures();
        if (opcode >= sigs.len) return error.InvalidOpcode;
        const sig = sigs[opcode];

        // Claim the fds before anything can fail, keeping the fd queue in step with the bytes.
        const nfds = fdCount(sig);
        if (nfds > max_event_fds) return error.InvalidMessage;
        var fds: [max_event_fds]Fd = undefined;
        var have: usize = 0;
        defer for (fds[0..have]) |f| sys.close(f);
        while (have < nfds) : (have += 1) {
            fds[have] = conn.in_fds.pop() orelse return error.InvalidMessage;
        }

        var new_ids: [max_event_new_ids]u32 = undefined;
        const n_new = try validate(sig, body, &new_ids);
        const ver = obj.version;
        const state = obj.state;
        const handler = obj.handler;
        // Server-created objects exist even if the event is ignored.
        var k: usize = 0;
        for (sig) |a| if (a.kind == .new_id) {
            try conn.registerServerObject(new_ids[k], a.interface, ver);
            k += 1;
        };
        std.debug.assert(k == n_new);

        if (id == display_id) return conn.handleDisplay(opcode, body);
        if (state != .live) return;
        const h = handler orelse return;
        var msg: Message = .{ .object = id, .opcode = opcode, .interface = iface, .body = body, .fds = fds[0..have] };
        try h.func(h.ctx, &msg);
    }

    fn handleDisplay(conn: *Connection, opcode: u16, body: []const u8) Error!void {
        var r: ArgReader = .{ .body = body };
        switch (try proto.WlDisplay.decodeEvent(opcode, &r)) {
            .@"error" => |e| {
                var pe: ProtocolError = .{
                    .object_id = e.object_id,
                    .interface = if (conn.object(e.object_id)) |o| o.interface else null,
                    .code = e.code,
                };
                pe.message_len = @min(e.message.len, pe.message_buf.len);
                @memcpy(pe.message_buf[0..pe.message_len], e.message[0..pe.message_len]);
                log.warn("protocol error on {s}@{d} code {d}: {s}", .{
                    if (pe.interface) |i| i.name() else "?", pe.object_id, pe.code, pe.message(),
                });
                conn.protocol_error = pe;
                return error.ProtocolError;
            },
            .delete_id => |d| conn.freeId(d.id),
        }
    }

    /// Flush, then read and dispatch without blocking.
    pub fn dispatch(conn: *Connection) Error!usize {
        try conn.flush();
        var n = try conn.dispatchPending();
        var reads: usize = 0;
        while (reads < 64 and try conn.readSome(true)) : (reads += 1) n += try conn.dispatchPending();
        try conn.flush();
        return n;
    }

    /// Flush, then wait up to `timeout_ms` (-1: forever); returns 0 on timeout.
    pub fn dispatchTimeout(conn: *Connection, timeout_ms: i32) Error!usize {
        try conn.flush();
        var n = try conn.dispatchPending();
        if (n > 0) {
            try conn.flush();
            return n;
        }
        switch (try sys.pollFd(conn.fd, false, timeout_ms)) {
            .timeout => return 0,
            .hangup, .ready => {},
        }
        _ = try conn.readSome(false);
        n = try conn.dispatchPending();
        var reads: usize = 0;
        while (reads < 64 and try conn.readSome(true)) : (reads += 1) n += try conn.dispatchPending();
        try conn.flush();
        return n;
    }

    /// wl_display.sync: every request sent before is processed and its events dispatched.
    pub fn roundtrip(conn: *Connection, timeout_ms: i32) Error!void {
        var done = false;
        const cb = try conn.display().sync(conn);
        conn.setHandler(cb.id, Handler.init(bool, &done, onSyncDone));
        // The handler points at a stack variable; detach it unless the id was deleted and reused.
        defer if (conn.object(cb.id)) |o| {
            if (o.handler) |h| if (h.ctx == @as(*anyopaque, &done)) {
                o.handler = null;
            };
        };
        const deadline: ?u32 = if (timeout_ms < 0) null else sys.nowMs() +% @as(u32, @intCast(timeout_ms));
        while (!done) {
            var wait: i32 = -1;
            if (deadline) |d| {
                const left: i32 = @bitCast(d -% sys.nowMs());
                if (left <= 0) return error.Timeout;
                wait = left;
            }
            _ = try conn.dispatchTimeout(wait);
        }
    }

    fn onSyncDone(done: *bool, msg: *Message) Error!void {
        _ = msg;
        done.* = true;
    }
};

const testing = std.testing;

fn readAllFrom(fd: Fd, buf: []u8) !sys.Received {
    var total: sys.Received = .{ .len = 0 };
    while (true) {
        const r = sys.recvMsg(fd, buf[total.len..], true) catch |e| switch (e) {
            error.WouldBlock => return total,
            else => return e,
        };
        for (r.fds[0..r.nfds]) |f| {
            total.fds[total.nfds] = f;
            total.nfds += 1;
        }
        total.len += r.len;
    }
}

test "request encoding with every argument type and fd passing" {
    const sp = try sys.socketPair();
    defer sys.close(sp[1]);
    const conn = try Connection.initFd(testing.allocator, sp[0]);
    defer conn.deinit();

    const mfd = try sys.memfdWithData("t", "keymap!");
    const id = try conn.newIdVersioned(.wl_seat, 7);
    try testing.expectEqual(2, id);
    try conn.request(id, 9, &.{
        .{ .int = -2 },
        .{ .uint = 0xdeadbeef },
        .{ .fixed = Fixed.fromFloat(1.5) },
        .{ .string = "abc" },
        .{ .string = null },
        .{ .object = 5 },
        .{ .new_id = 6 },
        .{ .array = &.{ 1, 2, 3, 4, 5 } },
        .{ .fd = mfd },
    });
    sys.close(mfd); // the connection holds its own duplicate
    try conn.flush();

    var buf: [256]u8 = undefined;
    const got = try readAllFrom(sp[1], &buf);
    defer for (got.fds[0..got.nfds]) |f| sys.close(f);
    const expect = [_]u8{
        2, 0, 0, 0, 9, 0, 52, 0, // header: id 2, opcode 9 | size 52 << 16
        0xfe, 0xff, 0xff, 0xff, // -2
        0xef, 0xbe, 0xad, 0xde,
        0x80, 1,   0,   0, // 1.5 * 256 = 384
        4,    0,   0,   0,
        'a',  'b', 'c', 0,
        0, 0, 0, 0, // null string
        5, 0, 0, 0,
        6, 0, 0, 0,
        5, 0, 0, 0,
        1, 2, 3, 4,
        5, 0, 0, 0,
    };
    try testing.expectEqualSlices(u8, &expect, buf[0..got.len]);
    try testing.expectEqual(1, got.nfds);
    var km: [7]u8 = undefined;
    _ = try sys.pread(got.fds[0], &km, 0);
    try testing.expectEqualStrings("keymap!", &km);
}

test "generated request helpers" {
    const sp = try sys.socketPair();
    defer sys.close(sp[1]);
    const conn = try Connection.initFd(testing.allocator, sp[0]);
    defer conn.deinit();

    const reg = try conn.display().getRegistry(conn);
    try testing.expectEqual(2, reg.id);
    const seat = try reg.bind(conn, 42, proto.WlSeat, 5);
    try testing.expectEqual(3, seat.id);
    try testing.expectEqual(5, conn.version(seat.id));
    const ptr = try seat.getPointer(conn);
    try testing.expectEqual(5, conn.version(ptr.id)); // inherited
    try conn.flush();

    var buf: [256]u8 = undefined;
    const got = try readAllFrom(sp[1], &buf);
    // get_registry: [1, 12<<16|1, 2]
    try testing.expectEqual(1, std.mem.readInt(u32, buf[0..4], .little));
    try testing.expectEqual(12 << 16 | 1, std.mem.readInt(u32, buf[4..8], .little));
    try testing.expectEqual(2, std.mem.readInt(u32, buf[8..12], .little));
    // bind: [2, size<<16|0, name=42, len=8 "wl_seat\0", version 5, new id 3]
    const b = buf[12..];
    try testing.expectEqual(2, std.mem.readInt(u32, b[0..4], .little));
    try testing.expectEqual(32 << 16 | 0, std.mem.readInt(u32, b[4..8], .little));
    try testing.expectEqual(42, std.mem.readInt(u32, b[8..12], .little));
    try testing.expectEqual(8, std.mem.readInt(u32, b[12..16], .little));
    try testing.expectEqualStrings("wl_seat\x00", b[16..24]);
    try testing.expectEqual(5, std.mem.readInt(u32, b[24..28], .little));
    try testing.expectEqual(3, std.mem.readInt(u32, b[28..32], .little));
    try testing.expectEqual(12 + 32 + 12, got.len);
}

fn sendEvent(fd: Fd, id: u32, opcode: u16, args: []const u8, fds: []const Fd) !void {
    var buf: [512]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], id, .little);
    std.mem.writeInt(u32, buf[4..8], @as(u32, @intCast(8 + args.len)) << 16 | opcode, .little);
    @memcpy(buf[8..][0..args.len], args);
    _ = try sys.sendMsg(fd, buf[0 .. 8 + args.len], fds);
}

const Recorder = struct {
    keymap_size: u32 = 0,
    keymap_text: [16]u8 = undefined,
    names: u32 = 0,
    last_name: [32]u8 = undefined,
    last_name_len: usize = 0,

    fn onKeyboard(r: *Recorder, msg: *Message) Error!void {
        switch (try msg.decode(proto.WlKeyboard)) {
            .keymap => |k| {
                defer sys.close(k.fd);
                r.keymap_size = k.size;
                const n = @min(k.size, r.keymap_text.len);
                _ = sys.pread(k.fd, r.keymap_text[0..n], 0) catch return error.ReadFailed;
            },
            else => {},
        }
    }

    fn onSeat(r: *Recorder, msg: *Message) Error!void {
        switch (try msg.decode(proto.WlSeat)) {
            .name => |n| {
                r.names += 1;
                r.last_name_len = @min(n.name.len, r.last_name.len);
                @memcpy(r.last_name[0..r.last_name_len], n.name[0..r.last_name_len]);
            },
            else => {},
        }
    }
};

test "event decoding, fd receipt, delete_id and protocol error" {
    const sp = try sys.socketPair();
    defer sys.close(sp[1]);
    const conn = try Connection.initFd(testing.allocator, sp[0]);
    defer conn.deinit();

    var rec: Recorder = .{};
    const seat = try conn.newIdVersioned(.wl_seat, 7);
    const kbd = try conn.newIdVersioned(.wl_keyboard, 7);
    conn.setHandler(seat, Handler.init(Recorder, &rec, Recorder.onSeat));
    conn.setHandler(kbd, Handler.init(Recorder, &rec, Recorder.onKeyboard));

    // wl_keyboard.keymap(format=1, fd, size=5)
    const mfd = try sys.memfdWithData("t", "xkb!\x00");
    var args: [8]u8 = undefined;
    std.mem.writeInt(u32, args[0..4], 1, .little);
    std.mem.writeInt(u32, args[4..8], 5, .little);
    try sendEvent(sp[1], kbd, 0, &args, &.{mfd});
    sys.close(mfd);
    // wl_seat.name("seat0")
    const name_args = [_]u8{ 6, 0, 0, 0, 's', 'e', 'a', 't', '0', 0, 0, 0 };
    try sendEvent(sp[1], seat, 1, &name_args, &.{});
    try sendEvent(sp[1], 77, 0, &.{}, &.{});

    try testing.expectEqual(3, try conn.dispatchTimeout(1000)); // incl. the dropped one
    try testing.expectEqual(5, rec.keymap_size);
    try testing.expectEqualStrings("xkb!", rec.keymap_text[0..4]);
    try testing.expectEqualStrings("seat0", rec.last_name[0..rec.last_name_len]);
    try testing.expectEqual(0, conn.in_fds.len);

    // Destroyed: zombie events (fds still consumed); delete_id frees the id.
    conn.destroyed(kbd);
    const mfd2 = try sys.memfdWithData("t", "zz");
    try sendEvent(sp[1], kbd, 0, &args, &.{mfd2});
    sys.close(mfd2);
    var del: [4]u8 = undefined;
    std.mem.writeInt(u32, &del, kbd, .little);
    try sendEvent(sp[1], 1, 1, &del, &.{});
    var spins: usize = 0;
    while (conn.in_fds.len != 0 or conn.object(kbd).?.state != .free) : (spins += 1) {
        if (spins > 10) return error.TestTimeout;
        _ = try conn.dispatchTimeout(1000);
    }
    try testing.expectEqual(kbd, try conn.newIdVersioned(.wl_callback, 1));

    // wl_display.error(object=seat, code=3, "bad"); its warning log is expected.
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    const err_args = [_]u8{ @intCast(seat), 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 'b', 'a', 'd', 0 };
    try sendEvent(sp[1], 1, 0, &err_args, &.{});
    try testing.expectError(error.ProtocolError, conn.dispatchTimeout(1000));
    const pe = conn.protocol_error.?;
    try testing.expectEqual(seat, pe.object_id);
    try testing.expectEqual(3, pe.code);
    try testing.expectEqual(Interface.wl_seat, pe.interface.?);
    try testing.expectEqualStrings("bad", pe.message());
}

test "malformed events are rejected, not trusted" {
    const cases = [_]struct { opcode: u16, body: []const u8 }{
        // wl_seat.name with string length beyond the body
        .{ .opcode = 1, .body = &.{ 200, 0, 0, 0, 'a', 0, 0, 0 } },
        // missing NUL terminator
        .{ .opcode = 1, .body = &.{ 2, 0, 0, 0, 'a', 'b', 0, 0 } },
        // non-nullable string encoded as null
        .{ .opcode = 1, .body = &.{ 0, 0, 0, 0 } },
        // truncated uint
        .{ .opcode = 0, .body = &.{ 1, 0 } },
        // trailing garbage
        .{ .opcode = 0, .body = &.{ 1, 0, 0, 0, 9, 9, 9, 9 } },
        // unknown opcode
        .{ .opcode = 9, .body = &.{} },
        // huge length that would overflow pad4 on 32-bit math
        .{ .opcode = 1, .body = &.{ 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 } },
    };
    for (cases) |cs| {
        const sp = try sys.socketPair();
        defer sys.close(sp[1]);
        const conn = try Connection.initFd(testing.allocator, sp[0]);
        defer conn.deinit();
        var rec: Recorder = .{};
        const seat = try conn.newIdVersioned(.wl_seat, 7);
        conn.setHandler(seat, Handler.init(Recorder, &rec, Recorder.onSeat));
        try sendEvent(sp[1], seat, cs.opcode, cs.body, &.{});
        if (conn.dispatchTimeout(1000)) |_| {
            return error.TestUnexpectedSuccess;
        } else |err| switch (err) {
            error.InvalidMessage, error.InvalidOpcode => {},
            else => return err,
        }
        try testing.expect(conn.broken);
        try testing.expectEqual(0, rec.names);
    }
}

const FuzzSink = struct {
    events: usize = 0,

    fn on(s: *FuzzSink, msg: *Message) Error!void {
        // Close fds the decoder took (it hands ownership to the caller).
        var saved: [max_event_fds]Fd = undefined;
        @memcpy(saved[0..msg.fds.len], msg.fds);
        defer for (msg.fds, 0..) |f, k| {
            if (f == -1 and saved[k] >= 0) sys.close(saved[k]);
        };
        switch (msg.interface) {
            inline else => |i| {
                const ev = msg.decode(proto.InterfaceType(i)) catch return;
                std.mem.doNotOptimizeAway(&ev);
                s.events += 1;
            },
        }
    }
};

fn injectForTest(conn: *Connection, bytes: []const u8) void {
    const n = @min(bytes.len, conn.in.len - conn.in_end);
    @memcpy(conn.in[conn.in_end..][0..n], bytes[0..n]);
    conn.in_end += n;
}

test "fuzz: random input never crashes dispatch or the decoders" {
    var prng: std.Random.DefaultPrng = .init(0x5eed_1234);
    const rand = prng.random();
    const ifaces = std.meta.tags(Interface);
    var sink: FuzzSink = .{};
    var buf: [2048]u8 = undefined;
    var iter: usize = 0;
    while (iter < 3000) : (iter += 1) {
        const conn = try Connection.initFd(testing.allocator, -1);
        conn.owns_fd = false;
        defer conn.deinit();
        for (0..8) |_| {
            const id = try conn.newIdVersioned(ifaces[rand.uintLessThan(usize, ifaces.len)], 9);
            conn.setHandler(id, Handler.init(FuzzSink, &sink, FuzzSink.on));
        }
        for (0..rand.uintLessThan(usize, 3)) |_| {
            const f = try sys.memfdWithData("f", "x");
            _ = conn.in_fds.push(f);
        }
        var len: usize = 0;
        while (len + 64 < buf.len) {
            if (rand.uintLessThan(u8, 8) == 0) {
                const n = rand.uintLessThan(usize, 32);
                rand.bytes(buf[len..][0..n]);
                len += n;
                continue;
            }
            const body_len = rand.uintLessThan(usize, 13) * 4;
            const id: u32 = if (rand.boolean()) rand.uintLessThan(u32, 11) else rand.int(u32);
            const opcode: u16 = rand.uintLessThan(u16, 12);
            std.mem.writeInt(u32, buf[len..][0..4], id, .little);
            std.mem.writeInt(u32, buf[len + 4 ..][0..4], @as(u32, @intCast(8 + body_len)) << 16 | opcode, .little);
            const body = buf[len + 8 ..][0..body_len];
            rand.bytes(body);
            if (body_len >= 4 and rand.boolean())
                std.mem.writeInt(u32, body[0..4], rand.uintLessThan(u32, 16), .little);
            len += 8 + body_len;
        }
        injectForTest(conn, buf[0..len]);
        _ = conn.dispatchPending() catch {};
    }
    try testing.expect(sink.events > 0);

    inline for (comptime std.meta.tags(Interface)) |i| {
        const T = proto.InterfaceType(i);
        for (0..T.event_signatures.len) |op| {
            for (0..50) |_| {
                const n = rand.uintLessThan(usize, 40);
                rand.bytes(buf[0..n]);
                if (n >= 4 and rand.boolean()) std.mem.writeInt(u32, buf[0..4], rand.uintLessThan(u32, 12), .little);
                var fds = [_]Fd{ -1, -1 };
                var r: ArgReader = .{ .body = buf[0..n], .fds = &fds };
                const ev = T.decodeEvent(@intCast(op), &r) catch continue;
                std.mem.doNotOptimizeAway(&ev);
            }
        }
    }
}
