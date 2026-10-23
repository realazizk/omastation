//! The client's copied files as a lazily served read-only FUSE tree (MS-RDPECLIP 3.1.5.4.5): each
//! File List is a generation directory whose contents are fetched in FILECONTENTS_RANGE chunks on read.
//! Inode numbers are never reused, so forgets need no bookkeeping.

const std = @import("std");
const cliprdr = @import("../channel/cliprdr.zig");
const fs = @import("../drives/fs.zig");

const log = std.log.scoped(.clipboard);
const Allocator = std.mem.Allocator;
const E = std.os.linux.E;

pub const Options = struct {
    /// Owner of every file (the session user).
    uid: u32 = 0,
    gid: u32 = 0,
    /// cbRequested of the RANGE requests, and the unit of the cache.
    chunk_len: u32 = 1 << 20,
    /// File contents kept for all generations together.
    max_cache_bytes: u64 = 256 << 20,
    max_inflight: u32 = 2,
    /// Kernel cache seconds for a generation's entries (never change) and the root's (come and go).
    entry_timeout: f64 = 60,
    root_timeout: f64 = 1,
    /// An unanswered request fails its reads after this (`progress` extends it).
    request_timeout_ms: u32 = 30_000,
    /// Monotonic milliseconds.
    now_ms: *const fn () u64,
    /// Wall clock (ns since the Unix epoch), for entries the list gives no time.
    clock: *const fn () i128 = fs.realtimeNs,
};

/// A File Contents Request to send (the bridge assigned `stream_id`).
pub const Request = cliprdr.FileContentsRequest;

const Kind = enum { dir, file };

/// A piece of a file: [index * chunk_len, + len), filled from the start.
const Chunk = struct {
    /// Allocated when first requested (len bytes).
    data: []u8 = &.{},
    len: usize,
    filled: usize = 0,
    /// A request for the rest is outstanding.
    busy: bool = false,
    wanted: bool = false,

    fn complete(ch: *const Chunk) bool {
        return ch.filled == ch.len;
    }
};

const Node = struct {
    ino: u64,
    parent: u64,
    gen: *Gen,
    name: []u8,
    kind: Kind,
    /// Index in the File List; null for implied directories and the generation's own.
    lindex: ?u32,
    attributes: u32 = 0,
    /// Null until known (no FD_FILESIZE).
    size: ?u64 = null,
    /// The size came from FILECONTENTS_SIZE: the kernel may have cached 0.
    size_fetched: bool = false,
    mtime: fs.Time,
    /// Directories: entries in list order.
    children: std.ArrayList(u64) = .empty,
    chunks: std.AutoHashMapUnmanaged(u64, *Chunk) = .empty,
};

pub const Gen = struct {
    id: u64,
    name: []u8,
    ino: u64,
    /// The lock on the client's data (3.1.5.3.2), if any.
    clip_id: ?u32,
    entries: usize,
    /// The client's clipboard was replaced.
    stale: bool = false,
    open: u32 = 0,
    nodes: std.ArrayList(u64) = .empty,
    requests: u64 = 0,
    fetched: u64 = 0,
};

const Handle = struct { ino: u64, gen: ?*Gen, dir: bool };

/// A read waiting for its chunks; answered from them once they cover it.
const Read = struct {
    req: fs.Req,
    ino: u64,
    off: u64,
    len: usize,
};

const OpenWait = struct { req: fs.Req, ino: u64 };

const Want = struct { ino: u64, what: What };

const What = union(enum) { size, chunk: u64 };

const Inflight = struct {
    stream: u32,
    ino: u64,
    what: What,
    /// RANGE: where the answer goes in the chunk.
    position: u64 = 0,
    cb: u32,
    deadline: u64,
};

const ChunkRef = struct { ino: u64, index: u64 };

const NameKey = struct { parent: u64, name: []const u8 };

const NameCtx = struct {
    pub fn hash(_: NameCtx, k: NameKey) u64 {
        var h = std.hash.Wyhash.init(k.parent);
        h.update(k.name);
        return h.final();
    }
    pub fn eql(_: NameCtx, a: NameKey, b: NameKey) bool {
        return a.parent == b.parent and std.mem.eql(u8, a.name, b.name);
    }
};

pub const Error = error{
    OutOfMemory,
    /// A name that is not a valid relative path, or longer than a Linux name.
    InvalidFileName,
    /// Two entries with the same path, or an entry inside a file.
    DuplicateName,
    InvalidFileList,
};

fn errno(e: E) u16 {
    return fs.errno(e);
}

pub const ClipFs = struct {
    gpa: Allocator,
    opts: Options,
    replier: ?fs.Replier = null,
    /// The session is remote and unlocked: reads are served.
    active: bool = true,
    /// abort: everything fails with EIO.
    dead: bool = false,
    nodes: std.AutoHashMapUnmanaged(u64, *Node) = .empty,
    names: std.HashMapUnmanaged(NameKey, u64, NameCtx, 80) = .empty,
    gens: std.ArrayList(*Gen) = .empty,
    /// The generation directories, oldest first.
    root_children: std.ArrayList(u64) = .empty,
    next_ino: u64 = fs.root_ino + 1,
    /// Never reused: an older listing of the same name may still be open.
    next_dir: u64 = 1,
    handles: std.AutoHashMapUnmanaged(u64, Handle) = .empty,
    next_fh: u64 = 1,
    reads: std.ArrayList(Read) = .empty,
    open_waits: std.ArrayList(OpenWait) = .empty,
    wants: std.ArrayList(Want) = .empty,
    inflight: std.ArrayList(Inflight) = .empty,
    /// Complete chunks, oldest first (refs may be stale).
    fifo: std.ArrayList(ChunkRef) = .empty,
    fifo_head: usize = 0,
    cache_bytes: u64 = 0,
    /// Locks of removed generations, for the bridge to release.
    unlocks: std.ArrayList(u32) = .empty,
    /// streamIds given up (timeout, generation gone), for the bridge to cancel.
    cancels: std.ArrayList(u32) = .empty,
    born: fs.Time,
    fetched_bytes: u64 = 0,
    requests: u64 = 0,

    pub fn init(gpa: Allocator, opts: Options) ClipFs {
        return .{ .gpa = gpa, .opts = opts, .born = timeFromNs(opts.clock()) };
    }

    pub fn deinit(c: *ClipFs) void {
        c.abort();
        const gpa = c.gpa;
        c.nodes.deinit(gpa);
        c.names.deinit(gpa);
        c.gens.deinit(gpa);
        c.root_children.deinit(gpa);
        c.handles.deinit(gpa);
        c.reads.deinit(gpa);
        c.open_waits.deinit(gpa);
        c.wants.deinit(gpa);
        c.inflight.deinit(gpa);
        c.fifo.deinit(gpa);
        c.unlocks.deinit(gpa);
        c.cancels.deinit(gpa);
    }

    pub fn handler(c: *ClipFs) fs.Handler {
        return .{ .ptr = c, .vtable = &handler_vtable };
    }

    const handler_vtable: fs.Handler.VTable = .{
        .handle = hHandle,
        .forget = hForget,
        .interrupt = hInterrupt,
        .set_replier = hSetReplier,
    };

    fn hHandle(ptr: *anyopaque, req: fs.Req, r: fs.Request) void {
        const c: *ClipFs = @ptrCast(@alignCast(ptr));
        c.handle(req, r);
    }

    fn hForget(_: *anyopaque, _: u64, _: u64) void {}

    fn hInterrupt(ptr: *anyopaque, req: fs.Req) void {
        const c: *ClipFs = @ptrCast(@alignCast(ptr));
        c.interrupt(req);
    }

    fn hSetReplier(ptr: *anyopaque, r: ?fs.Replier) void {
        const c: *ClipFs = @ptrCast(@alignCast(ptr));
        c.replier = r;
    }

    /// All or nothing, in the directory `nextDirName` gave; `files` stays the caller's.
    pub fn addGeneration(c: *ClipFs, id: u64, files: []const cliprdr.FileDescriptor, clip_id: ?u32) Error!*Gen {
        if (files.len == 0 or c.dead) return error.InvalidFileList;
        const gpa = c.gpa;
        const g = try gpa.create(Gen);
        errdefer gpa.destroy(g);
        const name = try std.fmt.allocPrint(gpa, "{d}", .{c.next_dir});
        errdefer gpa.free(name);
        g.* = .{ .id = id, .name = name, .ino = 0, .clip_id = clip_id, .entries = files.len };
        errdefer c.dropNodes(g);
        try c.gens.ensureUnusedCapacity(gpa, 1);
        try c.root_children.ensureUnusedCapacity(gpa, 1);
        // Reserve every unlock now so removing a generation never fails and no lock stays held.
        if (clip_id != null) try c.unlocks.ensureUnusedCapacity(gpa, c.lockedGens() + 1);
        const now = timeFromNs(c.opts.clock());
        const dir = try c.newNode(g, fs.root_ino, name, .dir, null);
        dir.mtime = now;
        g.ino = dir.ino;
        for (files, 0..) |f, i| try c.addEntry(g, f, @intCast(i), now);
        c.gens.appendAssumeCapacity(g);
        c.root_children.appendAssumeCapacity(g.ino);
        c.next_dir += 1;
        return g;
    }

    pub fn nextDirName(c: *const ClipFs, buf: *[24]u8) []const u8 {
        return std.fmt.bufPrint(buf, "{d}", .{c.next_dir}) catch unreachable;
    }

    pub fn generation(c: *const ClipFs, id: u64) ?*Gen {
        for (c.gens.items) |g| if (g.id == id) return g;
        return null;
    }

    /// Unlocked generations fail now: a read by lindex would hit the new clipboard.
    pub fn retireAll(c: *ClipFs) void {
        var i: usize = c.gens.items.len;
        while (i > 0) {
            i -= 1;
            if (i >= c.gens.items.len) continue;
            const g = c.gens.items[i];
            if (g.stale) continue;
            g.stale = true;
            if (g.clip_id == null) c.failGen(g);
            if (g.open == 0) c.removeGen(g);
        }
    }

    /// Turning it off fails everything waiting with EIO.
    pub fn setActive(c: *ClipFs, on: bool) void {
        c.active = on;
        if (on) return;
        for (c.gens.items) |g| c.failGen(g);
    }

    /// Unmount or end of connection: everything fails with EIO; locks go to `takeUnlock`.
    pub fn abort(c: *ClipFs) void {
        c.dead = true;
        for (c.gens.items) |g| c.failGen(g);
        while (c.gens.items.len > 0) c.removeGen(c.gens.items[c.gens.items.len - 1]);
        c.handles.clearRetainingCapacity();
        c.wants.clearRetainingCapacity();
    }

    /// Null when nothing is wanted or `max_inflight` are outstanding; on OutOfMemory its reads failed.
    pub fn nextRequest(c: *ClipFs, stream_id: u32) Allocator.Error!?Request {
        if (c.dead or c.inflight.items.len >= c.opts.max_inflight) return null;
        try c.inflight.ensureUnusedCapacity(c.gpa, 1);
        // Room to give up every request in flight without allocating.
        try c.cancels.ensureUnusedCapacity(c.gpa, c.inflight.items.len + 1);
        while (c.wants.items.len > 0) {
            const w = c.wants.orderedRemove(0);
            const n = c.nodes.get(w.ino) orelse continue;
            if (!c.servable(n.gen)) continue;
            const deadline = c.opts.now_ms() + c.opts.request_timeout_ms;
            switch (w.what) {
                .size => {
                    if (n.size != null or !c.waitingOpen(n.ino)) continue;
                    c.inflight.appendAssumeCapacity(.{ .stream = stream_id, .ino = n.ino, .what = .size, .cb = 8, .deadline = deadline });
                    c.requests += 1;
                    n.gen.requests += 1;
                    return .{
                        .stream_id = stream_id,
                        .lindex = @intCast(n.lindex.?),
                        .flags = cliprdr.FILECONTENTS_SIZE,
                        .cb_requested = 8,
                        .clip_data_id = n.gen.clip_id,
                    };
                },
                .chunk => |idx| {
                    const ch = n.chunks.get(idx) orelse continue;
                    ch.wanted = false;
                    if (ch.busy or ch.complete()) continue;
                    if (!c.chunkNeeded(n, idx)) {
                        c.dropChunk(n, idx);
                        continue;
                    }
                    if (ch.data.len == 0) {
                        ch.data = c.gpa.alloc(u8, ch.len) catch |err| {
                            c.failChunkReads(n, idx, errno(.NOMEM));
                            c.dropChunk(n, idx);
                            return err;
                        };
                        c.cache_bytes += ch.len;
                        c.evict();
                    }
                    ch.busy = true;
                    const position = idx * c.opts.chunk_len + ch.filled;
                    const cb: u32 = @intCast(ch.len - ch.filled);
                    c.inflight.appendAssumeCapacity(.{ .stream = stream_id, .ino = n.ino, .what = w.what, .position = position, .cb = cb, .deadline = deadline });
                    c.requests += 1;
                    n.gen.requests += 1;
                    return .{
                        .stream_id = stream_id,
                        .lindex = @intCast(n.lindex.?),
                        .flags = cliprdr.FILECONTENTS_RANGE,
                        .position = position,
                        .cb_requested = cb,
                        .clip_data_id = n.gen.clip_id,
                    };
                },
            }
        }
        return null;
    }

    /// The request `stream_id` could not be sent: its reads fail.
    pub fn requestFailed(c: *ClipFs, stream_id: u32) void {
        const i = c.inflightIndex(stream_id) orelse return;
        const inf = c.inflight.orderedRemove(i);
        c.failInflight(inf, errno(.IO));
    }

    /// A File Contents Response (3.1.5.4.8); false when not ours.
    /// On error.OutOfMemory the reads that needed more have failed (ENOMEM).
    pub fn onResponse(c: *ClipFs, r: cliprdr.FileContentsResponse) Allocator.Error!bool {
        const i = c.inflightIndex(r.stream_id) orelse return false;
        const inf = c.inflight.orderedRemove(i);
        const n = c.nodes.get(inf.ino) orelse return true;
        switch (inf.what) {
            .size => {
                const size = if (r.ok) cliprdr.fileSizeFromResponse(r) catch null else null;
                if (size) |s| {
                    n.size = s;
                    n.size_fetched = true;
                    c.finishOpens(n);
                } else {
                    log.warn("the client did not give the size of a copied file", .{});
                    c.failOpens(n.ino, errno(.IO));
                }
            },
            .chunk => |idx| {
                const ch = n.chunks.get(idx) orelse return true;
                ch.busy = false;
                const room = ch.len - ch.filled;
                if (!r.ok or r.data.len == 0 or r.data.len > room) {
                    // A failure, or an answer that would loop or overflow.
                    if (r.ok) log.warn("file contents: {d} bytes for a request of {d}", .{ r.data.len, room }) else log.warn("the client failed a File Contents Request", .{});
                    c.failChunkReads(n, idx, errno(.IO));
                    c.dropChunk(n, idx);
                    return true;
                }
                @memcpy(ch.data[ch.filled..][0..r.data.len], r.data);
                ch.filled += r.data.len;
                c.fetched_bytes += r.data.len;
                n.gen.fetched += r.data.len;
                c.deliver(n);
                if (ch.complete()) {
                    try c.fifo.append(c.gpa, .{ .ino = n.ino, .index = idx });
                    c.evict();
                } else if (c.chunkNeeded(n, idx)) {
                    // A short answer: the rest next.
                    c.want(n.ino, .{ .chunk = idx }, true) catch |err| {
                        c.failChunkReads(n, idx, errno(.NOMEM));
                        c.dropChunk(n, idx);
                        return err;
                    };
                } else c.dropChunk(n, idx);
            },
        }
        return true;
    }

    /// Part of a response arrived: outstanding requests get `request_timeout_ms` more.
    pub fn progress(c: *ClipFs) void {
        const d = c.opts.now_ms() + c.opts.request_timeout_ms;
        for (c.inflight.items) |*inf| inf.deadline = d;
    }

    /// Fails requests not answered in time; their streamIds go to `takeCancel`.
    pub fn checkTimeouts(c: *ClipFs) void {
        const now = c.opts.now_ms();
        var i: usize = 0;
        while (i < c.inflight.items.len) {
            const inf = c.inflight.items[i];
            if (now < inf.deadline) {
                i += 1;
                continue;
            }
            _ = c.inflight.orderedRemove(i);
            log.warn("the client did not answer a File Contents Request", .{});
            c.cancels.appendAssumeCapacity(inf.stream);
            c.failInflight(inf, errno(.IO));
        }
    }

    pub fn nextDeadline(c: *const ClipFs) ?u64 {
        var d: ?u64 = null;
        for (c.inflight.items) |inf| d = if (d) |x| @min(x, inf.deadline) else inf.deadline;
        return d;
    }

    pub fn takeUnlock(c: *ClipFs) ?u32 {
        if (c.unlocks.items.len == 0) return null;
        return c.unlocks.orderedRemove(0);
    }

    pub fn takeCancel(c: *ClipFs) ?u32 {
        if (c.cancels.items.len == 0) return null;
        return c.cancels.orderedRemove(0);
    }

    pub fn hasWants(c: *const ClipFs) bool {
        return c.wants.items.len > 0 and c.inflight.items.len < c.opts.max_inflight;
    }

    pub fn openCount(c: *const ClipFs) usize {
        return c.handles.count();
    }

    pub fn pendingReads(c: *const ClipFs) usize {
        return c.reads.items.len;
    }

    pub fn outstanding(c: *const ClipFs) usize {
        return c.inflight.items.len;
    }

    pub fn handle(c: *ClipFs, req: fs.Req, r: fs.Request) void {
        if (c.dead) return c.replyErr(req, errno(.IO));
        switch (r) {
            .lookup => |a| c.lookup(req, a.parent, a.name),
            .getattr => |a| c.getattr(req, a.ino),
            .open => |a| c.open(req, a.ino, a.flags),
            .read => |a| c.read(req, a.fh, a.size, a.offset),
            .release => |a| c.release(req, a.fh),
            .opendir => |a| c.opendir(req, a.ino),
            .readdir => |a| c.readdir(req, a.fh, a.size, a.offset, a.plus),
            .releasedir => |a| c.release(req, a.fh),
            .flush, .fsync, .fsyncdir => c.replyErr(req, 0),
            .statfs => c.statfs(req),
            .setattr, .create, .write, .mkdir, .unlink, .rmdir, .rename => c.replyErr(req, errno(.ROFS)),
        }
    }

    /// FUSE_INTERRUPT: a read or open still waiting gets EINTR.
    pub fn interrupt(c: *ClipFs, req: fs.Req) void {
        for (c.reads.items, 0..) |rd, i| if (rd.req == req) {
            _ = c.reads.orderedRemove(i);
            c.replyErr(req, errno(.INTR));
            return;
        };
        for (c.open_waits.items, 0..) |w, i| if (w.req == req) {
            _ = c.open_waits.orderedRemove(i);
            c.replyErr(req, errno(.INTR));
            return;
        };
    }

    fn lookup(c: *ClipFs, req: fs.Req, parent: u64, name: []const u8) void {
        const ino = c.names.get(.{ .parent = parent, .name = name }) orelse return c.replyErr(req, errno(.NOENT));
        const n = c.nodes.get(ino).?;
        const e = c.entryOf(n);
        if (c.replier) |rp| rp.vtable.entry(rp.ptr, req, &e);
    }

    fn getattr(c: *ClipFs, req: fs.Req, ino: u64) void {
        if (ino == fs.root_ino) {
            const a = c.rootAttr();
            if (c.replier) |rp| rp.vtable.attr(rp.ptr, req, &a, c.opts.root_timeout);
            return;
        }
        const n = c.nodes.get(ino) orelse return c.replyErr(req, errno(.NOENT));
        const a = c.attrOf(n);
        if (c.replier) |rp| rp.vtable.attr(rp.ptr, req, &a, c.timeoutOf(n));
    }

    fn open(c: *ClipFs, req: fs.Req, ino: u64, flags: u32) void {
        const n = c.nodes.get(ino) orelse return c.replyErr(req, errno(.NOENT));
        if (n.kind != .file) return c.replyErr(req, errno(.ISDIR));
        if (flags & fs.o.accmode != fs.o.rdonly or flags & fs.o.trunc != 0) return c.replyErr(req, errno(.ROFS));
        if (!c.servable(n.gen)) return c.replyErr(req, errno(.IO));
        if (n.size == null) {
            c.open_waits.append(c.gpa, .{ .req = req, .ino = ino }) catch return c.replyErr(req, errno(.NOMEM));
            c.want(ino, .size, false) catch {
                _ = c.open_waits.pop();
                return c.replyErr(req, errno(.NOMEM));
            };
            return;
        }
        c.finishOpen(req, n);
    }

    fn finishOpen(c: *ClipFs, req: fs.Req, n: *Node) void {
        const fh = c.next_fh;
        c.handles.put(c.gpa, fh, .{ .ino = n.ino, .gen = n.gen, .dir = false }) catch return c.replyErr(req, errno(.NOMEM));
        c.next_fh += 1;
        n.gen.open += 1;
        // A size learnt late may be cached as 0 by the kernel, so such files use direct I/O.
        const f: fs.FileReply = .{ .fh = fh, .keep_cache = !n.size_fetched, .direct_io = n.size_fetched };
        if (c.replier) |rp| rp.vtable.open(rp.ptr, req, f);
    }

    fn finishOpens(c: *ClipFs, n: *Node) void {
        var i: usize = 0;
        while (i < c.open_waits.items.len) {
            const w = c.open_waits.items[i];
            if (w.ino != n.ino) {
                i += 1;
                continue;
            }
            _ = c.open_waits.orderedRemove(i);
            c.finishOpen(w.req, n);
        }
    }

    fn failOpens(c: *ClipFs, ino: u64, err: u16) void {
        var i: usize = 0;
        while (i < c.open_waits.items.len) {
            const w = c.open_waits.items[i];
            if (w.ino != ino) {
                i += 1;
                continue;
            }
            _ = c.open_waits.orderedRemove(i);
            c.replyErr(w.req, err);
        }
    }

    fn waitingOpen(c: *const ClipFs, ino: u64) bool {
        for (c.open_waits.items) |w| if (w.ino == ino) return true;
        return false;
    }

    fn read(c: *ClipFs, req: fs.Req, fh: u64, size: usize, offset: i64) void {
        const h = c.handles.get(fh) orelse return c.replyErr(req, errno(.BADF));
        if (h.dir) return c.replyErr(req, errno(.ISDIR));
        const n = c.nodes.get(h.ino) orelse return c.replyErr(req, errno(.IO));
        if (!c.servable(n.gen)) return c.replyErr(req, errno(.IO));
        if (offset < 0) return c.replyErr(req, errno(.INVAL));
        const file_size = n.size orelse return c.replyErr(req, errno(.IO));
        const off: u64 = @intCast(offset);
        if (off >= file_size or size == 0) return c.replyData(req, &.{});
        const rd: Read = .{ .req = req, .ino = n.ino, .off = off, .len = @intCast(@min(@as(u64, size), file_size - off)) };
        const cl: u64 = c.opts.chunk_len;
        var idx = off / cl;
        const last = (off + rd.len - 1) / cl;
        while (idx <= last) : (idx += 1) {
            const ch = n.chunks.get(idx) orelse blk: {
                const ch = c.gpa.create(Chunk) catch return c.replyErr(req, errno(.NOMEM));
                ch.* = .{ .len = @intCast(@min(cl, file_size - idx * cl)) };
                n.chunks.put(c.gpa, idx, ch) catch {
                    c.gpa.destroy(ch);
                    return c.replyErr(req, errno(.NOMEM));
                };
                break :blk ch;
            };
            if (covers(rd, idx * cl, ch)) continue;
            if (!ch.busy and !ch.wanted) c.want(n.ino, .{ .chunk = idx }, false) catch return c.replyErr(req, errno(.NOMEM));
        }
        if (c.ready(n, rd)) return c.answer(n, rd);
        c.reads.append(c.gpa, rd) catch return c.replyErr(req, errno(.NOMEM));
    }

    /// The chunk at `start` holds all `rd` wants of it.
    fn covers(rd: Read, start: u64, ch: *const Chunk) bool {
        return @min(rd.off + rd.len, start + ch.len) <= start + ch.filled;
    }

    fn ready(c: *const ClipFs, n: *const Node, rd: Read) bool {
        const cl: u64 = c.opts.chunk_len;
        var idx = rd.off / cl;
        const last = (rd.off + rd.len - 1) / cl;
        while (idx <= last) : (idx += 1) {
            const ch = n.chunks.get(idx) orelse return false;
            if (!covers(rd, idx * cl, ch)) return false;
        }
        return true;
    }

    fn answer(c: *ClipFs, n: *const Node, rd: Read) void {
        const buf = c.gpa.alloc(u8, rd.len) catch return c.replyErr(rd.req, errno(.NOMEM));
        defer c.gpa.free(buf);
        const cl: u64 = c.opts.chunk_len;
        var idx = rd.off / cl;
        const last = (rd.off + rd.len - 1) / cl;
        while (idx <= last) : (idx += 1) {
            const ch = n.chunks.get(idx).?;
            const start = idx * cl;
            const lo = @max(rd.off, start);
            const hi = @min(rd.off + rd.len, start + ch.filled);
            @memcpy(buf[@intCast(lo - rd.off)..@intCast(hi - rd.off)], ch.data[@intCast(lo - start)..@intCast(hi - start)]);
        }
        c.replyData(rd.req, buf);
    }

    fn deliver(c: *ClipFs, n: *Node) void {
        var i: usize = 0;
        while (i < c.reads.items.len) {
            const rd = c.reads.items[i];
            if (rd.ino != n.ino or !c.ready(n, rd)) {
                i += 1;
                continue;
            }
            _ = c.reads.orderedRemove(i);
            c.answer(n, rd);
        }
    }

    fn release(c: *ClipFs, req: fs.Req, fh: u64) void {
        if (c.handles.fetchRemove(fh)) |kv| if (kv.value.gen) |g| {
            g.open -= 1;
            if (g.stale and g.open == 0) c.removeGen(g);
        };
        c.replyErr(req, 0);
    }

    fn opendir(c: *ClipFs, req: fs.Req, ino: u64) void {
        var gen: ?*Gen = null;
        if (ino != fs.root_ino) {
            const n = c.nodes.get(ino) orelse return c.replyErr(req, errno(.NOENT));
            if (n.kind != .dir) return c.replyErr(req, errno(.NOTDIR));
            gen = n.gen;
        }
        const fh = c.next_fh;
        c.handles.put(c.gpa, fh, .{ .ino = ino, .gen = gen, .dir = true }) catch return c.replyErr(req, errno(.NOMEM));
        c.next_fh += 1;
        if (gen) |g| g.open += 1;
        if (c.replier) |rp| rp.vtable.open(rp.ptr, req, .{ .fh = fh });
    }

    fn readdir(c: *ClipFs, req: fs.Req, fh: u64, size: usize, offset: i64, plus: bool) void {
        const h = c.handles.get(fh) orelse return c.replyErr(req, errno(.BADF));
        if (!h.dir) return c.replyErr(req, errno(.NOTDIR));
        if (offset < 0) return c.replyErr(req, errno(.INVAL));
        var children: []const u64 = c.root_children.items;
        var parent: u64 = fs.root_ino;
        if (h.ino != fs.root_ino) {
            const d = c.nodes.get(h.ino) orelse return c.replyErr(req, errno(.NOENT));
            children = d.children.items;
            parent = d.parent;
        }
        // ".", "..", then the entries in list order; `off` is the next one's.
        var out: std.ArrayList(fs.DirEntry) = .empty;
        defer out.deinit(c.gpa);
        var used: usize = 0;
        var i: u64 = @intCast(offset);
        while (i < children.len + 2) : (i += 1) {
            var e: fs.Entry = .{ .ino = 0 };
            var name: []const u8 = undefined;
            if (i < 2) {
                name = if (i == 0) "." else "..";
                e.attr = .{ .ino = if (i == 0) h.ino else parent, .mode = std.posix.S.IFDIR | 0o755 };
            } else {
                const n = c.nodes.get(children[@intCast(i - 2)]) orelse continue;
                name = n.name;
                if (plus) e = c.entryOf(n) else e.attr = c.attrOf(n);
            }
            const sz = fs.direntSize(plus, name.len);
            if (used + sz > size) break;
            out.append(c.gpa, .{ .name = name, .off = i + 1, .entry = e }) catch break;
            used += sz;
        }
        if (c.replier) |rp| rp.vtable.dir(rp.ptr, req, plus, size, out.items);
    }

    fn statfs(c: *ClipFs, req: fs.Req) void {
        var bytes: u64 = 0;
        var it = c.nodes.valueIterator();
        while (it.next()) |n| bytes +|= n.*.size orelse 0;
        const bsize: u64 = 4096;
        const s: fs.StatFs = .{
            .bsize = bsize,
            .frsize = bsize,
            .blocks = std.math.divCeil(u64, bytes, bsize) catch 0,
            .files = c.nodes.count() + 1,
            .namemax = fs.max_name,
        };
        if (c.replier) |rp| rp.vtable.statfs(rp.ptr, req, &s);
    }

    fn newNode(c: *ClipFs, g: *Gen, parent: u64, name: []const u8, kind: Kind, lindex: ?u32) Error!*Node {
        const gpa = c.gpa;
        if (name.len == 0 or name.len > fs.max_name) return error.InvalidFileName;
        if (c.names.contains(.{ .parent = parent, .name = name })) return error.DuplicateName;
        try g.nodes.ensureUnusedCapacity(gpa, 1);
        try c.nodes.ensureUnusedCapacity(gpa, 1);
        try c.names.ensureUnusedCapacity(gpa, 1);
        if (parent != fs.root_ino) try c.nodes.get(parent).?.children.ensureUnusedCapacity(gpa, 1);
        const n = try gpa.create(Node);
        errdefer gpa.destroy(n);
        const own = try gpa.dupe(u8, name);
        n.* = .{ .ino = c.next_ino, .parent = parent, .gen = g, .name = own, .kind = kind, .lindex = lindex, .mtime = .{} };
        c.next_ino += 1;
        c.nodes.putAssumeCapacity(n.ino, n);
        c.names.putAssumeCapacity(.{ .parent = parent, .name = own }, n.ino);
        g.nodes.appendAssumeCapacity(n.ino);
        if (parent != fs.root_ino) c.nodes.get(parent).?.children.appendAssumeCapacity(n.ino);
        return n;
    }

    /// Parents first (implied when the list has not named them yet), then the entry.
    fn addEntry(c: *ClipFs, g: *Gen, f: cliprdr.FileDescriptor, lindex: u32, now: fs.Time) Error!void {
        const rel = cliprdr.remoteNameToRelativePath(c.gpa, f.name) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidFileName,
        };
        defer c.gpa.free(rel);
        const is_dir = f.flags & cliprdr.FD_ATTRIBUTES != 0 and f.attributes & cliprdr.FILE_ATTRIBUTE_DIRECTORY != 0;
        const mtime = if (f.flags & cliprdr.FD_WRITESTIME != 0 and f.last_write_time != 0) fs.timeOf(f.last_write_time) else now;
        var parent = g.ino;
        var it = std.mem.splitScalar(u8, rel, '/');
        var comp = it.next().?;
        while (it.next()) |next| : (comp = next) {
            if (c.names.get(.{ .parent = parent, .name = comp })) |ino| {
                const p = c.nodes.get(ino).?;
                if (p.kind != .dir) return error.DuplicateName;
                parent = ino;
            } else {
                const d = try c.newNode(g, parent, comp, .dir, null);
                d.mtime = now;
                parent = d.ino;
            }
        }
        if (c.names.get(.{ .parent = parent, .name = comp })) |ino| {
            // A directory made up for an earlier entry, named now.
            const n = c.nodes.get(ino).?;
            if (!is_dir or n.kind != .dir or n.lindex != null) return error.DuplicateName;
            n.lindex = lindex;
            n.attributes = f.attributes;
            n.mtime = mtime;
            return;
        }
        const n = try c.newNode(g, parent, comp, if (is_dir) .dir else .file, lindex);
        n.attributes = if (f.flags & cliprdr.FD_ATTRIBUTES != 0) f.attributes else 0;
        n.mtime = mtime;
        if (!is_dir and f.flags & cliprdr.FD_FILESIZE != 0) n.size = f.size;
        if (is_dir) n.size = 0;
    }

    fn rootAttr(c: *const ClipFs) fs.Attr {
        return .{
            .ino = fs.root_ino,
            .mode = std.posix.S.IFDIR | 0o700,
            .nlink = 2,
            .uid = c.opts.uid,
            .gid = c.opts.gid,
            .atime = c.born,
            .mtime = c.born,
            .ctime = c.born,
        };
    }

    fn attrOf(c: *const ClipFs, n: *const Node) fs.Attr {
        const ro = n.attributes & cliprdr.FILE_ATTRIBUTE_READONLY != 0;
        const mode: u32 = switch (n.kind) {
            // The generation's own directory is private like the root.
            .dir => std.posix.S.IFDIR | @as(u32, if (n.parent == fs.root_ino) 0o700 else 0o755),
            .file => std.posix.S.IFREG | @as(u32, if (ro) 0o444 else 0o644),
        };
        const size: u64 = if (n.kind == .file) n.size orelse 0 else 0;
        return .{
            .ino = n.ino,
            .mode = mode,
            .nlink = if (n.kind == .dir) 2 else 1,
            .uid = c.opts.uid,
            .gid = c.opts.gid,
            .size = size,
            .blocks = std.math.divCeil(u64, size, 512) catch 0,
            .blksize = c.opts.chunk_len,
            .atime = n.mtime,
            .mtime = n.mtime,
            .ctime = n.mtime,
        };
    }

    fn timeoutOf(c: *const ClipFs, n: *const Node) f64 {
        // The root's entries come and go; a size still unknown changes.
        if (n.parent == fs.root_ino or (n.kind == .file and n.size == null)) return c.opts.root_timeout;
        return c.opts.entry_timeout;
    }

    fn entryOf(c: *const ClipFs, n: *const Node) fs.Entry {
        const t = c.timeoutOf(n);
        return .{ .ino = n.ino, .attr = c.attrOf(n), .attr_timeout = t, .entry_timeout = t };
    }

    fn servable(c: *const ClipFs, g: *const Gen) bool {
        return c.active and !c.dead and (!g.stale or g.clip_id != null);
    }

    fn want(c: *ClipFs, ino: u64, what: What, first: bool) Allocator.Error!void {
        for (c.wants.items) |w| if (w.ino == ino and std.meta.eql(w.what, what)) return;
        const w: Want = .{ .ino = ino, .what = what };
        if (first) try c.wants.insert(c.gpa, 0, w) else try c.wants.append(c.gpa, w);
        if (what == .chunk) if (c.nodes.get(ino)) |n| if (n.chunks.get(what.chunk)) |ch| {
            ch.wanted = true;
        };
    }

    fn lockedGens(c: *const ClipFs) usize {
        var n: usize = 0;
        for (c.gens.items) |g| n += @intFromBool(g.clip_id != null);
        return n;
    }

    fn inflightIndex(c: *const ClipFs, stream: u32) ?usize {
        for (c.inflight.items, 0..) |inf, i| if (inf.stream == stream) return i;
        return null;
    }

    fn spans(c: *const ClipFs, rd: Read, ino: u64, idx: u64) bool {
        const cl: u64 = c.opts.chunk_len;
        return rd.ino == ino and rd.off / cl <= idx and idx <= (rd.off + rd.len - 1) / cl;
    }

    fn chunkNeeded(c: *const ClipFs, n: *const Node, idx: u64) bool {
        const ch = n.chunks.get(idx) orelse return false;
        const start = idx * c.opts.chunk_len;
        for (c.reads.items) |rd| {
            if (c.spans(rd, n.ino, idx) and !covers(rd, start, ch)) return true;
        }
        return false;
    }

    /// A waiting read spans chunk `idx` of `n`: its data must stay.
    fn chunkInUse(c: *const ClipFs, n: *const Node, idx: u64) bool {
        for (c.reads.items) |rd| if (c.spans(rd, n.ino, idx)) return true;
        return false;
    }

    fn failChunkReads(c: *ClipFs, n: *const Node, idx: u64, err: u16) void {
        var i: usize = 0;
        while (i < c.reads.items.len) {
            const rd = c.reads.items[i];
            if (!c.spans(rd, n.ino, idx)) {
                i += 1;
                continue;
            }
            _ = c.reads.orderedRemove(i);
            c.replyErr(rd.req, err);
        }
    }

    fn failInflight(c: *ClipFs, inf: Inflight, err: u16) void {
        const n = c.nodes.get(inf.ino) orelse return;
        switch (inf.what) {
            .size => c.failOpens(n.ino, err),
            .chunk => |idx| {
                c.failChunkReads(n, idx, err);
                c.dropChunk(n, idx);
            },
        }
    }

    fn dropChunk(c: *ClipFs, n: *Node, idx: u64) void {
        const kv = n.chunks.fetchRemove(idx) orelse return;
        const ch = kv.value;
        if (ch.data.len > 0) {
            c.cache_bytes -= ch.data.len;
            c.gpa.free(ch.data);
        }
        c.gpa.destroy(ch);
    }

    /// Complete chunks go, oldest first, while over `max_cache_bytes`.
    fn evict(c: *ClipFs) void {
        // Chunks a waiting read needs go to the back; the cache may stay over until it is answered.
        const end = c.fifo.items.len;
        while (c.cache_bytes > c.opts.max_cache_bytes and c.fifo_head < end) {
            const ref = c.fifo.items[c.fifo_head];
            c.fifo_head += 1;
            const n = c.nodes.get(ref.ino) orelse continue;
            const ch = n.chunks.get(ref.index) orelse continue;
            if (!ch.complete()) continue;
            if (c.chunkInUse(n, ref.index)) {
                c.fifo.append(c.gpa, ref) catch {};
                continue;
            }
            c.dropChunk(n, ref.index);
        }
        if (c.fifo_head > 64 and c.fifo_head * 2 > c.fifo.items.len) {
            const rest = c.fifo.items.len - c.fifo_head;
            std.mem.copyForwards(ChunkRef, c.fifo.items[0..rest], c.fifo.items[c.fifo_head..]);
            c.fifo.shrinkRetainingCapacity(rest);
            c.fifo_head = 0;
        }
    }

    /// Fails everything of `g` waiting with EIO; its requests in flight go to `takeCancel`.
    fn failGen(c: *ClipFs, g: *Gen) void {
        var i: usize = 0;
        while (i < c.inflight.items.len) {
            const inf = c.inflight.items[i];
            const n = c.nodes.get(inf.ino) orelse {
                i += 1;
                continue;
            };
            if (n.gen != g) {
                i += 1;
                continue;
            }
            _ = c.inflight.orderedRemove(i);
            c.cancels.appendAssumeCapacity(inf.stream);
            c.failInflight(inf, errno(.IO));
        }
        i = 0;
        while (i < c.reads.items.len) {
            const rd = c.reads.items[i];
            const n = c.nodes.get(rd.ino);
            if (n == null or n.?.gen != g) {
                i += 1;
                continue;
            }
            _ = c.reads.orderedRemove(i);
            c.replyErr(rd.req, errno(.IO));
        }
        i = 0;
        while (i < c.open_waits.items.len) {
            const w = c.open_waits.items[i];
            const n = c.nodes.get(w.ino);
            if (n == null or n.?.gen != g) {
                i += 1;
                continue;
            }
            _ = c.open_waits.orderedRemove(i);
            c.replyErr(w.req, errno(.IO));
        }
    }

    /// Takes `g` out of the tree (its lock to `takeUnlock`).
    fn removeGen(c: *ClipFs, g: *Gen) void {
        log.info("client copy {d} removed: {d} entries, {d} bytes fetched in {d} File Contents Requests", .{ g.id, g.entries, g.fetched, g.requests });
        c.failGen(g);
        if (std.mem.indexOfScalar(*Gen, c.gens.items, g)) |i| _ = c.gens.orderedRemove(i);
        if (std.mem.indexOfScalar(u64, c.root_children.items, g.ino)) |i| _ = c.root_children.orderedRemove(i);
        if (g.clip_id) |id| c.unlocks.appendAssumeCapacity(id);
        var it = c.handles.iterator();
        while (it.next()) |kv| if (kv.value_ptr.gen == g) {
            kv.value_ptr.gen = null;
        };
        c.dropNodes(g);
        c.gpa.free(g.name);
        c.gpa.destroy(g);
    }

    fn dropNodes(c: *ClipFs, g: *Gen) void {
        for (g.nodes.items) |ino| {
            const kv = c.nodes.fetchRemove(ino) orelse continue;
            const n = kv.value;
            _ = c.names.remove(.{ .parent = n.parent, .name = n.name });
            var cit = n.chunks.iterator();
            while (cit.next()) |ck| {
                const ch = ck.value_ptr.*;
                if (ch.data.len > 0) {
                    c.cache_bytes -= ch.data.len;
                    c.gpa.free(ch.data);
                }
                c.gpa.destroy(ch);
            }
            n.chunks.deinit(c.gpa);
            n.children.deinit(c.gpa);
            c.gpa.free(n.name);
            c.gpa.destroy(n);
        }
        g.nodes.deinit(c.gpa);
        g.nodes = .empty;
    }

    fn replyErr(c: *ClipFs, req: fs.Req, err: u16) void {
        if (c.replier) |rp| rp.vtable.err(rp.ptr, req, err);
    }

    fn replyData(c: *ClipFs, req: fs.Req, data: []const u8) void {
        if (c.replier) |rp| rp.vtable.data(rp.ptr, req, data);
    }
};

fn timeFromNs(ns: i128) fs.Time {
    if (ns <= 0) return .{};
    return .{ .sec = @intCast(@divFloor(ns, std.time.ns_per_s)), .nsec = @intCast(@mod(ns, std.time.ns_per_s)) };
}

test {
    std.testing.refAllDecls(ClipFs);
}
