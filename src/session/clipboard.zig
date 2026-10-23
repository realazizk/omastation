//! Clipboard bridge between the RDP client (MS-RDPECLIP) and the desktop selection (ext-data-control-v1),
//! file copies included. Non-blocking, driven by `service`. At connection the client's clipboard wins
//! (1.3.2.1) unless it is empty and the desktop has a selection; afterwards the latest copy wins.

const std = @import("std");
const wl = @import("../wl/wl.zig");
const cliprdr = @import("../channel/cliprdr.zig");
const bytes = @import("../core/bytes.zig");
const drives = @import("../drives/drives.zig");
const clipfs = @import("clipfs.zig");
const libc = @import("c");

const sys = wl.sys;
const Fd = sys.Fd;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.clipboard);

/// error.Truncated (a dataLen that does not fit, 3.1.5.1) drops the connection; others fail the transfer.
pub const Error = cliprdr.Error;

pub const Options = struct {
    io: std.Io,
    cliprdr: cliprdr.ServerOptions = .{},
    /// The session is remote and unlocked from the start.
    active: bool = false,
    /// Largest clipboard data accepted from either side or produced by a conversion.
    max_data_len: usize = 64 << 20,
    /// Largest file transfer staged from the client (all files together).
    max_staged_bytes: u64 = 1 << 30,
    max_files: usize = 10_000,
    /// cbRequested of File Contents Requests sent.
    file_chunk_len: u32 = 1 << 20,
    /// A pipe nobody writes (or reads) for this long fails its transfer.
    timeout_ms: u32 = 10_000,
    /// A client request unanswered this long fails; `clientProgress` extends it.
    client_timeout_ms: u32 = 30_000,
    /// Pastes waiting or being written at once; more are refused.
    max_pastes: usize = 16,
    /// Where client file copies are mounted or staged; default $XDG_RUNTIME_DIR/omastation/clipboard.
    staging_root: ?[]const u8 = null,
    files: Files = .staging,
    max_cache_bytes: u64 = 256 << 20,
    /// Root of omastation's own mounts. Local paths into it are never offered: the connection's
    /// thread serves them. Default: `staging_root` or $XDG_RUNTIME_DIR/omastation.
    private_root: ?[]const u8 = null,
    now_ms: *const fn () u64 = monotonicMs,
};

pub fn monotonicMs() u64 {
    return sys.nowNs() / std.time.ns_per_ms;
}

/// A pipe the bridge waits on: readable (`write` false) or writable.
pub const PollFd = struct { fd: Fd, write: bool };

pub const Files = union(enum) {
    /// Every file is fetched into a staging directory before the paste.
    staging,
    /// Read-only FUSE tree fetching contents on read; staging when FUSE is unavailable.
    fuse,
    /// FUSE on the given backend instead of the kernel (tests).
    fuse_backend: drives.Backend,
};

const mount_id: u32 = 1;

/// Iterates the complete PDUs in `Bridge.outgoing()` (CLIPRDR_HEADER, 2.2.1).
pub const Messages = struct {
    rest: []const u8,

    pub fn next(m: *Messages) ?[]const u8 {
        if (m.rest.len < cliprdr.header_len) return null;
        const len = cliprdr.header_len + std.mem.readInt(u32, m.rest[4..8], .little);
        if (len > m.rest.len) return null;
        defer m.rest = m.rest[len..];
        return m.rest[0..len];
    }
};

/// Null if the runtime directory is unset, relative or too long.
pub fn defaultStagingRoot(buf: []u8, runtime_dir: ?[]const u8) ?[]const u8 {
    const rd = runtime_dir orelse return null;
    if (rd.len == 0 or rd[0] != '/') return null;
    return std.fmt.bufPrint(buf, "{s}/omastation/clipboard", .{std.mem.trimEnd(u8, rd, "/")}) catch null;
}

/// Absolute, with no empty, "." or ".." components: may be offered to the client.
pub fn isPlainAbsolutePath(path: []const u8) bool {
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/') return false;
    var it = std.mem.splitScalar(u8, path[1..], '/');
    while (it.next()) |comp| {
        if (comp.len == 0 or std.mem.eql(u8, comp, ".") or std.mem.eql(u8, comp, "..")) return false;
    }
    return std.mem.indexOfScalar(u8, path, 0) == null;
}

const Owner = enum { none, local, remote };

const OwnedFormat = struct {
    id: u32,
    name: []u8,

    fn init(gpa: Allocator, f: cliprdr.Format) Allocator.Error!OwnedFormat {
        const name = try gpa.dupe(u8, f.name);
        return .{ .id = f.id, .name = name };
    }

    fn deinit(f: OwnedFormat, gpa: Allocator) void {
        gpa.free(f.name);
    }

    fn format(f: OwnedFormat) cliprdr.Format {
        return .{ .id = f.id, .name = f.name };
    }

    fn isFileList(f: OwnedFormat) bool {
        return std.mem.eql(u8, f.name, cliprdr.name_file_group_descriptor_w);
    }
};

/// Bytes per pipe per service call, so one fast pipe cannot starve the session loop.
const pump_budget = 4 << 20;

const PumpStatus = enum { pending, done, timeout, too_big, failed };

const PipeReader = struct {
    fd: Fd,
    buf: std.ArrayList(u8) = .empty,
    max: usize,
    deadline: u64,

    fn deinit(r: *PipeReader, gpa: Allocator) void {
        sys.close(r.fd);
        r.buf.deinit(gpa);
    }

    fn pump(r: *PipeReader, gpa: Allocator, now: u64, timeout: u64) Allocator.Error!PumpStatus {
        var moved: usize = 0;
        while (moved < pump_budget) {
            // At most max + 1 bytes are ever held.
            const room = r.max + 1 - r.buf.items.len;
            try r.buf.ensureUnusedCapacity(gpa, @min(room, 64 << 10));
            const space = r.buf.unusedCapacitySlice();
            const n = sys.readNonBlock(r.fd, space[0..@min(space.len, room)]) catch return .failed;
            const got = n orelse return if (now >= r.deadline) .timeout else .pending;
            if (got == 0) return .done;
            r.buf.items.len += got;
            if (r.buf.items.len > r.max) return .too_big;
            r.deadline = now + timeout;
            moved += got;
        }
        return .pending;
    }
};

const PipeWriter = struct {
    fd: Fd,
    data: []u8,
    off: usize = 0,
    deadline: u64,

    fn pump(w: *PipeWriter, now: u64, timeout: u64) PumpStatus {
        var moved: usize = 0;
        while (w.off < w.data.len and moved < pump_budget) {
            const chunk = w.data[w.off..][0..@min(w.data.len - w.off, pump_budget - moved)];
            const n = sys.writeNonBlock(w.fd, chunk) catch |err| switch (err) {
                // The application stopped reading; not an error.
                error.ConnectionClosed => return .done,
                else => return .failed,
            };
            const got = n orelse return if (now >= w.deadline) .timeout else .pending;
            w.off += got;
            moved += got;
            w.deadline = now + timeout;
        }
        return if (w.off == w.data.len) .done else .pending;
    }
};

/// Reading the selection to answer the client's oldest Format Data Request.
const LocalRead = struct {
    reader: PipeReader,
    format: OwnedFormat,
    mime: []u8,
    /// local_gen when the read began.
    gen: u64,

    fn deinit(l: *LocalRead, gpa: Allocator) void {
        l.reader.deinit(gpa);
        l.format.deinit(gpa);
        gpa.free(l.mime);
    }
};

/// Files described for one local selection (3.1.1.2); kept alive by locks (3.1.5.3.2).
const LocalSet = struct {
    gen: u64,
    files: ?cliprdr.LocalFiles = null,
    refs: u32 = 1,
};

const Lock = struct { id: u32, set: *LocalSet };

const Paste = struct {
    fd: Fd,
    mime: []u8,
    format: OwnedFormat,
    /// remote_gen of the source it pasted from.
    gen: u64,
    writer: ?PipeWriter = null,

    fn deinit(p: *Paste, gpa: Allocator) void {
        sys.close(p.fd);
        gpa.free(p.mime);
        p.format.deinit(gpa);
        if (p.writer) |w| gpa.free(w.data);
    }
};

const Fetch = struct {
    format_id: u32,
    gen: u64,
    purpose: enum { data, file_list },
    deadline: u64,
};

/// The last Format Data Response (for the client's Format List `gen`).
const Cache = struct { gen: u64, format_id: u32, data: []u8 };

const Staging = struct {
    gen: u64,
    clip_id: ?u32 = null,
    /// The set's absolute directory and fd, once the File List arrives.
    dir: ?[]u8 = null,
    dir_fd: Fd = -1,
    list: ?cliprdr.FileList = null,
    rel: [][]u8 = &.{},
    index: usize = 0,
    file_fd: Fd = -1,
    offset: u64 = 0,
    size: ?u64 = null,
    /// Outstanding File Contents Request and its cbRequested.
    stream: ?u32 = null,
    requested: u32 = 0,
    deadline: u64 = 0,
    written: u64 = 0,
};

/// A completed staging: what pastes of its Format List get.
const Staged = struct {
    gen: u64,
    dir: []u8,
    uri_list: []u8,
    gnome: []u8,
};

const Tree = struct {
    fs: clipfs.ClipFs,
    backend: drives.Backend,
    kernel: ?*drives.fuse.Kernel = null,
    path: [:0]u8,
    mounted: bool = false,
    /// What the backend reported (handled after its dispatch).
    ev_mounted: bool = false,
    ev_failed: bool = false,
    texts: ?Texts = null,
};

const Texts = struct { gen: u64, uri_list: []u8, gnome: []u8 };

const Listing = struct {
    gen: u64,
    clip_id: ?u32 = null,
    list: ?cliprdr.FileList = null,
};

var session_counter: std.atomic.Value(u32) = .init(0);

pub const Bridge = struct {
    gpa: Allocator,
    opts: Options,
    srv: cliprdr.Server,
    dc: ?*wl.DataControl = null,
    out: std.ArrayList(u8) = .empty,
    active: bool,
    /// The client's first Format List arrived (end of initialization).
    synced: bool = false,
    owner: Owner = .none,

    seen_serial: u64 = 0,
    /// Incremented on every foreign selection change.
    local_gen: u64 = 0,
    /// The client holds a non-empty Format List from the server.
    announced: bool = false,
    /// The client's Format Data Requests not answered yet, in order.
    client_requests: std.ArrayList(u32) = .empty,
    local_read: ?LocalRead = null,
    current_set: ?*LocalSet = null,
    locks: std.ArrayList(Lock) = .empty,

    /// Incremented on every client Format List.
    remote_gen: u64 = 0,
    offers: []cliprdr.MimeOffer = &.{},
    pastes: std.ArrayList(Paste) = .empty,
    fetch: ?Fetch = null,
    cache: ?Cache = null,
    staging: ?Staging = null,
    staged: ?Staged = null,
    next_stream_id: u32 = 1,
    next_clip_id: u32 = 1,
    /// <staging root>/<pid>-<n>, created on the first file copy.
    session_dir: ?[]u8 = null,
    next_set: u32 = 0,
    tree: ?*Tree = null,
    /// FUSE cannot be used: files are staged.
    no_fuse: bool = false,
    listing: ?Listing = null,
    /// Options.private_root, symbolic links resolved where it exists.
    private_root: ?[]u8 = null,

    /// With a null `client` or no ext-data-control, the desktop clipboard is empty.
    pub fn create(gpa: Allocator, client: ?*wl.Client, opts: Options) Error!*Bridge {
        sys.ignoreSigpipe();
        const b = try gpa.create(Bridge);
        errdefer gpa.destroy(b);
        b.* = .{ .gpa = gpa, .opts = opts, .srv = cliprdr.Server.init(gpa, opts.cliprdr), .active = opts.active };
        b.private_root = try privateRoot(gpa, opts);
        errdefer if (b.private_root) |r| gpa.free(r);
        if (client) |cl| {
            b.dc = wl.DataControl.create(gpa, cl) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => blk: {
                    log.info("no desktop clipboard: {t}", .{err});
                    break :blk null;
                },
            };
        }
        return b;
    }

    /// Closes every pipe, withdraws the data source, removes staged files.
    pub fn destroy(b: *Bridge) void {
        const gpa = b.gpa;
        if (b.local_read) |*l| l.deinit(gpa);
        b.client_requests.deinit(gpa);
        for (b.pastes.items) |*p| p.deinit(gpa);
        b.pastes.deinit(gpa);
        b.dropStaging();
        b.dropStaged();
        b.dropCache();
        b.dropListing();
        b.destroyTree();
        if (b.private_root) |r| gpa.free(r);
        if (b.session_dir) |d| {
            std.Io.Dir.cwd().deleteTree(b.opts.io, d) catch |err| log.warn("cannot remove the clipboard staging directory: {t}", .{err});
            gpa.free(d);
        }
        if (b.current_set) |s| b.unref(s);
        for (b.locks.items) |l| b.unref(l.set);
        b.locks.deinit(gpa);
        gpa.free(b.offers);
        if (b.dc) |dc| dc.destroy();
        b.srv.deinit();
        b.out.deinit(gpa);
        gpa.destroy(b);
    }

    /// 3.3.5.1.1, 3.3.5.1.2: Clipboard Capabilities, then Monitor Ready.
    pub fn start(b: *Bridge) Error!void {
        try b.srv.start(&b.out);
    }

    pub fn outgoing(b: *const Bridge) []const u8 {
        return b.out.items;
    }

    pub fn clearOutgoing(b: *Bridge) void {
        // A big Format Data Response should not stay allocated.
        if (b.out.capacity > 1 << 20) {
            b.out.clearAndFree(b.gpa);
        } else b.out.clearRetainingCapacity();
    }

    /// The session became (or stopped being) remote and unlocked.
    pub fn setActive(b: *Bridge, on: bool) Error!void {
        if (on == b.active) return;
        b.active = on;
        if (b.tree) |t| t.fs.setActive(on);
        if (on) {
            switch (b.owner) {
                .local => try b.announceLocal(),
                .remote => try b.publishRemote(),
                .none => {},
            }
            return;
        }
        // Refuse what is in flight; nothing crosses until active again.
        try b.serveClientRequests();
        for (b.pastes.items) |*p| p.deinit(b.gpa);
        b.pastes.clearRetainingCapacity();
        try b.failStaging();
        try b.failListing();
        try b.retireTree();
        if (b.dc) |dc| dc.withdraw();
        if (b.announced and b.synced) {
            log.info("the client's copy of the desktop clipboard is emptied (empty Format List)", .{});
            try b.srv.setLocalFormats(&.{}, &b.out);
            b.announced = false;
        }
    }

    pub fn isActive(b: *const Bridge) bool {
        return b.active;
    }

    pub fn handleMessage(b: *Bridge, msg: []const u8) Error!void {
        const ev = try b.srv.handle(msg, &b.out);
        switch (ev) {
            .none => {},
            .remote_formats => |f| log.debug("client: Format List ({d} formats)", .{f.len}),
            .data_request => |id| log.debug("client: Format Data Request {d}", .{id}),
            .data_response => |r| log.debug("client: Format Data Response ok={} {d} bytes", .{ r.ok, r.data.len }),
            .file_contents_request => |r| log.debug("client: File Contents Request stream {d} lindex {d} flags {d} position {d} cb {d} clipDataId {?d}", .{ r.stream_id, r.lindex, r.flags, r.position, r.cb_requested, r.clip_data_id }),
            .file_contents_response => |r| log.debug("client: File Contents Response stream {d} ok={} {d} bytes", .{ r.stream_id, r.ok, r.data.len }),
            .lock => |id| log.debug("client: Lock Clipboard Data {d}", .{id}),
            .unlock => |id| log.debug("client: Unlock Clipboard Data {d}", .{id}),
            .caps => |c| log.debug("client: Capabilities, negotiated 0x{x}", .{c.negotiated_flags}),
            .temp_directory, .format_list_response => log.debug("client: {t}", .{std.meta.activeTag(ev)}),
        }
        switch (ev) {
            .none, .caps, .temp_directory, .format_list_response => {},
            .remote_formats => |formats| try b.onRemoteFormats(formats),
            .data_request => |id| {
                b.client_requests.append(b.gpa, id) catch |err| {
                    // Every request gets its response (in order).
                    try b.srv.sendData(null, &b.out);
                    return err;
                };
                try b.serveClientRequests();
            },
            .data_response => |r| try b.onDataResponse(r.ok, r.data),
            .file_contents_request => |req| try b.onFileContentsRequest(req),
            .file_contents_response => |r| try b.onFileContentsResponse(r),
            .lock => |id| try b.onLock(id),
            .unlock => |id| b.onUnlock(id),
        }
    }

    /// A chunk of a clipboard PDU arrived: outstanding requests get client_timeout_ms more.
    pub fn clientProgress(b: *Bridge) void {
        if (b.fetch) |*f| f.deadline = b.clientDeadline();
        if (b.staging) |*s| if (s.stream != null) {
            s.deadline = b.clientDeadline();
        };
        if (b.tree) |t| t.fs.progress();
    }

    /// Call after every Wayland dispatch and poll wake-up; never blocks.
    pub fn service(b: *Bridge) Error!void {
        if (b.dc) |dc| if (dc.finished) {
            log.info("the desktop clipboard went away", .{});
            dc.destroy();
            b.dc = null;
        };
        try b.checkSelection();
        try b.takeSends();
        try b.serveClientRequests();
        try b.serviceTree();
        try b.servePastes();
        try b.checkTimeouts();
    }

    /// Pipes and the FUSE fd to poll; `buf` should hold max_pastes + 2.
    pub fn pollFds(b: *const Bridge, buf: []PollFd) []PollFd {
        var n: usize = 0;
        if (b.tree) |t| {
            const fd = t.backend.vtable.fd(t.backend.ptr);
            if (fd >= 0 and n < buf.len) {
                buf[n] = .{ .fd = fd, .write = false };
                n += 1;
            }
        }
        if (b.local_read) |l| if (n < buf.len) {
            buf[n] = .{ .fd = l.reader.fd, .write = false };
            n += 1;
        };
        for (b.pastes.items) |p| if (p.writer != null and n < buf.len) {
            buf[n] = .{ .fd = p.fd, .write = true };
            n += 1;
        };
        return buf[0..n];
    }

    /// Milliseconds until the next transfer deadline, -1 for none.
    pub fn timeoutMs(b: *const Bridge) i32 {
        var next: ?u64 = null;
        const take = struct {
            fn f(n: *?u64, d: u64) void {
                n.* = if (n.*) |x| @min(x, d) else d;
            }
        }.f;
        if (b.local_read) |l| take(&next, l.reader.deadline);
        for (b.pastes.items) |p| if (p.writer) |w| take(&next, w.deadline);
        if (b.fetch) |f| take(&next, f.deadline);
        if (b.staging) |s| if (s.stream != null) take(&next, s.deadline);
        if (b.tree) |t| {
            if (t.fs.nextDeadline()) |d| take(&next, d);
            // A mount point being freed, fusermount3 to reap.
            if (t.kernel) |k| if (k.busy()) take(&next, b.nowMs() + tree_busy_ms);
        }
        const d = next orelse return -1;
        const now = b.nowMs();
        if (d <= now) return 0;
        return @intCast(@min(d - now, std.math.maxInt(i32)));
    }

    fn nowMs(b: *const Bridge) u64 {
        return b.opts.now_ms();
    }

    fn deadline(b: *const Bridge) u64 {
        return b.nowMs() + b.opts.timeout_ms;
    }

    fn clientDeadline(b: *const Bridge) u64 {
        return b.nowMs() + b.opts.client_timeout_ms;
    }

    fn localOffer(b: *const Bridge) ?*wl.data_control.Offer {
        const dc = b.dc orelse return null;
        if (dc.selection_own) return null;
        return dc.selection;
    }

    fn checkSelection(b: *Bridge) Error!void {
        const dc = b.dc orelse return;
        if (dc.selection_serial == b.seen_serial) return;
        b.seen_serial = dc.selection_serial;
        log.debug("desktop selection {d}: own={} offer={}", .{ dc.selection_serial, dc.selection_own, dc.selection != null });
        // The bridge's own source: the client already has it.
        if (dc.selection_own) return;
        if (dc.selection == null) {
            // Emptied: only the copy announced to the client is stale.
            if (b.owner != .local) return;
            b.owner = .none;
            b.newLocalGen();
            if (b.announced and b.active and b.synced) {
                try b.srv.setLocalFormats(&.{}, &b.out);
                b.announced = false;
            }
            return;
        }
        b.owner = .local;
        b.newLocalGen();
        try b.retireTree();
        try b.announceLocal();
    }

    fn newLocalGen(b: *Bridge) void {
        b.local_gen += 1;
        if (b.current_set) |s| b.unref(s);
        b.current_set = null;
    }

    /// 3.1.4.1: the Format List for the desktop selection (empty when nothing is usable).
    fn announceLocal(b: *Bridge) Error!void {
        if (!b.active or !b.synced) return;
        const formats: []cliprdr.Format = if (b.localOffer()) |o|
            try cliprdr.formatsForMimeTypes(b.gpa, o.mimeTypes(), b.srv.negotiatedFlags())
        else
            &.{};
        defer b.gpa.free(formats);
        try b.srv.setLocalFormats(formats, &b.out);
        b.announced = formats.len > 0;
    }

    fn serveClientRequests(b: *Bridge) Error!void {
        while (true) {
            if (b.local_read) |*l| {
                if (!b.active) {
                    l.deinit(b.gpa);
                    b.local_read = null;
                    try b.answerClient(null);
                    continue;
                }
                switch (try l.reader.pump(b.gpa, b.nowMs(), b.opts.timeout_ms)) {
                    .pending => return,
                    .done => try b.finishLocalRead(),
                    else => |st| {
                        log.warn("reading the selection ({s}) for the client failed: {t}", .{ l.mime, st });
                        l.deinit(b.gpa);
                        b.local_read = null;
                        try b.answerClient(null);
                    },
                }
                continue;
            }
            if (b.client_requests.items.len == 0) return;
            try b.startLocalRead(b.client_requests.items[0]);
        }
    }

    /// Answers the oldest client Format Data Request (null: CB_RESPONSE_FAIL, 3.1.5.4.3).
    fn answerClient(b: *Bridge, data: ?[]const u8) Error!void {
        const id = b.client_requests.orderedRemove(0);
        log.debug("server: Format Data Response for {d} ok={} {d} bytes", .{ id, data != null, if (data) |d| d.len else 0 });
        try b.srv.sendData(data, &b.out);
    }

    /// 3.1.5.4.2: read the requested format's mime type from the selection.
    fn startLocalRead(b: *Bridge, format_id: u32) Error!void {
        if (!b.active) return b.answerClient(null);
        const f = b.srv.localFormat(format_id) orelse return b.answerClient(null);
        const o = b.localOffer() orelse return b.answerClient(null);
        const mime = cliprdr.mimeForFormat(f, o.mimeTypes()) orelse return b.answerClient(null);
        const fd = o.receive(mime) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                log.warn("cannot read the selection ({s}): {t}", .{ mime, err });
                return b.answerClient(null);
            },
        };
        errdefer sys.close(fd);
        const mime_copy = try b.gpa.dupe(u8, mime);
        errdefer b.gpa.free(mime_copy);
        const of = try OwnedFormat.init(b.gpa, f);
        b.local_read = .{
            .reader = .{ .fd = fd, .max = b.opts.max_data_len, .deadline = b.deadline() },
            .format = of,
            .mime = mime_copy,
            .gen = b.local_gen,
        };
    }

    fn finishLocalRead(b: *Bridge) Error!void {
        var l = b.local_read.?;
        b.local_read = null;
        defer l.deinit(b.gpa);
        const data = l.reader.buf.items;
        const reply: ?[]u8 = if (l.format.isFileList())
            b.describeFiles(l.mime, data, l.gen) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => blk: {
                    log.warn("cannot describe the copied files: {t}", .{err});
                    break :blk null;
                },
            }
        else
            cliprdr.convertToRemote(b.gpa, l.format.format(), l.mime, data) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => blk: {
                    log.warn("cannot convert {s} ({d} bytes) to format {d}: {t}", .{ l.mime, data.len, l.format.id, err });
                    break :blk null;
                },
            };
        defer if (reply) |r| b.gpa.free(r);
        if (reply) |r| if (r.len > b.opts.max_data_len) {
            log.warn("format {d} would be {d} bytes, more than {d}", .{ l.format.id, r.len, b.opts.max_data_len });
            return b.answerClient(null);
        };
        try b.answerClient(reply);
    }

    /// Packed File List (2.2.5.2.3) for a uri-list or gnome-copied-files; File Contents Requests index it.
    fn describeFiles(b: *Bridge, mime: []const u8, data: []const u8, gen: u64) anyerror![]u8 {
        if (gen != b.local_gen) return error.SelectionChanged;
        const paths: cliprdr.PathList = if (std.mem.eql(u8, mime, cliprdr.mime_uri_list))
            try cliprdr.parseUriList(b.gpa, data)
        else
            (try cliprdr.parseGnomeCopiedFiles(b.gpa, data)).list;
        defer paths.deinit(b.gpa);
        if (paths.paths.len == 0 or paths.paths.len > b.opts.max_files) return error.InvalidFileList;
        for (paths.paths) |p| if (!isPlainAbsolutePath(p)) return error.InvalidFileName;
        var lf = try cliprdr.describeLocalFilesGuarded(b.gpa, b.opts.io, paths.paths, b.guard(), b.opts.max_files);
        errdefer lf.deinit(b.gpa);
        try confine(b.gpa, b.opts.io, &lf);
        if (lf.list.files.len > b.opts.max_files) return error.InvalidFileList;
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(b.gpa);
        var w = bytes.Writer.init(&list, b.gpa);
        try cliprdr.encodeFileList(&w, lf.list.files, b.srv.negotiatedFlags());
        const set = try b.currentSet();
        const payload = try list.toOwnedSlice(b.gpa);
        // Nothing fails from here: `lf` belongs to the set.
        if (set.files) |old| old.deinit(b.gpa);
        set.files = lf;
        return payload;
    }

    fn currentSet(b: *Bridge) Allocator.Error!*LocalSet {
        if (b.current_set) |s| return s;
        const s = try b.gpa.create(LocalSet);
        s.* = .{ .gen = b.local_gen };
        b.current_set = s;
        return s;
    }

    fn unref(b: *Bridge, s: *LocalSet) void {
        s.refs -= 1;
        if (s.refs > 0) return;
        if (s.files) |f| f.deinit(b.gpa);
        b.gpa.destroy(s);
    }

    /// 3.1.5.4.6: lindex into the current selection's File List, or the one locked under clipDataId.
    fn onFileContentsRequest(b: *Bridge, req: cliprdr.FileContentsRequest) Error!void {
        const set: ?*LocalSet = if (req.clip_data_id) |id| b.lockedSet(id) else b.current_set;
        const files: ?*const cliprdr.LocalFiles = if (set) |s| (if (s.files) |*f| f else null) else null;
        const range = req.flags & cliprdr.FILECONTENTS_RANGE != 0;
        if (!b.active or files == null or (range and req.cb_requested > b.opts.max_data_len)) {
            log.debug("server: File Contents Response stream {d} fails (active={} files={} cb {d})", .{ req.stream_id, b.active, files != null, req.cb_requested });
            return b.srv.sendFileContents(req.stream_id, null, &b.out);
        }
        // Refuse a symbolic link swapped in since it was described, in particular one into own mounts.
        if (req.lindex >= 0 and req.lindex < files.?.paths.len and
            (refusePath(b, files.?.paths[@intCast(req.lindex)]) or !try stillReal(b.gpa, b.opts.io, files.?.paths[@intCast(req.lindex)])))
        {
            log.debug("server: File Contents Response stream {d} fails (index {d} moved)", .{ req.stream_id, req.lindex });
            return b.srv.sendFileContents(req.stream_id, null, &b.out);
        }
        const data = cliprdr.readFileContents(b.gpa, b.opts.io, files.?, req) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => blk: {
                log.warn("file contents for index {d}: {t}", .{ req.lindex, err });
                break :blk null;
            },
        };
        defer if (data) |d| b.gpa.free(d);
        log.debug("server: File Contents Response stream {d} ok={} {d} bytes", .{ req.stream_id, data != null, if (data) |d| d.len else 0 });
        try b.srv.sendFileContents(req.stream_id, data, &b.out);
    }

    fn lockedSet(b: *const Bridge, id: u32) ?*LocalSet {
        for (b.locks.items) |l| if (l.id == id) return l.set;
        return null;
    }

    /// 3.1.5.3.2: keep the current selection's files for this clipDataId.
    fn onLock(b: *Bridge, id: u32) Error!void {
        if (b.lockedSet(id) != null) return;
        try b.locks.ensureUnusedCapacity(b.gpa, 1);
        const s = try b.currentSet();
        s.refs += 1;
        b.locks.appendAssumeCapacity(.{ .id = id, .set = s });
    }

    /// 3.1.5.3.4.
    fn onUnlock(b: *Bridge, id: u32) void {
        for (b.locks.items, 0..) |l, i| if (l.id == id) {
            _ = b.locks.orderedRemove(i);
            b.unref(l.set);
            return;
        };
    }

    /// 3.1.5.2.2 (the Format List Response is already queued).
    fn onRemoteFormats(b: *Bridge, formats: []const cliprdr.Format) Error!void {
        const first = !b.synced;
        b.synced = true;
        b.remote_gen += 1;
        b.dropCache();
        try b.retireTree();
        const offers = try cliprdr.offersForRemoteFormats(b.gpa, formats, b.srv.negotiatedFlags());
        b.gpa.free(b.offers);
        b.offers = offers;
        b.announced = false;
        // 1.3.2.1: the client's clipboard wins at connection unless empty and the desktop has one.
        if (first and formats.len == 0 and b.owner == .local) return b.announceLocal();
        b.owner = .remote;
        try b.publishRemote();
    }

    /// Offers the client's formats as the desktop selection, or withdraws it when there are none.
    fn publishRemote(b: *Bridge) Error!void {
        if (!b.active) return;
        const dc = b.dc orelse return;
        if (b.offers.len == 0) return dc.withdraw();
        var mimes: [16][]const u8 = undefined;
        const n = @min(b.offers.len, mimes.len);
        for (b.offers[0..n], 0..) |o, i| mimes[i] = o.mime;
        dc.setSelection(mimes[0..n], b.remote_gen) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => log.warn("cannot set the desktop selection: {t}", .{err}),
        };
    }

    fn takeSends(b: *Bridge) Error!void {
        const dc = b.dc orelse return;
        while (dc.takeSend()) |req| try b.onSend(req);
    }

    /// An application pastes from the data source (ext_data_control_source.send).
    fn onSend(b: *Bridge, req: wl.data_control.SendRequest) Error!void {
        var keep = false;
        defer if (!keep) req.deinit(b.gpa);
        // A source of an older Format List: the client has other data now.
        if (!b.active or req.tag != b.remote_gen or b.pastes.items.len >= b.opts.max_pastes) return;
        const offer = for (b.offers) |o| {
            if (std.mem.eql(u8, o.mime, req.mime)) break o;
        } else return;
        const f = b.srv.remoteFormat(offer.format_id) orelse return;
        sys.setNonBlocking(req.fd) catch return;
        try b.pastes.ensureUnusedCapacity(b.gpa, 1);
        const of = try OwnedFormat.init(b.gpa, f);
        errdefer of.deinit(b.gpa);
        // The password hint is answered locally, without a round trip.
        const writer: ?PipeWriter = if (std.mem.eql(u8, offer.mime, cliprdr.mime_password_hint))
            .{ .fd = req.fd, .data = try b.gpa.dupe(u8, cliprdr.password_hint_data), .deadline = b.deadline() }
        else
            null;
        b.pastes.appendAssumeCapacity(.{ .fd = req.fd, .mime = req.mime, .format = of, .gen = req.tag, .writer = writer });
        keep = true;
    }

    fn servePastes(b: *Bridge) Error!void {
        var i: usize = 0;
        while (i < b.pastes.items.len) {
            const p = &b.pastes.items[i];
            if (p.writer) |*w| {
                switch (w.pump(b.nowMs(), b.opts.timeout_ms)) {
                    .pending => i += 1,
                    .done => b.removePaste(i),
                    else => |st| {
                        log.warn("writing {s} to a pasting application: {t}", .{ p.mime, st });
                        b.removePaste(i);
                    },
                }
                continue;
            }
            if (try b.startPaste(p)) {
                if (p.writer == null) b.removePaste(i);
            } else i += 1;
        }
    }

    fn removePaste(b: *Bridge, i: usize) void {
        var p = b.pastes.orderedRemove(i);
        p.deinit(b.gpa);
    }

    /// Serves a waiting paste if its data is here, else requests it; true once settled.
    fn startPaste(b: *Bridge, p: *Paste) Error!bool {
        if (p.format.isFileList()) {
            if (b.staged) |s| if (s.gen == p.gen) {
                const text = if (std.mem.eql(u8, p.mime, cliprdr.mime_gnome_copied_files)) s.gnome else s.uri_list;
                // Not `.{ .data = try ... }`: p.writer would be set when it fails.
                const data = try b.gpa.dupe(u8, text);
                p.writer = .{ .fd = p.fd, .data = data, .deadline = b.deadline() };
                return true;
            };
            if (b.tree) |t| if (t.texts) |x| if (x.gen == p.gen) {
                const text = if (std.mem.eql(u8, p.mime, cliprdr.mime_gnome_copied_files)) x.gnome else x.uri_list;
                const data = try b.gpa.dupe(u8, text);
                p.writer = .{ .fd = p.fd, .data = data, .deadline = b.deadline() };
                return true;
            };
            if (b.staging != null or b.fetch != null or b.listing != null) return false;
            if (p.gen != b.remote_gen) return true;
            if (try b.ensureTree() != null) return !try b.startListing(p.format);
            return !try b.startStaging(p.format);
        }
        if (b.cache) |c| if (c.gen == p.gen and c.format_id == p.format.id) {
            const data = cliprdr.convertFromRemote(b.gpa, p.format.format(), p.mime, c.data) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    log.warn("cannot convert format {d} ({d} bytes) to {s}: {t}", .{ p.format.id, c.data.len, p.mime, err });
                    return true;
                },
            };
            if (data.len > b.opts.max_data_len) {
                b.gpa.free(data);
                return true;
            }
            p.writer = .{ .fd = p.fd, .data = data, .deadline = b.deadline() };
            return true;
        };
        if (b.fetch != null) return false;
        if (p.gen != b.remote_gen) return true;
        // 3.1.4.2, 3.1.5.4.1.
        b.srv.requestData(p.format.id, &b.out) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return true,
        };
        b.fetch = .{ .format_id = p.format.id, .gen = p.gen, .purpose = .data, .deadline = b.clientDeadline() };
        return false;
    }

    /// Fails the waiting pastes of Format List `gen`: the file pastes, or those of `format_id`.
    fn failPastes(b: *Bridge, gen: u64, what: union(enum) { files, format: u32 }) void {
        var i: usize = 0;
        while (i < b.pastes.items.len) {
            const p = &b.pastes.items[i];
            const hit = p.writer == null and p.gen == gen and switch (what) {
                .files => p.format.isFileList(),
                .format => |id| !p.format.isFileList() and p.format.id == id,
            };
            if (hit) b.removePaste(i) else i += 1;
        }
    }

    /// 3.1.5.4.4.
    fn onDataResponse(b: *Bridge, ok: bool, data: []const u8) Error!void {
        const f = b.fetch orelse return;
        b.fetch = null;
        switch (f.purpose) {
            .data => {
                if (ok and data.len <= b.opts.max_data_len) {
                    const copy = try b.gpa.dupe(u8, data);
                    b.dropCache();
                    b.cache = .{ .gen = f.gen, .format_id = f.format_id, .data = copy };
                } else {
                    if (ok) log.warn("format {d}: {d} bytes, more than {d}", .{ f.format_id, data.len, b.opts.max_data_len });
                    b.failPastes(f.gen, .{ .format = f.format_id });
                }
            },
            .file_list => try b.onFileList(ok, data),
        }
        try b.servePastes();
    }

    fn checkTimeouts(b: *Bridge) Error!void {
        const now = b.nowMs();
        if (b.fetch) |f| if (now >= f.deadline) {
            log.warn("the client did not answer the Format Data Request for format {d}", .{f.format_id});
            b.srv.cancelDataRequest();
            b.fetch = null;
            switch (f.purpose) {
                .data => b.failPastes(f.gen, .{ .format = f.format_id }),
                .file_list => try b.failStaging(),
            }
            try b.servePastes();
        };
        if (b.staging) |s| if (s.stream != null and now >= s.deadline) {
            log.warn("the client did not answer a File Contents Request", .{});
            try b.failStaging();
            try b.servePastes();
        };
        if (b.tree) |t| {
            t.fs.checkTimeouts();
            try b.flushTree();
        }
    }

    fn dropCache(b: *Bridge) void {
        if (b.cache) |c| b.gpa.free(c.data);
        b.cache = null;
    }

    /// Locks the client's file data (3.1.5.3.1, if negotiated) and requests its File List.
    fn startStaging(b: *Bridge, f: OwnedFormat) Error!bool {
        var st: Staging = .{ .gen = b.remote_gen };
        if (b.srv.negotiatedFlags() & cliprdr.CB_CAN_LOCK_CLIPDATA != 0) {
            const id = b.next_clip_id;
            b.next_clip_id +%= 1;
            b.srv.lock(id, &b.out) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return false,
            };
            st.clip_id = id;
        }
        b.srv.requestData(f.id, &b.out) catch |err| {
            if (st.clip_id) |id| try b.unlockClient(id);
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return false;
        };
        b.fetch = .{ .format_id = f.id, .gen = st.gen, .purpose = .file_list, .deadline = b.clientDeadline() };
        b.staging = st;
        return true;
    }

    fn onFileList(b: *Bridge, ok: bool, data: []const u8) Error!void {
        if (b.listing != null) return b.onListing(ok, data);
        if (b.staging == null) return;
        if (!ok) return b.failStaging();
        b.prepareStaging(data) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                log.warn("refusing the client's file list: {t}", .{err});
                return b.failStaging();
            },
        };
        try b.stageNext();
    }

    fn prepareStaging(b: *Bridge, data: []const u8) anyerror!void {
        const st = &b.staging.?;
        const list = try cliprdr.decodeFileList(b.gpa, data);
        st.list = list;
        if (list.files.len == 0 or list.files.len > b.opts.max_files) return error.InvalidFileList;
        st.rel = try b.gpa.alloc([]u8, list.files.len);
        @memset(st.rel, &.{});
        var total: u64 = 0;
        for (list.files, 0..) |f, i| {
            // No absolute names, ".." or names invalid on Windows: paths stay inside the set directory.
            st.rel[i] = try cliprdr.remoteNameToRelativePath(b.gpa, f.name);
            if (f.flags & cliprdr.FD_FILESIZE != 0 and !isDirectory(f)) total +|= f.size;
        }
        if (total > b.opts.max_staged_bytes) return error.FileTooLarge;
        const set = try b.newSetDir();
        st.dir = set.path;
        st.dir_fd = set.fd;
    }

    fn stageNext(b: *Bridge) Error!void {
        const st = &(b.staging orelse return);
        const list = st.list.?;
        while (st.index < list.files.len) {
            const f = list.files[st.index];
            const rel = st.rel[st.index];
            if (isDirectory(f)) {
                makeDirs(st.dir_fd, rel, true) catch |err| return b.stagingError("creating a directory", err);
                st.index += 1;
                continue;
            }
            makeDirs(st.dir_fd, rel, false) catch |err| return b.stagingError("creating a directory", err);
            st.file_fd = createFile(st.dir_fd, rel) catch |err| return b.stagingError("creating a file", err);
            st.offset = 0;
            st.size = if (f.flags & cliprdr.FD_FILESIZE != 0) f.size else null;
            if (st.size == 0) {
                b.closeStagedFile();
                st.index += 1;
                continue;
            }
            return b.requestContents();
        }
        try b.finishStaging();
    }

    /// The tree, mounted on first use; null when FUSE is unavailable (files are staged).
    fn ensureTree(b: *Bridge) Error!?*Tree {
        if (b.tree) |t| return t;
        if (b.no_fuse) return null;
        const backend: ?drives.Backend = switch (b.opts.files) {
            .staging => return null,
            .fuse => null,
            .fuse_backend => |be| be,
        };
        b.startTree(backend) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                log.warn("client file copies are staged: no FUSE tree ({t})", .{err});
                b.no_fuse = true;
                return null;
            },
        };
        return b.tree;
    }

    fn startTree(b: *Bridge, backend: ?drives.Backend) anyerror!void {
        const gpa = b.gpa;
        const dir = try b.createSessionDir();
        defer gpa.free(dir);
        errdefer removeDir(dir);
        const path = try gpa.dupeSentinel(u8, dir, 0);
        errdefer gpa.free(path);
        const t = try gpa.create(Tree);
        errdefer gpa.destroy(t);
        t.* = .{
            .fs = clipfs.ClipFs.init(gpa, .{
                .uid = std.c.getuid(),
                .gid = std.c.getgid(),
                .chunk_len = b.opts.file_chunk_len,
                .max_cache_bytes = b.opts.max_cache_bytes,
                .request_timeout_ms = b.opts.client_timeout_ms,
                .now_ms = b.opts.now_ms,
            }),
            .backend = undefined,
            .path = path,
        };
        errdefer t.fs.deinit();
        t.fs.active = b.active;
        if (backend) |be| {
            t.backend = be;
        } else {
            const k = try gpa.create(drives.fuse.Kernel);
            errdefer gpa.destroy(k);
            k.* = try drives.fuse.Kernel.init(gpa);
            t.kernel = k;
            t.backend = k.backend();
        }
        errdefer if (t.kernel) |k| {
            k.deinit();
            gpa.destroy(k);
        };
        try t.backend.vtable.mount(t.backend.ptr, .{
            .id = mount_id,
            .handler = t.fs.handler(),
            .path = path,
            .read_only = true,
            .stale = false,
            .notify = .{ .ctx = b, .f = onMountEvent },
        });
        b.tree = t;
    }

    fn onMountEvent(ctx: *anyopaque, id: u32, ev: drives.MountEvent) void {
        const b: *Bridge = @ptrCast(@alignCast(ctx));
        const t = b.tree orelse return;
        if (id != mount_id) return;
        switch (ev) {
            .mounted => t.ev_mounted = true,
            .failed, .gone => t.ev_failed = true,
        }
    }

    fn serviceTree(b: *Bridge) Error!void {
        const t = b.tree orelse return;
        t.backend.vtable.dispatch(t.backend.ptr);
        if (t.ev_failed) return b.treeFailed();
        if (t.ev_mounted) {
            t.ev_mounted = false;
            if (!t.mounted) log.info("client file copies are served from {s}", .{t.path});
            t.mounted = true;
        }
        if (t.mounted) if (b.listing) |l| if (l.list != null) try b.finishListing();
        try b.flushTree();
    }

    /// Mount failed or the tree was unmounted: staging from now on, waiting pastes restart that way.
    fn treeFailed(b: *Bridge) Error!void {
        const t = b.tree.?;
        if (t.mounted)
            log.warn("the FUSE tree of client file copies went away; they are staged from now on", .{})
        else
            log.warn("the FUSE tree of client file copies could not be mounted; they are staged", .{});
        b.no_fuse = true;
        t.fs.abort();
        try b.flushTree();
        b.destroyTree();
        if (b.listing) |l| {
            if (b.fetch) |f| if (f.purpose == .file_list) {
                b.srv.cancelDataRequest();
                b.fetch = null;
            };
            b.dropListing();
            if (l.clip_id) |id| try b.unlockClient(id);
        }
    }

    /// Unmounts the tree (pending requests fail with EIO) and frees it.
    fn destroyTree(b: *Bridge) void {
        const t = b.tree orelse return;
        const gpa = b.gpa;
        t.fs.abort();
        t.backend.vtable.unmount(t.backend.ptr, mount_id);
        if (t.kernel) |k| {
            // Waits for fusermount3's lazy unmount, which also removes the mount point.
            k.deinit();
            gpa.destroy(k);
        }
        // Only an empty directory: never a recursive delete into a mount.
        removeDir(t.path);
        if (t.texts) |x| freeTexts(gpa, x);
        t.fs.deinit();
        gpa.free(t.path);
        gpa.destroy(t);
        b.tree = null;
    }

    fn flushTree(b: *Bridge) Error!void {
        const t = b.tree orelse return;
        while (t.fs.takeCancel()) |stream| b.srv.cancelFileContentsRequest(stream);
        while (t.fs.takeUnlock()) |id| try b.unlockClient(id);
        while (true) {
            const stream = b.next_stream_id;
            const req = (try t.fs.nextRequest(stream)) orelse break;
            b.next_stream_id +%= 1;
            log.debug("server: File Contents Request stream {d} lindex {d} flags {d} position {d} cb {d} clipDataId {?d}", .{ req.stream_id, req.lindex, req.flags, req.position, req.cb_requested, req.clip_data_id });
            b.srv.requestFileContents(req, &b.out) catch |err| {
                t.fs.requestFailed(stream);
                if (err == error.OutOfMemory) return error.OutOfMemory;
            };
        }
    }

    fn retireTree(b: *Bridge) Error!void {
        const t = b.tree orelse return;
        t.fs.retireAll();
        if (t.texts) |x| freeTexts(b.gpa, x);
        t.texts = null;
        try b.flushTree();
    }

    fn startListing(b: *Bridge, f: OwnedFormat) Error!bool {
        var l: Listing = .{ .gen = b.remote_gen };
        if (b.srv.negotiatedFlags() & cliprdr.CB_CAN_LOCK_CLIPDATA != 0) {
            const id = b.next_clip_id;
            b.next_clip_id +%= 1;
            b.srv.lock(id, &b.out) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return false,
            };
            l.clip_id = id;
        }
        b.srv.requestData(f.id, &b.out) catch |err| {
            if (l.clip_id) |id| try b.unlockClient(id);
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return false;
        };
        b.fetch = .{ .format_id = f.id, .gen = l.gen, .purpose = .file_list, .deadline = b.clientDeadline() };
        b.listing = l;
        return true;
    }

    fn onListing(b: *Bridge, ok: bool, data: []const u8) Error!void {
        const l = &b.listing.?;
        // A list for a clipboard already replaced is not shown.
        if (!ok or l.gen != b.remote_gen) return b.failListing();
        const list = cliprdr.decodeFileList(b.gpa, data) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                log.warn("refusing the client's file list: {t}", .{err});
                return b.failListing();
            },
        };
        if (list.files.len == 0 or list.files.len > b.opts.max_files) {
            list.deinit(b.gpa);
            log.warn("refusing the client's file list: {d} entries", .{list.files.len});
            return b.failListing();
        }
        l.list = list;
        if (b.tree) |t| if (t.mounted) return b.finishListing();
    }

    /// The listed files become a tree generation; the pastes get their uri-list.
    fn finishListing(b: *Bridge) Error!void {
        const gpa = b.gpa;
        const t = b.tree.?;
        const l = &b.listing.?;
        const list = l.list.?;
        if (l.gen != b.remote_gen) return b.failListing();
        var name_buf: [24]u8 = undefined;
        const name = t.fs.nextDirName(&name_buf);
        const dir = try std.fs.path.join(gpa, &.{ t.path, name });
        defer gpa.free(dir);
        const texts = b.stagedTexts(dir, list.files) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                log.warn("refusing the client's file list: {t}", .{err});
                return b.failListing();
            },
        };
        _ = t.fs.addGeneration(l.gen, list.files, l.clip_id) catch |err| {
            gpa.free(texts.uri_list);
            gpa.free(texts.gnome);
            switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    log.warn("refusing the client's file list: {t}", .{err});
                    return b.failListing();
                },
            }
        };
        // The generation owns the lock now.
        log.info("{d} entries copied on the client are in {s} (fetched when read)", .{ list.files.len, dir });
        if (t.texts) |x| freeTexts(gpa, x);
        t.texts = .{ .gen = l.gen, .uri_list = texts.uri_list, .gnome = texts.gnome };
        b.dropListing();
    }

    fn failListing(b: *Bridge) Error!void {
        const l = b.listing orelse return;
        if (b.fetch) |f| if (f.purpose == .file_list) {
            b.srv.cancelDataRequest();
            b.fetch = null;
        };
        b.dropListing();
        b.failPastes(l.gen, .files);
        if (l.clip_id) |id| try b.unlockClient(id);
    }

    fn dropListing(b: *Bridge) void {
        const l = b.listing orelse return;
        if (l.list) |list| list.deinit(b.gpa);
        b.listing = null;
    }

    fn guard(b: *const Bridge) cliprdr.PathGuard {
        return .{ .ctx = b, .refuse = refuseGuard };
    }

    fn refuseGuard(ctx: *const anyopaque, path: []const u8) bool {
        const b: *const Bridge = @ptrCast(@alignCast(ctx));
        return refusePath(b, path);
    }

    fn stagingError(b: *Bridge, what: []const u8, err: anyerror) Error!void {
        log.warn("staging the client's files: {s}: {t}", .{ what, err });
        try b.failStaging();
    }

    /// 3.1.5.4.5: the size first when the File List has none, then ranges.
    fn requestContents(b: *Bridge) Error!void {
        const st = &b.staging.?;
        const stream = b.next_stream_id;
        b.next_stream_id +%= 1;
        const req: cliprdr.FileContentsRequest = if (st.size) |size| .{
            .stream_id = stream,
            .lindex = @intCast(st.index),
            .flags = cliprdr.FILECONTENTS_RANGE,
            .position = st.offset,
            .cb_requested = @intCast(@min(@as(u64, b.opts.file_chunk_len), size - st.offset)),
            .clip_data_id = st.clip_id,
        } else .{
            .stream_id = stream,
            .lindex = @intCast(st.index),
            .flags = cliprdr.FILECONTENTS_SIZE,
            .cb_requested = 8,
            .clip_data_id = st.clip_id,
        };
        b.srv.requestFileContents(req, &b.out) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return b.stagingError("File Contents Request", err),
        };
        st.stream = stream;
        st.requested = req.cb_requested;
        st.deadline = b.clientDeadline();
    }

    /// 3.1.5.4.8.
    fn onFileContentsResponse(b: *Bridge, r: cliprdr.FileContentsResponse) Error!void {
        if (b.tree) |t| if (try t.fs.onResponse(r)) return b.flushTree();
        const st = &(b.staging orelse return);
        if (st.stream != r.stream_id) return;
        st.stream = null;
        if (!r.ok) return b.stagingError("file contents", error.ResponseFail);
        if (st.size == null) {
            const size = cliprdr.fileSizeFromResponse(r) catch |err| return b.stagingError("file size", err);
            if (st.written +| size > b.opts.max_staged_bytes) return b.stagingError("file size", error.FileTooLarge);
            st.size = size;
            if (size == 0) {
                b.closeStagedFile();
                st.index += 1;
                return b.stageNext();
            }
            return b.requestContents();
        }
        const data = r.data;
        if (data.len == 0 or data.len > st.requested) return b.stagingError("file contents", error.InvalidPdu);
        if (st.written + data.len > b.opts.max_staged_bytes) return b.stagingError("file contents", error.FileTooLarge);
        pwriteAll(st.file_fd, data, st.offset) catch |err| return b.stagingError("writing a file", err);
        st.offset += data.len;
        st.written += data.len;
        if (st.offset < st.size.?) return b.requestContents();
        b.closeStagedFile();
        st.index += 1;
        try b.stageNext();
    }

    fn closeStagedFile(b: *Bridge) void {
        const st = &b.staging.?;
        const f = st.list.?.files[st.index];
        if (f.flags & cliprdr.FD_WRITESTIME != 0 and f.last_write_time != 0) {
            const ns = cliprdr.unixNsFromFiletime(f.last_write_time);
            const ts: std.c.timespec = .{ .sec = @intCast(@divFloor(ns, std.time.ns_per_s)), .nsec = @intCast(@mod(ns, std.time.ns_per_s)) };
            _ = std.c.futimens(st.file_fd, &.{ ts, ts });
        }
        sys.close(st.file_fd);
        st.file_fd = -1;
    }

    fn finishStaging(b: *Bridge) Error!void {
        const st = &b.staging.?;
        const texts = b.stagedTexts(st.dir.?, st.list.?.files) catch |err| switch (err) {
            error.OutOfMemory => {
                try b.failStaging();
                return error.OutOfMemory;
            },
            else => return b.stagingError("uri-list", err),
        };
        log.info("staged {d} entries from the client ({d} bytes)", .{ st.list.?.files.len, st.written });
        const gen = st.gen;
        const dir = st.dir.?;
        const clip_id = st.clip_id;
        // The set directory now belongs to `staged`.
        st.dir = null;
        b.dropStaging();
        b.dropStaged();
        b.staged = .{ .gen = gen, .dir = dir, .uri_list = texts.uri_list, .gnome = texts.gnome };
        // 3.1.5.3.3: done with the client's file data.
        if (clip_id) |id| try b.unlockClient(id);
    }

    /// text/uri-list and x-special/gnome-copied-files naming a staged set's top-level entries.
    fn stagedTexts(b: *Bridge, dir: []const u8, files: []const cliprdr.FileDescriptor) cliprdr.Error!struct { uri_list: []u8, gnome: []u8 } {
        const gpa = b.gpa;
        const uri_list = try cliprdr.fileListToUriList(gpa, dir, files);
        errdefer gpa.free(uri_list);
        var top: std.ArrayList([]const u8) = .empty;
        defer {
            for (top.items) |p| gpa.free(p);
            top.deinit(gpa);
        }
        for (files) |f| if (std.mem.indexOfScalar(u8, f.name, '\\') == null) {
            try top.ensureUnusedCapacity(gpa, 1);
            top.appendAssumeCapacity(try std.fs.path.join(gpa, &.{ dir, f.name }));
        };
        const gnome = try cliprdr.formatGnomeCopiedFiles(gpa, top.items, false);
        return .{ .uri_list = uri_list, .gnome = gnome };
    }

    fn failStaging(b: *Bridge) Error!void {
        const st = &(b.staging orelse return);
        if (st.stream) |s| b.srv.cancelFileContentsRequest(s);
        if (b.fetch) |f| if (f.purpose == .file_list) {
            b.srv.cancelDataRequest();
            b.fetch = null;
        };
        const gen = st.gen;
        const clip_id = st.clip_id;
        b.dropStaging();
        b.failPastes(gen, .files);
        if (clip_id) |id| try b.unlockClient(id);
    }

    /// 3.1.5.3.3, for an id this bridge locked (error.NotLocked cannot happen).
    fn unlockClient(b: *Bridge, id: u32) Error!void {
        b.srv.unlock(id, &b.out) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {},
        };
    }

    fn dropStaging(b: *Bridge) void {
        const st = &(b.staging orelse return);
        const gpa = b.gpa;
        sys.close(st.file_fd);
        sys.close(st.dir_fd);
        if (st.dir) |d| {
            std.Io.Dir.cwd().deleteTree(b.opts.io, d) catch {};
            gpa.free(d);
        }
        for (st.rel) |r| gpa.free(r);
        if (st.rel.len > 0) gpa.free(st.rel);
        if (st.list) |l| l.deinit(gpa);
        b.staging = null;
    }

    fn dropStaged(b: *Bridge) void {
        const s = b.staged orelse return;
        std.Io.Dir.cwd().deleteTree(b.opts.io, s.dir) catch {};
        b.gpa.free(s.dir);
        b.gpa.free(s.uri_list);
        b.gpa.free(s.gnome);
        b.staged = null;
    }

    const SetDir = struct { path: []u8, fd: Fd };

    /// <root>/<pid>-<n>/<k>, each level created 0700.
    fn newSetDir(b: *Bridge) anyerror!SetDir {
        const gpa = b.gpa;
        if (b.session_dir == null) b.session_dir = try b.createSessionDir();
        const k = b.next_set;
        b.next_set += 1;
        const path = try std.fmt.allocPrint(gpa, "{s}/{d}", .{ b.session_dir.?, k });
        errdefer gpa.free(path);
        const z = try gpa.dupeSentinel(u8, path, 0);
        defer gpa.free(z);
        if (std.c.mkdir(z, 0o700) != 0) return error.MkdirFailed;
        const fd = std.c.open(z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (fd < 0) return error.OpenFailed;
        return .{ .path = path, .fd = fd };
    }

    fn createSessionDir(b: *Bridge) anyerror![]u8 {
        const gpa = b.gpa;
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const root = b.opts.staging_root orelse defaultStagingRoot(&buf, sys.getenv("XDG_RUNTIME_DIR")) orelse return error.NoRuntimeDir;
        try mkdirAll(gpa, root);
        removeStaleSessions(b.opts.io, root);
        const pid = std.c.getpid();
        while (true) {
            const n = session_counter.fetchAdd(1, .monotonic);
            const path = try std.fmt.allocPrint(gpa, "{s}/{d}-{d}", .{ std.mem.trimEnd(u8, root, "/"), pid, n });
            errdefer gpa.free(path);
            const z = try gpa.dupeSentinel(u8, path, 0);
            defer gpa.free(z);
            if (std.c.mkdir(z, 0o700) == 0) return path;
            if (std.c.errno(@as(c_int, -1)) != .EXIST) return error.MkdirFailed;
            gpa.free(path);
        }
    }
};

/// Drops entries whose real path escapes their selected directory; paths become real paths (stillReal).
fn confine(gpa: Allocator, io: std.Io, lf: *cliprdr.LocalFiles) anyerror!void {
    const files = lf.list.files;
    const real = try gpa.alloc(?[]u8, files.len);
    @memset(real, null);
    defer {
        for (real) |r| if (r) |x| gpa.free(x);
        gpa.free(real);
    }
    var top: ?[]const u8 = null;
    var kept: usize = 0;
    for (files, 0..) |f, i| {
        const r = realPath(gpa, io, lf.paths[i]) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
        const is_top = std.mem.indexOfScalar(u8, f.name, '\\') == null;
        const inside = blk: {
            const x = r orelse break :blk false;
            if (is_top) break :blk true;
            const t = top orelse break :blk false;
            break :blk x.len > t.len and std.mem.startsWith(u8, x, t) and x[t.len] == '/';
        };
        if (inside) {
            real[i] = r;
            kept += 1;
        } else if (r) |x| gpa.free(x);
        // Kept in `real` until the end, so `top` stays valid.
        if (is_top) top = if (inside) r else null;
    }
    if (kept == files.len) {
        for (lf.paths, real) |*p, *r| {
            gpa.free(p.*);
            p.* = r.*.?;
            r.* = null;
        }
        return;
    }
    const new_files = try gpa.alloc(cliprdr.FileDescriptor, kept);
    errdefer gpa.free(new_files);
    const new_paths = try gpa.alloc([]u8, kept);
    var j: usize = 0;
    for (files, lf.paths, real) |f, p, *r| {
        gpa.free(p);
        if (r.*) |x| {
            new_files[j] = f;
            new_paths[j] = x;
            r.* = null;
            j += 1;
        } else gpa.free(f.name);
    }
    gpa.free(files);
    gpa.free(lf.paths);
    lf.* = .{ .list = .{ .files = new_files }, .paths = new_paths };
}

fn realPath(gpa: Allocator, io: std.Io, path: []const u8) anyerror![]u8 {
    const z = try std.Io.Dir.cwd().realPathFileAlloc(io, path, gpa);
    defer gpa.free(z);
    return gpa.dupe(u8, z);
}

fn stillReal(gpa: Allocator, io: std.Io, path: []const u8) Allocator.Error!bool {
    const r = realPath(gpa, io, path) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return false,
    };
    defer gpa.free(r);
    return std.mem.eql(u8, r, path);
}

const tree_busy_ms = 100;

fn freeTexts(gpa: Allocator, x: Texts) void {
    gpa.free(x.uri_list);
    gpa.free(x.gnome);
}

/// Options.private_root or its default, resolved as in ownMountsRoot.
fn privateRoot(gpa: Allocator, opts: Options) Allocator.Error!?[]u8 {
    return ownMountsRoot(gpa, opts.private_root orelse opts.staging_root);
}

/// Root of own mounts, never touched by the connection's thread: `given_root` or $XDG_RUNTIME_DIR/omastation.
pub fn ownMountsRoot(gpa: Allocator, given_root: ?[]const u8) Allocator.Error!?[]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const given: []const u8 = given_root orelse blk: {
        const rd = sys.getenv("XDG_RUNTIME_DIR") orelse return null;
        if (rd.len == 0 or rd[0] != '/') return null;
        break :blk std.fmt.bufPrint(&buf, "{s}/omastation", .{std.mem.trimEnd(u8, rd, "/")}) catch return null;
    };
    const trimmed = std.mem.trimEnd(u8, given, "/");
    if (trimmed.len == 0 or trimmed[0] != '/') return null;
    var out: [std.fs.max_path_bytes]u8 = undefined;
    if (canonical(trimmed, &out)) |r| return try gpa.dupe(u8, r);
    const parent = std.fs.path.dirname(trimmed) orelse return try gpa.dupe(u8, trimmed);
    if (canonical(parent, &out)) |r| return try std.fs.path.join(gpa, &.{ r, std.fs.path.basename(trimmed) });
    return try gpa.dupe(u8, trimmed);
}

/// realpath(3) of a directory outside own mounts; null on failure.
fn canonical(path: []const u8, out: *[std.fs.max_path_bytes]u8) ?[]const u8 {
    var z: [std.fs.max_path_bytes + 1]u8 = undefined;
    if (path.len > std.fs.max_path_bytes) return null;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    const r = std.c.realpath(z[0..path.len :0], out) orelse return null;
    return std.mem.sliceTo(r, 0);
}

fn removeDir(path: []const u8) void {
    var z: [std.fs.max_path_bytes + 1]u8 = undefined;
    if (path.len > std.fs.max_path_bytes) return;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    _ = std.c.rmdir(z[0..path.len :0]);
}

fn refusePath(b: *const Bridge, path: []const u8) bool {
    const root = b.private_root orelse return false;
    if (!leadsInto(path, root)) return false;
    log.warn("not copying a file of omastation's own mounts to the client", .{});
    return true;
}

fn isUnder(p: []const u8, root: []const u8) bool {
    return std.mem.startsWith(u8, p, root) and (p.len == root.len or p[root.len] == '/');
}

/// Resolves symbolic links by hand without touching anything in `root`. A missing component
/// gives false; over 40 links or an overlong path gives true.
pub fn leadsInto(path: []const u8, root: []const u8) bool {
    const max = std.fs.max_path_bytes;
    var cur_buf: [max]u8 = undefined;
    var cur_len: usize = 0;
    var bufs: [2][2 * max]u8 = undefined;
    var which: usize = 0;
    if (path.len > bufs[0].len) return true;
    @memcpy(bufs[0][0..path.len], path);
    var rest: []const u8 = bufs[0][0..path.len];
    var links: u32 = 0;
    while (true) {
        rest = std.mem.trimStart(u8, rest, "/");
        if (rest.len == 0) break;
        const end = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
        const comp = rest[0..end];
        rest = rest[end..];
        if (std.mem.eql(u8, comp, ".")) continue;
        if (std.mem.eql(u8, comp, "..")) {
            cur_len = std.mem.lastIndexOfScalar(u8, cur_buf[0..cur_len], '/') orelse 0;
            continue;
        }
        const keep = cur_len;
        if (cur_len + 1 + comp.len > max) return true;
        cur_buf[cur_len] = '/';
        @memcpy(cur_buf[cur_len + 1 ..][0..comp.len], comp);
        cur_len += 1 + comp.len;
        const cur = cur_buf[0..cur_len];
        if (isUnder(cur, root)) return true;
        var z: [max + 1]u8 = undefined;
        @memcpy(z[0..cur.len], cur);
        z[cur.len] = 0;
        var st: libc.struct_stat = undefined;
        if (libc.lstat(@ptrCast(&z), &st) != 0) return false;
        if (st.st_mode & libc.S_IFMT != libc.S_IFLNK) continue;
        links += 1;
        if (links > 40) return true;
        var target_buf: [max]u8 = undefined;
        const n = libc.readlink(@ptrCast(&z), &target_buf, target_buf.len);
        if (n <= 0 or n >= target_buf.len) return true;
        const target = target_buf[0..@intCast(n)];
        which ^= 1;
        const next = &bufs[which];
        if (target.len + 1 + rest.len > next.len) return true;
        @memcpy(next[0..target.len], target);
        next[target.len] = '/';
        @memcpy(next[target.len + 1 ..][0..rest.len], rest);
        rest = next[0 .. target.len + 1 + rest.len];
        cur_len = if (target[0] == '/') 0 else keep;
    }
    return isUnder(cur_buf[0..cur_len], root);
}

fn isDirectory(f: cliprdr.FileDescriptor) bool {
    return f.flags & cliprdr.FD_ATTRIBUTES != 0 and f.attributes & cliprdr.FILE_ATTRIBUTE_DIRECTORY != 0;
}

fn mkdirAll(gpa: Allocator, path: []const u8) anyerror!void {
    const z = try gpa.dupeSentinel(u8, path, 0);
    defer gpa.free(z);
    var i: usize = 1;
    while (i <= z.len) : (i += 1) {
        if (i < z.len and z[i] != '/') continue;
        const saved = z[i];
        z[i] = 0;
        defer z[i] = saved;
        if (std.c.mkdir(z[0..i :0], 0o700) != 0 and std.c.errno(@as(c_int, -1)) != .EXIST) return error.MkdirFailed;
    }
}

/// Removes staging directories of omastation processes that no longer exist.
fn removeStaleSessions(io: std.Io, root: []const u8) void {
    var dir = std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch return;
    defer dir.close(io);
    var names: [32][64]u8 = undefined;
    var lens: [32]usize = undefined;
    var n: usize = 0;
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        if (n == names.len) break;
        const dash = std.mem.indexOfScalar(u8, e.name, '-') orelse continue;
        const pid = std.fmt.parseInt(std.c.pid_t, e.name[0..dash], 10) catch continue;
        if (pid <= 0 or pid == std.c.getpid() or e.name.len > names[0].len) continue;
        if (std.c.kill(pid, @fromBackingInt(@intCast(0))) == 0 or std.c.errno(@as(c_int, -1)) != .SRCH) continue;
        @memcpy(names[n][0..e.name.len], e.name);
        lens[n] = e.name.len;
        n += 1;
    }
    for (names[0..n], lens[0..n]) |*name, len| dir.deleteTree(io, name[0..len]) catch {};
}

/// Parents of `rel` (and `rel` itself when `whole`) below `dir_fd`; existing ones are fine.
fn makeDirs(dir_fd: Fd, rel: []const u8, whole: bool) anyerror!void {
    var buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    if (rel.len >= buf.len) return error.NameTooLong;
    @memcpy(buf[0..rel.len], rel);
    buf[rel.len] = 0;
    var i: usize = 0;
    while (i <= rel.len) : (i += 1) {
        const end = i == rel.len;
        if (!end and rel[i] != '/') continue;
        if (end and !whole) break;
        buf[i] = 0;
        defer buf[i] = if (end) 0 else '/';
        if (std.c.mkdirat(dir_fd, buf[0..i :0], 0o755) != 0 and std.c.errno(@as(c_int, -1)) != .EXIST) return error.MkdirFailed;
    }
}

/// Never an existing file, never through a symbolic link.
fn createFile(dir_fd: Fd, rel: []const u8) anyerror!Fd {
    var buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    if (rel.len >= buf.len) return error.NameTooLong;
    @memcpy(buf[0..rel.len], rel);
    buf[rel.len] = 0;
    const fd = std.c.openat(dir_fd, buf[0..rel.len :0], .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, @as(std.c.mode_t, 0o644));
    if (fd < 0) return error.CreateFailed;
    return fd;
}

fn pwriteAll(fd: Fd, data: []const u8, offset: u64) error{WriteFailed}!void {
    var done: usize = 0;
    while (done < data.len) {
        const rc = std.c.pwrite(fd, data.ptr + done, data.len - done, @intCast(offset + done));
        if (rc < 0) {
            if (std.c.errno(rc) == .INTR) continue;
            return error.WriteFailed;
        }
        if (rc == 0) return error.WriteFailed;
        done += @intCast(rc);
    }
}

test "defaultStagingRoot" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("/run/user/1000/omastation/clipboard", defaultStagingRoot(&buf, "/run/user/1000").?);
    try std.testing.expectEqualStrings("/run/user/1000/omastation/clipboard", defaultStagingRoot(&buf, "/run/user/1000/").?);
    try std.testing.expect(defaultStagingRoot(&buf, null) == null);
    try std.testing.expect(defaultStagingRoot(&buf, "") == null);
    try std.testing.expect(defaultStagingRoot(&buf, "relative") == null);
    var small: [8]u8 = undefined;
    try std.testing.expect(defaultStagingRoot(&small, "/run/user/1000") == null);
}

test "isPlainAbsolutePath" {
    try std.testing.expect(isPlainAbsolutePath("/home/u/a.txt"));
    try std.testing.expect(!isPlainAbsolutePath("/"));
    try std.testing.expect(!isPlainAbsolutePath("a.txt"));
    try std.testing.expect(!isPlainAbsolutePath("/home/u/../etc"));
    try std.testing.expect(!isPlainAbsolutePath("/home/./u"));
    try std.testing.expect(!isPlainAbsolutePath("/home//u"));
    try std.testing.expect(!isPlainAbsolutePath("/home/u/"));
}

test "Messages splits back-to-back PDUs" {
    const two = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 } ++ [_]u8{ 5, 0, 1, 0, 2, 0, 0, 0, 'h', 'i' };
    var m: Messages = .{ .rest = &two };
    try std.testing.expectEqual(@as(usize, 8), m.next().?.len);
    try std.testing.expectEqualStrings("hi", m.next().?[8..]);
    try std.testing.expect(m.next() == null);
    var cut: Messages = .{ .rest = two[0..12] };
    _ = cut.next();
    try std.testing.expect(cut.next() == null);
}

test {
    std.testing.refAllDecls(Bridge);
}
