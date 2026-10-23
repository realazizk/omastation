//! FUSE request layer of a redirected drive: Linux file system requests in, MS-RDPEFS
//! Drive I/O Requests (2.2.3.3) out, client responses (2.2.3.4) back as replies. Nothing
//! blocks: each request is a `Job` advanced one step per response. Mapping:
//!   lookup, getattr  CREATE FILE_OPEN, query Basic and Standard information, CLOSE
//!   setattr          FileEndOfFileInformation, FileBasicInformation (chmod: READONLY)
//!   open, create     CREATE; generic rights sent as the specific rights they map to
//!   read, write      READ / WRITE in max_read / max_write pieces; O_APPEND at EndOfFile
//!   flush, fsync     answered at once: writes are forwarded as they happen
//!   release          CLOSE
//!   opendir, mkdir   CREATE FILE_DIRECTORY_FILE (mkdir: FILE_CREATE)
//!   readdir          QUERY_DIRECTORY FileBothDirectoryInformation; "." and ".." local
//!   unlink, rmdir    CREATE with DELETE, FileDispositionInformation, CLOSE
//!   rename           CREATE with DELETE, FileRenameInformation (2.2.3.3.9.1)
//!   statfs           QUERY_VOLUME_INFORMATION FileFsFullSizeInformation (2.2.3.3.6)

const std = @import("std");
const rdpdr = @import("../channel/rdpdr.zig");
const bytes = @import("../core/bytes.zig");

const log = std.log.scoped(.drives);
const Allocator = std.mem.Allocator;
const E = std.os.linux.E;

/// The kernel's request handle (fuse_req_t), or a test's request number.
pub const Req = u64;

pub fn errno(e: E) u16 {
    return @intCast(@backingInt(e));
}

/// FUSE_ROOT_ID.
pub const root_ino: u64 = 1;

/// Linux open(2) flags (asm-generic/fcntl.h).
pub const o = struct {
    pub const accmode: u32 = 0o3;
    pub const rdonly: u32 = 0o0;
    pub const wronly: u32 = 0o1;
    pub const rdwr: u32 = 0o2;
    pub const creat: u32 = 0o100;
    pub const excl: u32 = 0o200;
    pub const trunc: u32 = 0o1000;
    pub const append: u32 = 0o2000;
    pub const dsync: u32 = 0o10000;
    pub const sync: u32 = 0o4010000;
};

pub const rename_noreplace: u32 = 1;

/// Name offsets in struct fuse_dirent / fuse_direntplus (linux/fuse.h FUSE_NAME_OFFSET*).
pub const dirent_name_offset: usize = 24;
pub const direntplus_name_offset: usize = 152;

/// Reply buffer bytes of a readdir (plus) entry (FUSE_DIRENT_ALIGN, as fuse_add_direntry).
pub fn direntSize(plus: bool, name_len: usize) usize {
    const n = (if (plus) direntplus_name_offset else dirent_name_offset) + name_len;
    return std.mem.alignForward(usize, n, 8);
}

pub const Time = struct {
    sec: i64 = 0,
    nsec: u32 = 0,
};

/// struct stat, what FUSE uses of it.
pub const Attr = struct {
    ino: u64 = 0,
    mode: u32 = 0,
    nlink: u32 = 1,
    uid: u32 = 0,
    gid: u32 = 0,
    size: u64 = 0,
    /// 512-byte blocks.
    blocks: u64 = 0,
    blksize: u32 = 0,
    atime: Time = .{},
    mtime: Time = .{},
    ctime: Time = .{},
};

/// struct fuse_entry_param. `ino` 0 is a negative entry.
pub const Entry = struct {
    ino: u64,
    attr: Attr = .{},
    attr_timeout: f64 = 0,
    entry_timeout: f64 = 0,
};

/// What fuse_reply_open / fuse_reply_create take of struct fuse_file_info.
pub const FileReply = struct {
    fh: u64,
    keep_cache: bool = false,
    direct_io: bool = false,
};

/// struct statvfs.
pub const StatFs = struct {
    bsize: u64 = 0,
    frsize: u64 = 0,
    blocks: u64 = 0,
    bfree: u64 = 0,
    bavail: u64 = 0,
    files: u64 = 0,
    ffree: u64 = 0,
    namemax: u64 = 255,
};

/// One readdir entry; `off` is the offset of the next one.
pub const DirEntry = struct {
    name: []const u8,
    off: u64,
    entry: Entry,
};

/// fuse_reply_* in fuse.zig, or a test recorder. Every request gets exactly one call.
pub const Replier = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// fuse_reply_err; 0 is success.
        err: *const fn (ptr: *anyopaque, req: Req, err: u16) void,
        entry: *const fn (ptr: *anyopaque, req: Req, e: *const Entry) void,
        create: *const fn (ptr: *anyopaque, req: Req, e: *const Entry, f: FileReply) void,
        attr: *const fn (ptr: *anyopaque, req: Req, a: *const Attr, timeout: f64) void,
        open: *const fn (ptr: *anyopaque, req: Req, f: FileReply) void,
        data: *const fn (ptr: *anyopaque, req: Req, data: []const u8) void,
        written: *const fn (ptr: *anyopaque, req: Req, n: usize) void,
        statfs: *const fn (ptr: *anyopaque, req: Req, s: *const StatFs) void,
        /// `entries` all fit in `size` bytes (`direntSize`).
        dir: *const fn (ptr: *anyopaque, req: Req, plus: bool, size: usize, entries: []const DirEntry) void,
    };
};

/// Instant for setattr: a time, or "now" (UTIME_NOW).
pub const SetTime = union(enum) {
    now,
    ns: i128,
};

/// The attributes a setattr changes (FUSE_SET_ATTR_*); null: unchanged.
pub const SetAttr = struct {
    size: ?u64 = null,
    atime: ?SetTime = null,
    mtime: ?SetTime = null,
    mode: ?u32 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,
};

/// A FUSE low-level request (struct fuse_lowlevel_ops); names and data are borrowed
/// for the duration of `Fs.handle`. `fh` is what open/opendir answered.
pub const Request = union(enum) {
    lookup: struct { parent: u64, name: []const u8 },
    getattr: struct { ino: u64, fh: ?u64 = null },
    setattr: struct { ino: u64, fh: ?u64 = null, set: SetAttr },
    open: struct { ino: u64, flags: u32 },
    create: struct { parent: u64, name: []const u8, mode: u32 = 0o644, flags: u32 },
    read: struct { ino: u64, fh: u64, size: usize, offset: i64 },
    write: struct { ino: u64, fh: u64, data: []const u8, offset: i64 },
    flush: struct { ino: u64, fh: u64 },
    fsync: struct { ino: u64, fh: u64 },
    release: struct { ino: u64, fh: u64 },
    opendir: struct { ino: u64, flags: u32 = 0 },
    readdir: struct { ino: u64, fh: u64, size: usize, offset: i64, plus: bool = false },
    releasedir: struct { ino: u64, fh: u64 },
    fsyncdir: struct { ino: u64, fh: u64 },
    mkdir: struct { parent: u64, name: []const u8, mode: u32 = 0o755 },
    unlink: struct { parent: u64, name: []const u8 },
    rmdir: struct { parent: u64, name: []const u8 },
    rename: struct { parent: u64, name: []const u8, newparent: u64, newname: []const u8, flags: u32 = 0 },
    statfs: struct { ino: u64 },
};

/// What a mount serves: a drive's `Fs.handler`, or the clipboard's file tree.
/// Every request is answered exactly once through the Replier the backend sets.
pub const Handler = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        handle: *const fn (ptr: *anyopaque, req: Req, r: Request) void,
        /// FUSE forget / forget_multi (no reply).
        forget: *const fn (ptr: *anyopaque, ino: u64, nlookup: u64) void,
        /// FUSE_INTERRUPT of a request still unanswered.
        interrupt: *const fn (ptr: *anyopaque, req: Req) void,
        /// Null once unmounted (every request was answered before).
        set_replier: *const fn (ptr: *anyopaque, r: ?Replier) void,
    };

    pub fn handle(h: Handler, req: Req, r: Request) void {
        h.vtable.handle(h.ptr, req, r);
    }

    pub fn forget(h: Handler, ino: u64, nlookup: u64) void {
        h.vtable.forget(h.ptr, ino, nlookup);
    }

    pub fn interrupt(h: Handler, req: Req) void {
        h.vtable.interrupt(h.ptr, req);
    }

    pub fn setReplier(h: Handler, r: ?Replier) void {
        h.vtable.set_replier(h.ptr, r);
    }
};

pub const Options = struct {
    uid: u32 = 0,
    gid: u32 = 0,
    /// EROFS on every change; also set for a FILE_READ_ONLY_VOLUME (`probe`).
    read_only: bool = false,
    /// Seconds the kernel may cache names, attributes and absent names.
    entry_timeout: f64 = 1.0,
    attr_timeout: f64 = 1.0,
    negative_timeout: f64 = 1.0,
    /// Largest DR_READ_REQ / DR_WRITE_REQ Length (2.2.1.4.3, 2.2.1.4.4); bigger requests are split.
    max_read: u32 = 64 * 1024,
    max_write: u32 = 64 * 1024,
    /// Entries kept per listing, so a client that never ends one cannot take all memory.
    max_listing: u32 = 100_000,
    /// st_blksize.
    blksize: u32 = 64 * 1024,
    /// Current time, ns since the Unix epoch (setattr "now").
    clock: *const fn () i128 = realtimeNs,
};

pub fn realtimeNs() i128 {
    var ts: std.os.linux.timespec = undefined;
    if (std.os.linux.clock_gettime(.REALTIME, &ts) != 0) return 0;
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

pub const Link = struct {
    session: *rdpdr.Session,
    out: *rdpdr.Outbox,
};

/// What `probe` learned of the volume (FileFsAttributeInformation).
pub const Volume = struct {
    /// FILE_READ_ONLY_VOLUME ([MS-FSCC] 2.5.1).
    read_only: bool = false,
    /// MaximumComponentNameLength.
    namemax: u32 = 255,
};

const Node = struct {
    ino: u64,
    /// 0: not reachable by name any more (removed, or replaced by a rename).
    parent: u64,
    name: []u8,
    nlookup: u64 = 0,
    /// Nodes whose parent this is: a parent outlives its children.
    children: u32 = 0,
};

const NameKey = struct {
    parent: u64,
    name: []const u8,
};

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

const Listed = struct {
    name: []u8,
    meta: Meta,
};

/// An open file or directory (fuse_file_info.fh).
const Handle = struct {
    fh: u64,
    ino: u64,
    file_id: u32,
    dir: bool,
    writable: bool,
    append: bool,
    /// An append write is in progress; the others wait in `waiters`.
    busy: bool = false,
    waiters: std.ArrayList(u64) = .empty,
    /// Directory listing taken at offset 0.
    listing: std.ArrayList(Listed) = .empty,
    listed: bool = false,
    listing_job: ?u64 = null,
    /// `Fs.generation` when the listing started.
    listing_gen: u64 = 0,
};

/// From FileBasicInformation + FileStandardInformation, or a directory entry.
const Meta = struct {
    creation: u64 = 0,
    access: u64 = 0,
    write: u64 = 0,
    change: u64 = 0,
    attributes: u32 = 0,
    eof: u64 = 0,
    alloc: u64 = 0,
    links: u32 = 1,
    dir: bool = false,
};

const Kind = enum {
    lookup,
    getattr,
    setattr,
    open,
    create,
    mkdir,
    read,
    write,
    release,
    opendir,
    readdir,
    unlink,
    rmdir,
    rename,
    statfs,
    probe,
    close,
};

/// One request in progress. Freed only when no IRP of it is outstanding.
const Job = struct {
    id: u64,
    kind: Kind,
    /// Null once answered early (interrupt, abort) or for internal jobs.
    req: ?Req,
    phase: u8 = 0,
    inflight: u8 = 0,
    /// First error (errno) and its NTSTATUS.
    err: u16 = 0,
    status: u32 = 0,
    /// FileId this job opened and closes when it ends.
    temp: ?u32 = null,
    file_id: u32 = 0,
    fh: u64 = 0,
    ino: u64 = 0,
    parent: u64 = 0,
    newparent: u64 = 0,
    name: []u8 = &.{},
    newname: []u8 = &.{},
    /// UTF-16LE drive paths (owned).
    path: []u8 = &.{},
    path2: []u8 = &.{},
    data: std.ArrayList(u8) = .empty,
    /// SetBuffer of a set information request.
    info: std.ArrayList(u8) = .empty,
    basic: ?rdpdr.FileBasicInformation = null,
    standard: ?rdpdr.FileStandardInformation = null,
    volume: ?rdpdr.VolumeInformation = null,
    flags: u32 = 0,
    offset: u64 = 0,
    size: u64 = 0,
    done: u64 = 0,
    /// Length asked by the last read or write piece, and what the client answered.
    want: u32 = 0,
    piece: u32 = 0,
    set: SetAttr = .{},
    plus: bool = false,
    /// The listing ended (STATUS_NO_MORE_FILES).
    eof: bool = false,
    /// Barrier: CLOSEs numbered below this finish before the job starts (unlink, rmdir, rename).
    after_close: u64 = 0,
    /// Number of the job's own CLOSE in flight (0: none).
    close_seq: u64 = 0,
    /// Answered (or abandoned): no reply, no new main-phase IRPs.
    answered: bool = false,
};

/// A request `Session.submit` cannot take yet: one read and one write in flight per
/// file without ENABLE_ASYNCIO (3.3.5.2.8), or the session's outstanding limit.
const Deferred = struct {
    job: u64,
    req: rdpdr.IoRequest,
};

pub const Fs = struct {
    gpa: Allocator,
    link: Link,
    device_id: u32,
    opts: Options,
    replier: ?Replier = null,
    volume: Volume = .{},

    nodes: std.AutoHashMapUnmanaged(u64, *Node) = .empty,
    names: std.HashMapUnmanaged(NameKey, u64, NameCtx, 80) = .empty,
    next_ino: u64 = root_ino + 1,
    handles: std.AutoHashMapUnmanaged(u64, *Handle) = .empty,
    next_fh: u64 = 1,
    jobs: std.AutoHashMapUnmanaged(u64, *Job) = .empty,
    next_job: u64 = 1,
    deferred: std.ArrayList(Deferred) = .empty,
    /// Jobs to advance (all their IRPs answered, or not started).
    ready: std.ArrayList(u64) = .empty,
    closes: std.ArrayList(u64) = .empty,
    next_close: u64 = 1,
    /// Jobs waiting for earlier CLOSEs (unlink, rmdir, rename).
    barrier: std.ArrayList(u64) = .empty,
    /// No more requests: everything failed with EIO.
    dead: bool = false,
    /// Bumped when a change starts and ends: a listing taken under an older generation
    /// may hold attributes a local change made stale.
    generation: u64 = 0,
    pumping: bool = false,
    on_probe: ?struct { ctx: *anyopaque, f: *const fn (ctx: *anyopaque, fs: *Fs) void } = null,

    pub fn init(gpa: Allocator, link: Link, device_id: u32, opts: Options) Allocator.Error!Fs {
        var fs: Fs = .{ .gpa = gpa, .link = link, .device_id = device_id, .opts = opts };
        const root = try gpa.create(Node);
        errdefer gpa.destroy(root);
        root.* = .{ .ino = root_ino, .parent = 0, .name = &.{}, .nlookup = 1 };
        try fs.nodes.put(gpa, root_ino, root);
        return fs;
    }

    pub fn deinit(fs: *Fs) void {
        fs.abort(errno(.IO), false);
        var it = fs.nodes.valueIterator();
        while (it.next()) |n| {
            fs.gpa.free(n.*.name);
            fs.gpa.destroy(n.*);
        }
        fs.nodes.deinit(fs.gpa);
        fs.names.deinit(fs.gpa);
        fs.handles.deinit(fs.gpa);
        fs.jobs.deinit(fs.gpa);
        fs.deferred.deinit(fs.gpa);
        fs.ready.deinit(fs.gpa);
        fs.closes.deinit(fs.gpa);
        fs.barrier.deinit(fs.gpa);
    }

    /// The drive refuses changes: configured so, or a read-only volume.
    pub fn readOnly(fs: *const Fs) bool {
        return fs.opts.read_only or fs.volume.read_only;
    }

    pub fn pending(fs: *const Fs) usize {
        return fs.jobs.count();
    }

    pub fn openHandles(fs: *const Fs) usize {
        return fs.handles.count();
    }

    pub fn inodes(fs: *const Fs) usize {
        return fs.nodes.count();
    }

    pub fn handler(fs: *Fs) Handler {
        return .{ .ptr = fs, .vtable = &handler_vtable };
    }

    const handler_vtable: Handler.VTable = .{
        .handle = hHandle,
        .forget = hForget,
        .interrupt = hInterrupt,
        .set_replier = hSetReplier,
    };

    fn hHandle(ptr: *anyopaque, req: Req, r: Request) void {
        const fs: *Fs = @ptrCast(@alignCast(ptr));
        fs.handle(req, r);
    }

    fn hForget(ptr: *anyopaque, ino: u64, nlookup: u64) void {
        const fs: *Fs = @ptrCast(@alignCast(ptr));
        fs.forget(ino, nlookup);
    }

    fn hInterrupt(ptr: *anyopaque, req: Req) void {
        const fs: *Fs = @ptrCast(@alignCast(ptr));
        fs.interrupt(req);
    }

    fn hSetReplier(ptr: *anyopaque, r: ?Replier) void {
        const fs: *Fs = @ptrCast(@alignCast(ptr));
        fs.replier = r;
    }

    pub fn handle(fs: *Fs, req: Req, r: Request) void {
        if (fs.dead) return fs.replyErr(req, errno(.IO));
        fs.start(req, r) catch |e| fs.replyErr(req, errnoOfError(e));
        fs.pump();
    }

    pub fn forget(fs: *Fs, ino: u64, nlookup: u64) void {
        if (ino == root_ino) return;
        const n = fs.nodes.get(ino) orelse return;
        n.nlookup -|= nlookup;
        fs.maybeFree(n);
    }

    /// FUSE_INTERRUPT: EINTR now; the IRPs in flight finish without an answer.
    pub fn interrupt(fs: *Fs, req: Req) void {
        var it = fs.jobs.valueIterator();
        while (it.next()) |j| {
            if (j.*.req != null and j.*.req.? == req and !j.*.answered) {
                fs.answerErr(j.*, errno(.INTR));
                break;
            }
        }
        fs.pump();
    }

    /// An io_completed event of this device (`request.tag` is the job).
    pub fn ioCompleted(fs: *Fs, request: rdpdr.Request, io_status: u32, response: rdpdr.IoResponse) void {
        const job = fs.jobs.get(request.tag) orelse return fs.pump();
        if (request.major == .close) fs.closeDone(job);
        fs.record(job, request, io_status, response);
        fs.pump();
    }

    /// An io_cancelled event: the request will never be answered (3.1.5.1, 3.3.5.2.6).
    pub fn ioCancelled(fs: *Fs, request: rdpdr.Request) void {
        const job = fs.jobs.get(request.tag) orelse return fs.pump();
        if (request.major == .close) fs.closeDone(job);
        job.inflight -|= 1;
        fs.noteErr(job, rdpdr.status.cancelled, errno(.IO));
        if (job.inflight == 0) fs.markReady(job);
        fs.pump();
    }

    /// Retries what the session refused; call after its events (a completion frees a slot).
    pub fn retry(fs: *Fs) void {
        fs.pump();
    }

    /// Queries FileFsAttributeInformation (2.2.3.3.6) before mounting: FILE_READ_ONLY_VOLUME
    /// makes the drive read-only. `on_probe` is called when done, also on failure.
    pub fn probe(fs: *Fs) void {
        const job = fs.newJob(.probe, null) catch {
            if (fs.on_probe) |cb| cb.f(cb.ctx, fs);
            return;
        };
        fs.markReady(job);
        fs.pump();
    }

    /// Fails every request with `err` and forgets the open files, closing them on the client
    /// when `close_files`. Everything afterwards gets EIO.
    pub fn abort(fs: *Fs, err: u16, close_files: bool) void {
        if (fs.dead) return;
        fs.dead = true;
        var it = fs.jobs.valueIterator();
        while (it.next()) |j| {
            if (j.*.req != null and !j.*.answered) fs.answerErr(j.*, err);
        }
        var hit = fs.handles.valueIterator();
        while (hit.next()) |h| {
            if (close_files) fs.submitRaw(.{ .device_id = fs.device_id, .file_id = h.*.file_id, .body = .close }, 0);
            fs.freeHandle(h.*);
        }
        fs.handles.clearRetainingCapacity();
        var jt = fs.jobs.valueIterator();
        while (jt.next()) |j| {
            if (close_files) if (j.*.temp) |t| fs.submitRaw(.{ .device_id = fs.device_id, .file_id = t, .body = .close }, 0);
            fs.freeJob(j.*);
        }
        fs.jobs.clearRetainingCapacity();
        fs.deferred.clearRetainingCapacity();
        fs.ready.clearRetainingCapacity();
        fs.closes.clearRetainingCapacity();
        fs.barrier.clearRetainingCapacity();
    }

    fn start(fs: *Fs, req: Req, r: Request) Error!void {
        switch (r) {
            .lookup => |a| {
                const j = try fs.newJob(.lookup, req);
                j.parent = a.parent;
                j.name = try fs.gpa.dupe(u8, a.name);
                fs.markReady(j);
            },
            .getattr => |a| {
                const j = try fs.newJob(.getattr, req);
                j.ino = a.ino;
                j.fh = a.fh orelse 0;
                fs.markReady(j);
            },
            .setattr => |a| {
                const j = try fs.newJob(.setattr, req);
                j.ino = a.ino;
                j.fh = a.fh orelse 0;
                j.set = a.set;
                fs.markReady(j);
            },
            .open => |a| {
                const j = try fs.newJob(.open, req);
                j.ino = a.ino;
                j.flags = a.flags;
                fs.markReady(j);
            },
            .opendir => |a| {
                const j = try fs.newJob(.opendir, req);
                j.ino = a.ino;
                fs.markReady(j);
            },
            .create => |a| {
                const j = try fs.newJob(.create, req);
                j.parent = a.parent;
                j.name = try fs.gpa.dupe(u8, a.name);
                j.flags = a.flags;
                fs.markReady(j);
            },
            .mkdir => |a| {
                const j = try fs.newJob(.mkdir, req);
                j.parent = a.parent;
                j.name = try fs.gpa.dupe(u8, a.name);
                fs.markReady(j);
            },
            .read => |a| {
                if (a.offset < 0) return error.Invalid;
                const j = try fs.newJob(.read, req);
                j.fh = a.fh;
                j.offset = @intCast(a.offset);
                j.size = a.size;
                fs.markReady(j);
            },
            .write => |a| {
                if (a.offset < 0) return error.Invalid;
                const j = try fs.newJob(.write, req);
                j.fh = a.fh;
                j.offset = @intCast(a.offset);
                j.size = a.data.len;
                j.data.appendSlice(fs.gpa, a.data) catch |e| {
                    fs.freeJob(j);
                    _ = fs.jobs.remove(j.id);
                    return e;
                };
                fs.markReady(j);
            },
            .flush, .fsync, .fsyncdir => fs.replyErr(req, 0),
            inline .release, .releasedir => |a| {
                const j = try fs.newJob(.release, req);
                j.fh = a.fh;
                fs.markReady(j);
            },
            .readdir => |a| {
                if (a.offset < 0) return error.Invalid;
                const j = try fs.newJob(.readdir, req);
                j.fh = a.fh;
                j.ino = a.ino;
                j.offset = @intCast(a.offset);
                j.size = a.size;
                j.plus = a.plus;
                fs.markReady(j);
            },
            inline .unlink, .rmdir => |a| {
                const j = try fs.newJob(if (r == .unlink) .unlink else .rmdir, req);
                j.parent = a.parent;
                j.name = try fs.gpa.dupe(u8, a.name);
                j.after_close = fs.next_close;
                fs.markReady(j);
            },
            .rename => |a| {
                const j = try fs.newJob(.rename, req);
                j.parent = a.parent;
                j.newparent = a.newparent;
                j.name = try fs.gpa.dupe(u8, a.name);
                j.newname = try fs.gpa.dupe(u8, a.newname);
                j.flags = a.flags;
                j.after_close = fs.next_close;
                fs.markReady(j);
            },
            .statfs => {
                const j = try fs.newJob(.statfs, req);
                fs.markReady(j);
            },
        }
    }

    /// Advances ready jobs and resubmits deferred requests; never re-entered.
    fn pump(fs: *Fs) void {
        if (fs.pumping) return;
        fs.pumping = true;
        defer fs.pumping = false;
        while (true) {
            fs.flushDeferred();
            if (fs.ready.items.len == 0) break;
            const id = fs.ready.orderedRemove(0);
            const job = fs.jobs.get(id) orelse continue;
            if (job.inflight != 0) continue;
            fs.step(job);
        }
    }

    fn markReady(fs: *Fs, job: *Job) void {
        fs.ready.append(fs.gpa, job.id) catch {
            // Out of memory: the job cannot be advanced; answer now.
            fs.answerErr(job, errno(.NOMEM));
        };
    }

    fn newJob(fs: *Fs, kind: Kind, req: ?Req) Allocator.Error!*Job {
        const j = try fs.gpa.create(Job);
        errdefer fs.gpa.destroy(j);
        j.* = .{ .id = fs.next_job, .kind = kind, .req = req };
        try fs.jobs.put(fs.gpa, j.id, j);
        fs.next_job += 1;
        return j;
    }

    fn freeJob(fs: *Fs, j: *Job) void {
        fs.gpa.free(j.name);
        fs.gpa.free(j.newname);
        fs.gpa.free(j.path);
        fs.gpa.free(j.path2);
        j.data.deinit(fs.gpa);
        j.info.deinit(fs.gpa);
        fs.gpa.destroy(j);
    }

    /// Closes what the job opened, wakes the next append writer, forgets the job.
    fn end(fs: *Fs, job: *Job) void {
        if (mutates(job.kind) and job.phase != 0) fs.generation += 1;
        if (job.req != null and !job.answered) fs.answerErr(job, errno(.IO));
        if (job.temp) |t| fs.sendClose(t);
        if (job.kind == .write) if (fs.handles.get(job.fh)) |h| if (h.append) {
            // A queued writer that ended without starting holds nothing.
            if (job.phase != 0) h.busy = false;
            if (std.mem.indexOfScalar(u64, h.waiters.items, job.id)) |i| _ = h.waiters.orderedRemove(i);
            if (!h.busy) while (h.waiters.items.len > 0) {
                const next = h.waiters.orderedRemove(0);
                if (fs.jobs.get(next)) |w| {
                    fs.markReady(w);
                    break;
                }
            };
        };
        if (job.kind == .readdir) if (fs.handles.get(job.fh)) |h| if (h.listing_job == job.id) {
            h.listing_job = null;
        };
        _ = fs.jobs.remove(job.id);
        fs.freeJob(job);
    }

    fn noteErr(fs: *Fs, job: *Job, st: u32, err: u16) void {
        _ = fs;
        if (job.err != 0) return;
        job.err = if (err == 0) errno(.IO) else err;
        job.status = st;
    }

    /// Sends one IRP for `job`, deferred when the session cannot take it yet.
    fn send(fs: *Fs, job: *Job, file_id: u32, body: rdpdr.IoRequestBody) void {
        const req: rdpdr.IoRequest = .{ .device_id = fs.device_id, .file_id = file_id, .body = body };
        job.inflight += 1;
        if (fs.mustWait(req)) {
            fs.deferred.append(fs.gpa, .{ .job = job.id, .req = req }) catch return fs.refused(job, error.OutOfMemory);
            return;
        }
        _ = fs.link.session.submit(req, job.id, fs.link.out) catch |e| switch (e) {
            error.WouldBlock, error.TooManyRequests, error.NotReady => {
                fs.deferred.append(fs.gpa, .{ .job = job.id, .req = req }) catch return fs.refused(job, error.OutOfMemory);
            },
            else => fs.refused(job, e),
        };
    }

    fn refused(fs: *Fs, job: *Job, e: anyerror) void {
        // A CLOSE is the only IRP of its phase: a refused one is done.
        fs.closeDone(job);
        job.inflight -= 1;
        fs.noteErr(job, rdpdr.status.unsuccessful, errnoOfError(e));
        if (job.inflight == 0) fs.markReady(job);
    }

    /// Order kept behind deferred requests on the same FileId: reads behind reads, writes
    /// behind writes (3.3.5.2.8, 3.3.5.2.9), anything else behind all; creates behind creates.
    fn mustWait(fs: *const Fs, req: rdpdr.IoRequest) bool {
        for (fs.deferred.items) |d| if (overtakes(req, d.req)) return true;
        return false;
    }

    /// `req` would pass `earlier` if sent first.
    fn overtakes(req: rdpdr.IoRequest, earlier: rdpdr.IoRequest) bool {
        if (req.body == .create or earlier.body == .create) return req.body == .create and earlier.body == .create;
        if (req.file_id != earlier.file_id) return false;
        const a = req.majorFunction();
        const b = earlier.majorFunction();
        const rw = (a == .read or a == .write) and (b == .read or b == .write);
        return !rw or a == b;
    }

    fn flushDeferred(fs: *Fs) void {
        var i: usize = 0;
        // Requests still blocked in this pass: later ones must not pass them.
        var blocked: [16]rdpdr.IoRequest = undefined;
        var nblocked: usize = 0;
        outer: while (i < fs.deferred.items.len) {
            const d = fs.deferred.items[i];
            const job = fs.jobs.get(d.job) orelse {
                _ = fs.deferred.orderedRemove(i);
                continue;
            };
            for (blocked[0..nblocked]) |b| if (overtakes(d.req, b)) {
                i += 1;
                continue :outer;
            };
            if (fs.link.session.submit(d.req, d.job, fs.link.out)) |_| {
                _ = fs.deferred.orderedRemove(i);
            } else |e| switch (e) {
                error.WouldBlock => {
                    if (nblocked == blocked.len) return;
                    blocked[nblocked] = d.req;
                    nblocked += 1;
                    i += 1;
                },
                error.TooManyRequests, error.NotReady => return,
                else => {
                    _ = fs.deferred.orderedRemove(i);
                    fs.refused(job, e);
                },
            }
        }
    }

    /// Submits outside any job (closes during abort): errors are dropped.
    fn submitRaw(fs: *Fs, req: rdpdr.IoRequest, tag: u64) void {
        _ = fs.link.session.submit(req, tag, fs.link.out) catch {};
    }

    fn record(fs: *Fs, job: *Job, request: rdpdr.Request, st: u32, rsp: rdpdr.IoResponse) void {
        job.inflight -|= 1;
        defer if (job.inflight == 0) fs.markReady(job);
        const failed = st >> 31 != 0;
        switch (request.major) {
            .create => {
                // A FileId exists only after success (3.1.5): close it whatever happens to the job.
                if (!failed and rsp == .create) {
                    job.temp = rsp.create.file_id;
                    job.file_id = rsp.create.file_id;
                }
            },
            .query_information => if (!failed) {
                const buf = rsp.query_information;
                switch (@as(rdpdr.FileInformationClass, @fromBackingInt(request.information_class))) {
                    .basic => job.basic = rdpdr.FileBasicInformation.decode(buf) catch return fs.noteErr(job, st, errno(.IO)),
                    .standard => job.standard = rdpdr.FileStandardInformation.decode(buf) catch return fs.noteErr(job, st, errno(.IO)),
                    else => {},
                }
            },
            .query_volume_information => if (!failed) {
                const class: rdpdr.FsInformationClass = @fromBackingInt(request.information_class);
                job.volume = rdpdr.decodeVolumeInformation(class, rsp.query_volume_information) catch return fs.noteErr(job, st, errno(.IO));
            },
            .read => if (!failed) {
                job.data.appendSlice(fs.gpa, rsp.read) catch return fs.noteErr(job, st, errno(.NOMEM));
                job.piece = @intCast(rsp.read.len);
            },
            // More than was sent cannot have been written.
            .write => if (!failed) {
                job.piece = @min(rsp.write, job.want);
            },
            .directory_control => {
                // 2.2.3.3.10: STATUS_NO_MORE_FILES ends a listing,
                // STATUS_NO_SUCH_FILE on the first query is an empty one.
                if (st == rdpdr.status.no_more_files or (st == rdpdr.status.no_such_file and job.phase == 1)) {
                    job.eof = true;
                    return;
                }
                if (!failed) fs.takeEntries(job, rsp.query_directory) catch |e| return fs.noteErr(job, st, errnoOfError(e));
            },
            // A FileId ends with its Close Response whatever the status (3.1.1); FreeRDP may report a stale one.
            .close => return,
            else => {},
        }
        if (failed) {
            if (request.major == .read and st == rdpdr.status.end_of_file) {
                job.piece = 0;
                return;
            }
            // What failed, never on what (no names).
            log.debug("drive {d}: {t} class {d} failed: 0x{x:0>8}", .{ fs.device_id, request.major, request.information_class, st });
            fs.noteErr(job, st, statusErrno(st));
        }
    }

    fn step(fs: *Fs, job: *Job) void {
        // Interrupted while it waited (barrier, append queue): it never starts.
        if (job.answered and job.phase == 0 and job.req != null) return fs.end(job);
        if (job.phase == 0 and mutates(job.kind)) fs.generation += 1;
        switch (job.kind) {
            .lookup => fs.stepLookup(job),
            .getattr => fs.stepGetattr(job),
            .setattr => fs.stepSetattr(job),
            .open, .opendir => fs.stepOpen(job),
            .create, .mkdir => fs.stepCreate(job),
            .read => fs.stepRead(job),
            .write => fs.stepWrite(job),
            .release => fs.stepRelease(job),
            .readdir => fs.stepReaddir(job),
            .unlink, .rmdir => fs.stepRemove(job),
            .rename => fs.stepRename(job),
            .statfs => fs.stepStatfs(job),
            .probe => fs.stepProbe(job),
            .close => fs.end(job),
        }
    }

    /// Opens `path` for the job (its FileId is closed when the job ends).
    fn openPath(fs: *Fs, job: *Job, access: u32, disposition: u32, options: u32, attributes: u32) void {
        fs.send(job, 0, .{ .create = .{
            .desired_access = specificAccess(access),
            .file_attributes = attributes,
            .shared_access = rdpdr.file_share_read | rdpdr.file_share_write | rdpdr.file_share_delete,
            .create_disposition = disposition,
            .create_options = options,
            .path = job.path,
        } });
    }

    fn queryAttrs(fs: *Fs, job: *Job, file_id: u32) void {
        job.basic = null;
        job.standard = null;
        fs.send(job, file_id, .{ .query_information = .{ .file_information_class = .basic } });
        fs.send(job, file_id, .{ .query_information = .{ .file_information_class = .standard } });
    }

    fn stepLookup(fs: *Fs, job: *Job) void {
        switch (job.phase) {
            0 => {
                if (!nameOk(job.name)) return fs.finishErr(job, if (job.name.len > max_name) errno(.NAMETOOLONG) else 0);
                job.path = fs.childPath(job.parent, job.name) catch |e| return fs.finishErr(job, errnoOfError(e));
                job.phase = 1;
                fs.openPath(job, rdpdr.file_read_attributes | rdpdr.synchronize, rdpdr.file_open, 0, 0);
            },
            1 => {
                if (job.err != 0) return fs.finishErr(job, job.err);
                // Interrupted: nothing more is sent, the FileId is closed.
                if (job.answered) return fs.end(job);
                job.phase = 2;
                fs.queryAttrs(job, job.file_id);
            },
            else => {
                if (job.err != 0) return fs.finishErr(job, job.err);
                if (job.answered) return fs.end(job);
                const n = fs.child(job.parent, job.name) catch |e| return fs.finishErr(job, errnoOfError(e));
                // fuse_reply_entry counts one lookup.
                n.nlookup += 1;
                const e = fs.entryOf(n.ino, metaOf(job.basic.?, job.standard.?));
                job.answered = true;
                if (fs.replier) |rp| rp.vtable.entry(rp.ptr, job.req.?, &e);
                fs.end(job);
            },
        }
    }

    /// For a lookup, ENOENT (and 0: a name the client cannot hold) is a negative entry.
    fn finishErr(fs: *Fs, job: *Job, err: u16) void {
        if (job.kind == .lookup and (err == 0 or err == errno(.NOENT))) {
            if (job.req) |r| if (!job.answered) {
                job.answered = true;
                const e: Entry = .{ .ino = 0, .entry_timeout = fs.opts.negative_timeout };
                if (fs.replier) |rp| rp.vtable.entry(rp.ptr, r, &e);
            };
        } else {
            fs.answerErr(job, if (err == 0) errno(.IO) else err);
        }
        fs.end(job);
    }

    fn stepGetattr(fs: *Fs, job: *Job) void {
        switch (job.phase) {
            0 => {
                if (fs.fileIdFor(job.ino, job.fh, false)) |fid| {
                    job.phase = 2;
                    job.file_id = fid;
                    return fs.queryAttrs(job, fid);
                }
                job.path = fs.pathOf(job.ino) catch |e| return fs.finishErr(job, errnoOfError(e));
                job.phase = 1;
                fs.openPath(job, rdpdr.file_read_attributes | rdpdr.synchronize, rdpdr.file_open, 0, 0);
            },
            1 => {
                if (job.err != 0) return fs.finishErr(job, job.err);
                // Interrupted: nothing more is sent, the FileId is closed.
                if (job.answered) return fs.end(job);
                job.phase = 2;
                fs.queryAttrs(job, job.file_id);
            },
            else => {
                if (job.err != 0) return fs.finishErr(job, job.err);
                fs.answerAttr(job, metaOf(job.basic.?, job.standard.?));
                fs.end(job);
            },
        }
    }

    fn answerAttr(fs: *Fs, job: *Job, meta: Meta) void {
        const a = fs.attrOf(job.ino, meta);
        if (job.req) |r| if (!job.answered) {
            job.answered = true;
            if (fs.replier) |rp| rp.vtable.attr(rp.ptr, r, &a, fs.opts.attr_timeout);
        };
    }

    /// setattr phases: 0 open, 1 opened, 2 size, 3 basic, 4 attributes known, 5 query, 6 reply.
    fn stepSetattr(fs: *Fs, job: *Job) void {
        if (job.err != 0) return fs.finishErr(job, job.err);
        if (job.answered) return fs.end(job);
        const s = &job.set;
        switch (job.phase) {
            0 => {
                if ((s.uid != null and s.uid.? != fs.opts.uid) or (s.gid != null and s.gid.? != fs.opts.gid))
                    return fs.finishErr(job, errno(.PERM));
                s.uid = null;
                s.gid = null;
                const changes = s.size != null or s.atime != null or s.mtime != null or s.mode != null;
                if (changes and fs.readOnly()) return fs.finishErr(job, errno(.ROFS));
                if (s.mode) |m| {
                    // Only the write bits map (FILE_ATTRIBUTE_READONLY); file type bits must not change.
                    if (m & std.posix.S.IFMT != 0 and m & std.posix.S.IFMT != std.posix.S.IFREG and m & std.posix.S.IFMT != std.posix.S.IFDIR)
                        return fs.finishErr(job, errno(.INVAL));
                }
                // A handle opened for reading lacks FILE_WRITE_ATTRIBUTES: use a writable one.
                if (fs.fileIdFor(job.ino, job.fh, changes)) |fid| {
                    job.file_id = fid;
                    job.phase = 2;
                    return fs.stepSetattr(job);
                }
                job.path = fs.pathOf(job.ino) catch |e| return fs.finishErr(job, errnoOfError(e));
                var access: u32 = rdpdr.file_read_attributes | rdpdr.synchronize;
                if (s.size != null) access |= rdpdr.generic_write;
                if (s.atime != null or s.mtime != null or s.mode != null) access |= rdpdr.file_write_attributes;
                job.phase = 1;
                fs.openPath(job, access, rdpdr.file_open, 0, 0);
            },
            1 => {
                job.phase = 2;
                fs.stepSetattr(job);
            },
            2 => {
                job.phase = 3;
                if (s.size) |size| {
                    s.size = null;
                    job.info.clearRetainingCapacity();
                    var w = bytes.Writer.init(&job.info, fs.gpa);
                    rdpdr.FileEndOfFileInformation.encode(.{ .end_of_file = size }, &w) catch return fs.finishErr(job, errno(.NOMEM));
                    return fs.send(job, job.file_id, .{ .set_information = .{ .file_information_class = .end_of_file, .buffer = job.info.items } });
                }
                fs.stepSetattr(job);
            },
            3 => {
                if (s.mode != null) {
                    // The other attribute bits stay: read them first.
                    job.phase = 4;
                    job.basic = null;
                    return fs.send(job, job.file_id, .{ .query_information = .{ .file_information_class = .basic } });
                }
                job.phase = 4;
                fs.stepSetattr(job);
            },
            4 => {
                job.phase = 5;
                if (s.atime == null and s.mtime == null and s.mode == null) return fs.stepSetattr(job);
                var info: rdpdr.FileBasicInformation = .{};
                const now = fs.opts.clock();
                if (s.atime) |t| info.last_access_time = fileTime(t, now) catch return fs.finishErr(job, errno(.INVAL));
                if (s.mtime) |t| info.last_write_time = fileTime(t, now) catch return fs.finishErr(job, errno(.INVAL));
                if (s.mode) |m| info.file_attributes = attributesForMode(if (job.basic) |b| b.file_attributes else 0, m);
                s.atime = null;
                s.mtime = null;
                s.mode = null;
                job.info.clearRetainingCapacity();
                var w = bytes.Writer.init(&job.info, fs.gpa);
                info.encode(&w) catch return fs.finishErr(job, errno(.NOMEM));
                fs.send(job, job.file_id, .{ .set_information = .{ .file_information_class = .basic, .buffer = job.info.items } });
            },
            5 => {
                job.phase = 6;
                fs.queryAttrs(job, job.file_id);
            },
            else => {
                fs.answerAttr(job, metaOf(job.basic.?, job.standard.?));
                fs.end(job);
            },
        }
    }

    fn stepOpen(fs: *Fs, job: *Job) void {
        const dir = job.kind == .opendir;
        switch (job.phase) {
            0 => {
                const acc = job.flags & o.accmode;
                const writes = acc != o.rdonly or job.flags & o.trunc != 0;
                if (!dir and writes and fs.readOnly()) return fs.finishErr(job, errno(.ROFS));
                job.path = fs.pathOf(job.ino) catch |e| return fs.finishErr(job, errnoOfError(e));
                const p = rdpdr.createParams(.{
                    .access = if (dir) .read else switch (acc) {
                        o.wronly => .write,
                        o.rdwr => .read_write,
                        else => .read,
                    },
                    .truncate = !dir and job.flags & o.trunc != 0,
                    .directory = dir,
                    .sync = !dir and job.flags & o.dsync != 0,
                }) catch unreachable;
                job.phase = 1;
                fs.openPath(job, p.desired_access | rdpdr.file_read_attributes, p.create_disposition, p.create_options, 0);
            },
            else => {
                if (job.err != 0) return fs.finishErr(job, job.err);
                if (job.answered) return fs.end(job);
                const acc = job.flags & o.accmode;
                const h = fs.newHandle(job.ino, job.file_id, dir, !dir and acc != o.rdonly, !dir and job.flags & o.append != 0) catch
                    return fs.finishErr(job, errno(.NOMEM));
                job.temp = null; // the handle owns the FileId now
                job.answered = true;
                if (fs.replier) |rp| rp.vtable.open(rp.ptr, job.req.?, .{ .fh = h.fh });
                fs.end(job);
            },
        }
    }

    fn stepCreate(fs: *Fs, job: *Job) void {
        const dir = job.kind == .mkdir;
        switch (job.phase) {
            0 => {
                if (fs.readOnly()) return fs.finishErr(job, errno(.ROFS));
                if (!nameOk(job.name)) return fs.finishErr(job, if (job.name.len > max_name) errno(.NAMETOOLONG) else errno(.INVAL));
                job.path = fs.childPath(job.parent, job.name) catch |e| return fs.finishErr(job, errnoOfError(e));
                const acc = job.flags & o.accmode;
                const p = rdpdr.createParams(.{
                    .access = if (dir) .read else switch (acc) {
                        o.wronly => .write,
                        o.rdwr => .read_write,
                        else => .read,
                    },
                    .create = true,
                    // mkdir must not reuse an existing directory (EEXIST).
                    .exclusive = dir or job.flags & o.excl != 0,
                    .truncate = !dir and job.flags & o.trunc != 0,
                    .directory = dir,
                    .sync = !dir and job.flags & o.dsync != 0,
                }) catch unreachable;
                job.phase = 1;
                fs.openPath(job, p.desired_access | rdpdr.file_read_attributes, p.create_disposition, p.create_options, rdpdr.file_attribute_normal);
            },
            1 => {
                if (job.err != 0) return fs.finishErr(job, job.err);
                // Interrupted: nothing more is sent, the FileId is closed.
                if (job.answered) return fs.end(job);
                job.phase = 2;
                fs.queryAttrs(job, job.file_id);
            },
            else => {
                if (job.err != 0) return fs.finishErr(job, job.err);
                if (job.answered) return fs.end(job);
                const n = fs.child(job.parent, job.name) catch |e| return fs.finishErr(job, errnoOfError(e));
                const e = fs.entryOf(n.ino, metaOf(job.basic.?, job.standard.?));
                if (dir) {
                    n.nlookup += 1;
                    job.answered = true;
                    if (fs.replier) |rp| rp.vtable.entry(rp.ptr, job.req.?, &e);
                    return fs.end(job);
                }
                const acc = job.flags & o.accmode;
                const h = fs.newHandle(n.ino, job.file_id, false, acc != o.rdonly, job.flags & o.append != 0) catch {
                    fs.maybeFree(n);
                    return fs.finishErr(job, errno(.NOMEM));
                };
                n.nlookup += 1;
                job.temp = null;
                job.answered = true;
                if (fs.replier) |rp| rp.vtable.create(rp.ptr, job.req.?, &e, .{ .fh = h.fh });
                fs.end(job);
            },
        }
    }

    fn stepRead(fs: *Fs, job: *Job) void {
        if (job.phase == 0) {
            const h = fs.handles.get(job.fh) orelse return fs.finishErr(job, errno(.BADF));
            if (h.dir) return fs.finishErr(job, errno(.ISDIR));
            job.file_id = h.file_id;
            job.phase = 1;
            if (job.size == 0) return fs.answerData(job);
            return fs.readPiece(job);
        }
        if (job.err != 0) {
            // Bytes already read are returned; the error shows on the next read.
            if (job.data.items.len > 0) return fs.answerData(job);
            return fs.finishErr(job, job.err);
        }
        if (job.answered) return fs.end(job);
        // A short piece ends the read (2.2.3.4.3): clients return fewer bytes only at EOF,
        // and the kernel takes a short FUSE read as EOF.
        if (job.piece < job.want or job.data.items.len >= job.size) return fs.answerData(job);
        fs.readPiece(job);
    }

    fn readPiece(fs: *Fs, job: *Job) void {
        const left = job.size - job.data.items.len;
        const len: u32 = @intCast(@min(left, fs.opts.max_read));
        job.want = len;
        job.piece = 0;
        fs.send(job, job.file_id, .{ .read = .{ .length = len, .offset = job.offset + job.data.items.len } });
    }

    fn answerData(fs: *Fs, job: *Job) void {
        if (job.req) |r| if (!job.answered) {
            job.answered = true;
            if (fs.replier) |rp| rp.vtable.data(rp.ptr, r, job.data.items);
        };
        fs.end(job);
    }

    /// write phases: 0 checks (appends wait for the handle), 1 EndOfFile queried, 2+ pieces.
    fn stepWrite(fs: *Fs, job: *Job) void {
        switch (job.phase) {
            0 => {
                const h = fs.handles.get(job.fh) orelse return fs.finishErr(job, errno(.BADF));
                if (!h.writable) return fs.finishErr(job, errno(.BADF));
                if (fs.readOnly()) return fs.finishErr(job, errno(.ROFS));
                job.file_id = h.file_id;
                if (h.append) {
                    if (h.busy) {
                        h.waiters.append(fs.gpa, job.id) catch return fs.finishErr(job, errno(.NOMEM));
                        return;
                    }
                    h.busy = true;
                    job.phase = 1;
                    job.standard = null;
                    return fs.send(job, job.file_id, .{ .query_information = .{ .file_information_class = .standard } });
                }
                job.phase = 2;
                if (job.size == 0) return fs.answerWritten(job);
                fs.writePiece(job);
            },
            1 => {
                if (job.err != 0) return fs.finishErr(job, job.err);
                if (job.answered) return fs.end(job);
                // 2.2.1.4.4: write at the queried EndOfFile, never the all-ones append Offset; EndOfFile
                // is signed 64-bit (MS-FSCC 2.4.41), so no piece's Offset can wrap.
                const eof = job.standard.?.end_of_file;
                if (eof > std.math.maxInt(i64) or job.size > std.math.maxInt(i64) - eof) return fs.finishErr(job, errno(.FBIG));
                job.offset = eof;
                job.phase = 2;
                if (job.size == 0) return fs.answerWritten(job);
                fs.writePiece(job);
            },
            else => {
                if (job.err != 0) {
                    if (job.done > 0) return fs.answerWritten(job);
                    return fs.finishErr(job, job.err);
                }
                if (job.answered) return fs.end(job);
                const n = job.piece;
                job.done += n;
                // A partial piece, or none taken with success (FreeRDP drops appends), ends the write:
                // what was written is reported, nothing written is EIO.
                if (n < job.want or job.done >= job.size) {
                    if (job.done == 0) return fs.finishErr(job, errno(.IO));
                    return fs.answerWritten(job);
                }
                fs.writePiece(job);
            },
        }
    }

    fn writePiece(fs: *Fs, job: *Job) void {
        const left = job.size - job.done;
        const len: u32 = @intCast(@min(left, fs.opts.max_write));
        const at: usize = @intCast(job.done);
        job.want = len;
        job.piece = 0;
        fs.send(job, job.file_id, .{ .write = .{ .offset = job.offset + job.done, .data = job.data.items[at..][0..len] } });
    }

    fn answerWritten(fs: *Fs, job: *Job) void {
        if (job.req) |r| if (!job.answered) {
            job.answered = true;
            if (fs.replier) |rp| rp.vtable.written(rp.ptr, r, @intCast(job.done));
        };
        fs.end(job);
    }

    fn stepRelease(fs: *Fs, job: *Job) void {
        switch (job.phase) {
            0 => {
                const kv = fs.handles.fetchRemove(job.fh) orelse {
                    // Nothing to close (the drive was aborted).
                    fs.answerErr(job, 0);
                    return fs.end(job);
                };
                const h = kv.value;
                // Writes still queued on the handle cannot happen now.
                for (h.waiters.items) |w| if (fs.jobs.get(w)) |wj| fs.finishErr(wj, errno(.BADF));
                const fid = h.file_id;
                fs.freeHandle(h);
                job.phase = 1;
                fs.sendCloseFor(job, fid);
            },
            else => {
                // Release errors reach no one (close(2) has returned).
                fs.answerErr(job, 0);
                fs.end(job);
            },
        }
    }

    /// readdir phases: 0 start, 1 first query, 2 next queries, 3 page.
    fn stepReaddir(fs: *Fs, job: *Job) void {
        switch (job.phase) {
            0 => {
                const h = fs.handles.get(job.fh) orelse return fs.finishErr(job, errno(.BADF));
                if (!h.dir) return fs.finishErr(job, errno(.NOTDIR));
                if (job.offset != 0 and h.listed) return fs.answerPage(job, h);
                if (h.listing_job != null) return fs.finishErr(job, errno(.BUSY));
                fs.clearListing(h);
                job.path2 = fs.patternOf(h.ino) catch |e| return fs.finishErr(job, errnoOfError(e));
                h.listing_job = job.id;
                h.listing_gen = fs.generation;
                job.file_id = h.file_id;
                job.phase = 1;
                fs.send(job, job.file_id, .{ .query_directory = .{ .file_information_class = .both_directory, .initial_query = true, .path = job.path2 } });
            },
            1, 2 => {
                const h = fs.handles.get(job.fh) orelse return fs.finishErr(job, errno(.BADF));
                if (job.err != 0) {
                    fs.clearListing(h);
                    return fs.finishErr(job, job.err);
                }
                if (job.eof or h.listing.items.len >= fs.opts.max_listing) {
                    if (!job.eof) log.warn("drive {d}: listing cut at {d} entries", .{ fs.device_id, h.listing.items.len });
                    h.listed = true;
                    return fs.answerPage(job, h);
                }
                if (job.answered) {
                    fs.clearListing(h);
                    return fs.end(job);
                }
                job.phase = 2;
                // InitialQuery 0: the Path "MUST be ignored" but is sent again, null-terminated (2.2.3.3.10).
                fs.send(job, job.file_id, .{ .query_directory = .{ .file_information_class = .both_directory, .initial_query = false, .path = job.path2 } });
            },
            else => fs.end(job),
        }
    }

    fn takeEntries(fs: *Fs, job: *Job, buf: []const u8) Error!void {
        const h = fs.handles.get(job.fh) orelse return;
        var pos: usize = 0;
        while (pos < buf.len) {
            const e = rdpdr.decodeDirectoryEntry(.both_directory, buf[pos..]) catch return error.Malformed;
            try fs.addListed(h, e);
            if (e.next_entry_offset == 0) break;
            if (e.next_entry_offset > buf.len - pos) return error.Malformed;
            pos += e.next_entry_offset;
        }
    }

    fn addListed(fs: *Fs, h: *Handle, e: rdpdr.DirectoryEntry) Error!void {
        if (h.listing.items.len >= fs.opts.max_listing) return;
        var name_buf: [3 * 512]u8 = undefined;
        const name = listedName(&name_buf, e.file_name) orelse return;
        // "." and ".." are added locally; a name must be one component the client can reopen.
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return;
        if (!nameOk(name)) return;
        const owned = try fs.gpa.dupe(u8, name);
        errdefer fs.gpa.free(owned);
        try h.listing.append(fs.gpa, .{ .name = owned, .meta = .{
            .creation = e.creation_time,
            .access = e.last_access_time,
            .write = e.last_write_time,
            .change = e.change_time,
            .attributes = e.file_attributes,
            .eof = e.end_of_file,
            .alloc = e.allocation_size,
            .dir = e.file_attributes & rdpdr.file_attribute_directory != 0,
        } });
    }

    fn clearListing(fs: *Fs, h: *Handle) void {
        for (h.listing.items) |l| fs.gpa.free(l.name);
        h.listing.clearRetainingCapacity();
        h.listed = false;
    }

    /// Entries from `job.offset` that fit `job.size`: "." is offset 0, ".." 1, then the listing.
    fn answerPage(fs: *Fs, job: *Job, h: *Handle) void {
        defer fs.end(job);
        const r = job.req orelse return;
        if (job.answered) return;
        job.answered = true;
        if (h.listing_job == job.id) h.listing_job = null;
        const total = h.listing.items.len + 2;
        var out: std.ArrayList(DirEntry) = .empty;
        defer out.deinit(fs.gpa);
        var used: usize = 0;
        var i: u64 = job.offset;
        const dir_node = fs.nodes.get(h.ino);
        while (i < total) : (i += 1) {
            const name: []const u8 = switch (i) {
                0 => ".",
                1 => "..",
                else => h.listing.items[@intCast(i - 2)].name,
            };
            const sz = direntSize(job.plus, name.len);
            if (used + sz > job.size) break;
            var e: Entry = .{ .ino = 0 };
            if (i < 2) {
                const ino = if (i == 0) h.ino else if (dir_node) |d| (if (d.parent != 0) d.parent else h.ino) else h.ino;
                e.attr = .{ .ino = ino, .mode = std.posix.S.IFDIR | 0o755 };
            } else {
                const l = h.listing.items[@intCast(i - 2)];
                // Attributes from a listing older than the last local change are withheld (the kernel
                // drops only those older than its request): it looks the name up instead.
                if (job.plus and h.listing_gen == fs.generation) {
                    const n = fs.child(h.ino, l.name) catch break;
                    n.nlookup += 1;
                    e = fs.entryOf(n.ino, l.meta);
                } else {
                    const known = fs.names.get(.{ .parent = h.ino, .name = l.name });
                    e.attr = fs.attrOf(known orelse unknown_ino, l.meta);
                }
            }
            out.append(fs.gpa, .{ .name = name, .off = i + 1, .entry = e }) catch break;
            used += sz;
        }
        if (fs.replier) |rp| rp.vtable.dir(rp.ptr, r, job.plus, @intCast(job.size), out.items);
    }

    /// unlink / rmdir phases: 0 barrier and open, 1 disposition, 2 close, 3 reply.
    fn stepRemove(fs: *Fs, job: *Job) void {
        const dir = job.kind == .rmdir;
        switch (job.phase) {
            0 => {
                if (fs.readOnly()) return fs.finishErr(job, errno(.ROFS));
                if (!nameOk(job.name)) return fs.finishErr(job, errno(.NOENT));
                if (fs.waitCloses(job)) return;
                job.path = fs.childPath(job.parent, job.name) catch |e| return fs.finishErr(job, errnoOfError(e));
                job.phase = 1;
                fs.openPath(job, rdpdr.access_delete | rdpdr.file_read_attributes | rdpdr.synchronize, rdpdr.file_open, if (dir) rdpdr.file_directory_file else rdpdr.file_non_directory_file, 0);
            },
            1 => {
                if (job.err != 0) return fs.finishErr(job, job.err);
                // Interrupted: nothing more is sent, the FileId is closed.
                if (job.answered) return fs.end(job);
                job.phase = 2;
                // 2.2.3.3.9: FileDispositionInformation with an empty SetBuffer, DeletePending implied.
                fs.send(job, job.file_id, .{ .set_information = .{ .file_information_class = .disposition, .buffer = "" } });
            },
            2 => {
                // The client deletes when the handle closes: reply after.
                const fid = job.temp.?;
                job.temp = null;
                job.phase = 3;
                fs.sendCloseFor(job, fid);
            },
            else => {
                // The disposition's status decides; a cancelled close may not have deleted.
                if (job.err != 0) return fs.finishErr(job, job.err);
                fs.unlinkName(job.parent, job.name);
                fs.answerErr(job, 0);
                fs.end(job);
            },
        }
    }

    /// rename phases: 0 checks, barrier, open, 1 FileRenameInformation, 2 reply.
    fn stepRename(fs: *Fs, job: *Job) void {
        switch (job.phase) {
            0 => {
                if (fs.readOnly()) return fs.finishErr(job, errno(.ROFS));
                if (job.flags & ~rename_noreplace != 0) return fs.finishErr(job, errno(.INVAL));
                if (!nameOk(job.name)) return fs.finishErr(job, errno(.NOENT));
                if (!nameOk(job.newname)) return fs.finishErr(job, if (job.newname.len > max_name) errno(.NAMETOOLONG) else errno(.INVAL));
                if (fs.waitCloses(job)) return;
                job.path = fs.childPath(job.parent, job.name) catch |e| return fs.finishErr(job, errnoOfError(e));
                job.path2 = fs.childPath(job.newparent, job.newname) catch |e| return fs.finishErr(job, errnoOfError(e));
                job.phase = 1;
                fs.openPath(job, rdpdr.access_delete | rdpdr.file_read_attributes | rdpdr.synchronize, rdpdr.file_open, 0, 0);
            },
            1 => {
                if (job.err != 0) return fs.finishErr(job, job.err);
                // Interrupted: nothing more is sent, the FileId is closed.
                if (job.answered) return fs.end(job);
                job.phase = 2;
                job.info.clearRetainingCapacity();
                var w = bytes.Writer.init(&job.info, fs.gpa);
                // 2.2.3.3.9.1: FileName is the new drive path with its terminator.
                rdpdr.FileRenameInformation.encode(.{
                    .replace_if_exists = job.flags & rename_noreplace == 0,
                    .file_name = job.path2,
                }, &w) catch return fs.finishErr(job, errno(.NOMEM));
                fs.send(job, job.file_id, .{ .set_information = .{ .file_information_class = .rename, .buffer = job.info.items } });
            },
            else => {
                if (job.err != 0) return fs.finishErr(job, job.err);
                fs.moveName(job.parent, job.name, job.newparent, job.newname);
                fs.answerErr(job, 0);
                fs.end(job);
            },
        }
    }

    /// statfs phases: 0 open the root, 1 full size, 2 size (fallback), 3 reply.
    fn stepStatfs(fs: *Fs, job: *Job) void {
        switch (job.phase) {
            0 => {
                job.phase = 1;
                fs.openPath(job, rdpdr.file_read_attributes | rdpdr.synchronize, rdpdr.file_open, rdpdr.file_directory_file, 0);
            },
            1 => {
                if (job.err != 0) return fs.finishErr(job, job.err);
                // Interrupted: nothing more is sent, the FileId is closed.
                if (job.answered) return fs.end(job);
                job.phase = 2;
                fs.send(job, job.file_id, .{ .query_volume_information = .{ .fs_information_class = .full_size } });
            },
            2 => {
                if (job.err != 0 and job.status != rdpdr.status.cancelled) {
                    // A client without FileFsFullSizeInformation.
                    job.err = 0;
                    job.status = 0;
                    job.phase = 3;
                    return fs.send(job, job.file_id, .{ .query_volume_information = .{ .fs_information_class = .size } });
                }
                fs.answerStatfs(job);
            },
            else => fs.answerStatfs(job),
        }
    }

    fn answerStatfs(fs: *Fs, job: *Job) void {
        if (job.err != 0) return fs.finishErr(job, job.err);
        var s: StatFs = .{ .namemax = @min(fs.volume.namemax, max_name) };
        const v = job.volume orelse return fs.finishErr(job, errno(.IO));
        const units: struct { total: u64, caller: u64, actual: u64, spu: u32, bps: u32 } = switch (v) {
            .full_size => |f| .{ .total = f.total_allocation_units, .caller = f.caller_available_allocation_units, .actual = f.actual_available_allocation_units, .spu = f.sectors_per_allocation_unit, .bps = f.bytes_per_sector },
            .size => |f| .{ .total = f.total_allocation_units, .caller = f.available_allocation_units, .actual = f.available_allocation_units, .spu = f.sectors_per_allocation_unit, .bps = f.bytes_per_sector },
            else => return fs.finishErr(job, errno(.IO)),
        };
        const unit = @as(u64, units.spu) * units.bps;
        if (unit != 0) {
            s.bsize = unit;
            s.frsize = unit;
            s.blocks = units.total;
            s.bfree = @min(units.actual, units.total);
            s.bavail = @min(units.caller, units.total);
        } else {
            s.bsize = 4096;
            s.frsize = 4096;
        }
        if (job.req) |r| if (!job.answered) {
            job.answered = true;
            if (fs.replier) |rp| rp.vtable.statfs(rp.ptr, r, &s);
        };
        fs.end(job);
    }

    fn stepProbe(fs: *Fs, job: *Job) void {
        switch (job.phase) {
            0 => {
                job.phase = 1;
                fs.openPath(job, rdpdr.file_read_attributes | rdpdr.synchronize, rdpdr.file_open, rdpdr.file_directory_file, 0);
            },
            1 => {
                if (job.err != 0) return fs.probeDone(job);
                job.phase = 2;
                fs.send(job, job.file_id, .{ .query_volume_information = .{ .fs_information_class = .attribute } });
            },
            else => {
                if (job.err == 0) if (job.volume) |v| if (v == .attribute) {
                    const a = v.attribute;
                    fs.volume.read_only = a.file_system_attributes & rdpdr.file_read_only_volume != 0;
                    if (a.maximum_component_name_length != 0) fs.volume.namemax = a.maximum_component_name_length;
                };
                fs.probeDone(job);
            },
        }
    }

    fn probeDone(fs: *Fs, job: *Job) void {
        if (job.err != 0) log.info("drive {d}: no volume attributes (status 0x{x:0>8}), mounting writable", .{ fs.device_id, job.status });
        fs.end(job);
        if (fs.on_probe) |cb| cb.f(cb.ctx, fs);
    }

    /// A CLOSE outside any request (temporary FileIds after the reply).
    fn sendClose(fs: *Fs, file_id: u32) void {
        if (fs.dead) return;
        const j = fs.newJob(.close, null) catch return;
        fs.sendCloseFor(j, file_id);
    }

    /// A CLOSE as part of `job`; the barrier counts it until it is done.
    fn sendCloseFor(fs: *Fs, job: *Job, file_id: u32) void {
        fs.closes.append(fs.gpa, fs.next_close) catch {};
        job.close_seq = fs.next_close;
        fs.next_close += 1;
        fs.send(job, file_id, .close);
    }

    fn closeDone(fs: *Fs, job: *Job) void {
        if (job.close_seq == 0) return;
        if (std.mem.indexOfScalar(u64, fs.closes.items, job.close_seq)) |i| _ = fs.closes.orderedRemove(i);
        job.close_seq = 0;
        var i: usize = 0;
        while (i < fs.barrier.items.len) {
            const w = fs.jobs.get(fs.barrier.items[i]) orelse {
                _ = fs.barrier.orderedRemove(i);
                continue;
            };
            if (fs.oldestClose() >= w.after_close) {
                _ = fs.barrier.orderedRemove(i);
                fs.markReady(w);
            } else i += 1;
        }
    }

    fn oldestClose(fs: *const Fs) u64 {
        var m: u64 = std.math.maxInt(u64);
        for (fs.closes.items) |c| m = @min(m, c);
        return m;
    }

    fn waitCloses(fs: *Fs, job: *Job) bool {
        if (fs.oldestClose() >= job.after_close) return false;
        fs.barrier.append(fs.gpa, job.id) catch return false;
        return true;
    }

    fn answerErr(fs: *Fs, job: *Job, err: u16) void {
        if (job.answered) return;
        job.answered = true;
        const r = job.req orelse return;
        if (fs.replier) |rp| rp.vtable.err(rp.ptr, r, err);
    }

    fn replyErr(fs: *Fs, req: Req, err: u16) void {
        if (fs.replier) |rp| rp.vtable.err(rp.ptr, req, err);
    }

    /// The node of `name` in `parent`, created if new (nlookup 0).
    fn child(fs: *Fs, parent: u64, name: []const u8) Error!*Node {
        if (fs.names.get(.{ .parent = parent, .name = name })) |ino| return fs.nodes.get(ino).?;
        const p = fs.nodes.get(parent) orelse return error.Stale;
        if (p.ino != root_ino and p.parent == 0) return error.Stale;
        const n = try fs.gpa.create(Node);
        errdefer fs.gpa.destroy(n);
        const owned = try fs.gpa.dupe(u8, name);
        errdefer fs.gpa.free(owned);
        n.* = .{ .ino = fs.next_ino, .parent = parent, .name = owned };
        try fs.nodes.put(fs.gpa, n.ino, n);
        errdefer _ = fs.nodes.remove(n.ino);
        try fs.names.put(fs.gpa, .{ .parent = parent, .name = owned }, n.ino);
        fs.next_ino += 1;
        p.children += 1;
        return n;
    }

    /// Frees a node nothing refers to any more (and then its parent).
    fn maybeFree(fs: *Fs, start_node: *Node) void {
        var n = start_node;
        while (n.ino != root_ino and n.nlookup == 0 and n.children == 0 and !fs.hasHandle(n.ino)) {
            const parent = n.parent;
            if (parent != 0) {
                _ = fs.names.remove(.{ .parent = parent, .name = n.name });
            }
            _ = fs.nodes.remove(n.ino);
            fs.gpa.free(n.name);
            fs.gpa.destroy(n);
            const p = fs.nodes.get(if (parent != 0) parent else return) orelse return;
            p.children -|= 1;
            n = p;
        }
    }

    fn hasHandle(fs: *const Fs, ino: u64) bool {
        var it = fs.handles.valueIterator();
        while (it.next()) |h| if (h.*.ino == ino) return true;
        return false;
    }

    /// The name is gone on the client; the node lives on for kernel references, without a path.
    fn unlinkName(fs: *Fs, parent: u64, name: []const u8) void {
        const kv = fs.names.fetchRemove(.{ .parent = parent, .name = name }) orelse return;
        const n = fs.nodes.get(kv.value) orelse return;
        fs.detach(n);
    }

    fn detach(fs: *Fs, n: *Node) void {
        const parent = n.parent;
        n.parent = 0;
        if (fs.nodes.get(parent)) |p| {
            p.children -|= 1;
            fs.maybeFree(n);
            fs.maybeFree(p);
        } else fs.maybeFree(n);
    }

    fn moveName(fs: *Fs, parent: u64, name: []const u8, newparent: u64, newname: []const u8) void {
        if (fs.names.fetchRemove(.{ .parent = newparent, .name = newname })) |kv| {
            if (fs.nodes.get(kv.value)) |old| fs.detach(old);
        }
        const kv = fs.names.fetchRemove(.{ .parent = parent, .name = name }) orelse return;
        const n = fs.nodes.get(kv.value) orelse return;
        const np = fs.nodes.get(newparent) orelse return fs.detach(n);
        const owned = fs.gpa.dupe(u8, newname) catch return fs.detach(n);
        fs.names.put(fs.gpa, .{ .parent = newparent, .name = owned }, n.ino) catch {
            fs.gpa.free(owned);
            return fs.detach(n);
        };
        fs.gpa.free(n.name);
        n.name = owned;
        if (newparent != parent) {
            np.children += 1;
            n.parent = newparent;
            if (fs.nodes.get(parent)) |op| {
                op.children -|= 1;
                fs.maybeFree(op);
            }
        }
    }

    /// The Linux path of `ino` relative to the drive root ("" for the root).
    fn linuxPath(fs: *const Fs, ino: u64, extra: ?[]const u8) Error![]u8 {
        var parts: [max_depth][]const u8 = undefined;
        var n: usize = 0;
        var len: usize = 0;
        var cur = ino;
        while (cur != root_ino) {
            const node = fs.nodes.get(cur) orelse return error.Stale;
            if (node.parent == 0) return error.Stale;
            if (n == parts.len) return error.NameTooLong;
            parts[n] = node.name;
            n += 1;
            len += node.name.len + 1;
            cur = node.parent;
        }
        if (extra) |x| len += x.len + 1;
        const out = try fs.gpa.alloc(u8, len);
        var at: usize = 0;
        var i = n;
        while (i > 0) {
            i -= 1;
            @memcpy(out[at..][0..parts[i].len], parts[i]);
            at += parts[i].len;
            out[at] = '/';
            at += 1;
        }
        if (extra) |x| {
            @memcpy(out[at..][0..x.len], x);
            at += x.len;
            out[at] = '/';
            at += 1;
        }
        return out[0..at];
    }

    fn rdpPath(fs: *const Fs, linux: []const u8) Error![]u8 {
        const buf = try fs.gpa.alloc(u8, 2 * linux.len + 8);
        defer fs.gpa.free(buf);
        const p = rdpdr.rdpPathFromLinux(buf, linux) catch |e| return switch (e) {
            error.InvalidName => error.Invalid,
            error.NoSpaceLeft => error.NameTooLong,
            else => error.Malformed,
        };
        if (p.len > max_path_bytes) return error.NameTooLong;
        return fs.gpa.dupe(u8, p);
    }

    /// UTF-16LE drive path of an inode (DR_CREATE_REQ Path, 2.2.1.4.1).
    pub fn pathOf(fs: *const Fs, ino: u64) Error![]u8 {
        const l = try fs.linuxPath(ino, null);
        defer fs.gpa.free(l);
        return fs.rdpPath(l);
    }

    pub fn childPath(fs: *const Fs, parent: u64, name: []const u8) Error![]u8 {
        const l = try fs.linuxPath(parent, name);
        defer fs.gpa.free(l);
        return fs.rdpPath(l);
    }

    /// "\dir\*" for listing an inode (2.2.3.3.10).
    fn patternOf(fs: *const Fs, ino: u64) Error![]u8 {
        const l = try fs.linuxPath(ino, null);
        defer fs.gpa.free(l);
        const buf = try fs.gpa.alloc(u8, 2 * l.len + 12);
        defer fs.gpa.free(buf);
        const p = rdpdr.directoryPattern(buf, l) catch return error.Invalid;
        return fs.gpa.dupe(u8, p);
    }

    fn newHandle(fs: *Fs, ino: u64, file_id: u32, dir: bool, writable: bool, append: bool) Allocator.Error!*Handle {
        const h = try fs.gpa.create(Handle);
        errdefer fs.gpa.destroy(h);
        h.* = .{ .fh = fs.next_fh, .ino = ino, .file_id = file_id, .dir = dir, .writable = writable, .append = append };
        try fs.handles.put(fs.gpa, h.fh, h);
        fs.next_fh += 1;
        return h;
    }

    fn freeHandle(fs: *Fs, h: *Handle) void {
        fs.clearListing(h);
        h.listing.deinit(fs.gpa);
        h.waiters.deinit(fs.gpa);
        fs.gpa.destroy(h);
    }

    /// A FileId open on `ino`: the request's own handle first, then any other (writable if `need_write`).
    fn fileIdFor(fs: *const Fs, ino: u64, fh: u64, need_write: bool) ?u32 {
        if (fh != 0) if (fs.handles.get(fh)) |h| if (h.ino == ino and (!need_write or h.writable)) return h.file_id;
        var it = fs.handles.valueIterator();
        while (it.next()) |h| {
            if (h.*.ino == ino and (!need_write or h.*.writable)) return h.*.file_id;
        }
        return null;
    }

    fn attrOf(fs: *const Fs, ino: u64, m: Meta) Attr {
        var mode = rdpdr.modeFromAttributes(m.attributes | (if (m.dir) rdpdr.file_attribute_directory else 0)) catch unreachable;
        if (fs.readOnly()) mode &= ~@as(u32, 0o222);
        return .{
            .ino = ino,
            .mode = mode,
            .nlink = if (m.dir) 1 else @max(m.links, 1),
            .uid = fs.opts.uid,
            .gid = fs.opts.gid,
            .size = m.eof,
            .blocks = std.math.divCeil(u64, m.alloc, 512) catch 0,
            .blksize = fs.opts.blksize,
            .atime = timeOf(m.access),
            .mtime = timeOf(m.write),
            .ctime = timeOf(m.change),
        };
    }

    fn entryOf(fs: *const Fs, ino: u64, m: Meta) Entry {
        return .{
            .ino = ino,
            .attr = fs.attrOf(ino, m),
            .attr_timeout = fs.opts.attr_timeout,
            .entry_timeout = fs.opts.entry_timeout,
        };
    }
};

pub const Error = error{
    OutOfMemory,
    /// An inode with no path (removed, renamed over, or unknown).
    Stale,
    NameTooLong,
    Invalid,
    Malformed,
};

/// d_ino of an entry the kernel has not looked up (FUSE_UNKNOWN_INO).
pub const unknown_ino: u64 = 0xffffffff;
pub const max_name = 255;
/// Path components followed up to the root.
const max_depth = 4096;
/// The longest path sent: 32767 UTF-16 code units and the terminator.
const max_path_bytes = 2 * 32768;

fn errnoOfError(e: anyerror) u16 {
    return switch (e) {
        error.OutOfMemory => errno(.NOMEM),
        error.Stale => errno(.NOENT),
        error.NameTooLong => errno(.NAMETOOLONG),
        error.Invalid => errno(.INVAL),
        error.InvalidFileId => errno(.BADF),
        else => errno(.IO),
    };
}

/// errno for a failed NTSTATUS; a cancelled request is EIO.
pub fn statusErrno(st: u32) u16 {
    if (st == rdpdr.status.cancelled) return errno(.IO);
    const e = rdpdr.errnoFromStatus(st) catch return errno(.IO);
    return if (e == 0) errno(.IO) else e;
}

/// One component `rdpPathFromLinux` takes and a client may create (no reserved device name, 3.2.5.2.3).
pub fn nameOk(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    if (std.mem.indexOfAny(u8, name, "/\x00") != null) return false;
    var buf: [2 * max_name + 8]u8 = undefined;
    _ = rdpdr.rdpPathFromLinux(&buf, name) catch return false;
    return !(rdpdr.isReservedDeviceName(name) catch true);
}

/// A directory entry's FileName (UTF-16LE, [MS-FSCC] 2.4.8) as UTF-8. Null for a name
/// cut by a NUL or not valid UTF-16.
pub fn listedName(out: []u8, utf16le: []const u8) ?[]const u8 {
    if (utf16le.len % 2 != 0 or utf16le.len > out.len / 3 * 2) return null;
    var end = utf16le.len;
    while (end >= 2 and utf16le[end - 2] == 0 and utf16le[end - 1] == 0) end -= 2;
    var i: usize = 0;
    while (i < end) : (i += 2) {
        if (utf16le[i] == 0 and utf16le[i + 1] == 0) return null;
    }
    return rdpdr.utf16leToUtf8(out, utf16le[0..end]) catch null;
}

/// What the generic rights stand for ([MS-SMB2] 2.2.13.1.1).
pub const file_generic_read: u32 = rdpdr.read_control | rdpdr.file_read_data | rdpdr.file_read_attributes | rdpdr.file_read_ea | rdpdr.synchronize;
pub const file_generic_write: u32 = rdpdr.read_control | rdpdr.file_write_data | rdpdr.file_write_attributes | rdpdr.file_write_ea | rdpdr.file_append_data | rdpdr.synchronize;
pub const file_generic_execute: u32 = rdpdr.read_control | rdpdr.file_read_attributes | rdpdr.file_execute | rdpdr.synchronize;
pub const file_all_access: u32 = 0x001F01FF;

/// DR_CREATE_REQ DesiredAccess (2.2.1.4.1) with generic rights replaced by specific ones:
/// Windows clients do not map GENERIC_* (a Windows server sends mapped masks).
pub fn specificAccess(access: u32) u32 {
    var a = access & ~(rdpdr.generic_read | rdpdr.generic_write | rdpdr.generic_execute | rdpdr.generic_all);
    if (access & rdpdr.generic_read != 0) a |= file_generic_read;
    if (access & rdpdr.generic_write != 0) a |= file_generic_write;
    if (access & rdpdr.generic_execute != 0) a |= file_generic_execute;
    if (access & rdpdr.generic_all != 0) a |= file_all_access;
    return a;
}

/// Jobs that change the client's files.
fn mutates(kind: Kind) bool {
    return switch (kind) {
        .write, .setattr, .create, .mkdir, .unlink, .rmdir, .rename => true,
        else => false,
    };
}

fn metaOf(b: rdpdr.FileBasicInformation, s: rdpdr.FileStandardInformation) Meta {
    return .{
        .creation = b.creation_time,
        .access = b.last_access_time,
        .write = b.last_write_time,
        .change = b.change_time,
        .attributes = b.file_attributes,
        .eof = s.end_of_file,
        .alloc = s.allocation_size,
        .links = s.number_of_links,
        .dir = s.directory or b.file_attributes & rdpdr.file_attribute_directory != 0,
    };
}

/// FILETIME as a Unix time; 0 (not given) is the epoch.
pub fn timeOf(ft: u64) Time {
    if (ft == 0) return .{};
    const ns = rdpdr.fileTimeToUnixNs(ft) catch return .{};
    return .{ .sec = @intCast(@divFloor(ns, std.time.ns_per_s)), .nsec = @intCast(@mod(ns, std.time.ns_per_s)) };
}

fn fileTime(t: SetTime, now: i128) rdpdr.Error!u64 {
    const ft = try rdpdr.unixNsToFileTime(switch (t) {
        .now => now,
        .ns => |n| n,
    });
    // 0 means "unchanged" in a set request ([MS-FSCC] 2.4.7).
    return if (ft == 0) 1 else ft;
}

/// chmod attributes: FILE_ATTRIBUTE_READONLY when no write bit is left, others kept;
/// never 0 ("unchanged"), so a plain file is FILE_ATTRIBUTE_NORMAL ([MS-FSCC] 2.6).
pub fn attributesForMode(current: u32, mode: u32) u32 {
    const settable = rdpdr.file_attribute_readonly | rdpdr.file_attribute_hidden | rdpdr.file_attribute_system |
        rdpdr.file_attribute_archive | rdpdr.file_attribute_temporary | rdpdr.file_attribute_offline |
        rdpdr.file_attribute_not_content_indexed;
    var a = current & settable;
    if (mode & 0o222 == 0) a |= rdpdr.file_attribute_readonly else a &= ~rdpdr.file_attribute_readonly;
    return if (a == 0) rdpdr.file_attribute_normal else a;
}

test {
    refAll(@This());
}

/// References every declaration, nested types included, for `zig build test`.
fn refAll(comptime T: type) void {
    inline for (comptime std.meta.declarations(T)) |d| {
        const f = @field(T, d);
        if (@TypeOf(f) == type) {
            switch (@typeInfo(f)) {
                .@"struct", .@"union", .@"enum" => refAll(f),
                else => {},
            }
        } else {
            _ = &@field(T, d);
        }
    }
}
