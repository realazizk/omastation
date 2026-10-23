//! Redirected client drives as FUSE mounts (MS-RDPEFS 2.2.3.1, RDPDR_DTYP_FILESYSTEM).
//! Each drive mounts at $XDG_RUNTIME_DIR/omastation/drives/<name> and is linked
//! from "~/RDP Drives/<name> on <client>". Nothing here blocks.

const std = @import("std");
const c = @import("c");
const rdpdr = @import("../channel/rdpdr.zig");
pub const fs = @import("fs.zig");
pub const fuse = @import("fuse.zig");

const log = std.log.scoped(.drives);
const Allocator = std.mem.Allocator;

pub const Config = struct {
    /// $XDG_RUNTIME_DIR (absolute). Null: drives are not mounted.
    runtime_dir: ?[]const u8,
    /// "<home>/RDP Drives", created if missing. Null: no links.
    link_dir: ?[]const u8 = null,
    uid: u32,
    gid: u32,
    read_only: bool = false,
    /// Request layer settings; uid, gid and read_only are set from above.
    fs: fs.Options = .{},
};

pub const MountEvent = enum {
    mounted,
    failed,
    /// The mount went away (unmounted from outside, connection aborted).
    gone,
};

pub const Notify = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, id: u32, ev: MountEvent) void,
};

pub const MountArgs = struct {
    /// DeviceId: identifies the mount in `unmount`.
    id: u32,
    /// A drive's `Fs.handler()`, or the clipboard's file tree.
    handler: fs.Handler,
    path: [:0]const u8,
    read_only: bool,
    /// The mount point is a dead FUSE mount (ENOTCONN): unmount it first.
    stale: bool,
    /// How the outcome is reported (from `dispatch`, never from `mount`).
    notify: Notify,
};

/// The kernel side (fuse.Kernel), or a fake in tests.
pub const Backend = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Starts mounting; the backend sets the handler's replier.
        mount: *const fn (ptr: *anyopaque, args: MountArgs) anyerror!void,
        /// Unmounts lazily; the Fs is not called again for `id`.
        unmount: *const fn (ptr: *anyopaque, id: u32) void,
        /// File descriptor to poll for POLLIN, -1 when there is none.
        fd: *const fn (ptr: *anyopaque) i32,
        /// Serves ready requests and advances mounts, without blocking.
        dispatch: *const fn (ptr: *anyopaque) void,
    };
};

const State = enum { probing, mounting, mounted };

const Drive = struct {
    id: u32,
    state: State,
    fs: *fs.Fs,
    /// Mount point (owned).
    path: [:0]u8,
    /// The link made for it (owned), if any.
    link: ?[:0]u8 = null,
    /// Drop once the call stack has left its Fs (a failure inside an Fs callback).
    doomed: bool = false,
};

pub const Drives = struct {
    gpa: Allocator,
    session: *rdpdr.Session,
    out: *rdpdr.Outbox,
    backend: Backend,
    config: Config,
    drives: std.ArrayList(*Drive) = .empty,
    /// The link directory was created here (removed again when empty).
    made_link_dir: bool = false,

    /// `session` and `out` must outlive the Drives. Removes stale links.
    pub fn init(gpa: Allocator, session: *rdpdr.Session, out: *rdpdr.Outbox, backend: Backend, config: Config) Drives {
        var d: Drives = .{ .gpa = gpa, .session = session, .out = out, .backend = backend, .config = config };
        d.config.fs.uid = config.uid;
        d.config.fs.gid = config.gid;
        d.config.fs.read_only = config.read_only;
        if (config.link_dir) |ld| if (config.runtime_dir) |rd| {
            var buf: [4096]u8 = undefined;
            if (rdpdr.drivesDir(&buf, rd)) |dir| removeStaleLinks(gpa, ld, dir) else |_| {}
        };
        return d;
    }

    pub fn deinit(d: *Drives) void {
        d.shutdown();
        d.drives.deinit(d.gpa);
    }

    /// Session ended: pending requests fail with EIO, drives unmount, links go.
    pub fn shutdown(d: *Drives) void {
        while (d.drives.items.len > 0) d.drop(d.drives.items[d.drives.items.len - 1], false);
        d.removeLinkDir();
    }

    pub fn count(d: *const Drives) usize {
        return d.drives.items.len;
    }

    pub fn fsOf(d: *const Drives, id: u32) ?*fs.Fs {
        const dr = d.find(id) orelse return null;
        return dr.fs;
    }

    pub fn mountPointOf(d: *const Drives, id: u32) ?[]const u8 {
        const dr = d.find(id) orelse return null;
        return dr.path;
    }

    pub fn linkOf(d: *const Drives, id: u32) ?[]const u8 {
        const dr = d.find(id) orelse return null;
        return dr.link;
    }

    pub fn isMounted(d: *const Drives, id: u32) bool {
        const dr = d.find(id) orelse return false;
        return dr.state == .mounted;
    }

    /// The fd to poll (POLLIN), -1 when there is nothing to wait for.
    pub fn pollFd(d: *Drives) i32 {
        return d.backend.vtable.fd(d.backend.ptr);
    }

    /// Serves what the kernel asked; never blocks. IRPs land in the outbox.
    pub fn dispatch(d: *Drives) void {
        d.backend.vtable.dispatch(d.backend.ptr);
        d.retry();
        d.reap();
    }

    /// Events from `rdpdr.Session.receive` or `reset`; response buffers are used before returning.
    pub fn handleEvents(d: *Drives, events: []const rdpdr.Event) void {
        for (events) |e| switch (e) {
            .device_added => |id| d.added(id),
            .device_removed => |id| if (d.find(id)) |dr| d.drop(dr, false),
            .io_completed => |done| if (d.find(done.request.device_id)) |dr| {
                dr.fs.ioCompleted(done.request, done.io_status, done.response);
            },
            .io_cancelled => |r| if (d.find(r.device_id)) |dr| dr.fs.ioCancelled(r),
            // Logged by id only: the drive name is user data.
            .device_refused => |r| if (r.result_code == rdpdr.status.access_denied)
                log.info("client device {d}: a drive whose name is not usable (2.2.1.3); not mounted", .{r.device_id})
            else
                log.debug("client device {d} refused: 0x{x:0>8} (not a drive)", .{ r.device_id, r.result_code }),
            else => {},
        };
        d.retry();
        d.reap();
    }

    /// Drops the drives whose mount failed inside an Fs callback.
    fn reap(d: *Drives) void {
        var i: usize = d.drives.items.len;
        while (i > 0) {
            i -= 1;
            if (i < d.drives.items.len and d.drives.items[i].doomed) d.drop(d.drives.items[i], true);
        }
    }

    /// A completion freed room in the session: retry held-back requests.
    fn retry(d: *Drives) void {
        for (d.drives.items) |dr| dr.fs.retry();
    }

    fn find(d: *const Drives, id: u32) ?*Drive {
        for (d.drives.items) |dr| if (dr.id == id) return dr;
        return null;
    }

    fn added(d: *Drives, id: u32) void {
        const dev = d.session.device(id) orelse return;
        if (dev.device_type != .filesystem or !dev.accepted) return;
        if (d.find(id) != null) return;
        const rd = d.config.runtime_dir orelse {
            log.warn("drive {s}: no XDG_RUNTIME_DIR, not mounted", .{dev.name()});
            return;
        };
        d.start(id, rd, dev.name()) catch |e| log.warn("drive {s}: {t}", .{ dev.name(), e });
    }

    fn start(d: *Drives, id: u32, runtime_dir: []const u8, name: []const u8) !void {
        var buf: [4096]u8 = undefined;
        const mp = try rdpdr.mountPoint(&buf, runtime_dir, name);
        const path = try d.gpa.dupeSentinel(u8, mp, 0);
        errdefer d.gpa.free(path);
        const f = try d.gpa.create(fs.Fs);
        errdefer d.gpa.destroy(f);
        f.* = try fs.Fs.init(d.gpa, .{ .session = d.session, .out = d.out }, id, d.config.fs);
        errdefer f.deinit();
        const dr = try d.gpa.create(Drive);
        errdefer d.gpa.destroy(dr);
        dr.* = .{ .id = id, .state = .probing, .fs = f, .path = path };
        try d.drives.append(d.gpa, dr);
        f.on_probe = .{ .ctx = d, .f = probed };
        log.info("drive {s}: probing", .{name});
        f.probe();
        d.reap();
    }

    fn probed(ctx: *anyopaque, f: *fs.Fs) void {
        const d: *Drives = @ptrCast(@alignCast(ctx));
        const dr = d.find(f.device_id) orelse return;
        if (dr.state != .probing) return;
        // Called from inside the Fs: it cannot be freed here.
        const stale = prepareMountPoint(dr.path) catch |e| {
            log.warn("drive {s}: mount point: {t}", .{ dr.path, e });
            dr.doomed = true;
            return;
        };
        dr.state = .mounting;
        d.backend.vtable.mount(d.backend.ptr, .{
            .id = dr.id,
            .handler = f.handler(),
            .path = dr.path,
            .read_only = f.readOnly(),
            .stale = stale,
            .notify = .{ .ctx = d, .f = notified },
        }) catch |e| {
            log.warn("drive {s}: mount: {t}", .{ dr.path, e });
            dr.state = .probing; // not handed to the backend
            dr.doomed = true;
        };
    }

    fn notified(ctx: *anyopaque, id: u32, ev: MountEvent) void {
        const d: *Drives = @ptrCast(@alignCast(ctx));
        d.mountEvent(id, ev);
    }

    /// What the backend reports (public for backends and tests).
    pub fn mountEvent(d: *Drives, id: u32, ev: MountEvent) void {
        const dr = d.find(id) orelse return;
        switch (ev) {
            .mounted => {
                if (dr.state != .mounting) return;
                dr.state = .mounted;
                log.info("drive mounted at {s}{s}", .{ dr.path, if (dr.fs.readOnly()) " (read-only)" else "" });
                d.makeLink(dr);
            },
            .failed => d.drop(dr, true),
            .gone => {
                log.info("drive {s} unmounted", .{dr.path});
                d.drop(dr, true);
            },
        }
    }

    /// Ends a drive: EIO to pending requests, unmount, link removed.
    /// `device_alive`: the client still has the device, so its open files are closed.
    fn drop(d: *Drives, dr: *Drive, device_alive: bool) void {
        dr.fs.abort(fs.errno(.IO), device_alive);
        if (dr.state != .probing) d.backend.vtable.unmount(d.backend.ptr, dr.id);
        if (dr.link) |l| {
            removeLink(l, dr.path);
            d.gpa.free(l);
        }
        // Gone once the lazy unmount is through (or already: nothing was mounted).
        _ = c.rmdir(dr.path.ptr);
        if (std.mem.indexOfScalar(*Drive, d.drives.items, dr)) |i| _ = d.drives.orderedRemove(i);
        dr.fs.deinit();
        d.gpa.destroy(dr.fs);
        d.gpa.free(dr.path);
        d.gpa.destroy(dr);
        if (d.drives.items.len == 0) d.removeLinkDir();
    }

    fn makeLink(d: *Drives, dr: *Drive) void {
        const ld = d.config.link_dir orelse return;
        const dev = d.session.device(dr.id) orelse return;
        if (!d.made_link_dir) {
            const ldz = d.gpa.dupeSentinel(u8, ld, 0) catch return;
            defer d.gpa.free(ldz);
            if (c.mkdir(ldz.ptr, 0o755) == 0) d.made_link_dir = true;
        }
        var name_buf: [256]u8 = undefined;
        const name = linkName(&name_buf, dev.name(), d.session.clientName());
        dr.link = createLink(d.gpa, ld, name, dr.path) catch |e| blk: {
            log.warn("drive {s}: no link in {s}: {t}", .{ dr.path, ld, e });
            break :blk null;
        };
    }

    fn removeLinkDir(d: *Drives) void {
        if (!d.made_link_dir) return;
        const ld = d.config.link_dir orelse return;
        const ldz = d.gpa.dupeSentinel(u8, ld, 0) catch return;
        defer d.gpa.free(ldz);
        // Only if empty: what the user put there stays.
        if (c.rmdir(ldz.ptr) == 0) d.made_link_dir = false;
    }
};

/// Creates the drives directory and mount point (0700) if missing. True when the
/// mount point is a dead FUSE mount (ENOTCONN) the backend must unmount first.
pub fn prepareMountPoint(path: [:0]const u8) !bool {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.BadPath;
    var buf: [4096]u8 = undefined;
    if (slash >= buf.len) return error.BadPath;
    const parent = path[0..slash];
    const omastation_end = std.mem.lastIndexOfScalar(u8, parent, '/') orelse return error.BadPath;
    for ([_][]const u8{ parent[0..omastation_end], parent }) |p| {
        @memcpy(buf[0..p.len], p);
        buf[p.len] = 0;
        if (c.mkdir(@ptrCast(&buf), 0o700) != 0 and errnoNow() != .EXIST) return error.MkdirFailed;
    }
    if (c.mkdir(path.ptr, 0o700) == 0) return false;
    switch (errnoNow()) {
        .EXIST => {},
        .NOTCONN => return true,
        else => return error.MkdirFailed,
    }
    var st: c.struct_stat = undefined;
    if (c.stat(path.ptr, &st) != 0) {
        if (errnoNow() == .NOTCONN) return true;
        return error.StatFailed;
    }
    if (st.st_mode & c.S_IFMT != c.S_IFDIR) return error.NotDir;
    return false;
}

fn errnoNow() std.os.linux.E {
    return @fromBackingInt(@as(u16, @intCast(std.c._errno().*)));
}

/// "<drive> on <client>" (computer name, 2.2.2.4) or the drive name alone;
/// '/' and control characters become '_', cut to 255 bytes on a character boundary.
pub fn linkName(out: *[256]u8, drive: []const u8, client: ?[]const u8) []const u8 {
    var n: usize = 0;
    const parts = [_][]const u8{ drive, if (client != null and client.?.len > 0) " on " else "", if (client) |cl| cl else "" };
    outer: for (parts) |p| {
        var i: usize = 0;
        while (i < p.len) {
            const len = std.unicode.utf8ByteSequenceLength(p[i]) catch 1;
            if (i + len > p.len or n + len > 255) break :outer;
            const ch = p[i];
            if (len == 1 and (ch == '/' or ch < 0x20 or ch == 0x7f)) {
                out[n] = '_';
            } else @memcpy(out[n..][0..len], p[i..][0..len]);
            n += len;
            i += len;
        }
    }
    if (n == 0 or std.mem.eql(u8, out[0..n], ".") or std.mem.eql(u8, out[0..n], "..")) {
        @memcpy(out[0..5], "drive");
        n = 5;
    }
    return out[0..n];
}

/// Creates "<dir>/<name>" -> `target`, or "<name> (2)".."(9)" if taken by something else.
/// An existing link into the drives directory is replaced. Returns the path (owned).
pub fn createLink(gpa: Allocator, dir: []const u8, name: []const u8, target: [:0]const u8) ![:0]u8 {
    var attempt: u32 = 1;
    while (attempt <= 9) : (attempt += 1) {
        const path = if (attempt == 1)
            try std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ dir, name }, 0)
        else
            try std.fmt.allocPrintSentinel(gpa, "{s}/{s} ({d})", .{ dir, name, attempt }, 0);
        errdefer gpa.free(path);
        if (c.symlink(target.ptr, path.ptr) == 0) return path;
        if (errnoNow() != .EXIST) return error.SymlinkFailed;
        // Ours from an earlier session: replace it.
        if (isOurLink(path, target)) {
            if (c.unlink(path.ptr) == 0 and c.symlink(target.ptr, path.ptr) == 0) return path;
        }
        gpa.free(path);
    }
    return error.NameTaken;
}

/// The link at `path` points into the directory holding `target`.
fn isOurLink(path: [:0]const u8, target: []const u8) bool {
    var buf: [4096]u8 = undefined;
    const n = c.readlink(path.ptr, &buf, buf.len);
    if (n <= 0) return false;
    const dest = buf[0..@intCast(n)];
    const dir_end = std.mem.lastIndexOfScalar(u8, target, '/') orelse return false;
    const dir = target[0 .. dir_end + 1];
    return dest.len > dir.len and std.mem.startsWith(u8, dest, dir) and std.mem.indexOfScalar(u8, dest[dir.len..], '/') == null;
}

pub fn removeLink(path: [:0]const u8, target: []const u8) void {
    var buf: [4096]u8 = undefined;
    const n = c.readlink(path.ptr, &buf, buf.len);
    if (n <= 0 or !std.mem.eql(u8, buf[0..@intCast(n)], target)) return;
    _ = c.unlink(path.ptr);
}

/// Removes links in `link_dir` into `drives_dir` whose mount point no longer exists.
pub fn removeStaleLinks(gpa: Allocator, link_dir: []const u8, drives_dir: []const u8) void {
    const dz = gpa.dupeSentinel(u8, link_dir, 0) catch return;
    defer gpa.free(dz);
    const dir = c.opendir(dz.ptr) orelse return;
    defer _ = c.closedir(dir);
    var prefix_buf: [4096]u8 = undefined;
    const prefix = std.fmt.bufPrint(&prefix_buf, "{s}/", .{drives_dir}) catch return;
    while (c.readdir(dir)) |ent| {
        const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.*.d_name)), 0);
        if (ent.*.d_type != c.DT_LNK) continue;
        const path = std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ link_dir, name }, 0) catch continue;
        defer gpa.free(path);
        var buf: [4096]u8 = undefined;
        const n = c.readlink(path.ptr, &buf, buf.len);
        if (n <= 0) continue;
        const dest = buf[0..@intCast(n)];
        if (!std.mem.startsWith(u8, dest, prefix) or std.mem.indexOfScalar(u8, dest[prefix.len..], '/') != null) continue;
        var st: c.struct_stat = undefined;
        if (c.stat(path.ptr, &st) == 0) continue; // still there
        _ = c.unlink(path.ptr);
    }
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
