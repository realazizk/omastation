//! MS-RDPECLIP files: the packed file list (2.2.5.2.3) and FILETIME, file: URIs (RFC 8089),
//! text/uri-list (RFC 2483) and x-special/gnome-copied-files, remote file name safety, and
//! local files served as FileGroupDescriptorW and File Contents (3.1.1.2, 3.1.5.4.6).

const std = @import("std");
const c = @import("../cliprdr.zig");
const bytes = @import("../../core/bytes.zig");
const text_impl = @import("text.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

/// fileName: 260 UTF-16 code units, the last one reserved for the null.
const file_name_units = c.file_name_field_len / 2;

/// Unpaired surrogates become U+FFFD.
fn appendUtf16AsUtf8(gpa: Allocator, out: *std.ArrayList(u8), le: []const u8) Allocator.Error!void {
    var it: text_impl.Utf16Iter = .{ .data = le };
    while (it.next()) |cp| try text_impl.appendUtf8(gpa, out, cp);
}

pub fn decodeFileList(gpa: Allocator, payload: []const u8) c.Error!c.FileList {
    var r = bytes.Reader.init(payload);
    const count = r.u32le() catch return error.InvalidFileList;
    // Checked before allocating: cItems comes from the peer.
    if (@as(u64, count) * c.file_descriptor_len > r.remaining()) return error.InvalidFileList;

    const files = try gpa.alloc(c.FileDescriptor, count);
    var done: usize = 0;
    errdefer {
        for (files[0..done]) |f| gpa.free(f.name);
        gpa.free(files);
    }
    var name: std.ArrayList(u8) = .empty;
    defer name.deinit(gpa);
    while (done < count) : (done += 1) {
        var d = r.sub(c.file_descriptor_len) catch unreachable;
        const flags = d.u32le() catch unreachable;
        d.skip(32) catch unreachable; // reserved1 (clsid, sizel, pointl)
        const attributes = d.u32le() catch unreachable;
        d.skip(16) catch unreachable; // reserved2 (creation and access times)
        const last_write_time = d.u64le() catch unreachable;
        const size_high: u64 = d.u32le() catch unreachable;
        const size_low: u64 = d.u32le() catch unreachable;
        const field = d.bytes(c.file_name_field_len) catch unreachable;
        // Bytes after the null are not guaranteed to be zero.
        const units = for (0..file_name_units) |i| {
            if (field[2 * i] == 0 and field[2 * i + 1] == 0) break i;
        } else return error.InvalidFileList;
        name.clearRetainingCapacity();
        try appendUtf16AsUtf8(gpa, &name, field[0 .. 2 * units]);
        files[done] = .{
            .flags = flags,
            .attributes = attributes,
            .last_write_time = last_write_time,
            .size = size_high << 32 | size_low,
            .name = try gpa.dupe(u8, name.items),
        };
    }
    return .{ .files = files };
}

pub fn encodeFileList(w: *bytes.Writer, files: []const c.FileDescriptor, negotiated_flags: u32) !void {
    if (files.len > std.math.maxInt(u32)) return error.InvalidFileList;
    const start = w.len();
    errdefer w.list.shrinkRetainingCapacity(start);
    try w.u32le(@intCast(files.len));
    for (files) |f| {
        // 2.2.2.1.1.1: sizes above 4 GiB need CB_HUGE_FILE_SUPPORT_ENABLED.
        if (f.size > std.math.maxInt(u32) and negotiated_flags & c.CB_HUGE_FILE_SUPPORT_ENABLED == 0)
            return error.FileTooLarge;
        const units = std.unicode.calcUtf16LeLen(f.name) catch return error.InvalidFileName;
        if (units >= file_name_units) return error.NameTooLong;
        var name: [file_name_units]u16 = @splat(0);
        _ = std.unicode.utf8ToUtf16Le(&name, f.name) catch return error.InvalidFileName;

        try w.u32le(f.flags);
        try w.zeros(32); // reserved1
        try w.u32le(f.attributes);
        try w.zeros(16); // reserved2
        try w.u32le(@truncate(f.last_write_time));
        try w.u32le(@truncate(f.last_write_time >> 32));
        try w.u32le(@truncate(f.size >> 32)); // fileSizeHigh
        try w.u32le(@truncate(f.size)); // fileSizeLow
        for (name) |u| try w.u16le(std.mem.littleToNative(u16, u));
    }
}

pub fn filetimeFromUnixNs(ns: i128) u64 {
    const ticks = @divFloor(ns, 100) + c.filetime_unix_epoch;
    if (ticks < 0) return 0;
    if (ticks > std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(ticks);
}

pub fn unixNsFromFiletime(ft: u64) i128 {
    return (@as(i128, ft) - c.filetime_unix_epoch) * 100;
}

/// RFC 3986 3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
fn isScheme(s: []const u8) bool {
    if (s.len == 0 or !std.ascii.isAlphabetic(s[0])) return false;
    for (s[1..]) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '+' and ch != '-' and ch != '.') return false;
    }
    return true;
}

pub fn uriToLocalPath(gpa: Allocator, uri: []const u8) c.Error![]u8 {
    if (uri.len == 0) return error.InvalidUri;
    const colon = std.mem.indexOfScalar(u8, uri, ':') orelse return error.UnsupportedUriScheme;
    const scheme = uri[0..colon];
    if (!isScheme(scheme) or !std.ascii.eqlIgnoreCase(scheme, "file")) return error.UnsupportedUriScheme;

    const rest = uri[colon + 1 ..];
    var path = rest;
    if (std.mem.startsWith(u8, rest, "//")) {
        // RFC 8089 2: an empty authority and "localhost" are the local host.
        const after = rest[2..];
        const slash = std.mem.indexOfScalar(u8, after, '/') orelse after.len;
        const host = after[0..slash];
        if (host.len != 0 and !std.ascii.eqlIgnoreCase(host, "localhost")) return error.NotLocalFile;
        path = after[slash..];
    }
    // Only absolute paths; "file:a.txt" is relative.
    if (path.len == 0 or path[0] != '/') return error.InvalidUri;

    const out = try gpa.alloc(u8, path.len);
    errdefer gpa.free(out);
    var n: usize = 0;
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        var b = path[i];
        if (b == '%') {
            if (path.len - i < 3) return error.InvalidUri;
            const hi = std.fmt.charToDigit(path[i + 1], 16) catch return error.InvalidUri;
            const lo = std.fmt.charToDigit(path[i + 2], 16) catch return error.InvalidUri;
            b = hi << 4 | lo;
            i += 2;
        }
        if (b == 0) return error.InvalidUri;
        out[n] = b;
        n += 1;
    }
    if (gpa.resize(out, n)) return out[0..n];
    const exact = try gpa.dupe(u8, out[0..n]);
    gpa.free(out);
    return exact;
}

/// RFC 3986 2.3 unreserved characters.
fn isUnreserved(b: u8) bool {
    return std.ascii.isAlphanumeric(b) or b == '-' or b == '.' or b == '_' or b == '~';
}

fn appendUri(gpa: Allocator, out: *std.ArrayList(u8), path: []const u8) c.Error!void {
    if (path.len == 0 or path[0] != '/') return error.InvalidUri;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidUri;
    try out.appendSlice(gpa, "file://");
    for (path) |b| {
        if (isUnreserved(b) or b == '/') {
            try out.append(gpa, b);
        } else {
            const digits = "0123456789ABCDEF";
            try out.appendSlice(gpa, &.{ '%', digits[b >> 4], digits[b & 15] });
        }
    }
}

pub fn localPathToUri(gpa: Allocator, path: []const u8) c.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try appendUri(gpa, &out, path);
    return out.toOwnedSlice(gpa);
}

/// Some toolkits append nulls to the data they hand over.
fn trimNulls(data: []const u8) []const u8 {
    return std.mem.trimEnd(u8, data, "\x00");
}

fn freePaths(gpa: Allocator, paths: *std.ArrayList([]u8)) void {
    for (paths.items) |p| gpa.free(p);
    paths.deinit(gpa);
}

pub fn parseUriList(gpa: Allocator, data: []const u8) c.Error!c.PathList {
    var paths: std.ArrayList([]u8) = .empty;
    errdefer freePaths(gpa, &paths);
    const text = trimNulls(data);
    // RFC 2483 5: CRLF line ends; a lone LF or CR and a missing final break are accepted.
    var pos: usize = 0;
    while (pos < text.len) {
        const end = std.mem.indexOfAnyPos(u8, text, pos, "\r\n") orelse text.len;
        const line = text[pos..end];
        pos = end;
        if (pos < text.len) {
            pos += if (text[pos] == '\r' and pos + 1 < text.len and text[pos + 1] == '\n') 2 else 1;
        }
        if (line.len == 0 or line[0] == '#') continue;
        const p = try uriToLocalPath(gpa, line);
        errdefer gpa.free(p);
        try paths.append(gpa, p);
    }
    return .{ .paths = try paths.toOwnedSlice(gpa) };
}

pub fn formatUriList(gpa: Allocator, paths: []const []const u8) c.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (paths) |p| {
        try appendUri(gpa, &out, p);
        try out.appendSlice(gpa, "\r\n");
    }
    return out.toOwnedSlice(gpa);
}

pub fn parseGnomeCopiedFiles(gpa: Allocator, data: []const u8) c.Error!c.CopiedFiles {
    var lines = std.mem.splitScalar(u8, trimNulls(data), '\n');
    const verb = std.mem.trimEnd(u8, lines.first(), "\r");
    const cut = if (std.mem.eql(u8, verb, "cut"))
        true
    else if (std.mem.eql(u8, verb, "copy"))
        false
    else
        return error.InvalidUri;
    var paths: std.ArrayList([]u8) = .empty;
    errdefer freePaths(gpa, &paths);
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        const p = try uriToLocalPath(gpa, line);
        errdefer gpa.free(p);
        try paths.append(gpa, p);
    }
    return .{ .cut = cut, .list = .{ .paths = try paths.toOwnedSlice(gpa) } };
}

pub fn formatGnomeCopiedFiles(gpa: Allocator, paths: []const []const u8, cut: bool) c.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, if (cut) "cut" else "copy");
    for (paths) |p| {
        try out.append(gpa, '\n');
        try appendUri(gpa, &out, p);
    }
    return out.toOwnedSlice(gpa);
}

/// Exact matches only: "CONx", "COM10" and "AUXILIARY" are fine.
fn isReservedDeviceName(name: []const u8) bool {
    if (name.len == 3) {
        for ([_][]const u8{ "CON", "PRN", "AUX", "NUL" }) |r| {
            if (std.ascii.eqlIgnoreCase(name, r)) return true;
        }
    } else if (name.len == 4 and std.ascii.isDigit(name[3])) {
        return std.ascii.eqlIgnoreCase(name[0..3], "COM") or std.ascii.eqlIgnoreCase(name[0..3], "LPT");
    }
    return false;
}

pub fn isValidRemoteNameComponent(name: []const u8) bool {
    if (name.len == 0) return false;
    // The peer sees UTF-16: bytes that are not UTF-8 have no name there.
    if (!std.unicode.utf8ValidateSlice(name)) return false;
    for (name) |b| switch (b) {
        0...0x1f, '<', '>', ':', '"', '/', '\\', '|', '?', '*' => return false,
        else => {},
    };
    // Covers "." and ".." too.
    if (name[name.len - 1] == ' ' or name[name.len - 1] == '.') return false;
    return !isReservedDeviceName(name);
}

/// Rejects absolute and UNC names (an empty first component or a drive "C:") and
/// empty, "." or ".." components.
fn isSafeRemoteName(name: []const u8) bool {
    var it = std.mem.splitScalar(u8, name, '\\');
    while (it.next()) |comp| if (!isValidRemoteNameComponent(comp)) return false;
    return true;
}

pub fn remoteNameToRelativePath(gpa: Allocator, name: []const u8) c.Error![]u8 {
    if (!isSafeRemoteName(name)) return error.InvalidFileName;
    const out = try gpa.dupe(u8, name);
    std.mem.replaceScalar(u8, out, '\\', '/');
    return out;
}

pub fn fileListToUriList(gpa: Allocator, base_dir: []const u8, files: []const c.FileDescriptor) c.Error![]u8 {
    for (files) |f| if (!isSafeRemoteName(f.name)) return error.InvalidFileName;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var path: std.ArrayList(u8) = .empty;
    defer path.deinit(gpa);
    const base = if (base_dir.len > 1) std.mem.trimEnd(u8, base_dir, "/") else base_dir;
    for (files) |f| {
        // Nested entries come with their top-level directory.
        if (std.mem.indexOfScalar(u8, f.name, '\\') != null) continue;
        path.clearRetainingCapacity();
        try path.appendSlice(gpa, base);
        if (!std.mem.endsWith(u8, base, "/")) try path.append(gpa, '/');
        try path.appendSlice(gpa, f.name);
        try appendUri(gpa, &out, path.items);
        try out.appendSlice(gpa, "\r\n");
    }
    return out.toOwnedSlice(gpa);
}

const Collector = struct {
    gpa: Allocator,
    io: Io,
    files: std.ArrayList(c.FileDescriptor) = .empty,
    paths: std.ArrayList([]u8) = .empty,
    /// Inodes of the directories being listed (symlink loop guard).
    ancestors: std.ArrayList(std.Io.File.INode) = .empty,
    /// Paths not to touch (stat, open), checked first.
    guard: ?c.PathGuard = null,
    /// Real path of the selected directory; symlinks below it leading elsewhere are not followed.
    top_real: ?[]const u8 = null,
    /// Entry cap: the walk fails as soon as it is exceeded.
    max_files: usize = std.math.maxInt(usize),

    fn deinit(col: *Collector) void {
        for (col.files.items) |f| col.gpa.free(f.name);
        col.files.deinit(col.gpa);
        for (col.paths.items) |p| col.gpa.free(p);
        col.paths.deinit(col.gpa);
        col.ancestors.deinit(col.gpa);
    }

    /// False for a symlink below the selected directory that leads out of it or nowhere.
    fn staysInside(col: *Collector, path: []const u8) Allocator.Error!bool {
        const top = col.top_real orelse return true;
        const lst = std.Io.Dir.cwd().statFile(col.io, path, .{ .follow_symlinks = false }) catch return true;
        if (lst.kind != .sym_link) return true;
        const real = std.Io.Dir.cwd().realPathFileAlloc(col.io, path, col.gpa) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return false,
        };
        defer col.gpa.free(real);
        return real.len > top.len and std.mem.startsWith(u8, real, top) and real[top.len] == '/';
    }

    /// Adds `local` as `remote`, then a directory's entries; takes ownership of both.
    fn add(col: *Collector, local: []u8, remote: []u8, st: std.Io.File.Stat) anyerror!void {
        const is_dir = st.kind == .directory;
        {
            errdefer col.gpa.free(local);
            errdefer col.gpa.free(remote);
            try col.files.ensureUnusedCapacity(col.gpa, 1);
            try col.paths.ensureUnusedCapacity(col.gpa, 1);
        }
        col.files.appendAssumeCapacity(.{
            .flags = c.FD_ATTRIBUTES | c.FD_FILESIZE | c.FD_WRITESTIME | c.FD_SHOWPROGRESSUI,
            .attributes = if (is_dir) c.FILE_ATTRIBUTE_DIRECTORY else c.FILE_ATTRIBUTE_NORMAL,
            .last_write_time = filetimeFromUnixNs(st.mtime.nanoseconds),
            .size = if (is_dir) 0 else st.size,
            .name = remote,
        });
        col.paths.appendAssumeCapacity(local);
        if (col.files.items.len > col.max_files) return error.InvalidFileList;
        if (!is_dir) return;

        try col.ancestors.append(col.gpa, st.inode);
        defer _ = col.ancestors.pop();

        // Sorted so the list does not depend on the directory's order.
        var names: std.ArrayList([]u8) = .empty;
        defer {
            for (names.items) |n| col.gpa.free(n);
            names.deinit(col.gpa);
        }
        {
            var dir = try std.Io.Dir.cwd().openDir(col.io, local, .{ .iterate = true });
            defer dir.close(col.io);
            var it = dir.iterate();
            while (try it.next(col.io)) |e| {
                const n = try col.gpa.dupe(u8, e.name);
                errdefer col.gpa.free(n);
                try names.append(col.gpa, n);
            }
        }
        std.mem.sort([]u8, names.items, {}, struct {
            fn lt(_: void, a: []u8, b: []u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lt);

        for (names.items) |n| {
            if (std.mem.eql(u8, n, ".") or std.mem.eql(u8, n, "..")) continue;
            // '\\' is a valid Linux name character but a separator to the peer.
            if (!isValidRemoteNameComponent(n)) return error.InvalidFileName;
            const child_local = try std.fs.path.join(col.gpa, &.{ local, n });
            if (col.guard) |g| if (g.refuse(g.ctx, child_local)) {
                col.gpa.free(child_local);
                continue;
            };
            if (!try col.staysInside(child_local)) {
                col.gpa.free(child_local);
                continue;
            }
            const child_st = std.Io.Dir.cwd().statFile(col.io, child_local, .{}) catch |e| {
                col.gpa.free(child_local);
                // A dangling symbolic link or an entry removed meanwhile.
                if (e == error.FileNotFound) continue;
                return e;
            };
            // Only regular files and directories; a directory symlinked into itself is not re-entered.
            const loop = child_st.kind == .directory and
                std.mem.indexOfScalar(std.Io.File.INode, col.ancestors.items, child_st.inode) != null;
            if ((child_st.kind != .file and child_st.kind != .directory) or loop) {
                col.gpa.free(child_local);
                continue;
            }
            const child_remote = std.mem.concat(col.gpa, u8, &.{ remote, "\\", n }) catch |e| {
                col.gpa.free(child_local);
                return e;
            };
            try col.add(child_local, child_remote, child_st);
        }
    }
};

pub fn describeLocalFiles(gpa: Allocator, io: Io, paths: []const []const u8, guard: ?c.PathGuard, max_files: usize) anyerror!c.LocalFiles {
    var col: Collector = .{ .gpa = gpa, .io = io, .guard = guard, .max_files = max_files };
    defer col.deinit();
    for (paths) |p| {
        // Names are base names (CB_FILECLIP_NO_FILE_PATHS).
        const base = std.fs.path.basename(p);
        if (!isValidRemoteNameComponent(base)) return error.InvalidFileName;
        if (guard) |g| if (g.refuse(g.ctx, p)) return error.AccessDenied;
        const st = try std.Io.Dir.cwd().statFile(io, p, .{});
        if (st.kind != .file and st.kind != .directory) return error.UnsupportedFileType;
        const local = try gpa.dupe(u8, p);
        const remote = gpa.dupe(u8, base) catch |e| {
            gpa.free(local);
            return e;
        };
        const top: ?[:0]u8 = if (st.kind == .directory)
            std.Io.Dir.cwd().realPathFileAlloc(io, p, gpa) catch |e| switch (e) {
                error.OutOfMemory => {
                    gpa.free(local);
                    gpa.free(remote);
                    return e;
                },
                else => null,
            }
        else
            null;
        defer if (top) |x| gpa.free(x);
        col.top_real = top;
        defer col.top_real = null;
        try col.add(local, remote, st);
    }
    const files = try col.files.toOwnedSlice(gpa);
    errdefer {
        for (files) |f| gpa.free(f.name);
        gpa.free(files);
    }
    const local_paths = try col.paths.toOwnedSlice(gpa);
    return .{ .list = .{ .files = files }, .paths = local_paths };
}

pub fn readFileContents(gpa: Allocator, io: Io, files: *const c.LocalFiles, req: c.FileContentsRequest) anyerror!?[]u8 {
    if (req.lindex < 0) return null;
    const i: usize = @intCast(req.lindex);
    if (i >= files.list.files.len or i >= files.paths.len) return null;
    if (files.list.files[i].attributes & c.FILE_ATTRIBUTE_DIRECTORY != 0) return null;

    const file = try std.Io.Dir.cwd().openFile(io, files.paths[i], .{});
    defer file.close(io);
    const st = try file.stat(io);
    if (st.kind == .directory) return null;
    const size = st.size;

    const kind = req.flags & (c.FILECONTENTS_SIZE | c.FILECONTENTS_RANGE);
    if (kind == c.FILECONTENTS_SIZE) {
        // MS-RDPECLIP 3.1.5.4.8: the size as a 64-bit little-endian integer.
        const out = try gpa.alloc(u8, 8);
        std.mem.writeInt(u64, out[0..8], size, .little);
        return out;
    }
    if (kind != c.FILECONTENTS_RANGE) return null;
    if (req.position > size) return null;
    const want: usize = @intCast(@min(@as(u64, req.cb_requested), size - req.position));
    const buf = try gpa.alloc(u8, want);
    errdefer gpa.free(buf);
    const got = try file.readPositionalAll(io, buf, req.position);
    if (got == want) return buf;
    // The file shrank since it was stat'ed.
    const out = try gpa.dupe(u8, buf[0..got]);
    gpa.free(buf);
    return out;
}
