//! Freedesktop lookups for RemoteApp: desktop entries (Desktop Entry Specification 1.5) and
//! icon themes (Icon Theme Specification 0.13). Only PNG icons are used.

const std = @import("std");
const c = @import("c");

const Allocator = std.mem.Allocator;

pub const Error = error{ OutOfMemory, InvalidExec };

pub const Dirs = struct {
    /// By priority: $XDG_DATA_HOME, then $XDG_DATA_DIRS.
    data: []const []const u8,
    /// Searched before the data directories (Icon Theme Specification "Directory Layout").
    home_icons: ?[]const u8 = null,
    theme: []const u8 = "hicolor",

    pub fn fromEnv(arena: Allocator, env: *const std.process.Environ.Map) error{OutOfMemory}!Dirs {
        var data: std.ArrayList([]const u8) = .empty;
        const home = env.get("HOME");
        if (env.get("XDG_DATA_HOME")) |d| {
            if (d.len > 0) try data.append(arena, d);
        } else if (home) |h| try data.append(arena, try std.fmt.allocPrint(arena, "{s}/.local/share", .{h}));
        const dirs = env.get("XDG_DATA_DIRS") orelse "";
        var it = std.mem.tokenizeScalar(u8, if (dirs.len > 0) dirs else "/usr/local/share:/usr/share", ':');
        while (it.next()) |d| try data.append(arena, d);
        const config_home = if (env.get("XDG_CONFIG_HOME")) |x| x else if (home) |h| try std.fmt.allocPrint(arena, "{s}/.config", .{h}) else null;
        const theme = if (config_home) |ch| try gtkIconTheme(arena, ch) else null;
        return .{
            .data = try data.toOwnedSlice(arena),
            .home_icons = if (home) |h| try std.fmt.allocPrint(arena, "{s}/.icons", .{h}) else null,
            .theme = theme orelse "hicolor",
        };
    }
};

pub fn gtkIconTheme(arena: Allocator, config_home: []const u8) error{OutOfMemory}!?[]const u8 {
    const path = try std.fmt.allocPrint(arena, "{s}/gtk-3.0/settings.ini", .{config_home});
    const text = readFile(arena, path, 64 * 1024) orelse return null;
    var group: []const u8 = "";
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;
        if (line[0] == '[') {
            group = line;
            continue;
        }
        if (!std.mem.eql(u8, group, "[Settings]")) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        if (!std.mem.eql(u8, std.mem.trim(u8, line[0..eq], " \t"), "gtk-icon-theme-name")) continue;
        const v = std.mem.trim(u8, line[eq + 1 ..], " \t\"");
        if (v.len > 0 and validName(v)) return try arena.dupe(u8, v);
    }
    return null;
}

/// A name that cannot leave its directory.
fn validName(s: []const u8) bool {
    if (s.len == 0 or s.len > 255 or s[0] == '.') return false;
    for (s) |ch| if (ch == '/' or ch == 0) return false;
    return true;
}

/// Null if missing, unreadable or larger than `max`.
pub fn readFile(arena: Allocator, path: []const u8, max: usize) ?[]u8 {
    const z = arena.dupeSentinel(u8, path, 0) catch return null;
    const fd = c.open(z.ptr, c.O_RDONLY | c.O_CLOEXEC);
    if (fd < 0) return null;
    defer _ = c.close(fd);
    var list: std.ArrayList(u8) = .empty;
    var buf: [16384]u8 = undefined;
    while (true) {
        const n = c.read(fd, &buf, buf.len);
        if (n < 0) return null;
        if (n == 0) break;
        if (list.items.len + @as(usize, @intCast(n)) > max) return null;
        list.appendSlice(arena, buf[0..@intCast(n)]) catch return null;
    }
    return list.items;
}

fn exists(arena: Allocator, path: []const u8) bool {
    const z = arena.dupeSentinel(u8, path, 0) catch return false;
    var st: c.struct_stat = undefined;
    return c.stat(z.ptr, &st) == 0 and (st.st_mode & c.S_IFMT) == c.S_IFREG;
}

pub fn isDir(arena: Allocator, path: []const u8) bool {
    const z = arena.dupeSentinel(u8, path, 0) catch return false;
    var st: c.struct_stat = undefined;
    return c.stat(z.ptr, &st) == 0 and (st.st_mode & c.S_IFMT) == c.S_IFDIR;
}

pub fn isExecutable(arena: Allocator, path: []const u8) bool {
    if (!exists(arena, path)) return false;
    const z = arena.dupeSentinel(u8, path, 0) catch return false;
    return c.access(z.ptr, c.X_OK) == 0;
}

const Entry = struct { name: []const u8, dir: bool };

/// Sorted by name, without . and ..; empty if unreadable.
fn listDir(arena: Allocator, path: []const u8) error{OutOfMemory}![]Entry {
    const z = try arena.dupeSentinel(u8, path, 0);
    const fd = c.open(z.ptr, c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
    if (fd < 0) return &.{};
    defer _ = c.close(fd);
    var out: std.ArrayList(Entry) = .empty;
    var buf: [8192]u8 align(@alignOf(std.os.linux.dirent64)) = undefined;
    while (true) {
        const rc = std.os.linux.getdents64(fd, &buf, buf.len);
        if (std.os.linux.errno(rc) != .SUCCESS or rc == 0) break;
        var off: usize = 0;
        while (off < rc) {
            const d: *const std.os.linux.dirent64 = @ptrCast(@alignCast(&buf[off]));
            off += d.reclen;
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&d.name)), 0);
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            const is_dir = if (d.type == std.os.linux.DT.UNKNOWN or d.type == std.os.linux.DT.LNK)
                isDir(arena, try std.fmt.allocPrint(arena, "{s}/{s}", .{ path, name }))
            else
                d.type == std.os.linux.DT.DIR;
            try out.append(arena, .{ .name = try arena.dupe(u8, name), .dir = is_dir });
        }
    }
    std.mem.sort(Entry, out.items, {}, struct {
        fn lt(_: void, a: Entry, b: Entry) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.lt);
    return out.items;
}

pub const DesktopEntry = struct {
    /// Desktop file ID without ".desktop" (subdirectories joined with '-').
    id: []const u8,
    path: []const u8,
    name: []const u8 = "",
    exec: []const u8 = "",
    try_exec: []const u8 = "",
    icon: []const u8 = "",
    startup_wm_class: []const u8 = "",
    /// The Path= key.
    working_dir: []const u8 = "",
    terminal: bool = false,
    no_display: bool = false,
    /// Hidden=true: deleted, yet it still masks the same ID in lower-priority directories.
    hidden: bool = false,
    application: bool = false,

    pub fn program(e: *const DesktopEntry, arena: Allocator) ?[]const u8 {
        const argv = expandExec(arena, e.exec, .{}) catch return null;
        return if (argv.len > 0) argv[0] else null;
    }
};

/// The [Desktop Entry] group; localized keys are ignored, values unescaped.
pub fn parseDesktopEntry(arena: Allocator, id: []const u8, path: []const u8, text: []const u8) error{OutOfMemory}!DesktopEntry {
    var e: DesktopEntry = .{ .id = id, .path = path };
    var in_group = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (line[0] == '[') {
            in_group = std.mem.eql(u8, line, "[Desktop Entry]");
            continue;
        }
        if (!in_group) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const value = try unescapeValue(arena, std.mem.trim(u8, line[eq + 1 ..], " \t"));
        const eql = std.mem.eql;
        const strings = .{
            .{ "Name", "name" }, .{ "Exec", "exec" },                       .{ "TryExec", "try_exec" },
            .{ "Icon", "icon" }, .{ "StartupWMClass", "startup_wm_class" }, .{ "Path", "working_dir" },
        };
        const flags = .{ .{ "Terminal", "terminal" }, .{ "NoDisplay", "no_display" }, .{ "Hidden", "hidden" } };
        inline for (strings) |s| if (eql(u8, key, s[0])) {
            @field(e, s[1]) = value;
        };
        inline for (flags) |f| if (eql(u8, key, f[0])) {
            @field(e, f[1]) = eql(u8, value, "true");
        };
        if (eql(u8, key, "Type")) e.application = eql(u8, value, "Application");
    }
    return e;
}

/// Desktop Entry Specification "Possible value types": \s \n \t \r \\.
fn unescapeValue(arena: Allocator, v: []const u8) error{OutOfMemory}![]const u8 {
    if (std.mem.indexOfScalar(u8, v, '\\') == null) return arena.dupe(u8, v);
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < v.len) : (i += 1) {
        if (v[i] == '\\' and i + 1 < v.len) {
            i += 1;
            try out.append(arena, switch (v[i]) {
                's' => ' ',
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '\\' => '\\',
                else => {
                    // Not a string escape (e.g. \" in Exec quoting): kept for the next layer.
                    try out.append(arena, '\\');
                    try out.append(arena, v[i]);
                    continue;
                },
            });
        } else try out.append(arena, v[i]);
    }
    return out.items;
}

/// Desktop entries of the data directories; the first one wins per ID.
pub const AppIndex = struct {
    entries: []const DesktopEntry = &.{},

    pub fn load(arena: Allocator, dirs: Dirs) error{OutOfMemory}!AppIndex {
        var list: std.ArrayList(DesktopEntry) = .empty;
        for (dirs.data) |d| {
            const apps = try std.fmt.allocPrint(arena, "{s}/applications", .{d});
            try scanApps(arena, &list, apps, "", 0);
        }
        return .{ .entries = list.items };
    }

    fn scanApps(arena: Allocator, list: *std.ArrayList(DesktopEntry), dir: []const u8, prefix: []const u8, depth: u32) error{OutOfMemory}!void {
        for (try listDir(arena, dir)) |ent| {
            const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, ent.name });
            if (ent.dir) {
                if (depth < 2 and validName(ent.name)) try scanApps(arena, list, path, try std.fmt.allocPrint(arena, "{s}{s}-", .{ prefix, ent.name }), depth + 1);
                continue;
            }
            if (!std.mem.endsWith(u8, ent.name, ".desktop")) continue;
            const id = try std.fmt.allocPrint(arena, "{s}{s}", .{ prefix, ent.name[0 .. ent.name.len - ".desktop".len] });
            if (id.len == 0) continue;
            for (list.items) |prev| {
                if (std.mem.eql(u8, prev.id, id)) break;
            } else {
                const text = readFile(arena, path, 256 * 1024) orelse continue;
                try list.append(arena, try parseDesktopEntry(arena, id, path, text));
            }
        }
    }

    fn usable(e: *const DesktopEntry) bool {
        return e.application and !e.hidden and e.exec.len > 0;
    }

    /// Case-insensitive, with or without ".desktop".
    pub fn byId(idx: *const AppIndex, id_in: []const u8) ?*const DesktopEntry {
        const id = if (std.ascii.endsWithIgnoreCase(id_in, ".desktop")) id_in[0 .. id_in.len - ".desktop".len] else id_in;
        if (id.len == 0) return null;
        for (idx.entries) |*e| if (std.mem.eql(u8, e.id, id)) return if (usable(e)) e else null;
        for (idx.entries) |*e| if (std.ascii.eqlIgnoreCase(e.id, id) and usable(e)) return e;
        return null;
    }

    /// Matches desktop file ID, StartupWMClass, last reverse-DNS component or Exec's program, case-insensitively.
    pub fn forClass(idx: *const AppIndex, arena: Allocator, class: []const u8) ?*const DesktopEntry {
        if (class.len == 0) return null;
        if (idx.byId(class)) |e| return e;
        for (idx.entries) |*e| if (usable(e) and std.ascii.eqlIgnoreCase(e.startup_wm_class, class)) return e;
        for (idx.entries) |*e| {
            if (!usable(e)) continue;
            const dot = std.mem.lastIndexOfScalar(u8, e.id, '.') orelse continue;
            if (std.ascii.eqlIgnoreCase(e.id[dot + 1 ..], class)) return e;
        }
        for (idx.entries) |*e| {
            if (!usable(e)) continue;
            const prog = e.program(arena) orelse continue;
            if (std.ascii.eqlIgnoreCase(std.fs.path.basename(prog), class)) return e;
        }
        return null;
    }

    /// A full path must equal Exec's program; a bare name matches its basename.
    pub fn forProgram(idx: *const AppIndex, arena: Allocator, program: []const u8) ?*const DesktopEntry {
        if (program.len == 0) return null;
        const has_slash = std.mem.indexOfScalar(u8, program, '/') != null;
        for (idx.entries) |*e| {
            if (!usable(e)) continue;
            const prog = e.program(arena) orelse continue;
            if (has_slash) {
                if (std.mem.eql(u8, prog, program)) return e;
            } else if (std.mem.eql(u8, std.fs.path.basename(prog), program)) return e;
        }
        return null;
    }
};

pub const Takes = enum { nothing, one, many };

/// Field code values (Desktop Entry Specification "The Exec key").
pub const ExecValues = struct {
    /// For %f %u (the first) and %F %U (all).
    args: []const []const u8 = &.{},
    /// For %i ("--icon" "<icon>").
    icon: []const u8 = "",
    /// For %c.
    name: []const u8 = "",
    /// For %k.
    location: []const u8 = "",
};

/// Which arguments Exec takes: %F/%U many, %f/%u one, else nothing.
pub fn execTakes(arena: Allocator, exec: []const u8) Error!Takes {
    const words = try splitExec(arena, exec);
    var t: Takes = .nothing;
    for (words) |w| {
        var i: usize = 0;
        while (std.mem.indexOfScalarPos(u8, w.text, i, '%')) |p| {
            if (p + 1 >= w.text.len) return error.InvalidExec;
            if (w.quoted_codes) {
                i = p + 2;
                continue;
            }
            switch (w.text[p + 1]) {
                'F', 'U' => t = .many,
                'f', 'u' => if (t == .nothing) {
                    t = .one;
                },
                else => {},
            }
            i = p + 2;
        }
    }
    return t;
}

const Word = struct {
    text: []const u8,
    /// % is literal inside double quotes.
    quoted_codes: bool,
};

/// Double quotes take \" \` \$ \\ escapes; single quotes and bare backslash escapes
/// are accepted as GLib's g_shell_parse_argv does.
fn splitExec(arena: Allocator, exec: []const u8) Error![]Word {
    var words: std.ArrayList(Word) = .empty;
    var cur: std.ArrayList(u8) = .empty;
    var in_word = false;
    var quoted = false;
    var i: usize = 0;
    while (i < exec.len) : (i += 1) {
        const ch = exec[i];
        switch (ch) {
            ' ', '\t' => {
                if (in_word) {
                    try words.append(arena, .{ .text = cur.items, .quoted_codes = quoted });
                    cur = .empty;
                    in_word = false;
                    quoted = false;
                }
            },
            '"' => {
                in_word = true;
                quoted = true;
                i += 1;
                while (i < exec.len and exec[i] != '"') : (i += 1) {
                    if (exec[i] == '\\' and i + 1 < exec.len and std.mem.indexOfScalar(u8, "\"`$\\", exec[i + 1]) != null) i += 1;
                    try cur.append(arena, exec[i]);
                }
                if (i >= exec.len) return error.InvalidExec;
            },
            '\'' => {
                in_word = true;
                quoted = true;
                i += 1;
                while (i < exec.len and exec[i] != '\'') : (i += 1) try cur.append(arena, exec[i]);
                if (i >= exec.len) return error.InvalidExec;
            },
            '\\' => {
                in_word = true;
                i += 1;
                if (i >= exec.len) return error.InvalidExec;
                try cur.append(arena, exec[i]);
            },
            else => {
                if (ch < 0x20 or ch == 0x7f) return error.InvalidExec;
                in_word = true;
                try cur.append(arena, ch);
            },
        }
    }
    if (in_word) try words.append(arena, .{ .text = cur.items, .quoted_codes = quoted });
    return words.items;
}

/// Deprecated %d %D %n %N %v %m are removed; any other unknown code, an unterminated quote
/// or an empty result is error.InvalidExec.
pub fn expandExec(arena: Allocator, exec: []const u8, v: ExecValues) Error![][]const u8 {
    const words = try splitExec(arena, exec);
    var argv: std.ArrayList([]const u8) = .empty;
    for (words) |w| {
        if (w.quoted_codes or std.mem.indexOfScalar(u8, w.text, '%') == null) {
            try argv.append(arena, w.text);
            continue;
        }
        // Only a word that is exactly a list or %i code expands to several words.
        if (w.text.len == 2 and w.text[0] == '%') switch (w.text[1]) {
            'F', 'U' => {
                for (v.args) |a| try argv.append(arena, a);
                continue;
            },
            'f', 'u' => {
                if (v.args.len > 0) try argv.append(arena, v.args[0]);
                continue;
            },
            'i' => {
                if (v.icon.len > 0) {
                    try argv.append(arena, "--icon");
                    try argv.append(arena, v.icon);
                }
                continue;
            },
            'd', 'D', 'n', 'N', 'v', 'm' => continue,
            else => {},
        };
        var out: std.ArrayList(u8) = .empty;
        var i: usize = 0;
        while (i < w.text.len) : (i += 1) {
            if (w.text[i] != '%') {
                try out.append(arena, w.text[i]);
                continue;
            }
            i += 1;
            if (i >= w.text.len) return error.InvalidExec;
            switch (w.text[i]) {
                '%' => try out.append(arena, '%'),
                'f', 'u', 'F', 'U' => if (v.args.len > 0) try out.appendSlice(arena, v.args[0]),
                'c' => try out.appendSlice(arena, v.name),
                'k' => try out.appendSlice(arena, v.location),
                'i' => try out.appendSlice(arena, v.icon),
                'd', 'D', 'n', 'N', 'v', 'm' => {},
                else => return error.InvalidExec,
            }
        }
        try argv.append(arena, out.items);
    }
    if (argv.items.len == 0 or argv.items[0].len == 0) return error.InvalidExec;
    return argv.items;
}

/// One single-quoted POSIX shell word; Hyprland runs exec commands through /bin/sh -c.
pub fn shellQuote(arena: Allocator, s: []const u8) error{OutOfMemory}![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(arena, '\'');
    for (s) |ch| {
        if (ch == '\'') try out.appendSlice(arena, "'\\''") else try out.append(arena, ch);
    }
    try out.append(arena, '\'');
    return out.items;
}

/// Searches a PATH-style list unless `program` contains a '/'.
pub fn findProgram(arena: Allocator, program: []const u8, path: []const u8) ?[]const u8 {
    if (program.len == 0) return null;
    if (std.mem.indexOfScalar(u8, program, '/') != null) return if (isExecutable(arena, program)) program else null;
    var it = std.mem.tokenizeScalar(u8, path, ':');
    while (it.next()) |d| {
        const full = std.fmt.allocPrint(arena, "{s}/{s}", .{ d, program }) catch return null;
        if (isExecutable(arena, full)) return full;
    }
    return null;
}

const DirKind = enum { fixed, scalable, threshold };

const ThemeDir = struct {
    path: []const u8,
    size: u32,
    scale: u32 = 1,
    kind: DirKind = .threshold,
    min: u32,
    max: u32,
    threshold: u32 = 2,

    /// DirectoryMatchesSize at scale 1.
    fn matches(d: ThemeDir, px: u32) bool {
        return switch (d.kind) {
            .fixed => d.size * d.scale == px,
            .scalable => d.min * d.scale <= px and px <= d.max * d.scale,
            .threshold => d.size * d.scale -| d.threshold * d.scale <= px and px <= (d.size + d.threshold) * d.scale,
        };
    }

    /// DirectorySizeDistance, except larger icons always beat smaller ones
    /// (downscaling looks better than upscaling).
    fn distance(d: ThemeDir, px: u32) u32 {
        if (d.matches(px)) return 0;
        const lo = (if (d.kind == .scalable) d.min else d.size) * d.scale;
        const hi = (if (d.kind == .scalable) d.max else d.size) * d.scale;
        if (lo > px) return lo - px;
        return 1_000_000 + (px - hi);
    }
};

const Theme = struct {
    name: []const u8,
    dirs: []const ThemeDir,
    inherits: []const []const u8,
};

pub const IconThemes = struct {
    base: []const []const u8,
    pixmaps: []const []const u8,
    chain: []const Theme,

    pub fn load(arena: Allocator, dirs: Dirs) error{OutOfMemory}!IconThemes {
        var base: std.ArrayList([]const u8) = .empty;
        var pixmaps: std.ArrayList([]const u8) = .empty;
        if (dirs.home_icons) |h| try base.append(arena, h);
        for (dirs.data) |d| {
            try base.append(arena, try std.fmt.allocPrint(arena, "{s}/icons", .{d}));
            try pixmaps.append(arena, try std.fmt.allocPrint(arena, "{s}/pixmaps", .{d}));
        }
        var t: IconThemes = .{ .base = base.items, .pixmaps = pixmaps.items, .chain = &.{} };
        var chain: std.ArrayList(Theme) = .empty;
        try t.addTheme(arena, &chain, if (validName(dirs.theme)) dirs.theme else "hicolor", 0);
        try t.addTheme(arena, &chain, "hicolor", 0);
        t.chain = chain.items;
        return t;
    }

    fn addTheme(t: *const IconThemes, arena: Allocator, chain: *std.ArrayList(Theme), name: []const u8, depth: u32) error{OutOfMemory}!void {
        if (depth > 8 or !validName(name)) return;
        for (chain.items) |th| if (std.mem.eql(u8, th.name, name)) return;
        const theme = (try t.parseTheme(arena, name)) orelse return;
        try chain.append(arena, theme);
        for (theme.inherits) |parent| try t.addTheme(arena, chain, parent, depth + 1);
    }

    /// index.theme of the first base directory that has the theme.
    fn parseTheme(t: *const IconThemes, arena: Allocator, name: []const u8) error{OutOfMemory}!?Theme {
        const text = for (t.base) |b| {
            const p = try std.fmt.allocPrint(arena, "{s}/{s}/index.theme", .{ b, name });
            if (readFile(arena, p, 1 << 20)) |x| break x;
        } else return null;
        var dirs: std.ArrayList(ThemeDir) = .empty;
        var inherits: std.ArrayList([]const u8) = .empty;
        var listed: std.ArrayList([]const u8) = .empty;
        var group: []const u8 = "";
        var cur: ?ThemeDir = null;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            if (line[0] == '[' and line[line.len - 1] == ']') {
                if (cur) |d| try dirs.append(arena, d);
                group = line[1 .. line.len - 1];
                cur = null;
                for (listed.items) |l| if (std.mem.eql(u8, l, group)) {
                    cur = .{ .path = group, .size = 0, .min = 0, .max = 0 };
                };
                continue;
            }
            const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
            const key = std.mem.trim(u8, line[0..eq], " \t");
            const value = std.mem.trim(u8, line[eq + 1 ..], " \t");
            if (std.mem.eql(u8, group, "Icon Theme")) {
                if (std.mem.eql(u8, key, "Directories") or std.mem.eql(u8, key, "ScaledDirectories")) {
                    var it = std.mem.tokenizeScalar(u8, value, ',');
                    while (it.next()) |d| try listed.append(arena, std.mem.trim(u8, d, " "));
                } else if (std.mem.eql(u8, key, "Inherits")) {
                    var it = std.mem.tokenizeScalar(u8, value, ',');
                    while (it.next()) |p| try inherits.append(arena, std.mem.trim(u8, p, " "));
                }
                continue;
            }
            if (cur) |*d| {
                const num = std.fmt.parseInt(u32, value, 10) catch null;
                if (std.mem.eql(u8, key, "Size")) {
                    d.size = num orelse 0;
                } else if (std.mem.eql(u8, key, "Scale")) {
                    d.scale = @max(1, num orelse 1);
                } else if (std.mem.eql(u8, key, "MinSize")) {
                    d.min = num orelse 0;
                } else if (std.mem.eql(u8, key, "MaxSize")) {
                    d.max = num orelse 0;
                } else if (std.mem.eql(u8, key, "Threshold")) {
                    d.threshold = num orelse 2;
                } else if (std.mem.eql(u8, key, "Type")) {
                    d.kind = if (std.mem.eql(u8, value, "Fixed")) .fixed else if (std.mem.eql(u8, value, "Scalable")) .scalable else .threshold;
                }
            }
        }
        if (cur) |d| try dirs.append(arena, d);
        // Directories without Size are invalid; MinSize/MaxSize default to Size.
        var valid: std.ArrayList(ThemeDir) = .empty;
        for (dirs.items) |d0| {
            var d = d0;
            if (d.size == 0) continue;
            if (d.min == 0) d.min = d.size;
            if (d.max == 0) d.max = d.size;
            try valid.append(arena, d);
        }
        return .{ .name = name, .dirs = valid.items, .inherits = inherits.items };
    }

    /// Exact size in the first theme of the chain that has one, else its closest size, else the
    /// next theme, then pixmaps. An absolute Icon= PNG path is used as is.
    pub fn find(t: *const IconThemes, arena: Allocator, name_in: []const u8, px: u32) error{OutOfMemory}!?[]const u8 {
        if (name_in.len == 0) return null;
        if (name_in[0] == '/') {
            if (std.ascii.endsWithIgnoreCase(name_in, ".png") and exists(arena, name_in)) return name_in;
            return null;
        }
        var name = name_in;
        for ([_][]const u8{ ".png", ".svg", ".xpm" }) |ext| {
            if (std.ascii.endsWithIgnoreCase(name, ext)) name = name[0 .. name.len - ext.len];
        }
        if (!validName(name)) return null;
        for (t.chain) |th| {
            var best: ?[]const u8 = null;
            var best_d: u32 = std.math.maxInt(u32);
            for (th.dirs) |d| {
                const dist = d.distance(px);
                if (dist >= best_d) continue;
                for (t.base) |b| {
                    const p = try std.fmt.allocPrint(arena, "{s}/{s}/{s}/{s}.png", .{ b, th.name, d.path, name });
                    if (exists(arena, p)) {
                        best = p;
                        best_d = dist;
                        break;
                    }
                }
                if (best_d == 0) break;
            }
            if (best) |p| return p;
        }
        for (t.pixmaps) |d| {
            const p = try std.fmt.allocPrint(arena, "{s}/{s}.png", .{ d, name });
            if (exists(arena, p)) return p;
        }
        return null;
    }
};

test "Exec expansion follows the Desktop Entry Specification" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const argv = try expandExec(a, "foo --name=%c \"a b\" %F %i %d", .{ .args = &.{ "/x", "/y" }, .name = "Foo", .icon = "foo" });
    const want = [_][]const u8{ "foo", "--name=Foo", "a b", "/x", "/y", "--icon", "foo" };
    try std.testing.expectEqual(want.len, argv.len);
    for (want, argv) |w, g| try std.testing.expectEqualStrings(w, g);
    try std.testing.expectEqual(Takes.one, try execTakes(a, "foo %u"));
    try std.testing.expectEqual(Takes.nothing, try execTakes(a, "foo \"%u\""));
    try std.testing.expectError(error.InvalidExec, expandExec(a, "foo \"bar", .{}));
    try std.testing.expectError(error.InvalidExec, expandExec(a, "foo %z", .{}));
    try std.testing.expectEqualStrings("'it'\\''s'", try shellQuote(a, "it's"));
}
