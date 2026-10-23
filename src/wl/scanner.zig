//! Wayland protocol scanner: reads protocol XML and emits one Zig file with a typed proxy
//! per interface. Run at build time (`wl-scanner OUT.zig IN.xml...`); the output imports only
//! `std` and is duck-typed against `conn: anytype` so wire.zig can import it without a cycle.

const std = @import("std");
const Allocator = std.mem.Allocator;

// Protocol model

pub const ArgType = enum { int, uint, fixed, string, object, new_id, array, fd };

pub const Arg = struct {
    name: []const u8,
    type: ArgType,
    interface: ?[]const u8 = null,
    allow_null: bool = false,
    enum_name: ?[]const u8 = null,
    summary: ?[]const u8 = null,
};

pub const Message = struct {
    name: []const u8,
    destructor: bool = false,
    since: u32 = 1,
    summary: ?[]const u8 = null,
    args: []const Arg = &.{},
};

pub const Entry = struct {
    name: []const u8,
    value: u32,
    summary: ?[]const u8 = null,
};

pub const Enum = struct {
    name: []const u8,
    bitfield: bool = false,
    summary: ?[]const u8 = null,
    entries: []const Entry = &.{},
};

pub const Interface = struct {
    name: []const u8,
    version: u32,
    summary: ?[]const u8 = null,
    requests: []const Message = &.{},
    events: []const Message = &.{},
    enums: []const Enum = &.{},
};

pub const Protocol = struct {
    name: []const u8,
    interfaces: []const Interface,
};

pub const ParseError = error{ InvalidXml, InvalidProtocol, OutOfMemory };

// Minimal XML tokenizer: elements with quoted attributes, comments, PIs, CDATA and text.

const Attr = struct { name: []const u8, value: []const u8 };

const Tag = struct {
    kind: enum { open, close, empty },
    name: []const u8,
    attrs: []const Attr,
};

const Tokenizer = struct {
    src: []const u8,
    pos: usize = 0,
    arena: Allocator,

    fn next(t: *Tokenizer) ParseError!?Tag {
        while (true) {
            const lt = std.mem.indexOfScalarPos(u8, t.src, t.pos, '<') orelse return null;
            t.pos = lt;
            const rest = t.src[t.pos..];
            if (std.mem.startsWith(u8, rest, "<!--")) {
                const end = std.mem.indexOfPos(u8, t.src, t.pos + 4, "-->") orelse return error.InvalidXml;
                t.pos = end + 3;
                continue;
            }
            if (std.mem.startsWith(u8, rest, "<![CDATA[")) {
                const end = std.mem.indexOfPos(u8, t.src, t.pos, "]]>") orelse return error.InvalidXml;
                t.pos = end + 3;
                continue;
            }
            if (std.mem.startsWith(u8, rest, "<?") or std.mem.startsWith(u8, rest, "<!")) {
                const end = std.mem.indexOfScalarPos(u8, t.src, t.pos, '>') orelse return error.InvalidXml;
                t.pos = end + 1;
                continue;
            }
            return try t.tag();
        }
    }

    fn tag(t: *Tokenizer) ParseError!Tag {
        t.pos += 1; // '<'
        var kind: @FieldType(Tag, "kind") = .open;
        if (t.pos < t.src.len and t.src[t.pos] == '/') {
            kind = .close;
            t.pos += 1;
        }
        const name = t.ident();
        if (name.len == 0) return error.InvalidXml;
        var attrs: std.ArrayList(Attr) = .empty;
        while (true) {
            t.skipSpace();
            if (t.pos >= t.src.len) return error.InvalidXml;
            const ch = t.src[t.pos];
            if (ch == '>') {
                t.pos += 1;
                break;
            }
            if (ch == '/') {
                if (t.pos + 1 >= t.src.len or t.src[t.pos + 1] != '>') return error.InvalidXml;
                if (kind == .close) return error.InvalidXml;
                kind = .empty;
                t.pos += 2;
                break;
            }
            if (kind == .close) return error.InvalidXml;
            const an = t.ident();
            if (an.len == 0) return error.InvalidXml;
            t.skipSpace();
            if (t.pos >= t.src.len or t.src[t.pos] != '=') return error.InvalidXml;
            t.pos += 1;
            t.skipSpace();
            if (t.pos >= t.src.len) return error.InvalidXml;
            const q = t.src[t.pos];
            if (q != '"' and q != '\'') return error.InvalidXml;
            const end = std.mem.indexOfScalarPos(u8, t.src, t.pos + 1, q) orelse return error.InvalidXml;
            const raw = t.src[t.pos + 1 .. end];
            t.pos = end + 1;
            try attrs.append(t.arena, .{ .name = an, .value = try unescape(t.arena, raw) });
        }
        return .{ .kind = kind, .name = name, .attrs = attrs.items };
    }

    fn ident(t: *Tokenizer) []const u8 {
        const start = t.pos;
        while (t.pos < t.src.len) : (t.pos += 1) {
            const ch = t.src[t.pos];
            if (!(std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '-' or ch == ':' or ch == '.')) break;
        }
        return t.src[start..t.pos];
    }

    fn skipSpace(t: *Tokenizer) void {
        while (t.pos < t.src.len and std.ascii.isWhitespace(t.src[t.pos])) t.pos += 1;
    }
};

fn unescape(arena: Allocator, raw: []const u8) ParseError![]const u8 {
    if (std.mem.indexOfScalar(u8, raw, '&') == null) return raw;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < raw.len) {
        if (raw[i] == '&') {
            const semi = std.mem.indexOfScalarPos(u8, raw, i, ';') orelse return error.InvalidXml;
            const ent = raw[i + 1 .. semi];
            const ch: u8 = if (std.mem.eql(u8, ent, "lt")) '<' else if (std.mem.eql(u8, ent, "gt")) '>' else if (std.mem.eql(u8, ent, "amp")) '&' else if (std.mem.eql(u8, ent, "quot")) '"' else if (std.mem.eql(u8, ent, "apos")) '\'' else '?';
            try out.append(arena, ch);
            i = semi + 1;
        } else {
            try out.append(arena, raw[i]);
            i += 1;
        }
    }
    return out.items;
}

fn attr(attrs: []const Attr, name: []const u8) ?[]const u8 {
    for (attrs) |a| if (std.mem.eql(u8, a.name, name)) return a.value;
    return null;
}

fn parseU32(s: []const u8) ParseError!u32 {
    return std.fmt.parseInt(u32, std.mem.trim(u8, s, " \t\r\n"), 0) catch error.InvalidProtocol;
}

/// As wayland-scanner's strtouint: base 10, leading space and sign allowed, 0..INT_MAX.
fn parseVersion(s: []const u8) ParseError!u32 {
    var d = std.mem.trimStart(u8, s, " \t\r\n\x0b\x0c");
    if (d.len > 0 and d[0] == '+') d = d[1..];
    if (d.len == 0) return error.InvalidProtocol;
    var v: u32 = 0;
    for (d) |ch| {
        if (ch < '0' or ch > '9') return error.InvalidProtocol;
        v = std.math.mul(u32, v, 10) catch return error.InvalidProtocol;
        v = std.math.add(u32, v, ch - '0') catch return error.InvalidProtocol;
    }
    if (v > std.math.maxInt(i32)) return error.InvalidProtocol;
    return v;
}

/// As wayland-scanner verify_arguments: enum= only on int/uint, bitfields only on uint.
fn verifyEnumArgs(ifaces: []const Interface) ParseError!void {
    for (ifaces) |*iface| {
        for ([_][]const Message{ iface.requests, iface.events }) |msgs| {
            for (msgs) |m| for (m.args) |a| {
                const ref = a.enum_name orelse continue;
                if (ref.len == 0) continue;
                switch (a.type) {
                    .uint => {},
                    .int => if (findEnum(ifaces, iface, ref)) |e| {
                        if (e.bitfield) return error.InvalidProtocol;
                    },
                    else => return error.InvalidProtocol,
                }
            };
        }
    }
}

fn findEnum(ifaces: []const Interface, iface: *const Interface, ref: []const u8) ?*const Enum {
    var owner: ?*const Interface = iface;
    var ename = ref;
    if (std.mem.indexOfScalar(u8, ref, '.')) |dot| {
        owner = null;
        for (ifaces) |*i| if (std.mem.eql(u8, i.name, ref[0..dot])) {
            owner = i;
        };
        ename = ref[dot + 1 ..];
    }
    for ((owner orelse return null).enums) |*e| if (std.mem.eql(u8, e.name, ename)) return e;
    return null;
}

/// All memory comes from `arena`.
pub fn parse(arena: Allocator, xml: []const u8) ParseError!Protocol {
    var tok: Tokenizer = .{ .src = xml, .arena = arena };

    var proto_name: ?[]const u8 = null;
    var ifaces: std.ArrayList(Interface) = .empty;

    var cur_iface: ?Interface = null;
    var requests: std.ArrayList(Message) = .empty;
    var events: std.ArrayList(Message) = .empty;
    var enums: std.ArrayList(Enum) = .empty;
    var cur_msg: ?Message = null;
    var cur_msg_is_event = false;
    var args: std.ArrayList(Arg) = .empty;
    var cur_enum: ?Enum = null;
    var entries: std.ArrayList(Entry) = .empty;

    while (try tok.next()) |t| {
        const is_start = t.kind != .close;
        const is_end = t.kind != .open;
        if (std.mem.eql(u8, t.name, "protocol")) {
            if (is_start) proto_name = attr(t.attrs, "name") orelse return error.InvalidProtocol;
        } else if (std.mem.eql(u8, t.name, "interface")) {
            if (is_start) {
                if (cur_iface != null) return error.InvalidProtocol;
                // version is #REQUIRED (wayland.dtd), decimal, not 0.
                const version = try parseVersion(attr(t.attrs, "version") orelse return error.InvalidProtocol);
                if (version == 0) return error.InvalidProtocol;
                cur_iface = .{
                    .name = attr(t.attrs, "name") orelse return error.InvalidProtocol,
                    .version = version,
                };
                requests = .empty;
                events = .empty;
                enums = .empty;
            }
            if (is_end) {
                var iface = cur_iface orelse return error.InvalidProtocol;
                iface.requests = requests.items;
                iface.events = events.items;
                iface.enums = enums.items;
                try ifaces.append(arena, iface);
                cur_iface = null;
            }
        } else if (std.mem.eql(u8, t.name, "request") or std.mem.eql(u8, t.name, "event")) {
            if (is_start) {
                if (cur_iface == null or cur_msg != null) return error.InvalidProtocol;
                const ty = attr(t.attrs, "type");
                cur_msg = .{
                    .name = attr(t.attrs, "name") orelse return error.InvalidProtocol,
                    .destructor = ty != null and std.mem.eql(u8, ty.?, "destructor"),
                    .since = if (attr(t.attrs, "since")) |s| try parseVersion(s) else 1,
                };
                // As wayland-scanner: since <= version; destroy requests are destructors.
                if (cur_msg.?.since > cur_iface.?.version) return error.InvalidProtocol;
                if (std.mem.eql(u8, cur_msg.?.name, "destroy") and !cur_msg.?.destructor) return error.InvalidProtocol;
                cur_msg_is_event = std.mem.eql(u8, t.name, "event");
                args = .empty;
            }
            if (is_end) {
                var m = cur_msg orelse return error.InvalidProtocol;
                m.args = args.items;
                if (cur_msg_is_event) try events.append(arena, m) else try requests.append(arena, m);
                cur_msg = null;
            }
        } else if (std.mem.eql(u8, t.name, "arg")) {
            if (is_start) {
                if (cur_msg == null) return error.InvalidProtocol;
                const ty_s = attr(t.attrs, "type") orelse return error.InvalidProtocol;
                const ty = std.meta.stringToEnum(ArgType, ty_s) orelse return error.InvalidProtocol;
                const an = attr(t.attrs, "allow-null");
                // As wayland-scanner: interface= only on object/new_id; allow-null only on nullable types.
                const ref_type = ty == .object or ty == .new_id;
                if (attr(t.attrs, "interface") != null and !ref_type) return error.InvalidProtocol;
                if (an) |v| {
                    if (!std.mem.eql(u8, v, "true") and !std.mem.eql(u8, v, "false")) return error.InvalidProtocol;
                    if (!ref_type and ty != .string and ty != .array) return error.InvalidProtocol;
                }
                try args.append(arena, .{
                    .name = attr(t.attrs, "name") orelse return error.InvalidProtocol,
                    .type = ty,
                    .interface = attr(t.attrs, "interface"),
                    .allow_null = an != null and std.mem.eql(u8, an.?, "true"),
                    .enum_name = attr(t.attrs, "enum"),
                    .summary = attr(t.attrs, "summary"),
                });
            }
        } else if (std.mem.eql(u8, t.name, "enum")) {
            if (is_start) {
                if (cur_iface == null or cur_enum != null) return error.InvalidProtocol;
                const bf = attr(t.attrs, "bitfield");
                if (bf) |v| {
                    if (!std.mem.eql(u8, v, "true") and !std.mem.eql(u8, v, "false")) return error.InvalidProtocol;
                }
                cur_enum = .{
                    .name = attr(t.attrs, "name") orelse return error.InvalidProtocol,
                    .bitfield = bf != null and std.mem.eql(u8, bf.?, "true"),
                };
                entries = .empty;
            }
            if (is_end) {
                var e = cur_enum orelse return error.InvalidProtocol;
                if (entries.items.len == 0) return error.InvalidProtocol; // "enumeration %s was empty"
                e.entries = entries.items;
                try enums.append(arena, e);
                cur_enum = null;
            }
        } else if (std.mem.eql(u8, t.name, "entry")) {
            if (is_start) {
                if (cur_enum == null) return error.InvalidProtocol;
                try entries.append(arena, .{
                    .name = attr(t.attrs, "name") orelse return error.InvalidProtocol,
                    .value = try parseU32(attr(t.attrs, "value") orelse return error.InvalidProtocol),
                    .summary = attr(t.attrs, "summary"),
                });
            }
        } else if (std.mem.eql(u8, t.name, "description")) {
            if (is_start) {
                const s = attr(t.attrs, "summary");
                if (cur_enum) |*e| {
                    e.summary = s;
                } else if (cur_msg) |*m| {
                    m.summary = s;
                } else if (cur_iface) |*i| {
                    i.summary = s;
                }
            }
        }
    }
    if (cur_iface != null or cur_msg != null or cur_enum != null) return error.InvalidProtocol;
    try verifyEnumArgs(ifaces.items);
    return .{ .name = proto_name orelse return error.InvalidProtocol, .interfaces = ifaces.items };
}

// Code generation

const Writer = std.Io.Writer;

/// `wl_display` -> `WlDisplay`.
fn writeTitle(w: *Writer, snake: []const u8) Writer.Error!void {
    var it = std.mem.splitScalar(u8, snake, '_');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        try w.writeByte(std.ascii.toUpper(part[0]));
        try w.writeAll(part[1..]);
    }
}

/// `create_session` -> `createSession`.
fn writeCamel(w: *Writer, snake: []const u8) Writer.Error!void {
    var it = std.mem.splitScalar(u8, snake, '_');
    var first = true;
    while (it.next()) |part| {
        if (part.len == 0) continue;
        if (first) {
            try w.writeAll(part);
            first = false;
        } else {
            try w.writeByte(std.ascii.toUpper(part[0]));
            try w.writeAll(part[1..]);
        }
    }
}

fn titleAlloc(a: Allocator, snake: []const u8) ![]const u8 {
    var aw: Writer.Allocating = .init(a);
    try writeTitle(&aw.writer, snake);
    return aw.written();
}

fn camelAlloc(a: Allocator, snake: []const u8) ![]const u8 {
    var aw: Writer.Allocating = .init(a);
    try writeCamel(&aw.writer, snake);
    return aw.written();
}

fn writeDoc(w: *Writer, indent: []const u8, text: ?[]const u8) Writer.Error!void {
    const s = text orelse return;
    var it = std.mem.splitScalar(u8, s, '\n');
    while (it.next()) |line| {
        const l = std.mem.trim(u8, line, " \t\r");
        try w.print("{s}/// {s}\n", .{ indent, l });
    }
}

const Gen = struct {
    arena: Allocator,
    w: *Writer,
    protocols: []const Protocol,

    fn findInterface(g: *const Gen, name: []const u8) ?*const Interface {
        for (g.protocols) |*p| for (p.interfaces) |*i| if (std.mem.eql(u8, i.name, name)) return i;
        return null;
    }

    /// Zig type path of `enum="x"` / `enum="iface.x"`; null for bitfields or unknown (plain u32).
    fn enumType(g: *const Gen, iface: *const Interface, ref: []const u8) !?[]const u8 {
        var owner = iface;
        var ename = ref;
        if (std.mem.indexOfScalar(u8, ref, '.')) |dot| {
            owner = g.findInterface(ref[0..dot]) orelse return null;
            ename = ref[dot + 1 ..];
        }
        for (owner.enums) |e| {
            if (!std.mem.eql(u8, e.name, ename)) continue;
            if (e.bitfield) return null;
            return try std.fmt.allocPrint(g.arena, "{s}.{s}", .{ try titleAlloc(g.arena, owner.name), try enumTypeName(g.arena, e.name) });
        }
        return null;
    }

    fn knownIface(g: *const Gen, name: ?[]const u8) bool {
        return name != null and g.findInterface(name.?) != null;
    }
};

fn enumTypeName(a: Allocator, name: []const u8) ![]const u8 {
    const t = try titleAlloc(a, name);
    // Avoid clashing with the generated `Event` union.
    if (std.mem.eql(u8, t, "Event")) return "EventEnum";
    return t;
}

const preamble =
    \\//! Generated by src/wl/scanner.zig from the protocol XML in protocols/.
    \\//! Do not edit. See scanner.zig for the duck-typed `conn` contract.
    \\
    \\const std = @import("std");
    \\
    \\/// wl_fixed_t: signed 24.8 fixed point.
    \\pub const Fixed = enum(i32) {
    \\    _,
    \\
    \\    pub fn fromInt(v: i32) Fixed {
    \\        return @fromBackingInt(std.math.shl(i32, v, 8));
    \\    }
    \\
    \\    pub fn fromFloat(v: f64) Fixed {
    \\        const clamped = std.math.clamp(v * 256.0, -2147483648.0, 2147483647.0);
    \\        const raw: i32 = @round(clamped);
    \\        return @fromBackingInt(raw);
    \\    }
    \\
    \\    pub fn toFloat(f: Fixed) f64 {
    \\        const raw: f64 = @floatFromInt(@backingInt(f));
    \\        return raw / 256.0;
    \\    }
    \\
    \\    /// The integer part, truncated toward zero (wl_fixed_to_int: f / 256).
    \\    pub fn toInt(f: Fixed) i32 {
    \\        return @divTrunc(@backingInt(f), 256);
    \\    }
    \\};
    \\
    \\pub const ArgKind = enum(u8) { int, uint, fixed, string, object, new_id, array, fd };
    \\
    \\/// Wire signature of one message argument.
    \\pub const ArgSpec = struct {
    \\    kind: ArgKind,
    \\    /// For object/new_id: the interface, when it is part of this file.
    \\    interface: ?Interface = null,
    \\    nullable: bool = false,
    \\};
    \\
    \\/// One request argument handed to the wire encoder.
    \\pub const Arg = union(ArgKind) {
    \\    int: i32,
    \\    uint: u32,
    \\    fixed: Fixed,
    \\    /// null encodes a null string (length 0).
    \\    string: ?[]const u8,
    \\    /// 0 encodes a null object.
    \\    object: u32,
    \\    new_id: u32,
    \\    array: []const u8,
    \\    /// Borrowed; the encoder duplicates it.
    \\    fd: i32,
    \\};
    \\
    \\
;

pub fn generate(arena: Allocator, w: *Writer, protocols: []const Protocol) !void {
    var g: Gen = .{ .arena = arena, .w = w, .protocols = protocols };
    try w.writeAll(preamble);

    try w.writeAll("pub const Interface = enum {\n");
    for (protocols) |p| for (p.interfaces) |i| try w.print("    {f},\n", .{std.zig.fmtId(i.name)});
    try w.writeAll(
        \\
        \\    pub fn fromName(s: []const u8) ?Interface {
        \\        return std.meta.stringToEnum(Interface, s);
        \\    }
        \\
        \\    pub fn name(i: Interface) [:0]const u8 {
        \\        return @tagName(i);
        \\    }
        \\
        \\    /// Highest version this file knows.
        \\    pub fn maxVersion(i: Interface) u32 {
        \\        return switch (i) {
        \\
    );
    for (protocols) |p| for (p.interfaces) |i| {
        try w.print("            .{f} => ", .{std.zig.fmtId(i.name)});
        try writeTitle(w, i.name);
        try w.writeAll(".version,\n");
    };
    try w.writeAll(
        \\        };
        \\    }
        \\
        \\    /// Wire signatures of this interface's events, indexed by opcode.
        \\    pub fn eventSignatures(i: Interface) []const []const ArgSpec {
        \\        return switch (i) {
        \\
    );
    for (protocols) |p| for (p.interfaces) |i| {
        try w.print("            .{f} => ", .{std.zig.fmtId(i.name)});
        try writeTitle(w, i.name);
        try w.writeAll(".event_signatures,\n");
    };
    try w.writeAll(
        \\        };
        \\    }
        \\
        \\    pub fn eventNames(i: Interface) []const []const u8 {
        \\        return switch (i) {
        \\
    );
    for (protocols) |p| for (p.interfaces) |i| {
        try w.print("            .{f} => ", .{std.zig.fmtId(i.name)});
        try writeTitle(w, i.name);
        try w.writeAll(".event_names,\n");
    };
    try w.writeAll(
        \\        };
        \\    }
        \\};
        \\
        \\/// Proxy type of an interface.
        \\pub fn InterfaceType(comptime i: Interface) type {
        \\    return switch (i) {
        \\
    );
    for (protocols) |p| for (p.interfaces) |i| {
        try w.print("        .{f} => ", .{std.zig.fmtId(i.name)});
        try writeTitle(w, i.name);
        try w.writeAll(",\n");
    };
    try w.writeAll(
        \\    };
        \\}
        \\
        \\
    );

    for (protocols) |p| {
        try w.print("// ---- protocol {s}\n\n", .{p.name});
        for (p.interfaces) |*i| try genInterface(&g, i);
    }
}

fn genInterface(g: *Gen, i: *const Interface) !void {
    const w = g.w;
    const tname = try titleAlloc(g.arena, i.name);
    try writeDoc(w, "", i.summary);
    try w.print("pub const {s} = struct {{\n", .{tname});
    try w.writeAll("    id: u32,\n\n");
    try w.print("    pub const interface: Interface = .{f};\n", .{std.zig.fmtId(i.name)});
    try w.print("    pub const name = \"{s}\";\n", .{i.name});
    try w.print("    pub const version: u32 = {d};\n\n", .{i.version});

    // Names declared in this struct; request parameters must not shadow them.
    var reserved: std.StringHashMapUnmanaged(void) = .empty;
    for ([_][]const u8{ "self", "conn", "std", "interface", "name", "version", "id", "new_id", "r", "opcode" }) |n|
        try reserved.put(g.arena, n, {});
    for (i.requests) |m| try reserved.put(g.arena, try camelAlloc(g.arena, m.name), {});
    for (i.enums) |e| try reserved.put(g.arena, try enumTypeName(g.arena, e.name), {});

    for (i.enums) |e| {
        try writeDoc(w, "    ", e.summary);
        const ename = try enumTypeName(g.arena, e.name);
        if (e.bitfield) {
            try w.print("    pub const {s} = struct {{\n", .{ename});
            for (e.entries) |en| {
                try writeDoc(w, "        ", en.summary);
                try w.print("        pub const {f}: u32 = 0x{x};\n", .{ std.zig.fmtIdP(en.name), en.value });
            }
        } else {
            try w.print("    pub const {s} = enum(u32) {{\n", .{ename});
            for (e.entries) |en| {
                try writeDoc(w, "        ", en.summary);
                try w.print("        {f} = {d},\n", .{ std.zig.fmtIdPU(en.name), en.value });
            }
            try w.writeAll("        _,\n");
        }
        try w.writeAll("    };\n\n");
    }

    for (i.requests, 0..) |m, opcode| try genRequest(g, i, tname, &reserved, m, @intCast(opcode));

    try w.writeAll("    pub const Event = union(enum) {\n");
    for (i.events) |m| {
        try writeDoc(w, "        ", m.summary);
        if (m.args.len == 0) {
            try w.print("        {f},\n", .{std.zig.fmtIdPU(m.name)});
            continue;
        }
        try w.print("        {f}: struct {{\n", .{std.zig.fmtIdPU(m.name)});
        for (m.args) |a| {
            try writeDoc(w, "            ", a.summary);
            try w.print("            {f}: ", .{std.zig.fmtIdPU(a.name)});
            try writeEventArgType(g, i, a);
            try w.writeAll(",\n");
        }
        try w.writeAll("        },\n");
    }
    try w.writeAll("    };\n\n");

    try w.writeAll("    pub const event_names: []const []const u8 = &.{");
    for (i.events) |m| try w.print(" \"{s}\",", .{m.name});
    try w.writeAll(" };\n\n");

    try w.writeAll("    pub const event_signatures: []const []const ArgSpec = &.{\n");
    for (i.events) |m| {
        try w.writeAll("        &.{");
        for (m.args, 0..) |a, k| {
            if (k > 0) try w.writeAll(",");
            try w.print(" .{{ .kind = .{t}", .{a.type});
            if ((a.type == .object or a.type == .new_id) and g.knownIface(a.interface))
                try w.print(", .interface = .{f}", .{std.zig.fmtId(a.interface.?)});
            if (a.allow_null) try w.writeAll(", .nullable = true");
            try w.writeAll(" }");
        }
        try w.writeAll(" },\n");
    }
    try w.writeAll("    };\n\n");

    try w.writeAll("    /// Decode one event body. `r` yields the arguments in wire order.\n");
    try w.writeAll("    pub fn decodeEvent(opcode: u16, r: anytype) !Event {\n");
    if (i.events.len == 0) {
        try w.writeAll("        _ = r;\n        _ = opcode;\n        return error.InvalidOpcode;\n");
    } else {
        var any_args = false;
        for (i.events) |m| any_args = any_args or m.args.len > 0;
        if (!any_args) try w.writeAll("        _ = r;\n");
        try w.writeAll("        switch (opcode) {\n");
        for (i.events, 0..) |m, opcode| {
            if (m.args.len == 0) {
                try w.print("            {d} => return .{f},\n", .{ opcode, std.zig.fmtIdPU(m.name) });
                continue;
            }
            try w.print("            {d} => {{\n", .{opcode});
            for (m.args, 0..) |a, k| {
                try w.print("                const a{d}: ", .{k});
                try writeEventArgType(g, i, a);
                try w.writeAll(" = ");
                try writeEventArgDecode(g, i, a);
                try w.writeAll(";\n");
            }
            try w.print("                return .{{ .{f} = .{{", .{std.zig.fmtIdPU(m.name)});
            for (m.args, 0..) |a, k| try w.print(" .{f} = a{d},", .{ std.zig.fmtIdPU(a.name), k });
            try w.writeAll(" } };\n            },\n");
        }
        try w.writeAll("            else => return error.InvalidOpcode,\n        }\n");
    }
    try w.writeAll("    }\n");
    try w.writeAll("};\n\n");
}

fn writeEventArgType(g: *Gen, i: *const Interface, a: Arg) !void {
    const w = g.w;
    switch (a.type) {
        .int => if (a.enum_name) |en| {
            if (try g.enumType(i, en)) |t| return w.writeAll(t);
            try w.writeAll("i32");
        } else try w.writeAll("i32"),
        .uint => if (a.enum_name) |en| {
            if (try g.enumType(i, en)) |t| return w.writeAll(t);
            try w.writeAll("u32");
        } else try w.writeAll("u32"),
        .fixed => try w.writeAll("Fixed"),
        .string => try w.writeAll(if (a.allow_null) "?[:0]const u8" else "[:0]const u8"),
        .object, .new_id => {
            if (a.allow_null) try w.writeAll("?");
            if (g.knownIface(a.interface)) try writeTitle(w, a.interface.?) else try w.writeAll("u32");
        },
        .array => try w.writeAll("[]const u8"),
        .fd => try w.writeAll("i32"),
    }
}

fn writeEventArgDecode(g: *Gen, i: *const Interface, a: Arg) !void {
    const w = g.w;
    switch (a.type) {
        .int => if (a.enum_name != null and (try g.enumType(i, a.enum_name.?)) != null)
            try w.writeAll("@fromBackingInt(@as(u32, @bitCast(try r.int())))")
        else
            try w.writeAll("try r.int()"),
        .uint => if (a.enum_name != null and (try g.enumType(i, a.enum_name.?)) != null)
            try w.writeAll("@fromBackingInt(try r.uint())")
        else
            try w.writeAll("try r.uint()"),
        .fixed => try w.writeAll("try r.fixed()"),
        .string => try w.writeAll(if (a.allow_null) "try r.stringOpt()" else "try r.string()"),
        .object, .new_id => {
            const getter = if (a.type == .object) "object" else "newId";
            if (g.knownIface(a.interface)) {
                if (a.allow_null) {
                    try w.print("blk: {{\n                    const v = try r.{s}();\n                    break :blk if (v == 0) null else .{{ .id = v }};\n                }}", .{getter});
                } else {
                    try w.print(".{{ .id = try r.{s}() }}", .{getter});
                }
            } else if (a.allow_null) {
                try w.print("blk: {{\n                    const v = try r.{s}();\n                    break :blk if (v == 0) null else v;\n                }}", .{getter});
            } else {
                try w.print("try r.{s}()", .{getter});
            }
        },
        .array => try w.writeAll("try r.array()"),
        .fd => try w.writeAll("try r.fd()"),
    }
}

fn paramName(g: *Gen, reserved: *const std.StringHashMapUnmanaged(void), name: []const u8) ![]const u8 {
    if (reserved.contains(name)) return try std.fmt.allocPrint(g.arena, "{s}_", .{name});
    return name;
}

fn genRequest(
    g: *Gen,
    i: *const Interface,
    tname: []const u8,
    reserved: *const std.StringHashMapUnmanaged(void),
    m: Message,
    opcode: u16,
) !void {
    const w = g.w;

    // At most one new_id, which defines the return type.
    var new_id: ?Arg = null;
    for (m.args) |a| if (a.type == .new_id) {
        if (new_id != null) {
            try w.print("    // {s}: skipped, more than one new_id argument\n\n", .{m.name});
            return;
        }
        new_id = a;
    };
    if (new_id) |a| if (a.interface != null and !g.knownIface(a.interface)) {
        try w.print("    // {s}: skipped, creates unknown interface {s}\n\n", .{ m.name, a.interface.? });
        return;
    };

    try writeDoc(w, "    ", m.summary);
    if (m.since > 1) try w.print("    /// Since version {d}.\n", .{m.since});
    if (m.destructor) try w.writeAll("    /// Destructor.\n");
    try w.writeAll("    pub fn ");
    try writeCamel(w, m.name);
    try w.print("(self: {s}, conn: anytype", .{tname});

    for (m.args) |a| {
        const pn = try paramName(g, reserved, a.name);
        switch (a.type) {
            .new_id => if (a.interface == null) {
                try w.print(", comptime T: type, {s}: u32", .{try paramName(g, reserved, "version")});
            },
            .int => {
                const et = if (a.enum_name) |en| try g.enumType(i, en) else null;
                try w.print(", {f}: {s}", .{ std.zig.fmtId(pn), et orelse "i32" });
            },
            .uint => {
                const et = if (a.enum_name) |en| try g.enumType(i, en) else null;
                try w.print(", {f}: {s}", .{ std.zig.fmtId(pn), et orelse "u32" });
            },
            .fixed => try w.print(", {f}: Fixed", .{std.zig.fmtId(pn)}),
            .string => try w.print(", {f}: {s}", .{ std.zig.fmtId(pn), if (a.allow_null) "?[]const u8" else "[]const u8" }),
            .object => {
                try w.print(", {f}: {s}", .{ std.zig.fmtId(pn), if (a.allow_null) "?" else "" });
                if (g.knownIface(a.interface)) try writeTitle(w, a.interface.?) else try w.writeAll("u32");
            },
            .array => try w.print(", {f}: []const u8", .{std.zig.fmtId(pn)}),
            .fd => try w.print(", {f}: i32", .{std.zig.fmtId(pn)}),
        }
    }
    try w.writeAll(") !");
    if (new_id) |a| {
        if (a.interface) |ni| try writeTitle(w, ni) else try w.writeAll("T");
    } else try w.writeAll("void");
    try w.writeAll(" {\n");

    if (new_id) |a| {
        if (a.interface) |ni| {
            try w.print("        const new_id = try conn.newId(.{f}, self.id);\n", .{std.zig.fmtId(ni)});
        } else {
            try w.print("        const new_id = try conn.newIdVersioned(T.interface, {s});\n", .{try paramName(g, reserved, "version")});
        }
    }
    try w.print("        try conn.request(self.id, {d}, &.{{", .{opcode});
    for (m.args, 0..) |a, k| {
        if (k > 0) try w.writeAll(",");
        const pn = try paramName(g, reserved, a.name);
        switch (a.type) {
            .int => if (a.enum_name != null and (try g.enumType(i, a.enum_name.?)) != null)
                try w.print(" .{{ .int = @bitCast(@backingInt({f})) }}", .{std.zig.fmtId(pn)})
            else
                try w.print(" .{{ .int = {f} }}", .{std.zig.fmtId(pn)}),
            .uint => if (a.enum_name != null and (try g.enumType(i, a.enum_name.?)) != null)
                try w.print(" .{{ .uint = @backingInt({f}) }}", .{std.zig.fmtId(pn)})
            else
                try w.print(" .{{ .uint = {f} }}", .{std.zig.fmtId(pn)}),
            .fixed => try w.print(" .{{ .fixed = {f} }}", .{std.zig.fmtId(pn)}),
            .string => try w.print(" .{{ .string = {f} }}", .{std.zig.fmtId(pn)}),
            .object => if (g.knownIface(a.interface)) {
                if (a.allow_null)
                    try w.print(" .{{ .object = if ({f}) |o| o.id else 0 }}", .{std.zig.fmtId(pn)})
                else
                    try w.print(" .{{ .object = {f}.id }}", .{std.zig.fmtId(pn)});
            } else {
                if (a.allow_null)
                    try w.print(" .{{ .object = {f} orelse 0 }}", .{std.zig.fmtId(pn)})
                else
                    try w.print(" .{{ .object = {f} }}", .{std.zig.fmtId(pn)});
            },
            .new_id => if (a.interface == null) {
                try w.print(" .{{ .string = T.name }}, .{{ .uint = {s} }}, .{{ .new_id = new_id }}", .{try paramName(g, reserved, "version")});
            } else {
                try w.writeAll(" .{ .new_id = new_id }");
            },
            .array => try w.print(" .{{ .array = {f} }}", .{std.zig.fmtId(pn)}),
            .fd => try w.print(" .{{ .fd = {f} }}", .{std.zig.fmtId(pn)}),
        }
    }
    try w.writeAll(" });\n");
    if (m.destructor) try w.writeAll("        conn.destroyed(self.id);\n");
    if (new_id != null) try w.writeAll("        return .{ .id = new_id };\n");
    try w.writeAll("    }\n\n");
}

// Build-time entry point: wl-scanner OUT.zig IN.xml...

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) {
        std.debug.print("usage: wl-scanner OUT.zig PROTOCOL.xml...\n", .{});
        std.process.exit(2);
    }
    var protos: std.ArrayList(Protocol) = .empty;
    for (args[2..]) |path| {
        const xml = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(4 << 20));
        const p = parse(arena, xml) catch |err| {
            std.debug.print("wl-scanner: {s}: {t}\n", .{ path, err });
            std.process.exit(1);
        };
        try protos.append(arena, p);
    }
    var aw: Writer.Allocating = .init(arena);
    try generate(arena, &aw.writer, protos.items);
    const formatted = try format(arena, aw.written());
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = args[1], .data = formatted });
}

/// Canonical `zig fmt` layout; also rejects syntactically invalid output.
pub fn format(gpa: Allocator, source: []const u8) ![]u8 {
    const src_z = try gpa.dupeSentinel(u8, source, 0);
    var tree = try std.zig.Ast.parse(gpa, src_z, .{});
    defer tree.deinit(gpa);
    if (tree.errors.len > 0) {
        var ew: Writer.Allocating = .init(gpa);
        try tree.renderError(tree.errors[0], &ew.writer);
        std.debug.print("wl-scanner: generated code does not parse: {s}\n", .{ew.written()});
        return error.InvalidGeneratedCode;
    }
    return tree.renderAlloc(gpa);
}

const sample_xml =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<protocol name="sample">
    \\  <copyright>Public domain &amp; friends</copyright>
    \\  <!-- a comment with <tags> inside -->
    \\  <interface name="zz_thing_v1" version="3">
    \\    <description summary="a &quot;thing&quot;">long text</description>
    \\    <enum name="error">
    \\      <entry name="bad" value="1" summary="bad"/>
    \\      <entry name="90" value="0x2"/>
    \\    </enum>
    \\    <enum name="flags" bitfield="true">
    \\      <entry name="a" value="1"/>
    \\      <entry name="b" value="2"/>
    \\    </enum>
    \\    <request name="make_child">
    \\      <arg name="id" type="new_id" interface="zz_child_v1"/>
    \\      <arg name="name" type="string" allow-null="true"/>
    \\      <arg name="flags" type="uint" enum="flags"/>
    \\      <arg name="fd" type="fd"/>
    \\    </request>
    \\    <request name="destroy" type="destructor"/>
    \\    <event name="error">
    \\      <arg name="code" type="uint" enum="error"/>
    \\      <arg name="msg" type="string"/>
    \\      <arg name="where" type="fixed"/>
    \\      <arg name="other" type="object" interface="zz_child_v1" allow-null="true"/>
    \\    </event>
    \\    <event name="done" since="2"/>
    \\  </interface>
    \\  <interface name="zz_child_v1" version="1">
    \\    <request name="bind">
    \\      <arg name="name" type="uint"/>
    \\      <arg name="id" type="new_id"/>
    \\    </request>
    \\  </interface>
    \\</protocol>
;

test "parse sample protocol" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const p = try parse(arena_state.allocator(), sample_xml);
    try std.testing.expectEqualStrings("sample", p.name);
    try std.testing.expectEqual(2, p.interfaces.len);
    const t = p.interfaces[0];
    try std.testing.expectEqualStrings("zz_thing_v1", t.name);
    try std.testing.expectEqual(3, t.version);
    try std.testing.expectEqualStrings("a \"thing\"", t.summary.?);
    try std.testing.expectEqual(2, t.requests.len);
    try std.testing.expect(t.requests[1].destructor);
    try std.testing.expectEqual(4, t.requests[0].args.len);
    try std.testing.expect(t.requests[0].args[1].allow_null);
    try std.testing.expectEqual(ArgType.fd, t.requests[0].args[3].type);
    try std.testing.expectEqual(2, t.events.len);
    try std.testing.expectEqual(2, t.events[1].since);
    try std.testing.expectEqual(2, t.enums.len);
    try std.testing.expectEqual(2, t.enums[0].entries[1].value);
    try std.testing.expect(t.enums[1].bitfield);
}

test "generate sample protocol" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const p = try parse(a, sample_xml);
    var aw: Writer.Allocating = .init(a);
    try generate(a, &aw.writer, &.{p});
    const out = aw.written();
    _ = try format(a, out); // must parse
    const expectContains = struct {
        fn f(hay: []const u8, needle: []const u8) !void {
            if (std.mem.indexOf(u8, hay, needle) == null) {
                std.debug.print("missing in generated code: {s}\n", .{needle});
                return error.TestExpectedContains;
            }
        }
    }.f;
    try expectContains(out, "pub const ZzThingV1 = struct {");
    try expectContains(out, "pub const Error = enum(u32) {");
    try expectContains(out, "@\"90\" = 2,");
    try expectContains(out, "pub const Flags = struct {");
    // name param collides with the `name` decl -> suffixed.
    try expectContains(out, "pub fn makeChild(self: ZzThingV1, conn: anytype, name_: ?[]const u8, flags: u32, fd: i32) !ZzChildV1 {");
    try expectContains(out, "const new_id = try conn.newId(.zz_child_v1, self.id);");
    try expectContains(out, "try conn.request(self.id, 0, &.{ .{ .new_id = new_id }, .{ .string = name_ }, .{ .uint = flags }, .{ .fd = fd } });");
    try expectContains(out, "conn.destroyed(self.id);");
    try expectContains(out, "@\"error\": struct {");
    try expectContains(out, "const a0: ZzThingV1.Error = @fromBackingInt(try r.uint());");
    try expectContains(out, "other: ?ZzChildV1,");
    try expectContains(out, "&.{ .{ .kind = .uint }, .{ .kind = .string }, .{ .kind = .fixed }, .{ .kind = .object, .interface = .zz_child_v1, .nullable = true } },");
    try expectContains(out, "1 => return .done,");
    // Untyped new_id expands to (interface, version, id).
    try expectContains(out, "pub fn bind(self: ZzChildV1, conn: anytype, name_: u32, comptime T: type, version_: u32) !T {");
    try expectContains(out, ".{ .string = T.name }, .{ .uint = version_ }, .{ .new_id = new_id }");
}

test "parse rejects malformed xml" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const bad = [_][]const u8{
        "<protocol name=\"x\"><interface name=\"a\" version=\"1\">",
        "<protocol name=\"x\"><interface name=\"a\" version=\"zz\"></interface></protocol>",
        "<protocol name=\"x\"><arg name=\"a\" type=\"int\"/></protocol>",
        "<protocol name=\"x\"><interface name=\"a\" version=\"1\"><request name=\"r\"><arg name=\"q\" type=\"bogus\"/></request></interface></protocol>",
        "<protocol name='x' <",
        "<protocol",
        "",
    };
    for (bad) |s| {
        if (parse(a, s)) |_| {
            std.debug.print("accepted: {s}\n", .{s});
            return error.TestUnexpectedSuccess;
        } else |_| {}
    }
}
