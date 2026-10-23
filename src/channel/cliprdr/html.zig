//! MS-RDPECLIP "HTML Format" (CF_HTML): "Key:Value" header lines followed by UTF-8 HTML.
//! Offsets are bytes from the start of the data; StartHTML/EndHTML -1 means no context
//! (Version 1.0).

const std = @import("std");
const c = @import("../cliprdr.zig");
const text = @import("text.zig");

const Allocator = std.mem.Allocator;

const Key = enum { version, start_html, end_html, start_fragment, end_fragment, start_selection, end_selection, source_url };

const key_names = [_]struct { []const u8, Key }{
    .{ "Version", .version },
    .{ "StartHTML", .start_html },
    .{ "EndHTML", .end_html },
    .{ "StartFragment", .start_fragment },
    .{ "EndFragment", .end_fragment },
    .{ "StartSelection", .start_selection },
    .{ "EndSelection", .end_selection },
    .{ "SourceURL", .source_url },
};

const Line = struct { key: Key, value: []const u8, end: usize };

/// Null at the first line that is not a known key: HTML may itself hold "word:word" lines.
/// Lines end with CRLF, CR or LF.
fn headerLine(data: []const u8, pos: usize) ?Line {
    if (pos >= data.len) return null;
    const rest = data[pos..];
    const eol = std.mem.findAny(u8, rest, "\r\n") orelse rest.len;
    const line = rest[0..eol];
    const colon = std.mem.findScalar(u8, line, ':') orelse return null;
    const key = for (key_names) |k| {
        if (std.ascii.eqlIgnoreCase(line[0..colon], k[0])) break k[1];
    } else return null;
    var end = pos + eol;
    if (end < data.len and data[end] == '\r') end += 1;
    if (end < data.len and data[end] == '\n') end += 1;
    return .{ .key = key, .value = std.mem.trim(u8, line[colon + 1 ..], " \t"), .end = end };
}

/// Decimal digits; "-1" is `absent` (no context, Version 1.0).
const Offset = union(enum) { absent, at: usize };

fn parseFragmentOffset(value: ?[]const u8) c.Error!usize {
    return switch (try parseOffset(value orelse return error.InvalidHtmlFormat, false)) {
        .at => |v| v,
        .absent => error.InvalidHtmlFormat,
    };
}

fn parseOffset(value: []const u8, allow_absent: bool) c.Error!Offset {
    if (allow_absent and std.mem.eql(u8, value, "-1")) return .absent;
    if (value.len == 0) return error.InvalidHtmlFormat;
    var v: usize = 0;
    for (value) |ch| {
        if (ch < '0' or ch > '9') return error.InvalidHtmlFormat;
        v = std.math.mul(usize, v, 10) catch return error.InvalidHtmlFormat;
        v = std.math.add(usize, v, ch - '0') catch return error.InvalidHtmlFormat;
    }
    return .{ .at = v };
}

fn lineBreaksOnly(b: []const u8) bool {
    if (b.len == 0) return false;
    for (b) |ch| if (ch != '\r' and ch != '\n') return false;
    return true;
}

/// data[start..end] without the terminating nulls.
fn slice(data: []const u8, start: usize, end: usize) []const u8 {
    var e = end;
    while (e > start and data[e - 1] == 0) e -= 1;
    return data[start..e];
}

/// Upper bound of the header: StartHTML, else StartFragment.
fn headerLimit(values: std.EnumArray(Key, ?[]const u8)) usize {
    for ([_]Key{ .start_html, .start_fragment }) |k| {
        const v = values.get(k) orelse continue;
        switch (parseOffset(v, true) catch continue) {
            .at => |at| return at,
            .absent => {},
        }
    }
    return std.math.maxInt(usize);
}

pub fn parseHtmlFormat(data: []const u8) c.Error!c.HtmlFormat {
    if (!std.mem.startsWith(u8, data, "Version:")) return error.InvalidHtmlFormat;

    // The header never extends past StartHTML (else StartFragment): the context may itself
    // hold a "Version:" line. The first occurrence of a key wins.
    var values: std.EnumArray(Key, ?[]const u8) = .initFill(null);
    var pos: usize = 0;
    while (pos < headerLimit(values)) {
        const l = headerLine(data, pos) orelse break;
        const v = values.getPtr(l.key);
        if (v.* == null) v.* = l.value;
        pos = l.end;
        if (data[pos - 1] != '\n' and data[pos - 1] != '\r') break; // the data ends in this line
    }
    const header_end = pos;

    const ver = values.get(.version) orelse return error.InvalidHtmlFormat;
    const sf = try parseFragmentOffset(values.get(.start_fragment));
    const ef = try parseFragmentOffset(values.get(.end_fragment));
    if (sf < header_end or sf > ef or ef > data.len) return error.InvalidHtmlFormat;

    const start_html = values.get(.start_html);
    const end_html = values.get(.end_html);
    const source_url = values.get(.source_url);
    var html: ?[]const u8 = null;
    var sh: Offset = if (start_html) |v| try parseOffset(v, true) else .absent;
    // .NET DataObject counts StartHTML from before the header's last line break.
    if (sh == .at and sh.at < header_end and lineBreaksOnly(data[sh.at..header_end])) sh = .{ .at = header_end };
    const eh: Offset = if (end_html) |v| try parseOffset(v, true) else .absent;
    if (sh == .at and eh == .at) {
        const s = sh.at;
        const e = eh.at;
        if (s < header_end or s > sf or ef > e or e > data.len) return error.InvalidHtmlFormat;
        html = slice(data, s, e);
    } else if (sh == .at) {
        if (sh.at < header_end or sh.at > sf) return error.InvalidHtmlFormat;
    } else if (eh == .at) {
        if (eh.at < ef or eh.at > data.len) return error.InvalidHtmlFormat;
    }

    return .{
        .version = ver,
        .html = html,
        .fragment = slice(data, sf, ef),
        .source_url = source_url,
    };
}

pub fn htmlFormatToHtml(gpa: Allocator, data: []const u8) c.Error![]u8 {
    const p = try parseHtmlFormat(data);
    return gpa.dupe(u8, p.html orelse p.fragment);
}

const start_marker = "<!--StartFragment-->";
const end_marker = "<!--EndFragment-->";
const wrap_head = "<HTML><BODY>";
const wrap_tail = "</BODY></HTML>";
/// "Version:0.9\r\n" and four "Key:%010u\r\n" lines.
const header_len = 105;

/// Fragment marker positions: after the first <body> start tag and before the last
/// </body> (or the end of the HTML).
const BodySpan = struct { start: usize, end: usize };

fn findBody(html: []const u8) ?BodySpan {
    var from: usize = 0;
    const tag_end = while (std.ascii.findIgnoreCasePos(html, from, "<body")) |i| {
        from = i + 5;
        if (from < html.len and !std.ascii.isWhitespace(html[from]) and html[from] != '>' and html[from] != '/') continue;
        var quote: u8 = 0;
        var j = from;
        while (j < html.len) : (j += 1) {
            const ch = html[j];
            if (quote != 0) {
                if (ch == quote) quote = 0;
            } else if (ch == '"' or ch == '\'') {
                quote = ch;
            } else if (ch == '>') {
                break;
            }
        }
        if (j >= html.len) return null; // unterminated start tag
        break j + 1;
    } else return null;

    var end = html.len;
    var i = html.len;
    while (i > tag_end) {
        i -= 1;
        if (html.len - i < 6 or !std.ascii.eqlIgnoreCase(html[i..][0..6], "</body")) continue;
        const after = i + 6;
        if (after >= html.len or std.ascii.isWhitespace(html[after]) or html[after] == '>') {
            end = i;
            break;
        }
    }
    return .{ .start = tag_end, .end = end };
}

/// Offsets of the 10-digit fields in the header.
const digits_start_html = 23;
const digits_end_html = 43;
const digits_start_fragment = 69;
const digits_end_fragment = 93;

fn writeOffset(out: []u8, at: usize, v: usize) void {
    _ = std.fmt.bufPrint(out[at..][0..10], "{d:0>10}", .{v}) catch unreachable;
}

pub fn htmlToHtmlFormat(gpa: Allocator, html_in: []const u8) c.Error![]u8 {
    // Firefox offers text/html as UTF-16 with a byte order mark.
    var converted: ?[]u8 = null;
    defer if (converted) |s| gpa.free(s);
    var html = html_in;
    if (html.len >= 2 and html[0] == 0xFF and html[1] == 0xFE) {
        converted = try text.utf16ToUtf8(gpa, html[2..], false);
        html = converted.?;
    } else if (html.len >= 2 and html[0] == 0xFE and html[1] == 0xFF) {
        converted = try text.utf16ToUtf8(gpa, html[2..], true);
        html = converted.?;
    } else if (std.mem.startsWith(u8, html, "\xEF\xBB\xBF")) {
        html = html[3..];
    }
    // The data is null-terminated: the HTML ends at an embedded null.
    if (std.mem.findScalar(u8, html, 0)) |z| html = html[0..z];

    const body = findBody(html);
    const fs = if (body) |b| b.start else 0;
    const fe = if (body) |b| b.end else html.len;
    const head = if (body == null) wrap_head else "";
    const tail = if (body == null) wrap_tail else "";

    const total = header_len + head.len + html.len + start_marker.len + end_marker.len + tail.len + 1;
    // Offsets are written with 10 digits.
    if (total > 9_999_999_999) return error.OutOfMemory;
    const out = try gpa.alloc(u8, total);
    const hdr = "Version:0.9\r\nStartHTML:0000000000\r\nEndHTML:0000000000\r\nStartFragment:0000000000\r\nEndFragment:0000000000\r\n";
    comptime std.debug.assert(hdr.len == header_len);

    var n: usize = 0;
    for ([_][]const u8{ hdr, head, html[0..fs], start_marker }) |part| {
        @memcpy(out[n..][0..part.len], part);
        n += part.len;
    }
    const start_fragment = n;
    @memcpy(out[n..][0 .. fe - fs], html[fs..fe]);
    n += fe - fs;
    const end_fragment = n;
    for ([_][]const u8{ end_marker, html[fe..], tail }) |part| {
        @memcpy(out[n..][0..part.len], part);
        n += part.len;
    }
    const end_html = n;
    out[n] = 0;
    std.debug.assert(n + 1 == total);

    writeOffset(out, digits_start_html, header_len);
    writeOffset(out, digits_end_html, end_html);
    writeOffset(out, digits_start_fragment, start_fragment);
    writeOffset(out, digits_end_fragment, end_fragment);
    return out;
}
