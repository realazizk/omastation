//! MS-RDPECLIP text formats: CF_UNICODETEXT (UTF-16LE) and CF_TEXT / CF_OEMTEXT
//! (8-bit code page), with CRLF line breaks and a terminating null (MS-RDPECLIP 4.4.2).
//! Wayland text is UTF-8 with LF; ill-formed input decodes to U+FFFD.

const std = @import("std");
const c = @import("../cliprdr.zig");

const Allocator = std.mem.Allocator;

pub const replacement: u21 = 0xFFFD;

/// Little-endian unless `big_endian`; unpaired surrogates become U+FFFD.
pub const Utf16Iter = struct {
    data: []const u8,
    pos: usize = 0,
    big_endian: bool = false,

    fn unitAt(it: *const Utf16Iter, i: usize) u16 {
        const b = it.data[i..][0..2];
        return std.mem.readInt(u16, b, if (it.big_endian) .big else .little);
    }

    pub fn next(it: *Utf16Iter) ?u21 {
        if (it.data.len - it.pos < 2) return null;
        const u = it.unitAt(it.pos);
        it.pos += 2;
        switch (u) {
            0xD800...0xDBFF => {
                if (it.data.len - it.pos >= 2) {
                    const l = it.unitAt(it.pos);
                    if (l >= 0xDC00 and l <= 0xDFFF) {
                        it.pos += 2;
                        return 0x10000 + (@as(u21, u - 0xD800) << 10) + (l - 0xDC00);
                    }
                }
                return replacement;
            },
            0xDC00...0xDFFF => return replacement,
            else => return u,
        }
    }
};

/// Each maximal ill-formed subsequence becomes one U+FFFD (Unicode 3.9 D93b).
pub const Utf8Iter = struct {
    s: []const u8,
    pos: usize = 0,

    pub fn next(it: *Utf8Iter) ?u21 {
        if (it.pos >= it.s.len) return null;
        const b0 = it.s[it.pos];
        it.pos += 1;
        if (b0 < 0x80) return b0;
        var need: usize = undefined;
        var cp: u21 = undefined;
        var lo: u8 = 0x80;
        var hi: u8 = 0xBF;
        switch (b0) {
            0xC2...0xDF => {
                need = 1;
                cp = b0 & 0x1F;
            },
            0xE0...0xEF => {
                need = 2;
                cp = b0 & 0x0F;
                if (b0 == 0xE0) lo = 0xA0; // overlong
                if (b0 == 0xED) hi = 0x9F; // surrogates
            },
            0xF0...0xF4 => {
                need = 3;
                cp = b0 & 0x07;
                if (b0 == 0xF0) lo = 0x90; // overlong
                if (b0 == 0xF4) hi = 0x8F; // above U+10FFFF
            },
            else => return replacement, // C0, C1, F5..FF, continuation bytes
        }
        for (0..need) |_| {
            if (it.pos >= it.s.len) return replacement;
            const b = it.s[it.pos];
            if (b < lo or b > hi) return replacement;
            lo = 0x80;
            hi = 0xBF;
            cp = (cp << 6) | (b & 0x3F);
            it.pos += 1;
        }
        return cp;
    }
};

const CodepageIter = struct {
    data: []const u8,
    cp: c.Codepage,
    pos: usize = 0,

    fn next(it: *CodepageIter) ?u21 {
        if (it.pos >= it.data.len) return null;
        const b = it.data[it.pos];
        it.pos += 1;
        return codepageToUnicode(it.cp, b);
    }
};

/// Ends at the first U+0000; normalizes CRLF, CR and LF to LF, or to CR LF when `crlf`.
fn Lines(comptime Inner: type) type {
    return struct {
        inner: Inner,
        crlf: bool,
        done: bool = false,
        pending_lf: bool = false,
        held: ?u21 = null,

        const Self = @This();

        fn pull(self: *Self) ?u21 {
            if (self.held) |h| {
                self.held = null;
                return h;
            }
            if (self.done) return null;
            const cp = self.inner.next() orelse {
                self.done = true;
                return null;
            };
            if (cp == 0) {
                self.done = true;
                return null;
            }
            return cp;
        }

        fn lineBreak(self: *Self) u21 {
            if (!self.crlf) return '\n';
            self.pending_lf = true;
            return '\r';
        }

        fn next(self: *Self) ?u21 {
            if (self.pending_lf) {
                self.pending_lf = false;
                return '\n';
            }
            const cp = self.pull() orelse return null;
            switch (cp) {
                '\r' => {
                    if (self.pull()) |n| {
                        if (n != '\n') self.held = n;
                    }
                    return self.lineBreak();
                },
                '\n' => return self.lineBreak(),
                else => return cp,
            }
        }
    };
}

fn lines(inner: anytype, crlf: bool) Lines(@TypeOf(inner)) {
    return .{ .inner = inner, .crlf = crlf };
}

/// Append `cp` as UTF-8 (a value UTF-8 cannot hold as U+FFFD).
pub fn appendUtf8(gpa: Allocator, out: *std.ArrayList(u8), cp: u21) Allocator.Error!void {
    var buf: [4]u8 = undefined;
    const n = std.unicode.utf8Encode(cp, &buf) catch std.unicode.utf8Encode(replacement, &buf) catch unreachable;
    try out.appendSlice(gpa, buf[0..n]);
}

fn appendUtf16le(gpa: Allocator, out: *std.ArrayList(u8), cp: u21) Allocator.Error!void {
    if (cp >= 0x10000) {
        const v = cp - 0x10000;
        const hi: u16 = 0xD800 + @as(u16, @intCast(v >> 10));
        const lo: u16 = 0xDC00 + @as(u16, @intCast(v & 0x3FF));
        try out.appendSlice(gpa, &.{ @truncate(hi), @truncate(hi >> 8), @truncate(lo), @truncate(lo >> 8) });
    } else {
        const u: u16 = @intCast(cp);
        try out.appendSlice(gpa, &.{ @truncate(u), @truncate(u >> 8) });
    }
}

fn collectUtf8(gpa: Allocator, it: anytype, size_hint: usize) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, size_hint);
    while (it.next()) |cp| try appendUtf8(gpa, &out, cp);
    return out.toOwnedSlice(gpa);
}

/// UTF-8 of UTF-16 data, line breaks untouched, up to the end of the data.
pub fn utf16ToUtf8(gpa: Allocator, data: []const u8, big_endian: bool) Allocator.Error![]u8 {
    var it: Utf16Iter = .{ .data = data, .big_endian = big_endian };
    return collectUtf8(gpa, &it, data.len + data.len / 2);
}

pub fn unicodeTextToUtf8(gpa: Allocator, data: []const u8) c.Error![]u8 {
    var it = lines(Utf16Iter{ .data = data }, false);
    return collectUtf8(gpa, &it, data.len + data.len / 2);
}

pub fn utf8ToUnicodeText(gpa: Allocator, text: []const u8) c.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, 2 * text.len + 2);
    var it = lines(Utf8Iter{ .s = text }, true);
    while (it.next()) |cp| try appendUtf16le(gpa, &out, cp);
    try out.appendSlice(gpa, &.{ 0, 0 });
    return out.toOwnedSlice(gpa);
}

pub fn codepageTextToUtf8(gpa: Allocator, data: []const u8, cp: c.Codepage) c.Error![]u8 {
    var it = lines(CodepageIter{ .data = data, .cp = cp }, false);
    return collectUtf8(gpa, &it, data.len + data.len / 2);
}

pub fn utf8ToCodepageText(gpa: Allocator, text: []const u8, cp: c.Codepage) c.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, text.len + 1);
    var it = lines(Utf8Iter{ .s = text }, true);
    while (it.next()) |u| try out.append(gpa, unicodeToCodepage(cp, u) orelse '?');
    try out.append(gpa, 0);
    return out.toOwnedSlice(gpa);
}

/// Windows-1252 0x80..0x9F; the five undefined bytes map to C1 controls as Windows does.
/// 0xA0..0xFF are ISO 8859-1.
const cp1252_80: [32]u16 = .{
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
    0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
};

/// Code page 437, 0x80..0xFF.
const cp437_80: [128]u16 = .{
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7,
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA,
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F,
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B,
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4,
    0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248,
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
};

fn codepageToUnicode(cp: c.Codepage, b: u8) u21 {
    if (b < 0x80) return b;
    return switch (cp) {
        .cp1252 => if (b < 0xA0) cp1252_80[b - 0x80] else b,
        .cp437 => cp437_80[b - 0x80],
    };
}

/// Null when the code page has no byte for `u`.
fn unicodeToCodepage(cp: c.Codepage, u: u21) ?u8 {
    if (u < 0x80) return @intCast(u);
    const high: []const u16 = switch (cp) {
        .cp1252 => blk: {
            if (u >= 0xA0 and u <= 0xFF) return @intCast(u);
            break :blk &cp1252_80;
        },
        .cp437 => &cp437_80,
    };
    for (high, 0..) |v, i| if (v == u) return @intCast(0x80 + i);
    return null;
}
