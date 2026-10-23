//! Minimal strict DER (X.690 section 10) reader and writer for SPNEGO (RFC 4178) and CredSSP
//! (MS-CSSP 2.2). The reader takes untrusted pre-authentication input: low tag numbers only,
//! minimal definite lengths of at most 4 octets, minimal integers, and no recursion.

const std = @import("std");

pub const Error = error{
    /// Truncated input or a length pointing past the enclosing buffer.
    EndOfBuffer,
    /// Structurally invalid DER (bad length form, non-minimal integer, ...).
    InvalidDer,
    UnexpectedTag,
    /// Trailing bytes after the last expected element.
    TrailingData,
};

/// Identifier octets used by SPNEGO / CredSSP.
pub const tag = struct {
    pub const integer: u8 = 0x02;
    pub const bit_string: u8 = 0x03;
    pub const octet_string: u8 = 0x04;
    pub const oid: u8 = 0x06;
    pub const enumerated: u8 = 0x0A;
    pub const general_string: u8 = 0x1B;
    pub const sequence: u8 = 0x30;

    /// Context-specific, constructed: [n] EXPLICIT.
    pub fn context(comptime n: u5) u8 {
        comptime std.debug.assert(n < 31);
        return 0xA0 | @as(u8, n);
    }

    /// Application, constructed: [APPLICATION n].
    pub fn application(comptime n: u5) u8 {
        comptime std.debug.assert(n < 31);
        return 0x60 | @as(u8, n);
    }
};

pub const Element = struct {
    tag: u8,
    /// Content octets only.
    content: []const u8,
    /// Complete TLV encoding (identifier + length + content).
    raw: []const u8,

    pub fn reader(e: Element) Reader {
        return Reader.init(e.content);
    }
};

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    pub fn atEnd(r: *const Reader) bool {
        return r.pos >= r.buf.len;
    }

    /// Identifier octet of the next element; null at end of input.
    pub fn peekTag(r: *const Reader) ?u8 {
        return if (r.atEnd()) null else r.buf[r.pos];
    }

    pub fn next(r: *Reader) Error!Element {
        const start = r.pos;
        const rest = r.buf[r.pos..];
        if (rest.len < 2) return error.EndOfBuffer;
        const t = rest[0];
        if (t & 0x1F == 0x1F) return error.InvalidDer; // high-tag-number form
        var i: usize = 1;
        const first = rest[i];
        i += 1;
        var len: usize = 0;
        if (first < 0x80) {
            len = first;
        } else {
            const n: usize = first & 0x7F;
            if (n == 0) return error.InvalidDer; // indefinite length
            if (n > 4) return error.InvalidDer; // > 4 GiB is never legitimate here
            if (rest.len - i < n) return error.EndOfBuffer;
            if (rest[i] == 0) return error.InvalidDer; // non-minimal (leading zero)
            for (rest[i .. i + n]) |b| len = (len << 8) | b;
            i += n;
            if (len < 0x80) return error.InvalidDer; // long form where short suffices
        }
        if (len > rest.len - i) return error.EndOfBuffer;
        r.pos = start + i + len;
        return .{
            .tag = t,
            .content = rest[i .. i + len],
            .raw = rest[0 .. i + len],
        };
    }

    pub fn expect(r: *Reader, want: u8) Error!Element {
        if (r.peekTag()) |t| {
            if (t != want) return error.UnexpectedTag;
        } else return error.EndOfBuffer;
        return r.next();
    }

    pub fn optional(r: *Reader, want: u8) Error!?Element {
        if (r.peekTag() != want) return null;
        return try r.next();
    }

    pub fn finish(r: *const Reader) Error!void {
        if (!r.atEnd()) return error.TrailingData;
    }

    pub fn integer(r: *Reader) Error!i64 {
        return decodeInteger((try r.expect(tag.integer)).content);
    }

    pub fn enumerated(r: *Reader) Error!i64 {
        return decodeInteger((try r.expect(tag.enumerated)).content);
    }

    pub fn octetString(r: *Reader) Error![]const u8 {
        return (try r.expect(tag.octet_string)).content;
    }

    /// OID content octets (not decoded to arcs; compare against constants).
    pub fn oid(r: *Reader) Error![]const u8 {
        const c = (try r.expect(tag.oid)).content;
        try validateOid(c);
        return c;
    }

    /// Without the leading unused-bits octet.
    pub fn bitString(r: *Reader) Error!BitString {
        return decodeBitString((try r.expect(tag.bit_string)).content);
    }

    /// Content of an explicitly tagged [n] wrapper that must hold exactly one element.
    pub fn explicit(r: *Reader, want: u8) Error!Element {
        const outer = try r.expect(want);
        var inner = outer.reader();
        const e = try inner.next();
        try inner.finish();
        return e;
    }

    pub fn optionalExplicit(r: *Reader, want: u8) Error!?Element {
        if (r.peekTag() != want) return null;
        return try r.explicit(want);
    }
};

pub const BitString = struct {
    unused_bits: u3,
    data: []const u8,
};

pub fn decodeBitString(c: []const u8) Error!BitString {
    if (c.len == 0) return error.InvalidDer;
    if (c[0] > 7) return error.InvalidDer;
    if (c.len == 1 and c[0] != 0) return error.InvalidDer;
    if (c[0] != 0) {
        // DER: unused trailing bits must be zero.
        const mask = (@as(u8, 1) << @intCast(c[0])) - 1;
        if (c[c.len - 1] & mask != 0) return error.InvalidDer;
    }
    return .{ .unused_bits = @intCast(c[0]), .data = c[1..] };
}

/// Strict DER INTEGER decoding into an i64 (two's complement, minimal).
pub fn decodeInteger(c: []const u8) Error!i64 {
    if (c.len == 0 or c.len > 8) return error.InvalidDer;
    if (c.len > 1) {
        if (c[0] == 0x00 and c[1] & 0x80 == 0) return error.InvalidDer;
        if (c[0] == 0xFF and c[1] & 0x80 != 0) return error.InvalidDer;
    }
    var v: u64 = if (c[0] & 0x80 != 0) std.math.maxInt(u64) else 0;
    for (c) |b| v = (v << 8) | b;
    return @bitCast(v);
}

fn validateOid(c: []const u8) Error!void {
    if (c.len == 0) return error.InvalidDer;
    // Each sub-identifier: base-128, no leading 0x80, last octet has bit 8 clear.
    if (c[c.len - 1] & 0x80 != 0) return error.InvalidDer;
    var at_start = true;
    for (c) |b| {
        if (at_start and b == 0x80) return error.InvalidDer;
        at_start = b & 0x80 == 0;
    }
}

/// `begin` opens a constructed element; `end` back-fills its minimal length.
pub const Writer = struct {
    list: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,
    stack: [max_depth]usize = undefined,
    depth: usize = 0,

    pub const max_depth = 16;

    pub fn init(gpa: std.mem.Allocator) Writer {
        return .{ .gpa = gpa };
    }

    pub fn deinit(w: *Writer) void {
        std.crypto.secureZero(u8, w.list.items);
        w.list.deinit(w.gpa);
    }

    /// Caller frees with the same allocator.
    pub fn toOwnedSlice(w: *Writer) ![]u8 {
        std.debug.assert(w.depth == 0);
        return w.list.toOwnedSlice(w.gpa);
    }

    pub fn begin(w: *Writer, t: u8) !void {
        if (w.depth == max_depth) return error.NestingTooDeep;
        try w.list.append(w.gpa, t);
        w.stack[w.depth] = w.list.items.len;
        w.depth += 1;
    }

    pub fn end(w: *Writer) !void {
        std.debug.assert(w.depth > 0);
        w.depth -= 1;
        const at = w.stack[w.depth];
        const len = w.list.items.len - at;
        var hdr: [5]u8 = undefined;
        const h = encodeLength(len, &hdr);
        try w.list.insertSlice(w.gpa, at, h);
    }

    pub fn primitive(w: *Writer, t: u8, content: []const u8) !void {
        var hdr: [6]u8 = undefined;
        hdr[0] = t;
        const l = encodeLength(content.len, hdr[1..6]);
        try w.list.appendSlice(w.gpa, hdr[0 .. 1 + l.len]);
        try w.list.appendSlice(w.gpa, content);
    }

    pub fn octetString(w: *Writer, data: []const u8) !void {
        try w.primitive(tag.octet_string, data);
    }

    pub fn generalString(w: *Writer, data: []const u8) !void {
        try w.primitive(tag.general_string, data);
    }

    pub fn oid(w: *Writer, content: []const u8) !void {
        try w.primitive(tag.oid, content);
    }

    pub fn integer(w: *Writer, v: i64) !void {
        var buf: [8]u8 = undefined;
        try w.primitive(tag.integer, encodeInteger(v, &buf));
    }

    pub fn enumerated(w: *Writer, v: i64) !void {
        var buf: [8]u8 = undefined;
        try w.primitive(tag.enumerated, encodeInteger(v, &buf));
    }

    pub fn bitString(w: *Writer, unused_bits: u3, data: []const u8) !void {
        try w.list.append(w.gpa, tag.bit_string);
        var hdr: [5]u8 = undefined;
        try w.list.appendSlice(w.gpa, encodeLength(data.len + 1, &hdr));
        try w.list.append(w.gpa, unused_bits);
        try w.list.appendSlice(w.gpa, data);
    }

    pub fn raw(w: *Writer, data: []const u8) !void {
        try w.list.appendSlice(w.gpa, data);
    }
};

fn encodeLength(len: usize, out: []u8) []const u8 {
    if (len < 0x80) {
        out[0] = @intCast(len);
        return out[0..1];
    }
    var n: usize = 0;
    var v = len;
    while (v != 0) : (v >>= 8) n += 1;
    std.debug.assert(n <= 4);
    out[0] = 0x80 | @as(u8, @intCast(n));
    for (0..n) |k| out[1 + k] = @truncate(len >> @intCast(8 * (n - 1 - k)));
    return out[0 .. 1 + n];
}

fn encodeInteger(v: i64, buf: *[8]u8) []const u8 {
    std.mem.writeInt(i64, buf, v, .big);
    var s: usize = 0;
    while (s < 7) : (s += 1) {
        const a = buf[s];
        const b = buf[s + 1];
        if (!((a == 0x00 and b & 0x80 == 0) or (a == 0xFF and b & 0x80 != 0))) break;
    }
    return buf[s..];
}

const testing = std.testing;
const hex = @import("../core/bytes.zig").hex;

test "integer encode/decode round trip and minimality" {
    const cases = [_]struct { v: i64, enc: []const u8 }{
        .{ .v = 0, .enc = &hex("00") },
        .{ .v = 6, .enc = &hex("06") },
        .{ .v = 127, .enc = &hex("7f") },
        .{ .v = 128, .enc = &hex("00 80") },
        .{ .v = 256, .enc = &hex("01 00") },
        .{ .v = -1, .enc = &hex("ff") },
        .{ .v = -128, .enc = &hex("80") },
        .{ .v = -129, .enc = &hex("ff 7f") },
        .{ .v = @as(i32, @bitCast(@as(u32, 0xC000006D))), .enc = &hex("c0 00 00 6d") },
        .{ .v = 0xC000006D, .enc = &hex("00 c0 00 00 6d") },
    };
    for (cases) |c| {
        var buf: [8]u8 = undefined;
        try testing.expectEqualSlices(u8, c.enc, encodeInteger(c.v, &buf));
        try testing.expectEqual(c.v, try decodeInteger(c.enc));
    }
    try testing.expectError(error.InvalidDer, decodeInteger(&hex("00 05")));
    try testing.expectError(error.InvalidDer, decodeInteger(&hex("ff 80")));
    try testing.expectError(error.InvalidDer, decodeInteger(""));
    try testing.expectError(error.InvalidDer, decodeInteger(&hex("01 02 03 04 05 06 07 08 09")));
}

test "reader rejects malformed lengths" {
    // indefinite length
    var r = Reader.init(&hex("30 80 00 00"));
    try testing.expectError(error.InvalidDer, r.next());
    // non-minimal long form
    r = Reader.init(&hex("04 81 05 01 02 03 04 05"));
    try testing.expectError(error.InvalidDer, r.next());
    // leading zero in long form
    const zeros: [0x80]u8 = @splat(0);
    const padded = hex("04 82 00 80") ++ zeros;
    r = Reader.init(&padded);
    try testing.expectError(error.InvalidDer, r.next());
    // length beyond buffer
    r = Reader.init(&hex("04 05 01 02"));
    try testing.expectError(error.EndOfBuffer, r.next());
    r = Reader.init(&hex("04 84 7f ff ff ff 00"));
    try testing.expectError(error.EndOfBuffer, r.next());
    // too many length octets
    r = Reader.init(&hex("04 85 00 00 00 00 01 00"));
    try testing.expectError(error.InvalidDer, r.next());
    // truncated header
    r = Reader.init(&hex("04"));
    try testing.expectError(error.EndOfBuffer, r.next());
    r = Reader.init(&hex("04 82 01"));
    try testing.expectError(error.EndOfBuffer, r.next());
    // high tag number form
    r = Reader.init(&hex("1f 22 00"));
    try testing.expectError(error.InvalidDer, r.next());
}

test "reader long form lengths" {
    var buf: [3 + 200]u8 = undefined;
    buf[0] = 0x04;
    buf[1] = 0x81;
    buf[2] = 200;
    @memset(buf[3..], 0xAB);
    var r = Reader.init(&buf);
    const e = try r.next();
    try testing.expectEqual(@as(usize, 200), e.content.len);
    try testing.expectEqual(@as(usize, buf.len), e.raw.len);
    try r.finish();
}

test "writer nested structure matches reader" {
    var w = Writer.init(testing.allocator);
    defer w.deinit();
    try w.begin(tag.sequence);
    try w.begin(tag.context(0));
    try w.integer(6);
    try w.end();
    try w.begin(tag.context(1));
    const fill: [300]u8 = @splat(0x11);
    try w.octetString(&fill);
    try w.end();
    try w.end();
    const out = try w.toOwnedSlice();
    defer testing.allocator.free(out);
    try testing.expectEqualSlices(u8, &hex("30 82 01 39 a0 03 02 01 06 a1 82 01 30 04 82 01 2c"), out[0..17]);

    var r = Reader.init(out);
    const seq = try r.expect(tag.sequence);
    try r.finish();
    var sr = seq.reader();
    const v = try sr.explicit(tag.context(0));
    try testing.expectEqual(@as(i64, 6), try decodeInteger(v.content));
    const os = try sr.explicit(tag.context(1));
    try testing.expectEqual(@as(usize, 300), os.content.len);
    try sr.finish();
}

test "explicit wrapper must contain exactly one element" {
    var r = Reader.init(&hex("a0 06 02 01 01 02 01 02"));
    try testing.expectError(error.TrailingData, r.explicit(tag.context(0)));
    r = Reader.init(&hex("a0 00"));
    try testing.expectError(error.EndOfBuffer, r.explicit(tag.context(0)));
}

test "oid and bit string validation" {
    var r = Reader.init(&hex("06 06 2b 06 01 05 05 02"));
    try testing.expectEqualSlices(u8, &hex("2b 06 01 05 05 02"), try r.oid());
    r = Reader.init(&hex("06 02 2b 86"));
    try testing.expectError(error.InvalidDer, r.oid());
    r = Reader.init(&hex("06 02 80 01"));
    try testing.expectError(error.InvalidDer, r.oid());
    r = Reader.init(&hex("03 03 00 aa bb"));
    const bs = try r.bitString();
    try testing.expectEqual(@as(u3, 0), bs.unused_bits);
    try testing.expectEqualSlices(u8, &hex("aa bb"), bs.data);
    r = Reader.init(&hex("03 02 01 01"));
    try testing.expectError(error.InvalidDer, r.bitString());
    r = Reader.init(&hex("03 00"));
    try testing.expectError(error.InvalidDer, r.bitString());
}

test "reader never panics on arbitrary input" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rnd = prng.random();
    var buf: [64]u8 = undefined;
    for (0..20000) |_| {
        const n = rnd.uintAtMost(usize, buf.len);
        rnd.bytes(buf[0..n]);
        if (n > 0 and rnd.boolean()) buf[0] = tag.sequence;
        var r = Reader.init(buf[0..n]);
        var steps: usize = 0;
        while (steps < 64) : (steps += 1) {
            const e = r.next() catch break;
            var sub = e.reader();
            _ = sub.next() catch {};
            _ = decodeInteger(e.content) catch {};
        }
    }
}
