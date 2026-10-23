//! Bulk compression, MS-RDPBCGR 3.1.8 and MS-RDPEGDI 3.1.8: MPPC (RDP 4.0/5.0), NCRUSH
//! (RDP 6.0) and XCRUSH (RDP 6.1) compressors and decompressors.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const mppc = @import("bulk/mppc.zig");
const ncrush = @import("bulk/ncrush.zig");
const xcrush = @import("bulk/xcrush.zig");

pub const Error = error{
    /// Input larger than `maxInput` for the type.
    TooLarge,
    BadData,
    /// A token that cannot be encoded (offset beyond history, match < 3).
    BadToken,
    BufferTooSmall,
} || std.mem.Allocator.Error;

pub const Type = enum(u4) {
    mppc_8k = 0,
    mppc_64k = 1,
    ncrush = 2,
    xcrush = 3,
};

pub const compr_type_mask: u8 = 0x0F;
pub const packet_compressed: u8 = 0x20;
pub const packet_at_front: u8 = 0x40;
pub const packet_flushed: u8 = 0x80;

/// Compressor.min_len for server output, as Windows servers use for fast-path and channel data.
pub const server_min_compressed: usize = 51;

pub const l1_compressed: u8 = 0x01;
pub const l1_no_compression: u8 = 0x02;
pub const l1_packet_at_front: u8 = 0x04;
pub const l1_inner_compression: u8 = 0x10;

/// TS_INFO_PACKET flags (MS-RDPBCGR 2.2.1.11.1.1).
pub const info_compression: u32 = 0x0000_0080;
pub const info_compression_type_mask: u32 = 0x0000_1E00;
/// Fast-path updateHeader compression field value (bits 6-7).
pub const fastpath_output_compression_used: u8 = 0x2;
/// CHANNEL_PDU_HEADER flags (MS-RDPBCGR 2.2.6.1.1).
pub const channel_packet_compressed: u32 = 0x0020_0000;
pub const channel_packet_at_front: u32 = 0x0040_0000;
pub const channel_packet_flushed: u32 = 0x0080_0000;
pub const channel_compr_type_mask: u32 = 0x000F_0000;

pub fn historySize(t: Type) Error!usize {
    return switch (t) {
        .mppc_8k => 8192,
        .mppc_64k, .ncrush => 65536,
        .xcrush => xcrush.history_size,
    };
}

/// Largest block one call may compress; always smaller than the history.
pub fn maxInput(t: Type) Error!usize {
    return switch (t) {
        .mppc_8k, .mppc_64k => try historySize(t) - 1,
        .ncrush => ncrush.fill_limit,
        .xcrush => xcrush.max_input,
    };
}

/// Highest type the client accepts, null without INFO_COMPRESSION. Undefined values
/// above RDP 6.1 read as RDP 6.1.
pub fn clientMaxType(info_flags: u32) Error!?Type {
    if (info_flags & info_compression == 0) return null;
    const v = (info_flags & info_compression_type_mask) >> 9;
    return @fromBackingInt(@intCast(@min(v, @backingInt(Type.xcrush))));
}

/// min(client max, server max); null when the client did not ask for compression.
pub fn chooseType(info_flags: u32, server_max: Type) Error!?Type {
    const c = try clientMaxType(info_flags) orelse return null;
    return @fromBackingInt(@intCast(@min(@backingInt(c), @backingInt(server_max))));
}

/// `data` stays valid until the next call on the compressor.
pub const Result = struct {
    /// Type | PACKET_* bits; without PACKET_COMPRESSED `data` is the raw input.
    flags: u8,
    data: []const u8,
};

/// CHANNEL_PDU_HEADER flags bits for a result (flags << 16).
pub fn channelFlags(r: Result) Error!u32 {
    return @as(u32, r.flags) << 16;
}

/// Fast-path output update with compressionFlags (MS-RDPBCGR 2.2.9.1.2.1).
pub fn writeFastPathUpdate(w: *bytes.Writer, update_code: u4, r: Result) Error!void {
    if (r.data.len > std.math.maxInt(u16)) return error.TooLarge;
    try w.byte(@as(u8, fastpath_output_compression_used) << 6 | update_code);
    try w.byte(r.flags);
    try w.u16le(@intCast(r.data.len));
    try w.bytes(r.data);
}

pub const Compressor = struct {
    gpa: std.mem.Allocator,
    type: Type,
    state: State,
    /// Shorter packets go raw without touching the history.
    min_len: usize = 4,

    const State = union(enum) {
        mppc: mppc.Compressor,
        ncrush: ncrush.Compressor,
        xcrush: xcrush.Compressor,
    };

    pub fn init(gpa: std.mem.Allocator, t: Type) Error!Compressor {
        const state: State = switch (t) {
            .mppc_8k, .mppc_64k => .{ .mppc = try mppc.Compressor.init(gpa, t == .mppc_64k) },
            .ncrush => .{ .ncrush = try ncrush.Compressor.init(gpa) },
            .xcrush => .{ .xcrush = try xcrush.Compressor.init(gpa) },
        };
        return .{ .gpa = gpa, .type = t, .state = state };
    }

    pub fn deinit(c: *Compressor) void {
        switch (c.state) {
            inline else => |*s| s.deinit(c.gpa),
        }
    }

    /// Output is never larger than `src` (3.1.8.2.1): on expansion `src` goes raw and
    /// the history resets, signalled by PACKET_FLUSHED (3.1.8.2).
    pub fn compress(c: *Compressor, src: []const u8) Error!Result {
        if (src.len > try maxInput(c.type)) return error.TooLarge;
        if (src.len < c.min_len) return .{ .flags = 0, .data = src };
        return switch (c.state) {
            .mppc => |*s| s.compress(src),
            .ncrush => |*s| s.compress(src),
            .xcrush => |*s| try s.compress(src),
        };
    }

    /// Discard the history: the next compressed packet carries PACKET_FLUSHED.
    pub fn flush(c: *Compressor) Error!void {
        switch (c.state) {
            inline else => |*s| s.flush(),
        }
    }
};

/// Client-to-server channel data may be compressed (VCCAPS_COMPR_CS_8K, MS-RDPBCGR 3.1.8).
pub const Decompressor = struct {
    gpa: std.mem.Allocator,
    type: Type,
    state: State,

    const State = union(enum) {
        mppc: mppc.Decoder,
        ncrush: ncrush.Decoder,
        xcrush: xcrush.Decoder,
    };

    pub fn init(gpa: std.mem.Allocator, t: Type) Error!Decompressor {
        const state: State = switch (t) {
            .mppc_8k, .mppc_64k => .{ .mppc = try mppc.Decoder.init(gpa, t == .mppc_64k) },
            .ncrush => .{ .ncrush = try ncrush.Decoder.init(gpa) },
            .xcrush => .{ .xcrush = try xcrush.Decoder.init(gpa) },
        };
        return .{ .gpa = gpa, .type = t, .state = state };
    }

    pub fn deinit(d: *Decompressor) void {
        switch (d.state) {
            inline else => |*s| s.deinit(d.gpa),
        }
    }

    /// The result is valid until the next call; error.BadData on malformed input.
    pub fn decompress(d: *Decompressor, src: []const u8, flags: u8) Error![]const u8 {
        return switch (d.state) {
            inline else => |*s| s.decompress(src, flags),
        };
    }
};

pub const Token = union(enum) {
    literal: u8,
    /// Offset back from the current position (>= 1); length >= 3 for MPPC, >= 2 for NCRUSH.
    copy: struct { offset: u32, length: u32 },
};

/// MPPC bit packing (MS-RDPBCGR 3.1.8.4.1 / 3.1.8.4.2), zero-padded to a byte; returns
/// the byte count. error.BadToken for copies the type cannot express.
pub fn mppcEncodeTokens(t: Type, tokens: []const Token, out: []u8) Error!usize {
    const big = switch (t) {
        .mppc_8k => false,
        .mppc_64k => true,
        else => return error.BadToken,
    };
    var w: mppc.Writer = .{ .out = out };
    for (tokens) |tok| switch (tok) {
        .literal => |b| w.literal(b) catch return error.BufferTooSmall,
        .copy => |cp| {
            if (!mppc.checkCopy(big, cp.offset, cp.length)) return error.BadToken;
            w.copy(big, cp.offset, cp.length) catch return error.BufferTooSmall;
        },
    };
    return w.finish() catch error.BufferTooSmall;
}

/// NCRUSH bit packing (MS-RDPEGDI 3.1.8.1.4.3) plus EOS, from an empty OffsetCache. A cache
/// hit swaps with entry 0; 3.1.8.1.1 only says the cache holds the last four offsets.
pub fn ncrushEncodeTokens(tokens: []const Token, out: []u8) Error!usize {
    var w: ncrush.Writer = .{ .out = out };
    var cache = [4]u32{ 0, 0, 0, 0 };
    for (tokens) |tok| switch (tok) {
        .literal => |b| w.literal(b) catch return error.BufferTooSmall,
        .copy => |cp| {
            if (cp.offset < 1 or cp.offset > ncrush.max_offset or cp.length < ncrush.min_len or cp.length > ncrush.max_len) return error.BadToken;
            w.copy(&cache, cp.offset, cp.length) catch return error.BufferTooSmall;
        },
    };
    w.end() catch return error.BufferTooSmall;
    return w.finish() catch error.BufferTooSmall;
}

/// RDP61_MATCH_DETAILS (MS-RDPEGDI 2.2.2.4.1.1).
pub const MatchDetails = struct {
    length: u16,
    output_offset: u16,
    history_offset: u32,
};

/// RDP61_COMPRESSED_DATA (MS-RDPEGDI 2.2.2.4.1). L1_COMPRESSED requires at least one
/// match and MatchDetails require L1_COMPRESSED: error.BadToken otherwise.
pub fn writeRdp61(w: *bytes.Writer, l1_flags: u8, l2_flags: u8, matches: []const MatchDetails, literals: []const u8) Error!void {
    const compressed = l1_flags & l1_compressed != 0;
    if (compressed and (matches.len == 0 or matches.len > std.math.maxInt(u16))) return error.BadToken;
    if (!compressed and matches.len != 0) return error.BadToken;
    try w.byte(l1_flags);
    try w.byte(l2_flags);
    if (compressed) {
        try w.u16le(@intCast(matches.len));
        for (matches) |m| {
            try w.u16le(m.length);
            try w.u16le(m.output_offset);
            try w.u32le(m.history_offset);
        }
    }
    try w.bytes(literals);
}

pub const Level1Options = struct {
    /// Shortest match worth a RDP61_MATCH_DETAILS (8 bytes of overhead).
    min_match: usize = 11,
    /// Keep matches even when output grows, as the MS-RDPEGDI 3.1.8.2.2.1 example does.
    allow_expansion: bool = false,
};

/// Level-1 (RDP 6.1) output for one block, before level-2 compression.
pub const Level1Result = struct {
    l1_flags: u8,
    matches: []const MatchDetails,
    literals: []const u8,
};

pub const Level1 = struct {
    gpa: std.mem.Allocator,
    opts: Level1Options,
    core: xcrush.Level1,

    pub fn init(gpa: std.mem.Allocator, opts: Level1Options) Error!Level1 {
        return .{ .gpa = gpa, .opts = opts, .core = try xcrush.Level1.init(gpa, opts) };
    }

    pub fn deinit(l: *Level1) void {
        l.core.deinit();
    }

    /// The result stays valid until the next call.
    pub fn compress(l: *Level1, src: []const u8) Error!Level1Result {
        return l.core.compress(src);
    }
};

test {
    _ = mppc;
    _ = ncrush;
    _ = xcrush;
    _ = @import("bulk/lz.zig");
}

test "every type round trips through its decompressor" {
    const gpa = std.testing.allocator;
    const line = "No man is an island entire of itself; every man is a piece of the continent, a part of the main. ";
    var text: [line.len * 20]u8 = undefined;
    for (0..20) |i| @memcpy(text[i * line.len ..][0..line.len], line);
    for ([_]Type{ .mppc_8k, .mppc_64k, .ncrush, .xcrush }) |t| {
        var c = try Compressor.init(gpa, t);
        defer c.deinit();
        var d = try Decompressor.init(gpa, t);
        defer d.deinit();
        for (0..3) |_| {
            const r = try c.compress(&text);
            try std.testing.expect(r.flags & packet_compressed != 0);
            try std.testing.expect(r.data.len < text.len / 4);
            try std.testing.expectEqualStrings(&text, try d.decompress(r.data, r.flags));
        }
    }
}
