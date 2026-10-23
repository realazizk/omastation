//! Bulk compression for a connection (MS-RDPBCGR 3.1.8, 2.2.1.11.1.1). One history
//! covers fast-path, slow-path and static channel output: Windows clients keep a
//! single receive context across them. RDPGFX (already ZGFX) is left alone.

const std = @import("std");
const bulk = @import("../codec/bulk.zig");

const log = std.log.scoped(.conn);

/// TS_VIRTUALCHANNEL_CAPABILITYSET.flags (MS-RDPBCGR 2.2.7.1.10).
pub const vccaps_compr_sc: u32 = 0x00000001;
pub const vccaps_compr_cs_8k: u32 = 0x00000002;

pub const State = struct {
    /// The negotiated type; null: no compression on this connection.
    type: ?bulk.Type = null,
    out: ?bulk.Compressor = null,
    vc_in: ?bulk.Decompressor = null,

    pub fn deinit(s: *State) void {
        if (s.out) |*c| c.deinit();
        if (s.vc_in) |*d| d.deinit();
        s.* = .{};
    }

    /// `server_max` is the highest type the server uses (null: none).
    pub fn start(s: *State, gpa: std.mem.Allocator, info_flags: u32, server_max: ?bulk.Type) bulk.Error!void {
        s.deinit();
        const max = server_max orelse return;
        const t = try bulk.chooseType(info_flags, max) orelse return;
        s.out = try bulk.Compressor.init(gpa, t);
        s.out.?.min_len = bulk.server_min_compressed;
        s.type = t;
    }

    /// Client-to-server compression is accepted whenever a type was negotiated.
    pub fn serverVcFlags(s: *const State) u32 {
        return if (s.type != null) vccaps_compr_cs_8k else 0;
    }

    /// Compressor for fast-path and slow-path output, or null.
    pub fn output(s: *State) ?*bulk.Compressor {
        return if (s.out) |*c| c else null;
    }

    /// Static channel output shares the output's history, so one context covers all.
    pub fn channelOutput(s: *State, client_vc_flags: u32) ?*bulk.Compressor {
        if (client_vc_flags & vccaps_compr_sc == 0) return null;
        return s.output();
    }

    /// RDP 4.0 decompressor for client channel data (3.1.5.2.1), created on first use.
    pub fn channelInput(s: *State, gpa: std.mem.Allocator) bulk.Error!?*bulk.Decompressor {
        if (s.type == null) return null;
        if (s.vc_in == null) s.vc_in = try bulk.Decompressor.init(gpa, .mppc_8k);
        return &s.vc_in.?;
    }
};

pub fn typeName(t: bulk.Type) []const u8 {
    return switch (t) {
        .mppc_8k => "RDP 4.0 (MPPC 8K)",
        .mppc_64k => "RDP 5.0 (MPPC 64K)",
        .ncrush => "RDP 6.0 (NCRUSH)",
        .xcrush => "RDP 6.1 (XCRUSH)",
    };
}

test "negotiation picks client's highest type, capped by server" {
    const gpa = std.testing.allocator;
    var s: State = .{};
    defer s.deinit();
    // INFO_COMPRESSION | PACKET_COMPR_TYPE_RDP61 << 9
    try s.start(gpa, 0x80 | 3 << 9, .xcrush);
    try std.testing.expectEqual(bulk.Type.xcrush, s.type.?);
    try std.testing.expectEqual(vccaps_compr_cs_8k, s.serverVcFlags());
    try s.start(gpa, 0x80 | 3 << 9, .mppc_64k);
    try std.testing.expectEqual(bulk.Type.mppc_64k, s.type.?);
    try s.start(gpa, 0x80 | 0 << 9, .xcrush);
    try std.testing.expectEqual(bulk.Type.mppc_8k, s.type.?);
    try s.start(gpa, 3 << 9, .xcrush); // no INFO_COMPRESSION
    try std.testing.expect(s.type == null and s.output() == null);
    try std.testing.expectEqual(@as(u32, 0), s.serverVcFlags());
    try std.testing.expect(try s.channelInput(gpa) == null);
    try s.start(gpa, 0x80 | 2 << 9, null); // --bulk none
    try std.testing.expect(s.type == null);
}

test "channel data compressed only for VCCAPS_COMPR_SC clients, sharing output history" {
    const gpa = std.testing.allocator;
    var s: State = .{};
    defer s.deinit();
    try s.start(gpa, 0x80 | 1 << 9, .xcrush);
    try std.testing.expect(s.channelOutput(0) == null);
    const c = s.channelOutput(vccaps_compr_sc).?;
    try std.testing.expectEqual(bulk.Type.mppc_64k, c.type);
    try std.testing.expect(c == s.output().?);
    const d = (try s.channelInput(gpa)).?;
    try std.testing.expectEqual(bulk.Type.mppc_8k, d.type);
}
