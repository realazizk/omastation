//! Link characterization for codec choices from network detection, send-window measures
//! and frame acknowledgements (MS-RDPEGFX 3.2.5.13, MS-RDPBCGR 2.2.12.1). Pure decisions, no I/O.

const std = @import("std");

pub const Link = struct {
    /// Lowest RTT, ms.
    base_rtt: ?u32 = null,
    /// Smoothed RTT, ms.
    average_rtt: ?u32 = null,
    /// Bandwidth, kbit/s.
    bandwidth: ?u64 = null,
};

pub const lan_rtt_ms: u32 = 5;
pub const slow_kbps: u64 = 20_000;
pub const fast_kbps: u64 = 100_000;
pub const distant_rtt_ms: u32 = 50;
/// maxUnacknowledgedFrameCount advertised in TS_FRAME_ACKNOWLEDGE_CAPABILITYSET.
pub const max_window: u32 = 16;

/// On a fast link the compressor costs more event-loop time than the bytes it saves.
pub fn compressGraphics(link: Link) bool {
    if (link.bandwidth) |bw| return bw < fast_kbps;
    const rtt = link.average_rtt orelse return true;
    return rtt >= lan_rtt_ms;
}

pub const State = struct {
    link: Link = .{},
    /// Acknowledgement latency, ms: moving average (1/8) and lowest.
    ack_avg: ?u32 = null,
    ack_min: ?u32 = null,
    started: bool = false,

    pub fn start(s: *State, link: Link) void {
        s.link = link;
        s.started = true;
    }

    pub fn onLink(s: *State, link: Link) void {
        s.link = link;
    }

    /// One frame acknowledged `ms` after it was sent.
    pub fn onAck(s: *State, ms: u32) void {
        s.ack_min = if (s.ack_min) |m| @min(m, ms) else ms;
        s.ack_avg = if (s.ack_avg) |a| @intCast((@as(u64, a) * 7 + ms + 4) / 8) else ms;
    }

    /// The link is slow or distant: CPU lossy codecs pay off.
    pub fn slow(s: *const State) bool {
        if (s.link.bandwidth) |bw| return bw < slow_kbps;
        if (s.link.average_rtt) |rtt| return rtt >= distant_rtt_ms;
        return false;
    }

    /// A LAN: RTT under 5 ms and no bandwidth measured, or nothing known.
    pub fn lan(s: *const State) bool {
        if (s.link.bandwidth != null) return false;
        const rtt = s.link.average_rtt orelse return true;
        return rtt < lan_rtt_ms;
    }
};

const testing = std.testing;

test "LAN and slow link classification" {
    var s: State = .{};
    try testing.expect(s.lan() and !s.slow());
    s.onLink(.{ .base_rtt = 1, .average_rtt = 2 });
    try testing.expect(s.lan() and !s.slow());
    s.onLink(.{ .base_rtt = 60, .average_rtt = 80 });
    try testing.expect(!s.lan() and s.slow());
    s.onLink(.{ .base_rtt = 60, .average_rtt = 80, .bandwidth = 100_000 });
    try testing.expect(!s.slow()); // fast enough despite the distance
    s.onLink(.{ .base_rtt = 2, .average_rtt = 3, .bandwidth = 5_000 });
    try testing.expect(s.slow() and !s.lan());
}

test "acknowledgement latency tracks a 1/8 moving average and the minimum" {
    var s: State = .{};
    s.onAck(40);
    try testing.expectEqual(@as(?u32, 40), s.ack_avg);
    s.onAck(8);
    try testing.expectEqual(@as(?u32, 36), s.ack_avg);
    try testing.expectEqual(@as(?u32, 8), s.ack_min);
}

test "RTT at u32 max overflows nothing in link class or frames-in-flight bound" {
    const max = std.math.maxInt(u32);
    var s: State = .{};
    s.start(.{ .base_rtt = max, .average_rtt = max, .bandwidth = max });
    s.onAck(max);
    s.onLink(.{ .base_rtt = 0, .average_rtt = max, .bandwidth = 1 });
    _ = s.slow();
    _ = s.lan();
    const pacing = @import("pacing.zig");
    var p: pacing.State = .{};
    try testing.expectEqual(pacing.max_frames_in_flight, p.framesInFlight(max));
    p.client_ms = 0;
    try testing.expectEqual(pacing.max_frames_in_flight, p.framesInFlight(max));
}

test "graphics are bulk-compressed unless the link is measured fast; unknown compresses" {
    try testing.expect(compressGraphics(.{}));
    try testing.expect(!compressGraphics(.{ .base_rtt = 0, .average_rtt = 1 }));
    try testing.expect(compressGraphics(.{ .base_rtt = 4, .average_rtt = 5 }));
    try testing.expect(compressGraphics(.{ .average_rtt = 40 }));
    // A bandwidth measure decides over the RTT.
    try testing.expect(!compressGraphics(.{ .average_rtt = 40, .bandwidth = 128_000 }));
    try testing.expect(!compressGraphics(.{ .bandwidth = fast_kbps }));
    try testing.expect(compressGraphics(.{ .average_rtt = 1, .bandwidth = 50_000 }));
}
