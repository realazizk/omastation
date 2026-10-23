//! MS-RDPEUDP 3.1.5.2 server connection sequence, and the data transfer an established
//! connection switches to: the version 1/2 engine or the MS-RDPEUDP2 endpoint.

const std = @import("std");
const bytes = @import("../../core/bytes.zig");
const mt = @import("../multitransport.zig");
const udp2 = @import("udp2.zig");

const TransportError = mt.TransportError;
const ConnState = mt.ConnState;

/// 3.1.5.2 <8>: Windows retransmits the SYN+ACK three times.
const syn_ack_retransmits: u8 = 3;

/// Server end of the three-way handshake (3.1.5.2). The SYN+ACK is resent every
/// windows_syn_retransmit_timeout_us; without the client's ACK the endpoint closes.
pub const ServerHandshake = struct {
    config: mt.ServerUdpConfig,
    cookie: [16]u8,
    st: ConnState = .listen,
    syn: mt.Syn = undefined,
    answer: mt.Syn = undefined,
    wire: [mt.max_mtu]u8 = undefined,
    wire_len: usize = 0,
    send_now: bool = false,
    last_now: u64 = 0,
    retransmit_at: ?u64 = null,
    retransmits: u8 = 0,
    /// rtt_us: SYN+ACK to the client's ACK, 0 when the SYN+ACK was retransmitted.
    synack_sent_us: ?u64 = null,
    rtt_us: u64 = 0,

    pub fn init(config: mt.ServerUdpConfig, security_cookie: [16]u8) TransportError!ServerHandshake {
        return .{ .config = config, .cookie = security_cookie };
    }

    /// Malformed datagrams are errors and change nothing; out-of-state ones are ignored.
    pub fn onDatagram(h: *ServerHandshake, datagram: []const u8, now_us: u64) TransportError!void {
        if (h.st == .closed) return;
        var r = bytes.Reader.init(datagram);
        const sn_source_ack = try r.u32be();
        _ = try r.u16be();
        const flags = try r.u16be();
        h.last_now = @max(h.last_now, now_us);
        if (flags & mt.rdpudp_flag_syn != 0) {
            const syn = try mt.decodeSyn(datagram);
            if (syn.ack or h.st != .listen) return; // only a client SYN, once
            const answer = try mt.answerSyn(syn, h.config, h.cookie);
            h.wire_len = (try mt.encodeSynInto(answer, &h.wire)).len;
            h.syn = syn;
            h.answer = answer;
            h.st = .syn_received;
            h.send_now = true;
            return;
        }
        // 3.1.5.2 step 5: the ACK may carry Source Packets, which the data phase reads.
        if (h.st != .syn_received) return;
        if (flags & mt.rdpudp_flag_ack == 0) return;
        if (sn_source_ack != h.config.initial_sequence_number) return;
        if (h.retransmits == 0) if (h.synack_sent_us) |sent| {
            if (now_us > sent) h.rtt_us = now_us - sent;
        };
        h.st = .established;
        h.retransmit_at = null;
        h.send_now = false;
    }

    /// The SYN+ACK (zero-padded, 3.1.5.1.1 step 6) or its retransmission, or null.
    pub fn poll(h: *ServerHandshake, now_us: u64, out: []u8) TransportError!?[]u8 {
        if (h.st != .syn_received) return null;
        h.last_now = @max(h.last_now, now_us);
        if (!h.send_now) {
            const at = h.retransmit_at orelse return null;
            if (now_us < at) return null;
            if (h.retransmits >= syn_ack_retransmits) {
                h.st = .closed;
                h.retransmit_at = null;
                return null;
            }
            h.retransmits += 1;
        }
        if (out.len < h.wire_len) return error.EndOfBuffer;
        if (h.synack_sent_us == null) h.synack_sent_us = now_us;
        h.send_now = false;
        h.retransmit_at = now_us + mt.windows_syn_retransmit_timeout_us;
        @memcpy(out[0..h.wire_len], h.wire[0..h.wire_len]);
        return out[0..h.wire_len];
    }

    pub fn nextTimeout(h: *const ServerHandshake) TransportError!?u64 {
        if (h.st != .syn_received) return null;
        if (h.send_now) return h.last_now;
        return h.retransmit_at;
    }

    pub fn state(h: *const ServerHandshake) TransportError!ConnState {
        return h.st;
    }

    /// Once Established: what was negotiated (error.NotEstablished before).
    pub fn negotiated(h: *const ServerHandshake) TransportError!mt.Negotiated {
        if (h.st != .established) return error.NotEstablished;
        const version = try mt.negotiatedVersion(h.syn, h.answer);
        return .{
            .mode = try mt.modeOfSyn(h.syn),
            .version = version,
            .phase = try mt.dataPhaseFor(version),
            .local_isn = h.config.initial_sequence_number,
            .peer_isn = h.syn.syn_data.initial_sequence_number,
            .receive_window_size = h.config.receive_window_size,
            .peer_receive_window_size = h.syn.receive_window_size,
            .up_stream_mtu = h.answer.syn_data.up_stream_mtu,
            .down_stream_mtu = h.answer.syn_data.down_stream_mtu,
            .correlation_id = h.syn.correlation_id,
            .handshake_rtt_us = h.rtt_us,
        };
    }
};

/// Smallest LogWindowSize whose (1 << n) - 1 packets cover `window` (MS-RDPEUDP2 3.1.1.1.3).
pub fn logWindowFor(window: u16) u4 {
    var n: u5 = 1;
    while (n < udp2.max_log_window_size and (@as(u32, 1) << n) - 1 < window) n += 1;
    return @intCast(n);
}

/// Data transfer of an established connection (MS-RDPEUDP 1.3.2.2). RDP-UDP2 numbers data
/// packets from ISN + 1, like RDP-UDP Source Packets (MS-RDPEUDP 3.1.5.1.4).
pub const Connection = union(mt.DataPhase) {
    rdpudp: mt.Engine,
    rdpudp2: udp2.Endpoint,

    pub fn init(gpa: std.mem.Allocator, n: mt.Negotiated) TransportError!Connection {
        return switch (n.phase) {
            .rdpudp => .{
                .rdpudp = try mt.Engine.init(gpa, .{
                    .mode = n.mode,
                    .version = n.version,
                    .initial_sequence_number = n.local_isn,
                    .peer_initial_sequence_number = n.peer_isn,
                    .receive_window_size = n.receive_window_size,
                    .peer_receive_window_size = n.peer_receive_window_size,
                    // 3.1.1.3: the server sends at most uDownStreamMtu.
                    .mtu = n.down_stream_mtu,
                    // Keeps the first time-outs above a path slower than their minimum.
                    .initial_rtt_us = n.handshake_rtt_us,
                }),
            },
            .rdpudp2 => blk: {
                // MS-RDPEUDP2 1.3: reliable only.
                if (n.mode != .reliable) return error.InvalidField;
                break :blk .{ .rdpudp2 = try udp2.Endpoint.init(gpa, .{
                    .initial_seq = @as(u64, n.local_isn) + 1,
                    .peer_initial_seq = @as(u64, n.peer_isn) + 1,
                    .log_window_size = logWindowFor(n.receive_window_size),
                    .peer_log_window_size = logWindowFor(n.peer_receive_window_size),
                }) };
            },
        };
    }

    pub fn deinit(c: *Connection) void {
        switch (c.*) {
            inline else => |*x| x.deinit(),
        }
    }

    pub fn phase(c: *const Connection) TransportError!mt.DataPhase {
        return c.*;
    }

    /// RDP-UDP-R and RDP-UDP2 carry a byte stream cut into packets (MS-RDPEUDP 3.1.5.3.1);
    /// RDP-UDP-L sends one datagram per write.
    pub fn send(c: *Connection, data: []const u8) TransportError!void {
        switch (c.*) {
            .rdpudp => |*x| return x.send(data),
            .rdpudp2 => |*x| {
                const max = try x.maxPayload();
                var at: usize = 0;
                while (at < data.len) {
                    const end = @min(at + max, data.len);
                    try x.send(data[at..end]);
                    at = end;
                }
            },
        }
    }

    pub fn onDatagram(c: *Connection, datagram: []const u8, now_us: u64) TransportError!void {
        switch (c.*) {
            inline else => |*x| return x.onDatagram(datagram, now_us),
        }
    }

    pub fn poll(c: *Connection, now_us: u64, out: []u8) TransportError!?[]u8 {
        switch (c.*) {
            inline else => |*x| return x.poll(now_us, out),
        }
    }

    pub fn receive(c: *Connection, out: []u8) TransportError!?[]u8 {
        switch (c.*) {
            inline else => |*x| return x.receive(out),
        }
    }

    pub fn nextTimeout(c: *const Connection) TransportError!?u64 {
        switch (c.*) {
            inline else => |*x| return x.nextTimeout(),
        }
    }

    pub fn state(c: *const Connection) TransportError!ConnState {
        switch (c.*) {
            inline else => |*x| return x.state(),
        }
    }

    pub fn closeReason(c: *const Connection) ?mt.CloseReason {
        switch (c.*) {
            inline else => |*x| return x.closeReason(),
        }
    }

    /// Bytes accepted now without waiting for a window.
    pub fn sendRoom(c: *const Connection) usize {
        switch (c.*) {
            inline else => |*x| return x.sendRoom(),
        }
    }

    pub fn unsentBytes(c: *const Connection) usize {
        switch (c.*) {
            inline else => |*x| return x.unsentBytes(),
        }
    }

    /// The rate its window allows (B/s), null before an RTT sample.
    pub fn windowRate(c: *const Connection) ?f64 {
        switch (c.*) {
            inline else => |*x| return x.windowRate(),
        }
    }

    pub fn counters(c: *const Connection) struct { sent: u64, retransmits: u64, odd_acks: u64 = 0 } {
        return switch (c.*) {
            .rdpudp => |*x| .{ .sent = x.stats_.source_sent, .retransmits = x.stats_.retransmits, .odd_acks = x.stats_.ack_reach_before_first },
            .rdpudp2 => |*x| .{ .sent = x.stats_.data_sent, .retransmits = x.stats_.retransmits },
        };
    }
};
