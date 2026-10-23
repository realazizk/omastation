//! MS-RDPEUDP 3.1.5.3 data transfer, versions 1 and 2: Source and FEC Packets, windows,
//! ACK vectors, loss recovery, congestion control, reliable and lossy delivery. Sequence
//! numbers wrap (3.1.1.2); each side is tracked as a 64-bit offset from its ISN (`offsetOf`).

const std = @import("std");
const mt = @import("../multitransport.zig");
const fec = @import("fec.zig");

const TransportError = mt.TransportError;
const ConnState = mt.ConnState;
const Mode = mt.Mode;
const us_per_ms = mt.us_per_ms;
const us_per_s = mt.us_per_s;

pub const EngineConfig = struct {
    mode: Mode,
    /// RDPUDP_PROTOCOL_VERSION_1 or _2 (timers, 3.1.6).
    version: u16 = mt.rdpudp_protocol_version_2,
    /// The first Source Packet is ISN + 1 (3.1.5.1.4).
    initial_sequence_number: u32,
    peer_initial_sequence_number: u32,
    /// uReceiveWindowSize when nothing waits to be read (3.1.5.1.2), in datagrams.
    receive_window_size: u16 = 64,
    peer_receive_window_size: u16 = 64,
    /// Largest datagram sent (3.1.1.3).
    mtu: u16 = mt.max_mtu,
    /// Source Packets per FEC Packet (up to 255); 0: no FEC (1.3.2.2).
    fec_block_size: u8 = 0,
    /// RDP-UDP-L: wait for a missing datagram before handing up what follows (3.1.1.1).
    reorder_timeout_us: u64 = 200 * us_per_ms,
    /// 3..5 (3.1.5.4.1); Windows uses 5.
    max_retransmits: u8 = 5,
    /// Source Packets per cumulative ACK (3.1.1.4); Windows uses 2.
    ack_every: u8 = 2,
    /// At most 65 s (3.1.1.9); Windows sends four per 65 s.
    keepalive_interval_us: u64 = 65 * us_per_s / 4,
    /// 0: unknown.
    initial_rtt_us: u64 = 0,
    /// In datagrams (RFC 5681 3.1).
    initial_congestion_window: u16 = 3,
};

pub const EngineStats = struct {
    in_flight: usize = 0,
    source_sent: u64 = 0,
    retransmits: u64 = 0,
    fec_sent: u64 = 0,
    fec_recovered: u64 = 0,
    duplicates_dropped: u64 = 0,
    out_of_window_dropped: u64 = 0,
    /// RDP-UDP-L: datagrams given up on.
    skipped: u64 = 0,
    /// ACK vectors reaching back before the first datagram sent (miscoded run lengths).
    ack_reach_before_first: u64 = 0,
    delivered: u64 = 0,
};

/// Windows doubles the retransmit time-out up to 120 s.
const max_rto_us: u64 = 120 * us_per_s;
const max_vector = mt.max_ack_vector_size;
/// The header with two elements is one DWORD.
const reserved_vector_elements: usize = 2;
const min_congestion_window: usize = 2;
/// Read payloads kept for FEC recovery: a block spans at most 255 (1.3.2.2), plus slack.
const fec_history: u32 = 512;

const Outstanding = struct {
    payload: []u8,
    first_sent_us: u64,
    timer_at_us: u64,
    rto_us: u64,
    retransmits: u8 = 0,
    acked: bool = false,
    /// RDP-UDP-L: given up on; resolved for CumAcked (3.1.1.7).
    given_up: bool = false,
    /// For the current loss (3.1.5.3.2.1).
    fast_retransmitted: bool = false,
    /// In the retransmission queue.
    queued: bool = false,
    timer_retransmit: bool = false,
};

const Slot = struct {
    /// Offset from the peer ISN.
    off: u64 = 0,
    received: bool = false,
    payload: ?[]u8 = null,
};

/// One established RDP-UDP connection (3.1.5.3), both directions.
pub const Engine = struct {
    gpa: std.mem.Allocator,
    cfg: EngineConfig,
    closed: bool = false,
    close_reason: ?mt.CloseReason = null,
    started: bool = false,
    last_now: u64 = 0,
    last_heard_us: u64 = 0,
    last_sent_us: u64 = 0,

    // -- sender ------------------------------------------------------------
    /// snCoded of the next Coded Packet (3.1.5.1.4).
    next_coded: u32,
    next_off: u64 = 1,
    /// CumAcked, as an offset (3.1.1.7).
    cum_off: u64 = 0,
    /// Source Packets cum_off + 1 .. next_off - 1.
    outstanding: std.ArrayList(Outstanding) = .empty,
    out_head: usize = 0,
    /// One Source Packet each.
    unsent: std.ArrayList([]u8) = .empty,
    unsent_head: usize = 0,
    retx: std.ArrayList(u64) = .empty,
    peer_window: u16,
    srtt_us: u64,
    /// Doubled time-out kept for new datagrams until an RTT sample (RFC 6298 5.5-5.7); 0: none.
    rto_backoff_us: u64 = 0,
    rtt_known: bool,
    cwnd: usize,
    ssthresh: usize = std.math.maxInt(usize),
    cwnd_credit: usize = 0,
    /// NewReno: no second reduction until CumAcked passes this offset.
    recovery_off: ?u64 = null,
    /// A Congestion Notification to answer with CWR (3.1.1.8).
    cwr_due: bool = false,
    /// The Source Packet that carried the last CWR.
    cwr_off: ?u64 = null,
    /// Source transmissions since the last ACK of ACKs (2.2.2.6).
    since_ack_of_acks: u32 = 0,
    /// Payload copies of the current FEC block.
    fec_block: std.ArrayList([]u8) = .empty,
    fec_block_off: u64 = 0,
    fec_index: u8 = 0,

    // -- receiver ----------------------------------------------------------
    ring: []Slot,
    /// Highest Source offset received (0: none).
    rx_high: u64 = 0,
    /// Everything up to here was queued for the application or given up.
    rx_done: u64 = 0,
    /// Reliable: everything up to here was read.
    rx_read: u64 = 0,
    /// The ACK vector covers (vec_start, rx_high] (2.2.2.6).
    vec_start: u64 = 0,
    ready: std.ArrayList(u64) = .empty,
    ready_head: usize = 0,
    /// Received datagrams in (rx_done, rx_high].
    held: usize = 0,
    unacked: usize = 0,
    ack_deadline: ?u64 = null,
    ack_now: bool = false,
    /// The last data datagram cut its ACK vector: an ACK-only datagram is next.
    ack_cut: bool = false,
    /// Setting RDPUDP_FLAG_CN until a CWR arrives (3.1.1.8).
    cn_active: bool = false,
    /// Losses up to this offset were notified already.
    cn_marked: u64 = 0,
    /// RDP-UDP-L out-of-order timer (3.1.1.1).
    reorder_deadline: ?u64 = null,
    last_advertised: u16 = 0,

    stats_: EngineStats = .{},

    pub fn init(gpa: std.mem.Allocator, config: EngineConfig) TransportError!Engine {
        _ = try mt.minRetransmitTimeoutUs(config.version);
        if (config.max_retransmits < 3 or config.max_retransmits > 5) return error.InvalidField;
        if (config.mtu < mt.min_mtu or config.mtu > mt.max_mtu) return error.BadMtu;
        const window = @max(@as(usize, config.receive_window_size), 1);
        const ring_len = std.math.ceilPowerOfTwo(usize, @max(4 * window, 512)) catch return error.InvalidField;
        const ring = try gpa.alloc(Slot, @min(ring_len, 1 << 18));
        @memset(ring, .{});
        return .{
            .gpa = gpa,
            .cfg = config,
            .next_coded = config.initial_sequence_number +% 1,
            .peer_window = config.peer_receive_window_size,
            .srtt_us = config.initial_rtt_us,
            .rtt_known = config.initial_rtt_us != 0,
            .cwnd = @max(config.initial_congestion_window, 1),
            .ring = ring,
            .last_advertised = config.receive_window_size,
        };
    }

    pub fn deinit(e: *Engine) void {
        for (e.outstanding.items[e.out_head..]) |o| e.gpa.free(o.payload);
        e.outstanding.deinit(e.gpa);
        for (e.unsent.items[e.unsent_head..]) |u| e.gpa.free(u);
        e.unsent.deinit(e.gpa);
        e.retx.deinit(e.gpa);
        for (e.fec_block.items) |b| e.gpa.free(b);
        e.fec_block.deinit(e.gpa);
        for (e.ring) |s| if (s.payload) |p| e.gpa.free(p);
        e.gpa.free(e.ring);
        e.ready.deinit(e.gpa);
    }

    /// error.MessageTooLarge for an oversized lossy write.
    pub fn send(e: *Engine, data: []const u8) TransportError!void {
        if (e.closed) return error.ConnectionClosed;
        const max = try e.maxPayload();
        if (e.cfg.mode == .lossy) {
            if (data.len > max) return error.MessageTooLarge;
            try e.queueChunk(data);
            return;
        }
        // 3.1.5.3.1: RDP-UDP-R is a stream, cut into MTU-sized chunks.
        var at: usize = 0;
        while (true) {
            const end = @min(at + max, data.len);
            try e.queueChunk(data[at..end]);
            at = end;
            if (at >= data.len) break;
        }
    }

    fn queueChunk(e: *Engine, chunk: []const u8) TransportError!void {
        const copy = try e.gpa.dupe(u8, chunk);
        errdefer e.gpa.free(copy);
        try e.unsent.append(e.gpa, copy);
    }

    fn tick(e: *Engine, now_us: u64) void {
        if (!e.started) {
            e.started = true;
            e.last_heard_us = now_us;
            e.last_sent_us = now_us;
        }
        e.last_now = @max(e.last_now, now_us);
    }

    // -- receiving datagrams -------------------------------------------------

    /// Malformed: an error, state unchanged (5.1.2).
    pub fn onDatagram(e: *Engine, datagram: []const u8, now_us: u64) TransportError!void {
        const d = try mt.decodeDatagram(datagram);
        if (d.ack_vector) |v| for (v) |b| {
            // 2.2.1.1: only received / not yet received.
            const st = (try mt.unpackAckElement(b)).state;
            if (st != .received and st != .not_yet_received) return error.InvalidField;
        };
        if (e.closed) return;
        e.tick(now_us);
        e.last_heard_us = now_us;
        if (d.ack_vector) |v| try e.onAck(d.header, v, now_us);
        if (d.header.flags & mt.rdpudp_flag_cwr != 0) e.cn_active = false;
        if (d.ack_of_acks) |a| e.onAckOfAcks(a);
        if (d.source) |src| try e.onSource(src.sn_source_start, d.payload, now_us, false);
        if (d.fec) |f| try e.onFec(f, d.payload, now_us);
    }

    fn outAt(e: *Engine, off: u64) ?*Outstanding {
        if (off <= e.cum_off or off >= e.next_off) return null;
        return &e.outstanding.items[e.out_head + @as(usize, @intCast(off - e.cum_off - 1))];
    }

    /// 3.1.1.4, 3.1.1.7, 3.1.1.8; ACKs outside what was sent are ignored (5.1.1).
    fn onAck(e: *Engine, h: mt.FecHeader, elements: []const u8, now_us: u64) TransportError!void {
        const ack_off = offsetOf(e.cfg.initial_sequence_number, h.sn_source_ack, e.next_off - 1) orelse return;
        if (ack_off >= e.next_off) return;
        e.peer_window = h.receive_window_size;
        var newly_acked_top = false;
        var n: usize = 0;
        for (elements) |b| n += (mt.unpackAckElement(b) catch unreachable).length();
        // The vector ends at snSourceAck (3.1.1.4); what lies before it was received
        // (2.2.2.6), as Windows senders also assume.
        if (n > ack_off) e.stats_.ack_reach_before_first += 1;
        const first: u64 = if (n > ack_off) 1 else ack_off - n + 1;
        var off = e.cum_off + 1;
        while (off < first) : (off += 1) {
            if (e.outAt(off)) |o| if (!o.acked) {
                o.acked = true;
                if (off == ack_off) newly_acked_top = true;
            };
        }
        var i: usize = 0;
        for (elements) |b| {
            const el = mt.unpackAckElement(b) catch unreachable;
            const len = el.length();
            defer i += len;
            if (el.state != .received) continue;
            for (i..i + len) |k| {
                const back = n - 1 - k;
                if (back >= ack_off) continue;
                const at = ack_off - back;
                if (at <= e.cum_off) continue;
                if (e.outAt(at)) |o| if (!o.acked) {
                    o.acked = true;
                    if (at == ack_off) newly_acked_top = true;
                };
            }
        }
        // 3.1.6.1: RTT only from the newest packet, never a delayed ACK or a retransmission.
        if (newly_acked_top and h.flags & mt.rdpudp_flag_ackdelayed == 0) {
            if (e.outAt(ack_off)) |o| if (o.retransmits == 0 and now_us >= o.first_sent_us) e.addRttSample(now_us - o.first_sent_us);
        }
        e.detectLosses();
        e.advanceCumAcked();
        // 3.1.1.8: a CN on an ACK below the packet that carried the local CWR is stale.
        if (h.flags & mt.rdpudp_flag_cn != 0) {
            const stale = if (e.cwr_off) |c| ack_off < c else false;
            if (!stale) {
                e.cwr_due = true;
                e.congestionEvent();
            }
        }
    }

    fn addRttSample(e: *Engine, sample: u64) void {
        e.rto_backoff_us = 0;
        if (!e.rtt_known) {
            e.srtt_us = sample;
            e.rtt_known = true;
        } else {
            e.srtt_us = (7 * e.srtt_us + sample) / 8;
        }
    }

    /// 3.1.1.4.1: a packet is lost once three later ones were reported received.
    fn detectLosses(e: *Engine) void {
        const items = e.outstanding.items[e.out_head..];
        var later: usize = 0;
        var i = items.len;
        while (i > 0) {
            i -= 1;
            const o = &items[i];
            if (o.acked) {
                later += 1;
                continue;
            }
            if (later < 3 or o.given_up) continue;
            switch (e.cfg.mode) {
                .lossy => {
                    o.given_up = true;
                    e.congestionEvent();
                },
                .reliable => if (!o.fast_retransmitted) {
                    o.fast_retransmitted = true;
                    e.queueRetransmit(e.cum_off + 1 + i, o, false);
                    e.congestionEvent();
                },
            }
        }
    }

    fn queueRetransmit(e: *Engine, off: u64, o: *Outstanding, from_timer: bool) void {
        if (o.queued) {
            if (from_timer) o.timer_retransmit = true;
            return;
        }
        e.retx.append(e.gpa, off) catch return;
        o.queued = true;
        o.timer_retransmit = from_timer;
    }

    fn advanceCumAcked(e: *Engine) void {
        while (e.out_head < e.outstanding.items.len) {
            const o = e.outstanding.items[e.out_head];
            if (!o.acked and !o.given_up) break;
            if (o.acked) e.onDelivered();
            e.gpa.free(o.payload);
            e.out_head += 1;
            e.cum_off += 1;
        }
        if (e.out_head == e.outstanding.items.len) {
            e.outstanding.clearRetainingCapacity();
            e.out_head = 0;
        } else if (e.out_head > 1024 and e.out_head * 2 > e.outstanding.items.len) {
            const rest = e.outstanding.items.len - e.out_head;
            std.mem.copyForwards(Outstanding, e.outstanding.items[0..rest], e.outstanding.items[e.out_head..]);
            e.outstanding.shrinkRetainingCapacity(rest);
            e.out_head = 0;
        }
        if (e.recovery_off) |r| if (e.cum_off >= r) {
            e.recovery_off = null;
        };
    }

    /// Congestion control (3.1.1.8, NewReno-like).
    fn onDelivered(e: *Engine) void {
        if (e.cwnd < e.ssthresh) {
            e.cwnd += 1;
        } else {
            e.cwnd_credit += 1;
            if (e.cwnd_credit >= e.cwnd) {
                e.cwnd_credit = 0;
                e.cwnd += 1;
            }
        }
        e.cwnd = @min(e.cwnd, 1 << 16);
    }

    fn congestionEvent(e: *Engine) void {
        if (e.recovery_off != null) return;
        e.ssthresh = @max(e.cwnd / 2, min_congestion_window);
        e.cwnd = e.ssthresh;
        e.cwnd_credit = 0;
        e.recovery_off = e.next_off - 1;
    }

    fn slot(e: *Engine, off: u64) *Slot {
        return &e.ring[@intCast(off & (e.ring.len - 1))];
    }

    fn slotReceived(e: *Engine, off: u64) bool {
        const s = e.slot(off);
        return s.off == off and s.received;
    }

    /// 2.2.2.6: the peer has processed the local acknowledgements through snResetSeqNum.
    fn onAckOfAcks(e: *Engine, sn_reset: u32) void {
        const off = offsetOf(e.cfg.peer_initial_sequence_number, sn_reset, e.rx_high) orelse return;
        if (off > e.rx_high or off <= e.vec_start) return;
        e.vec_start = off;
    }

    /// 3.1.5.3.3: reliable, what the application read; lossy, what was handed up or given up.
    fn windowBase(e: *const Engine) u64 {
        return if (e.cfg.mode == .reliable) e.rx_read else e.rx_done;
    }

    /// Datagrams buffered and not read (3.1.5.3.4).
    fn unread(e: *const Engine) usize {
        return (e.ready.items.len - e.ready_head) + e.held;
    }

    fn advertisedWindow(e: *const Engine) u16 {
        const u = e.unread();
        return if (u >= e.cfg.receive_window_size) 0 else @intCast(e.cfg.receive_window_size - u);
    }

    fn onSource(e: *Engine, sn_source: u32, payload: []const u8, now_us: u64, recovered: bool) TransportError!void {
        const off = offsetOf(e.cfg.peer_initial_sequence_number, sn_source, e.rx_high) orelse 0;
        if (off == 0 or off > e.rx_high + e.ring.len) {
            e.stats_.out_of_window_dropped += 1;
            return;
        }
        if (off <= e.rx_done or (off <= e.rx_high and e.slotReceived(off))) {
            if (!recovered) {
                e.stats_.duplicates_dropped += 1;
                // Acknowledged at once (3.1.5.3.3): its ACK was lost, and a full window of such
                // datagrams would otherwise reach the sender's retransmit limit (3.1.5.4.1).
                e.ack_now = true;
            }
            return;
        }
        // 3.1.5.3.3: only the advertised window is accepted.
        const rws: u64 = e.cfg.receive_window_size;
        const base = e.windowBase();
        // Never reuse the slot of a datagram the application has not read.
        if (off - e.oldestUnread() >= e.ring.len) {
            e.stats_.out_of_window_dropped += 1;
            return;
        }
        if (off - base > rws) {
            const edge_ok = e.cfg.mode == .lossy and off - e.rx_done <= 2 * rws;
            if (!edge_ok) {
                e.stats_.out_of_window_dropped += 1;
                return;
            }
            // 3.1.1.1: a packet at the right edge gives up what is missing before it.
            e.slideTo(off - rws);
        }
        if (off - e.oldestUnread() >= e.ring.len) {
            e.stats_.out_of_window_dropped += 1;
            return;
        }
        // Copy first: on out of memory the datagram is as if lost, not marked received.
        const copy = try e.gpa.dupe(u8, payload);
        e.growTo(off);
        const s = e.slot(off);
        s.received = true;
        s.payload = copy;
        e.held += 1;
        if (recovered) e.stats_.fec_recovered += 1;
        e.deliverInOrder();
        if (e.cfg.mode == .lossy) {
            if (e.rx_done < e.rx_high) {
                if (e.reorder_deadline == null) e.reorder_deadline = now_us + e.cfg.reorder_timeout_us;
            } else e.reorder_deadline = null;
        }
        // 3.1.1.4: one ACK per ack_every Source Packets; the delayed ACK timer (3.1.6.3) covers the rest.
        e.unacked += 1;
        if (e.unacked >= e.cfg.ack_every) {
            e.ack_now = true;
        } else if (e.ack_deadline == null) {
            e.ack_deadline = now_us + (mt.delayedAckTimeoutUs(e.cfg.version, e.rttEstimate()) catch 200 * us_per_ms);
        }
        if (!e.cn_active) e.detectReceiveLoss();
    }

    fn growTo(e: *Engine, off: u64) void {
        const consumed = e.oldestUnread();
        while (e.rx_high < off) {
            e.rx_high += 1;
            const s = e.slot(e.rx_high);
            if (s.payload) |p| e.gpa.free(p);
            s.* = .{ .off = e.rx_high };
            // Read payloads stay for FEC recovery (3.1.1.6.3) only as far as a block reaches back.
            if (e.rx_high > fec_history) {
                const old = e.rx_high - fec_history;
                const o = e.slot(old);
                if (o.off == old and old <= consumed) if (o.payload) |p| {
                    e.gpa.free(p);
                    o.payload = null;
                };
            }
        }
        if (e.rx_high - e.vec_start >= e.ring.len) e.vec_start = e.rx_high - e.ring.len + 1;
    }

    fn oldestUnread(e: *const Engine) u64 {
        if (e.ready_head < e.ready.items.len) return e.ready.items[e.ready_head] - 1;
        return e.rx_done;
    }

    fn rttEstimate(e: *const Engine) u64 {
        return if (e.rtt_known) e.srtt_us else 0;
    }

    fn deliverInOrder(e: *Engine) void {
        while (e.rx_done < e.rx_high and e.slotReceived(e.rx_done + 1)) {
            e.rx_done += 1;
            e.held -= 1;
            e.ready.append(e.gpa, e.rx_done) catch {
                e.stats_.skipped += 1;
                continue;
            };
        }
    }

    /// RDP-UDP-L: gives up the missing datagrams up to `off`.
    fn slideTo(e: *Engine, off: u64) void {
        while (e.rx_done < off and e.rx_done < e.rx_high) {
            if (!e.slotReceived(e.rx_done + 1)) {
                e.rx_done += 1;
                e.stats_.skipped += 1;
            } else e.deliverInOrder();
        }
        if (e.rx_done < off) {
            e.stats_.skipped += off - e.rx_done;
            e.growTo(off);
            e.rx_done = off;
        }
        e.deliverInOrder();
    }

    /// 3.1.1.4.1 / 3.1.5.1.2: lost once three later ones arrived; sets RDPUDP_FLAG_CN until a CWR.
    fn detectReceiveLoss(e: *Engine) void {
        const lo = @max(e.vec_start, e.cn_marked);
        var later: usize = 0;
        var off = e.rx_high;
        while (off > lo) : (off -= 1) {
            if (e.slotReceived(off)) {
                later += 1;
            } else if (later >= 3) {
                e.cn_active = true;
                e.cn_marked = off;
                return;
            }
        }
    }

    /// 3.1.1.6.3: one missing Source Packet of the block is rebuilt.
    fn onFec(e: *Engine, f: mt.FecPayloadHeader, payload: []const u8, now_us: u64) TransportError!void {
        const first = offsetOf(e.cfg.peer_initial_sequence_number, f.sn_source_start, e.rx_high) orelse return;
        const count = @as(usize, f.range) + 1;
        if (count > fec.max_block) return;
        var srcs: [fec.max_block]?[]const u8 = undefined;
        var missing: ?usize = null;
        for (0..count) |i| {
            const off = first + i;
            if (off == 0) return;
            const s = e.slot(off);
            if (off <= e.rx_high and s.off == off and s.received) {
                srcs[i] = s.payload orelse return;
            } else {
                if (missing != null) return; // two missing: nothing to do
                missing = i;
                srcs[i] = null;
            }
        }
        const m = missing orelse return;
        const lost_off = first + m;
        if (lost_off <= e.rx_done) return; // given up already
        var buf: [mt.max_mtu]u8 = undefined;
        const got = fec.recover(payload, f.fec_index, f.sn_source_start, srcs[0..count], &buf) catch return;
        try e.onSource(e.cfg.peer_initial_sequence_number +% @as(u32, @truncate(lost_off)), got, now_us, true);
    }

    // -- sending -------------------------------------------------------------

    fn hasNewData(e: *const Engine) bool {
        return e.unsent_head < e.unsent.items.len;
    }

    fn inFlight(e: *const Engine) usize {
        var n: usize = 0;
        for (e.outstanding.items[e.out_head..]) |o| {
            if (!o.acked and !o.given_up) n += 1;
        }
        return n;
    }

    /// Peer receive window (3.1.1.7) and congestion window (3.1.1.8).
    fn canSendNew(e: *const Engine) bool {
        if (!e.hasNewData()) return false;
        if (e.next_off - e.cum_off > e.peer_window) return false;
        return e.inFlight() < e.cwnd;
    }

    fn fecDue(e: *const Engine) bool {
        return e.cfg.fec_block_size != 0 and e.fec_block.items.len >= e.cfg.fec_block_size;
    }

    fn ackDue(e: *const Engine, now_us: u64) bool {
        if (e.ack_now) return true;
        if (e.ack_deadline) |t| return now_us >= t;
        return false;
    }

    /// Retransmit (3.1.6.1), RDP-UDP-L reordering (3.1.1.1), keepalive time-out (3.1.6.2).
    fn runTimers(e: *Engine, now_us: u64) void {
        if (now_us >= e.last_heard_us + mt.keepalive_timeout_us) {
            e.closeFor(.keepalive_timeout);
            return;
        }
        if (e.reorder_deadline) |t| if (now_us >= t) {
            e.reorder_deadline = null;
            e.slideTo(e.rx_high);
        };
        var gave_up = false;
        for (e.outstanding.items[e.out_head..], 0..) |*o, i| {
            if (o.acked or o.given_up or o.queued or now_us < o.timer_at_us) continue;
            switch (e.cfg.mode) {
                .lossy => {
                    o.given_up = true;
                    gave_up = true;
                },
                .reliable => {
                    if (o.retransmits >= e.cfg.max_retransmits) {
                        // 3.1.5.4.1: retransmit limit.
                        e.closeFor(.{ .retransmit_limit = .{ .offset = e.cum_off + 1 + i, .retransmits = o.retransmits } });
                        return;
                    }
                    e.queueRetransmit(e.cum_off + 1 + i, o, true);
                },
            }
        }
        if (gave_up) e.advanceCumAcked();
    }

    /// The next datagram to send, or null; runs the timers due by `now_us` first.
    pub fn poll(e: *Engine, now_us: u64, out: []u8) TransportError!?[]u8 {
        if (e.closed) return null;
        e.tick(now_us);
        e.runTimers(now_us);
        if (e.closed) return null;
        if (e.ack_cut) return try e.emit(.{ .delayed = false }, now_us, out);
        while (e.retx.items.len > 0) {
            const off = e.retx.orderedRemove(0);
            const o = e.outAt(off) orelse continue;
            o.queued = false;
            if (o.acked or o.given_up) continue;
            return try e.sendSource(off, o, true, now_us, out);
        }
        if (e.fecDue()) return try e.sendFec(now_us, out);
        if (e.canSendNew()) {
            // Room first: out of memory, the data stays queued as it was.
            try e.outstanding.ensureUnusedCapacity(e.gpa, 1);
            const payload = e.unsent.items[e.unsent_head];
            e.unsent_head += 1;
            if (e.unsent_head == e.unsent.items.len) {
                e.unsent.clearRetainingCapacity();
                e.unsent_head = 0;
            }
            const off = e.next_off;
            const rto = @max(mt.retransmitTimeoutUs(e.cfg.version, e.rttEstimate()) catch unreachable, e.rto_backoff_us);
            e.outstanding.appendAssumeCapacity(.{ .payload = payload, .first_sent_us = now_us, .timer_at_us = now_us + rto, .rto_us = rto });
            e.next_off += 1;
            e.stats_.source_sent += 1;
            if (e.cfg.fec_block_size != 0) {
                if (e.fec_block.items.len == 0) e.fec_block_off = off;
                try e.fec_block.append(e.gpa, try e.gpa.dupe(u8, payload));
            }
            const o = e.outAt(off).?;
            return try e.sendSource(off, o, false, now_us, out);
        }
        if (e.ackDue(now_us)) return try e.emit(.{ .delayed = !e.ack_now }, now_us, out);
        if (now_us >= e.last_sent_us + e.cfg.keepalive_interval_us) return try e.emit(.{ .delayed = false }, now_us, out);
        return null;
    }

    const Body = union(enum) {
        /// ACK-only; RDPUDP_FLAG_ACKDELAYED when the delayed ACK timer fired.
        delayed: bool,
        source: struct { off: u64, payload: []const u8, cwr: bool },
        fec: struct { header: mt.FecPayloadHeader, payload: []const u8 },
    };

    fn sendSource(e: *Engine, off: u64, o: *Outstanding, retransmit: bool, now_us: u64, out: []u8) TransportError![]u8 {
        var cwr = false;
        if (retransmit) {
            o.retransmits += 1;
            e.stats_.retransmits += 1;
            if (o.timer_retransmit) {
                // 3.1.6.1: the time-out doubles; 3.1.1.8: a timer retransmission carries CWR.
                o.rto_us = @min(o.rto_us * 2, max_rto_us);
                e.rto_backoff_us = @max(e.rto_backoff_us, o.rto_us);
                cwr = true;
            }
            o.timer_at_us = now_us + o.rto_us;
            o.timer_retransmit = false;
        }
        if (e.cwr_due) cwr = true;
        if (cwr) {
            e.cwr_due = false;
            e.cwr_off = off;
        }
        e.since_ack_of_acks += 1;
        return e.emit(.{ .source = .{ .off = off, .payload = o.payload, .cwr = cwr } }, now_us, out);
    }

    fn sendFec(e: *Engine, now_us: u64, out: []u8) TransportError![]u8 {
        defer {
            for (e.fec_block.items) |b| e.gpa.free(b);
            e.fec_block.clearRetainingCapacity();
        }
        const n: u32 = @intCast(e.fec_block.items.len);
        const s1 = e.cfg.initial_sequence_number +% @as(u32, @truncate(e.fec_block_off));
        const sn = s1 +% (n - 1);
        e.fec_index = try fec.nextFecIndex(e.fec_index, s1, sn);
        var buf: [mt.max_mtu + 2]u8 = undefined;
        const payload = try fec.encode(e.fec_block.items, e.fec_index, s1, &buf);
        e.stats_.fec_sent += 1;
        return e.emit(.{ .fec = .{ .header = .{ .sn_coded = 0, .sn_source_start = s1, .range = @intCast(n - 1), .fec_index = e.fec_index }, .payload = payload } }, now_us, out);
    }

    /// ACK vector over (vec_start, rx_high]; when cut to `max_elements`, the newest states are
    /// left out, as Windows does. `last` is the newest offset reported (snSourceAck).
    fn ackVector(e: *Engine, buf: []u8, max_elements: usize) struct { elements: []u8, last: u64, complete: bool } {
        const limit = @min(max_elements, buf.len);
        var n: usize = 0;
        var off = e.vec_start;
        while (off < e.rx_high) {
            if (n == limit) {
                // snSourceAck must name a received datagram.
                if (n > 0 and buf[n - 1] >> 6 == @backingInt(mt.ElementState.not_yet_received)) {
                    n -= 1;
                    off -= @intCast((mt.unpackAckElement(buf[n]) catch unreachable).length());
                }
                return .{ .elements = buf[0..n], .last = off, .complete = false };
            }
            const st: mt.ElementState = if (e.slotReceived(off + 1)) .received else .not_yet_received;
            var len: u32 = 1;
            while (len < mt.max_ack_run and off + len < e.rx_high) {
                const st2: mt.ElementState = if (e.slotReceived(off + len + 1)) .received else .not_yet_received;
                if (st2 != st) break;
                len += 1;
            }
            buf[n] = mt.packAckElement(.{ .state = st, .count = @intCast(len) }) catch unreachable;
            n += 1;
            off += len;
        }
        return .{ .elements = buf[0..n], .last = e.rx_high, .complete = true };
    }

    /// Most elements an RDPUDP_ACK_VECTOR_HEADER of at most `room` bytes holds.
    fn elementsFitting(room: usize) usize {
        if (room < 4) return 0;
        var n = @min(room - 2, max_vector);
        while (n > 0 and mt.ackVectorHeaderSize(n) > room) n -= 1;
        return n;
    }

    /// Every datagram acknowledges (3.1.5.1.2); an ACK of ACKs every 20 Source Packets (2.2.2.6).
    fn emit(e: *Engine, body: Body, now_us: u64, out: []u8) TransportError![]u8 {
        var flags: u16 = mt.rdpudp_flag_ack;
        if (e.cn_active) flags |= mt.rdpudp_flag_cn;
        var d = mt.Datagram{ .header = .{
            .sn_source_ack = e.cfg.peer_initial_sequence_number +% @as(u32, @truncate(e.rx_high)),
            .receive_window_size = e.advertisedWindow(),
            .flags = 0,
        } };
        if (e.since_ack_of_acks >= mt.ack_of_acks_interval) {
            d.ack_of_acks = e.cfg.initial_sequence_number +% @as(u32, @truncate(e.cum_off));
            flags |= mt.rdpudp_flag_ack_of_acks;
        }
        switch (body) {
            .delayed => |delayed| if (delayed) {
                flags |= mt.rdpudp_flag_ackdelayed;
            },
            .source => |s| {
                flags |= mt.rdpudp_flag_data;
                if (s.cwr) flags |= mt.rdpudp_flag_cwr;
                d.source = .{ .sn_coded = e.next_coded, .sn_source_start = e.cfg.initial_sequence_number +% @as(u32, @truncate(s.off)) };
                d.payload = s.payload;
            },
            .fec => |f| {
                flags |= mt.rdpudp_flag_data | mt.rdpudp_flag_fec;
                var h = f.header;
                h.sn_coded = e.next_coded;
                d.fec = h;
                d.payload = f.payload;
            },
        }
        d.header.flags = flags;
        d.ack_vector = &.{};
        const fixed = mt.datagramSize(d) - mt.ackVectorHeaderSize(0);
        const mtu: usize = e.cfg.mtu;
        if (fixed + 4 > mtu or fixed > out.len) return error.MessageTooLarge;
        const room = @min(mtu, out.len) - fixed;
        var vec_buf: [max_vector]u8 = undefined;
        const v = e.ackVector(&vec_buf, elementsFitting(room));
        d.ack_vector = v.elements;
        d.header.sn_source_ack = e.cfg.peer_initial_sequence_number +% @as(u32, @truncate(v.last));
        const wire = try mt.encodeDatagramInto(d, out);
        if (body != .delayed) e.next_coded +%= 1;
        if (d.ack_of_acks != null) e.since_ack_of_acks = 0;
        e.last_sent_us = now_us;
        e.last_advertised = d.header.receive_window_size;
        // A data datagram with a cut vector: an ACK-only datagram with all of it goes next.
        if (v.complete or body == .delayed) {
            e.unacked = 0;
            e.ack_deadline = null;
            e.ack_now = false;
            e.ack_cut = false;
        } else {
            e.ack_now = true;
            e.ack_cut = true;
        }
        return wire;
    }

    /// The next application datagram (lossy) or stream chunk (reliable), in order.
    pub fn receive(e: *Engine, out: []u8) TransportError!?[]u8 {
        if (e.closed) return null;
        if (e.ready_head == e.ready.items.len) return null;
        const off = e.ready.items[e.ready_head];
        const s = e.slot(off);
        const p = if (s.off == off) s.payload orelse &[_]u8{} else &[_]u8{};
        if (out.len < p.len) return error.EndOfBuffer;
        @memcpy(out[0..p.len], p);
        e.ready_head += 1;
        if (e.ready_head == e.ready.items.len) {
            e.ready.clearRetainingCapacity();
            e.ready_head = 0;
        }
        if (e.cfg.mode == .reliable) e.rx_read = off;
        e.stats_.delivered += 1;
        // Window update (RFC 1122 4.2.3.3), so the sender need not wait for a keepalive (3.1.1.7).
        const w = e.advertisedWindow();
        const half = @max(e.cfg.receive_window_size / 2, 1);
        if (w > e.last_advertised and (e.last_advertised == 0 or w - e.last_advertised >= half)) e.ack_now = true;
        return out[0..p.len];
    }

    /// When poll() has something to do next (null: nothing scheduled).
    pub fn nextTimeout(e: *const Engine) TransportError!?u64 {
        if (e.closed or !e.started) return null;
        var t = e.last_heard_us + mt.keepalive_timeout_us;
        t = @min(t, e.last_sent_us + e.cfg.keepalive_interval_us);
        if (e.ack_now or e.retx.items.len > 0 or e.fecDue() or e.canSendNew()) t = @min(t, e.last_now);
        if (e.ack_deadline) |d| t = @min(t, d);
        if (e.reorder_deadline) |d| t = @min(t, d);
        for (e.outstanding.items[e.out_head..]) |o| {
            if (o.acked or o.given_up or o.queued) continue;
            t = @min(t, o.timer_at_us);
        }
        return t;
    }

    pub fn state(e: *const Engine) TransportError!ConnState {
        return if (e.closed) .closed else .established;
    }

    pub fn closeReason(e: *const Engine) ?mt.CloseReason {
        return e.close_reason;
    }

    fn closeFor(e: *Engine, why: mt.CloseReason) void {
        e.closed = true;
        if (e.close_reason == null) e.close_reason = why;
    }

    /// User-initiated termination (3.1.4.4).
    pub fn close(e: *Engine) TransportError!void {
        e.closeFor(.closed_locally);
    }

    /// Largest lossy write: the MTU minus the Source Packet, two-element ACK vector,
    /// ACK of ACKs and (with FEC) FEC payload headers.
    pub fn maxPayload(e: *const Engine) TransportError!usize {
        var overhead: usize = mt.fec_header_size + mt.ackVectorHeaderSize(reserved_vector_elements) + mt.ack_of_acks_size;
        overhead += if (e.cfg.fec_block_size != 0) mt.fec_payload_header_size + 2 else mt.source_header_size;
        return e.cfg.mtu - overhead;
    }

    /// Bytes accepted now without waiting for the congestion (3.1.1.8) or peer receive
    /// (3.1.1.7) window; 0 once Closed.
    pub fn sendRoom(e: *const Engine) usize {
        if (e.closed) return 0;
        const payload = e.maxPayload() catch return 0;
        const queued = e.unsent.items.len - e.unsent_head;
        const by_cwnd = e.cwnd -| (e.inFlight() + queued);
        const by_peer = @as(usize, e.peer_window) -| (@as(usize, e.next_off - e.cum_off) + queued);
        return @min(by_cwnd, by_peer) *| payload;
    }

    /// Bytes queued and not yet sent once.
    pub fn unsentBytes(e: *const Engine) usize {
        var n: usize = 0;
        for (e.unsent.items[e.unsent_head..]) |u| n +|= u.len;
        return n;
    }

    /// B/s the congestion window allows per smoothed RTT; null before an RTT sample.
    pub fn windowRate(e: *const Engine) ?f64 {
        if (!e.rtt_known or e.srtt_us == 0) return null;
        const payload = e.maxPayload() catch return null;
        const window: f64 = @floatFromInt(@min(e.cwnd, @as(usize, e.peer_window)));
        return window * @as(f64, @floatFromInt(payload)) * 1e6 / @as(f64, @floatFromInt(e.srtt_us));
    }

    pub fn stats(e: *const Engine) TransportError!EngineStats {
        var s = e.stats_;
        s.in_flight = e.inFlight();
        return s;
    }
};

/// The offset from `isn` of `sn` nearest to `reference`, across wrap (3.1.1.2); null before the ISN.
fn offsetOf(isn: u32, sn: u32, reference: u64) ?u64 {
    const delta: i32 = @bitCast((sn -% isn) -% @as(u32, @truncate(reference)));
    if (delta >= 0) return reference + @as(u32, @intCast(delta));
    return std.math.sub(u64, reference, @abs(delta)) catch null;
}

test "offsetOf: the offset nearest to the reference, across sequence number wrap" {
    try std.testing.expectEqual(@as(?u64, 1), offsetOf(5, 6, 0));
    try std.testing.expectEqual(@as(?u64, 0), offsetOf(5, 5, 0));
    try std.testing.expectEqual(@as(?u64, null), offsetOf(5, 4, 0)); // before the ISN
    const far: u64 = (1 << 32) + 10; // offsets past 2^32: sn has wrapped
    try std.testing.expectEqual(@as(?u64, far + 3), offsetOf(0xffff_fff0, 0xffff_fff0 +% 13, far));
    try std.testing.expectEqual(@as(?u64, far - 20), offsetOf(0xffff_fff0, 0xffff_fff0 +% @as(u32, @truncate(far - 20)), far));
    try std.testing.expectEqual(@as(?u64, (1 << 32) - 1), offsetOf(7, @as(u32, 7) +% 0xffff_ffff, (1 << 32) + 2));
}

test "payloads read by the application are kept only for the FEC horizon" {
    const gpa = std.testing.allocator;
    var e = try Engine.init(gpa, .{ .mode = .reliable, .initial_sequence_number = 1, .peer_initial_sequence_number = 100, .receive_window_size = 1024 });
    defer e.deinit();
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    for (1..2001) |i| {
        const d = try mt.encodeDatagramInto(.{
            .header = .{ .sn_source_ack = 1, .receive_window_size = 64, .flags = mt.rdpudp_flag_ack | mt.rdpudp_flag_data },
            .ack_vector = &.{},
            .source = .{ .sn_coded = 100 + @as(u32, @intCast(i)), .sn_source_start = 100 + @as(u32, @intCast(i)) },
            .payload = "payload",
        }, &buf);
        try e.onDatagram(d, i);
        try std.testing.expectEqualStrings("payload", (try e.receive(&out)).?);
    }
    var kept: usize = 0;
    for (e.ring) |s| {
        if (s.payload != null) kept += 1;
    }
    try std.testing.expect(kept <= fec_history + 1);
}

/// A Source Packet from the peer (ISN 100) with `payload`, as a datagram.
fn peerSource(buf: []u8, sn: u32, payload: []const u8) ![]u8 {
    return mt.encodeDatagramInto(.{
        .header = .{ .sn_source_ack = 1, .receive_window_size = 64, .flags = mt.rdpudp_flag_ack | mt.rdpudp_flag_data },
        .ack_vector = &.{},
        .source = .{ .sn_coded = sn, .sn_source_start = sn },
        .payload = payload,
    }, buf);
}

test "a Source Packet that cannot be kept (out of memory) is as if lost: the rest is delivered in order, nothing miscounted" {
    var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var e = try Engine.init(fa.allocator(), .{ .mode = .reliable, .initial_sequence_number = 1, .peer_initial_sequence_number = 100 });
    defer e.deinit();
    var buf: [64]u8 = undefined;
    fa.fail_index = fa.alloc_index; // its copy
    try std.testing.expectError(error.OutOfMemory, e.onDatagram(try peerSource(&buf, 101, "a"), 1));
    fa.fail_index = std.math.maxInt(usize);
    try e.onDatagram(try peerSource(&buf, 102, "b"), 2);
    try e.onDatagram(try peerSource(&buf, 101, "a"), 3); // sent again
    var out: [8]u8 = undefined;
    try std.testing.expectEqualStrings("a", (try e.receive(&out)).?);
    try std.testing.expectEqualStrings("b", (try e.receive(&out)).?);
    try std.testing.expectEqual(@as(usize, 0), e.held);
}

test "data that cannot be put in flight (out of memory) stays queued and goes out on the next poll" {
    var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var e = try Engine.init(fa.allocator(), .{ .mode = .reliable, .initial_sequence_number = 1, .peer_initial_sequence_number = 100 });
    defer e.deinit();
    try e.send("data");
    var out: [mt.max_mtu]u8 = undefined;
    fa.fail_index = fa.alloc_index; // room for it in flight
    try std.testing.expectError(error.OutOfMemory, e.poll(1, &out));
    fa.fail_index = std.math.maxInt(usize);
    const d = try mt.decodeDatagram((try e.poll(2, &out)).?);
    try std.testing.expectEqual(@as(u32, 2), d.source.?.sn_source_start);
    try std.testing.expectEqualStrings("data", d.payload);
}
