//! MS-RDPEUDP2 version 3 data transfer: packet layout, network format, ACKs, the
//! Sender/Receiver windows with loss detection, reliability controllers and the Endpoint.
//! Multi-byte fields are little-endian (2.2); sub-byte fields start at the LSB.

const std = @import("std");
const bytes = @import("../../core/bytes.zig");
const mt = @import("../multitransport.zig");

const TransportError = mt.TransportError;
const ConnState = mt.ConnState;
const us_per_ms = mt.us_per_ms;
const us_per_s = mt.us_per_s;

/// Scratch for encodeAckVector; the root module may supply `omastation_scratch_allocator`.
const scratch_allocator: std.mem.Allocator = if (@hasDecl(@import("root"), "omastation_scratch_allocator"))
    @import("root").omastation_scratch_allocator
else
    std.heap.page_allocator;

/// 2.2.1.1 Flags.
pub const flag_ack: u12 = 0x001;
pub const flag_data: u12 = 0x004;
pub const flag_ackvec: u12 = 0x008;
pub const flag_aoa: u12 = 0x010;
pub const flag_overheadsize: u12 = 0x040;
pub const flag_delayackinfo: u12 = 0x100;
pub const known_flags: u12 = flag_ack | flag_data | flag_ackvec | flag_aoa | flag_overheadsize | flag_delayackinfo;

/// 3.1.1.1.3: LogWindowSize is at most 15.
pub const max_log_window_size: u4 = 15;
/// 1.3: the RDP-UDP2 MTU.
pub const mtu: u16 = 1232;
/// 3.1.5.2: MaxDelayedAcks is at most 15; 8 until the first DelayAckInfo.
pub const max_delayed_acks_limit: u8 = 15;
pub const default_max_delayed_acks: u8 = 8;
pub const max_coded_ack_vec_size: usize = 127;
/// 2.2.1.2.6: SendAckTimeGapInMs 255 means invalid.
pub const send_ack_time_gap_invalid: u8 = 255;
/// 2.2.1.2.1 / 3.1.1.1.4: timestamps count 4 µs units.
pub const timestamp_unit_us: u64 = 4;
/// 3.1.1.1.4 step 5: more than 32 s after the reference is invalid.
pub const max_timestamp_lead_us: u64 = 32 * us_per_s;
/// 3.1.1.3: no keepalive from the peer for 16 s: Closed.
pub const keepalive_timeout_us: u64 = 16 * us_per_s;
/// 3.1.1.3 <2>, 3.1.2 <3>: Windows sends keepalives every 4 s.
pub const windows_keepalive_interval_us: u64 = 4 * us_per_s;
/// 2.2.1.3 Packet_Type_Index.
pub const packet_type_data: u4 = 0;
pub const packet_type_dummy: u4 = 8;

// -- 2.2.1 packet layout -------------------------------------------------

/// 2.2.1.1 header (a little-endian u16).
pub const Header = struct { flags: u12, log_window_size: u4 };

fn checkFlags(f: u12) TransportError!void {
    // 2.2.1.1, 3.1.1.1.2: at least one known flag, never ACK with ACKVEC.
    if (f == 0 or f & ~known_flags != 0) return error.InvalidField;
    if (f & flag_ack != 0 and f & flag_ackvec != 0) return error.InvalidField;
}

pub fn packHeader(h: Header) TransportError!u16 {
    try checkFlags(h.flags);
    return @as(u16, h.flags) | @as(u16, h.log_window_size) << 12;
}

pub fn unpackHeader(v: u16) TransportError!Header {
    const h = Header{ .flags = @truncate(v), .log_window_size = @intCast(v >> 12) };
    try checkFlags(h.flags);
    return h;
}

/// 2.2.1.2.1 Acknowledgement payload.
pub const Ack = struct {
    /// Low 16 bits of the newest sequence number acknowledged.
    seq_num: u16,
    /// Low 24 bits of its reception time in 4 µs units.
    received_ts: u24,
    /// Milliseconds between that reception and this ACK.
    send_ack_time_gap: u8,
    delay_ack_time_scale: u4 = 0,
    /// Reception gaps, newest first, in 1 << delay_ack_time_scale µs units (at most 15).
    delay_ack_time_additions: []const u8 = &.{},
};

/// 2.2.1.2.3 DelayAckInfo payload.
pub const DelayAckInfo = struct { max_delayed_acks: u8, delayed_ack_timeout_ms: u16 };

/// 2.2.1.2.6 optional TimeStamp + SendAckTimeGapInMs.
pub const AckVecTimestamp = struct { timestamp: u24, send_ack_time_gap_ms: u8 };

/// 2.2.1.2.6 Acknowledgement Vector payload.
pub const AckVector = struct {
    base_seq_num: u16,
    timestamp: ?AckVecTimestamp = null,
    coded: []const u8,
};

/// 2.2.1.2.5 DataHeader + 2.2.1.2.7 DataBody.
pub const Data = struct { seq_num: u16, channel_seq_num: u16, payload: []const u8 };

/// 2.2.1 Packet Layout; the header flags follow from the payloads present. Wire order:
/// Header, ACK, OverheadSize, DelayAckInfo, AckOfAcks, DataHeader, ACKVEC, DataBody.
pub const Packet = struct {
    log_window_size: u4,
    ack: ?Ack = null,
    overhead_size: ?u8 = null,
    delay_ack_info: ?DelayAckInfo = null,
    ack_of_acks: ?u16 = null,
    ack_vector: ?AckVector = null,
    data: ?Data = null,
};

pub fn flagsOf(p: Packet) TransportError!u12 {
    var f: u12 = 0;
    if (p.ack != null) f |= flag_ack;
    if (p.data != null) f |= flag_data;
    if (p.ack_vector != null) f |= flag_ackvec;
    if (p.ack_of_acks != null) f |= flag_aoa;
    if (p.overhead_size != null) f |= flag_overheadsize;
    if (p.delay_ack_info != null) f |= flag_delayackinfo;
    try checkFlags(f);
    return f;
}

fn packetSize(p: Packet) TransportError!usize {
    _ = try flagsOf(p);
    var n: usize = 2;
    if (p.ack) |a| {
        if (a.delay_ack_time_additions.len > 15) return error.InvalidField;
        n += 7 + a.delay_ack_time_additions.len;
    }
    if (p.overhead_size != null) n += 1;
    if (p.delay_ack_info) |d| {
        if (d.max_delayed_acks > max_delayed_acks_limit) return error.InvalidField;
        n += 3;
    }
    if (p.ack_of_acks != null) n += 2;
    if (p.ack_vector) |v| {
        if (v.coded.len > max_coded_ack_vec_size) return error.InvalidField;
        n += 3 + v.coded.len + @as(usize, if (v.timestamp != null) 4 else 0);
    }
    if (p.data) |d| n += 4 + d.payload.len;
    return n;
}

/// error.InvalidField when the packet exceeds a 2.2.1 field limit.
pub fn encodePacket(w: *bytes.Writer, p: Packet) !void {
    const n = try packetSize(p);
    const start = w.len();
    try w.zeros(n);
    _ = try encodePacketInto(p, w.list.items[start..][0..n]);
}

/// encodePacket into a fixed buffer (error.EndOfBuffer when too small).
pub fn encodePacketInto(p: Packet, out: []u8) TransportError![]u8 {
    const n = try packetSize(p);
    if (out.len < n) return error.EndOfBuffer;
    var c = mt.Cursor{ .buf = out };
    c.le16(try packHeader(.{ .flags = try flagsOf(p), .log_window_size = p.log_window_size }));
    if (p.ack) |a| {
        c.le16(a.seq_num);
        c.le24(a.received_ts);
        c.byte(a.send_ack_time_gap);
        c.byte(@as(u8, @intCast(a.delay_ack_time_additions.len)) | @as(u8, a.delay_ack_time_scale) << 4);
        c.slice(a.delay_ack_time_additions);
    }
    if (p.overhead_size) |o| c.byte(o);
    if (p.delay_ack_info) |d| {
        c.byte(d.max_delayed_acks);
        c.le16(d.delayed_ack_timeout_ms);
    }
    if (p.ack_of_acks) |a| c.le16(a);
    if (p.data) |d| c.le16(d.seq_num);
    if (p.ack_vector) |v| {
        c.le16(v.base_seq_num);
        c.byte(@as(u8, @intCast(v.coded.len)) | @as(u8, if (v.timestamp != null) 0x80 else 0));
        if (v.timestamp) |t| {
            c.le24(t.timestamp);
            c.byte(t.send_ack_time_gap_ms);
        }
        c.slice(v.coded);
    }
    if (p.data) |d| {
        c.le16(d.channel_seq_num);
        c.slice(d.payload);
    }
    return out[0..c.n];
}

fn readU24(r: *bytes.Reader) bytes.Error!u24 {
    const b = try r.bytes(3);
    return std.mem.readInt(u24, b[0..3], .little);
}

/// Slices point into `layout`. Bytes left over without DATA: error.BadDatagram (MS-RDPEUDP 5.1.2).
pub fn decodePacket(layout: []const u8) TransportError!Packet {
    var r = bytes.Reader.init(layout);
    const h = try unpackHeader(try r.u16le());
    const f = h.flags;
    var p = Packet{ .log_window_size = h.log_window_size };
    if (f & flag_ack != 0) {
        const seq = try r.u16le();
        const ts = try readU24(&r);
        const gap = try r.byte();
        const b = try r.byte();
        p.ack = .{ .seq_num = seq, .received_ts = ts, .send_ack_time_gap = gap, .delay_ack_time_scale = @intCast(b >> 4), .delay_ack_time_additions = try r.bytes(b & 0x0f) };
    }
    if (f & flag_overheadsize != 0) p.overhead_size = try r.byte();
    if (f & flag_delayackinfo != 0) {
        const m = try r.byte();
        const t = try r.u16le();
        if (m > max_delayed_acks_limit) return error.InvalidField;
        p.delay_ack_info = .{ .max_delayed_acks = m, .delayed_ack_timeout_ms = t };
    }
    if (f & flag_aoa != 0) p.ack_of_acks = try r.u16le();
    var data_seq: u16 = 0;
    if (f & flag_data != 0) data_seq = try r.u16le();
    if (f & flag_ackvec != 0) {
        const base = try r.u16le();
        const b = try r.byte();
        var v = AckVector{ .base_seq_num = base, .coded = &.{} };
        if (b & 0x80 != 0) {
            const ts = try readU24(&r);
            v.timestamp = .{ .timestamp = ts, .send_ack_time_gap_ms = try r.byte() };
        }
        v.coded = try r.bytes(b & 0x7f);
        p.ack_vector = v;
    }
    if (f & flag_data != 0) {
        const ch = try r.u16le();
        p.data = .{ .seq_num = data_seq, .channel_seq_num = ch, .payload = r.rest() };
    } else if (r.remaining() != 0) return error.BadDatagram;
    return p;
}

// -- 2.2.1.3 / 3.1.1.1.5 network format -----------------------------------

pub const PacketPrefix = struct { packet_type_index: u4 = packet_type_data, short_packet_length: u3 };

fn checkPacketType(t: u4) TransportError!void {
    if (t != packet_type_data and t != packet_type_dummy) return error.InvalidField;
}

pub fn packPrefix(p: PacketPrefix) TransportError!u8 {
    try checkPacketType(p.packet_type_index);
    return @as(u8, p.packet_type_index) << 1 | @as(u8, p.short_packet_length) << 5;
}

/// error.InvalidField: Reserved set or a Packet_Type_Index other than 0 or 8.
pub fn unpackPrefix(b: u8) TransportError!PacketPrefix {
    if (b & 1 != 0) return error.InvalidField;
    const t: u4 = @truncate(b >> 1);
    try checkPacketType(t);
    return .{ .packet_type_index = t, .short_packet_length = @intCast(b >> 5) };
}

/// 3.1.1.1.5: Short_Packet_Length is the layout length below 7, else 7.
pub fn prefixFor(layout_len: usize, packet_type_index: u4) TransportError!PacketPrefix {
    try checkPacketType(packet_type_index);
    return .{ .packet_type_index = packet_type_index, .short_packet_length = @intCast(@min(layout_len, 7)) };
}

/// 3.1.1.1.5.1 steps 2-4: zero-pad to 7 bytes, prefix the byte, swap bytes 0 and 7.
/// Writes max(len, 7) + 1 bytes.
pub fn wrapWithPrefix(prefix: u8, layout: []const u8, out: []u8) TransportError![]u8 {
    const n = @max(layout.len, 7) + 1;
    if (out.len < n) return error.EndOfBuffer;
    // `layout` may already sit at out[1..] (the endpoint encodes in place).
    std.mem.copyBackwards(u8, out[1 .. 1 + layout.len], layout);
    out[0] = prefix;
    @memset(out[1 + layout.len .. n], 0);
    std.mem.swap(u8, &out[0], &out[7]);
    return out[0..n];
}

/// 3.1.1.1.5.1.
pub fn toWire(layout: []const u8, packet_type_index: u4, out: []u8) TransportError![]u8 {
    return wrapWithPrefix(try packPrefix(try prefixFor(layout.len, packet_type_index)), layout, out);
}

pub const Unwrapped = struct { prefix: PacketPrefix, layout: []const u8 };

/// 3.1.1.1.5.2: swap bytes 0 and 7 (in `scratch`), strip the prefix byte and padding.
/// A datagram of 7 bytes or fewer: error.BadDatagram.
pub fn fromWire(datagram: []const u8, scratch: []u8) TransportError!Unwrapped {
    if (datagram.len <= 7) return error.BadDatagram;
    if (scratch.len < datagram.len) return error.EndOfBuffer;
    const s = scratch[0..datagram.len];
    @memcpy(s, datagram);
    std.mem.swap(u8, &s[0], &s[7]);
    const prefix = try unpackPrefix(s[0]);
    var layout = s[1..];
    if (prefix.short_packet_length != 0) layout = layout[0 .. layout.len - (7 - @as(usize, prefix.short_packet_length))];
    return .{ .prefix = prefix, .layout = layout };
}

// -- 3.1.1.1.3 / 3.1.1.1.4 reconstruction ---------------------------------

/// 3.1.1.1.3: the sequence number with low bits `low16` nearest to `reference`.
/// Never wraps below 0 or above 2^64 - 1.
pub fn expandSeqNum(reference: u64, low16: u16) TransportError!u64 {
    const cand = (reference & ~@as(u64, 0xffff)) | low16;
    if (cand > reference and cand - reference > 0x8000) {
        if (cand >= 0x10000) return cand - 0x10000;
    } else if (reference > cand and reference - cand > 0x8000) {
        if (cand <= std.math.maxInt(u64) - 0x10000) return cand + 0x10000;
    }
    return cand;
}

/// 3.1.1.1.4: the low 24 bits of `time_us` in 4 µs units.
pub fn codeTimestamp(time_us: u64) TransportError!u24 {
    return @truncate(time_us / timestamp_unit_us);
}

/// 3.1.1.1.4 steps 1-5: the timestamp (µs) of `coded` nearest to `reference_us`; null
/// when more than 32 s after the reference.
pub fn expandTimestamp(reference_us: u64, coded: u24) TransportError!?u64 {
    const ref_u = reference_us / timestamp_unit_us;
    var cand = (ref_u & ~@as(u64, 0xffffff)) | coded;
    if (cand > ref_u and cand - ref_u > 0x800000) {
        if (cand >= 0x1000000) cand -= 0x1000000;
    } else if (ref_u > cand and ref_u - cand > 0x800000) {
        if (cand <= std.math.maxInt(u64) - 0x1000000) cand += 0x1000000;
    }
    const t = std.math.mul(u64, cand, timestamp_unit_us) catch return null;
    if (t > reference_us and t - reference_us > max_timestamp_lead_us) return null;
    return t;
}

// -- 3.1.5.6 / 3.1.5.7 acknowledgements -----------------------------------

pub const Reception = struct { seq: u64, time_us: u64 };

/// 3.1.5.6: one ACK for consecutive receptions (oldest first); additions go to
/// `additions_buf`. error.InvalidField: none, more than 16, or not consecutive.
pub fn buildAck(receptions: []const Reception, now_us: u64, additions_buf: []u8) TransportError!Ack {
    const n = receptions.len;
    if (n == 0 or n > 16) return error.InvalidField;
    for (receptions[1..], receptions[0 .. n - 1]) |b, a| if (b.seq != a.seq +% 1) return error.InvalidField;
    if (additions_buf.len < n - 1) return error.EndOfBuffer;
    const newest = receptions[n - 1];
    var max_gap: u64 = 0;
    for (0..n - 1) |k| {
        const later = receptions[n - 1 - k].time_us;
        const earlier = receptions[n - 2 - k].time_us;
        max_gap = @max(max_gap, later -| earlier);
    }
    var scale: u5 = 0;
    while (max_gap >> scale > 255) : (scale += 1) if (scale == 15) return error.InvalidField;
    for (0..n - 1) |k| {
        const later = receptions[n - 1 - k].time_us;
        const earlier = receptions[n - 2 - k].time_us;
        additions_buf[k] = @intCast((later -| earlier) >> scale);
    }
    const gap_ms = (now_us -| newest.time_us) / us_per_ms;
    return .{
        .seq_num = @truncate(newest.seq),
        .received_ts = try codeTimestamp(newest.time_us),
        .send_ack_time_gap = @intCast(@min(gap_ms, 255)),
        .delay_ack_time_scale = @intCast(scale),
        .delay_ack_time_additions = additions_buf[0 .. n - 1],
    };
}

/// The receptions an ACK acknowledges (oldest first), expanded per 3.1.1.1.3 and
/// 3.1.1.1.4. error.InvalidField for an invalid timestamp.
pub fn expandAck(ack: Ack, reference_seq: u64, reference_time_us: u64, out: []Reception) TransportError![]Reception {
    const newest = try expandSeqNum(reference_seq, ack.seq_num);
    var t = (try expandTimestamp(reference_time_us, ack.received_ts)) orelse return error.InvalidField;
    const n = ack.delay_ack_time_additions.len + 1;
    if (out.len < n) return error.EndOfBuffer;
    if (newest < n - 1) return error.InvalidField;
    out[n - 1] = .{ .seq = newest, .time_us = t };
    for (ack.delay_ack_time_additions, 0..) |a, k| {
        t -|= @as(u64, a) << ack.delay_ack_time_scale;
        out[n - 2 - k] = .{ .seq = newest - (k + 1), .time_us = t };
    }
    return out[0..n];
}

/// Bytes the fewest-byte coding of `received` takes, and its choices.
const AckVecPlan = struct {
    /// best[i]: bytes to code received[i..].
    fn costs(received: []const bool, best: []u32, take: []u8) void {
        const n = received.len;
        best[n] = 0;
        var i = n;
        while (i > 0) {
            i -= 1;
            var run: usize = 1;
            while (i + run < n and received[i + run] == received[i] and run < 63) run += 1;
            // Prefer run-length on a tie: it codes exactly what is known.
            var b: u32 = 1 + best[i + run];
            var t: u8 = @intCast(run);
            var l = run;
            while (l > 1) {
                l -= 1;
                if (1 + best[i + l] < b) {
                    b = 1 + best[i + l];
                    t = @intCast(l);
                }
            }
            const map_cost = 1 + best[@min(i + 7, n)];
            if (map_cost < b) {
                b = map_cost;
                t = 0; // state map
            }
            best[i] = b;
            take[i] = t;
        }
    }
};

/// 3.1.5.7: codes the states (true: received) from the base in the fewest bytes
/// (7-state map bytes, run-length bytes up to 63).
pub fn encodeAckVector(received: []const bool, out: []u8) TransportError![]u8 {
    var stack_best: [513]u32 = undefined;
    var stack_take: [512]u8 = undefined;
    var heap: ?struct { best: []u32, take: []u8 } = null;
    defer if (heap) |h| {
        scratch_allocator.free(h.best);
        scratch_allocator.free(h.take);
    };
    var best: []u32 = &stack_best;
    var take: []u8 = &stack_take;
    if (received.len > stack_take.len) {
        const b = scratch_allocator.alloc(u32, received.len + 1) catch return error.OutOfMemory;
        const t = scratch_allocator.alloc(u8, received.len) catch {
            scratch_allocator.free(b);
            return error.OutOfMemory;
        };
        heap = .{ .best = b, .take = t };
        best = b;
        take = t;
    }
    AckVecPlan.costs(received, best, take);
    const n = received.len;
    if (out.len < best[0]) return error.EndOfBuffer;
    var i: usize = 0;
    var k: usize = 0;
    while (i < n) {
        const t = take[i];
        if (t == 0) {
            var b: u8 = 0;
            for (0..7) |j| {
                if (i + j < n and received[i + j]) b |= @as(u8, 1) << @intCast(j);
            }
            out[k] = b;
            i = @min(i + 7, n);
        } else {
            out[k] = 0x80 | @as(u8, if (received[i]) 0x40 else 0) | t;
            i += t;
        }
        k += 1;
    }
    return out[0..k];
}

fn codedSpan(b: u8) usize {
    return if (b & 0x80 == 0) 7 else b & 0x3f;
}

/// 3.1.5.7: the states a codedAckVector describes from the base.
pub fn decodeAckVector(coded: []const u8, out: []bool) TransportError![]bool {
    var n: usize = 0;
    for (coded) |b| {
        const span = codedSpan(b);
        if (out.len - n < span) return error.EndOfBuffer;
        if (b & 0x80 == 0) {
            for (0..7) |j| out[n + j] = (b >> @intCast(j)) & 1 != 0;
        } else {
            @memset(out[n .. n + span], b & 0x40 != 0);
        }
        n += span;
    }
    return out[0..n];
}

/// 3.1.5.7: several ACK vectors over consecutive ranges; only the last carries
/// `timestamp`.
pub fn encodeAckVectors(base: u64, received: []const bool, timestamp: ?AckVecTimestamp, coded_buf: []u8, out: []AckVector) TransportError![]AckVector {
    const coded = try encodeAckVector(received, coded_buf);
    var n: usize = 0;
    var at: usize = 0;
    var seq = base;
    while (at < coded.len) {
        const end = @min(at + max_coded_ack_vec_size, coded.len);
        if (n == out.len) return error.EndOfBuffer;
        out[n] = .{ .base_seq_num = @truncate(seq), .coded = coded[at..end] };
        for (coded[at..end]) |b| seq += codedSpan(b);
        n += 1;
        at = end;
    }
    if (n > 0) out[n - 1].timestamp = timestamp;
    return out[0..n];
}

/// (arrival - send) minus SendAckTimeGap; null when the gap is 255 (2.2.1.2.6: invalid)
/// or exceeds the elapsed time.
pub fn rttSampleUs(send_time_us: u64, ack_arrival_us: u64, send_ack_time_gap_ms: u8) TransportError!?u64 {
    if (send_ack_time_gap_ms == send_ack_time_gap_invalid) return null;
    if (ack_arrival_us < send_time_us) return null;
    const elapsed = ack_arrival_us - send_time_us;
    const gap = @as(u64, send_ack_time_gap_ms) * us_per_ms;
    if (gap > elapsed) return null;
    return elapsed - gap;
}

// -- 3.1.1.2 components ----------------------------------------------------

/// 3.1.1.2.1 node states.
pub const NodeState = enum { pending, received, lost };

/// A node leaving the Sender's active range, with its final state.
pub const Resolved = struct { seq: u64, state: NodeState };

fn windowCapacity(log_window_size: u4) usize {
    return (@as(usize, 1) << log_window_size) - 1;
}

/// 3.1.1.2.1 Sender Window Buffer with 3.1.1.2.3 loss detection. Resolved nodes leave via
/// popResolved(); sequence numbers outside the active range are ignored (MS-RDPEUDP 5.1.1).
pub const SenderWindow = struct {
    gpa: std.mem.Allocator,
    nodes: []Node,
    cap: usize,
    lower: u64,
    next: u64,
    highest_received: ?u64 = null,
    resolved: std.ArrayList(Resolved) = .empty,
    resolved_head: usize = 0,

    const Node = struct { state: NodeState, sent_us: u64 };

    pub fn init(gpa: std.mem.Allocator, log_window_size: u4, first_seq: u64) TransportError!SenderWindow {
        const nodes = try gpa.alloc(Node, @as(usize, 1) << log_window_size);
        return .{ .gpa = gpa, .nodes = nodes, .cap = windowCapacity(log_window_size), .lower = first_seq, .next = first_seq };
    }

    pub fn deinit(w: *SenderWindow) void {
        w.gpa.free(w.nodes);
        w.resolved.deinit(w.gpa);
    }

    fn node(w: *const SenderWindow, seq: u64) *Node {
        return &w.nodes[@intCast(seq & (w.nodes.len - 1))];
    }

    fn inRange(w: *const SenderWindow, seq: u64) bool {
        return seq >= w.lower and seq < w.next;
    }

    /// 4.1.1 step 2: a new Pending node sent at `now_us`. error.WindowFull when full.
    pub fn push(w: *SenderWindow, now_us: u64) TransportError!u64 {
        if (w.next - w.lower >= w.cap) return error.WindowFull;
        const seq = w.next;
        w.node(seq).* = .{ .state = .pending, .sent_us = now_us };
        w.next += 1;
        return seq;
    }

    /// The next one to push when the active range is empty.
    pub fn lowerBound(w: *const SenderWindow) TransportError!u64 {
        return w.lower;
    }

    /// first_seq - 1 before the first push.
    pub fn upperBound(w: *const SenderWindow) TransportError!u64 {
        return w.next -% 1;
    }

    pub fn active(w: *const SenderWindow) TransportError!usize {
        return @intCast(w.next - w.lower);
    }

    pub fn stateOf(w: *const SenderWindow, seq: u64) TransportError!?NodeState {
        if (!w.inRange(seq)) return null;
        return w.node(seq).state;
    }

    pub fn sentTime(w: *const SenderWindow, seq: u64) ?u64 {
        if (!w.inRange(seq)) return null;
        return w.node(seq).sent_us;
    }

    fn markReceived(w: *SenderWindow, seq: u64) void {
        const n = w.node(seq);
        if (n.state != .pending) return;
        n.state = .received;
        w.highest_received = if (w.highest_received) |h| @max(h, seq) else seq;
    }

    fn advance(w: *SenderWindow) TransportError!void {
        while (w.lower < w.next) {
            const n = w.node(w.lower);
            if (n.state == .pending) break;
            try w.resolved.append(w.gpa, .{ .seq = w.lower, .state = n.state });
            w.lower += 1;
        }
    }

    /// 3.1.1.2.1, 3.1.5.6: `seq` and every lower Pending node become Received.
    pub fn onAck(w: *SenderWindow, seq: u64) TransportError!void {
        if (!w.inRange(seq)) return;
        var s = w.lower;
        while (s <= seq) : (s += 1) w.markReceived(s);
        try w.advance();
    }

    /// 3.1.5.7, 4.2.2: only the nodes marked received change.
    pub fn onAckVector(w: *SenderWindow, base: u64, received: []const bool) TransportError!void {
        for (received, 0..) |r, i| {
            const seq = base +% i;
            if (r and w.inRange(seq)) w.markReceived(seq);
        }
        try w.advance();
    }

    /// 3.1.1.2.3: a Pending node `reorder_threshold` below the highest Received, or older than
    /// `loss_timeout_us`, is Lost with every Pending node below it. True when any was lost.
    pub fn detectLosses(w: *SenderWindow, now_us: u64, reorder_threshold: u64, loss_timeout_us: u64) TransportError!bool {
        var lost_upto: ?u64 = null;
        var s = w.lower;
        while (s < w.next) : (s += 1) {
            const n = w.node(s);
            if (n.state != .pending) continue;
            const by_reorder = if (w.highest_received) |h| h > s and h - s >= reorder_threshold else false;
            const by_time = now_us >= n.sent_us and now_us - n.sent_us >= loss_timeout_us;
            if (by_reorder or by_time) {
                lost_upto = s;
            } else if (w.highest_received == null or s > w.highest_received.?) {
                // Above the highest Received only the timeout applies, and later nodes are no older.
                break;
            }
        }
        const top = lost_upto orelse return false;
        s = w.lower;
        while (s <= top) : (s += 1) {
            const n = w.node(s);
            if (n.state == .pending) n.state = .lost;
        }
        try w.advance();
        return true;
    }

    /// Send time of the oldest Pending node.
    pub fn oldestPendingSent(w: *const SenderWindow) ?u64 {
        var s = w.lower;
        while (s < w.next) : (s += 1) {
            const n = w.node(s);
            if (n.state == .pending) return n.sent_us;
        }
        return null;
    }

    /// Nodes that left the active range since the last call, in order.
    pub fn popResolved(w: *SenderWindow, out: []Resolved) TransportError![]Resolved {
        const avail = w.resolved.items[w.resolved_head..];
        const n = @min(avail.len, out.len);
        @memcpy(out[0..n], avail[0..n]);
        w.resolved_head += n;
        if (w.resolved_head == w.resolved.items.len) {
            w.resolved.clearRetainingCapacity();
            w.resolved_head = 0;
        }
        return out[0..n];
    }
};

pub const Arrival = enum {
    /// Next after the highest received, with no Pending node below it.
    in_order,
    /// A new packet that opens, keeps or fills a gap.
    out_of_order,
    /// Already Received, or below the lower bound.
    duplicate,
    /// (1 << log_window_size) - 1 or more above the lower bound; not recorded.
    out_of_window,
};

/// What the Receiver owes the Sender (3.1.5.6, 3.1.5.7, 4.2.1).
pub const AckPlan = struct {
    /// Every node from the lower bound through this one is Received.
    ack_through: ?u64 = null,
    /// From the first Pending node to the highest Received.
    vector_base: ?u64 = null,
    vector_len: usize = 0,
};

/// 3.1.1.2.2 Receiver Window Buffer: active range [lower, end), end - 1 the highest received.
pub const ReceiverWindow = struct {
    gpa: std.mem.Allocator,
    nodes: []Node,
    cap: usize,
    lower: u64,
    end: u64,
    pending: usize = 0,
    highest_seen: ?u64 = null,

    const Node = struct { received: bool, time_us: u64 };

    pub fn init(gpa: std.mem.Allocator, log_window_size: u4, first_seq: u64) TransportError!ReceiverWindow {
        const nodes = try gpa.alloc(Node, @as(usize, 1) << log_window_size);
        return .{ .gpa = gpa, .nodes = nodes, .cap = windowCapacity(log_window_size), .lower = first_seq, .end = first_seq };
    }

    pub fn deinit(w: *ReceiverWindow) void {
        w.gpa.free(w.nodes);
    }

    fn node(w: *const ReceiverWindow, seq: u64) *Node {
        return &w.nodes[@intCast(seq & (w.nodes.len - 1))];
    }

    /// Nodes between the old upper bound and `seq` become Pending.
    pub fn onData(w: *ReceiverWindow, seq: u64, now_us: u64) TransportError!Arrival {
        if (seq < w.lower) return .duplicate;
        if (seq - w.lower >= w.cap) return .out_of_window;
        if (seq < w.end) {
            const n = w.node(seq);
            if (n.received) return .duplicate;
            n.* = .{ .received = true, .time_us = now_us };
            w.pending -= 1;
            w.highest_seen = if (w.highest_seen) |h| @max(h, seq) else seq;
            return .out_of_order;
        }
        const in_order = seq == w.end and w.pending == 0;
        var s = w.end;
        while (s < seq) : (s += 1) w.node(s).* = .{ .received = false, .time_us = 0 };
        w.pending += @intCast(seq - w.end);
        w.node(seq).* = .{ .received = true, .time_us = now_us };
        w.end = seq + 1;
        w.highest_seen = if (w.highest_seen) |h| @max(h, seq) else seq;
        return if (in_order) .in_order else .out_of_order;
    }

    pub fn lowerBound(w: *const ReceiverWindow) TransportError!u64 {
        return w.lower;
    }

    /// One past the highest node: the DataSeqNum reference (3.1.1.1.3).
    pub fn upperEnd(w: *const ReceiverWindow) u64 {
        return w.end;
    }

    pub fn highest(w: *const ReceiverWindow) TransportError!?u64 {
        return w.highest_seen;
    }

    pub fn stateOf(w: *const ReceiverWindow, seq: u64) TransportError!?NodeState {
        if (seq < w.lower or seq >= w.end) return null;
        return if (w.node(seq).received) .received else .pending;
    }

    pub fn receivedAt(w: *const ReceiverWindow, seq: u64) ?u64 {
        if (seq < w.lower or seq >= w.end) return null;
        const n = w.node(seq);
        return if (n.received) n.time_us else null;
    }

    fn firstPending(w: *const ReceiverWindow) ?u64 {
        if (w.pending == 0) return null;
        var s = w.lower;
        while (s < w.end) : (s += 1) if (!w.node(s).received) return s;
        return null;
    }

    pub fn plan(w: *const ReceiverWindow) TransportError!AckPlan {
        if (w.end <= w.lower) return .{};
        const fp = w.firstPending() orelse return .{ .ack_through = w.end - 1 };
        var p = AckPlan{ .vector_base = fp, .vector_len = @intCast(w.end - fp) };
        if (fp > w.lower) p.ack_through = fp - 1;
        return p;
    }

    /// The states of `out.len` nodes from `base` (true: Received).
    pub fn states(w: *const ReceiverWindow, base: u64, out: []bool) TransportError![]bool {
        for (out, 0..) |*o, i| {
            const s = base + i;
            o.* = if (s < w.lower) true else if (s >= w.end) false else w.node(s).received;
        }
        return out;
    }

    fn dropBelow(w: *ReceiverWindow, new_lower: u64) void {
        if (new_lower <= w.lower) return;
        var s = w.lower;
        const stop = @min(new_lower, w.end);
        while (s < stop) : (s += 1) if (!w.node(s).received) {
            w.pending -= 1;
        };
        w.lower = new_lower;
        if (w.end < w.lower) w.end = w.lower;
    }

    pub fn onAckSent(w: *ReceiverWindow, seq: u64) TransportError!void {
        w.dropBelow(seq + 1);
    }

    /// 3.1.1.2.2: the lower bound moves past the leading Received nodes only.
    pub fn onAckVectorSent(w: *ReceiverWindow, base: u64) TransportError!void {
        _ = base;
        var s = w.lower;
        while (s < w.end and w.node(s).received) s += 1;
        w.dropBelow(s);
    }

    /// 2.2.1.2.4, 4.3.3: the lower bound becomes `seq` (never lower).
    pub fn onAckOfAcks(w: *ReceiverWindow, seq: u64) TransportError!void {
        w.dropBelow(seq);
    }
};

/// 3.1.1.2.4.1 Sender Reliability Controller: ChannelSeqNum from 1 (as Windows, <1>);
/// keeps a copy until a packet carrying it is Received.
pub const SenderReliability = struct {
    gpa: std.mem.Allocator,
    next_channel: u64 = 1,
    copies: std.AutoHashMapUnmanaged(u64, Copy) = .empty,
    by_seq: std.AutoHashMapUnmanaged(u64, u64) = .empty,

    const Copy = struct { data: []u8, seq: ?u64 = null };

    pub fn init(gpa: std.mem.Allocator) TransportError!SenderReliability {
        return .{ .gpa = gpa };
    }

    pub fn deinit(r: *SenderReliability) void {
        var it = r.copies.valueIterator();
        while (it.next()) |c| r.gpa.free(c.data);
        r.copies.deinit(r.gpa);
        r.by_seq.deinit(r.gpa);
    }

    /// Stores a copy of `data`; returns its ChannelSeqNum.
    pub fn enqueue(r: *SenderReliability, data: []const u8) TransportError!u64 {
        const copy = try r.gpa.dupe(u8, data);
        errdefer r.gpa.free(copy);
        const ch = r.next_channel;
        try r.copies.put(r.gpa, ch, .{ .data = copy });
        r.next_channel += 1;
        return ch;
    }

    pub fn sent(r: *SenderReliability, channel_seq: u64, seq: u64) TransportError!void {
        const c = r.copies.getPtr(channel_seq) orelse return error.InvalidField;
        if (c.seq) |old| _ = r.by_seq.remove(old);
        try r.by_seq.put(r.gpa, seq, channel_seq);
        c.seq = seq;
    }

    /// Received drops the copy (null); Lost returns the ChannelSeqNum to resend.
    pub fn onResolved(r: *SenderReliability, resolved: Resolved) TransportError!?u64 {
        const kv = r.by_seq.fetchRemove(resolved.seq) orelse return null;
        const ch = kv.value;
        const c = r.copies.getPtr(ch) orelse return null;
        if (c.seq != resolved.seq) return null;
        switch (resolved.state) {
            .received => {
                r.gpa.free(c.data);
                _ = r.copies.remove(ch);
                return null;
            },
            .lost => {
                c.seq = null;
                return ch;
            },
            .pending => return null,
        }
    }

    pub fn copyOf(r: *const SenderReliability, channel_seq: u64) TransportError!?[]const u8 {
        const c = r.copies.get(channel_seq) orelse return null;
        return c.data;
    }

    pub fn buffered(r: *const SenderReliability) TransportError!usize {
        return r.copies.count();
    }
};

/// 3.1.1.2.4.2 Receiver Reliability Controller: forwards each ChannelSeqNum once, in order
/// from 1 (expanded per 3.1.1.1.3), buffering what follows a gap.
pub const ReceiverReliability = struct {
    gpa: std.mem.Allocator,
    next_expected: u64 = 1,
    held: std.AutoHashMapUnmanaged(u64, []u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) TransportError!ReceiverReliability {
        return .{ .gpa = gpa };
    }

    pub fn deinit(r: *ReceiverReliability) void {
        var it = r.held.valueIterator();
        while (it.next()) |d| r.gpa.free(d.*);
        r.held.deinit(r.gpa);
    }

    pub fn onData(r: *ReceiverReliability, channel_seq_num: u16, data: []const u8) TransportError!void {
        const ch = try expandSeqNum(r.next_expected, channel_seq_num);
        if (ch < r.next_expected) return; // forwarded already
        if (ch - r.next_expected >= 0x8000) return; // ambiguous: ignore
        const gop = try r.held.getOrPut(r.gpa, ch);
        if (gop.found_existing) return;
        gop.value_ptr.* = r.gpa.dupe(u8, data) catch |e| {
            _ = r.held.remove(ch);
            return e;
        };
    }

    /// The next in-order data (copied to `out`), or null.
    pub fn next(r: *ReceiverReliability, out: []u8) TransportError!?[]u8 {
        const d = r.held.get(r.next_expected) orelse return null;
        if (out.len < d.len) return error.EndOfBuffer;
        @memcpy(out[0..d.len], d);
        _ = r.held.remove(r.next_expected);
        r.gpa.free(d);
        r.next_expected += 1;
        return out[0..d.len];
    }

    /// Data waiting behind a gap.
    pub fn buffered(r: *const ReceiverReliability) TransportError!usize {
        return r.held.count();
    }
};

// -- the endpoint ------------------------------------------------------------

pub const EndpointConfig = struct {
    /// Announced in every header: the local Receiver window (2.2.1.1).
    log_window_size: u4 = 10,
    initial_seq: u64,
    peer_initial_seq: u64,
    /// The peer's LogWindowSize until a packet from it announces one.
    peer_log_window_size: u4 = 10,
    /// 3.1.1.2.3 reordering threshold.
    reorder_threshold: u32 = 3,
    /// 3.1.1.2.3 loss timeout.
    loss_timeout_us: u64 = 1 * us_per_s,
    /// Keepalive interval when quiescent (3.1.1.3: at most 16 s).
    keepalive_interval_us: u64 = windows_keepalive_interval_us,
    /// Sent to the peer (3.1.5.2); null: the peer uses 8 and RTT / 2.
    delay_ack_info: ?DelayAckInfo = null,
    initial_rtt_us: u64 = 100 * us_per_ms,
    /// Data packets allowed before the first acknowledgement.
    initial_congestion_window: u16 = 16,
};

pub const EndpointStats = struct {
    in_flight: usize = 0,
    data_sent: u64 = 0,
    retransmits: u64 = 0,
    ack_vectors_sent: u64 = 0,
    delivered: u64 = 0,
    duplicates_dropped: u64 = 0,
};

/// PacketPrefixByte, header, DataHeader, ChannelSeqNum.
const data_overhead: usize = 1 + 2 + 2 + 2;
/// Piggyback room: ACK with 15 delays (22), AckOfAcks (2), DelayAckInfo (3).
const piggyback_reserve: usize = 22 + 2 + 3;
/// 3.1.5.1 OverheadSize in keepalives with nothing to acknowledge: IPv4 + UDP headers.
const keepalive_overhead_size: u8 = 28;
/// Enough packets in flight for the reordering threshold to work.
const min_congestion_window: usize = 4;

/// One reliable RDP-UDP2 connection (1.3, 3.1.5, 3.1.1.3). A lost packet is resent with a
/// new sequence number and the same ChannelSeqNum; Dummy packets are never handed up.
pub const Endpoint = struct {
    gpa: std.mem.Allocator,
    cfg: EndpointConfig,
    closed: bool = false,
    close_reason: ?mt.CloseReason = null,
    started: bool = false,
    last_now: u64 = 0,
    last_heard_us: u64 = 0,
    last_sent_us: u64 = 0,
    peer_log_window_size: u4,

    sw: SenderWindow,
    sr: SenderReliability,
    /// ChannelSeqNums waiting for their first transmission, in order.
    fresh: std.ArrayList(u64) = .empty,
    fresh_head: usize = 0,
    /// ChannelSeqNums declared lost, to resend first.
    resend: std.ArrayList(u64) = .empty,
    /// Piggybacked (3.1.5.3) until an acknowledgement beyond it arrives.
    ack_of_acks: ?u64 = null,
    /// DelayAckInfo rides along until the peer acknowledges.
    announce_dai: bool,
    srtt_us: u64,
    rtt_sampled: bool = false,
    cwnd: usize,
    ssthresh: usize = std.math.maxInt(usize),
    cwnd_credit: usize = 0,
    /// NewReno: one reduction per window of data (3.1.1.8 in MS-RDPEUDP).
    recovery_until: ?u64 = null,

    rw: ReceiverWindow,
    rr: ReceiverReliability,
    max_delayed_acks: u8 = default_max_delayed_acks,
    delayed_ack_timeout_us: ?u64 = null,
    /// In-order receptions not acknowledged yet.
    unacked: usize = 0,
    ack_deadline: ?u64 = null,
    /// A hole opened or closed, or MaxDelayedAcks was reached.
    ack_now: bool = false,
    /// For keepalives (3.1.1.3).
    last_rx: ?Reception = null,
    /// Start of the next ACK vector of a split report (3.1.5.7).
    vector_from: ?u64 = null,

    stats_: EndpointStats = .{},

    pub fn init(gpa: std.mem.Allocator, config: EndpointConfig) TransportError!Endpoint {
        var sw = try SenderWindow.init(gpa, max_log_window_size, config.initial_seq);
        errdefer sw.deinit();
        var rw = try ReceiverWindow.init(gpa, config.log_window_size, config.peer_initial_seq);
        errdefer rw.deinit();
        return .{
            .gpa = gpa,
            .cfg = config,
            .peer_log_window_size = config.peer_log_window_size,
            .sw = sw,
            .sr = try SenderReliability.init(gpa),
            .announce_dai = config.delay_ack_info != null,
            .srtt_us = config.initial_rtt_us,
            .cwnd = @max(config.initial_congestion_window, 1),
            .rw = rw,
            .rr = try ReceiverReliability.init(gpa),
        };
    }

    pub fn deinit(e: *Endpoint) void {
        e.sw.deinit();
        e.sr.deinit();
        e.fresh.deinit(e.gpa);
        e.resend.deinit(e.gpa);
        e.rw.deinit();
        e.rr.deinit();
    }

    /// At most maxPayload() bytes.
    pub fn send(e: *Endpoint, data: []const u8) TransportError!void {
        if (e.closed) return error.ConnectionClosed;
        if (data.len > try e.maxPayload()) return error.MessageTooLarge;
        const ch = try e.sr.enqueue(data);
        try e.fresh.append(e.gpa, ch);
    }

    fn tick(e: *Endpoint, now_us: u64) void {
        if (!e.started) {
            e.started = true;
            e.last_heard_us = now_us;
            e.last_sent_us = now_us;
        }
        e.last_now = @max(e.last_now, now_us);
    }

    pub fn onDatagram(e: *Endpoint, datagram: []const u8, now_us: u64) TransportError!void {
        var scratch: [2048]u8 = undefined;
        if (datagram.len > scratch.len) return error.BadDatagram;
        const u = try fromWire(datagram, &scratch);
        const p = try decodePacket(u.layout);
        if (e.closed) return;
        e.tick(now_us);
        e.last_heard_us = now_us;
        e.peer_log_window_size = p.log_window_size;
        if (p.delay_ack_info) |d| {
            e.max_delayed_acks = d.max_delayed_acks;
            e.delayed_ack_timeout_us = @as(u64, d.delayed_ack_timeout_ms) * us_per_ms;
        }
        if (p.ack) |a| try e.onAckPayload(a, now_us);
        if (p.ack_vector) |v| try e.onAckVectorPayload(v, now_us);
        try e.senderHousekeeping(now_us);
        if (p.ack_of_acks) |a| try e.rw.onAckOfAcks(try expandSeqNum(e.rw.lower, a));
        if (p.data) |d| try e.onData(d, u.prefix.packet_type_index == packet_type_dummy, now_us);
    }

    fn onAckPayload(e: *Endpoint, a: Ack, now_us: u64) TransportError!void {
        const seq = try expandSeqNum(try e.sw.upperBound(), a.seq_num);
        if (e.sw.inRange(seq)) {
            if (e.sw.node(seq).state == .pending) {
                if (try rttSampleUs(e.sw.node(seq).sent_us, now_us, a.send_ack_time_gap)) |sample| e.addRttSample(sample);
            }
            e.announce_dai = false;
        }
        try e.sw.onAck(seq);
        // 3.1.5.3: an acknowledgement above the AckOfAcks ends it.
        if (e.ack_of_acks) |aoa| if (seq > aoa and seq <= try e.sw.upperBound()) {
            e.ack_of_acks = null;
        };
    }

    fn onAckVectorPayload(e: *Endpoint, v: AckVector, now_us: u64) TransportError!void {
        const base = try expandSeqNum(e.sw.lower, v.base_seq_num);
        var states_buf: [max_coded_ack_vec_size * 63]bool = undefined;
        const st = try decodeAckVector(v.coded, &states_buf);
        // The newest received packet carries the timestamp (3.1.5.7).
        var newest: ?u64 = null;
        for (st, 0..) |r, i| if (r) {
            newest = base + i;
        };
        if (newest) |n| if (e.sw.inRange(n) and e.sw.node(n).state == .pending) {
            if (v.timestamp) |t| if (try rttSampleUs(e.sw.node(n).sent_us, now_us, t.send_ack_time_gap_ms)) |sample| e.addRttSample(sample);
            e.announce_dai = false;
        };
        try e.sw.onAckVector(base, st);
        // 3.1.5.3: a vector whose first missing packet is beyond the AckOfAcks ends it.
        if (e.ack_of_acks) |aoa| if (st.len > 0 and !st[0] and base > aoa and base <= try e.sw.upperBound()) {
            e.ack_of_acks = null;
        };
    }

    fn addRttSample(e: *Endpoint, sample: u64) void {
        if (!e.rtt_sampled) {
            e.srtt_us = sample;
            e.rtt_sampled = true;
        } else {
            e.srtt_us = (7 * e.srtt_us + sample) / 8;
        }
    }

    /// 3.1.1.2.3, 3.1.1.2.4.1: lost packets are resent under new sequence numbers; an
    /// AckOfAcks announces the new lower bound.
    fn senderHousekeeping(e: *Endpoint, now_us: u64) TransportError!void {
        if (try e.sw.detectLosses(now_us, e.cfg.reorder_threshold, e.cfg.loss_timeout_us)) {
            e.ack_of_acks = e.sw.lower;
        }
        var buf: [64]Resolved = undefined;
        while (true) {
            const got = try e.sw.popResolved(&buf);
            if (got.len == 0) break;
            for (got) |r| {
                if (try e.sr.onResolved(r)) |ch| {
                    try e.resend.append(e.gpa, ch);
                    e.onLoss(r.seq);
                } else if (r.state == .received) {
                    e.onDelivered();
                }
            }
        }
    }

    /// NewReno-like: slow start, then +1 per window; one halving per window of losses.
    fn onDelivered(e: *Endpoint) void {
        if (e.cwnd < e.ssthresh) {
            e.cwnd += 1;
        } else {
            e.cwnd_credit += 1;
            if (e.cwnd_credit >= e.cwnd) {
                e.cwnd_credit = 0;
                e.cwnd += 1;
            }
        }
        e.cwnd = @min(e.cwnd, windowCapacity(max_log_window_size));
    }

    fn onLoss(e: *Endpoint, seq: u64) void {
        if (e.recovery_until) |r| if (seq <= r) return;
        e.ssthresh = @max(e.cwnd / 2, min_congestion_window);
        e.cwnd = e.ssthresh;
        e.cwnd_credit = 0;
        e.recovery_until = e.sw.next -% 1;
    }

    fn onData(e: *Endpoint, d: Data, dummy: bool, now_us: u64) TransportError!void {
        const seq = try expandSeqNum(e.rw.end, d.seq_num);
        switch (try e.rw.onData(seq, now_us)) {
            .duplicate => {
                e.stats_.duplicates_dropped += 1;
                return;
            },
            .out_of_window => return,
            .in_order => {
                e.unacked += 1;
                if (e.ack_deadline == null) e.ack_deadline = now_us + e.delayedAckTimeout();
                if (e.unacked > e.max_delayed_acks) e.ack_now = true;
            },
            .out_of_order => {
                // Acknowledge holes at once (3.1.5.7, 4.2.1, 4.2.3).
                e.unacked += 1;
                e.ack_now = true;
            },
        }
        if (e.last_rx == null or seq >= e.last_rx.?.seq) e.last_rx = .{ .seq = seq, .time_us = now_us };
        if (!dummy) try e.rr.onData(d.channel_seq_num, d.payload);
    }

    fn delayedAckTimeout(e: *const Endpoint) u64 {
        // 3.1.5.2: before any DelayAckInfo, half the round trip time.
        return e.delayed_ack_timeout_us orelse e.srtt_us / 2;
    }

    fn inFlightLimit(e: *const Endpoint) usize {
        return @min(windowCapacity(e.peer_log_window_size), e.cwnd);
    }

    fn hasQueued(e: *const Endpoint) bool {
        return e.resend.items.len > 0 or e.fresh_head < e.fresh.items.len;
    }

    fn canSendData(e: *const Endpoint) bool {
        return e.hasQueued() and (e.sw.next - e.sw.lower) < e.inFlightLimit();
    }

    fn ackDue(e: *const Endpoint, now_us: u64) bool {
        if (e.ack_now) return true;
        if (e.ack_deadline) |t| return now_us >= t;
        return false;
    }

    pub fn poll(e: *Endpoint, now_us: u64, out: []u8) TransportError!?[]u8 {
        if (e.closed) return null;
        e.tick(now_us);
        if (now_us >= e.last_heard_us + keepalive_timeout_us) {
            e.closed = true;
            if (e.close_reason == null) e.close_reason = .keepalive_timeout;
            return null;
        }
        try e.senderHousekeeping(now_us);
        if (e.canSendData()) return try e.sendData(now_us, out);
        if (e.ackDue(now_us)) {
            if (try e.sendAck(now_us, out, false)) |p| return p;
        }
        if (now_us >= e.last_sent_us + e.cfg.keepalive_interval_us) return try e.sendAck(now_us, out, true);
        return null;
    }

    /// An ACK when everything from the lower bound is in, else an ACK vector.
    const Owed = union(enum) {
        none,
        ack: u64,
        /// False for the continuation of a vector split over several packets.
        vector: struct { base: u64, len: usize, whole: bool = true },
    };

    fn owed(e: *Endpoint) TransportError!Owed {
        if (e.vector_from) |f| {
            if (f >= e.rw.lower and f < e.rw.end) return .{ .vector = .{ .base = f, .len = @intCast(e.rw.end - f), .whole = false } };
            e.vector_from = null;
        }
        const pl = try e.rw.plan();
        if (pl.ack_through) |x| return .{ .ack = x };
        if (pl.vector_base) |b| return .{ .vector = .{ .base = b, .len = pl.vector_len } };
        return .none;
    }

    /// At most MaxDelayedAcks + 1 receptions still in the window.
    fn buildOwedAck(e: *Endpoint, through: u64, now_us: u64, rec_buf: []Reception, adds: []u8) TransportError!Ack {
        var n: usize = 0;
        var s = through;
        const max_n = @as(usize, e.max_delayed_acks) + 1;
        while (n < max_n) {
            const t = e.rw.receivedAt(s) orelse break;
            n += 1;
            rec_buf[max_n - n] = .{ .seq = s, .time_us = t };
            if (s == 0) break;
            s -= 1;
        }
        if (n == 0) {
            const t = if (e.last_rx) |r| (if (r.seq == through) r.time_us else now_us) else now_us;
            rec_buf[0] = .{ .seq = through, .time_us = t };
            n = 1;
            return buildAck(rec_buf[0..1], now_us, adds);
        }
        var recs = rec_buf[max_n - n .. max_n];
        // Gaps too wide for one scale: drop the oldest receptions.
        while (true) {
            if (buildAck(recs, now_us, adds)) |a| return a else |err| {
                if (err != error.InvalidField or recs.len == 1) return err;
                recs = recs[1..];
            }
        }
    }

    fn markAckSent(e: *Endpoint) void {
        e.unacked = 0;
        e.ack_deadline = null;
        e.ack_now = false;
    }

    fn finish(e: *Endpoint, p: Packet, ptype: u4, now_us: u64, out: []u8) TransportError![]u8 {
        if (out.len < 2) return error.EndOfBuffer;
        const layout = try encodePacketInto(p, out[1..]);
        const wire = try toWire(layout, ptype, out);
        e.last_sent_us = now_us;
        return wire;
    }

    fn aoaField(e: *const Endpoint) ?u16 {
        return if (e.ack_of_acks) |a| @truncate(a) else null;
    }

    fn sendData(e: *Endpoint, now_us: u64, out: []u8) TransportError![]u8 {
        var retransmit = false;
        const ch = if (e.resend.items.len > 0) blk: {
            retransmit = true;
            break :blk e.resend.orderedRemove(0);
        } else blk: {
            const c = e.fresh.items[e.fresh_head];
            e.fresh_head += 1;
            if (e.fresh_head == e.fresh.items.len) {
                e.fresh.clearRetainingCapacity();
                e.fresh_head = 0;
            }
            break :blk c;
        };
        const payload = (try e.sr.copyOf(ch)) orelse return error.InvalidField;
        const seq = try e.sw.push(now_us);
        try e.sr.sent(ch, seq);
        if (retransmit) e.stats_.retransmits += 1 else e.stats_.data_sent += 1;
        var p = Packet{
            .log_window_size = e.cfg.log_window_size,
            .ack_of_acks = e.aoaField(),
            .delay_ack_info = if (e.announce_dai) e.cfg.delay_ack_info else null,
            .data = .{ .seq_num = @truncate(seq), .channel_seq_num = @truncate(ch), .payload = payload },
        };
        // An owed ACK fits the reserve; a vector rides along only if it fits the MTU.
        var rec_buf: [16]Reception = undefined;
        var adds: [15]u8 = undefined;
        var coded: [max_coded_ack_vec_size]u8 = undefined;
        var acked: ?u64 = null;
        var vector_base: ?u64 = null;
        if (e.unacked > 0 or e.ack_now) switch (try e.owed()) {
            .none => {},
            .ack => |x| {
                p.ack = try e.buildOwedAck(x, now_us, &rec_buf, &adds);
                acked = x;
            },
            .vector => |v| if (v.whole) {
                if (try e.buildVector(v.base, v.len, now_us, &coded)) |vec| {
                    var size: usize = data_overhead + payload.len + 3 + vec.coded.len;
                    if (vec.timestamp != null) size += 4;
                    if (p.ack_of_acks != null) size += 2;
                    if (p.delay_ack_info != null) size += 3;
                    if (size <= mtu) {
                        p.ack_vector = vec;
                        vector_base = v.base;
                    }
                }
            },
        };
        const wire = try e.finish(p, packet_type_data, now_us, out);
        if (acked) |x| {
            try e.rw.onAckSent(x);
            e.markAckSent();
        }
        if (vector_base) |b| {
            try e.rw.onAckVectorSent(b);
            e.stats_.ack_vectors_sent += 1;
            e.markAckSent();
        }
        return wire;
    }

    /// null when the states need more than one vector.
    fn buildVector(e: *Endpoint, base: u64, len: usize, now_us: u64, coded: []u8) TransportError!?AckVector {
        var st_buf: [max_coded_ack_vec_size * 63]bool = undefined;
        if (len > st_buf.len) return null;
        const st = try e.rw.states(base, st_buf[0..len]);
        const enc = encodeAckVector(st, coded) catch |err| switch (err) {
            error.EndOfBuffer => return null,
            else => return err,
        };
        return .{ .base_seq_num = @truncate(base), .timestamp = e.vectorTimestamp(now_us), .coded = enc };
    }

    /// 2.2.1.2.6: newest reception time and the ms since (255: invalid).
    fn vectorTimestamp(e: *const Endpoint, now_us: u64) ?AckVecTimestamp {
        const r = e.last_rx orelse return null;
        const gap = (now_us -| r.time_us) / us_per_ms;
        return .{ .timestamp = @truncate(r.time_us / timestamp_unit_us), .send_ack_time_gap_ms = @intCast(@min(gap, send_ack_time_gap_invalid)) };
    }

    /// The owed ACK or ACK vector; a keepalive re-acknowledges the last packet received or
    /// carries an OverheadSize when nothing was received (3.1.1.3).
    fn sendAck(e: *Endpoint, now_us: u64, out: []u8, keepalive: bool) TransportError!?[]u8 {
        var p = Packet{ .log_window_size = e.cfg.log_window_size, .ack_of_acks = e.aoaField() };
        var rec_buf: [16]Reception = undefined;
        var adds: [15]u8 = undefined;
        var coded_buf: [4096]u8 = undefined;
        switch (try e.owed()) {
            .ack => |x| {
                p.ack = try e.buildOwedAck(x, now_us, &rec_buf, &adds);
                const wire = try e.finish(p, packet_type_data, now_us, out);
                try e.rw.onAckSent(x);
                e.markAckSent();
                return wire;
            },
            .vector => |v| {
                // 3.1.5.7: the rest follows on the next poll, the timestamp on the last vector.
                var st_buf: [max_coded_ack_vec_size * 63]bool = undefined;
                const len = @min(v.len, st_buf.len);
                const st = try e.rw.states(v.base, st_buf[0..len]);
                var vecs: [64]AckVector = undefined;
                const all = try encodeAckVectors(v.base, st, e.vectorTimestamp(now_us), &coded_buf, &vecs);
                p.ack_vector = all[0];
                const wire = try e.finish(p, packet_type_data, now_us, out);
                try e.rw.onAckVectorSent(v.base);
                e.stats_.ack_vectors_sent += 1;
                e.markAckSent();
                if (all.len > 1) {
                    var covered: u64 = 0;
                    for (all[0].coded) |b| covered += codedSpan(b);
                    e.vector_from = v.base + covered;
                    e.ack_now = true;
                } else e.vector_from = null;
                return wire;
            },
            .none => {},
        }
        e.markAckSent();
        if (!keepalive) return null;
        if (e.last_rx) |r| {
            const gap = (now_us -| r.time_us) / us_per_ms;
            p.ack = .{ .seq_num = @truncate(r.seq), .received_ts = @truncate(r.time_us / timestamp_unit_us), .send_ack_time_gap = @intCast(@min(gap, 255)) };
        } else {
            p.overhead_size = keepalive_overhead_size;
        }
        return try e.finish(p, packet_type_data, now_us, out);
    }

    /// The next message, in order, exactly once.
    pub fn receive(e: *Endpoint, out: []u8) TransportError!?[]u8 {
        if (e.closed) return null;
        const m = (try e.rr.next(out)) orelse return null;
        e.stats_.delivered += 1;
        return m;
    }

    pub fn nextTimeout(e: *const Endpoint) TransportError!?u64 {
        if (e.closed or !e.started) return null;
        var t: u64 = e.last_heard_us + keepalive_timeout_us;
        t = @min(t, e.last_sent_us + e.cfg.keepalive_interval_us);
        if (e.ack_now or e.canSendData()) t = @min(t, e.last_now);
        if (e.ack_deadline) |d| t = @min(t, d);
        if (e.sw.oldestPendingSent()) |s| t = @min(t, s + e.cfg.loss_timeout_us);
        return t;
    }

    pub fn state(e: *const Endpoint) TransportError!ConnState {
        return if (e.closed) .closed else .established;
    }

    pub fn close(e: *Endpoint) TransportError!void {
        e.closed = true;
        if (e.close_reason == null) e.close_reason = .closed_locally;
    }

    pub fn closeReason(e: *const Endpoint) ?mt.CloseReason {
        return e.close_reason;
    }

    /// The MTU minus the prefix, headers and piggyback reserve.
    pub fn maxPayload(e: *const Endpoint) TransportError!usize {
        _ = e;
        return mtu - data_overhead - piggyback_reserve;
    }

    /// Payload bytes accepted without waiting: inFlightLimit minus packets in flight and
    /// queued, in payloads. 0 once Closed.
    pub fn sendRoom(e: *const Endpoint) usize {
        if (e.closed) return 0;
        const payload = e.maxPayload() catch return 0;
        const used = @as(usize, @intCast(@min(e.sw.next - e.sw.lower, std.math.maxInt(usize)))) +| (e.fresh.items.len - e.fresh_head);
        return (e.inFlightLimit() -| used) *| payload;
    }

    /// Queued bytes never sent (in payloads).
    pub fn unsentBytes(e: *const Endpoint) usize {
        const payload = e.maxPayload() catch return 0;
        return (e.fresh.items.len - e.fresh_head) *| payload;
    }

    /// B/s: inFlightLimit payloads per smoothed RTT; null before an RTT sample.
    pub fn windowRate(e: *const Endpoint) ?f64 {
        if (!e.rtt_sampled or e.srtt_us == 0) return null;
        const payload = e.maxPayload() catch return null;
        const window: f64 = @floatFromInt(e.inFlightLimit());
        return window * @as(f64, @floatFromInt(payload)) * 1e6 / @as(f64, @floatFromInt(e.srtt_us));
    }

    pub fn stats(e: *const Endpoint) TransportError!EndpointStats {
        var s = e.stats_;
        s.in_flight = @intCast(e.sw.next - e.sw.lower);
        return s;
    }
};
