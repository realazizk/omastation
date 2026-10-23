//! Send window and network estimates for a connection's TCP output, following
//! a Windows server's continuous auto-detect (MS-RDPBCGR 2.2.14). Pure bookkeeping;
//! flow.zig writes the PDUs. Units: ms, kbit/s (f64), bytes (u32).

const std = @import("std");

/// The unit of TCP output: a 1600-byte channel chunk.
pub const chunk: u32 = 1600;
pub const max_probes: u32 = 20;
/// "No RTT yet": UINT_MAX as a double.
pub const unknown_rtt: f64 = 4294967295.0;
/// Upper bound on a bandwidth sample (kbit/s, 100 Gbit/s); results are client-supplied.
pub const max_sample_kbps: f64 = 100_000_000;

/// Latency control parameters, with a Windows server's defaults.
pub const Params = struct {
    smart_latency: bool = true,
    /// Ideal and maximum queueing delay (ms).
    ideal_ms: u32 = 100,
    max_ms: u32 = 300,
    /// Allowed bandwidth drop range and window drop rate (percent).
    drop_min_pct: u32 = 10,
    drop_max_pct: u32 = 30,
    wnd_drop_pct: u32 = 20,
    /// Link time between RTT probes (ms).
    impact_ms: u32 = 15,
    /// Minimum send window, bytes.
    min_window: u32 = 4800,
};

/// An RTT Measure Request in flight; `bytes`: written since the previous one.
pub const Probe = struct { seq: u16, sent_ns: u64, bytes: u32 };

pub const Answer = struct {
    /// now - sent, whole ms.
    rtt_ms: u32,
    /// Older probes taken as answered with it.
    skipped: u32,
    /// Probes sent after it and still outstanding.
    newer: u32,
    bytes: u32,
};

pub const LatencyState = enum(u8) { normal = 0, congested = 1, dropped = 2 };

pub const Detector = struct {
    p: Params = .{},

    window: u32 = 0x9000,
    /// Written, not yet covered by an answered probe.
    in_flight: u32 = 0,
    since_probe: u32 = 0,
    since_avail: u32 = 0,
    /// When availableBytes was last called (ms; 0: never).
    avail_ms: i64 = 0,
    probe_due: bool = false,

    probes: [max_probes]Probe = undefined,
    probes_sent: u32 = 0,
    probes_done: u32 = 0,
    outstanding: u32 = 0,

    /// The lowest RTT seen (no decay).
    base: f64 = unknown_rtt,
    /// A continuous sample set the base.
    base_known: bool = false,
    /// Smoothed RTT (EWMA 0.05), the published RTT metric.
    srtt: f64 = 0,
    /// The same EWMA, restarted from rtt_win at every RTT evaluation.
    srtt_fast: f64 = 0,
    period_min: f64 = unknown_rtt,
    /// The RTT the window is sized from.
    rtt_win: u32 = 0,
    /// Queueing delay at the last bandwidth evaluation.
    prev_delay: u32 = 0,
    /// Latency control state, the bandwidth when it became congested, evaluations while dropped.
    lc_state: LatencyState = .normal,
    lc_entry_bw: f64 = 0,
    lc_evals: u32 = 0,

    /// kbit/s: the estimate, and the published value the window and graphics rate use.
    bw: f64 = 0,
    published: f64 = 0,
    /// Until the first result `bw` is a seed. Invariant: `bw` changes only on measurements;
    /// evaluations change `published` alone.
    bw_measured: bool = false,

    /// availableBytes calls between RTT / bandwidth evaluations (4, then 10 / 20, doubling up to 100 / 200), and calls since.
    n1: u32 = 4,
    n2: u32 = 4,
    c1: u32 = 0,
    c2: u32 = 0,
    start_phase: bool = true,
    /// Bandwidth averaged with weight 0.8 (the first 21 samples).
    slow_avg: bool = true,
    /// Short-term samples since the cadence last doubled.
    samples: u32 = 0,

    /// Probe payload (1600 .. 32000 bytes).
    payload: u32 = 1600,
    /// This flush is measured; a Start / Stop went in it.
    active: bool = false,
    start_sent: bool = false,
    stop_sent: bool = false,
    /// Bytes of the flush still to go, and since the Start.
    flush_left: u32 = 0,
    since_start: u32 = 0,
    /// Consecutive flushes smaller than the payload; whether the last small flush was measured.
    small_flushes: u32 = 0,
    small_measured: bool = false,

    /// Results under 3 ms, over 500 ms, and of 0 ms skipped.
    short_n: u32 = 0,
    long_n: u32 = 0,
    zero_n: u32 = 0,
    stops_out: i32 = 0,
    /// Short-term sums and the time they must span (ms).
    acc_ms: u32 = 0,
    acc_bytes: u32 = 0,
    min_acc_ms: u32 = 30,
    lt_ms: u32 = 0,
    lt_bytes: u32 = 0,
    lt_n: u32 = 0,

    /// Since the last output line (Conn.logOutput resets it), and over the connection.
    stats: Stats = .{},
    life: Stats = .{},

    pub const Stats = struct {
        probes: u32 = 0,
        answers: u32 = 0,
        /// Most probes newer than an answered one, highest RTT and queueing delay (ms).
        max_newer: u32 = 0,
        max_rtt_ms: u32 = 0,
        max_delay_ms: u32 = 0,
        bw_samples: u32 = 0,
        max_in_flight: u32 = 0,
    };

    pub fn queueingDelayMs(d: *const Detector) u32 {
        if (d.srtt <= d.base) return 0;
        return toU32(d.srtt - d.base);
    }

    pub fn bytesPerSecond(d: *const Detector) f64 {
        return d.published * 1000.0 * 0.125;
    }

    /// True when an RTT Measure Request is due; the caller writes one and calls `probeSent`.
    pub fn onWrite(d: *Detector, n: u32) bool {
        d.in_flight +|= n;
        d.since_probe +|= n;
        d.since_avail +|= n;
        for ([_]*Stats{ &d.stats, &d.life }) |st| st.max_in_flight = @max(st.max_in_flight, d.in_flight);
        const by_rate = toU32(@as(f64, @floatFromInt(d.p.impact_ms)) * d.published * 0.125);
        const thr = @min(d.window -% chunk, by_rate);
        if (thr <= d.since_probe) d.probe_due = true;
        return d.probe_due and d.outstanding < max_probes;
    }

    pub fn probeSent(d: *Detector, seq: u16, now_ns: u64) void {
        std.debug.assert(d.outstanding < max_probes);
        d.probes[d.probes_sent % max_probes] = .{ .seq = seq, .sent_ns = now_ns, .bytes = d.since_probe };
        d.since_probe = 0;
        d.probe_due = false;
        d.probes_sent +%= 1;
        d.outstanding += 1;
        for ([_]*Stats{ &d.stats, &d.life }) |st| st.probes +%= 1;
    }

    pub fn probeOutstanding(d: *const Detector, seq: u16) bool {
        var i: u32 = 0;
        while (i < d.outstanding) : (i += 1) {
            if (d.probes[(d.probes_done +% i) % max_probes].seq == seq) return true;
        }
        return false;
    }

    /// Older outstanding probes count as answered with it; null for a sequence number not outstanding.
    pub fn onRttResponse(d: *Detector, seq: u16, now_ns: u64) ?Answer {
        var skipped_bytes: u32 = 0;
        var i: u32 = 0;
        while (i < d.outstanding) : (i += 1) {
            const p = d.probes[(d.probes_done +% i) % max_probes];
            if (p.seq != seq) {
                skipped_bytes +|= p.bytes;
                continue;
            }
            d.probes_done +%= i + 1;
            d.outstanding -= i + 1;
            const covered = skipped_bytes +| p.bytes;
            d.in_flight -|= covered;
            const rtt: u32 = @intCast(@min((now_ns -| p.sent_ns) / std.time.ns_per_ms, std.math.maxInt(u32)));
            const r: f64 = @floatFromInt(rtt);
            if (r < d.base) d.setNewBaseRtt(r);
            d.onRttUpdate(rtt);
            for ([_]*Stats{ &d.stats, &d.life }) |st| {
                st.answers +%= 1;
                st.max_newer = @max(st.max_newer, d.outstanding);
                st.max_rtt_ms = @max(st.max_rtt_ms, rtt);
                st.max_delay_ms = @max(st.max_delay_ms, d.queueingDelayMs());
            }
            return .{ .rtt_ms = rtt, .skipped = i, .newer = d.outstanding, .bytes = covered };
        }
        return null;
    }

    /// Expired probes' bytes count as acknowledged, so a silent client cannot keep the window shut.
    pub fn expireProbes(d: *Detector, now_ns: u64, max_age_ns: u64) u32 {
        var n: u32 = 0;
        while (d.outstanding > 0) {
            const p = d.probes[d.probes_done % max_probes];
            if (now_ns -| p.sent_ns <= max_age_ns) break;
            d.in_flight -|= p.bytes;
            d.probes_done +%= 1;
            d.outstanding -= 1;
            n += 1;
        }
        return n;
    }

    fn setNewBaseRtt(d: *Detector, rtt: f64) void {
        if (rtt < 0) return;
        d.base = rtt;
        d.period_min = rtt;
    }

    pub fn onRttUpdate(d: *Detector, rtt_ms: u32) void {
        const r: f64 = @floatFromInt(rtt_ms);
        if (r < d.base or !d.base_known) {
            if (d.start_phase and rtt_ms > 10) d.startSteadyUpdateFrequency();
            d.base_known = true;
            d.setNewBaseRtt(r);
        }
        d.period_min = @min(d.period_min, r);
        d.srtt_fast = r * 0.05000000000000004 + d.srtt_fast * 0.95;
        d.srtt = d.srtt * 0.95 + r * 0.05000000000000004;
    }

    /// Once: evaluate less often.
    fn startSteadyUpdateFrequency(d: *Detector) void {
        if (!d.start_phase) return;
        d.start_phase = false;
        d.n1 = @max(d.n1, 10);
        d.n2 = @max(d.n2, 20);
    }

    /// With at most one probe out, bytes since the last availableBytes drained at the published rate.
    pub fn bytesInFlight(d: *const Detector, now_ms: i64) u32 {
        var bif = d.in_flight;
        if (d.outstanding < 2) {
            const el: u32 = if (d.avail_ms != 0) @intCast(std.math.clamp(now_ms -| d.avail_ms, 0, std.math.maxInt(u32))) else 0;
            const drained = @min(toU32(@as(f64, @floatFromInt(el)) * d.published * 0.125), d.since_avail);
            bif -|= drained;
        }
        return bif;
    }

    /// Window minus in flight, at least 1600 when no probe is out (the next write carries one).
    pub fn availableBytes(d: *Detector, now_ms: i64) u32 {
        const w = d.window;
        d.c1 +%= 1;
        d.c2 +%= 1;
        d.adjustNetworkMetrics(now_ms);
        const bif = d.bytesInFlight(now_ms);
        var avail: u32 = if (bif < w) w - bif else 0;
        if (avail < chunk and d.outstanding == 0) {
            d.probe_due = true;
            avail = chunk;
        }
        d.avail_ms = if (now_ms != 0) now_ms else 1;
        d.since_avail = 0;
        return avail;
    }

    /// Every n1 calls re-evaluates rtt_win, every n2 the bandwidth (a decrease is kept only if the
    /// queueing delay grew; +10 % creep at <= 256 kbit/s while half the window is used without delay).
    fn adjustNetworkMetrics(d: *Detector, now_ms: i64) void {
        var changed = false;
        if (d.n1 <= d.c1) {
            const fast: u32 = toU32(d.srtt_fast);
            const pmin: u32 = @min(fast, toU32(d.period_min));
            if (d.period_min < 60000.0) {
                d.smartUpdateRecentBaseRtt(fast, pmin);
                d.c1 = 0;
                d.period_min = 60000.0;
                changed = true;
                d.srtt_fast = @floatFromInt(d.rtt_win);
            }
        }
        // A queueing delay growing past the ideal forces an early bandwidth evaluation.
        if (d.srtt > d.base and d.c2 < d.n2) {
            const thr = @max(d.n2 >> 1, 20);
            const delay = toU32(d.srtt - d.base);
            if (thr < d.c2 and d.p.ideal_ms < d.prev_delay and d.prev_delay < delay) d.c2 = d.n2;
        }
        if (d.n2 <= d.c2) {
            const delay: u32 = if (d.srtt > d.base) toU32(d.srtt - d.base) else 0;
            // `bw` itself is not changed (bw_measured).
            var target = d.bw;
            if (target < d.published) {
                if (d.prev_delay < delay or d.lc_state == .congested) {
                    if (d.slow_avg) d.payload = calculateProbePayload(toU32(target));
                } else {
                    target = d.published;
                }
            }
            if (target <= 256.0 and d.window >> 1 < d.bytesInFlight(now_ms) and delay < 31) {
                target *= @as(f64, @as(f32, 1.1));
            }
            if (target != d.published) {
                d.published = target;
                changed = true;
                if (!d.slow_avg) d.payload = calculateProbePayload(toU32(target));
            }
            d.c2 = 0;
            d.prev_delay = delay;
        }
        if (changed) d.adjustWindowSize();
    }

    pub fn setNewBandwidth(d: *Detector, kbps: f64) void {
        d.bw = kbps;
        d.published = kbps;
    }

    /// rtt_win from the recent RTT and the period's lowest, capped at base + Ideal/2 early and
    /// base + Max later; latency control pulls it down while the delay stays above base + Ideal - 10.
    fn smartUpdateRecentBaseRtt(d: *Detector, fast: u32, pmin: u32) void {
        const base = d.base;
        const t_low: u32 = toU32Wrap(@as(f64, @floatFromInt(d.p.ideal_ms)) + base) -% 10;
        var r: u32 = if (fast <= pmin +| 45) pmin else fast;
        var t_max: u32 = toU32Wrap(@as(f64, @floatFromInt(d.p.max_ms)) + base);
        const bw = d.bw;
        if (d.n1 < 100) {
            t_max = toU32Wrap(@as(f64, @floatFromInt(d.p.ideal_ms >> 1)) + base);
        } else if (d.p.smart_latency) switch (d.lc_state) {
            .normal => if (t_low < d.rtt_win and t_low < r) {
                d.lc_state = .congested;
                d.lc_entry_bw = 0;
            },
            .congested => {
                if (d.lc_entry_bw == 0) d.lc_entry_bw = bw;
                const entry = d.lc_entry_bw;
                if (bw < @as(f64, @floatFromInt(100 - d.p.drop_max_pct)) * entry / 100.0 or bw <= 192.0) {
                    d.lc_state = .dropped;
                    r = pct(d.rtt_win, d.p.wnd_drop_pct + 100);
                } else if (@as(f64, @floatFromInt(100 - d.p.drop_min_pct)) * entry / 100.0 < bw or 20480.0 < bw) {
                    r = pct(d.rtt_win, 100 - d.p.wnd_drop_pct);
                } else {
                    r = if (d.rtt_win > 9) d.rtt_win - 10 else d.rtt_win;
                }
                if (r < t_low) d.lc_state = .normal;
            },
            .dropped => {
                var evals: u32 = 0;
                if (r < t_low) {
                    d.lc_state = .normal;
                } else if (fast +| 45 < d.rtt_win or d.lc_evals == 5) {
                    d.lc_entry_bw = bw;
                    d.lc_state = .congested;
                } else {
                    evals = d.lc_evals + 1;
                    r = fast;
                }
                d.lc_evals = evals;
            },
        };
        d.rtt_win = @min(r, t_max);
    }

    /// roundup((max(rtt_win, 20|30) + 25 ms headroom) x bandwidth / 8, 1600), at
    /// least the minimum; no headroom once queueing delay + 25 reaches the ideal.
    pub fn adjustWindowSize(d: *Detector) void {
        const floor: u32 = if (toU32Wrap(d.base) < 11) 20 else 30;
        const kbps: f64 = if (d.published <= 256.0) 256.0 else d.published;
        const rw = @max(d.rtt_win, floor);
        // Compared unsigned: a negative delay wraps and drops the headroom too.
        const delay_i: i64 = @intFromFloat(std.math.clamp(d.srtt - d.base, -4.0e9, 4.0e9));
        const delay32: u32 = @truncate(@as(u64, @bitCast(delay_i)));
        const head: u32 = if (d.p.ideal_ms <= delay32 +% 25) 0 else 25;
        const bytes = @as(f64, @floatFromInt(rw +| head)) * kbps * 0.125;
        const units = toU32((bytes + 1600.0 - 1.0) / 1600.0);
        d.window = @max(units *| chunk, d.p.min_window);
    }

    /// Flushes of 1600 bytes or more are measured; ones smaller than the payload only when they keep coming.
    pub fn preFlush(d: *Detector, total: u32) void {
        if (d.samples > 20) {
            // After 21 samples: weight 0.92, evaluations half as often.
            if (d.start_phase) d.startSteadyUpdateFrequency();
            d.slow_avg = false;
            d.samples = 0;
            d.n2 = @min(d.n2 * 2, 200);
            d.n1 = @min(d.n1 * 2, 100);
        }
        if (total < chunk) return;
        if (total < d.payload) {
            d.small_flushes +|= 1;
            d.active = false;
            if (d.small_flushes < 3) return;
            if (total < d.payload >> 1 and d.small_flushes < 10) return;
            if (total < 4000) return;
        }
        var measured_small = false;
        if (total < 2000 and toU32(d.bw) < 0x301) {
            if (d.small_measured) {
                d.small_measured = false;
                return;
            }
            measured_small = true;
        }
        d.small_measured = measured_small;
        d.small_flushes = 0;
        d.active = true;
        d.flush_left = total;
        d.start_sent = false;
        d.stop_sent = false;
    }

    /// Before a work item. True: write a Bandwidth Measure Start now.
    pub fn preFlushItem(d: *Detector) bool {
        if (!d.active or d.start_sent) return false;
        d.since_start = 0;
        d.stop_sent = false;
        d.start_sent = true;
        return true;
    }

    /// True: write a Bandwidth Measure Stop now; max(payload, 2000) bytes went since the Start and as many remain.
    pub fn postFlushItem(d: *Detector, n: u32) bool {
        if (!d.active or !d.start_sent) return false;
        d.flush_left -|= n;
        if (d.stop_sent) return false;
        const thr = @max(d.payload, 2000);
        d.since_start +|= n;
        if (thr <= d.since_start and thr <= d.flush_left) {
            d.endProbe();
            return true;
        }
        return false;
    }

    /// The flush is written. True: write the Stop of a measurement still open.
    pub fn postFlush(d: *Detector) bool {
        var stop = false;
        if (d.active and d.start_sent and !d.stop_sent) {
            d.endProbe();
            stop = true;
        }
        d.active = false;
        d.flush_left = 0;
        return stop;
    }

    fn endProbe(d: *Detector) void {
        d.since_start = 0;
        d.start_sent = false;
        d.stop_sent = true;
        d.stops_out +|= 1;
    }

    /// timeDelta ms, byteCount. Summed until they span 30 ms (or 600 results over 5 s long-term),
    /// then averaged into the estimate. Returns the sample (kbit/s) when one was taken.
    pub fn onBwResults(d: *Detector, time_delta: u32, byte_count: u32) ?f64 {
        var a: f64 = if (d.slow_avg) 0.8 else 0.92;
        const min_bytes = @min(d.payload, chunk);
        d.stops_out -|= 1;
        if (byte_count < min_bytes) return null;
        var time = time_delta;
        var overhead: u32 = 100;
        var force = false;
        if (time < 3) {
            if (time == 0 and d.zero_n < 16 and
                ((!d.slow_avg and toU32(d.bw) < 0x1389) or (!d.start_phase and toU32(d.bw) < 0x200)))
            {
                d.zero_n += 1;
                return null;
            }
            if (d.payload <= byte_count) {
                if (d.short_n < 3) {
                    d.short_n += 1;
                } else {
                    d.payload = if (d.payload < 2000) 4000 else @min(d.payload * 2, 32000);
                    d.short_n = 0;
                    if (d.start_phase) {
                        if (toU32(d.bw) < 4000) force = true else d.startSteadyUpdateFrequency();
                    }
                }
                if (4000 < d.payload) time +|= 1;
            }
            overhead = 0;
            if (time == 0) time = 1;
        } else if (500 < time) {
            if (d.long_n < 3) {
                d.long_n += 1;
            } else {
                var p = @min(d.payload >> 1, byte_count);
                if (p < 0x641) p = chunk;
                d.long_n = 0;
                d.payload = p;
            }
        }
        if (d.short_n != 0 and 2 < time) d.short_n -= 1;
        if (d.long_n != 0 and time < 500) d.long_n -= 1;
        // Client-supplied values: the sums saturate.
        d.lt_ms +|= time;
        d.lt_bytes +|= byte_count +| overhead;
        d.lt_n +|= 1;
        d.acc_ms +|= time;
        d.acc_bytes +|= byte_count +| overhead;
        const long_term = d.lt_n >= 600 and d.lt_ms >= 5000;
        if (!force and d.acc_ms < d.min_acc_ms and !long_term) return null;
        d.zero_n = 0;
        var sample: f64 = undefined;
        if (long_term) {
            a = 0.8;
            d.c2 = 200;
            sample = @floatCast(@as(f32, @floatFromInt(d.lt_bytes)) * 8.0 / @as(f32, @floatFromInt(d.lt_ms)));
            d.lt_ms = toU32(@as(f64, @floatFromInt(d.lt_ms)) * @as(f64, @as(f32, 0.1)));
            d.lt_n = toU32(@as(f64, @floatFromInt(d.lt_n)) * @as(f64, @as(f32, 0.1)));
            d.lt_bytes = toU32(@as(f64, @floatFromInt(d.lt_bytes)) * @as(f64, @as(f32, 0.1)));
        } else {
            d.samples +|= 1;
            sample = @floatCast(@as(f32, @floatFromInt(d.acc_bytes)) * 8.0 / @as(f32, @floatFromInt(d.acc_ms)));
        }
        if (d.bw < sample and d.base_known) {
            const delay = toU32(d.srtt - d.base);
            if (d.prev_delay == 0 or delay <= d.prev_delay or delay <= d.p.ideal_ms) {
                if (!d.slow_avg) {
                    if (sample >= d.bw * 6.0) {
                        a += 0.06;
                    } else if (sample > d.bw + d.bw) {
                        a += sample / d.bw / 100.0;
                    }
                }
            } else {
                // The queueing delay grows: increases only slowly.
                if (d.start_phase) d.startSteadyUpdateFrequency();
                a = 0.9 + 0.07000000000000001;
            }
        }
        // Bound client-supplied samples (u32 bytes over 1 ms is 34 Tbit/s).
        sample = @min(sample, max_sample_kbps);
        d.bw = if (d.bw_measured) (1.0 - a) * sample + a * d.bw else sample;
        d.bw_measured = true;
        if (d.min_acc_ms > 30) d.min_acc_ms = @max(d.min_acc_ms >> 1, 30);
        d.acc_ms = 0;
        d.acc_bytes = 0;
        for ([_]*Stats{ &d.stats, &d.life }) |st| st.bw_samples +%= 1;
        return sample;
    }

    /// From connect-time detection. `measured`: `kbps` was measured, not a default.
    pub fn seed(d: *Detector, base_ms: ?u32, avg_ms: ?u32, kbps: ?u64, measured: bool) void {
        if (kbps) |b| {
            // Connect-time bandwidth is client-supplied too: bound it like samples.
            d.setNewBandwidth(@min(@max(@as(f64, @floatFromInt(b)), d.bw), max_sample_kbps));
            d.bw_measured = measured;
        }
        if (base_ms) |b| {
            const base: f64 = @max(1.0, @as(f64, @floatFromInt(b)));
            d.setNewBaseRtt(base);
            d.rtt_win = toU32(base);
            const avg: f64 = if (avg_ms) |v| @floatFromInt(v) else base;
            d.srtt = avg;
            d.srtt_fast = avg;
        }
        d.adjustWindowSize();
    }
};

/// 10 ms of data at `kbps` (20 ms above 768 kbit/s), whole thousands, 1600 .. 32000.
pub fn calculateProbePayload(kbps: u32) u32 {
    const k: u32 = if (kbps > 0x300) 20 else 10;
    const v = ((k * (kbps >> 3) + 599) / 1000) * 1000;
    if (v <= chunk) return chunk;
    return @min(v, 32000);
}

fn pct(v: u32, p: u32) u32 {
    return @intCast(@min(@as(u64, v) * p / 100, std.math.maxInt(u32)));
}

/// Truncates x to u32, saturating; negative or NaN is 0.
fn toU32(x: f64) u32 {
    if (!(x > 0)) return 0;
    if (x >= 4294967295.0) return std.math.maxInt(u32);
    return @intFromFloat(x);
}

/// Truncates x and keeps the low 32 bits, as a Windows server computes it.
fn toU32Wrap(x: f64) u32 {
    const v: i64 = @intFromFloat(std.math.clamp(x, -9.0e18, 9.0e18));
    return @truncate(@as(u64, @bitCast(v)));
}

const testing = std.testing;

fn seeded(base: u32, avg: u32, kbps: u64) Detector {
    var d: Detector = .{};
    d.seed(base, avg, kbps, true);
    return d;
}

test "window: roundup((max(RTTwin, 20|30) + 25) x bw / 8, 1600), at least 4800" {
    // Base 65 ms, 4 Mbit/s: (65 + 25) x 500 B/ms = 45000 -> 46400.
    var d = seeded(65, 65, 4000);
    try testing.expectEqual(@as(u32, 46400), d.window);
    // RTTwin up to base + 50 early on: 115 + 25 -> 70 KB.
    d.rtt_win = 115;
    d.adjustWindowSize();
    try testing.expectEqual(@as(u32, 70400), d.window);
    // No headroom once (srtt - base) + 25 reaches the ideal delay.
    d.srtt = d.base + 75;
    d.adjustWindowSize();
    try testing.expectEqual(@as(u32, 57600), d.window); // 115 x 500 = 57500
    // A LAN: base 1 ms (floor 20), 1 Gbit/s: (20 + 25) x 125000 = 5.6 MB.
    const lan = seeded(1, 1, 1_000_000);
    try testing.expectEqual(@as(u32, 5_625_600), lan.window);
    const slow = seeded(40, 40, 100);
    try testing.expectEqual(@as(u32, 4800), slow.window); // (40+25) x 32 = 2080
    const unseeded: Detector = .{};
    try testing.expectEqual(@as(u32, 0x9000), unseeded.window);
}

test "bytes in flight: written minus what answered probes cover; a probe every 15 ms x bw" {
    var d = seeded(65, 65, 4000); // 15 ms x 500 B/ms = 7500 bytes per probe
    const ms = std.time.ns_per_ms;
    try testing.expect(!d.onWrite(5000));
    try testing.expect(d.onWrite(3000)); // 8000 >= 7500: a probe now
    d.probeSent(7, 100 * ms);
    try testing.expectEqual(@as(u32, 8000), d.in_flight);
    try testing.expect(!d.onWrite(1600));
    try testing.expect(d.onWrite(6000));
    d.probeSent(8, 110 * ms);
    try testing.expect(!d.onWrite(100));
    try testing.expectEqual(@as(u32, 15700), d.in_flight);
    const a = d.onRttResponse(8, 180 * ms).?;
    try testing.expectEqual(@as(u32, 70), a.rtt_ms);
    try testing.expectEqual(@as(u32, 1), a.skipped);
    try testing.expectEqual(@as(u32, 0), a.newer);
    try testing.expectEqual(@as(u32, 15600), a.bytes);
    try testing.expectEqual(@as(u32, 100), d.in_flight);
    try testing.expectEqual(@as(u32, 0), d.outstanding);
    try testing.expectEqual(@as(?Answer, null), d.onRttResponse(7, 190 * ms));
    var seq: u16 = 100;
    while (d.outstanding < max_probes) : (seq += 1) {
        try testing.expect(d.onWrite(8000));
        d.probeSent(seq, 200 * ms);
    }
    try testing.expect(!d.onWrite(8000));
    try testing.expect(d.probe_due);
}

test "probes unanswered past the timeout are lost: bytes leave in flight, no RTT sample" {
    var d = seeded(65, 65, 4000);
    const ms = std.time.ns_per_ms;
    _ = d.onWrite(8000);
    d.probeSent(1, 100 * ms);
    _ = d.onWrite(8000);
    d.probeSent(2, 5000 * ms);
    _ = d.onWrite(500);
    const srtt = d.srtt;
    try testing.expectEqual(@as(u32, 0), d.expireProbes(10_000 * ms, 10_000 * ms));
    try testing.expectEqual(@as(u32, 1), d.expireProbes(10_101 * ms, 10_000 * ms));
    try testing.expectEqual(@as(u32, 8500), d.in_flight);
    try testing.expectEqual(@as(u32, 1), d.outstanding);
    try testing.expectEqual(srtt, d.srtt);
    const a = d.onRttResponse(2, 5070 * ms).?;
    try testing.expectEqual(@as(u32, 70), a.rtt_ms);
    try testing.expectEqual(@as(u32, 500), d.in_flight);
}

test "available bytes: window - in flight, 1600 with no probe out; the time since the last call drains at bw with at most one probe out" {
    var d = seeded(65, 65, 4000);
    try testing.expectEqual(@as(u32, 46400), d.availableBytes(1000));
    _ = d.onWrite(46400);
    try testing.expectEqual(@as(u32, 5000), d.availableBytes(1010));
    d.probeSent(1, 1010 * std.time.ns_per_ms);
    d.probeSent(2, 1010 * std.time.ns_per_ms);
    try testing.expectEqual(@as(u32, 0), d.availableBytes(1020));
    _ = d.onRttResponse(2, 1085 * std.time.ns_per_ms);
    try testing.expectEqual(@as(u32, 46400), d.availableBytes(1085));
    _ = d.onWrite(100_000);
    d.probe_due = false;
    d.since_probe = 0;
    try testing.expectEqual(@as(u32, chunk), d.availableBytes(1086));
    try testing.expect(d.probe_due);
}

test "RTT: base the lowest ever, srtt an EWMA of 0.05, queueing delay srtt - base" {
    var d = seeded(60, 60, 4000);
    d.onRttUpdate(70);
    try testing.expectEqual(@as(f64, 70), d.base);
    try testing.expect(d.base_known);
    try testing.expectApproxEqAbs(@as(f64, 60 * 0.95 + 70 * 0.05), d.srtt, 1e-9);
    d.onRttUpdate(65);
    try testing.expectEqual(@as(f64, 65), d.base);
    for (0..200) |_| d.onRttUpdate(265);
    try testing.expect(d.srtt > 264 and d.srtt < 265);
    try testing.expectEqual(@as(u32, 199), d.queueingDelayMs());
    try testing.expectEqual(@as(u32, 10), d.n1);
    try testing.expectEqual(@as(u32, 20), d.n2);
}

test "bandwidth: results summed to 30 ms, then EWMA 0.8 for the first 21 samples, 0.92 after" {
    var d = seeded(65, 65, 4000);
    d.onRttUpdate(65);
    d.stops_out = 100;
    try testing.expectEqual(@as(?f64, null), d.onBwResults(10, 5000));
    try testing.expectEqual(@as(?f64, null), d.onBwResults(10, 5000));
    const s = d.onBwResults(10, 5000).?;
    try testing.expectApproxEqAbs(@as(f64, 15300.0 * 8.0 / 30.0), s, 1e-3);
    try testing.expectApproxEqAbs(0.2 * s + 0.8 * 4000.0, d.bw, 1e-6);
    const pub0 = d.published;
    for (0..30) |_| _ = d.onBwResults(10, 2500);
    try testing.expect(d.bw < pub0);
    try testing.expectEqual(pub0, d.published);
    const before = d.bw;
    try testing.expectEqual(@as(?f64, null), d.onBwResults(10, 1000));
    try testing.expectEqual(before, d.bw);
}

test "bandwidth: a decrease is published only if the queueing delay grew" {
    var d = seeded(65, 65, 4000);
    d.onRttUpdate(65);
    d.srtt = 66;
    var t: i64 = 1000;
    for (0..d.n2) |_| {
        _ = d.availableBytes(t);
        t += 1;
    }
    try testing.expectEqual(@as(u32, 1), d.prev_delay);
    // A lower estimate while the delay holds is not published; bw keeps the measured average.
    d.bw = 2000;
    for (0..d.n2) |_| {
        _ = d.availableBytes(t);
        t += 1;
    }
    try testing.expectEqual(@as(f64, 4000), d.published);
    try testing.expectEqual(@as(f64, 2000), d.bw);
    // The delay grows: the decrease is published and the window shrinks.
    const w0 = d.window;
    d.srtt = 150;
    d.bw = 2000;
    for (0..d.n2) |_| {
        _ = d.availableBytes(t);
        t += 1;
    }
    try testing.expectEqual(@as(f64, 2000), d.published);
    try testing.expect(d.window < w0);
}

test "latency control: RTTwin bounded to base + 50 at first, later pulled down while the delay exceeds base + 90" {
    var d = seeded(65, 65, 4000);
    d.smartUpdateRecentBaseRtt(400, 380);
    try testing.expectEqual(@as(u32, 115), d.rtt_win);
    d.n1 = 100;
    d.smartUpdateRecentBaseRtt(400, 380);
    try testing.expectEqual(LatencyState.normal, d.lc_state);
    try testing.expectEqual(@as(u32, 365), d.rtt_win);
    d.smartUpdateRecentBaseRtt(400, 380);
    try testing.expectEqual(LatencyState.congested, d.lc_state);
    try testing.expectEqual(@as(u32, 365), d.rtt_win);
    d.bw = 4000;
    d.smartUpdateRecentBaseRtt(400, 380);
    try testing.expectEqual(@as(u32, 292), d.rtt_win);
    d.smartUpdateRecentBaseRtt(400, 380);
    try testing.expectEqual(@as(u32, 233), d.rtt_win);
    d.smartUpdateRecentBaseRtt(400, 380);
    try testing.expectEqual(@as(u32, 186), d.rtt_win);
    d.smartUpdateRecentBaseRtt(400, 380);
    try testing.expectEqual(@as(u32, 148), d.rtt_win);
    try testing.expectEqual(LatencyState.normal, d.lc_state);
    d.lc_state = .congested;
    d.lc_entry_bw = 4000;
    d.rtt_win = 200;
    d.bw = 2000;
    d.smartUpdateRecentBaseRtt(400, 380);
    try testing.expectEqual(LatencyState.dropped, d.lc_state);
    try testing.expectEqual(@as(u32, 240), d.rtt_win);
}

test "bandwidth probes: Start before the first item of a flush >= 1600 bytes, Stop after max(payload, 2000)" {
    var d = seeded(65, 65, 4000);
    d.preFlush(1000);
    try testing.expect(!d.preFlushItem());
    try testing.expect(!d.postFlush());
    d.preFlush(10000);
    var starts: u32 = 0;
    var stops: u32 = 0;
    var left: u32 = 10000;
    while (left > 0) {
        const n = @min(left, 1600);
        if (d.preFlushItem()) starts += 1;
        left -= n;
        if (d.postFlushItem(n)) stops += 1;
    }
    if (d.postFlush()) stops += 1;
    try testing.expectEqual(starts, stops);
    try testing.expectEqual(@as(u32, 3), starts);
    try testing.expectEqual(@as(i32, 3), d.stops_out);
    d.stops_out = 10;
    for (0..4) |_| _ = d.onBwResults(1, 2000);
    try testing.expectEqual(@as(u32, 4000), d.payload);
    try testing.expectEqual(@as(u32, 20000), calculateProbePayload(8000));
    try testing.expectEqual(@as(u32, chunk), calculateProbePayload(300));
    try testing.expectEqual(@as(u32, 32000), calculateProbePayload(100_000));
}

/// Simulated link (`rate` bytes/ms, `rtt` ms) with an ideal client; flushes every 33 ms as flow.zig does.
const TestLink = struct {
    d: *Detector,
    rate: u32,
    rtt: u64,
    seq: u16 = 0,
    now_ms: i64 = 1000,

    fn flush(l: *TestLink, size: u32) !void {
        const d = l.d;
        const ns = @as(u64, @intCast(l.now_ms)) * std.time.ns_per_ms;
        const avail = d.availableBytes(l.now_ms);
        const total = @min(avail, size);
        d.preFlush(total);
        var left = total;
        var segment: u32 = 0;
        while (left > 0) {
            const n = @min(left, chunk);
            _ = d.preFlushItem();
            left -= n;
            segment += n;
            if (d.onWrite(n)) {
                d.probeSent(l.seq, ns);
                try testing.expect(d.onRttResponse(l.seq, ns + l.rtt * std.time.ns_per_ms) != null);
                l.seq +%= 1;
            }
            if (d.postFlushItem(n)) {
                _ = d.onBwResults(segment / l.rate, segment);
                segment = 0;
            }
        }
        if (d.postFlush()) _ = d.onBwResults(segment / l.rate, segment);
        l.now_ms += 33;
    }
};

test "busy and idle cycles: the estimate follows only measurements, the window stays bounded" {
    var d = seeded(65, 65, 4000);
    var l: TestLink = .{ .d = &d, .rate = 500, .rtt = 65 }; // 4 Mbit/s
    var cycle: u32 = 0;
    while (cycle < 60) : (cycle += 1) {
        for (0..150) |_| try l.flush(20_000);
        const before = d.published;
        l.now_ms += 10_000;
        _ = d.availableBytes(l.now_ms);
        try testing.expectEqual(before, d.published);
        if (cycle > 0) {
            try testing.expect(d.published > 2000 and d.published < 8000);
            try testing.expect(d.window <= 140 * 1000);
        }
        try testing.expect(std.math.isFinite(d.bw) and std.math.isFinite(d.srtt));
    }
    try testing.expect(d.stats.bw_samples > 100);
}

test "the estimate moves only with measurements; the creep changes only the published value" {
    var d: Detector = .{};
    d.seed(65, 65, 10_000, false);
    d.onRttUpdate(65);
    d.stops_out = 10;
    // The first result (4 Mbit/s over 30 ms) replaces the seed outright.
    const s = d.onBwResults(30, 15_000 - 100).?;
    try testing.expectApproxEqAbs(@as(f64, 4000), s, 1e-6);
    try testing.expectEqual(s, d.bw);
    try testing.expect(d.bw_measured);
    var e = seeded(65, 65, 200);
    e.onRttUpdate(65);
    e.srtt = 65;
    _ = e.onWrite(e.window);
    var t: i64 = 1000;
    for (0..20) |_| for (0..e.n2) |_| {
        _ = e.availableBytes(t);
        t += 1;
        _ = e.onWrite(e.window);
    };
    try testing.expectEqual(@as(f64, 200), e.bw);
    try testing.expect(e.published > 256 and e.published <= 256 * 1.1 + 1e-6);
}

test "client values at their type limits neither overflow nor run away" {
    var d = seeded(65, 65, 4000);
    d.onRttUpdate(65);
    const max = std.math.maxInt(u32);
    var t: i64 = 1000;
    for (0..2000) |_| {
        d.stops_out = 4;
        _ = d.onBwResults(max, max);
        _ = d.onBwResults(1, max);
        _ = d.onBwResults(0, max);
        _ = d.onBwResults(max, 1600);
        _ = d.availableBytes(t);
        t += 1;
        try testing.expect(d.bw <= max_sample_kbps and d.published <= max_sample_kbps);
        try testing.expect(std.math.isFinite(d.bw));
    }
    for (0..10) |_| _ = d.onWrite(max);
    try testing.expectEqual(@as(u32, max), d.in_flight);
    d.probeSent(1, 0);
    _ = d.onRttResponse(1, std.math.maxInt(u64)).?;
    d.n1 = 100;
    d.smartUpdateRecentBaseRtt(max, max);
    d.lc_state = .congested;
    d.rtt_win = max;
    d.smartUpdateRecentBaseRtt(max, max);
    d.adjustWindowSize();
    _ = d.availableBytes(-5);
    _ = d.bytesInFlight(std.math.minInt(i64));
    try testing.expect(d.window >= d.p.min_window);
    var s = seeded(65, 65, 100);
    s.onRttUpdate(65);
    for (0..10_000) |_| {
        _ = s.onWrite(10_000);
        s.c2 = s.n2;
        s.adjustNetworkMetrics(t);
        t += 1;
    }
    try testing.expect(s.published <= 256.0 * 1.1 + 1e-9);
}
