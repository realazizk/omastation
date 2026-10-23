//! Session audio: desktop sound to the client (MS-RDPEA) and the client's microphone
//! into the desktop (MS-RDPEAI). The desk is muted while the session plays elsewhere.

const std = @import("std");
const rdp = @import("../proto/rdp.zig");
const rdpsnd = @import("../channel/rdpsnd.zig");
const audin = @import("../channel/audin.zig");
const audio = @import("../audio/audio.zig");
const vc = @import("vc.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

const log = std.log.scoped(.audio);

/// Where the client wants the session's audio (MS-RDPBCGR 2.2.1.11.1.1).
pub const Mode = enum {
    /// "Play on this computer"; the desk is muted, as Windows plays it on the client only.
    client,
    /// "Leave at remote computer" (INFO_REMOTECONSOLEAUDIO); the desk plays as usual.
    remote,
    /// "Do not play" (INFO_NOAUDIOPLAYBACK); the desk is muted too.
    none,
};

pub fn modeOf(info_flags: u32) Mode {
    if (info_flags & rdp.info_remoteconsoleaudio != 0) return .remote;
    if (info_flags & rdp.info_noaudioplayback != 0) return .none;
    return .client;
}

pub fn wantsMic(info_flags: u32) bool {
    return info_flags & rdp.info_audiocapture != 0;
}

fn available(c: *const Conn) bool {
    return c.vc.opts.audio and (c.vc.opts.audio_backend != null or (c.vc.opts.audio_pipewire and c.desktop != null));
}

/// Restores speakers a previous connection left muted.
fn giveBackDesk(c: *Conn) void {
    const cfg = c.desktop_cfg orelse return;
    const da = cfg.seat.takeDeskAudio() orelse return;
    da.restore(c.gpa);
    log.info("{s}: the desk's speakers are restored (this connection plays nothing on the client)", .{c.peer});
}

fn nowU64() u64 {
    return @intCast(@max(conn_mod.nowMs(), 0));
}

/// MS-RDPEA on AUDIO_PLAYBACK_DVC, or on the rdpsnd static channel when the DVC cannot
/// open (MS-RDPEA 3.1.3). No flow control on Wave Confirms, as on Windows.
pub const AudioPlayback = struct {
    pub const static_channels = [_][]const u8{rdpsnd.static_channel_name};
    /// Real-time priority and no compression, as on Windows; AUDIO_PLAYBACK_LOSSY_DVC is unused.
    pub const dynamic_channels = [_]vc.Dynamic{.{ .name = rdpsnd.dvc_channel_name, .priority = .realtime, .compress = false }};
    pub const Error = rdpsnd.Error || audio.playback.Error;

    conn: *Conn,
    pb: audio.Playback,
    out: rdpsnd.Outbox,
    static_ch: ?vc.Channel = null,
    dvc_ch: ?vc.Channel = null,
    on: ?vc.Channel = null,
    /// Capture runs from the Server Audio Formats on.
    capturing: bool = false,
    announced: bool = false,
    streams_seen: u64 = 0,
    closes_seen: u64 = 0,
    switches_seen: u64 = 0,
    dropped_seen: u64 = 0,
    queue_dropped_seen: u64 = 0,

    pub fn init(c: *Conn) vc.Error!?AudioPlayback {
        if (!available(c) or modeOf(c.info_flags) != .client) return null;
        const pb = try audio.Playback.init(c.gpa, .{
            .formats = c.vc.opts.audio_formats,
            .quality_limit = c.vc.opts.audio_quality,
            .max_bandwidth = c.vc.opts.audio_max_bandwidth,
        });
        return .{ .conn = c, .pb = pb, .out = rdpsnd.Outbox.init(c.gpa) };
    }

    pub fn deinit(p: *AudioPlayback) void {
        p.stopCapture();
        p.pb.deinit();
        p.out.deinit();
    }

    pub fn open(p: *AudioPlayback, ch: vc.Channel) vc.Error!void {
        switch (ch.ref) {
            .static => {
                p.static_ch = ch;
                if (p.on != null) return;
                // Prefer AUDIO_PLAYBACK_DVC; the static channel only when it cannot open.
                if (vc.dvcUnavailable(p.conn)) return p.use(ch);
            },
            .dynamic => {
                if (p.on != null) return ch.close(); // on the static channel already
                p.dvc_ch = ch;
                return p.use(ch);
            },
        }
    }

    pub fn close(p: *AudioPlayback, ch: vc.Channel, why: vc.Closed) void {
        if (ch.ref != .dynamic) return;
        p.dvc_ch = null;
        const was_on = if (p.on) |on| on.ref == .dynamic else false;
        if (was_on) {
            // As on Windows, audio stops for good; nothing moves to the static channel.
            log.info("{s}: the client closed {s}: no more audio on this connection", .{ p.conn.peer, rdpsnd.dvc_channel_name });
            p.stopCapture();
            p.on = null;
            return;
        }
        if (why != .refused) return;
        // Already running on the static channel; initialization runs once (MS-RDPEA 3.1.5).
        if (p.on != null) return;
        if (p.static_ch) |st| {
            p.use(st) catch |e| log.warn("{s}: rdpsnd on the static channel: {t}", .{ p.conn.peer, e });
        } else {
            log.info("{s}: the client has no audio output channel", .{p.conn.peer});
        }
    }

    /// Starts MS-RDPEA on `ch` (MS-RDPEA 3.1.5) and the capture.
    fn use(p: *AudioPlayback, ch: vc.Channel) vc.Error!void {
        p.on = ch;
        log.info("{s}: audio output on {s}", .{ p.conn.peer, if (ch.ref == .dynamic) rdpsnd.dvc_channel_name else "the rdpsnd static channel" });
        try p.pb.start(nowU64(), &p.out);
        try p.flushOut();
        if (vc.find(p.conn, Audio)) |a| {
            try a.br.startCapture(nowU64());
            p.capturing = true;
        }
    }

    fn stopCapture(p: *AudioPlayback) void {
        if (!p.capturing) return;
        p.capturing = false;
        if (vc.find(p.conn, Audio)) |a| a.br.stopCapture();
        const s = p.pb.stats;
        log.info("{s}: audio to the client stopped ({d} waves in {d} streams, {d} confirmed)", .{ p.conn.peer, s.waves, s.streams, s.confirms });
    }

    fn flushOut(p: *AudioPlayback) vc.Error!void {
        defer p.out.clear();
        const ch = p.on orelse return;
        for (p.out.msgs.items) |m| try ch.send(m);
    }

    fn isOn(p: *const AudioPlayback, ch: vc.Channel) bool {
        const on = p.on orelse return false;
        return std.meta.eql(on.ref, ch.ref);
    }

    pub fn data(p: *AudioPlayback, ch: vc.Channel, msg: []const u8) vc.Error!void {
        if (!p.isOn(ch)) return; // the channel not chosen
        const ev = try p.pb.handle(msg, nowU64(), &p.out);
        try p.flushOut();
        switch (ev) {
            .terminated => {
                log.info("{s}: the client listed no audio format: no audio", .{p.conn.peer});
                p.stopCapture();
            },
            // mstsc and FreeRDP confirm every wave twice; stale confirms are not logged.
            .ignored => if (msg.len == 0 or msg[0] != @backingInt(rdpsnd.MsgType.wave_confirm))
                log.debug("{s}: rdpsnd message ignored (MS-RDPEA 3.1.5, type 0x{x:0>2}, {d} bytes)", .{ p.conn.peer, if (msg.len > 0) msg[0] else 0, msg.len }),
            else => {},
        }
        p.note();
    }

    pub fn tick(p: *AudioPlayback, now_ms: i64) vc.Error!?i64 {
        _ = now_ms;
        var next: ?i64 = null;
        if (p.on == null and p.static_ch != null and p.dvc_ch == null) {
            // An unanswered Create Request is waited for, as on Windows.
            if (vc.dvcUnavailable(p.conn)) {
                log.info("{s}: no dynamic channels (no DVC capabilities response): the rdpsnd static channel", .{p.conn.peer});
                try p.use(p.static_ch.?);
            } else if (!p.conn.vc.dvc_ready and p.conn.vc.caps_sent_ms != 0) {
                next = p.conn.vc.caps_sent_ms + vc.dvc_caps_timeout_ms + 1;
            }
        }
        const was = p.pb.srv.st;
        const due = try p.pb.tick(nowU64(), &p.out);
        try p.flushOut();
        if (was != .terminated and p.pb.srv.st == .terminated) {
            log.info("{s}: the client did not complete the audio initialization (MS-RDPEA 3.3.2)", .{p.conn.peer});
            p.stopCapture();
        }
        p.note();
        if (due) |d| {
            const di: i64 = @intCast(@min(d, std.math.maxInt(i64)));
            next = if (next) |n| @min(n, di) else di;
        }
        return next;
    }

    fn note(p: *AudioPlayback) void {
        const srv = &p.pb.srv;
        if (!p.announced and srv.st == .ready) {
            p.announced = true;
            const list = srv.clientFormats() catch &.{};
            const flags = srv.clientFlags() catch 0;
            const version = (srv.clientVersion() catch null) orelse 0;
            if (srv.current) |idx| {
                const f = list[idx];
                log.info("{s}: audio to the client: format {d} of {d} (0x{x:0>4}, {d} Hz, {d} ch, {d} bit, {d} B/s), client version {d}, {t} mode, {d} B/s measured, waves of {d} frames", .{
                    p.conn.peer, idx, list.len, f.tag, f.samples_per_sec, f.channels, f.bits_per_sample, f.avg_bytes_per_sec, version, srv.mode, srv.bw, srv.blockFrames(),
                });
            } else {
                log.warn("{s}: no audio format in common with the client ({d} formats, version {d})", .{ p.conn.peer, list.len, version });
                p.stopCapture();
            }
            if (flags & rdpsnd.TSSNDCAPS_ALIVE == 0)
                log.info("{s}: the client did not say it can play (no TSSNDCAPS_ALIVE, flags 0x{x}): not trained; waves go out all the same, as Windows sends them", .{ p.conn.peer, flags });
        }
        const s = p.pb.stats;
        if (s.streams != p.streams_seen) {
            p.streams_seen = s.streams;
            log.info("{s}: audio stream {d} starts (cBlockNo {d})", .{ p.conn.peer, s.streams, s.stream_block });
        }
        if (s.closes != p.closes_seen) {
            p.closes_seen = s.closes;
            log.info("{s}: audio stream {d} closed: {d} s without sound (Close PDU, {d} waves so far)", .{ p.conn.peer, s.streams, audio.playback.idle_close_ms / 1000, s.waves });
        }
        if (s.switches != p.switches_seen) {
            p.switches_seen = s.switches;
            const list = srv.clientFormats() catch &.{};
            if (srv.current) |idx| log.info("{s}: audio format {d} now (0x{x:0>4}, {d} Hz, {d} ch, {d} B/s): Dynamic mode measured {d} B/s", .{ p.conn.peer, idx, list[idx].tag, list[idx].samples_per_sec, list[idx].channels, list[idx].avg_bytes_per_sec, srv.bw });
        }
        if (vc.find(p.conn, Audio)) |a| {
            const dropped = a.br.captureStats().dropped_frames;
            if (dropped != p.dropped_seen) log.info("{s}: the capture dropped {d} ms of audio (the session did not read it in time)", .{ p.conn.peer, (dropped -| p.dropped_seen) / 48 });
            p.dropped_seen = dropped;
        }
        if (p.pb.queue.dropped != p.queue_dropped_seen) {
            log.info("{s}: {d} ms of audio dropped from the queue of 16 waves (the channel took none)", .{ p.conn.peer, (p.pb.queue.dropped - p.queue_dropped_seen) * 1000 / 44100 });
            p.queue_dropped_seen = p.pb.queue.dropped;
        }
    }

    pub fn pump(p: *AudioPlayback) vc.Error!void {
        if (!p.capturing) return;
        const a = vc.find(p.conn, Audio) orelse return;
        try p.pb.pumpBridge(&a.br, nowU64(), &p.out);
        try p.flushOut();
        p.note();
    }
};

pub const AudioInput = struct {
    pub const dynamic_channels = [_]vc.Dynamic{.{ .name = audin.channel_name }};
    pub const Error = audin.Error || audio.Error;

    conn: *Conn,
    srv: audin.Server,
    out: audin.Outbox,
    ch: ?vc.Channel = null,
    /// Client format index the microphone decoder is set to.
    mic_format: ?u32 = null,
    data_pdus: u64 = 0,
    bad_pdus: u64 = 0,
    next_stats_ms: u64 = 0,

    pub fn init(c: *Conn) vc.Error!?AudioInput {
        if (!available(c) or !wantsMic(c.info_flags)) return null;
        return .{ .conn = c, .srv = audin.Server.init(c.gpa, .{ .formats = &audio.mic_formats }), .out = audin.Outbox.init(c.gpa) };
    }

    pub fn deinit(m: *AudioInput) void {
        m.stopMic();
        m.srv.deinit();
        m.out.deinit();
    }

    pub fn open(m: *AudioInput, ch: vc.Channel) vc.Error!void {
        m.ch = ch;
        try m.srv.start(nowU64(), &m.out);
        try m.flushOut();
    }

    pub fn close(m: *AudioInput, _: vc.Channel, why: vc.Closed) void {
        if (why == .refused) log.info("{s}: the client refused {s}", .{ m.conn.peer, audin.channel_name });
        m.ch = null;
        m.stopMic();
    }

    fn flushOut(m: *AudioInput) vc.Error!void {
        defer m.out.clear();
        const ch = m.ch orelse return;
        for (m.out.msgs.items) |msg| try ch.send(msg);
    }

    pub fn data(m: *AudioInput, _: vc.Channel, msg: []const u8) vc.Error!void {
        const ev = try m.srv.handle(msg, nowU64(), &m.out);
        try m.flushOut();
        switch (ev) {
            .formats_negotiated => |n| {
                const f = (try m.srv.clientFormats())[n.initial_format];
                log.info("{s}: microphone format {d} of {d} (0x{x:0>4}, {d} Hz, {d} ch)", .{ m.conn.peer, n.initial_format, (try m.srv.clientFormats()).len, f.tag, f.samples_per_sec, f.channels });
            },
            .open_result => |hr| {
                if (!try audin.isSuccess(hr)) {
                    log.info("{s}: the client cannot record (Open Reply 0x{x:0>8})", .{ m.conn.peer, hr });
                    return;
                }
                const idx = (try m.srv.currentFormat()) orelse return;
                try m.startMic(idx);
            },
            .audio => |a| {
                m.data_pdus += 1;
                const am = vc.find(m.conn, Audio) orelse return;
                if (m.mic_format != a.format) {
                    am.br.setMicFormat((try m.srv.clientFormats())[a.format]) catch |e| {
                        log.warn("{s}: microphone format {d}: {t}", .{ m.conn.peer, a.format, e });
                        return;
                    };
                    m.mic_format = a.format;
                }
                const now = nowU64();
                am.br.pushMicAt(a.data, now) catch |e| switch (e) {
                    error.OutOfMemory => return e,
                    else => {
                        // Bad data in a Data PDU: dropped (MS-RDPEAI 3.1.5).
                        m.bad_pdus += 1;
                        log.debug("{s}: microphone data dropped ({t})", .{ m.conn.peer, e });
                    },
                };
                if (now >= m.next_stats_ms) {
                    m.next_stats_ms = now + 5000;
                    if (am.br.micStats()) |st| log.debug("{s}: microphone: {d} ms buffered, jitter buffer {d} ms (packets up to {d} ms late), {d} underruns, {d} ms dropped, {d} ms of quiet skipped", .{
                        m.conn.peer,            st.buffered_frames / 48, st.target_frames / 48,
                        am.br.micJitterMs(now), st.underruns,            st.dropped_frames / 48,
                        st.skipped_frames / 48,
                    });
                }
            },
            .terminated => m.stopMic(),
            else => {},
        }
    }

    pub fn tick(m: *AudioInput, _: i64) vc.Error!?i64 {
        const ev = try m.srv.tick(nowU64(), &m.out);
        try m.flushOut();
        if (ev == .terminated) {
            log.info("{s}: the client did not complete the microphone initialization (MS-RDPEAI 3.3.2)", .{m.conn.peer});
            m.stopMic();
        }
        const d = m.srv.deadline orelse return null;
        return @intCast(@min(d, std.math.maxInt(i64)));
    }

    fn startMic(m: *AudioInput, idx: u32) vc.Error!void {
        const am = vc.find(m.conn, Audio) orelse return;
        const f = (try m.srv.clientFormats())[idx];
        am.br.startMic(f, nowU64()) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => {
                log.warn("{s}: no microphone: {t}", .{ m.conn.peer, e });
                return;
            },
        };
        m.mic_format = idx;
        log.info("{s}: the client's microphone is \"{s}\"", .{ m.conn.peer, audio.pipewire.mic_description });
    }

    fn stopMic(m: *AudioInput) void {
        if (m.mic_format == null) return;
        m.mic_format = null;
        var underruns: u64 = 0;
        var peak_ms: u32 = 0;
        if (vc.find(m.conn, Audio)) |am| {
            if (am.br.micStats()) |st| underruns = st.underruns;
            peak_ms = am.br.mic_target_peak_ms;
            am.br.stopMic();
        }
        log.info("{s}: the client's microphone is gone ({d} data PDUs, {d} underruns, jitter buffer up to {d} ms)", .{ m.conn.peer, m.data_pdus, underruns, peak_ms });
    }
};

/// Owns the Bridge and its backend. Last in features.list so the features using its
/// Bridge are torn down first.
pub const Audio = struct {
    conn: *Conn,
    mode: Mode,
    /// The PipeWire backend, when created here rather than supplied by a test.
    pw: ?*audio.PipeWire = null,
    br: audio.Bridge,

    pub fn init(c: *Conn) vc.Error!?Audio {
        const mode = modeOf(c.info_flags);
        if (!available(c) or (mode == .remote and !wantsMic(c.info_flags))) {
            giveBackDesk(c);
            return null;
        }
        var pw: ?*audio.PipeWire = null;
        const backend = c.vc.opts.audio_backend orelse b: {
            const p = audio.PipeWire.create(c.gpa, .{}) catch |e| {
                log.warn("{s}: no audio ({t})", .{ c.peer, e });
                giveBackDesk(c);
                return null;
            };
            pw = p;
            break :b p.backend();
        };
        const br = audio.Bridge.init(c.gpa, backend, .{ .mic_max_target_ms = c.vc.opts.mic_buffer_max_ms }) catch |e| {
            if (pw) |p| p.destroy();
            log.warn("{s}: no audio ({t})", .{ c.peer, e });
            giveBackDesk(c);
            return null;
        };
        return .{ .conn = c, .mode = mode, .pw = pw, .br = br };
    }

    pub fn start(a: *Audio) vc.Error!void {
        if (a.mode == .remote) return giveBackDesk(a.conn);
        a.br.muteDesk(nowU64());
        if (a.br.deskState() == .running) log.info("{s}: the desk's speakers are muted while the session is remote", .{a.conn.peer});
        // Take over any mute a previous connection left; its record merges into this one.
        if (a.conn.desktop_cfg) |cfg| _ = cfg.seat.takeDeskAudio();
    }

    pub fn deinit(a: *Audio) void {
        // If the session outlives this connection (takeover or reconnect wait), the desk
        // stays muted and the seat keeps what to restore; otherwise the speakers come back.
        const cfg = a.conn.desktop_cfg;
        const takeover = if (cfg) |d| d.seat.takeoverPending() else false;
        const keep = cfg != null and (takeover or a.conn.lingering);
        if (a.br.deskState() != .off) {
            a.br.releaseDesk(keep);
            if (keep) cfg.?.seat.keepDeskAudio(.{ .backend = a.conn.vc.opts.audio_backend });
            log.info("{s}: the desk's speakers {s}", .{ a.conn.peer, if (takeover) "stay muted for the connection taking over" else if (keep) "stay muted while the session waits for a reconnect" else "are restored" });
        }
        a.br.deinit();
        if (a.pw) |p| p.destroy();
    }

    pub fn pollFd(a: *Audio) ?vc.Poll {
        return .{ .fd = a.br.fd() };
    }

    pub fn onFd(a: *Audio, _: c_short) vc.Error!void {
        try a.br.process(nowU64());
        if (vc.find(a.conn, AudioPlayback)) |p| try p.pump();
    }

    pub fn tick(a: *Audio, now_ms: i64) vc.Error!?i64 {
        const t = a.br.timeoutMs(nowU64());
        if (t < 0) return null;
        if (t == 0) {
            try a.br.process(nowU64());
            const t2 = a.br.timeoutMs(nowU64());
            return if (t2 < 0) null else now_ms + t2;
        }
        return now_ms + t;
    }
};
