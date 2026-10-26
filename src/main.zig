const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");
const omastation = @import("omastation");

const auth = omastation.server.auth;
const flight = omastation.server.flight;

/// The default panic, after the panicking connection's flight record (flight.onPanic).
pub const panic = std.debug.FullPanic(panicFn);

fn panicFn(msg: []const u8, first_trace_addr: ?usize) noreturn {
    @branchHint(.cold);
    flight.onPanic(msg);
    std.debug.defaultPanic(msg, first_trace_addr);
}

pub const std_options: std.Options = .{
    // Compiled in at every level; omastation.logging filters at run time.
    .log_level = .debug,
    .logFn = logFn,
};

/// The default log line prefixed with the UTC time of day (ms) and the thread.
fn logFn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (!omastation.logging.enabled(level)) return;
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_REALTIME, &ts);
    const day_ms: u64 = @intCast(@mod(ts.tv_sec, 86400) * 1000 + @divTrunc(ts.tv_nsec, 1_000_000));
    var buffer: [256]u8 = undefined;
    const stderr = std.debug.lockStderr(&buffer).terminal();
    defer std.debug.unlockStderr();
    stderr.writer.print("{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3} [{d}] ", .{
        day_ms / 3_600_000, day_ms / 60_000 % 60, day_ms / 1000 % 60, day_ms % 1000, c.gettid(),
    }) catch return;
    std.log.defaultLogFileTerminal(level, scope, format, args, stderr) catch {};
}

const log = std.log.scoped(.main);

const usage =
    \\usage: omastation [options]            run the server
    \\       omastation passwd [options]     store the NLA verifier for a user
    \\
    \\server options:
    \\  --port N               TCP port (default 3389)
    \\  --cert FILE            TLS certificate (PEM); generated if missing
    \\  --key FILE             TLS private key (PEM); generated if missing
    \\  --credentials FILE     NLA verifier store (default ~/.config/omastation/credentials)
    \\  --pam-service NAME     PAM service for the delegated password (default system-remote-login)
    \\  --no-pam               skip the PAM check after NLA (development only)
    \\  --no-hybrid-ex         select plain HYBRID even if the client offers HYBRID_EX
    \\  --insecure-allow-tls   accept TLS without NLA; NO authentication (development only)
    \\  --desktop              serve the real desktop: lock-screen takeover, physical
    \\                         monitors off while connected (without it: a test pattern)
    \\  --lock-command CMD     locks the session on disconnect (default omarchy-system-lock)
    \\  --helper-socket PATH   root helper fencing the desk (default /run/omastation/helper.sock)
    \\  --require-fence        refuse sessions when the desk cannot be fenced
    \\  --reconnect-grace S    after a connection is lost to the network, keep the remote
    \\                         session (desk dark and fenced) S seconds for the client to
    \\                         auto-reconnect (default 120; 0: lock and give the desk back
    \\                         at once)
    \\  --alt-drag MODE        Option + drag twins of the SUPER mouse bindings for clients
    \\                         that cannot hold Super during a drag (the Windows App on
    \\                         macOS): auto (default: macOS / iOS clients), on, off
    \\  --heartbeat S          Server Heartbeat PDUs every S seconds to clients that
    \\                         support them (default 1, as Windows; 0: none)
    \\  --frame-interval MS    target interval between frames, 8..200 ms (default 31,
    \\                         as Windows: about 32 frames a second)
    \\  --hyprland-plugin PATH omastation's Hyprland plugin, loaded while serving the desktop:
    \\                         protected windows (no_screen_share) shown over RDP, the
    \\                         hardware cursor following absolute motion, client-drawn
    \\                         pointers (default /usr/lib/omastation/omastation-plugin.so,
    \\                         loaded as a copy in $XDG_RUNTIME_DIR/omastation/plugin;
    \\                         none: don't load it)
    \\  --capture-backend B    how the desktop is captured: ext (ext-image-copy-capture,
    \\                         default) or wlr (wlr-screencopy; testing)
    \\  --cursor MODE          who draws the pointer: auto (the client, once the
    \\                         compositor's cursor capture works; default), client
    \\                         (always), paint (painted into the frames)
    \\  --test-animate         without --desktop: animate the test pattern (load test)
    \\  --test-video WxH       without --desktop: a video of WxH in the middle of the
    \\                         still test pattern, 15 s playing, 5 s paused (load test)
    \\  --test-scene NAME      without --desktop: play a desktop scene over and over:
    \\                         scroll, window, video_small, video_full, scroll_busy
    \\                         (picture quality; needs a desktop of at least 1920x1200)
    \\  --test-detail          without --desktop: fine noise over the test pattern, as
    \\                         photos and small text are to codecs (load test)
    \\  --echo MS              open the ECHO dynamic channel and measure its round
    \\                         trip every MS milliseconds (debug log; diagnostics)
    \\  --codecs LIST          graphics codecs the server may use, comma-separated:
    \\                         avc444, avc420, h264 (both), progressive, remotefx,
    \\                         nscodec, clear; all (default) or none (planar and
    \\                         bitmaps only). AVC444 goes to clients that ask for
    \\                         it (as Windows); naming avc444 or h264 offers it to
    \\                         every client that takes AVC
    \\  --gpu NODE             DRM render node whose VA-API driver encodes H.264, e.g.
    \\                         /dev/dri/renderD129 or just renderD129 (default: the
    \\                         first node that can; on a hybrid laptop with an NVIDIA
    \\                         dGPU that is usually the iGPU)
    \\  --no-gfx               do not offer the graphics pipeline (RDPGFX): bitmap
    \\                         updates and surface commands only (testing)
    \\  --lossy-motion MODE    CPU lossy codecs (progressive, RemoteFX, NSCodec) for
    \\                         motion: auto (slow links, default), always, never
    \\  --bulk TYPE            highest bulk compression: none, 8k, 64k, rdp6, rdp61
    \\                         (default rdp61; the client's maximum applies)
    \\  --no-clipboard         no clipboard redirection (the cliprdr channel is not served)
    \\  --no-audio             with --desktop: no audio to the client, no microphone
    \\                         from it, the desk's speakers left alone
    \\  --mic-buffer-max MS    the most the client microphone's jitter buffer grows to
    \\                         when its packets arrive unevenly (default 300; 40: a
    \\                         fixed 40 ms buffer)
    \\  --audio-quality LEVEL  the best audio quality mode a client may ask for, as
    \\                         Windows' "Limit audio playback quality" policy:
    \\                         dynamic (default: every client in Dynamic mode, AAC
    \\                         96 kbit/s or a format fitting the measured bandwidth),
    \\                         medium (also MS-ADPCM 44.1 kHz mono) or high (also
    \\                         PCM 44.1 kHz stereo)
    \\  --audio-max-bandwidth B
    \\                         the most bandwidth Dynamic mode measures, bytes/s
    \\                         (Windows' RdpsndMaxBandwidth, default 22201: IMA-ADPCM
    \\                         22.05 kHz stereo or less without AAC)
    \\  --no-drives            don't redirect the client's drives (with --desktop they
    \\                         appear in $XDG_RUNTIME_DIR/omastation/drives, linked from
    \\                         ~/RDP Drives; mounted by fusermount3, no root needed)
    \\  --drives-read-only     redirect the client's drives read-only
    \\  --no-remoteapp         clients asking for RemoteApp get the full desktop
    \\  --remoteapp-launcher "CMD ARGS"
    \\                         put in front of RemoteApp programs (default:
    \\                         "uwsm-app --" when uwsm-app is on $PATH)
    \\  --no-udp               no UDP side channels (multitransport): TCP only
    \\  --udp-version V        highest RDP-UDP version answered: 1, 2 (default) or
    \\                         3 (RDP-UDP2)
    \\  --touch MODE           touch and pen input (MS-RDPEI): auto (desktop sessions,
    \\                         default), on (also the test pattern), off
    \\  --log-level LEVEL      err, warn, info (default) or debug; debug shows every
    \\                         PDU and key event, i.e. what the remote user types
    \\  --flight-record MODE   each connection records its recent traffic (PDU types,
    \\                         sizes, ids; never what is typed, copied or shown) and
    \\                         writes it to $XDG_RUNTIME_DIR/omastation/flight when it ends:
    \\                         errors (default: abnormal ends), always, or off. SIGUSR1
    \\                         writes every live connection's record
    \\
    \\passwd options:
    \\  --user NAME            account name (default: the current user)
    \\  --credentials FILE     store to update
    \\  --pam-service NAME     PAM service used to check the password
    \\  --no-pam               don't check the password with PAM (test accounts only)
    \\
    \\The password is read from stdin.
    \\
;

const Options = struct {
    port: u16 = 3389,
    cert_path: ?[:0]const u8 = null,
    key_path: ?[:0]const u8 = null,
    credentials_path: ?[:0]const u8 = null,
    pam_service: [:0]const u8 = "system-remote-login",
    no_pam: bool = false,
    allow_tls: bool = false,
    hybrid_ex: bool = true,
    user: ?[:0]const u8 = null,
    desktop: bool = false,
    lock_command: []const u8 = "omarchy-system-lock",
    helper_socket: [:0]const u8 = "/run/omastation/helper.sock",
    require_fence: bool = false,
    reconnect_grace_s: u32 = omastation.server.conn.default_reconnect_grace_ms / 1000,
    alt_drag: omastation.session.altdrag.Mode = .auto,
    hyprland_plugin: ?[:0]const u8 = omastation.session.plugin.default_path,
    capture_backend: omastation.wl.capture.Backend = .ext,
    cursor: omastation.session.desktop.CursorMode = .auto,
    animate: bool = false,
    detail: bool = false,
    video: ?[2]u16 = null,
    scene: ?omastation.server.scene.Kind = null,
    features: omastation.server.features.Options = .{},
    /// --remoteapp-launcher was given (else uwsm-app when on $PATH).
    launcher_set: bool = false,
    udp: bool = true,
    udp_version: u16 = omastation.multitransport.rdpudp_protocol_version_2,
    flight: flight.Mode = .errors,
};

pub fn main(init: std.process.Init) !void {
    // ReleaseSafe's process allocator is the leak-checking SafeAllocator, which never reuses
    // memory and checks every call; a server encoding frames all day wants libc's.
    const gpa = if (builtin.mode == .debug) init.gpa else std.heap.c_allocator;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var o = Options{};
    var passwd_mode = false;
    var harness_dir: ?[]const u8 = null;
    var i: usize = 1;
    if (args.len > 1 and std.mem.eql(u8, args[1], "passwd")) {
        passwd_mode = true;
        i = 2;
    } else if (args.len > 2 and std.mem.eql(u8, args[1], "helper")) {
        // Root helper: `omastation helper UID [SOCKET]`.
        const uid = std.fmt.parseInt(u32, args[2], 10) catch return fail("helper: bad uid");
        const sock: [:0]const u8 = if (args.len > 3) try arena.dupeSentinel(u8, args[3], 0) else "/run/omastation/helper.sock";
        return omastation.session.helper.run(.{ .socket_path = sock, .allow_uid = uid });
    } else if (args.len > 1 and std.mem.eql(u8, args[1], "fence-list")) {
        return fenceList(arena);
    } else if (args.len > 2 and std.mem.eql(u8, args[1], "sspi-harness")) {
        // Hidden SSPI test tool.
        harness_dir = args[2];
        i = 3;
    }
    switch (try parseOptions(arena, args, i, &o)) {
        .run => {},
        .usage => {
            std.debug.print("{s}", .{usage});
            return;
        },
    }

    o.features.io = init.io;

    const dir = try configDir(arena, init.environ_map);
    _ = c.mkdir(dir.ptr, 0o700);
    const cred_path = o.credentials_path orelse try std.mem.concatWithSentinel(arena, u8, &.{ dir, "/credentials" }, 0);

    if (passwd_mode) return passwd(arena, &o, cred_path, init.environ_map);

    // RemoteApp: applications and icons from this session's XDG directories, programs checked
    // against its $PATH; on Omarchy apps start in their own systemd scope (uwsm-app --).
    o.features.remoteapp_xdg = try omastation.session.xdg.Dirs.fromEnv(arena, init.environ_map);
    o.features.remoteapp_path = init.environ_map.get("PATH");
    if (!o.launcher_set) {
        if (o.features.remoteapp_path) |path| {
            if (omastation.session.xdg.findProgram(arena, "uwsm-app", path) != null) o.features.remoteapp_launcher = &.{ "uwsm-app", "--" };
        }
    }

    var host_buf: [256]u8 = undefined;
    if (c.gethostname(&host_buf, host_buf.len) != 0) return fail("gethostname failed");
    const hostname = std.mem.sliceTo(&host_buf, 0);
    const hostname_z = try arena.dupeSentinel(u8, hostname, 0);

    var store = loadStore(arena, cred_path) catch |err| blk: {
        log.warn("no NLA verifiers loaded from {s} ({t}); run `omastation passwd`", .{ cred_path, err });
        break :blk auth.Store{};
    };
    log.info("{d} NLA user(s) configured", .{store.count});
    if (o.no_pam) log.warn("--no-pam: delegated passwords are NOT checked with PAM", .{});
    if (o.allow_tls) log.warn("--insecure-allow-tls: TLS-only clients get in WITHOUT authentication", .{});

    // NetBIOS name: upper-case, at most 15 characters.
    var nb_ascii: [15]u8 = undefined;
    const nb_len = @min(hostname.len, 15);
    for (hostname[0..nb_len], 0..) |ch, k| nb_ascii[k] = std.ascii.toUpper(ch);
    const auth_cfg = omastation.server.conn.AuthConfig{
        .store = &store,
        .pam_service = if (o.no_pam) null else o.pam_service,
        .allow_tls_without_nla = o.allow_tls,
        .use_hybrid_ex = o.hybrid_ex,
        .nb_computer = try utf16le(arena, nb_ascii[0..nb_len]),
        .dns_computer = try utf16le(arena, hostname),
    };

    // The SSPI harness only exercises SPNEGO/NTLM: no TLS, no listener.
    if (harness_dir) |d| return omastation.server.sspi_harness.run(gpa, d, &store, auth_cfg.nb_computer, auth_cfg.dns_computer);

    const cert_path = o.cert_path orelse try std.mem.concatWithSentinel(arena, u8, &.{ dir, "/tls.crt" }, 0);
    const key_path = o.key_path orelse try std.mem.concatWithSentinel(arena, u8, &.{ dir, "/tls.key" }, 0);
    var tls_ctx = try omastation.tls.Context.init(gpa, cert_path, key_path, hostname_z);
    defer tls_ctx.deinit();

    var seat: omastation.server.seat.Seat = .{};
    var desktop_cfg: ?omastation.server.conn.DesktopConfig = null;
    if (o.desktop) {
        const ipc = omastation.session.hypr.Ipc.fromEnv(init.environ_map) catch
            return fail("--desktop: not inside a Hyprland session (HYPRLAND_INSTANCE_SIGNATURE unset)");
        // The Option + drag bindings in force, for omastation-recover.
        const binds_state: ?[:0]const u8 = if (init.environ_map.get("XDG_RUNTIME_DIR")) |rt| blk: {
            const dir_z = try std.mem.concatWithSentinel(arena, u8, &.{ rt, "/omastation" }, 0);
            _ = c.mkdir(dir_z.ptr, 0o700);
            break :blk try std.mem.concatWithSentinel(arena, u8, &.{ rt, "/omastation/alt-drag-binds" }, 0);
        } else null;
        if (binds_state) |p| omastation.session.altdrag.removeStale(&ipc, gpa, p);
        // The console's restore plan while remote, for omastation-recover.
        const console_state: ?[:0]const u8 = if (init.environ_map.get("XDG_RUNTIME_DIR")) |rt|
            try std.mem.concatWithSentinel(arena, u8, &.{ rt, "/omastation/console-restore" }, 0)
        else
            null;
        // Loaded as a content-named copy in the runtime directory, so an upgraded plugin is new
        // code in a running Hyprland; omastation-recover unloads it when the service stops.
        if (o.hyprland_plugin) |p| {
            const staging: ?omastation.session.plugin.Staging = if (init.environ_map.get("XDG_RUNTIME_DIR")) |rt|
                try omastation.session.plugin.Staging.inRuntimeDir(arena, rt)
            else
                null;
            var text: [400]u8 = undefined;
            _ = omastation.session.plugin.activate(&ipc, gpa, p, staging, &text);
        }
        // Bindings back on for keyboard names a previous run may have left without them.
        omastation.session.textbinds.resetStale(&ipc, gpa);
        desktop_cfg = .{
            .ipc = ipc,
            .seat = &seat,
            .lock_command = o.lock_command,
            .helper_socket = o.helper_socket,
            .require_fence = o.require_fence,
            .reconnect_grace_ms = o.reconnect_grace_s * 1000,
            .alt_drag = o.alt_drag,
            .binds_state_path = binds_state,
            .console_state_path = console_state,
            .capture_backend = o.capture_backend,
            .cursor = o.cursor,
        };
        if (o.allow_tls) log.warn("--desktop ignores --insecure-allow-tls: desktop sessions require NLA", .{});
        // Client drives: mounted in the runtime directory, linked from the home directory.
        o.features.drives_runtime_dir = init.environ_map.get("XDG_RUNTIME_DIR");
        if (init.environ_map.get("HOME")) |home| o.features.drives_link_dir = try std.mem.concat(arena, u8, &.{ home, "/RDP Drives" });
        if (o.features.drives and o.features.drives_runtime_dir == null) log.warn("XDG_RUNTIME_DIR is not set: client drives are not redirected", .{});
        o.features.audio_pipewire = true;
    } else {
        log.info("test pattern mode: the local desktop is not served (see --desktop)", .{});
    }

    // SIGUSR1 asks live connections for their flight records; it is blocked in every thread
    // except in accept() below, so no connection's poll() is cut short.
    var flight_cfg: ?flight.Config = null;
    if (o.flight != .off) {
        if (init.environ_map.get("XDG_RUNTIME_DIR")) |rt| {
            flight_cfg = .{ .dir = try std.mem.concat(arena, u8, &.{ rt, "/omastation/flight" }), .mode = o.flight };
        } else log.warn("XDG_RUNTIME_DIR is not set: no flight records", .{});
    }
    flight.blockSignal(true);
    flight.installSignalHandler();

    const listen_fd = try omastation.socket.listenTcp(o.port, 8);
    defer omastation.socket.close(listen_fd);
    log.info("omastation listening on port {d} as {s}", .{ o.port, hostname });

    // UDP side channels on the same port (MS-RDPEUDP 3.1.3); without them clients stay on TCP.
    if (o.udp) {
        if (omastation.server.udp.Listener.start(gpa, o.port, .{ .cert_path = cert_path, .key_path = key_path, .max_version = o.udp_version })) |l| {
            o.features.udp = l;
            log.info("UDP multitransport on port {d} (RDP-UDP up to version {d})", .{ o.port, @as(u16, if (o.udp_version == omastation.multitransport.rdpudp_protocol_version_3) 3 else o.udp_version) });
        } else |err| log.warn("no UDP multitransport on port {d}: {t}", .{ o.port, err });
    }

    // A thread per connection, so a reconnecting client is not stuck behind a dead one. One owns
    // the desktop at a time (as Windows client editions); a new authenticated one takes over.
    const shared: Shared = .{
        .gpa = gpa,
        .tls_ctx = &tls_ctx,
        .auth_cfg = &auth_cfg,
        .desktop_cfg = if (desktop_cfg) |*d| d else null,
        .animate = o.animate and desktop_cfg == null,
        .detail = o.detail and desktop_cfg == null,
        .video = if (desktop_cfg == null) o.video else null,
        .scene = if (desktop_cfg == null) o.scene else null,
        .features = o.features,
        .seat = &seat,
        .flight = if (flight_cfg) |*f| f else null,
    };
    while (true) {
        flight.blockSignal(false);
        const accepted = omastation.socket.accept(listen_fd);
        flight.blockSignal(true);
        const peer = accepted catch |err| {
            log.err("accept: {t}", .{err});
            continue;
        };
        if (active_connections.load(.monotonic) >= max_connections) {
            log.warn("{s}: refused, {d} connections in progress", .{ peer.addrText(), max_connections });
            omastation.socket.close(peer.fd);
            continue;
        }
        log.info("connection from {s}", .{peer.addrText()});
        const job = gpa.create(Job) catch {
            omastation.socket.close(peer.fd);
            continue;
        };
        job.* = .{ .shared = &shared, .peer = peer };
        _ = active_connections.fetchAdd(1, .monotonic);
        const th = std.Thread.spawn(.{}, serve, .{job}) catch |err| {
            log.err("{s}: no thread: {t}", .{ peer.addrText(), err });
            _ = active_connections.fetchSub(1, .monotonic);
            omastation.socket.close(peer.fd);
            gpa.destroy(job);
            continue;
        };
        th.detach();
    }
}

const Parsed = enum { run, usage };

fn parseOptions(arena: std.mem.Allocator, args: []const [:0]const u8, first: usize, o: *Options) !Parsed {
    var i = first;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const val: [:0]const u8 = if (i + 1 < args.len) try arena.dupeSentinel(u8, args[i + 1], 0) else "";
        if (std.mem.eql(u8, a, "--port")) {
            o.port = std.fmt.parseInt(u16, val, 10) catch return fail("bad --port");
            i += 1;
        } else if (std.mem.eql(u8, a, "--cert")) {
            o.cert_path = val;
            i += 1;
        } else if (std.mem.eql(u8, a, "--key")) {
            o.key_path = val;
            i += 1;
        } else if (std.mem.eql(u8, a, "--credentials")) {
            o.credentials_path = val;
            i += 1;
        } else if (std.mem.eql(u8, a, "--pam-service")) {
            o.pam_service = val;
            i += 1;
        } else if (std.mem.eql(u8, a, "--user")) {
            o.user = val;
            i += 1;
        } else if (std.mem.eql(u8, a, "--no-pam")) {
            o.no_pam = true;
        } else if (std.mem.eql(u8, a, "--no-hybrid-ex")) {
            o.hybrid_ex = false;
        } else if (std.mem.eql(u8, a, "--insecure-allow-tls")) {
            o.allow_tls = true;
        } else if (std.mem.eql(u8, a, "--desktop")) {
            o.desktop = true;
        } else if (std.mem.eql(u8, a, "--lock-command")) {
            o.lock_command = val;
            i += 1;
        } else if (std.mem.eql(u8, a, "--helper-socket")) {
            o.helper_socket = val;
            i += 1;
        } else if (std.mem.eql(u8, a, "--require-fence")) {
            o.require_fence = true;
        } else if (std.mem.eql(u8, a, "--reconnect-grace")) {
            o.reconnect_grace_s = std.fmt.parseInt(u32, val, 10) catch return fail("bad --reconnect-grace");
            if (o.reconnect_grace_s > 24 * 3600) return fail("bad --reconnect-grace");
            i += 1;
        } else if (std.mem.eql(u8, a, "--alt-drag")) {
            o.alt_drag = std.meta.stringToEnum(omastation.session.altdrag.Mode, val) orelse return fail("bad --alt-drag");
            i += 1;
        } else if (std.mem.eql(u8, a, "--mic-buffer-max")) {
            o.features.mic_buffer_max_ms = std.math.clamp(std.fmt.parseInt(u32, val, 10) catch return fail("bad --mic-buffer-max"), 40, 2000);
            i += 1;
        } else if (std.mem.eql(u8, a, "--heartbeat")) {
            o.features.heartbeat_period_s = std.fmt.parseInt(u8, val, 10) catch return fail("bad --heartbeat");
            i += 1;
        } else if (std.mem.eql(u8, a, "--frame-interval")) {
            const ms = std.fmt.parseInt(u32, val, 10) catch return fail("bad --frame-interval");
            if (ms < omastation.server.pacing.min_interval_ms or ms > omastation.server.pacing.max_interval_ms) return fail("bad --frame-interval (8..200 ms)");
            o.features.frame_interval_ms = ms;
            i += 1;
        } else if (std.mem.eql(u8, a, "--hyprland-plugin")) {
            o.hyprland_plugin = if (std.mem.eql(u8, val, "none")) null else val;
            i += 1;
        } else if (std.mem.eql(u8, a, "--capture-backend")) {
            o.capture_backend = std.meta.stringToEnum(omastation.wl.capture.Backend, val) orelse return fail("bad --capture-backend");
            if (o.capture_backend == .auto) return fail("bad --capture-backend");
            i += 1;
        } else if (std.mem.eql(u8, a, "--cursor")) {
            o.cursor = std.meta.stringToEnum(omastation.session.desktop.CursorMode, val) orelse return fail("bad --cursor");
            i += 1;
        } else if (std.mem.eql(u8, a, "--test-animate")) {
            o.animate = true;
        } else if (std.mem.eql(u8, a, "--test-scene")) {
            o.scene = std.meta.stringToEnum(omastation.server.scene.Kind, val) orelse return fail("bad --test-scene");
            i += 1;
        } else if (std.mem.eql(u8, a, "--test-detail")) {
            o.detail = true;
        } else if (std.mem.eql(u8, a, "--test-video")) {
            const x = std.mem.indexOfScalar(u8, val, 'x') orelse return fail("bad --test-video");
            const vw = std.fmt.parseInt(u16, val[0..x], 10) catch return fail("bad --test-video");
            const vh = std.fmt.parseInt(u16, val[x + 1 ..], 10) catch return fail("bad --test-video");
            if (vw == 0 or vh == 0) return fail("bad --test-video");
            o.video = .{ vw, vh };
            o.animate = true;
            i += 1;
        } else if (std.mem.eql(u8, a, "--no-drives")) {
            o.features.drives = false;
        } else if (std.mem.eql(u8, a, "--drives-read-only")) {
            o.features.drives_read_only = true;
        } else if (std.mem.eql(u8, a, "--echo")) {
            o.features.echo_period_ms = std.fmt.parseInt(u32, val, 10) catch return fail("bad --echo");
            i += 1;
        } else if (std.mem.eql(u8, a, "--codecs")) {
            o.features.graphics.parseCodecs(val) catch return fail("bad --codecs");
            i += 1;
        } else if (std.mem.eql(u8, a, "--gpu")) {
            if (val.len == 0) return fail("bad --gpu");
            o.features.graphics.vaapi_device = if (std.mem.startsWith(u8, val, "/")) val else try std.fmt.allocPrintSentinel(arena, "/dev/dri/{s}", .{val}, 0);
            i += 1;
        } else if (std.mem.eql(u8, a, "--no-gfx")) {
            o.features.graphics.rdpgfx = false;
        } else if (std.mem.eql(u8, a, "--lossy-motion")) {
            o.features.graphics.lossy_motion = std.meta.stringToEnum(omastation.server.codec_policy.LossyMotion, val) orelse return fail("bad --lossy-motion");
            i += 1;
        } else if (std.mem.eql(u8, a, "--bulk")) {
            o.features.graphics.bulk = omastation.server.codec_policy.parseBulk(val) catch return fail("bad --bulk");
            i += 1;
        } else if (std.mem.eql(u8, a, "--no-clipboard")) {
            o.features.clipboard = false;
        } else if (std.mem.eql(u8, a, "--no-audio")) {
            o.features.audio = false;
        } else if (std.mem.eql(u8, a, "--audio-quality")) {
            o.features.audio_quality = std.meta.stringToEnum(omastation.channel.rdpsnd.QualityLimit, val) orelse return fail("bad --audio-quality");
            i += 1;
        } else if (std.mem.eql(u8, a, "--audio-max-bandwidth")) {
            o.features.audio_max_bandwidth = std.fmt.parseInt(u32, val, 10) catch return fail("bad --audio-max-bandwidth");
            if (o.features.audio_max_bandwidth == 0) return fail("bad --audio-max-bandwidth");
            i += 1;
        } else if (std.mem.eql(u8, a, "--no-remoteapp")) {
            o.features.remoteapp = false;
        } else if (std.mem.eql(u8, a, "--remoteapp-launcher")) {
            // Words separated by spaces, e.g. "uwsm-app --".
            var words: std.ArrayList([]const u8) = .empty;
            var it = std.mem.tokenizeScalar(u8, val, ' ');
            while (it.next()) |word| try words.append(arena, word);
            o.features.remoteapp_launcher = words.items;
            o.launcher_set = true;
            i += 1;
        } else if (std.mem.eql(u8, a, "--no-udp")) {
            o.udp = false;
        } else if (std.mem.eql(u8, a, "--udp-version")) {
            const mtp = omastation.multitransport;
            o.udp_version = switch (std.fmt.parseInt(u8, val, 10) catch return fail("bad --udp-version")) {
                1 => mtp.rdpudp_protocol_version_1,
                2 => mtp.rdpudp_protocol_version_2,
                3 => mtp.rdpudp_protocol_version_3,
                else => return fail("bad --udp-version"),
            };
            i += 1;
        } else if (std.mem.eql(u8, a, "--touch")) {
            o.features.touch = std.meta.stringToEnum(omastation.server.features.touch.Mode, val) orelse return fail("bad --touch");
            i += 1;
        } else if (std.mem.eql(u8, a, "--flight-record")) {
            o.flight = std.meta.stringToEnum(flight.Mode, val) orelse return fail("bad --flight-record");
            i += 1;
        } else if (std.mem.eql(u8, a, "--log-level")) {
            omastation.logging.level = omastation.logging.parseLevel(val) orelse return fail("bad --log-level");
            i += 1;
        } else return .usage;
    }
    return .run;
}

/// Connections being served (handshakes included); more are refused.
const max_connections = 8;
var active_connections = std.atomic.Value(u32).init(0);

const Shared = struct {
    gpa: std.mem.Allocator,
    tls_ctx: *omastation.tls.Context,
    auth_cfg: *const omastation.server.conn.AuthConfig,
    desktop_cfg: ?*const omastation.server.conn.DesktopConfig,
    animate: bool,
    detail: bool,
    video: ?[2]u16,
    scene: ?omastation.server.scene.Kind,
    features: omastation.server.features.Options,
    /// Session state shared by all connections (auto-reconnect cookie), test-pattern mode too.
    seat: *omastation.server.seat.Seat,
    /// null: no recorder.
    flight: ?*const flight.Config,
};

const Job = struct {
    shared: *const Shared,
    peer: omastation.socket.Peer,
};

fn serve(job: *Job) void {
    const sh = job.shared;
    defer {
        sh.gpa.destroy(job);
        _ = active_connections.fetchSub(1, .monotonic);
    }
    var conn = omastation.server.Conn.init(sh.gpa, omastation.transport.Transport.init(job.peer.fd), sh.tls_ctx, sh.auth_cfg, sh.desktop_cfg, job.peer.addrText());
    defer conn.deinit();
    conn.animate = sh.animate;
    conn.test_detail = sh.detail;
    conn.test_video = sh.video;
    var player: omastation.server.scene.Player = .{ .kind = sh.scene orelse .scroll };
    if (sh.scene != null) conn.test_source = .{ .ctx = &player, .pump = omastation.server.scene.Player.pump };
    conn.vc.opts = sh.features;
    conn.seat = sh.seat;
    if (sh.flight) |cfg| conn.flight.start(sh.gpa, cfg.capacity, cfg) catch
        log.warn("{s}: no flight recorder (out of memory)", .{job.peer.addrText()});
    flight.serving(&conn.flight, conn.peer);
    defer flight.serving(null, "");
    const result = conn.run();
    if (result) |_| {} else |err| log.warn("{s}: connection ended: {t}", .{ job.peer.addrText(), err });
    // An abnormal end writes the flight record (before deinit frees it).
    conn.flightEnd(result);
}

fn readSmall(arena: std.mem.Allocator, path: []const u8) ![]u8 {
    const z = try arena.dupeSentinel(u8, path, 0);
    const fd = c.open(z.ptr, c.O_RDONLY | c.O_CLOEXEC);
    if (fd < 0) return error.FileNotFound;
    defer _ = c.close(fd);
    const buf = try arena.alloc(u8, 4096);
    const n = c.read(fd, buf.ptr, buf.len);
    if (n < 0) return error.ReadFailed;
    return buf[0..@intCast(n)];
}

fn fenceList(arena: std.mem.Allocator) !void {
    const fence = omastation.session.fence;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        const base = try std.fmt.allocPrint(arena, "/sys/class/input/event{d}/device", .{i});
        const name = readSmall(arena, try std.fmt.allocPrint(arena, "{s}/name", .{base})) catch continue;
        const caps = fence.capsFromSysfs(
            try readSmall(arena, try std.fmt.allocPrint(arena, "{s}/capabilities/ev", .{base})),
            try readSmall(arena, try std.fmt.allocPrint(arena, "{s}/capabilities/key", .{base})),
            try readSmall(arena, try std.fmt.allocPrint(arena, "{s}/capabilities/rel", .{base})),
            try readSmall(arena, try std.fmt.allocPrint(arena, "{s}/capabilities/abs", .{base})),
        ) catch continue;
        const kind = fence.classify(&caps);
        std.debug.print("event{d:<3} {s:<6} {s:<9} {s}\n", .{ i, if (fence.shouldFence(&caps)) "FENCE" else "-", if (kind == .other) "" else @tagName(kind), std.mem.trimEnd(u8, name, "\n") });
    }
}

fn loadStore(arena: std.mem.Allocator, path: [:0]const u8) !auth.Store {
    const fd = c.open(path.ptr, c.O_RDONLY | c.O_CLOEXEC);
    if (fd < 0) return error.FileNotFound;
    defer _ = c.close(fd);
    const buf = try arena.alloc(u8, 64 * 1024);
    defer std.crypto.secureZero(u8, buf); // the file holds the NT hashes
    const n = c.read(fd, buf.ptr, buf.len);
    if (n < 0) return error.ReadFailed;
    return auth.Store.parse(buf[0..@intCast(n)]);
}

fn passwd(arena: std.mem.Allocator, o: *const Options, cred_path: [:0]const u8, env: *std.process.Environ.Map) !void {
    const user: [:0]const u8 = o.user orelse try arena.dupeSentinel(u8, env.get("USER") orelse return fail("--user required"), 0);

    var pw_buf: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &pw_buf);
    const pw = try readPassword(&pw_buf);

    if (!o.no_pam and !auth.pamCheck(o.pam_service, user, pw)) {
        std.debug.print("omastation: password check failed for {s}\n", .{user});
        return error.AuthenticationFailed;
    }
    const hash = try auth.ntHash(pw);

    // Keep other users' lines; replace this user's.
    var out: std.ArrayList(u8) = .empty;
    if (loadStore(arena, cred_path)) |old| {
        for (old.entries[0..old.count]) |*e| {
            if (std.ascii.eqlIgnoreCase(e.name(), user)) continue;
            try out.print(arena, "{s}:{x}\n", .{ e.name(), e.nt_hash });
        }
    } else |_| {}
    try out.print(arena, "{s}:{x}\n", .{ user, hash });

    // 0600 temp file, renamed over the store.
    const tmp = try std.mem.concatWithSentinel(arena, u8, &.{ cred_path, ".tmp" }, 0);
    const fd = c.open(tmp.ptr, c.O_WRONLY | c.O_CREAT | c.O_TRUNC | c.O_CLOEXEC, @as(c_uint, 0o600));
    if (fd < 0) return error.WriteFailed;
    if (c.write(fd, out.items.ptr, out.items.len) != @as(isize, @intCast(out.items.len))) {
        _ = c.close(fd);
        return error.WriteFailed;
    }
    _ = c.fsync(fd);
    _ = c.close(fd);
    if (c.rename(tmp.ptr, cred_path.ptr) != 0) return error.WriteFailed;
    std.debug.print("omastation: stored NLA verifier for {s} in {s}\n", .{ user, cred_path });
}

fn readPassword(buf: []u8) ![:0]u8 {
    var old: c.struct_termios = undefined;
    const tty = c.isatty(0) == 1 and c.tcgetattr(0, &old) == 0;
    if (tty) {
        std.debug.print("Password: ", .{});
        var raw = old;
        raw.c_lflag &= ~@as(c_uint, c.ECHO);
        _ = c.tcsetattr(0, c.TCSANOW, &raw);
    }
    defer if (tty) {
        _ = c.tcsetattr(0, c.TCSANOW, &old);
        std.debug.print("\n", .{});
    };
    var n: usize = 0;
    while (n < buf.len - 1) {
        const r = c.read(0, buf.ptr + n, 1);
        if (r <= 0 or buf[n] == '\n') break;
        n += 1;
    }
    if (n > 0 and buf[n - 1] == '\r') n -= 1;
    if (n == 0) return error.EmptyPassword;
    buf[n] = 0;
    return buf[0..n :0];
}

fn utf16le(arena: std.mem.Allocator, ascii: []const u8) ![]u8 {
    const out = try arena.alloc(u8, ascii.len * 2);
    for (ascii, 0..) |ch, k| {
        out[2 * k] = ch;
        out[2 * k + 1] = 0;
    }
    return out;
}

fn configDir(arena: std.mem.Allocator, env: *std.process.Environ.Map) ![:0]const u8 {
    if (env.get("XDG_CONFIG_HOME")) |x| return std.mem.concatWithSentinel(arena, u8, &.{ x, "/omastation" }, 0);
    const home = env.get("HOME") orelse return error.NoHome;
    _ = c.mkdir((try std.mem.concatWithSentinel(arena, u8, &.{ home, "/.config" }, 0)).ptr, 0o755);
    return std.mem.concatWithSentinel(arena, u8, &.{ home, "/.config/omastation" }, 0);
}

fn fail(msg: []const u8) error{InvalidArguments} {
    std.debug.print("omastation: {s}\n{s}", .{ msg, usage });
    return error.InvalidArguments;
}

test "--udp-version takes its value: 3 selects RDP-UDP2 and the options after it are still read" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var o = Options{};
    try std.testing.expectEqual(Parsed.run, try parseOptions(arena_state.allocator(), &.{ "omastation", "--udp-version", "3", "--port", "3390" }, 1, &o));
    try std.testing.expectEqual(omastation.multitransport.rdpudp_protocol_version_3, o.udp_version);
    try std.testing.expectEqual(@as(u16, 3390), o.port);
}

test "--gpu takes a render node path or its name under /dev/dri, and --codecs all keeps it" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var o = Options{};
    try std.testing.expectEqual(Parsed.run, try parseOptions(arena_state.allocator(), &.{ "omastation", "--gpu", "renderD129", "--codecs", "all" }, 1, &o));
    try std.testing.expectEqualStrings("/dev/dri/renderD129", o.features.graphics.vaapi_device.?);
    try std.testing.expectEqual(Parsed.run, try parseOptions(arena_state.allocator(), &.{ "omastation", "--gpu", "/dev/dri/renderD128" }, 1, &o));
    try std.testing.expectEqualStrings("/dev/dri/renderD128", o.features.graphics.vaapi_device.?);
    try std.testing.expect(o.features.graphics.avc420);
}

test "every option the usage text shows with a value consumes it" {
    // An option in the usage text without a sample here fails the test.
    const samples = [_]struct { []const u8, [:0]const u8 }{
        .{ "--port", "3391" },              .{ "--cert", "/c" },                   .{ "--key", "/k" },
        .{ "--credentials", "/x" },         .{ "--pam-service", "login" },         .{ "--user", "u" },
        .{ "--lock-command", "true" },      .{ "--helper-socket", "/h" },          .{ "--reconnect-grace", "5" },
        .{ "--alt-drag", "on" },            .{ "--heartbeat", "5" },               .{ "--hyprland-plugin", "none" },
        .{ "--frame-interval", "31" },      .{ "--capture-backend", "wlr" },       .{ "--echo", "100" },
        .{ "--codecs", "all" },             .{ "--lossy-motion", "auto" },         .{ "--bulk", "rdp61" },
        .{ "--audio-quality", "dynamic" },  .{ "--audio-max-bandwidth", "22201" }, .{ "--remoteapp-launcher", "a --" },
        .{ "--udp-version", "3" },          .{ "--mic-buffer-max", "300" },        .{ "--touch", "auto" },
        .{ "--log-level", "info" },         .{ "--flight-record", "off" },         .{ "--test-video", "640x360" },
        .{ "--test-scene", "scroll_busy" }, .{ "--cursor", "auto" },               .{ "--gpu", "renderD129" },
    };
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var lines = std.mem.splitScalar(u8, usage, '\n');
    var used: [samples.len]bool = @splat(false);
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "  --")) continue;
        const name = std.mem.sliceTo(line[2..], ' ');
        const after = line[2 + name.len ..];
        if (after.len < 2 or !(std.ascii.isUpper(after[1]) or after[1] == '"')) continue;
        const k = for (samples, 0..) |s, k| {
            if (std.mem.eql(u8, s[0], name)) break k;
        } else {
            std.debug.print("no sample value for {s}\n", .{name});
            return error.TestUnexpectedResult;
        };
        used[k] = true;
        var o = Options{};
        const args = [_][:0]const u8{ "omastation", try arena_state.allocator().dupeSentinel(u8, name, 0), samples[k][1], "--port", "3390" };
        try std.testing.expectEqual(Parsed.run, try parseOptions(arena_state.allocator(), &args, 1, &o));
        try std.testing.expectEqual(@as(u16, 3390), o.port);
    }
    for (used, samples) |u, s| if (!u) {
        std.debug.print("{s} is not in the usage text\n", .{s[0]});
        return error.TestUnexpectedResult;
    };
}
