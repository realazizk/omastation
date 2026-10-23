//! Connection features: each entry of `list` serves virtual channels or an event source of its own.
//! vc.zig wires up its optional declarations (static_channels, dynamic_channels, Error, start_stage,
//! static_show_protocol) and callbacks (vc.VTable). Features never log user data.

const std = @import("std");
const channels = @import("channels.zig");
const codec_policy = @import("codec_policy.zig");
const vc = @import("vc.zig");
const hypr = @import("../session/hypr.zig");
const xdg = @import("../session/xdg.zig");
const audio_mod = @import("../audio/audio.zig");
const rdpsnd = @import("../channel/rdpsnd.zig");
pub const echo = @import("echo.zig");
pub const session_info = @import("session_info.zig");
pub const heartbeat = @import("heartbeat.zig");
pub const drives = @import("drives.zig");
pub const remoteapp = @import("remoteapp.zig");
pub const multitransport = @import("multitransport.zig");
const udp = @import("udp.zig");
pub const clipboard = @import("clipboard.zig");
pub const touch = @import("touch.zig");
pub const audio = @import("audio.zig");

/// Position is the order of Create Requests and calls. DisplayControl precedes Graphics: the
/// client decides early whether the session can be resized.
pub const list = .{
    channels.DisplayControl,
    channels.Graphics,
    echo.Echo,
    session_info.SessionInfo,
    heartbeat.Heartbeat,
    drives.Rdpdr,
    remoteapp.RemoteApp,
    multitransport.Multitransport,
    clipboard.Clipboard,
    touch.Touch,
    // Audio last: the other two use its Bridge.
    audio.AudioPlayback,
    audio.AudioInput,
    audio.Audio,
};

pub const Options = struct {
    /// Echo Request period (echo.zig); null: no ECHO channel.
    echo_period_ms: ?u32 = null,
    /// 0: no Server Heartbeat PDUs.
    heartbeat_period_s: u8 = heartbeat.default_period_s,
    /// pacing.zig; Windows uses 31; range 8..200.
    frame_interval_ms: u32 = 31,
    graphics: codec_policy.Options = .{},
    clipboard: bool = true,
    /// Client file copies appear as a FUSE tree under $XDG_RUNTIME_DIR/omastation/clipboard.
    clipboard_files: clipboard.Files = .fuse,
    /// For file system work in features; null: a single-threaded std.Io of their own.
    io: ?std.Io = null,
    /// Desktop sound to the client, its microphone to the desktop, the desk muted; --no-audio.
    audio: bool = true,
    /// null: the desktop's PipeWire when `audio_pipewire` (test-pattern mode has no audio).
    audio_backend: ?audio_mod.Backend = null,
    /// Set by main.zig in --desktop mode only.
    audio_pipewire: bool = false,
    /// Windows' "Limit audio playback quality" policy; .dynamic, Windows' default, runs every
    /// client in Dynamic mode (AAC, else a format fitting the measured bandwidth).
    audio_quality: rdpsnd.QualityLimit = .dynamic,
    /// B/s; --audio-max-bandwidth.
    audio_max_bandwidth: u32 = rdpsnd.default_max_bandwidth,
    /// The Server Audio Formats list, matching Windows.
    audio_formats: []const rdpsnd.AudioFormat = &rdpsnd.default_server_formats,
    /// Microphone jitter buffer limit (--mic-buffer-max); 40: a fixed 40 ms buffer.
    mic_buffer_max_ms: u32 = 300,
    /// Desktop sessions with an authenticated user; off with --no-drives.
    drives: bool = true,
    drives_read_only: bool = false,
    /// Mount ($XDG_RUNTIME_DIR) and link ("$HOME/RDP Drives") directories; no runtime directory: no drives.
    drives_runtime_dir: ?[]const u8 = null,
    drives_link_dir: ?[]const u8 = null,
    /// Serve drives without a desktop, mounted by this backend (tests).
    drives_test_backend: ?drives.TestBackend = null,
    /// MS-RDPERP for clients that ask (INFO_RAIL); false: they get the full desktop.
    remoteapp: bool = true,
    /// null: no icons, and Execute requests are refused.
    remoteapp_xdg: ?xdg.Dirs = null,
    /// Put in front of launched programs (Omarchy: "uwsm-app --").
    remoteapp_launcher: []const []const u8 = &.{},
    /// $PATH the programs of Execute requests are checked against.
    remoteapp_path: ?[]const u8 = null,
    /// Hyprland to follow without a desktop session (test-pattern mode); null: RemoteApp needs --desktop.
    remoteapp_ipc: ?hypr.Ipc = null,
    /// A RemoteApp session ends this long after its last window closed; null: never.
    remoteapp_end_ms: ?u32 = 5_000,
    /// Shared UDP front end; null: no multitransport.
    udp: ?*udp.Listener = null,
    /// MS-RDPEI: desktop sessions (.auto), also without a desktop (.on), or never (.off).
    touch: touch.Mode = .auto,
};

pub const Error = vc.Errors(list);
