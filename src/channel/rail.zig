//! MS-RDPERP remote applications (static channel "rail"): PDUs, capability sets,
//! window orders (2.2.1.3) and the server side. Strings are UTF-16LE, unterminated unless noted.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const rdp = @import("../proto/rdp.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{
    EndOfBuffer,
    /// orderLength below 4, beyond the message, or below the order's fixed size.
    BadOrderLength,
    UnknownOrderType,
    UnexpectedOrderType,
    /// A field violates a MUST of 2.2.2 (odd UTF-16 length, unknown SystemParam, ...).
    InvalidField,
    TooLong,
    /// Window order: header byte not 0x2E, or OrderSize inconsistent with the data.
    BadOrderHeader,
    /// Window order: not exactly one of WINDOW_ORDER_TYPE_WINDOW, _NOTIFY, _DESKTOP.
    BadOrderType,
    /// Window order field needs TS_WINDOW_LEVEL_SUPPORTED_EX (2.2.1.1.2).
    FieldNotNegotiated,
    BadBpp,
    /// Capability negotiation failed (3.3.5.1.5); drop the connection.
    RailNotSupported,
    HandshakeNotReceived,
    NotNegotiated,
    OutOfMemory,
};

// --- 2.2.2 Static virtual channel -------------------------------------------

pub const channel_name = "rail";

pub const header_size: usize = 4;

pub const OrderType = enum(u16) {
    exec = 0x0001,
    activate = 0x0002,
    sysparam = 0x0003,
    syscommand = 0x0004,
    handshake = 0x0005,
    notify_event = 0x0006,
    window_move = 0x0008,
    local_move_size = 0x0009,
    min_max_info = 0x000A,
    client_status = 0x000B,
    sysmenu = 0x000C,
    langbar_info = 0x000D,
    get_appid_req = 0x000E,
    get_appid_resp = 0x000F,
    taskbar_info = 0x0010,
    language_ime_info = 0x0011,
    compartment_info = 0x0012,
    handshake_ex = 0x0013,
    zorder_sync = 0x0014,
    cloak = 0x0015,
    power_display_request = 0x0016,
    snap_arrange = 0x0017,
    get_appid_resp_ex = 0x0018,
    text_scale_info = 0x0019,
    caret_blink_info = 0x001A,
    exec_result = 0x0080,
    _,
};

pub const Direction = enum { client_to_server, server_to_client };

/// TS_RAIL_PDU_HEADER (2.2.2.1).
pub const Header = struct {
    order_type: u16,
    /// Length of the whole PDU, header included.
    order_length: u16,
};

pub fn encodeHeader(w: *bytes.Writer, h: Header) !void {
    try w.u16le(h.order_type);
    try w.u16le(h.order_length);
}

pub fn decodeHeader(pdu: []const u8) Error!Header {
    var r = bytes.Reader.init(pdu);
    const h = Header{ .order_type = try r.u16le(), .order_length = try r.u16le() };
    if (h.order_length < header_size or h.order_length > pdu.len) return error.BadOrderLength;
    return h;
}

fn fixedLength(t: OrderType) ?usize {
    return switch (t) {
        .exec => 12,
        .activate => 9,
        .sysparam => 8,
        .syscommand => 10,
        .handshake => 8,
        .notify_event => 16,
        .window_move => 16,
        .local_move_size => 16,
        .min_max_info => 24,
        .client_status => 8,
        .sysmenu => 12,
        .langbar_info => 8,
        .get_appid_req => 8,
        .get_appid_resp => 8 + appid_field_size,
        .taskbar_info => 16,
        .language_ime_info => 46,
        .compartment_info => 20,
        .handshake_ex => 12,
        .zorder_sync => 8,
        .cloak => 9,
        .power_display_request => 8,
        .snap_arrange => 16,
        .get_appid_resp_ex => 12 + 2 * appid_field_size,
        .text_scale_info => 8,
        .caret_blink_info => 8,
        .exec_result => 16,
        _ => null,
    };
}

// --- 2.2.2.2 Initialization --------------------------------------------------

/// TS_RAIL_ORDER_HANDSHAKE (2.2.2.2.1).
pub const Handshake = struct { build_number: u32 };

/// TS_RAIL_ORDER_HANDSHAKE_EX (2.2.2.2.3).
pub const HandshakeEx = struct { build_number: u32, flags: u32 };

pub const handshake_ex_flags_hidef: u32 = 0x00000001;
pub const handshake_ex_flags_extended_spi_supported: u32 = 0x00000002;
pub const handshake_ex_flags_snap_arrange_supported: u32 = 0x00000004;
pub const handshake_ex_flags_text_scale_supported: u32 = 0x00000008;
pub const handshake_ex_flags_caret_blink_supported: u32 = 0x00000010;
pub const handshake_ex_flags_extended_spi_2_supported: u32 = 0x00000020;
pub const handshake_ex_flags_extended_spi_3_supported: u32 = 0x00000040;

/// TS_RAIL_ORDER_CLIENTSTATUS (2.2.2.2.2).
pub const ClientStatus = struct { flags: u32 };

pub const clientstatus_allow_local_move_size: u32 = 0x00000001;
pub const clientstatus_autoreconnect: u32 = 0x00000002;
pub const clientstatus_zorder_sync: u32 = 0x00000004;
pub const clientstatus_window_resize_margin_supported: u32 = 0x00000010;
pub const clientstatus_high_dpi_icons_supported: u32 = 0x00000020;
pub const clientstatus_appbar_remoting_supported: u32 = 0x00000040;
pub const clientstatus_power_display_request_supported: u32 = 0x00000080;
pub const clientstatus_bidirectional_cloak_supported: u32 = 0x00000200;
pub const clientstatus_suppress_icon_orders: u32 = 0x00000400;

// --- 2.2.2.3 Program launching ------------------------------------------------

/// TS_RAIL_ORDER_EXEC (2.2.2.3.1).
pub const Exec = struct {
    flags: u16,
    exe_or_file: []const u8,
    working_dir: []const u8 = &.{},
    arguments: []const u8 = &.{},
};

pub const exec_flag_expand_working_directory: u16 = 0x0001;
pub const exec_flag_translate_files: u16 = 0x0002;
pub const exec_flag_file: u16 = 0x0004;
pub const exec_flag_expand_arguments: u16 = 0x0008;
pub const exec_flag_app_user_model_id: u16 = 0x0010;

pub const max_exe_or_file_len: usize = 520;
pub const max_working_dir_len: usize = 520;
pub const max_arguments_len: usize = 16000;

/// TS_RAIL_ORDER_EXEC_RESULT (2.2.2.3.2).
pub const ExecResult = struct {
    flags: u16,
    exec_result: u16,
    raw_result: u32,
    exe_or_file: []const u8,
};

pub const exec_s_ok: u16 = 0x0000;
pub const exec_e_hook_not_loaded: u16 = 0x0001;
pub const exec_e_decode_failed: u16 = 0x0002;
pub const exec_e_not_in_allowlist: u16 = 0x0003;
pub const exec_e_file_not_found: u16 = 0x0005;
pub const exec_e_fail: u16 = 0x0006;
pub const exec_e_session_locked: u16 = 0x0007;

// --- 2.2.2.4 / 2.2.2.5 System parameters ----------------------------------------

pub const spi_setdragfullwindows: u32 = 0x00000025;
pub const spi_setkeyboardcues: u32 = 0x0000100B;
pub const spi_setkeyboardpref: u32 = 0x00000045;
pub const spi_setworkarea: u32 = 0x0000002F;
pub const rail_spi_displaychange: u32 = 0x0000F001;
pub const spi_setmousebuttonswap: u32 = 0x00000021;
pub const rail_spi_taskbarpos: u32 = 0x0000F000;
pub const spi_sethighcontrast: u32 = 0x00000043;
pub const spi_setcaretwidth: u32 = 0x00002007;
pub const spi_setstickykeys: u32 = 0x0000003B;
pub const spi_settogglekeys: u32 = 0x00000035;
pub const spi_setfilterkeys: u32 = 0x00000033;
pub const rail_spi_display_animations_enabled: u32 = 0x0000F002;
pub const rail_spi_display_advanced_effects_enabled: u32 = 0x0000F003;
pub const rail_spi_display_auto_hide_scrollbars: u32 = 0x0000F004;
pub const rail_spi_display_message_duration: u32 = 0x0000F005;
pub const rail_spi_closed_caption_font_color: u32 = 0x0000F006;
pub const rail_spi_closed_caption_font_opacity: u32 = 0x0000F007;
pub const rail_spi_closed_caption_font_size: u32 = 0x0000F008;
pub const rail_spi_closed_caption_font_style: u32 = 0x0000F009;
pub const rail_spi_closed_caption_font_edge_effect: u32 = 0x0000F00A;
pub const rail_spi_closed_caption_background_color: u32 = 0x0000F00B;
pub const rail_spi_closed_caption_background_opacity: u32 = 0x0000F00C;
pub const rail_spi_closed_caption_region_color: u32 = 0x0000F00D;
pub const rail_spi_closed_caption_region_opacity: u32 = 0x0000F00E;
pub const rail_spi_accent_color: u32 = 0x0000F00F;
pub const rail_spi_system_uses_light_theme: u32 = 0x0000F010;
pub const rail_spi_apps_use_light_theme: u32 = 0x0000F011;
/// Server System Parameters Update PDU (2.2.2.5.1).
pub const spi_setscreensaveactive: u32 = 0x00000011;
pub const spi_setscreensavesecure: u32 = 0x00000077;

/// TS_RECTANGLE_16 (2.2.1.2.2), unsigned.
pub const Rect16 = struct { left: u16, top: u16, right: u16, bottom: u16 };

/// TS_HIGHCONTRAST (2.2.2.4.2); `color_scheme` is the raw ColorScheme field.
pub const HighContrast = struct { flags: u32, color_scheme: []const u8 };

pub const hcf_highcontraston: u32 = 0x00000001;
pub const hcf_available: u32 = 0x00000002;
pub const hcf_hotkeyactive: u32 = 0x00000004;
pub const hcf_confirmhotkey: u32 = 0x00000008;
pub const hcf_hotkeysound: u32 = 0x00000010;

/// TS_FILTERKEYS (2.2.2.4.3).
pub const FilterKeys = struct {
    flags: u32,
    wait_time: u32,
    delay_time: u32,
    repeat_time: u32,
    bounce_time: u32,
};

/// TS_ACCENTCOLOR (2.2.2.4.6).
pub const AccentColor = struct {
    fields_valid: u32,
    accent_color: u32 = 0,
    colorization_color: u32 = 0,
    colorization_color_balance: u32 = 0,
    colorization_afterglow: u32 = 0,
    colorization_afterglow_balance: u32 = 0,
    colorization_blur_balance: u32 = 0,
    colorization_glass_attribute: u32 = 0,
    color_prevalence: u32 = 0,
    enable_window_colorization: u32 = 0,
    accent_color_menu: u32 = 0,
    start_color_menu: u32 = 0,
    accent_palette: []const u8 = &.{},
};

/// TS_RAIL_ORDER_SYSPARAM body; SystemParam selects the variant (2.2.2.4.1, 2.2.2.5.1).
pub const SysParamValue = union(enum) {
    boolean: bool,
    byte: u8,
    dword: u32,
    rect: Rect16,
    high_contrast: HighContrast,
    filter_keys: FilterKeys,
    accent_color: AccentColor,
};

/// TS_RAIL_ORDER_SYSPARAM (2.2.2.4.1 client, 2.2.2.5.1 server).
pub const SysParam = struct { param: u32, value: SysParamValue };

// --- 2.2.2.6 Local client events ---------------------------------------------------

/// TS_RAIL_ORDER_ACTIVATE (2.2.2.6.1).
pub const Activate = struct { window_id: u32, enabled: bool };

/// TS_RAIL_ORDER_SYSMENU (2.2.2.6.2).
pub const SysMenu = struct { window_id: u32, left: i16, top: i16 };

/// TS_RAIL_ORDER_SYSCOMMAND (2.2.2.6.3).
pub const SysCommand = struct { window_id: u32, command: u16 };

pub const sc_size: u16 = 0xF000;
pub const sc_move: u16 = 0xF010;
pub const sc_minimize: u16 = 0xF020;
pub const sc_maximize: u16 = 0xF030;
pub const sc_close: u16 = 0xF060;
pub const sc_keymenu: u16 = 0xF100;
pub const sc_restore: u16 = 0xF120;
pub const sc_default: u16 = 0xF160;

/// TS_RAIL_ORDER_NOTIFY_EVENT (2.2.2.6.4).
pub const NotifyEvent = struct { window_id: u32, notify_icon_id: u32, message: u32 };

pub const wm_lbuttondown: u32 = 0x00000201;
pub const wm_lbuttonup: u32 = 0x00000202;
pub const wm_rbuttondown: u32 = 0x00000204;
pub const wm_rbuttonup: u32 = 0x00000205;
pub const wm_contextmenu: u32 = 0x0000007B;
pub const wm_lbuttondblclk: u32 = 0x00000203;
pub const wm_rbuttondblclk: u32 = 0x00000206;
pub const nin_select: u32 = 0x00000400;
pub const nin_keyselect: u32 = 0x00000401;
pub const nin_balloonshow: u32 = 0x00000402;
pub const nin_balloonhide: u32 = 0x00000403;
pub const nin_balloontimeout: u32 = 0x00000404;
pub const nin_balloonuserclick: u32 = 0x00000405;

/// TS_RAIL_ORDER_GET_APPID_REQ (2.2.2.6.5).
pub const GetAppIdReq = struct { window_id: u32 };

// --- 2.2.2.7 Window move ------------------------------------------------------------

/// TS_RAIL_ORDER_MINMAXINFO (2.2.2.7.1).
pub const MinMaxInfo = struct {
    window_id: u32,
    max_width: i16,
    max_height: i16,
    max_pos_x: i16,
    max_pos_y: i16,
    min_track_width: i16,
    min_track_height: i16,
    max_track_width: i16,
    max_track_height: i16,
};

/// TS_RAIL_ORDER_LOCALMOVESIZE (2.2.2.7.2, 2.2.2.7.3); `pos_*` is TopLeftX/Y for an end.
pub const LocalMoveSize = struct {
    window_id: u32,
    is_move_size_start: bool,
    move_size_type: u16,
    pos_x: i16,
    pos_y: i16,
};

pub const wmsz_left: u16 = 0x0001;
pub const wmsz_right: u16 = 0x0002;
pub const wmsz_top: u16 = 0x0003;
pub const wmsz_topleft: u16 = 0x0004;
pub const wmsz_topright: u16 = 0x0005;
pub const wmsz_bottom: u16 = 0x0006;
pub const wmsz_bottomleft: u16 = 0x0007;
pub const wmsz_bottomright: u16 = 0x0008;
pub const wmsz_move: u16 = 0x0009;
pub const wmsz_keymove: u16 = 0x000A;
pub const wmsz_keysize: u16 = 0x000B;

/// TS_RAIL_ORDER_WINDOWMOVE (2.2.2.7.4), also TS_RAIL_ORDER_SNAP_ARRANGE (2.2.2.7.5).
pub const WindowMove = struct { window_id: u32, left: i16, top: i16, right: i16, bottom: i16 };

// --- 2.2.2.8 Application ID ------------------------------------------------------------

/// ApplicationId / ProcessImageName size (2.2.2.8.1): 260 WCHARs, null-terminated, zero-padded.
pub const appid_field_size: usize = 520;

/// TS_RAIL_ORDER_GET_APPID_RESP (2.2.2.8.1); `application_id` excludes the terminator.
pub const GetAppIdResp = struct { window_id: u32, application_id: []const u8 };

/// TS_RAIL_ORDER_GET_APPID_RESP_EX (2.2.2.8.2).
pub const GetAppIdRespEx = struct {
    window_id: u32,
    application_id: []const u8,
    process_id: u32,
    process_image_name: []const u8,
};

// --- 2.2.2.9 / 2.2.2.10 Language bar and language sync -----------------------------------

/// TS_RAIL_ORDER_LANGBARINFO (2.2.2.9.1).
pub const LangBarInfo = struct { status: u32 };

pub const tf_sft_shownormal: u32 = 0x00000001;
pub const tf_sft_dock: u32 = 0x00000002;
pub const tf_sft_minimized: u32 = 0x00000004;
pub const tf_sft_hidden: u32 = 0x00000008;
pub const tf_sft_notransparency: u32 = 0x00000010;
pub const tf_sft_lowtransparency: u32 = 0x00000020;
pub const tf_sft_hightransparency: u32 = 0x00000040;
pub const tf_sft_labels: u32 = 0x00000080;
pub const tf_sft_nolabels: u32 = 0x00000100;
pub const tf_sft_extraiconsonminimized: u32 = 0x00000200;
pub const tf_sft_noextraiconsonminimized: u32 = 0x00000400;
pub const tf_sft_deskband: u32 = 0x00000800;

/// GUID (2.2.2.10.1.1, MS-DTYP 2.3.4): Data1..3 little-endian.
pub const Guid = struct { data1: u32, data2: u16, data3: u16, data4: [8]u8 };

pub const guid_null: Guid = .{ .data1 = 0, .data2 = 0, .data3 = 0, .data4 = @splat(0) };

/// TS_RAIL_ORDER_LANGUAGEIMEINFO (2.2.2.10.1).
pub const LanguageImeInfo = struct {
    profile_type: u32,
    language_id: u16,
    language_profile_clsid: Guid,
    profile_guid: Guid,
    keyboard_layout: u32,
};

pub const tf_profiletype_inputprocessor: u32 = 0x00000001;
pub const tf_profiletype_keyboardlayout: u32 = 0x00000002;

/// TS_RAIL_ORDER_COMPARTMENTINFO (2.2.2.10.2).
pub const CompartmentInfo = struct {
    ime_state: u32,
    ime_conv_mode: u32,
    ime_sentence_mode: u32,
    kana_mode: u32,
};

/// TS_RAIL_ORDER_ZORDER_SYNC (2.2.2.11.1).
pub const ZOrderSync = struct { window_id_marker: u32 };

/// TS_RAIL_ORDER_CLOAK (2.2.2.12.1).
pub const Cloak = struct { window_id: u32, cloaked: bool };

/// TS_RAIL_ORDER_POWER_DISPLAY_REQUEST (2.2.2.13.1).
pub const PowerDisplayRequest = struct { active: bool };

/// TS_RAIL_ORDER_TASKBARINFO (2.2.2.14.1).
pub const TaskbarInfo = struct { message: u32, window_id_tab: u32, body: u32 };

pub const taskbar_msg_tab_register: u32 = 0x00000001;
pub const taskbar_msg_tab_unregister: u32 = 0x00000002;
pub const taskbar_msg_tab_order: u32 = 0x00000003;
pub const taskbar_msg_tab_active: u32 = 0x00000004;
pub const taskbar_msg_tab_properties: u32 = 0x00000005;

/// TS_RAIL_ORDER_TEXTSCALEINFO (2.2.2.15.1): 100..225.
pub const TextScaleInfo = struct { text_scale_factor: u32 };

/// TS_RAIL_ORDER_CARETBLINKINFO (2.2.2.15.2): 0xFFFFFFFF = do not blink.
pub const CaretBlinkInfo = struct { caret_blink_rate: u32 };

pub const Order = union(enum) {
    exec: Exec,
    activate: Activate,
    sysparam: SysParam,
    syscommand: SysCommand,
    handshake: Handshake,
    notify_event: NotifyEvent,
    window_move: WindowMove,
    local_move_size: LocalMoveSize,
    min_max_info: MinMaxInfo,
    client_status: ClientStatus,
    sysmenu: SysMenu,
    langbar_info: LangBarInfo,
    get_appid_req: GetAppIdReq,
    get_appid_resp: GetAppIdResp,
    taskbar_info: TaskbarInfo,
    language_ime_info: LanguageImeInfo,
    compartment_info: CompartmentInfo,
    handshake_ex: HandshakeEx,
    zorder_sync: ZOrderSync,
    cloak: Cloak,
    power_display_request: PowerDisplayRequest,
    snap_arrange: WindowMove,
    get_appid_resp_ex: GetAppIdRespEx,
    text_scale_info: TextScaleInfo,
    caret_blink_info: CaretBlinkInfo,
    exec_result: ExecResult,
};

pub fn orderTypeOf(order: Order) Error!OrderType {
    return switch (order) {
        inline else => |_, tag| @field(OrderType, @tagName(tag)),
    };
}

/// Whether `t` may be sent in `dir` (2.2.2.1 table).
pub fn allowedDirection(t: OrderType, dir: Direction) Error!bool {
    const c2s: u2 = 1;
    const s2c: u2 = 2;
    const ways: u2 = switch (t) {
        .exec, .activate, .syscommand, .notify_event, .window_move, .client_status, .sysmenu, .get_appid_req, .language_ime_info, .snap_arrange, .text_scale_info, .caret_blink_info => c2s,
        .local_move_size, .min_max_info, .get_appid_resp, .taskbar_info, .handshake_ex, .zorder_sync, .power_display_request, .get_appid_resp_ex, .exec_result => s2c,
        .sysparam, .handshake, .langbar_info, .compartment_info, .cloak => c2s | s2c,
        _ => return error.UnknownOrderType,
    };
    return ways & (if (dir == .client_to_server) c2s else s2c) != 0;
}

/// Writes one complete PDU; a refused order writes nothing.
pub fn encode(w: *bytes.Writer, order: Order) !void {
    const start = w.len();
    errdefer w.list.shrinkRetainingCapacity(start);
    try w.u16le(@backingInt(try orderTypeOf(order)));
    try w.u16le(0); // orderLength, patched below
    switch (order) {
        .exec => |e| {
            if (e.exe_or_file.len == 0) return error.InvalidField; // 2.2.2.3.1 "MUST be nonzero"
            try checkUtf16(e.exe_or_file.len, max_exe_or_file_len);
            try checkUtf16(e.working_dir.len, max_working_dir_len);
            try checkUtf16(e.arguments.len, max_arguments_len);
            try w.u16le(e.flags);
            try w.u16le(@intCast(e.exe_or_file.len));
            try w.u16le(@intCast(e.working_dir.len));
            try w.u16le(@intCast(e.arguments.len));
            try w.bytes(e.exe_or_file);
            try w.bytes(e.working_dir);
            try w.bytes(e.arguments);
        },
        .exec_result => |e| {
            if (e.exe_or_file.len == 0) return error.InvalidField; // 2.2.2.3.2
            try checkUtf16(e.exe_or_file.len, max_exe_or_file_len);
            try w.u16le(e.flags);
            try w.u16le(e.exec_result);
            try w.u32le(e.raw_result);
            try w.u16le(0); // Padding
            try w.u16le(@intCast(e.exe_or_file.len));
            try w.bytes(e.exe_or_file);
        },
        .sysparam => |p| try encodeSysParam(w, p),
        .activate => |a| {
            try w.u32le(a.window_id);
            try w.byte(@intFromBool(a.enabled));
        },
        .sysmenu => |m| {
            try w.u32le(m.window_id);
            try w.u16le(@bitCast(m.left));
            try w.u16le(@bitCast(m.top));
        },
        .syscommand => |c| {
            if (!validCommand(c.command)) return error.InvalidField;
            try w.u32le(c.window_id);
            try w.u16le(c.command);
        },
        .handshake => |h| try w.u32le(h.build_number),
        .handshake_ex => |h| {
            try w.u32le(h.build_number);
            try w.u32le(h.flags);
        },
        .client_status => |c| try w.u32le(c.flags),
        .notify_event => |n| {
            try w.u32le(n.window_id);
            try w.u32le(n.notify_icon_id);
            try w.u32le(n.message);
        },
        .window_move, .snap_arrange => |m| {
            try w.u32le(m.window_id);
            inline for (.{ m.left, m.top, m.right, m.bottom }) |v| try w.u16le(@bitCast(v));
        },
        .local_move_size => |m| {
            try w.u32le(m.window_id);
            try w.u16le(@intFromBool(m.is_move_size_start));
            try w.u16le(m.move_size_type);
            try w.u16le(@bitCast(m.pos_x));
            try w.u16le(@bitCast(m.pos_y));
        },
        .min_max_info => |m| {
            try w.u32le(m.window_id);
            inline for (.{ m.max_width, m.max_height, m.max_pos_x, m.max_pos_y, m.min_track_width, m.min_track_height, m.max_track_width, m.max_track_height }) |v|
                try w.u16le(@bitCast(v));
        },
        .langbar_info => |l| try w.u32le(l.status),
        .get_appid_req => |g| try w.u32le(g.window_id),
        .get_appid_resp => |g| {
            try w.u32le(g.window_id);
            try writeAppIdField(w, g.application_id);
        },
        .get_appid_resp_ex => |g| {
            try w.u32le(g.window_id);
            try writeAppIdField(w, g.application_id);
            try w.u32le(g.process_id);
            try writeAppIdField(w, g.process_image_name);
        },
        .taskbar_info => |t| {
            if (!validTaskbarMessage(t.message)) return error.InvalidField;
            try w.u32le(t.message);
            try w.u32le(t.window_id_tab);
            try w.u32le(t.body);
        },
        .language_ime_info => |l| {
            try checkLanguageProfile(l);
            try w.u32le(l.profile_type);
            try w.u16le(l.language_id);
            try writeGuid(w, l.language_profile_clsid);
            try writeGuid(w, l.profile_guid);
            try w.u32le(l.keyboard_layout);
        },
        .compartment_info => |c| {
            try w.u32le(c.ime_state);
            try w.u32le(c.ime_conv_mode);
            try w.u32le(c.ime_sentence_mode);
            try w.u32le(c.kana_mode);
        },
        .zorder_sync => |z| try w.u32le(z.window_id_marker),
        .cloak => |c| {
            try w.u32le(c.window_id);
            try w.byte(@intFromBool(c.cloaked));
        },
        .power_display_request => |p| try w.u32le(@intFromBool(p.active)),
        .text_scale_info => |t| try w.u32le(t.text_scale_factor),
        .caret_blink_info => |c| try w.u32le(c.caret_blink_rate),
    }
    const len = w.len() - start;
    if (len > std.math.maxInt(u16)) return error.TooLong;
    w.patchU16le(start + 2, @intCast(len));
}

/// Slices point into `pdu`. Bytes after orderLength are ignored: Windows clients send some (4.3.1).
pub fn decode(pdu: []const u8, dir: Direction) Error!Order {
    const h = try decodeHeader(pdu);
    const t: OrderType = @fromBackingInt(@intCast(h.order_type));
    if (!try allowedDirection(t, dir)) return error.UnexpectedOrderType;
    if (h.order_length < fixedLength(t).?) return error.BadOrderLength;
    var r = bytes.Reader.init(pdu[header_size..h.order_length]);
    return switch (t) {
        .exec => .{ .exec = try decodeExec(&r) },
        .exec_result => .{ .exec_result = try decodeExecResult(&r) },
        .sysparam => .{ .sysparam = try decodeSysParam(&r, dir) },
        .activate => blk: {
            const id = try r.u32le();
            break :blk .{ .activate = .{ .window_id = id, .enabled = try r.byte() != 0 } };
        },
        .sysmenu => blk: {
            const id = try r.u32le();
            const left = try readI16(&r);
            break :blk .{ .sysmenu = .{ .window_id = id, .left = left, .top = try readI16(&r) } };
        },
        .syscommand => blk: {
            const id = try r.u32le();
            const command = try r.u16le();
            if (!validCommand(command)) return error.InvalidField;
            break :blk .{ .syscommand = .{ .window_id = id, .command = command } };
        },
        .handshake => .{ .handshake = .{ .build_number = try r.u32le() } },
        .handshake_ex => blk: {
            const build = try r.u32le();
            break :blk .{ .handshake_ex = .{ .build_number = build, .flags = try r.u32le() } };
        },
        .client_status => .{ .client_status = .{ .flags = try r.u32le() } },
        .notify_event => blk: {
            const id = try r.u32le();
            const icon = try r.u32le();
            break :blk .{ .notify_event = .{ .window_id = id, .notify_icon_id = icon, .message = try r.u32le() } };
        },
        .window_move => .{ .window_move = try decodeWindowMove(&r) },
        .snap_arrange => .{ .snap_arrange = try decodeWindowMove(&r) },
        .local_move_size => blk: {
            const id = try r.u32le();
            // 2.2.2.7.2: a start is any nonzero value; 2.2.2.7.3: an end is 0.
            const start = try r.u16le() != 0;
            const kind = try r.u16le();
            const x = try readI16(&r);
            break :blk .{ .local_move_size = .{ .window_id = id, .is_move_size_start = start, .move_size_type = kind, .pos_x = x, .pos_y = try readI16(&r) } };
        },
        .min_max_info => blk: {
            var m: MinMaxInfo = undefined;
            m.window_id = try r.u32le();
            inline for (.{ "max_width", "max_height", "max_pos_x", "max_pos_y", "min_track_width", "min_track_height", "max_track_width", "max_track_height" }) |f|
                @field(m, f) = try readI16(&r);
            break :blk .{ .min_max_info = m };
        },
        .langbar_info => .{ .langbar_info = .{ .status = try r.u32le() } },
        .get_appid_req => .{ .get_appid_req = .{ .window_id = try r.u32le() } },
        .get_appid_resp => blk: {
            const id = try r.u32le();
            break :blk .{ .get_appid_resp = .{ .window_id = id, .application_id = try readAppIdField(&r) } };
        },
        .get_appid_resp_ex => blk: {
            const id = try r.u32le();
            const app = try readAppIdField(&r);
            const pid = try r.u32le();
            break :blk .{ .get_appid_resp_ex = .{ .window_id = id, .application_id = app, .process_id = pid, .process_image_name = try readAppIdField(&r) } };
        },
        .taskbar_info => blk: {
            const msg = try r.u32le();
            if (!validTaskbarMessage(msg)) return error.InvalidField;
            const tab = try r.u32le();
            break :blk .{ .taskbar_info = .{ .message = msg, .window_id_tab = tab, .body = try r.u32le() } };
        },
        .language_ime_info => blk: {
            var l: LanguageImeInfo = undefined;
            l.profile_type = try r.u32le();
            l.language_id = try r.u16le();
            l.language_profile_clsid = try readGuid(&r);
            l.profile_guid = try readGuid(&r);
            l.keyboard_layout = try r.u32le();
            try checkLanguageProfile(l);
            break :blk .{ .language_ime_info = l };
        },
        .compartment_info => blk: {
            var c: CompartmentInfo = undefined;
            inline for (.{ "ime_state", "ime_conv_mode", "ime_sentence_mode", "kana_mode" }) |f| @field(c, f) = try r.u32le();
            break :blk .{ .compartment_info = c };
        },
        .zorder_sync => .{ .zorder_sync = .{ .window_id_marker = try r.u32le() } },
        .cloak => blk: {
            const id = try r.u32le();
            break :blk .{ .cloak = .{ .window_id = id, .cloaked = try r.byte() != 0 } };
        },
        .power_display_request => .{ .power_display_request = .{ .active = try r.u32le() != 0 } },
        .text_scale_info => .{ .text_scale_info = .{ .text_scale_factor = try r.u32le() } },
        .caret_blink_info => .{ .caret_blink_info = .{ .caret_blink_rate = try r.u32le() } },
        _ => unreachable, // allowedDirection rejected it
    };
}

fn readI16(r: *bytes.Reader) Error!i16 {
    return @bitCast(try r.u16le());
}

/// A UTF-16LE length: even (InvalidField) and at most `max` (TooLong).
fn checkUtf16(len: usize, max: usize) Error!void {
    if (len > max) return error.TooLong;
    if (len % 2 != 0) return error.InvalidField;
}

fn validCommand(c: u16) bool {
    return switch (c) {
        sc_size, sc_move, sc_minimize, sc_maximize, sc_close, sc_keymenu, sc_restore, sc_default => true,
        else => false,
    };
}

fn validTaskbarMessage(m: u32) bool {
    return m >= taskbar_msg_tab_register and m <= taskbar_msg_tab_properties;
}

fn decodeExec(r: *bytes.Reader) Error!Exec {
    const flags = try r.u16le();
    const exe_len = try r.u16le();
    const dir_len = try r.u16le();
    const args_len = try r.u16le();
    if (exe_len == 0) return error.InvalidField;
    try checkUtf16(exe_len, max_exe_or_file_len);
    try checkUtf16(dir_len, max_working_dir_len);
    try checkUtf16(args_len, max_arguments_len);
    const exe = try r.bytes(exe_len);
    const dir = try r.bytes(dir_len);
    return .{ .flags = flags, .exe_or_file = exe, .working_dir = dir, .arguments = try r.bytes(args_len) };
}

fn decodeExecResult(r: *bytes.Reader) Error!ExecResult {
    const flags = try r.u16le();
    const result = try r.u16le();
    const raw = try r.u32le();
    try r.skip(2); // Padding: not used
    const exe_len = try r.u16le();
    if (exe_len == 0) return error.InvalidField;
    try checkUtf16(exe_len, max_exe_or_file_len);
    return .{ .flags = flags, .exec_result = result, .raw_result = raw, .exe_or_file = try r.bytes(exe_len) };
}

fn decodeWindowMove(r: *bytes.Reader) Error!WindowMove {
    const id = try r.u32le();
    const left = try readI16(r);
    const top = try readI16(r);
    const right = try readI16(r);
    return .{ .window_id = id, .left = left, .top = top, .right = right, .bottom = try readI16(r) };
}

fn writeAppIdField(w: *bytes.Writer, s: []const u8) !void {
    // Leave room for the terminator; clients reject a field without one.
    try checkUtf16(s.len, appid_field_size - 2);
    try w.bytes(s);
    try w.zeros(appid_field_size - s.len);
}

fn readAppIdField(r: *bytes.Reader) Error![]const u8 {
    const field = try r.bytes(appid_field_size);
    var i: usize = 0;
    while (i < field.len) : (i += 2) {
        if (field[i] == 0 and field[i + 1] == 0) return field[0..i];
    }
    return error.InvalidField; // no terminator
}

fn writeGuid(w: *bytes.Writer, g: Guid) !void {
    try w.u32le(g.data1);
    try w.u16le(g.data2);
    try w.u16le(g.data3);
    try w.bytes(&g.data4);
}

fn readGuid(r: *bytes.Reader) Error!Guid {
    const d1 = try r.u32le();
    const d2 = try r.u16le();
    const d3 = try r.u16le();
    return .{ .data1 = d1, .data2 = d2, .data3 = d3, .data4 = (try r.bytes(8))[0..8].* };
}

/// 2.2.2.10.1: both GUIDs are GUID_NULL for TF_PROFILETYPE_KEYBOARDLAYOUT.
fn checkLanguageProfile(l: LanguageImeInfo) Error!void {
    if (l.profile_type != tf_profiletype_keyboardlayout) return;
    if (!std.meta.eql(l.language_profile_clsid, guid_null) or !std.meta.eql(l.profile_guid, guid_null))
        return error.InvalidField;
}

// --- system parameters (2.2.2.4.1, 2.2.2.5.1) ---------------------------------

const SysParamKind = std.meta.Tag(SysParamValue);

/// Body of a Client System Parameters Update (2.2.2.4.1 Body table).
fn clientSysParamKind(param: u32) ?SysParamKind {
    return switch (param) {
        spi_setdragfullwindows, spi_setkeyboardcues, spi_setkeyboardpref, spi_setmousebuttonswap => .boolean,
        rail_spi_display_animations_enabled, rail_spi_display_advanced_effects_enabled, rail_spi_display_auto_hide_scrollbars => .boolean,
        spi_setworkarea, rail_spi_displaychange, rail_spi_taskbarpos => .rect,
        spi_sethighcontrast => .high_contrast,
        spi_setcaretwidth, spi_setstickykeys, spi_settogglekeys => .dword,
        rail_spi_display_message_duration, rail_spi_system_uses_light_theme, rail_spi_apps_use_light_theme => .dword,
        spi_setfilterkeys => .filter_keys,
        rail_spi_closed_caption_font_color...rail_spi_closed_caption_region_opacity => .byte,
        rail_spi_accent_color => .accent_color,
        else => null,
    };
}

fn serverSysParamKind(param: u32) ?SysParamKind {
    return switch (param) {
        spi_setscreensaveactive, spi_setscreensavesecure => .boolean,
        else => null,
    };
}

/// HandshakeEx flag the server advertises before a client sends `param` (2.2.2.4.1); 0 if none.
pub fn sysParamHandshakeFlag(param: u32) u32 {
    return switch (param) {
        spi_setcaretwidth, spi_setstickykeys, spi_settogglekeys, spi_setfilterkeys => handshake_ex_flags_extended_spi_supported,
        rail_spi_display_animations_enabled...rail_spi_closed_caption_region_opacity => handshake_ex_flags_extended_spi_2_supported,
        rail_spi_accent_color...rail_spi_apps_use_light_theme => handshake_ex_flags_extended_spi_3_supported,
        else => 0,
    };
}

fn encodeSysParam(w: *bytes.Writer, p: SysParam) !void {
    const kind = clientSysParamKind(p.param) orelse serverSysParamKind(p.param) orelse return error.InvalidField;
    if (kind != std.meta.activeTag(p.value)) return error.InvalidField;
    try w.u32le(p.param);
    switch (p.value) {
        .boolean => |b| try w.byte(@intFromBool(b)),
        .byte => |b| try w.byte(b),
        .dword => |d| {
            if (p.param == spi_setcaretwidth and d == 0) return error.InvalidField;
            try w.u32le(d);
        },
        .rect => |r| try writeRect16(w, r),
        .high_contrast => |hc| {
            if (hc.color_scheme.len > std.math.maxInt(u32)) return error.TooLong;
            try w.u32le(hc.flags);
            try w.u32le(@intCast(hc.color_scheme.len));
            try w.bytes(hc.color_scheme);
        },
        .filter_keys => |f| {
            inline for (.{ f.flags, f.wait_time, f.delay_time, f.repeat_time, f.bounce_time }) |v| try w.u32le(v);
        },
        .accent_color => |a| {
            if (a.accent_palette.len > std.math.maxInt(u32)) return error.TooLong;
            inline for (accent_dwords) |f| try w.u32le(@field(a, f));
            try w.u32le(@intCast(a.accent_palette.len));
            try w.bytes(a.accent_palette);
        },
    }
}

/// TS_ACCENTCOLOR's DWORDs in wire order (2.2.2.4.6).
const accent_dwords = .{
    "fields_valid",               "accent_color",                 "colorization_color",
    "colorization_color_balance", "colorization_afterglow",       "colorization_afterglow_balance",
    "colorization_blur_balance",  "colorization_glass_attribute", "color_prevalence",
    "enable_window_colorization", "accent_color_menu",            "start_color_menu",
};

fn decodeSysParam(r: *bytes.Reader, dir: Direction) Error!SysParam {
    const param = try r.u32le();
    const kind = switch (dir) {
        .client_to_server => clientSysParamKind(param),
        .server_to_client => serverSysParamKind(param),
    } orelse return error.InvalidField; // "MUST be set to one of the following values"
    const value: SysParamValue = switch (kind) {
        .boolean => .{ .boolean = try r.byte() != 0 },
        .byte => .{ .byte = try r.byte() },
        .dword => blk: {
            const d = try r.u32le();
            if (param == spi_setcaretwidth and d == 0) return error.InvalidField;
            break :blk .{ .dword = d };
        },
        .rect => .{ .rect = try readRect16(r) },
        .high_contrast => blk: {
            const flags = try r.u32le();
            const len = try r.u32le();
            break :blk .{ .high_contrast = .{ .flags = flags, .color_scheme = try r.bytes(len) } };
        },
        .filter_keys => blk: {
            var f: FilterKeys = undefined;
            inline for (.{ "flags", "wait_time", "delay_time", "repeat_time", "bounce_time" }) |n| @field(f, n) = try r.u32le();
            break :blk .{ .filter_keys = f };
        },
        .accent_color => blk: {
            var a: AccentColor = .{ .fields_valid = 0 };
            inline for (accent_dwords) |n| @field(a, n) = try r.u32le();
            const len = try r.u32le();
            a.accent_palette = try r.bytes(len);
            break :blk .{ .accent_color = a };
        },
    };
    return .{ .param = param, .value = value };
}

fn writeRect16(w: *bytes.Writer, r: Rect16) !void {
    try w.u16le(r.left);
    try w.u16le(r.top);
    try w.u16le(r.right);
    try w.u16le(r.bottom);
}

fn readRect16(r: *bytes.Reader) Error!Rect16 {
    const left = try r.u16le();
    const top = try r.u16le();
    const right = try r.u16le();
    return .{ .left = left, .top = top, .right = right, .bottom = try r.u16le() };
}

// --- 2.2.1.1 Capability sets ------------------------------------------------

pub const capstype_rail: u16 = 0x0017;
pub const capstype_window: u16 = 0x0018;

pub const rail_level_supported: u32 = 0x00000001;
pub const rail_level_docked_langbar_supported: u32 = 0x00000002;
pub const rail_level_shell_integration_supported: u32 = 0x00000004;
pub const rail_level_language_ime_sync_supported: u32 = 0x00000008;
pub const rail_level_server_to_client_ime_sync_supported: u32 = 0x00000010;
pub const rail_level_hide_minimized_apps_supported: u32 = 0x00000020;
pub const rail_level_window_cloaking_supported: u32 = 0x00000040;
pub const rail_level_handshake_ex_supported: u32 = 0x00000080;

pub const window_level_not_supported: u32 = 0x00000000;
pub const window_level_supported: u32 = 0x00000001;
pub const window_level_supported_ex: u32 = 0x00000002;

/// Remote Programs Capability Set (2.2.1.1.1), 8 bytes on the wire.
pub const RailCapabilitySet = struct { rail_support_level: u32 };

/// Window List Capability Set (2.2.1.1.2), 11 bytes on the wire.
pub const WindowListCapabilitySet = struct {
    wnd_support_level: u32,
    num_icon_caches: u8,
    num_icon_cache_entries: u16,
};

pub fn encodeRailCapabilitySet(w: *bytes.Writer, c: RailCapabilitySet) !void {
    try w.u16le(capstype_rail);
    try w.u16le(rail_capset_len);
    try w.u32le(c.rail_support_level);
}

/// `cap` is the whole capability set, header included.
pub fn decodeRailCapabilitySet(cap: []const u8) Error!RailCapabilitySet {
    var r = try capabilityBody(cap, capstype_rail, rail_capset_len);
    return .{ .rail_support_level = try r.u32le() };
}

pub fn encodeWindowListCapabilitySet(w: *bytes.Writer, c: WindowListCapabilitySet) !void {
    try w.u16le(capstype_window);
    try w.u16le(window_capset_len);
    try w.u32le(c.wnd_support_level);
    try w.byte(c.num_icon_caches);
    try w.u16le(c.num_icon_cache_entries);
}

pub fn decodeWindowListCapabilitySet(cap: []const u8) Error!WindowListCapabilitySet {
    var r = try capabilityBody(cap, capstype_window, window_capset_len);
    const level = try r.u32le();
    if (level > window_level_supported_ex) return error.InvalidField;
    const caches = try r.byte();
    return .{ .wnd_support_level = level, .num_icon_caches = caches, .num_icon_cache_entries = try r.u16le() };
}

const rail_capset_len: u16 = 8;
const window_capset_len: u16 = 11;

fn capabilityBody(cap: []const u8, kind: u16, min_len: u16) Error!bytes.Reader {
    var r = bytes.Reader.init(cap);
    if (try r.u16le() != kind) return error.InvalidField;
    const len = try r.u16le();
    if (len < min_len) return error.InvalidField;
    if (len > cap.len) return error.EndOfBuffer;
    return bytes.Reader.init(cap[4..len]);
}

/// What the server advertised in its Demand Active PDU.
pub const ServerCaps = struct {
    rail: RailCapabilitySet,
    window: WindowListCapabilitySet,
};

/// Outcome of 3.3.5.1.5.
pub const Negotiated = struct {
    rail_support_level: u32,
    wnd_support_level: u32,
    /// The client's icon cache limits, which the server MUST adopt.
    num_icon_caches: u8,
    num_icon_cache_entries: u16,
};

/// Confirm Active processing (3.3.5.1.5). Client icon cache limits above the server's disable
/// icon caching (both counts 0), as Windows does (3.3.5.1.5 <36>).
pub fn negotiate(server: ServerCaps, client_rail: ?RailCapabilitySet, client_window: ?WindowListCapabilitySet) Error!Negotiated {
    const cr = client_rail orelse return error.RailNotSupported;
    const cw = client_window orelse return error.RailNotSupported;
    const level = server.rail.rail_support_level & cr.rail_support_level;
    if (level & rail_level_supported == 0) return error.RailNotSupported;
    if (cw.wnd_support_level == window_level_not_supported) return error.RailNotSupported;
    const too_many = cw.num_icon_caches > server.window.num_icon_caches or
        cw.num_icon_cache_entries > server.window.num_icon_cache_entries;
    return .{
        .rail_support_level = level,
        .wnd_support_level = cw.wnd_support_level,
        .num_icon_caches = if (too_many) 0 else cw.num_icon_caches,
        .num_icon_cache_entries = if (too_many) 0 else cw.num_icon_cache_entries,
    };
}

// --- 2.2.1.3 Windowing Alternate Secondary Drawing Orders ----------------------

/// TS_ALTSEC_WINDOW header byte (MS-RDPEGDI 2.2.2.2.1.3.1.1: class 0b10, orderType 0x0B << 2).
pub const altsec_window_header: u8 = 0x2E;
pub const ts_altsec_window: u8 = 0x0B;

pub const window_order_type_window: u32 = 0x01000000;
pub const window_order_type_notify: u32 = 0x02000000;
pub const window_order_type_desktop: u32 = 0x04000000;
pub const window_order_state_new: u32 = 0x10000000;
pub const window_order_state_deleted: u32 = 0x20000000;
pub const window_order_icon: u32 = 0x40000000;
pub const window_order_cachedicon: u32 = 0x80000000;

pub const window_order_field_appbar_edge: u32 = 0x00000001;
pub const window_order_field_owner: u32 = 0x00000002;
pub const window_order_field_title: u32 = 0x00000004;
pub const window_order_field_style: u32 = 0x00000008;
pub const window_order_field_show: u32 = 0x00000010;
pub const window_order_field_appbar_state: u32 = 0x00000040;
pub const window_order_field_resize_margin_x: u32 = 0x00000080;
pub const window_order_field_wndrects: u32 = 0x00000100;
pub const window_order_field_visibility: u32 = 0x00000200;
pub const window_order_field_wndsize: u32 = 0x00000400;
pub const window_order_field_wndoffset: u32 = 0x00000800;
pub const window_order_field_visoffset: u32 = 0x00001000;
pub const window_order_field_icon_big: u32 = 0x00002000;
pub const window_order_field_clientareaoffset: u32 = 0x00004000;
pub const window_order_field_clientdelta: u32 = 0x00008000;
pub const window_order_field_clientareasize: u32 = 0x00010000;
pub const window_order_field_rpcontent: u32 = 0x00020000;
pub const window_order_field_rootparent: u32 = 0x00040000;
pub const window_order_field_enforce_server_zorder: u32 = 0x00080000;
pub const window_order_field_icon_overlay: u32 = 0x00100000;
pub const window_order_field_icon_overlay_null: u32 = 0x00200000;
pub const window_order_field_overlay_description: u32 = 0x00400000;
pub const window_order_field_taskbar_button: u32 = 0x00800000;
pub const window_order_field_resize_margin_y: u32 = 0x08000000;

pub const window_order_field_notify_tip: u32 = 0x00000001;
pub const window_order_field_notify_info_tip: u32 = 0x00000002;
pub const window_order_field_notify_state: u32 = 0x00000004;
pub const window_order_field_notify_version: u32 = 0x00000008;

pub const window_order_field_desktop_none: u32 = 0x00000001;
pub const window_order_field_desktop_hooked: u32 = 0x00000002;
pub const window_order_field_desktop_arc_completed: u32 = 0x00000004;
pub const window_order_field_desktop_arc_began: u32 = 0x00000008;
pub const window_order_field_desktop_zorder: u32 = 0x00000010;
pub const window_order_field_desktop_activewnd: u32 = 0x00000020;

/// ShowState values (2.2.1.3.1.2.1).
pub const show_hide: u8 = 0x00;
pub const show_minimized: u8 = 0x02;
pub const show_maximized: u8 = 0x03;
pub const show_show: u8 = 0x05;

/// Maximum CbString of TitleInfo (2.2.1.3.1.2.1).
pub const max_title_len: usize = 520;
/// Maximum InfoTipText / Title of TS_NOTIFY_ICON_INFOTIP (2.2.1.3.2.2.3).
pub const max_infotip_text_len: usize = 510;
pub const max_infotip_title_len: usize = 126;

pub const niif_none: u32 = 0x00000000;
pub const niif_info: u32 = 0x00000001;
pub const niif_warning: u32 = 0x00000002;
pub const niif_error: u32 = 0x00000003;
pub const niif_nosound: u32 = 0x00000010;
pub const niif_large_icon: u32 = 0x00000020;

pub const Point32 = struct { x: i32, y: i32 };
pub const Size32 = struct { width: u32, height: u32 };

/// TS_ICON_INFO (2.2.1.2.3); `color_table` is on the wire only for Bpp 1, 4 and 8.
pub const IconInfo = struct {
    cache_entry: u16,
    cache_id: u8,
    bpp: u8,
    width: u16,
    height: u16,
    color_table: []const u8 = &.{},
    bits_mask: []const u8,
    bits_color: []const u8,
};

/// TS_CACHED_ICON_INFO (2.2.1.2.4).
pub const CachedIconInfo = struct { cache_entry: u16, cache_id: u8 };

/// New or Existing Window fields (2.2.1.3.1.2.1); a field is sent and flagged iff non-null.
pub const WindowState = struct {
    owner_window_id: ?u32 = null,
    style: ?struct { style: u32, extended_style: u32 } = null,
    show_state: ?u8 = null,
    title: ?[]const u8 = null,
    client_offset: ?Point32 = null,
    client_area_size: ?Size32 = null,
    resize_margin_x: ?struct { left: u32, right: u32 } = null,
    resize_margin_y: ?struct { top: u32, bottom: u32 } = null,
    rp_content: ?u8 = null,
    root_parent_handle: ?u32 = null,
    window_offset: ?Point32 = null,
    client_delta: ?Point32 = null,
    window_size: ?Size32 = null,
    window_rects: ?[]const Rect16 = null,
    visible_offset: ?Point32 = null,
    visibility_rects: ?[]const Rect16 = null,
    overlay_description: ?[]const u8 = null,
    /// WINDOW_ORDER_FIELD_ICON_OVERLAY_NULL (no data on the wire).
    icon_overlay_null: bool = false,
    taskbar_button: ?u8 = null,
    enforce_server_zorder: ?u8 = null,
    appbar_state: ?u8 = null,
    appbar_edge: ?u8 = null,
};

/// TS_NOTIFY_ICON_INFOTIP (2.2.1.3.2.2.3).
pub const InfoTip = struct { timeout: u32, flags: u32, text: []const u8, title: []const u8 };

/// Fields of a New or Existing Notification Icon order (2.2.1.3.2.2.1).
pub const NotifyIconState = struct {
    version: ?u32 = null,
    tooltip: ?[]const u8 = null,
    info_tip: ?InfoTip = null,
    state: ?u32 = null,
    icon: ?IconInfo = null,
    cached_icon: ?CachedIconInfo = null,
};

pub const WindowOrder = union(enum) {
    /// New or Existing Window (2.2.1.3.1.2.1).
    window: struct { window_id: u32, new: bool = false, state: WindowState },
    /// Window Icon (2.2.1.3.1.2.2).
    window_icon: struct { window_id: u32, new: bool = false, big: bool = false, overlay: bool = false, icon: IconInfo },
    /// Cached Icon (2.2.1.3.1.2.3).
    window_cached_icon: struct { window_id: u32, new: bool = false, big: bool = false, overlay: bool = false, cached: CachedIconInfo },
    /// Deleted Window (2.2.1.3.1.2.4).
    window_deleted: struct { window_id: u32 },
    /// New or Existing Notification Icon (2.2.1.3.2.2.1).
    notify_icon: struct { window_id: u32, notify_icon_id: u32, new: bool = false, state: NotifyIconState },
    /// Deleted Notification Icon (2.2.1.3.2.2.2).
    notify_icon_deleted: struct { window_id: u32, notify_icon_id: u32 },
    /// Actively Monitored Desktop (2.2.1.3.3.2.1).
    desktop: struct {
        hooked: bool = false,
        arc_began: bool = false,
        arc_completed: bool = false,
        active_window_id: ?u32 = null,
        /// Top-level window IDs in Z-order (NumWindowIds is one byte).
        z_order: ?[]const u32 = null,
    },
    /// Non-Monitored Desktop (2.2.1.3.3.2.2).
    desktop_none,
};

/// FieldsPresentFlags come from the fields; `wnd_support_level` is the client's WndSupportLevel.
pub fn encodeWindowOrder(w: *bytes.Writer, order: WindowOrder, wnd_support_level: u32) !void {
    const start = w.len();
    errdefer w.list.shrinkRetainingCapacity(start);
    try w.byte(altsec_window_header);
    try w.u16le(0); // OrderSize, patched below
    switch (order) {
        .window => |win| {
            const s = win.state;
            const flags = window_order_type_window | newFlag(win.new) | try windowFields(s, wnd_support_level);
            try w.u32le(flags);
            try w.u32le(win.window_id);
            try writeWindowState(w, s);
        },
        .window_icon => |wi| {
            try w.u32le(window_order_type_window | window_order_icon | newFlag(wi.new) | iconFlags(wi.big, wi.overlay));
            try w.u32le(wi.window_id);
            try encodeIconInfo(w, wi.icon);
        },
        .window_cached_icon => |wc| {
            try w.u32le(window_order_type_window | window_order_cachedicon | newFlag(wc.new) | iconFlags(wc.big, wc.overlay));
            try w.u32le(wc.window_id);
            try writeCachedIcon(w, wc.cached);
        },
        .window_deleted => |wd| {
            try w.u32le(window_order_type_window | window_order_state_deleted);
            try w.u32le(wd.window_id);
        },
        .notify_icon => |n| {
            const s = n.state;
            // 2.2.1.3.2.2.1: never both Icon and CachedIcon; a new icon has one.
            if (s.icon != null and s.cached_icon != null) return error.InvalidField;
            if (n.new and s.icon == null and s.cached_icon == null) return error.InvalidField;
            var flags = window_order_type_notify | newFlag(n.new);
            if (s.version) |v| {
                if (!validNotifyVersion(v)) return error.InvalidField;
                flags |= window_order_field_notify_version;
            }
            if (s.tooltip != null) flags |= window_order_field_notify_tip;
            if (s.info_tip != null) flags |= window_order_field_notify_info_tip;
            if (s.state != null) flags |= window_order_field_notify_state;
            if (s.icon != null) flags |= window_order_icon;
            if (s.cached_icon != null) flags |= window_order_cachedicon;
            try w.u32le(flags);
            try w.u32le(n.window_id);
            try w.u32le(n.notify_icon_id);
            if (s.version) |v| try w.u32le(v);
            if (s.tooltip) |t| try encodeUnicodeString(w, t, max_unicode_string_len);
            if (s.info_tip) |t| {
                try w.u32le(t.timeout);
                try w.u32le(t.flags);
                try encodeUnicodeString(w, t.text, max_infotip_text_len);
                try encodeUnicodeString(w, t.title, max_infotip_title_len);
            }
            if (s.state) |st| try w.u32le(st);
            if (s.icon) |icon| try encodeIconInfo(w, icon);
            if (s.cached_icon) |c| try writeCachedIcon(w, c);
        },
        .notify_icon_deleted => |n| {
            try w.u32le(window_order_type_notify | window_order_state_deleted);
            try w.u32le(n.window_id);
            try w.u32le(n.notify_icon_id);
        },
        .desktop => |d| {
            try checkDesktopFlags(d.hooked, d.arc_began, d.arc_completed, d.active_window_id != null, d.z_order != null);
            var flags = window_order_type_desktop;
            if (d.hooked) flags |= window_order_field_desktop_hooked;
            if (d.arc_began) flags |= window_order_field_desktop_arc_began;
            if (d.arc_completed) flags |= window_order_field_desktop_arc_completed;
            if (d.active_window_id != null) flags |= window_order_field_desktop_activewnd;
            if (d.z_order) |z| {
                if (z.len > std.math.maxInt(u8)) return error.TooLong;
                flags |= window_order_field_desktop_zorder;
            }
            try w.u32le(flags);
            if (d.active_window_id) |id| try w.u32le(id);
            if (d.z_order) |z| {
                try w.byte(@intCast(z.len));
                for (z) |id| try w.u32le(id);
            }
        },
        .desktop_none => try w.u32le(window_order_type_desktop | window_order_field_desktop_none),
    }
    const size = w.len() - start;
    if (size > std.math.maxInt(u16)) return error.TooLong;
    w.patchU16le(start + 1, @intCast(size));
}

const max_unicode_string_len: usize = 0xFFFE;

/// Window order fields that need TS_WINDOW_LEVEL_SUPPORTED_EX (2.2.1.1.2).
const window_fields_ex: u32 = window_order_field_clientareasize | window_order_field_rpcontent | window_order_field_rootparent;

fn newFlag(new: bool) u32 {
    return if (new) window_order_state_new else 0;
}

fn iconFlags(big: bool, overlay: bool) u32 {
    return (if (big) window_order_field_icon_big else 0) | (if (overlay) window_order_field_icon_overlay else 0);
}

fn validNotifyVersion(v: u32) bool {
    return v == 0 or v == 3 or v == 4;
}

/// 2.2.1.3.3.2.1: ARC_BEGAN needs HOOKED; ARC_COMPLETED combines with no other field.
fn checkDesktopFlags(hooked: bool, arc_began: bool, arc_completed: bool, active: bool, zorder: bool) Error!void {
    if (arc_began and !hooked) return error.InvalidField;
    if (arc_completed and (hooked or arc_began or active or zorder)) return error.InvalidField;
}

fn windowFields(s: WindowState, wnd_support_level: u32) Error!u32 {
    var f: u32 = 0;
    if (s.owner_window_id != null) f |= window_order_field_owner;
    if (s.style != null) f |= window_order_field_style;
    if (s.show_state) |v| {
        if (!validShowState(v)) return error.InvalidField;
        f |= window_order_field_show;
    }
    if (s.title) |t| {
        try checkUtf16(t.len, max_title_len);
        f |= window_order_field_title;
    }
    if (s.client_offset != null) f |= window_order_field_clientareaoffset;
    if (s.client_area_size != null) f |= window_order_field_clientareasize;
    if (s.resize_margin_x != null) f |= window_order_field_resize_margin_x;
    if (s.resize_margin_y != null) f |= window_order_field_resize_margin_y;
    if (s.rp_content) |v| {
        if (v > 1) return error.InvalidField;
        f |= window_order_field_rpcontent;
    }
    if (s.root_parent_handle != null) f |= window_order_field_rootparent;
    if (s.window_offset != null) f |= window_order_field_wndoffset;
    if (s.client_delta != null) f |= window_order_field_clientdelta;
    if (s.window_size != null) f |= window_order_field_wndsize;
    if (s.window_rects) |r| {
        if (r.len > std.math.maxInt(u16)) return error.TooLong;
        f |= window_order_field_wndrects;
    }
    if (s.visible_offset != null) f |= window_order_field_visoffset;
    if (s.visibility_rects) |r| {
        if (r.len > std.math.maxInt(u16)) return error.TooLong;
        f |= window_order_field_visibility;
    }
    if (s.overlay_description) |d| {
        try checkUtf16(d.len, max_unicode_string_len);
        f |= window_order_field_overlay_description;
    }
    if (s.icon_overlay_null) f |= window_order_field_icon_overlay_null;
    if (s.taskbar_button != null) f |= window_order_field_taskbar_button;
    if (s.enforce_server_zorder != null) f |= window_order_field_enforce_server_zorder;
    if (s.appbar_state != null) f |= window_order_field_appbar_state;
    if (s.appbar_edge) |v| {
        if (v > 3) return error.InvalidField; // left, top, right, bottom
        f |= window_order_field_appbar_edge;
    }
    if (f & window_fields_ex != 0 and wnd_support_level != window_level_supported_ex) return error.FieldNotNegotiated;
    return f;
}

fn validShowState(v: u8) bool {
    return v == show_hide or v == show_minimized or v == show_maximized or v == show_show;
}

/// The optional fields of 2.2.1.3.1.2.1, in wire order.
fn writeWindowState(w: *bytes.Writer, s: WindowState) !void {
    if (s.owner_window_id) |v| try w.u32le(v);
    if (s.style) |v| {
        try w.u32le(v.style);
        try w.u32le(v.extended_style);
    }
    if (s.show_state) |v| try w.byte(v);
    if (s.title) |v| try encodeUnicodeString(w, v, max_title_len);
    if (s.client_offset) |v| try writePoint(w, v);
    if (s.client_area_size) |v| try writeSize(w, v);
    if (s.resize_margin_x) |v| {
        try w.u32le(v.left);
        try w.u32le(v.right);
    }
    if (s.resize_margin_y) |v| {
        try w.u32le(v.top);
        try w.u32le(v.bottom);
    }
    if (s.rp_content) |v| try w.byte(v);
    if (s.root_parent_handle) |v| try w.u32le(v);
    if (s.window_offset) |v| try writePoint(w, v);
    if (s.client_delta) |v| try writePoint(w, v);
    if (s.window_size) |v| try writeSize(w, v);
    if (s.window_rects) |v| try writeRects(w, v);
    if (s.visible_offset) |v| try writePoint(w, v);
    if (s.visibility_rects) |v| try writeRects(w, v);
    if (s.overlay_description) |v| try encodeUnicodeString(w, v, max_unicode_string_len);
    if (s.taskbar_button) |v| try w.byte(v);
    if (s.enforce_server_zorder) |v| try w.byte(v);
    if (s.appbar_state) |v| try w.byte(v);
    if (s.appbar_edge) |v| try w.byte(v);
}

fn writePoint(w: *bytes.Writer, p: Point32) !void {
    try w.u32le(@bitCast(p.x));
    try w.u32le(@bitCast(p.y));
}

fn readPoint(r: *bytes.Reader) Error!Point32 {
    const x: i32 = @bitCast(try r.u32le());
    return .{ .x = x, .y = @bitCast(try r.u32le()) };
}

fn writeSize(w: *bytes.Writer, s: Size32) !void {
    try w.u32le(s.width);
    try w.u32le(s.height);
}

fn readSize(r: *bytes.Reader) Error!Size32 {
    const width = try r.u32le();
    return .{ .width = width, .height = try r.u32le() };
}

fn writeRects(w: *bytes.Writer, rects: []const Rect16) !void {
    try w.u16le(@intCast(rects.len));
    for (rects) |r| try writeRect16(w, r);
}

fn readRects(gpa: Allocator, r: *bytes.Reader) Error![]Rect16 {
    const n = try r.u16le();
    try r.need(@as(usize, n) * 8);
    const rects = try gpa.alloc(Rect16, n);
    for (rects) |*x| x.* = readRect16(r) catch unreachable; // length checked above
    return rects;
}

fn writeCachedIcon(w: *bytes.Writer, c: CachedIconInfo) !void {
    try w.u16le(c.cache_entry);
    try w.byte(c.cache_id);
}

fn readCachedIcon(r: *bytes.Reader) Error!CachedIconInfo {
    const entry = try r.u16le();
    return .{ .cache_entry = entry, .cache_id = try r.byte() };
}

fn freeWindowState(gpa: Allocator, s: WindowState) void {
    if (s.window_rects) |v| gpa.free(v);
    if (s.visibility_rects) |v| gpa.free(v);
}

/// Rect and window-id arrays are owned (free with `deinit`); strings and icons point into the input.
pub const DecodedWindowOrder = struct {
    order: WindowOrder,
    fields_present: u32,
    /// OrderSize: bytes consumed from the input.
    size: usize,

    pub fn deinit(d: *DecodedWindowOrder, gpa: Allocator) void {
        switch (d.order) {
            .window => |win| freeWindowState(gpa, win.state),
            .desktop => |dk| if (dk.z_order) |z| gpa.free(z),
            else => {},
        }
        d.* = undefined;
    }
};

/// Decodes the order at the start of `buf` (which can hold more orders).
pub fn decodeWindowOrder(gpa: Allocator, buf: []const u8, wnd_support_level: u32) Error!DecodedWindowOrder {
    var hr = bytes.Reader.init(buf);
    if (try hr.byte() != altsec_window_header) return error.BadOrderHeader;
    const size = try hr.u16le();
    // TS_DESKTOP_ORDER_HEADER (7 bytes) is the smallest header.
    if (size < 7 or size > buf.len) return error.BadOrderHeader;
    var r = bytes.Reader.init(buf[3..size]);
    const flags = try r.u32le();
    const types = flags & (window_order_type_window | window_order_type_notify | window_order_type_desktop);
    if (@popCount(types) != 1) return error.BadOrderType;
    const order = decodeWindowBody(gpa, &r, flags, wnd_support_level) catch |e| return switch (e) {
        error.EndOfBuffer => error.BadOrderHeader,
        else => e,
    };
    return .{ .order = order, .fields_present = flags, .size = size };
}

fn decodeWindowBody(gpa: Allocator, r: *bytes.Reader, flags: u32, wnd_support_level: u32) Error!WindowOrder {
    const new = flags & window_order_state_new != 0;
    if (flags & window_order_type_window != 0) {
        const id = try r.u32le();
        if (flags & window_order_state_deleted != 0) return .{ .window_deleted = .{ .window_id = id } };
        const icon = flags & window_order_icon != 0;
        const cached = flags & window_order_cachedicon != 0;
        if (icon and cached) return error.InvalidField;
        const big = flags & window_order_field_icon_big != 0;
        const overlay = flags & window_order_field_icon_overlay != 0;
        if (icon) return .{ .window_icon = .{ .window_id = id, .new = new, .big = big, .overlay = overlay, .icon = try decodeIconInfo(r) } };
        if (cached) return .{ .window_cached_icon = .{ .window_id = id, .new = new, .big = big, .overlay = overlay, .cached = try readCachedIcon(r) } };
        return .{ .window = .{ .window_id = id, .new = new, .state = try decodeWindowState(gpa, r, flags, wnd_support_level) } };
    }
    if (flags & window_order_type_notify != 0) {
        const id = try r.u32le();
        const icon_id = try r.u32le();
        // 2.2.1.3.2.2.2 (and 4.1.1.4, whose stray TIP/ICON flags carry no data).
        if (flags & window_order_state_deleted != 0) return .{ .notify_icon_deleted = .{ .window_id = id, .notify_icon_id = icon_id } };
        return .{ .notify_icon = .{ .window_id = id, .notify_icon_id = icon_id, .new = new, .state = try decodeNotifyIconState(r, flags) } };
    }
    // Desktop (2.2.1.3.3.2): NONE wins (2.2.1.3.3.2.2).
    if (flags & window_order_field_desktop_none != 0) return .desktop_none;
    const hooked = flags & window_order_field_desktop_hooked != 0;
    const began = flags & window_order_field_desktop_arc_began != 0;
    const completed = flags & window_order_field_desktop_arc_completed != 0;
    const has_active = flags & window_order_field_desktop_activewnd != 0;
    const has_zorder = flags & window_order_field_desktop_zorder != 0;
    try checkDesktopFlags(hooked, began, completed, has_active, has_zorder);
    const active: ?u32 = if (has_active) try r.u32le() else null;
    var z_order: ?[]u32 = null;
    if (has_zorder) {
        const n = try r.byte();
        try r.need(@as(usize, n) * 4);
        const ids = try gpa.alloc(u32, n);
        for (ids) |*id| id.* = r.u32le() catch unreachable; // length checked above
        z_order = ids;
    }
    return .{ .desktop = .{ .hooked = hooked, .arc_began = began, .arc_completed = completed, .active_window_id = active, .z_order = z_order } };
}

fn decodeWindowState(gpa: Allocator, r: *bytes.Reader, flags: u32, wnd_support_level: u32) Error!WindowState {
    // Clients that negotiated TS_WINDOW_LEVEL_SUPPORTED refuse these fields.
    if (flags & window_fields_ex != 0 and wnd_support_level != window_level_supported_ex) return error.FieldNotNegotiated;
    var s: WindowState = .{};
    errdefer freeWindowState(gpa, s);
    if (flags & window_order_field_owner != 0) s.owner_window_id = try r.u32le();
    if (flags & window_order_field_style != 0) {
        const style = try r.u32le();
        const ex = try r.u32le();
        s.style = .{ .style = style, .extended_style = ex };
    }
    if (flags & window_order_field_show != 0) {
        const v = try r.byte();
        if (!validShowState(v)) return error.InvalidField;
        s.show_state = v;
    }
    if (flags & window_order_field_title != 0) s.title = try decodeUnicodeString(r, max_title_len);
    if (flags & window_order_field_clientareaoffset != 0) s.client_offset = try readPoint(r);
    if (flags & window_order_field_clientareasize != 0) s.client_area_size = try readSize(r);
    if (flags & window_order_field_resize_margin_x != 0) {
        const left = try r.u32le();
        const right = try r.u32le();
        s.resize_margin_x = .{ .left = left, .right = right };
    }
    if (flags & window_order_field_resize_margin_y != 0) {
        const top = try r.u32le();
        const bottom = try r.u32le();
        s.resize_margin_y = .{ .top = top, .bottom = bottom };
    }
    if (flags & window_order_field_rpcontent != 0) {
        const v = try r.byte();
        if (v > 1) return error.InvalidField;
        s.rp_content = v;
    }
    if (flags & window_order_field_rootparent != 0) s.root_parent_handle = try r.u32le();
    if (flags & window_order_field_wndoffset != 0) s.window_offset = try readPoint(r);
    if (flags & window_order_field_clientdelta != 0) s.client_delta = try readPoint(r);
    if (flags & window_order_field_wndsize != 0) s.window_size = try readSize(r);
    if (flags & window_order_field_wndrects != 0) s.window_rects = try readRects(gpa, r);
    if (flags & window_order_field_visoffset != 0) s.visible_offset = try readPoint(r);
    if (flags & window_order_field_visibility != 0) s.visibility_rects = try readRects(gpa, r);
    if (flags & window_order_field_overlay_description != 0) s.overlay_description = try decodeUnicodeString(r, max_unicode_string_len);
    s.icon_overlay_null = flags & window_order_field_icon_overlay_null != 0;
    if (flags & window_order_field_taskbar_button != 0) s.taskbar_button = try r.byte();
    if (flags & window_order_field_enforce_server_zorder != 0) s.enforce_server_zorder = try r.byte();
    if (flags & window_order_field_appbar_state != 0) s.appbar_state = try r.byte();
    if (flags & window_order_field_appbar_edge != 0) {
        const v = try r.byte();
        if (v > 3) return error.InvalidField;
        s.appbar_edge = v;
    }
    return s;
}

fn decodeNotifyIconState(r: *bytes.Reader, flags: u32) Error!NotifyIconState {
    const icon = flags & window_order_icon != 0;
    const cached = flags & window_order_cachedicon != 0;
    if (icon and cached) return error.InvalidField;
    if (flags & window_order_state_new != 0 and !icon and !cached) return error.InvalidField;
    var s: NotifyIconState = .{};
    if (flags & window_order_field_notify_version != 0) {
        const v = try r.u32le();
        if (!validNotifyVersion(v)) return error.InvalidField;
        s.version = v;
    }
    if (flags & window_order_field_notify_tip != 0) s.tooltip = try decodeUnicodeString(r, max_unicode_string_len);
    if (flags & window_order_field_notify_info_tip != 0) {
        const timeout = try r.u32le();
        const info_flags = try r.u32le();
        const text = try decodeUnicodeString(r, max_infotip_text_len);
        const title = try decodeUnicodeString(r, max_infotip_title_len);
        s.info_tip = .{ .timeout = timeout, .flags = info_flags, .text = text, .title = title };
    }
    if (flags & window_order_field_notify_state != 0) s.state = try r.u32le();
    if (icon) s.icon = try decodeIconInfo(r);
    if (cached) s.cached_icon = try readCachedIcon(r);
    return s;
}

fn validBpp(bpp: u8) bool {
    return switch (bpp) {
        1, 4, 8, 16, 24, 32 => true,
        else => false,
    };
}

pub fn encodeIconInfo(w: *bytes.Writer, icon: IconInfo) !void {
    if (!validBpp(icon.bpp)) return error.BadBpp;
    const has_table = icon.bpp <= 8;
    if (!has_table and icon.color_table.len != 0) return error.InvalidField;
    const max = std.math.maxInt(u16);
    if (icon.color_table.len > max or icon.bits_mask.len > max or icon.bits_color.len > max) return error.TooLong;
    try w.u16le(icon.cache_entry);
    try w.byte(icon.cache_id);
    try w.byte(icon.bpp);
    try w.u16le(icon.width);
    try w.u16le(icon.height);
    if (has_table) try w.u16le(@intCast(icon.color_table.len));
    try w.u16le(@intCast(icon.bits_mask.len));
    try w.u16le(@intCast(icon.bits_color.len));
    try w.bytes(icon.bits_mask);
    if (has_table) try w.bytes(icon.color_table);
    try w.bytes(icon.bits_color);
}

pub fn decodeIconInfo(r: *bytes.Reader) Error!IconInfo {
    const entry = try r.u16le();
    const id = try r.byte();
    const bpp = try r.byte();
    if (!validBpp(bpp)) return error.BadBpp;
    const width = try r.u16le();
    const height = try r.u16le();
    const has_table = bpp <= 8;
    const cb_table: u16 = if (has_table) try r.u16le() else 0;
    const cb_mask = try r.u16le();
    const cb_color = try r.u16le();
    const mask = try r.bytes(cb_mask);
    const table = try r.bytes(cb_table);
    return .{
        .cache_entry = entry,
        .cache_id = id,
        .bpp = bpp,
        .width = width,
        .height = height,
        .color_table = table,
        .bits_mask = mask,
        .bits_color = try r.bytes(cb_color),
    };
}

/// UNICODE_STRING (2.2.1.2.1): CbString then the bytes.
pub fn encodeUnicodeString(w: *bytes.Writer, s: []const u8, max_len: usize) !void {
    try checkUtf16(s.len, @min(max_len, max_unicode_string_len));
    try w.u16le(@intCast(s.len));
    try w.bytes(s);
}

pub fn decodeUnicodeString(r: *bytes.Reader, max_len: usize) Error![]const u8 {
    const len = try r.u16le();
    try checkUtf16(len, max_len);
    return r.bytes(len);
}

// --- Server side (3.1.1.1, 3.1.5, 3.3.5) -------------------------------------

/// Server states of 3.1.1.1; the transient ones collapse into WaitForData.
pub const State = enum { uninitialized, initializing, sync_desktop, wait_for_data };

pub const ServerConfig = struct {
    build_number: u32,
    caps: ServerCaps,
    /// railHandshakeFlags the server supports besides HIDEF.
    handshake_ex_flags: u32 = 0,
    /// The server supports Enhanced RemoteApp (3.3.5.1.3).
    hidef_supported: bool = false,
    /// The server supports Local Move/Size (3.3.5.2.1.1).
    local_move_size_supported: bool = true,
    /// LanguageBarStatus the server reports (3.3.5.2.5.5).
    langbar_status: u32 = tf_sft_hidden,
    /// Marker window ID (3.3.1.3) for Z-Order Sync Information (3.3.5.2.8.1).
    marker_window_id: ?u32 = null,
};

pub const Event = union(enum) {
    /// Handshake and Client Information received: desktop sync (3.3.5.1.8) is due.
    ready,
    exec: Exec,
    sysparam: SysParam,
    activate: Activate,
    sysmenu: SysMenu,
    syscommand: SysCommand,
    notify_event: NotifyEvent,
    window_move: WindowMove,
    snap_arrange: WindowMove,
    get_appid_req: GetAppIdReq,
    langbar_info: LangBarInfo,
    language_ime_info: LanguageImeInfo,
    compartment_info: CompartmentInfo,
    cloak: Cloak,
    text_scale_info: TextScaleInfo,
    caret_blink_info: CaretBlinkInfo,
    /// Already processed (Handshake, Client Information).
    none,
};

pub const Server = struct {
    config: ServerConfig,
    negotiated: Negotiated,
    /// Client Info PDU flags (INFO_RAIL, INFO_HIDEF_RAIL_SUPPORTED).
    client_info_flags: u32,
    state: State = .initializing,
    client_status: ?u32 = null,
    client_build: ?u32 = null,
    desktop_synced: bool = false,

    /// Call after a successful `negotiate` (3.1.1.1 Uninitialized -> Initializing).
    pub fn init(config: ServerConfig, negotiated: Negotiated, client_info_flags: u32) Error!Server {
        if (client_info_flags & rdp.info_rail == 0) return error.RailNotSupported;
        if (negotiated.rail_support_level & rail_level_supported == 0) return error.RailNotSupported;
        if (negotiated.wnd_support_level == window_level_not_supported) return error.RailNotSupported;
        return .{ .config = config, .negotiated = negotiated, .client_info_flags = client_info_flags };
    }

    /// Whether Enhanced RemoteApp is enabled (3.3.5.1.3).
    pub fn hidef(s: *const Server) Error!bool {
        return s.client_info_flags & rdp.info_hidef_rail_supported != 0 and s.config.hidef_supported;
    }

    /// railHandshakeFlags of the HandshakeEx, or null for a plain Handshake (3.3.5.2.1.2).
    pub fn handshakeExFlags(s: *const Server) ?u32 {
        const others = s.config.handshake_ex_flags & ~handshake_ex_flags_hidef;
        // "If it has not been enabled, the server MUST NOT set this flag."
        if (s.hidef() catch unreachable) return others | handshake_ex_flags_hidef;
        if (s.level(rail_level_handshake_ex_supported)) return others;
        return null;
    }

    fn advertised(s: *const Server, flag: u32) bool {
        return (s.handshakeExFlags() orelse 0) & flag != 0;
    }

    fn level(s: *const Server, bit: u32) bool {
        return s.negotiated.rail_support_level & bit != 0;
    }

    fn status(s: *const Server, flag: u32) bool {
        return (s.client_status orelse 0) & flag != 0;
    }

    /// Writes the channel's first PDU: HandshakeEx or Handshake (3.3.5.2.1.2).
    pub fn start(s: *Server, w: *bytes.Writer) !void {
        if (s.handshakeExFlags()) |flags| {
            try encode(w, .{ .handshake_ex = .{ .build_number = s.config.build_number, .flags = flags } });
        } else {
            try encode(w, .{ .handshake = .{ .build_number = s.config.build_number } });
        }
    }

    /// Writes any response to `out`. error.NotNegotiated: the PDU needs a capability or
    /// HandshakeEx flag that was not negotiated; it can be ignored.
    pub fn receive(s: *Server, pdu: []const u8, out: *bytes.Writer) !Event {
        if (s.state == .uninitialized) return error.RailNotSupported;
        const order = try decode(pdu, .client_to_server);
        // 3.1.5.2: nothing is processed before the client's Handshake.
        if (s.client_build == null and order != .handshake) return error.HandshakeNotReceived;
        switch (order) {
            .handshake => |h| {
                s.client_build = h.build_number;
                return .none;
            },
            .client_status => |c| {
                s.client_status = c.flags;
                // 3.3.5.2.8.1: announce the marker window to a client with Z-order sync.
                if (c.flags & clientstatus_zorder_sync != 0) {
                    if (s.config.marker_window_id) |id| try encode(out, .{ .zorder_sync = .{ .window_id_marker = id } });
                }
                if (s.state == .initializing) {
                    s.state = if (s.desktop_synced) .wait_for_data else .sync_desktop;
                    return .ready;
                }
                return .none;
            },
            .exec => |e| return .{ .exec = e },
            .sysparam => |p| {
                const needs = sysParamHandshakeFlag(p.param);
                if (needs != 0 and !s.advertised(needs)) return error.NotNegotiated;
                return .{ .sysparam = p };
            },
            .activate => |a| return .{ .activate = a },
            .sysmenu => |m| return .{ .sysmenu = m },
            .syscommand => |c| return .{ .syscommand = c },
            .notify_event => |n| return .{ .notify_event = n },
            .window_move => |m| return .{ .window_move = m },
            .get_appid_req => |g| return .{ .get_appid_req = g },
            .snap_arrange => |m| {
                if (!s.advertised(handshake_ex_flags_snap_arrange_supported)) return error.NotNegotiated;
                return .{ .snap_arrange = m };
            },
            .langbar_info => |l| {
                if (!s.level(rail_level_docked_langbar_supported)) return error.NotNegotiated;
                // 3.3.5.2.5.5: the server sends its language bar status first.
                try encode(out, .{ .langbar_info = .{ .status = s.config.langbar_status } });
                return .{ .langbar_info = l };
            },
            .language_ime_info => |l| {
                if (!s.level(rail_level_language_ime_sync_supported)) return error.NotNegotiated;
                return .{ .language_ime_info = l };
            },
            .compartment_info => |c| {
                if (!s.level(rail_level_language_ime_sync_supported)) return error.NotNegotiated;
                return .{ .compartment_info = c };
            },
            .cloak => |c| {
                if (!s.level(rail_level_window_cloaking_supported)) return error.NotNegotiated;
                return .{ .cloak = c };
            },
            .text_scale_info => |t| {
                if (!s.advertised(handshake_ex_flags_text_scale_supported)) return error.NotNegotiated;
                return .{ .text_scale_info = t };
            },
            .caret_blink_info => |c| {
                if (!s.advertised(handshake_ex_flags_caret_blink_supported)) return error.NotNegotiated;
                return .{ .caret_blink_info = c };
            },
            // decode(.client_to_server) returns no other order.
            else => return error.UnexpectedOrderType,
        }
    }

    /// Server Execute Result (3.3.5.2.2.2); Flags and ExeOrFile come from the request.
    pub fn execResult(s: *Server, w: *bytes.Writer, request: Exec, result: u16, raw_result: u32) !void {
        _ = s;
        try encode(w, .{ .exec_result = .{ .flags = request.flags, .exec_result = result, .raw_result = raw_result, .exe_or_file = request.exe_or_file } });
    }

    fn localMoveSize(s: *const Server) bool {
        return s.config.local_move_size_supported and s.status(clientstatus_allow_local_move_size);
    }

    /// Min Max Info then Move/Size Start (3.3.5.2.6.1, 3.3.5.2.6.2).
    pub fn beginLocalMoveSize(s: *Server, w: *bytes.Writer, info: MinMaxInfo, move_size_type: u16, pos_x: i16, pos_y: i16) !void {
        if (!s.localMoveSize()) return error.NotNegotiated;
        const start_len = w.len();
        errdefer w.list.shrinkRetainingCapacity(start_len);
        try encode(w, .{ .min_max_info = info });
        try encode(w, .{ .local_move_size = .{ .window_id = info.window_id, .is_move_size_start = true, .move_size_type = move_size_type, .pos_x = pos_x, .pos_y = pos_y } });
    }

    /// Move/Size End (3.3.5.2.6.4).
    pub fn endLocalMoveSize(s: *Server, w: *bytes.Writer, window_id: u32, move_size_type: u16, top_left_x: i16, top_left_y: i16) !void {
        if (!s.localMoveSize()) return error.NotNegotiated;
        try encode(w, .{ .local_move_size = .{ .window_id = window_id, .is_move_size_start = false, .move_size_type = move_size_type, .pos_x = top_left_x, .pos_y = top_left_y } });
    }

    /// False under TS_RAIL_CLIENTSTATUS_SUPPRESS_ICON_ORDERS (3.3.5.1.6).
    pub fn sendWindowIcons(s: *const Server) Error!bool {
        return !s.status(clientstatus_suppress_icon_orders);
    }

    /// Power Display Request (3.3.5.2.10.1); needs POWER_DISPLAY_REQUEST_SUPPORTED.
    pub fn powerDisplayRequest(s: *Server, w: *bytes.Writer, active: bool) !void {
        if (!s.status(clientstatus_power_display_request_supported)) return error.NotNegotiated;
        try encode(w, .{ .power_display_request = .{ .active = active } });
    }

    /// Server cloak state change (2.2.2.12.1); needs BIDIRECTIONAL_CLOAK_SUPPORTED.
    pub fn cloak(s: *Server, w: *bytes.Writer, window_id: u32, cloaked: bool) !void {
        if (!s.status(clientstatus_bidirectional_cloak_supported)) return error.NotNegotiated;
        try encode(w, .{ .cloak = .{ .window_id = window_id, .cloaked = cloaked } });
    }

    /// Desktop synchronization (3.3.5.1.8): ARC_BEGAN|HOOKED, `windows`, then ARC_COMPLETED.
    /// Allowed while Initializing: FreeRDP clients send Client Information only after it.
    pub fn desktopSync(s: *Server, w: *bytes.Writer, windows: []const WindowOrder) !void {
        if (s.state == .uninitialized) return error.RailNotSupported;
        s.desktop_synced = true;
        errdefer s.desktop_synced = false;
        const icons = try s.sendWindowIcons();
        const level_ex = s.negotiated.wnd_support_level;
        const start_len = w.len();
        errdefer w.list.shrinkRetainingCapacity(start_len);
        try encodeWindowOrder(w, .{ .desktop = .{ .hooked = true, .arc_began = true } }, level_ex);
        for (windows) |o| {
            if (!icons and (o == .window_icon or o == .window_cached_icon)) continue;
            try encodeWindowOrder(w, o, level_ex);
        }
        try encodeWindowOrder(w, .{ .desktop = .{ .arc_completed = true } }, level_ex);
        if (s.state != .initializing) s.state = .wait_for_data;
    }
};

test {
    std.testing.refAllDecls(@This());
}
