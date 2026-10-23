//! MS-RDPEFS device redirection (channel "rdpdr"): PDU codecs, the server state machine
//! (3.1, 3.3) and client drive to Linux path mapping. Decoders never allocate.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

/// MS-RDPEFS 2.1.
pub const channel_name = "rdpdr";

pub const Error = error{
    /// Shorter than its fixed part, or a length field points past the end (3.1.5.2).
    Truncated,
    /// RDPDR_HEADER.Component is neither RDPDR_CTYP_CORE nor RDPDR_CTYP_PRN (3.1.5.2).
    UnknownComponent,
    /// PacketId not defined for the component (3.1.5.2).
    UnknownPacketId,
    /// A PDU from the wrong direction, or a decoder called on the wrong PDU.
    UnexpectedPdu,
    InvalidField,
    /// CapabilityType not defined by the protocol (3.1.5.2: SHOULD terminate).
    UnknownCapability,
    /// PDU out of the initialization order (3.1.3) or repeated (3.1.5.2).
    OutOfSequence,
    /// DeviceId re-announced as a different device (3.3.5.2.1). Identical re-announces
    /// are fine: FreeRDP re-sends its list after User Logged On and on hotplug.
    DuplicateDeviceId,
    /// Device I/O Response for an unknown or removed DeviceId (3.1.5.2).
    UnknownDevice,
    /// Device I/O Response whose CompletionId is not outstanding (3.1.5.2).
    UnknownCompletionId,
    /// FileId not returned by a create, or already closed (3.1.5).
    InvalidFileId,
    /// Device not accepted, removed, or not a file system for a drive IRP.
    InvalidDevice,
    /// A second read or write in flight without ENABLE_ASYNCIO (3.3.5.2.8, 3.3.5.2.9).
    WouldBlock,
    /// Request before the initialization sequence finished.
    NotReady,
    /// Too many outstanding requests (Config.max_outstanding).
    TooManyRequests,
    /// MS-FSCC 2.1.5 forbidden characters, "..", an unpaired surrogate, or empty.
    InvalidName,
    NoSpaceLeft,
    OutOfMemory,
};

// --- 2.2.1.1 RDPDR_HEADER ---

pub const header_len = 4;

pub const Component = enum(u16) {
    core = 0x4472,
    /// RDPDR_CTYP_PRN (MS-RDPEPC).
    prn = 0x5052,
    _,
};

/// RDPDR_HEADER.PacketId: the PAKID_ names, lower case.
pub const PacketId = enum(u16) {
    core_server_announce = 0x496E,
    /// Client Announce Reply (2.2.2.3) and Server Client ID Confirm (2.2.2.6).
    core_clientid_confirm = 0x4343,
    core_client_name = 0x434E,
    core_devicelist_announce = 0x4441,
    core_device_reply = 0x6472,
    core_device_iorequest = 0x4952,
    core_device_iocompletion = 0x4943,
    core_server_capability = 0x5350,
    core_client_capability = 0x4350,
    core_devicelist_remove = 0x444D,
    /// MS-RDPEPC 2.2.2.3 (component RDPDR_CTYP_PRN).
    prn_cache_data = 0x5043,
    core_user_loggedon = 0x554C,
    /// MS-RDPEPC 2.2.2.2 (component RDPDR_CTYP_PRN).
    prn_using_xps = 0x5543,
    _,
};

pub const Header = struct {
    component: Component,
    packet_id: PacketId,
};

// --- 2.2.2.2, 2.2.2.3, 2.2.2.6 versions ---

pub const version_major: u16 = 0x0001;
pub const version_minor_rdp50: u16 = 0x0002;
pub const version_minor_rdp51: u16 = 0x0005;
pub const version_minor_rdp52: u16 = 0x000A;
pub const version_minor_rdp6x: u16 = 0x000C;
pub const version_minor_rdp10: u16 = 0x000D;

pub const VersionInfo = struct {
    major: u16 = version_major,
    minor: u16,
    client_id: u32,
};

// --- 2.2.1.2 CAPABILITY_HEADER and 2.2.2.7.x capability sets ---

pub const capability_header_len = 8;

pub const CapabilityType = enum(u16) {
    general = 0x0001,
    printer = 0x0002,
    port = 0x0003,
    drive = 0x0004,
    smartcard = 0x0005,
    _,
};

pub const general_capability_version_01: u32 = 0x00000001;
pub const general_capability_version_02: u32 = 0x00000002;
pub const print_capability_version_01: u32 = 0x00000001;
pub const port_capability_version_01: u32 = 0x00000001;
pub const drive_capability_version_01: u32 = 0x00000001;
pub const drive_capability_version_02: u32 = 0x00000002;
pub const smartcard_capability_version_01: u32 = 0x00000001;

/// GENERAL_CAPS_SET CapabilityLength, version 1 and version 2.
pub const general_caps_len_v1: u16 = 40;
pub const general_caps_len_v2: u16 = 44;

/// GENERAL_CAPS_SET.ioCode1 bits (2.2.2.7.1).
pub const irp_mj_create_bit: u32 = 0x00000001;
pub const irp_mj_cleanup_bit: u32 = 0x00000002;
pub const irp_mj_close_bit: u32 = 0x00000004;
pub const irp_mj_read_bit: u32 = 0x00000008;
pub const irp_mj_write_bit: u32 = 0x00000010;
pub const irp_mj_flush_buffers_bit: u32 = 0x00000020;
pub const irp_mj_shutdown_bit: u32 = 0x00000040;
pub const irp_mj_device_control_bit: u32 = 0x00000080;
pub const irp_mj_query_volume_information_bit: u32 = 0x00000100;
pub const irp_mj_set_volume_information_bit: u32 = 0x00000200;
pub const irp_mj_query_information_bit: u32 = 0x00000400;
pub const irp_mj_set_information_bit: u32 = 0x00000800;
pub const irp_mj_directory_control_bit: u32 = 0x00001000;
pub const irp_mj_lock_control_bit: u32 = 0x00002000;
pub const irp_mj_query_security_bit: u32 = 0x00004000;
pub const irp_mj_set_security_bit: u32 = 0x00008000;
/// The fourteen bits the specification marks "Unused, always set".
pub const io_code1_always_set: u32 = 0x00003FFF;

/// GENERAL_CAPS_SET.extendedPDU bits.
pub const rdpdr_device_remove_pdus: u32 = 0x00000001;
pub const rdpdr_client_display_name_pdu: u32 = 0x00000002;
pub const rdpdr_user_loggedon_pdu: u32 = 0x00000004;

/// GENERAL_CAPS_SET.extraFlags1 bit.
pub const enable_asyncio: u32 = 0x00000001;

/// GENERAL_CAPS_SET.osType Windows sends (4.8); receivers ignore it.
pub const os_type_winnt: u32 = 0x00000002;

pub const GeneralCapabilitySet = struct {
    version: u32 = general_capability_version_02,
    os_type: u32 = 0,
    os_version: u32 = 0,
    protocol_major_version: u16 = version_major,
    protocol_minor_version: u16 = version_minor_rdp10,
    io_code1: u32 = 0x0000FFFF,
    io_code2: u32 = 0,
    extended_pdu: u32 = rdpdr_device_remove_pdus | rdpdr_client_display_name_pdu | rdpdr_user_loggedon_pdu,
    extra_flags1: u32 = 0,
    extra_flags2: u32 = 0,
    /// Present only in version 2; 0 when decoding version 1.
    special_type_device_cap: u32 = 0,
};

/// Capability sets of 2.2.2.7 / 2.2.2.8; null means absent. Device sets carry
/// only their version. Encoded in the order of 4.8.
pub const Capabilities = struct {
    general: ?GeneralCapabilitySet = null,
    printer: ?u32 = null,
    port: ?u32 = null,
    drive: ?u32 = null,
    smartcard: ?u32 = null,

    pub fn count(c: Capabilities) u16 {
        var n: u16 = 0;
        if (c.general != null) n += 1;
        if (c.printer != null) n += 1;
        if (c.port != null) n += 1;
        if (c.drive != null) n += 1;
        if (c.smartcard != null) n += 1;
        return n;
    }
};

// --- 2.2.1.3 DEVICE_ANNOUNCE ---

pub const device_announce_fixed_len = 20;

pub const DeviceType = enum(u32) {
    serial = 0x00000001,
    parallel = 0x00000002,
    print = 0x00000004,
    filesystem = 0x00000008,
    smartcard = 0x00000020,
    _,
};

pub const DeviceAnnounce = struct {
    device_type: DeviceType,
    device_id: u32,
    preferred_dos_name: [8]u8 = @splat(0),
    device_data: []const u8 = "",

    /// Up to the first NUL; FreeRDP fills all 8 bytes for long names.
    pub fn dosName(d: *const DeviceAnnounce) []const u8 {
        const n = std.mem.indexOfScalar(u8, &d.preferred_dos_name, 0) orelse d.preferred_dos_name.len;
        return d.preferred_dos_name[0..n];
    }

    /// PreferredDosName from a string (truncated to 8 bytes, NUL padded).
    pub fn dos(name: []const u8) [8]u8 {
        var out: [8]u8 = @splat(0);
        const n = @min(name.len, out.len);
        @memcpy(out[0..n], name[0..n]);
        return out;
    }
};

/// DR_DEVICELIST_ANNOUNCE after decoding: `data` holds DeviceCount validated entries.
pub const DeviceList = struct {
    count: u32,
    data: []const u8,

    pub fn iterator(l: DeviceList) DeviceIterator {
        return .{ .data = l.data, .left = l.count };
    }
};

pub const DeviceIterator = struct {
    data: []const u8,
    pos: usize = 0,
    left: u32,

    pub fn next(it: *DeviceIterator) ?DeviceAnnounce {
        if (it.left == 0) return null;
        if (it.data.len - it.pos < device_announce_fixed_len) return null;
        const p = it.data[it.pos..];
        const len = std.mem.readInt(u32, p[16..20], .little);
        if (p.len - device_announce_fixed_len < len) return null;
        it.left -= 1;
        it.pos += device_announce_fixed_len + len;
        return .{
            .device_type = @fromBackingInt(@intCast(std.mem.readInt(u32, p[0..4], .little))),
            .device_id = std.mem.readInt(u32, p[4..8], .little),
            .preferred_dos_name = p[8..16].*,
            .device_data = p[device_announce_fixed_len..][0..len],
        };
    }
};

/// DR_DEVICELIST_REMOVE (2.2.3.2) after decoding: DeviceCount ids.
pub const DeviceListRemove = struct {
    count: u32,
    ids: []const u8,

    pub fn get(r: DeviceListRemove, i: u32) u32 {
        return std.mem.readInt(u32, r.ids[4 * @as(usize, i) ..][0..4], .little);
    }
};

/// DR_CORE_DEVICE_ANNOUNCE_RSP (2.2.2.1).
pub const DeviceAnnounceResponse = struct {
    device_id: u32,
    result_code: u32,
};

// --- 2.2.2.4 DR_CORE_CLIENT_NAME_REQ ---

pub const ClientName = struct {
    /// Least significant bit of UnicodeFlag (the other 31 bits MUST be ignored).
    unicode: bool,
    code_page: u32 = 0,
    /// ComputerName as sent (ASCII or UTF-16LE), with or without its terminator.
    name: []const u8,
};

// --- 2.2.1.4 DR_DEVICE_IOREQUEST ---

pub const io_request_header_len = 24;
pub const io_completion_header_len = 16;

pub const MajorFunction = enum(u32) {
    create = 0x00000000,
    close = 0x00000002,
    read = 0x00000003,
    write = 0x00000004,
    query_information = 0x00000005,
    set_information = 0x00000006,
    query_volume_information = 0x0000000A,
    set_volume_information = 0x0000000B,
    directory_control = 0x0000000C,
    device_control = 0x0000000E,
    lock_control = 0x00000011,
    _,
};

pub const MinorFunction = enum(u32) {
    none = 0x00000000,
    query_directory = 0x00000001,
    notify_change_directory = 0x00000002,
    _,
};

/// [MS-FSCC] 2.4 file information classes used by MS-RDPEFS.
pub const FileInformationClass = enum(u32) {
    directory = 1,
    full_directory = 2,
    both_directory = 3,
    basic = 4,
    standard = 5,
    rename = 10,
    names = 12,
    disposition = 13,
    allocation = 19,
    end_of_file = 20,
    attribute_tag = 35,
    _,
};

/// [MS-FSCC] 2.5 file system information classes used by MS-RDPEFS.
pub const FsInformationClass = enum(u32) {
    volume = 1,
    label = 2,
    size = 3,
    device = 4,
    attribute = 5,
    full_size = 7,
    _,
};

/// DR_DRIVE_LOCK_REQ.Operation (2.2.3.3.12).
pub const LockOperation = enum(u32) {
    shared_lock = 0x00000002,
    exclusive_lock = 0x00000003,
    unlock = 0x00000004,
    unlock_multiple = 0x00000005,
    _,
};

/// The F bit of DR_DRIVE_LOCK_REQ: bit 0 of the 32-bit field after Operation.
pub const lock_flag_wait: u32 = 0x00000001;

/// [MS-SMB2] 2.2.13 CreateDisposition.
pub const file_supersede: u32 = 0x00000000;
pub const file_open: u32 = 0x00000001;
pub const file_create: u32 = 0x00000002;
pub const file_open_if: u32 = 0x00000003;
pub const file_overwrite: u32 = 0x00000004;
pub const file_overwrite_if: u32 = 0x00000005;

/// [MS-SMB2] 2.2.13 CreateOptions.
pub const file_directory_file: u32 = 0x00000001;
pub const file_write_through: u32 = 0x00000002;
pub const file_sequential_only: u32 = 0x00000004;
pub const file_no_intermediate_buffering: u32 = 0x00000008;
pub const file_synchronous_io_alert: u32 = 0x00000010;
pub const file_synchronous_io_nonalert: u32 = 0x00000020;
pub const file_non_directory_file: u32 = 0x00000040;
pub const file_complete_if_oplocked: u32 = 0x00000100;
pub const file_no_ea_knowledge: u32 = 0x00000200;
pub const file_random_access: u32 = 0x00000800;
pub const file_delete_on_close: u32 = 0x00001000;
pub const file_open_by_file_id: u32 = 0x00002000;
pub const file_open_for_backup_intent: u32 = 0x00004000;
pub const file_no_compression: u32 = 0x00008000;
pub const file_open_reparse_point: u32 = 0x00200000;
pub const file_open_no_recall: u32 = 0x00400000;

/// [MS-SMB2] 2.2.13.1.1 file access mask (DesiredAccess).
pub const file_read_data: u32 = 0x00000001;
pub const file_write_data: u32 = 0x00000002;
pub const file_append_data: u32 = 0x00000004;
pub const file_read_ea: u32 = 0x00000008;
pub const file_write_ea: u32 = 0x00000010;
pub const file_execute: u32 = 0x00000020;
pub const file_delete_child: u32 = 0x00000040;
pub const file_read_attributes: u32 = 0x00000080;
pub const file_write_attributes: u32 = 0x00000100;
pub const access_delete: u32 = 0x00010000;
pub const read_control: u32 = 0x00020000;
pub const write_dac: u32 = 0x00040000;
pub const write_owner: u32 = 0x00080000;
pub const synchronize: u32 = 0x00100000;
pub const access_system_security: u32 = 0x01000000;
pub const maximum_allowed: u32 = 0x02000000;
pub const generic_all: u32 = 0x10000000;
pub const generic_execute: u32 = 0x20000000;
pub const generic_write: u32 = 0x40000000;
pub const generic_read: u32 = 0x80000000;

/// [MS-SMB2] 2.2.13 ShareAccess.
pub const file_share_read: u32 = 0x00000001;
pub const file_share_write: u32 = 0x00000002;
pub const file_share_delete: u32 = 0x00000004;

/// [MS-FSCC] 2.6 file attributes.
pub const file_attribute_readonly: u32 = 0x00000001;
pub const file_attribute_hidden: u32 = 0x00000002;
pub const file_attribute_system: u32 = 0x00000004;
pub const file_attribute_directory: u32 = 0x00000010;
pub const file_attribute_archive: u32 = 0x00000020;
pub const file_attribute_normal: u32 = 0x00000080;
pub const file_attribute_temporary: u32 = 0x00000100;
pub const file_attribute_sparse_file: u32 = 0x00000200;
pub const file_attribute_reparse_point: u32 = 0x00000400;
pub const file_attribute_compressed: u32 = 0x00000800;
pub const file_attribute_offline: u32 = 0x00001000;
pub const file_attribute_not_content_indexed: u32 = 0x00002000;
pub const file_attribute_encrypted: u32 = 0x00004000;

/// DR_CREATE_RSP.Information (2.2.1.5.1).
pub const file_superseded: u8 = 0x00;
pub const file_opened: u8 = 0x01;
pub const file_overwritten: u8 = 0x03;

/// [MS-SMB2] 2.2.35 CHANGE_NOTIFY CompletionFilter.
pub const file_notify_change_file_name: u32 = 0x00000001;
pub const file_notify_change_dir_name: u32 = 0x00000002;
pub const file_notify_change_attributes: u32 = 0x00000004;
pub const file_notify_change_size: u32 = 0x00000008;
pub const file_notify_change_last_write: u32 = 0x00000010;
pub const file_notify_change_last_access: u32 = 0x00000020;
pub const file_notify_change_creation: u32 = 0x00000040;
pub const file_notify_change_ea: u32 = 0x00000080;
pub const file_notify_change_security: u32 = 0x00000100;
pub const file_notify_change_stream_name: u32 = 0x00000200;
pub const file_notify_change_stream_size: u32 = 0x00000400;
pub const file_notify_change_stream_write: u32 = 0x00000800;

/// [MS-FSCC] 2.7.1 FILE_NOTIFY_INFORMATION.Action.
pub const file_action_added: u32 = 0x00000001;
pub const file_action_removed: u32 = 0x00000002;
pub const file_action_modified: u32 = 0x00000003;
pub const file_action_renamed_old_name: u32 = 0x00000004;
pub const file_action_renamed_new_name: u32 = 0x00000005;

/// [MS-FSCC] 2.5.10 FileFsDeviceInformation.DeviceType values.
pub const file_device_cd_rom: u32 = 0x00000002;
pub const file_device_disk: u32 = 0x00000007;

/// [MS-FSCC] 2.5.1 FileFsAttributeInformation.FileSystemAttributes bits.
pub const file_case_sensitive_search: u32 = 0x00000001;
pub const file_case_preserved_names: u32 = 0x00000002;
pub const file_unicode_on_disk: u32 = 0x00000004;
pub const file_persistent_acls: u32 = 0x00000008;
pub const file_file_compression: u32 = 0x00000010;
pub const file_volume_quotas: u32 = 0x00000020;
pub const file_supports_sparse_files: u32 = 0x00000040;
pub const file_supports_reparse_points: u32 = 0x00000080;
pub const file_read_only_volume: u32 = 0x00080000;

/// [MS-ERREF] 2.3.1 NTSTATUS values that appear in MS-RDPEFS exchanges.
pub const status = struct {
    pub const success: u32 = 0x00000000;
    pub const pending: u32 = 0x00000103;
    pub const buffer_overflow: u32 = 0x80000005;
    pub const no_more_files: u32 = 0x80000006;
    pub const device_busy: u32 = 0x80000011;
    pub const unsuccessful: u32 = 0xC0000001;
    pub const not_implemented: u32 = 0xC0000002;
    pub const invalid_handle: u32 = 0xC0000008;
    pub const invalid_parameter: u32 = 0xC000000D;
    pub const no_such_device: u32 = 0xC000000E;
    pub const no_such_file: u32 = 0xC000000F;
    pub const invalid_device_request: u32 = 0xC0000010;
    pub const end_of_file: u32 = 0xC0000011;
    pub const no_memory: u32 = 0xC0000017;
    pub const access_denied: u32 = 0xC0000022;
    pub const buffer_too_small: u32 = 0xC0000023;
    pub const object_name_invalid: u32 = 0xC0000033;
    pub const object_name_not_found: u32 = 0xC0000034;
    pub const object_name_collision: u32 = 0xC0000035;
    pub const object_path_not_found: u32 = 0xC000003A;
    pub const sharing_violation: u32 = 0xC0000043;
    pub const file_lock_conflict: u32 = 0xC0000054;
    pub const lock_not_granted: u32 = 0xC0000055;
    pub const delete_pending: u32 = 0xC0000056;
    pub const disk_full: u32 = 0xC000007F;
    pub const media_write_protected: u32 = 0xC00000A2;
    pub const device_not_ready: u32 = 0xC00000A3;
    pub const file_is_a_directory: u32 = 0xC00000BA;
    pub const not_supported: u32 = 0xC00000BB;
    pub const directory_not_empty: u32 = 0xC0000101;
    pub const not_a_directory: u32 = 0xC0000103;
    pub const cancelled: u32 = 0xC0000120;

    pub fn isError(s: u32) bool {
        return s >> 30 == 3;
    }
};

/// [MS-FSCC] 2.3 FSCTL codes of the Server Drive Control Request (2.2.3.3.5).
pub const fsctl = struct {
    pub const create_or_get_object_id: u32 = 0x000900C0;
    pub const delete_object_id: u32 = 0x000900A0;
    pub const delete_reparse_point: u32 = 0x000900AC;
    pub const filesystem_get_statistics: u32 = 0x00090060;
    pub const find_files_by_sid: u32 = 0x0009008F;
    pub const get_compression: u32 = 0x0009003C;
    pub const get_ntfs_volume_data: u32 = 0x00090064;
    pub const get_object_id: u32 = 0x0009009C;
    pub const get_reparse_point: u32 = 0x000900A8;
    pub const get_retrieval_pointers: u32 = 0x00090073;
    pub const is_pathname_valid: u32 = 0x0009002C;
    pub const lmr_get_link_tracking_information: u32 = 0x001400E8;
    pub const lmr_set_link_tracking_information: u32 = 0x001400EC;
    pub const pipe_transceive: u32 = 0x0011C017;
    pub const pipe_wait: u32 = 0x00110018;
    pub const query_allocated_ranges: u32 = 0x000940CF;
    pub const read_file_usn_data: u32 = 0x000900EB;
    pub const recall_file: u32 = 0x00090117;
    pub const set_compression: u32 = 0x0009C040;
    pub const set_encryption: u32 = 0x000900D7;
    pub const set_object_id: u32 = 0x00090098;
    pub const set_object_id_extended: u32 = 0x000900BC;
    pub const set_reparse_point: u32 = 0x000900A4;
    pub const set_short_name_behavior: u32 = 0x000901B4;
    pub const set_sparse: u32 = 0x000900C4;
    pub const set_zero_data: u32 = 0x000980C8;
    pub const set_zero_on_deallocation: u32 = 0x00090194;
    pub const sis_copyfile: u32 = 0x00090100;
    pub const write_usn_close_record: u32 = 0x000900EF;

    pub const supported = [_]u32{
        create_or_get_object_id,           delete_object_id,       delete_reparse_point,
        filesystem_get_statistics,         find_files_by_sid,      get_compression,
        get_ntfs_volume_data,              get_object_id,          get_reparse_point,
        get_retrieval_pointers,            is_pathname_valid,      lmr_get_link_tracking_information,
        lmr_set_link_tracking_information, pipe_transceive,        pipe_wait,
        query_allocated_ranges,            read_file_usn_data,     recall_file,
        set_compression,                   set_encryption,         set_object_id,
        set_object_id_extended,            set_reparse_point,      set_short_name_behavior,
        set_sparse,                        set_zero_data,          set_zero_on_deallocation,
        sis_copyfile,                      write_usn_close_record,
    };
};

pub fn isSupportedFsctl(code: u32) Error!bool {
    return std.mem.indexOfScalar(u32, &fsctl.supported, code) != null;
}

/// Information a successful create MUST return for a CreateDisposition (2.2.1.5.1).
pub fn expectedCreateInformation(create_disposition: u32) Error!u8 {
    return switch (create_disposition) {
        file_open_if => file_opened,
        file_overwrite_if => file_overwritten,
        else => file_superseded,
    };
}

// --- request bodies ----------------------------------------------------------

/// DR_CREATE_REQ (2.2.1.4.1). `path` is UTF-16LE with its terminator, or
/// empty for the device root (4.12).
pub const CreateRequest = struct {
    desired_access: u32,
    allocation_size: u64 = 0,
    file_attributes: u32 = 0,
    shared_access: u32 = 0,
    create_disposition: u32 = file_open,
    create_options: u32 = 0,
    path: []const u8 = "",
};

/// DR_READ_REQ (2.2.1.4.3).
pub const ReadRequest = struct {
    length: u32,
    offset: u64,
};

/// "Append" offset from client minor version 13 (2.2.1.4.4); FreeRDP drops such writes.
pub const write_append_offset: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// DR_WRITE_REQ (2.2.1.4.4). Length is `data.len`.
pub const WriteRequest = struct {
    offset: u64,
    data: []const u8,
};

/// DR_CONTROL_REQ (2.2.1.4.5). InputBufferLength is `input.len`.
pub const DeviceControlRequest = struct {
    output_buffer_length: u32,
    io_control_code: u32,
    input: []const u8 = "",
};

/// DR_DRIVE_QUERY/SET_VOLUME_INFORMATION_REQ (2.2.3.3.6, 2.2.3.3.7).
pub const VolumeInformationRequest = struct {
    fs_information_class: FsInformationClass,
    buffer: []const u8 = "",
};

/// DR_DRIVE_QUERY/SET_INFORMATION_REQ (2.2.3.3.8, 2.2.3.3.9).
pub const FileInformationRequest = struct {
    file_information_class: FileInformationClass,
    buffer: []const u8 = "",
};

/// DR_DRIVE_QUERY_DIRECTORY_REQ (2.2.3.3.10). `path` is UTF-16LE with its terminator.
pub const QueryDirectoryRequest = struct {
    file_information_class: FileInformationClass,
    initial_query: bool,
    path: []const u8 = "",
};

/// DR_DRIVE_NOTIFY_CHANGE_DIRECTORY_REQ (2.2.3.3.11).
pub const NotifyChangeDirectoryRequest = struct {
    watch_tree: bool,
    completion_filter: u32,
};

/// RDP_LOCK_INFO (2.2.1.6).
pub const LockInfo = struct {
    length: u64,
    offset: u64,

    pub const size = 16;

    pub fn encode(l: LockInfo) [16]u8 {
        var out: [16]u8 = undefined;
        std.mem.writeInt(u64, out[0..8], l.length, .little);
        std.mem.writeInt(u64, out[8..16], l.offset, .little);
        return out;
    }
};

/// DR_DRIVE_LOCK_REQ (2.2.3.3.12). `locks` holds 16-byte RDP_LOCK_INFO entries.
pub const LockRequest = struct {
    operation: LockOperation,
    wait: bool = false,
    locks: []const u8 = "",

    pub fn count(l: LockRequest) u32 {
        return @intCast(l.locks.len / LockInfo.size);
    }

    pub fn lockAt(l: LockRequest, i: u32) LockInfo {
        const p = l.locks[LockInfo.size * @as(usize, i) ..][0..LockInfo.size];
        return .{
            .length = std.mem.readInt(u64, p[0..8], .little),
            .offset = std.mem.readInt(u64, p[8..16], .little),
        };
    }
};

pub const IoRequestBody = union(enum) {
    create: CreateRequest,
    close,
    read: ReadRequest,
    write: WriteRequest,
    device_control: DeviceControlRequest,
    query_volume_information: VolumeInformationRequest,
    set_volume_information: VolumeInformationRequest,
    query_information: FileInformationRequest,
    set_information: FileInformationRequest,
    query_directory: QueryDirectoryRequest,
    notify_change_directory: NotifyChangeDirectoryRequest,
    lock_control: LockRequest,
};

/// DR_DEVICE_IOREQUEST header and body; Major/MinorFunction follow from the body.
pub const IoRequest = struct {
    device_id: u32,
    file_id: u32 = 0,
    completion_id: u32 = 0,
    body: IoRequestBody,

    pub fn majorFunction(r: IoRequest) MajorFunction {
        return switch (r.body) {
            .create => .create,
            .close => .close,
            .read => .read,
            .write => .write,
            .device_control => .device_control,
            .query_volume_information => .query_volume_information,
            .set_volume_information => .set_volume_information,
            .query_information => .query_information,
            .set_information => .set_information,
            .query_directory, .notify_change_directory => .directory_control,
            .lock_control => .lock_control,
        };
    }

    pub fn minorFunction(r: IoRequest) MinorFunction {
        return switch (r.body) {
            .query_directory => .query_directory,
            .notify_change_directory => .notify_change_directory,
            else => .none,
        };
    }
};

// --- 2.2.1.5 DR_DEVICE_IOCOMPLETION -----------------------------------------

/// Device I/O Response header; `body` is everything after the 16 bytes.
pub const IoCompletion = struct {
    device_id: u32,
    completion_id: u32,
    io_status: u32,
    body: []const u8 = "",
};

/// DR_CREATE_RSP fields after the header (2.2.1.5.1).
pub const CreateResponse = struct {
    file_id: u32,
    /// 0 (FILE_SUPERSEDED) when the client skipped the field.
    information: u8 = file_superseded,
};

/// Device I/O Response body by the Major/MinorFunction of its request.
pub const IoResponse = union(enum) {
    create: CreateResponse,
    close,
    read: []const u8,
    /// DR_WRITE_RSP.Length: bytes written.
    write: u32,
    device_control: []const u8,
    query_volume_information: []const u8,
    set_volume_information: u32,
    query_information: []const u8,
    set_information: u32,
    query_directory: []const u8,
    notify_change_directory: []const u8,
    lock_control,
};

// --- PDU dispatch ---

pub const ClientPdu = union(enum) {
    announce_reply: VersionInfo,
    client_name: ClientName,
    capabilities: Capabilities,
    device_list_announce: DeviceList,
    device_list_remove: DeviceListRemove,
    io_completion: IoCompletion,
    /// RDPDR_CTYP_PRN PDUs (MS-RDPEPC), undecoded; `body` follows the header.
    printer: struct { packet_id: PacketId, body: []const u8 },
};

pub const ServerPdu = union(enum) {
    server_announce: VersionInfo,
    client_id_confirm: VersionInfo,
    capabilities: Capabilities,
    user_logged_on,
    device_announce_response: DeviceAnnounceResponse,
    io_request: IoRequest,
};

// --- [MS-FSCC] information structures, without the Reserved fields MS-RDPEFS omits ---

/// FileBasicInformation without its trailing Reserved field (2.2.3.3.8): 36 bytes.
pub const FileBasicInformation = struct {
    creation_time: u64 = 0,
    last_access_time: u64 = 0,
    last_write_time: u64 = 0,
    change_time: u64 = 0,
    file_attributes: u32 = 0,

    pub const size = 36;

    pub fn decode(buf: []const u8) Error!FileBasicInformation {
        var r: Rd = .{ .buf = buf };
        try r.need(size);
        var i: FileBasicInformation = .{};
        i.creation_time = try r.int(u64);
        i.last_access_time = try r.int(u64);
        i.last_write_time = try r.int(u64);
        i.change_time = try r.int(u64);
        i.file_attributes = try r.int(u32);
        return i;
    }
    pub fn encode(i: FileBasicInformation, w: *bytes.Writer) Error!void {
        try w.u64le(i.creation_time);
        try w.u64le(i.last_access_time);
        try w.u64le(i.last_write_time);
        try w.u64le(i.change_time);
        try w.u32le(i.file_attributes);
    }
};

/// FileStandardInformation without its trailing Reserved field (2.2.3.3.8): 22 bytes.
pub const FileStandardInformation = struct {
    allocation_size: u64 = 0,
    end_of_file: u64 = 0,
    number_of_links: u32 = 0,
    delete_pending: bool = false,
    directory: bool = false,

    pub const size = 22;

    pub fn decode(buf: []const u8) Error!FileStandardInformation {
        var r: Rd = .{ .buf = buf };
        try r.need(size);
        var i: FileStandardInformation = .{};
        i.allocation_size = try r.int(u64);
        i.end_of_file = try r.int(u64);
        i.number_of_links = try r.int(u32);
        i.delete_pending = try r.int(u8) != 0;
        i.directory = try r.int(u8) != 0;
        return i;
    }
    pub fn encode(i: FileStandardInformation, w: *bytes.Writer) Error!void {
        try w.u64le(i.allocation_size);
        try w.u64le(i.end_of_file);
        try w.u32le(i.number_of_links);
        try w.byte(@intFromBool(i.delete_pending));
        try w.byte(@intFromBool(i.directory));
    }
};

pub const FileAttributeTagInformation = struct {
    file_attributes: u32 = 0,
    reparse_tag: u32 = 0,

    pub const size = 8;

    pub fn decode(buf: []const u8) Error!FileAttributeTagInformation {
        var r: Rd = .{ .buf = buf };
        try r.need(size);
        var i: FileAttributeTagInformation = .{};
        i.file_attributes = try r.int(u32);
        i.reparse_tag = try r.int(u32);
        return i;
    }
    pub fn encode(i: FileAttributeTagInformation, w: *bytes.Writer) Error!void {
        try w.u32le(i.file_attributes);
        try w.u32le(i.reparse_tag);
    }
};

pub const FileEndOfFileInformation = struct {
    end_of_file: u64,

    pub const size = 8;

    pub fn decode(buf: []const u8) Error!FileEndOfFileInformation {
        var r: Rd = .{ .buf = buf };
        return .{ .end_of_file = try r.int(u64) };
    }
    pub fn encode(i: FileEndOfFileInformation, w: *bytes.Writer) Error!void {
        try w.u64le(i.end_of_file);
    }
};

pub const FileAllocationInformation = struct {
    allocation_size: u64,

    pub const size = 8;

    pub fn decode(buf: []const u8) Error!FileAllocationInformation {
        var r: Rd = .{ .buf = buf };
        return .{ .allocation_size = try r.int(u64) };
    }
    pub fn encode(i: FileAllocationInformation, w: *bytes.Writer) Error!void {
        try w.u64le(i.allocation_size);
    }
};

/// In a Set Information request an empty SetBuffer means DeletePending 1 (2.2.3.3.9).
pub const FileDispositionInformation = struct {
    delete_pending: bool = true,

    pub fn decode(buf: []const u8) Error!FileDispositionInformation {
        if (buf.len == 0) return .{};
        return .{ .delete_pending = buf[0] != 0 };
    }
    /// Writes nothing: the RDP SetBuffer is empty.
    pub fn encode(i: FileDispositionInformation, w: *bytes.Writer) Error!void {
        _ = i;
        _ = w;
    }
};

/// RDP_FILE_RENAME_INFORMATION (2.2.3.3.9.1): 6 + FileNameLength bytes.
pub const FileRenameInformation = struct {
    replace_if_exists: bool,
    root_directory: u8 = 0,
    file_name: []const u8,

    pub const fixed_size = 6;

    pub fn decode(buf: []const u8) Error!FileRenameInformation {
        var r: Rd = .{ .buf = buf };
        try r.need(fixed_size);
        const replace = try r.int(u8) != 0;
        const root = try r.int(u8);
        const len = try r.int(u32);
        if (root != 0) return error.InvalidField;
        const name = try r.take(len);
        if (len % 2 != 0) return error.InvalidField;
        return .{ .replace_if_exists = replace, .root_directory = root, .file_name = name };
    }
    pub fn encode(i: FileRenameInformation, w: *bytes.Writer) Error!void {
        const len = try utf16Len32(i.file_name);
        try w.byte(@intFromBool(i.replace_if_exists));
        try w.byte(i.root_directory);
        try w.u32le(len);
        try w.bytes(i.file_name);
    }
};

/// One query directory response entry of any supported class (FileBothDirectoryInformation
/// without its Reserved byte, 2.2.3.3.10); absent fields are 0.
pub const DirectoryEntry = struct {
    next_entry_offset: u32 = 0,
    file_index: u32 = 0,
    creation_time: u64 = 0,
    last_access_time: u64 = 0,
    last_write_time: u64 = 0,
    change_time: u64 = 0,
    end_of_file: u64 = 0,
    allocation_size: u64 = 0,
    file_attributes: u32 = 0,
    ea_size: u32 = 0,
    /// UTF-16LE, ShortNameLength bytes (at most 24).
    short_name: []const u8 = "",
    /// UTF-16LE, FileNameLength bytes, no terminator.
    file_name: []const u8,
};

/// ShortName of FileBothDirectoryInformation: 12 UTF-16 code units.
const short_name_max = 24;

/// [MS-FSCC] 2.4.8, 2.4.14, 2.4.17, 2.4.28.
fn directoryEntryFixed(class: FileInformationClass) Error!usize {
    return switch (class) {
        .directory => 64,
        .full_directory => 68,
        .both_directory => 93,
        .names => 12,
        else => error.InvalidField,
    };
}

pub fn directoryEntrySize(class: FileInformationClass, name_len: usize) Error!usize {
    return (try directoryEntryFixed(class)) + name_len;
}

/// Decodes the first entry of a query directory response buffer.
pub fn decodeDirectoryEntry(class: FileInformationClass, buf: []const u8) Error!DirectoryEntry {
    const fixed = try directoryEntryFixed(class);
    var r: Rd = .{ .buf = buf };
    try r.need(fixed);
    var e: DirectoryEntry = .{ .file_name = "" };
    e.next_entry_offset = try r.int(u32);
    e.file_index = try r.int(u32);
    var name_len: u32 = 0;
    if (class == .names) {
        name_len = try r.int(u32);
    } else {
        e.creation_time = try r.int(u64);
        e.last_access_time = try r.int(u64);
        e.last_write_time = try r.int(u64);
        e.change_time = try r.int(u64);
        e.end_of_file = try r.int(u64);
        e.allocation_size = try r.int(u64);
        e.file_attributes = try r.int(u32);
        name_len = try r.int(u32);
        if (class != .directory) e.ea_size = try r.int(u32);
        if (class == .both_directory) {
            const short_len = try r.int(u8);
            const short = try r.take(short_name_max);
            if (short_len > short_name_max or short_len % 2 != 0) return error.InvalidField;
            e.short_name = short[0..short_len];
        }
    }
    e.file_name = try r.take(name_len);
    if (name_len % 2 != 0) return error.InvalidField;
    return e;
}

pub fn encodeDirectoryEntry(w: *bytes.Writer, class: FileInformationClass, e: DirectoryEntry) Error!void {
    _ = try directoryEntryFixed(class);
    const name_len = try utf16Len32(e.file_name);
    if (class == .both_directory and (e.short_name.len > short_name_max or e.short_name.len % 2 != 0))
        return error.InvalidField;
    try w.u32le(e.next_entry_offset);
    try w.u32le(e.file_index);
    if (class == .names) {
        try w.u32le(name_len);
    } else {
        try w.u64le(e.creation_time);
        try w.u64le(e.last_access_time);
        try w.u64le(e.last_write_time);
        try w.u64le(e.change_time);
        try w.u64le(e.end_of_file);
        try w.u64le(e.allocation_size);
        try w.u32le(e.file_attributes);
        try w.u32le(name_len);
        if (class != .directory) try w.u32le(e.ea_size);
        if (class == .both_directory) {
            try w.byte(@intCast(e.short_name.len));
            try w.bytes(e.short_name);
            try w.zeros(short_name_max - e.short_name.len);
        }
    }
    try w.bytes(e.file_name);
}

/// FileFsVolumeInformation without the Reserved byte (2.2.3.3.6).
pub const FileFsVolumeInformation = struct {
    volume_creation_time: u64 = 0,
    volume_serial_number: u32 = 0,
    supports_objects: bool = false,
    /// UTF-16LE, VolumeLabelLength bytes.
    volume_label: []const u8 = "",

    pub const fixed_size = 17;

    pub fn decode(buf: []const u8) Error!FileFsVolumeInformation {
        var r: Rd = .{ .buf = buf };
        try r.need(fixed_size);
        var i: FileFsVolumeInformation = .{};
        i.volume_creation_time = try r.int(u64);
        i.volume_serial_number = try r.int(u32);
        const len = try r.int(u32);
        i.supports_objects = try r.int(u8) != 0;
        i.volume_label = try r.take(len);
        if (len % 2 != 0) return error.InvalidField;
        return i;
    }
    pub fn encode(i: FileFsVolumeInformation, w: *bytes.Writer) Error!void {
        const len = try utf16Len32(i.volume_label);
        try w.u64le(i.volume_creation_time);
        try w.u32le(i.volume_serial_number);
        try w.u32le(len);
        try w.byte(@intFromBool(i.supports_objects));
        try w.bytes(i.volume_label);
    }
};

pub const FileFsLabelInformation = struct {
    volume_label: []const u8,

    pub const fixed_size = 4;

    pub fn decode(buf: []const u8) Error!FileFsLabelInformation {
        var r: Rd = .{ .buf = buf };
        const len = try r.int(u32);
        const label = try r.take(len);
        if (len % 2 != 0) return error.InvalidField;
        return .{ .volume_label = label };
    }
    pub fn encode(i: FileFsLabelInformation, w: *bytes.Writer) Error!void {
        try w.u32le(try utf16Len32(i.volume_label));
        try w.bytes(i.volume_label);
    }
};

pub const FileFsSizeInformation = struct {
    total_allocation_units: u64 = 0,
    available_allocation_units: u64 = 0,
    sectors_per_allocation_unit: u32 = 0,
    bytes_per_sector: u32 = 0,

    pub const size = 24;

    pub fn decode(buf: []const u8) Error!FileFsSizeInformation {
        var r: Rd = .{ .buf = buf };
        try r.need(size);
        var i: FileFsSizeInformation = .{};
        i.total_allocation_units = try r.int(u64);
        i.available_allocation_units = try r.int(u64);
        i.sectors_per_allocation_unit = try r.int(u32);
        i.bytes_per_sector = try r.int(u32);
        return i;
    }
    pub fn encode(i: FileFsSizeInformation, w: *bytes.Writer) Error!void {
        try w.u64le(i.total_allocation_units);
        try w.u64le(i.available_allocation_units);
        try w.u32le(i.sectors_per_allocation_unit);
        try w.u32le(i.bytes_per_sector);
    }
};

pub const FileFsFullSizeInformation = struct {
    total_allocation_units: u64 = 0,
    caller_available_allocation_units: u64 = 0,
    actual_available_allocation_units: u64 = 0,
    sectors_per_allocation_unit: u32 = 0,
    bytes_per_sector: u32 = 0,

    pub const size = 32;

    pub fn decode(buf: []const u8) Error!FileFsFullSizeInformation {
        var r: Rd = .{ .buf = buf };
        try r.need(size);
        var i: FileFsFullSizeInformation = .{};
        i.total_allocation_units = try r.int(u64);
        i.caller_available_allocation_units = try r.int(u64);
        i.actual_available_allocation_units = try r.int(u64);
        i.sectors_per_allocation_unit = try r.int(u32);
        i.bytes_per_sector = try r.int(u32);
        return i;
    }
    pub fn encode(i: FileFsFullSizeInformation, w: *bytes.Writer) Error!void {
        try w.u64le(i.total_allocation_units);
        try w.u64le(i.caller_available_allocation_units);
        try w.u64le(i.actual_available_allocation_units);
        try w.u32le(i.sectors_per_allocation_unit);
        try w.u32le(i.bytes_per_sector);
    }
};

pub const FileFsAttributeInformation = struct {
    file_system_attributes: u32 = 0,
    maximum_component_name_length: u32 = 0,
    /// UTF-16LE; Windows sends no terminator, FreeRDP includes one.
    file_system_name: []const u8 = "",

    pub const fixed_size = 12;

    pub fn decode(buf: []const u8) Error!FileFsAttributeInformation {
        var r: Rd = .{ .buf = buf };
        try r.need(fixed_size);
        var i: FileFsAttributeInformation = .{};
        i.file_system_attributes = try r.int(u32);
        i.maximum_component_name_length = try r.int(u32);
        const len = try r.int(u32);
        i.file_system_name = try r.take(len);
        if (len % 2 != 0) return error.InvalidField;
        return i;
    }
    pub fn encode(i: FileFsAttributeInformation, w: *bytes.Writer) Error!void {
        const len = try utf16Len32(i.file_system_name);
        try w.u32le(i.file_system_attributes);
        try w.u32le(i.maximum_component_name_length);
        try w.u32le(len);
        try w.bytes(i.file_system_name);
    }
};

pub const FileFsDeviceInformation = struct {
    device_type: u32 = file_device_disk,
    characteristics: u32 = 0,

    pub const size = 8;

    pub fn decode(buf: []const u8) Error!FileFsDeviceInformation {
        var r: Rd = .{ .buf = buf };
        try r.need(size);
        var i: FileFsDeviceInformation = .{};
        i.device_type = try r.int(u32);
        i.characteristics = try r.int(u32);
        return i;
    }
    pub fn encode(i: FileFsDeviceInformation, w: *bytes.Writer) Error!void {
        try w.u32le(i.device_type);
        try w.u32le(i.characteristics);
    }
};

/// Query information response buffer (classes allowed by 2.2.3.3.8).
pub const QueryInformation = union(enum) {
    basic: FileBasicInformation,
    standard: FileStandardInformation,
    attribute_tag: FileAttributeTagInformation,
};

pub fn decodeQueryInformation(class: FileInformationClass, buf: []const u8) Error!QueryInformation {
    return switch (class) {
        .basic => .{ .basic = try FileBasicInformation.decode(buf) },
        .standard => .{ .standard = try FileStandardInformation.decode(buf) },
        .attribute_tag => .{ .attribute_tag = try FileAttributeTagInformation.decode(buf) },
        else => error.InvalidField,
    };
}

/// Query volume information response buffer (classes allowed by 2.2.3.3.6).
pub const VolumeInformation = union(enum) {
    volume: FileFsVolumeInformation,
    size: FileFsSizeInformation,
    attribute: FileFsAttributeInformation,
    full_size: FileFsFullSizeInformation,
    device: FileFsDeviceInformation,
};

pub fn decodeVolumeInformation(class: FsInformationClass, buf: []const u8) Error!VolumeInformation {
    return switch (class) {
        .volume => .{ .volume = try FileFsVolumeInformation.decode(buf) },
        .size => .{ .size = try FileFsSizeInformation.decode(buf) },
        .attribute => .{ .attribute = try FileFsAttributeInformation.decode(buf) },
        .full_size => .{ .full_size = try FileFsFullSizeInformation.decode(buf) },
        .device => .{ .device = try FileFsDeviceInformation.decode(buf) },
        else => error.InvalidField,
    };
}

/// [MS-FSCC] 2.7.1 FILE_NOTIFY_INFORMATION record ([MS-SMB2] 2.2.36).
pub const FileNotifyInformation = struct {
    action: u32,
    /// UTF-16LE, relative to the watched directory, '\' separated.
    file_name: []const u8,
};

const notify_record_fixed = 12;

/// Walks FILE_NOTIFY_INFORMATION records by NextEntryOffset (0 ends the chain).
pub const NotifyIterator = struct {
    buf: []const u8,
    pos: usize = 0,
    done: bool = false,

    pub fn init(buf: []const u8) NotifyIterator {
        return .{ .buf = buf, .done = buf.len == 0 };
    }

    pub fn next(it: *NotifyIterator) Error!?FileNotifyInformation {
        if (it.done) return null;
        errdefer it.done = true;
        var r: Rd = .{ .buf = it.buf, .pos = it.pos };
        const next_offset = try r.int(u32);
        const action = try r.int(u32);
        const name_len = try r.int(u32);
        const name = try r.take(name_len);
        if (name_len % 2 != 0) return error.InvalidField;
        if (next_offset == 0) {
            it.done = true;
        } else {
            // The next record starts past this name, so the walk always advances.
            if (next_offset < notify_record_fixed + @as(u64, name_len)) return error.InvalidField;
            if (next_offset > it.buf.len - it.pos) return error.Truncated;
            it.pos += next_offset;
        }
        return .{ .action = action, .file_name = name };
    }
};

/// Records chained by NextEntryOffset, all but the last padded to 4 bytes ([MS-FSCC] 2.7.1).
pub fn encodeNotifyInformation(w: *bytes.Writer, records: []const FileNotifyInformation) Error!void {
    for (records) |rec| _ = try utf16Len32(rec.file_name);
    for (records, 0..) |rec, i| {
        const last = i + 1 == records.len;
        const len = notify_record_fixed + rec.file_name.len;
        const padded = std.mem.alignForward(usize, len, 4);
        try w.u32le(if (last) 0 else try len32(padded));
        try w.u32le(rec.action);
        try w.u32le(@intCast(rec.file_name.len));
        try w.bytes(rec.file_name);
        if (!last) try w.zeros(padded - len);
    }
}

// --- Encoders (append one PDU to `w`) ---

pub fn encodeHeader(w: *bytes.Writer, h: Header) Error!void {
    try w.u16le(@backingInt(h.component));
    try w.u16le(@backingInt(h.packet_id));
}

fn encodeCoreHeader(w: *bytes.Writer, packet_id: PacketId) Error!void {
    return encodeHeader(w, .{ .component = .core, .packet_id = packet_id });
}

/// VersionMajor, VersionMinor, ClientId after the header (2.2.2.2, 2.2.2.3, 2.2.2.6).
fn encodeVersion(w: *bytes.Writer, packet_id: PacketId, v: VersionInfo) Error!void {
    try encodeCoreHeader(w, packet_id);
    try w.u16le(v.major);
    try w.u16le(v.minor);
    try w.u32le(v.client_id);
}

/// DR_CORE_SERVER_ANNOUNCE_REQ (2.2.2.2).
pub fn encodeServerAnnounce(w: *bytes.Writer, v: VersionInfo) Error!void {
    return encodeVersion(w, .core_server_announce, v);
}

/// DR_CORE_CLIENT_ANNOUNCE_RSP (2.2.2.3).
pub fn encodeClientAnnounceReply(w: *bytes.Writer, v: VersionInfo) Error!void {
    return encodeVersion(w, .core_clientid_confirm, v);
}

/// DR_CORE_SERVER_CLIENTID_CONFIRM (2.2.2.6).
pub fn encodeClientIdConfirm(w: *bytes.Writer, v: VersionInfo) Error!void {
    return encodeVersion(w, .core_clientid_confirm, v);
}

/// DR_CORE_CLIENT_NAME_REQ (2.2.2.4) from UTF-8: UTF-16LE when `unicode`, else the
/// bytes as they are; ComputerNameLen counts the terminator.
pub fn encodeClientName(w: *bytes.Writer, unicode: bool, utf8_name: []const u8) Error!void {
    const name_len = if (unicode) 2 * (try utf16UnitCount(utf8_name) + 1) else utf8_name.len + 1;
    try encodeCoreHeader(w, .core_client_name);
    try w.u32le(@intFromBool(unicode));
    try w.u32le(0); // CodePage
    try w.u32le(try len32(name_len));
    if (unicode) {
        try writeUtf16(w, utf8_name);
        try w.u16le(0);
    } else {
        try w.bytes(utf8_name);
        try w.byte(0);
    }
}

/// DR_CORE_USER_LOGGEDON (2.2.2.5): the header alone.
pub fn encodeUserLoggedOn(w: *bytes.Writer) Error!void {
    return encodeCoreHeader(w, .core_user_loggedon);
}

/// Device capability sets (2.2.2.7.2 - 2.2.2.7.5) in the order of 4.8.
const device_capability_sets = [_]struct { []const u8, CapabilityType }{
    .{ "printer", .printer },
    .{ "port", .port },
    .{ "drive", .drive },
    .{ "smartcard", .smartcard },
};

fn encodeCapabilities(w: *bytes.Writer, packet_id: PacketId, c: Capabilities) Error!void {
    try encodeCoreHeader(w, packet_id);
    try w.u16le(c.count());
    try w.u16le(0); // Padding
    if (c.general) |g| {
        const v2 = g.version >= general_capability_version_02;
        try w.u16le(@backingInt(CapabilityType.general));
        try w.u16le(if (v2) general_caps_len_v2 else general_caps_len_v1);
        try w.u32le(g.version);
        try w.u32le(g.os_type);
        try w.u32le(g.os_version);
        try w.u16le(g.protocol_major_version);
        try w.u16le(g.protocol_minor_version);
        try w.u32le(g.io_code1);
        try w.u32le(g.io_code2);
        try w.u32le(g.extended_pdu);
        try w.u32le(g.extra_flags1);
        try w.u32le(g.extra_flags2);
        if (v2) try w.u32le(g.special_type_device_cap);
    }
    inline for (device_capability_sets) |set| {
        if (@field(c, set[0])) |version| {
            try w.u16le(@backingInt(set[1]));
            try w.u16le(capability_header_len);
            try w.u32le(version);
        }
    }
}

/// DR_CORE_CAPABILITY_REQ (2.2.2.7): PAKID_CORE_SERVER_CAPABILITY.
pub fn encodeCapabilityRequest(w: *bytes.Writer, caps: Capabilities) Error!void {
    return encodeCapabilities(w, .core_server_capability, caps);
}

/// DR_CORE_CAPABILITY_RSP (2.2.2.8): PAKID_CORE_CLIENT_CAPABILITY.
pub fn encodeCapabilityResponse(w: *bytes.Writer, caps: Capabilities) Error!void {
    return encodeCapabilities(w, .core_client_capability, caps);
}

/// One DEVICE_ANNOUNCE (2.2.1.3), without RDPDR_HEADER.
pub fn encodeDeviceAnnounce(w: *bytes.Writer, d: DeviceAnnounce) Error!void {
    const len = try len32(d.device_data.len);
    try w.u32le(@backingInt(d.device_type));
    try w.u32le(d.device_id);
    try w.bytes(&d.preferred_dos_name);
    try w.u32le(len);
    try w.bytes(d.device_data);
}

/// DR_CORE_DEVICELIST_ANNOUNCE_REQ (2.2.2.9) / DR_DEVICELIST_ANNOUNCE (2.2.3.1).
pub fn encodeDeviceListAnnounce(w: *bytes.Writer, devices: []const DeviceAnnounce) Error!void {
    try encodeCoreHeader(w, .core_devicelist_announce);
    try w.u32le(try len32(devices.len));
    for (devices) |d| try encodeDeviceAnnounce(w, d);
}

/// DR_DEVICELIST_REMOVE (2.2.3.2).
pub fn encodeDeviceListRemove(w: *bytes.Writer, device_ids: []const u32) Error!void {
    try encodeCoreHeader(w, .core_devicelist_remove);
    try w.u32le(try len32(device_ids.len));
    for (device_ids) |id| try w.u32le(id);
}

/// DR_CORE_DEVICE_ANNOUNCE_RSP (2.2.2.1).
pub fn encodeDeviceAnnounceResponse(w: *bytes.Writer, r: DeviceAnnounceResponse) Error!void {
    try encodeCoreHeader(w, .core_device_reply);
    try w.u32le(r.device_id);
    try w.u32le(r.result_code);
}

/// Lengths fit 32 bits, UTF-16 paths are even, lock arrays hold whole entries.
fn checkIoRequestBody(body: IoRequestBody) Error!void {
    switch (body) {
        .create => |c| _ = try utf16Len32(c.path),
        .write => |wr| _ = try len32(wr.data.len),
        .device_control => |dc| _ = try len32(dc.input.len),
        .query_volume_information, .set_volume_information => |v| _ = try len32(v.buffer.len),
        .query_information, .set_information => |f| _ = try len32(f.buffer.len),
        .query_directory => |q| _ = try utf16Len32(q.path),
        .lock_control => |l| {
            if (l.locks.len % LockInfo.size != 0) return error.InvalidField;
            _ = try len32(l.locks.len / LockInfo.size);
        },
        .close, .read, .notify_change_directory => {},
    }
}

/// A Device I/O Request (2.2.1.4, 2.2.3.3): header and body, zero padding.
pub fn encodeIoRequest(w: *bytes.Writer, req: IoRequest) Error!void {
    try checkIoRequestBody(req.body);
    try encodeCoreHeader(w, .core_device_iorequest);
    try w.u32le(req.device_id);
    try w.u32le(req.file_id);
    try w.u32le(req.completion_id);
    try w.u32le(@backingInt(req.majorFunction()));
    try w.u32le(@backingInt(req.minorFunction()));
    switch (req.body) {
        .create => |c| {
            try w.u32le(c.desired_access);
            try w.u64le(c.allocation_size);
            try w.u32le(c.file_attributes);
            try w.u32le(c.shared_access);
            try w.u32le(c.create_disposition);
            try w.u32le(c.create_options);
            try w.u32le(@intCast(c.path.len));
            try w.bytes(c.path);
        },
        .close => try w.zeros(32),
        .read => |rd| {
            try w.u32le(rd.length);
            try w.u64le(rd.offset);
            try w.zeros(20);
        },
        .write => |wr| {
            try w.u32le(@intCast(wr.data.len));
            try w.u64le(wr.offset);
            try w.zeros(20);
            try w.bytes(wr.data);
        },
        .device_control => |dc| {
            try w.u32le(dc.output_buffer_length);
            try w.u32le(@intCast(dc.input.len));
            try w.u32le(dc.io_control_code);
            try w.zeros(20);
            try w.bytes(dc.input);
        },
        .query_volume_information, .set_volume_information => |v| {
            try w.u32le(@backingInt(v.fs_information_class));
            try w.u32le(@intCast(v.buffer.len));
            try w.zeros(24);
            try w.bytes(v.buffer);
        },
        .query_information, .set_information => |f| {
            try w.u32le(@backingInt(f.file_information_class));
            try w.u32le(@intCast(f.buffer.len));
            try w.zeros(24);
            try w.bytes(f.buffer);
        },
        .query_directory => |q| {
            try w.u32le(@backingInt(q.file_information_class));
            try w.byte(@intFromBool(q.initial_query));
            try w.u32le(@intCast(q.path.len));
            try w.zeros(23);
            try w.bytes(q.path);
        },
        .notify_change_directory => |n| {
            try w.byte(@intFromBool(n.watch_tree));
            try w.u32le(n.completion_filter);
            try w.zeros(27);
        },
        .lock_control => |l| {
            try w.u32le(@backingInt(l.operation));
            try w.u32le(if (l.wait) lock_flag_wait else 0);
            try w.u32le(l.count());
            try w.zeros(20);
            try w.bytes(l.locks);
        },
    }
}

/// DR_DEVICE_IOCOMPLETION header alone (2.2.1.5), 16 bytes.
pub fn encodeIoCompletionHeader(w: *bytes.Writer, device_id: u32, completion_id: u32, io_status: u32) Error!void {
    try encodeCoreHeader(w, .core_device_iocompletion);
    try w.u32le(device_id);
    try w.u32le(completion_id);
    try w.u32le(io_status);
}

/// A Device I/O Response with the padding Windows sends (section 4).
pub fn encodeIoResponse(w: *bytes.Writer, c: IoCompletion, rsp: IoResponse) Error!void {
    switch (rsp) {
        .read, .device_control, .query_volume_information, .query_information, .query_directory, .notify_change_directory => |b| _ = try len32(b.len),
        else => {},
    }
    try encodeIoCompletionHeader(w, c.device_id, c.completion_id, c.io_status);
    switch (rsp) {
        .create => |cr| {
            try w.u32le(cr.file_id);
            try w.byte(cr.information);
        },
        .close => try w.zeros(4),
        .read, .device_control, .query_volume_information, .query_information, .query_directory => |b| {
            try w.u32le(@intCast(b.len));
            try w.bytes(b);
        },
        .notify_change_directory => |b| {
            try w.u32le(@intCast(b.len));
            try w.bytes(b);
            try w.byte(0);
        },
        .write, .set_volume_information, .set_information => |n| {
            try w.u32le(n);
            try w.byte(0);
        },
        .lock_control => try w.zeros(5),
    }
}

// --- Decoders (one complete message) ---

/// Little-endian cursor; reading past the end is error.Truncated (3.1.5.2).
const Rd = struct {
    buf: []const u8,
    pos: usize = 0,

    fn left(r: *const Rd) usize {
        return r.buf.len - r.pos;
    }

    fn need(r: *const Rd, n: usize) Error!void {
        if (r.left() < n) return error.Truncated;
    }

    fn take(r: *Rd, n: usize) Error![]const u8 {
        try r.need(n);
        const s = r.buf[r.pos..][0..n];
        r.pos += n;
        return s;
    }

    fn skip(r: *Rd, n: usize) Error!void {
        _ = try r.take(n);
    }

    fn int(r: *Rd, comptime T: type) Error!T {
        const s = try r.take(@sizeOf(T));
        return std.mem.readInt(T, s[0..@sizeOf(T)], .little);
    }

    fn rest(r: *const Rd) []const u8 {
        return r.buf[r.pos..];
    }
};

/// RDPDR_HEADER. PAKID_PRN_* is valid only with RDPDR_CTYP_PRN, all others
/// only with RDPDR_CTYP_CORE.
pub fn decodeHeader(msg: []const u8) Error!Header {
    if (msg.len < header_len) return error.Truncated;
    const component: Component = switch (std.mem.readInt(u16, msg[0..2], .little)) {
        @backingInt(Component.core) => .core,
        @backingInt(Component.prn) => .prn,
        else => return error.UnknownComponent,
    };
    const packet_id: PacketId = @fromBackingInt(std.mem.readInt(u16, msg[2..4], .little));
    const known = switch (packet_id) {
        .core_server_announce,
        .core_clientid_confirm,
        .core_client_name,
        .core_devicelist_announce,
        .core_device_reply,
        .core_device_iorequest,
        .core_device_iocompletion,
        .core_server_capability,
        .core_client_capability,
        .core_devicelist_remove,
        .core_user_loggedon,
        => component == .core,
        .prn_cache_data, .prn_using_xps => component == .prn,
        _ => false,
    };
    if (!known) return error.UnknownPacketId;
    return .{ .component = component, .packet_id = packet_id };
}

fn corePdu(msg: []const u8, packet_id: PacketId) Error!Rd {
    const h = try decodeHeader(msg);
    if (h.component != .core or h.packet_id != packet_id) return error.UnexpectedPdu;
    return .{ .buf = msg, .pos = header_len };
}

fn decodeVersion(msg: []const u8, packet_id: PacketId) Error!VersionInfo {
    var r = try corePdu(msg, packet_id);
    try r.need(8);
    var v: VersionInfo = .{ .minor = 0, .client_id = 0 };
    v.major = try r.int(u16);
    v.minor = try r.int(u16);
    v.client_id = try r.int(u32);
    return v;
}

pub fn decodeServerAnnounce(msg: []const u8) Error!VersionInfo {
    return decodeVersion(msg, .core_server_announce);
}

/// Client Announce Reply (2.2.2.3); same layout as Server Client ID Confirm.
pub fn decodeClientAnnounceReply(msg: []const u8) Error!VersionInfo {
    return decodeVersion(msg, .core_clientid_confirm);
}

/// Server Client ID Confirm (2.2.2.6).
pub fn decodeClientIdConfirm(msg: []const u8) Error!VersionInfo {
    return decodeVersion(msg, .core_clientid_confirm);
}

/// Client Name Request (2.2.2.4); the name is display only (3.1.1). The macOS
/// Windows App omits the terminator.
pub fn decodeClientName(msg: []const u8) Error!ClientName {
    var r = try corePdu(msg, .core_client_name);
    try r.need(12);
    const flag = try r.int(u32);
    const code_page = try r.int(u32);
    const len = try r.int(u32);
    const unicode = flag & 1 != 0;
    const raw = try r.take(len);
    const name = if (unicode) raw[0 .. raw.len & ~@as(usize, 1)] else raw;
    return .{ .unicode = unicode, .code_page = code_page, .name = name };
}

/// GENERAL_CAPS_SET body after its CAPABILITY_HEADER (2.2.2.7.1).
fn decodeGeneralCapabilitySet(version: u32, body: []const u8) Error!GeneralCapabilitySet {
    const v2 = version >= general_capability_version_02;
    const need: usize = (if (v2) general_caps_len_v2 else general_caps_len_v1) - capability_header_len;
    if (body.len < need) return error.InvalidField;
    var r: Rd = .{ .buf = body };
    var g: GeneralCapabilitySet = .{ .version = version };
    g.os_type = try r.int(u32);
    g.os_version = try r.int(u32);
    g.protocol_major_version = try r.int(u16);
    g.protocol_minor_version = try r.int(u16);
    g.io_code1 = try r.int(u32);
    g.io_code2 = try r.int(u32);
    g.extended_pdu = try r.int(u32);
    g.extra_flags1 = try r.int(u32);
    g.extra_flags2 = try r.int(u32);
    g.special_type_device_cap = if (v2) try r.int(u32) else 0;
    if (g.protocol_major_version != version_major) return error.InvalidField;
    return g;
}

/// Server Core Capability Request or Client Core Capability Response.
pub fn decodeCapabilities(msg: []const u8) Error!Capabilities {
    const h = try decodeHeader(msg);
    if (h.component != .core or (h.packet_id != .core_server_capability and h.packet_id != .core_client_capability))
        return error.UnexpectedPdu;
    var r: Rd = .{ .buf = msg, .pos = header_len };
    const n = try r.int(u16);
    _ = try r.int(u16); // Padding
    var c: Capabilities = .{};
    for (0..n) |_| {
        try r.need(capability_header_len);
        const t = try r.int(u16);
        const len = try r.int(u16);
        const version = try r.int(u32);
        // CapabilityLength covers the header (2.2.1.2).
        if (len < capability_header_len) return error.InvalidField;
        const body = try r.take(len - capability_header_len);
        switch (@as(CapabilityType, @fromBackingInt(t))) {
            .general => c.general = try decodeGeneralCapabilitySet(version, body),
            .printer => c.printer = version,
            .port => c.port = version,
            .drive => c.drive = version,
            .smartcard => c.smartcard = version,
            _ => return error.UnknownCapability,
        }
    }
    return c;
}

pub fn decodeDeviceListAnnounce(msg: []const u8) Error!DeviceList {
    var r = try corePdu(msg, .core_devicelist_announce);
    const count = try r.int(u32);
    const start = r.pos;
    // Each entry takes at least 20 bytes, so an oversized count fails early.
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        try r.need(device_announce_fixed_len);
        const data_len = std.mem.readInt(u32, r.buf[r.pos + 16 ..][0..4], .little);
        try r.skip(device_announce_fixed_len);
        try r.skip(data_len);
    }
    return .{ .count = count, .data = msg[start..r.pos] };
}

pub fn decodeDeviceListRemove(msg: []const u8) Error!DeviceListRemove {
    var r = try corePdu(msg, .core_devicelist_remove);
    const count = try r.int(u32);
    const ids = try r.take(@as(usize, count) * 4);
    return .{ .count = count, .ids = ids };
}

pub fn decodeDeviceAnnounceResponse(msg: []const u8) Error!DeviceAnnounceResponse {
    var r = try corePdu(msg, .core_device_reply);
    try r.need(8);
    var d: DeviceAnnounceResponse = .{ .device_id = 0, .result_code = 0 };
    d.device_id = try r.int(u32);
    d.result_code = try r.int(u32);
    return d;
}

pub fn decodeUserLoggedOn(msg: []const u8) Error!void {
    _ = try corePdu(msg, .core_user_loggedon);
}

/// Device I/O Request. MinorFunction is checked only for IRP_MJ_DIRECTORY_CONTROL;
/// Windows leaves it uninitialized for IRP_MJ_DEVICE_CONTROL (<5>).
pub fn decodeIoRequest(msg: []const u8) Error!IoRequest {
    var r = try corePdu(msg, .core_device_iorequest);
    try r.need(io_request_header_len - header_len);
    const device_id = try r.int(u32);
    const file_id = try r.int(u32);
    const completion_id = try r.int(u32);
    const major: MajorFunction = @fromBackingInt(try r.int(u32));
    const minor: MinorFunction = @fromBackingInt(try r.int(u32));
    switch (major) {
        .create, .close, .read, .write, .query_information, .set_information => {},
        .query_volume_information, .set_volume_information, .device_control, .lock_control => {},
        .directory_control => if (minor != .query_directory and minor != .notify_change_directory) return error.InvalidField,
        _ => return error.InvalidField,
    }
    // Every request body has a 32-byte fixed part (2.2.1.4.1 - 2.2.3.3.12).
    try r.need(32);
    const body: IoRequestBody = switch (major) {
        .create => blk: {
            var c: CreateRequest = .{ .desired_access = try r.int(u32) };
            c.allocation_size = try r.int(u64);
            c.file_attributes = try r.int(u32);
            c.shared_access = try r.int(u32);
            c.create_disposition = try r.int(u32);
            c.create_options = try r.int(u32);
            c.path = try utf16Field(&r);
            break :blk .{ .create = c };
        },
        .close => blk: {
            try r.skip(32);
            break :blk .close;
        },
        .read => blk: {
            const length = try r.int(u32);
            const offset = try r.int(u64);
            try r.skip(20);
            break :blk .{ .read = .{ .length = length, .offset = offset } };
        },
        .write => blk: {
            const length = try r.int(u32);
            const offset = try r.int(u64);
            try r.skip(20);
            break :blk .{ .write = .{ .offset = offset, .data = try r.take(length) } };
        },
        .device_control => blk: {
            const output_len = try r.int(u32);
            const input_len = try r.int(u32);
            const code = try r.int(u32);
            try r.skip(20);
            break :blk .{ .device_control = .{ .output_buffer_length = output_len, .io_control_code = code, .input = try r.take(input_len) } };
        },
        .query_volume_information, .set_volume_information => blk: {
            const class: FsInformationClass = @fromBackingInt(try r.int(u32));
            const length = try r.int(u32);
            try r.skip(24);
            const v: VolumeInformationRequest = .{ .fs_information_class = class, .buffer = try r.take(length) };
            break :blk if (major == .query_volume_information) .{ .query_volume_information = v } else .{ .set_volume_information = v };
        },
        .query_information, .set_information => blk: {
            const class: FileInformationClass = @fromBackingInt(try r.int(u32));
            const length = try r.int(u32);
            try r.skip(24);
            const f: FileInformationRequest = .{ .file_information_class = class, .buffer = try r.take(length) };
            break :blk if (major == .query_information) .{ .query_information = f } else .{ .set_information = f };
        },
        .directory_control => blk: {
            if (minor == .query_directory) {
                const class: FileInformationClass = @fromBackingInt(try r.int(u32));
                const initial = try r.int(u8) != 0;
                const path_len = try r.int(u32);
                try r.skip(23);
                const path = try r.take(path_len);
                if (path_len % 2 != 0) return error.InvalidField;
                break :blk .{ .query_directory = .{ .file_information_class = class, .initial_query = initial, .path = path } };
            }
            const watch_tree = try r.int(u8) != 0;
            const filter = try r.int(u32);
            try r.skip(27);
            break :blk .{ .notify_change_directory = .{ .watch_tree = watch_tree, .completion_filter = filter } };
        },
        .lock_control => blk: {
            const operation: LockOperation = @fromBackingInt(try r.int(u32));
            // Only bit 0 (F) is defined; the rest is padding.
            const wait = try r.int(u32) & lock_flag_wait != 0;
            const count = try r.int(u32);
            try r.skip(20);
            const locks = try r.take(@as(usize, count) * LockInfo.size);
            break :blk .{ .lock_control = .{ .operation = operation, .wait = wait, .locks = locks } };
        },
        _ => unreachable,
    };
    return .{ .device_id = device_id, .file_id = file_id, .completion_id = completion_id, .body = body };
}

/// PathLength (4 bytes) then Path: UTF-16LE, so an even length.
fn utf16Field(r: *Rd) Error![]const u8 {
    const len = try r.int(u32);
    const s = try r.take(len);
    if (len % 2 != 0) return error.InvalidField;
    return s;
}

pub fn decodeIoCompletion(msg: []const u8) Error!IoCompletion {
    var r = try corePdu(msg, .core_device_iocompletion);
    try r.need(io_completion_header_len - header_len);
    var c: IoCompletion = .{ .device_id = 0, .completion_id = 0, .io_status = 0 };
    c.device_id = try r.int(u32);
    c.completion_id = try r.int(u32);
    c.io_status = try r.int(u32);
    c.body = r.rest();
    return c;
}

fn lengthPrefixed(r: *Rd) Error![]const u8 {
    const len = try r.int(u32);
    return r.take(len);
}

/// Trailing padding is ignored. Create's Information may be absent (2.2.1.5.1);
/// FreeRDP's printer omits it.
pub fn decodeIoResponse(major: MajorFunction, minor: MinorFunction, c: IoCompletion) Error!IoResponse {
    var r: Rd = .{ .buf = c.body };
    switch (major) {
        .create => {
            const file_id = try r.int(u32);
            const information: u8 = if (r.left() > 0) try r.int(u8) else file_superseded;
            return .{ .create = .{ .file_id = file_id, .information = information } };
        },
        .close => {
            try r.skip(4);
            return .close;
        },
        .read => return .{ .read = try lengthPrefixed(&r) },
        .write => return .{ .write = try r.int(u32) },
        .device_control => return .{ .device_control = try lengthPrefixed(&r) },
        .query_volume_information => return .{ .query_volume_information = try lengthPrefixed(&r) },
        .set_volume_information => return .{ .set_volume_information = try r.int(u32) },
        .query_information => return .{ .query_information = try lengthPrefixed(&r) },
        .set_information => return .{ .set_information = try r.int(u32) },
        .directory_control => return switch (minor) {
            .query_directory => .{ .query_directory = try lengthPrefixed(&r) },
            .notify_change_directory => .{ .notify_change_directory = try lengthPrefixed(&r) },
            else => error.InvalidField,
        },
        .lock_control => return .lock_control,
        _ => return error.InvalidField,
    }
}

/// Any client to server PDU. Server-only PacketIds: error.UnexpectedPdu.
pub fn decodeClientPdu(msg: []const u8) Error!ClientPdu {
    const h = try decodeHeader(msg);
    if (h.component == .prn) return .{ .printer = .{ .packet_id = h.packet_id, .body = msg[header_len..] } };
    return switch (h.packet_id) {
        .core_clientid_confirm => .{ .announce_reply = try decodeClientAnnounceReply(msg) },
        .core_client_name => .{ .client_name = try decodeClientName(msg) },
        .core_client_capability => .{ .capabilities = try decodeCapabilities(msg) },
        .core_devicelist_announce => .{ .device_list_announce = try decodeDeviceListAnnounce(msg) },
        .core_devicelist_remove => .{ .device_list_remove = try decodeDeviceListRemove(msg) },
        .core_device_iocompletion => .{ .io_completion = try decodeIoCompletion(msg) },
        else => error.UnexpectedPdu,
    };
}

/// Any server to client PDU; client-only and printer PDUs are error.UnexpectedPdu.
pub fn decodeServerPdu(msg: []const u8) Error!ServerPdu {
    const h = try decodeHeader(msg);
    if (h.component != .core) return error.UnexpectedPdu;
    return switch (h.packet_id) {
        .core_server_announce => .{ .server_announce = try decodeServerAnnounce(msg) },
        .core_clientid_confirm => .{ .client_id_confirm = try decodeClientIdConfirm(msg) },
        .core_server_capability => .{ .capabilities = try decodeCapabilities(msg) },
        .core_user_loggedon => blk: {
            try decodeUserLoggedOn(msg);
            break :blk .user_logged_on;
        },
        .core_device_reply => .{ .device_announce_response = try decodeDeviceAnnounceResponse(msg) },
        .core_device_iorequest => .{ .io_request = try decodeIoRequest(msg) },
        else => error.UnexpectedPdu,
    };
}

// --- Strings and names ---

/// UTF-16LE to UTF-8 up to the first NUL. Odd length: error.InvalidField;
/// unpaired surrogate: error.InvalidName.
pub fn utf16leToUtf8(out: []u8, utf16le: []const u8) Error![]const u8 {
    if (utf16le.len % 2 != 0) return error.InvalidField;
    var it: Utf16Iterator = .{ .s = utf16le };
    var n: usize = 0;
    while (try it.next()) |cp| {
        if (cp == 0) break;
        n += try putUtf8(out[n..], cp);
    }
    return out[0..n];
}

pub fn utf8ToUtf16le(out: []u8, utf8: []const u8, terminate: bool) Error![]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < utf8.len) n += try putUtf16(out[n..], try nextUtf8(utf8, &i));
    if (terminate) n += try putUtf16(out[n..], 0);
    return out[0..n];
}

pub fn clientNameUtf8(out: []u8, n: ClientName) Error![]const u8 {
    if (n.unicode) return utf16leToUtf8(out, n.name);
    const end = std.mem.indexOfScalar(u8, n.name, 0) orelse n.name.len;
    return codePageToUtf8(out, n.name[0..end]);
}

/// 2.2.1.3: NUL-terminated within 8 bytes, none of < > " / \ |, ':' only last.
pub fn validDosName(preferred_dos_name: [8]u8) Error!bool {
    const end = std.mem.indexOfScalar(u8, &preferred_dos_name, 0) orelse return false;
    const name = preferred_dos_name[0..end];
    for (name, 0..) |c, i| switch (c) {
        '<', '>', '"', '/', '\\', '|' => return false,
        ':' => if (i + 1 != name.len) return false,
        else => {},
    };
    return true;
}

/// 3.2.5.2.3: names a client MUST refuse (case-insensitive).
pub fn isReservedDeviceName(name: []const u8) Error!bool {
    for ([_][]const u8{ "PRN", "AUX", "NUL", "CON", "CLOCK$" }) |reserved| {
        if (std.ascii.eqlIgnoreCase(name, reserved)) return true;
    }
    if (name.len != 4 or name[3] < '1' or name[3] > '9') return false;
    return std.ascii.eqlIgnoreCase(name[0..3], "COM") or std.ascii.eqlIgnoreCase(name[0..3], "LPT");
}

const Utf16Iterator = struct {
    s: []const u8,
    i: usize = 0,

    fn unit(it: *const Utf16Iterator, at: usize) u16 {
        return std.mem.readInt(u16, it.s[at..][0..2], .little);
    }

    fn next(it: *Utf16Iterator) Error!?u21 {
        if (it.s.len - it.i < 2) return null;
        const hi = it.unit(it.i);
        it.i += 2;
        if (std.unicode.utf16IsLowSurrogate(hi)) return error.InvalidName;
        if (!std.unicode.utf16IsHighSurrogate(hi)) return hi;
        if (it.s.len - it.i < 2) return error.InvalidName;
        const lo = it.unit(it.i);
        if (!std.unicode.utf16IsLowSurrogate(lo)) return error.InvalidName;
        it.i += 2;
        return 0x10000 + ((@as(u21, hi) - 0xD800) << 10) + (lo - 0xDC00);
    }
};

/// Next scalar of strict UTF-8 (no overlong forms, surrogates or values above U+10FFFF).
fn nextUtf8(s: []const u8, i: *usize) Error!u21 {
    const len = std.unicode.utf8ByteSequenceLength(s[i.*]) catch return error.InvalidName;
    if (s.len - i.* < len) return error.InvalidName;
    const cp = std.unicode.utf8Decode(s[i.*..][0..len]) catch return error.InvalidName;
    i.* += len;
    return cp;
}

fn putUtf8(out: []u8, cp: u21) Error!usize {
    const len = std.unicode.utf8CodepointSequenceLength(cp) catch return error.InvalidName;
    if (out.len < len) return error.NoSpaceLeft;
    _ = std.unicode.utf8Encode(cp, out[0..len]) catch return error.InvalidName;
    return len;
}

fn putUtf16(out: []u8, cp: u21) Error!usize {
    if (cp < 0x10000) {
        if (out.len < 2) return error.NoSpaceLeft;
        std.mem.writeInt(u16, out[0..2], @intCast(cp), .little);
        return 2;
    }
    if (out.len < 4) return error.NoSpaceLeft;
    const v = cp - 0x10000;
    std.mem.writeInt(u16, out[0..2], @intCast(0xD800 + (v >> 10)), .little);
    std.mem.writeInt(u16, out[2..4], @intCast(0xDC00 + (v & 0x3FF)), .little);
    return 4;
}

fn utf16UnitCount(utf8: []const u8) Error!usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < utf8.len) n += if (try nextUtf8(utf8, &i) < 0x10000) 1 else 2;
    return n;
}

fn writeUtf16(w: *bytes.Writer, utf8: []const u8) Error!void {
    var buf: [4]u8 = undefined;
    var i: usize = 0;
    while (i < utf8.len) try w.bytes(buf[0..try putUtf16(&buf, try nextUtf8(utf8, &i))]);
}

/// Kept if valid UTF-8, else read as Latin-1.
fn codePageToUtf8(out: []u8, s: []const u8) Error![]const u8 {
    if (std.unicode.utf8ValidateSlice(s)) {
        if (out.len < s.len) return error.NoSpaceLeft;
        @memcpy(out[0..s.len], s);
        return out[0..s.len];
    }
    var n: usize = 0;
    for (s) |c| n += try putUtf8(out[n..], c);
    return out[0..n];
}

fn len32(n: usize) Error!u32 {
    return std.math.cast(u32, n) orelse error.InvalidField;
}

fn utf16Len32(s: []const u8) Error!u32 {
    if (s.len % 2 != 0) return error.InvalidField;
    return len32(s.len);
}

// --- Linux mapping ---

/// Directory under the runtime directory that holds the drives.
pub const drives_subdir = "omastation/drives";

fn concat(out: []u8, parts: []const []const u8) Error![]const u8 {
    var n: usize = 0;
    for (parts) |p| {
        if (out.len - n < p.len) return error.NoSpaceLeft;
        @memcpy(out[n..][0..p.len], p);
        n += p.len;
    }
    return out[0..n];
}

fn isPathComponent(name: []const u8) bool {
    if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    return std.mem.indexOfAny(u8, name, "/\x00") == null;
}

/// "<runtime_dir>/omastation/drives"; `runtime_dir` ($XDG_RUNTIME_DIR) must be absolute.
pub fn drivesDir(out: []u8, runtime_dir: []const u8) Error![]const u8 {
    if (runtime_dir.len == 0 or runtime_dir[0] != '/') return error.InvalidName;
    if (std.mem.indexOfScalar(u8, runtime_dir, 0) != null) return error.InvalidName;
    return concat(out, &.{ std.mem.trimEnd(u8, runtime_dir, "/"), "/", drives_subdir });
}

/// "<drivesDir>/<name>"; `name` must be a single path component.
pub fn mountPoint(out: []u8, runtime_dir: []const u8, name: []const u8) Error![]const u8 {
    if (!isPathComponent(name)) return error.InvalidName;
    const dir = try drivesDir(out, runtime_dir);
    const tail = try concat(out[dir.len..], &.{ "/", name });
    return out[0 .. dir.len + tail.len];
}

fn unsafeNameChar(cp: u21) bool {
    return cp == '/' or cp < 0x20 or (cp >= 0x7F and cp <= 0x9F);
}

/// Drive directory name (2.2.3.1): DeviceData, else PreferredDosName without ':';
/// '/' and control characters become '_'.
pub fn driveName(out: []u8, d: DeviceAnnounce) Error![]const u8 {
    const data = d.device_data;
    var n: usize = 0;
    const terminated = data.len >= 2 and data[data.len - 2] == 0 and data[data.len - 1] == 0;
    // The macOS app sends UTF-16LE without a terminator; FreeRDP sends ASCII,
    // whose second byte is zero only in a one-letter name.
    const unterminated = data.len >= 4 and data[0] != 0 and data[1] == 0;
    if (data.len % 2 == 0 and (terminated or unterminated)) {
        var it: Utf16Iterator = .{ .s = data };
        while (try it.next()) |cp| {
            if (cp == 0) break;
            n += try putUtf8(out[n..], if (unsafeNameChar(cp)) '_' else cp);
        }
    } else {
        var name = if (data.len > 0) data else d.dosName();
        if (std.mem.indexOfScalar(u8, name, 0)) |end| name = name[0..end];
        if (data.len == 0 and name.len > 0 and name[name.len - 1] == ':') name = name[0 .. name.len - 1];
        if (out.len < name.len) return error.NoSpaceLeft;
        for (name, out[0..name.len]) |c, *o| o.* = if (unsafeNameChar(c) or c >= 0x80) '_' else c;
        n = name.len;
    }
    const name = out[0..n];
    if (!isPathComponent(name)) return error.InvalidName;
    return name;
}

/// Drive-relative path to a DR_CREATE_REQ Path ("\dir\file.txt", NUL-terminated;
/// the root is empty, 4.12). Rejects "..", MS-FSCC 2.1.5 characters, bad UTF-8.
pub fn rdpPathFromLinux(out: []u8, rel_path: []const u8) Error![]const u8 {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, rel_path, '/');
    while (it.next()) |comp| {
        if (comp.len == 0 or std.mem.eql(u8, comp, ".")) continue;
        if (std.mem.eql(u8, comp, "..")) return error.InvalidName;
        for (comp) |c| {
            if (c < 0x20 or std.mem.indexOfScalar(u8, "\"*:<>?\\|", c) != null) return error.InvalidName;
        }
        n += try putUtf16(out[n..], '\\');
        var i: usize = 0;
        while (i < comp.len) n += try putUtf16(out[n..], try nextUtf8(comp, &i));
    }
    if (n == 0) return out[0..0];
    n += try putUtf16(out[n..], 0);
    return out[0..n];
}

/// Query directory Path for listing a directory: "\dir\*" (root "\*", 4.30), NUL-terminated.
pub fn directoryPattern(out: []u8, rel_dir: []const u8) Error![]const u8 {
    const dir = try rdpPathFromLinux(out, rel_dir);
    var n = if (dir.len == 0) 0 else dir.len - 2; // without its terminator
    n += try putUtf16(out[n..], '\\');
    n += try putUtf16(out[n..], '*');
    n += try putUtf16(out[n..], 0);
    return out[0..n];
}

/// UTF-16LE RDP path to a relative Linux path; '/' in names and ".." are InvalidName.
pub fn linuxPathFromRdp(out: []u8, rdp_path: []const u8) Error![]const u8 {
    const s = try utf16leToUtf8(out, rdp_path);
    // In place: components only move left, so each is read before it is overwritten.
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, s, '\\');
    while (it.next()) |comp| {
        if (comp.len == 0 or std.mem.eql(u8, comp, ".")) continue;
        if (std.mem.eql(u8, comp, "..") or std.mem.indexOfScalar(u8, comp, '/') != null) return error.InvalidName;
        if (n > 0) {
            out[n] = '/';
            n += 1;
        }
        std.mem.copyForwards(u8, out[n..], comp);
        n += comp.len;
    }
    return out[0..n];
}

/// What a Linux open asks for (from FUSE flags).
pub const OpenIntent = struct {
    access: enum { read, write, read_write } = .read,
    create: bool = false,
    exclusive: bool = false,
    truncate: bool = false,
    directory: bool = false,
    sync: bool = false,
};

pub const CreateParams = struct {
    desired_access: u32,
    shared_access: u32,
    create_disposition: u32,
    create_options: u32,
};

/// DR_CREATE_REQ fields for a Linux open, mapped as the Linux SMB client does;
/// POSIX has no share modes, so all sharing is allowed.
pub fn createParams(intent: OpenIntent) Error!CreateParams {
    const access: u32 = switch (intent.access) {
        .read => generic_read,
        .write => generic_write,
        .read_write => generic_read | generic_write,
    };
    const disposition: u32 = if (intent.create)
        (if (intent.exclusive) file_create else if (intent.truncate) file_overwrite_if else file_open_if)
    else if (intent.truncate) file_overwrite else file_open;
    var options: u32 = if (intent.directory) file_directory_file else file_non_directory_file;
    if (intent.sync) options |= file_write_through;
    return .{
        .desired_access = access,
        .shared_access = file_share_read | file_share_write | file_share_delete,
        .create_disposition = disposition,
        .create_options = options,
    };
}

/// Linux errno (positive) for a client NTSTATUS, following the Linux SMB
/// client's table; unlisted errors and warnings give EIO, NT_SUCCESS gives 0.
pub fn errnoFromStatus(s: u32) Error!u16 {
    const E = std.os.linux.E;
    const e: E = switch (s) {
        status.no_such_file,
        status.object_name_not_found,
        status.object_path_not_found,
        status.object_name_invalid,
        status.delete_pending,
        => .NOENT,
        status.access_denied, status.file_lock_conflict => .ACCES,
        status.object_name_collision => .EXIST,
        status.directory_not_empty => .NOTEMPTY,
        status.not_a_directory => .NOTDIR,
        status.file_is_a_directory => .ISDIR,
        status.disk_full => .NOSPC,
        status.not_supported, status.not_implemented => .OPNOTSUPP,
        status.invalid_handle => .BADF,
        status.invalid_parameter => .INVAL,
        status.sharing_violation => .BUSY,
        status.media_write_protected => .ROFS,
        status.lock_not_granted => .NOLCK,
        status.no_such_device => .NODEV,
        status.no_more_files => .NODATA,
        // NT_SUCCESS: severity success or informational.
        else => if (s >> 31 == 0) return 0 else .IO,
    };
    return @intCast(@backingInt(e));
}

/// FILETIME of the Unix epoch: 100 ns intervals from 1601-01-01 to 1970-01-01.
const filetime_unix_epoch: i128 = 116444736000000000;

/// FILETIME ([MS-DTYP] 2.3.3) to nanoseconds since the Unix epoch.
pub fn fileTimeToUnixNs(ft: u64) Error!i128 {
    return (@as(i128, ft) - filetime_unix_epoch) * 100;
}

/// Unix nanoseconds to FILETIME (truncated); out of range is error.InvalidField.
pub fn unixNsToFileTime(ns: i128) Error!u64 {
    const since_1601 = std.math.add(i128, ns, filetime_unix_epoch * 100) catch return error.InvalidField;
    if (since_1601 < 0) return error.InvalidField;
    return std.math.cast(u64, @divFloor(since_1601, 100)) orelse error.InvalidField;
}

pub fn modeFromAttributes(attributes: u32) Error!u32 {
    const S = std.posix.S;
    var mode: u32 = if (attributes & file_attribute_directory != 0) S.IFDIR | 0o755 else S.IFREG | 0o644;
    if (attributes & file_attribute_readonly != 0) mode &= ~@as(u32, 0o222);
    return mode;
}

// --- Server state machine ---

/// The capability request has a version 2 general set (4.8) and one set per enabled device type.
pub const Config = struct {
    /// Windows Server 2016+ send 13 (<8>).
    version_minor: u16 = version_minor_rdp10,
    /// ClientId of the Server Announce Request: unique per connection (3.3.5.1.2).
    client_id: u32,
    os_type: u32 = 0,
    special_type_device_cap: u32 = 0,
    /// Device types announced and accepted; others get STATUS_NOT_SUPPORTED.
    filesystem: bool = true,
    printer: bool = false,
    port: bool = false,
    smartcard: bool = false,
    /// The user is already logged on (NLA) when rdpdr starts.
    user_logged_on: bool = true,
    max_outstanding: u32 = 1024,
};

pub const State = enum {
    idle,
    /// Waiting for the Client Announce Reply.
    announce_sent,
    /// Waiting for the Client Name Request.
    reply_received,
    /// Waiting for the Client Core Capability Response.
    capabilities_sent,
    ready,
};

pub const Device = struct {
    id: u32,
    device_type: DeviceType,
    preferred_dos_name: [8]u8,
    /// Accepted (STATUS_SUCCESS was sent) and not removed.
    accepted: bool,
    /// Linux directory name (`driveName`, made unique); valid for drives.
    name_buf: [256]u8 = undefined,
    name_len: usize = 0,

    pub fn name(d: *const Device) []const u8 {
        return d.name_buf[0..d.name_len];
    }
};

pub const Request = struct {
    device_id: u32,
    file_id: u32,
    completion_id: u32,
    major: MajorFunction,
    minor: MinorFunction,
    /// Information class of query/set/directory requests; selects the response decoder.
    information_class: u32 = 0,
    /// Caller's cookie (e.g. the FUSE request).
    tag: u64 = 0,
};

pub const Event = union(enum) {
    client_name,
    capabilities,
    /// Accepted: mount it.
    device_added: u32,
    device_refused: DeviceAnnounceResponse,
    /// Removed by the client: unmount it.
    device_removed: u32,
    io_completed: struct { request: Request, io_status: u32, response: IoResponse },
    /// Will never complete (file closed, device removed, reset): report STATUS_CANCELLED.
    io_cancelled: Request,
};

/// PDUs to send, each one complete static channel message.
pub const Outbox = struct {
    gpa: std.mem.Allocator,
    messages: std.ArrayList([]u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) Outbox {
        return .{ .gpa = gpa };
    }

    pub fn deinit(o: *Outbox) void {
        o.clear();
        o.messages.deinit(o.gpa);
    }

    pub fn items(o: *const Outbox) []const []u8 {
        return o.messages.items;
    }

    pub fn clear(o: *Outbox) void {
        for (o.messages.items) |m| o.gpa.free(m);
        o.messages.clearRetainingCapacity();
    }
};

/// A device the client announced (accepted or refused) and has not removed.
const DeviceSlot = struct {
    dev: Device,
    /// Owned; an identical re-announce is answered again (3.3.5.2.1).
    data: []u8,
    /// ResultCode of its Server Device Announce Response.
    result: u32,
};

/// A FileId from a successful create until its Close Response (3.1.5).
const OpenFile = struct {
    device_id: u32,
    file_id: u32,
    reads: u32 = 0,
    writes: u32 = 0,
};

const Pending = struct {
    request: Request,
    /// DR_READ_REQ.Length: a read response carries at most that much (2.2.3.4.3).
    read_length: u32 = 0,
};

/// Linux NAME_MAX: the longest drive directory name.
const max_drive_name_len = 255;

pub const Session = struct {
    gpa: std.mem.Allocator,
    config: Config,
    st: State = .idle,
    version: ?VersionInfo = null,
    /// Client computer name, UTF-8 (owned).
    name: ?[]u8 = null,
    caps: ?Capabilities = null,
    devices: std.ArrayList(*DeviceSlot) = .empty,
    files: std.ArrayList(OpenFile) = .empty,
    /// Outstanding requests by CompletionId (unique among them, 2.2.1.4).
    pending: std.AutoArrayHashMapUnmanaged(u32, Pending) = .empty,
    /// Cancelled requests the client may still answer (CompletionId -> DeviceId); Windows
    /// clients answer a Close before the reads and writes in flight on that file.
    cancelled: std.AutoArrayHashMapUnmanaged(u32, u32) = .empty,
    events: std.ArrayList(Event) = .empty,
    next_completion_id: u32 = 1,

    pub fn init(gpa: std.mem.Allocator, config: Config) Error!Session {
        return .{ .gpa = gpa, .config = config };
    }

    pub fn deinit(s: *Session) void {
        s.forget();
        s.devices.deinit(s.gpa);
        s.files.deinit(s.gpa);
        s.pending.deinit(s.gpa);
        s.cancelled.deinit(s.gpa);
        s.events.deinit(s.gpa);
    }

    /// Drops all channel state, keeping table allocations.
    fn forget(s: *Session) void {
        for (s.devices.items) |slot| s.freeSlot(slot);
        s.devices.clearRetainingCapacity();
        s.files.clearRetainingCapacity();
        s.pending.clearRetainingCapacity();
        s.cancelled.clearRetainingCapacity();
        if (s.name) |n| s.gpa.free(n);
        s.name = null;
        s.version = null;
        s.caps = null;
    }

    fn freeSlot(s: *Session, slot: *DeviceSlot) void {
        s.gpa.free(slot.data);
        s.gpa.destroy(slot);
    }

    /// 3.1.3 step 1: queue the Server Announce Request. Once, in `idle`.
    pub fn start(s: *Session, out: *Outbox) Error!void {
        if (s.st != .idle) return error.OutOfSequence;
        try queue(out, encodeServerAnnounce, .{VersionInfo{ .minor = s.config.version_minor, .client_id = s.config.client_id }});
        s.st = .announce_sent;
    }

    /// Events are valid until the next call and point into `msg`. Any error means
    /// the channel must be torn down (3.1.5.2).
    pub fn receive(s: *Session, msg: []const u8, out: *Outbox) Error![]const Event {
        s.events.clearRetainingCapacity();
        const pdu = try decodeClientPdu(msg);
        if (s.st == .idle) return error.OutOfSequence;
        switch (pdu) {
            .announce_reply => |v| try s.onAnnounceReply(v),
            .client_name => |n| try s.onClientName(n, out),
            .capabilities => |c| try s.onCapabilities(c, out),
            .device_list_announce => |l| try s.onDeviceListAnnounce(l, out),
            .device_list_remove => |r| try s.onDeviceListRemove(r),
            .io_completion => |c| try s.onIoCompletion(c),
            .printer => {},
        }
        return s.events.items;
    }

    /// 3.3.5.1.3: stored; the ClientId goes back in the Client ID Confirm.
    fn onAnnounceReply(s: *Session, v: VersionInfo) Error!void {
        if (s.st != .announce_sent) return error.OutOfSequence;
        s.version = v;
        s.st = .reply_received;
    }

    /// 3.1.3 step 3, 3.3.5.1.6, 3.3.5.1.7.
    fn onClientName(s: *Session, n: ClientName, out: *Outbox) Error!void {
        if (s.st != .reply_received) return error.OutOfSequence;
        s.name = try clientNameAlloc(s.gpa, n);
        const v = s.version.?;
        // 3.1.5.2: no capability exchange with a newer major, or minor below 5.
        const exchange = !(v.major > version_major or (v.major == version_major and v.minor < version_minor_rdp51));
        if (exchange) try queue(out, encodeCapabilityRequest, .{s.serverCapabilities()});
        try queue(out, encodeClientIdConfirm, .{VersionInfo{ .minor = s.config.version_minor, .client_id = v.client_id }});
        s.st = if (exchange) .capabilities_sent else .ready;
        try s.events.append(s.gpa, .client_name);
    }

    fn serverCapabilities(s: *const Session) Capabilities {
        const c = s.config;
        return .{
            .general = .{
                .version = general_capability_version_02,
                .os_type = c.os_type,
                .os_version = 0,
                .protocol_major_version = version_major,
                .protocol_minor_version = c.version_minor,
                .io_code1 = 0x0000FFFF,
                .io_code2 = 0,
                .extended_pdu = rdpdr_device_remove_pdus | rdpdr_client_display_name_pdu | rdpdr_user_loggedon_pdu,
                .extra_flags1 = 0,
                .extra_flags2 = 0,
                .special_type_device_cap = c.special_type_device_cap,
            },
            .printer = if (c.printer) print_capability_version_01 else null,
            .port = if (c.port) port_capability_version_01 else null,
            .drive = if (c.filesystem) drive_capability_version_02 else null,
            .smartcard = if (c.smartcard) smartcard_capability_version_01 else null,
        };
    }

    /// 3.3.5.1.8, then Server User Logged On if the client asks (3.3.5.1.5).
    fn onCapabilities(s: *Session, c: Capabilities, out: *Outbox) Error!void {
        if (s.st != .capabilities_sent) return error.OutOfSequence;
        s.caps = c;
        s.st = .ready;
        try s.events.append(s.gpa, .capabilities);
        const wants_logon = if (c.general) |g| g.extended_pdu & rdpdr_user_loggedon_pdu != 0 else false;
        if (s.config.user_logged_on and wants_logon) try queue(out, encodeUserLoggedOn, .{});
    }

    /// 3.3.5.1.9; devices may be announced any time after the Client Name
    /// Request (3.2.5.1.9).
    fn onDeviceListAnnounce(s: *Session, l: DeviceList, out: *Outbox) Error!void {
        if (s.st != .capabilities_sent and s.st != .ready) return error.OutOfSequence;
        var it = l.iterator();
        while (it.next()) |d| try s.announce(d, out);
    }

    fn announce(s: *Session, d: DeviceAnnounce, out: *Outbox) Error!void {
        if (s.findSlot(d.device_id)) |slot| {
            const same = slot.dev.device_type == d.device_type and
                std.mem.eql(u8, &slot.dev.preferred_dos_name, &d.preferred_dos_name) and
                std.mem.eql(u8, slot.data, d.device_data);
            if (!same) return error.DuplicateDeviceId;
            return queue(out, encodeDeviceAnnounceResponse, .{DeviceAnnounceResponse{ .device_id = d.device_id, .result_code = slot.result }});
        }
        const slot = try s.addSlot(d);
        const r: DeviceAnnounceResponse = .{ .device_id = d.device_id, .result_code = slot.result };
        try queue(out, encodeDeviceAnnounceResponse, .{r});
        try s.events.append(s.gpa, if (slot.dev.accepted) .{ .device_added = d.device_id } else .{ .device_refused = r });
    }

    fn addSlot(s: *Session, d: DeviceAnnounce) Error!*DeviceSlot {
        const data = try s.gpa.dupe(u8, d.device_data);
        errdefer s.gpa.free(data);
        const slot = try s.gpa.create(DeviceSlot);
        errdefer s.gpa.destroy(slot);
        slot.* = .{
            .dev = .{ .id = d.device_id, .device_type = d.device_type, .preferred_dos_name = d.preferred_dos_name, .accepted = false },
            .data = data,
            .result = status.success,
        };
        slot.result = s.admit(d, &slot.dev);
        slot.dev.accepted = slot.result == status.success;
        try s.devices.append(s.gpa, slot);
        return slot;
    }

    /// The ResultCode for a newly announced device; names accepted drives.
    fn admit(s: *const Session, d: DeviceAnnounce, dev: *Device) u32 {
        const supported = switch (d.device_type) {
            .filesystem => s.config.filesystem,
            .print => s.config.printer,
            .serial, .parallel => s.config.port,
            .smartcard => s.config.smartcard,
            _ => false,
        };
        if (!supported) return status.not_supported;
        // 2.2.3.1: a DeviceData name overrides PreferredDosName; otherwise an
        // invalid name gets STATUS_ACCESS_DENIED (2.2.1.3).
        const named_by_data = d.device_type == .filesystem and d.device_data.len > 0;
        if (!named_by_data and !(validDosName(d.preferred_dos_name) catch false)) return status.access_denied;
        if (d.device_type == .filesystem) s.nameDrive(d, dev) catch return status.access_denied;
        return status.success;
    }

    /// `driveName` cut to NAME_MAX, with "_<DeviceId>" (then "_<n>") appended
    /// when an accepted drive already has that name.
    fn nameDrive(s: *const Session, d: DeviceAnnounce, dev: *Device) Error!void {
        var full: [4 * max_drive_name_len]u8 = undefined;
        const name = try driveName(&full, d);
        var attempt: u32 = 0;
        while (attempt < 100) : (attempt += 1) {
            var suffix_buf: [24]u8 = undefined;
            const suffix = switch (attempt) {
                0 => "",
                1 => std.fmt.bufPrint(&suffix_buf, "_{d}", .{d.device_id}) catch unreachable,
                else => std.fmt.bufPrint(&suffix_buf, "_{d}_{d}", .{ d.device_id, attempt }) catch unreachable,
            };
            const base = utf8Prefix(name, max_drive_name_len - suffix.len);
            @memcpy(dev.name_buf[0..base.len], base);
            @memcpy(dev.name_buf[base.len..][0..suffix.len], suffix);
            dev.name_len = base.len + suffix.len;
            if (!s.driveNameTaken(dev.name())) return;
        }
        return error.InvalidName;
    }

    fn driveNameTaken(s: *const Session, name: []const u8) bool {
        for (s.devices.items) |slot| {
            if (slot.dev.accepted and slot.dev.device_type == .filesystem and std.mem.eql(u8, slot.dev.name(), name)) return true;
        }
        return false;
    }

    /// 3.3.5.2.2: unknown DeviceIds are ignored; a removed drive's requests
    /// are cancelled and its FileIds end (3.1.5).
    fn onDeviceListRemove(s: *Session, r: DeviceListRemove) Error!void {
        if (s.st != .capabilities_sent and s.st != .ready) return error.OutOfSequence;
        var i: u32 = 0;
        while (i < r.count) : (i += 1) {
            const id = r.get(i);
            const index = s.slotIndex(id) orelse continue;
            const slot = s.devices.orderedRemove(index);
            const accepted = slot.dev.accepted;
            s.freeSlot(slot);
            if (!accepted) continue;
            try s.cancel(id, null);
            var f: usize = 0;
            while (f < s.files.items.len) {
                if (s.files.items[f].device_id == id) _ = s.files.swapRemove(f) else f += 1;
            }
            try s.events.append(s.gpa, .{ .device_removed = id });
        }
    }

    /// Cancels the requests of a device, or of one of its files when `file_id` is set.
    fn cancel(s: *Session, device_id: u32, file_id: ?u32) Error!void {
        var i: usize = 0;
        while (i < s.pending.count()) {
            const req = s.pending.values()[i].request;
            const hit = req.device_id == device_id and
                (file_id == null or (req.major != .create and req.file_id == file_id.?));
            if (!hit) {
                i += 1;
                continue;
            }
            s.pending.swapRemoveAt(i);
            s.release(req);
            if (s.cancelled.count() >= s.config.max_outstanding) s.cancelled.orderedRemoveAt(0);
            try s.cancelled.put(s.gpa, req.completion_id, req.device_id);
            try s.events.append(s.gpa, .{ .io_cancelled = req });
        }
    }

    /// 3.1.5.1: matched by CompletionId and DeviceId; 3.1.5.2: anything else terminates.
    fn onIoCompletion(s: *Session, c: IoCompletion) Error!void {
        // The late response of a request cancelled here (`cancelled`).
        if (s.cancelled.get(c.completion_id)) |dev| if (dev == c.device_id) {
            _ = s.cancelled.orderedRemove(c.completion_id);
            return;
        };
        if (s.findSlot(c.device_id) == null) return error.UnknownDevice;
        const p = s.pending.get(c.completion_id) orelse return error.UnknownCompletionId;
        if (p.request.device_id != c.device_id) return error.UnknownCompletionId;
        const req = p.request;
        const rsp = try decodeIoResponse(req.major, req.minor, c);
        if (rsp == .read and rsp.read.len > p.read_length) return error.InvalidField;
        _ = s.pending.swapRemove(c.completion_id);
        s.release(req);
        switch (req.major) {
            // NT_SUCCESS: the FileId is valid (3.1.5).
            .create => if (c.io_status >> 31 == 0) try s.openFile(req.device_id, rsp.create.file_id),
            .close => {
                // 3.1.1: the FileId ends with the Close Response.
                for (s.files.items, 0..) |f, i| {
                    if (f.device_id == req.device_id and f.file_id == req.file_id) {
                        _ = s.files.swapRemove(i);
                        break;
                    }
                }
            },
            else => {},
        }
        try s.events.append(s.gpa, .{ .io_completed = .{ .request = req, .io_status = c.io_status, .response = rsp } });
        // 3.3.5.2.6: pending I/O on the closed FileId MUST be cancelled.
        if (req.major == .close) try s.cancel(req.device_id, req.file_id);
    }

    fn openFile(s: *Session, device_id: u32, file_id: u32) Error!void {
        if (s.findFile(device_id, file_id) != null) return;
        try s.files.append(s.gpa, .{ .device_id = device_id, .file_id = file_id });
    }

    /// A read or write left the wire: the next one may go (3.3.5.2.8).
    fn release(s: *Session, req: Request) void {
        const f = s.findFile(req.device_id, req.file_id) orelse return;
        switch (req.major) {
            .read => f.reads -|= 1,
            .write => f.writes -|= 1,
            else => {},
        }
    }

    /// Queues a Device I/O Request and returns its CompletionId. Errors refuse
    /// this request only; the session stays usable.
    pub fn submit(s: *Session, req: IoRequest, tag: u64, out: *Outbox) Error!u32 {
        if (s.st != .ready) return error.NotReady;
        const slot = s.findSlot(req.device_id) orelse return error.InvalidDevice;
        if (!slot.dev.accepted) return error.InvalidDevice;
        const information_class: u32 = switch (req.body) {
            .query_information, .set_information => |f| @backingInt(f.file_information_class),
            .query_volume_information, .set_volume_information => |v| @backingInt(v.fs_information_class),
            .query_directory => |q| @backingInt(q.file_information_class),
            else => 0,
        };
        switch (req.body) {
            // 2.2.3.3: "a device that has been announced as a file system device".
            .query_information, .set_information, .query_volume_information, .set_volume_information, .query_directory, .notify_change_directory, .lock_control => {
                if (slot.dev.device_type != .filesystem) return error.InvalidDevice;
            },
            else => {},
        }
        const file: ?*OpenFile = if (req.body == .create) null else s.findFile(req.device_id, req.file_id) orelse return error.InvalidFileId;
        if (s.pending.count() >= s.config.max_outstanding) return error.TooManyRequests;
        // 3.3.5.2.8, 3.3.5.2.9: without ENABLE_ASYNCIO, one read and one write per file.
        if (!s.asyncIo()) switch (req.body) {
            .read => if (file.?.reads > 0) return error.WouldBlock,
            .write => if (file.?.writes > 0) return error.WouldBlock,
            else => {},
        };
        if (req.body == .write and req.body.write.offset == write_append_offset) {
            const minor = if (s.version) |v| v.minor else 0;
            if (minor < version_minor_rdp10) return error.InvalidField;
        }

        const cid = s.newCompletionId();
        var sent = req;
        sent.completion_id = cid;
        try s.pending.ensureUnusedCapacity(s.gpa, 1);
        try queue(out, encodeIoRequest, .{sent});
        s.pending.putAssumeCapacity(cid, .{
            .request = .{
                .device_id = req.device_id,
                .file_id = req.file_id,
                .completion_id = cid,
                .major = req.majorFunction(),
                .minor = req.minorFunction(),
                .information_class = information_class,
                .tag = tag,
            },
            .read_length = if (req.body == .read) req.body.read.length else 0,
        });
        switch (req.body) {
            .read => file.?.reads += 1,
            .write => file.?.writes += 1,
            else => {},
        }
        return cid;
    }

    /// Both tables hold at most `max_outstanding` < 2^31 ids, so one is always free.
    fn newCompletionId(s: *Session) u32 {
        while (true) {
            const id = s.next_completion_id;
            s.next_completion_id +%= 1;
            if (!s.pending.contains(id) and !s.cancelled.contains(id)) return id;
        }
    }

    /// Transport lost (3.1.5.1): cancels all requests, drops devices, returns to `idle`.
    pub fn reset(s: *Session) Error![]const Event {
        s.events.clearRetainingCapacity();
        const room = s.events.ensureTotalCapacity(s.gpa, s.pending.count());
        if (room) |_| {
            for (s.pending.values()) |p| s.events.appendAssumeCapacity(.{ .io_cancelled = p.request });
        } else |_| {}
        s.forget();
        s.st = .idle;
        try room;
        return s.events.items;
    }

    pub fn state(s: *const Session) State {
        return s.st;
    }

    /// UTF-8.
    pub fn clientName(s: *const Session) ?[]const u8 {
        return s.name;
    }

    pub fn clientVersion(s: *const Session) ?VersionInfo {
        return s.version;
    }

    pub fn clientCapabilities(s: *const Session) ?Capabilities {
        return s.caps;
    }

    pub fn device(s: *const Session, id: u32) ?*const Device {
        const slot = s.findSlot(id) orelse return null;
        return &slot.dev;
    }

    /// Number of accepted, not removed devices.
    pub fn deviceCount(s: *const Session) usize {
        var n: usize = 0;
        for (s.devices.items) |slot| n += @intFromBool(slot.dev.accepted);
        return n;
    }

    pub fn outstanding(s: *const Session) usize {
        return s.pending.count();
    }

    pub fn asyncIo(s: *const Session) bool {
        const caps = s.caps orelse return false;
        const g = caps.general orelse return false;
        return g.extra_flags1 & enable_asyncio != 0;
    }

    pub fn isOpen(s: *const Session, device_id: u32, file_id: u32) bool {
        return s.findFile(device_id, file_id) != null;
    }

    fn slotIndex(s: *const Session, id: u32) ?usize {
        for (s.devices.items, 0..) |slot, i| {
            if (slot.dev.id == id) return i;
        }
        return null;
    }

    fn findSlot(s: *const Session, id: u32) ?*DeviceSlot {
        return s.devices.items[s.slotIndex(id) orelse return null];
    }

    fn findFile(s: *const Session, device_id: u32, file_id: u32) ?*OpenFile {
        for (s.files.items) |*f| {
            if (f.device_id == device_id and f.file_id == file_id) return f;
        }
        return null;
    }
};

/// Encodes one PDU with `encode(&writer, args...)` and queues it.
fn queue(out: *Outbox, comptime encode: anytype, args: anytype) Error!void {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(out.gpa);
    var w = bytes.Writer.init(&list, out.gpa);
    try @call(.auto, encode, .{&w} ++ args);
    const msg = try list.toOwnedSlice(out.gpa);
    errdefer out.gpa.free(msg);
    try out.messages.append(out.gpa, msg);
}

/// ComputerName is display only (3.1.1), so an unpaired surrogate becomes U+FFFD
/// instead of failing the channel.
fn clientNameAlloc(gpa: std.mem.Allocator, n: ClientName) Error![]u8 {
    // At most 3 UTF-8 bytes per UTF-16 code unit, 2 per code page byte.
    const buf = try gpa.alloc(u8, if (n.unicode) n.name.len / 2 * 3 else n.name.len * 2);
    defer gpa.free(buf);
    const name = clientNameUtf8(buf, n) catch |e| switch (e) {
        error.InvalidName => lossyUtf16ToUtf8(buf, n.name),
        else => return e,
    };
    return gpa.dupe(u8, name);
}

/// `out` holds 3 bytes per code unit.
fn lossyUtf16ToUtf8(out: []u8, utf16le: []const u8) []const u8 {
    var it: Utf16Iterator = .{ .s = utf16le[0 .. utf16le.len & ~@as(usize, 1)] };
    var n: usize = 0;
    while ((it.next() catch std.unicode.replacement_character)) |cp| {
        if (cp == 0) break;
        n += putUtf8(out[n..], cp) catch break;
    }
    return out[0..n];
}

/// Longest prefix of at most `max` bytes ending on a character boundary.
fn utf8Prefix(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    var n = max;
    while (n > 0 and s[n] & 0xC0 == 0x80) n -= 1;
    return s[0..n];
}

test {
    refAll(@This());
}

fn refAll(comptime T: type) void {
    inline for (comptime std.meta.declarations(T)) |d| {
        const f = @field(T, d);
        if (@TypeOf(f) == type) {
            switch (@typeInfo(f)) {
                .@"struct", .@"union", .@"enum" => refAll(f),
                else => {},
            }
        } else {
            _ = &@field(T, d);
        }
    }
}

fn testMessage(comptime encode: anytype, args: anytype) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try @call(.auto, encode, .{&w} ++ args);
    return list.toOwnedSlice(std.testing.allocator);
}

fn testFeed(s: *Session, out: *Outbox, msg: []u8) ![]const Event {
    defer std.testing.allocator.free(msg);
    return s.receive(msg, out);
}

fn testReady(s: *Session, out: *Outbox) !void {
    try s.start(out);
    _ = try testFeed(s, out, try testMessage(encodeClientAnnounceReply, .{VersionInfo{ .minor = version_minor_rdp10, .client_id = s.config.client_id }}));
    _ = try testFeed(s, out, try testMessage(encodeClientName, .{ true, "unit" }));
    _ = try testFeed(s, out, try testMessage(encodeCapabilityResponse, .{Capabilities{ .general = .{}, .drive = drive_capability_version_02 }}));
    try std.testing.expectEqual(State.ready, s.state());
}

test "drive names are cut to NAME_MAX on a character boundary" {
    const gpa = std.testing.allocator;
    var s = try Session.init(gpa, .{ .client_id = 1 });
    defer s.deinit();
    var out = Outbox.init(gpa);
    defer out.deinit();
    try testReady(&s, &out);
    // 200 x U+00E9 (2 UTF-8 bytes each) and the terminator: 400 bytes of name.
    var name: [2 * 201]u8 = undefined;
    for (0..200) |i| std.mem.writeInt(u16, name[2 * i ..][0..2], 0xE9, .little);
    name[400] = 0;
    name[401] = 0;
    const devs = [_]DeviceAnnounce{
        .{ .device_type = .filesystem, .device_id = 7, .preferred_dos_name = DeviceAnnounce.dos("E:"), .device_data = &name },
        .{ .device_type = .filesystem, .device_id = 8, .preferred_dos_name = DeviceAnnounce.dos("F:"), .device_data = &name },
    };
    const ev = try testFeed(&s, &out, try testMessage(encodeDeviceListAnnounce, .{&devs}));
    try std.testing.expectEqual(@as(usize, 2), ev.len);
    const a = s.device(7).?.name();
    try std.testing.expectEqual(@as(usize, 254), a.len); // 255 would split a character
    try std.testing.expect(std.unicode.utf8ValidateSlice(a));
    const b = s.device(8).?.name();
    try std.testing.expectEqual(@as(usize, 254), b.len); // 126 characters and "_8"
    try std.testing.expect(std.mem.endsWith(u8, b, "_8"));
    try std.testing.expect(std.unicode.utf8ValidateSlice(b));
}

test "a drive name taken by a suffixed name gets a second suffix" {
    const gpa = std.testing.allocator;
    var s = try Session.init(gpa, .{ .client_id = 1 });
    defer s.deinit();
    var out = Outbox.init(gpa);
    defer out.deinit();
    try testReady(&s, &out);
    const devs = [_]DeviceAnnounce{
        .{ .device_type = .filesystem, .device_id = 9, .preferred_dos_name = DeviceAnnounce.dos("home_4"), .device_data = "home_4\x00" },
        .{ .device_type = .filesystem, .device_id = 3, .preferred_dos_name = DeviceAnnounce.dos("home"), .device_data = "home\x00" },
        .{ .device_type = .filesystem, .device_id = 4, .preferred_dos_name = DeviceAnnounce.dos("home"), .device_data = "home\x00" },
    };
    _ = try testFeed(&s, &out, try testMessage(encodeDeviceListAnnounce, .{&devs}));
    try std.testing.expectEqualStrings("home_4", s.device(9).?.name());
    try std.testing.expectEqualStrings("home", s.device(3).?.name());
    try std.testing.expectEqualStrings("home_4_2", s.device(4).?.name());
}

test "an unpaired surrogate in the client name becomes U+FFFD" {
    const gpa = std.testing.allocator;
    var s = try Session.init(gpa, .{ .client_id = 1 });
    defer s.deinit();
    var out = Outbox.init(gpa);
    defer out.deinit();
    try s.start(&out);
    _ = try testFeed(&s, &out, try testMessage(encodeClientAnnounceReply, .{VersionInfo{ .minor = version_minor_rdp10, .client_id = 1 }}));
    const name = [_]u8{ 0x72, 0x44, 0x4e, 0x43, 1, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 'A', 0, 0x00, 0xd8, 'B', 0, 0, 0 };
    _ = try s.receive(&name, &out);
    try std.testing.expectEqualStrings("A\u{FFFD}B", s.clientName().?);
}

test "an unterminated Client Name Request proceeds to the capability exchange" {
    const gpa = std.testing.allocator;
    var s = try Session.init(gpa, .{ .client_id = 1 });
    defer s.deinit();
    var out = Outbox.init(gpa);
    defer out.deinit();
    try s.start(&out);
    out.clear();
    _ = try testFeed(&s, &out, try testMessage(encodeClientAnnounceReply, .{VersionInfo{ .minor = version_minor_rdp10, .client_id = 1 }}));
    // UnicodeFlag 1, CodePage 0, ComputerNameLen 22: "MacBook-Air" without its NUL.
    const name = [_]u8{
        0x72, 0x44, 0x4e, 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00,
        'M',  0,    'a',  0,    'c',  0,    'B',  0,    'o',  0,    'o',  0,    'k',  0,    '-',  0,
        'A',  0,    'i',  0,    'r',  0,
    };
    const events = try s.receive(&name, &out);
    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(events[0] == .client_name);
    try std.testing.expectEqualStrings("MacBook-Air", s.clientName().?);
    try std.testing.expectEqual(State.capabilities_sent, s.state());
    try std.testing.expectEqual(@as(usize, 2), out.items().len);
    try std.testing.expectEqual(PacketId.core_server_capability, (try decodeHeader(out.items()[0])).packet_id);
    try std.testing.expectEqual(PacketId.core_clientid_confirm, (try decodeHeader(out.items()[1])).packet_id);
}
