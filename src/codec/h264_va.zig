//! libva H.264 encode structs whose C bitfield unions translate-c cannot emit, re-declared
//! with packed(u32) bitfields; sizes and offsets are asserted against libva 2.24.

const std = @import("std");
const c = @import("c");

pub const SeqFields = packed struct(u32) {
    chroma_format_idc: u2 = 1,
    frame_mbs_only_flag: u1 = 1,
    mb_adaptive_frame_field_flag: u1 = 0,
    seq_scaling_matrix_present_flag: u1 = 0,
    direct_8x8_inference_flag: u1 = 1,
    log2_max_frame_num_minus4: u4 = 0,
    pic_order_cnt_type: u2 = 0,
    log2_max_pic_order_cnt_lsb_minus4: u4 = 0,
    delta_pic_order_always_zero_flag: u1 = 0,
    _pad: u15 = 0,
};

pub const VuiFields = packed struct(u32) {
    aspect_ratio_info_present_flag: u1 = 0,
    timing_info_present_flag: u1 = 0,
    bitstream_restriction_flag: u1 = 0,
    log2_max_mv_length_horizontal: u5 = 0,
    log2_max_mv_length_vertical: u5 = 0,
    fixed_frame_rate_flag: u1 = 0,
    low_delay_hrd_flag: u1 = 0,
    motion_vectors_over_pic_boundaries_flag: u1 = 0,
    reserved: u16 = 0,
};

/// VAEncSequenceParameterBufferH264
pub const SeqParam = extern struct {
    seq_parameter_set_id: u8 = 0,
    level_idc: u8 = 0,
    intra_period: u32 = 0,
    intra_idr_period: u32 = 0,
    ip_period: u32 = 0,
    bits_per_second: u32 = 0,
    max_num_ref_frames: u32 = 0,
    picture_width_in_mbs: u16 = 0,
    picture_height_in_mbs: u16 = 0,
    seq_fields: SeqFields = .{},
    bit_depth_luma_minus8: u8 = 0,
    bit_depth_chroma_minus8: u8 = 0,
    num_ref_frames_in_pic_order_cnt_cycle: u8 = 0,
    offset_for_non_ref_pic: i32 = 0,
    offset_for_top_to_bottom_field: i32 = 0,
    offset_for_ref_frame: [256]i32 = @splat(0),
    frame_cropping_flag: u8 = 0,
    frame_crop_left_offset: u32 = 0,
    frame_crop_right_offset: u32 = 0,
    frame_crop_top_offset: u32 = 0,
    frame_crop_bottom_offset: u32 = 0,
    vui_parameters_present_flag: u8 = 0,
    vui_fields: VuiFields = .{},
    aspect_ratio_idc: u8 = 0,
    sar_width: u32 = 0,
    sar_height: u32 = 0,
    num_units_in_tick: u32 = 0,
    time_scale: u32 = 0,
    va_reserved: [4]u32 = @splat(0),
};

pub const PicFields = packed struct(u32) {
    idr_pic_flag: u1 = 0,
    reference_pic_flag: u2 = 0,
    entropy_coding_mode_flag: u1 = 0,
    weighted_pred_flag: u1 = 0,
    weighted_bipred_idc: u2 = 0,
    constrained_intra_pred_flag: u1 = 0,
    transform_8x8_mode_flag: u1 = 0,
    deblocking_filter_control_present_flag: u1 = 0,
    redundant_pic_cnt_present_flag: u1 = 0,
    pic_order_present_flag: u1 = 0,
    pic_scaling_matrix_present_flag: u1 = 0,
    _pad: u19 = 0,
};

/// VAEncPictureParameterBufferH264
pub const PicParam = extern struct {
    CurrPic: c.VAPictureH264 = invalid_picture,
    ReferenceFrames: [16]c.VAPictureH264 = @splat(invalid_picture),
    coded_buf: c.VABufferID = c.VA_INVALID_ID,
    pic_parameter_set_id: u8 = 0,
    seq_parameter_set_id: u8 = 0,
    last_picture: u8 = 0,
    frame_num: u16 = 0,
    pic_init_qp: u8 = 26,
    num_ref_idx_l0_active_minus1: u8 = 0,
    num_ref_idx_l1_active_minus1: u8 = 0,
    chroma_qp_index_offset: i8 = 0,
    second_chroma_qp_index_offset: i8 = 0,
    pic_fields: PicFields = .{},
    va_reserved: [4]u32 = @splat(0),
};

pub const invalid_picture: c.VAPictureH264 = .{
    .picture_id = c.VA_INVALID_SURFACE,
    .frame_idx = 0,
    .flags = c.VA_PICTURE_H264_INVALID,
    .TopFieldOrderCnt = 0,
    .BottomFieldOrderCnt = 0,
};

pub const RcFlags = packed struct(u32) {
    reset: u1 = 0,
    disable_frame_skip: u1 = 0,
    disable_bit_stuffing: u1 = 0,
    mb_rate_control: u4 = 0,
    temporal_id: u8 = 0,
    cfs_I_frames: u1 = 0,
    enable_parallel_brc: u1 = 0,
    enable_dynamic_scaling: u1 = 0,
    frame_tolerance_mode: u2 = 0,
    reserved: u12 = 0,
};

pub const RateControl = extern struct {
    bits_per_second: u32 = 0,
    target_percentage: u32 = 0,
    window_size: u32 = 0,
    initial_qp: u32 = 0,
    min_qp: u32 = 0,
    basic_unit_size: u32 = 0,
    rc_flags: RcFlags = .{},
    ICQ_quality_factor: u32 = 0,
    max_qp: u32 = 0,
    quality_factor: u32 = 0,
    target_frame_size: u32 = 0,
    va_reserved: [4]u32 = @splat(0),
};

/// VAEncMiscParameterFrameRate: framerate = num | den << 16 (den 0 => 1).
pub const FrameRate = extern struct {
    framerate: u32 = 0,
    framerate_flags: u32 = 0, // temporal_id:8, reserved:24
    va_reserved: [4]u32 = @splat(0),
};

/// VAEncMiscParameterBufferQualityLevel; 0 is Mesa's fastest preset (no pre-encode, no VBAQ).
pub const QualityLevel = extern struct {
    quality_level: u32 = 0,
    va_reserved: [4]u32 = @splat(0),
};

pub fn Misc(comptime T: type, comptime misc_type: c_int) type {
    return extern struct {
        type: u32 = @intCast(misc_type),
        data: T,
    };
}

comptime {
    const assert = std.debug.assert;
    assert(@sizeOf(SeqParam) == 1132);
    assert(@offsetOf(SeqParam, "intra_period") == 4);
    assert(@offsetOf(SeqParam, "picture_width_in_mbs") == 24);
    assert(@offsetOf(SeqParam, "seq_fields") == 28);
    assert(@offsetOf(SeqParam, "bit_depth_luma_minus8") == 32);
    assert(@offsetOf(SeqParam, "num_ref_frames_in_pic_order_cnt_cycle") == 34);
    assert(@offsetOf(SeqParam, "offset_for_non_ref_pic") == 36);
    assert(@offsetOf(SeqParam, "offset_for_ref_frame") == 44);
    assert(@offsetOf(SeqParam, "frame_cropping_flag") == 1068);
    assert(@offsetOf(SeqParam, "frame_crop_left_offset") == 1072);
    assert(@offsetOf(SeqParam, "vui_parameters_present_flag") == 1088);
    assert(@offsetOf(SeqParam, "vui_fields") == 1092);
    assert(@offsetOf(SeqParam, "aspect_ratio_idc") == 1096);
    assert(@offsetOf(SeqParam, "sar_width") == 1100);
    assert(@offsetOf(SeqParam, "time_scale") == 1112);
    assert(@offsetOf(SeqParam, "va_reserved") == 1116);

    assert(@sizeOf(c.VAPictureH264) == 36);
    assert(@sizeOf(PicParam) == 648);
    assert(@offsetOf(PicParam, "ReferenceFrames") == 36);
    assert(@offsetOf(PicParam, "coded_buf") == 612);
    assert(@offsetOf(PicParam, "pic_parameter_set_id") == 616);
    assert(@offsetOf(PicParam, "last_picture") == 618);
    assert(@offsetOf(PicParam, "frame_num") == 620);
    assert(@offsetOf(PicParam, "pic_init_qp") == 622);
    assert(@offsetOf(PicParam, "chroma_qp_index_offset") == 625);
    assert(@offsetOf(PicParam, "pic_fields") == 628);
    assert(@offsetOf(PicParam, "va_reserved") == 632);

    assert(@sizeOf(RateControl) == 60);
    assert(@offsetOf(RateControl, "rc_flags") == 24);
    assert(@offsetOf(RateControl, "ICQ_quality_factor") == 28);
    assert(@offsetOf(RateControl, "target_frame_size") == 40);
    assert(@sizeOf(FrameRate) == 24);
    assert(@sizeOf(QualityLevel) == 20);

    assert(@sizeOf(c.VAEncSliceParameterBufferH264) == 3140);
    assert(@sizeOf(c.VAEncMiscParameterHRD) == 24);
    assert(@sizeOf(c.VAProcPipelineParameterBuffer) == 224);
    assert(@sizeOf(c.VAEncPackedHeaderParameterBuffer) == 28);
    assert(@sizeOf(c.VACodedBufferSegment) == 48);
}
