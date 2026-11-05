//! A surface's H.264 encoder: VA-API on the GPU, else OpenH264 in software (`--h264-encoder`).
//! Both code a picture at the QP the caller sets; only VA-API codes AVC444, whose two views share
//! one stream with same-view references (vaapi_h264), so software AVC444 is refused and the
//! codec policy falls back to AVC420.

const std = @import("std");
const vaapi_h264 = @import("vaapi_h264.zig");
const openh264 = @import("openh264.zig");
const avc444 = @import("avc444.zig");

const log = std.log.scoped(.h264);

pub const Options = vaapi_h264.Options;
pub const FrameInfo = vaapi_h264.FrameInfo;
pub const Avc444Info = vaapi_h264.Avc444Info;

/// Which encoder codes H.264: auto (VA-API, else software), or only one of them.
pub const Backend = enum { auto, vaapi, software };

pub const Error = vaapi_h264.Error || openh264.Error;

/// Why VA-API has no encoder, for error.OpenDevice or error.VaInit, naming `device` (--gpu).
pub fn vaapiMissing(device: ?[:0]const u8, err: anyerror, buf: []u8) []const u8 {
    const init_failed = err == error.VaInit;
    const text = if (device) |d|
        std.fmt.bufPrint(buf, "{s} {s}", .{ if (init_failed) "VA-API does not initialize on" else "cannot open", d })
    else
        std.fmt.bufPrint(buf, "{s}", .{if (init_failed) "VA-API initializes on no render node" else "no render node opens"});
    return text catch @errorName(err);
}

/// Set once VA-API failed to open any device: later encoders go straight to software.
var vaapi_missing = std.atomic.Value(bool).init(false);

pub const Encoder = struct {
    /// Size, cropping and AVC444 as asked (the VA-API encoder's own `opts` also track its QP).
    opts: Options,
    /// What codes: the render node, or the software encoder.
    node: [:0]const u8,
    impl: union(enum) {
        vaapi: vaapi_h264.Encoder,
        software: openh264.Encoder,
    },

    pub fn init(gpa: std.mem.Allocator, opts: Options, backend: Backend) Error!Encoder {
        return switch (backend) {
            .vaapi => try initVaapi(gpa, opts),
            .software => try initSoftware(gpa, opts),
            .auto => initAuto(gpa, opts),
        };
    }

    fn initVaapi(gpa: std.mem.Allocator, opts: Options) Error!Encoder {
        const e = try vaapi_h264.Encoder.init(gpa, opts);
        return .{ .opts = opts, .node = e.node, .impl = .{ .vaapi = e } };
    }

    fn initSoftware(gpa: std.mem.Allocator, opts: Options) Error!Encoder {
        if (opts.avc444 != null) return error.Unsupported;
        const e = try openh264.Encoder.init(gpa, .{ .width = opts.width, .height = opts.height, .qp = opts.qp, .fps = opts.fps });
        return .{ .opts = opts, .node = "software (OpenH264)", .impl = .{ .software = e } };
    }

    /// VA-API; without a device that encodes, software. An error is VA-API's unless software
    /// only lacks AVC444 (then AVC420 can still go).
    fn initAuto(gpa: std.mem.Allocator, opts: Options) Error!Encoder {
        const va_err: Error = if (vaapi_missing.load(.monotonic)) error.OpenDevice else if (initVaapi(gpa, opts)) |e| return e else |err| err;
        switch (va_err) {
            error.OutOfMemory => return va_err,
            error.OpenDevice, error.VaInit => if (!vaapi_missing.swap(true, .monotonic)) {
                var buf: [96]u8 = undefined;
                log.info("no VA-API H.264 encoder ({s}): H.264 in software when OpenH264 is installed", .{vaapiMissing(opts.device, va_err, &buf)});
            },
            else => {},
        }
        if (initSoftware(gpa, opts)) |e| return e else |err| switch (err) {
            error.OutOfMemory => return err,
            error.Unsupported => if (opts.avc444 != null and openh264.library() != null) return err,
            else => {},
        }
        return va_err;
    }

    pub fn deinit(self: *Encoder) void {
        switch (self.impl) {
            inline else => |*e| e.deinit(),
        }
        self.* = undefined;
    }

    pub fn isSoftware(self: *const Encoder) bool {
        return self.impl == .software;
    }

    /// The VA-API encoder, whose input surfaces a GPU can write (GPU capture); null in software,
    /// which takes CPU pixels.
    pub fn vaapi(self: *Encoder) ?*vaapi_h264.Encoder {
        return switch (self.impl) {
            .vaapi => |*e| e,
            .software => null,
        };
    }

    pub fn vaapiConst(self: *const Encoder) ?*const vaapi_h264.Encoder {
        return switch (self.impl) {
            .vaapi => |*e| e,
            .software => null,
        };
    }

    /// Recreate for a new size (the next picture is an IDR).
    pub fn resize(self: *Encoder, new_width: u32, new_height: u32) Error!void {
        switch (self.impl) {
            inline else => |*e| try e.resize(new_width, new_height),
        }
        self.opts.width = new_width;
        self.opts.height = new_height;
    }

    /// QP of the next pictures (no IDR).
    pub fn setQp(self: *Encoder, qp: u8) void {
        switch (self.impl) {
            inline else => |*e| e.setQp(qp),
        }
    }

    /// One top-down BGRX frame to exactly one Annex-B access unit (AVC420).
    pub fn encode(self: *Encoder, pixels: []const u8, stride: usize, force_idr: bool, out: *std.ArrayList(u8)) Error!FrameInfo {
        switch (self.impl) {
            .vaapi => |*e| return e.encode(pixels, stride, force_idr, out),
            .software => |*e| {
                const f = try e.encode(pixels, stride, force_idr, out);
                return .{
                    .idr = f.idr,
                    .size = f.size,
                    .avg_qp = f.qp,
                    .frame_num = @truncate(e.frames),
                    .upload_ns = f.convert_ns,
                    .encode_ns = f.encode_ns,
                    .total_ns = f.convert_ns + f.encode_ns,
                };
            },
        }
    }

    /// The AVC444 views `lc` asks for (VA-API only; a software encoder is never AVC444).
    pub fn encode444(self: *Encoder, pixels: []const u8, stride: usize, force_idr: bool, lc: avc444.Lc, main_out: *std.ArrayList(u8), aux_out: *std.ArrayList(u8)) Error!Avc444Info {
        return switch (self.impl) {
            .vaapi => |*e| e.encode444(pixels, stride, force_idr, lc, main_out, aux_out),
            .software => error.Unsupported,
        };
    }
};

test "software AVC444 is refused, so the policy can fall back to AVC420" {
    try std.testing.expectError(error.Unsupported, Encoder.init(std.testing.allocator, .{ .width = 64, .height = 64, .avc444 = .v2 }, .software));
}

test "a software encoder through the common interface" {
    if (openh264.library() == null) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var e = try Encoder.init(gpa, .{ .width = 64, .height = 48, .qp = 30 }, .software);
    defer e.deinit();
    try std.testing.expect(e.isSoftware());
    const px = try gpa.alloc(u8, 64 * 48 * 4);
    defer gpa.free(px);
    @memset(px, 0x80);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const f = try e.encode(px, 64 * 4, false, &out);
    try std.testing.expect(f.idr);
    try std.testing.expectEqual(@as(u8, 30), f.avg_qp);
    try e.resize(96, 64);
    try std.testing.expectEqual(@as(u32, 96), e.opts.width);
    try std.testing.expectError(error.Unsupported, e.encode444(px, 64 * 4, false, .both, &out, &out));
}

test "VA-API's absence names the --gpu node" {
    var buf: [96]u8 = undefined;
    try std.testing.expectEqualStrings("cannot open /dev/dri/renderD129", vaapiMissing("/dev/dri/renderD129", error.OpenDevice, &buf));
    try std.testing.expectEqualStrings("VA-API does not initialize on /dev/dri/renderD128", vaapiMissing("/dev/dri/renderD128", error.VaInit, &buf));
    try std.testing.expectEqualStrings("no render node opens", vaapiMissing(null, error.OpenDevice, &buf));
}
