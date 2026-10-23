//! Fast-path input and output (MS-RDPBCGR 2.2.8.1.2, 2.2.9.1.2), and slow-path input
//! decoded to the same events.

const std = @import("std");
const bytes = @import("../core/bytes.zig");

pub const Error = error{ BadFastPath, TooManyEvents } || bytes.Error;

/// 1- or 2-byte (15-bit) PDU length, counting the header and length bytes.
pub fn readLength(r: *bytes.Reader) Error!u16 {
    const b0 = try r.byte();
    if (b0 & 0x80 == 0) return b0;
    return @as(u16, b0 & 0x7F) << 8 | try r.byte();
}

/// Frame size from a PDU's first bytes, or null if more are needed.
pub fn frameLength(head: []const u8) ?u16 {
    if (head.len < 2) return null;
    if (head[1] & 0x80 == 0) return head[1];
    if (head.len < 3) return null;
    return @as(u16, head[1] & 0x7F) << 8 | head[2];
}

pub const kbd_release: u8 = 0x01;
pub const kbd_extended: u8 = 0x02;
pub const kbd_extended1: u8 = 0x04;

pub const ptr_wheel_negative: u16 = 0x0100;
pub const ptr_wheel_mask: u16 = 0x01FF;
pub const ptr_wheel: u16 = 0x0200;
pub const ptr_hwheel: u16 = 0x0400;
pub const ptr_move: u16 = 0x0800;
pub const ptr_button1: u16 = 0x1000; // left
pub const ptr_button2: u16 = 0x2000; // right
pub const ptr_button3: u16 = 0x4000; // middle
pub const ptr_down: u16 = 0x8000;
pub const ptrx_button1: u16 = 0x0001; // XButton1 (back)
pub const ptrx_button2: u16 = 0x0002; // XButton2 (forward)
pub const ptrx_down: u16 = 0x8000;

pub const sync_scroll_lock: u8 = 0x01;
pub const sync_num_lock: u8 = 0x02;
pub const sync_caps_lock: u8 = 0x04;
pub const sync_kana_lock: u8 = 0x08;

pub const InputEvent = union(enum) {
    scancode: struct { code: u8, flags: u8 },
    mouse: struct { flags: u16, x: u16, y: u16 },
    mousex: struct { flags: u16, x: u16, y: u16 },
    sync: u8,
    unicode: struct { code: u16, release: bool },
    mouse_rel: struct { flags: u16, dx: i16, dy: i16 },
    qoe_timestamp: u32,
};

pub const max_events = 255;

pub fn parseInput(frame: []const u8, out: []InputEvent) Error![]InputEvent {
    var r = bytes.Reader.init(frame);
    const header = try r.byte();
    if (header & 0x03 != 0) return error.BadFastPath; // action must be FASTPATH
    // SECURE_CHECKSUM may be set without a signature; only ENCRYPTED adds one, never under TLS.
    if (header & 0x80 != 0) return error.BadFastPath;
    const len = try readLength(&r);
    if (len != frame.len) return error.BadFastPath;
    var n: usize = (header >> 2) & 0x0F;
    if (n == 0) n = try r.byte();
    if (n > out.len) return error.TooManyEvents;
    for (out[0..n]) |*ev| {
        const eh = try r.byte();
        const flags: u8 = eh & 0x1F;
        ev.* = switch (eh >> 5) {
            0 => .{ .scancode = .{ .code = try r.byte(), .flags = flags } },
            1 => .{ .mouse = .{ .flags = try r.u16le(), .x = try r.u16le(), .y = try r.u16le() } },
            2 => .{ .mousex = .{ .flags = try r.u16le(), .x = try r.u16le(), .y = try r.u16le() } },
            3 => .{ .sync = flags },
            4 => .{ .unicode = .{ .code = try r.u16le(), .release = flags & kbd_release != 0 } },
            5 => .{ .mouse_rel = .{ .flags = try r.u16le(), .dx = @bitCast(try r.u16le()), .dy = @bitCast(try r.u16le()) } },
            6 => .{ .qoe_timestamp = try r.u32le() },
            else => return error.BadFastPath,
        };
    }
    if (r.remaining() != 0) return error.BadFastPath;
    return out[0..n];
}

// Slow-path input (TS_INPUT_PDU_DATA, 2.2.8.1.1.3.1); keyboard flags map to fast-path bits.
pub const slow_kbd_extended: u16 = 0x0100;
pub const slow_kbd_extended1: u16 = 0x0200;
pub const slow_kbd_release: u16 = 0x8000;

pub const input_event_sync: u16 = 0x0000;
pub const input_event_unused: u16 = 0x0002;
pub const input_event_scancode: u16 = 0x0004;
pub const input_event_unicode: u16 = 0x0005;
pub const input_event_mouse: u16 = 0x8001;
pub const input_event_mousex: u16 = 0x8002;
pub const input_event_mouserel: u16 = 0x8004;

/// Slow-path Input Event PDU body; unused and unknown messageTypes are skipped.
pub const SlowInput = struct {
    r: bytes.Reader,
    left: u16,

    pub fn init(body: []const u8) Error!SlowInput {
        var r = bytes.Reader.init(body);
        const n = try r.u16le();
        try r.skip(2);
        try r.need(@as(usize, n) * 12);
        return .{ .r = r, .left = n };
    }

    pub fn next(it: *SlowInput) Error!?InputEvent {
        while (it.left > 0) {
            it.left -= 1;
            try it.r.skip(4); // eventTime, ignored by servers
            const message_type = try it.r.u16le();
            const a = try it.r.u16le();
            const b = try it.r.u16le();
            const c = try it.r.u16le();
            switch (message_type) {
                // TS_SYNC_EVENT: pad2Octets, toggleFlags (4 bytes).
                input_event_sync => return .{ .sync = @truncate(b) },
                input_event_scancode => {
                    var flags: u8 = 0;
                    if (a & slow_kbd_release != 0) flags |= kbd_release;
                    if (a & slow_kbd_extended != 0) flags |= kbd_extended;
                    if (a & slow_kbd_extended1 != 0) flags |= kbd_extended1;
                    return .{ .scancode = .{ .code = @truncate(b), .flags = flags } };
                },
                input_event_unicode => return .{ .unicode = .{ .code = b, .release = a & slow_kbd_release != 0 } },
                input_event_mouse => return .{ .mouse = .{ .flags = a, .x = b, .y = c } },
                input_event_mousex => return .{ .mousex = .{ .flags = a, .x = b, .y = c } },
                input_event_mouserel => return .{ .mouse_rel = .{ .flags = a, .dx = @bitCast(b), .dy = @bitCast(c) } },
                else => {},
            }
        }
        return null;
    }
};

/// Signed wheel delta from TS_POINTER_EVENT flags (9-bit two's complement).
pub fn wheelDelta(flags: u16) i16 {
    const v: i16 = @intCast(flags & 0xFF);
    return if (flags & ptr_wheel_negative != 0) v - 256 else v;
}

pub const UpdateCode = enum(u4) {
    orders = 0x0,
    bitmap = 0x1,
    palette = 0x2,
    synchronize = 0x3,
    surfcmds = 0x4,
    ptr_null = 0x5,
    ptr_default = 0x6,
    ptr_position = 0x8,
    color = 0x9,
    cached = 0xA,
    pointer = 0xB,
    large_pointer = 0xC,
};

pub const Fragment = enum(u2) { single = 0, last = 1, first = 2, next = 3 };

/// Max update bytes per fast-path PDU, well under the 15-bit length limit.
pub const max_update_payload = 0x3FF0;

pub fn writeUpdate(w: *bytes.Writer, code: UpdateCode, frag: Fragment, data: []const u8) !void {
    std.debug.assert(data.len <= max_update_payload);
    const total = 1 + 2 + 1 + 2 + data.len; // hdr + 2-byte len + updateHeader + size
    try w.byte(0); // FASTPATH_OUTPUT_ACTION_FASTPATH, no encryption
    try w.u16be(@as(u16, @intCast(total)) | 0x8000);
    try w.byte(@as(u8, @backingInt(code)) | @as(u8, @backingInt(frag)) << 4);
    try w.u16le(@intCast(data.len));
    try w.bytes(data);
}

/// FASTPATH_OUTPUT_COMPRESSION_USED (updateHeader bits 6-7, MS-RDPBCGR 2.2.9.1.2.1).
pub const output_compression_used: u8 = 0x2;

/// compressionFlags `flags` (MS-RDPBCGR 2.2.9.1.2.1, 3.1.8.2.1); 0 writes a plain update.
pub fn writeUpdateCompressed(w: *bytes.Writer, code: UpdateCode, frag: Fragment, flags: u8, data: []const u8) !void {
    if (flags == 0) return writeUpdate(w, code, frag, data);
    std.debug.assert(data.len <= max_update_payload);
    const total = 1 + 2 + 1 + 1 + 2 + data.len; // + compressionFlags
    try w.byte(0);
    try w.u16be(@as(u16, @intCast(total)) | 0x8000);
    try w.byte(@as(u8, @backingInt(code)) | @as(u8, @backingInt(frag)) << 4 | output_compression_used << 6);
    try w.byte(flags);
    try w.u16le(@intCast(data.len));
    try w.bytes(data);
}

/// Fragmented updates need a client MultifragmentUpdate MaxRequestSize >= `data.len`.
pub fn writeUpdateFragmented(w: *bytes.Writer, code: UpdateCode, data: []const u8) !void {
    if (data.len <= max_update_payload) return writeUpdate(w, code, .single, data);
    var off: usize = 0;
    while (off < data.len) {
        const n = @min(max_update_payload, data.len - off);
        const frag: Fragment = if (off == 0) .first else if (off + n == data.len) .last else .next;
        try writeUpdate(w, code, frag, data[off .. off + n]);
        off += n;
    }
}

/// TS_BITMAP_DATA for an uncompressed 32 bpp tile from top-down BGRX rows.
pub fn writeBitmapRect(w: *bytes.Writer, x: u16, y: u16, width: u16, height: u16, pixels: []const u8, stride: usize) !void {
    return writeBitmapRectBpp(w, x, y, width, height, pixels, stride, 32);
}

test "parse fast-path input events" {
    // 3 events: scancode 'A' down, mouse move to (100,200), unicode release.
    const frame = bytes.hex(
        \\0c 0e
        \\00 1e
        \\20 00 08 64 00 c8 00
        \\81 41 00
    );
    var buf: [16]InputEvent = undefined;
    const evs = try parseInput(&frame, &buf);
    try std.testing.expectEqual(@as(usize, 3), evs.len);
    try std.testing.expectEqual(@as(u8, 0x1e), evs[0].scancode.code);
    try std.testing.expectEqual(@as(u16, ptr_move), evs[1].mouse.flags);
    try std.testing.expectEqual(@as(u16, 200), evs[1].mouse.y);
    try std.testing.expect(evs[2].unicode.release);
    try std.testing.expectEqual(@as(u16, 'A'), evs[2].unicode.code);
}

test "fast-path input numEvents byte, relative mouse, and bad frames" {
    // numEvents = 0 in header -> explicit count byte (1), relative mouse.
    const frame = bytes.hex("00 0a 01 a0 00 08 fb ff 03 00");
    var buf: [4]InputEvent = undefined;
    const evs = try parseInput(&frame, &buf);
    try std.testing.expectEqual(@as(i16, -5), evs[0].mouse_rel.dx);
    try std.testing.expectEqual(@as(i16, 3), evs[0].mouse_rel.dy);

    try std.testing.expectError(error.BadFastPath, parseInput(&bytes.hex("04 05 00 1e 00"), &buf)); // trailing byte
    try std.testing.expectError(error.EndOfBuffer, parseInput(&bytes.hex("08 04 00 1e"), &buf)); // 2 events, 1 present
    try std.testing.expectError(error.BadFastPath, parseInput(&bytes.hex("84 04 00 1e"), &buf)); // ENCRYPTED flag
    try std.testing.expectError(error.TooManyEvents, parseInput(&bytes.hex("3c 03 00"), buf[0..2]));
}

test "Windows client focus-in burst with SECURE_CHECKSUM and no signature" {
    const frame = bytes.hex("6c 17 01 0f 60 01 2a 01 36 01 1d 03 1d 01 0f 01 38 01 0f 03 38 01 0f");
    var buf: [16]InputEvent = undefined;
    const evs = try parseInput(&frame, &buf);
    try std.testing.expectEqual(@as(usize, 11), evs.len);
    try std.testing.expectEqual(@as(u8, 0x0f), evs[0].scancode.code);
    try std.testing.expectEqual(kbd_release, evs[0].scancode.flags);
    try std.testing.expectEqual(@as(u8, 0), evs[1].sync);
    try std.testing.expectEqual(kbd_release | kbd_extended, evs[5].scancode.flags); // right Ctrl
}

test "slow-path input events decode to their fast-path forms" {
    // numEvents 5, pad; scancode E0 1D up, unicode, mouse, unused, sync.
    const body = [_]u8{ 5, 0, 0, 0 } ++
        [_]u8{ 0, 0, 0, 0, 0x04, 0x00, 0x00, 0x81, 0x1d, 0x00, 0x00, 0x00 } ++
        [_]u8{ 0, 0, 0, 0, 0x05, 0x00, 0x00, 0x80, 0xac, 0x20, 0x00, 0x00 } ++
        [_]u8{ 0, 0, 0, 0, 0x01, 0x80, 0x00, 0x08, 0x10, 0x00, 0x20, 0x00 } ++
        [_]u8{ 0, 0, 0, 0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } ++
        [_]u8{ 0, 0, 0, 0, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00 };
    var it = try SlowInput.init(&body);
    const k = (try it.next()).?.scancode;
    try std.testing.expectEqual(@as(u8, 0x1d), k.code);
    try std.testing.expectEqual(kbd_release | kbd_extended, k.flags);
    try std.testing.expectEqual(@as(u16, 0x20ac), (try it.next()).?.unicode.code);
    try std.testing.expectEqual(@as(u16, 0x20), (try it.next()).?.mouse.y);
    try std.testing.expectEqual(@as(u8, sync_num_lock | sync_caps_lock), (try it.next()).?.sync);
    try std.testing.expect(try it.next() == null);
    try std.testing.expectError(error.EndOfBuffer, SlowInput.init(body[0 .. body.len - 1]));
}

test "wheel delta sign extension" {
    try std.testing.expectEqual(@as(i16, 120), wheelDelta(ptr_wheel | 0x78));
    try std.testing.expectEqual(@as(i16, -120), wheelDelta(ptr_wheel | ptr_wheel_negative | 0x88));
}

test "compressed fast-path update layout (2.2.9.1.2.1)" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeUpdateCompressed(&w, .bitmap, .first, 0x61, &.{ 0xAA, 0xBB });
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x80, 0x09, 0x21 | 0x80, 0x61, 0x02, 0x00, 0xAA, 0xBB }, list.items);
    list.clearRetainingCapacity();
    try writeUpdateCompressed(&w, .ptr_null, .single, 0, &.{});
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x80, 0x06, 0x05, 0x00, 0x00 }, list.items);
}

test "fragmented output reassembles" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    const data = try std.testing.allocator.alloc(u8, max_update_payload * 2 + 10);
    defer std.testing.allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i);
    try writeUpdateFragmented(&w, .bitmap, data);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    var r = bytes.Reader.init(list.items);
    var frags: [3]Fragment = undefined;
    var i: usize = 0;
    while (r.remaining() > 0) : (i += 1) {
        const start = r.pos;
        _ = try r.byte();
        const len = try readLength(&r);
        const uh = try r.byte();
        frags[i] = @fromBackingInt(@intCast(@as(u2, @truncate(uh >> 4))));
        const size = try r.u16le();
        try out.appendSlice(std.testing.allocator, try r.bytes(size));
        try std.testing.expectEqual(start + len, r.pos);
    }
    try std.testing.expectEqual(@as(usize, 3), i);
    try std.testing.expectEqual(Fragment.first, frags[0]);
    try std.testing.expectEqual(Fragment.next, frags[1]);
    try std.testing.expectEqual(Fragment.last, frags[2]);
    try std.testing.expectEqualSlices(u8, data, out.items);
}

/// Uncompressed TS_BITMAP_DATA at `bpp` 15, 16, 24 or 32, rows padded to four bytes; the
/// destination keeps the real width (MS-RDPBCGR 2.2.9.1.1.3.1.2.2).
pub fn writeBitmapRectBpp(w: *bytes.Writer, x: u16, y: u16, width: u16, height: u16, pixels: []const u8, stride: usize, bpp: u16) !void {
    const bytes_pp: usize = switch (bpp) {
        15, 16 => 2,
        24 => 3,
        else => 4,
    };
    var padded: u16 = width;
    while (padded * bytes_pp % 4 != 0) padded += 1;
    try w.u16le(x);
    try w.u16le(y);
    try w.u16le(x + width - 1);
    try w.u16le(y + height - 1);
    try w.u16le(padded);
    try w.u16le(height);
    try w.u16le(if (bytes_pp == 4) 32 else bpp);
    try w.u16le(0); // flags: uncompressed
    try w.u16le(@intCast(@as(usize, padded) * bytes_pp * height));
    var row_i: usize = height;
    while (row_i > 0) {
        row_i -= 1;
        const row = pixels[row_i * stride ..][0 .. @as(usize, width) * 4];
        if (bytes_pp == 4) {
            try w.bytes(row);
        } else {
            var i: usize = 0;
            while (i < row.len) : (i += 4) {
                const b = row[i];
                const g = row[i + 1];
                const r = row[i + 2];
                switch (bpp) {
                    24 => try w.bytes(row[i..][0..3]), // B, G, R
                    15 => try w.u16le(@as(u16, r >> 3) << 10 | @as(u16, g >> 3) << 5 | b >> 3),
                    else => try w.u16le(@as(u16, r >> 3) << 11 | @as(u16, g >> 2) << 5 | b >> 3),
                }
            }
        }
        try w.zeros((@as(usize, padded) - width) * bytes_pp);
    }
}

test "bitmap rect at 16, 15 and 24 bpp: bottom-up, rows padded to four bytes" {
    // 1x2 image: top pixel white, bottom pixel pure red (BGRX).
    const px = bytes.hex("ff ff ff 00 00 00 ff 00");
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    try writeBitmapRectBpp(&w, 0, 0, 1, 2, &px, 4, 16);
    // width 2 (padded), destRight 0, bpp 16, 8 bytes: red 0xF800, pad, white, pad
    try std.testing.expectEqualSlices(u8, &bytes.hex("00 00 00 00 00 00 01 00 02 00 02 00 10 00 00 00 08 00 00 f8 00 00 ff ff 00 00"), list.items);
    list.clearRetainingCapacity();
    try writeBitmapRectBpp(&w, 0, 0, 1, 2, &px, 4, 15);
    try std.testing.expectEqualSlices(u8, &bytes.hex("00 7c 00 00 ff 7f 00 00"), list.items[18..]);
    list.clearRetainingCapacity();
    try writeBitmapRectBpp(&w, 0, 0, 1, 2, &px, 4, 24);
    try std.testing.expectEqual(@as(u16, 4), std.mem.readInt(u16, list.items[8..10], .little)); // width padded to 4
    try std.testing.expectEqualSlices(u8, &(bytes.hex("00 00 ff") ++ @as([9]u8, @splat(0)) ++ bytes.hex("ff ff ff") ++ @as([9]u8, @splat(0))), list.items[18..]);
}

test "bitmap rect is bottom-up" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    var w = bytes.Writer.init(&list, std.testing.allocator);
    const px = bytes.hex("11 11 11 00 22 22 22 00");
    try writeBitmapRect(&w, 0, 0, 1, 2, &px, 4);
    try std.testing.expectEqualSlices(u8, &bytes.hex("22 22 22 00 11 11 11 00"), list.items[18..]);
}
