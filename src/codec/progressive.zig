//! MS-RDPEGFX RemoteFX Progressive encoder (2.2.4.2, 3.2.8.1), sent in
//! RDPGFX_WIRE_TO_SURFACE_PDU_2 with codecId CAPROGRESSIVE (2.2.2.2).
//! Clients walk the Reduce-Extrapolate band layout in upgrade passes even when it is off.

const std = @import("std");
const bytes = @import("../core/bytes.zig");
const rfx = @import("rfx.zig");
const workers = @import("workers.zig");
const bits = rfx.bits;
const rlgr = rfx.rlgr;
const dwt = rfx.dwt;

pub const Error = error{
    InvalidDimensions,
    /// A quantization value out of range (0..15, progressive 0..8).
    BadQuant,
    /// A BitPos list that does not match the bands, or an upgrade to a larger BitPos.
    BadBitPos,
    /// No first pass was done for this component / tile.
    NoTile,
    /// A value too large for the SRL / raw field width.
    ValueTooLarge,
    BufferTooSmall,
} || std.mem.Allocator.Error;

pub const wbt_sync: u16 = 0xCCC0;
pub const wbt_frame_begin: u16 = 0xCCC1;
pub const wbt_frame_end: u16 = 0xCCC2;
pub const wbt_context: u16 = 0xCCC3;
pub const wbt_region: u16 = 0xCCC4;
pub const wbt_tile_simple: u16 = 0xCCC5;
pub const wbt_tile_first: u16 = 0xCCC6;
pub const wbt_tile_upgrade: u16 = 0xCCC7;

pub const magic: u32 = 0xCACCACCA;
pub const version_1_0: u16 = 0x0100;
pub const tile_size: u16 = 64;

pub const context_flag_subband_diffing: u8 = 0x01;
pub const region_flag_reduce_extrapolate: u8 = 0x01;
pub const tile_flag_difference: u8 = 0x01;
/// progressiveQuality meaning "100%, no progressive quantization".
pub const quality_full: u8 = 0xFF;

pub const sync_len: usize = 12;
pub const frame_begin_len: usize = 12;
pub const frame_end_len: usize = 6;
pub const context_len: usize = 10;
pub const region_fixed_len: usize = 18;
pub const tile_simple_fixed_len: usize = 22;
pub const tile_first_fixed_len: usize = 23;
pub const tile_upgrade_fixed_len: usize = 26;

/// RDPGFX_CODECID_CAPROGRESSIVE.
pub const gfx_codec_id: u16 = 0x0009;

/// RFX_COMPONENT_CODEC_QUANT (2.2.4.2.1.5.2).
pub const ComponentQuant = struct {
    ll3: u4,
    hl3: u4,
    lh3: u4,
    hh3: u4,
    hl2: u4,
    lh2: u4,
    hh2: u4,
    hl1: u4,
    lh1: u4,
    hh1: u4,

    fn wireOrder(q: ComponentQuant) [10]u4 {
        return .{ q.ll3, q.hl3, q.lh3, q.hh3, q.hl2, q.lh2, q.hh2, q.hl1, q.lh1, q.hh1 };
    }

    /// Nibbles LL3 (low nibble of byte 0), HL3, LH3, HH3, HL2, LH2, HH2, HL1, LH1, HH1.
    pub fn pack(q: ComponentQuant) Error![5]u8 {
        const v = q.wireOrder();
        var out: [5]u8 = undefined;
        for (&out, 0..) |*b, i| b.* = @as(u8, v[2 * i]) | @as(u8, v[2 * i + 1]) << 4;
        return out;
    }

    pub fn unpack(b: [5]u8) Error!ComponentQuant {
        var v: [10]u4 = undefined;
        for (b, 0..) |x, i| {
            v[2 * i] = @truncate(x);
            v[2 * i + 1] = @truncate(x >> 4);
        }
        return .{ .ll3 = v[0], .hl3 = v[1], .lh3 = v[2], .hh3 = v[3], .hl2 = v[4], .lh2 = v[5], .hh2 = v[6], .hl1 = v[7], .lh1 = v[8], .hh1 = v[9] };
    }

    /// The values in linearized band order (HL1 .. HH3, LL3), e.g. as BitPos.
    pub fn inBandOrder(q: ComponentQuant) Error![10]u8 {
        return .{ q.hl1, q.lh1, q.hh1, q.hl2, q.lh2, q.hh2, q.hl3, q.lh3, q.hh3, q.ll3 };
    }

    fn bandFactors(q: ComponentQuant) [10]u4 {
        return .{ q.hl1, q.lh1, q.hh1, q.hl2, q.lh2, q.hh2, q.hl3, q.lh3, q.hh3, q.ll3 };
    }

    /// RDP decoders need 6..15 here, the RemoteFX range (MS-RDPRFX 2.2.2.1.5).
    fn checkScalar(q: ComponentQuant) Error!void {
        for (q.wireOrder()) |f| if (f < 6) return error.BadQuant;
    }

    fn checkProgressive(q: ComponentQuant) Error!void {
        for (q.wireOrder()) |f| if (f > 8) return error.BadQuant;
    }
};

/// RFX_PROGRESSIVE_CODEC_QUANT (2.2.4.2.1.5.1): BitPos 0..8 per band for one quality level.
pub const ProgQuant = struct {
    quality: u8,
    y: ComponentQuant,
    cb: ComponentQuant,
    cr: ComponentQuant,

    pub fn pack(p: ProgQuant) Error![16]u8 {
        if (p.quality > 100) return error.BadQuant;
        var out: [16]u8 = undefined;
        out[0] = p.quality;
        for ([3]ComponentQuant{ p.y, p.cb, p.cr }, 0..) |q, i| {
            try q.checkProgressive();
            out[1 + 5 * i ..][0..5].* = try q.pack();
        }
        return out;
    }
};

// --- band layouts --------------------------------------------------------------------------

pub const Band = struct { len: usize, ll: bool = false };

/// Linearized band order with the Reduce-Extrapolate sizes (3.2.8.1.2.2, figure 3).
pub const tile_bands_extrapolate = [10]Band{
    .{ .len = 1023 },           .{ .len = 1023 }, .{ .len = 961 },
    .{ .len = 272 },            .{ .len = 272 },  .{ .len = 256 },
    .{ .len = 72 },             .{ .len = 72 },   .{ .len = 64 },
    .{ .len = 81, .ll = true },
};

/// The same with the original DWT (32x32, 16x16, 8x8 bands).
pub const tile_bands_original = [10]Band{
    .{ .len = 1024 },           .{ .len = 1024 }, .{ .len = 1024 },
    .{ .len = 256 },            .{ .len = 256 },  .{ .len = 256 },
    .{ .len = 64 },             .{ .len = 64 },   .{ .len = 64 },
    .{ .len = 64, .ll = true },
};

/// Band width x height of the Reduce-Extrapolate layout, in band order.
pub fn extrapolateBandSize(band: usize) Error!struct { width: u8, height: u8 } {
    if (band >= 10) return error.InvalidDimensions;
    const level = band / 3 + 1;
    const l: u8 = @intCast(dwt.bandL(level));
    const h: u8 = @intCast(dwt.bandH(level));
    if (band == 9) return .{ .width = 9, .height = 9 };
    return switch (band % 3) {
        0 => .{ .width = h, .height = l }, // HL: high horizontally
        1 => .{ .width = l, .height = h }, // LH
        else => .{ .width = h, .height = h }, // HH
    };
}

fn layoutLen(bands: []const Band) usize {
    var n: usize = 0;
    for (bands) |b| n += b.len;
    return n;
}

// --- entropy coding of upgrade passes ---------------------------------------------------

/// SRL encoder (3.1.8.1.5): zero runs coded like RLGR with KP from 8, values as sign + unary.
const SrlWriter = struct {
    w: bits.Writer,
    kp: u32 = 8,
    nz: usize = 0,

    fn zero(s: *SrlWriter) void {
        s.nz += 1;
    }

    /// Escapes for whole runs of 1 << K zeros (3.1.8.1.5.1).
    fn escapes(s: *SrlWriter) void {
        var k: u5 = @intCast(s.kp >> 3);
        while (s.nz >= @as(usize, 1) << k) {
            s.w.bit(0);
            s.nz -= @as(usize, 1) << k;
            s.kp = @min(s.kp + 4, 80);
            k = @intCast(s.kp >> 3);
        }
    }

    /// Terminate the run (nz < 1 << K): "1", nz in K bits, KP -= 6.
    fn terminate(s: *SrlWriter) void {
        const k: u5 = @intCast(s.kp >> 3);
        s.w.bit(1);
        s.w.bits(k, @intCast(s.nz));
        s.nz = 0;
        s.kp -|= 6;
    }

    /// A nonzero value with `nbits` of magnitude (3.1.8.1.5.2).
    fn value(s: *SrlWriter, v: i32, nbits: u5) void {
        s.escapes();
        s.terminate();
        s.w.bit(@intFromBool(v < 0));
        if (nbits == 1) return;
        const mag: u32 = @abs(v);
        const max = (@as(u32, 1) << nbits) - 1;
        s.w.zeros(mag - 1);
        if (mag != max) s.w.bit(1);
    }

    /// A final run writes its escapes, and the terminator only for leftover zeros (as
    /// 4.1.2.1.5); then the extra zero byte of 3.1.8.1.5 when anything was written.
    fn finish(s: *SrlWriter) error{BufferTooSmall}!usize {
        if (s.nz > 0) {
            s.escapes();
            if (s.nz > 0) s.terminate();
        }
        const any = s.w.bitCount() > 0;
        var n = try s.w.finish();
        if (any) {
            if (n >= s.w.buf.len) return error.BufferTooSmall;
            s.w.buf[n] = 0;
            n += 1;
        }
        return n;
    }
};

/// SRL bits for one element of magnitude `mag` (an upper bound).
fn srlCost(mag: u32) usize {
    return @as(usize, mag) + 13;
}

/// SRL encoding (3.1.8.1.5) with per-value magnitude widths `nbits` (1..15); the byte count.
/// Ends with the extra zero byte of 3.1.8.1.5, which the 4.1.2 examples omit and decoders ignore.
pub fn srlEncode(values: []const i16, nbits: []const u8, out: []u8) Error!usize {
    if (values.len != nbits.len) return error.BadBitPos;
    var s: SrlWriter = .{ .w = bits.Writer.init(out) };
    for (values, nbits) |v, nb| {
        if (nb == 0 or nb > 15) return error.BadBitPos;
        if (@abs(@as(i32, v)) > (@as(u32, 1) << @intCast(nb)) - 1) return error.ValueTooLarge;
        if (v == 0) s.zero() else s.value(v, @intCast(nb));
    }
    return s.finish();
}

/// Raw bits (3.2.8.1.5.2.1): each value MSB first in nbits[i] bits, back to back.
pub fn rawBitsEncode(values: []const u16, nbits: []const u8, out: []u8) Error!usize {
    if (values.len != nbits.len) return error.BadBitPos;
    var w = bits.Writer.init(out);
    for (values, nbits) |v, nb| {
        if (nb > 16) return error.BadBitPos;
        if (@as(u32, v) >> @intCast(nb) != 0) return error.ValueTooLarge;
        w.bits(@intCast(nb), v);
    }
    return w.finish();
}

// --- progressive coding of one component (3.2.8.1.5) ------------------------------------

/// Progressive quantization (3.1.8.1.3): toward zero, or toward -infinity for LL3.
inline fn progQ(v: i32, shift: u4, ll: bool) i32 {
    return if (ll or v >= 0) v >> shift else -((-v) >> shift);
}

/// Progressive state of one tile component: the decoder reference Ref (3.1.8.1.4) and the
/// data already sent (DAS) of the tile in flight. Works for any band layout.
pub const ComponentCodec = struct {
    gpa: std.mem.Allocator,
    bands: []const Band,
    /// Ref: what the decoder holds (DwtQ domain).
    ref: []i16 = &.{},
    /// SB and DAS of the tile in flight; kept only while some BitPos is above 0.
    sb: []i16 = &.{},
    das: []i16 = &.{},
    bitpos: []u8 = &.{},
    started: bool = false,

    pub fn init(gpa: std.mem.Allocator, bands: []const Band) Error!ComponentCodec {
        if (bands.len == 0) return error.InvalidDimensions;
        const ref = try gpa.alloc(i16, layoutLen(bands));
        errdefer gpa.free(ref);
        @memset(ref, 0);
        const bp = try gpa.alloc(u8, bands.len);
        @memset(bp, 0);
        return .{ .gpa = gpa, .bands = bands, .ref = ref, .bitpos = bp };
    }

    pub fn deinit(c: *ComponentCodec) void {
        c.dropSeries();
        c.gpa.free(c.ref);
        c.gpa.free(c.bitpos);
        c.* = undefined;
    }

    fn dropSeries(c: *ComponentCodec) void {
        c.gpa.free(c.sb);
        c.gpa.free(c.das);
        c.sb = &.{};
        c.das = &.{};
    }

    fn complete(c: *const ComponentCodec) bool {
        for (c.bitpos) |b| if (b != 0) return false;
        return true;
    }

    /// First pass (3.2.8.1.5.1) of `dwtq`, or of `dwtq` - Ref when `difference`, RLGR1-coded
    /// onto `out`. `bitpos` has one entry per band (0 = 100%).
    pub fn firstPass(c: *ComponentCodec, out: *std.ArrayList(u8), dwtq: []const i16, difference: bool, bitpos: []const u8) Error!void {
        const n = c.ref.len;
        if (dwtq.len != n or bitpos.len != c.bands.len) return error.BadBitPos;
        for (bitpos) |b| if (b > 15) return error.BadBitPos;
        const gpa = c.gpa;
        var stack: [4096]i16 = undefined;
        const vals = if (n <= stack.len) stack[0..n] else try gpa.alloc(i16, n);
        defer if (n > stack.len) gpa.free(vals);

        // ProgQ with LL deltas; nothing changes until the output is written
        var bound: usize = 64;
        var off: usize = 0;
        for (c.bands, bitpos) |band, bpos| {
            const shift: u4 = @intCast(bpos);
            var prev: i32 = 0;
            for (off..off + band.len) |i| {
                const s: i32 = if (difference) @as(i32, dwtq[i]) - c.ref[i] else dwtq[i];
                if (s < std.math.minInt(i16) or s > std.math.maxInt(i16)) return error.ValueTooLarge;
                const q = progQ(s, shift, band.ll);
                const v = if (band.ll) q - prev else q;
                prev = q;
                if (v < std.math.minInt(i16) or v > std.math.maxInt(i16)) return error.ValueTooLarge;
                vals[i] = @intCast(v);
                bound += 2 * @abs(v) + 32;
            }
            off += band.len;
        }
        var keep = false;
        for (bitpos) |b| keep = keep or b != 0;
        const fresh = keep and c.sb.len == 0;
        if (fresh) {
            c.sb = try gpa.alloc(i16, n);
            c.das = gpa.alloc(i16, n) catch |err| {
                gpa.free(c.sb);
                c.sb = &.{};
                return err;
            };
        }
        errdefer if (fresh) c.dropSeries();
        try out.ensureUnusedCapacity(gpa, bound / 8 + 8);
        const len = rlgr.encode(.rlgr1, vals, out.unusedCapacitySlice()) catch return error.BufferTooSmall;
        out.items.len += len;

        // commit: Ref = (difference ? Ref : 0) + DTS; SB and DAS kept while below 100%
        off = 0;
        for (c.bands, bitpos) |band, bpos| {
            const shift: u4 = @intCast(bpos);
            for (off..off + band.len) |i| {
                const s: i32 = if (difference) @as(i32, dwtq[i]) - c.ref[i] else dwtq[i];
                const dts: i32 = progQ(s, shift, band.ll) << shift;
                c.ref[i] = @intCast(if (difference) @as(i32, c.ref[i]) + dts else dts);
                if (keep) {
                    c.sb[i] = @intCast(s);
                    c.das[i] = @intCast(dts);
                }
            }
            off += band.len;
        }
        if (!keep) c.dropSeries();
        @memcpy(c.bitpos, bitpos);
        c.started = true;
    }

    /// Upgrade pass (3.2.8.1.5.2) to `bitpos` (each <= the current): elements with DAS 0 go to
    /// SRL, the others and LL3 to raw bits, nbits = BitPos(prev) - BitPos(target) per band.
    pub fn upgradePass(c: *ComponentCodec, srl: *std.ArrayList(u8), raw: *std.ArrayList(u8), bitpos: []const u8) Error!void {
        if (bitpos.len != c.bands.len) return error.BadBitPos;
        if (!c.started) return error.NoTile;
        for (bitpos, c.bitpos) |t, cur| if (t > cur) return error.BadBitPos;
        if (c.complete()) return; // already at 100%: nothing left to send
        const gpa = c.gpa;
        const n = c.ref.len;
        var stack: [4096]i32 = undefined;
        const upq = if (n <= stack.len) stack[0..n] else try gpa.alloc(i32, n);
        defer if (n > stack.len) gpa.free(upq);
        var srl_bits: usize = 64;
        var raw_bits: usize = 64;
        var off: usize = 0;
        for (c.bands, bitpos, c.bitpos) |band, t, cur| {
            const nb = cur - t;
            const shift: u4 = @intCast(t);
            for (off..off + band.len) |i| {
                if (nb == 0) {
                    upq[i] = 0;
                    continue;
                }
                const q = progQ(@as(i32, c.sb[i]) - c.das[i], shift, band.ll);
                upq[i] = q;
                if (!band.ll and c.das[i] == 0) srl_bits += srlCost(@abs(q)) else raw_bits += nb;
            }
            off += band.len;
        }
        try srl.ensureUnusedCapacity(gpa, srl_bits / 8 + 2);
        try raw.ensureUnusedCapacity(gpa, raw_bits / 8 + 1);
        var sw: SrlWriter = .{ .w = bits.Writer.init(srl.unusedCapacitySlice()) };
        var rw = bits.Writer.init(raw.unusedCapacitySlice());
        off = 0;
        for (c.bands, bitpos, c.bitpos) |band, t, cur| {
            const nb: u5 = @intCast(cur - t);
            defer off += band.len;
            if (nb == 0) continue;
            for (off..off + band.len) |i| {
                const q = upq[i];
                if (band.ll) {
                    rw.bits(nb, @intCast(q));
                } else if (c.das[i] == 0) {
                    if (q == 0) sw.zero() else sw.value(q, nb);
                } else {
                    rw.bits(nb, @abs(q));
                }
                const d: i32 = q * (@as(i32, 1) << @intCast(t));
                c.das[i] = @intCast(@as(i32, c.das[i]) + d);
                c.ref[i] = @intCast(@as(i32, c.ref[i]) + d);
            }
        }
        srl.items.len += sw.finish() catch return error.BufferTooSmall;
        raw.items.len += rw.finish() catch return error.BufferTooSmall;
        @memcpy(c.bitpos, bitpos);
        if (c.complete()) c.dropSeries();
    }

    /// Ref: the coefficients the decoder holds after the passes so far (3.2.8.1.5.3).
    pub fn reference(c: *const ComponentCodec) Error![]const i16 {
        return c.ref;
    }
};

/// Sub-band diffing decision (3.2.8.1.4) on luma: a difference tile only when
/// `dwtq_y` - `ref_y` has strictly more zeros outside LL3 than `dwtq_y`.
pub fn chooseDifference(bands: []const Band, dwtq_y: []const i16, ref_y: []const i16) Error!bool {
    const n = layoutLen(bands);
    if (dwtq_y.len != n or ref_y.len != n) return error.InvalidDimensions;
    var orig: usize = 0;
    var diff: usize = 0;
    var off: usize = 0;
    for (bands) |band| {
        defer off += band.len;
        if (band.ll) continue;
        for (dwtq_y[off..][0..band.len], ref_y[off..][0..band.len]) |q, r| {
            orig += @intFromBool(q == 0);
            diff += @intFromBool(q == r);
        }
    }
    return diff > orig;
}

// --- tile transform -----------------------------------------------------------------------

/// Forward Reduce-Extrapolate DWT (3.2.8.1.2.2) into the `tile_bands_extrapolate` layout.
pub fn dwtEncodeExtrapolate(c: *[4096]i16) Error!void {
    dwt.encodeExtrapolate(c);
}

pub fn dwtDecodeExtrapolate(c: *[4096]i16) Error!void {
    dwt.decodeExtrapolate(c);
}

// --- blocks (2.2.4.2.1) -------------------------------------------------------------------

pub const Rect = struct { x: u16, y: u16, width: u16, height: u16 };

pub fn writeSync(w: *bytes.Writer) Error!void {
    try w.u16le(wbt_sync);
    try w.u32le(sync_len);
    try w.u32le(magic);
    try w.u16le(version_1_0);
}

pub fn writeContext(w: *bytes.Writer, flags: u8) Error!void {
    try w.u16le(wbt_context);
    try w.u32le(context_len);
    try w.byte(0);
    try w.u16le(tile_size);
    try w.byte(flags);
}

pub fn writeFrameBegin(w: *bytes.Writer, frame_index: u32, region_count: u16) Error!void {
    try w.u16le(wbt_frame_begin);
    try w.u32le(frame_begin_len);
    try w.u32le(frame_index);
    try w.u16le(region_count);
}

pub fn writeFrameEnd(w: *bytes.Writer) Error!void {
    try w.u16le(wbt_frame_end);
    try w.u32le(frame_end_len);
}

/// RFX_PROGRESSIVE_REGION around encoded tile blocks; numRects > 0, numQuant <= 7.
pub const Region = struct {
    rects: []const Rect,
    quants: []const ComponentQuant,
    prog_quants: []const ProgQuant = &.{},
    flags: u8 = region_flag_reduce_extrapolate,
    num_tiles: u16,
    /// The concatenated tile blocks.
    tiles: []const u8,
};

pub fn writeRegion(w: *bytes.Writer, r: Region) Error!void {
    if (r.rects.len == 0 or r.rects.len > 0xFFFF) return error.InvalidDimensions;
    if (r.quants.len > 7 or r.prog_quants.len > 0xFF) return error.BadQuant;
    const len = region_fixed_len + 8 * r.rects.len + 5 * r.quants.len + 16 * r.prog_quants.len + r.tiles.len;
    if (len > std.math.maxInt(u32)) return error.ValueTooLarge;
    try w.u16le(wbt_region);
    try w.u32le(@intCast(len));
    try w.byte(@intCast(tile_size));
    try w.u16le(@intCast(r.rects.len));
    try w.byte(@intCast(r.quants.len));
    try w.byte(@intCast(r.prog_quants.len));
    try w.byte(r.flags);
    try w.u16le(r.num_tiles);
    try w.u32le(@intCast(r.tiles.len));
    for (r.rects) |rc| {
        try w.u16le(rc.x);
        try w.u16le(rc.y);
        try w.u16le(rc.width);
        try w.u16le(rc.height);
    }
    for (r.quants) |q| try w.bytes(&try q.pack());
    for (r.prog_quants) |p| try w.bytes(&try p.pack());
    try w.bytes(r.tiles);
}

pub const TileSimple = struct {
    quant_idx_y: u8 = 0,
    quant_idx_cb: u8 = 0,
    quant_idx_cr: u8 = 0,
    x_idx: u16,
    y_idx: u16,
    flags: u8 = 0,
    y_data: []const u8,
    cb_data: []const u8,
    cr_data: []const u8,
};

fn u16Len(data: []const u8) Error!u16 {
    return std.math.cast(u16, data.len) orelse error.ValueTooLarge;
}

pub fn writeTileSimple(w: *bytes.Writer, t: TileSimple) Error!void {
    const ly = try u16Len(t.y_data);
    const lcb = try u16Len(t.cb_data);
    const lcr = try u16Len(t.cr_data);
    try w.u16le(wbt_tile_simple);
    try w.u32le(@intCast(tile_simple_fixed_len + t.y_data.len + t.cb_data.len + t.cr_data.len));
    try w.byte(t.quant_idx_y);
    try w.byte(t.quant_idx_cb);
    try w.byte(t.quant_idx_cr);
    try w.u16le(t.x_idx);
    try w.u16le(t.y_idx);
    try w.byte(t.flags);
    try w.u16le(ly);
    try w.u16le(lcb);
    try w.u16le(lcr);
    try w.u16le(0);
    try w.bytes(t.y_data);
    try w.bytes(t.cb_data);
    try w.bytes(t.cr_data);
}

pub const TileFirst = struct {
    quant_idx_y: u8 = 0,
    quant_idx_cb: u8 = 0,
    quant_idx_cr: u8 = 0,
    x_idx: u16,
    y_idx: u16,
    flags: u8 = 0,
    quality: u8,
    y_data: []const u8,
    cb_data: []const u8,
    cr_data: []const u8,
};

pub fn writeTileFirst(w: *bytes.Writer, t: TileFirst) Error!void {
    const ly = try u16Len(t.y_data);
    const lcb = try u16Len(t.cb_data);
    const lcr = try u16Len(t.cr_data);
    try w.u16le(wbt_tile_first);
    try w.u32le(@intCast(tile_first_fixed_len + t.y_data.len + t.cb_data.len + t.cr_data.len));
    try w.byte(t.quant_idx_y);
    try w.byte(t.quant_idx_cb);
    try w.byte(t.quant_idx_cr);
    try w.u16le(t.x_idx);
    try w.u16le(t.y_idx);
    try w.byte(t.flags);
    try w.byte(t.quality);
    try w.u16le(ly);
    try w.u16le(lcb);
    try w.u16le(lcr);
    try w.u16le(0);
    try w.bytes(t.y_data);
    try w.bytes(t.cb_data);
    try w.bytes(t.cr_data);
}

pub const TileUpgrade = struct {
    quant_idx_y: u8 = 0,
    quant_idx_cb: u8 = 0,
    quant_idx_cr: u8 = 0,
    x_idx: u16,
    y_idx: u16,
    quality: u8,
    y_srl: []const u8,
    y_raw: []const u8,
    cb_srl: []const u8,
    cb_raw: []const u8,
    cr_srl: []const u8,
    cr_raw: []const u8,
};

pub fn writeTileUpgrade(w: *bytes.Writer, t: TileUpgrade) Error!void {
    const parts = [6][]const u8{ t.y_srl, t.y_raw, t.cb_srl, t.cb_raw, t.cr_srl, t.cr_raw };
    var lens: [6]u16 = undefined;
    var total: usize = tile_upgrade_fixed_len;
    for (parts, &lens) |p, *l| {
        l.* = try u16Len(p);
        total += p.len;
    }
    try w.u16le(wbt_tile_upgrade);
    try w.u32le(@intCast(total));
    try w.byte(t.quant_idx_y);
    try w.byte(t.quant_idx_cb);
    try w.byte(t.quant_idx_cr);
    try w.u16le(t.x_idx);
    try w.u16le(t.y_idx);
    try w.byte(t.quality);
    for (lens) |l| try w.u16le(l);
    for (parts) |p| try w.bytes(p);
}

// --- surface encoder ------------------------------------------------------------------------

pub const EncoderOptions = struct {
    /// RFX_COMPONENT_CODEC_QUANT for Y (and Cb/Cr unless `quant_chroma`).
    quant: ComponentQuant = .{ .ll3 = 6, .hl3 = 6, .lh3 = 6, .hh3 = 6, .hl2 = 7, .lh2 = 7, .hh2 = 8, .hl1 = 8, .lh1 = 8, .hh1 = 9 },
    quant_chroma: ?ComponentQuant = null,
    /// Quality levels in order, BitPos non-increasing, then 100%; empty: TILE_SIMPLE.
    /// Clients drop tiles whose quant + BitPos exceeds 16.
    levels: []const ProgQuant = &.{},
    subband_diffing: bool = true,
    reduce_extrapolate: bool = true,
};

const TileState = struct {
    comps: [3]ComponentCodec,
    /// Index of the level the decoder holds; levels.len = 100%.
    level: usize,
    /// Area inside the tile that upgrades repaint: what the current pass series covered.
    dirty: Rect,
};

/// Tiles an upgrade pass codes before checking its byte budget again.
const upgrade_min_batch: usize = 16;

/// A tile's coded output of the pass in flight, kept per tile so tiles code in parallel and
/// the buffers are reused frame after frame: Y, Cb, Cr (first pass) or SRL + raw per component.
const TileOut = struct {
    parts: [6]std.ArrayList(u8) = @splat(.empty),
    difference: bool = false,

    fn clear(o: *TileOut) void {
        for (&o.parts) |*p| p.clearRetainingCapacity();
    }

    fn deinit(o: *TileOut, gpa: std.mem.Allocator) void {
        for (&o.parts) |*p| p.deinit(gpa);
    }
};

fn rectUnion(a: Rect, b: Rect) Rect {
    const x0 = @min(a.x, b.x);
    const y0 = @min(a.y, b.y);
    const x1 = @max(@as(u32, a.x) + a.width, @as(u32, b.x) + b.width);
    const y1 = @max(@as(u32, a.y) + a.height, @as(u32, b.y) + b.height);
    return .{ .x = x0, .y = y0, .width = @intCast(x1 - x0), .height = @intCast(y1 - y0) };
}

fn toRfx(r: Rect) rfx.Rect {
    return .{ .x = r.x, .y = r.y, .width = r.width, .height = r.height };
}

fn mapRfx(e: rfx.Error) Error {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.BadQuant, error.BadQuantIndex => error.BadQuant,
        error.BufferTooSmall => error.BufferTooSmall,
        else => error.InvalidDimensions,
    };
}

/// Per-surface encoder (one per codecContextId). After an error or an undelivered stream the
/// client disagrees: send RDPGFX_DELETE_ENCODING_CONTEXT_PDU and start a fresh Encoder.
pub const Encoder = struct {
    gpa: std.mem.Allocator,
    width: u16,
    height: u16,
    opts: EncoderOptions,
    /// Owned copy of opts.levels.
    levels: []ProgQuant = &.{},
    bands: []const Band = &tile_bands_extrapolate,
    tiles_x: usize = 0,
    tiles: []?*TileState = &.{},
    /// Per tile, `tiles` order.
    outs: []TileOut = &.{},
    /// Bytes per tile of the last upgrade pass, 0 before one; sizes the parallel batches.
    upgrade_bytes_per_tile: usize = 0,
    frame_index: u32 = 0,
    context_sent: bool = false,

    pub fn init(gpa: std.mem.Allocator, width: u16, height: u16, opts: EncoderOptions) Error!Encoder {
        if (width == 0 or height == 0) return error.InvalidDimensions;
        try opts.quant.checkScalar();
        if (opts.quant_chroma) |q| try q.checkScalar();
        if (opts.levels.len >= quality_full) return error.BadQuant;
        for (opts.levels, 0..) |l, i| {
            _ = try l.pack();
            if (i == 0) continue;
            const prev = opts.levels[i - 1];
            for ([3]ComponentQuant{ prev.y, prev.cb, prev.cr }, [3]ComponentQuant{ l.y, l.cb, l.cr }) |a, b| {
                for (a.bandFactors(), b.bandFactors()) |x, y| if (y > x) return error.BadBitPos;
            }
        }
        const tx = (@as(usize, width) + 63) / 64;
        const ty = (@as(usize, height) + 63) / 64;
        const tiles = try gpa.alloc(?*TileState, tx * ty);
        @memset(tiles, null);
        errdefer gpa.free(tiles);
        const outs = try gpa.alloc(TileOut, tx * ty);
        @memset(outs, .{});
        errdefer gpa.free(outs);
        const levels = try gpa.dupe(ProgQuant, opts.levels);
        return .{
            .gpa = gpa,
            .width = width,
            .height = height,
            .opts = opts,
            .levels = levels,
            .bands = if (opts.reduce_extrapolate) &tile_bands_extrapolate else &tile_bands_original,
            .tiles_x = tx,
            .tiles = tiles,
            .outs = outs,
        };
    }

    pub fn deinit(e: *Encoder) void {
        for (e.tiles) |t| if (t) |ts| {
            for (&ts.comps) |*c| c.deinit();
            e.gpa.destroy(ts);
        };
        for (e.outs) |*o| o.deinit(e.gpa);
        e.gpa.free(e.outs);
        e.gpa.free(e.tiles);
        e.gpa.free(e.levels);
        e.* = undefined;
    }

    fn freeTile(e: *Encoder, ts: *TileState) void {
        for (&ts.comps) |*c| c.deinit();
        e.gpa.destroy(ts);
    }

    /// The first error any task hit.
    fn firstError(errs: []const ?Error) Error!void {
        for (errs) |m| if (m) |err| return err;
    }

    fn chromaQuant(e: *const Encoder) ComponentQuant {
        return e.opts.quant_chroma orelse e.opts.quant;
    }

    fn quantIdx(e: *const Encoder) [3]u8 {
        return if (e.opts.quant_chroma != null) .{ 0, 1, 1 } else .{ 0, 0, 0 };
    }

    fn quants(e: *const Encoder, buf: *[2]ComponentQuant) []const ComponentQuant {
        buf[0] = e.opts.quant;
        if (e.opts.quant_chroma) |q| {
            buf[1] = q;
            return buf[0..2];
        }
        return buf[0..1];
    }

    /// BitPos per band of component `comp` at `level` (levels.len: 100%).
    fn bitpos(e: *const Encoder, level: usize, comp: usize) [10]u8 {
        if (level >= e.levels.len) return @splat(0);
        const l = e.levels[level];
        const q = switch (comp) {
            0 => l.y,
            1 => l.cb,
            else => l.cr,
        };
        return q.inBandOrder() catch unreachable;
    }

    fn tileDwtq(e: *const Encoder, pixels: []const u8, stride: usize, tx: usize, ty: usize, out: *[3][4096]i16) Error!void {
        const x = tx * 64;
        const y = ty * 64;
        const vw: u16 = @intCast(@min(64, e.width - x));
        const vh: u16 = @intCast(@min(64, e.height - y));
        rfx.rgbToYCbCr(pixels[y * stride + x * 4 ..], stride, vw, vh, &out[0], &out[1], &out[2]) catch |err| return mapRfx(err);
        var lens: [10]usize = undefined;
        for (e.bands, &lens) |b, *l| l.* = b.len;
        for (out, 0..) |*c, i| {
            if (e.opts.reduce_extrapolate) dwt.encodeExtrapolate(c) else dwt.encode(c);
            const q = if (i == 0) e.opts.quant else e.chromaQuant();
            rfx.quantizeBands(c, &lens, &q.bandFactors()) catch |err| return mapRfx(err);
        }
    }

    fn tracking(e: *const Encoder) bool {
        return e.opts.subband_diffing or e.levels.len > 0;
    }

    fn newTile(e: *Encoder) Error!*TileState {
        const ts = try e.gpa.create(TileState);
        errdefer e.gpa.destroy(ts);
        var made: usize = 0;
        errdefer for (ts.comps[0..made]) |*c| c.deinit();
        for (&ts.comps) |*c| {
            c.* = try ComponentCodec.init(e.gpa, e.bands);
            made += 1;
        }
        ts.level = e.levels.len;
        ts.dirty = .{ .x = 0, .y = 0, .width = 0, .height = 0 };
        return ts;
    }

    /// One bitmap stream with a TILE_FIRST (TILE_SIMPLE when non-progressive) for every tile
    /// touching `rects` (BGRX, top-down); an empty `rects` means the whole surface.
    pub fn encodeFrame(e: *Encoder, out: *std.ArrayList(u8), pixels: []const u8, stride: usize, rects: []const Rect) Error!void {
        const gpa = e.gpa;
        const w: usize = e.width;
        const h: usize = e.height;
        if (stride < w * 4 or pixels.len < (h - 1) * stride + w * 4) return error.InvalidDimensions;
        const full = [1]Rect{.{ .x = 0, .y = 0, .width = e.width, .height = e.height }};
        const rs = if (rects.len == 0) &full else rects;
        if (rs.len > 0xFFFF) return error.InvalidDimensions;
        const rrs = try gpa.alloc(rfx.Rect, rs.len);
        defer gpa.free(rrs);
        for (rs, rrs) |r, *o| {
            if (r.width == 0 or r.height == 0) return error.InvalidDimensions;
            if (@as(usize, r.x) + r.width > w or @as(usize, r.y) + r.height > h) return error.InvalidDimensions;
            o.* = toRfx(r);
        }
        const idx = try gpa.alloc(rfx.TileIndex, e.tiles.len);
        defer gpa.free(idx);
        const list = rfx.tilesForRects(rrs, idx) catch |err| return mapRfx(err);
        if (list.len > 0xFFFF) return error.InvalidDimensions;

        // Tiles code in parallel: each touches its own TileState and TileOut. Without tracking
        // every tile starts from a blank state, so each task keeps one scratch state.
        const ntasks = workers.maxTasks();
        const scratch = try gpa.alloc(?*TileState, ntasks);
        defer {
            for (scratch) |s| if (s) |ts| e.freeTile(ts);
            gpa.free(scratch);
        }
        @memset(scratch, null);
        const errs = try gpa.alloc(?Error, ntasks);
        defer gpa.free(errs);
        @memset(errs, null);
        const progressive = e.levels.len > 0;
        const Job = struct {
            e: *Encoder,
            pixels: []const u8,
            stride: usize,
            rrs: []const rfx.Rect,
            list: []const rfx.TileIndex,
            scratch: []?*TileState,
            errs: []?Error,

            fn run(j: @This(), task: usize, i: usize) void {
                if (j.errs[task] != null) return;
                j.tile(task, j.list[i]) catch |err| {
                    j.errs[task] = err;
                };
            }

            fn tile(j: @This(), task: usize, t: rfx.TileIndex) Error!void {
                const e_ = j.e;
                var dq: [3][4096]i16 = undefined;
                try e_.tileDwtq(j.pixels, j.stride, t.x, t.y, &dq);
                const index = @as(usize, t.y) * e_.tiles_x + t.x;
                var ts: *TileState = undefined;
                var sent = false;
                if (e_.tracking()) {
                    const slot = &e_.tiles[index];
                    if (slot.* == null) slot.* = try e_.newTile();
                    ts = slot.*.?;
                    sent = ts.comps[0].started;
                } else {
                    if (j.scratch[task] == null) j.scratch[task] = try e_.newTile();
                    ts = j.scratch[task].?;
                }
                const diff = e_.opts.subband_diffing and sent and try chooseDifference(e_.bands, &dq[0], ts.comps[0].ref);
                const o = &e_.outs[index];
                o.clear();
                for (&ts.comps, &dq, o.parts[0..3], 0..) |*c, *d, *p, ci| try c.firstPass(p, d, diff, &e_.bitpos(0, ci));
                o.difference = diff;
                var area: ?Rect = null;
                for (j.rrs) |r| {
                    const cl = clip(r, t) orelse continue;
                    area = if (area) |a| rectUnion(a, cl) else cl;
                }
                ts.dirty = if (ts.level < e_.levels.len and sent) rectUnion(ts.dirty, area.?) else area.?;
                ts.level = 0; // the first level; 100% already when there are no levels
            }
        };
        workers.forEach(list.len, Job{ .e = e, .pixels = pixels, .stride = stride, .rrs = rrs, .list = list, .scratch = scratch, .errs = errs }, Job.run);
        try firstError(errs);

        var blocks: std.ArrayList(u8) = .empty;
        defer blocks.deinit(gpa);
        var bw = bytes.Writer.init(&blocks, gpa);
        const qi = e.quantIdx();
        for (list) |t| {
            const o = &e.outs[@as(usize, t.y) * e.tiles_x + t.x];
            const flags: u8 = if (o.difference) tile_flag_difference else 0;
            if (progressive) {
                try writeTileFirst(&bw, .{ .quant_idx_y = qi[0], .quant_idx_cb = qi[1], .quant_idx_cr = qi[2], .x_idx = t.x, .y_idx = t.y, .flags = flags, .quality = 0, .y_data = o.parts[0].items, .cb_data = o.parts[1].items, .cr_data = o.parts[2].items });
            } else {
                try writeTileSimple(&bw, .{ .quant_idx_y = qi[0], .quant_idx_cb = qi[1], .quant_idx_cr = qi[2], .x_idx = t.x, .y_idx = t.y, .flags = flags, .y_data = o.parts[0].items, .cb_data = o.parts[1].items, .cr_data = o.parts[2].items });
            }
        }
        var qbuf: [2]ComponentQuant = undefined;
        try e.writeStream(out, .{
            .rects = rs,
            .quants = e.quants(&qbuf),
            .prog_quants = if (progressive) e.levels[0..1] else &.{},
            .flags = if (e.opts.reduce_extrapolate) region_flag_reduce_extrapolate else 0,
            .num_tiles = @intCast(list.len),
            .tiles = blocks.items,
        });
    }

    /// SYNC + CONTEXT on the first stream only.
    fn writeStream(e: *Encoder, out: *std.ArrayList(u8), region: Region) Error!void {
        var w = bytes.Writer.init(out, e.gpa);
        if (!e.context_sent) {
            try writeSync(&w);
            try writeContext(&w, if (e.opts.subband_diffing) context_flag_subband_diffing else 0);
        }
        try writeFrameBegin(&w, e.frame_index, 1);
        try writeRegion(&w, region);
        try writeFrameEnd(&w);
        e.context_sent = true;
        e.frame_index +%= 1;
    }

    /// One upgrade step (next level, finally 100%) for every tile below full quality.
    /// Returns false and writes nothing when no tile needs one.
    pub fn encodeUpgrade(e: *Encoder, out: *std.ArrayList(u8)) Error!bool {
        return e.encodeUpgradeWithin(out, std.math.maxInt(usize));
    }

    /// `encodeUpgrade` limited to the tiles whose blocks fit `max_bytes` (at least one). Its
    /// quant table may list a level no tile uses; decoders ignore it (2.2.4.2.1.5.2).
    pub fn encodeUpgradeWithin(e: *Encoder, out: *std.ArrayList(u8), max_bytes: usize) Error!bool {
        const gpa = e.gpa;
        const pending = try e.pendingTiles();
        if (pending == 0) return false;
        var rects: std.ArrayList(Rect) = .empty;
        defer rects.deinit(gpa);
        try rects.ensureTotalCapacity(gpa, pending);
        const used = try gpa.alloc(bool, e.levels.len);
        defer gpa.free(used);
        @memset(used, false);
        for (e.tiles) |slot| if (slot) |ts| if (ts.level + 1 < e.levels.len) {
            used[ts.level + 1] = true;
        };
        var table: std.ArrayList(ProgQuant) = .empty;
        defer table.deinit(gpa);
        const index = try gpa.alloc(u8, e.levels.len);
        defer gpa.free(index);
        for (used, 0..) |u, l| if (u) {
            index[l] = @intCast(table.items.len);
            try table.append(gpa, e.levels[l]);
        };

        var blocks: std.ArrayList(u8) = .empty;
        defer blocks.deinit(gpa);
        var bw = bytes.Writer.init(&blocks, gpa);
        const qi = e.quantIdx();
        // The pending tiles in order, upgraded in parallel batches sized to the bytes left
        // (a fixed minimum, so the output does not depend on the thread count), written in
        // order after each batch; the pass stops once `max_bytes` is reached.
        const pend = try gpa.alloc(usize, pending);
        defer gpa.free(pend);
        var np: usize = 0;
        for (e.tiles, 0..) |slot, i| if (slot) |ts| if (ts.level < e.levels.len) {
            pend[np] = i;
            np += 1;
        };
        const ntasks = workers.maxTasks();
        const errs = try gpa.alloc(?Error, ntasks);
        defer gpa.free(errs);
        const Job = struct {
            e: *Encoder,
            pend: []const usize,
            errs: []?Error,

            fn run(j: @This(), task: usize, k: usize) void {
                if (j.errs[task] != null) return;
                const i = j.pend[k];
                const ts = j.e.tiles[i].?;
                const next = ts.level + 1;
                const o = &j.e.outs[i];
                o.clear();
                for (&ts.comps, 0..) |*c, ci| c.upgradePass(&o.parts[2 * ci], &o.parts[2 * ci + 1], &j.e.bitpos(next, ci)) catch |err| {
                    j.errs[task] = err;
                    return;
                };
                ts.level = next;
            }
        };
        var done: usize = 0;
        while (done < pend.len) {
            if (rects.items.len > 0 and blocks.items.len >= max_bytes) break;
            var batch: usize = upgrade_min_batch;
            const per_tile = if (rects.items.len > 0) blocks.items.len / rects.items.len else e.upgrade_bytes_per_tile;
            if (per_tile > 0) batch = @max(batch, (max_bytes - blocks.items.len) / per_tile + 1);
            batch = @min(batch, pend.len - done);
            @memset(errs, null);
            workers.forEach(batch, Job{ .e = e, .pend = pend[done..][0..batch], .errs = errs }, Job.run);
            try firstError(errs);
            for (pend[done..][0..batch]) |i| {
                const ts = e.tiles[i].?;
                const o = &e.outs[i];
                try writeTileUpgrade(&bw, .{
                    .quant_idx_y = qi[0],
                    .quant_idx_cb = qi[1],
                    .quant_idx_cr = qi[2],
                    .x_idx = @intCast(i % e.tiles_x),
                    .y_idx = @intCast(i / e.tiles_x),
                    .quality = if (ts.level < e.levels.len) index[ts.level] else quality_full,
                    .y_srl = o.parts[0].items,
                    .y_raw = o.parts[1].items,
                    .cb_srl = o.parts[2].items,
                    .cb_raw = o.parts[3].items,
                    .cr_srl = o.parts[4].items,
                    .cr_raw = o.parts[5].items,
                });
                rects.appendAssumeCapacity(ts.dirty);
            }
            done += batch;
        }
        if (rects.items.len > 0) e.upgrade_bytes_per_tile = blocks.items.len / rects.items.len;
        var qbuf: [2]ComponentQuant = undefined;
        try e.writeStream(out, .{
            .rects = rects.items,
            .quants = e.quants(&qbuf),
            .prog_quants = table.items,
            .flags = if (e.opts.reduce_extrapolate) region_flag_reduce_extrapolate else 0,
            .num_tiles = @intCast(rects.items.len),
            .tiles = blocks.items,
        });
        return true;
    }

    /// Another codec repainted `rects`: stop upgrading the tiles they touch, whose passes no
    /// longer match the surface. Their references stay, as the decoder keeps them.
    pub fn forget(e: *Encoder, rects: []const Rect) Error!void {
        const ty_n = e.tiles.len / e.tiles_x;
        for (rects) |r| {
            if (r.width == 0 or r.height == 0) continue;
            const tx1 = @min((@as(usize, r.x) + r.width + 63) / 64, e.tiles_x);
            const ty1 = @min((@as(usize, r.y) + r.height + 63) / 64, ty_n);
            for (@as(usize, r.y) / 64..ty1) |ty| for (@as(usize, r.x) / 64..tx1) |tx| {
                if (e.tiles[ty * e.tiles_x + tx]) |ts| ts.level = e.levels.len;
            };
        }
    }

    /// Tiles still below 100%.
    pub fn pendingTiles(e: *const Encoder) Error!usize {
        var n: usize = 0;
        for (e.tiles) |slot| if (slot) |ts| {
            n += @intFromBool(ts.level < e.levels.len);
        };
        return n;
    }
};

fn clip(r: rfx.Rect, t: rfx.TileIndex) ?Rect {
    const x0 = @max(@as(u32, r.x), @as(u32, t.x) * 64);
    const y0 = @max(@as(u32, r.y), @as(u32, t.y) * 64);
    const x1 = @min(@as(u32, r.x) + r.width, (@as(u32, t.x) + 1) * 64);
    const y1 = @min(@as(u32, r.y) + r.height, (@as(u32, t.y) + 1) * 64);
    if (x0 >= x1 or y0 >= y1) return null;
    return .{ .x = @intCast(x0), .y = @intCast(y0), .width = @intCast(x1 - x0), .height = @intCast(y1 - y0) };
}

/// False when RDPGFX_CAPS_FLAG_THINCLIENT is set in a version 8.0 or 8.1 capability set
/// (2.2.3.1, 2.2.3.2: RemoteFX MUST be used instead).
pub fn allowed(caps_version: u32, caps_flags: u32) Error!bool {
    const v8: u32 = 0x00080004;
    const v81: u32 = 0x00080105;
    const thinclient: u32 = 0x01;
    return !((caps_version == v8 or caps_version == v81) and caps_flags & thinclient != 0);
}

/// RDPGFX_WIRE_TO_SURFACE_PDU_2 (2.2.2.2) with codecId CAPROGRESSIVE.
pub fn writeWireToSurface2(w: *bytes.Writer, surface_id: u16, codec_context_id: u32, pixel_format: u8, data: []const u8) Error!void {
    const len = 8 + 13 + data.len;
    if (len > std.math.maxInt(u32)) return error.ValueTooLarge;
    try w.u16le(0x0002);
    try w.u16le(0);
    try w.u32le(@intCast(len));
    try w.u16le(surface_id);
    try w.u16le(gfx_codec_id);
    try w.u32le(codec_context_id);
    try w.byte(pixel_format);
    try w.u32le(@intCast(data.len));
    try w.bytes(data);
}

/// RDPGFX_DELETE_ENCODING_CONTEXT_PDU (2.2.2.3).
pub fn writeDeleteEncodingContext(w: *bytes.Writer, surface_id: u16, codec_context_id: u32) Error!void {
    try w.u16le(0x0003);
    try w.u16le(0);
    try w.u32le(14);
    try w.u16le(surface_id);
    try w.u32le(codec_context_id);
}

test "tiles coded in parallel give the same bytes as one task, first pass and upgrades" {
    const gpa = std.testing.allocator;
    const w: u16 = 300;
    const h: u16 = 200;
    const px = try gpa.alloc(u8, @as(usize, w) * h * 4);
    defer gpa.free(px);
    const lv = [_]ProgQuant{
        .{ .quality = 50, .y = .{ .ll3 = 2, .hl3 = 2, .lh3 = 2, .hh3 = 3, .hl2 = 3, .lh2 = 3, .hh2 = 4, .hl1 = 4, .lh1 = 4, .hh1 = 4 }, .cb = .{ .ll3 = 2, .hl3 = 2, .lh3 = 2, .hh3 = 3, .hl2 = 3, .lh2 = 3, .hh2 = 4, .hl1 = 4, .lh1 = 4, .hh1 = 4 }, .cr = .{ .ll3 = 2, .hl3 = 2, .lh3 = 2, .hh3 = 3, .hl2 = 3, .lh2 = 3, .hh2 = 4, .hl1 = 4, .lh1 = 4, .hh1 = 4 } },
    };
    var streams: [2]std.ArrayList(u8) = .{ .empty, .empty };
    defer for (&streams) |*s| s.deinit(gpa);
    const saved = workers.maxTasks();
    defer workers.setMaxTasks(saved);
    for ([_]usize{ 1, 5 }, &streams) |tasks, *stream| {
        workers.setMaxTasks(tasks);
        var e = try Encoder.init(gpa, w, h, .{ .levels = &lv });
        defer e.deinit();
        for (0..3) |frame| {
            for (px, 0..) |*b, i| b.* = @truncate((i * 7 + frame * 13) ^ (i >> 5));
            try e.encodeFrame(stream, px, @as(usize, w) * 4, &.{});
            // a partial frame: three tiles
            try e.encodeFrame(stream, px, @as(usize, w) * 4, &.{.{ .x = 70, .y = 10, .width = 150, .height = 40 }});
            // upgrades, with a byte budget so batches get cut
            while (try e.encodeUpgradeWithin(stream, 3000)) {}
        }
        var rfx_enc = try rfx.Encoder.init(gpa, .{ .width = w, .height = h });
        defer rfx_enc.deinit();
        try rfx_enc.encodeFrame(stream, px, @as(usize, w) * 4, &.{});
        const msgs = try rfx_enc.encodeFrameSplit(px, @as(usize, w) * 4, &.{}, 20_000);
        defer {
            for (msgs) |m| gpa.free(m);
            gpa.free(msgs);
        }
        for (msgs) |m| try stream.appendSlice(gpa, m);
    }
    try std.testing.expect(streams[0].items.len > 10_000);
    try std.testing.expectEqualSlices(u8, streams[0].items, streams[1].items);
}

test "SRL of the MS-RDPEGFX 4.1.2.1.2 entries" {
    var out: [16]u8 = undefined;
    const n = try srlEncode(&.{ -13, 15, -3, 0, 0, -3, 2, -1 }, &.{ 4, 4, 4, 4, 2, 2, 2, 2 }, &out);
    try std.testing.expectEqualSlices(u8, &.{ 0xa0, 0x01, 0x80, 0x00, 0xc9, 0x49, 0xe0, 0x00 }, out[0..n]);
}
