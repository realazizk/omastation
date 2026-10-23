//! Byte transport for one RDP connection: TCP, then TLS after the security upgrade.
//! Splits the stream into whole TPKT or fast-path PDUs.

const std = @import("std");
const socket = @import("socket.zig");
const tls = @import("tls.zig");
const tpkt = @import("../proto/tpkt.zig");
const fastpath = @import("../proto/fastpath.zig");

pub const Error = error{ BadFrame, ConnectionClosed } || socket.Error || tls.Error;

pub const Pdu = struct {
    kind: enum { tpkt, fastpath },
    data: []const u8,
};

/// Unsent bytes the kernel holds; the rest waits in the send queue where pacing sees it.
pub const notsent_lowat: u32 = 128 * 1024;

pub const Transport = struct {
    fd: socket.Fd,
    session: ?tls.Session = null,
    buf: [buf_size]u8 = undefined,
    start: usize = 0,
    end: usize = 0,
    nonblocking: bool = false,

    const buf_size = 1 << 17; // a TPKT frame is at most 64 KiB

    pub fn init(fd: socket.Fd) Transport {
        return .{ .fd = fd };
    }

    /// Called once the connection sequence has written everything.
    pub fn startNonBlocking(t: *Transport) Error!void {
        try socket.setNonBlocking(t.fd, true);
        _ = socket.setNotSentLowat(t.fd, notsent_lowat);
        t.nonblocking = true;
    }

    /// Null until the whole PDU has arrived. The slice is valid until the next call.
    pub fn tryNext(t: *Transport) Error!?Pdu {
        std.debug.assert(t.nonblocking);
        return t.next() catch |err| switch (err) {
            error.WouldBlock => null,
            else => err,
        };
    }

    /// Bytes taken now, 0 when full. After a TLS write that waited, the next call must pass data
    /// starting with the same bytes.
    pub fn writeSome(t: *Transport, data: []const u8) Error!usize {
        std.debug.assert(t.nonblocking);
        const r = if (t.session) |*s| s.writeSome(data) else socket.writeSome(t.fd, data);
        return r catch |err| switch (err) {
            error.WouldBlock => 0,
            else => err,
        };
    }

    /// A TLS read waits to write: poll for POLLOUT.
    pub fn readWantsWrite(t: *const Transport) bool {
        return if (t.session) |s| s.read_wants_write else false;
    }

    pub fn deinit(t: *Transport) void {
        if (t.session) |*s| s.deinit();
        socket.close(t.fd);
        // The buffer may hold passwords and keystrokes, and lives on a thread stack glibc reuses.
        std.crypto.secureZero(u8, &t.buf);
    }

    pub fn closedCleanly(t: *const Transport) bool {
        return if (t.session) |s| s.closed_cleanly else false;
    }

    /// Requires no buffered plaintext; the client handshakes after the X.224 Connection Confirm.
    pub fn startTls(t: *Transport, ctx: *tls.Context) Error!void {
        if (t.end != t.start) return error.BadFrame;
        t.session = try ctx.accept(t.fd);
    }

    fn fill(t: *Transport) Error!void {
        if (t.start > 0 and t.start == t.end) {
            t.start = 0;
            t.end = 0;
        } else if (t.end == t.buf.len) {
            std.mem.copyForwards(u8, t.buf[0 .. t.end - t.start], t.buf[t.start..t.end]);
            t.end -= t.start;
            t.start = 0;
        }
        const n = if (t.session) |*s|
            try s.readSome(t.buf[t.end..])
        else
            try socket.readSome(t.fd, t.buf[t.end..]);
        t.end += n;
    }

    fn need(t: *Transport, n: usize) Error!void {
        std.debug.assert(n <= buf_size);
        while (t.end - t.start < n) try t.fill();
    }

    /// Next complete PDU. The slice is valid until the following call.
    pub fn next(t: *Transport) Error!Pdu {
        try t.need(1);
        const first = t.buf[t.start];
        if (tpkt.isTpkt(first)) {
            try t.need(tpkt.header_len);
            const len = tpkt.parseHeader(t.buf[t.start .. t.start + tpkt.header_len]) catch return error.BadFrame;
            try t.need(len);
            const pdu = t.buf[t.start .. t.start + len];
            t.start += len;
            return .{ .kind = .tpkt, .data = pdu };
        }
        if (first & 0x03 != 0) return error.BadFrame;
        try t.need(2);
        const long_len = t.buf[t.start + 1] & 0x80 != 0;
        if (long_len) try t.need(3);
        const len = fastpath.frameLength(t.buf[t.start..t.end]) orelse return error.BadFrame;
        // The length includes the header (MS-RDPBCGR 2.2.8.1.2).
        if (len < @as(u16, if (long_len) 3 else 2)) return error.BadFrame;
        try t.need(len);
        const pdu = t.buf[t.start .. t.start + len];
        t.start += len;
        return .{ .kind = .fastpath, .data = pdu };
    }

    /// Next DER-encoded SEQUENCE (a CredSSP TSRequest), as raw bytes.
    pub fn nextDerSequence(t: *Transport, max_len: usize) Error![]const u8 {
        try t.need(2);
        if (t.buf[t.start] != 0x30) return error.BadFrame;
        const l0 = t.buf[t.start + 1];
        var hdr: usize = 2;
        var len: usize = l0;
        if (l0 & 0x80 != 0) {
            const n = l0 & 0x7F;
            if (n == 0 or n > 3) return error.BadFrame;
            try t.need(2 + n);
            len = 0;
            for (0..n) |i| len = len << 8 | t.buf[t.start + 2 + i];
            hdr += n;
        }
        const total = hdr + len;
        if (total > max_len or total > buf_size) return error.BadFrame;
        try t.need(total);
        const pdu = t.buf[t.start .. t.start + total];
        t.start += total;
        return pdu;
    }

    /// Input already buffered here or inside TLS, which poll() would not report.
    pub fn hasPending(t: *const Transport) bool {
        if (t.end > t.start) return true;
        if (t.session) |*s| return s.pending();
        return false;
    }

    /// Blocking socket: all of `data` (the connection sequence).
    pub fn writeAll(t: *Transport, data: []const u8) Error!void {
        if (t.session) |*s| return s.writeAll(data);
        return socket.writeAll(t.fd, data);
    }
};
