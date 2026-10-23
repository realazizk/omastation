//! Login accounts: the NT-hash store NLA needs (`user:<32 hex NT hash>` lines) and PAM checks
//! of the CredSSP-delegated password, so a stolen hash alone cannot log in.

const std = @import("std");
const c = @import("c");
const md4 = @import("../sec/md4.zig");

const log = std.log.scoped(.auth);

pub const max_users = 8;

pub const Entry = struct {
    user: [64]u8,
    user_len: usize,
    nt_hash: [16]u8,

    pub fn name(e: *const Entry) []const u8 {
        return e.user[0..e.user_len];
    }
};

pub const Store = struct {
    entries: [max_users]Entry = undefined,
    count: usize = 0,

    pub fn add(s: *Store, user: []const u8, nt_hash: [16]u8) !void {
        if (s.count == max_users) return error.TooManyUsers;
        if (user.len == 0 or user.len > 64) return error.BadUserName;
        var e = Entry{ .user = undefined, .user_len = user.len, .nt_hash = nt_hash };
        @memcpy(e.user[0..user.len], user);
        s.entries[s.count] = e;
        s.count += 1;
    }

    /// Wipe the NT hashes: each is a password equivalent (MS-NLMP 3.3.2).
    pub fn deinit(s: *Store) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&s.entries));
        s.count = 0;
    }

    pub fn parse(text: []const u8) !Store {
        var s = Store{};
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadCredentialsFile;
            const hex = line[colon + 1 ..];
            if (hex.len != 32) return error.BadCredentialsFile;
            var h: [16]u8 = undefined;
            defer std.crypto.secureZero(u8, &h);
            _ = std.fmt.hexToBytes(&h, hex) catch return error.BadCredentialsFile;
            try s.add(line[0..colon], h);
        }
        return s;
    }

    /// NtHashFn; the domain is ignored (clients send "", "." or the server name).
    pub fn lookup(ctx: ?*anyopaque, user_utf16: []const u8, domain_utf16: []const u8) ?[16]u8 {
        _ = domain_utf16;
        const s: *const Store = @ptrCast(@alignCast(ctx orelse return null));
        const e = s.find(user_utf16) orelse return null;
        return e.nt_hash;
    }

    pub fn find(s: *const Store, user_utf16: []const u8) ?*const Entry {
        for (s.entries[0..s.count]) |*e| {
            if (utf16EqlUtf8IgnoreAsciiCase(user_utf16, e.name())) return e;
        }
        return null;
    }
};

pub fn utf16EqlUtf8IgnoreAsciiCase(utf16: []const u8, utf8: []const u8) bool {
    var out: [256]u8 = undefined;
    const name = utf16ToUtf8(&out, utf16) catch return false;
    return std.ascii.eqlIgnoreCase(name, utf8);
}

pub fn utf16EqlAsciiIgnoreCase(utf16: []const u8, ascii: []const u8) bool {
    if (utf16.len != ascii.len * 2) return false;
    for (ascii, 0..) |ch, i| {
        if (utf16[2 * i + 1] != 0) return false;
        if (std.ascii.toLower(utf16[2 * i]) != std.ascii.toLower(ch)) return false;
    }
    return true;
}

/// Unpaired surrogates and NUL fail: they cannot be passed to PAM safely.
pub fn utf16ToUtf8(out: []u8, utf16: []const u8) ![]u8 {
    if (utf16.len % 2 != 0) return error.BadUtf16;
    var n: usize = 0;
    var i: usize = 0;
    while (i < utf16.len) : (i += 2) {
        var cp: u21 = @as(u21, utf16[i]) | @as(u21, utf16[i + 1]) << 8;
        if (cp >= 0xDC00 and cp <= 0xDFFF) return error.BadUtf16; // low surrogate first
        if (cp >= 0xD800 and cp <= 0xDBFF) {
            if (i + 4 > utf16.len) return error.BadUtf16;
            const lo: u21 = @as(u21, utf16[i + 2]) | @as(u21, utf16[i + 3]) << 8;
            if (lo < 0xDC00 or lo > 0xDFFF) return error.BadUtf16;
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            i += 2;
        }
        if (cp == 0) return error.BadUtf16;
        const len = std.unicode.utf8CodepointSequenceLength(cp) catch return error.BadUtf16;
        if (n + len > out.len) return error.TooLong;
        _ = std.unicode.utf8Encode(cp, out[n..]) catch return error.BadUtf16;
        n += len;
    }
    return out[0..n];
}

/// NT hash of a UTF-8 password: MD4(UTF-16LE(password)).
pub fn ntHash(password_utf8: []const u8) ![16]u8 {
    var buf: [1024]u8 = undefined;
    var n: usize = 0;
    const view = std.unicode.Utf8View.init(password_utf8) catch return error.BadUtf8;
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| {
        var units: [2]u16 = undefined;
        const k: usize = if (cp > 0xFFFF) blk: {
            const v = cp - 0x10000;
            units = .{ @intCast(0xD800 + (v >> 10)), @intCast(0xDC00 + (v & 0x3FF)) };
            break :blk 2;
        } else blk: {
            units[0] = @intCast(cp);
            break :blk 1;
        };
        if (n + 2 * k > buf.len) return error.TooLong;
        for (units[0..k]) |u| {
            buf[n] = @truncate(u);
            buf[n + 1] = @truncate(u >> 8);
            n += 2;
        }
    }
    defer std.crypto.secureZero(u8, buf[0..n]);
    return md4.ntHash(buf[0..n]);
}

pub const PamCtx = struct { password: [*:0]const u8 };

pub fn pamConv(num_msg: c_int, msg: [*c][*c]const c.struct_pam_message, resp: [*c][*c]c.struct_pam_response, appdata: ?*anyopaque) callconv(.c) c_int {
    if (num_msg <= 0 or num_msg > c.PAM_MAX_NUM_MSG) return c.PAM_CONV_ERR;
    const ctx: *const PamCtx = @ptrCast(@alignCast(appdata orelse return c.PAM_CONV_ERR));
    const n: usize = @intCast(num_msg);
    // PAM frees the array and each resp with free(), so use calloc/strdup.
    const arr: [*c]c.struct_pam_response = @ptrCast(@alignCast(c.calloc(n, @sizeOf(c.struct_pam_response)) orelse return c.PAM_BUF_ERR));
    for (0..n) |i| {
        const m = msg[i];
        switch (m.*.msg_style) {
            c.PAM_PROMPT_ECHO_OFF => {
                arr[i].resp = c.strdup(ctx.password);
                if (arr[i].resp == null) {
                    freeResponses(arr, i);
                    return c.PAM_BUF_ERR;
                }
            },
            c.PAM_ERROR_MSG, c.PAM_TEXT_INFO => {},
            else => {
                // Echo-on prompts (e.g. a second factor) can't be answered remotely.
                freeResponses(arr, i);
                return c.PAM_CONV_ERR;
            },
        }
    }
    resp.* = arr;
    return c.PAM_SUCCESS;
}

/// The responses hold copies of the password.
fn freeResponses(arr: [*c]c.struct_pam_response, n: usize) void {
    for (0..n) |j| {
        const r = arr[j].resp orelse continue;
        std.crypto.secureZero(u8, std.mem.span(r));
        c.free(r);
    }
    c.free(arr);
}

/// PAM auth + account. Runs as root or as `user`: pam_unix verifies only the caller's password.
pub fn pamCheck(service: [:0]const u8, user: [:0]const u8, password: [:0]const u8) bool {
    var ctx = PamCtx{ .password = password.ptr };
    const conv = c.struct_pam_conv{ .conv = pamConv, .appdata_ptr = &ctx };
    var handle: ?*c.pam_handle_t = null;
    if (c.pam_start(service.ptr, user.ptr, &conv, &handle) != c.PAM_SUCCESS) {
        log.err("pam_start({s}) failed", .{service});
        return false;
    }
    var rc = c.pam_authenticate(handle, c.PAM_SILENT | c.PAM_DISALLOW_NULL_AUTHTOK);
    if (rc == c.PAM_SUCCESS) rc = c.pam_acct_mgmt(handle, c.PAM_SILENT);
    if (rc != c.PAM_SUCCESS) log.warn("PAM {s} for {s}: {s}", .{ service, user, std.mem.sliceTo(c.pam_strerror(handle, rc), 0) });
    _ = c.pam_end(handle, rc);
    return rc == c.PAM_SUCCESS;
}

const OpensslRng = struct { unused: u8 = 0 };

fn opensslFill(_: *OpensslRng, buf: []u8) void {
    // RAND_bytes fails only on an unseeded CSPRNG; never continue with predictable challenges.
    var off: usize = 0;
    while (off < buf.len) {
        const n: c_int = @intCast(@min(buf.len - off, 1 << 20));
        if (c.RAND_bytes(buf.ptr + off, n) != 1) @panic("RAND_bytes failed");
        off += @intCast(n);
    }
}

var rng_state: OpensslRng = .{};

pub fn secureRandom() std.Random {
    return std.Random.init(&rng_state, opensslFill);
}

/// Current time as a Windows FILETIME (100 ns ticks since 1601-01-01).
pub fn nowFiletime() u64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_REALTIME, &ts);
    const unix_100ns: u64 = @as(u64, @intCast(ts.tv_sec)) * 10_000_000 + @as(u64, @intCast(ts.tv_nsec)) / 100;
    return unix_100ns + 116444736000000000;
}

test "store parse and lookup" {
    // NT hash of "Password" (MS-NLMP 4.2.2.1.2).
    var s = try Store.parse(
        \\# omastation verifiers
        \\User:a4f49c406510bdcab6824ee7c30fd852
        \\
    );
    const hash = Store.lookup(&s, &[_]u8{ 'u', 0, 'S', 0, 'E', 0, 'r', 0 }, "");
    try std.testing.expectEqualSlices(u8, &(try ntHash("Password")), &hash.?);
    try std.testing.expect(Store.lookup(&s, &[_]u8{ 'b', 0, 'o', 0, 'b', 0 }, "") == null);
    try std.testing.expectError(error.BadCredentialsFile, Store.parse("nouser"));
    try std.testing.expectError(error.BadCredentialsFile, Store.parse("u:abc"));
}

test "utf16 to utf8" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("pä", try utf16ToUtf8(&buf, &[_]u8{ 'p', 0, 0xE4, 0 }));
    try std.testing.expectError(error.BadUtf16, utf16ToUtf8(&buf, &[_]u8{ 0x00, 0xD8 }));
}

test "secure random fills" {
    var a: [32]u8 = @splat(0);
    var b: [32]u8 = @splat(0);
    secureRandom().bytes(&a);
    secureRandom().bytes(&b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "filetime is after 2020" {
    try std.testing.expect(nowFiletime() > 132223104000000000);
}
