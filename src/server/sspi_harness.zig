//! `omastation sspi-harness DIR`: runs the SPNEGO/NTLM server against a Windows SSPI client
//! through files (client writes DIR/c2s-N.bin, server answers DIR/s2c-N.bin).

const std = @import("std");
const c = @import("c");
const auth = @import("auth.zig");
const spnego = @import("../sec/spnego.zig");

const log = std.log.scoped(.sspi);

fn readFile(gpa: std.mem.Allocator, path: [:0]const u8) !?[]u8 {
    const fd = c.open(path.ptr, c.O_RDONLY | c.O_CLOEXEC);
    if (fd < 0) return null;
    defer _ = c.close(fd);
    const buf = try gpa.alloc(u8, 65536);
    errdefer gpa.free(buf);
    const n = c.read(fd, buf.ptr, buf.len);
    if (n < 0) return error.ReadFailed;
    if (n == 0) { // still being written
        gpa.free(buf);
        return null;
    }
    return try gpa.realloc(buf, @intCast(n));
}

fn writeFile(path: [:0]const u8, data: []const u8) !void {
    const fd = c.open(path.ptr, c.O_WRONLY | c.O_CREAT | c.O_TRUNC | c.O_CLOEXEC, @as(c_uint, 0o644));
    if (fd < 0) return error.WriteFailed;
    defer _ = c.close(fd);
    if (c.write(fd, data.ptr, data.len) != @as(isize, @intCast(data.len))) return error.WriteFailed;
}

pub fn run(gpa: std.mem.Allocator, dir: []const u8, store: *const auth.Store, nb_computer: []const u8, dns_computer: []const u8) !void {
    var srv = spnego.Server.init(gpa, .{
        .nb_computer = nb_computer,
        .dns_computer = dns_computer,
        .nt_hash = auth.Store.lookup,
        .nt_hash_ctx = @ptrCast(@constCast(store)),
        .rng = auth.secureRandom(),
        .now_filetime = auth.nowFiletime(),
    });
    defer srv.deinit();

    var step: usize = 1;
    var path_buf: [512]u8 = undefined;
    while (step < 8) : (step += 1) {
        const in_path = try std.mem.printSentinel(&path_buf, "{s}/c2s-{d}.bin", .{ dir, step }, 0);
        const token = blk: {
            var waited: usize = 0;
            while (waited < 1200) : (waited += 1) { // 120 s
                if (try readFile(gpa, in_path)) |t| break :blk t;
                _ = c.usleep(100_000);
            }
            log.err("timed out waiting for {s}", .{in_path});
            return error.Timeout;
        };
        defer gpa.free(token);
        log.info("c2s-{d}: {d} bytes: {x}", .{ step, token.len, token[0..@min(token.len, 96)] });

        const outcome = srv.step(token) catch |err| {
            log.err("step {d}: server rejected client token: {t}", .{ step, err });
            return err;
        };
        var out_buf: [512]u8 = undefined;
        const out_path = try std.mem.printSentinel(&out_buf, "{s}/s2c-{d}.bin", .{ dir, step }, 0);
        switch (outcome) {
            .reply => |r| {
                defer gpa.free(r);
                log.info("s2c-{d}: {d} bytes: {x}", .{ step, r.len, r[0..@min(r.len, 96)] });
                try writeFile(out_path, r);
            },
            .done => |d| {
                var res = d.result;
                defer res.deinit(gpa);
                log.info("authenticated after step {d}", .{step});
                if (d.final_token) |ft| {
                    defer gpa.free(ft);
                    log.info("s2c-{d} (final): {d} bytes: {x}", .{ step, ft.len, ft[0..@min(ft.len, 96)] });
                    try writeFile(out_path, ft);
                } else try writeFile(out_path, "");
                return;
            },
        }
    }
}
