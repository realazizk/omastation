//! Tests: a fake Hyprland IPC socket (abstract, per test) beside a fake compositor
//! (src/wl/fake_test.zig). It answers `j/monitors all` with its RDP-n outputs, `j/workspaces`
//! with none and "ok" to any other command, journaling commands in order with the compositor's
//! requests. `output remove` stops the output's captures in the fake compositor before it
//! answers, as Hyprland does.

const std = @import("std");
const c = @import("c");
const hypr = @import("hypr.zig");
const fake_wl = @import("../wl/fake_test.zig");

pub const FakeHypr = struct {
    gpa: std.mem.Allocator,
    fd: c_int,
    thread: std.Thread = undefined,
    stop: std.atomic.Value(bool) = .init(false),
    ipc: hypr.Ipc = .{},
    journal: *fake_wl.Journal,
    compositor: *fake_wl.Fake,
    /// RDP-(k+1) exists; all are the compositor's size, side by side.
    present: [8]bool = @splat(false),
    err: ?anyerror = null,

    var serial = std.atomic.Value(u32).init(0);

    pub fn start(gpa: std.mem.Allocator, journal: *fake_wl.Journal, compositor: *fake_wl.Fake, outputs: usize) !*FakeHypr {
        const h = try gpa.create(FakeHypr);
        errdefer gpa.destroy(h);
        const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM | c.SOCK_CLOEXEC, 0);
        if (fd < 0) return error.SocketFailed;
        errdefer _ = c.close(fd);
        h.* = .{ .gpa = gpa, .fd = fd, .journal = journal, .compositor = compositor };
        for (h.present[0..outputs]) |*p| p.* = true;
        // Abstract: a NUL, then the name; both sides use the whole zero-padded sun_path.
        var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
        addr.sun_family = c.AF_UNIX;
        _ = try std.fmt.bufPrint(addr.sun_path[1..], "omastation-test-hypr-{d}-{d}", .{ c.getpid(), serial.fetchAdd(1, .monotonic) });
        h.ipc.path_len = addr.sun_path.len - 1; // Ipc copies path_len bytes: all but the last
        @memcpy(h.ipc.path_buf[0..h.ipc.path_len], @as([*]const u8, @ptrCast(&addr.sun_path))[0..h.ipc.path_len]);
        if (c.bind(fd, .{ .__sockaddr__ = @ptrCast(&addr) }, @sizeOf(c.struct_sockaddr_un)) != 0) return error.BindFailed;
        if (c.listen(fd, 8) != 0) return error.ListenFailed;
        h.thread = try std.Thread.spawn(.{}, run, .{h});
        return h;
    }

    pub fn destroy(h: *FakeHypr) void {
        h.stop.store(true, .release);
        h.thread.join();
        _ = c.close(h.fd);
        if (h.err) |e| std.debug.panic("fake Hyprland: {t}", .{e});
        h.gpa.destroy(h);
    }

    fn run(h: *FakeHypr) void {
        while (!h.stop.load(.acquire)) {
            var pfd: c.struct_pollfd = .{ .fd = h.fd, .events = c.POLLIN, .revents = 0 };
            if (c.poll(&pfd, 1, 10) <= 0) continue;
            const conn = c.accept4(h.fd, .{ .__sockaddr__ = null }, null, c.SOCK_CLOEXEC);
            if (conn < 0) continue;
            defer _ = c.close(conn);
            h.serve(conn) catch |e| {
                h.err = e;
                return;
            };
        }
    }

    fn serve(h: *FakeHypr, fd: c_int) !void {
        var buf: [2048]u8 = undefined;
        var len: usize = 0;
        while (true) {
            var pfd: c.struct_pollfd = .{ .fd = fd, .events = c.POLLIN, .revents = 0 };
            if (c.poll(&pfd, 1, 2000) <= 0) return error.RequestTimeout;
            const n = c.recv(fd, buf[len..].ptr, buf.len - len, 0);
            if (n < 0) return error.ReadFailed;
            if (n == 0) break;
            len += @intCast(n);
            if (len == buf.len) return error.RequestTooLong;
        }
        const cmd = buf[0..len];
        var out: [4096]u8 = undefined;
        const reply = if (std.mem.eql(u8, cmd, "j/monitors all")) h.monitorsJson(&out) else if (std.mem.eql(u8, cmd, "j/workspaces")) "[]" else blk: {
            h.journal.add("ipc {s}", .{cmd[0..@min(cmd.len, 56)]});
            if (std.mem.startsWith(u8, cmd, "output remove RDP-")) {
                const k = try std.fmt.parseInt(usize, cmd["output remove RDP-".len..], 10);
                if (k == 0 or k > h.present.len or !h.present[k - 1]) break :blk "no such output";
                try h.compositor.removeOutput(k - 1);
                h.present[k - 1] = false;
            }
            break :blk "ok";
        };
        _ = c.send(fd, reply.ptr, reply.len, c.MSG_NOSIGNAL);
    }

    fn monitorsJson(h: *FakeHypr, out: []u8) []const u8 {
        var w: std.Io.Writer = .fixed(out);
        w.writeAll("[") catch {};
        var first = true;
        for (h.present, 0..) |p, k| {
            if (!p) continue;
            if (!first) w.writeAll(",") catch {};
            first = false;
            w.print("{{\"name\":\"RDP-{d}\",\"width\":{d},\"height\":{d},\"refreshRate\":60.0,\"x\":{d},\"y\":0,\"scale\":1.0,\"disabled\":false}}", .{
                k + 1, h.compositor.width, h.compositor.height, k * h.compositor.width,
            }) catch {};
        }
        w.writeAll("]") catch {};
        return w.buffered();
    }
};
