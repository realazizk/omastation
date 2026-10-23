//! Wayland client connection with the globals the agent needs (shm, seat, named outputs,
//! capture, virtual input and data control managers); outputs are tracked across hotplug.

const std = @import("std");
const wire = @import("wire.zig");
const sys = @import("sys.zig");
const P = wire.proto;

const log = std.log.scoped(.wl);

pub const Error = wire.Error;

pub const Options = struct {
    /// Socket name or absolute path; default `$WAYLAND_DISPLAY`.
    display: ?[]const u8 = null,
    /// Timeout of the initial roundtrips.
    timeout_ms: i32 = 5000,
};

pub const Global = struct {
    name: u32,
    interface: P.Interface,
    version: u32,
};

pub const Output = struct {
    client: *Client,
    global_name: u32,
    proxy: P.WlOutput,
    name_buf: [64]u8 = undefined,
    name_len: usize = 0,
    desc_buf: [160]u8 = undefined,
    desc_len: usize = 0,
    /// Position in the compositor's global space (wl_output.geometry).
    x: i32 = 0,
    y: i32 = 0,
    /// Current mode, in hardware pixels.
    width: i32 = 0,
    height: i32 = 0,
    refresh_mhz: i32 = 0,
    physical_width_mm: i32 = 0,
    physical_height_mm: i32 = 0,
    /// Integer scale as advertised (fractional scales are rounded up).
    scale: i32 = 1,
    transform: P.WlOutput.Transform = .normal,
    /// Number of wl_output.done events seen; > 0 once fully described.
    done_count: u32 = 0,
    /// The global went away; the struct stays valid until Client.deinit.
    removed: bool = false,

    pub fn name(o: *const Output) []const u8 {
        return o.name_buf[0..o.name_len];
    }

    pub fn description(o: *const Output) []const u8 {
        return o.desc_buf[0..o.desc_len];
    }

    fn onEvent(o: *Output, msg: *wire.Message) Error!void {
        switch (try msg.decode(P.WlOutput)) {
            .geometry => |g| {
                o.x = g.x;
                o.y = g.y;
                o.physical_width_mm = g.physical_width;
                o.physical_height_mm = g.physical_height;
                o.transform = g.transform;
            },
            .mode => |m| if (m.flags & P.WlOutput.Mode.current != 0) {
                o.width = m.width;
                o.height = m.height;
                o.refresh_mhz = m.refresh;
            },
            .done => o.done_count += 1,
            .scale => |s| o.scale = s.factor,
            .name => |n| o.name_len = copyTrunc(&o.name_buf, n.name),
            .description => |d| o.desc_len = copyTrunc(&o.desc_buf, d.description),
        }
    }
};

fn copyTrunc(dst: []u8, src: []const u8) usize {
    const n = @min(dst.len, src.len);
    @memcpy(dst[0..n], src[0..n]);
    return n;
}

pub const Client = struct {
    gpa: std.mem.Allocator,
    conn: *wire.Connection,
    registry: P.WlRegistry,
    globals: std.ArrayList(Global) = .empty,
    /// Every output ever announced (removed ones flagged), stable pointers.
    output_list: std.ArrayList(*Output) = .empty,

    shm: ?P.WlShm = null,
    shm_formats: [32]u32 = undefined,
    shm_format_count: usize = 0,

    seat: ?P.WlSeat = null,
    seat_global: u32 = 0,
    seat_caps: u32 = 0,
    /// Capabilities the seat has ever had (get_pointer needs pointer here).
    seat_caps_ever: u32 = 0,
    pointer: ?P.WlPointer = null,

    ext_capture: ?P.ExtImageCopyCaptureManagerV1 = null,
    ext_output_source: ?P.ExtOutputImageCaptureSourceManagerV1 = null,
    screencopy: ?P.ZwlrScreencopyManagerV1 = null,
    virtual_keyboard_manager: ?P.ZwpVirtualKeyboardManagerV1 = null,
    virtual_pointer_manager: ?P.ZwlrVirtualPointerManagerV1 = null,
    data_control_manager: ?P.ExtDataControlManagerV1 = null,

    pub fn connect(gpa: std.mem.Allocator, opts: Options) Error!*Client {
        return initConn(gpa, try wire.Connection.connect(gpa, opts.display), opts);
    }

    /// Takes ownership of an already connected `socket`.
    pub fn connectFd(gpa: std.mem.Allocator, socket: sys.Fd, opts: Options) Error!*Client {
        return initConn(gpa, wire.Connection.initFd(gpa, socket) catch |e| {
            sys.close(socket);
            return e;
        }, opts);
    }

    fn initConn(gpa: std.mem.Allocator, conn: *wire.Connection, opts: Options) Error!*Client {
        const client = gpa.create(Client) catch |e| {
            conn.deinit();
            return e;
        };
        client.* = .{ .gpa = gpa, .conn = conn, .registry = undefined };
        errdefer client.deinit(); // also frees conn
        client.registry = try conn.display().getRegistry(conn);
        conn.setHandler(client.registry.id, wire.Handler.init(Client, client, onRegistry));
        // First roundtrip: globals and binds; second: the bound objects' initial events.
        try conn.roundtrip(opts.timeout_ms);
        try conn.roundtrip(opts.timeout_ms);
        return client;
    }

    /// How long deinit waits for the compositor to process the last requests.
    pub const teardown_timeout_ms = 1000;

    pub fn deinit(client: *Client) void {
        const conn = client.conn;
        // Round trip first: libwayland-server destroys a client that hung up before it read
        // everything, so closing right after a flush loses requests.
        client.roundtrip(teardown_timeout_ms) catch {};
        if (client.pointer) |p| if (conn.version(p.id) >= 3) p.release(conn) catch {};
        if (client.seat) |s| if (conn.version(s.id) >= 5) s.release(conn) catch {};
        for (client.output_list.items) |o| {
            if (!o.removed and conn.version(o.proxy.id) >= 3) o.proxy.release(conn) catch {};
            client.gpa.destroy(o);
        }
        if (client.ext_capture) |m| m.destroy(conn) catch {};
        if (client.ext_output_source) |m| m.destroy(conn) catch {};
        if (client.screencopy) |m| m.destroy(conn) catch {};
        if (client.virtual_pointer_manager) |m| m.destroy(conn) catch {};
        if (client.data_control_manager) |m| m.destroy(conn) catch {};
        if (client.shm) |s| if (conn.version(s.id) >= 2) s.release(conn) catch {};
        conn.flush() catch {};
        client.output_list.deinit(client.gpa);
        client.globals.deinit(client.gpa);
        conn.deinit();
        client.gpa.destroy(client);
    }

    pub fn fd(client: *const Client) sys.Fd {
        return client.conn.fd;
    }

    /// Non-blocking: flush requests, read and dispatch available events.
    pub fn dispatch(client: *Client) Error!usize {
        return client.conn.dispatch();
    }

    /// `timeout_ms` -1 waits forever.
    pub fn dispatchTimeout(client: *Client, timeout_ms: i32) Error!usize {
        return client.conn.dispatchTimeout(timeout_ms);
    }

    pub fn flush(client: *Client) Error!void {
        return client.conn.flush();
    }

    pub fn roundtrip(client: *Client, timeout_ms: i32) Error!void {
        return client.conn.roundtrip(timeout_ms);
    }

    /// Includes removed ones (check `removed`); pointers stay valid until deinit.
    pub fn outputs(client: *const Client) []const *Output {
        return client.output_list.items;
    }

    pub fn findOutput(client: *const Client, name: []const u8) ?*Output {
        for (client.output_list.items) |o| {
            if (!o.removed and std.mem.eql(u8, o.name(), name)) return o;
        }
        return null;
    }

    pub fn hasGlobal(client: *const Client, iface: P.Interface) ?Global {
        for (client.globals.items) |g| if (g.interface == iface) return g;
        return null;
    }

    pub fn hasShmFormat(client: *const Client, format: P.WlShm.Format) bool {
        for (client.shm_formats[0..client.shm_format_count]) |f| if (f == @backingInt(format)) return true;
        return false;
    }

    /// Needs a seat that has had the pointer capability; creating a virtual pointer first ensures it.
    pub fn getPointer(client: *Client) Error!P.WlPointer {
        if (client.pointer) |p| return p;
        const seat = client.seat orelse return error.Unsupported;
        if (client.seat_caps_ever & P.WlSeat.Capability.pointer == 0) {
            try client.conn.roundtrip(5000);
            if (client.seat_caps_ever & P.WlSeat.Capability.pointer == 0) return error.Unsupported;
        }
        client.pointer = try seat.getPointer(client.conn);
        return client.pointer.?;
    }

    fn bindVersion(adv: u32, ours: u32) u32 {
        return @min(adv, ours);
    }

    fn onRegistry(client: *Client, msg: *wire.Message) Error!void {
        const conn = client.conn;
        switch (try msg.decode(P.WlRegistry)) {
            .global => |g| {
                const iface = P.Interface.fromName(g.interface) orelse return;
                try client.globals.append(client.gpa, .{ .name = g.name, .interface = iface, .version = g.version });
                const reg = client.registry;
                switch (iface) {
                    .wl_shm => if (client.shm == null) {
                        client.shm = try reg.bind(conn, g.name, P.WlShm, bindVersion(g.version, 2));
                        conn.setHandler(client.shm.?.id, wire.Handler.init(Client, client, onShm));
                    },
                    .wl_seat => if (client.seat == null) {
                        client.seat = try reg.bind(conn, g.name, P.WlSeat, bindVersion(g.version, 9));
                        client.seat_global = g.name;
                        conn.setHandler(client.seat.?.id, wire.Handler.init(Client, client, onSeat));
                    },
                    .wl_output => {
                        const o = try client.gpa.create(Output);
                        errdefer client.gpa.destroy(o);
                        o.* = .{
                            .client = client,
                            .global_name = g.name,
                            .proxy = try reg.bind(conn, g.name, P.WlOutput, bindVersion(g.version, 4)),
                        };
                        try client.output_list.append(client.gpa, o);
                        conn.setHandler(o.proxy.id, wire.Handler.init(Output, o, Output.onEvent));
                    },
                    .ext_image_copy_capture_manager_v1 => if (client.ext_capture == null) {
                        client.ext_capture = try reg.bind(conn, g.name, P.ExtImageCopyCaptureManagerV1, 1);
                    },
                    .ext_output_image_capture_source_manager_v1 => if (client.ext_output_source == null) {
                        client.ext_output_source = try reg.bind(conn, g.name, P.ExtOutputImageCaptureSourceManagerV1, 1);
                    },
                    .zwlr_screencopy_manager_v1 => if (client.screencopy == null) {
                        client.screencopy = try reg.bind(conn, g.name, P.ZwlrScreencopyManagerV1, bindVersion(g.version, 3));
                    },
                    .zwp_virtual_keyboard_manager_v1 => if (client.virtual_keyboard_manager == null) {
                        client.virtual_keyboard_manager = try reg.bind(conn, g.name, P.ZwpVirtualKeyboardManagerV1, 1);
                    },
                    .zwlr_virtual_pointer_manager_v1 => if (client.virtual_pointer_manager == null) {
                        client.virtual_pointer_manager = try reg.bind(conn, g.name, P.ZwlrVirtualPointerManagerV1, bindVersion(g.version, 2));
                    },
                    .ext_data_control_manager_v1 => if (client.data_control_manager == null) {
                        client.data_control_manager = try reg.bind(conn, g.name, P.ExtDataControlManagerV1, 1);
                    },
                    else => {},
                }
            },
            .global_remove => |r| {
                for (client.globals.items, 0..) |g, k| {
                    if (g.name != r.name) continue;
                    _ = client.globals.orderedRemove(k);
                    break;
                }
                for (client.output_list.items) |o| {
                    if (o.global_name != r.name or o.removed) continue;
                    o.removed = true;
                    if (conn.version(o.proxy.id) >= 3) try o.proxy.release(conn) else conn.destroyed(o.proxy.id);
                    log.info("output {s} removed", .{o.name()});
                }
                if (r.name == client.seat_global and client.seat != null) {
                    // The seat went away; input/cursor objects tied to it die.
                    client.seat = null;
                    client.pointer = null;
                }
            },
        }
    }

    fn onShm(client: *Client, msg: *wire.Message) Error!void {
        switch (try msg.decode(P.WlShm)) {
            .format => |f| if (client.shm_format_count < client.shm_formats.len) {
                client.shm_formats[client.shm_format_count] = @backingInt(f.format);
                client.shm_format_count += 1;
            },
        }
    }

    fn onSeat(client: *Client, msg: *wire.Message) Error!void {
        switch (try msg.decode(P.WlSeat)) {
            .capabilities => |c| {
                client.seat_caps = c.capabilities;
                client.seat_caps_ever |= c.capabilities;
            },
            .name => {},
        }
    }
};
