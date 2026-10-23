//! Pointer cursor capture (ext_image_copy_capture_cursor_session_v1): image (ARGB8888),
//! hotspot and position arrive apart from output frames, as RDP draws the pointer client-side.

const std = @import("std");
const wire = @import("wire.zig");
const client_mod = @import("client.zig");
const capture = @import("capture.zig");
const Client = client_mod.Client;
const Output = client_mod.Output;
const P = wire.proto;

pub const Error = wire.Error;

pub const Image = struct {
    /// ARGB8888 (B,G,R,A bytes), premultiplied as the compositor renders it.
    frame: *const capture.Frame,
    hotspot_x: i32,
    hotspot_y: i32,
};

pub const Cursor = struct {
    client: *Client,
    output: *Output,
    source: P.ExtImageCaptureSourceV1,
    cursor_session: P.ExtImageCopyCaptureCursorSessionV1,
    image_capture: *capture.Capture,

    /// The cursor image intersects the output.
    inside: bool = false,
    /// Hotspot relative to the output's top-left, buffer pixels (may lie outside).
    x: i32 = 0,
    y: i32 = 0,
    hotspot_x: i32 = 0,
    hotspot_y: i32 = 0,
    pending_hotspot: ?[2]i32 = null,
    latched_hotspot: ?[2]i32 = null,
    /// The last hotspot sent, applied or not. Hyprland sends it on the output's next commit,
    /// after its image, not before as the protocol says: for Hyprland it is the current image's.
    latest_hotspot: [2]i32 = .{ 0, 0 },
    hotspot_serial: u32 = 0,
    /// Bumped on every enter/leave/position event.
    position_serial: u32 = 0,
    image_serial: u32 = 0,

    /// Needs ext-image-copy-capture and a seat with a pointer (create a VirtualPointer first if none).
    pub fn init(client: *Client, output: *Output) Error!*Cursor {
        const mgr = client.ext_capture orelse return error.Unsupported;
        const src_mgr = client.ext_output_source orelse return error.Unsupported;
        if (output.removed) return error.Stopped;
        const pointer = try client.getPointer();
        const conn = client.conn;
        const cur = try client.gpa.create(Cursor);
        errdefer client.gpa.destroy(cur);
        const source = try src_mgr.createSource(conn, output.proxy);
        errdefer source.destroy(conn) catch {};
        const cs = try mgr.createPointerCursorSession(conn, source, pointer);
        errdefer {
            // No event may reach the freed Cursor, whether or not the destructor was queued.
            conn.setHandler(cs.id, null);
            cs.destroy(conn) catch {};
        }
        conn.setHandler(cs.id, wire.Handler.init(Cursor, cur, onCursorSession));
        const session = try cs.getCaptureSession(conn);
        const image_capture = capture.Capture.initSession(client, session) catch |err| {
            session.destroy(conn) catch {};
            return err;
        };
        errdefer image_capture.deinit();
        cur.* = .{
            .client = client,
            .output = output,
            .source = source,
            .cursor_session = cs,
            .image_capture = image_capture,
        };
        cur.image_capture.on_ready = .{ .ctx = cur, .func = latchHotspot };
        try cur.image_capture.requestFrame();
        try conn.flush();
        return cur;
    }

    pub fn deinit(cur: *Cursor) void {
        const conn = cur.client.conn;
        cur.image_capture.deinit();
        cur.cursor_session.destroy(conn) catch {};
        cur.source.destroy(conn) catch {};
        conn.flush() catch {};
        cur.client.gpa.destroy(cur);
    }

    /// Valid until the next call; re-arms the capture for the next change.
    pub fn takeImage(cur: *Cursor) Error!?Image {
        const f = cur.image_capture.takeFrame() orelse return null;
        if (cur.latched_hotspot) |h| {
            cur.hotspot_x = h[0];
            cur.hotspot_y = h[1];
            cur.latched_hotspot = null;
        }
        cur.image_serial +%= 1;
        try cur.image_capture.requestFrame();
        return .{ .frame = f, .hotspot_x = cur.hotspot_x, .hotspot_y = cur.hotspot_y };
    }

    /// Blocking helper for tests: wait for the next image.
    pub fn waitImage(cur: *Cursor, timeout_ms: i32) Error!Image {
        const sys = @import("sys.zig");
        const start = sys.nowMs();
        while (true) {
            if (try cur.takeImage()) |img| return img;
            switch (cur.image_capture.state) {
                .stopped => return error.Stopped,
                .failed => return error.CaptureFailed,
                else => {},
            }
            const el: i32 = @intCast(sys.nowMs() -% start);
            if (timeout_ms >= 0 and el >= timeout_ms) return error.Timeout;
            _ = try cur.client.dispatchTimeout(if (timeout_ms < 0) -1 else timeout_ms - el);
        }
    }

    fn latchHotspot(ctx: *anyopaque) void {
        const cur: *Cursor = @ptrCast(@alignCast(ctx));
        if (cur.pending_hotspot) |h| {
            cur.latched_hotspot = h;
            cur.pending_hotspot = null;
        }
    }

    fn onCursorSession(cur: *Cursor, msg: *wire.Message) Error!void {
        switch (try msg.decode(P.ExtImageCopyCaptureCursorSessionV1)) {
            .enter => cur.inside = true,
            .leave => cur.inside = false,
            .position => |p| {
                cur.x = p.x;
                cur.y = p.y;
            },
            .hotspot => |h| {
                // Takes effect with the next image frame, or now if none was captured yet.
                if (cur.image_serial == 0 and cur.image_capture.seq == 0) {
                    cur.hotspot_x = h.x;
                    cur.hotspot_y = h.y;
                }
                cur.pending_hotspot = .{ h.x, h.y };
                cur.latest_hotspot = .{ h.x, h.y };
                cur.hotspot_serial +%= 1;
            },
        }
        cur.position_serial +%= 1;
    }
};
