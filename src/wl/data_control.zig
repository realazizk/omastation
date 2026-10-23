//! The seat's clipboard via ext-data-control-v1, as a privileged client that sees every
//! selection and sets it without focus. Offers are read through pipes; pastes from sources
//! set here queue send requests (takeSend). Primary selections are not used.

const std = @import("std");
const wire = @import("wire.zig");
const sys = @import("sys.zig");
const client_mod = @import("client.zig");
const Client = client_mod.Client;
const P = wire.proto;

const log = std.log.scoped(.wl);

pub const Error = wire.Error || sys.PipeError;

/// Mime types kept per offer; more are dropped (`Offer.dropped`).
pub const max_mime_types = 64;
/// Longer mime types are dropped (real ones are short; this bounds memory).
pub const max_mime_len = 255;
/// Offers introduced by data_offer and not yet named by a selection; the oldest goes beyond this.
const max_introduced = 8;
/// Live sources; beyond this the oldest is destroyed (a newer one was set after it).
const max_sources = 4;
/// Pending send requests; more are refused (fd closed).
pub const max_sends = 32;

/// Another client's (or this client's own) selection, read-only.
pub const Offer = struct {
    dc: *DataControl,
    proxy: P.ExtDataControlOfferV1,
    mimes: std.ArrayList([]u8) = .empty,
    /// Mime types beyond max_mime_types or longer than max_mime_len were dropped.
    dropped: bool = false,

    fn create(dc: *DataControl, proxy: P.ExtDataControlOfferV1) wire.Error!*Offer {
        const o = try dc.gpa.create(Offer);
        o.* = .{ .dc = dc, .proxy = proxy };
        dc.client.conn.setHandler(proxy.id, wire.Handler.init(Offer, o, onEvent));
        return o;
    }

    fn destroy(o: *Offer) void {
        const gpa = o.dc.gpa;
        o.proxy.destroy(o.dc.client.conn) catch {};
        for (o.mimes.items) |m| gpa.free(m);
        o.mimes.deinit(gpa);
        gpa.destroy(o);
    }

    fn onEvent(o: *Offer, msg: *wire.Message) wire.Error!void {
        switch (try msg.decode(P.ExtDataControlOfferV1)) {
            .offer => |e| {
                const m = e.mime_type;
                if (m.len == 0 or m.len > max_mime_len or o.mimes.items.len == max_mime_types) {
                    o.dropped = true;
                    return;
                }
                if (o.hasMime(m)) return;
                const copy = try o.dc.gpa.dupe(u8, m);
                errdefer o.dc.gpa.free(copy);
                try o.mimes.append(o.dc.gpa, copy);
            },
        }
    }

    /// In the order announced.
    pub fn mimeTypes(o: *const Offer) []const []const u8 {
        return o.mimes.items;
    }

    pub fn hasMime(o: *const Offer, mime: []const u8) bool {
        for (o.mimes.items) |m| if (std.mem.eql(u8, m, mime)) return true;
        return false;
    }

    /// The source client writes `mime` into a pipe; returns the read end (non-blocking, close-on-exec)
    /// for the caller to read until EOF and close. The local write end is closed here.
    pub fn receive(o: *Offer, mime: []const u8) Error!sys.Fd {
        const conn = o.dc.client.conn;
        const p = try sys.pipe();
        defer sys.close(p[1]); // the request carries a duplicate
        errdefer sys.close(p[0]);
        try o.proxy.receive(conn, mime, p[1]);
        try conn.flush();
        return p[0];
    }
};

/// A paste from one of this client's sources: write `mime` data into `fd`, then close it (owned by the taker).
pub const SendRequest = struct {
    /// The `tag` given to setSelection for that source.
    tag: u64,
    mime: []u8,
    fd: sys.Fd,

    pub fn deinit(s: SendRequest, gpa: std.mem.Allocator) void {
        gpa.free(s.mime);
        sys.close(s.fd);
    }
};

const Source = struct {
    dc: *DataControl,
    proxy: P.ExtDataControlSourceV1,
    tag: u64,
    mimes: [][]u8,

    fn onEvent(s: *Source, msg: *wire.Message) wire.Error!void {
        const dc = s.dc;
        switch (try msg.decode(P.ExtDataControlSourceV1)) {
            .send => |e| {
                // The fd is owned now; refuse rather than leak it.
                if (dc.sends.items.len >= max_sends) {
                    sys.close(e.fd);
                    return;
                }
                const mime = dc.gpa.dupe(u8, e.mime_type) catch |err| {
                    sys.close(e.fd);
                    return err;
                };
                dc.sends.append(dc.gpa, .{ .tag = s.tag, .mime = mime, .fd = e.fd }) catch |err| {
                    dc.gpa.free(mime);
                    sys.close(e.fd);
                    return err;
                };
            },
            // "This data source is no longer valid ... should clean up and destroy this data source."
            .cancelled => dc.dropSource(s),
        }
    }

    fn destroy(s: *Source) void {
        const gpa = s.dc.gpa;
        s.proxy.destroy(s.dc.client.conn) catch {};
        for (s.mimes) |m| gpa.free(m);
        gpa.free(s.mimes);
        gpa.destroy(s);
    }

    fn sameMimes(s: *const Source, o: *const Offer) bool {
        if (o.dropped or o.mimes.items.len != s.mimes.len) return false;
        for (s.mimes) |m| if (!o.hasMime(m)) return false;
        return true;
    }
};

pub const DataControl = struct {
    gpa: std.mem.Allocator,
    client: *Client,
    device: ?P.ExtDataControlDeviceV1,
    introduced: std.ArrayList(*Offer) = .empty,
    /// null when empty; valid until the next dispatch.
    selection: ?*Offer = null,
    /// Incremented on every selection event (also for this client's own).
    selection_serial: u64 = 0,
    /// The current selection is one of this client's sources.
    selection_own: bool = false,
    /// Oldest first.
    sources: std.ArrayList(*Source) = .empty,
    /// Sources set here whose selection event has not come yet, in order.
    expected: std.ArrayList(*Source) = .empty,
    sends: std.ArrayList(SendRequest) = .empty,
    /// The compositor sent `finished` (or the seat went away): inert; create a new one.
    finished: bool = false,

    /// error.Unsupported without the manager global or a seat; the first selection event follows.
    pub fn create(gpa: std.mem.Allocator, client: *Client) Error!*DataControl {
        const mgr = client.data_control_manager orelse return error.Unsupported;
        const seat = client.seat orelse return error.Unsupported;
        const dc = try gpa.create(DataControl);
        errdefer gpa.destroy(dc);
        dc.* = .{ .gpa = gpa, .client = client, .device = null };
        const dev = try mgr.getDataDevice(client.conn, seat);
        dc.device = dev;
        client.conn.setHandler(dev.id, wire.Handler.init(DataControl, dc, onDevice));
        try client.conn.flush();
        return dc;
    }

    /// Destroys this client's sources (and a selection that is theirs), offers and device; call before Client.deinit.
    pub fn destroy(dc: *DataControl) void {
        const conn = dc.client.conn;
        for (dc.sends.items) |s| s.deinit(dc.gpa);
        dc.sends.deinit(dc.gpa);
        for (dc.sources.items) |s| s.destroy();
        dc.sources.deinit(dc.gpa);
        dc.expected.deinit(dc.gpa);
        for (dc.introduced.items) |o| o.destroy();
        dc.introduced.deinit(dc.gpa);
        if (dc.selection) |o| o.destroy();
        if (dc.device) |d| d.destroy(conn) catch {};
        conn.flush() catch {};
        dc.gpa.destroy(dc);
    }

    /// `tag` comes back with every send request for this source. The previous source lives until
    /// the compositor cancels it (it may still serve pastes begun before).
    pub fn setSelection(dc: *DataControl, mimes: []const []const u8, tag: u64) Error!void {
        const dev = dc.device orelse return error.Unsupported;
        const conn = dc.client.conn;
        // Owned by dc.sources from here on, whatever fails below.
        const s = try dc.newSource(mimes, tag);
        for (s.mimes) |m| try s.proxy.offer(conn, m);
        try dev.setSelection(conn, s.proxy);
        while (dc.sources.items.len > max_sources) dc.dropSource(dc.sources.items[0]);
        try conn.flush();
    }

    fn newSource(dc: *DataControl, mimes: []const []const u8, tag: u64) Error!*Source {
        const mgr = dc.client.data_control_manager orelse return error.Unsupported;
        const conn = dc.client.conn;
        const gpa = dc.gpa;
        const owned = try gpa.alloc([]u8, mimes.len);
        var n: usize = 0;
        errdefer {
            for (owned[0..n]) |m| gpa.free(m);
            gpa.free(owned);
        }
        while (n < mimes.len) : (n += 1) owned[n] = try gpa.dupe(u8, mimes[n]);
        try dc.sources.ensureUnusedCapacity(gpa, 1);
        try dc.expected.ensureUnusedCapacity(gpa, 1);
        const s = try gpa.create(Source);
        errdefer gpa.destroy(s);
        const proxy = try mgr.createDataSource(conn);
        s.* = .{ .dc = dc, .proxy = proxy, .tag = tag, .mimes = owned };
        conn.setHandler(proxy.id, wire.Handler.init(Source, s, Source.onEvent));
        dc.sources.appendAssumeCapacity(s);
        dc.expected.appendAssumeCapacity(s);
        return s;
    }

    /// Destroys all sources (the compositor clears a selection that is theirs); queued sends stay.
    pub fn withdraw(dc: *DataControl) void {
        while (dc.sources.items.len > 0) dc.dropSource(dc.sources.items[0]);
        dc.client.conn.flush() catch {};
    }

    /// It may or may not be the selection.
    pub fn hasSource(dc: *const DataControl) bool {
        return dc.sources.items.len > 0;
    }

    /// The caller owns it.
    pub fn takeSend(dc: *DataControl) ?SendRequest {
        if (dc.sends.items.len == 0) return null;
        return dc.sends.orderedRemove(0);
    }

    fn dropSource(dc: *DataControl, s: *Source) void {
        if (std.mem.indexOfScalar(*Source, dc.sources.items, s)) |i| _ = dc.sources.orderedRemove(i);
        if (std.mem.indexOfScalar(*Source, dc.expected.items, s)) |i| _ = dc.expected.orderedRemove(i);
        s.destroy();
    }

    fn takeIntroduced(dc: *DataControl, id: u32) ?*Offer {
        for (dc.introduced.items, 0..) |o, i| {
            if (o.proxy.id == id) return dc.introduced.orderedRemove(i);
        }
        return null;
    }

    /// Offers introduced but never named are stale once a selection event came.
    fn dropIntroduced(dc: *DataControl) void {
        for (dc.introduced.items) |o| o.destroy();
        dc.introduced.clearRetainingCapacity();
    }

    /// Whether `o` is the selection of a source set here: the first expected source with its
    /// mime types; set_selection is processed in order, so earlier expected ones never became it.
    fn claimOwn(dc: *DataControl, o: *const Offer) bool {
        for (dc.expected.items, 0..) |s, i| {
            if (!s.sameMimes(o)) continue;
            dc.expected.replaceRangeAssumeCapacity(0, i + 1, &.{});
            return true;
        }
        return false;
    }

    fn onDevice(dc: *DataControl, msg: *wire.Message) wire.Error!void {
        switch (try msg.decode(P.ExtDataControlDeviceV1)) {
            .data_offer => |e| {
                const o = try Offer.create(dc, e.id);
                dc.introduced.append(dc.gpa, o) catch |err| {
                    o.destroy();
                    return err;
                };
                if (dc.introduced.items.len > max_introduced) dc.introduced.orderedRemove(0).destroy();
            },
            .selection => |e| {
                // The current offer named again: nothing changed.
                if (e.id) |p| if (dc.selection) |cur| if (cur.proxy.id == p.id) return dc.dropIntroduced();
                // The protocol requires destroying the previous selection offer.
                const new: ?*Offer = if (e.id) |p| dc.takeIntroduced(p.id) else null;
                if (e.id != null and new == null) {
                    log.debug("selection names offer {d}, which was not introduced", .{e.id.?.id});
                }
                if (dc.selection) |old| old.destroy();
                dc.selection = new;
                dc.selection_own = if (new) |o| dc.claimOwn(o) else false;
                dc.selection_serial +%= 1;
                dc.dropIntroduced();
            },
            .primary_selection => |e| {
                if (e.id) |p| if (dc.takeIntroduced(p.id)) |o| o.destroy();
                dc.dropIntroduced();
            },
            .finished => {
                // The object is no longer valid and must be destroyed.
                dc.finished = true;
                if (dc.device) |d| d.destroy(dc.client.conn) catch {};
                dc.device = null;
                if (dc.selection) |o| o.destroy();
                dc.selection = null;
                dc.selection_own = false;
                dc.selection_serial +%= 1;
                dc.dropIntroduced();
            },
        }
    }
};

test {
    std.testing.refAllDecls(DataControl);
    std.testing.refAllDecls(Offer);
}
