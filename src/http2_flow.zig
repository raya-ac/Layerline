const std = @import("std");
const h2 = @import("h2_native.zig");
const support = @import("http2_support.zig");

const Pending = struct {
    id: u32,
    window: i64,
    body: ?[]u8 = null,
    sent: usize = 0,
};

// The runtime handles a connection synchronously on one worker, like its TLS
// context. Scope this pointer to that connection, never to an individual request.
pub threadlocal var active: ?*State = null;

pub const State = struct {
    allocator: std.mem.Allocator,
    streams: std.ArrayList(Pending) = .empty,
    connection_window: i64 = 65535,
    initial_window: i64 = 65535,
    queued_bytes: usize = 0,
    last_stream_id: u32 = 0,
    pub const max_streams = 128;
    pub const max_queued_bytes = 64 * 1024 * 1024;

    pub fn deinit(self: *State) void {
        for (self.streams.items) |item| if (item.body) |body| self.allocator.free(body);
        self.streams.deinit(self.allocator);
    }

    pub fn find(self: *State, id: u32) ?usize {
        for (self.streams.items, 0..) |item, i| if (item.id == id) return i;
        return null;
    }

    pub fn open(self: *State, id: u32) !void {
        if (self.find(id) != null) return error.BadRequest;
        if (self.streams.items.len >= max_streams) return error.StreamLimit;
        try self.streams.append(self.allocator, .{ .id = id, .window = self.initial_window });
        self.last_stream_id = @max(self.last_stream_id, id);
    }

    pub fn cancel(self: *State, id: u32) void {
        const i = self.find(id) orelse return;
        const item = self.streams.orderedRemove(i);
        if (item.body) |body| {
            self.queued_bytes -= body.len;
            self.allocator.free(body);
        }
    }

    pub fn settings(self: *State, payload: []const u8) !void {
        if (payload.len % 6 != 0) return error.BadRequest;
        var offset: usize = 0;
        while (offset < payload.len) : (offset += 6) {
            const id = std.mem.readInt(u16, payload[offset..][0..2], .big);
            const value = std.mem.readInt(u32, payload[offset + 2 ..][0..4], .big);
            switch (id) {
                2 => if (value > 1) {
                    return error.BadRequest;
                },
                4 => {
                    if (value > 0x7fffffff) return error.FlowControl;
                    const delta = @as(i64, value) - self.initial_window;
                    for (self.streams.items) |*item| {
                        if (item.window + delta > 0x7fffffff) return error.FlowControl;
                        item.window += delta;
                    }
                    self.initial_window = value;
                },
                5 => if (value < 16384 or value > 0xffffff) {
                    return error.BadRequest;
                },
                else => {},
            }
        }
    }

    pub fn update(self: *State, id: u32, increment: u32) !void {
        if (increment == 0) return error.BadRequest;
        const window = if (id == 0) &self.connection_window else &self.streams.items[self.find(id) orelse return].window;
        if (window.* + increment > 0x7fffffff) return error.FlowControl;
        window.* += increment;
    }

    pub fn queue(self: *State, id: u32, body: []const u8) !void {
        const i = self.find(id) orelse return error.BadRequest;
        if (self.streams.items[i].body != null) return error.BadRequest;
        if (body.len > max_queued_bytes - self.queued_bytes) return error.QueueLimit;
        self.streams.items[i].body = try self.allocator.dupe(u8, body);
        self.queued_bytes += body.len;
    }

    pub fn flush(self: *State, stream: std.Io.net.Stream, write: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !void {
        // One frame per eligible stream per round keeps a stalled stream from
        // consuming the connection's remaining credit ahead of its neighbours.
        while (self.connection_window > 0) {
            var progressed = false;
            var i: usize = 0;
            while (i < self.streams.items.len and self.connection_window > 0) {
                const item = &self.streams.items[i];
                const body = item.body orelse {
                    i += 1;
                    continue;
                };
                if (item.window <= 0) {
                    i += 1;
                    continue;
                }
                const count = @min(body.len - item.sent, 16384, @as(usize, @intCast(@min(item.window, self.connection_window))));
                const end = item.sent + count;
                try support.sendFrame(stream, h2.FRAME_DATA, if (end == body.len) h2.FLAG_END_STREAM else 0, item.id, body[item.sent..end], write);
                item.sent = end;
                item.window -= @intCast(count);
                self.connection_window -= @intCast(count);
                progressed = true;
                if (end == body.len) {
                    self.cancel(item.id);
                } else {
                    i += 1;
                }
            }
            if (!progressed) break;
        }
    }
};

test "settings preserve consumed credit and reject overflow" {
    var state = State{ .allocator = std.testing.allocator };
    defer state.deinit();
    try state.open(1);
    state.streams.items[0].window -= 10;
    try state.settings("\x00\x04\x00\x00\x00\x00");
    try std.testing.expectEqual(-10, state.streams.items[0].window);
    try state.update(1, 15);
    try std.testing.expectEqual(5, state.streams.items[0].window);
    try std.testing.expectError(error.BadRequest, state.update(0, 0));
    try std.testing.expectError(error.FlowControl, state.settings("\x00\x04\x80\x00\x00\x00"));
    try std.testing.expectError(error.FlowControl, state.update(0, 0x7fffffff));
}
