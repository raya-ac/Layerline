const std = @import("std");
const h2 = @import("h2_native.zig");
const support = @import("http2_support.zig");
const Deadline = @import("read_deadline.zig").Deadline;
const write_deadline = @import("write_deadline.zig");

const Pending = struct {
    id: u32,
    window: i64,
    body: ?[]u8 = null,
    trailers: ?[]u8 = null,
    sent: usize = 0,
    deadline: Deadline = .{},
};

// The runtime handles a connection synchronously on one worker, like its TLS
// context. Scope this pointer to that connection, never to an individual request.
pub threadlocal var active: ?*State = null;

pub const State = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    write_timeout_ms: u32 = 30000,
    streams: std.ArrayList(Pending) = .empty,
    connection_window: i64 = 65535,
    initial_window: i64 = 65535,
    queued_bytes: usize = 0,
    last_stream_id: u32 = 0,
    pub const max_streams = 128;
    pub const max_queued_bytes = 64 * 1024 * 1024;

    pub fn deinit(self: *State) void {
        for (self.streams.items) |item| {
            if (item.body) |body| self.allocator.free(body);
            if (item.trailers) |trailers| self.allocator.free(trailers);
        }
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
        if (item.trailers) |trailers| {
            self.queued_bytes -= trailers.len;
            self.allocator.free(trailers);
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
        try self.queueResponse(id, body, "");
    }

    pub fn queueResponse(self: *State, id: u32, body: []const u8, trailers: []const u8) !void {
        const i = self.find(id) orelse return error.BadRequest;
        if (self.streams.items[i].body != null) return error.BadRequest;
        if (body.len > max_queued_bytes - self.queued_bytes) return error.QueueLimit;
        if (trailers.len > max_queued_bytes - self.queued_bytes - body.len) return error.QueueLimit;
        const owned_body = try self.allocator.dupe(u8, body);
        errdefer self.allocator.free(owned_body);
        const owned_trailers = if (trailers.len > 0) try self.allocator.dupe(u8, trailers) else null;
        errdefer if (owned_trailers) |bytes| self.allocator.free(bytes);
        _ = try self.startResponse(id);
        self.streams.items[i].body = owned_body;
        self.streams.items[i].trailers = owned_trailers;
        self.queued_bytes += body.len + trailers.len;
    }

    pub fn startResponse(self: *State, id: u32) !Deadline {
        const item = &self.streams.items[self.find(id) orelse return error.BadRequest];
        if (item.deadline.at == null) item.deadline = .after(.now(self.io, .awake), self.write_timeout_ms);
        return item.deadline;
    }

    pub fn nextDeadline(self: *const State) Deadline {
        var deadline = Deadline{};
        for (self.streams.items) |item| {
            if (item.body != null) deadline = Deadline.earliest(deadline, item.deadline);
        }
        return deadline;
    }

    pub fn expire(self: *State, stream: std.Io.net.Stream, write: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !void {
        var i: usize = 0;
        while (i < self.streams.items.len) {
            if (try self.expireAt(i, .now(self.io, .awake), stream, write)) continue;
            i += 1;
        }
    }

    fn expireAt(self: *State, i: usize, now: std.Io.Timestamp, stream: std.Io.net.Stream, write: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !bool {
        const item = self.streams.items[i];
        if (item.body == null or !item.deadline.expired(now)) return false;
        self.cancel(item.id);
        if (!@import("builtin").is_test) std.debug.print("{{\"event\":\"server.write_timeout\",\"protocol\":\"h2\",\"phase\":\"response\",\"stream_id\":{d}}}\n", .{item.id});
        try support.sendRst(stream, item.id, 8, write);
        return true;
    }

    pub fn flush(self: *State, stream: std.Io.net.Stream, write: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !void {
        try self.expire(stream, write);
        // One frame per eligible stream per round keeps a stalled stream from
        // consuming the connection's remaining credit ahead of its neighbours.
        while (true) {
            var progressed = false;
            var i: usize = 0;
            while (i < self.streams.items.len) {
                if (try self.expireAt(i, .now(self.io, .awake), stream, write)) continue;
                const item = &self.streams.items[i];
                const body = item.body orelse {
                    i += 1;
                    continue;
                };
                if (item.sent < body.len and (item.window <= 0 or self.connection_window <= 0)) {
                    i += 1;
                    continue;
                }
                const count = if (item.sent == body.len) 0 else @min(body.len - item.sent, 16384, @as(usize, @intCast(@min(item.window, self.connection_window))));
                const end = item.sent + count;
                {
                    const previous = write_deadline.push(.{ .io = self.io, .handle = stream.socket.handle, .deadline = item.deadline, .restore_timeout_ms = self.write_timeout_ms, .stream_id = item.id });
                    defer write_deadline.restore(previous);
                    if (count > 0 or item.trailers == null) {
                        try support.sendFrame(stream, h2.FRAME_DATA, if (end == body.len and item.trailers == null) h2.FLAG_END_STREAM else 0, item.id, body[item.sent..end], write);
                    }
                    if (end == body.len) if (item.trailers) |trailers| {
                        try support.sendHeaderBlock(stream, item.id, trailers, true, write);
                    };
                }
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
    var state = State{ .allocator = std.testing.allocator, .io = std.testing.io };
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

threadlocal var test_output: [256]u8 = undefined;
threadlocal var test_output_used: usize = 0;

fn captureWrite(_: std.Io.net.Stream, bytes: []const u8) !void {
    @memcpy(test_output[test_output_used..][0..bytes.len], bytes);
    test_output_used += bytes.len;
}

test "response expiry releases owned bodies and slots without renewing on credit" {
    var state = State{ .allocator = std.testing.allocator, .io = std.testing.io };
    defer state.deinit();
    const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    try state.open(1);
    try state.queue(1, "held");
    try state.open(3);
    try state.queue(3, "healthy");
    state.streams.items[0].deadline = .after(.fromNanoseconds(0), 100);
    state.streams.items[1].deadline = .after(.fromNanoseconds(0), 200);
    const original = state.nextDeadline().at.?.nanoseconds;
    try state.settings("\x00\x04\x00\x00\x00\x00");
    try state.update(1, 1);
    try std.testing.expectEqual(original, (try state.startResponse(1)).at.?.nanoseconds);
    try std.testing.expectEqual(original, state.nextDeadline().at.?.nanoseconds);
    test_output_used = 0;
    try std.testing.expect(try state.expireAt(0, .fromNanoseconds(100 * std.time.ns_per_ms), stream, captureWrite));
    try std.testing.expectEqualStrings("\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x00\x08", test_output[0..test_output_used]);
    try std.testing.expectEqual(7, state.queued_bytes);
    try std.testing.expect(state.find(1) == null);
    try std.testing.expectEqualStrings("healthy", state.streams.items[state.find(3).?].body.?);
    state.cancel(3);
    try std.testing.expectEqual(0, state.queued_bytes);
    try std.testing.expect(state.nextDeadline().at == null);
    try state.open(5);
    try std.testing.expect(state.streams.items[state.find(5).?].deadline.at == null);
}

test "zero connection credit does not prevent response expiry" {
    var state = State{ .allocator = std.testing.allocator, .io = std.testing.io, .connection_window = 0 };
    defer state.deinit();
    try state.open(1);
    try state.queue(1, "held");
    state.streams.items[0].deadline = .after(.fromNanoseconds(0), 1);
    test_output_used = 0;
    try state.flush(.{ .socket = .{ .handle = 123, .address = undefined } }, captureWrite);
    try std.testing.expectEqual(13, test_output_used);
    try std.testing.expectEqual(0, state.streams.items.len);
    try std.testing.expectEqual(0, state.queued_bytes);
}

test "trailers wait for DATA but need no flow credit once the body is complete" {
    const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    var state = State{ .allocator = std.testing.allocator, .io = std.testing.io, .connection_window = 0, .initial_window = 0 };
    defer state.deinit();
    try state.open(1);
    try state.queueResponse(1, "ok", "trailer");
    test_output_used = 0;
    try state.flush(stream, captureWrite);
    try std.testing.expectEqual(0, test_output_used);
    try std.testing.expectEqual(9, state.queued_bytes);
    try state.update(0, 2);
    try state.update(1, 2);
    try state.flush(stream, captureWrite);
    try std.testing.expectEqualStrings("\x00\x00\x02\x00\x00\x00\x00\x00\x01ok\x00\x00\x07\x01\x05\x00\x00\x00\x01trailer", test_output[0..test_output_used]);
    try std.testing.expectEqual(0, state.queued_bytes);
    try state.open(3);
    try state.queueResponse(3, "", "trailer");
    test_output_used = 0;
    try state.flush(stream, captureWrite);
    try std.testing.expectEqualStrings("\x00\x00\x07\x01\x05\x00\x00\x00\x03trailer", test_output[0..test_output_used]);
    try std.testing.expectEqual(0, state.streams.items.len);
}

fn trailerAllocationCheck(allocator: std.mem.Allocator) !void {
    var state = State{ .allocator = allocator, .io = std.testing.io };
    defer state.deinit();
    try state.open(1);
    try state.queueResponse(1, "body", "owned trailers");
    state.cancel(1);
    try std.testing.expectEqual(0, state.queued_bytes);
}

test "queued trailers are reclaimed on allocation failure and cancellation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, trailerAllocationCheck, .{});
}
