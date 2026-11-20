const std = @import("std");
const h2 = @import("h2_native.zig");
const Deadline = @import("read_deadline.zig").Deadline;

pub const Head = struct {
    status_code: u16,
    content_type: []const u8,
    headers: []const h2.Header,
    content_length: ?usize,
};

pub const Sink = struct {
    context: *anyopaque,
    begin: *const fn (*anyopaque, std.mem.Allocator, Head) anyerror!void,
    data: *const fn (*anyopaque, []const u8, Deadline) anyerror!void,
    status: ?u16 = null,

    pub fn start(self: *Sink, allocator: std.mem.Allocator, head: Head) !void {
        std.debug.assert(self.status == null);
        try self.begin(self.context, allocator, head);
        self.status = head.status_code;
    }
};

pub threadlocal var active: ?*Sink = null;

// One origin worker fills the slot. The connection owns it until the whole
// chunk fits through both windows, then wakes the worker for the next read.
pub const Slot = struct {
    const State = enum(u32) { empty, ready, closed };
    pub const Message = union(enum) { head: []const u8, data: usize };
    const max_chunk = 16 * 1024;
    state: std.atomic.Value(State) = .init(.empty),
    value: Message = undefined,
    bytes: [max_chunk]u8 = undefined,

    pub fn init(head: []const u8) Slot {
        return .{ .state = .init(.ready), .value = .{ .head = head } };
    }

    pub fn next(self: *const Slot) ?Message {
        return if (self.state.load(.acquire) == .ready) self.value else null;
    }

    pub fn waitForEmpty(self: *Slot, io: std.Io, limit: Deadline) !void {
        const timeout: std.Io.Timeout = if (limit.at) |at| .{ .deadline = .{ .raw = at, .clock = .awake } } else .none;
        while (true) switch (self.state.load(.acquire)) {
            .empty => return,
            .closed => return error.Canceled,
            .ready => {
                if (limit.expired(.now(io, .awake))) return error.Http2BackpressureTimeout;
                try io.futexWaitTimeout(State, &self.state.raw, .ready, timeout);
            },
        };
    }

    pub fn publish(self: *Slot, io: std.Io, input: []const u8, limit: Deadline) !void {
        if (input.len == 0 or input.len > self.bytes.len) return error.InvalidResponseChunk;
        try self.waitForEmpty(io, limit);
        @memcpy(self.bytes[0..input.len], input);
        self.value = .{ .data = input.len };
        if (self.state.cmpxchgStrong(.empty, .ready, .release, .monotonic) != null) return error.Canceled;
    }

    pub fn consume(self: *Slot, io: std.Io) void {
        std.debug.assert(self.state.load(.monotonic) == .ready);
        self.state.store(.empty, .release);
        io.futexWake(State, &self.state.raw, 1);
    }

    pub fn close(self: *Slot, io: std.Io) void {
        self.state.store(.closed, .release);
        io.futexWake(State, &self.state.raw, 1);
    }
};

test "a ready chunk cannot be replaced before it is consumed" {
    const io = std.testing.io;
    var slot = Slot.init("head");
    var payload = [_]u8{ 'a', 'b' };
    try std.testing.expectEqualStrings("head", slot.next().?.head);
    try std.testing.expectError(error.Http2BackpressureTimeout, slot.publish(io, &payload, .{ .at = .zero }));
    slot.consume(io);
    try slot.publish(io, &payload, .{});
    payload[0] = 'c';
    try std.testing.expectEqualStrings("ab", slot.bytes[0..slot.next().?.data]);
    slot.consume(io);
    try slot.publish(io, &payload, .{});
    try std.testing.expectEqualStrings("cb", slot.bytes[0..slot.next().?.data]);
}

test "closing an occupied slot wakes an origin producer" {
    const Test = struct {
        fn run(io: std.Io, slot: *Slot) !void {
            try slot.publish(io, "waiting", .{});
        }
    };
    const io = std.testing.io;
    var slot = Slot.init("head");
    var worker = try io.concurrent(Test.run, .{ io, &slot });
    slot.close(io);
    try std.testing.expectError(error.Canceled, worker.await(io));
    try std.testing.expect(slot.next() == null);
}
