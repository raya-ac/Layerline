const std = @import("std");

pub const PacketNumber = u64;
pub const StreamId = u64;

pub const max_packet_number: PacketNumber = (@as(PacketNumber, 1) << 62) - 1;

pub const Error = error{
    InvalidRange,
    RangeCapacityExceeded,
    PacketNumberOverflow,
    StreamOffsetOverflow,
    StreamBufferTooSmall,
    FinalSizeMismatch,
    DataBeyondFinalSize,
    ConflictingStreamData,
};

pub const Http3FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0d,
};

pub fn knownFrameType(raw: u64) ?Http3FrameType {
    return switch (raw) {
        @intFromEnum(Http3FrameType.data) => .data,
        @intFromEnum(Http3FrameType.headers) => .headers,
        @intFromEnum(Http3FrameType.cancel_push) => .cancel_push,
        @intFromEnum(Http3FrameType.settings) => .settings,
        @intFromEnum(Http3FrameType.push_promise) => .push_promise,
        @intFromEnum(Http3FrameType.goaway) => .goaway,
        @intFromEnum(Http3FrameType.max_push_id) => .max_push_id,
        else => null,
    };
}

pub const FrameHeader = struct {
    raw_type: u64,
    payload_length: u64,

    pub fn typed(self: FrameHeader) ?Http3FrameType {
        return knownFrameType(self.raw_type);
    }
};

pub const InclusiveRange = struct {
    first: u64,
    last: u64,

    pub fn init(first: u64, last: u64) Error!InclusiveRange {
        if (last < first) return error.InvalidRange;
        return .{ .first = first, .last = last };
    }

    pub fn single(value: u64) InclusiveRange {
        return .{ .first = value, .last = value };
    }

    pub fn contains(self: InclusiveRange, value: u64) bool {
        return value >= self.first and value <= self.last;
    }

    pub fn containsRange(self: InclusiveRange, other: InclusiveRange) bool {
        return other.first >= self.first and other.last <= self.last;
    }

    pub fn ackRangeLength(self: InclusiveRange) u64 {
        return self.last - self.first;
    }
};

pub const AckRange = InclusiveRange;
pub const ByteRange = InclusiveRange;

pub const AckBlock = struct {
    gap: u64,
    range_length: u64,
};

pub fn AckFrame(comptime max_blocks: usize) type {
    return struct {
        largest_acknowledged: PacketNumber,
        ack_delay: u64,
        first_ack_range: u64,
        blocks: [max_blocks]AckBlock = undefined,
        block_count: usize = 0,

        const Self = @This();

        pub fn blockSlice(self: *const Self) []const AckBlock {
            return self.blocks[0..self.block_count];
        }
    };
}

pub fn RangeSet(comptime capacity: usize) type {
    return struct {
        ranges: [capacity]InclusiveRange = undefined,
        len: usize = 0,

        const Self = @This();

        pub fn init() Self {
            return .{ .ranges = undefined, .len = 0 };
        }

        pub fn asSlice(self: *const Self) []const InclusiveRange {
            return self.ranges[0..self.len];
        }

        pub fn contains(self: *const Self, value: u64) bool {
            for (self.asSlice()) |range| {
                if (range.contains(value)) return true;
                if (value < range.first) return false;
            }
            return false;
        }

        pub fn containsRange(self: *const Self, range: InclusiveRange) bool {
            for (self.asSlice()) |existing| {
                if (existing.containsRange(range)) return true;
                if (range.last < existing.first) return false;
            }
            return false;
        }

        pub fn insert(self: *Self, range: InclusiveRange) Error!void {
            var merged = range;
            var index: usize = 0;

            while (index < self.len) {
                const existing = self.ranges[index];
                if (canMerge(existing, merged)) {
                    merged = mergeRanges(existing, merged);
                    self.removeAt(index);
                    continue;
                }

                if (existing.first > merged.last) break;
                index += 1;
            }

            var insert_at: usize = 0;
            while (insert_at < self.len and self.ranges[insert_at].first < merged.first) {
                insert_at += 1;
            }

            if (self.len == capacity) return error.RangeCapacityExceeded;
            if (insert_at < self.len) {
                std.mem.copyBackwards(
                    InclusiveRange,
                    self.ranges[insert_at + 1 .. self.len + 1],
                    self.ranges[insert_at..self.len],
                );
            }
            self.ranges[insert_at] = merged;
            self.len += 1;
        }

        pub fn largest(self: *const Self) ?u64 {
            if (self.len == 0) return null;
            return self.ranges[self.len - 1].last;
        }

        pub fn toAckFrame(self: *const Self, ack_delay: u64) ?AckFrame(capacity) {
            if (self.len == 0) return null;

            const largest_range = self.ranges[self.len - 1];
            var frame = AckFrame(capacity){
                .largest_acknowledged = largest_range.last,
                .ack_delay = ack_delay,
                .first_ack_range = largest_range.ackRangeLength(),
            };

            var previous_first = largest_range.first;
            var source_index = self.len - 1;
            while (source_index > 0) {
                source_index -= 1;
                const current = self.ranges[source_index];
                frame.blocks[frame.block_count] = .{
                    .gap = previous_first - current.last - 2,
                    .range_length = current.ackRangeLength(),
                };
                frame.block_count += 1;
                previous_first = current.first;
            }

            return frame;
        }

        fn removeAt(self: *Self, index: usize) void {
            if (index + 1 < self.len) {
                std.mem.copyForwards(
                    InclusiveRange,
                    self.ranges[index .. self.len - 1],
                    self.ranges[index + 1 .. self.len],
                );
            }
            self.len -= 1;
        }
    };
}

pub const PacketObservation = enum {
    new_packet,
    duplicate,
};

pub fn PacketNumberSpace(comptime max_ack_ranges: usize) type {
    return struct {
        next_packet_number: PacketNumber = 0,
        largest_received: ?PacketNumber = null,
        received: RangeSet(max_ack_ranges) = RangeSet(max_ack_ranges).init(),
        ack_eliciting_since_last_ack: bool = false,

        const Self = @This();

        pub fn init() Self {
            return .{};
        }

        pub fn takeNext(self: *Self) Error!PacketNumber {
            if (self.next_packet_number > max_packet_number) return error.PacketNumberOverflow;

            const packet_number = self.next_packet_number;
            self.next_packet_number += 1;
            return packet_number;
        }

        pub fn observeReceived(
            self: *Self,
            packet_number: PacketNumber,
            ack_eliciting: bool,
        ) Error!PacketObservation {
            if (packet_number > max_packet_number) return error.PacketNumberOverflow;

            if (self.received.contains(packet_number)) {
                return .duplicate;
            }

            try self.received.insert(AckRange.single(packet_number));
            if (self.largest_received == null or packet_number > self.largest_received.?) {
                self.largest_received = packet_number;
            }
            self.ack_eliciting_since_last_ack = self.ack_eliciting_since_last_ack or ack_eliciting;

            return .new_packet;
        }

        pub fn ackFrame(self: *const Self, ack_delay: u64) ?AckFrame(max_ack_ranges) {
            return self.received.toAckFrame(ack_delay);
        }

        pub fn markAckSent(self: *Self) void {
            self.ack_eliciting_since_last_ack = false;
        }
    };
}

pub const StreamReceiveResult = struct {
    inserted_bytes: usize,
    duplicate_bytes: usize,
    contiguous_bytes: usize,
    final_size: ?u64,
    fully_received: bool,
};

pub fn StreamReceiveState(comptime max_ranges: usize, comptime max_buffer_bytes: usize) type {
    return struct {
        stream_id: StreamId,
        buffer: [max_buffer_bytes]u8 = undefined,
        received: RangeSet(max_ranges) = RangeSet(max_ranges).init(),
        read_offset: u64 = 0,
        final_size: ?u64 = null,

        const Self = @This();

        pub fn init(stream_id: StreamId) Self {
            return .{
                .stream_id = stream_id,
                .buffer = undefined,
                .received = RangeSet(max_ranges).init(),
                .read_offset = 0,
                .final_size = null,
            };
        }

        pub fn receive(
            self: *Self,
            offset: u64,
            data: []const u8,
            fin: bool,
        ) Error!StreamReceiveResult {
            const end = try checkedEndOffset(offset, data.len);
            if (end > @as(u64, @intCast(max_buffer_bytes))) return error.StreamBufferTooSmall;

            if (fin) {
                if (self.final_size) |known| {
                    if (known != end) return error.FinalSizeMismatch;
                } else {
                    self.final_size = end;
                }
            }

            if (self.final_size) |known| {
                if (end > known) return error.DataBeyondFinalSize;
            }

            var inserted_bytes: usize = 0;
            var duplicate_bytes: usize = 0;

            for (data, 0..) |byte, i| {
                const absolute = offset + @as(u64, @intCast(i));
                const index: usize = @intCast(absolute);
                if (self.received.contains(absolute)) {
                    duplicate_bytes += 1;
                    if (self.buffer[index] != byte) return error.ConflictingStreamData;
                } else {
                    inserted_bytes += 1;
                }
            }

            const start_index: usize = @intCast(offset);
            const end_index: usize = @intCast(end);
            @memcpy(self.buffer[start_index..end_index], data);

            if (data.len > 0) {
                try self.received.insert(try ByteRange.init(offset, end - 1));
            }

            return .{
                .inserted_bytes = inserted_bytes,
                .duplicate_bytes = duplicate_bytes,
                .contiguous_bytes = self.contiguousAvailable(),
                .final_size = self.final_size,
                .fully_received = self.isFullyReceived(),
            };
        }

        pub fn contiguousAvailable(self: *const Self) usize {
            for (self.received.asSlice()) |range| {
                if (range.contains(self.read_offset)) {
                    return @intCast(range.last - self.read_offset + 1);
                }
                if (self.read_offset < range.first) return 0;
            }
            return 0;
        }

        pub fn contiguousSlice(self: *const Self) []const u8 {
            const available = self.contiguousAvailable();
            const start: usize = @intCast(self.read_offset);
            return self.buffer[start .. start + available];
        }

        pub fn read(self: *Self, out: []u8) []u8 {
            const available = @min(out.len, self.contiguousAvailable());
            const start: usize = @intCast(self.read_offset);
            @memcpy(out[0..available], self.buffer[start .. start + available]);
            self.read_offset += @as(u64, @intCast(available));
            return out[0..available];
        }

        pub fn isFullyReceived(self: *const Self) bool {
            const size = self.final_size orelse return false;
            if (size == 0) return true;
            return self.received.containsRange(.{ .first = 0, .last = size - 1 });
        }

        pub fn isClosed(self: *const Self) bool {
            const size = self.final_size orelse return false;
            return self.read_offset == size;
        }
    };
}

fn canMerge(a: InclusiveRange, b: InclusiveRange) bool {
    return !endsBefore(a, b) and !endsBefore(b, a);
}

fn endsBefore(a: InclusiveRange, b: InclusiveRange) bool {
    return a.last != std.math.maxInt(u64) and a.last + 1 < b.first;
}

fn mergeRanges(a: InclusiveRange, b: InclusiveRange) InclusiveRange {
    return .{
        .first = @min(a.first, b.first),
        .last = @max(a.last, b.last),
    };
}

fn checkedEndOffset(offset: u64, len: usize) Error!u64 {
    const len64: u64 = @intCast(len);
    if (offset > std.math.maxInt(u64) - len64) return error.StreamOffsetOverflow;
    return offset + len64;
}

test "known HTTP/3 frame types are typed without rejecting extensions" {
    const data = FrameHeader{ .raw_type = 0x00, .payload_length = 12 };
    const extension = FrameHeader{ .raw_type = 0x21, .payload_length = 4 };

    try std.testing.expectEqual(Http3FrameType.data, data.typed().?);
    try std.testing.expectEqual(@as(?Http3FrameType, null), extension.typed());
}

test "range set merges adjacent ack ranges and reports largest packet" {
    var ranges = RangeSet(4).init();

    try ranges.insert(AckRange.single(10));
    try ranges.insert(AckRange.single(12));
    try ranges.insert(AckRange.single(11));
    try ranges.insert(try AckRange.init(1, 2));

    try std.testing.expectEqual(@as(usize, 2), ranges.asSlice().len);
    try std.testing.expectEqual(AckRange{ .first = 1, .last = 2 }, ranges.asSlice()[0]);
    try std.testing.expectEqual(AckRange{ .first = 10, .last = 12 }, ranges.asSlice()[1]);
    try std.testing.expectEqual(@as(?u64, 12), ranges.largest());
}

test "ack frame view produces QUIC gap and range lengths" {
    var ranges = RangeSet(4).init();
    try ranges.insert(try AckRange.init(1, 2));
    try ranges.insert(try AckRange.init(4, 6));
    try ranges.insert(try AckRange.init(10, 10));

    const frame = ranges.toAckFrame(7).?;
    try std.testing.expectEqual(@as(u64, 10), frame.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 7), frame.ack_delay);
    try std.testing.expectEqual(@as(u64, 0), frame.first_ack_range);
    try std.testing.expectEqual(@as(usize, 2), frame.blockSlice().len);
    try std.testing.expectEqual(AckBlock{ .gap = 2, .range_length = 2 }, frame.blockSlice()[0]);
    try std.testing.expectEqual(AckBlock{ .gap = 0, .range_length = 1 }, frame.blockSlice()[1]);
}

test "packet number space tracks outgoing and received packet numbers" {
    var space = PacketNumberSpace(8).init();

    try std.testing.expectEqual(@as(PacketNumber, 0), try space.takeNext());
    try std.testing.expectEqual(@as(PacketNumber, 1), try space.takeNext());
    try std.testing.expectEqual(PacketObservation.new_packet, try space.observeReceived(5, true));
    try std.testing.expectEqual(PacketObservation.duplicate, try space.observeReceived(5, true));
    try std.testing.expectEqual(@as(?PacketNumber, 5), space.largest_received);
    try std.testing.expect(space.ack_eliciting_since_last_ack);

    const frame = space.ackFrame(0).?;
    try std.testing.expectEqual(@as(PacketNumber, 5), frame.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 0), frame.first_ack_range);

    space.markAckSent();
    try std.testing.expect(!space.ack_eliciting_since_last_ack);
}

test "stream receive state reassembles out of order data" {
    var stream = StreamReceiveState(8, 64).init(0);

    var result = try stream.receive(6, "world", true);
    try std.testing.expectEqual(@as(usize, 0), result.contiguous_bytes);
    try std.testing.expect(!result.fully_received);

    result = try stream.receive(0, "hello ", false);
    try std.testing.expectEqual(@as(usize, 11), result.contiguous_bytes);
    try std.testing.expect(result.fully_received);
    try std.testing.expectEqualStrings("hello world", stream.contiguousSlice());

    var out: [16]u8 = undefined;
    const read = stream.read(&out);
    try std.testing.expectEqualStrings("hello world", read);
    try std.testing.expect(stream.isClosed());
}

test "stream receive state counts duplicates and rejects conflicting overlaps" {
    var stream = StreamReceiveState(8, 32).init(4);

    var result = try stream.receive(0, "abc", false);
    try std.testing.expectEqual(@as(usize, 3), result.inserted_bytes);
    try std.testing.expectEqual(@as(usize, 0), result.duplicate_bytes);

    result = try stream.receive(1, "bc", false);
    try std.testing.expectEqual(@as(usize, 0), result.inserted_bytes);
    try std.testing.expectEqual(@as(usize, 2), result.duplicate_bytes);

    try std.testing.expectError(error.ConflictingStreamData, stream.receive(1, "Bx", false));
}

test "stream final size rules are stable" {
    var stream = StreamReceiveState(4, 8).init(8);

    _ = try stream.receive(0, "", true);
    try std.testing.expect(stream.isFullyReceived());
    try std.testing.expect(stream.isClosed());

    try std.testing.expectError(error.FinalSizeMismatch, stream.receive(0, "x", true));
    try std.testing.expectError(error.DataBeyondFinalSize, stream.receive(0, "x", false));
}
