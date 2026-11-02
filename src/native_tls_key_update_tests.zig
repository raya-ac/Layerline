const std = @import("std");
const runtime = @import("native_tls_runtime.zig");
const tls = @import("tls13_native.zig");
const deadline = @import("write_deadline.zig");
const max_records = @import("upstream_tls_client.zig").max_key_records;

const Peer = struct {
    allocator: std.mem.Allocator = std.testing.allocator,
    input: std.ArrayList(u8) = .empty,
    output: std.ArrayList(u8) = .empty,
    offset: usize = 0,
    reads: usize = 0,
    read_limit: usize = 3,
    interrupt_at: ?usize = null,
    interrupt: anyerror = error.DispatchReady,
    write_failure: ?anyerror = null,
    note_budget: bool = false,
    armed_budget: bool = false,
    writer_entered: std.Io.Event = .unset,
    writer_release: std.Io.Event = .unset,
    block_write: bool = false,

    var active: *Peer = undefined;

    fn channel(self: *Peer) runtime.Channel {
        active = self;
        return .{ .io = std.testing.io, .stream = .{ .socket = .{ .handle = 123, .address = undefined } }, .allocator = self.allocator, .client_application_keys = tls.deriveTlsRecordKeys(@splat(0x43)), .server_application_keys = tls.deriveTlsRecordKeys(@splat(0x53)), .client_application_secret = @splat(0x43), .server_application_secret = @splat(0x53), .raw_read = read, .raw_write_all = write };
    }

    fn deinit(self: *Peer) void {
        self.input.deinit(self.allocator);
        self.output.deinit(self.allocator);
    }

    fn record(self: *Peer, secret: [32]u8, sequence: u64, kind: u8, payload: []const u8) !void {
        const bytes = try tls.encryptTlsRecord(self.allocator, tls.deriveTlsRecordKeys(secret), sequence, kind, payload);
        defer self.allocator.free(bytes);
        try self.input.appendSlice(self.allocator, bytes);
    }

    fn read(_: std.Io.net.Stream, out: []u8) !usize {
        const self = active;
        if (self.interrupt_at) |offset| if (self.offset == offset) {
            self.interrupt_at = null;
            return self.interrupt;
        };
        const n = @min(out.len, self.input.items.len - self.offset, self.read_limit);
        @memcpy(out[0..n], self.input.items[self.offset..][0..n]);
        self.offset += n;
        self.reads += 1;
        return n;
    }

    fn write(stream: std.Io.net.Stream, bytes: []const u8) !void {
        const self = active;
        if (self.block_write) {
            self.block_write = false;
            self.writer_entered.set(std.testing.io);
            self.writer_release.waitUncancelable(std.testing.io);
        }
        if (self.note_budget) {
            _ = deadline.startWrite(stream);
            self.armed_budget = deadline.started(stream);
        }
        if (self.write_failure) |err| {
            try self.output.appendSlice(self.allocator, bytes[0..@min(bytes.len, 6)]);
            return err;
        }
        try self.output.appendSlice(self.allocator, bytes);
    }

    fn expectRecord(self: *Peer, at: *usize, secret: [32]u8, sequence: u64, kind: u8, expected: []const u8) !void {
        try std.testing.expect(self.output.items.len >= at.* + 5);
        const len = std.mem.readInt(u16, self.output.items[at.* + 3 ..][0..2], .big);
        var decoded = try tls.decryptTlsRecord(self.allocator, tls.deriveTlsRecordKeys(secret), sequence, self.output.items[at.*..][0 .. 5 + len]);
        defer decoded.deinit(self.allocator);
        try std.testing.expectEqual(kind, decoded.content_type);
        try std.testing.expectEqualSlices(u8, expected, decoded.payload);
        at.* += 5 + len;
    }
};

test "requested and unrequested native key updates preserve generations and record boundaries" {
    const update = [_]u8{ 0x18, 0, 0, 1, 0 };
    for ([_]bool{ false, true }) |requested| {
        for (0..5) |split| {
            var peer: Peer = .{};
            defer peer.deinit();
            var channel = peer.channel();
            defer channel.deinit();
            var message = update;
            message[4] = @intFromBool(requested);
            var sequence: u64 = 0;
            if (split != 0) {
                try peer.record(@splat(0x43), sequence, 0x16, message[0..split]);
                sequence += 1;
            }
            try peer.record(@splat(0x43), sequence, 0x16, message[split..]);
            const client_next = tls.nextTlsTrafficSecret(@splat(0x43));
            try peer.record(client_next, 0, 0x17, "after update");
            var data: [64]u8 = undefined;
            const n = try runtime.readApplicationData(&channel, &data);
            try std.testing.expectEqualStrings("after update", data[0..n]);
            try std.testing.expectEqual(1, channel.client_sequence);
            try std.testing.expectEqualSlices(u8, &client_next, &channel.client_application_secret.?);
            var offset: usize = 0;
            if (requested) try peer.expectRecord(&offset, @splat(0x53), 0, 0x16, &.{ 0x18, 0, 0, 1, 0 });
            const server_secret = if (requested) tls.nextTlsTrafficSecret(@splat(0x53)) else @as([32]u8, @splat(0x53));
            try runtime.writeApplicationData(&channel, "reply");
            try peer.expectRecord(&offset, server_secret, 0, 0x17, "reply");
            try std.testing.expectEqual(peer.output.items.len, offset);
        }
    }
}

test "partial key-update messages survive both soft read interruptions" {
    for ([_]anyerror{ error.RequestTimeout, error.DispatchReady }) |pause| {
        for (1..5) |split| {
            var peer: Peer = .{};
            defer peer.deinit();
            var channel = peer.channel();
            defer channel.deinit();
            const update = [_]u8{ 0x18, 0, 0, 1, 1 };
            try peer.record(@splat(0x43), 0, 0x16, update[0..split]);
            peer.interrupt_at = peer.input.items.len;
            peer.interrupt = pause;
            try peer.record(@splat(0x43), 1, 0x16, update[split..]);
            try peer.record(tls.nextTlsTrafficSecret(@splat(0x43)), 0, 0x17, "resumed");
            var data: [32]u8 = undefined;
            try std.testing.expectError(pause, runtime.readApplicationData(&channel, &data));
            try std.testing.expectEqual(split, channel.post_handshake_used);
            try std.testing.expect(!channel.failed.load(.acquire));
            const n = try runtime.readApplicationData(&channel, &data);
            try std.testing.expectEqualStrings("resumed", data[0..n]);
        }
    }
}

test "bad key updates fail closed with an authenticated alert" {
    const malformed = [_][]const u8{ "", "\x18\x00\x00\x01\x02", "\x18\x00\x00\x02\x00", "\x04\x00\x00\x01\x00", "\x18\x00\x00\x01\x00\x18\x00\x00\x01\x00" };
    for (malformed) |payload| {
        var peer: Peer = .{};
        defer peer.deinit();
        var channel = peer.channel();
        defer channel.deinit();
        try peer.record(@splat(0x43), 0, 0x16, payload);
        var data: [16]u8 = undefined;
        if (runtime.readApplicationData(&channel, &data)) |_| return error.BadUpdateAccepted else |_| {}
        try std.testing.expect(channel.failed.load(.acquire));
        var offset: usize = 0;
        const description: u8 = if (payload.len == 5 and payload[0] == 0x18) 47 else 10;
        try peer.expectRecord(&offset, @splat(0x53), 0, 0x15, &.{ 2, description });
        try std.testing.expectEqual(offset, peer.output.items.len);
        try std.testing.expectError(error.TlsSessionFailed, runtime.writeApplicationData(&channel, "late"));
        try std.testing.expectError(error.TlsSessionFailed, runtime.end(&channel));
    }
}

test "a key update cannot be interleaved replayed or skipped" {
    for (0..3) |mode| {
        var peer: Peer = .{};
        defer peer.deinit();
        var channel = peer.channel();
        defer channel.deinit();
        const update = [_]u8{ 0x18, 0, 0, 1, 0 };
        if (mode == 0) {
            try peer.record(@splat(0x43), 0, 0x16, update[0..2]);
            try peer.record(@splat(0x43), 1, 0x17, "interleaved");
        } else if (mode == 1) {
            try peer.record(@splat(0x43), 0, 0x16, &update);
            try peer.record(@splat(0x43), 1, 0x17, "stale key");
        } else {
            try peer.record(tls.nextTlsTrafficSecret(@splat(0x43)), 0, 0x17, "unannounced key");
        }
        var data: [32]u8 = undefined;
        if (runtime.readApplicationData(&channel, &data)) |_| return error.KeyBoundaryWasIgnored else |_| {}
        try std.testing.expect(channel.failed.load(.acquire));
    }
}

test "native output rotates before the hard per-key record limit" {
    var peer: Peer = .{};
    defer peer.deinit();
    var channel = peer.channel();
    defer channel.deinit();
    channel.server_sequence = max_records - 1;
    var accepted: usize = 0;
    try runtime.writeApplicationDataCounted(&channel, "body", &accepted);
    try std.testing.expectEqual(4, accepted);
    var offset: usize = 0;
    try peer.expectRecord(&offset, @splat(0x53), max_records - 1, 0x16, &.{ 0x18, 0, 0, 1, 0 });
    const next = tls.nextTlsTrafficSecret(@splat(0x53));
    try peer.expectRecord(&offset, next, 0, 0x17, "body");
    try runtime.end(&channel);
    try peer.expectRecord(&offset, next, 1, 0x15, &.{ 1, 0 });
    try std.testing.expectEqual(offset, peer.output.items.len);
}

test "a failed key-update reply never resumes the old write generation" {
    for ([_]anyerror{ error.ConnectionResetByPeer, error.RequestTimeout, error.DispatchReady }) |failure| {
        var peer: Peer = .{ .write_failure = failure };
        defer peer.deinit();
        var channel = peer.channel();
        defer channel.deinit();
        try peer.record(@splat(0x43), 0, 0x16, &.{ 0x18, 0, 0, 1, 1 });
        var data: [16]u8 = undefined;
        try std.testing.expectError(failure, runtime.readApplicationData(&channel, &data));
        try std.testing.expect(channel.failed.load(.acquire));
        try std.testing.expectEqual(1, channel.server_sequence);
        try std.testing.expectEqual(6, peer.output.items.len);
        try std.testing.expectError(error.TlsSessionFailed, runtime.end(&channel));
    }
}

test "TLS control replies leave an unstarted HTTP response budget alone" {
    for ([_]bool{ false, true }) |started| {
        var peer: Peer = .{ .note_budget = true };
        defer peer.deinit();
        var channel = peer.channel();
        defer channel.deinit();
        const previous = deadline.pushHttp1(std.testing.io, channel.stream, 100);
        defer deadline.restore(previous);
        if (started) _ = deadline.startWrite(channel.stream);
        const initial = deadline.forStream(channel.stream).?.deadline.at;
        try peer.record(@splat(0x43), 0, 0x16, &.{ 0x18, 0, 0, 1, 1 });
        try peer.record(tls.nextTlsTrafficSecret(@splat(0x43)), 0, 0x17, "body");
        var data: [16]u8 = undefined;
        _ = try runtime.readApplicationData(&channel, &data);
        try std.testing.expectEqual(started, peer.armed_budget);
        try std.testing.expectEqual(initial, deadline.forStream(channel.stream).?.deadline.at);
    }
}

test "native input requests fresh peer keys before exhausting its read budget" {
    var peer: Peer = .{};
    defer peer.deinit();
    var channel = peer.channel();
    defer channel.deinit();
    channel.client_sequence = max_records - 1025;
    try peer.record(@splat(0x43), channel.client_sequence, 0x17, "old");
    try peer.record(@splat(0x43), channel.client_sequence + 1, 0x16, &.{ 0x18, 0, 0, 1, 0 });
    try peer.record(tls.nextTlsTrafficSecret(@splat(0x43)), 0, 0x17, "new");
    var data: [16]u8 = undefined;
    const first = try runtime.readApplicationData(&channel, &data);
    try std.testing.expectEqualStrings("old", data[0..first]);
    try std.testing.expect(channel.read_update_requested);
    var offset: usize = 0;
    try peer.expectRecord(&offset, @splat(0x53), 0, 0x16, &.{ 0x18, 0, 0, 1, 1 });
    const second = try runtime.readApplicationData(&channel, &data);
    try std.testing.expectEqualStrings("new", data[0..second]);
    try std.testing.expect(!channel.read_update_requested);
    try std.testing.expectEqual(1, channel.client_sequence);
    try std.testing.expectEqual(offset, peer.output.items.len);
}

test "key updates after local half-close cannot reopen output" {
    var peer: Peer = .{};
    defer peer.deinit();
    var channel = peer.channel();
    defer channel.deinit();
    try runtime.end(&channel);
    const closed_length = peer.output.items.len;
    try peer.record(@splat(0x43), 0, 0x16, &.{ 0x18, 0, 0, 1, 1 });
    try peer.record(tls.nextTlsTrafficSecret(@splat(0x43)), 0, 0x17, "final peer bytes");
    var data: [32]u8 = undefined;
    const n = try runtime.readApplicationData(&channel, &data);
    try std.testing.expectEqualStrings("final peer bytes", data[0..n]);
    try std.testing.expectEqual(closed_length, peer.output.items.len);
    try std.testing.expectError(error.TlsSessionFailed, runtime.writeApplicationData(&channel, "late"));
}

test "a backpressured writer does not stop key-update input and replies before its next record" {
    const Writer = struct {
        channel: *runtime.Channel,
        payload: []const u8,
        result: ?anyerror = null,
        accepted: usize = 0,
        fn run(self: *@This()) void {
            runtime.writeApplicationDataCounted(self.channel, self.payload, &self.accepted) catch |err| {
                self.result = err;
            };
        }
    };
    for ([_]usize{ 10, 20000 }) |size| {
        var peer: Peer = .{ .block_write = true };
        defer peer.deinit();
        var channel = peer.channel();
        defer channel.deinit();
        try peer.record(@splat(0x43), 0, 0x16, &.{ 0x18, 0, 0, 1, 1 });
        try peer.record(tls.nextTlsTrafficSecret(@splat(0x43)), 0, 0x17, "input still moves");
        const payload = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(payload);
        @memset(payload, 0x61);
        var writer: Writer = .{ .channel = &channel, .payload = payload };
        const worker = try std.Thread.spawn(.{ .stack_size = 1024 * 1024 }, Writer.run, .{&writer});
        {
            defer worker.join();
            defer peer.writer_release.set(std.testing.io);
            peer.writer_entered.waitUncancelable(std.testing.io);
            var data: [32]u8 = undefined;
            const n = try runtime.readApplicationData(&channel, &data);
            try std.testing.expectEqualStrings("input still moves", data[0..n]);
            try std.testing.expectEqual(1, channel.pending_key_updates.load(.acquire));
        }
        try std.testing.expect(writer.result == null);
        try std.testing.expectEqual(size, writer.accepted);
        var offset: usize = 0;
        const first = @min(size, 16383);
        try peer.expectRecord(&offset, @splat(0x53), 0, 0x17, payload[0..first]);
        try peer.expectRecord(&offset, @splat(0x53), 1, 0x16, &.{ 0x18, 0, 0, 1, 0 });
        if (size > first) try peer.expectRecord(&offset, tls.nextTlsTrafficSecret(@splat(0x53)), 0, 0x17, payload[first..]);
        try std.testing.expectEqual(offset, peer.output.items.len);
        try std.testing.expectEqual(0, channel.pending_key_updates.load(.acquire));
    }
}

fn allocationFailure(allocator: std.mem.Allocator) !void {
    var peer: Peer = .{ .allocator = allocator };
    defer peer.deinit();
    var channel = peer.channel();
    defer channel.deinit();
    try peer.record(@splat(0x43), 0, 0x16, &.{ 0x18, 0, 0, 1, 1 });
    try peer.record(tls.nextTlsTrafficSecret(@splat(0x43)), 0, 0x17, "body");
    var data: [16]u8 = undefined;
    const n = try runtime.readApplicationData(&channel, &data);
    try std.testing.expectEqualStrings("body", data[0..n]);
    try runtime.writeApplicationData(&channel, "reply");
}

test "key-update reassembly and replies release every failed allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailure, .{});
}
