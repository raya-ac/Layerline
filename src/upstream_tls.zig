const std = @import("std");
const Client = @import("upstream_tls_client.zig");
const policy = @import("upstream_certificate.zig");

pub const RawRead = *const fn (std.Io.net.Stream, []u8) anyerror!usize;
pub const RawWrite = *const fn (std.Io.net.Stream, []const u8) anyerror!void;
pub const CheckProgress = *const fn (std.Io.net.Stream) anyerror!void;
// Certificate verification and the vendored handshake use bounded stack scratch
// in Debug too. Callers must provide this floor, including existing reload workers.
pub const handshake_stack_bytes = 1024 * 1024;
pub const max_handshakes = 32;
var handshakes: std.atomic.Value(usize) = .init(0);

fn reserveHandshake() !void {
    var count = handshakes.load(.acquire);
    while (count < max_handshakes) count = handshakes.cmpxchgWeak(count, count + 1, .acq_rel, .acquire) orelse return;
    return error.BackendCapacity;
}
const ErrorCode = std.meta.Int(.unsigned, @bitSizeOf(anyerror));

threadlocal var active: ?*Channel = null;

pub fn bind(channel: ?*Channel) ?*Channel {
    const previous = active;
    active = channel;
    return previous;
}

pub fn current() ?*Channel {
    return active;
}

pub fn forStream(stream: std.Io.net.Stream) ?*Channel {
    const channel = active orelse return null;
    return if (channel.stream.socket.handle == stream.socket.handle) channel else null;
}

pub const Channel = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    raw_read: RawRead,
    raw_write: RawWrite,
    check_progress: CheckProgress,
    client: Client,
    reader: std.Io.Reader,
    writer: std.Io.Writer,
    read_mutex: std.Io.Mutex = .init,
    failed: std.atomic.Value(bool) = .init(false),
    sent_close_notify: bool = false,
    read_error: std.atomic.Value(ErrorCode) = .init(0),
    write_error: std.atomic.Value(ErrorCode) = .init(0),
    input_buffer: [Client.min_buffer_len]u8 = undefined,
    output_buffer: [Client.min_buffer_len]u8 = undefined,
    read_buffer: [Client.min_buffer_len]u8 = undefined,
    write_buffer: [16 * 1024]u8 = undefined,

    pub fn create(allocator: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream, peer_name: []const u8, anchors: []const policy.Certificate, raw_read: RawRead, raw_write: RawWrite, check_progress: CheckProgress) !*Channel {
        const reference = try policy.referenceName(peer_name);
        try reserveHandshake();
        defer _ = handshakes.fetchSub(1, .acq_rel);
        const address = std.Io.net.IpAddress.parse(reference, 0) catch null;
        const self = try allocator.create(Channel);
        errdefer self.destroy();
        self.* = .{ .allocator = allocator, .io = io, .stream = stream, .raw_read = raw_read, .raw_write = raw_write, .check_progress = check_progress, .client = undefined, .reader = undefined, .writer = undefined };
        self.reader = .{ .buffer = &self.input_buffer, .seek = 0, .end = 0, .vtable = &.{ .stream = readRaw } };
        self.writer = .{ .buffer = &self.output_buffer, .vtable = &.{ .drain = writeRaw } };
        var entropy: [Client.Options.entropy_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &entropy);
        io.randomSecure(&entropy) catch |err| switch (err) {
            error.EntropyUnavailable => {
                if (!@import("builtin").is_test) std.debug.print("{{\"event\":\"server.tls_entropy_unavailable\"}}\n", .{});
                return error.BackendCapacity;
            },
            else => return err,
        };
        const handshake_buffer = try allocator.alloc(u8, Client.max_handshake_bytes);
        defer allocator.free(handshake_buffer);
        self.client = Client.init(&self.reader, &self.writer, .{
            .io = io,
            .server_name = if (address == null) reference else null,
            .peer_identity = reference,
            .anchors = anchors,
            .progress_context = self,
            .check_progress = progress,
            .read_buffer = &self.read_buffer,
            .write_buffer = &self.write_buffer,
            .handshake_buffer = handshake_buffer,
            .entropy = &entropy,
            .realtime_now = .now(io, .real),
        }) catch |err| return self.wireError(err);
        try self.check_progress(stream);
        return self;
    }

    // The connection lease owns the socket. Destroy only after both tunnel
    // pumps have joined and no thread can still borrow this state.
    pub fn destroy(self: *Channel) void {
        const allocator = self.allocator;
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        allocator.destroy(self);
    }

    pub fn read(self: *Channel, output: []u8) !usize {
        self.read_mutex.lockUncancelable(self.io);
        defer self.read_mutex.unlock(self.io);
        if (self.failed.load(.acquire)) return error.TlsSessionFailed;
        errdefer self.failed.store(true, .release);
        if (output.len == 0) return 0;
        while (self.client.reader.bufferedLen() == 0) {
            try self.check_progress(self.stream);
            self.client.reader.fillMore() catch |err| switch (err) {
                error.EndOfStream => {
                    try self.check_progress(self.stream);
                    return 0;
                },
                else => return self.failure(err, true),
            };
        }
        try self.check_progress(self.stream);
        const available = self.client.reader.buffered();
        const n = @min(output.len, available.len);
        @memcpy(output[0..n], available[0..n]);
        self.client.reader.toss(n);
        return n;
    }

    pub fn write(self: *Channel, bytes: []const u8, accepted: *usize) !void {
        self.client.write_mutex.lockUncancelable(self.io);
        defer self.client.write_mutex.unlock(self.io);
        if (self.failed.load(.acquire) or self.sent_close_notify) return error.TlsSessionFailed;
        errdefer self.failed.store(true, .release);
        var offset: usize = 0;
        while (offset < bytes.len) {
            try self.check_progress(self.stream);
            const part = bytes[offset..][0..@min(bytes.len - offset, self.write_buffer.len)];
            self.client.writer.writeAll(part) catch |err| return self.failure(err, false);
            self.client.writer.flush() catch |err| return self.failure(err, false);
            self.writer.flush() catch |err| return self.wireError(err);
            accepted.* +|= part.len;
            offset += part.len;
            try self.check_progress(self.stream);
        }
    }

    pub fn end(self: *Channel) !void {
        self.client.write_mutex.lockUncancelable(self.io);
        defer self.client.write_mutex.unlock(self.io);
        if (self.failed.load(.acquire)) return error.TlsSessionFailed;
        if (self.sent_close_notify) return;
        errdefer self.failed.store(true, .release);
        try self.check_progress(self.stream);
        self.client.end() catch |err| return self.failure(err, false);
        self.writer.flush() catch |err| return self.wireError(err);
        self.sent_close_notify = true;
    }

    pub fn quiet(self: *const Channel) bool {
        return !self.failed.load(.acquire) and !self.sent_close_notify and !self.client.eof() and
            self.client.reader.bufferedLen() == 0 and self.reader.bufferedLen() == 0 and
            self.client.post_header_used == 0 and
            self.client.writer.end == 0 and self.writer.end == 0;
    }

    fn progress(context: *anyopaque) !void {
        const self: *Channel = @ptrCast(@alignCast(context));
        try self.check_progress(self.stream);
    }

    fn wireError(self: *const Channel, fallback: anyerror) anyerror {
        const read_error = self.read_error.load(.acquire);
        if (read_error != 0) return @errorFromInt(read_error);
        const write_error = self.write_error.load(.acquire);
        if (write_error != 0) return @errorFromInt(write_error);
        return fallback;
    }

    fn failure(self: *const Channel, fallback: anyerror, comptime reading: bool) anyerror {
        if (reading) if (self.client.read_err) |err| return self.wireError(err);
        if (self.client.key_exhausted.load(.acquire)) return self.wireError(error.TlsKeyLimit);
        if (self.client.sequence_exhausted.load(.acquire)) return self.wireError(error.TlsSequenceOverflow);
        return self.wireError(fallback);
    }

    fn readRaw(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *Channel = @alignCast(@fieldParentPtr("reader", reader));
        const output = limit.slice(try writer.writableSliceGreedy(1));
        if (output.len == 0) return 0;
        const n = self.raw_read(self.stream, output) catch |err| {
            self.read_error.store(@intFromError(err), .release);
            return error.ReadFailed;
        };
        if (n == 0) return error.EndOfStream;
        writer.advance(n);
        return n;
    }

    fn writeRaw(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Channel = @alignCast(@fieldParentPtr("writer", writer));
        self.raw_write(self.stream, writer.buffered()) catch |err| {
            self.write_error.store(@intFromError(err), .release);
            return error.WriteFailed;
        };
        writer.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |part| {
            self.raw_write(self.stream, part) catch |err| {
                self.write_error.store(@intFromError(err), .release);
                return error.WriteFailed;
            };
            n += part.len;
        }
        for (0..splat) |_| {
            const part = data[data.len - 1];
            self.raw_write(self.stream, part) catch |err| {
                self.write_error.store(@intFromError(err), .release);
                return error.WriteFailed;
            };
            n += part.len;
        }
        return n;
    }
};

test "origin handshake admission is bounded and rejection does not steal a slot" {
    try std.testing.expectEqual(0, handshakes.load(.acquire));
    defer handshakes.store(0, .release);
    for (0..max_handshakes) |_| try reserveHandshake();
    try std.testing.expectError(error.BackendCapacity, reserveHandshake());
    try std.testing.expectEqual(max_handshakes, handshakes.load(.acquire));
    _ = handshakes.fetchSub(1, .acq_rel);
    try reserveHandshake();
    try std.testing.expectEqual(max_handshakes, handshakes.load(.acquire));
}

test "missing secure entropy releases handshake admission without writing or falling back" {
    const Fake = struct {
        fn entropy(_: ?*anyopaque, _: []u8) std.Io.RandomSecureError!void {
            return error.EntropyUnavailable;
        }
        fn read(_: std.Io.net.Stream, _: []u8) !usize {
            return error.UnexpectedRead;
        }
        fn write(_: std.Io.net.Stream, _: []const u8) !void {
            return error.UnexpectedWrite;
        }
        fn progress(_: std.Io.net.Stream) !void {
            return error.UnexpectedProgress;
        }
    };
    var vtable = std.testing.io.vtable.*;
    vtable.randomSecure = Fake.entropy;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    try std.testing.expectError(error.BackendCapacity, Channel.create(std.testing.allocator, io, .{ .socket = .{ .handle = 123, .address = undefined } }, "example.test", &.{}, Fake.read, Fake.write, Fake.progress));
    try std.testing.expectEqual(0, handshakes.load(.acquire));
}
