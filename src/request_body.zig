const std = @import("std");

const http_headers = @import("http_headers.zig");
const request_trailers = @import("request_trailers.zig");

pub const BodyRead = struct {
    body: []const u8,
    trailers: []const u8 = "",
    discarded_pipeline_bytes: bool,
};

const BufferedBodyReader = struct {
    stream: std.Io.net.Stream,
    buffered: []const u8,
    read_fn: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
    pos: usize = 0,

    fn readByte(self: *BufferedBodyReader) !u8 {
        if (self.pos < self.buffered.len) {
            const byte = self.buffered[self.pos];
            self.pos += 1;
            return byte;
        }

        var one: [1]u8 = undefined;
        const n = try self.read_fn(self.stream, &one);
        if (n == 0) return error.BadRequest;
        return one[0];
    }

    fn readExact(self: *BufferedBodyReader, out: []u8) !void {
        var written: usize = 0;
        while (written < out.len) {
            if (self.pos < self.buffered.len) {
                const available = self.buffered.len - self.pos;
                const n = @min(available, out.len - written);
                @memcpy(out[written .. written + n], self.buffered[self.pos .. self.pos + n]);
                self.pos += n;
                written += n;
                continue;
            }

            const n = try self.read_fn(self.stream, out[written..]);
            if (n == 0) return error.BadRequest;
            written += n;
        }
    }

    fn unreadLen(self: *const BufferedBodyReader) usize {
        return self.buffered.len - self.pos;
    }
};

fn readChunkLineInto(reader: *BufferedBodyReader, line: []u8) ![]const u8 {
    var len: usize = 0;

    while (true) {
        const byte = try reader.readByte();
        if (byte == '\r') {
            if (try reader.readByte() != '\n') return error.BadRequest;
            return line[0..len];
        }
        if (byte == '\n' or len == line.len) return error.BadRequest;
        line[len] = byte;
        len += 1;
    }
}

fn parseChunkSize(line: []const u8) !usize {
    return @import("http_chunked.zig").parseSize(line) catch error.BadRequest;
}

fn readChunkedBody(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    buffer_tail: []const u8,
    max_body_bytes: usize,
    max_chunk_line_bytes: usize,
    max_trailer_bytes: usize,
    headers: []const u8,
    read_fn: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
) !BodyRead {
    var reader = BufferedBodyReader{ .stream = stream, .buffered = buffer_tail, .read_fn = read_fn };
    var body = std.ArrayList(u8).empty;
    errdefer body.deinit(allocator);
    var trailers = std.ArrayList(u8).empty;
    errdefer trailers.deinit(allocator);
    var trailer_budget = max_trailer_bytes;
    var trailer_count: usize = 0;
    const line_buf = try allocator.alloc(u8, max_chunk_line_bytes);
    defer allocator.free(line_buf);

    while (true) {
        const chunk_line = try readChunkLineInto(&reader, line_buf);
        const size = try parseChunkSize(chunk_line);
        if (std.mem.indexOfScalar(u8, chunk_line, ';')) |offset| {
            const extension_bytes = chunk_line.len - offset;
            if (extension_bytes > trailer_budget) return error.RequestTooLarge;
            trailer_budget -= extension_bytes;
        }
        if (size == 0) {
            while (true) {
                const trailer = try readChunkLineInto(&reader, line_buf);
                if (trailer.len == 0) break;
                trailer_count += 1;
                if (trailer_count > http_headers.MAX_HTTP1_HEADER_FIELDS or trailer.len > trailer_budget or
                    32 > trailer_budget - trailer.len) return error.RequestTooLarge;
                trailer_budget -= trailer.len + 32;
                try request_trailers.validateBlock(trailer, headers);
                const colon = std.mem.indexOfScalar(u8, trailer, ':').?;
                if (trailers.items.len != 0) try trailers.appendSlice(allocator, "\r\n");
                try trailers.print(allocator, "{s}: {s}", .{ trailer[0..colon], http_headers.trimValue(trailer[colon + 1 ..]) });
            }
            break;
        }

        if (size > max_body_bytes or body.items.len > max_body_bytes - size) {
            return error.PayloadTooLarge;
        }

        const start = body.items.len;
        try body.resize(allocator, start + size);
        try reader.readExact(body.items[start..]);

        const cr = try reader.readByte();
        const lf = try reader.readByte();
        if (cr != '\r' or lf != '\n') return error.BadRequest;
    }

    const owned_body = try body.toOwnedSlice(allocator);
    errdefer allocator.free(owned_body);
    return .{
        .body = owned_body,
        .trailers = try trailers.toOwnedSlice(allocator),
        .discarded_pipeline_bytes = reader.unreadLen() > 0,
    };
}

fn readContentLengthBody(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    headers: []const u8,
    buffer_tail: []const u8,
    max_body_bytes: usize,
    read_fn: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
) !BodyRead {
    const expected_len = try http_headers.parseContentLength(headers);
    if (expected_len == 0) return .{ .body = "", .discarded_pipeline_bytes = buffer_tail.len > 0 };
    if (expected_len > max_body_bytes) return error.PayloadTooLarge;

    const body = try allocator.alloc(u8, expected_len);
    errdefer allocator.free(body);
    const already = @min(buffer_tail.len, expected_len);
    @memcpy(body[0..already], buffer_tail[0..already]);

    var read_total: usize = already;
    while (read_total < expected_len) {
        const n = try read_fn(stream, body[read_total..]);
        if (n == 0) return error.BadRequest;
        read_total += n;
    }

    return .{
        .body = body,
        .discarded_pipeline_bytes = buffer_tail.len > expected_len,
    };
}

pub fn readBody(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    headers: []const u8,
    buffer_tail: []const u8,
    max_body_bytes: usize,
    max_chunk_line_bytes: usize,
    max_trailer_bytes: usize,
    read_fn: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
) !BodyRead {
    const is_chunked = try http_headers.transferEncodingIsChunkedOnly(headers);
    if (is_chunked) {
        if (http_headers.findHeaderValue(headers, "Content-Length") != null) return error.BadRequest;
        return try readChunkedBody(stream, allocator, buffer_tail, max_body_bytes, max_chunk_line_bytes, max_trailer_bytes, headers, read_fn);
    }

    return try readContentLengthBody(stream, allocator, headers, buffer_tail, max_body_bytes, read_fn);
}

const Fake = struct {
    threadlocal var input: []const u8 = "";
    fn read(_: std.Io.net.Stream, out: []u8) !usize {
        const count = @min(@as(usize, 3), @min(input.len, out.len));
        @memcpy(out[0..count], input[0..count]);
        input = input[count..];
        return count;
    }
    const stream: std.Io.net.Stream = .{ .socket = .{ .handle = 123, .address = undefined } };
};

test "chunked requests retain separate trailers across reads and allocation failures" {
    const Case = struct {
        fn run(allocator: std.mem.Allocator) !void {
            Fake.input = "llo\r\n0\r\nContent-Digest: sha-256=:test:\r\nX-Result: one\r\nX-Result: two\r\n\r\n";
            const result = try readBody(Fake.stream, allocator, "Transfer-Encoding: chunked", "5; ext=\"ok\"\r\nhe", 1024, 128, 1024, Fake.read);
            defer allocator.free(result.body);
            defer allocator.free(result.trailers);
            try std.testing.expectEqualStrings("hello", result.body);
            try std.testing.expectEqualStrings("Content-Digest: sha-256=:test:\r\nX-Result: one\r\nX-Result: two", result.trailers);
            try std.testing.expect(!result.discarded_pipeline_bytes);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Case.run, .{});
}

test "chunked requests reject ambiguous lines forbidden trailers and bounded metadata" {
    for ([_][]const u8{ "1\nx\r\n0\r\n\r\n", "1\rXx\r\n0\r\n\r\n", "+1\r\nx\r\n0\r\n\r\n", "0; bad=\"open\r\n\r\n", "0\r\nContent-Length: 4\r\n\r\n", "0\r\nX-Hop: hidden\r\n\r\n", "0\r\nDigest: x\n\r\n" }) |wire| {
        Fake.input = "";
        try std.testing.expectError(error.BadRequest, readBody(Fake.stream, std.testing.allocator, "Transfer-Encoding: chunked\r\nConnection: X-Hop", wire, 1024, 128, 1024, Fake.read));
    }
    Fake.input = "";
    try std.testing.expectError(error.RequestTooLarge, readBody(Fake.stream, std.testing.allocator, "Transfer-Encoding: chunked", "0\r\nDigest: one\r\nDigest: two\r\n\r\n", 1024, 128, 60, Fake.read));
    try std.testing.expectError(error.RequestTooLarge, readBody(Fake.stream, std.testing.allocator, "Transfer-Encoding: chunked", "1; ext=yes\r\nx\r\n0\r\n\r\n", 1024, 128, 3, Fake.read));
    try std.testing.expectError(error.BadRequest, readBody(Fake.stream, std.testing.allocator, "Content-Length: 6", "short", 1024, 128, 1024, Fake.read));
}
