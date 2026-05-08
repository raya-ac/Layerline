const std = @import("std");

const http_headers = @import("http_headers.zig");

pub const BodyRead = struct {
    body: []const u8,
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

    // The caller owns this buffer. Returning a slice to a local stack buffer is
    // exactly the kind of tiny mistake that makes chunk parsing look haunted.
    while (true) {
        const byte = try reader.readByte();
        if (byte == '\n') break;
        if (byte == '\r') continue;
        if (len == line.len) return error.BadRequest;
        line[len] = byte;
        len += 1;
    }

    return line[0..len];
}

fn parseChunkSize(line: []const u8) !usize {
    const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
    const raw_size = http_headers.trimValue(line[0..semi]);
    if (raw_size.len == 0) return error.BadRequest;
    return std.fmt.parseInt(usize, raw_size, 16) catch error.BadRequest;
}

fn readChunkedBody(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    buffer_tail: []const u8,
    max_body_bytes: usize,
    max_chunk_line_bytes: usize,
    read_fn: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
) !BodyRead {
    var reader = BufferedBodyReader{ .stream = stream, .buffered = buffer_tail, .read_fn = read_fn };
    var body = std.ArrayList(u8).empty;
    errdefer body.deinit(allocator);
    const line_buf = try allocator.alloc(u8, max_chunk_line_bytes);
    defer allocator.free(line_buf);

    while (true) {
        const size = try parseChunkSize(try readChunkLineInto(&reader, line_buf));
        if (size == 0) {
            while (true) {
                const trailer = try readChunkLineInto(&reader, line_buf);
                if (trailer.len == 0) break;
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

    return .{
        .body = try body.toOwnedSlice(allocator),
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
    read_fn: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
) !BodyRead {
    const is_chunked = try http_headers.transferEncodingIsChunkedOnly(headers);
    if (is_chunked) {
        if (http_headers.findHeaderValue(headers, "Content-Length") != null) return error.BadRequest;
        return try readChunkedBody(stream, allocator, buffer_tail, max_body_bytes, max_chunk_line_bytes, read_fn);
    }

    return try readContentLengthBody(stream, allocator, headers, buffer_tail, max_body_bytes, read_fn);
}
