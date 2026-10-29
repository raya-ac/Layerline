const std = @import("std");
const headers = @import("http_headers.zig");
const proxy = @import("proxy_utils.zig");

pub const Head = struct {
    bytes: []const u8,
    status_line: []const u8,
    fields: []const u8,
    framing: proxy.UpstreamResponseFraming,
};

// Head fields survive body reads, but not the next head (an informational reply).
// Body slices survive until nextData; callers consume them before reading again.
pub const Reader = struct {
    stream: std.Io.net.Stream,
    read: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
    head_buffer: [16384]u8 = undefined,
    used: usize = 0,
    head_end: usize = 0,
    head_count: usize = 0,
    head_bytes: usize = 0,
    pending: []const u8 = "",
    body_buffer: [8192]u8 = undefined,
    line_buffer: [4096]u8 = undefined,
    trailer_buffer: [16384]u8 = undefined,
    trailer_used: usize = 0,
    trailer_count: usize = 0,
    mode: enum { done, fixed, chunked, until_eof } = .done,
    remaining: usize = 0,
    chunk_suffix: bool = false,
    limit: ?usize = null,
    delivered: usize = 0,
    bodyless: bool = false,

    pub fn create(allocator: std.mem.Allocator, stream: std.Io.net.Stream, read: *const fn (std.Io.net.Stream, []u8) anyerror!usize) !*Reader {
        // These buffers do not fit alongside TLS on a 64 KiB connection stack.
        const reader = try allocator.create(Reader);
        reader.* = .{ .stream = stream, .read = read };
        return reader;
    }

    pub fn nextHead(self: *Reader) !Head {
        const tail = self.head_buffer[self.head_end..self.used];
        std.mem.copyForwards(u8, &self.head_buffer, tail);
        self.used = tail.len;
        self.head_end = 0;
        while (true) {
            if (std.mem.indexOf(u8, self.head_buffer[0..self.used], "\r\n\r\n")) |end| {
                self.head_end = end + 4;
                self.head_count += 1;
                self.head_bytes += self.head_end;
                if (self.head_count > 17 or self.head_bytes > 65536) return error.BadGateway;
                const bytes = self.head_buffer[0..self.head_end];
                const line_end = std.mem.indexOf(u8, bytes, "\r\n") orelse return error.BadGateway;
                const fields = if (line_end + 2 > end) "" else bytes[line_end + 2 .. end];
                const framing = try proxy.parseUpstreamResponseFraming(bytes, fields);
                if (framing.status_code.? < 200 and framing.status_code.? != 101 and self.head_count > 16) return error.BadGateway;
                self.pending = self.head_buffer[self.head_end..self.used];
                return .{ .bytes = bytes, .status_line = bytes[0..line_end], .fields = fields, .framing = framing };
            }
            if (self.used == self.head_buffer.len) return error.BadGateway;
            const count = try self.read(self.stream, self.head_buffer[self.used..]);
            if (count == 0) return error.BadGateway;
            self.used += count;
        }
    }

    pub fn beginBody(self: *Reader, method: []const u8, framing: proxy.UpstreamResponseFraming, limit: ?usize) !void {
        self.limit = limit;
        self.bodyless = proxy.responseHasNoBody(method, framing.status_code);
        if (self.bodyless) return;
        if (framing.transfer_chunked) {
            self.mode = .chunked;
        } else if (framing.content_length) |length| {
            if (limit) |maximum| if (length > maximum) return error.PayloadTooLarge;
            self.mode = .fixed;
            self.remaining = length;
        } else self.mode = .until_eof;
    }

    fn fill(self: *Reader) !bool {
        if (self.pending.len > 0) return true;
        const count = try self.read(self.stream, &self.body_buffer);
        self.pending = self.body_buffer[0..count];
        return count > 0;
    }

    fn byte(self: *Reader) !u8 {
        if (!try self.fill()) return error.BadGateway;
        const result = self.pending[0];
        self.pending = self.pending[1..];
        return result;
    }

    fn line(self: *Reader) ![]const u8 {
        var length: usize = 0;
        while (true) {
            const value = try self.byte();
            if (value == '\r') {
                if (try self.byte() != '\n') return error.BadGateway;
                return self.line_buffer[0..length];
            }
            if (value == '\n' or length == self.line_buffer.len) return error.BadGateway;
            self.line_buffer[length] = value;
            length += 1;
        }
    }

    fn readTrailers(self: *Reader) !void {
        while (true) {
            const field = try self.line();
            if (field.len == 0) return;
            headers.validateHeaderBlock(field) catch return error.BadGateway;
            const colon = std.mem.indexOfScalar(u8, field, ':').?;
            if (proxy.isForbiddenTrailer(field[0..colon])) return error.BadGateway;
            self.trailer_count += 1;
            if (self.trailer_count > headers.MAX_HTTP1_HEADER_FIELDS or field.len + 2 > self.trailer_buffer.len - self.trailer_used) return error.BadGateway;
            @memcpy(self.trailer_buffer[self.trailer_used..][0..field.len], field);
            self.trailer_used += field.len;
            @memcpy(self.trailer_buffer[self.trailer_used..][0..2], "\r\n");
            self.trailer_used += 2;
        }
    }

    pub fn trailers(self: *const Reader) []const u8 {
        return self.trailer_buffer[0..self.trailer_used -| 2];
    }

    pub fn nextData(self: *Reader) !?[]const u8 {
        if (self.mode == .done) return null;
        if (self.mode == .chunked and self.remaining == 0) {
            if (self.chunk_suffix) {
                if (try self.byte() != '\r' or try self.byte() != '\n') return error.BadGateway;
                self.chunk_suffix = false;
            }
            self.remaining = try parseChunkSize(try self.line());
            if (self.remaining == 0) {
                try self.readTrailers();
                self.mode = .done;
                return null;
            }
        } else if (self.mode == .fixed and self.remaining == 0) {
            self.mode = .done;
            return null;
        }
        if (!try self.fill()) {
            if (self.mode != .until_eof) return error.BadGateway;
            self.mode = .done;
            return null;
        }
        const count = if (self.mode == .until_eof) self.pending.len else @min(self.pending.len, self.remaining);
        if (self.limit) |maximum| if (count > maximum - self.delivered) return error.PayloadTooLarge;
        const result = self.pending[0..count];
        self.pending = self.pending[count..];
        self.delivered +|= count;
        if (self.mode != .until_eof) {
            self.remaining -= count;
            if (self.mode == .chunked and self.remaining == 0) self.chunk_suffix = true;
        }
        return result;
    }

    pub fn reusable(self: *const Reader, framing: proxy.UpstreamResponseFraming) bool {
        return self.mode == .done and self.pending.len == 0 and !framing.connection_close and
            (self.bodyless or framing.content_length != null or framing.transfer_chunked);
    }
};

fn parseChunkSize(value: []const u8) !usize {
    var end: usize = 0;
    while (end < value.len and std.ascii.isHex(value[end])) end += 1;
    if (end == 0) return error.BadGateway;
    const size = std.fmt.parseInt(usize, value[0..end], 16) catch return error.BadGateway;
    var cursor = end;
    while (cursor < value.len) {
        while (cursor < value.len and (value[cursor] == ' ' or value[cursor] == '\t')) cursor += 1;
        if (cursor == value.len or value[cursor] != ';') return error.BadGateway;
        cursor += 1;
        while (cursor < value.len and (value[cursor] == ' ' or value[cursor] == '\t')) cursor += 1;
        const name = cursor;
        while (cursor < value.len and headers.isHeaderNameByte(value[cursor])) cursor += 1;
        if (cursor == name) return error.BadGateway;
        while (cursor < value.len and (value[cursor] == ' ' or value[cursor] == '\t')) cursor += 1;
        if (cursor == value.len or value[cursor] != '=') continue;
        cursor += 1;
        while (cursor < value.len and (value[cursor] == ' ' or value[cursor] == '\t')) cursor += 1;
        if (cursor == value.len) return error.BadGateway;
        if (value[cursor] != '"') {
            const start = cursor;
            while (cursor < value.len and headers.isHeaderNameByte(value[cursor])) cursor += 1;
            if (cursor == start) return error.BadGateway;
        } else {
            cursor += 1;
            while (true) {
                if (cursor == value.len) return error.BadGateway;
                var character = value[cursor];
                cursor += 1;
                if (character == '"') break;
                if (character == '\\') {
                    if (cursor == value.len) return error.BadGateway;
                    character = value[cursor];
                    cursor += 1;
                }
                if ((character < 32 and character != '\t') or character == 127) return error.BadGateway;
            }
        }
    }
    return size;
}

const Fake = struct {
    threadlocal var input: []const u8 = "";
    threadlocal var split: usize = 1;
    threadlocal var allow_eof = false;
    fn read(_: std.Io.net.Stream, out: []u8) !usize {
        if (input.len == 0 and !allow_eof) return error.UnexpectedReadPastMessage;
        const count = @min(input.len, out.len, split);
        @memcpy(out[0..count], input[0..count]);
        input = input[count..];
        return count;
    }
    fn reader(value: []const u8, split_size: usize) Reader {
        Fake.input = value;
        Fake.split = split_size;
        Fake.allow_eof = false;
        return .{ .stream = .{ .socket = .{ .handle = 123, .address = undefined } }, .read = read };
    }
};

fn heapReaderAllocationCheck(allocator: std.mem.Allocator) !void {
    _ = Fake.reader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 4096);
    const reader = try Reader.create(allocator, .{ .socket = .{ .handle = 123, .address = undefined } }, Fake.read);
    defer allocator.destroy(reader);
    const head = try reader.nextHead();
    try reader.beginBody("GET", head.framing, 2);
    try std.testing.expectEqualStrings("ok", (try reader.nextData()).?);
    try std.testing.expect(try reader.nextData() == null);
}

test "request-owned reader allocation fails cleanly" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, heapReaderAllocationCheck, .{});
}

test "framed and bodyless responses stop without waiting for EOF" {
    for ([_]usize{ 1, 4096 }) |split| {
        var reader = Fake.reader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", split);
        const head = try reader.nextHead();
        try reader.beginBody("GET", head.framing, 2);
        var total: usize = 0;
        while (try reader.nextData()) |data| total += data.len;
        try std.testing.expectEqual(2, total);
        try std.testing.expect(reader.reusable(head.framing));
        for ([_][]const u8{ "HTTP/1.1 204 No Content\r\n\r\n", "HTTP/1.1 304 Not Modified\r\nContent-Length: 200\r\n\r\n" }) |raw| {
            reader = Fake.reader(raw, split);
            const empty = try reader.nextHead();
            try reader.beginBody("GET", empty.framing, 1);
            try std.testing.expect(try reader.nextData() == null);
        }
        reader = Fake.reader("HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n", split);
        try reader.beginBody("HEAD", (try reader.nextHead()).framing, 1);
        try std.testing.expect(try reader.nextData() == null);
    }
}

test "chunked responses validate the complete terminator and trailers" {
    for ([_]usize{ 1, 4096 }) |split| {
        var reader = Fake.reader("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2; name=\"a\\\"b\"\r\nok\r\n0\r\nDigest: sha-test\r\n\r\n", split);
        const head = try reader.nextHead();
        try reader.beginBody("GET", head.framing, 2);
        var output: [2]u8 = undefined;
        var length: usize = 0;
        while (try reader.nextData()) |data| {
            @memcpy(output[length..][0..data.len], data);
            length += data.len;
        }
        try std.testing.expectEqualStrings("ok", &output);
        try std.testing.expectEqualStrings("Digest: sha-test", reader.trailers());
        try std.testing.expectEqualStrings("Transfer-Encoding: chunked", head.fields);
    }
    for ([_][]const u8{ "", "0", "+1", "1;", "1;bad=\"unfinished", "g", "ffffffffffffffffffffffffffffffff" }) |bad| {
        if (std.mem.eql(u8, bad, "0")) continue;
        try std.testing.expectError(error.BadGateway, parseChunkSize(bad));
    }
}

test "read ahead prevents pooling and close-delimited bodies need EOF" {
    var reader = Fake.reader("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\njunk", 4096);
    const head = try reader.nextHead();
    try reader.beginBody("GET", head.framing, 0);
    try std.testing.expect(try reader.nextData() == null);
    try std.testing.expect(!reader.reusable(head.framing));
    reader = Fake.reader("HTTP/1.1 200 OK\r\n\r\nokay", 4096);
    Fake.allow_eof = true;
    try reader.beginBody("GET", (try reader.nextHead()).framing, 4);
    try std.testing.expectEqualStrings("okay", (try reader.nextData()).?);
    try std.testing.expect(try reader.nextData() == null);
}

test "informational heads can be coalesced and remain bounded" {
    var reader = Fake.reader("HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 4096);
    try std.testing.expectEqual(103, (try reader.nextHead()).framing.status_code.?);
    try std.testing.expectEqual(200, (try reader.nextHead()).framing.status_code.?);
    const repeated = "HTTP/1.1 100 Continue\r\n\r\n" ** 17;
    reader = Fake.reader(repeated, 4096);
    for (0..16) |_| _ = try reader.nextHead();
    try std.testing.expectError(error.BadGateway, reader.nextHead());
    for ([_][]const u8{ "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n" }) |final| {
        var bytes = std.ArrayList(u8).empty;
        defer bytes.deinit(std.testing.allocator);
        try bytes.appendSlice(std.testing.allocator, "HTTP/1.1 100 Continue\r\n\r\n" ** 16);
        try bytes.appendSlice(std.testing.allocator, final);
        reader = Fake.reader(bytes.items, 1);
        for (0..16) |_| _ = try reader.nextHead();
        const expected: u16 = if (std.mem.startsWith(u8, final, "HTTP/1.1 101")) 101 else 200;
        try std.testing.expectEqual(expected, (try reader.nextHead()).framing.status_code.?);
    }
}

test "incomplete chunks and forbidden trailer metadata fail closed" {
    for ([_][]const u8{
        "1\r\nx\r\n0\r\n",
        "1\r\nx\n0\r\n\r\n",
        "0\r\nContent-Length: 1\r\n\r\n",
        "0\r\nCache-Control: public\r\n\r\n",
        "0\r\nServer: Apache PHP/8.4.26\r\n\r\n",
        "0\r\nX-Powered-By: PHP/8.4.26\r\n\r\n",
        "0\r\nx-powered-by: PHP/8.4.27\r\n\r\n",
        "0\r\n folded: trailer\r\n\r\n",
        "0\r\nDigest: invalid\x00\r\n\r\n",
    }) |raw| {
        var reader = Fake.reader(raw, 1);
        Fake.allow_eof = true;
        reader.mode = .chunked;
        var failure: ?anyerror = null;
        while (reader.nextData() catch |err| {
            failure = err;
            break;
        }) |_| {}
        try std.testing.expectEqual(error.BadGateway, failure.?);
    }
    var reader = Fake.reader("x", 1);
    Fake.allow_eof = true;
    reader.mode = .fixed;
    reader.remaining = 2;
    _ = try reader.nextData();
    try std.testing.expectError(error.BadGateway, reader.nextData());
}

test "chunk body limits and metadata limits do not depend on read boundaries" {
    var reader = Fake.reader("3\r\nabc\r\n0\r\n\r\n", 4096);
    reader.mode = .chunked;
    reader.limit = 2;
    try std.testing.expectError(error.PayloadTooLarge, reader.nextData());
    reader = Fake.reader("1;name=" ++ ("x" ** 4096) ++ "\r\nx\r\n0\r\n\r\n", 17);
    reader.mode = .chunked;
    try std.testing.expectError(error.BadGateway, reader.nextData());
    reader = Fake.reader("HTTP/1.1 200 OK\r\nX-Large: " ++ ("x" ** 16384) ++ "\r\n\r\n", 17);
    try std.testing.expectError(error.BadGateway, reader.nextHead());
    reader = Fake.reader("0\r\n" ++ ("X-Trailer: value\r\n" ** 101) ++ "\r\n", 1);
    reader.mode = .chunked;
    try std.testing.expectError(error.BadGateway, reader.nextData());
}
