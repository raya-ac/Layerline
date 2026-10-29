const std = @import("std");

const h2_native = @import("h2_native.zig");
const http_headers = @import("http_headers.zig");
const proxy_utils = @import("proxy_utils.zig");
const request_mod = @import("request.zig");
const read_deadline = @import("read_deadline.zig");
const Deadline = read_deadline.Deadline;

pub const PREFACE_MAGIC = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub fn isLikelyPreface(bytes: []const u8) bool {
    if (bytes.len < 7) return false;
    if (std.mem.startsWith(u8, bytes, PREFACE_MAGIC)) return true;
    return std.mem.startsWith(u8, bytes, "PRI * ");
}

pub const BufferedResponse = struct {
    status_code: u16,
    content_type: []const u8,
    body: []const u8,
    headers: []const h2_native.Header = &.{},
    apply_custom_errors: bool = true,
};

pub const Frame = struct {
    header: h2_native.FrameHeader,
    // Borrowed until the reader advances to the next frame.
    payload: []u8,
};

pub const RequestState = struct {
    stream_id: u32,
    req: request_mod.HttpRequest,
    body: std.ArrayList(u8) = .empty,
    expected_content_length: ?usize = null,
    deadline: Deadline = .{},

    pub fn deinit(self: *RequestState, allocator: std.mem.Allocator) void {
        allocator.free(self.req.method);
        allocator.free(self.req.path);
        allocator.free(self.req.query);
        allocator.free(self.req.headers);
        self.body.deinit(allocator);
    }
};

pub const PendingReader = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    pending: []const u8,
    read: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
    header: [9]u8 = undefined,
    header_used: usize = 0,
    payload: ?[]u8 = null,
    buffer: ?[]u8 = null,
    payload_used: usize = 0,
    frame_started: ?std.Io.Timestamp = null,
    idle_started: ?std.Io.Timestamp = null,
    busy: bool = false,
    completed_started: std.Io.Timestamp = .zero,
    header_timeout_ms: u32 = 10_000,
    idle_timeout_ms: u32 = 60_000,
    limit: Deadline = .{},

    pub fn deinit(self: *PendingReader, allocator: std.mem.Allocator) void {
        if (self.buffer) |buffer| allocator.free(buffer);
        read_deadline.clear(self.stream);
    }

    pub fn phaseDeadline(self: *PendingReader) Deadline {
        if (self.frame_started) |start| return .after(start, self.header_timeout_ms);
        if (self.busy) return .{};
        if (self.idle_started == null) self.idle_started = .now(self.io, .awake);
        return .after(self.idle_started.?, self.idle_timeout_ms);
    }

    pub fn setBusy(self: *PendingReader, busy: bool) void {
        if (self.busy and !busy) self.idle_started = .now(self.io, .awake);
        self.busy = busy;
    }

    fn readFrameBytes(self: *PendingReader, out: []u8) !usize {
        read_deadline.install(.{
            .io = self.io,
            .handle = self.stream.socket.handle,
            .deadline = Deadline.earliest(self.phaseDeadline(), self.limit),
            .restore_timeout_ms = self.idle_timeout_ms,
            .progress_timeout_ms = self.header_timeout_ms,
            .track_progress = true,
            .progress_started = self.frame_started,
            .replace_on_progress = true,
            .limit = self.limit,
        });
        defer if (read_deadline.forStream(self.stream)) |budget| {
            self.frame_started = budget.progress_started;
        };
        if (self.pending.len > 0) {
            const n = @min(out.len, self.pending.len);
            @memcpy(out[0..n], self.pending[0..n]);
            self.pending = self.pending[n..];
            read_deadline.noteProgress(self.stream);
            return n;
        }
        const n = try self.read(self.stream, out);
        if (n > 0) read_deadline.noteProgress(self.stream);
        return n;
    }

    pub fn readExact(self: *PendingReader, out: []u8) !void {
        var written: usize = 0;
        if (self.pending.len > 0) {
            const n = @min(out.len, self.pending.len);
            @memcpy(out[0..n], self.pending[0..n]);
            self.pending = self.pending[n..];
            written = n;
        }

        while (written < out.len) {
            const n = try self.read(self.stream, out[written..]);
            if (n == 0) return error.ConnectionClosed;
            written += n;
        }
    }
};

test "active HTTP2 work pauses idle expiry but never a partial frame deadline" {
    var reader: PendingReader = .{
        .io = std.testing.io,
        .stream = .{ .socket = .{ .handle = 123, .address = undefined } },
        .pending = "",
        .read = undefined,
        .idle_started = .zero,
        .idle_timeout_ms = 600,
        .header_timeout_ms = 100,
    };
    try std.testing.expectEqual(Deadline.after(.zero, 600).at, reader.phaseDeadline().at);
    reader.setBusy(true);
    try std.testing.expect(reader.phaseDeadline().at == null);
    reader.frame_started = .zero;
    try std.testing.expectEqual(Deadline.after(.zero, 100).at, reader.phaseDeadline().at);
    reader.setBusy(false);
    try std.testing.expectEqual(Deadline.after(.zero, 100).at, reader.phaseDeadline().at);
    reader.frame_started = null;
    const idle = Deadline.after(reader.idle_started.?, 600);
    try std.testing.expectEqual(idle.at, reader.phaseDeadline().at);
    reader.setBusy(false);
    try std.testing.expectEqual(idle.at, reader.phaseDeadline().at);
}

pub fn cloneRequest(allocator: std.mem.Allocator, req: request_mod.HttpRequest) !request_mod.HttpRequest {
    const method = try allocator.dupe(u8, req.method);
    errdefer allocator.free(method);
    const path = try allocator.dupe(u8, req.path);
    errdefer allocator.free(path);
    const query = try allocator.dupe(u8, req.query);
    errdefer allocator.free(query);
    const headers = try allocator.dupe(u8, req.headers);
    return .{
        .method = method,
        .path = path,
        .query = query,
        .headers = headers,
        .version = req.version,
        .body = "",
        .close_connection = true,
    };
}

fn cloneWithAllocationFailures(allocator: std.mem.Allocator) !void {
    const req = try cloneRequest(allocator, .{ .method = "POST", .path = "/upload", .query = "x=y", .headers = "Host: local", .body = "", .version = "HTTP/2.0", .close_connection = true });
    allocator.free(req.method);
    allocator.free(req.path);
    allocator.free(req.query);
    allocator.free(req.headers);
}

test "HTTP2 request cloning cleans up when an allocation fails" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, cloneWithAllocationFailures, .{});
}

fn headerNameIndex(name: []const u8) ?u64 {
    if (std.ascii.eqlIgnoreCase(name, "accept-ranges")) return 18;
    if (std.ascii.eqlIgnoreCase(name, "allow")) return 22;
    if (std.ascii.eqlIgnoreCase(name, "cache-control")) return 24;
    if (std.ascii.eqlIgnoreCase(name, "content-encoding")) return 26;
    if (std.ascii.eqlIgnoreCase(name, "content-length")) return 28;
    if (std.ascii.eqlIgnoreCase(name, "content-range")) return 30;
    if (std.ascii.eqlIgnoreCase(name, "content-type")) return 31;
    if (std.ascii.eqlIgnoreCase(name, "date")) return 33;
    if (std.ascii.eqlIgnoreCase(name, "etag")) return 34;
    if (std.ascii.eqlIgnoreCase(name, "last-modified")) return 44;
    if (std.ascii.eqlIgnoreCase(name, "location")) return 46;
    if (std.ascii.eqlIgnoreCase(name, "server")) return 54;
    if (std.ascii.eqlIgnoreCase(name, "set-cookie")) return 55;
    if (std.ascii.eqlIgnoreCase(name, "strict-transport-security")) return 56;
    if (std.ascii.eqlIgnoreCase(name, "vary")) return 59;
    return null;
}

pub fn isSkippedResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "content-type") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-authenticate") or
        std.ascii.eqlIgnoreCase(name, "proxy-authorization") or
        std.ascii.eqlIgnoreCase(name, "te") or
        std.ascii.eqlIgnoreCase(name, "trailer") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade") or
        std.ascii.eqlIgnoreCase(name, "x-request-id");
}

pub fn lowerHeaderName(allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
    const lowered = try allocator.alloc(u8, name.len);
    for (name, 0..) |byte, index| {
        lowered[index] = std.ascii.toLower(byte);
    }
    return lowered;
}

pub fn appendHeader(allocator: std.mem.Allocator, block: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
    if (headerNameIndex(name)) |index| {
        try h2_native.appendHeaderIndexedName(allocator, block, index, value);
        return;
    }

    const lowered = try lowerHeaderName(allocator, name);
    try h2_native.appendHeaderLiteralName(allocator, block, lowered, value);
}

pub fn sendFrame(stream: std.Io.net.Stream, frame_type: u8, flags: u8, stream_id: u32, payload: []const u8, write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !void {
    var header: [9]u8 = undefined;
    const rendered = try h2_native.writeFrameHeader(&header, payload.len, frame_type, flags, stream_id);
    // A failed write may have sent half a frame or TLS record. Nothing else,
    // including GOAWAY, can safely be appended to this connection afterward.
    write_all(stream, rendered) catch return error.CloseConnection;
    if (payload.len > 0) write_all(stream, payload) catch return error.CloseConnection;
}

test "a failed frame write requires connection close, not a protocol error reply" {
    const writer = struct {
        fn fail(_: std.Io.net.Stream, _: []const u8) !void {
            return error.WriteTimeout;
        }

        fn failBody(_: std.Io.net.Stream, bytes: []const u8) !void {
            if (bytes.len != 9) return error.WriteTimeout;
        }
    };
    const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    try std.testing.expectError(error.CloseConnection, sendFrame(stream, h2_native.FRAME_DATA, 0, 1, "body", writer.fail));
    try std.testing.expectError(error.CloseConnection, sendFrame(stream, h2_native.FRAME_DATA, 0, 1, "body", writer.failBody));
}

pub fn textResponse(status_code: u16, content_type: []const u8, body: []const u8) BufferedResponse {
    return .{ .status_code = status_code, .content_type = content_type, .body = body };
}

pub fn validateRequestFields(fields: anytype) !void {
    var saw_regular = false;
    var pseudo_seen: u4 = 0;
    for (fields) |header| {
        if (header.name.len == 0 or !http_headers.validFieldValue(header.value)) return error.BadRequest;
        const pseudo = header.name[0] == ':';
        for (header.name[@intFromBool(pseudo)..]) |byte| {
            if (!http_headers.isHeaderNameByte(byte) or std.ascii.isUpper(byte)) return error.BadRequest;
        }
        if (pseudo) {
            if (saw_regular) return error.BadRequest;
            const bit: u4 = if (std.mem.eql(u8, header.name, ":method")) 1 else if (std.mem.eql(u8, header.name, ":scheme")) 2 else if (std.mem.eql(u8, header.name, ":authority")) 4 else if (std.mem.eql(u8, header.name, ":path")) 8 else return error.BadRequest;
            if (pseudo_seen & bit != 0) return error.BadRequest;
            pseudo_seen |= bit;
        } else {
            saw_regular = true;
            for ([_][]const u8{ "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade" }) |forbidden| {
                if (std.mem.eql(u8, header.name, forbidden)) return error.BadRequest;
            }
            if (std.mem.eql(u8, header.name, "te") and !std.ascii.eqlIgnoreCase(header.value, "trailers")) return error.BadRequest;
        }
    }
}

pub fn validateTrailerFields(fields: anytype) !void {
    try validateRequestFields(fields);
    for (fields) |header| {
        if (header.name[0] == ':') return error.BadRequest;
        // Trailers must never change framing, routing, authentication, or the
        // interpretation of content already received. Keep them out of headers.
        for ([_][]const u8{ "host", "content-length", "content-type", "content-encoding", "content-range", "authorization", "proxy-authorization", "cookie", "expect", "range", "te", "trailer" }) |name| {
            if (std.mem.eql(u8, header.name, name)) return error.BadRequest;
        }
        if (std.mem.startsWith(u8, header.name, "if-")) return error.BadRequest;
    }
}

pub fn headerListFits(fields: anytype, limit: usize) bool {
    var remaining = limit;
    for (fields) |header| {
        for ([_]usize{ header.name.len, header.value.len, 32 }) |size| {
            if (size > remaining) return false;
            remaining -= size;
        }
    }
    return true;
}

pub fn parseRequest(allocator: std.mem.Allocator, decoded: *const h2_native.DecodedHeaders) !request_mod.HttpRequest {
    try validateRequestFields(decoded.headers.items);
    const method = decoded.get(":method") orelse return error.BadRequest;
    const path_and_query = decoded.get(":path") orelse return error.BadRequest;
    const authority = decoded.get(":authority") orelse decoded.get("host") orelse "";
    if (authority.len == 0 or method.len == 0 or path_and_query.len == 0) return error.BadRequest;
    for (method) |byte| {
        if (!http_headers.isHeaderNameByte(byte)) return error.BadRequest;
    }
    const target = request_mod.parseRequestTarget(path_and_query) catch return error.BadRequest;
    if (target.authority != null or (std.mem.eql(u8, target.path, "*") and !std.mem.eql(u8, method, "OPTIONS"))) return error.BadRequest;
    const scheme = decoded.get(":scheme") orelse return error.BadRequest;
    if (!std.mem.eql(u8, scheme, "http") and !std.mem.eql(u8, scheme, "https")) return error.BadRequest;
    if (decoded.get("host")) |host| {
        if (!std.ascii.eqlIgnoreCase(host, authority)) return error.BadRequest;
    }

    const query_pos = std.mem.indexOfScalar(u8, path_and_query, '?');
    const path = if (query_pos) |idx| path_and_query[0..idx] else path_and_query;
    const query = if (query_pos) |idx| if (idx + 1 < path_and_query.len) path_and_query[idx + 1 ..] else "" else "";

    var headers = std.ArrayList(u8).empty;
    errdefer headers.deinit(allocator);
    if (authority.len > 0) {
        try headers.print(allocator, "Host: {s}\r\n", .{authority});
    }
    for (decoded.headers.items) |header| {
        if (header.name.len > 0 and header.name[0] == ':') continue;
        if (std.ascii.eqlIgnoreCase(header.name, "host")) continue;
        if (std.mem.eql(u8, header.name, "cookie")) continue;
        try headers.print(allocator, "{s}: {s}\r\n", .{ header.name, header.value });
    }
    // RFC 9113 section 8.2.3: applications receive one Cookie field, joined
    // with semicolons. Other repeated fields retain their original boundaries.
    var saw_cookie = false;
    for (decoded.headers.items) |header| {
        if (!std.mem.eql(u8, header.name, "cookie")) continue;
        try headers.appendSlice(allocator, if (saw_cookie) "; " else "cookie: ");
        try headers.appendSlice(allocator, header.value);
        saw_cookie = true;
    }
    if (saw_cookie) try headers.appendSlice(allocator, "\r\n");

    const owned_method = try allocator.dupe(u8, method);
    errdefer allocator.free(owned_method);
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);
    const owned_query = try allocator.dupe(u8, query);
    errdefer allocator.free(owned_query);

    return .{
        .method = owned_method,
        .path = owned_path,
        .query = owned_query,
        .headers = try headers.toOwnedSlice(allocator),
        .version = "HTTP/2.0",
        .body = "",
        .close_connection = true,
    };
}

pub fn readFrame(reader: *PendingReader, allocator: std.mem.Allocator, max_payload_bytes: usize) !Frame {
    while (reader.header_used < reader.header.len) {
        const n = try reader.readFrameBytes(reader.header[reader.header_used..]);
        if (n == 0) return error.ConnectionClosed;
        reader.header_used += n;
    }
    const header = try h2_native.parseFrameHeader(&reader.header);
    if (header.length > max_payload_bytes) return error.FrameSize;
    if (reader.payload == null) {
        if (header.length == 0) {
            reader.payload = &.{};
        } else {
            if (reader.buffer) |buffer| {
                if (buffer.len < header.length) reader.buffer = try allocator.realloc(buffer, max_payload_bytes);
            } else {
                reader.buffer = try allocator.alloc(u8, max_payload_bytes);
            }
            reader.payload = reader.buffer.?[0..header.length];
        }
    }
    const payload = reader.payload.?;
    while (reader.payload_used < payload.len) {
        const n = try reader.readFrameBytes(payload[reader.payload_used..]);
        if (n == 0) return error.ConnectionClosed;
        reader.payload_used += n;
    }
    reader.completed_started = reader.frame_started orelse .now(reader.io, .awake);
    reader.header_used = 0;
    reader.payload = null;
    reader.payload_used = 0;
    reader.frame_started = null;
    reader.idle_started = .now(reader.io, .awake);
    read_deadline.clear(reader.stream);
    return .{ .header = header, .payload = payload };
}

pub fn sendRst(stream: std.Io.net.Stream, stream_id: u32, code: u32, write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, code, .big);
    try sendFrame(stream, h2_native.FRAME_RST_STREAM, 0, stream_id, &payload, write_all);
}

pub fn sendSettings(stream: std.Io.net.Stream, max_streams: u32, header_bytes: usize, write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !void {
    var payload: [12]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], 3, .big);
    std.mem.writeInt(u32, payload[2..6], max_streams, .big);
    std.mem.writeInt(u16, payload[6..8], 6, .big);
    std.mem.writeInt(u32, payload[8..12], @intCast(@min(header_bytes, std.math.maxInt(u32))), .big);
    try sendFrame(stream, h2_native.FRAME_SETTINGS, 0, 0, &payload, write_all);
}

pub fn makeGoawayPayload(last_stream_id: u32, code: u32) [8]u8 {
    var payload: [8]u8 = undefined;
    std.mem.writeInt(u32, payload[0..4], last_stream_id & 0x7fff_ffff, .big);
    std.mem.writeInt(u32, payload[4..8], code, .big);
    return payload;
}

pub fn sendGoaway(stream: std.Io.net.Stream, last_stream_id: u32, code: u32, write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !void {
    const payload = makeGoawayPayload(last_stream_id, code);
    try sendFrame(stream, h2_native.FRAME_GOAWAY, 0, 0, &payload, write_all);
}

pub fn sendWindowUpdate(stream: std.Io.net.Stream, stream_id: u32, increment: usize, write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !void {
    if (increment == 0) return;
    if (increment > 0x7fff_ffff) return error.BadRequest;
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, @intCast(increment), .big);
    try sendFrame(stream, h2_native.FRAME_WINDOW_UPDATE, 0, stream_id, &payload, write_all);
}

pub fn parseRequestContentLength(headers: []const u8) !?usize {
    var expected: ?usize = null;
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        const trimmed = http_headers.trimValue(line);
        if (trimmed.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse continue;
        const name = http_headers.trimValue(trimmed[0..colon]);
        if (!std.ascii.eqlIgnoreCase(name, "content-length")) continue;

        const value = http_headers.trimValue(trimmed[colon + 1 ..]);
        const parsed = try http_headers.parseDecimalLength(value);
        if (expected) |previous| {
            if (previous != parsed) return error.InvalidContentLength;
        } else {
            expected = parsed;
        }
    }
    return expected;
}

pub fn findRequestState(states: *std.ArrayList(RequestState), stream_id: u32) ?usize {
    for (states.items, 0..) |state, index| {
        if (state.stream_id == stream_id) return index;
    }
    return null;
}

pub fn removeRequestState(states: *std.ArrayList(RequestState), allocator: std.mem.Allocator, index: usize) void {
    var state = states.orderedRemove(index);
    state.deinit(allocator);
}

pub fn readClientPreface(reader: *PendingReader) !void {
    var preface_buf: [PREFACE_MAGIC.len]u8 = undefined;
    try reader.readExact(&preface_buf);
    if (!std.mem.eql(u8, &preface_buf, PREFACE_MAGIC)) return error.BadRequest;
}

threadlocal var partial_frame_step: usize = 0;

fn partialFrameRead(_: std.Io.net.Stream, out: []u8) !usize {
    const step = partial_frame_step;
    partial_frame_step += 1;
    const piece: []const u8 = switch (step) {
        0 => "\x00\x00\x08\x06",
        1, 4 => return error.RequestTimeout,
        2 => "\x00\x00\x00\x00\x00",
        3 => "pin",
        5 => "gpong",
        else => return 0,
    };
    @memcpy(out[0..piece.len], piece);
    return piece.len;
}

test "HTTP2 frame header and payload survive read budget interrupts" {
    partial_frame_step = 0;
    var reader = PendingReader{ .io = std.testing.io, .stream = .{ .socket = .{ .handle = 123, .address = undefined } }, .pending = "", .read = partialFrameRead };
    defer reader.deinit(std.testing.allocator);
    try std.testing.expectError(error.RequestTimeout, readFrame(&reader, std.testing.allocator, 16384));
    try std.testing.expectEqual(4, reader.header_used);
    try std.testing.expectError(error.RequestTimeout, readFrame(&reader, std.testing.allocator, 16384));
    try std.testing.expectEqual(3, reader.payload_used);
    const frame = try readFrame(&reader, std.testing.allocator, 16384);
    try std.testing.expectEqual(h2_native.FRAME_PING, frame.header.frame_type);
    try std.testing.expectEqualStrings("pingpong", frame.payload);
}

pub fn decodeChunkedBuffer(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    var cursor = bytes;
    while (true) {
        const line_end = std.mem.indexOf(u8, cursor, "\r\n") orelse return error.BadGateway;
        const line = cursor[0..line_end];
        const ext = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
        const size = std.fmt.parseInt(usize, http_headers.trimValue(line[0..ext]), 16) catch return error.BadGateway;
        cursor = cursor[line_end + 2 ..];
        if (size == 0) return out.toOwnedSlice(allocator);
        if (cursor.len < size + 2) return error.BadGateway;
        try out.appendSlice(allocator, cursor[0..size]);
        if (!std.mem.eql(u8, cursor[size .. size + 2], "\r\n")) return error.BadGateway;
        cursor = cursor[size + 2 ..];
    }
}

pub fn collectUpstreamHeaders(allocator: std.mem.Allocator, response_headers: []const u8) ![]h2_native.Header {
    var out = std.ArrayList(h2_native.Header).empty;
    errdefer out.deinit(allocator);

    var lines = std.mem.splitSequence(u8, response_headers, "\r\n");
    while (lines.next()) |line| {
        const trimmed = http_headers.trimValue(line);
        if (trimmed.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse continue;
        const name = http_headers.trimValue(trimmed[0..colon]);
        if (isSkippedResponseHeader(name)) continue;
        const value = http_headers.trimValue(trimmed[colon + 1 ..]);
        if (value.len == 0) continue;
        const lowered = try lowerHeaderName(allocator, name);
        try out.append(allocator, .{ .name = lowered, .value = try allocator.dupe(u8, value) });
    }

    return out.toOwnedSlice(allocator);
}

pub fn responseHasNoBody(method: []const u8, status_code: u16) bool {
    return proxy_utils.responseHasNoBody(method, status_code);
}
