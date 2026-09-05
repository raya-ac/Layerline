const std = @import("std");

const h2_native = @import("h2_native.zig");
const http_headers = @import("http_headers.zig");
const proxy_utils = @import("proxy_utils.zig");
const request_mod = @import("request.zig");

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
};

pub const Frame = struct {
    header: h2_native.FrameHeader,
    payload: []u8,
};

pub const RequestState = struct {
    stream_id: u32,
    req: request_mod.HttpRequest,
    body: std.ArrayList(u8) = .empty,
    expected_content_length: ?usize = null,

    pub fn deinit(self: *RequestState, allocator: std.mem.Allocator) void {
        allocator.free(self.req.method);
        allocator.free(self.req.path);
        allocator.free(self.req.query);
        allocator.free(self.req.headers);
        self.body.deinit(allocator);
    }
};

pub const PendingReader = struct {
    stream: std.Io.net.Stream,
    pending: []const u8,
    read: *const fn (std.Io.net.Stream, []u8) anyerror!usize,

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

pub fn cloneRequest(allocator: std.mem.Allocator, req: request_mod.HttpRequest) !request_mod.HttpRequest {
    return .{
        .method = try allocator.dupe(u8, req.method),
        .path = try allocator.dupe(u8, req.path),
        .query = try allocator.dupe(u8, req.query),
        .headers = try allocator.dupe(u8, req.headers),
        .version = req.version,
        .body = "",
        .close_connection = true,
    };
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
    try write_all(stream, rendered);
    if (payload.len > 0) try write_all(stream, payload);
}

pub fn textResponse(status_code: u16, content_type: []const u8, body: []const u8) BufferedResponse {
    return .{ .status_code = status_code, .content_type = content_type, .body = body };
}

pub fn parseRequest(allocator: std.mem.Allocator, decoded: *const h2_native.DecodedHeaders) !request_mod.HttpRequest {
    var saw_regular = false;
    var pseudo_seen: u4 = 0;
    for (decoded.headers.items) |header| {
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
        try headers.print(allocator, "{s}: {s}\r\n", .{ header.name, header.value });
    }

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
    var header_bytes: [9]u8 = undefined;
    try reader.readExact(&header_bytes);
    const header = try h2_native.parseFrameHeader(&header_bytes);
    if (header.length > max_payload_bytes) return error.RequestTooLarge;
    const payload = try allocator.alloc(u8, header.length);
    errdefer allocator.free(payload);
    if (payload.len > 0) try reader.readExact(payload);
    return .{ .header = header, .payload = payload };
}

pub fn sendRst(stream: std.Io.net.Stream, stream_id: u32, code: u32, write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, code, .big);
    try sendFrame(stream, h2_native.FRAME_RST_STREAM, 0, stream_id, &payload, write_all);
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
