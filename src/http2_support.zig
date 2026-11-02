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
    trailers: []const h2_native.Header = &.{},
    informational: []const Informational = &.{},
    content_length: ?usize = null,
    omit_content_length: bool = false,
    apply_custom_errors: bool = true,
};

pub const Informational = struct {
    status_code: u16,
    headers: []const h2_native.Header,
};

pub const InformationalSink = struct {
    context: *anyopaque,
    emit: *const fn (*anyopaque, Informational) anyerror!void,
};

// Routing workers publish through their owning dispatcher; only the connection
// thread writes TLS records, HPACK blocks and frames.
pub threadlocal var informational_sink: ?InformationalSink = null;

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
        allocator.free(self.req.trailers);
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
    errdefer allocator.free(headers);
    const trailers = try allocator.dupe(u8, req.trailers);
    return .{
        .method = method,
        .path = path,
        .query = query,
        .headers = headers,
        .version = req.version,
        .body = "",
        .trailers = trailers,
        .close_connection = true,
    };
}

fn cloneWithAllocationFailures(allocator: std.mem.Allocator) !void {
    const req = try cloneRequest(allocator, .{ .method = "POST", .path = "/upload", .query = "x=y", .headers = "Host: local", .body = "", .trailers = "digest: one", .version = "HTTP/2.0", .close_connection = true });
    defer allocator.free(req.method);
    defer allocator.free(req.path);
    defer allocator.free(req.query);
    defer allocator.free(req.headers);
    defer allocator.free(req.trailers);
    try std.testing.expectEqualStrings("digest: one", req.trailers);
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
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
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
    defer allocator.free(lowered);
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
        if (header.value.len > 0 and (header.value[0] == ' ' or header.value[0] == '\t' or
            header.value[header.value.len - 1] == ' ' or header.value[header.value.len - 1] == '\t')) return error.BadRequest;
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
    if (fields.len > http_headers.MAX_HTTP1_HEADER_FIELDS) return error.BadRequest;
    for (fields) |header| {
        if (header.name[0] == ':') return error.BadRequest;
        try @import("request_trailers.zig").validateField(header.name, header.value, "");
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
    if (@import("http2_flow.zig").active) |flow| {
        if (flow.record(stream_id)) |record| record.locally_reset = true;
    }
}

pub fn drainClosing(io: std.Io, stream: std.Io.net.Stream) void {
    drainClosingWith(io, stream, @import("socket_io.zig").read);
}

fn drainClosingWith(io: std.Io, stream: std.Io.net.Stream, comptime read: anytype) void {
    // Closing with unread TCP data can erase the GOAWAY with a transport reset.
    // Half-close first, then discard only a bounded amount of raw transport
    // input. No TLS/application data is interpreted after this terminal error.
    stream.shutdown(io, .send) catch return;
    const deadline = @import("read_deadline.zig").Deadline.after(.now(io, .awake), 50);
    var bytes: [1024]u8 = undefined;
    var remaining: usize = 64 * 1024;
    while (remaining != 0) {
        _ = deadline.remaining(.now(io, .awake)) catch return;
        const count = read(io, stream, bytes[0..@min(bytes.len, remaining)], @import("socket_io.zig").Options{ .timeout_ms = 50, .deadline = deadline }) catch return;
        if (count == 0) return;
        remaining -= count;
    }
}

test "terminal drain has byte and absolute time bounds and never owns the final close" {
    const Fake = struct {
        var mode: u8 = 0;
        var calls: usize = 0;
        var total: usize = 0;
        fn shutdown(_: ?*anyopaque, handle: std.Io.net.Socket.Handle, how: std.Io.net.ShutdownHow) std.Io.net.ShutdownError!void {
            std.debug.assert(handle == 123 and how == .send);
        }
        fn read(io: std.Io, _: std.Io.net.Stream, bytes: []u8, _: @import("socket_io.zig").Options) !usize {
            calls += 1;
            if (mode == 1) return error.Canceled;
            if (mode == 2) try io.sleep(.fromMilliseconds(60), .awake);
            total += bytes.len;
            return bytes.len;
        }
    };
    var vtable = std.testing.io.vtable.*;
    vtable.netShutdown = Fake.shutdown;
    var io = std.testing.io;
    io.vtable = &vtable;
    const stream: std.Io.net.Stream = .{ .socket = .{ .handle = 123, .address = undefined } };
    for (0..3) |mode| {
        Fake.mode = @intCast(mode);
        Fake.calls = 0;
        Fake.total = 0;
        drainClosingWith(io, stream, Fake.read);
        try std.testing.expectEqual(if (mode == 0) @as(usize, 64) else 1, Fake.calls);
        try std.testing.expectEqual(@as(usize, if (mode == 0) 65536 else if (mode == 1) 0 else 1024), Fake.total);
    }
}

test "only completed stream resets mark the locally closed history" {
    const flow_mod = @import("http2_flow.zig");
    var flow: flow_mod.State = .{ .io = std.testing.io, .allocator = std.testing.allocator };
    defer flow.deinit();
    const previous = flow_mod.active;
    flow_mod.active = &flow;
    defer flow_mod.active = previous;
    const Fake = struct {
        var fail: bool = false;
        fn write(_: std.Io.net.Stream, _: []const u8) !void {
            if (fail) return error.InjectedWriteFailure;
        }
    };
    try flow.noteStream(1);
    const stream: std.Io.net.Stream = .{ .socket = .{ .handle = 123, .address = undefined } };
    Fake.fail = true;
    try std.testing.expectError(error.CloseConnection, sendRst(stream, 1, 1, Fake.write));
    try std.testing.expect(!flow.record(1).?.locally_reset);
    Fake.fail = false;
    try sendRst(stream, 1, 1, Fake.write);
    try std.testing.expect(flow.record(1).?.locally_reset);
}

pub fn sendHeaderBlock(stream: std.Io.net.Stream, stream_id: u32, block: []const u8, end_stream: bool, write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !void {
    var continuation = false;
    if (@import("http2_flow.zig").active) |flow| {
        if (flow.encoder_resize_pending) {
            const flags: u8 = (if (end_stream) h2_native.FLAG_END_STREAM else @as(u8, 0)) |
                (if (block.len == 0) h2_native.FLAG_END_HEADERS else @as(u8, 0));
            try sendFrame(stream, h2_native.FRAME_HEADERS, flags, stream_id, "\x20", write_all);
            flow.encoder_resize_pending = false;
            continuation = true;
            if (block.len == 0) return;
        }
    }
    if (block.len == 0) {
        try sendFrame(stream, h2_native.FRAME_HEADERS, h2_native.FLAG_END_HEADERS | (if (end_stream) h2_native.FLAG_END_STREAM else @as(u8, 0)), stream_id, "", write_all);
        return;
    }
    var offset: usize = 0;
    while (offset < block.len) {
        const end = @min(offset + 16384, block.len);
        const flags: u8 = (if (end == block.len) h2_native.FLAG_END_HEADERS else @as(u8, 0)) |
            (if (!continuation and offset == 0 and end_stream) h2_native.FLAG_END_STREAM else @as(u8, 0));
        try sendFrame(stream, if (!continuation and offset == 0) h2_native.FRAME_HEADERS else 0x9, flags, stream_id, block[offset..end], write_all);
        offset = end;
    }
}

pub fn sendSettings(stream: std.Io.net.Stream, max_streams: u32, header_bytes: usize, write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !void {
    var payload: [12]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], 3, .big);
    std.mem.writeInt(u32, payload[2..6], max_streams, .big);
    std.mem.writeInt(u16, payload[6..8], 6, .big);
    std.mem.writeInt(u32, payload[8..12], @intCast(@min(header_bytes, std.math.maxInt(u32))), .big);
    try sendFrame(stream, h2_native.FRAME_SETTINGS, 0, 0, &payload, write_all);
}

test "peer table reductions lead the next field block and preserve END_STREAM across continuation" {
    const flow_mod = @import("http2_flow.zig");
    var flow: flow_mod.State = .{ .io = std.testing.io, .allocator = std.testing.allocator };
    defer flow.deinit();
    const previous = flow_mod.active;
    flow_mod.active = &flow;
    defer flow_mod.active = previous;
    const Fake = struct {
        var output: std.ArrayList(u8) = .empty;
        var fail = false;
        fn write(_: std.Io.net.Stream, bytes: []const u8) !void {
            if (fail) return error.InjectedWriteFailure;
            try output.appendSlice(std.testing.allocator, bytes);
        }
    };
    Fake.output = .empty;
    defer Fake.output.deinit(std.testing.allocator);
    try flow.settings("\x00\x01\x00\x00\x00\x08\x00\x01\x00\x00\x10\x00");
    try std.testing.expectEqual(0, flow.encoder_table_limit);
    const stream: std.Io.net.Stream = .{ .socket = .{ .handle = 123, .address = undefined } };
    Fake.fail = true;
    try std.testing.expectError(error.CloseConnection, sendHeaderBlock(stream, 1, "\x88", true, Fake.write));
    try std.testing.expect(flow.encoder_resize_pending);
    Fake.fail = false;
    try sendHeaderBlock(stream, 1, "\x88", true, Fake.write);
    try std.testing.expect(!flow.encoder_resize_pending);
    try std.testing.expectEqualSlices(u8, "\x00\x00\x01\x01\x01\x00\x00\x00\x01\x20" ++
        "\x00\x00\x01\x09\x04\x00\x00\x00\x01\x88", Fake.output.items);
    Fake.output.clearRetainingCapacity();
    try sendHeaderBlock(stream, 3, "", true, Fake.write);
    try std.testing.expectEqualSlices(u8, "\x00\x00\x00\x01\x05\x00\x00\x00\x03", Fake.output.items);
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

pub fn collectUpstreamHeaders(allocator: std.mem.Allocator, response_headers: []const u8, connection_fields: []const u8) ![]h2_native.Header {
    var out = std.ArrayList(h2_native.Header).empty;
    errdefer out.deinit(allocator);

    var lines = std.mem.splitSequence(u8, response_headers, "\r\n");
    while (lines.next()) |line| {
        const trimmed = http_headers.trimValue(line);
        if (trimmed.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse continue;
        const name = http_headers.trimValue(trimmed[0..colon]);
        if (isSkippedResponseHeader(name) or proxy_utils.isConnectionField(connection_fields, name)) continue;
        const value = http_headers.trimValue(trimmed[colon + 1 ..]);
        const lowered = try lowerHeaderName(allocator, name);
        try out.append(allocator, .{ .name = lowered, .value = try allocator.dupe(u8, value) });
    }

    return out.toOwnedSlice(allocator);
}

pub fn responseHasNoBody(method: []const u8, status_code: u16) bool {
    return proxy_utils.responseHasNoBody(method, status_code);
}
