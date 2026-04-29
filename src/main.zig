const std = @import("std");
const builtin = @import("builtin");
const h3_native = @import("h3_native.zig");
const h3_state = @import("h3_state.zig");
const http_response = @import("http_response.zig");
const quic_native = @import("quic_native.zig");
const tls13_native = @import("tls13_native.zig");

// Boring defaults on purpose: enough room for local dev, with caps before
// anything can turn into an accidental memory sink.
const DEFAULT_MAX_REQUEST_BYTES = 16 * 1024;
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
const DEFAULT_MAX_STATIC_FILE_BYTES = 10 * 1024 * 1024;
// Keep one chatty keep-alive socket from owning a worker forever.
const DEFAULT_MAX_REQUESTS_PER_CONNECTION = 256;
// High ceiling, but still a ceiling. Past it we answer 503 instead of drifting.
const DEFAULT_MAX_CONCURRENT_CONNECTIONS = 1_000_000;
// Small enough for lots of workers; not so small that PHP/proxy paths fall over.
const DEFAULT_WORKER_STACK_BYTES = 64 * 1024;
// PHP can be noisy. Treat child output as untrusted input too.
const DEFAULT_MAX_PHP_OUTPUT_BYTES = 2 * 1024 * 1024;
const DEFAULT_READ_HEADER_TIMEOUT_MS = 10_000;
const DEFAULT_READ_BODY_TIMEOUT_MS = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS = 60_000;
const DEFAULT_WRITE_TIMEOUT_MS = 30_000;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 30_000;
const DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_MS = 10_000;
const HTTP2_PREFACE_MAGIC = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_CHUNK_LINE_BYTES = 4096;
const DEFAULT_CONFIG_PATH = "server.conf";
const SERVER_NAME = "Layerline";
const SERVER_TAGLINE = "Modern web server";
const SERVER_HEADER = "Layerline";
const HTTP3_INITIAL_PADDING_BYTES = 600;
const HTTP3_MAX_DATAGRAM_BYTES = 1200;
const HTTP3_CONNECTION_TABLE_CAPACITY = 1024;
const QUIC_SHORT_PACKET_NUMBER_BYTES = 4;
const QUIC_AEAD_TAG_BYTES = 16;

const HAS_DARWIN_SENDFILE = switch (builtin.os.tag) {
    .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => true,
    else => false,
};

const SERVER_ICON_SVG =
    \\<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" role="img" aria-labelledby="title desc">
    \\  <title id="title">Layerline</title>
    \\  <desc id="desc">A layered route mark for the Layerline HTTP server.</desc>
    \\  <rect width="128" height="128" rx="30" fill="#fbfaf6"/>
    \\  <rect x="8" y="8" width="112" height="112" rx="24" fill="none" stroke="#11110f" stroke-opacity=".16" stroke-width="4"/>
    \\  <path d="M29 33h70L29 96h70" fill="none" stroke="#11110f" stroke-width="12" stroke-linecap="round" stroke-linejoin="round"/>
    \\  <path d="M40 48h48M40 80h48" fill="none" stroke="#11110f" stroke-opacity=".18" stroke-width="5" stroke-linecap="round"/>
    \\  <circle cx="38" cy="39" r="8" fill="#fbfaf6" stroke="#11110f" stroke-width="5"/>
    \\  <circle cx="90" cy="89" r="8" fill="#fbfaf6" stroke="#11110f" stroke-width="5"/>
    \\  <circle cx="64" cy="64" r="17" fill="none" stroke="#11110f" stroke-opacity=".28" stroke-width="4"/>
    \\</svg>
;

threadlocal var current_io: ?std.Io = null;
threadlocal var current_response_headers: []const ResponseHeaderRule = &.{};
var shutdown_requested = std.atomic.Value(bool).init(false);
var listener_closed_by_shutdown = std.atomic.Value(bool).init(false);

// Zig 0.16 moved sockets behind std.Io, so detached worker threads need their
// own bound handle before they touch a stream.
fn bindThreadIo(io: std.Io) void {
    current_io = io;
}

fn activeIo() std.Io {
    return current_io orelse @panic("network stream used before std.Io was bound to this thread");
}

fn normalizeSocketIoError(err: anyerror) anyerror {
    return switch (err) {
        error.WouldBlock, error.TimedOut, error.ConnectionTimedOut, error.Unexpected => error.RequestTimeout,
        else => err,
    };
}

fn streamRead(stream: std.Io.net.Stream, out: []u8) !usize {
    const io = activeIo();
    var data: [1][]u8 = .{out};
    return io.vtable.netRead(io.userdata, stream.socket.handle, &data) catch |err| return normalizeSocketIoError(err);
}

fn streamWriteAll(stream: std.Io.net.Stream, bytes: []const u8) !void {
    const io = activeIo();
    var written: usize = 0;
    while (written < bytes.len) {
        // netWrite expects a real scatter list here. Passing an empty one
        // looked tidy, then crashed in the vtable path.
        const empty: [1][]const u8 = .{""};
        const n = io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &empty, 0) catch |err| return normalizeSocketIoError(err);
        if (n == 0) return error.WriteZero;
        written += n;
    }
}

fn streamWriteFmt(stream: std.Io.net.Stream, comptime fmt: []const u8, args: anytype) !void {
    var stack_buffer: [4096]u8 = undefined;
    const rendered = try std.fmt.bufPrint(&stack_buffer, fmt, args);
    try streamWriteAll(stream, rendered);
}

fn timeoutMsToTimeval(timeout_ms: u32) std.posix.timeval {
    return .{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
}

fn setStreamReadTimeout(stream: std.Io.net.Stream, timeout_ms: u32) !void {
    if (builtin.os.tag == .windows) return;
    var tv = timeoutMsToTimeval(timeout_ms);
    try std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
}

fn setStreamWriteTimeout(stream: std.Io.net.Stream, timeout_ms: u32) !void {
    if (builtin.os.tag == .windows) return;
    var tv = timeoutMsToTimeval(timeout_ms);
    try std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv));
}

fn setStreamTimeouts(stream: std.Io.net.Stream, read_timeout_ms: u32, write_timeout_ms: u32) !void {
    try setStreamReadTimeout(stream, read_timeout_ms);
    try setStreamWriteTimeout(stream, write_timeout_ms);
}

fn shutdownSignalHandler(_: std.posix.SIG) callconv(.c) void {
    shutdown_requested.store(true, .release);
}

fn installShutdownSignalHandlers() void {
    if (std.posix.Sigaction == void) return;
    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = shutdownSignalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &action, null);
    std.posix.sigaction(.TERM, &action, null);
}

const ShutdownWatcherContext = struct {
    io: std.Io,
    server: *std.Io.net.Server,
};

fn shutdownWatcherTask(ctx: ShutdownWatcherContext) void {
    bindThreadIo(ctx.io);
    while (!shutdown_requested.load(.acquire)) {
        ctx.io.sleep(.fromMilliseconds(25), .awake) catch {};
    }

    if (!listener_closed_by_shutdown.swap(true, .acq_rel)) {
        ctx.server.socket.close(ctx.io);
    }
}

fn streamWriteConfiguredResponseHeaders(stream: std.Io.net.Stream) !void {
    for (current_response_headers) |header| {
        try streamWriteFmt(stream, "{s}: {s}\r\n", .{ header.name, header.value });
    }
}

fn streamClose(stream: std.Io.net.Stream) void {
    stream.close(activeIo());
}

fn connectTcpHost(allocator: std.mem.Allocator, host: []const u8, port: u16) !std.Io.net.Stream {
    _ = allocator;
    if (std.Io.net.IpAddress.parse(host, port)) |address| {
        var addr = address;
        return addr.connect(activeIo(), .{ .mode = .stream });
    } else |_| {}

    const host_name = try std.Io.net.HostName.init(host);
    return host_name.connect(activeIo(), port, .{ .mode = .stream });
}

// Slices in here point into the per-request arena. Keep that arena alive until
// routing finishes or the request quietly turns into garbage.
const HttpRequest = struct {
    method: []const u8,
    path: []const u8,
    query: []const u8,
    headers: []const u8,
    version: []const u8,
    body: []const u8,
    close_connection: bool,
};

// Parsed form of a configured upstream endpoint.
const UpstreamConfig = struct {
    host: []const u8,
    port: u16,
    base_path: []const u8,
    https: bool,
};

const UpstreamPoolPolicy = enum {
    round_robin,
};

const UpstreamPoolConfig = struct {
    targets: std.ArrayList(UpstreamConfig),
    policy: UpstreamPoolPolicy,
};

const ResponseHeaderRule = struct {
    name: []const u8,
    value: []const u8,
};

const RedirectRule = struct {
    from: []const u8,
    to: []const u8,
    status_code: u16,
    prefix_match: bool,
};

const RouteMatchKind = enum {
    exact,
    prefix,
};

const RouteHandlerKind = enum {
    static,
    php,
    proxy,
};

const RouteStringProperty = enum {
    static_dir,
    index_file,
    php_root,
    php_binary,
};

const RouteBoolProperty = enum {
    php_info_page,
    strip_prefix,
};

const DomainStringProperty = enum {
    static_dir,
    index_file,
    php_root,
    php_binary,
};

const DomainBoolProperty = enum {
    serve_static_root,
    php_info_page,
};

const RouteConfig = struct {
    name: []const u8,
    pattern: []const u8,
    match_kind: RouteMatchKind,
    handler: RouteHandlerKind,
    strip_prefix: bool,
    static_dir: ?[]const u8,
    index_file: ?[]const u8,
    php_root: ?[]const u8,
    php_binary: ?[]const u8,
    php_info_page: ?bool,
    upstream: ?UpstreamPoolConfig,
};

const DomainConfig = struct {
    name: []const u8,
    server_names: std.ArrayList([]const u8),
    static_dir: ?[]const u8,
    serve_static_root: ?bool,
    index_file: ?[]const u8,
    php_root: ?[]const u8,
    php_binary: ?[]const u8,
    php_info_page: ?bool,
    upstream: ?UpstreamPoolConfig,
    redirects: std.ArrayList(RedirectRule),
    routes: std.ArrayList(RouteConfig),
};

// All server behavior is described in this single config object.
const ServerConfig = struct {
    host: []const u8,
    port: u16,
    static_dir: []const u8,
    serve_static_root: bool,
    index_file: []const u8,
    php_root: []const u8,
    php_binary: []const u8,
    php_info_page: bool,
    upstream: ?UpstreamPoolConfig,
    tls_enabled: bool,
    tls_cert: ?[]const u8,
    tls_key: ?[]const u8,
    tls_auto: bool,
    letsencrypt_email: ?[]const u8,
    letsencrypt_domains: ?[]const u8,
    letsencrypt_webroot: []const u8,
    letsencrypt_certbot: []const u8,
    letsencrypt_staging: bool,
    h2_upstream: ?UpstreamConfig,
    http3_enabled: bool,
    http3_port: u16,
    response_headers: std.ArrayList(ResponseHeaderRule),
    redirects: std.ArrayList(RedirectRule),
    routes: std.ArrayList(RouteConfig),
    domains: std.ArrayList(DomainConfig),
    max_request_bytes: usize,
    max_body_bytes: usize,
    max_static_file_bytes: usize,
    max_requests_per_connection: usize,
    max_concurrent_connections: usize,
    worker_stack_size: usize,
    read_header_timeout_ms: u32,
    read_body_timeout_ms: u32,
    idle_timeout_ms: u32,
    write_timeout_ms: u32,
    upstream_timeout_ms: u32,
    graceful_shutdown_timeout_ms: u32,
    cloudflare_auto_deploy: bool,
    max_php_output_bytes: usize,
    cloudflare_api_base: []const u8,
    cloudflare_token: ?[]const u8,
    cloudflare_zone_id: ?[]const u8,
    cloudflare_zone_name: ?[]const u8,
    cloudflare_record_name: ?[]const u8,
    cloudflare_record_type: []const u8,
    cloudflare_record_content: ?[]const u8,
    cloudflare_record_ttl: u32,
    cloudflare_record_proxied: bool,
    cloudflare_record_comment: ?[]const u8,
};

fn parseContentLength(headers: []const u8) !usize {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const key = std.mem.trim(u8, line[0..colon], " \t");
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(key, "Content-Length")) {
                return std.fmt.parseInt(usize, value, 10) catch return error.InvalidContentLength;
            }
        }
    }

    return 0;
}

fn hasHeaderToken(headers: []const u8, name: []const u8, token: []const u8) bool {
    const value = findHeaderValue(headers, name) orelse return false;
    return hasConnectionToken(value, token);
}

fn hasConnectionToken(connection: []const u8, token: []const u8) bool {
    var cursor = connection;
    while (cursor.len > 0) {
        const comma_pos = std.mem.indexOfScalar(u8, cursor, ',') orelse cursor.len;
        const item = if (comma_pos > 0) trimValue(cursor[0..comma_pos]) else cursor;
        if (item.len > 0 and std.ascii.eqlIgnoreCase(item, token)) return true;
        if (comma_pos >= cursor.len) break;
        cursor = cursor[comma_pos + 1 ..];
    }
    return false;
}

fn parseConnectionClose(version: []const u8, headers: []const u8) bool {
    const connection = findHeaderValue(headers, "Connection") orelse "";
    const wants_close = hasConnectionToken(connection, "close");
    const wants_keep_alive = hasConnectionToken(connection, "keep-alive");

    const is_http11 = std.mem.startsWith(u8, version, "HTTP/1.1");
    const is_http10 = std.mem.startsWith(u8, version, "HTTP/1.0");

    if (wants_close) return true;
    if (is_http10) {
        return !wants_keep_alive;
    }
    if (is_http11) return false;
    return true;
}

fn transferEncodingIsChunkedOnly(headers: []const u8) !bool {
    const value = findHeaderValue(headers, "Transfer-Encoding") orelse return false;

    // This server understands normal fixed-length bodies and chunked bodies.
    // Anything stacked on top of chunked needs a real decoder, not optimism.
    var saw_chunked = false;
    var cursor = value;
    while (cursor.len > 0) {
        const comma_pos = std.mem.indexOfScalar(u8, cursor, ',') orelse cursor.len;
        const item = if (comma_pos > 0) trimValue(cursor[0..comma_pos]) else cursor;
        if (item.len > 0) {
            if (std.ascii.eqlIgnoreCase(item, "chunked")) {
                saw_chunked = true;
            } else {
                return error.UnsupportedTransferEncoding;
            }
        }
        if (comma_pos >= cursor.len) break;
        cursor = cursor[comma_pos + 1 ..];
    }

    return saw_chunked;
}

fn findHeaderValue(headers: []const u8, target_name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const key = std.mem.trim(u8, line[0..colon], " \t");
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(key, target_name)) return value;
        }
    }

    return null;
}

fn findQueryValue(query: []const u8, key: []const u8) ?[]const u8 {
    if (query.len == 0) return null;

    var cursor = query;
    while (cursor.len > 0) {
        const token_end = std.mem.indexOfScalar(u8, cursor, '&') orelse cursor.len;
        const pair = cursor[0..token_end];

        if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
            const k = pair[0..eq];
            const v = pair[eq + 1 ..];
            if (std.mem.eql(u8, k, key)) return v;
        } else if (std.mem.eql(u8, pair, key)) {
            return "";
        }

        if (token_end == cursor.len) break;
        cursor = cursor[token_end + 1 ..];
    }

    return null;
}

fn trimValue(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t\r\n");
}

const CgiHeaderSplit = struct {
    headers: []const u8,
    body: []const u8,
};

const CgiStatus = struct {
    code: u16,
    text: []const u8,
};

fn splitCgiHeaderBlock(output: []const u8) ?CgiHeaderSplit {
    if (std.mem.indexOf(u8, output, "\r\n\r\n")) |idx| {
        return .{ .headers = output[0..idx], .body = output[idx + 4 ..] };
    }
    if (std.mem.indexOf(u8, output, "\n\n")) |idx| {
        return .{ .headers = output[0..idx], .body = output[idx + 2 ..] };
    }
    return null;
}

fn findCgiHeaderValue(headers: []const u8, target_name: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const key = trimValue(line[0..colon]);
            const value = trimValue(line[colon + 1 ..]);
            if (std.ascii.eqlIgnoreCase(key, target_name)) return value;
        }
    }
    return null;
}

fn statusTextForCode(status_code: u16) []const u8 {
    return switch (status_code) {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        426 => "Upgrade Required",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        else => if (status_code >= 500) "Internal Server Error" else if (status_code >= 400) "Bad Request" else "OK",
    };
}

fn parseCgiStatus(headers: []const u8) CgiStatus {
    const raw_status = findCgiHeaderValue(headers, "Status") orelse return .{ .code = 200, .text = "OK" };
    const status_line = trimValue(raw_status);
    if (status_line.len < 3) return .{ .code = 200, .text = "OK" };

    const code = std.fmt.parseInt(u16, status_line[0..@min(3, status_line.len)], 10) catch 200;
    if (code < 100 or code > 599) return .{ .code = 200, .text = "OK" };

    if (status_line.len > 3) {
        const reason = trimValue(status_line[3..]);
        if (reason.len > 0) return .{ .code = code, .text = reason };
    }

    return .{ .code = code, .text = statusTextForCode(code) };
}

fn isSkippedCgiResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "Status") or
        std.ascii.eqlIgnoreCase(name, "Content-Type") or
        std.ascii.eqlIgnoreCase(name, "Content-Length") or
        std.ascii.eqlIgnoreCase(name, "Connection") or
        std.ascii.eqlIgnoreCase(name, "Keep-Alive") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authenticate") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authorization") or
        std.ascii.eqlIgnoreCase(name, "TE") or
        std.ascii.eqlIgnoreCase(name, "Trailer") or
        std.ascii.eqlIgnoreCase(name, "Trailers") or
        std.ascii.eqlIgnoreCase(name, "Transfer-Encoding") or
        std.ascii.eqlIgnoreCase(name, "Upgrade") or
        std.ascii.eqlIgnoreCase(name, "Server");
}

fn buildCgiExtraHeaders(allocator: std.mem.Allocator, headers: []const u8) !?[]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |line| {
        const trimmed = trimValue(line);
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const name = trimValue(trimmed[0..colon]);
            const value = trimValue(trimmed[colon + 1 ..]);
            if (name.len == 0 or value.len == 0 or isSkippedCgiResponseHeader(name)) continue;
            try out.print(allocator, "{s}: {s}\r\n", .{ name, value });
        }
    }

    if (out.items.len == 0) {
        out.deinit(allocator);
        return null;
    }
    return try out.toOwnedSlice(allocator);
}

fn isCgiHeaderNameChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_';
}

fn putCgiRequestHeaders(
    allocator: std.mem.Allocator,
    env: *std.process.Environ.Map,
    request_headers: []const u8,
) !void {
    var lines = std.mem.splitSequence(u8, request_headers, "\r\n");
    while (lines.next()) |line| {
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const name = trimValue(line[0..colon]);
            const value = trimValue(line[colon + 1 ..]);
            if (name.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(name, "Content-Type") or std.ascii.eqlIgnoreCase(name, "Content-Length")) continue;

            var env_name = std.ArrayList(u8).empty;
            defer env_name.deinit(allocator);
            try env_name.appendSlice(allocator, "HTTP_");
            for (name) |c| {
                if (!isCgiHeaderNameChar(c)) {
                    env_name.clearRetainingCapacity();
                    break;
                }
                try env_name.append(allocator, if (c == '-') '_' else std.ascii.toUpper(c));
            }
            if (env_name.items.len <= "HTTP_".len) continue;
            try env.put(env_name.items, value);
        }
    }
}

fn isPhpCgiBinary(path: []const u8) bool {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return std.mem.indexOf(u8, path, "php-cgi") != null;
    return std.mem.indexOf(u8, path[slash + 1 ..], "php-cgi") != null;
}

test "splits CGI output with CRLF or LF separators" {
    const crlf = splitCgiHeaderBlock("Content-Type: text/plain\r\n\r\nbody").?;
    try std.testing.expectEqualStrings("Content-Type: text/plain", crlf.headers);
    try std.testing.expectEqualStrings("body", crlf.body);

    const lf = splitCgiHeaderBlock("Content-Type: text/plain\n\nbody").?;
    try std.testing.expectEqualStrings("Content-Type: text/plain", lf.headers);
    try std.testing.expectEqualStrings("body", lf.body);
}

test "parses CGI status headers with reason text" {
    const status = parseCgiStatus("Status: 404 Not Found\nContent-Type: text/plain");
    try std.testing.expectEqual(@as(u16, 404), status.code);
    try std.testing.expectEqualStrings("Not Found", status.text);

    const default_status = parseCgiStatus("Content-Type: text/plain");
    try std.testing.expectEqual(@as(u16, 200), default_status.code);
    try std.testing.expectEqualStrings("OK", default_status.text);
}

fn firstToken(raw: []const u8, delimiter: u8, start: usize) ?[]const u8 {
    if (raw.len == 0 or start >= raw.len) return null;
    const remaining = raw[start..];
    const trimmed = trimValue(remaining);
    if (trimmed.len == 0) return null;
    if (std.mem.indexOfScalar(u8, trimmed, delimiter)) |delim| {
        return trimValue(trimmed[0..delim]);
    }
    return trimmed;
}

fn listLetsencryptDomains(allocator: std.mem.Allocator, raw: []const u8, out: *std.ArrayList([]const u8)) !bool {
    var has_domain = false;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |domain_raw| {
        const domain = trimValue(domain_raw);
        if (domain.len == 0) continue;
        try out.append(allocator, try allocator.dupe(u8, domain));
        has_domain = true;
    }
    return has_domain;
}

fn runCommandCapture(io: std.Io, allocator: std.mem.Allocator, command: []const u8, args: []const []const u8) ![]const u8 {
    var full_args = std.ArrayList([]const u8).empty;
    defer full_args.deinit(allocator);
    try full_args.append(allocator, command);
    for (args) |arg| try full_args.append(allocator, arg);

    const result = try std.process.run(
        allocator,
        io,
        .{
            .argv = full_args.items,
            .stdout_limit = .limited(1024 * 1024),
            .stderr_limit = .limited(256 * 1024),
        },
    );
    const out = result.stdout;
    const err_out = result.stderr;
    defer allocator.free(err_out);
    switch (result.term) {
        .exited => |code| {
            if (code != 0) return error.UnexpectedExit;
        },
        else => return error.UnexpectedExit,
    }

    if (out.len > 0 and std.mem.indexOf(u8, command, "curl") == null) {
        std.debug.print("[cmd] {s}\n", .{out});
    }
    if (err_out.len > 0) {
        std.debug.print("[cmd err] {s}\n", .{err_out});
    }

    return out;
}

fn runCommand(io: std.Io, allocator: std.mem.Allocator, command: []const u8, args: []const []const u8) !void {
    const out = try runCommandCapture(io, allocator, command, args);
    allocator.free(out);
}

fn isCloudflareSuccess(payload: []const u8) bool {
    return std.mem.indexOf(u8, payload, "\"success\":true") != null;
}

fn extractCloudflareFirstId(payload: []const u8) ?[]const u8 {
    const result_pos = std.mem.indexOf(u8, payload, "\"result\":") orelse return null;
    const payload_rest = payload[result_pos + "\"result\":".len ..];
    const id_key = "\"id\":\"";
    const id_pos = std.mem.indexOf(u8, payload_rest, id_key) orelse return null;
    const start = id_pos + id_key.len;
    const end = std.mem.indexOfScalar(u8, payload_rest[start..], '"') orelse return null;
    return payload_rest[start .. start + end];
}

fn extractCloudflareError(payload: []const u8) ?[]const u8 {
    const errors_pos = std.mem.indexOf(u8, payload, "\"errors\":[") orelse return null;
    const marker = "\"message\":\"";
    const msg_pos = std.mem.indexOf(u8, payload[errors_pos..], marker) orelse return null;
    const msg_start = msg_pos + marker.len;
    const msg_end = std.mem.indexOfScalar(u8, payload[errors_pos + msg_start ..], '"') orelse return null;
    return payload[errors_pos + msg_start .. errors_pos + msg_start + msg_end];
}

fn callCloudflareApi(
    io: std.Io,
    allocator: std.mem.Allocator,
    token: []const u8,
    api_base: []const u8,
    method: []const u8,
    endpoint: []const u8,
    payload: ?[]const u8,
) ![]const u8 {
    const url = try std.fmt.allocPrint(allocator, "{s}{s}", .{ api_base, endpoint });
    defer allocator.free(url);

    const auth_header = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{token});
    defer allocator.free(auth_header);

    var args = std.ArrayList([]const u8).empty;
    defer args.deinit(allocator);
    try args.appendSlice(allocator, &.{
        "curl",
        "-fsS",
        "-X",
        method,
        "-H",
        auth_header,
        "-H",
        "Content-Type: application/json",
    });
    if (payload) |body| {
        try args.append(allocator, "-d");
        try args.append(allocator, body);
    }
    try args.append(allocator, url);

    return try runCommandCapture(io, allocator, args.items[0], args.items[1..]);
}

fn detectPublicIp(io: std.Io, allocator: std.mem.Allocator, record_type: []const u8) ![]const u8 {
    const target_service = if (std.mem.eql(u8, record_type, "AAAA"))
        "https://api64.ipify.org?format=text"
    else
        "https://api64.ipify.org";
    const out = trimValue(try runCommandCapture(io, allocator, "curl", &.{ "-fsS", target_service }));
    if (out.len == 0) return error.UnexpectedResponse;
    return try allocator.dupe(u8, out);
}

fn ensureCloudflareDeployment(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig) !void {
    if (!cfg.cloudflare_auto_deploy) return;

    if (cfg.cloudflare_token == null) {
        std.debug.print("Cloudflare deployment enabled but no token configured (--cf-token).\n", .{});
        return error.MissingCloudflareToken;
    }

    const token = cfg.cloudflare_token.?;
    const api_base = cfg.cloudflare_api_base;

    var zone_id = cfg.cloudflare_zone_id;
    var zone_id_owned: ?[]const u8 = null;
    defer if (zone_id_owned) |owned| allocator.free(owned);

    if (zone_id == null and cfg.cloudflare_zone_name != null) {
        const zone_name = cfg.cloudflare_zone_name.?;
        const zone_lookup_ep = try std.fmt.allocPrint(allocator, "/zones?name={s}", .{zone_name});
        defer allocator.free(zone_lookup_ep);

        const zone_payload = try callCloudflareApi(io, allocator, token, api_base, "GET", zone_lookup_ep, null);
        defer allocator.free(zone_payload);

        if (!isCloudflareSuccess(zone_payload)) {
            const reason = extractCloudflareError(zone_payload) orelse "unknown reason";
            std.debug.print("Cloudflare zone lookup failed: {s}\n", .{reason});
            return error.CloudflareZoneLookupFailed;
        }

        if (extractCloudflareFirstId(zone_payload)) |found_zone_id| {
            zone_id_owned = try allocator.dupe(u8, found_zone_id);
            zone_id = zone_id_owned;
        }
    }

    if (zone_id == null) {
        std.debug.print("Cloudflare deployment needs --cf-zone-id or --cf-zone-name.\n", .{});
        return error.CloudflareZoneMissing;
    }

    var record_name = if (cfg.cloudflare_record_name) |name| trimValue(name) else "";
    if (record_name.len == 0 and cfg.letsencrypt_domains != null) {
        const first_domain = firstToken(cfg.letsencrypt_domains.?, ',', 0);
        if (first_domain != null) record_name = first_domain.?;
    }
    if (record_name.len == 0) {
        std.debug.print("Cloudflare deployment needs --cf-record-name (or letsencrypt_domains for default).\n", .{});
        return error.CloudflareRecordNameMissing;
    }

    const record_type = if (cfg.cloudflare_record_type.len > 0) cfg.cloudflare_record_type else "A";
    const config_content = if (cfg.cloudflare_record_content) |value| trimValue(value) else "";
    var auto_content: ?[]const u8 = null;
    defer if (auto_content) |value| allocator.free(value);
    const final_content: []const u8 = if (config_content.len > 0) config_content else blk: {
        if (!std.mem.eql(u8, record_type, "A") and !std.mem.eql(u8, record_type, "AAAA")) {
            std.debug.print(
                "Cloudflare deployment needs --cf-record-content for DNS type {s}.\n",
                .{record_type},
            );
            return error.CloudflareRecordContentMissing;
        }
        const detected = try detectPublicIp(io, allocator, record_type);
        auto_content = detected;
        break :blk detected;
    };

    if (final_content.len == 0) {
        std.debug.print("Cloudflare deployment needs --cf-record-content or a detectable public IP.\n", .{});
        return error.CloudflareRecordContentMissing;
    }

    const list_endpoint = try std.fmt.allocPrint(
        allocator,
        "/zones/{s}/dns_records?type={s}&name={s}",
        .{ zone_id.?, record_type, record_name },
    );
    defer allocator.free(list_endpoint);

    const list_payload = try callCloudflareApi(io, allocator, token, api_base, "GET", list_endpoint, null);
    defer allocator.free(list_payload);

    if (!isCloudflareSuccess(list_payload)) {
        const reason = extractCloudflareError(list_payload) orelse "unknown reason";
        std.debug.print("Cloudflare DNS lookup failed: {s}\n", .{reason});
        return error.CloudflareDnsLookupFailed;
    }

    const existing_record_id = extractCloudflareFirstId(list_payload);

    const record_payload = if (cfg.cloudflare_record_comment) |raw_comment| blk: {
        const comment = trimValue(raw_comment);
        if (comment.len == 0) {
            break :blk try std.fmt.allocPrint(
                allocator,
                "{{\"type\":\"{s}\",\"name\":\"{s}\",\"content\":\"{s}\",\"ttl\":{d},\"proxied\":{s}}}",
                .{
                    record_type,
                    record_name,
                    final_content,
                    cfg.cloudflare_record_ttl,
                    if (cfg.cloudflare_record_proxied) "true" else "false",
                },
            );
        }
        break :blk try std.fmt.allocPrint(
            allocator,
            "{{\"type\":\"{s}\",\"name\":\"{s}\",\"content\":\"{s}\",\"ttl\":{d},\"proxied\":{s},\"comment\":\"{s}\"}}",
            .{
                record_type,
                record_name,
                final_content,
                cfg.cloudflare_record_ttl,
                if (cfg.cloudflare_record_proxied) "true" else "false",
                comment,
            },
        );
    } else try std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"{s}\",\"name\":\"{s}\",\"content\":\"{s}\",\"ttl\":{d},\"proxied\":{s}}}",
        .{
            record_type,
            record_name,
            final_content,
            cfg.cloudflare_record_ttl,
            if (cfg.cloudflare_record_proxied) "true" else "false",
        },
    );
    defer allocator.free(record_payload);

    const method: []const u8 = if (existing_record_id != null) "PUT" else "POST";
    const endpoint: []const u8 = if (existing_record_id != null)
        try std.fmt.allocPrint(allocator, "/zones/{s}/dns_records/{s}", .{ zone_id.?, existing_record_id.? })
    else
        try std.fmt.allocPrint(allocator, "/zones/{s}/dns_records", .{zone_id.?});
    defer allocator.free(endpoint);

    const deploy_payload = try callCloudflareApi(io, allocator, token, api_base, method, endpoint, record_payload);
    defer allocator.free(deploy_payload);

    if (!isCloudflareSuccess(deploy_payload)) {
        const reason = extractCloudflareError(deploy_payload) orelse "unknown reason";
        std.debug.print("Cloudflare DNS {s} failed for {s}: {s}\n", .{ method, record_name, reason });
        return error.CloudflareRecordUpdateFailed;
    }

    const action = if (existing_record_id != null) "updated" else "created";
    std.debug.print("Cloudflare DNS {s}: {s} {s} -> {s}\n", .{ action, record_name, record_type, final_content });
}

fn ensureLetsEncryptSetup(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
    if (!cfg.tls_auto) return;
    if (cfg.letsencrypt_domains == null or cfg.letsencrypt_domains.?.len == 0) {
        std.debug.print("Skipping Let's Encrypt setup because letsencrypt_domains is empty.\n", .{});
        return;
    }

    if (cfg.letsencrypt_webroot.len == 0) return;
    std.Io.Dir.cwd().createDirPath(io, cfg.letsencrypt_webroot) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    if (cfg.tls_cert == null or cfg.tls_key == null) {
        if (firstToken(cfg.letsencrypt_domains.?, ',', 0)) |domain| {
            if (cfg.tls_cert == null) cfg.tls_cert = try std.fmt.allocPrint(allocator, "/etc/letsencrypt/live/{s}/fullchain.pem", .{domain});
            if (cfg.tls_key == null) cfg.tls_key = try std.fmt.allocPrint(allocator, "/etc/letsencrypt/live/{s}/privkey.pem", .{domain});
        }
    }

    var domains = std.ArrayList([]const u8).empty;
    defer {
        for (domains.items) |d| allocator.free(d);
        domains.deinit(allocator);
    }
    if (!try listLetsencryptDomains(allocator, cfg.letsencrypt_domains.?, &domains)) {
        std.debug.print("Skipping Let's Encrypt setup because domain list is empty.\n", .{});
        return;
    }

    var cert_args = std.ArrayList([]const u8).empty;
    defer cert_args.deinit(allocator);
    try cert_args.appendSlice(allocator, &.{
        "certonly",
        "--non-interactive",
        "--agree-tos",
        "--keep-until-expiring",
        "--webroot",
        "-w",
        cfg.letsencrypt_webroot,
        "--config-dir",
        "/etc/letsencrypt",
    });
    if (cfg.letsencrypt_staging) {
        try cert_args.append(allocator, "--staging");
    }
    if (cfg.letsencrypt_email) |email| {
        try cert_args.append(allocator, "--email");
        try cert_args.append(allocator, email);
    } else {
        try cert_args.append(allocator, "--register-unsafely-without-email");
    }

    for (domains.items) |domain| {
        try cert_args.append(allocator, "-d");
        try cert_args.append(allocator, domain);
    }

    std.debug.print("Running Let's Encrypt setup for {d} domain(s) via {s}\n", .{ domains.items.len, cfg.letsencrypt_certbot });
    try runCommand(io, allocator, cfg.letsencrypt_certbot, cert_args.items);
}

fn isLikelyHttp2Preface(bytes: []const u8) bool {
    if (bytes.len < 7) return false;
    if (std.mem.startsWith(u8, bytes, HTTP2_PREFACE_MAGIC)) return true;
    return std.mem.startsWith(u8, bytes, "PRI * ");
}

// Shared tracker for active socket workers to enforce max concurrent limit.
const ConcurrencyState = struct {
    active_connections: std.atomic.Value(usize),

    fn init() ConcurrencyState {
        return .{ .active_connections = std.atomic.Value(usize).init(0) };
    }

    fn tryAcquire(self: *ConcurrencyState, limit: usize) bool {
        while (true) {
            const current = self.active_connections.load(.acquire);
            if (current >= limit) return false;
            if (self.active_connections.cmpxchgWeak(current, current + 1, .acq_rel, .acquire) == null) {
                server_metrics.connectionAccepted();
                return true;
            }
        }
    }

    fn release(self: *ConcurrencyState) void {
        _ = self.active_connections.fetchSub(1, .acq_rel);
        server_metrics.connectionClosed();
    }

    fn active(self: *ConcurrencyState) usize {
        return self.active_connections.load(.acquire);
    }
};

const ServerMetrics = struct {
    active_connections: std.atomic.Value(usize),
    connections_total: std.atomic.Value(usize),
    connections_rejected_total: std.atomic.Value(usize),
    requests_total: std.atomic.Value(usize),
    request_parse_errors_total: std.atomic.Value(usize),
    route_errors_total: std.atomic.Value(usize),
    responses_total: std.atomic.Value(usize),
    response_2xx_total: std.atomic.Value(usize),
    response_3xx_total: std.atomic.Value(usize),
    response_4xx_total: std.atomic.Value(usize),
    response_5xx_total: std.atomic.Value(usize),
    response_body_bytes_total: std.atomic.Value(usize),
    static_responses_total: std.atomic.Value(usize),
    static_sendfile_responses_total: std.atomic.Value(usize),
    static_buffered_responses_total: std.atomic.Value(usize),
    static_body_bytes_total: std.atomic.Value(usize),
    h3_responses_total: std.atomic.Value(usize),
    h3_packets_sent_total: std.atomic.Value(usize),

    fn init() ServerMetrics {
        return .{
            .active_connections = std.atomic.Value(usize).init(0),
            .connections_total = std.atomic.Value(usize).init(0),
            .connections_rejected_total = std.atomic.Value(usize).init(0),
            .requests_total = std.atomic.Value(usize).init(0),
            .request_parse_errors_total = std.atomic.Value(usize).init(0),
            .route_errors_total = std.atomic.Value(usize).init(0),
            .responses_total = std.atomic.Value(usize).init(0),
            .response_2xx_total = std.atomic.Value(usize).init(0),
            .response_3xx_total = std.atomic.Value(usize).init(0),
            .response_4xx_total = std.atomic.Value(usize).init(0),
            .response_5xx_total = std.atomic.Value(usize).init(0),
            .response_body_bytes_total = std.atomic.Value(usize).init(0),
            .static_responses_total = std.atomic.Value(usize).init(0),
            .static_sendfile_responses_total = std.atomic.Value(usize).init(0),
            .static_buffered_responses_total = std.atomic.Value(usize).init(0),
            .static_body_bytes_total = std.atomic.Value(usize).init(0),
            .h3_responses_total = std.atomic.Value(usize).init(0),
            .h3_packets_sent_total = std.atomic.Value(usize).init(0),
        };
    }

    fn load(counter: *const std.atomic.Value(usize)) usize {
        return counter.load(.monotonic);
    }

    fn inc(counter: *std.atomic.Value(usize)) void {
        _ = counter.fetchAdd(1, .monotonic);
    }

    fn add(counter: *std.atomic.Value(usize), value: usize) void {
        _ = counter.fetchAdd(value, .monotonic);
    }

    fn connectionAccepted(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.connections_total);
        ServerMetrics.inc(&self.active_connections);
    }

    fn connectionRejected(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.connections_rejected_total);
    }

    fn connectionClosed(self: *ServerMetrics) void {
        _ = self.active_connections.fetchSub(1, .monotonic);
    }

    fn requestStarted(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.requests_total);
    }

    fn requestParseError(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.request_parse_errors_total);
    }

    fn routeError(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.route_errors_total);
    }

    fn responseSent(self: *ServerMetrics, status_code: u16, body_bytes: usize) void {
        ServerMetrics.inc(&self.responses_total);
        ServerMetrics.add(&self.response_body_bytes_total, body_bytes);
        switch (http_response.statusClass(status_code)) {
            2 => ServerMetrics.inc(&self.response_2xx_total),
            3 => ServerMetrics.inc(&self.response_3xx_total),
            4 => ServerMetrics.inc(&self.response_4xx_total),
            5 => ServerMetrics.inc(&self.response_5xx_total),
            else => {},
        }
    }

    fn staticBodySent(self: *ServerMetrics, body_bytes: usize, transfer_mode: StaticTransferMode) void {
        ServerMetrics.inc(&self.static_responses_total);
        switch (transfer_mode) {
            .sendfile => ServerMetrics.inc(&self.static_sendfile_responses_total),
            .buffered => ServerMetrics.inc(&self.static_buffered_responses_total),
        }
        ServerMetrics.add(&self.static_body_bytes_total, body_bytes);
    }

    fn h3ResponseSent(self: *ServerMetrics, packet_count: usize) void {
        ServerMetrics.inc(&self.h3_responses_total);
        ServerMetrics.add(&self.h3_packets_sent_total, packet_count);
    }
};

var server_metrics = ServerMetrics.init();
var upstream_round_robin_cursor = std.atomic.Value(usize).init(0);

const StaticTransferMode = enum {
    sendfile,
    buffered,
};

// Parse CLI/config booleans without crashing on odd values.
fn parseBool(value: []const u8) ?bool {
    if (std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "on") or std.ascii.eqlIgnoreCase(value, "yes") or std.ascii.eqlIgnoreCase(value, "1")) {
        return true;
    }
    if (std.ascii.eqlIgnoreCase(value, "false") or std.ascii.eqlIgnoreCase(value, "off") or std.ascii.eqlIgnoreCase(value, "no") or std.ascii.eqlIgnoreCase(value, "0")) {
        return false;
    }
    return null;
}

fn parseConfigBool(value: []const u8) !bool {
    return parseBool(value) orelse error.InvalidConfigValue;
}

fn parseConfigU16(value: []const u8) !u16 {
    return std.fmt.parseInt(u16, value, 10) catch error.InvalidConfigValue;
}

fn parseConfigU32(value: []const u8) !u32 {
    return std.fmt.parseInt(u32, value, 10) catch error.InvalidConfigValue;
}

fn parseConfigUsize(value: []const u8) !usize {
    return std.fmt.parseInt(usize, value, 10) catch error.InvalidConfigValue;
}

fn isSupportedCloudflareRecordType(value: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, "A") or
        std.ascii.eqlIgnoreCase(value, "AAAA") or
        std.ascii.eqlIgnoreCase(value, "CNAME") or
        std.ascii.eqlIgnoreCase(value, "TXT");
}

fn disablesOptionalUrl(value: []const u8) bool {
    if (value.len == 0) return true;
    if (parseBool(value)) |enabled| return !enabled;
    if (std.ascii.eqlIgnoreCase(value, "none") or std.ascii.eqlIgnoreCase(value, "null")) return true;
    return false;
}

fn isValidHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (c <= 32 or c >= 127 or c == ':' or c == '\r' or c == '\n') return false;
    }
    return true;
}

fn isSafeHeaderValue(value: []const u8) bool {
    return std.mem.indexOfAny(u8, value, "\r\n") == null;
}

fn parseResponseHeaderRule(allocator: std.mem.Allocator, raw: []const u8) !ResponseHeaderRule {
    const colon = std.mem.indexOfScalar(u8, raw, ':') orelse return error.InvalidHeader;
    const name = trimValue(raw[0..colon]);
    const value = trimValue(raw[colon + 1 ..]);
    if (!isValidHeaderName(name) or !isSafeHeaderValue(value)) return error.InvalidHeader;
    return .{
        .name = try allocator.dupe(u8, name),
        .value = try allocator.dupe(u8, value),
    };
}

fn isSafeRedirectLocation(value: []const u8) bool {
    return value.len > 0 and std.mem.indexOfAny(u8, value, "\r\n") == null;
}

fn parseRedirectRule(allocator: std.mem.Allocator, raw: []const u8) !RedirectRule {
    var tokens = std.ArrayList([]const u8).empty;
    defer tokens.deinit(allocator);

    var it = std.mem.tokenizeAny(u8, raw, " \t");
    while (it.next()) |token| {
        if (std.mem.eql(u8, token, "->")) continue;
        try tokens.append(allocator, token);
    }

    if (tokens.items.len < 2) return error.InvalidRedirect;

    const from_raw = trimValue(tokens.items[0]);
    const to = trimValue(tokens.items[1]);
    if (from_raw.len == 0 or from_raw[0] != '/' or !isSafeRedirectLocation(to)) return error.InvalidRedirect;

    const status_code = if (tokens.items.len >= 3)
        std.fmt.parseInt(u16, tokens.items[2], 10) catch 308
    else
        308;
    if (status_code != 301 and status_code != 302 and status_code != 303 and status_code != 307 and status_code != 308) return error.InvalidRedirect;

    const prefix_match = std.mem.endsWith(u8, from_raw, "*");
    const from = if (prefix_match) from_raw[0 .. from_raw.len - 1] else from_raw;
    if (from.len == 0 or from[0] != '/') return error.InvalidRedirect;

    return .{
        .from = try allocator.dupe(u8, from),
        .to = try allocator.dupe(u8, to),
        .status_code = status_code,
        .prefix_match = prefix_match,
    };
}

fn routeHandlerName(handler: RouteHandlerKind) []const u8 {
    return switch (handler) {
        .static => "static",
        .php => "php",
        .proxy => "proxy",
    };
}

fn routeMatchName(match_kind: RouteMatchKind) []const u8 {
    return switch (match_kind) {
        .exact => "exact",
        .prefix => "prefix",
    };
}

fn parseRouteHandler(value: []const u8) !RouteHandlerKind {
    if (std.mem.eql(u8, value, "static")) return .static;
    if (std.mem.eql(u8, value, "php")) return .php;
    if (std.mem.eql(u8, value, "proxy")) return .proxy;
    return error.InvalidConfigValue;
}

fn isRouteNameValid(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '_' or c == '-') continue;
        return false;
    }
    return true;
}

fn findRouteConfigMutable(routes: *std.ArrayList(RouteConfig), name: []const u8) ?*RouteConfig {
    for (routes.items) |*route| {
        if (std.mem.eql(u8, route.name, name)) return route;
    }
    return null;
}

fn findRoutePropertyName(key: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, key, prefix)) return null;
    const name = key[prefix.len..];
    if (name.len == 0) return null;
    return name;
}

fn setRouteLineFor(routes: *std.ArrayList(RouteConfig), allocator: std.mem.Allocator, raw: []const u8) !void {
    var parts = std.mem.tokenizeAny(u8, raw, " \t");
    const name = parts.next() orelse return error.InvalidConfigValue;
    const pattern_raw = parts.next() orelse return error.InvalidConfigValue;
    const handler_raw = parts.next() orelse return error.InvalidConfigValue;
    if (parts.next() != null) return error.InvalidConfigValue;
    if (!isRouteNameValid(name)) return error.InvalidConfigValue;
    if (findRouteConfigMutable(routes, name) != null) return error.DuplicateConfigRoute;
    if (pattern_raw.len == 0 or pattern_raw[0] != '/') return error.InvalidConfigValue;

    const match_kind: RouteMatchKind = if (std.mem.endsWith(u8, pattern_raw, "*")) .prefix else .exact;
    const pattern_without_star = if (match_kind == .prefix) pattern_raw[0 .. pattern_raw.len - 1] else pattern_raw;
    const normalized_pattern = if (pattern_without_star.len == 0) "/" else pattern_without_star;

    try routes.append(allocator, .{
        .name = try allocator.dupe(u8, name),
        .pattern = try allocator.dupe(u8, normalized_pattern),
        .match_kind = match_kind,
        .handler = try parseRouteHandler(handler_raw),
        .strip_prefix = true,
        .static_dir = null,
        .index_file = null,
        .php_root = null,
        .php_binary = null,
        .php_info_page = null,
        .upstream = null,
    });
}

fn setRouteLine(cfg: *ServerConfig, allocator: std.mem.Allocator, raw: []const u8) !void {
    try setRouteLineFor(&cfg.routes, allocator, raw);
}

fn setRouteStringProperty(
    routes: *std.ArrayList(RouteConfig),
    allocator: std.mem.Allocator,
    route_name: []const u8,
    value: []const u8,
    field: RouteStringProperty,
) !void {
    if (value.len == 0) return error.InvalidConfigValue;
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const dupe_value = try allocator.dupe(u8, value);
    switch (field) {
        .static_dir => route.static_dir = dupe_value,
        .index_file => route.index_file = dupe_value,
        .php_root => route.php_root = dupe_value,
        .php_binary => route.php_binary = dupe_value,
    }
}

fn setRouteProxyProperty(routes: *std.ArrayList(RouteConfig), allocator: std.mem.Allocator, route_name: []const u8, value: []const u8) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    if (disablesOptionalUrl(value)) {
        route.upstream = null;
    } else {
        route.upstream = try parseUpstreamPool(allocator, value);
    }
}

fn setRouteBoolProperty(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8, field: RouteBoolProperty) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const parsed = try parseConfigBool(value);
    switch (field) {
        .php_info_page => route.php_info_page = parsed,
        .strip_prefix => route.strip_prefix = parsed,
    }
}

fn isDomainConfigNameValid(name: []const u8) bool {
    return isRouteNameValid(name);
}

fn findDomainConfigMutable(cfg: *ServerConfig, name: []const u8) ?*DomainConfig {
    for (cfg.domains.items) |*domain| {
        if (std.mem.eql(u8, domain.name, name)) return domain;
    }
    return null;
}

fn splitDomainRoutePropertyName(value: []const u8) ?struct { domain: []const u8, route: []const u8 } {
    const dot = std.mem.indexOfScalar(u8, value, '.') orelse return null;
    const domain = value[0..dot];
    const route = value[dot + 1 ..];
    if (domain.len == 0 or route.len == 0) return null;
    return .{ .domain = domain, .route = route };
}

fn appendServerNames(allocator: std.mem.Allocator, domain: *DomainConfig, value: []const u8) !void {
    var parts = std.mem.tokenizeAny(u8, value, " \t,");
    var added = false;
    while (parts.next()) |name| {
        if (name.len == 0) continue;
        try domain.server_names.append(allocator, try allocator.dupe(u8, name));
        added = true;
    }
    if (!added) return error.InvalidConfigValue;
}

fn setDomainLine(cfg: *ServerConfig, allocator: std.mem.Allocator, raw: []const u8) !void {
    const name = trimValue(raw);
    if (!isDomainConfigNameValid(name)) return error.InvalidConfigValue;
    if (findDomainConfigMutable(cfg, name) != null) return error.DuplicateConfigDomain;

    try cfg.domains.append(allocator, .{
        .name = try allocator.dupe(u8, name),
        .server_names = .empty,
        .static_dir = null,
        .serve_static_root = null,
        .index_file = null,
        .php_root = null,
        .php_binary = null,
        .php_info_page = null,
        .upstream = null,
        .redirects = .empty,
        .routes = .empty,
    });
}

fn setDomainStringProperty(
    cfg: *ServerConfig,
    allocator: std.mem.Allocator,
    domain_name: []const u8,
    value: []const u8,
    field: DomainStringProperty,
) !void {
    if (value.len == 0) return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const dupe_value = try allocator.dupe(u8, value);
    switch (field) {
        .static_dir => domain.static_dir = dupe_value,
        .index_file => domain.index_file = dupe_value,
        .php_root => domain.php_root = dupe_value,
        .php_binary => domain.php_binary = dupe_value,
    }
}

fn setDomainBoolProperty(cfg: *ServerConfig, domain_name: []const u8, value: []const u8, field: DomainBoolProperty) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const parsed = try parseConfigBool(value);
    switch (field) {
        .serve_static_root => domain.serve_static_root = parsed,
        .php_info_page => domain.php_info_page = parsed,
    }
}

fn setDomainProxyProperty(cfg: *ServerConfig, allocator: std.mem.Allocator, domain_name: []const u8, value: []const u8) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    if (disablesOptionalUrl(value)) {
        domain.upstream = null;
    } else {
        domain.upstream = try parseUpstreamPool(allocator, value);
    }
}

fn setDomainRouteLine(cfg: *ServerConfig, allocator: std.mem.Allocator, domain_name: []const u8, value: []const u8) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    try setRouteLineFor(&domain.routes, allocator, value);
}

fn setDomainRouteStringProperty(
    cfg: *ServerConfig,
    allocator: std.mem.Allocator,
    property_name: []const u8,
    value: []const u8,
    field: RouteStringProperty,
) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteStringProperty(&domain.routes, allocator, split.route, value, field);
}

fn setDomainRouteBoolProperty(cfg: *ServerConfig, property_name: []const u8, value: []const u8, field: RouteBoolProperty) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteBoolProperty(&domain.routes, split.route, value, field);
}

fn setDomainRouteProxyProperty(cfg: *ServerConfig, allocator: std.mem.Allocator, property_name: []const u8, value: []const u8) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteProxyProperty(&domain.routes, allocator, split.route, value);
}

// Map one config file line to fields. Config files are strict so typos do not
// silently change server behavior.
fn applyConfigLine(cfg: *ServerConfig, allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
    const k = std.mem.trim(u8, key, " \t\r\n");
    const v = trimValue(value);

    if (std.mem.eql(u8, k, "host")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.host = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "port")) {
        cfg.port = try parseConfigU16(v);
    } else if (std.mem.eql(u8, k, "static_dir") or std.mem.eql(u8, k, "dir")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.static_dir = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "serve_static_root")) {
        cfg.serve_static_root = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "index_file") or std.mem.eql(u8, k, "index")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.index_file = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "php_root")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.php_root = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "php_binary") or std.mem.eql(u8, k, "php_bin")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.php_binary = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "php_info_page") or std.mem.eql(u8, k, "phpinfo_page") or std.mem.eql(u8, k, "enable_php_info_page")) {
        cfg.php_info_page = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "proxy")) {
        if (disablesOptionalUrl(v)) {
            cfg.upstream = null;
        } else {
            cfg.upstream = try parseUpstreamPool(allocator, v);
        }
    } else if (std.mem.eql(u8, k, "tls")) {
        cfg.tls_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "tls_cert")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.tls_cert = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "tls_key")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.tls_key = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "tls_auto")) {
        cfg.tls_auto = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "letsencrypt_email")) {
        if (v.len == 0) {
            cfg.letsencrypt_email = null;
        } else {
            cfg.letsencrypt_email = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "letsencrypt_domains")) {
        if (v.len == 0) {
            cfg.letsencrypt_domains = null;
        } else {
            cfg.letsencrypt_domains = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "letsencrypt_webroot")) {
        cfg.letsencrypt_webroot = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "letsencrypt_certbot")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.letsencrypt_certbot = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "letsencrypt_staging")) {
        cfg.letsencrypt_staging = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "h2_upstream") or std.mem.eql(u8, k, "http2_upstream")) {
        if (disablesOptionalUrl(v)) {
            cfg.h2_upstream = null;
        } else {
            cfg.h2_upstream = try parseUpstream(allocator, v);
        }
    } else if (std.mem.eql(u8, k, "http3")) {
        cfg.http3_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "http3_port")) {
        cfg.http3_port = try parseConfigU16(v);
    } else if (std.mem.eql(u8, k, "header") or std.mem.eql(u8, k, "response_header") or std.mem.eql(u8, k, "add_header")) {
        if (v.len > 0) try cfg.response_headers.append(allocator, try parseResponseHeaderRule(allocator, v));
    } else if (std.mem.eql(u8, k, "redirect") or std.mem.eql(u8, k, "redir")) {
        if (v.len > 0) try cfg.redirects.append(allocator, try parseRedirectRule(allocator, v));
    } else if (std.mem.eql(u8, k, "server") or std.mem.eql(u8, k, "domain") or std.mem.eql(u8, k, "vhost")) {
        try setDomainLine(cfg, allocator, v);
    } else if (findRoutePropertyName(k, "server_name.")) |name| {
        const domain = findDomainConfigMutable(cfg, name) orelse return error.UnknownConfigDomain;
        try appendServerNames(allocator, domain, v);
    } else if (findRoutePropertyName(k, "server_names.")) |name| {
        const domain = findDomainConfigMutable(cfg, name) orelse return error.UnknownConfigDomain;
        try appendServerNames(allocator, domain, v);
    } else if (findRoutePropertyName(k, "server_root.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "server_dir.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "server_static_dir.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "server_index.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "server_index_file.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "server_serve_static.")) |name| {
        try setDomainBoolProperty(cfg, name, v, .serve_static_root);
    } else if (findRoutePropertyName(k, "server_serve_static_root.")) |name| {
        try setDomainBoolProperty(cfg, name, v, .serve_static_root);
    } else if (findRoutePropertyName(k, "server_php_root.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_root);
    } else if (findRoutePropertyName(k, "server_php_bin.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "server_php_binary.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "server_php_info_page.")) |name| {
        try setDomainBoolProperty(cfg, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "server_phpinfo_page.")) |name| {
        try setDomainBoolProperty(cfg, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "server_proxy.")) |name| {
        try setDomainProxyProperty(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_upstream.")) |name| {
        try setDomainProxyProperty(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_redirect.")) |name| {
        const domain = findDomainConfigMutable(cfg, name) orelse return error.UnknownConfigDomain;
        if (v.len > 0) try domain.redirects.append(allocator, try parseRedirectRule(allocator, v));
    } else if (findRoutePropertyName(k, "server_route.")) |name| {
        try setDomainRouteLine(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_dir.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "server_route_static_dir.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "server_route_index.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "server_route_index_file.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "server_route_php_root.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_root);
    } else if (findRoutePropertyName(k, "server_route_php_bin.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "server_route_php_binary.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "server_route_php_info_page.")) |name| {
        try setDomainRouteBoolProperty(cfg, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "server_route_phpinfo_page.")) |name| {
        try setDomainRouteBoolProperty(cfg, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "server_route_proxy.")) |name| {
        try setDomainRouteProxyProperty(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_upstream.")) |name| {
        try setDomainRouteProxyProperty(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_strip_prefix.")) |name| {
        try setDomainRouteBoolProperty(cfg, name, v, .strip_prefix);
    } else if (std.mem.eql(u8, k, "route")) {
        try setRouteLine(cfg, allocator, v);
    } else if (findRoutePropertyName(k, "route_dir.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "route_static_dir.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "route_index.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "route_index_file.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "route_php_root.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_root);
    } else if (findRoutePropertyName(k, "route_php_bin.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "route_php_binary.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "route_php_info_page.")) |name| {
        try setRouteBoolProperty(&cfg.routes, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "route_phpinfo_page.")) |name| {
        try setRouteBoolProperty(&cfg.routes, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "route_proxy.")) |name| {
        try setRouteProxyProperty(&cfg.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_upstream.")) |name| {
        try setRouteProxyProperty(&cfg.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_strip_prefix.")) |name| {
        try setRouteBoolProperty(&cfg.routes, name, v, .strip_prefix);
    } else if (std.mem.eql(u8, k, "max_request_bytes")) {
        cfg.max_request_bytes = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "max_body_bytes")) {
        cfg.max_body_bytes = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "max_static_file_bytes")) {
        cfg.max_static_file_bytes = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "max_requests_per_connection")) {
        cfg.max_requests_per_connection = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "max_concurrent_connections")) {
        cfg.max_concurrent_connections = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "worker_stack_size")) {
        cfg.worker_stack_size = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "read_header_timeout_ms")) {
        cfg.read_header_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "read_body_timeout_ms")) {
        cfg.read_body_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "idle_timeout_ms")) {
        cfg.idle_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "write_timeout_ms")) {
        cfg.write_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "upstream_timeout_ms")) {
        cfg.upstream_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "graceful_shutdown_timeout_ms")) {
        cfg.graceful_shutdown_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "max_php_output_bytes")) {
        cfg.max_php_output_bytes = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "cf_auto_deploy")) {
        cfg.cloudflare_auto_deploy = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "cf_api_base")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.cloudflare_api_base = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "cf_token")) {
        if (v.len == 0) {
            cfg.cloudflare_token = null;
        } else {
            cfg.cloudflare_token = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "cf_zone_id")) {
        if (v.len == 0) {
            cfg.cloudflare_zone_id = null;
        } else {
            cfg.cloudflare_zone_id = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "cf_zone_name")) {
        if (v.len == 0) {
            cfg.cloudflare_zone_name = null;
        } else {
            cfg.cloudflare_zone_name = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "cf_record_name")) {
        if (v.len == 0) {
            cfg.cloudflare_record_name = null;
        } else {
            cfg.cloudflare_record_name = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "cf_record_type")) {
        if (v.len == 0) {
            cfg.cloudflare_record_type = "A";
        } else {
            if (!isSupportedCloudflareRecordType(v)) return error.InvalidConfigValue;
            cfg.cloudflare_record_type = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "cf_record_content")) {
        if (v.len == 0) {
            cfg.cloudflare_record_content = null;
        } else {
            cfg.cloudflare_record_content = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "cf_record_ttl")) {
        cfg.cloudflare_record_ttl = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "cf_record_proxied")) {
        cfg.cloudflare_record_proxied = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "cf_record_comment")) {
        if (v.len == 0) {
            cfg.cloudflare_record_comment = null;
        } else {
            cfg.cloudflare_record_comment = try allocator.dupe(u8, v);
        }
    } else {
        return error.UnknownConfigKey;
    }
}

// Load and apply file-based config, skipping comments and empty lines.
fn loadConfig(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig, path: []const u8) !void {
    const content = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(MAX_CONFIG_BYTES));
    defer allocator.free(content);

    var lines = std.mem.splitSequence(u8, content, "\n");
    var line_number: usize = 0;
    while (lines.next()) |raw_line| {
        line_number += 1;
        var line = trimValue(raw_line);
        if (line.len == 0) continue;

        if (std.mem.indexOfScalar(u8, line, '#')) |comment_start| {
            if (comment_start == 0) continue;
            line = trimValue(line[0..comment_start]);
        }
        if (line.len == 0) continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse {
            std.debug.print("Config error in {s}:{d}: expected key = value\n", .{ path, line_number });
            return error.MalformedConfigLine;
        };
        const key = line[0..eq];
        const value = if (eq + 1 < line.len) line[eq + 1 ..] else "";
        applyConfigLine(cfg, allocator, key, value) catch |err| {
            std.debug.print("Config error in {s}:{d}: {s}: {}\n", .{ path, line_number, trimValue(key), err });
            return err;
        };
    }
}

fn normalizeConfig(cfg: *ServerConfig) void {
    if (cfg.max_concurrent_connections == 0) {
        cfg.max_concurrent_connections = 1024;
    }
    if (cfg.max_requests_per_connection == 0) {
        cfg.max_requests_per_connection = DEFAULT_MAX_REQUESTS_PER_CONNECTION;
    }
    if (cfg.max_php_output_bytes == 0) {
        cfg.max_php_output_bytes = DEFAULT_MAX_PHP_OUTPUT_BYTES;
    }
    if (cfg.worker_stack_size < 16 * 1024) {
        cfg.worker_stack_size = 16 * 1024;
    }
}

fn validateUpstreamPool(pool: UpstreamPoolConfig) !void {
    if (pool.targets.items.len == 0) return error.InvalidConfigValue;
    for (pool.targets.items) |target| {
        if (target.host.len == 0) return error.InvalidConfigValue;
        if (target.port == 0) return error.InvalidConfigValue;
        if (target.base_path.len == 0 or target.base_path[0] != '/') return error.InvalidConfigValue;
    }
}

fn validateRouteConfig(route: *const RouteConfig, fallback_upstream: ?UpstreamPoolConfig) !void {
    if (!isRouteNameValid(route.name)) return error.InvalidConfigValue;
    if (route.pattern.len == 0 or route.pattern[0] != '/') return error.InvalidConfigValue;
    if (route.static_dir) |static_dir| {
        if (static_dir.len == 0) return error.InvalidConfigValue;
    }
    if (route.index_file) |index_file| {
        if (index_file.len == 0) return error.InvalidConfigValue;
    }
    if (route.php_root) |php_root| {
        if (php_root.len == 0) return error.InvalidConfigValue;
    }
    if (route.php_binary) |php_binary| {
        if (php_binary.len == 0) return error.InvalidConfigValue;
    }
    if (route.upstream) |pool| {
        try validateUpstreamPool(pool);
    }
    if (route.handler == .proxy and route.upstream == null and fallback_upstream == null) {
        return error.InvalidConfigValue;
    }
}

fn validateConfig(cfg: *const ServerConfig) !void {
    if (cfg.host.len == 0) return error.InvalidConfigValue;
    if (cfg.port == 0) return error.InvalidConfigValue;
    if (cfg.static_dir.len == 0) return error.InvalidConfigValue;
    if (cfg.index_file.len == 0) return error.InvalidConfigValue;
    if (cfg.php_root.len == 0) return error.InvalidConfigValue;
    if (cfg.php_binary.len == 0) return error.InvalidConfigValue;
    if (cfg.http3_enabled and cfg.http3_port == 0) return error.InvalidConfigValue;
    if (cfg.max_request_bytes < 1024) return error.InvalidConfigValue;
    if (cfg.max_body_bytes == 0) return error.InvalidConfigValue;
    if (cfg.max_static_file_bytes == 0) return error.InvalidConfigValue;
    if (cfg.max_concurrent_connections == 0) return error.InvalidConfigValue;
    if (cfg.worker_stack_size < 16 * 1024) return error.InvalidConfigValue;
    if (cfg.read_header_timeout_ms == 0) return error.InvalidConfigValue;
    if (cfg.read_body_timeout_ms == 0) return error.InvalidConfigValue;
    if (cfg.idle_timeout_ms == 0) return error.InvalidConfigValue;
    if (cfg.write_timeout_ms == 0) return error.InvalidConfigValue;
    if (cfg.upstream_timeout_ms == 0) return error.InvalidConfigValue;
    if (cfg.upstream) |pool| {
        try validateUpstreamPool(pool);
    }

    if (cfg.tls_auto and (cfg.letsencrypt_domains == null or cfg.letsencrypt_domains.?.len == 0)) {
        return error.InvalidConfigValue;
    }
    if (cfg.cloudflare_auto_deploy) {
        if (cfg.cloudflare_token == null or cfg.cloudflare_token.?.len == 0) return error.InvalidConfigValue;
        if ((cfg.cloudflare_zone_id == null or cfg.cloudflare_zone_id.?.len == 0) and (cfg.cloudflare_zone_name == null or cfg.cloudflare_zone_name.?.len == 0)) return error.InvalidConfigValue;
        if (cfg.cloudflare_record_name == null or cfg.cloudflare_record_name.?.len == 0) return error.InvalidConfigValue;
        if (cfg.cloudflare_record_content == null or cfg.cloudflare_record_content.?.len == 0) return error.InvalidConfigValue;
    }

    for (cfg.routes.items) |*route| {
        try validateRouteConfig(route, cfg.upstream);
    }

    for (cfg.domains.items) |*domain| {
        if (!isDomainConfigNameValid(domain.name)) return error.InvalidConfigValue;
        if (domain.server_names.items.len == 0) return error.InvalidConfigValue;
        for (domain.server_names.items) |name| {
            if (std.mem.trim(u8, name, " \t\r\n").len == 0) return error.InvalidConfigValue;
        }
        if (domain.static_dir) |static_dir| {
            if (static_dir.len == 0) return error.InvalidConfigValue;
        }
        if (domain.index_file) |index_file| {
            if (index_file.len == 0) return error.InvalidConfigValue;
        }
        if (domain.php_root) |php_root| {
            if (php_root.len == 0) return error.InvalidConfigValue;
        }
        if (domain.php_binary) |php_binary| {
            if (php_binary.len == 0) return error.InvalidConfigValue;
        }
        if (domain.upstream) |pool| {
            try validateUpstreamPool(pool);
        }

        const fallback_upstream = if (domain.upstream) |upstream| upstream else cfg.upstream;
        for (domain.routes.items) |*route| {
            try validateRouteConfig(route, fallback_upstream);
        }
    }
}

fn contentTypeFromPath(path: []const u8) []const u8 {
    if (std.mem.endsWith(u8, path, ".html")) return "text/html; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".txt")) return "text/plain; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".css")) return "text/css; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".js")) return "application/javascript; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".json")) return "application/json; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".xml")) return "application/xml; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".svg")) return "image/svg+xml";
    if (std.mem.endsWith(u8, path, ".png")) return "image/png";
    if (std.mem.endsWith(u8, path, ".jpg") or std.mem.endsWith(u8, path, ".jpeg")) return "image/jpeg";
    if (std.mem.endsWith(u8, path, ".webp")) return "image/webp";
    if (std.mem.endsWith(u8, path, ".gif")) return "image/gif";
    if (std.mem.endsWith(u8, path, ".ico")) return "image/x-icon";
    if (std.mem.endsWith(u8, path, ".wasm")) return "application/wasm";
    return "text/plain; charset=utf-8";
}

// Render a Memorylayer-style fallback instead of a plain error line.
fn renderCoolErrorPage(allocator: std.mem.Allocator, status_code: u16, status_text: []const u8, detail: []const u8) ![]const u8 {
    const eyebrow = if (status_code == 404) "Route not found" else "Request stopped";
    const headline = if (status_code == 404) "Memory has no path here." else status_text;
    const route_label = if (status_code == 404) "unresolved route" else "server response";
    const panel_title = if (status_code == 404) "No matching server surface" else "Boundary held";
    const panel_text = if (status_code == 404) "Try the root page, health check, or static sample." else "The request stopped inside a controlled response path.";

    return std.fmt.allocPrint(
        allocator,
        \\<!doctype html>
        \\<html lang="en">
        \\<head>
        \\<meta charset="utf-8">
        \\<meta name="viewport" content="width=device-width, initial-scale=1">
        \\<title>{d} · {s}</title>
        \\<link rel="icon" type="image/svg+xml" href="/favicon.svg">
        \\</head>
        \\<body style="box-sizing:border-box;margin:0;min-height:100vh;overflow-x:hidden;background:radial-gradient(circle at 16% -12%, rgba(255,255,255,0.92), transparent 28%),linear-gradient(180deg,#f7f4ed 0%,#f0ece2 46%,#e9e3d6 100%);color:#11110f;font:14px/1.6 Instrument Sans,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;">
        \\<div style="position:fixed;inset:0;z-index:-2;background:linear-gradient(rgba(15,15,12,0.05) 1px, transparent 1px),linear-gradient(90deg, rgba(15,15,12,0.05) 1px, transparent 1px);background-size:64px 64px;pointer-events:none;"></div>
        \\<div style="position:fixed;inset:0;z-index:-1;background:radial-gradient(circle at 50% 18%, transparent 0 28%, rgba(244,241,234,0.28) 62%, rgba(214,204,186,0.42) 100%),linear-gradient(90deg,rgba(17,17,15,0.035),transparent 18%,transparent 82%,rgba(17,17,15,0.035));pointer-events:none;"></div>
        \\<main style="max-width:1280px;margin:0 auto;padding:18px 30px 72px;">
        \\<header style="display:flex;align-items:center;justify-content:space-between;gap:16px;margin:0 auto 10px;padding:10px;border:1px solid rgba(17,17,15,0.12);border-radius:18px;background:rgba(251,250,246,0.82);box-shadow:0 18px 60px rgba(38,34,24,0.09);backdrop-filter:blur(22px);">
        \\<a href="/" style="display:flex;gap:12px;align-items:center;color:inherit;text-decoration:none;">
        \\<img src="/favicon.svg" alt="" width="40" height="40" style="display:block;width:40px;height:40px;border-radius:12px;box-shadow:0 18px 36px rgba(17,17,15,0.08);">
        \\<span><strong style="display:block;font-size:16px;line-height:1.1;font-weight:700;letter-spacing:-0.035em;">{s}</strong><small style="display:block;color:#8b8c84;font-size:11px;line-height:1.1;">{s}</small></span>
        \\</a>
        \\<nav style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
        \\<a href="/health" style="display:inline-flex;align-items:center;padding:9px 13px;border-radius:12px;border:1px solid rgba(15,15,12,0.14);background:rgba(255,255,255,0.5);color:#11110f;text-decoration:none;">Health</a>
        \\<a href="/static/hello.txt" style="display:inline-flex;align-items:center;padding:9px 13px;border-radius:12px;border:1px solid rgba(15,15,12,0.14);background:rgba(255,255,255,0.5);color:#11110f;text-decoration:none;">Static</a>
        \\</nav>
        \\</header>
        \\<section style="position:relative;min-height:min(740px,calc(100svh - 130px));display:grid;grid-template-columns:repeat(auto-fit,minmax(min(360px,100%),1fr));gap:clamp(28px,6vw,86px);align-items:center;overflow:hidden;margin:0 calc(50% - 50vw) 56px;padding:clamp(42px,8vw,92px) max(30px,calc((100vw - 1280px) / 2 + 30px));border-bottom:1px solid rgba(15,15,12,0.12);background:radial-gradient(circle at 74% 42%,rgba(17,17,15,0.14),transparent 18%),linear-gradient(rgba(17,17,15,0.055) 1px,transparent 1px),linear-gradient(90deg,rgba(17,17,15,0.055) 1px,transparent 1px),linear-gradient(135deg,rgba(251,250,246,0.95),rgba(231,225,212,0.84));background-size:auto,56px 56px,56px 56px,auto;">
        \\<div style="position:absolute;right:clamp(-36px,3vw,44px);bottom:clamp(-18px,2vw,26px);color:rgba(17,17,15,0.045);font:800 clamp(180px,30vw,420px)/0.78 Instrument Sans,ui-sans-serif,system-ui,sans-serif;letter-spacing:-0.12em;pointer-events:none;">{d}</div>
        \\<div style="position:relative;z-index:2;max-width:650px;">
        \\<div style="display:inline-flex;align-items:center;gap:8px;padding:6px 10px;margin-bottom:16px;border-radius:999px;border:1px solid rgba(17,17,15,0.18);background:rgba(255,255,255,0.58);color:#5d5e58;font:11px/1 IBM Plex Mono,ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:0.16em;text-transform:uppercase;">{s}</div>
        \\<h1 style="margin:0 0 18px;max-width:10ch;font-size:clamp(56px,8vw,118px);line-height:0.88;letter-spacing:-0.075em;">{s}</h1>
        \\<p style="max-width:50ch;margin:0 0 18px;color:#5d5e58;font-size:clamp(16px,1.3vw,19px);">{s}</p>
        \\<div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:24px;">
        \\<a href="/" style="display:inline-flex;align-items:center;padding:9px 13px;border-radius:12px;border:1px solid #11110f;background:#11110f;color:#fbfaf6;text-decoration:none;font-weight:600;box-shadow:0 18px 36px rgba(17,17,15,0.16);">Return home</a>
        \\<a href="/health" style="display:inline-flex;align-items:center;padding:9px 13px;border-radius:12px;border:1px solid rgba(15,15,12,0.14);background:rgba(255,255,255,0.5);color:#11110f;text-decoration:none;">Check health</a>
        \\<a href="/static/hello.txt" style="display:inline-flex;align-items:center;padding:9px 13px;border-radius:12px;border:1px solid rgba(15,15,12,0.14);background:rgba(255,255,255,0.5);color:#11110f;text-decoration:none;">Static sample</a>
        \\</div>
        \\</div>
        \\<aside aria-hidden="true" style="position:relative;z-index:1;min-height:420px;width:100%;border:1px solid rgba(17,17,15,0.16);border-radius:28px;overflow:hidden;background:rgba(251,250,246,0.72);box-shadow:0 44px 110px rgba(38,34,24,0.14);backdrop-filter:blur(18px);">
        \\<div style="position:absolute;inset:0;background:linear-gradient(rgba(17,17,15,0.08) 1px,transparent 1px),linear-gradient(90deg,rgba(17,17,15,0.08) 1px,transparent 1px);background-size:44px 44px;"></div>
        \\<div style="position:absolute;left:28px;right:28px;top:28px;display:flex;justify-content:space-between;gap:16px;padding:12px 14px;border:1px solid rgba(17,17,15,0.14);border-radius:999px;background:rgba(251,250,246,0.86);color:#8b8c84;font:11px/1.2 IBM Plex Mono,ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:0.08em;text-transform:uppercase;"><span>{s}</span><span>/{d}</span></div>
        \\<div style="position:absolute;left:20%;right:24%;top:48%;height:1px;background:repeating-linear-gradient(90deg,rgba(17,17,15,0.42) 0 12px,transparent 12px 22px);transform:rotate(-9deg);"></div>
        \\<div style="position:absolute;left:18%;top:34%;width:12px;height:12px;border-radius:999px;background:#11110f;box-shadow:0 0 0 9px rgba(17,17,15,0.08);"></div>
        \\<div style="position:absolute;right:22%;top:44%;width:12px;height:12px;border-radius:999px;background:#11110f;box-shadow:0 0 0 9px rgba(17,17,15,0.08);"></div>
        \\<div style="position:absolute;left:46%;bottom:24%;width:12px;height:12px;border-radius:999px;background:#11110f;box-shadow:0 0 0 9px rgba(17,17,15,0.08);"></div>
        \\<div style="position:absolute;left:28px;right:28px;bottom:28px;display:grid;grid-template-columns:1fr auto;gap:18px;align-items:end;padding:18px;border-top:1px solid rgba(17,17,15,0.12);background:rgba(251,250,246,0.78);">
        \\<div><strong style="display:block;margin-bottom:5px;font-size:18px;letter-spacing:-0.04em;">{s}</strong><span style="color:#5d5e58;font-size:13px;">{s}</span></div>
        \\<div style="font:600 48px/0.9 Instrument Sans,ui-sans-serif,system-ui,sans-serif;letter-spacing:-0.08em;">{d}</div>
        \\</div>
        \\</aside>
        \\</section>
        \\</main>
        \\</body>
        \\</html>
        \\
    ,
        .{
            status_code,
            SERVER_NAME,
            SERVER_NAME,
            SERVER_TAGLINE,
            status_code,
            eyebrow,
            headline,
            detail,
            route_label,
            status_code,
            panel_title,
            panel_text,
            status_code,
        },
    );
}

fn sendCoolErrorWithConnection(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    status_code: u16,
    status_text: []const u8,
    detail: []const u8,
    close_connection: bool,
    is_head: bool,
    extra_headers: ?[]const u8,
) !void {
    const body = try renderCoolErrorPage(allocator, status_code, status_text, detail);
    defer allocator.free(body);

    if (is_head) {
        try sendResponseNoBodyWithConnectionAndHeaders(stream, status_code, status_text, "text/html; charset=utf-8", body.len, close_connection, extra_headers);
        return;
    }
    try sendResponseWithConnectionAndHeaders(stream, status_code, status_text, "text/html; charset=utf-8", body, close_connection, extra_headers);
}

fn sendCoolError(stream: std.Io.net.Stream, allocator: std.mem.Allocator, status_code: u16, status_text: []const u8, detail: []const u8) !void {
    return sendCoolErrorWithConnection(stream, allocator, status_code, status_text, detail, true, false, null);
}

fn sendCoolErrorWithConnectionOnly(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    status_code: u16,
    status_text: []const u8,
    detail: []const u8,
    close_connection: bool,
) !void {
    return sendCoolErrorWithConnection(stream, allocator, status_code, status_text, detail, close_connection, false, null);
}

fn sendResponseWithConnectionAndHeaders(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8, close_connection: bool, extra_headers: ?[]const u8) !void {
    const body_len = body.len;
    var header_buffer: [4096]u8 = undefined;
    const base_headers = try http_response.formatHttp1BaseHeaders(&header_buffer, .{
        .status_code = status_code,
        .status_text = status_text,
        .server = SERVER_HEADER,
        .content_type = content_type,
        .content_length = body_len,
        .close_connection = close_connection,
    });
    try streamWriteAll(stream, base_headers);
    if (extra_headers) |headers| {
        try streamWriteAll(stream, headers);
    }
    try streamWriteConfiguredResponseHeaders(stream);
    try streamWriteAll(stream, "\r\n");

    if (body_len > 0) try streamWriteAll(stream, body);
    server_metrics.responseSent(status_code, body_len);
}

fn sendResponseWithConnection(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8, close_connection: bool) !void {
    try sendResponseWithConnectionAndHeaders(stream, status_code, status_text, content_type, body, close_connection, null);
}

fn sendResponse(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8) !void {
    try sendResponseWithConnectionAndHeaders(stream, status_code, status_text, content_type, body, true, null);
}

fn sendResponseNoBody(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body_len: usize) !void {
    try sendResponseNoBodyWithConnection(stream, status_code, status_text, content_type, body_len, true);
}

fn sendResponseNoBodyWithConnectionAndHeaders(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body_len: usize, close_connection: bool, extra_headers: ?[]const u8) !void {
    var header_buffer: [4096]u8 = undefined;
    const base_headers = try http_response.formatHttp1BaseHeaders(&header_buffer, .{
        .status_code = status_code,
        .status_text = status_text,
        .server = SERVER_HEADER,
        .content_type = content_type,
        .content_length = body_len,
        .close_connection = close_connection,
    });
    try streamWriteAll(stream, base_headers);
    if (extra_headers) |headers| {
        try streamWriteAll(stream, headers);
    }
    try streamWriteConfiguredResponseHeaders(stream);
    try streamWriteAll(stream, "\r\n");
    server_metrics.responseSent(status_code, 0);
}

fn sendResponseNoBodyWithConnection(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body_len: usize, close_connection: bool) !void {
    try sendResponseNoBodyWithConnectionAndHeaders(stream, status_code, status_text, content_type, body_len, close_connection, null);
}

fn sendNotFound(allocator: std.mem.Allocator, stream: std.Io.net.Stream) !void {
    try sendCoolError(stream, allocator, 404, "Not Found", "The requested resource was not found on this server.");
}

fn sendNotFoundWithConnection(allocator: std.mem.Allocator, stream: std.Io.net.Stream, close_connection: bool) !void {
    try sendCoolErrorWithConnectionOnly(stream, allocator, 404, "Not Found", "The requested resource was not found on this server.", close_connection);
}

fn sendBadRequest(allocator: std.mem.Allocator, stream: std.Io.net.Stream, reason: []const u8) !void {
    try sendCoolError(stream, allocator, 400, "Bad Request", reason);
}

fn sendBadRequestWithConnection(allocator: std.mem.Allocator, stream: std.Io.net.Stream, reason: []const u8, close_connection: bool) !void {
    try sendCoolErrorWithConnection(stream, allocator, 400, "Bad Request", reason, close_connection, false, null);
}

fn sendMethodNotAllowed(allocator: std.mem.Allocator, stream: std.Io.net.Stream) !void {
    try sendCoolError(stream, allocator, 405, "Method Not Allowed", "That method is not supported for this endpoint.");
}

fn sendMethodNotAllowedWithConnection(stream: std.Io.net.Stream, allocator: std.mem.Allocator, close_connection: bool) !void {
    const headers = "Allow: GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS\r\n";
    try sendCoolErrorWithConnection(stream, allocator, 405, "Method Not Allowed", "That method is not supported for this endpoint.", close_connection, false, headers);
}

fn sendNotImplemented(stream: std.Io.net.Stream, allocator: std.mem.Allocator, close_connection: bool) !void {
    try sendCoolErrorWithConnection(stream, allocator, 501, "Not Implemented", "This server has not implemented that behavior.", close_connection, false, null);
}

fn sendResponseForMethod(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8, close_connection: bool, is_head: bool) !void {
    if (http_response.canSendBody(status_code, is_head)) {
        try sendResponseWithConnection(stream, status_code, status_text, content_type, body, close_connection);
        return;
    }

    const declared_len = if (is_head) body.len else 0;
    try sendResponseNoBodyWithConnection(stream, status_code, status_text, content_type, declared_len, close_connection);
}

fn redirectStatusText(status_code: u16) []const u8 {
    return switch (status_code) {
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        else => "Permanent Redirect",
    };
}

fn findRedirectRuleIn(rules: []const RedirectRule, path: []const u8) ?RedirectRule {
    for (rules) |rule| {
        if (rule.prefix_match) {
            if (std.mem.startsWith(u8, path, rule.from)) return rule;
        } else if (std.mem.eql(u8, path, rule.from)) {
            return rule;
        }
    }
    return null;
}

fn findRedirectRule(cfg: *const ServerConfig, path: []const u8) ?RedirectRule {
    return findRedirectRuleIn(cfg.redirects.items, path);
}

fn buildRedirectLocation(allocator: std.mem.Allocator, rule: RedirectRule, req: HttpRequest) ![]const u8 {
    const suffix = if (rule.prefix_match and req.path.len >= rule.from.len) req.path[rule.from.len..] else "";
    const should_preserve_query = req.query.len > 0 and std.mem.indexOfScalar(u8, rule.to, '?') == null;
    const joiner: []const u8 = if (should_preserve_query) "?" else "";
    const query: []const u8 = if (should_preserve_query) req.query else "";
    return try std.fmt.allocPrint(allocator, "{s}{s}{s}{s}", .{ rule.to, suffix, joiner, query });
}

fn sendConfiguredRedirect(stream: std.Io.net.Stream, allocator: std.mem.Allocator, rule: RedirectRule, req: HttpRequest, close_connection: bool, is_head: bool) !void {
    const location = try buildRedirectLocation(allocator, rule, req);
    defer allocator.free(location);

    const extra_headers = try std.fmt.allocPrint(allocator, "Location: {s}\r\n", .{location});
    defer allocator.free(extra_headers);

    const body = try std.fmt.allocPrint(
        allocator,
        "Redirecting to {s}\n",
        .{location},
    );
    defer allocator.free(body);

    if (is_head) {
        try sendResponseNoBodyWithConnectionAndHeaders(stream, rule.status_code, redirectStatusText(rule.status_code), "text/plain; charset=utf-8", body.len, close_connection, extra_headers);
        return;
    }

    try sendResponseWithConnectionAndHeaders(stream, rule.status_code, redirectStatusText(rule.status_code), "text/plain; charset=utf-8", body, close_connection, extra_headers);
}

fn sendServerIcon(stream: std.Io.net.Stream, close_connection: bool, is_head: bool) !void {
    try sendResponseForMethod(stream, 200, "OK", "image/svg+xml", SERVER_ICON_SVG, close_connection, is_head);
}

fn renderMetrics(allocator: std.mem.Allocator) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "# HELP layerline_connections_active Active TCP connections currently owned by Layerline workers.\n" ++
            "# TYPE layerline_connections_active gauge\n" ++
            "layerline_connections_active {d}\n" ++
            "# HELP layerline_connections_total Accepted TCP connections.\n" ++
            "# TYPE layerline_connections_total counter\n" ++
            "layerline_connections_total {d}\n" ++
            "# HELP layerline_connections_rejected_total Connections rejected by the concurrency gate.\n" ++
            "# TYPE layerline_connections_rejected_total counter\n" ++
            "layerline_connections_rejected_total {d}\n" ++
            "# HELP layerline_requests_total Parsed HTTP/1 requests.\n" ++
            "# TYPE layerline_requests_total counter\n" ++
            "layerline_requests_total {d}\n" ++
            "# HELP layerline_request_parse_errors_total Requests rejected by the parser.\n" ++
            "# TYPE layerline_request_parse_errors_total counter\n" ++
            "layerline_request_parse_errors_total {d}\n" ++
            "# HELP layerline_route_errors_total Routed requests that failed before a response completed.\n" ++
            "# TYPE layerline_route_errors_total counter\n" ++
            "layerline_route_errors_total {d}\n" ++
            "# HELP layerline_responses_total HTTP/1 responses by status class.\n" ++
            "# TYPE layerline_responses_total counter\n" ++
            "layerline_responses_total{{class=\"2xx\"}} {d}\n" ++
            "layerline_responses_total{{class=\"3xx\"}} {d}\n" ++
            "layerline_responses_total{{class=\"4xx\"}} {d}\n" ++
            "layerline_responses_total{{class=\"5xx\"}} {d}\n" ++
            "layerline_responses_total{{class=\"all\"}} {d}\n" ++
            "# HELP layerline_response_body_bytes_total HTTP/1 response body bytes written by normal response helpers.\n" ++
            "# TYPE layerline_response_body_bytes_total counter\n" ++
            "layerline_response_body_bytes_total {d}\n" ++
            "# HELP layerline_static_body_bytes_total Static file body bytes streamed from disk.\n" ++
            "# TYPE layerline_static_body_bytes_total counter\n" ++
            "layerline_static_body_bytes_total {d}\n" ++
            "# HELP layerline_static_responses_total Static file responses streamed from disk.\n" ++
            "# TYPE layerline_static_responses_total counter\n" ++
            "layerline_static_responses_total {d}\n" ++
            "# HELP layerline_static_sendfile_responses_total Static file responses transferred with kernel sendfile.\n" ++
            "# TYPE layerline_static_sendfile_responses_total counter\n" ++
            "layerline_static_sendfile_responses_total {d}\n" ++
            "# HELP layerline_static_buffered_responses_total Static file responses transferred through the buffered fallback.\n" ++
            "# TYPE layerline_static_buffered_responses_total counter\n" ++
            "layerline_static_buffered_responses_total {d}\n" ++
            "# HELP layerline_h3_responses_total Native HTTP/3 responses sent.\n" ++
            "# TYPE layerline_h3_responses_total counter\n" ++
            "layerline_h3_responses_total {d}\n" ++
            "# HELP layerline_h3_packets_sent_total Protected HTTP/3 1-RTT packets sent for responses.\n" ++
            "# TYPE layerline_h3_packets_sent_total counter\n" ++
            "layerline_h3_packets_sent_total {d}\n",
        .{
            ServerMetrics.load(&server_metrics.active_connections),
            ServerMetrics.load(&server_metrics.connections_total),
            ServerMetrics.load(&server_metrics.connections_rejected_total),
            ServerMetrics.load(&server_metrics.requests_total),
            ServerMetrics.load(&server_metrics.request_parse_errors_total),
            ServerMetrics.load(&server_metrics.route_errors_total),
            ServerMetrics.load(&server_metrics.response_2xx_total),
            ServerMetrics.load(&server_metrics.response_3xx_total),
            ServerMetrics.load(&server_metrics.response_4xx_total),
            ServerMetrics.load(&server_metrics.response_5xx_total),
            ServerMetrics.load(&server_metrics.responses_total),
            ServerMetrics.load(&server_metrics.response_body_bytes_total),
            ServerMetrics.load(&server_metrics.static_body_bytes_total),
            ServerMetrics.load(&server_metrics.static_responses_total),
            ServerMetrics.load(&server_metrics.static_sendfile_responses_total),
            ServerMetrics.load(&server_metrics.static_buffered_responses_total),
            ServerMetrics.load(&server_metrics.h3_responses_total),
            ServerMetrics.load(&server_metrics.h3_packets_sent_total),
        },
    );
}

fn sendMetrics(stream: std.Io.net.Stream, allocator: std.mem.Allocator, close_connection: bool, is_head: bool) !void {
    const body = try renderMetrics(allocator);
    defer allocator.free(body);
    try sendResponseForMethod(stream, 200, "OK", "text/plain; version=0.0.4; charset=utf-8", body, close_connection, is_head);
}

fn sendMethodNotAllowedWithAllow(stream: std.Io.net.Stream, allocator: std.mem.Allocator, allowed_methods: []const u8, close_connection: bool) !void {
    const allow_header = try std.fmt.allocPrint(allocator, "Allow: {s}\r\n", .{allowed_methods});
    defer allocator.free(allow_header);
    try sendCoolErrorWithConnection(stream, allocator, 405, "Method Not Allowed", "That method is not supported for this endpoint.", close_connection, false, allow_header);
}

const ByteRange = struct {
    start: usize,
    end: usize,
};

// Single ranges cover the common browser/media case. Multi-range responses are
// MIME multipart work, so they stay rejected until there is a real need.
fn etagMatches(raw: []const u8, etag: []const u8) bool {
    var cursor = raw;
    while (cursor.len > 0) {
        const comma_pos = std.mem.indexOfScalar(u8, cursor, ',') orelse cursor.len;
        const item = trimValue(cursor[0..comma_pos]);
        if (std.mem.eql(u8, item, "*") or std.mem.eql(u8, item, etag)) return true;
        if (comma_pos >= cursor.len) break;
        cursor = cursor[comma_pos + 1 ..];
    }
    return false;
}

fn parseByteRange(raw: []const u8, total_len: usize) !ByteRange {
    if (!std.mem.startsWith(u8, raw, "bytes=")) return error.BadRequest;
    if (total_len == 0) return error.RangeNotSatisfiable;

    const spec = trimValue(raw["bytes=".len..]);
    if (std.mem.indexOfScalar(u8, spec, ',') != null) return error.BadRequest;

    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return error.BadRequest;
    const start_raw = trimValue(spec[0..dash]);
    const end_raw = trimValue(spec[dash + 1 ..]);

    if (start_raw.len == 0) {
        if (end_raw.len == 0) return error.BadRequest;
        const suffix_len = std.fmt.parseInt(usize, end_raw, 10) catch return error.BadRequest;
        if (suffix_len == 0) return error.RangeNotSatisfiable;
        const actual_len = @min(suffix_len, total_len);
        return .{ .start = total_len - actual_len, .end = total_len - 1 };
    }

    const start = std.fmt.parseInt(usize, start_raw, 10) catch return error.BadRequest;
    const end = if (end_raw.len == 0)
        total_len - 1
    else
        std.fmt.parseInt(usize, end_raw, 10) catch return error.BadRequest;

    if (start >= total_len or start > end) return error.RangeNotSatisfiable;
    return .{ .start = start, .end = @min(end, total_len - 1) };
}

fn makeStaticEtag(allocator: std.mem.Allocator, stat: std.Io.File.Stat) ![]const u8 {
    // Cheap validator, not a content hash. Good enough to catch ordinary local
    // edits without reading the file twice.
    return std.fmt.allocPrint(
        allocator,
        "\"{d}-{d}-{d}\"",
        .{ stat.inode, stat.size, stat.mtime.toNanoseconds() },
    );
}

fn makeStaticBaseHeaders(allocator: std.mem.Allocator, etag: []const u8, content_encoding: ?[]const u8) ![]const u8 {
    if (content_encoding) |encoding| {
        return std.fmt.allocPrint(
            allocator,
            "Accept-Ranges: bytes\r\n" ++
                "ETag: {s}\r\n" ++
                "Cache-Control: public, max-age=60\r\n" ++
                "Vary: Accept-Encoding\r\n" ++
                "Content-Encoding: {s}\r\n",
            .{ etag, encoding },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "Accept-Ranges: bytes\r\n" ++
            "ETag: {s}\r\n" ++
            "Cache-Control: public, max-age=60\r\n" ++
            "Vary: Accept-Encoding\r\n",
        .{etag},
    );
}

fn acceptsContentCoding(request_headers: []const u8, coding: []const u8) bool {
    const raw = findHeaderValue(request_headers, "Accept-Encoding") orelse return false;
    var cursor = raw;
    while (cursor.len > 0) {
        const comma_pos = std.mem.indexOfScalar(u8, cursor, ',') orelse cursor.len;
        const item = trimValue(cursor[0..comma_pos]);
        const semicolon_pos = std.mem.indexOfScalar(u8, item, ';') orelse item.len;
        const token = trimValue(item[0..semicolon_pos]);
        if (std.mem.eql(u8, token, "*") or std.ascii.eqlIgnoreCase(token, coding)) return true;
        if (comma_pos >= cursor.len) break;
        cursor = cursor[comma_pos + 1 ..];
    }
    return false;
}

fn statRegularFile(io: std.Io, file_path: []const u8) !std.Io.File.Stat {
    const stat = try std.Io.Dir.cwd().statFile(io, file_path, .{});
    if (stat.kind != .file) return error.NotFile;
    return stat;
}

fn trySendfileStaticRange(stream: std.Io.net.Stream, file: std.Io.File, start: usize, body_len: usize) !bool {
    if (comptime !HAS_DARWIN_SENDFILE) return false;
    if (body_len == 0) return true;

    var offset = std.math.cast(std.c.off_t, start) orelse return error.FileTooBig;
    var remaining = body_len;
    var sent_total: usize = 0;

    while (remaining > 0) {
        const chunk = @min(remaining, @as(usize, @intCast(std.math.maxInt(i32))));
        var len: std.c.off_t = @intCast(chunk);
        switch (std.c.errno(std.c.sendfile(file.handle, stream.socket.handle, offset, &len, null, 0))) {
            .SUCCESS => {},
            .INTR, .AGAIN => {
                if (len == 0) continue;
            },
            .OPNOTSUPP, .NOTSOCK, .NOSYS => {
                if (sent_total == 0) return false;
                return error.Unexpected;
            },
            .PIPE, .NOTCONN => return error.BrokenPipe,
            .IO => return error.InputOutput,
            else => return error.Unexpected,
        }

        if (len <= 0) return error.WriteZero;
        const sent: usize = @intCast(len);
        remaining -= sent;
        sent_total += sent;
        offset += len;
    }

    return true;
}

fn streamStaticFileRangeBody(
    io: std.Io,
    stream: std.Io.net.Stream,
    file_path: []const u8,
    start: usize,
    body_len: usize,
) !void {
    const file = try std.Io.Dir.cwd().openFile(io, file_path, .{ .mode = .read_only, .allow_directory = false });
    defer file.close(io);

    if (try trySendfileStaticRange(stream, file, start, body_len)) {
        server_metrics.staticBodySent(body_len, .sendfile);
        return;
    }

    var buffer: [8 * 1024]u8 = undefined;
    var sent: usize = 0;
    while (sent < body_len) {
        const chunk_len = @min(buffer.len, body_len - sent);
        var vec: [1][]u8 = .{buffer[0..chunk_len]};
        const read_n = try file.readPositional(io, &vec, start + sent);
        if (read_n == 0) return error.UnexpectedEndOfFile;
        try streamWriteAll(stream, buffer[0..read_n]);
        sent += read_n;
    }

    server_metrics.staticBodySent(body_len, .buffered);
}

fn serveStatic(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    static_dir: []const u8,
    rel_path: []const u8,
    request_headers: []const u8,
    close_connection: bool,
    is_head: bool,
    max_file_bytes: usize,
) !void {
    // Static paths are deliberately boring: no parent hops, no backslashes, no
    // directory listings. If it is not a plain file, it is not served.
    if (rel_path.len == 0 or std.mem.indexOf(u8, rel_path, "..") != null or std.mem.indexOfScalar(u8, rel_path, '\\') != null) {
        try sendBadRequestWithConnection(allocator, stream, "Invalid static file path.", close_connection);
        return;
    }

    const file_path = try std.fs.path.join(allocator, &.{ static_dir, rel_path });
    defer allocator.free(file_path);

    var stat = statRegularFile(io, file_path) catch |err| {
        if (err == error.NotDir or err == error.FileNotFound) {
            try sendNotFoundWithConnection(allocator, stream, close_connection);
            return;
        }
        if (err == error.NotFile) {
            try sendNotFoundWithConnection(allocator, stream, close_connection);
            return;
        }
        return err;
    };

    const range_header = findHeaderValue(request_headers, "Range");
    var selected_path = file_path;
    var encoded_path: ?[]const u8 = null;
    defer if (encoded_path) |path| allocator.free(path);
    var content_encoding: ?[]const u8 = null;

    // Serve precompressed assets when present. On-the-fly compression belongs
    // in a worker/offline build step, not on the hot request path.
    if (range_header == null) {
        const candidates = [_]struct { coding: []const u8, suffix: []const u8 }{
            .{ .coding = "br", .suffix = ".br" },
            .{ .coding = "gzip", .suffix = ".gz" },
        };
        for (candidates) |candidate| {
            if (!acceptsContentCoding(request_headers, candidate.coding)) continue;
            const candidate_path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ file_path, candidate.suffix });
            if (statRegularFile(io, candidate_path)) |candidate_stat| {
                selected_path = candidate_path;
                encoded_path = candidate_path;
                stat = candidate_stat;
                content_encoding = candidate.coding;
                break;
            } else |_| {
                allocator.free(candidate_path);
            }
        }
    }

    if (stat.size > max_file_bytes) {
        try sendCoolErrorWithConnection(
            stream,
            allocator,
            413,
            "Payload Too Large",
            "Static file is too large for configured limits.",
            close_connection,
            false,
            null,
        );
        return;
    }
    const file_len = std.math.cast(usize, stat.size) orelse return error.FileTooBig;

    const etag = try makeStaticEtag(allocator, stat);
    defer allocator.free(etag);
    const base_headers = try makeStaticBaseHeaders(allocator, etag, content_encoding);
    defer allocator.free(base_headers);

    if (findHeaderValue(request_headers, "If-None-Match")) |if_none_match| {
        if (etagMatches(if_none_match, etag)) {
            try sendResponseNoBodyWithConnectionAndHeaders(stream, 304, "Not Modified", contentTypeFromPath(rel_path), 0, close_connection, base_headers);
            return;
        }
    }

    if (range_header) |range_value| {
        const range = parseByteRange(range_value, file_len) catch |err| switch (err) {
            error.RangeNotSatisfiable => {
                const headers = try std.fmt.allocPrint(allocator, "{s}Content-Range: bytes */{d}\r\n", .{ base_headers, file_len });
                defer allocator.free(headers);
                try sendCoolErrorWithConnection(stream, allocator, 416, "Range Not Satisfiable", "Requested byte range cannot be served.", close_connection, is_head, headers);
                return;
            },
            error.BadRequest => {
                try sendBadRequestWithConnection(allocator, stream, "Invalid Range header.", close_connection);
                return;
            },
        };

        const content_range = try std.fmt.allocPrint(allocator, "bytes {d}-{d}/{d}", .{ range.start, range.end, file_len });
        defer allocator.free(content_range);
        const headers = try std.fmt.allocPrint(allocator, "{s}Content-Range: {s}\r\n", .{ base_headers, content_range });
        defer allocator.free(headers);
        const body_len = range.end - range.start + 1;

        if (is_head) {
            try sendResponseNoBodyWithConnectionAndHeaders(stream, 206, "Partial Content", contentTypeFromPath(rel_path), body_len, close_connection, headers);
            return;
        }

        try sendResponseNoBodyWithConnectionAndHeaders(stream, 206, "Partial Content", contentTypeFromPath(rel_path), body_len, close_connection, headers);
        try streamStaticFileRangeBody(io, stream, selected_path, range.start, body_len);
        return;
    }

    if (is_head) {
        try sendResponseNoBodyWithConnectionAndHeaders(stream, 200, "OK", contentTypeFromPath(rel_path), file_len, close_connection, base_headers);
        return;
    }

    try sendResponseNoBodyWithConnectionAndHeaders(stream, 200, "OK", contentTypeFromPath(rel_path), file_len, close_connection, base_headers);
    try streamStaticFileRangeBody(io, stream, selected_path, 0, file_len);
}

fn serveAcmeChallenge(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    webroot: []const u8,
    token: []const u8,
    close_connection: bool,
    is_head: bool,
) !void {
    if (token.len == 0 or std.mem.indexOf(u8, token, "..") != null or std.mem.indexOfScalar(u8, token, '\\') != null or std.mem.indexOfScalar(u8, token, '/') != null) {
        try sendBadRequestWithConnection(allocator, stream, "Invalid ACME challenge path.", close_connection);
        return;
    }

    const file_path = try std.fs.path.join(allocator, &.{ webroot, token });
    defer allocator.free(file_path);

    const data = std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(64 * 1024)) catch |err| {
        if (err == error.StreamTooLong) {
            try sendCoolErrorWithConnection(stream, allocator, 413, "Payload Too Large", "ACME challenge file is too large.", close_connection, false, null);
            return;
        }
        if (err == error.NotDir or err == error.FileNotFound) {
            try sendNotFoundWithConnection(allocator, stream, close_connection);
            return;
        }
        return err;
    };
    defer allocator.free(data);

    // ACME files are expected to be small; enforce strict plaintext response.
    if (data.len > 0 and std.mem.indexOfScalar(u8, data, 0) != null) {
        try sendNotFoundWithConnection(allocator, stream, close_connection);
        return;
    }

    if (is_head) {
        try sendResponseNoBodyWithConnection(stream, 200, "OK", "text/plain; charset=utf-8", data.len, close_connection);
        return;
    }
    try sendResponseWithConnection(stream, 200, "OK", "text/plain; charset=utf-8", data, close_connection);
}

const BodyRead = struct {
    body: []const u8,
    discarded_pipeline_bytes: bool,
};

const BufferedBodyReader = struct {
    stream: std.Io.net.Stream,
    buffered: []const u8,
    pos: usize = 0,

    fn readByte(self: *BufferedBodyReader) !u8 {
        if (self.pos < self.buffered.len) {
            const byte = self.buffered[self.pos];
            self.pos += 1;
            return byte;
        }

        var one: [1]u8 = undefined;
        const n = try streamRead(self.stream, &one);
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

            const n = try streamRead(self.stream, out[written..]);
            if (n == 0) return error.BadRequest;
            written += n;
        }
    }

    fn unreadLen(self: *const BufferedBodyReader) usize {
        return self.buffered.len - self.pos;
    }
};

fn readChunkLineInto(reader: *BufferedBodyReader, line: *[MAX_CHUNK_LINE_BYTES]u8) ![]const u8 {
    var len: usize = 0;

    // The caller owns this buffer. Returning a slice to a local stack buffer is
    // exactly the kind of tiny mistake that makes chunk parsing look haunted.
    while (true) {
        const byte = try reader.readByte();
        if (byte == '\n') break;
        if (byte == '\r') continue;
        if (len == line.*.len) return error.BadRequest;
        line.*[len] = byte;
        len += 1;
    }

    return line.*[0..len];
}

fn parseChunkSize(line: []const u8) !usize {
    const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
    const raw_size = trimValue(line[0..semi]);
    if (raw_size.len == 0) return error.BadRequest;
    return std.fmt.parseInt(usize, raw_size, 16) catch error.BadRequest;
}

fn readChunkedBody(stream: std.Io.net.Stream, allocator: std.mem.Allocator, buffer_tail: []const u8, max_body_bytes: usize) !BodyRead {
    var reader = BufferedBodyReader{ .stream = stream, .buffered = buffer_tail };
    var body = std.ArrayList(u8).empty;
    errdefer body.deinit(allocator);
    var line_buf: [MAX_CHUNK_LINE_BYTES]u8 = undefined;

    while (true) {
        const size = try parseChunkSize(try readChunkLineInto(&reader, &line_buf));
        if (size == 0) {
            while (true) {
                const trailer = try readChunkLineInto(&reader, &line_buf);
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

fn readContentLengthBody(stream: std.Io.net.Stream, allocator: std.mem.Allocator, headers: []const u8, buffer_tail: []const u8, max_body_bytes: usize) !BodyRead {
    const expected_len = try parseContentLength(headers);
    if (expected_len == 0) return .{ .body = "", .discarded_pipeline_bytes = buffer_tail.len > 0 };
    if (expected_len > max_body_bytes) return error.PayloadTooLarge;

    const body = try allocator.alloc(u8, expected_len);
    const already = @min(buffer_tail.len, expected_len);
    @memcpy(body[0..already], buffer_tail[0..already]);

    var read_total: usize = already;
    while (read_total < expected_len) {
        const n = try streamRead(stream, body[read_total..]);
        if (n == 0) return error.BadRequest;
        read_total += n;
    }

    return .{
        .body = body,
        .discarded_pipeline_bytes = buffer_tail.len > expected_len,
    };
}

fn readBody(stream: std.Io.net.Stream, allocator: std.mem.Allocator, headers: []const u8, buffer_tail: []const u8, max_body_bytes: usize) !BodyRead {
    const is_chunked = try transferEncodingIsChunkedOnly(headers);
    if (is_chunked) {
        if (findHeaderValue(headers, "Content-Length") != null) return error.BadRequest;
        return try readChunkedBody(stream, allocator, buffer_tail, max_body_bytes);
    }

    return try readContentLengthBody(stream, allocator, headers, buffer_tail, max_body_bytes);
}

const RawProxyContext = struct {
    io: std.Io,
    src: std.Io.net.Stream,
    dst: std.Io.net.Stream,
};

fn proxyRawStream(ctx: RawProxyContext) void {
    bindThreadIo(ctx.io);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = streamRead(ctx.src, &buf) catch return;
        if (n == 0) return;
        streamWriteAll(ctx.dst, buf[0..n]) catch return;
    }
}

fn proxyRawBidirectional(a: std.Io.net.Stream, b: std.Io.net.Stream, initial_payload: []const u8) !void {
    if (initial_payload.len > 0) {
        try streamWriteAll(b, initial_payload);
    }

    const io = activeIo();
    const t1 = try std.Thread.spawn(
        .{},
        proxyRawStream,
        .{RawProxyContext{ .io = io, .src = a, .dst = b }},
    );
    const t2 = try std.Thread.spawn(
        .{},
        proxyRawStream,
        .{RawProxyContext{ .io = io, .src = b, .dst = a }},
    );
    t1.join();
    t2.join();
}

fn isHttp3OverTcpProbe(bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    return bytes[0] == 0x00;
}

// Read the whole request envelope while the backing buffer is still alive.
// Method/path/header slices all point into it.
fn parseRequest(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    max_request_bytes: usize,
    max_body_bytes: usize,
    read_body_timeout_ms: u32,
    prefill: []const u8,
) !HttpRequest {
    const request_buffer = try allocator.alloc(u8, max_request_bytes);
    var used: usize = 0;

    const prefill_len = @min(prefill.len, request_buffer.len);
    if (prefill_len > 0) {
        @memcpy(request_buffer[0..prefill_len], prefill[0..prefill_len]);
        used = prefill_len;
    }

    while (used < request_buffer.len) {
        const n = try streamRead(stream, request_buffer[used..]);
        if (n == 0) return error.ConnectionClosed;
        used += n;

        if (std.mem.indexOf(u8, request_buffer[0..used], "\r\n\r\n") != null) break;
        if (used == request_buffer.len) return error.RequestTooLarge;
    }

    const header_end = (std.mem.indexOf(u8, request_buffer[0..used], "\r\n\r\n") orelse return error.MalformedRequest) + 4;
    const header_bytes = request_buffer[0..header_end];
    const body_tail = request_buffer[header_end..used];

    const request_line_end = std.mem.indexOf(u8, header_bytes, "\r\n") orelse return error.MalformedRequest;
    const request_line = header_bytes[0..request_line_end];
    var request_parts = std.mem.splitSequence(u8, request_line, " ");

    const method = request_parts.next() orelse return error.MalformedRequest;
    const path_and_query = request_parts.next() orelse return error.MalformedRequest;
    const version = request_parts.next() orelse return error.MalformedRequest;

    const query_pos = std.mem.indexOfScalar(u8, path_and_query, '?');
    const path = if (query_pos) |idx| path_and_query[0..idx] else path_and_query;
    const query = if (query_pos) |idx| if (idx + 1 < path_and_query.len) path_and_query[idx + 1 ..] else "" else "";

    const headers_start = request_line_end + 2;
    const headers_end = if (header_end >= 4) header_end - 4 else 0;
    const headers = if (headers_start <= headers_end) header_bytes[headers_start..headers_end] else "";

    if (!std.mem.eql(u8, version, "HTTP/1.1") and !std.mem.eql(u8, version, "HTTP/1.0")) return error.UnsupportedHttpVersion;
    if (std.mem.startsWith(u8, version, "HTTP/1.1") and findHeaderValue(headers, "Host") == null) {
        return error.MissingHostHeader;
    }

    if (findHeaderValue(headers, "Expect")) |expect| {
        if (!hasConnectionToken(expect, "100-continue")) return error.ExpectationFailed;
        try streamWriteAll(stream, "HTTP/1.1 100 Continue\r\n\r\n");
    }

    // Parse body only after headers are validated, and enforce limits immediately.
    try setStreamReadTimeout(stream, read_body_timeout_ms);
    const body_read = try readBody(stream, allocator, headers, body_tail, max_body_bytes);
    const close_connection = parseConnectionClose(version, headers) or body_read.discarded_pipeline_bytes;

    return HttpRequest{
        .method = method,
        .path = path,
        .query = query,
        .headers = headers,
        .version = version,
        .body = body_read.body,
        .close_connection = close_connection,
    };
}

fn handleHttp2Preface(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, prefill: []const u8) !void {
    if (cfg.h2_upstream == null) {
        try sendCoolErrorWithConnection(
            stream,
            allocator,
            426,
            "Upgrade Required",
            "HTTP/2 requests require an HTTP/2-aware upstream. Configure --h2-upstream (for example, Caddy/nghttp2/nginx h2c target) and keep this binary as an HTTP/1 origin.",
            false,
            false,
            null,
        );
        return;
    }

    const upstream = cfg.h2_upstream.?;
    if (upstream.https) {
        try sendCoolErrorWithConnection(
            stream,
            allocator,
            501,
            "Not Implemented",
            "HTTP/2 upstream to HTTPS is not supported in this passthrough mode. Use an HTTP/1 backend for h2c passthrough.",
            false,
            false,
            null,
        );
        return;
    }

    const upstream_conn = try connectTcpHost(allocator, upstream.host, upstream.port);
    defer streamClose(upstream_conn);
    try setStreamTimeouts(upstream_conn, cfg.upstream_timeout_ms, cfg.upstream_timeout_ms);

    // Preserve any bytes already read (including partial preface/frame data)
    // and bridge both directions.
    try proxyRawBidirectional(stream, upstream_conn, prefill);
}

// Parse scheme/host/port/path strings from a proxy URL into normalized fields.
fn parseUpstream(allocator: std.mem.Allocator, raw: []const u8) !UpstreamConfig {
    const scheme_https = std.mem.startsWith(u8, raw, "https://");
    const scheme_http = std.mem.startsWith(u8, raw, "http://");
    var rest = raw;

    if (scheme_https) {
        rest = raw["https://".len..];
    } else if (scheme_http) {
        rest = raw["http://".len..];
    }

    const slash_pos = std.mem.indexOfScalar(u8, rest, '/');
    const host_port = if (slash_pos) |p| rest[0..p] else rest;
    const base_path = if (slash_pos) |p| rest[p..] else "/";

    const colon = std.mem.lastIndexOfScalar(u8, host_port, ':');
    var host = host_port;
    var port: u16 = if (scheme_https) 443 else 80;

    if (colon) |col| {
        host = host_port[0..col];
        port = std.fmt.parseInt(u16, host_port[col + 1 ..], 10) catch if (scheme_https) 443 else 80;
    }
    if (host.len == 0) return error.InvalidUpstream;

    const dupe_host = try allocator.dupe(u8, host);
    const dupe_path = try allocator.dupe(u8, if (base_path.len == 0) "/" else base_path);

    return UpstreamConfig{ .host = dupe_host, .port = port, .base_path = dupe_path, .https = scheme_https };
}

fn parseUpstreamPool(allocator: std.mem.Allocator, raw: []const u8) !UpstreamPoolConfig {
    var pool = UpstreamPoolConfig{
        .targets = .empty,
        .policy = .round_robin,
    };

    var parts = std.mem.tokenizeAny(u8, raw, " \t,");
    while (parts.next()) |part| {
        const value = trimValue(part);
        if (value.len == 0) continue;
        try pool.targets.append(allocator, try parseUpstream(allocator, value));
    }

    if (pool.targets.items.len == 0) return error.InvalidUpstream;
    return pool;
}

fn upstreamPoolTargetCount(pool: UpstreamPoolConfig) usize {
    return pool.targets.items.len;
}

fn selectUpstream(pool: *const UpstreamPoolConfig) ?*const UpstreamConfig {
    if (pool.targets.items.len == 0) return null;
    return switch (pool.policy) {
        .round_robin => blk: {
            const ticket = upstream_round_robin_cursor.fetchAdd(1, .monotonic);
            break :blk &pool.targets.items[ticket % pool.targets.items.len];
        },
    };
}

fn printUpstreamPool(pool: UpstreamPoolConfig) void {
    std.debug.print(" upstream=round_robin[", .{});
    for (pool.targets.items, 0..) |up, i| {
        if (i > 0) std.debug.print(",", .{});
        std.debug.print("{s}:{d}{s}", .{ up.host, up.port, up.base_path });
    }
    std.debug.print("]", .{});
}

// Build a target path for proxying while avoiding `//` and leading path glitches.
fn buildProxyPath(allocator: std.mem.Allocator, base_path: []const u8, request_path: []const u8, query: []const u8) ![]const u8 {
    var final_path = std.ArrayList(u8).empty;

    if (std.mem.eql(u8, base_path, "/")) {
        try final_path.appendSlice(allocator, request_path);
    } else {
        try final_path.appendSlice(allocator, base_path);
        if (!std.mem.endsWith(u8, base_path, "/") and request_path.len > 0 and request_path[0] != '/') {
            try final_path.append(allocator, '/');
        }
        if (!std.mem.startsWith(u8, request_path, "/")) {
            try final_path.appendSlice(allocator, request_path);
        } else {
            try final_path.appendSlice(allocator, request_path[1..]);
        }
    }

    if (final_path.items.len == 0) {
        try final_path.append(allocator, '/');
    }

    if (query.len > 0) {
        try final_path.append(allocator, '?');
        try final_path.appendSlice(allocator, query);
    }

    return try final_path.toOwnedSlice(allocator);
}

fn makeStaticPathFromRequest(allocator: std.mem.Allocator, request_path: []const u8, index_file: []const u8) ![]const u8 {
    if (request_path.len == 0) return allocator.dupe(u8, index_file);

    const rel = if (request_path[0] == '/') request_path[1..] else request_path;
    if (std.mem.eql(u8, rel, "")) return allocator.dupe(u8, index_file);

    if (std.mem.endsWith(u8, rel, "/")) {
        const full_len = rel.len + index_file.len;
        const out = try allocator.alloc(u8, full_len);
        @memcpy(out[0..rel.len], rel);
        @memcpy(out[rel.len..full_len], index_file);
        return out;
    }

    return allocator.dupe(u8, rel);
}

fn isSkippedProxyHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "Connection") or
        std.ascii.eqlIgnoreCase(name, "Content-Length") or
        std.ascii.eqlIgnoreCase(name, "Keep-Alive") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authenticate") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authorization") or
        std.ascii.eqlIgnoreCase(name, "TE") or
        std.ascii.eqlIgnoreCase(name, "Trailers") or
        std.ascii.eqlIgnoreCase(name, "Transfer-Encoding") or
        std.ascii.eqlIgnoreCase(name, "Upgrade") or
        std.ascii.eqlIgnoreCase(name, "Host");
}

fn isSkippedProxyResponseHeader(name: []const u8) bool {
    // The proxy closes the client connection after each upstream response, so
    // forwarding an upstream "keep-alive" promise would be a lie.
    return std.ascii.eqlIgnoreCase(name, "Connection") or
        std.ascii.eqlIgnoreCase(name, "Keep-Alive") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authenticate") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authorization") or
        std.ascii.eqlIgnoreCase(name, "TE") or
        std.ascii.eqlIgnoreCase(name, "Trailers") or
        std.ascii.eqlIgnoreCase(name, "Upgrade");
}

fn forwardUpstreamResponse(stream: std.Io.net.Stream, upstream_conn: std.Io.net.Stream) !void {
    var response_buffer: [DEFAULT_MAX_REQUEST_BYTES]u8 = undefined;
    var used: usize = 0;

    // Buffer only the upstream headers so we can scrub hop-by-hop fields, then
    // stream the body straight through.
    while (used < response_buffer.len) {
        const n = try streamRead(upstream_conn, response_buffer[used..]);
        if (n == 0) return error.BadGateway;
        used += n;
        if (std.mem.indexOf(u8, response_buffer[0..used], "\r\n\r\n") != null) break;
    }

    const header_end = (std.mem.indexOf(u8, response_buffer[0..used], "\r\n\r\n") orelse return error.BadGateway) + 4;
    const header_bytes = response_buffer[0..header_end];
    const body_tail = response_buffer[header_end..used];
    const status_line_end = std.mem.indexOf(u8, header_bytes, "\r\n") orelse return error.BadGateway;

    try streamWriteAll(stream, header_bytes[0..status_line_end]);
    try streamWriteAll(stream, "\r\n");

    const headers_start = status_line_end + 2;
    const headers_end = header_end - 4;
    var headers = std.mem.splitSequence(u8, header_bytes[headers_start..headers_end], "\r\n");
    while (headers.next()) |line| {
        const trimmed = trimValue(line);
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const name = trimValue(trimmed[0..colon]);
            if (isSkippedProxyResponseHeader(name)) continue;
        }
        try streamWriteAll(stream, trimmed);
        try streamWriteAll(stream, "\r\n");
    }

    try streamWriteAll(stream, "Connection: close\r\n\r\n");
    if (body_tail.len > 0) try streamWriteAll(stream, body_tail);

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try streamRead(upstream_conn, &buf);
        if (n == 0) break;
        try streamWriteAll(stream, buf[0..n]);
    }
}

fn forwardToUpstream(stream: std.Io.net.Stream, allocator: std.mem.Allocator, upstream: *const UpstreamConfig, req: HttpRequest, upstream_timeout_ms: u32) !void {
    if (upstream.https) {
        try sendCoolErrorWithConnection(
            stream,
            allocator,
            501,
            "Not Implemented",
            "HTTPS upstream is not yet supported in this single-file server path. Use HTTPS reverse proxy in front of this binary.",
            false,
            false,
            null,
        );
        return;
    }

    const upstream_conn = try connectTcpHost(allocator, upstream.host, upstream.port);
    defer streamClose(upstream_conn);
    try setStreamTimeouts(upstream_conn, upstream_timeout_ms, upstream_timeout_ms);

    const proxy_path = try buildProxyPath(allocator, upstream.base_path, req.path, req.query);
    defer allocator.free(proxy_path);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    // Rebuild framing headers from parsed state. Copying the client's
    // Content-Length here caused duplicate lengths and strict backends rejected it.
    try out.print(
        allocator,
        "{s} {s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n",
        .{
            req.method,
            proxy_path,
            upstream.host,
        },
    );

    var headers = std.mem.splitSequence(u8, req.headers, "\r\n");
    while (headers.next()) |line| {
        const trimmed = trimValue(line);
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const name = trimValue(trimmed[0..colon]);
            if (isSkippedProxyHeader(name)) continue;
            const value = trimValue(trimmed[colon + 1 ..]);
            if (value.len == 0) continue;
            try out.print(allocator, "{s}: {s}\r\n", .{ name, value });
        }
    }

    try out.print(
        allocator,
        "Content-Length: {d}\r\n\r\n",
        .{req.body.len},
    );
    const request_line = try out.toOwnedSlice(allocator);
    defer allocator.free(request_line);

    streamWriteAll(upstream_conn, request_line) catch |err| switch (err) {
        error.RequestTimeout => {
            try sendCoolErrorWithConnection(stream, allocator, 504, "Gateway Timeout", "Timed out writing to upstream.", true, false, null);
            return;
        },
        else => |e| return e,
    };
    if (req.body.len > 0) {
        streamWriteAll(upstream_conn, req.body) catch |err| switch (err) {
            error.RequestTimeout => {
                try sendCoolErrorWithConnection(stream, allocator, 504, "Gateway Timeout", "Timed out writing request body to upstream.", true, false, null);
                return;
            },
            else => |e| return e,
        };
    }

    forwardUpstreamResponse(stream, upstream_conn) catch |err| switch (err) {
        error.RequestTimeout => {
            try sendCoolErrorWithConnection(stream, allocator, 504, "Gateway Timeout", "Timed out waiting for upstream response.", true, false, null);
            return;
        },
        else => |e| return e,
    };

    return error.CloseConnection;
}

fn forwardToUpstreamPool(stream: std.Io.net.Stream, allocator: std.mem.Allocator, pool: *const UpstreamPoolConfig, req: HttpRequest, upstream_timeout_ms: u32) !void {
    const upstream = selectUpstream(pool) orelse {
        try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "Proxy upstream pool is empty.", true, false, null);
        return;
    };
    try forwardToUpstream(stream, allocator, upstream, req, upstream_timeout_ms);
}

fn handlePhp(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    close_connection: bool,
    is_head: bool,
    process_env: *const std.process.Environ.Map,
) !void {
    const rel_path = if (req.path.len > 0 and req.path[0] == '/') req.path[1..] else req.path;
    try handlePhpScript(io, stream, allocator, cfg, req, cfg.php_root, cfg.php_binary, rel_path, close_connection, is_head, process_env);
}

fn handlePhpScript(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    php_root: []const u8,
    php_binary: []const u8,
    script_rel_path: []const u8,
    close_connection: bool,
    is_head: bool,
    process_env: *const std.process.Environ.Map,
) !void {
    if (php_binary.len == 0) {
        try sendCoolErrorWithConnection(stream, allocator, 500, "Server Error", "PHP support is not configured for this server.", close_connection, false, null);
        return;
    }

    const rel_path = script_rel_path;
    if (rel_path.len == 0 or std.mem.indexOf(u8, rel_path, "..") != null) {
        try sendNotFoundWithConnection(allocator, stream, close_connection);
        return;
    }

    const script_path = try std.fs.path.join(allocator, &.{ php_root, rel_path });
    defer allocator.free(script_path);

    const script_stat = std.Io.Dir.cwd().statFile(io, script_path, .{}) catch {
        try sendNotFoundWithConnection(allocator, stream, close_connection);
        return;
    };
    if (script_stat.kind != .file) {
        try sendNotFoundWithConnection(allocator, stream, close_connection);
        return;
    }

    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(allocator);

    try argv.append(allocator, php_binary);
    if (!isPhpCgiBinary(php_binary)) {
        try argv.append(allocator, "-f");
        try argv.append(allocator, script_path);
    }

    var child_env = try process_env.clone(allocator);
    defer child_env.deinit();

    const request_uri = try std.fmt.allocPrint(allocator, "{s}{s}{s}", .{
        req.path,
        if (req.query.len > 0) "?" else "",
        req.query,
    });
    defer allocator.free(request_uri);

    const content_length = try std.fmt.allocPrint(allocator, "{d}", .{req.body.len});
    defer allocator.free(content_length);

    const server_port = try std.fmt.allocPrint(allocator, "{d}", .{cfg.port});
    defer allocator.free(server_port);

    try child_env.put("GATEWAY_INTERFACE", "CGI/1.1");
    try child_env.put("SERVER_SOFTWARE", SERVER_HEADER);
    try child_env.put("SERVER_NAME", cfg.host);
    try child_env.put("SERVER_PORT", server_port);
    try child_env.put("SERVER_PROTOCOL", req.version);
    try child_env.put("REQUEST_METHOD", req.method);
    try child_env.put("REQUEST_URI", request_uri);
    try child_env.put("SCRIPT_NAME", req.path);
    try child_env.put("SCRIPT_FILENAME", script_path);
    try child_env.put("PATH_TRANSLATED", script_path);
    try child_env.put("PATH_INFO", "");
    try child_env.put("QUERY_STRING", req.query);
    try child_env.put("DOCUMENT_ROOT", php_root);
    try child_env.put("REQUEST_SCHEME", "http");
    try child_env.put("HTTPS", "off");
    try child_env.put("REDIRECT_STATUS", "200");
    try child_env.put("CONTENT_LENGTH", content_length);
    try child_env.put("CONTENT_TYPE", findHeaderValue(req.headers, "Content-Type") orelse "");
    try putCgiRequestHeaders(allocator, &child_env, req.headers);

    // PHP-CGI wants the script in the CGI environment. Plain `php` gets a
    // script argument as a fallback for local development setups.
    var child = std.process.spawn(io, .{
        .argv = argv.items,
        .environ_map = &child_env,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print("PHP spawn failed for {s}: {}\n", .{ php_binary, err });
        try sendCoolErrorWithConnection(
            stream,
            allocator,
            502,
            "Bad Gateway",
            "PHP worker could not be started. Check php_bin and make sure php-cgi is installed or configured with an absolute path.",
            close_connection,
            false,
            null,
        );
        return;
    };
    defer child.kill(io);

    if (child.stdin) |in_pipe| {
        var in_writer = in_pipe.writer(io, &.{});
        if (req.body.len > 0) {
            try in_writer.interface.writeAll(req.body);
        }
        in_pipe.close(io);
    }

    const max_output = cfg.max_php_output_bytes;
    const output = if (child.stdout) |out_pipe| blk: {
        var out_reader = out_pipe.reader(io, &.{});
        const captured_output = out_reader.interface.allocRemaining(allocator, .limited(max_output)) catch |err| switch (err) {
            error.StreamTooLong => {
                try sendCoolErrorWithConnection(
                    stream,
                    allocator,
                    502,
                    "Bad Gateway",
                    "PHP response exceeded max_php_output_bytes.",
                    close_connection,
                    false,
                    null,
                );
                return;
            },
            else => |e| return e,
        };
        break :blk captured_output;
    } else return error.InternalServerError;
    defer allocator.free(output);
    if (child.stdout) |out_pipe| out_pipe.close(io);

    const term = try child.wait(io);
    switch (term) {
        .exited => |code| {
            if (code != 0) {
                try sendCoolErrorWithConnection(
                    stream,
                    allocator,
                    502,
                    "Bad Gateway",
                    "PHP process exited with a non-zero status.",
                    close_connection,
                    false,
                    null,
                );
                return;
            }
        },
        .signal, .stopped, .unknown => {
            try sendCoolErrorWithConnection(
                stream,
                allocator,
                502,
                "Bad Gateway",
                "PHP process terminated abnormally.",
                close_connection,
                false,
                null,
            );
            return;
        },
    }

    const split = splitCgiHeaderBlock(output) orelse {
        if (is_head) {
            try sendResponseNoBodyWithConnection(stream, 200, "OK", "text/plain; charset=utf-8", output.len, close_connection);
        } else {
            try sendResponseWithConnection(stream, 200, "OK", "text/plain; charset=utf-8", output, close_connection);
        }
        return;
    };

    const headers = split.headers;
    const body = split.body;

    const status = parseCgiStatus(headers);
    const ctype_out = findCgiHeaderValue(headers, "Content-Type") orelse "text/plain; charset=utf-8";
    const extra_headers = try buildCgiExtraHeaders(allocator, headers);
    defer if (extra_headers) |h| allocator.free(h);

    if (http_response.canSendBody(status.code, is_head)) {
        try sendResponseWithConnectionAndHeaders(stream, status.code, status.text, ctype_out, body, close_connection, extra_headers);
    } else {
        const declared_len = if (is_head) body.len else 0;
        try sendResponseNoBodyWithConnectionAndHeaders(stream, status.code, status.text, ctype_out, declared_len, close_connection, extra_headers);
    }
}

fn routeMatches(route: *const RouteConfig, path: []const u8) bool {
    return switch (route.match_kind) {
        .exact => std.mem.eql(u8, path, route.pattern),
        .prefix => std.mem.startsWith(u8, path, route.pattern),
    };
}

fn findNamedRoute(cfg: *const ServerConfig, path: []const u8) ?*const RouteConfig {
    return findNamedRouteIn(cfg.routes.items, path);
}

fn findNamedRouteIn(routes: []const RouteConfig, path: []const u8) ?*const RouteConfig {
    var best: ?*const RouteConfig = null;
    var best_len: usize = 0;
    for (routes) |*route| {
        if (!routeMatches(route, path)) continue;
        if (route.match_kind == .exact) return route;
        if (route.pattern.len >= best_len) {
            best = route;
            best_len = route.pattern.len;
        }
    }
    return best;
}

fn stripHostPort(raw_host: []const u8) []const u8 {
    const host = std.mem.trim(u8, raw_host, " \t\r\n");
    if (host.len == 0) return host;

    if (host[0] == '[') {
        if (std.mem.indexOfScalar(u8, host, ']')) |close| {
            return host[0 .. close + 1];
        }
        return host;
    }

    if (std.mem.lastIndexOfScalar(u8, host, ':')) |colon| {
        if (std.mem.indexOfScalar(u8, host[0..colon], ':') == null) {
            return host[0..colon];
        }
    }

    return host;
}

fn asciiEndsWithIgnoreCase(value: []const u8, suffix: []const u8) bool {
    if (suffix.len > value.len) return false;
    return std.ascii.eqlIgnoreCase(value[value.len - suffix.len ..], suffix);
}

fn serverNameMatchScore(server_name: []const u8, host: []const u8) usize {
    const pattern = std.mem.trim(u8, server_name, " \t\r\n");
    if (pattern.len == 0 or host.len == 0) return 0;

    if (std.mem.eql(u8, pattern, "_") or std.ascii.eqlIgnoreCase(pattern, "default")) {
        return 1;
    }

    if (std.ascii.eqlIgnoreCase(pattern, host)) {
        return 1_000_000 + pattern.len;
    }

    if (std.mem.startsWith(u8, pattern, "*.")) {
        const suffix = pattern[1..];
        if (host.len > suffix.len and asciiEndsWithIgnoreCase(host, suffix)) {
            return 1000 + suffix.len;
        }
    }

    return 0;
}

fn findDomainForHost(cfg: *const ServerConfig, raw_host: []const u8) ?*const DomainConfig {
    const host = stripHostPort(raw_host);
    var best: ?*const DomainConfig = null;
    var best_score: usize = 0;

    for (cfg.domains.items) |*domain| {
        for (domain.server_names.items) |server_name| {
            const score = serverNameMatchScore(server_name, host);
            if (score > best_score) {
                best = domain;
                best_score = score;
            }
        }
    }

    return best;
}

fn findDomainForRequest(cfg: *const ServerConfig, headers: []const u8) ?*const DomainConfig {
    const host = findHeaderValue(headers, "Host") orelse return null;
    return findDomainForHost(cfg, host);
}

fn domainStaticDir(cfg: *const ServerConfig, domain: ?*const DomainConfig) []const u8 {
    if (domain) |d| {
        if (d.static_dir) |value| return value;
    }
    return cfg.static_dir;
}

fn domainServeStaticRoot(cfg: *const ServerConfig, domain: ?*const DomainConfig) bool {
    if (domain) |d| {
        if (d.serve_static_root) |value| return value;
    }
    return cfg.serve_static_root;
}

fn domainIndexFile(cfg: *const ServerConfig, domain: ?*const DomainConfig) []const u8 {
    if (domain) |d| {
        if (d.index_file) |value| return value;
    }
    return cfg.index_file;
}

fn domainPhpRoot(cfg: *const ServerConfig, domain: ?*const DomainConfig) []const u8 {
    if (domain) |d| {
        if (d.php_root) |value| return value;
    }
    return cfg.php_root;
}

fn domainPhpBinary(cfg: *const ServerConfig, domain: ?*const DomainConfig) []const u8 {
    if (domain) |d| {
        if (d.php_binary) |value| return value;
    }
    return cfg.php_binary;
}

fn domainPhpInfoPage(cfg: *const ServerConfig, domain: ?*const DomainConfig) bool {
    if (domain) |d| {
        if (d.php_info_page) |value| return value;
    }
    return cfg.php_info_page;
}

fn domainUpstream(cfg: *const ServerConfig, domain: ?*const DomainConfig) ?UpstreamPoolConfig {
    if (domain) |d| {
        if (d.upstream) |value| return value;
    }
    return cfg.upstream;
}

fn findDomainRedirectRule(domain: ?*const DomainConfig, path: []const u8) ?RedirectRule {
    if (domain) |d| {
        if (findRedirectRuleIn(d.redirects.items, path)) |rule| return rule;
    }
    return null;
}

fn findDomainRoute(domain: ?*const DomainConfig, path: []const u8) ?*const RouteConfig {
    if (domain) |d| {
        return findNamedRouteIn(d.routes.items, path);
    }
    return null;
}

fn routeFileRelativePath(allocator: std.mem.Allocator, route: *const RouteConfig, request_path: []const u8, index_file: []const u8) ![]const u8 {
    if (!route.strip_prefix) {
        return makeStaticPathFromRequest(allocator, request_path, index_file);
    }

    const raw_rel = switch (route.match_kind) {
        .exact => "",
        .prefix => if (request_path.len > route.pattern.len) request_path[route.pattern.len..] else "",
    };
    const rel = if (raw_rel.len > 0 and raw_rel[0] == '/') raw_rel[1..] else raw_rel;
    if (rel.len == 0) return allocator.dupe(u8, index_file);
    return allocator.dupe(u8, rel);
}

fn handleNamedRoute(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    domain: ?*const DomainConfig,
    route: *const RouteConfig,
    req: HttpRequest,
    close_connection: bool,
    is_head: bool,
    process_env: *const std.process.Environ.Map,
) !void {
    if (std.mem.eql(u8, req.method, "OPTIONS")) {
        const allow = switch (route.handler) {
            .static => "GET,HEAD,OPTIONS",
            .php => "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
            .proxy => "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
        };
        const allow_header = try std.fmt.allocPrint(allocator, "Allow: {s}\r\n", .{allow});
        defer allocator.free(allow_header);
        try sendResponseNoBodyWithConnectionAndHeaders(stream, 204, "No Content", "text/plain; charset=utf-8", 0, close_connection, allow_header);
        return;
    }

    switch (route.handler) {
        .static => {
            if (!(std.mem.eql(u8, req.method, "GET") or is_head)) {
                try sendMethodNotAllowedWithAllow(stream, allocator, "GET,HEAD,OPTIONS", close_connection);
                return;
            }
            const static_dir = route.static_dir orelse domainStaticDir(cfg, domain);
            const index_file = route.index_file orelse domainIndexFile(cfg, domain);
            const rel = try routeFileRelativePath(allocator, route, req.path, index_file);
            defer allocator.free(rel);
            try serveStatic(io, stream, allocator, static_dir, rel, req.headers, close_connection, is_head, cfg.max_static_file_bytes);
            return;
        },
        .php => {
            if (std.mem.eql(u8, req.path, "/test.php") and !(route.php_info_page orelse domainPhpInfoPage(cfg, domain))) {
                try sendNotFoundWithConnection(allocator, stream, close_connection);
                return;
            }
            const php_root = route.php_root orelse domainPhpRoot(cfg, domain);
            const php_binary = route.php_binary orelse domainPhpBinary(cfg, domain);
            const script_rel = try routeFileRelativePath(allocator, route, req.path, route.index_file orelse domainIndexFile(cfg, domain));
            defer allocator.free(script_rel);
            try handlePhpScript(io, stream, allocator, cfg, req, php_root, php_binary, script_rel, close_connection, is_head, process_env);
            return;
        },
        .proxy => {
            const maybe_pool = if (route.upstream) |pool| pool else domainUpstream(cfg, domain);
            const pool = maybe_pool orelse {
                try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "Route proxy upstream is not configured.", close_connection, false, null);
                return;
            };
            try forwardToUpstreamPool(stream, allocator, &pool, req, cfg.upstream_timeout_ms);
            return;
        },
    }
}

test "named routes prefer exact and longest prefix matches" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var cfg = ServerConfig{
        .host = "127.0.0.1",
        .port = 8080,
        .static_dir = "public",
        .serve_static_root = false,
        .index_file = "index.html",
        .php_root = "public",
        .php_binary = "php-cgi",
        .php_info_page = false,
        .upstream = null,
        .tls_enabled = false,
        .tls_cert = null,
        .tls_key = null,
        .tls_auto = false,
        .letsencrypt_email = null,
        .letsencrypt_domains = null,
        .letsencrypt_webroot = "public/.well-known/acme-challenge",
        .letsencrypt_certbot = "certbot",
        .letsencrypt_staging = false,
        .h2_upstream = null,
        .http3_enabled = false,
        .http3_port = 8443,
        .response_headers = .empty,
        .redirects = .empty,
        .routes = .empty,
        .domains = .empty,
        .max_request_bytes = DEFAULT_MAX_REQUEST_BYTES,
        .max_body_bytes = DEFAULT_MAX_BODY_BYTES,
        .max_static_file_bytes = DEFAULT_MAX_STATIC_FILE_BYTES,
        .max_requests_per_connection = DEFAULT_MAX_REQUESTS_PER_CONNECTION,
        .max_concurrent_connections = DEFAULT_MAX_CONCURRENT_CONNECTIONS,
        .worker_stack_size = DEFAULT_WORKER_STACK_BYTES,
        .read_header_timeout_ms = DEFAULT_READ_HEADER_TIMEOUT_MS,
        .read_body_timeout_ms = DEFAULT_READ_BODY_TIMEOUT_MS,
        .idle_timeout_ms = DEFAULT_IDLE_TIMEOUT_MS,
        .write_timeout_ms = DEFAULT_WRITE_TIMEOUT_MS,
        .upstream_timeout_ms = DEFAULT_UPSTREAM_TIMEOUT_MS,
        .graceful_shutdown_timeout_ms = DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_MS,
        .cloudflare_auto_deploy = false,
        .max_php_output_bytes = DEFAULT_MAX_PHP_OUTPUT_BYTES,
        .cloudflare_api_base = "https://api.cloudflare.com/client/v4",
        .cloudflare_token = null,
        .cloudflare_zone_id = null,
        .cloudflare_zone_name = null,
        .cloudflare_record_name = null,
        .cloudflare_record_type = "A",
        .cloudflare_record_content = null,
        .cloudflare_record_ttl = 300,
        .cloudflare_record_proxied = false,
        .cloudflare_record_comment = null,
    };

    try setRouteLine(&cfg, allocator, "assets /assets/* static");
    try setRouteLine(&cfg, allocator, "private /assets/private/* static");
    try setRouteLine(&cfg, allocator, "health /health proxy");

    try std.testing.expectEqualStrings("health", findNamedRoute(&cfg, "/health").?.name);
    try std.testing.expectEqualStrings("private", findNamedRoute(&cfg, "/assets/private/a.txt").?.name);
    try std.testing.expectEqualStrings("assets", findNamedRoute(&cfg, "/assets/hello.txt").?.name);
    try std.testing.expect(findNamedRoute(&cfg, "/missing") == null);

    const rel = try routeFileRelativePath(allocator, findNamedRoute(&cfg, "/assets/hello.txt").?, "/assets/hello.txt", "index.html");
    try std.testing.expectEqualStrings("hello.txt", rel);

    try setDomainLine(&cfg, allocator, "site");
    try appendServerNames(allocator, findDomainConfigMutable(&cfg, "site").?, "example.test *.example.test");
    try setDomainRouteLine(&cfg, allocator, "site", "site-assets /assets/* static");

    try setDomainLine(&cfg, allocator, "fallback");
    try appendServerNames(allocator, findDomainConfigMutable(&cfg, "fallback").?, "_");

    try std.testing.expectEqualStrings("site", findDomainForHost(&cfg, "example.test:8080").?.name);
    try std.testing.expectEqualStrings("site", findDomainForHost(&cfg, "www.example.test").?.name);
    try std.testing.expectEqualStrings("fallback", findDomainForHost(&cfg, "other.test").?.name);
    try std.testing.expectEqualStrings("site-assets", findDomainRoute(findDomainForHost(&cfg, "example.test"), "/assets/domain.txt").?.name);
    try std.testing.expectEqualStrings("assets", findNamedRoute(&cfg, "/assets/global.txt").?.name);
}

test "upstream pools parse multiple targets and rotate selection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000/api, http://127.0.0.1:9001");

    try std.testing.expectEqual(@as(usize, 2), pool.targets.items.len);
    try std.testing.expectEqualStrings("127.0.0.1", pool.targets.items[0].host);
    try std.testing.expectEqual(@as(u16, 9000), pool.targets.items[0].port);
    try std.testing.expectEqualStrings("/api", pool.targets.items[0].base_path);
    try std.testing.expectEqual(@as(u16, 9001), pool.targets.items[1].port);

    const first = selectUpstream(&pool).?;
    const second = selectUpstream(&pool).?;
    try std.testing.expect(first.port != second.port);
}

fn routeRequest(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    process_env: *const std.process.Environ.Map,
) !void {
    // Route locally first, then fall back to proxying so known endpoints stay predictable.
    current_response_headers = cfg.response_headers.items;
    defer current_response_headers = &.{};

    const should_close = req.close_connection;
    const method = req.method;
    const is_head = std.mem.eql(u8, method, "HEAD");
    const domain = findDomainForRequest(cfg, req.headers);

    if (findDomainRedirectRule(domain, req.path)) |redirect| {
        try sendConfiguredRedirect(stream, allocator, redirect, req, should_close, is_head);
        return;
    }

    if (findRedirectRule(cfg, req.path)) |redirect| {
        try sendConfiguredRedirect(stream, allocator, redirect, req, should_close, is_head);
        return;
    }

    if (findDomainRoute(domain, req.path)) |route| {
        try handleNamedRoute(io, stream, allocator, cfg, domain, route, req, should_close, is_head, process_env);
        return;
    }

    if (findNamedRoute(cfg, req.path)) |route| {
        try handleNamedRoute(io, stream, allocator, cfg, domain, route, req, should_close, is_head, process_env);
        return;
    }

    if (std.mem.eql(u8, method, "GET") or is_head) {
        if (std.mem.eql(u8, req.path, "/favicon.svg") or std.mem.eql(u8, req.path, "/icon.svg")) {
            try sendServerIcon(stream, should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/")) {
            const body =
                \\<!doctype html>
                \\<html lang="en">
                \\<head>
                \\<meta charset="utf-8">
                \\<meta name="viewport" content="width=device-width, initial-scale=1">
                \\<title>Layerline</title>
                \\<link rel="icon" type="image/svg+xml" href="/favicon.svg">
                \\<style>
                \\  * { box-sizing: border-box; }
                \\  body {
                \\    margin: 0;
                \\    min-height: 100vh;
                \\    overflow-x: hidden;
                \\    color: #11110f;
                \\    background:
                \\      radial-gradient(circle at 16% -12%, rgba(255,255,255,.92), transparent 28%),
                \\      linear-gradient(180deg, #f7f4ed 0%, #f0ece2 46%, #e9e3d6 100%);
                \\    font: 14px/1.6 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                \\  }
                \\  body::before {
                \\    content: "";
                \\    position: fixed;
                \\    inset: 0;
                \\    z-index: -2;
                \\    background:
                \\      linear-gradient(rgba(15,15,12,.05) 1px, transparent 1px),
                \\      linear-gradient(90deg, rgba(15,15,12,.05) 1px, transparent 1px);
                \\    background-size: 64px 64px;
                \\  }
                \\  main {
                \\    min-height: 100vh;
                \\    display: grid;
                \\    grid-template-columns: minmax(0, 1.05fr) minmax(280px, .95fr);
                \\    align-items: center;
                \\    gap: clamp(28px, 6vw, 90px);
                \\    max-width: 1280px;
                \\    margin: 0 auto;
                \\    padding: clamp(28px, 6vw, 72px);
                \\  }
                \\  .brand {
                \\    display: inline-flex;
                \\    align-items: center;
                \\    gap: 14px;
                \\    margin-bottom: 28px;
                \\    color: inherit;
                \\    text-decoration: none;
                \\  }
                \\  .brand img {
                \\    width: 54px;
                \\    height: 54px;
                \\    border-radius: 16px;
                \\    box-shadow: 0 22px 48px rgba(17,17,15,.1);
                \\  }
                \\  .brand strong {
                \\    display: block;
                \\    font-size: 18px;
                \\    line-height: 1.1;
                \\    letter-spacing: 0;
                \\  }
                \\  .brand small {
                \\    display: block;
                \\    color: #6b6c65;
                \\    font-size: 12px;
                \\    line-height: 1.2;
                \\  }
                \\  h1 {
                \\    margin: 0;
                \\    max-width: 8.5ch;
                \\    font-size: clamp(72px, 11vw, 156px);
                \\    line-height: .82;
                \\    letter-spacing: 0;
                \\  }
                \\  .eyebrow {
                \\    display: inline-flex;
                \\    margin: 0 0 16px;
                \\    color: #77786f;
                \\    font: 12px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace;
                \\    text-transform: uppercase;
                \\  }
                \\  p {
                \\    max-width: 46ch;
                \\    margin: 24px 0 0;
                \\    color: #5d5e58;
                \\    font-size: clamp(16px, 1.4vw, 20px);
                \\  }
                \\  .actions {
                \\    display: flex;
                \\    flex-wrap: wrap;
                \\    gap: 10px;
                \\    margin-top: 30px;
                \\  }
                \\  a.button {
                \\    display: inline-flex;
                \\    min-height: 42px;
                \\    align-items: center;
                \\    border: 1px solid rgba(15,15,12,.14);
                \\    border-radius: 12px;
                \\    padding: 9px 13px;
                \\    background: rgba(255,255,255,.5);
                \\    color: #11110f;
                \\    text-decoration: none;
                \\  }
                \\  a.button.primary {
                \\    border-color: #11110f;
                \\    background: #11110f;
                \\    color: #fbfaf6;
                \\    box-shadow: 0 18px 36px rgba(17,17,15,.16);
                \\  }
                \\  .surface {
                \\    position: relative;
                \\    min-height: 470px;
                \\    border: 1px solid rgba(17,17,15,.16);
                \\    border-radius: 28px;
                \\    overflow: hidden;
                \\    background: rgba(251,250,246,.72);
                \\    box-shadow: 0 44px 110px rgba(38,34,24,.14);
                \\    backdrop-filter: blur(18px);
                \\  }
                \\  .surface::before {
                \\    content: "";
                \\    position: absolute;
                \\    inset: 0;
                \\    background:
                \\      linear-gradient(rgba(17,17,15,.08) 1px, transparent 1px),
                \\      linear-gradient(90deg, rgba(17,17,15,.08) 1px, transparent 1px);
                \\    background-size: 44px 44px;
                \\  }
                \\  .rail {
                \\    position: absolute;
                \\    left: 28px;
                \\    right: 28px;
                \\    top: 28px;
                \\    display: flex;
                \\    justify-content: space-between;
                \\    gap: 16px;
                \\    padding: 12px 14px;
                \\    border: 1px solid rgba(17,17,15,.14);
                \\    border-radius: 999px;
                \\    background: rgba(251,250,246,.86);
                \\    color: #8b8c84;
                \\    font: 11px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace;
                \\    letter-spacing: .08em;
                \\    text-transform: uppercase;
                \\  }
                \\  .route {
                \\    position: absolute;
                \\    left: 18%;
                \\    right: 18%;
                \\    top: 48%;
                \\    height: 2px;
                \\    background: repeating-linear-gradient(90deg, rgba(17,17,15,.5) 0 12px, transparent 12px 22px);
                \\    transform: rotate(-9deg);
                \\  }
                \\  .packet {
                \\    position: absolute;
                \\    left: 14%;
                \\    top: 45%;
                \\    width: 54px;
                \\    height: 28px;
                \\    border: 1px solid rgba(17,17,15,.28);
                \\    border-radius: 999px;
                \\    background: #11110f;
                \\    box-shadow: 0 18px 40px rgba(17,17,15,.2);
                \\    animation: packet-run 4.8s ease-in-out infinite;
                \\  }
                \\  .h3mark {
                \\    position: absolute;
                \\    left: 34px;
                \\    bottom: 118px;
                \\    font-size: clamp(62px, 10vw, 116px);
                \\    line-height: .82;
                \\    letter-spacing: 0;
                \\    color: rgba(17,17,15,.11);
                \\  }
                \\  .caps {
                \\    position: absolute;
                \\    left: 28px;
                \\    right: 28px;
                \\    top: 100px;
                \\    display: grid;
                \\    grid-template-columns: repeat(2, minmax(0, 1fr));
                \\    gap: 10px;
                \\  }
                \\  .cap {
                \\    min-height: 48px;
                \\    padding: 10px 11px;
                \\    border-top: 1px solid rgba(17,17,15,.14);
                \\    background: rgba(251,250,246,.52);
                \\    color: #11110f;
                \\    font: 12px/1.25 ui-monospace, SFMono-Regular, Menlo, monospace;
                \\    transition: background .18s ease, transform .18s ease;
                \\  }
                \\  .cap:hover {
                \\    background: rgba(255,255,255,.76);
                \\    transform: translateY(-2px);
                \\  }
                \\  .node {
                \\    position: absolute;
                \\    width: 12px;
                \\    height: 12px;
                \\    border-radius: 999px;
                \\    background: #11110f;
                \\    box-shadow: 0 0 0 9px rgba(17,17,15,.08);
                \\    animation: node-pulse 3.2s ease-in-out infinite;
                \\  }
                \\  .n1 { left: 18%; top: 34%; }
                \\  .n2 { right: 22%; top: 44%; }
                \\  .n3 { left: 46%; bottom: 24%; }
                \\  .footer {
                \\    position: absolute;
                \\    left: 28px;
                \\    right: 28px;
                \\    bottom: 28px;
                \\    display: grid;
                \\    grid-template-columns: 1fr auto;
                \\    gap: 18px;
                \\    align-items: end;
                \\    padding: 18px;
                \\    border-top: 1px solid rgba(17,17,15,.12);
                \\    background: rgba(251,250,246,.78);
                \\  }
                \\  .footer strong {
                \\    display: block;
                \\    margin-bottom: 5px;
                \\    font-size: 18px;
                \\  }
                \\  .footer span {
                \\    color: #5d5e58;
                \\    font-size: 13px;
                \\  }
                \\  .status {
                \\    font-size: 48px;
                \\    line-height: .9;
                \\  }
                \\  @keyframes packet-run {
                \\    0%, 100% { transform: translateX(0) rotate(-9deg); opacity: .68; }
                \\    50% { transform: translateX(230px) rotate(-9deg); opacity: 1; }
                \\  }
                \\  @keyframes node-pulse {
                \\    0%, 100% { box-shadow: 0 0 0 8px rgba(17,17,15,.08); }
                \\    50% { box-shadow: 0 0 0 15px rgba(17,17,15,.04); }
                \\  }
                \\  @media (max-width: 820px) {
                \\    main { grid-template-columns: 1fr; padding: 24px; }
                \\    h1 { font-size: clamp(64px, 22vw, 104px); }
                \\    .surface { min-height: 420px; }
                \\    .route { top: 60%; }
                \\    .packet { top: 56%; animation: none; transform: rotate(-9deg); }
                \\    .h3mark { bottom: 138px; font-size: 70px; }
                \\    .caps { grid-template-columns: 1fr 1fr; }
                \\  }
                \\</style>
                \\</head>
                \\<body>
                \\<main>
                \\  <section>
                \\    <a class="brand" href="/" aria-label="Layerline home">
                \\      <img src="/favicon.svg" alt="">
                \\      <span><strong>Layerline</strong><small>Modern web server</small></span>
                \\    </a>
                \\    <div class="eyebrow">native QUIC path active</div>
                \\    <h1>Layerline</h1>
                \\    <p>A Zig web server with HTTP/3 in the binary: QUIC v1, TLS 1.3, 1-RTT packet protection, QPACK headers, and bounded request handling.</p>
                \\    <div class="actions">
                \\      <a class="button primary" href="/health">Health</a>
                \\      <a class="button" href="/time">Time</a>
                \\      <a class="button" href="/api/echo?msg=hello">Echo</a>
                \\      <a class="button" href="/static/hello.txt">Static</a>
                \\      <a class="button" href="/favicon.svg">Icon</a>
                \\    </div>
                \\  </section>
                \\  <aside class="surface" aria-hidden="true">
                \\    <div class="rail"><span>QUIC/TLS 1.3</span><span>HTTP/3</span></div>
                \\    <div class="caps"><div class="cap">QUIC v1 Initial</div><div class="cap">TLS 1.3 Finished</div><div class="cap">1-RTT packets</div><div class="cap">QPACK response</div></div>
                \\    <div class="h3mark">HTTP/3</div>
                \\    <div class="route"></div>
                \\    <div class="packet"></div>
                \\    <div class="node n1"></div>
                \\    <div class="node n2"></div>
                \\    <div class="node n3"></div>
                \\    <div class="footer"><div><strong>1-RTT ready</strong><span>native HTTP/3 default page path is live</span></div><div class="status">H3</div></div>
                \\  </aside>
                \\</main>
                \\</body>
                \\</html>
            ;
            try sendResponseForMethod(stream, 200, "OK", "text/html; charset=utf-8", body, should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/health")) {
            try sendResponseForMethod(stream, 200, "OK", "text/plain; charset=utf-8", "ok\n", should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/metrics")) {
            try sendMetrics(stream, allocator, should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/time")) {
            var ts_buf: [64]u8 = undefined;
            const ts = try std.fmt.bufPrint(&ts_buf, "{{\"time\":{}}}\n", .{std.Io.Timestamp.now(io, .real).toSeconds()});
            try sendResponseForMethod(stream, 200, "OK", "application/json; charset=utf-8", ts, should_close, is_head);
            return;
        }

        if (std.mem.startsWith(u8, req.path, "/.well-known/acme-challenge/")) {
            const token = req.path["/.well-known/acme-challenge/".len..];
            try serveAcmeChallenge(io, stream, allocator, cfg.letsencrypt_webroot, token, should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/api/echo")) {
            if (findQueryValue(req.query, "msg")) |msg| {
                const payload = try std.fmt.allocPrint(allocator, "{{\"msg\":\"{s}\"}}\n", .{msg});
                defer allocator.free(payload);
                try sendResponseForMethod(stream, 200, "OK", "application/json; charset=utf-8", payload, should_close, is_head);
            } else {
                try sendResponseForMethod(stream, 200, "OK", "text/plain; charset=utf-8", "try /api/echo?msg=your-text\n", should_close, is_head);
            }
            return;
        }

        if (std.mem.eql(u8, req.path, "/test.php") and !domainPhpInfoPage(cfg, domain)) {
            try sendNotFoundWithConnection(allocator, stream, should_close);
            return;
        }

        if (std.mem.endsWith(u8, req.path, ".php") or std.mem.startsWith(u8, req.path, "/php/")) {
            const rel_path = if (req.path.len > 0 and req.path[0] == '/') req.path[1..] else req.path;
            try handlePhpScript(io, stream, allocator, cfg, req, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), rel_path, should_close, is_head, process_env);
            return;
        }

        if (std.mem.startsWith(u8, req.path, "/static/")) {
            const rel = req.path["/static/".len..];
            try serveStatic(io, stream, allocator, domainStaticDir(cfg, domain), rel, req.headers, should_close, is_head, cfg.max_static_file_bytes);
            return;
        }

        if (domainServeStaticRoot(cfg, domain) and
            !std.mem.startsWith(u8, req.path, "/api/") and
            !std.mem.startsWith(u8, req.path, "/php/") and
            !std.mem.eql(u8, req.path, "/health") and
            !std.mem.eql(u8, req.path, "/time") and
            !std.mem.eql(u8, req.path, "/"))
        {
            const static_dir = domainStaticDir(cfg, domain);
            const rel = try makeStaticPathFromRequest(allocator, req.path, domainIndexFile(cfg, domain));
            defer allocator.free(rel);

            const candidate_path = try std.fs.path.join(allocator, &.{ static_dir, rel });
            defer allocator.free(candidate_path);

            var file_exists = false;
            if (std.Io.Dir.cwd().statFile(io, candidate_path, .{})) |stat| {
                if (stat.kind == .file) {
                    file_exists = true;
                }
            } else |_| {}

            if (file_exists) {
                try serveStatic(io, stream, allocator, static_dir, rel, req.headers, should_close, is_head, cfg.max_static_file_bytes);
                return;
            }
        }

        if (domainUpstream(cfg, domain)) |pool| {
            try forwardToUpstreamPool(stream, allocator, &pool, req, cfg.upstream_timeout_ms);
            return;
        }

        try sendNotFoundWithConnection(allocator, stream, should_close);
        return;
    }

    if (std.mem.eql(u8, method, "POST")) {
        if (std.mem.eql(u8, req.path, "/test.php") and !domainPhpInfoPage(cfg, domain)) {
            try sendNotFoundWithConnection(allocator, stream, should_close);
            return;
        }

        if (std.mem.endsWith(u8, req.path, ".php")) {
            const rel_path = if (req.path.len > 0 and req.path[0] == '/') req.path[1..] else req.path;
            try handlePhpScript(io, stream, allocator, cfg, req, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), rel_path, should_close, false, process_env);
            return;
        }

        if (std.mem.eql(u8, req.path, "/api/echo")) {
            try sendResponseWithConnection(stream, 200, "OK", "text/plain; charset=utf-8", req.body, should_close);
            return;
        }

        if (domainUpstream(cfg, domain)) |pool| {
            try forwardToUpstreamPool(stream, allocator, &pool, req, cfg.upstream_timeout_ms);
            return;
        }

        try sendNotFoundWithConnection(allocator, stream, should_close);
        return;
    }

    if (std.mem.eql(u8, method, "OPTIONS")) {
        const allow = "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS";
        const allow_header = try std.fmt.allocPrint(allocator, "Allow: {s}\r\n", .{allow});
        defer allocator.free(allow_header);
        try sendResponseNoBodyWithConnectionAndHeaders(stream, 204, "No Content", "text/plain; charset=utf-8", 0, should_close, allow_header);
        return;
    }

    if (std.mem.eql(u8, method, "PUT") or std.mem.eql(u8, method, "PATCH") or std.mem.eql(u8, method, "DELETE")) {
        if (domainUpstream(cfg, domain)) |pool| {
            try forwardToUpstreamPool(stream, allocator, &pool, req, cfg.upstream_timeout_ms);
            return;
        }
        try sendMethodNotAllowedWithAllow(stream, allocator, "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS", should_close);
        return;
    }

    try sendNotImplemented(stream, allocator, should_close);
}

fn handleConnection(
    io: std.Io,
    stream: std.Io.net.Stream,
    cfg: *const ServerConfig,
    allocator: std.mem.Allocator,
    process_env: *const std.process.Environ.Map,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var handled_requests: usize = 0;
    setStreamWriteTimeout(stream, cfg.write_timeout_ms) catch |err| {
        std.debug.print("Socket write timeout setup failed: {}\n", .{err});
    };

    // Keep one connection worker alive across keep-alive requests.
    // Each request still gets a hard cap before the socket is closed.
    while (true) {
        if (cfg.max_requests_per_connection > 0 and handled_requests >= cfg.max_requests_per_connection) {
            return;
        }

        _ = arena.reset(.retain_capacity);
        const req_alloc = arena.allocator();
        const next_read_timeout = if (handled_requests == 0) cfg.read_header_timeout_ms else cfg.idle_timeout_ms;
        setStreamReadTimeout(stream, next_read_timeout) catch |err| {
            std.debug.print("Socket read timeout setup failed: {}\n", .{err});
        };
        var prefill_buf: [64]u8 = undefined;
        const prefill_len = streamRead(stream, &prefill_buf) catch |err| switch (err) {
            error.RequestTimeout => {
                if (handled_requests > 0) return;
                try sendCoolErrorWithConnection(
                    stream,
                    req_alloc,
                    408,
                    "Request Timeout",
                    "No request bytes arrived before the header timeout.",
                    true,
                    false,
                    null,
                );
                return;
            },
            else => |e| return e,
        };
        if (prefill_len == 0) return;
        const prefill = prefill_buf[0..prefill_len];

        if (isLikelyHttp2Preface(prefill)) {
            try handleHttp2Preface(stream, req_alloc, cfg, prefill);
            return;
        }

        if (isHttp3OverTcpProbe(prefill)) {
            try sendCoolErrorWithConnection(
                stream,
                req_alloc,
                426,
                "Upgrade Required",
                "HTTP/3 is a QUIC transport and cannot be served directly over this TCP socket.",
                true,
                false,
                null,
            );
            return;
        }

        setStreamReadTimeout(stream, cfg.read_header_timeout_ms) catch |err| {
            std.debug.print("Socket header timeout setup failed: {}\n", .{err});
        };
        var req = parseRequest(stream, req_alloc, cfg.max_request_bytes, cfg.max_body_bytes, cfg.read_body_timeout_ms, prefill) catch |err| {
            if (err != error.ConnectionClosed) server_metrics.requestParseError();
            switch (err) {
                error.ConnectionClosed => return,
                error.RequestTimeout => {
                    try sendCoolErrorWithConnection(
                        stream,
                        req_alloc,
                        408,
                        "Request Timeout",
                        "The request took too long to read.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
                error.RequestTooLarge => {
                    try sendCoolErrorWithConnection(
                        stream,
                        req_alloc,
                        413,
                        "Payload Too Large",
                        "Request headers are too large.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
                error.PayloadTooLarge => {
                    try sendCoolErrorWithConnection(
                        stream,
                        req_alloc,
                        413,
                        "Payload Too Large",
                        "Request body exceeds configured limit.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
                error.InvalidContentLength => {
                    try sendBadRequest(req_alloc, stream, "Invalid Content-Length header.");
                    return;
                },
                error.UnsupportedTransferEncoding => {
                    try sendCoolErrorWithConnection(
                        stream,
                        req_alloc,
                        501,
                        "Not Implemented",
                        "Only plain Content-Length and chunked request bodies are supported.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
                error.ExpectationFailed => {
                    try sendCoolErrorWithConnection(
                        stream,
                        req_alloc,
                        417,
                        "Expectation Failed",
                        "Only Expect: 100-continue is supported.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
                error.MalformedRequest => {
                    try sendBadRequest(req_alloc, stream, "Malformed request.");
                    return;
                },
                error.BadRequest => {
                    try sendBadRequest(req_alloc, stream, "Bad request.");
                    return;
                },
                error.MissingHostHeader => {
                    try sendBadRequest(req_alloc, stream, "Missing Host header.");
                    return;
                },
                error.UnsupportedHttpVersion => {
                    try sendCoolErrorWithConnection(
                        stream,
                        req_alloc,
                        505,
                        "HTTP Version Not Supported",
                        "This process only serves HTTP/1.x requests directly. Configure TLS reverse proxy fronting for h2/h3 and set --h2-upstream for HTTP/2 cleartext passthrough.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
                else => {
                    try sendCoolErrorWithConnection(
                        stream,
                        req_alloc,
                        500,
                        "Internal Server Error",
                        "Internal server error while parsing request.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
            }
        };
        handled_requests += 1;
        server_metrics.requestStarted();
        if (cfg.max_requests_per_connection > 0 and handled_requests >= cfg.max_requests_per_connection) {
            req.close_connection = true;
        }

        std.debug.print("{s} {s}\n", .{ req.method, req.path });
        routeRequest(io, stream, req_alloc, cfg, req, process_env) catch |err| switch (err) {
            error.CloseConnection => break,
            else => {
                server_metrics.routeError();
                return err;
            },
        };

        if (req.close_connection) break;
    }
}

fn serveConnectionTask(
    io: std.Io,
    stream: std.Io.net.Stream,
    cfg: *const ServerConfig,
    allocator: std.mem.Allocator,
    state: *ConcurrencyState,
    process_env: *const std.process.Environ.Map,
) void {
    bindThreadIo(io);

    // One worker thread owns one stream; always release the slot and close stream.
    defer {
        state.release();
        streamClose(stream);
    }

    handleConnection(io, stream, cfg, allocator, process_env) catch |err| {
        std.debug.print("Connection handler error: {}\n", .{err});
    };
}

const Http3InitialAssembly = struct {
    has_scid: bool = false,
    scid: quic_native.ConnectionId = .{},
    has_original_dcid: bool = false,
    original_dcid: quic_native.ConnectionId = .{},
    has_server_cid: bool = false,
    server_cid: quic_native.ConnectionId = .{},
    crypto: std.ArrayListUnmanaged(u8) = .empty,
    server_flight_sent: bool = false,
    client_handshake_crypto: std.ArrayListUnmanaged(u8) = .empty,
    has_handshake_keys: bool = false,
    client_handshake_keys: quic_native.PacketKeys = undefined,
    server_handshake_keys: quic_native.PacketKeys = undefined,
    traffic: tls13_native.TrafficSecrets = undefined,
    application_transcript_hash: [32]u8 = undefined,
    handshake_done: bool = false,
    has_application_keys: bool = false,
    client_application_keys: quic_native.PacketKeys = undefined,
    server_application_keys: quic_native.PacketKeys = undefined,
    server_handshake_packets: h3_state.PacketNumberSpace(16) = h3_state.PacketNumberSpace(16).init(),
    server_application_packets: h3_state.PacketNumberSpace(64) = h3_state.PacketNumberSpace(64).init(),
    h3_response_sent: bool = false,

    fn matches(self: *const Http3InitialAssembly, scid: []const u8) bool {
        return self.has_scid and std.mem.eql(u8, self.scid.slice(), scid);
    }

    fn matchesServerCid(self: *const Http3InitialAssembly, dcid: []const u8) bool {
        return self.has_server_cid and std.mem.eql(u8, self.server_cid.slice(), dcid);
    }

    fn deinit(self: *Http3InitialAssembly, allocator: std.mem.Allocator) void {
        self.crypto.deinit(allocator);
        self.client_handshake_crypto.deinit(allocator);
        self.* = .{};
    }

    fn reset(self: *Http3InitialAssembly, allocator: std.mem.Allocator, original_dcid: []const u8, scid: []const u8) !void {
        self.crypto.clearRetainingCapacity();
        self.client_handshake_crypto.clearRetainingCapacity();
        self.original_dcid = try quic_native.ConnectionId.init(original_dcid);
        self.has_original_dcid = true;
        self.scid = try quic_native.ConnectionId.init(scid);
        self.has_scid = true;
        self.has_server_cid = false;
        self.server_flight_sent = false;
        self.has_handshake_keys = false;
        self.handshake_done = false;
        self.has_application_keys = false;
        self.server_handshake_packets = h3_state.PacketNumberSpace(16).init();
        self.server_application_packets = h3_state.PacketNumberSpace(64).init();
        self.h3_response_sent = false;
        _ = allocator;
    }

    fn rememberServerCid(self: *Http3InitialAssembly, server_cid: []const u8) !void {
        self.server_cid = try quic_native.ConnectionId.init(server_cid);
        self.has_server_cid = true;
    }
};

const Http3ConnectionTable = struct {
    allocator: std.mem.Allocator,
    entries: []Http3InitialAssembly,
    active: []bool,
    active_count: usize = 0,

    fn init(allocator: std.mem.Allocator, capacity: usize) !Http3ConnectionTable {
        const entries = try allocator.alloc(Http3InitialAssembly, capacity);
        errdefer allocator.free(entries);
        const active = try allocator.alloc(bool, capacity);
        @memset(active, false);
        return .{
            .allocator = allocator,
            .entries = entries,
            .active = active,
        };
    }

    fn deinit(self: *Http3ConnectionTable) void {
        for (self.entries, self.active) |*entry, is_active| {
            if (is_active) entry.deinit(self.allocator);
        }
        self.allocator.free(self.entries);
        self.allocator.free(self.active);
        self.* = undefined;
    }

    fn findByClientScid(self: *Http3ConnectionTable, scid: []const u8) ?*Http3InitialAssembly {
        for (self.entries, self.active) |*entry, is_active| {
            if (is_active and entry.matches(scid)) return entry;
        }
        return null;
    }

    fn findByServerCid(self: *Http3ConnectionTable, dcid: []const u8) ?*Http3InitialAssembly {
        for (self.entries, self.active) |*entry, is_active| {
            if (is_active and entry.matchesServerCid(dcid)) return entry;
        }
        return null;
    }

    fn findByShortPacketDcid(self: *Http3ConnectionTable, packet: []const u8) ?*Http3InitialAssembly {
        if (packet.len <= 1) return null;
        for (self.entries, self.active) |*entry, is_active| {
            if (!is_active or !entry.has_server_cid) continue;
            const cid = entry.server_cid.slice();
            if (packet.len >= 1 + cid.len and std.mem.eql(u8, packet[1 .. 1 + cid.len], cid)) return entry;
        }
        return null;
    }

    fn acquire(self: *Http3ConnectionTable) !*Http3InitialAssembly {
        for (self.active, 0..) |is_active, i| {
            if (!is_active) {
                self.entries[i] = .{};
                self.active[i] = true;
                self.active_count += 1;
                return &self.entries[i];
            }
        }
        return error.Http3ConnectionCapacityExceeded;
    }
};

fn packetKeysFromTls(keys: tls13_native.QuicPacketKeys) quic_native.PacketKeys {
    return .{ .key = keys.key, .iv = keys.iv, .hp = keys.hp };
}

fn findTlsFinishedVerifyData(handshake_messages: []const u8) !?[32]u8 {
    var offset: usize = 0;
    while (offset < handshake_messages.len) {
        if (handshake_messages.len < offset + 4) return error.Truncated;
        const kind = handshake_messages[offset];
        const len = (@as(usize, handshake_messages[offset + 1]) << 16) |
            (@as(usize, handshake_messages[offset + 2]) << 8) |
            @as(usize, handshake_messages[offset + 3]);
        offset += 4;
        if (handshake_messages.len < offset + len) return error.Truncated;
        if (kind == 0x14) {
            if (len != 32) return error.InvalidFinished;
            return handshake_messages[offset..][0..32].*;
        }
        offset += len;
    }
    return null;
}

fn skipAckFrame(plaintext: []const u8, offset: *usize, with_ecn: bool) !void {
    const largest = try h3_native.decodeVarInt(plaintext[offset.*..]);
    offset.* += largest.len;
    const delay = try h3_native.decodeVarInt(plaintext[offset.*..]);
    offset.* += delay.len;
    const range_count = try h3_native.decodeVarInt(plaintext[offset.*..]);
    offset.* += range_count.len;
    const first_range = try h3_native.decodeVarInt(plaintext[offset.*..]);
    offset.* += first_range.len;
    var i: u64 = 0;
    while (i < range_count.value) : (i += 1) {
        const gap = try h3_native.decodeVarInt(plaintext[offset.*..]);
        offset.* += gap.len;
        const range = try h3_native.decodeVarInt(plaintext[offset.*..]);
        offset.* += range.len;
    }
    if (with_ecn) {
        const ect0 = try h3_native.decodeVarInt(plaintext[offset.*..]);
        offset.* += ect0.len;
        const ect1 = try h3_native.decodeVarInt(plaintext[offset.*..]);
        offset.* += ect1.len;
        const ce = try h3_native.decodeVarInt(plaintext[offset.*..]);
        offset.* += ce.len;
    }
}

fn findRequestStreamId(plaintext: []const u8) !?u64 {
    var offset: usize = 0;
    while (offset < plaintext.len) {
        const frame_type_vi = try h3_native.decodeVarInt(plaintext[offset..]);
        offset += frame_type_vi.len;
        const frame_type = frame_type_vi.value;

        switch (frame_type) {
            0x00, 0x01, 0x1e => {},
            0x02 => try skipAckFrame(plaintext, &offset, false),
            0x03 => try skipAckFrame(plaintext, &offset, true),
            0x06 => {
                const crypto_offset = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += crypto_offset.len;
                const len = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += len.len + @as(usize, @intCast(len.value));
                if (offset > plaintext.len) return error.Truncated;
            },
            0x08...0x0f => {
                const stream_id = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += stream_id.len;
                if ((frame_type & 0x04) != 0) {
                    const stream_offset = try h3_native.decodeVarInt(plaintext[offset..]);
                    offset += stream_offset.len;
                }
                const data_len = if ((frame_type & 0x02) != 0) len: {
                    const len_vi = try h3_native.decodeVarInt(plaintext[offset..]);
                    offset += len_vi.len;
                    break :len @as(usize, @intCast(len_vi.value));
                } else plaintext.len - offset;
                if (plaintext.len < offset + data_len) return error.Truncated;
                if ((stream_id.value & 0x03) == 0) return stream_id.value;
                offset += data_len;
            },
            0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19 => {
                const ignored = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += ignored.len;
            },
            0x11, 0x15 => {
                const stream_id = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += stream_id.len;
                const value = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += value.len;
            },
            0x18 => {
                const sequence = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += sequence.len;
                const retire_prior = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += retire_prior.len;
                if (plaintext.len < offset + 1) return error.Truncated;
                const cid_len = plaintext[offset];
                offset += 1;
                if (plaintext.len < offset + cid_len + 16) return error.Truncated;
                offset += cid_len + 16;
            },
            0x1a, 0x1b => {
                if (plaintext.len < offset + 8) return error.Truncated;
                offset += 8;
            },
            0x1c, 0x1d => {
                const error_code = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += error_code.len;
                if (frame_type == 0x1c) {
                    const failed_frame = try h3_native.decodeVarInt(plaintext[offset..]);
                    offset += failed_frame.len;
                }
                const reason_len = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += reason_len.len + @as(usize, @intCast(reason_len.value));
                if (offset > plaintext.len) return error.Truncated;
            },
            else => return error.UnsupportedFrame,
        }
    }

    return null;
}

fn buildHttp3ControlStreamData(allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);

    var stream_type_buf: [8]u8 = undefined;
    const stream_type_len = try h3_native.encodeVarInt(&stream_type_buf, 0x00);
    try out.appendSlice(allocator, stream_type_buf[0..stream_type_len]);

    var settings_buf: [16]u8 = undefined;
    const settings_len = try h3_native.encodeFrameHeader(&settings_buf, @intFromEnum(h3_native.FrameType.settings), 0);
    try out.appendSlice(allocator, settings_buf[0..settings_len]);

    return out.toOwnedSlice(allocator);
}

fn buildHttp3ResponseData(allocator: std.mem.Allocator, head: http_response.ResponseHead, body: []const u8) ![]u8 {
    var status_buf: [8]u8 = undefined;
    const status = try std.fmt.bufPrint(&status_buf, "{d}", .{head.status_code});
    var length_buf: [32]u8 = undefined;
    const content_length = try std.fmt.bufPrint(&length_buf, "{d}", .{head.content_length});
    const headers = [_]h3_native.Header{
        .{ .name = ":status", .value = status },
        .{ .name = "server", .value = head.server },
        .{ .name = "content-type", .value = head.content_type },
        .{ .name = "content-length", .value = content_length },
    };

    const headers_frame = try h3_native.buildHeadersFrame(allocator, &headers);
    defer allocator.free(headers_frame);
    const data_frame = try h3_native.buildDataFrame(allocator, body);
    defer allocator.free(data_frame);

    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, headers_frame);
    try out.appendSlice(allocator, data_frame);
    return out.toOwnedSlice(allocator);
}

fn buildHttp3DefaultResponseData(allocator: std.mem.Allocator) ![]u8 {
    const body =
        \\<!doctype html>
        \\<html lang="en">
        \\<head>
        \\<meta charset="utf-8">
        \\<meta name="viewport" content="width=device-width, initial-scale=1">
        \\<title>Layerline</title>
        \\<style>
        \\body{margin:0;min-height:100vh;background:linear-gradient(180deg,#f7f4ed,#e9e3d6);color:#11110f;font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
        \\main{min-height:100vh;display:grid;grid-template-columns:minmax(0,1fr) minmax(260px,.7fr);gap:48px;align-items:center;padding:48px}
        \\section{max-width:820px}
        \\h1{margin:0;font-size:clamp(68px,14vw,148px);line-height:.82;letter-spacing:0}
        \\p{max-width:48ch;color:#5d5e58;font-size:20px}
        \\code,.tag{font:14px ui-monospace,SFMono-Regular,Menlo,monospace}
        \\.tag{display:inline-block;margin:0 0 18px;color:#77786f;text-transform:uppercase}
        \\ul{display:grid;gap:12px;margin:0;padding:0;list-style:none}
        \\li{border-top:1px solid rgba(17,17,15,.16);padding-top:12px;font:14px ui-monospace,SFMono-Regular,Menlo,monospace}
        \\@media(max-width:760px){main{grid-template-columns:1fr;padding:28px}}
        \\</style>
        \\</head>
        \\<body><main><section><div class="tag">native QUIC response</div><h1>HTTP/3</h1><p>Served by Layerline from the Zig QUIC path after TLS 1.3 Finished, 1-RTT packet protection, QPACK headers, and an HTTP/3 DATA frame.</p><code>HTTP/3 200</code></section><ul><li>QUIC v1</li><li>TLS 1.3</li><li>1-RTT</li><li>QPACK</li></ul></main></body>
        \\</html>
    ;

    return buildHttp3ResponseData(allocator, .{
        .status_code = 200,
        .status_text = "OK",
        .server = SERVER_HEADER,
        .content_type = "text/html; charset=utf-8",
        .content_length = body.len,
        .close_connection = true,
    }, body);
}

fn maxHttp3ShortPlaintextBytes(dcid_len: usize) !usize {
    // Stay inside QUIC's conservative 1200-byte datagram floor until path MTU
    // discovery exists. Bigger responses should split, not gamble on UDP.
    const packet_overhead = 1 + dcid_len + QUIC_SHORT_PACKET_NUMBER_BYTES + QUIC_AEAD_TAG_BYTES;
    if (HTTP3_MAX_DATAGRAM_BYTES <= packet_overhead + 16) return error.PacketBudgetTooSmall;
    return HTTP3_MAX_DATAGRAM_BYTES - packet_overhead;
}

fn h3StreamFramePrefixLen(stream_id: u64, stream_offset: u64, data_len: usize) !usize {
    const has_offset = stream_offset != 0;
    const frame_type = 0x08 | 0x02 | (if (has_offset) @as(u64, 0x04) else @as(u64, 0));
    return (try h3_native.varIntLen(frame_type)) +
        (try h3_native.varIntLen(stream_id)) +
        (if (has_offset) try h3_native.varIntLen(stream_offset) else 0) +
        (try h3_native.varIntLen(@intCast(data_len)));
}

fn maxHttp3StreamChunkLen(available_plaintext: usize, stream_id: u64, stream_offset: u64, remaining: usize) !usize {
    if (remaining == 0) return 0;

    var chunk_len = @min(available_plaintext, remaining);
    while (chunk_len > 0) {
        const prefix_len = try h3StreamFramePrefixLen(stream_id, stream_offset, chunk_len);
        if (prefix_len >= available_plaintext) return error.PacketBudgetTooSmall;

        const next = @min(available_plaintext - prefix_len, remaining);
        if (next == chunk_len) return chunk_len;
        chunk_len = next;
    }

    return error.PacketBudgetTooSmall;
}

fn sendHttp3ShortPlaintext(
    socket: anytype,
    peer: *const std.Io.net.IpAddress,
    assembly: *Http3InitialAssembly,
    plaintext: []const u8,
) !void {
    var padded: ?[]u8 = null;
    defer if (padded) |buf| std.heap.page_allocator.free(buf);

    var packet_plaintext = plaintext;
    if (packet_plaintext.len < 16) {
        const buf = try std.heap.page_allocator.alloc(u8, 16);
        @memcpy(buf[0..packet_plaintext.len], packet_plaintext);
        @memset(buf[packet_plaintext.len..], 0);
        padded = buf;
        packet_plaintext = buf;
    }

    const packet_number = try assembly.server_application_packets.takeNext();
    const packet = try quic_native.buildProtectedShortPacket(std.heap.page_allocator, .{
        .dcid = assembly.scid.slice(),
        .packet_number = packet_number,
        .keys = assembly.server_application_keys,
        .plaintext = packet_plaintext,
    });
    defer std.heap.page_allocator.free(packet);

    try socket.send(activeIo(), peer, packet);
}

fn sendHttp3ResponsePacket(
    socket: anytype,
    peer: *const std.Io.net.IpAddress,
    assembly: *Http3InitialAssembly,
    largest_client_packet_number: u64,
    request_stream_id: u64,
) !usize {
    const ack_frame = try quic_native.buildAckFrame(std.heap.page_allocator, largest_client_packet_number, 0);
    defer std.heap.page_allocator.free(ack_frame);
    const control_data = try buildHttp3ControlStreamData(std.heap.page_allocator);
    defer std.heap.page_allocator.free(control_data);
    const control_stream = try quic_native.buildStreamFrame(std.heap.page_allocator, 3, control_data, false);
    defer std.heap.page_allocator.free(control_stream);
    const response_data = try buildHttp3DefaultResponseData(std.heap.page_allocator);
    defer std.heap.page_allocator.free(response_data);

    const max_plaintext = try maxHttp3ShortPlaintextBytes(assembly.scid.slice().len);
    var response_offset: usize = 0;
    var include_control = true;
    var packet_count: usize = 0;

    // STREAM offsets are byte offsets into the HTTP/3 stream. The client sees
    // one ordered response even though we ship it as multiple QUIC packets.
    while (include_control or response_offset < response_data.len) {
        var plaintext = std.ArrayListUnmanaged(u8).empty;
        defer plaintext.deinit(std.heap.page_allocator);

        if (include_control) {
            try plaintext.appendSlice(std.heap.page_allocator, ack_frame);
            try plaintext.appendSlice(std.heap.page_allocator, control_stream);
            include_control = false;
        }

        if (plaintext.items.len > max_plaintext) return error.PacketBudgetTooSmall;

        if (response_offset < response_data.len and plaintext.items.len < max_plaintext) {
            const remaining = response_data.len - response_offset;
            const available = max_plaintext - plaintext.items.len;
            const chunk_len = try maxHttp3StreamChunkLen(available, request_stream_id, @intCast(response_offset), remaining);
            const fin = chunk_len == remaining;
            const response_stream = try quic_native.buildStreamFrameAt(
                std.heap.page_allocator,
                request_stream_id,
                @intCast(response_offset),
                response_data[response_offset .. response_offset + chunk_len],
                fin,
            );
            defer std.heap.page_allocator.free(response_stream);
            try plaintext.appendSlice(std.heap.page_allocator, response_stream);
            response_offset += chunk_len;
        }

        try sendHttp3ShortPlaintext(socket, peer, assembly, plaintext.items);
        packet_count += 1;
    }

    return packet_count;
}

fn serveHttp3ProbeTask(io: std.Io, cfg: *const ServerConfig) void {
    bindThreadIo(io);

    var address = std.Io.net.IpAddress.parse(cfg.host, cfg.http3_port) catch |err| {
        std.debug.print("HTTP/3 bind address error: {}\n", .{err});
        return;
    };
    const socket = address.bind(activeIo(), .{ .mode = .dgram, .protocol = .udp }) catch |err| {
        std.debug.print("HTTP/3 UDP bind failed on {s}:{d}: {}\n", .{ cfg.host, cfg.http3_port, err });
        return;
    };
    defer socket.close(activeIo());

    std.debug.print("HTTP/3 native UDP listener on udp://{s}:{d}\n", .{ cfg.host, cfg.http3_port });
    std.debug.print("HTTP/3 status: native QUIC/TLS handshake and default-page response path active.\n", .{});

    var connections = Http3ConnectionTable.init(std.heap.page_allocator, HTTP3_CONNECTION_TABLE_CAPACITY) catch |err| {
        std.debug.print("HTTP/3 connection table allocation failed: {}\n", .{err});
        return;
    };
    defer connections.deinit();

    var recv_buf: [4096]u8 = undefined;

    while (true) {
        const msg = socket.receive(activeIo(), &recv_buf) catch |err| {
            std.debug.print("HTTP/3 UDP receive error: {}\n", .{err});
            continue;
        };

        if (msg.data.len == 0) continue;

        if ((msg.data[0] & 0x80) != 0) {
            const long = quic_native.parseLongHeader(msg.data) catch |err| {
                std.debug.print("HTTP/3 ignored malformed long-header datagram from {f}: {}\n", .{ msg.from, err });
                continue;
            };
            const assembly_opt = connections.findByServerCid(long.dcid.slice());
            if (long.packet_type == .handshake or (assembly_opt != null and assembly_opt.?.has_handshake_keys and assembly_opt.?.server_flight_sent)) {
                const assembly = assembly_opt orelse {
                    std.debug.print("HTTP/3 ignored Handshake packet from {f}: unknown destination CID\n", .{msg.from});
                    continue;
                };
                if (!assembly.has_handshake_keys) {
                    std.debug.print("HTTP/3 ignored early Handshake packet from {f}: no handshake keys yet\n", .{msg.from});
                    continue;
                }

                var packet_cursor: usize = 0;
                var largest_handshake_packet_number: u64 = 0;
                var saw_handshake_packet = false;
                while (packet_cursor < msg.data.len and (msg.data[packet_cursor] & 0x80) != 0) {
                    const packet = msg.data[packet_cursor..];
                    const packet_long = quic_native.parseLongHeader(packet) catch break;
                    const packet_len = quic_native.protectedLongPacketLen(packet) catch |err| {
                        std.debug.print("HTTP/3 Handshake packet length parse failed from {f}: {}\n", .{ msg.from, err });
                        break;
                    };
                    if (packet.len < packet_len) {
                        std.debug.print("HTTP/3 truncated Handshake datagram from {f}: packet_len={d}, datagram_len={d}\n", .{ msg.from, packet_len, packet.len });
                        break;
                    }
                    if (packet_long.packet_type != .handshake) {
                        packet_cursor += packet_len;
                        continue;
                    }

                    const decrypted = quic_native.decryptProtectedLongPacketWithKeys(
                        std.heap.page_allocator,
                        packet[0..packet_len],
                        assembly.client_handshake_keys,
                    ) catch |err| {
                        std.debug.print("HTTP/3 client Handshake decrypt failed from {f}: {}\n", .{ msg.from, err });
                        packet_cursor += packet_len;
                        continue;
                    };
                    defer std.heap.page_allocator.free(decrypted.plaintext);

                    quic_native.appendCryptoData(std.heap.page_allocator, decrypted.plaintext, &assembly.client_handshake_crypto) catch |err| {
                        std.debug.print("HTTP/3 client Handshake CRYPTO parse failed from {f}: {}\n", .{ msg.from, err });
                        packet_cursor += packet_len;
                        continue;
                    };
                    largest_handshake_packet_number = decrypted.packet_number;
                    saw_handshake_packet = true;
                    packet_cursor += packet_len;
                }

                if (!saw_handshake_packet) {
                    std.debug.print("HTTP/3 ignored Handshake datagram from {f}: no decryptable Handshake packet\n", .{msg.from});
                    continue;
                }

                const finished = findTlsFinishedVerifyData(assembly.client_handshake_crypto.items) catch |err| {
                    std.debug.print("HTTP/3 client Finished parse failed from {f}: {}\n", .{ msg.from, err });
                    continue;
                } orelse {
                    std.debug.print("HTTP/3 waiting for client Finished from {f}: crypto_bytes={d}\n", .{ msg.from, assembly.client_handshake_crypto.items.len });
                    continue;
                };
                const expected_finished = tls13_native.finishedVerifyData(assembly.traffic.client_finished_key, assembly.application_transcript_hash);
                if (!std.mem.eql(u8, &finished, &expected_finished)) {
                    std.debug.print("HTTP/3 client Finished verify failed from {f}\n", .{msg.from});
                    continue;
                }

                const was_handshake_done = assembly.handshake_done;
                if (!was_handshake_done) {
                    const application = tls13_native.deriveApplicationTrafficSecrets(assembly.traffic.master_secret, assembly.application_transcript_hash);
                    assembly.client_application_keys = packetKeysFromTls(tls13_native.deriveQuicPacketKeys(application.client_application_traffic_secret));
                    assembly.server_application_keys = packetKeysFromTls(tls13_native.deriveQuicPacketKeys(application.server_application_traffic_secret));
                    assembly.has_application_keys = true;
                    assembly.handshake_done = true;
                }

                const ack_frame = quic_native.buildAckFrame(std.heap.page_allocator, largest_handshake_packet_number, 0) catch |err| {
                    std.debug.print("HTTP/3 Handshake ACK frame build failed for {f}: {}\n", .{ msg.from, err });
                    continue;
                };
                defer std.heap.page_allocator.free(ack_frame);
                var handshake_ack_plaintext = std.ArrayListUnmanaged(u8).empty;
                defer handshake_ack_plaintext.deinit(std.heap.page_allocator);
                handshake_ack_plaintext.appendSlice(std.heap.page_allocator, ack_frame) catch |err| {
                    std.debug.print("HTTP/3 Handshake ACK plaintext build failed for {f}: {}\n", .{ msg.from, err });
                    continue;
                };
                handshake_ack_plaintext.appendNTimes(std.heap.page_allocator, 0, 16) catch |err| {
                    std.debug.print("HTTP/3 Handshake ACK padding build failed for {f}: {}\n", .{ msg.from, err });
                    continue;
                };
                const handshake_ack_packet_number = assembly.server_handshake_packets.takeNext() catch |err| {
                    std.debug.print("HTTP/3 Handshake ACK packet number failed for {f}: {}\n", .{ msg.from, err });
                    continue;
                };
                const ack_packet = quic_native.buildProtectedLongPacket(std.heap.page_allocator, .{
                    .packet_type = .handshake,
                    .dcid = assembly.scid.slice(),
                    .scid = assembly.server_cid.slice(),
                    .packet_number = handshake_ack_packet_number,
                    .keys = assembly.server_handshake_keys,
                    .plaintext = handshake_ack_plaintext.items,
                }) catch |err| {
                    std.debug.print("HTTP/3 Handshake ACK packet build failed for {f}: {}\n", .{ msg.from, err });
                    continue;
                };
                defer std.heap.page_allocator.free(ack_packet);
                socket.send(activeIo(), &msg.from, ack_packet) catch |err| {
                    std.debug.print("HTTP/3 Handshake ACK send failed for {f}: {}\n", .{ msg.from, err });
                    continue;
                };

                if (!was_handshake_done) {
                    std.debug.print("HTTP/3 handshake complete with {f}; 1-RTT keys ready\n", .{msg.from});
                }

                if (packet_cursor < msg.data.len and (msg.data[packet_cursor] & 0x80) == 0) {
                    const short = quic_native.decryptProtectedShortPacketWithKeys(
                        std.heap.page_allocator,
                        msg.data[packet_cursor..],
                        assembly.server_cid.len,
                        assembly.client_application_keys,
                    ) catch |err| {
                        std.debug.print("HTTP/3 coalesced 1-RTT decrypt failed from {f}: {}\n", .{ msg.from, err });
                        continue;
                    };
                    defer std.heap.page_allocator.free(short.plaintext);
                    const stream_id_opt = findRequestStreamId(short.plaintext) catch |err| {
                        if (!assembly.h3_response_sent) {
                            std.debug.print("HTTP/3 coalesced request parse failed from {f}: {}\n", .{ msg.from, err });
                        }
                        continue;
                    };
                    if (stream_id_opt) |stream_id| {
                        const packet_count = sendHttp3ResponsePacket(socket, &msg.from, assembly, short.packet_number, stream_id) catch |err| {
                            std.debug.print("HTTP/3 response send failed for {f}: {}\n", .{ msg.from, err });
                            continue;
                        };
                        assembly.h3_response_sent = true;
                        server_metrics.h3ResponseSent(packet_count);
                        std.debug.print("HTTP/3 served default page to {f} on stream {d} in {d} packet(s)\n", .{ msg.from, stream_id, packet_count });
                    }
                }
                continue;
            }
        } else {
            const assembly = connections.findByShortPacketDcid(msg.data) orelse {
                std.debug.print("HTTP/3 ignored 1-RTT packet from {f}: unknown destination CID\n", .{msg.from});
                continue;
            };
            if (!assembly.has_application_keys) {
                std.debug.print("HTTP/3 ignored 1-RTT packet from {f}: application keys not ready\n", .{msg.from});
                continue;
            }

            const decrypted = quic_native.decryptProtectedShortPacketWithKeys(
                std.heap.page_allocator,
                msg.data,
                assembly.server_cid.len,
                assembly.client_application_keys,
            ) catch |err| {
                std.debug.print("HTTP/3 1-RTT decrypt failed from {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(decrypted.plaintext);

            const stream_id_opt = findRequestStreamId(decrypted.plaintext) catch |err| {
                if (!assembly.h3_response_sent) {
                    std.debug.print("HTTP/3 request parse failed from {f}: {}\n", .{ msg.from, err });
                }
                continue;
            };
            if (stream_id_opt) |stream_id| {
                if (!assembly.h3_response_sent) {
                    const packet_count = sendHttp3ResponsePacket(socket, &msg.from, assembly, decrypted.packet_number, stream_id) catch |err| {
                        std.debug.print("HTTP/3 response send failed for {f}: {}\n", .{ msg.from, err });
                        continue;
                    };
                    assembly.h3_response_sent = true;
                    server_metrics.h3ResponseSent(packet_count);
                    std.debug.print("HTTP/3 served default page to {f} on stream {d} in {d} packet(s)\n", .{ msg.from, stream_id, packet_count });
                }
            }
            continue;
        }

        const initial = quic_native.parseInitialHeader(msg.data) catch |err| {
            std.debug.print("HTTP/3 ignored non-initial datagram from {f}: {}\n", .{ msg.from, err });
            continue;
        };

        if (!quic_native.isSupportedVersion(initial.long.version)) {
            var response: [128]u8 = undefined;
            const len = quic_native.encodeVersionNegotiation(
                &response,
                initial.long.dcid.slice(),
                initial.long.scid.slice(),
                &.{ @intFromEnum(quic_native.Version.v1), @intFromEnum(quic_native.Version.v2) },
            ) catch |err| {
                std.debug.print("HTTP/3 version negotiation build failed: {}\n", .{err});
                continue;
            };
            socket.send(activeIo(), &msg.from, response[0..len]) catch |err| {
                std.debug.print("HTTP/3 version negotiation send failed: {}\n", .{err});
            };
            continue;
        }

        var used_fresh_initial_keys = false;
        const existing_assembly = connections.findByClientScid(initial.long.scid.slice());
        const decrypted = if (existing_assembly) |assembly|
            if (assembly.has_original_dcid)
                quic_native.decryptClientInitialWithOriginalDcid(
                    std.heap.page_allocator,
                    msg.data,
                    assembly.original_dcid.slice(),
                ) catch |stored_err| fresh: {
                    const fresh_decrypted = quic_native.decryptClientInitial(std.heap.page_allocator, msg.data) catch {
                        std.debug.print(
                            "HTTP/3 QUIC Initial from {f}: version=0x{x}, dcid_len={d}, scid_len={d}; decrypt failed: {}\n",
                            .{
                                msg.from,
                                initial.long.version,
                                initial.long.dcid.len,
                                initial.long.scid.len,
                                stored_err,
                            },
                        );
                        continue;
                    };
                    used_fresh_initial_keys = true;
                    break :fresh fresh_decrypted;
                }
            else
                quic_native.decryptClientInitial(std.heap.page_allocator, msg.data) catch |err| {
                    std.debug.print(
                        "HTTP/3 QUIC Initial from {f}: version=0x{x}, dcid_len={d}, scid_len={d}; decrypt failed: {}\n",
                        .{
                            msg.from,
                            initial.long.version,
                            initial.long.dcid.len,
                            initial.long.scid.len,
                            err,
                        },
                    );
                    continue;
                }
        else fresh: {
            used_fresh_initial_keys = true;
            break :fresh quic_native.decryptClientInitial(std.heap.page_allocator, msg.data) catch |err| {
                std.debug.print(
                    "HTTP/3 QUIC Initial from {f}: version=0x{x}, dcid_len={d}, scid_len={d}; decrypt failed: {}\n",
                    .{
                        msg.from,
                        initial.long.version,
                        initial.long.dcid.len,
                        initial.long.scid.len,
                        err,
                    },
                );
                continue;
            };
        };
        defer std.heap.page_allocator.free(decrypted.plaintext);

        const assembly = existing_assembly orelse (connections.acquire() catch |err| {
            std.debug.print("HTTP/3 connection table is full; dropping Initial from {f}: {}\n", .{ msg.from, err });
            continue;
        });

        if (existing_assembly == null or !assembly.has_original_dcid or used_fresh_initial_keys or (!assembly.server_flight_sent and !assembly.matches(initial.long.scid.slice()))) {
            assembly.reset(std.heap.page_allocator, initial.long.dcid.slice(), initial.long.scid.slice()) catch |err| {
                std.debug.print("HTTP/3 state reset failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
        }

        quic_native.appendCryptoData(std.heap.page_allocator, decrypted.plaintext, &assembly.crypto) catch |err| {
            std.debug.print(
                "HTTP/3 QUIC Initial from {f}: packet_number={d}, plaintext_bytes={d}; CRYPTO reassembly failed: {}\n",
                .{ msg.from, decrypted.packet_number, decrypted.plaintext.len, err },
            );
            continue;
        };

        if (assembly.server_flight_sent) continue;

        const hello = quic_native.parseClientHello(assembly.crypto.items) catch |err| {
            if (err == error.Truncated) {
                std.debug.print(
                    "HTTP/3 waiting for complete ClientHello from {f}: packet_number={d}, crypto_bytes={d}\n",
                    .{ msg.from, decrypted.packet_number, assembly.crypto.items.len },
                );
                continue;
            }
            std.debug.print(
                "HTTP/3 QUIC Initial from {f}: packet_number={d}, crypto_bytes={d}; ClientHello parse failed: {}\n",
                .{ msg.from, decrypted.packet_number, assembly.crypto.items.len, err },
            );
            continue;
        };

        std.debug.print(
            "HTTP/3 ClientHello from {f}: packet_number={d}, alpn={s}, sni={s}, tls13={}, aes128gcm={}, ed25519={}, x25519={}, quic_transport_params={}\n",
            .{
                msg.from,
                decrypted.packet_number,
                hello.alpn orelse "(none)",
                hello.server_name orelse "(none)",
                hello.supports_tls13,
                hello.supports_aes_128_gcm_sha256,
                hello.supports_ed25519,
                hello.x25519_key_share != null,
                hello.has_quic_transport_parameters,
            },
        );

        if (hello.x25519_key_share) |client_key| {
            if (!std.mem.eql(u8, hello.alpn orelse "", "h3")) {
                std.debug.print("HTTP/3 ClientHello from {f} did not offer h3 ALPN; skipping server flight.\n", .{msg.from});
                continue;
            }

            var server_random: [32]u8 = undefined;
            activeIo().random(&server_random);
            const server_kp = tls13_native.X25519.KeyPair.generate(activeIo());
            const server_hello = tls13_native.buildServerHello(std.heap.page_allocator, .{
                .legacy_session_id = hello.legacy_session_id,
                .random = server_random,
                .x25519_public_key = server_kp.public_key,
            }) catch |err| {
                std.debug.print("HTTP/3 TLS ServerHello build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(server_hello);

            const shared = tls13_native.X25519.scalarmult(server_kp.secret_key, client_key) catch |err| {
                std.debug.print("HTTP/3 TLS X25519 shared-secret failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            const transcript_hash = tls13_native.transcriptHash(&.{ assembly.crypto.items, server_hello });
            const traffic = tls13_native.deriveTrafficSecrets(shared, transcript_hash);
            const client_handshake_keys = packetKeysFromTls(tls13_native.deriveQuicPacketKeys(traffic.client_handshake_traffic_secret));
            const server_handshake_keys = packetKeysFromTls(tls13_native.deriveQuicPacketKeys(traffic.server_handshake_traffic_secret));

            var server_cid: [8]u8 = undefined;
            activeIo().random(&server_cid);
            assembly.rememberServerCid(&server_cid) catch |err| {
                std.debug.print("HTTP/3 server CID tracking failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            const ack_frame = quic_native.buildAckFrame(std.heap.page_allocator, decrypted.packet_number, 0) catch |err| {
                std.debug.print("HTTP/3 QUIC ACK frame build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(ack_frame);

            const crypto_frame = quic_native.buildCryptoFrame(std.heap.page_allocator, 0, server_hello) catch |err| {
                std.debug.print("HTTP/3 QUIC CRYPTO frame build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(crypto_frame);

            var initial_plaintext = std.ArrayListUnmanaged(u8).empty;
            defer initial_plaintext.deinit(std.heap.page_allocator);
            initial_plaintext.appendSlice(std.heap.page_allocator, ack_frame) catch |err| {
                std.debug.print("HTTP/3 QUIC plaintext build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            initial_plaintext.appendSlice(std.heap.page_allocator, crypto_frame) catch |err| {
                std.debug.print("HTTP/3 QUIC plaintext build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            // QUIC Initial datagrams are intentionally bulky. Some clients will
            // read the ServerHello from a small packet and still reject the flight.
            initial_plaintext.appendNTimes(std.heap.page_allocator, 0, HTTP3_INITIAL_PADDING_BYTES) catch |err| {
                std.debug.print("HTTP/3 QUIC Initial padding build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };

            const initial_secrets = quic_native.deriveInitialSecrets(initial.long.dcid.slice());
            const response = quic_native.buildProtectedLongPacket(std.heap.page_allocator, .{
                .packet_type = .initial,
                .dcid = initial.long.scid.slice(),
                .scid = &server_cid,
                .packet_number = 0,
                .keys = quic_native.packetKeysFromInitialDirection(initial_secrets.server),
                .plaintext = initial_plaintext.items,
            }) catch |err| {
                std.debug.print("HTTP/3 QUIC server Initial build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(response);

            const transport_params = quic_native.buildDefaultTransportParameters(std.heap.page_allocator, initial.long.dcid.slice(), &server_cid) catch |err| {
                std.debug.print("HTTP/3 QUIC transport parameter build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(transport_params);

            const encrypted_extensions = tls13_native.buildEncryptedExtensions(std.heap.page_allocator, "h3", transport_params) catch |err| {
                std.debug.print("HTTP/3 TLS EncryptedExtensions build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(encrypted_extensions);

            const cert_key = tls13_native.Ed25519.KeyPair.generate(activeIo());
            const cert_der = tls13_native.buildSelfSignedEd25519Certificate(std.heap.page_allocator, cert_key, "localhost") catch |err| {
                std.debug.print("HTTP/3 TLS self-signed certificate build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(cert_der);

            const certificate_msg = tls13_native.buildCertificate(std.heap.page_allocator, &.{cert_der}) catch |err| {
                std.debug.print("HTTP/3 TLS Certificate build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(certificate_msg);

            const cert_verify_hash = tls13_native.transcriptHash(&.{
                assembly.crypto.items,
                server_hello,
                encrypted_extensions,
                certificate_msg,
            });
            const cert_verify_signature = tls13_native.signCertificateVerifyEd25519(cert_key, cert_verify_hash) catch |err| {
                std.debug.print("HTTP/3 TLS CertificateVerify signature failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            const certificate_verify_msg = tls13_native.buildCertificateVerify(std.heap.page_allocator, .ed25519, &cert_verify_signature) catch |err| {
                std.debug.print("HTTP/3 TLS CertificateVerify build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(certificate_verify_msg);

            const finished_hash = tls13_native.transcriptHash(&.{
                assembly.crypto.items,
                server_hello,
                encrypted_extensions,
                certificate_msg,
                certificate_verify_msg,
            });
            const server_finished_msg = tls13_native.buildFinished(
                std.heap.page_allocator,
                tls13_native.finishedVerifyData(traffic.server_finished_key, finished_hash),
            ) catch |err| {
                std.debug.print("HTTP/3 TLS Finished build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(server_finished_msg);

            assembly.traffic = traffic;
            assembly.client_handshake_keys = client_handshake_keys;
            assembly.server_handshake_keys = server_handshake_keys;
            assembly.application_transcript_hash = tls13_native.transcriptHash(&.{
                assembly.crypto.items,
                server_hello,
                encrypted_extensions,
                certificate_msg,
                certificate_verify_msg,
                server_finished_msg,
            });
            assembly.has_handshake_keys = true;

            var server_handshake_flight = std.ArrayListUnmanaged(u8).empty;
            defer server_handshake_flight.deinit(std.heap.page_allocator);
            server_handshake_flight.appendSlice(std.heap.page_allocator, encrypted_extensions) catch |err| {
                std.debug.print("HTTP/3 TLS server flight build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            server_handshake_flight.appendSlice(std.heap.page_allocator, certificate_msg) catch |err| {
                std.debug.print("HTTP/3 TLS server flight build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            server_handshake_flight.appendSlice(std.heap.page_allocator, certificate_verify_msg) catch |err| {
                std.debug.print("HTTP/3 TLS server flight build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            server_handshake_flight.appendSlice(std.heap.page_allocator, server_finished_msg) catch |err| {
                std.debug.print("HTTP/3 TLS server flight build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };

            const handshake_crypto = quic_native.buildCryptoFrame(std.heap.page_allocator, 0, server_handshake_flight.items) catch |err| {
                std.debug.print("HTTP/3 QUIC Handshake CRYPTO frame build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(handshake_crypto);

            const server_handshake_packet_number = assembly.server_handshake_packets.takeNext() catch |err| {
                std.debug.print("HTTP/3 server Handshake packet number failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            const handshake_response = quic_native.buildProtectedLongPacket(std.heap.page_allocator, .{
                .packet_type = .handshake,
                .dcid = initial.long.scid.slice(),
                .scid = &server_cid,
                .packet_number = server_handshake_packet_number,
                .keys = server_handshake_keys,
                .plaintext = handshake_crypto,
            }) catch |err| {
                std.debug.print("HTTP/3 QUIC server Handshake build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(handshake_response);

            var server_datagram = std.ArrayListUnmanaged(u8).empty;
            defer server_datagram.deinit(std.heap.page_allocator);
            server_datagram.appendSlice(std.heap.page_allocator, response) catch |err| {
                std.debug.print("HTTP/3 QUIC server datagram build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            server_datagram.appendSlice(std.heap.page_allocator, handshake_response) catch |err| {
                std.debug.print("HTTP/3 QUIC server datagram build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };

            socket.send(activeIo(), &msg.from, server_datagram.items) catch |err| {
                std.debug.print("HTTP/3 QUIC server Initial+Handshake send failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };

            std.debug.print(
                "HTTP/3 sent server Initial+Handshake to {f}: datagram_bytes={d}, initial_bytes={d}, handshake_bytes={d}, initial_padding={d}, server_hello_bytes={d}, cert_bytes={d}, finished_bytes={d}\n",
                .{ msg.from, server_datagram.items.len, response.len, handshake_response.len, HTTP3_INITIAL_PADDING_BYTES, server_hello.len, cert_der.len, server_finished_msg.len },
            );
            assembly.server_flight_sent = true;
        }
    }
}

fn dumpRoutes(cfg: *const ServerConfig) void {
    if (cfg.routes.items.len == 0 and cfg.domains.items.len == 0) {
        std.debug.print("Layerline routes: no named routes configured; built-in routes remain active.\n", .{});
        return;
    }

    if (cfg.routes.items.len == 0) {
        std.debug.print("Layerline routes: no global named routes configured.\n", .{});
    } else {
        std.debug.print("Layerline routes ({d}):\n", .{cfg.routes.items.len});
    }
    for (cfg.routes.items) |route| {
        std.debug.print(
            "  {s}: {s} {s} -> {s}",
            .{ route.name, routeMatchName(route.match_kind), route.pattern, routeHandlerName(route.handler) },
        );
        switch (route.handler) {
            .static => {
                std.debug.print(" dir={s} index={s}", .{ route.static_dir orelse cfg.static_dir, route.index_file orelse cfg.index_file });
            },
            .php => {
                std.debug.print(" php_root={s} php_bin={s}", .{ route.php_root orelse cfg.php_root, route.php_binary orelse cfg.php_binary });
            },
            .proxy => {
                const maybe_upstream = if (route.upstream) |pool| pool else cfg.upstream;
                if (maybe_upstream) |pool| {
                    printUpstreamPool(pool);
                } else {
                    std.debug.print(" upstream=<unset>", .{});
                }
            },
        }
        if (!route.strip_prefix) std.debug.print(" strip_prefix=false", .{});
        std.debug.print("\n", .{});
    }

    if (cfg.domains.items.len > 0) {
        std.debug.print("Layerline domains ({d}):\n", .{cfg.domains.items.len});
    }
    for (cfg.domains.items) |*domain| {
        std.debug.print("  server {s}: server_name", .{domain.name});
        for (domain.server_names.items) |server_name| {
            std.debug.print(" {s}", .{server_name});
        }
        std.debug.print(" root={s} index={s}", .{ domainStaticDir(cfg, domain), domainIndexFile(cfg, domain) });
        if (domainServeStaticRoot(cfg, domain)) std.debug.print(" serve_static_root=true", .{});
        if (domain.upstream) |pool| printUpstreamPool(pool);
        std.debug.print("\n", .{});

        for (domain.routes.items) |route| {
            std.debug.print(
                "    {s}: {s} {s} -> {s}",
                .{ route.name, routeMatchName(route.match_kind), route.pattern, routeHandlerName(route.handler) },
            );
            switch (route.handler) {
                .static => {
                    std.debug.print(" dir={s} index={s}", .{ route.static_dir orelse domainStaticDir(cfg, domain), route.index_file orelse domainIndexFile(cfg, domain) });
                },
                .php => {
                    std.debug.print(" php_root={s} php_bin={s}", .{ route.php_root orelse domainPhpRoot(cfg, domain), route.php_binary orelse domainPhpBinary(cfg, domain) });
                },
                .proxy => {
                    const maybe_upstream = if (route.upstream) |pool| pool else domainUpstream(cfg, domain);
                    if (maybe_upstream) |pool| {
                        printUpstreamPool(pool);
                    } else {
                        std.debug.print(" upstream=<unset>", .{});
                    }
                },
            }
            if (!route.strip_prefix) std.debug.print(" strip_prefix=false", .{});
            std.debug.print("\n", .{});
        }
    }
}

fn waitForConnectionDrain(io: std.Io, state: *ConcurrencyState, timeout_ms: u32) void {
    var waited_ms: u32 = 0;
    while (state.active() > 0 and waited_ms < timeout_ms) {
        const step_ms: u32 = @min(@as(u32, 25), timeout_ms - waited_ms);
        io.sleep(.fromMilliseconds(step_ms), .awake) catch {};
        waited_ms += step_ms;
    }

    const remaining = state.active();
    if (remaining == 0) {
        std.debug.print("Graceful shutdown complete: all connections drained.\n", .{});
    } else {
        std.debug.print("Graceful shutdown timeout reached with {d} active connection(s).\n", .{remaining});
    }
}

// Emit current runtime usage, flags, and sample invocations.
fn usage() void {
    std.debug.print(
        "Layerline HTTP server\n\n" ++
            "Usage:\n" ++
            "  zig build run -- [--config server.conf] [--validate-config] [--dump-routes] [--host 127.0.0.1] [--port PORT] [--dir STATIC_DIR] " ++
            "[--index INDEX.html] [--serve-static true|false] [--php-root PHP_ROOT] [--php-bin /usr/bin/php-cgi] [--php-info-page true|false] " ++
            "[--proxy http://HOST:PORT[/path][,http://HOST:PORT[/path]]] [--h2-upstream http://HOST:PORT[/path]] " ++
            "[--http3 true|false] [--http3-port PORT] [--tls true|false] [--tls-cert path] [--tls-key path] " ++
            "[--tls-auto true|false] [--letsencrypt-email EMAIL] [--letsencrypt-domains example.com,www.example.com] " ++
            "[--letsencrypt-webroot /var/www/html] [--letsencrypt-certbot /usr/bin/certbot] [--letsencrypt-staging true|false] " ++
            "[--cf-auto-deploy true|false] [--cf-zone-name example.com] [--cf-zone-id ZONE_ID] [--cf-record-name www.example.com] " ++
            "[--cf-record-type A|AAAA|CNAME|TXT] [--cf-record-content 203.0.113.10] [--cf-record-ttl 300] [--cf-record-proxied true|false] " ++
            "[--max-request-bytes N] [--max-body-bytes N] [--max-static-bytes N] [--max-concurrent-connections N] " ++
            "[--max-requests-per-connection N] [--max-php-output-bytes N] [--worker-stack-size N] [--read-header-timeout-ms N] " ++
            "[--read-body-timeout-ms N] [--idle-timeout-ms N] [--write-timeout-ms N] [--upstream-timeout-ms N] " ++
            "[--graceful-shutdown-timeout-ms N]\n" ++
            "  Supported config keys: host, port, static_dir/dir, index_file/index, serve_static_root, " ++
            "php_root, php_binary/php_bin, php_info_page/phpinfo_page, proxy, h2_upstream, http3, http3_port, header/response_header/add_header, redirect/redir, tls, tls_cert, tls_key, max_request_bytes, " ++
            "tls_auto, letsencrypt_email, letsencrypt_domains, letsencrypt_webroot, letsencrypt_certbot, letsencrypt_staging, " ++
            "max_body_bytes, max_static_file_bytes, max_requests_per_connection, max_php_output_bytes, max_concurrent_connections, worker_stack_size, " ++
            "read_header_timeout_ms, read_body_timeout_ms, idle_timeout_ms, write_timeout_ms, upstream_timeout_ms, graceful_shutdown_timeout_ms, " ++
            "cf_auto_deploy, cf_api_base, cf_token, cf_zone_id, cf_zone_name, cf_record_name, cf_record_type, cf_record_content, " ++
            "cf_record_ttl, cf_record_proxied, cf_record_comment, route, route_dir.NAME, route_index.NAME, route_php_root.NAME, " ++
            "route_php_bin.NAME, route_php_info_page.NAME, route_proxy.NAME, route_strip_prefix.NAME, server/domain/vhost, " ++
            "server_name.NAME, server_root.NAME, server_index.NAME, server_serve_static_root.NAME, server_proxy.NAME, " ++
            "server_redirect.NAME, server_route.NAME, server_route_dir.DOMAIN.ROUTE, server_route_proxy.DOMAIN.ROUTE\n" ++
            "  HTTP/1 is served directly. HTTP/2 cleartext can be passed through with --h2-upstream. " ++
            "Native HTTP/3 serves the built-in default page over QUIC on --http3-port.\n\n" ++
            "Examples:\n" ++
            "  zig build run\n" ++
            "  zig build run -- --validate-config\n" ++
            "  zig build run -- --dump-routes\n" ++
            "  zig build run -- --port 4000\n" ++
            "  zig build run -- --index index.php --serve-static true\n" ++
            "  zig build run -- --php-root public --php-bin php-cgi\n" ++
            "  zig build run -- --config server.conf\n" ++
            "  zig build run -- --proxy http://127.0.0.1:9000,http://127.0.0.1:9001\n" ++
            "  zig build run -- --proxy off\n" ++
            "  zig build run -- --tls-auto true --letsencrypt-email admin@example.com --letsencrypt-domains example.com\n" ++
            "  zig build run -- --cf-auto-deploy true --cf-token xxxxx --cf-zone-name example.com --cf-record-name www.example.com\n" ++
            "  zig build run -- --h2-upstream http://127.0.0.1:9001\n\n" ++
            "Notes:\n" ++
            "  This is a thread-per-connection model for now. For very high fan-in (large counts of\n" ++
            "  open keep-alive sockets), place this server behind a TLS/HTTP proxy with strict\n" ++
            "  timeout and connection management policies.\n" ++
            "  Native HTTP/3 currently covers the local default-page path, with broader routing\n" ++
            "  and certificate trust/automation still kept separate from the HTTP/1 surface.\n",
        .{},
    );
}

// Bootstraps config/CLI, optional cert automation, then starts the accept loop.
pub fn main(init: std.process.Init) !void {
    bindThreadIo(init.io);
    installShutdownSignalHandlers();
    shutdown_requested.store(false, .release);
    listener_closed_by_shutdown.store(false, .release);

    var cfg = ServerConfig{
        .host = "127.0.0.1",
        .port = 8080,
        .static_dir = "public",
        .serve_static_root = false,
        .index_file = "index.html",
        .php_root = "public",
        .php_binary = "php-cgi",
        .php_info_page = false,
        .tls_enabled = false,
        .tls_auto = false,
        .letsencrypt_email = null,
        .letsencrypt_domains = null,
        .letsencrypt_webroot = "public/.well-known/acme-challenge",
        .letsencrypt_certbot = "certbot",
        .letsencrypt_staging = false,
        .cloudflare_auto_deploy = false,
        .cloudflare_api_base = "https://api.cloudflare.com/client/v4",
        .cloudflare_token = null,
        .cloudflare_zone_id = null,
        .cloudflare_zone_name = null,
        .cloudflare_record_name = null,
        .cloudflare_record_type = "A",
        .cloudflare_record_content = null,
        .cloudflare_record_ttl = 300,
        .cloudflare_record_proxied = false,
        .cloudflare_record_comment = null,
        .upstream = null,
        .tls_cert = null,
        .tls_key = null,
        .h2_upstream = null,
        .http3_enabled = false,
        .http3_port = 8443,
        .response_headers = .empty,
        .redirects = .empty,
        .routes = .empty,
        .domains = .empty,
        .max_request_bytes = DEFAULT_MAX_REQUEST_BYTES,
        .max_body_bytes = DEFAULT_MAX_BODY_BYTES,
        .max_static_file_bytes = DEFAULT_MAX_STATIC_FILE_BYTES,
        .max_requests_per_connection = DEFAULT_MAX_REQUESTS_PER_CONNECTION,
        .max_concurrent_connections = DEFAULT_MAX_CONCURRENT_CONNECTIONS,
        .worker_stack_size = DEFAULT_WORKER_STACK_BYTES,
        .read_header_timeout_ms = DEFAULT_READ_HEADER_TIMEOUT_MS,
        .read_body_timeout_ms = DEFAULT_READ_BODY_TIMEOUT_MS,
        .idle_timeout_ms = DEFAULT_IDLE_TIMEOUT_MS,
        .write_timeout_ms = DEFAULT_WRITE_TIMEOUT_MS,
        .upstream_timeout_ms = DEFAULT_UPSTREAM_TIMEOUT_MS,
        .graceful_shutdown_timeout_ms = DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_MS,
        .max_php_output_bytes = DEFAULT_MAX_PHP_OUTPUT_BYTES,
    };

    var args_for_config = std.process.Args.iterate(init.minimal.args);
    _ = args_for_config.next();
    var config_explicitly_set = false;
    while (args_for_config.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config")) {
            config_explicitly_set = true;
            if (args_for_config.next()) |path| {
                loadConfig(init.io, std.heap.page_allocator, &cfg, path) catch |err| {
                    std.debug.print("Failed to load config file: {s}\n", .{path});
                    return err;
                };
            } else {
                usage();
                return;
            }
        }
    }

    if (!config_explicitly_set) {
        if (std.Io.Dir.cwd().statFile(init.io, DEFAULT_CONFIG_PATH, .{})) |_| {
            loadConfig(init.io, std.heap.page_allocator, &cfg, DEFAULT_CONFIG_PATH) catch |err| {
                std.debug.print("Failed to load default config file: {s}\n", .{DEFAULT_CONFIG_PATH});
                return err;
            };
        } else |_| {}
    }

    var args = std.process.Args.iterate(init.minimal.args);
    _ = args.next();
    var validate_only = false;
    var dump_routes = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            usage();
            return;
        } else if (std.mem.eql(u8, arg, "--config")) {
            _ = args.next();
        } else if (std.mem.eql(u8, arg, "--validate-config") or std.mem.eql(u8, arg, "--check-config")) {
            validate_only = true;
        } else if (std.mem.eql(u8, arg, "--dump-routes") or std.mem.eql(u8, arg, "--routes")) {
            dump_routes = true;
        } else if (std.mem.eql(u8, arg, "--tls")) {
            if (args.next()) |value| {
                cfg.tls_enabled = parseBool(value) orelse cfg.tls_enabled;
            } else {
                usage();
                return;
            }
        } else if (std.mem.eql(u8, arg, "--tls-auto")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.tls_auto = parseBool(value) orelse cfg.tls_auto;
        } else if (std.mem.eql(u8, arg, "--letsencrypt-email")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            if (value.len == 0) {
                cfg.letsencrypt_email = null;
            } else {
                cfg.letsencrypt_email = value;
            }
        } else if (std.mem.eql(u8, arg, "--letsencrypt-domains")) {
            cfg.letsencrypt_domains = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--letsencrypt-webroot")) {
            cfg.letsencrypt_webroot = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--letsencrypt-certbot")) {
            cfg.letsencrypt_certbot = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--letsencrypt-staging")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.letsencrypt_staging = parseBool(value) orelse cfg.letsencrypt_staging;
        } else if (std.mem.eql(u8, arg, "--tls-cert")) {
            cfg.tls_cert = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--tls-key")) {
            cfg.tls_key = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--index")) {
            cfg.index_file = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--serve-static")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.serve_static_root = parseBool(value) orelse cfg.serve_static_root;
        } else if (std.mem.eql(u8, arg, "--host") or std.mem.eql(u8, arg, "-H")) {
            cfg.host = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--port") or std.mem.eql(u8, arg, "-p")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.port = std.fmt.parseInt(u16, value, 10) catch 80;
        } else if (std.mem.eql(u8, arg, "--dir") or std.mem.eql(u8, arg, "-d")) {
            cfg.static_dir = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--php-root") or std.mem.eql(u8, arg, "-r")) {
            cfg.php_root = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--php-bin") or std.mem.eql(u8, arg, "-P")) {
            cfg.php_binary = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--php-info-page") or std.mem.eql(u8, arg, "--phpinfo-page")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.php_info_page = parseBool(value) orelse cfg.php_info_page;
        } else if (std.mem.eql(u8, arg, "--proxy") or std.mem.eql(u8, arg, "-x")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream = if (disablesOptionalUrl(value)) null else parseUpstreamPool(std.heap.page_allocator, value) catch null;
        } else if (std.mem.eql(u8, arg, "--h2-upstream") or std.mem.eql(u8, arg, "--http2-upstream")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            if (disablesOptionalUrl(value)) {
                cfg.h2_upstream = null;
                continue;
            }
            cfg.h2_upstream = parseUpstream(std.heap.page_allocator, value) catch {
                std.debug.print("Failed to parse h2-upstream URL: {s}\n", .{value});
                return;
            };
        } else if (std.mem.eql(u8, arg, "--http3")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.http3_enabled = parseBool(value) orelse cfg.http3_enabled;
        } else if (std.mem.eql(u8, arg, "--http3-port")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.http3_port = std.fmt.parseInt(u16, value, 10) catch cfg.http3_port;
        } else if (std.mem.eql(u8, arg, "--max-request-bytes")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.max_request_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.max_request_bytes;
        } else if (std.mem.eql(u8, arg, "--max-body-bytes")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.max_body_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.max_body_bytes;
        } else if (std.mem.eql(u8, arg, "--max-static-bytes")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.max_static_file_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.max_static_file_bytes;
        } else if (std.mem.eql(u8, arg, "--max-requests-per-connection")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.max_requests_per_connection = std.fmt.parseInt(usize, value, 10) catch cfg.max_requests_per_connection;
        } else if (std.mem.eql(u8, arg, "--max-php-output-bytes")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.max_php_output_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.max_php_output_bytes;
        } else if (std.mem.eql(u8, arg, "--worker-stack-size")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.worker_stack_size = std.fmt.parseInt(usize, value, 10) catch cfg.worker_stack_size;
        } else if (std.mem.eql(u8, arg, "--read-header-timeout-ms")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.read_header_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.read_header_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--read-body-timeout-ms")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.read_body_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.read_body_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--idle-timeout-ms")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.idle_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.idle_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--write-timeout-ms")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.write_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.write_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--upstream-timeout-ms")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.upstream_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--graceful-shutdown-timeout-ms")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.graceful_shutdown_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.graceful_shutdown_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--max-concurrent-connections")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.max_concurrent_connections = std.fmt.parseInt(usize, value, 10) catch cfg.max_concurrent_connections;
        } else if (std.mem.eql(u8, arg, "--cf-auto-deploy")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.cloudflare_auto_deploy = parseBool(value) orelse cfg.cloudflare_auto_deploy;
        } else if (std.mem.eql(u8, arg, "--cf-api-base")) {
            cfg.cloudflare_api_base = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--cf-token")) {
            cfg.cloudflare_token = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--cf-zone-id")) {
            cfg.cloudflare_zone_id = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--cf-zone-name")) {
            cfg.cloudflare_zone_name = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--cf-record-name")) {
            cfg.cloudflare_record_name = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--cf-record-type")) {
            cfg.cloudflare_record_type = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--cf-record-content")) {
            cfg.cloudflare_record_content = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--cf-record-ttl")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.cloudflare_record_ttl = std.fmt.parseInt(u32, value, 10) catch cfg.cloudflare_record_ttl;
        } else if (std.mem.eql(u8, arg, "--cf-record-proxied")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.cloudflare_record_proxied = parseBool(value) orelse cfg.cloudflare_record_proxied;
        } else if (std.mem.eql(u8, arg, "--cf-record-comment")) {
            cfg.cloudflare_record_comment = args.next() orelse {
                usage();
                return;
            };
        } else {
            std.debug.print("Unknown argument: {s}\n", .{arg});
            usage();
            return error.InvalidCommandLine;
        }
    }

    normalizeConfig(&cfg);
    validateConfig(&cfg) catch |err| {
        std.debug.print("Invalid Layerline configuration: {}\n", .{err});
        return err;
    };

    if (validate_only) {
        std.debug.print("Layerline config OK: {s}:{d}\n", .{ cfg.host, cfg.port });
    }
    if (dump_routes) {
        dumpRoutes(&cfg);
    }
    if (validate_only or dump_routes) {
        return;
    }

    if (cfg.tls_auto) {
        ensureLetsEncryptSetup(init.io, std.heap.page_allocator, &cfg) catch |err| {
            std.debug.print("Let's Encrypt automation failed: {}\n", .{err});
            return;
        };
    }

    ensureCloudflareDeployment(init.io, std.heap.page_allocator, &cfg) catch |err| {
        std.debug.print("Cloudflare deployment failed: {}\n", .{err});
        return;
    };

    var concurrency = ConcurrencyState.init();

    if (cfg.tls_enabled) {
        if (cfg.tls_cert == null or cfg.tls_key == null) {
            std.debug.print("TLS hint: tls=true was set, but cert/key were not both provided. Keep TLS at the reverse proxy layer.\n", .{});
        } else {
            std.debug.print("TLS hint: cert/key were provided, but this version currently requires TLS termination in front of this process.\n", .{});
        }
    }

    var address = try std.Io.net.IpAddress.parse(cfg.host, cfg.port);
    var server = try address.listen(init.io, .{ .reuse_address = true });
    defer {
        if (!listener_closed_by_shutdown.load(.acquire)) {
            server.deinit(init.io);
        }
    }
    const shutdown_watcher = std.Thread.spawn(
        .{},
        shutdownWatcherTask,
        .{ShutdownWatcherContext{ .io = init.io, .server = &server }},
    ) catch |err| {
        std.debug.print("Failed to start shutdown watcher: {}\n", .{err});
        return;
    };
    shutdown_watcher.detach();

    std.debug.print("Serving on http://{s}:{d}\n", .{ cfg.host, cfg.port });
    std.debug.print("Concurrency limit: {d} concurrent connection handlers\n", .{cfg.max_concurrent_connections});
    if (cfg.upstream != null) {
        const pool = cfg.upstream.?;
        std.debug.print("Reverse proxy pool: round_robin over {d} target(s)\n", .{upstreamPoolTargetCount(pool)});
    }
    if (cfg.h2_upstream != null) {
        const hup = cfg.h2_upstream.?;
        std.debug.print("HTTP/2 cleartext passthrough to: {s}:{d} (base {s})\n", .{ hup.host, hup.port, hup.base_path });
    }
    std.debug.print(
        "Timeouts: header={d}ms body={d}ms idle={d}ms write={d}ms upstream={d}ms graceful_shutdown={d}ms\n",
        .{
            cfg.read_header_timeout_ms,
            cfg.read_body_timeout_ms,
            cfg.idle_timeout_ms,
            cfg.write_timeout_ms,
            cfg.upstream_timeout_ms,
            cfg.graceful_shutdown_timeout_ms,
        },
    );
    if (cfg.http3_enabled) {
        const h3_worker = std.Thread.spawn(.{}, serveHttp3ProbeTask, .{ init.io, &cfg }) catch |err| {
            std.debug.print("Failed to start HTTP/3 native listener: {}\n", .{err});
            return;
        };
        h3_worker.detach();
    }

    while (!shutdown_requested.load(.acquire)) {
        const conn = server.accept(init.io) catch |err| {
            if (shutdown_requested.load(.acquire)) break;
            std.debug.print("Accept failed: {}. Continuing to accept.\n", .{err});
            init.io.sleep(.fromMilliseconds(25), .awake) catch {};
            continue;
        };

        if (!concurrency.tryAcquire(cfg.max_concurrent_connections)) {
            server_metrics.connectionRejected();
            std.debug.print("Rejecting connection: max concurrency reached ({d})\n", .{cfg.max_concurrent_connections});
            sendCoolError(
                conn,
                std.heap.page_allocator,
                503,
                "Service Unavailable",
                "Maximum concurrent connections reached. Try again in a moment.",
            ) catch {};
            streamClose(conn);
            continue;
        }

        const worker = std.Thread.spawn(
            .{
                .stack_size = cfg.worker_stack_size,
            },
            serveConnectionTask,
            .{
                init.io,
                conn,
                &cfg,
                std.heap.page_allocator,
                &concurrency,
                init.environ_map,
            },
        ) catch |err| {
            std.debug.print("Failed to start connection worker: {}\n", .{err});
            concurrency.release();
            streamClose(conn);
            continue;
        };
        worker.detach();
    }

    std.debug.print("Shutdown requested; draining active connections for up to {d}ms.\n", .{cfg.graceful_shutdown_timeout_ms});
    waitForConnectionDrain(init.io, &concurrency, cfg.graceful_shutdown_timeout_ms);
}
