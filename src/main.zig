const std = @import("std");
const builtin = @import("builtin");
const h2_native = @import("h2_native.zig");
const h3_native = @import("h3_native.zig");
const h3_state = @import("h3_state.zig");
const http_response = @import("http_response.zig");
const quic_native = @import("quic_native.zig");
const tls13_native = @import("tls13_native.zig");
const tls_client_hello = @import("tls_client_hello.zig");
const tls_pem = @import("tls_pem.zig");

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
const DEFAULT_MAX_PHP_FASTCGI_STDERR_BYTES = 64 * 1024;
const DEFAULT_PHP_INDEX = "index.php";
const DEFAULT_READ_HEADER_TIMEOUT_MS = 10_000;
const DEFAULT_READ_BODY_TIMEOUT_MS = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS = 60_000;
const DEFAULT_WRITE_TIMEOUT_MS = 30_000;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 30_000;
const DEFAULT_UPSTREAM_RETRIES = 1;
const DEFAULT_UPSTREAM_MAX_FAILURES = 2;
const DEFAULT_UPSTREAM_FAIL_TIMEOUT_MS = 10_000;
const DEFAULT_UPSTREAM_KEEPALIVE_MAX_IDLE = 16;
const DEFAULT_UPSTREAM_KEEPALIVE_IDLE_TIMEOUT_MS = 30_000;
const DEFAULT_UPSTREAM_KEEPALIVE_MAX_REQUESTS = 100;
const DEFAULT_FASTCGI_KEEPALIVE_MAX_IDLE = 8;
const DEFAULT_FASTCGI_KEEPALIVE_IDLE_TIMEOUT_MS = 30_000;
const DEFAULT_FASTCGI_KEEPALIVE_MAX_REQUESTS = 100;
const DEFAULT_UPSTREAM_HEALTH_CHECK_INTERVAL_MS = 5_000;
const DEFAULT_UPSTREAM_HEALTH_CHECK_TIMEOUT_MS = 1_000;
const DEFAULT_UPSTREAM_HEALTH_CHECK_PATH = "/health";
const DEFAULT_UPSTREAM_CIRCUIT_HALF_OPEN_MAX = 1;
const DEFAULT_UPSTREAM_SLOW_START_MS = 10_000;
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
const FASTCGI_VERSION: u8 = 1;
const FASTCGI_BEGIN_REQUEST: u8 = 1;
const FASTCGI_END_REQUEST: u8 = 3;
const FASTCGI_PARAMS: u8 = 4;
const FASTCGI_STDIN: u8 = 5;
const FASTCGI_STDOUT: u8 = 6;
const FASTCGI_STDERR: u8 = 7;
const FASTCGI_RESPONDER: u16 = 1;
const FASTCGI_KEEP_CONN: u8 = 1;
const FASTCGI_REQUEST_COMPLETE: u8 = 0;
const QUIC_SHORT_PACKET_NUMBER_BYTES = 4;
const QUIC_AEAD_TAG_BYTES = 16;
const TLS_MAX_INNER_PLAINTEXT_BYTES = 16 * 1024;
const TLS_MAX_RECORD_BYTES = 5 + TLS_MAX_INNER_PLAINTEXT_BYTES + 256;
const TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_CONTENT_TYPE_ALERT: u8 = 0x15;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
const TLS_ALERT_HANDSHAKE_FAILURE: u8 = 40;
const TLS_ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;

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
threadlocal var current_tls_channel: ?*TlsChannel = null;
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

fn rawStreamRead(stream: std.Io.net.Stream, out: []u8) !usize {
    const io = activeIo();
    var data: [1][]u8 = .{out};
    return io.vtable.netRead(io.userdata, stream.socket.handle, &data) catch |err| return normalizeSocketIoError(err);
}

fn streamRead(stream: std.Io.net.Stream, out: []u8) !usize {
    if (current_tls_channel) |channel| {
        if (stream.socket.handle == channel.stream.socket.handle) {
            return tlsReadApplicationData(channel, out);
        }
    }
    return rawStreamRead(stream, out);
}

fn rawStreamWriteAll(stream: std.Io.net.Stream, bytes: []const u8) !void {
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

fn streamWriteAll(stream: std.Io.net.Stream, bytes: []const u8) !void {
    if (current_tls_channel) |channel| {
        if (stream.socket.handle == channel.stream.socket.handle) {
            return tlsWriteApplicationData(channel, bytes);
        }
    }
    return rawStreamWriteAll(stream, bytes);
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

fn connectFastcgiEndpoint(allocator: std.mem.Allocator, endpoint: PhpFastcgiEndpoint) !std.Io.net.Stream {
    return switch (endpoint) {
        .tcp => |tcp| try connectTcpHost(allocator, tcp.host, tcp.port),
        .unix => |path| blk: {
            const unix_addr = try std.Io.net.UnixAddress.init(path);
            break :blk try unix_addr.connect(activeIo());
        },
    };
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
    h2c_upgrade_tail: []const u8 = "",
};

const UpstreamIdleConnection = struct {
    stream: std.Io.net.Stream,
    expires_at_ms: i64,
    requests_served: usize,
};

const UpstreamKeepAlivePool = struct {
    mutex: std.Io.Mutex,
    idle: std.ArrayList(UpstreamIdleConnection),

    fn init() UpstreamKeepAlivePool {
        return .{
            .mutex = .init,
            .idle = .empty,
        };
    }
};

const FastcgiIdleConnection = struct {
    stream: std.Io.net.Stream,
    endpoint_name: []const u8,
    expires_at_ms: i64,
    requests_served: usize,
};

const FastcgiKeepAlivePool = struct {
    mutex: std.Io.Mutex,
    idle: std.ArrayList(FastcgiIdleConnection),

    fn init() FastcgiKeepAlivePool {
        return .{
            .mutex = .init,
            .idle = .empty,
        };
    }
};

// Parsed form of a configured upstream endpoint.
const UpstreamConfig = struct {
    host: []const u8,
    port: u16,
    base_path: []const u8,
    https: bool,
    weight: usize,
    keepalive_pool: UpstreamKeepAlivePool,
    active_requests: std.atomic.Value(usize),
    half_open_requests: std.atomic.Value(usize),
    passive_failures: std.atomic.Value(usize),
    ejected_until_ms: std.atomic.Value(i64),
    recovered_at_ms: std.atomic.Value(i64),
};

const PhpFastcgiTcpEndpoint = struct {
    host: []const u8,
    port: u16,
};

const PhpFastcgiEndpoint = union(enum) {
    tcp: PhpFastcgiTcpEndpoint,
    unix: []const u8,
};

const UpstreamPoolPolicy = enum {
    round_robin,
    random,
    least_connections,
    weighted,
    consistent_hash,
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
    php_index,
    php_fastcgi,
};

const RouteBoolProperty = enum {
    php_info_page,
    php_front_controller,
    strip_prefix,
};

const RouteU32Property = enum {
    upstream_timeout_ms,
};

const DomainStringProperty = enum {
    static_dir,
    index_file,
    php_root,
    php_binary,
    php_index,
    php_fastcgi,
    tls_cert,
    tls_key,
};

const DomainBoolProperty = enum {
    serve_static_root,
    php_info_page,
    php_front_controller,
};

const DomainU32Property = enum {
    upstream_timeout_ms,
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
    php_index: ?[]const u8,
    php_fastcgi: ?[]const u8,
    php_info_page: ?bool,
    php_front_controller: ?bool,
    upstream: ?UpstreamPoolConfig,
    upstream_policy: ?UpstreamPoolPolicy,
    upstream_timeout_ms: ?u32,
    response_headers: std.ArrayList(ResponseHeaderRule),
};

const DomainConfig = struct {
    name: []const u8,
    server_names: std.ArrayList([]const u8),
    static_dir: ?[]const u8,
    serve_static_root: ?bool,
    index_file: ?[]const u8,
    php_root: ?[]const u8,
    php_binary: ?[]const u8,
    php_index: ?[]const u8,
    php_fastcgi: ?[]const u8,
    php_info_page: ?bool,
    php_front_controller: ?bool,
    tls_cert: ?[]const u8,
    tls_key: ?[]const u8,
    tls_material: ?tls_pem.ConfiguredTlsMaterial,
    upstream: ?UpstreamPoolConfig,
    upstream_policy: ?UpstreamPoolPolicy,
    upstream_timeout_ms: ?u32,
    response_headers: std.ArrayList(ResponseHeaderRule),
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
    php_index: []const u8,
    php_fastcgi: ?[]const u8,
    php_info_page: bool,
    php_front_controller: bool,
    upstream: ?UpstreamPoolConfig,
    upstream_policy: UpstreamPoolPolicy,
    tls_enabled: bool,
    tls_cert: ?[]const u8,
    tls_key: ?[]const u8,
    tls_material: ?tls_pem.ConfiguredTlsMaterial,
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
    domain_config_dir: ?[]const u8,
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
    upstream_retries: usize,
    upstream_max_failures: usize,
    upstream_fail_timeout_ms: u32,
    upstream_keepalive_enabled: bool,
    upstream_keepalive_max_idle: usize,
    upstream_keepalive_idle_timeout_ms: u32,
    upstream_keepalive_max_requests: usize,
    fastcgi_keepalive_enabled: bool,
    fastcgi_keepalive_max_idle: usize,
    fastcgi_keepalive_idle_timeout_ms: u32,
    fastcgi_keepalive_max_requests: usize,
    upstream_health_check_enabled: bool,
    upstream_health_check_path: []const u8,
    upstream_health_check_interval_ms: u32,
    upstream_health_check_timeout_ms: u32,
    upstream_circuit_breaker_enabled: bool,
    upstream_circuit_half_open_max: usize,
    upstream_slow_start_ms: u32,
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

const ResponseHeaderContext = struct {
    items: []const ResponseHeaderRule,
    owned: ?[]ResponseHeaderRule = null,

    fn deinit(self: ResponseHeaderContext, allocator: std.mem.Allocator) void {
        if (self.owned) |owned| allocator.free(owned);
    }
};

fn appendResponseHeaderSlice(dest: []ResponseHeaderRule, cursor: *usize, source: []const ResponseHeaderRule) void {
    if (source.len == 0) return;
    @memcpy(dest[cursor.* .. cursor.* + source.len], source);
    cursor.* += source.len;
}

fn buildResponseHeaderContext(allocator: std.mem.Allocator, cfg: *const ServerConfig, domain: ?*const DomainConfig, route: ?*const RouteConfig) !ResponseHeaderContext {
    const domain_headers = if (domain) |d| d.response_headers.items else &.{};
    const route_headers = if (route) |r| r.response_headers.items else &.{};
    const count = cfg.response_headers.items.len + domain_headers.len + route_headers.len;
    if (count == 0) return .{ .items = &.{} };

    const owned = try allocator.alloc(ResponseHeaderRule, count);
    var cursor: usize = 0;
    appendResponseHeaderSlice(owned, &cursor, cfg.response_headers.items);
    appendResponseHeaderSlice(owned, &cursor, domain_headers);
    appendResponseHeaderSlice(owned, &cursor, route_headers);
    return .{ .items = owned, .owned = owned };
}

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

fn http2SettingsDecodedLength(value: []const u8) ?usize {
    var len: usize = 0;
    for (value) |byte| {
        const valid = (byte >= 'A' and byte <= 'Z') or
            (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '-' or
            byte == '_';
        if (!valid) return null;
        len += 1;
    }

    const rem = len % 4;
    if (rem == 1) return null;
    return (len / 4) * 3 + switch (rem) {
        0 => @as(usize, 0),
        2 => @as(usize, 1),
        3 => @as(usize, 2),
        else => unreachable,
    };
}

fn isValidHttp2SettingsHeader(value: []const u8) bool {
    const decoded_len = http2SettingsDecodedLength(trimValue(value)) orelse return false;
    return decoded_len % 6 == 0;
}

fn isH2cUpgradeHeaders(headers: []const u8) bool {
    const upgrade = findHeaderValue(headers, "Upgrade") orelse return false;
    const settings = findHeaderValue(headers, "HTTP2-Settings") orelse return false;
    return hasConnectionToken(upgrade, "h2c") and
        hasHeaderToken(headers, "Connection", "Upgrade") and
        hasHeaderToken(headers, "Connection", "HTTP2-Settings") and
        isValidHttp2SettingsHeader(settings);
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

test "parses FastCGI tcp and unix endpoints" {
    const tcp = try parseFastcgiEndpoint("tcp://127.0.0.1:9000");
    try std.testing.expectEqualStrings("127.0.0.1", tcp.tcp.host);
    try std.testing.expectEqual(@as(u16, 9000), tcp.tcp.port);

    const shorthand = try parseFastcgiEndpoint("localhost:9001");
    try std.testing.expectEqualStrings("localhost", shorthand.tcp.host);
    try std.testing.expectEqual(@as(u16, 9001), shorthand.tcp.port);

    const unix_endpoint = try parseFastcgiEndpoint("unix:///tmp/layerline.sock");
    try std.testing.expectEqualStrings("/tmp/layerline.sock", unix_endpoint.unix);

    try std.testing.expectError(error.InvalidConfigValue, parseFastcgiEndpoint("localhost"));
    try std.testing.expectError(error.InvalidConfigValue, parseFastcgiEndpoint("false"));
}

test "encodes FastCGI name value pairs" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);

    try appendFastcgiParam(&out, std.testing.allocator, "A", "B");
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 'A', 'B' }, out.items);

    out.clearRetainingCapacity();
    const long_name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try appendFastcgiParam(&out, std.testing.allocator, long_name, "x");
    try std.testing.expectEqual(@as(u8, 0x80), out.items[0]);
    try std.testing.expectEqual(@as(u8, 0x00), out.items[1]);
    try std.testing.expectEqual(@as(u8, 0x00), out.items[2]);
    try std.testing.expectEqual(@as(u8, 0x80), out.items[3]);
    try std.testing.expectEqual(@as(u8, 1), out.items[4]);
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

fn loadConfiguredTlsMaterial(
    io: std.Io,
    allocator: std.mem.Allocator,
    cert_path: []const u8,
    key_path: []const u8,
) !tls_pem.ConfiguredTlsMaterial {
    const cert_pem = try std.Io.Dir.cwd().readFileAlloc(io, cert_path, allocator, .limited(512 * 1024));
    defer allocator.free(cert_pem);
    const key_pem = try std.Io.Dir.cwd().readFileAlloc(io, key_path, allocator, .limited(128 * 1024));
    defer allocator.free(key_pem);
    return tls_pem.loadMaterialFromPem(allocator, cert_pem, key_pem);
}

fn loadAllConfiguredTlsMaterials(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
    if (cfg.tls_enabled) {
        if (cfg.tls_cert == null and cfg.tls_key == null) {
            std.debug.print("TLS enabled without cert/key; native TLS will use an ephemeral self-signed certificate.\n", .{});
        } else if (cfg.tls_cert == null or cfg.tls_key == null) {
            return error.InvalidTlsConfig;
        } else {
            cfg.tls_material = try loadConfiguredTlsMaterial(io, allocator, cfg.tls_cert.?, cfg.tls_key.?);
            std.debug.print("Native TLS certificate loaded from {s}\n", .{cfg.tls_cert.?});
        }
    }

    for (cfg.domains.items) |*domain| {
        if (domain.tls_cert == null and domain.tls_key == null) continue;
        if (domain.tls_cert == null or domain.tls_key == null) return error.InvalidTlsConfig;
        domain.tls_material = try loadConfiguredTlsMaterial(io, allocator, domain.tls_cert.?, domain.tls_key.?);
        std.debug.print("Native TLS certificate loaded for {s} from {s}\n", .{ domain.name, domain.tls_cert.? });
    }
}

fn deinitConfiguredTlsMaterials(allocator: std.mem.Allocator, cfg: *ServerConfig) void {
    if (cfg.tls_material) |*material| material.deinit(allocator);
    cfg.tls_material = null;
    for (cfg.domains.items) |*domain| {
        if (domain.tls_material) |*material| material.deinit(allocator);
        domain.tls_material = null;
    }
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
    upstream_requests_total: std.atomic.Value(usize),
    upstream_failures_total: std.atomic.Value(usize),
    upstream_retries_total: std.atomic.Value(usize),
    upstream_ejections_total: std.atomic.Value(usize),
    upstream_ejected_skips_total: std.atomic.Value(usize),
    upstream_connections_opened_total: std.atomic.Value(usize),
    upstream_connections_reused_total: std.atomic.Value(usize),
    upstream_connections_pooled_total: std.atomic.Value(usize),
    upstream_connections_discarded_total: std.atomic.Value(usize),
    fastcgi_connections_opened_total: std.atomic.Value(usize),
    fastcgi_connections_reused_total: std.atomic.Value(usize),
    fastcgi_connections_pooled_total: std.atomic.Value(usize),
    fastcgi_connections_discarded_total: std.atomic.Value(usize),
    upstream_health_checks_total: std.atomic.Value(usize),
    upstream_health_check_failures_total: std.atomic.Value(usize),
    upstream_health_check_recoveries_total: std.atomic.Value(usize),
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
            .upstream_requests_total = std.atomic.Value(usize).init(0),
            .upstream_failures_total = std.atomic.Value(usize).init(0),
            .upstream_retries_total = std.atomic.Value(usize).init(0),
            .upstream_ejections_total = std.atomic.Value(usize).init(0),
            .upstream_ejected_skips_total = std.atomic.Value(usize).init(0),
            .upstream_connections_opened_total = std.atomic.Value(usize).init(0),
            .upstream_connections_reused_total = std.atomic.Value(usize).init(0),
            .upstream_connections_pooled_total = std.atomic.Value(usize).init(0),
            .upstream_connections_discarded_total = std.atomic.Value(usize).init(0),
            .fastcgi_connections_opened_total = std.atomic.Value(usize).init(0),
            .fastcgi_connections_reused_total = std.atomic.Value(usize).init(0),
            .fastcgi_connections_pooled_total = std.atomic.Value(usize).init(0),
            .fastcgi_connections_discarded_total = std.atomic.Value(usize).init(0),
            .upstream_health_checks_total = std.atomic.Value(usize).init(0),
            .upstream_health_check_failures_total = std.atomic.Value(usize).init(0),
            .upstream_health_check_recoveries_total = std.atomic.Value(usize).init(0),
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

    fn upstreamRequestStarted(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_requests_total);
    }

    fn upstreamRequestFailed(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_failures_total);
    }

    fn upstreamRetried(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_retries_total);
    }

    fn upstreamEjected(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_ejections_total);
    }

    fn upstreamEjectedSkip(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_ejected_skips_total);
    }

    fn upstreamConnectionOpened(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_connections_opened_total);
    }

    fn upstreamConnectionReused(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_connections_reused_total);
    }

    fn upstreamConnectionPooled(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_connections_pooled_total);
    }

    fn upstreamConnectionDiscarded(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_connections_discarded_total);
    }

    fn fastcgiConnectionOpened(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.fastcgi_connections_opened_total);
    }

    fn fastcgiConnectionReused(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.fastcgi_connections_reused_total);
    }

    fn fastcgiConnectionPooled(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.fastcgi_connections_pooled_total);
    }

    fn fastcgiConnectionDiscarded(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.fastcgi_connections_discarded_total);
    }

    fn upstreamHealthCheckRan(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_health_checks_total);
    }

    fn upstreamHealthCheckFailed(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_health_check_failures_total);
    }

    fn upstreamHealthCheckRecovered(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_health_check_recoveries_total);
    }

    fn h3ResponseSent(self: *ServerMetrics, packet_count: usize) void {
        ServerMetrics.inc(&self.h3_responses_total);
        ServerMetrics.add(&self.h3_packets_sent_total, packet_count);
    }
};

var server_metrics = ServerMetrics.init();
var upstream_round_robin_cursor = std.atomic.Value(usize).init(0);
var upstream_random_cursor = std.atomic.Value(u64).init(0x9e3779b97f4a7c15);
var fastcgi_keepalive_pool = FastcgiKeepAlivePool.init();

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

fn parseFastcgiHostPort(value: []const u8) !PhpFastcgiTcpEndpoint {
    if (value.len == 0) return error.InvalidConfigValue;

    if (value[0] == '[') {
        const close = std.mem.indexOfScalar(u8, value, ']') orelse return error.InvalidConfigValue;
        if (close + 2 > value.len or value[close + 1] != ':') return error.InvalidConfigValue;
        const host = value[1..close];
        const port = std.fmt.parseInt(u16, value[close + 2 ..], 10) catch return error.InvalidConfigValue;
        if (host.len == 0 or port == 0) return error.InvalidConfigValue;
        return .{ .host = host, .port = port };
    }

    const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse return error.InvalidConfigValue;
    const host = value[0..colon];
    const port = std.fmt.parseInt(u16, value[colon + 1 ..], 10) catch return error.InvalidConfigValue;
    if (host.len == 0 or port == 0) return error.InvalidConfigValue;
    return .{ .host = host, .port = port };
}

fn normalizeFastcgiUnixPath(raw: []const u8) []const u8 {
    var path = raw;
    while (path.len > 1 and path[0] == '/' and path[1] == '/') {
        path = path[1..];
    }
    return path;
}

fn parseFastcgiEndpoint(raw: []const u8) !PhpFastcgiEndpoint {
    const value = trimValue(raw);
    if (disablesOptionalUrl(value)) return error.InvalidConfigValue;

    if (std.mem.startsWith(u8, value, "unix:")) {
        const path = normalizeFastcgiUnixPath(value["unix:".len..]);
        if (path.len == 0 or path[0] != '/') return error.InvalidConfigValue;
        return .{ .unix = path };
    }

    if (value[0] == '/') return .{ .unix = value };

    const host_port = if (std.mem.startsWith(u8, value, "tcp://"))
        value["tcp://".len..]
    else if (std.mem.startsWith(u8, value, "fastcgi://"))
        value["fastcgi://".len..]
    else
        value;

    return .{ .tcp = try parseFastcgiHostPort(host_port) };
}

fn validateFastcgiEndpoint(raw: []const u8) !void {
    _ = try parseFastcgiEndpoint(raw);
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

fn upstreamPoolPolicyName(policy: UpstreamPoolPolicy) []const u8 {
    return switch (policy) {
        .round_robin => "round_robin",
        .random => "random",
        .least_connections => "least_connections",
        .weighted => "weighted",
        .consistent_hash => "consistent_hash",
    };
}

fn parseUpstreamPoolPolicy(value: []const u8) !UpstreamPoolPolicy {
    if (std.ascii.eqlIgnoreCase(value, "round_robin") or
        std.ascii.eqlIgnoreCase(value, "round-robin") or
        std.ascii.eqlIgnoreCase(value, "roundrobin") or
        std.ascii.eqlIgnoreCase(value, "rr"))
    {
        return .round_robin;
    }
    if (std.ascii.eqlIgnoreCase(value, "random") or std.ascii.eqlIgnoreCase(value, "rand")) {
        return .random;
    }
    if (std.ascii.eqlIgnoreCase(value, "least_connections") or
        std.ascii.eqlIgnoreCase(value, "least-connections") or
        std.ascii.eqlIgnoreCase(value, "least_conn") or
        std.ascii.eqlIgnoreCase(value, "leastconn"))
    {
        return .least_connections;
    }
    if (std.ascii.eqlIgnoreCase(value, "weighted") or
        std.ascii.eqlIgnoreCase(value, "weighted_round_robin") or
        std.ascii.eqlIgnoreCase(value, "weighted-round-robin") or
        std.ascii.eqlIgnoreCase(value, "wrr"))
    {
        return .weighted;
    }
    if (std.ascii.eqlIgnoreCase(value, "consistent_hash") or
        std.ascii.eqlIgnoreCase(value, "consistent-hash") or
        std.ascii.eqlIgnoreCase(value, "hash") or
        std.ascii.eqlIgnoreCase(value, "uri_hash") or
        std.ascii.eqlIgnoreCase(value, "uri-hash"))
    {
        return .consistent_hash;
    }
    return error.InvalidConfigValue;
}

fn parseOptionalUpstreamPoolPolicy(value: []const u8) !?UpstreamPoolPolicy {
    if (std.ascii.eqlIgnoreCase(value, "inherit") or
        std.ascii.eqlIgnoreCase(value, "default") or
        std.ascii.eqlIgnoreCase(value, "auto"))
    {
        return null;
    }
    return try parseUpstreamPoolPolicy(value);
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
        .php_index = null,
        .php_fastcgi = null,
        .php_info_page = null,
        .php_front_controller = null,
        .upstream = null,
        .upstream_policy = null,
        .upstream_timeout_ms = null,
        .response_headers = .empty,
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
        .php_index => route.php_index = dupe_value,
        .php_fastcgi => route.php_fastcgi = dupe_value,
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

fn setRouteUpstreamPolicyProperty(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    route.upstream_policy = try parseOptionalUpstreamPoolPolicy(value);
}

fn setRouteU32Property(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8, field: RouteU32Property) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const parsed = try parseConfigU32(value);
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .upstream_timeout_ms => route.upstream_timeout_ms = parsed,
    }
}

fn setRouteBoolProperty(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8, field: RouteBoolProperty) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const parsed = try parseConfigBool(value);
    switch (field) {
        .php_info_page => route.php_info_page = parsed,
        .php_front_controller => route.php_front_controller = parsed,
        .strip_prefix => route.strip_prefix = parsed,
    }
}

fn appendRouteResponseHeader(routes: *std.ArrayList(RouteConfig), allocator: std.mem.Allocator, route_name: []const u8, value: []const u8) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    if (value.len > 0) try route.response_headers.append(allocator, try parseResponseHeaderRule(allocator, value));
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

fn initDomainConfig(allocator: std.mem.Allocator, name: []const u8) !DomainConfig {
    if (!isDomainConfigNameValid(name)) return error.InvalidConfigValue;
    return .{
        .name = try allocator.dupe(u8, name),
        .server_names = .empty,
        .static_dir = null,
        .serve_static_root = null,
        .index_file = null,
        .php_root = null,
        .php_binary = null,
        .php_index = null,
        .php_fastcgi = null,
        .php_info_page = null,
        .php_front_controller = null,
        .tls_cert = null,
        .tls_key = null,
        .tls_material = null,
        .upstream = null,
        .upstream_policy = null,
        .upstream_timeout_ms = null,
        .response_headers = .empty,
        .redirects = .empty,
        .routes = .empty,
    };
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

    try cfg.domains.append(allocator, try initDomainConfig(allocator, name));
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
        .php_index => domain.php_index = dupe_value,
        .php_fastcgi => domain.php_fastcgi = dupe_value,
        .tls_cert => domain.tls_cert = dupe_value,
        .tls_key => domain.tls_key = dupe_value,
    }
}

fn setDomainBoolProperty(cfg: *ServerConfig, domain_name: []const u8, value: []const u8, field: DomainBoolProperty) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const parsed = try parseConfigBool(value);
    switch (field) {
        .serve_static_root => domain.serve_static_root = parsed,
        .php_info_page => domain.php_info_page = parsed,
        .php_front_controller => domain.php_front_controller = parsed,
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

fn setDomainUpstreamPolicyProperty(cfg: *ServerConfig, domain_name: []const u8, value: []const u8) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    domain.upstream_policy = try parseOptionalUpstreamPoolPolicy(value);
}

fn setDomainU32Property(cfg: *ServerConfig, domain_name: []const u8, value: []const u8, field: DomainU32Property) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const parsed = try parseConfigU32(value);
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .upstream_timeout_ms => domain.upstream_timeout_ms = parsed,
    }
}

fn appendDomainResponseHeader(cfg: *ServerConfig, allocator: std.mem.Allocator, domain_name: []const u8, value: []const u8) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    if (value.len > 0) try domain.response_headers.append(allocator, try parseResponseHeaderRule(allocator, value));
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

fn setDomainRouteUpstreamPolicyProperty(cfg: *ServerConfig, property_name: []const u8, value: []const u8) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteUpstreamPolicyProperty(&domain.routes, split.route, value);
}

fn setDomainRouteU32Property(cfg: *ServerConfig, property_name: []const u8, value: []const u8, field: RouteU32Property) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteU32Property(&domain.routes, split.route, value, field);
}

fn appendDomainRouteResponseHeader(cfg: *ServerConfig, allocator: std.mem.Allocator, property_name: []const u8, value: []const u8) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try appendRouteResponseHeader(&domain.routes, allocator, split.route, value);
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
    } else if (std.mem.eql(u8, k, "php_fastcgi") or std.mem.eql(u8, k, "php_fpm") or std.mem.eql(u8, k, "fastcgi")) {
        if (disablesOptionalUrl(v)) {
            cfg.php_fastcgi = null;
        } else {
            try validateFastcgiEndpoint(v);
            cfg.php_fastcgi = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "php_index") or std.mem.eql(u8, k, "php_index_file")) {
        if (v.len == 0 or std.mem.indexOf(u8, v, "..") != null or std.mem.startsWith(u8, v, "/")) return error.InvalidConfigValue;
        cfg.php_index = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "php_info_page") or std.mem.eql(u8, k, "phpinfo_page") or std.mem.eql(u8, k, "enable_php_info_page")) {
        cfg.php_info_page = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "php_front_controller") or std.mem.eql(u8, k, "php_front_controller_enabled")) {
        cfg.php_front_controller = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "proxy")) {
        if (disablesOptionalUrl(v)) {
            cfg.upstream = null;
        } else {
            cfg.upstream = try parseUpstreamPool(allocator, v);
        }
    } else if (std.mem.eql(u8, k, "upstream_policy") or std.mem.eql(u8, k, "proxy_policy") or std.mem.eql(u8, k, "load_balance")) {
        cfg.upstream_policy = try parseUpstreamPoolPolicy(v);
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
    } else if (std.mem.eql(u8, k, "domain_config_dir") or std.mem.eql(u8, k, "domains_dir") or std.mem.eql(u8, k, "sites_enabled") or std.mem.eql(u8, k, "sites_dir")) {
        cfg.domain_config_dir = if (v.len == 0) null else try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "server") or std.mem.eql(u8, k, "domain") or std.mem.eql(u8, k, "vhost")) {
        try setDomainLine(cfg, allocator, v);
    } else if (findRoutePropertyName(k, "server_name.")) |name| {
        const domain = findDomainConfigMutable(cfg, name) orelse return error.UnknownConfigDomain;
        try appendServerNames(allocator, domain, v);
    } else if (findRoutePropertyName(k, "server_names.")) |name| {
        const domain = findDomainConfigMutable(cfg, name) orelse return error.UnknownConfigDomain;
        try appendServerNames(allocator, domain, v);
    } else if (findRoutePropertyName(k, "server_header.")) |name| {
        try appendDomainResponseHeader(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_response_header.")) |name| {
        try appendDomainResponseHeader(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_add_header.")) |name| {
        try appendDomainResponseHeader(cfg, allocator, name, v);
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
    } else if (findRoutePropertyName(k, "server_php_fastcgi.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "server_php_fpm.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "server_fastcgi.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "server_php_index.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "server_php_index_file.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "server_tls_cert.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .tls_cert);
    } else if (findRoutePropertyName(k, "server_tls_key.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .tls_key);
    } else if (findRoutePropertyName(k, "server_php_info_page.")) |name| {
        try setDomainBoolProperty(cfg, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "server_phpinfo_page.")) |name| {
        try setDomainBoolProperty(cfg, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "server_php_front_controller.")) |name| {
        try setDomainBoolProperty(cfg, name, v, .php_front_controller);
    } else if (findRoutePropertyName(k, "server_proxy.")) |name| {
        try setDomainProxyProperty(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_upstream.")) |name| {
        try setDomainProxyProperty(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_proxy_policy.")) |name| {
        try setDomainUpstreamPolicyProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_upstream_policy.")) |name| {
        try setDomainUpstreamPolicyProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_load_balance.")) |name| {
        try setDomainUpstreamPolicyProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_upstream_timeout_ms.")) |name| {
        try setDomainU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_proxy_timeout_ms.")) |name| {
        try setDomainU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_php_timeout_ms.")) |name| {
        try setDomainU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_fastcgi_timeout_ms.")) |name| {
        try setDomainU32Property(cfg, name, v, .upstream_timeout_ms);
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
    } else if (findRoutePropertyName(k, "server_route_php_fastcgi.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "server_route_php_fpm.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "server_route_fastcgi.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "server_route_php_index.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "server_route_php_index_file.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "server_route_php_info_page.")) |name| {
        try setDomainRouteBoolProperty(cfg, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "server_route_phpinfo_page.")) |name| {
        try setDomainRouteBoolProperty(cfg, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "server_route_php_front_controller.")) |name| {
        try setDomainRouteBoolProperty(cfg, name, v, .php_front_controller);
    } else if (findRoutePropertyName(k, "server_route_proxy.")) |name| {
        try setDomainRouteProxyProperty(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_upstream.")) |name| {
        try setDomainRouteProxyProperty(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_proxy_policy.")) |name| {
        try setDomainRouteUpstreamPolicyProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_route_upstream_policy.")) |name| {
        try setDomainRouteUpstreamPolicyProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_route_load_balance.")) |name| {
        try setDomainRouteUpstreamPolicyProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_route_upstream_timeout_ms.")) |name| {
        try setDomainRouteU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_route_proxy_timeout_ms.")) |name| {
        try setDomainRouteU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_route_php_timeout_ms.")) |name| {
        try setDomainRouteU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_route_fastcgi_timeout_ms.")) |name| {
        try setDomainRouteU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_route_strip_prefix.")) |name| {
        try setDomainRouteBoolProperty(cfg, name, v, .strip_prefix);
    } else if (findRoutePropertyName(k, "server_route_header.")) |name| {
        try appendDomainRouteResponseHeader(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_response_header.")) |name| {
        try appendDomainRouteResponseHeader(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_add_header.")) |name| {
        try appendDomainRouteResponseHeader(cfg, allocator, name, v);
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
    } else if (findRoutePropertyName(k, "route_php_fastcgi.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "route_php_fpm.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "route_fastcgi.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "route_php_index.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "route_php_index_file.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "route_php_info_page.")) |name| {
        try setRouteBoolProperty(&cfg.routes, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "route_phpinfo_page.")) |name| {
        try setRouteBoolProperty(&cfg.routes, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "route_php_front_controller.")) |name| {
        try setRouteBoolProperty(&cfg.routes, name, v, .php_front_controller);
    } else if (findRoutePropertyName(k, "route_proxy.")) |name| {
        try setRouteProxyProperty(&cfg.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_upstream.")) |name| {
        try setRouteProxyProperty(&cfg.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_proxy_policy.")) |name| {
        try setRouteUpstreamPolicyProperty(&cfg.routes, name, v);
    } else if (findRoutePropertyName(k, "route_upstream_policy.")) |name| {
        try setRouteUpstreamPolicyProperty(&cfg.routes, name, v);
    } else if (findRoutePropertyName(k, "route_load_balance.")) |name| {
        try setRouteUpstreamPolicyProperty(&cfg.routes, name, v);
    } else if (findRoutePropertyName(k, "route_upstream_timeout_ms.")) |name| {
        try setRouteU32Property(&cfg.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_proxy_timeout_ms.")) |name| {
        try setRouteU32Property(&cfg.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_php_timeout_ms.")) |name| {
        try setRouteU32Property(&cfg.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_fastcgi_timeout_ms.")) |name| {
        try setRouteU32Property(&cfg.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_strip_prefix.")) |name| {
        try setRouteBoolProperty(&cfg.routes, name, v, .strip_prefix);
    } else if (findRoutePropertyName(k, "route_header.")) |name| {
        try appendRouteResponseHeader(&cfg.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_response_header.")) |name| {
        try appendRouteResponseHeader(&cfg.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_add_header.")) |name| {
        try appendRouteResponseHeader(&cfg.routes, allocator, name, v);
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
    } else if (std.mem.eql(u8, k, "upstream_retries")) {
        cfg.upstream_retries = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "upstream_max_failures") or std.mem.eql(u8, k, "upstream_max_fails") or std.mem.eql(u8, k, "proxy_max_fails")) {
        cfg.upstream_max_failures = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "upstream_fail_timeout_ms") or std.mem.eql(u8, k, "proxy_fail_timeout_ms")) {
        cfg.upstream_fail_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "upstream_keepalive") or std.mem.eql(u8, k, "proxy_keepalive")) {
        cfg.upstream_keepalive_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "upstream_keepalive_max_idle") or std.mem.eql(u8, k, "proxy_keepalive_max_idle")) {
        cfg.upstream_keepalive_max_idle = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "upstream_keepalive_idle_timeout_ms") or std.mem.eql(u8, k, "proxy_keepalive_idle_timeout_ms")) {
        cfg.upstream_keepalive_idle_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "upstream_keepalive_max_requests") or std.mem.eql(u8, k, "proxy_keepalive_max_requests")) {
        cfg.upstream_keepalive_max_requests = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "fastcgi_keepalive") or std.mem.eql(u8, k, "php_fastcgi_keepalive") or std.mem.eql(u8, k, "fastcgi_keep_conn")) {
        cfg.fastcgi_keepalive_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "fastcgi_keepalive_max_idle") or std.mem.eql(u8, k, "php_fastcgi_keepalive_max_idle")) {
        cfg.fastcgi_keepalive_max_idle = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "fastcgi_keepalive_idle_timeout_ms") or std.mem.eql(u8, k, "php_fastcgi_keepalive_idle_timeout_ms")) {
        cfg.fastcgi_keepalive_idle_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "fastcgi_keepalive_max_requests") or std.mem.eql(u8, k, "php_fastcgi_keepalive_max_requests")) {
        cfg.fastcgi_keepalive_max_requests = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "upstream_health_check") or std.mem.eql(u8, k, "upstream_health_check_enabled") or std.mem.eql(u8, k, "active_health_check") or std.mem.eql(u8, k, "proxy_health_check")) {
        cfg.upstream_health_check_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "upstream_health_check_path") or std.mem.eql(u8, k, "proxy_health_check_path")) {
        cfg.upstream_health_check_path = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "upstream_health_check_interval_ms") or std.mem.eql(u8, k, "proxy_health_check_interval_ms")) {
        cfg.upstream_health_check_interval_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "upstream_health_check_timeout_ms") or std.mem.eql(u8, k, "proxy_health_check_timeout_ms")) {
        cfg.upstream_health_check_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "upstream_circuit_breaker") or std.mem.eql(u8, k, "upstream_circuit_breaker_enabled") or std.mem.eql(u8, k, "proxy_circuit_breaker")) {
        cfg.upstream_circuit_breaker_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "upstream_circuit_half_open_max") or std.mem.eql(u8, k, "proxy_circuit_half_open_max")) {
        cfg.upstream_circuit_half_open_max = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "upstream_slow_start_ms") or std.mem.eql(u8, k, "proxy_slow_start_ms")) {
        cfg.upstream_slow_start_ms = try parseConfigU32(v);
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

fn isDomainConfigFileName(name: []const u8) bool {
    return name.len > 0 and name[0] != '.' and std.mem.endsWith(u8, name, ".conf");
}

fn domainConfigNameFromPath(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const slash = std.mem.lastIndexOfAny(u8, path, "/\\");
    const base = if (slash) |pos| path[pos + 1 ..] else path;
    const stem = if (std.mem.endsWith(u8, base, ".conf")) base[0 .. base.len - ".conf".len] else base;
    if (stem.len == 0) return error.InvalidConfigValue;

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    for (stem) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '_' or c == '-') {
            try out.append(allocator, c);
        } else {
            try out.append(allocator, '-');
        }
    }
    return try out.toOwnedSlice(allocator);
}

fn stringLessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
}

fn setDomainStringPropertyDirect(allocator: std.mem.Allocator, domain: *DomainConfig, value: []const u8, field: DomainStringProperty) !void {
    if (value.len == 0) return error.InvalidConfigValue;
    const dupe_value = try allocator.dupe(u8, value);
    switch (field) {
        .static_dir => domain.static_dir = dupe_value,
        .index_file => domain.index_file = dupe_value,
        .php_root => domain.php_root = dupe_value,
        .php_binary => domain.php_binary = dupe_value,
        .php_index => domain.php_index = dupe_value,
        .php_fastcgi => domain.php_fastcgi = dupe_value,
        .tls_cert => domain.tls_cert = dupe_value,
        .tls_key => domain.tls_key = dupe_value,
    }
}

fn setDomainBoolPropertyDirect(domain: *DomainConfig, value: []const u8, field: DomainBoolProperty) !void {
    const parsed = try parseConfigBool(value);
    switch (field) {
        .serve_static_root => domain.serve_static_root = parsed,
        .php_info_page => domain.php_info_page = parsed,
        .php_front_controller => domain.php_front_controller = parsed,
    }
}

fn setDomainProxyPropertyDirect(allocator: std.mem.Allocator, domain: *DomainConfig, value: []const u8) !void {
    if (disablesOptionalUrl(value)) {
        domain.upstream = null;
    } else {
        domain.upstream = try parseUpstreamPool(allocator, value);
    }
}

fn setDomainUpstreamPolicyPropertyDirect(domain: *DomainConfig, value: []const u8) !void {
    domain.upstream_policy = try parseOptionalUpstreamPoolPolicy(value);
}

fn setDomainU32PropertyDirect(domain: *DomainConfig, value: []const u8, field: DomainU32Property) !void {
    const parsed = try parseConfigU32(value);
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .upstream_timeout_ms => domain.upstream_timeout_ms = parsed,
    }
}

fn applyDomainConfigLine(domain: *DomainConfig, allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
    const k = std.mem.trim(u8, key, " \t\r\n");
    const v = trimValue(value);

    if (std.mem.eql(u8, k, "server") or std.mem.eql(u8, k, "domain") or std.mem.eql(u8, k, "vhost") or std.mem.eql(u8, k, "name")) {
        if (!isDomainConfigNameValid(v)) return error.InvalidConfigValue;
        domain.name = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "server_name") or std.mem.eql(u8, k, "server_names")) {
        try appendServerNames(allocator, domain, v);
    } else if (std.mem.eql(u8, k, "root") or std.mem.eql(u8, k, "dir") or std.mem.eql(u8, k, "static_dir") or std.mem.eql(u8, k, "server_root")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .static_dir);
    } else if (std.mem.eql(u8, k, "index") or std.mem.eql(u8, k, "index_file") or std.mem.eql(u8, k, "server_index")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .index_file);
    } else if (std.mem.eql(u8, k, "serve_static") or std.mem.eql(u8, k, "serve_static_root")) {
        try setDomainBoolPropertyDirect(domain, v, .serve_static_root);
    } else if (std.mem.eql(u8, k, "php_root")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .php_root);
    } else if (std.mem.eql(u8, k, "php_binary") or std.mem.eql(u8, k, "php_bin")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .php_binary);
    } else if (std.mem.eql(u8, k, "php_fastcgi") or std.mem.eql(u8, k, "php_fpm") or std.mem.eql(u8, k, "fastcgi")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .php_fastcgi);
    } else if (std.mem.eql(u8, k, "php_index") or std.mem.eql(u8, k, "php_index_file")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .php_index);
    } else if (std.mem.eql(u8, k, "php_info_page") or std.mem.eql(u8, k, "phpinfo_page")) {
        try setDomainBoolPropertyDirect(domain, v, .php_info_page);
    } else if (std.mem.eql(u8, k, "php_front_controller") or std.mem.eql(u8, k, "php_front_controller_enabled")) {
        try setDomainBoolPropertyDirect(domain, v, .php_front_controller);
    } else if (std.mem.eql(u8, k, "tls_cert") or std.mem.eql(u8, k, "ssl_certificate")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .tls_cert);
    } else if (std.mem.eql(u8, k, "tls_key") or std.mem.eql(u8, k, "ssl_certificate_key")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .tls_key);
    } else if (std.mem.eql(u8, k, "proxy") or std.mem.eql(u8, k, "upstream")) {
        try setDomainProxyPropertyDirect(allocator, domain, v);
    } else if (std.mem.eql(u8, k, "upstream_policy") or std.mem.eql(u8, k, "proxy_policy") or std.mem.eql(u8, k, "load_balance")) {
        try setDomainUpstreamPolicyPropertyDirect(domain, v);
    } else if (std.mem.eql(u8, k, "upstream_timeout_ms") or std.mem.eql(u8, k, "proxy_timeout_ms") or std.mem.eql(u8, k, "php_timeout_ms") or std.mem.eql(u8, k, "fastcgi_timeout_ms")) {
        try setDomainU32PropertyDirect(domain, v, .upstream_timeout_ms);
    } else if (std.mem.eql(u8, k, "header") or std.mem.eql(u8, k, "response_header") or std.mem.eql(u8, k, "add_header")) {
        if (v.len > 0) try domain.response_headers.append(allocator, try parseResponseHeaderRule(allocator, v));
    } else if (std.mem.eql(u8, k, "redirect") or std.mem.eql(u8, k, "redir")) {
        if (v.len > 0) try domain.redirects.append(allocator, try parseRedirectRule(allocator, v));
    } else if (std.mem.eql(u8, k, "route")) {
        try setRouteLineFor(&domain.routes, allocator, v);
    } else if (findRoutePropertyName(k, "route_dir.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "route_static_dir.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "route_index.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "route_index_file.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "route_php_root.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_root);
    } else if (findRoutePropertyName(k, "route_php_bin.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "route_php_binary.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "route_php_fastcgi.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "route_php_fpm.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "route_fastcgi.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "route_php_index.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "route_php_index_file.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "route_php_info_page.")) |name| {
        try setRouteBoolProperty(&domain.routes, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "route_phpinfo_page.")) |name| {
        try setRouteBoolProperty(&domain.routes, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "route_php_front_controller.")) |name| {
        try setRouteBoolProperty(&domain.routes, name, v, .php_front_controller);
    } else if (findRoutePropertyName(k, "route_proxy.")) |name| {
        try setRouteProxyProperty(&domain.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_upstream.")) |name| {
        try setRouteProxyProperty(&domain.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_proxy_policy.")) |name| {
        try setRouteUpstreamPolicyProperty(&domain.routes, name, v);
    } else if (findRoutePropertyName(k, "route_upstream_policy.")) |name| {
        try setRouteUpstreamPolicyProperty(&domain.routes, name, v);
    } else if (findRoutePropertyName(k, "route_load_balance.")) |name| {
        try setRouteUpstreamPolicyProperty(&domain.routes, name, v);
    } else if (findRoutePropertyName(k, "route_upstream_timeout_ms.")) |name| {
        try setRouteU32Property(&domain.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_proxy_timeout_ms.")) |name| {
        try setRouteU32Property(&domain.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_php_timeout_ms.")) |name| {
        try setRouteU32Property(&domain.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_fastcgi_timeout_ms.")) |name| {
        try setRouteU32Property(&domain.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_strip_prefix.")) |name| {
        try setRouteBoolProperty(&domain.routes, name, v, .strip_prefix);
    } else if (findRoutePropertyName(k, "route_header.")) |name| {
        try appendRouteResponseHeader(&domain.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_response_header.")) |name| {
        try appendRouteResponseHeader(&domain.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_add_header.")) |name| {
        try appendRouteResponseHeader(&domain.routes, allocator, name, v);
    } else {
        return error.UnknownConfigKey;
    }
}

fn loadDomainConfigFile(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig, path: []const u8) !void {
    const default_name = try domainConfigNameFromPath(allocator, path);
    var domain = try initDomainConfig(allocator, default_name);

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
            std.debug.print("Domain config error in {s}:{d}: expected key = value\n", .{ path, line_number });
            return error.MalformedConfigLine;
        };
        const key = line[0..eq];
        const value = if (eq + 1 < line.len) line[eq + 1 ..] else "";
        applyDomainConfigLine(&domain, allocator, key, value) catch |err| {
            std.debug.print("Domain config error in {s}:{d}: {s}: {}\n", .{ path, line_number, trimValue(key), err });
            return err;
        };
    }

    if (findDomainConfigMutable(cfg, domain.name) != null) return error.DuplicateConfigDomain;
    try cfg.domains.append(allocator, domain);
}

fn loadDomainConfigDir(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig, dir_path: []const u8) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
    defer dir.close(io);

    var paths = std.ArrayList([]const u8).empty;
    defer paths.deinit(allocator);

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (!isDomainConfigFileName(entry.name)) continue;
        const full_path = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        try paths.append(allocator, full_path);
    }

    std.sort.insertion([]const u8, paths.items, {}, stringLessThan);
    for (paths.items) |path| {
        try loadDomainConfigFile(io, allocator, cfg, path);
    }
}

fn loadConfiguredDomainConfigs(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
    if (cfg.domain_config_dir) |dir_path| {
        try loadDomainConfigDir(io, allocator, cfg, dir_path);
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
    if (cfg.upstream_keepalive_max_requests == 0) {
        cfg.upstream_keepalive_max_requests = DEFAULT_UPSTREAM_KEEPALIVE_MAX_REQUESTS;
    }
    if (cfg.upstream_keepalive_idle_timeout_ms == 0) {
        cfg.upstream_keepalive_idle_timeout_ms = DEFAULT_UPSTREAM_KEEPALIVE_IDLE_TIMEOUT_MS;
    }
    if (cfg.fastcgi_keepalive_max_requests == 0) {
        cfg.fastcgi_keepalive_max_requests = DEFAULT_FASTCGI_KEEPALIVE_MAX_REQUESTS;
    }
    if (cfg.fastcgi_keepalive_idle_timeout_ms == 0) {
        cfg.fastcgi_keepalive_idle_timeout_ms = DEFAULT_FASTCGI_KEEPALIVE_IDLE_TIMEOUT_MS;
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

fn isSafeRelativeScriptPath(path: []const u8) bool {
    return path.len > 0 and
        path[0] != '/' and
        std.mem.indexOf(u8, path, "..") == null and
        std.mem.indexOfScalar(u8, path, '\x00') == null;
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
    if (route.php_fastcgi) |endpoint| {
        if (!disablesOptionalUrl(endpoint)) try validateFastcgiEndpoint(endpoint);
    }
    if (route.php_index) |php_index| {
        if (!isSafeRelativeScriptPath(php_index)) return error.InvalidConfigValue;
    }
    if (route.upstream) |pool| {
        try validateUpstreamPool(pool);
    }
    if (route.handler == .proxy and route.upstream == null and fallback_upstream == null) {
        return error.InvalidConfigValue;
    }
    if (route.upstream_timeout_ms) |timeout_ms| {
        if (timeout_ms == 0) return error.InvalidConfigValue;
    }
}

fn validateConfig(cfg: *const ServerConfig) !void {
    if (cfg.host.len == 0) return error.InvalidConfigValue;
    if (cfg.port == 0) return error.InvalidConfigValue;
    if (cfg.static_dir.len == 0) return error.InvalidConfigValue;
    if (cfg.index_file.len == 0) return error.InvalidConfigValue;
    if (cfg.php_root.len == 0) return error.InvalidConfigValue;
    if (cfg.php_binary.len == 0) return error.InvalidConfigValue;
    if (cfg.php_fastcgi) |endpoint| try validateFastcgiEndpoint(endpoint);
    if (!isSafeRelativeScriptPath(cfg.php_index)) return error.InvalidConfigValue;
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
    if (cfg.fastcgi_keepalive_enabled and cfg.fastcgi_keepalive_max_requests == 0) return error.InvalidConfigValue;
    if (cfg.upstream_max_failures > 0 and cfg.upstream_fail_timeout_ms == 0) return error.InvalidConfigValue;
    if (cfg.upstream_health_check_enabled) {
        if (cfg.upstream_health_check_path.len == 0 or cfg.upstream_health_check_path[0] != '/') return error.InvalidConfigValue;
        if (cfg.upstream_health_check_interval_ms == 0) return error.InvalidConfigValue;
        if (cfg.upstream_health_check_timeout_ms == 0) return error.InvalidConfigValue;
    }
    if (cfg.upstream_circuit_breaker_enabled and cfg.upstream_circuit_half_open_max == 0) return error.InvalidConfigValue;
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
        if (domain.php_fastcgi) |endpoint| {
            if (!disablesOptionalUrl(endpoint)) try validateFastcgiEndpoint(endpoint);
        }
        if (domain.php_index) |php_index| {
            if (!isSafeRelativeScriptPath(php_index)) return error.InvalidConfigValue;
        }
        if ((domain.tls_cert == null) != (domain.tls_key == null)) return error.InvalidConfigValue;
        if (domain.upstream) |pool| {
            try validateUpstreamPool(pool);
        }
        if (domain.upstream_timeout_ms) |timeout_ms| {
            if (timeout_ms == 0) return error.InvalidConfigValue;
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
    const base_metrics = try std.fmt.allocPrint(
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
            "# HELP layerline_upstream_requests_total Reverse proxy upstream forwarding attempts.\n" ++
            "# TYPE layerline_upstream_requests_total counter\n" ++
            "layerline_upstream_requests_total {d}\n" ++
            "# HELP layerline_upstream_failures_total Reverse proxy upstream attempts that returned an unexpected transport error.\n" ++
            "# TYPE layerline_upstream_failures_total counter\n" ++
            "layerline_upstream_failures_total {d}\n" ++
            "# HELP layerline_upstream_retries_total Reverse proxy attempts made after an earlier upstream target failed.\n" ++
            "# TYPE layerline_upstream_retries_total counter\n" ++
            "layerline_upstream_retries_total {d}\n" ++
            "# HELP layerline_upstream_ejections_total Upstream targets temporarily ejected by passive health checks.\n" ++
            "# TYPE layerline_upstream_ejections_total counter\n" ++
            "layerline_upstream_ejections_total {d}\n" ++
            "# HELP layerline_upstream_ejected_skips_total Proxy attempts skipped because a target is in passive-health cooldown.\n" ++
            "# TYPE layerline_upstream_ejected_skips_total counter\n" ++
            "layerline_upstream_ejected_skips_total {d}\n" ++
            "# HELP layerline_upstream_connections_opened_total New TCP connections opened to upstream targets.\n" ++
            "# TYPE layerline_upstream_connections_opened_total counter\n" ++
            "layerline_upstream_connections_opened_total {d}\n" ++
            "# HELP layerline_upstream_connections_reused_total Idle upstream TCP connections reused from a keep-alive pool.\n" ++
            "# TYPE layerline_upstream_connections_reused_total counter\n" ++
            "layerline_upstream_connections_reused_total {d}\n" ++
            "# HELP layerline_upstream_connections_pooled_total Upstream TCP connections returned to an idle keep-alive pool.\n" ++
            "# TYPE layerline_upstream_connections_pooled_total counter\n" ++
            "layerline_upstream_connections_pooled_total {d}\n" ++
            "# HELP layerline_upstream_connections_discarded_total Upstream TCP connections closed instead of pooled or reused.\n" ++
            "# TYPE layerline_upstream_connections_discarded_total counter\n" ++
            "layerline_upstream_connections_discarded_total {d}\n" ++
            "# HELP layerline_upstream_health_checks_total Active upstream health probes run.\n" ++
            "# TYPE layerline_upstream_health_checks_total counter\n" ++
            "layerline_upstream_health_checks_total {d}\n" ++
            "# HELP layerline_upstream_health_check_failures_total Active upstream health probes that failed or returned unhealthy status.\n" ++
            "# TYPE layerline_upstream_health_check_failures_total counter\n" ++
            "layerline_upstream_health_check_failures_total {d}\n" ++
            "# HELP layerline_upstream_health_check_recoveries_total Active upstream health probes that restored an unavailable target.\n" ++
            "# TYPE layerline_upstream_health_check_recoveries_total counter\n" ++
            "layerline_upstream_health_check_recoveries_total {d}\n" ++
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
            ServerMetrics.load(&server_metrics.upstream_requests_total),
            ServerMetrics.load(&server_metrics.upstream_failures_total),
            ServerMetrics.load(&server_metrics.upstream_retries_total),
            ServerMetrics.load(&server_metrics.upstream_ejections_total),
            ServerMetrics.load(&server_metrics.upstream_ejected_skips_total),
            ServerMetrics.load(&server_metrics.upstream_connections_opened_total),
            ServerMetrics.load(&server_metrics.upstream_connections_reused_total),
            ServerMetrics.load(&server_metrics.upstream_connections_pooled_total),
            ServerMetrics.load(&server_metrics.upstream_connections_discarded_total),
            ServerMetrics.load(&server_metrics.upstream_health_checks_total),
            ServerMetrics.load(&server_metrics.upstream_health_check_failures_total),
            ServerMetrics.load(&server_metrics.upstream_health_check_recoveries_total),
            ServerMetrics.load(&server_metrics.h3_responses_total),
            ServerMetrics.load(&server_metrics.h3_packets_sent_total),
        },
    );
    defer allocator.free(base_metrics);

    const fastcgi_metrics = try std.fmt.allocPrint(
        allocator,
        "# HELP layerline_fastcgi_connections_opened_total New connections opened to FastCGI workers.\n" ++
            "# TYPE layerline_fastcgi_connections_opened_total counter\n" ++
            "layerline_fastcgi_connections_opened_total {d}\n" ++
            "# HELP layerline_fastcgi_connections_reused_total Idle FastCGI worker connections reused from the keep-alive pool.\n" ++
            "# TYPE layerline_fastcgi_connections_reused_total counter\n" ++
            "layerline_fastcgi_connections_reused_total {d}\n" ++
            "# HELP layerline_fastcgi_connections_pooled_total FastCGI worker connections returned to the idle keep-alive pool.\n" ++
            "# TYPE layerline_fastcgi_connections_pooled_total counter\n" ++
            "layerline_fastcgi_connections_pooled_total {d}\n" ++
            "# HELP layerline_fastcgi_connections_discarded_total FastCGI worker connections closed instead of pooled or reused.\n" ++
            "# TYPE layerline_fastcgi_connections_discarded_total counter\n" ++
            "layerline_fastcgi_connections_discarded_total {d}\n",
        .{
            ServerMetrics.load(&server_metrics.fastcgi_connections_opened_total),
            ServerMetrics.load(&server_metrics.fastcgi_connections_reused_total),
            ServerMetrics.load(&server_metrics.fastcgi_connections_pooled_total),
            ServerMetrics.load(&server_metrics.fastcgi_connections_discarded_total),
        },
    );
    defer allocator.free(fastcgi_metrics);

    return std.mem.concat(allocator, u8, &.{ base_metrics, fastcgi_metrics });
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
    tls_channel: ?*TlsChannel = null,
};

fn proxyRawStream(ctx: RawProxyContext) void {
    bindThreadIo(ctx.io);
    current_tls_channel = ctx.tls_channel;
    defer current_tls_channel = null;

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = streamRead(ctx.src, &buf) catch break;
        if (n == 0) break;
        streamWriteAll(ctx.dst, buf[0..n]) catch break;
    }
    ctx.dst.shutdown(activeIo(), .send) catch {};
}

fn proxyRawBidirectional(a: std.Io.net.Stream, b: std.Io.net.Stream, initial_payload: []const u8) !void {
    if (initial_payload.len > 0) {
        try streamWriteAll(b, initial_payload);
    }

    const io = activeIo();
    const tls_channel = current_tls_channel;
    const t1 = try std.Thread.spawn(
        .{},
        proxyRawStream,
        .{RawProxyContext{ .io = io, .src = a, .dst = b, .tls_channel = tls_channel }},
    );
    const t2 = try std.Thread.spawn(
        .{},
        proxyRawStream,
        .{RawProxyContext{ .io = io, .src = b, .dst = a, .tls_channel = tls_channel }},
    );
    t1.join();
    t2.join();
}

fn isHttp3OverTcpProbe(bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    return bytes[0] == 0x00;
}

fn readTlsClientHelloRecord(stream: std.Io.net.Stream, allocator: std.mem.Allocator, prefill: []const u8) ![]u8 {
    var header: [5]u8 = undefined;
    const copied_header: usize = @min(prefill.len, header.len);
    if (copied_header > 0) @memcpy(header[0..copied_header], prefill[0..copied_header]);
    var header_used: usize = copied_header;
    while (header_used < header.len) {
        const n = try rawStreamRead(stream, header[header_used..]);
        if (n == 0) return error.ConnectionClosed;
        header_used += n;
    }

    const record_len = try tls_client_hello.recordLength(&header);
    if (record_len > 5 + 16 * 1024) return error.RequestTooLarge;
    const record = try allocator.alloc(u8, record_len);
    @memcpy(record[0..header.len], &header);
    const copied_body: usize = if (prefill.len > header.len) @min(prefill.len - header.len, record_len - header.len) else 0;
    if (copied_body > 0) {
        @memcpy(record[header.len .. header.len + copied_body], prefill[header.len .. header.len + copied_body]);
    }

    var used = header.len + copied_body;
    while (used < record.len) {
        const n = try rawStreamRead(stream, record[used..]);
        if (n == 0) return error.ConnectionClosed;
        used += n;
    }
    return record;
}

fn sendTlsFatalAlert(stream: std.Io.net.Stream, description: u8) !void {
    const alert = [_]u8{
        0x15,
        0x03,
        0x03,
        0x00,
        0x02,
        0x02,
        description,
    };
    try rawStreamWriteAll(stream, &alert);
}

const TlsChannel = struct {
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    client_application_keys: tls13_native.TlsRecordKeys,
    server_application_keys: tls13_native.TlsRecordKeys,
    client_sequence: u64 = 0,
    server_sequence: u64 = 0,
    pending_plaintext: ?[]u8 = null,
    pending_offset: usize = 0,

    fn deinit(self: *TlsChannel) void {
        if (self.pending_plaintext) |pending| self.allocator.free(pending);
        self.pending_plaintext = null;
        self.pending_offset = 0;
    }
};

const NativeTlsResult = struct {
    channel: TlsChannel,
    alpn: ?[]const u8,
};

const TlsSigningKeyKind = enum {
    configured_ecdsa,
    configured_rsa,
    generated_ecdsa,
    generated_ed25519,
};

fn selectedTlsAlpn(info: tls_client_hello.ClientHelloInfo) ?[]const u8 {
    if (info.offers_h2) return "h2";
    if (info.offers_http11) return "http/1.1";
    return null;
}

fn selectedTlsMaterialForClientHello(cfg: *const ServerConfig, info: tls_client_hello.ClientHelloInfo) ?tls_pem.ConfiguredTlsMaterial {
    if (info.sni) |server_name| {
        if (findDomainForHost(cfg, server_name)) |domain| {
            if (domain.tls_material) |material| return material;
        }
    }
    return cfg.tls_material;
}

fn tlsClientHelloHandshakeMessage(record: []const u8) ![]const u8 {
    if (record.len < 5) return error.Truncated;
    const record_len = (@as(usize, record[3]) << 8) | record[4];
    if (record.len < 5 + record_len) return error.Truncated;
    return record[5 .. 5 + record_len];
}

fn readTlsRecordRaw(stream: std.Io.net.Stream, allocator: std.mem.Allocator) ![]u8 {
    var header: [5]u8 = undefined;
    var used: usize = 0;
    while (used < header.len) {
        const n = try rawStreamRead(stream, header[used..]);
        if (n == 0) return error.ConnectionClosed;
        used += n;
    }

    const payload_len = (@as(usize, header[3]) << 8) | header[4];
    if (payload_len > TLS_MAX_RECORD_BYTES - 5) return error.RequestTooLarge;
    const record = try allocator.alloc(u8, 5 + payload_len);
    @memcpy(record[0..5], &header);
    used = 5;
    while (used < record.len) {
        const n = try rawStreamRead(stream, record[used..]);
        if (n == 0) return error.ConnectionClosed;
        used += n;
    }
    return record;
}

fn sendTlsPlainRecord(stream: std.Io.net.Stream, content_type: u8, payload: []const u8) !void {
    if (payload.len > TLS_MAX_INNER_PLAINTEXT_BYTES) return error.TlsPlaintextTooLarge;
    var header: [5]u8 = .{ content_type, 0x03, 0x03, 0, 0 };
    std.mem.writeInt(u16, header[3..5], @intCast(payload.len), .big);
    try rawStreamWriteAll(stream, &header);
    if (payload.len > 0) try rawStreamWriteAll(stream, payload);
}

fn sendTlsEncryptedRecord(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    keys: tls13_native.TlsRecordKeys,
    sequence: *u64,
    inner_content_type: u8,
    payload: []const u8,
) !void {
    if (sequence.* == std.math.maxInt(u64)) return error.TlsSequenceOverflow;
    const record = try tls13_native.encryptTlsRecord(allocator, keys, sequence.*, inner_content_type, payload);
    defer allocator.free(record);
    try rawStreamWriteAll(stream, record);
    sequence.* += 1;
}

fn tlsReadApplicationData(channel: *TlsChannel, out: []u8) !usize {
    if (out.len == 0) return 0;

    while (true) {
        if (channel.pending_plaintext) |pending| {
            const available = pending[channel.pending_offset..];
            const copied = @min(out.len, available.len);
            if (copied > 0) {
                @memcpy(out[0..copied], available[0..copied]);
                channel.pending_offset += copied;
                if (channel.pending_offset >= pending.len) {
                    channel.allocator.free(pending);
                    channel.pending_plaintext = null;
                    channel.pending_offset = 0;
                }
                return copied;
            }

            channel.allocator.free(pending);
            channel.pending_plaintext = null;
            channel.pending_offset = 0;
        }

        const record = try readTlsRecordRaw(channel.stream, channel.allocator);
        defer channel.allocator.free(record);

        switch (record[0]) {
            TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC => continue,
            TLS_CONTENT_TYPE_ALERT => return 0,
            TLS_CONTENT_TYPE_APPLICATION_DATA => {},
            else => return error.UnexpectedTlsRecordType,
        }

        if (channel.client_sequence == std.math.maxInt(u64)) return error.TlsSequenceOverflow;
        var decrypted = try tls13_native.decryptTlsRecord(
            channel.allocator,
            channel.client_application_keys,
            channel.client_sequence,
            record,
        );
        channel.client_sequence += 1;

        switch (decrypted.content_type) {
            TLS_CONTENT_TYPE_APPLICATION_DATA => {
                if (decrypted.payload.len == 0) {
                    decrypted.deinit(channel.allocator);
                    continue;
                }
                channel.pending_plaintext = decrypted.payload;
                channel.pending_offset = 0;
            },
            TLS_CONTENT_TYPE_ALERT => {
                decrypted.deinit(channel.allocator);
                return 0;
            },
            TLS_CONTENT_TYPE_HANDSHAKE => {
                decrypted.deinit(channel.allocator);
                continue;
            },
            else => {
                decrypted.deinit(channel.allocator);
                return error.UnexpectedTlsInnerContentType;
            },
        }
    }
}

fn tlsWriteApplicationData(channel: *TlsChannel, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const chunk_len = @min(bytes.len - offset, TLS_MAX_INNER_PLAINTEXT_BYTES - 1);
        try sendTlsEncryptedRecord(
            channel.stream,
            channel.allocator,
            channel.server_application_keys,
            &channel.server_sequence,
            TLS_CONTENT_TYPE_APPLICATION_DATA,
            bytes[offset .. offset + chunk_len],
        );
        offset += chunk_len;
    }
}

fn verifyClientFinished(plain: tls13_native.DecryptedRecord, expected_verify_data: [32]u8) !void {
    if (plain.content_type != TLS_CONTENT_TYPE_HANDSHAKE) return error.BadTlsFinished;
    if (plain.payload.len != 4 + expected_verify_data.len) return error.BadTlsFinished;
    if (plain.payload[0] != 0x14) return error.BadTlsFinished;
    const finished_len = (@as(usize, plain.payload[1]) << 16) |
        (@as(usize, plain.payload[2]) << 8) |
        @as(usize, plain.payload[3]);
    if (finished_len != expected_verify_data.len) return error.BadTlsFinished;
    const client_verify_data: [32]u8 = plain.payload[4..][0..32].*;
    if (!std.crypto.timing_safe.eql([32]u8, expected_verify_data, client_verify_data)) {
        return error.BadTlsFinishedVerifyData;
    }
}

fn establishNativeTls13(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    client_hello_record: []const u8,
    info: tls_client_hello.ClientHelloInfo,
) !NativeTlsResult {
    if (!info.supports_tls13) return error.UnsupportedTlsVersion;
    if (!info.offers_aes_128_gcm_sha256) return error.UnsupportedTlsCipherSuite;
    if (!info.offers_ecdsa_secp256r1_sha256 and !info.offers_rsa_pss_rsae_sha256 and !info.offers_ed25519) {
        return error.UnsupportedTlsSignatureScheme;
    }
    const client_x25519 = info.x25519_key_share orelse return error.MissingTlsKeyShare;
    const alpn = selectedTlsAlpn(info);
    if (info.alpn != null and alpn == null) return error.NoApplicationProtocol;

    const io = activeIo();
    var server_random: [32]u8 = undefined;
    io.random(&server_random);
    const server_key_pair = tls13_native.X25519.KeyPair.generate(io);
    const shared_secret = try tls13_native.X25519.scalarmult(server_key_pair.secret_key, client_x25519);

    const legacy_session_id = info.legacy_session_id orelse "";
    const server_hello = try tls13_native.buildServerHello(allocator, .{
        .legacy_session_id = legacy_session_id,
        .random = server_random,
        .x25519_public_key = server_key_pair.public_key,
    });
    defer allocator.free(server_hello);

    const client_hello = try tlsClientHelloHandshakeMessage(client_hello_record);
    const hello_hash = tls13_native.transcriptHash(&.{ client_hello, server_hello });
    const traffic = tls13_native.deriveTrafficSecrets(shared_secret, hello_hash);
    const client_handshake_keys = tls13_native.deriveTlsRecordKeys(traffic.client_handshake_traffic_secret);
    const server_handshake_keys = tls13_native.deriveTlsRecordKeys(traffic.server_handshake_traffic_secret);

    const encrypted_extensions = try tls13_native.buildTcpEncryptedExtensions(allocator, alpn);
    defer allocator.free(encrypted_extensions);

    const cert_name = info.sni orelse "localhost";
    const selected_material = selectedTlsMaterialForClientHello(cfg, info);
    const signing_key_kind: TlsSigningKeyKind = if (selected_material) |material| switch (material.private_key) {
        .ecdsa_p256 => if (info.offers_ecdsa_secp256r1_sha256) .configured_ecdsa else return error.UnsupportedTlsSignatureScheme,
        .rsa => if (info.offers_rsa_pss_rsae_sha256) .configured_rsa else return error.UnsupportedTlsSignatureScheme,
    } else if (info.offers_ecdsa_secp256r1_sha256)
        .generated_ecdsa
    else if (info.offers_ed25519)
        .generated_ed25519
    else
        return error.UnsupportedTlsSignatureScheme;

    const generated_ecdsa_key_pair = if (signing_key_kind == .generated_ecdsa)
        tls13_native.EcdsaP256Sha256.KeyPair.generate(io)
    else
        null;
    const generated_ed25519_key_pair = if (signing_key_kind == .generated_ed25519)
        tls13_native.Ed25519.KeyPair.generate(io)
    else
        null;
    var generated_cert_der: ?[]u8 = null;
    defer if (generated_cert_der) |cert| allocator.free(cert);

    const certificate = switch (signing_key_kind) {
        .configured_ecdsa, .configured_rsa => try tls13_native.buildCertificate(allocator, selected_material.?.certificate_chain),
        .generated_ecdsa => blk: {
            generated_cert_der = try tls13_native.buildSelfSignedEcdsaP256Sha256Certificate(allocator, generated_ecdsa_key_pair.?, cert_name);
            break :blk try tls13_native.buildCertificate(allocator, &.{generated_cert_der.?});
        },
        .generated_ed25519 => blk: {
            generated_cert_der = try tls13_native.buildSelfSignedEd25519Certificate(allocator, generated_ed25519_key_pair.?, cert_name);
            break :blk try tls13_native.buildCertificate(allocator, &.{generated_cert_der.?});
        },
    };
    defer allocator.free(certificate);

    const cert_verify_hash = tls13_native.transcriptHash(&.{ client_hello, server_hello, encrypted_extensions, certificate });
    const cert_signature = switch (signing_key_kind) {
        .configured_ecdsa => blk: {
            const key_pair = selected_material.?.private_key.ecdsa_p256;
            break :blk try tls13_native.signCertificateVerifyEcdsaP256Sha256(allocator, key_pair, cert_verify_hash);
        },
        .configured_rsa => blk: {
            const key = selected_material.?.private_key.rsa;
            break :blk try tls13_native.signCertificateVerifyRsaPssSha256(io, allocator, key, cert_verify_hash);
        },
        .generated_ecdsa => try tls13_native.signCertificateVerifyEcdsaP256Sha256(allocator, generated_ecdsa_key_pair.?, cert_verify_hash),
        .generated_ed25519 => blk: {
            const signature = try tls13_native.signCertificateVerifyEd25519(generated_ed25519_key_pair.?, cert_verify_hash);
            break :blk try allocator.dupe(u8, &signature);
        },
    };
    defer allocator.free(cert_signature);
    const signature_scheme: tls13_native.SignatureScheme = switch (signing_key_kind) {
        .configured_ecdsa, .generated_ecdsa => .ecdsa_secp256r1_sha256,
        .configured_rsa => .rsa_pss_rsae_sha256,
        .generated_ed25519 => .ed25519,
    };
    const certificate_verify = try tls13_native.buildCertificateVerify(allocator, signature_scheme, cert_signature);
    defer allocator.free(certificate_verify);

    const finished_hash = tls13_native.transcriptHash(&.{
        client_hello,
        server_hello,
        encrypted_extensions,
        certificate,
        certificate_verify,
    });
    const server_verify_data = tls13_native.finishedVerifyData(traffic.server_finished_key, finished_hash);
    const server_finished = try tls13_native.buildFinished(allocator, server_verify_data);
    defer allocator.free(server_finished);

    const application_hash = tls13_native.transcriptHash(&.{
        client_hello,
        server_hello,
        encrypted_extensions,
        certificate,
        certificate_verify,
        server_finished,
    });

    try sendTlsPlainRecord(stream, TLS_CONTENT_TYPE_HANDSHAKE, server_hello);
    var server_handshake_sequence: u64 = 0;
    try sendTlsEncryptedRecord(stream, allocator, server_handshake_keys, &server_handshake_sequence, TLS_CONTENT_TYPE_HANDSHAKE, encrypted_extensions);
    try sendTlsEncryptedRecord(stream, allocator, server_handshake_keys, &server_handshake_sequence, TLS_CONTENT_TYPE_HANDSHAKE, certificate);
    try sendTlsEncryptedRecord(stream, allocator, server_handshake_keys, &server_handshake_sequence, TLS_CONTENT_TYPE_HANDSHAKE, certificate_verify);
    try sendTlsEncryptedRecord(stream, allocator, server_handshake_keys, &server_handshake_sequence, TLS_CONTENT_TYPE_HANDSHAKE, server_finished);

    var client_handshake_sequence: u64 = 0;
    while (true) {
        const client_record = try readTlsRecordRaw(stream, allocator);
        defer allocator.free(client_record);
        if (client_record[0] == TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC) continue;
        if (client_record[0] != TLS_CONTENT_TYPE_APPLICATION_DATA) return error.UnexpectedTlsRecordType;

        var client_finished = try tls13_native.decryptTlsRecord(allocator, client_handshake_keys, client_handshake_sequence, client_record);
        defer client_finished.deinit(allocator);
        client_handshake_sequence += 1;
        const expected_client_verify_data = tls13_native.finishedVerifyData(traffic.client_finished_key, application_hash);
        try verifyClientFinished(client_finished, expected_client_verify_data);
        break;
    }

    const app_secrets = tls13_native.deriveApplicationTrafficSecrets(traffic.master_secret, application_hash);
    return .{
        .channel = .{
            .stream = stream,
            .allocator = allocator,
            .client_application_keys = tls13_native.deriveTlsRecordKeys(app_secrets.client_application_traffic_secret),
            .server_application_keys = tls13_native.deriveTlsRecordKeys(app_secrets.server_application_traffic_secret),
        },
        .alpn = alpn,
    };
}

fn handleTlsClientHelloProbe(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    prefill: []const u8,
    process_env: *const std.process.Environ.Map,
) anyerror!void {
    const record = try readTlsClientHelloRecord(stream, allocator, prefill);
    defer allocator.free(record);
    var info = tls_client_hello.parse(allocator, record) catch |err| {
        std.debug.print("TLS ClientHello parse failed before native TLS termination: {}\n", .{err});
        try sendTlsFatalAlert(stream, TLS_ALERT_HANDSHAKE_FAILURE);
        return;
    };
    defer info.deinit(allocator);

    std.debug.print(
        "TLS ClientHello sni={s} alpn={s} tls13={} aes128gcm={} ecdsa_p256={} rsa_pss={} ed25519={} h2={} http11={} tls_configured={}\n",
        .{
            info.sni orelse "(none)",
            info.alpn orelse "(none)",
            info.supports_tls13,
            info.offers_aes_128_gcm_sha256,
            info.offers_ecdsa_secp256r1_sha256,
            info.offers_rsa_pss_rsae_sha256,
            info.offers_ed25519,
            info.offers_h2,
            info.offers_http11,
            cfg.tls_enabled,
        },
    );

    var established = establishNativeTls13(stream, allocator, cfg, record, info) catch |err| {
        std.debug.print("Native TLS 1.3 handshake failed: {}\n", .{err});
        const alert = switch (err) {
            error.NoApplicationProtocol => TLS_ALERT_NO_APPLICATION_PROTOCOL,
            else => TLS_ALERT_HANDSHAKE_FAILURE,
        };
        try sendTlsFatalAlert(stream, alert);
        return;
    };
    defer established.channel.deinit();

    current_tls_channel = &established.channel;
    defer current_tls_channel = null;

    std.debug.print(
        "TLS 1.3 native connection accepted sni={s} alpn={s}\n",
        .{ info.sni orelse "(none)", established.alpn orelse "(none)" },
    );

    if (established.alpn) |alpn| {
        if (std.mem.eql(u8, alpn, "h2")) {
            try handleHttp2Preface(io, stream, allocator, cfg, "", process_env);
            return;
        }
    }

    try handleConnection(io, stream, cfg, allocator, process_env);
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

    if (isH2cUpgradeHeaders(headers)) {
        return HttpRequest{
            .method = method,
            .path = path,
            .query = query,
            .headers = headers,
            .version = version,
            .body = "",
            .close_connection = true,
            .h2c_upgrade_tail = body_tail,
        };
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

const H2BufferedResponse = struct {
    status_code: u16,
    content_type: []const u8,
    body: []const u8,
    headers: []const h2_native.Header = &.{},
};

const H2Frame = struct {
    header: h2_native.FrameHeader,
    payload: []u8,
};

const H2PendingReader = struct {
    stream: std.Io.net.Stream,
    pending: []const u8,

    fn readExact(self: *H2PendingReader, out: []u8) !void {
        var written: usize = 0;
        if (self.pending.len > 0) {
            const n = @min(out.len, self.pending.len);
            @memcpy(out[0..n], self.pending[0..n]);
            self.pending = self.pending[n..];
            written = n;
        }

        while (written < out.len) {
            const n = try streamRead(self.stream, out[written..]);
            if (n == 0) return error.ConnectionClosed;
            written += n;
        }
    }
};

fn h2HeaderNameIndex(name: []const u8) ?u64 {
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

fn isSkippedHttp2ResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "content-type") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-authenticate") or
        std.ascii.eqlIgnoreCase(name, "proxy-authorization") or
        std.ascii.eqlIgnoreCase(name, "te") or
        std.ascii.eqlIgnoreCase(name, "trailer") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade");
}

fn lowerHeaderName(allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
    const lowered = try allocator.alloc(u8, name.len);
    for (name, 0..) |byte, index| {
        lowered[index] = std.ascii.toLower(byte);
    }
    return lowered;
}

fn appendHttp2Header(allocator: std.mem.Allocator, block: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
    if (h2HeaderNameIndex(name)) |index| {
        try h2_native.appendHeaderIndexedName(allocator, block, index, value);
        return;
    }

    const lowered = try lowerHeaderName(allocator, name);
    try h2_native.appendHeaderLiteralName(allocator, block, lowered, value);
}

fn sendHttp2Frame(stream: std.Io.net.Stream, frame_type: u8, flags: u8, stream_id: u32, payload: []const u8) !void {
    var header: [9]u8 = undefined;
    const rendered = try h2_native.writeFrameHeader(&header, payload.len, frame_type, flags, stream_id);
    try streamWriteAll(stream, rendered);
    if (payload.len > 0) try streamWriteAll(stream, payload);
}

fn sendHttp2Response(stream: std.Io.net.Stream, allocator: std.mem.Allocator, stream_id: u32, response: H2BufferedResponse, is_head: bool) !void {
    var header_block = std.ArrayList(u8).empty;
    defer header_block.deinit(allocator);

    try h2_native.appendStatus(allocator, &header_block, response.status_code);
    try h2_native.appendHeaderIndexedName(allocator, &header_block, 54, SERVER_HEADER);
    try h2_native.appendHeaderIndexedName(allocator, &header_block, 31, response.content_type);

    var len_buf: [32]u8 = undefined;
    const body_len = if (http_response.canSendBody(response.status_code, is_head)) response.body.len else 0;
    const len_text = try std.fmt.bufPrint(&len_buf, "{d}", .{body_len});
    try h2_native.appendHeaderIndexedName(allocator, &header_block, 28, len_text);

    for (response.headers) |header| {
        if (isSkippedHttp2ResponseHeader(header.name)) continue;
        try appendHttp2Header(allocator, &header_block, header.name, header.value);
    }
    for (current_response_headers) |header| {
        if (isSkippedHttp2ResponseHeader(header.name)) continue;
        try appendHttp2Header(allocator, &header_block, header.name, header.value);
    }

    const header_flags = h2_native.FLAG_END_HEADERS | if (body_len == 0) h2_native.FLAG_END_STREAM else @as(u8, 0);
    try sendHttp2Frame(stream, h2_native.FRAME_HEADERS, header_flags, stream_id, header_block.items);

    if (body_len > 0) {
        var sent: usize = 0;
        while (sent < body_len) {
            const chunk_len = @min(@as(usize, 16 * 1024), body_len - sent);
            const flags = if (sent + chunk_len == body_len) h2_native.FLAG_END_STREAM else @as(u8, 0);
            try sendHttp2Frame(stream, h2_native.FRAME_DATA, flags, stream_id, response.body[sent .. sent + chunk_len]);
            sent += chunk_len;
        }
    }

    server_metrics.responseSent(response.status_code, body_len);
}

fn h2CoolErrorResponse(allocator: std.mem.Allocator, status_code: u16, status_text: []const u8, detail: []const u8) !H2BufferedResponse {
    const body = try renderCoolErrorPage(allocator, status_code, status_text, detail);
    return .{ .status_code = status_code, .content_type = "text/html; charset=utf-8", .body = body };
}

fn h2TextResponse(status_code: u16, content_type: []const u8, body: []const u8) H2BufferedResponse {
    return .{ .status_code = status_code, .content_type = content_type, .body = body };
}

fn readStaticFileForHttp2(io: std.Io, allocator: std.mem.Allocator, static_dir: []const u8, rel_path: []const u8, max_file_bytes: usize) !H2BufferedResponse {
    if (rel_path.len == 0 or std.mem.indexOf(u8, rel_path, "..") != null or std.mem.indexOfScalar(u8, rel_path, '\\') != null) {
        return h2CoolErrorResponse(allocator, 400, "Bad Request", "Invalid static file path.");
    }

    const file_path = try std.fs.path.join(allocator, &.{ static_dir, rel_path });
    const stat = statRegularFile(io, file_path) catch |err| {
        if (err == error.NotDir or err == error.FileNotFound or err == error.NotFile) {
            return h2CoolErrorResponse(allocator, 404, "Not Found", "The requested resource was not found on this server.");
        }
        return err;
    };
    if (stat.size > max_file_bytes) {
        return h2CoolErrorResponse(allocator, 413, "Payload Too Large", "Static file is too large for configured limits.");
    }

    const data = std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(max_file_bytes)) catch |err| {
        if (err == error.StreamTooLong) {
            return h2CoolErrorResponse(allocator, 413, "Payload Too Large", "Static file is too large for configured limits.");
        }
        return err;
    };
    server_metrics.staticBodySent(data.len, .buffered);
    return .{ .status_code = 200, .content_type = contentTypeFromPath(rel_path), .body = data };
}

fn readAcmeChallengeForHttp2(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig, token: []const u8) !H2BufferedResponse {
    if (token.len == 0 or std.mem.indexOf(u8, token, "..") != null or std.mem.indexOfScalar(u8, token, '\\') != null or std.mem.indexOfScalar(u8, token, '/') != null) {
        return h2CoolErrorResponse(allocator, 400, "Bad Request", "Invalid ACME challenge path.");
    }

    const file_path = try std.fs.path.join(allocator, &.{ cfg.letsencrypt_webroot, token });
    const data = std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(64 * 1024)) catch |err| {
        if (err == error.NotDir or err == error.FileNotFound) {
            return h2CoolErrorResponse(allocator, 404, "Not Found", "The requested resource was not found on this server.");
        }
        if (err == error.StreamTooLong) {
            return h2CoolErrorResponse(allocator, 413, "Payload Too Large", "ACME challenge file is too large.");
        }
        return err;
    };
    if (data.len > 0 and std.mem.indexOfScalar(u8, data, 0) != null) {
        return h2CoolErrorResponse(allocator, 404, "Not Found", "The requested resource was not found on this server.");
    }
    return .{ .status_code = 200, .content_type = "text/plain; charset=utf-8", .body = data };
}

fn parseHttp2Request(allocator: std.mem.Allocator, decoded: *const h2_native.DecodedHeaders) !HttpRequest {
    const method = decoded.get(":method") orelse return error.BadRequest;
    const path_and_query = decoded.get(":path") orelse return error.BadRequest;
    const authority = decoded.get(":authority") orelse decoded.get("host") orelse "";

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
        if (std.ascii.eqlIgnoreCase(header.name, "connection")) continue;
        try headers.print(allocator, "{s}: {s}\r\n", .{ header.name, header.value });
    }

    return .{
        .method = method,
        .path = path,
        .query = query,
        .headers = try headers.toOwnedSlice(allocator),
        .version = "HTTP/2.0",
        .body = "",
        .close_connection = true,
    };
}

fn buildHttp2RedirectResponse(allocator: std.mem.Allocator, rule: RedirectRule, req: HttpRequest) !H2BufferedResponse {
    const location = try buildRedirectLocation(allocator, rule, req);
    const body = try std.fmt.allocPrint(allocator, "Redirecting to {s}\n", .{location});
    const headers = try allocator.alloc(h2_native.Header, 1);
    headers[0] = .{ .name = "location", .value = location };
    return .{ .status_code = rule.status_code, .content_type = "text/plain; charset=utf-8", .body = body, .headers = headers };
}

fn appendForwardedRequestHeaders(allocator: std.mem.Allocator, out: *std.ArrayList(u8), req: HttpRequest, upstream: *const UpstreamConfig, cfg: *const ServerConfig) !void {
    const forwarded_host = findHeaderValue(req.headers, "Host") orelse upstream.host;
    const forwarded_proto = if (findHeaderValue(req.headers, "X-Forwarded-Proto")) |proto|
        trimValue(proto)
    else if (cfg.tls_enabled)
        "https"
    else
        "http";

    try out.print(allocator, "Host: {s}\r\nConnection: close\r\n", .{trimValue(forwarded_host)});

    var saw_forwarded_host = false;
    var saw_forwarded_proto = false;
    var headers = std.mem.splitSequence(u8, req.headers, "\r\n");
    while (headers.next()) |line| {
        const trimmed = trimValue(line);
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const name = trimValue(trimmed[0..colon]);
            if (isSkippedProxyHeader(name)) continue;
            const value = trimValue(trimmed[colon + 1 ..]);
            if (value.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(name, "X-Forwarded-Host")) saw_forwarded_host = true;
            if (std.ascii.eqlIgnoreCase(name, "X-Forwarded-Proto")) saw_forwarded_proto = true;
            try out.print(allocator, "{s}: {s}\r\n", .{ name, value });
        }
    }
    if (!saw_forwarded_host) try out.print(allocator, "X-Forwarded-Host: {s}\r\n", .{trimValue(forwarded_host)});
    if (!saw_forwarded_proto) try out.print(allocator, "X-Forwarded-Proto: {s}\r\n", .{forwarded_proto});
}

fn readHttp1ResponseToBuffer(allocator: std.mem.Allocator, upstream_conn: std.Io.net.Stream, max_bytes: usize) ![]u8 {
    var raw = std.ArrayList(u8).empty;
    errdefer raw.deinit(allocator);
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try streamRead(upstream_conn, &buf);
        if (n == 0) break;
        if (raw.items.len + n > max_bytes) return error.PayloadTooLarge;
        try raw.appendSlice(allocator, buf[0..n]);
    }
    return raw.toOwnedSlice(allocator);
}

fn decodeChunkedBuffer(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    var cursor = bytes;
    while (true) {
        const line_end = std.mem.indexOf(u8, cursor, "\r\n") orelse return error.BadGateway;
        const line = cursor[0..line_end];
        const ext = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
        const size = std.fmt.parseInt(usize, trimValue(line[0..ext]), 16) catch return error.BadGateway;
        cursor = cursor[line_end + 2 ..];
        if (size == 0) return out.toOwnedSlice(allocator);
        if (cursor.len < size + 2) return error.BadGateway;
        try out.appendSlice(allocator, cursor[0..size]);
        if (!std.mem.eql(u8, cursor[size .. size + 2], "\r\n")) return error.BadGateway;
        cursor = cursor[size + 2 ..];
    }
}

fn collectHttp2UpstreamHeaders(allocator: std.mem.Allocator, response_headers: []const u8) ![]h2_native.Header {
    var out = std.ArrayList(h2_native.Header).empty;
    errdefer out.deinit(allocator);

    var lines = std.mem.splitSequence(u8, response_headers, "\r\n");
    while (lines.next()) |line| {
        const trimmed = trimValue(line);
        if (trimmed.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse continue;
        const name = trimValue(trimmed[0..colon]);
        if (isSkippedHttp2ResponseHeader(name)) continue;
        const value = trimValue(trimmed[colon + 1 ..]);
        if (value.len == 0) continue;
        const lowered = try lowerHeaderName(allocator, name);
        try out.append(allocator, .{ .name = lowered, .value = try allocator.dupe(u8, value) });
    }

    return out.toOwnedSlice(allocator);
}

fn fetchHttp2UpstreamResponse(allocator: std.mem.Allocator, upstream: *UpstreamConfig, req: HttpRequest, cfg: *const ServerConfig) !H2BufferedResponse {
    if (upstream.https) return error.UnsupportedUpstreamScheme;

    const upstream_conn = try connectTcpHost(allocator, upstream.host, upstream.port);
    defer streamClose(upstream_conn);
    try setStreamTimeouts(upstream_conn, cfg.upstream_timeout_ms, cfg.upstream_timeout_ms);

    const proxy_path = try buildProxyPath(allocator, upstream.base_path, req.path, req.query);
    var request = std.ArrayList(u8).empty;
    defer request.deinit(allocator);
    try request.print(allocator, "{s} {s} HTTP/1.1\r\n", .{ req.method, proxy_path });
    try appendForwardedRequestHeaders(allocator, &request, req, upstream, cfg);
    try request.print(allocator, "Content-Length: {d}\r\n\r\n", .{req.body.len});
    try request.appendSlice(allocator, req.body);
    try streamWriteAll(upstream_conn, request.items);

    const raw = try readHttp1ResponseToBuffer(allocator, upstream_conn, cfg.max_static_file_bytes + DEFAULT_MAX_REQUEST_BYTES);
    const header_end = (std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.BadGateway) + 4;
    const header_bytes = raw[0..header_end];
    const body_tail = raw[header_end..];
    const status_line_end = std.mem.indexOf(u8, header_bytes, "\r\n") orelse return error.BadGateway;
    const response_headers = header_bytes[status_line_end + 2 .. header_end - 4];
    const framing = try parseUpstreamResponseFraming(header_bytes, response_headers);
    const status_code = framing.status_code orelse 502;

    const body = if (responseHasNoBody(req.method, status_code))
        try allocator.dupe(u8, "")
    else if (framing.transfer_chunked)
        try decodeChunkedBuffer(allocator, body_tail)
    else if (framing.content_length) |content_length| blk: {
        if (body_tail.len < content_length) return error.BadGateway;
        break :blk try allocator.dupe(u8, body_tail[0..content_length]);
    } else try allocator.dupe(u8, body_tail);

    const content_type = if (findHeaderValue(response_headers, "Content-Type")) |ctype|
        try allocator.dupe(u8, trimValue(ctype))
    else
        "application/octet-stream";
    const headers = try collectHttp2UpstreamHeaders(allocator, response_headers);
    return .{ .status_code = status_code, .content_type = content_type, .body = body, .headers = headers };
}

fn fetchHttp2UpstreamPoolResponse(allocator: std.mem.Allocator, pool: *UpstreamPoolConfig, policy: UpstreamPoolPolicy, req: HttpRequest, cfg: *const ServerConfig) !H2BufferedResponse {
    if (pool.targets.items.len == 0) return h2CoolErrorResponse(allocator, 502, "Bad Gateway", "Proxy upstream pool is empty.");

    const attempt_limit = upstreamAttemptLimit(pool, cfg.upstream_retries);
    const now_ms = upstreamNowMs();
    const start_ticket = upstreamStartTicket(pool, policy, now_ms, req, cfg);
    var considered: usize = 0;
    var attempts: usize = 0;
    var skipped_ejected: usize = 0;
    var last_error: ?anyerror = null;

    while (considered < pool.targets.items.len and attempts < attempt_limit) : (considered += 1) {
        const upstream = upstreamAtAttempt(pool, start_ticket, considered);
        const lease = upstreamBeginAttempt(upstream, now_ms, cfg) orelse {
            skipped_ejected += 1;
            server_metrics.upstreamEjectedSkip();
            continue;
        };

        if (attempts > 0) server_metrics.upstreamRetried();
        attempts += 1;
        server_metrics.upstreamRequestStarted();
        const response = fetchHttp2UpstreamResponse(allocator, upstream, req, cfg) catch |err| {
            upstreamEndAttempt(upstream, lease);
            last_error = err;
            server_metrics.upstreamRequestFailed();
            if (upstreamRecordFailure(upstream, upstreamNowMs(), cfg.upstream_max_failures, cfg.upstream_fail_timeout_ms)) {
                server_metrics.upstreamEjected();
            }
            continue;
        };
        upstreamEndAttempt(upstream, lease);
        upstreamRecordSuccess(upstream, upstreamNowMs(), cfg.upstream_slow_start_ms);
        return response;
    }

    if (attempts == 0 and skipped_ejected > 0) {
        return h2CoolErrorResponse(allocator, 503, "Service Unavailable", "All configured upstream targets are unavailable or limited by circuit breaker recovery.");
    }
    if (last_error) |err| switch (err) {
        error.RequestTimeout => return h2CoolErrorResponse(allocator, 504, "Gateway Timeout", "All configured upstream attempts timed out."),
        error.UnsupportedUpstreamScheme => return h2CoolErrorResponse(allocator, 501, "Not Implemented", "HTTPS upstream is not yet supported in this server path."),
        error.PayloadTooLarge => return h2CoolErrorResponse(allocator, 502, "Bad Gateway", "Upstream response exceeds configured response buffer."),
        else => {},
    };
    return h2CoolErrorResponse(allocator, 502, "Bad Gateway", "All configured upstream attempts failed.");
}

const H2_DEFAULT_PAGE =
    \\<!doctype html>
    \\<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    \\<title>Layerline HTTP/2</title><link rel="icon" type="image/svg+xml" href="/favicon.svg">
    \\<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f7f4ed;color:#11110f;font:16px/1.5 system-ui,sans-serif}main{max-width:760px;padding:48px}h1{font-size:clamp(56px,10vw,120px);line-height:.85;margin:0}p{color:#5d5e58;max-width:48ch}.tag{font:12px/1.2 ui-monospace,monospace;text-transform:uppercase;color:#77786f}</style>
    \\</head><body><main><div class="tag">native h2c route</div><h1>Layerline</h1><p>This response came from Layerline's native HTTP/2 frame path: SETTINGS, HPACK request headers, HEADERS, and DATA frames emitted by the Zig server.</p></main></body></html>
;

fn buildHttp2ResponseForRequest(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig, req: HttpRequest, process_env: *const std.process.Environ.Map) !H2BufferedResponse {
    _ = process_env;
    const is_head = std.mem.eql(u8, req.method, "HEAD");
    const domain = findDomainForRequestMutable(cfg, req.headers);
    const base_header_context = try buildResponseHeaderContext(allocator, cfg, domain, null);
    current_response_headers = base_header_context.items;

    if (findDomainRedirectRule(domain, req.path)) |redirect| return buildHttp2RedirectResponse(allocator, redirect, req);
    if (findRedirectRule(cfg, req.path)) |redirect| return buildHttp2RedirectResponse(allocator, redirect, req);

    if (findDomainRouteMutable(domain, req.path)) |route| {
        const route_header_context = try buildResponseHeaderContext(allocator, cfg, domain, route);
        current_response_headers = route_header_context.items;
        return buildHttp2RouteResponse(io, allocator, cfg, domain, route, req);
    }
    if (findNamedRouteMutable(cfg, req.path)) |route| {
        const route_header_context = try buildResponseHeaderContext(allocator, cfg, domain, route);
        current_response_headers = route_header_context.items;
        return buildHttp2RouteResponse(io, allocator, cfg, domain, route, req);
    }

    if ((std.mem.eql(u8, req.method, "GET") or is_head) and std.mem.startsWith(u8, req.path, "/.well-known/acme-challenge/")) {
        return readAcmeChallengeForHttp2(io, allocator, cfg, req.path["/.well-known/acme-challenge/".len..]);
    }

    if (domain != null) {
        if (domainUpstreamMutable(cfg, domain)) |pool| {
            return fetchHttp2UpstreamPoolResponse(allocator, pool, domainUpstreamPolicy(cfg, domain), req, cfg);
        }
    }

    if (std.mem.eql(u8, req.method, "GET") or is_head) {
        if (std.mem.eql(u8, req.path, "/favicon.svg") or std.mem.eql(u8, req.path, "/icon.svg")) {
            return h2TextResponse(200, "image/svg+xml", SERVER_ICON_SVG);
        }
        if (std.mem.eql(u8, req.path, "/")) {
            return h2TextResponse(200, "text/html; charset=utf-8", H2_DEFAULT_PAGE);
        }
        if (std.mem.eql(u8, req.path, "/health")) {
            return h2TextResponse(200, "text/plain; charset=utf-8", "ok\n");
        }
        if (std.mem.eql(u8, req.path, "/metrics")) {
            return .{ .status_code = 200, .content_type = "text/plain; version=0.0.4; charset=utf-8", .body = try renderMetrics(allocator) };
        }
        if (std.mem.eql(u8, req.path, "/time")) {
            return .{ .status_code = 200, .content_type = "application/json; charset=utf-8", .body = try std.fmt.allocPrint(allocator, "{{\"time\":{}}}\n", .{std.Io.Timestamp.now(io, .real).toSeconds()}) };
        }
        if (std.mem.eql(u8, req.path, "/api/echo")) {
            if (findQueryValue(req.query, "msg")) |msg| {
                return .{ .status_code = 200, .content_type = "application/json; charset=utf-8", .body = try std.fmt.allocPrint(allocator, "{{\"msg\":\"{s}\"}}\n", .{msg}) };
            }
            return h2TextResponse(200, "text/plain; charset=utf-8", "try /api/echo?msg=your-text\n");
        }
        if (std.mem.startsWith(u8, req.path, "/static/")) {
            return readStaticFileForHttp2(io, allocator, domainStaticDir(cfg, domain), req.path["/static/".len..], cfg.max_static_file_bytes);
        }
        if (domainServeStaticRoot(cfg, domain) and
            !std.mem.startsWith(u8, req.path, "/api/") and
            !std.mem.startsWith(u8, req.path, "/php/") and
            !std.mem.eql(u8, req.path, "/health") and
            !std.mem.eql(u8, req.path, "/time") and
            !std.mem.eql(u8, req.path, "/"))
        {
            const rel = try makeStaticPathFromRequest(allocator, req.path, domainIndexFile(cfg, domain));
            return readStaticFileForHttp2(io, allocator, domainStaticDir(cfg, domain), rel, cfg.max_static_file_bytes);
        }
        if (domainUpstreamMutable(cfg, domain)) |pool| {
            return fetchHttp2UpstreamPoolResponse(allocator, pool, domainUpstreamPolicy(cfg, domain), req, cfg);
        }
        return h2CoolErrorResponse(allocator, 404, "Not Found", "The requested resource was not found on this server.");
    }

    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, req.path, "/api/echo")) {
        return .{ .status_code = 200, .content_type = "text/plain; charset=utf-8", .body = req.body };
    }
    if (std.mem.eql(u8, req.method, "OPTIONS")) {
        const headers = try allocator.alloc(h2_native.Header, 1);
        headers[0] = .{ .name = "allow", .value = "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS" };
        return .{ .status_code = 204, .content_type = "text/plain; charset=utf-8", .body = "", .headers = headers };
    }
    if (domainUpstreamMutable(cfg, domain)) |pool| {
        return fetchHttp2UpstreamPoolResponse(allocator, pool, domainUpstreamPolicy(cfg, domain), req, cfg);
    }
    return h2CoolErrorResponse(allocator, 501, "Not Implemented", "This server has not implemented that HTTP/2 behavior yet.");
}

fn buildHttp2RouteResponse(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig, domain: ?*DomainConfig, route: *RouteConfig, req: HttpRequest) !H2BufferedResponse {
    const is_head = std.mem.eql(u8, req.method, "HEAD");
    switch (route.handler) {
        .static => {
            if (!(std.mem.eql(u8, req.method, "GET") or is_head)) {
                const headers = try allocator.alloc(h2_native.Header, 1);
                headers[0] = .{ .name = "allow", .value = "GET,HEAD,OPTIONS" };
                var response = try h2CoolErrorResponse(allocator, 405, "Method Not Allowed", "That method is not supported for this endpoint.");
                response.headers = headers;
                return response;
            }
            const rel = try routeFileRelativePath(allocator, route, req.path, route.index_file orelse domainIndexFile(cfg, domain));
            return readStaticFileForHttp2(io, allocator, route.static_dir orelse domainStaticDir(cfg, domain), rel, cfg.max_static_file_bytes);
        },
        .proxy => {
            const pool = if (route.upstream) |*route_pool|
                route_pool
            else
                domainUpstreamMutable(cfg, domain) orelse return h2CoolErrorResponse(allocator, 502, "Bad Gateway", "Route proxy upstream is not configured.");
            return fetchHttp2UpstreamPoolResponse(allocator, pool, routeUpstreamPolicy(cfg, domain, route), req, cfg);
        },
        .php => {
            if (!(std.mem.eql(u8, req.method, "GET") or is_head)) {
                const headers = try allocator.alloc(h2_native.Header, 1);
                headers[0] = .{ .name = "allow", .value = "GET,HEAD,OPTIONS" };
                var response = try h2CoolErrorResponse(allocator, 405, "Method Not Allowed", "HTTP/2 PHP routes currently accept GET and HEAD.");
                response.headers = headers;
                return response;
            }
            if (std.mem.eql(u8, req.path, "/test.php") and !(route.php_info_page orelse domainPhpInfoPage(cfg, domain))) {
                return h2CoolErrorResponse(allocator, 404, "Not Found", "The requested resource was not found on this server.");
            }
            if (routePhpFrontController(cfg, domain, route)) {
                const target = try makePhpFrontControllerTarget(allocator, route, req.path, routePhpIndex(cfg, domain, route));
                defer target.deinit(allocator);
                return buildHttp2PhpFastcgiResponse(io, allocator, cfg, req, route.php_root orelse domainPhpRoot(cfg, domain), routePhpFastcgi(cfg, domain, route), target.script_rel_path, target.script_name, target.path_info, routeUpstreamTimeoutMs(cfg, domain, route));
            }
            const script_rel = try routeFileRelativePath(allocator, route, req.path, route.index_file orelse domainIndexFile(cfg, domain));
            defer allocator.free(script_rel);
            return buildHttp2PhpFastcgiResponse(io, allocator, cfg, req, route.php_root orelse domainPhpRoot(cfg, domain), routePhpFastcgi(cfg, domain, route), script_rel, req.path, "", routeUpstreamTimeoutMs(cfg, domain, route));
        },
    }
}

fn readHttp2Frame(reader: *H2PendingReader, allocator: std.mem.Allocator, max_payload_bytes: usize) !H2Frame {
    var header_bytes: [9]u8 = undefined;
    try reader.readExact(&header_bytes);
    const header = try h2_native.parseFrameHeader(&header_bytes);
    if (header.length > max_payload_bytes) return error.RequestTooLarge;
    const payload = try allocator.alloc(u8, header.length);
    errdefer allocator.free(payload);
    if (payload.len > 0) try reader.readExact(payload);
    return .{ .header = header, .payload = payload };
}

fn sendHttp2Rst(stream: std.Io.net.Stream, stream_id: u32, code: u32) !void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, code, .big);
    try sendHttp2Frame(stream, h2_native.FRAME_RST_STREAM, 0, stream_id, &payload);
}

fn readHttp2ClientPreface(reader: *H2PendingReader) !void {
    var preface_buf: [HTTP2_PREFACE_MAGIC.len]u8 = undefined;
    try reader.readExact(&preface_buf);
    if (!std.mem.eql(u8, &preface_buf, HTTP2_PREFACE_MAGIC)) return error.BadRequest;
}

fn handleHttp2HeadersFrame(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    hpack_decoder: *h2_native.HpackDecoder,
    cfg: *ServerConfig,
    process_env: *const std.process.Environ.Map,
    frame: H2Frame,
) !void {
    current_response_headers = &.{};

    if (frame.header.stream_id == 0 or (frame.header.flags & h2_native.FLAG_END_HEADERS) == 0) {
        if (frame.header.stream_id != 0) try sendHttp2Rst(stream, frame.header.stream_id, 0x1);
        return;
    }

    var offset: usize = 0;
    var pad_len: usize = 0;
    if ((frame.header.flags & h2_native.FLAG_PADDED) != 0) {
        if (offset >= frame.payload.len) return error.BadRequest;
        pad_len = frame.payload[offset];
        offset += 1;
    }
    if ((frame.header.flags & h2_native.FLAG_PRIORITY) != 0) {
        if (frame.payload.len < offset + 5) return error.BadRequest;
        offset += 5;
    }
    if (frame.payload.len < offset + pad_len) return error.BadRequest;
    const header_block = frame.payload[offset .. frame.payload.len - pad_len];

    var decoded = hpack_decoder.decodeHeaderBlock(allocator, header_block) catch |err| {
        const response = switch (err) {
            else => try h2CoolErrorResponse(allocator, 400, "Bad Request", "Invalid HTTP/2 header block."),
        };
        try sendHttp2Response(stream, allocator, frame.header.stream_id, response, false);
        return;
    };
    defer decoded.deinit(allocator);

    const req = parseHttp2Request(allocator, &decoded) catch {
        const response = try h2CoolErrorResponse(allocator, 400, "Bad Request", "Missing required HTTP/2 pseudo-headers.");
        try sendHttp2Response(stream, allocator, frame.header.stream_id, response, false);
        return;
    };

    if ((frame.header.flags & h2_native.FLAG_END_STREAM) == 0) {
        const response = try h2CoolErrorResponse(allocator, 501, "Not Implemented", "HTTP/2 request bodies are not supported in this route path yet.");
        try sendHttp2Response(stream, allocator, frame.header.stream_id, response, false);
        return;
    }

    server_metrics.requestStarted();
    std.debug.print("HTTP/2 {s} {s}\n", .{ req.method, req.path });
    const response = buildHttp2ResponseForRequest(io, allocator, cfg, req, process_env) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => try h2CoolErrorResponse(allocator, 500, "Internal Server Error", "Internal server error while routing HTTP/2 request."),
    };
    try sendHttp2Response(stream, allocator, frame.header.stream_id, response, std.mem.eql(u8, req.method, "HEAD"));
}

fn runHttp2FrameLoop(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    reader: *H2PendingReader,
    process_env: *const std.process.Environ.Map,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var hpack_decoder = h2_native.HpackDecoder.init(allocator);
    defer hpack_decoder.deinit();

    while (true) {
        _ = arena.reset(.retain_capacity);
        const req_alloc = arena.allocator();
        const frame = readHttp2Frame(reader, req_alloc, @max(cfg.max_request_bytes, cfg.max_body_bytes)) catch |err| switch (err) {
            error.ConnectionClosed => return,
            error.RequestTimeout => return,
            else => return err,
        };

        switch (frame.header.frame_type) {
            h2_native.FRAME_SETTINGS => {
                if ((frame.header.flags & h2_native.FLAG_ACK) == 0) {
                    try sendHttp2Frame(stream, h2_native.FRAME_SETTINGS, h2_native.FLAG_ACK, 0, "");
                }
            },
            h2_native.FRAME_PING => {
                if (frame.payload.len == 8 and (frame.header.flags & h2_native.FLAG_ACK) == 0) {
                    try sendHttp2Frame(stream, h2_native.FRAME_PING, h2_native.FLAG_ACK, 0, frame.payload);
                }
            },
            h2_native.FRAME_HEADERS => {
                try handleHttp2HeadersFrame(io, stream, req_alloc, &hpack_decoder, cfg, process_env, frame);
            },
            h2_native.FRAME_DATA => {
                if (frame.header.stream_id != 0) try sendHttp2Rst(stream, frame.header.stream_id, 0x7);
            },
            h2_native.FRAME_GOAWAY => return,
            h2_native.FRAME_WINDOW_UPDATE => {},
            else => {},
        }
    }
}

fn handleHttp2Preface(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    prefill: []const u8,
    process_env: *const std.process.Environ.Map,
) !void {
    var reader = H2PendingReader{
        .stream = stream,
        .pending = prefill,
    };
    readHttp2ClientPreface(&reader) catch {
        try sendCoolErrorWithConnection(stream, allocator, 400, "Bad Request", "Invalid HTTP/2 connection preface.", true, false, null);
        return;
    };

    try sendHttp2Frame(stream, h2_native.FRAME_SETTINGS, 0, 0, "");
    std.debug.print("HTTP/2 native h2c connection accepted\n", .{});
    try runHttp2FrameLoop(io, stream, allocator, cfg, &reader, process_env);
}

fn handleHttp2Upgrade(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    req: HttpRequest,
    process_env: *const std.process.Environ.Map,
) !void {
    try streamWriteAll(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Server: " ++ SERVER_HEADER ++ "\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Upgrade: h2c\r\n" ++
            "\r\n",
    );
    server_metrics.responseSent(101, 0);

    try sendHttp2Frame(stream, h2_native.FRAME_SETTINGS, 0, 0, "");

    var reader = H2PendingReader{
        .stream = stream,
        .pending = req.h2c_upgrade_tail,
    };
    readHttp2ClientPreface(&reader) catch {
        try sendHttp2Frame(stream, h2_native.FRAME_GOAWAY, 0, 0, "\x00\x00\x00\x00\x00\x00\x00\x01");
        return;
    };

    var h2_req = req;
    h2_req.version = "HTTP/2.0";
    h2_req.close_connection = true;
    std.debug.print("HTTP/2 h2c upgrade {s} {s}\n", .{ h2_req.method, h2_req.path });
    const response = buildHttp2ResponseForRequest(io, allocator, cfg, h2_req, process_env) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => try h2CoolErrorResponse(allocator, 500, "Internal Server Error", "Internal server error while routing HTTP/2 upgrade request."),
    };
    try sendHttp2Response(stream, allocator, 1, response, std.mem.eql(u8, h2_req.method, "HEAD"));
    try runHttp2FrameLoop(io, stream, allocator, cfg, &reader, process_env);
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

    return UpstreamConfig{
        .host = dupe_host,
        .port = port,
        .base_path = dupe_path,
        .https = scheme_https,
        .weight = 1,
        .keepalive_pool = UpstreamKeepAlivePool.init(),
        .active_requests = std.atomic.Value(usize).init(0),
        .half_open_requests = std.atomic.Value(usize).init(0),
        .passive_failures = std.atomic.Value(usize).init(0),
        .ejected_until_ms = std.atomic.Value(i64).init(0),
        .recovered_at_ms = std.atomic.Value(i64).init(0),
    };
}

fn applyUpstreamOption(upstream: *UpstreamConfig, raw: []const u8) !bool {
    const token = std.mem.trim(u8, raw, " \t\r\n;");
    const eq = std.mem.indexOfScalar(u8, token, '=') orelse return false;
    const key = token[0..eq];
    const value = token[eq + 1 ..];

    if (std.ascii.eqlIgnoreCase(key, "weight") or std.ascii.eqlIgnoreCase(key, "w")) {
        const weight = std.fmt.parseInt(usize, value, 10) catch return error.InvalidUpstream;
        if (weight == 0 or weight > 1_000_000) return error.InvalidUpstream;
        upstream.weight = weight;
        return true;
    }

    if (!std.mem.startsWith(u8, token, "http://") and !std.mem.startsWith(u8, token, "https://")) {
        return error.InvalidUpstream;
    }
    return false;
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

        if (pool.targets.items.len > 0) {
            if (try applyUpstreamOption(&pool.targets.items[pool.targets.items.len - 1], value)) continue;
        } else if (std.mem.indexOfScalar(u8, value, '=') != null and
            !std.mem.startsWith(u8, value, "http://") and
            !std.mem.startsWith(u8, value, "https://"))
        {
            return error.InvalidUpstream;
        }

        try pool.targets.append(allocator, try parseUpstream(allocator, value));
    }

    if (pool.targets.items.len == 0) return error.InvalidUpstream;
    return pool;
}

fn upstreamPoolTargetCount(pool: UpstreamPoolConfig) usize {
    return pool.targets.items.len;
}

fn upstreamNowMs() i64 {
    return std.Io.Timestamp.now(activeIo(), .awake).toMilliseconds();
}

fn upstreamRandomTicket() usize {
    var z = upstream_random_cursor.fetchAdd(0x9e3779b97f4a7c15, .monotonic);
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return @truncate(z ^ (z >> 31));
}

fn upstreamInSlowStart(upstream: *UpstreamConfig, now_ms: i64, cfg: ?*const ServerConfig) bool {
    const slow_start_ms = if (cfg) |config| config.upstream_slow_start_ms else 0;
    if (slow_start_ms == 0) return false;
    const recovered_at = upstream.recovered_at_ms.load(.monotonic);
    if (recovered_at == 0) return false;
    if (now_ms <= recovered_at) return true;
    if (now_ms - recovered_at < @as(i64, @intCast(slow_start_ms))) return true;
    upstream.recovered_at_ms.store(0, .monotonic);
    return false;
}

fn upstreamEffectiveWeight(upstream: *UpstreamConfig, now_ms: i64, cfg: ?*const ServerConfig) usize {
    const base_weight = upstream.weight;
    if (base_weight <= 1) return base_weight;
    const config = cfg orelse return base_weight;
    if (config.upstream_slow_start_ms == 0) return base_weight;

    const recovered_at = upstream.recovered_at_ms.load(.monotonic);
    if (recovered_at == 0) return base_weight;
    if (now_ms <= recovered_at) return 1;

    const elapsed_ms = now_ms - recovered_at;
    const slow_start_ms = @as(i64, @intCast(config.upstream_slow_start_ms));
    if (elapsed_ms >= slow_start_ms) {
        upstream.recovered_at_ms.store(0, .monotonic);
        return base_weight;
    }

    const scaled = (@as(u128, base_weight) * @as(u128, @intCast(elapsed_ms))) / @as(u128, @intCast(slow_start_ms));
    return @max(@as(usize, 1), @min(base_weight, @as(usize, @intCast(scaled))));
}

fn upstreamInHalfOpen(upstream: *UpstreamConfig, now_ms: i64) bool {
    const until_ms = upstream.ejected_until_ms.load(.monotonic);
    return until_ms != 0 and now_ms >= until_ms;
}

fn upstreamIsSelectable(upstream: *UpstreamConfig, now_ms: i64, cfg: ?*const ServerConfig) bool {
    if (upstreamIsEjected(upstream, now_ms)) return false;
    const config = cfg orelse return true;
    if (!config.upstream_circuit_breaker_enabled) return true;
    if (!upstreamInHalfOpen(upstream, now_ms)) return true;
    if (config.upstream_circuit_half_open_max == 0) return false;
    return upstream.half_open_requests.load(.monotonic) < config.upstream_circuit_half_open_max;
}

fn upstreamLeastConnectionsTicket(pool: *UpstreamPoolConfig, now_ms: i64, cfg: ?*const ServerConfig) usize {
    const target_count = pool.targets.items.len;
    const tie_ticket = upstream_round_robin_cursor.fetchAdd(1, .monotonic);
    if (target_count == 0) return tie_ticket;

    var best_index: ?usize = null;
    var best_active: usize = std.math.maxInt(usize);
    var offset: usize = 0;
    while (offset < target_count) : (offset += 1) {
        const index = (tie_ticket + offset) % target_count;
        const upstream = &pool.targets.items[index];
        if (!upstreamIsSelectable(upstream, now_ms, cfg)) continue;

        var active = upstream.active_requests.load(.monotonic);
        if (upstreamInSlowStart(upstream, now_ms, cfg)) active += 1;
        if (best_index == null or active < best_active) {
            best_index = index;
            best_active = active;
        }
    }

    return best_index orelse tie_ticket;
}

fn upstreamWeightedTicket(pool: *UpstreamPoolConfig, now_ms: i64, cfg: ?*const ServerConfig) usize {
    const target_count = pool.targets.items.len;
    const ticket = upstream_round_robin_cursor.fetchAdd(1, .monotonic);
    if (target_count == 0) return ticket;

    var total_weight: usize = 0;
    for (pool.targets.items) |*upstream| {
        if (!upstreamIsSelectable(upstream, now_ms, cfg)) continue;
        total_weight += upstreamEffectiveWeight(upstream, now_ms, cfg);
    }
    if (total_weight == 0) return ticket;

    var remaining = ticket % total_weight;
    for (pool.targets.items, 0..) |*upstream, index| {
        if (!upstreamIsSelectable(upstream, now_ms, cfg)) continue;
        const weight = upstreamEffectiveWeight(upstream, now_ms, cfg);
        if (remaining < weight) return index;
        remaining -= weight;
    }

    return ticket;
}

const UPSTREAM_HASH_OFFSET: u64 = 0xcbf29ce484222325;
const UPSTREAM_HASH_PRIME: u64 = 0x100000001b3;

fn upstreamHashByte(seed: u64, value: u8) u64 {
    return (seed ^ value) *% UPSTREAM_HASH_PRIME;
}

fn upstreamHashBytes(seed: u64, value: []const u8) u64 {
    var hash = seed;
    for (value) |byte| {
        hash = upstreamHashByte(hash, byte);
    }
    return hash;
}

fn upstreamHashU16(seed: u64, value: u16) u64 {
    var hash = seed;
    hash = upstreamHashByte(hash, @intCast(value & 0xff));
    hash = upstreamHashByte(hash, @intCast(value >> 8));
    return hash;
}

fn firstForwardedValue(value: []const u8) []const u8 {
    const first = if (std.mem.indexOfScalar(u8, value, ',')) |comma| value[0..comma] else value;
    return std.mem.trim(u8, first, " \t\r\n");
}

fn upstreamConsistentHashKey(req: HttpRequest) u64 {
    var hash = UPSTREAM_HASH_OFFSET;

    if (findHeaderValue(req.headers, "X-Forwarded-For")) |forwarded| {
        const first = firstForwardedValue(forwarded);
        if (first.len > 0) return upstreamHashBytes(upstreamHashBytes(hash, "xff:"), first);
    }
    if (findHeaderValue(req.headers, "X-Real-IP")) |real_ip| {
        const trimmed = trimValue(real_ip);
        if (trimmed.len > 0) return upstreamHashBytes(upstreamHashBytes(hash, "xri:"), trimmed);
    }
    if (findHeaderValue(req.headers, "Host")) |host| {
        hash = upstreamHashBytes(upstreamHashBytes(hash, "host:"), host);
    }
    hash = upstreamHashBytes(upstreamHashBytes(hash, "path:"), req.path);
    if (req.query.len > 0) {
        hash = upstreamHashBytes(upstreamHashBytes(hash, "?"), req.query);
    }
    return hash;
}

fn upstreamConsistentHashTicket(pool: *UpstreamPoolConfig, req: ?HttpRequest, now_ms: i64, cfg: ?*const ServerConfig) usize {
    const target_count = pool.targets.items.len;
    const fallback = upstream_round_robin_cursor.fetchAdd(1, .monotonic);
    if (target_count == 0) return fallback;

    const key = if (req) |request| upstreamConsistentHashKey(request) else fallback;
    var best_index: ?usize = null;
    var best_score: u64 = 0;

    for (pool.targets.items, 0..) |*upstream, index| {
        if (!upstreamIsSelectable(upstream, now_ms, cfg)) continue;

        var score = upstreamHashBytes(key, upstream.host);
        score = upstreamHashU16(upstreamHashByte(score, 0), upstream.port);
        score = upstreamHashBytes(upstreamHashByte(score, 0), upstream.base_path);
        if (best_index == null or score > best_score) {
            best_index = index;
            best_score = score;
        }
    }

    return best_index orelse @as(usize, @intCast(key % target_count));
}

fn upstreamStartTicket(pool: *UpstreamPoolConfig, policy: UpstreamPoolPolicy, now_ms: i64, req: ?HttpRequest, cfg: ?*const ServerConfig) usize {
    return switch (policy) {
        .round_robin => upstream_round_robin_cursor.fetchAdd(1, .monotonic),
        .random => upstreamRandomTicket(),
        .least_connections => upstreamLeastConnectionsTicket(pool, now_ms, cfg),
        .weighted => upstreamWeightedTicket(pool, now_ms, cfg),
        .consistent_hash => upstreamConsistentHashTicket(pool, req, now_ms, cfg),
    };
}

fn selectUpstream(pool: *UpstreamPoolConfig) ?*UpstreamConfig {
    if (pool.targets.items.len == 0) return null;
    const ticket = upstreamStartTicket(pool, pool.policy, upstreamNowMs(), null, null);
    return &pool.targets.items[ticket % pool.targets.items.len];
}

fn upstreamIsEjected(upstream: *UpstreamConfig, now_ms: i64) bool {
    const until_ms = upstream.ejected_until_ms.load(.monotonic);
    if (until_ms == 0) return false;
    return now_ms < until_ms;
}

fn upstreamRecordSuccess(upstream: *UpstreamConfig, now_ms: i64, slow_start_ms: u32) void {
    const was_recovering = upstream.ejected_until_ms.load(.monotonic) != 0 or upstream.passive_failures.load(.monotonic) != 0;
    upstream.passive_failures.store(0, .monotonic);
    upstream.ejected_until_ms.store(0, .monotonic);
    if (was_recovering and slow_start_ms > 0) {
        upstream.recovered_at_ms.store(now_ms, .monotonic);
    }
}

fn upstreamRecordFailure(upstream: *UpstreamConfig, now_ms: i64, max_failures: usize, fail_timeout_ms: u32) bool {
    if (max_failures == 0 or fail_timeout_ms == 0) return false;

    const half_open = upstreamInHalfOpen(upstream, now_ms);
    const failures = upstream.passive_failures.fetchAdd(1, .monotonic) + 1;
    if (!half_open and failures < max_failures) return false;

    const previous_until = upstream.ejected_until_ms.load(.monotonic);
    const cooldown_until = now_ms + @as(i64, @intCast(fail_timeout_ms));
    upstream.ejected_until_ms.store(cooldown_until, .monotonic);
    upstream.recovered_at_ms.store(0, .monotonic);
    return previous_until == 0 or previous_until <= now_ms;
}

const UpstreamAttemptLease = struct {
    half_open: bool,
};

fn upstreamBeginAttempt(upstream: *UpstreamConfig, now_ms: i64, cfg: *const ServerConfig) ?UpstreamAttemptLease {
    if (upstreamIsEjected(upstream, now_ms)) return null;

    var half_open = false;
    if (cfg.upstream_circuit_breaker_enabled and upstreamInHalfOpen(upstream, now_ms)) {
        if (cfg.upstream_circuit_half_open_max == 0) return null;
        const active_half_open = upstream.half_open_requests.fetchAdd(1, .monotonic);
        if (active_half_open >= cfg.upstream_circuit_half_open_max) {
            _ = upstream.half_open_requests.fetchSub(1, .monotonic);
            return null;
        }
        half_open = true;
    }

    _ = upstream.active_requests.fetchAdd(1, .monotonic);
    return .{ .half_open = half_open };
}

fn upstreamEndAttempt(upstream: *UpstreamConfig, lease: UpstreamAttemptLease) void {
    _ = upstream.active_requests.fetchSub(1, .monotonic);
    if (lease.half_open) _ = upstream.half_open_requests.fetchSub(1, .monotonic);
}

fn upstreamAttemptLimit(pool: *const UpstreamPoolConfig, retry_budget: usize) usize {
    const target_count = pool.targets.items.len;
    if (target_count == 0) return 0;
    if (retry_budget >= target_count) return target_count;
    return retry_budget + 1;
}

fn upstreamAtAttempt(pool: *UpstreamPoolConfig, start_ticket: usize, attempt: usize) *UpstreamConfig {
    const target_count = pool.targets.items.len;
    var index = start_ticket % target_count;
    var remaining = attempt;
    while (remaining > 0) : (remaining -= 1) {
        index += 1;
        if (index == target_count) index = 0;
    }
    return &pool.targets.items[index];
}

fn printUpstreamPool(policy: UpstreamPoolPolicy, pool: UpstreamPoolConfig) void {
    std.debug.print(" upstream={s}[", .{upstreamPoolPolicyName(policy)});
    for (pool.targets.items, 0..) |up, i| {
        if (i > 0) std.debug.print(",", .{});
        std.debug.print("{s}:{d}{s}", .{ up.host, up.port, up.base_path });
        if (up.weight != 1) std.debug.print(" weight={d}", .{up.weight});
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

fn isHttpUpgradeRequest(req: HttpRequest) bool {
    const upgrade = findHeaderValue(req.headers, "Upgrade") orelse return false;
    const connection = findHeaderValue(req.headers, "Connection") orelse return false;
    return trimValue(upgrade).len > 0 and hasConnectionToken(connection, "upgrade");
}

fn isSkippedProxyResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "Connection") or
        std.ascii.eqlIgnoreCase(name, "Keep-Alive") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authenticate") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authorization") or
        std.ascii.eqlIgnoreCase(name, "TE") or
        std.ascii.eqlIgnoreCase(name, "Trailers") or
        std.ascii.eqlIgnoreCase(name, "Upgrade");
}

const UpstreamConnectionLease = struct {
    stream: std.Io.net.Stream,
    requests_served: usize,
};

const UpstreamResponseForwardResult = struct {
    reusable: bool,
};

const UpstreamResponseFraming = struct {
    status_code: ?u16,
    content_length: ?usize,
    transfer_chunked: bool,
    connection_close: bool,
};

const ChunkScanState = enum {
    size,
    size_lf,
    data,
    data_cr,
    data_lf,
    trailer,
    trailer_lf,
    done,
};

const ChunkedBodyScanner = struct {
    state: ChunkScanState = .size,
    chunk_size: usize = 0,
    remaining: usize = 0,
    saw_size_digit: bool = false,
    in_extension: bool = false,
    trailer_line_start: bool = true,

    fn resetSize(self: *ChunkedBodyScanner) void {
        self.chunk_size = 0;
        self.saw_size_digit = false;
        self.in_extension = false;
    }

    fn consume(self: *ChunkedBodyScanner, byte: u8) !bool {
        switch (self.state) {
            .size => {
                if (byte == ';') {
                    if (!self.saw_size_digit) return error.BadGateway;
                    self.in_extension = true;
                    return false;
                }
                if (byte == '\r') {
                    if (!self.saw_size_digit) return error.BadGateway;
                    self.state = .size_lf;
                    return false;
                }
                if (self.in_extension) return false;

                const digit = std.fmt.charToDigit(byte, 16) catch return error.BadGateway;
                self.saw_size_digit = true;
                self.chunk_size = std.math.mul(usize, self.chunk_size, 16) catch return error.BadGateway;
                self.chunk_size = std.math.add(usize, self.chunk_size, digit) catch return error.BadGateway;
                return false;
            },
            .size_lf => {
                if (byte != '\n') return error.BadGateway;
                if (self.chunk_size == 0) {
                    self.trailer_line_start = true;
                    self.state = .trailer;
                } else {
                    self.remaining = self.chunk_size;
                    self.state = .data;
                }
                self.resetSize();
                return false;
            },
            .data => {
                self.remaining -= 1;
                if (self.remaining == 0) self.state = .data_cr;
                return false;
            },
            .data_cr => {
                if (byte != '\r') return error.BadGateway;
                self.state = .data_lf;
                return false;
            },
            .data_lf => {
                if (byte != '\n') return error.BadGateway;
                self.state = .size;
                return false;
            },
            .trailer => {
                if (byte == '\r') {
                    self.state = .trailer_lf;
                } else {
                    self.trailer_line_start = false;
                }
                return false;
            },
            .trailer_lf => {
                if (byte != '\n') return error.BadGateway;
                if (self.trailer_line_start) {
                    self.state = .done;
                    return true;
                }
                self.trailer_line_start = true;
                self.state = .trailer;
                return false;
            },
            .done => return true,
        }
    }
};

fn upstreamKeepaliveConfigured(cfg: *const ServerConfig) bool {
    return cfg.upstream_keepalive_enabled and cfg.upstream_keepalive_max_idle > 0;
}

fn closeIdleUpstreamConnection(conn: UpstreamIdleConnection) void {
    streamClose(conn.stream);
    server_metrics.upstreamConnectionDiscarded();
}

fn upstreamAcquireConnection(allocator: std.mem.Allocator, upstream: *UpstreamConfig, cfg: *const ServerConfig, now_ms: i64) !UpstreamConnectionLease {
    if (upstreamKeepaliveConfigured(cfg) and !upstream.https) {
        const io = activeIo();
        upstream.keepalive_pool.mutex.lockUncancelable(io);
        defer upstream.keepalive_pool.mutex.unlock(io);

        while (upstream.keepalive_pool.idle.pop()) |conn| {
            if (conn.expires_at_ms <= now_ms or conn.requests_served >= cfg.upstream_keepalive_max_requests) {
                closeIdleUpstreamConnection(conn);
                continue;
            }

            server_metrics.upstreamConnectionReused();
            return .{
                .stream = conn.stream,
                .requests_served = conn.requests_served,
            };
        }
    }

    const upstream_conn = try connectTcpHost(allocator, upstream.host, upstream.port);
    try setStreamTimeouts(upstream_conn, cfg.upstream_timeout_ms, cfg.upstream_timeout_ms);
    server_metrics.upstreamConnectionOpened();
    return .{
        .stream = upstream_conn,
        .requests_served = 0,
    };
}

fn upstreamReleaseConnection(upstream: *UpstreamConfig, cfg: *const ServerConfig, lease: UpstreamConnectionLease, reusable: bool, now_ms: i64) void {
    if (!reusable or !upstreamKeepaliveConfigured(cfg) or upstream.https) {
        streamClose(lease.stream);
        server_metrics.upstreamConnectionDiscarded();
        return;
    }

    const served = lease.requests_served + 1;
    if (served >= cfg.upstream_keepalive_max_requests) {
        streamClose(lease.stream);
        server_metrics.upstreamConnectionDiscarded();
        return;
    }

    const idle_conn = UpstreamIdleConnection{
        .stream = lease.stream,
        .expires_at_ms = now_ms + @as(i64, @intCast(cfg.upstream_keepalive_idle_timeout_ms)),
        .requests_served = served,
    };

    const io = activeIo();
    upstream.keepalive_pool.mutex.lockUncancelable(io);
    defer upstream.keepalive_pool.mutex.unlock(io);

    while (upstream.keepalive_pool.idle.items.len >= cfg.upstream_keepalive_max_idle) {
        closeIdleUpstreamConnection(upstream.keepalive_pool.idle.orderedRemove(0));
    }

    upstream.keepalive_pool.idle.append(std.heap.page_allocator, idle_conn) catch {
        streamClose(idle_conn.stream);
        server_metrics.upstreamConnectionDiscarded();
        return;
    };
    server_metrics.upstreamConnectionPooled();
}

const FastcgiConnectionLease = struct {
    stream: std.Io.net.Stream,
    requests_served: usize,
};

fn fastcgiKeepaliveConfigured(cfg: *const ServerConfig) bool {
    return cfg.fastcgi_keepalive_enabled and cfg.fastcgi_keepalive_max_idle > 0;
}

fn closeIdleFastcgiConnection(conn: FastcgiIdleConnection) void {
    streamClose(conn.stream);
    server_metrics.fastcgiConnectionDiscarded();
}

fn fastcgiAcquireConnection(allocator: std.mem.Allocator, endpoint_name: []const u8, endpoint: PhpFastcgiEndpoint, cfg: *const ServerConfig, timeout_ms: u32, now_ms: i64) !FastcgiConnectionLease {
    if (fastcgiKeepaliveConfigured(cfg)) {
        const io = activeIo();
        fastcgi_keepalive_pool.mutex.lockUncancelable(io);
        defer fastcgi_keepalive_pool.mutex.unlock(io);

        var index: usize = 0;
        while (index < fastcgi_keepalive_pool.idle.items.len) {
            const conn = fastcgi_keepalive_pool.idle.items[index];
            if (conn.expires_at_ms <= now_ms or conn.requests_served >= cfg.fastcgi_keepalive_max_requests) {
                closeIdleFastcgiConnection(fastcgi_keepalive_pool.idle.orderedRemove(index));
                continue;
            }
            if (std.mem.eql(u8, conn.endpoint_name, endpoint_name)) {
                const reused = fastcgi_keepalive_pool.idle.orderedRemove(index);
                setStreamTimeouts(reused.stream, timeout_ms, timeout_ms) catch |err| {
                    closeIdleFastcgiConnection(reused);
                    return err;
                };
                server_metrics.fastcgiConnectionReused();
                return .{
                    .stream = reused.stream,
                    .requests_served = reused.requests_served,
                };
            }
            index += 1;
        }
    }

    const conn = try connectFastcgiEndpoint(allocator, endpoint);
    try setStreamTimeouts(conn, timeout_ms, timeout_ms);
    server_metrics.fastcgiConnectionOpened();
    return .{
        .stream = conn,
        .requests_served = 0,
    };
}

fn fastcgiReleaseConnection(endpoint_name: []const u8, cfg: *const ServerConfig, lease: FastcgiConnectionLease, reusable: bool, now_ms: i64) void {
    if (!reusable or !fastcgiKeepaliveConfigured(cfg)) {
        streamClose(lease.stream);
        server_metrics.fastcgiConnectionDiscarded();
        return;
    }

    const served = lease.requests_served + 1;
    if (served >= cfg.fastcgi_keepalive_max_requests) {
        streamClose(lease.stream);
        server_metrics.fastcgiConnectionDiscarded();
        return;
    }

    const idle_conn = FastcgiIdleConnection{
        .stream = lease.stream,
        .endpoint_name = endpoint_name,
        .expires_at_ms = now_ms + @as(i64, @intCast(cfg.fastcgi_keepalive_idle_timeout_ms)),
        .requests_served = served,
    };

    const io = activeIo();
    fastcgi_keepalive_pool.mutex.lockUncancelable(io);
    defer fastcgi_keepalive_pool.mutex.unlock(io);

    while (fastcgi_keepalive_pool.idle.items.len >= cfg.fastcgi_keepalive_max_idle) {
        closeIdleFastcgiConnection(fastcgi_keepalive_pool.idle.orderedRemove(0));
    }

    fastcgi_keepalive_pool.idle.append(std.heap.page_allocator, idle_conn) catch {
        streamClose(idle_conn.stream);
        server_metrics.fastcgiConnectionDiscarded();
        return;
    };
    server_metrics.fastcgiConnectionPooled();
}

fn parseOptionalContentLength(headers: []const u8) !?usize {
    if (findHeaderValue(headers, "Content-Length")) |raw| {
        const value = trimValue(raw);
        if (value.len == 0) return error.BadGateway;
        return std.fmt.parseInt(usize, value, 10) catch return error.BadGateway;
    }
    return null;
}

fn parseUpstreamResponseFraming(header_bytes: []const u8, response_headers: []const u8) !UpstreamResponseFraming {
    const connection = findHeaderValue(response_headers, "Connection") orelse "";
    const transfer_encoding = findHeaderValue(response_headers, "Transfer-Encoding") orelse "";
    return .{
        .status_code = parseHttpStatusCode(header_bytes),
        .content_length = try parseOptionalContentLength(response_headers),
        .transfer_chunked = hasConnectionToken(transfer_encoding, "chunked"),
        .connection_close = hasConnectionToken(connection, "close"),
    };
}

fn responseHasNoBody(method: []const u8, status_code: ?u16) bool {
    if (std.ascii.eqlIgnoreCase(method, "HEAD")) return true;
    const code = status_code orelse return false;
    return (code >= 100 and code < 200) or code == 204 or code == 304;
}

fn forwardFixedUpstreamBody(stream: std.Io.net.Stream, upstream_conn: std.Io.net.Stream, body_tail: []const u8, content_length: usize) !bool {
    const initial = @min(body_tail.len, content_length);
    if (initial > 0) streamWriteAll(stream, body_tail[0..initial]) catch return error.CloseConnection;
    if (body_tail.len > content_length) return false;

    var remaining = content_length - initial;
    var buf: [8192]u8 = undefined;
    while (remaining > 0) {
        const max_read = @min(remaining, buf.len);
        const n = try streamRead(upstream_conn, buf[0..max_read]);
        if (n == 0) return error.BadGateway;
        remaining -= n;
        streamWriteAll(stream, buf[0..n]) catch return error.CloseConnection;
    }
    return true;
}

fn forwardChunkedUpstreamBody(stream: std.Io.net.Stream, upstream_conn: std.Io.net.Stream, body_tail: []const u8) !void {
    var scanner = ChunkedBodyScanner{};

    if (body_tail.len > 0) {
        var consumed: usize = 0;
        while (consumed < body_tail.len) : (consumed += 1) {
            if (try scanner.consume(body_tail[consumed])) {
                streamWriteAll(stream, body_tail[0 .. consumed + 1]) catch return error.CloseConnection;
                return;
            }
        }
        streamWriteAll(stream, body_tail) catch return error.CloseConnection;
    }

    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try streamRead(upstream_conn, &buf);
        if (n == 0) return error.BadGateway;

        var consumed: usize = 0;
        while (consumed < n) : (consumed += 1) {
            if (try scanner.consume(buf[consumed])) {
                streamWriteAll(stream, buf[0 .. consumed + 1]) catch return error.CloseConnection;
                return;
            }
        }
        streamWriteAll(stream, buf[0..n]) catch return error.CloseConnection;
    }
}

fn forwardUnknownLengthUpstreamBody(stream: std.Io.net.Stream, upstream_conn: std.Io.net.Stream, body_tail: []const u8) !void {
    if (body_tail.len > 0) streamWriteAll(stream, body_tail) catch return error.CloseConnection;

    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try streamRead(upstream_conn, &buf);
        if (n == 0) break;
        streamWriteAll(stream, buf[0..n]) catch return error.CloseConnection;
    }
}

fn forwardUpstreamResponse(stream: std.Io.net.Stream, upstream_conn: std.Io.net.Stream, req: HttpRequest) !UpstreamResponseForwardResult {
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

    const headers_start = status_line_end + 2;
    const headers_end = header_end - 4;
    const response_headers = header_bytes[headers_start..headers_end];
    const framing = try parseUpstreamResponseFraming(header_bytes, response_headers);

    streamWriteAll(stream, header_bytes[0..status_line_end]) catch return error.CloseConnection;
    streamWriteAll(stream, "\r\n") catch return error.CloseConnection;

    var headers = std.mem.splitSequence(u8, response_headers, "\r\n");
    while (headers.next()) |line| {
        const trimmed = trimValue(line);
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const name = trimValue(trimmed[0..colon]);
            if (isSkippedProxyResponseHeader(name)) continue;
        }
        streamWriteAll(stream, trimmed) catch return error.CloseConnection;
        streamWriteAll(stream, "\r\n") catch return error.CloseConnection;
    }

    try streamWriteConfiguredResponseHeaders(stream);
    streamWriteAll(stream, "Connection: close\r\n\r\n") catch return error.CloseConnection;

    if (responseHasNoBody(req.method, framing.status_code)) {
        return .{ .reusable = !framing.connection_close and body_tail.len == 0 };
    }
    if (framing.content_length) |content_length| {
        const completed = try forwardFixedUpstreamBody(stream, upstream_conn, body_tail, content_length);
        return .{ .reusable = completed and !framing.connection_close };
    }
    if (framing.transfer_chunked) {
        try forwardChunkedUpstreamBody(stream, upstream_conn, body_tail);
        return .{ .reusable = !framing.connection_close };
    }

    try forwardUnknownLengthUpstreamBody(stream, upstream_conn, body_tail);
    return .{ .reusable = false };
}

fn forwardUpgradeResponse(stream: std.Io.net.Stream, upstream_conn: std.Io.net.Stream) !void {
    var response_buffer: [DEFAULT_MAX_REQUEST_BYTES]u8 = undefined;
    var used: usize = 0;

    while (used < response_buffer.len) {
        const n = try streamRead(upstream_conn, response_buffer[used..]);
        if (n == 0) return error.BadGateway;
        used += n;
        if (std.mem.indexOf(u8, response_buffer[0..used], "\r\n\r\n") != null) break;
    }

    const header_end = (std.mem.indexOf(u8, response_buffer[0..used], "\r\n\r\n") orelse return error.BadGateway) + 4;
    const header_bytes = response_buffer[0..header_end];
    const body_tail = response_buffer[header_end..used];
    const status_code = parseHttpStatusCode(header_bytes) orelse return error.BadGateway;
    if (status_code != 101) return error.BadGateway;

    streamWriteAll(stream, header_bytes) catch return error.CloseConnection;
    try proxyRawBidirectional(upstream_conn, stream, body_tail);
}

fn forwardToUpstream(stream: std.Io.net.Stream, allocator: std.mem.Allocator, upstream: *UpstreamConfig, req: HttpRequest, cfg: *const ServerConfig, timeout_ms: u32) !void {
    if (upstream.https) {
        return error.UnsupportedUpstreamScheme;
    }

    const upgrade_request = isHttpUpgradeRequest(req);
    const keepalive_enabled = upstreamKeepaliveConfigured(cfg) and !upgrade_request;
    const lease = try upstreamAcquireConnection(allocator, upstream, cfg, upstreamNowMs());
    var lease_released = false;
    defer if (!lease_released) {
        streamClose(lease.stream);
        server_metrics.upstreamConnectionDiscarded();
    };
    try setStreamTimeouts(lease.stream, timeout_ms, timeout_ms);

    const proxy_path = try buildProxyPath(allocator, upstream.base_path, req.path, req.query);
    defer allocator.free(proxy_path);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    const forwarded_host = if (findHeaderValue(req.headers, "Host")) |host|
        trimValue(host)
    else
        upstream.host;
    const forwarded_proto = if (findHeaderValue(req.headers, "X-Forwarded-Proto")) |proto|
        trimValue(proto)
    else if (cfg.tls_enabled)
        "https"
    else
        "http";

    // Rebuild framing headers from parsed state. Copying the client's
    // Content-Length here caused duplicate lengths and strict backends rejected it.
    try out.print(
        allocator,
        "{s} {s} HTTP/1.1\r\nHost: {s}\r\nConnection: {s}\r\n",
        .{
            req.method,
            proxy_path,
            forwarded_host,
            if (upgrade_request) "Upgrade" else if (keepalive_enabled) "keep-alive" else "close",
        },
    );
    if (upgrade_request) {
        try out.print(allocator, "Upgrade: {s}\r\n", .{trimValue(findHeaderValue(req.headers, "Upgrade").?)});
    }

    var saw_forwarded_host = false;
    var saw_forwarded_proto = false;
    var headers = std.mem.splitSequence(u8, req.headers, "\r\n");
    while (headers.next()) |line| {
        const trimmed = trimValue(line);
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const name = trimValue(trimmed[0..colon]);
            if (isSkippedProxyHeader(name)) continue;
            const value = trimValue(trimmed[colon + 1 ..]);
            if (value.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(name, "X-Forwarded-Host")) saw_forwarded_host = true;
            if (std.ascii.eqlIgnoreCase(name, "X-Forwarded-Proto")) saw_forwarded_proto = true;
            try out.print(allocator, "{s}: {s}\r\n", .{ name, value });
        }
    }

    // App frameworks commonly build absolute URLs from these. Keep caller-provided
    // values when a trusted frontend has already set them.
    if (!saw_forwarded_host) try out.print(allocator, "X-Forwarded-Host: {s}\r\n", .{forwarded_host});
    if (!saw_forwarded_proto) try out.print(allocator, "X-Forwarded-Proto: {s}\r\n", .{forwarded_proto});

    if (upgrade_request and req.body.len == 0) {
        try out.appendSlice(allocator, "\r\n");
    } else {
        try out.print(allocator, "Content-Length: {d}\r\n\r\n", .{req.body.len});
    }
    const request_line = try out.toOwnedSlice(allocator);
    defer allocator.free(request_line);

    streamWriteAll(lease.stream, request_line) catch |err| switch (err) {
        error.RequestTimeout => {
            return err;
        },
        else => |e| return e,
    };
    if (req.body.len > 0) {
        streamWriteAll(lease.stream, req.body) catch |err| switch (err) {
            error.RequestTimeout => {
                return err;
            },
            else => |e| return e,
        };
    }

    if (upgrade_request) {
        try forwardUpgradeResponse(stream, lease.stream);
        return error.CloseConnection;
    }

    const result = forwardUpstreamResponse(stream, lease.stream, req) catch |err| switch (err) {
        error.RequestTimeout => {
            return err;
        },
        else => |e| return e,
    };
    upstreamReleaseConnection(upstream, cfg, lease, result.reusable, upstreamNowMs());
    lease_released = true;

    return error.CloseConnection;
}

fn parseHttpStatusCode(response_head: []const u8) ?u16 {
    const first_line_end = std.mem.indexOf(u8, response_head, "\r\n") orelse response_head.len;
    const first_line = response_head[0..first_line_end];
    if (!std.mem.startsWith(u8, first_line, "HTTP/")) return null;

    var parts = std.mem.tokenizeAny(u8, first_line, " \t");
    _ = parts.next() orelse return null;
    const code_raw = parts.next() orelse return null;
    if (code_raw.len != 3) return null;
    return std.fmt.parseInt(u16, code_raw, 10) catch null;
}

fn readUpstreamHealthStatus(upstream_conn: std.Io.net.Stream) !u16 {
    var buffer: [2048]u8 = undefined;
    var used: usize = 0;
    while (used < buffer.len) {
        const n = streamRead(upstream_conn, buffer[used..]) catch |err| switch (err) {
            error.RequestTimeout => return err,
            else => |e| return e,
        };
        if (n == 0) break;
        used += n;
        if (std.mem.indexOf(u8, buffer[0..used], "\r\n\r\n") != null) break;
    }

    if (used == 0) return error.InvalidUpstream;
    return parseHttpStatusCode(buffer[0..used]) orelse error.InvalidUpstream;
}

fn checkUpstreamHealth(allocator: std.mem.Allocator, upstream: *const UpstreamConfig, health_path: []const u8, timeout_ms: u32) !bool {
    if (upstream.https) return error.UnsupportedUpstreamScheme;

    const upstream_conn = try connectTcpHost(allocator, upstream.host, upstream.port);
    defer streamClose(upstream_conn);
    try setStreamTimeouts(upstream_conn, timeout_ms, timeout_ms);

    const probe_path = try buildProxyPath(allocator, upstream.base_path, health_path, "");
    defer allocator.free(probe_path);

    var request_buffer: [1024]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &request_buffer,
        "GET {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: Layerline-healthcheck\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        .{ probe_path, upstream.host },
    );
    try streamWriteAll(upstream_conn, request);

    const status_code = try readUpstreamHealthStatus(upstream_conn);
    return status_code >= 200 and status_code < 400;
}

const UpstreamHealthTransition = enum {
    unchanged,
    ejected,
    recovered,
};

fn upstreamRecordActiveHealthResult(upstream: *UpstreamConfig, healthy: bool, now_ms: i64, cooldown_ms: u32, slow_start_ms: u32) UpstreamHealthTransition {
    if (healthy) {
        const was_unavailable = upstream.ejected_until_ms.load(.monotonic) != 0 or upstream.passive_failures.load(.monotonic) != 0;
        upstreamRecordSuccess(upstream, now_ms, slow_start_ms);
        return if (was_unavailable) .recovered else .unchanged;
    }

    const was_available = !upstreamIsEjected(upstream, now_ms);
    upstream.passive_failures.store(1, .monotonic);
    upstream.ejected_until_ms.store(now_ms + @as(i64, @intCast(cooldown_ms)), .monotonic);
    return if (was_available) .ejected else .unchanged;
}

fn activeHealthCooldownMs(cfg: *const ServerConfig) u32 {
    const doubled_interval = cfg.upstream_health_check_interval_ms *| 2;
    return @max(doubled_interval, cfg.upstream_health_check_timeout_ms);
}

fn recordActiveHealthMetrics(transition: UpstreamHealthTransition, healthy: bool) void {
    server_metrics.upstreamHealthCheckRan();
    if (!healthy) server_metrics.upstreamHealthCheckFailed();
    switch (transition) {
        .ejected => server_metrics.upstreamEjected(),
        .recovered => server_metrics.upstreamHealthCheckRecovered(),
        .unchanged => {},
    }
}

fn runActiveHealthCheckForPool(allocator: std.mem.Allocator, pool: *UpstreamPoolConfig, cfg: *const ServerConfig) void {
    const cooldown_ms = activeHealthCooldownMs(cfg);
    for (pool.targets.items) |*upstream| {
        if (shutdown_requested.load(.acquire)) return;

        const healthy = checkUpstreamHealth(allocator, upstream, cfg.upstream_health_check_path, cfg.upstream_health_check_timeout_ms) catch false;
        const transition = upstreamRecordActiveHealthResult(upstream, healthy, upstreamNowMs(), cooldown_ms, cfg.upstream_slow_start_ms);
        recordActiveHealthMetrics(transition, healthy);
    }
}

fn runActiveHealthCheckCycle(allocator: std.mem.Allocator, cfg: *ServerConfig) void {
    if (cfg.upstream) |*pool| {
        runActiveHealthCheckForPool(allocator, pool, cfg);
    }
    for (cfg.routes.items) |*route| {
        if (route.upstream) |*pool| {
            runActiveHealthCheckForPool(allocator, pool, cfg);
        }
    }
    for (cfg.domains.items) |*domain| {
        if (domain.upstream) |*pool| {
            runActiveHealthCheckForPool(allocator, pool, cfg);
        }
        for (domain.routes.items) |*route| {
            if (route.upstream) |*pool| {
                runActiveHealthCheckForPool(allocator, pool, cfg);
            }
        }
    }
}

const UpstreamHealthCheckContext = struct {
    io: std.Io,
    cfg: *ServerConfig,
};

fn sleepUpstreamHealthInterval(io: std.Io, interval_ms: u32) void {
    var remaining = interval_ms;
    while (remaining > 0 and !shutdown_requested.load(.acquire)) {
        const chunk = @min(remaining, 250);
        io.sleep(.fromMilliseconds(chunk), .awake) catch {};
        remaining -= chunk;
    }
}

fn upstreamHealthCheckTask(ctx: UpstreamHealthCheckContext) void {
    bindThreadIo(ctx.io);
    while (!shutdown_requested.load(.acquire)) {
        runActiveHealthCheckCycle(std.heap.page_allocator, ctx.cfg);
        sleepUpstreamHealthInterval(ctx.io, ctx.cfg.upstream_health_check_interval_ms);
    }
}

fn forwardToUpstreamPool(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    pool: *UpstreamPoolConfig,
    policy: UpstreamPoolPolicy,
    timeout_ms: u32,
    req: HttpRequest,
    cfg: *const ServerConfig,
) !void {
    if (pool.targets.items.len == 0) {
        try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "Proxy upstream pool is empty.", true, false, null);
        return;
    }

    const attempt_limit = upstreamAttemptLimit(pool, cfg.upstream_retries);
    const now_ms = upstreamNowMs();
    const start_ticket = upstreamStartTicket(pool, policy, now_ms, req, cfg);
    var considered: usize = 0;
    var attempts: usize = 0;
    var skipped_ejected: usize = 0;
    var last_error: ?anyerror = null;

    attempt_loop: while (considered < pool.targets.items.len and attempts < attempt_limit) : (considered += 1) {
        const upstream = upstreamAtAttempt(pool, start_ticket, considered);
        const lease = upstreamBeginAttempt(upstream, now_ms, cfg) orelse {
            skipped_ejected += 1;
            server_metrics.upstreamEjectedSkip();
            continue :attempt_loop;
        };

        if (attempts > 0) server_metrics.upstreamRetried();
        attempts += 1;
        server_metrics.upstreamRequestStarted();
        forwardToUpstream(stream, allocator, upstream, req, cfg, timeout_ms) catch |err| switch (err) {
            error.CloseConnection => {
                upstreamEndAttempt(upstream, lease);
                upstreamRecordSuccess(upstream, upstreamNowMs(), cfg.upstream_slow_start_ms);
                return err;
            },
            error.OutOfMemory => {
                upstreamEndAttempt(upstream, lease);
                return err;
            },
            else => {
                upstreamEndAttempt(upstream, lease);
                last_error = err;
                server_metrics.upstreamRequestFailed();
                if (upstreamRecordFailure(upstream, upstreamNowMs(), cfg.upstream_max_failures, cfg.upstream_fail_timeout_ms)) {
                    server_metrics.upstreamEjected();
                }
                continue :attempt_loop;
            },
        };
        upstreamEndAttempt(upstream, lease);
        upstreamRecordSuccess(upstream, upstreamNowMs(), cfg.upstream_slow_start_ms);
        return;
    }

    if (attempts == 0 and skipped_ejected > 0) {
        try sendCoolErrorWithConnection(stream, allocator, 503, "Service Unavailable", "All configured upstream targets are unavailable or limited by circuit breaker recovery.", true, false, null);
        return;
    }

    if (last_error) |err| switch (err) {
        error.RequestTimeout => {
            try sendCoolErrorWithConnection(stream, allocator, 504, "Gateway Timeout", "All configured upstream attempts timed out.", true, false, null);
            return;
        },
        error.UnsupportedUpstreamScheme => {
            try sendCoolErrorWithConnection(stream, allocator, 501, "Not Implemented", "HTTPS upstream is not yet supported in this single-file server path. Use HTTPS reverse proxy in front of this binary.", true, false, null);
            return;
        },
        else => {},
    };

    try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "All configured upstream attempts failed.", true, false, null);
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
    try handlePhpScript(io, stream, allocator, cfg, req, cfg.php_root, cfg.php_binary, cfg.php_fastcgi, cfg.upstream_timeout_ms, rel_path, req.path, "", close_connection, is_head, process_env);
}

const PhpFrontControllerTarget = struct {
    script_rel_path: []const u8,
    script_name: []const u8,
    path_info: []const u8,

    fn deinit(self: *const PhpFrontControllerTarget, allocator: std.mem.Allocator) void {
        allocator.free(self.script_rel_path);
        allocator.free(self.script_name);
        allocator.free(self.path_info);
    }
};

fn appendUrlPath(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    if (value.len == 0) return;
    const segment = if (value[0] == '/') value[1..] else value;
    if (segment.len == 0) return;
    if (out.items.len == 0 or out.items[out.items.len - 1] != '/') try out.append(allocator, '/');
    try out.appendSlice(allocator, segment);
}

fn phpFrontControllerScriptName(allocator: std.mem.Allocator, route: ?*const RouteConfig, php_index: []const u8) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, '/');

    if (route) |r| {
        if (r.strip_prefix and r.match_kind == .prefix) {
            try appendUrlPath(&out, allocator, r.pattern);
        }
    }
    try appendUrlPath(&out, allocator, php_index);
    return out.toOwnedSlice(allocator);
}

fn phpFrontControllerPathInfo(allocator: std.mem.Allocator, route: ?*const RouteConfig, request_path: []const u8, script_name: []const u8) ![]const u8 {
    if (std.mem.eql(u8, request_path, script_name)) return allocator.dupe(u8, "");

    if (route) |r| {
        if (r.strip_prefix and r.match_kind == .prefix) {
            const raw = if (request_path.len > r.pattern.len) request_path[r.pattern.len..] else "";
            if (raw.len == 0) return allocator.dupe(u8, "/");
            return if (raw[0] == '/')
                allocator.dupe(u8, raw)
            else
                std.fmt.allocPrint(allocator, "/{s}", .{raw});
        }
    }

    return if (request_path.len == 0)
        allocator.dupe(u8, "/")
    else
        allocator.dupe(u8, request_path);
}

fn makePhpFrontControllerTarget(allocator: std.mem.Allocator, route: ?*const RouteConfig, request_path: []const u8, php_index: []const u8) !PhpFrontControllerTarget {
    if (!isSafeRelativeScriptPath(php_index)) return error.InvalidConfigValue;

    const script_rel_path = try allocator.dupe(u8, php_index);
    errdefer allocator.free(script_rel_path);
    const script_name = try phpFrontControllerScriptName(allocator, route, php_index);
    errdefer allocator.free(script_name);
    const path_info = try phpFrontControllerPathInfo(allocator, route, request_path, script_name);
    errdefer allocator.free(path_info);

    return .{
        .script_rel_path = script_rel_path,
        .script_name = script_name,
        .path_info = path_info,
    };
}

fn handlePhpFrontController(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    route: ?*const RouteConfig,
    php_root: []const u8,
    php_binary: []const u8,
    php_fastcgi: ?[]const u8,
    timeout_ms: u32,
    php_index: []const u8,
    close_connection: bool,
    is_head: bool,
    process_env: *const std.process.Environ.Map,
) !void {
    const target = try makePhpFrontControllerTarget(allocator, route, req.path, php_index);
    defer target.deinit(allocator);
    try handlePhpScript(io, stream, allocator, cfg, req, php_root, php_binary, php_fastcgi, timeout_ms, target.script_rel_path, target.script_name, target.path_info, close_connection, is_head, process_env);
}

fn appendFastcgiLength(out: *std.ArrayList(u8), allocator: std.mem.Allocator, len: usize) !void {
    if (len < 128) {
        try out.append(allocator, @intCast(len));
        return;
    }
    if (len > 0x7fff_ffff) return error.InvalidConfigValue;
    const wide: u32 = @intCast(len);
    try out.append(allocator, @intCast(((wide >> 24) & 0x7f) | 0x80));
    try out.append(allocator, @intCast((wide >> 16) & 0xff));
    try out.append(allocator, @intCast((wide >> 8) & 0xff));
    try out.append(allocator, @intCast(wide & 0xff));
}

fn appendFastcgiParam(out: *std.ArrayList(u8), allocator: std.mem.Allocator, name: []const u8, value: []const u8) !void {
    if (name.len == 0) return;
    try appendFastcgiLength(out, allocator, name.len);
    try appendFastcgiLength(out, allocator, value.len);
    try out.appendSlice(allocator, name);
    try out.appendSlice(allocator, value);
}

fn appendFastcgiRequestHeaders(allocator: std.mem.Allocator, params: *std.ArrayList(u8), request_headers: []const u8) !void {
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
            try appendFastcgiParam(params, allocator, env_name.items, value);
        }
    }
}

fn buildPhpFastcgiParams(
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    php_root: []const u8,
    script_path: []const u8,
    script_name: []const u8,
    path_info: []const u8,
) ![]u8 {
    var params = std.ArrayList(u8).empty;
    errdefer params.deinit(allocator);

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

    const path_translated = if (path_info.len > 0 and path_info[0] == '/') blk: {
        const translated_rel = path_info[1..];
        break :blk try std.fs.path.join(allocator, &.{ php_root, translated_rel });
    } else try allocator.dupe(u8, script_path);
    defer allocator.free(path_translated);

    try appendFastcgiParam(&params, allocator, "GATEWAY_INTERFACE", "CGI/1.1");
    try appendFastcgiParam(&params, allocator, "SERVER_SOFTWARE", SERVER_HEADER);
    try appendFastcgiParam(&params, allocator, "SERVER_NAME", cfg.host);
    try appendFastcgiParam(&params, allocator, "SERVER_PORT", server_port);
    try appendFastcgiParam(&params, allocator, "SERVER_PROTOCOL", req.version);
    try appendFastcgiParam(&params, allocator, "REQUEST_METHOD", req.method);
    try appendFastcgiParam(&params, allocator, "REQUEST_URI", request_uri);
    try appendFastcgiParam(&params, allocator, "SCRIPT_NAME", script_name);
    try appendFastcgiParam(&params, allocator, "SCRIPT_FILENAME", script_path);
    try appendFastcgiParam(&params, allocator, "PHP_SELF", script_name);
    try appendFastcgiParam(&params, allocator, "PATH_TRANSLATED", path_translated);
    try appendFastcgiParam(&params, allocator, "PATH_INFO", path_info);
    try appendFastcgiParam(&params, allocator, "QUERY_STRING", req.query);
    try appendFastcgiParam(&params, allocator, "DOCUMENT_ROOT", php_root);
    try appendFastcgiParam(&params, allocator, "REQUEST_SCHEME", "http");
    try appendFastcgiParam(&params, allocator, "HTTPS", "off");
    try appendFastcgiParam(&params, allocator, "REDIRECT_STATUS", "200");
    try appendFastcgiParam(&params, allocator, "CONTENT_LENGTH", content_length);
    try appendFastcgiParam(&params, allocator, "CONTENT_TYPE", findHeaderValue(req.headers, "Content-Type") orelse "");
    try appendFastcgiParam(&params, allocator, "FCGI_ROLE", "RESPONDER");
    try appendFastcgiRequestHeaders(allocator, &params, req.headers);

    return params.toOwnedSlice(allocator);
}

fn writeFastcgiRecord(conn: std.Io.net.Stream, record_type: u8, request_id: u16, content: []const u8) !void {
    if (content.len == 0) {
        const header = [_]u8{
            FASTCGI_VERSION,
            record_type,
            @intCast(request_id >> 8),
            @intCast(request_id & 0xff),
            0,
            0,
            0,
            0,
        };
        try streamWriteAll(conn, &header);
        return;
    }

    var offset: usize = 0;
    while (offset < content.len) {
        const chunk_len = @min(content.len - offset, 0xffff);
        const padding_len: u8 = @intCast((8 - (chunk_len % 8)) % 8);
        const header = [_]u8{
            FASTCGI_VERSION,
            record_type,
            @intCast(request_id >> 8),
            @intCast(request_id & 0xff),
            @intCast(chunk_len >> 8),
            @intCast(chunk_len & 0xff),
            padding_len,
            0,
        };
        try streamWriteAll(conn, &header);
        try streamWriteAll(conn, content[offset .. offset + chunk_len]);
        if (padding_len > 0) {
            const padding = [_]u8{0} ** 8;
            try streamWriteAll(conn, padding[0..padding_len]);
        }
        offset += chunk_len;
    }
}

fn readFastcgiBytes(conn: std.Io.net.Stream, out: []u8) !void {
    var used: usize = 0;
    while (used < out.len) {
        const n = try streamRead(conn, out[used..]);
        if (n == 0) return error.BadGateway;
        used += n;
    }
}

fn skipFastcgiBytes(conn: std.Io.net.Stream, len: usize) !void {
    var scratch: [512]u8 = undefined;
    var remaining = len;
    while (remaining > 0) {
        const n = @min(remaining, scratch.len);
        try readFastcgiBytes(conn, scratch[0..n]);
        remaining -= n;
    }
}

const FastcgiRunResult = struct {
    stdout: []u8,
    stderr: []u8,
    app_status: u32,
    protocol_status: u8,

    fn deinit(self: *const FastcgiRunResult, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

fn readFastcgiResponse(allocator: std.mem.Allocator, conn: std.Io.net.Stream, request_id: u16, max_stdout: usize) !FastcgiRunResult {
    var stdout = std.ArrayList(u8).empty;
    errdefer stdout.deinit(allocator);
    var stderr = std.ArrayList(u8).empty;
    errdefer stderr.deinit(allocator);

    var app_status: u32 = 0;
    var protocol_status: u8 = FASTCGI_REQUEST_COMPLETE;

    while (true) {
        var header: [8]u8 = undefined;
        try readFastcgiBytes(conn, &header);
        if (header[0] != FASTCGI_VERSION) return error.BadGateway;

        const record_type = header[1];
        const rec_request_id = (@as(u16, header[2]) << 8) | @as(u16, header[3]);
        const content_len = (@as(usize, header[4]) << 8) | @as(usize, header[5]);
        const padding_len = @as(usize, header[6]);

        if (rec_request_id != request_id and rec_request_id != 0) {
            try skipFastcgiBytes(conn, content_len + padding_len);
            continue;
        }

        switch (record_type) {
            FASTCGI_STDOUT => {
                if (stdout.items.len + content_len > max_stdout) return error.StreamTooLong;
                const old_len = stdout.items.len;
                try stdout.resize(allocator, old_len + content_len);
                try readFastcgiBytes(conn, stdout.items[old_len..]);
            },
            FASTCGI_STDERR => {
                var remaining = content_len;
                var scratch: [512]u8 = undefined;
                while (remaining > 0) {
                    const n = @min(remaining, scratch.len);
                    try readFastcgiBytes(conn, scratch[0..n]);
                    if (stderr.items.len < DEFAULT_MAX_PHP_FASTCGI_STDERR_BYTES) {
                        const keep = @min(n, DEFAULT_MAX_PHP_FASTCGI_STDERR_BYTES - stderr.items.len);
                        try stderr.appendSlice(allocator, scratch[0..keep]);
                    }
                    remaining -= n;
                }
            },
            FASTCGI_END_REQUEST => {
                var body: [8]u8 = .{0} ** 8;
                if (content_len >= body.len) {
                    try readFastcgiBytes(conn, &body);
                    try skipFastcgiBytes(conn, content_len - body.len);
                } else {
                    try readFastcgiBytes(conn, body[0..content_len]);
                }
                app_status = (@as(u32, body[0]) << 24) | (@as(u32, body[1]) << 16) | (@as(u32, body[2]) << 8) | @as(u32, body[3]);
                protocol_status = body[4];
                if (padding_len > 0) try skipFastcgiBytes(conn, padding_len);
                return .{
                    .stdout = try stdout.toOwnedSlice(allocator),
                    .stderr = try stderr.toOwnedSlice(allocator),
                    .app_status = app_status,
                    .protocol_status = protocol_status,
                };
            },
            else => try skipFastcgiBytes(conn, content_len),
        }

        if (record_type != FASTCGI_END_REQUEST and padding_len > 0) {
            try skipFastcgiBytes(conn, padding_len);
        }
    }
}

fn sendPhpOutput(stream: std.Io.net.Stream, allocator: std.mem.Allocator, output: []const u8, close_connection: bool, is_head: bool) !void {
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

fn collectCgiHttp2Headers(allocator: std.mem.Allocator, headers: []const u8) ![]h2_native.Header {
    var out = std.ArrayList(h2_native.Header).empty;
    errdefer out.deinit(allocator);

    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |line| {
        const trimmed = trimValue(line);
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const name = trimValue(trimmed[0..colon]);
            const value = trimValue(trimmed[colon + 1 ..]);
            if (name.len == 0 or value.len == 0 or isSkippedCgiResponseHeader(name) or isSkippedHttp2ResponseHeader(name)) continue;
            try out.append(allocator, .{
                .name = try allocator.dupe(u8, name),
                .value = try allocator.dupe(u8, value),
            });
        }
    }

    return out.toOwnedSlice(allocator);
}

fn h2PhpOutputResponse(allocator: std.mem.Allocator, output: []const u8) !H2BufferedResponse {
    const split = splitCgiHeaderBlock(output) orelse {
        return .{
            .status_code = 200,
            .content_type = "text/plain; charset=utf-8",
            .body = try allocator.dupe(u8, output),
        };
    };

    const status = parseCgiStatus(split.headers);
    const content_type = if (findCgiHeaderValue(split.headers, "Content-Type")) |ctype|
        try allocator.dupe(u8, trimValue(ctype))
    else
        "text/plain; charset=utf-8";
    const headers = try collectCgiHttp2Headers(allocator, split.headers);

    return .{
        .status_code = status.code,
        .content_type = content_type,
        .body = try allocator.dupe(u8, split.body),
        .headers = headers,
    };
}

fn runPhpFastcgiRequest(
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    php_root: []const u8,
    php_fastcgi: []const u8,
    script_path: []const u8,
    script_name: []const u8,
    path_info: []const u8,
    timeout_ms: u32,
) !FastcgiRunResult {
    const endpoint = parseFastcgiEndpoint(php_fastcgi) catch return error.InvalidFastcgiEndpoint;

    const lease = fastcgiAcquireConnection(allocator, php_fastcgi, endpoint, cfg, timeout_ms, upstreamNowMs()) catch return error.FastcgiConnectFailed;
    const conn = lease.stream;
    var reusable_fastcgi_conn = false;
    defer fastcgiReleaseConnection(php_fastcgi, cfg, lease, reusable_fastcgi_conn, upstreamNowMs());

    const request_id: u16 = 1;
    const begin_body = [_]u8{ 0, @intCast(FASTCGI_RESPONDER), if (fastcgiKeepaliveConfigured(cfg)) FASTCGI_KEEP_CONN else 0, 0, 0, 0, 0, 0 };
    try writeFastcgiRecord(conn, FASTCGI_BEGIN_REQUEST, request_id, &begin_body);

    const params = try buildPhpFastcgiParams(allocator, cfg, req, php_root, script_path, script_name, path_info);
    defer allocator.free(params);
    try writeFastcgiRecord(conn, FASTCGI_PARAMS, request_id, params);
    try writeFastcgiRecord(conn, FASTCGI_PARAMS, request_id, "");
    if (req.body.len > 0) try writeFastcgiRecord(conn, FASTCGI_STDIN, request_id, req.body);
    try writeFastcgiRecord(conn, FASTCGI_STDIN, request_id, "");

    const result = try readFastcgiResponse(allocator, conn, request_id, cfg.max_php_output_bytes);
    errdefer result.deinit(allocator);

    if (result.protocol_status != FASTCGI_REQUEST_COMPLETE) return error.FastcgiProtocolFailed;
    if (result.app_status != 0) return error.FastcgiAppFailed;

    reusable_fastcgi_conn = fastcgiKeepaliveConfigured(cfg);
    return result;
}

fn handlePhpFastcgi(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    php_root: []const u8,
    php_fastcgi: []const u8,
    script_path: []const u8,
    script_name: []const u8,
    path_info: []const u8,
    timeout_ms: u32,
    close_connection: bool,
    is_head: bool,
) !void {
    const result = runPhpFastcgiRequest(allocator, cfg, req, php_root, php_fastcgi, script_path, script_name, path_info, timeout_ms) catch |err| switch (err) {
        error.InvalidFastcgiEndpoint => {
            try sendCoolErrorWithConnection(stream, allocator, 500, "Server Error", "PHP FastCGI endpoint is invalid.", close_connection, false, null);
            return;
        },
        error.FastcgiConnectFailed => {
            std.debug.print("PHP FastCGI connect failed for {s}\n", .{php_fastcgi});
            try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "PHP FastCGI worker could not be reached.", close_connection, false, null);
            return;
        },
        error.StreamTooLong => {
            try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "PHP FastCGI response exceeded max_php_output_bytes.", close_connection, false, null);
            return;
        },
        error.FastcgiProtocolFailed => {
            try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "PHP FastCGI request did not complete cleanly.", close_connection, false, null);
            return;
        },
        error.FastcgiAppFailed => {
            try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "PHP FastCGI app returned a non-zero status.", close_connection, false, null);
            return;
        },
        else => |e| return e,
    };
    defer result.deinit(allocator);

    if (result.stderr.len > 0) {
        std.debug.print("PHP FastCGI stderr: {s}\n", .{result.stderr});
    }

    try sendPhpOutput(stream, allocator, result.stdout, close_connection, is_head);
}

fn buildHttp2PhpFastcgiResponse(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    php_root: []const u8,
    php_fastcgi: ?[]const u8,
    script_rel_path: []const u8,
    script_name: []const u8,
    path_info: []const u8,
    timeout_ms: u32,
) !H2BufferedResponse {
    const endpoint = php_fastcgi orelse return h2CoolErrorResponse(allocator, 501, "Not Implemented", "Native HTTP/2 PHP routing currently requires FastCGI.");
    if (disablesOptionalUrl(endpoint)) return h2CoolErrorResponse(allocator, 501, "Not Implemented", "Native HTTP/2 PHP routing currently requires FastCGI.");

    const rel_path = script_rel_path;
    if (rel_path.len == 0 or std.mem.indexOf(u8, rel_path, "..") != null) {
        return h2CoolErrorResponse(allocator, 404, "Not Found", "The requested resource was not found on this server.");
    }

    const script_path = try std.fs.path.join(allocator, &.{ php_root, rel_path });
    defer allocator.free(script_path);

    const script_stat = std.Io.Dir.cwd().statFile(io, script_path, .{}) catch {
        return h2CoolErrorResponse(allocator, 404, "Not Found", "The requested resource was not found on this server.");
    };
    if (script_stat.kind != .file) {
        return h2CoolErrorResponse(allocator, 404, "Not Found", "The requested resource was not found on this server.");
    }

    const result = runPhpFastcgiRequest(allocator, cfg, req, php_root, endpoint, script_path, script_name, path_info, timeout_ms) catch |err| switch (err) {
        error.InvalidFastcgiEndpoint => return h2CoolErrorResponse(allocator, 500, "Server Error", "PHP FastCGI endpoint is invalid."),
        error.FastcgiConnectFailed => return h2CoolErrorResponse(allocator, 502, "Bad Gateway", "PHP FastCGI worker could not be reached."),
        error.StreamTooLong => return h2CoolErrorResponse(allocator, 502, "Bad Gateway", "PHP FastCGI response exceeded max_php_output_bytes."),
        error.FastcgiProtocolFailed => return h2CoolErrorResponse(allocator, 502, "Bad Gateway", "PHP FastCGI request did not complete cleanly."),
        error.FastcgiAppFailed => return h2CoolErrorResponse(allocator, 502, "Bad Gateway", "PHP FastCGI app returned a non-zero status."),
        else => |e| return e,
    };
    defer result.deinit(allocator);

    if (result.stderr.len > 0) {
        std.debug.print("PHP FastCGI stderr: {s}\n", .{result.stderr});
    }

    return h2PhpOutputResponse(allocator, result.stdout);
}

fn handlePhpScript(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    php_root: []const u8,
    php_binary: []const u8,
    php_fastcgi: ?[]const u8,
    timeout_ms: u32,
    script_rel_path: []const u8,
    script_name: []const u8,
    path_info: []const u8,
    close_connection: bool,
    is_head: bool,
    process_env: *const std.process.Environ.Map,
) !void {
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

    if (php_fastcgi) |endpoint| {
        if (!disablesOptionalUrl(endpoint)) {
            try handlePhpFastcgi(stream, allocator, cfg, req, php_root, endpoint, script_path, script_name, path_info, timeout_ms, close_connection, is_head);
            return;
        }
    }

    if (php_binary.len == 0) {
        try sendCoolErrorWithConnection(stream, allocator, 500, "Server Error", "PHP support is not configured for this server.", close_connection, false, null);
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
    const path_translated = if (path_info.len > 0 and path_info[0] == '/') blk: {
        const translated_rel = path_info[1..];
        break :blk try std.fs.path.join(allocator, &.{ php_root, translated_rel });
    } else try allocator.dupe(u8, script_path);
    defer allocator.free(path_translated);

    try child_env.put("SCRIPT_NAME", script_name);
    try child_env.put("SCRIPT_FILENAME", script_path);
    try child_env.put("PHP_SELF", script_name);
    try child_env.put("PATH_TRANSLATED", path_translated);
    try child_env.put("PATH_INFO", path_info);
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

    try sendPhpOutput(stream, allocator, output, close_connection, is_head);
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

fn findNamedRouteMutable(cfg: *ServerConfig, path: []const u8) ?*RouteConfig {
    return findNamedRouteInMutable(&cfg.routes, path);
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

fn findNamedRouteInMutable(routes: *std.ArrayList(RouteConfig), path: []const u8) ?*RouteConfig {
    var best: ?*RouteConfig = null;
    var best_len: usize = 0;
    for (routes.items) |*route| {
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

fn findDomainForHostMutable(cfg: *ServerConfig, raw_host: []const u8) ?*DomainConfig {
    const host = stripHostPort(raw_host);
    var best: ?*DomainConfig = null;
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

fn findDomainForRequestMutable(cfg: *ServerConfig, headers: []const u8) ?*DomainConfig {
    const host = findHeaderValue(headers, "Host") orelse return null;
    return findDomainForHostMutable(cfg, host);
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

fn domainPhpFastcgi(cfg: *const ServerConfig, domain: ?*const DomainConfig) ?[]const u8 {
    if (domain) |d| {
        if (d.php_fastcgi) |value| {
            if (disablesOptionalUrl(value)) return null;
            return value;
        }
    }
    return cfg.php_fastcgi;
}

fn domainPhpIndex(cfg: *const ServerConfig, domain: ?*const DomainConfig) []const u8 {
    if (domain) |d| {
        if (d.php_index) |value| return value;
    }
    return cfg.php_index;
}

fn domainPhpInfoPage(cfg: *const ServerConfig, domain: ?*const DomainConfig) bool {
    if (domain) |d| {
        if (d.php_info_page) |value| return value;
    }
    return cfg.php_info_page;
}

fn domainPhpFrontController(cfg: *const ServerConfig, domain: ?*const DomainConfig) bool {
    if (domain) |d| {
        if (d.php_front_controller) |value| return value;
    }
    return cfg.php_front_controller;
}

fn routePhpIndex(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: *const RouteConfig) []const u8 {
    if (route.php_index) |value| return value;
    return domainPhpIndex(cfg, domain);
}

fn routePhpFrontController(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: *const RouteConfig) bool {
    if (route.php_front_controller) |value| return value;
    return domainPhpFrontController(cfg, domain);
}

fn routePhpFastcgi(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: *const RouteConfig) ?[]const u8 {
    if (route.php_fastcgi) |value| {
        if (disablesOptionalUrl(value)) return null;
        return value;
    }
    return domainPhpFastcgi(cfg, domain);
}

fn domainUpstream(cfg: *const ServerConfig, domain: ?*const DomainConfig) ?UpstreamPoolConfig {
    if (domain) |d| {
        if (d.upstream) |value| return value;
    }
    return cfg.upstream;
}

fn domainUpstreamMutable(cfg: *ServerConfig, domain: ?*DomainConfig) ?*UpstreamPoolConfig {
    if (domain) |d| {
        if (d.upstream) |*value| return value;
    }
    if (cfg.upstream) |*value| return value;
    return null;
}

fn domainUpstreamPolicy(cfg: *const ServerConfig, domain: ?*const DomainConfig) UpstreamPoolPolicy {
    if (domain) |d| {
        if (d.upstream_policy) |policy| return policy;
    }
    return cfg.upstream_policy;
}

fn routeUpstreamPolicy(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: *const RouteConfig) UpstreamPoolPolicy {
    if (route.upstream_policy) |policy| return policy;
    return domainUpstreamPolicy(cfg, domain);
}

fn domainUpstreamTimeoutMs(cfg: *const ServerConfig, domain: ?*const DomainConfig) u32 {
    if (domain) |d| {
        if (d.upstream_timeout_ms) |value| return value;
    }
    return cfg.upstream_timeout_ms;
}

fn routeUpstreamTimeoutMs(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: *const RouteConfig) u32 {
    if (route.upstream_timeout_ms) |value| return value;
    return domainUpstreamTimeoutMs(cfg, domain);
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

fn findDomainRouteMutable(domain: ?*DomainConfig, path: []const u8) ?*RouteConfig {
    if (domain) |d| {
        return findNamedRouteInMutable(&d.routes, path);
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
    cfg: *ServerConfig,
    domain: ?*DomainConfig,
    route: *RouteConfig,
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
            const php_fastcgi = routePhpFastcgi(cfg, domain, route);
            if (routePhpFrontController(cfg, domain, route)) {
                try handlePhpFrontController(io, stream, allocator, cfg, req, route, php_root, php_binary, php_fastcgi, routeUpstreamTimeoutMs(cfg, domain, route), routePhpIndex(cfg, domain, route), close_connection, is_head, process_env);
                return;
            }
            const script_rel = try routeFileRelativePath(allocator, route, req.path, route.index_file orelse domainIndexFile(cfg, domain));
            defer allocator.free(script_rel);
            try handlePhpScript(io, stream, allocator, cfg, req, php_root, php_binary, php_fastcgi, routeUpstreamTimeoutMs(cfg, domain, route), script_rel, req.path, "", close_connection, is_head, process_env);
            return;
        },
        .proxy => {
            const pool = if (route.upstream) |*route_pool|
                route_pool
            else
                domainUpstreamMutable(cfg, domain) orelse {
                    try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "Route proxy upstream is not configured.", close_connection, false, null);
                    return;
                };
            try forwardToUpstreamPool(stream, allocator, pool, routeUpstreamPolicy(cfg, domain, route), routeUpstreamTimeoutMs(cfg, domain, route), req, cfg);
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
        .php_index = DEFAULT_PHP_INDEX,
        .php_fastcgi = null,
        .php_info_page = false,
        .php_front_controller = false,
        .upstream = null,
        .upstream_policy = .round_robin,
        .tls_enabled = false,
        .tls_cert = null,
        .tls_key = null,
        .tls_material = null,
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
        .domain_config_dir = null,
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
        .upstream_retries = DEFAULT_UPSTREAM_RETRIES,
        .upstream_max_failures = DEFAULT_UPSTREAM_MAX_FAILURES,
        .upstream_fail_timeout_ms = DEFAULT_UPSTREAM_FAIL_TIMEOUT_MS,
        .upstream_keepalive_enabled = true,
        .upstream_keepalive_max_idle = DEFAULT_UPSTREAM_KEEPALIVE_MAX_IDLE,
        .upstream_keepalive_idle_timeout_ms = DEFAULT_UPSTREAM_KEEPALIVE_IDLE_TIMEOUT_MS,
        .upstream_keepalive_max_requests = DEFAULT_UPSTREAM_KEEPALIVE_MAX_REQUESTS,
        .fastcgi_keepalive_enabled = true,
        .fastcgi_keepalive_max_idle = DEFAULT_FASTCGI_KEEPALIVE_MAX_IDLE,
        .fastcgi_keepalive_idle_timeout_ms = DEFAULT_FASTCGI_KEEPALIVE_IDLE_TIMEOUT_MS,
        .fastcgi_keepalive_max_requests = DEFAULT_FASTCGI_KEEPALIVE_MAX_REQUESTS,
        .upstream_health_check_enabled = false,
        .upstream_health_check_path = DEFAULT_UPSTREAM_HEALTH_CHECK_PATH,
        .upstream_health_check_interval_ms = DEFAULT_UPSTREAM_HEALTH_CHECK_INTERVAL_MS,
        .upstream_health_check_timeout_ms = DEFAULT_UPSTREAM_HEALTH_CHECK_TIMEOUT_MS,
        .upstream_circuit_breaker_enabled = true,
        .upstream_circuit_half_open_max = DEFAULT_UPSTREAM_CIRCUIT_HALF_OPEN_MAX,
        .upstream_slow_start_ms = DEFAULT_UPSTREAM_SLOW_START_MS,
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
    try applyConfigLine(&cfg, allocator, "upstream_policy", "random");
    try applyConfigLine(&cfg, allocator, "upstream_max_failures", "3");
    try applyConfigLine(&cfg, allocator, "upstream_fail_timeout_ms", "1500");
    try applyConfigLine(&cfg, allocator, "upstream_keepalive", "true");
    try applyConfigLine(&cfg, allocator, "upstream_keepalive_max_idle", "24");
    try applyConfigLine(&cfg, allocator, "upstream_keepalive_idle_timeout_ms", "45000");
    try applyConfigLine(&cfg, allocator, "upstream_keepalive_max_requests", "250");
    try applyConfigLine(&cfg, allocator, "fastcgi_keepalive", "true");
    try applyConfigLine(&cfg, allocator, "fastcgi_keepalive_max_idle", "12");
    try applyConfigLine(&cfg, allocator, "fastcgi_keepalive_idle_timeout_ms", "35000");
    try applyConfigLine(&cfg, allocator, "fastcgi_keepalive_max_requests", "125");
    try applyConfigLine(&cfg, allocator, "upstream_health_check", "true");
    try applyConfigLine(&cfg, allocator, "upstream_health_check_path", "/ready");
    try applyConfigLine(&cfg, allocator, "upstream_health_check_interval_ms", "2500");
    try applyConfigLine(&cfg, allocator, "upstream_health_check_timeout_ms", "750");
    try applyConfigLine(&cfg, allocator, "upstream_circuit_half_open_max", "2");
    try applyConfigLine(&cfg, allocator, "upstream_slow_start_ms", "6000");
    try applyConfigLine(&cfg, allocator, "header", "X-Global-Policy: one");
    try applyConfigLine(&cfg, allocator, "route_header.assets", "X-Route-Policy: assets");
    try applyConfigLine(&cfg, allocator, "route_proxy_policy.health", "round-robin");
    try applyConfigLine(&cfg, allocator, "route_proxy_timeout_ms.health", "1250");

    try std.testing.expectEqualStrings("health", findNamedRoute(&cfg, "/health").?.name);
    try std.testing.expectEqualStrings("private", findNamedRoute(&cfg, "/assets/private/a.txt").?.name);
    try std.testing.expectEqualStrings("assets", findNamedRoute(&cfg, "/assets/hello.txt").?.name);
    try std.testing.expect(findNamedRoute(&cfg, "/missing") == null);
    try std.testing.expectEqual(UpstreamPoolPolicy.random, cfg.upstream_policy);
    try std.testing.expectEqual(@as(usize, 3), cfg.upstream_max_failures);
    try std.testing.expectEqual(@as(u32, 1500), cfg.upstream_fail_timeout_ms);
    try std.testing.expect(cfg.upstream_keepalive_enabled);
    try std.testing.expectEqual(@as(usize, 24), cfg.upstream_keepalive_max_idle);
    try std.testing.expectEqual(@as(u32, 45000), cfg.upstream_keepalive_idle_timeout_ms);
    try std.testing.expectEqual(@as(usize, 250), cfg.upstream_keepalive_max_requests);
    try std.testing.expect(cfg.fastcgi_keepalive_enabled);
    try std.testing.expectEqual(@as(usize, 12), cfg.fastcgi_keepalive_max_idle);
    try std.testing.expectEqual(@as(u32, 35000), cfg.fastcgi_keepalive_idle_timeout_ms);
    try std.testing.expectEqual(@as(usize, 125), cfg.fastcgi_keepalive_max_requests);
    try std.testing.expect(cfg.upstream_health_check_enabled);
    try std.testing.expectEqualStrings("/ready", cfg.upstream_health_check_path);
    try std.testing.expectEqual(@as(u32, 2500), cfg.upstream_health_check_interval_ms);
    try std.testing.expectEqual(@as(u32, 750), cfg.upstream_health_check_timeout_ms);
    try std.testing.expect(cfg.upstream_circuit_breaker_enabled);
    try std.testing.expectEqual(@as(usize, 2), cfg.upstream_circuit_half_open_max);
    try std.testing.expectEqual(@as(u32, 6000), cfg.upstream_slow_start_ms);
    try std.testing.expectEqual(@as(usize, 1), cfg.response_headers.items.len);
    try std.testing.expectEqual(@as(usize, 1), findNamedRoute(&cfg, "/assets/hello.txt").?.response_headers.items.len);
    try std.testing.expectEqual(UpstreamPoolPolicy.round_robin, routeUpstreamPolicy(&cfg, null, findNamedRoute(&cfg, "/health").?));
    try std.testing.expectEqual(@as(u32, 1250), routeUpstreamTimeoutMs(&cfg, null, findNamedRoute(&cfg, "/health").?));

    cfg.upstream = try parseUpstreamPool(allocator, "http://127.0.0.1:9100");
    const fallback_pool = domainUpstreamMutable(&cfg, null).?;
    try std.testing.expect(!upstreamRecordFailure(&fallback_pool.targets.items[0], 1_000, 2, 500));
    try std.testing.expectEqual(@as(usize, 1), domainUpstreamMutable(&cfg, null).?.targets.items[0].passive_failures.load(.monotonic));

    var breaker_target = try parseUpstream(allocator, "http://127.0.0.1:9200");
    breaker_target.weight = 5;
    try std.testing.expect(upstreamRecordFailure(&breaker_target, 10_000, 1, 500));
    try std.testing.expect(upstreamIsEjected(&breaker_target, 10_250));
    try std.testing.expect(upstreamBeginAttempt(&breaker_target, 10_250, &cfg) == null);
    const half_open_1 = upstreamBeginAttempt(&breaker_target, 10_500, &cfg) orelse return error.TestUnexpectedResult;
    const half_open_2 = upstreamBeginAttempt(&breaker_target, 10_500, &cfg) orelse return error.TestUnexpectedResult;
    try std.testing.expect(half_open_1.half_open);
    try std.testing.expect(half_open_2.half_open);
    try std.testing.expect(upstreamBeginAttempt(&breaker_target, 10_500, &cfg) == null);
    upstreamEndAttempt(&breaker_target, half_open_2);
    upstreamEndAttempt(&breaker_target, half_open_1);
    upstreamRecordSuccess(&breaker_target, 10_550, cfg.upstream_slow_start_ms);
    try std.testing.expect(!upstreamIsEjected(&breaker_target, 10_551));
    try std.testing.expect(upstreamInSlowStart(&breaker_target, 10_551, &cfg));
    try std.testing.expectEqual(@as(usize, 1), upstreamEffectiveWeight(&breaker_target, 10_551, &cfg));
    try std.testing.expectEqual(@as(usize, 5), upstreamEffectiveWeight(&breaker_target, 16_550, &cfg));

    try applyConfigLine(&cfg, allocator, "route_proxy.health", "http://127.0.0.1:9101");
    const health_route = findNamedRouteMutable(&cfg, "/health").?;
    if (health_route.upstream) |*route_pool| {
        try std.testing.expect(!upstreamRecordFailure(&route_pool.targets.items[0], 1_000, 2, 500));
    } else {
        return error.TestUnexpectedResult;
    }
    if (findNamedRouteMutable(&cfg, "/health").?.upstream) |*route_pool| {
        try std.testing.expectEqual(@as(usize, 1), route_pool.targets.items[0].passive_failures.load(.monotonic));
    } else {
        return error.TestUnexpectedResult;
    }

    const rel = try routeFileRelativePath(allocator, findNamedRoute(&cfg, "/assets/hello.txt").?, "/assets/hello.txt", "index.html");
    try std.testing.expectEqualStrings("hello.txt", rel);

    try setDomainLine(&cfg, allocator, "site");
    try appendServerNames(allocator, findDomainConfigMutable(&cfg, "site").?, "example.test *.example.test");
    try applyConfigLine(&cfg, allocator, "server_tls_cert.site", "/certs/site/fullchain.pem");
    try applyConfigLine(&cfg, allocator, "server_tls_key.site", "/certs/site/privkey.pem");
    try applyConfigLine(&cfg, allocator, "server_header.site", "X-Site-Policy: site");
    try setDomainRouteLine(&cfg, allocator, "site", "site-assets /assets/* static");
    try setDomainRouteLine(&cfg, allocator, "site", "site-api /api/* proxy");
    try applyConfigLine(&cfg, allocator, "server_route_header.site.site-api", "X-Api-Policy: route");
    try applyConfigLine(&cfg, allocator, "server_proxy_policy.site", "random");
    try applyConfigLine(&cfg, allocator, "server_proxy_timeout_ms.site", "4200");
    try applyConfigLine(&cfg, allocator, "server_route_proxy_policy.site.site-api", "inherit");
    try applyConfigLine(&cfg, allocator, "server_route_proxy_timeout_ms.site.site-api", "900");

    try setDomainLine(&cfg, allocator, "fallback");
    try appendServerNames(allocator, findDomainConfigMutable(&cfg, "fallback").?, "_");

    try std.testing.expectEqualStrings("site", findDomainForHost(&cfg, "example.test:8080").?.name);
    try std.testing.expectEqualStrings("site", findDomainForHost(&cfg, "www.example.test").?.name);
    try std.testing.expectEqualStrings("fallback", findDomainForHost(&cfg, "other.test").?.name);
    try std.testing.expectEqualStrings("/certs/site/fullchain.pem", findDomainForHost(&cfg, "example.test").?.tls_cert.?);
    try std.testing.expectEqualStrings("/certs/site/privkey.pem", findDomainForHost(&cfg, "example.test").?.tls_key.?);
    try std.testing.expectEqualStrings("site-assets", findDomainRoute(findDomainForHost(&cfg, "example.test"), "/assets/domain.txt").?.name);
    try std.testing.expectEqualStrings("assets", findNamedRoute(&cfg, "/assets/global.txt").?.name);
    try std.testing.expectEqual(UpstreamPoolPolicy.random, routeUpstreamPolicy(&cfg, findDomainForHost(&cfg, "example.test"), findDomainRoute(findDomainForHost(&cfg, "example.test"), "/api/status").?));
    try std.testing.expectEqual(@as(u32, 900), routeUpstreamTimeoutMs(&cfg, findDomainForHost(&cfg, "example.test"), findDomainRoute(findDomainForHost(&cfg, "example.test"), "/api/status").?));
    try std.testing.expectEqual(@as(u32, 4200), domainUpstreamTimeoutMs(&cfg, findDomainForHost(&cfg, "example.test")));
    const site_domain = findDomainForHost(&cfg, "example.test").?;
    const site_api_route = findDomainRoute(site_domain, "/api/status").?;
    const response_header_context = try buildResponseHeaderContext(allocator, &cfg, site_domain, site_api_route);
    defer response_header_context.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), response_header_context.items.len);
    try std.testing.expectEqualStrings("X-Global-Policy", response_header_context.items[0].name);
    try std.testing.expectEqualStrings("X-Site-Policy", response_header_context.items[1].name);
    try std.testing.expectEqualStrings("X-Api-Policy", response_header_context.items[2].name);

    var file_domain = try initDomainConfig(allocator, "file-site");
    try applyDomainConfigLine(&file_domain, allocator, "add_header", "X-File-Policy: file");
    try applyDomainConfigLine(&file_domain, allocator, "ssl_certificate", "/certs/file/fullchain.pem");
    try applyDomainConfigLine(&file_domain, allocator, "ssl_certificate_key", "/certs/file/privkey.pem");
    try std.testing.expectEqual(@as(usize, 1), file_domain.response_headers.items.len);
    try std.testing.expectEqualStrings("/certs/file/fullchain.pem", file_domain.tls_cert.?);
    try std.testing.expectEqualStrings("/certs/file/privkey.pem", file_domain.tls_key.?);
}

test "php front controller target keeps script and path info separate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var global_target = try makePhpFrontControllerTarget(allocator, null, "/orders/42", DEFAULT_PHP_INDEX);
    defer global_target.deinit(allocator);
    try std.testing.expectEqualStrings("index.php", global_target.script_rel_path);
    try std.testing.expectEqualStrings("/index.php", global_target.script_name);
    try std.testing.expectEqualStrings("/orders/42", global_target.path_info);

    var routes = std.ArrayList(RouteConfig).empty;
    try setRouteLineFor(&routes, allocator, "app /app/* php");
    const route = &routes.items[0];
    var route_target = try makePhpFrontControllerTarget(allocator, route, "/app/users/7", DEFAULT_PHP_INDEX);
    defer route_target.deinit(allocator);
    try std.testing.expectEqualStrings("index.php", route_target.script_rel_path);
    try std.testing.expectEqualStrings("/app/index.php", route_target.script_name);
    try std.testing.expectEqualStrings("/users/7", route_target.path_info);
}

test "upstream pools parse multiple targets and rotate selection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000/api, http://127.0.0.1:9001");

    try std.testing.expectEqual(@as(usize, 2), pool.targets.items.len);
    try std.testing.expectEqualStrings("127.0.0.1", pool.targets.items[0].host);
    try std.testing.expectEqual(@as(u16, 9000), pool.targets.items[0].port);
    try std.testing.expectEqualStrings("/api", pool.targets.items[0].base_path);
    try std.testing.expectEqual(@as(u16, 9001), pool.targets.items[1].port);

    const first = selectUpstream(&pool).?;
    const second = selectUpstream(&pool).?;
    try std.testing.expect(first.port != second.port);
}

test "upstream retry budget is capped to configured targets" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000, http://127.0.0.1:9001, http://127.0.0.1:9002");

    try std.testing.expectEqual(@as(usize, 1), upstreamAttemptLimit(&pool, 0));
    try std.testing.expectEqual(@as(usize, 2), upstreamAttemptLimit(&pool, 1));
    try std.testing.expectEqual(@as(usize, 3), upstreamAttemptLimit(&pool, 99));
    try std.testing.expectEqual(@as(u16, 9001), upstreamAtAttempt(&pool, 4, 0).port);
    try std.testing.expectEqual(@as(u16, 9002), upstreamAtAttempt(&pool, 4, 1).port);
    try std.testing.expectEqual(@as(u16, 9000), upstreamAtAttempt(&pool, 4, 2).port);
}

test "upstream policy parser accepts configured policy names" {
    try std.testing.expectEqual(UpstreamPoolPolicy.round_robin, try parseUpstreamPoolPolicy("round_robin"));
    try std.testing.expectEqual(UpstreamPoolPolicy.round_robin, try parseUpstreamPoolPolicy("round-robin"));
    try std.testing.expectEqual(UpstreamPoolPolicy.random, try parseUpstreamPoolPolicy("random"));
    try std.testing.expectEqual(UpstreamPoolPolicy.least_connections, try parseUpstreamPoolPolicy("least_connections"));
    try std.testing.expectEqual(UpstreamPoolPolicy.least_connections, try parseUpstreamPoolPolicy("least-connections"));
    try std.testing.expectEqual(UpstreamPoolPolicy.least_connections, try parseUpstreamPoolPolicy("leastconn"));
    try std.testing.expectEqual(UpstreamPoolPolicy.weighted, try parseUpstreamPoolPolicy("weighted"));
    try std.testing.expectEqual(UpstreamPoolPolicy.weighted, try parseUpstreamPoolPolicy("weighted-round-robin"));
    try std.testing.expectEqual(UpstreamPoolPolicy.weighted, try parseUpstreamPoolPolicy("wrr"));
    try std.testing.expectEqual(UpstreamPoolPolicy.consistent_hash, try parseUpstreamPoolPolicy("consistent_hash"));
    try std.testing.expectEqual(UpstreamPoolPolicy.consistent_hash, try parseUpstreamPoolPolicy("consistent-hash"));
    try std.testing.expectEqual(UpstreamPoolPolicy.consistent_hash, try parseUpstreamPoolPolicy("uri_hash"));
    try std.testing.expectEqual(@as(?UpstreamPoolPolicy, null), try parseOptionalUpstreamPoolPolicy("inherit"));
}

test "upstream pools parse target weights" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000 weight=3, http://127.0.0.1:9001 w=1");

    try std.testing.expectEqual(@as(usize, 2), pool.targets.items.len);
    try std.testing.expectEqual(@as(usize, 3), pool.targets.items[0].weight);
    try std.testing.expectEqual(@as(usize, 1), pool.targets.items[1].weight);
    try std.testing.expectError(error.InvalidUpstream, parseUpstreamPool(allocator, "weight=3 http://127.0.0.1:9000"));
    try std.testing.expectError(error.InvalidUpstream, parseUpstreamPool(allocator, "http://127.0.0.1:9000 weight=0"));
}

test "least-connections policy chooses the quietest healthy upstream" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000, http://127.0.0.1:9001, http://127.0.0.1:9002");

    pool.targets.items[0].active_requests.store(5, .monotonic);
    pool.targets.items[1].active_requests.store(1, .monotonic);
    pool.targets.items[2].active_requests.store(3, .monotonic);
    try std.testing.expectEqual(@as(usize, 1), upstreamStartTicket(&pool, .least_connections, 1_000, null, null));

    pool.targets.items[1].ejected_until_ms.store(2_000, .monotonic);
    try std.testing.expectEqual(@as(usize, 2), upstreamStartTicket(&pool, .least_connections, 1_000, null, null));
}

test "weighted policy honors target weights and passive ejection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000 weight=3, http://127.0.0.1:9001 weight=1");

    upstream_round_robin_cursor.store(0, .monotonic);
    try std.testing.expectEqual(@as(usize, 0), upstreamStartTicket(&pool, .weighted, 1_000, null, null));
    try std.testing.expectEqual(@as(usize, 0), upstreamStartTicket(&pool, .weighted, 1_000, null, null));
    try std.testing.expectEqual(@as(usize, 0), upstreamStartTicket(&pool, .weighted, 1_000, null, null));
    try std.testing.expectEqual(@as(usize, 1), upstreamStartTicket(&pool, .weighted, 1_000, null, null));

    upstream_round_robin_cursor.store(0, .monotonic);
    pool.targets.items[0].ejected_until_ms.store(2_000, .monotonic);
    try std.testing.expectEqual(@as(usize, 1), upstreamStartTicket(&pool, .weighted, 1_000, null, null));
}

test "consistent hash policy keeps a stable healthy target" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000, http://127.0.0.1:9001, http://127.0.0.1:9002");
    const req = HttpRequest{
        .method = "GET",
        .path = "/api/users",
        .query = "page=1",
        .headers = "Host: example.test\r\nX-Forwarded-For: 203.0.113.10, 10.0.0.1\r\n",
        .version = "HTTP/1.1",
        .body = "",
        .close_connection = false,
    };

    const first = upstreamStartTicket(&pool, .consistent_hash, 1_000, req, null);
    try std.testing.expectEqual(first, upstreamStartTicket(&pool, .consistent_hash, 1_000, req, null));

    pool.targets.items[first].ejected_until_ms.store(2_000, .monotonic);
    const replacement = upstreamStartTicket(&pool, .consistent_hash, 1_000, req, null);
    try std.testing.expect(replacement != first);
    try std.testing.expect(replacement < pool.targets.items.len);
}

test "active health result transitions update upstream availability" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var upstream = try parseUpstream(allocator, "http://127.0.0.1:9000");

    try std.testing.expectEqual(UpstreamHealthTransition.ejected, upstreamRecordActiveHealthResult(&upstream, false, 1_000, 500, 0));
    try std.testing.expect(upstreamIsEjected(&upstream, 1_250));
    try std.testing.expectEqual(@as(i64, 1_500), upstream.ejected_until_ms.load(.monotonic));
    try std.testing.expectEqual(UpstreamHealthTransition.unchanged, upstreamRecordActiveHealthResult(&upstream, false, 1_300, 500, 0));
    try std.testing.expectEqual(UpstreamHealthTransition.recovered, upstreamRecordActiveHealthResult(&upstream, true, 1_350, 500, 0));
    try std.testing.expect(!upstreamIsEjected(&upstream, 1_351));
}

test "health check status parser accepts normal HTTP status lines" {
    try std.testing.expectEqual(@as(?u16, 200), parseHttpStatusCode("HTTP/1.1 200 OK\r\nServer: test\r\n\r\n"));
    try std.testing.expectEqual(@as(?u16, 503), parseHttpStatusCode("HTTP/1.0 503 Service Unavailable\r\n\r\n"));
    try std.testing.expectEqual(@as(?u16, null), parseHttpStatusCode("not-http\r\n\r\n"));
}

test "chunked upstream body scanner detects trailers and terminator" {
    var scanner = ChunkedBodyScanner{};
    var completed = false;
    for ("4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Upstream: yes\r\n\r\n") |byte| {
        completed = try scanner.consume(byte);
    }
    try std.testing.expect(completed);
}

test "upstream response framing parser keeps keep-alive candidates explicit" {
    const head =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 12\r\n" ++
        "Connection: keep-alive\r\n" ++
        "\r\n";
    const headers = head["HTTP/1.1 200 OK\r\n".len .. head.len - 4];
    const framing = try parseUpstreamResponseFraming(head, headers);
    try std.testing.expectEqual(@as(?u16, 200), framing.status_code);
    try std.testing.expectEqual(@as(?usize, 12), framing.content_length);
    try std.testing.expect(!framing.connection_close);
    try std.testing.expect(!framing.transfer_chunked);
}

test "passive upstream health ejects and recovers targets" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var upstream = try parseUpstream(allocator, "http://127.0.0.1:9000");
    try std.testing.expect(!upstreamIsEjected(&upstream, 1_000));
    try std.testing.expect(!upstreamRecordFailure(&upstream, 1_000, 2, 250));
    try std.testing.expect(upstreamRecordFailure(&upstream, 1_010, 2, 250));
    try std.testing.expect(upstreamIsEjected(&upstream, 1_100));
    try std.testing.expect(!upstreamIsEjected(&upstream, 1_300));
    try std.testing.expectEqual(@as(usize, 2), upstream.passive_failures.load(.monotonic));
    upstreamRecordSuccess(&upstream, 1_301, 0);
    try std.testing.expectEqual(@as(usize, 0), upstream.passive_failures.load(.monotonic));

    try std.testing.expect(!upstreamRecordFailure(&upstream, 1_400, 0, 250));
    try std.testing.expect(!upstreamIsEjected(&upstream, 1_401));
}

fn routeRequest(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    req: HttpRequest,
    process_env: *const std.process.Environ.Map,
) !void {
    // Route locally first, then fall back to proxying so known endpoints stay predictable.
    const should_close = req.close_connection;
    const method = req.method;
    const is_head = std.mem.eql(u8, method, "HEAD");
    const domain = findDomainForRequestMutable(cfg, req.headers);

    const base_header_context = try buildResponseHeaderContext(allocator, cfg, domain, null);
    defer base_header_context.deinit(allocator);
    current_response_headers = base_header_context.items;
    defer current_response_headers = &.{};

    if (findDomainRedirectRule(domain, req.path)) |redirect| {
        try sendConfiguredRedirect(stream, allocator, redirect, req, should_close, is_head);
        return;
    }

    if (findRedirectRule(cfg, req.path)) |redirect| {
        try sendConfiguredRedirect(stream, allocator, redirect, req, should_close, is_head);
        return;
    }

    if (findDomainRouteMutable(domain, req.path)) |route| {
        const route_header_context = try buildResponseHeaderContext(allocator, cfg, domain, route);
        defer route_header_context.deinit(allocator);
        current_response_headers = route_header_context.items;
        try handleNamedRoute(io, stream, allocator, cfg, domain, route, req, should_close, is_head, process_env);
        return;
    }

    if (findNamedRouteMutable(cfg, req.path)) |route| {
        const route_header_context = try buildResponseHeaderContext(allocator, cfg, domain, route);
        defer route_header_context.deinit(allocator);
        current_response_headers = route_header_context.items;
        try handleNamedRoute(io, stream, allocator, cfg, domain, route, req, should_close, is_head, process_env);
        return;
    }

    if ((std.mem.eql(u8, method, "GET") or is_head) and std.mem.startsWith(u8, req.path, "/.well-known/acme-challenge/")) {
        const token = req.path["/.well-known/acme-challenge/".len..];
        try serveAcmeChallenge(io, stream, allocator, cfg.letsencrypt_webroot, token, should_close, is_head);
        return;
    }

    // A domain-level proxy is the virtual host's fallback owner. Keep the
    // built-in Layerline pages for direct/default hosts, not for proxied apps.
    if (domain != null) {
        if (domainUpstreamMutable(cfg, domain)) |pool| {
            try forwardToUpstreamPool(stream, allocator, pool, domainUpstreamPolicy(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), req, cfg);
            return;
        }
    }

    if (std.mem.eql(u8, method, "GET") or is_head) {
        if (std.mem.eql(u8, req.path, "/favicon.svg") or std.mem.eql(u8, req.path, "/icon.svg")) {
            try sendServerIcon(stream, should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/") and domainPhpFrontController(cfg, domain)) {
            try handlePhpFrontController(io, stream, allocator, cfg, req, null, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), domainPhpFastcgi(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), domainPhpIndex(cfg, domain), should_close, is_head, process_env);
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
                \\    max-width: 9ch;
                \\    font-size: clamp(68px, 9vw, 132px);
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
                \\    min-height: 560px;
                \\    border: 1px solid rgba(17,17,15,.16);
                \\    border-radius: 10px;
                \\    overflow: hidden;
                \\    background: rgba(251,250,246,.72);
                \\    box-shadow: 0 44px 110px rgba(38,34,24,.14);
                \\    backdrop-filter: blur(18px);
                \\  }
                \\  .surface::before {
                \\    content: "";
                \\    position: absolute;
                \\    inset: 0;
                \\    z-index: 0;
                \\    pointer-events: none;
                \\    background:
                \\      linear-gradient(rgba(17,17,15,.08) 1px, transparent 1px),
                \\      linear-gradient(90deg, rgba(17,17,15,.08) 1px, transparent 1px);
                \\    background-size: 44px 44px;
                \\  }
                \\  .mascot-wrap {
                \\    position: absolute;
                \\    left: 90px;
                \\    right: 30px;
                \\    top: 70px;
                \\    bottom: 74px;
                \\    z-index: 2;
                \\    display: flex;
                \\    align-items: flex-end;
                \\    justify-content: center;
                \\    pointer-events: auto;
                \\  }
                \\  .mascot-wrap::after {
                \\    content: "";
                \\    position: absolute;
                \\    left: 50%;
                \\    bottom: 0;
                \\    width: min(58%, 280px);
                \\    height: 26px;
                \\    border-radius: 999px;
                \\    background: rgba(17,17,15,.13);
                \\    filter: blur(14px);
                \\    transform: translateX(-50%);
                \\    animation: mascot-shadow 5.4s ease-in-out infinite;
                \\  }
                \\  .mascot {
                \\    position: relative;
                \\    z-index: 2;
                \\    display: block;
                \\    width: auto;
                \\    height: min(100%, 500px);
                \\    max-width: 100%;
                \\    border-radius: 8px;
                \\    object-fit: contain;
                \\    filter: drop-shadow(0 30px 42px rgba(17,17,15,.18));
                \\    animation: mascot-float 5.4s ease-in-out infinite;
                \\  }
                \\  .mascot-wrap:focus-visible {
                \\    outline: 2px solid #1c8c74;
                \\    outline-offset: -8px;
                \\  }
                \\  .mascot-wrap:hover .mascot,
                \\  .mascot-wrap:focus-within .mascot {
                \\    animation-duration: 3.8s;
                \\  }
                \\  .mascot-name {
                \\    position: absolute;
                \\    z-index: 5;
                \\    left: 28px;
                \\    bottom: 106px;
                \\    color: #11110f;
                \\    font: 700 13px/1.1 ui-monospace, SFMono-Regular, Menlo, monospace;
                \\    text-transform: uppercase;
                \\  }
                \\  .mascot-name span {
                \\    display: block;
                \\    margin-top: 4px;
                \\    color: #5f6f68;
                \\    font-weight: 500;
                \\    text-transform: none;
                \\  }
                \\  .rail {
                \\    position: absolute;
                \\    z-index: 5;
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
                \\    letter-spacing: 0;
                \\    text-transform: uppercase;
                \\  }
                \\  .route {
                \\    position: absolute;
                \\    z-index: 1;
                \\    left: 18%;
                \\    right: 18%;
                \\    top: 51%;
                \\    height: 2px;
                \\    background: repeating-linear-gradient(90deg, rgba(17,17,15,.5) 0 12px, transparent 12px 22px);
                \\    transform: rotate(-9deg);
                \\  }
                \\  .packet {
                \\    position: absolute;
                \\    z-index: 3;
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
                \\    z-index: 1;
                \\    left: 34px;
                \\    bottom: 128px;
                \\    font-size: clamp(62px, 10vw, 116px);
                \\    line-height: .82;
                \\    letter-spacing: 0;
                \\    color: rgba(17,17,15,.11);
                \\  }
                \\  .caps {
                \\    position: absolute;
                \\    left: 28px;
                \\    right: 28px;
                \\    top: 88px;
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
                \\    z-index: 4;
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
                \\    z-index: 5;
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
                \\  @keyframes mascot-float {
                \\    0%, 100% { transform: translateY(0) rotate(-.8deg); }
                \\    50% { transform: translateY(-12px) rotate(.8deg); }
                \\  }
                \\  @keyframes mascot-shadow {
                \\    0%, 100% { transform: translateX(-50%) scaleX(.92); opacity: .72; }
                \\    50% { transform: translateX(-50%) scaleX(1.06); opacity: .46; }
                \\  }
                \\  @keyframes node-pulse {
                \\    0%, 100% { box-shadow: 0 0 0 8px rgba(17,17,15,.08); }
                \\    50% { box-shadow: 0 0 0 15px rgba(17,17,15,.04); }
                \\  }
                \\  @media (max-width: 820px) {
                \\    main { grid-template-columns: 1fr; padding: 24px; }
                \\    h1 { font-size: clamp(64px, 22vw, 104px); }
                \\    .surface { min-height: 560px; }
                \\    .mascot-wrap { left: 62px; right: 8px; top: 76px; bottom: 114px; }
                \\    .mascot { height: min(100%, 430px); }
                \\    .mascot-name { bottom: 104px; }
                \\    .route { top: 57%; }
                \\    .packet { top: 54%; animation: none; transform: rotate(-9deg); }
                \\    .h3mark { bottom: 148px; font-size: 70px; }
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
                \\  <aside class="surface" aria-labelledby="laina-heading laina-role">
                \\    <div class="rail"><span>Laina // route operator</span><span>HTTP/3</span></div>
                \\    <div class="h3mark">HTTP/3</div>
                \\    <div class="route"></div>
                \\    <div class="packet"></div>
                \\    <div class="mascot-wrap" tabindex="0">
                \\      <img class="mascot" src="/static/laina.png?v=hands" alt="Laina, Layerline's anime route operator mascot">
                \\    </div>
                \\    <div class="mascot-name" id="laina-heading">Laina<span id="laina-role">packet-route mascot</span></div>
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
            try handlePhpScript(io, stream, allocator, cfg, req, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), domainPhpFastcgi(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), rel_path, req.path, "", should_close, is_head, process_env);
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

        if (domainPhpFrontController(cfg, domain)) {
            try handlePhpFrontController(io, stream, allocator, cfg, req, null, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), domainPhpFastcgi(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), domainPhpIndex(cfg, domain), should_close, is_head, process_env);
            return;
        }

        if (domainUpstreamMutable(cfg, domain)) |pool| {
            try forwardToUpstreamPool(stream, allocator, pool, domainUpstreamPolicy(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), req, cfg);
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
            try handlePhpScript(io, stream, allocator, cfg, req, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), domainPhpFastcgi(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), rel_path, req.path, "", should_close, false, process_env);
            return;
        }

        if (std.mem.eql(u8, req.path, "/api/echo")) {
            try sendResponseWithConnection(stream, 200, "OK", "text/plain; charset=utf-8", req.body, should_close);
            return;
        }

        if (domainPhpFrontController(cfg, domain)) {
            try handlePhpFrontController(io, stream, allocator, cfg, req, null, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), domainPhpFastcgi(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), domainPhpIndex(cfg, domain), should_close, false, process_env);
            return;
        }

        if (domainUpstreamMutable(cfg, domain)) |pool| {
            try forwardToUpstreamPool(stream, allocator, pool, domainUpstreamPolicy(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), req, cfg);
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
        if (domainPhpFrontController(cfg, domain)) {
            try handlePhpFrontController(io, stream, allocator, cfg, req, null, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), domainPhpFastcgi(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), domainPhpIndex(cfg, domain), should_close, false, process_env);
            return;
        }

        if (domainUpstreamMutable(cfg, domain)) |pool| {
            try forwardToUpstreamPool(stream, allocator, pool, domainUpstreamPolicy(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), req, cfg);
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
    cfg: *ServerConfig,
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
            try handleHttp2Preface(io, stream, req_alloc, cfg, prefill, process_env);
            return;
        }

        if (tls_client_hello.looksLikeTlsClientHello(prefill)) {
            try handleTlsClientHelloProbe(io, stream, allocator, cfg, prefill, process_env);
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

        if (req.h2c_upgrade_tail.len > 0 or isH2cUpgradeHeaders(req.headers)) {
            try handleHttp2Upgrade(io, stream, req_alloc, cfg, req, process_env);
            return;
        }

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
    cfg: *ServerConfig,
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
                std.debug.print(" php_root={s} php_bin={s} php_index={s}", .{ route.php_root orelse cfg.php_root, route.php_binary orelse cfg.php_binary, route.php_index orelse cfg.php_index });
                if (routePhpFastcgi(cfg, null, &route)) |endpoint| std.debug.print(" fastcgi={s}", .{endpoint});
                if (route.upstream_timeout_ms) |timeout_ms| std.debug.print(" timeout_ms={d}", .{timeout_ms});
                if (route.php_front_controller orelse cfg.php_front_controller) std.debug.print(" front_controller=true", .{});
            },
            .proxy => {
                const maybe_upstream = if (route.upstream) |pool| pool else cfg.upstream;
                if (maybe_upstream) |pool| {
                    printUpstreamPool(route.upstream_policy orelse cfg.upstream_policy, pool);
                } else {
                    std.debug.print(" upstream=<unset>", .{});
                }
                if (route.upstream_timeout_ms) |timeout_ms| std.debug.print(" timeout_ms={d}", .{timeout_ms});
            },
        }
        if (!route.strip_prefix) std.debug.print(" strip_prefix=false", .{});
        if (route.response_headers.items.len > 0) std.debug.print(" response_headers={d}", .{route.response_headers.items.len});
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
        if (domain.upstream) |pool| printUpstreamPool(domainUpstreamPolicy(cfg, domain), pool);
        if (domain.upstream_timeout_ms) |timeout_ms| std.debug.print(" timeout_ms={d}", .{timeout_ms});
        if (domain.response_headers.items.len > 0) std.debug.print(" response_headers={d}", .{domain.response_headers.items.len});
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
                    std.debug.print(" php_root={s} php_bin={s} php_index={s}", .{ route.php_root orelse domainPhpRoot(cfg, domain), route.php_binary orelse domainPhpBinary(cfg, domain), routePhpIndex(cfg, domain, &route) });
                    if (routePhpFastcgi(cfg, domain, &route)) |endpoint| std.debug.print(" fastcgi={s}", .{endpoint});
                    if (route.upstream_timeout_ms) |timeout_ms| std.debug.print(" timeout_ms={d}", .{timeout_ms});
                    if (routePhpFrontController(cfg, domain, &route)) std.debug.print(" front_controller=true", .{});
                },
                .proxy => {
                    const maybe_upstream = if (route.upstream) |pool| pool else domainUpstream(cfg, domain);
                    if (maybe_upstream) |pool| {
                        printUpstreamPool(routeUpstreamPolicy(cfg, domain, &route), pool);
                    } else {
                        std.debug.print(" upstream=<unset>", .{});
                    }
                    if (route.upstream_timeout_ms) |timeout_ms| std.debug.print(" timeout_ms={d}", .{timeout_ms});
                },
            }
            if (!route.strip_prefix) std.debug.print(" strip_prefix=false", .{});
            if (route.response_headers.items.len > 0) std.debug.print(" response_headers={d}", .{route.response_headers.items.len});
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
            "[--index INDEX.html] [--serve-static true|false] [--php-root PHP_ROOT] [--php-bin /usr/bin/php-cgi] [--php-fastcgi 127.0.0.1:9000|unix:/run/php.sock] [--php-index index.php] [--php-front-controller true|false] [--php-info-page true|false] " ++
            "[--domain-config-dir domains-enabled] " ++
            "[--proxy http://HOST:PORT[/path][,http://HOST:PORT[/path]]] [--upstream-policy round_robin|random|least_connections|weighted|consistent_hash] [--h2-upstream http://HOST:PORT[/path]] " ++
            "[--http3 true|false] [--http3-port PORT] [--tls true|false] [--tls-cert path] [--tls-key path] " ++
            "[--tls-auto true|false] [--letsencrypt-email EMAIL] [--letsencrypt-domains example.com,www.example.com] " ++
            "[--letsencrypt-webroot /var/www/html] [--letsencrypt-certbot /usr/bin/certbot] [--letsencrypt-staging true|false] " ++
            "[--cf-auto-deploy true|false] [--cf-zone-name example.com] [--cf-zone-id ZONE_ID] [--cf-record-name www.example.com] " ++
            "[--cf-record-type A|AAAA|CNAME|TXT] [--cf-record-content 203.0.113.10] [--cf-record-ttl 300] [--cf-record-proxied true|false] " ++
            "[--max-request-bytes N] [--max-body-bytes N] [--max-static-bytes N] [--max-concurrent-connections N] " ++
            "[--max-requests-per-connection N] [--max-php-output-bytes N] [--worker-stack-size N] [--read-header-timeout-ms N] " ++
            "[--read-body-timeout-ms N] [--idle-timeout-ms N] [--write-timeout-ms N] [--upstream-timeout-ms N] [--upstream-retries N] [--upstream-max-failures N] [--upstream-fail-timeout-ms N] " ++
            "[--upstream-keepalive true|false] [--upstream-keepalive-max-idle N] [--upstream-keepalive-idle-timeout-ms N] [--upstream-keepalive-max-requests N] " ++
            "[--fastcgi-keepalive true|false] [--fastcgi-keepalive-max-idle N] [--fastcgi-keepalive-idle-timeout-ms N] [--fastcgi-keepalive-max-requests N] " ++
            "[--upstream-health-check true|false] [--upstream-health-path /health] [--upstream-health-interval-ms N] [--upstream-health-timeout-ms N] " ++
            "[--upstream-circuit-breaker true|false] [--upstream-circuit-half-open-max N] [--upstream-slow-start-ms N] " ++
            "[--graceful-shutdown-timeout-ms N]\n" ++
            "  Supported config keys: host, port, static_dir/dir, index_file/index, serve_static_root, " ++
            "php_root, php_binary/php_bin, php_fastcgi/php_fpm/fastcgi, php_index/php_index_file, php_front_controller, php_info_page/phpinfo_page, proxy, upstream_policy/proxy_policy, h2_upstream, http3, http3_port, domain_config_dir/domains_dir/sites_enabled, header/response_header/add_header, redirect/redir, tls, tls_cert, tls_key, max_request_bytes, " ++
            "tls_auto, letsencrypt_email, letsencrypt_domains, letsencrypt_webroot, letsencrypt_certbot, letsencrypt_staging, " ++
            "max_body_bytes, max_static_file_bytes, max_requests_per_connection, max_php_output_bytes, max_concurrent_connections, worker_stack_size, " ++
            "read_header_timeout_ms, read_body_timeout_ms, idle_timeout_ms, write_timeout_ms, upstream_timeout_ms, upstream_retries, upstream_max_failures, upstream_fail_timeout_ms, upstream_keepalive, upstream_keepalive_max_idle, upstream_keepalive_idle_timeout_ms, upstream_keepalive_max_requests, fastcgi_keepalive, fastcgi_keepalive_max_idle, fastcgi_keepalive_idle_timeout_ms, fastcgi_keepalive_max_requests, upstream_health_check, upstream_health_check_path, upstream_health_check_interval_ms, upstream_health_check_timeout_ms, upstream_circuit_breaker, upstream_circuit_half_open_max, upstream_slow_start_ms, graceful_shutdown_timeout_ms, " ++
            "cf_auto_deploy, cf_api_base, cf_token, cf_zone_id, cf_zone_name, cf_record_name, cf_record_type, cf_record_content, " ++
            "cf_record_ttl, cf_record_proxied, cf_record_comment, route, route_dir.NAME, route_index.NAME, route_php_root.NAME, " ++
            "route_php_bin.NAME, route_php_fastcgi.NAME, route_php_index.NAME, route_php_front_controller.NAME, route_php_info_page.NAME, route_proxy.NAME, route_upstream_policy.NAME, route_upstream_timeout_ms.NAME, route_strip_prefix.NAME, route_header.NAME, server/domain/vhost, " ++
            "server_name.NAME, server_root.NAME, server_index.NAME, server_serve_static_root.NAME, server_header.NAME, server_proxy.NAME, " ++
            "server_upstream_policy.NAME, server_upstream_timeout_ms.NAME, server_php_fastcgi.NAME, server_php_index.NAME, server_php_front_controller.NAME, server_tls_cert.NAME, server_tls_key.NAME, server_redirect.NAME, server_route.NAME, server_route_dir.DOMAIN.ROUTE, server_route_header.DOMAIN.ROUTE, server_route_php_fastcgi.DOMAIN.ROUTE, server_route_php_index.DOMAIN.ROUTE, server_route_php_front_controller.DOMAIN.ROUTE, server_route_proxy.DOMAIN.ROUTE, server_route_upstream_policy.DOMAIN.ROUTE, server_route_upstream_timeout_ms.DOMAIN.ROUTE\n" ++
            "  HTTP/1 is served directly. HTTP/2 cleartext can be passed through with --h2-upstream. " ++
            "Native HTTP/3 serves the built-in default page over QUIC on --http3-port.\n\n" ++
            "Examples:\n" ++
            "  zig build run\n" ++
            "  zig build run -- --validate-config\n" ++
            "  zig build run -- --dump-routes\n" ++
            "  zig build run -- --port 4000\n" ++
            "  zig build run -- --index index.php --serve-static true\n" ++
            "  zig build run -- --php-root public --php-bin php-cgi\n" ++
            "  zig build run -- --php-root public --php-fastcgi 127.0.0.1:9000\n" ++
            "  zig build run -- --php-front-controller true --php-index index.php\n" ++
            "  zig build run -- --config server.conf\n" ++
            "  zig build run -- --domain-config-dir domains-enabled --dump-routes\n" ++
            "  zig build run -- --proxy http://127.0.0.1:9000,http://127.0.0.1:9001\n" ++
            "  zig build run -- --proxy http://127.0.0.1:9000,http://127.0.0.1:9001 --upstream-policy random\n" ++
            "  zig build run -- --proxy http://127.0.0.1:9000 --upstream-keepalive true --upstream-keepalive-max-idle 32\n" ++
            "  zig build run -- --proxy http://127.0.0.1:9000,http://127.0.0.1:9001 --upstream-health-check true\n" ++
            "  zig build run -- --proxy http://127.0.0.1:9000,http://127.0.0.1:9001 --upstream-circuit-breaker true --upstream-slow-start-ms 10000\n" ++
            "  zig build run -- --proxy off\n" ++
            "  zig build run -- --tls-auto true --letsencrypt-email admin@example.com --letsencrypt-domains example.com\n" ++
            "  zig build run -- --cf-auto-deploy true --cf-token xxxxx --cf-zone-name example.com --cf-record-name www.example.com\n" ++
            "  zig build run -- --h2-upstream http://127.0.0.1:9001\n\n" ++
            "Notes:\n" ++
            "  HTTP/1 client handling is still thread-per-connection. Upstream keep-alive pooling\n" ++
            "  removes backend reconnect churn, but very high fan-in still needs strict timeout\n" ++
            "  and connection management policies.\n" ++
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
        .php_index = DEFAULT_PHP_INDEX,
        .php_fastcgi = null,
        .php_info_page = false,
        .php_front_controller = false,
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
        .upstream_policy = .round_robin,
        .tls_cert = null,
        .tls_key = null,
        .tls_material = null,
        .h2_upstream = null,
        .http3_enabled = false,
        .http3_port = 8443,
        .response_headers = .empty,
        .redirects = .empty,
        .routes = .empty,
        .domains = .empty,
        .domain_config_dir = null,
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
        .upstream_retries = DEFAULT_UPSTREAM_RETRIES,
        .upstream_max_failures = DEFAULT_UPSTREAM_MAX_FAILURES,
        .upstream_fail_timeout_ms = DEFAULT_UPSTREAM_FAIL_TIMEOUT_MS,
        .upstream_keepalive_enabled = true,
        .upstream_keepalive_max_idle = DEFAULT_UPSTREAM_KEEPALIVE_MAX_IDLE,
        .upstream_keepalive_idle_timeout_ms = DEFAULT_UPSTREAM_KEEPALIVE_IDLE_TIMEOUT_MS,
        .upstream_keepalive_max_requests = DEFAULT_UPSTREAM_KEEPALIVE_MAX_REQUESTS,
        .fastcgi_keepalive_enabled = true,
        .fastcgi_keepalive_max_idle = DEFAULT_FASTCGI_KEEPALIVE_MAX_IDLE,
        .fastcgi_keepalive_idle_timeout_ms = DEFAULT_FASTCGI_KEEPALIVE_IDLE_TIMEOUT_MS,
        .fastcgi_keepalive_max_requests = DEFAULT_FASTCGI_KEEPALIVE_MAX_REQUESTS,
        .upstream_health_check_enabled = false,
        .upstream_health_check_path = DEFAULT_UPSTREAM_HEALTH_CHECK_PATH,
        .upstream_health_check_interval_ms = DEFAULT_UPSTREAM_HEALTH_CHECK_INTERVAL_MS,
        .upstream_health_check_timeout_ms = DEFAULT_UPSTREAM_HEALTH_CHECK_TIMEOUT_MS,
        .upstream_circuit_breaker_enabled = true,
        .upstream_circuit_half_open_max = DEFAULT_UPSTREAM_CIRCUIT_HALF_OPEN_MAX,
        .upstream_slow_start_ms = DEFAULT_UPSTREAM_SLOW_START_MS,
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
        } else if (std.mem.eql(u8, arg, "--domain-config-dir") or std.mem.eql(u8, arg, "--domains-dir") or std.mem.eql(u8, arg, "--sites-enabled")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.domain_config_dir = if (value.len == 0) null else value;
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
        } else if (std.mem.eql(u8, arg, "--php-fastcgi") or std.mem.eql(u8, arg, "--php-fpm") or std.mem.eql(u8, arg, "--fastcgi")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            if (disablesOptionalUrl(value)) {
                cfg.php_fastcgi = null;
            } else {
                validateFastcgiEndpoint(value) catch {
                    std.debug.print("Failed to parse php_fastcgi endpoint: {s}\n", .{value});
                    return;
                };
                cfg.php_fastcgi = value;
            }
        } else if (std.mem.eql(u8, arg, "--php-index") or std.mem.eql(u8, arg, "--php-index-file")) {
            cfg.php_index = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--php-info-page") or std.mem.eql(u8, arg, "--phpinfo-page")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.php_info_page = parseBool(value) orelse cfg.php_info_page;
        } else if (std.mem.eql(u8, arg, "--php-front-controller")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.php_front_controller = parseBool(value) orelse cfg.php_front_controller;
        } else if (std.mem.eql(u8, arg, "--proxy") or std.mem.eql(u8, arg, "-x")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream = if (disablesOptionalUrl(value)) null else parseUpstreamPool(std.heap.page_allocator, value) catch null;
        } else if (std.mem.eql(u8, arg, "--upstream-policy") or std.mem.eql(u8, arg, "--proxy-policy") or std.mem.eql(u8, arg, "--load-balance")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_policy = parseUpstreamPoolPolicy(value) catch {
                std.debug.print("Failed to parse upstream policy: {s}\n", .{value});
                return;
            };
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
        } else if (std.mem.eql(u8, arg, "--upstream-retries")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_retries = std.fmt.parseInt(usize, value, 10) catch cfg.upstream_retries;
        } else if (std.mem.eql(u8, arg, "--upstream-max-failures") or std.mem.eql(u8, arg, "--upstream-max-fails") or std.mem.eql(u8, arg, "--proxy-max-fails")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_max_failures = std.fmt.parseInt(usize, value, 10) catch cfg.upstream_max_failures;
        } else if (std.mem.eql(u8, arg, "--upstream-fail-timeout-ms") or std.mem.eql(u8, arg, "--proxy-fail-timeout-ms")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_fail_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.upstream_fail_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--upstream-keepalive") or std.mem.eql(u8, arg, "--proxy-keepalive")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_keepalive_enabled = parseBool(value) orelse cfg.upstream_keepalive_enabled;
        } else if (std.mem.eql(u8, arg, "--upstream-keepalive-max-idle") or std.mem.eql(u8, arg, "--proxy-keepalive-max-idle")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_keepalive_max_idle = std.fmt.parseInt(usize, value, 10) catch cfg.upstream_keepalive_max_idle;
        } else if (std.mem.eql(u8, arg, "--upstream-keepalive-idle-timeout-ms") or std.mem.eql(u8, arg, "--proxy-keepalive-idle-timeout-ms")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_keepalive_idle_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.upstream_keepalive_idle_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--upstream-keepalive-max-requests") or std.mem.eql(u8, arg, "--proxy-keepalive-max-requests")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_keepalive_max_requests = std.fmt.parseInt(usize, value, 10) catch cfg.upstream_keepalive_max_requests;
        } else if (std.mem.eql(u8, arg, "--fastcgi-keepalive") or std.mem.eql(u8, arg, "--php-fastcgi-keepalive") or std.mem.eql(u8, arg, "--fastcgi-keep-conn")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.fastcgi_keepalive_enabled = parseBool(value) orelse cfg.fastcgi_keepalive_enabled;
        } else if (std.mem.eql(u8, arg, "--fastcgi-keepalive-max-idle") or std.mem.eql(u8, arg, "--php-fastcgi-keepalive-max-idle")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.fastcgi_keepalive_max_idle = std.fmt.parseInt(usize, value, 10) catch cfg.fastcgi_keepalive_max_idle;
        } else if (std.mem.eql(u8, arg, "--fastcgi-keepalive-idle-timeout-ms") or std.mem.eql(u8, arg, "--php-fastcgi-keepalive-idle-timeout-ms")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.fastcgi_keepalive_idle_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.fastcgi_keepalive_idle_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--fastcgi-keepalive-max-requests") or std.mem.eql(u8, arg, "--php-fastcgi-keepalive-max-requests")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.fastcgi_keepalive_max_requests = std.fmt.parseInt(usize, value, 10) catch cfg.fastcgi_keepalive_max_requests;
        } else if (std.mem.eql(u8, arg, "--upstream-health-check") or std.mem.eql(u8, arg, "--proxy-health-check")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_health_check_enabled = parseBool(value) orelse cfg.upstream_health_check_enabled;
        } else if (std.mem.eql(u8, arg, "--upstream-health-path") or std.mem.eql(u8, arg, "--upstream-health-check-path") or std.mem.eql(u8, arg, "--proxy-health-path")) {
            cfg.upstream_health_check_path = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--upstream-health-interval-ms") or std.mem.eql(u8, arg, "--upstream-health-check-interval-ms") or std.mem.eql(u8, arg, "--proxy-health-interval-ms")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_health_check_interval_ms = std.fmt.parseInt(u32, value, 10) catch cfg.upstream_health_check_interval_ms;
        } else if (std.mem.eql(u8, arg, "--upstream-health-timeout-ms") or std.mem.eql(u8, arg, "--upstream-health-check-timeout-ms") or std.mem.eql(u8, arg, "--proxy-health-timeout-ms")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_health_check_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.upstream_health_check_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--upstream-circuit-breaker") or std.mem.eql(u8, arg, "--proxy-circuit-breaker")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_circuit_breaker_enabled = parseBool(value) orelse cfg.upstream_circuit_breaker_enabled;
        } else if (std.mem.eql(u8, arg, "--upstream-circuit-half-open-max") or std.mem.eql(u8, arg, "--proxy-circuit-half-open-max")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_circuit_half_open_max = std.fmt.parseInt(usize, value, 10) catch cfg.upstream_circuit_half_open_max;
        } else if (std.mem.eql(u8, arg, "--upstream-slow-start-ms") or std.mem.eql(u8, arg, "--proxy-slow-start-ms")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.upstream_slow_start_ms = std.fmt.parseInt(u32, value, 10) catch cfg.upstream_slow_start_ms;
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

    loadConfiguredDomainConfigs(init.io, std.heap.page_allocator, &cfg) catch |err| {
        std.debug.print("Failed to load domain config dir: {}\n", .{err});
        return err;
    };

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

    loadAllConfiguredTlsMaterials(init.io, std.heap.page_allocator, &cfg) catch |err| {
        std.debug.print("Failed to load native TLS certificate/key: {}\n", .{err});
        return err;
    };
    defer {
        deinitConfiguredTlsMaterials(std.heap.page_allocator, &cfg);
    }

    var concurrency = ConcurrencyState.init();

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
        std.debug.print(
            "Reverse proxy pool: {s} over {d} target(s), retries={d}, max_failures={d}, fail_timeout={d}ms, circuit={s} half_open={d}, slow_start={d}ms, keepalive={s} max_idle={d}\n",
            .{
                upstreamPoolPolicyName(cfg.upstream_policy),
                upstreamPoolTargetCount(pool),
                cfg.upstream_retries,
                cfg.upstream_max_failures,
                cfg.upstream_fail_timeout_ms,
                if (cfg.upstream_circuit_breaker_enabled) "on" else "off",
                cfg.upstream_circuit_half_open_max,
                cfg.upstream_slow_start_ms,
                if (upstreamKeepaliveConfigured(&cfg)) "on" else "off",
                cfg.upstream_keepalive_max_idle,
            },
        );
    }
    if (cfg.h2_upstream != null) {
        const hup = cfg.h2_upstream.?;
        std.debug.print("HTTP/2 cleartext passthrough to: {s}:{d} (base {s})\n", .{ hup.host, hup.port, hup.base_path });
    }
    std.debug.print(
        "Timeouts: header={d}ms body={d}ms idle={d}ms write={d}ms upstream={d}ms upstream_retries={d} graceful_shutdown={d}ms\n",
        .{
            cfg.read_header_timeout_ms,
            cfg.read_body_timeout_ms,
            cfg.idle_timeout_ms,
            cfg.write_timeout_ms,
            cfg.upstream_timeout_ms,
            cfg.upstream_retries,
            cfg.graceful_shutdown_timeout_ms,
        },
    );
    if (cfg.upstream_health_check_enabled) {
        const health_worker = std.Thread.spawn(.{}, upstreamHealthCheckTask, .{UpstreamHealthCheckContext{ .io = init.io, .cfg = &cfg }}) catch |err| {
            std.debug.print("Failed to start upstream health checker: {}\n", .{err});
            return;
        };
        health_worker.detach();
        std.debug.print("Active upstream health checks: path={s} interval={d}ms timeout={d}ms\n", .{ cfg.upstream_health_check_path, cfg.upstream_health_check_interval_ms, cfg.upstream_health_check_timeout_ms });
    }
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
