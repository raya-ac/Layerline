const std = @import("std");
const builtin = @import("builtin");
const access_log_mod = @import("access_log.zig");
const admin_pages = @import("admin_pages.zig");
const admin_support = @import("admin_support.zig");
const admin_ui_mod = @import("admin_ui.zig");
const acme_mod = @import("acme.zig");
const cgi_headers = @import("cgi_headers.zig");
const config_mod = @import("config.zig");
const fastcgi = @import("fastcgi.zig");
const h2_native = @import("h2_native.zig");
const h2_support = @import("http2_support.zig");
const http3_server = @import("http3_server.zig");
const http_headers = @import("http_headers.zig");
const http_response = @import("http_response.zig");
const metrics_mod = @import("metrics.zig");
const native_tls = @import("native_tls_runtime.zig");
const proxy_utils = @import("proxy_utils.zig");
const request_mod = @import("request.zig");
const request_trace = @import("request_trace.zig");
const routing_mod = @import("routing.zig");
const static_files = @import("static_files.zig");
const tls_client_hello = @import("tls_client_hello.zig");
const tls_pem = @import("tls_pem.zig");
const upstream_mod = @import("upstream.zig");

const findRedirectRule = routing_mod.findRedirectRule;
const makeStaticPathFromRequest = routing_mod.makeStaticPathFromRequest;
const findNamedRoute = routing_mod.findNamedRoute;
const findNamedRouteMutable = routing_mod.findNamedRouteMutable;
const findDomainForHost = routing_mod.findDomainForHost;
const findDomainForHostMutable = routing_mod.findDomainForHostMutable;
const findDomainForRequest = routing_mod.findDomainForRequest;
const findDomainForRequestMutable = routing_mod.findDomainForRequestMutable;
const domainStaticDir = routing_mod.domainStaticDir;
const domainServeStaticRoot = routing_mod.domainServeStaticRoot;
const domainIndexFile = routing_mod.domainIndexFile;
const domainPhpRoot = routing_mod.domainPhpRoot;
const domainPhpBinary = routing_mod.domainPhpBinary;
const domainPhpFastcgi = routing_mod.domainPhpFastcgi;
const domainPhpIndex = routing_mod.domainPhpIndex;
const domainPhpInfoPage = routing_mod.domainPhpInfoPage;
const domainPhpFrontController = routing_mod.domainPhpFrontController;
const routePhpIndex = routing_mod.routePhpIndex;
const routePhpFrontController = routing_mod.routePhpFrontController;
const routePhpFastcgi = routing_mod.routePhpFastcgi;
const domainUpstream = routing_mod.domainUpstream;
const domainUpstreamMutable = routing_mod.domainUpstreamMutable;
const domainUpstreamPolicy = routing_mod.domainUpstreamPolicy;
const routeUpstreamPolicy = routing_mod.routeUpstreamPolicy;
const domainUpstreamTimeoutMs = routing_mod.domainUpstreamTimeoutMs;
const routeUpstreamTimeoutMs = routing_mod.routeUpstreamTimeoutMs;
const findDomainRedirectRule = routing_mod.findDomainRedirectRule;
const findDomainRoute = routing_mod.findDomainRoute;
const findDomainRouteMutable = routing_mod.findDomainRouteMutable;
const routeFileRelativePath = routing_mod.routeFileRelativePath;
const findHeaderValue = http_headers.findHeaderValue;
const hasConnectionToken = http_headers.hasConnectionToken;
const trimValue = http_headers.trimValue;
const buildCgiExtraHeaders = cgi_headers.buildExtraHeaders;
const findCgiHeaderValue = cgi_headers.findHeaderValue;
const isCgiHeaderNameChar = cgi_headers.isHeaderNameChar;
const isPhpCgiBinary = cgi_headers.isPhpCgiBinary;
const isSkippedCgiResponseHeader = cgi_headers.isSkippedResponseHeader;
const parseCgiStatus = cgi_headers.parseStatus;
const putCgiRequestHeaders = cgi_headers.putRequestHeaders;
const splitCgiHeaderBlock = cgi_headers.splitHeaderBlock;
const renderAdminSetupPage = admin_ui_mod.renderAdminSetupPage;
const renderAdminLoginPage = admin_ui_mod.renderAdminLoginPage;
const AdminConfigSetting = admin_support.AdminConfigSetting;
const AdminCredentials = admin_support.AdminCredentials;
const FormField = admin_support.FormField;
const adminTrimmedField = admin_support.adminTrimmedField;
const adminCheckboxEnabled = admin_support.adminCheckboxEnabled;
const validateAdminSettingsPatch = admin_support.validateAdminSettingsPatch;
const writeAdminMainConfigFile = admin_support.writeAdminMainConfigFile;
const buildAdminSiteConfig = admin_support.buildAdminSiteConfig;
const writeAdminSiteConfigFile = admin_support.writeAdminSiteConfigFile;
const validateAdminUiPath = admin_support.validateAdminUiPath;
const adminPathMatches = admin_support.adminPathMatches;
const adminSubPath = admin_support.adminSubPath;
const parseUrlEncodedForm = admin_support.parseUrlEncodedForm;
const freeFormFields = admin_support.freeFormFields;
const formValue = admin_support.formValue;
const loadAdminCredentials = admin_support.loadAdminCredentials;
const createAdminCredentials = admin_support.createAdminCredentials;
const verifyAdminPassword = admin_support.verifyAdminPassword;
const adminSessionCookieValid = admin_support.adminSessionCookieValid;
const makeAdminSessionCookie = admin_support.makeAdminSessionCookie;
const makeAdminClearCookie = admin_support.makeAdminClearCookie;
const buildAcmeChallengeFilePath = acme_mod.buildAcmeChallengeFilePath;
const certbotWebrootFromAcmeConfig = acme_mod.certbotWebrootFromAcmeConfig;
const ensureCloudflareDeployment = acme_mod.ensureCloudflareDeployment;
const ensureLetsEncryptSetup = acme_mod.ensureLetsEncryptSetup;
const ServerMetrics = metrics_mod.ServerMetrics;
const StaticTransferMode = metrics_mod.StaticTransferMode;
const UpstreamResponseForwardResult = proxy_utils.UpstreamResponseForwardResult;
const UpstreamResponseFraming = proxy_utils.UpstreamResponseFraming;
const ChunkedBodyScanner = proxy_utils.ChunkedBodyScanner;
const buildProxyPath = proxy_utils.buildProxyPath;
const isSkippedProxyHeader = proxy_utils.isSkippedProxyHeader;
const isSkippedProxyResponseHeader = proxy_utils.isSkippedProxyResponseHeader;
const parseOptionalContentLength = proxy_utils.parseOptionalContentLength;
const parseUpstreamResponseFraming = proxy_utils.parseUpstreamResponseFraming;
const responseHasNoBody = proxy_utils.responseHasNoBody;
const parseHttpStatusCode = proxy_utils.parseHttpStatusCode;
const FastcgiRunResult = fastcgi.RunResult;
const PhpFrontControllerTarget = fastcgi.PhpFrontControllerTarget;
const appendFastcgiParam = fastcgi.appendParam;
const makePhpFrontControllerTarget = fastcgi.makePhpFrontControllerTarget;
const FASTCGI_BEGIN_REQUEST = fastcgi.BEGIN_REQUEST;
const FASTCGI_PARAMS = fastcgi.PARAMS;
const FASTCGI_STDIN = fastcgi.STDIN;
const FASTCGI_RESPONDER = fastcgi.RESPONDER;
const FASTCGI_KEEP_CONN = fastcgi.KEEP_CONN;
const FASTCGI_REQUEST_COMPLETE = fastcgi.REQUEST_COMPLETE;
const ByteRange = static_files.ByteRange;
const acceptsContentCoding = static_files.acceptsContentCoding;
const contentTypeFromPath = static_files.contentTypeFromPath;
const etagMatches = static_files.etagMatches;
const makeStaticBaseHeaders = static_files.makeStaticBaseHeaders;
const makeStaticEtag = static_files.makeStaticEtag;
const parseByteRange = static_files.parseByteRange;
const statRegularFile = static_files.statRegularFile;
const TlsChannel = native_tls.Channel;
const HttpRequest = request_mod.HttpRequest;
const H2BufferedResponse = h2_support.BufferedResponse;
const H2Frame = h2_support.Frame;
const H2PendingReader = h2_support.PendingReader;
const H2RequestState = h2_support.RequestState;
const UpstreamAttemptLease = upstream_mod.UpstreamAttemptLease;
const upstreamPoolTargetCount = upstream_mod.upstreamPoolTargetCount;
const upstreamInSlowStart = upstream_mod.upstreamInSlowStart;
const upstreamEffectiveWeight = upstream_mod.upstreamEffectiveWeight;
const upstreamIsSelectable = upstream_mod.upstreamIsSelectable;
const selectUpstream = upstream_mod.selectUpstream;
const upstreamIsEjected = upstream_mod.upstreamIsEjected;
const upstreamRecordSuccess = upstream_mod.upstreamRecordSuccess;
const upstreamRecordFailure = upstream_mod.upstreamRecordFailure;
const upstreamBeginAttempt = upstream_mod.upstreamBeginAttempt;
const upstreamEndAttempt = upstream_mod.upstreamEndAttempt;
const upstreamAttemptLimit = upstream_mod.upstreamAttemptLimit;
const upstreamAtAttempt = upstream_mod.upstreamAtAttempt;
const upstreamStartTicket = upstream_mod.upstreamStartTicket;
const printUpstreamPool = upstream_mod.printUpstreamPool;
const UpstreamIdleConnection = config_mod.UpstreamIdleConnection;
const UpstreamKeepAlivePool = config_mod.UpstreamKeepAlivePool;
const FastcgiIdleConnection = config_mod.FastcgiIdleConnection;
const FastcgiKeepAlivePool = config_mod.FastcgiKeepAlivePool;
const UpstreamConfig = config_mod.UpstreamConfig;
const PhpFastcgiTcpEndpoint = config_mod.PhpFastcgiTcpEndpoint;
const PhpFastcgiEndpoint = config_mod.PhpFastcgiEndpoint;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const ResponseHeaderRule = config_mod.ResponseHeaderRule;
const CompressionPolicy = config_mod.CompressionPolicy;
const RedirectRule = config_mod.RedirectRule;
const RouteMatchKind = config_mod.RouteMatchKind;
const RouteHandlerKind = config_mod.RouteHandlerKind;
const RouteConfig = config_mod.RouteConfig;
const DomainConfig = config_mod.DomainConfig;
const ServerConfig = config_mod.ServerConfig;
const ResponseHeaderContext = config_mod.ResponseHeaderContext;
const defaultServerConfig = config_mod.defaultServerConfig;
const buildResponseHeaderContext = config_mod.buildResponseHeaderContext;
const compressionPolicyFromConfig = config_mod.compressionPolicyFromConfig;
const responseHeaderRulesContain = config_mod.responseHeaderRulesContain;
const parseBool = config_mod.parseBool;
const disablesOptionalUrl = config_mod.disablesOptionalUrl;
const parseFastcgiEndpoint = config_mod.parseFastcgiEndpoint;
const validateFastcgiEndpoint = config_mod.validateFastcgiEndpoint;
const parseUpstream = config_mod.parseUpstream;
const parseUpstreamPool = config_mod.parseUpstreamPool;
const parseUpstreamPoolPolicy = config_mod.parseUpstreamPoolPolicy;
const parseOptionalUpstreamPoolPolicy = config_mod.parseOptionalUpstreamPoolPolicy;
const routeHandlerName = config_mod.routeHandlerName;
const routeMatchName = config_mod.routeMatchName;
const upstreamPoolPolicyName = config_mod.upstreamPoolPolicyName;
const applyConfigLine = config_mod.applyConfigLine;
const loadConfig = config_mod.loadConfig;
const loadConfiguredDomainConfigs = config_mod.loadConfiguredDomainConfigs;
const normalizeConfig = config_mod.normalizeConfig;
const validateConfig = config_mod.validateConfig;
const initDomainConfig = config_mod.initDomainConfig;
const findDomainConfigMutable = config_mod.findDomainConfigMutable;
const appendServerNames = config_mod.appendServerNames;
const isDomainConfigNameValid = config_mod.isDomainConfigNameValid;
const isDomainConfigFileName = config_mod.isDomainConfigFileName;
const setRouteLine = config_mod.setRouteLine;
const setRouteLineFor = config_mod.setRouteLineFor;
const setRouteStringProperty = config_mod.setRouteStringProperty;
const setRouteProxyProperty = config_mod.setRouteProxyProperty;
const setRouteUpstreamPolicyProperty = config_mod.setRouteUpstreamPolicyProperty;
const setRouteU32Property = config_mod.setRouteU32Property;
const setRouteBoolProperty = config_mod.setRouteBoolProperty;
const setDomainLine = config_mod.setDomainLine;
const setDomainRouteLine = config_mod.setDomainRouteLine;
const setDomainStringPropertyDirect = config_mod.setDomainStringPropertyDirect;
const setDomainBoolPropertyDirect = config_mod.setDomainBoolPropertyDirect;
const setDomainProxyPropertyDirect = config_mod.setDomainProxyPropertyDirect;
const setDomainUpstreamPolicyPropertyDirect = config_mod.setDomainUpstreamPolicyPropertyDirect;
const setDomainU32PropertyDirect = config_mod.setDomainU32PropertyDirect;
const applyDomainConfigLine = config_mod.applyDomainConfigLine;
const validateUpstreamPool = config_mod.validateUpstreamPool;
const validateRouteConfig = config_mod.validateRouteConfig;

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
const DEFAULT_LETSENCRYPT_RENEW_INTERVAL_MS = 12 * 60 * 60 * 1000;
const DEFAULT_COMPRESSION_MIN_BYTES = 512;
const DEFAULT_COMPRESSION_MAX_BYTES = 1024 * 1024;
const DEFAULT_COMPRESSION_WORK_BUFFER_BYTES = std.compress.flate.max_window_len;
const DEFAULT_COMPRESSION_WORKER_STACK_BYTES = 512 * 1024;
const HTTP2_MAX_PENDING_BODY_STREAMS = 128;
const HTTP2_ERROR_NO_ERROR: u32 = 0x0;
const HTTP2_ERROR_PROTOCOL: u32 = 0x1;
const HTTP2_ERROR_STREAM_CLOSED: u32 = 0x5;
const HTTP2_ERROR_REFUSED_STREAM: u32 = 0x7;
const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_CHUNK_LINE_BYTES = 4096;
const DEFAULT_CONFIG_PATH = "server.conf";
const ACME_CHALLENGE_DIR = ".well-known/acme-challenge";
const ACME_CHALLENGE_PATH_SUFFIX = "/.well-known/acme-challenge";
const DEFAULT_ADMIN_SOCKET_PATH = "/tmp/layerline-admin.sock";
const DEFAULT_ADMIN_UI_PATH = "/_layerline/admin";
const DEFAULT_ADMIN_CREDENTIALS_PATH = ".layerline-admin";
const DEFAULT_ACCESS_LOG_PATH = "stderr";
const SERVER_NAME = "Layerline";
const SERVER_TAGLINE = "Modern web server";
const SERVER_HEADER = "Layerline";
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
threadlocal var current_request_headers: []const u8 = "";
threadlocal var current_request_id: []const u8 = "";
threadlocal var current_compression_policy: CompressionPolicy = .disabled;
threadlocal var current_access_log: ?*access_log_mod.Context = null;
var access_log_writer = access_log_mod.Writer{};
var request_id_generator = request_trace.Generator{};
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
            return native_tls.readApplicationData(channel, out);
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
            return native_tls.writeApplicationData(channel, bytes);
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
    closed: *std.atomic.Value(bool),
    wake_host: ?[]const u8 = null,
    wake_port: u16 = 0,
};

fn shutdownWatcherTask(ctx: ShutdownWatcherContext) void {
    bindThreadIo(ctx.io);
    while (!shutdown_requested.load(.acquire)) {
        ctx.io.sleep(.fromMilliseconds(25), .awake) catch {};
    }

    if (ctx.wake_host) |host| {
        if (ctx.wake_port != 0) {
            if (connectTcpHost(std.heap.page_allocator, host, ctx.wake_port)) |wake| {
                streamClose(wake);
            } else |_| {}
        }
    }
    if (!ctx.closed.swap(true, .acq_rel)) {
        ctx.server.socket.close(ctx.io);
    }
}

fn streamWriteRequestIdHeader(stream: std.Io.net.Stream) !void {
    if (current_request_id.len == 0) return;
    try streamWriteFmt(stream, "X-Request-Id: {s}\r\n", .{current_request_id});
}

fn streamWriteConfiguredResponseHeaders(stream: std.Io.net.Stream) !void {
    try streamWriteRequestIdHeader(stream);
    for (current_response_headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "X-Request-Id")) continue;
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

fn listenerWakeHost(host: []const u8) []const u8 {
    if (std.mem.eql(u8, host, "0.0.0.0")) return "127.0.0.1";
    if (std.mem.eql(u8, host, "::")) return "::1";
    return host;
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

fn headerBlockContainsHeader(headers: ?[]const u8, name: []const u8) bool {
    const raw_headers = headers orelse return false;
    var lines = std.mem.splitSequence(u8, raw_headers, "\r\n");
    while (lines.next()) |line| {
        const trimmed = trimValue(line);
        if (trimmed.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse continue;
        const header_name = trimValue(trimmed[0..colon]);
        if (std.ascii.eqlIgnoreCase(header_name, name)) return true;
    }
    return false;
}

fn h2HeadersContain(headers: []const h2_native.Header, name: []const u8) bool {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return true;
    }
    return false;
}

fn isCompressibleContentType(content_type: []const u8) bool {
    const semicolon = std.mem.indexOfScalar(u8, content_type, ';') orelse content_type.len;
    const base = trimValue(content_type[0..semicolon]);
    return std.mem.startsWith(u8, base, "text/") or
        std.ascii.eqlIgnoreCase(base, "application/javascript") or
        std.ascii.eqlIgnoreCase(base, "application/json") or
        std.ascii.eqlIgnoreCase(base, "application/xml") or
        std.ascii.eqlIgnoreCase(base, "application/wasm") or
        std.ascii.eqlIgnoreCase(base, "image/svg+xml");
}

fn gzipCompressAlloc(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    var output = try std.Io.Writer.Allocating.initCapacity(allocator, @max(@as(usize, 64), body.len / 2));
    errdefer output.deinit();

    const work_buffer = try allocator.alloc(u8, DEFAULT_COMPRESSION_WORK_BUFFER_BYTES);
    defer allocator.free(work_buffer);

    const GzipCompressor = std.compress.flate.Compress;
    const gzip = try allocator.create(GzipCompressor);
    defer allocator.destroy(gzip);

    gzip.* = try GzipCompressor.init(&output.writer, work_buffer, .gzip, .fastest);
    try gzip.writer.writeAll(body);
    try gzip.finish();
    return output.toOwnedSlice();
}

const PreparedResponseBody = struct {
    body: []const u8,
    encoding: ?[]const u8 = null,
    owned: ?[]u8 = null,

    fn deinit(self: PreparedResponseBody, allocator: std.mem.Allocator) void {
        if (self.owned) |owned| allocator.free(owned);
    }
};

fn prepareResponseBody(
    allocator: std.mem.Allocator,
    status_code: u16,
    content_type: []const u8,
    body: []const u8,
    is_head: bool,
    extra_headers: ?[]const u8,
    h2_headers: []const h2_native.Header,
) !PreparedResponseBody {
    const policy = current_compression_policy;
    if (!http_response.canSendBody(status_code, is_head) or
        !policy.enabled or
        !policy.gzip_enabled or
        body.len < policy.min_bytes or
        body.len > policy.max_bytes or
        !isCompressibleContentType(content_type) or
        !acceptsContentCoding(current_request_headers, "gzip") or
        headerBlockContainsHeader(extra_headers, "Content-Encoding") or
        h2HeadersContain(h2_headers, "content-encoding") or
        responseHeaderRulesContain(current_response_headers, "Content-Encoding"))
    {
        return .{ .body = body };
    }

    const compressed = try gzipCompressAlloc(allocator, body);
    if (compressed.len >= body.len) {
        allocator.free(compressed);
        return .{ .body = body };
    }

    server_metrics.compressedResponseSent(compressed.len);
    return .{ .body = compressed, .encoding = "gzip", .owned = compressed };
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

const LetsEncryptRenewalContext = struct {
    io: std.Io,
    cfg: *const ServerConfig,
};

fn sleepUntilShutdown(io: std.Io, total_ms: u32) bool {
    var remaining = total_ms;
    while (remaining > 0 and !shutdown_requested.load(.acquire)) {
        const step_ms: u32 = @min(@as(u32, 1_000), remaining);
        io.sleep(.fromMilliseconds(step_ms), .awake) catch {};
        remaining -= step_ms;
    }
    return shutdown_requested.load(.acquire);
}

fn letsEncryptRenewalTask(ctx: LetsEncryptRenewalContext) void {
    bindThreadIo(ctx.io);
    std.debug.print("Let's Encrypt renewal loop: interval={d}ms webroot={s}\n", .{ ctx.cfg.letsencrypt_renew_interval_ms, ctx.cfg.letsencrypt_webroot });

    while (!shutdown_requested.load(.acquire)) {
        if (sleepUntilShutdown(ctx.io, ctx.cfg.letsencrypt_renew_interval_ms)) break;
        acme_mod.runLetsEncryptRenewal(ctx.io, std.heap.page_allocator, ctx.cfg, &server_metrics) catch |err| {
            std.debug.print("Let's Encrypt renewal failed: {}\n", .{err});
        };
    }
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
    if (std.mem.startsWith(u8, bytes, h2_support.PREFACE_MAGIC)) return true;
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

var server_metrics = ServerMetrics.init();
var fastcgi_keepalive_pool = FastcgiKeepAlivePool.init();

fn upstreamNowMs() i64 {
    return std.Io.Timestamp.now(activeIo(), .awake).toMilliseconds();
}

fn validateConfigFileForActivation(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const candidate_allocator = arena.allocator();

    var candidate = defaultServerConfig();
    candidate.config_path = cfg.config_path;
    try loadConfig(io, candidate_allocator, &candidate, candidate.config_path);
    try loadConfiguredDomainConfigs(io, candidate_allocator, &candidate);
    normalizeConfig(&candidate);
    try validateConfig(&candidate);

    // Catch bad certificate paths before an operator asks a supervisor to
    // restart into them. The arena drops the temporary material afterwards.
    try loadAllConfiguredTlsMaterials(io, candidate_allocator, &candidate);
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
    const prepared = try prepareResponseBody(std.heap.page_allocator, status_code, content_type, body, false, extra_headers, &.{});
    defer prepared.deinit(std.heap.page_allocator);

    const body_len = prepared.body.len;
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
    if (prepared.encoding) |encoding| {
        try streamWriteFmt(stream, "Content-Encoding: {s}\r\nVary: Accept-Encoding\r\n", .{encoding});
    }
    try streamWriteConfiguredResponseHeaders(stream);
    try streamWriteAll(stream, "\r\n");

    if (body_len > 0) try streamWriteAll(stream, prepared.body);
    recordResponseSent(status_code, body_len);
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
    recordResponseSent(status_code, 0);
}

fn sendResponseNoBodyWithConnection(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body_len: usize, close_connection: bool) !void {
    try sendResponseNoBodyWithConnectionAndHeaders(stream, status_code, status_text, content_type, body_len, close_connection, null);
}

fn sendNotFound(allocator: std.mem.Allocator, stream: std.Io.net.Stream) !void {
    try sendCoolError(stream, allocator, 404, "Not Found", "The requested resource was not found on this server.");
}

fn sendNotFoundWithConnection(allocator: std.mem.Allocator, stream: std.Io.net.Stream, close_connection: bool) !void {
    try sendNotFoundForMethod(allocator, stream, close_connection, false);
}

fn sendNotFoundForMethod(allocator: std.mem.Allocator, stream: std.Io.net.Stream, close_connection: bool, is_head: bool) !void {
    try sendCoolErrorWithConnection(stream, allocator, 404, "Not Found", "The requested resource was not found on this server.", close_connection, is_head, null);
}

fn customErrorDocumentName(status_code: u16) ?[]const u8 {
    return switch (status_code) {
        404 => "404.html",
        else => null,
    };
}

fn readDomainCustomErrorDocument(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    domain: ?*const DomainConfig,
    status_code: u16,
) !?[]u8 {
    const name = customErrorDocumentName(status_code) orelse return null;
    if (domain == null) return null;

    const file_path = try std.fs.path.join(allocator, &.{ domainStaticDir(cfg, domain), name });
    defer allocator.free(file_path);

    const stat = statRegularFile(io, file_path) catch |err| {
        if (err == error.NotDir or err == error.FileNotFound or err == error.NotFile) return null;
        return err;
    };
    if (stat.size > cfg.max_static_file_bytes) return null;

    return std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(cfg.max_static_file_bytes)) catch |err| {
        if (err == error.StreamTooLong or err == error.NotDir or err == error.FileNotFound or err == error.NotFile) return null;
        return err;
    };
}

fn sendDomainCustomNotFoundForMethod(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    domain: ?*const DomainConfig,
    close_connection: bool,
    is_head: bool,
) !void {
    if (try readDomainCustomErrorDocument(io, allocator, cfg, domain, 404)) |body| {
        defer allocator.free(body);
        try sendResponseForMethod(stream, 404, "Not Found", "text/html; charset=utf-8", body, close_connection, is_head);
        return;
    }

    try sendNotFoundForMethod(allocator, stream, close_connection, is_head);
}

fn sendBadRequest(allocator: std.mem.Allocator, stream: std.Io.net.Stream, reason: []const u8) !void {
    try sendCoolError(stream, allocator, 400, "Bad Request", reason);
}

fn sendBadRequestWithConnection(allocator: std.mem.Allocator, stream: std.Io.net.Stream, reason: []const u8, close_connection: bool) !void {
    try sendBadRequestForMethod(allocator, stream, reason, close_connection, false);
}

fn sendBadRequestForMethod(allocator: std.mem.Allocator, stream: std.Io.net.Stream, reason: []const u8, close_connection: bool, is_head: bool) !void {
    try sendCoolErrorWithConnection(stream, allocator, 400, "Bad Request", reason, close_connection, is_head, null);
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

fn isRedirectStatusCode(status_code: u16) bool {
    return switch (status_code) {
        301, 302, 303, 307, 308 => true,
        else => false,
    };
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

fn isAsciiDigitSlice(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (byte < '0' or byte > '9') return false;
    }
    return true;
}

fn stripPortFromHostForRedirect(raw_host: []const u8) []const u8 {
    const host = trimValue(raw_host);
    if (host.len == 0) return host;
    if (host[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host, ']') orelse return host;
        return host[0 .. close + 1];
    }

    var colon_count: usize = 0;
    for (host) |byte| {
        if (byte == ':') colon_count += 1;
    }
    if (colon_count == 1) {
        const colon = std.mem.lastIndexOfScalar(u8, host, ':') orelse return host;
        if (isAsciiDigitSlice(host[colon + 1 ..])) return host[0..colon];
    }
    return host;
}

fn isSafeRedirectHost(host: []const u8) bool {
    if (host.len == 0) return false;
    if (std.mem.indexOfAny(u8, host, " \t\r\n\x00/?#") != null) return false;
    if (host[0] != '[' and std.mem.indexOfScalar(u8, host, ':') != null) return false;
    return true;
}

fn buildHttpsRedirectLocation(allocator: std.mem.Allocator, cfg: *const ServerConfig, req: HttpRequest) ![]const u8 {
    if (req.path.len == 0 or req.path[0] != '/') return error.InvalidRedirectPath;
    const raw_host = findHeaderValue(req.headers, "Host") orelse return error.MissingHostHeader;
    const host = stripPortFromHostForRedirect(raw_host);
    if (!isSafeRedirectHost(host)) return error.InvalidRedirectHost;

    const query_joiner: []const u8 = if (req.query.len > 0) "?" else "";
    if (cfg.http_redirect_https_port == 443) {
        return std.fmt.allocPrint(allocator, "https://{s}{s}{s}{s}", .{ host, req.path, query_joiner, req.query });
    }
    return std.fmt.allocPrint(allocator, "https://{s}:{d}{s}{s}{s}", .{ host, cfg.http_redirect_https_port, req.path, query_joiner, req.query });
}

fn sendHttpsRedirect(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, req: HttpRequest, close_connection: bool, is_head: bool) !void {
    const location = try buildHttpsRedirectLocation(allocator, cfg, req);
    defer allocator.free(location);

    const extra_headers = try std.fmt.allocPrint(allocator, "Location: {s}\r\n", .{location});
    defer allocator.free(extra_headers);

    const body = try std.fmt.allocPrint(allocator, "Redirecting to {s}\n", .{location});
    defer allocator.free(body);

    if (is_head) {
        try sendResponseNoBodyWithConnectionAndHeaders(stream, cfg.http_redirect_status, redirectStatusText(cfg.http_redirect_status), "text/plain; charset=utf-8", body.len, close_connection, extra_headers);
        return;
    }
    try sendResponseWithConnectionAndHeaders(stream, cfg.http_redirect_status, redirectStatusText(cfg.http_redirect_status), "text/plain; charset=utf-8", body, close_connection, extra_headers);
}

fn sendServerIcon(stream: std.Io.net.Stream, close_connection: bool, is_head: bool) !void {
    try sendResponseForMethod(stream, 200, "OK", "image/svg+xml", SERVER_ICON_SVG, close_connection, is_head);
}

fn recordResponseSent(status_code: u16, body_bytes: usize) void {
    server_metrics.responseSent(status_code, body_bytes);
    emitAccessLog(status_code, body_bytes);
}

fn sendMetrics(stream: std.Io.net.Stream, allocator: std.mem.Allocator, close_connection: bool, is_head: bool) !void {
    const body = try metrics_mod.render(allocator, &server_metrics);
    defer allocator.free(body);
    try sendResponseForMethod(stream, 200, "OK", "text/plain; version=0.0.4; charset=utf-8", body, close_connection, is_head);
}

fn adminRuntimeView() admin_pages.RuntimeView {
    return .{ .server_name = SERVER_NAME, .metrics = &server_metrics };
}

fn sendAdminRedirect(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, cookie: ?[]const u8, close_connection: bool, is_head: bool) !void {
    const extra_headers = if (cookie) |cookie_value|
        try std.fmt.allocPrint(allocator, "Location: {s}\r\nSet-Cookie: {s}\r\nCache-Control: no-store\r\n", .{ cfg.admin_ui_path, cookie_value })
    else
        try std.fmt.allocPrint(allocator, "Location: {s}\r\nCache-Control: no-store\r\n", .{cfg.admin_ui_path});
    defer allocator.free(extra_headers);

    const body = "Redirecting to Layerline Admin.\n";
    if (is_head) {
        try sendResponseNoBodyWithConnectionAndHeaders(stream, 303, "See Other", "text/plain; charset=utf-8", body.len, close_connection, extra_headers);
    } else {
        try sendResponseWithConnectionAndHeaders(stream, 303, "See Other", "text/plain; charset=utf-8", body, close_connection, extra_headers);
    }
}

fn sendAdminPage(stream: std.Io.net.Stream, allocator: std.mem.Allocator, status_code: u16, status_text: []const u8, body: []const u8, close_connection: bool, is_head: bool) !void {
    _ = allocator;
    const headers = "Cache-Control: no-store\r\n";
    if (is_head) {
        try sendResponseNoBodyWithConnectionAndHeaders(stream, status_code, status_text, "text/html; charset=utf-8", body.len, close_connection, headers);
    } else {
        try sendResponseWithConnectionAndHeaders(stream, status_code, status_text, "text/html; charset=utf-8", body, close_connection, headers);
    }
}

fn sendAdminSetupPage(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, maybe_error: ?[]const u8, status_code: u16, status_text: []const u8, close_connection: bool, is_head: bool) !void {
    const body = try renderAdminSetupPage(allocator, cfg, maybe_error);
    defer allocator.free(body);
    try sendAdminPage(stream, allocator, status_code, status_text, body, close_connection, is_head);
}

fn sendAdminLoginPage(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, maybe_error: ?[]const u8, status_code: u16, status_text: []const u8, close_connection: bool, is_head: bool) !void {
    const body = try renderAdminLoginPage(allocator, cfg, maybe_error);
    defer allocator.free(body);
    try sendAdminPage(stream, allocator, status_code, status_text, body, close_connection, is_head);
}

fn sendAdminDashboardPage(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    credentials: AdminCredentials,
    maybe_notice: ?[]const u8,
    maybe_error: ?[]const u8,
    status_code: u16,
    status_text: []const u8,
    close_connection: bool,
    is_head: bool,
) !void {
    const body = try admin_pages.renderDashboardPage(io, allocator, cfg, credentials, maybe_notice, maybe_error, adminRuntimeView(), validateConfigFileForActivation);
    defer allocator.free(body);
    try sendAdminPage(stream, allocator, status_code, status_text, body, close_connection, is_head);
}

fn accessLogSetHandler(handler: []const u8) void {
    access_log_mod.setHandler(current_access_log, handler);
}

fn accessLogSetUpstream(upstream: []const u8) void {
    access_log_mod.setUpstream(current_access_log, upstream);
}

fn accessLogSetError(error_name: []const u8) void {
    access_log_mod.setError(current_access_log, error_name);
}

fn emitAccessLog(status_code: u16, body_bytes: usize) void {
    access_log_writer.emit(activeIo(), current_access_log, SERVER_NAME, status_code, body_bytes);
}

fn handleAdminSetupPost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, req: HttpRequest, close_connection: bool) !void {
    var fields = parseUrlEncodedForm(allocator, req.body) catch {
        try sendAdminSetupPage(stream, allocator, cfg, "The setup form could not be parsed.", 400, "Bad Request", close_connection, false);
        return;
    };
    defer freeFormFields(allocator, &fields);

    const username = formValue(fields.items, "username") orelse "";
    const password = formValue(fields.items, "password") orelse "";
    const password_confirm = formValue(fields.items, "password_confirm") orelse "";
    const credentials = createAdminCredentials(io, allocator, cfg, username, password, password_confirm) catch |err| {
        const message = switch (err) {
            error.InvalidAdminUsername => "Use 2-64 characters: letters, numbers, dot, underscore, dash, or @.",
            error.AdminPasswordTooShort => "Use a password with at least 8 characters.",
            error.AdminPasswordMismatch => "The password confirmation did not match.",
            error.PathAlreadyExists => "Admin access is already configured. Sign in instead.",
            else => "Layerline could not create the admin credentials file.",
        };
        try sendAdminSetupPage(stream, allocator, cfg, message, 400, "Bad Request", close_connection, false);
        return;
    };
    const cookie = try makeAdminSessionCookie(allocator, cfg, credentials);
    defer allocator.free(cookie);
    try sendAdminRedirect(stream, allocator, cfg, cookie, close_connection, false);
}

fn handleAdminLoginPost(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials, req: HttpRequest, close_connection: bool) !void {
    var fields = parseUrlEncodedForm(allocator, req.body) catch {
        try sendAdminLoginPage(stream, allocator, cfg, "The login form could not be parsed.", 400, "Bad Request", close_connection, false);
        return;
    };
    defer freeFormFields(allocator, &fields);

    const username = formValue(fields.items, "username") orelse "";
    const password = formValue(fields.items, "password") orelse "";
    if (!std.mem.eql(u8, username, credentials.username) or !(try verifyAdminPassword(credentials, password))) {
        try sendAdminLoginPage(stream, allocator, cfg, "The username or password was not accepted.", 401, "Unauthorized", close_connection, false);
        return;
    }

    const cookie = try makeAdminSessionCookie(allocator, cfg, credentials);
    defer allocator.free(cookie);
    try sendAdminRedirect(stream, allocator, cfg, cookie, close_connection, false);
}

fn handleAdminValidatePost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials, close_connection: bool) !void {
    validateConfigFileForActivation(io, allocator, cfg) catch |err| {
        const message = try std.fmt.allocPrint(allocator, "Activation config is invalid: {}", .{err});
        defer allocator.free(message);
        try sendAdminDashboardPage(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };
    try sendAdminDashboardPage(io, stream, allocator, cfg, credentials, "Activation config is valid. A managed restart can apply staged writes.", null, 200, "OK", close_connection, false);
}

fn handleAdminRestartPost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials, close_connection: bool) !void {
    validateConfigFileForActivation(io, allocator, cfg) catch |err| {
        const message = try std.fmt.allocPrint(allocator, "Restart blocked because activation config is invalid: {}", .{err});
        defer allocator.free(message);
        try sendAdminDashboardPage(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };

    shutdown_requested.store(true, .release);
    try sendAdminDashboardPage(io, stream, allocator, cfg, credentials, "Graceful restart requested after activation config preflight passed.", null, 202, "Accepted", close_connection, false);
}

fn handleAdminAddSitePost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials, req: HttpRequest, close_connection: bool) !void {
    var fields = parseUrlEncodedForm(allocator, req.body) catch {
        try sendAdminDashboardPage(io, stream, allocator, cfg, credentials, null, "The site form could not be parsed.", 400, "Bad Request", close_connection, false);
        return;
    };
    defer freeFormFields(allocator, &fields);

    const name = adminTrimmedField(fields.items, "name");
    const server_names = adminTrimmedField(fields.items, "server_names");
    const root = adminTrimmedField(fields.items, "root");
    const index = adminTrimmedField(fields.items, "index");
    const proxy = adminTrimmedField(fields.items, "proxy");
    const upstream_policy = adminTrimmedField(fields.items, "upstream_policy");
    const php_fastcgi = adminTrimmedField(fields.items, "php_fastcgi");
    const tls_cert = adminTrimmedField(fields.items, "tls_cert");
    const tls_key = adminTrimmedField(fields.items, "tls_key");
    const route_name = adminTrimmedField(fields.items, "route_name");
    const route_pattern = adminTrimmedField(fields.items, "route_pattern");
    const route_handler = adminTrimmedField(fields.items, "route_handler");
    const route_static_dir = adminTrimmedField(fields.items, "route_static_dir");
    const route_proxy = adminTrimmedField(fields.items, "route_proxy");
    const route_php_fastcgi = adminTrimmedField(fields.items, "route_php_fastcgi");

    const site_config = buildAdminSiteConfig(
        allocator,
        name,
        server_names,
        if (root.len > 0) root else "public",
        if (index.len > 0) index else "index.html",
        adminCheckboxEnabled(fields.items, "serve_static_root"),
        proxy,
        upstream_policy,
        php_fastcgi,
        adminCheckboxEnabled(fields.items, "php_front_controller"),
        tls_cert,
        tls_key,
        route_name,
        route_pattern,
        route_handler,
        route_static_dir,
        route_proxy,
        route_php_fastcgi,
        adminCheckboxEnabled(fields.items, "route_php_front_controller"),
    ) catch |err| {
        const message = switch (err) {
            error.InvalidUpstream => "The proxy field must be one or more http:// or https:// upstream URLs.",
            error.InvalidConfigValue => "The site values are invalid. Use a simple name, server names, safe paths, and complete route fields when adding a route.",
            else => "Layerline could not build that site config.",
        };
        try sendAdminDashboardPage(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };
    defer allocator.free(site_config);

    const path = writeAdminSiteConfigFile(io, allocator, cfg, name, site_config) catch |err| {
        const message = switch (err) {
            error.AdminDomainConfigDirMissing => "Set domain_config_dir before adding sites.",
            error.PathAlreadyExists => "A site config with that internal name already exists.",
            else => "Layerline could not write the site config file.",
        };
        try sendAdminDashboardPage(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };
    defer allocator.free(path);

    const message = try std.fmt.allocPrint(allocator, "Created {s}. Restart Layerline for the new site to become active.", .{path});
    defer allocator.free(message);
    try sendAdminDashboardPage(io, stream, allocator, cfg, credentials, message, null, 201, "Created", close_connection, false);
}

fn handleAdminSettingsPost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials, req: HttpRequest, close_connection: bool) !void {
    var fields = parseUrlEncodedForm(allocator, req.body) catch {
        try sendAdminDashboardPage(io, stream, allocator, cfg, credentials, null, "The settings form could not be parsed.", 400, "Bad Request", close_connection, false);
        return;
    };
    defer freeFormFields(allocator, &fields);

    const host = adminTrimmedField(fields.items, "host");
    const port = adminTrimmedField(fields.items, "port");
    const static_dir = adminTrimmedField(fields.items, "static_dir");
    const index_file = adminTrimmedField(fields.items, "index_file");
    const domain_config_dir = adminTrimmedField(fields.items, "domain_config_dir");
    const serve_static_root = adminTrimmedField(fields.items, "serve_static_root");
    const compression = adminTrimmedField(fields.items, "compression");
    const gzip = adminTrimmedField(fields.items, "gzip");
    const php_root = adminTrimmedField(fields.items, "php_root");
    const php_binary = adminTrimmedField(fields.items, "php_binary");
    const php_fastcgi = adminTrimmedField(fields.items, "php_fastcgi");
    const php_front_controller = adminTrimmedField(fields.items, "php_front_controller");
    const proxy = adminTrimmedField(fields.items, "proxy");
    const upstream_policy = adminTrimmedField(fields.items, "upstream_policy");
    const upstream_timeout_ms = adminTrimmedField(fields.items, "upstream_timeout_ms");
    const upstream_retries = adminTrimmedField(fields.items, "upstream_retries");
    const upstream_keepalive = adminTrimmedField(fields.items, "upstream_keepalive");
    const fastcgi_keepalive = adminTrimmedField(fields.items, "fastcgi_keepalive");
    const tls = adminTrimmedField(fields.items, "tls");
    const tls_cert = adminTrimmedField(fields.items, "tls_cert");
    const tls_key = adminTrimmedField(fields.items, "tls_key");
    const http_redirect = adminTrimmedField(fields.items, "http_redirect");
    const http_redirect_port = adminTrimmedField(fields.items, "http_redirect_port");
    const http_redirect_https_port = adminTrimmedField(fields.items, "http_redirect_https_port");
    const http3 = adminTrimmedField(fields.items, "http3");
    const http3_port = adminTrimmedField(fields.items, "http3_port");
    const admin_socket = adminTrimmedField(fields.items, "admin_socket");
    const admin_ui = adminTrimmedField(fields.items, "admin_ui");
    const admin_ui_path = adminTrimmedField(fields.items, "admin_ui_path");
    const admin_credentials_path = adminTrimmedField(fields.items, "admin_credentials_path");
    const access_log = adminTrimmedField(fields.items, "access_log");
    const max_concurrent_connections = adminTrimmedField(fields.items, "max_concurrent_connections");
    const max_request_bytes = adminTrimmedField(fields.items, "max_request_bytes");
    const read_header_timeout_ms = adminTrimmedField(fields.items, "read_header_timeout_ms");
    const idle_timeout_ms = adminTrimmedField(fields.items, "idle_timeout_ms");
    const worker_stack_size = adminTrimmedField(fields.items, "worker_stack_size");

    const settings = [_]AdminConfigSetting{
        .{ .key = "host", .value = host },
        .{ .key = "port", .value = port },
        .{ .key = "static_dir", .value = static_dir },
        .{ .key = "index_file", .value = index_file },
        .{ .key = "domain_config_dir", .value = domain_config_dir, .emit = domain_config_dir.len > 0 },
        .{ .key = "serve_static_root", .value = serve_static_root },
        .{ .key = "compression", .value = compression },
        .{ .key = "gzip", .value = gzip },
        .{ .key = "php_root", .value = php_root },
        .{ .key = "php_binary", .value = php_binary },
        .{ .key = "php_fastcgi", .value = if (php_fastcgi.len > 0) php_fastcgi else "off" },
        .{ .key = "php_front_controller", .value = php_front_controller },
        .{ .key = "proxy", .value = if (proxy.len > 0) proxy else "off" },
        .{ .key = "upstream_policy", .value = upstream_policy },
        .{ .key = "upstream_timeout_ms", .value = upstream_timeout_ms },
        .{ .key = "upstream_retries", .value = upstream_retries },
        .{ .key = "upstream_keepalive", .value = upstream_keepalive },
        .{ .key = "fastcgi_keepalive", .value = fastcgi_keepalive },
        .{ .key = "tls", .value = tls },
        .{ .key = "tls_cert", .value = tls_cert, .emit = tls_cert.len > 0 },
        .{ .key = "tls_key", .value = tls_key, .emit = tls_key.len > 0 },
        .{ .key = "http_redirect", .value = http_redirect },
        .{ .key = "http_redirect_port", .value = http_redirect_port },
        .{ .key = "http_redirect_https_port", .value = http_redirect_https_port },
        .{ .key = "http3", .value = http3 },
        .{ .key = "http3_port", .value = http3_port },
        .{ .key = "admin_socket", .value = if (admin_socket.len > 0) admin_socket else "off" },
        .{ .key = "admin_ui", .value = admin_ui },
        .{ .key = "admin_ui_path", .value = admin_ui_path },
        .{ .key = "admin_credentials_path", .value = admin_credentials_path },
        .{ .key = "access_log", .value = if (access_log.len > 0) access_log else "off" },
        .{ .key = "max_concurrent_connections", .value = max_concurrent_connections },
        .{ .key = "max_request_bytes", .value = max_request_bytes },
        .{ .key = "read_header_timeout_ms", .value = read_header_timeout_ms },
        .{ .key = "idle_timeout_ms", .value = idle_timeout_ms },
        .{ .key = "worker_stack_size", .value = worker_stack_size },
    };

    validateAdminSettingsPatch(allocator, cfg, settings[0..], tls_cert, tls_key) catch |err| {
        const message = switch (err) {
            error.InvalidConfigValue => "The settings are invalid. Check ports, booleans, paths, TLS cert/key pairs, and upstream URLs.",
            error.InvalidUpstream => "The proxy field must be one or more http:// or https:// upstream URLs.",
            else => "Layerline could not validate those settings.",
        };
        try sendAdminDashboardPage(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };

    const path = writeAdminMainConfigFile(io, allocator, cfg, settings[0..]) catch |err| {
        const message = switch (err) {
            error.InvalidConfigValue => "The generated main config was too large or contained unsafe values.",
            else => "Layerline could not write the main config file.",
        };
        try sendAdminDashboardPage(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };
    defer allocator.free(path);

    const message = try std.fmt.allocPrint(allocator, "Saved settings to {s}. A backup was written when the file already existed. Restart Layerline for these changes to become active.", .{path});
    defer allocator.free(message);
    try sendAdminDashboardPage(io, stream, allocator, cfg, credentials, message, null, 200, "OK", close_connection, false);
}

fn handleAdminUi(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    req: HttpRequest,
    close_connection: bool,
    is_head: bool,
) !void {
    accessLogSetHandler("admin_ui");
    const method = req.method;
    if (std.mem.eql(u8, method, "OPTIONS")) {
        const allow_header = "Allow: GET,HEAD,POST,OPTIONS\r\nCache-Control: no-store\r\n";
        try sendResponseNoBodyWithConnectionAndHeaders(stream, 204, "No Content", "text/plain; charset=utf-8", 0, close_connection, allow_header);
        return;
    }
    if (!(std.mem.eql(u8, method, "GET") or is_head or std.mem.eql(u8, method, "POST"))) {
        try sendMethodNotAllowedWithAllow(stream, allocator, "GET,HEAD,POST,OPTIONS", close_connection, is_head);
        return;
    }

    const sub_path = adminSubPath(cfg.admin_ui_path, req.path);
    const maybe_credentials = try loadAdminCredentials(io, allocator, cfg.admin_credentials_path);
    if (maybe_credentials == null) {
        if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/setup")) {
            try handleAdminSetupPost(io, stream, allocator, cfg, req, close_connection);
            return;
        }
        if (std.mem.eql(u8, method, "GET") or is_head) {
            try sendAdminSetupPage(stream, allocator, cfg, null, 200, "OK", close_connection, is_head);
            return;
        }
        try sendMethodNotAllowedWithAllow(stream, allocator, "GET,HEAD,POST,OPTIONS", close_connection, is_head);
        return;
    }

    const credentials = maybe_credentials.?;
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/login")) {
        try handleAdminLoginPost(stream, allocator, cfg, credentials, req, close_connection);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/logout")) {
        const cookie = try makeAdminClearCookie(allocator, cfg);
        defer allocator.free(cookie);
        try sendAdminRedirect(stream, allocator, cfg, cookie, close_connection, false);
        return;
    }

    if (!adminSessionCookieValid(req.headers, credentials)) {
        if (std.mem.eql(u8, method, "GET") or is_head) {
            try sendAdminLoginPage(stream, allocator, cfg, null, 200, "OK", close_connection, is_head);
            return;
        }
        try sendAdminLoginPage(stream, allocator, cfg, "Sign in before using the admin dashboard.", 401, "Unauthorized", close_connection, false);
        return;
    }

    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/validate")) {
        try handleAdminValidatePost(io, stream, allocator, cfg, credentials, close_connection);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/restart")) {
        try handleAdminRestartPost(io, stream, allocator, cfg, credentials, close_connection);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/sites/add")) {
        try handleAdminAddSitePost(io, stream, allocator, cfg, credentials, req, close_connection);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/settings/save")) {
        try handleAdminSettingsPost(io, stream, allocator, cfg, credentials, req, close_connection);
        return;
    }

    if (std.mem.eql(u8, method, "GET") or is_head) {
        try sendAdminDashboardPage(io, stream, allocator, cfg, credentials, null, null, 200, "OK", close_connection, is_head);
        return;
    }

    try sendMethodNotAllowedWithAllow(stream, allocator, "GET,HEAD,POST,OPTIONS", close_connection, is_head);
}

fn sendAdminText(stream: std.Io.net.Stream, bytes: []const u8) !void {
    try streamWriteAll(stream, bytes);
    if (bytes.len == 0 or bytes[bytes.len - 1] != '\n') try streamWriteAll(stream, "\n");
}

fn handleAdminCommand(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *ServerConfig, command_raw: []const u8) !void {
    const command = trimValue(command_raw);
    if (command.len == 0 or std.mem.eql(u8, command, "help")) {
        try sendAdminText(stream, "commands: status, validate, validate-runtime, restart, routes, certs, metrics, help\n");
        return;
    }

    if (std.mem.eql(u8, command, "status")) {
        const body = try admin_pages.renderStatus(allocator, cfg, adminRuntimeView());
        defer allocator.free(body);
        try sendAdminText(stream, body);
        return;
    }

    if (std.mem.eql(u8, command, "validate") or std.mem.eql(u8, command, "validate-config")) {
        validateConfigFileForActivation(activeIo(), allocator, cfg) catch |err| {
            const body = try std.fmt.allocPrint(allocator, "ERROR config invalid: {}\n", .{err});
            defer allocator.free(body);
            try sendAdminText(stream, body);
            return;
        };
        try sendAdminText(stream, "OK activation config\n");
        return;
    }

    if (std.mem.eql(u8, command, "validate-runtime")) {
        validateConfig(cfg) catch |err| {
            const body = try std.fmt.allocPrint(allocator, "ERROR runtime config invalid: {}\n", .{err});
            defer allocator.free(body);
            try sendAdminText(stream, body);
            return;
        };
        try sendAdminText(stream, "OK runtime config\n");
        return;
    }

    if (std.mem.eql(u8, command, "restart") or std.mem.eql(u8, command, "graceful-restart")) {
        validateConfigFileForActivation(activeIo(), allocator, cfg) catch |err| {
            const body = try std.fmt.allocPrint(allocator, "ERROR restart blocked: {}\n", .{err});
            defer allocator.free(body);
            try sendAdminText(stream, body);
            return;
        };
        try sendAdminText(stream, "OK graceful restart requested\n");
        shutdown_requested.store(true, .release);
        return;
    }

    if (std.mem.eql(u8, command, "routes")) {
        const body = try admin_pages.renderRoutes(allocator, cfg);
        defer allocator.free(body);
        try sendAdminText(stream, body);
        return;
    }

    if (std.mem.eql(u8, command, "certs") or std.mem.eql(u8, command, "certificates")) {
        const body = try admin_pages.renderCerts(allocator, cfg, adminRuntimeView());
        defer allocator.free(body);
        try sendAdminText(stream, body);
        return;
    }

    if (std.mem.eql(u8, command, "metrics")) {
        const body = try metrics_mod.render(allocator, &server_metrics);
        defer allocator.free(body);
        try sendAdminText(stream, body);
        return;
    }

    try sendAdminText(stream, "ERROR unknown command\n");
}

fn handleAdminConnection(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
    setStreamTimeouts(stream, 1_000, 1_000) catch {};
    var buffer: [1024]u8 = undefined;
    const n = try streamRead(stream, &buffer);
    if (n == 0) return;
    try handleAdminCommand(stream, allocator, cfg, buffer[0..n]);
}

const AdminSocketContext = struct {
    io: std.Io,
    cfg: *ServerConfig,
    socket_path: []const u8,
};

fn unlinkUnixSocket(path: []const u8) void {
    if (builtin.os.tag == .windows) return;
    std.Io.Dir.deleteFileAbsolute(activeIo(), path) catch {};
}

fn serveAdminSocketTask(ctx: AdminSocketContext) void {
    bindThreadIo(ctx.io);
    unlinkUnixSocket(ctx.socket_path);

    const address = std.Io.net.UnixAddress.init(ctx.socket_path) catch |err| {
        std.debug.print("Admin socket path invalid: {s}: {}\n", .{ ctx.socket_path, err });
        return;
    };
    var server = address.listen(ctx.io, .{ .kernel_backlog = 16 }) catch |err| {
        std.debug.print("Admin socket listen failed: {s}: {}\n", .{ ctx.socket_path, err });
        return;
    };
    defer {
        server.deinit(ctx.io);
        unlinkUnixSocket(ctx.socket_path);
    }

    std.debug.print("Admin socket: {s}\n", .{ctx.socket_path});
    while (!shutdown_requested.load(.acquire)) {
        const conn = server.accept(ctx.io) catch |err| {
            if (shutdown_requested.load(.acquire)) break;
            std.debug.print("Admin socket accept failed: {}\n", .{err});
            ctx.io.sleep(.fromMilliseconds(50), .awake) catch {};
            continue;
        };
        handleAdminConnection(conn, std.heap.page_allocator, ctx.cfg) catch |err| {
            std.debug.print("Admin command failed: {}\n", .{err});
        };
        streamClose(conn);
    }
}

fn sendMethodNotAllowedWithAllow(stream: std.Io.net.Stream, allocator: std.mem.Allocator, allowed_methods: []const u8, close_connection: bool, is_head: bool) !void {
    const allow_header = try std.fmt.allocPrint(allocator, "Allow: {s}\r\n", .{allowed_methods});
    defer allocator.free(allow_header);
    try sendCoolErrorWithConnection(stream, allocator, 405, "Method Not Allowed", "That method is not supported for this endpoint.", close_connection, is_head, allow_header);
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
        try sendBadRequestForMethod(allocator, stream, "Invalid static file path.", close_connection, is_head);
        return;
    }

    const file_path = try std.fs.path.join(allocator, &.{ static_dir, rel_path });
    defer allocator.free(file_path);

    var stat = statRegularFile(io, file_path) catch |err| {
        if (err == error.NotDir or err == error.FileNotFound) {
            try sendNotFoundForMethod(allocator, stream, close_connection, is_head);
            return;
        }
        if (err == error.NotFile) {
            try sendNotFoundForMethod(allocator, stream, close_connection, is_head);
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
            is_head,
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
                try sendBadRequestForMethod(allocator, stream, "Invalid Range header.", close_connection, is_head);
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
        try sendBadRequestForMethod(allocator, stream, "Invalid ACME challenge path.", close_connection, is_head);
        return;
    }

    const file_path = try buildAcmeChallengeFilePath(allocator, webroot, token);
    defer allocator.free(file_path);

    const data = std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(64 * 1024)) catch |err| {
        if (err == error.StreamTooLong) {
            try sendCoolErrorWithConnection(stream, allocator, 413, "Payload Too Large", "ACME challenge file is too large.", close_connection, is_head, null);
            return;
        }
        if (err == error.NotDir or err == error.FileNotFound) {
            try sendNotFoundForMethod(allocator, stream, close_connection, is_head);
            return;
        }
        return err;
    };
    defer allocator.free(data);

    // ACME files are expected to be small; enforce strict plaintext response.
    if (data.len > 0 and std.mem.indexOfScalar(u8, data, 0) != null) {
        try sendNotFoundForMethod(allocator, stream, close_connection, is_head);
        return;
    }

    if (is_head) {
        try sendResponseNoBodyWithConnection(stream, 200, "OK", "text/plain; charset=utf-8", data.len, close_connection);
        return;
    }
    try sendResponseWithConnection(stream, 200, "OK", "text/plain; charset=utf-8", data, close_connection);
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

fn handleTlsClientHelloProbe(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    prefill: []const u8,
    process_env: *const std.process.Environ.Map,
) anyerror!void {
    const record = try native_tls.readClientHelloRecord(stream, allocator, prefill, rawStreamRead);
    defer allocator.free(record);
    var info = tls_client_hello.parse(allocator, record) catch |err| {
        std.debug.print("TLS ClientHello parse failed before native TLS termination: {}\n", .{err});
        try native_tls.sendFatalAlert(stream, native_tls.ALERT_HANDSHAKE_FAILURE, rawStreamWriteAll);
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

    var established = native_tls.establishTls13(stream, allocator, cfg, record, info, activeIo(), rawStreamRead, rawStreamWriteAll) catch |err| {
        std.debug.print("Native TLS 1.3 handshake failed: {}\n", .{err});
        const alert = switch (err) {
            error.NoApplicationProtocol => native_tls.ALERT_NO_APPLICATION_PROTOCOL,
            else => native_tls.ALERT_HANDSHAKE_FAILURE,
        };
        try native_tls.sendFatalAlert(stream, alert, rawStreamWriteAll);
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

fn sendHttp2Response(stream: std.Io.net.Stream, allocator: std.mem.Allocator, stream_id: u32, response: H2BufferedResponse, is_head: bool) !void {
    var header_block = std.ArrayList(u8).empty;
    defer header_block.deinit(allocator);

    const prepared = try prepareResponseBody(allocator, response.status_code, response.content_type, response.body, is_head, null, response.headers);
    defer prepared.deinit(allocator);

    try h2_native.appendStatus(allocator, &header_block, response.status_code);
    try h2_native.appendHeaderIndexedName(allocator, &header_block, 54, SERVER_HEADER);
    try h2_native.appendHeaderIndexedName(allocator, &header_block, 31, response.content_type);

    var len_buf: [32]u8 = undefined;
    const body_len = if (http_response.canSendBody(response.status_code, is_head)) prepared.body.len else 0;
    const len_text = try std.fmt.bufPrint(&len_buf, "{d}", .{body_len});
    try h2_native.appendHeaderIndexedName(allocator, &header_block, 28, len_text);
    if (current_request_id.len > 0) {
        try h2_support.appendHeader(allocator, &header_block, "x-request-id", current_request_id);
    }

    for (response.headers) |header| {
        if (h2_support.isSkippedResponseHeader(header.name)) continue;
        try h2_support.appendHeader(allocator, &header_block, header.name, header.value);
    }
    if (prepared.encoding) |encoding| {
        try h2_support.appendHeader(allocator, &header_block, "content-encoding", encoding);
        try h2_support.appendHeader(allocator, &header_block, "vary", "Accept-Encoding");
    }
    for (current_response_headers) |header| {
        if (h2_support.isSkippedResponseHeader(header.name)) continue;
        if (std.ascii.eqlIgnoreCase(header.name, "x-request-id")) continue;
        try h2_support.appendHeader(allocator, &header_block, header.name, header.value);
    }

    const header_flags = h2_native.FLAG_END_HEADERS | if (body_len == 0) h2_native.FLAG_END_STREAM else @as(u8, 0);
    try h2_support.sendFrame(stream, h2_native.FRAME_HEADERS, header_flags, stream_id, header_block.items, streamWriteAll);

    if (body_len > 0) {
        var sent: usize = 0;
        while (sent < body_len) {
            const chunk_len = @min(@as(usize, 16 * 1024), body_len - sent);
            const flags = if (sent + chunk_len == body_len) h2_native.FLAG_END_STREAM else @as(u8, 0);
            try h2_support.sendFrame(stream, h2_native.FRAME_DATA, flags, stream_id, prepared.body[sent .. sent + chunk_len], streamWriteAll);
            sent += chunk_len;
        }
    }

    recordResponseSent(response.status_code, body_len);
}

fn h2CoolErrorResponse(allocator: std.mem.Allocator, status_code: u16, status_text: []const u8, detail: []const u8) !H2BufferedResponse {
    const body = try renderCoolErrorPage(allocator, status_code, status_text, detail);
    return .{ .status_code = status_code, .content_type = "text/html; charset=utf-8", .body = body };
}

fn h2DomainCustomNotFoundResponse(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    domain: ?*const DomainConfig,
) !?H2BufferedResponse {
    if (try readDomainCustomErrorDocument(io, allocator, cfg, domain, 404)) |body| {
        return .{ .status_code = 404, .content_type = "text/html; charset=utf-8", .body = body };
    }
    return null;
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
    const etag = try makeStaticEtag(allocator, stat);
    const headers = try allocator.alloc(h2_native.Header, 5);
    headers[0] = .{ .name = "accept-ranges", .value = "bytes" };
    headers[1] = .{ .name = "etag", .value = etag };
    headers[2] = .{ .name = "cache-control", .value = "public, max-age=60" };
    headers[3] = .{ .name = "cache-status", .value = "Layerline; hit; ttl=60; detail=\"static-file\"" };
    headers[4] = .{ .name = "vary", .value = "Accept-Encoding" };

    server_metrics.staticBodySent(data.len, .buffered);
    return .{ .status_code = 200, .content_type = contentTypeFromPath(rel_path), .body = data, .headers = headers };
}

fn readAcmeChallengeForHttp2(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig, token: []const u8) !H2BufferedResponse {
    if (token.len == 0 or std.mem.indexOf(u8, token, "..") != null or std.mem.indexOfScalar(u8, token, '\\') != null or std.mem.indexOfScalar(u8, token, '/') != null) {
        return h2CoolErrorResponse(allocator, 400, "Bad Request", "Invalid ACME challenge path.");
    }

    const file_path = try buildAcmeChallengeFilePath(allocator, cfg.letsencrypt_webroot, token);
    defer allocator.free(file_path);
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
    if (current_request_id.len > 0) try out.print(allocator, "X-Request-Id: {s}\r\n", .{current_request_id});
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

fn fetchHttp2UpstreamResponse(allocator: std.mem.Allocator, upstream: *UpstreamConfig, req: HttpRequest, cfg: *const ServerConfig) !H2BufferedResponse {
    if (upstream.https) return error.UnsupportedUpstreamScheme;

    const upstream_label = try std.fmt.allocPrint(
        allocator,
        "{s}://{s}:{d}{s}",
        .{ if (upstream.https) "https" else "http", upstream.host, upstream.port, upstream.base_path },
    );
    accessLogSetUpstream(upstream_label);

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
        try h2_support.decodeChunkedBuffer(allocator, body_tail)
    else if (framing.content_length) |content_length| blk: {
        if (body_tail.len < content_length) return error.BadGateway;
        break :blk try allocator.dupe(u8, body_tail[0..content_length]);
    } else try allocator.dupe(u8, body_tail);

    const content_type = if (findHeaderValue(response_headers, "Content-Type")) |ctype|
        try allocator.dupe(u8, trimValue(ctype))
    else
        "application/octet-stream";
    const headers = try h2_support.collectUpstreamHeaders(allocator, response_headers);
    return .{ .status_code = status_code, .content_type = content_type, .body = body, .headers = headers };
}

fn fetchHttp2UpstreamPoolResponse(allocator: std.mem.Allocator, pool: *UpstreamPoolConfig, policy: UpstreamPoolPolicy, req: HttpRequest, cfg: *const ServerConfig) !H2BufferedResponse {
    if (pool.targets.items.len == 0) return h2CoolErrorResponse(allocator, 502, "Bad Gateway", "Proxy upstream pool is empty.");

    const attempt_limit = upstreamAttemptLimit(pool, cfg.upstream_retries);
    const now_ms = upstreamNowMs();
    const start_ticket = upstreamStartTicket(pool, policy, now_ms, request_mod.upstreamHashInput(req), cfg);
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

    if (findDomainRedirectRule(domain, req.path)) |redirect| {
        accessLogSetHandler("domain_redirect");
        return buildHttp2RedirectResponse(allocator, redirect, req);
    }
    if (findRedirectRule(cfg, req.path)) |redirect| {
        accessLogSetHandler("redirect");
        return buildHttp2RedirectResponse(allocator, redirect, req);
    }

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
        accessLogSetHandler("acme_challenge");
        return readAcmeChallengeForHttp2(io, allocator, cfg, req.path["/.well-known/acme-challenge/".len..]);
    }

    if (domain != null) {
        if (domainUpstreamMutable(cfg, domain)) |pool| {
            accessLogSetHandler("domain_proxy");
            return fetchHttp2UpstreamPoolResponse(allocator, pool, domainUpstreamPolicy(cfg, domain), req, cfg);
        }
    }

    if (std.mem.eql(u8, req.method, "GET") or is_head) {
        if (std.mem.eql(u8, req.path, "/favicon.svg") or std.mem.eql(u8, req.path, "/icon.svg")) {
            accessLogSetHandler("builtin_asset");
            return h2_support.textResponse(200, "image/svg+xml", SERVER_ICON_SVG);
        }
        if (std.mem.eql(u8, req.path, "/") and domainServeStaticRoot(cfg, domain)) {
            accessLogSetHandler("static_root");
            return readStaticFileForHttp2(io, allocator, domainStaticDir(cfg, domain), domainIndexFile(cfg, domain), cfg.max_static_file_bytes);
        }
        if (std.mem.eql(u8, req.path, "/")) {
            accessLogSetHandler("builtin_root");
            return h2_support.textResponse(200, "text/html; charset=utf-8", H2_DEFAULT_PAGE);
        }
        if (std.mem.eql(u8, req.path, "/health")) {
            accessLogSetHandler("health");
            return h2_support.textResponse(200, "text/plain; charset=utf-8", "ok\n");
        }
        if (std.mem.eql(u8, req.path, "/metrics")) {
            accessLogSetHandler("metrics");
            return .{ .status_code = 200, .content_type = "text/plain; version=0.0.4; charset=utf-8", .body = try metrics_mod.render(allocator, &server_metrics) };
        }
        if (std.mem.eql(u8, req.path, "/time")) {
            accessLogSetHandler("time");
            return .{ .status_code = 200, .content_type = "application/json; charset=utf-8", .body = try std.fmt.allocPrint(allocator, "{{\"time\":{}}}\n", .{std.Io.Timestamp.now(io, .real).toSeconds()}) };
        }
        if (std.mem.eql(u8, req.path, "/api/echo")) {
            accessLogSetHandler("api_echo");
            if (findQueryValue(req.query, "msg")) |msg| {
                return .{ .status_code = 200, .content_type = "application/json; charset=utf-8", .body = try std.fmt.allocPrint(allocator, "{{\"msg\":\"{s}\"}}\n", .{msg}) };
            }
            return h2_support.textResponse(200, "text/plain; charset=utf-8", "try /api/echo?msg=your-text\n");
        }
        if (std.mem.startsWith(u8, req.path, "/static/")) {
            accessLogSetHandler("static");
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
            accessLogSetHandler("static_root");
            const response = try readStaticFileForHttp2(io, allocator, domainStaticDir(cfg, domain), rel, cfg.max_static_file_bytes);
            if (response.status_code == 404) {
                if (try h2DomainCustomNotFoundResponse(io, allocator, cfg, domain)) |custom| return custom;
            }
            return response;
        }
        if (domainUpstreamMutable(cfg, domain)) |pool| {
            accessLogSetHandler("domain_proxy");
            return fetchHttp2UpstreamPoolResponse(allocator, pool, domainUpstreamPolicy(cfg, domain), req, cfg);
        }
        accessLogSetHandler("not_found");
        if (try h2DomainCustomNotFoundResponse(io, allocator, cfg, domain)) |custom| return custom;
        return h2CoolErrorResponse(allocator, 404, "Not Found", "The requested resource was not found on this server.");
    }

    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, req.path, "/api/echo")) {
        accessLogSetHandler("api_echo");
        return .{ .status_code = 200, .content_type = "text/plain; charset=utf-8", .body = req.body };
    }
    if (std.mem.eql(u8, req.method, "OPTIONS")) {
        accessLogSetHandler("options");
        const headers = try allocator.alloc(h2_native.Header, 1);
        headers[0] = .{ .name = "allow", .value = "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS" };
        return .{ .status_code = 204, .content_type = "text/plain; charset=utf-8", .body = "", .headers = headers };
    }
    if (domainUpstreamMutable(cfg, domain)) |pool| {
        accessLogSetHandler("domain_proxy");
        return fetchHttp2UpstreamPoolResponse(allocator, pool, domainUpstreamPolicy(cfg, domain), req, cfg);
    }
    accessLogSetHandler("not_implemented");
    return h2CoolErrorResponse(allocator, 501, "Not Implemented", "This server has not implemented that HTTP/2 behavior yet.");
}

fn buildHttp2RouteResponse(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig, domain: ?*DomainConfig, route: *RouteConfig, req: HttpRequest) !H2BufferedResponse {
    const is_head = std.mem.eql(u8, req.method, "HEAD");
    switch (route.handler) {
        .static => {
            accessLogSetHandler("route_static");
            if (std.mem.eql(u8, req.method, "OPTIONS")) {
                const headers = try allocator.alloc(h2_native.Header, 1);
                headers[0] = .{ .name = "allow", .value = "GET,HEAD,OPTIONS" };
                return .{ .status_code = 204, .content_type = "text/plain; charset=utf-8", .body = "", .headers = headers };
            }
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
            accessLogSetHandler("route_proxy");
            const pool = if (route.upstream) |*route_pool|
                route_pool
            else
                domainUpstreamMutable(cfg, domain) orelse return h2CoolErrorResponse(allocator, 502, "Bad Gateway", "Route proxy upstream is not configured.");
            return fetchHttp2UpstreamPoolResponse(allocator, pool, routeUpstreamPolicy(cfg, domain, route), req, cfg);
        },
        .php => {
            accessLogSetHandler("route_php");
            if (std.mem.eql(u8, req.method, "OPTIONS")) {
                const headers = try allocator.alloc(h2_native.Header, 1);
                headers[0] = .{ .name = "allow", .value = "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS" };
                return .{ .status_code = 204, .content_type = "text/plain; charset=utf-8", .body = "", .headers = headers };
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

fn sendCompletedHttp2Request(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    process_env: *const std.process.Environ.Map,
    stream_id: u32,
    req: HttpRequest,
) !void {
    current_request_headers = req.headers;
    current_compression_policy = compressionPolicyFromConfig(cfg);
    defer {
        current_request_headers = "";
        current_request_id = "";
        current_compression_policy = .disabled;
        current_response_headers = &.{};
    }
    const request_id = try request_id_generator.resolve(io, allocator, req.headers);
    current_request_id = request_id;

    var access_ctx = access_log_mod.Context{
        .enabled = cfg.access_log_enabled,
        .sink = cfg.access_log_path,
        .method = req.method,
        .path = req.path,
        .query = req.query,
        .protocol = req.version,
        .host = findHeaderValue(req.headers, "Host") orelse "",
        .request_id = request_id,
        .start_ms = std.Io.Timestamp.now(io, .awake).toMilliseconds(),
    };
    current_access_log = &access_ctx;
    defer current_access_log = null;

    server_metrics.requestStarted();
    accessLogSetHandler("h2");
    const response = buildHttp2ResponseForRequest(io, allocator, cfg, req, process_env) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => blk: {
            accessLogSetError(@errorName(err));
            break :blk try h2CoolErrorResponse(allocator, 500, "Internal Server Error", "Internal server error while routing HTTP/2 request.");
        },
    };
    try sendHttp2Response(stream, allocator, stream_id, response, std.mem.eql(u8, req.method, "HEAD"));
    if (!access_ctx.logged) emitAccessLog(0, 0);
}

fn handleHttp2HeadersFrame(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    state_allocator: std.mem.Allocator,
    hpack_decoder: *h2_native.HpackDecoder,
    cfg: *ServerConfig,
    process_env: *const std.process.Environ.Map,
    states: *std.ArrayList(H2RequestState),
    frame: H2Frame,
) !void {
    current_response_headers = &.{};

    if (frame.header.stream_id == 0 or (frame.header.flags & h2_native.FLAG_END_HEADERS) == 0) {
        if (frame.header.stream_id != 0) try h2_support.sendRst(stream, frame.header.stream_id, HTTP2_ERROR_PROTOCOL, streamWriteAll);
        return;
    }
    if (h2_support.findRequestState(states, frame.header.stream_id) != null) {
        try h2_support.sendRst(stream, frame.header.stream_id, HTTP2_ERROR_PROTOCOL, streamWriteAll);
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

    const req = h2_support.parseRequest(allocator, &decoded) catch {
        const response = try h2CoolErrorResponse(allocator, 400, "Bad Request", "Missing required HTTP/2 pseudo-headers.");
        try sendHttp2Response(stream, allocator, frame.header.stream_id, response, false);
        return;
    };

    const expected_content_length = h2_support.parseRequestContentLength(req.headers) catch {
        const response = try h2CoolErrorResponse(allocator, 400, "Bad Request", "Invalid HTTP/2 Content-Length header.");
        try sendHttp2Response(stream, allocator, frame.header.stream_id, response, false);
        return;
    };

    if ((frame.header.flags & h2_native.FLAG_END_STREAM) != 0) {
        if (expected_content_length) |content_length| {
            if (content_length != 0) {
                const response = try h2CoolErrorResponse(allocator, 400, "Bad Request", "HTTP/2 Content-Length did not match the received request body.");
                try sendHttp2Response(stream, allocator, frame.header.stream_id, response, false);
                return;
            }
        }
        try sendCompletedHttp2Request(io, stream, allocator, cfg, process_env, frame.header.stream_id, req);
        return;
    }

    if (expected_content_length) |content_length| {
        if (content_length > cfg.max_body_bytes) {
            const response = try h2CoolErrorResponse(allocator, 413, "Payload Too Large", "Request body exceeds configured limit.");
            try sendHttp2Response(stream, allocator, frame.header.stream_id, response, false);
            return;
        }
    }
    if (states.items.len >= HTTP2_MAX_PENDING_BODY_STREAMS) {
        try h2_support.sendRst(stream, frame.header.stream_id, HTTP2_ERROR_REFUSED_STREAM, streamWriteAll);
        return;
    }

    var pending = H2RequestState{
        .stream_id = frame.header.stream_id,
        .req = try h2_support.cloneRequest(state_allocator, req),
        .expected_content_length = expected_content_length,
    };
    errdefer pending.deinit(state_allocator);
    try states.append(state_allocator, pending);
}

fn handleHttp2DataFrame(
    io: std.Io,
    stream: std.Io.net.Stream,
    scratch_allocator: std.mem.Allocator,
    state_allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    process_env: *const std.process.Environ.Map,
    states: *std.ArrayList(H2RequestState),
    frame: H2Frame,
) !void {
    if (frame.header.stream_id == 0) return error.BadRequest;

    const state_index = h2_support.findRequestState(states, frame.header.stream_id) orelse {
        try h2_support.sendRst(stream, frame.header.stream_id, HTTP2_ERROR_STREAM_CLOSED, streamWriteAll);
        return;
    };
    const state = &states.items[state_index];

    var offset: usize = 0;
    var pad_len: usize = 0;
    if ((frame.header.flags & h2_native.FLAG_PADDED) != 0) {
        if (frame.payload.len == 0) return error.BadRequest;
        pad_len = frame.payload[0];
        offset = 1;
    }
    if (frame.payload.len < offset + pad_len) return error.BadRequest;
    const data = frame.payload[offset .. frame.payload.len - pad_len];

    if (data.len > cfg.max_body_bytes or state.body.items.len > cfg.max_body_bytes - data.len) {
        h2_support.removeRequestState(states, state_allocator, state_index);
        const response = try h2CoolErrorResponse(scratch_allocator, 413, "Payload Too Large", "Request body exceeds configured limit.");
        try sendHttp2Response(stream, scratch_allocator, frame.header.stream_id, response, false);
        return;
    }
    if (state.expected_content_length) |content_length| {
        if (state.body.items.len + data.len > content_length) {
            h2_support.removeRequestState(states, state_allocator, state_index);
            const response = try h2CoolErrorResponse(scratch_allocator, 400, "Bad Request", "HTTP/2 Content-Length did not match the received request body.");
            try sendHttp2Response(stream, scratch_allocator, frame.header.stream_id, response, false);
            return;
        }
    }

    if (data.len > 0) try state.body.appendSlice(state_allocator, data);
    try h2_support.sendWindowUpdate(stream, 0, frame.payload.len, streamWriteAll);
    try h2_support.sendWindowUpdate(stream, frame.header.stream_id, frame.payload.len, streamWriteAll);

    if ((frame.header.flags & h2_native.FLAG_END_STREAM) == 0) return;
    if (state.expected_content_length) |content_length| {
        if (state.body.items.len != content_length) {
            h2_support.removeRequestState(states, state_allocator, state_index);
            const response = try h2CoolErrorResponse(scratch_allocator, 400, "Bad Request", "HTTP/2 Content-Length did not match the received request body.");
            try sendHttp2Response(stream, scratch_allocator, frame.header.stream_id, response, false);
            return;
        }
    }

    state.req.body = state.body.items;
    try sendCompletedHttp2Request(io, stream, scratch_allocator, cfg, process_env, frame.header.stream_id, state.req);
    h2_support.removeRequestState(states, state_allocator, state_index);
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
    var body_states = std.ArrayList(H2RequestState).empty;
    defer {
        for (body_states.items) |*state| state.deinit(allocator);
        body_states.deinit(allocator);
    }
    var requests_seen: usize = 0;
    var last_stream_id: u32 = 0;

    while (true) {
        if (shutdown_requested.load(.acquire)) {
            try h2_support.sendGoaway(stream, last_stream_id, HTTP2_ERROR_NO_ERROR, streamWriteAll);
            return;
        }

        _ = arena.reset(.retain_capacity);
        const req_alloc = arena.allocator();
        const frame = h2_support.readFrame(reader, req_alloc, @max(cfg.max_request_bytes, cfg.max_body_bytes)) catch |err| switch (err) {
            error.ConnectionClosed => return,
            error.RequestTimeout => return,
            else => return err,
        };

        switch (frame.header.frame_type) {
            h2_native.FRAME_SETTINGS => {
                if ((frame.header.flags & h2_native.FLAG_ACK) == 0) {
                    try h2_support.sendFrame(stream, h2_native.FRAME_SETTINGS, h2_native.FLAG_ACK, 0, "", streamWriteAll);
                }
            },
            h2_native.FRAME_PING => {
                if (frame.payload.len == 8 and (frame.header.flags & h2_native.FLAG_ACK) == 0) {
                    try h2_support.sendFrame(stream, h2_native.FRAME_PING, h2_native.FLAG_ACK, 0, frame.payload, streamWriteAll);
                }
            },
            h2_native.FRAME_HEADERS => {
                if (frame.header.stream_id > last_stream_id) last_stream_id = frame.header.stream_id;
                if (cfg.max_requests_per_connection > 0 and requests_seen >= cfg.max_requests_per_connection) {
                    try h2_support.sendRst(stream, frame.header.stream_id, HTTP2_ERROR_REFUSED_STREAM, streamWriteAll);
                    continue;
                }
                try handleHttp2HeadersFrame(io, stream, req_alloc, allocator, &hpack_decoder, cfg, process_env, &body_states, frame);
                requests_seen += 1;
            },
            h2_native.FRAME_DATA => {
                try handleHttp2DataFrame(io, stream, req_alloc, allocator, cfg, process_env, &body_states, frame);
            },
            h2_native.FRAME_GOAWAY => return,
            h2_native.FRAME_WINDOW_UPDATE => {},
            else => {},
        }

        if (cfg.max_requests_per_connection > 0 and requests_seen >= cfg.max_requests_per_connection and body_states.items.len == 0) {
            try h2_support.sendGoaway(stream, last_stream_id, HTTP2_ERROR_NO_ERROR, streamWriteAll);
            return;
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
        .read = streamRead,
    };
    h2_support.readClientPreface(&reader) catch {
        try sendCoolErrorWithConnection(stream, allocator, 400, "Bad Request", "Invalid HTTP/2 connection preface.", true, false, null);
        return;
    };

    try h2_support.sendFrame(stream, h2_native.FRAME_SETTINGS, 0, 0, "", streamWriteAll);
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
            "Upgrade: h2c\r\n",
    );
    try streamWriteRequestIdHeader(stream);
    try streamWriteAll(stream, "\r\n");
    recordResponseSent(101, 0);

    try h2_support.sendFrame(stream, h2_native.FRAME_SETTINGS, 0, 0, "", streamWriteAll);

    var reader = H2PendingReader{
        .stream = stream,
        .pending = req.h2c_upgrade_tail,
        .read = streamRead,
    };
    h2_support.readClientPreface(&reader) catch {
        try h2_support.sendFrame(stream, h2_native.FRAME_GOAWAY, 0, 0, "\x00\x00\x00\x00\x00\x00\x00\x01", streamWriteAll);
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

fn isHttpUpgradeRequest(req: HttpRequest) bool {
    return proxy_utils.isHttpUpgradeHeaders(req.headers);
}

const UpstreamConnectionLease = struct {
    stream: std.Io.net.Stream,
    requests_served: usize,
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
    if (current_request_id.len > 0) try out.print(allocator, "X-Request-Id: {s}\r\n", .{current_request_id});

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
    const is_head = std.mem.eql(u8, req.method, "HEAD");
    if (pool.targets.items.len == 0) {
        try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "Proxy upstream pool is empty.", true, is_head, null);
        return;
    }

    const attempt_limit = upstreamAttemptLimit(pool, cfg.upstream_retries);
    const now_ms = upstreamNowMs();
    const start_ticket = upstreamStartTicket(pool, policy, now_ms, request_mod.upstreamHashInput(req), cfg);
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
        const upstream_label = try std.fmt.allocPrint(
            allocator,
            "{s}://{s}:{d}{s}",
            .{ if (upstream.https) "https" else "http", upstream.host, upstream.port, upstream.base_path },
        );
        accessLogSetUpstream(upstream_label);
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
        try sendCoolErrorWithConnection(stream, allocator, 503, "Service Unavailable", "All configured upstream targets are unavailable or limited by circuit breaker recovery.", true, is_head, null);
        return;
    }

    if (last_error) |err| switch (err) {
        error.RequestTimeout => {
            try sendCoolErrorWithConnection(stream, allocator, 504, "Gateway Timeout", "All configured upstream attempts timed out.", true, is_head, null);
            return;
        },
        error.UnsupportedUpstreamScheme => {
            try sendCoolErrorWithConnection(stream, allocator, 501, "Not Implemented", "HTTPS upstream is not yet supported in this single-file server path. Use HTTPS reverse proxy in front of this binary.", true, is_head, null);
            return;
        },
        else => {},
    };

    try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "All configured upstream attempts failed.", true, is_head, null);
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
            if (name.len == 0 or value.len == 0 or isSkippedCgiResponseHeader(name) or h2_support.isSkippedResponseHeader(name)) continue;
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
    try fastcgi.writeRecord(conn, FASTCGI_BEGIN_REQUEST, request_id, &begin_body, streamWriteAll);

    const params = try fastcgi.buildParams(allocator, .{
        .server_header = SERVER_HEADER,
        .current_request_id = current_request_id,
        .server_host = cfg.host,
        .server_port = cfg.port,
        .method = req.method,
        .path = req.path,
        .query = req.query,
        .version = req.version,
        .headers = req.headers,
        .body_len = req.body.len,
    }, php_root, script_path, script_name, path_info);
    defer allocator.free(params);
    try fastcgi.writeRecord(conn, FASTCGI_PARAMS, request_id, params, streamWriteAll);
    try fastcgi.writeRecord(conn, FASTCGI_PARAMS, request_id, "", streamWriteAll);
    if (req.body.len > 0) try fastcgi.writeRecord(conn, FASTCGI_STDIN, request_id, req.body, streamWriteAll);
    try fastcgi.writeRecord(conn, FASTCGI_STDIN, request_id, "", streamWriteAll);

    const result = try fastcgi.readResponse(allocator, conn, request_id, cfg.max_php_output_bytes, DEFAULT_MAX_PHP_FASTCGI_STDERR_BYTES, streamRead);
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
            try sendCoolErrorWithConnection(stream, allocator, 500, "Server Error", "PHP FastCGI endpoint is invalid.", close_connection, is_head, null);
            return;
        },
        error.FastcgiConnectFailed => {
            std.debug.print("PHP FastCGI connect failed for {s}\n", .{php_fastcgi});
            try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "PHP FastCGI worker could not be reached.", close_connection, is_head, null);
            return;
        },
        error.StreamTooLong => {
            try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "PHP FastCGI response exceeded max_php_output_bytes.", close_connection, is_head, null);
            return;
        },
        error.FastcgiProtocolFailed => {
            try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "PHP FastCGI request did not complete cleanly.", close_connection, is_head, null);
            return;
        },
        error.FastcgiAppFailed => {
            try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "PHP FastCGI app returned a non-zero status.", close_connection, is_head, null);
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
        try sendNotFoundForMethod(allocator, stream, close_connection, is_head);
        return;
    }

    const script_path = try std.fs.path.join(allocator, &.{ php_root, rel_path });
    defer allocator.free(script_path);

    const script_stat = std.Io.Dir.cwd().statFile(io, script_path, .{}) catch {
        try sendNotFoundForMethod(allocator, stream, close_connection, is_head);
        return;
    };
    if (script_stat.kind != .file) {
        try sendNotFoundForMethod(allocator, stream, close_connection, is_head);
        return;
    }

    if (php_fastcgi) |endpoint| {
        if (!disablesOptionalUrl(endpoint)) {
            try handlePhpFastcgi(stream, allocator, cfg, req, php_root, endpoint, script_path, script_name, path_info, timeout_ms, close_connection, is_head);
            return;
        }
    }

    if (php_binary.len == 0) {
        try sendCoolErrorWithConnection(stream, allocator, 500, "Server Error", "PHP support is not configured for this server.", close_connection, is_head, null);
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
    if (current_request_id.len > 0) try child_env.put("HTTP_X_REQUEST_ID", current_request_id);

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
            is_head,
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
                    is_head,
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
                    is_head,
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
                is_head,
                null,
            );
            return;
        },
    }

    try sendPhpOutput(stream, allocator, output, close_connection, is_head);
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
            accessLogSetHandler("route_static");
            if (!(std.mem.eql(u8, req.method, "GET") or is_head)) {
                try sendMethodNotAllowedWithAllow(stream, allocator, "GET,HEAD,OPTIONS", close_connection, is_head);
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
            accessLogSetHandler("route_php");
            if (std.mem.eql(u8, req.path, "/test.php") and !(route.php_info_page orelse domainPhpInfoPage(cfg, domain))) {
                try sendNotFoundForMethod(allocator, stream, close_connection, is_head);
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
            accessLogSetHandler("route_proxy");
            const pool = if (route.upstream) |*route_pool|
                route_pool
            else
                domainUpstreamMutable(cfg, domain) orelse {
                    try sendCoolErrorWithConnection(stream, allocator, 502, "Bad Gateway", "Route proxy upstream is not configured.", close_connection, is_head, null);
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
        .config_path = DEFAULT_CONFIG_PATH,
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
        .letsencrypt_webroot = "public",
        .letsencrypt_certbot = "certbot",
        .letsencrypt_staging = false,
        .letsencrypt_renew = true,
        .letsencrypt_renew_interval_ms = DEFAULT_LETSENCRYPT_RENEW_INTERVAL_MS,
        .http_redirect_enabled = false,
        .http_redirect_port = 80,
        .http_redirect_https_port = 443,
        .http_redirect_status = 308,
        .h2_upstream = null,
        .http3_enabled = false,
        .http3_port = 8443,
        .admin_enabled = false,
        .admin_socket_path = DEFAULT_ADMIN_SOCKET_PATH,
        .admin_ui_enabled = false,
        .admin_ui_path = DEFAULT_ADMIN_UI_PATH,
        .admin_credentials_path = DEFAULT_ADMIN_CREDENTIALS_PATH,
        .access_log_enabled = false,
        .access_log_path = DEFAULT_ACCESS_LOG_PATH,
        .compression_enabled = false,
        .gzip_enabled = true,
        .compression_min_bytes = DEFAULT_COMPRESSION_MIN_BYTES,
        .compression_max_bytes = DEFAULT_COMPRESSION_MAX_BYTES,
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
    try applyConfigLine(&cfg, allocator, "compression", "true");
    try applyConfigLine(&cfg, allocator, "compression_min_bytes", "128");
    try applyConfigLine(&cfg, allocator, "compression_max_bytes", "4096");
    try applyConfigLine(&cfg, allocator, "admin_socket", "/tmp/layerline-test-admin.sock");
    try applyConfigLine(&cfg, allocator, "admin_ui", "true");
    try applyConfigLine(&cfg, allocator, "admin_ui_path", "/_test/admin");
    try applyConfigLine(&cfg, allocator, "admin_credentials_path", "/tmp/layerline-test-admin.creds");
    try applyConfigLine(&cfg, allocator, "access_log", "/tmp/layerline-access.log");
    try applyConfigLine(&cfg, allocator, "letsencrypt_renew", "false");
    try applyConfigLine(&cfg, allocator, "letsencrypt_renew_interval_ms", "7200000");
    try applyConfigLine(&cfg, allocator, "http_redirect", "true");
    try applyConfigLine(&cfg, allocator, "http_redirect_port", "18080");
    try applyConfigLine(&cfg, allocator, "http_redirect_https_port", "18443");
    try applyConfigLine(&cfg, allocator, "http_redirect_status", "308");
    try applyConfigLine(&cfg, allocator, "upstream_health_check", "true");
    try applyConfigLine(&cfg, allocator, "upstream_health_check_path", "/ready");
    try applyConfigLine(&cfg, allocator, "upstream_health_check_interval_ms", "2500");
    try applyConfigLine(&cfg, allocator, "upstream_health_check_timeout_ms", "750");
    try applyConfigLine(&cfg, allocator, "upstream_circuit_half_open_max", "2");
    try applyConfigLine(&cfg, allocator, "upstream_slow_start_ms", "6000");
    try applyConfigLine(&cfg, allocator, "header", "X-Global-Policy: one");
    try applyConfigLine(&cfg, allocator, "cache_control", "public, max-age=60");
    try applyConfigLine(&cfg, allocator, "route_header.assets", "X-Route-Policy: assets");
    try applyConfigLine(&cfg, allocator, "route_cache_control.assets", "public, max-age=31536000, immutable");
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
    try std.testing.expect(cfg.compression_enabled);
    try std.testing.expect(cfg.gzip_enabled);
    try std.testing.expectEqual(@as(usize, 128), cfg.compression_min_bytes);
    try std.testing.expectEqual(@as(usize, 4096), cfg.compression_max_bytes);
    try std.testing.expect(cfg.admin_enabled);
    try std.testing.expectEqualStrings("/tmp/layerline-test-admin.sock", cfg.admin_socket_path.?);
    try std.testing.expect(cfg.admin_ui_enabled);
    try std.testing.expectEqualStrings("/_test/admin", cfg.admin_ui_path);
    try std.testing.expectEqualStrings("/tmp/layerline-test-admin.creds", cfg.admin_credentials_path);
    try std.testing.expect(cfg.access_log_enabled);
    try std.testing.expectEqualStrings("/tmp/layerline-access.log", cfg.access_log_path);
    try std.testing.expect(!cfg.letsencrypt_renew);
    try std.testing.expectEqual(@as(u32, 7200000), cfg.letsencrypt_renew_interval_ms);
    try std.testing.expect(cfg.http_redirect_enabled);
    try std.testing.expectEqual(@as(u16, 18080), cfg.http_redirect_port);
    try std.testing.expectEqual(@as(u16, 18443), cfg.http_redirect_https_port);
    try std.testing.expectEqual(@as(u16, 308), cfg.http_redirect_status);
    try std.testing.expectEqualStrings("public", certbotWebrootFromAcmeConfig("public/.well-known/acme-challenge"));
    const acme_path = try buildAcmeChallengeFilePath(allocator, "public", "token-123");
    try std.testing.expectEqualStrings("public/.well-known/acme-challenge/token-123", acme_path);
    const redirect_req = HttpRequest{
        .method = "GET",
        .path = "/docs",
        .query = "q=1",
        .headers = "Host: example.com:18080\r\n",
        .version = "HTTP/1.1",
        .body = "",
        .close_connection = true,
    };
    const redirect_location = try buildHttpsRedirectLocation(allocator, &cfg, redirect_req);
    try std.testing.expectEqualStrings("https://example.com:18443/docs?q=1", redirect_location);
    const bad_redirect_req = HttpRequest{
        .method = "GET",
        .path = "/docs",
        .query = "",
        .headers = "Host: example.com:bad\r\n",
        .version = "HTTP/1.1",
        .body = "",
        .close_connection = true,
    };
    try std.testing.expectError(error.InvalidRedirectHost, buildHttpsRedirectLocation(allocator, &cfg, bad_redirect_req));
    normalizeConfig(&cfg);
    try std.testing.expectEqual(@as(usize, DEFAULT_COMPRESSION_WORKER_STACK_BYTES), cfg.worker_stack_size);
    try std.testing.expect(cfg.upstream_health_check_enabled);
    try std.testing.expectEqualStrings("/ready", cfg.upstream_health_check_path);
    try std.testing.expectEqual(@as(u32, 2500), cfg.upstream_health_check_interval_ms);
    try std.testing.expectEqual(@as(u32, 750), cfg.upstream_health_check_timeout_ms);
    try std.testing.expect(cfg.upstream_circuit_breaker_enabled);
    try std.testing.expectEqual(@as(usize, 2), cfg.upstream_circuit_half_open_max);
    try std.testing.expectEqual(@as(u32, 6000), cfg.upstream_slow_start_ms);
    try std.testing.expectEqual(@as(usize, 2), cfg.response_headers.items.len);
    try std.testing.expectEqual(@as(usize, 2), findNamedRoute(&cfg, "/assets/hello.txt").?.response_headers.items.len);
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
    try applyConfigLine(&cfg, allocator, "server_cache_control.site", "private, max-age=30");
    try setDomainRouteLine(&cfg, allocator, "site", "site-assets /assets/* static");
    try setDomainRouteLine(&cfg, allocator, "site", "site-api /api/* proxy");
    try applyConfigLine(&cfg, allocator, "server_route_header.site.site-api", "X-Api-Policy: route");
    try applyConfigLine(&cfg, allocator, "server_route_cache_control.site.site-api", "no-store");
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
    try std.testing.expectEqual(@as(usize, 6), response_header_context.items.len);
    try std.testing.expectEqualStrings("X-Global-Policy", response_header_context.items[0].name);
    try std.testing.expectEqualStrings("Cache-Control", response_header_context.items[1].name);
    try std.testing.expectEqualStrings("X-Site-Policy", response_header_context.items[2].name);
    try std.testing.expectEqualStrings("Cache-Control", response_header_context.items[3].name);
    try std.testing.expectEqualStrings("X-Api-Policy", response_header_context.items[4].name);
    try std.testing.expectEqualStrings("Cache-Control", response_header_context.items[5].name);

    var file_domain = try initDomainConfig(allocator, "file-site");
    try applyDomainConfigLine(&file_domain, allocator, "add_header", "X-File-Policy: file");
    try applyDomainConfigLine(&file_domain, allocator, "cache_control", "public, max-age=120");
    try applyDomainConfigLine(&file_domain, allocator, "ssl_certificate", "/certs/file/fullchain.pem");
    try applyDomainConfigLine(&file_domain, allocator, "ssl_certificate_key", "/certs/file/privkey.pem");
    try std.testing.expectEqual(@as(usize, 2), file_domain.response_headers.items.len);
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

    upstream_mod.round_robin_cursor.store(0, .monotonic);
    try std.testing.expectEqual(@as(usize, 0), upstreamStartTicket(&pool, .weighted, 1_000, null, null));
    try std.testing.expectEqual(@as(usize, 0), upstreamStartTicket(&pool, .weighted, 1_000, null, null));
    try std.testing.expectEqual(@as(usize, 0), upstreamStartTicket(&pool, .weighted, 1_000, null, null));
    try std.testing.expectEqual(@as(usize, 1), upstreamStartTicket(&pool, .weighted, 1_000, null, null));

    upstream_mod.round_robin_cursor.store(0, .monotonic);
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

    const first = upstreamStartTicket(&pool, .consistent_hash, 1_000, request_mod.upstreamHashInput(req), null);
    try std.testing.expectEqual(first, upstreamStartTicket(&pool, .consistent_hash, 1_000, request_mod.upstreamHashInput(req), null));

    pool.targets.items[first].ejected_until_ms.store(2_000, .monotonic);
    const replacement = upstreamStartTicket(&pool, .consistent_hash, 1_000, request_mod.upstreamHashInput(req), null);
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

test "accept encoding q values control gzip negotiation" {
    try std.testing.expect(acceptsContentCoding("Accept-Encoding: br, gzip\r\n", "gzip"));
    try std.testing.expect(acceptsContentCoding("Accept-Encoding: *;q=0.5\r\n", "gzip"));
    try std.testing.expect(!acceptsContentCoding("Accept-Encoding: gzip;q=0, br\r\n", "gzip"));
    try std.testing.expect(!acceptsContentCoding("Accept-Encoding: *;q=1, gzip;q=0\r\n", "gzip"));
    try std.testing.expect(!acceptsContentCoding("Accept-Encoding: gzip;q=0.0\r\n", "gzip"));
}

test "gzip response preparation compresses eligible text bodies" {
    var body: [2048]u8 = undefined;
    @memset(&body, 'a');

    current_request_headers = "Accept-Encoding: gzip\r\n";
    current_response_headers = &.{};
    current_compression_policy = .{
        .enabled = true,
        .gzip_enabled = true,
        .min_bytes = 1,
        .max_bytes = 4096,
    };
    defer {
        current_request_headers = "";
        current_response_headers = &.{};
        current_compression_policy = .disabled;
    }

    const prepared = try prepareResponseBody(std.testing.allocator, 200, "text/plain; charset=utf-8", &body, false, null, &.{});
    defer prepared.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("gzip", prepared.encoding.?);
    try std.testing.expect(prepared.body.len < body.len);
    try std.testing.expectEqual(@as(u8, 0x1f), prepared.body[0]);
    try std.testing.expectEqual(@as(u8, 0x8b), prepared.body[1]);
}

test "http2 goaway payload masks reserved stream bit" {
    const payload = h2_support.makeGoawayPayload(0xffff_ffff, HTTP2_ERROR_NO_ERROR);
    try std.testing.expectEqual(@as(u32, 0x7fff_ffff), std.mem.readInt(u32, payload[0..4], .big));
    try std.testing.expectEqual(@as(u32, HTTP2_ERROR_NO_ERROR), std.mem.readInt(u32, payload[4..8], .big));
}

test "static cache headers include cache status detail" {
    const plain = try makeStaticBaseHeaders(std.testing.allocator, "\"etag\"", null);
    defer std.testing.allocator.free(plain);
    try std.testing.expect(std.mem.indexOf(u8, plain, "Cache-Status: Layerline; hit; ttl=60; detail=\"static-file\"\r\n") != null);

    const encoded = try makeStaticBaseHeaders(std.testing.allocator, "\"etag\"", "br");
    defer std.testing.allocator.free(encoded);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "Cache-Status: Layerline; hit; ttl=60; detail=\"precompressed-static\"\r\n") != null);
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
    current_request_headers = req.headers;
    current_compression_policy = compressionPolicyFromConfig(cfg);
    defer {
        current_request_headers = "";
        current_compression_policy = .disabled;
    }

    const base_header_context = try buildResponseHeaderContext(allocator, cfg, domain, null);
    defer base_header_context.deinit(allocator);
    current_response_headers = base_header_context.items;
    defer current_response_headers = &.{};

    if (cfg.admin_ui_enabled and adminPathMatches(cfg.admin_ui_path, req.path)) {
        try handleAdminUi(io, stream, allocator, cfg, req, should_close, is_head);
        return;
    }

    if (findDomainRedirectRule(domain, req.path)) |redirect| {
        accessLogSetHandler("domain_redirect");
        try sendConfiguredRedirect(stream, allocator, redirect, req, should_close, is_head);
        return;
    }

    if (findRedirectRule(cfg, req.path)) |redirect| {
        accessLogSetHandler("redirect");
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
        accessLogSetHandler("acme_challenge");
        const token = req.path["/.well-known/acme-challenge/".len..];
        try serveAcmeChallenge(io, stream, allocator, cfg.letsencrypt_webroot, token, should_close, is_head);
        return;
    }

    // A domain-level proxy is the virtual host's fallback owner. Keep the
    // built-in Layerline pages for direct/default hosts, not for proxied apps.
    if (domain != null) {
        if (domainUpstreamMutable(cfg, domain)) |pool| {
            accessLogSetHandler("domain_proxy");
            try forwardToUpstreamPool(stream, allocator, pool, domainUpstreamPolicy(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), req, cfg);
            return;
        }
    }

    if (std.mem.eql(u8, method, "GET") or is_head) {
        if (std.mem.eql(u8, req.path, "/favicon.svg") or std.mem.eql(u8, req.path, "/icon.svg")) {
            accessLogSetHandler("builtin_asset");
            try sendServerIcon(stream, should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/") and domainPhpFrontController(cfg, domain)) {
            accessLogSetHandler("php_front_controller");
            try handlePhpFrontController(io, stream, allocator, cfg, req, null, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), domainPhpFastcgi(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), domainPhpIndex(cfg, domain), should_close, is_head, process_env);
            return;
        }

        if (std.mem.eql(u8, req.path, "/") and domainServeStaticRoot(cfg, domain)) {
            accessLogSetHandler("static_root");
            try serveStatic(io, stream, allocator, domainStaticDir(cfg, domain), domainIndexFile(cfg, domain), req.headers, should_close, is_head, cfg.max_static_file_bytes);
            return;
        }

        if (std.mem.eql(u8, req.path, "/")) {
            accessLogSetHandler("builtin_root");
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
            accessLogSetHandler("health");
            try sendResponseForMethod(stream, 200, "OK", "text/plain; charset=utf-8", "ok\n", should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/metrics")) {
            accessLogSetHandler("metrics");
            try sendMetrics(stream, allocator, should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/time")) {
            accessLogSetHandler("time");
            var ts_buf: [64]u8 = undefined;
            const ts = try std.fmt.bufPrint(&ts_buf, "{{\"time\":{}}}\n", .{std.Io.Timestamp.now(io, .real).toSeconds()});
            try sendResponseForMethod(stream, 200, "OK", "application/json; charset=utf-8", ts, should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/api/echo")) {
            accessLogSetHandler("api_echo");
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
            try sendNotFoundForMethod(allocator, stream, should_close, is_head);
            return;
        }

        if (std.mem.endsWith(u8, req.path, ".php") or std.mem.startsWith(u8, req.path, "/php/")) {
            accessLogSetHandler("php");
            const rel_path = if (req.path.len > 0 and req.path[0] == '/') req.path[1..] else req.path;
            try handlePhpScript(io, stream, allocator, cfg, req, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), domainPhpFastcgi(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), rel_path, req.path, "", should_close, is_head, process_env);
            return;
        }

        if (std.mem.startsWith(u8, req.path, "/static/")) {
            accessLogSetHandler("static");
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
                accessLogSetHandler("static_root");
                try serveStatic(io, stream, allocator, static_dir, rel, req.headers, should_close, is_head, cfg.max_static_file_bytes);
                return;
            }
        }

        if (domainPhpFrontController(cfg, domain)) {
            accessLogSetHandler("php_front_controller");
            try handlePhpFrontController(io, stream, allocator, cfg, req, null, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), domainPhpFastcgi(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), domainPhpIndex(cfg, domain), should_close, is_head, process_env);
            return;
        }

        if (domainUpstreamMutable(cfg, domain)) |pool| {
            accessLogSetHandler("domain_proxy");
            try forwardToUpstreamPool(stream, allocator, pool, domainUpstreamPolicy(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), req, cfg);
            return;
        }

        accessLogSetHandler("not_found");
        try sendDomainCustomNotFoundForMethod(io, stream, allocator, cfg, domain, should_close, is_head);
        return;
    }

    if (std.mem.eql(u8, method, "POST")) {
        if (std.mem.eql(u8, req.path, "/test.php") and !domainPhpInfoPage(cfg, domain)) {
            try sendNotFoundWithConnection(allocator, stream, should_close);
            return;
        }

        if (std.mem.endsWith(u8, req.path, ".php")) {
            accessLogSetHandler("php");
            const rel_path = if (req.path.len > 0 and req.path[0] == '/') req.path[1..] else req.path;
            try handlePhpScript(io, stream, allocator, cfg, req, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), domainPhpFastcgi(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), rel_path, req.path, "", should_close, false, process_env);
            return;
        }

        if (std.mem.eql(u8, req.path, "/api/echo")) {
            accessLogSetHandler("api_echo");
            try sendResponseWithConnection(stream, 200, "OK", "text/plain; charset=utf-8", req.body, should_close);
            return;
        }

        if (domainPhpFrontController(cfg, domain)) {
            accessLogSetHandler("php_front_controller");
            try handlePhpFrontController(io, stream, allocator, cfg, req, null, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), domainPhpFastcgi(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), domainPhpIndex(cfg, domain), should_close, false, process_env);
            return;
        }

        if (domainUpstreamMutable(cfg, domain)) |pool| {
            accessLogSetHandler("domain_proxy");
            try forwardToUpstreamPool(stream, allocator, pool, domainUpstreamPolicy(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), req, cfg);
            return;
        }

        accessLogSetHandler("not_found");
        try sendNotFoundWithConnection(allocator, stream, should_close);
        return;
    }

    if (std.mem.eql(u8, method, "OPTIONS")) {
        accessLogSetHandler("options");
        const allow = "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS";
        const allow_header = try std.fmt.allocPrint(allocator, "Allow: {s}\r\n", .{allow});
        defer allocator.free(allow_header);
        try sendResponseNoBodyWithConnectionAndHeaders(stream, 204, "No Content", "text/plain; charset=utf-8", 0, should_close, allow_header);
        return;
    }

    if (std.mem.eql(u8, method, "PUT") or std.mem.eql(u8, method, "PATCH") or std.mem.eql(u8, method, "DELETE")) {
        if (domainPhpFrontController(cfg, domain)) {
            accessLogSetHandler("php_front_controller");
            try handlePhpFrontController(io, stream, allocator, cfg, req, null, domainPhpRoot(cfg, domain), domainPhpBinary(cfg, domain), domainPhpFastcgi(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), domainPhpIndex(cfg, domain), should_close, false, process_env);
            return;
        }

        if (domainUpstreamMutable(cfg, domain)) |pool| {
            accessLogSetHandler("domain_proxy");
            try forwardToUpstreamPool(stream, allocator, pool, domainUpstreamPolicy(cfg, domain), domainUpstreamTimeoutMs(cfg, domain), req, cfg);
            return;
        }
        accessLogSetHandler("method_not_allowed");
        try sendMethodNotAllowedWithAllow(stream, allocator, "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS", should_close, false);
        return;
    }

    accessLogSetHandler("not_implemented");
    try sendNotImplemented(stream, allocator, should_close);
}

fn routeHttpRedirectRequest(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    req: HttpRequest,
) !void {
    const is_head = std.mem.eql(u8, req.method, "HEAD");
    const close_connection = true;

    current_request_headers = req.headers;
    current_compression_policy = .disabled;
    current_response_headers = &.{};
    defer {
        current_request_headers = "";
        current_compression_policy = .disabled;
        current_response_headers = &.{};
    }

    if ((std.mem.eql(u8, req.method, "GET") or is_head) and std.mem.startsWith(u8, req.path, "/.well-known/acme-challenge/")) {
        accessLogSetHandler("acme_challenge");
        const token = req.path["/.well-known/acme-challenge/".len..];
        try serveAcmeChallenge(io, stream, allocator, cfg.letsencrypt_webroot, token, close_connection, is_head);
        return;
    }

    accessLogSetHandler("http_to_https_redirect");
    sendHttpsRedirect(stream, allocator, cfg, req, close_connection, is_head) catch |err| switch (err) {
        error.MissingHostHeader => try sendBadRequestForMethod(allocator, stream, "Missing Host header.", close_connection, is_head),
        error.InvalidRedirectHost => try sendBadRequestForMethod(allocator, stream, "Invalid Host header.", close_connection, is_head),
        error.InvalidRedirectPath => try sendBadRequestForMethod(allocator, stream, "Invalid request path.", close_connection, is_head),
        else => return err,
    };
}

fn handleHttpRedirectConnection(
    io: std.Io,
    stream: std.Io.net.Stream,
    cfg: *ServerConfig,
    allocator: std.mem.Allocator,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const req_alloc = arena.allocator();

    setStreamTimeouts(stream, cfg.read_header_timeout_ms, cfg.write_timeout_ms) catch |err| {
        std.debug.print("HTTP redirect socket timeout setup failed: {}\n", .{err});
    };

    var prefill_buf: [64]u8 = undefined;
    const prefill_len = streamRead(stream, &prefill_buf) catch |err| switch (err) {
        error.RequestTimeout => {
            try sendCoolErrorWithConnection(
                stream,
                req_alloc,
                408,
                "Request Timeout",
                "No request bytes arrived before the redirect listener timeout.",
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

    if (isLikelyHttp2Preface(prefill) or tls_client_hello.looksLikeTlsClientHello(prefill) or native_tls.isHttp3OverTcpProbe(prefill)) {
        try sendCoolErrorWithConnection(
            stream,
            req_alloc,
            426,
            "Upgrade Required",
            "Use the HTTPS listener for TLS, HTTP/2, or HTTP/3. This socket only handles ACME HTTP-01 and HTTP-to-HTTPS redirects.",
            true,
            false,
            null,
        );
        return;
    }

    var req = request_mod.parseHeadersOnly(stream, req_alloc, cfg.max_request_bytes, prefill, .{
        .read = streamRead,
        .write_all = streamWriteAll,
        .set_read_timeout = setStreamReadTimeout,
    }) catch |err| {
        if (err != error.ConnectionClosed) server_metrics.requestParseError();
        switch (err) {
            error.ConnectionClosed => return,
            error.RequestTimeout => {
                try sendCoolErrorWithConnection(stream, req_alloc, 408, "Request Timeout", "The request took too long to read.", true, false, null);
                return;
            },
            error.RequestTooLarge => {
                try sendCoolErrorWithConnection(stream, req_alloc, 413, "Payload Too Large", "Request headers are too large.", true, false, null);
                return;
            },
            error.PayloadTooLarge => {
                try sendCoolErrorWithConnection(stream, req_alloc, 413, "Payload Too Large", "Request body exceeds configured limit.", true, false, null);
                return;
            },
            error.InvalidContentLength => {
                try sendBadRequest(req_alloc, stream, "Invalid Content-Length header.");
                return;
            },
            error.UnsupportedTransferEncoding => {
                try sendCoolErrorWithConnection(stream, req_alloc, 501, "Not Implemented", "Only plain Content-Length and chunked request bodies are supported.", true, false, null);
                return;
            },
            error.ExpectationFailed => {
                try sendCoolErrorWithConnection(stream, req_alloc, 417, "Expectation Failed", "Only Expect: 100-continue is supported.", true, false, null);
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
                try sendCoolErrorWithConnection(stream, req_alloc, 505, "HTTP Version Not Supported", "The redirect listener only accepts HTTP/1.x before sending clients to HTTPS.", true, false, null);
                return;
            },
            else => {
                try sendCoolErrorWithConnection(stream, req_alloc, 500, "Internal Server Error", "Internal server error while parsing request.", true, false, null);
                return;
            },
        }
    };
    req.close_connection = true;
    server_metrics.requestStarted();
    const request_id = try request_id_generator.resolve(io, req_alloc, req.headers);

    var access_ctx = access_log_mod.Context{
        .enabled = cfg.access_log_enabled,
        .sink = cfg.access_log_path,
        .method = req.method,
        .path = req.path,
        .query = req.query,
        .protocol = req.version,
        .host = findHeaderValue(req.headers, "Host") orelse "",
        .request_id = request_id,
        .start_ms = std.Io.Timestamp.now(io, .awake).toMilliseconds(),
    };
    current_request_id = request_id;
    current_access_log = &access_ctx;
    defer {
        current_access_log = null;
        current_request_id = "";
    }

    routeHttpRedirectRequest(io, stream, req_alloc, cfg, req) catch |err| {
        accessLogSetError(@errorName(err));
        emitAccessLog(0, 0);
        server_metrics.routeError();
        return err;
    };
    if (!access_ctx.logged) emitAccessLog(0, 0);
}

fn serveHttpRedirectConnectionTask(
    io: std.Io,
    stream: std.Io.net.Stream,
    cfg: *ServerConfig,
    allocator: std.mem.Allocator,
    state: *ConcurrencyState,
) void {
    bindThreadIo(io);
    defer {
        state.release();
        streamClose(stream);
    }

    handleHttpRedirectConnection(io, stream, cfg, allocator) catch |err| {
        std.debug.print("HTTP redirect handler error: {}\n", .{err});
    };
}

const HttpRedirectListenerContext = struct {
    io: std.Io,
    server: *std.Io.net.Server,
    cfg: *ServerConfig,
    allocator: std.mem.Allocator,
    state: *ConcurrencyState,
};

fn serveHttpRedirectListenerTask(ctx: HttpRedirectListenerContext) void {
    bindThreadIo(ctx.io);

    while (!shutdown_requested.load(.acquire)) {
        const conn = ctx.server.accept(ctx.io) catch |err| {
            if (shutdown_requested.load(.acquire)) break;
            std.debug.print("HTTP redirect accept failed: {}. Continuing to accept.\n", .{err});
            ctx.io.sleep(.fromMilliseconds(25), .awake) catch {};
            continue;
        };
        if (shutdown_requested.load(.acquire)) {
            streamClose(conn);
            break;
        }

        if (!ctx.state.tryAcquire(ctx.cfg.max_concurrent_connections)) {
            server_metrics.connectionRejected();
            sendCoolError(
                conn,
                ctx.allocator,
                503,
                "Service Unavailable",
                "Maximum concurrent connections reached. Try again in a moment.",
            ) catch {};
            streamClose(conn);
            continue;
        }

        const worker = std.Thread.spawn(
            .{ .stack_size = ctx.cfg.worker_stack_size },
            serveHttpRedirectConnectionTask,
            .{ ctx.io, conn, ctx.cfg, ctx.allocator, ctx.state },
        ) catch |err| {
            std.debug.print("Failed to start HTTP redirect worker: {}\n", .{err});
            ctx.state.release();
            streamClose(conn);
            continue;
        };
        worker.detach();
    }
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

        if (native_tls.isHttp3OverTcpProbe(prefill)) {
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
        var req = request_mod.parse(stream, req_alloc, cfg.max_request_bytes, cfg.max_body_bytes, cfg.read_body_timeout_ms, MAX_CHUNK_LINE_BYTES, prefill, .{
            .read = streamRead,
            .write_all = streamWriteAll,
            .set_read_timeout = setStreamReadTimeout,
        }) catch |err| {
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

        {
            const request_id = try request_id_generator.resolve(io, req_alloc, req.headers);
            var access_ctx = access_log_mod.Context{
                .enabled = cfg.access_log_enabled,
                .sink = cfg.access_log_path,
                .method = req.method,
                .path = req.path,
                .query = req.query,
                .protocol = req.version,
                .host = findHeaderValue(req.headers, "Host") orelse "",
                .request_id = request_id,
                .start_ms = std.Io.Timestamp.now(io, .awake).toMilliseconds(),
            };
            current_request_id = request_id;
            current_access_log = &access_ctx;
            defer {
                current_access_log = null;
                current_request_id = "";
            }

            if (req.h2c_upgrade_tail.len > 0 or request_mod.isH2cUpgradeHeaders(req.headers)) {
                accessLogSetHandler("h2c_upgrade");
                try handleHttp2Upgrade(io, stream, req_alloc, cfg, req, process_env);
                return;
            }

            if (cfg.max_requests_per_connection > 0 and handled_requests >= cfg.max_requests_per_connection) {
                req.close_connection = true;
            }

            routeRequest(io, stream, req_alloc, cfg, req, process_env) catch |err| switch (err) {
                error.CloseConnection => break,
                else => {
                    accessLogSetError(@errorName(err));
                    emitAccessLog(0, 0);
                    server_metrics.routeError();
                    return err;
                },
            };

            if (!access_ctx.logged) emitAccessLog(0, 0);
        }

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
            "[--http3 true|false] [--http3-port PORT] [--admin true|false] [--admin-socket /run/layerline/admin.sock] [--admin-ui true|false] [--admin-ui-path /_layerline/admin] [--admin-credentials-path .layerline-admin] [--access-log off|stderr|PATH] [--compression true|false] [--compression-min-bytes N] [--compression-max-bytes N] [--tls true|false] [--tls-cert path] [--tls-key path] " ++
            "[--tls-auto true|false] [--letsencrypt-email EMAIL] [--letsencrypt-domains example.com,www.example.com] " ++
            "[--letsencrypt-webroot /var/www/html] [--letsencrypt-certbot /usr/bin/certbot] [--letsencrypt-staging true|false] [--letsencrypt-renew true|false] [--letsencrypt-renew-interval-ms N] " ++
            "[--http-redirect true|false] [--http-redirect-port 80] [--http-redirect-https-port 443] [--http-redirect-status 308] " ++
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
            "php_root, php_binary/php_bin, php_fastcgi/php_fpm/fastcgi, php_index/php_index_file, php_front_controller, php_info_page/phpinfo_page, proxy, upstream_policy/proxy_policy, h2_upstream, http3, http3_port, admin, admin_socket/admin_socket_path, admin_ui/admin_ui_enabled, admin_ui_path, admin_credentials_path, access_log, access_log_path, compression/compress/encode, gzip, compression_min_bytes, compression_max_bytes, domain_config_dir/domains_dir/sites_enabled, header/response_header/add_header, cache_control, redirect/redir, tls, tls_cert, tls_key, max_request_bytes, " ++
            "tls_auto, letsencrypt_email, letsencrypt_domains, letsencrypt_webroot, letsencrypt_certbot, letsencrypt_staging, letsencrypt_renew, letsencrypt_renew_interval_ms, http_redirect, http_redirect_port, http_redirect_https_port, http_redirect_status, " ++
            "max_body_bytes, max_static_file_bytes, max_requests_per_connection, max_php_output_bytes, max_concurrent_connections, worker_stack_size, " ++
            "read_header_timeout_ms, read_body_timeout_ms, idle_timeout_ms, write_timeout_ms, upstream_timeout_ms, upstream_retries, upstream_max_failures, upstream_fail_timeout_ms, upstream_keepalive, upstream_keepalive_max_idle, upstream_keepalive_idle_timeout_ms, upstream_keepalive_max_requests, fastcgi_keepalive, fastcgi_keepalive_max_idle, fastcgi_keepalive_idle_timeout_ms, fastcgi_keepalive_max_requests, upstream_health_check, upstream_health_check_path, upstream_health_check_interval_ms, upstream_health_check_timeout_ms, upstream_circuit_breaker, upstream_circuit_half_open_max, upstream_slow_start_ms, graceful_shutdown_timeout_ms, " ++
            "cf_auto_deploy, cf_api_base, cf_token, cf_zone_id, cf_zone_name, cf_record_name, cf_record_type, cf_record_content, " ++
            "cf_record_ttl, cf_record_proxied, cf_record_comment, route, route_dir.NAME, route_index.NAME, route_php_root.NAME, " ++
            "route_php_bin.NAME, route_php_fastcgi.NAME, route_php_index.NAME, route_php_front_controller.NAME, route_php_info_page.NAME, route_proxy.NAME, route_upstream_policy.NAME, route_upstream_timeout_ms.NAME, route_strip_prefix.NAME, route_header.NAME, route_cache_control.NAME, server/domain/vhost, " ++
            "server_name.NAME, server_root.NAME, server_index.NAME, server_serve_static_root.NAME, server_header.NAME, server_cache_control.NAME, server_proxy.NAME, " ++
            "server_upstream_policy.NAME, server_upstream_timeout_ms.NAME, server_php_fastcgi.NAME, server_php_index.NAME, server_php_front_controller.NAME, server_tls_cert.NAME, server_tls_key.NAME, server_redirect.NAME, server_route.NAME, server_route_dir.DOMAIN.ROUTE, server_route_header.DOMAIN.ROUTE, server_route_cache_control.DOMAIN.ROUTE, server_route_php_fastcgi.DOMAIN.ROUTE, server_route_php_index.DOMAIN.ROUTE, server_route_php_front_controller.DOMAIN.ROUTE, server_route_proxy.DOMAIN.ROUTE, server_route_upstream_policy.DOMAIN.ROUTE, server_route_upstream_timeout_ms.DOMAIN.ROUTE\n" ++
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
            "  zig build run -- --admin-ui true --admin-ui-path /_layerline/admin\n" ++
            "  zig build run -- --access-log /var/log/layerline/access.log\n" ++
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
        .config_path = DEFAULT_CONFIG_PATH,
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
        .letsencrypt_webroot = "public",
        .letsencrypt_certbot = "certbot",
        .letsencrypt_staging = false,
        .letsencrypt_renew = true,
        .letsencrypt_renew_interval_ms = DEFAULT_LETSENCRYPT_RENEW_INTERVAL_MS,
        .http_redirect_enabled = false,
        .http_redirect_port = 80,
        .http_redirect_https_port = 443,
        .http_redirect_status = 308,
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
        .admin_enabled = false,
        .admin_socket_path = DEFAULT_ADMIN_SOCKET_PATH,
        .admin_ui_enabled = false,
        .admin_ui_path = DEFAULT_ADMIN_UI_PATH,
        .admin_credentials_path = DEFAULT_ADMIN_CREDENTIALS_PATH,
        .access_log_enabled = false,
        .access_log_path = DEFAULT_ACCESS_LOG_PATH,
        .compression_enabled = false,
        .gzip_enabled = true,
        .compression_min_bytes = DEFAULT_COMPRESSION_MIN_BYTES,
        .compression_max_bytes = DEFAULT_COMPRESSION_MAX_BYTES,
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
                cfg.config_path = path;
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
        } else if (std.mem.eql(u8, arg, "--letsencrypt-renew") or std.mem.eql(u8, arg, "--tls-renew") or std.mem.eql(u8, arg, "--acme-renew")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.letsencrypt_renew = parseBool(value) orelse cfg.letsencrypt_renew;
        } else if (std.mem.eql(u8, arg, "--letsencrypt-renew-interval-ms") or std.mem.eql(u8, arg, "--tls-renew-interval-ms") or std.mem.eql(u8, arg, "--acme-renew-interval-ms")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.letsencrypt_renew_interval_ms = std.fmt.parseInt(u32, value, 10) catch cfg.letsencrypt_renew_interval_ms;
        } else if (std.mem.eql(u8, arg, "--http-redirect") or std.mem.eql(u8, arg, "--http-to-https")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.http_redirect_enabled = parseBool(value) orelse cfg.http_redirect_enabled;
        } else if (std.mem.eql(u8, arg, "--http-redirect-port") or std.mem.eql(u8, arg, "--http-to-https-port")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.http_redirect_port = std.fmt.parseInt(u16, value, 10) catch cfg.http_redirect_port;
        } else if (std.mem.eql(u8, arg, "--http-redirect-https-port") or std.mem.eql(u8, arg, "--https-port")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.http_redirect_https_port = std.fmt.parseInt(u16, value, 10) catch cfg.http_redirect_https_port;
        } else if (std.mem.eql(u8, arg, "--http-redirect-status") or std.mem.eql(u8, arg, "--http-to-https-status")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.http_redirect_status = std.fmt.parseInt(u16, value, 10) catch cfg.http_redirect_status;
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
        } else if (std.mem.eql(u8, arg, "--admin")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.admin_enabled = parseBool(value) orelse cfg.admin_enabled;
        } else if (std.mem.eql(u8, arg, "--admin-socket") or std.mem.eql(u8, arg, "--admin-socket-path")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            if (disablesOptionalUrl(value)) {
                cfg.admin_enabled = false;
                cfg.admin_socket_path = null;
            } else {
                cfg.admin_enabled = true;
                cfg.admin_socket_path = value;
            }
        } else if (std.mem.eql(u8, arg, "--admin-ui") or std.mem.eql(u8, arg, "--admin-ui-enabled")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.admin_ui_enabled = parseBool(value) orelse cfg.admin_ui_enabled;
        } else if (std.mem.eql(u8, arg, "--admin-ui-path")) {
            cfg.admin_ui_path = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--admin-credentials-path") or std.mem.eql(u8, arg, "--admin-state-path")) {
            cfg.admin_credentials_path = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--access-log")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            if (disablesOptionalUrl(value)) {
                cfg.access_log_enabled = false;
            } else if (std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "on") or std.ascii.eqlIgnoreCase(value, "yes") or std.mem.eql(u8, value, "1")) {
                cfg.access_log_enabled = true;
            } else {
                cfg.access_log_enabled = true;
                cfg.access_log_path = value;
            }
        } else if (std.mem.eql(u8, arg, "--access-log-path")) {
            cfg.access_log_enabled = true;
            cfg.access_log_path = args.next() orelse {
                usage();
                return;
            };
        } else if (std.mem.eql(u8, arg, "--compression") or std.mem.eql(u8, arg, "--compress") or std.mem.eql(u8, arg, "--encode")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.compression_enabled = parseBool(value) orelse cfg.compression_enabled;
        } else if (std.mem.eql(u8, arg, "--gzip")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.gzip_enabled = parseBool(value) orelse cfg.gzip_enabled;
        } else if (std.mem.eql(u8, arg, "--compression-min-bytes") or std.mem.eql(u8, arg, "--gzip-min-bytes")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.compression_min_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.compression_min_bytes;
        } else if (std.mem.eql(u8, arg, "--compression-max-bytes") or std.mem.eql(u8, arg, "--gzip-max-bytes")) {
            const value = args.next() orelse {
                usage();
                return;
            };
            cfg.compression_max_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.compression_max_bytes;
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
    var redirect_listener_closed_by_shutdown = std.atomic.Value(bool).init(false);
    var redirect_server: ?std.Io.net.Server = null;
    if (cfg.http_redirect_enabled) {
        const redirect_address = try std.Io.net.IpAddress.parse(cfg.host, cfg.http_redirect_port);
        redirect_server = try redirect_address.listen(init.io, .{ .reuse_address = true });
    }
    defer {
        if (!listener_closed_by_shutdown.load(.acquire)) {
            server.deinit(init.io);
        }
    }
    defer {
        if (redirect_server) |*http_server| {
            if (!redirect_listener_closed_by_shutdown.load(.acquire)) {
                http_server.deinit(init.io);
            }
        }
    }
    const shutdown_watcher = std.Thread.spawn(
        .{},
        shutdownWatcherTask,
        .{ShutdownWatcherContext{ .io = init.io, .server = &server, .closed = &listener_closed_by_shutdown, .wake_host = listenerWakeHost(cfg.host), .wake_port = cfg.port }},
    ) catch |err| {
        std.debug.print("Failed to start shutdown watcher: {}\n", .{err});
        return;
    };
    shutdown_watcher.detach();

    if (redirect_server) |*http_server| {
        const http_shutdown_watcher = std.Thread.spawn(
            .{},
            shutdownWatcherTask,
            .{ShutdownWatcherContext{ .io = init.io, .server = http_server, .closed = &redirect_listener_closed_by_shutdown, .wake_host = listenerWakeHost(cfg.host), .wake_port = cfg.http_redirect_port }},
        ) catch |err| {
            std.debug.print("Failed to start HTTP redirect shutdown watcher: {}\n", .{err});
            return;
        };
        http_shutdown_watcher.detach();

        const http_redirect_worker = std.Thread.spawn(
            .{},
            serveHttpRedirectListenerTask,
            .{HttpRedirectListenerContext{ .io = init.io, .server = http_server, .cfg = &cfg, .allocator = std.heap.page_allocator, .state = &concurrency }},
        ) catch |err| {
            std.debug.print("Failed to start HTTP redirect listener: {}\n", .{err});
            return;
        };
        http_redirect_worker.detach();
        std.debug.print("HTTP redirect listener on http://{s}:{d} -> https port {d} status {d}\n", .{ cfg.host, cfg.http_redirect_port, cfg.http_redirect_https_port, cfg.http_redirect_status });
    }

    std.debug.print("Serving on {s}://{s}:{d}\n", .{ if (cfg.tls_enabled) "https" else "http", cfg.host, cfg.port });
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
        const h3_worker = std.Thread.spawn(.{}, http3_server.serveProbeTask, .{ init.io, &cfg, &server_metrics, SERVER_HEADER }) catch |err| {
            std.debug.print("Failed to start HTTP/3 native listener: {}\n", .{err});
            return;
        };
        h3_worker.detach();
    }
    if (cfg.admin_enabled) {
        const admin_socket_path = cfg.admin_socket_path orelse DEFAULT_ADMIN_SOCKET_PATH;
        const admin_worker = std.Thread.spawn(.{}, serveAdminSocketTask, .{AdminSocketContext{ .io = init.io, .cfg = &cfg, .socket_path = admin_socket_path }}) catch |err| {
            std.debug.print("Failed to start admin socket: {}\n", .{err});
            return;
        };
        admin_worker.detach();
    }
    if (cfg.tls_auto and cfg.letsencrypt_renew) {
        const acme_worker = std.Thread.spawn(.{}, letsEncryptRenewalTask, .{LetsEncryptRenewalContext{ .io = init.io, .cfg = &cfg }}) catch |err| {
            std.debug.print("Failed to start Let's Encrypt renewal loop: {}\n", .{err});
            return;
        };
        acme_worker.detach();
    }

    while (!shutdown_requested.load(.acquire)) {
        const conn = server.accept(init.io) catch |err| {
            if (shutdown_requested.load(.acquire)) break;
            std.debug.print("Accept failed: {}. Continuing to accept.\n", .{err});
            init.io.sleep(.fromMilliseconds(25), .awake) catch {};
            continue;
        };
        if (shutdown_requested.load(.acquire)) {
            streamClose(conn);
            break;
        }

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
    if (cfg.admin_enabled) {
        unlinkUnixSocket(cfg.admin_socket_path orelse DEFAULT_ADMIN_SOCKET_PATH);
    }
}
