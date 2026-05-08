const std = @import("std");
const access_log_mod = @import("access_log.zig");
const admin_pages = @import("admin_pages.zig");
const admin_runtime = @import("admin_runtime.zig");
const admin_support = @import("admin_support.zig");
const admin_ui_mod = @import("admin_ui.zig");
const acme_mod = @import("acme.zig");
const cli_config = @import("cli_config.zig");
const cli_output = @import("cli_output.zig");
const concurrency_mod = @import("concurrency.zig");
const config_mod = @import("config.zig");
const fastcgi = @import("fastcgi.zig");
const h2_native = @import("h2_native.zig");
const h2_server = @import("http2_server.zig");
const h2_support = @import("http2_support.zig");
const http2_content = @import("http2_content.zig");
const http2_upstream = @import("http2_upstream.zig");
const http1_router = @import("http1_router.zig");
const http1_responses = @import("http1_responses.zig");
const http1_runtime = @import("http1_runtime.zig");
const http1_static = @import("http1_static.zig");
const http3_server = @import("http3_server.zig");
const http_headers = @import("http_headers.zig");
const http_response = @import("http_response.zig");
const metrics_mod = @import("metrics.zig");
const native_tls = @import("native_tls_runtime.zig");
const php_runtime = @import("php_runtime.zig");
const proxy_utils = @import("proxy_utils.zig");
const request_mod = @import("request.zig");
const request_trace = @import("request_trace.zig");
const response_body = @import("response_body.zig");
const routing_mod = @import("routing.zig");
const server_assets = @import("server_assets.zig");
const static_files = @import("static_files.zig");
const stream_runtime = @import("stream_runtime.zig");
const tls_client_hello = @import("tls_client_hello.zig");
const tls_pem = @import("tls_pem.zig");
const upstream_mod = @import("upstream.zig");
const upstream_runtime = @import("upstream_runtime.zig");

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
const renderAdminSetupPage = admin_ui_mod.renderAdminSetupPage;
const renderAdminLoginPage = admin_ui_mod.renderAdminLoginPage;
const AdminCredentials = admin_support.AdminCredentials;
const adminPathMatches = admin_support.adminPathMatches;
const certbotWebrootFromAcmeConfig = acme_mod.certbotWebrootFromAcmeConfig;
const ensureCloudflareDeployment = acme_mod.ensureCloudflareDeployment;
const ensureLetsEncryptSetup = acme_mod.ensureLetsEncryptSetup;
const ServerMetrics = metrics_mod.ServerMetrics;
const isSkippedProxyResponseHeader = proxy_utils.isSkippedProxyResponseHeader;
const makePhpFrontControllerTarget = fastcgi.makePhpFrontControllerTarget;
const ByteRange = static_files.ByteRange;
const acceptsContentCoding = static_files.acceptsContentCoding;
const etagMatches = static_files.etagMatches;
const makeStaticBaseHeaders = static_files.makeStaticBaseHeaders;
const parseByteRange = static_files.parseByteRange;
const statRegularFile = static_files.statRegularFile;
const HttpRequest = request_mod.HttpRequest;
const activeIo = stream_runtime.activeIo;
const bindThreadIo = stream_runtime.bindThreadIo;
const connectFastcgiEndpoint = stream_runtime.connectFastcgiEndpoint;
const connectTcpHost = stream_runtime.connectTcpHost;
const listenerWakeHost = stream_runtime.listenerWakeHost;
const rawStreamRead = stream_runtime.rawStreamRead;
const rawStreamWriteAll = stream_runtime.rawStreamWriteAll;
const setStreamReadTimeout = stream_runtime.setStreamReadTimeout;
const setStreamTimeouts = stream_runtime.setStreamTimeouts;
const setStreamWriteTimeout = stream_runtime.setStreamWriteTimeout;
const streamClose = stream_runtime.streamClose;
const streamRead = stream_runtime.streamRead;
const streamWriteAll = stream_runtime.streamWriteAll;
const ConcurrencyState = concurrency_mod.State;
const H2BufferedResponse = h2_support.BufferedResponse;
const H2PendingReader = h2_support.PendingReader;
const upstreamPoolTargetCount = upstream_mod.upstreamPoolTargetCount;
const FastcgiKeepAlivePool = config_mod.FastcgiKeepAlivePool;
const UpstreamConfig = config_mod.UpstreamConfig;
const PhpFastcgiTcpEndpoint = config_mod.PhpFastcgiTcpEndpoint;
const PhpFastcgiEndpoint = config_mod.PhpFastcgiEndpoint;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const ResponseHeaderRule = config_mod.ResponseHeaderRule;
const CompressionPolicy = config_mod.CompressionPolicy;
const RedirectRule = config_mod.RedirectRule;
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
const validateRouteConfig = config_mod.validateRouteConfig;

const DEFAULT_MAX_PHP_FASTCGI_STDERR_BYTES = 64 * 1024;
const DEFAULT_COMPRESSION_WORK_BUFFER_BYTES = std.compress.flate.max_window_len;
const DEFAULT_ADMIN_SOCKET_PATH = "/tmp/layerline-admin.sock";
const SERVER_NAME = "Layerline";
const SERVER_TAGLINE = "Modern web server";
const SERVER_HEADER = "Layerline";

threadlocal var current_response_headers: []const ResponseHeaderRule = &.{};
threadlocal var current_request_headers: []const u8 = "";
threadlocal var current_request_id: []const u8 = "";
threadlocal var current_compression_policy: CompressionPolicy = .disabled;
threadlocal var current_access_log: ?*access_log_mod.Context = null;
var access_log_writer = access_log_mod.Writer{};
var request_id_generator = request_trace.Generator{};
var shutdown_requested = std.atomic.Value(bool).init(false);
var listener_closed_by_shutdown = std.atomic.Value(bool).init(false);

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

fn http1ResponseContext() http1_responses.Context {
    return .{
        .server_name = SERVER_NAME,
        .server_tagline = SERVER_TAGLINE,
        .server_header = SERVER_HEADER,
        .request_headers = current_request_headers,
        .request_id = current_request_id,
        .response_headers = current_response_headers,
        .compression_policy = current_compression_policy,
        .compression_work_buffer_bytes = DEFAULT_COMPRESSION_WORK_BUFFER_BYTES,
        .metrics = &server_metrics,
        .emit_access_log = emitAccessLog,
        .stream_write_all = streamWriteAll,
    };
}

fn streamWriteRequestIdHeader(stream: std.Io.net.Stream) !void {
    try http1_responses.writeRequestIdHeader(stream, http1ResponseContext());
}

fn streamWriteConfiguredResponseHeaders(stream: std.Io.net.Stream) !void {
    try http1_responses.writeConfiguredResponseHeaders(stream, http1ResponseContext());
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
    try http1_responses.sendCoolErrorWithConnection(stream, allocator, status_code, status_text, detail, close_connection, is_head, extra_headers, http1ResponseContext());
}

fn sendCoolError(stream: std.Io.net.Stream, allocator: std.mem.Allocator, status_code: u16, status_text: []const u8, detail: []const u8) !void {
    return http1_responses.sendCoolError(stream, allocator, status_code, status_text, detail, http1ResponseContext());
}

fn sendCoolErrorWithConnectionOnly(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    status_code: u16,
    status_text: []const u8,
    detail: []const u8,
    close_connection: bool,
) !void {
    return http1_responses.sendCoolErrorWithConnection(stream, allocator, status_code, status_text, detail, close_connection, false, null, http1ResponseContext());
}

fn sendResponseWithConnectionAndHeaders(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8, close_connection: bool, extra_headers: ?[]const u8) !void {
    try http1_responses.sendResponseWithConnectionAndHeaders(stream, status_code, status_text, content_type, body, close_connection, extra_headers, http1ResponseContext());
}

fn sendResponseWithConnection(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8, close_connection: bool) !void {
    try http1_responses.sendResponseWithConnection(stream, status_code, status_text, content_type, body, close_connection, http1ResponseContext());
}

fn sendResponse(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8) !void {
    try http1_responses.sendResponse(stream, status_code, status_text, content_type, body, http1ResponseContext());
}

fn sendResponseNoBody(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body_len: usize) !void {
    try http1_responses.sendResponseNoBody(stream, status_code, status_text, content_type, body_len, http1ResponseContext());
}

fn sendResponseNoBodyWithConnectionAndHeaders(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body_len: usize, close_connection: bool, extra_headers: ?[]const u8) !void {
    try http1_responses.sendResponseNoBodyWithConnectionAndHeaders(stream, status_code, status_text, content_type, body_len, close_connection, extra_headers, http1ResponseContext());
}

fn sendResponseNoBodyWithConnection(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body_len: usize, close_connection: bool) !void {
    try http1_responses.sendResponseNoBodyWithConnection(stream, status_code, status_text, content_type, body_len, close_connection, http1ResponseContext());
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
    try http1_responses.sendResponseForMethod(stream, status_code, status_text, content_type, body, close_connection, is_head, http1ResponseContext());
}

fn sendConfiguredRedirect(stream: std.Io.net.Stream, allocator: std.mem.Allocator, rule: RedirectRule, req: HttpRequest, close_connection: bool, is_head: bool) !void {
    try http1_responses.sendConfiguredRedirect(stream, allocator, rule, req, close_connection, is_head, http1ResponseContext());
}

fn sendHttpsRedirect(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, req: HttpRequest, close_connection: bool, is_head: bool) !void {
    try http1_responses.sendHttpsRedirect(stream, allocator, cfg, req, close_connection, is_head, http1ResponseContext());
}

fn sendServerIcon(stream: std.Io.net.Stream, close_connection: bool, is_head: bool) !void {
    try sendResponseForMethod(stream, 200, "OK", "image/svg+xml", server_assets.SERVER_ICON_SVG, close_connection, is_head);
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

fn adminRenderMetrics(allocator: std.mem.Allocator) ![]const u8 {
    return metrics_mod.render(allocator, &server_metrics);
}

fn adminRequestRestart() void {
    shutdown_requested.store(true, .release);
}

fn adminCallbacks() admin_runtime.Callbacks {
    return .{
        .active_io = activeIo,
        .bind_thread_io = bindThreadIo,
        .close_stream = streamClose,
        .read_stream = streamRead,
        .render_metrics = adminRenderMetrics,
        .request_restart = adminRequestRestart,
        .runtime_view = adminRuntimeView,
        .send_dashboard_page = sendAdminDashboardPage,
        .send_login_page = sendAdminLoginPage,
        .send_method_not_allowed = sendMethodNotAllowedWithAllow,
        .send_redirect = sendAdminRedirect,
        .send_response_no_body = sendResponseNoBodyWithConnectionAndHeaders,
        .send_setup_page = sendAdminSetupPage,
        .set_stream_timeouts = setStreamTimeouts,
        .shutdown_requested = &shutdown_requested,
        .validate_activation = validateConfigFileForActivation,
        .validate_runtime = validateConfig,
        .write_all = streamWriteAll,
    };
}

fn currentRequestId() []const u8 {
    return current_request_id;
}

fn phpCallbacks() php_runtime.Callbacks {
    return .{
        .active_io = activeIo,
        .connect_fastcgi_endpoint = connectFastcgiEndpoint,
        .current_request_id = currentRequestId,
        .fastcgi_pool = &fastcgi_keepalive_pool,
        .h2_error_response = h2CoolErrorResponse,
        .metrics = &server_metrics,
        .now_ms = upstreamNowMs,
        .send_cool_error = sendCoolErrorWithConnection,
        .send_not_found_for_method = sendNotFoundForMethod,
        .send_response = sendResponseWithConnection,
        .send_response_headers = sendResponseWithConnectionAndHeaders,
        .send_response_no_body = sendResponseNoBodyWithConnection,
        .send_response_no_body_headers = sendResponseNoBodyWithConnectionAndHeaders,
        .server_header = SERVER_HEADER,
        .set_stream_timeouts = setStreamTimeouts,
        .stderr_limit = DEFAULT_MAX_PHP_FASTCGI_STDERR_BYTES,
        .stream_close = streamClose,
        .stream_read = streamRead,
        .stream_write_all = streamWriteAll,
    };
}

fn upstreamRuntimeCallbacks() upstream_runtime.Callbacks {
    return .{
        .access_log_set_upstream = accessLogSetUpstream,
        .active_io = activeIo,
        .bind_thread_io = bindThreadIo,
        .connect_tcp_host = connectTcpHost,
        .current_request_id = currentRequestId,
        .metrics = &server_metrics,
        .proxy_raw_bidirectional = proxyRawBidirectional,
        .send_cool_error = sendCoolErrorWithConnection,
        .set_stream_timeouts = setStreamTimeouts,
        .shutdown_requested = &shutdown_requested,
        .stream_close = streamClose,
        .stream_read = streamRead,
        .stream_write_all = streamWriteAll,
        .upstream_now_ms = upstreamNowMs,
        .write_response_headers = streamWriteConfiguredResponseHeaders,
    };
}

fn sendMethodNotAllowedWithAllow(stream: std.Io.net.Stream, allocator: std.mem.Allocator, allowed_methods: []const u8, close_connection: bool, is_head: bool) !void {
    const allow_header = try std.fmt.allocPrint(allocator, "Allow: {s}\r\n", .{allowed_methods});
    defer allocator.free(allow_header);
    try sendCoolErrorWithConnection(stream, allocator, 405, "Method Not Allowed", "That method is not supported for this endpoint.", close_connection, is_head, allow_header);
}

fn http1StaticCallbacks() http1_static.Callbacks {
    return .{
        .metrics = &server_metrics,
        .send_bad_request_for_method = sendBadRequestForMethod,
        .send_cool_error = sendCoolErrorWithConnection,
        .send_not_found_for_method = sendNotFoundForMethod,
        .send_response = sendResponseWithConnection,
        .send_response_no_body = sendResponseNoBodyWithConnection,
        .send_response_no_body_headers = sendResponseNoBodyWithConnectionAndHeaders,
        .write_all = streamWriteAll,
    };
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
    try http1_static.serveStatic(io, stream, allocator, static_dir, rel_path, request_headers, close_connection, is_head, max_file_bytes, http1StaticCallbacks());
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
    try http1_static.serveAcmeChallenge(io, stream, allocator, webroot, token, close_connection, is_head, http1StaticCallbacks());
}

const RawProxyContext = struct {
    io: std.Io,
    src: std.Io.net.Stream,
    dst: std.Io.net.Stream,
    tls_channel: ?*native_tls.Channel = null,
};

fn proxyRawStream(ctx: RawProxyContext) void {
    bindThreadIo(ctx.io);
    stream_runtime.setTlsChannel(ctx.tls_channel);
    defer stream_runtime.clearTlsChannel();

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
    const tls_channel = stream_runtime.currentTlsChannel();
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

    stream_runtime.setTlsChannel(&established.channel);
    defer stream_runtime.clearTlsChannel();

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

    try http1_runtime.handleConnection(io, stream, cfg, allocator, process_env, http1RuntimeCallbacks());
}

fn sendHttp2Response(stream: std.Io.net.Stream, allocator: std.mem.Allocator, stream_id: u32, response: H2BufferedResponse, is_head: bool) !void {
    var header_block = std.ArrayList(u8).empty;
    defer header_block.deinit(allocator);

    const prepared = try response_body.prepare(allocator, .{
        .status_code = response.status_code,
        .content_type = response.content_type,
        .body = response.body,
        .is_head = is_head,
        .h2_headers = response.headers,
        .request_headers = current_request_headers,
        .response_headers = current_response_headers,
        .compression_policy = current_compression_policy,
        .compression_work_buffer_bytes = DEFAULT_COMPRESSION_WORK_BUFFER_BYTES,
        .metrics = &server_metrics,
    });
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
    return http2_content.coolErrorResponse(allocator, SERVER_NAME, SERVER_TAGLINE, status_code, status_text, detail);
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
    return http2_content.readStaticFile(io, allocator, static_dir, rel_path, max_file_bytes, &server_metrics, SERVER_NAME, SERVER_TAGLINE);
}

fn readAcmeChallengeForHttp2(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig, token: []const u8) !H2BufferedResponse {
    return http2_content.readAcmeChallenge(io, allocator, cfg.letsencrypt_webroot, token, SERVER_NAME, SERVER_TAGLINE);
}

fn buildHttp2RedirectResponse(allocator: std.mem.Allocator, rule: RedirectRule, req: HttpRequest) !H2BufferedResponse {
    return http2_content.redirectResponse(allocator, rule, req);
}

fn fetchHttp2UpstreamPoolResponse(allocator: std.mem.Allocator, pool: *UpstreamPoolConfig, policy: UpstreamPoolPolicy, req: HttpRequest, cfg: *const ServerConfig) !H2BufferedResponse {
    return http2_upstream.fetchPoolResponse(allocator, pool, policy, req, cfg, http2UpstreamCallbacks());
}

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
            return h2_support.textResponse(200, "image/svg+xml", server_assets.SERVER_ICON_SVG);
        }
        if (std.mem.eql(u8, req.path, "/") and domainServeStaticRoot(cfg, domain)) {
            accessLogSetHandler("static_root");
            return readStaticFileForHttp2(io, allocator, domainStaticDir(cfg, domain), domainIndexFile(cfg, domain), cfg.max_static_file_bytes);
        }
        if (std.mem.eql(u8, req.path, "/")) {
            accessLogSetHandler("builtin_root");
            return h2_support.textResponse(200, "text/html; charset=utf-8", server_assets.H2_DEFAULT_PAGE);
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
            if (request_mod.findQueryValue(req.query, "msg")) |msg| {
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

fn http2Callbacks() h2_server.Callbacks {
    return .{
        .send_response = sendHttp2Response,
        .error_response = h2CoolErrorResponse,
        .complete_request = sendCompletedHttp2Request,
        .write_all = streamWriteAll,
        .shutdown_requested = &shutdown_requested,
    };
}

fn http2UpstreamCallbacks() http2_upstream.Callbacks {
    return .{
        .access_log_set_upstream = accessLogSetUpstream,
        .connect_tcp_host = connectTcpHost,
        .current_request_id = currentRequestId,
        .error_response = h2CoolErrorResponse,
        .metrics = &server_metrics,
        .set_stream_timeouts = setStreamTimeouts,
        .stream_close = streamClose,
        .stream_read = streamRead,
        .stream_write_all = streamWriteAll,
        .upstream_now_ms = upstreamNowMs,
    };
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
    try h2_server.runFrameLoop(io, stream, allocator, cfg, &reader, process_env, http2Callbacks());
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
    try h2_server.runFrameLoop(io, stream, allocator, cfg, &reader, process_env, http2Callbacks());
}

fn isHttpUpgradeRequest(req: HttpRequest) bool {
    return proxy_utils.isHttpUpgradeHeaders(req.headers);
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
    try upstream_runtime.forwardToPool(stream, allocator, pool, policy, timeout_ms, req, cfg, upstreamRuntimeCallbacks());
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
    try php_runtime.handleFrontController(io, stream, allocator, cfg, req, route, php_root, php_binary, php_fastcgi, timeout_ms, php_index, close_connection, is_head, process_env, phpCallbacks());
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
    return php_runtime.buildHttp2FastcgiResponse(io, allocator, cfg, req, php_root, php_fastcgi, script_rel_path, script_name, path_info, timeout_ms, phpCallbacks());
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
    try php_runtime.handleScript(io, stream, allocator, cfg, req, php_root, php_binary, php_fastcgi, timeout_ms, script_rel_path, script_name, path_info, close_connection, is_head, process_env, phpCallbacks());
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

fn setHttp1RequestContext(headers: []const u8, policy: CompressionPolicy) void {
    current_request_headers = headers;
    current_compression_policy = policy;
}

fn clearHttp1RequestContext() void {
    current_request_headers = "";
    current_compression_policy = .disabled;
}

fn setHttp1ResponseHeaders(headers: []const ResponseHeaderRule) void {
    current_response_headers = headers;
}

fn clearHttp1ResponseHeaders() void {
    current_response_headers = &.{};
}

fn routeAdminUi(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *ServerConfig, req: HttpRequest, close_connection: bool, is_head: bool) !void {
    try admin_runtime.handleUi(io, stream, allocator, cfg, req, close_connection, is_head, adminCallbacks());
}

fn http1RouterCallbacks() http1_router.Callbacks {
    return .{
        .access_log_set_handler = accessLogSetHandler,
        .clear_request_context = clearHttp1RequestContext,
        .clear_response_headers = clearHttp1ResponseHeaders,
        .forward_to_upstream_pool = forwardToUpstreamPool,
        .handle_admin_ui = routeAdminUi,
        .handle_named_route = handleNamedRoute,
        .handle_php_front_controller = handlePhpFrontController,
        .handle_php_script = handlePhpScript,
        .send_configured_redirect = sendConfiguredRedirect,
        .send_domain_custom_not_found = sendDomainCustomNotFoundForMethod,
        .send_method_not_allowed = sendMethodNotAllowedWithAllow,
        .send_metrics = sendMetrics,
        .send_not_found_for_method = sendNotFoundForMethod,
        .send_not_found_with_connection = sendNotFoundWithConnection,
        .send_not_implemented = sendNotImplemented,
        .send_response = sendResponseWithConnection,
        .send_response_for_method = sendResponseForMethod,
        .send_response_no_body_headers = sendResponseNoBodyWithConnectionAndHeaders,
        .send_server_icon = sendServerIcon,
        .serve_acme_challenge = serveAcmeChallenge,
        .serve_static = serveStatic,
        .set_request_context = setHttp1RequestContext,
        .set_response_headers = setHttp1ResponseHeaders,
    };
}

fn routeRequest(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    req: HttpRequest,
    process_env: *const std.process.Environ.Map,
) !void {
    try http1_router.route(io, stream, allocator, cfg, req, process_env, http1RouterCallbacks());
}

fn resolveRequestId(io: std.Io, allocator: std.mem.Allocator, headers: []const u8) ![]const u8 {
    return request_id_generator.resolve(io, allocator, headers);
}

fn setAccessLogContext(ctx: *access_log_mod.Context, request_id: []const u8) void {
    current_access_log = ctx;
    current_request_id = request_id;
}

fn clearAccessLogContext() void {
    current_access_log = null;
    current_request_id = "";
}

fn http1RuntimeCallbacks() http1_runtime.Callbacks {
    return .{
        .access_log_set_error = accessLogSetError,
        .access_log_set_handler = accessLogSetHandler,
        .bind_thread_io = bindThreadIo,
        .clear_access_context = clearAccessLogContext,
        .clear_request_context = clearHttp1RequestContext,
        .clear_response_headers = clearHttp1ResponseHeaders,
        .emit_access_log = emitAccessLog,
        .handle_http2_preface = handleHttp2Preface,
        .handle_http2_upgrade = handleHttp2Upgrade,
        .handle_tls_client_hello_probe = handleTlsClientHelloProbe,
        .metrics = &server_metrics,
        .resolve_request_id = resolveRequestId,
        .route_request = routeRequest,
        .send_bad_request = sendBadRequest,
        .send_bad_request_for_method = sendBadRequestForMethod,
        .send_cool_error = sendCoolError,
        .send_cool_error_with_connection = sendCoolErrorWithConnection,
        .send_https_redirect = sendHttpsRedirect,
        .serve_acme_challenge = serveAcmeChallenge,
        .set_access_context = setAccessLogContext,
        .set_request_context = setHttp1RequestContext,
        .set_response_headers = setHttp1ResponseHeaders,
        .set_stream_read_timeout = setStreamReadTimeout,
        .set_stream_timeouts = setStreamTimeouts,
        .set_stream_write_timeout = setStreamWriteTimeout,
        .shutdown_requested = &shutdown_requested,
        .stream_close = streamClose,
        .stream_read = streamRead,
        .stream_write_all = streamWriteAll,
    };
}

fn dumpRoutes(cfg: *const ServerConfig) void {
    cli_output.dumpRoutes(cfg);
}

fn usage() void {
    cli_output.usage();
}

// Bootstraps config/CLI, optional cert automation, then starts the accept loop.
pub fn main(init: std.process.Init) !void {
    bindThreadIo(init.io);
    installShutdownSignalHandlers();
    shutdown_requested.store(false, .release);
    listener_closed_by_shutdown.store(false, .release);

    var cfg = defaultServerConfig();

    if (!(try cli_config.prepare(init, std.heap.page_allocator, &cfg, .{ .usage = usage, .dump_routes = dumpRoutes }))) return;

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

    var concurrency = ConcurrencyState.init(&server_metrics);

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
            http1_runtime.serveHttpRedirectListenerTask,
            .{http1_runtime.HttpRedirectListenerContext{ .io = init.io, .server = http_server, .cfg = &cfg, .allocator = std.heap.page_allocator, .state = &concurrency, .callbacks = http1RuntimeCallbacks() }},
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
                if (cfg.upstream_keepalive_enabled and cfg.upstream_keepalive_max_idle > 0) "on" else "off",
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
        const health_worker = std.Thread.spawn(.{}, upstream_runtime.healthCheckTask, .{upstream_runtime.HealthCheckContext{ .io = init.io, .cfg = &cfg, .callbacks = upstreamRuntimeCallbacks() }}) catch |err| {
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
        const admin_worker = std.Thread.spawn(.{}, admin_runtime.serveSocketTask, .{admin_runtime.SocketContext{ .io = init.io, .cfg = &cfg, .socket_path = admin_socket_path, .callbacks = adminCallbacks() }}) catch |err| {
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
            http1_runtime.serveConnectionTask,
            .{
                init.io,
                conn,
                &cfg,
                std.heap.page_allocator,
                &concurrency,
                init.environ_map,
                http1RuntimeCallbacks(),
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
    concurrency_mod.waitForDrain(init.io, &concurrency, cfg.graceful_shutdown_timeout_ms);
    if (cfg.admin_enabled) {
        admin_runtime.unlinkUnixSocket(cfg.admin_socket_path orelse DEFAULT_ADMIN_SOCKET_PATH, adminCallbacks());
    }
}
