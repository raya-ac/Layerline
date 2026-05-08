const std = @import("std");
const admin_http = @import("admin_http.zig");
const access_log_mod = @import("access_log.zig");
const admin_pages = @import("admin_pages.zig");
const admin_runtime = @import("admin_runtime.zig");
const admin_support = @import("admin_support.zig");
const acme_mod = @import("acme.zig");
const cli_config = @import("cli_config.zig");
const cli_output = @import("cli_output.zig");
const config_mod = @import("config.zig");
const custom_errors = @import("custom_errors.zig");
const h2_server = @import("http2_server.zig");
const h2_support = @import("http2_support.zig");
const http2_content = @import("http2_content.zig");
const http2_router = @import("http2_router.zig");
const http2_runtime = @import("http2_runtime.zig");
const http2_upstream = @import("http2_upstream.zig");
const http1_route_handlers = @import("http1_route_handlers.zig");
const http1_router = @import("http1_router.zig");
const http1_responses = @import("http1_responses.zig");
const http1_runtime = @import("http1_runtime.zig");
const http1_static = @import("http1_static.zig");
const http_headers = @import("http_headers.zig");
const metrics_mod = @import("metrics.zig");
const native_tls = @import("native_tls_runtime.zig");
const php_runtime = @import("php_runtime.zig");
const proxy_utils = @import("proxy_utils.zig");
const raw_proxy = @import("raw_proxy.zig");
const request_mod = @import("request.zig");
const request_trace = @import("request_trace.zig");
const server_runtime = @import("server_runtime.zig");
const server_assets = @import("server_assets.zig");
const static_files = @import("static_files.zig");
const stream_runtime = @import("stream_runtime.zig");
const tls_accept = @import("tls_accept.zig");
const tls_material = @import("tls_material.zig");
const upstream_runtime = @import("upstream_runtime.zig");

const hasConnectionToken = http_headers.hasConnectionToken;
const AdminCredentials = admin_support.AdminCredentials;
const adminPathMatches = admin_support.adminPathMatches;
const certbotWebrootFromAcmeConfig = acme_mod.certbotWebrootFromAcmeConfig;
const ensureCloudflareDeployment = acme_mod.ensureCloudflareDeployment;
const ensureLetsEncryptSetup = acme_mod.ensureLetsEncryptSetup;
const ServerMetrics = metrics_mod.ServerMetrics;
const isSkippedProxyResponseHeader = proxy_utils.isSkippedProxyResponseHeader;
const ByteRange = static_files.ByteRange;
const acceptsContentCoding = static_files.acceptsContentCoding;
const etagMatches = static_files.etagMatches;
const makeStaticBaseHeaders = static_files.makeStaticBaseHeaders;
const parseByteRange = static_files.parseByteRange;
const HttpRequest = request_mod.HttpRequest;
const activeIo = stream_runtime.activeIo;
const bindThreadIo = stream_runtime.bindThreadIo;
const connectFastcgiEndpoint = stream_runtime.connectFastcgiEndpoint;
const connectTcpHost = stream_runtime.connectTcpHost;
const rawStreamRead = stream_runtime.rawStreamRead;
const rawStreamWriteAll = stream_runtime.rawStreamWriteAll;
const setStreamReadTimeout = stream_runtime.setStreamReadTimeout;
const setStreamTimeouts = stream_runtime.setStreamTimeouts;
const setStreamWriteTimeout = stream_runtime.setStreamWriteTimeout;
const streamClose = stream_runtime.streamClose;
const streamRead = stream_runtime.streamRead;
const streamWriteAll = stream_runtime.streamWriteAll;
const H2BufferedResponse = h2_support.BufferedResponse;
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

fn loadAllConfiguredTlsMaterials(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
    return tls_material.loadAll(io, allocator, cfg);
}

fn deinitConfiguredTlsMaterials(allocator: std.mem.Allocator, cfg: *ServerConfig) void {
    tls_material.deinitAll(allocator, cfg);
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

fn sendDomainCustomNotFoundForMethod(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    domain: ?*const DomainConfig,
    close_connection: bool,
    is_head: bool,
) !void {
    try custom_errors.sendHttp1DomainNotFound(io, stream, allocator, cfg, domain, close_connection, is_head, .{
        .send_not_found_for_method = sendNotFoundForMethod,
        .send_response_for_method = sendResponseForMethod,
    });
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
    try admin_http.sendRedirect(stream, allocator, cfg, cookie, close_connection, is_head, adminHttpCallbacks());
}

fn sendAdminSetupPage(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, maybe_error: ?[]const u8, status_code: u16, status_text: []const u8, close_connection: bool, is_head: bool) !void {
    try admin_http.sendSetupPage(stream, allocator, cfg, maybe_error, status_code, status_text, close_connection, is_head, adminHttpCallbacks());
}

fn sendAdminLoginPage(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, maybe_error: ?[]const u8, status_code: u16, status_text: []const u8, close_connection: bool, is_head: bool) !void {
    try admin_http.sendLoginPage(stream, allocator, cfg, maybe_error, status_code, status_text, close_connection, is_head, adminHttpCallbacks());
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
    try admin_http.sendDashboardPage(io, stream, allocator, cfg, credentials, maybe_notice, maybe_error, status_code, status_text, close_connection, is_head, adminHttpCallbacks());
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

fn adminHttpCallbacks() admin_http.Callbacks {
    return .{
        .runtime_view = adminRuntimeView,
        .send_response_headers = sendResponseWithConnectionAndHeaders,
        .send_response_no_body_headers = sendResponseNoBodyWithConnectionAndHeaders,
        .validate_activation = validateConfigFileForActivation,
    };
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
    try http1_route_handlers.sendMethodNotAllowedWithAllow(stream, allocator, allowed_methods, close_connection, is_head, .{
        .send_cool_error = sendCoolErrorWithConnection,
    });
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

fn setTlsChannel(channel: ?*native_tls.Channel) void {
    stream_runtime.setTlsChannel(channel);
}

fn clearTlsChannel() void {
    stream_runtime.clearTlsChannel();
}

fn currentTlsChannel() ?*native_tls.Channel {
    return stream_runtime.currentTlsChannel();
}

fn rawProxyCallbacks() raw_proxy.Callbacks {
    return .{
        .active_io = activeIo,
        .bind_thread_io = bindThreadIo,
        .clear_tls_channel = clearTlsChannel,
        .current_tls_channel = currentTlsChannel,
        .set_tls_channel = setTlsChannel,
        .stream_read = streamRead,
        .stream_write_all = streamWriteAll,
    };
}

fn proxyRawBidirectional(a: std.Io.net.Stream, b: std.Io.net.Stream, initial_payload: []const u8) !void {
    try raw_proxy.proxyBidirectional(a, b, initial_payload, rawProxyCallbacks());
}

fn handleHttp1ConnectionFromTls(
    io: std.Io,
    stream: std.Io.net.Stream,
    cfg: *ServerConfig,
    allocator: std.mem.Allocator,
    process_env: *const std.process.Environ.Map,
) !void {
    try http1_runtime.handleConnection(io, stream, cfg, allocator, process_env, http1RuntimeCallbacks());
}

fn tlsAcceptCallbacks() tls_accept.Callbacks {
    return .{
        .active_io = activeIo,
        .clear_tls_channel = clearTlsChannel,
        .handle_http1_connection = handleHttp1ConnectionFromTls,
        .handle_http2_preface = handleHttp2Preface,
        .raw_stream_read = rawStreamRead,
        .raw_stream_write_all = rawStreamWriteAll,
        .set_tls_channel = setTlsChannel,
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
    try tls_accept.handleClientHelloProbe(io, stream, allocator, cfg, prefill, process_env, tlsAcceptCallbacks());
}

fn http2SendContext() http2_runtime.SendContext {
    return .{
        .server_header = SERVER_HEADER,
        .request_id = current_request_id,
        .request_headers = current_request_headers,
        .response_headers = current_response_headers,
        .compression_policy = current_compression_policy,
        .compression_work_buffer_bytes = DEFAULT_COMPRESSION_WORK_BUFFER_BYTES,
        .metrics = &server_metrics,
        .stream_write_all = streamWriteAll,
        .record_response_sent = recordResponseSent,
    };
}

fn sendHttp2Response(stream: std.Io.net.Stream, allocator: std.mem.Allocator, stream_id: u32, response: H2BufferedResponse, is_head: bool) !void {
    try http2_runtime.sendResponse(stream, allocator, stream_id, response, is_head, http2SendContext());
}

fn h2CoolErrorResponse(allocator: std.mem.Allocator, status_code: u16, status_text: []const u8, detail: []const u8) !H2BufferedResponse {
    return http2_runtime.coolErrorResponse(allocator, SERVER_NAME, SERVER_TAGLINE, status_code, status_text, detail);
}

fn h2DomainCustomNotFoundResponse(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    domain: ?*const DomainConfig,
) !?H2BufferedResponse {
    return custom_errors.h2DomainNotFoundResponse(io, allocator, cfg, domain);
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
    return http2_router.buildResponseForRequest(io, allocator, cfg, req, process_env, http2RouterCallbacks());
}

fn setHttp2RequestContext(headers: []const u8, request_id: []const u8, policy: CompressionPolicy) void {
    current_request_headers = headers;
    current_request_id = request_id;
    current_compression_policy = policy;
}

fn clearHttp2RequestContext() void {
    current_request_headers = "";
    current_request_id = "";
    current_compression_policy = .disabled;
    current_response_headers = &.{};
}

fn http2CompleteContext() http2_runtime.CompleteContext {
    return .{
        .metrics = &server_metrics,
        .resolve_request_id = resolveRequestId,
        .set_request_context = setHttp2RequestContext,
        .clear_request_context = clearHttp2RequestContext,
        .set_access_context = setAccessLogContext,
        .clear_access_context = clearAccessLogContext,
        .access_log_set_handler = accessLogSetHandler,
        .access_log_set_error = accessLogSetError,
        .emit_access_log = emitAccessLog,
        .build_response_for_request = buildHttp2ResponseForRequest,
        .cool_error_response = h2CoolErrorResponse,
        .send_response = sendHttp2Response,
    };
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
    try http2_runtime.completeRequest(io, stream, allocator, cfg, process_env, stream_id, req, http2CompleteContext());
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

fn http2RouterCallbacks() http2_router.Callbacks {
    return .{
        .access_log_set_handler = accessLogSetHandler,
        .custom_not_found_response = h2DomainCustomNotFoundResponse,
        .error_response = h2CoolErrorResponse,
        .fetch_upstream_pool_response = fetchHttp2UpstreamPoolResponse,
        .metrics = &server_metrics,
        .php_callbacks = phpCallbacks(),
        .read_acme_challenge = readAcmeChallengeForHttp2,
        .read_static_file = readStaticFileForHttp2,
        .redirect_response = buildHttp2RedirectResponse,
        .set_response_headers = setHttp1ResponseHeaders,
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

fn http2ConnectionContext() http2_runtime.ConnectionContext {
    return .{
        .server_header = SERVER_HEADER,
        .stream_read = streamRead,
        .stream_write_all = streamWriteAll,
        .write_request_id_header = streamWriteRequestIdHeader,
        .record_response_sent = recordResponseSent,
        .send_cool_error_with_connection = sendCoolErrorWithConnection,
        .build_response_for_request = buildHttp2ResponseForRequest,
        .cool_error_response = h2CoolErrorResponse,
        .send_response = sendHttp2Response,
        .frame_callbacks = http2Callbacks(),
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
    try http2_runtime.handlePreface(io, stream, allocator, cfg, prefill, process_env, http2ConnectionContext());
}

fn handleHttp2Upgrade(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    req: HttpRequest,
    process_env: *const std.process.Environ.Map,
) !void {
    try http2_runtime.handleUpgrade(io, stream, allocator, cfg, req, process_env, http2ConnectionContext());
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
    try http1_route_handlers.handleNamedRoute(io, stream, allocator, cfg, domain, route, req, close_connection, is_head, process_env, .{
        .access_log_set_handler = accessLogSetHandler,
        .forward_to_upstream_pool = forwardToUpstreamPool,
        .php_callbacks = phpCallbacks(),
        .send_cool_error = sendCoolErrorWithConnection,
        .send_method_not_allowed = sendMethodNotAllowedWithAllow,
        .send_not_found_for_method = sendNotFoundForMethod,
        .send_response_no_body_headers = sendResponseNoBodyWithConnectionAndHeaders,
        .serve_static = serveStatic,
    });
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
        .php_callbacks = phpCallbacks(),
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

    try server_runtime.run(.{
        .io = init.io,
        .allocator = std.heap.page_allocator,
        .cfg = &cfg,
        .process_env = init.environ_map,
        .metrics = &server_metrics,
        .shutdown_requested = &shutdown_requested,
        .default_admin_socket_path = DEFAULT_ADMIN_SOCKET_PATH,
        .server_header = SERVER_HEADER,
        .callbacks = .{
            .admin = adminCallbacks(),
            .bind_thread_io = bindThreadIo,
            .http1 = http1RuntimeCallbacks(),
            .send_cool_error = sendCoolError,
            .upstream = upstreamRuntimeCallbacks(),
        },
    });
}
