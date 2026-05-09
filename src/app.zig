const std = @import("std");
const admin_http = @import("admin_http.zig");
const admin_pages = @import("admin_pages.zig");
const admin_runtime = @import("admin_runtime.zig");
const admin_support = @import("admin_support.zig");
const acme_mod = @import("acme.zig");
const cli_config = @import("cli_config.zig");
const cli_output = @import("cli_output.zig");
const config_loader = @import("config_loader.zig");
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
const http1_response_bridge = @import("http1_response_bridge.zig");
const http1_runtime = @import("http1_runtime.zig");
const http1_static = @import("http1_static.zig");
const metrics_mod = @import("metrics.zig");
const native_tls = @import("native_tls_runtime.zig");
const php_runtime = @import("php_runtime.zig");
const proxy_utils = @import("proxy_utils.zig");
const raw_proxy = @import("raw_proxy.zig");
const request_mod = @import("request.zig");
const runtime_state = @import("runtime_state.zig");
const server_runtime = @import("server_runtime.zig");
const server_identity = @import("server_identity.zig");
const static_cache = @import("static_cache.zig");
const stream_runtime = @import("stream_runtime.zig");
const tls_accept = @import("tls_accept.zig");
const tls_material = @import("tls_material.zig");
const upstream_runtime = @import("upstream_runtime.zig");

const AdminCredentials = admin_support.AdminCredentials;
const ensureCloudflareDeployment = acme_mod.ensureCloudflareDeployment;
const ensureLetsEncryptSetup = acme_mod.ensureLetsEncryptSetup;
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
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const UpstreamRuntimePolicy = config_mod.UpstreamRuntimePolicy;
const RedirectRule = config_mod.RedirectRule;
const RouteConfig = config_mod.RouteConfig;
const DomainConfig = config_mod.DomainConfig;
const ServerConfig = config_mod.ServerConfig;
const defaultServerConfig = config_mod.defaultServerConfig;
const loadConfig = config_loader.loadConfig;
const loadConfiguredDomainConfigs = config_loader.loadConfiguredDomainConfigs;
const normalizeConfig = config_mod.normalizeConfig;
const validateConfig = config_mod.validateConfig;

const DEFAULT_MAX_PHP_FASTCGI_STDERR_BYTES = server_identity.max_php_fastcgi_stderr_bytes;
const DEFAULT_COMPRESSION_WORK_BUFFER_BYTES = http1_response_bridge.compression_work_buffer_bytes;
const DEFAULT_ADMIN_SOCKET_PATH = server_identity.default_admin_socket_path;
const SERVER_NAME = server_identity.name;
const SERVER_TAGLINE = server_identity.tagline;
const SERVER_HEADER = server_identity.header;

const streamWriteRequestIdHeader = http1_response_bridge.streamWriteRequestIdHeader;
const streamWriteConfiguredResponseHeaders = http1_response_bridge.streamWriteConfiguredResponseHeaders;
const sendCoolErrorWithConnection = http1_response_bridge.sendCoolErrorWithConnection;
const sendCoolError = http1_response_bridge.sendCoolError;
const sendResponseWithConnectionAndHeaders = http1_response_bridge.sendResponseWithConnectionAndHeaders;
const sendResponseWithConnection = http1_response_bridge.sendResponseWithConnection;
const sendResponse = http1_response_bridge.sendResponse;
const sendResponseNoBodyWithConnectionAndHeaders = http1_response_bridge.sendResponseNoBodyWithConnectionAndHeaders;
const sendResponseNoBodyWithConnection = http1_response_bridge.sendResponseNoBodyWithConnection;
const sendNotFoundWithConnection = http1_response_bridge.sendNotFoundWithConnection;
const sendNotFoundForMethod = http1_response_bridge.sendNotFoundForMethod;
const sendDomainCustomNotFoundForMethod = http1_response_bridge.sendDomainCustomNotFoundForMethod;
const sendBadRequest = http1_response_bridge.sendBadRequest;
const sendBadRequestForMethod = http1_response_bridge.sendBadRequestForMethod;
const sendNotImplemented = http1_response_bridge.sendNotImplemented;
const sendResponseForMethod = http1_response_bridge.sendResponseForMethod;
const sendConfiguredRedirect = http1_response_bridge.sendConfiguredRedirect;
const sendHttpsRedirect = http1_response_bridge.sendHttpsRedirect;
const sendServerIcon = http1_response_bridge.sendServerIcon;
const recordResponseSent = http1_response_bridge.recordResponseSent;
const sendMetrics = http1_response_bridge.sendMetrics;
const emitAccessLog = http1_response_bridge.emitAccessLog;

fn shutdownSignalHandler(_: std.posix.SIG) callconv(.c) void {
    runtime_state.shutdown_requested.store(true, .release);
}

fn reloadSignalHandler(_: std.posix.SIG) callconv(.c) void {
    runtime_state.reload_requested.store(true, .release);
}

fn installProcessSignalHandlers() void {
    if (std.posix.Sigaction == void) return;
    const shutdown_action: std.posix.Sigaction = .{
        .handler = .{ .handler = shutdownSignalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    const reload_action: std.posix.Sigaction = .{
        .handler = .{ .handler = reloadSignalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &shutdown_action, null);
    std.posix.sigaction(.TERM, &shutdown_action, null);
    std.posix.sigaction(.HUP, &reload_action, null);
}

fn loadAllConfiguredTlsMaterials(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
    return tls_material.loadAll(io, allocator, cfg);
}

fn deinitConfiguredTlsMaterials(allocator: std.mem.Allocator, cfg: *ServerConfig) void {
    tls_material.deinitAll(allocator, cfg);
}

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

fn optionalStringEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?, b.?);
}

fn validateReloadCompatibility(active: *const ServerConfig, candidate: *const ServerConfig) !void {
    if (!std.mem.eql(u8, active.host, candidate.host)) return error.ReloadRequiresRestart;
    if (active.port != candidate.port) return error.ReloadRequiresRestart;
    if (active.tls_enabled != candidate.tls_enabled) return error.ReloadRequiresRestart;
    if (active.tls_auto != candidate.tls_auto) return error.ReloadRequiresRestart;
    if (active.http_redirect_enabled != candidate.http_redirect_enabled) return error.ReloadRequiresRestart;
    if (active.http_redirect_port != candidate.http_redirect_port) return error.ReloadRequiresRestart;
    if (active.http_redirect_https_port != candidate.http_redirect_https_port) return error.ReloadRequiresRestart;
    if (active.http3_enabled != candidate.http3_enabled) return error.ReloadRequiresRestart;
    if (active.http3_port != candidate.http3_port) return error.ReloadRequiresRestart;
    if (active.admin_enabled != candidate.admin_enabled) return error.ReloadRequiresRestart;
    if (!optionalStringEql(active.admin_socket_path, candidate.admin_socket_path)) return error.ReloadRequiresRestart;
}

fn reloadConfigInMemory(io: std.Io, allocator: std.mem.Allocator, active: *const ServerConfig) !void {
    const arena = try allocator.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer {
        arena.deinit();
        allocator.destroy(arena);
    }

    const candidate_allocator = arena.allocator();
    const candidate = try candidate_allocator.create(ServerConfig);
    candidate.* = defaultServerConfig();
    candidate.config_path = active.config_path;
    try loadConfig(io, candidate_allocator, candidate, candidate.config_path);
    try loadConfiguredDomainConfigs(io, candidate_allocator, candidate);
    normalizeConfig(candidate);
    try validateConfig(candidate);
    try validateReloadCompatibility(active, candidate);
    try loadAllConfiguredTlsMaterials(io, candidate_allocator, candidate);
    try runtime_state.config_store.activateOwned(allocator, arena, candidate);
}

const ReloadSignalWatcherContext = struct {
    io: std.Io,
};

fn reloadSignalWatcherTask(ctx: ReloadSignalWatcherContext) void {
    bindThreadIo(ctx.io);
    while (!runtime_state.shutdown_requested.load(.acquire)) {
        if (runtime_state.reload_requested.swap(false, .acq_rel)) {
            reloadConfigInMemory(ctx.io, std.heap.page_allocator, runtime_state.activeConfig()) catch |err| {
                std.debug.print("SIGHUP reload blocked: {}\n", .{err});
                continue;
            };
            std.debug.print("SIGHUP config reload completed for new connections.\n", .{});
        }
        ctx.io.sleep(.fromMilliseconds(100), .awake) catch {};
    }
}

fn startReloadSignalWatcher(io: std.Io) void {
    const worker = std.Thread.spawn(.{}, reloadSignalWatcherTask, .{ReloadSignalWatcherContext{ .io = io }}) catch |err| {
        std.debug.print("Failed to start SIGHUP reload watcher: {}\n", .{err});
        return;
    };
    worker.detach();
}

fn adminRuntimeView() admin_pages.RuntimeView {
    return .{ .server_name = SERVER_NAME, .metrics = &runtime_state.server_metrics };
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

fn adminRenderMetrics(allocator: std.mem.Allocator) ![]const u8 {
    return metrics_mod.render(allocator, &runtime_state.server_metrics);
}

fn adminRequestRestart() void {
    runtime_state.shutdown_requested.store(true, .release);
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
        .active_config = runtime_state.activeConfig,
        .active_io = activeIo,
        .bind_thread_io = bindThreadIo,
        .close_stream = streamClose,
        .read_stream = streamRead,
        .reload_config = reloadConfigInMemory,
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
        .shutdown_requested = &runtime_state.shutdown_requested,
        .validate_activation = validateConfigFileForActivation,
        .validate_runtime = validateConfig,
        .write_all = streamWriteAll,
    };
}

fn phpCallbacks() php_runtime.Callbacks {
    return .{
        .active_io = activeIo,
        .connect_fastcgi_endpoint = connectFastcgiEndpoint,
        .current_request_id = runtime_state.currentRequestId,
        .fastcgi_pool = &runtime_state.fastcgi_keepalive_pool,
        .h2_error_response = h2CoolErrorResponse,
        .metrics = &runtime_state.server_metrics,
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
        .access_log_set_upstream = runtime_state.accessLogSetUpstream,
        .active_io = activeIo,
        .bind_thread_io = bindThreadIo,
        .connect_tcp_host = connectTcpHost,
        .current_request_id = runtime_state.currentRequestId,
        .metrics = &runtime_state.server_metrics,
        .proxy_raw_bidirectional = proxyRawBidirectional,
        .send_cool_error = sendCoolErrorWithConnection,
        .set_stream_timeouts = setStreamTimeouts,
        .shutdown_requested = &runtime_state.shutdown_requested,
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
        .metrics = &runtime_state.server_metrics,
        .response_cache = &runtime_state.static_response_cache,
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
    response_cache_policy: static_cache.Policy,
) !void {
    try http1_static.serveStatic(io, stream, allocator, static_dir, rel_path, request_headers, close_connection, is_head, max_file_bytes, response_cache_policy, http1StaticCallbacks());
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
        .request_id = runtime_state.current_request_id,
        .request_headers = runtime_state.current_request_headers,
        .response_headers = runtime_state.current_response_headers,
        .compression_policy = runtime_state.current_compression_policy,
        .compression_work_buffer_bytes = DEFAULT_COMPRESSION_WORK_BUFFER_BYTES,
        .metrics = &runtime_state.server_metrics,
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

fn readStaticFileForHttp2(io: std.Io, allocator: std.mem.Allocator, static_dir: []const u8, rel_path: []const u8, max_file_bytes: usize, response_cache_policy: static_cache.Policy) !H2BufferedResponse {
    return http2_content.readStaticFile(io, allocator, static_dir, rel_path, max_file_bytes, &runtime_state.server_metrics, &runtime_state.static_response_cache, response_cache_policy, SERVER_NAME, SERVER_TAGLINE);
}

fn readAcmeChallengeForHttp2(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig, token: []const u8) !H2BufferedResponse {
    return http2_content.readAcmeChallenge(io, allocator, cfg.letsencrypt_webroot, token, SERVER_NAME, SERVER_TAGLINE);
}

fn buildHttp2RedirectResponse(allocator: std.mem.Allocator, rule: RedirectRule, req: HttpRequest) !H2BufferedResponse {
    return http2_content.redirectResponse(allocator, rule, req);
}

fn fetchHttp2UpstreamPoolResponse(allocator: std.mem.Allocator, pool: *UpstreamPoolConfig, policy: UpstreamPoolPolicy, runtime_policy: UpstreamRuntimePolicy, req: HttpRequest, cfg: *const ServerConfig) !H2BufferedResponse {
    return http2_upstream.fetchPoolResponse(allocator, pool, policy, runtime_policy, req, cfg, http2UpstreamCallbacks());
}

fn buildHttp2ResponseForRequest(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig, req: HttpRequest, process_env: *const std.process.Environ.Map) !H2BufferedResponse {
    return http2_router.buildResponseForRequest(io, allocator, cfg, req, process_env, http2RouterCallbacks());
}

fn http2CompleteContext() http2_runtime.CompleteContext {
    return .{
        .metrics = &runtime_state.server_metrics,
        .resolve_request_id = runtime_state.resolveRequestId,
        .set_request_context = runtime_state.setHttp2RequestContext,
        .clear_request_context = runtime_state.clearHttp2RequestContext,
        .set_access_context = runtime_state.setAccessLogContext,
        .clear_access_context = runtime_state.clearAccessLogContext,
        .access_log_set_handler = runtime_state.accessLogSetHandler,
        .access_log_set_error = runtime_state.accessLogSetError,
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
        .shutdown_requested = &runtime_state.shutdown_requested,
    };
}

fn http2RouterCallbacks() http2_router.Callbacks {
    return .{
        .access_log_set_handler = runtime_state.accessLogSetHandler,
        .custom_not_found_response = h2DomainCustomNotFoundResponse,
        .error_response = h2CoolErrorResponse,
        .fetch_upstream_pool_response = fetchHttp2UpstreamPoolResponse,
        .metrics = &runtime_state.server_metrics,
        .php_callbacks = phpCallbacks(),
        .read_acme_challenge = readAcmeChallengeForHttp2,
        .read_static_file = readStaticFileForHttp2,
        .redirect_response = buildHttp2RedirectResponse,
        .set_compression_policy = runtime_state.setCompressionPolicy,
        .set_response_headers = runtime_state.setResponseHeaders,
    };
}

fn http2UpstreamCallbacks() http2_upstream.Callbacks {
    return .{
        .access_log_set_upstream = runtime_state.accessLogSetUpstream,
        .connect_tcp_host = connectTcpHost,
        .current_request_id = runtime_state.currentRequestId,
        .error_response = h2CoolErrorResponse,
        .metrics = &runtime_state.server_metrics,
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
    runtime_policy: UpstreamRuntimePolicy,
    req: HttpRequest,
    cfg: *const ServerConfig,
) !void {
    try upstream_runtime.forwardToPool(stream, allocator, pool, policy, runtime_policy, req, cfg, upstreamRuntimeCallbacks());
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
        .access_log_set_handler = runtime_state.accessLogSetHandler,
        .forward_to_upstream_pool = forwardToUpstreamPool,
        .php_callbacks = phpCallbacks(),
        .send_cool_error = sendCoolErrorWithConnection,
        .send_method_not_allowed = sendMethodNotAllowedWithAllow,
        .send_not_found_for_method = sendNotFoundForMethod,
        .send_response_no_body_headers = sendResponseNoBodyWithConnectionAndHeaders,
        .serve_static = serveStatic,
    });
}

fn routeAdminUi(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *ServerConfig, req: HttpRequest, close_connection: bool, is_head: bool) !void {
    try admin_runtime.handleUi(io, stream, allocator, cfg, req, close_connection, is_head, adminCallbacks());
}

fn http1RouterCallbacks() http1_router.Callbacks {
    return .{
        .access_log_set_handler = runtime_state.accessLogSetHandler,
        .clear_request_context = runtime_state.clearHttp1RequestContext,
        .clear_response_headers = runtime_state.clearResponseHeaders,
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
        .set_request_context = runtime_state.setHttp1RequestContext,
        .set_response_headers = runtime_state.setResponseHeaders,
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

fn http1RuntimeCallbacks() http1_runtime.Callbacks {
    return .{
        .access_log_set_error = runtime_state.accessLogSetError,
        .access_log_set_handler = runtime_state.accessLogSetHandler,
        .active_config = runtime_state.activeConfig,
        .bind_thread_io = bindThreadIo,
        .clear_access_context = runtime_state.clearAccessLogContext,
        .clear_request_context = runtime_state.clearHttp1RequestContext,
        .clear_response_headers = runtime_state.clearResponseHeaders,
        .emit_access_log = emitAccessLog,
        .handle_http2_preface = handleHttp2Preface,
        .handle_http2_upgrade = handleHttp2Upgrade,
        .handle_tls_client_hello_probe = handleTlsClientHelloProbe,
        .metrics = &runtime_state.server_metrics,
        .resolve_request_id = runtime_state.resolveRequestId,
        .route_request = routeRequest,
        .send_bad_request = sendBadRequest,
        .send_bad_request_for_method = sendBadRequestForMethod,
        .send_cool_error = sendCoolError,
        .send_cool_error_with_connection = sendCoolErrorWithConnection,
        .send_https_redirect = sendHttpsRedirect,
        .serve_acme_challenge = serveAcmeChallenge,
        .set_access_context = runtime_state.setAccessLogContext,
        .set_request_context = runtime_state.setHttp1RequestContext,
        .set_response_headers = runtime_state.setResponseHeaders,
        .set_stream_read_timeout = setStreamReadTimeout,
        .set_stream_timeouts = setStreamTimeouts,
        .set_stream_write_timeout = setStreamWriteTimeout,
        .shutdown_requested = &runtime_state.shutdown_requested,
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
    installProcessSignalHandlers();
    runtime_state.shutdown_requested.store(false, .release);
    runtime_state.reload_requested.store(false, .release);

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
    try runtime_state.config_store.installInitial(std.heap.page_allocator, &cfg);
    startReloadSignalWatcher(init.io);
    defer runtime_state.config_store.deinit();
    defer {
        runtime_state.static_response_cache.deinit();
        deinitConfiguredTlsMaterials(std.heap.page_allocator, &cfg);
    }

    try server_runtime.run(.{
        .io = init.io,
        .allocator = std.heap.page_allocator,
        .cfg = &cfg,
        .process_env = init.environ_map,
        .metrics = &runtime_state.server_metrics,
        .response_cache = &runtime_state.static_response_cache,
        .shutdown_requested = &runtime_state.shutdown_requested,
        .default_admin_socket_path = DEFAULT_ADMIN_SOCKET_PATH,
        .server_header = SERVER_HEADER,
        .callbacks = .{
            .active_config = runtime_state.activeConfig,
            .admin = adminCallbacks(),
            .bind_thread_io = bindThreadIo,
            .http1 = http1RuntimeCallbacks(),
            .send_cool_error = sendCoolError,
            .upstream = upstreamRuntimeCallbacks(),
        },
    });
}
