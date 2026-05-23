const std = @import("std");

const admin_support = @import("admin_support.zig");
const admin_upstreams = @import("admin_upstreams.zig");
const admin_ui = @import("admin_ui.zig");
const config_mod = @import("config.zig");
const metrics_mod = @import("metrics.zig");
const routing = @import("routing.zig");

const AdminCredentials = admin_support.AdminCredentials;
const ServerConfig = config_mod.ServerConfig;

pub const RuntimeView = struct {
    server_name: []const u8,
    metrics: *const metrics_mod.ServerMetrics,
};

pub const ValidateConfigFn = *const fn (std.Io, std.mem.Allocator, *const ServerConfig) anyerror!void;

pub fn renderStatus(allocator: std.mem.Allocator, cfg: *const ServerConfig, runtime: RuntimeView) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"server\":\"{s}\",\"host\":\"{s}\",\"port\":{d},\"http_redirect\":{},\"http_redirect_port\":{d},\"http_redirect_https_port\":{d},\"http3\":{},\"compression\":{},\"admin\":{},\"admin_ui\":{},\"tls\":{},\"tls_auto\":{},\"acme_renew\":{},\"active_connections\":{d},\"requests_total\":{d},\"responses_total\":{d}}}\n",
        .{
            runtime.server_name,
            cfg.host,
            cfg.port,
            cfg.http_redirect_enabled,
            cfg.http_redirect_port,
            cfg.http_redirect_https_port,
            cfg.http3_enabled,
            cfg.compression_enabled,
            cfg.admin_enabled,
            cfg.admin_ui_enabled,
            cfg.tls_enabled,
            cfg.tls_auto,
            cfg.letsencrypt_renew,
            metrics_mod.ServerMetrics.load(&runtime.metrics.active_connections),
            metrics_mod.ServerMetrics.load(&runtime.metrics.requests_total),
            metrics_mod.ServerMetrics.load(&runtime.metrics.responses_total),
        },
    );
}

pub fn renderRoutes(allocator: std.mem.Allocator, cfg: *const ServerConfig) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    const global_cache = config_mod.responseCachePolicyFor(cfg, null, null);
    const global_upstream = config_mod.upstreamRuntimePolicyFor(cfg, null, null);
    try out.print(
        allocator,
        "global host={s} port={d} static_dir={s} index={s} security={s} response_cache={s} upstream_timeout_ms={d} upstream_retries={d} upstream_health={s}\n",
        .{ cfg.host, cfg.port, cfg.static_dir, cfg.index_file, config_mod.securityHeaderPresetName(cfg.security_headers), boolText(global_cache.enabled), global_upstream.timeout_ms, global_upstream.retries, boolText(global_upstream.health_check_enabled) },
    );
    if (cfg.http_redirect_enabled) {
        try out.print(allocator, "http_redirect port={d} https_port={d} status={d} webroot={s}\n", .{ cfg.http_redirect_port, cfg.http_redirect_https_port, cfg.http_redirect_status, cfg.letsencrypt_webroot });
    }
    for (cfg.routes.items) |route| {
        const cache = config_mod.responseCachePolicyFor(cfg, null, &route);
        const upstream = config_mod.upstreamRuntimePolicyFor(cfg, null, &route);
        try out.print(
            allocator,
            "route {s}: {s} {s} -> {s} security={s} response_cache={s} cache_ttl_ms={d} max_static_bytes={d} upstream_timeout_ms={d} upstream_retries={d} upstream_health={s}\n",
            .{ route.name, config_mod.routeMatchName(route.match_kind), route.pattern, config_mod.routeHandlerName(route.handler), config_mod.securityHeaderPresetName(config_mod.securityHeaderPresetFor(cfg, null, &route)), boolText(cache.enabled), cache.ttl_ms, config_mod.maxStaticFileBytesFor(cfg, null, &route), upstream.timeout_ms, upstream.retries, boolText(upstream.health_check_enabled) },
        );
    }
    for (cfg.domains.items) |domain| {
        const domain_cache = config_mod.responseCachePolicyFor(cfg, &domain, null);
        const domain_upstream = config_mod.upstreamRuntimePolicyFor(cfg, &domain, null);
        try out.print(allocator, "server {s} names=", .{domain.name});
        for (domain.server_names.items, 0..) |name, index| {
            if (index > 0) try out.append(allocator, ',');
            try out.appendSlice(allocator, name);
        }
        try out.print(
            allocator,
            " root={s} index={s} security={s} response_cache={s} upstream_timeout_ms={d} upstream_retries={d} upstream_health={s}\n",
            .{ routing.domainStaticDir(cfg, &domain), routing.domainIndexFile(cfg, &domain), config_mod.securityHeaderPresetName(config_mod.securityHeaderPresetFor(cfg, &domain, null)), boolText(domain_cache.enabled), domain_upstream.timeout_ms, domain_upstream.retries, boolText(domain_upstream.health_check_enabled) },
        );
        for (domain.routes.items) |route| {
            const cache = config_mod.responseCachePolicyFor(cfg, &domain, &route);
            const upstream = config_mod.upstreamRuntimePolicyFor(cfg, &domain, &route);
            try out.print(
                allocator,
                "  route {s}: {s} {s} -> {s} security={s} response_cache={s} cache_ttl_ms={d} max_static_bytes={d} upstream_timeout_ms={d} upstream_retries={d} upstream_health={s}\n",
                .{ route.name, config_mod.routeMatchName(route.match_kind), route.pattern, config_mod.routeHandlerName(route.handler), config_mod.securityHeaderPresetName(config_mod.securityHeaderPresetFor(cfg, &domain, &route)), boolText(cache.enabled), cache.ttl_ms, config_mod.maxStaticFileBytesFor(cfg, &domain, &route), upstream.timeout_ms, upstream.retries, boolText(upstream.health_check_enabled) },
            );
        }
    }

    return out.toOwnedSlice(allocator);
}

fn boolText(value: bool) []const u8 {
    return if (value) "true" else "false";
}

fn optionalPath(value: ?[]const u8) []const u8 {
    return value orelse "<none>";
}

pub fn renderCerts(allocator: std.mem.Allocator, cfg: *const ServerConfig, runtime: RuntimeView) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    try out.print(
        allocator,
        "global tls={s} tls_auto={s} renew={s} renew_interval_ms={d} cert={s} key={s}\n",
        .{
            boolText(cfg.tls_enabled),
            boolText(cfg.tls_auto),
            boolText(cfg.letsencrypt_renew),
            cfg.letsencrypt_renew_interval_ms,
            optionalPath(cfg.tls_cert),
            if (cfg.tls_key != null) "<configured>" else "<none>",
        },
    );
    try out.print(
        allocator,
        "acme renewals={d} successes={d} failures={d} certbot={s} webroot={s} staging={s}\n",
        .{
            metrics_mod.ServerMetrics.load(&runtime.metrics.acme_renewals_total),
            metrics_mod.ServerMetrics.load(&runtime.metrics.acme_renewal_successes_total),
            metrics_mod.ServerMetrics.load(&runtime.metrics.acme_renewal_failures_total),
            cfg.letsencrypt_certbot,
            cfg.letsencrypt_webroot,
            boolText(cfg.letsencrypt_staging),
        },
    );

    for (cfg.domains.items) |domain| {
        try out.print(
            allocator,
            "server {s} cert={s} key={s} names=",
            .{
                domain.name,
                optionalPath(domain.tls_cert),
                if (domain.tls_key != null) "<configured>" else "<none>",
            },
        );
        for (domain.server_names.items, 0..) |name, index| {
            if (index > 0) try out.append(allocator, ',');
            try out.appendSlice(allocator, name);
        }
        try out.append(allocator, '\n');
    }

    return out.toOwnedSlice(allocator);
}

fn appendMainConfigPreview(
    io: std.Io,
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    validate_config: ValidateConfigFn,
) !void {
    try out.appendSlice(allocator,
        \\<section class="block span-all" id="config">
        \\  <div class="section-head"><div><h2>Config management</h2><p>Activation preflight plus redacted previews of the main config and enabled site files.</p></div><span class="pill">managed restart applies writes</span></div>
        \\
    );
    try out.appendSlice(allocator, "<pre>");
    validate_config(io, allocator, cfg) catch |err| {
        const message = try std.fmt.allocPrint(allocator, "ERROR activation config invalid: {}\n", .{err});
        defer allocator.free(message);
        try admin_support.appendHtmlEscaped(out, allocator, message);
        try out.appendSlice(allocator, "</pre></section>\n");
        return;
    };
    try admin_support.appendHtmlEscaped(out, allocator, "OK activation config\n");
    try admin_support.appendHtmlEscaped(out, allocator, "main_config = ");
    try admin_support.appendHtmlEscaped(out, allocator, cfg.config_path);
    try admin_support.appendHtmlEscaped(out, allocator, "\n");
    if (cfg.domain_config_dir) |dir| {
        try admin_support.appendHtmlEscaped(out, allocator, "domain_config_dir = ");
        try admin_support.appendHtmlEscaped(out, allocator, dir);
        try admin_support.appendHtmlEscaped(out, allocator, "\n");
    } else {
        try admin_support.appendHtmlEscaped(out, allocator, "domain_config_dir is not configured\n");
    }
    try out.appendSlice(allocator, "</pre>\n");

    const content = std.Io.Dir.cwd().readFileAlloc(io, cfg.config_path, allocator, .limited(admin_support.ADMIN_MAIN_CONFIG_MAX_BYTES)) catch |err| switch (err) {
        error.FileNotFound => {
            try out.appendSlice(allocator, "<p class=\"notice\">The main config file does not exist yet. Saving settings will create it.</p></section>\n");
            return;
        },
        error.FileTooBig => {
            try out.appendSlice(allocator, "<p class=\"notice error\">The main config is too large to preview safely.</p></section>\n");
            return;
        },
        else => return err,
    };
    defer allocator.free(content);

    try out.appendSlice(allocator, "<details class=\"config-file\" open><summary><code>");
    try admin_support.appendHtmlEscaped(out, allocator, cfg.config_path);
    try out.appendSlice(allocator, "</code><span class=\"muted\">redacted preview</span></summary><pre>");
    try admin_support.appendRedactedConfigEscaped(out, allocator, content);
    try out.appendSlice(allocator, "</pre></details></section>\n");
}

pub fn renderDashboardPage(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    credentials: AdminCredentials,
    maybe_notice: ?[]const u8,
    maybe_error: ?[]const u8,
    runtime: RuntimeView,
    validate_config: ValidateConfigFn,
) ![]const u8 {
    const status = try renderStatus(allocator, cfg, runtime);
    defer allocator.free(status);
    const routes = try renderRoutes(allocator, cfg);
    defer allocator.free(routes);
    const certs = try renderCerts(allocator, cfg, runtime);
    defer allocator.free(certs);
    const upstreams = try admin_upstreams.renderReport(io, allocator, cfg);
    defer allocator.free(upstreams);
    const metrics = try metrics_mod.render(allocator, runtime.metrics);
    defer allocator.free(metrics);

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try admin_ui.appendAdminShellStart(&out, allocator, cfg, "Dashboard");
    try out.appendSlice(allocator, "<h1>Control surface</h1>\n<p class=\"lede\">Manage site files, inspect the live route table, validate config, and see the runtime state from the same Layerline process handling traffic.</p>\n");
    try out.appendSlice(allocator, "<div class=\"dashboard\">\n");
    try out.appendSlice(allocator, "<div class=\"actions\"><form method=\"post\" action=\"");
    try admin_support.appendHtmlEscaped(&out, allocator, cfg.admin_ui_path);
    try out.appendSlice(allocator, "/validate\"><button type=\"submit\">Validate config</button></form><form method=\"post\" action=\"");
    try admin_support.appendHtmlEscaped(&out, allocator, cfg.admin_ui_path);
    try out.appendSlice(allocator, "/reload\"><button type=\"submit\">Reload config</button></form><form method=\"post\" action=\"");
    try admin_support.appendHtmlEscaped(&out, allocator, cfg.admin_ui_path);
    try out.appendSlice(allocator, "/restart\"><button type=\"submit\">Graceful restart</button></form><form method=\"post\" action=\"");
    try admin_support.appendHtmlEscaped(&out, allocator, cfg.admin_ui_path);
    try out.appendSlice(allocator, "/logout\"><button type=\"submit\">Log out</button></form></div>\n");
    if (maybe_notice) |message| try admin_ui.appendAdminNotice(&out, allocator, "", message);
    if (maybe_error) |message| try admin_ui.appendAdminNotice(&out, allocator, "error", message);
    try out.appendSlice(allocator, "<div class=\"grid\">\n");
    try out.print(allocator, "<div class=\"metric\"><span>admin user</span><strong>", .{});
    try admin_support.appendHtmlEscaped(&out, allocator, credentials.username);
    try out.appendSlice(allocator, "</strong></div>\n");
    try out.print(allocator, "<div class=\"metric\"><span>listener</span><strong>{s}:{d}</strong></div>\n", .{ cfg.host, cfg.port });
    try out.print(allocator, "<div class=\"metric\"><span>http redirect</span><strong>{s}</strong></div>\n", .{if (cfg.http_redirect_enabled) "on" else "off"});
    try out.print(allocator, "<div class=\"metric\"><span>sites active</span><strong>{d}</strong></div>\n", .{cfg.domains.items.len});
    try out.print(allocator, "<div class=\"metric\"><span>requests</span><strong>{d}</strong></div>\n", .{metrics_mod.ServerMetrics.load(&runtime.metrics.requests_total)});
    try out.appendSlice(allocator, "</div>\n");

    try out.appendSlice(allocator, "<div class=\"workspace\">\n");
    try admin_ui.appendAdminActiveSites(&out, allocator, cfg);
    try admin_upstreams.appendAdminPanel(io, &out, allocator, cfg);
    try admin_ui.appendAdminSettingsForm(&out, allocator, cfg);
    try admin_ui.appendAdminAddSiteForm(&out, allocator, cfg);
    try appendMainConfigPreview(io, &out, allocator, cfg, validate_config);
    try admin_ui.appendAdminDomainFiles(io, &out, allocator, cfg);

    try out.appendSlice(allocator, "<section class=\"block\" id=\"status\"><h2>Status</h2><pre>");
    try admin_support.appendHtmlEscaped(&out, allocator, status);
    try out.appendSlice(allocator, "</pre></section>\n<section class=\"block\" id=\"upstream-report\"><h2>Upstream report</h2><pre>");
    try admin_support.appendHtmlEscaped(&out, allocator, upstreams);
    try out.appendSlice(allocator, "</pre></section>\n<section class=\"block\" id=\"routes\"><h2>Routes</h2><pre>");
    try admin_support.appendHtmlEscaped(&out, allocator, routes);
    try out.appendSlice(allocator, "</pre></section>\n<section class=\"block\" id=\"certs\"><div class=\"section-head\"><div><h2>Certificates</h2><p>Configured TLS material and ACME renewal counters.</p></div><form method=\"post\" action=\"");
    try admin_support.appendHtmlEscaped(&out, allocator, cfg.admin_ui_path);
    try out.appendSlice(allocator, "/certs/renew\"><button type=\"submit\">Renew certificates</button></form></div><pre>");
    try admin_support.appendHtmlEscaped(&out, allocator, certs);
    try out.appendSlice(allocator, "</pre></section>\n<section class=\"block\" id=\"metrics\"><h2>Metrics</h2><pre>");
    try admin_support.appendHtmlEscaped(&out, allocator, metrics);
    try out.appendSlice(allocator, "</pre></section>\n</div>\n</div>\n");
    try admin_ui.appendAdminShellEnd(&out, allocator);
    return out.toOwnedSlice(allocator);
}
