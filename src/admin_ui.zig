const std = @import("std");

const admin_support = @import("admin_support.zig");
const config_loader = @import("config_loader.zig");
const config_mod = @import("config.zig");
const routing_mod = @import("routing.zig");

const ServerConfig = config_mod.ServerConfig;
const SecurityHeaderPreset = config_mod.SecurityHeaderPreset;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;

const ADMIN_SITE_CONFIG_MAX_BYTES = admin_support.ADMIN_SITE_CONFIG_MAX_BYTES;
const appendHtmlEscaped = admin_support.appendHtmlEscaped;
const appendRedactedConfigEscaped = admin_support.appendRedactedConfigEscaped;
const domainStaticDir = routing_mod.domainStaticDir;
const isDomainConfigFileName = config_loader.isDomainConfigFileName;
const upstreamPoolPolicyName = config_mod.upstreamPoolPolicyName;

pub fn appendAdminShellStart(out: *std.ArrayList(u8), allocator: std.mem.Allocator, cfg: *const ServerConfig, title: []const u8) !void {
    try out.print(
        allocator,
        \\<!doctype html>
        \\<html lang="en">
        \\<head>
        \\<meta charset="utf-8">
        \\<meta name="viewport" content="width=device-width, initial-scale=1">
        \\<title>{s} - Layerline Admin</title>
        \\<link rel="icon" type="image/svg+xml" href="/favicon.svg">
        \\<style>
        \\  * {{ box-sizing: border-box; }}
        \\  body {{
        \\    margin: 0;
        \\    min-height: 100vh;
        \\    color: #11110f;
        \\    background:
        \\      linear-gradient(rgba(17,17,15,.045) 1px, transparent 1px),
        \\      linear-gradient(90deg, rgba(17,17,15,.045) 1px, transparent 1px),
        \\      linear-gradient(180deg, #f7f4ed 0%, #f0ece2 54%, #e9e3d6 100%);
        \\    background-size: 52px 52px, 52px 52px, auto;
        \\    font: 14px/1.55 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        \\  }}
        \\  main {{ width: min(1240px, calc(100vw - 32px)); margin: 0 auto; padding: 28px 0 42px; }}
        \\  header {{ display: flex; align-items: center; justify-content: space-between; gap: 18px; padding: 0 0 22px; border-bottom: 1px solid rgba(17,17,15,.14); }}
        \\  .brand {{ display: inline-flex; align-items: center; gap: 12px; color: inherit; text-decoration: none; }}
        \\  .brand img {{ width: 42px; height: 42px; border-radius: 8px; box-shadow: 0 16px 30px rgba(17,17,15,.12); }}
        \\  .brand strong {{ display: block; font-size: 18px; line-height: 1.1; }}
        \\  .brand span span {{ display: block; color: #66675f; font-size: 12px; }}
        \\  nav {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
        \\  a, button {{ color: #11110f; }}
        \\  .navlink, button {{ min-height: 36px; border: 1px solid rgba(17,17,15,.18); border-radius: 8px; background: rgba(251,250,246,.72); padding: 7px 10px; text-decoration: none; font: inherit; cursor: pointer; }}
        \\  button.primary {{ background: #11110f; color: #fbfaf6; border-color: #11110f; }}
        \\  h1 {{ margin: 32px 0 8px; font-size: clamp(34px, 5vw, 64px); line-height: .95; letter-spacing: 0; }}
        \\  .lede {{ margin: 0 0 24px; max-width: 62ch; color: #5d5e58; font-size: 16px; }}
        \\  .panel {{ border: 1px solid rgba(17,17,15,.16); border-radius: 8px; background: rgba(251,250,246,.78); box-shadow: 0 28px 70px rgba(38,34,24,.12); }}
        \\  .panel-inner {{ padding: clamp(18px, 3vw, 28px); }}
        \\  .dashboard {{ margin-top: 24px; }}
        \\  .workspace {{ display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(280px, .65fr); gap: 16px; align-items: start; }}
        \\  .span-all {{ grid-column: 1 / -1; }}
        \\  .grid {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin: 26px 0; }}
        \\  .metric {{ min-height: 86px; padding: 14px; border: 1px solid rgba(17,17,15,.14); border-radius: 8px; background: rgba(255,255,255,.38); }}
        \\  .metric span {{ display: block; color: #696a63; font: 11px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }}
        \\  .metric strong {{ display: block; margin-top: 8px; font-size: 24px; line-height: 1; }}
        \\  form.stack {{ display: grid; gap: 14px; }}
        \\  .form-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
        \\  .full {{ grid-column: 1 / -1; }}
        \\  .form-section {{ grid-column: 1 / -1; margin: 10px 0 0; padding-top: 12px; border-top: 1px solid rgba(17,17,15,.1); font-size: 13px; text-transform: uppercase; color: #686963; letter-spacing: 0; }}
        \\  label {{ display: grid; gap: 6px; color: #4f504a; font-size: 13px; }}
        \\  input, select, textarea {{ min-height: 42px; border: 1px solid rgba(17,17,15,.2); border-radius: 8px; padding: 9px 11px; background: rgba(255,255,255,.72); color: #11110f; font: inherit; }}
        \\  input[type="checkbox"] {{ width: 18px; height: 18px; min-height: 18px; padding: 0; }}
        \\  .check {{ display: flex; align-items: center; gap: 9px; min-height: 42px; }}
        \\  .check input {{ flex: 0 0 auto; }}
        \\  textarea {{ min-height: 74px; resize: vertical; }}
        \\  .notice {{ margin: 0 0 18px; padding: 12px 14px; border-left: 3px solid #11110f; background: rgba(255,255,255,.5); color: #454640; }}
        \\  .error {{ border-left-color: #a13b2f; color: #6f2118; }}
        \\  section.block {{ margin-top: 18px; }}
        \\  section.block h2 {{ margin: 0 0 8px; font-size: 16px; }}
        \\  .section-head {{ display: flex; justify-content: space-between; gap: 16px; align-items: start; margin-bottom: 10px; }}
        \\  .section-head h2 {{ margin: 0; }}
        \\  .section-head p, .muted {{ margin: 0; color: #686963; font-size: 13px; }}
        \\  .table-wrap {{ overflow: auto; border: 1px solid rgba(17,17,15,.13); border-radius: 8px; background: rgba(255,255,255,.38); }}
        \\  table {{ width: 100%; border-collapse: collapse; min-width: 760px; }}
        \\  th, td {{ padding: 11px 12px; border-bottom: 1px solid rgba(17,17,15,.1); text-align: left; vertical-align: top; }}
        \\  th {{ color: #696a63; font: 11px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }}
        \\  td code, .pill {{ display: inline-flex; align-items: center; min-height: 24px; border: 1px solid rgba(17,17,15,.12); border-radius: 999px; padding: 3px 8px; background: rgba(255,255,255,.5); color: #2e302b; font: 12px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; }}
        \\  .file-list {{ display: grid; gap: 8px; }}
        \\  .file-row {{ display: flex; justify-content: space-between; gap: 12px; padding: 9px 0; border-bottom: 1px solid rgba(17,17,15,.1); }}
        \\  .file-row:last-child {{ border-bottom: 0; }}
        \\  details.config-file {{ border-bottom: 1px solid rgba(17,17,15,.1); padding: 8px 0; }}
        \\  details.config-file:last-child {{ border-bottom: 0; }}
        \\  details.config-file summary {{ cursor: pointer; display: flex; justify-content: space-between; gap: 12px; list-style: none; }}
        \\  details.config-file summary::-webkit-details-marker {{ display: none; }}
        \\  pre {{ overflow: auto; max-height: 360px; margin: 0; padding: 14px; border: 1px solid rgba(17,17,15,.13); border-radius: 8px; background: #11110f; color: #f6f0e5; font: 12px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; }}
        \\  .actions {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-top: 18px; }}
        \\  .inline-actions {{ display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }}
        \\  .inline-actions form {{ margin: 0; }}
        \\  .inline-actions button {{ min-height: 30px; padding: 5px 8px; font-size: 12px; }}
        \\  @media (max-width: 900px) {{ .workspace, .form-grid {{ grid-template-columns: 1fr; }} .full, .span-all {{ grid-column: auto; }} }}
        \\  @media (max-width: 760px) {{ header {{ align-items: flex-start; flex-direction: column; }} .grid {{ grid-template-columns: 1fr; }} main {{ width: min(100vw - 24px, 1120px); }} }}
        \\</style>
        \\</head>
        \\<body>
        \\<main>
        \\<header>
        \\  <a class="brand" href="{s}">
        \\    <img src="/favicon.svg" alt="">
        \\    <span><strong>Layerline Admin</strong><span>disabled unless explicitly enabled</span></span>
        \\  </a>
        \\  <nav>
        \\    <a class="navlink" href="/">Site</a>
        \\    <a class="navlink" href="{s}">Dashboard</a>
        \\    <a class="navlink" href="{s}#sites">Sites</a>
        \\    <a class="navlink" href="{s}#upstreams">Upstreams</a>
        \\    <a class="navlink" href="{s}#settings">Settings</a>
        \\    <a class="navlink" href="{s}#config">Config</a>
        \\    <a class="navlink" href="{s}#config-diff">Diff</a>
        \\  </nav>
        \\</header>
        \\
    ,
        .{ title, cfg.admin_ui_path, cfg.admin_ui_path, cfg.admin_ui_path, cfg.admin_ui_path, cfg.admin_ui_path, cfg.admin_ui_path, cfg.admin_ui_path },
    );
}

pub fn appendAdminShellEnd(out: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
    try out.appendSlice(allocator,
        \\</main>
        \\</body>
        \\</html>
        \\
    );
}

pub fn appendAdminNotice(out: *std.ArrayList(u8), allocator: std.mem.Allocator, class_name: []const u8, message: []const u8) !void {
    try out.print(allocator, "<p class=\"notice {s}\">", .{class_name});
    try appendHtmlEscaped(out, allocator, message);
    try out.appendSlice(allocator, "</p>\n");
}

pub fn renderAdminSetupPage(allocator: std.mem.Allocator, cfg: *const ServerConfig, maybe_error: ?[]const u8) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try appendAdminShellStart(&out, allocator, cfg, "First Launch Setup");
    try out.appendSlice(allocator,
        \\<h1>First launch setup</h1>
        \\<p class="lede">Create the first local admin account. Layerline writes the password hash and session seed to the configured credentials file, then locks this setup screen.</p>
        \\<div class="panel"><div class="panel-inner">
        \\
    );
    if (maybe_error) |message| try appendAdminNotice(&out, allocator, "error", message);
    try out.print(
        allocator,
        \\<form class="stack" method="post" action="{s}/setup">
        \\  <label>Username<input name="username" autocomplete="username" required minlength="2" maxlength="64"></label>
        \\  <label>Password<input type="password" name="password" autocomplete="new-password" required minlength="8"></label>
        \\  <label>Confirm password<input type="password" name="password_confirm" autocomplete="new-password" required minlength="8"></label>
        \\  <div class="actions"><button class="primary" type="submit">Create admin access</button></div>
        \\</form>
        \\</div></div>
        \\
    ,
        .{cfg.admin_ui_path},
    );
    try appendAdminShellEnd(&out, allocator);
    return out.toOwnedSlice(allocator);
}

pub fn renderAdminLoginPage(allocator: std.mem.Allocator, cfg: *const ServerConfig, maybe_error: ?[]const u8) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try appendAdminShellStart(&out, allocator, cfg, "Login");
    try out.appendSlice(allocator,
        \\<h1>Admin login</h1>
        \\<p class="lede">Use the local admin account created during first launch. The dashboard is served by Layerline itself, under the configured admin path.</p>
        \\<div class="panel"><div class="panel-inner">
        \\
    );
    if (maybe_error) |message| try appendAdminNotice(&out, allocator, "error", message);
    try out.print(
        allocator,
        \\<form class="stack" method="post" action="{s}/login">
        \\  <label>Username<input name="username" autocomplete="username" required></label>
        \\  <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
        \\  <div class="actions"><button class="primary" type="submit">Sign in</button></div>
        \\</form>
        \\</div></div>
        \\
    ,
        .{cfg.admin_ui_path},
    );
    try appendAdminShellEnd(&out, allocator);
    return out.toOwnedSlice(allocator);
}

fn appendAdminServerNames(out: *std.ArrayList(u8), allocator: std.mem.Allocator, names: []const []const u8) !void {
    if (names.len == 0) {
        try out.appendSlice(allocator, "<span class=\"muted\">none</span>");
        return;
    }
    for (names, 0..) |name, index| {
        if (index > 0) try out.appendSlice(allocator, " ");
        try out.appendSlice(allocator, "<code>");
        try appendHtmlEscaped(out, allocator, name);
        try out.appendSlice(allocator, "</code>");
    }
}

fn appendAdminUpstreamSummary(out: *std.ArrayList(u8), allocator: std.mem.Allocator, pool: ?UpstreamPoolConfig) !void {
    const upstream = pool orelse {
        try out.appendSlice(allocator, "<span class=\"muted\">none</span>");
        return;
    };
    for (upstream.targets.items, 0..) |target, index| {
        if (index > 0) try out.appendSlice(allocator, "<br>");
        try out.print(allocator, "<code>{s}:{d}{s}</code>", .{ target.host, target.port, target.base_path });
    }
}

pub fn appendAdminActiveSites(out: *std.ArrayList(u8), allocator: std.mem.Allocator, cfg: *const ServerConfig) !void {
    try out.appendSlice(allocator,
        \\<section class="block span-all" id="sites">
        \\  <div class="section-head"><div><h2>Sites</h2><p>Active virtual hosts loaded into this process.</p></div></div>
        \\
    );
    if (cfg.domains.items.len == 0) {
        try out.appendSlice(allocator, "<p class=\"notice\">No domain configs are active yet. Add a site below, then use managed restart until in-memory reload lands.</p></section>\n");
        return;
    }
    try out.appendSlice(allocator,
        \\<div class="table-wrap"><table>
        \\  <thead><tr><th>Site</th><th>Server names</th><th>Root</th><th>Proxy</th><th>TLS</th><th>Routes</th></tr></thead>
        \\  <tbody>
        \\
    );
    for (cfg.domains.items) |domain| {
        try out.appendSlice(allocator, "<tr><td><strong>");
        try appendHtmlEscaped(out, allocator, domain.name);
        try out.appendSlice(allocator, "</strong></td><td>");
        try appendAdminServerNames(out, allocator, domain.server_names.items);
        try out.appendSlice(allocator, "</td><td><code>");
        try appendHtmlEscaped(out, allocator, domainStaticDir(cfg, &domain));
        try out.appendSlice(allocator, "</code></td><td>");
        try appendAdminUpstreamSummary(out, allocator, domain.upstream);
        try out.appendSlice(allocator, "</td><td><span class=\"pill\">");
        try out.appendSlice(allocator, if (domain.tls_cert != null and domain.tls_key != null) "site cert" else "fallback");
        try out.appendSlice(allocator, "</span></td><td>");
        try out.print(allocator, "{d}", .{domain.routes.items.len});
        try out.appendSlice(allocator, "</td></tr>\n");
    }
    try out.appendSlice(allocator, "</tbody></table></div></section>\n");
}

pub fn appendAdminDomainFiles(io: std.Io, out: *std.ArrayList(u8), allocator: std.mem.Allocator, cfg: *const ServerConfig) !void {
    try out.appendSlice(allocator,
        \\<section class="block" id="config-files">
        \\  <div class="section-head"><div><h2>Enabled files</h2><p>Files under the configured domain directory.</p></div></div>
        \\
    );
    const dir_path = cfg.domain_config_dir orelse {
        try out.appendSlice(allocator, "<p class=\"notice error\">Set <code>domain_config_dir = domains-enabled</code> in the main config before the admin UI can write site files.</p></section>\n");
        return;
    };
    try out.appendSlice(allocator, "<p class=\"muted\">Directory: <code>");
    try appendHtmlEscaped(out, allocator, dir_path);
    try out.appendSlice(allocator, "</code></p><div class=\"file-list\">\n");

    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => {
            try out.appendSlice(allocator, "<p class=\"notice\">The directory does not exist yet. Creating a site from this UI will create it.</p></div></section>\n");
            return;
        },
        else => return err,
    };
    defer dir.close(io);

    var found = false;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (!isDomainConfigFileName(entry.name)) continue;
        found = true;
        const path = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        defer allocator.free(path);
        const content = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(ADMIN_SITE_CONFIG_MAX_BYTES)) catch |err| switch (err) {
            error.FileTooBig => {
                try out.appendSlice(allocator, "<div class=\"file-row\"><code>");
                try appendHtmlEscaped(out, allocator, entry.name);
                try out.appendSlice(allocator, "</code><span class=\"muted\">too large to preview</span></div>\n");
                continue;
            },
            else => return err,
        };
        defer allocator.free(content);

        try out.appendSlice(allocator, "<details class=\"config-file\"><summary><code>");
        try appendHtmlEscaped(out, allocator, entry.name);
        try out.appendSlice(allocator, "</code><span class=\"muted\">redacted preview</span></summary><pre>");
        try appendRedactedConfigEscaped(out, allocator, content);
        try out.appendSlice(allocator, "</pre></details>\n");
    }
    if (!found) try out.appendSlice(allocator, "<p class=\"muted\">No enabled site files yet.</p>\n");
    try out.appendSlice(allocator, "</div></section>\n");
}

fn appendAdminTextInput(out: *std.ArrayList(u8), allocator: std.mem.Allocator, label: []const u8, name: []const u8, value: []const u8, placeholder: []const u8) !void {
    try out.appendSlice(allocator, "<label>");
    try appendHtmlEscaped(out, allocator, label);
    try out.appendSlice(allocator, "<input name=\"");
    try appendHtmlEscaped(out, allocator, name);
    try out.appendSlice(allocator, "\" value=\"");
    try appendHtmlEscaped(out, allocator, value);
    try out.appendSlice(allocator, "\" placeholder=\"");
    try appendHtmlEscaped(out, allocator, placeholder);
    try out.appendSlice(allocator, "\"></label>\n");
}

fn appendAdminNumberInput(out: *std.ArrayList(u8), allocator: std.mem.Allocator, label: []const u8, name: []const u8, value: anytype) !void {
    try out.appendSlice(allocator, "<label>");
    try appendHtmlEscaped(out, allocator, label);
    try out.print(allocator, "<input name=\"{s}\" value=\"{d}\" inputmode=\"numeric\"></label>\n", .{ name, value });
}

fn appendAdminBoolSelect(out: *std.ArrayList(u8), allocator: std.mem.Allocator, label: []const u8, name: []const u8, value: bool) !void {
    try out.appendSlice(allocator, "<label>");
    try appendHtmlEscaped(out, allocator, label);
    try out.print(
        allocator,
        "<select name=\"{s}\"><option value=\"true\" {s}>true</option><option value=\"false\" {s}>false</option></select></label>\n",
        .{ name, if (value) "selected" else "", if (!value) "selected" else "" },
    );
}

fn appendAdminPolicySelect(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: UpstreamPoolPolicy) !void {
    try out.appendSlice(allocator, "<label>Load balance<select name=\"upstream_policy\">");
    const options = [_]UpstreamPoolPolicy{ .round_robin, .random, .least_connections, .weighted, .consistent_hash, .sticky_cookie };
    for (options) |option| {
        const name = upstreamPoolPolicyName(option);
        try out.print(allocator, "<option value=\"{s}\" {s}>{s}</option>", .{ name, if (option == value) "selected" else "", name });
    }
    try out.appendSlice(allocator, "</select></label>\n");
}

fn appendAdminSecuritySelect(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: SecurityHeaderPreset) !void {
    try out.appendSlice(allocator, "<label>Security headers<select name=\"security_headers\">");
    const options = [_]SecurityHeaderPreset{ .off, .basic, .strict };
    for (options) |option| {
        const name = config_mod.securityHeaderPresetName(option);
        try out.print(allocator, "<option value=\"{s}\" {s}>{s}</option>", .{ name, if (option == value) "selected" else "", name });
    }
    try out.appendSlice(allocator, "</select></label>\n");
}

fn appendAdminSectionTitle(out: *std.ArrayList(u8), allocator: std.mem.Allocator, title: []const u8) !void {
    try out.appendSlice(allocator, "<h3 class=\"form-section\">");
    try appendHtmlEscaped(out, allocator, title);
    try out.appendSlice(allocator, "</h3>\n");
}

fn formatAdminUpstreamPoolValue(allocator: std.mem.Allocator, pool: ?UpstreamPoolConfig) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    if (pool) |upstream| {
        for (upstream.targets.items, 0..) |target, index| {
            if (index > 0) try out.append(allocator, ' ');
            try out.print(allocator, "{s}://{s}:{d}{s}", .{ if (target.https) "https" else "http", target.host, target.port, target.base_path });
            if (target.weight != 1) try out.print(allocator, " weight={d}", .{target.weight});
        }
    }
    return out.toOwnedSlice(allocator);
}

pub fn appendAdminSettingsForm(out: *std.ArrayList(u8), allocator: std.mem.Allocator, cfg: *const ServerConfig) !void {
    const proxy_value = try formatAdminUpstreamPoolValue(allocator, cfg.upstream);
    defer allocator.free(proxy_value);
    try out.appendSlice(allocator,
        \\<section class="block span-all" id="settings">
        \\  <div class="section-head"><div><h2>Settings</h2><p>Edit the main process config. Writes are staged to disk and take effect after managed restart until in-memory reload lands.</p></div><span class="pill">main config</span></div>
        \\  <div class="panel"><div class="panel-inner">
        \\
    );
    try out.print(allocator, "<p class=\"muted\">File: <code>{s}</code></p>\n<form class=\"stack\" method=\"post\" action=\"{s}/settings/save\"><div class=\"form-grid\">\n", .{ cfg.config_path, cfg.admin_ui_path });
    try appendAdminSectionTitle(out, allocator, "Listener");
    try appendAdminTextInput(out, allocator, "Host", "host", cfg.host, "0.0.0.0");
    try appendAdminNumberInput(out, allocator, "Port", "port", cfg.port);
    try appendAdminTextInput(out, allocator, "Static root", "static_dir", cfg.static_dir, "public");
    try appendAdminTextInput(out, allocator, "Index file", "index_file", cfg.index_file, "index.html");
    try appendAdminTextInput(out, allocator, "Domain config dir", "domain_config_dir", cfg.domain_config_dir orelse "", "domains-enabled");
    try appendAdminBoolSelect(out, allocator, "Serve static root", "serve_static_root", cfg.serve_static_root);
    try appendAdminBoolSelect(out, allocator, "Compression", "compression", cfg.compression_enabled);
    try appendAdminBoolSelect(out, allocator, "Gzip", "gzip", cfg.gzip_enabled);
    try appendAdminSecuritySelect(out, allocator, cfg.security_headers);
    try appendAdminBoolSelect(out, allocator, "Response cache", "response_cache", cfg.response_cache_enabled);
    try appendAdminNumberInput(out, allocator, "Response cache bytes", "response_cache_max_bytes", cfg.response_cache_max_bytes);
    try appendAdminNumberInput(out, allocator, "Response cache entry bytes", "response_cache_max_entry_bytes", cfg.response_cache_max_entry_bytes);
    try appendAdminNumberInput(out, allocator, "Response cache ttl ms", "response_cache_ttl_ms", cfg.response_cache_ttl_ms);

    try appendAdminSectionTitle(out, allocator, "PHP and Proxy");
    try appendAdminTextInput(out, allocator, "PHP root", "php_root", cfg.php_root, "public");
    try appendAdminTextInput(out, allocator, "PHP binary", "php_binary", cfg.php_binary, "php-cgi");
    try appendAdminTextInput(out, allocator, "php-fpm / FastCGI", "php_fastcgi", cfg.php_fastcgi orelse "", "127.0.0.1:9000 or unix:/run/php.sock");
    try appendAdminBoolSelect(out, allocator, "PHP front controller", "php_front_controller", cfg.php_front_controller);
    try appendAdminTextInput(out, allocator, "Proxy fallback", "proxy", proxy_value, "http://127.0.0.1:3000");
    try appendAdminPolicySelect(out, allocator, cfg.upstream_policy);
    try appendAdminNumberInput(out, allocator, "Upstream timeout ms", "upstream_timeout_ms", cfg.upstream_timeout_ms);
    try appendAdminNumberInput(out, allocator, "Upstream retries", "upstream_retries", cfg.upstream_retries);
    try appendAdminBoolSelect(out, allocator, "Upstream keep-alive", "upstream_keepalive", cfg.upstream_keepalive_enabled);
    try appendAdminBoolSelect(out, allocator, "FastCGI keep-alive", "fastcgi_keepalive", cfg.fastcgi_keepalive_enabled);

    try appendAdminSectionTitle(out, allocator, "TLS and Protocols");
    try appendAdminBoolSelect(out, allocator, "TLS", "tls", cfg.tls_enabled);
    try appendAdminTextInput(out, allocator, "TLS certificate", "tls_cert", cfg.tls_cert orelse "", "/etc/letsencrypt/live/site/fullchain.pem");
    try appendAdminTextInput(out, allocator, "TLS private key", "tls_key", cfg.tls_key orelse "", "/etc/letsencrypt/live/site/privkey.pem");
    try appendAdminBoolSelect(out, allocator, "HTTP to HTTPS redirect", "http_redirect", cfg.http_redirect_enabled);
    try appendAdminNumberInput(out, allocator, "HTTP redirect port", "http_redirect_port", cfg.http_redirect_port);
    try appendAdminNumberInput(out, allocator, "HTTPS redirect target", "http_redirect_https_port", cfg.http_redirect_https_port);
    try appendAdminBoolSelect(out, allocator, "HTTP/3", "http3", cfg.http3_enabled);
    try appendAdminNumberInput(out, allocator, "HTTP/3 port", "http3_port", cfg.http3_port);

    try appendAdminSectionTitle(out, allocator, "Admin and Limits");
    try appendAdminTextInput(out, allocator, "Admin socket", "admin_socket", if (cfg.admin_enabled) (cfg.admin_socket_path orelse "") else "off", "/run/layerline/admin.sock");
    try appendAdminBoolSelect(out, allocator, "Admin UI", "admin_ui", cfg.admin_ui_enabled);
    try appendAdminTextInput(out, allocator, "Admin UI path", "admin_ui_path", cfg.admin_ui_path, "/_layerline/admin");
    try appendAdminTextInput(out, allocator, "Admin credentials path", "admin_credentials_path", cfg.admin_credentials_path, "/etc/layerline/admin.credentials");
    try appendAdminTextInput(out, allocator, "Access log", "access_log", if (cfg.access_log_enabled) cfg.access_log_path else "off", "stderr or /var/log/layerline/access.log");
    try appendAdminNumberInput(out, allocator, "Max concurrent connections", "max_concurrent_connections", cfg.max_concurrent_connections);
    try appendAdminNumberInput(out, allocator, "Max request bytes", "max_request_bytes", cfg.max_request_bytes);
    try appendAdminNumberInput(out, allocator, "Header timeout ms", "read_header_timeout_ms", cfg.read_header_timeout_ms);
    try appendAdminNumberInput(out, allocator, "Idle timeout ms", "idle_timeout_ms", cfg.idle_timeout_ms);
    try appendAdminNumberInput(out, allocator, "Worker stack bytes", "worker_stack_size", cfg.worker_stack_size);

    try out.appendSlice(allocator,
        \\  </div>
        \\  <div class="actions"><button class="primary" type="submit">Save settings</button><span class="muted">A backup is written beside the config before overwrite.</span></div>
        \\</form>
        \\</div></div></section>
        \\
    );
}

pub fn appendAdminAddSiteForm(out: *std.ArrayList(u8), allocator: std.mem.Allocator, cfg: *const ServerConfig) !void {
    const disabled = cfg.domain_config_dir == null;
    try out.appendSlice(allocator,
        \\<section class="block" id="add-site">
        \\  <div class="section-head"><div><h2>Add site</h2><p>Write a nginx-style per-domain config file from the browser.</p></div></div>
        \\
    );
    if (disabled) {
        try out.appendSlice(allocator, "<p class=\"notice error\">Site creation is disabled until <code>domain_config_dir</code> is configured.</p>\n");
    }
    try out.print(
        allocator,
        \\<div class="panel"><div class="panel-inner">
        \\<form class="stack" method="post" action="{s}/sites/add">
        \\  <div class="form-grid">
        \\    <label>Internal name<input name="name" required pattern="[A-Za-z0-9_-]+" placeholder="layerline" {s}></label>
        \\    <label>Server names<input name="server_names" required placeholder="layerline.dev www.layerline.dev" {s}></label>
        \\    <label>Root<input name="root" required value="public" {s}></label>
        \\    <label>Index file<input name="index" required value="index.html" {s}></label>
        \\    <label class="check full"><input type="checkbox" name="serve_static_root" checked {s}> Serve static root before fallback handlers</label>
        \\    <label>Proxy fallback<input name="proxy" placeholder="http://127.0.0.1:3000" {s}></label>
        \\    <label>Load balance<select name="upstream_policy" {s}><option value="">round_robin</option><option>random</option><option>least_connections</option><option>weighted</option><option>consistent_hash</option><option>sticky_cookie</option></select></label>
        \\    <label>php-fpm / FastCGI<input name="php_fastcgi" placeholder="127.0.0.1:9000 or unix:/run/php.sock" {s}></label>
        \\    <label class="check full"><input type="checkbox" name="php_front_controller" {s}> Use index.php as a front controller</label>
        \\    <label>TLS certificate<input name="tls_cert" placeholder="/etc/letsencrypt/live/site/fullchain.pem" {s}></label>
        \\    <label>TLS private key<input name="tls_key" placeholder="/etc/letsencrypt/live/site/privkey.pem" {s}></label>
        \\    <label class="full">Initial route name<input name="route_name" placeholder="app" {s}></label>
        \\    <label>Route pattern<input name="route_pattern" placeholder="/app/*" {s}></label>
        \\    <label>Route handler<select name="route_handler" {s}><option value="">none</option><option>static</option><option>php</option><option>proxy</option></select></label>
        \\    <label>Route static root<input name="route_static_dir" placeholder="public" {s}></label>
        \\    <label>Route proxy<input name="route_proxy" placeholder="http://127.0.0.1:3000" {s}></label>
        \\    <label>Route FastCGI<input name="route_php_fastcgi" placeholder="127.0.0.1:9000" {s}></label>
        \\    <label class="check full"><input type="checkbox" name="route_php_front_controller" {s}> Route PHP through index.php front controller</label>
        \\  </div>
        \\  <div class="actions"><button class="primary" type="submit" {s}>Create site config</button></div>
        \\</form>
        \\</div></div></section>
        \\
    ,
        .{
            cfg.admin_ui_path,
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
            if (disabled) "disabled" else "",
        },
    );
}
