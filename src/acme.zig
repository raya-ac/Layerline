const std = @import("std");
const config_mod = @import("config.zig");
const http_headers = @import("http_headers.zig");
const metrics_mod = @import("metrics.zig");

const ServerConfig = config_mod.ServerConfig;
const ServerMetrics = metrics_mod.ServerMetrics;
const trimValue = http_headers.trimValue;

pub const ACME_CHALLENGE_DIR = ".well-known/acme-challenge";
pub const ACME_CHALLENGE_PATH_SUFFIX = "/.well-known/acme-challenge";

pub fn firstToken(raw: []const u8, delimiter: u8, start: usize) ?[]const u8 {
    if (raw.len == 0 or start >= raw.len) return null;
    const remaining = raw[start..];
    const trimmed = trimValue(remaining);
    if (trimmed.len == 0) return null;
    if (std.mem.indexOfScalar(u8, trimmed, delimiter)) |delim| {
        return trimValue(trimmed[0..delim]);
    }
    return trimmed;
}

pub fn listLetsencryptDomains(allocator: std.mem.Allocator, raw: []const u8, out: *std.ArrayList([]const u8)) !bool {
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

pub fn stripTrailingPathSeparators(path: []const u8) []const u8 {
    var end = path.len;
    while (end > 1 and path[end - 1] == '/') end -= 1;
    return path[0..end];
}

pub fn certbotWebrootFromAcmeConfig(webroot: []const u8) []const u8 {
    const trimmed = stripTrailingPathSeparators(webroot);
    if (std.mem.endsWith(u8, trimmed, ACME_CHALLENGE_PATH_SUFFIX)) {
        const root = trimmed[0 .. trimmed.len - ACME_CHALLENGE_PATH_SUFFIX.len];
        return if (root.len == 0) "/" else root;
    }
    return trimmed;
}

pub fn buildAcmeChallengeDir(allocator: std.mem.Allocator, webroot: []const u8) ![]const u8 {
    const trimmed = stripTrailingPathSeparators(webroot);
    if (std.mem.endsWith(u8, trimmed, ACME_CHALLENGE_PATH_SUFFIX)) {
        return allocator.dupe(u8, trimmed);
    }
    return std.fs.path.join(allocator, &.{ trimmed, ACME_CHALLENGE_DIR });
}

pub fn buildAcmeChallengeFilePath(allocator: std.mem.Allocator, webroot: []const u8, token: []const u8) ![]const u8 {
    const challenge_dir = try buildAcmeChallengeDir(allocator, webroot);
    defer allocator.free(challenge_dir);
    return std.fs.path.join(allocator, &.{ challenge_dir, token });
}

pub fn appendLetsEncryptWebrootArgs(
    allocator: std.mem.Allocator,
    args: *std.ArrayList([]const u8),
    webroot: []const u8,
    staging: bool,
) !void {
    try args.appendSlice(allocator, &.{
        "--non-interactive",
        "--webroot",
        "-w",
        certbotWebrootFromAcmeConfig(webroot),
        "--config-dir",
        "/etc/letsencrypt",
    });
    if (staging) try args.append(allocator, "--staging");
}

pub fn buildLetsEncryptCertonlyArgs(
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    domains: []const []const u8,
    out: *std.ArrayList([]const u8),
) !void {
    try out.append(allocator, "certonly");
    try out.append(allocator, "--agree-tos");
    try out.append(allocator, "--keep-until-expiring");
    try appendLetsEncryptWebrootArgs(allocator, out, cfg.letsencrypt_webroot, cfg.letsencrypt_staging);

    if (cfg.letsencrypt_email) |email| {
        try out.append(allocator, "--email");
        try out.append(allocator, email);
    } else {
        try out.append(allocator, "--register-unsafely-without-email");
    }

    for (domains) |domain| {
        try out.append(allocator, "-d");
        try out.append(allocator, domain);
    }
}

pub fn buildLetsEncryptRenewArgs(
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    out: *std.ArrayList([]const u8),
) !void {
    try out.append(allocator, "renew");
    try appendLetsEncryptWebrootArgs(allocator, out, cfg.letsencrypt_webroot, cfg.letsencrypt_staging);
}

pub fn applyLetsEncryptDefaultCertPaths(allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
    if (!cfg.tls_auto) return;
    if (cfg.letsencrypt_domains == null or cfg.letsencrypt_domains.?.len == 0) return;
    if (cfg.tls_cert != null and cfg.tls_key != null) return;

    if (firstToken(cfg.letsencrypt_domains.?, ',', 0)) |domain| {
        if (cfg.tls_cert == null) cfg.tls_cert = try std.fmt.allocPrint(allocator, "/etc/letsencrypt/live/{s}/fullchain.pem", .{domain});
        if (cfg.tls_key == null) cfg.tls_key = try std.fmt.allocPrint(allocator, "/etc/letsencrypt/live/{s}/privkey.pem", .{domain});
    }
}

pub fn runCommandCapture(io: std.Io, allocator: std.mem.Allocator, command: []const u8, args: []const []const u8) ![]const u8 {
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

pub fn runCommand(io: std.Io, allocator: std.mem.Allocator, command: []const u8, args: []const []const u8) !void {
    const out = try runCommandCapture(io, allocator, command, args);
    allocator.free(out);
}

pub fn isCloudflareSuccess(payload: []const u8) bool {
    return std.mem.indexOf(u8, payload, "\"success\":true") != null;
}

pub fn extractCloudflareFirstId(payload: []const u8) ?[]const u8 {
    const result_pos = std.mem.indexOf(u8, payload, "\"result\":") orelse return null;
    const payload_rest = payload[result_pos + "\"result\":".len ..];
    const id_key = "\"id\":\"";
    const id_pos = std.mem.indexOf(u8, payload_rest, id_key) orelse return null;
    const start = id_pos + id_key.len;
    const end = std.mem.indexOfScalar(u8, payload_rest[start..], '"') orelse return null;
    return payload_rest[start .. start + end];
}

pub fn extractCloudflareError(payload: []const u8) ?[]const u8 {
    const errors_pos = std.mem.indexOf(u8, payload, "\"errors\":[") orelse return null;
    const marker = "\"message\":\"";
    const msg_pos = std.mem.indexOf(u8, payload[errors_pos..], marker) orelse return null;
    const msg_start = msg_pos + marker.len;
    const msg_end = std.mem.indexOfScalar(u8, payload[errors_pos + msg_start ..], '"') orelse return null;
    return payload[errors_pos + msg_start .. errors_pos + msg_start + msg_end];
}

pub fn callCloudflareApi(
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

pub fn detectPublicIp(io: std.Io, allocator: std.mem.Allocator, record_type: []const u8) ![]const u8 {
    const target_service = if (std.mem.eql(u8, record_type, "AAAA"))
        "https://api64.ipify.org?format=text"
    else
        "https://api64.ipify.org";
    const out = trimValue(try runCommandCapture(io, allocator, "curl", &.{ "-fsS", target_service }));
    if (out.len == 0) return error.UnexpectedResponse;
    return try allocator.dupe(u8, out);
}

pub fn ensureCloudflareDeployment(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig) !void {
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

pub fn ensureLetsEncryptSetup(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
    if (!cfg.tls_auto) return;
    if (cfg.letsencrypt_domains == null or cfg.letsencrypt_domains.?.len == 0) {
        std.debug.print("Skipping Let's Encrypt setup because letsencrypt_domains is empty.\n", .{});
        return;
    }

    if (cfg.letsencrypt_webroot.len == 0) return;
    const challenge_dir = try buildAcmeChallengeDir(allocator, cfg.letsencrypt_webroot);
    defer allocator.free(challenge_dir);
    std.Io.Dir.cwd().createDirPath(io, challenge_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    try applyLetsEncryptDefaultCertPaths(allocator, cfg);

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
    try buildLetsEncryptCertonlyArgs(allocator, cfg, domains.items, &cert_args);

    std.debug.print("Running Let's Encrypt setup for {d} domain(s) via {s}\n", .{ domains.items.len, cfg.letsencrypt_certbot });
    try runCommand(io, allocator, cfg.letsencrypt_certbot, cert_args.items);
}

pub fn runLetsEncryptRenewal(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig, metrics: *ServerMetrics) !void {
    if (!cfg.tls_auto or !cfg.letsencrypt_renew) return;
    if (cfg.letsencrypt_domains == null or cfg.letsencrypt_domains.?.len == 0) return;
    if (cfg.letsencrypt_webroot.len == 0) return;

    var renew_args = std.ArrayList([]const u8).empty;
    defer renew_args.deinit(allocator);
    try buildLetsEncryptRenewArgs(allocator, cfg, &renew_args);

    std.debug.print("Running Let's Encrypt renewal via {s}\n", .{cfg.letsencrypt_certbot});
    metrics.acmeRenewalStarted();
    runCommand(io, allocator, cfg.letsencrypt_certbot, renew_args.items) catch |err| {
        metrics.acmeRenewalFailed();
        return err;
    };
    metrics.acmeRenewalSucceeded();
    std.debug.print("Let's Encrypt renewal completed. Reload Layerline to activate renewed TLS material.\n", .{});
}
