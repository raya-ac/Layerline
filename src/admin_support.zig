const std = @import("std");

const config_mod = @import("config.zig");
const http_headers = @import("http_headers.zig");

const trimValue = http_headers.trimValue;
const findHeaderValue = http_headers.findHeaderValue;
const ServerConfig = config_mod.ServerConfig;

const appendServerNames = config_mod.appendServerNames;
const applyConfigLine = config_mod.applyConfigLine;
const disablesOptionalUrl = config_mod.disablesOptionalUrl;
const initDomainConfig = config_mod.initDomainConfig;
const isDomainConfigNameValid = config_mod.isDomainConfigNameValid;
const parseOptionalUpstreamPoolPolicy = config_mod.parseOptionalUpstreamPoolPolicy;
const parseUpstreamPool = config_mod.parseUpstreamPool;
const setRouteLineFor = config_mod.setRouteLineFor;
const setRouteProxyProperty = config_mod.setRouteProxyProperty;
const setRouteStringProperty = config_mod.setRouteStringProperty;
const validateConfig = config_mod.validateConfig;
const validateFastcgiEndpoint = config_mod.validateFastcgiEndpoint;
const validateRouteConfig = config_mod.validateRouteConfig;
const validateUpstreamPool = config_mod.validateUpstreamPool;

const ADMIN_COOKIE_NAME = "layerline_admin";
const ADMIN_CREDENTIALS_VERSION = "layerline-admin-v1";
const ADMIN_CREDENTIALS_MAX_BYTES = 8 * 1024;
const ADMIN_USERNAME_MIN_BYTES = 2;
const ADMIN_USERNAME_MAX_BYTES = 64;
const ADMIN_PASSWORD_MIN_BYTES = 8;
const ADMIN_PBKDF2_ROUNDS: u32 = 100_000;
const ADMIN_SALT_BYTES = 16;
const ADMIN_HASH_BYTES = 32;
const ADMIN_SESSION_BYTES = 32;
pub const ADMIN_SITE_CONFIG_MAX_BYTES = 16 * 1024;
pub const ADMIN_MAIN_CONFIG_MAX_BYTES = 256 * 1024;

fn adminConfigValueSafe(value: []const u8) bool {
    return std.mem.indexOfAny(u8, value, "\r\n\x00") == null;
}

fn asciiContainsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[index .. index + needle.len], needle)) return true;
    }
    return false;
}

fn adminConfigKeySensitive(key: []const u8) bool {
    return asciiContainsIgnoreCase(key, "token") or
        asciiContainsIgnoreCase(key, "secret") or
        asciiContainsIgnoreCase(key, "password") or
        asciiContainsIgnoreCase(key, "credential") or
        asciiContainsIgnoreCase(key, "private_key") or
        asciiContainsIgnoreCase(key, "tls_key") or
        asciiContainsIgnoreCase(key, "ssl_certificate_key");
}

fn appendRedactedLine(out: *std.ArrayList(u8), allocator: std.mem.Allocator, line: []const u8, comptime escape_html: bool) !void {
    if (escape_html) {
        try appendHtmlEscaped(out, allocator, line);
    } else {
        try out.appendSlice(allocator, line);
    }
}

fn appendRedactedConfig(out: *std.ArrayList(u8), allocator: std.mem.Allocator, content: []const u8, comptime escape_html: bool) !void {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = if (std.mem.endsWith(u8, raw_line, "\r")) raw_line[0 .. raw_line.len - 1] else raw_line;
        const trimmed = trimValue(line);
        if (trimmed.len == 0 or trimmed[0] == '#') {
            try appendRedactedLine(out, allocator, line, escape_html);
            try out.append(allocator, '\n');
            continue;
        }

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse {
            try appendRedactedLine(out, allocator, line, escape_html);
            try out.append(allocator, '\n');
            continue;
        };
        const key = trimValue(line[0..eq]);
        if (adminConfigKeySensitive(key)) {
            try appendRedactedLine(out, allocator, key, escape_html);
            try out.appendSlice(allocator, if (escape_html) " = &lt;redacted&gt;\n" else " = <redacted>\n");
            continue;
        }

        try appendRedactedLine(out, allocator, line, escape_html);
        try out.append(allocator, '\n');
    }
}

pub fn appendRedactedConfigEscaped(out: *std.ArrayList(u8), allocator: std.mem.Allocator, content: []const u8) !void {
    try appendRedactedConfig(out, allocator, content, true);
}

pub fn appendRedactedConfigPlain(out: *std.ArrayList(u8), allocator: std.mem.Allocator, content: []const u8) !void {
    try appendRedactedConfig(out, allocator, content, false);
}

pub fn adminTrimmedField(fields: []const FormField, name: []const u8) []const u8 {
    return trimValue(formValue(fields, name) orelse "");
}

pub fn adminCheckboxEnabled(fields: []const FormField, name: []const u8) bool {
    return formValue(fields, name) != null;
}

fn appendDomainConfigLine(out: *std.ArrayList(u8), allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
    if (!adminConfigValueSafe(value)) return error.InvalidConfigValue;
    try out.print(allocator, "{s} = {s}\n", .{ key, value });
}

pub const AdminConfigSetting = struct {
    key: []const u8,
    value: []const u8,
    emit: bool = true,
};

fn adminConfigSettingMatches(setting: AdminConfigSetting, key: []const u8) bool {
    if (std.mem.eql(u8, setting.key, key)) return true;
    if (std.mem.eql(u8, setting.key, "static_dir")) return std.mem.eql(u8, key, "dir");
    if (std.mem.eql(u8, setting.key, "index_file")) return std.mem.eql(u8, key, "index");
    if (std.mem.eql(u8, setting.key, "php_binary")) return std.mem.eql(u8, key, "php_bin");
    if (std.mem.eql(u8, setting.key, "admin_socket")) return std.mem.eql(u8, key, "admin_socket_path");
    if (std.mem.eql(u8, setting.key, "access_log")) return std.mem.eql(u8, key, "access_log_path");
    return false;
}

fn adminConfigSettingIndex(settings: []const AdminConfigSetting, key: []const u8) ?usize {
    for (settings, 0..) |setting, index| {
        if (adminConfigSettingMatches(setting, key)) return index;
    }
    return null;
}

fn appendAdminConfigSettingLine(out: *std.ArrayList(u8), allocator: std.mem.Allocator, setting: AdminConfigSetting) !void {
    if (!setting.emit) return;
    try appendDomainConfigLine(out, allocator, setting.key, setting.value);
}

pub fn buildAdminConfigWithSettings(allocator: std.mem.Allocator, existing: []const u8, settings: []const AdminConfigSetting) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    const written = try allocator.alloc(bool, settings.len);
    defer allocator.free(written);
    @memset(written, false);

    var lines = std.mem.splitScalar(u8, existing, '\n');
    while (lines.next()) |raw_line| {
        const line = if (std.mem.endsWith(u8, raw_line, "\r")) raw_line[0 .. raw_line.len - 1] else raw_line;
        const trimmed = trimValue(line);
        if (trimmed.len > 0 and trimmed[0] != '#') {
            if (std.mem.indexOfScalar(u8, line, '=')) |eq| {
                const key = trimValue(line[0..eq]);
                if (adminConfigSettingIndex(settings, key)) |setting_index| {
                    if (!written[setting_index]) {
                        try appendAdminConfigSettingLine(&out, allocator, settings[setting_index]);
                        written[setting_index] = true;
                    }
                    continue;
                }
            }
        }
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
    }

    var appended_header = false;
    for (settings, 0..) |setting, index| {
        if (written[index] or !setting.emit) continue;
        if (!appended_header) {
            if (out.items.len > 0 and out.items[out.items.len - 1] != '\n') try out.append(allocator, '\n');
            try out.appendSlice(allocator, "\n# Managed by Layerline Admin settings\n");
            appended_header = true;
        }
        try appendAdminConfigSettingLine(&out, allocator, setting);
    }

    if (out.items.len > ADMIN_MAIN_CONFIG_MAX_BYTES) return error.InvalidConfigValue;
    return out.toOwnedSlice(allocator);
}

pub fn validateAdminSettingsPatch(allocator: std.mem.Allocator, cfg: *const ServerConfig, settings: []const AdminConfigSetting, tls_cert: []const u8, tls_key: []const u8) !void {
    if ((tls_cert.len == 0) != (tls_key.len == 0)) return error.InvalidConfigValue;

    var trial = cfg.*;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();

    for (settings) |setting| {
        if (!setting.emit) continue;
        if (!adminConfigValueSafe(setting.value)) return error.InvalidConfigValue;
        try applyConfigLine(&trial, scratch, setting.key, setting.value);
    }
    try validateConfig(&trial);
}

pub fn writeAdminMainConfigFile(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig, settings: []const AdminConfigSetting) ![]const u8 {
    const path = cfg.config_path;
    const maybe_existing = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(ADMIN_MAIN_CONFIG_MAX_BYTES)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (maybe_existing) |existing| allocator.free(existing);

    const existing = maybe_existing orelse "";
    const merged = try buildAdminConfigWithSettings(allocator, existing, settings);
    defer allocator.free(merged);

    try ensureParentDir(io, path);
    if (maybe_existing) |existing_content| {
        const backup_path = try std.fmt.allocPrint(allocator, "{s}.bak", .{path});
        defer allocator.free(backup_path);
        try ensureParentDir(io, backup_path);
        try std.Io.Dir.cwd().writeFile(io, .{
            .sub_path = backup_path,
            .data = existing_content,
            .flags = .{ .permissions = @enumFromInt(0o640) },
        });
    }

    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = merged,
        .flags = .{ .permissions = @enumFromInt(0o640) },
    });

    return try allocator.dupe(u8, path);
}

fn validateAdminSiteInput(
    allocator: std.mem.Allocator,
    name: []const u8,
    server_names: []const u8,
    root: []const u8,
    index: []const u8,
    proxy: []const u8,
    upstream_policy: []const u8,
    php_fastcgi: []const u8,
    tls_cert: []const u8,
    tls_key: []const u8,
    route_name: []const u8,
    route_pattern: []const u8,
    route_handler: []const u8,
    route_static_dir: []const u8,
    route_proxy: []const u8,
    route_php_fastcgi: []const u8,
) !void {
    if (!isDomainConfigNameValid(name)) return error.InvalidConfigValue;
    if (server_names.len == 0 or root.len == 0 or index.len == 0) return error.InvalidConfigValue;
    const values = [_][]const u8{ server_names, root, index, proxy, upstream_policy, php_fastcgi, tls_cert, tls_key, route_name, route_pattern, route_handler, route_static_dir, route_proxy, route_php_fastcgi };
    for (values) |value| {
        if (!adminConfigValueSafe(value)) return error.InvalidConfigValue;
    }

    var scratch_arena = std.heap.ArenaAllocator.init(allocator);
    defer scratch_arena.deinit();
    const scratch = scratch_arena.allocator();

    var domain = try initDomainConfig(scratch, name);
    try appendServerNames(scratch, &domain, server_names);

    if (proxy.len > 0) {
        const pool = try parseUpstreamPool(scratch, proxy);
        try validateUpstreamPool(pool);
    }
    if (upstream_policy.len > 0) _ = try parseOptionalUpstreamPoolPolicy(upstream_policy);
    if (php_fastcgi.len > 0 and !disablesOptionalUrl(php_fastcgi)) try validateFastcgiEndpoint(php_fastcgi);
    if ((tls_cert.len == 0) != (tls_key.len == 0)) return error.InvalidConfigValue;

    const has_route = route_name.len > 0 or route_pattern.len > 0 or route_handler.len > 0 or route_static_dir.len > 0 or route_proxy.len > 0 or route_php_fastcgi.len > 0;
    if (has_route) {
        if (route_name.len == 0 or route_pattern.len == 0 or route_handler.len == 0) return error.InvalidConfigValue;
        const line = try std.fmt.allocPrint(scratch, "{s} {s} {s}", .{ route_name, route_pattern, route_handler });
        try setRouteLineFor(&domain.routes, scratch, line);
        if (route_static_dir.len > 0) try setRouteStringProperty(&domain.routes, scratch, route_name, route_static_dir, .static_dir);
        if (route_proxy.len > 0) try setRouteProxyProperty(&domain.routes, scratch, route_name, route_proxy);
        if (route_php_fastcgi.len > 0) try setRouteStringProperty(&domain.routes, scratch, route_name, route_php_fastcgi, .php_fastcgi);
        try validateRouteConfig(&domain.routes.items[0], null);
    }
}

pub fn buildAdminSiteConfig(
    allocator: std.mem.Allocator,
    name: []const u8,
    server_names: []const u8,
    root: []const u8,
    index: []const u8,
    serve_static_root: bool,
    proxy: []const u8,
    upstream_policy: []const u8,
    php_fastcgi: []const u8,
    php_front_controller: bool,
    tls_cert: []const u8,
    tls_key: []const u8,
    route_name: []const u8,
    route_pattern: []const u8,
    route_handler: []const u8,
    route_static_dir: []const u8,
    route_proxy: []const u8,
    route_php_fastcgi: []const u8,
    route_php_front_controller: bool,
) ![]const u8 {
    try validateAdminSiteInput(allocator, name, server_names, root, index, proxy, upstream_policy, php_fastcgi, tls_cert, tls_key, route_name, route_pattern, route_handler, route_static_dir, route_proxy, route_php_fastcgi);

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "# Generated by Layerline Admin. Run activation preflight, then managed restart for this site to become active.\n");
    try appendDomainConfigLine(&out, allocator, "name", name);
    try appendDomainConfigLine(&out, allocator, "server_name", server_names);
    try appendDomainConfigLine(&out, allocator, "root", root);
    try appendDomainConfigLine(&out, allocator, "index", index);
    try appendDomainConfigLine(&out, allocator, "serve_static_root", if (serve_static_root) "true" else "false");
    if (php_fastcgi.len > 0) try appendDomainConfigLine(&out, allocator, "php_fastcgi", php_fastcgi);
    try appendDomainConfigLine(&out, allocator, "php_front_controller", if (php_front_controller) "true" else "false");
    if (proxy.len > 0) try appendDomainConfigLine(&out, allocator, "proxy", proxy);
    if (upstream_policy.len > 0) try appendDomainConfigLine(&out, allocator, "upstream_policy", upstream_policy);
    if (tls_cert.len > 0) try appendDomainConfigLine(&out, allocator, "tls_cert", tls_cert);
    if (tls_key.len > 0) try appendDomainConfigLine(&out, allocator, "tls_key", tls_key);
    if (route_name.len > 0) {
        try out.append(allocator, '\n');
        const route_line = try std.fmt.allocPrint(allocator, "{s} {s} {s}", .{ route_name, route_pattern, route_handler });
        defer allocator.free(route_line);
        try appendDomainConfigLine(&out, allocator, "route", route_line);
        if (route_static_dir.len > 0) {
            const key = try std.fmt.allocPrint(allocator, "route_dir.{s}", .{route_name});
            defer allocator.free(key);
            try appendDomainConfigLine(&out, allocator, key, route_static_dir);
        }
        if (route_proxy.len > 0) {
            const key = try std.fmt.allocPrint(allocator, "route_proxy.{s}", .{route_name});
            defer allocator.free(key);
            try appendDomainConfigLine(&out, allocator, key, route_proxy);
        }
        if (route_php_fastcgi.len > 0) {
            const key = try std.fmt.allocPrint(allocator, "route_php_fastcgi.{s}", .{route_name});
            defer allocator.free(key);
            try appendDomainConfigLine(&out, allocator, key, route_php_fastcgi);
        }
        if (route_php_front_controller) {
            const key = try std.fmt.allocPrint(allocator, "route_php_front_controller.{s}", .{route_name});
            defer allocator.free(key);
            try appendDomainConfigLine(&out, allocator, key, "true");
        }
    }

    if (out.items.len > ADMIN_SITE_CONFIG_MAX_BYTES) return error.InvalidConfigValue;
    return out.toOwnedSlice(allocator);
}

pub fn writeAdminSiteConfigFile(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig, name: []const u8, content: []const u8) ![]const u8 {
    const dir = cfg.domain_config_dir orelse return error.AdminDomainConfigDirMissing;
    if (!isDomainConfigNameValid(name)) return error.InvalidConfigValue;
    const file_name = try std.fmt.allocPrint(allocator, "{s}.conf", .{name});
    defer allocator.free(file_name);
    const path = try std.fs.path.join(allocator, &.{ dir, file_name });
    errdefer allocator.free(path);

    try ensureParentDir(io, path);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = content,
        .flags = .{ .exclusive = true, .permissions = @enumFromInt(0o640) },
    });

    return path;
}

pub const AdminCredentials = struct {
    username: []const u8,
    rounds: u32,
    salt: [ADMIN_SALT_BYTES]u8,
    hash: [ADMIN_HASH_BYTES]u8,
    session: [ADMIN_SESSION_BYTES]u8,
};

pub const FormField = struct {
    name: []const u8,
    value: []const u8,
};

fn isAdminUiPathByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '/' or byte == '_' or byte == '-' or byte == '.' or byte == '~';
}

pub fn validateAdminUiPath(path: []const u8) !void {
    if (path.len < 2 or path[0] != '/') return error.InvalidConfigValue;
    if (std.mem.indexOf(u8, path, "..") != null) return error.InvalidConfigValue;
    if (std.mem.endsWith(u8, path, "/")) return error.InvalidConfigValue;
    for (path) |byte| {
        if (!isAdminUiPathByte(byte)) return error.InvalidConfigValue;
    }
}

pub fn adminPathMatches(base_path: []const u8, request_path: []const u8) bool {
    if (std.mem.eql(u8, base_path, request_path)) return true;
    return std.mem.startsWith(u8, request_path, base_path) and request_path.len > base_path.len and request_path[base_path.len] == '/';
}

pub fn adminSubPath(base_path: []const u8, request_path: []const u8) []const u8 {
    if (std.mem.eql(u8, base_path, request_path)) return "";
    return request_path[base_path.len..];
}

fn isValidAdminUsername(username: []const u8) bool {
    if (username.len < ADMIN_USERNAME_MIN_BYTES or username.len > ADMIN_USERNAME_MAX_BYTES) return false;
    for (username) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '_' or byte == '-' or byte == '@')) return false;
    }
    return true;
}

pub fn appendHtmlEscaped(out: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    for (text) |byte| {
        switch (byte) {
            '&' => try out.appendSlice(allocator, "&amp;"),
            '<' => try out.appendSlice(allocator, "&lt;"),
            '>' => try out.appendSlice(allocator, "&gt;"),
            '"' => try out.appendSlice(allocator, "&quot;"),
            '\'' => try out.appendSlice(allocator, "&#39;"),
            else => try out.append(allocator, byte),
        }
    }
}

fn percentDecodeFormComponent(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    var index: usize = 0;
    while (index < input.len) {
        const byte = input[index];
        if (byte == '+') {
            try out.append(allocator, ' ');
            index += 1;
        } else if (byte == '%') {
            if (index + 2 >= input.len) return error.InvalidFormEncoding;
            const hi = std.fmt.charToDigit(input[index + 1], 16) catch return error.InvalidFormEncoding;
            const lo = std.fmt.charToDigit(input[index + 2], 16) catch return error.InvalidFormEncoding;
            try out.append(allocator, @as(u8, @intCast((hi << 4) | lo)));
            index += 3;
        } else {
            try out.append(allocator, byte);
            index += 1;
        }
    }

    return out.toOwnedSlice(allocator);
}

pub fn parseUrlEncodedForm(allocator: std.mem.Allocator, body: []const u8) !std.ArrayList(FormField) {
    var fields = std.ArrayList(FormField).empty;
    errdefer freeFormFields(allocator, &fields);

    if (body.len == 0) return fields;

    var parts = std.mem.splitScalar(u8, body, '&');
    while (parts.next()) |part| {
        if (part.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse part.len;
        const raw_name = part[0..eq];
        const raw_value = if (eq < part.len) part[eq + 1 ..] else "";
        const name = try percentDecodeFormComponent(allocator, raw_name);
        errdefer allocator.free(name);
        const value = try percentDecodeFormComponent(allocator, raw_value);
        errdefer allocator.free(value);
        try fields.append(allocator, .{ .name = name, .value = value });
    }

    return fields;
}

pub fn freeFormFields(allocator: std.mem.Allocator, fields: *std.ArrayList(FormField)) void {
    for (fields.items) |field| {
        allocator.free(field.name);
        allocator.free(field.value);
    }
    fields.deinit(allocator);
}

pub fn formValue(fields: []const FormField, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}

test "admin form parser decodes url encoded setup fields" {
    var fields = try parseUrlEncodedForm(std.testing.allocator, "username=ari%40layerline&password=hello+world&empty=");
    defer freeFormFields(std.testing.allocator, &fields);

    try std.testing.expectEqualStrings("ari@layerline", formValue(fields.items, "username").?);
    try std.testing.expectEqualStrings("hello world", formValue(fields.items, "password").?);
    try std.testing.expectEqualStrings("", formValue(fields.items, "empty").?);
}

test "admin UI path matching stays under the configured prefix" {
    try validateAdminUiPath("/_layerline/admin");
    try std.testing.expect(adminPathMatches("/_layerline/admin", "/_layerline/admin"));
    try std.testing.expect(adminPathMatches("/_layerline/admin", "/_layerline/admin/setup"));
    try std.testing.expect(!adminPathMatches("/_layerline/admin", "/_layerline/administrator"));
    try std.testing.expectError(error.InvalidConfigValue, validateAdminUiPath("/_layerline/admin/"));
}

test "admin site config builder emits domain file" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const config = try buildAdminSiteConfig(
        allocator,
        "verify",
        "verify.test www.verify.test",
        "public",
        "index.html",
        true,
        "http://127.0.0.1:9000",
        "least_connections",
        "",
        false,
        "",
        "",
        "app",
        "/app/*",
        "proxy",
        "",
        "http://127.0.0.1:9001",
        "",
        false,
    );

    try std.testing.expect(std.mem.indexOf(u8, config, "name = verify\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "server_name = verify.test www.verify.test\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "proxy = http://127.0.0.1:9000\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "upstream_policy = least_connections\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "route = app /app/* proxy\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "route_proxy.app = http://127.0.0.1:9001\n") != null);
}

test "admin config preview redacts sensitive keys" {
    var html_out = std.ArrayList(u8).empty;
    defer html_out.deinit(std.testing.allocator);

    const source = "server_name = example.test\ntls_key = /private/key.pem\ncf_token = secret\n";
    try appendRedactedConfigEscaped(&html_out, std.testing.allocator, source);
    try std.testing.expect(std.mem.indexOf(u8, html_out.items, "server_name = example.test\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, html_out.items, "tls_key = &lt;redacted&gt;\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, html_out.items, "cf_token = &lt;redacted&gt;\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, html_out.items, "/private/key.pem") == null);
    try std.testing.expect(std.mem.indexOf(u8, html_out.items, "secret") == null);

    var text_out = std.ArrayList(u8).empty;
    defer text_out.deinit(std.testing.allocator);

    try appendRedactedConfigPlain(&text_out, std.testing.allocator, source);
    try std.testing.expect(std.mem.indexOf(u8, text_out.items, "server_name = example.test\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text_out.items, "tls_key = <redacted>\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text_out.items, "cf_token = <redacted>\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text_out.items, "/private/key.pem") == null);
    try std.testing.expect(std.mem.indexOf(u8, text_out.items, "secret") == null);
}

test "admin settings merge preserves comments and replaces owned keys" {
    const settings = [_]AdminConfigSetting{
        .{ .key = "host", .value = "0.0.0.0" },
        .{ .key = "static_dir", .value = "www" },
        .{ .key = "proxy", .value = "off" },
        .{ .key = "tls_key", .value = "", .emit = false },
        .{ .key = "admin_ui", .value = "true" },
    };
    const merged = try buildAdminConfigWithSettings(
        std.testing.allocator,
        "# keep me\nhost = 127.0.0.1\ndir = public\nproxy = http://127.0.0.1:9000\ntls_key = /private/key.pem\n",
        settings[0..],
    );
    defer std.testing.allocator.free(merged);

    try std.testing.expect(std.mem.indexOf(u8, merged, "# keep me\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged, "host = 0.0.0.0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged, "static_dir = www\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged, "proxy = off\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged, "admin_ui = true\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged, "dir = public") == null);
    try std.testing.expect(std.mem.indexOf(u8, merged, "/private/key.pem") == null);
}

fn deriveAdminPasswordHash(password: []const u8, salt: [ADMIN_SALT_BYTES]u8, rounds: u32) ![ADMIN_HASH_BYTES]u8 {
    var hash: [ADMIN_HASH_BYTES]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(hash[0..], password, salt[0..], rounds, std.crypto.auth.hmac.sha2.HmacSha256);
    return hash;
}

fn parseAdminCredentialFile(allocator: std.mem.Allocator, content: []const u8) !AdminCredentials {
    var lines = std.mem.splitScalar(u8, content, '\n');
    const version = trimValue(lines.next() orelse return error.InvalidAdminCredentials);
    if (!std.mem.eql(u8, version, ADMIN_CREDENTIALS_VERSION)) return error.InvalidAdminCredentials;

    var username_raw: ?[]const u8 = null;
    var rounds_raw: ?[]const u8 = null;
    var salt_raw: ?[]const u8 = null;
    var hash_raw: ?[]const u8 = null;
    var session_raw: ?[]const u8 = null;

    while (lines.next()) |line_raw| {
        const line = trimValue(line_raw);
        if (line.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse return error.InvalidAdminCredentials;
        const key = trimValue(line[0..eq]);
        const value = trimValue(line[eq + 1 ..]);
        if (std.mem.eql(u8, key, "username")) {
            username_raw = value;
        } else if (std.mem.eql(u8, key, "rounds")) {
            rounds_raw = value;
        } else if (std.mem.eql(u8, key, "salt")) {
            salt_raw = value;
        } else if (std.mem.eql(u8, key, "hash")) {
            hash_raw = value;
        } else if (std.mem.eql(u8, key, "session")) {
            session_raw = value;
        }
    }

    const username_value = username_raw orelse return error.InvalidAdminCredentials;
    if (!isValidAdminUsername(username_value)) return error.InvalidAdminCredentials;
    const rounds = std.fmt.parseInt(u32, rounds_raw orelse return error.InvalidAdminCredentials, 10) catch return error.InvalidAdminCredentials;
    if (rounds == 0) return error.InvalidAdminCredentials;

    var salt: [ADMIN_SALT_BYTES]u8 = undefined;
    if ((std.fmt.hexToBytes(salt[0..], salt_raw orelse return error.InvalidAdminCredentials) catch return error.InvalidAdminCredentials).len != ADMIN_SALT_BYTES) return error.InvalidAdminCredentials;
    var hash: [ADMIN_HASH_BYTES]u8 = undefined;
    if ((std.fmt.hexToBytes(hash[0..], hash_raw orelse return error.InvalidAdminCredentials) catch return error.InvalidAdminCredentials).len != ADMIN_HASH_BYTES) return error.InvalidAdminCredentials;
    var session: [ADMIN_SESSION_BYTES]u8 = undefined;
    if ((std.fmt.hexToBytes(session[0..], session_raw orelse return error.InvalidAdminCredentials) catch return error.InvalidAdminCredentials).len != ADMIN_SESSION_BYTES) return error.InvalidAdminCredentials;

    return .{
        .username = try allocator.dupe(u8, username_value),
        .rounds = rounds,
        .salt = salt,
        .hash = hash,
        .session = session,
    };
}

pub fn loadAdminCredentials(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !?AdminCredentials {
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(ADMIN_CREDENTIALS_MAX_BYTES)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(content);

    return try parseAdminCredentialFile(allocator, content);
}

fn ensureParentDir(io: std.Io, path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    if (parent.len == 0 or std.mem.eql(u8, parent, ".")) return;
    if (std.Io.Dir.cwd().statFile(io, parent, .{})) |_| {
        return;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    std.Io.Dir.cwd().createDirPath(io, parent) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

pub fn createAdminCredentials(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig, username_raw: []const u8, password: []const u8, password_confirm: []const u8) !AdminCredentials {
    const username = trimValue(username_raw);
    if (!isValidAdminUsername(username)) return error.InvalidAdminUsername;
    if (password.len < ADMIN_PASSWORD_MIN_BYTES) return error.AdminPasswordTooShort;
    if (!std.mem.eql(u8, password, password_confirm)) return error.AdminPasswordMismatch;

    var salt: [ADMIN_SALT_BYTES]u8 = undefined;
    var session: [ADMIN_SESSION_BYTES]u8 = undefined;
    io.random(salt[0..]);
    io.random(session[0..]);
    const hash = try deriveAdminPasswordHash(password, salt, ADMIN_PBKDF2_ROUNDS);

    const salt_hex = std.fmt.bytesToHex(salt, .lower);
    const hash_hex = std.fmt.bytesToHex(hash, .lower);
    const session_hex = std.fmt.bytesToHex(session, .lower);
    const content = try std.fmt.allocPrint(
        allocator,
        "{s}\nusername={s}\nrounds={d}\nsalt={s}\nhash={s}\nsession={s}\n",
        .{ ADMIN_CREDENTIALS_VERSION, username, ADMIN_PBKDF2_ROUNDS, salt_hex[0..], hash_hex[0..], session_hex[0..] },
    );
    defer allocator.free(content);

    try ensureParentDir(io, cfg.admin_credentials_path);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = cfg.admin_credentials_path,
        .data = content,
        .flags = .{ .exclusive = true, .permissions = @enumFromInt(0o600) },
    });

    return .{
        .username = try allocator.dupe(u8, username),
        .rounds = ADMIN_PBKDF2_ROUNDS,
        .salt = salt,
        .hash = hash,
        .session = session,
    };
}

pub fn verifyAdminPassword(credentials: AdminCredentials, password: []const u8) !bool {
    const candidate = try deriveAdminPasswordHash(password, credentials.salt, credentials.rounds);
    return std.crypto.timing_safe.eql([ADMIN_HASH_BYTES]u8, candidate, credentials.hash);
}

fn findCookieValue(headers: []const u8, name: []const u8) ?[]const u8 {
    const cookie_header = findHeaderValue(headers, "Cookie") orelse return null;
    var parts = std.mem.splitScalar(u8, cookie_header, ';');
    while (parts.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, " \t");
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        const cookie_name = std.mem.trim(u8, part[0..eq], " \t");
        const cookie_value = std.mem.trim(u8, part[eq + 1 ..], " \t");
        if (std.mem.eql(u8, cookie_name, name)) return cookie_value;
    }
    return null;
}

pub fn adminSessionCookieValid(headers: []const u8, credentials: AdminCredentials) bool {
    const value = findCookieValue(headers, ADMIN_COOKIE_NAME) orelse return false;
    const expected = std.fmt.bytesToHex(credentials.session, .lower);
    if (value.len != expected.len) return false;
    var actual: [ADMIN_SESSION_BYTES * 2]u8 = undefined;
    @memcpy(actual[0..], value);
    return std.crypto.timing_safe.eql([ADMIN_SESSION_BYTES * 2]u8, expected, actual);
}

pub fn makeAdminSessionCookie(allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials) ![]const u8 {
    const session_hex = std.fmt.bytesToHex(credentials.session, .lower);
    return std.fmt.allocPrint(
        allocator,
        "{s}={s}; HttpOnly; SameSite=Strict; Path={s}",
        .{ ADMIN_COOKIE_NAME, session_hex[0..], cfg.admin_ui_path },
    );
}

pub fn makeAdminClearCookie(allocator: std.mem.Allocator, cfg: *const ServerConfig) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}=; Max-Age=0; HttpOnly; SameSite=Strict; Path={s}",
        .{ ADMIN_COOKIE_NAME, cfg.admin_ui_path },
    );
}
