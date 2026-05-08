const std = @import("std");

const config_mod = @import("config.zig");
const http_headers = @import("http_headers.zig");
const request_mod = @import("request.zig");

const HttpRequest = request_mod.HttpRequest;
const RedirectRule = config_mod.RedirectRule;
const ServerConfig = config_mod.ServerConfig;

pub fn statusText(status_code: u16) []const u8 {
    return switch (status_code) {
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        else => "Permanent Redirect",
    };
}

pub fn buildLocation(allocator: std.mem.Allocator, rule: RedirectRule, req: HttpRequest) ![]const u8 {
    const suffix = if (rule.prefix_match and req.path.len >= rule.from.len) req.path[rule.from.len..] else "";
    const should_preserve_query = req.query.len > 0 and std.mem.indexOfScalar(u8, rule.to, '?') == null;
    const joiner: []const u8 = if (should_preserve_query) "?" else "";
    const query: []const u8 = if (should_preserve_query) req.query else "";
    return try std.fmt.allocPrint(allocator, "{s}{s}{s}{s}", .{ rule.to, suffix, joiner, query });
}

fn isAsciiDigitSlice(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (byte < '0' or byte > '9') return false;
    }
    return true;
}

fn stripPortFromHost(raw_host: []const u8) []const u8 {
    const host = http_headers.trimValue(raw_host);
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

fn isSafeHost(host: []const u8) bool {
    if (host.len == 0) return false;
    if (std.mem.indexOfAny(u8, host, " \t\r\n\x00/?#") != null) return false;
    if (host[0] != '[' and std.mem.indexOfScalar(u8, host, ':') != null) return false;
    return true;
}

pub fn buildHttpsLocation(allocator: std.mem.Allocator, cfg: *const ServerConfig, req: HttpRequest) ![]const u8 {
    if (req.path.len == 0 or req.path[0] != '/') return error.InvalidRedirectPath;
    const raw_host = http_headers.findHeaderValue(req.headers, "Host") orelse return error.MissingHostHeader;
    const host = stripPortFromHost(raw_host);
    if (!isSafeHost(host)) return error.InvalidRedirectHost;

    const query_joiner: []const u8 = if (req.query.len > 0) "?" else "";
    if (cfg.http_redirect_https_port == 443) {
        return std.fmt.allocPrint(allocator, "https://{s}{s}{s}{s}", .{ host, req.path, query_joiner, req.query });
    }
    return std.fmt.allocPrint(allocator, "https://{s}:{d}{s}{s}{s}", .{ host, cfg.http_redirect_https_port, req.path, query_joiner, req.query });
}
