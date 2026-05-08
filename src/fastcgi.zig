const std = @import("std");

const cgi_headers = @import("cgi_headers.zig");
const config_mod = @import("config.zig");
const http_headers = @import("http_headers.zig");

const RouteConfig = config_mod.RouteConfig;

pub const VERSION: u8 = 1;
pub const BEGIN_REQUEST: u8 = 1;
pub const END_REQUEST: u8 = 3;
pub const PARAMS: u8 = 4;
pub const STDIN: u8 = 5;
pub const STDOUT: u8 = 6;
pub const STDERR: u8 = 7;
pub const RESPONDER: u16 = 1;
pub const KEEP_CONN: u8 = 1;
pub const REQUEST_COMPLETE: u8 = 0;

pub const PhpFrontControllerTarget = struct {
    script_rel_path: []const u8,
    script_name: []const u8,
    path_info: []const u8,

    pub fn deinit(self: *const PhpFrontControllerTarget, allocator: std.mem.Allocator) void {
        allocator.free(self.script_rel_path);
        allocator.free(self.script_name);
        allocator.free(self.path_info);
    }
};

pub const ParamsInput = struct {
    server_header: []const u8,
    current_request_id: []const u8,
    server_host: []const u8,
    server_port: u16,
    method: []const u8,
    path: []const u8,
    query: []const u8,
    version: []const u8,
    headers: []const u8,
    body_len: usize,
};

pub const RunResult = struct {
    stdout: []u8,
    stderr: []u8,
    app_status: u32,
    protocol_status: u8,

    pub fn deinit(self: *const RunResult, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
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

pub fn makePhpFrontControllerTarget(allocator: std.mem.Allocator, route: ?*const RouteConfig, request_path: []const u8, php_index: []const u8) !PhpFrontControllerTarget {
    if (!config_mod.isSafeRelativeScriptPath(php_index)) return error.InvalidConfigValue;

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

fn appendLength(out: *std.ArrayList(u8), allocator: std.mem.Allocator, len: usize) !void {
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

pub fn appendParam(out: *std.ArrayList(u8), allocator: std.mem.Allocator, name: []const u8, value: []const u8) !void {
    if (name.len == 0) return;
    try appendLength(out, allocator, name.len);
    try appendLength(out, allocator, value.len);
    try out.appendSlice(allocator, name);
    try out.appendSlice(allocator, value);
}

fn appendRequestHeaders(allocator: std.mem.Allocator, params: *std.ArrayList(u8), request_headers: []const u8) !void {
    var lines = std.mem.splitSequence(u8, request_headers, "\r\n");
    while (lines.next()) |line| {
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const name = http_headers.trimValue(line[0..colon]);
            const value = http_headers.trimValue(line[colon + 1 ..]);
            if (name.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(name, "Content-Type") or std.ascii.eqlIgnoreCase(name, "Content-Length")) continue;
            if (std.ascii.eqlIgnoreCase(name, "X-Request-Id")) continue;

            var env_name = std.ArrayList(u8).empty;
            defer env_name.deinit(allocator);
            try env_name.appendSlice(allocator, "HTTP_");
            for (name) |c| {
                if (!cgi_headers.isHeaderNameChar(c)) {
                    env_name.clearRetainingCapacity();
                    break;
                }
                try env_name.append(allocator, if (c == '-') '_' else std.ascii.toUpper(c));
            }
            if (env_name.items.len <= "HTTP_".len) continue;
            try appendParam(params, allocator, env_name.items, value);
        }
    }
}

pub fn buildParams(
    allocator: std.mem.Allocator,
    input: ParamsInput,
    php_root: []const u8,
    script_path: []const u8,
    script_name: []const u8,
    path_info: []const u8,
) ![]u8 {
    var params = std.ArrayList(u8).empty;
    errdefer params.deinit(allocator);

    const request_uri = try std.fmt.allocPrint(allocator, "{s}{s}{s}", .{
        input.path,
        if (input.query.len > 0) "?" else "",
        input.query,
    });
    defer allocator.free(request_uri);

    const content_length = try std.fmt.allocPrint(allocator, "{d}", .{input.body_len});
    defer allocator.free(content_length);

    const server_port = try std.fmt.allocPrint(allocator, "{d}", .{input.server_port});
    defer allocator.free(server_port);

    const path_translated = if (path_info.len > 0 and path_info[0] == '/') blk: {
        const translated_rel = path_info[1..];
        break :blk try std.fs.path.join(allocator, &.{ php_root, translated_rel });
    } else try allocator.dupe(u8, script_path);
    defer allocator.free(path_translated);

    try appendParam(&params, allocator, "GATEWAY_INTERFACE", "CGI/1.1");
    try appendParam(&params, allocator, "SERVER_SOFTWARE", input.server_header);
    try appendParam(&params, allocator, "SERVER_NAME", input.server_host);
    try appendParam(&params, allocator, "SERVER_PORT", server_port);
    try appendParam(&params, allocator, "SERVER_PROTOCOL", input.version);
    try appendParam(&params, allocator, "REQUEST_METHOD", input.method);
    try appendParam(&params, allocator, "REQUEST_URI", request_uri);
    try appendParam(&params, allocator, "SCRIPT_NAME", script_name);
    try appendParam(&params, allocator, "SCRIPT_FILENAME", script_path);
    try appendParam(&params, allocator, "PHP_SELF", script_name);
    try appendParam(&params, allocator, "PATH_TRANSLATED", path_translated);
    try appendParam(&params, allocator, "PATH_INFO", path_info);
    try appendParam(&params, allocator, "QUERY_STRING", input.query);
    try appendParam(&params, allocator, "DOCUMENT_ROOT", php_root);
    try appendParam(&params, allocator, "REQUEST_SCHEME", "http");
    try appendParam(&params, allocator, "HTTPS", "off");
    try appendParam(&params, allocator, "REDIRECT_STATUS", "200");
    try appendParam(&params, allocator, "CONTENT_LENGTH", content_length);
    try appendParam(&params, allocator, "CONTENT_TYPE", http_headers.findHeaderValue(input.headers, "Content-Type") orelse "");
    try appendParam(&params, allocator, "FCGI_ROLE", "RESPONDER");
    try appendRequestHeaders(allocator, &params, input.headers);
    if (input.current_request_id.len > 0) try appendParam(&params, allocator, "HTTP_X_REQUEST_ID", input.current_request_id);

    return params.toOwnedSlice(allocator);
}

pub fn writeRecord(conn: std.Io.net.Stream, record_type: u8, request_id: u16, content: []const u8, write_all: anytype) !void {
    if (content.len == 0) {
        const header = [_]u8{
            VERSION,
            record_type,
            @intCast(request_id >> 8),
            @intCast(request_id & 0xff),
            0,
            0,
            0,
            0,
        };
        try write_all(conn, &header);
        return;
    }

    var offset: usize = 0;
    while (offset < content.len) {
        const chunk_len = @min(content.len - offset, 0xffff);
        const padding_len: u8 = @intCast((8 - (chunk_len % 8)) % 8);
        const header = [_]u8{
            VERSION,
            record_type,
            @intCast(request_id >> 8),
            @intCast(request_id & 0xff),
            @intCast(chunk_len >> 8),
            @intCast(chunk_len & 0xff),
            padding_len,
            0,
        };
        try write_all(conn, &header);
        try write_all(conn, content[offset .. offset + chunk_len]);
        if (padding_len > 0) {
            const padding = [_]u8{0} ** 8;
            try write_all(conn, padding[0..padding_len]);
        }
        offset += chunk_len;
    }
}

fn readBytes(conn: std.Io.net.Stream, out: []u8, read_fn: anytype) !void {
    var used: usize = 0;
    while (used < out.len) {
        const n = try read_fn(conn, out[used..]);
        if (n == 0) return error.BadGateway;
        used += n;
    }
}

fn skipBytes(conn: std.Io.net.Stream, len: usize, read_fn: anytype) !void {
    var scratch: [512]u8 = undefined;
    var remaining = len;
    while (remaining > 0) {
        const n = @min(remaining, scratch.len);
        try readBytes(conn, scratch[0..n], read_fn);
        remaining -= n;
    }
}

pub fn readResponse(
    allocator: std.mem.Allocator,
    conn: std.Io.net.Stream,
    request_id: u16,
    max_stdout: usize,
    max_stderr: usize,
    read_fn: anytype,
) !RunResult {
    var stdout = std.ArrayList(u8).empty;
    errdefer stdout.deinit(allocator);
    var stderr = std.ArrayList(u8).empty;
    errdefer stderr.deinit(allocator);

    var app_status: u32 = 0;
    var protocol_status: u8 = REQUEST_COMPLETE;

    while (true) {
        var header: [8]u8 = undefined;
        try readBytes(conn, &header, read_fn);
        if (header[0] != VERSION) return error.BadGateway;

        const record_type = header[1];
        const rec_request_id = (@as(u16, header[2]) << 8) | @as(u16, header[3]);
        const content_len = (@as(usize, header[4]) << 8) | @as(usize, header[5]);
        const padding_len = @as(usize, header[6]);

        if (rec_request_id != request_id and rec_request_id != 0) {
            try skipBytes(conn, content_len + padding_len, read_fn);
            continue;
        }

        switch (record_type) {
            STDOUT => {
                if (stdout.items.len + content_len > max_stdout) return error.StreamTooLong;
                const old_len = stdout.items.len;
                try stdout.resize(allocator, old_len + content_len);
                try readBytes(conn, stdout.items[old_len..], read_fn);
            },
            STDERR => {
                var remaining = content_len;
                var scratch: [512]u8 = undefined;
                while (remaining > 0) {
                    const n = @min(remaining, scratch.len);
                    try readBytes(conn, scratch[0..n], read_fn);
                    if (stderr.items.len < max_stderr) {
                        const keep = @min(n, max_stderr - stderr.items.len);
                        try stderr.appendSlice(allocator, scratch[0..keep]);
                    }
                    remaining -= n;
                }
            },
            END_REQUEST => {
                var body: [8]u8 = .{0} ** 8;
                if (content_len >= body.len) {
                    try readBytes(conn, &body, read_fn);
                    try skipBytes(conn, content_len - body.len, read_fn);
                } else {
                    try readBytes(conn, body[0..content_len], read_fn);
                }
                app_status = (@as(u32, body[0]) << 24) | (@as(u32, body[1]) << 16) | (@as(u32, body[2]) << 8) | @as(u32, body[3]);
                protocol_status = body[4];
                if (padding_len > 0) try skipBytes(conn, padding_len, read_fn);
                return .{
                    .stdout = try stdout.toOwnedSlice(allocator),
                    .stderr = try stderr.toOwnedSlice(allocator),
                    .app_status = app_status,
                    .protocol_status = protocol_status,
                };
            },
            else => try skipBytes(conn, content_len, read_fn),
        }

        if (record_type != END_REQUEST and padding_len > 0) {
            try skipBytes(conn, padding_len, read_fn);
        }
    }
}
