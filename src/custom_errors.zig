const std = @import("std");

const config_mod = @import("config.zig");
const h2_support = @import("http2_support.zig");
const routing_mod = @import("routing.zig");
const static_files = @import("static_files.zig");

const DomainConfig = config_mod.DomainConfig;
const H2BufferedResponse = h2_support.BufferedResponse;
const ServerConfig = config_mod.ServerConfig;

pub const Http1Callbacks = struct {
    send_not_found_for_method: *const fn (std.mem.Allocator, std.Io.net.Stream, bool, bool) anyerror!void,
    send_response_for_method: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, []const u8, bool, bool) anyerror!void,
};

pub fn documentName(status_code: u16) ?[]const u8 {
    @setEvalBranchQuota(100000);
    return switch (status_code) {
        inline 400...599 => |code| std.fmt.comptimePrint("{d}.html", .{code}),
        else => null,
    };
}

pub fn readDomainDocument(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    domain: ?*const DomainConfig,
    status_code: u16,
) !?[]u8 {
    const name = documentName(status_code) orelse return null;
    if (domain == null) return null;

    const file = static_files.openRootFile(io, routing_mod.domainStaticDir(cfg, domain), name) catch |err| {
        if (static_files.isHiddenFileError(err)) return null;
        return err;
    };
    defer file.close(io);
    const stat = try file.stat(io);
    const max_document_bytes = @min(64 * 1024, config_mod.maxStaticFileBytesFor(cfg, domain, null));
    if (stat.size > max_document_bytes) return null;

    return static_files.readOpened(io, allocator, file, max_document_bytes) catch |err| {
        if (err == error.StreamTooLong or err == error.NotDir or err == error.FileNotFound or err == error.NotFile) return null;
        return err;
    };
}

pub fn sendHttp1DomainNotFound(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    domain: ?*const DomainConfig,
    close_connection: bool,
    is_head: bool,
    callbacks: Http1Callbacks,
) !void {
    if (try readDomainDocument(io, allocator, cfg, domain, 404)) |body| {
        defer allocator.free(body);
        try callbacks.send_response_for_method(stream, 404, "Not Found", "text/html; charset=utf-8", body, close_connection, is_head);
        return;
    }

    try callbacks.send_not_found_for_method(allocator, stream, close_connection, is_head);
}

pub fn h2DomainNotFoundResponse(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    domain: ?*const DomainConfig,
) !?H2BufferedResponse {
    if (try readDomainDocument(io, allocator, cfg, domain, 404)) |body| {
        return .{ .status_code = 404, .content_type = "text/html; charset=utf-8", .body = body };
    }
    return null;
}
