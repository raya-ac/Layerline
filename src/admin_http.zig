const std = @import("std");

const admin_pages = @import("admin_pages.zig");
const admin_support = @import("admin_support.zig");
const admin_ui = @import("admin_ui.zig");
const config_mod = @import("config.zig");

const AdminCredentials = admin_support.AdminCredentials;
const ServerConfig = config_mod.ServerConfig;

pub const Callbacks = struct {
    runtime_view: *const fn () admin_pages.RuntimeView,
    send_response_headers: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, []const u8, bool, ?[]const u8) anyerror!void,
    send_response_no_body_headers: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, usize, bool, ?[]const u8) anyerror!void,
    validate_activation: *const fn (std.Io, std.mem.Allocator, *const ServerConfig) anyerror!void,
};

pub fn sendRedirect(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, cookie: ?[]const u8, close_connection: bool, is_head: bool, callbacks: Callbacks) !void {
    const extra_headers = if (cookie) |cookie_value|
        try std.fmt.allocPrint(allocator, "Location: {s}\r\nSet-Cookie: {s}\r\nCache-Control: no-store\r\n", .{ cfg.admin_ui_path, cookie_value })
    else
        try std.fmt.allocPrint(allocator, "Location: {s}\r\nCache-Control: no-store\r\n", .{cfg.admin_ui_path});
    defer allocator.free(extra_headers);

    const body = "Redirecting to Layerline Admin.\n";
    if (is_head) {
        try callbacks.send_response_no_body_headers(stream, 303, "See Other", "text/plain; charset=utf-8", body.len, close_connection, extra_headers);
    } else {
        try callbacks.send_response_headers(stream, 303, "See Other", "text/plain; charset=utf-8", body, close_connection, extra_headers);
    }
}

fn sendPage(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, body: []const u8, close_connection: bool, is_head: bool, callbacks: Callbacks) !void {
    const headers = "Cache-Control: no-store\r\n";
    if (is_head) {
        try callbacks.send_response_no_body_headers(stream, status_code, status_text, "text/html; charset=utf-8", body.len, close_connection, headers);
    } else {
        try callbacks.send_response_headers(stream, status_code, status_text, "text/html; charset=utf-8", body, close_connection, headers);
    }
}

pub fn sendSetupPage(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, maybe_error: ?[]const u8, status_code: u16, status_text: []const u8, close_connection: bool, is_head: bool, callbacks: Callbacks) !void {
    const body = try admin_ui.renderAdminSetupPage(allocator, cfg, maybe_error);
    defer allocator.free(body);
    try sendPage(stream, status_code, status_text, body, close_connection, is_head, callbacks);
}

pub fn sendLoginPage(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, maybe_error: ?[]const u8, status_code: u16, status_text: []const u8, close_connection: bool, is_head: bool, callbacks: Callbacks) !void {
    const body = try admin_ui.renderAdminLoginPage(allocator, cfg, maybe_error);
    defer allocator.free(body);
    try sendPage(stream, status_code, status_text, body, close_connection, is_head, callbacks);
}

pub fn sendDashboardPage(
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
    callbacks: Callbacks,
) !void {
    const body = try admin_pages.renderDashboardPage(io, allocator, cfg, credentials, maybe_notice, maybe_error, callbacks.runtime_view(), callbacks.validate_activation);
    defer allocator.free(body);
    try sendPage(stream, status_code, status_text, body, close_connection, is_head, callbacks);
}
