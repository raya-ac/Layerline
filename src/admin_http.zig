const std = @import("std");

const admin_reply = @import("admin_reply.zig");
const Reply = admin_reply.Reply;
const admin_pages = @import("admin_pages.zig");
const admin_support = @import("admin_support.zig");
const admin_ui = @import("admin_ui.zig");
const config_mod = @import("config.zig");

const AdminCredentials = admin_support.AdminCredentials;
const ServerConfig = config_mod.ServerConfig;

pub const Callbacks = struct {
    render_activation_diff: *const fn (std.Io, std.mem.Allocator, *const ServerConfig) anyerror![]const u8,
    runtime_view: *const fn () admin_pages.RuntimeView,
    validate_activation: *const fn (std.Io, std.mem.Allocator, *const ServerConfig) anyerror!void,
};

pub fn sendRedirect(reply: *Reply, _: std.mem.Allocator, cfg: *const ServerConfig, cookie: ?[]const u8) !void {
    var headers: [2]admin_reply.Header = undefined;
    headers[0] = .{ .name = "location", .value = cfg.admin_ui_path };
    if (cookie) |value| headers[1] = .{ .name = "set-cookie", .value = value };
    const count: usize = if (cookie != null) 2 else 1;
    try reply.set(303, "See Other", "text/plain; charset=utf-8", "Redirecting to Layerline Admin.\n", headers[0..count]);
}

fn sendPage(reply: *Reply, status_code: u16, status_text: []const u8, body: []const u8) !void {
    try reply.set(status_code, status_text, "text/html; charset=utf-8", body, &.{});
}

pub fn sendSetupPage(reply: *Reply, allocator: std.mem.Allocator, cfg: *const ServerConfig, maybe_error: ?[]const u8, status_code: u16, status_text: []const u8) !void {
    const body = try admin_ui.renderAdminSetupPage(allocator, cfg, maybe_error);
    defer allocator.free(body);
    try sendPage(reply, status_code, status_text, body);
}

pub fn sendLoginPage(reply: *Reply, allocator: std.mem.Allocator, cfg: *const ServerConfig, maybe_error: ?[]const u8, status_code: u16, status_text: []const u8) !void {
    const body = try admin_ui.renderAdminLoginPage(allocator, cfg, maybe_error);
    defer allocator.free(body);
    try sendPage(reply, status_code, status_text, body);
}

pub fn sendDashboardPage(
    io: std.Io,
    reply: *Reply,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    credentials: AdminCredentials,
    maybe_notice: ?[]const u8,
    maybe_error: ?[]const u8,
    status_code: u16,
    status_text: []const u8,
    callbacks: Callbacks,
) !void {
    const body = try admin_pages.renderDashboardPage(io, allocator, cfg, credentials, maybe_notice, maybe_error, callbacks.runtime_view(), callbacks.validate_activation, callbacks.render_activation_diff);
    defer allocator.free(body);
    try sendPage(reply, status_code, status_text, body);
}
