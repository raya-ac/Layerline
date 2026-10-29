const std = @import("std");
const http_headers = @import("http_headers.zig");

pub const Header = struct { name: []const u8, value: []const u8 };
const private_headers = [_]Header{
    .{ .name = "cache-control", .value = "no-store" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "x-frame-options", .value = "DENY" },
    .{ .name = "referrer-policy", .value = "no-referrer" },
};

pub const Response = struct {
    status_code: u16,
    status_text: []const u8,
    content_type: []const u8,
    body: []const u8,
    headers: []const Header,

    pub fn deinit(self: Response, allocator: std.mem.Allocator) void {
        allocator.free(self.status_text);
        allocator.free(self.content_type);
        allocator.free(self.body);
        for (self.headers) |header| {
            allocator.free(header.name);
            allocator.free(header.value);
        }
        allocator.free(self.headers);
    }

    pub fn renderHeaders(self: Response, allocator: std.mem.Allocator) ![]u8 {
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(allocator);
        for (self.headers) |header| try out.print(allocator, "{s}: {s}\r\n", .{ header.name, header.value });
        return out.toOwnedSlice(allocator);
    }
};

// Handlers may free their rendered pages immediately. Own the reply until the
// HTTP/1 sender finishes, or transfer it into the HTTP/2 request arena.
pub const Reply = struct {
    allocator: std.mem.Allocator,
    response: ?Response = null,

    pub fn deinit(self: *Reply) void {
        if (self.response) |response| response.deinit(self.allocator);
        self.response = null;
    }

    pub fn take(self: *Reply) !Response {
        const response = self.response orelse return error.MissingAdminResponse;
        self.response = null;
        return response;
    }

    pub fn set(self: *Reply, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8, extra: []const Header) !void {
        if (self.response != null) return error.DuplicateAdminResponse;
        for (extra) |header| {
            if (header.name.len == 0 or !http_headers.validFieldValue(header.value)) return error.InvalidAdminHeader;
            for (header.name) |byte| if (!http_headers.isHeaderNameByte(byte)) return error.InvalidAdminHeader;
            for (private_headers) |required| {
                if (std.ascii.eqlIgnoreCase(header.name, required.name)) return error.InvalidAdminHeader;
            }
        }
        const allocator = self.allocator;
        const owned_status = try allocator.dupe(u8, status_text);
        errdefer allocator.free(owned_status);
        const owned_type = try allocator.dupe(u8, content_type);
        errdefer allocator.free(owned_type);
        const owned_body = try allocator.dupe(u8, body);
        errdefer allocator.free(owned_body);
        const headers = try allocator.alloc(Header, private_headers.len + extra.len);
        var used: usize = 0;
        errdefer {
            for (headers[0..used]) |header| {
                allocator.free(header.name);
                allocator.free(header.value);
            }
            allocator.free(headers);
        }
        for (0..headers.len) |index| {
            const header = if (index < private_headers.len) private_headers[index] else extra[index - private_headers.len];
            const name = try allocator.dupe(u8, header.name);
            errdefer allocator.free(name);
            const value = try allocator.dupe(u8, header.value);
            headers[used] = .{ .name = name, .value = value };
            used += 1;
        }
        self.response = .{ .status_code = status_code, .status_text = owned_status, .content_type = owned_type, .body = owned_body, .headers = headers };
    }
};

pub fn sendResponse(reply: *Reply, code: u16, text: []const u8, content_type: []const u8, body: []const u8) !void {
    try reply.set(code, text, content_type, body, &.{});
}

pub fn sendMethodNotAllowed(reply: *Reply, _: std.mem.Allocator, allow: []const u8) !void {
    try reply.set(405, "Method Not Allowed", "text/plain; charset=utf-8", "This admin action does not accept that method.\n", &.{.{ .name = "allow", .value = allow }});
}

fn allocationCheck(allocator: std.mem.Allocator) !void {
    var reply: Reply = .{ .allocator = allocator };
    defer reply.deinit();
    var body = [_]u8{ 'p', 'a', 'g', 'e' };
    try reply.set(303, "See Other", "text/plain", &body, &.{.{ .name = "set-cookie", .value = "session=secret; Secure" }});
    body[0] = 'x';
    try std.testing.expectEqualStrings("page", reply.response.?.body);
    try std.testing.expectError(error.DuplicateAdminResponse, reply.set(200, "OK", "text/plain", "bad", &.{}));
    const response = try reply.take();
    defer response.deinit(allocator);
    const headers = try response.renderHeaders(allocator);
    defer allocator.free(headers);
    try std.testing.expect(std.mem.indexOf(u8, headers, "cache-control: no-store\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, headers, "set-cookie: session=secret; Secure\r\n") != null);
}

test "admin replies own bodies and headers across every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCheck, .{});
}

test "admin replies reject response splitting and cache policy overrides" {
    var reply: Reply = .{ .allocator = std.testing.allocator };
    defer reply.deinit();
    for ([_]Header{
        .{ .name = "location", .value = "/admin\r\nInjected: true" },
        .{ .name = "bad\r\n", .value = "value" },
        .{ .name = "Cache-Control", .value = "public" },
    }) |header| try std.testing.expectError(error.InvalidAdminHeader, reply.set(200, "OK", "text/plain", "", &.{header}));
}
