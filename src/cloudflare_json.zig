const std = @import("std");

pub const maximum_response_bytes = 1024 * 1024;
const Id = struct { id: []const u8 };
const List = struct { success: bool, result: []const Id };
const Mutation = struct { success: bool, result: Id };

fn parse(comptime T: type, allocator: std.mem.Allocator, payload: []const u8) !std.json.Parsed(T) {
    if (payload.len > maximum_response_bytes) return error.InvalidCloudflareResponse;
    return std.json.parseFromSlice(T, allocator, payload, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidCloudflareResponse,
    };
}

pub fn validId(id: []const u8) bool {
    if (id.len == 0 or id.len > 32) return false;
    for (id) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return false;
    return true;
}

pub fn validToken(token: []const u8) bool {
    if (token.len == 0) return false;
    for (token) |byte| if (byte < 0x21 or byte > 0x7e) return false;
    return true;
}

// Return an owned ID. An absent/malformed result is not an empty lookup, and
// choosing one record from an ambiguous list could overwrite the wrong DNS entry.
pub fn lookupId(allocator: std.mem.Allocator, payload: []const u8) !?[]const u8 {
    const parsed = try parse(List, allocator, payload);
    defer parsed.deinit();
    if (!parsed.value.success) return error.CloudflareApiFailure;
    const items = parsed.value.result;
    if (items.len == 0) return null;
    if (items.len != 1) return error.AmbiguousCloudflareResult;
    if (!validId(items[0].id)) return error.InvalidCloudflareResponse;
    return try allocator.dupe(u8, items[0].id);
}

pub fn validateMutation(allocator: std.mem.Allocator, payload: []const u8, expected_id: ?[]const u8) !void {
    const parsed = try parse(Mutation, allocator, payload);
    defer parsed.deinit();
    if (!parsed.value.success) return error.CloudflareApiFailure;
    if (!validId(parsed.value.result.id)) return error.InvalidCloudflareResponse;
    if (expected_id) |id| {
        if (!std.mem.eql(u8, id, parsed.value.result.id)) return error.UnexpectedCloudflareRecord;
    }
}

pub const Record = struct {
    type: []const u8,
    name: []const u8,
    content: []const u8,
    ttl: u32,
    proxied: bool,
    comment: ?[]const u8 = null,
};

pub fn encodeRecord(allocator: std.mem.Allocator, record: Record) ![]const u8 {
    for ([_][]const u8{ record.type, record.name, record.content, record.comment orelse "" }) |value| {
        if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidCloudflareRecord;
    }
    return std.json.Stringify.valueAlloc(allocator, record, .{ .emit_null_optional_fields = false });
}

pub fn escapeComponent(allocator: std.mem.Allocator, raw: []const u8) ![]const u8 {
    const component: std.Uri.Component = .{ .raw = raw };
    return std.fmt.allocPrint(allocator, "{f}", .{std.fmt.alt(component, .formatEscaped)});
}

test "Cloudflare lookup parses whitespace, escaped keys and only direct IDs" {
    const a = std.testing.allocator;
    const id = (try lookupId(a,
        \\{ "result": [ { "account": {"id": "wrong"}, "i\u0064": "rec\u006frd" } ],
        \\  "succ\u0065ss": true, "messages": [{"id": "also-wrong"}] }
    )).?;
    defer a.free(id);
    try std.testing.expectEqualStrings("record", id);
    try std.testing.expectEqual(null, try lookupId(a, "{\"success\":true,\"result\":[],\"meta\":{\"id\":\"wrong\"}}"));
}

test "Cloudflare lookups fail closed on malformed, ambiguous and misleading replies" {
    const invalid = [_][]const u8{
        "{\"success\":true}",
        "{\"success\":\"true\",\"result\":[]}",
        "{\"nested\":{\"success\":true},\"result\":[]}",
        "{\"success\":true,\"success\":false,\"result\":[]}",
        "{\"success\":true,\"result\":null}",
        "{\"success\":true,\"result\":{\"id\":\"record\"}}",
        "{\"success\":true,\"result\":[{\"nested\":{\"id\":\"wrong\"}}]}",
        "{\"success\":true,\"result\":[{\"id\":42}]}",
        "{\"success\":true,\"result\":[{\"id\":\"record\",\"id\":\"other\"}]}",
        "{\"success\":true,\"result\":[{\"id\":\"\"}]}",
        "{\"success\":true,\"result\":[{\"id\":\"../other\"}]}",
        "{\"success\":true,\"result\":[]} trailing",
        "{\"success\":true,\"result\":[],}",
        "[]",
    };
    for (invalid) |payload| try std.testing.expectError(error.InvalidCloudflareResponse, lookupId(std.testing.allocator, payload));
    try std.testing.expectError(error.CloudflareApiFailure, lookupId(std.testing.allocator, "{\"success\":false,\"result\":[],\"nested\":{\"success\":true}}"));
    try std.testing.expectError(error.AmbiguousCloudflareResult, lookupId(std.testing.allocator, "{\"success\":true,\"result\":[{\"id\":\"one\"},{\"id\":\"two\"}]}"));
}

test "Cloudflare mutation requires a direct result and the updated record ID" {
    const a = std.testing.allocator;
    const valid = "{ \"result\": {\"id\":\"record\",\"name\":\"example.com\"}, \"success\": true }";
    try validateMutation(a, valid, null);
    try validateMutation(a, valid, "record");
    try std.testing.expectError(error.UnexpectedCloudflareRecord, validateMutation(a, valid, "other"));
    try std.testing.expectError(error.InvalidCloudflareResponse, validateMutation(a, "{\"success\":true,\"result\":[]}", null));
    try std.testing.expectError(error.InvalidCloudflareResponse, validateMutation(a, "{\"success\":true}", null));
    try std.testing.expectError(error.InvalidCloudflareResponse, validateMutation(a, "{\"success\":true,\"result\":{\"id\":\"record/other\"}}", null));
    try std.testing.expectError(error.CloudflareApiFailure, validateMutation(a, "{\"success\":false,\"result\":{\"id\":\"record\"},\"nested\":{\"success\":true}}", null));
}

test "Cloudflare record JSON and query components keep data separate from syntax" {
    const a = std.testing.allocator;
    const record: Record = .{ .type = "TXT", .name = "example.com", .content = "\"quoted\" \\ text\r\n\xE2\x98\x83", .ttl = 120, .proxied = false, .comment = "\",\"proxied\":true,\"other\":\"" };
    const encoded = try encodeRecord(a, record);
    defer a.free(encoded);
    const parsed = try std.json.parseFromSlice(Record, a, encoded, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings(record.content, parsed.value.content);
    try std.testing.expectEqualStrings(record.comment.?, parsed.value.comment.?);
    try std.testing.expect(!parsed.value.proxied);
    const escaped = try escapeComponent(a, "a&name=other/#?% +");
    defer a.free(escaped);
    try std.testing.expectEqualStrings("a%26name%3Dother%2F%23%3F%25%20%2B", escaped);
    const no_comment = try encodeRecord(a, .{ .type = "A", .name = "example.com", .content = "203.0.113.1", .ttl = 1, .proxied = true });
    defer a.free(no_comment);
    try std.testing.expect(std.mem.indexOf(u8, no_comment, "comment") == null);
    try std.testing.expectError(error.InvalidCloudflareRecord, encodeRecord(a, .{ .type = "TXT", .name = "example.com", .content = "\xff", .ttl = 1, .proxied = false }));
}

test "Cloudflare parser allocation failures release owned storage" {
    const Check = struct {
        fn run(a: std.mem.Allocator) !void {
            const id = (try lookupId(a, "{\"success\":true,\"result\":[{\"id\":\"rec\\u006frd\"}]}")).?;
            defer a.free(id);
            try validateMutation(a, "{\"success\":true,\"result\":{\"id\":\"rec\\u006frd\"}}", id);
            const body = try encodeRecord(a, .{ .type = "TXT", .name = "example.com", .content = "a\"b", .ttl = 1, .proxied = false });
            defer a.free(body);
            const escaped = try escapeComponent(a, "a&b");
            defer a.free(escaped);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Check.run, .{});
    for ([_][]const u8{ "", "../other", "a/b", "a?b", "a#b", "abcdefghijklmnopqrstuvwxyz1234567" }) |id| try std.testing.expect(!validId(id));
    for ([_][]const u8{ "", "a b", "a\r\nb", "a\x00b", "a\x7fb" }) |token| try std.testing.expect(!validToken(token));
    try std.testing.expect(validToken("token_-./+=~"));
}

test "Cloudflare response ceiling and deeply nested unrelated metadata are bounded" {
    const a = std.testing.allocator;
    const oversized = try a.alloc(u8, maximum_response_bytes + 1);
    defer a.free(oversized);
    @memset(oversized, ' ');
    try std.testing.expectError(error.InvalidCloudflareResponse, lookupId(a, oversized));
    try std.testing.expectError(error.InvalidCloudflareResponse, validateMutation(a, oversized, null));
    var payload = std.ArrayList(u8).empty;
    defer payload.deinit(a);
    try payload.appendSlice(a, "{\"success\":true,\"result\":[],\"metadata\":");
    try payload.appendNTimes(a, '[', 4096);
    try payload.appendSlice(a, "null");
    try payload.appendNTimes(a, ']', 4096);
    try payload.append(a, '}');
    try std.testing.expectEqual(null, try lookupId(a, payload.items));
}
