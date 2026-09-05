const std = @import("std");

const h2_native = @import("h2_native.zig");
const h2_support = @import("http2_support.zig");
const http_headers = @import("http_headers.zig");
const request_mod = @import("request.zig");
const static_cache = @import("static_cache.zig");

const BufferedResponse = h2_support.BufferedResponse;
const Header = h2_native.Header;
pub const Policy = static_cache.Policy;
pub const StoreOutcome = static_cache.StoreOutcome;
pub const StoreResult = static_cache.StoreResult;

const Entry = struct {
    key: []u8,
    status_code: u16,
    content_type: []u8,
    body: []u8,
    headers: []Header,
    expires_at_ms: i64,
};

pub const Store = struct {
    mutex: std.atomic.Mutex = .unlocked,
    allocator: ?std.mem.Allocator = null,
    entries: std.ArrayList(Entry) = .empty,
    body_bytes: usize = 0,

    pub fn fetch(self: *Store, allocator: std.mem.Allocator, key: []const u8, now_ms: i64, policy: Policy) !?BufferedResponse {
        if (!policyUsable(policy)) return null;

        self.lock();
        defer self.mutex.unlock();

        self.pruneExpiredLocked(now_ms);
        for (self.entries.items) |entry| {
            if (!std.mem.eql(u8, entry.key, key)) continue;
            var response = try cloneEntryResponse(allocator, entry);
            const status = try cacheStatusHit(allocator, policy);
            response = try withCacheStatus(allocator, response, status);
            return response;
        }
        return null;
    }

    pub fn store(self: *Store, key: []const u8, response: BufferedResponse, now_ms: i64, policy: Policy) !StoreOutcome {
        if (!responseCanStore(response, policy)) return .{ .result = .disabled };

        self.lock();
        defer self.mutex.unlock();

        const allocator = self.allocator orelse blk: {
            self.allocator = std.heap.page_allocator;
            break :blk std.heap.page_allocator;
        };

        self.pruneExpiredLocked(now_ms);
        var index: usize = 0;
        while (index < self.entries.items.len) {
            const entry = self.entries.items[index];
            if (std.mem.eql(u8, entry.key, key)) {
                self.removeAtLocked(index);
                continue;
            }
            index += 1;
        }

        var evictions: usize = 0;
        while (self.entries.items.len > 0 and self.body_bytes + response.body.len > policy.max_bytes) {
            self.removeAtLocked(0);
            evictions += 1;
        }
        if (self.body_bytes + response.body.len > policy.max_bytes) return .{ .result = .too_large, .evictions = evictions };

        const owned_key = try allocator.dupe(u8, key);
        errdefer allocator.free(owned_key);
        const owned_content_type = try allocator.dupe(u8, response.content_type);
        errdefer allocator.free(owned_content_type);
        const owned_body = try allocator.dupe(u8, response.body);
        errdefer allocator.free(owned_body);
        const owned_headers = try cloneHeadersOwned(allocator, response.headers);
        errdefer freeHeaders(allocator, owned_headers);

        try self.entries.append(allocator, .{
            .key = owned_key,
            .status_code = response.status_code,
            .content_type = owned_content_type,
            .body = owned_body,
            .headers = owned_headers,
            .expires_at_ms = now_ms + @as(i64, policy.ttl_ms),
        });
        self.body_bytes += response.body.len;
        return .{ .result = .stored, .evictions = evictions };
    }

    pub fn deinit(self: *Store) void {
        self.lock();
        defer self.mutex.unlock();

        const allocator = self.allocator orelse return;
        for (self.entries.items) |entry| self.freeEntry(allocator, entry);
        self.entries.deinit(allocator);
        self.body_bytes = 0;
        self.allocator = null;
    }

    pub fn clear(self: *Store) usize {
        self.lock();
        defer self.mutex.unlock();

        const allocator = self.allocator orelse return 0;
        const removed = self.entries.items.len;
        for (self.entries.items) |entry| self.freeEntry(allocator, entry);
        self.entries.clearRetainingCapacity();
        self.body_bytes = 0;
        return removed;
    }

    pub fn clearMatching(self: *Store, needle: []const u8) usize {
        if (needle.len == 0) return self.clear();

        self.lock();
        defer self.mutex.unlock();

        var removed: usize = 0;
        var index: usize = 0;
        while (index < self.entries.items.len) {
            if (std.mem.indexOf(u8, self.entries.items[index].key, needle) != null) {
                self.removeAtLocked(index);
                removed += 1;
                continue;
            }
            index += 1;
        }
        return removed;
    }

    fn lock(self: *Store) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    fn pruneExpiredLocked(self: *Store, now_ms: i64) void {
        var index: usize = 0;
        while (index < self.entries.items.len) {
            if (self.entries.items[index].expires_at_ms <= now_ms) {
                self.removeAtLocked(index);
                continue;
            }
            index += 1;
        }
    }

    fn removeAtLocked(self: *Store, index: usize) void {
        const allocator = self.allocator orelse return;
        const entry = self.entries.orderedRemove(index);
        self.body_bytes -|= entry.body.len;
        self.freeEntry(allocator, entry);
    }

    fn freeEntry(self: *Store, allocator: std.mem.Allocator, entry: Entry) void {
        _ = self;
        allocator.free(entry.key);
        allocator.free(entry.content_type);
        allocator.free(entry.body);
        freeHeaders(allocator, entry.headers);
    }
};

fn policyUsable(policy: Policy) bool {
    return policy.enabled and policy.max_bytes > 0 and policy.max_entry_bytes > 0 and policy.ttl_ms > 0;
}

pub fn requestCanUse(req: request_mod.HttpRequest, policy: Policy) bool {
    if (!policyUsable(policy)) return false;
    if (!std.mem.eql(u8, req.method, "GET")) return false;
    if (req.body.len != 0) return false;
    if (http_headers.findHeaderValue(req.headers, "Authorization") != null) return false;
    if (http_headers.findHeaderValue(req.headers, "Cookie") != null) return false;
    // Conditional and partial responses need their own cache evaluation.
    for ([_][]const u8{ "Range", "If-Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "Cache-Control", "Pragma" }) |name| {
        if (http_headers.findHeaderValue(req.headers, name) != null) return false;
    }
    return true;
}

pub fn responseCanStore(response: BufferedResponse, policy: Policy) bool {
    if (!policyUsable(policy)) return false;
    if (response.status_code != 200) return false;
    if (response.body.len > policy.max_entry_bytes or response.body.len > policy.max_bytes) return false;
    if (findResponseHeader(response.headers, "set-cookie") != null) return false;
    if (findResponseHeader(response.headers, "vary") != null) return false;
    if (findResponseHeader(response.headers, "content-encoding") != null) return false;
    if (findResponseHeader(response.headers, "age") != null or findResponseHeader(response.headers, "expires") != null) return false;
    for (response.headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cache-control")) continue;
        var directives = std.mem.splitScalar(u8, header.value, ',');
        while (directives.next()) |raw| {
            const directive = http_headers.trimValue(raw);
            const eq = std.mem.indexOfScalar(u8, directive, '=') orelse directive.len;
            const name = http_headers.trimValue(directive[0..eq]);
            if (std.ascii.eqlIgnoreCase(name, "no-store") or std.ascii.eqlIgnoreCase(name, "no-cache") or std.ascii.eqlIgnoreCase(name, "private")) return false;
            if (std.ascii.eqlIgnoreCase(name, "max-age") or std.ascii.eqlIgnoreCase(name, "s-maxage")) {
                if (eq == directive.len) return false;
                const value = std.mem.trim(u8, http_headers.trimValue(directive[eq + 1 ..]), "\"");
                const seconds = http_headers.parseDecimalLength(value) catch return false;
                // Until entries carry origin freshness metadata, only cache
                // when the configured lifetime fits inside the origin limit.
                if (seconds == 0 or seconds < (@as(u64, policy.ttl_ms) + 999) / 1000) return false;
            }
        }
    }
    return true;
}

pub fn makeKey(allocator: std.mem.Allocator, scope: []const u8, req: request_mod.HttpRequest) ![]u8 {
    const host = http_headers.findHeaderValue(req.headers, "Host") orelse "";
    if (req.query.len > 0) {
        return std.fmt.allocPrint(allocator, "{s}|{s}|{s}?{s}", .{ scope, host, req.path, req.query });
    }
    return std.fmt.allocPrint(allocator, "{s}|{s}|{s}", .{ scope, host, req.path });
}

pub fn cacheStatusStored(allocator: std.mem.Allocator, policy: Policy) ![]const u8 {
    return std.fmt.allocPrint(allocator, "Layerline; fwd=uri-miss; stored; ttl={d}; detail=\"microcache\"", .{ttlSeconds(policy)});
}

pub fn cacheStatusHit(allocator: std.mem.Allocator, policy: Policy) ![]const u8 {
    return std.fmt.allocPrint(allocator, "Layerline; hit; ttl={d}; detail=\"microcache\"", .{ttlSeconds(policy)});
}

pub fn withCacheStatus(allocator: std.mem.Allocator, response: BufferedResponse, cache_status: []const u8) !BufferedResponse {
    const headers = try allocator.alloc(Header, response.headers.len + 1);
    if (response.headers.len > 0) @memcpy(headers[0..response.headers.len], response.headers);
    headers[response.headers.len] = .{ .name = "cache-status", .value = cache_status };
    return .{
        .status_code = response.status_code,
        .content_type = response.content_type,
        .body = response.body,
        .headers = headers,
    };
}

fn ttlSeconds(policy: Policy) u32 {
    if (policy.ttl_ms == 0) return 0;
    return (policy.ttl_ms + 999) / 1000;
}

fn findResponseHeader(headers: []const Header, target_name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, target_name)) return http_headers.trimValue(header.value);
    }
    return null;
}

fn cloneEntryResponse(allocator: std.mem.Allocator, entry: Entry) !BufferedResponse {
    return .{
        .status_code = entry.status_code,
        .content_type = try allocator.dupe(u8, entry.content_type),
        .body = try allocator.dupe(u8, entry.body),
        .headers = try cloneHeadersOwned(allocator, entry.headers),
    };
}

fn cloneHeadersOwned(allocator: std.mem.Allocator, headers: []const Header) ![]Header {
    var out = std.ArrayList(Header).empty;
    errdefer {
        for (out.items) |header| {
            allocator.free(header.name);
            allocator.free(header.value);
        }
        out.deinit(allocator);
    }

    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "cache-status")) continue;
        const name = try allocator.dupe(u8, header.name);
        errdefer allocator.free(name);
        const value = try allocator.dupe(u8, header.value);
        errdefer allocator.free(value);
        try out.append(allocator, .{ .name = name, .value = value });
    }
    return out.toOwnedSlice(allocator);
}

fn freeHeaders(allocator: std.mem.Allocator, headers: []Header) void {
    for (headers) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    allocator.free(headers);
}

test "buffered microcache stores, hits, and expires responses" {
    var store = Store{};
    defer store.deinit();

    const policy = Policy{ .enabled = true, .max_bytes = 1024, .max_entry_bytes = 1024, .ttl_ms = 1000 };
    const headers = [_]Header{.{ .name = "x-layerline-test", .value = "yes" }};
    const response = BufferedResponse{ .status_code = 200, .content_type = "application/json", .body = "{\"ok\":true}\n", .headers = headers[0..] };
    try std.testing.expectEqual(StoreResult.stored, (try store.store("api|host|/path", response, 10, policy)).result);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const hit = (try store.fetch(arena.allocator(), "api|host|/path", 20, policy)).?;
    try std.testing.expectEqual(@as(u16, 200), hit.status_code);
    try std.testing.expectEqualStrings("{\"ok\":true}\n", hit.body);
    try std.testing.expectEqualStrings("cache-status", hit.headers[hit.headers.len - 1].name);
    try std.testing.expectEqualStrings("Layerline; hit; ttl=1; detail=\"microcache\"", hit.headers[hit.headers.len - 1].value);

    try std.testing.expectEqual(StoreResult.stored, (try store.store("api|host|/other", response, 20, policy)).result);
    try std.testing.expectEqual(@as(usize, 1), store.clearMatching("/path"));
    try std.testing.expect(try store.fetch(arena.allocator(), "api|host|/path", 20, policy) == null);
    try std.testing.expect(try store.fetch(arena.allocator(), "api|host|/other", 20, policy) != null);
    try std.testing.expect(try store.fetch(arena.allocator(), "api|host|/other", 2000, policy) == null);
}

test "buffered microcache bypasses private request and response state" {
    const policy = Policy{ .enabled = true, .max_bytes = 1024, .max_entry_bytes = 1024, .ttl_ms = 1000 };
    const req = request_mod.HttpRequest{
        .method = "GET",
        .path = "/api/echo",
        .query = "",
        .headers = "Cookie: session=secret\r\n",
        .version = "HTTP/2.0",
        .body = "",
        .close_connection = true,
    };
    try std.testing.expect(!requestCanUse(req, policy));

    const headers = [_]Header{.{ .name = "set-cookie", .value = "session=secret" }};
    const response = BufferedResponse{ .status_code = 200, .content_type = "text/plain", .body = "ok", .headers = headers[0..] };
    try std.testing.expect(!responseCanStore(response, policy));
}
