const std = @import("std");

const config_mod = @import("config.zig");

pub const Policy = struct {
    enabled: bool,
    max_bytes: usize,
    max_entry_bytes: usize,
    ttl_ms: u32,

    pub const disabled: Policy = .{
        .enabled = false,
        .max_bytes = 0,
        .max_entry_bytes = 0,
        .ttl_ms = 0,
    };
};

const Entry = struct {
    key: []u8,
    etag: []u8,
    body: []u8,
    expires_at_ms: i64,
};

pub const StoreResult = enum {
    disabled,
    too_large,
    stored,
};

pub const StoreOutcome = struct {
    result: StoreResult,
    evictions: usize = 0,
};

pub const Store = struct {
    mutex: std.atomic.Mutex = .unlocked,
    allocator: ?std.mem.Allocator = null,
    entries: std.ArrayList(Entry) = .empty,
    body_bytes: usize = 0,

    pub fn fetch(self: *Store, allocator: std.mem.Allocator, key: []const u8, etag: []const u8, now_ms: i64) !?[]u8 {
        self.lock();
        defer self.mutex.unlock();

        self.pruneExpiredLocked(now_ms);
        for (self.entries.items) |entry| {
            if (!std.mem.eql(u8, entry.key, key)) continue;
            if (!std.mem.eql(u8, entry.etag, etag)) continue;
            return try allocator.dupe(u8, entry.body);
        }
        return null;
    }

    pub fn store(self: *Store, key: []const u8, etag: []const u8, body: []const u8, now_ms: i64, policy: Policy) !StoreOutcome {
        if (!policy.enabled) return .{ .result = .disabled };
        if (policy.max_bytes == 0 or policy.max_entry_bytes == 0 or policy.ttl_ms == 0) return .{ .result = .disabled };
        if (body.len > policy.max_entry_bytes or body.len > policy.max_bytes) return .{ .result = .too_large };

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
        while (self.entries.items.len > 0 and self.body_bytes + body.len > policy.max_bytes) {
            self.removeAtLocked(0);
            evictions += 1;
        }
        if (self.body_bytes + body.len > policy.max_bytes) return .{ .result = .too_large, .evictions = evictions };

        const owned_key = try allocator.dupe(u8, key);
        errdefer allocator.free(owned_key);
        const owned_etag = try allocator.dupe(u8, etag);
        errdefer allocator.free(owned_etag);
        const owned_body = try allocator.dupe(u8, body);
        errdefer allocator.free(owned_body);

        const entry = Entry{
            .key = owned_key,
            .etag = owned_etag,
            .body = owned_body,
            .expires_at_ms = now_ms + @as(i64, policy.ttl_ms),
        };

        try self.entries.append(allocator, entry);
        self.body_bytes += body.len;
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
        allocator.free(entry.etag);
        allocator.free(entry.body);
    }
};

pub fn policyFromConfig(cfg: *const config_mod.ServerConfig) Policy {
    return .{
        .enabled = cfg.response_cache_enabled,
        .max_bytes = cfg.response_cache_max_bytes,
        .max_entry_bytes = cfg.response_cache_max_entry_bytes,
        .ttl_ms = cfg.response_cache_ttl_ms,
    };
}

fn ttlSeconds(policy: Policy) u32 {
    if (policy.ttl_ms == 0) return 0;
    return (policy.ttl_ms + 999) / 1000;
}

pub fn cacheStatusStatic(allocator: std.mem.Allocator, content_encoding: ?[]const u8) ![]const u8 {
    const detail = if (content_encoding == null) "static-file" else "precompressed-static";
    return std.fmt.allocPrint(allocator, "Layerline; fwd=uri-miss; detail=\"{s}\"", .{detail});
}

pub fn cacheStatusStored(allocator: std.mem.Allocator, policy: Policy) ![]const u8 {
    return std.fmt.allocPrint(allocator, "Layerline; fwd=uri-miss; stored; ttl={d}; detail=\"response-cache\"", .{ttlSeconds(policy)});
}

pub fn cacheStatusHit(allocator: std.mem.Allocator, policy: Policy) ![]const u8 {
    return std.fmt.allocPrint(allocator, "Layerline; hit; ttl={d}; detail=\"response-cache\"", .{ttlSeconds(policy)});
}

test "static response cache stores, hits, and expires entries" {
    var store = Store{};
    defer store.deinit();

    const policy = Policy{ .enabled = true, .max_bytes = 16, .max_entry_bytes = 16, .ttl_ms = 1000 };
    try std.testing.expectEqual(StoreResult.stored, (try store.store("file", "\"etag\"", "body", 10, policy)).result);

    const hit = (try store.fetch(std.testing.allocator, "file", "\"etag\"", 20)).?;
    defer std.testing.allocator.free(hit);
    try std.testing.expectEqualStrings("body", hit);

    try std.testing.expect(try store.fetch(std.testing.allocator, "file", "\"other\"", 20) == null);
    try std.testing.expect(try store.fetch(std.testing.allocator, "file", "\"etag\"", 2000) == null);
}
