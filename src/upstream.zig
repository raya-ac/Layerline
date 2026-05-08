const std = @import("std");

const config_mod = @import("config.zig");
const http_headers = @import("http_headers.zig");

const findHeaderValue = http_headers.findHeaderValue;
const trimValue = http_headers.trimValue;
const ServerConfig = config_mod.ServerConfig;
const UpstreamConfig = config_mod.UpstreamConfig;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;
const upstreamPoolPolicyName = config_mod.upstreamPoolPolicyName;

pub var round_robin_cursor = std.atomic.Value(usize).init(0);
pub var random_cursor = std.atomic.Value(u64).init(0x9e3779b97f4a7c15);

pub const RequestHashInput = struct {
    path: []const u8,
    query: []const u8,
    headers: []const u8,
};

pub fn upstreamPoolTargetCount(pool: UpstreamPoolConfig) usize {
    return pool.targets.items.len;
}

fn upstreamRandomTicket() usize {
    var z = random_cursor.fetchAdd(0x9e3779b97f4a7c15, .monotonic);
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return @truncate(z ^ (z >> 31));
}

pub fn upstreamInSlowStart(upstream: *UpstreamConfig, now_ms: i64, cfg: ?*const ServerConfig) bool {
    const slow_start_ms = if (cfg) |config| config.upstream_slow_start_ms else 0;
    if (slow_start_ms == 0) return false;
    const recovered_at = upstream.recovered_at_ms.load(.monotonic);
    if (recovered_at == 0) return false;
    if (now_ms <= recovered_at) return true;
    if (now_ms - recovered_at < @as(i64, @intCast(slow_start_ms))) return true;
    upstream.recovered_at_ms.store(0, .monotonic);
    return false;
}

pub fn upstreamEffectiveWeight(upstream: *UpstreamConfig, now_ms: i64, cfg: ?*const ServerConfig) usize {
    const base_weight = upstream.weight;
    if (base_weight <= 1) return base_weight;
    const config = cfg orelse return base_weight;
    if (config.upstream_slow_start_ms == 0) return base_weight;

    const recovered_at = upstream.recovered_at_ms.load(.monotonic);
    if (recovered_at == 0) return base_weight;
    if (now_ms <= recovered_at) return 1;

    const elapsed_ms = now_ms - recovered_at;
    const slow_start_ms = @as(i64, @intCast(config.upstream_slow_start_ms));
    if (elapsed_ms >= slow_start_ms) {
        upstream.recovered_at_ms.store(0, .monotonic);
        return base_weight;
    }

    const scaled = (@as(u128, base_weight) * @as(u128, @intCast(elapsed_ms))) / @as(u128, @intCast(slow_start_ms));
    return @max(@as(usize, 1), @min(base_weight, @as(usize, @intCast(scaled))));
}

pub fn upstreamInHalfOpen(upstream: *UpstreamConfig, now_ms: i64) bool {
    const until_ms = upstream.ejected_until_ms.load(.monotonic);
    return until_ms != 0 and now_ms >= until_ms;
}

pub fn upstreamIsSelectable(upstream: *UpstreamConfig, now_ms: i64, cfg: ?*const ServerConfig) bool {
    if (upstreamIsEjected(upstream, now_ms)) return false;
    const config = cfg orelse return true;
    if (!config.upstream_circuit_breaker_enabled) return true;
    if (!upstreamInHalfOpen(upstream, now_ms)) return true;
    if (config.upstream_circuit_half_open_max == 0) return false;
    return upstream.half_open_requests.load(.monotonic) < config.upstream_circuit_half_open_max;
}

fn upstreamLeastConnectionsTicket(pool: *UpstreamPoolConfig, now_ms: i64, cfg: ?*const ServerConfig) usize {
    const target_count = pool.targets.items.len;
    const tie_ticket = round_robin_cursor.fetchAdd(1, .monotonic);
    if (target_count == 0) return tie_ticket;

    var best_index: ?usize = null;
    var best_active: usize = std.math.maxInt(usize);
    var offset: usize = 0;
    while (offset < target_count) : (offset += 1) {
        const index = (tie_ticket + offset) % target_count;
        const upstream = &pool.targets.items[index];
        if (!upstreamIsSelectable(upstream, now_ms, cfg)) continue;

        var active = upstream.active_requests.load(.monotonic);
        if (upstreamInSlowStart(upstream, now_ms, cfg)) active += 1;
        if (best_index == null or active < best_active) {
            best_index = index;
            best_active = active;
        }
    }

    return best_index orelse tie_ticket;
}

fn upstreamWeightedTicket(pool: *UpstreamPoolConfig, now_ms: i64, cfg: ?*const ServerConfig) usize {
    const target_count = pool.targets.items.len;
    const ticket = round_robin_cursor.fetchAdd(1, .monotonic);
    if (target_count == 0) return ticket;

    var total_weight: usize = 0;
    for (pool.targets.items) |*upstream| {
        if (!upstreamIsSelectable(upstream, now_ms, cfg)) continue;
        total_weight += upstreamEffectiveWeight(upstream, now_ms, cfg);
    }
    if (total_weight == 0) return ticket;

    var remaining = ticket % total_weight;
    for (pool.targets.items, 0..) |*upstream, index| {
        if (!upstreamIsSelectable(upstream, now_ms, cfg)) continue;
        const weight = upstreamEffectiveWeight(upstream, now_ms, cfg);
        if (remaining < weight) return index;
        remaining -= weight;
    }

    return ticket;
}

const UPSTREAM_HASH_OFFSET: u64 = 0xcbf29ce484222325;
const UPSTREAM_HASH_PRIME: u64 = 0x100000001b3;

fn upstreamHashByte(seed: u64, value: u8) u64 {
    return (seed ^ value) *% UPSTREAM_HASH_PRIME;
}

fn upstreamHashBytes(seed: u64, value: []const u8) u64 {
    var hash = seed;
    for (value) |byte| {
        hash = upstreamHashByte(hash, byte);
    }
    return hash;
}

fn upstreamHashU16(seed: u64, value: u16) u64 {
    var hash = seed;
    hash = upstreamHashByte(hash, @intCast(value & 0xff));
    hash = upstreamHashByte(hash, @intCast(value >> 8));
    return hash;
}

fn firstForwardedValue(value: []const u8) []const u8 {
    const first = if (std.mem.indexOfScalar(u8, value, ',')) |comma| value[0..comma] else value;
    return std.mem.trim(u8, first, " \t\r\n");
}

fn upstreamConsistentHashKey(req: RequestHashInput) u64 {
    var hash = UPSTREAM_HASH_OFFSET;

    if (findHeaderValue(req.headers, "X-Forwarded-For")) |forwarded| {
        const first = firstForwardedValue(forwarded);
        if (first.len > 0) return upstreamHashBytes(upstreamHashBytes(hash, "xff:"), first);
    }
    if (findHeaderValue(req.headers, "X-Real-IP")) |real_ip| {
        const trimmed = trimValue(real_ip);
        if (trimmed.len > 0) return upstreamHashBytes(upstreamHashBytes(hash, "xri:"), trimmed);
    }
    if (findHeaderValue(req.headers, "Host")) |host| {
        hash = upstreamHashBytes(upstreamHashBytes(hash, "host:"), host);
    }
    hash = upstreamHashBytes(upstreamHashBytes(hash, "path:"), req.path);
    if (req.query.len > 0) {
        hash = upstreamHashBytes(upstreamHashBytes(hash, "?"), req.query);
    }
    return hash;
}

fn upstreamConsistentHashTicket(pool: *UpstreamPoolConfig, req: ?RequestHashInput, now_ms: i64, cfg: ?*const ServerConfig) usize {
    const target_count = pool.targets.items.len;
    const fallback = round_robin_cursor.fetchAdd(1, .monotonic);
    if (target_count == 0) return fallback;

    const key = if (req) |request| upstreamConsistentHashKey(request) else fallback;
    var best_index: ?usize = null;
    var best_score: u64 = 0;

    for (pool.targets.items, 0..) |*upstream, index| {
        if (!upstreamIsSelectable(upstream, now_ms, cfg)) continue;

        var score = upstreamHashBytes(key, upstream.host);
        score = upstreamHashU16(upstreamHashByte(score, 0), upstream.port);
        score = upstreamHashBytes(upstreamHashByte(score, 0), upstream.base_path);
        if (best_index == null or score > best_score) {
            best_index = index;
            best_score = score;
        }
    }

    return best_index orelse @as(usize, @intCast(key % target_count));
}

pub fn upstreamStartTicket(pool: *UpstreamPoolConfig, policy: UpstreamPoolPolicy, now_ms: i64, req: ?RequestHashInput, cfg: ?*const ServerConfig) usize {
    return switch (policy) {
        .round_robin => round_robin_cursor.fetchAdd(1, .monotonic),
        .random => upstreamRandomTicket(),
        .least_connections => upstreamLeastConnectionsTicket(pool, now_ms, cfg),
        .weighted => upstreamWeightedTicket(pool, now_ms, cfg),
        .consistent_hash => upstreamConsistentHashTicket(pool, req, now_ms, cfg),
    };
}

pub fn selectUpstream(pool: *UpstreamPoolConfig) ?*UpstreamConfig {
    if (pool.targets.items.len == 0) return null;
    const ticket = upstreamStartTicket(pool, pool.policy, 0, null, null);
    return &pool.targets.items[ticket % pool.targets.items.len];
}

pub fn upstreamIsEjected(upstream: *UpstreamConfig, now_ms: i64) bool {
    const until_ms = upstream.ejected_until_ms.load(.monotonic);
    if (until_ms == 0) return false;
    return now_ms < until_ms;
}

pub fn upstreamRecordSuccess(upstream: *UpstreamConfig, now_ms: i64, slow_start_ms: u32) void {
    const was_recovering = upstream.ejected_until_ms.load(.monotonic) != 0 or upstream.passive_failures.load(.monotonic) != 0;
    upstream.passive_failures.store(0, .monotonic);
    upstream.ejected_until_ms.store(0, .monotonic);
    if (was_recovering and slow_start_ms > 0) {
        upstream.recovered_at_ms.store(now_ms, .monotonic);
    }
}

pub fn upstreamRecordFailure(upstream: *UpstreamConfig, now_ms: i64, max_failures: usize, fail_timeout_ms: u32) bool {
    if (max_failures == 0 or fail_timeout_ms == 0) return false;

    const half_open = upstreamInHalfOpen(upstream, now_ms);
    const failures = upstream.passive_failures.fetchAdd(1, .monotonic) + 1;
    if (!half_open and failures < max_failures) return false;

    const previous_until = upstream.ejected_until_ms.load(.monotonic);
    const cooldown_until = now_ms + @as(i64, @intCast(fail_timeout_ms));
    upstream.ejected_until_ms.store(cooldown_until, .monotonic);
    upstream.recovered_at_ms.store(0, .monotonic);
    return previous_until == 0 or previous_until <= now_ms;
}

pub const UpstreamAttemptLease = struct {
    half_open: bool,
};

pub fn upstreamBeginAttempt(upstream: *UpstreamConfig, now_ms: i64, cfg: *const ServerConfig) ?UpstreamAttemptLease {
    if (upstreamIsEjected(upstream, now_ms)) return null;

    var half_open = false;
    if (cfg.upstream_circuit_breaker_enabled and upstreamInHalfOpen(upstream, now_ms)) {
        if (cfg.upstream_circuit_half_open_max == 0) return null;
        const active_half_open = upstream.half_open_requests.fetchAdd(1, .monotonic);
        if (active_half_open >= cfg.upstream_circuit_half_open_max) {
            _ = upstream.half_open_requests.fetchSub(1, .monotonic);
            return null;
        }
        half_open = true;
    }

    _ = upstream.active_requests.fetchAdd(1, .monotonic);
    return .{ .half_open = half_open };
}

pub fn upstreamEndAttempt(upstream: *UpstreamConfig, lease: UpstreamAttemptLease) void {
    _ = upstream.active_requests.fetchSub(1, .monotonic);
    if (lease.half_open) _ = upstream.half_open_requests.fetchSub(1, .monotonic);
}

pub fn upstreamAttemptLimit(pool: *const UpstreamPoolConfig, retry_budget: usize) usize {
    const target_count = pool.targets.items.len;
    if (target_count == 0) return 0;
    if (retry_budget >= target_count) return target_count;
    return retry_budget + 1;
}

pub fn upstreamAtAttempt(pool: *UpstreamPoolConfig, start_ticket: usize, attempt: usize) *UpstreamConfig {
    const target_count = pool.targets.items.len;
    var index = start_ticket % target_count;
    var remaining = attempt;
    while (remaining > 0) : (remaining -= 1) {
        index += 1;
        if (index == target_count) index = 0;
    }
    return &pool.targets.items[index];
}

pub fn printUpstreamPool(policy: UpstreamPoolPolicy, pool: UpstreamPoolConfig) void {
    std.debug.print(" upstream={s}[", .{upstreamPoolPolicyName(policy)});
    for (pool.targets.items, 0..) |up, i| {
        if (i > 0) std.debug.print(",", .{});
        std.debug.print("{s}:{d}{s}", .{ up.host, up.port, up.base_path });
        if (up.weight != 1) std.debug.print(" weight={d}", .{up.weight});
    }
    std.debug.print("]", .{});
}
