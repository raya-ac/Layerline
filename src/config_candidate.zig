const std = @import("std");
const acme = @import("acme.zig");
const config = @import("config.zig");
const loader = @import("config_loader.zig");
const store = @import("config_store.zig");
const tls_material = @import("tls_material.zig");
const upstream_material = @import("upstream_material.zig");

const ServerConfig = config.ServerConfig;

// Keep one owner in the caller's scope until publication transfers its arena.
pub const Candidate = struct {
    arena: ?*std.heap.ArenaAllocator,
    cfg: *ServerConfig,

    pub fn load(io: std.Io, backing: std.mem.Allocator, path: []const u8, active: ?*const ServerConfig) !Candidate {
        const arena = try backing.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(backing);
        errdefer {
            arena.deinit();
            backing.destroy(arena);
        }
        const allocator = arena.allocator();
        const cfg = try allocator.create(ServerConfig);
        cfg.* = config.defaultServerConfig();
        errdefer deinitMaterials(allocator, cfg);
        cfg.config_path = try allocator.dupe(u8, path);
        try loader.loadConfig(io, allocator, cfg, cfg.config_path);
        try loader.loadConfiguredDomainConfigs(io, allocator, cfg);
        config.normalizeConfig(cfg);
        try acme.applyLetsEncryptDefaultCertPaths(allocator, cfg);
        try config.validateConfig(cfg);
        if (active) |previous| try validateCompatibility(previous, cfg);
        try loadMaterials(io, allocator, cfg);
        return .{ .arena = arena, .cfg = cfg };
    }

    pub fn deinit(self: *Candidate) void {
        const arena = self.arena orelse return;
        const backing = arena.child_allocator;
        // Arena teardown alone does not erase loaded signing keys.
        deinitMaterials(arena.allocator(), self.cfg);
        arena.deinit();
        backing.destroy(arena);
        self.arena = null;
        self.cfg = undefined;
    }

    pub fn publish(self: *Candidate, target: *store.Store, generation: u64, shutdown: *const std.atomic.Value(bool)) !void {
        const arena = self.arena orelse return error.ConfigCandidateConsumed;
        if (shutdown.load(.acquire)) return error.Canceled;
        try target.activateOwned(arena, self.cfg, generation);
        // Failed publication leaves cleanup here; only success transfers it.
        self.arena = null;
    }
};

pub fn loadMaterials(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
    errdefer deinitMaterials(allocator, cfg);
    try tls_material.loadAll(io, allocator, cfg);
    try upstream_material.loadAll(io, allocator, cfg);
}

pub fn deinitMaterials(allocator: std.mem.Allocator, cfg: *ServerConfig) void {
    tls_material.deinitAll(allocator, cfg);
    upstream_material.deinitAll(cfg);
}

fn optionalStringEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?, b.?);
}

fn validateCompatibility(active: *const ServerConfig, candidate: *const ServerConfig) !void {
    if (candidate.worker_stack_size > active.worker_stack_size) return error.ReloadRequiresRestart;
    if (active.memory_budget_bytes != candidate.memory_budget_bytes) return error.ReloadRequiresRestart;
    if (active.descriptor_limit != candidate.descriptor_limit) return error.ReloadRequiresRestart;
    if (active.io_thread_limit != candidate.io_thread_limit or active.io_stack_size != candidate.io_stack_size) return error.ReloadRequiresRestart;
    if (!std.mem.eql(u8, active.host, candidate.host)) return error.ReloadRequiresRestart;
    if (active.port != candidate.port) return error.ReloadRequiresRestart;
    if (active.tls_enabled != candidate.tls_enabled) return error.ReloadRequiresRestart;
    if (active.tls_auto != candidate.tls_auto) return error.ReloadRequiresRestart;
    if (active.http_redirect_enabled != candidate.http_redirect_enabled) return error.ReloadRequiresRestart;
    if (active.http_redirect_port != candidate.http_redirect_port) return error.ReloadRequiresRestart;
    if (active.http_redirect_https_port != candidate.http_redirect_https_port) return error.ReloadRequiresRestart;
    if (active.http3_enabled != candidate.http3_enabled) return error.ReloadRequiresRestart;
    if (active.http3_port != candidate.http3_port) return error.ReloadRequiresRestart;
    if (active.admin_enabled != candidate.admin_enabled) return error.ReloadRequiresRestart;
    if (!optionalStringEql(active.admin_socket_path, candidate.admin_socket_path)) return error.ReloadRequiresRestart;
}
