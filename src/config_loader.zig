const std = @import("std");

const config_mod = @import("config.zig");
const http_headers = @import("http_headers.zig");

const DomainConfig = config_mod.DomainConfig;
const ServerConfig = config_mod.ServerConfig;
const trimValue = http_headers.trimValue;

pub fn loadConfig(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig, path: []const u8) !void {
    const content = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(config_mod.MAX_CONFIG_BYTES));
    defer allocator.free(content);

    var lines = std.mem.splitSequence(u8, content, "\n");
    var line_number: usize = 0;
    while (lines.next()) |raw_line| {
        line_number += 1;
        var line = trimValue(raw_line);
        if (line.len == 0) continue;

        if (std.mem.indexOfScalar(u8, line, '#')) |comment_start| {
            if (comment_start == 0) continue;
            line = trimValue(line[0..comment_start]);
        }
        if (line.len == 0) continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse {
            std.debug.print("Config error in {s}:{d}: expected key = value\n", .{ path, line_number });
            return error.MalformedConfigLine;
        };
        const key = line[0..eq];
        const value = if (eq + 1 < line.len) line[eq + 1 ..] else "";
        config_mod.applyConfigLine(cfg, allocator, key, value) catch |err| {
            std.debug.print("Config error in {s}:{d}: {s}: {}\n", .{ path, line_number, trimValue(key), err });
            return err;
        };
    }
}

pub fn isDomainConfigFileName(name: []const u8) bool {
    return name.len > 0 and name[0] != '.' and std.mem.endsWith(u8, name, ".conf");
}

pub fn domainConfigNameFromPath(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const slash = std.mem.lastIndexOfAny(u8, path, "/\\");
    const base = if (slash) |pos| path[pos + 1 ..] else path;
    const stem = if (std.mem.endsWith(u8, base, ".conf")) base[0 .. base.len - ".conf".len] else base;
    if (stem.len == 0) return error.InvalidConfigValue;

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    for (stem) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '_' or c == '-') {
            try out.append(allocator, c);
        } else {
            try out.append(allocator, '-');
        }
    }
    return try out.toOwnedSlice(allocator);
}

fn stringLessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
}

pub fn loadDomainConfigFile(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig, path: []const u8) !void {
    const default_name = try domainConfigNameFromPath(allocator, path);
    var domain = try config_mod.initDomainConfig(allocator, default_name);

    const content = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(config_mod.MAX_CONFIG_BYTES));
    defer allocator.free(content);

    var lines = std.mem.splitSequence(u8, content, "\n");
    var line_number: usize = 0;
    while (lines.next()) |raw_line| {
        line_number += 1;
        var line = trimValue(raw_line);
        if (line.len == 0) continue;

        if (std.mem.indexOfScalar(u8, line, '#')) |comment_start| {
            if (comment_start == 0) continue;
            line = trimValue(line[0..comment_start]);
        }
        if (line.len == 0) continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse {
            std.debug.print("Domain config error in {s}:{d}: expected key = value\n", .{ path, line_number });
            return error.MalformedConfigLine;
        };
        const key = line[0..eq];
        const value = if (eq + 1 < line.len) line[eq + 1 ..] else "";
        config_mod.applyDomainConfigLine(&domain, allocator, key, value) catch |err| {
            std.debug.print("Domain config error in {s}:{d}: {s}: {}\n", .{ path, line_number, trimValue(key), err });
            return err;
        };
    }

    if (config_mod.findDomainConfigMutable(cfg, domain.name) != null) return error.DuplicateConfigDomain;
    try cfg.domains.append(allocator, domain);
}

pub fn loadDomainConfigDir(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig, dir_path: []const u8) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
    defer dir.close(io);

    var paths = std.ArrayList([]const u8).empty;
    defer paths.deinit(allocator);

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!isDomainConfigFileName(entry.name)) continue;
        const path = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        try paths.append(allocator, path);
    }
    defer for (paths.items) |path| allocator.free(path);

    std.mem.sort([]const u8, paths.items, {}, stringLessThan);
    for (paths.items) |path| {
        try loadDomainConfigFile(io, allocator, cfg, path);
    }
}

pub fn loadConfiguredDomainConfigs(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
    if (cfg.domain_config_dir) |dir_path| {
        try loadDomainConfigDir(io, allocator, cfg, dir_path);
    }
}

test "domain config names are normalized from paths" {
    const name = try domainConfigNameFromPath(std.testing.allocator, "sites-enabled/my site.conf");
    defer std.testing.allocator.free(name);
    try std.testing.expectEqualStrings("my-site", name);
}
