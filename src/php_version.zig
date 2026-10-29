const std = @import("std");

pub const Version = struct { major: u16, minor: u16, patch: u16, prerelease: bool = false };

pub fn affected(version: Version) bool {
    if (version.major < 8) return true;
    if (version.major > 8) return false;
    const fixed_patch: u16 = switch (version.minor) {
        0, 1 => return true,
        2 => 35,
        3 => 36,
        4 => 27,
        5 => 12,
        else => return false,
    };
    return version.patch < fixed_patch or (version.patch == fixed_patch and version.prerelease);
}

fn prereleaseSuffix(suffix: []const u8) bool {
    if (suffix.len == 0) return false;
    if (std.ascii.isAlphabetic(suffix[0])) return true;
    if (suffix[0] != '-' and suffix[0] != '_') return false;
    const label = suffix[1..];
    inline for (.{ "dev", "alpha", "beta", "rc" }) |prefix| {
        if (std.ascii.startsWithIgnoreCase(label, prefix)) return true;
    }
    return false;
}

pub fn exposedValue(name: []const u8, value: []const u8) ?Version {
    if (!std.ascii.eqlIgnoreCase(name, "X-Powered-By") and !std.ascii.eqlIgnoreCase(name, "Server")) return null;
    if (value.len < 9) return null;
    tokens: for (0..value.len - 3) |offset| {
        if (!std.ascii.eqlIgnoreCase(value[offset..][0..4], "PHP/")) continue;
        var cursor = offset + 4;
        var numbers: [3]u16 = undefined;
        for (&numbers, 0..) |*number, i| {
            const start = cursor;
            while (cursor < value.len and std.ascii.isDigit(value[cursor])) : (cursor += 1) {}
            if (cursor == start) continue :tokens;
            number.* = std.fmt.parseInt(u16, value[start..cursor], 10) catch continue :tokens;
            if (i < 2) {
                if (cursor == value.len or value[cursor] != '.') continue :tokens;
                cursor += 1;
            }
        }
        const version = Version{ .major = numbers[0], .minor = numbers[1], .patch = numbers[2], .prerelease = prereleaseSuffix(value[cursor..]) };
        if (affected(version)) return version;
    }
    return null;
}

pub fn exposedHeaders(raw: []const u8) ?Version {
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t\r");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t\r");
        if (exposedValue(name, value)) |version| return version;
    }
    return null;
}

pub fn updateMessage(allocator: std.mem.Allocator, version: Version) ![]u8 {
    return std.fmt.allocPrint(allocator, "This site's PHP backend reports PHP/{d}.{d}.{d}{s}, a version affected by PHP2Shell.\n\n" ++
        "Site owner: update PHP to a patched release and restart every PHP worker.\n" ++
        "Minimum fixed releases: PHP 8.2.35, 8.3.36, 8.4.27, or 8.5.12. Older branches need migration.\n" ++
        "If your vendor backported the fix, verify the exact installed package and its security advisory.\n" ++
        "Layerline has withheld the backend response.\n", .{ version.major, version.minor, version.patch, if (version.prerelease) " (pre-release)" else "" });
}

pub fn log(version: Version) void {
    if (@import("builtin").is_test) return;
    std.debug.print("{{\"event\":\"security.php_version\",\"action\":\"deny\",\"status\":503,\"reported_version\":\"{d}.{d}.{d}\",\"prerelease\":{}}}\n", .{ version.major, version.minor, version.patch, version.prerelease });
}

test "PHP2Shell version floors and exposed response headers" {
    for ([_][]const u8{ "PHP/8.2.34", "PHP/8.3.35", "PHP/8.4.26", "PHP/8.5.11", "PHP/7.4.33", "PHP/8.1.31", "PHP/8.5.12RC1" }) |value|
        try std.testing.expect(exposedValue("X-Powered-By", value) != null);
    for ([_][]const u8{ "PHP/8.2.35", "PHP/8.3.36", "PHP/8.4.27", "PHP/8.5.12", "PHP/8.5.13", "PHP/8.5.13RC1", "PHP/not-a-version" }) |value|
        try std.testing.expect(exposedValue("Server", value) == null);
    for ([_][]const u8{ "PHP/not-a-version PHP/8.4.26", "PHP/999999.0.0 PHP/8.4.26", "PHP/8.4.27 PHP/8.4.26", "Apache (PHP/8.4.26)" }) |value|
        try std.testing.expect(exposedValue("Server", value) != null);
    try std.testing.expect(exposedValue("X-Comment", "PHP/8.4.26") == null);
    try std.testing.expect(exposedHeaders("X-Powered-By: PHP/8.5.12\r\nServer: Apache PHP/8.4.26") != null);
}

test "fixed-floor development builds are not proof of a patched PHP release" {
    for ([_][]const u8{ "PHP/8.2.35-dev", "PHP/8.3.36-RC1", "PHP/8.4.27_beta1", "PHP/8.5.12-alpha2" }) |value| {
        const version = exposedValue("Server", value).?;
        try std.testing.expect(version.prerelease);
        const message = try updateMessage(std.testing.allocator, version);
        defer std.testing.allocator.free(message);
        try std.testing.expect(std.mem.indexOf(u8, message, "(pre-release)") != null);
    }
    for ([_][]const u8{ "PHP/8.4.27-1ubuntu1", "PHP/8.4.28-dev", "PHP/8.5.13-RC1" }) |value|
        try std.testing.expect(exposedValue("X-Powered-By", value) == null);
}
