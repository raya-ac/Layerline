const std = @import("std");

pub const Version = struct { major: u16, minor: u16, patch: u16 };

pub fn affected(version: Version) bool {
    if (version.major < 8) return true;
    if (version.major > 8) return false;
    return switch (version.minor) {
        0, 1 => true,
        2 => version.patch < 35,
        3 => version.patch < 36,
        4 => version.patch < 27,
        5 => version.patch < 12,
        else => false,
    };
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
        const version = Version{ .major = numbers[0], .minor = numbers[1], .patch = numbers[2] };
        if (affected(version)) return version;
        // A pre-release at the patch floor does not establish that the fix landed.
        // Later patch releases have already crossed that floor.
        if (cursor < value.len and std.ascii.isAlphabetic(value[cursor]) and version.patch > 0) {
            var previous = version;
            previous.patch -= 1;
            if (affected(previous)) return version;
        }
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
    return std.fmt.allocPrint(allocator, "This site's PHP backend reports PHP/{d}.{d}.{d}, a version affected by PHP2Shell.\n\n" ++
        "Site owner: update PHP to a patched release and restart every PHP worker.\n" ++
        "Minimum fixed releases: PHP 8.2.35, 8.3.36, 8.4.27, or 8.5.12. Older branches need migration.\n" ++
        "If your vendor backported the fix, verify the exact installed package and its security advisory.\n" ++
        "Layerline has withheld the backend response.\n", .{ version.major, version.minor, version.patch });
}

pub fn log(version: Version) void {
    if (@import("builtin").is_test) return;
    std.debug.print("{{\"event\":\"security.php_version\",\"action\":\"deny\",\"status\":503,\"reported_version\":\"{d}.{d}.{d}\"}}\n", .{ version.major, version.minor, version.patch });
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
