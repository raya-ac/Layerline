const std = @import("std");
const headers = @import("http_headers.zig");

pub fn parseSize(value: []const u8) !usize {
    var end: usize = 0;
    while (end < value.len and std.ascii.isHex(value[end])) end += 1;
    if (end == 0) return error.InvalidChunk;
    const size = std.fmt.parseInt(usize, value[0..end], 16) catch return error.InvalidChunk;
    var cursor = end;
    while (cursor < value.len) {
        while (cursor < value.len and (value[cursor] == ' ' or value[cursor] == '\t')) cursor += 1;
        if (cursor == value.len or value[cursor] != ';') return error.InvalidChunk;
        cursor += 1;
        while (cursor < value.len and (value[cursor] == ' ' or value[cursor] == '\t')) cursor += 1;
        const name = cursor;
        while (cursor < value.len and headers.isHeaderNameByte(value[cursor])) cursor += 1;
        if (cursor == name) return error.InvalidChunk;
        while (cursor < value.len and (value[cursor] == ' ' or value[cursor] == '\t')) cursor += 1;
        if (cursor == value.len or value[cursor] != '=') continue;
        cursor += 1;
        while (cursor < value.len and (value[cursor] == ' ' or value[cursor] == '\t')) cursor += 1;
        if (cursor == value.len) return error.InvalidChunk;
        if (value[cursor] != '"') {
            const start = cursor;
            while (cursor < value.len and headers.isHeaderNameByte(value[cursor])) cursor += 1;
            if (cursor == start) return error.InvalidChunk;
        } else {
            cursor += 1;
            while (true) {
                if (cursor == value.len) return error.InvalidChunk;
                var character = value[cursor];
                cursor += 1;
                if (character == '"') break;
                if (character == '\\') {
                    if (cursor == value.len) return error.InvalidChunk;
                    character = value[cursor];
                    cursor += 1;
                }
                if ((character < 32 and character != '\t') or character == 127) return error.InvalidChunk;
            }
        }
    }
    return size;
}

test "chunk sizes and extensions use the same strict grammar in both directions" {
    try std.testing.expectEqual(5, try parseSize("5 ; ext = \"a;\\\"b\"; flag"));
    try std.testing.expectEqual(0, try parseSize("000; end=yes"));
    for ([_][]const u8{ "", "+1", " 1", "1 ", "1_0", "1;", "1; =x", "1; x=", "1; x=\"open", "1; x=\"bad\x00\"", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" }) |value| {
        try std.testing.expectError(error.InvalidChunk, parseSize(value));
    }
}
