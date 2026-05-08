const std = @import("std");

pub const Context = struct {
    enabled: bool,
    sink: []const u8,
    method: []const u8,
    path: []const u8,
    query: []const u8,
    protocol: []const u8,
    host: []const u8,
    request_id: []const u8,
    start_ms: i64,
    handler: []const u8 = "routing",
    upstream: ?[]const u8 = null,
    error_name: ?[]const u8 = null,
    logged: bool = false,
};

pub const Writer = struct {
    mutex: std.Io.Mutex = .init,

    pub fn emit(self: *Writer, io: std.Io, maybe_ctx: ?*Context, server_name: []const u8, status_code: u16, body_bytes: usize) void {
        const ctx = maybe_ctx orelse return;
        if (!ctx.enabled or ctx.logged) return;
        ctx.logged = true;

        var out = std.ArrayList(u8).empty;
        const allocator = std.heap.page_allocator;
        defer out.deinit(allocator);

        const now_real_ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
        const now_awake_ms = std.Io.Timestamp.now(io, .awake).toMilliseconds();
        const duration_ms = @max(@as(i64, 0), now_awake_ms - ctx.start_ms);

        out.append(allocator, '{') catch return;
        appendJsonNumberField(&out, allocator, "ts_ms", now_real_ms, false) catch return;
        appendJsonStringField(&out, allocator, "server", server_name, true) catch return;
        appendJsonStringField(&out, allocator, "method", ctx.method, true) catch return;
        appendJsonStringField(&out, allocator, "path", ctx.path, true) catch return;
        appendJsonStringField(&out, allocator, "query", ctx.query, true) catch return;
        appendJsonStringField(&out, allocator, "host", ctx.host, true) catch return;
        appendJsonStringField(&out, allocator, "protocol", ctx.protocol, true) catch return;
        appendJsonStringField(&out, allocator, "request_id", ctx.request_id, true) catch return;
        appendJsonNumberField(&out, allocator, "status", status_code, true) catch return;
        appendJsonNumberField(&out, allocator, "bytes", body_bytes, true) catch return;
        appendJsonNumberField(&out, allocator, "duration_ms", duration_ms, true) catch return;
        appendJsonStringField(&out, allocator, "handler", ctx.handler, true) catch return;
        if (ctx.upstream) |upstream| {
            appendJsonStringField(&out, allocator, "upstream", upstream, true) catch return;
        }
        if (ctx.error_name) |error_name| {
            appendJsonStringField(&out, allocator, "error", error_name, true) catch return;
        }
        out.appendSlice(allocator, "}\n") catch return;

        self.writeLine(io, ctx.sink, out.items) catch |err| {
            std.debug.print("Access log write failed: {}\n", .{err});
        };
    }

    fn writeLine(self: *Writer, io: std.Io, sink: []const u8, line: []const u8) !void {
        if (usesStderr(sink)) {
            std.debug.print("{s}", .{line});
            return;
        }
        if (usesStdout(sink)) {
            try std.Io.File.stdout().writeStreamingAll(io, line);
            return;
        }

        try ensureParentDir(io, sink);
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var file = std.Io.Dir.cwd().openFile(io, sink, .{ .mode = .write_only }) catch |err| switch (err) {
            error.FileNotFound => try std.Io.Dir.cwd().createFile(io, sink, .{ .truncate = false, .permissions = @enumFromInt(0o640) }),
            else => return err,
        };
        defer file.close(io);

        const stat = std.Io.Dir.cwd().statFile(io, sink, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.FileNotFound,
            else => return err,
        };
        try file.writePositionalAll(io, line, stat.size);
    }
};

pub fn setHandler(maybe_ctx: ?*Context, handler: []const u8) void {
    if (maybe_ctx) |ctx| ctx.handler = handler;
}

pub fn setUpstream(maybe_ctx: ?*Context, upstream: []const u8) void {
    if (maybe_ctx) |ctx| ctx.upstream = upstream;
}

pub fn setError(maybe_ctx: ?*Context, error_name: []const u8) void {
    if (maybe_ctx) |ctx| ctx.error_name = error_name;
}

fn appendJsonString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    try out.append(allocator, '"');
    for (text) |byte| {
        switch (byte) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            0...8, 11...12, 14...0x1f => try out.print(allocator, "\\u{x:0>4}", .{byte}),
            else => try out.append(allocator, byte),
        }
    }
    try out.append(allocator, '"');
}

fn appendJsonStringField(out: *std.ArrayList(u8), allocator: std.mem.Allocator, name: []const u8, value: []const u8, comma: bool) !void {
    if (comma) try out.append(allocator, ',');
    try appendJsonString(out, allocator, name);
    try out.append(allocator, ':');
    try appendJsonString(out, allocator, value);
}

fn appendJsonNumberField(out: *std.ArrayList(u8), allocator: std.mem.Allocator, name: []const u8, value: anytype, comma: bool) !void {
    if (comma) try out.append(allocator, ',');
    try appendJsonString(out, allocator, name);
    try out.print(allocator, ":{d}", .{value});
}

fn usesStderr(sink: []const u8) bool {
    return sink.len == 0 or std.mem.eql(u8, sink, "-") or std.ascii.eqlIgnoreCase(sink, "stderr");
}

fn usesStdout(sink: []const u8) bool {
    return std.ascii.eqlIgnoreCase(sink, "stdout");
}

fn ensureParentDir(io: std.Io, path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    if (parent.len == 0 or std.mem.eql(u8, parent, ".")) return;
    if (std.Io.Dir.cwd().statFile(io, parent, .{})) |_| {
        return;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    std.Io.Dir.cwd().createDirPath(io, parent) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}
