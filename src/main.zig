const std = @import("std");

const app = @import("app.zig");

pub fn main(init: std.process.Init.Minimal) !void {
    try @import("runtime_io.zig").run(init, app.main);
}
