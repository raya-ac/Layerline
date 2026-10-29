const std = @import("std");
const access_log = @import("access_log.zig");
const config = @import("config.zig");
const flow_mod = @import("http2_flow.zig");
const support = @import("http2_support.zig");
const request = @import("request.zig");
const read_interrupt = @import("read_interrupt.zig");
const resource_budget = @import("resource_budget.zig");

pub const Result = struct {
    response: support.BufferedResponse,
    request_id: []const u8,
    access: access_log.Context,
    response_headers: []const config.ResponseHeaderRule,
    compression_policy: config.CompressionPolicy,
};

pub const Callbacks = struct {
    prepare: *const fn (std.Io, std.mem.Allocator, *config.ServerConfig, request.HttpRequest, *const std.process.Environ.Map) anyerror!Result,
    deliver: *const fn (std.Io.net.Stream, std.mem.Allocator, u32, request.HttpRequest, *Result) anyerror!void,
};

const admitted = &resource_budget.http2_jobs;
pub const max_global_jobs = resource_budget.max_http2_jobs;
pub const max_connection_jobs = 8;

const Job = struct {
    arena: std.heap.ArenaAllocator,
    stream_id: u32,
    req: request.HttpRequest,
    bytes: usize,
    canceled: std.atomic.Value(bool) = .init(false),
    done: std.atomic.Value(bool) = .init(false),
    result: anyerror!Result = undefined,
};

pub const Dispatcher = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *config.ServerConfig,
    env: *const std.process.Environ.Map,
    callbacks: Callbacks,
    wake: read_interrupt.Wake,
    group: std.Io.Group = .init,
    jobs: [max_connection_jobs]?*Job = @splat(null),
    request_bytes: usize = 0,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, cfg: *config.ServerConfig, env: *const std.process.Environ.Map, callbacks: Callbacks) !Dispatcher {
        return .{ .io = io, .allocator = allocator, .cfg = cfg, .env = env, .callbacks = callbacks, .wake = try read_interrupt.Wake.init() };
    }

    pub fn deinit(self: *Dispatcher) void {
        for (self.jobs) |maybe| if (maybe) |job| job.canceled.store(true, .release);
        // No task may retain the connection, request arena or wake descriptor
        // after the connection thread returns to its TLS/config cleanup.
        self.group.cancel(self.io);
        for (&self.jobs) |*maybe| {
            if (maybe.*) |job| self.destroy(job);
            maybe.* = null;
        }
        self.wake.deinit();
    }

    pub fn count(self: *const Dispatcher) usize {
        var result: usize = 0;
        for (self.jobs) |job| if (job != null) {
            result += 1;
        };
        return result;
    }

    pub fn submit(self: *Dispatcher, stream_id: u32, req: request.HttpRequest) !void {
        var slot: ?usize = null;
        for (self.jobs, 0..) |job, i| if (job == null) {
            slot = i;
            break;
        };
        const index = slot orelse return error.DispatchLimit;
        const bytes = req.method.len + req.path.len + req.query.len + req.headers.len + req.body.len;
        if (bytes > flow_mod.State.max_queued_bytes -| self.request_bytes) return error.DispatchLimit;
        var current = admitted.load(.acquire);
        while (true) {
            if (current >= max_global_jobs) return error.DispatchLimit;
            current = admitted.cmpxchgWeak(current, current + 1, .acq_rel, .acquire) orelse break;
        }
        errdefer _ = admitted.fetchSub(1, .acq_rel);
        const job = try self.allocator.create(Job);
        errdefer self.allocator.destroy(job);
        job.* = .{ .arena = std.heap.ArenaAllocator.init(self.allocator), .stream_id = stream_id, .bytes = bytes, .req = undefined };
        errdefer job.arena.deinit();
        job.req = try support.cloneRequest(job.arena.allocator(), req);
        // Body-state storage is released after submission; jobs own their copy.
        job.req.body = try job.arena.allocator().dupe(u8, req.body);
        self.jobs[index] = job;
        errdefer self.jobs[index] = null;
        self.request_bytes += bytes;
        errdefer self.request_bytes -= bytes;
        self.group.concurrent(self.io, run, .{ self, job }) catch return error.DispatchLimit;
    }

    fn run(self: *Dispatcher, job: *Job) void {
        job.result = if (job.canceled.load(.acquire)) error.Canceled else self.callbacks.prepare(self.io, job.arena.allocator(), self.cfg, job.req, self.env);
        job.done.store(true, .release);
        self.wake.signal();
    }

    fn destroy(self: *Dispatcher, job: *Job) void {
        self.request_bytes -= job.bytes;
        job.arena.deinit();
        self.allocator.destroy(job);
        _ = admitted.fetchSub(1, .acq_rel);
    }

    pub fn cancel(self: *Dispatcher, id: u32) void {
        for (self.jobs) |maybe| if (maybe) |job| {
            if (job.stream_id == id) job.canceled.store(true, .release);
        };
    }

    pub fn pump(self: *Dispatcher, stream: std.Io.net.Stream, flow: *flow_mod.State, write: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !void {
        for (&self.jobs) |*maybe| {
            const job = maybe.* orelse continue;
            if (!job.done.load(.acquire)) continue;
            maybe.* = null;
            defer self.destroy(job);
            if (job.canceled.load(.acquire) or flow.find(job.stream_id) == null) continue;
            const result = if (job.result) |*result| result else |_| {
                try support.sendRst(stream, job.stream_id, 2, write);
                flow.cancel(job.stream_id);
                continue;
            };
            try self.callbacks.deliver(stream, job.arena.allocator(), job.stream_id, job.req, result);
        }
    }
};

fn testPrepare(_: std.Io, _: std.mem.Allocator, _: *config.ServerConfig, _: request.HttpRequest, _: *const std.process.Environ.Map) !Result {
    return error.InjectedRoutingFailure;
}

fn testDeliver(_: std.Io.net.Stream, _: std.mem.Allocator, _: u32, _: request.HttpRequest, _: *Result) !void {
    return error.UnexpectedDelivery;
}

fn submitAllocationCheck(allocator: std.mem.Allocator) !void {
    var cfg = config.defaultServerConfig();
    var env = std.process.Environ.Map.init(allocator);
    defer env.deinit();
    var jobs = try Dispatcher.init(std.testing.io, allocator, &cfg, &env, .{ .prepare = testPrepare, .deliver = testDeliver });
    defer jobs.deinit();
    try jobs.submit(1, .{ .method = "POST", .path = "/api/echo", .query = "", .headers = "Host: local", .body = "borrowed parser body", .version = "HTTP/2.0", .close_connection = true });
}

test "failed job allocations release admission and all request storage" {
    defer std.debug.assert(admitted.load(.acquire) == 0);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, submitAllocationCheck, .{});
}

test "global routing admission refuses new work before allocating" {
    var cfg = config.defaultServerConfig();
    var env = std.process.Environ.Map.init(std.testing.allocator);
    defer env.deinit();
    var jobs = try Dispatcher.init(std.testing.io, std.testing.allocator, &cfg, &env, .{ .prepare = testPrepare, .deliver = testDeliver });
    defer jobs.deinit();
    admitted.store(max_global_jobs, .release);
    defer admitted.store(0, .release);
    try std.testing.expectError(error.DispatchLimit, jobs.submit(1, .{ .method = "GET", .path = "/", .query = "", .headers = "Host: local", .body = "", .version = "HTTP/2.0", .close_connection = true }));
    try std.testing.expectEqual(0, jobs.count());
}
