const std = @import("std");
const http_response = @import("http_response.zig");

pub const StaticTransferMode = enum {
    sendfile,
    buffered,
};

pub const ServerMetrics = struct {
    active_connections: std.atomic.Value(usize),
    connections_total: std.atomic.Value(usize),
    connections_rejected_total: std.atomic.Value(usize),
    requests_total: std.atomic.Value(usize),
    request_parse_errors_total: std.atomic.Value(usize),
    route_errors_total: std.atomic.Value(usize),
    responses_total: std.atomic.Value(usize),
    response_2xx_total: std.atomic.Value(usize),
    response_3xx_total: std.atomic.Value(usize),
    response_4xx_total: std.atomic.Value(usize),
    response_5xx_total: std.atomic.Value(usize),
    response_body_bytes_total: std.atomic.Value(usize),
    static_responses_total: std.atomic.Value(usize),
    static_sendfile_responses_total: std.atomic.Value(usize),
    static_buffered_responses_total: std.atomic.Value(usize),
    static_body_bytes_total: std.atomic.Value(usize),
    compressed_responses_total: std.atomic.Value(usize),
    compressed_body_bytes_total: std.atomic.Value(usize),
    response_cache_hits_total: std.atomic.Value(usize),
    response_cache_misses_total: std.atomic.Value(usize),
    response_cache_stores_total: std.atomic.Value(usize),
    response_cache_evictions_total: std.atomic.Value(usize),
    response_cache_body_bytes_total: std.atomic.Value(usize),
    upstream_requests_total: std.atomic.Value(usize),
    upstream_failures_total: std.atomic.Value(usize),
    upstream_retries_total: std.atomic.Value(usize),
    upstream_ejections_total: std.atomic.Value(usize),
    upstream_ejected_skips_total: std.atomic.Value(usize),
    upstream_connections_opened_total: std.atomic.Value(usize),
    upstream_connections_reused_total: std.atomic.Value(usize),
    upstream_connections_pooled_total: std.atomic.Value(usize),
    upstream_connections_discarded_total: std.atomic.Value(usize),
    fastcgi_connections_opened_total: std.atomic.Value(usize),
    fastcgi_connections_reused_total: std.atomic.Value(usize),
    fastcgi_connections_pooled_total: std.atomic.Value(usize),
    fastcgi_connections_discarded_total: std.atomic.Value(usize),
    upstream_health_checks_total: std.atomic.Value(usize),
    upstream_health_check_failures_total: std.atomic.Value(usize),
    upstream_health_check_recoveries_total: std.atomic.Value(usize),
    acme_renewals_total: std.atomic.Value(usize),
    acme_renewal_successes_total: std.atomic.Value(usize),
    acme_renewal_failures_total: std.atomic.Value(usize),
    h3_responses_total: std.atomic.Value(usize),
    h3_packets_sent_total: std.atomic.Value(usize),

    pub fn init() ServerMetrics {
        return .{
            .active_connections = std.atomic.Value(usize).init(0),
            .connections_total = std.atomic.Value(usize).init(0),
            .connections_rejected_total = std.atomic.Value(usize).init(0),
            .requests_total = std.atomic.Value(usize).init(0),
            .request_parse_errors_total = std.atomic.Value(usize).init(0),
            .route_errors_total = std.atomic.Value(usize).init(0),
            .responses_total = std.atomic.Value(usize).init(0),
            .response_2xx_total = std.atomic.Value(usize).init(0),
            .response_3xx_total = std.atomic.Value(usize).init(0),
            .response_4xx_total = std.atomic.Value(usize).init(0),
            .response_5xx_total = std.atomic.Value(usize).init(0),
            .response_body_bytes_total = std.atomic.Value(usize).init(0),
            .static_responses_total = std.atomic.Value(usize).init(0),
            .static_sendfile_responses_total = std.atomic.Value(usize).init(0),
            .static_buffered_responses_total = std.atomic.Value(usize).init(0),
            .static_body_bytes_total = std.atomic.Value(usize).init(0),
            .compressed_responses_total = std.atomic.Value(usize).init(0),
            .compressed_body_bytes_total = std.atomic.Value(usize).init(0),
            .response_cache_hits_total = std.atomic.Value(usize).init(0),
            .response_cache_misses_total = std.atomic.Value(usize).init(0),
            .response_cache_stores_total = std.atomic.Value(usize).init(0),
            .response_cache_evictions_total = std.atomic.Value(usize).init(0),
            .response_cache_body_bytes_total = std.atomic.Value(usize).init(0),
            .upstream_requests_total = std.atomic.Value(usize).init(0),
            .upstream_failures_total = std.atomic.Value(usize).init(0),
            .upstream_retries_total = std.atomic.Value(usize).init(0),
            .upstream_ejections_total = std.atomic.Value(usize).init(0),
            .upstream_ejected_skips_total = std.atomic.Value(usize).init(0),
            .upstream_connections_opened_total = std.atomic.Value(usize).init(0),
            .upstream_connections_reused_total = std.atomic.Value(usize).init(0),
            .upstream_connections_pooled_total = std.atomic.Value(usize).init(0),
            .upstream_connections_discarded_total = std.atomic.Value(usize).init(0),
            .fastcgi_connections_opened_total = std.atomic.Value(usize).init(0),
            .fastcgi_connections_reused_total = std.atomic.Value(usize).init(0),
            .fastcgi_connections_pooled_total = std.atomic.Value(usize).init(0),
            .fastcgi_connections_discarded_total = std.atomic.Value(usize).init(0),
            .upstream_health_checks_total = std.atomic.Value(usize).init(0),
            .upstream_health_check_failures_total = std.atomic.Value(usize).init(0),
            .upstream_health_check_recoveries_total = std.atomic.Value(usize).init(0),
            .acme_renewals_total = std.atomic.Value(usize).init(0),
            .acme_renewal_successes_total = std.atomic.Value(usize).init(0),
            .acme_renewal_failures_total = std.atomic.Value(usize).init(0),
            .h3_responses_total = std.atomic.Value(usize).init(0),
            .h3_packets_sent_total = std.atomic.Value(usize).init(0),
        };
    }

    pub fn load(counter: *const std.atomic.Value(usize)) usize {
        return counter.load(.monotonic);
    }

    pub fn inc(counter: *std.atomic.Value(usize)) void {
        _ = counter.fetchAdd(1, .monotonic);
    }

    pub fn add(counter: *std.atomic.Value(usize), value: usize) void {
        _ = counter.fetchAdd(value, .monotonic);
    }

    pub fn connectionAccepted(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.connections_total);
        ServerMetrics.inc(&self.active_connections);
    }

    pub fn connectionRejected(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.connections_rejected_total);
    }

    pub fn connectionClosed(self: *ServerMetrics) void {
        _ = self.active_connections.fetchSub(1, .monotonic);
    }

    pub fn requestStarted(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.requests_total);
    }

    pub fn requestParseError(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.request_parse_errors_total);
    }

    pub fn routeError(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.route_errors_total);
    }

    pub fn responseSent(self: *ServerMetrics, status_code: u16, body_bytes: usize) void {
        ServerMetrics.inc(&self.responses_total);
        ServerMetrics.add(&self.response_body_bytes_total, body_bytes);
        switch (http_response.statusClass(status_code)) {
            2 => ServerMetrics.inc(&self.response_2xx_total),
            3 => ServerMetrics.inc(&self.response_3xx_total),
            4 => ServerMetrics.inc(&self.response_4xx_total),
            5 => ServerMetrics.inc(&self.response_5xx_total),
            else => {},
        }
    }

    pub fn staticBodySent(self: *ServerMetrics, body_bytes: usize, transfer_mode: StaticTransferMode) void {
        ServerMetrics.inc(&self.static_responses_total);
        switch (transfer_mode) {
            .sendfile => ServerMetrics.inc(&self.static_sendfile_responses_total),
            .buffered => ServerMetrics.inc(&self.static_buffered_responses_total),
        }
        ServerMetrics.add(&self.static_body_bytes_total, body_bytes);
    }

    pub fn compressedResponseSent(self: *ServerMetrics, body_bytes: usize) void {
        ServerMetrics.inc(&self.compressed_responses_total);
        ServerMetrics.add(&self.compressed_body_bytes_total, body_bytes);
    }

    pub fn responseCacheHit(self: *ServerMetrics, body_bytes: usize) void {
        ServerMetrics.inc(&self.response_cache_hits_total);
        ServerMetrics.add(&self.response_cache_body_bytes_total, body_bytes);
    }

    pub fn responseCacheMiss(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.response_cache_misses_total);
    }

    pub fn responseCacheStore(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.response_cache_stores_total);
    }

    pub fn responseCacheEviction(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.response_cache_evictions_total);
    }

    pub fn upstreamRequestStarted(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_requests_total);
    }

    pub fn upstreamRequestFailed(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_failures_total);
    }

    pub fn upstreamRetried(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_retries_total);
    }

    pub fn upstreamEjected(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_ejections_total);
    }

    pub fn upstreamEjectedSkip(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_ejected_skips_total);
    }

    pub fn upstreamConnectionOpened(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_connections_opened_total);
    }

    pub fn upstreamConnectionReused(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_connections_reused_total);
    }

    pub fn upstreamConnectionPooled(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_connections_pooled_total);
    }

    pub fn upstreamConnectionDiscarded(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_connections_discarded_total);
    }

    pub fn fastcgiConnectionOpened(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.fastcgi_connections_opened_total);
    }

    pub fn fastcgiConnectionReused(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.fastcgi_connections_reused_total);
    }

    pub fn fastcgiConnectionPooled(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.fastcgi_connections_pooled_total);
    }

    pub fn fastcgiConnectionDiscarded(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.fastcgi_connections_discarded_total);
    }

    pub fn upstreamHealthCheckRan(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_health_checks_total);
    }

    pub fn upstreamHealthCheckFailed(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_health_check_failures_total);
    }

    pub fn upstreamHealthCheckRecovered(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.upstream_health_check_recoveries_total);
    }

    pub fn acmeRenewalStarted(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.acme_renewals_total);
    }

    pub fn acmeRenewalSucceeded(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.acme_renewal_successes_total);
    }

    pub fn acmeRenewalFailed(self: *ServerMetrics) void {
        ServerMetrics.inc(&self.acme_renewal_failures_total);
    }

    pub fn h3ResponseSent(self: *ServerMetrics, packet_count: usize) void {
        ServerMetrics.inc(&self.h3_responses_total);
        ServerMetrics.add(&self.h3_packets_sent_total, packet_count);
    }
};

pub fn render(allocator: std.mem.Allocator, metrics: *const ServerMetrics) ![]const u8 {
    const base_metrics = try std.fmt.allocPrint(
        allocator,
        "# HELP layerline_connections_active Active TCP connections currently owned by Layerline workers.\n" ++
            "# TYPE layerline_connections_active gauge\n" ++
            "layerline_connections_active {d}\n" ++
            "# HELP layerline_connections_total Accepted TCP connections.\n" ++
            "# TYPE layerline_connections_total counter\n" ++
            "layerline_connections_total {d}\n" ++
            "# HELP layerline_connections_rejected_total Connections rejected by the concurrency gate.\n" ++
            "# TYPE layerline_connections_rejected_total counter\n" ++
            "layerline_connections_rejected_total {d}\n" ++
            "# HELP layerline_requests_total Parsed HTTP/1 requests.\n" ++
            "# TYPE layerline_requests_total counter\n" ++
            "layerline_requests_total {d}\n" ++
            "# HELP layerline_request_parse_errors_total Requests rejected by the parser.\n" ++
            "# TYPE layerline_request_parse_errors_total counter\n" ++
            "layerline_request_parse_errors_total {d}\n" ++
            "# HELP layerline_route_errors_total Routed requests that failed before a response completed.\n" ++
            "# TYPE layerline_route_errors_total counter\n" ++
            "layerline_route_errors_total {d}\n" ++
            "# HELP layerline_responses_total HTTP/1 responses by status class.\n" ++
            "# TYPE layerline_responses_total counter\n" ++
            "layerline_responses_total{{class=\"2xx\"}} {d}\n" ++
            "layerline_responses_total{{class=\"3xx\"}} {d}\n" ++
            "layerline_responses_total{{class=\"4xx\"}} {d}\n" ++
            "layerline_responses_total{{class=\"5xx\"}} {d}\n" ++
            "layerline_responses_total{{class=\"all\"}} {d}\n" ++
            "# HELP layerline_response_body_bytes_total HTTP/1 response body bytes written by normal response helpers.\n" ++
            "# TYPE layerline_response_body_bytes_total counter\n" ++
            "layerline_response_body_bytes_total {d}\n" ++
            "# HELP layerline_static_body_bytes_total Static file body bytes streamed from disk.\n" ++
            "# TYPE layerline_static_body_bytes_total counter\n" ++
            "layerline_static_body_bytes_total {d}\n" ++
            "# HELP layerline_static_responses_total Static file responses streamed from disk.\n" ++
            "# TYPE layerline_static_responses_total counter\n" ++
            "layerline_static_responses_total {d}\n" ++
            "# HELP layerline_static_sendfile_responses_total Static file responses transferred with kernel sendfile.\n" ++
            "# TYPE layerline_static_sendfile_responses_total counter\n" ++
            "layerline_static_sendfile_responses_total {d}\n" ++
            "# HELP layerline_static_buffered_responses_total Static file responses transferred through the buffered fallback.\n" ++
            "# TYPE layerline_static_buffered_responses_total counter\n" ++
            "layerline_static_buffered_responses_total {d}\n" ++
            "# HELP layerline_compressed_responses_total Responses compressed by Layerline before write.\n" ++
            "# TYPE layerline_compressed_responses_total counter\n" ++
            "layerline_compressed_responses_total {d}\n" ++
            "# HELP layerline_compressed_body_bytes_total Compressed response body bytes written by Layerline.\n" ++
            "# TYPE layerline_compressed_body_bytes_total counter\n" ++
            "layerline_compressed_body_bytes_total {d}\n" ++
            "# HELP layerline_upstream_requests_total Reverse proxy upstream forwarding attempts.\n" ++
            "# TYPE layerline_upstream_requests_total counter\n" ++
            "layerline_upstream_requests_total {d}\n" ++
            "# HELP layerline_upstream_failures_total Reverse proxy upstream attempts that returned an unexpected transport error.\n" ++
            "# TYPE layerline_upstream_failures_total counter\n" ++
            "layerline_upstream_failures_total {d}\n" ++
            "# HELP layerline_upstream_retries_total Reverse proxy attempts made after an earlier upstream target failed.\n" ++
            "# TYPE layerline_upstream_retries_total counter\n" ++
            "layerline_upstream_retries_total {d}\n" ++
            "# HELP layerline_upstream_ejections_total Upstream targets temporarily ejected by passive health checks.\n" ++
            "# TYPE layerline_upstream_ejections_total counter\n" ++
            "layerline_upstream_ejections_total {d}\n" ++
            "# HELP layerline_upstream_ejected_skips_total Proxy attempts skipped because a target is in passive-health cooldown.\n" ++
            "# TYPE layerline_upstream_ejected_skips_total counter\n" ++
            "layerline_upstream_ejected_skips_total {d}\n" ++
            "# HELP layerline_upstream_connections_opened_total New TCP connections opened to upstream targets.\n" ++
            "# TYPE layerline_upstream_connections_opened_total counter\n" ++
            "layerline_upstream_connections_opened_total {d}\n" ++
            "# HELP layerline_upstream_connections_reused_total Idle upstream TCP connections reused from a keep-alive pool.\n" ++
            "# TYPE layerline_upstream_connections_reused_total counter\n" ++
            "layerline_upstream_connections_reused_total {d}\n" ++
            "# HELP layerline_upstream_connections_pooled_total Upstream TCP connections returned to an idle keep-alive pool.\n" ++
            "# TYPE layerline_upstream_connections_pooled_total counter\n" ++
            "layerline_upstream_connections_pooled_total {d}\n" ++
            "# HELP layerline_upstream_connections_discarded_total Upstream TCP connections closed instead of pooled or reused.\n" ++
            "# TYPE layerline_upstream_connections_discarded_total counter\n" ++
            "layerline_upstream_connections_discarded_total {d}\n" ++
            "# HELP layerline_upstream_health_checks_total Active upstream health probes run.\n" ++
            "# TYPE layerline_upstream_health_checks_total counter\n" ++
            "layerline_upstream_health_checks_total {d}\n" ++
            "# HELP layerline_upstream_health_check_failures_total Active upstream health probes that failed or returned unhealthy status.\n" ++
            "# TYPE layerline_upstream_health_check_failures_total counter\n" ++
            "layerline_upstream_health_check_failures_total {d}\n" ++
            "# HELP layerline_upstream_health_check_recoveries_total Active upstream health probes that restored an unavailable target.\n" ++
            "# TYPE layerline_upstream_health_check_recoveries_total counter\n" ++
            "layerline_upstream_health_check_recoveries_total {d}\n" ++
            "# HELP layerline_h3_responses_total Native HTTP/3 responses sent.\n" ++
            "# TYPE layerline_h3_responses_total counter\n" ++
            "layerline_h3_responses_total {d}\n" ++
            "# HELP layerline_h3_packets_sent_total Protected HTTP/3 1-RTT packets sent for responses.\n" ++
            "# TYPE layerline_h3_packets_sent_total counter\n" ++
            "layerline_h3_packets_sent_total {d}\n",
        .{
            ServerMetrics.load(&metrics.active_connections),
            ServerMetrics.load(&metrics.connections_total),
            ServerMetrics.load(&metrics.connections_rejected_total),
            ServerMetrics.load(&metrics.requests_total),
            ServerMetrics.load(&metrics.request_parse_errors_total),
            ServerMetrics.load(&metrics.route_errors_total),
            ServerMetrics.load(&metrics.response_2xx_total),
            ServerMetrics.load(&metrics.response_3xx_total),
            ServerMetrics.load(&metrics.response_4xx_total),
            ServerMetrics.load(&metrics.response_5xx_total),
            ServerMetrics.load(&metrics.responses_total),
            ServerMetrics.load(&metrics.response_body_bytes_total),
            ServerMetrics.load(&metrics.static_body_bytes_total),
            ServerMetrics.load(&metrics.static_responses_total),
            ServerMetrics.load(&metrics.static_sendfile_responses_total),
            ServerMetrics.load(&metrics.static_buffered_responses_total),
            ServerMetrics.load(&metrics.compressed_responses_total),
            ServerMetrics.load(&metrics.compressed_body_bytes_total),
            ServerMetrics.load(&metrics.upstream_requests_total),
            ServerMetrics.load(&metrics.upstream_failures_total),
            ServerMetrics.load(&metrics.upstream_retries_total),
            ServerMetrics.load(&metrics.upstream_ejections_total),
            ServerMetrics.load(&metrics.upstream_ejected_skips_total),
            ServerMetrics.load(&metrics.upstream_connections_opened_total),
            ServerMetrics.load(&metrics.upstream_connections_reused_total),
            ServerMetrics.load(&metrics.upstream_connections_pooled_total),
            ServerMetrics.load(&metrics.upstream_connections_discarded_total),
            ServerMetrics.load(&metrics.upstream_health_checks_total),
            ServerMetrics.load(&metrics.upstream_health_check_failures_total),
            ServerMetrics.load(&metrics.upstream_health_check_recoveries_total),
            ServerMetrics.load(&metrics.h3_responses_total),
            ServerMetrics.load(&metrics.h3_packets_sent_total),
        },
    );
    defer allocator.free(base_metrics);

    const acme_metrics = try std.fmt.allocPrint(
        allocator,
        "# HELP layerline_acme_renewals_total ACME renewal attempts started by the background renewal loop.\n" ++
            "# TYPE layerline_acme_renewals_total counter\n" ++
            "layerline_acme_renewals_total {d}\n" ++
            "# HELP layerline_acme_renewal_successes_total ACME renewal attempts that completed successfully.\n" ++
            "# TYPE layerline_acme_renewal_successes_total counter\n" ++
            "layerline_acme_renewal_successes_total {d}\n" ++
            "# HELP layerline_acme_renewal_failures_total ACME renewal attempts that returned an error.\n" ++
            "# TYPE layerline_acme_renewal_failures_total counter\n" ++
            "layerline_acme_renewal_failures_total {d}\n",
        .{
            ServerMetrics.load(&metrics.acme_renewals_total),
            ServerMetrics.load(&metrics.acme_renewal_successes_total),
            ServerMetrics.load(&metrics.acme_renewal_failures_total),
        },
    );
    defer allocator.free(acme_metrics);

    const response_cache_metrics = try std.fmt.allocPrint(
        allocator,
        "# HELP layerline_response_cache_hits_total Static response-cache lookups served from memory.\n" ++
            "# TYPE layerline_response_cache_hits_total counter\n" ++
            "layerline_response_cache_hits_total {d}\n" ++
            "# HELP layerline_response_cache_misses_total Static response-cache lookups that missed memory.\n" ++
            "# TYPE layerline_response_cache_misses_total counter\n" ++
            "layerline_response_cache_misses_total {d}\n" ++
            "# HELP layerline_response_cache_stores_total Static responses stored in memory cache.\n" ++
            "# TYPE layerline_response_cache_stores_total counter\n" ++
            "layerline_response_cache_stores_total {d}\n" ++
            "# HELP layerline_response_cache_evictions_total Static response-cache entries evicted from memory.\n" ++
            "# TYPE layerline_response_cache_evictions_total counter\n" ++
            "layerline_response_cache_evictions_total {d}\n" ++
            "# HELP layerline_response_cache_body_bytes_total Static response-cache body bytes served from memory.\n" ++
            "# TYPE layerline_response_cache_body_bytes_total counter\n" ++
            "layerline_response_cache_body_bytes_total {d}\n",
        .{
            ServerMetrics.load(&metrics.response_cache_hits_total),
            ServerMetrics.load(&metrics.response_cache_misses_total),
            ServerMetrics.load(&metrics.response_cache_stores_total),
            ServerMetrics.load(&metrics.response_cache_evictions_total),
            ServerMetrics.load(&metrics.response_cache_body_bytes_total),
        },
    );
    defer allocator.free(response_cache_metrics);

    const fastcgi_metrics = try std.fmt.allocPrint(
        allocator,
        "# HELP layerline_fastcgi_connections_opened_total New connections opened to FastCGI workers.\n" ++
            "# TYPE layerline_fastcgi_connections_opened_total counter\n" ++
            "layerline_fastcgi_connections_opened_total {d}\n" ++
            "# HELP layerline_fastcgi_connections_reused_total Idle FastCGI worker connections reused from the keep-alive pool.\n" ++
            "# TYPE layerline_fastcgi_connections_reused_total counter\n" ++
            "layerline_fastcgi_connections_reused_total {d}\n" ++
            "# HELP layerline_fastcgi_connections_pooled_total FastCGI worker connections returned to the idle keep-alive pool.\n" ++
            "# TYPE layerline_fastcgi_connections_pooled_total counter\n" ++
            "layerline_fastcgi_connections_pooled_total {d}\n" ++
            "# HELP layerline_fastcgi_connections_discarded_total FastCGI worker connections closed instead of pooled or reused.\n" ++
            "# TYPE layerline_fastcgi_connections_discarded_total counter\n" ++
            "layerline_fastcgi_connections_discarded_total {d}\n",
        .{
            ServerMetrics.load(&metrics.fastcgi_connections_opened_total),
            ServerMetrics.load(&metrics.fastcgi_connections_reused_total),
            ServerMetrics.load(&metrics.fastcgi_connections_pooled_total),
            ServerMetrics.load(&metrics.fastcgi_connections_discarded_total),
        },
    );
    defer allocator.free(fastcgi_metrics);

    return std.mem.concat(allocator, u8, &.{ base_metrics, acme_metrics, response_cache_metrics, fastcgi_metrics });
}
