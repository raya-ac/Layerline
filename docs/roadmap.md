# Layerline Roadmap

Layerline should become a production web server, not a demo binary. The target is broad compatibility with the useful nginx and Caddy surface area, then a set of Layerline-native features that make the server worth choosing on its own.

This plan is based on the current local code plus the public feature surfaces documented by Caddy and NGINX:

- Caddy: automatic HTTPS, config API, pluggable modules, static file server, reverse proxy, HTTP/1.1, HTTP/2, HTTP/3, and FastCGI transport.
- NGINX: static web serving, reverse proxying, caching, HTTP load balancing, media serving, mail proxying, and HTTP/TCP/UDP proxy and load balancing.

Sources:

- https://caddyserver.com/features
- https://caddyserver.com/docs/caddyfile/directives/reverse_proxy
- https://docs.nginx.com/nginx/
- https://docs.nginx.com/nginx/admin-guide/load-balancer/http-load-balancer/

## Ground Rules

- Keep the binary dependency-light. Optional integrations can exist, but the core runtime should stay Zig-owned.
- Make config declarative, reloadable, and testable before expanding the directive set heavily.
- Prefer measured behavior over feature claims. Every major feature needs a conformance test or a live smoke check.
- Do not expose diagnostic surfaces by default. `/test.php` and future admin tools must require explicit config.
- Split features into stable modules internally even if they ship as one binary.

## Phase 1: Core Server Correctness

- Harden HTTP/1 parsing: request-line limits, header count limits, duplicate header policy, chunked trailers, absolute-form requests, and strict keep-alive semantics.
- Add request and response timeout controls: read header timeout, body timeout, idle timeout, write timeout, upstream timeout, and graceful shutdown timeout. Initial socket-level timeout config and SIGINT/SIGTERM drain are implemented; route-local timeout policy remains next.
- Add config validation: report unknown keys, invalid values, unsafe combinations, and line numbers. Initial strict key/value validation, route-local validation, domain block validation, and `--validate-config` are implemented; richer diagnostics remain next.
- Add hot reload: validate new config, swap atomically, keep existing connections alive, expose reload through signal and local admin command.
- Add structured logs: access logs, error logs, JSON logs, request IDs, latency, bytes, upstream timing, and TLS/protocol fields.
- Expand tests around route precedence, PHP gating, static file behavior, parser failures, and proxy errors.

## Phase 2: Static Files and Content Handling

- Directory index controls: index file priority lists, directory browse templates, and browse disable by default.
- MIME database and override config.
- Strong caching: ETag, Last-Modified, Cache-Control policies, immutable assets, conditional range requests, and stale-while-revalidate headers.
- Compression: gzip, brotli, zstd, precompressed asset serving, Vary handling, minimum size, and content-type filters.
- Static transforms: safe template mode, include variables, generated headers, and route-local error pages.
- Large-file performance: sendfile on supported targets, fallback streaming, mmap evaluation, rate limiting, and backpressure tests.

## Phase 3: Reverse Proxy and Load Balancing

- Multiple upstreams per route with round-robin, random, least-connections, weighted, consistent-hash, and sticky-session policies. Initial comma/space-separated upstream pools with round-robin selection are implemented for global, domain, and route proxy settings.
- Active and passive health checks with slow start, outlier ejection, retry budgets, and circuit breakers.
- Upstream connection pools with keep-alive limits, per-host caps, DNS re-resolution, happy-eyeballs dialing, and Unix socket upstreams.
- WebSocket and CONNECT tunneling.
- Header rewrite rules: set, append, delete, regex map, forwarded headers, trusted proxy CIDRs, and host/SNI override.
- Response interception: status/header matchers, custom error fallback, maintenance responses, and retry-on conditions.
- Upstream TLS: SNI, trust store, client certs, certificate pinning, TLS versions, and HTTP/2 or HTTP/3 upstream transport.

## Phase 4: PHP and Dynamic Apps

- Add FastCGI support alongside current CGI: Unix socket and TCP FastCGI, request multiplex safety, stderr capture, and timeout controls.
- PHP front-controller support: `try_files`, split PATH_INFO, index.php fallback, framework-friendly rewrites, and per-route env vars.
- Per-route dynamic handlers: CGI, FastCGI, proxy, static, redirect, and internal response.
- Worker process pools for CGI-like execution where useful, with max process count and kill timeouts.
- Safe diagnostic routes: opt-in phpinfo, runtime environment report, and redacted config view.

## Phase 5: TLS, ACME, and Protocols

- Native TLS termination in Zig with modern defaults, certificate chain loading, OCSP stapling, session tickets, ALPN, SNI, and client certificate auth.
- ACME automation: HTTP-01, TLS-ALPN-01, DNS-01 provider interface, renewal scheduler, certificate storage, staging mode, and multi-domain certs.
- HTTP/2 server implementation: HPACK, streams, flow control, prioritization stance, graceful GOAWAY, and h2c upgrade.
- HTTP/3 full routing: route all app responses over QUIC, not just the default page; QPACK dynamic table policy; stream lifecycle; connection migration stance; anti-amplification limits.
- Protocol conformance tests using external clients and captured packet tests.

## Phase 6: Security Controls

- Rate limits by IP, token, route, header, and upstream.
- Connection limits, body limits, header limits, method allowlists, and per-route auth.
- Basic auth, bearer auth, mTLS auth, JWT verification, OIDC forward-auth, and signed URL support.
- WAF-lite rule engine: path/header/body matchers, regex and prefix rules, bot traps, deny/allow lists, and audit-only mode.
- Security headers presets: HSTS, CSP, X-Frame-Options, COOP/COEP, referrer policy, and permissions policy.
- Secret handling: env references, external secret command, config redaction, and safe debug dumps.

## Phase 7: Caching and Edge Behavior

- HTTP cache: memory and disk backends, cache keys, vary keys, TTL, stale-if-error, stale-while-revalidate, purge API, and cache status header.
- Microcache for dynamic upstreams.
- Request coalescing to prevent thundering-herd fills.
- CDN-like rules: path maps, header maps, redirects, canonical host, trailing slash policy, and language/device variants.
- Image/media options later: byte-range correctness first, then optional resizing/transcoding only if the project wants that scope.

## Phase 8: Admin, Operations, and Developer Experience

- Local admin API over Unix socket by default: status, config validate, reload, metrics, route dump, upstream health, and cert status.
- CLI: `layerline validate`, `layerline fmt`, `layerline reload`, `layerline bench`, `layerline routes`, `layerline certs`, and `layerline doctor`.
- Config language evolution: keep simple key/value for now, add named routes/upstreams/listeners, then consider a structured adapter. Initial host-based `server`/`server_name` domain configs are implemented.
- Prometheus metrics plus optional OpenTelemetry traces.
- Systemd/launchd templates, Docker image, Homebrew tap, and reproducible release builds.
- Crash reporting primitives: panic log, build info, runtime profile, and redacted support bundle.

## Layerline-Native Features

- Origin Surface: first-class origin personality pages for error states, health, diagnostics, and protocol demos.
- Protocol Observatory: built-in debug routes that show negotiated HTTP version, TLS, QUIC, compression, cache, and upstream timing.
- Config Replay: record a request and replay it against a candidate config before reload.
- Route Diff: compare two configs and show which routes, headers, upstreams, and security rules changed.
- Self-Profiling Mode: expose per-route CPU, allocations, bytes, and upstream wait time under an admin-only endpoint.
- Failure Lab: controlled fault injection for upstream latency, resets, body truncation, and timeout testing.
- Policy Bundles: reusable named bundles for secure-static, php-app, api-gateway, private-admin, and edge-cache routes.
- Native Protocol Showcase: demo pages for HTTP/1.1, HTTP/2, HTTP/3, TLS, PHP, proxy, caching, and compression that can be disabled in production.

## Immediate Build Order

1. Config validation and route gates.
2. Named route model and route-local settings. Initial exact/prefix route table with route-local static, PHP, and proxy settings is implemented. Host-based domain configs with per-domain routes are implemented; route-local TLS/cache/security policy remains next.
3. Timeouts and graceful shutdown.
4. Reverse proxy upstream pools. Initial multi-target round-robin pools are implemented; active health checks, retry budgets, and richer policies remain next.
5. FastCGI and PHP front-controller.
6. Native TLS termination.
7. HTTP/2 server.
8. HTTP/3 full routing.
9. Cache and compression.
10. Admin API and hot reload.

The next engineering milestone should be a config parser and route table refactor. Most nginx/Caddy-class features need route-local policy; adding more global booleans will not scale.
