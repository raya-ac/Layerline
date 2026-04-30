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
- Do not expose diagnostic surfaces by default. `/test.php`, the Unix admin socket, and the browser admin UI all require explicit config.
- Split features into stable modules internally even if they ship as one binary.

## Phase 1: Core Server Correctness

- Harden HTTP/1 parsing and response framing: request-line limits, header count limits, duplicate header policy, chunked trailers, absolute-form requests, HEAD/error response body suppression, and strict keep-alive semantics.
- Add request and response timeout controls: read header timeout, body timeout, idle timeout, write timeout, upstream timeout, and graceful shutdown timeout. Initial socket-level timeout config, route/domain backend timeout overrides, and SIGINT/SIGTERM drain are implemented; richer request-body and client-write route policy remain next.
- Add config validation: report unknown keys, invalid values, unsafe combinations, and line numbers. Initial strict key/value validation, route-local validation, domain block validation, and `--validate-config` are implemented; richer diagnostics remain next.
- Add hot reload: validate new config, swap atomically, keep existing connections alive, expose reload through signal and authenticated admin control. Activation preflight plus managed graceful restart are implemented as the safe intermediate step; in-memory snapshot swap remains next.
- Add structured logs: access logs, error logs, JSON logs, request IDs, latency, bytes, upstream timing, and TLS/protocol fields. Initial opt-in JSON access logs are implemented for HTTP/1 and HTTP/2 request handling with method, path, query, host, protocol, status, bytes, latency, handler, route error, and upstream target fields; request IDs, TLS fields, and h3 logging remain.
- Expand tests around route precedence, PHP gating, static file behavior, parser failures, and proxy errors.
- Expand the admin control UI beyond the implemented first-launch setup/login dashboard, activation preflight, managed graceful restart, and site-file controls into in-memory hot reload, upstream drain/eject, cert renewal, config diff, and richer redacted config inspection.

## Phase 2: Static Files and Content Handling

- Directory index controls: index file priority lists, directory browse templates, and browse disable by default.
- MIME database and override config.
- Strong caching: ETag, Last-Modified, Cache-Control policies, immutable assets, conditional range requests, Cache-Status, and stale-while-revalidate headers. Initial `cache_control`, `server_cache_control.NAME`, `route_cache_control.NAME`, `server_route_cache_control.DOMAIN.ROUTE`, and static Cache-Status headers are implemented on top of inherited response-header policy.
- Compression: gzip, brotli, zstd, precompressed asset serving, Vary handling, minimum size, and content-type filters. Initial opt-in dynamic gzip covers buffered HTTP/1.1 and HTTP/2 text responses; brotli/zstd and route/domain presets remain.
- Static transforms: safe template mode, include variables, generated headers, and route-local error pages.
- Large-file performance: sendfile on supported targets, fallback streaming, mmap evaluation, rate limiting, and backpressure tests.

## Phase 3: Reverse Proxy and Load Balancing

- Multiple upstreams per route with round-robin, random, least-connections, weighted, consistent-hash, and sticky-session policies. Initial comma/space-separated upstream pools with configurable round-robin/random/least-connections/weighted/consistent-hash selection and per-target `weight=N` options are implemented for global, domain, and route proxy settings.
- Active and passive health checks with slow start, outlier ejection, retry budgets, and circuit breakers. Initial upstream attempt/failure/retry/ejection metrics, bounded retry budgets, config-owned health state, passive target cooldown, circuit breaker half-open probes, weighted slow start after recovery, and opt-in active HTTP probes are implemented; per-route health policy and richer circuit thresholds remain next.
- Upstream connection pools with keep-alive limits, per-host caps, DNS re-resolution, happy-eyeballs dialing, and Unix socket upstreams. Initial per-target HTTP/1 upstream keep-alive pooling with idle caps, idle expiry, max-use rotation, framed fixed/chunked response handling, and connection-pool metrics is implemented.
- WebSocket and CONNECT tunneling. Initial HTTP/1.1 WebSocket/Upgrade proxy tunneling is implemented for route/domain proxy targets; CONNECT and HTTP/2 extended CONNECT remain next.
- Header rewrite rules: set, append, delete, regex map, forwarded headers, trusted proxy CIDRs, and host/SNI override. Initial inherited response header policy is implemented for global, domain, and route scopes and is applied to Layerline-generated responses plus normal HTTP/1 proxy responses.
- Response interception: status/header matchers, custom error fallback, maintenance responses, and retry-on conditions.
- Upstream TLS: SNI, trust store, client certs, certificate pinning, TLS versions, and HTTP/2 or HTTP/3 upstream transport.

## Phase 4: PHP and Dynamic Apps

- Add FastCGI support alongside current CGI: Unix socket and TCP FastCGI, request multiplex safety, stderr capture, and timeout controls. Direct FastCGI transport is implemented for TCP and Unix-socket php-fpm targets with bounded stdout/stderr capture, route/domain timeout overrides, FCGI_KEEP_CONN pooling, idle caps, idle expiry, max-use rotation, and forced close on unsafe responses; multiplex refusal handling remains next.
- PHP front-controller support: `try_files`, split PATH_INFO, index.php fallback, framework-friendly rewrites, and per-route env vars. Initial opt-in CGI front-controller routing is implemented globally, per-domain, and per-route with `php_index`, `php_front_controller`, SCRIPT_NAME, SCRIPT_FILENAME, PATH_INFO, PATH_TRANSLATED, and REQUEST_URI handling; richer `try_files` chains and per-route env vars remain next.
- Per-route dynamic handlers: CGI, FastCGI, proxy, static, redirect, and internal response.
- Worker process pools for CGI-like execution where useful, with max process count and kill timeouts.
- Safe diagnostic routes: opt-in phpinfo, runtime environment report, and redacted config view.

## Phase 5: TLS, ACME, and Protocols

- Native TLS termination in Zig with modern defaults, certificate chain loading, OCSP stapling, session tickets, ALPN, SNI, and client certificate auth. Initial native TLS 1.3 termination is implemented for X25519 + TLS_AES_128_GCM_SHA256 with ALPN dispatch to HTTP/1.1 or HTTP/2, ECDSA P-256 and RSA configured certificate loading, RSA-PSS CertificateVerify, SNI certificate selection for domain configs, and self-signed local fallback; session resumption, OCSP stapling, live certificate reload, and mTLS remain next.
- ACME automation: HTTP-01, TLS-ALPN-01, DNS-01 provider interface, renewal scheduler, certificate storage, staging mode, and multi-domain certs. Initial certbot/webroot startup issuance, HTTP-01 challenge serving from certbot webroots, a companion HTTP redirect/ACME listener for port 80, and periodic `certbot renew` scheduling are implemented, with admin cert visibility and renewal metrics.
- HTTP/2 server implementation: HPACK, streams, flow control, prioritization stance, graceful GOAWAY, and h2c upgrade. Initial h2 route parity now covers static routes, redirects, health/metrics, reverse proxy routes, inherited response headers, FastCGI PHP routes, bounded DATA request bodies, content-length validation, WINDOW_UPDATE for consumed body bytes, and graceful GOAWAY on request caps/shutdown; richer flow-control behavior and prioritization stance remain next.
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

- Local admin API over Unix socket by default: status, activation config validate, runtime validate, managed restart, metrics, route dump, upstream health, and cert status.
- CLI: `layerline validate`, `layerline fmt`, `layerline reload`, `layerline bench`, `layerline routes`, `layerline certs`, and `layerline doctor`.
- Config language evolution: keep simple key/value for now, add named routes/upstreams/listeners, then consider a structured adapter. Initial host-based domain configs are implemented, including nginx-style per-domain files loaded from `domain_config_dir`.
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
2. Named route model and route-local settings. Initial exact/prefix route table with route-local static, PHP, proxy, and backend timeout settings is implemented. Host-based domain configs with per-domain routes and `domain_config_dir` file loading are implemented; route-local TLS/cache/security policy remains next.
3. Timeouts and graceful shutdown.
4. Reverse proxy upstream pools. Initial multi-target pools, round-robin/random/least-connections/weighted/consistent-hash policies, target weights, durable per-upstream state, upstream attempt/failure/retry/ejection/connect-reuse metrics, bounded retry budgets, passive cooldown, circuit breaker half-open probes, weighted slow start, opt-in active HTTP probes, and upstream keep-alive sockets are implemented; sticky sessions and route-local health policy remain next.
5. FastCGI and PHP front-controller. FastCGI transport, route/domain backend timeouts, FCGI_KEEP_CONN pooling, and CGI front-controller fallback are implemented; richer framework rewrites and multiplex refusal handling remain next.
6. Native TLS termination. Initial TLS 1.3 TCP termination, ALPN, configured ECDSA/RSA certificate loading, SNI certificate selection, HTTP/1.1 over TLS, and HTTP/2 over TLS are implemented.
7. HTTP/2 server. Initial h2c and ALPN h2 request routing are implemented for static/proxy/redirect/metrics, FastCGI PHP routes, bounded request bodies, consumed-body WINDOW_UPDATE, and graceful GOAWAY on request caps/shutdown; prioritization stance and broader conformance tests remain next.
8. HTTP/3 full routing.
9. Cache and compression. Initial inherited Cache-Control policy shortcuts, static Cache-Status detail, and opt-in dynamic gzip for buffered HTTP/1.1 and HTTP/2 text responses are implemented; richer stale policy and route/domain compression presets remain next.
10. Admin API and hot reload. Initial Unix socket commands cover status, activation validation, runtime validation, managed restart, routes, certs, and metrics; the browser admin UI covers first-launch setup, login, active site inventory, enabled domain files, activation preflight, managed restart, and new site-file creation. In-memory hot reload plus live upstream/cert controls remain.
11. Deployment packaging. Initial systemd, launchd, cert renewal timer, runtime Dockerfile, Linux limit guidance, smoke checks, and rollback runbook are implemented; package-manager installers remain future work.
12. Conformance harness. Initial self-starting verifier covers HTTP/1, HEAD 404 framing, static files, gzip negotiation, native h2c, h2 request bodies, admin socket commands, admin site-file creation, structured access logs, HTTP redirect/ACME listener behavior, and shutdown cleanup; broader h2load/autocannon/php-fpm/slow-upstream soak remains.

The next engineering milestone should be in-memory config snapshot reload, then HTTP/3 route dispatch, route-local cache/security/upstream policy, and a config parser refactor. Most nginx/Caddy-class features need route-local policy; adding more global booleans will not scale.
