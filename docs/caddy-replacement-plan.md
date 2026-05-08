# Layerline Caddy Replacement Plan

Layerline is already the public edge for the controlled `layerline.dev` deployment and fronts `memorylayer.run` without Caddy in front of it. That is not the same thing as a broad Caddy/nginx replacement claim. The general replacement bar is operational, not cosmetic: it must keep apps online, reload config safely, terminate TLS reliably, proxy modern app protocols, and expose enough diagnostics to debug failures.

## Replacement Gate

Layerline can replace Caddy for controlled sites now when the deployment accepts the current HTTP/3 limits and the set of config changes that still require a listener restart. For a broader drop-in replacement story, these gates need to pass:

- Static files, PHP/FastCGI, reverse proxy routes, and HEAD/error response framing work from nginx-style per-domain config files.
- TLS can load configured certs and keep serving HTTP/1.1 and HTTP/2 through ALPN.
- ACME renewal is automated or the deployment has a documented certbot/webroot renewal path. Initial in-process `certbot renew --webroot` scheduling is implemented, manual/admin reload can pick up renewed certificate material, and systemd renewal timer assets still restart Layerline from certbot's deploy hook as the conservative unattended path.
- WebSocket upgrade proxying works for app frameworks and realtime dashboards.
- HTTP/2 routing is usable for normal static, PHP, and proxy routes.
- HTTP/3 either fully routes app responses or is clearly scoped. Initial native HTTP/3 now decodes simple QPACK request fields and dispatches static/health/redirect responses, but proxy/PHP parity is not complete enough for a replacement claim.
- Config validation catches bad domain, route, TLS, PHP, and upstream policy before startup or reload.
- Reload can validate and swap config without dropping existing connections. The admin socket now exposes status, activation config preflight, runtime validation, in-memory reload, graceful restart, routes, certs, and metrics, and the opt-in browser admin UI has first-launch setup, staged main-setting writes with backups, site-file creation, redacted config previews, enabled-file visibility, activation validation, reload, managed restart, routes, certs, and metrics. Listener-bound changes still require a managed restart.
- Compression, cache policy, redirects, headers, health, and metrics have route/domain controls. Response header inheritance, security presets, cache shortcuts, stale directives, dynamic gzip policy, and an opt-in memory cache for eligible static responses are implemented with route/domain-local overrides; brotli/zstd, disk cache, and dynamic microcache remain open.
- Logs identify request ID, path, status, latency, upstream, protocol, and failure reason. Initial opt-in JSON access logs now cover HTTP/1 and HTTP/2 request handling; TLS fields, richer upstream timing, and h3 parity remain.
- There is a deployment runbook for Linux service management, limits, certs, logs, and rollback. Initial systemd, launchd, runtime Dockerfile, and deployment runbook assets are implemented.

## Build Sections

Commit each section independently after tests and at least one live smoke where the feature touches network behavior.

1. Replacement readiness document and acceptance checklist.
2. Route/domain backend policy: timeout inheritance, route-local proxy/PHP/FastCGI controls, response-cache/security/upstream policy, and route dump visibility.
3. WebSocket and raw upgrade proxying for HTTP/1.1 upstreams. Initial route/domain proxy support for `101 Switching Protocols` tunnels is implemented; CONNECT and HTTP/2 extended CONNECT remain.
4. FastCGI pooling with max idle, max requests, idle expiry, and forced close on unsafe responses. Initial FCGI_KEEP_CONN pooling is implemented with process-wide endpoint-keyed idle reuse and metrics.
5. HTTP/2 route parity for static, PHP/FastCGI, proxy, redirects, errors, metrics, and health. Static, proxy, redirects, metrics/health, inherited headers, FastCGI PHP routes, bounded DATA request bodies, content-length validation, consumed-body WINDOW_UPDATE, and graceful GOAWAY on request caps/shutdown are implemented; prioritization stance and broader conformance work remain.
6. Hot reload: validate candidate config, atomically swap route tables, keep existing workers on old config until drained. Initial in-memory snapshot reload is implemented for compatible config changes; listener rebinding and signal wiring remain.
7. ACME renewal loop: scheduled certbot/webroot renewal, SNI material reload, staging mode, and clear failure logs. Initial startup issuance, HTTP-01 challenge serving from certbot webroots, a companion HTTP redirect/ACME listener for port 80, periodic renewal scheduling, systemd certbot renewal/restart timer assets, staging mode, admin cert visibility, renewal counters, and manual/admin reload of configured certificate material are implemented; automated live SNI renewal activation remains.
8. Compression policy: gzip first, then brotli/zstd if available without bloating the core. Initial opt-in dynamic gzip is implemented for buffered HTTP/1.1 and HTTP/2 text responses with inherited domain and route overrides.
9. Cache policy: route/domain `Cache-Control`, immutable assets, stale-if-error, cache-status headers, and a bounded memory cache before a disk cache. Initial inherited `cache_control`, stale directive shortcuts, and route/domain response-cache controls are implemented, and static responses emit Cache-Status store/hit detail.
10. Admin API and web UI: validate, reload, routes, metrics, upstream health, cert status, redacted config, and authenticated browser controls. Initial Unix socket commands plus first-launch browser setup/login/dashboard, active site inventory, staged main-setting writes with backups, redacted config previews, domain-file visibility, activation preflight, in-memory reload, managed graceful restart, runtime validation, and site-file creation are implemented; live upstream/cert controls remain.
11. Deployment assets: systemd unit, launchd plist, Linux sysctl/ulimit notes, Dockerfile, and rollback commands. Initial templates and runbook are implemented.
12. Conformance and soak tests: curl/h2load/autocannon, WebSocket echo, php-fpm, slow upstreams, config reload, and TLS smoke. Initial self-starting verifier covers HTTP/1, HEAD 404 framing, h2c, h2 request bodies, request IDs, gzip, admin socket, admin web first-launch flow, admin main-setting saves, in-memory config reload, admin site-file creation with routes, redacted config previews, structured access logs, static files, best-effort external HTTP/3 curl smoke when the local curl supports HTTP3, domain custom 404 documents, the HTTP redirect/ACME listener, and shutdown cleanup; broader h3 conformance still needs a dedicated client matrix.

## Not Ready Means Not Ready

Layerline is ready for narrow controlled services where HTTP/3 is not required for full app routing and listener-bound changes can go through the managed restart bridge. It should not be described as a full Caddy/nginx replacement while HTTP/3 full routing, full protocol conformance, automated live certificate activation, and live mutating operational admin controls are incomplete.
