# Layerline Caddy Replacement Plan

Layerline is not a Caddy replacement until it can be the public edge for normal production sites without a second web server in front of it. The bar is operational, not cosmetic: it must keep apps online, reload config safely, terminate TLS reliably, proxy modern app protocols, and expose enough diagnostics to debug failures.

## Replacement Gate

Layerline can replace Caddy for `layerline.dev` or similar sites only after these gates pass:

- Static files, PHP/FastCGI, reverse proxy routes, and HEAD/error response framing work from nginx-style per-domain config files.
- TLS can load configured certs and keep serving HTTP/1.1 and HTTP/2 through ALPN.
- ACME renewal is automated or the deployment has a documented certbot/webroot renewal path. Initial in-process `certbot renew --webroot` scheduling is implemented; live TLS material reload still depends on the hot-reload work.
- WebSocket upgrade proxying works for app frameworks and realtime dashboards.
- HTTP/2 routing is usable for normal static, PHP, and proxy routes.
- HTTP/3 either fully routes app responses or is clearly opt-in as a demo surface, not a replacement claim.
- Config validation catches bad domain, route, TLS, PHP, and upstream policy before startup or reload.
- Reload can validate and swap config without dropping existing connections. The read-only admin socket now exposes status, current config validation, routes, and metrics, and the opt-in browser admin UI has first-launch setup plus an authenticated status/routes/certs/metrics dashboard; reload remains blocked on safe config snapshot ownership.
- Compression, cache policy, redirects, headers, health, and metrics have route/domain controls. Response header inheritance and cache shortcuts are implemented for global, domain, and route scopes; dynamic gzip is implemented globally for buffered HTTP/1.1 and HTTP/2 responses, while route/domain compression presets still need richer controls.
- Logs identify request path, status, latency, upstream, protocol, and failure reason. Initial opt-in JSON access logs now cover HTTP/1 and HTTP/2 request handling; TLS fields, request IDs, and h3 parity remain.
- There is a deployment runbook for Linux service management, limits, certs, logs, and rollback. Initial systemd, launchd, runtime Dockerfile, and deployment runbook assets are implemented.

## Build Sections

Commit each section independently after tests and at least one live smoke where the feature touches network behavior.

1. Replacement readiness document and acceptance checklist.
2. Route/domain backend policy: timeout inheritance, route-local proxy/PHP/FastCGI controls, and route dump visibility.
3. WebSocket and raw upgrade proxying for HTTP/1.1 upstreams. Initial route/domain proxy support for `101 Switching Protocols` tunnels is implemented; CONNECT and HTTP/2 extended CONNECT remain.
4. FastCGI pooling with max idle, max requests, idle expiry, and forced close on unsafe responses. Initial FCGI_KEEP_CONN pooling is implemented with process-wide endpoint-keyed idle reuse and metrics.
5. HTTP/2 route parity for static, PHP/FastCGI, proxy, redirects, errors, metrics, and health. Static, proxy, redirects, metrics/health, inherited headers, FastCGI PHP routes, bounded DATA request bodies, content-length validation, and WINDOW_UPDATE on consumed bodies are implemented; GOAWAY policy, prioritization stance, and broader conformance work remain.
6. Hot reload: validate candidate config, atomically swap route tables, keep existing workers on old config until drained.
7. ACME renewal loop: scheduled certbot/webroot renewal, SNI material reload, staging mode, and clear failure logs. Initial startup issuance plus periodic renewal scheduling, staging mode, admin cert visibility, and renewal counters are implemented; live SNI material reload remains blocked on safe config snapshot ownership.
8. Compression policy: gzip first, then brotli/zstd if available without bloating the core. Initial opt-in dynamic gzip is implemented for buffered HTTP/1.1 and HTTP/2 text responses.
9. Cache policy: route/domain `Cache-Control`, immutable assets, stale-if-error, and cache-status headers before a disk cache. Initial inherited `cache_control` shortcuts are implemented for global, domain, and route scopes.
10. Admin API and web UI: validate, reload, routes, metrics, upstream health, cert status, redacted config, and authenticated browser controls. Initial read-only Unix socket commands plus first-launch browser setup/login/dashboard are implemented; reload and mutating controls remain.
11. Deployment assets: systemd unit, launchd plist, Linux sysctl/ulimit notes, Dockerfile, and rollback commands. Initial templates and runbook are implemented.
12. Conformance and soak tests: curl/h2load/autocannon, WebSocket echo, php-fpm, slow upstreams, config reload, and TLS smoke. Initial self-starting verifier covers HTTP/1, HEAD 404 framing, h2c, h2 request bodies, gzip, admin socket, admin web first-launch flow, static files, and shutdown cleanup.

## Not Ready Means Not Ready

Until those gates pass, Layerline can replace Caddy only for narrow controlled services. It should not be described as a full Caddy replacement while HTTP/3 full routing, hot reload, complete protocol logging, WebSocket proxying, renewal automation, and mutating operational admin controls are incomplete.
