# Layerline

Modern Zig web server for direct edge serving: static sites, PHP, reverse proxying, virtual hosts, TLS, metrics, admin controls, and native HTTP/2/HTTP/3 work.

- Website: [layerline.dev](https://layerline.dev)
- Repository: [github.com/raya-ac/Layerline](https://github.com/raya-ac/Layerline)

This is a practical build that blends local serving with edge-style deployment:

- Named runtime identity with branded root and error pages.
- Built-in SVG app icon at `/favicon.svg` and `/icon.svg`.
- PHP route execution for `.php` paths via `php-cgi`/`php` or pooled php-fpm/FastCGI, plus opt-in `index.php` front-controller fallback with PATH_INFO.
- Reverse-proxy fallback for anything the local server does not handle, including comma/space-separated upstream pools, selectable `round_robin`/`random`/`least_connections`/`weighted`/`consistent_hash` policies, target weights, bounded retries, passive upstream ejection, circuit breaker half-open probes, slow start, upstream keep-alive pooling, and opt-in active health checks.
- HTTP/1.1 WebSocket/Upgrade proxy tunneling for route and domain proxy targets.
- Named route config for route-local static, PHP, and proxy behavior.
- Host-based domain configs with nginx-style server names, wildcard names, per-domain roots, redirects, routes, PHP, and proxy fallbacks.
- Configured redirects and inherited global/domain/route response headers, using familiar Caddy/nginx-style primitives.
- Native TLS listener support plus an optional plaintext HTTP listener for ACME HTTP-01 and HTTP-to-HTTPS redirects.
- HTTP/1.1 parsing with request limits, keep-alive, `HEAD`, `OPTIONS`, chunked request bodies, `Expect: 100-continue`, and forwarding.
- Request lifecycle caps like `--max-requests-per-connection` so keep-alive sockets are periodically rotated.
- Socket-level header/body/idle/write/upstream timeouts plus SIGINT/SIGTERM graceful connection draining.
- Built-in gzip compression policy for eligible buffered text responses on HTTP/1.1 and native HTTP/2.
- Optional read-only Unix-socket admin surface for status, config validation, routes, cert visibility, and metrics.
- Optional browser admin UI served by the same HTTP listener, disabled by default, with first-launch local account setup.
- Opt-in structured JSON access logs with method, path, protocol, status, bytes, latency, handler, and upstream target when proxying.
- Static responses use kernel `sendfile` on Darwin before falling back to bounded buffered reads, can serve precompressed `.br`/`.gz` sidecars, and include ETag/cache headers, `If-None-Match`, `Accept-Ranges`, and single byte-range responses.
- Prometheus-style runtime metrics at `/metrics`, including compression, static sendfile/buffered transfer, and reverse-proxy upstream attempt/failure/retry/ejection/connection-pool counters.
- Native HTTP/2 routing for static, redirects, metrics, proxy, request bodies, and FastCGI PHP routes, plus cleartext passthrough target support through `h2_upstream`.
- Native HTTP/3 work is in the Zig binary: QUIC varints, HTTP/3 frame headers, QPACK literal response headers, QUIC Initial/Handshake/1-RTT packet protection, TLS 1.3 handshake flight generation, and a default-page response path.
- Auto Let’s Encrypt (certbot) bootstrap, ACME challenge serving from certbot webroots, periodic renewal loop, and systemd renewal timer assets.
- Automatic Cloudflare DNS automation at startup (`--cf-auto-deploy`) with create/update behavior for A/AAAA/CNAME.
- Concurrent-connection protection (`--max-concurrent-connections`, default 1,000,000) to prevent overload instability.
- High-load knobs (`--max-requests-per-connection`, `--max-php-output-bytes`, `--worker-stack-size`) to tune behavior under sustained pressure.
- Branded HTML error responses for common 4xx/5xx paths, including HEAD-safe behavior.

## Current status

Layerline is past the toy-server stage: the HTTP/1 path has strict parsing, bounded bodies, keep-alive rotation, chunked request bodies, static sendfile/precompressed assets, gzip for eligible buffered responses, PHP CGI execution, php-fpm/FastCGI transport with worker connection pooling, PHP front-controller fallback, native HTTP/2 request-body routing, route-local backend timeout overrides, inherited global/domain/route response headers, redirects, WebSocket upgrade proxying, reverse-proxy fallback with pooled retries, configurable pool policy, least-connections, weighted, and consistent-hash balancing, reusable upstream keep-alive sockets, circuit breaker recovery, durable upstream health state, metrics, structured JSON access logs, a read-only Unix admin socket, an opt-in first-launch browser admin UI, named routes, host-based domain configs, direct TLS, and a companion HTTP redirect/ACME listener for owning ports 80 and 443 without Caddy. The native HTTP/3 work is in-tree and currently serves the built-in default page over QUIC/TLS 1.3; full route dispatch over HTTP/3 is still on the roadmap.

The next roadmap slice is richer HTTP/2 connection policy and cache behavior: GOAWAY behavior, route-local stale/cache-status policy, and broader h2 conformance tests. That work builds on the existing `proxy`, `route_proxy.NAME`, `server_proxy.NAME`, and `server_route_proxy.DOMAIN.ROUTE` config surface instead of adding another parallel config style.

## Files

- `src/main.zig` – server implementation.
- `build.zig` – Zig build script.
- `public/index.html` and `public/site.css` – the Layerline website served when `serve_static_root = true`.
- `public/laina.png` – Laina, the Layerline route-operator mascot used by the website.
- `public/hello.txt` – sample static file.
- `public/index.php` – sample php endpoint (if PHP binary is installed and configured).
- `server.conf` – sample config file.
- `domains-available/example.conf` – sample per-domain config file.
- `domains-enabled/` – nginx-style enabled domain config directory.
- `scripts/benchmark-layerline.sh` – smoke and benchmark harness for HTTP/1 plus best-effort native HTTP/3 response checks.
- `scripts/verify-layerline.sh` – self-starting conformance smoke for HTTP/1, HEAD error framing, h2c, h2 request bodies, gzip, admin socket/UI, static files, access logs, the HTTP redirect/ACME listener, and shutdown cleanup.
- `docs/benchmarking.md` – benchmark runbook and environment knobs.
- `docs/deployment.md` – Linux/macOS service deployment, limits, certs, smoke checks, and rollback.
- `deploy/systemd/layerline.service` – production-oriented systemd unit template.
- `deploy/systemd/layerline-cert-renew.{service,timer}` – certbot renewal timer with Layerline restart deploy hook.
- `deploy/launchd/dev.layerline.layerline.plist` – macOS launchd service template.
- `Dockerfile` – runtime image template for an already built `zig-out/bin/layerline`.
- HTTP/2/HTTP/3 deployment notes in this README.


```bash
zig build run
```

Run with options:

```bash
zig build run -- --help
zig build run -- --config server.conf
zig build run -- --port 4000
zig build run -- --port 8080 --dir public
```

Run the self-starting local verification harness:

```bash
./scripts/verify-layerline.sh
```

## Config file

Use `--config` to load a base config, then override values with CLI flags.
From the project root, `server.conf` loads automatically when present unless you pass a custom `--config`.
With `serve_static_root` enabled, unknown paths are checked against local static files first, then forwarded upstream.
Validate a config without opening sockets:

```bash
zig build run -- --validate-config
zig build run -- --config server.conf --validate-config
zig build run -- --dump-routes
```

Config files are strict: unknown keys, malformed lines, invalid booleans, invalid numbers, invalid headers, and invalid redirects fail with a line-numbered error.

Example `server.conf`:

```text
# server.conf
host = 127.0.0.1
port = 8080
dir = public
serve_static_root = true
index_file = index.html
php_root = public
php_bin = php-cgi
php_fastcgi = off
php_index = index.php
# Send unknown local paths to php_index with PATH_INFO for framework-style apps.
php_front_controller = false
# /test.php renders phpinfo(); keep disabled outside local diagnostics.
php_info_page = false
# Set proxy to one upstream URL, or a comma/space-separated pool, to forward unknown local routes.
# Use off/false/no/0/none/null to disable it.
proxy = off
#proxy = http://127.0.0.1:9000 weight=3, http://127.0.0.1:9001 weight=1
# Pick the first target in a pool with round_robin, random, least_connections, weighted, or consistent_hash.
#upstream_policy = round_robin
# Retry failed pooled upstream targets before Layerline commits a proxy response.
# Set to 0 to disable retry attempts.
#upstream_retries = 1
# Passive health ejects a target after repeated failed attempts.
# Circuit breaker recovery allows a small half-open probe window after cooldown.
# Set upstream_max_failures = 0 to disable passive ejection.
#upstream_max_failures = 2
#upstream_fail_timeout_ms = 10000
#upstream_circuit_breaker = true
#upstream_circuit_half_open_max = 1
#upstream_slow_start_ms = 10000
# Reuse backend TCP sockets after framed upstream responses.
#upstream_keepalive = true
#upstream_keepalive_max_idle = 16
#upstream_keepalive_idle_timeout_ms = 30000
#upstream_keepalive_max_requests = 100
# Active health checks are opt-in and mark unhealthy targets before user traffic hits them.
#upstream_health_check = false
#upstream_health_check_path = /health
#upstream_health_check_interval_ms = 5000
#upstream_health_check_timeout_ms = 1000
# Named route syntax: route = NAME /path-or-prefix/* static|php|proxy
# Route-local settings inherit global values unless overridden.
#route = assets /assets/* static
#route_dir.assets = public
#route_index.assets = index.html
#route = app /app/* php
#route_php_root.app = public
#route_php_bin.app = php-cgi
#route_php_fastcgi.app = 127.0.0.1:9000
#route_php_index.app = index.php
#route_php_front_controller.app = true
#route_php_timeout_ms.app = 10000
#route = api /api/* proxy
#route_proxy.api = http://127.0.0.1:9000, http://127.0.0.1:9001
#route_proxy_timeout_ms.api = 15000
# Nginx-style per-domain files live outside this main runtime config.
# Put .conf files in domains-enabled/ and enable this:
#domain_config_dir = domains-enabled
# optional h2 cleartext passthrough target; requests with HTTP/2 preface are tunneled raw
#h2_upstream = http://127.0.0.1:9001
# Read-only local admin socket: status, validate, routes, certs, metrics.
#admin_socket = /tmp/layerline-admin.sock
# Browser admin UI is disabled by default and creates access on first launch.
#admin_ui = false
#admin_ui_path = /_layerline/admin
#admin_credentials_path = .layerline-admin
# Structured JSON access logs are off by default.
#access_log = off
# Opt-in dynamic gzip for buffered text responses.
#compression = false
#compression_min_bytes = 512
#compression_max_bytes = 1048576
tls = false
# Let's Encrypt auto TLS bootstrap (webroot mode)
#tls_auto = true
#letsencrypt_email = admin@example.com
#letsencrypt_domains = example.com,www.example.com
#letsencrypt_webroot = public
#letsencrypt_certbot = /usr/bin/certbot
#letsencrypt_staging = false
#letsencrypt_renew = true
#letsencrypt_renew_interval_ms = 43200000
#http_redirect = false
#http_redirect_port = 80
#http_redirect_https_port = 443
#http_redirect_status = 308
#cf_auto_deploy = false
#cf_api_base = https://api.cloudflare.com/client/v4
#cf_token = your-api-token
#cf_zone_id = optional-zone-id
#cf_zone_name = example.com
#cf_record_name = www.example.com
#cf_record_type = A
#cf_record_content = 198.51.100.10
#cf_record_ttl = 300
#cf_record_proxied = false
#cf_record_comment = managed by Layerline
#max_requests_per_connection = 256
#worker_stack_size = 65536
#max_php_output_bytes = 2097152
#read_header_timeout_ms = 10000
#read_body_timeout_ms = 30000
#idle_timeout_ms = 60000
#write_timeout_ms = 30000
#upstream_timeout_ms = 30000
#upstream_retries = 1
#graceful_shutdown_timeout_ms = 10000
max_request_bytes = 16384
max_body_bytes = 1048576
max_static_file_bytes = 10485760
max_concurrent_connections = 1000000
```

## HTTP/2 and HTTP/3

This server now terminates native TLS 1.3 on the TCP listener and uses ALPN to route HTTP/1.1 or HTTP/2 on the same socket:

- Native HTTPS supports TLS 1.3 with X25519, TLS_AES_128_GCM_SHA256, ECDSA P-256/SHA-256 certificates, RSA-PSS/SHA-256 certificates, and Ed25519 fallback.
- HTTP/2 is served directly over TLS when the client selects `h2`, and HTTP/1.1 stays on the existing router when the client selects `http/1.1` or sends no ALPN.
- HTTP/2 cleartext (`h2c`) is still supported for local or upstream cleartext workflows.
- Native HTTP/3 can be started with `--http3 true --http3-port 8443`.
- The current native HTTP/3 path decrypts QUIC v1 Initial packets, completes a TLS 1.3 `h3` handshake with an in-process self-signed Ed25519 certificate, derives Handshake and 1-RTT packet keys, accepts a client request stream, and sends the built-in Layerline page as HTTP/3 HEADERS + DATA.
- HTTP/3 connection state is tracked per QUIC connection ID with a bounded in-process table, so concurrent handshakes no longer share one global assembly buffer.
- Broader HTTP/3 routing is intentionally still narrow: the native path serves the default page first, while HTTP/1 keeps the full static/PHP/proxy surface.

Run with:

```bash
zig build run -- --config server.conf --http3 true --http3-port 8443
```

Argument precedence (highest wins):

1. explicit CLI flags (`--port`, `--dir`, `--proxy`, etc.)
2. config file values
3. built-in defaults

### Standards behavior

- `GET` and `HEAD` routes are supported together on local handlers (static files and endpoints).
- `OPTIONS` returns `204 No Content` with an `Allow` header.
- Request parsing enforces valid versions (`HTTP/1.0`/`HTTP/1.1`) and required headers.
- Request bodies support fixed `Content-Length` and standards-style `Transfer-Encoding: chunked`; unsupported transfer codings are rejected.
- `Expect: 100-continue` receives an interim `100 Continue` response before the body is read.
- Incoming HTTP/2 preface payload is detected and can be tunneled to `--h2-upstream`.
- HTTP/3 traffic on TCP is rejected with an explicit guidance message; native HTTP/3 uses UDP.
- Unsupported methods return `501 Method Not Implemented`.
- Unknown paths can still be handled by reverse proxy mode if configured.

## Static serving behavior

- `/static/<file>` always maps to that exact file under `dir`.
- `/favicon.svg` and `/icon.svg` return the built-in Layerline SVG mark.
- If `serve_static_root` is enabled and a requested GET path is not a known API route (`/health`, `/time`, `/api/*`, `/php/*`),
  the server checks for a matching file in `dir` (for `/` and trailing-slash paths it resolves to `index_file`).
- If a client advertises `br` or `gzip` and a matching `.br` or `.gz` sidecar exists, the full-file static path serves that precompressed asset with `Content-Encoding` and `Vary: Accept-Encoding`.
- Range requests use the original file representation so byte offsets stay predictable.
- On Darwin targets, response bodies are transferred with `sendfile` when the socket and file descriptor support it; unsupported platforms or syscalls fall back to the bounded buffered path.
- If no local static match is found, the reverse proxy (if configured) handles the request.

## Compression

Dynamic gzip is opt-in and applies to buffered text-like responses on HTTP/1.1 and native HTTP/2 when the client advertises `Accept-Encoding: gzip`:

```conf
compression = true
compression_min_bytes = 512
compression_max_bytes = 1048576
```

Layerline skips bodies that are too small, too large, already encoded, or not a compressible content type. Static files should still prefer `.br`/`.gz` sidecars when possible so large assets stay on the sendfile/precompressed path.

When dynamic compression is enabled, Layerline raises worker stack size to at least 512 KiB unless `worker_stack_size` is already higher. That keeps Zig's gzip encoder off the tiny default worker stack while leaving compression disabled deployments at the smaller default.

## Admin Socket

Set `admin_socket` to enable a local Unix socket for read-only operations:

```conf
admin_socket = /tmp/layerline-admin.sock
```

Commands are one line each: `status`, `validate`, `routes`, `certs`, `metrics`, and `help`.

```bash
printf 'status\n' | nc -U /tmp/layerline-admin.sock
printf 'routes\n' | nc -U /tmp/layerline-admin.sock
printf 'certs\n' | nc -U /tmp/layerline-admin.sock
```

This socket deliberately does not reload config yet. Reload needs an owned immutable config snapshot per worker so existing requests can drain on the old config while new requests move to the new one.

## Admin Web UI

The browser admin UI is disabled by default. Enable it only on a trusted admin path:

```conf
admin_ui = true
admin_ui_path = /_layerline/admin
admin_credentials_path = /etc/layerline/admin.credentials
domain_config_dir = domains-enabled
```

On first launch, `GET /_layerline/admin` shows a setup form. The setup POST writes a PBKDF2-HMAC-SHA256 credential file and sets an HttpOnly `SameSite=Strict` session cookie scoped to the admin path. After that, the same URL shows the login screen unless a valid admin session cookie is present.

The dashboard is now an actual control surface: it lists active virtual hosts, shows enabled domain config files, validates the runtime config, exposes status/routes/certs/metrics, and can create new nginx-style site files under `domain_config_dir`. Site-file writes are deliberately staged: restart Layerline for new sites to become active until the hot-reload config snapshot work lands.

## Website and branding

The default repository website lives in `public/index.html` and `public/site.css`. With `serve_static_root = true`, Layerline serves it at `/` before falling back to the built-in diagnostic homepage. The site presents Layerline as a production web server project, links to GitHub, shows setup snippets, compares the current feature surface with Caddy and nginx, and uses the Laina mascot asset from `public/laina.png`.

For a site config:

```conf
dir = public
serve_static_root = true
index_file = index.html
domain_config_dir = domains-enabled
```

## Access Logs

Access logs are disabled by default. Enable structured JSON logs to stderr for systemd/journald, or point them at a file:

```conf
access_log = stderr
access_log = /var/log/layerline/access.log
```

Each line includes `ts_ms`, `server`, `method`, `path`, `query`, `host`, `protocol`, `status`, `bytes`, `duration_ms`, `handler`, and, for proxied requests, `upstream`. Route errors include an `error` field. File logs are appended under a process-wide lock so concurrent workers do not interleave JSON lines.

## Header and Redirect Rules

Repeat `header` lines in `server.conf` to add global headers to Layerline-generated responses and normal HTTP/1 proxy responses:

```conf
header = X-Frame-Options: DENY
header = X-Content-Type-Options: nosniff
```

Headers inherit from global to domain to route. Use inline server keys or per-domain files when a site or route needs its own policy:

```conf
server = main
server_name.main = example.com
server_header.main = Strict-Transport-Security: max-age=31536000

route = app /app/* proxy
route_header.app = Cache-Control: no-store
server_route_header.main.app = X-App-Policy: isolated
```

Cache policy has a first-class shortcut that emits `Cache-Control` at the same scopes:

```conf
cache_control = public, max-age=60
server_cache_control.main = private, max-age=30
route_cache_control.app = no-store
server_route_cache_control.main.assets = public, max-age=31536000, immutable
```

Redirects use `redirect = FROM TO [status]`. `FROM` may end with `*` for prefix matching; the matched suffix is appended to `TO`.

```conf
redirect = /old /new 308
redirect = /docs/* /documentation/ 308
```

## Named Routes

Named routes are the route-local config surface that future Caddy/nginx-class behavior will hang from. A route line has a name, a match pattern, and a handler:

```conf
route = assets /assets/* static
route_dir.assets = public
route_index.assets = index.html

route = app /app/* php
route_php_root.app = public
route_php_bin.app = php-cgi

route = api /api/* proxy
route_proxy.api = http://127.0.0.1:9000, http://127.0.0.1:9001
route_upstream_policy.api = random
```

Patterns ending in `*` are prefix routes; other patterns are exact routes. Prefix routes strip their matched prefix by default, so `/assets/hello.txt` maps to `public/hello.txt`. Set `route_strip_prefix.NAME = false` when the upstream filesystem or app expects the full path. Proxy settings accept one upstream or a comma/space-separated upstream pool. Pool policy defaults to `round_robin`; use `upstream_policy`, `server_upstream_policy.NAME`, or `route_upstream_policy.NAME` for `random`, `least_connections`, `weighted`, or `consistent_hash` when you want nginx-style per-scope balancing behavior. Use `zig build run -- --dump-routes` to validate and print the active route table without opening sockets.

## Per-Domain Config Files

Keep `server.conf` for the actual web server runtime: listener, limits, global headers, default PHP binary, HTTP/3 port, ACME/Cloudflare, and other process-level behavior. Domain configs can live in separate files loaded from `domain_config_dir`, which is closer to nginx `sites-enabled`.

```text
# server.conf
host = 127.0.0.1
port = 8080
dir = public
php_bin = /opt/homebrew/bin/php-cgi
domain_config_dir = domains-enabled
```

Each `*.conf` file in that directory defines one virtual host. The file name becomes the internal server name unless you set `name` or `server` inside the file.

```conf
# domains-enabled/example.conf
server_name = example.com www.example.com
root = public
index = index.html
serve_static_root = true
tls_cert = /etc/letsencrypt/live/example.com/fullchain.pem
tls_key = /etc/letsencrypt/live/example.com/privkey.pem
add_header = Strict-Transport-Security: max-age=31536000
add_header = X-Content-Type-Options: nosniff
cache_control = private, max-age=30

route = assets /assets/* static
route_dir.assets = public
route_cache_control.assets = public, max-age=31536000, immutable

route = app /app/* php
route_php_root.app = public
route_php_bin.app = php-cgi
route_php_fastcgi.app = off
route_php_index.app = index.php
route_php_front_controller.app = true
route_php_timeout_ms.app = 10000

proxy = http://127.0.0.1:9000, http://127.0.0.1:9001
upstream_policy = random
proxy_timeout_ms = 15000
```

`server_name` accepts exact names, wildcard names like `*.example.com`, and `_` as a catch-all default. Exact names win over wildcards, and domain-local redirects/routes are checked before the global redirect and route table. Domain settings inherit from global config unless the domain or route overrides them, including response headers, upstream pool policy, and TLS material. Domain-local `tls_cert`/`tls_key` pairs are selected by SNI before Layerline falls back to the global certificate. The older inline form (`server = main`, `server_name.main = ...`, `server_tls_cert.main = ...`) still works, but domain files are the intended layout.

## TLS options in config / CLI

Set `tls = true` with global `tls_cert` and `tls_key` to load a fallback PEM certificate chain and private key directly into Layerline. Put `tls_cert` and `tls_key` in a domain config file when a virtual host needs its own certificate. Layerline selects the matching domain certificate from the ClientHello SNI name, then falls back to the global pair. If TLS is enabled without any cert/key pair, Layerline still accepts HTTPS with an ephemeral self-signed certificate for local testing.

```ini
tls = true
tls_cert = /etc/letsencrypt/live/example.com/fullchain.pem
tls_key = /etc/letsencrypt/live/example.com/privkey.pem
```

The configured certificate path supports ECDSA P-256 private keys in SEC1 (`BEGIN EC PRIVATE KEY`) or PKCS#8 (`BEGIN PRIVATE KEY`) PEM form, plus RSA private keys in PKCS#1 (`BEGIN RSA PRIVATE KEY`) or PKCS#8 (`BEGIN PRIVATE KEY`) PEM form.

### Auto Let's Encrypt

The server can run `certbot` in webroot mode automatically on startup when both `--tls-auto true` and `--letsencrypt-domains` are provided. With `letsencrypt_renew = true`, Layerline also starts a background `certbot renew` loop; the default interval is 12 hours.

```bash
zig build run -- \
  --tls-auto true \
  --letsencrypt-email admin@example.com \
  --letsencrypt-domains example.com,www.example.com \
  --letsencrypt-webroot public \
  --letsencrypt-renew true \
  --http-redirect true \
  --http-redirect-port 80 \
  --tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/example.com/privkey.pem \
  --dir public
```

`letsencrypt_webroot` follows certbot webroot semantics: point it at the public root, and Layerline serves files from `<webroot>/.well-known/acme-challenge/<token>`. Older configs that point directly at `.well-known/acme-challenge` still work, but new production configs should use the public root. Enable `http_redirect = true` when Layerline owns both ports: the plaintext listener serves ACME challenges and redirects every other request to HTTPS with the original host, path, and query.

Renewal updates the certificate files on disk. Until hot reload lands, the running process must restart to pick up new TLS material. For production systemd hosts, install `deploy/systemd/layerline-cert-renew.timer`; its certbot deploy hook restarts Layerline only after a renewed certificate is deployed.

### Cloudflare automatic deployment

Enable startup DNS automation with:

```bash
zig build run -- \
  --cf-auto-deploy true \
  --cf-token <CLOUDFLARE_API_TOKEN> \
  --cf-zone-name example.com \
  --cf-record-name www.example.com \
  --cf-record-type A \
  --cf-record-content 198.51.100.10
  --cf-record-comment "managed by Layerline"
```

Behavior:

- If `--cf-record-content` is not set, the server detects the public IP via `api64.ipify.org` and uses it automatically.
- If a DNS record for that name already exists in the zone, it is updated.
- If the record does not exist, it is created.
- If multiple entries match name/type, the first matching record id is updated.
- `--cf-record-comment` is optional and only added when provided (useful for tagging deployments).

### High-traffic operation

For sustained inbound load, run behind your edge proxy/load balancer and tune:

```bash
zig build run -- \
  --max-concurrent-connections 1000000 \
  --max-requests-per-connection 256 \
  --worker-stack-size 65536 \
  --max-php-output-bytes 2097152 \
  --read-header-timeout-ms 10000 \
  --read-body-timeout-ms 30000 \
  --idle-timeout-ms 60000 \
  --write-timeout-ms 30000 \
  --upstream-timeout-ms 30000 \
  --max-request-bytes 16384 \
  --max-body-bytes 1048576 \
  --max-static-bytes 10485760
```

When overloaded, the server returns `503 Service Unavailable` and stops accepting additional work instead of growing past the limit.
This process still uses one worker thread per accepted socket, so for very high live-connection counts it should sit behind HAProxy/Nginx/Caddy or another edge balancer while native evented IO is built out.
`SIGINT` and `SIGTERM` stop accepting new connections and wait up to `graceful_shutdown_timeout_ms` for active handlers to drain.
Common host limits to revisit before aggressive load tests:

- Linux/macOS: increase open file limit (`ulimit -n 2000000`).
- Tune socket backlog and SYN/FIN handling in kernel sysctls according to your OS.
- Keep `max_requests_per_connection` low so idle keep-alive connections rotate quickly.

## Endpoints

- `GET /` → HTML welcome page.
- `GET /health` → plain health check.
- `GET /metrics` → Prometheus-style counters for connections, requests, responses, compressed bytes, static bytes, upstream proxy attempts, and native H3 packets.
- `GET /time` → JSON with current epoch seconds.
- `GET /api/echo?msg=hello` → JSON `{"msg":"hello"}`.
- `POST /api/echo` → echoes the POST body as plain text.
- `GET /static/<file>` → serves files from `public/` with basic MIME detection.
- Static files support `If-None-Match` and single `Range: bytes=...` requests.
- `HEAD /...` mirrors GET metadata for matching endpoints.
- `OPTIONS *` (or path-based OPTIONS) returns advertised methods and keeps response body empty.

Example:

```bash
curl -X POST --data 'hello zig' http://127.0.0.1:8080/api/echo
curl -H 'Transfer-Encoding: chunked' --data-binary 'hello chunked zig' http://127.0.0.1:8080/api/echo
curl http://127.0.0.1:8080/static/hello.txt
curl -H 'Range: bytes=0-4' http://127.0.0.1:8080/static/hello.txt
curl http://127.0.0.1:8080/metrics
```

## Benchmarking

Run the smoke and benchmark harness against a running server:

```bash
./scripts/benchmark-layerline.sh
```

Use `./scripts/benchmark-layerline.sh --verify-only` for deployment checks, or see `docs/benchmarking.md` for concurrency, duration, target, tool, and HTTP/3 smoke-test knobs.

## Reverse proxy mode

Forward unknown routes to another local service:

```bash
zig build run -- --proxy http://127.0.0.1:9000
```

Disable fallback proxying explicitly with:

```bash
zig build run -- --proxy off
```

You can pass an upstream base path:

```bash
zig build run -- --proxy http://127.0.0.1:9000/service
```

For upstream pools, Layerline retries another target when a target fails before a proxy response is committed:

```bash
zig build run -- --proxy http://127.0.0.1:9000,http://127.0.0.1:9001 --upstream-retries 1
```

Choose the first target with `round_robin` or `random`; retries still walk the remaining pool members once the first target is picked:

```bash
zig build run -- --proxy http://127.0.0.1:9000,http://127.0.0.1:9001 --upstream-policy random
```

Passive health marks a target as unavailable after repeated failed attempts. After the cooldown, the circuit breaker only allows a small half-open probe window; successful recovery starts the target at reduced weighted capacity before it receives full traffic again.

```bash
zig build run -- --proxy http://127.0.0.1:9000,http://127.0.0.1:9001 --upstream-max-failures 2 --upstream-fail-timeout-ms 10000 --upstream-circuit-half-open-max 1 --upstream-slow-start-ms 10000
```

You can also run only HTTP/2 cleartext passthrough:

```bash
zig build run -- --h2-upstream http://127.0.0.1:9001
```

## PHP support

The server executes matching paths through CGI by default. Use `php-cgi` for real HTTP-style `header()` output, and set an absolute path if it is not on `PATH`:

```bash
zig build run -- --php-bin /usr/bin/php-cgi --php-root public
```

For persistent PHP workers, point Layerline at php-fpm. TCP and Unix socket endpoints are supported:

```text
php_root = public
php_fastcgi = 127.0.0.1:9000
# or:
php_fastcgi = unix:/run/php/php-fpm.sock
```

Layerline keeps FastCGI worker connections open by default with `FCGI_KEEP_CONN`, then rotates them by idle age and request count:

```text
fastcgi_keepalive = true
fastcgi_keepalive_max_idle = 8
fastcgi_keepalive_idle_timeout_ms = 30000
fastcgi_keepalive_max_requests = 100
```

Unsafe FastCGI responses, failed reads/writes, non-complete protocol status, and non-zero app status are forced closed instead of returned to the idle pool.

Native HTTP/2 PHP routes use the same FastCGI transport and can forward bounded request bodies to php-fpm. CGI binary execution is still HTTP/1-only; configure php-fpm/FastCGI for h2 PHP traffic.

Route and domain config can override or disable FastCGI with `route_php_fastcgi.NAME`, `server_php_fastcgi.NAME`, and `server_route_php_fastcgi.DOMAIN.ROUTE`. When `php_fastcgi` is set, Layerline speaks FastCGI directly and only falls back to CGI if FastCGI is disabled with `off`/`false`/`none`.

Use `php_timeout_ms`, `fastcgi_timeout_ms`, `proxy_timeout_ms`, or `upstream_timeout_ms` on a domain or route when one app needs a tighter backend limit than the global default:

```text
route = app /app/* php
route_php_fastcgi.app = 127.0.0.1:9000
route_php_timeout_ms.app = 10000
```

If the PHP worker is missing or cannot start, Layerline returns `502 Bad Gateway` instead of dropping the connection.

For framework-style apps, enable the front controller. Layerline will still serve real static files first when `serve_static_root = true`, then run `php_index` and set `SCRIPT_NAME`, `SCRIPT_FILENAME`, `PATH_INFO`, `PATH_TRANSLATED`, and `REQUEST_URI` for the original request.

```text
php_root = public
php_bin = /usr/bin/php-cgi
php_index = index.php
php_front_controller = true
```

Route-local front controllers work the same way:

```text
route = app /app/* php
route_php_root.app = public
route_php_index.app = index.php
route_php_front_controller.app = true
```

The bundled `/test.php` phpinfo page is disabled by default because it exposes runtime details. Enable it only when you need diagnostics:

```text
php_info_page = true
```

Example PHP file:

```php
<?php
echo json_encode([
  "message" => "hello from php",
  "time" => time(),
]);
```

Request it at:

```bash
curl http://127.0.0.1:8080/index.php
```

## SSL/TLS

Layerline can terminate HTTPS itself:

```bash
zig build run -- \
  --tls true \
  --tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/example.com/privkey.pem
```

The same listener can serve plain HTTP and native HTTPS. HTTPS clients negotiate TLS 1.3, then ALPN dispatches to HTTP/2 or HTTP/1.1. Keeping a reverse proxy in front is still possible during migration, but it is no longer required for the basic HTTPS path.

### Caddy sample

```text
my-site.example.com {
  reverse_proxy http://127.0.0.1:8080
}
```

### Nginx sample

```text
server {
  listen 443 ssl;
  server_name my-site.example.com;
  ssl_certificate /path/to/fullchain.pem;
  ssl_certificate_key /path/to/privkey.pem;
  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
  }
}
```
