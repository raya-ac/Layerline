# Layerline (Zig HTTP Server)

This is a practical build that blends local serving with edge-style deployment:

- Named runtime identity with branded root and error pages.
- Built-in SVG app icon at `/favicon.svg` and `/icon.svg`.
- PHP route execution for `.php` paths via `php-cgi`/`php`.
- Reverse-proxy fallback for anything the local server does not handle, including comma/space-separated upstream pools, selectable `round_robin`/`random`/`least_connections`/`weighted`/`consistent_hash` policies, target weights, bounded retries, passive upstream ejection, upstream keep-alive pooling, and opt-in active health checks.
- Named route config for route-local static, PHP, and proxy behavior.
- Host-based domain configs with nginx-style server names, wildcard names, per-domain roots, redirects, routes, PHP, and proxy fallbacks.
- Configured redirects and global response headers, using familiar Caddy/nginx-style primitives.
- Edge-friendly deployment notes for HTTPS/TLS (proxy-terminated by default).
- HTTP/1.1 parsing with request limits, keep-alive, `HEAD`, `OPTIONS`, chunked request bodies, `Expect: 100-continue`, and forwarding.
- Request lifecycle caps like `--max-requests-per-connection` so keep-alive sockets are periodically rotated.
- Socket-level header/body/idle/write/upstream timeouts plus SIGINT/SIGTERM graceful connection draining.
- Static responses use kernel `sendfile` on Darwin before falling back to bounded buffered reads, can serve precompressed `.br`/`.gz` sidecars, and include ETag/cache headers, `If-None-Match`, `Accept-Ranges`, and single byte-range responses.
- Prometheus-style runtime metrics at `/metrics`, including static sendfile/buffered transfer counters and reverse-proxy upstream attempt/failure/retry/ejection/connection-pool counters.
- HTTP/2 cleartext passthrough target support through `h2_upstream`.
- Native HTTP/3 work is in the Zig binary: QUIC varints, HTTP/3 frame headers, QPACK literal response headers, QUIC Initial/Handshake/1-RTT packet protection, TLS 1.3 handshake flight generation, and a default-page response path.
- Auto Let’s Encrypt (certbot) bootstrap and ACME challenge serving.
- Automatic Cloudflare DNS automation at startup (`--cf-auto-deploy`) with create/update behavior for A/AAAA/CNAME.
- Concurrent-connection protection (`--max-concurrent-connections`, default 1,000,000) to prevent overload instability.
- High-load knobs (`--max-requests-per-connection`, `--max-php-output-bytes`, `--worker-stack-size`) to tune behavior under sustained pressure.
- Branded HTML error responses for common 4xx/5xx paths, including HEAD-safe behavior.

## Current status

Layerline is past the toy-server stage: the HTTP/1 path has strict parsing, bounded bodies, keep-alive rotation, chunked request bodies, static sendfile/precompressed assets, PHP CGI execution, response headers, redirects, reverse-proxy fallback with pooled retries, configurable pool policy, least-connections, weighted, and consistent-hash balancing, reusable upstream keep-alive sockets, durable upstream health state, metrics, named routes, and host-based domain configs. The native HTTP/3 work is in-tree and currently serves the built-in default page over QUIC/TLS 1.3; full route dispatch over HTTP/3 is still on the roadmap.

The next roadmap slice is deeper upstream behavior: circuit breakers, slow start, sticky-session balancing, and per-route upstream pool policy. That work builds on the existing `proxy`, `route_proxy.NAME`, `server_proxy.NAME`, and `server_route_proxy.DOMAIN.ROUTE` config surface instead of adding another parallel config style.

## Files

- `src/main.zig` – server implementation.
- `build.zig` – Zig build script.
- `public/hello.txt` – sample static file.
- `public/index.php` – sample php endpoint (if PHP binary is installed and configured).
- `server.conf` – sample config file.
- `domains-available/example.conf` – sample per-domain config file.
- `domains-enabled/` – nginx-style enabled domain config directory.
- `scripts/benchmark-layerline.sh` – smoke and benchmark harness for HTTP/1 plus best-effort native HTTP/3 response checks.
- `docs/benchmarking.md` – benchmark runbook and environment knobs.
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
# Set upstream_max_failures = 0 to disable passive ejection.
#upstream_max_failures = 2
#upstream_fail_timeout_ms = 10000
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
#route = api /api/* proxy
#route_proxy.api = http://127.0.0.1:9000, http://127.0.0.1:9001
# Nginx-style per-domain files live outside this main runtime config.
# Put .conf files in domains-enabled/ and enable this:
#domain_config_dir = domains-enabled
# optional h2 cleartext passthrough target; requests with HTTP/2 preface are tunneled raw
#h2_upstream = http://127.0.0.1:9001
tls = false
# Let's Encrypt auto TLS bootstrap (webroot mode)
#tls_auto = true
#letsencrypt_email = admin@example.com
#letsencrypt_domains = example.com,www.example.com
#letsencrypt_webroot = public/.well-known/acme-challenge
#letsencrypt_certbot = /usr/bin/certbot
#letsencrypt_staging = false
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

## Header and Redirect Rules

Repeat `header` lines in `server.conf` to add global headers to Layerline-generated responses:

```conf
header = X-Frame-Options: DENY
header = X-Content-Type-Options: nosniff
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

route = assets /assets/* static
route_dir.assets = public

route = app /app/* php
route_php_root.app = public
route_php_bin.app = php-cgi

proxy = http://127.0.0.1:9000, http://127.0.0.1:9001
upstream_policy = random
```

`server_name` accepts exact names, wildcard names like `*.example.com`, and `_` as a catch-all default. Exact names win over wildcards, and domain-local redirects/routes are checked before the global redirect and route table. Domain settings inherit from global config unless the domain or route overrides them, including upstream pool policy. The older inline form (`server = main`, `server_name.main = ...`) still works, but domain files are the intended layout.

## TLS options in config / CLI

Set `tls = true` with `tls_cert` and `tls_key` to load a PEM certificate chain and private key directly into Layerline. If TLS is enabled without a cert/key pair, Layerline still accepts HTTPS with an ephemeral self-signed certificate for local testing.

```ini
tls = true
tls_cert = /etc/letsencrypt/live/example.com/fullchain.pem
tls_key = /etc/letsencrypt/live/example.com/privkey.pem
```

The configured certificate path supports ECDSA P-256 private keys in SEC1 (`BEGIN EC PRIVATE KEY`) or PKCS#8 (`BEGIN PRIVATE KEY`) PEM form, plus RSA private keys in PKCS#1 (`BEGIN RSA PRIVATE KEY`) or PKCS#8 (`BEGIN PRIVATE KEY`) PEM form.

### Auto Let's Encrypt

The server can run `certbot` in webroot mode automatically on startup when both `--tls-auto true` and `--letsencrypt-domains` are provided.

```bash
zig build run -- \
  --tls-auto true \
  --letsencrypt-email admin@example.com \
  --letsencrypt-domains example.com,www.example.com \
  --letsencrypt-webroot public/.well-known/acme-challenge \
  --tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/example.com/privkey.pem \
  --dir public
```

Keep the challenge root reachable at `/.well-known/acme-challenge/<token>` for successful issuance.

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
- `GET /metrics` → Prometheus-style counters for connections, requests, responses, static bytes, upstream proxy attempts, and native H3 packets.
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

Passive health marks a target as unavailable after repeated failed attempts and skips it until the cooldown expires:

```bash
zig build run -- --proxy http://127.0.0.1:9000,http://127.0.0.1:9001 --upstream-max-failures 2 --upstream-fail-timeout-ms 10000
```

You can also run only HTTP/2 cleartext passthrough:

```bash
zig build run -- --h2-upstream http://127.0.0.1:9001
```

## PHP support

The server executes matching paths through CGI. Use `php-cgi` for real HTTP-style `header()` output, and set an absolute path if it is not on `PATH`:

```bash
zig build run -- --php-bin /usr/bin/php-cgi --php-root public
```

If the PHP worker is missing or cannot start, Layerline returns `502 Bad Gateway` instead of dropping the connection.

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
