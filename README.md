# Custom HTTP Server (Zig)

This is a practical build that blends local serving with edge-style deployment:

- PHP route execution for `.php` paths via `php-cgi`/`php`.
- Reverse-proxy fallback for anything the local server does not handle.
- Edge-friendly deployment notes for HTTPS/TLS (proxy-terminated by default).
- HTTP/1.1 parsing with request limits, keep-alive, `HEAD`, `OPTIONS`, chunked request bodies, `Expect: 100-continue`, and forwarding.
- Request lifecycle caps like `--max-requests-per-connection` so keep-alive sockets are periodically rotated.
- Static responses include ETag/cache headers, `If-None-Match`, `Accept-Ranges`, and single byte-range responses.
- HTTP/2 cleartext passthrough target support through `h2_upstream`.
- HTTP/3 handled as an edge/proxy concern in this version.
- Auto Let’s Encrypt (certbot) bootstrap and ACME challenge serving.
- Automatic Cloudflare DNS automation at startup (`--cf-auto-deploy`) with create/update behavior for A/AAAA/CNAME.
- Concurrent-connection protection (`--max-concurrent-connections`, default 1,000,000) to prevent overload instability.
- High-load knobs (`--max-requests-per-connection`, `--max-php-output-bytes`, `--worker-stack-size`) to tune behavior under sustained pressure.
- Branded HTML error responses for common 4xx/5xx paths, including HEAD-safe behavior.

## Files

- `src/main.zig` – server implementation.
- `build.zig` – Zig build script.
- `public/hello.txt` – sample static file.
- `public/index.php` – sample php endpoint (if PHP binary is installed and configured).
- `server.conf` – sample config file.
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
# Set proxy to an upstream URL to forward unknown local routes.
# Use off/false/no/0/none/null to disable it.
proxy = off
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
#cf_record_comment = managed by local zig server
#max_requests_per_connection = 256
#worker_stack_size = 65536
#max_php_output_bytes = 2097152
max_request_bytes = 16384
max_body_bytes = 1048576
max_static_file_bytes = 10485760
max_concurrent_connections = 1000000
```

## HTTP/2 and HTTP/3

This server is HTTP/1.x first, with protocol handoff at the edge:

- HTTP/2 cleartext (`h2c`) passthrough using `--h2-upstream` / `h2_upstream`.
- HTTP/3 handled by a reverse-proxy front.

Use this when you want modern protocol support at the edge while keeping this binary focused and small:

### Caddy example

```text
my-site.example.com {
  reverse_proxy http://127.0.0.1:8080
}
```

### NGINX HTTP/2 + HTTP/3 example

```text
server {
  listen 443 ssl http2;
  listen 443 quic reuseport;
  server_name my-site.example.com;

  ssl_certificate /path/to/fullchain.pem;
  ssl_certificate_key /path/to/privkey.pem;
  ssl_protocols TLSv1.3;
  ssl_early_data off;

  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }
}
```

If you need HTTP/2 framing inside the origin process, run a dedicated HTTP/2-aware component in front.

Run with:

```bash
zig build run -- --config server.conf
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
- HTTP/3 traffic on TCP is rejected with an explicit guidance message; use QUIC proxying in front.
- Unsupported methods return `501 Method Not Implemented`.
- Unknown paths can still be handled by reverse proxy mode if configured.

## Static serving behavior

- `/static/<file>` always maps to that exact file under `dir`.
- If `serve_static_root` is enabled and a requested GET path is not a known API route (`/health`, `/time`, `/api/*`, `/php/*`),
  the server checks for a matching file in `dir` (for `/` and trailing-slash paths it resolves to `index_file`).
- If no local static match is found, the reverse proxy (if configured) handles the request.

## TLS options in config / CLI

Config supports `tls`, `tls_cert`, and `tls_key` for deployment tracking, while this app socket stays plain HTTP.
Terminate TLS at a reverse proxy in front.

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
  --cf-record-comment "managed by local zig server"
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
  --max-request-bytes 16384 \
  --max-body-bytes 1048576 \
  --max-static-bytes 10485760
```

When overloaded, the server returns `503 Service Unavailable` and stops accepting additional work instead of growing past the limit.
This process still uses one worker thread per accepted socket, so for very high live-connection counts it should sit behind HAProxy/Nginx/Caddy with strict timeouts and strict reuse policies.
Common host limits to revisit before aggressive load tests:

- Linux/macOS: increase open file limit (`ulimit -n 2000000`).
- Tune socket backlog and SYN/FIN handling in kernel sysctls according to your OS.
- Keep `max_requests_per_connection` low so idle keep-alive connections rotate quickly.

## Endpoints

- `GET /` → small HTML welcome page.
- `GET /health` → plain health check.
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
```

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

You can also run only HTTP/2 cleartext passthrough:

```bash
zig build run -- --h2-upstream http://127.0.0.1:9001
```

## PHP support

The server will attempt to execute matching paths using `php-cgi` (or configured `--php-bin`):

```bash
zig build run -- --php-bin /usr/bin/php-cgi --php-root public
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

This server currently supports HTTP on the app socket.
Run it behind a TLS reverse proxy for HTTPS:

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
