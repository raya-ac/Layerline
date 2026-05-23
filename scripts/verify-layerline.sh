#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ZIG=${ZIG:-}
PORT=${LAYERLINE_VERIFY_PORT:-18145}
HOST=${LAYERLINE_VERIFY_HOST:-127.0.0.1}
REDIRECT_PORT=${LAYERLINE_VERIFY_REDIRECT_PORT:-$((PORT + 1))}
REDIRECT_TLS_PORT=${LAYERLINE_VERIFY_REDIRECT_TLS_PORT:-$((PORT + 2))}
H3_PORT=${LAYERLINE_VERIFY_H3_PORT:-$((PORT + 3))}

if [[ -z $ZIG ]]; then
  if [[ -x /opt/homebrew/bin/zig ]]; then
    ZIG=/opt/homebrew/bin/zig
  else
    ZIG=zig
  fi
fi

TMP_DIR=$(mktemp -d)
SOCKET="$TMP_DIR/layerline-admin.sock"
ADMIN_CREDS="$TMP_DIR/layerline-admin.creds"
ACCESS_LOG="$TMP_DIR/access.log"
SITE_DIR="$TMP_DIR/domains-enabled"
CUSTOM_ROOT="$TMP_DIR/custom-root"
RELOAD_ROOT="$TMP_DIR/reload-root"
SIGHUP_ROOT="$TMP_DIR/sighup-root"
CONFIG="$TMP_DIR/server.conf"
LOG="$TMP_DIR/layerline.log"
PID=
H2_SMOKE=0

cleanup() {
  if [[ -n ${PID:-} ]] && kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

log() {
  printf '==> %s\n' "$*"
}

ok() {
  printf 'ok: %s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  if [[ -f $LOG ]]; then
    printf '%s\n' '--- layerline log ---' >&2
    cat "$LOG" >&2
  fi
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

wait_for_http() {
  local url=$1
  local i
  for i in {1..50}; do
    if curl -fsS --max-time 1 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

header_has() {
  local file=$1
  local pattern=$2
  grep -qi "$pattern" "$file"
}

curl_supports_http3() {
  curl --version 2>/dev/null | grep -Eq '(^Features:| )HTTP3( |$)'
}

log "building Layerline release binary"
"$ZIG" build -Doptimize=ReleaseFast

cat >"$CONFIG" <<CONF
host = $HOST
port = $PORT
dir = public
serve_static_root = true
domain_config_dir = $SITE_DIR
admin_socket = $SOCKET
admin_ui = true
admin_ui_path = /_layerline/admin
admin_credentials_path = $ADMIN_CREDS
access_log = $ACCESS_LOG
cf_token = verify-secret-token
http3 = true
http3_port = $H3_PORT
compression = true
compression_min_bytes = 1
compression_max_bytes = 1048576
security_headers = basic
response_cache = true
response_cache_max_bytes = 1048576
response_cache_max_entry_bytes = 65536
response_cache_ttl_ms = 60000
route = nogzip /nogzip/* static
route_compression.nogzip = false
route_stale_if_error.nogzip = 30
route = nocache /nocache/* static
route_response_cache.nocache = false
route_security_headers.nocache = strict
route_max_static_file_bytes.nocache = 2048
route = verify_proxy /verify-proxy/* proxy
route_proxy.verify_proxy = http://127.0.0.1:19000 http://127.0.0.1:19001
route_upstream_policy.verify_proxy = least_connections
CONF
mkdir -p "$SITE_DIR" "$CUSTOM_ROOT" "$RELOAD_ROOT" "$SIGHUP_ROOT"
cat >"$CUSTOM_ROOT/index.html" <<'HTML'
custom domain root
HTML
cat >"$CUSTOM_ROOT/404.html" <<'HTML'
custom domain 404 page
HTML
printf 'woff2\n' >"$CUSTOM_ROOT/font.woff2"
cat >"$SITE_DIR/custom404.conf" <<CONF
name = custom404
server_name = custom404.test
root = $CUSTOM_ROOT
index = index.html
serve_static_root = true
php_info_page = false
compression = false
stale_while_revalidate = 45
CONF
cat >"$RELOAD_ROOT/index.html" <<'HTML'
reloaded domain root
HTML
cat >"$SIGHUP_ROOT/index.html" <<'HTML'
sighup domain root
HTML

DOCTOR_OUT="$TMP_DIR/doctor.out"
"$ROOT_DIR/zig-out/bin/layerline" --config "$CONFIG" --doctor >"$DOCTOR_OUT" 2>&1 || {
  cat "$DOCTOR_OUT" >&2
  die "layerline doctor failed"
}
grep -Fq 'Layerline doctor OK' "$DOCTOR_OUT" || die "layerline doctor did not report OK"
ok "CLI doctor"

CERTS_OUT="$TMP_DIR/certs.out"
"$ROOT_DIR/zig-out/bin/layerline" --config "$CONFIG" --certs >"$CERTS_OUT" 2>&1 || {
  cat "$CERTS_OUT" >&2
  die "layerline certs failed"
}
grep -Fq 'Layerline certificates:' "$CERTS_OUT" || die "layerline certs output missing heading"
grep -Fq 'acme domains=' "$CERTS_OUT" || die "layerline certs output missing ACME line"
ok "CLI certs"

log "starting temporary server on http://$HOST:$PORT"
(
  cd "$ROOT_DIR"
  ./zig-out/bin/layerline --config "$CONFIG"
) >"$LOG" 2>&1 &
PID=$!

wait_for_http "http://$HOST:$PORT/health" || die "server did not become healthy"

CLI_ADMIN_OUT="$TMP_DIR/cli-admin-status.out"
"$ROOT_DIR/zig-out/bin/layerline" --config "$CONFIG" --admin-command status >"$CLI_ADMIN_OUT" 2>&1 || {
  cat "$CLI_ADMIN_OUT" >&2
  die "CLI admin command failed"
}
grep -Fq '"server":"Layerline"' "$CLI_ADMIN_OUT" || die "CLI admin command did not return status JSON"
ok "CLI admin command"

CLI_CONFIG_OUT="$TMP_DIR/cli-admin-config.out"
"$ROOT_DIR/zig-out/bin/layerline" --config "$CONFIG" --admin-command config >"$CLI_CONFIG_OUT" 2>&1 || {
  cat "$CLI_CONFIG_OUT" >&2
  die "CLI admin config command failed"
}
grep -Fq 'Layerline redacted config' "$CLI_CONFIG_OUT" || die "CLI admin config output missing heading"
grep -Fq 'cf_token = <redacted>' "$CLI_CONFIG_OUT" || die "CLI admin config did not redact cf_token"
if grep -Fq 'verify-secret-token' "$CLI_CONFIG_OUT"; then
  die "CLI admin config leaked a secret token"
fi
ok "CLI admin redacted config"

ROOT_BODY="$TMP_DIR/root.body"
curl -fsS "http://$HOST:$PORT/" -o "$ROOT_BODY"
grep -Fq 'Layerline' "$ROOT_BODY" || die "root page did not contain Layerline"
ok "HTTP/1 root page"

REQUEST_ID_HEADERS="$TMP_DIR/request-id.headers"
curl -fsS -D "$REQUEST_ID_HEADERS" -H 'X-Request-Id: verify-request-123' "http://$HOST:$PORT/health" >/dev/null
header_has "$REQUEST_ID_HEADERS" '^X-Request-Id: verify-request-123' || die "HTTP/1 response did not preserve inbound X-Request-Id"
GENERATED_REQUEST_ID_HEADERS="$TMP_DIR/generated-request-id.headers"
curl -fsS -D "$GENERATED_REQUEST_ID_HEADERS" "http://$HOST:$PORT/health" >/dev/null
header_has "$GENERATED_REQUEST_ID_HEADERS" '^X-Request-Id: ll-' || die "HTTP/1 response did not generate X-Request-Id"
ok "HTTP/1 request id header"

MALFORMED_HEADER_RAW="$TMP_DIR/malformed-header.raw"
printf 'GET / HTTP/1.1\r\nHost: %s:%s\r\nBroken-Header\r\nConnection: close\r\n\r\n' "$HOST" "$PORT" | nc "$HOST" "$PORT" >"$MALFORMED_HEADER_RAW"
grep -Fq '400 Bad Request' "$MALFORMED_HEADER_RAW" || die "malformed header line did not return 400"
DUP_CONTENT_LENGTH_RAW="$TMP_DIR/duplicate-content-length.raw"
printf 'POST /api/echo HTTP/1.1\r\nHost: %s:%s\r\nContent-Length: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab' "$HOST" "$PORT" | nc "$HOST" "$PORT" >"$DUP_CONTENT_LENGTH_RAW"
grep -Fq '400 Bad Request' "$DUP_CONTENT_LENGTH_RAW" || die "conflicting duplicate Content-Length did not return 400"
ABSOLUTE_FORM_RAW="$TMP_DIR/absolute-form.raw"
printf 'GET http://%s:%s/health HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n' "$HOST" "$PORT" "$HOST" "$PORT" | nc "$HOST" "$PORT" >"$ABSOLUTE_FORM_RAW"
grep -Fq '200 OK' "$ABSOLUTE_FORM_RAW" || die "absolute-form request target did not return 200"
grep -Fq 'ok' "$ABSOLUTE_FORM_RAW" || die "absolute-form request target did not route to health endpoint"
BAD_TARGET_RAW="$TMP_DIR/bad-target.raw"
printf 'GET not-a-target HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n' "$HOST" "$PORT" | nc "$HOST" "$PORT" >"$BAD_TARGET_RAW"
grep -Fq '400 Bad Request' "$BAD_TARGET_RAW" || die "bad request target did not return 400"
ok "HTTP/1 parser hardening"

STATIC_HEADERS="$TMP_DIR/static.headers"
curl -fsS -D "$STATIC_HEADERS" "http://$HOST:$PORT/static/hello.txt" >/dev/null
header_has "$STATIC_HEADERS" '^Cache-Status: Layerline; fwd=uri-miss; stored; ttl=60; detail="response-cache"' || die "static Cache-Status store header missing"
STATIC_HIT_HEADERS="$TMP_DIR/static-hit.headers"
curl -fsS -D "$STATIC_HIT_HEADERS" "http://$HOST:$PORT/static/hello.txt" >/dev/null
header_has "$STATIC_HIT_HEADERS" '^Cache-Status: Layerline; hit; ttl=60; detail="response-cache"' || die "static response-cache hit header missing"
STATIC_ETAG=$(grep -i '^ETag:' "$STATIC_HIT_HEADERS" | head -1 | sed -E 's/^[^:]+:[[:space:]]*//;s/\r$//')
header_has "$STATIC_HIT_HEADERS" '^Last-Modified: ' || die "static Last-Modified header missing"
STATIC_LAST_MODIFIED=$(grep -i '^Last-Modified:' "$STATIC_HIT_HEADERS" | head -1 | sed -E 's/^[^:]+:[[:space:]]*//;s/\r$//')
HTTP1_IFMOD_HEADERS="$TMP_DIR/http1-if-modified.headers"
HTTP1_IFMOD_BODY="$TMP_DIR/http1-if-modified.body"
HTTP1_IFMOD_CODE=$(curl -sS -D "$HTTP1_IFMOD_HEADERS" -o "$HTTP1_IFMOD_BODY" -w '%{http_code}' -H "If-Modified-Since: $STATIC_LAST_MODIFIED" "http://$HOST:$PORT/static/hello.txt")
[[ $HTTP1_IFMOD_CODE == 304 ]] || die "If-Modified-Since static request returned HTTP $HTTP1_IFMOD_CODE instead of 304"
[[ ! -s $HTTP1_IFMOD_BODY ]] || die "If-Modified-Since static 304 returned a body"
HTTP1_IFRANGE_HEADERS="$TMP_DIR/http1-if-range.headers"
HTTP1_IFRANGE_BODY="$TMP_DIR/http1-if-range.body"
HTTP1_IFRANGE_CODE=$(curl -sS -D "$HTTP1_IFRANGE_HEADERS" -o "$HTTP1_IFRANGE_BODY" -w '%{http_code}' -H 'Range: bytes=0-4' -H "If-Range: $STATIC_ETAG" "http://$HOST:$PORT/static/hello.txt")
[[ $HTTP1_IFRANGE_CODE == 206 ]] || die "If-Range matching static request returned HTTP $HTTP1_IFRANGE_CODE instead of 206"
header_has "$HTTP1_IFRANGE_HEADERS" '^Content-Range: bytes 0-4/' || die "If-Range matching static request missed Content-Range"
grep -Fq 'hello' "$HTTP1_IFRANGE_BODY" || die "If-Range matching static response missed partial body"
HTTP1_IFRANGE_STALE_HEADERS="$TMP_DIR/http1-if-range-stale.headers"
HTTP1_IFRANGE_STALE_BODY="$TMP_DIR/http1-if-range-stale.body"
HTTP1_IFRANGE_STALE_CODE=$(curl -sS -D "$HTTP1_IFRANGE_STALE_HEADERS" -o "$HTTP1_IFRANGE_STALE_BODY" -w '%{http_code}' -H 'Range: bytes=0-4' -H 'If-Range: "stale-etag"' "http://$HOST:$PORT/static/hello.txt")
[[ $HTTP1_IFRANGE_STALE_CODE == 200 ]] || die "If-Range stale static request returned HTTP $HTTP1_IFRANGE_STALE_CODE instead of 200"
if header_has "$HTTP1_IFRANGE_STALE_HEADERS" '^Content-Range:'; then
  die "If-Range stale static request still returned Content-Range"
fi
grep -Fq 'static file support' "$HTTP1_IFRANGE_STALE_BODY" || die "If-Range stale static response did not fall back to the full body"
ok "static file route"

ROUTE_POLICY_HEADERS="$TMP_DIR/route-policy.headers"
curl -fsS -D "$ROUTE_POLICY_HEADERS" "http://$HOST:$PORT/nocache/hello.txt" >/dev/null
header_has "$ROUTE_POLICY_HEADERS" '^Cache-Status: Layerline; fwd=uri-miss; detail="static-file"' || die "route response-cache disable did not bypass memory cache"
header_has "$ROUTE_POLICY_HEADERS" "^Content-Security-Policy: default-src 'self'; base-uri 'self'; frame-ancestors 'none'" || die "route security header preset missing"
ok "route-local cache and security policy"

GZIP_HEADERS="$TMP_DIR/gzip.headers"
GZIP_BODY="$TMP_DIR/gzip.body"
GZIP_PAYLOAD=$(printf 'layerline%.0s' {1..200})
GZIP_URL="http://$HOST:$PORT/api/echo?msg=$GZIP_PAYLOAD"
curl -fsS --raw -D "$GZIP_HEADERS" -o "$GZIP_BODY" -H 'Accept-Encoding: gzip' "$GZIP_URL"
header_has "$GZIP_HEADERS" '^Content-Encoding: gzip' || die "gzip response header missing"
[[ $(od -An -tx1 -N2 "$GZIP_BODY" | tr -d ' \n') == 1f8b ]] || die "gzip response did not start with gzip magic"
ok "HTTP/1 gzip response"

IDENTITY_HEADERS="$TMP_DIR/identity.headers"
curl -fsS --raw -D "$IDENTITY_HEADERS" -o /dev/null -H 'Accept-Encoding: gzip;q=0' "$GZIP_URL"
if header_has "$IDENTITY_HEADERS" '^Content-Encoding: gzip'; then
  die "gzip q=0 response was compressed"
fi
ok "gzip q=0 negotiation"

ROUTE_NOGZIP_HEADERS="$TMP_DIR/route-nogzip.headers"
ROUTE_NOGZIP_CODE=$(curl -sS --raw -D "$ROUTE_NOGZIP_HEADERS" -o /dev/null -w '%{http_code}' -X POST -H 'Accept-Encoding: gzip' "http://$HOST:$PORT/nogzip/blocked")
[[ $ROUTE_NOGZIP_CODE == 405 ]] || die "route compression override returned HTTP $ROUTE_NOGZIP_CODE instead of 405"
if header_has "$ROUTE_NOGZIP_HEADERS" '^Content-Encoding: gzip'; then
  die "route compression override still compressed the route-local 405"
fi
header_has "$ROUTE_NOGZIP_HEADERS" '^Cache-Control: stale-if-error=30' || die "route stale-if-error Cache-Control header missing"
ok "HTTP/1 route compression override"

if curl --help all 2>/dev/null | grep -q -- '--http2-prior-knowledge'; then
  H2_ROOT_BODY="$TMP_DIR/h2-root.body"
  curl -fsS --http2-prior-knowledge "http://$HOST:$PORT/" -o "$H2_ROOT_BODY"
  grep -Fq 'Origin Surface Web Server' "$H2_ROOT_BODY" || die "h2 root page did not serve static website"
  ok "h2c root static website"

  H2_STATIC_HEADERS="$TMP_DIR/h2-static.headers"
  curl -fsS --http2-prior-knowledge -D "$H2_STATIC_HEADERS" "http://$HOST:$PORT/static/hello.txt" >/dev/null
  header_has "$H2_STATIC_HEADERS" '^cache-status: Layerline; hit; ttl=60; detail="response-cache"' || die "h2 static response-cache hit header missing"
  header_has "$H2_STATIC_HEADERS" '^last-modified: ' || die "h2 static Last-Modified header missing"
  H2_LAST_MODIFIED=$(grep -i '^last-modified:' "$H2_STATIC_HEADERS" | head -1 | sed -E 's/^[^:]+:[[:space:]]*//;s/\r$//')
  H2_IFMOD_HEADERS="$TMP_DIR/h2-if-modified.headers"
  H2_IFMOD_BODY="$TMP_DIR/h2-if-modified.body"
  H2_IFMOD_CODE=$(curl -sS --http2-prior-knowledge -D "$H2_IFMOD_HEADERS" -o "$H2_IFMOD_BODY" -w '%{http_code}' -H "If-Modified-Since: $H2_LAST_MODIFIED" "http://$HOST:$PORT/static/hello.txt")
  [[ $H2_IFMOD_CODE == 304 ]] || die "h2 If-Modified-Since static request returned HTTP $H2_IFMOD_CODE instead of 304"
  [[ ! -s $H2_IFMOD_BODY ]] || die "h2 If-Modified-Since static 304 returned a body"
  ok "h2c static cache status"

  H2_DYNAMIC_STORE_HEADERS="$TMP_DIR/h2-dynamic-store.headers"
  curl -fsS --http2-prior-knowledge -D "$H2_DYNAMIC_STORE_HEADERS" "http://$HOST:$PORT/api/echo?msg=microcache" >/dev/null
  header_has "$H2_DYNAMIC_STORE_HEADERS" '^cache-status: Layerline; fwd=uri-miss; stored; ttl=60; detail="microcache"' || die "h2 dynamic microcache store header missing"
  H2_DYNAMIC_HIT_HEADERS="$TMP_DIR/h2-dynamic-hit.headers"
  curl -fsS --http2-prior-knowledge -D "$H2_DYNAMIC_HIT_HEADERS" "http://$HOST:$PORT/api/echo?msg=microcache" >/dev/null
  header_has "$H2_DYNAMIC_HIT_HEADERS" '^cache-status: Layerline; hit; ttl=60; detail="microcache"' || die "h2 dynamic microcache hit header missing"
  H2_SELECTIVE_PURGE=$(printf 'cache-purge microcache\n' | nc -U "$SOCKET")
  case "$H2_SELECTIVE_PURGE" in
    'OK purged '*" cache entries matching microcache"*) ;;
    *) die "admin selective cache purge response was unexpected: $H2_SELECTIVE_PURGE" ;;
  esac
  H2_DYNAMIC_REFILL_HEADERS="$TMP_DIR/h2-dynamic-refill.headers"
  curl -fsS --http2-prior-knowledge -D "$H2_DYNAMIC_REFILL_HEADERS" "http://$HOST:$PORT/api/echo?msg=microcache" >/dev/null
  header_has "$H2_DYNAMIC_REFILL_HEADERS" '^cache-status: Layerline; fwd=uri-miss; stored; ttl=60; detail="microcache"' || die "h2 dynamic microcache did not refill after selective purge"
  ok "h2c dynamic microcache"

  H2_ROUTE_POLICY_HEADERS="$TMP_DIR/h2-route-policy.headers"
  curl -fsS --http2-prior-knowledge -D "$H2_ROUTE_POLICY_HEADERS" "http://$HOST:$PORT/nocache/hello.txt" >/dev/null
  header_has "$H2_ROUTE_POLICY_HEADERS" '^cache-status: Layerline; fwd=uri-miss; detail="static-file"' || die "h2 route response-cache disable did not bypass memory cache"
  header_has "$H2_ROUTE_POLICY_HEADERS" "^content-security-policy: default-src 'self'; base-uri 'self'; frame-ancestors 'none'" || die "h2 route security header preset missing"
  ok "h2c route-local cache and security policy"

  H2_REQUEST_ID_HEADERS="$TMP_DIR/h2-request-id.headers"
  curl -fsS --http2-prior-knowledge -D "$H2_REQUEST_ID_HEADERS" -H 'X-Request-Id: verify-h2-request-123' "http://$HOST:$PORT/health" >/dev/null
  header_has "$H2_REQUEST_ID_HEADERS" '^x-request-id: verify-h2-request-123' || die "h2 response did not preserve inbound X-Request-Id"
  ok "h2c request id header"

  H2_HEADERS="$TMP_DIR/h2.headers"
  H2_BODY="$TMP_DIR/h2.body"
  curl -fsS --http2-prior-knowledge --raw -D "$H2_HEADERS" -o "$H2_BODY" -H 'Accept-Encoding: gzip' "$GZIP_URL"
  header_has "$H2_HEADERS" '^content-encoding: gzip' || die "h2 gzip response header missing"
  [[ $(od -An -tx1 -N2 "$H2_BODY" | tr -d ' \n') == 1f8b ]] || die "h2 gzip response did not start with gzip magic"
  ok "h2c gzip response"

  H2_ROUTE_NOGZIP_HEADERS="$TMP_DIR/h2-route-nogzip.headers"
  H2_ROUTE_NOGZIP_CODE=$(curl -sS --http2-prior-knowledge --raw -D "$H2_ROUTE_NOGZIP_HEADERS" -o /dev/null -w '%{http_code}' -X POST -H 'Accept-Encoding: gzip' "http://$HOST:$PORT/nogzip/blocked")
  [[ $H2_ROUTE_NOGZIP_CODE == 405 ]] || die "h2 route compression override returned HTTP $H2_ROUTE_NOGZIP_CODE instead of 405"
  if header_has "$H2_ROUTE_NOGZIP_HEADERS" '^content-encoding: gzip'; then
    die "h2 route compression override still compressed the route-local 405"
  fi
  header_has "$H2_ROUTE_NOGZIP_HEADERS" '^cache-control: stale-if-error=30' || die "h2 route stale-if-error Cache-Control header missing"
  ok "h2c route compression override"

  H2_POST_BODY="$TMP_DIR/h2-post.body"
  curl -fsS --http2-prior-knowledge --data 'layerline-h2-body' "http://$HOST:$PORT/api/echo" -o "$H2_POST_BODY"
  grep -Fq 'layerline-h2-body' "$H2_POST_BODY" || die "h2 request body was not routed"
  ok "h2c request body"
  H2_SMOKE=1
else
  ok "h2c smoke skipped; curl lacks --http2-prior-knowledge"
fi

if curl_supports_http3; then
  H3_HEALTH_BODY="$TMP_DIR/h3-health.body"
  curl -fsSk --http3-only --max-time 5 "https://$HOST:$H3_PORT/health" -o "$H3_HEALTH_BODY"
  grep -Fq 'ok' "$H3_HEALTH_BODY" || die "HTTP/3 external curl smoke did not receive health body"
  ok "HTTP/3 external curl smoke"
else
  ok "HTTP/3 external curl smoke skipped; curl lacks HTTP3 feature"
fi

require_command nc
require_command perl

HEAD_404_RAW="$TMP_DIR/head-404.raw"
printf 'HEAD /missing-head-check HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n' "$HOST" "$PORT" | nc "$HOST" "$PORT" >"$HEAD_404_RAW"
grep -Fq '404 Not Found' "$HEAD_404_RAW" || die "HEAD 404 did not return 404"
perl -0ne 'exit(/\r\n\r\n\z/ ? 0 : 1)' "$HEAD_404_RAW" || die "HEAD 404 response included a body"
ok "HEAD 404 has no body"

CUSTOM_404_BODY="$TMP_DIR/custom-404.body"
CUSTOM_404_HEADERS="$TMP_DIR/custom-404.headers"
CUSTOM_404_CODE=$(curl -sS -D "$CUSTOM_404_HEADERS" -o "$CUSTOM_404_BODY" -w '%{http_code}' -H 'Host: custom404.test' "http://$HOST:$PORT/missing-custom-page")
[[ $CUSTOM_404_CODE == 404 ]] || die "domain custom 404 returned HTTP $CUSTOM_404_CODE"
grep -Fq 'custom domain 404 page' "$CUSTOM_404_BODY" || die "domain custom 404 body was not served"
header_has "$CUSTOM_404_HEADERS" '^X-Request-Id: ll-' || die "domain custom 404 did not include generated request id"
header_has "$CUSTOM_404_HEADERS" '^Cache-Control: stale-while-revalidate=45' || die "domain stale-while-revalidate Cache-Control header missing"
ok "domain custom 404 document"

MIME_HEADERS="$TMP_DIR/mime.headers"
curl -fsS -H 'Host: custom404.test' -D "$MIME_HEADERS" "http://$HOST:$PORT/font.woff2" >/dev/null
header_has "$MIME_HEADERS" '^Content-Type: font/woff2' || die "woff2 static MIME type missing"
ok "static MIME database"

CUSTOM_404_GZIP_HEADERS="$TMP_DIR/custom-404-gzip.headers"
CUSTOM_404_GZIP_CODE=$(curl -sS --raw -D "$CUSTOM_404_GZIP_HEADERS" -o /dev/null -w '%{http_code}' -H 'Host: custom404.test' -H 'Accept-Encoding: gzip' "http://$HOST:$PORT/missing-custom-page")
[[ $CUSTOM_404_GZIP_CODE == 404 ]] || die "domain compression override returned HTTP $CUSTOM_404_GZIP_CODE instead of 404"
if header_has "$CUSTOM_404_GZIP_HEADERS" '^Content-Encoding: gzip'; then
  die "domain compression override still compressed the custom 404"
fi
ok "domain compression override"

cat >"$SITE_DIR/sighup.conf" <<CONF
name = sighup
server_name = sighup.test
root = $SIGHUP_ROOT
index = index.html
serve_static_root = true
CONF
kill -HUP "$PID"
SIGHUP_BODY="$TMP_DIR/sighup-domain.body"
for _ in {1..50}; do
  if curl -fsS -H 'Host: sighup.test' "http://$HOST:$PORT/" -o "$SIGHUP_BODY" 2>/dev/null && grep -Fq 'sighup domain root' "$SIGHUP_BODY"; then
    ok "SIGHUP config reload"
    break
  fi
  sleep 0.1
done
grep -Fq 'sighup domain root' "$SIGHUP_BODY" || die "SIGHUP reload did not activate new domain config"

cat >"$SITE_DIR/reloaded.conf" <<CONF
name = reloaded
server_name = reload.test
root = $RELOAD_ROOT
index = index.html
serve_static_root = true
CONF
ADMIN_RELOAD=$(printf 'reload\n' | nc -U "$SOCKET")
case "$ADMIN_RELOAD" in
  'OK config reloaded'*) ok "admin reload" ;;
  *) die "admin reload response was unexpected: $ADMIN_RELOAD" ;;
esac
kill -0 "$PID" 2>/dev/null || die "server exited during admin reload"
RELOAD_BODY="$TMP_DIR/reload-domain.body"
curl -fsS -H 'Host: reload.test' "http://$HOST:$PORT/" -o "$RELOAD_BODY"
grep -Fq 'reloaded domain root' "$RELOAD_BODY" || die "reloaded domain was not served without restart"
ok "in-memory domain reload"

ADMIN_STATUS=$(printf 'status\n' | nc -U "$SOCKET")
case "$ADMIN_STATUS" in
  *'"server":"Layerline"'*) ok "admin status" ;;
  *) die "admin status response was unexpected: $ADMIN_STATUS" ;;
esac

ADMIN_VALIDATE=$(printf 'validate\n' | nc -U "$SOCKET")
case "$ADMIN_VALIDATE" in
  'OK activation config'*) ok "admin validate" ;;
  *) die "admin validate response was unexpected: $ADMIN_VALIDATE" ;;
esac
ADMIN_DIFF=$(printf 'diff\n' | nc -U "$SOCKET")
case "$ADMIN_DIFF" in
  *'activation diff'*'no activation changes'*) ok "admin config diff" ;;
  *) die "admin config diff response was unexpected: $ADMIN_DIFF" ;;
esac

ADMIN_CONFIG=$(printf 'config\n' | nc -U "$SOCKET")
case "$ADMIN_CONFIG" in
  *'Layerline redacted config'*) ;;
  *) die "admin config response was unexpected: $ADMIN_CONFIG" ;;
esac
case "$ADMIN_CONFIG" in
  *'cf_token = <redacted>'*) ;;
  *) die "admin config did not redact cf_token: $ADMIN_CONFIG" ;;
esac
case "$ADMIN_CONFIG" in
  *'custom404.conf'*) ok "admin redacted config" ;;
  *) die "admin config did not include enabled domain files: $ADMIN_CONFIG" ;;
esac
case "$ADMIN_CONFIG" in
  *'verify-secret-token'*) die "admin config leaked a secret token" ;;
esac

ADMIN_ROUTES=$(printf 'routes\n' | nc -U "$SOCKET")
case "$ADMIN_ROUTES" in
  *"global host=$HOST port=$PORT"*) ok "admin routes" ;;
  *) die "admin routes response was unexpected: $ADMIN_ROUTES" ;;
esac
case "$ADMIN_ROUTES" in
  *"route nocache:"*"security=strict response_cache=false"*) ok "admin routes show route policy" ;;
  *) die "admin routes did not show route-local policy: $ADMIN_ROUTES" ;;
esac

ADMIN_UPSTREAMS=$(printf 'upstreams\n' | nc -U "$SOCKET")
case "$ADMIN_UPSTREAMS" in
  *"route verify_proxy policy=least_connections targets=2"*) ok "admin upstream report" ;;
  *) die "admin upstream report was unexpected: $ADMIN_UPSTREAMS" ;;
esac
ADMIN_EJECT=$(printf 'upstream-eject route verify_proxy 0 60000\n' | nc -U "$SOCKET")
case "$ADMIN_EJECT" in
  'OK Ejected route verify_proxy upstream target 0.'*) ok "admin upstream eject" ;;
  *) die "admin upstream eject response was unexpected: $ADMIN_EJECT" ;;
esac
ADMIN_UPSTREAMS_EJECTED=$(printf 'upstreams\n' | nc -U "$SOCKET")
case "$ADMIN_UPSTREAMS_EJECTED" in
  *"route verify_proxy 0 http://127.0.0.1:19000/"*"state=ejected"*) ok "admin upstream ejected state" ;;
  *) die "admin upstream report did not show ejected target: $ADMIN_UPSTREAMS_EJECTED" ;;
esac
ADMIN_RECOVER=$(printf 'upstream-recover route verify_proxy 0\n' | nc -U "$SOCKET")
case "$ADMIN_RECOVER" in
  'OK Recovered route verify_proxy upstream target 0.'*) ok "admin upstream recover" ;;
  *) die "admin upstream recover response was unexpected: $ADMIN_RECOVER" ;;
esac

ADMIN_CERTS=$(printf 'certs\n' | nc -U "$SOCKET")
case "$ADMIN_CERTS" in
  *"global tls=false"*"acme renewals="*) ok "admin certs" ;;
  *) die "admin certs response was unexpected: $ADMIN_CERTS" ;;
esac
ADMIN_CERT_RENEW_DISABLED=$(printf 'cert-renew\n' | nc -U "$SOCKET")
case "$ADMIN_CERT_RENEW_DISABLED" in
  'ERROR certificate renewal failed: error.AcmeRenewalDisabled'*) ok "admin cert renew disabled guard" ;;
  *) die "admin cert renew disabled response was unexpected: $ADMIN_CERT_RENEW_DISABLED" ;;
esac

ADMIN_METRICS=$(printf 'metrics\n' | nc -U "$SOCKET")
case "$ADMIN_METRICS" in
  *'layerline_requests_total'*'layerline_acme_renewals_total'*) ok "admin metrics" ;;
  *) die "admin metrics response was unexpected" ;;
esac
ADMIN_CACHE_PURGE=$(printf 'cache-purge\n' | nc -U "$SOCKET")
case "$ADMIN_CACHE_PURGE" in
  'OK purged '*" cache entries"*) ok "admin cache purge" ;;
  *) die "admin cache purge response was unexpected: $ADMIN_CACHE_PURGE" ;;
esac

ADMIN_URL="http://$HOST:$PORT/_layerline/admin"
ADMIN_SETUP_BODY="$TMP_DIR/admin-setup.body"
curl -fsS "$ADMIN_URL" -o "$ADMIN_SETUP_BODY"
grep -Fq 'First launch setup' "$ADMIN_SETUP_BODY" || die "admin UI did not show first-launch setup"
ok "admin UI first-launch setup"

COOKIE_JAR="$TMP_DIR/admin.cookies"
curl -fsS -c "$COOKIE_JAR" -o /dev/null \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=admin&password=layerline-test-pass&password_confirm=layerline-test-pass' \
  "$ADMIN_URL/setup"
[[ -s $ADMIN_CREDS ]] || die "admin credentials file was not created"
ok "admin UI setup created credentials"

ADMIN_LOGIN_BODY="$TMP_DIR/admin-login.body"
curl -fsS "$ADMIN_URL" -o "$ADMIN_LOGIN_BODY"
grep -Fq 'Admin login' "$ADMIN_LOGIN_BODY" || die "admin UI did not require login after setup"
ok "admin UI requires login"

ADMIN_DASH_BODY="$TMP_DIR/admin-dashboard.body"
curl -fsS -b "$COOKIE_JAR" "$ADMIN_URL" -o "$ADMIN_DASH_BODY"
grep -Fq 'Control surface' "$ADMIN_DASH_BODY" || die "admin UI dashboard was not served with setup cookie"
grep -Fq 'Add site' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not include site management"
grep -Fq 'Save settings' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not include settings management"
grep -Fq 'Reload config' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not include in-memory reload"
grep -Fq 'redacted preview' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not include redacted config previews"
grep -Fq 'Activation diff' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not include activation diff"
grep -Fq 'Live proxy targets' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not include upstream controls"
grep -Fq 'route verify_proxy' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not expose upstream report"
grep -Fq 'Purge cache' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not include cache purge control"
grep -Fq 'Renew certificates' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not include certificate renewal control"
grep -Fq 'layerline_requests_total' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not include metrics"
grep -Fq 'layerline_response_cache_hits_total' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not include response-cache metrics"
grep -Fq 'security=strict response_cache=false' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not expose route-local policy"
ok "admin UI authenticated dashboard"

if [[ $H2_SMOKE -eq 1 ]]; then
  H2_ADMIN_CACHE_STORE_HEADERS="$TMP_DIR/h2-admin-cache-store.headers"
  curl -fsS --http2-prior-knowledge -D "$H2_ADMIN_CACHE_STORE_HEADERS" "http://$HOST:$PORT/api/echo?msg=ui-cache" >/dev/null
  header_has "$H2_ADMIN_CACHE_STORE_HEADERS" '^cache-status: Layerline; fwd=uri-miss; stored; ttl=60; detail="microcache"' || die "h2 admin cache prefill did not store microcache entry"
  H2_ADMIN_CACHE_HIT_HEADERS="$TMP_DIR/h2-admin-cache-hit.headers"
  curl -fsS --http2-prior-knowledge -D "$H2_ADMIN_CACHE_HIT_HEADERS" "http://$HOST:$PORT/api/echo?msg=ui-cache" >/dev/null
  header_has "$H2_ADMIN_CACHE_HIT_HEADERS" '^cache-status: Layerline; hit; ttl=60; detail="microcache"' || die "h2 admin cache prefill did not hit microcache entry"
  curl -fsS -b "$COOKIE_JAR" -o "$TMP_DIR/admin-cache-purge.body" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data 'target=ui-cache' \
    "$ADMIN_URL/cache/purge"
  grep -Fq 'Purged ' "$TMP_DIR/admin-cache-purge.body" || die "admin UI cache purge response did not confirm purge"
  grep -Fq 'matching ui-cache' "$TMP_DIR/admin-cache-purge.body" || die "admin UI cache purge response did not include target"
  H2_ADMIN_CACHE_REFILL_HEADERS="$TMP_DIR/h2-admin-cache-refill.headers"
  curl -fsS --http2-prior-knowledge -D "$H2_ADMIN_CACHE_REFILL_HEADERS" "http://$HOST:$PORT/api/echo?msg=ui-cache" >/dev/null
  header_has "$H2_ADMIN_CACHE_REFILL_HEADERS" '^cache-status: Layerline; fwd=uri-miss; stored; ttl=60; detail="microcache"' || die "h2 admin cache entry did not refill after UI purge"
  ok "admin UI purges matching cache entries"

  H2_ADMIN_API_CACHE_STORE_HEADERS="$TMP_DIR/h2-admin-api-cache-store.headers"
  curl -fsS --http2-prior-knowledge -D "$H2_ADMIN_API_CACHE_STORE_HEADERS" "http://$HOST:$PORT/api/echo?msg=api-cache" >/dev/null
  header_has "$H2_ADMIN_API_CACHE_STORE_HEADERS" '^cache-status: Layerline; fwd=uri-miss; stored; ttl=60; detail="microcache"' || die "h2 admin API cache prefill did not store microcache entry"
  H2_ADMIN_API_CACHE_HIT_HEADERS="$TMP_DIR/h2-admin-api-cache-hit.headers"
  curl -fsS --http2-prior-knowledge -D "$H2_ADMIN_API_CACHE_HIT_HEADERS" "http://$HOST:$PORT/api/echo?msg=api-cache" >/dev/null
  header_has "$H2_ADMIN_API_CACHE_HIT_HEADERS" '^cache-status: Layerline; hit; ttl=60; detail="microcache"' || die "h2 admin API cache prefill did not hit microcache entry"
  ADMIN_CACHE_PURGE_API_HEADERS="$TMP_DIR/admin-cache-purge-api.headers"
  ADMIN_CACHE_PURGE_API_BODY="$TMP_DIR/admin-cache-purge-api.body"
  curl -fsS -b "$COOKIE_JAR" -D "$ADMIN_CACHE_PURGE_API_HEADERS" -o "$ADMIN_CACHE_PURGE_API_BODY" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data 'target=api-cache' \
    "$ADMIN_URL/api/cache/purge"
  header_has "$ADMIN_CACHE_PURGE_API_HEADERS" '^Content-Type: application/json; charset=utf-8' || die "admin cache purge API did not return JSON"
  grep -Fq '"ok":true' "$ADMIN_CACHE_PURGE_API_BODY" || die "admin cache purge API did not confirm success"
  grep -Fq '"target":"api-cache"' "$ADMIN_CACHE_PURGE_API_BODY" || die "admin cache purge API response did not include target"
  H2_ADMIN_API_CACHE_REFILL_HEADERS="$TMP_DIR/h2-admin-api-cache-refill.headers"
  curl -fsS --http2-prior-knowledge -D "$H2_ADMIN_API_CACHE_REFILL_HEADERS" "http://$HOST:$PORT/api/echo?msg=api-cache" >/dev/null
  header_has "$H2_ADMIN_API_CACHE_REFILL_HEADERS" '^cache-status: Layerline; fwd=uri-miss; stored; ttl=60; detail="microcache"' || die "h2 admin API cache entry did not refill after API purge"
  ok "admin HTTP API purges matching cache entries"
fi

curl -fsS -b "$COOKIE_JAR" -o "$TMP_DIR/admin-settings.body" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "host=$HOST&port=$PORT&static_dir=public&index_file=index.html&domain_config_dir=$SITE_DIR&serve_static_root=true&compression=true&gzip=true&security_headers=basic&response_cache=true&response_cache_max_bytes=1048576&response_cache_max_entry_bytes=65536&response_cache_ttl_ms=60000&php_root=public&php_binary=php-cgi&php_fastcgi=off&php_front_controller=false&proxy=off&upstream_policy=round_robin&upstream_timeout_ms=5000&upstream_retries=1&upstream_keepalive=true&fastcgi_keepalive=true&tls=false&tls_cert=&tls_key=&http_redirect=false&http_redirect_port=$REDIRECT_PORT&http_redirect_https_port=$PORT&http3=false&http3_port=8443&admin_socket=$SOCKET&admin_ui=true&admin_ui_path=%2F_layerline%2Fadmin&admin_credentials_path=$ADMIN_CREDS&access_log=$ACCESS_LOG&max_concurrent_connections=1024&max_request_bytes=1048576&read_header_timeout_ms=5000&idle_timeout_ms=30000&worker_stack_size=524288" \
  "$ADMIN_URL/settings/save"
grep -Fq 'Saved settings to ' "$TMP_DIR/admin-settings.body" || die "admin settings response did not confirm save"
grep -Fq 'compression = true' "$CONFIG" || die "admin settings did not update main config"
grep -Fq 'admin_ui = true' "$CONFIG" || die "admin settings did not preserve admin UI"
[[ -s "$CONFIG.bak" ]] || die "admin settings did not create a config backup"
ok "admin UI saves main settings"

curl -fsS -b "$COOKIE_JAR" -o "$TMP_DIR/admin-add-site.body" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'name=verify&server_names=verify.test+www.verify.test&root=public&index=index.html&serve_static_root=on&proxy=http%3A%2F%2F127.0.0.1%3A9000&upstream_policy=least_connections&tls_cert=%2Fcerts%2Fverify%2Ffullchain.pem&tls_key=%2Fcerts%2Fverify%2Fprivkey.pem&route_name=app&route_pattern=%2Fapp%2F%2A&route_handler=proxy&route_proxy=http%3A%2F%2F127.0.0.1%3A9001' \
  "$ADMIN_URL/sites/add"
[[ -s "$SITE_DIR/verify.conf" ]] || die "admin UI did not create a site config file"
grep -Fq 'server_name = verify.test www.verify.test' "$SITE_DIR/verify.conf" || die "admin site config missing server names"
grep -Fq 'proxy = http://127.0.0.1:9000' "$SITE_DIR/verify.conf" || die "admin site config missing proxy"
grep -Fq 'tls_key = /certs/verify/privkey.pem' "$SITE_DIR/verify.conf" || die "admin site config missing TLS key"
grep -Fq 'route = app /app/* proxy' "$SITE_DIR/verify.conf" || die "admin site config missing route"
grep -Fq 'route_proxy.app = http://127.0.0.1:9001' "$SITE_DIR/verify.conf" || die "admin site config missing route proxy"
grep -Fq 'Created ' "$TMP_DIR/admin-add-site.body" || die "admin add-site response did not confirm creation"
grep -Fq 'verify.conf' "$TMP_DIR/admin-add-site.body" || die "admin add-site response did not show enabled file"
grep -Fq 'tls_key = &lt;redacted&gt;' "$TMP_DIR/admin-add-site.body" || die "admin add-site response did not redact TLS key preview"
if grep -Fq '/certs/verify/privkey.pem' "$TMP_DIR/admin-add-site.body"; then
  die "admin add-site response leaked TLS key path"
fi
ok "admin UI creates site configs"

[[ -s $ACCESS_LOG ]] || die "access log was not written"
grep -Fq '"method":"GET"' "$ACCESS_LOG" || die "access log missing method"
grep -Fq '"path":"/"' "$ACCESS_LOG" || die "access log missing root path"
grep -Fq '"protocol":"HTTP/1.1"' "$ACCESS_LOG" || die "access log missing protocol"
grep -Fq '"request_id":"verify-request-123"' "$ACCESS_LOG" || die "access log missing request id"
grep -Fq '"status":200' "$ACCESS_LOG" || die "access log missing status"
grep -Fq '"duration_ms":' "$ACCESS_LOG" || die "access log missing duration"
grep -Fq '"handler":"admin_ui"' "$ACCESS_LOG" || die "access log missing admin UI handler"
if [[ $H2_SMOKE -eq 1 ]]; then
  grep -Fq '"protocol":"HTTP/2.0"' "$ACCESS_LOG" || die "access log missing HTTP/2 protocol"
  grep -Fq '"path":"/api/echo"' "$ACCESS_LOG" || die "access log missing h2 echo path"
fi
ok "structured access log"

kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=

if [[ -e $SOCKET ]]; then
  die "admin socket was not removed after shutdown"
fi
ok "admin socket cleanup"

REDIRECT_WEBROOT="$TMP_DIR/acme-webroot"
mkdir -p "$REDIRECT_WEBROOT/.well-known/acme-challenge"
printf 'redirect-acme-token\n' >"$REDIRECT_WEBROOT/.well-known/acme-challenge/token-123"

cat >"$CONFIG" <<CONF
host = $HOST
port = $REDIRECT_TLS_PORT
dir = public
tls = true
http_redirect = true
http_redirect_port = $REDIRECT_PORT
http_redirect_https_port = $REDIRECT_TLS_PORT
letsencrypt_webroot = $REDIRECT_WEBROOT
access_log = $ACCESS_LOG
CONF

log "starting temporary TLS server with HTTP redirect listener on http://$HOST:$REDIRECT_PORT"
(
  cd "$ROOT_DIR"
  ./zig-out/bin/layerline --config "$CONFIG"
) >"$LOG" 2>&1 &
PID=$!

wait_for_http "http://$HOST:$REDIRECT_PORT/.well-known/acme-challenge/token-123" || die "HTTP redirect listener did not serve ACME challenge"
ACME_BODY="$TMP_DIR/acme.body"
curl -fsS "http://$HOST:$REDIRECT_PORT/.well-known/acme-challenge/token-123" -o "$ACME_BODY"
grep -Fq 'redirect-acme-token' "$ACME_BODY" || die "ACME challenge body was unexpected"
ok "HTTP redirect listener serves ACME challenge"

REDIRECT_HEADERS="$TMP_DIR/redirect.headers"
REDIRECT_BODY="$TMP_DIR/redirect.body"
curl -fsS -D "$REDIRECT_HEADERS" -o "$REDIRECT_BODY" "http://$HOST:$REDIRECT_PORT/some/path?x=1"
header_has "$REDIRECT_HEADERS" "^Location: https://$HOST:$REDIRECT_TLS_PORT/some/path?x=1" || die "HTTP redirect Location header was wrong"
grep -Fq "https://$HOST:$REDIRECT_TLS_PORT/some/path?x=1" "$REDIRECT_BODY" || die "HTTP redirect body was wrong"
ok "HTTP to HTTPS redirect preserves host, path, and query"

LARGE_POST="$TMP_DIR/large-post.bin"
dd if=/dev/zero of="$LARGE_POST" bs=1024 count=2048 >/dev/null 2>&1
POST_REDIRECT_HEADERS="$TMP_DIR/post-redirect.headers"
curl -fsS --max-time 5 -D "$POST_REDIRECT_HEADERS" -o /dev/null \
  --data-binary @"$LARGE_POST" \
  "http://$HOST:$REDIRECT_PORT/oversized-upload" || die "HTTP redirect listener failed to answer an oversized POST without reading the body"
header_has "$POST_REDIRECT_HEADERS" "^Location: https://$HOST:$REDIRECT_TLS_PORT/oversized-upload" || die "POST redirect Location header was wrong"
ok "HTTP redirect listener does not read request bodies"

HEAD_REDIRECT_RAW="$TMP_DIR/head-redirect.raw"
printf 'HEAD /head-redirect?ok=1 HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n' "$HOST" "$REDIRECT_PORT" | nc "$HOST" "$REDIRECT_PORT" >"$HEAD_REDIRECT_RAW"
grep -Fq '308 Permanent Redirect' "$HEAD_REDIRECT_RAW" || die "HEAD redirect did not return 308"
grep -Fq "Location: https://$HOST:$REDIRECT_TLS_PORT/head-redirect?ok=1" "$HEAD_REDIRECT_RAW" || die "HEAD redirect Location header was wrong"
perl -0ne 'exit(/\r\n\r\n\z/ ? 0 : 1)' "$HEAD_REDIRECT_RAW" || die "HEAD redirect response included a body"
ok "HEAD redirect has no body"

grep -Fq '"handler":"http_to_https_redirect"' "$ACCESS_LOG" || die "access log missing HTTP redirect handler"
grep -Fq '"handler":"acme_challenge"' "$ACCESS_LOG" || die "access log missing ACME challenge handler"
ok "redirect listener access log"

kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=

log "Layerline verification passed"
