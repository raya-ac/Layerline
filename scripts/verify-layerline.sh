#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ZIG=${ZIG:-}
PORT=${LAYERLINE_VERIFY_PORT:-18145}
HOST=${LAYERLINE_VERIFY_HOST:-127.0.0.1}
REDIRECT_PORT=${LAYERLINE_VERIFY_REDIRECT_PORT:-$((PORT + 1))}
REDIRECT_TLS_PORT=${LAYERLINE_VERIFY_REDIRECT_TLS_PORT:-$((PORT + 2))}

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
compression = true
compression_min_bytes = 1
compression_max_bytes = 1048576
CONF
mkdir -p "$SITE_DIR"

log "starting temporary server on http://$HOST:$PORT"
(
  cd "$ROOT_DIR"
  ./zig-out/bin/layerline --config "$CONFIG"
) >"$LOG" 2>&1 &
PID=$!

wait_for_http "http://$HOST:$PORT/health" || die "server did not become healthy"

ROOT_BODY="$TMP_DIR/root.body"
curl -fsS "http://$HOST:$PORT/" -o "$ROOT_BODY"
grep -Fq 'Layerline' "$ROOT_BODY" || die "root page did not contain Layerline"
ok "HTTP/1 root page"

STATIC_HEADERS="$TMP_DIR/static.headers"
curl -fsS -D "$STATIC_HEADERS" "http://$HOST:$PORT/static/hello.txt" >/dev/null
header_has "$STATIC_HEADERS" '^Cache-Status: Layerline; hit; ttl=60; detail="static-file"' || die "static Cache-Status header missing"
ok "static file route"

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

if curl --help all 2>/dev/null | grep -q -- '--http2-prior-knowledge'; then
  H2_ROOT_BODY="$TMP_DIR/h2-root.body"
  curl -fsS --http2-prior-knowledge "http://$HOST:$PORT/" -o "$H2_ROOT_BODY"
  grep -Fq 'Origin Surface Web Server' "$H2_ROOT_BODY" || die "h2 root page did not serve static website"
  ok "h2c root static website"

  H2_STATIC_HEADERS="$TMP_DIR/h2-static.headers"
  curl -fsS --http2-prior-knowledge -D "$H2_STATIC_HEADERS" "http://$HOST:$PORT/static/hello.txt" >/dev/null
  header_has "$H2_STATIC_HEADERS" '^cache-status: Layerline; hit; ttl=60; detail="static-file"' || die "h2 static Cache-Status header missing"
  ok "h2c static cache status"

  H2_HEADERS="$TMP_DIR/h2.headers"
  H2_BODY="$TMP_DIR/h2.body"
  curl -fsS --http2-prior-knowledge --raw -D "$H2_HEADERS" -o "$H2_BODY" -H 'Accept-Encoding: gzip' "$GZIP_URL"
  header_has "$H2_HEADERS" '^content-encoding: gzip' || die "h2 gzip response header missing"
  [[ $(od -An -tx1 -N2 "$H2_BODY" | tr -d ' \n') == 1f8b ]] || die "h2 gzip response did not start with gzip magic"
  ok "h2c gzip response"

  H2_POST_BODY="$TMP_DIR/h2-post.body"
  curl -fsS --http2-prior-knowledge --data 'layerline-h2-body' "http://$HOST:$PORT/api/echo" -o "$H2_POST_BODY"
  grep -Fq 'layerline-h2-body' "$H2_POST_BODY" || die "h2 request body was not routed"
  ok "h2c request body"
  H2_SMOKE=1
else
  ok "h2c smoke skipped; curl lacks --http2-prior-knowledge"
fi

require_command nc
require_command perl

HEAD_404_RAW="$TMP_DIR/head-404.raw"
printf 'HEAD /missing-head-check HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n' "$HOST" "$PORT" | nc "$HOST" "$PORT" >"$HEAD_404_RAW"
grep -Fq '404 Not Found' "$HEAD_404_RAW" || die "HEAD 404 did not return 404"
perl -0ne 'exit(/\r\n\r\n\z/ ? 0 : 1)' "$HEAD_404_RAW" || die "HEAD 404 response included a body"
ok "HEAD 404 has no body"

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

ADMIN_ROUTES=$(printf 'routes\n' | nc -U "$SOCKET")
case "$ADMIN_ROUTES" in
  *"global host=$HOST port=$PORT"*) ok "admin routes" ;;
  *) die "admin routes response was unexpected: $ADMIN_ROUTES" ;;
esac

ADMIN_CERTS=$(printf 'certs\n' | nc -U "$SOCKET")
case "$ADMIN_CERTS" in
  *"global tls=false"*"acme renewals="*) ok "admin certs" ;;
  *) die "admin certs response was unexpected: $ADMIN_CERTS" ;;
esac

ADMIN_METRICS=$(printf 'metrics\n' | nc -U "$SOCKET")
case "$ADMIN_METRICS" in
  *'layerline_requests_total'*'layerline_acme_renewals_total'*) ok "admin metrics" ;;
  *) die "admin metrics response was unexpected" ;;
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
grep -Fq 'redacted preview' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not include redacted config previews"
grep -Fq 'layerline_requests_total' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not include metrics"
ok "admin UI authenticated dashboard"

curl -fsS -b "$COOKIE_JAR" -o "$TMP_DIR/admin-settings.body" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "host=$HOST&port=$PORT&static_dir=public&index_file=index.html&domain_config_dir=$SITE_DIR&serve_static_root=true&compression=true&gzip=true&php_root=public&php_binary=php-cgi&php_fastcgi=off&php_front_controller=false&proxy=off&upstream_policy=round_robin&upstream_timeout_ms=5000&upstream_retries=1&upstream_keepalive=true&fastcgi_keepalive=true&tls=false&tls_cert=&tls_key=&http_redirect=false&http_redirect_port=$REDIRECT_PORT&http_redirect_https_port=$PORT&http3=false&http3_port=8443&admin_socket=$SOCKET&admin_ui=true&admin_ui_path=%2F_layerline%2Fadmin&admin_credentials_path=$ADMIN_CREDS&access_log=$ACCESS_LOG&max_concurrent_connections=1024&max_request_bytes=1048576&read_header_timeout_ms=5000&idle_timeout_ms=30000&worker_stack_size=524288" \
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
