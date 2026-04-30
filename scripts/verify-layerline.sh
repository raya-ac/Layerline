#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ZIG=${ZIG:-}
PORT=${LAYERLINE_VERIFY_PORT:-18145}
HOST=${LAYERLINE_VERIFY_HOST:-127.0.0.1}

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
admin_socket = $SOCKET
admin_ui = true
admin_ui_path = /_layerline/admin
admin_credentials_path = $ADMIN_CREDS
access_log = $ACCESS_LOG
compression = true
compression_min_bytes = 1
compression_max_bytes = 1048576
CONF

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

curl -fsS "http://$HOST:$PORT/static/hello.txt" >/dev/null
ok "static file route"

GZIP_HEADERS="$TMP_DIR/gzip.headers"
GZIP_BODY="$TMP_DIR/gzip.body"
curl -fsS --raw -D "$GZIP_HEADERS" -o "$GZIP_BODY" -H 'Accept-Encoding: gzip' "http://$HOST:$PORT/"
header_has "$GZIP_HEADERS" '^Content-Encoding: gzip' || die "gzip response header missing"
[[ $(od -An -tx1 -N2 "$GZIP_BODY" | tr -d ' \n') == 1f8b ]] || die "gzip response did not start with gzip magic"
ok "HTTP/1 gzip response"

IDENTITY_HEADERS="$TMP_DIR/identity.headers"
curl -fsS --raw -D "$IDENTITY_HEADERS" -o /dev/null -H 'Accept-Encoding: gzip;q=0' "http://$HOST:$PORT/"
if header_has "$IDENTITY_HEADERS" '^Content-Encoding: gzip'; then
  die "gzip q=0 response was compressed"
fi
ok "gzip q=0 negotiation"

if curl --help all 2>/dev/null | grep -q -- '--http2-prior-knowledge'; then
  H2_HEADERS="$TMP_DIR/h2.headers"
  H2_BODY="$TMP_DIR/h2.body"
  curl -fsS --http2-prior-knowledge --raw -D "$H2_HEADERS" -o "$H2_BODY" -H 'Accept-Encoding: gzip' "http://$HOST:$PORT/"
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
  'OK config'*) ok "admin validate" ;;
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
grep -Fq 'layerline_requests_total' "$ADMIN_DASH_BODY" || die "admin UI dashboard did not include metrics"
ok "admin UI authenticated dashboard"

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

log "Layerline verification passed"
