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
CONFIG="$TMP_DIR/server.conf"
LOG="$TMP_DIR/layerline.log"
PID=

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
else
  ok "h2c smoke skipped; curl lacks --http2-prior-knowledge"
fi

require_command nc

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

kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=

if [[ -e $SOCKET ]]; then
  die "admin socket was not removed after shutdown"
fi
ok "admin socket cleanup"

log "Layerline verification passed"
