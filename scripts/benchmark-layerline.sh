#!/usr/bin/env bash
set -euo pipefail

BASE_URL=${LAYERLINE_URL:-http://127.0.0.1:8080}
ROOT_PATH=${LAYERLINE_ROOT_PATH:-/}
STATIC_PATH=${LAYERLINE_STATIC_PATH:-/static/hello.txt}
HEALTH_PATH=${LAYERLINE_HEALTH_PATH:-/health}
H3_URL=${LAYERLINE_H3_URL:-https://127.0.0.1:8443/}

BENCH_DURATION=${BENCH_DURATION:-10s}
BENCH_CONNECTIONS=${BENCH_CONNECTIONS:-64}
BENCH_THREADS=${BENCH_THREADS:-4}
BENCH_REQUESTS=${BENCH_REQUESTS:-10000}
BENCH_TOOL=${BENCH_TOOL:-}

CURL_TIMEOUT=${CURL_TIMEOUT:-5}
H3_TIMEOUT=${H3_TIMEOUT:-6}
SKIP_VERIFY=${LAYERLINE_SKIP_VERIFY:-0}
SKIP_H3=${LAYERLINE_SKIP_H3:-0}
H3_REQUIRED=${LAYERLINE_H3_REQUIRED:-0}
VERIFY_ONLY=${LAYERLINE_VERIFY_ONLY:-0}

ROOT_EXPECT=${LAYERLINE_EXPECT_ROOT_CONTAINS:-Layerline}
HEALTH_EXPECT=${LAYERLINE_EXPECT_HEALTH_CONTAINS:-ok}
STATIC_EXPECT=${LAYERLINE_EXPECT_STATIC_CONTAINS:-}

usage() {
  cat <<'USAGE'
Usage: scripts/benchmark-layerline.sh [options]

Smoke-checks a running Layerline instance, then benchmarks HTTP/1 endpoints
with the first available tool in this order: oha, wrk, hey, ab.

Options:
  --url URL             Base HTTP/1 URL. Default: LAYERLINE_URL or http://127.0.0.1:8080
  --h3-url URL          HTTP/3 URL for OpenSSL QUIC smoke. Default: LAYERLINE_H3_URL or https://127.0.0.1:8443/
  --duration DURATION   Duration for oha/wrk/hey. Default: BENCH_DURATION or 10s
  --connections N       Concurrent connections. Default: BENCH_CONNECTIONS or 64
  --threads N           wrk threads. Default: BENCH_THREADS or 4
  --requests N          ab request count. Default: BENCH_REQUESTS or 10000
  --tool TOOL           Force oha, wrk, hey, or ab.
  --verify-only         Run smoke checks only.
  --no-verify           Skip HTTP/1 and HTTP/3 smoke checks.
  --no-h3               Skip HTTP/3 OpenSSL smoke check.
  -h, --help            Show this help.

Useful environment:
  LAYERLINE_ROOT_PATH=/                         root endpoint path
  LAYERLINE_STATIC_PATH=/static/hello.txt       static endpoint path
  LAYERLINE_HEALTH_PATH=/health                 health endpoint path
  LAYERLINE_H3_REQUIRED=1                       fail if OpenSSL QUIC smoke fails
  LAYERLINE_EXPECT_ROOT_CONTAINS=Layerline      expected root body substring
  LAYERLINE_EXPECT_HEALTH_CONTAINS=ok           expected health body substring
  LAYERLINE_EXPECT_STATIC_CONTAINS=...          optional static body substring
USAGE
}

log() {
  printf '==> %s\n' "$*"
}

ok() {
  printf 'ok: %s\n' "$*"
}

warn() {
  printf 'warn: %s\n' "$*" >&2
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

require_command() {
  command_exists "$1" || die "required command not found: $1"
}

require_positive_int() {
  local name=$1
  local value=$2

  [[ $value =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer: $value"
}

url_for_path() {
  local base=$1
  local path=$2

  base=${base%/}
  if [[ -z $path || $path == "/" ]]; then
    printf '%s/\n' "$base"
    return
  fi

  if [[ $path != /* ]]; then
    path="/$path"
  fi

  printf '%s%s\n' "$base" "$path"
}

body_snippet() {
  local file=$1
  tr '\n' ' ' <"$file" | cut -c 1-240
}

smoke_endpoint() {
  local name=$1
  local url=$2
  local expected_status=$3
  local expected_substring=${4:-}
  local body_file="$TMP_DIR/${name}.body"
  local status

  status=$(curl --http1.1 --silent --show-error --location --max-time "$CURL_TIMEOUT" \
    --output "$body_file" --write-out '%{http_code}' "$url") || {
    local curl_status=$?
    die "$name smoke failed: curl exited $curl_status for $url"
  }

  if [[ $status != "$expected_status" ]]; then
    die "$name smoke expected HTTP $expected_status, got HTTP $status from $url: $(body_snippet "$body_file")"
  fi

  if [[ -n $expected_substring ]] && ! grep -Fq "$expected_substring" "$body_file"; then
    die "$name smoke did not find expected body substring '$expected_substring' from $url: $(body_snippet "$body_file")"
  fi

  ok "$name HTTP/1 smoke returned $status"
}

run_http1_smoke() {
  require_command curl

  log "HTTP/1 production smoke against $BASE_URL"
  smoke_endpoint root "$ROOT_URL" 200 "$ROOT_EXPECT"
  smoke_endpoint static "$STATIC_URL" 200 "$STATIC_EXPECT"
  smoke_endpoint health "$HEALTH_URL" 200 "$HEALTH_EXPECT"
}

openssl_supports_quic() {
  command_exists openssl && openssl s_client -help 2>&1 | grep -q -- '-quic'
}

parse_tls_host_port() {
  local url=$1
  local rest host_port host port after_bracket

  case "$url" in
    https://*) rest=${url#https://} ;;
    http://*) rest=${url#http://} ;;
    *) rest=$url ;;
  esac

  host_port=${rest%%/*}
  if [[ $host_port == \[*\]* ]]; then
    host=${host_port#\[}
    host=${host%%\]*}
    after_bracket=${host_port#*\]}
    if [[ $after_bracket == :* ]]; then
      port=${after_bracket#:}
    else
      port=443
    fi
  elif [[ $host_port == *:* ]]; then
    host=${host_port%:*}
    port=${host_port##*:}
  else
    host=$host_port
    port=443
  fi

  [[ -n $host ]] || return 1
  [[ $port =~ ^[0-9]+$ ]] || return 1
  printf '%s %s\n' "$host" "$port"
}

run_with_timeout() {
  local seconds=$1
  shift
  local pid watcher status

  "$@" &
  pid=$!
  (
    sleep "$seconds"
    kill "$pid" 2>/dev/null || true
  ) &
  watcher=$!

  status=0
  wait "$pid" || status=$?
  kill "$watcher" 2>/dev/null || true
  wait "$watcher" 2>/dev/null || true
  return "$status"
}

run_h3_smoke() {
  local host port output status

  if [[ $SKIP_H3 == 1 ]]; then
    warn "HTTP/3 OpenSSL smoke skipped by LAYERLINE_SKIP_H3/--no-h3"
    return
  fi

  if ! openssl_supports_quic; then
    warn "HTTP/3 OpenSSL smoke skipped; this OpenSSL does not expose s_client -quic"
    return
  fi

  read -r host port < <(parse_tls_host_port "$H3_URL") || die "could not parse H3 URL: $H3_URL"
  output="$TMP_DIR/openssl-h3.out"

  log "HTTP/3 OpenSSL QUIC smoke against $host:$port"
  status=0
  printf 'x' | run_with_timeout "$H3_TIMEOUT" \
    openssl s_client -quic -connect "${host}:${port}" -servername "$host" -alpn h3 -quiet \
    >"$output" 2>&1 || status=$?

  if grep -aq 'HTTP/3</h1>' "$output" && grep -aq 'Layerline' "$output"; then
    ok "HTTP/3 OpenSSL smoke fetched the native default page"
    return
  fi

  if [[ $H3_REQUIRED == 1 ]]; then
    die "HTTP/3 OpenSSL smoke failed with status $status: $(body_snippet "$output")"
  fi

  if grep -Eiq 'ALPN.*h3|Protocol.*TLSv1\.3|CONNECTION ESTABLISHED|verify return:1' "$output"; then
    warn "HTTP/3 OpenSSL smoke completed the handshake but did not see the default page; set LAYERLINE_H3_REQUIRED=1 to make this fatal: $(body_snippet "$output")"
    return
  fi

  warn "HTTP/3 OpenSSL smoke did not complete; set LAYERLINE_H3_REQUIRED=1 to make this fatal: $(body_snippet "$output")"
}

select_benchmark_tool() {
  local tool

  if [[ -n $BENCH_TOOL ]]; then
    case "$BENCH_TOOL" in
      oha | wrk | hey | ab) ;;
      *) die "unsupported benchmark tool '$BENCH_TOOL'; expected oha, wrk, hey, or ab" ;;
    esac
    require_command "$BENCH_TOOL"
    printf '%s\n' "$BENCH_TOOL"
    return
  fi

  for tool in oha wrk hey ab; do
    if command_exists "$tool"; then
      printf '%s\n' "$tool"
      return
    fi
  done

  die "no benchmark tool found; install oha, wrk, hey, or ab"
}

run_benchmark() {
  local tool=$1
  local name=$2
  local url=$3

  printf '\n'
  log "benchmark $name with $tool at concurrency $BENCH_CONNECTIONS: $url"

  case "$tool" in
    oha)
      oha -z "$BENCH_DURATION" -c "$BENCH_CONNECTIONS" "$url"
      ;;
    wrk)
      wrk -t "$BENCH_THREADS" -c "$BENCH_CONNECTIONS" -d "$BENCH_DURATION" "$url"
      ;;
    hey)
      hey -z "$BENCH_DURATION" -c "$BENCH_CONNECTIONS" "$url"
      ;;
    ab)
      if (( BENCH_REQUESTS < BENCH_CONNECTIONS )); then
        die "BENCH_REQUESTS ($BENCH_REQUESTS) must be >= BENCH_CONNECTIONS ($BENCH_CONNECTIONS) for ab"
      fi
      ab -k -n "$BENCH_REQUESTS" -c "$BENCH_CONNECTIONS" "$url"
      ;;
  esac
}

while (($#)); do
  case "$1" in
    --url)
      [[ $# -ge 2 ]] || die "--url requires a value"
      BASE_URL=$2
      shift 2
      ;;
    --h3-url)
      [[ $# -ge 2 ]] || die "--h3-url requires a value"
      H3_URL=$2
      shift 2
      ;;
    --duration)
      [[ $# -ge 2 ]] || die "--duration requires a value"
      BENCH_DURATION=$2
      shift 2
      ;;
    --connections | -c)
      [[ $# -ge 2 ]] || die "--connections requires a value"
      BENCH_CONNECTIONS=$2
      shift 2
      ;;
    --threads)
      [[ $# -ge 2 ]] || die "--threads requires a value"
      BENCH_THREADS=$2
      shift 2
      ;;
    --requests | -n)
      [[ $# -ge 2 ]] || die "--requests requires a value"
      BENCH_REQUESTS=$2
      shift 2
      ;;
    --tool)
      [[ $# -ge 2 ]] || die "--tool requires a value"
      BENCH_TOOL=$2
      shift 2
      ;;
    --verify-only)
      VERIFY_ONLY=1
      shift
      ;;
    --no-verify)
      SKIP_VERIFY=1
      shift
      ;;
    --no-h3)
      SKIP_H3=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

require_positive_int BENCH_CONNECTIONS "$BENCH_CONNECTIONS"
require_positive_int BENCH_THREADS "$BENCH_THREADS"
require_positive_int BENCH_REQUESTS "$BENCH_REQUESTS"
require_positive_int CURL_TIMEOUT "$CURL_TIMEOUT"
require_positive_int H3_TIMEOUT "$H3_TIMEOUT"

ROOT_URL=$(url_for_path "$BASE_URL" "$ROOT_PATH")
STATIC_URL=$(url_for_path "$BASE_URL" "$STATIC_PATH")
HEALTH_URL=$(url_for_path "$BASE_URL" "$HEALTH_PATH")

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/layerline-bench.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT

log "Layerline benchmark harness"
printf 'base_url=%s\n' "$BASE_URL"
printf 'root_url=%s\n' "$ROOT_URL"
printf 'static_url=%s\n' "$STATIC_URL"
printf 'health_url=%s\n' "$HEALTH_URL"
printf 'h3_url=%s\n' "$H3_URL"

if [[ $SKIP_VERIFY != 1 ]]; then
  run_http1_smoke
  run_h3_smoke
else
  warn "production smoke checks skipped by LAYERLINE_SKIP_VERIFY/--no-verify"
fi

if [[ $VERIFY_ONLY == 1 ]]; then
  exit 0
fi

BENCHMARK_TOOL=$(select_benchmark_tool)
log "selected benchmark tool: $BENCHMARK_TOOL"

run_benchmark "$BENCHMARK_TOOL" root "$ROOT_URL"
run_benchmark "$BENCHMARK_TOOL" static "$STATIC_URL"
run_benchmark "$BENCHMARK_TOOL" health "$HEALTH_URL"
