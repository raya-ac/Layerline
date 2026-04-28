# Layerline Benchmarking

This harness targets a running Layerline process. It does not build or start the
server, so it can be used against a local dev process, a staging host, or a
production origin behind a controlled test window.

Start Layerline separately, for example:

```bash
zig build run -- --config server.conf
```

Then run the benchmark:

```bash
./scripts/benchmark-layerline.sh
```

The default target is `http://127.0.0.1:8080`. Override it for another host:

```bash
LAYERLINE_URL=http://127.0.0.1:4000 ./scripts/benchmark-layerline.sh
```

For a larger run:

```bash
BENCH_DURATION=30s BENCH_CONNECTIONS=128 ./scripts/benchmark-layerline.sh
```

## What It Measures

The script first performs production smoke checks for the HTTP/1 endpoints:

- `GET /`
- `GET /static/hello.txt`
- `GET /health`

It then benchmarks those same endpoints using the first available tool in this
order: `oha`, `wrk`, `hey`, `ab`. The benchmark tool runs with keep-alive enabled
where the tool supports it; `ab` is invoked with `-k`. `oha`, `wrk`, and `hey`
use `BENCH_DURATION`; `ab` uses `BENCH_REQUESTS` because ApacheBench is
request-count oriented.

If OpenSSL exposes QUIC support through `openssl s_client -quic`, the harness
also attempts a best-effort HTTP/3 smoke against `LAYERLINE_H3_URL`, defaulting
to `https://127.0.0.1:8443/`. It writes a small stream payload and checks for
Layerline's native default-page response. This is still not a full HTTP/3 load
test. If the local OpenSSL build does not support QUIC, the check is reported as
skipped.

## Useful Knobs

```bash
LAYERLINE_URL=http://127.0.0.1:8080
LAYERLINE_ROOT_PATH=/
LAYERLINE_STATIC_PATH=/static/hello.txt
LAYERLINE_HEALTH_PATH=/health
LAYERLINE_H3_URL=https://127.0.0.1:8443/
LAYERLINE_H3_REQUIRED=1
BENCH_TOOL=wrk
BENCH_DURATION=10s
BENCH_CONNECTIONS=64
BENCH_THREADS=4
BENCH_REQUESTS=10000
```

Use smoke-only mode for deployment checks:

```bash
./scripts/benchmark-layerline.sh --verify-only
```

Skip the best-effort HTTP/3 probe when the native UDP listener is not expected
to be running:

```bash
./scripts/benchmark-layerline.sh --no-h3
```

Make the HTTP/3 smoke fatal when a release candidate is expected to have native
HTTP/3 enabled:

```bash
LAYERLINE_H3_REQUIRED=1 ./scripts/benchmark-layerline.sh --verify-only
```

## Reading Results

Treat the output as comparative data for the same machine, same server build,
same config, and same benchmark tool. The useful fields are requests per second,
latency distribution, non-2xx/3xx responses, socket errors, and transfer rate.
For production runs, keep the window short, record the exact command, and avoid
mixing results from different tools as if they were equivalent.
