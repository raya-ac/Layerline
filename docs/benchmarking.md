# benchmarking layerline

the script hits a server that's already running. it won't build or start one.
use a local or staging server unless you've set aside time to load test prod.

start the server first:

```bash
zig build run -- --config examples/local.conf
```

then run the benchmark:

```bash
./scripts/benchmark-layerline.sh
```

it defaults to `http://127.0.0.1:8080`. to test another address:

```bash
LAYERLINE_URL=http://127.0.0.1:4000 ./scripts/benchmark-layerline.sh
```

for a longer run with more connections:

```bash
BENCH_DURATION=30s BENCH_CONNECTIONS=128 ./scripts/benchmark-layerline.sh
```

## what it measures

it checks these over HTTP/1 first:

- `GET /`
- `GET /static/hello.txt`
- `GET /health`

then it benchmarks those URLs with the first tool it finds: `oha`, `wrk`,
`hey` or `ab`. it keeps connections open where it can and passes `-k` to
`ab`. `ab` uses `BENCH_REQUESTS`; the other three use `BENCH_DURATION`.

if `openssl s_client` has `-quic`, it also checks the default page at
`LAYERLINE_H3_URL` (`https://127.0.0.1:8443/` by default). that tells you
whether the page came back over HTTP/3. it isn't a load test. without QUIC
support the script reports a skip.

## settings

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

check the URLs without load testing:

```bash
./scripts/benchmark-layerline.sh --verify-only
```

skip HTTP/3 if the UDP listener is off:

```bash
./scripts/benchmark-layerline.sh --no-h3
```

fail the run if HTTP/3 is required but doesn't work:

```bash
LAYERLINE_H3_REQUIRED=1 ./scripts/benchmark-layerline.sh --verify-only
```

## slow HTTP/2 clients

this check starts its own loopback server and origin. it holds four 2 MiB replies
at 4 KiB of stream credit, checks memory and health, then lets the replies finish.
run more rounds on a candidate without pointing it at live traffic:

```bash
python3 scripts/verify-h2-proxy-pressure.py ./zig-out/bin/layerline --rounds 20
```

## reading results

keep the machine, config and tool the same when comparing builds. look at
latency and errors as well as requests per second; fast errors don't count as
an improvement. keep prod runs short and record the exact command.
