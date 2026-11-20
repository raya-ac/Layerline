# layerline roadmap

i want layerline to be the server i put in front of my sites. it already does
that for a real deployment. i wouldn't tell someone to swap out caddy or nginx
without checking what their sites actually need.

## what works now

- static sites, PHP through CGI or FastCGI, and HTTP/HTTPS reverse proxying.
  each domain can have its own config. limits, retry rules and cache settings can
  vary by route instead of forcing every site to use the same defaults.
- HTTP/1.1 and HTTP/2 share the main routing path. HTTP/2 has bounded streams,
  flow control, trailers and graceful drain. proxy bodies can stream to HTTP/2
  clients unless the route needs to buffer for cache, gzip or an error page.
  both client protocols can reuse HTTP/1.1 origin connections. HTTPS backends
  use TLS 1.2 or 1.3 with certificate checks.
- the TCP listener speaks TLS 1.3 and picks configured certificates by hostname.
  certbot can issue and renew certs. first-time webroot issuance still needs the
  challenge path to be reachable before Layerline starts.
- compatible config changes reload while old requests finish on the previous
  config. listener changes need a restart. the optional admin UI can add sites,
  stage edits, show diffs and run the same validation and reload as the local
  socket. it's off by default, including first-account setup.
- HTTP/3 can serve the homepage and health route to an independent curl client.
  it has buffered routing for other responses and can decode all 99 static QPACK
  entries plus Huffman literals. that isn't enough to put it on by default.

the [September audit](audit-2026-09-05.md) explains why the release gates exist.
the [security notes](security.md) cover the limits, failure behavior and wire
checks. [origin TLS](upstream-tls.md) has the certificate corpus results,
including what doesn't pass.

## what i'm doing first

1. close out the shutdown and pressure tests on Linux and macOS. A CI failure
   needs an explanation even if the next run passes. Linux CI uses the x86-64
   baseline CPU and a glibc 2.35 target for the units, server and test helper.
2. make releases repeatable. run a candidate off the live ports on the actual
   host, compare site behavior, then prove rollback with the real systemd unit.
   Test memory and descriptor pressure there too. A green CI run doesn't do
   those things. See the [replacement checklist](caddy-replacement-plan.md).
3. run a longer HTTP/2 proxy soak with slow clients and large bodies.
   loopback tests already cover early bytes, window credit, trailers, resets
   and no retry after final headers. expand the RFC 9113 checks too; h2spec
   alone doesn't cover the current spec.
4. close the TLS gaps: first-boot HTTP-01, unattended renewal checks, more TCP
   listener profiles and absolute handshake write budgets. The origin
   certificate corpus still has mismatches and skips.
5. finish the QUIC transport before calling HTTP/3 ready: configured certs, flow
   control, loss recovery, connection and stream lifetimes, and an independent
   client matrix for more than a small GET. Keep dynamic QPACK off until its
   memory and blocking behavior are tested.

## after that

- **proxying:** HTTP/2 and HTTP/3 to backends, CONNECT and extended CONNECT,
  signed affinity, more circuit breaker controls, and response interception.
  add header and path rewrites without trusting arbitrary forwarded headers.
- **static and cache:** directory indexes and MIME overrides, brotli and zstd,
  HTTP/1 microcache, disk cache, stale serving and request coalescing. check
  ranges and backpressure before adding any media transforms.
- **PHP:** better `try_files` chains, route-local environment, explicit handling
  of refused FastCGI multiplexing, and php-fpm tests under load.
- **TLS:** resumption, mTLS, OCSP and revocation policy; more ACME challenge
  options. listener key checks aren't a full PKIX or key-quality guarantee.
- **request policy:** route-local rate limits and auth, trusted proxies, more
  useful deny/allow rules and a way to report matches without blocking traffic.
  keep tokens and secret values out of config dumps and diagnostic output.
- **operations:** least privilege and tighter child-process containment,
  portable resource ceilings, systemd watchdog and socket activation, signed
  release packages, admin change history, richer upstream timing and H3 logs.

## things i'd like to build here

- compare two configs and replay a scrubbed request against the candidate before
  a reload. the config diff already exists; replay doesn't.
- a local page that shows which protocol was negotiated and why a request hit
  a route, a cache entry or an upstream. keep it opt-in.
- per-route CPU, allocations and upstream wait times. i'd rather make a slow
  site explain itself than ship a dashboard full of counters nobody reads.
- named policy bundles for common setups. a PHP app and a public fileserver
  shouldn't need the same hand-written limits copied into every site file.
- a local test setup for slow, reset and truncated upstream replies, with no
  effect on production traffic.

keep the server in Zig. when a tool is optional, call it optional. a demo,
a wire test and a deployment each prove different things.
