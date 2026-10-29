# Security behavior

Layerline applies its native request guard before redirects, static files, PHP,
admin routes, caches, and proxy dispatch. HTTP/1 uses the same policy as the
buffered HTTP/2 and HTTP/3 router. There is no external WAF dependency.

## PHP2Shell

The guard rejects named PHP2Shell/CVE probes, including percent-encoded forms,
PHP runtime override headers, the default PHP session upload-progress marker,
and malformed or excessive multipart input. Multipart parsing requires an
unambiguous boundary, at most 128 parts, at most 32 headers per part, at most
8 KiB of part headers, and at most eight opening brackets in a field's
Content-Disposition. Empty file controls count as parts. Nested multipart and
encoded multipart bodies are rejected. Existing decoded body limits still
apply. Ordinary bounded uploads remain supported.

Blocked requests receive HTTP 403 and:

> Nice try. This is a web server, not a shell vending machine.

Security denials produce JSON `security.block` records even when access logging
is disabled. Each contains the rule, timestamp, method, protocol, status, and a
SHA-256 fingerprint of the path. It does not contain the body, cookies,
authorization, or raw query. The ordinary access record for a denied request
also redacts its path and query. With access logging enabled, the security
record goes to that sink; otherwise it goes to stderr/journald.

These request checks reduce exposure, but cannot repair PHP's allocator or
worker lifecycle. PHP's [OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
require patched PHP for complete mitigation. They describe application-dependent
paths as well as multipart triggers. A request filter cannot guarantee that
every exploit is recognizable from HTTP bytes.

## Exposed PHP versions

CGI, FastCGI, and ordinary HTTP proxy responses are checked for an affected
PHP version in `X-Powered-By` or `Server`. Layerline withholds that response and
returns HTTP 503 with an owner-facing update notice. The notice names the
reported version and minimum fixed releases: 8.2.35, 8.3.36, 8.4.27, and 8.5.12.
Older branches require migration. A structured `security.php_version` denial
is written to stderr/journald. The replacement response uses `Cache-Control:
no-store`.

Development, alpha, beta, and release-candidate builds at a minimum fixed
version are not accepted as proof of a patched release. Notices and log events
mark them as pre-releases; ordinary distribution package suffixes remain valid.

This checks what the backend advertises; it does not probe third-party hosts,
inspect hidden PHP installations, or prove an undisclosed runtime is patched.
Some vendors backport fixes without changing the upstream version. Owners must
verify the exact package against their vendor advisory; a version string alone
cannot certify a backport. Upgrade and restart all relevant PHP workers.

## Admin access

The web UI remains disabled by default. Enabling it on a non-loopback listener
requires native TLS. A primary listener with `tls = true` rejects plaintext
HTTP/1 and h2c before routing, including admin bootstrap. Forwarding headers do
not establish an encrypted transport. The separate HTTP redirect/ACME listener
remains HTTP-only. First-account setup requires a random 256-bit local token,
stored beside the configured credentials as `.<credentials-basename>.setup-token`
with mode 0600. Visiting the setup screen creates that file; read it locally or
over SSH and enter it into the setup form. It is removed after credentials are
created. Never publish the credentials directory.

Login creates an independent random session lasting eight hours. Sessions live
in a bounded in-memory store, bind to the credentials identity, expire, and are
revoked on logout. Restarting Layerline signs everyone out. The old persistent
credential seed is no longer accepted as a cookie. Cookies are HttpOnly,
SameSite=Strict, and Secure on TLS. POST actions reject foreign Origin headers
and same-site/cross-site browser fetch metadata. Non-browser clients without an
Origin still need valid authentication. A global budget of ten login attempts
per ten seconds bounds password-hash work.

HTTP/1 and native HTTP/2 share the same setup, authentication, and mutation
handlers. Admin replies always use `no-store`, `nosniff`, `DENY` framing, and
`no-referrer`; tenant response headers, custom error documents, compression,
and response caches do not apply. HEAD keeps the representation length without
sending its body. HTTP/2 Cookie fields are joined with `; ` before application
dispatch, as required by [RFC 9113 section 8.2.3](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.3).
This does not enable admin over the experimental HTTP/3 path.

Web-triggered reloads allocate published config snapshots independently of the
request arena. Snapshot metadata uses the store's allocator, while each owned
arena is released by its own allocator after workers have stopped. The existing
32-snapshot retention limit remains; this is not yet reader-lease reclamation.

The local Unix control socket accepts one newline-terminated command per
connection, at most 1023 bytes before the newline. It does not dispatch partial
reads or incomplete EOF input, and an absolute one-second read deadline bounds
fragmented commands. Extra lines are not executed. The CLI sends each command
with its newline in the same write buffer; command framing does not depend on
socket read boundaries.

## Files and memory

Static assets, precompressed sidecars, custom error documents, and ACME tokens
are opened beneath held directory handles. Child symlinks are rejected, and
reads use the validated handle instead of reopening a path. A configured root
itself may be a deployment symlink. Hidden files and PHP source are not served
as static assets. PHP diagnostic gating also checks the selected script name
when a route alias maps to `test.php`.

PHP/FastCGI ultimately executes a script by pathname in another process: keep
script directories owned by a trusted deployment user and isolate workers.
These checks do not sandbox a compromised PHP application or stop a local
writer from changing script contents. Public roots must contain ordinary files,
not devices or FIFOs. TLS responses always use the encrypted writer; Darwin
sendfile is restricted to plaintext streams.

HTTP/2 bounds active streams, queued response bodies, accumulated request bodies,
frame size, and header assembly. Its send windows stop DATA when either the
stream or connection has no credit. Stream and decoded-header limits are
advertised in SETTINGS. Header blocks are decoded even on refused/closed streams
to preserve HPACK state, after stripping padding and priority prefixes. Valid
request trailers may finish buffered uploads; optional trailer metadata is
validated and discarded, never merged into routing or authentication headers.
Pseudo-headers, framing/routing/authentication fields, and non-terminal trailers
reset only that stream. Decoded header bytes have the configured header budget,
including HPACK's 32-byte field accounting overhead. HPACK table-size updates
must precede fields, and literal lengths are checked before offset arithmetic.
DATA discarded on closed or rejected streams still restores connection credit.

HTTP/2 connection state, HPACK, request buffers, routing arenas, and queued output
share a 256 MiB allocator budget across connections. Routing admits at most eight
jobs per connection and 64 process-wide, including completed jobs awaiting
delivery; owned requests also have a 64 MiB per-connection ceiling. Exhausted
admission refuses the stream instead of starting more backend work. The gauges
`layerline_http2_routing_jobs`, `layerline_http2_memory_bytes`, and
`layerline_http2_memory_limit_bytes` expose this accounting. It excludes TLS
storage, caches, thread stacks, kernel buffers, and other protocols, so it is not
a full process memory or thread cap.

Cache budgets charge keys, headers and
entry metadata as well as bodies, and each cache has a 4096-entry ceiling.
These are live-data budgets, not exact process RSS limits.
The default connection gate is 1,024 sockets because the current runtime uses a
worker thread per connection. Explicit higher limits require a measured host
budget; this is not a process-wide heap/RSS cap.

Config snapshots have distinct cache generations. Until reader leases replace
raw config pointers, a process retains at most 32 snapshots including startup;
further reloads return `ReloadLimitRequiresRestart` without replacing the active
config. Plan a managed restart after 31 successful reloads. This bounds snapshot
count while preserving old connections; it is not automatic snapshot reclamation.

## Shutdown ownership

The server retains and joins background threads before freeing runtime state,
including the reload watcher, health checker, admin socket, QUIC listener, and
optional redirect and renewal workers. QUIC's receive loop checks for shutdown
between bounded receive waits. A locked connection registry interrupts idle
HTTP/1 and HTTP/2 reads without shutting down active uploads or response writes.
Workers unlink before closing sockets, so shutdown cannot target a reused file
descriptor. Connection workers close their stream and finish
metrics updates before publishing their final concurrency release.

The graceful shutdown timeout covers the whole worker drain. HTTP/2 sends GOAWAY,
refuses new streams, and lets existing uploads and flow-controlled responses
finish within that period. If a connection or background operation is still
stuck at the deadline, a separate guard logs `server.shutdown_timeout`, removes
the admin socket, and exits with status 1 without unwinding runtime destructors.
The OS then reclaims process memory together instead of freeing config/caches
while another thread might still access them. Outstanding requests can be lost
at that deadline. This is a process boundary, not cancellation of external PHP
or certificate-tool child processes; supervise and isolate those separately.

## Read Deadlines

On the verified macOS/Linux socket backends, read limits are absolute monotonic
budgets, not timers renewed by every byte. HTTP/1 headers and TLS negotiation
use `read_header_timeout_ms`; decoded request bodies, including chunk framing
and trailers, use `read_body_timeout_ms`. Keep-alive idle waits have a separate
`idle_timeout_ms` budget and transition to a fresh header budget on first input.

HTTP/2 bounds preface/initial SETTINGS waits, frame assembly, and the whole
HEADERS/CONTINUATION block. Each pending upload has its own absolute body
deadline. Expired uploads receive CANCEL resets without resetting healthy
streams. Partial frame bytes and partial TLS record headers/ciphertext survive
those interrupts. The frame reader reuses one bounded buffer per connection.
An expired framing/header budget closes the connection because its message
boundary can no longer be obtained within policy. Optional trailers do not
renew the upload deadline. Backend sockets never inherit a client read budget.

This does not add a process-wide RSS cap, QUIC request deadlines, or verified
Windows timeout enforcement. Upstream socket timeouts still apply; broader
resource/transport gates remain.

## Response Deadlines

HTTP/1 arms a fresh `write_timeout_ms` budget per response, beginning at its first
write attempt rather than while reading the request or waiting for backend
headers. Headers and body share that absolute monotonic deadline. Static files,
byte ranges, buffered responses, redirects, and error pages use it. Darwin's
plaintext sendfile path checks the same budget between bounded chunks, including
retryable zero-progress results. TLS continues through the encrypted writer.

A forwarded proxy body spends the remaining response budget while waiting for
the upstream as well as while writing to the client. This applies to fixed,
chunked, and close-delimited bodies, without extending a shorter upstream socket
timeout. Once any response write has started, upstream errors close the client
connection: they cannot trigger another attempt or append a second status line.
Only an upstream failure before visible response bytes can use failover.

Completed `100 Continue` responses leave a fresh budget for the final response;
keep-alive requests also get independent budgets. A successful Upgrade handshake
disarms the HTTP response budget before tunnel traffic begins. Tunnel socket
timeouts and the server's shutdown deadline still apply. If starting the second
tunnel pump fails, the first pump is interrupted and joined before its borrowed
TLS/config state can be freed.

`write_timeout_ms` is also an absolute transfer budget for each HTTP/2 response,
starting when the response is queued for sending. It covers output headers, DATA,
and time spent waiting for stream or connection flow-control credit. PINGs,
SETTINGS, and tiny WINDOW_UPDATE increments do not renew it. Increase this budget
deliberately for responses that need longer transfers.

An expired queued response releases its owned body and stream slot, receives
RST_STREAM CANCEL, and records `server.write_timeout` with phase `response` and
the stream ID. Other streams can continue. The frame reader includes these
deadlines in its next wait while preserving partially received frames and TLS
records. Backend sockets do not inherit a downstream response write budget.

Every raw write within an HTTP/2 response frame uses the remaining absolute budget,
including TLS record writes. A failed or timed-out frame write closes the whole
connection: another frame or GOAWAY cannot be appended after potentially partial
frame/record bytes. Wire timeouts log phase `wire`; HTTP/1 also identifies
`sendfile` and forwarded-body `upstream` waits. These events do not include
request paths, cookies, headers, or bodies.

Pre-response upstream operations and external PHP execution still have separate
limits, not an end-to-end application deadline. HTTP/2 backend routing runs in
bounded concurrent tasks; the connection thread alone owns frame parsing, HPACK,
TLS output, and response flow control. Completion wakes the reader without
requiring another client frame. A blocked backend therefore does not prevent
PING handling or expiry of another stream's upload/queued response. Idle expiry
pauses while work remains and starts afresh when the connection becomes idle;
partial-frame, upload, and response deadlines do not pause.

Reset streams suppress late replies but cannot undo backend side effects already
performed. Connection teardown cancels and joins routing tasks before releasing
their arenas, wake descriptors, or borrowed config/TLS state. Local cancellation
and allocation failure release upstream attempt leases without retrying or
ejecting a healthy target. This is not a fully evented socket scheduler:
downstream writes can still occupy the connection thread until their deadline.

## Verification scope

`zig build test` includes the native guard, session lifecycle, cache accounting,
reload cap, and exposed-version checks. Allocation-failure injection covers
HPACK table insertion and pending request cloning, including cleanup after every
failed allocation. `scripts/verify-layerline.sh` exercises
wire-level HTTP/1 and HTTP/2, normal and abusive multipart fixtures, denial log
privacy, backend version notices, admin bootstrap/logout/origin behavior,
symlink escapes, encrypted static responses, and config reload. The raw HTTP/2
tests include padded/split trailers, refused-stream HPACK synchronization,
compressed header budget bypass attempts, discarded DATA credit, and GOAWAY
error codes. Request trailer forwarding and response trailers are not implemented.

`scripts/verify-shutdown.py` starts isolated loopback instances with admin, QUIC,
health, and reload workers. It checks idle shutdown, in-flight HTTP/1 uploads,
HTTP/2 upload/response drain with new-stream refusal, and deadline expiry for
blocked request reads, zero-window responses, and blocked large-file writes.

To exercise an already-built release on its target OS without installing Zig,
run `LAYERLINE_VERIFY_BINARY=/absolute/path/to/layerline bash scripts/verify-layerline.sh`.
The verifier reports this explicitly and skips only compilation, not runtime checks.

`scripts/verify-deadlines.py` tests plain and TLS trickle headers, Content-Length
and chunked bodies, separate keep-alive timing, HTTP/2 upload expiry alongside
healthy streams, interrupted frame/TLS-record resumption, frame-byte trickles,
and aggregate continuation limits. Unit tests cover deadline rounding/socket
isolation and partial frame/record cleanup. Both scripts run in the main verifier.

`scripts/verify-h2-dispatch.py` holds a real backend request while testing PINGs,
healthy streams, upload/response expiry, idle rearming, and per-request log/header
isolation on plain and native TLS HTTP/2. It also covers h2c Upgrade dispatch,
eight-job admission, reset suppression, and disconnect cancellation with zero
remaining jobs/tracked HTTP/2 bytes. It runs in the main verifier too.

HTTP/3 uses the shared request guard, but its external interoperability, QUIC
recovery/flow control, and configured certificate integration remain open. Do
not treat the shared guard or codec tests as production HTTP/3 acceptance.
