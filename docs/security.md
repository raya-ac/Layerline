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
arena is released by its own allocator. Connection and background-reader leases
keep published arenas alive only until their final reader exits. Admin requests
recheck the current enablement, path and credentials even on a connection opened
before a reload.

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

Config snapshots have distinct cache generations. Retired reload arenas and
their HTTP idle pools are reclaimed after their final connection/background
reader exits, including joined HTTP/2 routing jobs. The shared FastCGI pool owns
its endpoint keys independently of these arenas. At most 32 generations may be
live or undergoing cleanup at once; `TooManyLiveConfigGenerations` rejects a
reload without changing the active config until old readers drain. This is not
a lifetime reload limit. Stale concurrent builders cannot overwrite a newer
publication. Metrics expose the current generation, retained snapshot count,
reader count and owned reload-arena capacity; the process-owned boot config and
separately allocated pool storage are excluded from the arena-byte gauge.

Health checks acquire the current config each cycle and follow each pool's own
interval, including checks enabled by reload. Certificate renewal also reads
current policy, releases its lease before sleeping and reloads TLS material after
renewal. Unrelated config reloads do not postpone scheduled renewal. External
certificate-tool execution still lacks an independently enforced child deadline.

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
timeout. A response-controlled read timeout is logged even if a coarse socket
timer fires before the next exact clock sample; a shorter backend budget is not
relabeled as a response timeout. Once the final response has started, upstream
errors close the client
connection: they cannot trigger another attempt or append a second status line.
Only an upstream failure before final response bytes can use failover, subject
to the request's retry policy. A completed informational reply is not a final
response and never extends the original backend attempt budget.

Completed informational responses leave a fresh budget for the final response;
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

HTTP/2 backend routing runs in
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

## Backend deadlines

`upstream_timeout_ms` and its domain/route overrides now bound a complete proxy
attempt: dialing, request writes, and response reads share one monotonic budget.
FastCGI uses the same mechanism, including TCP and Unix sockets, PARAMS/STDIN
writes, record headers, and output reads. Health probes use their own configured
budget. Bytes arriving periodically do not renew these clocks. Validated backend
timeout policies must be positive; zero is rejected by configuration validation.

Dialing races an owned IO task against the deadline and cancels/joins it before
returning; even a successful late connection is closed. Linux uses Zig's
cancellable resolver. Darwin's libc resolver can delay cancellation while inside
`getaddrinfo`, so a hard DNS deadline there is not yet guaranteed. This is not a
full end-to-end application execution deadline on every platform/path.

## Child Processes

On Linux and macOS, CGI uses the selected `upstream_timeout_ms` budget for child
launch, request input, stdout/stderr capture, and process exit. The pipes are
pumped together, so a worker writing output before reading stdin cannot deadlock
the request. Periodic output does not renew the deadline. Positive global,
domain, and route timeout policies are honored.
CGI output is bounded by `max_php_output_bytes`; stderr has a separate 64 KiB cap.
Timeouts return 504, output/exec failures return 502, and local process/descriptor
or allocation exhaustion returns 503 before response output.

CGI, certificate, and DNS helper commands share a 64-child process-wide admission
limit, held through cleanup. Layerline owns each PID immediately after fork,
including failed execs, rather than relying on the standard spawn error path.
Only prebuilt arguments/environment and async-signal-safe syscalls run in the
fork child. A close-on-exec status pipe reports launch failure to the parent.
Launch serialization prevents another command from inheriting a partially
configured Darwin pipe. Normal completion and failure close all parent endpoints
and reap the direct child. Remaining members of the child's process group receive
SIGKILL; a SIGTERM-ignoring child cannot turn cleanup into an indefinite wait.
The leader stays unreaped until group signaling is complete, avoiding PID reuse
races. The shutdown registry uses the same ownership lock when signaling/reaping.

Certificate commands use the positive `external_command_timeout_ms` setting,
defaulting to 300000 ms. DNS/public-IP helpers use the lesser of that value and
30000 ms. Setup failure exits nonzero. Setup and renewal observe shutdown;
CGI gets its normal drain window, with remaining child work canceled 100 ms
before the configured forced-exit deadline to allow joined cleanup. The final
shutdown guard also signals registered children before exiting. Raw helper output
is not logged. CGI diagnostics report byte counts, not their contents, and the
Cloudflare child receives its authorization header through stdin instead of argv.
Keep credentials in a private config rather than the owner's command line too.

These are process-lifetime controls, not a sandbox or a hard kernel scheduling
guarantee. Trusted scripts can change groups/credentials or delegate work to
another service; that work is outside this process-group ownership. Uninterruptible
kernel operations can delay reaping. CGI still runs with the server's identity
and configured environment. Use an isolated PHP-FPM service for untrusted code.
Native HTTP/2 PHP currently requires FastCGI, and Windows child lifetime handling
has not been accepted.

## RSA Signing

RSA TLS signing uses joined, separately sized worker stacks instead of the small
connection stack. At most eight signers run at once, each with a 512 KiB stack;
excess handshakes fail admission. This bounds the extra signing workspace without
enlarging every connection stack. It is not a full TLS/process memory budget.

## Backend Failures

Local dial task/descriptor exhaustion returns 503 without retries or passive
backend ejection. Active probes skip results caused by local capacity/allocation
failure or cancellation instead of marking the target unhealthy. A private
`server.backend_capacity` event records the connect phase. Fault-injection tests
cover first/second task launch failure, late socket cleanup, and health counters.

Each permitted retry receives a fresh attempt budget, within the configured
attempt limit. Automatic retries are restricted to known idempotent methods
(GET, HEAD, OPTIONS, TRACE, PUT, DELETE), following
[RFC 9110 section 9.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2).
POST, PATCH, CONNECT, and unknown methods are never automatically replayed.
Already-started HTTP/1 replies still close without retries or a second status
line. Their total elapsed budget includes downstream forwarding time; timeout
closure after output starts does not count as passive backend failure, since
slow clients can consume that time too. Other backend failures and pre-response
timeouts retain passive failure accounting.

Buffered proxy requests remove `Expect` before forwarding: Layerline has already
handled `100-continue` and received the client's body. This avoids soliciting a
second interim response from the backend after the upload is complete.

Buffered HTTP/2 and FastCGI timeouts return 504 before response output. FastCGI
transport/protocol failures return 502 and discard the connection, rather than
turning a stale worker socket into an internal 500. Reused connections start a
fresh budget. A successful HTTP/1 Upgrade handshake disarms the attempt deadline
before tunnel traffic begins; normal tunnel idle/shutdown rules still apply.
`server.backend_timeout` events identify `connect`, `read`, `write`, or `cgi`, not
request paths, query strings, headers, bodies, or credentials.

## Verification scope

`zig build test` includes the native guard, session lifecycle, cache accounting,
reload cap, and exposed-version checks. Allocation-failure injection covers
HPACK table insertion and pending request cloning, including cleanup after every
failed allocation, plus native child capture/launch allocations and output cleanup.
`scripts/verify-layerline.sh` exercises
wire-level HTTP/1 and HTTP/2, normal and abusive multipart fixtures, denial log
privacy, backend version notices, admin bootstrap/logout/origin behavior,
symlink escapes, encrypted static responses, and config reload. The raw HTTP/2
tests include padded/split trailers, refused-stream HPACK synchronization,
compressed header budget bypass attempts, discarded DATA credit, and GOAWAY
error codes. Request trailer forwarding is still not implemented; validated
request trailers remain separate from routing/authentication headers.

Proxy responses now share a bounded upstream reader. Fixed-length, chunked,
HEAD, 204 and 304 replies finish at their message boundary without waiting for
origin EOF. Close-delimited bodies still require EOF. Reader buffers live in
request-owned storage rather than large worker-stack objects. Heads are limited to
16 KiB each, 64 KiB total and at most 16 informational replies before the final
response. Status syntax, chunk sizes/extensions, CRLF, the complete chunk
terminator and trailers are validated; premature EOF does not complete a body.
Trailers have a 16 KiB / 100-field budget with 4 KiB lines. Framing, routing,
authentication and response-control trailer fields are rejected. Layerline also
rejects backend version fields (`Server`, `X-Powered-By`) in trailers, so they
cannot bypass the header-phase PHP version policy. If a streamed HTTP/1 body
is already visible, a late trailer failure aborts it without a second response.

Connection-nominated fields are removed across repeated `Connection` headers,
case-insensitively, from forwarded request/response fields and response trailers.
`Proxy-Connection`, `Trailer` and other fixed hop fields are also removed. HTTP/1
regenerates framing for the bytes it actually sends. Valid empty end-to-end fields
are preserved in both proxy paths and in response trailers. Upgrade responses must
select an offered protocol and carry a valid Upgrade handshake; ordinary proxy
requests cannot switch protocols unexpectedly. HTTP/2 rejects SP/HTAB at either
edge of request and trailer values rather than trimming malformed input, following
[RFC 9113 section 8.2.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.1).

Informational replies other than locally handled 100 Continue are forwarded before
the final response. HTTP/2 routing tasks publish them to the connection thread
through a per-job queue capped at 16 blocks / 128 KiB, charged to its shared HTTP/2
allocator. Cancellation, connection teardown and allocation failure reclaim queued
blocks. The connection thread remains the only frame/TLS writer; each informational
write has its own write budget and does not spend the final body-transfer budget.
This does not make the final HTTP/2 upstream body streaming: that body is still
buffered within its configured limit before final headers are sent.

Valid response trailers remain separate from headers. HTTP/1 rechunks payloads
and forwards scrubbed trailers only after validation; native HTTP/2 queues an
owned trailing HEADERS block after DATA, ending the stream there. Trailers do not
consume flow credit, but cannot overtake unsent DATA. Reset/expiry cleanup charges
and frees both body and trailer buffers. Responses with trailers bypass the current
microcache and recompression so metadata is not silently discarded or invalidated.
HEAD/304 retain known representation lengths without reading nonexistent bodies;
an unknown upstream HEAD length stays absent rather than becoming a false zero.
The experimental HTTP/3 buffered encoder also retains known/unknown lengths and
encodes informational, final, DATA and trailer sections in order. These are
codec/allocation checks, not external QUIC interoperability or live early-hint
streaming guarantees.
`scripts/verify-upstream-framing.py` checks these paths over plain and native TLS.

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

`scripts/verify-backend-deadlines.py` covers trickling headers and fixed/chunked/
close-delimited bodies, shared header/body timing, blocked upstream request
writes, FastCGI record-header/output trickles over TCP and Unix sockets, stale
FastCGI failure/recovery, fresh pooled budgets, safe GET fallback, non-replayed
POSTs, and tunnel lifetimes. It checks plain and native TLS HTTP/1 and HTTP/2 and
runs in the main verifier. Unit tests cover joined dial cancellation, late socket
cleanup, deadline scoping, and the method retry gate.

HTTP/3 uses the shared request guard, but its external interoperability, QUIC
recovery/flow control, and configured certificate integration remain open. Do
not treat the shared guard or codec tests as production HTTP/3 acceptance.
