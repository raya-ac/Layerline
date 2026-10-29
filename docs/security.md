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

This checks what the backend advertises; it does not probe third-party hosts,
inspect hidden PHP installations, or prove an undisclosed runtime is patched.
Some vendors backport fixes without changing the upstream version. Owners must
verify the exact package against their vendor advisory; a version string alone
cannot certify a backport. Upgrade and restart all relevant PHP workers.

## Admin access

The web UI remains disabled by default. Enabling it on a non-loopback listener
requires native TLS. First-account setup requires a random 256-bit local token,
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
stream or connection has no credit. Cache budgets now charge keys, headers and
entry metadata as well as bodies, and each cache has a 4096-entry ceiling.
These are live-data budgets, not exact process RSS limits.

Config snapshots have distinct cache generations. Until reader leases replace
raw config pointers, a process retains at most 32 snapshots including startup;
further reloads return `ReloadLimitRequiresRestart` without replacing the active
config. Plan a managed restart after 31 successful reloads. This bounds snapshot
count while preserving old connections; it is not automatic snapshot reclamation.

## Verification scope

`zig build test` includes the native guard, session lifecycle, cache accounting,
reload cap, and exposed-version checks. `scripts/verify-layerline.sh` exercises
wire-level HTTP/1 and HTTP/2, normal and abusive multipart fixtures, denial log
privacy, backend version notices, admin bootstrap/logout/origin behavior,
symlink escapes, encrypted static responses, and config reload.

HTTP/3 uses the shared request guard, but its external interoperability, QUIC
recovery/flow control, and configured certificate integration remain open. Do
not treat the shared guard or codec tests as production HTTP/3 acceptance.
