# upstream TLS work

HTTPS origins use authenticated TLS 1.2/1.3 in both reverse-proxy paths and active
health probes. The backend HTTP protocol is still HTTP/1.1, including when the
downstream client uses HTTP/2. There is no plaintext downgrade or insecure mode.
TLS on the client-facing listener is configured separately.

The certificate and channel probes remain developer-only executables, not server
commands. Source support and passing local tests are not a production deployment
receipt or a claim of complete TLS/PKIX conformance.

## configuration and ownership

```conf
proxy = https://origin.example.test:443/app
# Private CA and an explicit service identity when dialing an IP:
#proxy = https://192.0.2.10:8443/app tls_ca_file=/etc/layerline/roots.pem tls_server_name=origin.example.test
```

The same per-target options work in global, route, domain and domain-route pools,
alongside `weight`. Without `tls_ca_file`, the fixed system PEM bundle paths below
are used. An explicit file replaces system trust for that target. File paths are
relative to the process working directory unless absolute; paths cannot contain
whitespace. `tls_server_name` sets both verification identity and DNS SNI, not the
forwarded HTTP Host. Without it, the configured target host is verified. IP
identities use IP SANs and do not send DNS SNI. Options on HTTP targets are rejected.
The old `h2_upstream` setting is parsed for compatibility but does not route native
HTTP/2 traffic; use `proxy` or a named proxy route instead.

Startup, activation validation and reload preload immutable trust stores. A
startup trust failure happens before certificate helpers, ACME directory creation
or DNS API requests. Listener keys load after ACME can provision them. A
snapshot deduplicates stores by configured path and owns their decoded bytes until
its last request/health lease and idle TLS pool are gone. Changing a CA file on
disk does not mutate a running snapshot. Failed preflight leaves the working
configuration intact. Trust-load events record system/explicit source, anchor
count and unusable system certificates skipped, not private file contents.

HTTPS targets raise the worker stack minimum to 1 MiB, including route/domain
targets. Reload refuses any increase that existing workers cannot satisfy; restart
instead. Set `worker_stack_size = 1048576` at startup if adding the first HTTPS
target later must be reloadable. There are at most 32 simultaneous origin TLS
handshakes process-wide. Capacity or secure-entropy failure is local overload,
not evidence that an origin should be ejected.

Dialing, handshake and HTTP I/O share the original attempt deadline and
cancellation. HTTP/1 pools own the socket and TLS channel together; buffered input,
pending protocol state or readable idle sockets prevent reuse. This conservative
check may discard a connection with harmless pending session tickets too.
Eviction, failed requests, retirement and shutdown release the channel before its
socket. Upgraded tunnels bind the two independent TLS directions in both joined
pump threads and send encrypted close-notify before a TCP write-half-close.
The HTTP/2 proxy remains buffered and non-pooled; this work does not add backend
HTTP/2 ALPN or streaming final response bodies.

## channel implementation

`src/upstream_tls_client.zig` is derived from Zig 0.16.0's
`lib/std/crypto/tls/Client.zig`, under the unmodified license in
`licenses/zig-stdlib-MIT.txt`. The original source SHA-256 is
`1464bd0d53f799e7714fa073a0783cb94c68c10fb1ab4381246e01f9cb130c8a`.
This is a maintained Zig standard-library derivative, not a claim that Layerline
invented the underlying cryptography or has completed a TLS conformance audit.

The local changes authenticate the actual handshake's certificate chain and leaf
key with the bounded policy below. There is no insecure verification option,
self-signed fallback, root download, or plaintext downgrade. Initialization
rejects secret logging and the inherited truncation-bypass option.
The HTTP origin channel offers only `http/1.1` through ALPN; an absent ALPN reply
is allowed, a different selected protocol is not. TLS 1.2 requires the extended
master secret extension and ECDHE with authenticated AEAD ciphers. TLS 1.3
offers AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, not experimental AEGIS
ciphers. Its handshakes do not depend on the optional compatibility
ChangeCipherSpec record.
They ignore early compatibility CCS and legacy record-version values as required
by [RFC 8446 section 5](https://www.rfc-editor.org/rfc/rfc8446.html#section-5),
without omitting those header bytes from encrypted-record authentication.

Other patches bound certificate/handshake reassembly, validate negotiation and
record lengths, retain fragmented post-handshake messages, prevent sequence
wrap, and preserve writes larger than one output buffer. Requested key-update
replies use the old write keys before rotation, sharing a write lock with tunnel
traffic without serializing a blocked read against an ordinary write. Tickets
are ignored rather than cached for resumption. Channel destruction wipes owned
traffic state, and the handshake wipes its key-share and cipher scratch.

`src/upstream_tls.zig` owns the encrypted and plaintext buffers, preserves raw
I/O errors and the original deadline, and treats missing close-notify as
truncation. Its socket belongs to the caller, not the channel. Both tunnel pumps
must join before destroying it. Callers need a 1 MiB handshake stack floor:
the real Debug probe exposed a stack overflow at the ordinary 256 KiB request
worker size. The runtime enforces that floor and the restart-only growth boundary.

`src/upstream_trust.zig` loads immutable PEM stores, bounded to 8 MiB, 1024
anchors and 128 KiB per certificate. An explicit store rejects unsupported or
malformed certificates. System PEM loading records the number of unusable DER
certificates skipped; malformed PEM framing still fails the entire load. This is
not full OS keychain integration. Linux uses fixed
distribution bundle paths and macOS uses `/etc/ssl/cert.pem`. No environment
variable can replace trust material, and a corrupt first-found bundle does not
silently select another source. Temporary PEM input is wiped after decoding;
configured trust anchors themselves contain public certificates, not private keys.

## what is covered

- Bounds-checked DER framing before using Zig's existing signature primitives.
  No new RSA, ECDSA, Ed25519 or TLS cryptography is implemented here.
- SAN-only DNS and binary IPv4/IPv6 service identities, one-label wildcards, and
  no common-name fallback. Names later in the SAN list are validated too.
- Calendar validity with the correct UTCTime century boundary and real dates.
- CA authorization, critical basic constraints, key usage, server EKU, CA path
  lengths, and DNS/IP name constraints across all presented names in the path.
- Duplicate extensions and unsupported critical policies are rejected. DNS
  constraints use DNS names, not leading-dot URI constraint syntax. OtherName
  constraints are a no-op only when no matching name type occurs; otherwise they
  fail closed. AIA is structurally checked but never fetched.
- Immutable explicit anchors and bounded alternate-chain search: at most 16 peer
  certificates, 1024 anchors, 128 KiB per certificate and 64 signature checks.
  Unused, unsupported intermediate candidates do not poison a valid path or gain
  trust. An explicit legacy anchor may have serial zero; untrusted peers may not.

This is deliberately narrower than a complete PKIX implementation. RSA-PSS
certificate algorithms, P-521, certificate policy processing, general directory/
URI/email name constraints, revocation and Certificate Transparency are not
implemented. Unsupported required policies fail closed. It is not a browser root
program or a public-CA issuance linter: matching common names against SANs and
auditing an anchor's own AKI are not service-identity verification.

## checking it

```sh
zig build test
zig build test-upstream-certificates -Doptimize=Debug
zig build test-upstream-certificates -Doptimize=ReleaseSafe
zig build test-upstream-tls -Doptimize=Debug
zig build test-upstream-tls -Doptimize=ReleaseSafe
zig build test-https-upstreams -Doptimize=Debug
zig build test-https-upstreams -Doptimize=ReleaseSafe
```

The second target needs Python 3 and OpenSSL as developer tools. It generates
disposable keys inside a private temporary directory, removes them afterward, and
tests real valid/invalid chains, alternate paths, work-limit exhaustion and every
one-bit corruption of a generated leaf. Its signature-only negative control must
accept a non-CA signer that the real policy rejects. Keys never become fixtures.
These tools are not runtime dependencies.

The TLS target uses Python's SSL MemoryBIO as a real independent peer, disposable
OpenSSL certificates, and a probe on a 1 MiB worker stack. Its 59 cases cover
TLS 1.2/1.3, RSA/ECDSA/Ed25519 leaf-key proof, DNS/IP identities, certificate and
TCP fragmentation, AES-GCM/ChaCha20, P-256/P-384 exchange, ALPN and extended-master-
secret negotiation, unauthenticated-origin refusal, malformed records, HTTP
informational replies, close-notify/truncation and original handshake/body
deadlines. It asserts that authentication failures send no HTTP request bytes.
The build target repeats those cases under three forced TLS 1.3 cipher profiles
(177 cases per build mode). A private temporary OpenSSL configuration in a child
process works around Python's missing public TLS 1.3 ciphersuite setter; each
positive case checks the actually negotiated cipher. No system configuration is
changed. Optional `--output` receipts include binary/script hashes and SSL versions.
Unit tests separately exercise fragmented key updates, correct reply-key order,
sequence exhaustion, record/body bounds, large writes, and trust allocation
failure cleanup. Invalid KeyUpdate lengths fail with `TlsDecodeError` before
rotation or a reply, including split headers and declarations above the general
handshake limit. Invalid request values remain `TlsIllegalParameter`. These are
channel tests, not reverse-proxy, pool, concurrent
tunnel, reload or full TLS conformance acceptance.

The separate HTTPS integration target (also in `verify-layerline.sh`) runs the
actual server against disposable TLS origins. It covers both origin versions,
plain/native-TLS H1/H2 clients, certificate refusal before any HTTP bytes, framing,
pool reuse/poisoning, health probes, original deadlines, scoped targets and the
restart-only stack boundary. Real worker tests include RSA, P-384, Ed25519 and
certificates larger than a record; the native listener also sends a fragmented
large Certificate message. Tunnels exercise prefetched bytes, bidirectional
traffic, TLS half-close and requested origin key rotations. OpenSSL's
[documented K command](https://docs.openssl.org/3.5/man1/openssl-s_server/#connected-commands)
requests rotation; its independent trace must show each authenticated reply.
Reset/disconnect tests join stalled handshakes/body reads without peer ejection.
Reload tests retain old H2 leases across root changes, delete an old CA file to
prove immutable ownership, reject failed preflight and verify final reclamation.
Optional JSON receipts hash the server, fixture and raw H2 helper. These selected
wire cases are not a TLS or HTTP/2 conformance suite.

Each traffic key is limited to 2^20 records in either direction. Exceeding that
budget closes the channel, rather than relying only on sequence-number wrap;
see the [AEAD usage limits in RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.5).
Peer key updates reset the corresponding counter. Proactive local key updates,
HelloRetryRequest, session resumption and client-certificate authentication are
not implemented in this channel.

`scripts/verify-upstream-limbo.py` evaluates a separately obtained, pinned
[x509-limbo corpus](https://github.com/C2SP/x509-limbo/tree/1080e565f26e544bbe9cf99953be8a57c08e7e20).
It verifies the corpus hash, executes no upstream scripts, retains raw mismatches
and records every skipped feature. The default gate fails on any mismatch.
`--security-only` allows unexpected rejections but still fails on unexpected
acceptances; it does not turn those rejections into compatibility passes.
The entire corpus is **not passing**: generic-PKIX targets without TLS signing
usage, conflicting name-constraint criticality profiles and public-CA issuance
rules remain visible differences. Do not describe a selected subset as a full
corpus pass. The checked-in harness does not download data or install anything.

The current pinned macOS Debug and Linux ReleaseSafe evaluation checks 9709
cases, skips 93 with recorded reasons, and retains 16 raw mismatches: 13
acceptances against public-CA issuance expectations and three conservative
rejections. The latter are two generic CA targets without TLS signing usage and
the non-critical name-constraints profile that conflicts with the RFC test.
The thirteen acceptances are public-CA issuance-lint differences, not a bypass of
chain signatures or SAN identity. They are retained rather than reclassified as a
green full-corpus result. Unsupported algorithms and the three conservative
rejections remain interoperability gaps.

## remaining boundaries

Wider independent certificate/TLS conformance, unsupported policy/algorithm
coverage, revocation, resumption, mTLS, proactive origin key updates, backend
HTTP/2/3 and streaming H2 responses remain work. The native client-facing TLS
server has a narrower cipher/group profile, but now supports fragmented TLS 1.3
KeyUpdate, proactive output rotation and requests for peer rotation. Its separate
`zig build test-native-tls` fixture uses an independent, certificate-verifying
OpenSSL client over HTTP/1.1 and HTTP/2, including split HTTP/2 frames and normal
authenticated shutdown. This is selected interoperability evidence, not complete
TLS conformance. Both channels retain their hard per-key record cap. Runtime
changes must pass native/Linux regression and the candidate, rollback and
live-route gates before deployment.

Identity and path checks follow the separate responsibilities described in
[RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html) and
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html). This work does not claim
complete conformance to either specification.
