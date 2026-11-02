# upstream TLS work

HTTPS origins are **not enabled yet**. Both proxy paths and active health probes
still reject them with `UnsupportedUpstreamScheme`; there is no insecure fallback
to plaintext. TLS on the client-facing listener is a separate, existing feature.

The certificate policy and owned TLS channel are exercised by unit tests and
test-only executables. Neither probe is installed with Layerline or exposed as a
server command. The runtime does not import the new transport yet.

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
worker size. Raising a setting on reload cannot repair already-running workers;
runtime integration must enforce that boundary too.

`src/upstream_trust.zig` loads immutable PEM stores, bounded to 8 MiB, 1024
anchors and 128 KiB per certificate. An explicit store rejects unsupported or
malformed certificates. System PEM loading records the number of unusable DER
certificates skipped; malformed PEM framing still fails the entire load. This is
not full OS keychain integration. Linux uses fixed
distribution bundle paths and macOS uses `/etc/ssl/cert.pem`. No environment
variable can replace trust material, and a corrupt first-found bundle does not
silently select another source. Snapshot ownership and operator diagnostics are
still required before using this loader in the server.

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
failure cleanup. These are channel tests, not reverse-proxy, pool, concurrent
tunnel, reload or full TLS conformance acceptance.

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
These counts are test-bed evidence, not approval to enable an HTTPS transport.

## before enabling HTTPS origins

1. Finish the certificate profile and compatibility audit, including the retained
   independent-corpus differences and unsupported algorithms.
2. Integrate the tested channel, which authenticates the actual handshake's chain
   and leaf key, into both proxy paths and health probes. A separate certificate-
   preflight connection would not authenticate proxy traffic.
3. Load bounded trust material into configuration snapshots, with explicit SNI
   and hostname policy and no peer-controlled trust mutation or root downloads.
4. Carry the original backend deadline, cancellation and descriptor/heap ownership
   through handshakes, reads, writes, health probes, pools, reload and shutdown.
5. Cover TLS close-notify/truncation, session ownership, concurrent upgraded
   tunnels and key updates before adding encrypted sockets to the existing pool.
6. Exercise real adversarial HTTPS origins through both proxy paths on macOS and
   Linux, then pass the existing runtime and production rollout gates.

Identity and path checks follow the separate responsibilities described in
[RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html) and
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html). This work does not claim
complete conformance to either specification.
