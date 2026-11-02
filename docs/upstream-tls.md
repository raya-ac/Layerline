# upstream TLS work

HTTPS origins are **not enabled yet**. Both proxy paths and active health probes
still reject them with `UnsupportedUpstreamScheme`; there is no insecure fallback
to plaintext. TLS on the client-facing listener is a separate, existing feature.

`src/upstream_certificate.zig` is a certificate-policy foundation, not a transport.
It is exercised by unit tests and a test-only executable that is neither installed
with Layerline nor exposed as a server command. The runtime does not import it.

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
```

The second target needs Python 3 and OpenSSL as developer tools. It generates
disposable keys inside a private temporary directory, removes them afterward, and
tests real valid/invalid chains, alternate paths, work-limit exhaustion and every
one-bit corruption of a generated leaf. Its signature-only negative control must
accept a non-CA signer that the real policy rejects. Keys never become fixtures.
These tools are not runtime dependencies.

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
2. Authenticate the actual handshake's chain and leaf key with this policy. A
   separate certificate-preflight connection would not authenticate proxy traffic.
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
