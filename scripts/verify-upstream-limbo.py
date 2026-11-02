#!/usr/bin/env python3
"""Evaluate the certificate-policy probe against an offline, pinned x509-limbo corpus."""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import time

REVISION = "1080e565f26e544bbe9cf99953be8a57c08e7e20"
CORPUS_SHA256 = "611e337b9fb477b927bae65434650692cb9d2070ff5b05f975d0403510acd4de"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("probe", type=Path)
parser.add_argument("corpus", type=Path)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--prefix", default="")
parser.add_argument("--time", type=int, default=int(time.time()), help="clock for fixtures without an explicit validation_time")
parser.add_argument("--security-only", action="store_true", help="fail on unexpected acceptance, retain every compatibility mismatch")
args = parser.parse_args()
probe, corpus = args.probe.resolve(strict=True), args.corpus.resolve(strict=True)
probe_hash = hashlib.sha256(probe.read_bytes()).hexdigest()
data = corpus.read_bytes()
assert hashlib.sha256(data).hexdigest() == CORPUS_SHA256, "unexpected corpus; do not execute or fetch repository scripts"
suite = json.loads(data)
assert suite["version"] == 1
results = []


def unsupported(case):
    if case["validation_kind"] != "SERVER":
        return "client-certificate validation"
    peer = case.get("expected_peer_name")
    if not peer or peer["kind"] not in ["DNS", "IP"]:
        return "no DNS/IP service identity"
    if "\0" in peer["value"]:
        return "NUL reference cannot be passed through argv"
    if len(case["trusted_certs"]) != 1:
        return "probe accepts exactly one explicit anchor"
    if len(case["untrusted_intermediates"]) >= 16:
        return "probe chain admission limit"
    if case["signature_algorithms"] or case["key_usage"] or case["expected_peer_names"]:
        return "custom signature, usage or multiple-identity policy"
    if case["extended_key_usage"] not in [[], ["serverAuth"]]:
        return "non-server EKU policy"
    if case.get("max_chain_depth") is not None:
        return "custom chain-depth policy"
    optional = set(case["features"]) & {"has-crl", "has-mldsa", "has-policy-constraints", "has-cert-policies",
                                         "no-cert-policies", "name-constraint-dn", "denial-of-service",
                                         "pedantic-public-suffix-wildcard", "pedantic-webpki-eku",
                                         "pedantic-webpki-subscriber-key", "rfc5280-incompatible-with-webpki"}
    optional |= set(case["features"]) & {"pedantic-rfc5280"}
    if optional:
        return "optional feature: " + ",".join(sorted(optional))
    return None


with tempfile.TemporaryDirectory(prefix="layerline-limbo-", dir="/tmp") as temporary:
    folder = Path(temporary)
    for case in suite["testcases"]:
        if not case["id"].startswith(args.prefix):
            continue
        result = {"id": case["id"], "expected": case["expected_result"]}
        if reason := unsupported(case):
            results.append({**result, "actual": "SKIPPED", "reason": reason})
            continue
        certificates = [*case["trusted_certs"], case["peer_certificate"], *case["untrusted_intermediates"]]
        paths = []
        for index, pem in enumerate(certificates):
            path = folder / f"certificate-{index}.der"
            path.write_bytes(ssl.PEM_cert_to_DER_cert(pem))
            paths.append(str(path))
        now = str(int(datetime.fromisoformat(case["validation_time"]).timestamp()) if case.get("validation_time") else args.time)
        command = [str(probe), "strict", case["expected_peer_name"]["value"], now, *paths]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        assert completed.returncode in [0, 1], (case["id"], "probe crashed", completed.returncode, completed.stderr)
        actual = "SUCCESS" if completed.returncode == 0 else "FAILURE"
        results.append({**result, "actual": actual, "detail": completed.stderr.strip()})
        if actual != result["expected"]:
            print(f"mismatch: {case['id']} expected={result['expected']} actual={actual} {completed.stderr.strip()}", flush=True)

skips = Counter(result["reason"] for result in results if result["actual"] == "SKIPPED")
mismatches = [result for result in results if result["actual"] not in ["SKIPPED", result["expected"]]]
false_accepts = [result for result in mismatches if result["actual"] == "SUCCESS"]
receipt = {"corpus_revision": REVISION, "corpus_sha256": CORPUS_SHA256,
           "probe_sha256": probe_hash, "prefix": args.prefix,
           "default_validation_time": args.time,
           "total": len(results), "skipped": sum(skips.values()), "skip_reasons": dict(skips),
           "mismatches": len(mismatches), "results": results,
           "unexpected_acceptances": len(false_accepts), "security_only": args.security_only,
           "scope": "offline certificate-policy evaluation; no HTTPS transport, complete PKIX, revocation or path-building claim"}
args.output.write_text(json.dumps(receipt, indent=2) + "\n")
assert hashlib.sha256(probe.read_bytes()).hexdigest() == probe_hash, "probe changed during verification"
print(f"evaluated={len(results) - sum(skips.values())} skipped={sum(skips.values())} mismatches={len(mismatches)}", flush=True)
assert results and len(results) > sum(skips.values()), "zero evaluated fixtures"
assert not (false_accepts if args.security_only else mismatches), f"independent certificate checks failed; inspect {args.output}"
