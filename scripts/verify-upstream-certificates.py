#!/usr/bin/env python3
"""Issue disposable real chains and test the native upstream certificate policy."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("probe", type=Path)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
probe = args.probe.resolve(strict=True)
probe_hash = hashlib.sha256(probe.read_bytes()).hexdigest()
results = []


def run(command):
    return subprocess.run(command, check=True, capture_output=True, timeout=20)


with tempfile.TemporaryDirectory(prefix="layerline-pki-", dir="/tmp") as temporary:
    folder = Path(temporary)

    def issue(label, issuer=None, extensions=(), host="api.example.test", days=365, key_ids=True, key_kind="p256", digest="sha256", serial=None):
        key, csr, pem, der = (folder / (label + suffix) for suffix in [".key", ".csr", ".pem", ".der"])
        key_options = {"p256": ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
                       "p384": ["ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
                       "rsa": ["rsa:2048"], "weak-rsa": ["rsa:1024"], "ed25519": ["ed25519"]}[key_kind]
        run(["openssl", "req", "-new", "-newkey", *key_options, "-nodes",
             "-subj", "/CN=" + host, "-keyout", str(key), "-out", str(csr)])
        config = folder / (label + ".ext")
        # OpenSSL 3 auto-adds identifiers while 4 does not. Make deliberately
        # absent extensions explicit so the negative fixtures mean the same thing.
        identifiers = ["subjectKeyIdentifier=hash"] if key_ids else ["subjectKeyIdentifier=none", "authorityKeyIdentifier=none"]
        if key_ids and issuer:
            identifiers += ["authorityKeyIdentifier=keyid:always"]
        config.write_text("\n".join([*identifiers, *extensions]) + "\n")
        command = ["openssl", "x509", "-req", "-in", str(csr), "-days", str(days),
                   "-set_serial", str(serial if serial is not None else len(list(folder.glob("*.pem"))) + 1), "-extfile", str(config), "-out", str(pem)]
        if (issuer[3] if issuer else key_kind) != "ed25519":
            command += ["-" + digest]
        if issuer:
            command += ["-CA", str(issuer[0]), "-CAkey", str(issuer[1])]
        else:
            command += ["-signkey", str(key)]
        run(command)
        run(["openssl", "x509", "-in", str(pem), "-outform", "DER", "-out", str(der)])
        return pem, key, der, key_kind

    def check(label, chain, anchor, host="api.example.test", accept=True, primitive=False, now=None, error=None):
        command = [str(probe), "primitive" if primitive else "strict", host, str(now or int(time.time())),
                   str(anchor[2]), *[str(item[2]) for item in chain]]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        assert result.returncode in [0, 1], (label, "crashed", result.returncode, result.stderr)
        assert (result.returncode == 0) == accept, (label, result.returncode, result.stderr)
        assert ("accepted" if accept else "rejected:") in result.stderr, (label, result.stderr)
        if error:
            assert "rejected:" + error in result.stderr, (label, result.stderr)
        results.append({"case": label, "accepted": accept, "primitive_control": primitive, "result": result.stderr.strip()})
        print("ok: " + label, flush=True)

    ca = ["basicConstraints=critical,CA:true", "keyUsage=critical,keyCertSign,cRLSign"]
    leaf = ["basicConstraints=critical,CA:false", "keyUsage=critical,digitalSignature", "extendedKeyUsage=serverAuth",
            "subjectAltName=DNS:api.example.test,DNS:*.example.test,IP:127.0.0.1,IP:::1"]
    root = issue("root", extensions=ca, host="Layerline disposable root", days=3650)
    intermediate = issue("intermediate", root, ca + ["nameConstraints=critical,permitted;DNS:example.test,permitted;IP:127.0.0.0/255.0.0.0,permitted;IP:::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"], host="Layerline intermediate", days=1000)
    good = issue("good", intermediate, leaf)
    for host in ["api.example.test", "API.EXAMPLE.TEST.", "other.example.test", "127.0.0.1", "::1"]:
        check("valid chain " + host, [good, intermediate], root, host)
    for host in ["example.test", "a.b.example.test", "unrelated.test", "127.0.0.2", "::2"]:
        check("wrong identity " + host, [good, intermediate], root, host, accept=False)
    check("omitted trust anchor is not inferred", [good, intermediate], issue("other-root", extensions=ca, host="Other root"), accept=False)
    check("expired leaf", [good, intermediate], root, accept=False, now=int(time.time()) + 366 * 86400)
    check("not-yet-valid leaf", [good, intermediate], root, accept=False, now=int(time.time()) - 86400)

    nonca = issue("non-ca", root, ["basicConstraints=critical,CA:false", "keyUsage=critical,digitalSignature"], host="Not a CA")
    forged = issue("forged", nonca, leaf)
    check("signature-only control accepts non-CA signer", [forged, nonca], root, primitive=True)
    check("non-CA signer is unauthorized", [forged, nonca], root, accept=False)
    wrong_usage = issue("wrong-usage", root, ["basicConstraints=critical,CA:true", "keyUsage=critical,digitalSignature"], host="Wrong key usage")
    check("issuer keyCertSign is mandatory when constrained", [issue("wrong-usage-child", wrong_usage, leaf), wrong_usage], root, accept=False)
    wrong_eku = issue("wrong-eku", root, ca + ["extendedKeyUsage=clientAuth"], host="Client-only issuer")
    check("issuer EKU restricts TLS server authentication", [issue("wrong-eku-child", wrong_eku, leaf), wrong_eku], root, accept=False)
    check("leaf clientAuth is not serverAuth", [issue("client-only", root, [*leaf[:2], "extendedKeyUsage=clientAuth", leaf[3]])], root, accept=False)
    check("leaf encipherment is not signing", [issue("encipher-only", root, [leaf[0], "keyUsage=keyEncipherment", *leaf[2:]])], root, accept=False)
    check("common name is not a SAN", [issue("cn-only", root, leaf[:3])], root, accept=False)
    check("DNS text is not an IP SAN", [issue("dns-ip", root, [*leaf[:3], "subjectAltName=DNS:127.0.0.1"], host="127.0.0.1")], root, "127.0.0.1", accept=False)
    check("unknown critical extension", [issue("unknown-critical", root, leaf + ["1.2.3.4=critical,DER:05:00"])], root, accept=False)

    limited = issue("limited-root", extensions=["basicConstraints=critical,CA:true,pathlen:0", ca[1]], host="Limited root", days=3650)
    childca = issue("limited-intermediate", limited, ca, host="Excess intermediate")
    check("anchor path length is enforced", [issue("limited-leaf", childca, leaf), childca], limited, accept=False)
    outside = issue("outside", intermediate, [*leaf[:3], "subjectAltName=DNS:api.example.test,DNS:outside.test"])
    check("all SAN names obey permitted subtrees", [outside, intermediate], root, accept=False)
    excluded = issue("excluded-ca", root, ca + ["nameConstraints=critical,excluded;DNS:blocked.example.test"], host="Excluded subtree")
    check("wildcard cannot include an excluded name", [issue("excluded-wildcard", excluded, leaf), excluded], root, accept=False)
    ip_outside = issue("outside-ip", intermediate, [*leaf[:3], "subjectAltName=DNS:api.example.test,IP:192.0.2.1"])
    check("all IP SANs obey subnet constraints", [ip_outside, intermediate], root, accept=False)

    signing_roots = {}
    for kind in ["rsa", "p384", "ed25519"]:
        signing_root = issue(kind + "-root", extensions=ca, host=kind + " root", days=1000, key_kind=kind)
        signing_roots[kind] = signing_root
        child = issue(kind + "-leaf", signing_root, leaf, key_kind=kind)
        check(kind + " signing and public keys", [child], signing_root)
    check("RSA below 2048 bits is rejected", [issue("weak-key", root, leaf, key_kind="weak-rsa")], root, accept=False)
    check("SHA1 signatures are rejected", [issue("weak-signature", signing_roots["rsa"], leaf, digest="sha1")], signing_roots["rsa"], accept=False)
    no_ski = issue("no-ski", root, ca + ["authorityKeyIdentifier=keyid:always"], host="Missing SKI", key_ids=False)
    # A syntactically valid key identifier lets the child reach CA policy; the
    # intentionally broken issuer has no SKI for OpenSSL to copy automatically.
    child_ids = ["subjectKeyIdentifier=hash", "2.5.29.35=DER:30:16:80:14:" + ":".join(["01"] * 20)]
    check("CA subject key identifier is required", [issue("no-ski-child", no_ski, [*child_ids, *leaf], key_ids=False), no_ski], root, accept=False)
    no_aki = issue("no-aki", root, ["subjectKeyIdentifier=hash", *leaf], key_ids=False)
    check("non-anchor authority key identifier is required", [no_aki], root, accept=False)
    for critical in ["", "critical,"]:
        check("leaf cannot impose name constraints " + critical,
              [issue("leaf-nc-" + str(bool(critical)), root, leaf + ["nameConstraints=" + critical + "permitted;DNS:example.test"])], root, accept=False)
    check("empty AIA is malformed", [issue("empty-aia", root, leaf + ["1.3.6.1.5.5.7.1.1=DER:30:00"])], root, accept=False)
    check("AIA is validated but never fetched", [issue("aia", root, leaf + ["authorityInfoAccess=caIssuers;URI:http://127.0.0.1:1/not-fetched"])], root)
    unrelated = issue("unrelated-ca", root, ca, host="Unrelated CA")
    check("unordered issuer candidates", [good, unrelated, intermediate], root)
    unsupported = issue("unsupported-unrelated-ca", root, ca + ["1.2.3.4=critical,DER:05:00"], host="Unsupported unused CA")
    check("unsupported unused candidate does not poison a valid path", [good, unsupported, intermediate], root)
    loop = issue("loop", extensions=ca, host="Loop CA")
    check("cyclic candidates hit the signature work limit", [issue("loop-leaf", loop, leaf), *([loop] * 15)], root,
          accept=False, error="CertificateSearchLimit")
    zero_root = issue("zero-root", extensions=ca, host="Explicit legacy zero-serial root", serial=0)
    check("explicit legacy anchor does not need a positive serial", [issue("zero-root-leaf", zero_root, leaf)], zero_root)
    check("peer leaf serial zero is rejected", [issue("zero-leaf", root, leaf, serial=0)], root, accept=False)

    damaged = folder / "damaged.der"
    original = good[2].read_bytes()
    malformed = [b"", b"\x30", b"\x30\x80", b"\x30\x84\xff\xff\xff\xff", original + b"\0"]
    malformed += [original[:length] for length in [2, 3, 4, 8, 16, 32, 64, len(original) - 1]]
    malformed += [original[:-1] + bytes([original[-1] ^ 1]), original.replace(b"api.example.test", b"bad.example.test", 1)]
    for index, value in enumerate(malformed):
        damaged.write_bytes(value)
        check("malformed certificate " + str(index), [(None, None, damaged), intermediate], root, accept=False)
    for index in range(len(original)):
        corrupted = bytearray(original)
        corrupted[index] ^= 1
        damaged.write_bytes(corrupted)
        check("one-bit certificate corruption " + str(index), [(None, None, damaged), intermediate], root, accept=False)
    assert len(results) >= 50 + len(original)

assert hashlib.sha256(probe.read_bytes()).hexdigest() == probe_hash, "probe changed during verification"
receipt = {"probe_sha256": probe_hash, "cases": results,
           "scope": "upstream certificate-policy foundation; not wired HTTPS transport or complete PKIX/revocation acceptance"}
if args.output:
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
print(f"ok: {len(results)} real certificate-policy cases, including signature-only negative control", flush=True)
