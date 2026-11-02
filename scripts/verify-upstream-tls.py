#!/usr/bin/env python3
"""Exercise the owned TLS origin channel against disposable real TLS peers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("probe", type=Path)
parser.add_argument("--output", type=Path)
parser.add_argument("--tls13-suite", choices=["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"])
args = parser.parse_args()
if args.tls13_suite and os.environ.get("LAYERLINE_TEST_TLS_PROFILE") != args.tls13_suite:
    # Python has no public TLS 1.3 ciphersuite setter. Apply a private OpenSSL
    # profile before ssl is initialized in a child; never alter system config.
    with tempfile.TemporaryDirectory(prefix="layerline-tls-profile-", dir="/tmp") as profile:
        config = Path(profile) / "openssl.cnf"
        config.write_text("openssl_conf = init\n[init]\nssl_conf = ssl\n[ssl]\nsystem_default = origin\n[origin]\nCiphersuites = " + args.tls13_suite + "\n")
        environment = dict(os.environ, OPENSSL_CONF=str(config), LAYERLINE_TEST_TLS_PROFILE=args.tls13_suite)
        completed = subprocess.run([sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]], env=environment, timeout=120)
    sys.exit(completed.returncode)
probe = args.probe.resolve(strict=True)
probe_hash = hashlib.sha256(probe.read_bytes()).hexdigest()
results = []


class Origin:
    def __init__(self, cert, key, version, mode="fixed", fragment=65536):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = self.context.maximum_version = version
        if mode == "no-ccs":
            self.context.options &= ~ssl.OP_ENABLE_MIDDLEBOX_COMPAT
        if mode != "no-alpn":
            self.context.set_alpn_protocols(["h2", "http/1.1"])
        ciphers = {"aes256": "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
                   "chacha": "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"}
        if mode in ciphers:
            self.context.set_ciphers(ciphers[mode])
        if mode in ["p256", "p384"]:
            self.context.set_ecdh_curve("prime256v1" if mode == "p256" else "secp384r1")
        self.context.load_cert_chain(cert, key)
        self.sni, self.alpn, self.request, self.errors = [], [], b"", []
        self.ciphers = []
        self.fixture_failure = None
        self.context.set_servername_callback(lambda _, name, __: self.sni.append(name))
        self.mode, self.fragment = mode, fragment
        self.stopping = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def serve(self):
        try:
            while not self.stopping.is_set():
                try:
                    wire, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            with wire:
                wire.settimeout(.2)
                incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                connection = self.context.wrap_bio(incoming, outgoing, server_side=True)
                first_flight = True

                def mutate_hello(data):
                    assert data[0] == 22 and data[5] == 2, "fixture expected ServerHello"
                    length = int.from_bytes(data[3:5], "big")
                    message = data[5:5 + length]
                    body = bytearray(message[4:4 + int.from_bytes(message[1:4], "big")])
                    offset = 35 + body[34] + 3
                    size = int.from_bytes(body[offset:offset + 2], "big")
                    extensions, cursor = [], offset + 2
                    while cursor < offset + 2 + size:
                        n = int.from_bytes(body[cursor + 2:cursor + 4], "big")
                        extensions.append(bytes(body[cursor:cursor + 4 + n]))
                        cursor += 4 + n
                    if self.mode == "no-ems":
                        extensions = [e for e in extensions if e[:2] != b"\x00\x17"]
                    elif self.mode == "duplicate-version":
                        extensions.append(next(e for e in extensions if e[:2] == b"\x00\x2b"))
                    elif self.mode == "trailing-version":
                        extensions = [b"\x00\x2b\x00\x03\x03\x04\x00" if e[:2] == b"\x00\x2b" else e for e in extensions]
                    elif self.mode == "unsolicited-extension":
                        extensions.append(b"\xfe\xfe\x00\x00")
                    elif self.mode == "wrong-alpn":
                        extensions = [e for e in extensions if e[:2] != b"\x00\x10"]
                        extensions.append(b"\x00\x10\x00\x05\x00\x03\x02h2")
                    elif self.mode == "wrong-hello-version":
                        body[:2] = b"\x03\x01"
                    encoded = b"".join(extensions)
                    body = bytes(body[:offset]) + len(encoded).to_bytes(2, "big") + encoded
                    hello = b"\x02" + len(body).to_bytes(3, "big") + body
                    # A TLS 1.2 flight may contain later handshake messages in this record.
                    payload = hello + message[4 + int.from_bytes(message[1:4], "big"):]
                    return data[:3] + len(payload).to_bytes(2, "big") + payload + data[5 + length:]

                def flush():
                    nonlocal first_flight
                    while outgoing.pending:
                        data = outgoing.read()
                        if first_flight and self.mode == "early-ccs":
                            data = b"\x14\x03\x03\x00\x01\x01" + data
                        if first_flight and self.mode == "legacy-record-version":
                            data = data[:1] + b"\x03\x01" + data[3:]
                        if first_flight and self.mode in ["no-ems", "duplicate-version", "trailing-version", "unsolicited-extension", "wrong-alpn", "wrong-hello-version"]:
                            data = mutate_hello(data)
                        first_flight = False
                        for offset in range(0, len(data), self.fragment):
                            if self.stopping.is_set():
                                raise EOFError
                            wire.sendall(data[offset:offset + self.fragment])

                def receive():
                    while not self.stopping.is_set():
                        try:
                            data = wire.recv(65536)
                            if not data:
                                raise EOFError
                            incoming.write(data)
                            return
                        except socket.timeout:
                            continue
                    raise EOFError

                if self.mode == "stall-handshake":
                    self.stopping.wait(3)
                    return
                while True:
                    try:
                        connection.do_handshake()
                        self.alpn.append(connection.selected_alpn_protocol())
                        self.ciphers.append(connection.cipher()[0])
                        flush()
                        break
                    except ssl.SSLWantReadError:
                        flush()
                        receive()
                while b"\r\n\r\n" not in self.request:
                    try:
                        self.request += connection.read(65536)
                    except ssl.SSLWantReadError:
                        flush()
                        receive()
                malformed = {"short-record": b"\x17\x03\x03\x00\x00",
                             "huge-record": b"\x17\x03\x03\xff\xff",
                             "bad-record-version": b"\x17\x03\x01\x00\x11" + bytes(17),
                             "bad-record-type": b"\x16\x03\x03\x00\x11" + bytes(17)}
                if self.mode in malformed:
                    wire.sendall(malformed[self.mode])
                    return
                body = b"layerline origin transport\n" * 1024
                head = b"HTTP/1.1 200 OK\r\nConnection: close\r\n"
                if self.mode == "informational":
                    head = b"HTTP/1.1 103 Early Hints\r\nLink: </asset.css>; rel=preload\r\n\r\n" + head
                if self.mode not in ["eof", "truncated-eof"]:
                    head += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                connection.write(head + b"\r\n")
                flush()
                for offset in range(0, len(body), 4096):
                    if self.mode == "trickle-body" and self.stopping.wait(.08):
                        return
                    connection.write(body[offset:offset + 4096])
                    flush()
                if self.mode == "truncated-eof":
                    return
                try:
                    connection.unwrap()
                except ssl.SSLWantReadError:
                    pass
                flush()
        except (EOFError, OSError, ssl.SSLError) as error:
            self.errors.append(type(error).__name__ + ": " + str(error))
        except Exception as error:
            self.fixture_failure = repr(error)
        finally:
            self.listener.close()

    def close(self):
        self.stopping.set()
        self.thread.join(4)
        assert not self.thread.is_alive(), "TLS fixture did not terminate"
        assert self.fixture_failure is None, self.fixture_failure


with tempfile.TemporaryDirectory(prefix="layerline-origin-tls-", dir="/tmp") as temporary:
    folder = Path(temporary)

    def run(command):
        return subprocess.run(command, check=True, capture_output=True, timeout=20)

    def issue(label, issuer=None, ca=False, san="DNS:origin.example.test,IP:127.0.0.1,IP:::1", extensions=(), key_kind="p256"):
        key, csr, pem = (folder / (label + suffix) for suffix in [".key", ".csr", ".pem"])
        key_args = {"p256": ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
                    "p384": ["ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
                    "rsa": ["rsa:2048"], "ed25519": ["ed25519"]}[key_kind]
        run(["openssl", "req", "-new", "-newkey", *key_args, "-nodes",
             "-subj", "/CN=" + label, "-keyout", str(key), "-out", str(csr)])
        fields = ["basicConstraints=critical,CA:" + str(ca).upper(), "subjectKeyIdentifier=hash",
                  "keyUsage=critical," + ("keyCertSign,cRLSign" if ca else "digitalSignature")]
        if issuer:
            fields += ["authorityKeyIdentifier=keyid:always"]
        if not ca:
            fields += ["extendedKeyUsage=serverAuth"]
        if san is not None:
            fields += ["subjectAltName=" + san]
        fields += list(extensions)
        config = folder / (label + ".ext")
        config.write_text("\n".join(fields) + "\n")
        command = ["openssl", "x509", "-req", "-in", str(csr), "-sha256", "-days", "1", "-set_serial",
                   str(len(list(folder.glob("*.pem"))) + 1), "-extfile", str(config), "-out", str(pem)]
        command += ["-CA", str(issuer[0]), "-CAkey", str(issuer[1])] if issuer else ["-signkey", str(key)]
        run(command)
        return pem, key

    root = issue("root", ca=True)
    intermediate = issue("intermediate", root, ca=True)
    leaf = issue("leaf", intermediate)

    def check(label, certificate=leaf, chain=(intermediate,), anchor=root, peer="origin.example.test", version=ssl.TLSVersion.TLSv1_3,
              accept=True, mode="fixed", timeout=2000, fragment=65536, error=None, dial="127.0.0.1"):
        chain_file = folder / "served-chain.pem"
        chain_file.write_bytes(certificate[0].read_bytes() + b"".join(cert[0].read_bytes() for cert in chain))
        origin = Origin(str(chain_file), str(certificate[1]), version, mode, fragment)
        started = time.monotonic()
        try:
            completed = subprocess.run([str(probe), dial, str(origin.port), peer, str(anchor[0]), str(timeout)],
                                       capture_output=True, text=True, timeout=8)
            elapsed = time.monotonic() - started
        except subprocess.TimeoutExpired as failure:
            raise AssertionError(label, "probe exceeded outer watchdog", failure.stderr, origin.errors) from failure
        finally:
            origin.close()
        assert completed.returncode in [0, 1], (label, "crash", completed.returncode, completed.stderr)
        assert (completed.returncode == 0) == accept, (label, completed.stderr, origin.errors)
        if accept:
            expected = b"layerline origin transport\n" * 1024
            assert f"accepted status=200 bytes={len(expected)} sha256={hashlib.sha256(expected).hexdigest()}" in completed.stderr, (label, completed.stderr)
            assert origin.request.startswith(b"GET / HTTP/1.1\r\n"), (label, origin.request)
            expected_sni = None if peer in ["127.0.0.1", "::1"] else peer.rstrip(".")
            assert origin.sni == [expected_sni], (label, origin.sni)
            assert origin.alpn == [None if mode == "no-alpn" else "http/1.1"], (label, origin.alpn)
            if args.tls13_suite and version == ssl.TLSVersion.TLSv1_3:
                assert origin.ciphers == [args.tls13_suite], (label, "test profile not applied", origin.ciphers)
        else:
            assert "rejected:" in completed.stderr, (label, completed.stderr)
            if mode not in ["short-record", "huge-record", "bad-record-version", "bad-record-type", "trickle-body", "truncated-eof"]:
                assert not origin.request, (label, "sent application bytes to unauthenticated origin")
        if error:
            assert "rejected:" + error in completed.stderr, (label, completed.stderr)
        if mode in ["stall-handshake", "trickle-body"]:
            assert elapsed < 1.5, (label, "original backend budget was extended", elapsed)
        results.append({"case": label, "accepted": accept, "seconds": elapsed, "result": completed.stderr.strip(), "ciphers": origin.ciphers})
        print("ok: " + label, flush=True)

    for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
        for peer in ["origin.example.test", "ORIGIN.EXAMPLE.TEST.", "127.0.0.1", "::1"]:
            check(version.name + " " + peer, version=version, peer=peer)
        check(version.name + " fragmented TCP records", version=version, fragment=7)
        check(version.name + " unknown-length orderly close", version=version, mode="eof")
        check(version.name + " unknown-length truncation", version=version, mode="truncated-eof", accept=False, error="TlsConnectionTruncated")
        check(version.name + " body original deadline", version=version, mode="trickle-body", timeout=150, accept=False, error="RequestTimeout")
        check(version.name + " wrong identity", version=version, peer="wrong.example.test", accept=False, error="CertificateHostMismatch")
        check(version.name + " missing intermediate", version=version, chain=(), accept=False, error="CertificateUntrusted")
    other_root = issue("other-root", ca=True)
    check("TLS1.3 without optional compatibility CCS", mode="no-ccs")
    check("TLS1.3 early compatibility CCS", mode="early-ccs")
    check("TLS1.2 rejects an early CCS", mode="early-ccs", version=ssl.TLSVersion.TLSv1_2, accept=False, error="TlsUnexpectedMessage")
    check("TLS1.3 ignores the ServerHello record legacy version", mode="legacy-record-version")
    check("TLS1.2 checks the negotiated record version", mode="legacy-record-version", version=ssl.TLSVersion.TLSv1_2, accept=False, error="TlsIllegalParameter")
    check("HTTP1 origin without ALPN", mode="no-alpn")
    check("native hostname resolution retains the same TLS peer identity", dial="localhost")
    check("informational HTTP response over the authenticated channel", mode="informational")
    for kind in ["rsa", "p384", "ed25519"]:
        certificate = issue("leaf-" + kind, root, key_kind=kind)
        check("TLS1.3 " + kind + " proof of leaf key", certificate=certificate, chain=())
        if kind != "ed25519":
            check("TLS1.2 " + kind + " proof of leaf key", certificate=certificate, chain=(), version=ssl.TLSVersion.TLSv1_2)
    for mode in ["aes256", "chacha", "p256", "p384"]:
        check("TLS1.2 " + mode + " negotiated parameters", version=ssl.TLSVersion.TLSv1_2, mode=mode)
    check("TLS1.2 cannot fall back to the legacy master secret", version=ssl.TLSVersion.TLSv1_2, mode="no-ems", accept=False, error="TlsExtendedMasterSecretRequired")
    check("duplicate ServerHello version", mode="duplicate-version", accept=False, error="TlsIllegalParameter")
    check("trailing ServerHello version bytes", mode="trailing-version", accept=False, error="TlsDecodeError")
    for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
        check(version.name + " unsolicited ServerHello extension", version=version, mode="unsolicited-extension", accept=False, error="TlsUnsupportedExtension")
        check(version.name + " wrong ALPN", version=version, mode="wrong-alpn", accept=False, error="TlsIllegalParameter")
        check(version.name + " invalid ServerHello legacy version", version=version, mode="wrong-hello-version", accept=False, error="TlsIllegalParameter")
    check("untrusted CA", anchor=other_root, accept=False, error="CertificateUntrusted")
    impostor = issue("not-a-ca", root)
    forged = issue("forged-leaf", impostor)
    check("signed non-CA cannot authorize handshake", certificate=forged, chain=(impostor,), accept=False, error="CertificateUntrusted")
    common_only = issue("origin.example.test", root, san=None)
    check("common name is not handshake authentication", certificate=common_only, chain=(), accept=False, error="CertificateHostMismatch")
    constrained = issue("constrained", root, ca=True, extensions=("nameConstraints=critical,excluded;DNS:example.test",))
    check("name constraints authenticate the actual handshake", certificate=issue("constrained-leaf", constrained), chain=(constrained,), accept=False, error="CertificateUntrusted")
    client_only = issue("client-only", root, extensions=("extendedKeyUsage=clientAuth",))
    check("TLS peer requires server authentication usage", certificate=client_only, chain=(), accept=False, error="CertificateExtendedKeyUsage")
    oversized_extension = "1.2.3.4=DER:" + ":".join(["04", "83", "02", "00", "00"] + ["01"] * (128 * 1024))
    large_leaf = issue("oversized-leaf", root, extensions=(oversized_extension,))
    check("certificate byte limit applies during the real handshake", certificate=large_leaf, chain=(), accept=False, error="CertificateMalformed")
    fragmented_extension = "1.2.3.4=DER:" + ":".join(["04", "82", "50", "00"] + ["01"] * (20 * 1024))
    large_valid = issue("large-valid-leaf", root, extensions=(fragmented_extension,))
    for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
        check(version.name + " certificate across TLS records", certificate=large_valid, chain=(), version=version)
    check("short encrypted record is rejected without panic", mode="short-record", accept=False, error="TlsBadLength")
    check("oversized encrypted record", mode="huge-record", accept=False, error="TlsRecordOverflow")
    check("TLS1.3 legacy version remains authenticated", mode="bad-record-version", accept=False, error="TlsBadRecordMac")
    check("invalid TLS1.3 encrypted outer content type", mode="bad-record-type", accept=False, error="TlsUnexpectedMessage")
    check("handshake original deadline", mode="stall-handshake", timeout=100, accept=False, error="RequestTimeout")

assert hashlib.sha256(probe.read_bytes()).hexdigest() == probe_hash, "probe changed during gate"
receipt = {"probe_sha256": probe_hash, "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
           "python_ssl": ssl.OPENSSL_VERSION,
           "tls13_suite": args.tls13_suite,
           "openssl_cli": subprocess.run(["openssl", "version"], check=True, capture_output=True, text=True, timeout=5).stdout.strip(),
           "cases": results,
           "scope": "actual authenticated TLS origin channel; not yet reverse-proxy/config/pool/tunnel acceptance"}
if args.output:
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
print(f"ok: {len(results)} real TLS origin-channel cases", flush=True)
