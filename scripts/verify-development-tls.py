#!/usr/bin/env python3
"""Exercise bounded development TLS identities without changing configured keys."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", type=Path)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
binary = args.binary.resolve(strict=True)
binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
fixture_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
if args.output:
    args.output.unlink(missing_ok=True)
results = []


def wait(check, label, timeout=6):
    until = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < until, label
        time.sleep(.01)


with tempfile.TemporaryDirectory(prefix="layerline-development-tls-", dir="/tmp") as temporary:
    folder = Path(temporary)
    cert, key = folder / "cert.pem", folder / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-days", "1", "-subj", "/CN=configured.test", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True, timeout=15)
    expected = ssl.PEM_cert_to_DER_cert(cert.read_text())
    domains = folder / "domains"
    domains.mkdir()
    (domains / "configured.conf").write_text(f"server_name = configured.test\ntls_cert = {cert}\ntls_key = {key}\n")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config, log = folder / "server.conf", folder / "server.log"
    config.write_text(f"""host = 127.0.0.1
port = {port}
tls = true
http3 = false
admin = false
admin_ui = false
read_header_timeout_ms = 5000
idle_timeout_ms = 10000
graceful_shutdown_timeout_ms = 1500
domain_config_dir = {domains}
""")

    def connect(name):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["http/1.1"])
        raw = socket.create_connection(("127.0.0.1", port), timeout=6)
        try:
            return context.wrap_socket(raw, server_hostname=name)
        except BaseException:
            raw.close()
            raise

    def health(peer, name, close=True):
        peer.sendall(f"GET /health HTTP/1.1\r\nHost: {name}\r\nConnection: {'close' if close else 'keep-alive'}\r\n\r\n".encode())
        with http.client.HTTPResponse(peer) as response:
            response.begin()
            assert response.status == 200 and response.read() == b"ok\n"

    def certificate(name):
        with connect(name) as peer:
            value = peer.getpeercert(binary_form=True)
            health(peer, name)
            return value

    def ed25519(name, accepted=True):
        process = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", name,
                                  "-tls1_3", "-alpn", "http/1.1", "-sigalgs", "ed25519", "-showcerts", "-ign_eof"],
                                 input=f"GET /health HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode(),
                                 capture_output=True, timeout=8)
        certificates = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", process.stdout, re.S)
        if not accepted:
            assert process.returncode != 0 and not certificates and b"handshake failure" in process.stderr.lower(), (process.returncode, process.stderr[-1000:])
            return None
        assert process.returncode == 0 and b"HTTP/1.1 200 " in process.stdout and b"\r\n\r\nok\n" in process.stdout, (name, process.returncode, process.stderr[-1000:])
        assert len(certificates) == 1
        return ssl.PEM_cert_to_DER_cert(certificates[0].decode())

    with log.open("wb") as output:
        process = subprocess.Popen([str(binary), "--config", str(config)], cwd=folder, stdout=output, stderr=output)
        try:
            wait(lambda: process.poll() is not None or '"event":"server.ready"' in log.read_text(), "server readiness")
            assert process.poll() is None, log.read_text()
            localhost = certificate("localhost")
            assert certificate("LOCALHOST") == certificate("localhost") == localhost
            other = certificate("other.test")
            assert certificate("OTHER.TEST") == other and other != localhost
            results.append({"case": "stable-host-identities", "passed": True})
            print("ok: repeated development hosts reuse distinct identities, including case folding", flush=True)

            ed = ed25519("localhost")
            assert ed25519("localhost") == ed and ed != localhost
            results.append({"case": "separate-signature-algorithms", "passed": True})
            print("ok: ECDSA and Ed25519 development identities remain independent", flush=True)

            with ThreadPoolExecutor(max_workers=8) as workers:
                concurrent = list(workers.map(certificate, ["concurrent.test"] * 8))
            assert len(set(concurrent)) == 1 and concurrent[0] != localhost
            results.append({"case": "concurrent-cold-host", "passed": True, "clients": 8})
            print("ok: concurrent cold handshakes publish one stable identity", flush=True)

            assert certificate("configured.test") == expected
            ed25519("configured.test", accepted=False)
            results.append({"case": "configured-material-precedence", "passed": True})
            print("ok: configured SNI certificates stay authoritative, including signature refusal", flush=True)

            with connect("localhost") as held:
                health(held, "localhost", close=False)
                process.send_signal(signal.SIGHUP)
                wait(lambda: "SIGHUP config reload completed for new connections." in log.read_text(), "reload")
                assert certificate("localhost") == localhost
                health(held, "localhost")
            results.append({"case": "reload-and-held-reader", "passed": True})
            print("ok: identities outlive reloads and held connection readers", flush=True)

            for index in range(66):
                assert ed25519(f"capacity-{index}.test")
            overflow = ed25519("overflow.test")
            assert ed25519("overflow.test") != overflow
            assert certificate("localhost") == localhost and certificate("configured.test") == expected
            results.append({"case": "bounded-cache-uncached-overflow", "passed": True, "overflow_hosts": 66})
            print("ok: cache exhaustion retains uncached handshakes without evicting borrowed identities", flush=True)
        except BaseException:
            print(log.read_text()[-12000:])
            raise
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                code = process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
                raise
            assert code == 0 and '"event":"server.shutdown_timeout"' not in log.read_text(), (code, log.read_text())
            assert "All connection and background workers stopped." in log.read_text(), log.read_text()

assert len(results) == 6
assert hashlib.sha256(binary.read_bytes()).hexdigest() == binary_hash
assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == fixture_hash
if args.output:
    args.output.write_text(json.dumps({"binary_sha256": binary_hash, "fixture_sha256": fixture_hash, "results": results}, indent=2) + "\n")
