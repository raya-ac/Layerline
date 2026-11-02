#!/usr/bin/env python3
"""Configured certificates must match SPKI, fail closed, and rotate without downtime."""
import argparse
import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("binary", type=Path)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
BINARY = args.binary.resolve(strict=True)
if args.output:
    args.output.unlink(missing_ok=True)
TOKEN = "listener-fixture-not-a-real-token"
results = []


def run(*command):
    return subprocess.run(command, check=True, capture_output=True).stdout


def der(tag, value):
    size = len(value)
    length = bytes([size]) if size < 128 else size.to_bytes((size.bit_length() + 7) // 8, "big")
    if size >= 128:
        length = bytes([0x80 | len(length)]) + length
    return bytes([tag]) + length + value


def parts(data):
    # These are mutations of generated fixtures, not a production DER parser.
    nodes, offset = [], 0
    while offset < len(data):
        tag, length = data[offset:offset + 2]
        offset += 2
        if length & 0x80:
            count = length & 0x7f
            assert 0 < count <= 4 and offset + count <= len(data)
            length = int.from_bytes(data[offset:offset + count], "big")
            offset += count
        assert offset + length <= len(data)
        nodes.append((tag, data[offset:offset + length]))
        offset += length
    return nodes


def unpem(label, value):
    lines = value.strip().splitlines()
    assert lines[0] == f"-----BEGIN {label}-----".encode()
    assert lines[-1] == f"-----END {label}-----".encode()
    return base64.b64decode(b"".join(lines[1:-1]), validate=True)


def pem(label, value):
    return f"-----BEGIN {label}-----\n".encode() + base64.b64encode(value) + f"\n-----END {label}-----\n".encode()


class API(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self):
        self.server.calls.append(self.command)
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        data = json.dumps({"success": True, "result": [] if self.command == "GET" else {"id": "fixture-record"}}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = reply
    do_POST = reply


def port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def control(path, command):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(6)
        client.connect(str(path))
        client.sendall(command.encode() + b"\n")
        response = b""
        while block := client.recv(4096):
            response += block
            assert len(response) < 65536
        return response


def request(client, path="/health"):
    client.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n".encode())
    response = http.client.HTTPResponse(client)
    try:
        response.begin()
        body = response.read()
        assert response.status == 200, (path, response.status, body[:200])
        return body
    finally:
        response.close()


def connect(number, trust, certificate):
    context = ssl.create_default_context(cafile=str(trust))
    context.set_alpn_protocols(["http/1.1"])
    raw = socket.create_connection(("127.0.0.1", number), timeout=10)
    try:
        client = context.wrap_socket(raw, server_hostname="localhost")
    except BaseException:
        raw.close()
        raise
    try:
        assert client.getpeercert(binary_form=True) == certificate
        assert request(client).strip() == b"ok"
        return client
    except BaseException:
        client.close()
        raise


def generation(client):
    body = request(client, "/metrics").decode()
    values = {line.split()[0]: int(line.split()[1]) for line in body.splitlines() if line.startswith("layerline_config_generation ")}
    return values["layerline_config_generation"]


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise AssertionError("listener fixture did not drain cleanly")


with tempfile.TemporaryDirectory(prefix="layerline-listener-materials-", dir="/tmp") as temporary:
    root = Path(temporary)

    def certificate(name, key_spec, extra=None):
        cert, key = root / f"{name}.pem", root / f"{name}-key.pem"
        command = ["openssl", "req", "-x509", "-newkey", key_spec, "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign", "-keyout", str(key), "-out", str(cert)]
        if key_spec == "ec":
            command += ["-pkeyopt", "ec_paramgen_curve:P-256"]
        if extra:
            command += ["-addext", extra]
        run(*command)
        return cert, key

    ec, ec_key = certificate("ec", "ec")
    other_ec, other_ec_key = certificate("other-ec", "ec")
    rsa, rsa_key = certificate("rsa", "rsa:2048")
    weak, weak_key = certificate("weak", "rsa:1024")
    ec_der = unpem("CERTIFICATE", ec.read_bytes())
    other_ec_der = unpem("CERTIFICATE", other_ec.read_bytes())
    public_ec = parts(parts(run("openssl", "pkey", "-in", str(ec_key), "-pubout", "-outform", "DER"))[0][1])[1][1][1:]
    other_public_ec = parts(parts(run("openssl", "pkey", "-in", str(other_ec_key), "-pubout", "-outform", "DER"))[0][1])[1][1][1:]
    public_rsa = parts(parts(run("openssl", "pkey", "-in", str(rsa_key), "-pubout", "-outform", "DER"))[0][1])[1][1][1:]
    modulus = parts(parts(public_rsa)[0][1])[0][1].lstrip(b"\0")
    fake_ec, _ = certificate("ec-extension", "ec", "1.3.6.1.4.1.57264.1=DER:" + der(4, public_ec).hex(":"))
    fake_rsa, _ = certificate("rsa-extension", "rsa:2048", "1.3.6.1.4.1.57264.1=DER:" + der(4, modulus).hex(":"))
    traditional = run("openssl", "rsa", "-in", str(rsa_key), "-traditional")
    rsa_fields = parts(parts(unpem("RSA PRIVATE KEY", traditional))[0][1])
    assert len(rsa_fields) == 9 and all(tag == 2 for tag, _ in rsa_fields)

    def rsa_pem(fields):
        return pem("RSA PRIVATE KEY", der(0x30, b"".join(der(tag, value) for tag, value in fields)))

    altered_exponent = rsa_fields.copy()
    altered_exponent[2] = (2, b"\x03")
    wrong_exponent = rsa_pem(altered_exponent)
    changed_curve = bytearray(ec_der)
    curve = b"\x2a\x86\x48\xce\x3d\x03\x01\x07"
    changed_curve[changed_curve.index(curve) + len(curve) - 1] ^= 1
    cases = {
        "key bytes instead of certificate": (pem("CERTIFICATE", public_ec), ec_key.read_bytes()),
        "trailing leaf data": (pem("CERTIFICATE", ec_der + b"\x05\0"), ec_key.read_bytes()),
        "truncated leaf": (pem("CERTIFICATE", ec_der[:-1]), ec_key.read_bytes()),
        "different key after leaf": (pem("CERTIFICATE", ec_der + other_public_ec), other_ec_key.read_bytes()),
        "EC key hidden in extension": (fake_ec.read_bytes(), ec_key.read_bytes()),
        "RSA modulus hidden in extension": (fake_rsa.read_bytes(), rsa_key.read_bytes()),
        "RSA exponent mismatch": (rsa.read_bytes(), wrong_exponent),
        "RSA below strength floor": (weak.read_bytes(), weak_key.read_bytes()),
        "wrong named curve": (pem("CERTIFICATE", changed_curve), ec_key.read_bytes()),
        "malformed intermediate": (ec.read_bytes() + pem("CERTIFICATE", b"abc"), ec_key.read_bytes()),
        "excessive chain": (ec.read_bytes() * 17, ec_key.read_bytes()),
        "oversized certificate": (pem("CERTIFICATE", ec_der + bytes(128 * 1024)), ec_key.read_bytes()),
    }
    for index, name in enumerate(["private exponent", "p", "q", "dP", "dQ", "q inverse"], start=3):
        fields = rsa_fields.copy()
        value = bytearray(fields[index][1])
        value[-1] ^= 1
        fields[index] = (2, bytes(value))
        cases[f"RSA altered {name}"] = (rsa.read_bytes(), rsa_pem(fields))
    for name, index, value in [
        ("zero private exponent", 3, b"\0"),
        ("multi-prime version without factors", 0, b"\1"),
        ("negative modulus", 1, rsa_fields[1][1].lstrip(b"\0")),
        ("nonminimal exponent", 2, b"\0" + rsa_fields[2][1]),
    ]:
        fields = rsa_fields.copy()
        fields[index] = (2, value)
        cases[f"RSA {name}"] = (rsa.read_bytes(), rsa_pem(fields))
    cases["RSA missing CRT fields"] = (rsa.read_bytes(), rsa_pem(rsa_fields[:4]))
    cases["RSA trailing private field"] = (rsa.read_bytes(), rsa_pem(rsa_fields + [(2, b"\1")]))
    rsa_der = unpem("RSA PRIVATE KEY", traditional)
    assert rsa_der[1] & 0x80
    ambiguous_length = rsa_der[:1] + bytes([rsa_der[1] + 1, 0]) + rsa_der[2:]
    cases["RSA nonminimal DER length"] = (rsa.read_bytes(), pem("RSA PRIVATE KEY", ambiguous_length))
    pkcs8 = parts(parts(unpem("PRIVATE KEY", rsa_key.read_bytes()))[0][1])
    algorithm = parts(pkcs8[1][1])

    def pkcs8_pem(fields):
        return pem("PRIVATE KEY", der(0x30, b"".join(der(tag, value) for tag, value in fields)))

    fields = pkcs8.copy()
    fields[0] = (2, b"\1")
    cases["PKCS8 unsupported version"] = (rsa.read_bytes(), pkcs8_pem(fields))
    cases["PKCS8 unsupported attributes"] = (rsa.read_bytes(), pkcs8_pem(pkcs8 + [(0xa0, b"")]))
    for name, parameters in [
        ("nonempty NULL", [(5, b"\0")]),
        ("duplicate parameters", [(5, b""), (5, b"")]),
        ("wrong parameter tag", [(4, b"")]),
    ]:
        fields = pkcs8.copy()
        fields[1] = (0x30, b"".join(der(tag, value) for tag, value in algorithm[:1] + parameters))
        cases[f"PKCS8 RSA {name}"] = (rsa.read_bytes(), pkcs8_pem(fields))
    fields = pkcs8.copy()
    fields[1] = (0x30, der(*algorithm[0]))
    absent_rsa_parameters = pkcs8_pem(fields)
    fields = parts(parts(unpem("PRIVATE KEY", ec_key.read_bytes()))[0][1])
    ec_algorithm = parts(fields[1][1])
    fields[1] = (0x30, b"".join(der(tag, value) for tag, value in ec_algorithm + ec_algorithm[1:]))
    cases["PKCS8 duplicate named curve"] = (ec.read_bytes(), pkcs8_pem(fields))
    cases["oversized private PEM"] = (rsa.read_bytes(), traditional + b" " * (32 * 1024))
    cases["oversized private DER"] = (rsa.read_bytes(), pem("RSA PRIVATE KEY", bytes(16 * 1024 + 1)))
    csr, signed = root / "leaf.csr", root / "pss-leaf.pem"
    run("openssl", "req", "-new", "-key", str(ec_key), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-out", str(csr))
    run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(rsa), "-CAkey", str(rsa_key), "-set_serial", "7", "-days", "1", "-copy_extensions", "copy", "-sigopt", "rsa_padding_mode:pss", "-out", str(signed))
    rsa4096, rsa4096_key = certificate("rsa4096", "rsa:4096")
    positives = [(ec.read_bytes(), ec_key.read_bytes(), ec, ec_der),
                 (rsa.read_bytes(), traditional, rsa, unpem("CERTIFICATE", rsa.read_bytes())),
                 (rsa.read_bytes(), rsa_key.read_bytes(), rsa, unpem("CERTIFICATE", rsa.read_bytes())),
                 (rsa.read_bytes(), absent_rsa_parameters, rsa, unpem("CERTIFICATE", rsa.read_bytes())),
                 (rsa4096.read_bytes(), rsa4096_key.read_bytes(), rsa4096, unpem("CERTIFICATE", rsa4096.read_bytes())),
                 (signed.read_bytes() + rsa.read_bytes(), ec_key.read_bytes(), rsa, unpem("CERTIFICATE", signed.read_bytes())),
                 (other_ec.read_bytes(), other_ec_key.read_bytes(), other_ec, other_ec_der)]
    api = http.server.ThreadingHTTPServer(("127.0.0.1", 0), API)
    api.daemon_threads = True
    api.calls = []
    thread = threading.Thread(target=api.serve_forever)
    thread.start()
    try:
        for scope in ["global", "domain"]:
            folder = root / scope
            folder.mkdir()
            active_cert, active_key = folder / "active.pem", folder / "active-key.pem"
            config, log, admin = folder / "server.conf", folder / "server.log", folder / "admin.sock"
            number = port()
            text = f"""host = 127.0.0.1
port = {number}
admin = true
admin_socket = {admin}
admin_ui = false
http3 = false
tls = true
tls_cert = {active_cert if scope == 'global' else ec}
tls_key = {active_key if scope == 'global' else ec_key}
cf_auto_deploy = true
cf_api_base = http://127.0.0.1:{api.server_port}
cf_token = {TOKEN}
cf_zone_id = fixture-zone
cf_record_name = listener.fixture.invalid
cf_record_type = TXT
cf_record_content = listener-material-fixture
cf_record_proxied = false
graceful_shutdown_timeout_ms = 1500
"""
            if scope == "domain":
                text += f"server = secure\nserver_name.secure = localhost\nserver_tls_cert.secure = {active_cert}\nserver_tls_key.secure = {active_key}\n"
            config.write_text(text)
            automatic = folder / "automatic.conf"
            automatic.write_text(text + "tls_auto = true\nletsencrypt_domains = listener.fixture.invalid\nletsencrypt_certbot = /bin/false\n")
            before = len(api.calls)
            checked = subprocess.run([str(BINARY), "--config", str(automatic), "--validate-config"], cwd=ROOT, capture_output=True, timeout=10)
            assert checked.returncode == 0, checked.stderr
            assert not active_cert.exists() and not active_key.exists() and len(api.calls) == before
            print(f"ok: {scope} missing ACME inputs defer to issuance without executing helpers/DNS", flush=True)
            results.append({"scope": scope, "phase": "missing-issuance-inputs", "passed": True})
            for name, (cert_bytes, key_bytes) in cases.items():
                active_cert.write_bytes(cert_bytes)
                active_key.write_bytes(key_bytes)
                before = len(api.calls)
                for flag in ["--validate-config", "--doctor"]:
                    checked = subprocess.run([str(BINARY), "--config", str(config), flag], cwd=ROOT, capture_output=True, timeout=10)
                    assert checked.returncode != 0, (scope, name, flag, "invalid material passed validation")
                    assert TOKEN.encode() not in checked.stderr
                checked = subprocess.run([str(BINARY), "--config", str(automatic), "--validate-config"], cwd=ROOT, capture_output=True, timeout=10)
                assert checked.returncode != 0, (scope, name, "ACME bypassed validation of present files")
                started = subprocess.run([str(BINARY), "--config", str(config)], cwd=ROOT, capture_output=True, timeout=10)
                assert started.returncode != 0, (scope, name, "invalid material reached readiness")
                assert b"Failed to load configured TLS material" in started.stderr, started.stderr
                assert len(api.calls) == before, (scope, name, "DNS ran before material rejection")
                print(f"ok: {scope} {name}: CLI/doctor/startup rejected before DNS", flush=True)
                results.append({"scope": scope, "case": name, "phase": "startup", "passed": True})

            active_cert.write_bytes(ec.read_bytes())
            active_key.write_bytes(ec_key.read_bytes())
            with log.open("wb") as output:
                process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=output, stderr=output, start_new_session=True)
                held = None
                try:
                    until = time.monotonic() + 6
                    while b'"event":"server.ready"' not in log.read_bytes():
                        assert process.poll() is None and time.monotonic() < until, log.read_bytes()
                        time.sleep(.02)
                    held = connect(number, ec, ec_der)
                    initial = generation(held)
                    before = len(api.calls)
                    for name, (cert_bytes, key_bytes) in cases.items():
                        active_cert.write_bytes(cert_bytes)
                        active_key.write_bytes(key_bytes)
                        response = control(admin, "validate")
                        assert response.startswith(b"ERROR "), (scope, name, response)
                        assert control(admin, "validate-runtime").startswith(b"OK "), "published config must remain valid"
                        response = control(admin, "reload")
                        assert response.startswith(b"ERROR "), (scope, name, response)
                        assert generation(held) == initial
                        assert request(held).strip() == b"ok"
                        fresh = connect(number, ec, ec_der)
                        fresh.close()
                        assert len(api.calls) == before
                        print(f"ok: {scope} {name}: rejected reload keeps old readers/certificate", flush=True)
                        results.append({"scope": scope, "case": name, "phase": "reload", "passed": True})
                    for index, (cert_bytes, key_bytes, trusted, expected) in enumerate(positives):
                        active_cert.write_bytes(cert_bytes)
                        active_key.write_bytes(key_bytes)
                        assert control(admin, "reload").startswith(b"OK ")
                        assert generation(held) == initial + index + 1
                        assert request(held).strip() == b"ok"
                        fresh = connect(number, trusted, expected)
                        fresh.close()
                        assert len(api.calls) == before
                    print(f"ok: {scope} verified EC/PKCS1/PKCS8/RSA-PSS-chain rotation and retained connections", flush=True)
                    results.append({"scope": scope, "phase": "positive-rotation", "passed": True, "profiles": len(positives)})
                finally:
                    if held:
                        held.close()
                    stop(process)
                assert process.returncode == 0, log.read_bytes()
                assert TOKEN.encode() not in log.read_bytes()
    finally:
        api.shutdown()
        api.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()

if args.output:
    args.output.write_text(json.dumps({"binary_sha256": hashlib.sha256(BINARY.read_bytes()).hexdigest(), "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "ssl_version": ssl.OPENSSL_VERSION, "results": results}, indent=2) + "\n")
