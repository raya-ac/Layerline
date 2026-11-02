#!/usr/bin/env python3
"""Run pinned, independent HTTP/2 tests against isolated loopback servers."""
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
REVISION = "af83a65f0b6273ef38bf778d400d98892e7653d8"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", type=Path)
parser.add_argument("--h2spec", type=Path, required=True)
parser.add_argument("--output", type=Path)
parser.add_argument("--transport", choices=["plain", "tls", "both"], default="both")
parser.add_argument("--strict", action="store_true")
parser.add_argument("sections", nargs="*")
args = parser.parse_args()
binary, tester = args.binary.resolve(strict=True), args.h2spec.resolve(strict=True)
version = subprocess.check_output([str(tester), "--version"], text=True, timeout=5).strip()
assert version == f"Version: 2.6.0 ({REVISION})", ("use the audited h2spec revision", version)
output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="layerline-h2spec-", dir="/tmp"))
if args.output:
    output.mkdir(mode=0o700)


def sha(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


binary_hash, tester_hash = sha(binary), sha(tester)
receipt = {"server_sha256": binary_hash, "tester_sha256": tester_hash, "tester_version": version,
           "strict": args.strict, "sections": args.sections, "transports": {},
           "scope": "h2spec RFC7540/7541 corpus, not a complete RFC9113 acceptance claim"}
print(f"evidence: {output}", flush=True)
try:
    for transport in ["plain", "tls"] if args.transport == "both" else [args.transport]:
        folder = output / transport
        folder.mkdir(mode=0o700)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        cert, key = folder / "cert.pem", folder / "key.pem"
        if transport == "tls":
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-nodes", "-days", "1", "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)],
                           check=True, capture_output=True, timeout=10)
        config = folder / "server.conf"
        config.write_text(f"""host = 127.0.0.1
port = {port}
dir = {folder}
admin = false
admin_ui = false
access_log = false
http3 = false
cf_auto_deploy = false
tls = {str(transport == 'tls').lower()}
tls_cert = {cert}
tls_key = {key}
read_header_timeout_ms = 5000
read_body_timeout_ms = 5000
idle_timeout_ms = 10000
write_timeout_ms = 5000
graceful_shutdown_timeout_ms = 1500
""")
        log, report = folder / "server.log", folder / "junit.xml"
        process = None
        try:
            with log.open("wb") as sink:
                process = subprocess.Popen([str(binary), "--config", str(config)], cwd=folder, stdout=sink, stderr=sink)
            until = time.monotonic() + 5
            while '"event":"server.ready"' not in log.read_text():
                assert process.poll() is None and time.monotonic() < until, log.read_text()
                time.sleep(.02)
            command = [str(tester), "--host", "127.0.0.1", "--port", str(port), "--path", "/api/echo",
                       "--timeout", "2", "--junit-report", str(report)]
            if transport == "tls":
                command += ["--tls", "--insecure"]
            if args.strict:
                command += ["--strict"]
            command += args.sections
            with (folder / "h2spec.log").open("wb") as sink:
                result = subprocess.run(command, stdout=sink, stderr=sink, timeout=900)
            suites = ET.parse(report).getroot().findall("testsuite")
            totals = {key: sum(int(suite.get(key, "0")) for suite in suites)
                      for key in ["tests", "failures", "errors", "skipped"]}
            assert totals["tests"] > 0, "zero tests is not conformance evidence"
            assert process.poll() is None, "server exited during protocol testing"
            failures = [{"section": suite.get("package"), "case": case.get("classname"),
                         "detail": "".join((case.find("failure") if case.find("failure") is not None else case.find("error")).itertext())}
                        for suite in suites for case in suite.findall("testcase")
                        if case.find("failure") is not None or case.find("error") is not None]
            receipt["transports"][transport] = {**totals, "exit": result.returncode, "failures_detail": failures,
                                                 "command": command, "report_sha256": sha(report),
                                                 "invalid_preface_case_passed": any(suite.get("package") == "http2/3.5" and
                                                     case.get("classname") == "Sends invalid connection preface" and
                                                     all(case.find(tag) is None for tag in ["failure", "error", "skipped"])
                                                     for suite in suites for case in suite.findall("testcase"))}
            if transport == "plain":
                # With no ALPN or HTTP/2 magic, this is an HTTP/1 syntax error on
                # the shared listener. Keep the tester's raw failure, then prove
                # what protocol response it tried to decode as an HTTP/2 frame.
                with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                    connection.sendall(b"INVALID CONNECTION PREFACE\r\n\r\n")
                    response = http.client.HTTPResponse(connection)
                    response.begin()
                    receipt["transports"][transport]["invalid_text_http1_status"] = response.status
                    assert len(response.read(65537)) <= 65536
            print(f"{transport}: {totals}, exit={result.returncode}", flush=True)
        finally:
            if process and process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=4)
                    raise AssertionError("conformance fixture required forced shutdown")
            if process:
                assert process.returncode == 0, ("server did not stop cleanly", process.returncode)
    assert sha(binary) == binary_hash and sha(tester) == tester_hash, "artifact changed during protocol gate"
    plain, tls = (receipt["transports"].get(name) for name in ["plain", "tls"])
    if plain and tls and tls["exit"] == 0 and tls["invalid_preface_case_passed"] and plain.get("invalid_text_http1_status") == 400:
        failures = plain["failures_detail"]
        if len(failures) == 1 and failures[0]["section"] == "http2/3.5" and failures[0]["case"] == "Sends invalid connection preface":
            plain["qualified_cleartext_exception"] = "Non-H2 text is rejected with HTTP/1 400 on the shared listener; ALPN h2 invalid-preface case passed separately. Raw failing JUnit is retained."
finally:
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
assert len(receipt["transports"]) == (2 if args.transport == "both" else 1)
assert all((result["exit"] == 0 and result["failures"] == 0 and result["errors"] == 0 and result["skipped"] == 0) or
           (result.get("qualified_cleartext_exception") and result["failures"] + result["errors"] == 1 and result["skipped"] == 0)
           for result in receipt["transports"].values()), f"independent conformance failed; inspect {output}"
print("ok: independent HTTP/2 gate; raw counts and any shared-listener qualification retained in receipt", flush=True)
