#!/usr/bin/env python3
"""Exercise the actual native TLS listener with an independent OpenSSL client."""
import argparse
import hashlib
import json
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time

from wire_h2 import H2, frame

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", type=Path)
parser.add_argument("--output", type=Path)
parser.add_argument("--basic-commands", action="store_true")
args = parser.parse_args()
binary = args.binary.resolve(strict=True)
if args.output:
    args.output.unlink(missing_ok=True)
results = []
client_help = subprocess.run(["openssl", "s_client", "-help"], capture_output=True).stderr
advanced_commands = not args.basic_commands and b"-adv" in client_help


def wait_for(check, label, seconds=6):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if value := check():
            return value
        time.sleep(.01)
    raise AssertionError(label)


def port():
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        return reserved.getsockname()[1]


class Client:
    def __init__(self, folder, number, alpn):
        self.timeout = 4
        self.trace = folder / (alpn.replace("/", "-") + ".trace")
        self.stderr = folder / (alpn.replace("/", "-") + ".stderr")
        self.errors = self.stderr.open("wb")
        self.process = subprocess.Popen(["openssl", "s_client", "-connect", f"127.0.0.1:{number}", "-servername", "localhost", "-verify_hostname", "localhost", "-CAfile", str(folder / "cert.pem"), "-verify_return_error", "-tls1_3", "-alpn", alpn, "-brief", *(["-adv"] if advanced_commands else []), "-msg", "-msgfile", str(self.trace)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.errors)
        self.received = bytearray()
        try:
            wait_for(lambda: any(line.startswith(">>>") and "Finished" in line for line in self.trace_text().splitlines()), "OpenSSL did not finish its authenticated handshake")
        except BaseException:
            self.close()
            raise

    def write_input(self, data):
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def sendall(self, data):
        before = self.sent_records()
        self.write_input(data)
        # OpenSSL 3's basic commands apply to one stdin read, not every line.
        # Do not let a later K command share that read with binary frame bytes.
        wait_for(lambda: self.sent_records() > before, "OpenSSL did not write the application fragment")

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, count):
        ready, _, _ = select.select([self.process.stdout], [], [], self.timeout)
        assert ready, "OpenSSL client stalled: " + self.stderr.read_text()[-3000:]
        data = self.process.stdout.read1(count)
        self.received.extend(data)
        assert len(self.received) < 8 * 1024 * 1024
        return data

    def trace_text(self):
        data = self.trace.read_text() if self.trace.exists() else ""
        assert len(data) < 8 * 1024 * 1024
        return data

    def sent_records(self):
        return sum(line.startswith(">>>") and "RecordHeader" in line for line in self.trace_text().splitlines())

    def updates(self):
        messages = [line for line in self.trace_text().splitlines() if "KeyUpdate" in line]
        return sum(line.startswith(">>>") for line in messages), sum(line.startswith("<<<") for line in messages)

    def update(self, requested):
        sent = self.updates()[0]
        if advanced_commands:
            self.write_input(b"{keyup:req}\n" if requested else b"{keyup:noreq}\n")
        else:
            self.write_input(b"K\n" if requested else b"k\n")
        wait_for(lambda: self.updates()[0] == sent + 1, "OpenSSL did not send KeyUpdate")

    def exact(self, count):
        data = bytearray()
        while len(data) < count:
            part = self.recv(count - len(data))
            assert part, "OpenSSL ended before the application response"
            data.extend(part)
        return bytes(data)

    def http1(self, close=False):
        self.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\nconnection: " + (b"close" if close else b"keep-alive") + b"\r\n\r\n")
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            header.extend(self.exact(1))
            assert len(header) < 16384, header[:200]
        assert header.startswith(b"HTTP/1.1 200 "), header[:200]
        fields = dict(line.lower().split(b":", 1) for line in bytes(header).split(b"\r\n")[1:] if b":" in line)
        assert int(fields[b"content-length"]) == 3
        assert self.exact(3) == b"ok\n"

    def finish(self):
        status = self.process.wait(6)
        assert status == 0, ("unclean native TLS shutdown", status, self.stderr.read_text()[-3000:])
        trace = self.trace.read_text()
        assert any(line.startswith("<<<") and "close_notify" in line for line in trace.splitlines()), "native listener closed TCP without a TLS close-notify"

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(4)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise AssertionError("OpenSSL client did not join")
        self.process.stdin.close()
        self.process.stdout.close()
        self.errors.close()


with tempfile.TemporaryDirectory(prefix="layerline-native-tls-") as temporary:
    folder = Path(temporary)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-out", str(folder / "cert.pem"), "-keyout", str(folder / "key.pem")], check=True, capture_output=True, timeout=15)
    number = port()
    config = folder / "server.conf"
    config.write_text(f"host = 127.0.0.1\nport = {number}\ntls = true\ntls_cert = {folder / 'cert.pem'}\ntls_key = {folder / 'key.pem'}\nadmin = false\nadmin_ui = false\nhttp3 = false\nwrite_timeout_ms = 200\nread_header_timeout_ms = 3000\nread_body_timeout_ms = 3000\nidle_timeout_ms = 5000\ngraceful_shutdown_timeout_ms = 1200\n")
    server_log = folder / "server.log"
    with server_log.open("wb") as output:
        process = subprocess.Popen([str(binary), "--config", str(config)], stdout=output, stderr=output, cwd=binary.parent)
        try:
            wait_for(lambda: process.poll() is not None or '"event":"server.ready"' in server_log.read_text(), "native TLS server did not start")
            assert process.poll() is None, server_log.read_text()
            for alpn in ["http/1.1", "h2"]:
                client = Client(folder, number, alpn)
                try:
                    if alpn == "h2":
                        h2 = H2.__new__(H2)
                        h2.connection, h2.tls = client, True
                        client.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))
                        stream = 1
                        h2.request(stream, b"/health")
                        assert h2.response(stream) == (200, b"ok\n")
                    else:
                        client.http1()
                    requests = 0
                    for requested in [False, True, True, False, True, False]:
                        client.update(requested)
                        requests += requested
                        if requested:
                            wait_for(lambda: client.updates()[1] == requests, "native KeyUpdate reply missing")
                            # This exceeds write_timeout_ms before any new HTTP
                            # response exists. TLS control must not arm its budget.
                            time.sleep(.25)
                        if alpn == "h2":
                            stream += 2
                            h2.request(stream, b"/health")
                            assert h2.response(stream) == (200, b"ok\n")
                            h2.ping()
                        else:
                            client.http1()
                        if requested:
                            wait_for(lambda: client.updates()[1] == requests, "native KeyUpdate reply missing")
                    assert client.updates() == (6, 3), client.updates()
                    if alpn == "h2":
                        ping = frame(6, 0, 0, b"bounded!")
                        for split in range(1, len(ping)):
                            client.sendall(ping[:split])
                            client.update(True)
                            requests += 1
                            wait_for(lambda: client.updates()[1] == requests, "split-frame KeyUpdate reply missing")
                            client.sendall(ping[split:])
                            h2.until(lambda k, f, s, p: k == 6 and f == 1 and s == 0 and p == b"bounded!")
                        assert client.updates() == (6 + len(ping) - 1, requests)
                        client.sendall(frame(7, 0, 0, stream.to_bytes(4, "big") + bytes(4)))
                    else:
                        client.http1(close=True)
                    client.finish()
                    expected_updates = (22, 19) if alpn == "h2" else (6, 3)
                    assert client.updates() == expected_updates, client.updates()
                    results.append({"alpn": alpn, "sent_key_updates": client.updates()[0], "received_key_updates": client.updates()[1], "application_responses": 8 if alpn == "http/1.1" else 7, "split_h2_frame_boundaries": len(ping) - 1 if alpn == "h2" else 0, "authenticated_shutdown": True, "openssl_commands": "advanced" if advanced_commands else "basic"})
                    print(f"ok: {alpn} independent client key updates, exact replies, application traffic and clean close", flush=True)
                finally:
                    client.close()
        except BaseException:
            print(server_log.read_text()[-16000:])
            raise
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("native TLS server did not join")
if args.output:
    args.output.write_text(json.dumps({"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "openssl_version": subprocess.check_output(["openssl", "version"], text=True).strip(), "results": results}, indent=2) + "\n")
