#!/usr/bin/env python3
"""Check TLS alert protection with an independent OpenSSL MemoryBIO peer."""
import argparse
import hashlib
import json
from pathlib import Path
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


def records(data):
    result, offset = [], 0
    while offset < len(data):
        assert len(data) - offset >= 5, "truncated TLS record header"
        size = int.from_bytes(data[offset + 3:offset + 5], "big")
        end = offset + 5 + size
        assert end <= len(data), "truncated TLS record body"
        result.append(data[offset:end])
        offset = end
    return result


with tempfile.TemporaryDirectory(prefix="layerline-handshake-alerts-", dir="/tmp") as temporary:
    folder = Path(temporary)
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
read_header_timeout_ms = 2000
write_timeout_ms = 1000
graceful_shutdown_timeout_ms = 1000
""")
    with log.open("wb") as output:
        process = subprocess.Popen([str(binary), "--config", str(config)], cwd=folder, stdout=output, stderr=output)
        try:
            until = time.monotonic() + 5
            while '"event":"server.ready"' not in log.read_text():
                assert process.poll() is None, log.read_text()
                assert time.monotonic() < until, log.read_text()
                time.sleep(.01)
            for alpn in ["http/1.1", "h2"]:
                for mode, expected in [("withheld-finished", "HANDSHAKE_FAILURE"),
                                       ("corrupt-finished", "BAD_RECORD_MAC"),
                                       ("unexpected-record", "UNEXPECTED_MESSAGE")]:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
                    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
                    context.set_alpn_protocols([alpn])
                    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                    peer = context.wrap_bio(incoming, outgoing, server_hostname="localhost")
                    with socket.create_connection(("127.0.0.1", port), timeout=4) as wire:
                        until = time.monotonic() + 4
                        while True:
                            assert time.monotonic() < until, "handshake stalled before server Finished"
                            try:
                                peer.do_handshake()
                                break
                            except ssl.SSLWantReadError:
                                pending = outgoing.read()
                                if pending:
                                    wire.sendall(pending)
                                block = wire.recv(16384)
                                assert block, "server closed before its Finished"
                                incoming.write(block)
                        assert peer.selected_alpn_protocol() == alpn
                        # OpenSSL has verified the server Finished. Hold back only
                        # its newly generated client Finished, not the ClientHello.
                        pending = outgoing.read()
                        assert records(pending)[-1][0] == 23, "OpenSSL did not produce encrypted Finished"
                        if mode == "corrupt-finished":
                            corrupted = bytearray(pending)
                            corrupted[-1] ^= 1
                            wire.sendall(corrupted)
                        elif mode == "unexpected-record":
                            wire.sendall(b"\x16\x03\x03\x00\x01\x00")
                        alert_wire = bytearray()
                        until = time.monotonic() + 4
                        while True:
                            assert time.monotonic() < until, (alpn, mode, "no fatal alert")
                            block = wire.recv(16384)
                            assert block, (alpn, mode, "connection closed without its protected alert")
                            alert_wire.extend(block)
                            incoming.write(block)
                            try:
                                peer.read(1)
                            except ssl.SSLWantReadError:
                                continue
                            except ssl.SSLError as error:
                                assert expected in error.reason, (alpn, mode, error.reason, bytes(alert_wire).hex())
                                break
                            raise AssertionError((alpn, mode, "application data accepted before client Finished"))
                        assert all(record[0] == 23 for record in records(alert_wire)), (alpn, mode, "plaintext alert after server Finished")
                        results.append({"alpn": alpn, "mode": mode, "authenticated_alert": expected})
                        print(f"ok: {alpn} {mode}: authenticated application-epoch fatal alert", flush=True)

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.set_alpn_protocols(["unsupported-protocol"])
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            peer = context.wrap_bio(incoming, outgoing, server_hostname="localhost")
            with socket.create_connection(("127.0.0.1", port), timeout=4) as wire:
                try:
                    peer.do_handshake()
                except ssl.SSLWantReadError:
                    wire.sendall(outgoing.read())
                else:
                    raise AssertionError("handshake completed without a server")
                alert = bytearray()
                while len(alert) < 7:
                    block = wire.recv(7 - len(alert))
                    assert block, "ALPN refusal closed without an alert"
                    alert.extend(block)
                assert alert == b"\x15\x03\x03\x00\x02\x02\x78", bytes(alert).hex()
                incoming.write(alert)
                try:
                    peer.do_handshake()
                except ssl.SSLError:
                    pass
                else:
                    raise AssertionError("unsupported ALPN was accepted")
            results.append({"mode": "pre-server-hello", "alert": "NO_APPLICATION_PROTOCOL"})
            print("ok: pre-ServerHello ALPN refusal remains a readable plaintext alert", flush=True)
        except BaseException:
            print(log.read_text())
            raise
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                code = process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
                raise
            assert code == 0 and '"event":"server.shutdown_timeout"' not in log.read_text(), (code, log.read_text())

assert len(results) == 7
assert hashlib.sha256(binary.read_bytes()).hexdigest() == binary_hash
assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == fixture_hash
if args.output:
    args.output.write_text(json.dumps({"binary_sha256": binary_hash, "fixture_sha256": fixture_hash, "results": results}, indent=2) + "\n")
