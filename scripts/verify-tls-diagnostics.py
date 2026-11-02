#!/usr/bin/env python3
"""Unauthenticated TLS metadata must stay bounded, printable and on one log line."""
import pathlib
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"
MAX_BYTES = 256


def escaped(data):
    escapes = {10: r"\n", 13: r"\r", 9: r"\t", 34: r'\"', 92: r"\\"}
    parts = []
    for byte in data[:MAX_BYTES]:
        if byte in escapes:
            parts.append(escapes[byte])
        elif 32 <= byte <= 126:
            parts.append(chr(byte))
        else:
            parts.append(f"\\x{byte:02x}")
    return "".join(parts) + ("..." if len(data) > MAX_BYTES else "")


def assert_fields(fragment, name, protocols, accepted):
    assert all(byte == 10 or 32 <= byte <= 126 for byte in fragment), ("raw terminal/control byte", fragment)
    lines = fragment.decode("ascii").splitlines()
    assert not any(line.startswith("layerline.fixture_forged") for line in lines), ("forged diagnostic line", lines)
    probes = [line for line in lines if line.startswith("TLS ClientHello ")]
    assert len(probes) == 1, ("missing or forged ClientHello line", lines)
    expected_name = escaped(name if name is not None else b"(none)")
    expected_alpn = escaped(b",".join(protocols) if protocols else b"(none)")
    prefix = f'TLS ClientHello sni="{expected_name}" alpn="{expected_alpn}" tls13=true '
    assert probes[0].startswith(prefix), ("unescaped or truncated field", probes[0], prefix)
    assert len(probes[0]) <= 2300, ("unbounded ClientHello log", len(probes[0]))
    established = [line for line in lines if line.startswith("TLS 1.3 native connection accepted ")]
    if accepted:
        protocol = "http/1.1" if protocols else "(none)"
        assert established == [f'TLS 1.3 native connection accepted sni="{expected_name}" alpn="{protocol}"'], established
    else:
        assert not established, established


with tempfile.TemporaryDirectory(prefix="layerline-tls-diagnostics-") as temporary:
    folder = pathlib.Path(temporary)
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    config, log = folder / "server.conf", folder / "server.log"
    config.write_text(f"host = 127.0.0.1\nport = {port}\ndir = {folder}\nadmin = false\nadmin_ui = false\ntls = true\ntls_auto = false\ncf_auto_deploy = false\nhttp3 = false\ngraceful_shutdown_timeout_ms = 1200\n")
    with log.open("wb") as output:
        process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=output, stderr=output, start_new_session=True)
        try:
            until = time.monotonic() + 5
            while b'"event":"server.ready"' not in log.read_bytes():
                assert process.poll() is None and time.monotonic() < until, log.read_bytes()
                time.sleep(.02)
            cases = [
                ("forged lines", "good\nlayerline.fixture_forged_sni.example", ["http/1.1", "safe\nlayerline.fixture_forged_alpn"]),
                ("normal", "localhost", ["http/1.1"]),
                ("absent", None, []),
                ("controls and delimiters", 'quote"slash\\name.example', ["http/1.1", 'opaque"\\\x00\r\t\x1b[31m']),
                ("oversized ALPN", "localhost", ["http/1.1"] + ["p" * 250] * 16),
            ]
            for label, name, protocols in cases:
                offset = log.stat().st_size
                context = ssl._create_unverified_context()
                if protocols:
                    context.set_alpn_protocols(protocols)
                with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                    with context.wrap_socket(raw, server_hostname=name, suppress_ragged_eofs=False) as peer:
                        peer.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                        response = bytearray()
                        while part := peer.recv(4096):
                            response.extend(part)
                            assert len(response) < 65536
                        assert response.startswith(b"HTTP/1.1 200 "), response
                assert_fields(log.read_bytes()[offset:], name.encode("ascii") if name is not None else None, [p.encode("ascii") for p in protocols], True)
                print(f"ok: TLS diagnostics {label}, successful request and authenticated closure", flush=True)

            # Python rejects NUL in server_hostname; mutate only the raw SNI
            # bytes of its valid ClientHello to exercise the pre-auth log path.
            injected = b"good\x00\xff\xe2\x80\xa8.example"
            original = b"a" * (len(injected) - 8) + b".example"
            context = ssl._create_unverified_context()
            context.set_alpn_protocols(["http/1.1"])
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            client = context.wrap_bio(incoming, outgoing, server_hostname=original.decode())
            try:
                client.do_handshake()
            except ssl.SSLWantReadError:
                pass
            hello = outgoing.read()
            assert hello.count(original) == 1
            offset = log.stat().st_size
            with socket.create_connection(("127.0.0.1", port), timeout=5) as peer:
                peer.sendall(hello.replace(original, injected))
                assert peer.recv(1024), "no handshake reply"
            until = time.monotonic() + 3
            while b"TLS ClientHello " not in log.read_bytes()[offset:]:
                assert process.poll() is None and time.monotonic() < until
                time.sleep(.02)
            assert_fields(log.read_bytes()[offset:], injected, [b"http/1.1"], False)
            print("ok: pre-auth TLS diagnostics escape binary SNI and Unicode line separators", flush=True)
        except BaseException:
            print(log.read_bytes(), file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            assert process.returncode == 0, log.read_bytes()
