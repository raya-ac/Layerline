#!/usr/bin/env python3
"""Saturate application allocations without losing Unix control or recovery."""
import http.client
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"
LIMIT = 8 * 1024 * 1024


def available_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for(check, description):
    until = time.monotonic() + 5
    while not check():
        assert time.monotonic() < until, description
        time.sleep(.02)


def command(path, text):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(3)
        conn.connect(str(path))
        conn.sendall(text.encode() + b"\n")
        output = b""
        while part := conn.recv(16384):
            output += part
        return output.decode()


def metrics(path):
    return {line.rsplit(" ", 1)[0]: int(line.rsplit(" ", 1)[1])
            for line in command(path, "metrics").splitlines()
            if line and not line.startswith("#")}


def usage(path, pool="normal"):
    return metrics(path)[f'layerline_heap_bytes{{pool="{pool}"}}']


def response(conn, first=b""):
    conn.settimeout(3)
    output = first
    while True:
        try:
            part = conn.recv(16384)
        except ConnectionResetError:
            # Rejecting before the remaining request headers are read may end
            # TCP with RST. The caller still requires the entire framed 503.
            return output
        if not part:
            return output
        output += part


def overloaded(output, head_only=False):
    head, body = output.split(b"\r\n\r\n", 1)
    assert head.startswith(b"HTTP/1.1 503 "), output[:200]
    assert b"Content-Length: 12" in head and b"Retry-After: 1" in head, head
    assert body == (b"" if head_only else b"server busy\n"), body
    assert output.count(b"HTTP/1.1 ") == 1, "a second final response was appended"


def frame(kind, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


def exact(conn, count):
    output = b""
    while len(output) < count:
        part = conn.recv(count - len(output))
        if not part:
            raise EOFError("HTTP/2 connection closed")
        output += part
    return output


def literal(name, value):
    return b"\0" + bytes([len(name)]) + name + bytes([len(value)]) + value


with tempfile.TemporaryDirectory(prefix="ll-memory-", dir="/tmp") as temporary:
    folder = Path(temporary)
    (folder / "cached.bin").write_bytes(b"c" * 131072)
    (folder / "queued.bin").write_bytes(b"q" * 1048576)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=memory.test",
                    "-keyout", str(folder / "key.pem"), "-out", str(folder / "cert.pem")],
                   check=True, capture_output=True)
    for secure in [False, True]:
        port = available_port()
        config, admin = folder / "server.conf", folder / "admin.sock"
        config_text = f"""host = 127.0.0.1
port = {port}
dir = {folder}
serve_static_root = true
tls = {str(secure).lower()}
tls_cert = {folder}/cert.pem
tls_key = {folder}/key.pem
admin_socket = {admin}
admin_ui = false
memory_budget_bytes = {LIMIT}
max_request_bytes = 1048576
max_body_bytes = 1048576
read_header_timeout_ms = 15000
read_body_timeout_ms = 15000
idle_timeout_ms = 15000
response_cache = true
response_cache_max_bytes = 1048576
response_cache_max_entry_bytes = 262144
response_cache_ttl_ms = 60000
graceful_shutdown_timeout_ms = 500
"""
        config.write_text(config_text)
        log_path = folder / ("tls.log" if secure else "plain.log")
        process, held, spare, head_spare = None, [], None, None
        context = ssl._create_unverified_context()
        context.set_alpn_protocols(["http/1.1"])

        def connect(alpn="http/1.1"):
            conn = socket.create_connection(("127.0.0.1", port), timeout=3)
            if secure:
                selected = context
                if alpn != "http/1.1":
                    selected = ssl._create_unverified_context()
                    selected.set_alpn_protocols([alpn])
                conn = selected.wrap_socket(conn, server_hostname="memory.test")
                assert conn.selected_alpn_protocol() == alpn
            return conn

        def get(path, expected):
            conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=3, context=context) if secure else http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            try:
                conn.request("GET", path, headers={"Connection": "close"})
                reply = conn.getresponse()
                body = reply.read()
                assert reply.status == 200 and body == expected, (reply.status, body[:200])
            finally:
                conn.close()

        try:
            # Invalid limits must fail before a listener announces readiness.
            config.write_text(config_text.replace(f"memory_budget_bytes = {LIMIT}", "memory_budget_bytes = 1"))
            invalid = subprocess.run([str(BINARY), "--config", str(config)], cwd=ROOT, capture_output=True, timeout=5)
            assert invalid.returncode != 0 and b'"event":"server.ready"' not in invalid.stderr
            config.write_text(config_text)
            with log_path.open("wb") as log:
                process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            wait_for(lambda: process.poll() is not None or '"event":"server.ready"' in log_path.read_text(), "startup timed out")
            assert process.poll() is None, log_path.read_text()
            baseline = usage(admin)

            for cycle in range(2):
                previous_reclaims = log_path.read_text().count("reclaimed 1 cache entries")
                get("/cached.bin", b"c" * 131072)
                assert metrics(admin)["layerline_response_cache_stores_total"] > cycle
                # Complete TLS before the request heap is exhausted. A 503 must
                # still be encrypted, rather than leaked as plaintext or lost.
                spare = connect()
                head_spare = connect()
                # Bootstrap and I/O metadata now count toward the same cap.
                # Finish these handshakes before uploads consume request space;
                # a handshake refusal cannot prove encrypted HTTP 503 framing.
                for _ in range(8):
                    held.append(connect())
                denied = False
                uploads = 0
                for conn in list(held):
                    conn.sendall(b"POST /api/echo HTTP/1.1\r\nHost: memory.test\r\nContent-Length: 524288\r\n\r\n")
                    conn.settimeout(.15)
                    try:
                        first = conn.recv(16384)
                    except TimeoutError:
                        uploads += 1
                        continue
                    overloaded(response(conn, first))
                    denied = True
                    held.remove(conn)
                    conn.close()
                    break
                assert denied and uploads > 0, "requests did not reach the shared allocation cap"
                # Each method gets a fresh pressure cycle. Closing the GET's
                # TLS channel can legitimately free enough for a following HEAD.
                probe = spare if cycle == 0 else head_spare
                method = b"GET" if cycle == 0 else b"HEAD"
                probe.sendall(method + b" /health HTTP/1.1\r\nHost: memory.test\r\nConnection: close\r\n\r\n")
                overloaded(response(probe), head_only=cycle == 1)
                spare.close()
                spare = None
                head_spare.close()
                head_spare = None
                values = metrics(admin)
                for pool in ["total", "normal", "control"]:
                    assert values[f'layerline_heap_peak_bytes{{pool="{pool}"}}'] <= values[f'layerline_heap_limit_bytes{{pool="{pool}"}}'], values
                assert values['layerline_heap_limit_bytes{pool="total"}'] == LIMIT
                assert values['layerline_heap_rejections_total{pool="normal"}'] > cycle
                assert values["layerline_overload_responses_total"] >= (cycle + 1) * 2
                assert "Layerline" in command(admin, "status")
                wait_for(lambda: log_path.read_text().count("reclaimed 1 cache entries") > previous_reclaims, "cached bodies were not reclaimed under pressure")
                for conn in held:
                    conn.close()
                held.clear()
                wait_for(lambda: usage(admin) <= baseline + 262144, "request allocations were not reclaimed")
                get("/health", b"ok\n")
                get("/cached.bin", b"c" * 131072)
                assert process.poll() is None, log_path.read_text()

            # Zero DATA credit retains final responses in the HTTP/2 pool.
            # Its larger sub-limit must not bypass the shared application cap.
            prior_rejections = metrics(admin)['layerline_heap_rejections_total{pool="normal"}']
            conn = connect("h2")
            successful = 0
            try:
                conn.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, struct.pack("!HI", 4, 0)))
                for stream in range(1, 33, 2):
                    block = b"\x82" + (b"\x87" if secure else b"\x86")
                    block += literal(b":authority", b"memory.test") + literal(b":path", b"/queued.bin")
                    conn.sendall(frame(1, 5, stream, block))
                    for _ in range(100):
                        head = exact(conn, 9)
                        payload = exact(conn, int.from_bytes(head[:3], "big"))
                        kind, flags, received_stream = head[3], head[4], int.from_bytes(head[5:], "big")
                        if kind == 4 and not flags & 1:
                            conn.sendall(frame(4, 1, 0))
                        assert kind != 0, "DATA bypassed the zero stream window"
                        if received_stream == stream and kind in [1, 3]:
                            if kind == 1:
                                assert payload.startswith(b"\x88"), payload
                                successful += 1
                            break
                        if kind == 7:
                            break
                    else:
                        raise AssertionError("HTTP/2 request did not complete or reject")
                    if metrics(admin)['layerline_heap_rejections_total{pool="normal"}'] > prior_rejections:
                        break
            except (EOFError, ConnectionError):
                pass
            finally:
                conn.close()
            assert successful > 0, "HTTP/2 never queued a response"
            assert metrics(admin)['layerline_heap_rejections_total{pool="normal"}'] > prior_rejections, "HTTP/2 bypassed the shared cap"
            wait_for(lambda: metrics(admin)["layerline_http2_memory_bytes"] == 0, "HTTP/2 disconnect retained allocator bytes")
            assert metrics(admin)["layerline_http2_routing_jobs"] == 0
            get("/health", b"ok\n")

            config.write_text(config_text + "max_concurrent_connections = 2\n")
            assert "OK" in command(admin, "reload")
            try:
                held.extend([connect(), connect()])
                wait_for(lambda: metrics(admin)["layerline_connections_active"] == 2, "connection slots were not held")
                with socket.create_connection(("127.0.0.1", port), timeout=3) as rejected:
                    try:
                        rejected.sendall(b"\x16\x03\x01\x00\x00" if secure else b"GET /health HTTP/1.1\r\nHost: memory.test\r\n\r\n")
                        output = response(rejected)
                    except (ConnectionResetError, BrokenPipeError):
                        output = b""
                    if secure:
                        assert not output, "TLS admission leaked a plaintext overload response"
                    else:
                        overloaded(output)
                assert "Layerline" in command(admin, "status")
            finally:
                for conn in held:
                    conn.close()
                held.clear()
            wait_for(lambda: metrics(admin)["layerline_connections_active"] == 0, "connection slots were not released")
            get("/health", b"ok\n")

            config.write_text(config_text.replace(f"memory_budget_bytes = {LIMIT}", f"memory_budget_bytes = {LIMIT * 2}"))
            assert "ReloadRequiresRestart" in command(admin, "reload")
            assert metrics(admin)['layerline_heap_limit_bytes{pool="total"}'] == LIMIT
            get("/health", b"ok\n")
            print(f"ok: {'TLS' if secure else 'plain'} shared heap, protected control/503, cache reclamation, HTTP/2 queued output, recovery and restart-only limits")
        except BaseException:
            if log_path.exists():
                print(log_path.read_text(), file=sys.stderr)
            raise
        finally:
            if spare is not None:
                spare.close()
            if head_spare is not None:
                head_spare.close()
            for conn in held:
                conn.close()
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                    raise AssertionError("budgeted server did not shut down")
