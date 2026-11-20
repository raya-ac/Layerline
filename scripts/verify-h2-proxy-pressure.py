#!/usr/bin/env python3
"""Keep four large origin replies open without buffering their bodies."""
import argparse
import http.client
import http.server
import pathlib
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

from wire_h2 import H2, frame

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPLY_BYTES = 2 * 1024 * 1024
WINDOW = 4096
STREAMS = (1, 3, 5, 7)
JOBS = "layerline_http2_routing_jobs"
MEMORY = "layerline_http2_memory_bytes"
REUSED = "layerline_upstream_connections_reused_total"


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        size = 2 if self.path == "/small" else REPLY_BYTES
        byte = b"x" if size == 2 else self.path.rsplit("/", 1)[-1].encode()
        assert len(byte) == 1
        self.send_response(200)
        self.send_header("Content-Length", str(size))
        self.end_headers()
        chunk = byte * (16 * 1024)
        try:
            for offset in range(0, size, len(chunk)):
                self.wfile.write(chunk[:min(size - offset, len(chunk))])
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def log_message(self, *_):
        pass


def metrics(port, tls):
    if tls:
        conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=3, context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request("GET", "/metrics")
        response = conn.getresponse()
        assert response.status == 200
        return {name: int(value) for name, _, value in
                (line.partition(" ") for line in response.read().decode().splitlines())
                if name in (JOBS, MEMORY, REUSED)}
    finally:
        conn.close()


def round_trip(port, tls):
    client = H2(port, tls)
    try:
        send = client.connection.sendall
        send(frame(4, 0, 0, struct.pack("!HI", 4, WINDOW)))
        for stream in STREAMS:
            client.request(stream, f"/large/{stream}".encode())

        received = dict.fromkeys(STREAMS, 0)
        ended = set()
        credit = False

        def consume(kind, flags, stream, payload):
            if stream not in received:
                return False
            assert kind != 3, ("stream reset", stream, payload)
            if kind == 1:
                assert payload.startswith(b"\x88"), (stream, payload)
            if kind == 0:
                assert payload == str(stream).encode() * len(payload), (stream, received[stream])
                received[stream] += len(payload)
                if flags & 1:
                    ended.add(stream)
                if credit and payload:
                    increment = struct.pack("!I", len(payload))
                    send(frame(8, 0, 0, increment) + frame(8, 0, stream, increment))
            return True

        while not all(count == WINDOW for count in received.values()):
            client.until(consume)
            assert max(received.values()) <= WINDOW, received
        client.ping()
        held = metrics(port, tls)
        assert held[JOBS] == len(STREAMS), held
        assert held[MEMORY] < 1024 * 1024, held

        client.request(9, b"/health")
        assert client.response(9) == (200, b"ok\n")
        credit = True
        send(b"".join(frame(8, 0, stream, struct.pack("!I", WINDOW)) for stream in STREAMS))
        deadline = time.monotonic() + 25
        while len(ended) < len(STREAMS):
            assert time.monotonic() < deadline, received
            client.until(consume)
            assert max(received.values()) <= REPLY_BYTES, received
        assert all(count == REPLY_BYTES for count in received.values()), received

        before = metrics(port, tls)[REUSED]
        client.request(11, b"/small")
        assert client.response(11) == (200, b"xx")
        assert metrics(port, tls)[REUSED] == before + 1
        return held[MEMORY]
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--rounds", type=int, default=1)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be positive")
    binary = args.binary.resolve(strict=True)
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin, tempfile.TemporaryDirectory(prefix="ll-h2-pressure-") as temporary:
        origin.daemon_threads = True
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        folder = pathlib.Path(temporary)
        try:
            for tls in (False, True):
                with socket.socket() as probe:
                    probe.bind(("127.0.0.1", 0))
                    port = probe.getsockname()[1]
                config = folder / "server.conf"
                config.write_text(f"""host = 127.0.0.1
port = {port}
tls = {str(tls).lower()}
admin_socket = off
proxy = http://127.0.0.1:{origin.server_port}
max_static_file_bytes = {REPLY_BYTES + 1}
upstream_timeout_ms = 30000
write_timeout_ms = 30000
graceful_shutdown_timeout_ms = 1200
""")
                log_path = folder / "server.log"
                with log_path.open("wb") as log:
                    process = subprocess.Popen([str(binary), "--config", str(config)], cwd=ROOT, stdout=log, stderr=log)
                    try:
                        until = time.monotonic() + 5
                        while True:
                            assert process.poll() is None and time.monotonic() < until, log_path.read_text()
                            try:
                                metrics(port, tls)
                                break
                            except OSError:
                                time.sleep(.05)
                        held = max(round_trip(port, tls) for _ in range(args.rounds))
                        until = time.monotonic() + 3
                        while True:
                            current = metrics(port, tls)
                            if current[JOBS] == 0 and current[MEMORY] == 0:
                                break
                            assert time.monotonic() < until, current
                            time.sleep(.02)
                        print(f"ok: {'TLS' if tls else 'plain'} {args.rounds} rounds of four 2 MiB streams, {held} tracked bytes while stalled", flush=True)
                    except BaseException:
                        print(log_path.read_text())
                        raise
                    finally:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=3)
        finally:
            origin.shutdown()


if __name__ == "__main__":
    main()
