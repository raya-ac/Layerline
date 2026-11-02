"""Small raw HTTP/2 peer for bounded-resource wire tests, not a conformance client."""
import socket
import ssl
import time


def frame(kind, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


class H2:
    def __init__(self, port, tls=False):
        self.connection = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.tls = tls
        if tls:
            context = ssl._create_unverified_context()
            context.set_alpn_protocols(["h2"])
            self.connection = context.wrap_socket(self.connection, server_hostname="localhost")
            assert self.connection.selected_alpn_protocol() == "h2"
        self.connection.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))

    def request(self, stream, path):
        def literal(name, value):
            assert len(name) < 127 and len(value) < 127
            return b"\0" + bytes([len(name)]) + name + bytes([len(value)]) + value
        self.connection.sendall(frame(1, 5, stream, b"\x82" + (b"\x87" if self.tls else b"\x86") + literal(b":authority", b"localhost") + literal(b":path", path)))

    def exact(self, count):
        result = b""
        while len(result) < count:
            part = self.connection.recv(count - len(result))
            if not part:
                raise EOFError("HTTP/2 transport ended under resource pressure")
            result += part
        return result

    def until(self, predicate):
        until = time.monotonic() + 3
        while True:
            self.connection.settimeout(max(.01, until - time.monotonic()))
            header = self.exact(9)
            kind, flags, stream = header[3], header[4], int.from_bytes(header[5:], "big")
            payload = self.exact(int.from_bytes(header[:3], "big"))
            if kind == 4 and not flags & 1:
                self.connection.sendall(frame(4, 1, 0))
            assert kind != 7, ("unexpected GOAWAY", payload)
            if predicate(kind, flags, stream, payload):
                return
            assert time.monotonic() < until

    def response(self, stream):
        headers, body = bytearray(), bytearray()
        def complete(kind, flags, number, payload):
            if number != stream:
                return False
            assert kind != 3, ("response reset", stream, payload)
            if kind in [1, 9]:
                headers.extend(payload)
            if kind == 0:
                body.extend(payload)
            return kind in [0, 1] and flags & 1
        self.until(complete)
        # These tests inspect the stock encoder's first :status field. Wider
        # interoperability tests must use an independent HPACK implementation.
        if headers.startswith(b"\x88"):
            status = 200
        else:
            assert headers.startswith(b"\x00\x07:status\x03"), headers[:30]
            status = int(headers[10:13])
        return status, bytes(body)

    def ping(self):
        self.connection.sendall(frame(6, 0, 0, b"bounded!"))
        self.until(lambda k, f, s, p: k == 6 and f == 1 and s == 0 and p == b"bounded!")

    def close(self):
        self.connection.close()
