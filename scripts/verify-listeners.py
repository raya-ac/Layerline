#!/usr/bin/env python3
"""Listener startup is one transaction; control sockets belong to one server."""
import http.client
import os
from pathlib import Path
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Server:
    def __init__(self, folder, name, admin=None, extra="", tls=False):
        self.port = port()
        self.redirect = port()
        self.udp = port(socket.SOCK_DGRAM)
        self.admin = admin or folder / (name + ".sock")
        self.log = folder / (name + ".log")
        self.config = folder / (name + ".conf")
        self.config.write_text(f"""host = 127.0.0.1
port = {self.port}
tls = {'true' if tls else 'false'}
http_redirect = {'true' if tls else 'false'}
http_redirect_port = {self.redirect}
http_redirect_https_port = {self.port}
http3 = true
http3_port = {self.udp}
admin_socket = {self.admin}
graceful_shutdown_timeout_ms = 1200
""" + extra)
        self.tls = tls
        self.process = None

    def start(self):
        with self.log.open("wb") as output:
            self.process = subprocess.Popen([str(BINARY), "--config", str(self.config)], cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, umask=0)

    def text(self):
        return self.log.read_text()

    def ready(self):
        until = time.monotonic() + 4
        while time.monotonic() < until:
            assert self.process.poll() is None, self.text()
            if '"event":"server.ready"' in self.text():
                return
            time.sleep(.01)
        raise AssertionError(self.text())

    def status(self):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(1)
            client.connect(str(self.admin))
            client.sendall(b"status\n")
            result = b""
            while part := client.recv(4096):
                result += part
            assert b"Layerline" in result, result

    def http(self):
        client = http.client.HTTPSConnection("127.0.0.1", self.port, context=ssl._create_unverified_context(), timeout=2) if self.tls else http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        try:
            client.request("GET", "/health")
            reply = client.getresponse()
            reply.read()
            assert reply.status == 200
        finally:
            client.close()

    def stop(self, force=False):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGKILL if force else signal.SIGTERM)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
                raise AssertionError("listener shutdown hung: " + self.text())

    def failed(self):
        try:
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                raise AssertionError("startup did not fail: " + self.text()) from None
            assert self.process.returncode != 0, self.text()
            assert '"event":"server.ready"' not in self.text() and "Serving on " not in self.text(), self.text()
            # All successfully prepared listeners must have been released.
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", self.port))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(("127.0.0.1", self.udp))
        finally:
            self.stop()


with tempfile.TemporaryDirectory(prefix="ll-listeners-") as temporary:
    folder = Path(temporary)
    active = []
    try:
        for label in ["primary", "redirect"]:
            with socket.socket() as occupied:
                occupied.bind(("127.0.0.1", 0))
                occupied.listen(2)
                key = "port" if label == "primary" else "http_redirect_port"
                server = Server(folder, label + "-busy", tls=label == "redirect", extra=f"{key} = {occupied.getsockname()[1]}\n")
                active.append(server)
                server.start()
                server.failed()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(("127.0.0.1", 0))
            server = Server(folder, "udp-busy", extra=f"http3_port = {occupied.getsockname()[1]}\n")
            active.append(server)
            server.start()
            server.failed()
        for kind in ["file", "symlink", "live-socket", "lock-symlink"]:
            path = folder / (kind + ".sock")
            target = folder / (kind + ".sentinel")
            target.write_bytes(b"do not alter this file\n")
            old_socket = None
            if kind == "file":
                path.write_bytes(target.read_bytes())
            elif kind == "symlink":
                path.symlink_to(target)
            elif kind == "lock-symlink":
                Path(str(path) + ".lock").symlink_to(target)
            else:
                old_socket = socket.socket(socket.AF_UNIX)
                old_socket.bind(str(path))
                old_socket.listen(2)
            original = path.lstat().st_ino if path.exists() or path.is_symlink() else None
            server = Server(folder, kind, admin=path)
            active.append(server)
            server.start()
            try:
                server.failed()
                assert target.read_bytes() == b"do not alter this file\n"
                if original is not None:
                    assert path.lstat().st_ino == original, (kind, "existing path replaced")
            finally:
                if old_socket is not None:
                    old_socket.close()
        print("ok: failed configured UDP/admin listeners abort startup and preserve existing files, symlinks and active sockets", flush=True)

        server = Server(folder, "owned", tls=True)
        active.append(server)
        server.start()
        server.ready()
        server.status()
        server.http()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            destination = ("127.0.0.1", server.udp)
            client.sendto(b"malformed" * 800, destination)
            client.sendto(b"\xc0\x12\x34\x56\x78\x08abcdefgh\x08ijklmnop\x00\x01\x00", destination)
            packet, _ = client.recvfrom(4096)
            assert packet[1:5] == b"\x00" * 4 and b"\x00\x00\x00\x01" in packet, packet
        server.http()
        assert stat.S_IMODE(server.admin.stat().st_mode) == 0o600, "socket permissions depend on process umask"
        lock_inode = Path(str(server.admin) + ".lock").stat().st_ino
        rival = Server(folder, "rival", admin=server.admin)
        active.append(rival)
        rival.start()
        rival.failed()
        server.status()
        redirect = http.client.HTTPConnection("127.0.0.1", server.redirect, timeout=2)
        try:
            redirect.request("GET", "/")
            reply = redirect.getresponse()
            reply.read()
            assert reply.status in [301, 302, 307, 308]
        finally:
            redirect.close()
        server.stop(force=True)
        assert server.admin.exists()
        # SIGKILL releases the lock, but cannot remove the socket pathname.
        for _ in range(3):
            server.start()
            server.ready()
            server.status()
            server.http()
            server.stop()
            assert server.process.returncode == 0 and not server.admin.exists(), server.text()
            assert Path(str(server.admin) + ".lock").stat().st_ino == lock_inode
        print("ok: all listeners become ready together, malformed UDP stays isolated, control ownership survives SIGKILL and repeated restarts", flush=True)

        replacement = Server(folder, "replacement")
        active.append(replacement)
        replacement.start()
        replacement.ready()
        replacement.admin.rename(folder / "moved.sock")
        replacement.admin.write_text("replacement belongs to someone else\n")
        replacement.stop()
        assert replacement.admin.read_text() == "replacement belongs to someone else\n"
        print("ok: shutdown never removes a replacement at the old control socket path", flush=True)

        if sys.platform.startswith("linux") and os.geteuid() == 0:
            import pwd
            nobody = pwd.getpwnam("nobody")
            folder.chmod(0o711)
            server = Server(folder, "peer")
            active.append(server)
            server.start()
            server.ready()
            server.admin.chmod(0o666)
            code = ("import socket,sys\n"
                    "s=socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect(sys.argv[1])\n"
                    "try:\n"
                    " s.sendall(b'restart\\n')\n"
                    " data=s.recv(4096)\n"
                    "except (BrokenPipeError, ConnectionResetError):\n"
                    " data=b''\n"
                    "assert not data, data\n")
            subprocess.run([sys.executable, "-c", code, str(server.admin)], user=nobody.pw_uid, group=nobody.pw_gid, extra_groups=[], check=True, timeout=3)
            server.status()
            assert '"event":"server.admin_peer_rejected"' in server.text()
            server.stop()
            print("ok: kernel peer credentials reject another UID even with deliberately relaxed socket mode", flush=True)
    finally:
        for server in active:
            server.stop()
