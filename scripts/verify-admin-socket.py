#!/usr/bin/env python3
"""One bounded newline-framed admin command per Unix connection."""
import json
import socket
import sys
import time


def connect():
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(2)
    conn.connect(sys.argv[1])
    return conn


def read_all(conn):
    result = b""
    while True:
        try:
            part = conn.recv(4096)
        except ConnectionResetError:
            break
        if not part:
            break
        result += part
    return result


with connect() as conn:
    for part in [b"sta", b"tus"]:
        conn.sendall(part)
        conn.settimeout(0.05)
        try:
            premature = conn.recv(1)
        except TimeoutError:
            pass
        else:
            raise AssertionError(("admin executed an incomplete command", premature))
    conn.settimeout(2)
    conn.sendall(b"\n")
    assert json.loads(read_all(conn))["server"] == "Layerline"

with connect() as conn:
    conn.sendall(b"status\nstatus\n")
    assert json.loads(read_all(conn))["server"] == "Layerline", "more than one admin command executed"

with connect() as conn:
    conn.sendall(b"status")
    conn.shutdown(socket.SHUT_WR)
    assert b"requires a newline" in read_all(conn)

with connect() as conn:
    conn.sendall(b"x" * 1025)
    assert b"exceeds 1023" in read_all(conn)

with connect() as conn:
    started = time.monotonic()
    for _ in range(6):
        try:
            conn.sendall(b"x")
        except (BrokenPipeError, ConnectionResetError):
            break
        time.sleep(0.2)
    received = read_all(conn)
    assert not received or b"timed out" in received, received
    assert time.monotonic() - started < 1.8, "admin command traffic renewed its read budget"

print("ok: admin socket waits for a complete bounded command and trickle bytes cannot renew its deadline")
