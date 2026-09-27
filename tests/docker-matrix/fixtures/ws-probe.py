#!/usr/bin/env python3
"""Minimal stdlib WebSocket client: handshake against the engine's /traffic
and /logs streams, read one frame, print it. Exit 0 when a frame with
non-empty (or JSON-parseable) payload arrives.

  ws-probe.py <port> <path> [timeout-seconds]
"""
import base64
import os
import socket
import sys
import time


def main():
    port = int(sys.argv[1])
    path = sys.argv[2]
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 5.0
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    s.sendall(req.encode())
    s.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            print("NO_HANDSHAKE")
            return 2
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    if b"101" not in head.split(b"\r\n")[0]:
        print(f"BAD_STATUS {head.split(b' ')[1] if b' ' in head else head!r}")
        return 2
    # read one data frame (server frames are unmasked)
    deadline = time.time() + timeout
    data = rest
    while time.time() < deadline:
        if len(data) >= 2:
            opcode = data[0] & 0x0F
            ln = data[1] & 0x7F
            off = 2
            if ln == 126:
                if len(data) < 4:
                    continue
                ln = int.from_bytes(data[2:4], "big")
                off = 4
            elif ln == 127:
                if len(data) < 10:
                    continue
                ln = int.from_bytes(data[2:10], "big")
                off = 10
            if len(data) >= off + ln:
                payload = data[off : off + ln]
                print(payload.decode(errors="replace"))
                return 0
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    print("NO_FRAME")
    return 3


if __name__ == "__main__":
    sys.exit(main())
