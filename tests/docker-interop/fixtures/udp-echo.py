#!/usr/bin/env python3
"""UDP echo server: replies to every datagram with ECHO:<same payload>.

The UDP interop checks send a nonce through the whole chain
(socks5 UDP ASSOCIATE -> engine outbound -> real mihomo listener -> this
echo) and assert the nonce comes back. Unlike a DNS oracle this proves
arbitrary payload round-trips, not just a well-formed resolver.

Usage: udp-echo.py <port>
"""

import os
import socket
import sys


def main() -> int:
    port = int(sys.argv[1])
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    print(f"[echo] UDP echo on 127.0.0.1:{port}", flush=True)
    while True:
        data, addr = srv.recvfrom(65535)
        srv.sendto(b"ECHO:" + data, addr)


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    sys.exit(main())
