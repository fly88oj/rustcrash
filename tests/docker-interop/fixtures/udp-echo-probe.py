#!/usr/bin/env python3
"""SOCKS5 UDP-echo probe: opens a UDP ASSOCIATE on a SOCKS5/mixed inbound,
sends a random nonce to the UDP echo server THROUGH the tunnel and asserts
the nonce is echoed back. Exit 0 only on a full round-trip.

Usage: udp-echo-probe.py <proxy_ip> <proxy_port> <echo_ip> <echo_port> [label]
"""

import random
import socket
import struct
import sys
import time


def read_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("short read")
        buf += chunk
    return buf


def main() -> int:
    proxy_ip, proxy_port, echo_ip, echo_port = (
        sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]),
    )
    label = sys.argv[5] if len(sys.argv) > 5 else "probe"

    tcp = socket.create_connection((proxy_ip, proxy_port), timeout=10)
    tcp.sendall(b"\x05\x01\x00")
    assert read_exact(tcp, 2) == b"\x05\x00", "greeting refused"
    tcp.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0))
    head = read_exact(tcp, 4)
    assert head[:2] == b"\x05\x00", f"associate failed code={head[1]}"
    if head[3] != 1:
        raise SystemExit(f"{label}: unexpected atyp {head[3]} in associate reply")
    bnd = read_exact(tcp, 4 + 2)
    relay_ip = socket.inet_ntoa(bnd[:4])
    relay_port = struct.unpack(">H", bnd[4:6])[0]

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(10)
    nonce = b"udp-interop-" + bytes(random.randrange(1, 256) for _ in range(16))
    packet = (
        b"\x00\x00\x00\x01"
        + socket.inet_aton(echo_ip)
        + struct.pack(">H", echo_port)
        + nonce
    )
    udp.sendto(packet, (relay_ip, relay_port))

    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            data, _ = udp.recvfrom(65535)
        except socket.timeout:
            break
        # SOCKS5 UDP relays prepend RSV/FRAG/ATYP/addr/port (10 bytes for
        # an IPv4 target) to the carried payload on the way back; the echo
        # payload must match the nonce exactly at the datagram's end.
        payload = data[10:] if data[:3] == b"\x00\x00\x00" and len(data) > 10 else data
        if payload == b"ECHO:" + nonce:
            print(f"{label}: udp echo round-trip ok ({len(data)} bytes)")
            return 0
        # A different datagram (late answer from an earlier probe): keep waiting.
    print(f"{label}: udp echo round-trip FAILED (no matching answer)", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
