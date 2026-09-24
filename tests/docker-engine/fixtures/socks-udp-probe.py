#!/usr/bin/env python3
"""SOCKS5 UDP probe: sends a DNS query through a SOCKS5 UDP ASSOCIATE and
prints the response size. Used by the interop tests to verify the whole
UDP path (socks inbound -> rules -> ss outbound -> real mihomo server ->
upstream DNS).

Usage: socks-udp-probe.py <proxy_ip> <proxy_port> <dns_ip> <dns_port> <qname>
Exit 0 when a DNS response with matching id came back.
"""
import socket
import struct
import sys
import random


def dns_query(qname: str) -> bytes:
    qid = random.randint(0, 65535)
    parts = qname.strip(".").split(".")
    name = b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"
    return qid, struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + name + struct.pack(">HH", 1, 1)


def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("short read")
        buf += chunk
    return buf


def main():
    proxy_ip, proxy_port, dns_ip, dns_port, qname = (
        sys.argv[1],
        int(sys.argv[2]),
        sys.argv[3],
        int(sys.argv[4]),
        sys.argv[5],
    )
    tcp = socket.create_connection((proxy_ip, proxy_port), timeout=5)
    tcp.sendall(b"\x05\x01\x00")
    assert read_exact(tcp, 2) == b"\x05\x00", "greeting refused"
    tcp.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0))
    head = read_exact(tcp, 4)
    assert head[:2] == b"\x05\x00", f"associate failed {head[1]}"
    if head[3] == 1:
        bnd = read_exact(tcp, 4 + 2)
        relay_ip = socket.inet_ntoa(bnd[:4])
        relay_port = struct.unpack(">H", bnd[4:])[0]
    else:
        raise SystemExit(f"unexpected atyp {head[3]}")

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(5)
    qid, query = dns_query(qname)
    udp.sendto(
        b"\x00\x00\x00\x01" + socket.inet_aton(dns_ip) + struct.pack(">H", dns_port) + query,
        (relay_ip, relay_port),
    )
    data, _ = udp.recvfrom(4096)
    assert len(data) > 12, "runt response"
    # Skip the SOCKS UDP header: RSV(2) FRAG(1) ATYP(1) addr port.
    off = 3
    atyp = data[off]
    off += 1
    if atyp == 1:
        off += 4
    elif atyp == 3:
        off += 1 + data[off]
    elif atyp == 4:
        off += 16
    off += 2
    dns = data[off:]
    rcode = dns[3] & 0xF
    resp_id = struct.unpack(">H", dns[:2])[0]
    assert resp_id == qid, "id mismatch"
    print(f"udp-ok rcode={rcode} bytes={len(data)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
