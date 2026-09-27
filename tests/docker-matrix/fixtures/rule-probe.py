#!/usr/bin/env python3
"""Rule-hit oracle: open ONE connection through an engine inbound, keep
it open, read /connections, and report the outbound the rule ladder
picked (chains[0]).

  rule-probe.py <inbound-port> <api-port> <expected-outbound> <target-url> [options]
    --src-port N     bind the local source port N (SRC-PORT rule probe)
    --socks          speak SOCKS5 CONNECT first (for socks listeners)
    --udp            do a SOCKS5 UDP-ASSOCIATE probe instead (NETWORK,udp)
    --hold MS        how long to hold the conn before reading the API
                     (default 700; QEMU needs more — pass 2500)
    --peek HOST PORT another process (e.g. curl) already opened the
                     connection; report its chains

The connection is identified by the CLIENT source port
(metadata.sourcePort) — exact and immune to stale entries — with a
host/port fallback for peek mode.

Exit 0 = chains[0] == expected; prints the observed chain.
"""
import json
import socket
import struct
import sys
import time
import urllib.parse
import urllib.request


def api_connections(api_port: int):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{api_port}/connections", timeout=5
    ) as r:
        return json.loads(r.read())


def find_conn(conns, host, port, network, sport=None):
    """Identify OUR connection: sourcePort first (exact), then host,
    then newest matching destination port + network."""
    conns = conns.get("connections", [])
    if sport is not None:
        for c in conns:
            m = c.get("metadata", {})
            if str(m.get("sourcePort")) == str(sport) and (
                not network or m.get("network") == network
            ):
                return c
    for c in conns:
        m = c.get("metadata", {})
        if host and m.get("host") == host and (
            not network or m.get("network") == network
        ):
            return c
    candidates = [
        c
        for c in conns
        if c.get("metadata", {}).get("destinationPort") == str(port)
        and (not network or c.get("metadata", {}).get("network") == network)
    ]
    if candidates:
        return max(candidates, key=lambda c: c.get("start", 0))
    net_conns = [
        c
        for c in conns
        if not network or c.get("metadata", {}).get("network") == network
    ]
    return max(net_conns, key=lambda c: c.get("start", 0), default=None)


def http_request_head(target):
    u = urllib.parse.urlparse(target)
    host, port = u.hostname, u.port or 80
    return (
        f"GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"User-Agent: rule-probe\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
    ).encode(), host, port


def http_probe(in_port, target, src_port=None, hold=0.7):
    """HTTP-proxy absolute-form request; socket stays open."""
    req, host, port = http_request_head(target)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if src_port:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", src_port))
    s.settimeout(6)
    s.connect(("127.0.0.1", in_port))
    s.sendall(req)
    time.sleep(hold)
    return s, host, port


def socks_connect_probe(in_port, target, hold=0.7):
    """SOCKS5 CONNECT (for the socks listener) then the HTTP request in
    the tunnel; socket stays open."""
    req, host, port = http_request_head(target)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6)
    s.connect(("127.0.0.1", in_port))
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00", "socks greeting failed"
    host_b = host.encode()
    req_hdr = (
        b"\x05\x01\x00\x03"
        + bytes([len(host_b)])
        + host_b
        + struct.pack(">H", port)
    )
    s.sendall(req_hdr)
    resp = s.recv(10 + len(host_b) + 1)
    assert resp[:2] == b"\x05\x00", f"socks connect failed: {resp!r}"
    s.sendall(req)
    time.sleep(hold)
    return s, host, port


def socks_udp_probe(in_port, hold=0.7):
    """SOCKS5 UDP ASSOCIATE + one datagram to the UDP echo target."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6)
    s.connect(("127.0.0.1", in_port))
    s.sendall(b"\x05\x01\x00")  # greet, no auth
    assert s.recv(2) == b"\x05\x00", "socks greeting failed"
    s.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
    resp = s.recv(10)
    assert resp[:2] == b"\x05\x00", f"udp associate failed: {resp!r}"
    relay_ip = socket.inet_ntoa(resp[4:8])
    relay_port = struct.unpack(">H", resp[8:10])[0]
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(4)
    hdr = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + (41890).to_bytes(2, "big")
    u.sendto(hdr + b"rule-udp-probe", (relay_ip, relay_port))
    try:
        data, _ = u.recvfrom(2048)
    except socket.timeout:
        data = b""
    time.sleep(hold)
    return s, data


def main():
    in_port = int(sys.argv[1])
    api_port = int(sys.argv[2])
    expected = sys.argv[3]
    # the target is positional but optional: a leading -- means options
    # follow immediately and the default target is used
    rest = list(sys.argv[4:])
    if rest and rest[0].startswith("--"):
        target = "http://127.0.0.1:41800/hello.txt"
    else:
        target = rest.pop(0) if rest else "http://127.0.0.1:41800/hello.txt"
    src_port = None
    udp = False
    socks = False
    peek = None
    hold = 0.7
    args = rest
    i = 0
    while i < len(args):
        if args[i] == "--src-port":
            src_port = int(args[i + 1])
            i += 2
        elif args[i] == "--udp":
            udp = True
            i += 1
        elif args[i] == "--socks":
            socks = True
            i += 1
        elif args[i] == "--hold":
            hold = float(args[i + 1])
            i += 2
        elif args[i] == "--peek":
            peek = (args[i + 1], int(args[i + 2]))
            i += 3
        else:
            i += 1

    sock = None
    echo_ok = True
    if udp:
        sock, echo_data = socks_udp_probe(in_port, hold)
        # the reply carries the SOCKS UDP header before the payload
        echo_ok = b"ECHO:" in echo_data
        host, port, network, sport = "", 41890, "udp", sock.getsockname()[1]
    elif peek is not None:
        host, port = peek
        network = "tcp"
        sport = None
    elif socks:
        sock, host, port = socks_connect_probe(in_port, target, hold)
        network, sport = "tcp", sock.getsockname()[1]
    else:
        sock, host, port = http_probe(in_port, target, src_port, hold)
        network, sport = "tcp", sock.getsockname()[1]

    conns = api_connections(api_port)
    c = find_conn(conns, host, port, network, sport)
    if sock is not None:
        sock.close()
    if not c:
        print(f"NO_CONN host={host} port={port} net={network} sport={sport}")
        return 2
    chains = c.get("chains") or []
    observed = chains[0] if chains else "<none>"
    if udp:
        # The UDP session itself is not tracked in /connections; the
        # echo round-trip is the functional oracle (only the udp-capable
        # r-net-udp outbound can carry it).
        print(f"{observed} echo={'yes' if echo_ok else 'no'}")
        return 0 if echo_ok else 1
    print(f"{observed}")
    return 0 if observed == expected else 1


if __name__ == "__main__":
    sys.exit(main())
