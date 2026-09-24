#!/usr/bin/env python3
"""Minimal DNS upstream responder: answers every A query with 10.9.9.9 and
every AAAA with fd99::9, so the engine's redir-host path and the UDP relay
probe have a deterministic oracle. Runs on the given port (default 5353).
"""
import socket
import struct
import sys


def build_response(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    qid = query[:2]
    # Parse the single question.
    off = 12
    while off < len(query) and query[off] != 0:
        off += 1 + query[off]
    off += 1 + 4
    question = query[12:off]
    qtype = struct.unpack(">H", question[-4:-2])[0]

    def rr(name: bytes, rtype: int, rdata: bytes) -> bytes:
        # Answer NAME: pointer to the question at offset 12.
        ptr = b"\xc0\x0c"
        return ptr + struct.pack(">HHIH", rtype, 1, 30, len(rdata)) + rdata

    if qtype == 1:  # A
        answers = rr(question, 1, bytes([10, 9, 9, 9]))
    elif qtype == 28:  # AAAA
        answers = rr(question, 28, socket.inet_pton(socket.AF_INET6, "fd99::9"))
    else:
        answers = b""
    flags = 0x8180
    return qid + struct.pack(">HHHHH", flags, 1, 1 if answers else 0, 0, 0) + question + answers


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5353
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    print(f"dns-upstream listening on 127.0.0.1:{port}", flush=True)
    while True:
        data, peer = sock.recvfrom(4096)
        print(f"query from {peer}: {len(data)} bytes", flush=True)
        resp = build_response(data)
        if resp:
            sock.sendto(resp, peer)
            print(f"reply sent to {peer}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
