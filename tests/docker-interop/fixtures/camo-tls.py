#!/usr/bin/env python3
"""The camouflage TLS site ("dest" oracle) for the interop suite.

The jls / res-tls / reality fronts on the real mihomo server point their
`dest` at a TLS site: unauthenticated or rejected clients are relayed to it
(that is the camouflage), so this site must be a REAL TLS 1.3 server. Every
connection is logged so run.sh can show the fallback path carried traffic.

Usage: camo-tls.py <port> <cert.pem> <key.pem>
"""

import os
import socket
import ssl
import sys
import threading

BODY = b"camo-tls-page\n"


def handle(tls: ssl.SSLSocket, peer: str) -> None:
    try:
        req = b""
        while b"\r\n\r\n" not in req and len(req) < 1 << 16:
            chunk = tls.recv(4096)
            if not chunk:
                break
            req += chunk
        first = req.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        print(f"[camo] {peer} tls-ok {first}", flush=True)
        resp = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(BODY)
        ) + BODY
        tls.sendall(resp)
    except Exception as exc:  # noqa: BLE001 - a probe connection may vanish
        print(f"[camo] {peer} error: {exc}", flush=True)
    finally:
        try:
            tls.close()
        except Exception:  # noqa: BLE001
            pass


def main() -> int:
    port = int(sys.argv[1])
    cert, key = sys.argv[2], sys.argv[3]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    print(f"[camo] TLS site on 127.0.0.1:{port}", flush=True)

    while True:
        conn, addr = srv.accept()
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[camo] {addr} handshake failed: {exc}", flush=True)
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            continue
        threading.Thread(target=handle, args=(tls, str(addr)), daemon=True).start()


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    sys.exit(main())
