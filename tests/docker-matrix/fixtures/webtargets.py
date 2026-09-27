#!/usr/bin/env python3
"""The multi-address HTTP target: ONE process binding several loopback
aliases (the rule-matrix probe IPs) on a few ports, serving a fixed body
per path. Binds:

    127.0.0.1:41800    the generic web target      /hello.txt
    127.126.0.1:41800  the GEOIP-CN probe alias
    127.0.0.99:41800   the IP-CIDR probe alias
    127.0.127.9:41800  the IP-SUFFIX probe alias
    127.0.128.5:41800  the IP-ASN probe alias
    127.0.0.2:41801    the DST-PORT probe
    127.0.0.3:41802    the IN-TYPE probe
    127.0.0.4:41802    the CLASH-MODE probe
    127.0.0.6:41803    the MATCH probe

Whole 127/8 is local, so any 127.x address is bindable and dialable
without leaving loopback (hermetic by construction).
"""
import http.server
import socket
import socketserver
import sys
import threading

BODY = {
    "/hello.txt": "matrix-target-ok",
    "/slow.txt": "matrix-slow-ok",
}

BINDS = [
    ("127.0.0.1", 41800),
    ("127.126.0.1", 41800),
    ("127.0.0.99", 41800),
    ("127.0.127.9", 41800),
    ("127.0.128.5", 41800),
    ("127.0.0.2", 41801),
    ("127.0.0.3", 41802),
    ("127.0.0.4", 41802),
    ("127.0.0.5", 41804),
    ("127.0.0.6", 41803),
]
V6_BINDS = [("::1", 41805)]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        slow = self.path.startswith("/slow")
        if slow:
            import time

            time.sleep(4)
        body = BODY.get(self.path if not slow else "/slow.txt", "matrix-target-ok")
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET


class Server6(Server):
    address_family = socket.AF_INET6


def main() -> int:
    servers = []
    for addr, port in BINDS:
        srv = Server((addr, port), Handler)
        servers.append(srv)
        print(f"webtarget {addr}:{port}", flush=True)
    for addr, port in V6_BINDS:
        srv = Server6((addr, port), Handler)
        servers.append(srv)
        print(f"webtarget [{addr}]:{port}", flush=True)
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("webtargets ready", flush=True)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
