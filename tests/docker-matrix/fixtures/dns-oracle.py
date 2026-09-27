#!/usr/bin/env python3
"""The hermetic DNS oracle: one process, four transports, deterministic
answers, everything on loopback.

  UDP   --port      (plain RFC 1035 datagrams)
  TCP   --port      (2-byte length framed, same port)
  DoT   --tls-port  (TCP + TLS 1.2/1.3, RFC 7858)
  DoH   --doh-port  (HTTPS GET ?dns= / POST application/dns-message,
                     RFC 8484; HTTP/1.1)

Answer table (A queries only; AAAA -> fd99::9, anything else -> NODATA):
    geoip-cn.test        -> 127.126.0.1   (the CN-mapped loopback alias)
    <anything>.test      -> 127.0.0.1     (the local web target)
    <anything>.sys.test  -> 127.0.0.1     (same; distinct NAME proves
                                           which upstream answered)
    everything else      -> 10.9.9.9      (never dialed; TEST-NET-2)

Every name is answered by every transport with its own marker in the
answer so the SUITE can tell WHICH upstream served it: the TXT-style
marker is not needed — the source port of the query in the oracle's log
plus the engine's own config make the mapping unambiguous, so the A
record itself is the oracle.
"""
import base64
import http.server
import socket
import socketserver
import ssl
import struct
import sys
import threading

A_TEST = "127.0.0.1"
A_CN = "127.126.0.1"
A_OTHER = "10.9.9.9"
AAAA = "fd99::9"


def qname_of(query: bytes) -> str:
    off = 12
    labels = []
    while off < len(query) and query[off] != 0:
        n = query[off]
        labels.append(query[off + 1 : off + 1 + n].decode("latin1"))
        off += 1 + n
    return ".".join(labels)


def build_response(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    qid = query[:2]
    off = 12
    while off < len(query) and query[off] != 0:
        off += 1 + query[off]
    off += 1 + 4
    question = query[12:off]
    qtype = struct.unpack(">H", question[-4:-2])[0]
    name = qname_of(query)

    def rr(rtype: int, rdata: bytes) -> bytes:
        return b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 30, len(rdata)) + rdata

    if qtype == 1:  # A
        if name == "geoip-cn.test":
            answers = rr(1, socket.inet_aton(A_CN))
        elif name.endswith(".test"):
            answers = rr(1, socket.inet_aton(A_TEST))
        else:
            answers = rr(1, socket.inet_aton(A_OTHER))
    elif qtype == 28:  # AAAA
        answers = rr(28, socket.inet_pton(socket.AF_INET6, AAAA))
    else:
        answers = b""
    flags = 0x8180
    return (
        qid
        + struct.pack(">HHHHH", flags, 1, 1 if answers else 0, 0, 0)
        + question
        + answers
    )


def handle_datagram(sock: socket.socket) -> None:
    data, peer = sock.recvfrom(4096)
    resp = build_response(data)
    if resp:
        sock.sendto(resp, peer)


def serve_udp(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    print(f"dns-oracle udp 127.0.0.1:{port}", flush=True)
    while True:
        handle_datagram(sock)


def serve_tcp(conn: socket.socket) -> None:
    try:
        while True:
            hdr = conn.recv(2)
            if len(hdr) < 2:
                return
            (n,) = struct.unpack(">H", hdr)
            query = b""
            while len(query) < n:
                chunk = conn.recv(n - len(query))
                if not chunk:
                    return
                query += chunk
            resp = build_response(query)
            if resp:
                conn.sendall(struct.pack(">H", len(resp)) + resp)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve_tcp_listener(port: int, wrap=None) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    label = "DoT" if wrap else "tcp"
    print(f"dns-oracle {label} 127.0.0.1:{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        if wrap:
            try:
                conn = wrap(conn)
            except (ssl.SSLError, OSError):
                continue
        threading.Thread(target=serve_tcp, args=(conn,), daemon=True).start()


class DohHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _close_tls_cleanly(self):
        """Send close_notify before closing: the engine's DoH client
        reads to EOF and treats a bare close as a TLS error."""
        self.close_connection = True
        try:
            self.connection = self.connection.unwrap()
        except Exception:
            pass

    def _answer(self, query: bytes) -> bytes:
        resp = build_response(query)
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)
        self._close_tls_cleanly()

    def do_GET(self):
        if not self.path.startswith("/dns-query"):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            self._close_tls_cleanly()
            return
        qs = self.path.split("?", 1)[1] if "?" in self.path else ""
        for kv in qs.split("&"):
            if kv.startswith("dns="):
                b64 = kv[4:]
                b64 += "=" * (-len(b64) % 4)
                self._answer(base64.urlsafe_b64decode(b64))
                return
        self.send_response(400)
        self.send_header("Content-Length", "0")
        self.end_headers()
        self._close_tls_cleanly()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self._answer(self.rfile.read(n))

    def log_message(self, *args):
        pass


class DohServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 41553
    tls_port = int(sys.argv[2]) if len(sys.argv) > 2 else 41853
    doh_port = int(sys.argv[3]) if len(sys.argv) > 3 else 41443
    sys_port = int(sys.argv[4]) if len(sys.argv) > 4 else 53
    cert = sys.argv[5] if len(sys.argv) > 5 else None
    key = sys.argv[6] if len(sys.argv) > 6 else None

    threads = [
        threading.Thread(target=serve_udp, args=(port,), daemon=True),
        threading.Thread(target=serve_udp, args=(sys_port,), daemon=True),
        threading.Thread(target=serve_tcp_listener, args=(port,), daemon=True),
        threading.Thread(target=serve_tcp_listener, args=(sys_port,), daemon=True),
    ]
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        threads.append(
            threading.Thread(
                target=serve_tcp_listener,
                args=(tls_port, lambda c: ctx.wrap_socket(c, server_side=True)),
                daemon=True,
            )
        )
        doh = DohServer(("127.0.0.1", doh_port), DohHandler)
        doh.socket = ctx.wrap_socket(doh.socket, server_side=True)
        threads.append(
            threading.Thread(target=doh.serve_forever, daemon=True)
        )
    for t in threads:
        t.start()
    print("dns-oracle ready", flush=True)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
