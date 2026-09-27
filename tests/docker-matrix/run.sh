#!/bin/bash
# Feature-matrix e2e: EVERY user-facing feature, on THREE platforms, side
# by side — x86_64-glibc (the engine image binary), x86_64-musl (static
# musl build), aarch64-musl (cross-rs build under qemu-user).
#
# One container carries the whole world on loopback: the web targets
# (several 127.x aliases so the IP rules have hermetic probe IPs), the
# DNS oracle (UDP/TCP/DoT/DoH + :53 for the `system` upstream), the TLS
# camo site (reality/jls/restls camouflage), the UDP echo, a
# subscription HTTP server, the real mihomo binary as proxy server AND
# client, and the engine's own wireguard endpoint (sing-box dialect).
# The MINIMAL Country.mmdb + geosite.dat are generated in-container at
# test time (fixtures/gen-geodata.py) and land in $CRASHDIR/bin/geodata
# where the engine's loader picks them up.
#
# Hermetic (loopback only). Network-dependent steps, all cached on a
# warm host: the docker image pulls (engine image, rust:1.98-slim,
# cross-rs image) — nothing else touches the network.
#
# Usage: bash tests/docker-matrix/run.sh [platform...]   (default: all 3)
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
MUSL_DIR=/tmp/rustcrash-musl
QEMU_BIN=/tmp/qemu-aarch64
ARM64_BIN="$PROJECT_ROOT/target/aarch64-unknown-linux-musl/release/crash"

if [ $# -gt 0 ]; then
    PLATFORMS=("$@")
else
    PLATFORMS=(glibc musl arm64)
fi

DC="docker compose -f $COMPOSE_FILE"
sub() { $DC exec -T rustcrash "$@"; }

cleanup() {
    $DC down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== Feature-matrix e2e: 3 platforms x every feature ==="

# ---------------------------------------------------------------------------
# 0. Binaries: the engine image (glibc), the static musl build, the
#    cross-rs arm64 build, and the qemu-user runner.
# ---------------------------------------------------------------------------
echo "--- engine image (shared with tests/docker-engine) ---"
if ! docker image inspect docker-engine-rustcrash >/dev/null 2>&1 \
    || [ "${E2E_FORCE_BUILD:-0}" = "1" ]; then
    EXPORT_DIR=$(mktemp -d /tmp/rustcrash-matrix-export.XXXXXX)
    if git -C "$PROJECT_ROOT" archive HEAD | tar -x -C "$EXPORT_DIR" 2>/dev/null; then
        echo "  building from committed tree ($(git -C "$PROJECT_ROOT" describe --always --dirty 2>/dev/null || echo HEAD))"
        docker build --quiet -t docker-engine-rustcrash \
            -f "$PROJECT_ROOT/tests/docker-engine/Dockerfile.engine" "$EXPORT_DIR" \
            || { echo "image build failed"; exit 1; }
    else
        docker build --quiet -t docker-engine-rustcrash \
            -f "$PROJECT_ROOT/tests/docker-engine/Dockerfile.engine" "$PROJECT_ROOT" \
            || { echo "image build failed"; exit 1; }
    fi
    rm -rf "$EXPORT_DIR"
fi

echo "--- x86_64-musl static binary ---"
mkdir -p "$MUSL_DIR"
if [ ! -x "$MUSL_DIR/crash" ] || [ "${E2E_FORCE_BUILD:-0}" = "1" ]; then
    rm -f "$MUSL_DIR/crash"
    docker run --rm \
        -v "$PROJECT_ROOT":/src:ro \
        -v "$MUSL_DIR":/src/target \
        -w /src \
        rust:1.98-slim \
        bash -c '
rustup target add x86_64-unknown-linux-musl 2>/dev/null
apt-get update -qq && apt-get install -y -qq musl-tools >/dev/null 2>&1
cargo build --release --target x86_64-unknown-linux-musl --bin crash --features engine-full 2>&1 | grep "^error" && exit 1
exit 0
' | tail -3
    [ -x "$MUSL_DIR/x86_64-unknown-linux-musl/release/crash" ] || { echo "FATAL: musl build failed"; exit 1; }
    cp "$MUSL_DIR/x86_64-unknown-linux-musl/release/crash" "$MUSL_DIR/crash"
    chmod +x "$MUSL_DIR/crash"
fi
echo "  musl binary: $(ls -la "$MUSL_DIR/crash" 2>/dev/null | awk '{print $5}') bytes"

echo "--- aarch64-musl cross build + qemu-user ---"
if command -v cross >/dev/null 2>&1; then
    (cd "$PROJECT_ROOT" && cross build --release --target aarch64-unknown-linux-musl --bin crash --features engine-full >/tmp/rustcrash-matrix-cross.log 2>&1) \
        || tail -5 /tmp/rustcrash-matrix-cross.log
    [ -x "$ARM64_BIN" ] || { echo "FATAL: arm64 cross build failed (see /tmp/rustcrash-matrix-cross.log)"; exit 1; }
else
    [ -x "$ARM64_BIN" ] || { echo "FATAL: cross CLI missing and no cached arm64 binary"; exit 1; }
    echo "  cross CLI absent; using cached arm64 binary"
fi
if [ ! -x "$QEMU_BIN" ]; then
    docker create --name qemu-extract-matrix ghcr.io/cross-rs/aarch64-unknown-linux-musl:0.2.5 >/dev/null 2>&1
    docker cp qemu-extract-matrix:/usr/local/bin/qemu-aarch64 "$QEMU_BIN" >/dev/null 2>&1
    docker rm qemu-extract-matrix >/dev/null 2>&1
    chmod +x "$QEMU_BIN"
fi
[ -x "$QEMU_BIN" ] || { echo "FATAL: qemu-aarch64 unavailable"; exit 1; }
echo "  arm64: $(du -h "$ARM64_BIN" | cut -f1), qemu: $QEMU_BIN"

# ---------------------------------------------------------------------------
# 1. The container + shared servers.
# ---------------------------------------------------------------------------
export MUSL_BIN="$MUSL_DIR/crash" ARM64_BIN QEMU_BIN
$DC down -v --remove-orphans >/dev/null 2>&1 || true
$DC up -d >/dev/null || { echo "container start failed"; exit 1; }

port_open() { sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/'"$1"')' 2>/dev/null; }
wait_port() {
    local p=$1 tries="${2:-40}"
    for _ in $(seq 1 "$tries"); do port_open "$p" && return 0; sleep 1; done
    return 1
}

sub mkdir -p /tmp/matrix/certs /tmp/matrix/logs /tmp/rustcrash/bin/geodata \
    /tmp/matrix/mihomo-cli-home /tmp/matrix/kc /tmp/matrix/fw

echo "--- certs: CA + server pair (DoT/DoH + all TLS listeners) ---"
sub bash -c '
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout /tmp/matrix/certs/ca.key -out /tmp/matrix/certs/ca.crt \
    -subj /CN=matrix-test-ca \
    -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign \
    -addext subjectKeyIdentifier=hash >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -keyout /tmp/matrix/certs/server.key -out /tmp/matrix/certs/server.csr \
    -subj /CN=tls.test >/dev/null 2>&1
printf "subjectAltName=DNS:tls.test,DNS:dns.test,IP:127.0.0.1\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" > /tmp/matrix/certs/ext.cnf
openssl x509 -req -in /tmp/matrix/certs/server.csr \
    -CA /tmp/matrix/certs/ca.crt -CAkey /tmp/matrix/certs/ca.key \
    -CAcreateserial -days 2 -out /tmp/matrix/certs/server.crt \
    -extfile /tmp/matrix/certs/ext.cnf >/dev/null 2>&1
cp /tmp/matrix/certs/ca.crt /usr/local/share/ca-certificates/matrix-test-ca.crt
update-ca-certificates >/dev/null 2>&1
' && echo "  CA installed into the system store (engine TLS verifies it)"

echo "--- geodata: minimal Country.mmdb + geosite.dat ---"
sub python3 /matrix-fixtures/gen-geodata.py /tmp/rustcrash/bin/geodata
sub bash -c 'cp /matrix-fixtures/ruleset-provider.txt /tmp/matrix/ruleset-provider.txt'

echo "--- shared servers: web targets, dns oracle, camo, udp echo, subs ---"
sub bash -c 'nohup python3 /matrix-fixtures/webtargets.py >/tmp/matrix/logs/webtargets.log 2>&1 </dev/null &'
sub bash -c 'nohup python3 /matrix-fixtures/dns-oracle.py 41553 41853 41443 53 \
    /tmp/matrix/certs/server.crt /tmp/matrix/certs/server.key >/tmp/matrix/logs/dns-oracle.log 2>&1 </dev/null &'
sub bash -c 'nohup python3 /interop-fixtures/camo-tls.py 41843 \
    /tmp/matrix/certs/server.crt /tmp/matrix/certs/server.key >/tmp/matrix/logs/camo.log 2>&1 </dev/null &'
sub bash -c 'nohup python3 /interop-fixtures/udp-echo.py 41890 >/tmp/matrix/logs/udp-echo.log 2>&1 </dev/null &'
sub bash -c 'nohup python3 -m http.server 41880 --bind 127.0.0.1 --directory /matrix-fixtures/subs >/tmp/matrix/logs/subs.log 2>&1 </dev/null &'
sleep 2

# preflight each shared server
pre=0
body=$(sub bash -c "curl -s --max-time 4 http://127.0.0.1:41800/hello.txt" 2>/dev/null)
[ "$body" = "matrix-target-ok" ] && echo "  web targets up" || { echo "  WEB TARGETS FAILED: '$body'"; pre=1; }
ans=$(sub bash -c "dig +short +time=2 +tries=1 @127.0.0.1 -p 41553 a.test A 2>/dev/null | head -1")
[ "$ans" = "127.0.0.1" ] && echo "  dns oracle (udp) up" || { echo "  DNS ORACLE FAILED: '$ans'"; pre=1; }
ans=$(sub bash -c "dig +short +tcp +time=2 +tries=1 @127.0.0.1 -p 41553 a.test A 2>/dev/null | head -1")
[ "$ans" = "127.0.0.1" ] && echo "  dns oracle (tcp) up" || { echo "  DNS TCP FAILED: '$ans'"; pre=1; }
ans=$(sub bash -c "dig +short +time=3 +tries=1 +tls @127.0.0.1 -p 41853 dot.test A 2>/dev/null | head -1")
[ "$ans" = "127.0.0.1" ] && echo "  dns oracle (DoT) up" || { echo "  DNS DOT FAILED: '$ans'"; pre=1; }
ans=$(sub python3 -c "
import urllib.request, ssl, struct
q = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x03dot\x04test\x00' + struct.pack('>HH',1,1)
r = urllib.request.Request('https://127.0.0.1:41443/dns-query', data=q, headers={'Content-Type':'application/dns-message'})
ctx = ssl.create_default_context(cafile='/tmp/matrix/certs/ca.crt')
resp = urllib.request.urlopen(r, timeout=4, context=ctx)
print('ok' if resp.status==200 else resp.status)
" 2>/dev/null)
[ "$ans" = "ok" ] && echo "  dns oracle (DoH) up" || { echo "  DNS DOH FAILED: '$ans'"; pre=1; }
camo=$(sub bash -c "curl -sk --max-time 4 --http1.1 https://127.0.0.1:41843/" 2>/dev/null)
[ "$camo" = "camo-tls-page" ] && echo "  camo TLS site up" || { echo "  CAMO FAILED: '$camo'"; pre=1; }
if sub python3 -c "
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3)
s.sendto(b'pre',('127.0.0.1',41890))
d,_=s.recvfrom(1024);sys.exit(0 if d==b'ECHO:pre' else 1)
" 2>/dev/null; then echo "  udp echo up"; else echo "  UDP ECHO FAILED"; pre=1; fi
subs=$(sub bash -c "curl -s --max-time 4 http://127.0.0.1:41880/sub1.txt" 2>/dev/null)
echo "$subs" | grep -q sub1-ss && echo "  subscription http up" || { echo "  SUBS HTTP FAILED"; pre=1; }
[ "$pre" = 0 ] || { echo "FATAL: shared servers unhealthy"; exit 1; }

echo "--- real mihomo proxy server (14 listeners) ---"
MIHOMO_HOST_CACHE="${MIHOMO_CACHE_DIR:-$HOME/.cache/rustcrash-e2e}/mihomo"
MIHOMO_BIN=/usr/local/bin/mihomo
if [ -x "$MIHOMO_HOST_CACHE" ] && "$MIHOMO_HOST_CACHE" -v >/dev/null 2>&1; then
    $DC cp "$MIHOMO_HOST_CACHE" rustcrash:/tmp/matrix/mihomo >/dev/null 2>&1 \
        && sub chmod +x /tmp/matrix/mihomo 2>/dev/null \
        && MIHOMO_BIN=/tmp/matrix/mihomo \
        && echo "  using host-cached mihomo ($("$MIHOMO_HOST_CACHE" -v 2>/dev/null | head -1))"
fi
sub bash -c "nohup $MIHOMO_BIN -t -f /matrix-fixtures/mihomo-server.yaml -d /tmp/matrix/mihomo-home >/tmp/matrix/logs/mihomo-server-test.log 2>&1" \
    || { echo "  mihomo server config REJECTED:"; sub bash -c 'tail -3 /tmp/matrix/logs/mihomo-server-test.log'; exit 1; }
# SAFE_PATHS: mihomo only loads certs under its home dir or SAFE_PATHS
# (the interop suite's pattern).
sub bash -c "nohup env SAFE_PATHS=/tmp/matrix/certs $MIHOMO_BIN -f /matrix-fixtures/mihomo-server.yaml \
    -d /tmp/matrix/mihomo-home >/tmp/matrix/logs/mihomo-server.log 2>&1 </dev/null &"
MIHOMO_BOUND=0
for p in 42388 42389 42400 42401 42402 42403 42404 42405 42406 42407 42409 42410 42411 42412; do
    if wait_port "$p" 30; then MIHOMO_BOUND=$((MIHOMO_BOUND+1)); fi
done
echo "  mihomo listeners: $MIHOMO_BOUND/14 TCP bound (socks/http = 42409/42410)"
SNELL5_OK=$(sub bash -c "grep -c 'snell' /tmp/matrix/logs/mihomo-server.log 2>/dev/null | head -1" 2>/dev/null)
if ! wait_port 42408 10; then
    echo "  NOTE: mihomo snell v5 listener (:42408) not bound — the o-snell5 row will reflect it"
fi

echo "--- engine wireguard endpoint (sing-box dialect, serve_endpoint) ---"
sub bash -c 'nohup crash engine run --flavor rust-sing-box --config /matrix-fixtures/wg-server.json >/tmp/matrix/logs/wg-server.log 2>&1 </dev/null &'
if wait_port 42161 40; then echo "  wg endpoint up (mixed :42161, udp :42160)"; else
    echo "  WG ENDPOINT FAILED:"; sub bash -c 'tail -5 /tmp/matrix/logs/wg-server.log'; exit 1
fi

# sanity: one wg relay through the glibc engine before the batteries
WGOK=$(sub bash -c '
cat > /tmp/matrix/wg-client.yaml <<EOF
mixed-port: 42199
proxies:
  - name: wg
    type: wireguard
    private-key: CEPallHQzXQ2OIAxgB4M2Ng9lWH+Xhcwmwv5Pu54R2Q=
    ip: 172.19.0.2
    peers:
      - {server: 127.0.0.1, port: 42160, public-key: hSpZ638o2zcJ4RLj72HgeiXWzPlu8Xlxw0QXJeQ6Cyc=}
rules:
  - MATCH,wg
EOF
nohup crash engine run --flavor rust-mihomo --config /tmp/matrix/wg-client.yaml >/tmp/matrix/logs/wg-client.log 2>&1 </dev/null &
sleep 3
curl -s --max-time 8 -x http://127.0.0.1:42199 http://127.0.0.1:41800/hello.txt
pkill -f wg-client.yaml
')
if [ "$WGOK" = "matrix-target-ok" ]; then
    echo "  wireguard relay engine->engine->web: OK"
else
    echo "  WG RELAY PREFLIGHT: '$WGOK' (batteries will report honestly)"
fi

# ---------------------------------------------------------------------------
# 2. The batteries, one per platform; collect RESULT rows.
# ---------------------------------------------------------------------------
RESULTS_DIR=/tmp/rustcrash-matrix-results
mkdir -p "$RESULTS_DIR"
for plat in "${PLATFORMS[@]}"; do
    echo ""
    echo "=================== battery: $plat ==================="
    $DC exec -T rustcrash bash /matrix-fixtures/battery.sh "$plat" \
        | tee "$RESULTS_DIR/$plat.log" || true
done

# archive the in-container logs for post-mortems (before teardown)
for plat in "${PLATFORMS[@]}"; do
    $DC cp "rustcrash:/tmp/matrix/logs" "$RESULTS_DIR/logs-$plat" >/dev/null 2>&1 || true
done

# ---------------------------------------------------------------------------
# 3. The matrix table.
# ---------------------------------------------------------------------------
echo ""
echo "=== Feature Matrix ==="
python3 - "$RESULTS_DIR" "${PLATFORMS[@]}" <<'RENDER'
import os, sys

resdir = sys.argv[1]
plats = sys.argv[2:]
col_names = {"glibc": "x86-glibc", "musl": "x86-musl", "arm64": "arm64-musl"}

rows = []          # ordered labels
table = {}         # (plat, label) -> verdict
details = {}
for plat in plats:
    path = os.path.join(resdir, f"{plat}.log")
    if not os.path.exists(path):
        continue
    for line in open(path, encoding="utf-8", errors="replace"):
        parts = line.strip().split("|")
        if len(parts) < 4 or parts[0] != "RESULT":
            continue
        _, label, verdict, detail = parts[0], parts[1], parts[2], "|".join(parts[3:])
        if verdict == "INFO":
            continue
        if label not in rows:
            rows.append(label)
        table[(plat, label)] = verdict
        details[(plat, label)] = detail

plats = [p for p in plats if any((p, r) in table for r in rows)]
label_w = max([len("Feature")] + [len(r) for r in rows]) + 1
cell_w = 9
line = "-" * (label_w + 1) + "+" + ("-" * (cell_w + 2) + "+") * len(plats)
hdr = "Feature".ljust(label_w) + " |" + "".join(
    col_names[p].center(cell_w + 2) + "|" for p in plats
)
print(hdr)
print(line)
totals = {}
for p in plats:
    totals[p] = [0, 0]
for r in rows:
    cells = []
    for p in plats:
        v = table.get((p, r), "—")
        cells.append(v.center(cell_w + 2) + "|")
        if v == "PASS":
            totals[p][0] += 1
            totals[p][1] += 1
        elif v == "FAIL":
            totals[p][1] += 1
    print(r.ljust(label_w) + " |" + "".join(cells))
print(line)
tot_cells = ""
for p in plats:
    done, seen = totals[p]
    tot_cells += f"{done}/{seen}".center(cell_w + 2) + "|"
print("Total".ljust(label_w) + " |" + tot_cells)

# failures + skips detail
fails = [(p, r) for p in plats for r in rows if table.get((p, r)) == "FAIL"]
skips = [(p, r) for p in plats for r in rows if table.get((p, r)) == "SKIP"]
if fails:
    print("\nFAILURES:")
    for p, r in fails:
        print(f"  [{col_names[p]}] {r}: {details.get((p, r), '')[:160]}")
if skips:
    print(f"\nSKIPPED (labelled, not failures): {len(skips)}")
    for p, r in skips[:12]:
        print(f"  [{col_names[p]}] {r}: {details.get((p, r), '')[:140]}")
    if len(skips) > 12:
        print(f"  ... and {len(skips) - 12} more")
sys.exit(1 if fails else 0)
RENDER
rc=$?

echo ""
if [ $rc = 0 ]; then
    echo "=== Matrix GREEN ==="
else
    echo "=== Matrix has FAILURES (see above) ==="
fi
exit $rc
