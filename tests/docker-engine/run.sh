#!/bin/bash
# Engine interop e2e: the Rust engine (inside the crash binary) talks to a
# REAL mihomo binary over every implemented protocol, plus the sing-box
# dialect, the DNS/fake-IP path, and the UDP relay. Everything runs inside
# ONE container on internal loopback 127.0.0.1 — hermetic by construction.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

PASS=0
FAIL=0
log_pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
log_fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

cleanup() {
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Self-signed TLS pair for the vless/trojan listeners (test-only, never
# committed; regenerated whenever absent).
CERT_DIR="$SCRIPT_DIR/fixtures/certs"
if [ ! -f "$CERT_DIR/server.crt" ]; then
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
        -days 30 -subj "/CN=tls.test" >/dev/null 2>&1
fi

echo "=== Building engine interop image ==="
# Reuse the cached image unless missing or E2E_FORCE_BUILD=1 (offline /
# rerun-friendly; the image embeds the engine binary under test).
if [ "${E2E_FORCE_BUILD:-0}" = "1" ] \
    || ! docker image inspect docker-engine-rustcrash >/dev/null 2>&1; then
    docker compose -f "$COMPOSE_FILE" build rustcrash --quiet || {
        echo "image build failed"; exit 1;
    }
fi

echo "=== Starting container ==="
docker compose -f "$COMPOSE_FILE" up -d >/dev/null

DC="docker compose -f $COMPOSE_FILE"
sub() {
    $DC exec -T rustcrash "$@"
}

# ---- in-container services on 127.0.0.1 ----
sub bash -c 'nohup env SAFE_PATHS=/fixtures/certs mihomo -f /fixtures/mihomo-server.yaml -d /tmp/mihomo-home >/tmp/mihomo.log 2>&1 &'
sub bash -c 'nohup python3 -m http.server 38080 --bind 127.0.0.1 --directory /fixtures/webroot >/tmp/web.log 2>&1 &'
sub bash -c 'nohup python3 /fixtures/dns-upstream.py 35353 >/tmp/dns-up.log 2>&1 &'
sleep 2

sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/28388)' 2>/dev/null \
    && log_pass "mihomo ss listener up" \
    || { log_fail "mihomo ss listener"; sub sh -c 'tail -5 /tmp/mihomo.log'; }
sub curl -s --max-time 2 -o /dev/null http://127.0.0.1:38080/hello.txt \
    && log_pass "http target up" || log_fail "http target"
sub sh -c 'dig +short +time=2 +tries=1 @127.0.0.1 -p 35353 probe.upstream.test A | grep -q 10.9.9.9' \
    && log_pass "dns upstream up" || log_fail "dns upstream"

# ---- 1. engine version + config test (mihomo dialect) ----
sub crash engine version | grep -q "rustcrash-engine" \
    && log_pass "engine version" || log_fail "engine version"

sub mkdir -p /tmp/rustcrash/configs /tmp/rustcrash/logs
sub sh -c 'sed -e "s/DNS_UPSTREAM/127.0.0.1:35353/" /fixtures/engine-mihomo.template.yaml > /tmp/rustcrash/configs/mihomo.yaml'
sub crash engine test --flavor rust-mihomo >/dev/null 2>&1 \
    && log_pass "engine config test (mihomo dialect)" \
    || { log_fail "engine config test"; sub crash engine test --flavor rust-mihomo; }

# ---- 2. supervisor start via kernel selection ----
sub crash init --force >/dev/null 2>&1 || true
sub sh -c 'sed -i "s/^kernel: mihomo/kernel: rust-mihomo/" /tmp/rustcrash/config.yaml'
sub crash start start >/dev/null 2>&1 \
    && log_pass "crash start with kernel: rust-mihomo" || log_fail "crash start (engine)"
# Wait for the engine to bind its listeners (cold starts can exceed 1s).
for i in $(seq 1 20); do
    if sub curl -s --max-time 1 -o /dev/null http://127.0.0.1:29090/version; then break; fi
    sleep 0.5
done
sub crash start status | grep -q "Kernel: rust-mihomo" \
    && log_pass "status reports the engine selection" || log_fail "status selection"
sub sh -c 'test -f /tmp/rustcrash/run/rustcrash-engine.pid' \
    && log_pass "engine pid file present" || log_fail "engine pid file"
# Anti-loop gid on the engine process.
if sub sh -c 'grep "^Groups:" "/proc/$(cat /tmp/rustcrash/run/rustcrash-engine.pid)/status" | tr "\t " "\n" | grep -qx 7890' 2>/dev/null; then
    log_pass "engine runs with anti-loop gid 7890"
else
    log_fail "engine missing anti-loop gid"
fi

# ---- 3. Clash API ----
sub curl -s --max-time 3 http://127.0.0.1:29090/version | grep -q '"version"' \
    && log_pass "clash api /version" || log_fail "clash api /version"
sub curl -s --max-time 3 http://127.0.0.1:29090/proxies | grep -q "node-ss2022" \
    && log_pass "clash api /proxies lists nodes" || log_fail "clash api /proxies"

select_node() {
    sub curl -s --max-time 3 -X PUT -d '{"name": "'"$1"'"}' \
        http://127.0.0.1:29090/proxies/Auto >/dev/null
}

# ---- 4. TCP interop: curl through each protocol ----
check_tcp() {
    local node=$1 label=$2
    select_node "$node"
    local out
    out=$(sub sh -c 'curl -s --max-time 6 -x http://127.0.0.1:27890 http://127.0.0.1:38080/hello.txt' 2>&1)
    if [ "$out" = "hello-interop" ]; then
        log_pass "TCP via $label (real mihomo server)"
    else
        log_fail "TCP via $label: got '${out:0:60}'"
    fi
}
check_tcp node-ss "ss aes-256-gcm"
check_tcp node-ss2022 "ss 2022-blake3-aes-256-gcm"
check_tcp node-vmess "vmess aes-128-gcm (AEAD)"
check_tcp node-vmess-ws "vmess auto over ws"
check_tcp node-vless "vless (rustls)"
check_tcp node-trojan "trojan (rustls)"
check_tcp node-socks "socks5"
check_tcp node-http "http connect"

# Transparent listeners are bound (redir-port + the tproxy inbound from the
# sing-box section later binds 27896): full NAT steering is covered by the
# firewall e2e in tests/docker.
sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/27891)' 2>/dev/null \
    && log_pass "redir listener bound (27891)" || log_fail "redir listener"

# ---- 5. DNS hijack + fake-ip ----
fake=$(sub dig +short +time=3 +tries=1 @127.0.0.1 -p 27892 fake.query.test A 2>/dev/null | head -1)
case "$fake" in
    198.18.*) log_pass "dns hijack returns fake-ip ($fake)" ;;
    "") log_fail "dns hijack: empty answer" ;;
    *) log_fail "dns hijack: unexpected answer $fake" ;;
esac

# ---- 6. UDP relay: socks5 UDP associate -> ss -> mihomo -> upstream DNS ----
select_node node-ss
if sub python3 /fixtures/socks-udp-probe.py 127.0.0.1 27890 127.0.0.1 35353 udp.relay.test >/tmp/udp-probe-out 2>&1; then
    log_pass "UDP relay via ss (socks5 associate -> mihomo -> upstream DNS)"
else
    log_fail "UDP relay via ss"
    cat /tmp/udp-probe-out
    # Failure forensics: engine state at the moment of the miss.
    echo "--- forensics ---"
    sub sh -c 'date; ps aux | grep -E "engine|crash" | grep -v grep | head -6; tail -6 /tmp/rustcrash/logs/rustcrash-engine.log'
    sleep 2
    echo "--- retry probe:"
    sub python3 /fixtures/socks-udp-probe.py 127.0.0.1 27890 127.0.0.1 35353 udp.relay.test && echo "retry OK" || echo "retry FAILED"
fi

# ---- 6b. UDP over ss2022 and trojan (validates the upstream framings) ----
select_node node-ss2022
if sub python3 /fixtures/socks-udp-probe.py 127.0.0.1 27890 127.0.0.1 35353 udp.2022.test >/tmp/udp2022-out 2>&1; then
    log_pass "UDP relay via ss2022 (SIP022 headers)"
else
    log_fail "UDP relay via ss2022"
    cat /tmp/udp2022-out
fi
select_node node-trojan
if sub python3 /fixtures/socks-udp-probe.py 127.0.0.1 27890 127.0.0.1 35353 udp.trojan.test >/tmp/udptrojan-out 2>&1; then
    log_pass "UDP relay via trojan (CRLF framing vs real mihomo)"
else
    log_fail "UDP relay via trojan"
    cat /tmp/udptrojan-out
fi
select_node node-ss

# ---- 7. sing-box dialect ----
sub bash -c 'pkill -9 -f "engine run --flavor rust-sing-box" 2>/dev/null; true'
sub sh -c 'cat > /tmp/rustcrash/configs/sing-box.json <<EOF
{
  "inbounds": [
    {"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 27895},
    {"type": "tproxy", "tag": "tp", "listen": "0.0.0.0", "listen_port": 27896}
  ],
  "outbounds": [
    {"type": "shadowsocks", "tag": "sb-ss", "server": "127.0.0.1", "server_port": 28388,
     "method": "aes-256-gcm", "password": "interop-ss-psk-123456"},
    {"type": "vmess", "tag": "sb-vm", "server": "127.0.0.1", "server_port": 28401,
     "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "security": "auto",
     "transport": {"type": "ws", "path": "/ws"}},
    {"type": "selector", "tag": "pick", "outbounds": ["sb-ss", "sb-vm"]}
  ],
  "route": {"rules": [{"domain_suffix": ["direct.test"], "outbound": "direct"}], "final": "pick"},
  "dns": {"servers": [{"tag": "u", "address": "udp://127.0.0.1:35353"}]}
}
EOF'
sub crash engine test --flavor rust-sing-box >/dev/null 2>&1 \
    && log_pass "engine config test (sing-box dialect)" \
    || { log_fail "sing-box dialect test"; sub crash engine test --flavor rust-sing-box; }

sub bash -c 'nohup crash engine run --flavor rust-sing-box >/tmp/sb-run.log 2>&1 &'
for i in $(seq 1 20); do
    sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/27895)' 2>/dev/null && break
    sleep 0.5
done
out=$(sub sh -c 'curl -s --max-time 6 -x http://127.0.0.1:27895 http://127.0.0.1:38080/hello.txt' 2>&1)
[ "$out" = "hello-interop" ] \
    && log_pass "TCP via sing-box dialect (ss through selector)" \
    || { log_fail "sing-box dialect TCP: got '${out:0:60}'"; sub sh -c 'tail -5 /tmp/sb-run.log'; }
# Switch the selector to the vmess-ws outbound through the clash API.
sub curl -s --max-time 3 -X PUT -d '{"name": "sb-vm"}' \
    http://127.0.0.1:29090/proxies/pick >/dev/null 2>&1
out=$(sub sh -c 'curl -s --max-time 6 -x http://127.0.0.1:27895 http://127.0.0.1:38080/hello.txt' 2>&1)
[ "$out" = "hello-interop" ] \
    && log_pass "sing-box dialect: vmess-over-ws outbound through selector" \
    || log_fail "sing-box dialect vmess-ws"
# The sing-box config's tproxy inbound must be listening (transparent UDP+TCP).
sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/27896)' 2>/dev/null \
    && log_pass "tproxy listener bound via sing-box dialect (27896)" \
    || log_fail "tproxy listener (sing-box dialect)"
sub bash -c 'pkill -9 -f "engine run --flavor rust-sing-box" 2>/dev/null; true'

# ---- 7b. TUN device inbound (NET_ADMIN + /dev/net/tun in this container) ----
# The device node is not in the base image; create it (CAP_MKNOD) — the
# host kernel's tun module serves it.
sub sh -c 'mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200 2>/dev/null; true'
sub sh -c 'cat > /tmp/rustcrash/configs/tun.yaml <<EOF
mixed-port: 0
mode: rule
log-level: debug
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - udp://127.0.0.1:35353
proxies:
  - {name: direct, type: socks5, server: 127.0.0.1, port: 1}
rules:
  - MATCH,DIRECT
tun:
  enable: true
  device: rtun0
  inet4-address: 198.18.0.1/30
  mtu: 1500
  dns-hijack: [198.18.0.2]
EOF'
sub bash -c 'nohup crash engine run --flavor rust-mihomo --config /tmp/rustcrash/configs/tun.yaml >/tmp/tun-run.log 2>&1 &'
TUN_OK=0
for i in $(seq 1 20); do
    if sub sh -c 'ip addr show rtun0 2>/dev/null | grep -q "198.18.0.1"'; then
        TUN_OK=1; break
    fi
    sleep 0.5
done
if [ "$TUN_OK" = 1 ]; then
    log_pass "tun inbound attaches rtun0 with its address (NET_ADMIN)"
    # A UDP packet through the device must reach the relay (dns-hijack
    # destination 198.18.0.0 → answered by the engine resolver; the
    # upstream in the fixture is unreachable from this config, so the
    # observable is that the stack consumed the packet and replied).
    if sub python3 - <<'PY'
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
# DNS query for a fake-ip name via the hijack destination.
qid = 0x1234
name = b"\x04fake\x05query\x04test\x00"
query = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + name + struct.pack(">HH", 1, 1)
s.sendto(query, ("198.18.0.2", 53))
try:
    data, _ = s.recvfrom(2048)
    print("tun-dns-answer", len(data))
    sys.exit(0 if len(data) > 12 else 1)
except Exception as e:
    print("tun-dns-err", e)
    sys.exit(1)
PY
    then
        log_pass "tun: DNS-hijacked UDP answered through the netstack"
    else
        log_fail "tun: DNS-hijacked UDP"
    fi
else
    log_fail "tun inbound attach"
    sub sh -c 'tail -5 /tmp/tun-run.log'
fi
sub bash -c 'pkill -9 -f "config /tmp/rustcrash/configs/tun.yaml" 2>/dev/null; sleep 0.5; ip link del rtun0 2>/dev/null; true'

# ---- 8. watchdog restart ----
ENGINE_PID=$(sub sh -c 'cat /tmp/rustcrash/run/rustcrash-engine.pid' 2>/dev/null | tr -d '\r\n')
export ENGINE_PID
if [ -n "$ENGINE_PID" ]; then
    sub sh -c 'kill -9 "$ENGINE_PID"' >/dev/null 2>&1 || true
fi
# Enable the REST API in the management config (in-place edit — appending
# would create a duplicate YAML key that breaks config parsing).
sub sh -c 'sed -i "s/^api_enabled: false/api_enabled: true/" /tmp/rustcrash/config.yaml; grep -q "^api_enabled: true" /tmp/rustcrash/config.yaml || printf "api_enabled: true\n" >> /tmp/rustcrash/config.yaml'
sub bash -c 'nohup crash start serve >/tmp/serve.log 2>&1 &'
sleep 35
if sub sh -c 'grep "^Groups:" "/proc/$(cat /tmp/rustcrash/run/rustcrash-engine.pid)/status" 2>/dev/null' | tr "\t " "\n" | grep -qx 7890; then
    log_pass "watchdog restarted the engine (with anti-loop gid)"
else
    log_fail "watchdog engine restart"
    sub sh -c 'tail -10 /tmp/serve.log' 2>/dev/null
fi
out=$(sub sh -c 'curl -s --max-time 6 -x http://127.0.0.1:27890 http://127.0.0.1:38080/hello.txt' 2>&1)
[ "$out" = "hello-interop" ] && log_pass "proxy works after watchdog restart" || log_fail "post-restart proxy"

# Stop the supervisor first (it would restart the engine after the stop).
sub bash -c 'pkill -9 -f "crash start serve" 2>/dev/null; pkill -9 -f "start serve" 2>/dev/null; true'
sleep 1
sub crash start stop >/tmp/stop-out 2>&1 && log_pass "crash stop (engine)" \
    || { log_fail "crash stop"; sub sh -c 'cat /tmp/stop-out 2>/dev/null | head -3'; }

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" = 0 ]
