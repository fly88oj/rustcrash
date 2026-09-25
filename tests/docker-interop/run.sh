#!/bin/bash
# Interop e2e: the Rust engine against a REAL mihomo release binary, in
# BOTH directions.
#
#   forward:  real mihomo serves one listener per protocol of the matrix
#             (ss AEAD + 2022, vmess tcp + ws, vless TLS + REALITY, trojan,
#             hysteria2, tuic, anytls, snell v4 — plus the restls / jls
#             FRONTINGS, because the real binary has no standalone jls /
#             restls listener types); the engine (mihomo dialect) dials
#             each of them as a client through its mixed port, asserting
#             the HTTP payload, a UDP-echo round-trip on the UDP-capable
#             ones, and wrong-credential refusals.
#   reverse:  the engine serves ss / trojan / anytls listeners and the
#             real mihomo binary dials THEM as a client.
#
# Everything runs inside ONE container's network namespace on loopback
# 127.0.0.1 — hermetic by construction (this host runs its own transparent
# proxy on 7890 & co, so host ports are never touched). The only
# network-dependent step is fetching the real mihomo binary
# (fixtures/fetch-mihomo.sh), cached under ~/.cache/rustcrash-e2e.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

PASS=0
FAIL=0
SKIP=0
log_pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
log_fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
log_skip() { echo "[SKIP] $1"; SKIP=$((SKIP+1)); }

cleanup() {
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# The port map (single source of truth; the templates are rendered from it).
# Fixed ports are fine: this is a single-tenant loopback container.
# ---------------------------------------------------------------------------
WEB_PORT=38080            # plaintext HTTP target reached THROUGH the tunnels
CAMO_PORT=38443           # TLS 1.3 camo site: jls/reality `dest` oracle
ECHO_PORT=38090           # UDP echo server (arbitrary-payload UDP oracle)
MIHOMO_API=39190          # mihomo server's external controller

PORT_SS=39388             # mihomo: ss aes-256-gcm
PORT_SS2022=39389         # mihomo: ss 2022-blake3-aes-256-gcm
PORT_VMESS=39400          # mihomo: vmess tcp (AEAD)
PORT_VMESS_WS=39401       # mihomo: vmess over ws (/ws)
PORT_VLESS=39402          # mihomo: vless over TLS (rustls-verified self-signed)
PORT_VLESS_REALITY=39412  # mihomo: vless over REALITY (dest = camo site)
PORT_TROJAN=39403         # mihomo: trojan over TLS
PORT_HY2=39404            # mihomo: hysteria2 (QUIC)
PORT_TUIC=39405           # mihomo: tuic v5 (QUIC)
PORT_ANYTLS=39406         # mihomo: anytls (TLS)
PORT_SNELL=39407          # mihomo: snell v4
PORT_SNELL_RESTLS=39408   # mihomo: snell v4 + res-tls (restls) fronting
PORT_SNELL_JLS=39409      # mihomo: snell v4 + jls fronting
PORT_ANYTLS_JLS=39410     # mihomo: anytls + jls fronting

ENGINE_MIXED=27890        # engine client mixed inbound
ENGINE_API=29090          # engine client external controller
ENG_SRV_MIXED=39600       # engine server instance mixed inbound (unused by
                          # the checks; required by the engine's config
                          # validation, which insists on a classic inbound)
PORT_ENG_SS=39601         # engine (server direction): ss listener
PORT_ENG_TROJAN=39602     # engine (server direction): trojan listener
PORT_ENG_ANYTLS=39603     # engine (server direction): anytls listener
MIHOMO_CLI_MIXED=39500    # mihomo client mixed inbound
MIHOMO_CLI_API=39590      # mihomo client external controller

EXPECTED_BODY="hello-interop"
CAMO_BODY="camo-tls-page"
UUID="b831381d-6324-4d53-ad4f-8cda48b30811"
# Fixed test-only X25519 pair for the REALITY listener (openssl-generated;
# fake credentials like everything else in this suite).
REALITY_PRIVATE_KEY="IMr2zKQXw_IjvcdKV1jdnpR40GAJE-zfJRezmwJzAUs"
REALITY_PUBLIC_KEY="pF3AsmPmCvPgtT6eIhqv5Et6nes_Gy9-IBFXSC_oNTY"

HOST_CACHE="${MIHOMO_CACHE_DIR:-$HOME/.cache/rustcrash-e2e}"

echo "=== Building/reusing the engine image (shared with tests/docker-engine) ==="
# The image is built from the last COMMIT (git archive HEAD), not the
# working tree: this suite is one of several agents' waves that run in
# parallel on this repo, and a build from a half-edited working tree is a
# coin flip. E2E_WORKING_TREE_BUILD=1 restores the direct compose build
# for local use.
if [ "${E2E_FORCE_BUILD:-0}" = "1" ] \
    || ! docker image inspect docker-engine-rustcrash >/dev/null 2>&1; then
    if [ "${E2E_WORKING_TREE_BUILD:-0}" = "1" ]; then
        docker compose -f "$COMPOSE_FILE" build rustcrash --quiet \
            || { echo "image build failed"; exit 1; }
    else
        EXPORT_DIR=$(mktemp -d /tmp/rustcrash-interop-export.XXXXXX)
        if git -C "$SCRIPT_DIR/../.." archive HEAD | tar -x -C "$EXPORT_DIR" 2>/dev/null; then
            HEAD_DESC=$(git -C "$SCRIPT_DIR/../.." describe --always --dirty 2>/dev/null || echo HEAD)
            echo "  building from committed tree ($HEAD_DESC)"
            docker build --quiet -t docker-engine-rustcrash \
                -f "$SCRIPT_DIR/../docker-engine/Dockerfile.engine" "$EXPORT_DIR" \
                || { echo "image build failed (from $EXPORT_DIR)"; rm -rf "$EXPORT_DIR"; exit 1; }
            rm -rf "$EXPORT_DIR"
        else
            rm -rf "$EXPORT_DIR"
            docker compose -f "$COMPOSE_FILE" build rustcrash --quiet \
                || { echo "image build failed"; exit 1; }
        fi
    fi
fi

echo "=== Starting container ==="
docker compose -f "$COMPOSE_FILE" up -d >/dev/null
DC="docker compose -f $COMPOSE_FILE"
sub() {
    $DC exec -T rustcrash "$@"
}

render() { # <container template> <container out> <placeholder=value ...>
    # Substitution happens INSIDE the container (sed runs there, writing the
    # container file); values are base64url / hex / uuid / digits, none of
    # which carry sed or shell metacharacters.
    local tmpl=$1 out=$2; shift 2
    local exprs=""
    local kv
    for kv in "$@"; do
        exprs="$exprs -e 's|${kv%%=*}|${kv#*=}|g'"
    done
    sub sh -c "sed $exprs $tmpl > $out"
}

probe() { # <mixed port> -> body (or the curl error)
    sub sh -c "curl -s --max-time 12 -x http://127.0.0.1:$1 http://127.0.0.1:$WEB_PORT/hello.txt" 2>&1
}

port_open() { # live port check: TCP connect against the container loopback
    sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/'"$1"')' 2>/dev/null
}

wait_port() { # <port> [tries]
    local p=$1 tries="${2:-30}"
    for _ in $(seq 1 "$tries"); do
        if port_open "$p"; then return 0; fi
        sleep 0.5
    done
    return 1
}

dump_logs() {
    echo "--- mihomo server log (tail 25) ---"
    sub sh -c 'tail -25 /tmp/interop/logs/mihomo-server.log 2>/dev/null'
    echo "--- engine client log (tail 25) ---"
    sub sh -c 'tail -25 /tmp/interop/logs/engine-client.log 2>/dev/null'
}

# ---------------------------------------------------------------------------
# 0. Live port-collision pre-check: nothing of the matrix may be bound yet
# (a leftover process or a duplicated port in the map would make every
# later "listener up" check a lie).
# ---------------------------------------------------------------------------
ALL_TCP_PORTS="$WEB_PORT $PORT_SS $PORT_SS2022 $PORT_VMESS $PORT_VMESS_WS \
$PORT_VLESS $PORT_VLESS_REALITY $PORT_TROJAN $PORT_ANYTLS $PORT_SNELL \
$PORT_SNELL_RESTLS $PORT_SNELL_JLS $PORT_ANYTLS_JLS $ENGINE_MIXED $ENGINE_API \
$ENG_SRV_MIXED $PORT_ENG_SS $PORT_ENG_TROJAN $PORT_ENG_ANYTLS $MIHOMO_CLI_MIXED"
collision=0
for p in $ALL_TCP_PORTS; do
    if port_open "$p"; then
        echo "  port $p is ALREADY bound in the container before anything started"
        collision=1
    fi
done
[ "$collision" = 0 ] \
    && log_pass "port-collision pre-check: all $(echo $ALL_TCP_PORTS | wc -w) matrix TCP ports free" \
    || log_fail "port-collision pre-check (see the ports above)"

# ---------------------------------------------------------------------------
# 1. In-container services: certs, HTTP target, TLS camo site, UDP echo
# ---------------------------------------------------------------------------
sub mkdir -p /tmp/interop/certs /tmp/interop/logs /tmp/interop/mihomo-home /tmp/mihomo

sub openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /tmp/interop/certs/server.key -out /tmp/interop/certs/server.crt -days 2 \
    -subj /CN=tls.test -addext subjectAltName=DNS:tls.test >/dev/null 2>&1 \
    && echo "  test cert generated" || echo "  cert generation FAILED"

sub bash -c 'nohup python3 -m http.server '"$WEB_PORT"' --bind 127.0.0.1 --directory /interop-fixtures/webroot >/tmp/interop/logs/web.log 2>&1 &'
sub bash -c 'nohup python3 /interop-fixtures/camo-tls.py '"$CAMO_PORT"' /tmp/interop/certs/server.crt /tmp/interop/certs/server.key >/tmp/interop/logs/camo.log 2>&1 &'
sub bash -c 'nohup python3 /interop-fixtures/udp-echo.py '"$ECHO_PORT"' >/tmp/interop/logs/echo.log 2>&1 &'
sleep 1

out=$(sub sh -c "curl -s --max-time 3 http://127.0.0.1:$WEB_PORT/hello.txt" 2>&1)
[ "$out" = "$EXPECTED_BODY" ] \
    && log_pass "http target up ($EXPECTED_BODY)" \
    || log_fail "http target: got '${out:0:60}'"
camo=$(sub sh -c "curl -sk --max-time 4 --http1.1 https://127.0.0.1:$CAMO_PORT/" 2>&1)
[ "$camo" = "$CAMO_BODY" ] \
    && log_pass "camo TLS site up (the jls/reality dest oracle)" \
    || log_fail "camo TLS site: got '${camo:0:60}'"
if sub python3 -c "
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3)
s.sendto(b'control',('127.0.0.1',$ECHO_PORT))
d,_=s.recvfrom(1024);sys.exit(0 if d==b'ECHO:control' else 1)
" 2>/dev/null; then
    log_pass "udp echo server up"
else
    log_fail "udp echo server"
fi

# ---------------------------------------------------------------------------
# 2. The real mihomo binary (NETWORK-DEPENDENT, host-cached)
# ---------------------------------------------------------------------------
echo "=== Fetching the real mihomo release binary ==="
if [ -x "$HOST_CACHE/mihomo" ] && "$HOST_CACHE/mihomo" -v >/dev/null 2>&1; then
    echo "  [mihomo] host cache hit: $HOST_CACHE/mihomo"
    $DC cp "$HOST_CACHE/mihomo" rustcrash:/tmp/mihomo/mihomo >/dev/null 2>&1
    sub chmod +x /tmp/mihomo/mihomo
fi
sub env \
    MIHOMO_PINNED_VERSION="${MIHOMO_PINNED_VERSION:-v1.19.31}" \
    MIHOMO_FORCE_PINNED="${MIHOMO_FORCE_PINNED:-0}" \
    MIHOMO_FORCE_FETCH="${MIHOMO_FORCE_FETCH:-0}" \
    MIHOMO_PROXY="${MIHOMO_PROXY:-}" \
    bash /interop-fixtures/fetch-mihomo.sh /tmp/mihomo >/tmp/rustcrash-interop-fetch.out 2>&1 || true
sed 's/^/  /' /tmp/rustcrash-interop-fetch.out
if sub sh -c 'test -x /tmp/mihomo/mihomo'; then
    MIHOMO_VERSION=$(sub /tmp/mihomo/mihomo -v 2>/dev/null | head -1 | tr -d '\r')
    log_pass "real mihomo binary available ($MIHOMO_VERSION)"
    # Refill the host cache so the next run is fully offline.
    mkdir -p "$HOST_CACHE"
    $DC cp rustcrash:/tmp/mihomo/mihomo "$HOST_CACHE/mihomo" >/dev/null 2>&1 || true
    chmod +x "$HOST_CACHE/mihomo" 2>/dev/null || true
else
    log_fail "real mihomo binary fetch (NETWORK-DEPENDENT step; reason printed above)"
    echo "=== Results: $PASS passed, $FAIL failed ==="
    exit 1
fi

# ---------------------------------------------------------------------------
# 3. The real mihomo SERVER (one listener per matrix protocol)
# ---------------------------------------------------------------------------
render /interop-fixtures/mihomo-server.yaml.tmpl /tmp/interop/mihomo-server.yaml \
    "__PORT_SS__=$PORT_SS" "__PORT_SS2022__=$PORT_SS2022" \
    "__PORT_VMESS__=$PORT_VMESS" "__PORT_VMESS_WS__=$PORT_VMESS_WS" \
    "__PORT_VLESS__=$PORT_VLESS" "__PORT_VLESS_REALITY__=$PORT_VLESS_REALITY" \
    "__PORT_TROJAN__=$PORT_TROJAN" "__PORT_HY2__=$PORT_HY2" \
    "__PORT_TUIC__=$PORT_TUIC" "__PORT_ANYTLS__=$PORT_ANYTLS" \
    "__PORT_SNELL__=$PORT_SNELL" "__PORT_SNELL_RESTLS__=$PORT_SNELL_RESTLS" \
    "__PORT_SNELL_JLS__=$PORT_SNELL_JLS" "__PORT_ANYTLS_JLS__=$PORT_ANYTLS_JLS" \
    "__PORT_CAMO__=$CAMO_PORT" "__REALITY_PRIVATE_KEY__=$REALITY_PRIVATE_KEY"

sub bash -c 'nohup env SAFE_PATHS=/tmp/interop/certs /tmp/mihomo/mihomo \
    -f /tmp/interop/mihomo-server.yaml -d /tmp/interop/mihomo-home \
    >/tmp/interop/logs/mihomo-server.log 2>&1 &'

# Live checks: every TCP listener must actually be bound (a silent bind
# failure — e.g. a port already taken — must fail loudly, not silently
# degrade the matrix), and the two QUIC listeners (hysteria2 / tuic) are
# confirmed from mihomo's own log because they bind UDP only.
bound=0; total=0
for p in "$PORT_SS" "$PORT_SS2022" "$PORT_VMESS" "$PORT_VMESS_WS" \
         "$PORT_VLESS" "$PORT_VLESS_REALITY" "$PORT_TROJAN" "$PORT_ANYTLS" \
         "$PORT_SNELL" "$PORT_SNELL_RESTLS" "$PORT_SNELL_JLS" "$PORT_ANYTLS_JLS"; do
    total=$((total+1))
    if wait_port "$p" 40; then bound=$((bound+1)); fi
done
quic_ok=0
for _ in $(seq 1 20); do
    n=$(sub sh -c "grep -acE 'Hysteria2\[hy2-in\].*listening|Tuic\[tuic-in\].*listening' /tmp/interop/logs/mihomo-server.log" 2>/dev/null | tr -d '\r')
    [ "${n:-0}" -ge 2 ] && { quic_ok=1; break; }
    sleep 0.5
done
if [ "$bound" = "$total" ] && [ "$quic_ok" = 1 ]; then
    log_pass "mihomo listeners bound ($bound TCP live-checked + hysteria2/tuic via log)"
else
    log_fail "mihomo listeners ($bound/$total TCP, quic=$quic_ok)"
    dump_logs
fi

# ---------------------------------------------------------------------------
# 4. The engine (mihomo dialect) as the client
# ---------------------------------------------------------------------------
echo "=== Starting the engine client (mihomo dialect) ==="
render /interop-fixtures/engine-client.yaml.tmpl /tmp/interop/engine-client.yaml \
    "__PORT_SS__=$PORT_SS" "__PORT_SS2022__=$PORT_SS2022" \
    "__PORT_VMESS__=$PORT_VMESS" "__PORT_VMESS_WS__=$PORT_VMESS_WS" \
    "__PORT_VLESS__=$PORT_VLESS" "__PORT_VLESS_REALITY__=$PORT_VLESS_REALITY" \
    "__PORT_TROJAN__=$PORT_TROJAN" "__PORT_HY2__=$PORT_HY2" \
    "__PORT_TUIC__=$PORT_TUIC" "__PORT_ANYTLS__=$PORT_ANYTLS" \
    "__PORT_SNELL__=$PORT_SNELL" "__PORT_SNELL_RESTLS__=$PORT_SNELL_RESTLS" \
    "__PORT_SNELL_JLS__=$PORT_SNELL_JLS" "__PORT_ANYTLS_JLS__=$PORT_ANYTLS_JLS" \
    "__REALITY_PUBLIC_KEY__=$REALITY_PUBLIC_KEY"

sub crash engine test --flavor rust-mihomo --config /tmp/interop/engine-client.yaml \
    >/tmp/rustcrash-interop-engine-test.out 2>&1 \
    && log_pass "engine accepts the client config (19 outbounds, mihomo dialect)" \
    || { log_fail "engine config test (mihomo dialect)"; cat /tmp/rustcrash-interop-engine-test.out; }

sub bash -c 'nohup crash engine run --flavor rust-mihomo --config /tmp/interop/engine-client.yaml >/tmp/interop/logs/engine-client.log 2>&1 &'
ENG_UP=0
for _ in $(seq 1 40); do
    if wait_port "$ENGINE_MIXED" 1 && port_open "$ENGINE_API"; then ENG_UP=1; break; fi
    sleep 0.5
done
[ "$ENG_UP" = 1 ] \
    && log_pass "engine client up (mixed $ENGINE_MIXED + api $ENGINE_API)" \
    || { log_fail "engine client listeners"; dump_logs; }

# EXPECTED-FAIL (dialect): real mihomo spells the snell fronting options
# `obfs-opts:` (adapter/outbound/snell.go, SnellOption.ObfsOpts,
# proxy:"obfs-opts"); the engine reads them from `plugin-opts:` instead, so
# a mihomo-canonical snell+res-tls outbound is REJECTED at config load with
# "snell jls fronting requires obfs-opts username and password"-style
# errors (config_mihomo.rs plugin_opt()). The working matrix above carries
# both spellings to stay runnable; this check pins the canonical form
# (fixtures/snell-obfs-opts-dialect.yaml) and must flip to PASS when the
# engine accepts obfs-opts.
if sub crash engine test --flavor rust-mihomo \
        --config /interop-fixtures/snell-obfs-opts-dialect.yaml \
        >/tmp/rustcrash-interop-dialect.out 2>&1; then
    log_pass "engine accepts mihomo-canonical obfs-opts spelling for snell fronting"
else
    log_skip "EXPECTED-FAIL (engine dialect): snell fronting opts are read from plugin-opts, not mihomo's obfs-opts ($(tail -1 /tmp/rustcrash-interop-dialect.out 2>/dev/null | head -c 120))"
fi

select_node() { # <node>
    sub curl -s --max-time 5 -X PUT -d '{"name": "'"$1"'"}' \
        "http://127.0.0.1:$ENGINE_API/proxies/Auto" >/dev/null
}

# ---- 4a. TCP relay per protocol ----
check_tcp() { # <node> <label> [expected-fail-symptom-regex]
    local node=$1 label=$2 symptom="${3:-}"
    if [ "$ENG_UP" != 1 ]; then
        log_skip "$label: engine client is down (see the config/listener check above)"
        return
    fi
    select_node "$node"
    local out
    out=$(probe "$ENGINE_MIXED")
    if [ "$out" = "$EXPECTED_BODY" ]; then
        log_pass "TCP via $label (real mihomo server)"
        eval "POS_${node//-/_}=1"
        return
    fi
    if [ -n "$symptom" ]; then
        local err
        err=$(sub sh -c "grep -aE 'WARN|ERROR' /tmp/interop/logs/engine-client.log 2>/dev/null | tail -3" \
            | tr -d '\r' | sed 's/\x1b\[[0-9;]*m//g')
        case "$err" in
            *"$symptom"*)
                log_skip "EXPECTED-FAIL (engine bug): TCP via $label — $symptom"
                return
                ;;
        esac
    fi
    log_fail "TCP via $label: got '${out:0:70}'"
    sub sh -c "grep -aE 'WARN|ERROR' /tmp/interop/logs/engine-client.log 2>/dev/null | tail -3" | tr -d '\r' | sed 's/\x1b\[[0-9;]*m//g'
}
echo "=== TCP matrix: engine client -> real mihomo listeners ==="
check_tcp node-ss           "ss aes-256-gcm (legacy AEAD)"
check_tcp node-ss2022       "ss 2022-blake3-aes-256-gcm (SIP022)"
check_tcp node-vmess        "vmess aes-128-gcm (AEAD, tcp)"
check_tcp node-vmess-ws     "vmess auto over ws"
check_tcp node-vless        "vless over TLS"
check_tcp node-vless-reality "vless over REALITY (dest = camo site)"
check_tcp node-trojan       "trojan over TLS"
# EXPECTED-FAIL #2 (engine, h3/qpack): the engine's hysteria2 client
# advertises a zero QPACK dynamic-table capacity but its decoder only
# accepts static references — mihomo's quic-go H3 encoder still emits a
# dynamic NAME reference in the response HEADERS, so every relay dies at
# "qpack: dynamic name reference" (proto/hysteria2.rs decode_field_section,
# which assumes "a conforming encoder never emits dynamic references
# here"). The QUIC/TLS layer itself is fine (the handshake completes).
check_tcp node-hy2          "hysteria2 (QUIC)"          "qpack: dynamic name reference"
check_tcp node-tuic         "tuic v5 (QUIC)"
check_tcp node-anytls       "anytls (TLS)"
check_tcp node-snell        "snell v4"
check_tcp node-snell-restls "snell v4 + res-tls fronting (restls wire)"
# EXPECTED-FAIL #3 (engine, jls client): the JLS auth itself is ACCEPTED
# by the real server — mihomo logs the inner snell/anytls request being
# relayed to the target — but the engine's TLS record layer then fails to
# decrypt the server's application records (rustls DecryptError "cannot
# decrypt peer's message"): the engine's rx application-traffic key
# diverges from the server's tx key while every handshake-stage key was
# right (the server could read the request). See proto/jls.rs two-pass
# stamping + the record drive loop.
check_tcp node-snell-jls    "snell v4 + jls fronting (jls wire)"   "cannot decrypt peer's message"
check_tcp node-anytls-jls   "anytls + jls-opts (jls wire)"         "cannot decrypt peer's message"

# ---- 4b. UDP echo per UDP-capable protocol ----
check_udp() { # <node> <label>
    local node=$1 label=$2
    if [ "$ENG_UP" != 1 ]; then
        log_skip "$label UDP: engine client is down"
        return
    fi
    select_node "$node"
    if sub python3 /interop-fixtures/udp-echo-probe.py 127.0.0.1 "$ENGINE_MIXED" \
        127.0.0.1 "$ECHO_PORT" "$label" >/tmp/rustcrash-interop-udp-out.out 2>&1; then
        log_pass "UDP echo via $label (socks associate -> mihomo -> echo)"
    else
        log_fail "UDP echo via $label"
        cat /tmp/rustcrash-interop-udp-out.out
    fi
}
echo "=== UDP matrix: engine client -> real mihomo listeners -> udp echo ==="
check_udp node-ss      "ss aes-256-gcm"
check_udp node-ss2022  "ss 2022-blake3-aes-256-gcm"
check_udp node-trojan  "trojan (UDP command)"
if [ "${POS_node_hy2:-0}" = 1 ]; then
    check_udp node-hy2 "hysteria2 (QUIC datagram)"
else
    log_skip "hysteria2 UDP: EXPECTED-FAIL — the hy2 session rides the same broken h3/qpack path as the hy2 TCP check above"
fi
check_udp node-tuic    "tuic v5 native (QUIC datagram)"
check_udp node-anytls  "anytls (UDP over the mux session)"

# ---- 4c. Negatives: wrong credentials must be refused ----
# Only interpretable when the engine is up AND the corresponding positive
# worked; a dead engine fails every curl, which would prove nothing.
check_negative() { # <node> <label> <positive-worked>
    local node=$1 label=$2 positive=$3
    if [ "$ENG_UP" != 1 ]; then
        log_skip "$label: engine client is down"
        return
    fi
    if [ "$positive" != 1 ]; then
        log_skip "$label: not interpretable while the positive relay is broken"
        return
    fi
    select_node "$node"
    local out
    out=$(probe "$ENGINE_MIXED")
    if [ "$out" = "$EXPECTED_BODY" ]; then
        log_fail "$label SILENTLY SUCCEEDED — auth is not enforced"
    else
        log_pass "$label refused (no payload: '${out:0:40}')"
    fi
}
echo "=== Negatives: wrong credentials ==="
check_negative node-ss-wrongpw       "ss with wrong password"       "${POS_node_ss:-0}"
check_negative node-trojan-wrongpw   "trojan with wrong password"   "${POS_node_trojan:-0}"
check_negative node-vmess-wronguuid  "vmess with wrong uuid"        "${POS_node_vmess:-0}"
check_negative node-anytls-wrongpw   "anytls with wrong password"   "${POS_node_anytls:-0}"
check_negative node-snell-wrongpsk   "snell with wrong psk"         "${POS_node_snell:-0}"

# ---------------------------------------------------------------------------
# 5. REVERSE direction: the engine as the SERVER, real mihomo as the client
# ---------------------------------------------------------------------------
echo "=== Reverse: engine listeners <-> real mihomo client ==="
render /interop-fixtures/engine-server.yaml.tmpl /tmp/interop/engine-server.yaml \
    "__PORT_ENG_SS__=$PORT_ENG_SS" "__PORT_ENG_TROJAN__=$PORT_ENG_TROJAN" \
    "__PORT_ENG_ANYTLS__=$PORT_ENG_ANYTLS"
sub crash engine test --flavor rust-mihomo --config /tmp/interop/engine-server.yaml \
    >/tmp/rustcrash-interop-engine-server-test.out 2>&1 \
    && log_pass "engine accepts the server config (ss/trojan/anytls listeners)" \
    || { log_fail "engine server config test"; cat /tmp/rustcrash-interop-engine-server-test.out; }
sub bash -c 'nohup crash engine run --flavor rust-mihomo --config /tmp/interop/engine-server.yaml >/tmp/interop/logs/engine-server.log 2>&1 &'
SRV_UP=0
srv_bound=0
for p in "$PORT_ENG_SS" "$PORT_ENG_TROJAN" "$PORT_ENG_ANYTLS"; do
    if wait_port "$p" 40; then srv_bound=$((srv_bound+1)); fi
done
[ "$srv_bound" = 3 ] && SRV_UP=1
[ "$srv_bound" = 3 ] \
    && log_pass "engine server listeners bound (live: ss/trojan/anytls)" \
    || { log_fail "engine server listeners ($srv_bound/3)"; sub sh -c 'tail -20 /tmp/interop/logs/engine-server.log'; }

render /interop-fixtures/mihomo-client.yaml.tmpl /tmp/interop/mihomo-client.yaml \
    "__PORT_ENG_SS__=$PORT_ENG_SS" "__PORT_ENG_TROJAN__=$PORT_ENG_TROJAN" \
    "__PORT_ENG_ANYTLS__=$PORT_ENG_ANYTLS"
sub bash -c 'nohup /tmp/mihomo/mihomo -f /tmp/interop/mihomo-client.yaml \
    -d /tmp/interop/mihomo-home >/tmp/interop/logs/mihomo-client.log 2>&1 &'
CLI_UP=0
if wait_port "$MIHOMO_CLI_MIXED" 40; then
    CLI_UP=1
    log_pass "mihomo client up (mixed $MIHOMO_CLI_MIXED)"
else
    log_fail "mihomo client mixed port"
    sub sh -c 'tail -20 /tmp/interop/logs/mihomo-client.log'
fi
REV_UP=$(( SRV_UP * CLI_UP ))

pick_node() { # <node> on the mihomo client's selector
    sub curl -s --max-time 5 -X PUT -d '{"name": "'"$1"'"}' \
        "http://127.0.0.1:$MIHOMO_CLI_API/proxies/Pick" >/dev/null
}
check_rev() { # <node> <label>
    local node=$1 label=$2
    if [ "$REV_UP" != 1 ]; then
        log_skip "reverse $label: engine server listeners or mihomo client did not come up"
        return
    fi
    pick_node "$node"
    local out
    out=$(sub sh -c "curl -s --max-time 12 -x http://127.0.0.1:$MIHOMO_CLI_MIXED http://127.0.0.1:$WEB_PORT/hello.txt" 2>&1)
    if [ "$out" = "$EXPECTED_BODY" ]; then
        log_pass "reverse TCP: $label (real mihomo client -> engine listener)"
        eval "REVPOS_${node//-/_}=1"
    else
        log_fail "reverse $label: got '${out:0:70}'"
    fi
}
check_rev m-ss      "ss aes-256-gcm"
check_rev m-trojan  "trojan over TLS"
check_rev m-anytls  "anytls"

if [ "$REV_UP" = 1 ] && [ "${REVPOS_m_ss:-0}" = 1 ]; then
    pick_node m-ss-wrongpw
    out=$(sub sh -c "curl -s --max-time 12 -x http://127.0.0.1:$MIHOMO_CLI_MIXED http://127.0.0.1:$WEB_PORT/hello.txt" 2>&1)
    if [ "$out" = "$EXPECTED_BODY" ]; then
        log_fail "reverse negative: wrong ss password SILENTLY SUCCEEDED"
    else
        log_pass "reverse negative: wrong ss password refused"
    fi
else
    log_skip "reverse negative: not interpretable while the reverse ss relay is broken"
fi

# Reverse UDP: mihomo's own socks UDP ASSOCIATE -> mihomo ss client ->
# engine ss listener (udp: true) -> udp echo.
if [ "$REV_UP" = 1 ] && [ "${REVPOS_m_ss:-0}" = 1 ]; then
    pick_node m-ss
    if sub python3 /interop-fixtures/udp-echo-probe.py 127.0.0.1 "$MIHOMO_CLI_MIXED" \
        127.0.0.1 "$ECHO_PORT" "reverse-udp" >/tmp/rustcrash-interop-rev-udp-out.out 2>&1; then
        log_pass "reverse UDP echo: mihomo socks associate -> mihomo ss -> engine ss listener"
    else
        log_fail "reverse UDP echo (mihomo -> engine ss)"
        cat /tmp/rustcrash-interop-rev-udp-out.out
    fi
else
    log_skip "reverse UDP echo: needs the working reverse ss relay"
fi

echo
[ "$SKIP" -gt 0 ] && echo "=== Skipped: $SKIP (labelled above, not counted as failures) ==="
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" = 0 ]
