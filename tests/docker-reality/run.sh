#!/bin/bash
# REALITY e2e: the Rust engine's REALITY client against a REAL Xray server.
#
# The engine's REALITY client (engine/src/proto/reality/) was ported from the
# XTLS sources line by line and, until this suite, had never touched a live
# server. This is the acceptance test: a real Xray binary serves REALITY
# vless inbounds whose `dest` is a local TLS site, the engine dials them as a
# client through the mihomo dialect, and the suite asserts the positive relay
# plus the negative (wrong short id / wrong public key) cases.
#
# Two local TLS cams ("dest" sites) are run on purpose, because Xray's REALITY
# server *mirrors the dest's ServerHello* (cipher suite included) and zero-pads
# its handshake records to the dest's record sizes:
#   * camo A: python/OpenSSL, default suite preference  -> dest picks 0x1302
#   * camo B: openssl s_server restricted to 0x1301     -> dest picks 0x1301
# The engine's TLS 1.3 stack implements 0x1301/0x1303 only and takes the last
# byte of a record as its content type (RFC 8446 says: last NON-ZERO byte), so
# the two cams separate "cannot agree a suite" from "padded record misread".
#
# Everything runs inside ONE container's network namespace on loopback
# 127.0.0.1 — hermetic by construction, except the one network-dependent step
# that downloads the real Xray binary (see fixtures/fetch-xray.sh).
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
# Fixed parameters (single-tenant loopback container, so fixed ports are fine)
# ---------------------------------------------------------------------------
CAMO_PORT=8444           # camo A: python TLS site, REALITY's `dest`
CAMO_1301_PORT=8449      # camo B: openssl s_server, TLS 1.3 0x1301 only
HTTP_PORT=38080          # plaintext HTTP target reached THROUGH the tunnel
REALITY_NOVISION_PORT=8443  # vless no-flow  (dest = camo A)
REALITY_VISION_PORT=8445    # vless flow xtls-rprx-vision (dest = camo A)
REALITY_1301_PORT=8446      # vless no-flow  (dest = camo B)
XRAY_SOCKS_PORT=27900    # xray's own client (the vision oracle) socks inbound
MIXED_GOOD=27890         # engine mixed port: correct REALITY config -> 8443
MIXED_BAD_SHORT=27891    # engine mixed port: wrong short id       -> 8443
MIXED_BAD_KEY=27892      # engine mixed port: wrong public key     -> 8443
MIXED_1301=27895         # engine mixed port: good config          -> 8446
UUID="b831381d-6324-4d53-ad4f-8cda48b30811"
SHORT_ID="0123456789abcdef"
WRONG_SHORT_ID="ffffffffffffffff"
EXPECTED_BODY="hello-reality"
CAMO_BODY="camo-page"

echo "=== Building/reusing the engine image (shared with tests/docker-engine) ==="
# The REALITY suite needs no extra image content: the engine binary is the
# workspace build, and the real Xray binary is fetched inside the container.
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

# Log tails, so a wire mismatch is debuggable from CI output alone.
dump_logs() {
    local engine_log="${1:-/tmp/engine-good.log}"
    echo "--- xray log (tail 30) ---"
    sub sh -c 'tail -30 /tmp/xray.log 2>/dev/null'
    echo "--- engine log $engine_log (tail 30) ---"
    sub sh -c "tail -30 $engine_log 2>/dev/null"
    echo "--- camo A (python) log (tail 8) ---"
    sub sh -c 'tail -8 /tmp/camo.log 2>/dev/null'
    echo "--- camo B (openssl) log (tail 8) ---"
    sub sh -c 'tail -8 /tmp/camo1301.log 2>/dev/null'
}

engine_error() { # <engine log> -> the last wire/protocol error line
    sub sh -c "grep -aE 'tls13:|reality:|REALITY' $1 2>/dev/null | tail -1" \
        | tr -d '\r' | sed 's/\x1b\[[0-9;]*m//g'
}

probe() { # <mixed port> -> body (or the curl error)
    sub sh -c "curl -s --max-time 8 -x http://127.0.0.1:$1 http://127.0.0.1:$HTTP_PORT/hello.txt" 2>&1
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

# ---------------------------------------------------------------------------
# 0. In-container services: the two camo TLS sites and the HTTP target
# ---------------------------------------------------------------------------
sub mkdir -p /tmp/rustcrash/configs /tmp/rustcrash/logs
sub crash init --force >/dev/null 2>&1 || true

# The camo certificate is generated in-container (test-only, never committed).
sub openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /tmp/camo.key -out /tmp/camo.crt -days 2 \
    -subj /CN=camo.test -addext subjectAltName=DNS:camo.test >/dev/null 2>&1 \
    && echo "  camo cert generated" || echo "  camo cert generation FAILED"

sub bash -c 'nohup python3 /reality-fixtures/camo-tls.py '"$CAMO_PORT"' /tmp/camo.crt /tmp/camo.key >/tmp/camo.log 2>&1 &'
# Camo B: a TLS 1.3 server that offers ONLY TLS_AES_128_GCM_SHA256 (0x1301),
# the suite the engine implements. Its ServerHello is what Xray mirrors, so
# this makes the REALITY handshake get past the cipher-suite step.
sub bash -c 'nohup openssl s_server -accept '"$CAMO_1301_PORT"' -cert /tmp/camo.crt \
    -key /tmp/camo.key -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -www >/tmp/camo1301.log 2>&1 &'
sub bash -c 'nohup python3 -m http.server '"$HTTP_PORT"' --bind 127.0.0.1 --directory /reality-fixtures/webroot >/tmp/web.log 2>&1 &'
sleep 1

sub curl -s --max-time 2 -o /dev/null "http://127.0.0.1:$HTTP_PORT/hello.txt" \
    && log_pass "http target up" || log_fail "http target"
camo=$(sub curl -sk --max-time 3 "https://127.0.0.1:$CAMO_PORT/" 2>&1)
[ "$camo" = "$CAMO_BODY" ] \
    && log_pass "camo A up (python TLS site, the REALITY dest oracle)" \
    || { log_fail "camo A: got '${camo:0:60}'"; sub sh -c 'tail -5 /tmp/camo.log'; }
camo_b=$(sub sh -c "echo | openssl s_client -connect 127.0.0.1:$CAMO_1301_PORT -tls1_3 2>/dev/null | grep -m1 'Cipher is'" | tr -d '\r')
case "$camo_b" in
    *TLS_AES_128_GCM_SHA256*) log_pass "camo B up (openssl TLS 1.3, 0x1301 only)" ;;
    *) log_fail "camo B: got '${camo_b:0:60}'"; sub sh -c 'tail -5 /tmp/camo1301.log' ;;
esac

# ---------------------------------------------------------------------------
# 1. The real Xray binary (NETWORK-DEPENDENT)
# ---------------------------------------------------------------------------
echo "=== Fetching the real Xray binary ==="
if [ -n "${XRAY_ZIP:-}" ] && [ -f "${XRAY_ZIP:-}" ]; then
    # Offline escape hatch: a host-side Xray-linux-64.zip (documented in the
    # README), for hosts where GitHub is unreachable. A distribution zip, not
    # a repo source.
    echo "  [xray] using pre-downloaded $XRAY_ZIP"
    $DC cp "$XRAY_ZIP" rustcrash:/tmp/xray-dl-host.zip >/dev/null 2>&1
    sub python3 -c "
import zipfile, os
zipfile.ZipFile('/tmp/xray-dl-host.zip').extract('xray', '/tmp/xray-extract')
os.makedirs('/tmp/xray', exist_ok=True)
os.replace('/tmp/xray-extract/xray', '/tmp/xray/xray')
os.chmod('/tmp/xray/xray', 0o755)" || true
else
    # XRAY_PINNED_VERSION / XRAY_FORCE_PINNED / XRAY_PROXY are forwarded so a
    # run can pin the server release (or use a proxy) without editing files.
    sub env \
        XRAY_PINNED_VERSION="${XRAY_PINNED_VERSION:-v25.6.8}" \
        XRAY_FORCE_PINNED="${XRAY_FORCE_PINNED:-0}" \
        XRAY_PROXY="${XRAY_PROXY:-}" \
        bash /reality-fixtures/fetch-xray.sh /tmp/xray || true
fi
if sub sh -c 'test -x /tmp/xray/xray'; then
    XRAY_VERSION=$(sub /tmp/xray/xray version 2>/dev/null | head -1 | tr -d '\r')
    log_pass "real Xray binary available ($XRAY_VERSION)"
else
    log_fail "real Xray binary fetch (NETWORK-DEPENDENT step; the reason is printed above)"
    echo "=== Results: $PASS passed, $FAIL failed ==="
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. REALITY server config (keypair, short id, camo dest) and the server
# ---------------------------------------------------------------------------
echo "=== Generating the REALITY keypair with xray x25519 ==="
KEYPAIR=$(sub /tmp/xray/xray x25519 2>&1)
printf '%s\n' "$KEYPAIR" | sed 's/^/  /'
# Output spelling differs across releases: "PrivateKey:"/"Password (PublicKey):"
# in v25.9+/v26, "Private key:"/"Public key:" earlier.
PRIV=$(printf '%s\n' "$KEYPAIR" | sed -n 's/^[Pp]rivate[ _]*[Kk]ey:[[:space:]]*//p' | head -1)
PUB=$(printf '%s\n' "$KEYPAIR" \
    | sed -n -e 's/^[Pp]assword[[:space:]]*([Pp]ublic[Kk]ey):[[:space:]]*//p' \
             -e 's/^[Pp]ublic[ _]*[Kk]ey:[[:space:]]*//p' | head -1)
if [ -z "$PUB" ] && [ -n "$PRIV" ]; then
    PUB=$(sub /tmp/xray/xray x25519 -i "$PRIV" 2>&1 \
        | sed -n -e 's/^[Pp]assword[[:space:]]*([Pp]ublic[Kk]ey):[[:space:]]*//p' \
                 -e 's/^[Pp]ublic[ _]*[Kk]ey:[[:space:]]*//p' | head -1)
fi
[ -n "$PRIV" ] && log_pass "xray x25519 produced a private key" \
    || log_fail "xray x25519 private key parse (output: $(printf '%s' "$KEYPAIR" | head -1))"
[ -n "$PUB" ] && log_pass "xray x25519 produced the matching public key" \
    || log_fail "xray x25519 public key parse"
# An unrelated but well-formed X25519 public key, for the negative check.
WRONG_PUB=$(sub /tmp/xray/xray x25519 2>&1 \
    | sed -n -e 's/^[Pp]assword[[:space:]]*([Pp]ublic[Kk]ey):[[:space:]]*//p' \
             -e 's/^[Pp]ublic[ _]*[Kk]ey:[[:space:]]*//p' | head -1)
[ -n "$WRONG_PUB" ] || WRONG_PUB="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

render /reality-fixtures/xray-server.json.tmpl /tmp/xray-server.json \
    "__UUID__=$UUID" \
    "__PRIVATE_KEY__=$PRIV" \
    "__SHORT_ID__=$SHORT_ID" \
    "__CAMO_PORT__=$CAMO_PORT" \
    "__CAMO_1301_PORT__=$CAMO_1301_PORT" \
    "__SERVER_PORT_NOVISION__=$REALITY_NOVISION_PORT" \
    "__SERVER_PORT_VISION__=$REALITY_VISION_PORT" \
    "__SERVER_PORT_1301__=$REALITY_1301_PORT"
sub python3 -c 'import json;json.load(open("/tmp/xray-server.json"))' 2>/dev/null \
    && log_pass "xray server config rendered (valid JSON)" \
    || { log_fail "xray server config render"; sub sh -c 'head -40 /tmp/xray-server.json'; }

sub bash -c 'nohup /tmp/xray/xray run -c /tmp/xray-server.json >/tmp/xray.log 2>&1 &'
for _ in $(seq 1 30); do
    sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/'"$REALITY_NOVISION_PORT"')' 2>/dev/null && break
    sleep 0.5
done
if sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/'"$REALITY_NOVISION_PORT"')' 2>/dev/null; then
    log_pass "xray REALITY listener up (vless/reality on $REALITY_NOVISION_PORT)"
else
    log_fail "xray REALITY listener"
    sub sh -c 'tail -30 /tmp/xray.log'
fi

# ---------------------------------------------------------------------------
# 3. Engine (client) configs and instances
# ---------------------------------------------------------------------------
echo "=== Starting the engine as the REALITY client ==="
render /reality-fixtures/engine-reality.tmpl.yaml /tmp/engine-good.yaml \
    "__MIXED_PORT__=$MIXED_GOOD" "__SERVER_PORT__=$REALITY_NOVISION_PORT" \
    "__UUID__=$UUID" "__PUBLIC_KEY__=$PUB" "__SHORT_ID__=$SHORT_ID" \
    "__FINGERPRINT__=chrome"
render /reality-fixtures/engine-reality.tmpl.yaml /tmp/engine-badshort.yaml \
    "__MIXED_PORT__=$MIXED_BAD_SHORT" "__SERVER_PORT__=$REALITY_NOVISION_PORT" \
    "__UUID__=$UUID" "__PUBLIC_KEY__=$PUB" "__SHORT_ID__=$WRONG_SHORT_ID" \
    "__FINGERPRINT__=chrome"
render /reality-fixtures/engine-reality.tmpl.yaml /tmp/engine-badkey.yaml \
    "__MIXED_PORT__=$MIXED_BAD_KEY" "__SERVER_PORT__=$REALITY_NOVISION_PORT" \
    "__UUID__=$UUID" "__PUBLIC_KEY__=$WRONG_PUB" "__SHORT_ID__=$SHORT_ID" \
    "__FINGERPRINT__=chrome"
render /reality-fixtures/engine-reality.tmpl.yaml /tmp/engine-1301.yaml \
    "__MIXED_PORT__=$MIXED_1301" "__SERVER_PORT__=$REALITY_1301_PORT" \
    "__UUID__=$UUID" "__PUBLIC_KEY__=$PUB" "__SHORT_ID__=$SHORT_ID" \
    "__FINGERPRINT__=chrome"
render /reality-fixtures/engine-reality.tmpl.yaml /tmp/engine-firefox.yaml \
    "__MIXED_PORT__=27894" "__SERVER_PORT__=$REALITY_NOVISION_PORT" \
    "__UUID__=$UUID" "__PUBLIC_KEY__=$PUB" "__SHORT_ID__=$SHORT_ID" \
    "__FINGERPRINT__=firefox"

sub crash engine test --flavor rust-mihomo --config /tmp/engine-good.yaml >/tmp/reality-engine-test.out 2>&1 \
    && log_pass "engine accepts the REALITY client config (mihomo dialect)" \
    || { log_fail "engine config test (mihomo dialect)"; cat /tmp/reality-engine-test.out; }

for cfg in good badshort badkey 1301 firefox; do
    sub bash -c "nohup crash engine run --flavor rust-mihomo --config /tmp/engine-$cfg.yaml >/tmp/engine-$cfg.log 2>&1 &"
done
bound=0
for p in "$MIXED_GOOD" "$MIXED_BAD_SHORT" "$MIXED_BAD_KEY" "$MIXED_1301" 27894; do
    for _ in $(seq 1 20); do
        sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/'"$p"')' 2>/dev/null && { bound=$((bound+1)); break; }
        sleep 0.5
    done
done
[ "$bound" = 5 ] && log_pass "engine mixed listeners up (5 instances)" \
    || { log_fail "engine mixed listeners ($bound/5)"; dump_logs /tmp/engine-good.log; }

# ---------------------------------------------------------------------------
# 4. Checks
# ---------------------------------------------------------------------------
# 4a. PRIMARY: REALITY handshake + VLESS relay through the no-flow inbound.
echo "=== 4a. REALITY handshake + relay (no-flow inbound, dest = camo A) ==="
PRIMARY_OK=0
out=$(probe "$MIXED_GOOD")
if [ "$out" = "$EXPECTED_BODY" ]; then
    PRIMARY_OK=1
    log_pass "REALITY handshake + vless relay (engine client -> real Xray server, no flow)"
else
    log_fail "REALITY handshake + relay: got '${out:0:120}'"
    dump_logs /tmp/engine-good.log
fi

# 4b. Did the REALITY *authentication* succeed? Xray reports a failure reason
# for every rejected REALITY connection; "handshake did not complete
# successfully" is only reachable after `hs.c.conn == conn`, i.e. after the
# sealed session id was unsealed and the short id matched (XTLS/reality
# tls.go), while a bad short id yields "authentication failed or validation
# criteria not met". That separates "REALITY wire format rejected" from
# "TLS 1.3 layer broken after a successful auth".
echo "=== 4b. REALITY auth verdict from the server ==="
AUTH_REASON=$(sub sh -c \
    'grep "REALITY: processed invalid connection" /tmp/xray.log 2>/dev/null | grep -v "failed to read client hello" | sed "s/.*connection from //" | tail -1' \
    | tr -d '\r')
case "$AUTH_REASON" in
    *"handshake did not complete successfully"*)
        log_pass "REALITY auth ACCEPTED by the server (Xray: '${AUTH_REASON:0:72}')" ;;
    *"authentication failed or validation criteria not met"*)
        log_fail "REALITY auth REJECTED by the server (Xray: '${AUTH_REASON:0:72}')" ;;
    *)
        log_skip "server release did not report a REALITY failure reason (got '${AUTH_REASON:0:60}')" ;;
esac

# 4c. Divergence pinpoint. Camo A's ServerHello (which the REALITY server
# mirrors verbatim, key share aside) advertises 0x1302; camo B's advertises
# 0x1301, which the engine implements. Comparing the engine's error for the
# same client against the same server on both dests says WHICH handshake step
# diverges.
if [ "$PRIMARY_OK" = 0 ]; then
    echo "=== 4c. Divergence pinpoint (same client, dest suite 0x1302 vs 0x1301) ==="
    err_a=$(engine_error /tmp/engine-good.log)
    probe "$MIXED_1301" >/dev/null 2>&1
    err_b=$(engine_error /tmp/engine-1301.log)
    echo "  dest 0x1302 (camo A) -> ${err_a:-<no error line>}"
    echo "  dest 0x1301 (camo B) -> ${err_b:-<no error line>}"
    case "$err_a" in
        *"unsupported cipher suite"*)
            echo "  DIVERGENCE 1 (TLS 1.3 cipher suite): the REALITY ServerHello is the DEST site's"
            echo "  ServerHello (XTLS/reality tls.go unmarshals the target's hello into hs.hello and"
            echo "  reuses it, replacing only the key share), so its suite is whatever the dest picked"
            echo "  - 0x1302 here. The engine offers 0x1301/0x1302/0x1303 in its Chrome hello but"
            echo "  tls13::CipherSuite::from_id implements only 0x1301/0x1303 -> abort at ServerHello."
            ;;
    esac
    case "$err_b" in
        *"unexpected inner content type"*)
            echo "  DIVERGENCE 2 (record padding): with a 0x1301 dest the suite step passes and the"
            echo "  engine fails decrypting the server's first encrypted handshake record, reading"
            echo "  inner content type 0. REALITY zero-pads its handshake records to the dest's record"
            echo "  sizes (XTLS/reality conn.go halfConn.encrypt, '[REALITY] SECTION: mimic recorded"
            echo "  handshakeLen': record = append(record, empty[:padding]...) AFTER the type byte)."
            echo "  RFC 8446 sec 5.4: the content type is the last NON-ZERO byte; Xray's own receiver"
            echo "  scans backwards for it. RecordProtector::open (tls13.rs) does inner.pop() - no scan."
            ;;
    esac
    [ -z "$err_a$err_b" ] && echo "  (no engine error lines captured: see the log tails above)"
else
    # Primary works: exercise the second uTLS profile for real.
    echo "=== 4c. Reality with the firefox uTLS profile ==="
    out=$(probe 27894)
    if [ "$out" = "$EXPECTED_BODY" ]; then
        log_pass "REALITY handshake with the firefox uTLS profile"
    else
        log_fail "REALITY handshake with the firefox uTLS profile: got '${out:0:80}'"
        dump_logs /tmp/engine-firefox.log
    fi
fi

# 4d. NEGATIVE checks. They are only interpretable when the positive
# handshake works: while the handshake is broken every connection fails and a
# "failure" would prove nothing. In that case they are labelled SKIP with the
# reason, and the primary failure above is the only root cause reported.
neg_check() { # <mixed port> <engine log> <label>
    local port=$1 elog=$2 label=$3
    if [ "$PRIMARY_OK" = 0 ]; then
        log_skip "$label: not interpretable while the positive REALITY handshake fails (see 4a)"
        return
    fi
    local out
    out=$(probe "$port")
    if [ "$out" = "$EXPECTED_BODY" ]; then
        log_fail "$label SILENTLY SUCCEEDED (payload relayed) — REALITY auth is not enforced"
        dump_logs "$elog"
        return
    fi
    # The refusal must be REALITY's own: the fallback site presents a normal
    # certificate and the engine can only accept REALITY's HMAC-stamped one.
    local reason
    reason=$(sub sh -c "grep -i 'received real certificate' $elog 2>/dev/null | tail -1" | tr -d '\r')
    if [ -n "$reason" ]; then
        log_pass "$label refused by REALITY temp-auth (engine: 'received real certificate')"
    else
        log_fail "$label failed, but not with a REALITY temp-auth refusal — see the log"
        dump_logs "$elog"
    fi
}

echo "=== 4d. Negative: wrong short id ==="
neg_check "$MIXED_BAD_SHORT" /tmp/engine-badshort.log "wrong short id"
echo "=== 4e. Negative: wrong public key ==="
neg_check "$MIXED_BAD_KEY" /tmp/engine-badkey.log "wrong public key"

# 4f. Evidence that the refusals above are REALITY auth rejections and not a
# dead port: a plain TLS client (no REALITY at all) reaching the same port
# gets the camo site, i.e. the fallback path really serves the dest.
echo "=== 4f. Fallback path (dest/camo) is a real TLS oracle ==="
camo_via_reality=$(sub curl -sk --max-time 6 --http1.1 "https://127.0.0.1:$REALITY_NOVISION_PORT/" 2>&1)
[ "$camo_via_reality" = "$CAMO_BODY" ] \
    && log_pass "plain TLS client to the REALITY port lands on the camo site (fallback works)" \
    || { log_fail "REALITY fallback/camo path: got '${camo_via_reality:0:80}'"; dump_logs /tmp/engine-good.log; }

# 4g. SECONDARY / expected skip: vless flow xtls-rprx-vision.
# The engine rejects `flow` at config load, so the no-flow inbound above is
# the primary check. This section is clearly labelled and does not fail the
# suite; if the engine ever gains Vision, it is exercised for real instead.
echo "=== 4g. Secondary: vision (engine client) ==="
render /reality-fixtures/engine-reality.tmpl.yaml /tmp/engine-vision.yaml \
    "__MIXED_PORT__=27893" "__SERVER_PORT__=$REALITY_VISION_PORT" \
    "__UUID__=$UUID" "__PUBLIC_KEY__=$PUB" "__SHORT_ID__=$SHORT_ID" \
    "__FINGERPRINT__=chrome"
sub sh -c 'sed -i "s|^    uuid: |    flow: xtls-rprx-vision\n    uuid: |" /tmp/engine-vision.yaml'
if sub crash engine test --flavor rust-mihomo --config /tmp/engine-vision.yaml >/tmp/reality-engine-vision-test.out 2>&1; then
    sub bash -c 'nohup crash engine run --flavor rust-mihomo --config /tmp/engine-vision.yaml >/tmp/engine-vision.log 2>&1 &'
    for _ in $(seq 1 20); do
        sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/27893)' 2>/dev/null && break
        sleep 0.5
    done
    out=$(probe 27893)
    [ "$out" = "$EXPECTED_BODY" ] \
        && log_pass "vless flow xtls-rprx-vision through the engine client" \
        || { log_fail "vision through the engine client: got '${out:0:80}'"; dump_logs /tmp/engine-vision.log; }
else
    reason=$(tail -2 /tmp/reality-engine-vision-test.out 2>/dev/null | tr '\n' ' ')
    log_skip "engine client cannot do flow xtls-rprx-vision yet — ${reason:0:110}"
fi

# 4h. Secondary oracle: the vision inbound is real and usable — Xray's OWN
# client completes a Vision REALITY handshake against it. This isolates any
# engine gap to the engine's client, not to the server config.
echo "=== 4h. Secondary: vision server-side oracle (xray client) ==="
render /reality-fixtures/xray-client-vision.json.tmpl /tmp/xray-client-vision.json \
    "__UUID__=$UUID" "__PUBLIC_KEY__=$PUB" "__SHORT_ID__=$SHORT_ID" \
    "__SERVER_PORT_VISION__=$REALITY_VISION_PORT" "__SOCKS_PORT__=$XRAY_SOCKS_PORT"
sub bash -c 'nohup /tmp/xray/xray run -c /tmp/xray-client-vision.json >/tmp/xray-client.log 2>&1 &'
for _ in $(seq 1 20); do
    sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/'"$XRAY_SOCKS_PORT"')' 2>/dev/null && break
    sleep 0.5
done
out=$(sub sh -c "curl -s --max-time 8 -x socks5h://127.0.0.1:$XRAY_SOCKS_PORT http://127.0.0.1:$HTTP_PORT/hello.txt" 2>&1)
[ "$out" = "$EXPECTED_BODY" ] \
    && log_pass "vision (xtls-rprx-vision) REALITY handshake via xray's own client (server side proven)" \
    || { log_fail "xray client vision oracle: got '${out:0:80}'"; sub sh -c 'tail -20 /tmp/xray-client.log'; }
sub bash -c 'pkill -f "xray run -c /tmp/xray-client-vision.json" 2>/dev/null; true'

# 4i. No-flow oracle: the same REALITY server + same inbound also works with
# Xray's own client (no flow), which proves the server config itself is sane.
echo "=== 4i. Secondary: no-flow server-side oracle (xray client) ==="
render /reality-fixtures/xray-client-vision.json.tmpl /tmp/xray-client-noflow.json \
    "__UUID__=$UUID" "__PUBLIC_KEY__=$PUB" "__SHORT_ID__=$SHORT_ID" \
    "__SERVER_PORT_VISION__=$REALITY_NOVISION_PORT" "__SOCKS_PORT__=27901"
sub sh -c 'sed -i "s|\"flow\": \"xtls-rprx-vision\"|\"flow\": \"\"|" /tmp/xray-client-noflow.json'
sub bash -c 'nohup /tmp/xray/xray run -c /tmp/xray-client-noflow.json >/tmp/xray-client-nf.log 2>&1 &'
for _ in $(seq 1 20); do
    sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/27901)' 2>/dev/null && break
    sleep 0.5
done
out=$(sub sh -c "curl -s --max-time 8 -x socks5h://127.0.0.1:27901 http://127.0.0.1:$HTTP_PORT/hello.txt" 2>&1)
[ "$out" = "$EXPECTED_BODY" ] \
    && log_pass "no-flow REALITY handshake via xray's own client (server side proven)" \
    || { log_fail "xray client no-flow oracle: got '${out:0:80}'"; sub sh -c 'tail -20 /tmp/xray-client-nf.log'; }
sub bash -c 'pkill -f "xray run -c /tmp/xray-client-noflow.json" 2>/dev/null; true'

# 4j. The REALITY tunnel must not let a plain (non-REALITY) client through
# to the HTTP target: a bare TLS client cannot use the vless inbound.
echo "=== 4j. Negative: bare TLS to the REALITY port never reaches the target ==="
out=$(sub sh -c "curl -sk --max-time 6 https://127.0.0.1:$REALITY_NOVISION_PORT/hello.txt" 2>&1)
case "$out" in
    *"$EXPECTED_BODY"*) log_fail "a bare TLS client reached the HTTP target through the REALITY port" ;;
    *) log_pass "bare TLS client does not reach the tunnel target (got '${out:0:40}')" ;;
esac

echo
[ "$SKIP" -gt 0 ] && echo "=== Skipped: $SKIP (labelled above, not counted as failures) ==="
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" = 0 ]