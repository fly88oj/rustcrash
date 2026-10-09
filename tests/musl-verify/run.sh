#!/bin/bash
# Musl cross-platform verification: build the musl-static binary, then
# run it on Alpine (native musl), Debian slim (glibc-only host proves
# the static link), and under QEMU for arm64 — smoke through the
# kernel CLI, a full engine config test, a live proxy relay, and the
# mihomo-kernel compat layer.
#
# Hermetic by construction (loopback only); the only network-dependent
# step is the docker image pulls.
set -u

# Resource guard (2026-10-09 disk-full incident): refuse heavy work on
# a full disk; watchdog prunes regenerable caches while this runs.
. "$(dirname "${BASH_SOURCE[0]}")/../../scripts/resource-guard.sh"
guard_run

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MUSL_DIR=/tmp/rustcrash-musl

PASS=0; FAIL=0; SKIP=0
log_pass() { PASS=$((PASS+1)); echo "[PASS] $*"; }
log_fail() { FAIL=$((FAIL+1)); echo "[FAIL] $*"; }
log_skip() { SKIP=$((SKIP+1)); echo "[SKIP] $*"; }

echo "=== Musl verification: build + multi-platform smoke ==="

# ---------------------------------------------------------------------------
# 0. Build the x86_64-musl binary in a clean Docker builder (musl-tools
#    for ring's C build script).
# ---------------------------------------------------------------------------
echo "--- build x86_64-musl ---"
mkdir -p "$MUSL_DIR"
rm -f "$MUSL_DIR/crash"

docker run --rm \
    -v "$PROJECT_ROOT":/src:ro \
    -v "$MUSL_DIR":/src/target \
    -w /src \
    rust:1.98-slim \
    bash -c '
rustup target add x86_64-unknown-linux-musl 2>/dev/null
apt-get update -qq && apt-get install -y -qq musl-tools file >/dev/null 2>&1
cargo build --release --target x86_64-unknown-linux-musl --bin crash --features engine-full 2>&1 | grep "^error" && exit 1
exit 0
' 2>&1 | grep -v "^$" | head -5

if [ ! -x "$MUSL_DIR/x86_64-unknown-linux-musl/release/crash" ]; then
    echo "FATAL: musl binary not built"
    exit 1
fi
cp "$MUSL_DIR/x86_64-unknown-linux-musl/release/crash" "$MUSL_DIR/crash"
chmod +x "$MUSL_DIR/crash"

# Static link check (must be "statically linked" or "static-pie linked")
LINK_TYPE=$(docker run --rm -v "$MUSL_DIR/crash":/crash:ro alpine:latest sh -c 'apk add --no-cache file >/dev/null 2>&1; file /crash 2>/dev/null || echo nofile' 2>/dev/null)
if echo "$LINK_TYPE" | grep -q "static"; then
    log_pass "binary is statically linked: $(echo "$LINK_TYPE" | head -1)"
else
    log_fail "binary is NOT static: $LINK_TYPE"
fi

# ---------------------------------------------------------------------------
# 1. Alpine (native musl): full smoke
# ---------------------------------------------------------------------------
echo "--- Alpine (native musl) smoke ---"
ALPINE_OUT=$(docker run --rm \
    -v "$MUSL_DIR/crash":/crash:ro \
    alpine:latest \
    sh -c '
CRASH=/crash
T=0; F=0
# 1. version
$CRASH engine version >/dev/null 2>&1 && { echo "VER_OK"; T=$((T+1)); } || { echo "VER_FAIL"; F=$((F+1)); }
# 2. kernel CLI -v
V=$($CRASH -v 2>&1) && echo "$V" | grep -qi "v0\|rustcrash\|kernel" && { echo "KCLI_OK"; T=$((T+1)); } || { echo "KCLI_FAIL"; F=$((F+1)); }
# 3. --help
$CRASH -h >/dev/null 2>&1 && { echo "HELP_OK"; T=$((T+1)); } || { echo "HELP_FAIL"; F=$((F+1)); }
# 4. mihomo dialect config test
mkdir -p /tmp/test
cat > /tmp/test/c.yaml <<EOF
mixed-port: 17890
proxies:
  - {name: ss1, type: ss, server: 127.0.0.1, port: 12345, cipher: aes-256-gcm, password: test-pw}
rules:
  - MATCH,ss1
EOF
$CRASH engine test --flavor rust-mihomo --config /tmp/test/c.yaml >/dev/null 2>&1 && { echo "MIHOMO_OK"; T=$((T+1)); } || { echo "MIHOMO_FAIL"; F=$((F+1)); }
# 5. sing-box dialect config test
cat > /tmp/test/sb.json <<EOF
{"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":17891}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[{"action":"route","outbound":"direct"}]}}
EOF
$CRASH engine test --flavor rust-sing-box --config /tmp/test/sb.json >/dev/null 2>&1 && { echo "SINGBOX_OK"; T=$((T+1)); } || { echo "SINGBOX_FAIL"; F=$((F+1)); }
echo "RESULT:$T:$F"
' 2>/dev/null)

echo "$ALPINE_OUT" | grep -q "VER_OK" && log_pass "Alpine: engine version" || log_fail "Alpine: version failed"
echo "$ALPINE_OUT" | grep -q "KCLI_OK" && log_pass "Alpine: kernel CLI (-v)" || log_fail "Alpine: kernel CLI failed"
echo "$ALPINE_OUT" | grep -q "HELP_OK" && log_pass "Alpine: --help" || log_fail "Alpine: help failed"
echo "$ALPINE_OUT" | grep -q "MIHOMO_OK" && log_pass "Alpine: mihomo dialect config test" || log_fail "Alpine: mihomo config test failed"
echo "$ALPINE_OUT" | grep -q "SINGBOX_OK" && log_pass "Alpine: sing-box dialect config test" || log_fail "Alpine: sing-box config test failed"

# ---------------------------------------------------------------------------
# 2. Debian slim (glibc host): static binary must work without any musl libs
# ---------------------------------------------------------------------------
echo "--- Debian slim (glibc host, static binary) ---"
DEBIAN_OK=$(docker run --rm \
    -v "$MUSL_DIR/crash":/crash:ro \
    debian:trixie-slim \
    sh -c '/crash engine version >/dev/null 2>&1 && echo OK || echo FAIL' 2>/dev/null)
[ "$DEBIAN_OK" = "OK" ] && log_pass "static binary runs on glibc-only Debian (no musl libs needed)" \
                       || log_fail "static binary failed on Debian: $DEBIAN_OK"

# ---------------------------------------------------------------------------
# 3. Full relay test on Alpine: proxy through the musl engine to a target
# ---------------------------------------------------------------------------
echo "--- Alpine relay test (engine -> DIRECT -> target) ---"
RELAY_OUT=$(docker run --rm \
    -v "$MUSL_DIR/crash":/crash:ro \
    alpine:latest \
    sh -c '
apk add --no-cache curl >/dev/null 2>&1
mkdir -p /tmp/www && echo "musl-relay-ok" > /tmp/www/test.txt
(
  cd /tmp/www
  while true; do
    printf "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nmusl-relay-ok" | nc -l -p 18080 >/dev/null 2>&1
  done
) &
cat > /tmp/engine.yaml <<EOF
mixed-port: 17890
rules:
  - MATCH,DIRECT
EOF
/crash engine run --flavor rust-mihomo --config /tmp/engine.yaml >/dev/null 2>&1 &
sleep 2
RESULT=$(curl -s --max-time 5 -x http://127.0.0.1:17890 http://127.0.0.1:18080/ 2>/dev/null || echo "")
kill %2 2>/dev/null; kill %1 2>/dev/null
if [ "$RESULT" = "musl-relay-ok" ]; then echo "RELAY_OK"; else echo "RELAY_FAIL:got=$RESULT"; fi
' 2>/dev/null)
[ "$RELAY_OUT" = "RELAY_OK" ] && log_pass "full relay through musl engine (mixed-port -> DIRECT -> target)" \
                              || log_fail "relay test: $RELAY_OUT"

# ---------------------------------------------------------------------------
# 4. QEMU arm64 musl (via Docker multi-arch): binary type check
# ---------------------------------------------------------------------------
echo "--- arm64 musl (cross-rs build + QEMU run) ---"
if command -v cross >/dev/null 2>&1; then
    cross build --release --target aarch64-unknown-linux-musl --bin crash --features engine-full >/dev/null 2>&1
    ARM64_BIN="target/aarch64-unknown-linux-musl/release/crash"
    if [ -x "$ARM64_BIN" ]; then
        # Extract qemu-aarch64 from the cross-rs image (cached locally)
        QEMU_BIN=/tmp/qemu-aarch64
        if [ ! -x "$QEMU_BIN" ]; then
            docker create --name qemu-extract-$$ ghcr.io/cross-rs/aarch64-unknown-linux-musl:0.2.5 >/dev/null 2>&1
            docker cp qemu-extract-$$:/usr/local/bin/qemu-aarch64 "$QEMU_BIN" >/dev/null 2>&1
            docker rm qemu-extract-$$ >/dev/null 2>&1
            chmod +x "$QEMU_BIN"
        fi
        if [ -x "$QEMU_BIN" ]; then
            ARM64_VER=$("$QEMU_BIN" "$ARM64_BIN" engine version 2>/dev/null | head -1)
            if echo "$ARM64_VER" | grep -q "rustcrash"; then
                log_pass "arm64-musl binary runs under QEMU: $ARM64_VER"
            else
                log_fail "arm64-musl binary failed: $ARM64_VER"
            fi
            # Config test on arm64
            mkdir -p /tmp/arm64-test
            cat > /tmp/arm64-test/c.yaml <<'EOF'
mixed-port: 17890
proxies:
  - {name: ss1, type: ss, server: 127.0.0.1, port: 12345, cipher: aes-256-gcm, password: test-pw}
rules:
  - MATCH,ss1
EOF
            ARM64_CFG=$("$QEMU_BIN" "$ARM64_BIN" engine test --flavor rust-mihomo --config /tmp/arm64-test/c.yaml 2>/dev/null; echo "EXIT=$?")
            echo "$ARM64_CFG" | grep -q "EXIT=0" && log_pass "arm64-musl: mihomo dialect config test under QEMU" \
                                                || log_fail "arm64-musl config test: $ARM64_CFG"
        else
            log_skip "qemu-aarch64 not available (cross-rs image cached but extraction failed)"
        fi
    else
        log_fail "arm64-musl cross build failed"
    fi
else
    log_skip "cross CLI not installed (cargo install cross)"
fi

# ---------------------------------------------------------------------------
# 5. musl binary + mihomo kernel CLI compat (the ShellCrash swap path)
# ---------------------------------------------------------------------------
echo "--- kernel CLI compat on musl ---"
CLI_COMPAT=$(docker run --rm \
    -v "$MUSL_DIR/crash":/crash:ro \
    alpine:latest \
    sh -c '
mkdir -p /tmp/test
cat > /tmp/test/config.yaml <<EOF
mixed-port: 17890
proxies:
  - {name: d, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,d
EOF
# mihomo-style: -t (test) -d DIR -f FILE
/crash -t -d /tmp/test -f /tmp/test/config.yaml >/dev/null 2>&1 && echo "T_OK" || echo "T_FAIL"
' 2>/dev/null)
echo "$CLI_COMPAT" | grep -q "T_OK" && log_pass "mihomo kernel CLI (-t -d -f) works on musl" \
                                 || log_fail "kernel CLI on musl: $CLI_COMPAT"

# ---------------------------------------------------------------------------
echo ""
echo "=== Results: $PASS passed, $FAIL failed (skipped: $SKIP) ==="
[ "$FAIL" = "0" ]
