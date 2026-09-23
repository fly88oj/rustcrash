#!/bin/bash
# Docker-based end-to-end test: builds the real image, starts the
# mock subscription server + RustCrash container + prober, and runs the
# full management flow against the real binary in containers.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

PASS=0
FAIL=0
log_pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
log_fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

cleanup() {
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== Building image (real Dockerfile) ==="
docker compose -f "$COMPOSE_FILE" build rustcrash --quiet || {
    echo "image build failed"; exit 1;
}

echo "=== Starting containers ==="
docker compose -f "$COMPOSE_FILE" up -d >/dev/null

SUB="docker compose -f $COMPOSE_FILE exec -T rustcrash"
PROBE="docker compose -f $COMPOSE_FILE exec -T prober"
# Container IPs (service-name DNS is unreliable behind host VPN DNS like
# Tailscale, which hijacks *.ts.net lookups).
MOCK_IP=$(docker compose -f "$COMPOSE_FILE" exec -T mock-sub hostname -i 2>/dev/null | tr -d '\r' | awk '{print $1}')

# Wait for the mock server.
for i in $(seq 1 30); do
    if $SUB wget -q -O- "http://$MOCK_IP/sub-uris.txt" >/dev/null 2>&1; then break; fi
    sleep 1
done
$SUB wget -q -O- "http://$MOCK_IP/sub-uris.txt" >/dev/null 2>&1 \
    && log_pass "mock subscription server reachable from rustcrash container" \
    || log_fail "mock subscription server unreachable"

echo "=== 1. init ==="
$SUB crash init >/dev/null 2>&1 && log_pass "crash init" || log_fail "crash init"
$SUB test -d /tmp/rustcrash/configs && log_pass "directory layout created" || log_fail "directory layout"

echo "=== 2. version/status ==="
$SUB crash --version >/dev/null 2>&1 && log_pass "crash --version" || log_fail "crash --version"
$SUB crash start status >/dev/null 2>&1 && log_pass "crash start status (no kernel)" || log_fail "start status"

echo "=== 3. subscription import (native conversion) ==="
$SUB crash sub convert -i "http://$MOCK_IP/sub-uris.txt" -t clash -o /tmp/sub.yaml >/dev/null 2>&1
if $SUB grep -q "proxies:" /tmp/sub.yaml && $SUB grep -q "proxy-groups:" /tmp/sub.yaml; then
    log_pass "native sub conversion (clash output)"
else
    log_fail "native sub conversion"
fi
$SUB grep -q "tolerance:" /tmp/sub.yaml && log_pass "url-test group with tolerance" || log_fail "tolerance group"
$SUB crash sub convert -i "http://$MOCK_IP/sub-uris.txt" -t surfboard -o /tmp/sub.sb >/dev/null 2>&1 \
    && $SUB grep -q "\[Proxy\]" /tmp/sub.sb && log_pass "surfboard output" || log_fail "surfboard output"

echo "=== 4. config import + generate ==="
$SUB crash config import "http://$MOCK_IP/sub-uris.txt" --name test >/dev/null 2>&1 \
    && log_pass "config import" || log_fail "config import"
$SUB crash config generate >/dev/null 2>&1 && log_pass "config generate" || log_fail "config generate"
$SUB crash config validate >/dev/null 2>&1 && log_pass "config validate" || log_fail "config validate"

echo "=== 5. kernel install (real GitHub download) ==="
HAVE_KERNEL=0
if $SUB crash install >/dev/null 2>&1; then
    log_pass "kernel install from GitHub releases (latest)"
    HAVE_KERNEL=1
else
    # The latest-version lookup hits the GitHub API (anonymous quota).
    # Asset downloads don't — fall back to a pinned version when the
    # lookup is rate-limited.
    PINNED=$($SUB sh -c "wget -q -T 10 -O- https://github.com/MetaCubeX/mihomo/releases/version.txt 2>/dev/null || echo v1.19.13" | tail -1)
    if $SUB crash install --version "${PINNED#v}" >/dev/null 2>&1; then
        log_pass "kernel install from GitHub releases (pinned ${PINNED})"
        HAVE_KERNEL=1
    else
        log_fail "kernel install (network-dependent; may fail offline)"
    fi
fi

echo "=== 6. supervisor + REST API ==="
if [ "$HAVE_KERNEL" = "1" ]; then
    # Enable API and start the supervisor in the background.
    $SUB sh -c "sed -i 's/api_enabled: false/api_enabled: true/' /tmp/rustcrash/config.yaml"
    $SUB sh -c "crash start serve >/tmp/serve.log 2>&1 &"
    sleep 3
    $SUB wget -q -O- http://127.0.0.1:9097/healthz | grep -q '"ok"' \
        && log_pass "REST API /healthz" || log_fail "REST API /healthz"
    $SUB wget -q -O- http://127.0.0.1:9097/api/status | grep -q '"kernel"' \
        && log_pass "REST API /api/status" || log_fail "REST API /api/status"
    $SUB wget -q -O- http://127.0.0.1:9097/api/config | grep -q '"mode"' \
        && log_pass "REST API /api/config" || log_fail "REST API /api/config"
    # Cross-container probe: API must be loopback-only by design, so the
    # prober must NOT reach it (negative security test).
    if $PROBE wget -q -T 3 -O- http://rustcrash:9097/healthz >/dev/null 2>&1; then
        log_fail "API unexpectedly reachable cross-container (should be loopback)"
    else
        log_pass "API correctly loopback-only (cross-container blocked)"
    fi
    # Real kernel lifecycle.
    $SUB wget -q -O- --post-data='' http://127.0.0.1:9097/api/start | grep -q started \
        && log_pass "API start kernel" || log_fail "API start kernel"
    sleep 2
    $SUB wget -q -O- http://127.0.0.1:9097/api/status | grep -q '"running":true' \
        && $SUB wget -q -O- http://127.0.0.1:9097/api/status | grep -q '"memory_mb":[^n]' \
        && log_pass "kernel reports running (with real memory — not a zombie)" \
        || log_fail "kernel running check"
    # Anti-loop gid: the kernel process must carry supplementary gid 7890
    # (the firewall's skgid exemption matches the NUMERIC gid). Parsed via
    # a fixed /proc path — no shell interpolation of external input.
    if $SUB sh -c 'grep "^Groups:" "/proc/$(cat /tmp/rustcrash/run/mihomo.pid)/status" | tr "\t " "\n" | grep -qx 7890' 2>/dev/null; then
        log_pass "kernel runs with anti-loop gid 7890"
    else
        log_fail "kernel missing anti-loop gid (traffic-loop risk)"
    fi
    $SUB wget -q -O- http://127.0.0.1:9097/api/logs | grep -q '"logs"' \
        && log_pass "API /api/logs" || log_fail "API /api/logs"
    $SUB wget -q -O- --post-data='' http://127.0.0.1:9097/api/stop | grep -q stopped \
        && log_pass "API stop kernel" || log_fail "API stop kernel"
    # Version probe uses the flag the kernel actually accepts (mihomo
    # rejects --version); must print a real version, not "not installed".
    if $SUB crash --exec version 2>/dev/null | grep -q "Mihomo Meta"; then
        log_pass "kernel version probe (mihomo -v)"
    else
        log_fail "kernel version probe"
    fi

    # Community scenario #919 ("gateway+DNS at the box, nothing goes
    # through"): the generated kernel config must actually parse and carry
    # the listeners the firewall redirects to. Parse = the kernel accepts
    # it with -t (config test).
    if $SUB sh -c "/tmp/rustcrash/bin/mihomo -t -f /tmp/rustcrash/configs/mihomo.yaml >/dev/null 2>&1" \
        && $SUB grep -q "redir-port: 7890" /tmp/rustcrash/configs/mihomo.yaml \
        && $SUB grep -q "mixed-port: 7891" /tmp/rustcrash/configs/mihomo.yaml \
        && $SUB grep -q "listen: 0.0.0.0:7892" /tmp/rustcrash/configs/mihomo.yaml; then
        log_pass "generated kernel config valid (mihomo -t) with listeners+dns"
    else
        log_fail "generated kernel config rejected by kernel or missing listeners"
    fi
else
    echo "[SKIP] supervisor tests (no kernel installed)"
fi

echo "=== 7. firewall generation ==="
$SUB crash firewall generate --backend nftables >/dev/null 2>&1 \
    && log_pass "firewall script generation" || log_fail "firewall generation"

echo "=== 8. rule providers (mock server) ==="
# Drop the serialized empty list first so the appended block is the only
# rule_providers key (a duplicate YAML key would fail to parse).
$SUB sh -c "sed -i '/^rule_providers: *\[\]/d' /tmp/rustcrash/config.yaml; cat >> /tmp/rustcrash/config.yaml <<EOF
rule_providers:
  - name: test
    url: http://$MOCK_IP/sub-uris.txt
    interval: 60
EOF"
$SUB crash task rules >/dev/null 2>&1 \
    && $SUB test -f /tmp/rustcrash/configs/ruleset/test-sub-uris.txt \
    && log_pass "rule provider download" || log_fail "rule provider download"
$SUB crash config generate >/dev/null 2>&1
if $SUB sh -c 'grep -c "rule-providers:" /tmp/rustcrash/configs/mihomo.yaml | grep -q "^1$"'; then
    log_pass "generated config has exactly one rule-providers section"
else
    log_fail "rule-providers section count"
fi

echo "=== 9. firewall APPLY against the real kernel (NET_ADMIN) ==="
if [ "$(docker compose -f "$COMPOSE_FILE" exec -T rustcrash id -u)" = "0" ] \
    && $SUB sh -c 'command -v nft >/dev/null 2>&1'; then
    # 9a. default config applies and loads redirect rules
    $SUB crash -c /tmp/fw-real init >/dev/null 2>&1
    if $SUB crash -c /tmp/fw-real firewall apply >/dev/null 2>&1 \
        && [ "$($SUB nft list ruleset 2>/dev/null | grep -c redirect)" -gt 0 ]; then
        log_pass "firewall apply (nft, default) loads redirect rules"
    else
        log_fail "firewall apply (nft, default)"
    fi

    # Community scenario "open proxy": the applied prerouting hijack must
    # be LAN-subnet scoped (WAN traffic must never be redirected).
    if $SUB nft list ruleset 2>/dev/null | grep -E "redirect to" | grep -q "ip saddr"; then
        log_pass "prerouting hijack is LAN-subnet scoped (no open proxy)"
    else
        log_fail "prerouting hijack not source-scoped (open-proxy risk)"
    fi

    # 9b. TUN + IPv6 combo: ruleset loads, v4+v6 policy routing installed
    # (single-quoted sed programs, literal paths — nothing interpolated)
    $SUB sh -c "crash -c /tmp/fw-real config show >/dev/null 2>&1; sed -i -e 's/^tun_enabled: false/tun_enabled: true/' -e 's/^tun_port: null/tun_port: 7890/' -e 's/^ipv6_enabled: false/ipv6_enabled: true/' -e 's/^ipv6_redir: false/ipv6_redir: true/' /tmp/fw-real/config.yaml"
    if $SUB crash -c /tmp/fw-real firewall apply >/dev/null 2>&1; then
        TPROXY=$($SUB nft list ruleset 2>/dev/null | grep -c tproxy)
        V4RULE=$($SUB sh -c "ip rule show | grep -c 'fwmark 0x80000' || true")
        V6RULE=$($SUB sh -c "ip -6 rule show | grep -c 'fwmark 0x80000' || true")
        if [ "$TPROXY" -gt 0 ] && [ "$V4RULE" -ge 1 ] && [ "$V6RULE" -ge 1 ]; then
            log_pass "firewall apply (TUN+IPv6): tproxy rules + v4/v6 policy routing live"
        else
            log_fail "firewall apply (TUN+IPv6) state (tproxy=$TPROXY v4=$V4RULE v6=$V6RULE)"
        fi
    else
        log_fail "firewall apply (TUN+IPv6) exits nonzero"
    fi

    # 9c. cleanup removes the routing and rules
    if $SUB crash -c /tmp/fw-real firewall cleanup >/dev/null 2>&1 \
        && [ "$($SUB sh -c "ip rule show | grep -c 'fwmark 0x80000' || true")" = "0" ] \
        && [ "$($SUB sh -c "ip -6 rule show | grep -c 'fwmark 0x80000' || true")" = "0" ] \
        && [ -z "$($SUB nft list tables 2>/dev/null)" ]; then
        log_pass "firewall cleanup removes rules + v4/v6 routing"
    else
        log_fail "firewall cleanup leaves state behind"
    fi

    # 9d. TUN apply is IDEMPOTENT: second apply succeeds, exactly one rule
    $SUB crash -c /tmp/fw-real firewall apply >/dev/null 2>&1
    if $SUB crash -c /tmp/fw-real firewall apply >/dev/null 2>&1 \
        && [ "$($SUB sh -c "ip rule show | grep -c 'fwmark 0x80000' || true")" = "1" ]; then
        log_pass "firewall apply is idempotent (re-apply leaves one rule)"
    else
        log_fail "firewall re-apply not idempotent"
    fi

    # 9d-2. REPEATED applies must not stack rules (nft -f merges; apply
    # resets first) — count dns-redirect rules across three applies.
    # (Live listings interleave counter stats: "udp dport 53 counter
    # packets N redirect to …" — match with a regex, not a substring.)
    R1=$($SUB nft list ruleset 2>/dev/null | grep -cE "udp dport 53.*redirect to")
    $SUB crash -c /tmp/fw-real firewall apply >/dev/null 2>&1
    $SUB crash -c /tmp/fw-real firewall apply >/dev/null 2>&1
    R3=$($SUB nft list ruleset 2>/dev/null | grep -cE "udp dport 53.*redirect to")
    if [ "$R1" -gt 0 ] && [ "$R1" = "$R3" ]; then
        log_pass "repeated applies keep a stable ruleset (dns rules $R1=$R3)"
    else
        log_fail "rules stack across applies (dns rules $R1 -> $R3)"
    fi

    # 9d-3. Toggling TUN+IPv6 OFF must not leave stale state behind
    $SUB sh -c "sed -i -e 's/^tun_enabled: true/tun_enabled: false/' -e 's/^ipv6_enabled: true/ipv6_enabled: false/' -e 's/^ipv6_redir: true/ipv6_redir: false/' /tmp/fw-real/config.yaml"
    if $SUB crash -c /tmp/fw-real firewall apply >/dev/null 2>&1; then
        STALE_TABLES=$($SUB nft list tables 2>/dev/null | grep -c -e 'inet shellcrash' -e 'ip6 nat' -e 'ip6 mangle' || true)
        if [ "$($SUB sh -c "ip rule show | grep -c 'fwmark 0x80000' || true")" = "0" ] \
            && [ "$($SUB sh -c "ip -6 rule show | grep -c 'fwmark 0x80000' || true")" = "0" ] \
            && [ "$($SUB nft list ruleset 2>/dev/null | grep -c tproxy)" = "0" ] \
            && [ "$STALE_TABLES" = "0" ]; then
            log_pass "toggling TUN/IPv6 off leaves no stale tproxy/routing state"
        else
            log_fail "stale TUN/IPv6 state after toggle-off"
        fi
    else
        log_fail "toggle-off apply exits nonzero"
    fi
    $SUB crash -c /tmp/fw-real firewall cleanup >/dev/null 2>&1

    # 9e. iptables BACKEND: fresh default config (ipv6 is nft-only, R12),
    # generated script installs real chains
    # (redirect must happen INSIDE the container)
    $SUB crash -c /tmp/fw-ip4 init >/dev/null 2>&1
    $SUB sh -c "crash -c /tmp/fw-ip4 firewall generate --backend iptables >/tmp/fw4.sh 2>/dev/null"
    if $SUB sh -c "sh /tmp/fw4.sh && iptables -t nat -S shellcrash_pre 2>/dev/null | grep -q REDIRECT" \
        && $SUB sh -c "iptables -t mangle -S shellcrash_mark 2>/dev/null | grep -q MARK" \
        && $SUB sh -c "iptables -t filter -S shellcrash_in 2>/dev/null | grep -q 'shellcrash_in'"; then
        log_pass "iptables backend script installs nat/mangle/filter chains"
    else
        log_fail "iptables backend apply"
    fi
    # 9f. iptables re-apply idempotent (set -e must not trip on -N)
    if $SUB sh -c "sh /tmp/fw4.sh" >/dev/null 2>&1; then
        log_pass "iptables backend re-apply idempotent"
    else
        log_fail "iptables backend re-apply fails"
    fi
    $SUB sh -c "iptables -t nat -F && iptables -t mangle -F && iptables -t filter -F" >/dev/null 2>&1
else
    echo "[SKIP] firewall apply tests (need root + nft in container)"
fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
