#!/bin/bash
# ShellCrash migration e2e: install the REAL ShellCrash manager (its own
# release tarball, its own install.sh) inside the engine container, drive
# it the way a user does, then swap its kernel for the RustCrash engine
# binary and prove everything keeps working — the "I run ShellCrash on my
# box; I replace the kernel; everything keeps working" story.
#
#   phase 1  BASELINE: ShellCrash + the real mihomo kernel (from the
#            host cache shared with tests/docker-interop, or the image's
#            baked-in mihomo). Full user flow: import a subscription-shape
#            config, start, firewall (nft table `inet shellcrash`), DNS
#            hijack, per-node relay, panel API.
#   phase 2  MIGRATION: stop, replace the kernel with the RustCrash
#            engine (raw drop-in first — pinned as engine gap A — then
#            the committed CLI adapter), run the SAME ShellCrash start
#            flow, and assert the same behaviors against ShellCrash's
#            OWN generated config.yaml.
#   phase 3  CLI compat: the /usr/bin/crash wrapper still targets
#            ShellCrash's menu, and the RustCrash binary's own
#            subcommands work against the migrated layout.
#   phase 4  subscription shape: the SAME converter-shaped multi-proxy
#            config relays identically through both kernels.
#
# Everything runs inside ONE container's network namespace on loopback
# 127.0.0.1 (hermetic by construction; this host runs its own transparent
# proxy on 7890 & co, so host ports are never touched). The ShellCrash
# payload tarball is committed under fixtures/, so the suite is fully
# offline on a warm host; the only network-capable step
# (fixtures/fetch-shellcrash.sh) never needs it.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

PASS=0
FAIL=0
SKIP=0
log_pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
log_fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
log_skip() { echo "[SKIP] $1"; SKIP=$((SKIP+1)); }
# An engine gap with a precisely-reproduced symptom: counted as SKIP, not
# FAIL, and labelled so it can be flipped to a PASS check when fixed.
log_gap() { echo "[SKIP] EXPECTED-FAIL (engine gap $1) $2"; SKIP=$((SKIP+1)); }

cleanup() {
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# The port map (single source of truth).
# ---------------------------------------------------------------------------
WEB_PORT=38080            # plaintext HTTP target reached THROUGH the tunnels
DNSUP_PORT=5353           # the DNS upstream oracle (answers 10.9.9.9)
FX_HTTP=8123              # in-container server for install.sh's payload fetch
MIHOMO_API=39190          # mihomo proxy-server external controller
PORT_SS=39388             # mihomo proxy server: ss aes-256-gcm
PORT_VMESS=39400          # mihomo proxy server: vmess tcp
PORT_VMESS_WS=39401       # mihomo proxy server: vmess over ws

# ShellCrash's own defaults (configs/ShellCrash.cfg): the ports the suite
# must see live after `start.sh start`.
SC_MIX=7890
SC_REDIR=7892
SC_TPROXY=7893
SC_API=9999
SC_DNS=1053

# Isolated ports for the engine-gap reproductions (never collide with the
# live instances, and never with each other's lifecycle).
ISO_MIX=47890
ISO_TPROXY=47893
ISO_API=49990
ISO_DNS=41053

EXPECTED_BODY="hello-shellcrash"
SC_DIR=/etc/ShellCrash
TMPDIR_SC=/tmp/ShellCrash
HOST_CACHE="${SC_HOST_CACHE:-$HOME/.cache/rustcrash-e2e}"

echo "=== Building/reusing the engine image (shared with tests/docker-engine) ==="
# Built from the last COMMIT (git archive HEAD), not the working tree —
# same policy as tests/docker-interop (parallel agents share this repo).
# E2E_WORKING_TREE_BUILD=1 restores the direct compose build for local use.
if [ "${E2E_FORCE_BUILD:-0}" = "1" ] \
    || ! docker image inspect docker-engine-rustcrash >/dev/null 2>&1; then
    if [ "${E2E_WORKING_TREE_BUILD:-0}" = "1" ]; then
        docker compose -f "$COMPOSE_FILE" build rustcrash --quiet \
            || { echo "image build failed"; exit 1; }
    else
        EXPORT_DIR=$(mktemp -d /tmp/rustcrash-sc-export.XXXXXX)
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
# This suite INSTALLS ShellCrash: install.sh interacts differently when
# /etc/ShellCrash already exists, so every run starts from a fresh
# container (and fresh nftables state) instead of reusing a running one.
docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
docker compose -f "$COMPOSE_FILE" up -d >/dev/null
DC="docker compose -f $COMPOSE_FILE"
sub() {
    $DC exec -T rustcrash "$@"
}

port_open() { # live TCP check against the container loopback
    sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/'"$1"')' 2>/dev/null
}

wait_port() { # <port> [tries]
    local p=$1 tries="${2:-40}"
    for _ in $(seq 1 "$tries"); do
        if port_open "$p"; then return 0; fi
        sleep 0.5
    done
    return 1
}

listener_bound() { # <port>: a LISTEN socket exists (no connection made —
    # needed for the tproxy port, see engine gap G below)
    sub bash -c "ss -tln 2>/dev/null | grep -q ':$1 '" 2>/dev/null
}

crash_running() { # a LIVE crash process (a plain pgrep also matches
    # zombies: the container's PID-1 bash never reaps adopted children,
    # so an exited engine lingers as <defunct> forever)
    sub bash -c "ps -eo stat=,comm= | grep -v '^Z' | grep -qw crash" 2>/dev/null
}

relay() { # [user:pass@] -> body (or the curl error)
    local auth="$1"
    sub sh -c "curl -s --max-time 12 -x http://$auth@127.0.0.1:$SC_MIX http://127.0.0.1:$WEB_PORT/hello.txt" 2>&1
}

pick_node() { # <node>: select on the ShellCrash panel's selector group
    sub sh -c "curl -s --max-time 5 -X PUT -d '{\"name\": \"$1\"}' http://127.0.0.1:$SC_API/proxies/sub-select -o /dev/null -w '%{http_code}'" 2>/dev/null
}

# ---------------------------------------------------------------------------
# 0. Live port-collision pre-check: nothing of the matrix may be bound yet.
# (Safe even for the tproxy port: nothing is listening yet, so the probes
# cannot trigger the engine's tproxy self-relay bug — gap G below.)
# ---------------------------------------------------------------------------
ALL_TCP_PORTS="$WEB_PORT $FX_HTTP $PORT_SS $PORT_VMESS $PORT_VMESS_WS $MIHOMO_API \
$SC_MIX $SC_REDIR $SC_TPROXY $SC_API $SC_DNS"
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
# 1. In-container services: fixture server, web target, DNS oracle, the
#    mihomo proxy server (the "remote" the subscription points at)
# ---------------------------------------------------------------------------
sub mkdir -p /tmp/sc /tmp/interop/logs

sub bash -c 'nohup python3 -m http.server '"$FX_HTTP"' --bind 127.0.0.1 --directory /sc-fixtures >/tmp/interop/logs/fx-http.log 2>&1 &'
sub bash -c 'nohup python3 -m http.server '"$WEB_PORT"' --bind 127.0.0.1 --directory /sc-fixtures/webroot >/tmp/interop/logs/web.log 2>&1 &'
sub bash -c 'nohup python3 /fixtures/dns-upstream.py '"$DNSUP_PORT"' >/tmp/interop/logs/dnsup.log 2>&1 &'
sleep 1

out=$(sub sh -c "curl -s --max-time 3 http://127.0.0.1:$WEB_PORT/hello.txt" 2>&1)
[ "$out" = "$EXPECTED_BODY" ] \
    && log_pass "http target up ($EXPECTED_BODY)" \
    || log_fail "http target: got '${out:0:60}'"

if sub sh -c "dig +short +time=2 +tries=1 @127.0.0.1 -p $DNSUP_PORT oracle.test A 2>/dev/null | grep -q '10.9.9.9'"; then
    log_pass "dns upstream oracle up (answers A with 10.9.9.9)"
else
    log_fail "dns upstream oracle"
fi

# --- inputs: the ShellCrash payload + the mihomo kernel (host-cache first) ---
if [ -x "$HOST_CACHE/mihomo" ]; then
    # pre-warm the in-container cache so fixtures/fetch-shellcrash.sh
    # finds it (it shares ~/.cache/rustcrash-e2e with the interop suite)
    sub mkdir -p /root/.cache/rustcrash-e2e
    $DC cp "$HOST_CACHE/mihomo" rustcrash:/root/.cache/rustcrash-e2e/mihomo >/dev/null 2>&1 || true
    sub chmod +x /root/.cache/rustcrash-e2e/mihomo 2>/dev/null || true
fi
sub bash /sc-fixtures/fetch-shellcrash.sh /tmp/sc >/tmp/sc-fetch.out 2>&1 \
    || true
sed 's/^/  /' /tmp/sc-fetch.out
if sub sh -c 'test -s /tmp/sc/ShellCrash.tar.gz && test -x /tmp/sc/mihomo-kernel'; then
    MIHOMO_VER=$(sub /tmp/sc/mihomo-kernel -v 2>/dev/null | head -1 | tr -d '\r')
    SC_PAYLOAD_FILES=$(sub sh -c 'tar -tzf /tmp/sc/ShellCrash.tar.gz | wc -l' 2>/dev/null | tr -d '\r')
    log_pass "inputs ready: ShellCrash payload ($SC_PAYLOAD_FILES files) + kernel ($MIHOMO_VER)"
else
    log_fail "input fetch (see above)"
    echo "=== Results: $PASS passed, $FAIL failed ==="
    exit 1
fi

# --- the mihomo proxy server: the "remote box" of the subscription ---
sub bash -c 'nohup /tmp/sc/mihomo-kernel -f /sc-fixtures/mihomo-server.yaml \
    -d /tmp/interop/mihomo-home >/tmp/interop/logs/mihomo-server.log 2>&1 &'
bound=0; total=0
for p in "$PORT_SS" "$PORT_VMESS" "$PORT_VMESS_WS"; do
    total=$((total+1))
    if wait_port "$p" 40; then bound=$((bound+1)); fi
done
[ "$bound" = "$total" ] \
    && log_pass "mihomo proxy-server listeners bound (ss/vmess/vmess-ws, live-checked)" \
    || { log_fail "mihomo proxy-server listeners ($bound/$total)"; \
         sub sh -c 'tail -5 /tmp/interop/logs/mihomo-server.log'; }

# ---------------------------------------------------------------------------
# 2. PHASE A — install the REAL ShellCrash (its own install.sh)
# ---------------------------------------------------------------------------
echo "=== Phase A: installing real ShellCrash via its own install.sh ==="
# install.sh is driven exactly like on a user box: a URL for the payload
# (the in-container fixture server stands in for jsdelivr) and stdin
# answers for the three prompts: install dir (/etc), confirm, alias.
# The alias must NOT be `crash`: this box already has a crash command
# (the RustCrash binary at /usr/local/bin/crash) and install.sh refuses
# conflicting aliases — the migration-realistic choice is `sc`.
sub bash -c 'cp /sc-fixtures/install.sh /tmp/sc/install.sh && cd /tmp/sc \
    && printf "1\n1\n2\n2\n" | url=http://127.0.0.1:'"$FX_HTTP"' bash install.sh' \
    >/tmp/sc-install.out 2>&1 || true
if sub sh -c "test -f $SC_DIR/start.sh && test -f $SC_DIR/configs/ShellCrash.cfg"; then
    log_pass "install.sh completed: $SC_DIR populated (start.sh, configs/)"
else
    log_fail "install.sh did not populate $SC_DIR"
    tail -15 /tmp/sc-install.out
fi

if sub sh -c 'head -1 /usr/bin/crash | grep -q "#!/bin/sh" && grep -q menu.sh /usr/bin/crash'; then
    log_pass "/usr/bin/crash wrapper created by init.sh (targets ShellCrash menu.sh)"
else
    log_fail "/usr/bin/crash wrapper"
fi
# The drop-in story: BOTH binaries coexist — /usr/local/bin/crash (the
# RustCrash engine, first on PATH) and /usr/bin/crash (the ShellCrash menu).
sc_which=$(sub sh -c 'command -v crash' 2>/dev/null | tr -d '\r')
[ "$sc_which" = "/usr/local/bin/crash" ] \
    && log_pass "crash on PATH resolves to the RustCrash binary while /usr/bin/crash keeps the ShellCrash menu (coexistence)" \
    || log_fail "crash command resolution: got '$sc_which'"

sc_systype=$(sub sh -c "grep -o 'systype=.*' $SC_DIR/configs/ShellCrash.cfg" 2>/dev/null | tr -d '\r')
case "$sc_systype" in
    systype=container) log_pass "container environment detected (systype=container; container defaults applied)" ;;
    *) log_fail "systype detection: got '$sc_systype'" ;;
esac

# ---------------------------------------------------------------------------
# 3. PHASE B — configure it the way a user does
# ---------------------------------------------------------------------------
echo "=== Phase B: user-style configuration (subscription import + setconfig) ==="
# The subscription-shape config (what a converter emits) lands in
# yamls/config.yaml; the settings below are written exactly the way
# scripts/libs/set_config.sh writes them (key=value lines sourced by
# libs/get_config.sh).
sub bash -c '
mkdir -p '"$SC_DIR"'/yamls
cp /sc-fixtures/subscription-config.yaml '"$SC_DIR"'/yamls/config.yaml
CFG='"$SC_DIR"'/configs/ShellCrash.cfg
setc() { sed -i "/^$1=.*/d" $CFG; printf "%s=%s\n" "$1" "$2" >>$CFG; }
setc dns_mod redir_host          # no cn-rule-set downloads (hermetic)
setc firewall_area 2             # proxy the local machine (output hooks)
setc network_check OFF           # no ping-based connectivity gate
setc authentication "e2e-user:e2e-pass"   # fake credential, like everything here
setc dns_nameserver "127.0.0.1:'"$DNSUP_PORT"'"  # the in-container DNS oracle
'
if sub sh -c "grep -q '^firewall_area=2' $SC_DIR/configs/ShellCrash.cfg \
    && grep -q '^authentication=e2e-user:e2e-pass' $SC_DIR/configs/ShellCrash.cfg \
    && grep -q '^dns_nameserver=127.0.0.1:$DNSUP_PORT' $SC_DIR/configs/ShellCrash.cfg"; then
    log_pass "tool_config written the setconfig way (firewall_area=2, authentication, hermetic dns_nameserver)"
else
    log_fail "tool_config overrides"
fi
if sub sh -c "grep -q 'sub-ss-aes256' $SC_DIR/yamls/config.yaml"; then
    log_pass "subscription-shape config imported at yamls/config.yaml"
else
    log_fail "subscription import"
fi

# kernel install helper: seed $BINDIR/CrashCore.gz (the archive form
# libs/core_tools.sh core_check() itself stores after a kernel download;
# check_core -> core_find re-materializes $TMPDIR/CrashCore from it)
install_mihomo_kernel() {
    sub bash -c '
rm -f '"$TMPDIR_SC"'/CrashCore '"$SC_DIR"'/CrashCore.* '"$TMPDIR_SC"'/error.yaml '"$SC_DIR"'/.start_error
gzip -c /tmp/sc/mihomo-kernel > '"$SC_DIR"'/CrashCore.gz
'
}
# the migration kernel: the CLI adapter (fixtures/rustcrash-kernel-adapter.sh)
# as $TMPDIR/CrashCore, padded past the find -size +2000 threshold that
# starts/check_core.sh uses to recognize a kernel file
install_rust_kernel() {
    sub bash -c '
cp /sc-fixtures/rustcrash-kernel-adapter.sh '"$SC_DIR"'/tools/CrashCore-rust
chmod +x '"$SC_DIR"'/tools/CrashCore-rust
rm -f '"$SC_DIR"'/CrashCore.* '"$TMPDIR_SC"'/error.yaml '"$SC_DIR"'/.start_error '"$TMPDIR_SC"'/engine-rust.log
{ cat '"$SC_DIR"'/tools/CrashCore-rust; for i in $(seq 1 22000); do echo "# rustcrash kernel adapter padding line $i"; done; } > '"$TMPDIR_SC"'/CrashCore
chmod +x '"$TMPDIR_SC"'/CrashCore
'
}

sc_stop() {
    sub bash -c "'$SC_DIR'/start.sh stop" >/dev/null 2>&1 || true
    # the engine's SIGTERM shutdown can linger a few seconds (it logs
    # "shutting down" then races its own tasks); poll before checking,
    # and as a last resort take the process down so later phases start
    # from a clean slate (suite self-defense, not an assertion)
    local i=0
    while crash_running && [ $i -lt 15 ]; do
        sleep 1
        i=$((i+1))
    done
    sub bash -c 'pgrep -x crash >/dev/null && pkill -x crash' >/dev/null 2>&1 || true
    sleep 1
}

check_nft_fw() { # <label>: ShellCrash's own fw scripts, same assertions both phases
    local label=$1
    if sub nft list table inet shellcrash >/dev/null 2>&1; then
        log_pass "$label: nft table inet shellcrash exists"
    else
        log_fail "$label: nft table inet shellcrash missing"
        return
    fi
    local rules
    rules=$(sub nft list table inet shellcrash 2>/dev/null | tr -d '\r')
    echo "$rules" | grep -q "udp dport 53 redirect to :$SC_DNS" \
        && echo "$rules" | grep -q "tcp dport 53 redirect to :$SC_DNS" \
        && log_pass "$label: DNS-hijack rules redirect :53 -> :$SC_DNS" \
        || log_fail "$label: DNS-hijack rules"
    echo "$rules" | grep -q "meta skgid 7890 return" \
        && echo "$rules" | grep -q "meta mark 0x00001ed6 return" \
        && log_pass "$label: loop-guard exemptions present (skgid 7890 + routing-mark 7894 return)" \
        || log_fail "$label: loop-guard exemptions"
    echo "$rules" | grep -q "tcp redirect to :$SC_REDIR" \
        && log_pass "$label: REDIRECT rule to redir port $SC_REDIR present" \
        || log_fail "$label: REDIRECT rule"
}

check_generated_config() { # <label> <config-path>: set.yaml fields in the generated config
    local label=$1 cfg=$2
    local ok=1
    for field in \
        "^mixed-port: $SC_MIX$" \
        "^redir-port: $SC_REDIR$" \
        "^tproxy-port: $SC_TPROXY$" \
        "^authentication: \[\"e2e-user:e2e-pass\"\]$" \
        "^allow-lan: true$" \
        "^external-controller: " \
        "^routing-mark: 7894$" \
        "^unified-delay: true$" \
        "^tun: {enable: false}$"; do
        sub sh -c "grep -qE '$field' $cfg" 2>/dev/null || ok=0
    done
    [ "$ok" = 1 ] \
        && log_pass "$label: generated config carries the set.yaml fields (ports/auth/routing-mark/unified-delay/tun)" \
        || log_fail "$label: generated config missing set.yaml fields (see $cfg)"
}

check_relay_matrix() { # <label> <user:pass> <result-var-prefix>
    local label=$1 auth=$2 prefix=$3
    local node rc out
    for node in sub-ss-aes256 sub-vmess-tcp sub-vmess-ws; do
        rc=$(pick_node "$node" | tr -d '\r')
        out=$(relay "$auth")
        if [ "$out" = "$EXPECTED_BODY" ]; then
            log_pass "$label: TCP relay via $node (rc=$rc, body match)"
            eval "${prefix}_${node//-/_}=1"
        else
            log_fail "$label: TCP relay via $node: got '${out:0:50}'"
            eval "${prefix}_${node//-/_}=0"
        fi
    done
}

# ---------------------------------------------------------------------------
# 4. PHASE 1 — BASELINE: the real mihomo kernel under real ShellCrash
# ---------------------------------------------------------------------------
echo "=== Phase 1 (baseline): ShellCrash + the real mihomo kernel ==="
install_mihomo_kernel
sub bash -c "'$SC_DIR'/start.sh start" >/tmp/sc-phase1-start.out 2>&1 || true
P1_UP=0
if wait_port "$SC_API" 60 && sub sh -c 'pidof CrashCore >/dev/null'; then
    P1_UP=1
    log_pass "ShellCrash started the mihomo kernel (pidof CrashCore + panel api up)"
else
    log_fail "phase 1 start (mihomo kernel); log tail:"
    sub sh -c "tail -5 $TMPDIR_SC/ShellCrash.log" | tr -d '\r'
fi

if [ "$P1_UP" = 1 ]; then
    p1ver=$(sub sh -c "curl -s --max-time 4 http://127.0.0.1:$SC_API/version" 2>/dev/null | tr -d '\r')
    case "$p1ver" in
        *Mihomo*|*Meta*|*v1.19*) log_pass "kernel identity: panel /version reports mihomo ($p1ver)" ;;
        *) log_fail "kernel identity: /version gave '$p1ver'" ;;
    esac

    # where the generated config lands: $BINDIR/config.yaml -> $TMPDIR/config.yaml
    if sub sh -c "test -s $TMPDIR_SC/config.yaml"; then
        log_pass "clash_modify.sh generated config.yaml at $TMPDIR_SC/config.yaml (linked at \$BINDIR)"
    else
        log_fail "generated config.yaml"
    fi
    sub cp "$TMPDIR_SC/config.yaml" /tmp/interop/config-phase1.yaml >/dev/null 2>&1 || true
    check_generated_config "phase 1" "$TMPDIR_SC/config.yaml"
    if sub sh -c "test -f $SC_DIR/config.yaml"; then
        log_pass "kernel config linked at \$BINDIR/config.yaml (mihomo -d form)"
    else
        log_fail "\$BINDIR/config.yaml link"
    fi
    check_nft_fw "phase 1"

    # DNS hijack: a query to 127.0.0.1:53 is nft-redirected to the kernel's
    # dns listener; redir_host emulation ('+.*' filter) resolves through the
    # oracle upstream -> 10.9.9.9
    dns1=$(sub sh -c "dig +short +time=3 +tries=1 @127.0.0.1 web.shellcrash.test A 2>/dev/null | head -1" | tr -d '\r')
    [ "$dns1" = "10.9.9.9" ] \
        && log_pass "phase 1 DNS hijack answers with the oracle's 10.9.9.9 (nft :53 -> :$SC_DNS -> kernel dns -> upstream)" \
        || log_fail "phase 1 DNS hijack: got '$dns1'"

    check_relay_matrix "phase 1" "e2e-user:e2e-pass" PH1

    # negatives: no/wrong credentials must be refused by the kernel
    out=$(relay "e2e-user")
    [ "$out" = "$EXPECTED_BODY" ] \
        && log_fail "phase 1 negative: missing proxy credential SILENTLY RELAYED" \
        || log_pass "phase 1 negative: missing credential refused (empty: '${out:0:30}')"
    out=$(relay "e2e-user:WRONG")
    [ "$out" = "$EXPECTED_BODY" ] \
        && log_fail "phase 1 negative: wrong proxy password SILENTLY RELAYED" \
        || log_pass "phase 1 negative: wrong password refused"
fi

# stop: the manager must tear the kernel + firewall down again
sc_stop
if sub sh -c 'pidof CrashCore >/dev/null'; then
    log_fail "phase 1 stop: CrashCore still running"
else
    log_pass "phase 1 stop: kernel gone"
fi
if sub nft list table inet shellcrash >/dev/null 2>&1; then
    log_fail "phase 1 stop: nft table still present"
else
    log_pass "phase 1 stop: nft table inet shellcrash removed"
fi

# ---------------------------------------------------------------------------
# 5. PHASE 2 — MIGRATION: swap the kernel for the RustCrash engine
# ---------------------------------------------------------------------------
echo "=== Phase 2 (migration): replacing the kernel with the RustCrash engine ==="

# --- 2a. the RAW drop-in (binary swap, nothing else): the crash binary
# natively speaks mihomo's kernel CLI (`-t -d DIR -f FILE` test, `-d -f`
# run, `-v`/`-h` probes) — gap A fixed in cmd/crash (kernel_compat).
sub bash -c 'ln -sf /usr/local/bin/crash '"$TMPDIR_SC"'/CrashCore' >/dev/null 2>&1
raw_t=$(sub bash -c "'$TMPDIR_SC'/CrashCore -t -d $SC_DIR -f /tmp/interop/config-phase1.yaml 2>&1; echo rc=\$?" | tr -d '\r')
raw_v=$(sub sh -c "'$TMPDIR_SC'/CrashCore -v 2>&1" | tr -d '\r')
raw_h=$(sub sh -c "'$TMPDIR_SC'/CrashCore -h 2>&1" | tr -d '\r')
if echo "$raw_t" | grep -q 'rc=0' && ! echo "$raw_t" | grep -q 'unexpected argument' \
    && echo "$raw_v" | grep -q 'RustCrash' && echo "$raw_h" | grep -q -- '-t'; then
    log_pass "raw drop-in probes: mihomo kernel CLI accepted natively (-t/-d/-f validates the RAW ShellCrash config, -v/-h answer)"
else
    log_fail "raw drop-in probes: t='${raw_t:0:80}' v='${raw_v:0:40}' h='${raw_h:0:40}'"
fi
sub bash -c 'rm -f '"$TMPDIR_SC"'/CrashCore' >/dev/null 2>&1
# check_core's kernel-size heuristic: `find CrashCore -size +2000`
# (512-byte blocks, i.e. > 1MiB) — the real release binary qualifies.
raw_size=$(sub stat -c %s /usr/local/bin/crash 2>/dev/null | tr -d '\r')
if [ "${raw_size:-0}" -gt 1048576 ]; then
    log_pass "raw binary passes check_core's find -size +2000 kernel threshold (${raw_size} bytes)"
else
    log_fail "raw binary size ${raw_size:-?} below the kernel threshold"
fi
# the full "ShellCrash runs unchanged" proof: install the RAW binary as
# the kernel (a real file, not the adapter) and drive the SAME start
# flow — the engine parses ShellCrash's raw config natively (mode Rule,
# :9999 controller, :1053 dns, authentication, routing-mark).
sub bash -c '
rm -f '"$TMPDIR_SC"'/CrashCore '"$SC_DIR"'/CrashCore.* '"$SC_DIR"'/tools/CrashCore-rust '"$TMPDIR_SC"'/error.yaml '"$SC_DIR"'/.start_error '"$TMPDIR_SC"'/engine-rust.log
cp /usr/local/bin/crash '"$TMPDIR_SC"'/CrashCore
chmod +x '"$TMPDIR_SC"'/CrashCore
'
sub bash -c "'$SC_DIR'/start.sh start" >/dev/null 2>&1 || true
if wait_port "$SC_API" 60; then
    log_pass "raw binary drop-in: the SAME ShellCrash start flow runs the Rust engine with NO adapter"
    raw_body=$(relay "e2e-user:e2e-pass")
    if [ "$raw_body" = "$EXPECTED_BODY" ]; then
        log_pass "raw drop-in relay works through the raw ShellCrash config (incl. authentication)"
    else
        log_fail "raw drop-in relay: '${raw_body:0:40}'"
    fi
    sub bash -c "'$SC_DIR'/start.sh stop" >/dev/null 2>&1 || true
    raw_wait=99
    for i in $(seq 1 15); do
        if ! sub sh -c 'pidof CrashCore >/dev/null' 2>/dev/null; then raw_wait=$i; break; fi
        sleep 1
    done
    if [ "$raw_wait" -le 15 ]; then
        log_pass "raw drop-in engine exits on ShellCrash's SIGTERM stop (${raw_wait}s)"
    else
        log_fail "raw drop-in engine lingers after stop"
        sub bash -c 'pkill -x CrashCore; pkill -x crash' >/dev/null 2>&1 || true
        sleep 1
    fi
else
    log_fail "raw drop-in start (panel api never came up); log tail:"
    sub sh -c 'tail -8 '"$TMPDIR_SC"'/ShellCrash.log' | tr -d '\r'
    sub bash -c "'$SC_DIR'/start.sh stop" >/dev/null 2>&1 || true
    sub bash -c 'pkill -x CrashCore; pkill -x crash' >/dev/null 2>&1 || true
fi
sleep 1

# --- 2b. the migration kernel: the CLI adapter as CrashCore ---
install_rust_kernel
if sub sh -c "'$TMPDIR_SC'/CrashCore -h 2>/dev/null | grep -q '\-t'" \
    && sub sh -c "'$TMPDIR_SC'/CrashCore -v 2>/dev/null | grep -q rustcrash"; then
    log_pass "adapter installed as \$TMPDIR/CrashCore (passes core_check's -h/-v kernel probes)"
else
    log_fail "adapter kernel probes"
fi

sub bash -c "'$SC_DIR'/start.sh start" >/tmp/sc-phase2-start.out 2>&1 || true
P2_UP=0
if wait_port "$SC_API" 60; then
    P2_UP=1
    log_pass "the SAME ShellCrash start flow brought up the Rust engine (panel api up)"
else
    log_fail "phase 2 start (rust engine); log tail:"
    sub sh -c "tail -5 $TMPDIR_SC/ShellCrash.log; tail -5 $TMPDIR_SC/engine-rust.log 2>/dev/null" | tr -d '\r'
fi

if [ "$P2_UP" = 1 ]; then
    # identity: it must be the ENGINE serving the panel, not a kernel
    p2ver=$(sub sh -c "curl -s --max-time 4 http://127.0.0.1:$SC_API/version" 2>/dev/null | tr -d '\r')
    engver=$(sub crash engine version 2>/dev/null | head -1 | awk '{print $NF}' | tr -d '\r')
    case "$p2ver" in
        *"$engver"*) log_pass "kernel identity: panel /version reports the Rust engine ($p2ver)" ;;
        *) log_fail "kernel identity: /version gave '$p2ver' (engine version $engver)" ;;
    esac

    # listeners: mixed/redir/tproxy/api + dns — via ss (NO connection to the
    # tproxy port; see gap G below for why that matters)
    lb=0; lt=0
    for p in "$SC_MIX" "$SC_REDIR" "$SC_TPROXY" "$SC_API"; do
        lt=$((lt+1))
        listener_bound "$p" && lb=$((lb+1))
    done
    [ "$lb" = "$lt" ] \
        && log_pass "engine listeners bound from set.yaml (mixed/redir/tproxy/api, live LISTEN-checked)" \
        || log_fail "engine listeners ($lb/$lt)"
    sub bash -c "ss -uln | grep -q ':$SC_DNS '" 2>/dev/null \
        && log_pass "engine dns listener bound on :$SC_DNS (udp)" \
        || log_fail "engine dns listener"

    # ShellCrash's own config validation (test_yaml) ran through the adapter
    if sub sh -c "test ! -f $TMPDIR_SC/error.yaml" && sub sh -c "test -s $TMPDIR_SC/config.yaml.rustcrash"; then
        log_pass "clash_modify.sh validation passed via the adapter (no error.yaml fallback; merged config kept)"
    else
        log_fail "phase 2 validation state (error.yaml present?)"
    fi
    check_generated_config "phase 2" "$TMPDIR_SC/config.yaml"
    ndiff=$(sub sh -c "diff $TMPDIR_SC/config.yaml $TMPDIR_SC/config.yaml.rustcrash | grep -c '^<'" 2>/dev/null | tr -d '\r')
    if [ "${ndiff:-x}" = 3 ]; then
        log_pass "adapter normalization touched exactly 3 lines (mode casing, external-controller form, dns listen form)"
    else
        log_fail "adapter normalization diff: ${ndiff} changed lines (expected 3)"
    fi

    # firewall: ShellCrash's own scripts, unchanged between phases
    check_nft_fw "phase 2"

    # DNS hijack still answers — ShellCrash's dns.yaml uses fake-ip-filter
    # '+.*' (exclude everything = redir_host emulation); gap D fixed: a
    # bare `*` suffix in the DomainMatcher matches every domain, so the
    # engine resolves through the upstream instead of answering fake-ips.
    dns2=$(sub sh -c "dig +short +time=3 +tries=1 @127.0.0.1 web.shellcrash.test A 2>/dev/null | head -1" | tr -d '\r')
    case "$dns2" in
        10.9.9.9)
            log_pass "phase 2 DNS hijack answers with the oracle's 10.9.9.9 (match-all '+.*' filter implemented)"
            ;;
        198.18.*)
            log_fail "phase 2 DNS hijack answered with a fake-ip ($dns2): the '+.*' match-all filter is not in effect"
            ;;
        *)
            log_fail "phase 2 DNS hijack: got '$dns2'"
            ;;
    esac

    check_relay_matrix "phase 2" "e2e-user:e2e-pass" PH2

    # gap F fixed: the engine enforces set.yaml's `authentication` on the
    # mixed/http/socks listeners (HTTP 407 challenge / SOCKS5 RFC 1929).
    out=$(relay "e2e-user:WRONG")
    if [ "$out" = "$EXPECTED_BODY" ]; then
        log_fail "phase 2 negative: wrong proxy credentials SILENTLY RELAYED (authentication not enforced)"
    else
        log_pass "phase 2 negative: wrong password refused by the engine"
    fi
fi

# ---------------------------------------------------------------------------
# 6. PHASE 3 — CLI compat on the migrated box
# ---------------------------------------------------------------------------
echo "=== Phase 3: CLI compatibility of the migrated layout ==="
if sub sh -c 'test -x /usr/bin/crash && grep -q "menu.sh" /usr/bin/crash'; then
    log_pass "/usr/bin/crash still wraps ShellCrash's menu.sh (manager unchanged by the swap)"
else
    log_fail "/usr/bin/crash wrapper after migration"
fi
menu_out=$(sub bash -c 'timeout 6 /usr/bin/crash </dev/null 2>&1 | head -20' 2>/dev/null | tr -d '\r')
if [ -n "$menu_out" ] && echo "$menu_out" | grep -q "7890"; then
    log_pass "ShellCrash menu runs through the wrapper (port check visible in non-interactive smoke)"
else
    log_fail "menu smoke: '${menu_out:0:60}'"
fi
if sub crash engine version >/dev/null 2>&1; then
    log_pass "crash engine version works (subcommand form)"
else
    log_fail "crash engine version"
fi
if [ "$P2_UP" = 1 ] && sub crash engine test --flavor rust-mihomo --config "$TMPDIR_SC/config.yaml.rustcrash" >/dev/null 2>&1; then
    log_pass "crash engine test accepts ShellCrash's generated config on the migrated layout"
else
    log_fail "crash engine test against the migrated config"
fi
# gap H fixed: the manager CLI names the config-model collision on a
# ShellCrash layout precisely instead of leaking serde's
# "missing field `kernel`" (core config.rs looks_like_kernel_config).
mgr_out=$(sub bash -c 'crash -c /etc/ShellCrash config show 2>&1' | tr -d '\r')
if echo "$mgr_out" | grep -q "KERNEL config" && echo "$mgr_out" | grep -qi "shellcrash"; then
    log_pass "manager CLI on the migrated layout names the kernel-config collision precisely (hints the engine path)"
else
    log_fail "manager config command: '$mgr_out'"
fi
fw_out=$(sub bash -c 'crash -c /etc/ShellCrash firewall show 2>&1' | tr -d '\r')
if echo "$fw_out" | grep -q "nftables" && echo "$fw_out" | grep -q "true"; then
    log_pass "crash firewall show works against the migrated layout (backend nftables, available)"
else
    log_fail "crash firewall show: '$fw_out'"
fi

# ---------------------------------------------------------------------------
# 7. PHASE 4 — subscription shape through BOTH kernels (comparison)
# ---------------------------------------------------------------------------
echo "=== Phase 4: subscription shape, phase 1 vs phase 2 ==="
same=1
for node in sub_ss_aes256 sub_vmess_tcp sub_vmess_ws; do
    p1=$(eval "echo \${PH1_$node:-0}")
    p2=$(eval "echo \${PH2_$node:-0}")
    [ "$p1" = "$p2" ] && [ "$p1" = 1 ] || same=0
done
if [ "$same" = 1 ]; then
    log_pass "the SAME converter-shaped subscription relays identically through both kernels (ss/vmess/vmess-ws)"
else
    log_fail "subscription relay divergence between kernels (see the matrices above)"
fi

# --- stop the migrated instance: the pidfile path must still work ---
if [ "$P2_UP" = 1 ]; then
    sub bash -c "'$SC_DIR'/start.sh stop" >/dev/null 2>&1 || true
    eng_wait=99
    for i in $(seq 1 15); do
        if ! crash_running; then eng_wait=$i; break; fi
        sleep 1
    done
    if [ "$eng_wait" -le 15 ]; then
        log_pass "phase 2 stop: engine terminated via ShellCrash's pidfile path (exited ${eng_wait}s after SIGTERM — gap I: bounded shutdown)"
    else
        log_fail "phase 2 stop: engine still running 15s after SIGTERM"
        echo "  --- diag: processes ---"
        sub bash -c 'ps -ef | grep -iE "crash" | grep -v grep' 2>/dev/null | tr -d '\r' | sed 's/^/  /'
        echo "  --- diag: engine log tail ---"
        sub sh -c 'tail -6 '"$TMPDIR_SC"'/engine-rust.log 2>/dev/null' | tr -d '\r' | cat -v | sed 's/^/  /'
        sub bash -c 'pkill -x crash' >/dev/null 2>&1 || true
        sleep 1
    fi
    if sub nft list table inet shellcrash >/dev/null 2>&1; then
        log_fail "phase 2 stop: nft table still present"
    else
        log_pass "phase 2 stop: nft table removed"
    fi

    # restart resilience: the migrated start is repeatable
    install_rust_kernel
    sub bash -c "'$SC_DIR'/start.sh start" >/dev/null 2>&1 || true
    if wait_port "$SC_API" 60; then
        out=$(relay "e2e-user:e2e-pass")
        [ "$out" = "$EXPECTED_BODY" ] \
            && log_pass "migrated setup restarts cleanly through start.sh (kernel swap is repeatable)" \
            || log_fail "restart relay: '${out:0:40}'"
        sc_stop
    else
        log_fail "migrated restart"
    fi
fi

# ---------------------------------------------------------------------------
# 8. Engine-gap reproductions (isolated instances; ports 47xxx)
# ---------------------------------------------------------------------------
echo "=== Engine gaps: precise reproductions on isolated instances ==="
sub bash -c 'sed -e "s/^mixed-port: 7890/mixed-port: '"$ISO_MIX"'/" \
    -e "s/^redir-port: 7892/redir-port: '"$((ISO_MIX+2))"'/" \
    -e "s/^tproxy-port: 7893/tproxy-port: '"$ISO_TPROXY"'/" \
    -e "s|^external-controller: .*|external-controller: %API%|" \
    -e "s|^\( *listen: *\).*|\1%DNSLISTEN%|" \
    /tmp/interop/config-phase1.yaml > /tmp/interop/iso-base.yaml'

# gap B fixed: mihomo lowercases the mode before matching — ShellCrash's
# set.yaml hardcodes `mode: Rule`, which must parse like `rule`.
sub bash -c 'sed "s/%API%/127.0.0.1:'"$ISO_API"'/
    s/%DNSLISTEN%/0.0.0.0:'"$ISO_DNS"'/" /tmp/interop/iso-base.yaml > /tmp/interop/iso-B.yaml'
pinB=$(sub bash -c 'timeout 6 crash engine test --flavor rust-mihomo --config /tmp/interop/iso-B.yaml 2>&1; echo rc=$?' | tr -d '\r')
if echo "$pinB" | grep -q 'rc=0' && ! echo "$pinB" | grep -q 'bad mode'; then
    log_pass "gap B fixed: \`mode: Rule\` (ShellCrash's capitalized form) parses like mihomo"
else
    log_fail "gap B pin: mode still rejected: '${pinB:0:80}'"
fi

# gap C fixed: mihomo's leading-colon dns listen (`:1053`) is the
# all-interfaces shorthand — the engine normalizes to 0.0.0.0 and binds.
sub bash -c 'sed -e "s/^mode: Rule/mode: rule/" \
    -e "s/%API%/127.0.0.1:'"$ISO_API"'/" -e "s/%DNSLISTEN%/:'"$ISO_DNS"'/" \
    /tmp/interop/iso-base.yaml > /tmp/interop/iso-C.yaml'
$DC exec -T -d rustcrash bash -c 'crash engine run --flavor rust-mihomo --config /tmp/interop/iso-C.yaml >/tmp/interop/iso-C.log 2>&1'
sleep 3
dnsC=$(sub sh -c "dig +short +time=3 +tries=1 @127.0.0.1 -p $ISO_DNS web.shellcrash.test A 2>/dev/null | head -1" | tr -d '\r')
sub bash -c 'pkill -f iso-C.yaml' >/dev/null 2>&1 || true
sleep 1
if [ "$dnsC" = "10.9.9.9" ]; then
    log_pass "gap C fixed: dns listen ':$ISO_DNS' binds all interfaces and answers (oracle 10.9.9.9 through the '+.*' match-all filter)"
elif [ -n "$dnsC" ]; then
    log_fail "gap C pin: dns answered '$dnsC' (expected the oracle's 10.9.9.9)"
else
    log_fail "gap C pin: dns listener never answered (engine did not start); log: $(sub sh -c 'tail -3 /tmp/interop/iso-C.log' | tr -d '\r')"
fi

# gap E fixed: mihomo's leading-colon external-controller (`:9999`) binds
# 0.0.0.0 — the panel must come up on the shorthand form.
sub bash -c 'sed -e "s/^mode: Rule/mode: rule/" \
    -e "s/%API%/:'"$ISO_API"'/" -e "s/%DNSLISTEN%/0.0.0.0:'"$ISO_DNS"'/" \
    /tmp/interop/iso-base.yaml > /tmp/interop/iso-E.yaml'
$DC exec -T -d rustcrash bash -c 'crash engine run --flavor rust-mihomo --config /tmp/interop/iso-E.yaml >/tmp/interop/iso-E.log 2>&1'
apiE=""
for _ in $(seq 1 20); do
    apiE=$(sub sh -c "curl -s --max-time 3 http://127.0.0.1:$ISO_API/version" 2>/dev/null | tr -d '\r')
    [ -n "$apiE" ] && break
    sleep 0.5
done
sub bash -c 'pkill -f iso-E.yaml' >/dev/null 2>&1 || true
sleep 1
if echo "$apiE" | grep -q '"version"'; then
    log_pass "gap E fixed: external-controller ':$ISO_API' binds all interfaces (panel /version: $apiE)"
else
    log_fail "gap E pin: api never answered on ':$ISO_API'"
    echo "  --- diag: full iso-E.log ---"
    sub sh -c 'cat /tmp/interop/iso-E.log 2>/dev/null' | tr -d '\r' | cat -v | sed 's/^/  /'
fi

# gap G fixed: (a) routing-mark is applied to every outbound socket
# (SO_MARK before the handshake, verified by an nft counter on marked
# output packets) and (b) the transparent inbounds refuse to relay a
# destination that IS the engine's own listener — a direct connection to
# the tproxy port must no longer cascade.
sub bash -c 'sed -e "s/^mode: Rule/mode: rule/" \
    -e "s/%API%/127.0.0.1:'"$ISO_API"'/" -e "s/%DNSLISTEN%/0.0.0.0:'"$ISO_DNS"'/" \
    /tmp/interop/iso-base.yaml > /tmp/interop/iso-G.yaml'
$DC exec -T -d rustcrash bash -c 'crash engine run --flavor rust-mihomo --config /tmp/interop/iso-G.yaml >/tmp/interop/iso-G.log 2>&1'
sleep 3
# mark counter: packets leaving with mark 7894 (the config's routing-mark)
sub nft add table inet mtest >/dev/null 2>&1 || true
sub bash -c "nft 'add chain inet mtest out { type filter hook output priority -1 ; }'" >/dev/null 2>&1
sub nft add rule inet mtest out meta mark 7894 counter >/dev/null 2>&1
mark_out=$(sub sh -c "curl -s --max-time 8 -x http://e2e-user:e2e-pass@127.0.0.1:$ISO_MIX http://127.0.0.1:$WEB_PORT/hello.txt" 2>&1)
mark_packets=$(sub nft list chain inet mtest out 2>/dev/null | grep -o 'counter packets [0-9]*' | grep -o '[0-9]*$' | head -1 | tr -d '\r')
sub nft delete table inet mtest >/dev/null 2>&1 || true
# self-relay probe: one direct connection to the tproxy port
sub bash -c '(exec 3<>/dev/tcp/127.0.0.1/'"$ISO_TPROXY"')' 2>/dev/null || true
sleep 4
loopconns=$(sub sh -c "ss -tn 2>/dev/null | grep -c ':$ISO_TPROXY'" | tr -d '\r')
sub bash -c 'pkill -f iso-G.yaml' >/dev/null 2>&1 || true
sleep 1
if [ "${mark_packets:-0}" -gt 0 ] 2>/dev/null; then
    log_pass "gap G fixed (mark): outbound dials carry routing-mark 7894 (${mark_packets} marked packets; relay body '${mark_out:0:20}')"
else
    log_fail "gap G pin (mark): no packets left with mark 7894 (routing-mark not applied); relay='${mark_out:0:40}'"
fi
if [ "${loopconns:-0}" -le 5 ] 2>/dev/null; then
    log_pass "gap G fixed (loop): a direct tproxy connection does not self-relay (${loopconns} conns, was 1000+)"
else
    log_fail "gap G pin (loop): self-relay cascade still reproduces (${loopconns} connections)"
fi

echo
echo "=== Matrix summary ==="
echo "  phase 1 (mihomo kernel):  ss=${PH1_sub_ss_aes256:-?} vmess=${PH1_sub_vmess_tcp:-?} vmess-ws=${PH1_sub_vmess_ws:-?} dns=$dns1"
echo "  phase 2 (rust engine):    ss=${PH2_sub_ss_aes256:-?} vmess=${PH2_sub_vmess_tcp:-?} vmess-ws=${PH2_sub_vmess_ws:-?} dns=$dns2"
[ "$SKIP" -gt 0 ] && echo "=== Skipped: $SKIP (EXPECTED-FAIL engine gaps, labelled above) ==="
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" = 0 ]
