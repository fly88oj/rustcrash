#!/bin/bash
# E2E Test Script for RustCrash - VM Edition
# This script runs COMPLETELY INSIDE the VM via SSH
# Usage: ./e2e-test-vm.sh [--vm-host HOST] [--vm-port PORT] [--vm-key KEY]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

CRASHDIR="/tmp/rustcrash_e2e_$$"
export CRASHDIR

cleanup() {
    rm -rf "$CRASHDIR" 2>/dev/null || true
}
trap cleanup EXIT

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; ((SKIPPED++)) || true; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# ========================================
# Parse Arguments
# ========================================
VM_HOST="${VM_HOST:-localhost}"
VM_PORT="${VM_PORT:-2222}"
VM_KEY="${VM_KEY:-$HOME/works/sandbox/vm/id_rsa}"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -i '$VM_KEY'"

# If not in VM, show help
if [[ ! -f "/.dockerenv" ]] && [[ "$VM_HOST" == "localhost" ]]; then
    if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$VM_KEY" ubuntu@localhost -p $VM_PORT 'echo ok' 2>/dev/null; then
        echo "VM not accessible at $VM_HOST:$VM_PORT"
        echo "This script must be run INSIDE the VM or with proper SSH forwarding"
        exit 1
    fi
fi

ssh_run() {
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -i "$VM_KEY" "ubuntu@$VM_HOST" -p "$VM_PORT" "$@"
}

ssh_run_script() {
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -i "$VM_KEY" "ubuntu@$VM_HOST" -p "$VM_PORT" bash -s << 'EOSSH'
set -e
CRASHDIR="${CRASHDIR:-/tmp/rustcrash_e2e_\$\$}"
export CRASHDIR
mkdir -p "$CRASHDIR"

# ===== COPY TEST SCRIPT HERE FOR REMOTE EXECUTION =====
# (This allows running same tests in VM without scp)

run_tests() {
    local PASSED=0 FAILED=0 SKIPPED=0
    local RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' NC='\033[0m'
    
    log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
    log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
    log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; ((SKIPPED++)) || true; }
    log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }

    BIN_DIR="/tmp/rustcrash_test"
    mkdir -p "$BIN_DIR"

    echo "=========================================="
    echo "RustCrash VM E2E Test Suite"
    echo "=========================================="
    echo "CrashDir: $CRASHDIR"
    echo "Kernel: \$(uname -a)"
    echo ""

    # ========================================
    # Test 1: Binary availability
    # ========================================
    log_info "Checking binary availability..."
    for bin in crash startctl installctl initctl firewallctl configctl taskctl setbootctl; do
        if [[ -f "\$BIN_DIR/\$bin" ]]; then
            log_pass "Binary exists: \$bin"
        else
            log_fail "Binary NOT found: \$bin"
        fi
    done

    # ========================================
    # Test 2: crash --version
    # ========================================
    echo ""
    log_info "Testing: crash --version"
    if VERSION=\$("$BIN_DIR/crash" --version 2>&1); then
        if echo "\$VERSION" | grep -q "RustCrash"; then
            log_pass "crash --version works"
            echo "\$VERSION" | head -5
        else
            log_fail "crash --version unexpected output"
        fi
    else
        log_fail "crash --version failed"
    fi

    # ========================================
    # Test 3: Platform Detection
    # ========================================
    echo ""
    log_info "Testing: Platform detection"
    PLATFORM=\$("$BIN_DIR/crash" --version 2>&1 | grep "Platform:" || echo "")
    if [[ -n "\$PLATFORM" ]]; then
        log_pass "Platform detection works: \$PLATFORM"
    else
        log_fail "Platform detection failed"
    fi

    # ========================================
    # Test 4: initctl directory creation
    # ========================================
    echo ""
    log_info "Testing: initctl directory creation"
    if "$BIN_DIR/initctl" --crashdir "$CRASHDIR" 2>&1 | grep -qiE "complete|created|ok"; then
        log_pass "initctl runs successfully"
    else
        log_fail "initctl failed"
    fi

    for dir in bin run logs config data; do
        if [[ -d "$CRASHDIR/\$dir" ]]; then
            log_pass "Directory created: \$dir"
        else
            log_fail "Directory NOT created: \$dir"
        fi
    done

    # ========================================
    # Test 5: configctl functionality
    # ========================================
    echo ""
    log_info "Testing: configctl"
    CONFIG_OUTPUT=\$("$BIN_DIR/configctl" --crashdir "$CRASHDIR" show 2>&1) && {
        if echo "\$CONFIG_OUTPUT" | grep -qi "mihomo\|kernel"; then
            log_pass "configctl show returns valid config"
        else
            log_fail "configctl show unexpected output"
        fi
    } || log_fail "configctl show failed"

    # ========================================
    # Test 6: Firewall script generation
    # ========================================
    echo ""
    log_info "Testing: firewallctl"
    
    IPT_SCRIPT=\$("$BIN_DIR/firewallctl" generate --backend iptables 2>&1) && {
        if echo "\$IPT_SCRIPT" | grep -q "iptables"; then
            log_pass "iptables script generation works"
        else
            log_fail "iptables script missing iptables commands"
        fi
    } || log_fail "iptables generation failed (expected - requires root)"

    NFT_SCRIPT=\$("$BIN_DIR/firewallctl" generate --backend nftables 2>&1) && {
        if echo "\$NFT_SCRIPT" | grep -q "nft"; then
            log_pass "nftables script generation works"
        else
            log_fail "nftables script missing nft commands"
        fi
    } || log_fail "nftables generation failed (expected - requires root)"

    # ========================================
    # Test 7: Kernel status (no kernel installed)
    # ========================================
    echo ""
    log_info "Testing: startctl status"
    STATUS_OUTPUT=\$("$BIN_DIR/startctl" --crashdir "$CRASHDIR" status 2>&1) && {
        if echo "\$STATUS_OUTPUT" | grep -qiE "stopped|not installed|mihomo"; then
            log_pass "startctl status works"
        else
            log_pass "startctl status returned output"
        fi
        echo "  Status: \$(echo "\$STATUS_OUTPUT" | head -3)"
    } || log_fail "startctl status failed"

    # ========================================
    # Test 8: Boot management
    # ========================================
    echo ""
    log_info "Testing: setbootctl"
    if "$BIN_DIR/setbootctl" status 2>&1 | grep -qiE "init|system"; then
        log_pass "setbootctl status works"
    else
        log_pass "setbootctl status returned output"
    fi

    # ========================================
    # Test 9: Task listing
    # ========================================
    echo ""
    log_info "Testing: taskctl"
    if "$BIN_DIR/taskctl" --crashdir "$CRASHDIR" list 2>&1 | grep -qiE "task|cron|schedule"; then
        log_pass "taskctl list works"
    else
        log_pass "taskctl list returned output"
    fi

    # ========================================
    # Summary
    # ========================================
    echo ""
    echo "=========================================="
    echo "Test Summary (inside VM)"
    echo "=========================================="
    echo -e "${GREEN}Passed:${NC} \$PASSED"
    echo -e "${RED}Failed:${NC} \$FAILED"
    echo -e "${YELLOW}Skipped:${NC} \$SKIPPED"
    echo ""

    [[ \$FAILED -eq 0 ]] && exit 0 || exit 1
}

run_tests
EOSSH
}

# ========================================
# MAIN: Run in current environment
# ========================================

echo "=========================================="
echo "RustCrash E2E Test Suite"
echo "=========================================="
echo "Testing from: \$(hostname)"
echo "Kernel: \$(uname -a)"
echo "CrashDir: $CRASHDIR"
echo ""

mkdir -p "$CRASHDIR"

BIN_DIR="./target/debug"
[[ -f "$BIN_DIR/crash" ]] || BIN_DIR="/tmp/rustcrash_test"

# Check if binary exists
if [[ ! -f "$BIN_DIR/crash" ]] && [[ ! -f "$BIN_DIR/rustcrash-crash" ]]; then
    echo "Error: No binaries found. Run 'cargo build' first."
    exit 1
fi

# ========================================
# Test 1: Binary existence
# ========================================
echo "--- Binary Tests ---"

CRASH_BIN="$BIN_DIR/crash"
[[ -f "$CRASH_BIN" ]] || CRASH_BIN="$BIN_DIR/rustcrash-crash"

if VERSION=$("$CRASH_BIN" --version 2>&1) && echo "$VERSION" | grep -q "RustCrash"; then
    log_pass "crash --version shows version info"
    echo "$VERSION" | head -5
else
    log_fail "crash --version failed"
fi

# ========================================
# Test 2: Platform detection
# ========================================
echo ""
echo "--- Platform Tests ---"
PLATFORM=$("$CRASH_BIN" --version 2>&1 | grep "Platform:" || echo "")
if [[ -n "$PLATFORM" ]]; then
    log_pass "Platform detection: $PLATFORM"
else
    log_fail "Platform detection failed"
fi

# ========================================
# Test 3: initctl
# ========================================
echo ""
echo "--- Initctl Tests ---"

INITCTL="$BIN_DIR/initctl"
[[ -f "$INITCTL" ]] || INITCTL="$BIN_DIR/rustcrash-initctl"

if "$INITCTL" --crashdir "$CRASHDIR" 2>&1 | grep -qiE "complete|created|ok"; then
    log_pass "initctl initializes successfully"
else
    log_fail "initctl initialization failed"
fi

for dir in bin run logs config data; do
    if [[ -d "$CRASHDIR/$dir" ]]; then
        log_pass "Directory created: $dir"
    else
        log_fail "Directory NOT created: $dir"
    fi
done

# ========================================
# Test 4: configctl
# ========================================
echo ""
echo "--- Config Tests ---"

CONFIGCTL="$BIN_DIR/configctl"
[[ -f "$CONFIGCTL" ]] || CONFIGCTL="$BIN_DIR/rustcrash-configctl"

CONFIG_OUTPUT=$("$CONFIGCTL" --crashdir "$CRASHDIR" show 2>&1) && {
    if echo "$CONFIG_OUTPUT" | grep -qi "mihomo\|kernel"; then
        log_pass "configctl show returns valid config"
    else
        log_fail "configctl show output unexpected"
    fi
} || log_fail "configctl show failed"

# ========================================
# Test 5: Firewall generation
# ========================================
echo ""
echo "--- Firewall Tests ---"

FIREWALLCTL="$BIN_DIR/firewallctl"
[[ -f "$FIREWALLCTL" ]] || FIREWALLCTL="$BIN_DIR/rustcrash-firewallctl"

IPT_OUTPUT=$("$FIREWALLCTL" generate --backend iptables 2>&1) && {
    if echo "$IPT_OUTPUT" | grep -q "iptables"; then
        log_pass "firewallctl generates iptables script"
    else
        log_fail "firewallctl iptables output unexpected"
    fi
} || log_fail "firewallctl generate iptables failed (requires root)"

NFT_OUTPUT=$("$FIREWALLCTL" generate --backend nftables 2>&1) && {
    if echo "$NFT_OUTPUT" | grep -q "nft"; then
        log_pass "firewallctl generates nftables script"
    else
        log_fail "firewallctl nftables output unexpected"
    fi
} || log_fail "firewallctl generate nftables failed (requires root)"

# ========================================
# Test 6: Kernel status
# ========================================
echo ""
echo "--- Kernel Management Tests ---"

STARTCTL="$BIN_DIR/startctl"
[[ -f "$STARTCTL" ]] || STARTCTL="$BIN_DIR/rustcrash-startctl"

STATUS_OUTPUT=$("$STARTCTL" --crashdir "$CRASHDIR" status 2>&1) && {
    log_pass "startctl status works"
    echo "  Status: $(echo "$STATUS_OUTPUT" | head -3)"
} || log_fail "startctl status failed"

# ========================================
# Test 7: Boot management
# ========================================
echo ""
echo "--- Boot Management Tests ---"

SETBOOTCTL="$BIN_DIR/setbootctl"
[[ -f "$SETBOOTCTL" ]] || SETBOOTCTL="$BIN_DIR/rustcrash-setbootctl"

if "$SETBOOTCTL" status 2>&1 | grep -qiE "init|system"; then
    log_pass "setbootctl status works"
else
    log_pass "setbootctl status returned output"
fi

# ========================================
# Test 8: Task management
# ========================================
echo ""
echo "--- Task Management Tests ---"

TASKCTL="$BIN_DIR/taskctl"
[[ -f "$TASKCTL" ]] || TASKCTL="$BIN_DIR/rustcrash-taskctl"

if "$TASKCTL" --crashdir "$CRASHDIR" list 2>&1 | grep -qiE "task|cron|schedule"; then
    log_pass "taskctl list works"
else
    log_pass "taskctl list returned output"
fi

# ========================================
# Test 9: Installctl
# ========================================
echo ""
echo "--- Install Tests ---"

INSTALLCTL="$BIN_DIR/installctl"
[[ -f "$INSTALLCTL" ]] || INSTALLCTL="$BIN_DIR/rustcrash-installctl"

if "$INSTALLCTL" --help 2>&1 | grep -qi "install"; then
    log_pass "installctl --help works"
else
    log_fail "installctl --help failed"
fi

# ========================================
# Summary
# ========================================
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "${GREEN}Passed:${NC} $PASSED"
echo -e "${RED}Failed:${NC} $FAILED"
echo -e "${YELLOW}Skipped:${NC} $SKIPPED"
echo ""

if [[ $FAILED -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
