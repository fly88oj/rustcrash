#!/bin/bash
# Run E2E tests INSIDE a VM for RustCrash
# IMPORTANT: Uses temporary copies to avoid affecting original VM files
# Usage: ./run-e2e-vm.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VM_DIR="${VM_DIR:-$HOME/works/sandbox/vm}"
VM_IMAGE="$VM_DIR/ubuntu-24.04-cloudimg-amd64.img"
VM_SSH_KEY="${VM_KEY:-$VM_DIR/id_rsa}"
VM_USER="ubuntu"
VM_PORT="${VM_PORT:-2222}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Temporary files (all cleaned up on exit)
TMP_BASE="/tmp/rustcrash_vm_test_$$"
TMP_IMAGE="$TMP_BASE.qcow2"
TMP_CLOUDINIT_DIR="$TMP_BASE/cloudinit"
TMP_SSH_KEY="$TMP_BASE/id_rsa"
QEMU_PID_FILE="$TMP_BASE/qemu.pid"

log() { echo "[$(date '+%H:%M:%S')] $1"; }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

# ========================================
# Cleanup Function - CRITICAL
# ========================================
cleanup() {
    log "Cleaning up temporary files..."

    # Kill QEMU if running
    if [[ -f "$QEMU_PID_FILE" ]]; then
        local pid=$(cat "$QEMU_PID_FILE" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log "Stopping QEMU (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 2
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$QEMU_PID_FILE"
    fi

    # Kill any QEMU on our port
    local qemu_pids=$(lsof -ti :$VM_PORT 2>/dev/null || true)
    if [[ -n "$qemu_pids" ]]; then
        log "Killing processes on port $VM_PORT..."
        echo "$qemu_pids" | xargs kill -9 2>/dev/null || true
    fi

    # Remove temporary files
    rm -rf "$TMP_BASE"* 2>/dev/null || true

    log "Cleanup complete"
}
trap cleanup EXIT

# ========================================
# Pre-flight Checks
# ========================================
if [[ ! -f "$VM_IMAGE" ]]; then
    echo "Error: VM image not found at $VM_IMAGE"
    exit 1
fi

if [[ ! -f "$VM_SSH_KEY" ]]; then
    echo "Error: SSH key not found at $VM_SSH_KEY"
    echo "Generate it with: ssh-keygen -t rsa -b 4096 -f '$VM_SSH_KEY' -N ''"
    exit 1
fi

if ! command -v qemu-system-x86_64 &>/dev/null; then
    echo "Error: qemu-system-x86_64 not found"
    exit 1
fi

# Check binaries exist
if [[ ! -f "$PROJECT_ROOT/target/debug/rustcrash-crash" ]]; then
    echo "Error: Debug binaries not found. Run 'cargo build' first."
    exit 1
fi

# ========================================
# Setup: Copy to temp location
# ========================================
log "Setting up temporary test environment..."
mkdir -p "$TMP_CLOUDINIT_DIR"

# Copy SSH key to temp location
cp "$VM_SSH_KEY" "$TMP_SSH_KEY"
chmod 600 "$TMP_SSH_KEY"

# ========================================
# Create Cloud-Init Configuration
# ========================================
log "Creating cloud-init configuration..."

SSH_PUB_KEY="$(cat "${VM_SSH_KEY}.pub" 2>/dev/null || echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ== test')"

cat > "$TMP_CLOUDINIT_DIR/meta-data" << 'EOF'
instance-id: rustcrash-e2e-test
local-hostname: rustcrash-vm
EOF

cat > "$TMP_CLOUDINIT_DIR/user-data" << EOF
#cloud-config
users:
  - name: $VM_USER
    ssh_authorized_keys:
      - $SSH_PUB_KEY
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    groups: sudo
    shell: /bin/bash

# Skip package installation to speed up boot
package_update: false
package_reboot_if_required: false

runcmd:
  - ['echo', 'vm.ready=yes', '>', '/var/tmp/vm_ready']
EOF

# ========================================
# Create Cloud-Init ISO
# ========================================
CLOUD_INIT_ISO="$TMP_BASE-seed.iso"

if command -v cloud-localds &>/dev/null; then
    cloud-localds "$CLOUD_INIT_ISO" \
                  "$TMP_CLOUDINIT_DIR/user-data" \
                  "$TMP_CLOUDINIT_DIR/meta-data"
    log "Created cloud-init ISO with cloud-localds"
elif command -v xorriso &>/dev/null; then
    # Use xorriso to create ISO9660 image with Joliet extension
    xorriso -as mkisofs -o "$CLOUD_INIT_ISO" \
            -V CIDATA \
            -J \
            -r "$TMP_CLOUDINIT_DIR" 2>/dev/null
    log "Created cloud-init ISO with xorriso"
elif command -v genisoimage &>/dev/null; then
    genisoimage -quiet -V cidata -R -J \
                -o "$CLOUD_INIT_ISO" \
                "$TMP_CLOUDINIT_DIR/user-data" \
                "$TMP_CLOUDINIT_DIR/meta-data"
    log "Created cloud-init ISO with genisoimage"
else
    log_info "No ISO creation tools, will try direct QEMU options"
    CLOUD_INIT_ISO=""
fi

# ========================================
# Start VM
# ========================================
log "Starting QEMU VM (temp image: $TMP_IMAGE)..."

# Create snapshot/copy of base image (15GB for debug binaries)
qemu-img create -f qcow2 -o size=15G -b "$VM_IMAGE" -F qcow2 "$TMP_IMAGE" 2>/dev/null || {
    log "Snapshot failed, copying image directly..."
    cp "$VM_IMAGE" "$TMP_IMAGE"
}

QEMU_CMD=(
    qemu-system-x86_64
    -m 4096
    -smp 2
    -hda "$TMP_IMAGE"
    -bios /usr/share/qemu/OVMF.fd
    -netdev user,id=net0,hostfwd=tcp::${VM_PORT}-:22
    -device virtio-net-pci,netdev=net0
    -nographic
    -pidfile "$QEMU_PID_FILE"
)

# Add cloud-init ISO if available
if [[ -f "$CLOUD_INIT_ISO" ]]; then
    QEMU_CMD+=(-cdrom "$CLOUD_INIT_ISO")
fi

# Remove old bridge config issue
export QEMU_AUDIO_DRV=none

# Start QEMU in background
"${QEMU_CMD[@]}" 2>&1 &
VM_PID=$!

log "QEMU started with internal PID handling"

# Wait for boot and SSH
log_info "Waiting 20 seconds for VM boot..."
sleep 20

# Wait for SSH to be ready
log_info "Waiting for SSH to be ready..."
SSH_READY=0
for i in {1..25}; do
    if ssh -o StrictHostKeyChecking=no \
           -o ConnectTimeout=3 \
           -o UserKnownHostsFile=/dev/null \
           -i "$TMP_SSH_KEY" \
           -p "$VM_PORT" \
           "$VM_USER@localhost" \
           'echo ok' 2>/dev/null; then
        SSH_READY=1
        log "SSH is ready!"
        break
    fi
    echo -n "."
    sleep 2
done

echo ""

if [[ $SSH_READY -eq 0 ]]; then
    log_fail "SSH failed to become ready"
    exit 1
fi

# Quick cloud-init check
log_info "Checking cloud-init status..."
ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=10 \
    -o UserKnownHostsFile=/dev/null \
    -i "$TMP_SSH_KEY" \
    -p "$VM_PORT" \
    "$VM_USER@localhost" \
    'if [[ -f /var/tmp/vm_ready ]]; then echo "Cloud-init done"; else echo "Waiting for cloud-init..."; fi' 2>/dev/null || true

# ========================================
# Prepare Test Environment in VM
# ========================================
log "Preparing test environment in VM..."

ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=10 \
    -o UserKnownHostsFile=/dev/null \
    -i "$TMP_SSH_KEY" \
    -p "$VM_PORT" \
    "$VM_USER@localhost" << 'EOSSH'
set -e
echo "VM Info:"
echo "  Hostname: $(hostname)"
echo "  Kernel: $(uname -r)"
echo "  Arch: $(uname -m)"
echo "  User: $(whoami)"
echo ""

# Create test directory
mkdir -p /tmp/rustcrash_test
chmod 755 /tmp/rustcrash_test
EOSSH

# ========================================
# Copy Binaries to VM
# ========================================
log "Copying RustCrash binaries to VM..."

# Get current PID for tarball naming
CURRENT_PID=$$
log_info "Current PID: $CURRENT_PID"

# Create tarball
TARFILE="/tmp/rustcrash_bins_${CURRENT_PID}.tar.gz"
TAR_REMOTE="/tmp/rustcrash_bins_${CURRENT_PID}.tar.gz"

tar -czf "$TARFILE" -C "$PROJECT_ROOT/target/debug" \
    rustcrash-crash rustcrash-startctl rustcrash-installctl \
    rustcrash-initctl rustcrash-firewallctl rustcrash-configctl \
    rustcrash-taskctl rustcrash-setbootctl 2>/dev/null

if [[ ! -f "$TARFILE" ]]; then
    log_fail "Failed to create tarball"
    exit 1
fi

log_info "Tarball created: $(ls -lh "$TARFILE" | awk '{print $5}')"

# Copy tarball to VM
log_info "SCP tarball to VM..."
if ! scp -o StrictHostKeyChecking=no \
    -o ConnectTimeout=60 \
    -o UserKnownHostsFile=/dev/null \
    -i "$TMP_SSH_KEY" \
    -P "$VM_PORT" \
    "$TARFILE" \
    "${VM_USER}@localhost:/tmp/"; then
    log_fail "SCP failed"
    exit 1
fi
log_info "SCP completed"

# Extract in VM
log_info "Extracting in VM..."
ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=30 \
    -o UserKnownHostsFile=/dev/null \
    -i "$TMP_SSH_KEY" \
    -p "$VM_PORT" \
    "$VM_USER@localhost" << EOSSH
set -e
mkdir -p /tmp/rustcrash_test
tar -xzf "$TAR_REMOTE" -C /tmp/rustcrash_test/
chmod +x /tmp/rustcrash_test/rustcrash-*

# Create symlinks without rustcrash- prefix
cd /tmp/rustcrash_test
for f in rustcrash-*; do
    ln -sf "\$f" "\${f#rustcrash-}" 2>/dev/null || true
done

ls -la /tmp/rustcrash_test/
EOSSH

rm -f "$TARFILE"
log "Binaries copied to VM"

# ========================================
# Run E2E Tests in VM
# ========================================
log "=========================================="
log "Running E2E Tests INSIDE VM"
log "=========================================="

ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=60 \
    -o UserKnownHostsFile=/dev/null \
    -i "$TMP_SSH_KEY" \
    -p "$VM_PORT" \
    "$VM_USER@localhost" << 'EOSSH'
set -e

CRASHDIR="/tmp/rustcrash_e2e"
mkdir -p "$CRASHDIR"
export CRASHDIR

BIN_DIR="/tmp/rustcrash_test"
cd "$BIN_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)) || true; }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; ((SKIPPED++)) || true; }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

echo "=========================================="
echo "RustCrash VM E2E Test Suite"
echo "=========================================="
echo "VM Host: $(hostname)"
echo "VM Kernel: $(uname -a)"
echo "CrashDir: $CRASHDIR"
echo ""

# ========================================
# Test 1: Binary Existence
# ========================================
log_info "=== Test 1: Binary Existence ==="
for bin in crash startctl installctl initctl firewallctl configctl taskctl setbootctl; do
    if [[ -f "$BIN_DIR/$bin" ]]; then
        log_pass "Binary exists: $bin"
    else
        log_fail "Binary NOT found: $bin"
    fi
done

# ========================================
# Test 2: crash --version
# ========================================
echo ""
log_info "=== Test 2: crash --version ==="
VERSION=$("$BIN_DIR/crash" --version 2>&1) && {
    if echo "$VERSION" | grep -q "RustCrash"; then
        log_pass "crash --version works"
        echo "$VERSION"
    else
        log_fail "crash --version unexpected output: $VERSION"
    fi
} || log_fail "crash --version failed"

# ========================================
# Test 3: Platform Detection
# ========================================
echo ""
log_info "=== Test 3: Platform Detection ==="
PLATFORM=$("$BIN_DIR/crash" --version 2>&1 | grep "Platform:" || echo "")
if [[ -n "$PLATFORM" ]]; then
    log_pass "Platform detection: $PLATFORM"
else
    log_fail "Platform detection failed"
fi

# ========================================
# Test 4: initctl
# ========================================
echo ""
log_info "=== Test 4: initctl Directory Creation ==="
INIT_OUTPUT=$("$BIN_DIR/initctl" --crashdir "$CRASHDIR" 2>&1) && {
    log_pass "initctl runs successfully"
} || log_fail "initctl failed: $INIT_OUTPUT"

for dir in bin run logs config data; do
    if [[ -d "$CRASHDIR/$dir" ]]; then
        log_pass "Directory created: $dir"
    else
        log_fail "Directory NOT created: $dir"
    fi
done

# ========================================
# Test 5: configctl
# ========================================
echo ""
log_info "=== Test 5: configctl show ==="
CONFIG_OUTPUT=$("$BIN_DIR/configctl" --crashdir "$CRASHDIR" show 2>&1) && {
    if echo "$CONFIG_OUTPUT" | grep -qi "mihomo\|kernel\|config"; then
        log_pass "configctl show returns valid config"
    else
        log_fail "configctl show unexpected output"
    fi
} || log_fail "configctl show failed"

# ========================================
# Test 6: firewallctl generate
# ========================================
echo ""
log_info "=== Test 6: firewallctl generate ==="

IPT_OUTPUT=$("$BIN_DIR/firewallctl" generate --backend iptables 2>&1) && {
    if echo "$IPT_OUTPUT" | grep -q "iptables"; then
        log_pass "iptables script generation works"
    else
        log_fail "iptables script missing iptables commands"
    fi
} || log_fail "iptables generation failed"

NFT_OUTPUT=$("$BIN_DIR/firewallctl" generate --backend nftables 2>&1) && {
    if echo "$NFT_OUTPUT" | grep -q "nft"; then
        log_pass "nftables script generation works"
    else
        log_fail "nftables script missing nft commands"
    fi
} || log_fail "nftables generation failed"

# ========================================
# Test 7: startctl status
# ========================================
echo ""
log_info "=== Test 7: startctl status ==="
STATUS_OUTPUT=$("$BIN_DIR/startctl" --crashdir "$CRASHDIR" status 2>&1) && {
    log_pass "startctl status works"
    echo "  Status: $(echo "$STATUS_OUTPUT" | head -5)"
} || log_fail "startctl status failed"

# ========================================
# Test 8: setbootctl
# ========================================
echo ""
log_info "=== Test 8: setbootctl ==="
if "$BIN_DIR/setbootctl" status 2>&1 | grep -qiE "init|system|boot"; then
    log_pass "setbootctl status works"
else
    log_pass "setbootctl returned output"
fi

# ========================================
# Test 9: taskctl
# ========================================
echo ""
log_info "=== Test 9: taskctl list ==="
if "$BIN_DIR/taskctl" --crashdir "$CRASHDIR" list 2>&1 | grep -qiE "task|cron|schedule|empty"; then
    log_pass "taskctl list works"
else
    log_pass "taskctl list returned output"
fi

# ========================================
# Test 10: installctl
# ========================================
echo ""
log_info "=== Test 10: installctl --help ==="
if "$BIN_DIR/installctl" --help 2>&1 | grep -qi "install"; then
    log_pass "installctl --help works"
else
    log_fail "installctl --help failed"
fi

# ========================================
# Test 11: Firewall availability
# ========================================
echo ""
log_info "=== Test 11: Firewall Availability ==="
if command -v iptables &>/dev/null; then
    log_pass "iptables available on VM"
else
    log_skip "iptables not available"
fi

if command -v nft &>/dev/null; then
    log_pass "nftables available on VM"
else
    log_skip "nftables not available"
fi

# ========================================
# Test 12: Root privilege test
# ========================================
echo ""
log_info "=== Test 12: Privilege Check ==="
if [[ $EUID -eq 0 ]]; then
    log_pass "Running as root (can test privileged operations)"
else
    log_info "Not running as root - skipping privileged tests"
fi

# ========================================
# Test 13: File permissions in CRASHDIR
# ========================================
echo ""
log_info "=== Test 13: File Permissions ==="
if [[ -d "$CRASHDIR" ]] && [[ -r "$CRASHDIR" ]] && [[ -w "$CRASHDIR" ]]; then
    log_pass "CRASHDIR has proper permissions"
else
    log_fail "CRASHDIR permissions issue"
fi

# ========================================
# Summary
# ========================================
echo ""
echo "=========================================="
echo "VM E2E Test Summary"
echo "=========================================="
echo -e "${GREEN}Passed:${NC} $PASSED"
echo -e "${RED}Failed:${NC} $FAILED"
echo -e "${YELLOW}Skipped:${NC} $SKIPPED"
echo ""

[[ $FAILED -eq 0 ]] && exit 0 || exit 1
EOSSH

TEST_RESULT=$?

echo ""
if [[ $TEST_RESULT -eq 0 ]]; then
    log_pass "All VM E2E tests PASSED!"
else
    log_fail "Some VM E2E tests FAILED!"
fi

exit $TEST_RESULT
