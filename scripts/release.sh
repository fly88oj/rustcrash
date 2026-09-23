#!/bin/bash
# Release builder: cross-compile every supported target, package each as
# rustcrash-<version>-<target>.tar.gz with a README + LICENSE, and emit a
# SHA256SUMS manifest. One command → a complete release directory.
#
# Usage: ./release.sh [outdir]      (default: dist/release-<version>)
#
# Requires: Docker, the cross-compile.sh prerequisites, and — recommended,
# not mandatory — qemu binfmt for the ARM/x86 smoke runs (they are skipped
# non-fatally when unavailable; MIPS smoke uses in-container qemu-user-static
# instead). The smoke runs execute `crash --version` under emulation where
# available; a binary that crashes under available emulation fails the release.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$PROJECT_ROOT/Cargo.toml" | head -1)"
OUT_DIR="${1:-$PROJECT_ROOT/dist/release-$VERSION}"

mkdir -p "$OUT_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# The device-facing target list (the same six targets as
# cross-compile.sh's whitelist).
TARGETS=(
    aarch64-unknown-linux-musl
    armv7-unknown-linux-musleabihf
    arm-unknown-linux-musleabihf
    x86_64-unknown-linux-musl
    mipsel-unknown-linux-musl
    mips-unknown-linux-musl
)

# Docker --platform per target (for the emulated smoke test).
platform_for() {
    case "$1" in
        aarch64-*)       echo linux/arm64 ;;
        armv7-*)         echo linux/arm/v7 ;;
        arm-*)           echo linux/arm/v6 ;;
        x86_64-*)        echo linux/amd64 ;;
        mipsel-*|mips-*) echo "" ;;   # no docker platform images; qemu below
        *)               return 1 ;;
    esac
}

expected_file_arch() {
    case "$1" in
        aarch64-*)       echo "ARM aarch64" ;;
        armv7-*|arm-*)   echo "ARM" ;;
        x86_64-*)        echo "x86-64" ;;
        mipsel-*|mips-*) echo "MIPS" ;;
        *)               return 1 ;;
    esac
}

smoke_ok=0
pkgs=()

smoke_test() {
    local target=$1 bin=$2
    local plat; plat="$(platform_for "$target")"
    if [[ -n "$plat" ]]; then
        # Probe emulation separately: a missing binfmt registration is a
        # skip (not a build defect), but a crashing binary is fatal.
        if ! docker run --rm --platform "$plat" alpine:3.21 true >/dev/null 2>&1; then
            log "  smoke: emulation unavailable for $plat (skipped, non-fatal)"
            return 0
        fi
        if docker run --rm --platform "$plat" \
            -v "$(dirname "$bin"):/smoke:ro" \
            alpine:3.21 /smoke/$(basename "$bin") --version >/dev/null 2>&1; then
            log "  smoke: $plat OK"
            ((smoke_ok++)) || true
            return 0
        fi
        log "[FAIL] smoke: $target binary crashed under $plat emulation"
        exit 1
    fi
    # MIPS: no docker platform images exist. The binary is mounted at a
    # fixed path and executed under qemu-user-static from debian; the
    # shell command strings below are fully literal per target — nothing
    # is interpolated into them. If the run fails, a probe run of the
    # interpreter alone distinguishes a broken binary (fatal) from an
    # unavailable environment (skip).
    if [[ "$target" == mipsel-unknown-linux-musl ]]; then
        if docker run --rm -v "$bin:/smoke/crash:ro" debian:bookworm-slim \
            sh -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -qqy qemu-user-static >/dev/null 2>&1 && qemu-mipsel-static /smoke/crash --version" >/dev/null 2>&1; then
            log "  smoke: qemu-mipsel-static OK"
            ((smoke_ok++)) || true
            return 0
        fi
        if docker run --rm debian:bookworm-slim \
            sh -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -qqy qemu-user-static >/dev/null 2>&1 && qemu-mipsel-static --version" >/dev/null 2>&1; then
            log "[FAIL] smoke: $target binary crashed under qemu-mipsel-static"
            exit 1
        fi
    else
        if docker run --rm -v "$bin:/smoke/crash:ro" debian:bookworm-slim \
            sh -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -qqy qemu-user-static >/dev/null 2>&1 && qemu-mips-static /smoke/crash --version" >/dev/null 2>&1; then
            log "  smoke: qemu-mips-static OK"
            ((smoke_ok++)) || true
            return 0
        fi
        if docker run --rm debian:bookworm-slim \
            sh -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -qqy qemu-user-static >/dev/null 2>&1 && qemu-mips-static --version" >/dev/null 2>&1; then
            log "[FAIL] smoke: $target binary crashed under qemu-mips-static"
            exit 1
        fi
    fi
    log "  smoke: qemu-user-static unavailable for $target (skipped, non-fatal)"
}

for target in "${TARGETS[@]}"; do
    log "=== $target ==="
    bash "$SCRIPT_DIR/cross-compile.sh" "$target"
    bin="$PROJECT_ROOT/target/cross/$target/crash"
    [[ -f "$bin" ]] || { log "[FAIL] missing $bin"; exit 1; }

    # Header sanity: correct arch + statically linked (routers have no libc).
    local_arch="$(expected_file_arch "$target")"
    file_output="$(file "$bin")"
    if [[ "$file_output" != *"$local_arch"* ]]; then
        log "[FAIL] wrong architecture: $file_output"
        exit 1
    fi
    if [[ "$file_output" != *"statically linked"* && "$file_output" != *"static-pie linked"* ]]; then
        log "[FAIL] not static: $file_output"
        exit 1
    fi
    log "  ELF: OK ($file_output)"
    smoke_test "$target" "$bin"

    # Package: tar.gz with the binary + short README + LICENSE.
    pkg="rustcrash-$VERSION-$target.tar.gz"
    pkgs+=("$pkg")
    staging="$(mktemp -d)"
    trap 'rm -rf "$staging"' EXIT
    mkdir -p "$staging/rustcrash-$VERSION-$target"
    cp "$bin" "$staging/rustcrash-$VERSION-$target/crash"
    cp "$PROJECT_ROOT/LICENSE" "$staging/rustcrash-$VERSION-$target/" 2>/dev/null || true
    cp "$PROJECT_ROOT/LICENSE-MIT" "$staging/rustcrash-$VERSION-$target/" 2>/dev/null || true
    cp "$PROJECT_ROOT/LICENSE-APACHE" "$staging/rustcrash-$VERSION-$target/" 2>/dev/null || true
    cat > "$staging/rustcrash-$VERSION-$target/README.txt" <<EOF
RustCrash $VERSION ($target)

A single-binary mihomo/sing-box manager (ShellCrash-compatible).

Install:
  tar -xzf $pkg
  sudo install -m755 rustcrash-$VERSION-$target/crash /usr/local/bin/crash
  sudo crash init --init
  sudo crash install
  crash config import <subscription-url>
  sudo crash start serve

Docs: https://github.com/fly88oj/rustcrash#readme
EOF
    tar -czf "$OUT_DIR/$pkg" -C "$staging" "rustcrash-$VERSION-$target"
    rm -rf "$staging"
    log "  packaged: $pkg ($(du -h "$OUT_DIR/$pkg" | cut -f1))"
done

# Checksums cover exactly the archives this run produced — a reused
# OUT_DIR can hold stale tarballs that a glob would wrongly certify.
(cd "$OUT_DIR" && sha256sum "${pkgs[@]}" > SHA256SUMS)

log ""
log "=== Release $VERSION → $OUT_DIR ==="
ls -lh "$OUT_DIR/"
log "smoke runs passed: $smoke_ok (MIPS via qemu-user-static; others via docker binfmt)"
