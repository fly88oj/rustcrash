#!/bin/bash
# Cross-compile the single RustCrash `crash` binary for multiple
# architectures: tier-2 targets in Docker (cross-rs/cross), the tier-3
# MIPS targets on the host via cargo-zigbuild (no cross-rs image exists).
# Usage: ./cross-compile.sh [target...]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/target/cross"

# Allowed targets (whitelist: user input never reaches the docker command
# unvalidated). Coverage for mainstream devices:
#   aarch64  — 64-bit routers (AX series), Raspberry Pi 3/4/5 (64-bit OS), ARM servers
#   armv7    — 32-bit routers, Raspberry Pi 2/3/4 (32-bit OS)
#   arm(v6)  — Raspberry Pi Zero/1, legacy ARMv5/6 routers (ARMv6+VFP2)
#   x86_64   — x86 boxes, containers
#   mipsel   — LE WiFi routers (MTK/Ath)
#   mips     — BE routers (some Broadcom/Atheros) — tier-3, nightly build-std
VALID_TARGETS=(
    "aarch64-unknown-linux-musl"      # ARM64: 64-bit routers, Pi 3/4/5
    "armv7-unknown-linux-musleabihf"  # ARMv7 HF: 32-bit routers, Pi 2/3/4 (32-bit OS)
    "arm-unknown-linux-musleabihf"    # ARMv6 HF: Pi Zero/1, legacy routers
    "x86_64-unknown-linux-musl"       # x86_64 static
    "mipsel-unknown-linux-musl"       # MIPS LE routers (tier-3)
    "mips-unknown-linux-musl"         # MIPS BE routers (tier-3)
)

# Tier-3 targets have no prebuilt std (nightly + -Zbuild-std) and no
# cross-rs Docker image; they build on the HOST via cargo-zigbuild,
# which uses zig cc as the linker and zig's bundled musl.
TIER3_TARGETS=(
    "mipsel-unknown-linux-musl"
    "mips-unknown-linux-musl"
)

# cargo-zigbuild 0.23.x needs zig 0.14.x: 0.13 rejects the musleabi
# target spelling, 0.16+ fails linking with undefined c.malloc symbols.
ZIG_REQUIRED_MAJOR=0
ZIG_REQUIRED_MINOR=14

# Map a shorthand (e.g. "aarch64") to a full target triple, or fail.
resolve_target() {
    local input=$1
    for t in "${VALID_TARGETS[@]}"; do
        if [[ "$t" == "$input" || "$t" == "$input"-* ]]; then
            printf '%s' "$t"
            return 0
        fi
    done
    return 1
}

is_valid_target() {
    local t=$1
    for valid in "${VALID_TARGETS[@]}"; do
        [[ "$t" == "$valid" ]] && return 0
    done
    return 1
}

is_tier3() {
    local t=$1
    for t3 in "${TIER3_TARGETS[@]}"; do
        [[ "$t" == "$t3" ]] && return 0
    done
    return 1
}

# Fail with the exact fix when a tier-3 prerequisite is missing.
check_zigbuild() {
    if ! command -v cargo-zigbuild >/dev/null 2>&1; then
        log "[FAIL] tier-3 targets need cargo-zigbuild: cargo install cargo-zigbuild --locked"
        return 1
    fi
    local zig_ver
    zig_ver="$(python3 -m ziglang version 2>/dev/null)" || {
        log "[FAIL] ziglang python package missing: python3 -m pip install --user ziglang==0.14.1"
        return 1
    }
    case "$zig_ver" in
        "$ZIG_REQUIRED_MAJOR.$ZIG_REQUIRED_MINOR."*) return 0 ;;
        *)
            log "[FAIL] zig $zig_ver incompatible with cargo-zigbuild (needs 0.14.x):"
            log "       python3 -m pip install --user ziglang==0.14.1"
            return 1
            ;;
    esac
}

# cross-rs/cross:edge tracks current Rust (lockfile v4 support). Pin a
# digest for reproducible/supply-chain-locked builds via CROSS_IMAGE.
DOCKER_IMAGE="${CROSS_IMAGE:-ghcr.io/cross-rs/cross:edge}"

show_help() {
    echo "Cross-compile the RustCrash crash binary for multiple architectures"
    echo ""
    echo "Usage: $0 [target...]"
    echo ""
    echo "Targets:"
    for t in "${VALID_TARGETS[@]}"; do
        echo "  - $t"
    done
    echo ""
    echo "Examples:"
    echo "  $0                    # Build all targets"
    echo "  $0 aarch64            # Build only ARM64"
}

log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

build_target() {
    local target=$1
    if ! is_valid_target "$target"; then
        log "[FAIL] refusing unknown target: $target"
        return 1
    fi
    local output_dir="$BUILD_DIR/$target"
    local docker_out="$PROJECT_ROOT/target/cross-docker"
    local cargo_bin build_rc

    log "Building crash for $target..."

    mkdir -p "$output_dir"
    # A previous run's published binary must not survive a failed
    # rebuild in the output directory.
    rm -f "$output_dir/crash"

    # `cross build` installs the target std and picks the cross linker;
    # the docker socket lets cross drive sibling toolchain containers.
    # Tier-3 targets build on the host via cargo-zigbuild (zig supplies
    # the linker and musl); -Zbuild-std compiles std (nightly+rust-src).
    #
    # The docker path gets its own CARGO_TARGET_DIR: host-built
    # (newer-glibc) build scripts in a shared target/release would fail
    # to execute inside the older-glibc cross container.
    if is_tier3 "$target"; then
        check_zigbuild || return 1
        # Remove any previous artifact first: a stale binary must never
        # satisfy the post-build existence check after a failed rebuild.
        rm -f "$PROJECT_ROOT/target/$target/release/crash"
        cargo +nightly zigbuild -Z build-std --release \
            --target "$target" --bin crash 2>&1 | tail -20
        [[ ${PIPESTATUS[0]} -eq 0 ]] || {
            log "[FAIL] zigbuild exited nonzero for $target"
            return 1
        }
        cargo_bin="$PROJECT_ROOT/target/$target/release/crash"
    else
        docker run --rm \
            -e CARGO_TARGET_DIR=/build/target/cross-docker \
            -v "$PROJECT_ROOT:/build" \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -w /build \
            "$DOCKER_IMAGE" \
            cross build --release --target "$target" --bin crash 2>&1 | tail -20
        build_rc=${PIPESTATUS[0]}
        # Docker builds as root; return the build tree to the invoking
        # user or later host builds (cargo/zigbuild) hit permission
        # errors on the root-owned fingerprint files.
        if ! docker run --rm -v "$docker_out:/t" \
                "$DOCKER_IMAGE" \
                chown -R "$(id -u):$(id -g)" /t >/dev/null 2>&1; then
            log "[WARN] could not chown $docker_out back to $(id -u):$(id -g) — later host builds may hit permission errors"
        fi
        [[ $build_rc -eq 0 ]] || return 1
        cargo_bin="$docker_out/$target/release/crash"
    fi

    if [[ -f "$cargo_bin" ]]; then
        cp "$cargo_bin" "$output_dir/"

        log "[OK] $target built successfully"
        ls -lh "$output_dir/"
    else
        log "[FAIL] $target build failed"
        return 1
    fi
}

# Main
if [[ $# -eq 0 ]]; then
    # Build all targets
    for target in "${VALID_TARGETS[@]}"; do
        build_target "$target"
    done
elif [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    show_help
else
    # Build specified targets (shorthands resolved via whitelist)
    for input in "$@"; do
        target=$(resolve_target "$input") || {
            log "[FAIL] unknown target: $input (see --help)"
            exit 1
        }
        build_target "$target"
    done
fi

log "Cross-compilation complete!"
log "Output directory: $BUILD_DIR"
