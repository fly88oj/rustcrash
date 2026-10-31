#!/bin/bash
# Shared builders for the heavy-lane suites' host-side artifacts
# (tests/musl-verify and tests/docker-matrix both consume them).
#
# Extracted because the two suites carried near-identical copies that
# had already drifted (rm vs rm -f, container naming, tag stamping).
# Source after e2e-image-tag.sh (the content hash comes from there).
#
#   . scripts/e2e-musl.sh
#   ensure_musl_binary           # reuse unless stale by content tag
#   ensure_musl_binary force     # always rebuild (musl-verify semantics)
#   ensure_qemu                  # extract qemu-aarch64 once, flocked
#
# Artifacts (both flocked against the OTHER suite running in parallel):
#   /tmp/rustcrash-musl/crash       static x86_64-musl binary
#   /tmp/rustcrash-musl/crash.tag   content hash it was built from
#   /tmp/qemu-aarch64               qemu-user runner
#
# Knob: E2E_DOCKER_JOBS (default 16) caps cargo inside the build
# container so a parallel-heavy host stays within memory bounds.

MUSL_DIR="${MUSL_DIR:-/tmp/rustcrash-musl}"
QEMU_BIN="${QEMU_BIN:-/tmp/qemu-aarch64}"

# Build (or reuse) the static x86_64-musl crash binary. Reuse requires
# the crash.tag stamp to match the current tree's content hash — a
# stale artifact is rebuilt, never silently reused; "force" rebuilds
# unconditionally (the musl-verify suite verifies FRESH builds).
ensure_musl_binary() {
    local force="${1:-}"
    local root want_tag
    root="$(_e2e_root)"
    mkdir -p "$MUSL_DIR"
    (
        flock 9
        want_tag=$(_e2e_content_hash "$root")
        if [ "$force" != force ] && [ "${E2E_FORCE_BUILD:-0}" != "1" ] \
            && [ -x "$MUSL_DIR/crash" ] \
            && [ "$(cat "$MUSL_DIR/crash.tag" 2>/dev/null)" = "$want_tag" ]; then
            exit 0
        fi
        rm -f "$MUSL_DIR/crash"
        docker run --rm \
            -v "$root":/src:ro \
            -v "$MUSL_DIR":/src/target \
            -w /src \
            rust:1.98-slim \
            bash -c "
rustup target add x86_64-unknown-linux-musl 2>/dev/null
apt-get update -qq && apt-get install -y -qq musl-tools file >/dev/null 2>&1
cargo build --release --target x86_64-unknown-linux-musl --bin crash --features engine-full -j \"${E2E_DOCKER_JOBS:-16}\" 2>&1 | grep '^error' && exit 1
exit 0
" | tail -3
        [ -x "$MUSL_DIR/x86_64-unknown-linux-musl/release/crash" ] || {
            echo "FATAL: musl build failed"; exit 1; }
        cp "$MUSL_DIR/x86_64-unknown-linux-musl/release/crash" "$MUSL_DIR/crash"
        chmod +x "$MUSL_DIR/crash"
        echo "$want_tag" > "$MUSL_DIR/crash.tag"
    ) 9>/tmp/rustcrash-musl.lock || return 1
    echo "  musl binary: $(ls -la "$MUSL_DIR/crash" 2>/dev/null | awk '{print $5}') bytes (tag $(cat "$MUSL_DIR/crash.tag" 2>/dev/null))"
}

# Extract the qemu-user aarch64 runner from the cross-rs image once.
# Shared with the other heavy suite: extract under the shared flock,
# and clear a leftover extraction container from a crashed run.
ensure_qemu() {
    [ -x "$QEMU_BIN" ] && return 0
    (
        flock 9
        [ -x "$QEMU_BIN" ] && exit 0
        docker rm -f qemu-extract.$$ >/dev/null 2>&1 || true
        docker create --name qemu-extract.$$ ghcr.io/cross-rs/aarch64-unknown-linux-musl:0.2.5 >/dev/null 2>&1
        docker cp qemu-extract.$$:/usr/local/bin/qemu-aarch64 "$QEMU_BIN" >/dev/null 2>&1
        docker rm qemu-extract.$$ >/dev/null 2>&1
        chmod +x "$QEMU_BIN"
    ) 9>/tmp/rustcrash-qemu.lock
    [ -x "$QEMU_BIN" ] || { echo "FATAL: qemu-aarch64 unavailable"; return 1; }
    return 0
}
