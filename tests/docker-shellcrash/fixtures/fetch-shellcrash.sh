#!/bin/bash
# Fetch the inputs of the ShellCrash migration suite. Everything the suite
# needs beside the engine image:
#
#   1. the REAL ShellCrash release payload (ShellCrash.tar.gz, the same
#      tarball `bash install.sh` would download, plus the `version` file
#      its check_version step reads). The tarball is COMMITTED under
#      fixtures/ (it is 174KB: the scripts tree, not the 226MB repo with
#      kernels), so the normal path never touches the network; a
#      host-side cache (~/.cache/rustcrash-e2e by default) and the GitHub
#      dev-branch tarball are fallbacks for a stripped checkout.
#   2. the real mihomo KERNEL binary for the phase-1 baseline: the host
#      cache (~/.cache/rustcrash-e2e/mihomo, shared with the interop
#      suite) is preferred, then the mihomo baked into the engine image
#      (/usr/local/bin/mihomo) — one of the two is always present, so
#      this step needs no network at all.
#
# Usage: fetch-shellcrash.sh [out_dir]   (default /tmp/sc)
set -u

OUT_DIR="${1:-/tmp/sc}"
CACHE_DIR="${SC_CACHE_DIR:-$HOME/.cache/rustcrash-e2e}"
FIXTURES="${SC_FIXTURES_DIR:-/sc-fixtures}"
PINNED_VERSION="${SC_PINNED_VERSION:-1.9.5beta3}"
TIMEOUT="${SC_FETCH_TIMEOUT:-120}"
mkdir -p "$OUT_DIR" "$CACHE_DIR"

# ---------------------------------------------------------------------------
# 1. ShellCrash payload
# ---------------------------------------------------------------------------
shellcrash_ok() {
    # a payload is usable when the tarball lists the install entry points
    [ -s "$OUT_DIR/ShellCrash.tar.gz" ] || return 1
    tar -tzf "$OUT_DIR/ShellCrash.tar.gz" 2>/dev/null | grep -q '^init.sh$' \
        && tar -tzf "$OUT_DIR/ShellCrash.tar.gz" 2>/dev/null | grep -q '^start.sh$'
}

if shellcrash_ok && [ "${SC_FORCE_FETCH:-0}" != "1" ]; then
    echo "[shellcrash] reusing $OUT_DIR/ShellCrash.tar.gz ($(wc -c <"$OUT_DIR/ShellCrash.tar.gz") bytes)"
else
    OK=0
    # a. the committed fixture (the normal, offline path)
    if [ -s "$FIXTURES/ShellCrash.tar.gz" ] \
        && cp -f "$FIXTURES/ShellCrash.tar.gz" "$OUT_DIR/ShellCrash.tar.gz" 2>/dev/null \
        && shellcrash_ok; then
        echo "[shellcrash] using the committed fixture tarball"
        OK=1
    fi
    # b. the host cache (interop-style refill)
    if [ "$OK" = 0 ] && [ -s "$CACHE_DIR/ShellCrash-$PINNED_VERSION.tar.gz" ] \
        && cp -f "$CACHE_DIR/ShellCrash-$PINNED_VERSION.tar.gz" "$OUT_DIR/ShellCrash.tar.gz" 2>/dev/null \
        && shellcrash_ok; then
        echo "[shellcrash] host cache hit ($PINNED_VERSION)"
        OK=1
    fi
    # c. NETWORK FALLBACK: the tarball committed in the upstream repo's
    #    dev branch (juewuy/ShellCrash). Direct, then the docker-gateway
    #    proxy ports, like fixtures/fetch-mihomo.sh of the interop suite.
    if [ "$OK" = 0 ]; then
        echo "[shellcrash] no local payload; fetching the dev-branch tarball (network-dependent)" >&2
        URL="https://raw.githubusercontent.com/juewuy/ShellCrash/dev/ShellCrash.tar.gz"
        GW="$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')"
        for proxy in "" ${SC_PROXY:-} \
            ${GW:+http://$GW:7890 http://$GW:7891 http://$GW:8080}; do
            if curl -fsSL --max-time "$TIMEOUT" --connect-timeout 15 \
                ${proxy:+-x "$proxy"} -o "$OUT_DIR/ShellCrash.tar.gz" "$URL" 2>/dev/null \
                && shellcrash_ok; then
                echo "[shellcrash] downloaded via ${proxy:-direct}"
                OK=1
                cp -f "$OUT_DIR/ShellCrash.tar.gz" \
                    "$CACHE_DIR/ShellCrash-$PINNED_VERSION.tar.gz" 2>/dev/null || true
                break
            fi
        done
    fi
    if [ "$OK" = 0 ] || ! shellcrash_ok; then
        echo "[shellcrash] FAILED: no usable ShellCrash.tar.gz (fixture, cache and network all exhausted)" >&2
        exit 1
    fi
fi
[ -s "$OUT_DIR/version" ] || cp -f "$FIXTURES/version" "$OUT_DIR/version" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 2. The real mihomo kernel (phase-1 baseline)
# ---------------------------------------------------------------------------
mihomo_ok() { [ -x "$OUT_DIR/mihomo-kernel" ] && "$OUT_DIR/mihomo-kernel" -v >/dev/null 2>&1; }
MIHOMO_PINNED_VERSION="${MIHOMO_PINNED_VERSION:-v1.19.31}"

if mihomo_ok && [ "${MIHOMO_FORCE_FETCH:-0}" != "1" ]; then
    echo "[mihomo-kernel] reusing $("$OUT_DIR/mihomo-kernel" -v 2>/dev/null | head -1)"
else
    OK=0
    # a. the host cache shared with the interop suite (plain binary there;
    #    gunzip the .gz variant if that is what is cached)
    for cached in "$CACHE_DIR/mihomo" "$CACHE_DIR/mihomo-$MIHOMO_PINNED_VERSION-linux-amd64.gz"; do
        if [ -e "$cached" ]; then
            case "$cached" in
                *.gz) gunzip -c "$cached" >"$OUT_DIR/mihomo-kernel" ;;
                *) cp -f "$cached" "$OUT_DIR/mihomo-kernel" ;;
            esac
            chmod +x "$OUT_DIR/mihomo-kernel" 2>/dev/null || true
            mihomo_ok && {
                echo "[mihomo-kernel] host cache hit: $cached"
                OK=1
                break
            }
        fi
    done
    # b. the mihomo release baked into the engine image itself
    if [ "$OK" = 0 ] && [ -x /usr/local/bin/mihomo ] \
        && cp -f /usr/local/bin/mihomo "$OUT_DIR/mihomo-kernel" && mihomo_ok; then
        echo "[mihomo-kernel] using the engine image's /usr/local/bin/mihomo ($("$OUT_DIR/mihomo-kernel" -v 2>/dev/null | head -1))"
        OK=1
    fi
    if [ "$OK" = 0 ]; then
        echo "[mihomo-kernel] FAILED: no mihomo binary (host cache empty and image has none)" >&2
        exit 1
    fi
fi

echo "[fetch] ready: $(tar -tzf "$OUT_DIR/ShellCrash.tar.gz" | wc -l) payload files," \
    "kernel $("$OUT_DIR/mihomo-kernel" -v 2>/dev/null | head -1 | awk '{print $1, $2, $3}')"
