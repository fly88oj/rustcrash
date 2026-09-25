#!/bin/bash
# Fetch the REAL mihomo release binary. NETWORK-DEPENDENT — this is the only
# step of the suite that touches the outside world (everything else is
# loopback inside one container).
#
# Sources are tried in order: the GitHub "latest" release (resolved via the
# releases/latest redirect, because mihomo asset names carry the version),
# then a pinned release. Direct first, then through a proxy: MIHOMO_PROXY=<url>
# pins one, otherwise the docker gateway's usual 7890/7891/8080 ports are
# probed (this suite runs inside a container, so a host-side proxy is
# reachable at the default gateway address).
#
# Caching / skipping:
#   * if $OUT_DIR/mihomo already exists and runs, the fetch is skipped
#     (MIHOMO_FORCE_FETCH=1 overrides);
#   * a host-side cache (~/.cache/rustcrash-e2e/mihomo-<ver>-linux-amd64.gz
#     by default, MIHOMO_CACHE_DIR overrides) is checked before any network
#     use and refilled after a successful download, so repeated runs of the
#     suite are fully offline.
#
# Usage: fetch-mihomo.sh [out_dir]
# Prints the downloaded `mihomo -v` first line on success; exit != 0 on
# total failure with the attempted URLs on stderr.
set -u

OUT_DIR="${1:-/tmp/mihomo}"
PINNED="${MIHOMO_PINNED_VERSION:-v1.19.31}"
TIMEOUT="${MIHOMO_FETCH_TIMEOUT:-120}"
GZ=/tmp/mihomo-dl.gz
CACHE_DIR="${MIHOMO_CACHE_DIR:-$HOME/.cache/rustcrash-e2e}"
mkdir -p "$OUT_DIR" "$CACHE_DIR"

# Skip-if-present: an already-fetched binary that still runs wins.
if [ -x "$OUT_DIR/mihomo" ] && [ "${MIHOMO_FORCE_FETCH:-0}" != "1" ]; then
    if "$OUT_DIR/mihomo" -v >/dev/null 2>&1; then
        echo "[mihomo] reusing $( "$OUT_DIR/mihomo" -v 2>/dev/null | head -1 )"
        "$OUT_DIR/mihomo" -v | head -1
        exit 0
    fi
fi

resolve_latest() { # the releases/latest redirect carries the tag
    curl -fsSI --max-time 20 -o /dev/null -w '%{redirect_url}' \
        https://github.com/MetaCubeX/mihomo/releases/latest 2>/dev/null \
        | sed -n 's#.*/tag/\(v[0-9][^/]*\)$#\1#p'
}

asset_url() { # <version> -> the linux-amd64 .gz asset URL
    echo "https://github.com/MetaCubeX/mihomo/releases/download/$1/mihomo-linux-amd64-$1.gz"
}

GW="$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')"
PROXIES=""
[ -n "${MIHOMO_PROXY:-}" ] && PROXIES="$PROXIES $MIHOMO_PROXY"
if [ -n "$GW" ]; then
    PROXIES="$PROXIES http://$GW:7890 http://$GW:7891 http://$GW:8080"
fi

install_from_gz() { # gunzip + exec-bit the downloaded asset
    gunzip -c "$GZ" > "$OUT_DIR/mihomo" && chmod +x "$OUT_DIR/mihomo"
    "$OUT_DIR/mihomo" -v >/dev/null 2>&1
}

try_cache() { # <version> <label>
    local ver=$1 cached="$CACHE_DIR/mihomo-$1-linux-amd64.gz"
    [ -f "$cached" ] || return 1
    cp -f "$cached" "$GZ"
    if install_from_gz; then
        echo "[mihomo] cache hit ($ver)"
        return 0
    fi
    rm -f "$cached"
    return 1
}

attempt() { # <url> <proxy-or-empty> <label>
    local url=$1 proxy=$2 label=$3
    rm -f "$GZ"
    # --speed-limit aborts a stalled transfer quickly; --connect-timeout
    # keeps a dropped-SYN route from eating the full --max-time budget.
    local args=(-fsSL --max-time "$TIMEOUT" --connect-timeout 15 \
        --speed-limit 2048 --speed-time 15 -o "$GZ" "$url")
    [ -n "$proxy" ] && args=(-x "$proxy" "${args[@]}")
    if ! curl "${args[@]}" 2>/tmp/mihomo-dl.err; then
        echo "  [mihomo] $label: download failed ($(tail -1 /tmp/mihomo-dl.err 2>/dev/null))"
        return 1
    fi
    if ! install_from_gz; then
        echo "  [mihomo] $label: not a usable mihomo asset"
        return 1
    fi
    # Refill the cache with what just worked (the version is the
    # second-to-last path component of the asset URL).
    local ver
    ver=$(basename "$(dirname "$url")")
    case "$ver" in
        v[0-9]*) cp -f "$GZ" "$CACHE_DIR/mihomo-$ver-linux-amd64.gz" 2>/dev/null || true ;;
    esac
    echo "  [mihomo] $label: ok"
    return 0
}

try_url() { # <url> <label>
    local url=$1 what=$2
    attempt "$url" "" "$what (direct)" && return 0
    local proxy
    for proxy in $PROXIES; do
        attempt "$url" "$proxy" "$what via $proxy" && return 0
    done
    return 1
}

echo "[mihomo] fetching the real mihomo release binary (network-dependent)"
ATTEMPTED=""

try_version() { # <version> -> 0 on success
    local ver=$1
    local url
    url=$(asset_url "$ver")
    ATTEMPTED="$ATTEMPTED $url"
    try_cache "$ver" && return 0
    try_url "$url" "release $ver" && return 0
    return 1
}

OK=0
if [ "${MIHOMO_FORCE_PINNED:-0}" != "1" ]; then
    LATEST=$(resolve_latest)
    if [ -n "$LATEST" ]; then
        try_version "$LATEST" && OK=1
    else
        echo "[mihomo] could not resolve the latest tag (offline?); trying the pinned $PINNED" >&2
    fi
fi
if [ "$OK" = 0 ]; then
    echo "[mihomo] using the pinned $PINNED" >&2
    try_version "$PINNED" && OK=1
fi

if [ "$OK" = 0 ] || [ ! -x "$OUT_DIR/mihomo" ]; then
    {
        echo "[mihomo] FAILED: no mihomo binary could be obtained; tried:$ATTEMPTED"
        echo "[mihomo] (cache dir $CACHE_DIR; tried direct and via:$PROXIES)"
        echo "[mihomo] this step is network-dependent; the rest of the suite cannot run without it"
        echo "[mihomo] offline escape hatch: put mihomo-linux-amd64-<ver>.gz in $CACHE_DIR"
    } >&2
    exit 1
fi

"$OUT_DIR/mihomo" -v | head -1
