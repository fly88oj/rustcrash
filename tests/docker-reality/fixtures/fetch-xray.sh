#!/bin/bash
# Fetch the REAL Xray binary. NETWORK-DEPENDENT — this is the only step of
# the suite that touches the outside world (everything else is loopback).
#
# Sources are tried in order; the first one that yields a zip containing an
# `xray` binary wins. Direct first, then through a proxy: XRAY_PROXY=<url>
# pins one, otherwise the docker gateway's usual 7890/7891/8080 ports are
# probed (this suite runs inside a container, so a host-side proxy is
# reachable at the default gateway address).
#
# Usage: fetch-xray.sh [out_dir]
# Prints the downloaded `xray version` first line on success; exit != 0 on
# total failure with the attempted URLs on stderr.
set -u

OUT_DIR="${1:-/tmp/xray}"
PINNED="${XRAY_PINNED_VERSION:-v25.6.8}"
TIMEOUT="${XRAY_FETCH_TIMEOUT:-90}"
ZIP=/tmp/xray-dl.zip
EXTRACT=/tmp/xray-extract
mkdir -p "$OUT_DIR"

LATEST_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
PINNED_URL="https://github.com/XTLS/Xray-core/releases/download/${PINNED}/Xray-linux-64.zip"

GW="$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')"
PROXIES=""
[ -n "${XRAY_PROXY:-}" ] && PROXIES="$PROXIES $XRAY_PROXY"
if [ -n "$GW" ]; then
    PROXIES="$PROXIES http://$GW:7890 http://$GW:7891 http://$GW:8080"
fi

attempt() { # <url> <proxy-or-empty> <label>
    local url=$1 proxy=$2 label=$3
    rm -rf "$ZIP" "$EXTRACT"
    # --speed-limit aborts a stalled transfer quickly (a blocked direct route
    # often accepts the connection then sends nothing for minutes);
    # --connect-timeout keeps a dropped-SYN route from eating the full
    # --max-time budget.
    local args=(-fsSL --max-time "$TIMEOUT" --connect-timeout 15 \
        --speed-limit 2048 --speed-time 15 -o "$ZIP" "$url")
    [ -n "$proxy" ] && args=(-x "$proxy" "${args[@]}")
    if ! curl "${args[@]}" 2>/tmp/xray-dl.err; then
        echo "  [xray] $label: download failed ($(tail -1 /tmp/xray-dl.err 2>/dev/null))"
        return 1
    fi
    if ! python3 - "$ZIP" "$EXTRACT" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    if "xray" not in z.namelist():
        sys.exit("zip has no xray entry")
    z.extract("xray", sys.argv[2])
PY
    then
        echo "  [xray] $label: not a usable Xray zip"
        return 1
    fi
    mv -f "$EXTRACT/xray" "$OUT_DIR/xray"
    chmod +x "$OUT_DIR/xray"
    echo "  [xray] $label: ok"
    return 0
}

try_url() { # <url> <what>
    local url=$1 what=$2
    attempt "$url" "" "$what (direct)" && return 0
    local proxy
    for proxy in $PROXIES; do
        attempt "$url" "$proxy" "$what via $proxy" && return 0
    done
    return 1
}

echo "[xray] fetching the real Xray binary (network-dependent)"
OK=0
if [ "${XRAY_FORCE_PINNED:-0}" != "1" ]; then
    try_url "$LATEST_URL" "latest release" && OK=1
fi
if [ "$OK" = 0 ]; then
    echo "[xray] ${XRAY_FORCE_PINNED:+pinned requested; }using the pinned $PINNED" >&2
    try_url "$PINNED_URL" "pinned $PINNED" && OK=1
fi

if [ "$OK" = 0 ] || [ ! -x "$OUT_DIR/xray" ]; then
    {
        echo "[xray] FAILED: no Xray binary could be downloaded from:"
        echo "[xray]   $LATEST_URL"
        echo "[xray]   $PINNED_URL"
        echo "[xray] (tried direct and via:$PROXIES)"
        echo "[xray] this step is network-dependent; the rest of the suite cannot run without it"
    } >&2
    exit 1
fi

"$OUT_DIR/xray" version | head -1