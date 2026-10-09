#!/bin/bash
# Resource guard for heavy dev/test operations (cargo, docker, e2e).
#
# Born of the 2026-10-09 disk-full incident: repeated cargo runs across
# the feature matrix (mihomo / singbox / both) let incremental caches
# pile up to 80 GB in target/debug, and E2E_FORCE_BUILD docker runs
# grew the build cache to ~490 GB — together they pushed the root
# filesystem to 96% and starved every process on the machine.
#
# Usage (source, then call):
#   . scripts/resource-guard.sh
#   guard_run                 # pre-flight (refuses on violation) + start
#                             # the watchdog — the one-liner runners call
#   guard_check               # pre-flight only (report + enforce)
#   guard_watch_start         # background monitor during long runs
#   guard_watch_stop          # stop the monitor
#
# Knobs (env):
#   MIN_FREE_GB   (default 60)  below this the guard REFUSES to start
#                               (after trying its safe prunes)
#   WARN_FREE_GB  (default 120) below this the guard warns and prunes
#   MAX_TARGET_GB (default 50)  above this target/ is trimmed (incremental
#                               first — regenerable by definition)
#   GUARD_KILL=1                watch mode may kill cargo/rustc/docker
#                               build processes when MIN_FREE_GB is hit
#                               despite pruning (off by default: kills
#                               are a user decision)
#
# What the guard prunes autonomously (regenerable caches ONLY — never
# source, never tagged docker images of other projects, never volumes):
#   - target/*/incremental (and target/debug/incremental)
#   - docker BUILDER cache (docker builder prune -f — cache only)
#   - dangling docker images (docker image prune -f)

GUARD_MIN_FREE_GB="${MIN_FREE_GB:-60}"
GUARD_WARN_FREE_GB="${WARN_FREE_GB:-120}"
GUARD_MAX_TARGET_GB="${MAX_TARGET_GB:-50}"

guard_log() { echo "[resource-guard] $*" >&2; }
guard_warn() { echo "[resource-guard WARNING] $*" >&2; }
guard_err() { echo "[resource-guard REFUSED] $*" >&2; }

# Size of a directory in whole GB (du -sm; 0 when absent).
_guard_dir_gb() {
    [ -d "$1" ] || { echo 0; return; }
    du -sm "$1" 2>/dev/null | awk '{ printf "%.0f", $1 / 1024 }'
}

# Free space on the filesystem holding the repo (GB).
_guard_free_gb() {
    df -BG --output=avail "$(pwd)" 2>/dev/null | tail -1 | tr -dc '0-9'
}

# MemAvailable in GB.
_guard_mem_avail_gb() {
    awk '/MemAvailable/ {printf "%.0f", $2 / 1048576}' /proc/meminfo 2>/dev/null || echo 0
}

_guard_nproc() { nproc 2>/dev/null || echo 4; }

# Suggest/export a parallelism cap that keeps peak build memory sane:
# ~2 GB per rustc/linker slot is the observed ceiling for this tree.
# GUARD_MAX_JOBS (default 24) matches .cargo/config.toml's jobs cap; the
# export exists to TIGHTEN it under memory pressure, never to raise it.
_guard_cap_jobs() {
    local mem_gb ceiling
    mem_gb=$(_guard_mem_avail_gb)
    ceiling="${GUARD_MAX_JOBS:-24}"
    local by_mem=$((mem_gb / 2))
    local cap
    cap=$(_guard_nproc)
    [ "$cap" -gt "$ceiling" ] && cap=$ceiling
    [ "$by_mem" -gt 0 ] && [ "$by_mem" -lt "$cap" ] && cap=$by_mem
    [ "$cap" -lt 2 ] && cap=2
    echo "$cap"
}

# Safe prunes (regenerable caches only). Returns the GB reclaimed
# (approximately, from df deltas).
_guard_prune_safe() {
    local before after
    before=$(_guard_free_gb)
    local t
    for t in target/debug/incremental target/release/incremental \
        target/x86_64-unknown-linux-musl/incremental \
        target/aarch64-unknown-linux-musl/incremental; do
        if [ -d "$t" ]; then
            guard_log "removing $t ($(_guard_dir_gb "$t") GB)"
            rm -rf "$t"
        fi
    done
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        guard_log "pruning docker builder cache (cache only)"
        docker builder prune -f >/dev/null 2>&1
        guard_log "pruning dangling docker images"
        docker image prune -f >/dev/null 2>&1
    fi
    after=$(_guard_free_gb)
    awk -v a="$after" -v b="$before" 'BEGIN { printf "%.0f", a - b }'
}

# Preflight check. Returns non-zero (after pruning attempts) when the
# machine cannot safely host another heavy run.
guard_check() {
    local free_gb target_gb mem_gb jobs_cap

    free_gb=$(_guard_free_gb)
    target_gb=$(_guard_dir_gb target)
    mem_gb=$(_guard_mem_avail_gb)
    jobs_cap=$(_guard_cap_jobs)

    guard_log "disk free ${free_gb}G (warn<${GUARD_WARN_FREE_GB}G refuse<${GUARD_MIN_FREE_GB}G); target/ ${target_gb}G (cap ${GUARD_MAX_TARGET_GB}G); MemAvailable ${mem_gb}G; suggested jobs ${jobs_cap}"

    # Bound cargo parallelism for this shell unless the caller pinned it.
    if [ -z "${CARGO_BUILD_JOBS:-}" ] && command -v cargo >/dev/null 2>&1; then
        export CARGO_BUILD_JOBS="$jobs_cap"
        guard_log "CARGO_BUILD_JOBS=$jobs_cap exported"
    fi

    # GPU: report when present (this tree never schedules GPU work, but
    # the guard reports anything that could surprise a full machine).
    if command -v nvidia-smi >/dev/null 2>&1; then
        nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu \
            --format=csv,noheader 2>/dev/null | while read -r line; do
            guard_log "gpu: $line"
        done
    fi

    # Over-cap target dir: trim the regenerable part.
    if [ "$target_gb" -gt "$GUARD_MAX_TARGET_GB" ]; then
        guard_warn "target/ is ${target_gb}G (cap ${GUARD_MAX_TARGET_GB}G) — trimming regenerable caches"
        _guard_prune_safe
        free_gb=$(_guard_free_gb)
        target_gb=$(_guard_dir_gb target)
        if [ "$target_gb" -gt "$GUARD_MAX_TARGET_GB" ]; then
            guard_warn "target/ still ${target_gb}G after pruning — full 'cargo clean' recommended (or set GUARD_ALLOW_BIG=1 to proceed)"
            [ "${GUARD_ALLOW_BIG:-0}" != "1" ] && return 2
        fi
    fi

    # Disk headroom gate.
    if [ "$free_gb" -lt "$GUARD_WARN_FREE_GB" ]; then
        guard_warn "only ${free_gb}G free — pruning regenerable caches"
        _guard_prune_safe
        free_gb=$(_guard_free_gb)
    fi
    if [ "$free_gb" -lt "$GUARD_MIN_FREE_GB" ]; then
        guard_err "${free_gb}G free < ${GUARD_MIN_FREE_GB}G floor — refusing to start a heavy run (prunes already attempted; free space or raise MIN_FREE_GB deliberately)"
        return 1
    fi

    # Memory gate: warn below 8G available (the linker OOMs first).
    if [ "$mem_gb" -lt 8 ]; then
        guard_warn "MemAvailable ${mem_gb}G — heavy links may OOM; jobs already capped to ${jobs_cap}"
    fi

    guard_log "OK — proceeding"
    return 0
}

# The runner entry point: check, then arm the watchdog.
guard_run() {
    guard_check || exit 1
    guard_watch_start
}

# Whether a pid is alive AND not a zombie (kill -0 alone succeeds on
# unreaped zombies, which would keep a watchdog running past its caller).
_guard_parent_alive() {
    [ -n "$1" ] || return 1
    local state
    state=$(ps -o stat= -p "$1" 2>/dev/null) || return 1
    case "$state" in
        Z* | z*) return 1 ;;
    esac
    return 0
}

# Background watchdog for long runs (e2e suites, matrix builds). Ties
# itself to the caller's lifetime (parent-liveness poll — no trap wiring
# needed) and checks every 30 s; below WARN it prunes caches; below MIN
# it prunes again and (only with GUARD_KILL=1) kills cargo/rustc/
# docker-build processes.
GUARD_WATCH_PID=""
guard_watch_start() {
    # Own the cleanup contract entirely: the watchdog polls its PARENT
    # (this shell) and self-terminates when the caller exits — no trap
    # wiring needed at any call site, and a later `trap cleanup EXIT` in
    # the caller cannot accidentally orphan it. guard_watch_stop remains
    # for immediate teardown (and runs no-op when already gone).
    (
        parent=$PPID
        while _guard_parent_alive "$parent"; do
            sleep 30
            free_gb=$(_guard_free_gb)
            if [ "$free_gb" -lt "$GUARD_WARN_FREE_GB" ]; then
                guard_warn "watch: ${free_gb}G free — pruning regenerable caches"
                _guard_prune_safe
                free_gb=$(_guard_free_gb)
                if [ "$free_gb" -lt "$GUARD_MIN_FREE_GB" ]; then
                    if [ "${GUARD_KILL:-0}" = "1" ]; then
                        guard_warn "watch: still ${free_gb}G free — GUARD_KILL=1, stopping build processes"
                        pkill -TERM -x rustc 2>/dev/null
                        pkill -TERM -x cargo 2>/dev/null
                        pkill -TERM -f "docker build" 2>/dev/null
                    else
                        guard_warn "watch: still ${free_gb}G free — set GUARD_KILL=1 to let the guard stop build processes"
                    fi
                fi
            fi
        done
    ) &
    GUARD_WATCH_PID=$!
    guard_log "watchdog started (pid $GUARD_WATCH_PID, poll 30s, warn<${GUARD_WARN_FREE_GB}G)"
}

guard_watch_stop() {
    if [ -n "$GUARD_WATCH_PID" ]; then
        kill "$GUARD_WATCH_PID" 2>/dev/null
        wait "$GUARD_WATCH_PID" 2>/dev/null
        GUARD_WATCH_PID=""
        guard_log "watchdog stopped"
    fi
}
