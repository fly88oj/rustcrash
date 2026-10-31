#!/bin/bash
# Parallel test orchestrator: runs EVERY suite in the repo with the
# host's resources fully — but safely — utilized.
#
# Three lanes run concurrently (see docs/CONTRIBUTING.md "Test suites"):
#
#   unit    cargo/nextest across the feature matrix:
#             workspace (default features) ->
#             rustcrash-engine (mihomo,singbox) ->
#             rustcrash-core (engine-mihomo,engine-singbox) ->
#             doctests
#           nextest when installed (per-test process isolation kills the
#           env-var/global-state races that flake threaded runners).
#
#   docker  the hermetic container suites (no host ports, one compose
#           project each) through a bounded parallel pool, default 4
#           wide: docker-engine, docker-interop, docker-shellcrash,
#           docker, docker-reality, docker-cluster.
#
#   heavy   musl-verify -> docker-matrix, SEQUENTIALLY: both drive the
#           same host-side artifacts (/tmp/rustcrash-musl, the
#           aarch64 cross target dir, /tmp/qemu-aarch64), so sharing
#           them beats racing them — musl-verify produces the fresh
#           musl binary, matrix then reuses it plus the warm cross
#           cache. Ordering musl-verify first is deliberate.
#
# The lanes are independent by construction: the container suites are
# hermetic (own netns / own compose project), the engine image is
# content-addressed (scripts/e2e-image-tag.sh), and shared /tmp
# artifacts are flock-guarded. The resource guard (disk/mem preflight +
# watchdog) runs once for the whole tree of work.
#
# Usage:
#   scripts/run-all-tests.sh              # everything
#   scripts/run-all-tests.sh --unit-only  # skip all container suites
#   scripts/run-all-tests.sh --docker-only  # skip cargo suites
#   scripts/run-all-tests.sh --fast       # skip the heavy lane
#   scripts/run-all-tests.sh --list
#
# Knobs (env):
#   PARALLEL_DOCKER=N   docker-lane pool width      (default 4)
#   NEXTEST_JOBS=N      nextest concurrency         (default nproc)
#   TOKIO_TEST_WORKERS=N per-runtime tokio workers  (default 2; bounds
#                       the multi-thread runtimes some tests build)
#   SUITES=a,b,c        restrict the docker lane (disables heavy lane)
#   E2E_FORCE_BUILD=1 / E2E_WORKING_TREE_BUILD=1 pass through to suites

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_ROOT="${LOG_ROOT:-/tmp/rustcrash-test-logs}"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="$LOG_ROOT/$STAMP"

UNIT=1
DOCKER=1
HEAVY=1
LIST=0
while [ $# -gt 0 ]; do
    case "$1" in
        --unit-only) DOCKER=0; HEAVY=0 ;;
        --docker-only) UNIT=0 ;;
        --fast) HEAVY=0 ;;
        --list) LIST=1 ;;
        *) echo "unknown flag: $1 (see header)"; exit 2 ;;
    esac
    shift
done

# The docker lane: name -> run script. Heaviest first for better pool
# packing. docker-matrix and musl-verify are NOT here (heavy lane).
LIGHT_SUITES=(docker-engine docker-interop docker-shellcrash docker docker-reality docker-cluster)
HEAVY_SUITES=(musl-verify docker-matrix)

if [ "$LIST" = 1 ]; then
    echo "unit lane: workspace, engine(mihomo,singbox), core(engine-*), doctests"
    echo "docker lane (bounded parallel pool): ${LIGHT_SUITES[*]}"
    echo "heavy lane (sequential): ${HEAVY_SUITES[*]}"
    exit 0
fi

if [ -n "${SUITES:-}" ]; then
    IFS=, read -ra LIGHT_SUITES <<< "$SUITES"
    HEAVY=0
fi

# ---------------------------------------------------------------------------
# Preflight: resource guard once for the whole tree (each suite script
# sources it again; its checks are idempotent and its watchdog ties
# itself to the calling shell, so nesting is harmless).
# ---------------------------------------------------------------------------
. "$SCRIPT_DIR/resource-guard.sh"
guard_run

mkdir -p "$LOG_DIR"

# Bound the tokio multi-thread runtimes built inside tests (Runtime::new()
# defaults to one worker per core; 32-way test parallelism x 32 workers
# is a thread explosion with zero test value).
export TOKIO_WORKER_THREADS="${TOKIO_TEST_WORKERS:-2}"

# nextest when available: per-test process isolation (env vars and
# global statics cannot bleed between tests) plus per-test timing.
HAVE_NEXTEST=0
command -v cargo-nextest >/dev/null 2>&1 && HAVE_NEXTEST=1

run_step() { # <lane> <name> <cmd...> — run, log, record rc + duration
    local lane="$1" name="$2"; shift 2
    local log="$LOG_DIR/$name.log"
    local t0 rc
    t0=$SECONDS
    # Subshell so the inner exit only ends THIS step, never the lane.
    (
        echo "=== [$lane] $name — $(date) ==="
        "$@"
        rc=$?
        echo "=== [$lane] $name rc=$rc elapsed=$((SECONDS - t0))s ==="
        exit $rc
    ) > "$log" 2>&1
    rc=$?
    printf '%s\t%s\t%s\t%s\n' "$lane" "$name" "$rc" "$((SECONDS - t0))" \
        >> "$LOG_DIR/results.tsv"
    if [ "$rc" != 0 ]; then
        echo "[$lane] FAIL $name (rc=$rc) — tail of $log:" >&2
        tail -25 "$log" >&2
    else
        echo "[$lane] ok   $name ($((SECONDS - t0))s)"
    fi
    return $rc
}

cargo_suite() { # <label> <cargo-args...>
    local label="$1"; shift
    if [ "$HAVE_NEXTEST" = 1 ]; then
        run_step unit "$label" cargo nextest run "$@" \
            --test-threads "${NEXTEST_JOBS:-$(nproc)}"
    else
        run_step unit "$label" cargo test "$@"
    fi
}

unit_lane() {
    local fail=0
    cargo_suite workspace-default --workspace || fail=1
    cargo_suite engine-mihomo-singbox -p rustcrash-engine --features mihomo,singbox || fail=1
    cargo_suite core-engine-features -p rustcrash-core --features engine-mihomo,engine-singbox || fail=1
    # nextest does not run doctests; plain cargo does (fast, no bin tests).
    run_step unit doctests cargo test --workspace --doc || fail=1
    return $fail
}

docker_lane() {
    # Pool width: env override wins; else scale with the host (>=8
    # cores can host 4 suites comfortably, smaller machines get 2).
    local width="${PARALLEL_DOCKER:-$([ "$(nproc)" -ge 8 ] && echo 4 || echo 2)}"
    local -a pids=()
    local suite i fail=0
    for suite in "${LIGHT_SUITES[@]}"; do
        # Keep the pool bounded: wait for any finisher at full width.
        while [ "$(jobs -rp | wc -l)" -ge "$width" ]; do
            wait -n || true
        done
        echo "[docker] start $suite"
        run_step docker "$suite" bash "$PROJECT_ROOT/tests/$suite/run.sh" &
        pids+=($!)
    done
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || fail=1
    done
    return $fail
}

heavy_lane() {
    local suite fail=0
    for suite in "${HEAVY_SUITES[@]}"; do
        echo "[heavy] start $suite"
        run_step heavy "$suite" bash "$PROJECT_ROOT/tests/$suite/run.sh" || fail=1
    done
    return $fail
}

# SIGTERM the whole descendant tree on interrupt so every suite's EXIT
# trap fires and tears its containers down (bash skips EXIT traps on an
# untrapped TERM, so the signal must reach each script, not just lanes).
kill_tree() {
    local parent="$1" child
    for child in $(pgrep -P "$parent" 2>/dev/null); do
        kill_tree "$child"
    done
    kill -TERM "$parent" 2>/dev/null
}
trap 'for pid in $(jobs -p); do kill_tree "$pid"; done; exit 130' INT TERM

T0=$SECONDS
declare -a LANE_PIDS=()
[ "$UNIT" = 1 ] && { unit_lane & LANE_PIDS+=($!); }
[ "$DOCKER" = 1 ] && { docker_lane & LANE_PIDS+=($!); }
[ "$HEAVY" = 1 ] && { heavy_lane & LANE_PIDS+=($!); }

FAILED_LANES=0
for pid in "${LANE_PIDS[@]}"; do
    wait "$pid" || FAILED_LANES=$((FAILED_LANES + 1))
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
# Stop the resource-guard watchdog and drop every background job from
# the table (it only contained the watchdog by now): an exiting script
# must not sit in wait() on the watchdog's sleep chain.
guard_watch_stop || true
disown -a 2>/dev/null || true

echo ""
echo "=================== test run summary ($STAMP) ==================="
if [ -f "$LOG_DIR/results.tsv" ]; then
    column -t -s$'\t' "$LOG_DIR/results.tsv"
fi
echo "------------------------------------------------------------------"
echo "total wall: $((SECONDS - T0))s   logs: $LOG_DIR"
if [ "$FAILED_LANES" = 0 ]; then
    exit 0
fi
echo "FAILED LANES: $FAILED_LANES"
exit 1
