#!/bin/sh
# rustcrash-kernel-adapter — the migration adapter that lets the REAL
# ShellCrash drive the RustCrash engine binary as its kernel.
#
# ShellCrash invokes its kernel with mihomo's CLI convention, hardcoded in
# its own scripts (starts/clash_modify.sh test_yaml, configs/command.env):
#
#     CrashCore -t -d $BINDIR -f $TMPDIR/config.yaml    (config validation)
#     CrashCore    -d $BINDIR -f $TMPDIR/config.yaml    (run)
#     CrashCore -v / -h                                 (kernel manager probes)
#
# The RustCrash binary speaks a different CLI (`crash engine run/test
# --flavor rust-mihomo --config FILE`), so a raw binary swap fails at the
# first probe (this suite pins that as an engine gap). This adapter is the
# documented migration step: install it as $TMPDIR/CrashCore and
# ShellCrash's stock kernel invocation works unchanged. The -h text shows
# the mihomo-style flags because libs/core_tools.sh core_check() greps -h
# output for '-t' to classify a kernel as valid.
#
# The adapter ALSO normalizes the three mihomo-dialect forms ShellCrash's
# generator emits that the engine does not parse yet (each one is pinned
# as an EXPECTED-FAIL engine gap by this suite; the normalizations are
# semantics-preserving re-spellings mihomo itself accepts):
#   * `mode: Rule`            -> `mode: rule`         (case-insensitive upstream)
#   * `external-controller: :9999` -> `...: 0.0.0.0:9999` (leading-colon listen)
#   * `listen: :1053`         -> `listen: 0.0.0.0:1053`  (leading-colon listen)
# The normalized copy is written next to the config as <config>.rustcrash
# so the original ShellCrash output stays inspectable.
set -u
ENGINE=${RUSTCRASH_ENGINE:-/usr/local/bin/crash}
FLAVOR=${RUSTCRASH_FLAVOR:-rust-mihomo}

mode=run
config=""
while [ $# -gt 0 ]; do
    case "$1" in
        -t) mode=test ;;
        -v) mode=version ;;
        -h | --help) mode=help ;;
        -d) shift ;; # the config dir: the engine resolves paths from the
        #               config file itself, so it is accepted and unused
        -f) config=${2:-}; shift ;;
        *)
            echo "adapter: unknown flag $1" >&2
            exit 2
            ;;
    esac
    shift
done

case "$mode" in
    help)
        cat <<'EOF'
Usage: CrashCore [-t] [-d DIR] -f FILE   (rustcrash kernel adapter)
  -t  test configuration and exit
  -d  configuration directory
  -f  configuration file
  -v  show version
EOF
        exit 0
        ;;
    version)
        exec "$ENGINE" engine version
        ;;
    test | run)
        [ -n "$config" ] || {
            echo "adapter: -f <config> required" >&2
            exit 2
        }
        normalized="$config.rustcrash"
        sed -e 's/^mode: Rule$/mode: rule/' \
            -e 's/^\( *external-controller: *\):\([0-9][0-9]*\)$/\10.0.0.0:\2/' \
            -e 's/^\( *listen: *\):\([0-9][0-9]*\)$/\10.0.0.0:\2/' \
            "$config" >"$normalized"
        # run-mode output goes to a log (start_legacy redirects the kernel's
        # stdout to /dev/null; this adapter-level redirect replaces it)
        if [ "$mode" = run ]; then
            exec "$ENGINE" engine run --flavor "$FLAVOR" --config "$normalized" \
                >>"${RUSTCRASH_LOG:-/tmp/ShellCrash/engine-rust.log}" 2>&1
        fi
        exec "$ENGINE" engine "$mode" --flavor "$FLAVOR" --config "$normalized"
        ;;
esac
