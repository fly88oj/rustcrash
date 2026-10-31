#!/bin/sh
# Task execution script (D-14: $CRASHDIR/task/task.sh <task_id> <task_type>)
# Follows ShellCrash task.sh behavior

CRASHDIR="${CRASHDIR:-/etc/ShellCrash}"
TASK_ID="$1"
TASK_TYPE="$2"

# Load config if available
if [ -f "$CRASHDIR/libs/set_config.sh" ]; then
    . "$CRASHDIR/libs/set_config.sh" 2>/dev/null
fi

# Run one of the plain line-per-command task files (bfstart / afstart /
# running / affirewall): strip comments, eval each non-empty line.
run_task_file() {
    if [ -f "$CRASHDIR/task/$1" ]; then
        grep -v '^#' "$CRASHDIR/task/$1" 2>/dev/null | while read line; do
            [ -n "$line" ] && eval "$line"
        done
    fi
}

case "$TASK_TYPE" in
    bfstart|afstart|running|affirewall)
        run_task_file "$TASK_TYPE"
        ;;
    subscription_update)
        if [ -x "$CRASHDIR/bin/crash" ]; then
            "$CRASHDIR/bin/crash" update-subscriptions 2>/dev/null
        fi
        ;;
    kernel_update)
        if [ -x "$CRASHDIR/bin/crash" ]; then
            "$CRASHDIR/bin/crash" kernel-update 2>/dev/null
        fi
        ;;
    *)
        if [ -f "$CRASHDIR/task/task.user" ]; then
            cmd=$(grep "^${TASK_ID}#" "$CRASHDIR/task/task.user" 2>/dev/null | cut -d# -f2)
            if [ -n "$cmd" ]; then
                eval "$cmd"
            fi
        fi
        ;;
esac