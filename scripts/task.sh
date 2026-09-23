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

case "$TASK_TYPE" in
    bfstart)
        if [ -f "$CRASHDIR/task/bfstart" ]; then
            grep -v '^#' "$CRASHDIR/task/bfstart" 2>/dev/null | while read line; do
                [ -n "$line" ] && eval "$line"
            done
        fi
        ;;
    afstart)
        if [ -f "$CRASHDIR/task/afstart" ]; then
            grep -v '^#' "$CRASHDIR/task/afstart" 2>/dev/null | while read line; do
                [ -n "$line" ] && eval "$line"
            done
        fi
        ;;
    running)
        if [ -f "$CRASHDIR/task/running" ]; then
            grep -v '^#' "$CRASHDIR/task/running" 2>/dev/null | while read line; do
                [ -n "$line" ] && eval "$line"
            done
        fi
        ;;
    affirewall)
        if [ -f "$CRASHDIR/task/affirewall" ]; then
            grep -v '^#' "$CRASHDIR/task/affirewall" 2>/dev/null | while read line; do
                [ -n "$line" ] && eval "$line"
            done
        fi
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