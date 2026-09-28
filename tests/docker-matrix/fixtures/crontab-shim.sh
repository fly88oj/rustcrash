#!/bin/sh
# Hermetic crontab(1) shim for the matrix battery.
#
# The matrix image (debian-trixie-slim) ships no cron daemon and no
# crontab binary, but `crash task enable/list/disable` drive the real
# `crontab -l` / `crashtab -` / `crontab -r` commands. mgmt.sh installs
# this shim into /usr/local/bin/crontab ONLY when no real crontab
# exists, so those subcommands run their genuine code paths against a
# file-backed crontab store instead of failing on a missing binary.
#
# Supported grammar (exactly what cmd/crash's task helpers use):
#   crontab -l    list the store (exit 1 when empty, like real crontab)
#   crontab -     replace the store from stdin
#   crontab -r    remove the store
STORE=/tmp/matrix/crontab-store.txt
case "${1:-}" in
    -l) [ -f "$STORE" ] && cat "$STORE" || exit 1 ;;
    -r) rm -f "$STORE" ;;
    -)  cat > "$STORE" ;;
    *)  echo "crontab-shim: unsupported arg: $*" >&2; exit 2 ;;
esac
exit 0
