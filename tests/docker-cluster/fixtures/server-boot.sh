#!/bin/bash
# Upstream role: real mihomo server (listeners on 0.0.0.0 so other
# containers reach them), TWO web targets (38080 direct lane, 38081 the
# chaining lane), and the DNS upstream. The TLS pair is pre-baked into
# the image by run.sh (generated on the host, never committed).
set -u

nohup env SAFE_PATHS=/fixtures/certs mihomo -f /fixtures/cluster-server.yaml \
    -d /tmp/mihomo-home >/tmp/mihomo.log 2>&1 &
nohup python3 -m http.server 38080 --bind 0.0.0.0 \
    --directory /fixtures/webroot >/tmp/web.log 2>&1 &
nohup python3 -m http.server 38081 --bind 0.0.0.0 \
    --directory /fixtures/webroot >/tmp/web2.log 2>&1 &
nohup python3 /fixtures/dns-upstream.py 35353 >/tmp/dns-up.log 2>&1 &

# Stay up; the suite tears the whole stack down.
exec sleep infinity
