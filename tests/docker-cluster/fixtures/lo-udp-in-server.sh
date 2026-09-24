#!/bin/bash
# Loopback UDP relay INSIDE the server container: engine -> ss(28388) ->
# mihomo -> dns-upstream(35353), all on 127.0.0.1. Isolates the engine's
# ss-UDP path from cross-container UDP transport.
set -u
mkdir -p /tmp/lo-udp
cat > /tmp/lo-udp/eng.yaml <<'YEOF'
mixed-port: 27897
mode: rule
log-level: debug
dns:
  enable: false
proxies:
  - name: ss-lo
    type: ss
    server: 127.0.0.1
    port: 28388
    cipher: aes-256-gcm
    password: interop-ss-psk-123456
    udp: true
rules:
  - MATCH,ss-lo
YEOF
nohup crash engine run --flavor rust-mihomo --config /tmp/lo-udp/eng.yaml >/tmp/lo-udp/run.log 2>&1 &
for i in $(seq 1 20); do
    (exec 3<>/dev/tcp/127.0.0.1/27897) 2>/dev/null && break
    sleep 0.5
done
python3 /fixtures/socks-udp-probe.py 127.0.0.1 27897 127.0.0.1 35353 lo.udp.test
echo "probe rc=$?"
