# REALITY e2e — the engine's REALITY client against a REAL Xray server

## What this validates

The Rust engine's REALITY client (`engine/src/proto/reality/`, wired into vless
through `reality-opts` / `client-fingerprint` in the mihomo dialect and
`tls.reality` / `tls.utls` in the sing-box dialect) against a **real Xray
binary** serving **real REALITY inbounds**.

Until this suite the REALITY client had never been tested against a live
server: its wire format was ported line-cited from the XTLS sources
(`reality.go`, `reality/tls.go`, `handshake_server_tls13.go`) and verified only
against an in-process fake server built from the same crate. This suite is the
acceptance test that either validates the port or pinpoints the mismatch.

## Layout (one container, loopback only)

| what | where |
| --- | --- |
| Xray REALITY inbound, vless **no flow** (dest = camo A) | `127.0.0.1:8443` |
| Xray REALITY inbound, vless **flow xtls-rprx-vision** (dest = camo A) | `127.0.0.1:8445` |
| Xray REALITY inbound, vless no flow (dest = camo B) | `127.0.0.1:8446` |
| camo A — python/OpenSSL TLS 1.3 site (the "dest" oracle) | `127.0.0.1:8444` |
| camo B — `openssl s_server`, TLS 1.3 **0x1301 only** | `127.0.0.1:8449` |
| plaintext HTTP target reached *through* the tunnel | `127.0.0.1:38080` |
| engine (mihomo dialect) mixed inbounds | `27890`, `27891`, `27892`, `27895`, `27894` |
| Xray's own client (server-side oracle), socks inbounds | `27900`, `27901` |

Two camos are deliberate: Xray's REALITY server **mirrors the dest site's
ServerHello** (cipher suite included) and zero-pads its handshake records to the
dest's record sizes, so the two dests separate "cannot agree a cipher suite"
from "padded record misread".

The image is the *same* one `tests/docker-engine` builds
(`tests/docker-engine/Dockerfile.engine` → `docker-engine-rustcrash`); nothing
is added to it. The real Xray binary is downloaded at test time inside the
container.

## How to run

```sh
bash tests/docker-reality/run.sh
```

Exit code is non-zero when any check fails. `run.sh` prints xray's and the
engine's log tails on failure, so a wire mismatch is debuggable from CI output
alone, and ends with `=== Results: N passed, M failed ===`.

Environment knobs (all optional):

| var | effect |
| --- | --- |
| `E2E_FORCE_BUILD=1` | rebuild the engine image instead of reusing it |
| `XRAY_ZIP=/path/Xray-linux-64.zip` | use a pre-downloaded Xray zip instead of fetching |
| `XRAY_PROXY=http://host:port` | proxy to use for the download |
| `XRAY_PINNED_VERSION=v25.6.8` | release used for the pinned fallback |
| `XRAY_FORCE_PINNED=1` | skip the "latest" URL and use the pinned release |

## Network dependency

Everything is loopback **except the Xray download**
(`fixtures/fetch-xray.sh`), which is marked network-dependent and is the only
step that can fail for environmental reasons. It tries, in order:

1. `https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip`
   (direct, then via `XRAY_PROXY`, then via the docker gateway's `7890`,
   `7891`, `8080` — this suite runs in a container, so a host-side proxy is
   reachable at the default gateway);
2. the same for the pinned release (`v25.6.8` by default, or
   `releases/version.txt`-style pinning via `XRAY_PINNED_VERSION`).

If the download fails, the suite prints the attempted URLs and the reason,
keeps the structure (results line, non-zero exit) and stops. On hosts where
GitHub is unreachable, pass `XRAY_ZIP=...` to run entirely offline.

## Current status: ONE known divergence (the acceptance finding)

The **REALITY wire format itself is accepted** by Xray 26.3.27: Xray reports
`handshake did not complete successfully` for the engine's connection, a branch
that XTLS/reality's `tls.go` only reaches after `hs.c.conn == conn`, i.e. after
the sealed session id was unsealed, the short id matched, the version/time
bounds held and the SNI was in `serverNames`. The wrong-short-id probe yields
`authentication failed or validation criteria not met`. So HKDF auth key,
AES-256-GCM session-id sealing, short id and temp-auth inputs are correct.

The failure is in the **post-auth TLS 1.3 layer**, at two independent points:

1. **Cipher suite (fails first).** The REALITY ServerHello is the *dest site's*
   ServerHello (XTLS/reality `tls.go` unmarshals the target's hello into
   `hs.hello` and reuses it, replacing only the key share), so its suite is
   whatever the dest picked — `0x1302` for the python/OpenSSL camo. The
   engine's Chrome hello offers `0x1301/0x1302/0x1303`, but
   `tls13::CipherSuite::from_id` implements only `0x1301` and `0x1303`, so the
   handshake aborts at ServerHello with
   `protocol: tls13: server selected unsupported cipher suite 0x1302`.
2. **Record padding.** With a dest that offers `0x1301` (camo B) the suite step
   passes and the engine fails on the server's first encrypted handshake
   record: `protocol: tls13: unexpected inner content type 0 during the
   handshake`. REALITY zero-pads its handshake records to the dest's record
   sizes (`conn.go`, `halfConn.encrypt`, section "mimic recorded handshakeLen":
   `record = append(record, empty[:padding]...)` *after* the content-type
   byte). RFC 8446 §5.4 defines the content type as the last **non-zero** byte
   and Xray's own receiver scans backwards for it; `RecordProtector::open`
   (`tls13.rs`, `inner.pop()`) takes the last byte unconditionally.

Both reproduce on Xray 26.3.27 and on the pinned v25.6.8, and the checks that
depend on a working positive handshake (wrong short id / wrong public key) are
reported as **SKIP** while the handshake is broken — a "failure" there would
prove nothing.

Because of the divergence the primary check `[FAIL] REALITY handshake + relay`
is expected on the current engine; the server side is proven sound by Xray's
own client completing both the no-flow and the Vision handshakes through the
same inbounds. This suite intentionally does not work around the divergence:
when the engine's TLS 1.3 layer implements all three mandatory suites and
strips inner-plaintext padding, this check must go green on its own.

## Check list

- control: HTTP target, camo A (python TLS), camo B (openssl 0x1301)
- engine binary image present / config accepted / listeners bound
- `[PASS/FAIL]` REALITY handshake + vless relay through the no-flow inbound
- `[PASS/FAIL/SKIP]` REALITY auth verdict from the server's own failure reason
- divergence pinpoint: same client against a 0x1302 dest and a 0x1301 dest
- `[PASS/FAIL/SKIP]` negative: wrong short id is refused (no silent success)
- `[PASS/FAIL/SKIP]` negative: wrong public key is refused (no silent success)
- `[PASS]` fallback: a plain TLS client to the REALITY port lands on the camo
- `[SKIP]`/`[PASS]` vision through the engine client (rejected at config load
  today, so clearly labelled as a skip; exercised for real if that changes)
- `[PASS/FAIL]` vision and no-flow oracles with Xray's own client
- `[PASS/FAIL]` negative: a bare TLS client never reaches the tunnel target

The container is given `NET_ADMIN` for parity with the engine suite (REALITY
itself needs none).