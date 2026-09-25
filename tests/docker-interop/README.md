# Interop e2e — the Rust engine against a REAL mihomo release binary, both directions

## What this validates

Unlike `tests/docker-engine` (which interops against the mihomo **v1.19.13
binary baked into the image**) this suite **fetches the current real mihomo
release** at test time and drives it in both directions:

* **forward** — the real mihomo serves one listener per transport a
  ShellCrash user actually runs; the Rust engine (mihomo dialect, inside the
  `crash` binary) dials each of them as a client through its mixed port.
  Assertions: the HTTP payload round-trips, a **UDP-echo nonce** round-trips
  on every UDP-capable outbound, and wrong credentials are refused.
* **reverse** — the engine *serves* ss / trojan / anytls listeners and the
  real mihomo binary dials **them** as a client (TCP payload + UDP echo +
  a wrong-password negative).

### Ground truth discovered about the real binary (v1.19.31)

* `hysteria2`, `tuic` and `anytls` listeners take `users` as a **map**
  (`user: password`), unlike trojan/vmess/vless which take a **list**.
* There is **no standalone `jls:` or `restls:` listener type** (`Parse
  config error: listener N: unsupport proxy type: jls`). JLS and RestLS
  exist as **frontings** (`jls-config:` / `res-tls:`) on the snell /
  anytls / trojan / vless listeners — so that is how this suite exercises
  those two wires:
  * `snell v4 + res-tls` ↔ engine `snell` outbound with
    `obfs-mode: res-tls` (the restls wire under snell),
  * `snell v4 + jls` ↔ engine `snell` outbound with `obfs-mode: jls`,
  * `anytls + jls-config` ↔ engine `anytls` outbound with `jls-opts`.
* The frontings and `certificate` are **mutually exclusive** security modes
  (`listener/anytls/server.go`), so the jls-fronted anytls listener carries
  no certificate.
* restls `dest` is a **dialable `host:port`** — the server relays a
  rejected client's handshake there (a bare hostname gets `:443` appended
  and DNS-resolved, which fails in a hermetic container). jls `dest` is a
  `host:port` fallback target too; the SNI the client must send is the
  separate `sni:`/`host:` field.
* the tuic listener **defaults its TLS ALPN to `h3`**
  (`listener/tuic/server.go`: `NextProtos = []string{"h3"}` when unset)
  while the TUIC v5 spec and both engines' clients use `tuic` — without
  `alpn: [tuic]` the handshake dies with TLS alert 120
  (no_application_protocol).
* Certificates must live under mihomo's home dir or `SAFE_PATHS`.

## Layout (one container, loopback only)

| what | where (`127.0.0.1`) |
| --- | --- |
| plaintext HTTP target (payload oracle) | `38080` |
| TLS 1.3 camo site (jls/reality `dest` oracle) | `38443` |
| UDP echo server (nonce oracle) | `38090` |
| mihomo ss aes-256-gcm / ss 2022-blake3 | `39388` / `39389` |
| mihomo vmess tcp / vmess ws | `39400` / `39401` |
| mihomo vless TLS / vless REALITY | `39402` / `39412` |
| mihomo trojan TLS | `39403` |
| mihomo hysteria2 / tuic (QUIC) | `39404` / `39405` |
| mihomo anytls | `39406` |
| mihomo snell v4 (plain / +res-tls / +jls) | `39407` / `39408` / `39409` |
| mihomo anytls + jls fronting | `39410` |
| engine client (mixed + Clash API) | `27890` / `29090` |
| engine server listeners (ss / trojan / anytls) | `39601`-`39603` |
| mihomo client (mixed + API) | `39500` / `39590` |

The image is the *same* one `tests/docker-engine` builds
(`tests/docker-engine/Dockerfile.engine` → `docker-engine-rustcrash`); this
suite adds nothing to it. All credentials are fake test values; the REALITY
X25519 pair is a fixed openssl-generated test pair.

## How to run

```sh
bash tests/docker-interop/run.sh
```

Exit code is non-zero when any check fails. `run.sh` prints mihomo's and
the engine's log tails on failure and ends with
`=== Results: N passed, M failed ===`.

Environment knobs (all optional):

| var | effect |
| --- | --- |
| `E2E_FORCE_BUILD=1` | rebuild the engine image instead of reusing it |
| `MIHOMO_PINNED_VERSION=v1.19.31` | release used for the pinned fallback |
| `MIHOMO_FORCE_PINNED=1` | skip the "latest" resolution, use the pinned release |
| `MIHOMO_FORCE_FETCH=1` | re-download even if the binary is already present |
| `MIHOMO_PROXY=http://host:port` | proxy for the download |
| `MIHOMO_CACHE_DIR=…` | host cache dir (default `~/.cache/rustcrash-e2e`) |

## The mihomo binary download and its caching

Everything is loopback **except the mihomo download**
(`fixtures/fetch-mihomo.sh`), the only network-dependent step:

1. resolve the latest release tag via the `releases/latest` redirect
   (mihomo asset names carry the version, so `latest/download/<asset>` does
   not exist for this repo), then download `mihomo-linux-amd64-<tag>.gz`;
2. fall back to the pinned `v1.19.31` when the latest cannot be resolved;
3. try direct, then `MIHOMO_PROXY`, then the docker gateway's
   `7890/7891/8080` (the suite runs in a container, so a host-side proxy is
   reachable at the default gateway).

Caching is two-layered so repeated runs are fully offline:

* **in-container skip-if-present**: an existing runnable
  `/tmp/mihomo/mihomo` short-circuits the network entirely;
* **host-side cache** (`~/.cache/rustcrash-e2e/mihomo`, override with
  `MIHOMO_CACHE_DIR`): `run.sh` `docker cp`s a cached binary *into* the
  container before invoking the fetch (which then skips) and copies a
  freshly fetched binary *back out* after success. The fetch script itself
  also keeps a `.gz` cache inside the container.

## Check matrix

Forward (engine client → real mihomo listener), each asserting the HTTP
payload through `mixed-port` (status as of the current engine):

| # | protocol | UDP echo? | negative | status |
| --- | --- | --- | --- | --- |
| 1 | ss aes-256-gcm (legacy AEAD) | yes | wrong password | pass |
| 2 | ss 2022-blake3-aes-256-gcm (SIP022) | yes | — | pass |
| 3 | vmess aes-128-gcm (AEAD, tcp) | — | wrong uuid | pass |
| 4 | vmess auto over ws (`/ws`) | — | — | pass |
| 5 | vless over TLS | — | — | pass |
| 6 | vless over REALITY (dest = camo site) | — | — | pass |
| 7 | trojan over TLS | yes | wrong password | pass |
| 8 | hysteria2 (QUIC) | (skipped) | — | EXPECTED-FAIL #2 |
| 9 | tuic v5 (QUIC, `alpn: [tuic]`) | yes (native mode) | — | pass |
| 10 | anytls | yes (mux session) | wrong password | pass |
| 11 | snell v4 | — | wrong psk | pass |
| 12 | snell v4 + res-tls fronting (**restls wire**) | — | — | pass |
| 13 | snell v4 + jls fronting (**jls wire**) | — | — | EXPECTED-FAIL #3 |
| 14 | anytls + jls-opts (**jls wire**) | — | — | EXPECTED-FAIL #3 |

Reverse (real mihomo client → engine listener): ss, trojan, anytls (TCP
payload each), UDP echo via mihomo's socks UDP-ASSOCIATE → its ss client →
the engine's ss listener, and a wrong-password negative — all pass.

Plus the EXPECTED-FAIL #1 dialect probe
(`fixtures/snell-obfs-opts-dialect.yaml`).

Controls: HTTP target, camo TLS site, UDP echo, real-binary fetch, live
port-collision pre-check (every matrix TCP port must be **free** before
anything starts), every mihomo TCP listener live-checked with a real
connect after start (hysteria2/tuic are QUIC/UDP-only, verified from
mihomo's own log), engine config acceptance, engine listener binds (both
directions).

## Current status

`=== Results: 37 passed, 0 failed ===` with **5 labelled EXPECTED-FAIL
skips** (the dialect probe + hy2 TCP + hy2 UDP + the two jls-wire checks),
all engine-side, all
precisely pinned. The suite intentionally does not work around engine
bugs: each known failure is classified by its exact engine log symptom and
reported as `[SKIP] EXPECTED-FAIL (engine bug): …`; when the engine is
fixed the classification disappears and the check must go green on its
own. Anything failing differently is a hard `[FAIL]`.

### EXPECTED-FAIL #1 (dialect): snell fronting options are read from
`plugin-opts`, not mihomo's `obfs-opts`

Real mihomo reads the snell security-fronting fields from `obfs-opts:`
(`adapter/outbound/snell.go`, `SnellOption.ObfsOpts`, `proxy:"obfs-opts"`).
The engine reads them from `plugin-opts:` (`config_mihomo.rs plugin_opt()`,
which exists for SIP003 ss plugins). Consequences, both reproduced here:

* a mihomo-canonical `obfs-mode: jls` + `obfs-opts: {username, password}`
  outbound is REJECTED at config load with the confusing
  `snell jls fronting requires obfs-opts username and password`
  (the credentials are there — under the key the engine ignores);
  pinned by `fixtures/snell-obfs-opts-dialect.yaml`;
* the `res-tls` flavor is worse: it is SILENTLY accepted with empty
  fronting credentials (`plugin_opt -> None -> password: ""`) and would
  only fail at connect time.

The working wire checks carry both spellings (`obfs-opts` for the day the
engine is fixed, `plugin-opts` to run today); the extra mapping is ignored
by the engine.

### EXPECTED-FAIL #2 (h3/qpack): hysteria2 relay dies at
`qpack: dynamic name reference`

The QUIC/TLS handshake to mihomo's hysteria2 listener completes; the
engine's H3 response decoder then chokes because mihomo's quic-go encoder
emits a QPACK **dynamic name reference** in the response HEADERS. The
engine's decoder only accepts static-table references and literals and
assumes "a conforming encoder never emits dynamic references here"
(`engine/src/proto/hysteria2.rs` `decode_field_section`) because the client
advertises a zero dynamic-table capacity — mihomo's encoder does it anyway.
The hy2 **UDP** check is skipped with the same root cause: the hy2 session
establishment rides the same h3 path (the failure is silent there).

### EXPECTED-FAIL #3 (jls client): record layer diverges after an
ACCEPTED JLS authentication

Against the real jls fronting (snell `jls-config` and anytls
`jls-config`): the JLS authentication itself is **accepted** — mihomo's
log shows the inner snell/anytls request being relayed to the HTTP
target — but the engine then fails to decrypt the server's application
records (rustls `DecryptError`: `cannot decrypt peer's message`). The
handshake-stage keys were right (the server could read the request); the
engine's rx application-traffic key diverges from the server's tx key —
pointing at the two-pass stamping / record drive loop in
`engine/src/proto/jls.rs`.

### Documented dialect gaps (worked around, not FAILs)

* the engine rejects a mihomo-dialect config with no `proxies:` section
  (`mihomo config has no proxies`) and with no classic inbound
  (`defines no inbound ports … and no tun block`) even for a
  **listener-only** server config; real mihomo runs such configs fine.
  `engine-server.yaml.tmpl` carries a dummy proxy and an unused
  `mixed-port` for this reason.

### What already passes byte-for-byte against the real binary

ss (AEAD + 2022) TCP+UDP, vmess (tcp + ws), vless over TLS, vless over
REALITY (mihomo's REALITY listener with the camo dest — the fixed TLS 1.3
suite/padding handling holds against mihomo's utls port too), trojan
TCP+UDP, tuic v5 TCP+UDP (native datagrams, with the listener's ALPN
pinned to `tuic`), anytls TCP+UDP, snell v4 (plain and +res-tls/restls
fronting), all five forward negatives, and the full reverse direction
(ss / trojan / anytls TCP, ss UDP echo, wrong-password negative).
