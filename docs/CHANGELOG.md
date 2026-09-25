# Changelog

All notable changes to RustCrash. Format based on
[Keep a Changelog](https://keepachangelog.com/); versioning follows
[SemVer](https://semver.org/).

## [Unreleased]

### Engine — WireGuard, QUIC servers, TUN v6/ICMP, DoH on the DNS port

- WireGuard outbound: hand-rolled Noise_IKpsk2 handshake (KDF/MAC1/2
  step-cited from the whitepaper), transport keys with anti-replay and
  cookie consumption, keepalive/rekey timers, a smoltcp userspace
  client stack for TCP and UDP, and mihomo's `reserved` bytes exactly
  as sing-wireguard's client bind encodes them. Both dialects parse
  the full field set.
- hysteria2 and TUIC v5 server listeners (the engine acting as the
  proxy server over QUIC): H3 auth with status 233, exporter-token
  authentication, TCP streams and UDP datagram relays with idle
  reaping, constant-time credential compares.
- TUN inbound: IPv6 (in6_ifreq address assignment verified against
  the kernel source chain; smoltcp proto-ipv6) and ICMP echo answers
  for both families — `ping` through the tunnel now works.
- The DNS TCP port now serves RFC 8484 DoH (POST and GET ?dns=,
  keep-alive) alongside the length-framed wireformat, like mihomo.
- vless Vision: server-commanded direct (`02`) is parsed with verbatim
  passthrough (the framing half of the splice; the raw-transport
  rebind is tracked).

### Engine — wave 8: ECH runtime, OpenVPN, snell/mieru UDP, sudoku tunnel modes, tlsmirror enrolment, restls/tlsmirror listeners

- **ECH is live** on the TCP-TLS outbounds (vless/trojan/vmess/anytls,
  `ech-opts`): the engine's own TLS 1.3 stack now performs the full
  encrypted-client-hello handshake — inner/outer ClientHello shaping,
  HPKE-sealed extension, accept/HRR confirmations, transcript rebind to
  the inner hello, certificate verification against the inner name, and
  the upstream rejection path (`ech_required` alert, one retry with the
  server's retry configs, exact Go error strings). QUIC/h2 carriers
  (hysteria2/tuic/trusttunnel) still fail with the precise quinn/rustls
  blocker; HTTPS-RR discovery needs DNS type-64 (precise error).
- **OpenVPN outbound**: the complete 2.x client — control channel with
  reliable transport and replay windows, tls-auth/tls-crypt/tls-crypt-v2
  auth layers, rustls TLS-1.3 control epoch, key-method-2 derivation,
  AES-GCM/CHACHA20/AES-CBC data channel, push parsing (ifconfig/route/
  dns/cipher negotiation), soft-reset rekey, and the smoltcp userspace
  stack for L3 dialing (the wireguard pattern). TCP and UDP transports.
- **snell UDP**: a frame-boundary reader on the AEAD session
  (one decrypted frame per read, v4 whole-datagram single-frame writes)
  — `UdpChannel::Snell` wired, the refusal deleted.
- **mieru UDP packet transport**: stateless datagram cipher with the
  retransmit/window/ACK engine (RTT stats + CUBIC, heartbeats, reorder
  delivery), plus the SOCKS5 UDP-ASSOCIATE relay that works over either
  underlay; `transport: UDP` no longer rejected.
- **sudoku http-mask tunnel modes**: stream (chunked pull + sequenced
  uploads), poll (base64 lines), auto (probe + fallback) and ws
  (WebSocket upgrade + HMAC token), each with optional TLS carriers and
  the early-handshake KIP exchange riding the tunnel bootstrap; TCP,
  UoT and session-mux entry points over any mode.
- **tlsmirror connection-enrolment**: server-identifier host derivation,
  the protobuf confirmation over a minimal h2c client/server, and the
  server half (`ServeConnReady`) with the matching camouflage listener;
  a `tlsmirror` listener now also serves enrolment control connections.
- **restls listener**: the server half of the restls handshake
  (session-id MAC over key shares, XOR-masked first flight, script-framed
  records with min-record-len/rate-limit, camouflage raw-relay fallback)
  behind a fixed-dest listener; the wave-6 client was fixed to capture
  its Finished record for real-server compatibility.

### Engine — wave 7: jls, shadowquic, sudoku, gost-relay, tlsmirror, trusttunnel, masque, ECH core; Vision full splice; WireGuard IPv6

- Five new mihomo outbound types, all with TCP+UDP wiring and their
  option surfaces parsed in the mihomo dialect:
  - **shadowquic** — TCP + UDP (datagram and udp-over-stream) over
    quinn, control-stream id registration, ≤32-packet pending demux,
    Brutal codec and the QUIC tuning knobs that map. JLS-inside-the-
    QUIC-TLS-handshake cannot ride quinn/rustls (no hook) and fails
    with the exact upstream mechanism named; the empty-credential
    framing-only mode works (delta documented in the module).
  - **sudoku** — KIP framing, X25519+nonce-echo+session-rekey
    handshake, epoch-rotating RecordConn AEAD, the complete table
    obfuscation with a bit-exact Go `math/rand` transcription
    (directional/custom/rotation layouts, pinned by generated Go
    vectors), legacy HTTP mask, UoT UDP and the session mux.
    http-mask tunnel modes (stream/poll/auto/ws) fail with precise
    errors pointing at legacy.
  - **gost-relay** — relay protocol client: feature-framed handshake
    (userauth/addr/network), TCP and UDP associations, TLS, forward
    mode; `mux: true` rejected citing smux.
  - **trusttunnel** — pool client with an in-tree minimal HTTP/2
    client (full HPACK incl. Huffman + dynamic table, flow control)
    and HTTP/3-over-quinn CONNECT tunnels, both UDP framings, h2/h3
    ALPN selection, health check.
  - **masque** — Cloudflare-flavoured MASQUE: ECDSA client-cert auth
    and server public-key pinning, a minimal in-module HTTP/3 client,
    `cf-connect-ip` extended CONNECT with the ADDRESS_ASSIGN/
    ROUTE_ADVERTISEMENT capsules, L4-proxy plain-CONNECT TCP; TUN/
    ip-stack mode and L4 UDP fail with precise upstream-cited errors.
- **jls** (`jls-opts` on vless/trojan/vmess/anytls): TLS 1.3 with the
  hello randoms replaced by AES-256-GCM-sealed seeds keyed by
  SHA256(user‖authData)/SHA256(password‖authData) — a two-pass rustls
  hello-stamping technique with golden vectors generated by the actual
  Go construction; validated against a live JLS rustls server mimic.
- **tlsmirror** (`tlsmirror-opts` on vmess): the mirror carrier with
  XOR-nonce AES-GCM (counter-retry semantics), HKDF labels, TLS 1.2
  explicit-nonce path, ChaCha20 sequence watermarking, transport
  padding and the embedded HTTP traffic generator.
- **ech** (`ech-opts` on seven carriers): the complete ECH core —
  ECHConfigList parsing 1:1 from metacubex/tls (draft-18/RFC 9460),
  HPKE base sender (RFC 9180 vectors) and the outer ClientHello
  extension builder. Runtime enablement fails with the precise
  blocker until the engine's own TLS 1.3 stack grows the handshake
  hook (staged; the splice rebind API from this wave is the seam).
- **Vision direct splice, full**: `Tls13Stream` gained the rebind API
  (take read-ahead, unwrap to the raw transport, per-direction splice
  flags); `VisionConn::connect_tls13` re-binds each direction at the
  server `02` transition exactly like Xray's direct copy — the vless
  wiring now uses it whenever the outer TLS is the engine's own
  REALITY stack. Opaque rustls outers keep framing mode.
- **WireGuard IPv6**: dual-stack smoltcp interface (local_ipv6),
  per-family source selection, v6 TCP/UDP targets, one tunnel shared
  across families; unconfigured v6 targets fail with the upstream
  error text.

### Engine — snell, anytls, mieru, restls; SS-2022 multi-user server

- Snell v3/v4 outbound: Argon2id key derivation implemented in-module
  (RFC 9106, validated against Go x/crypto vectors), v4's stride-2
  padding swap, bit-ratio padding and chunk ramp, and the UDP codecs
  (TCP relay wired; UDP channel pending a frame-boundary reader).
- AnyTLS outbound: password auth, negotiated padding scheme, and
  UDP-over-TCP (uot v2) wired as a UDP channel.
- Mieru outbound (the mihomo adapter subset): hashed-password auth,
  PBKDF2 time-derived keys, XChaCha20-Poly1305 implicit-nonce session
  over the stream transport; UDP packet transport and multiplexing
  fail loudly at config time.
- RestLS outbound: TLS 1.3 session-id BLAKE3 MAC stamping via a
  custom rustls SecureRandom, XOR'd server auth record, and
  script-driven padding with writer interruption; the tls12 version
  hint is rejected with the reason (no rustls KEX hook).
- SS-2022 multi-user server (SIP023 extended identity headers) for
  TCP and UDP, with per-user replay windows and silent drops;
  single-user listeners unchanged.


### Engine — server side, camouflage transports, TUN, REALITY

- Server listeners now serve UDP too: Shadowsocks (legacy + 2022 with a
  SIP022 replay window), trojan/vless/vmess UDP commands; the trojan
  client framing was corrected to the upstream layout
  (`addr || len || CRLF || payload`) after the live-server e2e pinned it.
- vless `flow: xtls-rprx-vision` (framing mode): the request addons,
  padding frames and command transitions are ported from Xray/mihomo;
  direct splice remains a tracked follow-up.
- Platform DNS upstreams: `system`/`local` (resolv.conf) and
  `dhcp://iface` (systemd-networkd + dhclient leases).
- The REALITY client is now validated against a REAL Xray server by a
  new container suite (tests/docker-reality, 19 checks): handshake +
  relay through the camo site, firefox-profile parity, wrong short-id /
  wrong public key refusals, and the TLS_AES_256_GCM_SHA384 path — the
  suite found and drove the fixes for the SHA-384 key schedule (0x1302)
  and zero-padded inner plaintext.
- UDP correctness against real servers is now covered by interop checks
  (Shadowsocks legacy + 2022 with SIP022 keying from the DECRYPTED
  header, trojan with the upstream CRLF frame and real association
  target) — all three were broken before the checks existed and pass
  now.

- Server-side proxy listeners: the engine can now ACT AS the proxy
  server (mihomo `listeners:`, sing-box server inbounds) for
  Shadowsocks AEAD + 2022, Trojan, VMess AEAD and VLESS; TCP only.
- Outbound transports: SSH (russh; password / PEM key auth, known-host
  pins), ShadowTLS v3 client with mihomo-style inner `proxy:` nesting,
  simple-obfs (http/tls) under Shadowsocks.
- DDR: sing-box `dns.rules` end to end (tag-referenced servers, cache
  bypass, TTL rewrite, per-rule client subnet) and DoQ (`quic://`) +
  DoH3 (`h3://`) DNS upstreams over QUIC.
- TUN device inbound (Linux): `/dev/net/tun` + smoltcp userspace
  netstack bridged into the same relay as tproxy, with DNS hijack
  answering through the engine resolver; firewall/TUN-mode keeps
  ownership of routes. Verified end to end in the docker suite with
  NET_ADMIN.
- REALITY + uTLS-style TLS fingerprinting: a from-scratch Rust TLS 1.3
  client with byte-controlled ClientHello (Chrome/Firefox profile
  templates), REALITY auth/camouflage per the XTLS spec, and plain
  `client-fingerprint`/`tls.utls` support on vless; no BoringSSL, so
  musl-static builds stay intact. RFC 8448 key-schedule vectors and
  rustls loopback pin the TLS engine; the REALITY wire is ported from
  upstream sources (line-cited) pending a live-server capture.
- Traffic sniffer: per-protocol destination-port gates
  (`sniff: {TLS: {ports}}`).

## [0.2.0] — 2026-09-24

### Integrated Rust proxy engine

- New `engine/` crate: a from-scratch Rust rewrite of the mihomo/sing-box
  data plane, selected at runtime via `kernel: rust-mihomo` /
  `rust-sing-box` in `config.yaml` (the classic external-kernel modes are
  unchanged).
- Outbounds: Shadowsocks AEAD (aes-128/256-gcm, chacha20-ietf-poly1305)
  and Shadowsocks 2022 (2022-blake3-aes-128/256-gcm), VMess AEAD (tcp,
  WebSocket and httpupgrade transports), VLESS, Trojan (TLS via rustls,
  skip-cert-verify supported), SOCKS5 (TCP + UDP ASSOCIATE), HTTP CONNECT,
  DIRECT/REJECT; hysteria2 (QUIC, salamander obfs) and TUIC v5 (QUIC,
  native/quic UDP relay, heartbeats) over quinn.
- Transports: WebSocket (with ≤757-byte 0-RTT early-data), v2ray
  httpupgrade, and gRPC/gun (hand-rolled HTTP/2 with HPACK + flow
  control, TLS ALPN h2).
- Inbounds: mixed (auto SOCKS5/HTTP), SOCKS5 with UDP ASSOCIATE, HTTP
  proxy (CONNECT + absolute-form replay), Linux REDIRECT (SO_ORIGINAL_DST)
  and TPROXY (TCP + UDP with IP_TRANSPARENT/RECVORIGDSTADDR).
- DNS subsystem: hijack server (UDP + TCP), fake-IP pool with LRU
  eviction and reverse mapping, redir-host forwarding, answer caching,
  static hosts overrides, upstreams over UDP/TCP/DoT/DoH,
  `nameserver-policy` per-domain routing, EDNS0 client-subnet.
- Traffic sniffer: TLS ClientHello SNI, HTTP Host, and QUIC v1 Initial
  (RFC 9001 decryption) with override-destination, skip-domain and
  force-domain semantics — mirrored from mihomo's `sniffer`.
- Routing rules: DOMAIN/-SUFFIX/-KEYWORD/-REGEX/-WILDCARD, IP-CIDR/
  IP-CIDR6, SRC-IP-CIDR, DST/SRC-PORT, GEOIP (MaxMind mmdb), GEOSITE
  (v2ray dat), RULE-SET (text/yaml plus binary .srs and .mrs readers),
  PROCESS-NAME/PATH, UID, IN-TYPE, IN-NAME, IN-USER, IN-PORT, NETWORK,
  DSCP, IP-ASN, IP-SUFFIX, LOGIC AND/OR/NOT, SUB-RULE, CLASH-MODE, MATCH;
  rule/global/direct modes.
- Proxy groups: select, url-test, fallback, load-balance with background
  health checks.
- Clash RESTful API subset: version, proxies (list/select/delay),
  connections, traffic (websocket), rules, configs (mode patch).
- Config dialects behind cargo features: `engine-mihomo` (Clash YAML),
  `engine-singbox` (sing-box JSON); default build ships neither.
- Wire-format fidelity pinned by upstream vectors (v2fly KDF, RFC 5869
  HKDF, RFC 9001 QUIC Initial, RFC 7541 HPACK, RFC 7871 ECS) and Docker
  interop suites (`tests/docker-engine/run.sh`, 29 checks, against a
  real mihomo binary; `tests/docker-cluster/run.sh`, 10 checks, across a
  four-container bridge with engine-to-engine chaining).
- Fixed a wire bug found by the cluster suite: the SOCKS address type
  for domain names was serialized as 0x02 instead of RFC 1928's 0x03,
  which made every domain-targeted Shadowsocks request fail against
  real mihomo servers (vmess/vless keep sing's separate port-first
  1/2/3 convention).
- Unsupported features (WireGuard, TUN, REALITY/vision/utls, SSR,
  simple-obfs) fail with precise errors at `crash engine test`.

### Manager integration

- `KernelSelection` (external vs integrated engine) through config,
  ServiceManager (self-spawned engine worker with the anti-loop gid,
  pid file, watchdog restart, notifications), REST API, and the CLI.
- New `crash engine run|test|version` subcommand; `crash --exec version`
  reports the engine version in-process for engine selections.
- ConfigValidator rejects engine selections in builds without the
  matching feature, naming the build flag to use.
- Docker e2e split: `tests/docker/run.sh` (external kernels, 35 checks),
  `tests/docker-engine/run.sh` (engine interop, 29 checks) and
  `tests/docker-cluster/run.sh` (multi-container cluster, 10 checks).

## [0.1.0] — 2026-09-23

Initial release.

### Core

- Single static `crash` binary (CLI + TUI) covering init, kernel
  installation, firewall, lifecycle, subscriptions, scheduling, bot
  and API — every function is a subcommand.
- Transparent-proxy firewall for nftables and iptables: TPROXY and
  REDIRECT modes with TUN, IPv6, VM/Docker handling, QUIC reject, MAC
  filter and common-port rules; LAN-scoped hijack; idempotent,
  stateless apply; WAN listener guarding.
- Kernel management for mihomo and sing-box: GitHub release discovery,
  SHA-256-verified downloads, per-kernel version probing, watchdog,
  and supervisor mode (`crash start serve` = kernel + REST API +
  Telegram bot in one process).
- Subscription system: URL validation, base64 and concurrent fetch,
  native URI parsing for 8 protocols (VMess, VLESS, SS, SSR, Trojan,
  Hysteria2, TUIC, WireGuard) and 16 output formats (Clash, ClashR,
  sing-box, Quantumult(X), Loon, Surge, Surfboard, Stash, V2Ray, SS,
  SSR, SSD, Trojan, Mixed, Mellow), filtering and sorting with a mini
  script engine, country markers, dedup presets.
- Scheduled tasks: 5-field cron parser with aliases, subscription and
  kernel updates, GeoIP/GeoSite and rule-provider updates with mirror
  support, task hooks.
- Remote management: Telegram bot (inline menus, file transfer,
  chat-ID whitelist), REST API (token auth, loopback bind, request
  size caps), push notifications to 7 providers.
- Init-system integration: systemd, OpenWrt init, OpenRC, rc.local;
  container detection; configuration templates, backup/restore and
  import/export; rotated logging with panic crash reports.

### Platforms & tooling

- Linux x86_64/ARM64/ARMv6/ARMv7/MIPS+MIPSel (musl, fully static
  binaries); OpenWrt; Docker image (NET_ADMIN-ready).
- `scripts/cross-compile.sh`: six device targets (aarch64, armv7,
  armv6, x86_64, mips, mipsel); `scripts/release.sh`: per-target
  tar.gz + SHA256SUMS with ELF verification and emulated smoke runs;
  CI release workflow publishing on `v*` tags.
- Test suite: 513 tests, a multi-container Docker e2e suite (35 checks
  including live firewall apply), clippy `-D warnings` clean.

### Docs & license

- English documentation set (CLI, API, bot, configuration,
  architecture, security, install, benchmarks, troubleshooting) with
  READMEs in nine languages: English, 简体中文, 繁體中文, 日本語,
  Español, Français, Deutsch, Português, Русский.
- Dual-licensed under MIT OR Apache-2.0, at your option.
