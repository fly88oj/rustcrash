# Changelog

All notable changes to RustCrash. Format based on
[Keep a Changelog](https://keepachangelog.com/); versioning follows
[SemVer](https://semver.org/).

## [Unreleased]

### Integrated Rust proxy engine

- New `engine/` crate: a from-scratch Rust rewrite of the mihomo/sing-box
  data plane, selected at runtime via `kernel: rust-mihomo` /
  `rust-sing-box` in `config.yaml` (the classic external-kernel modes are
  unchanged).
- Outbounds: Shadowsocks AEAD (aes-128/256-gcm, chacha20-ietf-poly1305)
  and Shadowsocks 2022 (2022-blake3-aes-128/256-gcm), VMess AEAD (tcp and
  WebSocket transports), VLESS, Trojan (TLS via rustls, skip-cert-verify
  supported), SOCKS5 (TCP + UDP ASSOCIATE), HTTP CONNECT, DIRECT/REJECT.
- Inbounds: mixed (auto SOCKS5/HTTP), SOCKS5 with UDP ASSOCIATE, HTTP
  proxy (CONNECT + absolute-form replay), Linux REDIRECT (SO_ORIGINAL_DST)
  and TPROXY (TCP + UDP with IP_TRANSPARENT/RECVORIGDSTADDR).
- DNS subsystem: hijack server (UDP + TCP), fake-IP pool with LRU
  eviction and reverse mapping, redir-host forwarding, answer caching.
- Routing rules: DOMAIN/-SUFFIX/-KEYWORD/-REGEX, IP-CIDR/IP-CIDR6,
  SRC-IP-CIDR, DST/SRC-PORT, GEOIP (MaxMind mmdb), GEOSITE (v2ray dat),
  RULE-SET (text/yaml providers), MATCH; rule/global/direct modes.
- Proxy groups: select, url-test, fallback, load-balance with background
  health checks.
- Clash RESTful API subset: version, proxies (list/select/delay),
  connections, traffic (websocket), rules, configs (mode patch).
- Config dialects behind cargo features: `engine-mihomo` (Clash YAML),
  `engine-singbox` (sing-box JSON); default build ships neither.
- Wire-format fidelity pinned by upstream vectors (v2fly KDF, RFC 5869
  HKDF) and a Docker interop suite (`tests/docker-engine/run.sh`, 26
  checks) that round-trips every protocol through a real mihomo binary.
- Unsupported features (hysteria2, TUIC, WireGuard, gRPC, TUN,
  REALITY/vision) fail with precise errors at `crash engine test`.

### Manager integration

- `KernelSelection` (external vs integrated engine) through config,
  ServiceManager (self-spawned engine worker with the anti-loop gid,
  pid file, watchdog restart, notifications), REST API, and the CLI.
- New `crash engine run|test|version` subcommand; `crash --exec version`
  reports the engine version in-process for engine selections.
- ConfigValidator rejects engine selections in builds without the
  matching feature, naming the build flag to use.
- Docker e2e split: `tests/docker/run.sh` (external kernels, 35 checks)
  and `tests/docker-engine/run.sh` (engine interop, 26 checks).

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
