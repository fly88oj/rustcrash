# Changelog

All notable changes to RustCrash. Format based on
[Keep a Changelog](https://keepachangelog.com/); versioning follows
[SemVer](https://semver.org/).

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
