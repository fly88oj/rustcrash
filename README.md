# RustCrash

[![CI](https://img.shields.io/badge/tests-500%2B-green)]() [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)]() [![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)]()

**A single-binary, cross-platform manager for [mihomo](https://github.com/MetaCubeX/mihomo) and [sing-box](https://github.com/SagerNet/sing-box) proxy kernels — a Rust rewrite of [ShellCrash](https://github.com/juewuy/ShellCrash).**

English | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md) | [Português](README.pt.md) | [Русский](README.ru.md)

## Why RustCrash

ShellCrash is a battle-tested shell toolkit for running transparent proxies
on routers. RustCrash keeps its feature set but ships as **one static
binary**: no shell dependencies, typed configuration, verified downloads,
and a full test suite.

- **One binary** — every function (init, install, firewall, lifecycle,
  subscriptions, scheduling, bot, API) is a subcommand of `crash`.
- **Real platforms** — Linux x86_64/ARM64/ARMv6/ARMv7/MIPS (musl, static)
  for routers and Raspberry Pi, OpenWrt, Docker; iptables and nftables;
  systemd, OpenWrt init and OpenRC.
- **Verified installs** — kernel downloads are SHA-256-checked against
  release checksum sidecars before anything touches disk.
- **Native subscription conversion** — 8 protocol URI parsers (VMess, VLESS,
  SS, SSR, Trojan, Hysteria2, TUIC, WireGuard) and 16 output formats
  (Clash, sing-box, Quantumult(X), Loon, Surge, Surfboard, Stash, V2Ray, …),
  no external subconverter binary.
- **Remote management** — Telegram bot with inline menus, REST API with
  token auth, push notifications to 7 providers.

## Quick start

First time? Open the [install guide](docs/INSTALL.md) — it maps your
device (`uname -m`) to the right prebuilt binary, so you don't need a
Rust toolchain. You will also need a **proxy subscription URL** from
your provider for the `config import` step.

```bash
sudo crash init --init        # create /etc/rustcrash + register the init system
sudo crash install            # download the mihomo kernel (SHA-256 verified; needs GitHub access)
crash config import https://example.com/sub   # your subscription URL
crash config generate         # write the kernel config from that subscription
sudo crash start serve        # supervisor: kernel + watchdog + bot + REST API

# confirm it is alive:
sudo crash start status       # platform, chosen kernel, install state
sudo crash start logs         # tail the kernel log
```

Prefer building? `cargo build --release --bin crash` then
`sudo install -m755 target/release/crash /usr/local/bin/`; for routers
and Raspberry Pi use `bash scripts/cross-compile.sh` (see the
install guide).

Docker:

```bash
docker build -t rustcrash .
docker run --rm --cap-add NET_ADMIN rustcrash crash --version
```

## Commands

| Area | Examples |
|------|----------|
| Lifecycle | `crash start start/stop/restart/status/logs/watchdog` |
| Supervisor | `crash start serve` (REST API + Telegram bot + watchdog) |
| Firewall | `crash firewall setup --tun --ipv6 --quic-reject` / `cleanup` |
| Subscriptions | `crash config import/list/select/generate`, `crash sub convert -t clash` |
| Updates | `crash task enable --interval 12h`, `crash task geo`, `crash task rules` |
| Telegram bot | configure in `config.yaml`, then `crash start bot` |

Full reference: [docs/CLI.md](docs/CLI.md) · [REST API](docs/API.md) ·
[Telegram bot](docs/BOT.md) · [Configuration](docs/CONFIGURATION.md)

## Security

Runs as root on routers, so the rules are strict: argument-vector process
spawns only (no shell, no string-built commands), loopback-only API with
token auth, chat-ID whitelisting for the bot, atomic+sanitized downloads,
secrets from config/env only. See [docs/SECURITY.md](docs/SECURITY.md).

## Building & testing

```bash
cargo test --workspace                 # 500+ tests, no network required
cargo clippy --workspace --all-targets
bash scripts/cross-compile.sh          # 6 targets: ARM/ARM64/MIPS routers, Pi, x86
bash scripts/release.sh                # release dir: tar.gz per target + SHA256SUMS
bash tests/docker/run.sh               # multi-container e2e (real binary)
```

## Project layout

```
core/            rustcrash-core library (platform, service, bot, notify,
                 api, geo, rules, firewall, subconverter, …)
cmd/crash/       the single crash binary (CLI + TUI)
tests/           integration + Docker e2e suites
docs/            CLI / API / bot / config / architecture / security docs
```

Architecture details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Roadmap & compatibility

Feature parity with ShellCrash core is complete through its advanced
features (TUN, IPv6, VM/Docker handling, task hooks, Telegram bot, push
channels). Out of initial scope: PAC mode, SSH tools, DDNS.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option.
