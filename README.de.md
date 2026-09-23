# RustCrash

[![CI](https://img.shields.io/badge/tests-500%2B-green)]() [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)]() [![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)]()

**Ein plattformübergreifender Manager als einzelnes Binärprogramm für die Proxy-Kernel [mihomo](https://github.com/MetaCubeX/mihomo) und [sing-box](https://github.com/SagerNet/sing-box) — eine Rust-Neufassung von [ShellCrash](https://github.com/juewuy/ShellCrash).**

[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) | Deutsch | [Português](README.pt.md) | [Русский](README.ru.md)

## Warum RustCrash

ShellCrash ist ein bewährtes Shell-Toolkit, um transparente Proxys auf
Routern zu betreiben. RustCrash behält dessen Funktionsumfang bei,
kommt jedoch als **ein einziges statisches Binärprogramm**: keine
Shell-Abhängigkeiten, typisierte Konfiguration, verifizierte Downloads
und eine vollständige Testsuite.

- **Ein Binärprogramm** — jede Funktion (init, install, Firewall,
  Lebenszyklus, Abos, Planung, Bot, API) ist ein Unterbefehl von `crash`.
- **Echte Plattformen** — Linux x86_64/ARM64/ARMv6/ARMv7/MIPS (musl,
  statisch) für Router und Raspberry Pi, OpenWrt, Docker; iptables und
  nftables; systemd, OpenWrt init und OpenRC.
- **Verifizierte Installationen** — Kernel-Downloads werden per SHA-256
  gegen die offiziellen Checksummen geprüft, bevor etwas auf die Platte
  kommt.
- **Native Abo-Konvertierung** — 8 Protokoll-URI-Parser (VMess, VLESS,
  SS, SSR, Trojan, Hysteria2, TUIC, WireGuard) und 16 Ausgabeformate
  (Clash, sing-box, Quantumult(X), Loon, Surge, Surfboard, Stash,
  V2Ray, …), ohne externes subconverter-Binärprogramm.
- **Fernverwaltung** — Telegram-Bot mit Inline-Menüs, REST-API mit
  Token-Authentifizierung, Push-Benachrichtigungen zu 7 Anbietern.

## Schnellstart

Erste Nutzung? Öffne die [Installationsanleitung](docs/INSTALL.md) —
sie ordnet deinem Gerät (`uname -m`) das passende vorgebaute Binärprogramm
zu, du brauchst also keine Rust-Toolchain. Außerdem brauchst du eine
**Proxy-Abo-URL** deines Anbieters für den Schritt `config import`.

```bash
sudo crash init --init        # /etc/rustcrash anlegen + Init-System registrieren
sudo crash install            # mihomo-Kernel herunterladen (SHA-256-verifiziert; GitHub-Zugriff nötig)
crash config import https://example.com/sub   # deine Abo-URL
crash config generate         # Kernel-Konfiguration aus dem Abo schreiben
sudo crash start serve        # Supervisor: Kernel + Watchdog + Bot + REST-API

# prüfen, ob es läuft:
sudo crash start status       # Plattform, gewählter Kernel, Installationsstatus
sudo crash start logs         # Ende des Kernel-Logs
```

Gerät kommt nicht an GitHub heran? Der Kernel lässt sich offline
installieren: Lade das mihomo-Release auf einer anderen Maschine
herunter, kopiere es nach `/etc/rustcrash/bin/mihomo` (OpenWrt:
`/etc/ShellCrash/bin/mihomo`) und führe `chmod +x` aus — dann kannst du
`crash install` überspringen.

Lieber selbst bauen? `cargo build --release --bin crash` und danach
`sudo install -m755 target/release/crash /usr/local/bin/`; für Router
und Raspberry Pi nutze `bash scripts/cross-compile.sh` (siehe die
Installationsanleitung).

Docker:

```bash
docker build -t rustcrash .
docker run --rm --cap-add NET_ADMIN rustcrash crash --version
```

## Befehle

| Bereich | Beispiele |
|---------|-----------|
| Lebenszyklus | `crash start start/stop/restart/status/logs/watchdog` |
| Supervisor | `crash start serve` (REST-API + Telegram-Bot + Watchdog) |
| Firewall | `crash firewall setup --tun --ipv6 --quic-reject` / `cleanup` |
| Abos | `crash config import/list/select/generate`, `crash sub convert -t clash` |
| Updates | `crash task enable --interval 12h`, `crash task geo`, `crash task rules` |
| Telegram-Bot | in `config.yaml` einrichten, dann `crash start bot` |

Vollständige Referenz: [CLI](docs/CLI.md) · [REST-API](docs/API.md) ·
[Telegram-Bot](docs/BOT.md) · [Konfiguration](docs/CONFIGURATION.md) (auf Englisch)

## Sicherheit

Läuft als root auf Routern, deshalb sind die Regeln streng:
Prozesse werden nur per Argumentvektor gestartet (keine Shell, keine
zusammengesetzten Befehlsstrings), API nur auf Loopback mit Token,
Chat-ID-Whitelist für den Bot, atomare und bereinigte Downloads,
Secrets nur aus Konfiguration bzw. Umgebungsvariablen. Siehe
[docs/SECURITY.md](docs/SECURITY.md).

## Bauen & Testen

```bash
cargo test --workspace                 # 500+ Tests, ohne Netzwerk
cargo clippy --workspace --all-targets
bash scripts/cross-compile.sh          # 6 Ziele: ARM/ARM64/MIPS-Router, Pi, x86
bash scripts/release.sh                # Release-Verzeichnis: tar.gz pro Ziel + SHA256SUMS
bash tests/docker/run.sh               # Multi-Container-E2E (echtes Binärprogramm)
```

## Projektstruktur

```
core/            rustcrash-core-Bibliothek (platform, service, bot, notify,
                 api, geo, rules, firewall, subconverter, …)
cmd/crash/       das einzelne crash-Binärprogramm (CLI + TUI)
tests/           Integrations- + Docker-E2E-Suiten
docs/            CLI-/API-/Bot-/Konfig-/Architektur-/Sicherheits-Doku
```

Architektur-Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Roadmap & Kompatibilität

Die Funktionsparität mit dem ShellCrash-Kern ist vollständig bis hin zu
den erweiterten Funktionen (TUN, IPv6, VM/Docker-Handhabung,
Task-Hooks, Telegram-Bot, Push-Kanäle). Zunächst außerhalb des Umfangs:
PAC-Modus, SSH-Werkzeuge, DDNS.

## Lizenz

Doppellizenziert unter [MIT](LICENSE-MIT) oder [Apache-2.0](LICENSE-APACHE), nach Wahl.
