# Architecture

RustCrash is a Cargo workspace with two libraries and one binary:

```
┌────────────────────────────────────────────┐
│ cmd/crash         the single `crash` binary │
│  CLI (clap) + TUI (ratatui)                 │
│  + `crash engine run|test|version`          │
└───────────────┬────────────────────────────┘
                │ depends on
┌───────────────▼────────────────────────────┐
│ core (rustcrash-core)                       │
│                                             │
│ platform ─ config ─ service ─ bot ─ notify  │
│     └────── firewall / geo / rules ─ api    │
│            subconverter (uri/filters/fmts)  │
│            engine (KernelSelection bridge)  │
└───────────────┬─────────────────────────────┘
                │ optional dep, feature-gated
┌───────────────▼─────────────────────────────┐
│ engine (rustcrash-engine)                   │
│  protocols (ss/2022, vmess, vless, trojan,  │
│   socks, http) ─ TLS/WS transports          │
│  inbounds (mixed/socks/http/redir/tproxy)   │
│  dns (wire, fake-IP, resolver) ─ rules       │
│  geoip/geosite ─ app (Engine) ─ clash api   │
│  dialects: mihomo YAML / sing-box JSON      │
└─────────────────────────────────────────────┘
```

## Module map

| Module | Interface (what callers need) | Depth behind it |
|--------|-------------------------------|-----------------|
| `platform` | `Platform` value (detected once, immutable snapshot of OS/arch/init/dirs) | /proc and filesystem probing, OpenWrt/container detection |
| `config` | `ConfigManager::load/save`, typed `Config` | YAML persistence, defaults, kernel-config paths |
| `service` | `ServiceManager::{start,stop,restart,status}`, `serve()` | pid files, `libc::kill` signalling, /proc VmRSS, uptime, validated process spawn, supervisor wiring |
| `bot` | `TelegramBot::{run,poll_once}`, `TgApi` trait | long polling, whitelist, callback/text/document dispatch, state machine, menus |
| `notify` | `NotificationManager::notify_event`, pure `build_request` | 7 provider payload formats, event gating, fan-out |
| `api` | `ApiServer::serve`, `token_from` | hand-rolled HTTP/1.1 parsing, routing, auth, secret redaction, size caps |
| `geo` | `GeoUpdater::update` | GitHub release discovery, mirror rewriting, atomic installs |
| `rules` | `RuleProviderManager::update_due`, `due_providers` | sidecar state file, bounded-concurrency fetch, atomic writes |
| `logging` | `append_rotated`, `tail_file`, `init_logging`, `install_crash_reporting` | line-capped rotation, backward block reads, panic reports |
| `firewall` | `Firewall` + `FirewallConfig` | nftables/iptables script generation (TUN, IPv6, VM, MAC filter) |
| `kernels` | `KernelManager::{install,get_kernel_version,…}` | GitHub releases, SHA-256 sidecar verification, gz unpack |
| `subconverter` | `parse_uri`, `apply_filters`, `convert_nodes` | 8 protocol URI parsers, filter/sort pipeline (incl. mini JS-like scripts), 16 output formats |
| `subscription` | `SubscriptionManager::{fetch,convert,…}`, `ConvertOptions` | URL validation, base64, concurrent fetch, format detection |
| `task` | `CronExpr`, `TaskManager`, updaters | cron parsing, hooks, scheduled sub/kernel updates |
| `init` | init-system integrations | systemd/OpenWrt/OpenRC generation, container detection |
| `backup`, `template`, `validate`, `import_export` | backup tarballs, config templates, validation | |
| `engine` (core) | `KernelSelection`, `EngineFlavor`, `engine::{run,test,version}` | feature-gated bridge into the engine crate; geo-path wiring; builds without engine features get precise errors |
| `engine` (crate) | `Engine::build/run`, `EngineConfig`, `RelayHandler` | the integrated data plane: protocol codecs, transports, inbounds, DNS/fake-IP, rules, groups, Clash API, dialect loaders |

The engine crate's own seams:

- **`BoxProxyStream`** — every protocol handshake returns the same boxed
  duplex stream, so relays and transports compose without knowing the
  protocol.
- **`RelayHandler`** — inbounds hand `(meta, stream)` or UDP channel
  pairs to the engine core; the app layer routes and relays.
- **dialect loaders** (`config_mihomo` / `config_singbox`, cargo
  features) — both produce the same normalized `EngineConfig`; the app
  layer is dialect-agnostic.
- **wire formats pinned by vectors** — v2fly KDF, RFC 5869 HKDF,
  upstream mihomo binary interop (tests/docker-engine).

## Key seams

- **`TgApi`** (bot): two real adapters — `HttpTgApi` (reqwest) and the
  in-memory `MockApi` used by tests. Bot logic never touches HTTP
  directly.
- **`Platform::for_crash_dir`**: tests build hermetic platforms instead of
  mutating `CRASHDIR` (which races between parallel tests).
- **`build_request`** (notify) / **`apply_filters`** (subconverter): pure
  functions — provider payloads and filter pipelines are unit-testable
  without I/O.
- **injectable GitHub/API bases** (`install_with_base`,
  `GeoUpdater::with_api_base`, `HttpTgApi::new(base,…)`): releases and
  the Bot API are tested against `wiremock`.

## Design rules

1. No shell: argument-vector spawns only; `libc::kill` for signals;
   validated, canonicalized paths for anything executed.
2. Secrets from config/env only; placeholder tokens in tests; redaction
   on the API surface.
3. Remote-supplied filenames sanitized to their final component; atomic
   temp+rename writes for downloads.
4. The binary stays thin: logic lands in `core` so the CLI, bot, API and
  tests share one implementation.

## Known design debt

- **`Config` stays a flat struct (~45 fields).** Bot/Api/Geo/Notify
  sub-structs behind `#[serde(flatten)]` were considered and
  deliberately deferred: the flat shape mirrors ShellCrash's
  `ShellCrash.cfg` keys one-to-one (eases migration and parity checks),
  and every consumer site churns in the same file. Revisit when a group
  needs independent validation.
- **`Firewall` exposes `setup_tcp_redir`/`setup_dns`** for script
  generation; the live path is `apply_full(&FirewallConfig)`. Collapse
  the two when `generate_nft_script` renders directly from
  `FirewallConfig`.

## Data flow (supervisor)

`crash start serve` → loads config → `KernelSelection` (external kernel
or integrated engine) → optional `ApiServer` (loopback) → optional
`TelegramBot` (poll loop) → watchdog ticks every N seconds →
`ServiceManager::is_running_selection`/`start_selection` → kernel process
or self-spawned engine worker (`crash engine run`, anti-loop gid, pid
file); events fan out through `NotificationManager`.

## Data flow (engine, integrated mode)

`crash engine run` → dialect loader (Clash YAML / sing-box JSON) →
normalized `EngineConfig` → `Engine::build` (registry, rules, geo,
DNS/fake-IP) → inbounds (mixed/socks/http/redir/tproxy) + DNS server +
Clash API → per connection: inbound parses target → `route()` (fake-IP
reversed first, rules, lazy resolve for IP rules) → outbound handshake
(ss/vmess/vless/trojan/socks/http/direct) → bidirectional copy with
per-connection counters feeding the connection table and traffic
channels.
