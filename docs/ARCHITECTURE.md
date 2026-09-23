# Architecture

RustCrash is a Cargo workspace with one library and one binary:

```
┌────────────────────────────────────────────┐
│ cmd/crash         the single `crash` binary │
│  CLI (clap) + TUI (ratatui)                 │
└───────────────┬────────────────────────────┘
                │ depends on
┌───────────────▼────────────────────────────┐
│ core (rustcrash-core)                       │
│                                             │
│ platform ─ config ─ service ─ bot ─ notify  │
│     └────── firewall / geo / rules ─ api    │
│            subconverter (uri/filters/fmts)  │
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

`crash start serve` → loads config → optional `ApiServer` (loopback) →
optional `TelegramBot` (poll loop) → watchdog ticks every N seconds →
`ServiceManager::status`/`start` → kernel process; events fan out through
`NotificationManager`.
