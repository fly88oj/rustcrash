# CLI Reference

`crash` is the single RustCrash binary. Every management function is a
subcommand. Run without arguments it starts the interactive TUI.

```
crash [OPTIONS] [COMMAND]
```

Global option: `-c, --crashdir <DIR>` — override the crash directory
(default `/etc/rustcrash`, or `/etc/ShellCrash` on OpenWrt; the `CRASHDIR`
environment variable works too).

## Command overview

| Command | Purpose |
|---------|---------|
| `crash init` | Initialize directory structure and config |
| `crash config …` | Configuration and subscription management |
| `crash firewall …` | Firewall rule management |
| `crash start …` | Kernel lifecycle, bot, supervisor |
| `crash engine …` | Integrated Rust engine (run/test/version) |
| `crash task …` | Scheduled tasks, geo data, rule providers |
| `crash install` | Download and install a proxy kernel |
| `crash setboot …` | Boot-time autostart |
| `crash sub …` | Native subscription conversion |
| `crash -e <CMD>` | Non-interactive shortcut (start/stop/restart/status/version) |

## crash init

```
crash init [--force] [--init]
```

Creates the directory layout (`bin/ run/ logs/ config/ data/`) and a default
`config.yaml`. `--init` additionally sets up init-system integration
(systemd unit, OpenWrt init script, or OpenRC script, depending on what is
detected). `--force` skips confirmation prompts.

## crash start

| Subcommand | Description |
|------------|-------------|
| `start` | Start the configured kernel (mihomo or sing-box) |
| `stop` | Stop any running kernel (SIGTERM → SIGKILL) |
| `restart` | Restart the kernel |
| `status` | Running state, PID, memory (VmRSS), uptime |
| `logs [--follow]` | Tail the newest kernel log (follow polls every 2 s) |
| `watchdog [--interval N]` | Keep the kernel alive, restart on crash |
| `bot` | Run the Telegram bot in the foreground |
| `serve [--interval N]` | **Supervisor**: REST API + Telegram bot + watchdog in one process |

`crash start serve` is the intended long-running entry point for init
systems. It starts:

- the REST API when `api_enabled: true` in the config (loopback, optional
  token auth),
- the Telegram bot when fully configured,
- a kernel watchdog with the given interval.

## crash task

| Subcommand | Description |
|------------|-------------|
| `enable [--interval 24h]` | Enable scheduled subscription auto-update |
| `disable` | Disable scheduled updates |
| `list` | Show cron entries |
| `run-now` | Fetch subscriptions immediately |
| `geo [--repo owner/name] [--mirror URL]` | Update GeoIP/GeoSite databases |
| `rules` | Refresh external rule providers whose interval elapsed |

Geo data defaults to the
[`MetaCubeX/meta-rules-dat`](https://github.com/MetaCubeX/meta-rules-dat)
release; `--mirror` prefixes GitHub download URLs with a CDN proxy.

## crash engine

```
crash engine run  --flavor rust-mihomo|rust-sing-box [--config PATH] [--dir DIR]
crash engine test --flavor rust-mihomo|rust-sing-box [--config PATH]
crash engine version
```

The integrated Rust proxy engine (only in builds with the
`engine-mihomo` / `engine-singbox` cargo features). `run` executes the
engine in the foreground (used by the supervisor); `test` validates the
kernel config like `mihomo -t` and prints warnings; `version` prints the
engine version and which flavors the binary contains.

Select it as the managed kernel by setting `kernel: rust-mihomo` (or
`rust-sing-box`) in `config.yaml` — the same `configs/mihomo.yaml` /
`configs/sing-box.json` files the external kernels use, so switching
editions is a one-line change. `crash start start/stop/status/serve` and
the REST API treat the engine like any kernel: pid file, watchdog,
notifications, anti-loop gid.

## crash install

```
crash install [--kernel mihomo|sing-box] [--version vX.Y.Z] [--force]
```

Downloads the kernel from GitHub releases. When the release publishes a
`.dgst` or `.sha256` checksum sidecar, the archive hash is verified before
anything is installed — a mismatch aborts the installation.

## crash config

| Subcommand | Description |
|------------|-------------|
| `show` | Print the current config |
| `validate` | Validate config.yaml |
| `export` / `import <url> [--name N]` | Export for debugging / import a subscription |
| `list` / `select <index>` | Manage subscriptions |
| `generate` | Generate kernel config from the selected subscription |
| `edit` | Edit the config (runs vi; edit `<crashdir>/config.yaml` directly for other editors) |

## crash firewall

| Subcommand | Description |
|------------|-------------|
| `setup` | Apply transparent-proxy rules (see `--help` for TUN/IPv6/VM options) |
| `cleanup` | Remove all RustCrash firewall rules |
| `show` | Show backend availability |
| `apply` | Apply the config-driven full rule set |
| `generate` | Print the firewall script without applying |

## crash setboot

`enable` / `disable` / `status` — configure autostart through the detected
init system (systemd, OpenWrt init.d, or OpenRC).

## crash sub

Native (no external subconverter binary) subscription conversion between
formats: Clash, ClashR, sing-box, Quantumult(X), Loon, Surge, Surfboard,
Stash, V2Ray, SS/SSR/SSD, Trojan, Mixed, Mellow. Note: `surge&ver=2/3`
targets are accepted for subconverter URL compatibility but emit Surge 4
syntax (Surge 4 parses 2/3-era configs). Includes filtering (include/
exclude regex, rename rules, emoji, UDP capability filter, `--country`
country filter, max-link dedup, `--tolerance` url-test switching
tolerance), script-based filter/sort expressions, and preset sort
algorithms (`--sort-algorithm name|name-desc|server|port|protocol`).
See `crash sub --help` for the full option list.

## Exit codes and logging

Errors print to stderr and exit non-zero. The supervisor initializes
`tracing` logging from `config.yaml`'s `log_level` (the `RUST_LOG`
environment variable overrides it). Panics produce a crash report under
`<crashdir>/logs/crash-report-<timestamp>.md`.
