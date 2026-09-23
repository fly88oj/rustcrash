# Configuration Reference

RustCrash keeps its state under the *crash directory* — `/etc/rustcrash`
by default, `/etc/ShellCrash` on OpenWrt, overridable with
`CRASHDIR`/`CRASH_DIR` environment variables or `crash -c <dir>`. The main
file is `<crashdir>/config.yaml`.

## Core

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `kernel` | string | `mihomo` | Active kernel: `mihomo` or `sing-box` |
| `kernel_version` | string | *(empty)* | Installed kernel version |
| `variant` | string | `Lite` | Rule template: Full, FullNoAds, Lite, LiteNoAds, Light, Nano |
| `mode` | string | `Router` | `Router`, `Local`, or `Pure` (no firewall hijack) |
| `dns_mode` | string | `FakeIp` | `FakeIp`, `RedirHost`, `Local` |
| `proxy_port` | u16 | 7890 | Mixed proxy port |
| `dns_port` | u16 | 7892 | DNS hijack port |
| `tun_port` | u16? | — | TUN mode port |
| `mixed_port` | u16? | 7890 | Explicit mixed port |
| `log_level` | string | `info` | `trace`/`debug`/`info`/`warn`/`error`; `RUST_LOG` overrides |
| `dashboard` / `dashboard_port` | bool/u16 | true/9090 | Kernel external controller (yacd etc.) |

## Subscriptions

```yaml
subscriptions:
  - name: sub1
    url: https://provider.example/sub?token=…
    updated_at: 1760000000     # set by the updater
auto_update: true
update_interval: 24h
selected_sub: 0
```

## Firewall (advanced)

| Field | Default | Description |
|-------|---------|-------------|
| `tun_enabled` | false | TUN mode (fwmark routing) |
| `ipv6_enabled` / `ipv6_redir` | false | IPv6 dual-stack hijack |
| `vm_ipv4` / `vm_redir` | — | VM/Docker subnet prerouting |
| `macfilter_type` | — | `whitelist`/`blacklist` + `macfilter_addrs` |
| `ip_filter` | — | Source IP filter |
| `cn_ip_route` | false | China IP direct routing |
| `quic_reject` | false | Reject QUIC (UDP 443) |
| `common_ports` | [] | Limit hijack to these ports |

## Telegram bot

| Field | Default | Description |
|-------|---------|-------------|
| `tgbot_enable` | false | Master switch |
| `tgbot_token` | — | Bot API token (env `RUSTCRASH_TGBOT_TOKEN` overrides) |
| `tgbot_chat_ids` | [] | Whitelisted chat IDs |
| `mode_before_pure` | `Router` | Mode restored by the bot's Enable Hijack |

See [BOT.md](BOT.md).

## REST API

| Field | Default | Description |
|-------|---------|-------------|
| `api_enabled` | false | Serve the management API |
| `api_port` | 9097 | Loopback bind port |
| `api_token` | — | Bearer-style token via `x-api-token` header (env `RUSTCRASH_API_TOKEN` overrides) |

See [API.md](API.md).

## Notifications

```yaml
notify_events: [start, error, sub_update, kernel_update]
notifications:
  - provider: bark            # telegram|bark|pushdeer|pushover|pushplus|gotify|synochat
    enabled: true
    url: https://api.day.app/<key>     # bark/gotify/synochat base URL
  - provider: pushover
    token: <api token>        # telegram token / pushdeer pushkey / pushplus token
    user: <user key>
  - provider: telegram
    token: <bot token>
    chat_id: 123456789
```

Event ids: `start`, `stop`, `restart`, `sub_update`, `kernel_update`,
`error`. Credentials are read from this file or environment variables only;
never hardcode them in scripts you share.

## Geo data

| Field | Default | Description |
|-------|---------|-------------|
| `geo_repo` | `MetaCubeX/meta-rules-dat` | Release source (`owner/name`) |
| `geo_mirror` | — | CDN prefix for GitHub download URLs |

Assets installed to `<crashdir>/bin/geodata`: `geosite*.dat`,
`country*.mmdb`, `geoip*.metadb`, `*.mrs`, `*.srs`.

## Rule providers

```yaml
rule_providers:
  - name: cn
    url: https://example.com/cn.mrs
    interval: 86400          # seconds; refresh cadence
```

Payloads land in `<crashdir>/configs/ruleset/`; last-update state lives in
`configs/ruleset/.state.json`.

## Directory layout

```
<crashdir>/
├── config.yaml          # this file
├── bin/                 # kernel binaries, bin/geodata/
├── configs/             # kernel configs, configs/ruleset/
├── run/                 # pid files, crash_start_time
├── logs/                # kernel logs, crash reports
├── data/
└── backup/              # .tar.gz backups
```
