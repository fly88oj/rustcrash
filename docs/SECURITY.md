# Security Policy

## Supported versions

Security fixes target the latest release line.

## Reporting a vulnerability

Please report vulnerabilities privately by opening a GitHub Security
Advisory ("Report a vulnerability" under the Security tab of the
repository). Do **not** open a public issue for security problems.

Include reproduction steps, affected versions, and impact assessment. You
will get an acknowledgement within a week.

## Security-relevant design decisions

RustCrash runs as root on routers — it must manage firewall rules and the
kernel process. The implementation follows these rules:

- **No shell, no string-built commands.** External processes are spawned
  with explicit argument vectors; signals are sent via `libc::kill`, not
  `/bin/kill`. Kernel and config paths are validated (absolute,
  canonicalized, regular file) before launch.
- **Secrets never live in source.** Bot tokens, API tokens and
  notification credentials are read from `config.yaml` or environment
  variables (`RUSTCRASH_TGBOT_TOKEN`, `RUSTCRASH_API_TOKEN`). Tests use
  placeholder values only. The REST API redacts secrets in responses.
- **Remote surfaces are opt-in and authenticated.** The REST API binds
  loopback only and supports token auth (constant-shape comparison).
  Request sizes are capped (64 KiB headers, 1 MiB body).
- **Telegram bot is whitelisted.** Updates from chats not in
  `tgbot_chat_ids` are dropped silently; tokens are format-validated to
  prevent URL path injection.
- **Downloads are verified.** Kernel archives whose release publishes a
  checksum sidecar are SHA-256-verified before installation. Geo/rule
  downloads reject empty payloads and write atomically (temp + rename);
  remote-supplied filenames are sanitized to their final component.
- **Repo/mirror identifiers are validated** before being interpolated
  into URLs (`owner/name` shape, endpoint scheme/length checks).
