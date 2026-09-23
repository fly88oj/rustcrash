# Telegram Bot

Remote control and monitoring through a Telegram bot, mirroring ShellCrash's
`tg_bot`. The bot uses long polling (`getUpdates`, 25 s timeout), answers
with inline-keyboard menus, and only reacts to whitelisted chat IDs.

## Setup

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy its API
   token.
2. Add the configuration to `config.yaml`:

```yaml
tgbot_enable: true
tgbot_token: "123456:ABC-DEF…"     # or env RUSTCRASH_TGBOT_TOKEN
tgbot_chat_ids: [123456789]        # your chat id (comma list for several)
```

The token is a secret: keep it in the config file (mode 600) or pass it via
the `RUSTCRASH_TGBOT_TOKEN` environment variable. Never commit it.

3. Send any message to your bot, find your chat id in the bot log, or get it
   from `https://api.telegram.org/bot<TOKEN>/getUpdates`.
4. Run it:

```bash
crash start bot      # standalone
crash start serve    # or inside the supervisor (bot + API + watchdog)
```

## Commands

| Command | Action |
|---------|--------|
| `/crash` or `/start` | Show the status menu |
| `/help` | Help text |

## Inline menu

The status menu shows version, kernel name, running state, memory (VmRSS)
and uptime, then buttons:

| Button | callback | Action |
|--------|----------|--------|
| ▶ Enable Hijack | `start_redir` | Leave Pure mode: restore previous mode and firewall rules |
| ■ Pure Mode | `stop_redir` | Save current mode, switch to Pure, clean firewall |
| 🔄 Restart Kernel | `restart` | Restart the kernel process |
| 🌀 Update Subscriptions | `refresh` | Fetch all subscriptions now |
| 📝 Add Subscription | `set_sub` | Next text message is stored as a new subscription URL |
| 📄 Read Logs | `readlog` | Newest kernel log tail (64 KiB cap) sent as a document |
| 📁 File Transfer | `transport` | Submenu below |

### File transfer submenu

Download: logs, newest backup (`.tar.gz`), kernel config.
Upload: send a file while an upload button is armed — the next document
message is stored as the kernel binary (chmod 755), a backup archive, or
the kernel config. Filenames are sanitized to their final component (no
path traversal).

## Security

- **Chat-ID whitelist**: updates from chats not in `tgbot_chat_ids` are
  dropped silently.
- **Token validation**: tokens must match the Telegram format
  (`digits:alphanumerics`), preventing URL path injection into the API base.
- Pending-input state (`await_sub`, `await_upload:*`) persists in
  `/tmp/rustcrash/tgbot_state`; action logs go to
  `/tmp/rustcrash/tgbot.log` (rotated at 199 lines).

## Push notifications

Separately from the bot, `notifications:` channels and `notify_events:` in
`config.yaml` push events (start, sub_update, kernel_update, error, …) to
Telegram, Bark, PushDeer, Pushover, PushPlus, Gotify or SynoChat. See the
sample in `docs/CONFIGURATION.md`.
