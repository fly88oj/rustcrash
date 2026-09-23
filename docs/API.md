# REST API Reference

Enabled with `api_enabled: true` in `config.yaml`. The server binds
`127.0.0.1` only — expose it remotely via an SSH tunnel or a reverse proxy,
never by opening the port.

```yaml
api_enabled: true
api_port: 9097        # default
api_token: "..."      # optional; env RUSTCRASH_API_TOKEN overrides
```

When a token is configured, every request must send the header
`x-api-token: <token>`; otherwise the server answers `401`.

## Endpoints

### GET /healthz

Liveness probe. → `{"status": "ok"}`

### GET /api/status

```json
{
  "version": "0.1.0",
  "kernel": "mihomo",
  "kernel_version": "1.19.0",
  "running": true,
  "pid": 1234,
  "memory_mb": 24.5,
  "uptime_display": "1d 2h 3m 4s",
  "mode": "Router"
}
```

### GET /api/config

Current `config.yaml` as JSON. Secrets are redacted to `"***"`:
`tgbot_token`, `api_token`, and every notification channel's
`token`/`user`.

### POST /api/config

Replace the configuration. Body: a full Config JSON (use the redacted GET
response as a template — redacted secrets are preserved on save? No:
**secrets you send are written verbatim; fetch-and-POST without restoring
real secrets will clear them**). Invalid JSON → `400`.

### POST /api/start | /api/stop | /api/restart

Kernel lifecycle. `{"status": "started", "pid": 1234}` on success,
`{"error": "…"}` with `500` on failure.

### GET /api/subscriptions

```json
{"subscriptions": [{"name": "sub1", "url": "https://…", "updated_at": 1760000000}]}
```

### POST /api/subscriptions/refresh

Fetch every configured subscription now. Returns updated/failed lists.

### GET /api/logs?lines=100

Tail of the newest kernel log. Reads backward in blocks, so large logs are
cheap.

### GET /api/rules

Configured rule providers with their stored file path and interval.

### POST /api/rules/update

Refresh rule providers whose interval has elapsed (concurrent, bounded).

### POST /api/geo/update

Update GeoIP/GeoSite databases from `geo_repo` (optionally through
`geo_mirror`). Returns the release tag and per-file results.

## Limits

Requests are capped at 64 KiB of headers and 1 MiB of body; larger inputs
are rejected. One request per connection (`Connection: close`).
