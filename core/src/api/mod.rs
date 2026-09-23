//! Minimal REST API for remote management (Phase 11).
//!
//! Hand-rolled HTTP/1.1 server on tokio (project rule: minimal dependencies).
//! Binds loopback by default; optional token auth via the `x-api-token`
//! header. JSON in, JSON out.

use crate::config::{Config, ConfigManager};
use crate::error::{Error, Result};
use crate::geo::GeoUpdater;
use crate::platform::Platform;
use crate::service::ServiceManager;
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_LINES: usize = 100;

pub struct ApiServer {
    platform: Platform,
    token: Option<String>,
    /// Cached config + the config.yaml mtime it was parsed at (perf: the
    /// YAML parse was ~24µs on every request).
    config_cache: std::sync::Mutex<Option<(std::time::SystemTime, Config)>>,
}

/// A parsed HTTP request.
#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl ApiServer {
    pub fn new(platform: &Platform, token: Option<String>) -> Self {
        ApiServer {
            platform: platform.clone(),
            token: token.filter(|t| !t.is_empty()),
            config_cache: std::sync::Mutex::new(None),
        }
    }

    /// Config from the mtime cache; re-parses only when config.yaml
    /// changed (or after a POST /api/config, which rewrites the file).
    fn cached_config(&self) -> Config {
        let path = ConfigManager::new(&self.platform).config_path();
        let mtime = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        let mut cache = self.config_cache.lock().unwrap();
        if let Some((cached_at, ref cfg)) = *cache {
            if cached_at == mtime {
                return cfg.clone();
            }
        }
        let config = ConfigManager::new(&self.platform)
            .load()
            .unwrap_or_default();
        *cache = Some((mtime, config.clone()));
        config
    }

    /// Token from env first, then config; never hardcoded.
    pub fn token_from(platform: &Platform) -> Option<String> {
        std::env::var("RUSTCRASH_API_TOKEN")
            .ok()
            .filter(|t| !t.trim().is_empty())
            .or_else(|| {
                ConfigManager::new(platform)
                    .load()
                    .ok()
                    .and_then(|c| c.api_token.filter(|t| !t.trim().is_empty()))
            })
    }

    /// Bind and serve forever. Intended to run as a tokio task.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _peer) = listener
                .accept()
                .await
                .map_err(|e| Error::Process(format!("api accept failed: {e}")))?;
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.handle_connection(stream).await {
                    tracing::debug!("api connection error: {e}");
                }
            });
        }
    }

    async fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        let request = match read_request(&mut stream).await {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(()),
            Err(e) => {
                // Semantically correct statuses: unsupported body framing
                // → 411, oversized input → 413, everything else 400.
                let status = match &e {
                    Error::NotSupported(_) => 411,
                    Error::Config(msg) if msg.contains("too large") => 413,
                    _ => 400,
                };
                let _ = write_json(&mut stream, status, &json!({"error": e.to_string()})).await;
                return Ok(());
            }
        };

        let (status, body) = self.route(&request).await;
        write_json(&mut stream, status, &body).await
    }

    /// Route a request to a handler. Returns (HTTP status, JSON body).
    async fn route(&self, req: &Request) -> (u16, serde_json::Value) {
        if let Some(token) = &self.token {
            let provided = req.header("x-api-token").unwrap_or("");
            // Plain byte comparison; the loopback bind is the primary
            // protection, so no constant-time guarantee is claimed.
            if provided.len() != token.len()
                || !provided.bytes().zip(token.bytes()).all(|(a, b)| a == b)
            {
                return (401, json!({"error": "unauthorized"}));
            }
        }

        let path = req.path.split('?').next().unwrap_or("").to_string();

        // Cheap liveness probe first — no config load on the hot path.
        if req.method == "GET" && path == "/healthz" {
            return (200, json!({"status": "ok"}));
        }

        // Config with an mtime cache: the API server reads config.yaml on
        // every request otherwise (~24µs of YAML parsing each). Writes
        // through this server bump the mtime, so the cache self-invalidates.
        let config = self.cached_config();
        let kernel = config.active_kernel();
        let sm = ServiceManager::new(&self.platform);

        match (req.method.as_str(), path.as_str()) {
            ("GET", "/api/status") => {
                let st = sm.status(kernel);
                (
                    200,
                    json!({
                        "version": env!("CARGO_PKG_VERSION"),
                        "kernel": kernel.binary_name(),
                        "kernel_version": config.kernel_version,
                        "running": st.running,
                        "pid": st.pid,
                        "memory_mb": st.memory_mb,
                        "uptime_display": st.uptime_display(),
                        "mode": config.mode,
                    }),
                )
            }
            ("GET", "/api/config") => (200, json!(config.redacted())),
            ("POST", "/api/config") | ("PUT", "/api/config") => {
                match serde_json::from_slice::<Config>(&req.body) {
                    Ok(new_config) => {
                        let save_result = ConfigManager::new(&self.platform).save(&new_config);
                        // Save rewrites config.yaml → new mtime → the cache
                        // re-parses on the next read; drop it now so a
                        // same-mtime filesystem (coarse granularity)
                        // can't serve the stale copy.
                        self.config_cache.lock().unwrap().take();
                        match save_result {
                            Ok(()) => (200, json!({"status": "saved"})),
                            Err(e) => (500, json!({"error": e.to_string()})),
                        }
                    }
                    Err(e) => (400, json!({"error": format!("invalid config: {e}")})),
                }
            }
            ("POST", "/api/start") => match sm.start(kernel).await {
                Ok(pid) => (200, json!({"status": "started", "pid": pid})),
                Err(e) => (500, json!({"error": e.to_string()})),
            },
            ("POST", "/api/stop") => {
                // stop blocks (SIGTERM wait) — keep it off the async workers.
                let stopper = ServiceManager::new(&self.platform);
                match tokio::task::spawn_blocking(move || stopper.stop()).await {
                    Ok(Ok(())) => (200, json!({"status": "stopped"})),
                    Ok(Err(e)) => (500, json!({"error": e.to_string()})),
                    Err(e) => (500, json!({"error": e.to_string()})),
                }
            }
            ("POST", "/api/restart") => match sm.restart(kernel).await {
                Ok(pid) => (200, json!({"status": "restarted", "pid": pid})),
                Err(e) => (500, json!({"error": e.to_string()})),
            },
            ("GET", "/api/subscriptions") => {
                let subs: Vec<serde_json::Value> = config
                    .subscriptions
                    .iter()
                    .map(|s| {
                        json!({
                            "name": s.name,
                            // Subscription URLs routinely embed access tokens.
                            "url": redact_url(&s.url),
                            "updated_at": s.updated_at,
                        })
                    })
                    .collect();
                (200, json!({"subscriptions": subs}))
            }
            ("POST", "/api/subscriptions/refresh") => {
                let crash_dir = std::path::PathBuf::from(self.platform.crash_dir());
                // update_all builds its own runtime — keep it off async threads.
                match tokio::task::spawn_blocking(move || {
                    crate::task::subscription::SubscriptionUpdater::update_all(&crash_dir)
                })
                .await
                {
                    Ok(Ok(report)) => (
                        200,
                        json!({
                            "updated": report.updated,
                            "failed": report
                                .failed
                                .iter()
                                .map(|(n, e)| format!("{n}: {e}"))
                                .collect::<Vec<_>>(),
                        }),
                    ),
                    Ok(Err(e)) => (500, json!({"error": e.to_string()})),
                    Err(e) => (500, json!({"error": e.to_string()})),
                }
            }
            ("GET", "/api/logs") => {
                let lines = req
                    .path
                    .split_once('?')
                    .and_then(|(_, q)| q.split('&').find(|p| p.starts_with("lines=")))
                    .and_then(|p| p["lines=".len()..].parse::<usize>().ok())
                    .unwrap_or(DEFAULT_LINES);
                (200, json!({"logs": tail_log(&self.platform, lines)}))
            }
            ("POST", "/api/rules/update") => {
                match crate::rules::update_due_for(&self.platform).await {
                    Ok(report) => (
                        200,
                        json!({
                            "updated": report.updated,
                            "failed": report.failed,
                            "skipped": report.skipped,
                        }),
                    ),
                    Err(e) => (500, json!({"error": e.to_string()})),
                }
            }
            ("GET", "/api/rules") => {
                let mgr = crate::rules::RuleProviderManager::new(&self.platform);
                let providers: Vec<serde_json::Value> = config
                    .rule_providers
                    .iter()
                    .map(|p| {
                        json!({
                            "name": p.name,
                            "url": p.url,
                            "interval": p.interval,
                            "path": mgr.provider_path(p).display().to_string(),
                        })
                    })
                    .collect();
                (200, json!({"providers": providers}))
            }
            ("POST", "/api/geo/update") => {
                let geodata_dir =
                    std::path::PathBuf::from(format!("{}/bin/geodata", self.platform.crash_dir()));
                let repo = config.geo_repo.clone();
                let mirror = config.geo_mirror.clone();
                match GeoUpdater::new()
                    .update(&geodata_dir, &repo, mirror.as_deref())
                    .await
                {
                    Ok(report) => (
                        200,
                        json!({
                            "repo": report.repo,
                            "tag": report.tag,
                            "updated": report.updated,
                            "failed": report.failed,
                        }),
                    ),
                    Err(e) => (500, json!({"error": e.to_string()})),
                }
            }
            (m, p) => {
                if p.starts_with("/api/") {
                    (404, json!({"error": format!("no route for {m} {p}")}))
                } else {
                    (404, json!({"error": "not found"}))
                }
            }
        }
    }
}

/// Last `lines` lines of the newest kernel log (backward block read).
fn tail_log(platform: &Platform, lines: usize) -> Vec<String> {
    match crate::logging::newest_file(std::path::Path::new(&platform.log_dir()), |n| {
        n.ends_with(".log")
    }) {
        Some(path) => crate::logging::tail_file(&path, lines),
        None => Vec::new(),
    }
}

/// Read one HTTP request from the stream. Ok(None) on clean EOF.
async fn read_request(stream: &mut TcpStream) -> Result<Option<Request>> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    // Read until end of headers.
    let header_end = loop {
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(Error::Config("http headers too large".into()));
        }
        let n = stream.read(&mut chunk).await.map_err(Error::from)?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(Error::Config("connection closed mid-request".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_uppercase();
    let raw_path = parts.next().unwrap_or_default().to_string();
    let path = raw_path
        .split_once("://")
        .map(|(_, rest)| {
            rest.split_once('/')
                .map(|(_, r)| format!("/{r}"))
                .unwrap_or("/".into())
        })
        .unwrap_or(raw_path);

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    // Only Content-Length bodies are supported; fail fast (411) on
    // Transfer-Encoding instead of silently treating the body as empty.
    if method == "POST" || method == "PUT" {
        let has_length = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
        let chunked = headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
        });
        if chunked {
            return Err(Error::NotSupported(
                "chunked bodies not supported; send Content-Length".into(),
            ));
        }
        if !has_length {
            return Err(Error::NotSupported(
                "POST/PUT requires a Content-Length body".into(),
            ));
        }
    }

    let content_length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(Error::Config("http body too large".into()));
    }

    let mut body: Vec<u8> = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).await.map_err(Error::from)?;
        if n == 0 {
            return Err(Error::Config("connection closed mid-body".into()));
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);

    if method.is_empty() || path.is_empty() {
        return Err(Error::Config("malformed request line".into()));
    }
    Ok(Some(Request {
        method,
        path,
        headers,
        body,
    }))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Mask the query string of a URL (subscription links embed tokens);
/// keeps scheme/host/path visible for debugging.
fn redact_url(url: &str) -> String {
    match url.split_once('?') {
        Some((prefix, _)) => format!("{prefix}?…"),
        None => url.to_string(),
    }
}

async fn write_json(stream: &mut TcpStream, status: u16, body: &serde_json::Value) -> Result<()> {
    let payload = serde_json::to_string(body)
        .map_err(|e| Error::Config(format!("json encode failed: {e}")))?;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        411 => "Length Required",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(Error::from)?;
    stream.flush().await.map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn start_test_server(token: Option<String>) -> (u16, tempfile::TempDir) {
        let tmp = tempfile::TempDir::new().unwrap();
        let platform = Platform::for_crash_dir(tmp.path().to_str().unwrap());
        let server = Arc::new(ApiServer::new(&platform, token));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });
        (port, tmp)
    }

    async fn get(port: u16, path: &str, token: Option<&str>) -> (u16, serde_json::Value) {
        let mut req = reqwest::Client::new().get(format!("http://127.0.0.1:{port}{path}"));
        if let Some(t) = token {
            req = req.header("x-api-token", t);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap())
    }

    #[tokio::test]
    async fn healthz_responds() {
        let (port, _tmp) = start_test_server(None).await;
        let (status, body) = get(port, "/healthz", None).await;
        assert_eq!(status, 200);
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn status_reports_kernel_state() {
        let (port, _tmp) = start_test_server(None).await;
        let (status, body) = get(port, "/api/status", None).await;
        assert_eq!(status, 200);
        assert_eq!(body["kernel"], "mihomo");
        assert!(body["running"].is_boolean());
    }

    #[tokio::test]
    async fn unknown_api_route_is_404() {
        let (port, _tmp) = start_test_server(None).await;
        let (status, _) = get(port, "/api/nothing", None).await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn missing_token_is_401_when_configured() {
        let (port, _tmp) = start_test_server(Some("test-secret".into())).await;
        let (status, _) = get(port, "/api/status", None).await;
        assert_eq!(status, 401);
    }

    #[tokio::test]
    async fn wrong_token_is_401() {
        let (port, _tmp) = start_test_server(Some("test-secret".into())).await;
        let (status, _) = get(port, "/api/status", Some("wrong")).await;
        assert_eq!(status, 401);
    }

    #[tokio::test]
    async fn correct_token_passes() {
        let (port, _tmp) = start_test_server(Some("test-secret".into())).await;
        let (status, _) = get(port, "/api/status", Some("test-secret")).await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn config_roundtrip_and_redaction() {
        let (port, tmp) = start_test_server(None).await;
        // Seed a config with secrets.
        let platform = Platform::for_crash_dir(tmp.path().to_str().unwrap());
        let cm = ConfigManager::new(&platform);
        let cfg = Config {
            tgbot_token: Some("123456:SECRET".into()),
            api_token: Some("hunter2".into()),
            notifications: vec![crate::notify::NotifyConfig {
                provider: "bark".into(),
                enabled: true,
                token: Some("bark-secret".into()),
                user: None,
                url: Some("https://example.invalid/push".into()),
                chat_id: None,
            }],
            ..Default::default()
        };
        cm.save(&cfg).unwrap();

        let (status, body) = get(port, "/api/config", None).await;
        assert_eq!(status, 200);
        assert_eq!(body["tgbot_token"], "***");
        assert_eq!(body["api_token"], "***");
        assert_eq!(body["notifications"][0]["token"], "***");

        // POST a new config and verify it persisted.
        let mut new_cfg = cfg.clone();
        new_cfg.tgbot_token = None;
        new_cfg.proxy_port = 1234;
        let resp = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{port}/api/config"))
            .json(&new_cfg)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let reloaded = cm.load().unwrap();
        assert_eq!(reloaded.proxy_port, 1234);
    }

    #[tokio::test]
    async fn post_invalid_config_is_400() {
        let (port, _tmp) = start_test_server(None).await;
        let resp = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{port}/api/config"))
            .body("this is not json")
            .header("content-type", "application/json")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400);
    }

    #[tokio::test]
    async fn subscriptions_empty_by_default() {
        let (port, _tmp) = start_test_server(None).await;
        let (status, body) = get(port, "/api/subscriptions", None).await;
        assert_eq!(status, 200);
        assert_eq!(body["subscriptions"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn logs_empty_when_no_log_file() {
        let (port, _tmp) = start_test_server(None).await;
        let (status, body) = get(port, "/api/logs?lines=5", None).await;
        assert_eq!(status, 200);
        assert_eq!(body["logs"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn logs_returns_tail() {
        let tmp = tempfile::TempDir::new().unwrap();
        let platform = Platform::for_crash_dir(tmp.path().to_str().unwrap());
        std::fs::create_dir_all(platform.log_dir()).unwrap();
        std::fs::write(
            format!("{}/mihomo.log", platform.log_dir()),
            "l1\nl2\nl3\nl4\nl5\n",
        )
        .unwrap();
        let tail = tail_log(&platform, 3);
        assert_eq!(tail, vec!["l3", "l4", "l5"]);
    }

    #[test]
    fn subsequence_finder() {
        assert_eq!(find_subsequence(b"abc\r\n\r\nx", b"\r\n\r\n"), Some(3));
        assert_eq!(find_subsequence(b"abc", b"\r\n\r\n"), None);
    }

    #[test]
    fn redact_config_hides_all_secrets() {
        let cfg = Config {
            tgbot_token: Some("1:abc".into()),
            api_token: Some("secret".into()),
            notifications: vec![crate::notify::NotifyConfig {
                provider: "pushover".into(),
                enabled: true,
                token: Some("t".into()),
                user: Some("u".into()),
                url: None,
                chat_id: None,
            }],
            ..Default::default()
        };
        let v = serde_json::to_value(cfg.redacted()).unwrap();
        assert_eq!(v["tgbot_token"], "***");
        assert_eq!(v["api_token"], "***");
        assert_eq!(v["notifications"][0]["token"], "***");
        assert_eq!(v["notifications"][0]["user"], "***");
    }

    #[test]
    fn redacted_config_masks_subscription_url_queries() {
        let cfg = Config {
            subscriptions: vec![crate::config::Subscription {
                name: "s".into(),
                url: "https://example.com/sub?token=hunter2".into(),
                updated_at: None,
                raw_config: None,
            }],
            ..Default::default()
        };
        let v = serde_json::to_value(cfg.redacted()).unwrap();
        assert_eq!(v["subscriptions"][0]["url"], "https://example.com/sub?…");
    }
}
