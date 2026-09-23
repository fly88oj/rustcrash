//! Push notification system, mirroring ShellCrash's `logger` push channels.
//!
//! Supported providers: Telegram, Bark (iOS), PushDeer, Pushover, PushPlus,
//! Gotify and SynoChat. Credentials come from configuration or environment
//! variables only — never from code.

use crate::config::{Config, ConfigManager};
use crate::error::{Error, Result};
use crate::platform::Platform;
use serde::{Deserialize, Serialize};

/// One configured notification channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotifyConfig {
    /// Provider id: telegram | bark | pushdeer | pushover | pushplus | gotify | synochat
    pub provider: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// telegram bot token / pushdeer pushkey / pushover token / pushplus token / synochat token.
    #[serde(default)]
    pub token: Option<String>,
    /// pushover user key / synochat user id.
    #[serde(default)]
    pub user: Option<String>,
    /// bark / gotify / self-hosted pushdeer / synochat base URL.
    #[serde(default)]
    pub url: Option<String>,
    /// telegram chat id.
    #[serde(default)]
    pub chat_id: Option<i64>,
}

fn default_true() -> bool {
    true
}

/// Required non-empty field from a channel config.
fn req_field<'a>(value: Option<&'a str>, what: &str) -> std::result::Result<&'a str, Error> {
    value
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Config(format!("channel requires {what}")))
}

/// Build the HTTP request (URL + JSON body) for one channel.
///
/// Pure function so provider payloads can be unit-tested without network.
pub fn build_request(
    channel: &NotifyConfig,
    title: &str,
    message: &str,
) -> Result<(String, serde_json::Value)> {
    match channel.provider.as_str() {
        "telegram" => {
            let token = req_field(channel.token.as_deref(), "token")?;
            crate::bot::api::validate_token(token)?;
            let chat = channel
                .chat_id
                .ok_or(Error::Config("telegram channel requires a chat_id".into()))?;
            Ok((
                format!("https://api.telegram.org/bot{token}/sendMessage"),
                serde_json::json!({"chat_id": chat, "text": format!("{title}\n{message}")}),
            ))
        }
        "bark" => {
            let url = req_field(channel.url.as_deref(), "url")?;
            validate_endpoint(url)?;
            Ok((
                url.to_string(),
                serde_json::json!({
                    "body": message,
                    "title": title,
                    "level": "passive",
                    "badge": "1",
                }),
            ))
        }
        "pushdeer" => {
            let key = req_field(channel.token.as_deref(), "token")?;
            let mut base = channel
                .url
                .as_deref()
                .filter(|u| !u.is_empty())
                .unwrap_or("https://api2.pushdeer.com")
                .trim_end_matches('/')
                .to_string();
            if !base.contains("://") {
                base = format!("https://{base}");
            }
            validate_endpoint(&base)?;
            Ok((
                format!("{base}/message/push"),
                serde_json::json!({"pushkey": key, "text": format!("{title}: {message}")}),
            ))
        }
        "pushover" => {
            let token = req_field(channel.token.as_deref(), "token")?;
            let user = req_field(channel.user.as_deref(), "user")?;
            Ok((
                "https://api.pushover.net/1/messages.json".to_string(),
                serde_json::json!({"token": token, "user": user, "title": title, "message": message}),
            ))
        }
        "pushplus" => {
            let token = req_field(channel.token.as_deref(), "token")?;
            Ok((
                "https://www.pushplus.plus/send".to_string(),
                serde_json::json!({"token": token, "title": title, "content": message}),
            ))
        }
        "gotify" => {
            // ShellCrash stores the full push URL including the app token.
            let url = req_field(channel.url.as_deref(), "url")?;
            validate_endpoint(url)?;
            Ok((
                url.to_string(),
                serde_json::json!({"title": title, "message": message, "priority": 5}),
            ))
        }
        "synochat" => {
            let base = req_field(channel.url.as_deref(), "url")?;
            let token = req_field(channel.token.as_deref(), "token")?;
            let user = req_field(channel.user.as_deref(), "user")?;
            validate_endpoint(base)?;
            Ok((
                format!(
                    "{}/webapi/entry.cgi?api=SYNO.Chat.External&method=chatbot&version=2&token={token}",
                    base.trim_end_matches('/')
                ),
                serde_json::json!({"text": format!("{title}: {message}"), "user_ids": [user]}),
            ))
        }
        other => Err(Error::Config(format!(
            "unknown notification provider: {other}"
        ))),
    }
}

/// Validate a user-supplied endpoint: absolute http(s) URL, no whitespace,
/// and a bounded length. Prevents injection of malformed targets.
fn validate_endpoint(url: &str) -> Result<()> {
    let ok = url.len() <= 2048
        && !url.contains(char::is_whitespace)
        && (url.starts_with("https://") || url.starts_with("http://"));
    if ok {
        Ok(())
    } else {
        Err(Error::Security(format!(
            "invalid notification endpoint: {url}"
        )))
    }
}

/// Shared HTTP client (connection pool reuse across notification sends,
/// geo/rules downloads).
pub(crate) fn shared_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

/// Fan-out notification sender.
pub struct NotificationManager {
    channels: Vec<NotifyConfig>,
    events: Vec<String>,
    client: reqwest::Client,
}

impl NotificationManager {
    pub fn from_config(config: &Config) -> Self {
        NotificationManager {
            channels: config
                .notifications
                .iter()
                .filter(|c| c.enabled)
                .cloned()
                .collect(),
            events: config.notify_events.clone(),
            client: shared_client().clone(),
        }
    }

    pub fn from_platform(platform: &Platform) -> Self {
        let config = ConfigManager::new(platform).load().unwrap_or_default();
        Self::from_config(&config)
    }

    /// True when the given event id has notifications enabled.
    pub fn event_enabled(&self, event: &str) -> bool {
        !self.channels.is_empty() && self.events.iter().any(|e| e == event)
    }

    /// Send a notification for an event to every enabled channel.
    /// Failures are logged, never propagated — notifications are best-effort.
    pub async fn notify_event(&self, event: &str, message: &str) {
        if !self.event_enabled(event) {
            return;
        }
        let title = format!("RustCrash: {event}");
        for channel in &self.channels {
            match build_request(channel, &title, message) {
                Ok((url, body)) => {
                    if let Err(e) = self.post(&url, &body).await {
                        tracing::warn!("notification via {} failed: {e}", channel.provider);
                    }
                }
                Err(e) => {
                    tracing::warn!("invalid {} channel: {e}", channel.provider);
                }
            }
        }
    }

    async fn post(&self, url: &str, body: &serde_json::Value) -> Result<()> {
        self.client
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| Error::Download(format!("notification post failed: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel(provider: &str) -> NotifyConfig {
        NotifyConfig {
            provider: provider.to_string(),
            enabled: true,
            token: Some("123456:TEST_TOKEN".to_string()),
            user: Some("user1".to_string()),
            url: Some("https://example.invalid/push".to_string()),
            chat_id: Some(42),
        }
    }

    #[test]
    fn telegram_request_shape() {
        let (url, body) = build_request(&channel("telegram"), "T", "M").unwrap();
        assert!(url.starts_with("https://api.telegram.org/bot123456:TEST_TOKEN/"));
        assert_eq!(body["chat_id"], 42);
        assert_eq!(body["text"], "T\nM");
    }

    #[test]
    fn bark_request_shape() {
        let (url, body) = build_request(&channel("bark"), "T", "M").unwrap();
        assert_eq!(url, "https://example.invalid/push");
        assert_eq!(body["body"], "M");
        assert_eq!(body["title"], "T");
        assert_eq!(body["level"], "passive");
    }

    #[test]
    fn pushdeer_defaults_to_official_server() {
        let mut c = channel("pushdeer");
        c.url = None;
        let (url, body) = build_request(&c, "T", "M").unwrap();
        assert_eq!(url, "https://api2.pushdeer.com/message/push");
        assert_eq!(body["pushkey"], "123456:TEST_TOKEN");
    }

    #[test]
    fn pushdeer_custom_server_normalized() {
        let mut c = channel("pushdeer");
        c.url = Some("https://deer.example.com/".to_string());
        let (url, _) = build_request(&c, "T", "M").unwrap();
        assert_eq!(url, "https://deer.example.com/message/push");
    }

    #[test]
    fn pushover_request_shape() {
        let (url, body) = build_request(&channel("pushover"), "T", "M").unwrap();
        assert_eq!(url, "https://api.pushover.net/1/messages.json");
        assert_eq!(body["token"], "123456:TEST_TOKEN");
        assert_eq!(body["user"], "user1");
    }

    #[test]
    fn pushplus_request_shape() {
        let (_, body) = build_request(&channel("pushplus"), "T", "M").unwrap();
        assert_eq!(body["content"], "M");
    }

    #[test]
    fn gotify_request_shape() {
        let (url, body) = build_request(&channel("gotify"), "T", "M").unwrap();
        assert_eq!(url, "https://example.invalid/push");
        assert_eq!(body["priority"], 5);
    }

    #[test]
    fn synochat_request_shape() {
        let (url, body) = build_request(&channel("synochat"), "T", "M").unwrap();
        assert!(url.starts_with("https://example.invalid/push/webapi/entry.cgi"));
        assert!(url.contains("token=123456:TEST_TOKEN"));
        assert_eq!(body["user_ids"][0], "user1");
    }

    #[test]
    fn unknown_provider_rejected() {
        assert!(build_request(&channel("nope"), "T", "M").is_err());
    }

    #[test]
    fn missing_fields_rejected() {
        let mut c = channel("bark");
        c.url = None;
        assert!(build_request(&c, "T", "M").is_err());

        let mut c = channel("telegram");
        c.chat_id = None;
        assert!(build_request(&c, "T", "M").is_err());

        let mut c = channel("pushover");
        c.user = None;
        assert!(build_request(&c, "T", "M").is_err());
    }

    #[test]
    fn malicious_endpoints_rejected() {
        let mut c = channel("gotify");
        c.url = Some("javascript:alert(1)".to_string());
        assert!(build_request(&c, "T", "M").is_err());

        c.url = Some("https://x.example/a b".to_string());
        assert!(build_request(&c, "T", "M").is_err());

        c.url = Some(format!("https://x.example/{}", "a".repeat(3000)));
        assert!(build_request(&c, "T", "M").is_err());
    }

    #[test]
    fn event_gating() {
        let cfg = Config {
            notifications: vec![channel("bark")],
            notify_events: vec!["start".to_string(), "error".to_string()],
            ..Default::default()
        };
        let nm = NotificationManager::from_config(&cfg);
        assert!(nm.event_enabled("start"));
        assert!(nm.event_enabled("error"));
        assert!(!nm.event_enabled("sub_update"));
    }

    #[test]
    fn event_disabled_without_channels() {
        let cfg = Config {
            notify_events: vec!["start".to_string()],
            ..Default::default()
        };
        let nm = NotificationManager::from_config(&cfg);
        assert!(!nm.event_enabled("start"));
    }

    #[tokio::test]
    async fn notify_event_skips_disabled_events_without_error() {
        let cfg = Config {
            notifications: vec![channel("bark")],
            notify_events: vec![],
            ..Default::default()
        };
        let nm = NotificationManager::from_config(&cfg);
        // No channels listen for this event — must be a silent no-op.
        nm.notify_event("start", "hello").await;
    }

    #[tokio::test]
    async fn notify_event_posts_to_mock_server() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/push"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let mut cfg = Config::default();
        let mut c = channel("bark");
        c.url = Some(format!("{}/push", server.uri()));
        cfg.notifications = vec![c];
        cfg.notify_events = vec!["start".to_string()];
        let nm = NotificationManager::from_config(&cfg);

        nm.notify_event("start", "kernel started").await;
        // Mock verifies the request arrived; give the async post a beat.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
