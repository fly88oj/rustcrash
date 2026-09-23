//! Telegram Bot HTTP API layer.
//!
//! Thin async client for the subset of the Bot API RustCrash uses: long
//! polling updates, sending messages with inline keyboards, sending
//! documents, answering callbacks and registering bot commands.
//!
//! The trait is object-safe via boxed futures so the bot logic can be tested
//! against an in-memory mock without network access.

use crate::error::{Error, Result};
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;

pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// One entry from `getUpdates`.
#[derive(Debug, Clone, Deserialize)]
pub struct TgUpdate {
    pub update_id: u64,
    #[serde(default)]
    pub message: Option<TgMessage>,
    #[serde(default)]
    pub callback_query: Option<TgCallbackQuery>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TgMessage {
    #[serde(default)]
    pub message_id: i64,
    #[serde(default)]
    pub chat: TgChat,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub document: Option<TgDocument>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TgChat {
    #[serde(default)]
    pub id: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TgDocument {
    #[serde(default)]
    pub file_id: String,
    #[serde(default)]
    pub file_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TgCallbackQuery {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub message: Option<TgMessage>,
}

impl TgUpdate {
    /// Chat ID this update originated from, if any.
    pub fn chat_id(&self) -> Option<i64> {
        if let Some(m) = &self.message {
            return Some(m.chat.id);
        }
        if let Some(cq) = &self.callback_query {
            if let Some(m) = &cq.message {
                return Some(m.chat.id);
            }
        }
        None
    }

    /// Callback data for callback-query updates.
    pub fn callback_data(&self) -> Option<&str> {
        self.callback_query.as_ref()?.data.as_deref()
    }

    /// Text body for plain messages.
    pub fn text(&self) -> Option<&str> {
        self.message.as_ref()?.text.as_deref()
    }

    /// Attached document, if any.
    pub fn document(&self) -> Option<&TgDocument> {
        self.message.as_ref()?.document.as_ref()
    }
}

/// Object-safe async API surface used by the bot.
pub trait TgApi: Send + Sync {
    /// Long-poll for updates; must return only updates with id >= offset.
    fn get_updates(&self, offset: u64, timeout_secs: u64) -> BoxFut<Result<Vec<TgUpdate>>>;
    /// Send a text message, optionally with an inline keyboard.
    fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        keyboard: Option<serde_json::Value>,
    ) -> BoxFut<Result<()>>;
    /// Send a file as a Telegram document.
    fn send_document(&self, chat_id: i64, filename: &str, content: Vec<u8>) -> BoxFut<Result<()>>;
    /// Acknowledge a callback query (clears the loading state on the button).
    fn answer_callback(&self, callback_id: &str) -> BoxFut<Result<()>>;
    /// Register the bot command list shown by Telegram clients.
    fn set_my_commands(&self, commands: serde_json::Value) -> BoxFut<Result<()>>;
    /// Resolve a file_id to a downloadable URL path via `getFile`.
    fn get_file_path(&self, file_id: &str) -> BoxFut<Result<String>>;
    /// Download file content for a previously resolved path.
    fn download_file(&self, path: &str) -> BoxFut<Result<Vec<u8>>>;
}

/// Default Telegram API endpoint.
pub const TELEGRAM_API_BASE: &str = "https://api.telegram.org";

/// Validate a bot token: Telegram tokens are digits, a colon and
/// alphanumerics. Rejecting anything else keeps the token from being usable
/// to inject path segments into the API URL.
pub fn validate_token(token: &str) -> Result<()> {
    let valid = !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'-' || b == b'_')
        && token.contains(':');
    if valid {
        Ok(())
    } else {
        Err(Error::Security("invalid Telegram bot token format".into()))
    }
}

/// reqwest-backed implementation talking to the real Bot API.
pub struct HttpTgApi {
    client: reqwest::Client,
    base: String,
    token: String,
}

impl HttpTgApi {
    /// Create a client for `base` (override for tests/proxies) and `token`.
    pub fn new(base: &str, token: &str) -> Result<Self> {
        validate_token(token)?;
        Ok(HttpTgApi {
            client: reqwest::Client::builder()
                .build()
                .map_err(|e| Error::Download(format!("http client init failed: {e}")))?,
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }

    fn method_url(&self, method: &str) -> String {
        format!("{}/bot{}/{method}", self.base, self.token)
    }
}

/// POST `payload` to `method` and check the Telegram `ok` envelope.
/// Shared by every JSON call so error handling lives in one place.
async fn tg_call_json(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    payload: serde_json::Value,
) -> Result<serde_json::Value> {
    let resp = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| Error::Download(format!("{method} failed: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| Error::Download(format!("{method} decode failed: {e}")))?;
    if body["ok"].as_bool() != Some(true) {
        return Err(Error::Download(format!(
            "{method} error: {}",
            body["description"].as_str().unwrap_or("unknown")
        )));
    }
    Ok(body)
}

impl TgApi for HttpTgApi {
    fn get_updates(&self, offset: u64, timeout_secs: u64) -> BoxFut<Result<Vec<TgUpdate>>> {
        let url = self.method_url("getUpdates");
        let client = self.client.clone();
        let payload = serde_json::json!({ "timeout": timeout_secs, "offset": offset });
        Box::pin(async move {
            let body = tg_call_json(&client, &url, "getUpdates", payload).await?;
            let updates: Vec<TgUpdate> = serde_json::from_value(body["result"].clone())
                .map_err(|e| Error::Download(format!("getUpdates parse failed: {e}")))?;
            Ok(updates)
        })
    }

    fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        keyboard: Option<serde_json::Value>,
    ) -> BoxFut<Result<()>> {
        let url = self.method_url("sendMessage");
        let client = self.client.clone();
        let mut payload = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
        });
        if let Some(kb) = keyboard {
            payload["reply_markup"] = kb;
        }
        Box::pin(async move {
            tg_call_json(&client, &url, "sendMessage", payload).await?;
            Ok(())
        })
    }

    fn send_document(&self, chat_id: i64, filename: &str, content: Vec<u8>) -> BoxFut<Result<()>> {
        let url = self.method_url("sendDocument");
        let client = self.client.clone();
        let filename = filename.to_string();
        Box::pin(async move {
            let part = reqwest::multipart::Part::bytes(content).file_name(filename);
            let form = reqwest::multipart::Form::new()
                .text("chat_id", chat_id.to_string())
                .part("document", part);
            let resp = client
                .post(&url)
                .multipart(form)
                .send()
                .await
                .map_err(|e| Error::Download(format!("sendDocument failed: {e}")))?;
            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| Error::Download(format!("sendDocument decode failed: {e}")))?;
            if body["ok"].as_bool() != Some(true) {
                return Err(Error::Download(format!(
                    "sendDocument error: {}",
                    body["description"].as_str().unwrap_or("unknown")
                )));
            }
            Ok(())
        })
    }

    fn answer_callback(&self, callback_id: &str) -> BoxFut<Result<()>> {
        let url = self.method_url("answerCallbackQuery");
        let client = self.client.clone();
        let callback_id = callback_id.to_string();
        let payload = serde_json::json!({ "callback_query_id": callback_id });
        Box::pin(async move {
            tg_call_json(&client, &url, "answerCallbackQuery", payload).await?;
            Ok(())
        })
    }

    fn set_my_commands(&self, commands: serde_json::Value) -> BoxFut<Result<()>> {
        let url = self.method_url("setMyCommands");
        let client = self.client.clone();
        let payload = serde_json::json!({ "commands": commands });
        Box::pin(async move {
            tg_call_json(&client, &url, "setMyCommands", payload).await?;
            Ok(())
        })
    }

    fn get_file_path(&self, file_id: &str) -> BoxFut<Result<String>> {
        let url = self.method_url("getFile");
        let client = self.client.clone();
        let file_id = file_id.to_string();
        Box::pin(async move {
            let payload = serde_json::json!({ "file_id": file_id });
            let body = tg_call_json(&client, &url, "getFile", payload).await?;
            let path = body["result"]["file_path"]
                .as_str()
                .ok_or_else(|| Error::Download("getFile returned no file_path".into()))?;
            Ok(path.to_string())
        })
    }

    fn download_file(&self, path: &str) -> BoxFut<Result<Vec<u8>>> {
        let url = format!("{}/file/bot{}/{path}", self.base, self.token);
        let client = self.client.clone();
        Box::pin(async move {
            let bytes = client
                .get(&url)
                .send()
                .await
                .map_err(|e| Error::Download(format!("file download failed: {e}")))?
                .bytes()
                .await
                .map_err(|e| Error::Download(format!("file read failed: {e}")))?;
            Ok(bytes.to_vec())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_validation_accepts_typical_tokens() {
        assert!(validate_token("123456:ABC-DEF_gHIjklMNOpqrs").is_ok());
    }

    #[test]
    fn token_validation_rejects_bad_formats() {
        assert!(validate_token("").is_err());
        assert!(validate_token("no-colon").is_err());
        // Path traversal and query injection attempts must fail.
        assert!(validate_token("123:abc/../../evil").is_err());
        assert!(validate_token("123:abc?x=1").is_err());
        assert!(validate_token("123:abc#frag").is_err());
        assert!(validate_token("123:abc def").is_err());
    }

    #[test]
    fn update_accessors() {
        let raw = r#"{
            "update_id": 42,
            "message": {"message_id": 1, "chat": {"id": 777}, "text": "/crash"}
        }"#;
        let u: TgUpdate = serde_json::from_str(raw).unwrap();
        assert_eq!(u.chat_id(), Some(777));
        assert_eq!(u.text(), Some("/crash"));
        assert_eq!(u.callback_data(), None);

        let raw = r#"{
            "update_id": 43,
            "callback_query": {"id": "cq1", "data": "restart",
                "message": {"message_id": 2, "chat": {"id": 888}}}
        }"#;
        let u: TgUpdate = serde_json::from_str(raw).unwrap();
        assert_eq!(u.chat_id(), Some(888));
        assert_eq!(u.callback_data(), Some("restart"));
    }

    #[tokio::test]
    async fn http_api_get_updates_against_mock() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/bot123:abc/getUpdates"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true,
                    "result": [
                        {"update_id": 7, "message": {"chat": {"id": 1}, "text": "/crash"}}
                    ]
                })),
            )
            .mount(&server)
            .await;

        let api = HttpTgApi::new(&server.uri(), "123:abc").unwrap();
        let updates = api.get_updates(0, 0).await.unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].update_id, 7);
    }

    #[tokio::test]
    async fn http_api_send_message_against_mock() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/bot123:abc/sendMessage"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"ok": true, "result": {"message_id": 5}})),
            )
            .mount(&server)
            .await;

        let api = HttpTgApi::new(&server.uri(), "123:abc").unwrap();
        api.send_message(1, "hello", None).await.unwrap();
    }

    #[tokio::test]
    async fn http_api_rejects_invalid_token() {
        assert!(HttpTgApi::new("https://example.invalid", "bad token").is_err());
    }
}
