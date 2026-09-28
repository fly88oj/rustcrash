//! Subscription management
//!
//! Provides subscription fetching and conversion functionality.
//! Uses native Rust implementation for URI parsing and format conversion.

use crate::error::{Error, Result};
use crate::subconverter::filters::{
    apply_filters, default_emoji_rules, parse_rename_rules, FilterOptions,
};
use crate::subconverter::formats::{convert_nodes, convert_nodes_with_options};
use crate::subconverter::merge::merge_nodes;
use crate::subconverter::uri::parse_uri_list;
use crate::subconverter::{ProxyNode, TargetFormat};
use base64::Engine;
use regex::Regex;
use std::io::Read;

/// Subscription info from remote
#[derive(Debug, Clone)]
pub struct SubscriptionInfo {
    pub content: String,
    pub format: SubscriptionFormat,
    pub backend: Option<String>,
}

/// Detected subscription format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionFormat {
    ClashYaml,
    SingBoxJson,
    UriList,
    Unknown,
}

/// Conversion options for subscription processing
/// Parameter names match subconverter API for compatibility
#[derive(Debug, Clone, Default)]
pub struct ConvertOptions {
    /// Target format (clash, clashr, surge&ver=4, quan, quanx, loon, v2ray, etc.)
    pub target: String,
    /// Subscription URL
    pub url: Option<String>,
    /// Group name (for SSD/SSR subscriptions)
    pub group: Option<String>,
    /// Regex pattern to exclude matching nodes
    pub exclude: Option<String>,
    /// Regex pattern to include only matching nodes
    pub include: Option<String>,
    /// Rename rules (format: pattern▶replacement or pattern->replacement)
    pub rename: Option<String>,
    /// Enable emoji in node names (true/false)
    pub emoji: Option<bool>,
    /// Add emoji prefix to node names (true/false)
    pub add_emoji: Option<bool>,
    /// Remove existing emoji from node names (true/false)
    pub remove_emoji: Option<bool>,
    /// Append proxy type prefix like \[SS\] (true/false)
    pub append_type: Option<bool>,
    /// Sort nodes by name (true/false)
    pub sort: Option<bool>,
    /// Enable TCP Fast Open (true/false)
    pub tfo: Option<bool>,
    /// Enable UDP support (true/false)
    pub udp: Option<bool>,
    /// Skip TLS certificate verification (true/false)
    pub scv: Option<bool>,
    /// Enable TLS 1.3 (true/false)
    pub tls13: Option<bool>,
    /// Insert nodes into existing config (true/false)
    pub insert: Option<bool>,
    /// Enable new name format (true/false)
    pub new_name: Option<bool>,
    /// Append server:port info to node name (true/false)
    pub append_info: Option<bool>,
    /// Filter out unsupported node types (true/false)
    pub fdn: Option<bool>,
    /// Expand rules into subscription (true/false)
    pub expand: Option<bool>,
    /// Generate Clash classical rule-provider (true/false)
    pub classic: Option<bool>,
    /// Output node list only (true/false)
    pub list: Option<bool>,
    /// Filename for the subscription file
    pub filename: Option<String>,
    /// JavaScript-like filter expression (e.g., "name.includes('US') && port > 1000")
    pub filter_script: Option<String>,
    /// JavaScript-like sort expression (e.g., "name.localeCompare(other.name)")
    pub sort_script: Option<String>,
    /// Keep only UDP-capable (or UDP-incapable) nodes
    pub udp_filter: Option<bool>,
    /// Max nodes per (server, port) pair
    pub max_link: Option<usize>,
    /// Preset sort algorithm: name|name-desc|server|port|protocol
    pub sort_algorithm: Option<String>,
    /// url-test group switching tolerance in milliseconds
    pub tolerance: Option<u32>,
    /// Country filter: keep only these countries (codes or aliases)
    pub country: Option<Vec<String>>,
}

impl ConvertOptions {
    /// Create options with target format
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            ..Default::default()
        }
    }

    /// Set the subscription URL
    pub fn url(mut self, url: &str) -> Self {
        self.url = Some(url.to_string());
        self
    }

    /// Set the group name
    pub fn group(mut self, name: &str) -> Self {
        self.group = Some(name.to_string());
        self
    }

    /// Set exclude regex
    pub fn exclude(mut self, pattern: &str) -> Self {
        self.exclude = Some(pattern.to_string());
        self
    }

    /// Set include regex
    pub fn include(mut self, pattern: &str) -> Self {
        self.include = Some(pattern.to_string());
        self
    }

    /// Set rename rules
    pub fn rename(mut self, rules: &str) -> Self {
        self.rename = Some(rules.to_string());
        self
    }

    /// Enable emoji
    pub fn emoji(mut self, yes: bool) -> Self {
        self.emoji = Some(yes);
        self
    }

    /// Enable add emoji prefix
    pub fn add_emoji(mut self, yes: bool) -> Self {
        self.add_emoji = Some(yes);
        self
    }

    /// Enable remove emoji
    pub fn remove_emoji(mut self, yes: bool) -> Self {
        self.remove_emoji = Some(yes);
        self
    }

    /// Enable append type prefix
    pub fn append_type(mut self, yes: bool) -> Self {
        self.append_type = Some(yes);
        self
    }

    /// Enable sorting
    pub fn sort(mut self, yes: bool) -> Self {
        self.sort = Some(yes);
        self
    }

    /// Enable TCP Fast Open
    pub fn tfo(mut self, yes: bool) -> Self {
        self.tfo = Some(yes);
        self
    }

    /// Enable UDP
    pub fn udp(mut self, yes: bool) -> Self {
        self.udp = Some(yes);
        self
    }

    /// Enable skip cert verify
    pub fn scv(mut self, yes: bool) -> Self {
        self.scv = Some(yes);
        self
    }

    /// Enable TLS 1.3
    pub fn tls13(mut self, yes: bool) -> Self {
        self.tls13 = Some(yes);
        self
    }

    /// Enable insert mode (add nodes to existing config)
    pub fn insert(mut self, yes: bool) -> Self {
        self.insert = Some(yes);
        self
    }

    /// Enable new name format
    pub fn new_name(mut self, yes: bool) -> Self {
        self.new_name = Some(yes);
        self
    }

    /// Enable append server:port info
    pub fn append_info(mut self, yes: bool) -> Self {
        self.append_info = Some(yes);
        self
    }

    /// Enable filter unsupported types
    pub fn fdn(mut self, yes: bool) -> Self {
        self.fdn = Some(yes);
        self
    }

    /// Enable expand rules
    pub fn expand(mut self, yes: bool) -> Self {
        self.expand = Some(yes);
        self
    }

    /// Enable classic rule-provider
    pub fn classic(mut self, yes: bool) -> Self {
        self.classic = Some(yes);
        self
    }

    /// Enable list output
    pub fn list(mut self, yes: bool) -> Self {
        self.list = Some(yes);
        self
    }

    /// Set filename
    pub fn filename(mut self, name: &str) -> Self {
        self.filename = Some(name.to_string());
        self
    }

    /// Parse from subconverter-style query string
    /// e.g., "target=clash&exclude=流量&sort=true&emoji=true"
    pub fn from_query(query: &str) -> std::result::Result<Self, String> {
        let mut opts = Self::default();

        for pair in query.split('&') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }

            if let Some((key, value)) = pair.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "target" => opts.target = value.to_string(),
                    "url" => {
                        opts.url = Some(urlencoding::decode(value).unwrap_or_default().to_string())
                    }
                    "group" => {
                        opts.group =
                            Some(urlencoding::decode(value).unwrap_or_default().to_string())
                    }
                    "exclude" => {
                        opts.exclude =
                            Some(urlencoding::decode(value).unwrap_or_default().to_string())
                    }
                    "include" => {
                        opts.include =
                            Some(urlencoding::decode(value).unwrap_or_default().to_string())
                    }
                    "rename" => {
                        opts.rename =
                            Some(urlencoding::decode(value).unwrap_or_default().to_string())
                    }
                    "emoji" => opts.emoji = Some(value == "true"),
                    "add_emoji" => opts.add_emoji = Some(value == "true"),
                    "remove_emoji" => opts.remove_emoji = Some(value == "true"),
                    "append_type" => opts.append_type = Some(value == "true"),
                    "sort" => opts.sort = Some(value == "true"),
                    "tfo" => opts.tfo = Some(value == "true"),
                    "udp" => opts.udp = Some(value == "true"),
                    "scv" => opts.scv = Some(value == "true"),
                    "tls13" => opts.tls13 = Some(value == "true"),
                    "insert" => opts.insert = Some(value == "true"),
                    "new_name" => opts.new_name = Some(value == "true"),
                    "append_info" => opts.append_info = Some(value == "true"),
                    "fdn" => opts.fdn = Some(value == "true"),
                    "expand" => opts.expand = Some(value == "true"),
                    "classic" => opts.classic = Some(value == "true"),
                    "list" => opts.list = Some(value == "true"),
                    "filename" => {
                        opts.filename =
                            Some(urlencoding::decode(value).unwrap_or_default().to_string())
                    }
                    "filter_script" => {
                        opts.filter_script =
                            Some(urlencoding::decode(value).unwrap_or_default().to_string())
                    }
                    "sort_script" => {
                        opts.sort_script =
                            Some(urlencoding::decode(value).unwrap_or_default().to_string())
                    }
                    _ => {}
                }
            }
        }

        if opts.target.is_empty() {
            return Err("target parameter is required".to_string());
        }

        Ok(opts)
    }

    /// Convert to subconverter-style query string
    pub fn to_query(&self) -> String {
        let mut parts = vec![format!("target={}", self.target)];

        if let Some(ref url) = self.url {
            parts.push(format!("url={}", urlencoding::encode(url)));
        }
        if let Some(ref group) = self.group {
            parts.push(format!("group={}", urlencoding::encode(group)));
        }
        if let Some(ref exclude) = self.exclude {
            parts.push(format!("exclude={}", urlencoding::encode(exclude)));
        }
        if let Some(ref include) = self.include {
            parts.push(format!("include={}", urlencoding::encode(include)));
        }
        if let Some(ref rename) = self.rename {
            parts.push(format!("rename={}", urlencoding::encode(rename)));
        }
        if let Some(emoji) = self.emoji {
            parts.push(format!("emoji={}", emoji));
        }
        if let Some(add_emoji) = self.add_emoji {
            parts.push(format!("add_emoji={}", add_emoji));
        }
        if let Some(remove_emoji) = self.remove_emoji {
            parts.push(format!("remove_emoji={}", remove_emoji));
        }
        if let Some(append_type) = self.append_type {
            parts.push(format!("append_type={}", append_type));
        }
        if let Some(sort) = self.sort {
            parts.push(format!("sort={}", sort));
        }
        if let Some(tfo) = self.tfo {
            parts.push(format!("tfo={}", tfo));
        }
        if let Some(udp) = self.udp {
            parts.push(format!("udp={}", udp));
        }
        if let Some(scv) = self.scv {
            parts.push(format!("scv={}", scv));
        }
        if let Some(tls13) = self.tls13 {
            parts.push(format!("tls13={}", tls13));
        }
        if let Some(insert) = self.insert {
            parts.push(format!("insert={}", insert));
        }
        if let Some(new_name) = self.new_name {
            parts.push(format!("new_name={}", new_name));
        }
        if let Some(append_info) = self.append_info {
            parts.push(format!("append_info={}", append_info));
        }
        if let Some(fdn) = self.fdn {
            parts.push(format!("fdn={}", fdn));
        }
        if let Some(expand) = self.expand {
            parts.push(format!("expand={}", expand));
        }
        if let Some(classic) = self.classic {
            parts.push(format!("classic={}", classic));
        }
        if let Some(list) = self.list {
            parts.push(format!("list={}", list));
        }
        if let Some(ref filename) = self.filename {
            parts.push(format!("filename={}", urlencoding::encode(filename)));
        }
        if let Some(ref filter_script) = self.filter_script {
            parts.push(format!(
                "filter_script={}",
                urlencoding::encode(filter_script)
            ));
        }
        if let Some(ref sort_script) = self.sort_script {
            parts.push(format!("sort_script={}", urlencoding::encode(sort_script)));
        }

        parts.join("&")
    }
}

/// Subscription manager for fetching and converting subscriptions
pub struct SubscriptionManager;

/// URL validation result with details
#[derive(Debug)]
pub struct UrlValidationResult {
    pub is_valid: bool,
    pub error_message: Option<String>,
    pub scheme: Option<String>,
    pub host: Option<String>,
}

impl SubscriptionManager {
    /// Validate subscription URL
    /// Checks for valid scheme (http/https), valid host, and reasonable length
    pub fn validate_url(url: &str) -> UrlValidationResult {
        let url = url.trim();

        if url.is_empty() {
            return UrlValidationResult {
                is_valid: false,
                error_message: Some("URL cannot be empty".to_string()),
                scheme: None,
                host: None,
            };
        }

        if url.len() > 4096 {
            return UrlValidationResult {
                is_valid: false,
                error_message: Some("URL exceeds maximum length of 4096 characters".to_string()),
                scheme: None,
                host: None,
            };
        }

        let (scheme, rest) = match url.split_once("://") {
            Some((scheme, rest)) => (scheme, rest),
            None => {
                return UrlValidationResult {
                    is_valid: false,
                    error_message: Some("URL must have a scheme (http:// or https://)".to_string()),
                    scheme: None,
                    host: None,
                };
            }
        };

        let scheme_lower = scheme.to_lowercase();
        if scheme_lower != "http" && scheme_lower != "https" {
            return UrlValidationResult {
                is_valid: false,
                error_message: Some(format!(
                    "Invalid scheme '{}'. Only http and https are supported",
                    scheme
                )),
                scheme: Some(scheme.to_string()),
                host: None,
            };
        }

        let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);

        if host.is_empty() {
            return UrlValidationResult {
                is_valid: false,
                error_message: Some("URL must have a valid host".to_string()),
                scheme: Some(scheme.to_string()),
                host: None,
            };
        }

        if host.len() > 253 {
            return UrlValidationResult {
                is_valid: false,
                error_message: Some(
                    "Hostname exceeds maximum length of 253 characters".to_string(),
                ),
                scheme: Some(scheme.to_string()),
                host: Some(host.to_string()),
            };
        }

        UrlValidationResult {
            is_valid: true,
            error_message: None,
            scheme: Some(scheme.to_string()),
            host: Some(host.to_string()),
        }
    }

    /// Fetch subscription from URL
    pub async fn fetch(url: &str) -> Result<SubscriptionInfo> {
        let validation = Self::validate_url(url);
        if !validation.is_valid {
            return Err(Error::Subscription(
                validation
                    .error_message
                    .unwrap_or_else(|| "Invalid URL".to_string()),
            ));
        }

        tracing::debug!(
            "Fetching subscription from {} (host: {:?})",
            url,
            validation.host.as_deref()
        );

        let client = reqwest::Client::builder()
            .user_agent("Mozilla/5.0 (compatible; RustCrash/1.0)")
            .timeout(std::time::Duration::from_secs(30))
            // Redirect chains (CDN hops, short-links) are followed, but
            // bounded — an airport redirect loop must terminate.
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .map_err(|e| Error::Subscription(e.to_string()))?;

        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Subscription(format!("Network error: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::Subscription(format!("HTTP {}", resp.status())));
        }

        let raw = resp
            .bytes()
            .await
            .map_err(|e| Error::Subscription(format!("Failed to read response: {e}")))?;

        let content = Self::decode_content(&Self::decode_body_bytes(&raw));
        if content.trim().is_empty() {
            return Err(Error::Subscription(format!(
                "Empty subscription body from {}",
                validation.host.as_deref().unwrap_or("server")
            )));
        }
        let format = Self::detect_format(&content);

        tracing::debug!(
            "Fetched subscription from {}, format: {:?}, content length: {}",
            validation.host.as_deref().unwrap_or("unknown"),
            format,
            content.len()
        );

        Ok(SubscriptionInfo {
            content,
            format,
            backend: None,
        })
    }

    /// Raw response body → text. Some providers force
    /// `Content-Encoding: gzip` regardless of `Accept-Encoding`; the
    /// client passes those bytes through untouched, so gunzip on the
    /// gzip magic before the (lossy) UTF-8 conversion — otherwise the
    /// whole subscription turns into replacement characters.
    fn decode_body_bytes(raw: &[u8]) -> String {
        if raw.starts_with(&[0x1f, 0x8b]) {
            if let Some(plain) = Self::decompress_gzip(raw)
                .ok()
                .and_then(|v| String::from_utf8(v).ok())
            {
                return plain;
            }
        }
        String::from_utf8_lossy(raw).into_owned()
    }

    fn decode_content(body: &str) -> String {
        let trimmed = body.trim();

        let decoded_looks_like_payload = |s: &str| {
            // Full configs (Clash/sing-box) or any proxy-URI list — the
            // base64-of-URI-list format airports serve most commonly.
            s.contains("proxies:")
                || s.contains("outbounds:")
                || Self::URI_SCHEMES.iter().any(|scheme| s.contains(scheme))
        };

        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
            if let Ok(s) = String::from_utf8(decoded.clone()) {
                if decoded_looks_like_payload(&s) {
                    return s;
                }
            }
            if let Ok(decompressed) = Self::decompress_gzip(&decoded) {
                if let Ok(s) = String::from_utf8(decompressed) {
                    if decoded_looks_like_payload(&s) {
                        return s;
                    }
                }
            }
        }

        trimmed.to_string()
    }

    fn decompress_gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut buffer = Vec::new();
        decoder.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    /// Detect subscription format
    pub fn detect_format(content: &str) -> SubscriptionFormat {
        let trimmed = content.trim();

        if trimmed.contains("proxies:")
            || trimmed.contains("proxy-groups:")
            || trimmed.contains("rules:")
        {
            return SubscriptionFormat::ClashYaml;
        }
        if trimmed.starts_with('{') && trimmed.contains("\"outbounds\"") {
            return SubscriptionFormat::SingBoxJson;
        }
        if Self::URI_SCHEMES
            .iter()
            .any(|s| trimmed.starts_with(s) || trimmed.contains(&format!("\n{s}")))
        {
            return SubscriptionFormat::UriList;
        }

        SubscriptionFormat::Unknown
    }

    /// Convert URIs to the specified target format (native implementation)
    pub fn convert(uris: &[String], target: &str, name: Option<&str>) -> Result<String> {
        let target_fmt = TargetFormat::from_str(target)
            .ok_or_else(|| Error::Subscription(format!("Unsupported target format: {}", target)))?;

        let nodes = parse_uri_list(&uris.join("\n"));
        if nodes.is_empty() {
            return Err(Error::Subscription(
                "No valid proxy nodes found".to_string(),
            ));
        }

        let mut output = convert_nodes(&nodes, target_fmt);

        // If a name is provided and target is Clash, rename the first proxy-group
        if let Some(n) = name {
            if target_fmt == TargetFormat::Clash {
                output = output.replace("  - name: Auto\n", &format!("  - name: {}\n", n));
            }
        }

        Ok(output)
    }

    /// Convert URIs to the specified target format with full options
    pub fn convert_with_options(uris: &[String], opts: &ConvertOptions) -> Result<String> {
        let target_fmt = TargetFormat::from_str(&opts.target).ok_or_else(|| {
            Error::Subscription(format!("Unsupported target format: {}", opts.target))
        })?;

        let nodes = parse_uri_list(&uris.join("\n"));
        if nodes.is_empty() {
            return Err(Error::Subscription(
                "No valid proxy nodes found".to_string(),
            ));
        }

        // Build filter options directly
        let exclude = opts.exclude.as_ref().and_then(|s| Regex::new(s).ok());
        let include = opts.include.as_ref().and_then(|s| Regex::new(s).ok());
        let rename_rules = opts
            .rename
            .as_ref()
            .and_then(|r| parse_rename_rules(r).ok())
            .unwrap_or_default();
        let emoji_rules = if opts.add_emoji.unwrap_or(false) {
            default_emoji_rules()
        } else {
            std::collections::HashMap::new()
        };
        let filter_opts = FilterOptions {
            exclude,
            include,
            rename_rules,
            remove_emoji: opts.remove_emoji.unwrap_or(false),
            emoji_rules,
            sort: opts.sort.unwrap_or(false),
            sort_reverse: false,
            append_type: opts.append_type.unwrap_or(false),
            fdn: opts.fdn.unwrap_or(false),
            new_name: opts.new_name.unwrap_or(false),
            append_info: opts.append_info.unwrap_or(false),
            filter_script: opts.filter_script.clone(),
            sort_script: opts.sort_script.clone(),
            udp_require: opts.udp_filter,
            country_keep: opts.country.clone().unwrap_or_default(),
            max_link: opts.max_link,
            sort_algorithm: opts
                .sort_algorithm
                .as_deref()
                .and_then(crate::subconverter::filters::SortAlgorithm::from_str),
        };

        // Apply filters
        let filtered_nodes = apply_filters(&nodes, &filter_opts);
        if filtered_nodes.is_empty() {
            return Err(Error::Subscription(
                "No nodes remaining after filtering".to_string(),
            ));
        }

        let mut output = convert_nodes_with_options(
            &filtered_nodes,
            target_fmt,
            opts.expand.unwrap_or(false),
            opts.classic.unwrap_or(false),
            opts.tolerance,
        );

        // If a group name is provided and target is Clash, rename the first proxy-group
        if let Some(ref group) = opts.group {
            if target_fmt == TargetFormat::Clash {
                output = output.replace("  - name: Auto\n", &format!("  - name: {}\n", group));
            }
        }

        Ok(output)
    }

    /// Fetch and convert a subscription URL to the specified format
    pub async fn fetch_and_convert(url: &str, opts: &ConvertOptions) -> Result<String> {
        let info = Self::fetch(url).await?;
        let uris = Self::extract_uris(&info.content, info.format);
        Self::convert_with_options(&uris, opts)
    }

    /// All supported URI schemes (used for extraction and format detection).
    pub const URI_SCHEMES: &[&str] = &[
        "vmess://",
        "ss://",
        "ssr://",
        "trojan://",
        "vless://",
        "hysteria2://",
        "hysteria://",
        "tuic://",
        "wireguard://",
    ];

    /// True when the line is a supported proxy URI.
    fn is_proxy_uri(line: &str) -> bool {
        Self::URI_SCHEMES.iter().any(|s| line.starts_with(s))
    }

    /// Extract URIs from subscription content based on format
    pub fn extract_uris(content: &str, format: SubscriptionFormat) -> Vec<String> {
        match format {
            SubscriptionFormat::UriList => content.lines().map(|s| s.to_string()).collect(),
            SubscriptionFormat::ClashYaml => Self::extract_uris_from_clash(content),
            SubscriptionFormat::SingBoxJson => Self::extract_uris_from_singbox(content),
            // Unknown content: keep whatever proxy-URI lines are present.
            SubscriptionFormat::Unknown => content
                .lines()
                .filter(|l| Self::is_proxy_uri(l.trim()))
                .map(|s| s.to_string())
                .collect(),
        }
    }

    /// Extract proxy URIs from Clash YAML content
    fn extract_uris_from_clash(content: &str) -> Vec<String> {
        let mut uris = Vec::new();
        let mut in_proxies = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed == "proxies:" {
                in_proxies = true;
                continue;
            }
            if in_proxies && trimmed.starts_with("proxy-groups:") {
                break;
            }
            if in_proxies && (trimmed.starts_with("- name:") || trimmed.starts_with("  - name:")) {
                // Found a proxy entry, extract what we can
                // For now, we'll skip full YAML parsing - the subscription content
                // should already be in URI format if it was a Clash subscription
            }
        }

        // If we couldn't parse YAML, try to find URI lines
        if uris.is_empty() {
            uris = content
                .lines()
                .filter(|l| l.contains("://"))
                .map(|s| s.trim().to_string())
                .collect();
        }

        uris
    }

    /// Extract proxy URIs from SingBox JSON content
    fn extract_uris_from_singbox(_content: &str) -> Vec<String> {
        // For SingBox JSON, we need to parse and reconstruct URIs
        // This is complex - for now, return empty and rely on raw content
        Vec::new()
    }

    /// Merge multiple URI lists into a single list in the specified target format
    pub fn merge(uris_lists: &[Vec<String>], target: &str) -> Result<String> {
        let target_fmt = TargetFormat::from_str(target)
            .ok_or_else(|| Error::Subscription(format!("Unsupported target format: {}", target)))?;

        let all_nodes: Vec<Vec<ProxyNode>> = uris_lists
            .iter()
            .map(|uris| parse_uri_list(&uris.join("\n")))
            .collect();

        let merge_result = merge_nodes(&all_nodes);
        if merge_result.nodes.is_empty() {
            return Err(Error::Subscription(
                "No valid proxy nodes found".to_string(),
            ));
        }

        let output = convert_nodes(&merge_result.nodes, target_fmt);
        Ok(output)
    }

    /// Maximum number of concurrent subscription fetches
    const MAX_CONCURRENT_FETCHES: usize = 5;

    /// Fetch multiple subscriptions concurrently with limited parallelism
    /// Returns a vector of (index, result) tuples
    pub async fn fetch_multiple(urls: &[String]) -> Vec<(usize, Result<SubscriptionInfo>)> {
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let semaphore = Arc::new(Semaphore::new(Self::MAX_CONCURRENT_FETCHES));
        let mut handles = Vec::with_capacity(urls.len());

        for (idx, url) in urls.iter().enumerate() {
            let url = url.clone();
            let semaphore = semaphore.clone();
            let permit = semaphore.acquire_owned().await.unwrap();

            let handle = tokio::spawn(async move {
                let result = Self::fetch(&url).await;
                drop(permit);
                (idx, result)
            });
            handles.push(handle);
        }

        let mut results = Vec::with_capacity(urls.len());
        for handle in handles {
            if let Ok(result) = handle.await {
                results.push(result);
            }
        }

        results.sort_by_key(|(idx, _)| *idx);
        results
    }

    /// Fetch multiple subscriptions and merge them
    pub async fn fetch_and_merge_multiple(urls: &[String], target: &str) -> Result<String> {
        let validation_errors: Vec<String> = urls
            .iter()
            .enumerate()
            .filter_map(|(idx, url)| {
                let result = Self::validate_url(url);
                if !result.is_valid {
                    Some(format!(
                        "URL {}: {}",
                        idx + 1,
                        result.error_message.unwrap_or_default()
                    ))
                } else {
                    None
                }
            })
            .collect();

        if !validation_errors.is_empty() {
            return Err(Error::Subscription(format!(
                "URL validation failed:\n{}",
                validation_errors.join("\n")
            )));
        }

        tracing::info!("Fetching {} subscriptions concurrently", urls.len());

        let results = Self::fetch_multiple(urls).await;

        let mut all_uris: Vec<String> = Vec::new();
        let mut fetch_errors: Vec<String> = Vec::new();

        for (idx, result) in results {
            match result {
                Ok(info) => {
                    let uris = Self::extract_uris(&info.content, info.format);
                    let count = uris.len();
                    all_uris.extend(uris);
                    tracing::debug!("Fetched {} URIs from subscription {}", count, idx + 1);
                }
                Err(e) => {
                    fetch_errors.push(format!("Subscription {}: {}", idx + 1, e));
                }
            }
        }

        if !fetch_errors.is_empty() {
            tracing::warn!(
                "Some subscriptions failed to fetch: {}",
                fetch_errors.join("; ")
            );
        }

        if all_uris.is_empty() {
            return Err(Error::Subscription(
                "No valid proxy nodes found from any source".to_string(),
            ));
        }

        tracing::info!(
            "Merged {} URIs from {} subscriptions",
            all_uris.len(),
            urls.len()
        );

        let target_fmt = TargetFormat::from_str(target)
            .ok_or_else(|| Error::Subscription(format!("Unsupported target format: {}", target)))?;

        let nodes = parse_uri_list(&all_uris.join("\n"));
        let output = convert_nodes(&nodes, target_fmt);

        Ok(output)
    }

    /// Convert URIs to Clash YAML format
    pub fn uris_to_clash(uris: &[String], name: &str) -> String {
        Self::convert(uris, "clash", Some(name)).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_format_clash() {
        let content = r#"
proxies:
  - name: test
    type: ss
    server: example.com
"#;
        assert_eq!(
            SubscriptionManager::detect_format(content),
            SubscriptionFormat::ClashYaml
        );
    }

    #[test]
    fn test_detect_format_singbox() {
        let content = r#"{"outbounds": []}"#;
        assert_eq!(
            SubscriptionManager::detect_format(content),
            SubscriptionFormat::SingBoxJson
        );
    }

    #[test]
    fn test_detect_format_uri_list() {
        assert_eq!(
            SubscriptionManager::detect_format("vmess://..."),
            SubscriptionFormat::UriList
        );
        assert_eq!(
            SubscriptionManager::detect_format("ss://..."),
            SubscriptionFormat::UriList
        );
        assert_eq!(
            SubscriptionManager::detect_format("trojan://..."),
            SubscriptionFormat::UriList
        );
    }

    #[test]
    fn test_detect_format_unknown() {
        assert_eq!(
            SubscriptionManager::detect_format("random content"),
            SubscriptionFormat::Unknown
        );
    }

    #[test]
    fn test_convert_to_clash() {
        let uris = vec!["trojan://pass@1.2.3.4:443#Node1".to_string()];
        let result = SubscriptionManager::convert(&uris, "clash", Some("Proxy")).unwrap();
        assert!(result.contains("proxy-groups:"));
        assert!(result.contains("name: Proxy"));
        assert!(result.contains("Node1"));
    }

    #[test]
    fn test_convert_to_singbox() {
        let uris = vec!["trojan://pass@1.2.3.4:443#Node1".to_string()];
        let result = SubscriptionManager::convert(&uris, "singbox", None).unwrap();
        assert!(result.contains("\"outbounds\""));
        assert!(result.contains("\"trojan\""));
    }

    #[test]
    fn test_merge() {
        let list1 = vec!["trojan://pass1@1.2.3.4:443#Node1".to_string()];
        let list2 = vec!["ss://YmFkYmFkYmQ6cGFzc3dvcmQxMjM=@192.168.1.1:8388#Node2".to_string()];

        let result = SubscriptionManager::merge(&[list1, list2], "clash").unwrap();
        assert!(result.contains("Node1"));
        assert!(result.contains("Node2"));
    }

    #[test]
    fn test_uris_to_clash_trojan_only() {
        let uris = vec!["trojan://pass@1.2.3.4:443#Node1".to_string()];
        let result = SubscriptionManager::uris_to_clash(&uris, "Proxy");
        assert!(result.contains("proxy-groups:"));
        assert!(result.contains("name: Proxy"));
        assert!(result.contains("Node1"));
    }

    #[test]
    fn test_decode_content_plain_text() {
        let content = "plain text content";
        let result = SubscriptionManager::decode_content(content);
        assert_eq!(result, content);
    }

    #[test]
    fn test_decode_content_with_base64_proxies() {
        // Base64 encoded Clash YAML
        let yaml = "cHJveGllczogW10="; // {"proxies": []}
        let result = SubscriptionManager::decode_content(yaml);
        assert!(result.contains("proxies"));
    }

    #[test]
    fn test_decode_content_with_base64_non_yaml() {
        // Base64 encoded non-YAML content should return original
        let content = "not base64 encoded yaml";
        let result = SubscriptionManager::decode_content(content);
        assert_eq!(result, content);
    }

    #[test]
    fn test_decode_content_with_gzip_base64() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let yaml = "proxies:\n  - name: test";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(yaml.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&compressed);

        let result = SubscriptionManager::decode_content(&b64);
        assert!(result.contains("proxies"));
    }

    #[test]
    fn test_decode_content_with_whitespace() {
        let content = "   proxies:\n  - name: test   ";
        let result = SubscriptionManager::decode_content(content);
        assert!(result.contains("proxies"));
    }

    #[test]
    fn test_convert_empty_uris_error() {
        let uris: Vec<String> = vec![];
        let result = SubscriptionManager::convert(&uris, "clash", None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No valid proxy nodes found"));
    }

    #[test]
    fn test_convert_invalid_format_error() {
        let uris = vec!["trojan://pass@1.2.3.4:443#Node1".to_string()];
        let result = SubscriptionManager::convert(&uris, "invalid_format", None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported target format"));
    }

    #[test]
    fn test_merge_empty_lists_error() {
        let empty_lists: Vec<Vec<String>> = vec![vec![]];
        let result = SubscriptionManager::merge(&empty_lists, "clash");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No valid proxy nodes found"));
    }

    #[test]
    fn test_merge_invalid_format_error() {
        let lists = vec![vec!["trojan://pass@1.2.3.4:443#Node1".to_string()]];
        let result = SubscriptionManager::merge(&lists, "invalid_format");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported target format"));
    }

    #[test]
    fn test_merge_multiple_lists() {
        let list1 = vec!["trojan://pass1@1.2.3.4:443#Node1".to_string()];
        let list2 = vec![
            "ss://YmFkYmFkYmQ6cGFzc3dvcmQxMjM=@192.168.1.1:8388#Node2".to_string(),
            "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjZCIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInRscyI6InRscyJ9".to_string(),
        ];

        let result = SubscriptionManager::merge(&[list1, list2], "singbox").unwrap();
        assert!(result.contains("\"outbounds\""));
    }

    #[test]
    fn test_convert_to_all_formats() {
        let uris = vec![
            "trojan://pass@1.2.3.4:443#Node1".to_string(),
            "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjZCIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInRscyI6InRscyJ9".to_string(),
        ];

        // Test all supported formats
        for format in &[
            "clash", "singbox", "quan", "quanx", "loon", "surge", "v2ray",
        ] {
            let result = SubscriptionManager::convert(&uris, format, None);
            assert!(result.is_ok(), "Format {} should work", format);
            assert!(!result.unwrap().is_empty());
        }
    }

    #[test]
    fn test_detect_format_with_singbox() {
        let content = r#"{"outbounds": [{"type": "trojan"}]}"#;
        assert_eq!(
            SubscriptionManager::detect_format(content),
            SubscriptionFormat::SingBoxJson
        );
    }

    #[test]
    fn test_detect_format_with_rules() {
        let content = "rules:\n  - DOMAIN,example.com,DIRECT";
        assert_eq!(
            SubscriptionManager::detect_format(content),
            SubscriptionFormat::ClashYaml
        );
    }

    #[test]
    fn test_convert_options_with_exclude() {
        let uris = vec![
            "trojan://pass@1.2.3.4:443#US-Node".to_string(),
            "trojan://pass@1.2.3.4:443#JP-Node".to_string(),
            "trojan://pass@1.2.3.4:443#流量提醒".to_string(),
        ];

        let opts = ConvertOptions::new("clash").exclude("流量");

        let result = SubscriptionManager::convert_with_options(&uris, &opts).unwrap();
        assert!(result.contains("US-Node"));
        assert!(result.contains("JP-Node"));
        assert!(!result.contains("流量提醒"));
    }

    #[test]
    fn test_convert_options_with_include() {
        let uris = vec![
            "trojan://pass@1.2.3.4:443#US-Node".to_string(),
            "trojan://pass@1.2.3.4:443#JP-Node".to_string(),
            "trojan://pass@1.2.3.4:443#HK-Node".to_string(),
        ];

        let opts = ConvertOptions::new("clash").include("(US|JP)");

        let result = SubscriptionManager::convert_with_options(&uris, &opts).unwrap();
        assert!(result.contains("US-Node"));
        assert!(result.contains("JP-Node"));
        assert!(!result.contains("HK-Node"));
    }

    #[test]
    fn test_convert_options_with_rename() {
        let uris = vec!["trojan://pass@1.2.3.4:443#US-Node".to_string()];

        let opts = ConvertOptions::new("clash").rename("US->美国");

        let result = SubscriptionManager::convert_with_options(&uris, &opts).unwrap();
        assert!(result.contains("美国-Node"));
    }

    #[test]
    fn test_convert_options_with_sort() {
        let uris = vec![
            "trojan://pass@1.2.3.4:443#Zebra".to_string(),
            "trojan://pass@1.2.3.4:443#Apple".to_string(),
            "trojan://pass@1.2.3.4:443#Mango".to_string(),
        ];

        let opts = ConvertOptions::new("clash").sort(true);

        let result = SubscriptionManager::convert_with_options(&uris, &opts).unwrap();
        // Check that Apple comes before Mango comes before Zebra
        let apple_pos = result.find("Apple").unwrap();
        let mango_pos = result.find("Mango").unwrap();
        let zebra_pos = result.find("Zebra").unwrap();
        assert!(apple_pos < mango_pos);
        assert!(mango_pos < zebra_pos);
    }

    #[test]
    fn test_convert_options_with_remove_emoji() {
        let uris = vec![
            "trojan://pass@1.2.3.4:443#🇺🇸 美国节点".to_string(),
            "trojan://pass@1.2.3.4:443#🇯🇵 日本节点".to_string(),
        ];

        let opts = ConvertOptions::new("clash").remove_emoji(true);

        let result = SubscriptionManager::convert_with_options(&uris, &opts).unwrap();
        assert!(result.contains("美国节点"));
        assert!(result.contains("日本节点"));
        assert!(!result.contains("🇺🇸"));
        assert!(!result.contains("🇯🇵"));
    }

    #[test]
    fn test_convert_options_empty_after_filter() {
        let uris = vec!["trojan://pass@1.2.3.4:443#US-Node".to_string()];

        let opts = ConvertOptions::new("clash").exclude(".*"); // Exclude all

        let result = SubscriptionManager::convert_with_options(&uris, &opts);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_options_unsupported_format() {
        let uris = vec!["trojan://pass@1.2.3.4:443#Node1".to_string()];

        let opts = ConvertOptions::new("unsupported_format");

        let result = SubscriptionManager::convert_with_options(&uris, &opts);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_options_to_query() {
        let opts = ConvertOptions::new("clash")
            .exclude("流量")
            .sort(true)
            .remove_emoji(true);

        let query = opts.to_query();
        assert!(query.contains("target=clash"));
        assert!(query.contains("exclude="));
        assert!(query.contains("sort=true"));
        assert!(query.contains("remove_emoji=true"));
    }

    #[test]
    fn test_convert_options_from_query() {
        let query = "target=clash&exclude=%E6%B5%81%E9%87%8F&sort=true&emoji=true";
        let opts = ConvertOptions::from_query(query).unwrap();

        assert_eq!(opts.target, "clash");
        assert_eq!(opts.exclude, Some("流量".to_string()));
        assert_eq!(opts.sort, Some(true));
        assert_eq!(opts.emoji, Some(true));
    }

    #[test]
    fn test_convert_options_with_add_emoji() {
        let uris = vec![
            "trojan://pass@1.2.3.4:443#美国节点".to_string(),
            "trojan://pass@5.6.7.8:443#日本节点".to_string(),
            "trojan://pass@9.10.11.12:443#香港节点".to_string(),
        ];

        // Enable add_emoji (should use default emoji rules)
        let opts = ConvertOptions::new("clash").add_emoji(true);

        let result = SubscriptionManager::convert_with_options(&uris, &opts).unwrap();
        // Default rules: 美国->🇺🇸, 日本->🇯🇵, 香港->🇭🇰
        assert!(result.contains("🇺🇸"), "Should have 🇺🇸 for 美国");
        assert!(result.contains("🇯🇵"), "Should have 🇯🇵 for 日本");
        assert!(result.contains("🇭🇰"), "Should have 🇭🇰 for 香港");
        assert!(
            result.contains("美国节点"),
            "Should contain original name after emoji"
        );
        assert!(
            result.contains("日本节点"),
            "Should contain original name after emoji"
        );
        assert!(
            result.contains("香港节点"),
            "Should contain original name after emoji"
        );
    }

    #[test]
    fn test_convert_options_with_expand() {
        let uris = vec!["trojan://pass@1.2.3.4:443#Node1".to_string()];

        let opts = ConvertOptions::new("clash").expand(true);

        let result = SubscriptionManager::convert_with_options(&uris, &opts).unwrap();
        // With expand=true, should have rules section
        assert!(result.contains("rules:"));
        assert!(result.contains("GEOIP,CN,DIRECT"));
        assert!(result.contains("MATCH,Auto"));
    }

    #[test]
    fn test_convert_options_with_classic() {
        let uris = vec!["trojan://pass@1.2.3.4:443#Node1".to_string()];

        let opts = ConvertOptions::new("clash").expand(true).classic(true);

        let result = SubscriptionManager::convert_with_options(&uris, &opts).unwrap();
        // With classic=true, should have inline rules without rule-providers
        assert!(result.contains("rules:"));
        assert!(!result.contains("rule-providers:"));
        assert!(result.contains("GEOIP,CN,DIRECT"));
    }

    #[test]
    fn test_convert_options_expand_false_no_rules() {
        let uris = vec!["trojan://pass@1.2.3.4:443#Node1".to_string()];

        let opts = ConvertOptions::new("clash").expand(false);

        let result = SubscriptionManager::convert_with_options(&uris, &opts).unwrap();
        // Without expand, should not have rules section
        assert!(!result.contains("rules:"));
        assert!(!result.contains("rule-providers:"));
    }

    #[test]
    fn test_validate_url_valid_https() {
        let result = SubscriptionManager::validate_url("https://example.com/sub");
        assert!(result.is_valid);
        assert!(result.error_message.is_none());
        assert_eq!(result.scheme, Some("https".to_string()));
        assert_eq!(result.host, Some("example.com".to_string()));
    }

    #[test]
    fn test_validate_url_valid_http() {
        let result = SubscriptionManager::validate_url("http://example.com/sub");
        assert!(result.is_valid);
        assert_eq!(result.scheme, Some("http".to_string()));
    }

    #[test]
    fn test_validate_url_with_port() {
        let result = SubscriptionManager::validate_url("https://example.com:8080/path");
        assert!(result.is_valid);
        assert_eq!(result.host, Some("example.com:8080".to_string()));
    }

    #[test]
    fn test_validate_url_with_path_and_query() {
        let result = SubscriptionManager::validate_url("https://example.com/path/to/sub?foo=bar");
        assert!(result.is_valid);
        assert_eq!(result.host, Some("example.com".to_string()));
    }

    #[test]
    fn test_validate_url_empty() {
        let result = SubscriptionManager::validate_url("");
        assert!(!result.is_valid);
        assert!(result.error_message.unwrap().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_url_whitespace_only() {
        let result = SubscriptionManager::validate_url("   ");
        assert!(!result.is_valid);
        assert!(result.error_message.unwrap().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_url_missing_scheme() {
        let result = SubscriptionManager::validate_url("example.com/sub");
        assert!(!result.is_valid);
        assert!(result.error_message.unwrap().contains("must have a scheme"));
    }

    #[test]
    fn test_validate_url_invalid_scheme() {
        let result = SubscriptionManager::validate_url("ftp://example.com/sub");
        assert!(!result.is_valid);
        assert!(result.error_message.unwrap().contains("Invalid scheme"));
    }

    #[test]
    fn test_validate_url_invalid_scheme_ftp() {
        let result = SubscriptionManager::validate_url("ftp://example.com/sub");
        assert!(!result.is_valid);
        assert!(result.error_message.unwrap().contains("ftp"));
    }

    #[test]
    fn test_validate_url_case_insensitive_scheme() {
        let result = SubscriptionManager::validate_url("HTTPS://example.com");
        assert!(result.is_valid);
        assert_eq!(result.scheme, Some("HTTPS".to_string()));
    }

    #[test]
    fn test_validate_url_too_long() {
        let long_path = "a".repeat(5000);
        let result =
            SubscriptionManager::validate_url(&format!("https://example.com/{}", long_path));
        assert!(!result.is_valid);
        assert!(result
            .error_message
            .unwrap()
            .contains("exceeds maximum length"));
    }

    #[test]
    fn test_validate_url_missing_host() {
        let result = SubscriptionManager::validate_url("https://");
        assert!(!result.is_valid);
        assert!(result.error_message.unwrap().contains("valid host"));
    }

    #[test]
    fn test_validate_url_hostname_too_long() {
        let long_host = "a".repeat(300);
        let result = SubscriptionManager::validate_url(&format!("https://{}.com", long_host));
        assert!(!result.is_valid);
        assert!(result
            .error_message
            .unwrap()
            .contains("Hostname exceeds maximum length"));
    }

    #[test]
    fn test_validate_url_ipv4() {
        let result = SubscriptionManager::validate_url("https://192.168.1.1/sub");
        assert!(result.is_valid);
        assert_eq!(result.host, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_validate_url_with_fragment() {
        let result = SubscriptionManager::validate_url("https://example.com#section");
        assert!(result.is_valid);
        assert_eq!(result.host, Some("example.com".to_string()));
    }

    // ==================================================================
    // HTTP fetch hardening — hermetic, raw wire-level HTTP/1.1 servers
    // on loopback (no external network, no new dev-dependencies).
    // ==================================================================

    mod http {
        use super::super::*;
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        /// Serve `responses` (raw HTTP/1.1 wire bytes, one per accepted
        /// connection, in order) on a fresh loopback port; returns the
        /// base URL. The listener closes when the list is exhausted.
        fn raw_server(responses: Vec<Vec<u8>>) -> String {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            std::thread::spawn(move || {
                for resp in responses {
                    let Ok((mut sock, _)) = listener.accept() else {
                        break;
                    };
                    // Drain the request head so our reply can't race the
                    // client's write (keep-alive + pipelining safety).
                    let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut buf = [0u8; 8192];
                    loop {
                        match sock.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = sock.write_all(&resp);
                    let _ = sock.flush();
                    let _ = sock.shutdown(std::net::Shutdown::Write);
                }
            });
            format!("http://{addr}")
        }

        fn plain_response(status_line: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
            let mut r = format!("{status_line}\r\nServer: wave17\r\nConnection: close\r\n").into_bytes();
            for (k, v) in headers {
                r.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
            }
            r.extend_from_slice(b"\r\n");
            r.extend_from_slice(body);
            r
        }

        /// `Transfer-Encoding: chunked` framing over arbitrary chunk
        /// boundaries — including boundaries that split a UTF-8
        /// sequence, which is legal on the wire.
        fn chunked_response(chunks: &[&[u8]]) -> Vec<u8> {
            let mut r =
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    .to_vec();
            for c in chunks {
                r.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
                r.extend_from_slice(c);
                r.extend_from_slice(b"\r\n");
            }
            r.extend_from_slice(b"0\r\n\r\n");
            r
        }

        fn redirect(status: u16, location: &str) -> Vec<u8> {
            plain_response(
                &format!("HTTP/1.1 {status} Moved"),
                &[("Location", location)],
                b"",
            )
        }

        const VMESS_URI: &str = "vmess://eyJ2IjoiMiIsInBzIjoiQ2h1bmtlZCIsImFkZCI6ImNodW5rLmV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjZCIsImFpZCI6IjAiLCJuZXQiOiJ0Y3AiLCJ0bHMiOiJub25lIn0=";

        /// Chunked transfer encoding with a boundary inside the base64
        /// payload and inside the UTF-8 node name — reassembly must be
        /// byte-exact or the node is garbage.
        #[tokio::test]
        async fn fetch_decodes_chunked_transfer_encoding() {
            let body = format!("{VMESS_URI}\ntrojan://pw@chunk.example.com:443#%E9%A6%99%E6%B8%AF\n");
            let bytes = body.as_bytes();
            // 1/3, 1/3, 1/3 — cuts mid-payload and mid-multibyte-name.
            let a = &bytes[..bytes.len() / 3];
            let b = &bytes[bytes.len() / 3..2 * bytes.len() / 3];
            let c = &bytes[2 * bytes.len() / 3..];
            let base = raw_server(vec![chunked_response(&[a, b, c])]);

            let info = SubscriptionManager::fetch(&format!("{base}/sub")).await.unwrap();
            assert_eq!(info.format, SubscriptionFormat::UriList);
            // decode_content trims surrounding whitespace — everything
            // else must be byte-exact.
            assert_eq!(
                info.content,
                body.trim_end(),
                "chunk reassembly must be byte-exact"
            );
            assert!(info.content.contains("chunk.example.com"));
        }

        /// A 100KB subscription across many chunks — no truncation.
        #[tokio::test]
        async fn fetch_large_chunked_subscription_no_truncation() {
            let mut body = String::with_capacity(200_000);
            let mut last_line = String::new();
            while body.len() < 100_000 {
                let line = format!(
                    "trojan://pw@big.example.com:{}/#big-{}\n",
                    body.len() % 60000 + 1024,
                    body.len()
                );
                last_line = line.trim_end().to_string();
                body.push_str(&line);
            }
            let expected = body.trim_end().to_string();
            let chunks: Vec<&[u8]> = body.as_bytes().chunks(7).collect();
            assert!(chunks.len() > 1000, "many chunks: {}", chunks.len());
            let base = raw_server(vec![chunked_response(&chunks)]);

            let info = SubscriptionManager::fetch(&format!("{base}/big")).await.unwrap();
            assert_eq!(info.content.len(), expected.len(), "payload truncated");
            // The FINAL chunk's node must have survived (tail truncation
            // check, since decode_content trims the trailing newline).
            assert!(
                info.content.contains(&last_line),
                "tail lost; last line was {last_line}"
            );
        }

        /// 3xx chains are followed, at most 3 hops; the final body wins.
        #[tokio::test]
        async fn fetch_follows_redirects_up_to_three_hops() {
            let base = raw_server(vec![
                redirect(301, "/hop1"),
                redirect(302, "/hop2"),
                redirect(307, "/final"),
                plain_response("HTTP/1.1 200 OK", &[], VMESS_URI.as_bytes()),
            ]);

            let info = SubscriptionManager::fetch(&format!("{base}/start")).await.unwrap();
            assert_eq!(info.format, SubscriptionFormat::UriList);
            assert!(info.content.starts_with("vmess://"));
            // The node inside the final body must actually parse.
            let uris = SubscriptionManager::extract_uris(&info.content, info.format);
            assert_eq!(uris.len(), 1);
        }

        /// Redirect chains longer than 3 hops are cut off with an error
        /// (loops must terminate).
        #[tokio::test]
        async fn fetch_rejects_redirect_chains_beyond_three_hops() {
            let base = raw_server(vec![
                redirect(302, "/loop1"),
                redirect(302, "/loop2"),
                redirect(302, "/loop3"),
                redirect(302, "/loop4"),
                plain_response("HTTP/1.1 200 OK", &[], b"never reached"),
            ]);

            let err = SubscriptionManager::fetch(&format!("{base}/start"))
                .await
                .unwrap_err();
            assert!(
                err.to_string().to_lowercase().contains("redirect"),
                "expected redirect error, got: {err}"
            );
        }

        /// Non-2xx statuses surface as errors carrying the status code.
        #[tokio::test]
        async fn fetch_non_200_status_is_an_error() {
            for status in ["503 Service Unavailable", "404 Not Found", "500 Internal Server Error"] {
                let base = raw_server(vec![plain_response(
                    &format!("HTTP/1.1 {status}"),
                    &[],
                    b"server exploded",
                )]);
                let err = SubscriptionManager::fetch(&format!("{base}/sub"))
                    .await
                    .unwrap_err();
                let msg = err.to_string();
                assert!(msg.contains("HTTP"), "missing status in: {msg}");
            }
        }

        /// 200 with an empty body is a dead airport link, not a valid
        /// empty subscription — must be an error, not an empty config.
        #[tokio::test]
        async fn fetch_empty_body_is_an_error() {
            for body in ["", "   ", "\r\n"] {
                let base = raw_server(vec![plain_response(
                    "HTTP/1.1 200 OK",
                    &[],
                    body.as_bytes(),
                )]);
                let err = SubscriptionManager::fetch(&format!("{base}/sub"))
                    .await
                    .unwrap_err();
                assert!(
                    err.to_string().contains("Empty subscription body"),
                    "got: {err}"
                );
            }
        }

        /// Providers that force `Content-Encoding: gzip` anyway: the
        /// body must be inflated before parsing (uses flate2, which is
        /// already a dependency — reqwest's gzip feature is not enabled).
        #[tokio::test]
        async fn fetch_gunzips_content_encoding_gzip() {
            use flate2::write::GzEncoder;
            use flate2::Compression;

            let payload = format!("{VMESS_URI}\n");
            let mut enc = GzEncoder::new(Vec::new(), Compression::default());
            enc.write_all(payload.as_bytes()).unwrap();
            let gz = enc.finish().unwrap();

            let base = raw_server(vec![plain_response(
                "HTTP/1.1 200 OK",
                &[("Content-Encoding", "gzip")],
                &gz,
            )]);

            let info = SubscriptionManager::fetch(&format!("{base}/gz")).await.unwrap();
            assert_eq!(info.content, payload.trim_end(), "gzip body was not inflated");
            assert_eq!(info.format, SubscriptionFormat::UriList);
        }

        /// Large plain Content-Length body (100KB) — no truncation.
        #[tokio::test]
        async fn fetch_large_content_length_body_no_truncation() {
            let mut body = String::with_capacity(200_000);
            let mut i = 0usize;
            while body.len() < 100_000 {
                body.push_str(&format!(
                    "trojan://pw{i}@cl.example.com:{}#cl-{i}\n",
                    i % 60000 + 1024
                ));
                i += 1;
            }
            let expected = body.clone();
            let base = raw_server(vec![plain_response(
                "HTTP/1.1 200 OK",
                &[("Content-Type", "text/plain")],
                expected.as_bytes(),
            )]);

            let info = SubscriptionManager::fetch(&format!("{base}/cl")).await.unwrap();
            assert_eq!(
                info.content.len(),
                expected.trim_end().len(),
                "payload truncated"
            );
        }
    }
}
