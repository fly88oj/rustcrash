//! Filters for subscription processing
//!
//! Provides node filtering, renaming, emoji handling, and sorting.

use super::script::{apply_sort_script, ScriptEvaluator};
use super::{ProxyNode, ProxyProtocol};
use regex::Regex;
use std::collections::HashMap;

/// Filter options for subscription processing
#[derive(Debug, Clone, Default)]
pub struct FilterOptions {
    /// Regex pattern to exclude matching nodes
    pub exclude: Option<Regex>,
    /// Regex pattern to include only matching nodes (takes precedence over exclude)
    pub include: Option<Regex>,
    /// Rename rules: vec of (from_pattern, toReplacement)
    pub rename_rules: Vec<(Regex, String)>,
    /// Remove emoji from node names
    pub remove_emoji: bool,
    /// Emoji addition rules: keyword -> emoji
    pub emoji_rules: HashMap<String, String>,
    /// Sort nodes by name
    pub sort: bool,
    /// Reverse sort order
    pub sort_reverse: bool,
    /// Append proxy type prefix like \[SS\], \[VMess\], etc.
    pub append_type: bool,
    /// Filter out unsupported node types (Unknown protocol)
    pub fdn: bool,
    /// Enable new name format (standardized name from properties)
    pub new_name: bool,
    /// Append server:port info to node name
    pub append_info: bool,
    /// JavaScript-like filter expression (e.g., "name.includes('US') && port > 1000")
    pub filter_script: Option<String>,
    /// JavaScript-like sort expression (e.g., "name.localeCompare(other.name)")
    pub sort_script: Option<String>,
    /// UDP capability filter: Some(true) keeps only UDP-capable nodes,
    /// Some(false) only UDP-incapable ones.
    pub udp_require: Option<bool>,
    /// Max nodes to keep per (server, port) pair — deduplicates mirror
    /// spam in subscriptions. None keeps everything.
    pub max_link: Option<usize>,
    /// Preset sort algorithm (applied when `sort` is true and no script).
    pub sort_algorithm: Option<SortAlgorithm>,
    /// Country filter: keep only nodes whose detected country matches any
    /// of these codes/aliases (case-insensitive), e.g. ["US","HK"].
    pub country_keep: Vec<String>,
}

/// Country markers: aliases (Chinese names, flags, English/codes) →
/// canonical code. Shared by the country filter and the script engine.
const COUNTRY_MARKERS: &[(&[&str], &str)] = &[
    (&["美国", "🇺🇸", "US", "USA", "United States"], "US"),
    (&["香港", "🇭🇰", "HK", "Hong Kong"], "HK"),
    (&["台湾", "🇹🇼", "TW", "Taiwan"], "TW"),
    (&["日本", "🇯🇵", "JP", "Japan"], "JP"),
    (&["韩国", "🇰🇷", "KR", "Korea", "South Korea"], "KR"),
    (&["新加坡", "🇸🇬", "SG", "Singapore"], "SG"),
    (&["英国", "🇬🇧", "UK", "GB", "United Kingdom"], "UK"),
    (&["德国", "🇩🇪", "DE", "Germany"], "DE"),
    (&["法国", "🇫🇷", "FR", "France"], "FR"),
    (&["加拿大", "🇨🇦", "CA", "Canada"], "CA"),
    (&["澳大利亚", "澳洲", "🇦🇺", "AU", "Australia"], "AU"),
    (&["荷兰", "🇳🇱", "NL", "Netherlands"], "NL"),
    (&["俄罗斯", "🇷🇺", "RU", "Russia"], "RU"),
    (&["印度", "🇮🇳", "IN", "India"], "IN"),
    (&["巴西", "🇧🇷", "BR", "Brazil"], "BR"),
];

/// Detect a node's country from its name → canonical code.
/// Short ASCII codes (US, HK, …) match whole tokens only — "US" must not
/// match "AUS-Sydney" — while CJK/flag/long aliases match by substring,
/// case-insensitively. Hot path (per node): allocation-free.
pub fn detect_country(name: &str) -> Option<&'static str> {
    for (aliases, code) in COUNTRY_MARKERS {
        for alias in *aliases {
            let is_ascii_short = alias.is_ascii() && alias.len() <= 3;
            let hit = if is_ascii_short {
                // Whole-token match, case-insensitive, no token Vec.
                split_tokens_ci(name).any(|tok| tok.eq_ignore_ascii_case(alias))
            } else if alias.is_ascii() {
                // Long ASCII alias ("United States"): case-insensitive
                // substring without a lowercase copy.
                ascii_contains_ci(name, alias)
            } else {
                // CJK / flag emoji: case is irrelevant.
                name.contains(alias)
            };
            if hit {
                return Some(code);
            }
        }
    }
    None
}

/// Token iterator mirroring `str::split(|c| !c.is_alphanumeric())`.
fn split_tokens_ci(name: &str) -> impl Iterator<Item = &str> {
    let mut rest = name;
    std::iter::from_fn(move || {
        let start = rest.find(|c: char| c.is_alphanumeric())?;
        let remainder = &rest[start..];
        let end = remainder
            .find(|c: char| !c.is_alphanumeric())
            .unwrap_or(remainder.len());
        let (tok, next) = remainder.split_at(end);
        rest = next;
        Some(tok)
    })
}

/// Case-insensitive ASCII substring search (no allocation).
fn ascii_contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// Preset sort algorithms for node ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortAlgorithm {
    /// Case-insensitive node name (default).
    Name,
    /// Reverse of [SortAlgorithm::Name].
    NameDesc,
    /// Server address, then port.
    Server,
    /// Numeric port.
    Port,
    /// Protocol family, then name.
    Protocol,
}

impl SortAlgorithm {
    // ShellCrash-parity API: returns Option, not FromStr's Result.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "name" | "default" => Some(SortAlgorithm::Name),
            "name-desc" | "namerev" => Some(SortAlgorithm::NameDesc),
            "server" => Some(SortAlgorithm::Server),
            "port" => Some(SortAlgorithm::Port),
            "protocol" => Some(SortAlgorithm::Protocol),
            _ => None,
        }
    }
}

/// Does this node support UDP forwarding? An explicit `udp` flag from the
/// URI wins; otherwise fall back to protocol defaults.
pub fn node_supports_udp(node: &ProxyNode) -> bool {
    if let Some(explicit) = node.extra.udp {
        return explicit;
    }
    match node.protocol {
        // Native or commonly UDP-capable protocols.
        ProxyProtocol::Trojan
        | ProxyProtocol::Hysteria2
        | ProxyProtocol::Tuic
        | ProxyProtocol::WireGuard
        | ProxyProtocol::Shadowsocks
        | ProxyProtocol::ShadowSocksR => true,
        // VMess/VLESS UDP depends on transport; default to false.
        ProxyProtocol::VMess | ProxyProtocol::VLESS | ProxyProtocol::Unknown => false,
    }
}

/// Apply filters to a list of proxy nodes
pub fn apply_filters(nodes: &[ProxyNode], options: &FilterOptions) -> Vec<ProxyNode> {
    let mut result: Vec<ProxyNode> = Vec::new();

    // Pre-compile filter_script for efficiency
    let mut filter_script_evaluator: Option<ScriptEvaluator> = None;
    if let Some(ref script) = options.filter_script {
        let mut evaluator = ScriptEvaluator::new();
        if evaluator.compile_filter(script).is_ok() {
            filter_script_evaluator = Some(evaluator);
        } else {
            tracing::warn!("filter_script compilation failed: {}, ignoring", script);
        }
    };

    // Country filter: keep only nodes whose country matches a wanted
    // code/alias (both sides go through the shared marker table, so
    // "japan" matches a node named "jp-tokyo"). Short codes never
    // substring-match — "us" must not keep "AUS-Sydney".
    // The want-side work is node-independent: hoist it out of the loop.
    let country_wants: Vec<(String, Option<&'static str>, bool)> = options
        .country_keep
        .iter()
        .map(|want| {
            let lower = want.to_lowercase();
            let code = detect_country(want);
            let is_short_code = lower.is_ascii() && lower.len() <= 3;
            (lower, code, is_short_code)
        })
        .collect();

    for mut node in nodes.iter().cloned() {
        // Apply FDN filter - skip unsupported node types (Unknown protocol)
        if options.fdn && node.protocol == ProxyProtocol::Unknown {
            continue;
        }

        // UDP capability filter
        if let Some(require_udp) = options.udp_require {
            if node_supports_udp(&node) != require_udp {
                continue;
            }
        }

        if !country_wants.is_empty() {
            let node_country = detect_country(&node.name);
            let code_hit = node_country
                .is_some_and(|nc| country_wants.iter().any(|(_, code, _)| Some(nc) == *code));
            // The lowercase copy is only needed when some want is a long
            // alias doing substring matching.
            let hit = code_hit
                || country_wants.iter().any(|(_, _, s)| !s) && {
                    let lower_name = node.name.to_lowercase();
                    country_wants.iter().any(|(want_lower, _, is_short)| {
                        !*is_short && lower_name.contains(want_lower.as_str())
                    })
                };
            if !hit {
                continue;
            }
        }

        // Apply filter_script if provided
        if let Some(ref evaluator) = filter_script_evaluator {
            if !evaluator.evaluate_filter(&node) {
                continue;
            }
        }

        // Apply include filter (keep only matching nodes)
        if let Some(ref include_re) = options.include {
            if !include_re.is_match(&node.name) {
                continue;
            }
        }

        // Apply exclude filter (skip matching nodes)
        if let Some(ref exclude_re) = options.exclude {
            if exclude_re.is_match(&node.name) {
                continue;
            }
        }

        // Apply rename rules
        if !options.rename_rules.is_empty()
            || options.remove_emoji
            || !options.emoji_rules.is_empty()
            || options.append_type
            || options.new_name
            || options.append_info
        {
            let mut name = node.name.clone();

            // Remove emoji first if enabled
            if options.remove_emoji {
                name = remove_emoji_from_string(&name);
            }

            // Apply new_name format (standardized name: server:port or protocol-based)
            if options.new_name {
                name = generate_new_name(&node);
            }

            // Apply rename rules
            for (ref pattern, ref replacement) in &options.rename_rules {
                name = pattern.replace_all(&name, replacement.as_str()).to_string();
            }

            // Add emoji based on rules
            if !options.emoji_rules.is_empty() {
                name = add_emoji_from_rules(&name, &options.emoji_rules);
            }

            // Append type prefix
            if options.append_type {
                name = format!("[{}] {}", protocol_prefix(&node.protocol), name);
            }

            // Append server:port info
            if options.append_info {
                name = format!("{} ({}:{})", name, node.server, node.port);
            }

            node.name = name;
        }

        result.push(node);
    }

    // Max-link dedup: keep at most N nodes per (server, port).
    if let Some(max_link) = options.max_link.filter(|m| *m > 0) {
        let mut counts: HashMap<(String, u16), usize> = HashMap::new();
        result.retain(|node| {
            let key = (node.server.clone(), node.port);
            let count = counts.entry(key).or_insert(0);
            *count += 1;
            *count <= max_link
        });
    }

    // Apply sorting
    if options.sort {
        if let Some(ref script) = options.sort_script {
            // Use sort_script if provided
            if let Err(e) = apply_sort_script(&mut result, script) {
                tracing::warn!(
                    "sort_script evaluation failed: {}, falling back to default sort",
                    e
                );
                // Fall back to default name sorting on error
                if options.sort_reverse {
                    result.sort_by_key(|a| std::cmp::Reverse(a.name.to_lowercase()));
                } else {
                    result.sort_by_key(|a| a.name.to_lowercase());
                }
            }
        } else {
            let reverse = options.sort_reverse;
            let algorithm = options.sort_algorithm.unwrap_or(if reverse {
                SortAlgorithm::NameDesc
            } else {
                SortAlgorithm::Name
            });
            match algorithm {
                SortAlgorithm::Name => {
                    result.sort_by_key(|a| a.name.to_lowercase());
                }
                SortAlgorithm::NameDesc => {
                    result.sort_by_key(|a| std::cmp::Reverse(a.name.to_lowercase()));
                }
                SortAlgorithm::Server => {
                    result.sort_by(|a, b| a.server.cmp(&b.server).then(a.port.cmp(&b.port)))
                }
                SortAlgorithm::Port => result.sort_by_key(|a| a.port),
                SortAlgorithm::Protocol => result.sort_by(|a, b| {
                    protocol_prefix(&a.protocol)
                        .cmp(protocol_prefix(&b.protocol))
                        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                }),
            }
        }
    }

    result
}

/// Parse filter options from strings
pub fn parse_filter_options(
    exclude: Option<&str>,
    include: Option<&str>,
    rename: Option<&str>,
    remove_emoji: bool,
    emoji_rules: Option<&str>,
    sort: bool,
) -> Result<FilterOptions, String> {
    let exclude = exclude
        .map(|s| Regex::new(s).map_err(|e| format!("Invalid exclude regex: {}", e)))
        .transpose()?;

    let include = include
        .map(|s| Regex::new(s).map_err(|e| format!("Invalid include regex: {}", e)))
        .transpose()?;

    let rename_rules = if let Some(r) = rename {
        parse_rename_rules(r)?
    } else {
        Vec::new()
    };

    let emoji_rules = if let Some(e) = emoji_rules {
        parse_emoji_rules(e)?
    } else {
        HashMap::new()
    };

    Ok(FilterOptions {
        exclude,
        include,
        rename_rules,
        remove_emoji,
        emoji_rules,
        sort,
        sort_reverse: false,
        append_type: false,
        fdn: false,
        new_name: false,
        append_info: false,
        filter_script: None,
        sort_script: None,
        udp_require: None,
        max_link: None,
        sort_algorithm: None,
        country_keep: Vec::new(),
    })
}

/// Parse rename rules from string format "pattern1->replacement1;pattern2->replacement2"
pub fn parse_rename_rules(input: &str) -> Result<Vec<(Regex, String)>, String> {
    let mut rules = Vec::new();
    for part in input.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((from, to)) = part.split_once("->") {
            let from = from.trim();
            let to = to.trim();
            if !from.is_empty() {
                rules.push((
                    Regex::new(from)
                        .map_err(|e| format!("Invalid rename regex '{}': {}", from, e))?,
                    to.to_string(),
                ));
            }
        }
    }
    Ok(rules)
}

/// Parse emoji rules from string format "keyword1->emoji1,keyword2->emoji2"
fn parse_emoji_rules(input: &str) -> Result<HashMap<String, String>, String> {
    let mut rules = HashMap::new();
    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((keyword, emoji)) = part.split_once("->") {
            let keyword = keyword.trim();
            let emoji = emoji.trim();
            if !keyword.is_empty() && !emoji.is_empty() {
                rules.insert(keyword.to_lowercase(), emoji.to_string());
            }
        }
    }
    Ok(rules)
}

/// Remove emoji characters from a string
fn remove_emoji_from_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        // Skip emoji characters (Unicode ranges for emoji)
        if !is_emoji_char(c) {
            result.push(c);
        }
    }
    result.trim().to_string()
}

/// Check if a character is an emoji
fn is_emoji_char(c: char) -> bool {
    // Emoji Unicode ranges (comprehensive)
    matches!(c as u32,
        // Emoticons
        0x1F600..=0x1F64F |
        // Miscellaneous symbols and pictographs
        0x1F300..=0x1F5FF |
        // Transport and map symbols
        0x1F680..=0x1F6FF |
        // Supplement emoticons
        0x1F900..=0x1F9FF |
        // Symbols & Pictographs Extended
        0x1FA00..=0x1FA6F |
        // Chess symbols, arrows, etc.
        0x2600..=0x26FF |
        // Dingbats
        0x2700..=0x27BF |
        // Flags
        0x1F1E6..=0x1F1FF |
        // Tag characters (used in flags)
        0xE0020..=0xE007F
    )
}

/// Add emoji to a node name based on keyword rules
fn add_emoji_from_rules(name: &str, rules: &HashMap<String, String>) -> String {
    let name_lower = name.to_lowercase();
    for (keyword, emoji) in rules {
        if name_lower.contains(keyword.as_str()) {
            return format!("{} {}", emoji, name);
        }
    }
    name.to_string()
}

/// Generate a new standardized name for a node
/// Format: "{Protocol} {server}:{port}" or similar based on subconverter behavior
fn generate_new_name(node: &ProxyNode) -> String {
    let prefix = protocol_prefix(&node.protocol);
    format!("{} {}:{}", prefix, node.server, node.port)
}

/// Common emoji rules for country codes
pub fn default_emoji_rules() -> HashMap<String, String> {
    HashMap::from([
        ("美国", "🇺🇸"),
        ("香港", "🇭🇰"),
        ("台湾", "🇹🇼"),
        ("日本", "🇯🇵"),
        ("韩国", "🇰🇷"),
        ("新加坡", "🇸🇬"),
        ("英国", "🇬🇧"),
        ("德国", "🇩🇪"),
        ("法国", "🇫🇷"),
        ("加拿大", "🇨🇦"),
        ("澳大利亚", "🇦🇺"),
        ("荷兰", "🇳🇱"),
        ("俄罗斯", "🇷🇺"),
        ("印度", "🇮🇳"),
        ("巴西", "🇧🇷"),
    ])
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// Filter nodes by protocol type
pub fn filter_by_protocol(nodes: &[ProxyNode], protocols: &[ProxyProtocol]) -> Vec<ProxyNode> {
    nodes
        .iter()
        .filter(|n| protocols.contains(&n.protocol))
        .cloned()
        .collect()
}

/// Get the short prefix string for a protocol type
pub fn protocol_prefix(protocol: &ProxyProtocol) -> &'static str {
    match protocol {
        ProxyProtocol::Shadowsocks => "SS",
        ProxyProtocol::ShadowSocksR => "SSR",
        ProxyProtocol::VMess => "VMess",
        ProxyProtocol::VLESS => "VLESS",
        ProxyProtocol::Trojan => "Trojan",
        ProxyProtocol::Hysteria2 => "Hy2",
        ProxyProtocol::Tuic => "TUIC",
        ProxyProtocol::WireGuard => "WG",
        ProxyProtocol::Unknown => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_node(name: &str, protocol: ProxyProtocol) -> ProxyNode {
        ProxyNode {
            name: name.to_string(),
            protocol,
            server: "example.com".to_string(),
            port: 443,
            extra: Default::default(),
        }
    }

    #[test]
    fn test_remove_emoji() {
        let name = "🇺🇸 美国节点 高速";
        let result = remove_emoji_from_string(name);
        assert_eq!(result, "美国节点 高速");
    }

    #[test]
    fn test_udp_filter_keeps_only_capable() {
        let mut nodes = vec![
            create_test_node("hy2", ProxyProtocol::Hysteria2),
            create_test_node("vmess", ProxyProtocol::VMess),
            create_test_node("trojan", ProxyProtocol::Trojan),
        ];
        nodes[1].extra.udp = Some(false);

        let opts = FilterOptions {
            udp_require: Some(true),
            ..Default::default()
        };
        let result = apply_filters(&nodes, &opts);
        let names: Vec<&str> = result.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["hy2", "trojan"]);
    }

    #[test]
    fn test_udp_filter_explicit_flag_overrides_default() {
        // VMess defaults to no UDP, but an explicit udp=1 wins.
        let mut nodes = vec![create_test_node("vm", ProxyProtocol::VMess)];
        nodes[0].extra.udp = Some(true);

        let opts = FilterOptions {
            udp_require: Some(true),
            ..Default::default()
        };
        assert_eq!(apply_filters(&nodes, &opts).len(), 1);

        // Trojan defaults to UDP, but an explicit udp=0 disables it.
        let mut nodes = vec![create_test_node("tj", ProxyProtocol::Trojan)];
        nodes[0].extra.udp = Some(false);
        assert_eq!(apply_filters(&nodes, &opts).len(), 0);
    }

    #[test]
    fn test_udp_filter_keeps_only_incapable() {
        let nodes = vec![
            create_test_node("hy2", ProxyProtocol::Hysteria2),
            create_test_node("vmess", ProxyProtocol::VMess),
        ];
        let opts = FilterOptions {
            udp_require: Some(false),
            ..Default::default()
        };
        let result = apply_filters(&nodes, &opts);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "vmess");
    }

    #[test]
    fn test_max_link_dedups_per_server_port() {
        let mut nodes: Vec<ProxyNode> = (0..5)
            .map(|i| {
                let mut n = create_test_node(&format!("a{i}"), ProxyProtocol::Trojan);
                n.server = "same.example.com".to_string();
                n.port = 443;
                n
            })
            .collect();
        nodes.push({
            let mut n = create_test_node("other", ProxyProtocol::Trojan);
            n.server = "other.example.com".to_string();
            n.port = 443;
            n
        });

        let opts = FilterOptions {
            max_link: Some(2),
            ..Default::default()
        };
        let result = apply_filters(&nodes, &opts);
        // 2 from the busy server + 1 from the other server.
        assert_eq!(result.len(), 3);
        assert!(result.iter().any(|n| n.name == "other"));
    }

    #[test]
    fn test_max_link_zero_or_none_keeps_all() {
        let nodes = vec![
            create_test_node("a", ProxyProtocol::Trojan),
            create_test_node("b", ProxyProtocol::Trojan),
            create_test_node("c", ProxyProtocol::Trojan),
        ];
        let mut opts = FilterOptions {
            max_link: Some(0),
            ..Default::default()
        };
        assert_eq!(apply_filters(&nodes, &opts).len(), 3);
        opts.max_link = None;
        assert_eq!(apply_filters(&nodes, &opts).len(), 3);
    }

    #[test]
    fn test_sort_algorithms() {
        let mut nodes = vec![
            create_test_node("b-node", ProxyProtocol::VMess),
            create_test_node("a-node", ProxyProtocol::Trojan),
        ];
        nodes[0].server = "z.example.com".into();
        nodes[0].port = 9999;
        nodes[1].server = "a.example.com".into();
        nodes[1].port = 80;

        let mut opts = FilterOptions {
            sort: true,
            sort_algorithm: Some(SortAlgorithm::Name),
            ..Default::default()
        };
        assert_eq!(apply_filters(&nodes, &opts)[0].name, "a-node");

        opts.sort_algorithm = Some(SortAlgorithm::NameDesc);
        assert_eq!(apply_filters(&nodes, &opts)[0].name, "b-node");

        opts.sort_algorithm = Some(SortAlgorithm::Server);
        assert_eq!(apply_filters(&nodes, &opts)[0].server, "a.example.com");

        opts.sort_algorithm = Some(SortAlgorithm::Port);
        assert_eq!(apply_filters(&nodes, &opts)[0].port, 80);

        opts.sort_algorithm = Some(SortAlgorithm::Protocol);
        // Trojan prefix sorts before VMess prefix.
        assert_eq!(apply_filters(&nodes, &opts)[0].name, "a-node");
    }

    #[test]
    fn test_sort_algorithm_parsing() {
        assert_eq!(SortAlgorithm::from_str("name"), Some(SortAlgorithm::Name));
        assert_eq!(
            SortAlgorithm::from_str("NAME-DESC"),
            Some(SortAlgorithm::NameDesc)
        );
        assert_eq!(
            SortAlgorithm::from_str("server"),
            Some(SortAlgorithm::Server)
        );
        assert_eq!(SortAlgorithm::from_str("bogus"), None);
    }

    #[test]
    fn country_detection_by_alias() {
        assert_eq!(detect_country("🇺🇸 美国 高速"), Some("US"));
        assert_eq!(detect_country("JP-Tokyo-01"), Some("JP"));
        assert_eq!(detect_country("香港 IEPL"), Some("HK"));
        assert_eq!(detect_country("Amsterdam"), None);
    }

    #[test]
    fn country_detection_no_substring_false_positives() {
        // Short codes match whole tokens only: "US" must not match
        // AUS/RUS/Linode-style names.
        assert_eq!(detect_country("AUS-Sydney"), None);
        assert_eq!(detect_country("RUS-1"), None);
        assert_eq!(detect_country("Linode"), None);
        assert_eq!(detect_country("Ukraine-Kyiv"), None);
        // But real tokens still match.
        assert_eq!(detect_country("US East"), Some("US"));
    }

    #[test]
    fn country_filter_no_false_positives() {
        let nodes = vec![
            create_test_node("AUS-Sydney", ProxyProtocol::Trojan),
            create_test_node("US East", ProxyProtocol::Trojan),
            create_test_node("RUS-Moscow", ProxyProtocol::Trojan),
        ];
        let opts = FilterOptions {
            country_keep: vec!["US".to_string()],
            ..Default::default()
        };
        let kept = apply_filters(&nodes, &opts);
        assert_eq!(
            kept.len(),
            1,
            "only US East should survive: {:?}",
            kept.iter().map(|n| &n.name).collect::<Vec<_>>()
        );
        assert_eq!(kept[0].name, "US East");
    }

    #[test]
    fn country_filter_keeps_matching_nodes() {
        let nodes = vec![
            create_test_node("US Node", ProxyProtocol::Trojan),
            create_test_node("香港 IEPL", ProxyProtocol::Trojan),
            create_test_node("Germany-1", ProxyProtocol::Trojan),
        ];
        let opts = FilterOptions {
            country_keep: vec!["US".to_string(), "HK".to_string()],
            ..Default::default()
        };
        let kept = apply_filters(&nodes, &opts);
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(|n| n.name != "Germany-1"));
    }

    #[test]
    fn country_filter_accepts_aliases_case_insensitively() {
        let nodes = vec![
            create_test_node("jp-tokyo fast", ProxyProtocol::Trojan),
            create_test_node("London", ProxyProtocol::Trojan),
        ];
        // "japan" matches by alias even though the node name only has "jp".
        let opts = FilterOptions {
            country_keep: vec!["JAPAN".to_string()],
            ..Default::default()
        };
        let kept = apply_filters(&nodes, &opts);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].name, "jp-tokyo fast");
    }

    #[test]
    fn test_remove_emoji_no_emoji() {
        let name = "美国节点 高速";
        let result = remove_emoji_from_string(name);
        assert_eq!(result, "美国节点 高速");
    }

    #[test]
    fn test_add_emoji_from_rules() {
        let mut rules = HashMap::new();
        rules.insert("美国".to_string(), "🇺🇸".to_string());
        rules.insert("日本".to_string(), "🇯🇵".to_string());

        let name = "美国高速节点";
        let result = add_emoji_from_rules(name, &rules);
        assert_eq!(result, "🇺🇸 美国高速节点");
    }

    #[test]
    fn test_add_emoji_no_match() {
        let mut rules = HashMap::new();
        rules.insert("美国".to_string(), "🇺🇸".to_string());

        let name = "日本节点";
        let result = add_emoji_from_rules(name, &rules);
        assert_eq!(result, "日本节点");
    }

    #[test]
    fn test_exclude_filter() {
        let nodes = vec![
            create_test_node("美国节点", ProxyProtocol::Trojan),
            create_test_node("日本节点", ProxyProtocol::Trojan),
            create_test_node("流量提醒", ProxyProtocol::Trojan),
        ];

        let options = FilterOptions {
            exclude: Some(Regex::new("流量").unwrap()),
            ..Default::default()
        };

        let result = apply_filters(&nodes, &options);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "美国节点");
        assert_eq!(result[1].name, "日本节点");
    }

    #[test]
    fn test_include_filter() {
        let nodes = vec![
            create_test_node("美国节点", ProxyProtocol::Trojan),
            create_test_node("日本节点", ProxyProtocol::Trojan),
            create_test_node("欧洲节点", ProxyProtocol::Trojan),
        ];

        let options = FilterOptions {
            include: Some(Regex::new("美国|日本").unwrap()),
            ..Default::default()
        };

        let result = apply_filters(&nodes, &options);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_include_takes_precedence_over_exclude() {
        let nodes = vec![
            create_test_node("美国节点", ProxyProtocol::Trojan),
            create_test_node("美国流量", ProxyProtocol::Trojan),
        ];

        let options = FilterOptions {
            include: Some(Regex::new("美国").unwrap()),
            exclude: Some(Regex::new("流量").unwrap()),
            ..Default::default()
        };

        let result = apply_filters(&nodes, &options);
        // Include takes precedence, so only nodes matching include are considered
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "美国节点");
    }

    #[test]
    fn test_rename_rules() {
        let nodes = vec![
            create_test_node("美国节点", ProxyProtocol::Trojan),
            create_test_node("日本节点", ProxyProtocol::Trojan),
        ];

        let rules = vec![(Regex::new("美国").unwrap(), "US".to_string())];
        let options = FilterOptions {
            rename_rules: rules,
            ..Default::default()
        };

        let result = apply_filters(&nodes, &options);
        assert_eq!(result[0].name, "US节点");
    }

    #[test]
    fn test_sort_nodes() {
        let nodes = vec![
            create_test_node("Zebra", ProxyProtocol::Trojan),
            create_test_node("Apple", ProxyProtocol::Trojan),
            create_test_node("Mango", ProxyProtocol::Trojan),
        ];

        let options = FilterOptions {
            sort: true,
            ..Default::default()
        };

        let result = apply_filters(&nodes, &options);
        assert_eq!(result[0].name, "Apple");
        assert_eq!(result[1].name, "Mango");
        assert_eq!(result[2].name, "Zebra");
    }

    #[test]
    fn test_sort_reverse() {
        let nodes = vec![
            create_test_node("Apple", ProxyProtocol::Trojan),
            create_test_node("Mango", ProxyProtocol::Trojan),
        ];

        let options = FilterOptions {
            sort: true,
            sort_reverse: true,
            ..Default::default()
        };

        let result = apply_filters(&nodes, &options);
        assert_eq!(result[0].name, "Mango");
        assert_eq!(result[1].name, "Apple");
    }

    #[test]
    fn test_parse_rename_rules() {
        let input = "美国->US;日本->JP;香港->HK";
        let rules = parse_rename_rules(input).unwrap();
        assert_eq!(rules.len(), 3);

        let test_str = "美国日本香港";
        let result = rules[0].0.replace_all(test_str, &rules[0].1);
        assert_eq!(result, "US日本香港");
    }

    #[test]
    fn test_parse_emoji_rules() {
        let input = "美国->🇺🇸,日本->🇯🇵,香港->🇭🇰";
        let rules = parse_emoji_rules(input).unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules.get("美国"), Some(&"🇺🇸".to_string()));
    }

    #[test]
    fn test_default_emoji_rules() {
        let rules = default_emoji_rules();
        assert!(!rules.is_empty());
        assert_eq!(rules.get("美国"), Some(&"🇺🇸".to_string()));
        assert_eq!(rules.get("香港"), Some(&"🇭🇰".to_string()));
    }

    #[test]
    fn test_filter_by_protocol() {
        let nodes = vec![
            create_test_node("SS节点", ProxyProtocol::Shadowsocks),
            create_test_node("VMess节点", ProxyProtocol::VMess),
            create_test_node("Trojan节点", ProxyProtocol::Trojan),
        ];

        let result =
            filter_by_protocol(&nodes, &[ProxyProtocol::Shadowsocks, ProxyProtocol::VMess]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_remove_emoji_comprehensive() {
        // Various emoji formats
        assert_eq!(remove_emoji_from_string("🎉 🎊 🎁"), "");
        assert_eq!(remove_emoji_from_string("🇺🇸美国节点"), "美国节点");
        assert_eq!(remove_emoji_from_string("test🎮game"), "testgame");
    }

    #[test]
    fn test_append_type() {
        let nodes = vec![
            create_test_node("节点1", ProxyProtocol::Shadowsocks),
            create_test_node("节点2", ProxyProtocol::VMess),
            create_test_node("节点3", ProxyProtocol::Trojan),
            create_test_node("节点4", ProxyProtocol::Hysteria2),
            create_test_node("节点5", ProxyProtocol::Tuic),
            create_test_node("节点6", ProxyProtocol::WireGuard),
            create_test_node("节点7", ProxyProtocol::VLESS),
            create_test_node("节点8", ProxyProtocol::ShadowSocksR),
        ];

        let options = FilterOptions {
            append_type: true,
            ..Default::default()
        };

        let result = apply_filters(&nodes, &options);
        assert_eq!(result.len(), 8);
        assert_eq!(result[0].name, "[SS] 节点1");
        assert_eq!(result[1].name, "[VMess] 节点2");
        assert_eq!(result[2].name, "[Trojan] 节点3");
        assert_eq!(result[3].name, "[Hy2] 节点4");
        assert_eq!(result[4].name, "[TUIC] 节点5");
        assert_eq!(result[5].name, "[WG] 节点6");
        assert_eq!(result[6].name, "[VLESS] 节点7");
        assert_eq!(result[7].name, "[SSR] 节点8");
    }

    #[test]
    fn test_fdn_filters_unknown() {
        let nodes = vec![
            create_test_node("正常节点", ProxyProtocol::Shadowsocks),
            create_test_node("未知节点", ProxyProtocol::Unknown),
            create_test_node("另一个正常节点", ProxyProtocol::VMess),
        ];

        // Without FDN - should keep all nodes
        let options_no_fdn = FilterOptions {
            fdn: false,
            ..Default::default()
        };
        let result = apply_filters(&nodes, &options_no_fdn);
        assert_eq!(result.len(), 3);

        // With FDN - should filter out Unknown protocol
        let options_with_fdn = FilterOptions {
            fdn: true,
            ..Default::default()
        };
        let result = apply_filters(&nodes, &options_with_fdn);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "正常节点");
        assert_eq!(result[1].name, "另一个正常节点");
    }

    #[test]
    fn test_protocol_prefix() {
        assert_eq!(protocol_prefix(&ProxyProtocol::Shadowsocks), "SS");
        assert_eq!(protocol_prefix(&ProxyProtocol::ShadowSocksR), "SSR");
        assert_eq!(protocol_prefix(&ProxyProtocol::VMess), "VMess");
        assert_eq!(protocol_prefix(&ProxyProtocol::VLESS), "VLESS");
        assert_eq!(protocol_prefix(&ProxyProtocol::Trojan), "Trojan");
        assert_eq!(protocol_prefix(&ProxyProtocol::Hysteria2), "Hy2");
        assert_eq!(protocol_prefix(&ProxyProtocol::Tuic), "TUIC");
        assert_eq!(protocol_prefix(&ProxyProtocol::WireGuard), "WG");
        assert_eq!(protocol_prefix(&ProxyProtocol::Unknown), "Unknown");
    }

    #[test]
    fn test_new_name_format() {
        let mut node = create_test_node("原始名称", ProxyProtocol::Shadowsocks);
        node.server = "example.com".to_string();
        node.port = 443;
        let nodes = vec![node];

        let options = FilterOptions {
            new_name: true,
            ..Default::default()
        };

        let result = apply_filters(&nodes, &options);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "SS example.com:443");
    }

    #[test]
    fn test_new_name_format_vmess() {
        let mut node = create_test_node("原始名称", ProxyProtocol::VMess);
        node.server = "vmess.example.com".to_string();
        node.port = 8080;
        let nodes = vec![node];

        let options = FilterOptions {
            new_name: true,
            ..Default::default()
        };

        let result = apply_filters(&nodes, &options);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "VMess vmess.example.com:8080");
    }

    #[test]
    fn test_append_info() {
        let mut node = create_test_node("节点名称", ProxyProtocol::Trojan);
        node.server = "trojan.example.com".to_string();
        node.port = 443;
        let nodes = vec![node];

        let options = FilterOptions {
            append_info: true,
            ..Default::default()
        };

        let result = apply_filters(&nodes, &options);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "节点名称 (trojan.example.com:443)");
    }

    #[test]
    fn test_append_info_with_new_name() {
        let mut node = create_test_node("原始名称", ProxyProtocol::Shadowsocks);
        node.server = "ss.example.com".to_string();
        node.port = 443;
        let nodes = vec![node];

        let options = FilterOptions {
            new_name: true,
            append_info: true,
            ..Default::default()
        };

        let result = apply_filters(&nodes, &options);
        assert_eq!(result.len(), 1);
        // new_name is applied first, then append_info appends to that result
        assert_eq!(result[0].name, "SS ss.example.com:443 (ss.example.com:443)");
    }

    #[test]
    fn test_append_info_with_append_type() {
        let mut node = create_test_node("节点名称", ProxyProtocol::VMess);
        node.server = "vmess.example.com".to_string();
        node.port = 8888;
        let nodes = vec![node];

        let options = FilterOptions {
            append_type: true,
            append_info: true,
            ..Default::default()
        };

        let result = apply_filters(&nodes, &options);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "[VMess] 节点名称 (vmess.example.com:8888)");
    }

    #[test]
    fn test_append_info_with_rename() {
        let mut node = create_test_node("美国节点", ProxyProtocol::Trojan);
        node.server = "us.example.com".to_string();
        node.port = 443;
        let nodes = vec![node];

        let rename_rules = vec![(Regex::new("美国").unwrap(), "US".to_string())];
        let options = FilterOptions {
            rename_rules,
            append_info: true,
            ..Default::default()
        };

        let result = apply_filters(&nodes, &options);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "US节点 (us.example.com:443)");
    }

    #[test]
    fn test_default_emoji_rules_no_duplicates() {
        let rules = default_emoji_rules();
        let keys: Vec<&String> = rules.keys().collect();
        let unique_keys: std::collections::HashSet<&String> = rules.keys().collect();

        assert_eq!(
            keys.len(),
            unique_keys.len(),
            "default_emoji_rules should not have duplicate keys"
        );
    }

    #[test]
    fn test_default_emoji_rules_contains_all_countries() {
        let rules = default_emoji_rules();

        let expected_countries = vec![
            "美国",
            "香港",
            "台湾",
            "日本",
            "韩国",
            "新加坡",
            "英国",
            "德国",
            "法国",
            "加拿大",
            "澳大利亚",
            "荷兰",
            "俄罗斯",
            "印度",
            "巴西",
        ];

        for country in expected_countries {
            assert!(
                rules.contains_key(country),
                "default_emoji_rules should contain '{}'",
                country
            );
        }
    }

    #[test]
    fn test_default_emoji_rules_correct_mapping() {
        let rules = default_emoji_rules();

        assert_eq!(rules.get("美国"), Some(&"🇺🇸".to_string()));
        assert_eq!(rules.get("香港"), Some(&"🇭🇰".to_string()));
        assert_eq!(rules.get("日本"), Some(&"🇯🇵".to_string()));
        assert_eq!(rules.get("英国"), Some(&"🇬🇧".to_string()));
    }
}
