//! Subscription merge functionality
//!
//! Merges multiple subscription sources into a single output.

use super::formats::convert_nodes;
use super::uri::parse_uri;
use super::{ProxyNode, TargetFormat};
use std::collections::HashMap;

/// Merge results from multiple subscriptions
pub struct MergeResult {
    pub nodes: Vec<ProxyNode>,
    pub errors: Vec<String>,
}

impl MergeResult {
    /// Create a new empty merge result
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Get the number of successfully parsed nodes
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get the number of errors encountered
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }
}

impl Default for MergeResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Assign a config-safe unique name to a node.
///
/// Collisions are resolved by suffixing — the same contract as mihomo's
/// `uniqueName` (common/convert/converter.go), which keeps the first
/// node's name verbatim and renames later duplicates (`mihomo` appends
/// `-02`, `-03`, ...; we append ` (1)`, ` (2)`, ...). Unlike mihomo we
/// also register the RENAMED form, so a later node literally named
/// "Node (1)" cannot silently collide with a renamed duplicate.
fn assign_unique_name(raw: &str, seen: &mut HashMap<String, usize>) -> String {
    let base = sanitize_name(raw);
    // How many earlier nodes already used this base name.
    let mut suffix = *seen.get(&base).unwrap_or(&0);
    let mut name = if suffix == 0 {
        base.clone()
    } else {
        format!("{base} ({suffix})")
    };
    // A pre-existing node may literally own this exact form (renamed or
    // not) — keep bumping until the name is genuinely free.
    while seen.contains_key(&name) {
        suffix += 1;
        name = format!("{base} ({suffix})");
    }
    let renamed = name != base;
    seen.insert(base, suffix + 1);
    if renamed {
        seen.insert(name.clone(), 0);
    }
    name
}

/// Merge URIs from multiple sources
///
/// Takes a list of URIs (which may be individual proxy URIs or subscription URLs)
/// and merges them into a single list of ProxyNodes.
pub fn merge_uris(uris: &[String]) -> MergeResult {
    let mut result = MergeResult::new();
    let mut seen_names: HashMap<String, usize> = HashMap::new();

    for uri in uris {
        let uri = uri.trim();
        if uri.is_empty() {
            continue;
        }

        // Skip comments
        if uri.starts_with('#') {
            continue;
        }

        // Try to parse as a single URI
        if let Some(mut node) = parse_uri(uri) {
            node.name = assign_unique_name(&node.name, &mut seen_names);
            result.nodes.push(node);
        } else if uri.starts_with("http://") || uri.starts_with("https://") {
            // This is a subscription URL, we can't fetch it synchronously
            // In a real implementation, we would fetch and parse it
            result.errors.push(format!(
                "Skipping subscription URL (use SubscriptionManager::fetch first): {}",
                uri
            ));
        } else {
            result.errors.push(format!("Failed to parse URI: {}", uri));
        }
    }

    result
}

/// Merge already-parsed ProxyNodes from multiple sources
pub fn merge_nodes(node_lists: &[Vec<ProxyNode>]) -> MergeResult {
    let mut result = MergeResult::new();
    let mut seen_names: HashMap<String, usize> = HashMap::new();

    for nodes in node_lists {
        for mut node in nodes.clone() {
            node.name = assign_unique_name(&node.name, &mut seen_names);
            result.nodes.push(node);
        }
    }

    result
}

/// Deduplicate nodes by server+port combination
pub fn deduplicate_nodes(nodes: &[ProxyNode]) -> Vec<ProxyNode> {
    let mut seen: HashMap<(String, u16), ProxyNode> = HashMap::new();

    for node in nodes {
        let key = (node.server.clone(), node.port);
        seen.entry(key).or_insert_with(|| node.clone());
    }

    let mut result: Vec<_> = seen.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

/// Sanitize proxy name for use in configs
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Convert merge result to target format
pub fn merge_to_format(uris: &[String], target: TargetFormat) -> Result<String, String> {
    let merge_result = merge_uris(uris);

    if merge_result.nodes.is_empty() {
        return Err("No valid proxy nodes found".to_string());
    }

    let output = convert_nodes(&merge_result.nodes, target);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subconverter::{ProxyNode, ProxyProtocol};

    fn create_test_nodes() -> Vec<ProxyNode> {
        vec![
            ProxyNode {
                name: "Node1".to_string(),
                protocol: ProxyProtocol::Trojan,
                server: "server1.com".to_string(),
                port: 443,
                extra: Default::default(),
            },
            ProxyNode {
                name: "Node2".to_string(),
                protocol: ProxyProtocol::Shadowsocks,
                server: "server2.com".to_string(),
                port: 8388,
                extra: Default::default(),
            },
        ]
    }

    #[test]
    fn test_merge_nodes() {
        let lists = vec![create_test_nodes(), create_test_nodes()];
        let result = merge_nodes(&lists);
        assert_eq!(result.nodes.len(), 4);
    }

    #[test]
    fn test_merge_nodes_handles_duplicates() {
        let lists = vec![create_test_nodes(), create_test_nodes()];
        let result = merge_nodes(&lists);
        // Names should be deduplicated
        let names: Vec<_> = result.nodes.iter().map(|n| n.name.clone()).collect();
        assert!(names.contains(&"Node1".to_string()));
        assert!(names.contains(&"Node1 (1)".to_string()));
    }

    #[test]
    fn test_deduplicate_nodes() {
        let mut nodes = create_test_nodes();
        // Add a duplicate
        nodes.push(ProxyNode {
            name: "Duplicate".to_string(),
            protocol: ProxyProtocol::VMess,
            server: "server1.com".to_string(), // Same server:port as Node1
            port: 443,
            extra: Default::default(),
        });

        let deduped = deduplicate_nodes(&nodes);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_merge_uris_with_subscription_url() {
        let uris = vec![
            "trojan://pass@example.com:443#Node1".to_string(),
            "https://example.com/sub".to_string(),
        ];
        let result = merge_uris(&uris);
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_sanitize_name() {
        assert_eq!(sanitize_name("Node/Name"), "Node_Name");
        assert_eq!(sanitize_name("Node:Name"), "Node_Name");
        assert_eq!(sanitize_name("Node.Name"), "Node_Name"); // dots are replaced with underscore
    }

    #[test]
    fn test_merge_to_format_success() {
        let uris = vec!["trojan://pass@example.com:443#Node1".to_string()];
        let result = merge_to_format(&uris, crate::subconverter::TargetFormat::Clash);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Node1"));
    }

    #[test]
    fn test_merge_to_format_empty_nodes() {
        // Empty uris should return error
        let uris: Vec<String> = vec![];
        let result = merge_to_format(&uris, crate::subconverter::TargetFormat::Clash);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "No valid proxy nodes found");
    }

    #[test]
    fn test_merge_to_format_invalid_uri() {
        // Invalid URI should result in empty nodes, triggering error
        let uris = vec!["invalid://uri".to_string()];
        let result = merge_to_format(&uris, crate::subconverter::TargetFormat::Clash);
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_result_new() {
        let result = MergeResult::new();
        assert_eq!(result.node_count(), 0);
        assert_eq!(result.error_count(), 0);
    }

    #[test]
    fn test_merge_result_node_count() {
        let mut result = MergeResult::new();
        assert_eq!(result.node_count(), 0);
        result.nodes.push(create_test_nodes()[0].clone());
        assert_eq!(result.node_count(), 1);
    }

    #[test]
    fn test_merge_result_error_count() {
        let mut result = MergeResult::new();
        assert_eq!(result.error_count(), 0);
        result.errors.push("error1".to_string());
        result.errors.push("error2".to_string());
        assert_eq!(result.error_count(), 2);
    }

    #[test]
    fn test_merge_result_default() {
        let result: MergeResult = Default::default();
        assert_eq!(result.node_count(), 0);
        assert_eq!(result.error_count(), 0);
    }

    #[test]
    fn test_merge_uris_with_empty_list() {
        let uris: Vec<String> = vec![];
        let result = merge_uris(&uris);
        assert_eq!(result.nodes.len(), 0);
        assert_eq!(result.errors.len(), 0);
    }

    #[test]
    fn test_merge_uris_with_whitespace_only() {
        let uris = vec!["   ".to_string(), "".to_string()];
        let result = merge_uris(&uris);
        assert_eq!(result.nodes.len(), 0);
    }

    #[test]
    fn test_merge_uris_with_only_comments() {
        let uris = vec!["# comment".to_string(), "# another".to_string()];
        let result = merge_uris(&uris);
        assert_eq!(result.nodes.len(), 0);
    }

    #[test]
    fn test_merge_uris_with_invalid_uri() {
        let uris = vec!["not-a-valid-uri".to_string()];
        let result = merge_uris(&uris);
        assert_eq!(result.nodes.len(), 0);
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("Failed to parse URI"));
    }

    #[test]
    fn test_merge_uris_multiple_valid() {
        let uris = vec![
            "trojan://pass1@example.com:443#Node1".to_string(),
            "trojan://pass2@example.com:443#Node2".to_string(),
        ];
        let result = merge_uris(&uris);
        assert_eq!(result.nodes.len(), 2);
        assert_eq!(result.errors.len(), 0);
    }

    #[test]
    fn test_merge_uris_with_duplicate_names() {
        // Two URIs with same name - should rename second to "Name (1)"
        let uris = vec![
            "trojan://pass1@example.com:443#SameName".to_string(),
            "trojan://pass2@example.com:443#SameName".to_string(),
        ];
        let result = merge_uris(&uris);
        assert_eq!(result.nodes.len(), 2);
        // First keeps original name, second gets (1) suffix
        let names: Vec<_> = result.nodes.iter().map(|n| n.name.clone()).collect();
        assert!(names.contains(&"SameName".to_string()));
        assert!(names.contains(&"SameName (1)".to_string()));
    }

    #[test]
    fn test_deduplicate_nodes_preserves_order() {
        let nodes = create_test_nodes();
        let deduped = deduplicate_nodes(&nodes);
        // Should keep first occurrence and sort by name
        assert_eq!(deduped.len(), 2);
        // Results are sorted alphabetically by name
        let names: Vec<_> = deduped.iter().map(|n| n.name.clone()).collect();
        assert_eq!(names, vec!["Node1", "Node2"]);
    }

    #[test]
    fn test_deduplicate_nodes_all_unique() {
        let nodes = create_test_nodes();
        let deduped = deduplicate_nodes(&nodes);
        assert_eq!(deduped.len(), nodes.len());
    }

    // ==================================================================
    // Multi-subscription merge semantics, verified against mihomo's
    // behavior (common/convert/converter.go `uniqueName`: the first
    // node keeps its name, later collisions get a suffix — mihomo uses
    // "-02"/"-03", we use " (1)"/" (2)"; mihomo's config loader itself
    // REJECTS duplicate names outright, so suffixing is strictly more
    // forgiving).
    // ==================================================================

    fn node(name: &str, server: &str, port: u16) -> ProxyNode {
        ProxyNode {
            name: name.to_string(),
            protocol: ProxyProtocol::Trojan,
            server: server.to_string(),
            port,
            extra: Default::default(),
        }
    }

    fn assert_all_unique(result: &MergeResult) {
        let mut names: Vec<&str> = result.nodes.iter().map(|n| n.name.as_str()).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            total,
            "duplicate names in merge output: {:?}",
            result
                .nodes
                .iter()
                .map(|n| n.name.clone())
                .collect::<Vec<_>>()
        );
    }

    /// Same name, different servers (two airports with "香港 01"):
    /// both survive, the second gets a suffix.
    #[test]
    fn merge_same_name_different_servers_keeps_both() {
        let lists = vec![
            vec![node("HK 01", "a.example.com", 443)],
            vec![node("HK 01", "b.example.com", 443)],
            vec![node("HK 01", "c.example.com", 8443)],
        ];
        let result = merge_nodes(&lists);
        assert_eq!(result.node_count(), 3);
        let names: Vec<_> = result.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["HK 01", "HK 01 (1)", "HK 01 (2)"]);
        // Servers preserved verbatim — no node was dropped as a
        // "duplicate".
        let servers: Vec<_> = result.nodes.iter().map(|n| n.server.as_str()).collect();
        assert_eq!(servers, vec!["a.example.com", "b.example.com", "c.example.com"]);
        assert_all_unique(&result);
    }

    /// Same name AND same server:port across subscriptions — kept (the
    /// merge is name-based, mihomo-style); `deduplicate_nodes` is the
    /// server:port-based collapse.
    #[test]
    fn merge_identical_nodes_are_suffixed_dedup_collapses_them() {
        let lists = vec![
            vec![node("Same", "dup.example.com", 443)],
            vec![node("Same", "dup.example.com", 443)],
        ];
        let result = merge_nodes(&lists);
        assert_eq!(result.node_count(), 2);
        assert_eq!(result.nodes[0].name, "Same");
        assert_eq!(result.nodes[1].name, "Same (1)");

        // Server:port dedup keeps the FIRST node (order of appearance).
        let deduped = deduplicate_nodes(&result.nodes);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].name, "Same");
    }

    /// A node literally named "X (1)" arriving after a renamed "X (1)"
    /// must not collide: sanitize_name strips parens from literal names
    /// ("X _1_") while generated suffixes keep real parens, so the two
    /// forms can never produce the same output name.
    #[test]
    fn merge_literal_suffixed_name_does_not_collide() {
        let lists = vec![vec![
            node("X", "one.example.com", 443),
            node("X", "two.example.com", 443),
            node("X (1)", "three.example.com", 443),
        ]];
        let result = merge_nodes(&lists);
        assert_all_unique(&result);
        // First keeps "X", second becomes "X (1)", the literal third
        // sanitizes to a distinct form.
        assert_eq!(result.nodes[0].name, "X");
        assert_eq!(result.nodes[1].name, "X (1)");
        assert_eq!(result.nodes[2].name, "X _1_");
    }

    /// Cross-list merge preserves subscription order (list 1 nodes
    /// before list 2 nodes) — the order mihomo's subscription concat
    /// produces.
    #[test]
    fn merge_preserves_subscription_order() {
        let lists = vec![
            vec![node("A1", "a1.example.com", 1), node("A2", "a2.example.com", 2)],
            vec![node("B1", "b1.example.com", 3)],
        ];
        let result = merge_nodes(&lists);
        let names: Vec<_> = result.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["A1", "A2", "B1"]);
    }

    /// Invariant on a hostile mix: many collisions, pre-suffixed
    /// literals, CJK names — output names are always unique.
    #[test]
    fn merge_hostile_name_mix_stays_unique() {
        let mut list = Vec::new();
        for i in 0..5 {
            list.push(node("東京", &format!("tokyo{i}.example.com"), 443));
        }
        for name in ["Node (1)", "Node", "Node (2)", "Node"] {
            list.push(node(name, "node.example.com", 443));
        }
        let result = merge_nodes(&[list]);
        assert_eq!(result.node_count(), 9);
        assert_all_unique(&result);
        // First occurrence keeps the verbatim name.
        assert_eq!(result.nodes[0].name, "東京");
    }

    /// merge_uris (string form) resolves collisions the same way and
    /// reports unparseable lines without dropping the good ones.
    #[test]
    fn merge_uris_mixed_valid_invalid_and_collisions() {
        let uris = vec![
            "trojan://p1@s1.example.com:443#Dup".to_string(),
            "not-a-uri".to_string(),
            "trojan://p2@s2.example.com:443#Dup".to_string(),
            "https://sub.example.com/list".to_string(),
            "trojan://p3@s3.example.com:443#Unique".to_string(),
        ];
        let result = merge_uris(&uris);
        assert_eq!(result.node_count(), 3);
        assert_eq!(result.error_count(), 2);
        let names: Vec<_> = result.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["Dup", "Dup (1)", "Unique"]);
        assert_all_unique(&result);
    }

    /// Names containing config-hostile characters are sanitized before
    /// the collision suffix is applied (mihomo YAML proxies would
    /// otherwise break quoting).
    #[test]
    fn merge_sanitizes_names_before_suffixing() {
        let uris = vec![
            "trojan://p1@s1.example.com:443#HK:01".to_string(),
            "trojan://p2@s2.example.com:443#HK:01".to_string(),
        ];
        let result = merge_uris(&uris);
        let names: Vec<_> = result.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["HK_01", "HK_01 (1)"]);
    }
}
