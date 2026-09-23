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
            // Handle duplicate names by appending index
            let name = sanitize_name(&node.name);
            let count = seen_names.entry(name.clone()).or_insert(0);
            if *count > 0 {
                node.name = format!("{} ({})", name, count);
            }
            *count += 1;
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
            let name = sanitize_name(&node.name);
            let count = seen_names.entry(name.clone()).or_insert(0);
            if *count > 0 {
                node.name = format!("{} ({})", name, count);
            }
            *count += 1;
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
}
