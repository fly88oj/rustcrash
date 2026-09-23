//! Format conversion for proxy nodes
//!
//! Converts ProxyNode to Clash YAML, SingBox JSON, Quantumult, QuantumultX, Loon, Surge, V2Ray, Mellow formats.

use super::{ProxyNode, ProxyProtocol, TargetFormat, TransportType};
use base64::Engine;
use serde_json::{json, Value};

/// Convert a list of proxy nodes to the target format
pub fn convert_nodes(nodes: &[ProxyNode], target: TargetFormat) -> String {
    convert_nodes_with_options(nodes, target, false, false, None)
}

/// Convert a list of proxy nodes to the target format with expand and
/// classic options. `tolerance` sets the url-test group's switching
/// tolerance in milliseconds (None uses the 50 ms default).
pub fn convert_nodes_with_options(
    nodes: &[ProxyNode],
    target: TargetFormat,
    expand: bool,
    classic: bool,
    tolerance: Option<u32>,
) -> String {
    match target {
        TargetFormat::Clash => to_clash(nodes, false, expand, classic, tolerance),
        TargetFormat::ClashR => to_clash(nodes, true, expand, classic, tolerance),
        TargetFormat::SingBox => to_singbox(nodes),
        TargetFormat::Quantumult => to_quantumult(nodes),
        TargetFormat::QuantumultX => to_quantumultx(nodes),
        TargetFormat::Loon => to_loon(nodes),
        TargetFormat::Surge => to_surge(nodes, super::SurgeVersion::V4),
        TargetFormat::Surfboard => to_surfboard(nodes),
        // Stash is Clash-compatible.
        TargetFormat::Stash => to_clash(nodes, false, expand, classic, tolerance),
        TargetFormat::V2Ray => to_v2ray(nodes),
        TargetFormat::SS | TargetFormat::SSD => to_ss(nodes),
        TargetFormat::SSR => to_ssr(nodes),
        TargetFormat::Trojan => to_trojan(nodes),
        TargetFormat::Mixed => to_mixed(nodes),
        TargetFormat::Mellow => to_mellow(nodes),
    }
}

/// Convert to Clash YAML format
/// is_clashr: if true, enables ClashR-specific features (UDP over TCP)
/// expand: if true, include rules section with common rules
/// classic: if true, use classical rule style instead of rule-providers
fn to_clash(
    nodes: &[ProxyNode],
    is_clashr: bool,
    expand: bool,
    classic: bool,
    tolerance: Option<u32>,
) -> String {
    let mut output = if is_clashr {
        String::from("# RustCrash Auto Generated (ClashR)\n# DO NOT EDIT MANUALLY\n\n")
    } else {
        String::from("# RustCrash Auto Generated\n# DO NOT EDIT MANUALLY\n\n")
    };

    // Build proxies section
    output.push_str("proxies:\n");
    for node in nodes {
        output.push_str(&clash_proxy_entry(node, is_clashr));
        output.push('\n');
    }

    // Build proxy-groups section
    output.push_str("\nproxy-groups:\n");
    output.push_str("  - name: Auto\n");
    output.push_str("    type: select\n");
    output.push_str("    proxies:\n");
    output.push_str("      - Manual\n");
    for node in nodes {
        output.push_str(&format!("      - {}\n", node.name));
    }
    output.push_str("  - name: Manual\n");
    output.push_str("    type: select\n");
    output.push_str("    proxies:\n");
    for node in nodes {
        output.push_str(&format!("      - {}\n", node.name));
    }
    // Auto-tested group with switching tolerance (subconverter semantics).
    output.push_str("  - name: AutoUrlTest\n");
    output.push_str("    type: url-test\n");
    output.push_str("    url: http://www.gstatic.com/generate_204\n");
    output.push_str("    interval: 300\n");
    output.push_str(&format!("    tolerance: {}\n", tolerance.unwrap_or(50)));
    output.push_str("    proxies:\n");
    for node in nodes {
        output.push_str(&format!("      - {}\n", node.name));
    }

    // Add rules section if expand=true
    if expand {
        output.push('\n');
        output.push_str(&generate_clash_rules(classic));
    }

    output
}

/// Generate Clash rules section
fn generate_clash_rules(classic: bool) -> String {
    if classic {
        // Classical style - inline rules without rule-providers
        generate_classic_rules()
    } else {
        // Modern style with rule-providers
        generate_rule_providers()
    }
}

/// Generate classical inline rules (no rule-providers)
fn generate_classic_rules() -> String {
    let mut rules = String::from("rules:\n");

    // Add common classical rules
    rules.push_str("  - RULE-SET,direct,DIRECT\n");
    rules.push_str("  - DOMAIN,clash.razord.top,DIRECT\n");
    rules.push_str("  - DOMAIN,yacd.haishan.me,DIRECT\n");
    rules.push_str("  - DOMAIN-SUFFIX,cn,DIRECT\n");
    rules.push_str("  - DOMAIN-KEYWORD,china,DIRECT\n");
    rules.push_str("  - DOMAIN-KEYWORD,baidu,DIRECT\n");
    rules.push_str("  - DOMAIN-KEYWORD,aliyun,DIRECT\n");
    rules.push_str("  - IP-CIDR,127.0.0.0/8,DIRECT\n");
    rules.push_str("  - IP-CIDR,10.0.0.0/8,DIRECT\n");
    rules.push_str("  - IP-CIDR,172.16.0.0/12,DIRECT\n");
    rules.push_str("  - IP-CIDR,192.168.0.0/16,DIRECT\n");
    rules.push_str("  - IP-CIDR6,::1/128,DIRECT\n");
    rules.push_str("  - GEOIP,CN,DIRECT\n");
    rules.push_str("  - MATCH,Auto\n");

    rules
}

/// Generate modern rule-providers style
fn generate_rule_providers() -> String {
    let mut output = String::from("rule-providers:\n");

    // Define rule providers
    output.push_str("  direct:\n");
    output.push_str("    type: file\n");
    output.push_str("    behavior: domain\n");
    output.push_str("    path: ./ruleset/direct.yaml\n");
    output.push_str("    interval: 86400\n");
    output.push('\n');

    output.push_str("  china:\n");
    output.push_str("    type: file\n");
    output.push_str("    behavior: domain\n");
    output.push_str("    path: ./ruleset/china.yaml\n");
    output.push_str("    interval: 86400\n");
    output.push('\n');

    output.push_str("  ipcidr-china:\n");
    output.push_str("    type: file\n");
    output.push_str("    behavior: ipcidr\n");
    output.push_str("    path: ./ruleset/ipcidr-china.txt\n");
    output.push_str("    interval: 86400\n");
    output.push('\n');

    output.push_str("  cncidr:\n");
    output.push_str("    type: file\n");
    output.push_str("    behavior: ipcidr\n");
    output.push_str("    path: ./ruleset/cncidr.txt\n");
    output.push_str("    interval: 86400\n");

    // Now add rules section using the providers
    output.push_str("\nrules:\n");
    output.push_str("  - RULE-SET,direct,DIRECT\n");
    output.push_str("  - DOMAIN,clash.razord.top,DIRECT\n");
    output.push_str("  - DOMAIN,yacd.haishan.me,DIRECT\n");
    output.push_str("  - RULE-SET,china,DIRECT\n");
    output.push_str("  - RULE-SET,ipcidr-china,DIRECT\n");
    output.push_str("  - RULE-SET,cncidr,DIRECT\n");
    output.push_str("  - GEOIP,CN,DIRECT\n");
    output.push_str("  - MATCH,Auto\n");

    output
}

fn clash_proxy_entry(node: &ProxyNode, is_clashr: bool) -> String {
    match node.protocol {
        ProxyProtocol::Shadowsocks => {
            format!(
                "  - name: \"{}\"\n    type: ss\n    server: {}\n    port: {}\n    cipher: {}\n    password: {}",
                node.name,
                node.server,
                node.port,
                node.extra.cipher.as_deref().unwrap_or("aes-256-gcm"),
                node.extra.password.as_deref().unwrap_or("")
            )
        }
        ProxyProtocol::ShadowSocksR => {
            // Clash/Mihomo doesn't natively support SSR, but we can output it as a custom proxy
            // or fall back to Shadowsocks with available info
            format!(
                "  - name: \"{}\"\n    type: ss\n    server: {}\n    port: {}\n    cipher: {}\n    password: {}",
                node.name,
                node.server,
                node.port,
                node.extra.ssr_method.as_deref().unwrap_or("aes-256-cfb"),
                node.extra.password.as_deref().unwrap_or("")
            )
        }
        ProxyProtocol::VMess => {
            let transport = node.extra.transport.as_ref().unwrap_or(&TransportType::Tcp);
            let network = match transport {
                TransportType::WebSocket => "ws",
                TransportType::Http => "http",
                TransportType::Grpc => "grpc",
                TransportType::Tcp => "tcp",
            };

            let mut yaml = format!(
                "  - name: \"{}\"\n    type: vmess\n    server: {}\n    port: {}\n    uuid: {}\n    alterId: {}\n    cipher: auto\n    network: {}",
                node.name,
                node.server,
                node.port,
                node.extra.uuid.as_deref().unwrap_or(""),
                node.extra.alter_id.unwrap_or(0),
                network
            );

            if node.extra.tls {
                yaml.push_str("\n    tls: true");
                if let Some(sni) = &node.extra.sni {
                    yaml.push_str(&format!("\n    sni: {}", sni));
                }
            }

            // Add transport-specific options
            match transport {
                TransportType::WebSocket => {
                    yaml.push_str("\n    ws-opts:\n      path: /");
                }
                TransportType::Http => {
                    yaml.push_str("\n    http-opts:\n      path: /");
                }
                TransportType::Grpc => {
                    yaml.push_str("\n    grpc-opts:\n      grpc-service-name: /");
                }
                _ => {}
            }

            yaml
        }
        ProxyProtocol::VLESS => {
            let mut yaml = format!(
                "  - name: \"{}\"\n    type: vless\n    server: {}\n    port: {}\n    uuid: {}",
                node.name,
                node.server,
                node.port,
                node.extra
                    .vless_uuid
                    .as_deref()
                    .unwrap_or(node.extra.uuid.as_deref().unwrap_or("")),
            );

            if let Some(flow) = &node.extra.vless_flow {
                yaml.push_str(&format!("\n    flow: {}", flow));
            }

            if node.extra.tls {
                yaml.push_str("\n    tls: true");
                if let Some(sni) = &node.extra.sni {
                    yaml.push_str(&format!("\n    servername: {}", sni));
                }
            }

            yaml
        }
        ProxyProtocol::Trojan => {
            let mut yaml = format!(
                "  - name: \"{}\"\n    type: trojan\n    server: {}\n    port: {}\n    password: {}",
                node.name,
                node.server,
                node.port,
                node.extra.trojan_password.as_deref().unwrap_or("")
            );
            if is_clashr {
                yaml.push_str("\n    udp-over-tcp: true");
            }
            yaml
        }
        ProxyProtocol::Hysteria2 => {
            let mut yaml = format!(
                "  - name: \"{}\"\n    type: hysteria2\n    server: {}\n    port: {}\n    password: {}",
                node.name,
                node.server,
                node.port,
                node.extra.hy2_password.as_deref().unwrap_or("")
            );

            if let Some(obfs) = &node.extra.hy2_obfs {
                yaml.push_str(&format!("\n    obfs: {}", obfs));
            }
            if let Some(sni) = &node.extra.sni {
                yaml.push_str(&format!("\n    sni: {}", sni));
            }

            yaml
        }
        ProxyProtocol::Tuic => {
            let mut yaml = format!(
                "  - name: \"{}\"\n    type: tuic\n    server: {}\n    port: {}\n    uuid: {}\n    password: {}",
                node.name,
                node.server,
                node.port,
                node.extra.tuic_uuid.as_deref().unwrap_or(""),
                node.extra.tuic_password.as_deref().unwrap_or("")
            );

            if let Some(cc) = &node.extra.tuic_congestion_control {
                yaml.push_str(&format!("\n    congestion_control: {}", cc));
            }
            if let Some(sni) = &node.extra.sni {
                yaml.push_str(&format!("\n    sni: {}", sni));
            }

            yaml
        }
        ProxyProtocol::WireGuard => {
            let mut yaml = format!(
                "  - name: \"{}\"\n    type: wireguard\n    server: {}\n    port: {}\n    private_key: {}",
                node.name,
                node.server,
                node.port,
                node.extra.wg_private_key.as_deref().unwrap_or("")
            );

            if let Some(pk) = &node.extra.wg_public_key {
                yaml.push_str(&format!("\n    public_key: {}", pk));
            }
            if let Some(psk) = &node.extra.wg_preshared_key {
                yaml.push_str(&format!("\n    preshared_key: {}", psk));
            }
            if let Some(mtu) = node.extra.wg_mtu {
                yaml.push_str(&format!("\n    mtu: {}", mtu));
            }
            if !node.extra.wg_addresses.is_empty() {
                yaml.push_str(&format!(
                    "\n    local_address: {}",
                    node.extra.wg_addresses.join(", ")
                ));
            }

            yaml
        }
        ProxyProtocol::Unknown => {
            format!(
                "  - name: \"{}\"\n    type: http\n    server: {}\n    port: {}",
                node.name, node.server, node.port
            )
        }
    }
}

/// Convert to SingBox JSON format
fn to_singbox(nodes: &[ProxyNode]) -> String {
    let outbounds: Vec<Value> = nodes.iter().map(singbox_outbound).collect();

    let singbox_config = json!({
        "outbounds": outbounds
    });

    serde_json::to_string_pretty(&singbox_config).unwrap_or_default()
}

fn singbox_outbound(node: &ProxyNode) -> Value {
    match node.protocol {
        ProxyProtocol::Shadowsocks => {
            json!({
                "type": "shadowsocks",
                "tag": node.name,
                "server": node.server,
                "port": node.port,
                "method": node.extra.cipher.as_deref().unwrap_or("aes-256-gcm"),
                "password": node.extra.password.as_deref().unwrap_or(""),
            })
        }
        ProxyProtocol::ShadowSocksR => {
            // SingBox doesn't natively support SSR, fall back to Shadowsocks output
            json!({
                "type": "shadowsocks",
                "tag": node.name,
                "server": node.server,
                "port": node.port,
                "method": node.extra.ssr_method.as_deref().unwrap_or("aes-256-cfb"),
                "password": node.extra.password.as_deref().unwrap_or(""),
            })
        }
        ProxyProtocol::VMess => {
            let mut obj = json!({
                "type": "vmess",
                "tag": node.name,
                "server": node.server,
                "port": node.port,
                "uuid": node.extra.uuid.as_deref().unwrap_or(""),
                "alter_id": node.extra.alter_id.unwrap_or(0),
                "security": "auto",
            });

            let transport = node.extra.transport.as_ref().unwrap_or(&TransportType::Tcp);
            match transport {
                TransportType::WebSocket => {
                    obj["transport"] = json!({
                        "type": "websocket",
                        "path": "/"
                    });
                }
                TransportType::Http => {
                    obj["transport"] = json!({
                        "type": "http",
                        "path": "/"
                    });
                }
                TransportType::Grpc => {
                    obj["transport"] = json!({
                        "type": "grpc",
                        "service_name": "/"
                    });
                }
                _ => {
                    obj["transport"] = json!({
                        "type": "tcp"
                    });
                }
            }

            if node.extra.tls {
                obj["tls"] = json!({
                    "enabled": true,
                    "server_name": node.extra.sni.as_deref().unwrap_or("")
                });
            }

            obj
        }
        ProxyProtocol::VLESS => {
            let mut obj = json!({
                "type": "vless",
                "tag": node.name,
                "server": node.server,
                "port": node.port,
                "uuid": node.extra.vless_uuid.as_deref().unwrap_or(""),
                "flow": node.extra.vless_flow.as_deref().unwrap_or(""),
            });

            if node.extra.tls {
                obj["tls"] = json!({
                    "enabled": true,
                    "server_name": node.extra.sni.as_deref().unwrap_or("")
                });
            }

            obj
        }
        ProxyProtocol::Trojan => {
            json!({
                "type": "trojan",
                "tag": node.name,
                "server": node.server,
                "port": node.port,
                "password": node.extra.trojan_password.as_deref().unwrap_or(""),
            })
        }
        ProxyProtocol::Hysteria2 => {
            let mut obj = json!({
                "type": "hysteria2",
                "tag": node.name,
                "server": node.server,
                "port": node.port,
                "password": node.extra.hy2_password.as_deref().unwrap_or(""),
            });

            if let Some(obfs) = &node.extra.hy2_obfs {
                obj["obfs"] = json!({
                    "type": obfs
                });
            }

            if let Some(sni) = &node.extra.sni {
                obj["tls"] = json!({
                    "enabled": true,
                    "server_name": sni
                });
            }

            obj
        }
        ProxyProtocol::Tuic => {
            let mut obj = json!({
                "type": "tuic",
                "tag": node.name,
                "server": node.server,
                "port": node.port,
                "uuid": node.extra.tuic_uuid.as_deref().unwrap_or(""),
                "password": node.extra.tuic_password.as_deref().unwrap_or(""),
                "congestion_control": node.extra.tuic_congestion_control.as_deref().unwrap_or("bbr"),
            });

            if let Some(sni) = &node.extra.sni {
                obj["tls"] = json!({
                    "enabled": true,
                    "server_name": sni
                });
            }

            obj
        }
        ProxyProtocol::WireGuard => {
            json!({
                "type": "wireguard",
                "tag": node.name,
                "server": node.server,
                "port": node.port,
                "private_key": node.extra.wg_private_key.as_deref().unwrap_or(""),
                "peer_public_key": node.extra.wg_public_key.as_deref().unwrap_or(""),
                "preshared_key": node.extra.wg_preshared_key.as_deref().unwrap_or(""),
                "mtu": node.extra.wg_mtu.unwrap_or(1280),
                "local_address": node.extra.wg_addresses,
            })
        }
        ProxyProtocol::Unknown => {
            json!({
                "type": "http",
                "tag": node.name,
                "server": node.server,
                "port": node.port,
            })
        }
    }
}

/// Convert to Quantumult format
fn to_quantumult(nodes: &[ProxyNode]) -> String {
    let mut output = String::new();

    for node in nodes {
        output.push_str(&quantumult_entry(node));
        output.push('\n');
    }

    output
}

fn quantumult_entry(node: &ProxyNode) -> String {
    match node.protocol {
        ProxyProtocol::Shadowsocks => {
            format!(
                "shadowsocks={}:{}@{}:{}",
                node.extra.cipher.as_deref().unwrap_or("aes-256-gcm"),
                node.extra.password.as_deref().unwrap_or(""),
                node.server,
                node.port
            )
        }
        ProxyProtocol::VMess => {
            format!(
                "vmess={}@{}:{}",
                node.extra.uuid.as_deref().unwrap_or(""),
                node.server,
                node.port
            )
        }
        ProxyProtocol::Trojan => {
            format!(
                "trojan={}@{}:{}",
                node.extra.trojan_password.as_deref().unwrap_or(""),
                node.server,
                node.port
            )
        }
        ProxyProtocol::VLESS => {
            format!(
                "vless={}@{}:{}",
                node.extra.vless_uuid.as_deref().unwrap_or(""),
                node.server,
                node.port
            )
        }
        _ => {
            format!(
                "{}={}:{}",
                format!("{:?}", node.protocol).to_lowercase(),
                node.server,
                node.port
            )
        }
    }
}

/// Convert to QuantumultX format
fn to_quantumultx(nodes: &[ProxyNode]) -> String {
    let mut output = String::new();

    for node in nodes {
        output.push_str(&quantumultx_entry(node));
        output.push('\n');
    }

    output
}

fn quantumultx_entry(node: &ProxyNode) -> String {
    // QuantumultX uses similar format to Quantumult but with different options
    match node.protocol {
        ProxyProtocol::Shadowsocks => {
            format!(
                "shadowsocks={}:{}@{}:{}",
                node.extra.cipher.as_deref().unwrap_or("aes-256-gcm"),
                node.extra.password.as_deref().unwrap_or(""),
                node.server,
                node.port
            )
        }
        _ => quantumult_entry(node),
    }
}

/// Convert to Loon format
fn to_loon(nodes: &[ProxyNode]) -> String {
    let mut output = String::new();

    for node in nodes {
        output.push_str(&loon_entry(node));
        output.push('\n');
    }

    output
}

fn loon_entry(node: &ProxyNode) -> String {
    match node.protocol {
        ProxyProtocol::Shadowsocks => {
            format!("Shadowsocks={}={}:{}", node.name, node.server, node.port)
        }
        ProxyProtocol::VMess => {
            format!("VMess={}={}:{}", node.name, node.server, node.port)
        }
        ProxyProtocol::Trojan => {
            format!("Trojan={}={}:{}", node.name, node.server, node.port)
        }
        _ => {
            format!(
                "{}={}:{}",
                format!("{:?}", node.protocol).to_lowercase(),
                node.server,
                node.port
            )
        }
    }
}

/// Convert to Surge format
fn to_surge(nodes: &[ProxyNode], version: super::SurgeVersion) -> String {
    let mut output = String::new();

    for node in nodes {
        output.push_str(&surge_entry(node, version));
        output.push('\n');
    }

    output
}

fn surge_entry(node: &ProxyNode, _version: super::SurgeVersion) -> String {
    match node.protocol {
        ProxyProtocol::Shadowsocks => {
            format!(
                "{} = ss, {}, {}, {}",
                node.name,
                node.server,
                node.port,
                node.extra.cipher.as_deref().unwrap_or("aes-256-gcm"),
            )
        }
        ProxyProtocol::VMess => {
            format!(
                "{} = vmess, {}, {}, {}",
                node.name,
                node.server,
                node.port,
                node.extra.uuid.as_deref().unwrap_or(""),
            )
        }
        ProxyProtocol::Trojan => {
            format!(
                "{} = trojan, {}, {}, password={}",
                node.name,
                node.server,
                node.port,
                node.extra.trojan_password.as_deref().unwrap_or(""),
            )
        }
        ProxyProtocol::VLESS => {
            format!(
                "{} = vless, {}, {}, uuid={}",
                node.name,
                node.server,
                node.port,
                node.extra.vless_uuid.as_deref().unwrap_or(""),
            )
        }
        _ => {
            format!(
                "{} = {}, {}, {}",
                node.name,
                format!("{:?}", node.protocol).to_lowercase(),
                node.server,
                node.port
            )
        }
    }
}

/// Convert to Surfboard format (Surge-like sections).
fn to_surfboard(nodes: &[ProxyNode]) -> String {
    let mut output = String::from("#!MANAGED-CONFIG interval=86400\n\n[Proxy]\nDirect = direct\n");
    for node in nodes {
        output.push_str(&surfboard_entry(node));
        output.push('\n');
    }
    output
}

fn surfboard_entry(node: &ProxyNode) -> String {
    match node.protocol {
        ProxyProtocol::Shadowsocks => {
            format!(
                "{} = ss, {}, {}, encrypt-method={}, password={}",
                node.name,
                node.server,
                node.port,
                node.extra.cipher.as_deref().unwrap_or("aes-256-gcm"),
                node.extra.password.as_deref().unwrap_or(""),
            )
        }
        ProxyProtocol::VMess => {
            format!(
                "{} = vmess, {}, {}, username={}",
                node.name,
                node.server,
                node.port,
                node.extra.uuid.as_deref().unwrap_or(""),
            )
        }
        ProxyProtocol::Trojan => {
            format!(
                "{} = trojan, {}, {}, password={}",
                node.name,
                node.server,
                node.port,
                node.extra.trojan_password.as_deref().unwrap_or(""),
            )
        }
        ProxyProtocol::VLESS => {
            format!(
                "{} = vless, {}, {}, uuid={}",
                node.name,
                node.server,
                node.port,
                node.extra.vless_uuid.as_deref().unwrap_or(""),
            )
        }
        _ => {
            format!(
                "{} = {}, {}, {}",
                node.name,
                format!("{:?}", node.protocol).to_lowercase(),
                node.server,
                node.port
            )
        }
    }
}

/// Convert to V2Ray format
fn to_v2ray(nodes: &[ProxyNode]) -> String {
    let mut output = String::new();

    for (i, node) in nodes.iter().enumerate() {
        output.push_str(&v2ray_entry(node, i));
        output.push('\n');
    }

    output
}

fn v2ray_entry(node: &ProxyNode, _index: usize) -> String {
    match node.protocol {
        ProxyProtocol::VMess => {
            let json = json!({
                "address": node.server,
                "port": node.port,
                "uuid": node.extra.uuid.as_deref().unwrap_or(""),
                "alterId": node.extra.alter_id.unwrap_or(0),
                "security": "auto",
                "network": match node.extra.transport.as_ref().unwrap_or(&TransportType::Tcp) {
                    TransportType::WebSocket => "ws",
                    TransportType::Http => "http",
                    TransportType::Grpc => "grpc",
                    _ => "tcp",
                },
                "tls": node.extra.tls,
            });

            format!(
                "vmess://{}",
                base64::engine::general_purpose::STANDARD.encode(json.to_string().as_bytes())
            )
        }
        _ => {
            // For other protocols, just return a simple format
            format!(
                "{}://{}:{}@{}:{}",
                format!("{:?}", node.protocol).to_lowercase(),
                match node.protocol {
                    ProxyProtocol::Trojan => node.extra.trojan_password.as_deref().unwrap_or(""),
                    ProxyProtocol::VLESS => node.extra.vless_uuid.as_deref().unwrap_or(""),
                    _ => "",
                },
                node.server,
                node.port,
                node.name
            )
        }
    }
}

/// Convert to SS (Shadowsocks SIP002) format
fn to_ss(nodes: &[ProxyNode]) -> String {
    let mut output = String::new();
    for node in nodes {
        if node.protocol == ProxyProtocol::Shadowsocks {
            output.push_str(&format!(
                "ss://{}@{}:{}#{}\n",
                node.extra.cipher.as_deref().unwrap_or("aes-256-gcm"),
                node.server,
                node.port,
                urlencoding::encode(&node.name)
            ));
        }
    }
    output
}

/// Convert to SSR (ShadowSocksR) format
/// Format: ssr://(base64(method:password:protocol:obfs:urlbase64(host:port:protocol_param:obfs_param)))/remarks
fn to_ssr(nodes: &[ProxyNode]) -> String {
    let mut output = String::new();
    for node in nodes {
        if node.protocol == ProxyProtocol::ShadowSocksR {
            let method = node.extra.ssr_method.as_deref().unwrap_or("aes-256-cfb");
            let password = node.extra.password.as_deref().unwrap_or("");
            let protocol = node.extra.ssr_protocol.as_deref().unwrap_or("origin");
            let obfs = node.extra.ssr_obfs.as_deref().unwrap_or("plain");
            let obfs_param = node.extra.ssr_obfs_param.as_deref().unwrap_or("");

            // Build the URL part: host:port:protocol_param:obfs_param
            let url_part = format!("{}:{}:{}:{}", node.server, node.port, "", obfs_param);
            let url_encoded = base64::engine::general_purpose::STANDARD.encode(url_part.as_bytes());

            // Build the first part: method:password:protocol:obfs:url_encoded
            let first_part = format!(
                "{}:{}:{}:{}:{}",
                method, password, protocol, obfs, url_encoded
            );
            let first_encoded =
                base64::engine::general_purpose::STANDARD.encode(first_part.as_bytes());

            // Remarks (base64 encoded name)
            let remarks = base64::engine::general_purpose::STANDARD.encode(node.name.as_bytes());

            output.push_str(&format!("ssr://{}/{}\n", first_encoded, remarks));
        }
    }
    output
}

/// Convert to Trojan URI format
fn to_trojan(nodes: &[ProxyNode]) -> String {
    let mut output = String::new();
    for node in nodes {
        if node.protocol == ProxyProtocol::Trojan {
            let password = node.extra.trojan_password.as_deref().unwrap_or("");
            let sni = node
                .extra
                .sni
                .as_deref()
                .map(|s| format!("&sni={}", s))
                .unwrap_or_default();
            output.push_str(&format!(
                "trojan://{}@{}:{}{}#{}\n",
                urlencoding::encode(password),
                node.server,
                node.port,
                sni,
                urlencoding::encode(&node.name)
            ));
        }
    }
    output
}

/// Convert to Mixed format (SS + Trojan)
fn to_mixed(nodes: &[ProxyNode]) -> String {
    let mut output = String::new();
    for node in nodes {
        match node.protocol {
            ProxyProtocol::Shadowsocks => {
                output.push_str(&format!(
                    "ss://{}@{}:{}#{}\n",
                    node.extra.cipher.as_deref().unwrap_or("aes-256-gcm"),
                    node.server,
                    node.port,
                    urlencoding::encode(&node.name)
                ));
            }
            ProxyProtocol::Trojan => {
                let password = node.extra.trojan_password.as_deref().unwrap_or("");
                let sni = node
                    .extra
                    .sni
                    .as_deref()
                    .map(|s| format!("&sni={}", s))
                    .unwrap_or_default();
                output.push_str(&format!(
                    "trojan://{}@{}:{}{}#{}\n",
                    urlencoding::encode(password),
                    node.server,
                    node.port,
                    sni,
                    urlencoding::encode(&node.name)
                ));
            }
            _ => {}
        }
    }
    output
}

/// Convert to Mellow format
/// Mellow is a Clash-like format with YAML structure
fn to_mellow(nodes: &[ProxyNode]) -> String {
    let mut output =
        String::from("# RustCrash Auto Generated (Mellow)\n# DO NOT EDIT MANUALLY\n\n");

    // Build proxies section
    output.push_str("proxies:\n");
    for node in nodes {
        output.push_str(&mellow_proxy_entry(node));
        output.push('\n');
    }

    // Build proxy-groups section
    output.push_str("\nproxy-groups:\n");
    output.push_str("  - name: Auto\n");
    output.push_str("    type: select\n");
    output.push_str("    proxies:\n");
    output.push_str("      - Manual\n");
    for node in nodes {
        output.push_str(&format!("      - {}\n", node.name));
    }
    output.push_str("  - name: Manual\n");
    output.push_str("    type: select\n");
    output.push_str("    proxies:\n");
    for node in nodes {
        output.push_str(&format!("      - {}\n", node.name));
    }

    output
}

/// Generate Mellow proxy entry
fn mellow_proxy_entry(node: &ProxyNode) -> String {
    match node.protocol {
        ProxyProtocol::Shadowsocks => {
            format!(
                "  - name: \"{}\"\n    type: ss\n    server: {}\n    port: {}\n    cipher: {}\n    password: {}",
                node.name,
                node.server,
                node.port,
                node.extra.cipher.as_deref().unwrap_or("aes-256-gcm"),
                node.extra.password.as_deref().unwrap_or("")
            )
        }
        ProxyProtocol::ShadowSocksR => {
            format!(
                "  - name: \"{}\"\n    type: ss\n    server: {}\n    port: {}\n    cipher: {}\n    password: {}",
                node.name,
                node.server,
                node.port,
                node.extra.ssr_method.as_deref().unwrap_or("aes-256-cfb"),
                node.extra.password.as_deref().unwrap_or("")
            )
        }
        ProxyProtocol::VMess => {
            let transport = node.extra.transport.as_ref().unwrap_or(&TransportType::Tcp);
            let network = match transport {
                TransportType::WebSocket => "ws",
                TransportType::Http => "http",
                TransportType::Grpc => "grpc",
                TransportType::Tcp => "tcp",
            };

            let mut yaml = format!(
                "  - name: \"{}\"\n    type: vmess\n    server: {}\n    port: {}\n    uuid: {}\n    alterId: {}\n    cipher: auto\n    network: {}",
                node.name,
                node.server,
                node.port,
                node.extra.uuid.as_deref().unwrap_or(""),
                node.extra.alter_id.unwrap_or(0),
                network
            );

            if node.extra.tls {
                yaml.push_str("\n    tls: true");
                if let Some(sni) = &node.extra.sni {
                    yaml.push_str(&format!("\n    sni: {}", sni));
                }
            }

            match transport {
                TransportType::WebSocket => {
                    yaml.push_str("\n    ws-opts:\n      path: /");
                }
                TransportType::Http => {
                    yaml.push_str("\n    http-opts:\n      path: /");
                }
                TransportType::Grpc => {
                    yaml.push_str("\n    grpc-opts:\n      grpc-service-name: /");
                }
                _ => {}
            }

            yaml
        }
        ProxyProtocol::VLESS => {
            let mut yaml = format!(
                "  - name: \"{}\"\n    type: vless\n    server: {}\n    port: {}\n    uuid: {}",
                node.name,
                node.server,
                node.port,
                node.extra
                    .vless_uuid
                    .as_deref()
                    .unwrap_or(node.extra.uuid.as_deref().unwrap_or("")),
            );

            if let Some(flow) = &node.extra.vless_flow {
                yaml.push_str(&format!("\n    flow: {}", flow));
            }

            if node.extra.tls {
                yaml.push_str("\n    tls: true");
                if let Some(sni) = &node.extra.sni {
                    yaml.push_str(&format!("\n    servername: {}", sni));
                }
            }

            yaml
        }
        ProxyProtocol::Trojan => {
            let yaml = format!(
                "  - name: \"{}\"\n    type: trojan\n    server: {}\n    port: {}\n    password: {}",
                node.name,
                node.server,
                node.port,
                node.extra.trojan_password.as_deref().unwrap_or("")
            );
            yaml
        }
        ProxyProtocol::Hysteria2 => {
            let mut yaml = format!(
                "  - name: \"{}\"\n    type: hysteria2\n    server: {}\n    port: {}\n    password: {}",
                node.name,
                node.server,
                node.port,
                node.extra.hy2_password.as_deref().unwrap_or("")
            );

            if let Some(obfs) = &node.extra.hy2_obfs {
                yaml.push_str(&format!("\n    obfs: {}", obfs));
            }
            if let Some(sni) = &node.extra.sni {
                yaml.push_str(&format!("\n    sni: {}", sni));
            }

            yaml
        }
        ProxyProtocol::Tuic => {
            let mut yaml = format!(
                "  - name: \"{}\"\n    type: tuic\n    server: {}\n    port: {}\n    uuid: {}\n    password: {}",
                node.name,
                node.server,
                node.port,
                node.extra.tuic_uuid.as_deref().unwrap_or(""),
                node.extra.tuic_password.as_deref().unwrap_or("")
            );

            if let Some(cc) = &node.extra.tuic_congestion_control {
                yaml.push_str(&format!("\n    congestion_control: {}", cc));
            }
            if let Some(sni) = &node.extra.sni {
                yaml.push_str(&format!("\n    sni: {}", sni));
            }

            yaml
        }
        ProxyProtocol::WireGuard => {
            let mut yaml = format!(
                "  - name: \"{}\"\n    type: wireguard\n    server: {}\n    port: {}\n    private_key: {}",
                node.name,
                node.server,
                node.port,
                node.extra.wg_private_key.as_deref().unwrap_or("")
            );

            if let Some(pk) = &node.extra.wg_public_key {
                yaml.push_str(&format!("\n    public_key: {}", pk));
            }
            if let Some(psk) = &node.extra.wg_preshared_key {
                yaml.push_str(&format!("\n    preshared_key: {}", psk));
            }
            if let Some(mtu) = node.extra.wg_mtu {
                yaml.push_str(&format!("\n    mtu: {}", mtu));
            }
            if !node.extra.wg_addresses.is_empty() {
                yaml.push_str(&format!(
                    "\n    local_address: {}",
                    node.extra.wg_addresses.join(", ")
                ));
            }

            yaml
        }
        ProxyProtocol::Unknown => {
            format!(
                "  - name: \"{}\"\n    type: http\n    server: {}\n    port: {}",
                node.name, node.server, node.port
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subconverter::ProxyNode;

    fn create_test_node(protocol: ProxyProtocol) -> ProxyNode {
        ProxyNode {
            name: "Test Node".to_string(),
            protocol,
            server: "example.com".to_string(),
            port: 443,
            extra: Default::default(),
        }
    }

    #[test]
    fn test_convert_clash() {
        let nodes = vec![create_test_node(ProxyProtocol::Shadowsocks)];
        let output = convert_nodes(&nodes, TargetFormat::Clash);
        assert!(output.contains("proxies:"));
        assert!(output.contains("proxy-groups:"));
        assert!(output.contains("name: Auto"));
        assert!(output.contains("name: Manual"));
    }

    #[test]
    fn test_convert_clash_has_manual_group() {
        let mut node1 = create_test_node(ProxyProtocol::Shadowsocks);
        node1.name = "Node-Shadowsocks".to_string();
        let mut node2 = create_test_node(ProxyProtocol::Trojan);
        node2.name = "Node-Trojan".to_string();

        let nodes = vec![node1, node2];
        let output = convert_nodes(&nodes, TargetFormat::Clash);

        // Verify Manual group structure
        assert!(output.contains("  - name: Manual\n    type: select\n    proxies:"));
        // Verify each node appears in Auto, Manual and AutoUrlTest groups
        let count_shadowsocks = output.matches("      - Node-Shadowsocks").count();
        let count_trojan = output.matches("      - Node-Trojan").count();
        assert_eq!(
            count_shadowsocks, 3,
            "Shadowsocks should appear in Auto, Manual and AutoUrlTest"
        );
        assert_eq!(count_trojan, 3, "Trojan should appear in all groups");
    }

    #[test]
    fn test_convert_singbox() {
        let nodes = vec![create_test_node(ProxyProtocol::VMess)];
        let output = convert_nodes(&nodes, TargetFormat::SingBox);
        assert!(output.contains("\"outbounds\""));
        assert!(output.contains("\"vmess\""));
    }

    #[test]
    fn test_clash_proxy_entry_trojan() {
        let mut node = create_test_node(ProxyProtocol::Trojan);
        node.extra.trojan_password = Some("test123".to_string());
        let entry = clash_proxy_entry(&node, false);
        assert!(entry.contains("type: trojan"));
        assert!(entry.contains("password: test123"));
    }

    #[test]
    fn test_clash_proxy_entry_hysteria2() {
        let mut node = create_test_node(ProxyProtocol::Hysteria2);
        node.extra.hy2_password = Some("test456".to_string());
        node.extra.sni = Some("example.com".to_string());
        let entry = clash_proxy_entry(&node, false);
        assert!(entry.contains("type: hysteria2"));
        assert!(entry.contains("password: test456"));
        assert!(entry.contains("sni: example.com"));
    }

    #[test]
    fn test_clash_proxy_entry_tuic() {
        let mut node = create_test_node(ProxyProtocol::Tuic);
        node.extra.tuic_uuid = Some("uuid-123".to_string());
        node.extra.tuic_password = Some("pass-456".to_string());
        node.extra.tuic_congestion_control = Some("bbr".to_string());
        let entry = clash_proxy_entry(&node, false);
        assert!(entry.contains("type: tuic"));
        assert!(entry.contains("uuid: uuid-123"));
        assert!(entry.contains("password: pass-456"));
        assert!(entry.contains("congestion_control: bbr"));
    }

    #[test]
    fn test_clash_proxy_entry_wireguard() {
        let mut node = create_test_node(ProxyProtocol::WireGuard);
        node.extra.wg_private_key = Some("private-key".to_string());
        node.extra.wg_public_key = Some("public-key".to_string());
        node.extra.wg_mtu = Some(1280);
        node.extra.wg_addresses = vec!["10.0.0.1/32".to_string()];
        let entry = clash_proxy_entry(&node, false);
        assert!(entry.contains("type: wireguard"));
        assert!(entry.contains("private_key: private-key"));
        assert!(entry.contains("public_key: public-key"));
        assert!(entry.contains("mtu: 1280"));
    }

    #[test]
    fn test_clash_proxy_entry_vless() {
        let mut node = create_test_node(ProxyProtocol::VLESS);
        node.extra.vless_uuid = Some("uuid-123".to_string());
        node.extra.vless_flow = Some("xtls-rprx-vision".to_string());
        node.extra.tls = true;
        node.extra.sni = Some("example.com".to_string());
        let entry = clash_proxy_entry(&node, false);
        assert!(entry.contains("type: vless"));
        assert!(entry.contains("uuid: uuid-123"));
        assert!(entry.contains("flow: xtls-rprx-vision"));
        assert!(entry.contains("tls: true"));
    }

    #[test]
    fn test_convert_all_formats() {
        let nodes = vec![
            create_test_node(ProxyProtocol::VMess),
            create_test_node(ProxyProtocol::Shadowsocks),
            create_test_node(ProxyProtocol::Trojan),
            create_test_node(ProxyProtocol::VLESS),
            create_test_node(ProxyProtocol::Hysteria2),
            create_test_node(ProxyProtocol::Tuic),
            create_test_node(ProxyProtocol::WireGuard),
        ];

        // Test all target formats
        let formats = vec![
            TargetFormat::Clash,
            TargetFormat::SingBox,
            TargetFormat::Quantumult,
            TargetFormat::QuantumultX,
            TargetFormat::Loon,
            TargetFormat::Surge,
            TargetFormat::Surfboard,
            TargetFormat::Stash,
            TargetFormat::V2Ray,
            TargetFormat::Mellow,
        ];

        for fmt in formats {
            let output = convert_nodes(&nodes, fmt);
            assert!(
                !output.is_empty(),
                "Output for {:?} should not be empty",
                fmt
            );
        }
    }

    #[test]
    fn test_convert_surfboard() {
        let nodes = vec![create_test_node(ProxyProtocol::Shadowsocks)];
        let output = convert_nodes(&nodes, TargetFormat::Surfboard);
        assert!(output.starts_with("#!MANAGED-CONFIG"));
        assert!(output.contains("[Proxy]"));
        assert!(output.contains("Direct = direct"));
        assert!(output.contains("= ss, "));
        assert!(output.contains("encrypt-method="));

        let nodes = vec![create_test_node(ProxyProtocol::Trojan)];
        let output = convert_nodes(&nodes, TargetFormat::Surfboard);
        assert!(output.contains("= trojan, "));
        assert!(output.contains("password="));
    }

    #[test]
    fn test_convert_stash_is_clash_compatible() {
        let nodes = vec![create_test_node(ProxyProtocol::Shadowsocks)];
        let output = convert_nodes(&nodes, TargetFormat::Stash);
        assert!(output.contains("proxies:"));
        assert!(output.contains("proxy-groups:"));
    }

    #[test]
    fn test_format_parsing_new_formats() {
        assert_eq!(
            super::super::TargetFormat::from_str("surfboard"),
            Some(TargetFormat::Surfboard)
        );
        assert_eq!(
            super::super::TargetFormat::from_str("stash"),
            Some(TargetFormat::Stash)
        );
    }

    #[test]
    fn test_convert_mellow() {
        let nodes = vec![create_test_node(ProxyProtocol::Shadowsocks)];
        let output = convert_nodes(&nodes, TargetFormat::Mellow);
        assert!(output.contains("proxies:"));
        assert!(output.contains("proxy-groups:"));
        assert!(output.contains("name: Auto"));
        assert!(output.contains("name: Manual"));
        assert!(output.contains("Mellow"));
    }

    #[test]
    fn test_mellow_proxy_entry_all_protocols() {
        let protocols = vec![
            ProxyProtocol::VMess,
            ProxyProtocol::Shadowsocks,
            ProxyProtocol::Trojan,
            ProxyProtocol::VLESS,
            ProxyProtocol::Hysteria2,
            ProxyProtocol::Tuic,
            ProxyProtocol::WireGuard,
        ];
        for protocol in protocols {
            let node = create_test_node(protocol.clone());
            let entry = mellow_proxy_entry(&node);
            assert!(
                !entry.is_empty(),
                "Mellow entry for {:?} should not be empty",
                protocol
            );
            assert!(entry.contains(&node.name), "Entry should contain node name");
        }
    }

    #[test]
    fn test_mellow_proxy_entry_trojan() {
        let mut node = create_test_node(ProxyProtocol::Trojan);
        node.extra.trojan_password = Some("test123".to_string());
        let entry = mellow_proxy_entry(&node);
        assert!(entry.contains("type: trojan"));
        assert!(entry.contains("password: test123"));
    }

    #[test]
    fn test_mellow_proxy_entry_vmess_with_tls() {
        let mut node = create_test_node(ProxyProtocol::VMess);
        node.extra.uuid = Some("uuid-123".to_string());
        node.extra.tls = true;
        node.extra.sni = Some("example.com".to_string());
        let entry = mellow_proxy_entry(&node);
        assert!(entry.contains("type: vmess"));
        assert!(entry.contains("uuid: uuid-123"));
        assert!(entry.contains("tls: true"));
        assert!(entry.contains("sni: example.com"));
    }

    #[test]
    fn test_singbox_outbound_hysteria2() {
        let mut node = create_test_node(ProxyProtocol::Hysteria2);
        node.extra.hy2_password = Some("pass123".to_string());
        node.extra.sni = Some("example.com".to_string());
        let output = singbox_outbound(&node);
        assert_eq!(output["type"], "hysteria2");
        assert_eq!(output["password"], "pass123");
    }

    #[test]
    fn test_singbox_outbound_tuic() {
        let mut node = create_test_node(ProxyProtocol::Tuic);
        node.extra.tuic_uuid = Some("uuid-123".to_string());
        node.extra.tuic_password = Some("pass-456".to_string());
        node.extra.tuic_congestion_control = Some("bbr".to_string());
        let output = singbox_outbound(&node);
        assert_eq!(output["type"], "tuic");
        assert_eq!(output["uuid"], "uuid-123");
        assert_eq!(output["congestion_control"], "bbr");
    }

    #[test]
    fn test_singbox_outbound_wireguard() {
        let mut node = create_test_node(ProxyProtocol::WireGuard);
        node.extra.wg_private_key = Some("priv".to_string());
        node.extra.wg_public_key = Some("pub".to_string());
        node.extra.wg_mtu = Some(1280);
        node.extra.wg_addresses = vec!["10.0.0.1/32".to_string()];
        let output = singbox_outbound(&node);
        assert_eq!(output["type"], "wireguard");
        assert_eq!(output["private_key"], "priv");
        assert_eq!(output["peer_public_key"], "pub");
    }

    #[test]
    fn test_clash_proxy_entry_hysteria2_with_obfs() {
        // Test obfs optional field
        let mut node = create_test_node(ProxyProtocol::Hysteria2);
        node.extra.hy2_password = Some("pass123".to_string());
        node.extra.hy2_obfs = Some(" Loyola".to_string());
        node.extra.sni = Some("example.com".to_string());
        let entry = clash_proxy_entry(&node, false);
        // obfs value is " Loyola" (with leading space to match URI format)
        assert!(entry.contains("obfs:"));
    }

    #[test]
    fn test_clash_proxy_entry_tuic_with_sni() {
        // Test sni optional field for Tuic
        let mut node = create_test_node(ProxyProtocol::Tuic);
        node.extra.tuic_uuid = Some("uuid-123".to_string());
        node.extra.tuic_password = Some("pass-456".to_string());
        node.extra.tuic_congestion_control = Some("bbr".to_string());
        node.extra.sni = Some("custom.sni.com".to_string());
        let entry = clash_proxy_entry(&node, false);
        assert!(entry.contains("sni: custom.sni.com"));
    }

    #[test]
    fn test_clash_proxy_entry_wireguard_with_preshared_key() {
        // Test preshared_key optional field
        let mut node = create_test_node(ProxyProtocol::WireGuard);
        node.extra.wg_private_key = Some("priv".to_string());
        node.extra.wg_public_key = Some("pub".to_string());
        node.extra.wg_preshared_key = Some("psk123".to_string());
        let entry = clash_proxy_entry(&node, false);
        assert!(entry.contains("preshared_key: psk123"));
    }

    #[test]
    fn test_clash_proxy_entry_unknown_protocol() {
        // Test Unknown protocol fallback
        let node = create_test_node(ProxyProtocol::Unknown);
        let entry = clash_proxy_entry(&node, false);
        assert!(entry.contains("type: http"));
        assert!(entry.contains("server: example.com"));
        assert!(entry.contains("port: 443"));
    }

    #[test]
    fn test_singbox_outbound_vmess_with_ws() {
        let mut node = create_test_node(ProxyProtocol::VMess);
        node.extra.uuid = Some("uuid-123".to_string());
        node.extra.transport = Some(TransportType::WebSocket);
        let output = singbox_outbound(&node);
        assert_eq!(output["type"], "vmess");
        assert!(output["transport"].is_object());
    }

    #[test]
    fn test_singbox_outbound_vmess_with_http() {
        let mut node = create_test_node(ProxyProtocol::VMess);
        node.extra.uuid = Some("uuid-123".to_string());
        node.extra.transport = Some(TransportType::Http);
        let output = singbox_outbound(&node);
        assert_eq!(output["type"], "vmess");
        assert_eq!(output["transport"]["type"], "http");
    }

    #[test]
    fn test_singbox_outbound_vmess_with_grpc() {
        let mut node = create_test_node(ProxyProtocol::VMess);
        node.extra.uuid = Some("uuid-123".to_string());
        node.extra.transport = Some(TransportType::Grpc);
        let output = singbox_outbound(&node);
        assert_eq!(output["type"], "vmess");
        assert_eq!(output["transport"]["type"], "grpc");
    }

    #[test]
    fn test_singbox_outbound_vmess_with_tcp() {
        let mut node = create_test_node(ProxyProtocol::VMess);
        node.extra.uuid = Some("uuid-123".to_string());
        node.extra.transport = Some(TransportType::Tcp);
        let output = singbox_outbound(&node);
        assert_eq!(output["type"], "vmess");
        assert_eq!(output["transport"]["type"], "tcp");
    }

    #[test]
    fn test_singbox_outbound_vmess_with_tls() {
        // Test TLS enabled for VMess (in singbox_outbound for VMess)
        let mut node = create_test_node(ProxyProtocol::VMess);
        node.extra.uuid = Some("uuid-123".to_string());
        node.extra.tls = true;
        node.extra.sni = Some("example.com".to_string());
        let output = singbox_outbound(&node);
        assert_eq!(output["type"], "vmess");
        assert!(output["tls"].is_object());
        assert_eq!(output["tls"]["enabled"], true);
    }

    #[test]
    fn test_singbox_outbound_vless_with_tls() {
        // Test TLS enabled for VLESS (lines 292-296)
        let mut node = create_test_node(ProxyProtocol::VLESS);
        node.extra.vless_uuid = Some("uuid-123".to_string());
        node.extra.tls = true;
        node.extra.sni = Some("example.com".to_string());
        let output = singbox_outbound(&node);
        assert_eq!(output["type"], "vless");
        assert!(output["tls"].is_object());
        assert_eq!(output["tls"]["enabled"], true);
    }

    #[test]
    fn test_singbox_outbound_hysteria2_with_obfs() {
        // Test obfs optional field for Hysteria2 (lines 319-322)
        let mut node = create_test_node(ProxyProtocol::Hysteria2);
        node.extra.hy2_password = Some("pass123".to_string());
        node.extra.hy2_obfs = Some(" Loyola".to_string());
        node.extra.sni = Some("example.com".to_string());
        let output = singbox_outbound(&node);
        assert_eq!(output["type"], "hysteria2");
        assert!(output["obfs"].is_object());
    }

    #[test]
    fn test_singbox_outbound_tuic_with_sni() {
        // Test SNI optional field for TUIC (line 346)
        let mut node = create_test_node(ProxyProtocol::Tuic);
        node.extra.tuic_uuid = Some("uuid-123".to_string());
        node.extra.tuic_password = Some("pass-456".to_string());
        node.extra.sni = Some("custom.sni.com".to_string());
        let output = singbox_outbound(&node);
        assert_eq!(output["type"], "tuic");
        assert!(output["tls"].is_object());
        assert_eq!(output["tls"]["enabled"], true);
    }

    #[test]
    fn test_clash_proxy_entry_vmess_with_ws() {
        let mut node = create_test_node(ProxyProtocol::VMess);
        node.extra.uuid = Some("uuid-123".to_string());
        node.extra.transport = Some(TransportType::WebSocket);
        node.extra.tls = true;
        node.extra.sni = Some("example.com".to_string());
        let entry = clash_proxy_entry(&node, false);
        assert!(entry.contains("type: vmess"));
        assert!(entry.contains("ws-opts"));
        assert!(entry.contains("tls: true"));
    }

    #[test]
    fn test_clash_proxy_entry_vmess_with_http() {
        let mut node = create_test_node(ProxyProtocol::VMess);
        node.extra.uuid = Some("uuid-123".to_string());
        node.extra.transport = Some(TransportType::Http);
        let entry = clash_proxy_entry(&node, false);
        assert!(entry.contains("type: vmess"));
        assert!(entry.contains("http-opts"));
    }

    #[test]
    fn test_clash_proxy_entry_vmess_with_grpc() {
        let mut node = create_test_node(ProxyProtocol::VMess);
        node.extra.uuid = Some("uuid-123".to_string());
        node.extra.transport = Some(TransportType::Grpc);
        let entry = clash_proxy_entry(&node, false);
        assert!(entry.contains("type: vmess"));
        assert!(entry.contains("grpc-opts"));
    }

    #[test]
    fn test_clash_proxy_entry_vmess_with_tcp() {
        let mut node = create_test_node(ProxyProtocol::VMess);
        node.extra.uuid = Some("uuid-123".to_string());
        node.extra.transport = Some(TransportType::Tcp);
        let entry = clash_proxy_entry(&node, false);
        assert!(entry.contains("type: vmess"));
        assert!(entry.contains("network: tcp"));
        // Should not have ws-opts, http-opts, or grpc-opts
        assert!(!entry.contains("ws-opts"));
        assert!(!entry.contains("http-opts"));
        assert!(!entry.contains("grpc-opts"));
    }

    #[test]
    fn test_singbox_outbound_unknown() {
        let node = create_test_node(ProxyProtocol::Unknown);
        let output = singbox_outbound(&node);
        assert_eq!(output["type"], "http");
    }

    #[test]
    fn test_quantumult_entry_all_protocols() {
        let protocols = vec![
            ProxyProtocol::VMess,
            ProxyProtocol::Shadowsocks,
            ProxyProtocol::Trojan,
            ProxyProtocol::VLESS,
        ];
        for protocol in protocols {
            let node = create_test_node(protocol);
            let entry = quantumult_entry(&node);
            assert!(!entry.is_empty());
        }
    }

    #[test]
    fn test_loon_entry_all_protocols() {
        let protocols = vec![
            ProxyProtocol::VMess,
            ProxyProtocol::Shadowsocks,
            ProxyProtocol::Trojan,
        ];
        for protocol in protocols {
            let node = create_test_node(protocol);
            let entry = loon_entry(&node);
            assert!(!entry.is_empty());
        }
    }

    #[test]
    fn test_loon_entry_fallback_for_vless() {
        // VLESS falls through to the _ case
        let node = create_test_node(ProxyProtocol::VLESS);
        let entry = loon_entry(&node);
        assert!(entry.contains("vless"));
        assert!(entry.contains("example.com"));
        assert!(entry.contains("443"));
    }

    #[test]
    fn test_loon_entry_fallback_for_hysteria2() {
        let node = create_test_node(ProxyProtocol::Hysteria2);
        let entry = loon_entry(&node);
        assert!(entry.contains("hysteria2"));
    }

    #[test]
    fn test_surge_entry_all_protocols() {
        let protocols = vec![
            ProxyProtocol::VMess,
            ProxyProtocol::Shadowsocks,
            ProxyProtocol::Trojan,
            ProxyProtocol::VLESS,
        ];
        for protocol in protocols {
            let node = create_test_node(protocol);
            let entry = surge_entry(&node, crate::subconverter::SurgeVersion::V4);
            assert!(!entry.is_empty());
        }
    }

    #[test]
    fn test_v2ray_entry_trojan() {
        let mut node = create_test_node(ProxyProtocol::Trojan);
        node.extra.trojan_password = Some("pass123".to_string());
        let entry = v2ray_entry(&node, 0);
        assert!(entry.contains("trojan://"));
        assert!(entry.contains("pass123"));
    }

    #[test]
    fn test_v2ray_entry_vless() {
        let mut node = create_test_node(ProxyProtocol::VLESS);
        node.extra.vless_uuid = Some("uuid-123".to_string());
        let entry = v2ray_entry(&node, 0);
        assert!(entry.contains("vless://"));
    }

    #[test]
    fn test_v2ray_entry_vmess_with_http() {
        let mut node = create_test_node(ProxyProtocol::VMess);
        node.extra.uuid = Some("uuid-123".to_string());
        node.extra.transport = Some(TransportType::Http);
        let entry = v2ray_entry(&node, 0);
        // v2ray_entry returns base64-encoded JSON prepended with vmess://
        assert!(entry.starts_with("vmess://"));
    }

    #[test]
    fn test_v2ray_entry_vmess_with_grpc() {
        let mut node = create_test_node(ProxyProtocol::VMess);
        node.extra.uuid = Some("uuid-123".to_string());
        node.extra.transport = Some(TransportType::Grpc);
        let entry = v2ray_entry(&node, 0);
        assert!(entry.starts_with("vmess://"));
    }

    #[test]
    fn test_clash_proxy_entry_ss_with_2022_cipher() {
        let mut node = create_test_node(ProxyProtocol::Shadowsocks);
        node.extra.cipher = Some("2022-blake3-aes-256-gcm".to_string());
        node.extra.password = Some("password".to_string());
        let entry = clash_proxy_entry(&node, false);
        assert!(entry.contains("cipher: 2022-blake3-aes-256-gcm"));
        assert!(entry.contains("password: password"));
    }

    #[test]
    fn test_to_ssr_basic() {
        let mut node = create_test_node(ProxyProtocol::ShadowSocksR);
        node.extra.ssr_method = Some("aes-256-cfb".to_string());
        node.extra.password = Some("password123".to_string());
        node.extra.ssr_protocol = Some("origin".to_string());
        node.extra.ssr_obfs = Some("plain".to_string());
        node.extra.ssr_obfs_param = Some("".to_string());
        let output = to_ssr(&[node]);
        assert!(output.starts_with("ssr://"));
        // SSR format ends with: /<remarks>\n
        assert!(output.ends_with("\n"));
    }

    #[test]
    fn test_to_ssr_with_obfs() {
        let mut node = create_test_node(ProxyProtocol::ShadowSocksR);
        node.name = "TestSSR".to_string();
        node.extra.ssr_method = Some("chacha20-ietf".to_string());
        node.extra.password = Some("pass456".to_string());
        node.extra.ssr_protocol = Some("auth_chain_a".to_string());
        node.extra.ssr_obfs = Some("tls1.2-ticket_auth".to_string());
        node.extra.ssr_obfs_param = Some("obfs_param".to_string());
        let output = to_ssr(&[node]);
        assert!(output.starts_with("ssr://"));
    }

    #[test]
    fn test_convert_nodes_ssr_format() {
        let mut node = create_test_node(ProxyProtocol::ShadowSocksR);
        node.extra.ssr_method = Some("aes-256-cfb".to_string());
        node.extra.password = Some("password".to_string());
        node.extra.ssr_protocol = Some("origin".to_string());
        node.extra.ssr_obfs = Some("plain".to_string());
        let output = convert_nodes(&[node], TargetFormat::SSR);
        assert!(output.starts_with("ssr://"));
    }

    #[test]
    fn test_convert_clash_with_expand_false_no_rules() {
        let nodes = vec![create_test_node(ProxyProtocol::Trojan)];
        let output = convert_nodes_with_options(&nodes, TargetFormat::Clash, false, false, None);
        // Without expand, should not have rules section
        assert!(!output.contains("rules:"));
        assert!(!output.contains("rule-providers:"));
    }

    #[test]
    fn test_convert_clash_with_expand_true_has_rules() {
        let nodes = vec![create_test_node(ProxyProtocol::Trojan)];
        let output = convert_nodes_with_options(&nodes, TargetFormat::Clash, true, false, None);
        // With expand=true, should have rules section
        assert!(output.contains("rules:"));
        assert!(output.contains("rule-providers:"));
        assert!(output.contains("GEOIP,CN,DIRECT"));
    }

    #[test]
    fn test_convert_clash_with_classic_rules() {
        let nodes = vec![create_test_node(ProxyProtocol::Trojan)];
        let output = convert_nodes_with_options(&nodes, TargetFormat::Clash, true, true, None);
        // With classic=true, should have inline rules without rule-providers
        assert!(output.contains("rules:"));
        assert!(!output.contains("rule-providers:"));
        assert!(output.contains("GEOIP,CN,DIRECT"));
        assert!(output.contains("DOMAIN-SUFFIX,cn,DIRECT"));
    }

    #[test]
    fn test_convert_clash_with_expand_and_rule_providers() {
        let nodes = vec![create_test_node(ProxyProtocol::Trojan)];
        let output = convert_nodes_with_options(&nodes, TargetFormat::Clash, true, false, None);
        // With expand=true but classic=false, should have rule-providers
        assert!(output.contains("rule-providers:"));
        assert!(output.contains("direct:"));
        assert!(output.contains("china:"));
        assert!(output.contains("cncidr:"));
    }

    #[test]
    fn test_generate_classic_rules_contains_domains() {
        let rules = generate_classic_rules();
        assert!(rules.contains("rules:"));
        assert!(rules.contains("DOMAIN-SUFFIX,cn,DIRECT"));
        assert!(rules.contains("IP-CIDR,10.0.0.0/8,DIRECT"));
        assert!(rules.contains("GEOIP,CN,DIRECT"));
        assert!(rules.contains("MATCH,Auto"));
    }

    #[test]
    fn test_generate_rule_providers_contains_providers() {
        let rules = generate_rule_providers();
        assert!(rules.contains("rule-providers:"));
        assert!(rules.contains("behavior: domain"));
        assert!(rules.contains("behavior: ipcidr"));
        assert!(rules.contains("path: ./ruleset/"));
    }
}
