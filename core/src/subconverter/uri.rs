//! URI parsing for various proxy protocol schemes
//!
//! Supports: vmess://, ss://, ssr://, trojan://, vless://, hysteria2://, tuic://, wireguard://

use super::{ProxyExtra, ProxyNode, ProxyProtocol, TransportType};
use base64::Engine;

/// Parse a single URI into a ProxyNode
pub fn parse_uri(uri: &str) -> Option<ProxyNode> {
    let uri = uri.trim();

    if uri.starts_with("vmess://") {
        parse_vmess(uri)
    } else if uri.starts_with("ss://") {
        parse_ss(uri)
    } else if uri.starts_with("ssr://") {
        parse_ssr(uri)
    } else if uri.starts_with("trojan://") {
        parse_trojan(uri)
    } else if uri.starts_with("vless://") {
        parse_vless(uri)
    } else if uri.starts_with("hysteria2://") || uri.starts_with("hysteria://") {
        parse_hysteria2(uri)
    } else if uri.starts_with("tuic://") {
        parse_tuic(uri)
    } else if uri.starts_with("wireguard://") {
        parse_wireguard(uri)
    } else {
        None
    }
}

/// Padding-tolerant, alphabet-tolerant base64 decode. Share links arrive
/// URL-safe and/or unpadded from many panels and generators — a strict
/// STANDARD decode drops the whole node, which is exactly the mihomo
/// #3220 failure mode ("subscription parsing fails with the new share
/// links"): one new link form and the user sees no nodes at all.
fn b64_flex(data: &str) -> Option<Vec<u8>> {
    let cleaned: String = data.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(v) = base64::engine::general_purpose::STANDARD.decode(cleaned.as_bytes()) {
        return Some(v);
    }
    if let Ok(v) = base64::engine::general_purpose::URL_SAFE.decode(cleaned.as_bytes()) {
        return Some(v);
    }
    // Strip padding, normalize the alphabet, re-pad to a multiple of 4.
    let mut buf = String::with_capacity(cleaned.len() + 4);
    for c in cleaned.chars() {
        match c {
            '-' => buf.push('+'),
            '_' => buf.push('/'),
            '=' => {}
            other => buf.push(other),
        }
    }
    while !buf.len().is_multiple_of(4) {
        buf.push('=');
    }
    base64::engine::general_purpose::STANDARD.decode(buf.as_bytes()).ok()
}

/// Split `host:port` or `[ipv6]:port`. A bare `rsplit_once(':')` on an
/// IPv6 literal yields garbage ("server" keeps part of the address) —
/// the same #3220 class of "node silently dropped on a link form the
/// parser never saw".
pub(crate) fn split_host_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        Some((host.to_string(), port.parse().ok()?))
    } else {
        let (host, port) = s.rsplit_once(':')?;
        Some((host.to_string(), port.parse().ok()?))
    }
}

/// Parse VMess URI
/// Format: vmess://(base64(json))
/// JSON fields: v, ps, add, port, id, aid, net, cl, sl, sni, spx, tls
fn parse_vmess(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("vmess://")?;
    let json_str = b64_flex(data)?;
    let json_str = String::from_utf8(json_str).ok()?;

    let json: serde_json::Value = serde_json::from_str(&json_str).ok()?;

    let name = json["ps"].as_str().unwrap_or("VMess").to_string();
    let server = json["add"].as_str()?.to_string();
    let port = json["port"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(443);
    let uuid = json["id"].as_str()?.to_string();
    let alter_id = json["aid"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let net = json["net"].as_str().unwrap_or("tcp");
    let transport = match net {
        "ws" | "websocket" => TransportType::WebSocket,
        "h2" | "http" => TransportType::Http,
        "grpc" => TransportType::Grpc,
        _ => TransportType::Tcp,
    };

    let tls_str = json["tls"].as_str().unwrap_or("");
    let tls = !tls_str.is_empty() && tls_str != "none";

    let sni = json["sni"].as_str().map(|s| s.to_string());

    Some(ProxyNode {
        name,
        protocol: ProxyProtocol::VMess,
        server,
        port,
        extra: ProxyExtra {
            uuid: Some(uuid),
            alter_id: Some(alter_id),
            transport: Some(transport),
            tls,
            sni,
            ..Default::default()
        },
    })
}

/// Parse Shadowsocks URI (mihomo #3220: BOTH share-link shapes must
/// parse or a panel that switches forms drops the whole subscription):
///   SIP002:  ss://BASE64URL(method:password)@server:port#name
///            ss://method:password@server:port#name   (percent-encoded)
///   legacy:  ss://BASE64(method:password@server:port)#name
fn parse_ss(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("ss://")?;
    // The fragment (node name) is never part of any base64 payload.
    let (body, fragment) = data.split_once('#').unwrap_or((data, ""));
    let name = if fragment.is_empty() {
        "Shadowsocks".to_string()
    } else {
        urlencoding::decode(fragment).ok()?.to_string()
    };

    // userinfo@hostport, or the whole body base64'd (legacy form).
    let (userinfo, hostport): (String, String) = if let Some((ui, hp)) = body.rsplit_once('@') {
        (ui.to_string(), hp.to_string())
    } else {
        let decoded = b64_flex(body)?;
        let plain = String::from_utf8(decoded).ok()?;
        let (ui, hp) = plain.rsplit_once('@')?;
        (ui.to_string(), hp.to_string())
    };
    // Panels sometimes append query params after the port — never part
    // of the address.
    let hostport = hostport.split('?').next().unwrap_or(&hostport).to_string();
    let (server, port) = split_host_port(&hostport)?;

    // method:password — plain (percent-encoded) or base64'd userinfo.
    let plain_userinfo = if userinfo.contains(':') {
        urlencoding::decode(&userinfo).ok().map(String::from)
    } else {
        b64_flex(&userinfo).and_then(|b| String::from_utf8(b).ok())
    };
    let (cipher, password) = plain_userinfo
        .and_then(|plain| plain.split_once(':').map(|(c, p)| (c.to_string(), p.to_string())))?;

    Some(ProxyNode {
        name,
        protocol: ProxyProtocol::Shadowsocks,
        server,
        port,
        extra: ProxyExtra {
            cipher: Some(cipher),
            password: Some(password),
            ..Default::default()
        },
    })
}

/// Parse ShadowSocksR URI
/// Format: ssr://(base64(method:password:protocol:obfs:urlbase64(host:port:protocol_param:obfs_param)))/remarks
/// The SSR URI is NOT URL-encoded - it's plain base64 with a / separator for remarks
fn parse_ssr(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("ssr://")?;

    // Split by '/' only once to separate base64 data from remarks
    // The remarks part is optional and is also base64 encoded
    let (base64_part, remarks_part) = data.split_once('/').unwrap_or((data, ""));

    // Decode the main base64 part to get: method:password:protocol:obfs:urlbase64(host:port:protocol_param:obfs_param)
    let main_decoded = b64_flex(base64_part)?;
    let main_str = String::from_utf8(main_decoded).ok()?;

    // Split to get method:password:protocol:obfs:urlbase64
    let parts: Vec<&str> = main_str.split(':').collect();
    if parts.len() < 5 {
        return None;
    }

    let method = parts.first().unwrap_or(&"").to_string();
    let password = parts.get(1).unwrap_or(&"").to_string();
    let protocol = parts.get(2).unwrap_or(&"").to_string();
    let obfs = parts.get(3).unwrap_or(&"").to_string();
    let urlbase64 = parts.get(4).unwrap_or(&"");

    // Decode URL base64 to get host:port:protocol_param:obfs_param
    let url_decoded = b64_flex(urlbase64)?;
    let url_str = String::from_utf8(url_decoded).ok()?;

    // URL format: host:port:protocol_param:obfs_param
    let url_parts: Vec<&str> = url_str.split(':').collect();
    if url_parts.len() < 2 {
        return None;
    }

    let host = url_parts.first().unwrap_or(&"").to_string();
    let port_str = url_parts.get(1).unwrap_or(&"");
    let port: u16 = port_str.parse().ok()?;
    let _protocol_param = url_parts.get(2).map(|s| s.to_string()).unwrap_or_default();
    let obfs_param = url_parts.get(3).map(|s| s.to_string()).unwrap_or_default();

    // Parse remarks (base64 encoded name)
    let name = if remarks_part.is_empty() {
        "ShadowSocksR".to_string()
    } else {
        b64_flex(remarks_part)
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| "ShadowSocksR".to_string())
    };

    Some(ProxyNode {
        name,
        protocol: ProxyProtocol::ShadowSocksR,
        server: host,
        port,
        extra: ProxyExtra {
            cipher: Some(method.clone()),
            password: Some(password),
            ssr_protocol: Some(protocol),
            ssr_method: Some(method),
            ssr_obfs: Some(obfs),
            ssr_obfs_param: Some(obfs_param),
            ..Default::default()
        },
    })
}

/// Parse Trojan URI
/// Format: trojan://password@server:port#name?allowln=1&sni=example.com
fn parse_trojan(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("trojan://")?;
    let data = urlencoding::decode(data).ok()?.to_string();

    let (password, rest) = data.split_once('@')?;
    let (addr_port, name) = rest.split_once('#').unwrap_or((rest, ""));

    // addr_port might contain query params
    let addr_port = addr_port.split('?').next().unwrap_or(addr_port);
    let (server, port) = split_host_port(addr_port)?;

    let name = if name.is_empty() {
        "Trojan".to_string()
    } else {
        name.to_string()
    };

    Some(ProxyNode {
        name,
        protocol: ProxyProtocol::Trojan,
        server: server.to_string(),
        port,
        extra: ProxyExtra {
            trojan_password: Some(password.to_string()),
            ..Default::default()
        },
    })
}

/// Parse VLESS URI
/// Format: vless://uuid@server:port?encryption=none&flow=xtls-rprx-vision&sni=example.com#name
fn parse_vless(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("vless://")?;
    let data = urlencoding::decode(data).ok()?.to_string();

    let (uuid, rest) = data.split_once('@')?;
    let (addr_port, name) = rest.split_once('#').unwrap_or((rest, ""));

    // Parse query parameters
    let mut sni = None;
    let mut flow = None;
    let mut tls = false;
    let mut udp = None;

    if let Some(query_start) = addr_port.find('?') {
        let (host_port, query) = addr_port.split_at(query_start);
        for param in query.strip_prefix('?').unwrap_or("").split('&') {
            let (key, value) = param.split_once('=').unwrap_or((param, ""));
            match key {
                "sni" => sni = Some(value.to_string()),
                "flow" => flow = Some(value.to_string()),
                "tls" | "security" if value == "tls" || value == "xtls" => tls = true,
                "udp" => udp = Some(parse_udp_value(value)),
                _ => {}
            }
        }

        let (server, port) = split_host_port(host_port)?;

        let name = if name.is_empty() {
            "VLESS".to_string()
        } else {
            name.to_string()
        };

        return Some(ProxyNode {
            name,
            protocol: ProxyProtocol::VLESS,
            server: server.to_string(),
            port,
            extra: ProxyExtra {
                uuid: Some(uuid.to_string()),
                vless_uuid: Some(uuid.to_string()),
                vless_flow: flow,
                sni,
                tls,
                udp,
                ..Default::default()
            },
        });
    }

    let (server, port) = split_host_port(addr_port)?;

    let name = if name.is_empty() {
        "VLESS".to_string()
    } else {
        name.to_string()
    };

    Some(ProxyNode {
        name,
        protocol: ProxyProtocol::VLESS,
        server: server.to_string(),
        port,
        extra: ProxyExtra {
            uuid: Some(uuid.to_string()),
            vless_uuid: Some(uuid.to_string()),
            vless_flow: flow,
            sni,
            tls,
            udp,
            ..Default::default()
        },
    })
}

/// Parse Hysteria2 URI
/// Format: hysteria2://password@server:port?obfs= Loyola&obfs-password=xxx&sni=example.com#name
/// Or (older): hysteria://password@server:port
fn parse_hysteria2(uri: &str) -> Option<ProxyNode> {
    let data = uri
        .strip_prefix("hysteria2://")
        .or_else(|| uri.strip_prefix("hysteria://"))?;
    let data = urlencoding::decode(data).ok()?.to_string();

    let (password, rest) = data.split_once('@')?;
    let (addr_port, name) = rest.split_once('#').unwrap_or((rest, ""));

    // Parse query parameters
    let mut obfs = None;
    let mut _obfs_password = None;
    let mut sni = None;
    let mut udp = None;
    let mut server_part = addr_port;

    if let Some(query_start) = addr_port.find('?') {
        server_part = &addr_port[..query_start];
        let query = &addr_port[query_start + 1..];
        for param in query.split('&') {
            let (key, value) = param.split_once('=').unwrap_or((param, ""));
            match key {
                "obfs" => obfs = Some(value.to_string()),
                "obfs-password" => _obfs_password = Some(value.to_string()),
                "sni" => sni = Some(value.to_string()),
                "udp" => udp = Some(parse_udp_value(value)),
                _ => {}
            }
        }
    }

    let (server, port) = split_host_port(server_part)?;

    let name = if name.is_empty() {
        "Hysteria2".to_string()
    } else {
        name.to_string()
    };

    Some(ProxyNode {
        name,
        protocol: ProxyProtocol::Hysteria2,
        server: server.to_string(),
        port,
        extra: ProxyExtra {
            hy2_password: Some(password.to_string()),
            hy2_obfs: obfs,
            sni,
            udp,
            ..Default::default()
        },
    })
}

/// Parse TUIC URI
/// Format: tuic://uuid:password@server:port?congestion_control=bbr&udp_relay_mode=native&sni=example.com#name
fn parse_tuic(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("tuic://")?;
    let data = urlencoding::decode(data).ok()?.to_string();

    // Split userinfo and rest
    let (userinfo, rest) = data.split_once('@')?;
    let (userinfo_part, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let uuid = userinfo_part;

    let (addr_port, name) = rest.split_once('#').unwrap_or((rest, ""));

    // Parse query parameters
    let mut congestion_control = None;
    let mut sni = None;
    let mut server_part = addr_port;

    if let Some(query_start) = addr_port.find('?') {
        server_part = &addr_port[..query_start];
        let query = &addr_port[query_start + 1..];
        for param in query.split('&') {
            let (key, value) = param.split_once('=').unwrap_or((param, ""));
            match key {
                "congestion_control" => congestion_control = Some(value.to_string()),
                "sni" => sni = Some(value.to_string()),
                _ => {}
            }
        }
    }

    let (server, port) = split_host_port(server_part)?;

    let name = if name.is_empty() {
        "TUIC".to_string()
    } else {
        name.to_string()
    };

    Some(ProxyNode {
        name,
        protocol: ProxyProtocol::Tuic,
        server: server.to_string(),
        port,
        extra: ProxyExtra {
            tuic_uuid: Some(uuid.to_string()),
            tuic_password: Some(password.to_string()),
            tuic_congestion_control: congestion_control,
            sni,
            ..Default::default()
        },
    })
}

/// Parse WireGuard URI
/// Format: wireguard://private_key=xxx&peer_public_key=xxx&preshared_key=xxx&endpoint=server:port&mtu=1280&allowed_ips=0.0.0.0/0#name
fn parse_wireguard(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("wireguard://")?;
    let data = urlencoding::decode(data).ok()?.to_string();

    let (params, name) = data.split_once('#').unwrap_or((&data, ""));

    let mut private_key = None;
    let mut public_key = None;
    let mut preshared_key = None;
    let mut endpoint = None;
    let mut mtu = None;
    let mut addresses = Vec::new();

    for param in params.split('&') {
        let (key, value) = param.split_once('=').unwrap_or((param, ""));
        match key {
            "private_key" => private_key = Some(value.to_string()),
            "peer_public_key" | "public_key" => public_key = Some(value.to_string()),
            "preshared_key" => preshared_key = Some(value.to_string()),
            "endpoint" => endpoint = Some(value.to_string()),
            "mtu" => mtu = value.parse().ok(),
            "allowed_ips" => {
                for cidr in value.split(',') {
                    addresses.push(cidr.to_string());
                }
            }
            _ => {}
        }
    }

    // Extract server and port from endpoint if present
    let (server, port) = if let Some(ref ep) = endpoint {
        match split_host_port(ep) {
            Some((s, p)) => (s, p),
            // Port-less endpoint: the WireGuard default port.
            None if !ep.contains(':') => (ep.to_string(), 51820),
            None => return None,
        }
    } else {
        return None; // WireGuard requires endpoint
    };

    let name = if name.is_empty() {
        "WireGuard".to_string()
    } else {
        name.to_string()
    };

    Some(ProxyNode {
        name,
        protocol: ProxyProtocol::WireGuard,
        server,
        port,
        extra: ProxyExtra {
            wg_private_key: private_key,
            wg_public_key: public_key,
            wg_preshared_key: preshared_key,
            wg_endpoint: endpoint,
            wg_mtu: mtu,
            wg_addresses: addresses,
            ..Default::default()
        },
    })
}

/// Parse multiple URIs from a URI list string
pub fn parse_uri_list(content: &str) -> Vec<ProxyNode> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                None
            } else {
                parse_uri(line)
            }
        })
        .collect()
}

/// Interpret a `udp=` query value: 1/true -> Some(true), 0/false -> Some(false).
fn parse_udp_value(value: &str) -> bool {
    matches!(value, "1" | "true")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_vmess() {
        // This is a real vmess URI (dummy values)
        let uri = "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjZCIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInRscyI6InRscyJ9";
        let node = parse_vmess(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::VMess);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
    }

    #[test]
    fn test_parse_vmess_with_http_transport() {
        // VMess with net=h2 (HTTP/2 transport) - covers line 50
        let json = json!({
            "v": "2",
            "ps": "test-http",
            "add": "1.2.3.4",
            "port": "443",
            "id": "12345678-1234-1234-1234-123456789012",
            "net": "h2"
        });
        let uri = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json.to_string().as_bytes())
        );
        let node = parse_vmess(&uri).unwrap();
        assert_eq!(node.extra.transport, Some(TransportType::Http));
    }

    #[test]
    fn test_parse_vmess_with_grpc_transport() {
        // VMess with net=grpc transport - covers line 51
        let json = json!({
            "v": "2",
            "ps": "test-grpc",
            "add": "1.2.3.4",
            "port": "443",
            "id": "12345678-1234-1234-1234-123456789012",
            "net": "grpc"
        });
        let uri = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json.to_string().as_bytes())
        );
        let node = parse_vmess(&uri).unwrap();
        assert_eq!(node.extra.transport, Some(TransportType::Grpc));
    }

    #[test]
    fn test_parse_vmess_with_unknown_transport() {
        // VMess with unknown net field should fall back to Tcp - covers line 52
        let json = json!({
            "v": "2",
            "ps": "test-unknown",
            "add": "1.2.3.4",
            "port": "443",
            "id": "12345678-1234-1234-1234-123456789012",
            "net": "unknown-transport"
        });
        let uri = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json.to_string().as_bytes())
        );
        let node = parse_vmess(&uri).unwrap();
        // Unknown transport should result in Tcp (the default)
        assert_eq!(node.extra.transport, Some(TransportType::Tcp));
    }

    #[test]
    fn test_parse_trojan() {
        let uri = "trojan://password123@example.com:443#Test-Trojan";
        let node = parse_trojan(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Trojan);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.extra.trojan_password.as_deref(), Some("password123"));
    }

    #[test]
    fn test_parse_vless() {
        let uri = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?flow=xtls-rprx-vision&sni=example.com#Test-VLESS";
        let node = parse_vless(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::VLESS);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
        // No udp param: defaults apply at filter time (None).
        assert_eq!(node.extra.udp, None);
    }

    #[test]
    fn test_parse_vless_udp_flag() {
        let uri = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?udp=1#VLESS-UDP";
        let node = parse_vless(uri).unwrap();
        assert_eq!(node.extra.udp, Some(true));

        let uri = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?udp=0#VLESS-NoUDP";
        let node = parse_vless(uri).unwrap();
        assert_eq!(node.extra.udp, Some(false));
    }

    #[test]
    fn test_parse_hysteria2_udp_flag() {
        let uri = "hysteria2://pass@example.com:443?obfs=salamander&udp=true#HY2";
        let node = parse_uri(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(node.extra.udp, Some(true));
    }

    #[test]
    fn test_parse_vless_with_security_xtls() {
        // VLESS with security=xtls query param - covers line 176
        let uri = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=xtls&sni=example.com#Test-VLESS-XTLS";
        let node = parse_vless(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::VLESS);
        assert!(node.extra.tls);
    }

    #[test]
    fn test_parse_uri_list() {
        // Valid base64 for "badbadbd:password123" (18 chars = 24 base64 chars with padding)
        let content = r#"
# Comment line
vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjZCIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInRscyI6InRscyJ9
trojan://password123@example.com:443#Test-Trojan

ss://YmFkYmFkYmQ6cGFzc3dvcmQxMjM=@192.168.1.1:8388#Test-SS
"#;
        let nodes = parse_uri_list(content);
        assert_eq!(nodes.len(), 3);
    }

    #[test]
    fn test_parse_hysteria2() {
        // hysteria2://password@server:port?obfs= Loyola&sni=example.com#name
        let uri =
            "hysteria2://password123@example.com:443?obfs=simpla&sni=example.com#Test-Hysteria2";
        let node = parse_hysteria2(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.extra.hy2_password.as_deref(), Some("password123"));
        assert_eq!(node.extra.hy2_obfs.as_deref(), Some("simpla"));
        assert_eq!(node.extra.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_parse_hysteria2_simple() {
        // Without obfs and sni
        let uri = "hysteria2://password123@example.com:443#Simple";
        let node = parse_hysteria2(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(node.name, "Simple");
        assert_eq!(node.extra.hy2_password.as_deref(), Some("password123"));
    }

    #[test]
    fn test_parse_tuic() {
        // tuic://uuid:password@server:port?congestion_control=bbr&sni=example.com#name
        let uri = "tuic://550e8400-e29b-41d4-a716-446655440000:password123@example.com:443?congestion_control=bbr&sni=example.com#Test-TUIC";
        let node = parse_tuic(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Tuic);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
        assert_eq!(
            node.extra.tuic_uuid.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(node.extra.tuic_password.as_deref(), Some("password123"));
        assert_eq!(node.extra.tuic_congestion_control.as_deref(), Some("bbr"));
        assert_eq!(node.extra.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_parse_wireguard() {
        // wireguard://private_key=xxx&peer_public_key=xxx&endpoint=server:port&mtu=1280&allowed_ips=0.0.0.0/0#name
        let uri = "wireguard://private_key=YGJhYmNkZWYxMjM0NTY3ODlhYmNkZWYxMjM0NTY3ODk=&peer_public_key=aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDEF=&endpoint=example.com:51820&mtu=1280&allowed_ips=0.0.0.0/0,::/0#Test-WG";
        let node = parse_wireguard(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::WireGuard);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 51820);
        assert!(node.extra.wg_private_key.is_some());
        assert!(node.extra.wg_public_key.is_some());
        assert_eq!(node.extra.wg_mtu, Some(1280));
    }

    #[test]
    fn test_parse_wireguard_without_optional_params() {
        let uri = "wireguard://private_key=abc123&peer_public_key=xyz789&endpoint=192.168.1.1:51820#Min-WG";
        let node = parse_wireguard(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::WireGuard);
        assert_eq!(node.server, "192.168.1.1");
        assert_eq!(node.port, 51820);
    }

    #[test]
    fn test_parse_wireguard_without_endpoint() {
        // WireGuard without endpoint should return None - covers line 361
        let uri = "wireguard://private_key=abc123&peer_public_key=xyz789#No-Endpoint";
        let node = parse_wireguard(uri);
        assert!(node.is_none());
    }

    #[test]
    fn test_parse_unsupported_uri() {
        // Unknown scheme should return None
        let uri = "unknown://something";
        assert!(parse_uri(uri).is_none());
    }

    #[test]
    fn test_parse_uri_with_vless() {
        // Test that parse_uri correctly dispatches to parse_vless
        let uri = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?flow=xtls-rprx-vision&sni=example.com#Test-VLESS";
        let node = parse_uri(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::VLESS);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
    }

    #[test]
    fn test_parse_vless_without_query_params() {
        // VLESS without query parameters (second code path)
        let uri = "vless://12345678-1234-1234-1234-123456789abc@example.com:443#NoParams";
        let node = parse_vless(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::VLESS);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
        assert!(node.extra.vless_flow.is_none());
        assert!(!node.extra.tls);
    }

    #[test]
    fn test_parse_uri_with_hysteria2() {
        let uri =
            "hysteria2://password123@example.com:443?obfs=simpla&sni=example.com#Test-Hysteria2";
        let node = parse_uri(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
    }

    #[test]
    fn test_parse_uri_with_tuic() {
        let uri = "tuic://550e8400-e29b-41d4-a716-446655440000:password123@example.com:443?congestion_control=bbr&sni=example.com#Test-TUIC";
        let node = parse_uri(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Tuic);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
    }

    #[test]
    fn test_parse_uri_with_wireguard() {
        let uri = "wireguard://private_key=abc123&peer_public_key=xyz789&endpoint=192.168.1.1:51820#Min-WG";
        let node = parse_uri(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::WireGuard);
        assert_eq!(node.server, "192.168.1.1");
        assert_eq!(node.port, 51820);
    }

    #[test]
    fn test_parse_ss_with_base64_encoded_userinfo() {
        // ss:// with base64 encoded userinfo (for @2022-... format)
        // chacha20:password encoded in base64 = Y2hhY2hhMjA6cGFzc3dvcmQ=
        let uri = "ss://Y2hhY2hhMjA6cGFzc3dvcmQ=@192.168.1.1:8388#TestNode";
        let node = parse_ss(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Shadowsocks);
        assert_eq!(node.server, "192.168.1.1");
        assert_eq!(node.port, 8388);
        assert_eq!(node.extra.cipher.as_deref(), Some("chacha20"));
        assert_eq!(node.extra.password.as_deref(), Some("password"));
    }

    #[test]
    fn test_parse_ss_with_invalid_base64() {
        // Invalid base64 should return None
        let uri = "ss://!!!invalid!!!@192.168.1.1:8388";
        assert!(parse_ss(uri).is_none());
    }

    #[test]
    fn test_parse_ss_with_empty_name() {
        // No name after # should default to "Shadowsocks"
        let uri = "ss://chacha20:password@192.168.1.1:8388";
        let node = parse_ss(uri).unwrap();
        assert_eq!(node.name, "Shadowsocks");
    }

    #[test]
    fn test_parse_ss_with_base64_non_utf8() {
        // Valid base64 but decodes to non-UTF-8 bytes - covers line 105-106
        // Create a valid base64 that decodes to invalid UTF-8
        // 0x80 is not a valid UTF-8 start byte
        let encoded = "gICAgA=="; // base64 of [0x80, 0x80, 0x80, 0x80]
        let uri = format!("ss://{}@192.168.1.1:8388#Test", encoded);
        let node = parse_ss(&uri);
        // Non-UTF-8 base64 decode should return None
        assert!(node.is_none());
    }

    #[test]
    fn test_parse_hysteria_without_2_suffix() {
        // hysteria:// (without 2) should also be supported
        let uri = "hysteria://password@example.com:443";
        let node = parse_hysteria2(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
    }

    #[test]
    fn test_parse_uri_whitespace_only() {
        // Whitespace only input should return None
        assert!(parse_uri("   ").is_none());
        assert!(parse_uri("").is_none());
    }

    #[test]
    fn test_parse_ss_with_2022_cipher() {
        // Shadowsocks with 2022 cipher
        let uri = "ss://2022-blake3-aes-256-gcm:password@192.168.1.1:8388#Test2022";
        let node = parse_ss(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Shadowsocks);
        assert_eq!(
            node.extra.cipher.as_deref(),
            Some("2022-blake3-aes-256-gcm")
        );
    }

    #[test]
    fn test_parse_ssr_basic() {
        // Build a real SSR URI
        // method:password:protocol:obfs:urlbase64(host:port:protocol_param:obfs_param)
        // Example: aes-256-cfb:password123:origin:plain:btoa("example.com:443::")
        let url_part = base64::engine::general_purpose::STANDARD.encode(b"example.com:443::");
        let first_part = format!("aes-256-cfb:password123:origin:plain:{}", url_part);
        let first_encoded = base64::engine::general_purpose::STANDARD.encode(first_part.as_bytes());
        let remarks = base64::engine::general_purpose::STANDARD.encode(b"Test-SSR");
        let uri = format!("ssr://{}/{}", first_encoded, remarks);

        let node = parse_ssr(&uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::ShadowSocksR);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.name, "Test-SSR");
        assert_eq!(node.extra.ssr_method.as_deref(), Some("aes-256-cfb"));
        assert_eq!(node.extra.password.as_deref(), Some("password123"));
        assert_eq!(node.extra.ssr_protocol.as_deref(), Some("origin"));
        assert_eq!(node.extra.ssr_obfs.as_deref(), Some("plain"));
    }

    #[test]
    fn test_parse_ssr_with_obfs_param() {
        // SSR with obfs parameters
        let url_part =
            base64::engine::general_purpose::STANDARD.encode(b"192.168.1.1:8080::obfs_param");
        let first_part = format!(
            "chacha20-ietf:pass456:auth_chain_a:tls1.2-ticket_auth:{}",
            url_part
        );
        let first_encoded = base64::engine::general_purpose::STANDARD.encode(first_part.as_bytes());
        let remarks = base64::engine::general_purpose::STANDARD.encode(b"MySSRNode");
        let uri = format!("ssr://{}/{}", first_encoded, remarks);

        let node = parse_ssr(&uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::ShadowSocksR);
        assert_eq!(node.server, "192.168.1.1");
        assert_eq!(node.port, 8080);
        assert_eq!(node.extra.ssr_method.as_deref(), Some("chacha20-ietf"));
        assert_eq!(node.extra.ssr_protocol.as_deref(), Some("auth_chain_a"));
        assert_eq!(node.extra.ssr_obfs.as_deref(), Some("tls1.2-ticket_auth"));
        assert_eq!(node.extra.ssr_obfs_param.as_deref(), Some("obfs_param"));
    }

    #[test]
    fn test_parse_ssr_without_remarks() {
        // SSR URI without remarks part
        let url_part = base64::engine::general_purpose::STANDARD.encode(b"example.com:443::");
        let first_part = format!("aes-256-cfb:password123:origin:plain:{}", url_part);
        let first_encoded = base64::engine::general_purpose::STANDARD.encode(first_part.as_bytes());
        let uri = format!("ssr://{}/", first_encoded);

        let node = parse_ssr(&uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::ShadowSocksR);
        assert_eq!(node.name, "ShadowSocksR");
    }

    #[test]
    fn test_parse_uri_with_ssr() {
        // Test parse_uri dispatch for SSR
        let url_part = base64::engine::general_purpose::STANDARD.encode(b"example.com:443::");
        let first_part = format!("aes-256-cfb:password123:origin:plain:{}", url_part);
        let first_encoded = base64::engine::general_purpose::STANDARD.encode(first_part.as_bytes());
        let remarks = base64::engine::general_purpose::STANDARD.encode(b"TestSSR");
        let uri = format!("ssr://{}/{}", first_encoded, remarks);

        let node = parse_uri(&uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::ShadowSocksR);
        assert_eq!(node.server, "example.com");
    }

    // ============== mihomo #3220: share-link robustness ==============

    #[test]
    fn test_ss_legacy_full_base64_form() {
        // Panels (and Xray-based generators) emit the legacy form where
        // the WHOLE method:password@host:port is base64'd — the old
        // parser required an '@' in the plain text and dropped the node.
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(b"aes-256-gcm:testpassword@10.2.3.4:8388");
        let uri = format!("ss://{encoded}#Legacy%20Node");
        let node = parse_uri(&uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Shadowsocks);
        assert_eq!(node.server, "10.2.3.4");
        assert_eq!(node.port, 8388);
        assert_eq!(node.extra.cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(node.extra.password.as_deref(), Some("testpassword"));
        assert_eq!(node.name, "Legacy Node");
    }

    #[test]
    fn test_ss_unpadded_urlsafe_userinfo() {
        // Unpadded URL-safe base64 userinfo (SIP002 as many generators
        // emit it) must not kill the node.
        let mut encoded = base64::engine::general_purpose::URL_SAFE
            .encode(b"aes-128-gcm:pw123")
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_");
        encoded = encoded.trim_end_matches('=').to_string();
        let uri = format!("ss://{encoded}@example.org:9999#Edge");
        let node = parse_uri(&uri).unwrap();
        assert_eq!(node.server, "example.org");
        assert_eq!(node.port, 9999);
        assert_eq!(node.extra.cipher.as_deref(), Some("aes-128-gcm"));
        assert_eq!(node.extra.password.as_deref(), Some("pw123"));
    }

    #[test]
    fn test_ss_plain_percent_encoded_userinfo() {
        // Plain userinfo where the password carries an encoded '@' and
        // ':' — split on the LAST '@', decode AFTER splitting.
        let uri = "ss://2022-blake3-aes-256-gcm:p%40ss%3Aword@1.2.3.4:443#Node";
        let node = parse_uri(uri).unwrap();
        assert_eq!(node.server, "1.2.3.4");
        assert_eq!(node.port, 443);
        assert_eq!(node.extra.cipher.as_deref(), Some("2022-blake3-aes-256-gcm"));
        assert_eq!(node.extra.password.as_deref(), Some("p@ss:word"));
    }

    #[test]
    fn test_ipv6_bracket_hosts_parse() {
        // The "new link form" class: an IPv6 node drops silently when
        // host:port is split on the last ':'.
        let vless = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::10]:443?sni=v6.example.com&security=tls#V6";
        let node = parse_uri(vless).unwrap();
        assert_eq!(node.server, "2001:db8::10");
        assert_eq!(node.port, 443);
        assert_eq!(node.extra.sni.as_deref(), Some("v6.example.com"));
        assert!(node.extra.tls);

        let trojan = "trojan://pw@[fd00::1]:443#T6";
        let node = parse_uri(trojan).unwrap();
        assert_eq!(node.server, "fd00::1");
        assert_eq!(node.port, 443);
    }

    #[test]
    fn test_vmess_unpadded_link() {
        // Subscription providers emit vmess:// links without base64
        // padding — strict decode dropped every node in the list.
        let json = r#"{"v":"2","ps":"NoPad","add":"np.example.com","port":"8443","id":"12345678-1234-1234-1234-123456789012","aid":"0","net":"tcp","tls":"tls"}"#;
        let mut encoded = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        while encoded.ends_with('=') {
            encoded.pop();
        }
        let node = parse_uri(&format!("vmess://{encoded}")).unwrap();
        assert_eq!(node.server, "np.example.com");
        assert_eq!(node.port, 8443);
        assert_eq!(node.name, "NoPad");
        assert!(node.extra.tls);
    }

    #[test]
    fn test_vless_unknown_params_are_ignored_not_fatal() {
        // The literal #3220 shape: a generator adds NEW query params with
        // a new release — unknown keys must not fail the parse.
        let uri = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@gen.example.com:443?encryption=none&flow=xtls-rprx-vision&sni=gen.example.com&security=tls&newParam2699=whatever&another=1#Gen";
        let node = parse_uri(uri).unwrap();
        assert_eq!(node.server, "gen.example.com");
        assert_eq!(node.extra.vless_flow.as_deref(), Some("xtls-rprx-vision"));
        assert!(node.extra.tls);
    }

    #[test]
    fn test_host_port_split_forms() {
        assert_eq!(split_host_port("a.example.com:443").unwrap(), ("a.example.com".into(), 443));
        assert_eq!(split_host_port("[2001:db8::1]:8443").unwrap(), ("2001:db8::1".into(), 8443));
        assert!(split_host_port("no-port.example.com").is_none());
        assert!(split_host_port("[2001:db8::1]:notaport").is_none());
        assert!(split_host_port("[2001:db8::1]443").is_none());
    }
}
