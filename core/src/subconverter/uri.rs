//! URI parsing for various proxy protocol schemes
//!
//! Supports: vmess://, ss://, ssr://, trojan://, vless://, hysteria2://
//! (hy2://, hysteria://), tuic://, wireguard://
//!
//! The accepted share-link shapes are verified against the reference
//! implementations users actually paste links from — mihomo
//! `common/convert/converter.go` + `v.go` (handleVShareLink,
//! splitHysteria2Ports, uniqueName) and tindy2013/subconverter
//! `src/parser/subparser.cpp` (explodeSS/explodeSSR/explodeHysteria2) —
//! cached under /tmp/wave17-upstream. Notably: mihomo has NO URI
//! constructors in adapter/outbound/*.go; all link handling lives in
//! common/convert, and neither project defines a wireguard:// share
//! link (ours is a local extension kept for CLI convenience).

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
    } else if uri.starts_with("hysteria2://")
        || uri.starts_with("hy2://")
        || uri.starts_with("hysteria://")
    {
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

/// Lenient percent-decode: a stray `%` or invalid sequence degrades to the
/// raw text instead of dropping the node (Go's url.PathUnescape behavior
/// that mihomo inherits).
fn pct_decode(s: &str) -> String {
    urlencoding::decode(s)
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| s.to_string())
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
        Some((host.to_string(), valid_port(port)?))
    } else {
        let (host, port) = s.rsplit_once(':')?;
        Some((host.to_string(), valid_port(port)?))
    }
}

/// A dialable port: parses as u16 and is non-zero (port 0 is never a
/// real node — silently keeping it would emit a broken config).
fn valid_port(s: &str) -> Option<u16> {
    let p: u16 = s.parse().ok()?;
    (p != 0).then_some(p)
}

/// The authority portion of every `scheme://userinfo@host:port/path?query`
/// share link (mihomo feeds `net/url.Parse` the same pieces). The splits
/// happen on the RAW (still percent-encoded) text so a password carrying
/// `%40` / `%23` / `%3F` cannot move a delimiter; components are decoded
/// afterwards, individually. The URI path (usually just `/`) is never
/// part of the address and is stripped here.
struct ShareLinkParts<'a> {
    userinfo: &'a str,
    hostport: &'a str,
    query: &'a str,
    fragment: &'a str,
}

fn split_share_link(data: &str) -> Option<ShareLinkParts<'_>> {
    // Fragment first ('?' inside a fragment belongs to the fragment).
    let (head, fragment) = data.split_once('#').unwrap_or((data, ""));
    // Then the query ('@' inside a query value cannot move the userinfo).
    let (authority, query) = head.split_once('?').unwrap_or((head, ""));
    // Go's url.Parse splits the userinfo at the LAST '@'.
    let (userinfo, hostport) = authority.rsplit_once('@')?;
    // Drop any trailing path — hysteria2's official scheme is
    // `hysteria2://auth@host:port/?params` and SIP002 allows `/?plugin=`.
    let hostport = hostport.split('/').next().unwrap_or(hostport);
    Some(ShareLinkParts {
        userinfo,
        hostport,
        query,
        fragment,
    })
}

/// Percent-decoded key=value pairs. Matches Go `url.Query()`: `+` is a
/// space in keys and values (encoded `+` travels as `%2B`).
fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|param| {
            let (key, value) = param.split_once('=').unwrap_or((param, ""));
            let plus_to_space = |s: &str| s.replace('+', " ");
            (
                pct_decode(&plus_to_space(key)),
                pct_decode(&plus_to_space(value)),
            )
        })
        .collect()
}

/// `security=`/`tls=` semantics shared by the Xray VLESS/VMessAEAD links
/// (mihomo v.go: `HasSuffix(tls, "tls") || tls == "reality"`).
fn security_enables_tls(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    v.ends_with("tls") || v == "reality" || v == "1" || v == "true"
}

/// Xray `type=`/vmess `net=` transport names → our transport enum.
/// `httpupgrade` is a ws flavor (mihomo groups it under ws-opts), `h2`
/// and `http` both ride HTTP/2, `xhttp`/unknown fall back to Tcp so the
/// node survives instead of being dropped.
fn transport_from_name(net: &str) -> TransportType {
    match net.to_ascii_lowercase().as_str() {
        "ws" | "websocket" | "httpupgrade" => TransportType::WebSocket,
        "h2" | "http" => TransportType::Http,
        "grpc" => TransportType::Grpc,
        _ => TransportType::Tcp,
    }
}

/// Parse VMess URI. Two real-world shapes (mihomo converter.go `case
/// "vmess"`):
///   1. V2RayN JSON: `vmess://BASE64({"v","ps","add","port","id","aid","scy","net","path","host","tls","sni",...})`
///      — `port`/`aid` arrive as strings OR numbers depending on the
///      generator; `tls` is a string ("tls"/"none") or a bool.
///   2. Xray VMessAEAD: `vmess://uuid@host:port?security=tls&type=ws&sni=...#name`
///      — v2rayN 6.x emits these for AEAD servers; mihomo falls back to
///      handleVShareLink when the base64 decode fails.
fn parse_vmess(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("vmess://")?;
    if data.contains('@') {
        // Base64 never contains '@' — this is the AEAD URL form.
        return parse_vmess_aead(data);
    }
    let json_str = b64_flex(data)?;
    let json_str = String::from_utf8(json_str).ok()?;

    let json: serde_json::Value = serde_json::from_str(&json_str).ok()?;

    let name = json["ps"].as_str().unwrap_or("VMess").to_string();
    let server = json["add"].as_str()?.to_string();
    // JSON number or string — panels emit both. Out-of-range ports drop
    // the node rather than truncating to a wrong port.
    let port = json_u16(&json["port"])?;
    let uuid = json["id"].as_str()?.to_string();
    let alter_id = json_u16(&json["aid"]).unwrap_or(0);

    let transport = Some(transport_from_name(json["net"].as_str().unwrap_or("tcp")));

    // `"tls":"tls"` / `"tls":"xtls"` / `"tls":true`; absent/"none" → off.
    let tls = match &json["tls"] {
        serde_json::Value::String(s) => {
            let s = s.to_ascii_lowercase();
            s.ends_with("tls")
        }
        serde_json::Value::Bool(b) => *b,
        _ => false,
    };

    let sni = json["sni"].as_str().map(|s| s.to_string());

    Some(ProxyNode {
        name,
        protocol: ProxyProtocol::VMess,
        server,
        port,
        extra: ProxyExtra {
            uuid: Some(uuid),
            alter_id: Some(alter_id),
            transport,
            tls,
            sni,
            ..Default::default()
        },
    })
}

/// JSON field as u64 whether the generator wrote `"port": "8443"` or
/// `"port": 8443`.
fn json_u64(v: &serde_json::Value) -> Option<u64> {
    match v {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Range-checked variant for port/alterId.
fn json_u16(v: &serde_json::Value) -> Option<u16> {
    json_u64(v).and_then(|x| u16::try_from(x).ok())
}

/// Xray VMessAEAD form: `vmess://uuid@host:port?encryption=auto&security=tls&type=ws&host=..&path=..#name`
fn parse_vmess_aead(data: &str) -> Option<ProxyNode> {
    let parts = split_share_link(data)?;
    let uuid = pct_decode(parts.userinfo);
    let (server, port) = split_host_port(parts.hostport)?;

    let mut tls = false;
    let mut sni = None;
    let mut transport = None;
    for (key, value) in parse_query(parts.query) {
        match key.as_str() {
            "security" | "tls" => {
                if security_enables_tls(&value) {
                    tls = true;
                }
            }
            "sni" => sni = Some(value),
            "type" | "net" => transport = Some(transport_from_name(&value)),
            _ => {}
        }
    }

    Some(ProxyNode {
        name: fragment_name(parts.fragment, "VMess"),
        protocol: ProxyProtocol::VMess,
        server,
        port,
        extra: ProxyExtra {
            uuid: Some(uuid),
            alter_id: Some(0),
            transport,
            tls,
            sni,
            ..Default::default()
        },
    })
}

/// Fragment (node name) or the protocol default.
fn fragment_name(fragment: &str, default: &str) -> String {
    if fragment.is_empty() {
        default.to_string()
    } else {
        pct_decode(fragment)
    }
}

/// Parse Shadowsocks URI (mihomo #3220: BOTH share-link shapes must
/// parse or a panel that switches forms drops the whole subscription):
///   SIP002:  ss://BASE64URL(method:password)@server:port[/path][?plugin=...]#name
///            ss://method:password@server:port#name   (percent-encoded)
///   legacy:  ss://BASE64(method:password@server:port)#name
/// mihomo decides legacy-ness exactly like this: a parsed URL with no
/// port means the whole authority is the base64 payload.
fn parse_ss(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("ss://")?;
    // The fragment (node name) is never part of any base64 payload; a
    // query (plugin params) never part of the address.
    let (body, fragment) = data.split_once('#').unwrap_or((data, ""));
    let body = body.split('?').next().unwrap_or(body);
    let name = fragment_name(fragment, "Shadowsocks");

    // userinfo@hostport, or the whole body base64'd (legacy form).
    let (userinfo, hostport): (String, String) = if let Some((ui, hp)) = body.rsplit_once('@') {
        (ui.to_string(), hp.to_string())
    } else {
        let decoded = b64_flex(body)?;
        let plain = String::from_utf8(decoded).ok()?;
        let (ui, hp) = plain.rsplit_once('@')?;
        (ui.to_string(), hp.to_string())
    };
    // A trailing URI path ("ss://...@host:port/") is never part of the
    // address.
    let hostport = hostport.split('/').next().unwrap_or(&hostport).to_string();
    let (server, port) = split_host_port(&hostport)?;

    // method:password — plain (percent-encoded) or base64'd userinfo.
    let plain_userinfo = if userinfo.contains(':') {
        Some(pct_decode(&userinfo))
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

/// Parse ShadowSocksR URI — the format real SSR clients emit, matching
/// mihomo converter.go `case "ssr"` and subconverter explodeSSR:
///   ssr://URLSAFE_B64(host:port:protocol:method:obfs:URLSAFE_B64(password)/?obfsparam=B64&protoparam=B64&remarks=B64&group=B64)
/// The ENTIRE payload — including the `/?params` tail — is one base64
/// blob (RawURL alphabet, so no '/' appears in the wire form). Fields
/// split from the right so a raw-colon IPv6 host survives.
fn parse_ssr(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("ssr://")?;

    let decoded = b64_flex(data)?;
    let plain = String::from_utf8(decoded).ok()?;

    let (main, query) = plain.split_once("/?").unwrap_or((plain.as_str(), ""));

    // host:port:protocol:method:obfs:password_b64 — six fields, split
    // from the right; everything left of the fifth separator is host.
    let parts: Vec<&str> = main.rsplit(':').collect();
    if parts.len() < 6 {
        return None;
    }
    let password_b64 = parts[0];
    let obfs = parts[1].to_string();
    let method = parts[2].to_string();
    let protocol = parts[3].to_string();
    let port: u16 = parts[4].parse().ok()?;
    let host = parts[5..].iter().rev().copied().collect::<Vec<_>>().join(":");

    let password = b64_flex(password_b64)
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| password_b64.to_string());

    // remarks/obfsparam/protoparam values are urlsafe-base64; fall back
    // to the raw value for generators that skip the encoding.
    let b64_or_raw = |v: &str| -> String {
        b64_flex(v)
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| v.to_string())
    };
    let mut name = "ShadowSocksR".to_string();
    let mut obfs_param = String::new();
    for (key, value) in parse_query(query) {
        match key.as_str() {
            "remarks" => name = b64_or_raw(&value),
            "obfsparam" => obfs_param = b64_or_raw(&value),
            // protoparam/group — no ProxyNode field; ignored, never fatal.
            _ => {}
        }
    }

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
/// Format: trojan://password@server:port[?sni=..&allowInsecure=1&type=ws&fp=chrome&alpn=h3]#name
/// mihomo converter.go `case "trojan"` reads sni/allowInsecure/alpn/
/// type/path/serviceName/fp/pcs from the query — we capture sni (the
/// field ProxyNode models) and ignore the rest without failing.
fn parse_trojan(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("trojan://")?;
    let parts = split_share_link(data)?;
    let password = pct_decode(parts.userinfo);
    let (server, port) = split_host_port(parts.hostport)?;

    let mut sni = None;
    for (key, value) in parse_query(parts.query) {
        if key == "sni" && !value.is_empty() {
            sni = Some(value);
        }
    }

    Some(ProxyNode {
        name: fragment_name(parts.fragment, "Trojan"),
        protocol: ProxyProtocol::Trojan,
        server,
        port,
        extra: ProxyExtra {
            trojan_password: Some(password),
            sni,
            ..Default::default()
        },
    })
}

/// Parse VLESS URI (Xray share-link standard, XTLS/Xray-core#716):
/// vless://uuid@server:port?encryption=none&flow=xtls-rprx-vision&security=tls|reality|none
///   &sni=..&fp=..&pbk=..&sid=..&spx=..&type=tcp|ws|grpc|h2|xhttp&path=..&host=..#name
fn parse_vless(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("vless://")?;
    let parts = split_share_link(data)?;
    let uuid = pct_decode(parts.userinfo);
    let (server, port) = split_host_port(parts.hostport)?;

    let mut sni = None;
    let mut flow = None;
    let mut tls = false;
    let mut udp = None;
    let mut transport = None;

    for (key, value) in parse_query(parts.query) {
        match key.as_str() {
            "sni" if !value.is_empty() => sni = Some(value),
            "flow" => flow = Some(value),
            "tls" | "security" => {
                if security_enables_tls(&value) {
                    tls = true;
                }
            }
            "udp" => udp = Some(parse_udp_value(&value)),
            "type" | "net" => transport = Some(transport_from_name(&value)),
            // encryption/pbk/sid/spx/fp/alpn/packetEncoding/... — no
            // ProxyNode field; ignored, never fatal.
            _ => {}
        }
    }

    Some(ProxyNode {
        name: fragment_name(parts.fragment, "VLESS"),
        protocol: ProxyProtocol::VLESS,
        server,
        port,
        extra: ProxyExtra {
            uuid: Some(uuid.clone()),
            vless_uuid: Some(uuid),
            vless_flow: flow,
            transport,
            sni,
            tls,
            udp,
            ..Default::default()
        },
    })
}

/// Parse Hysteria2 URI (apernet/hysteria URI scheme):
///   hysteria2://[auth@]host[:port]/?sni=..&insecure=1&obfs=salamander&obfs-password=..&up=..&down=..&alpn=h3#name
/// mihomo/subconverter also accept the `hy2://` alias; the port is
/// optional (defaults to 443) and may be a port-hop range
/// (`host:443-8443`, `host:443,8443`) — mihomo's splitHysteria2Ports
/// connects to the FIRST port of the range.
fn parse_hysteria2(uri: &str) -> Option<ProxyNode> {
    let data = uri
        .strip_prefix("hysteria2://")
        .or_else(|| uri.strip_prefix("hy2://"))
        .or_else(|| uri.strip_prefix("hysteria://"))?;
    let parts = split_share_link(data)?;
    let password = pct_decode(parts.userinfo);

    let mut obfs = None;
    let mut sni = None;
    let mut udp = None;
    for (key, value) in parse_query(parts.query) {
        match key.as_str() {
            "obfs" => obfs = Some(value),
            "sni" if !value.is_empty() => sni = Some(value),
            "udp" => udp = Some(parse_udp_value(&value)),
            // obfs-password/insecure/up/down/alpn/pinSHA256 — no
            // ProxyNode field; ignored, never fatal.
            _ => {}
        }
    }

    // Port: plain, port-hop range (first wins), or omitted (443) —
    // mihomo converter.go defaults hysteria2 to 443 and
    // splitHysteria2Ports connects to the FIRST port of a range.
    let (server, port) = if let Some((h, p)) = split_host_port(parts.hostport) {
        (h, p)
    } else if let Some((h, first)) = parts
        .hostport
        .rsplit_once(':')
        .and_then(|(h, tail)| Some((h.to_string(), valid_port(tail.split([',', '-']).next()?)?)))
    {
        (h, first)
    } else if !parts.hostport.is_empty() && !parts.hostport.contains(':') {
        (parts.hostport.to_string(), 443)
    } else {
        return None;
    };

    Some(ProxyNode {
        name: fragment_name(parts.fragment, "Hysteria2"),
        protocol: ProxyProtocol::Hysteria2,
        server,
        port,
        extra: ProxyExtra {
            hy2_password: Some(password),
            hy2_obfs: obfs,
            sni,
            udp,
            ..Default::default()
        },
    })
}

/// Parse TUIC URI — the unofficial standard mihomo implements (from
/// daeuniverse/dae#182): TUICv5 `tuic://uuid:password@server:port?...`
/// and TUICv4 token form `tuic://token@server:port`.
/// Query: congestion_control, alpn, sni, disable_sni, udp_relay_mode.
fn parse_tuic(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("tuic://")?;
    let parts = split_share_link(data)?;
    // Split userinfo on the RAW text so an encoded ':' (%3A) inside the
    // password stays in the password.
    let (uuid, password) = match parts.userinfo.split_once(':') {
        Some((u, p)) => (pct_decode(u), pct_decode(p)),
        // TUICv4: bare token, no password.
        None => (pct_decode(parts.userinfo), String::new()),
    };
    let (server, port) = split_host_port(parts.hostport)?;

    let mut congestion_control = None;
    let mut sni = None;
    for (key, value) in parse_query(parts.query) {
        match key.as_str() {
            "congestion_control" => congestion_control = Some(value),
            "sni" if !value.is_empty() => sni = Some(value),
            // alpn/udp_relay_mode/disable_sni — no ProxyNode field;
            // ignored, never fatal.
            _ => {}
        }
    }

    Some(ProxyNode {
        name: fragment_name(parts.fragment, "TUIC"),
        protocol: ProxyProtocol::Tuic,
        server,
        port,
        extra: ProxyExtra {
            tuic_uuid: Some(uuid),
            tuic_password: Some(password),
            tuic_congestion_control: congestion_control,
            sni,
            ..Default::default()
        },
    })
}

/// Parse WireGuard URI — NOT a mihomo/subconverter share-link form
/// (neither project defines one); a local extension.
/// Format: wireguard://private_key=xxx&peer_public_key=xxx&preshared_key=xxx&endpoint=server:port&mtu=1280&allowed_ips=0.0.0.0/0#name
fn parse_wireguard(uri: &str) -> Option<ProxyNode> {
    let data = uri.strip_prefix("wireguard://")?;
    let data = pct_decode(data);

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

    Some(ProxyNode {
        name: fragment_name(name, "WireGuard"),
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

    // ------------------------------------------------------------------
    // Hand-crafted baseline tests (pre-existing behavior that must hold)
    // ------------------------------------------------------------------

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
        // VMess with net=h2 (HTTP/2 transport)
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
        // Unknown net field falls back to Tcp — the node survives.
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
        let uri = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=xtls&sni=example.com#Test-VLESS-XTLS";
        let node = parse_vless(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::VLESS);
        assert!(node.extra.tls);
    }

    #[test]
    fn test_parse_uri_list() {
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
        let uri = "hysteria2://password123@example.com:443#Simple";
        let node = parse_hysteria2(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(node.name, "Simple");
        assert_eq!(node.extra.hy2_password.as_deref(), Some("password123"));
    }

    #[test]
    fn test_parse_tuic() {
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
        let uri = "wireguard://private_key=abc123&peer_public_key=xyz789#No-Endpoint";
        let node = parse_wireguard(uri);
        assert!(node.is_none());
    }

    #[test]
    fn test_parse_unsupported_uri() {
        assert!(parse_uri("unknown://something").is_none());
    }

    #[test]
    fn test_parse_uri_with_vless() {
        let uri = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?flow=xtls-rprx-vision&sni=example.com#Test-VLESS";
        let node = parse_uri(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::VLESS);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
    }

    #[test]
    fn test_parse_vless_without_query_params() {
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
        let uri = "ss://chacha20:password@192.168.1.1:8388";
        let node = parse_ss(uri).unwrap();
        assert_eq!(node.name, "Shadowsocks");
    }

    #[test]
    fn test_parse_ss_with_base64_non_utf8() {
        // Valid base64 but decodes to non-UTF-8 bytes — clean skip.
        let encoded = "gICAgA=="; // base64 of [0x80, 0x80, 0x80, 0x80]
        let uri = format!("ss://{encoded}@192.168.1.1:8388#Test");
        let node = parse_ss(&uri);
        assert!(node.is_none());
    }

    #[test]
    fn test_parse_hysteria_without_2_suffix() {
        let uri = "hysteria://password@example.com:443";
        let node = parse_hysteria2(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
    }

    #[test]
    fn test_parse_uri_whitespace_only() {
        assert!(parse_uri("   ").is_none());
        assert!(parse_uri("").is_none());
    }

    #[test]
    fn test_parse_ss_with_2022_cipher() {
        let uri = "ss://2022-blake3-aes-256-gcm:password@192.168.1.1:8388#Test2022";
        let node = parse_ss(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Shadowsocks);
        assert_eq!(
            node.extra.cipher.as_deref(),
            Some("2022-blake3-aes-256-gcm")
        );
    }

    // ------------------------------------------------------------------
    // mihomo #3220: share-link robustness
    // ------------------------------------------------------------------

    #[test]
    fn test_ss_legacy_full_base64_form() {
        // Panels (and Xray-based generators) emit the legacy form where
        // the WHOLE method:password@host:port is base64'd.
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
        let uri = "ss://2022-blake3-aes-256-gcm:p%40ss%3Aword@1.2.3.4:443#Node";
        let node = parse_uri(uri).unwrap();
        assert_eq!(node.server, "1.2.3.4");
        assert_eq!(node.port, 443);
        assert_eq!(node.extra.cipher.as_deref(), Some("2022-blake3-aes-256-gcm"));
        assert_eq!(node.extra.password.as_deref(), Some("p@ss:word"));
    }

    #[test]
    fn test_ipv6_bracket_hosts_parse() {
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
        let uri = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@gen.example.com:443?encryption=none&flow=xtls-rprx-vision&sni=gen.example.com&security=tls&newParam2699=whatever&another=1#Gen";
        let node = parse_uri(uri).unwrap();
        assert_eq!(node.server, "gen.example.com");
        assert_eq!(node.extra.vless_flow.as_deref(), Some("xtls-rprx-vision"));
        assert!(node.extra.tls);
    }

    #[test]
    fn test_host_port_split_forms() {
        assert_eq!(
            split_host_port("a.example.com:443").unwrap(),
            ("a.example.com".into(), 443)
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:8443").unwrap(),
            ("2001:db8::1".into(), 8443)
        );
        assert!(split_host_port("no-port.example.com").is_none());
        assert!(split_host_port("[2001:db8::1]:notaport").is_none());
        assert!(split_host_port("[2001:db8::1]443").is_none());
    }

    // ------------------------------------------------------------------
    // Real-world corpus (shapes from mihomo common/convert/converter.go,
    // v.go handleVShareLink, and subconverter subparser.cpp). Each URI
    // asserts EVERY ProxyNode field it encodes.
    // ------------------------------------------------------------------

    type Check = Box<dyn Fn(&ProxyNode)>;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    }

    fn b64url_raw(s: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes())
    }

    fn corpus() -> Vec<(&'static str, Check)> {
        let mut cases: Vec<(&'static str, Check)> = Vec::new();

        // ---- ss:// SIP002, base64 userinfo (v2rayN/NekoBox style) ----
        cases.push((
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@server.example.com:8388#SIP002%20Node",
            Box::new(|n| {
                assert_eq!(n.protocol, ProxyProtocol::Shadowsocks);
                assert_eq!(n.name, "SIP002 Node");
                assert_eq!(n.server, "server.example.com");
                assert_eq!(n.port, 8388);
                assert_eq!(n.extra.cipher.as_deref(), Some("aes-256-gcm"));
                assert_eq!(n.extra.password.as_deref(), Some("password"));
            }),
        ));

        // ---- ss:// SIP002, urlsafe unpadded userinfo (password keeps a raw '@') ----
        let ui = b64url_raw("chacha20-ietf-poly1305:p@ss");
        let uri = leak(format!("ss://{ui}@sip002.example.com:443#Unpadded"));
        cases.push((
            uri,
            Box::new(|n| {
                assert_eq!(n.server, "sip002.example.com");
                assert_eq!(n.port, 443);
                assert_eq!(n.extra.cipher.as_deref(), Some("chacha20-ietf-poly1305"));
                // b64 userinfo exists precisely so raw '@' can ride along
                assert_eq!(n.extra.password.as_deref(), Some("p@ss"));
            }),
        ));

        // ---- ss:// SIP002, plain percent-encoded userinfo with '@'/':' in password ----
        cases.push((
            "ss://aes-128-gcm:p%40ss%3Aword@1.2.3.4:443#Plain",
            Box::new(|n| {
                assert_eq!(n.extra.cipher.as_deref(), Some("aes-128-gcm"));
                assert_eq!(n.extra.password.as_deref(), Some("p@ss:word"));
                assert_eq!(n.server, "1.2.3.4");
                assert_eq!(n.port, 443);
            }),
        ));

        // ---- ss:// SIP002 with plugin query and trailing slash (obfs/v2ray-plugin) ----
        cases.push((
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@cdn.example.com:443/?plugin=v2ray-plugin;obfs=websocket;obfs-host=cdn.example.com;path=%2Fws&tls#Plugin%20SS",
            Box::new(|n| {
                // The plugin param is dropped (no ProxyNode field) but
                // MUST NOT corrupt the address or kill the node.
                assert_eq!(n.name, "Plugin SS");
                assert_eq!(n.server, "cdn.example.com");
                assert_eq!(n.port, 443);
                assert_eq!(n.extra.cipher.as_deref(), Some("aes-256-gcm"));
                assert_eq!(n.extra.password.as_deref(), Some("password"));
            }),
        ));

        // ---- ss:// legacy full-base64 with urlsafe alphabet ----
        let legacy = b64url_raw("chacha20:legacy@10.0.0.1:9999");
        let uri = leak(format!("ss://{legacy}#Legacy"));
        cases.push((
            uri,
            Box::new(|n| {
                assert_eq!(n.server, "10.0.0.1");
                assert_eq!(n.port, 9999);
                assert_eq!(n.extra.cipher.as_deref(), Some("chacha20"));
                assert_eq!(n.extra.password.as_deref(), Some("legacy"));
            }),
        ));

        // ---- ss:// IPv6 bracket host ----
        let uri = leak(format!(
            "ss://{}@[2001:db8::2]:8388#V6",
            b64("aes-256-gcm:pw")
        ));
        cases.push((
            uri,
            Box::new(|n| {
                assert_eq!(n.server, "2001:db8::2");
                assert_eq!(n.port, 8388);
                assert_eq!(n.extra.cipher.as_deref(), Some("aes-256-gcm"));
                assert_eq!(n.extra.password.as_deref(), Some("pw"));
            }),
        ));

        // ---- vmess:// v2rayN full JSON (all common fields) ----
        let vm = json!({
            "v": "2", "ps": "东京 WS", "add": "vm.example.com", "port": "443",
            "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "0",
            "scy": "auto", "net": "ws", "type": "none",
            "host": "cdn.example.com", "path": "/ws?ed=2048",
            "tls": "tls", "sni": "cdn.example.com", "alpn": "h2,http/1.1",
            "fp": "chrome"
        });
        let uri = leak(format!("vmess://{}", b64(&vm.to_string())));
        cases.push((
            uri,
            Box::new(|n| {
                assert_eq!(n.protocol, ProxyProtocol::VMess);
                assert_eq!(n.name, "东京 WS");
                assert_eq!(n.server, "vm.example.com");
                assert_eq!(n.port, 443);
                assert_eq!(
                    n.extra.uuid.as_deref(),
                    Some("b831381d-6324-4d53-ad4f-8cda48b30811")
                );
                assert_eq!(n.extra.alter_id, Some(0));
                assert_eq!(n.extra.transport, Some(TransportType::WebSocket));
                assert!(n.extra.tls);
                assert_eq!(n.extra.sni.as_deref(), Some("cdn.example.com"));
            }),
        ));

        // ---- vmess:// JSON with NUMERIC port/aid (panel generators) ----
        let vm = json!({
            "ps": "NumPort", "add": "num.example.com", "port": 2053,
            "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": 0,
            "net": "grpc", "path": "grpcSvc"
        });
        let uri = leak(format!("vmess://{}", b64(&vm.to_string())));
        cases.push((
            uri,
            Box::new(|n| {
                assert_eq!(n.port, 2053, "numeric port must not fall back to 443");
                assert_eq!(n.extra.alter_id, Some(0));
                assert_eq!(n.extra.transport, Some(TransportType::Grpc));
                assert!(!n.extra.tls);
            }),
        ));

        // ---- vmess:// minimal JSON (optional fields absent) ----
        let vm = json!({"add": "min.example.com", "port": "8080", "id": "b831381d-6324-4d53-ad4f-8cda48b30811"});
        let uri = leak(format!("vmess://{}", b64(&vm.to_string())));
        cases.push((
            uri,
            Box::new(|n| {
                assert_eq!(n.name, "VMess");
                assert_eq!(n.port, 8080);
                assert_eq!(n.extra.alter_id, Some(0));
                assert_eq!(n.extra.transport, Some(TransportType::Tcp));
                assert!(!n.extra.tls);
                assert!(n.extra.sni.is_none());
            }),
        ));

        // ---- vmess:// tls as JSON bool, net=h2, aid string ----
        let vm = json!({
            "ps": "BoolTls", "add": "h2.example.com", "port": "8443",
            "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "64",
            "net": "h2", "tls": true
        });
        let uri = leak(format!("vmess://{}", b64(&vm.to_string())));
        cases.push((
            uri,
            Box::new(|n| {
                assert_eq!(n.extra.alter_id, Some(64));
                assert_eq!(n.extra.transport, Some(TransportType::Http));
                assert!(n.extra.tls);
            }),
        ));

        // ---- vmess:// Xray VMessAEAD URL form (v2rayN 6.x) ----
        cases.push((
            "vmess://b831381d-6324-4d53-ad4f-8cda48b30811@aead.example.com:443?encryption=auto&security=tls&sni=aead.example.com&type=ws&host=cdn.example.com&path=%2Fpath#AEAD%20Node",
            Box::new(|n| {
                assert_eq!(n.protocol, ProxyProtocol::VMess);
                assert_eq!(n.name, "AEAD Node");
                assert_eq!(n.server, "aead.example.com");
                assert_eq!(n.port, 443);
                assert_eq!(
                    n.extra.uuid.as_deref(),
                    Some("b831381d-6324-4d53-ad4f-8cda48b30811")
                );
                assert_eq!(n.extra.alter_id, Some(0));
                assert_eq!(n.extra.transport, Some(TransportType::WebSocket));
                assert!(n.extra.tls);
                assert_eq!(n.extra.sni.as_deref(), Some("aead.example.com"));
            }),
        ));

        // ---- vless:// REALITY (Xray vision + reality-opts) ----
        cases.push((
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=xIvB3b7L1yArxZQzD5pV0tWq2s8u4mN6cJ9kH3fT7gU&sid=a1b2c3d4&spx=%2F&type=tcp&flow=xtls-rprx-vision#Reality%20Node",
            Box::new(|n| {
                assert_eq!(n.protocol, ProxyProtocol::VLESS);
                assert_eq!(n.name, "Reality Node");
                assert_eq!(n.server, "1.2.3.4");
                assert_eq!(n.port, 443);
                assert_eq!(
                    n.extra.vless_uuid.as_deref(),
                    Some("b831381d-6324-4d53-ad4f-8cda48b30811")
                );
                assert_eq!(n.extra.vless_flow.as_deref(), Some("xtls-rprx-vision"));
                // REALITY implies TLS (mihomo: security=reality -> tls=true).
                assert!(n.extra.tls);
                assert_eq!(n.extra.sni.as_deref(), Some("www.microsoft.com"));
            }),
        ));

        // ---- vless:// ws + tls (cdn fronting) ----
        cases.push((
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@ws.example.com:443?encryption=none&security=tls&sni=ws.example.com&type=ws&host=cdn.example.com&path=%2Fvless#WS",
            Box::new(|n| {
                assert!(n.extra.tls);
                assert_eq!(n.extra.transport, Some(TransportType::WebSocket));
                assert_eq!(n.extra.sni.as_deref(), Some("ws.example.com"));
                assert_eq!(n.server, "ws.example.com");
                assert_eq!(n.port, 443);
            }),
        ));

        // ---- vless:// grpc + serviceName ----
        cases.push((
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@grpc.example.com:443?security=tls&type=grpc&serviceName=grpcSvc&sni=grpc.example.com#GRPC",
            Box::new(|n| {
                assert_eq!(n.extra.transport, Some(TransportType::Grpc));
                assert!(n.extra.tls);
            }),
        ));

        // ---- vless:// xhttp (new Xray transport: node survives, Tcp) ----
        cases.push((
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@xhttp.example.com:443?security=tls&type=xhttp&path=%2Fxhttp&mode=auto#XHTTP",
            Box::new(|n| {
                assert_eq!(n.server, "xhttp.example.com");
                assert_eq!(n.port, 443);
                assert!(n.extra.tls);
                assert_eq!(n.extra.transport, Some(TransportType::Tcp));
            }),
        ));

        // ---- vless:// security=none (plain) ----
        cases.push((
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@plain.example.com:80?security=none&type=tcp#Plain",
            Box::new(|n| {
                assert!(!n.extra.tls);
                assert_eq!(n.port, 80);
            }),
        ));

        // ---- trojan:// with full query (sni/allowInsecure/fp/alpn) ----
        cases.push((
            "trojan://password123@trojan.example.com:443?sni=trojan.example.com&allowInsecure=1&type=ws&path=%2Ftj&fp=chrome&alpn=h3#Trojan%20WS",
            Box::new(|n| {
                assert_eq!(n.protocol, ProxyProtocol::Trojan);
                assert_eq!(n.name, "Trojan WS");
                assert_eq!(n.server, "trojan.example.com");
                assert_eq!(n.port, 443);
                assert_eq!(n.extra.trojan_password.as_deref(), Some("password123"));
                assert_eq!(n.extra.sni.as_deref(), Some("trojan.example.com"));
            }),
        ));

        // ---- trojan:// grpc variant ----
        cases.push((
            "trojan://pw@tj-grpc.example.com:443?security=tls&sni=tj-grpc.example.com&type=grpc&serviceName=svc#TJ-gRPC",
            Box::new(|n| {
                assert_eq!(n.extra.sni.as_deref(), Some("tj-grpc.example.com"));
                assert_eq!(n.port, 443);
            }),
        ));

        // ---- trojan:// password with encoded '@' and ':' ----
        cases.push((
            "trojan://p%40ss%3Aword@tj-pw.example.com:443#EncodedPw",
            Box::new(|n| {
                assert_eq!(n.extra.trojan_password.as_deref(), Some("p@ss:word"));
                assert_eq!(n.server, "tj-pw.example.com");
            }),
        ));

        // ---- trojan:// minimal (no query, percent-encoded CJK name) ----
        cases.push((
            "trojan://pw@tj.example.com:443#%E9%A6%99%E6%B8%AF",
            Box::new(|n| {
                assert_eq!(n.name, "香港");
            }),
        ));

        // ---- hy2:// alias with full official query ----
        cases.push((
            "hy2://authpass@hy2.example.com:443/?sni=hy2.example.com&insecure=1&obfs=salamander&obfs-password=obfspw&up=100&down=500&alpn=h3#Hy2%20Full",
            Box::new(|n| {
                assert_eq!(n.protocol, ProxyProtocol::Hysteria2);
                assert_eq!(n.name, "Hy2 Full");
                assert_eq!(n.server, "hy2.example.com");
                assert_eq!(n.port, 443);
                assert_eq!(n.extra.hy2_password.as_deref(), Some("authpass"));
                assert_eq!(n.extra.hy2_obfs.as_deref(), Some("salamander"));
                assert_eq!(n.extra.sni.as_deref(), Some("hy2.example.com"));
            }),
        ));

        // ---- hysteria2:// port omitted → default 443 (mihomo) ----
        cases.push((
            "hysteria2://auth@noport.example.com?sni=x.example.com#NoPort",
            Box::new(|n| {
                assert_eq!(n.port, 443);
                assert_eq!(n.server, "noport.example.com");
            }),
        ));

        // ---- hysteria2:// port hopping range → first port (mihomo splitHysteria2Ports) ----
        cases.push((
            "hysteria2://auth@hop.example.com:443-8443?sni=hop.example.com#Hopping",
            Box::new(|n| {
                assert_eq!(n.port, 443);
                assert_eq!(n.server, "hop.example.com");
            }),
        ));
        cases.push((
            "hysteria2://auth@hop2.example.com:20000,20001#HoppingComma",
            Box::new(|n| {
                assert_eq!(n.port, 20000);
            }),
        ));

        // ---- hysteria2:// password with encoded '@' ----
        cases.push((
            "hysteria2://p%40ss@hy2-pw.example.com:443#Encoded",
            Box::new(|n| {
                assert_eq!(n.extra.hy2_password.as_deref(), Some("p@ss"));
            }),
        ));

        // ---- tuic:// v5 with full query ----
        cases.push((
            "tuic://550e8400-e29b-41d4-a716-446655440000:tuicpass@tuic.example.com:443?congestion_control=bbr&alpn=h3&udp_relay_mode=native&sni=tuic.example.com&disable_sni=0#TUICv5",
            Box::new(|n| {
                assert_eq!(n.protocol, ProxyProtocol::Tuic);
                assert_eq!(n.name, "TUICv5");
                assert_eq!(n.server, "tuic.example.com");
                assert_eq!(n.port, 443);
                assert_eq!(
                    n.extra.tuic_uuid.as_deref(),
                    Some("550e8400-e29b-41d4-a716-446655440000")
                );
                assert_eq!(n.extra.tuic_password.as_deref(), Some("tuicpass"));
                assert_eq!(n.extra.tuic_congestion_control.as_deref(), Some("bbr"));
                assert_eq!(n.extra.sni.as_deref(), Some("tuic.example.com"));
            }),
        ));

        // ---- tuic:// v4 token form (no password) ----
        cases.push((
            "tuic://token123@tuic4.example.com:443#TUICv4",
            Box::new(|n| {
                assert_eq!(n.extra.tuic_uuid.as_deref(), Some("token123"));
                assert_eq!(n.extra.tuic_password.as_deref(), Some(""));
                assert_eq!(n.port, 443);
            }),
        ));

        // ---- tuic:// password containing encoded ':' ----
        cases.push((
            "tuic://550e8400-e29b-41d4-a716-446655440000:p%3A%40w@tuic-pw.example.com:443#Pw",
            Box::new(|n| {
                assert_eq!(n.extra.tuic_password.as_deref(), Some("p:@w"));
            }),
        ));

        // ---- tuic:// IPv6 ----
        cases.push((
            "tuic://550e8400-e29b-41d4-a716-446655440000:pw@[2001:db8::9]:443#TUICv6",
            Box::new(|n| {
                assert_eq!(n.server, "2001:db8::9");
                assert_eq!(n.port, 443);
            }),
        ));

        // ---- ssr:// real client format (mihomo/subconverter spec) ----
        {
            let main = format!(
                "ssr.example.com:8388:auth_chain_a:aes-256-cfb:tls1.2-ticket_auth:{}",
                b64url_raw("ssrpassword")
            );
            let query = format!(
                "remarks={}&obfsparam={}&protoparam={}&group={}",
                b64url_raw("SSR 节点"),
                b64url_raw("obfsparam1"),
                b64url_raw("protoparam1"),
                b64url_raw("group1")
            );
            let payload = format!("{main}/?{query}");
            let uri = leak(format!("ssr://{}", b64url_raw(&payload)));
            cases.push((
                uri,
                Box::new(move |n| {
                    assert_eq!(n.protocol, ProxyProtocol::ShadowSocksR);
                    assert_eq!(n.name, "SSR 节点");
                    assert_eq!(n.server, "ssr.example.com");
                    assert_eq!(n.port, 8388);
                    assert_eq!(n.extra.ssr_method.as_deref(), Some("aes-256-cfb"));
                    assert_eq!(n.extra.password.as_deref(), Some("ssrpassword"));
                    assert_eq!(n.extra.ssr_protocol.as_deref(), Some("auth_chain_a"));
                    assert_eq!(
                        n.extra.ssr_obfs.as_deref(),
                        Some("tls1.2-ticket_auth")
                    );
                    assert_eq!(n.extra.ssr_obfs_param.as_deref(), Some("obfsparam1"));
                }),
            ));
        }

        // ---- ssr:// no "/?" params → default name ----
        {
            let payload = format!(
                "plain.example.com:443:origin:aes-128-cfb:plain:{}",
                b64url_raw("pw2")
            );
            let uri = leak(format!("ssr://{}", b64url_raw(&payload)));
            cases.push((
                uri,
                Box::new(move |n| {
                    assert_eq!(n.name, "ShadowSocksR");
                    assert_eq!(n.server, "plain.example.com");
                    assert_eq!(n.port, 443);
                    assert_eq!(n.extra.ssr_protocol.as_deref(), Some("origin"));
                    assert_eq!(n.extra.ssr_obfs.as_deref(), Some("plain"));
                    assert_eq!(n.extra.password.as_deref(), Some("pw2"));
                    assert_eq!(n.extra.ssr_obfs_param.as_deref(), Some(""));
                }),
            ));
        }

        // ---- ssr:// IPv6 host with raw colons (mihomo's fixed 6-way
        // split cannot do IPv6 at all; our right-split keeps the address) ----
        {
            let payload = format!(
                "2001:db8::7:443:origin:aes-128-cfb:plain:{}",
                b64url_raw("pw3")
            );
            let uri = leak(format!("ssr://{}", b64url_raw(&payload)));
            cases.push((
                uri,
                Box::new(move |n| {
                    // everything left of the fifth-from-right colon is host
                    assert_eq!(n.server, "2001:db8::7");
                    assert_eq!(n.port, 443);
                }),
            ));
        }

        cases
    }

    // Leak corpus strings so table entries can hold both static and
    // dynamically built URIs behind one &'static str type.
    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    #[test]
    fn real_world_share_link_corpus() {
        let cases = corpus();
        assert!(cases.len() >= 30, "corpus shrank: {}", cases.len());
        for (uri, check) in cases {
            let node =
                parse_uri(uri).unwrap_or_else(|| panic!("corpus URI failed to parse: {uri}"));
            check(&node);
        }
    }

    /// Every corpus URI must also round-trip through the list parser
    /// (the shape subscriptions actually arrive in).
    #[test]
    fn real_world_corpus_parses_as_subscription_list() {
        let uris: Vec<String> = corpus().iter().map(|(u, _)| u.to_string()).collect();
        let nodes = parse_uri_list(&uris.join("\r\n"));
        assert_eq!(
            nodes.len(),
            uris.len(),
            "one corpus URI dropped in list form"
        );
    }

    // ------------------------------------------------------------------
    // Malformed / hostile inputs: no panics, clean None skips.
    // ------------------------------------------------------------------

    #[test]
    fn malformed_uris_never_panic_and_skip_cleanly() {
        let bad = [
            "",
            "   ",
            "vmess://",
            "vmess://!!!!not-base64!!!!",
            "vmess://bnVsbA",                       // valid b64, not JSON ("nul")
            "vmess://eyJhZGQiOiJ9",                 // JSON without required fields
            "vmess://eyJpZCI6IngifQ==",             // id but no add
            "vmess://eyJhZGQiOiJ4In0=",             // add but no id
            "vmess://eyJhZGQiOiJ4IiwiaWQiOiJ5IiwicG9ydCI6Im5vdGFwb3J0In0=", // port NaN
            "ss://",
            "ss://@",
            "ss://@host:0",
            "ss://!!!@1.2.3.4:443",
            "ss://Y2hhY2hhMjA=@no-port-host",       // SIP002 without port
            "ssr://",
            "ssr://!!!",
            // SSR payload with < 6 fields
            "ssr://b25seTp0d28=",
            "trojan://",
            "trojan://only-password",               // no '@'
            "trojan://pw@host:notaport",
            "trojan://pw@:443",                     // empty host
            "vless://",
            "vless://uuid@no-port",
            "vless://uuid@host:notaport#x",
            "hysteria2://",
            "hysteria2://pw@host:notaport",
            "hy2://pw@host:0",
            "tuic://",
            "tuic://uuid@host:notaport",
            "wireguard://",
            "wireguard://private_key=x",            // no endpoint
            "unknown://whatever",
            "http://example.com/sub",
            "\u{0}\u{1}\u{2}",
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@host:65536", // port out of range
        ];
        for uri in bad {
            // Must terminate quickly, not panic; None (skip) or a node
            // with a valid port are both acceptable — a panic is not.
            if let Some(node) = parse_uri(uri) {
                assert!(node.port > 0, "bogus port parsed from {uri:?}: {node:?}");
            }
        }
    }

    /// Fuzz-ish sweep: arbitrary byte soup after each scheme prefix must
    /// never panic (parser is total).
    #[test]
    fn garbage_after_scheme_prefix_never_panics() {
        let mut seed: u64 = 0x1234_5678_9abc_def0;
        let mut garbage = |n: usize| -> String {
            let mut s = String::new();
            for _ in 0..n {
                // xorshift over a printable + hostile mix
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let pick = (seed % 100) as u8;
                let c = match pick {
                    0..=5 => '%',
                    6..=10 => '@',
                    11..=15 => ':',
                    16..=20 => '#',
                    21..=25 => '?',
                    26..=30 => '/',
                    31..=35 => '[',
                    36..=40 => ']',
                    41..=45 => '=',
                    46..=50 => '\u{4e2d}',
                    _ => char::from(b'a' + (seed % 26) as u8),
                };
                s.push(c);
            }
            s
        };
        for scheme in [
            "vmess://", "ss://", "ssr://", "trojan://", "vless://",
            "hysteria2://", "hy2://", "tuic://", "wireguard://",
        ] {
            for len in [1usize, 5, 20, 100, 500] {
                let _ = parse_uri(&format!("{scheme}{}", garbage(len)));
            }
        }
    }
}
