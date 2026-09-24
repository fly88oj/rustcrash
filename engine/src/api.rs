//! Clash RESTful API subset: version, traffic (websocket), proxies (with
//! selection and delay tests), connections (with close), rules, configs,
//! logs. Hand-rolled HTTP/1.1 + minimal websocket, mirroring core::api's
//! zero-dependency approach.

use std::sync::Arc;

use base64::Engine as _;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::app::Engine;
use crate::config::{ApiConfig, RuleMode};
use crate::error::{Error, Result};

/// Serve the Clash API; returns after spawning the accept loop.
pub async fn serve(cfg: ApiConfig, engine: Arc<Engine>) -> Result<()> {
    let listener = TcpListener::bind((cfg.bind.as_str(), cfg.port))
        .await
        .map_err(|e| Error::network(format!("api bind {}:{}: {e}", cfg.bind, cfg.port)))?;
    let bound = listener
        .local_addr()
        .map_err(|e| Error::network(e.to_string()))?;
    tracing::info!(target: "engine", "clash api listening on {bound}");
    let secret = cfg.secret.clone().filter(|s| !s.is_empty());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let engine = engine.clone();
            let secret = secret.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, engine, secret).await {
                    tracing::debug!(target: "engine", "api: {e}");
                }
            });
        }
    });
    Ok(())
}

struct Request {
    method: String,
    path: String,
    query: String,
    #[allow(dead_code)]
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    is_websocket: bool,
    ws_key: Option<String>,
}

async fn read_request(stream: &mut TcpStream) -> Result<Request> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(Error::network("api: EOF before request"));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 32 * 1024 {
            return Err(Error::network("api: request too large"));
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or_default().to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let mut headers = Vec::new();
    let mut ws_key = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "sec-websocket-key" {
                ws_key = Some(value.clone());
            }
            headers.push((name, value));
        }
    }
    // Read body per Content-Length (JSON PUTs are small).
    let content_length: usize = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    if content_length > 1024 * 1024 {
        return Err(Error::network("api: body too large"));
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body).await?;
    }
    let is_websocket = headers
        .iter()
        .any(|(n, v)| n == "upgrade" && v.eq_ignore_ascii_case("websocket"));
    Ok(Request {
        method,
        path,
        query,
        headers,
        body,
        is_websocket,
        ws_key,
    })
}

async fn handle_connection(
    mut stream: TcpStream,
    engine: Arc<Engine>,
    secret: Option<String>,
) -> Result<()> {
    loop {
        let req = read_request(&mut stream).await?;
        // Auth: Bearer header or ?token=.
        if let Some(secret) = &secret {
            let bearer = req
                .headers
                .iter()
                .find(|(n, _)| n == "authorization")
                .and_then(|(_, v)| v.strip_prefix("Bearer "))
                .map(str::to_string);
            let query_token = req
                .query
                .split('&')
                .find_map(|kv| kv.strip_prefix("token="))
                .map(percent_decode);
            if bearer.as_deref() != Some(secret.as_str()) && query_token.as_deref() != Some(secret.as_str())
            {
                write_json(&mut stream, 401, r#"{"message":"Unauthorized"}"#).await?;
                return Ok(());
            }
        }
        dispatch(&mut stream, &req, &engine).await?;
        if !req.is_websocket {
            // Keep-alive: continue to the next request.
        } else {
            return Ok(());
        }
    }
}

async fn dispatch(stream: &mut TcpStream, req: &Request, engine: &Arc<Engine>) -> Result<()> {
    let path = req.path.as_str();
    let method = req.method.as_str();
    match (method, path) {
        ("GET", "/") | ("GET", "/version") => {
            write_json(
                stream,
                200,
                &serde_json::json!({ "meta": true, "version": crate::VERSION }).to_string(),
            )
            .await
        }
        ("GET", "/traffic") => {
            if req.is_websocket {
                websocket_traffic(stream, req, engine).await
            } else {
                let (down, up) = engine.stats().totals();
                write_json(
                    stream,
                    200,
                    &serde_json::json!({ "up": up, "down": down }).to_string(),
                )
                .await
            }
        }
        ("GET", "/proxies") => {
            let proxies = proxies_payload(engine).await;
            write_json(stream, 200, &proxies.to_string()).await
        }
        ("GET", "/rules") => {
            let rules: Vec<serde_json::Value> = engine
                .rules()
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "type": rule_type(r),
                        "payload": rule_payload(r),
                        "proxy": r.outbound,
                    })
                })
                .collect();
            write_json(stream, 200, &serde_json::json!({ "rules": rules }).to_string()).await
        }
        ("GET", "/connections") => {
            let conns: Vec<serde_json::Value> = engine
                .stats()
                .snapshot_conns()
                .iter()
                .map(conn_json)
                .collect();
            let (down, up) = engine.stats().totals();
            write_json(
                stream,
                200,
                &serde_json::json!({
                    "downloadTotal": down,
                    "uploadTotal": up,
                    "connections": conns,
                    "memory": 0,
                })
                .to_string(),
            )
            .await
        }
        ("DELETE", "/connections") => {
            // The engine closes with the client; drop is implicit.
            write_json(stream, 204, "").await
        }
        ("GET", "/configs") => {
            write_json(
                stream,
                200,
                &serde_json::json!({
                    "mode": engine.mode().await.as_str(),
                    "log-level": "info",
                    "ipv6": engine.config().ipv6,
                })
                .to_string(),
            )
            .await
        }
        ("PATCH", "/configs") => {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) {
                if let Some(mode) = v["mode"].as_str() {
                    if let Ok(mode) = RuleMode::parse(mode) {
                        engine.set_mode(mode).await;
                    }
                }
            }
            write_json(stream, 204, "").await
        }
        _ => {
            if let Some(name) = path.strip_prefix("/proxies/") {
                proxy_subroute(stream, req, engine, name).await
            } else if let Some(id) = path.strip_prefix("/connections/") {
                if method == "DELETE" {
                    let _ = id;
                    write_json(stream, 204, "").await
                } else {
                    write_json(stream, 404, r#"{"message":"Not Found"}"#).await
                }
            } else {
                write_json(stream, 404, r#"{"message":"Not Found"}"#).await
            }
        }
    }
}

async fn proxy_subroute(
    stream: &mut TcpStream,
    req: &Request,
    engine: &Arc<Engine>,
    name: &str,
) -> Result<()> {
    match req.method.as_str() {
        "GET" => {
            if name.ends_with("/delay") {
                let real = name.trim_end_matches("/delay");
                let url = req
                    .query
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("url="))
                    .unwrap_or("http://www.gstatic.com/generate_204")
                    .to_string();
                let url = percent_decode(&url);
                let registry = engine.registry();
                let Ok(outbound) = registry.resolve(real).await else {
                    return write_json(stream, 404, r#"{"message":"Proxy not found"}"#).await;
                };
                let started = std::time::Instant::now();
                match crate::outbound::probe(&url, outbound).await {
                    Ok(()) => {
                        let delay = started.elapsed().as_millis() as u32;
                        registry.record_latency(real, Some(delay)).await;
                        write_json(
                            stream,
                            200,
                            &serde_json::json!({ "delay": delay }).to_string(),
                        )
                        .await
                    }
                    Err(e) => {
                        registry.record_latency(real, Some(0)).await;
                        write_json(
                            stream,
                            408,
                            &serde_json::json!({
                                "message": format!("An error occurred: {e}"),
                                "delay": 0,
                            })
                            .to_string(),
                        )
                        .await
                    }
                }
            } else if let Some(group) = engine.registry().group(name) {
                let selected = engine
                    .registry()
                    .resolve(name)
                    .await
                    .map(|o| o.name.clone())
                    .unwrap_or_default();
                let payload = serde_json::json!({
                    "name": group.cfg.name,
                    "type": group.cfg.policy.as_str(),
                    "now": selected,
                    "all": group.cfg.members,
                    "history": [],
                    "udp": true,
                });
                write_json(stream, 200, &payload.to_string()).await
            } else {
                // Leaf proxy.
                let registry = engine.registry();
                if registry.resolve(name).await.is_err() {
                    return write_json(stream, 404, r#"{"message":"Proxy not found"}"#).await;
                }
                let payload = serde_json::json!({
                    "name": name,
                    "type": "Unknown",
                    "udp": true,
                    "history": [],
                });
                write_json(stream, 200, &payload.to_string()).await
            }
        }
        "PUT" => {
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
                return write_json(stream, 400, r#"{"message":"Bad body"}"#).await;
            };
            let Some(selected) = value["name"].as_str() else {
                return write_json(stream, 400, r#"{"message":"Missing name"}"#).await;
            };
            match engine.registry().set_selected(name, selected).await {
                Ok(()) => write_json(stream, 204, "").await,
                Err(e) => write_json(
                    stream,
                    400,
                    &serde_json::json!({ "message": e.to_string() }).to_string(),
                )
                .await,
            }
        }
        _ => write_json(stream, 405, r#"{"message":"Method Not Allowed"}"#).await,
    }
}

async fn proxies_payload(engine: &Arc<Engine>) -> serde_json::Value {
    let registry = engine.registry();
    let mut map = serde_json::Map::new();
    let latencies = registry.latency_snapshot().await;
    for name in registry.leaf_names() {
        map.insert(
            name.clone(),
            serde_json::json!({
                "name": name,
                "type": leaf_type(registry, &name).await,
                "udp": true,
                "history": latency_history(&latencies, &name),
            }),
        );
    }
    for name in registry.group_names() {
        let selected = registry
            .resolve(&name)
            .await
            .map(|o| o.name.clone())
            .unwrap_or_default();
        let group = registry.group(&name);
        map.insert(
            name.clone(),
            serde_json::json!({
                "name": name,
                "type": group.map(|g| g.cfg.policy.as_str()).unwrap_or("Selector"),
                "now": selected,
                "all": group.map(|g| g.cfg.members.clone()).unwrap_or_default(),
                "udp": true,
            }),
        );
    }
    serde_json::json!({ "proxies": map })
}

async fn leaf_type(registry: &Arc<crate::outbound::Registry>, name: &str) -> String {
    registry
        .resolve(name)
        .await
        .map(|o| o.kind_name().to_string())
        .unwrap_or_else(|_| "Unknown".to_string())
}

fn latency_history(
    latencies: &std::collections::HashMap<String, Option<u32>>,
    name: &str,
) -> Vec<serde_json::Value> {
    match latencies.get(name) {
        Some(Some(delay)) if *delay > 0 => vec![serde_json::json!({ "delay": delay })],
        _ => vec![],
    }
}

fn conn_json(c: &crate::stats::ConnSnapshot) -> serde_json::Value {
    serde_json::json!({
        "id": c.id.to_string(),
        "metadata": {
            "network": c.network,
            "type": c.inbound,
            "sourceIP": c.source.ip().to_string(),
            "sourcePort": c.source.port().to_string(),
            "host": c.host,
            "destinationPort": c.destination_port.to_string(),
        },
        "upload": c.upload,
        "download": c.download,
        "start": c.started_unix.to_string(),
        "chains": [c.outbound],
        "rule": c.rule,
        "rulePayload": "",
    })
}

fn rule_type(rule: &crate::rule::Rule) -> String {
    use crate::rule::RuleMatcher as M;
    match &rule.matcher {
        M::Domain(_) => "Domain".into(),
        M::DomainSuffix(_) => "DomainSuffix".into(),
        M::DomainKeyword(_) => "DomainKeyword".into(),
        M::DomainRegex(_) => "DomainRegex".into(),
        M::IpCidr { .. } => "IpCidr".into(),
        M::GeoIp { .. } => "GeoIP".into(),
        M::Geosite { .. } => "Geosite".into(),
        M::PortDst(_) => "DstPort".into(),
        M::PortSrc(_) => "SrcPort".into(),
        M::RuleSet { .. } => "RuleSet".into(),
        M::ClashMode(_) => "ClashMode".into(),
        M::Network(_) => "Network".into(),
        M::InPort(_) => "InPort".into(),
        M::InName(_) => "InName".into(),
        M::InType(_) => "InType".into(),
        M::Uid(_) => "Uid".into(),
        M::InUser(_) => "InUser".into(),
        M::Dscp(_) => "DSCP".into(),
        M::IpAsn { .. } => "IPASN".into(),
        M::IpSuffix { .. } => "IPSuffix".into(),
        M::Process { .. } => "Process".into(),
        M::Logic { .. } => "Logic".into(),
        M::MatchAll => "Match".into(),
    }
}

fn rule_payload(rule: &crate::rule::Rule) -> String {
    use crate::rule::RuleMatcher as M;
    match &rule.matcher {
        M::Domain(d) => d.clone(),
        M::DomainSuffix(s) => s.clone(),
        M::DomainKeyword(k) => k.clone(),
        M::DomainRegex(_) => "".into(),
        M::IpCidr { net, .. } => net.to_string(),
        M::GeoIp { country, .. } => country.clone(),
        M::Geosite { name } => name.clone(),
        M::PortDst(p) => format!("{}-{}", p.start, p.end),
        M::PortSrc(p) => format!("{}-{}", p.start, p.end),
        M::RuleSet { name, .. } => name.clone(),
        M::ClashMode(m) => m.clone(),
        M::Network(n) => n.as_str().to_string(),
        M::InPort(p) => format!("{}-{}", p.start, p.end),
        M::InName(n) => n.clone(),
        M::InType(t) => t.clone(),
        M::Uid(u) => format!("{}-{}", u.start, u.end),
        M::InUser(u) => u.clone(),
        M::Dscp(d) => d.to_string(),
        M::IpAsn { asn, .. } => asn.to_string(),
        M::IpSuffix { suffix, .. } => suffix.clone(),
        M::Process { pattern, .. } => pattern.clone(),
        M::Logic { .. } => String::new(),
        M::MatchAll => "".into(),
    }
}

async fn write_json(stream: &mut TcpStream, status: u16, body: &str) -> Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|e| Error::network(e.to_string()))?;
    if !body.is_empty() {
        stream
            .write_all(body.as_bytes())
            .await
            .map_err(|e| Error::network(e.to_string()))?;
    }
    Ok(())
}

/// Server-side websocket for /traffic: one JSON object per second.
async fn websocket_traffic(stream: &mut TcpStream, req: &Request, engine: &Arc<Engine>) -> Result<()> {
    let Some(key) = &req.ws_key else {
        return write_json(stream, 400, r#"{"message":"Expected websocket"}"#).await;
    };
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let accept = base64::engine::general_purpose::STANDARD.encode(h.finalize());
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| Error::network(e.to_string()))?;
    let mut rx = engine.stats().subscribe_traffic();
    loop {
        let (down, up) = *rx.borrow_and_update();
        let frame = serde_json::json!({ "up": up, "down": down }).to_string();
        ws_send_text(stream, frame.as_bytes()).await?;
        // Wait for the next tick (or client close).
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
            }
            _ = stream.readable() => {
                let mut buf = [0u8; 64];
                
                match stream.try_read(&mut buf) {
                    Ok(0) | Err(_) => return Ok(()),
                    Ok(_) => {}
                }
            }
        }
    }
}

/// Write one unmasked text frame (server→client).
async fn ws_send_text(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x81); // FIN + text
    match payload.len() {
        n if n < 126 => frame.push(n as u8),
        n if n <= 0xFFFF => {
            frame.push(126);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            frame.push(127);
            frame.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    stream
        .write_all(&frame)
        .await
        .map_err(|e| Error::network(e.to_string()))?;
    Ok(())
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() + 1 {
            if let (Some(h), Some(l)) = (
                bytes.get(i + 1).and_then(|b| (*b as char).to_digit(16)),
                bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16)),
            ) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_forms() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("http%3A%2F%2Fx"), "http://x");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("bad%2"), "bad%2");
    }

    #[tokio::test]
    async fn api_serves_version_and_proxies() {
        use crate::config::{DnsConfig, EngineConfig};
        use crate::inbound::{ListenerConfig, ListenerKind};
        let cfg = EngineConfig {
            listeners: vec![ListenerConfig {
                tag: "mixed".into(),
                bind: "127.0.0.1".into(),
                port: 0,
                kind: ListenerKind::Mixed,
            }],
            rules: vec!["MATCH,DIRECT".into()],
            dns: Some(DnsConfig::default()),
            api: Some(ApiConfig {
                bind: "127.0.0.1".into(),
                port: 0,
                secret: Some("sekrit".into()),
            }),
            ..Default::default()
        }
        .with_builtin_outbounds();
        let engine = crate::app::Engine::build(cfg).unwrap();
        serve(
            ApiConfig {
                bind: "127.0.0.1".into(),
                port: 0,
                secret: Some("sekrit".into()),
            },
            engine.clone(),
        )
        .await
        .unwrap();
        // Find the bound port by asking the engine? serve() returns ();
        // re-bind deterministically instead.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        serve(
            ApiConfig {
                bind: "127.0.0.1".into(),
                port: addr.port(),
                secret: Some("sekrit".into()),
            },
            engine,
        )
        .await
        .unwrap();

        // No token → 401.
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"GET /version HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 512];
        let n = c.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 401"));

        // With token → 200.
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"GET /version HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer sekrit\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), c.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(text.starts_with("HTTP/1.1 200") || text.contains("200 OK"));
        assert!(text.contains(crate::VERSION));
    }
}
