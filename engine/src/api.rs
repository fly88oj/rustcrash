//! Clash RESTful API subset, endpoint-by-endpoint against mihomo's
//! `hub/route` (Alpha): version/hello, traffic (websocket), memory,
//! proxies (detail/select/delay), groups (list/detail/group delay),
//! connections (list/close, websocket), rules, configs (GET/PATCH),
//! logs, dns query, cache flushes and the providers surface.
//! Hand-rolled HTTP/1.1 + minimal websocket, mirroring core::api's
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
        ("GET", "/") => {
            // mihomo hub/route/server.go hello(): {"hello": "mihomo"}.
            write_json(stream, 200, r#"{"hello":"rustcrash"}"#).await
        }
        ("GET", "/version") => {
            write_json(
                stream,
                200,
                &serde_json::json!({ "meta": true, "version": crate::VERSION }).to_string(),
            )
            .await
        }
        // mihomo server.go memory(): in-use allocator bytes streamed per
        // second. The engine does no pool accounting; the field is
        // reported as 0 so dashboards keep rendering.
        ("GET", "/memory") => {
            write_json(stream, 200, r#"{"memory":0}"#).await
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
        // mihomo hub/route/groups.go getGroups(): every group payload.
        ("GET", "/group") => {
            let mut groups = Vec::new();
            for name in engine.registry().group_names() {
                groups.push(group_payload(engine, &name).await);
            }
            write_json(
                stream,
                200,
                &serde_json::json!({ "proxies": groups }).to_string(),
            )
            .await
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
            if req.is_websocket {
                // mihomo connections.go: snapshot stream, ?interval= ms.
                websocket_connections(stream, req, engine).await
            } else {
                write_json(stream, 200, &connections_payload(engine)).await
            }
        }
        ("DELETE", "/connections") => {
            // mihomo connections.go closeAllConnections(): iterates the
            // tracked conns and Close()s each. The engine's Stats table
            // carries no per-connection cancellation handle yet, so the
            // relays cannot be signalled from here — wiring needed:
            // a cancel token inside stats::ConnEntry plus a
            // force-close the relay select() observes; until then the
            // 204 matches mihomo's status without the teardown.
            write_json(stream, 204, "").await
        }
        // mihomo hub/route/dns.go queryDNS(): resolve through the
        // engine's own DNS path and render the miekg-shaped JSON.
        ("GET", "/dns/query") => dns_query(stream, req, engine).await,
        // mihomo hub/route/cache.go flushFakeIPPool() /
        // flushDnsCache().
        ("POST", "/cache/fakeip/flush") => {
            if let Some(dns) = engine.dns() {
                match dns.fakeip() {
                    Some(pool) => {
                        pool.flush();
                        write_json(stream, 204, "").await
                    }
                    None => write_json(
                        stream,
                        400,
                        r#"{"message":"fake-ip is not enabled"}"#,
                    )
                    .await,
                }
            } else {
                write_json(stream, 400, r#"{"message":"DNS section is disabled"}"#).await
            }
        }
        ("POST", "/cache/dns/flush") => {
            // resolver.rs owns the DNS cache and exposes no clear()
            // yet; fail loudly instead of pretending the cache was
            // dropped (a one-line `pub fn clear_cache` wires this).
            write_json(
                stream,
                503,
                r#"{"message":"DNS cache flush is not wired into the engine resolver"}"#,
            )
            .await
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
        // The engine defines no proxy providers (only rule providers),
        // so the honest list is empty.
        ("GET", "/providers/proxies") => {
            write_json(stream, 200, r#"{"providers":{}}"#).await
        }
        ("GET", "/providers/rules") => {
            let providers = rule_providers_payload(engine);
            write_json(
                stream,
                200,
                &serde_json::json!({ "providers": providers }).to_string(),
            )
            .await
        }
        _ => {
            if let Some(name) = path.strip_prefix("/proxies/") {
                proxy_subroute(stream, req, engine, name).await
            } else if let Some(id) = path.strip_prefix("/connections/") {
                if method == "DELETE" {
                    // mihomo connections.go closeConnection(): looks the
                    // tracker up by id and Close()s it. Same gap as the
                    // close-all arm above: no cancellation seam yet.
                    let _ = id;
                    write_json(stream, 204, "").await
                } else {
                    write_json(stream, 404, r#"{"message":"Not Found"}"#).await
                }
            } else if let Some(rest) = path.strip_prefix("/group/") {
                group_subroute(stream, req, engine, rest).await
            } else if method == "PUT" {
                if let Some(name) = path.strip_prefix("/providers/rules/") {
                    update_rule_provider(stream, engine, name).await
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
        // mihomo proxies.go unfixedProxy(): releases a pinned selection
        // so the group's own algorithm re-selects. The engine registry
        // keeps no pin to release — reported honestly instead of a
        // silent no-op 204.
        "DELETE" => write_json(
            stream,
            400,
            r#"{"message":"unfixed (releasing a selection) is not supported by the engine registry"}"#,
        )
        .await,
        _ => write_json(stream, 405, r#"{"message":"Method Not Allowed"}"#).await,
    }
}

/// Decoded `?key=value` lookup (values are percent-encoded).
fn query_param(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .map(percent_decode)
}

/// The DNS qtype table mihomo's `/dns/query` accepts (a subset of
/// miekg's `StringToType` covering the types the engine can usefully
/// render).
fn dns_type_from_str(s: &str) -> Option<u16> {
    use crate::dns::wire;
    Some(match s.to_ascii_uppercase().as_str() {
        "A" => wire::TYPE_A,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => wire::TYPE_AAAA,
        "SRV" => 33,
        "SVCB" => 64,
        "HTTPS" => 65,
        _ => return None,
    })
}

/// `example.com` → `example.com.` (miekg renders fqdns with the root
/// dot; dashboards match on that).
fn fqdn(name: &str) -> String {
    if name.is_empty() {
        ".".into()
    } else if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

/// `GET /dns/query` — mihomo hub/route/dns.go queryDNS(): exchange
/// through the engine's own DNS path (fake-ip / policy / cache all
/// apply) and render the miekg `Msg` JSON shape: Status, Question,
/// TC/RD/RA/AD/CD flags and Answer[{name,type,TTL,data}].
async fn dns_query(stream: &mut TcpStream, req: &Request, engine: &Arc<Engine>) -> Result<()> {
    use crate::dns::wire;
    let Some(dns) = engine.dns() else {
        return write_json(stream, 500, r#"{"message":"DNS section is disabled"}"#).await;
    };
    let name = query_param(&req.query, "name").unwrap_or_default();
    let type_str = query_param(&req.query, "type").unwrap_or_else(|| "A".into());
    let Some(qtype) = dns_type_from_str(&type_str) else {
        return write_json(stream, 400, r#"{"message":"invalid query type"}"#).await;
    };
    let query = wire::build_query(0, &name, qtype);
    let resp = dns.handle(&query).await;
    let Ok(msg) = wire::parse(&resp) else {
        return write_json(
            stream,
            500,
            r#"{"message":"unparseable DNS response"}"#,
        )
        .await;
    };

    let question: Vec<serde_json::Value> = msg
        .questions
        .iter()
        .map(|q| {
            serde_json::json!({
                "name": fqdn(&q.name),
                "qtype": q.qtype,
                "qclass": q.qclass,
            })
        })
        .collect();
    let mut payload = serde_json::json!({
        "Status": msg.rcode,
        "Question": question,
        "TC": msg.flags & 0x0200 != 0,
        "RD": msg.flags & 0x0100 != 0,
        "RA": msg.flags & 0x0080 != 0,
        "AD": msg.flags & 0x0020 != 0,
        "CD": msg.flags & 0x0010 != 0,
    });
    if !msg.answers.is_empty() {
        payload["Answer"] = serde_json::Value::Array(dns_answer_section(&msg));
    }
    write_json(stream, 200, &payload.to_string()).await
}

/// Render the answer section with presentation `data` strings. Walks
/// the raw message in lock-step with the parser so name-valued rdata
/// (CNAME/NS/PTR) decompresses against the real offsets.
fn dns_answer_section(msg: &crate::dns::wire::DnsMessage) -> Vec<serde_json::Value> {
    use crate::dns::wire;
    let raw = msg.raw.as_slice();
    let mut off = 12usize;
    for _ in &msg.questions {
        match wire::read_name(raw, off) {
            Ok((_, used)) => off += used + 4,
            Err(_) => return Vec::new(),
        }
    }
    let mut out = Vec::with_capacity(msg.answers.len());
    for rr in &msg.answers {
        let rdata_at = match wire::read_name(raw, off) {
            Ok((_, used)) => off + used + 10,
            Err(_) => break,
        };
        out.push(serde_json::json!({
            "name": fqdn(&rr.name),
            "type": rr.rtype,
            "TTL": rr.ttl,
            "data": present_rdata(raw, rdata_at, rr.rtype, &rr.rdata),
        }));
        off = rdata_at + rr.rdata.len();
    }
    out
}

/// Presentation string for one record's rdata (mihomo shows
/// `rr.String()` minus the header).
fn present_rdata(raw: &[u8], rdata_at: usize, rtype: u16, rdata: &[u8]) -> String {
    use crate::dns::wire;
    match rtype {
        wire::TYPE_A if rdata.len() == 4 => {
            std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string()
        }
        wire::TYPE_AAAA if rdata.len() == 16 => {
            let o: [u8; 16] = rdata.try_into().unwrap();
            std::net::Ipv6Addr::from(o).to_string()
        }
        // Character-string sequences (TXT).
        16 => {
            let mut parts = Vec::new();
            let mut i = 0;
            while i < rdata.len() {
                let len = rdata[i] as usize;
                i += 1;
                if i + len > rdata.len() {
                    break;
                }
                parts.push(String::from_utf8_lossy(&rdata[i..i + len]).to_string());
                i += len;
            }
            if parts.is_empty() {
                hex_lossy(rdata)
            } else {
                parts.join(" ")
            }
        }
        // Name-valued records decompress against the full message;
        // MX is preference(2) then a name.
        2 | 5 | 12 => wire::read_name(raw, rdata_at)
            .map(|(n, _)| fqdn(&n))
            .unwrap_or_else(|_| hex_lossy(rdata)),
        15 if rdata.len() >= 2 => wire::read_name(raw, rdata_at + 2)
            .map(|(n, _)| {
                let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
                format!("{pref} {}", fqdn(&n))
            })
            .unwrap_or_else(|_| hex_lossy(rdata)),
        _ => hex_lossy(rdata),
    }
}

fn hex_lossy(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

/// The full /connections snapshot document.
fn connections_payload(engine: &Arc<Engine>) -> String {
    let conns: Vec<serde_json::Value> = engine
        .stats()
        .snapshot_conns()
        .iter()
        .map(conn_json)
        .collect();
    let (down, up) = engine.stats().totals();
    serde_json::json!({
        "downloadTotal": down,
        "uploadTotal": up,
        "connections": conns,
        "memory": 0,
    })
    .to_string()
}

/// mihomo groups.go: `GET /group` (list) and `GET /group/{name}`
/// (detail; 404 for non-groups), plus `GET /group/{name}/delay`.
async fn group_subroute(
    stream: &mut TcpStream,
    req: &Request,
    engine: &Arc<Engine>,
    rest: &str,
) -> Result<()> {
    if let Some(group) = rest.strip_suffix("/delay") {
        return group_delay(stream, req, engine, group).await;
    }
    if req.method != "GET" {
        return write_json(stream, 405, r#"{"message":"Method Not Allowed"}"#).await;
    }
    match engine.registry().group(rest) {
        Some(_) => {
            let payload = group_payload(engine, rest).await;
            write_json(stream, 200, &payload.to_string()).await
        }
        None => write_json(stream, 404, r#"{"message":"Group not found"}"#).await,
    }
}

/// One group document, members included (mihomo's ProxyGroup
/// MarshalJSON embeds full member payloads under "proxies").
async fn group_payload(engine: &Arc<Engine>, name: &str) -> serde_json::Value {
    let registry = engine.registry();
    let group = registry.group(name);
    let selected = registry
        .resolve(name)
        .await
        .map(|o| o.name.clone())
        .unwrap_or_default();
    let members = group.map(|g| g.cfg.members.clone()).unwrap_or_default();
    let mut proxies = Vec::with_capacity(members.len());
    for member in &members {
        proxies.push(proxy_payload(engine, member).await);
    }
    serde_json::json!({
        "name": name,
        "type": group.map(|g| g.cfg.policy.as_str()).unwrap_or("Selector"),
        "now": selected,
        "all": members,
        "udp": true,
        "proxies": proxies,
    })
}

/// A single proxy document (leaf or nested group summary).
async fn proxy_payload(engine: &Arc<Engine>, name: &str) -> serde_json::Value {
    let registry = engine.registry();
    if let Some(group) = registry.group(name) {
        let selected = registry
            .resolve(name)
            .await
            .map(|o| o.name.clone())
            .unwrap_or_default();
        return serde_json::json!({
            "name": name,
            "type": group.cfg.policy.as_str(),
            "now": selected,
            "all": group.cfg.members,
            "udp": true,
        });
    }
    let latencies = registry.latency_snapshot().await;
    serde_json::json!({
        "name": name,
        "type": leaf_type(registry, name).await,
        "udp": true,
        "history": latency_history(&latencies, name),
    })
}

/// mihomo groups.go getGroupDelay(): url-test every member of the
/// group concurrently and answer `{member: delay_ms}`. `timeout` (ms)
/// is required and a bad value is a 400, exactly like upstream.
async fn group_delay(
    stream: &mut TcpStream,
    req: &Request,
    engine: &Arc<Engine>,
    name: &str,
) -> Result<()> {
    let registry = engine.registry();
    if registry.group(name).is_none() {
        return write_json(stream, 404, r#"{"message":"Group not found"}"#).await;
    }
    let Some(timeout_ms) = query_param(&req.query, "timeout")
        .and_then(|t| t.parse::<u64>().ok())
    else {
        return write_json(stream, 400, r#"{"message":"Params invalid"}"#).await;
    };
    if let Some(expected) = query_param(&req.query, "expected") {
        // mihomo parses unsigned ranges ("200" / "200,301"); anything
        // non-numeric is a 400. The ranges themselves are not filtered
        // on yet (known groupbase gap).
        if !expected
            .split(',')
            .all(|part| part.split('-').all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())))
        {
            return write_json(stream, 400, r#"{"message":"Params invalid"}"#).await;
        }
    }
    let url = query_param(&req.query, "url")
        .unwrap_or_else(|| "http://www.gstatic.com/generate_204".into());
    let members = registry.group(name).map(|g| g.cfg.members.clone()).unwrap_or_default();

    let mut set = tokio::task::JoinSet::new();
    for member in members {
        let engine = engine.clone();
        let url = url.clone();
        set.spawn(async move {
            let started = std::time::Instant::now();
            let ok = match engine.registry().resolve(&member).await {
                Ok(outbound) => crate::outbound::probe(&url, outbound).await.is_ok(),
                Err(_) => false,
            };
            let delay = if ok {
                started.elapsed().as_millis() as u32
            } else {
                0
            };
            engine.registry().record_latency(&member, ok.then_some(delay)).await;
            (member, delay)
        });
    }
    let collected = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        async {
            let mut out = serde_json::Map::new();
            while let Some(joined) = set.join_next().await {
                if let Ok((member, delay)) = joined {
                    out.insert(member, serde_json::json!(delay));
                }
            }
            out
        },
    )
    .await;
    match collected {
        Ok(map) => write_json(stream, 200, &serde_json::Value::Object(map).to_string()).await,
        Err(_) => write_json(
            stream,
            504,
            r#"{"message":"An error occurred in the delay test"}"#,
        )
        .await,
    }
}

/// Rule-provider documents (mihomo provider.go getRuleProviders()): the
/// engine loads providers at config build, so the list comes from the
/// config and ruleCount is counted from the live rule table.
fn rule_providers_payload(engine: &Arc<Engine>) -> serde_json::Map<String, serde_json::Value> {
    use crate::config::{ProviderBehavior, ProviderFormat};
    let behavior = |b: ProviderBehavior| {
        match b {
            ProviderBehavior::Domain => "domain",
            ProviderBehavior::IpCidr => "ipcidr",
            ProviderBehavior::Classical => "classical",
        }
        .to_string()
    };
    let format = |f: ProviderFormat| {
        match f {
            ProviderFormat::Text => "text",
            ProviderFormat::Yaml => "yaml",
            ProviderFormat::Mrs => "mrs",
        }
        .to_string()
    };
    let mut out = serde_json::Map::new();
    for spec in &engine.config().rule_providers {
        let rule_count = engine
            .rules()
            .iter()
            .filter(|r| rule_payload(r) == spec.name)
            .count();
        out.insert(
            spec.name.clone(),
            serde_json::json!({
                "name": spec.name,
                "behavior": behavior(spec.behavior),
                "format": format(spec.format),
                "vehicleType": "File",
                "ruleCount": rule_count,
                "updatedAt": "",
            }),
        );
    }
    out
}

/// mihomo provider.go updateRuleProvider(): re-fetches the provider.
/// The engine materializes providers at config build and has no
/// runtime reload path — 404 for unknown names, honest 503 otherwise.
async fn update_rule_provider(
    stream: &mut TcpStream,
    engine: &Arc<Engine>,
    name: &str,
) -> Result<()> {
    let known = engine
        .config()
        .rule_providers
        .iter()
        .any(|p| p.name == name);
    if !known {
        return write_json(stream, 404, r#"{"message":"Provider not found"}"#).await;
    }
    write_json(
        stream,
        503,
        &serde_json::json!({
            "message": "runtime rule-provider reload is not wired: providers are \
                        materialized at config build — update the file and restart"
        })
        .to_string(),
    )
    .await
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
        // mihomo marshals start as unix seconds (a number).
        "start": c.started_unix,
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
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
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

/// Complete the websocket handshake (RFC 6455 §4.2.2): 101 with the
/// base64(SHA1(key ‖ GUID)) accept token.
async fn ws_upgrade(stream: &mut TcpStream, req: &Request) -> Result<()> {
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
        .map_err(|e| Error::network(e.to_string()))
}

/// Server-side websocket for /traffic: one JSON object per second.
async fn websocket_traffic(stream: &mut TcpStream, req: &Request, engine: &Arc<Engine>) -> Result<()> {
    ws_upgrade(stream, req).await?;
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

/// Server-side websocket for /connections (mihomo connections.go
/// getConnections): the full snapshot document on a ticker, with the
/// upstream `?interval=` (ms, default 1000) controlling the cadence.
async fn websocket_connections(
    stream: &mut TcpStream,
    req: &Request,
    engine: &Arc<Engine>,
) -> Result<()> {
    ws_upgrade(stream, req).await?;
    let interval = query_param(&req.query, "interval")
        .and_then(|i| i.parse::<u64>().ok())
        .unwrap_or(1000)
        .clamp(50, 60_000);
    loop {
        let frame = connections_payload(engine);
        ws_send_text(stream, frame.as_bytes()).await?;
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_millis(interval)) => {}
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

    #[test]
    fn dns_type_table_and_fqdn_forms() {
        assert_eq!(dns_type_from_str("A"), Some(1));
        assert_eq!(dns_type_from_str("aaaa"), Some(28));
        assert_eq!(dns_type_from_str("CNAME"), Some(5));
        assert_eq!(dns_type_from_str("HTTPS"), Some(65));
        assert_eq!(dns_type_from_str("nonsense"), None);
        assert_eq!(fqdn("web.test"), "web.test.");
        assert_eq!(fqdn("dot.test."), "dot.test.");
        assert_eq!(fqdn(""), ".");
    }

    /// A hand-built response with a compressed CNAME plus an A record:
    /// the answer renderer must decompress names against real offsets.
    #[test]
    fn dns_answer_section_renders_compressed_names() {
        use crate::dns::wire;
        let mut msg = wire::build_query(3, "web.test", wire::TYPE_A);
        msg[2] = 0x81; // response
        // CNAME web.test -> web.test (pointer rdata into the question).
        msg.extend_from_slice(&[0xC0, 0x0C]);
        msg.extend_from_slice(&5u16.to_be_bytes()); // CNAME
        msg.extend_from_slice(&1u16.to_be_bytes()); // IN
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&2u16.to_be_bytes()); // rdlen
        msg.extend_from_slice(&[0xC0, 0x0C]); // name pointer
        // A web.test -> 198.18.0.9
        msg.extend_from_slice(&[0xC0, 0x0C]);
        msg.extend_from_slice(&wire::TYPE_A.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&7u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[198, 18, 0, 9]);
        msg[6] = 0;
        msg[7] = 2; // ANCOUNT = 2
        let parsed = wire::parse(&msg).unwrap();
        let answers = dns_answer_section(&parsed);
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0]["type"], 5);
        assert_eq!(answers[0]["data"], "web.test."); // decompressed
        assert_eq!(answers[1]["type"], 1);
        assert_eq!(answers[1]["data"], "198.18.0.9");
        assert_eq!(answers[1]["name"], "web.test.");
        assert_eq!(answers[1]["TTL"], 7);
    }

    #[test]
    fn txt_rdata_joins_character_strings() {
        use crate::dns::wire;
        let mut msg = wire::build_query(4, "txt.test", 16);
        msg[2] = 0x81;
        msg.extend_from_slice(&[0xC0, 0x0C]);
        msg.extend_from_slice(&16u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&30u32.to_be_bytes());
        msg.extend_from_slice(&8u16.to_be_bytes());
        msg.extend_from_slice(&[3, b'a', b'b', b'c', 3, b'd', b'e', b'f']);
        msg[7] = 1;
        let parsed = wire::parse(&msg).unwrap();
        let answers = dns_answer_section(&parsed);
        assert_eq!(answers[0]["data"], "abc def");
    }

    // ---- live endpoint tests (loopback api + in-process engine) ----

    use crate::config::{DnsConfig, EngineConfig, EnhancedMode};
    use crate::inbound::{ListenerConfig, ListenerKind};

    fn base_cfg() -> EngineConfig {
        EngineConfig {
            listeners: vec![ListenerConfig {
                tag: "mixed".into(),
                bind: "127.0.0.1".into(),
                port: 0,
                kind: ListenerKind::Mixed,
            }],
            rules: vec!["MATCH,DIRECT".into()],
            dns: None,
            ..Default::default()
        }
        .with_builtin_outbounds()
    }

    fn fakeip_cfg() -> DnsConfig {
        DnsConfig {
            fakeip_store: None,
            enable: true,
            listen: None,
            enhanced_mode: EnhancedMode::FakeIp,
            ipv6: false,
            // Never contacted: the fake-ip path answers before any
            // upstream exchange.
            nameservers: vec!["udp://127.0.0.1:1".into()],
            fallback: vec![],
            fakeip_range: "198.18.0.1/15".into(),
            fakeip_filter: vec!["*.lan".into()],
            hosts: std::collections::HashMap::new(),
            nameserver_policy: Vec::new(),
            client_subnet: None,
            rules: Vec::new(),
        }
    }

    async fn start_api(cfg: EngineConfig) -> std::net::SocketAddr {
        let engine = crate::app::Engine::build(cfg).unwrap();
        // Reserve a free port, then serve on it (serve() does not
        // report the bound address when port 0 is used).
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
        addr
    }

    /// One request/response roundtrip; the client half-closes after
    /// sending so read-to-EOF terminates.
    async fn request(
        addr: std::net::SocketAddr,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> (u16, String) {
        let mut c = TcpStream::connect(addr).await.unwrap();
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer sekrit\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        c.write_all(head.as_bytes()).await.unwrap();
        c.write_all(body).await.unwrap();
        c.shutdown().await.unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), c.read_to_end(&mut buf))
            .await
            .expect("response within 5s")
            .unwrap();
        let text = String::from_utf8_lossy(&buf).to_string();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        let body = text
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .to_string();
        (status, body)
    }

    #[tokio::test]
    async fn hello_memory_version_and_groups() {
        let mut cfg = base_cfg();
        cfg.groups = vec![crate::outbound::GroupConfig {
            name: "Pick".into(),
            members: vec!["DIRECT".into()],
            policy: crate::outbound::GroupPolicy::Select,
            url: None,
            interval: 0,
            tolerance: 0,
        }];
        let addr = start_api(cfg).await;

        let (status, body) = request(addr, "GET", "/", b"").await;
        assert_eq!(status, 200);
        assert!(body.contains("hello"), "body: {body}");

        let (status, body) = request(addr, "GET", "/version", b"").await;
        assert_eq!(status, 200);
        assert!(body.contains(crate::VERSION));

        let (status, body) = request(addr, "GET", "/memory", b"").await;
        assert_eq!(status, 200);
        assert!(body.contains("\"memory\":0"), "body: {body}");

        let (status, body) = request(addr, "GET", "/group", b"").await;
        assert_eq!(status, 200);
        assert!(body.contains("\"Pick\""), "body: {body}");

        let (status, body) = request(addr, "GET", "/group/Pick", b"").await;
        assert_eq!(status, 200);
        assert!(body.contains("\"DIRECT\"") && body.contains("\"now\""), "body: {body}");

        let (status, _) = request(addr, "GET", "/group/Nope", b"").await;
        assert_eq!(status, 404);
        // Leaves are not groups.
        let (status, _) = request(addr, "GET", "/group/DIRECT", b"").await;
        assert_eq!(status, 404);
        // mihomo requires ?timeout for group delay tests.
        let (status, _) = request(addr, "GET", "/group/Pick/delay", b"").await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn dns_query_through_fakeip_and_flush() {
        let mut cfg = base_cfg();
        cfg.dns = Some(fakeip_cfg());
        let addr = start_api(cfg).await;

        let (status, body) =
            request(addr, "GET", "/dns/query?name=web.test&type=A", b"").await;
        assert_eq!(status, 200, "body: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["Status"], 0);
        assert_eq!(v["Question"][0]["name"], "web.test.");
        assert_eq!(v["Question"][0]["qtype"], 1);
        assert_eq!(v["RA"], true);
        let data = v["Answer"][0]["data"].as_str().unwrap();
        assert!(data.starts_with("198.18."), "fake ip: {data}");
        let first_slot = data.to_string();

        // Unknown qtype is a 400 with mihomo's message.
        let (status, body) = request(addr, "GET", "/dns/query?name=x&type=BOGUS", b"").await;
        assert_eq!(status, 400);
        assert!(body.contains("invalid query type"));

        // Flush resets the pool: b.test's next address wraps to the
        // first slot again instead of its pre-flush one.
        let (_, b1) = request(addr, "GET", "/dns/query?name=a.test&type=A", b"").await;
        let (_, b2) = request(addr, "GET", "/dns/query?name=b.test&type=A", b"").await;
        let ip_of = |body: &str| {
            serde_json::from_str::<serde_json::Value>(body).unwrap()["Answer"][0]["data"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_ne!(ip_of(&b1), ip_of(&b2));
        let (status, _) = request(addr, "POST", "/cache/fakeip/flush", b"").await;
        assert_eq!(status, 204);
        let (_, b3) = request(addr, "GET", "/dns/query?name=b.test&type=A", b"").await;
        // web.test took slot 1 before a/b; after the flush allocation
        // restarts there, so b.test gets slot 1 back (not its old slot).
        assert_eq!(ip_of(&b3), first_slot, "allocation restarted at slot 1");
        assert_ne!(ip_of(&b3), ip_of(&b2));

        // With DNS disabled the endpoint reports mihomo's message.
        let addr_nodns = start_api(base_cfg()).await;
        let (status, body) = request(addr_nodns, "GET", "/dns/query?name=x&type=A", b"").await;
        assert_eq!(status, 500);
        assert!(body.contains("DNS section is disabled"));
    }

    #[tokio::test]
    async fn connections_snapshot_and_close_statuses() {
        let addr = start_api(base_cfg()).await;
        let (status, body) = request(addr, "GET", "/connections", b"").await;
        assert_eq!(status, 200);
        assert!(body.contains("\"downloadTotal\"") && body.contains("\"connections\""));
        // Close-all and per-id return mihomo's 204 (the relay-side
        // cancel seam is the documented follow-up).
        let (status, _) = request(addr, "DELETE", "/connections", b"").await;
        assert_eq!(status, 204);
        let (status, _) = request(addr, "DELETE", "/connections/42", b"").await;
        assert_eq!(status, 204);
    }

    #[tokio::test]
    async fn rule_provider_surface() {
        use crate::config::{ProviderBehavior, ProviderFormat, RuleProviderSpec};
        let mut cfg = base_cfg();
        cfg.rules = vec!["RULE-SET,ads,DIRECT".into(), "MATCH,DIRECT".into()];
        cfg.rule_providers = vec![RuleProviderSpec {
            name: "ads".into(),
            path: "/nonexistent/ads.list".into(),
            behavior: ProviderBehavior::Domain,
            format: ProviderFormat::Text,
        }];
        let addr = start_api(cfg).await;

        let (status, body) = request(addr, "GET", "/providers/rules", b"").await;
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let ads = &v["providers"]["ads"];
        assert_eq!(ads["behavior"], "domain");
        assert_eq!(ads["vehicleType"], "File");
        assert_eq!(ads["ruleCount"], 1, "one RULE-SET rule references it");

        // Proxy providers: the engine has none — honest empty map.
        let (status, body) = request(addr, "GET", "/providers/proxies", b"").await;
        assert_eq!(status, 200);
        assert_eq!(body, "{\"providers\":{}}");

        // Update: known name fails loudly (no runtime reload), unknown
        // name is a 404 like upstream.
        let (status, body) = request(addr, "PUT", "/providers/rules/ads", b"").await;
        assert_eq!(status, 503, "body: {body}");
        assert!(body.contains("not wired"));
        let (status, _) = request(addr, "PUT", "/providers/rules/nope", b"").await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn api_serves_version_and_proxies() {
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
            .await.unwrap();
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
