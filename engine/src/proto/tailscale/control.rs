//! The control session: registration and the map long-poll over the
//! Noise transport.
//!
//! Port of the client halves of `tailscale.com/control/controlclient`
//! (direct.go's `TryLogin` register leg, `sendMapRequest`'s poll loop and
//! `mapSession`'s delta application; cached at
//! `/tmp/wave11-upstream/control_controlclient_{direct,map,auto}.go`,
//! upstream `main` as of 2026-09).
//!
//! # What runs inside the Noise records
//!
//! Upstream wraps the controlbase Noise stream in an `http.Client` whose
//! transport speaks **unencrypted HTTP/2** (`SetUnencryptedHTTP2(true)`,
//! control/ts2021/client.go:166-179). This port speaks **HTTP/1.1**
//! inside the same records — a deliberate delta: the tree carries no
//! HTTP/2 client usable over an arbitrary stream without new
//! dependencies, and the control servers' noise handlers are Go
//! `http.Server`s configured with `SetUnencryptedHTTP2(true)`, which
//! serve HTTP/1.1 and h2c side by side (the server sniffs the h2
//! preface; a plain request line is HTTP/1.1). The paths, JSON bodies
//! and the map response framing are identical either way.
//!
//! Two further deltas, both documented in `super`'s module docs: no
//! zstd request (`MapRequest.Compress = ""`, upstream asks for "zstd" at
//! direct.go:1110 — zstd responses are still decoded when a server
//! sends them anyway), and one noise connection per request instead of
//! upstream's pooled `MaxConnsPerHost: 1` h2 connection.
//!
//! # The wire exchanges
//!
//! * Optional early payload: right after the Noise handshake the server
//!   may send a 9-byte header — `\xff\xff\xffTS` + BE u32 length +
//!   JSON `tailcfg.EarlyNoise` — before the HTTP session starts
//!   (control/ts2021/conn.go:82-96, 128-174). Sniffed and skipped here.
//! * Register: `POST /machine/register` (direct.go:810-847), JSON
//!   `RegisterRequest` in, JSON `RegisterResponse` out.
//! * Map poll: `POST /machine/map` (direct.go:1166-1190), the response
//!   body a stream of `LE u32 size || message` frames (direct.go:
//!   1467-1485), each a (possibly zstd-compressed) JSON `MapResponse`.

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;
use crate::transport::{tls_connect, TlsSettings};

use super::controlhttp::ControlHttpDialer;
use super::noise::{MachinePublicKey, NoiseConn};
use super::tailcfg::{
    DerpMap, Hostinfo, MapRequest, MapResponse, Node, NodeKey, RegisterRequest, RegisterResponse,
    RegisterResponseAuth, UserProfile,
};

/// The early-payload magic (control/ts2021/conn.go:90).
const EARLY_PAYLOAD_MAGIC: &[u8; 5] = b"\xff\xff\xffTS";
/// The early payload header is 9 bytes (conn.go:87).
const EARLY_HEADER_LEN: usize = 9;
/// `maxCompressedMapResponseSize` (direct.go:1460): the cap on one
/// length-prefixed map message before any allocation.
const MAX_COMPRESSED_MAP_RESPONSE_SIZE: usize = 256 << 20;
/// `watchdogTimeout` (direct.go:1018): a map read silent longer than
/// this is a broken poll.
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(120);
/// Response bodies other than the map stream are capped at 1 MiB
/// (direct.go:1440 `io.LimitReader(res.Body, 1<<20)`).
const MAX_RESPONSE_BODY: usize = 1 << 20;
/// The keep-alive message, verbatim (direct.go:1452).
const JUST_KEEP_ALIVE: &[u8] = br#"{"KeepAlive":true}"#;
/// `tailcfg.LBHeader` (tailcfg.go:3109) — the load-balancer hint header
/// carrying the node key (ts2021.AddLBHeader, client.go:314-318).
const LB_HEADER: &str = "Ts-Lb";

/// A compile-time lockstep check: the capability version the messages
/// carry must equal the noise protocol version negotiated by the
/// controlhttp dialer (direct.go seeds it from the same constant).
const _: () = assert!(
    super::tailcfg::CURRENT_CAPABILITY_VERSION == super::noise::CURRENT_PROTOCOL_VERSION as u32
);

// ---------------------------------------------------------------------------
// The /key bootstrap (direct.go:1535-1574 loadServerPubKeys)
// ---------------------------------------------------------------------------

/// `GET /key?v=<capver>` over regular HTTP(S) — NOT Noise (the
/// `OverTLSPublicKeyResponse` doc, tailcfg.go:2967-2975, says so loudly).
/// Returns the server's Noise public key.
pub async fn fetch_control_key(control_url: &str) -> Result<MachinePublicKey> {
    let (scheme, host, port) = split_url(control_url)?;
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| Error::network(format!("control /key: connect {host}:{port}: {e}")))?;
    let mut stream: BoxProxyStream = if scheme == "https" {
        let settings = TlsSettings {
            enabled: true,
            server_name: Some(host.clone()),
            skip_cert_verify: false,
            alpn: Vec::new(),
        };
        tls_connect(Box::new(tcp), &host, &settings)
            .await
            .map_err(|e| Error::network(format!("control /key: tls: {e}")))?
    } else {
        Box::new(tcp)
    };
    let req = format!(
        "GET /key?v={} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n",
        super::tailcfg::CURRENT_CAPABILITY_VERSION
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| Error::network(format!("control /key: write: {e}")))?;

    let mut reader = PlainHttpReader::new(stream);
    let head = reader.read_head().await?;
    let status = head.split("\r\n").next().unwrap_or_default();
    if !status.contains(" 200") {
        let body = reader.read_to_end(MAX_RESPONSE_BODY).await.unwrap_or_default();
        return Err(Error::network(format!(
            "fetch control key: {status} (body: {})",
            String::from_utf8_lossy(&truncate(&body, 200))
        )));
    }
    let body = reader.read_to_end(MAX_RESPONSE_BODY).await?;
    let body = strip_content_encoding(&head, body);
    // JSON first; "some old control servers might not be updated to send
    // the new format. Accept the old pre-JSON format too" (direct.go:
    // 1559-1571) — a bare 32-byte machine key.
    if let Ok(parsed) = serde_json::from_slice::<super::tailcfg::OverTlsPublicKeyResponse>(&body)
    {
        if let Some(pk) = parsed.public_key {
            return Ok(pk.to_machine_public_key());
        }
        return Err(Error::protocol("control /key: response has no publicKey"));
    }
    if body.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&body);
        return Ok(MachinePublicKey::from_bytes(key));
    }
    Err(Error::protocol(format!(
        "control /key: unrecognized body ({} bytes)",
        body.len()
    )))
}

fn truncate(v: &[u8], max: usize) -> Vec<u8> {
    v[..v.len().min(max)].to_vec()
}

/// Decode gzip response bodies (Go's http transport transparently
/// decodes them; a `Content-Encoding: gzip` answer must be handled).
fn strip_content_encoding(head: &str, body: Vec<u8>) -> Vec<u8> {
    let gzipped = head
        .lines()
        .any(|l| l.eq_ignore_ascii_case("content-encoding: gzip"));
    if !gzipped {
        return body;
    }
    use flate2::read::GzDecoder;
    let mut out = Vec::new();
    let mut dec = GzDecoder::new(&body[..]);
    if std::io::Read::read_to_end(&mut dec, &mut out).is_ok() && !out.is_empty() {
        out
    } else {
        body
    }
}

fn split_url(url: &str) -> Result<(String, String, u16)> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| Error::config(format!("control url {url:?}: missing scheme")))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let default_port = match scheme {
        "https" => 443,
        "http" => 80,
        _ => return Err(Error::config(format!("control url {url:?}: bad scheme"))),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse::<u16>().unwrap_or(default_port))
        }
        _ => (authority.to_string(), default_port),
    };
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .map(|h| h.to_string())
        .unwrap_or(host);
    if host.is_empty() {
        return Err(Error::config(format!("control url {url:?}: empty host")));
    }
    Ok((scheme.to_ascii_lowercase(), host, port))
}

/// A plain (non-noise) HTTP/1.1 reader for the `/key` fetch.
struct PlainHttpReader<S> {
    stream: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + Unpin> PlainHttpReader<S> {
    fn new(stream: S) -> Self {
        PlainHttpReader {
            stream,
            buf: Vec::new(),
        }
    }

    async fn fill(&mut self) -> Result<usize> {
        let mut tmp = [0u8; 4096];
        let n = self
            .stream
            .read(&mut tmp)
            .await
            .map_err(|e| Error::network(format!("control /key: read: {e}")))?;
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    /// Read the response head (through `\r\n\r\n`), leaving the rest of
    /// the stream buffered.
    async fn read_head(&mut self) -> Result<String> {
        loop {
            if let Some(pos) = find_subslice(&self.buf, b"\r\n\r\n") {
                let head = self.buf.drain(..pos + 4).collect();
                return String::from_utf8(head)
                    .map_err(|_| Error::protocol("control /key: non-UTF8 headers"));
            }
            if self.buf.len() > 16 * 1024 {
                return Err(Error::protocol("control /key: response head too large"));
            }
            if self.fill().await? == 0 {
                return Err(Error::protocol("control /key: EOF before headers"));
            }
        }
    }

    /// Read everything the server sends (Connection: close semantics).
    async fn read_to_end(&mut self, cap: usize) -> Result<Vec<u8>> {
        let out: Vec<u8> = std::mem::take(&mut self.buf);
        loop {
            let n = self.fill().await?;
            if n == 0 {
                break;
            }
            if out.len() > cap {
                return Err(Error::protocol("control /key: response too large"));
            }
        }
        Ok(out)
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Decode bytes as UTF-8 for String return values.
fn utf8_or_protocol(bytes: Vec<u8>, what: &str) -> Result<String> {
    String::from_utf8(bytes).map_err(|_| Error::protocol(format!("control: non-UTF8 {what}")))
}

// ---------------------------------------------------------------------------
// ControlSession: HTTP/1.1 over the Noise record stream
// ---------------------------------------------------------------------------

/// One request/response exchange over a fresh noise connection. The
/// optional EarlyNoise payload (when the server sends one) is sniffed
/// lazily at the first response read — an HTTP/2 server prefaces the
/// session with its SETTINGS frame unprompted, but an HTTP/1.1 server
/// sends nothing until a request arrives, so an eager sniff would
/// deadlock (see [`ControlSession::read_head`]).
pub struct ControlSession<S> {
    conn: NoiseConn<S>,
    /// Decrypted record bytes not yet consumed (the byte-stream view of
    /// the record layer).
    rbuf: Vec<u8>,
    /// `EarlyNoise.nodeKeyChallenge`, when the server sent one.
    early_node_key_challenge: Option<String>,
    /// Whether the early-payload sniff already ran (once per session).
    early_checked: bool,
    /// The response body still to read.
    body: BodyState,
}

#[derive(Default)]
enum BodyState {
    #[default]
    None,
    /// Exactly N bytes left (Content-Length).
    Fixed(u64),
    /// Chunked transfer coding until the 0-chunk.
    Chunked { partial: u64 },
    /// Until the connection closes (no framing headers).
    UntilClose,
}

impl ControlSession<BoxProxyStream> {
    /// Dial control (`nc.dial`, ts2021/client.go:199-282). The early
    /// payload, if any, is picked up on the first response read.
    pub async fn dial(dialer: &ControlHttpDialer) -> Result<ControlSession<BoxProxyStream>> {
        let conn = dialer.dial().await?;
        Ok(ControlSession {
            conn,
            rbuf: Vec::new(),
            early_node_key_challenge: None,
            early_checked: false,
            body: BodyState::None,
        })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> ControlSession<S> {
    /// Wrap an existing NoiseConn (tests drive the server half directly).
    pub fn over(conn: NoiseConn<S>) -> Self {
        ControlSession {
            conn,
            rbuf: Vec::new(),
            early_node_key_challenge: None,
            early_checked: false,
            body: BodyState::None,
        }
    }

    /// The EarlyNoise `nodeKeyChallenge`, if the server sent one
    /// (tailcfg.go:3085-3091) — unused by this port's flows (it feeds
    /// the tsp stateful-session protocol), surfaced for completeness.
    pub fn early_node_key_challenge(&self) -> Option<&str> {
        self.early_node_key_challenge.as_deref()
    }

    /// `readHeader` (conn.go:128-174) in its lazy form: the first nine
    /// response bytes are either the HTTP session start (pushed back) or
    /// the early-payload header (magic + BE u32 length + JSON). Runs
    /// once per session, right before the first response head read.
    async fn sniff_early_payload(&mut self) -> Result<()> {
        // Gather up to 9 bytes; the response head will be far longer, so
        // waiting for 9 bytes cannot over-block (only a total response
        // shorter than 9 bytes would, which no HTTP/1.1 server sends).
        let mut hdr = [0u8; EARLY_HEADER_LEN];
        self.read_exact(&mut hdr).await?;
        if &hdr[..EARLY_PAYLOAD_MAGIC.len()] != EARLY_PAYLOAD_MAGIC {
            // No early payload; the consumed bytes are the session
            // start and must go back to the FRONT of the buffer
            // (read_exact may have left later bytes of the same record
            // behind them).
            let mut pushed = hdr.to_vec();
            pushed.extend_from_slice(&self.rbuf);
            self.rbuf = pushed;
            return Ok(());
        }
        let len = u32::from_be_bytes(hdr[5..9].try_into().expect("4 bytes")) as usize;
        if len > 10 << 20 {
            return Err(Error::protocol("control: invalid early payload length"));
        }
        let mut payload = vec![0u8; len];
        self.read_exact(&mut payload).await?;
        let parsed: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|e| Error::protocol(format!("control: early payload JSON: {e}")))?;
        self.early_node_key_challenge = parsed
            .get("nodeKeyChallenge")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        Ok(())
    }

    /// Byte-stream read over the record layer: drain `rbuf` first, then
    /// pull one whole record.
    async fn fill(&mut self) -> Result<usize> {
        if self.rbuf.is_empty() {
            self.rbuf = self.conn.recv().await?;
        }
        Ok(self.rbuf.len())
    }

    async fn read_exact(&mut self, out: &mut [u8]) -> Result<()> {
        let mut done = 0;
        while done < out.len() {
            if self.fill().await? == 0 && self.rbuf.is_empty() {
                return Err(Error::protocol("control: EOF mid-message"));
            }
            let take = (out.len() - done).min(self.rbuf.len());
            out[done..done + take].copy_from_slice(&self.rbuf[..take]);
            self.rbuf.drain(..take);
            done += take;
        }
        Ok(())
    }

    /// Read the HTTP response head (through `\r\n\r\n`), byte-exactly so
    /// the first body byte is never swallowed. The first call also runs
    /// the lazy early-payload sniff.
    async fn read_head(&mut self) -> Result<String> {
        if !self.early_checked {
            self.early_checked = true;
            self.sniff_early_payload().await?;
        }
        let mut head = Vec::with_capacity(512);
        loop {
            if self.fill().await? == 0 && self.rbuf.is_empty() {
                return Err(Error::protocol("control: EOF before response headers"));
            }
            head.push(self.rbuf[0]);
            self.rbuf.drain(..1);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
            if head.len() > 16 * 1024 {
                return Err(Error::protocol("control: response head too large"));
            }
        }
        utf8_or_protocol(head, "response head")
    }

    /// `POST <path>` with a JSON body (ts2021.Client.Post, client.go:
    /// 293-311: json.Marshal body, Content-Type: application/json, the
    /// LB header carrying the node key). Returns the status code; the
    /// body then streams via [`ControlSession::read_body`].
    pub async fn post_json(
        &mut self,
        path: &str,
        authority: &str,
        node_key: &NodeKey,
        body: &[u8],
    ) -> Result<u16> {
        let node_hex: String = node_key.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let req = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {authority}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             {LB_HEADER}: nodekey:{node_hex}\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        );
        let mut wire = req.into_bytes();
        wire.extend_from_slice(body);
        // NoiseConn::send splits at the record boundary (4077-byte
        // maxPlaintextSize frames) — the server side just reads bytes.
        self.conn.send(&wire).await?;

        let head = self.read_head().await?;
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let status = status_line
            .split_ascii_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| Error::protocol(format!("control: bad status line {status_line:?}")))?;
        let mut content_length: Option<u64> = None;
        let mut chunked = false;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                if k.eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse::<u64>().ok();
                } else if k.eq_ignore_ascii_case("transfer-encoding")
                    && v.to_ascii_lowercase().contains("chunked")
                {
                    chunked = true;
                }
            }
        }
        self.body = if chunked {
            BodyState::Chunked { partial: 0 }
        } else if let Some(len) = content_length {
            BodyState::Fixed(len)
        } else {
            // Read until the connection closes (the map poll's streaming
            // responses carry no length).
            BodyState::UntilClose
        };
        Ok(status)
    }

    /// Read up to `out.len()` bytes of the response body according to its
    /// framing; `Ok(0)` = end of body.
    pub async fn read_body(&mut self, out: &mut [u8]) -> Result<usize> {
        // The framing state is taken out for the match: the fixed and
        // chunked arms need `&mut self` (fill/read_exact) while holding
        // their counters.
        let state = std::mem::take(&mut self.body);
        let (n, state) = match state {
            BodyState::None | BodyState::Fixed(0) => (Ok(0), state),
            BodyState::Fixed(mut left) => {
                let want = (out.len() as u64).min(left) as usize;
                let mut done = 0;
                while done < want {
                    if self.fill().await? == 0 && self.rbuf.is_empty() {
                        return Err(Error::protocol(
                            "control: EOF inside a fixed-length body",
                        ));
                    }
                    let take = (want - done).min(self.rbuf.len());
                    out[done..done + take].copy_from_slice(&self.rbuf[..take]);
                    self.rbuf.drain(..take);
                    done += take;
                }
                left -= done as u64;
                (Ok(done), BodyState::Fixed(left))
            }
            BodyState::UntilClose => {
                if self.rbuf.is_empty() {
                    match self.conn.recv().await {
                        Ok(record) => {
                            if record.is_empty() {
                                return Ok(0);
                            }
                            self.rbuf = record;
                        }
                        Err(_) => return Ok(0),
                    }
                }
                let take = out.len().min(self.rbuf.len());
                out[..take].copy_from_slice(&self.rbuf[..take]);
                self.rbuf.drain(..take);
                (Ok(take), BodyState::UntilClose)
            }
            BodyState::Chunked { mut partial } => {
                // RFC 9112 §7.1: size-line (hex, CRLF), data, CRLF; a
                // zero chunk ends the body (trailers then final CRLF).
                if partial == 0 {
                    let size = self.read_chunk_header().await?;
                    if size == 0 {
                        return Ok(0);
                    }
                    partial = size;
                }
                let want = (out.len() as u64).min(partial) as usize;
                let mut done = 0;
                while done < want {
                    if self.fill().await? == 0 && self.rbuf.is_empty() {
                        return Err(Error::protocol("control: EOF inside a chunk"));
                    }
                    let take = (want - done).min(self.rbuf.len());
                    out[done..done + take].copy_from_slice(&self.rbuf[..take]);
                    self.rbuf.drain(..take);
                    done += take;
                }
                partial -= done as u64;
                if partial == 0 {
                    // Swallow the CRLF after the chunk data.
                    let mut crlf = [0u8; 2];
                    self.read_exact(&mut crlf).await?;
                }
                (Ok(done), BodyState::Chunked { partial })
            }
        };
        self.body = state;
        n
    }

    async fn read_chunk_header(&mut self) -> Result<u64> {
        let mut line = Vec::new();
        loop {
            if self.fill().await? == 0 && self.rbuf.is_empty() {
                return Err(Error::protocol("control: EOF in chunk header"));
            }
            let b = self.rbuf[0];
            self.rbuf.drain(..1);
            if b == b'\n' {
                break;
            }
            if b != b'\r' {
                line.push(b);
            }
            if line.len() > 32 {
                return Err(Error::protocol("control: bad chunk header"));
            }
        }
        let text = String::from_utf8_lossy(&line).into_owned();
        let size_str = text.split(';').next().unwrap_or("").trim();
        u64::from_str_radix(size_str, 16)
            .map_err(|_| Error::protocol("control: bad chunk size"))
    }

    /// Read the whole (small, non-streaming) body: register responses,
    /// error bodies (direct.go:1438-1448 caps at 1 MiB).
    pub async fn read_body_to_end(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = self.read_body(&mut chunk).await?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
            if out.len() > MAX_RESPONSE_BODY {
                return Err(Error::protocol("control: response body exceeds 1 MiB"));
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Register (direct.go TryLogin's auth-key leg, 759-860)
// ---------------------------------------------------------------------------

/// The outcome of one register round: success, or the interactive-URL
/// branch upstream parks in a `LoginGoal{url}` (auto.go:386-405).
#[derive(Debug)]
pub enum RegisterOutcome {
    /// `resp.AuthURL == "" && resp.Error == ""` — registered; the map
    /// poll may start (auto.go:411-429 commits loggedIn and restarts the
    /// map routine).
    Registered(Box<RegisterResponse>),
    /// The control server wants an interactive browser login. Staged,
    /// not ported: a headless proxy cannot open the URL. The URL is
    /// carried for the integrator to surface.
    NeedsBrowserAuth(String),
}

/// Build the RegisterRequest exactly like direct.go:759-804: the node
/// key (fresh or persisted), Hostinfo with a BackendLogID, the auth key
/// in `Auth.AuthKey` (786-789), `Ephemeral` from the login flags (766),
/// and `Version = CurrentCapabilityVersion` before sending (804).
pub fn build_register_request(
    node_key: &NodeKey,
    old_node_key: Option<&NodeKey>,
    auth_key: &str,
    hostinfo: Hostinfo,
    ephemeral: bool,
) -> RegisterRequest {
    RegisterRequest {
        version: super::tailcfg::CURRENT_CAPABILITY_VERSION,
        node_key: node_key.clone(),
        old_node_key: old_node_key
            .cloned()
            .unwrap_or_else(RegisterRequest::zero_node_key),
        nl_key: Default::default(),
        auth: (!auth_key.is_empty()).then(|| RegisterResponseAuth {
            oauth2_token: None,
            auth_key: auth_key.to_string(),
        }),
        expiry: None,
        followup: String::new(),
        hostinfo: Some(hostinfo),
        ephemeral,
        tailnet: String::new(),
    }
}

/// Run one register exchange over a fresh session
/// (POST /machine/register, direct.go:810-860).
pub async fn register(
    session: &mut ControlSession<BoxProxyStream>,
    authority: &str,
    request: &RegisterRequest,
) -> Result<RegisterOutcome> {
    let body = serde_json::to_vec(request)
        .map_err(|e| Error::config(format!("register request JSON: {e}")))?;
    let status = session
        .post_json("/machine/register", authority, &request.node_key, &body)
        .await?;
    let body = session.read_body_to_end().await?;
    if status != 200 {
        // direct.go:828-834 "register request: http %d".
        return Err(Error::protocol(format!(
            "register request: http {status}: {}",
            String::from_utf8_lossy(&truncate(&body, 200))
        )));
    }
    let resp: RegisterResponse = serde_json::from_slice(&body)
        .map_err(|e| Error::protocol(format!("register request: bad JSON: {e}")))?;
    if !resp.error.is_empty() {
        // direct.go:849-851.
        return Err(Error::protocol(format!("register request: {}", resp.error)));
    }
    if !resp.auth_url.is_empty() {
        // auto.go:386-405 stores the URL as the next login goal and
        // waits for the visit; staged here instead (see RegisterOutcome).
        return Ok(RegisterOutcome::NeedsBrowserAuth(resp.auth_url));
    }
    if resp.node_key_expired {
        return Err(Error::protocol(
            "register request: node key expired (key rotation is not ported)",
        ));
    }
    Ok(RegisterOutcome::Registered(Box::new(resp)))
}

// ---------------------------------------------------------------------------
// mapSession (map.go:52-1055) — delta application + netmap building
// ---------------------------------------------------------------------------

/// The inflated network map (types/netmap.NetworkMap's consumed fields,
/// `mapSession.netmap()`, map.go:1007-1056).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetMap {
    /// The self node (`MapResponse.Node`).
    pub self_node: Node,
    /// Our node key (`ms.publicNodeKey`).
    pub node_key: NodeKey,
    /// All peers, sorted by Node ID (map.go:993-1005 sortedPeers).
    pub peers: Vec<Node>,
    pub derp_map: DerpMap,
    /// The profiles of every user among self+peers (map.go:1051-1055).
    pub user_profiles: BTreeMap<i64, UserProfile>,
    /// The tailnet domain (`MapResponse.Domain`).
    pub domain: String,
}

impl NetMap {
    /// Longest-prefix cryptokey routing: the peer whose AllowedIPs best
    /// match `ip` (ties: the earlier peer — peers are sorted by ID).
    pub fn route_peer(&self, ip: std::net::IpAddr) -> Option<&Node> {
        let mut best: Option<(u8, &Node)> = None;
        for peer in &self.peers {
            for prefix in &peer.allowed_ips {
                if prefix.contains(&ip) {
                    let better = best
                        .as_ref()
                        .map(|(bits, _)| prefix.bits > *bits)
                        .unwrap_or(true);
                    if better {
                        best = Some((prefix.bits, peer));
                    }
                }
            }
        }
        best.map(|(_, peer)| peer)
    }

    /// A peer by its node key.
    pub fn peer_by_key(&self, key: &[u8; 32]) -> Option<&Node> {
        self.peers.iter().find(|p| p.key.as_bytes() == key)
    }
}

/// The stateful session over one long-poll (map.go:52-134 mapSession):
/// applies each MapResponse to the accumulated peer state and produces
/// fully-inflated NetMaps.
#[derive(Debug, Default)]
pub struct MapSession {
    peers: BTreeMap<i64, Node>,
    last_node: Option<Node>,
    last_derp_map: Option<DerpMap>,
    last_user_profiles: BTreeMap<i64, UserProfile>,
    last_domain: String,
    node_key: NodeKey,
}

impl MapSession {
    pub fn new(node_key: NodeKey) -> Self {
        MapSession {
            node_key,
            ..Default::default()
        }
    }

    /// `upgradeNode` (map.go:244-272): canonicalize the deprecated DERP
    /// string into `HomeDERP` (the "127.3.3.40:<region>" form,
    /// tailcfg.go:421-431) and fill implicit AllowedIPs from Addresses.
    fn upgrade_node(n: &mut Node) {
        if !n.legacy_derp_string.is_empty() {
            if n.home_derp == 0 {
                if let Some((ip, port)) = n.legacy_derp_string.rsplit_once(':') {
                    if ip == "127.3.3.40" {
                        if let Ok(region) = port.parse::<i64>() {
                            n.home_derp = region;
                        }
                    }
                }
            }
            n.legacy_derp_string = String::new();
        }
        if n.allowed_ips.is_empty() {
            // "As of CapabilityVersion 112, this may be nil on the wire
            // to mean the same as Addresses" (tailcfg.go:393-395).
            n.allowed_ips = n.addresses.clone();
        }
    }

    /// `HandleNonKeepAliveMapResponse` minus the knob/display pieces:
    /// apply the deltas, then build the netmap. Returns `None` for
    /// keep-alive messages (direct.go:1327-1331 ignores them beyond the
    /// watchdog reset).
    pub fn handle_response(&mut self, resp: &MapResponse) -> Option<NetMap> {
        if resp.keep_alive {
            return None;
        }
        // upgradeNode over every node-bearing field (map.go:209-218).
        let mut resp = resp.clone();
        if let Some(node) = resp.node.as_mut() {
            Self::upgrade_node(node);
        }
        for p in resp.peers.iter_mut().chain(resp.peers_changed.iter_mut()) {
            Self::upgrade_node(p);
        }

        // updatePeersStateFromResponse (map.go:550-672).
        if !resp.peers.is_empty() {
            // "Peers precludes all other delta operations" (map.go:556-570).
            self.peers = resp
                .peers
                .iter()
                .map(|n| (n.id, n.clone()))
                .collect::<BTreeMap<_, _>>();
        } else {
            for id in &resp.peers_removed {
                self.peers.remove(id);
            }
            for n in &resp.peers_changed {
                self.peers.insert(n.id, n.clone());
            }
            if let Some(seen) = &resp.peer_seen_change {
                for (id, online) in seen {
                    if let Some(peer) = self.peers.get_mut(id) {
                        // "If the value is false, the peer is gone. If
                        // true, the LastSeen time is now" (tailcfg.go:
                        // 2168-2172).
                        peer.last_seen = online.then_some("now".to_string());
                    }
                }
            }
            if let Some(online) = &resp.online_change {
                for (id, state) in online {
                    if let Some(peer) = self.peers.get_mut(id) {
                        peer.online = Some(*state);
                    }
                }
            }
            for pc in &resp.peers_changed_patch {
                let Some(peer) = self.peers.get_mut(&pc.node_id) else {
                    // "If the NodeID is not known in the current netmap,
                    // this update should be ignored" (map.go:3037-3039).
                    continue;
                };
                if pc.derp_region != 0 {
                    peer.home_derp = pc.derp_region;
                }
                if !pc.endpoints.is_empty() {
                    peer.endpoints = pc.endpoints.clone();
                }
                if let Some(key) = &pc.key {
                    peer.key = key.clone();
                }
                if let Some(online) = pc.online {
                    peer.online = Some(online);
                }
                if pc.last_seen.is_some() {
                    peer.last_seen = pc.last_seen.clone();
                }
                if pc.key_expiry.is_some() {
                    peer.key_expiry = pc.key_expiry.clone();
                }
            }
        }

        // updateStateFromResponse (map.go:368-470: node, profiles, DERP
        // map, domain).
        if let Some(node) = resp.node.clone() {
            self.last_node = Some(node);
        }
        for up in &resp.user_profiles {
            self.last_user_profiles.insert(up.id, up.clone());
        }
        if let Some(dm) = resp.derp_map.clone() {
            // Guard against empty regions, "which at least Headscale was
            // observed to send" (map.go:399-404).
            let mut dm = dm;
            dm.regions
                .retain(|_, r| !r.nodes.is_empty() || !r.region_name.is_empty());
            // "Zero-valued fields in a DERPMap mean that we're not
            // changing anything" (map.go:435-443).
            if dm.regions.is_empty() {
                if let Some(last) = &self.last_derp_map {
                    dm.regions = last.regions.clone();
                    dm.omit_default_regions = last.omit_default_regions;
                }
            }
            self.last_derp_map = Some(dm);
        }
        if !resp.domain.is_empty() {
            self.last_domain = resp.domain.clone();
        }

        Some(self.netmap())
    }

    /// `netmap()` (map.go:1007-1056): the fully-inflated map.
    pub fn netmap(&self) -> NetMap {
        NetMap {
            self_node: self.last_node.clone().unwrap_or_default(),
            node_key: self.node_key.clone(),
            peers: self.peers.values().cloned().collect(),
            derp_map: self.last_derp_map.clone().unwrap_or_default(),
            user_profiles: self.last_user_profiles.clone(),
            domain: self.last_domain.clone(),
        }
    }
}

/// Build the map request like direct.go:1083-1094 (plus Compress="",
/// see the module docs).
pub fn build_map_request(node_key: &NodeKey, hostinfo: Hostinfo, streaming: bool) -> MapRequest {
    MapRequest {
        version: super::tailcfg::CURRENT_CAPABILITY_VERSION,
        compress: String::new(),
        keep_alive: true,
        node_key: node_key.clone(),
        disco_key: Default::default(),
        stream: streaming,
        hostinfo: Some(hostinfo),
        endpoints: Vec::new(),
        omit_peers: false,
    }
}

/// Decode one length-prefixed map message: zstd when compressed
/// (`decodeMsg`, direct.go:1487-1519 uses zstdframe.AppendDecode; the
/// engine's decode-only zstd crate `ruzstd` reads the same frames), plain
/// JSON otherwise; the literal keep-alive short-circuits (direct.go:
/// 1452, 1490-1494).
pub fn decode_map_message(msg: &[u8]) -> Result<MapResponse> {
    if msg == JUST_KEEP_ALIVE || msg.first() == Some(&b'{') {
        return serde_json::from_slice(msg)
            .map_err(|e| Error::protocol(format!("netmap: bad map response JSON: {e}")));
    }
    let mut out = Vec::new();
    let mut dec = ruzstd::decoding::StreamingDecoder::new(msg)
        .map_err(|e| Error::protocol(format!("netmap: zstd: {e}")))?;
    std::io::Read::read_to_end(&mut dec, &mut out)
        .map_err(|e| Error::protocol(format!("netmap: zstd: {e}")))?;
    serde_json::from_slice(&out)
        .map_err(|e| Error::protocol(format!("netmap: bad map response JSON: {e}")))
}

/// The long-poll loop (direct.go sendMapRequest's read loop, 1245-1330):
/// read length-prefixed messages until the connection dies, feeding each
/// through the session and invoking `on_map` for every rebuilt netmap.
/// Only returns on error (upstream: "only returns if the context expires
/// or the server returns an error/closes the connection").
pub async fn stream_map<F>(
    session: &mut ControlSession<BoxProxyStream>,
    authority: &str,
    request: &MapRequest,
    map_session: &mut MapSession,
    mut on_map: F,
) -> Result<()>
where
    F: FnMut(&NetMap),
{
    let body = serde_json::to_vec(request)
        .map_err(|e| Error::config(format!("map request JSON: {e}")))?;
    let status = session
        .post_json("/machine/map", authority, &request.node_key, &body)
        .await?;
    if status != 200 {
        // The error body is small; read it for the message like
        // direct.go:1216-1220 does.
        let err_body = session.read_body_to_end().await.unwrap_or_default();
        return Err(Error::protocol(format!(
            "initial fetch failed {status}: {}",
            String::from_utf8_lossy(&truncate(&err_body, 200))
        )));
    }

    // readMapResponseMessage (direct.go:1471-1485): LE u32 size, then
    // that many bytes. The watchdog (direct.go:1018, 1175-1185) bounds
    // every read.
    let mut msg = Vec::new();
    loop {
        let read = tokio::time::timeout(WATCHDOG_TIMEOUT, async {
            let mut size = [0u8; 4];
            if !read_body_exact(session, &mut size).await? {
                return Ok(false);
            }
            let size = u32::from_le_bytes(size) as usize;
            if size > MAX_COMPRESSED_MAP_RESPONSE_SIZE {
                return Err(Error::protocol(format!(
                    "map response message size {size} exceeds max"
                )));
            }
            msg.clear();
            msg.resize(size, 0);
            if size > 0 {
                read_body_exact(session, &mut msg).await?;
            }
            Ok(true)
        })
        .await
        .map_err(|_| Error::network("map response long-poll timed out"))??;

        if !read {
            // The server closed the poll (Stream ended).
            return Ok(());
        }
        let resp = decode_map_message(&msg)?;
        if let Some(netmap) = map_session.handle_response(&resp) {
            on_map(&netmap);
        }
    }
}

async fn read_body_exact(
    session: &mut ControlSession<BoxProxyStream>,
    out: &mut [u8],
) -> Result<bool> {
    let mut done = 0;
    while done < out.len() {
        let n = session.read_body(&mut out[done..]).await?;
        if n == 0 {
            if done == 0 {
                return Ok(false);
            }
            return Err(Error::protocol("control: EOF inside a map message"));
        }
        done += n;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::derp::NodePrivateKey;
    use super::super::noise::{client_handshake, server_handshake, MachinePrivateKey};
    use super::super::tailcfg::Prefix;
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn gen_pub() -> [u8; 32] {
        *NodePrivateKey::generate().public().as_bytes()
    }

    fn hostinfo() -> Hostinfo {
        Hostinfo {
            backend_log_id: "logid-test".into(),
            os: "linux".into(),
            app: "rustcrash".into(),
            hostname: "rustcrash-node".into(),
            userspace: Some(true),
            ..Default::default()
        }
    }

    // -- pure pieces -------------------------------------------------------

    #[test]
    fn map_message_decoding_accepts_plain_and_keepalive() {
        let ka = decode_map_message(JUST_KEEP_ALIVE).unwrap();
        assert!(ka.keep_alive);
        let resp = decode_map_message(br#"{"Domain":"x.example"}"#).unwrap();
        assert_eq!(resp.domain, "x.example");
        // Garbage that is neither JSON nor zstd fails clearly.
        assert!(decode_map_message(b"\x00\x01not-zstd-not-json").is_err());
    }

    #[test]
    fn map_session_applies_full_map_then_each_delta_kind() {
        let self_key = NodeKey(gen_pub());
        let p1 = gen_pub();
        let p2 = gen_pub();
        let mut ms = MapSession::new(self_key.clone());

        // Full map: self + two peers (map.go:556-570 path).
        let full = MapResponse {
            node: Some(Node {
                id: 1,
                addresses: vec![Prefix::new("100.64.0.1".parse().unwrap(), 32)],
                ..Default::default()
            }),
            peers: vec![
                Node {
                    id: 10,
                    key: NodeKey(p1),
                    allowed_ips: vec![Prefix::new("100.64.0.10".parse().unwrap(), 32)],
                    home_derp: 0,
                    legacy_derp_string: "127.3.3.40:2".into(),
                    ..Default::default()
                },
                Node {
                    id: 20,
                    key: NodeKey(p2),
                    allowed_ips: vec![Prefix::new("100.64.0.20".parse().unwrap(), 32)],
                    online: Some(true),
                    ..Default::default()
                },
            ],
            user_profiles: vec![UserProfile {
                id: 7,
                login_name: "u@example".into(),
                ..Default::default()
            }],
            domain: "x.example".into(),
            ..Default::default()
        };
        let nm = ms.handle_response(&full).expect("full map produces a netmap");
        assert_eq!(nm.peers.len(), 2);
        assert_eq!(nm.domain, "x.example");
        // upgradeNode: the legacy DERP string became HomeDERP=2 and was
        // cleared (map.go:245-255).
        assert_eq!(nm.peers[0].home_derp, 2);
        assert_eq!(nm.peers[0].legacy_derp_string, "");
        // Peers sorted by ID (sortedPeers, map.go:993-1005).
        assert_eq!(nm.peers[0].id, 10);
        assert_eq!(nm.user_profiles.get(&7).unwrap().login_name, "u@example");
        // Cryptokey routing through AllowedIPs.
        assert_eq!(nm.route_peer("100.64.0.10".parse().unwrap()).unwrap().id, 10);
        assert!(nm.route_peer("10.0.0.1".parse().unwrap()).is_none());

        // PeersRemoved (map.go:573-580).
        let nm = ms
            .handle_response(&MapResponse {
                peers_removed: vec![20],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(nm.peers.len(), 1);
        assert_eq!(nm.peers[0].id, 10);

        // PeerSeenChange + OnlineChange (map.go:590-617).
        let mut seen = BTreeMap::new();
        seen.insert(10i64, true);
        let mut online = BTreeMap::new();
        online.insert(10i64, false);
        let nm = ms
            .handle_response(&MapResponse {
                peer_seen_change: Some(seen),
                online_change: Some(online),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(nm.peers[0].online, Some(false));
        assert_eq!(nm.peers[0].last_seen.as_deref(), Some("now"));

        // PeersChangedPatch: endpoints + DERP region + expiry
        // (map.go:633-672).
        let nm = ms
            .handle_response(&MapResponse {
                peers_changed_patch: vec![super::super::tailcfg::PeerChange {
                    node_id: 10,
                    derp_region: 5,
                    endpoints: vec![super::super::tailcfg::AddrPort(
                        "127.0.0.1:5555".parse().unwrap(),
                    )],
                    key_expiry: Some("2999-01-01T00:00:00Z".into()),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(nm.peers[0].home_derp, 5);
        assert_eq!(nm.peers[0].endpoints[0].0.port(), 5555);
        assert_eq!(nm.peers[0].key_expiry.as_deref(), Some("2999-01-01T00:00:00Z"));
        // An unknown NodeID patch is ignored (map.go:3037-3039).
        let nm = ms
            .handle_response(&MapResponse {
                peers_changed_patch: vec![super::super::tailcfg::PeerChange {
                    node_id: 999,
                    derp_region: 9,
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(nm.peers.len(), 1);
        assert_eq!(nm.peers[0].home_derp, 5);

        // KeepAlive produces no netmap (direct.go:1327-1331).
        assert!(ms
            .handle_response(&MapResponse {
                keep_alive: true,
                ..Default::default()
            })
            .is_none());

        // A second full Peers list REPLACES the set (map.go:556-570:
        // "not delta encoded").
        let nm = ms
            .handle_response(&MapResponse {
                peers: vec![Node {
                    id: 30,
                    key: NodeKey(gen_pub()),
                    allowed_ips: vec![Prefix::new("100.64.0.30".parse().unwrap(), 32)],
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(nm.peers.len(), 1);
        assert_eq!(nm.peers[0].id, 30);
    }

    // -- wire exchanges against the in-test server half -------------------

    /// The control server half for one noise connection: /ts2021 upgrade,
    /// server_handshake, then read one HTTP/1.1 request, answer with
    /// `respond`.
    #[allow(clippy::type_complexity)]
    type ControlMimicRespond = fn(&str, &str, &[u8]) -> Option<(u16, String)>;

    async fn control_mimic(
        listener: tokio::net::TcpListener,
        control_key: MachinePrivateKey,
        respond: ControlMimicRespond,
    ) {
        let (socket, _) = listener.accept().await.expect("mimic accept");
        let (mut r, mut w) = tokio::io::split(socket);
        let mut head = Vec::new();
        loop {
            let mut b = [0u8; 1];
            r.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        assert!(head.starts_with("POST /ts2021 HTTP/1.1"), "{head}");
        let b64 = head
            .lines()
            .find_map(|l| l.strip_prefix("X-Tailscale-Handshake: "))
            .expect("handshake header");
        let init = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        w.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: tailscale-control-protocol\r\n\
              Connection: upgrade\r\n\r\n",
        )
        .await
        .unwrap();
        w.flush().await.unwrap();
        let socket = r.unsplit(w);
        let mut conn = server_handshake(socket, &control_key, Some(init))
            .await
            .unwrap();

        // Inside noise: one HTTP/1.1 request (head + Content-Length body).
        let (method, path, body) = read_noise_http_request(&mut conn).await;
        if let Some((status, resp_body)) = respond(&method, &path, &body) {
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                resp_body.len()
            );
            let mut wire = head.into_bytes();
            wire.extend_from_slice(resp_body.as_bytes());
            conn.send(&wire).await.unwrap();
        }
    }

    /// Read one whole HTTP/1.1 request out of the noise records.
    async fn read_noise_http_request<S>(conn: &mut NoiseConn<S>) -> (String, String, Vec<u8>)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut buf = Vec::new();
        let (content_len, head_end) = loop {
            let text = String::from_utf8_lossy(&buf).into_owned();
            if let Some(pos) = text.find("\r\n\r\n") {
                if let Some(cl) = text
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                {
                    if buf.len() >= pos + 4 + cl {
                        break (cl, pos + 4);
                    }
                } else if buf.len() >= pos + 4 {
                    break (0, pos + 4);
                }
            }
            buf.extend_from_slice(&conn.recv().await.unwrap());
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let mut body = buf[head_end..head_end + content_len].to_vec();
        while body.len() < content_len {
            body.extend_from_slice(&conn.recv().await.unwrap());
        }
        let request_line = head.lines().next().unwrap_or_default();
        let mut parts = request_line.split_ascii_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts.next().unwrap_or_default().to_string();
        (method, path, body)
    }

    #[tokio::test]
    async fn register_exchange_over_noise_h1() {
        let control_key = MachinePrivateKey::generate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_key = control_key.clone();
        tokio::spawn(control_mimic(listener, server_key, |method, path, body| {
            assert_eq!(method, "POST");
            assert_eq!(path, "/machine/register");
            let req: RegisterRequest = serde_json::from_slice(body).unwrap();
            assert_eq!(req.version, super::super::tailcfg::CURRENT_CAPABILITY_VERSION);
            assert!(!req.hostinfo.as_ref().unwrap().backend_log_id.is_empty());
            assert!(!req.auth.as_ref().unwrap().auth_key.is_empty());
            assert_eq!(req.hostinfo.as_ref().unwrap().app, "rustcrash");
            Some((200, r#"{"MachineAuthorized":true}"#.to_string()))
        }));

        let dialer = ControlHttpDialer::from_url(
            &format!("http://{addr}"),
            MachinePrivateKey::generate(),
            control_key.public(),
        )
        .unwrap();
        let mut session = ControlSession::dial(&dialer).await.unwrap();
        let node = NodePrivateKey::generate();
        let req = build_register_request(
            &NodeKey(*node.public().as_bytes()),
            None,
            "auth-key-generated-in-test",
            hostinfo(),
            false,
        );
        let authority = format!("127.0.0.1:{}", addr.port());
        match register(&mut session, &authority, &req).await.unwrap() {
            RegisterOutcome::Registered(resp) => assert!(resp.machine_authorized),
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_error_and_browser_branches() {
        let node = NodePrivateKey::generate();
        let req = build_register_request(
            &NodeKey(*node.public().as_bytes()),
            None,
            "k",
            Hostinfo {
                backend_log_id: "l".into(),
                ..Default::default()
            },
            false,
        );

        // resp.Error is a hard error (direct.go:849-851).
        let control_key = MachinePrivateKey::generate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let k = control_key.clone();
        tokio::spawn(control_mimic(listener, k, |_, _, _| {
            Some((200, r#"{"Error":"access denied"}"#.to_string()))
        }));
        let dialer = ControlHttpDialer::from_url(
            &format!("http://{addr}"),
            MachinePrivateKey::generate(),
            control_key.public(),
        )
        .unwrap();
        let mut session = ControlSession::dial(&dialer).await.unwrap();
        let err = register(&mut session, "a", &req).await.unwrap_err();
        assert!(err.to_string().contains("access denied"), "{err}");

        // AuthURL is the staged interactive branch.
        let control_key = MachinePrivateKey::generate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let k = control_key.clone();
        tokio::spawn(control_mimic(listener, k, |_, _, _| {
            Some((
                200,
                r#"{"AuthURL":"https://control.example/a/1"}"#.to_string(),
            ))
        }));
        let dialer = ControlHttpDialer::from_url(
            &format!("http://{addr}"),
            MachinePrivateKey::generate(),
            control_key.public(),
        )
        .unwrap();
        let mut session = ControlSession::dial(&dialer).await.unwrap();
        match register(&mut session, "a", &req).await.unwrap() {
            RegisterOutcome::NeedsBrowserAuth(url) => {
                assert_eq!(url, "https://control.example/a/1")
            }
            other => panic!("unexpected outcome: {other:?}"),
        }

        // A non-200 is a hard error (direct.go:828-834).
        let control_key = MachinePrivateKey::generate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let k = control_key.clone();
        tokio::spawn(control_mimic(listener, k, |_, _, _| {
            Some((500, "boom".to_string()))
        }));
        let dialer = ControlHttpDialer::from_url(
            &format!("http://{addr}"),
            MachinePrivateKey::generate(),
            control_key.public(),
        )
        .unwrap();
        let mut session = ControlSession::dial(&dialer).await.unwrap();
        let err = register(&mut session, "a", &req).await.unwrap_err();
        assert!(err.to_string().contains("http 500"), "{err}");
    }

    /// A streaming map mimic: one noise conn that answers the map POST
    /// with a chunked stream of length-prefixed messages, then holds the
    /// long-poll open like a real control server.
    async fn map_mimic(
        listener: tokio::net::TcpListener,
        control_key: MachinePrivateKey,
        messages: Vec<Vec<u8>>,
    ) {
        let (socket, _) = listener.accept().await.expect("mimic accept");
        let (mut r, mut w) = tokio::io::split(socket);
        let mut head = Vec::new();
        loop {
            let mut b = [0u8; 1];
            r.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        let b64 = head
            .lines()
            .find_map(|l| l.strip_prefix("X-Tailscale-Handshake: "))
            .expect("handshake header");
        let init = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        w.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: tailscale-control-protocol\r\n\
              Connection: upgrade\r\n\r\n",
        )
        .await
        .unwrap();
        w.flush().await.unwrap();
        let socket = r.unsplit(w);
        let mut conn = server_handshake(socket, &control_key, Some(init))
            .await
            .unwrap();

        let (method, path, body) = read_noise_http_request(&mut conn).await;
        assert_eq!((method.as_str(), path.as_str()), ("POST", "/machine/map"));
        let req: MapRequest = serde_json::from_slice(&body).unwrap();
        assert!(req.stream, "the long-poll sets Stream");
        assert!(req.keep_alive);
        assert_eq!(req.version, super::super::tailcfg::CURRENT_CAPABILITY_VERSION);
        assert!(req.compress.is_empty());

        // 200 + chunked stream of length-prefixed messages (LE u32 +
        // message per chunk, exactly the body framing direct.go reads).
        conn.send(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        for msg in messages {
            let mut framed = Vec::with_capacity(4 + msg.len());
            framed.extend_from_slice(&(msg.len() as u32).to_le_bytes());
            framed.extend_from_slice(&msg);
            let mut chunk = format!("{:x}\r\n", framed.len()).into_bytes();
            chunk.extend_from_slice(&framed);
            chunk.extend_from_slice(b"\r\n");
            conn.send(&chunk).await.unwrap();
        }
        // Hold the poll open (a real long-poll keeps streaming); exit
        // when the client goes away.
        loop {
            if conn.recv().await.is_err() {
                break;
            }
        }
    }

    #[tokio::test]
    async fn map_poll_streams_and_applies_deltas() {
        let control_key = MachinePrivateKey::generate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let node = NodePrivateKey::generate();
        let node_key = NodeKey(*node.public().as_bytes());
        let peer_key = NodeKey(gen_pub());

        let self_hex: String = node_key.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let peer_hex: String = peer_key.as_bytes().iter().map(|b| format!("{b:02x}")).collect();

        let first = format!(
            r#"{{"Node":{{"ID":1,"Key":"nodekey:{self_hex}",
                 "Addresses":["100.64.0.1/32"],
                 "AllowedIPs":["100.64.0.1/32"]}},
                "Peers":[{{"ID":2,"Key":"nodekey:{peer_hex}",
                 "Addresses":["100.64.0.2/32"],
                 "AllowedIPs":["100.64.0.2/32"],
                 "Endpoints":["127.0.0.1:4242"],"HomeDERP":1}}],
                "Domain":"poll.example"}}"#
        );
        let messages = vec![
            JUST_KEEP_ALIVE.to_vec(), // watchdog reset, no netmap
            first.into_bytes(),
            br#"{"PeersChangedPatch":[{"NodeID":2,"DERPRegion":3}],"OnlineChange":{"2":false}}"#
                .to_vec(),
        ];
        let k = control_key.clone();
        tokio::spawn(map_mimic(listener, k, messages));

        let dialer = ControlHttpDialer::from_url(
            &format!("http://{addr}"),
            MachinePrivateKey::generate(),
            control_key.public(),
        )
        .unwrap();
        let mut session = ControlSession::dial(&dialer).await.unwrap();
        let mut ms = MapSession::new(node_key.clone());
        let req = build_map_request(&node_key, hostinfo(), true);

        let maps = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = maps.clone();
        // The mimic holds the poll open (a real long-poll), so the poll
        // future only ends at our 5s deadline or when the session drops;
        // the assertions are on the maps delivered until then.
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let authority = format!("127.0.0.1:{}", addr.port());
            let _ = stream_map(&mut session, &authority, &req, &mut ms, move |nm| {
                sink.lock().unwrap().push(nm.clone());
            })
            .await;
        })
        .await;
        drop(session);

        let got = maps.lock().unwrap().clone();
        assert_eq!(got.len(), 2, "keepalive produced no netmap: {got:?}");
        assert_eq!(got[0].peers.len(), 1);
        assert_eq!(got[0].peers[0].home_derp, 1);
        assert_eq!(got[0].domain, "poll.example");
        assert_eq!(got[0].peers[0].endpoints[0].0.port(), 4242);
        // The delta applied on top (patch + online change).
        assert_eq!(got[1].peers[0].home_derp, 3);
        assert_eq!(got[1].peers[0].online, Some(false));
    }

    #[tokio::test]
    async fn map_poll_surfaces_a_non_200_initial_fetch() {
        let control_key = MachinePrivateKey::generate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let k = control_key.clone();
        tokio::spawn(control_mimic(listener, k, |method, path, _| {
            assert_eq!((method, path), ("POST", "/machine/map"));
            Some((403, "forbidden".to_string()))
        }));
        let dialer = ControlHttpDialer::from_url(
            &format!("http://{addr}"),
            MachinePrivateKey::generate(),
            control_key.public(),
        )
        .unwrap();
        let mut session = ControlSession::dial(&dialer).await.unwrap();
        let node = NodePrivateKey::generate();
        let node_key = NodeKey(*node.public().as_bytes());
        let mut ms = MapSession::new(node_key.clone());
        let err = stream_map(
            &mut session,
            "a",
            &build_map_request(&node_key, hostinfo(), true),
            &mut ms,
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("403"), "{err}");
    }

    #[tokio::test]
    async fn early_noise_payload_is_sniffed_and_skipped() {
        // conn.go:128-174: magic + BE u32 len + JSON, then the HTTP
        // session bytes.
        let control_key = MachinePrivateKey::generate();
        let control_pub = control_key.public();
        let machine_key = MachinePrivateKey::generate();
        let (client_stream, server_stream) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let mut conn =
                server_handshake(server_stream, &control_key, None).await.unwrap();
            let early = br#"{"nodeKeyChallenge":"chal1234"}"#;
            let mut payload = EARLY_PAYLOAD_MAGIC.to_vec();
            payload.extend_from_slice(&(early.len() as u32).to_be_bytes());
            payload.extend_from_slice(early);
            conn.send(&payload).await.unwrap();
            conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                .await
                .unwrap();
        });
        let conn = client_handshake(client_stream, &machine_key, &control_pub, 148)
            .await
            .unwrap();
        let mut session = ControlSession::over(conn);
        // read_head runs the lazy sniff first; the challenge is captured
        // and the HTTP session bytes still parse.
        let head = session.read_head().await.unwrap();
        assert_eq!(session.early_node_key_challenge.as_deref(), Some("chal1234"));
        assert!(head.starts_with("HTTP/1.1 200"));
        let mut body = [0u8; 2];
        session.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"hi");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn early_noise_absent_means_the_nine_bytes_are_pushed_back() {
        // No magic: the first 9 bytes belong to the HTTP session
        // (conn.go:148-152).
        let control_key = MachinePrivateKey::generate();
        let control_pub = control_key.public();
        let machine_key = MachinePrivateKey::generate();
        let (client_stream, server_stream) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let mut conn =
                server_handshake(server_stream, &control_key, None).await.unwrap();
            conn.send(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let conn = client_handshake(client_stream, &machine_key, &control_pub, 148)
            .await
            .unwrap();
        let mut session = ControlSession::over(conn);
        let head = session.read_head().await.unwrap();
        assert!(session.early_node_key_challenge.is_none());
        assert!(head.starts_with("HTTP/1.1 204"));
        server.await.unwrap();
    }

    #[test]
    fn url_splitting() {
        assert_eq!(
            split_url("https://control.example").unwrap(),
            ("https".into(), "control.example".into(), 443)
        );
        assert_eq!(
            split_url("http://127.0.0.1:8080/x").unwrap(),
            ("http".into(), "127.0.0.1".into(), 8080)
        );
        assert!(split_url("control.example").is_err());
    }

    #[tokio::test]
    async fn key_fetch_against_a_plain_http_mimic() {
        let key = MachinePrivateKey::generate();
        let hexs: String = key.public().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = format!(r#"{{"publicKey":"mkey:{hexs}"}}"#);
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 1];
            let mut head = Vec::new();
            loop {
                sock.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&head).into_owned();
            assert!(req.starts_with("GET /key?v=148 HTTP/1.1"), "{req}");
            sock.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        });
        let got = fetch_control_key(&format!("http://{addr}")).await.unwrap();
        assert_eq!(got, key.public());
    }

    #[tokio::test]
    async fn key_fetch_accepts_the_old_raw_key_body() {
        // direct.go:1559-1571: old control servers answer with the bare
        // 32-byte machine key.
        let key = MachinePrivateKey::generate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = key.public().as_bytes().to_vec();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 1];
            let mut head = Vec::new();
            loop {
                sock.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            sock.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            sock.write_all(&body).await.unwrap();
        });
        let got = fetch_control_key(&format!("http://{addr}")).await.unwrap();
        assert_eq!(got, key.public());
    }
}
