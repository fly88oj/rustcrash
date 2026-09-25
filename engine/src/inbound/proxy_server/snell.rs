//! Snell server listener: mihomo `listener/snell/server.go`.
//!
//! Every accepted connection is (optionally) wrapped in a stacked
//! security fronting, then (optionally) in http obfs, then runs the
//! server half of the wire codecs in [`crate::proto::snell`]: the
//! request header carries the target (relay like trojan), the first
//! relay write prefixes the tunnel reply, and a request that negotiated
//! `CommandConnectV2` keeps the conn alive for the next request (the
//! zero-chunk half-close + [`crate::proto::snell::SnellServerNext`]
//! continuation).
//!
//! Config gate parity with upstream `New`
//! (listener/snell/server.go:37-52): version `0` defaults to v4 (the
//! *server* default — the client's is v1), `1..=5` pass, anything else
//! is `snell inbound version %d is not supported`; an empty psk is
//! `snell inbound requires psk`; `obfs-mode` accepts `""`/`http` (the
//! `tls` mode needs the TLS-record camouflage server from
//! `transport/simple-obfs/tls_server.go`, which the engine does not
//! carry — a precise error at serve time, see [`OBFS_TLS_UNSUPPORTED`]).
//!
//! ## Stacked security frontings (server.go:56-89, 100-106)
//!
//! The three frontings — `shadow-tls`, `res-tls`, `jls` — are mutually
//! exclusive upstream (`security modes are mutually exclusive: …`,
//! server.go:56-68) and wrap the RAW listener, so they run BEFORE the
//! obfs + snell codecs of `HandleConn`. The stack order each side
//! composes is therefore exactly one of:
//!
//! | fronting    | wire stack (outer → inner)                              |
//! |-------------|---------------------------------------------------------|
//! | shadow-tls  | shadowtls v3 server → (obfs) → snell                     |
//! | res-tls     | restls camouflage server → (obfs) → snell                |
//! | jls         | JLS-authenticated TLS 1.3 server → (obfs) → snell        |
//!
//! * **shadow-tls**: the v3 SERVER half of
//!   [`crate::proto::shadowtls`] — which only ships the client — is
//!   ported into this module (see the "shadow-tls v3 server fronting"
//!   section below for the upstream citations). The enum's
//!   `(password, sni, skip-verify)` tuple maps to a single-user v3
//!   table whose handshake destination is `sni` (host or host:port,
//!   443 default); `skip-verify` is a no-op server-side (upstream's
//!   server never verifies the handshake dest's certificate either —
//!   it only relays).
//! * **res-tls**: reuses [`crate::proto::restls::server`] as-is (the
//!   wave-8 server half; upstream `listener/restls/restls.go:27-31`
//!   maps `ResTLS` → `restls.ServerConfig` field-for-field).
//! * **jls**: reuses [`crate::proto::jls::server`] (wave-10) with the
//!   sub-config's own `dest` fallback (`relayFallback` toward the
//!   camouflage site, `transport/jls/jls.go:199-212`).
//!
//! The authenticated user a fronting recovers (`shadowtls.UserFromConn`
//! / `jls.UserFromConn`, server.go:148-154 → `inbound.WithInUser`) has
//! no field on the engine's [`crate::inbound::TcpMeta`] — it is logged
//! at debug level (same position as the jls listener).
//!
//! Integrator deltas (fields upstream's `LC.SnellServer` carries that
//! [`ServerProtocol::Snell`] lacks — parse-time errors are the
//! integrator's once the enum grows them):
//!
//! * `UDP` — upstream gates the UDP command on it
//!   (server.go:202-204, "snell UDP is disabled"); this listener always
//!   serves UDP (the engine's client advertises it per outbound).
//! * `shadow-tls.users` / `handshake-for-server-name` / `wildcard-sni` /
//!   `strict-mode` / v1-v2 — the tuple carries a single password and a
//!   single handshake dest; multi-user tables, per-SNI handshake
//!   selection and v1/v2 are out of the enum's shape (the engine's
//!   shadowtls client is v3-only too).
//! * `obfs-host` is accepted but unused server-side: mihomo's
//!   `NewHTTPObfsServer` echoes no Host (the client-side wrapper is the
//!   one that needs it).

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use bytes::{Buf, BytesMut};
use hmac::Mac;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::inbound::proxy_server::{
    hand_off, serve_with, ServerConfig, ServerProtocol, SharedRelay,
};
use crate::proto::snell::{
    http_obfs_server, parse_server_version, parse_snell_udp_request, snell_udp_response_frame,
    SnellServerConn, SnellServerNext, SnellServerRequest, SnellServerUdp,
};
use crate::stream::BoxProxyStream;

/// `maxPacketLength` (listener/snell/server.go:28).
const MAX_PACKET_LENGTH: usize = crate::proto::snell::MAX_LENGTH;

/// The precise error for `obfs-mode: tls`: the TLS-record camouflage
/// server half lives upstream at
/// `transport/simple-obfs/tls_server.go` (`NewTLSObfsServer`,
/// listener/snell/server.go:159-160) and the engine's
/// `proto::obfs` carries only the client wrapper.
pub const OBFS_TLS_UNSUPPORTED: &str = concat!(
    "snell inbound obfs mode tls is not implemented server-side: it needs the ",
    "TLS-record camouflage server from mihomo transport/simple-obfs/tls_server.go ",
    "(NewTLSObfsServer); the engine's proto::obfs ships only the client half. ",
    "Use obfs-mode http or plain"
);

/// Per-listener context shared by every accepted conn.
#[derive(Clone)]
struct SnellListenCtx {
    psk: Vec<u8>,
    version: u8,
    http_obfs: bool,
    fronting: Fronting,
    relay: SharedRelay,
    tag: Arc<str>,
}

/// The one security fronting stacked under the snell wire
/// (server.go:56-89, 100-106 — at most one, `security modes are
/// mutually exclusive`). Built once at serve time; cloned per conn.
#[derive(Clone)]
enum Fronting {
    /// No fronting: plain (obfs +) snell.
    None,
    /// shadow-tls v3: `(password, handshake dest host[:port])`.
    ShadowTls { password: Arc<str>, dest: String },
    /// res-tls: the camouflage restls server config (dest inside).
    ResTls(Arc<crate::proto::restls::RestlsServerConfig>),
    /// jls: the JLS server config, the fallback dest and its rate limit.
    Jls {
        cfg: Arc<crate::proto::jls::JlsServerConfig>,
        dest: crate::addr::NetAddr,
        rate_limit: u64,
    },
}

/// Serve a snell listener; returns the bound address.
pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let ServerProtocol::Snell {
        psk,
        version,
        obfs_mode,
        obfs_host: _,
        shadow_tls,
        res_tls,
        jls,
    } = &cfg.protocol
    else {
        return Err(Error::config("snell::serve called with a non-snell protocol"));
    };
    // New()'s gate (listener/snell/server.go:37-52), verbatim messages.
    let version = parse_server_version(*version)?;
    if psk.is_empty() {
        return Err(Error::config("snell inbound requires psk"));
    }
    let http_obfs = match obfs_mode.as_str() {
        "" => false,
        "http" => true,
        "tls" => return Err(Error::config(OBFS_TLS_UNSUPPORTED)),
        other => {
            return Err(Error::config(format!(
                "snell inbound obfs mode error: {other}"
            )));
        }
    };
    let fronting = build_fronting(shadow_tls, res_tls, jls)?;
    let ctx = SnellListenCtx {
        psk: psk.as_bytes().to_vec(),
        version,
        http_obfs,
        fronting,
        relay,
        tag: Arc::from(cfg.tag.as_str()),
    };
    serve_with(cfg, move |stream, peer, port| {
        let ctx = ctx.clone();
        async move { handle_conn(stream, peer, port, ctx).await }
    })
    .await
}

/// The security-mode builder (server.go:56-89): mutual exclusion with
/// upstream's exact error, then the validated fronting. Order of the
/// joined names matches upstream's append order (shadow-tls, res-tls,
/// jls).
#[allow(clippy::type_complexity)] // the enum's tuple shape (mod.rs)
fn build_fronting(
    shadow_tls: &Option<(String, String, bool)>,
    res_tls: &Option<crate::proto::restls::RestlsServerConfig>,
    jls: &Option<(String, String, Vec<(String, String)>, Vec<String>, u32)>,
) -> Result<Fronting> {
    let mut modes: Vec<&str> = Vec::with_capacity(3);
    if shadow_tls.is_some() {
        modes.push("shadow-tls");
    }
    if res_tls.is_some() {
        modes.push("res-tls");
    }
    if jls.is_some() {
        modes.push("jls");
    }
    if modes.len() > 1 {
        // server.go:66-68, verbatim.
        return Err(Error::config(format!(
            "security modes are mutually exclusive: {}",
            modes.join(", ")
        )));
    }
    if let Some((password, sni, _skip_verify)) = shadow_tls {
        // NewServerConfig's v3 gates (transport/shadowtls/server.go:
        // 73-84): a user table (the tuple's single password) and a
        // default handshake dest ("missing default handshake
        // information" when empty). `skip-verify` is client-only.
        if password.is_empty() {
            return Err(Error::config(
                "shadow-tls: at least one user is required",
            ));
        }
        if sni.trim().is_empty() {
            return Err(Error::config(
                "shadow-tls: missing default handshake information",
            ));
        }
        return Ok(Fronting::ShadowTls {
            password: Arc::from(password.as_str()),
            dest: handshake_dest(sni),
        });
    }
    if let Some(restls_cfg) = res_tls {
        // The restls builder (listener/restls/restls.go:22-31) takes the
        // config as-is; its own gates (password, script) run inside
        // `restls::server`.
        if restls_cfg.password.is_empty() {
            return Err(Error::config("restls: password is required"));
        }
        return Ok(Fronting::ResTls(Arc::new(restls_cfg.clone())));
    }
    if let Some((sni, dest, users, alpn, rate_limit)) = jls {
        // NewServerConfig (transport/jls/jls.go:121-150): dest required
        // and host:port, empty SNI defaults to the dest host, users
        // required, empty ALPN defaults inside JlsServerConfig::new.
        if dest.trim().is_empty() {
            return Err(Error::config("jls: dest is required"));
        }
        let (dest_host, dest_port) = split_dest(dest)?;
        let sni = if sni.is_empty() {
            dest_host.clone()
        } else {
            sni.clone()
        };
        let users: Vec<crate::proto::jls::JlsUser> = users
            .iter()
            .map(|(username, password)| crate::proto::jls::JlsUser {
                username: username.clone(),
                password: password.clone(),
            })
            .collect();
        let server_cfg = crate::proto::jls::JlsServerConfig::new(&sni, users, alpn.clone())?;
        return Ok(Fronting::Jls {
            cfg: Arc::new(server_cfg),
            dest: crate::addr::NetAddr {
                host: parse_dest_host(&dest_host)?,
                port: dest_port,
            },
            rate_limit: *rate_limit as u64,
        });
    }
    Ok(Fronting::None)
}

/// `HandshakeConfig.Server` normalization: a bare host gets the
/// wildcard-selection port (`net.JoinHostPort(name, "443")`,
/// transport/shadowtls/server.go:186-193), a `host:port` form passes.
fn handshake_dest(dest: &str) -> String {
    if let Some((_, port)) = dest.rsplit_once(':') {
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return dest.to_string();
        }
    }
    format!("{dest}:443")
}

/// `net.SplitHostPort` (the jls listener's `split_dest` shape,
/// transport/jls/jls.go:127-131).
fn split_dest(dest: &str) -> Result<(String, u16)> {
    let (host, port) = dest
        .rsplit_once(':')
        .ok_or_else(|| Error::config(format!("jls: invalid dest address: {dest:?}")))?;
    if host.is_empty() || port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::config(format!("jls: invalid dest address: {dest:?}")));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| Error::config(format!("jls: invalid dest address: {dest:?}")))?;
    Ok((host.to_string(), port))
}

fn parse_dest_host(host: &str) -> Result<crate::addr::Host> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        Ok(crate::addr::Host::Ip(ip))
    } else {
        Ok(crate::addr::Host::Domain(host.to_string()))
    }
}

/// HandleConn (listener/snell/server.go:146-172): the fronting (the
/// builder's `NewListener` wrap, server.go:100-106) runs first, then
/// the obfs wrap, then the request loop.
async fn handle_conn(
    stream: BoxProxyStream,
    peer: SocketAddr,
    port: u16,
    ctx: SnellListenCtx,
) -> Result<()> {
    let stream = match &ctx.fronting {
        Fronting::None => stream,
        Fronting::ShadowTls { password, dest } => {
            match shadowtls_v3_server(password, dest, stream).await? {
                ShadowTlsOutcome::Authenticated(stream) => stream,
                // relayFallback completed (upstream ErrFallbackCompleted):
                // the conn was relayed to the camouflage dest — done.
                ShadowTlsOutcome::FallbackDone => return Ok(()),
            }
        }
        Fronting::ResTls(cfg) => {
            // restls.Server: camouflage TLS toward dest + the hidden
            // stream; a completed raw fallback surfaces the sentinel
            // error (logged by serve_with), nothing reaches the snell
            // codec.
            crate::proto::restls::server(cfg, stream).await?
        }
        Fronting::Jls { cfg, dest, rate_limit } => {
            match crate::proto::jls::server(cfg, stream).await? {
                crate::proto::jls::JlsServerHandshake::Authenticated { stream, user } => {
                    // UserFromConn → WithInUser (server.go:148-154):
                    // TcpMeta has no user field yet — log it.
                    tracing::debug!(
                        target: "engine",
                        "snell+shadow fronting user {user} from {peer}"
                    );
                    stream
                }
                crate::proto::jls::JlsServerHandshake::Fallback { conn, prefix } => {
                    crate::proto::jls::relay_fallback(conn, prefix, dest.clone(), *rate_limit)
                        .await?;
                    return Ok(());
                }
            }
        }
    };
    let stream = if ctx.http_obfs {
        http_obfs_server(stream).await?
    } else {
        stream
    };
    let conn = SnellServerConn::new(stream, &ctx.psk, ctx.version)?;
    serve_loop(conn, peer, port, ctx).await;
    Ok(())
}

/// Boxed request-loop continuation — the recursion breaker: the
/// continuation closure hands back an erased future instead of an
/// inline async block, so the loop's own generator type never has to
/// prove its own `Send`.
fn continue_serve_loop(
    conn: SnellServerConn,
    peer: SocketAddr,
    port: u16,
    ctx: SnellListenCtx,
) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(serve_loop(conn, peer, port, ctx))
}

/// The request loop — `for { handleRequest }` (server.go:166-171). A
/// reusable request returns into this loop from the relay stream's Drop
/// continuation instead of straight through.
async fn serve_loop(conn: SnellServerConn, peer: SocketAddr, port: u16, ctx: SnellListenCtx) {
    if let Err(e) = serve_loop_inner(conn, peer, port, ctx).await {
        tracing::debug!(target: "engine", "snell server {peer}: {e}");
    }
}

async fn serve_loop_inner(
    conn: SnellServerConn,
    peer: SocketAddr,
    port: u16,
    ctx: SnellListenCtx,
) -> Result<()> {
    // One request per entry: the loop-back for reusable requests comes
    // from the Drop continuation re-entering serve_loop, not from a
    // literal loop here (the relay owns the conn between requests).
    let mut conn = conn;
    match conn.read_request().await? {
        // Answered inline with a pong frame; the conn closes
        // (server.go:188-191).
        SnellServerRequest::Ping => Ok(()),
        SnellServerRequest::Udp { .. } => {
            // handleUDP (server.go:257-294): the tunnel reply first,
            // then the datagram pumps own the conn to the end (UDP
            // sessions never reuse).
            conn.write_tunnel_reply().await?;
            udp_relay(conn.into_udp(), peer, port, ctx).await;
            Ok(())
        }
        SnellServerRequest::Connect { target, reuse, .. } => {
            // handleTCP (server.go:226-255): the relay owns the
            // stream; when it finishes, Drop performs the close
            // semantics and — on the reuse path — re-enters this loop
            // through the continuation.
            let next_ctx = ctx.clone();
            let next_peer = peer;
            let next_port = port;
            let next: SnellServerNext = Arc::new(move |conn| {
                continue_serve_loop(conn, next_peer, next_port, next_ctx.clone())
            });
            let stream = conn.into_tcp(reuse, Some(next));
            hand_off(
                &ctx.tag,
                "snell",
                port,
                peer,
                target,
                Box::new(stream),
                ctx.relay.clone(),
            );
            Ok(())
        }
    }
}

/// The UDP relay — handleUDP + udpPacket.WriteBack
/// (listener/snell/server.go:257-294, 387-410): one AEAD frame per
/// datagram both ways, bridged to [`crate::inbound::RelayHandler::handle_udp`].
///
/// Response addresses must be IPs (`WritePacketResponse` has no domain
/// form — upstream resolves domain targets before replying); a domain
/// downlink datagram is dropped, mirroring a lossy link.
async fn udp_relay(io: SnellServerUdp, peer: SocketAddr, _port: u16, ctx: SnellListenCtx) {
    let (up_tx, up_rx) = tokio::sync::mpsc::channel::<(crate::addr::NetAddr, Vec<u8>)>(64);
    let (down_tx, mut down_rx) = tokio::sync::mpsc::channel::<(crate::addr::NetAddr, Vec<u8>)>(64);
    ctx.relay.handle_udp(peer, ctx.tag.to_string(), up_rx, down_tx);

    let (mut rd, mut wr) = tokio::io::split(io);
    // Uplink: one AEAD frame per datagram, parsed and forwarded until
    // the session ends (server.go:266-293).
    let uplink = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PACKET_LENGTH + 32];
        loop {
            let n = match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let (target, payload) = match parse_snell_udp_request(&buf[..n]) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(target: "engine", "snell udp frame from {peer}: {e}");
                    break;
                }
            };
            if up_tx.send((target, payload)).await.is_err() {
                break;
            }
        }
    });
    // Downlink: relay replies sealed one frame per datagram
    // (udpPacket.WriteBack → WritePacketResponse, server.go:399-410).
    while let Some((from, data)) = down_rx.recv().await {
        match snell_udp_response_frame(&from, &data) {
            Ok(frame) => {
                if wr.write_all(&frame).await.is_err() {
                    break;
                }
                let _ = wr.flush().await;
            }
            Err(_) => {
                tracing::debug!(target: "engine", "snell udp: dropping domain downlink datagram")
            }
        }
    }
    let _ = uplink.await;
}

// ---------------------------------------------------------------------------
// shadow-tls v3 server fronting (mihomo transport/shadowtls server.go:132-197
// `serverV3`, v3.go, protocol.go).
//
// CROSS-REF: `crate::proto::shadowtls` ships only the CLIENT half (its
// module doc lists "the server side (`server.go`) … out of scope"); the
// half the snell stacking needs is ported here — the listener is its
// only consumer in the engine. The wire constants and the HMAC
// constructions are the same ones the client half documents; see
// `proto/shadowtls.rs` for the client-side mirror.
// ---------------------------------------------------------------------------

/// `tlsHeaderSize` (protocol.go).
const STLS_HEADER: usize = 5;
/// `hmacSize` (protocol.go).
const STLS_HMAC: usize = 4;
/// `tlsRandomSize` (protocol.go).
const STLS_RANDOM: usize = 32;
/// `tlsSessionIDSize` (protocol.go).
const STLS_SESSION_ID: usize = 32;
/// `tlsHMACHeaderSize` (protocol.go).
const STLS_HMAC_HEADER: usize = STLS_HEADER + STLS_HMAC;
/// `serverRandomIndex` (protocol.go): record header + handshake header +
/// legacy version.
const STLS_SERVER_RANDOM_INDEX: usize = STLS_HEADER + 1 + 3 + 2;
/// `sessionIDLengthIndex` (protocol.go).
const STLS_SESSION_ID_LEN_INDEX: usize = STLS_SERVER_RANDOM_INDEX + STLS_RANDOM;
/// `sessionIDStart` (v3.go `generateSessionID`).
const STLS_SESSION_ID_OFFSET: usize = STLS_SESSION_ID_LEN_INDEX + 1;
/// The session-id tail carrying the v3 HMAC.
const STLS_HMAC_INDEX: usize = STLS_SESSION_ID_OFFSET + STLS_SESSION_ID - STLS_HMAC;
/// `maxTLSPlaintext` (protocol.go).
const STLS_MAX_PLAINTEXT: usize = 16384;
/// Largest frame accepted from the wire (one plaintext + framing).
const STLS_MAX_FRAME: usize = STLS_MAX_PLAINTEXT + STLS_HMAC_HEADER * 2;

const STLS_REC_ALERT: u8 = 21;
const STLS_REC_HANDSHAKE: u8 = 22;
const STLS_REC_APPDATA: u8 = 23;
const STLS_HS_CLIENT_HELLO: u8 = 1;
const STLS_HS_SERVER_HELLO: u8 = 2;

/// The outcome of the v3 server handshake: the authenticated tunnel, or
/// a completed fallback relay (upstream `ErrFallbackCompleted`,
/// server.go:31 — surfaced as a plain `Ok` end by the caller).
enum ShadowTlsOutcome {
    Authenticated(BoxProxyStream),
    FallbackDone,
}

/// A rolling HMAC-SHA1 tag chain — the server mirror of the client
/// half's `HmacChain` (`hmacAdd` / `verifyApplicationData` in v3.go).
struct StlsChain {
    mac: hmac::Hmac<sha1::Sha1>,
}

impl StlsChain {
    /// `hmacReset` (v3.go:327-331): `HMAC-SHA1(password, random [||
    /// side])`.
    fn new(password: &str, server_random: &[u8], side: Option<u8>) -> Self {
        let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(password.as_bytes())
            .expect("HMAC-SHA1 accepts any key length");
        mac.update(server_random);
        if let Some(side) = side {
            mac.update(&[side]);
        }
        StlsChain { mac }
    }

    fn update(&mut self, data: &[u8]) {
        self.mac.update(data);
    }

    /// Current tag without advancing past it (`Sum(nil)[:4]`).
    fn tag(&self) -> [u8; STLS_HMAC] {
        let mut tag = [0u8; STLS_HMAC];
        tag.copy_from_slice(&self.mac.clone().finalize().into_bytes()[..STLS_HMAC]);
        tag
    }
}

/// `kdf` (v3.go:315-320): `SHA256(password ‖ server_random)`.
fn stls_kdf(password: &str, server_random: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(password.as_bytes());
    h.update(server_random);
    h.finalize().into()
}

/// `xorSlice` (v3.go:322-326).
fn stls_xor(data: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
}

/// `readFrame` (protocol.go:24-37): one length-prefixed TLS record. A
/// length cap is added upstream of Go's unbounded allocation.
async fn stls_read_frame<R: tokio::io::AsyncRead + Unpin>(io: &mut R) -> Result<Vec<u8>> {
    let mut frame = vec![0u8; STLS_HEADER];
    io.read_exact(&mut frame).await?;
    let len = usize::from(u16::from_be_bytes([frame[3], frame[4]]));
    if STLS_HEADER + len > STLS_MAX_FRAME {
        return Err(Error::protocol("shadow-tls: oversized TLS record"));
    }
    frame.resize(STLS_HEADER + len, 0);
    io.read_exact(&mut frame[STLS_HEADER..]).await?;
    Ok(frame)
}

/// `verifyClientHello` for the single-password table (v3.go:186-207):
/// HMAC-SHA1(password) over the hello with the session-id tail zeroed
/// must equal the tail on the wire.
fn stls_verify_client_hello(frame: &[u8], password: &str) -> bool {
    let min_len = STLS_HEADER + 1 + 3 + 2 + STLS_RANDOM + 1 + STLS_SESSION_ID;
    if frame.len() < min_len
        || frame[0] != STLS_REC_HANDSHAKE
        || frame[STLS_HEADER] != STLS_HS_CLIENT_HELLO
        || frame[STLS_SESSION_ID_LEN_INDEX] as usize != STLS_SESSION_ID
    {
        return false;
    }
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(password.as_bytes())
        .expect("HMAC-SHA1 accepts any key length");
    mac.update(&frame[STLS_HEADER..STLS_HMAC_INDEX]);
    mac.update(&[0u8; STLS_HMAC]);
    mac.update(&frame[STLS_HMAC_INDEX + STLS_HMAC..]);
    let tag = mac.finalize().into_bytes();
    frame[STLS_HMAC_INDEX..STLS_HMAC_INDEX + STLS_HMAC] == tag[..STLS_HMAC]
}

/// `extractServerRandom` (protocol.go:141-147).
fn stls_extract_server_random(frame: &[u8]) -> Option<[u8; STLS_RANDOM]> {
    if frame.len() < STLS_SERVER_RANDOM_INDEX + STLS_RANDOM
        || frame[0] != STLS_REC_HANDSHAKE
        || frame[STLS_HEADER] != STLS_HS_SERVER_HELLO
    {
        return None;
    }
    frame[STLS_SERVER_RANDOM_INDEX..STLS_SERVER_RANDOM_INDEX + STLS_RANDOM]
        .try_into()
        .ok()
}

/// `sendAlert` (v3.go:328-335): a forged 31-byte alert record so an
/// active prober sees a TLS-shaped failure.
fn stls_alert() -> Vec<u8> {
    let mut record = vec![0u8; 31];
    record[0] = STLS_REC_ALERT;
    record[1] = 3;
    record[2] = 3;
    record[3] = 0;
    record[4] = 26;
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut record[STLS_HEADER..]);
    record
}

/// Dial the handshake destination (`HandshakeConfig.dial`,
/// transport/shadowtls/server.go:185-193).
async fn stls_dial_dest(dest: &str) -> Result<tokio::net::TcpStream> {
    let stream = tokio::net::TcpStream::connect(dest)
        .await
        .map_err(|e| Error::network(format!("shadow-tls: dial handshake server {dest}: {e}")))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// `relayFallback` (transport/shadowtls/server.go:194-206): dial the
/// handshake dest, replay the recorded ClientHello, then a plain
/// bidirectional relay. A completed relay IS upstream's
/// `ErrFallbackCompleted`.
async fn stls_relay_fallback(
    conn: BoxProxyStream,
    client_hello: Vec<u8>,
    dest: &str,
) -> Result<()> {
    let upstream = stls_dial_dest(dest).await?;
    let inbound = crate::inbound::PrependStream::new(conn, client_hello);
    relay_plain(Box::new(inbound), Box::new(upstream)).await;
    Ok(())
}

/// `N.RelayContext`: copy both directions until both end; each
/// direction half-closes its write side as it finishes.
async fn relay_plain(a: BoxProxyStream, b: BoxProxyStream) {
    use tokio::io::AsyncWriteExt;
    let (mut ra, mut wa) = tokio::io::split(a);
    let (mut rb, mut wb) = tokio::io::split(b);
    let x = async {
        let _ = tokio::io::copy(&mut ra, &mut wb).await;
        let _ = wb.shutdown().await;
    };
    let y = async {
        let _ = tokio::io::copy(&mut rb, &mut wa).await;
        let _ = wa.shutdown().await;
    };
    let _ = tokio::join!(x, y);
}

/// The v3 server handshake — `serverV3` (transport/shadowtls/
/// server.go:132-197) + `relayV3Handshake` (server.go:297-322) + the
/// v3.go copy helpers (250-289):
///
/// 1. read the ClientHello and verify its session-id HMAC against the
///    single password — failure runs `relayFallback` (the camouflage
///    site answers, the conn is spent, `FallbackDone`);
/// 2. forward the hello to the handshake dest, relay the dest's
///    ServerHello back, extract its random (failure → plain relay,
///    server.go:169-176);
/// 3. relay the rest of the TLS handshake BOTH WAYS: client frames pass
///    through to the dest until one arrives tagged with the tunnel's
///    `'C'` chain (`copyByFrameUntilHMACMatches`) — that frame's payload
///    is the tunnel's first bytes; dest frames pass through, except its
///    application records are XOR-obfuscated and HMAC-tagged toward the
///    client (`copyByFrameWithModification`);
/// 4. hand back the data-phase stream: reads verify the `'C'` chain,
///    writes tag the `'S'` chain, and the intercepted first payload is
///    served as already-read bytes (`N.NewCachedConn`).
///
/// `strictMode`, per-SNI handshakes and `wildcard-sni` are out of the
/// enum's shape (single password + single dest) — upstream's defaults
/// are off/fixed.
async fn shadowtls_v3_server(
    password: &str,
    dest: &str,
    conn: BoxProxyStream,
) -> Result<ShadowTlsOutcome> {
    let mut conn = conn;
    let client_hello = stls_read_frame(&mut conn)
        .await
        .map_err(|e| Error::network(format!("shadow-tls: read client handshake: {e}")))?;
    if !stls_verify_client_hello(&client_hello, password) {
        // server.go:160-163: "client hello verify failed" → the fallback.
        tracing::debug!(target: "engine", "shadow-tls: client hello verify failed, relaying to {dest}");
        return stls_relay_fallback(conn, client_hello, dest)
            .await
            .map(|()| ShadowTlsOutcome::FallbackDone);
    }

    let mut upstream = stls_dial_dest(dest).await?;
    upstream
        .write_all(&client_hello)
        .await
        .map_err(|e| Error::network(format!("shadow-tls: write client handshake: {e}")))?;
    let server_hello = stls_read_frame(&mut upstream)
        .await
        .map_err(|e| Error::network(format!("shadow-tls: read server handshake: {e}")))?;
    conn.write_all(&server_hello)
        .await
        .map_err(|e| Error::network(format!("shadow-tls: write server handshake: {e}")))?;
    let Some(server_random) = stls_extract_server_random(&server_hello) else {
        // server.go:168-176: no extractable random → the plain relay.
        tracing::debug!(target: "engine", "shadow-tls: server random extract failed, relaying");
        relay_plain(conn, Box::new(upstream)).await;
        return Ok(ShadowTlsOutcome::FallbackDone);
    };

    // relayV3Handshake: A (client → dest until the 'C' tag) and B (dest →
    // client with modification) run concurrently; A finishing shuts the
    // dest side down (upstream `serverConn.Close()`) so B ends. Both
    // tasks hand their halves of the client conn back so it can be
    // re-united for the data-phase stream.
    let (conn_rd, conn_wr) = tokio::io::split(conn);
    let (up_rd, up_wr) = upstream.into_split();
    let pw_a: Arc<str> = Arc::from(password);
    let pw_b = pw_a.clone();
    let random_b = server_random;
    let a = tokio::spawn(async move {
        stls_copy_until_hmac_matches(conn_rd, up_wr, &pw_a, &server_random).await
    });
    let b = tokio::spawn(stls_copy_with_modification(up_rd, conn_wr, pw_b, random_b));

    let (request, verify, conn_rd) = match a.await {
        Ok(Ok(found)) => found,
        Ok(Err(e)) => {
            b.abort();
            return Err(Error::network(format!("shadow-tls: relay handshake: {e}")));
        }
        Err(e) => {
            b.abort();
            return Err(Error::network(format!("shadow-tls: relay handshake: {e}")));
        }
    };
    // A's match already shut the dest write side down; collect B, then
    // re-unite the client conn halves for the data-phase stream.
    let conn_wr = match b.await {
        Ok(wr) => wr,
        Err(e) => {
            return Err(Error::network(format!("shadow-tls: relay handshake: {e}")));
        }
    };
    let conn = conn_rd.unsplit(conn_wr);
    let write = StlsChain::new(password, &server_random, Some(b'S'));
    Ok(ShadowTlsOutcome::Authenticated(Box::new(
        ShadowTlsFrontStream::new(conn, write, verify, request),
    )))
}

/// `copyByFrameUntilHMACMatches` (v3.go:250-272): forward client frames
/// to the handshake dest until an application record's tag matches a
/// fresh `'C'` chain over its payload — the tunnel's first frame.
/// Returns its payload, the chain state continued past it (reset +
/// payload + tag — exactly what `verifyApplicationData(true)` leaves,
/// so the data-phase reads continue seamlessly) and the client read
/// half. The dest write half is shut down on the match (upstream
/// `serverConn.Close()`).
async fn stls_copy_until_hmac_matches<R, W>(
    mut conn: R,
    mut upstream: W,
    password: &str,
    server_random: &[u8; STLS_RANDOM],
) -> Result<(Vec<u8>, StlsChain, R)>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        let frame = stls_read_frame(&mut conn).await?;
        if frame[0] == STLS_REC_APPDATA && frame.len() > STLS_HMAC_HEADER {
            let payload = &frame[STLS_HMAC_HEADER..];
            let tag = &frame[STLS_HEADER..STLS_HMAC_HEADER];
            let mut probe = StlsChain::new(password, server_random, Some(b'C'));
            probe.update(payload);
            if probe.tag() == tag {
                probe.update(tag);
                let _ = upstream.shutdown().await;
                return Ok((payload.to_vec(), probe, conn));
            }
        }
        upstream
            .write_all(&frame)
            .await
            .map_err(|e| Error::network(format!("shadow-tls: write client record: {e}")))?;
    }
}

/// `copyByFrameWithModification` (v3.go:274-289): dest → client.
/// Handshake records pass through; application records are XOR'd with
/// `kdf(password, server_random)`, HMAC-tagged with the no-side chain
/// (`hmacWrite`), and re-lengthed — the exact framing the engine's
/// shadowtls client verifies during its handshake phase. The client
/// write half is returned when the dest side ends.
async fn stls_copy_with_modification<R, W>(
    mut upstream: R,
    mut conn: W,
    password: Arc<str>,
    server_random: [u8; STLS_RANDOM],
) -> W
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let write_key = stls_kdf(&password, &server_random);
    let mut chain = StlsChain::new(&password, &server_random, None);
    loop {
        let mut frame = match stls_read_frame(&mut upstream).await {
            Ok(f) => f,
            Err(_) => return conn, // dest closed: the handshake relay is over
        };
        if frame[0] != STLS_REC_APPDATA {
            if conn.write_all(&frame).await.is_err() {
                return conn;
            }
            continue;
        }
        stls_xor(&mut frame[STLS_HEADER..], &write_key);
        chain.update(&frame[STLS_HEADER..]);
        let tag = chain.tag();
        let new_len = (frame.len() - STLS_HEADER + STLS_HMAC) as u16;
        frame[3..5].copy_from_slice(&new_len.to_be_bytes());
        let mut out = Vec::with_capacity(frame.len() + STLS_HMAC);
        out.extend_from_slice(&frame[..STLS_HEADER]);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&frame[STLS_HEADER..]);
        if conn.write_all(&out).await.is_err() {
            return conn;
        }
    }
}

/// The data-phase server stream — `verifiedConn` (v3.go:91-186): reads
/// verify the client `'C'` chain (`verifyApplicationData(update=true)`),
/// writes tag the `'S'` chain (`writeRecord`), the intercepted first
/// payload is served first (`N.NewCachedConn`), and errors send the
/// forged alert. `hmacIgnore` is nil on the v3 server (server.go:190).
struct ShadowTlsFrontStream {
    inner: BoxProxyStream,
    read_chain: StlsChain,
    write_chain: StlsChain,
    /// The intercepted first tunnel payload (upstream `pending`).
    pending: Vec<u8>,
    /// Raw bytes off the transport.
    rbuf: BytesMut,
    /// Verified plaintext ready for the consumer.
    out: BytesMut,
    /// Wire bytes queued for the transport.
    wbuf: BytesMut,
    /// Plaintext byte count `wbuf` corresponds to (write accounting).
    out_plain: usize,
    /// Alert already queued after a failure.
    failed: bool,
}

impl ShadowTlsFrontStream {
    fn new(
        inner: BoxProxyStream,
        write_chain: StlsChain,
        read_chain: StlsChain,
        pending: Vec<u8>,
    ) -> Self {
        ShadowTlsFrontStream {
            inner,
            read_chain,
            write_chain,
            pending,
            rbuf: BytesMut::with_capacity(16 * 1024),
            out: BytesMut::with_capacity(16 * 1024),
            wbuf: BytesMut::new(),
            out_plain: 0,
            failed: false,
        }
    }

    /// Split one complete frame off `rbuf` and verify it
    /// (`verifiedConn.Read`): alerts error, application data must match
    /// the `'C'` chain, anything else errors.
    fn try_parse(&mut self) -> std::io::Result<bool> {
        if self.rbuf.len() < STLS_HEADER {
            return Ok(false);
        }
        let len = usize::from(u16::from_be_bytes([self.rbuf[3], self.rbuf[4]]));
        if STLS_HEADER + len > STLS_MAX_FRAME {
            return Err(io_invalid("shadow-tls: oversized TLS record"));
        }
        if self.rbuf.len() < STLS_HEADER + len {
            return Ok(false);
        }
        let frame = self.rbuf.split_to(STLS_HEADER + len);
        match frame[0] {
            STLS_REC_ALERT => {
                return Err(io_invalid("shadow-tls: remote alert"));
            }
            STLS_REC_APPDATA if frame.len() > STLS_HMAC_HEADER => {
                let tag: [u8; STLS_HMAC] =
                    frame[STLS_HEADER..STLS_HMAC_HEADER].try_into().expect("4 bytes");
                let payload = &frame[STLS_HMAC_HEADER..];
                self.read_chain.update(payload);
                let expected = self.read_chain.tag();
                if expected != tag {
                    return Err(io_invalid(
                        "shadow-tls: application data verification failed",
                    ));
                }
                self.read_chain.update(&expected);
                self.out.extend_from_slice(payload);
            }
            other => {
                return Err(io_invalid(&format!(
                    "shadow-tls: unexpected TLS record type: {other}"
                )));
            }
        }
        Ok(true)
    }
}

fn io_invalid(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

impl tokio::io::AsyncRead for ShadowTlsFrontStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::{ready, Poll};
        loop {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if !self.pending.is_empty() {
                let n = self.pending.len().min(buf.remaining());
                buf.put_slice(&self.pending[..n]);
                self.pending.drain(..n);
                return Poll::Ready(Ok(()));
            }
            if !self.out.is_empty() {
                let n = self.out.len().min(buf.remaining());
                let chunk: Vec<u8> = self.out.split_to(n).to_vec();
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            match self.try_parse() {
                Ok(true) => continue,
                Ok(false) => {
                    let mut tmp = [0u8; 16 * 1024];
                    let mut rb = tokio::io::ReadBuf::new(&mut tmp);
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
                    if rb.filled().is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    self.rbuf.extend_from_slice(rb.filled());
                }
                Err(e) => {
                    if !self.failed {
                        // sendAlert (v3.go:328-335): queued for the next
                        // write/flush, like the client half's queue_alert.
                        self.failed = true;
                        self.wbuf.extend_from_slice(&stls_alert());
                    }
                    return Poll::Ready(Err(e));
                }
            }
        }
    }
}

impl tokio::io::AsyncWrite for ShadowTlsFrontStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::{ready, Poll};
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.failed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "shadow-tls: stream failed",
            )));
        }
        if this.wbuf.is_empty() {
            // `writeRecord` (v3.go:158-166): 16 KiB chunks, each tagged
            // with the advancing `'S'` chain.
            let take = buf.len().min(STLS_MAX_PLAINTEXT);
            let payload = &buf[..take];
            this.write_chain.update(payload);
            let tag = this.write_chain.tag();
            this.write_chain.update(&tag);
            this.wbuf.reserve(STLS_HMAC_HEADER + take);
            this.wbuf.extend_from_slice(&[
                STLS_REC_APPDATA,
                0x03,
                0x03,
                ((STLS_HMAC + take) >> 8) as u8,
                ((STLS_HMAC + take) & 0xFF) as u8,
            ]);
            this.wbuf.extend_from_slice(&tag);
            this.wbuf.extend_from_slice(payload);
            this.out_plain = take;
        }
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "shadow-tls: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Poll::Ready(Ok(this.out_plain))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::{ready, Poll};
        let this = self.get_mut();
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "shadow-tls: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::ready;
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{Host, NetAddr};
    use crate::inbound::proxy_server::test_support::Capture;
    use crate::proto::snell::{handshake, udp_session, SnellOut};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    fn fresh_psk() -> String {
        format!("psk-{:016x}", rand::random::<u64>())
    }

    fn cfg(version: u8, psk: &str, obfs_mode: &str) -> ServerConfig {
        cfg_fronted(version, psk, obfs_mode, None, None, None)
    }

    #[allow(clippy::type_complexity)]
    fn cfg_fronted(
        version: u8,
        psk: &str,
        obfs_mode: &str,
        shadow_tls: Option<(String, String, bool)>,
        res_tls: Option<crate::proto::restls::RestlsServerConfig>,
        jls: Option<(String, String, Vec<(String, String)>, Vec<String>, u32)>,
    ) -> ServerConfig {
        ServerConfig {
            tag: "snell-test".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::Snell {
                psk: psk.into(),
                version,
                obfs_mode: obfs_mode.into(),
                obfs_host: "cdn.example".into(),
                shadow_tls,
                res_tls,
                jls,
            },
        }
    }

    async fn spawn_server(version: u8, psk: &str) -> (Arc<Capture>, SocketAddr) {
        spawn_server_obfs(version, psk, "").await
    }

    async fn spawn_server_obfs(
        version: u8,
        psk: &str,
        obfs_mode: &str,
    ) -> (Arc<Capture>, SocketAddr) {
        let capture = Capture::new();
        let addr = serve(&cfg(version, psk, obfs_mode), capture.clone())
            .await
            .unwrap();
        (capture, addr)
    }

    fn client(psk: &str, port: u16, version: u8) -> SnellOut {
        SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port,
            psk: psk.into(),
            version,
            udp: false,
        }
    }

    /// Connect + handshake + one echo exchange through the listener.
    async fn roundtrip(psk: &str, addr: SocketAddr, version: u8) -> NetAddr {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream = handshake(Box::new(tcp), &client(psk, addr.port(), version), &target, false)
            .await
            .unwrap();
        stream.write_all(b"ping-snell").await.unwrap();
        let mut buf = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(&buf, b"ping-snell");
        target
    }

    #[tokio::test]
    async fn tcp_roundtrip_all_versions() {
        // The engine's own snell client (every wire version, plus v5
        // riding v4) connects through the listener end to end.
        for version in [1u8, 2, 3, 4, 5] {
            let psk = fresh_psk();
            let (capture, addr) = spawn_server(version, &psk).await;
            let target = roundtrip(&psk, addr, version).await;
            assert_eq!(capture.targets(), vec![target], "version {version}");
        }
    }

    #[tokio::test]
    async fn default_version_is_v4_on_the_server() {
        // version 0 → v4 (listener/snell/server.go:37-39): a v4 client
        // interops with a version-0 listener.
        let psk = fresh_psk();
        let (capture, addr) = spawn_server(0, &psk).await;
        let target = roundtrip(&psk, addr, 4).await;
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn wrong_psk_relays_nothing() {
        let (capture, addr) = spawn_server(4, &fresh_psk()).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream =
            handshake(Box::new(tcp), &client(&fresh_psk(), addr.port(), 4), &target, false)
                .await
                .unwrap();
        let _ = stream.write_all(b"ping").await;
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("unexpected {n} bytes from a rejected client"),
            Err(_) => panic!("timeout: server did not close the connection"),
        }
        assert_eq!(capture.relayed(), 0);
    }

    #[tokio::test]
    async fn udp_session_roundtrip_v3_v4() {
        // The engine's UDP client (udp_session) through the listener's
        // UDP command: request frames parsed, responses IP-framed.
        for version in [3u8, 4] {
            let psk = fresh_psk();
            let (capture, addr) = spawn_server(version, &psk).await;
            let tcp = TcpStream::connect(addr).await.unwrap();
            let mut cfg = client(&psk, addr.port(), version);
            cfg.udp = true;
            let mut udp = udp_session(&cfg, Box::new(tcp)).await.unwrap();
            // An IP target keeps the echo on the IP-only response wire.
            let target = NetAddr::ip("8.8.8.8".parse().unwrap(), 53);
            udp.send_to(&target, b"dgram").await.unwrap();
            let mut buf = [0u8; 1500];
            let (from, n) =
                tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
                    .await
                    .expect("udp response timeout")
                    .unwrap();
            assert_eq!(&buf[..n], b"dgram");
            assert_eq!(from, target, "the echo comes from the requested host");
            // The datagram went through the relay's UDP side.
            assert_eq!(capture.udp_targets(), vec![target]);
            assert_eq!(capture.udp_sessions().len(), 1);
            assert_eq!(capture.udp_sessions()[0].1, "snell-test");
            assert_eq!(capture.relayed(), 0);
        }
    }

    #[tokio::test]
    async fn udp_domain_target_reaches_relay() {
        // A domain request datagram is forwarded to the relay (the
        // Capture echoes it back as a domain, which the response codec
        // drops — upstream resolves before replying).
        let psk = fresh_psk();
        let (capture, addr) = spawn_server(4, &psk).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut cfg = client(&psk, addr.port(), 4);
        cfg.udp = true;
        let mut udp = udp_session(&cfg, Box::new(tcp)).await.unwrap();
        let target = NetAddr::domain("dns.example", 53).unwrap();
        udp.send_to(&target, b"q").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(capture.udp_targets(), vec![target]);
    }

    #[tokio::test]
    async fn http_obfs_roundtrip() {
        // obfs-mode http: the engine's http-obfs client below the snell
        // client, the server-side wrapper above the snell server.
        let psk = fresh_psk();
        let (capture, addr) = spawn_server_obfs(4, &psk, "http").await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let settings = crate::proto::obfs::ObfsSettings::new("cdn.example", addr.port());
        let transport = crate::proto::obfs::http_obfs_client(Box::new(tcp), &settings)
            .await
            .unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream =
            handshake(transport, &client(&psk, addr.port(), 4), &target, false)
                .await
                .unwrap();
        stream.write_all(b"obfs-ping").await.unwrap();
        let mut buf = [0u8; 9];
        tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(&buf, b"obfs-ping");
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn pooled_client_reuses_one_listener_conn() {
        // The engine's snell pool through the listener: two requests,
        // one TCP conn (the server's reuse loop + zero-chunk dance).
        let psk = fresh_psk();
        let (_capture, addr) = spawn_server(4, &psk).await;
        let addr_str = addr.to_string();
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dials2 = dials.clone();
        let pool = crate::proto::snell::SnellPool::with_dialer(
            client(&psk, addr.port(), 4),
            move || {
                let addr_str = addr_str.clone();
                let dials = dials2.clone();
                Box::pin(async move {
                    dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let tcp = TcpStream::connect(addr_str.as_str())
                        .await
                        .map_err(|e| Error::network(e.to_string()))?;
                    Ok(Box::new(tcp) as BoxProxyStream)
                })
            },
        )
        .unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        {
            let mut conn = pool.dial(&target).await.unwrap();
            conn.write_all(b"first").await.unwrap();
            conn.flush().await.unwrap();
            let mut buf = [0u8; 5];
            tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf, b"first");
            conn.shutdown().await.unwrap();
            let mut tail = [0u8; 4];
            let n = tokio::time::timeout(Duration::from_secs(10), conn.read(&mut tail))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(n, 0, "the server's zero chunk ends the request");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(pool.idle_len().await, 1);
        {
            let mut conn = pool.dial(&target).await.unwrap();
            conn.write_all(b"seco").await.unwrap();
            conn.flush().await.unwrap();
            let mut buf = [0u8; 4];
            tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf, b"seco");
        }
        assert_eq!(
            dials.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "one listener conn served both requests"
        );
    }

    #[tokio::test]
    async fn config_gates_match_upstream() {
        let capture = Capture::new();
        // Version gate (server.go:43).
        let err = serve(&cfg(6, "p", ""), capture.clone()).await.unwrap_err();
        assert!(
            err.to_string().contains("snell inbound version 6 is not supported"),
            "{err}"
        );
        // PSK gate (server.go:45-47).
        let err = serve(&cfg(4, "", ""), capture.clone()).await.unwrap_err();
        assert!(err.to_string().contains("snell inbound requires psk"), "{err}");
        // obfs mode gate (server.go:48-52) + the tls precise error.
        let err = serve(&cfg(4, "p", "weird"), capture.clone()).await.unwrap_err();
        assert!(
            err.to_string().contains("snell inbound obfs mode error: weird"),
            "{err}"
        );
        let err = serve(&cfg(4, "p", "tls"), capture.clone()).await.unwrap_err();
        assert!(err.to_string().contains("tls_server.go"), "{err}");
        assert!(err.to_string().contains("obfs mode tls"), "{err}");
    }

    #[tokio::test]
    async fn version_byte_gate_rejects_bad_header() {
        // A conn whose first decrypted byte is not the protocol version
        // is dropped with no relay (handleRequest's version check,
        // server.go:180-182). Simulated with a wrong psk — same wire
        // effect (undecryptable header).
        let (capture, addr) = spawn_server(3, &fresh_psk()).await;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        // Raw garbage: never decrypts to a valid header.
        tcp.write_all(&[0u8; 64]).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("unexpected {n} bytes from a rejected client"),
            Err(_) => panic!("timeout: server did not close the connection"),
        }
        assert_eq!(capture.relayed(), 0);
    }

    #[test]
    fn host_parse_matches_metadata_rules() {
        // metadata() (server.go:296-313): parseable IPs become IP hosts.
        let t = NetAddr::ip("10.0.0.1".parse::<std::net::IpAddr>().unwrap(), 80);
        assert!(matches!(t.host, Host::Ip(_)));
    }

    // ------------------------------------------------- fronting test bench

    /// A fake handshake destination: a real rustls TLS server on
    /// loopback (self-signed `restls.test`) answering any number of
    /// conns — what the shadow-tls fronting relays the camouflage
    /// handshake to (the same shape as the restls listener's `spawn_dest`).
    async fn spawn_tls_dest() -> SocketAddr {
        use crate::inbound::proxy_server::test_support::self_signed_tls;
        // self_signed_tls writes PEM files; the listener-style dest wants
        // the DER pair directly.
        let certified = rcgen::generate_simple_self_signed(vec!["restls.test".to_string()])
            .expect("rcgen self-signed cert");
        let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let config = std::sync::Arc::new(
            rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("dest server config"),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = tokio_rustls::TlsAcceptor::from(config).accept(stream).await;
                });
            }
        });
        let _ = self_signed_tls; // (kept for symmetry; the DER pair is used)
        addr
    }

    /// A plain TCP recorder/echo standing in for the jls fallback dest
    /// (the jls listener tests' `spawn_dest_echo`).
    async fn spawn_dest_echo() -> (SocketAddr, Arc<std::sync::Mutex<Vec<u8>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    continue;
                };
                let seen = seen2.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                seen.lock().unwrap().extend_from_slice(&buf[..n]);
                                let _ = sock.write_all(&buf[..n]).await;
                            }
                        }
                    }
                });
            }
        });
        (addr, seen)
    }

    /// The engine's shadow-tls CLIENT (the stack the outbound composes:
    /// shadowtls::connect wraps the TCP, snell::handshake rides it —
    /// adapter/outbound/snell.go:53-65 stacks the same way).
    async fn shadowtls_snell_dial(
        addr: SocketAddr,
        front_password: &str,
        psk: &str,
        target: &NetAddr,
    ) -> Result<crate::stream::BoxProxyStream> {
        let tcp = TcpStream::connect(addr).await.expect("connect listener");
        let stls_cfg = crate::proto::shadowtls::ShadowTlsOut {
            server: "127.0.0.1".into(),
            port: addr.port(),
            password: front_password.into(),
            sni: "127.0.0.1".into(),
            skip_verify: true,
        };
        let front = crate::proto::shadowtls::connect(&stls_cfg, Box::new(tcp)).await?;
        handshake(front, &client(psk, addr.port(), 4), target, false).await
    }

    #[tokio::test]
    async fn shadow_tls_fronting_roundtrips_with_engine_client_stack() {
        // shadow-tls v3 fronting under snell v4: the engine's own
        // shadowtls client (inner TLS against the relayed dest) below
        // the engine's snell client — the client stack of
        // adapter/outbound/snell.go:53-65.
        let psk = fresh_psk();
        let front_password = format!("stls-{:016x}", rand::random::<u64>());
        let dest = spawn_tls_dest().await;
        let capture = Capture::new();
        let cfg = cfg_fronted(
            4,
            &psk,
            "",
            Some((front_password.clone(), dest.to_string(), false)),
            None,
            None,
        );
        let addr = serve(&cfg, capture.clone()).await.expect("serve");

        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream = tokio::time::timeout(
            Duration::from_secs(20),
            shadowtls_snell_dial(addr, &front_password, &psk, &target),
        )
        .await
        .expect("stacked handshake timeout")
        .expect("stacked handshake failed");

        stream.write_all(b"ping-stls-snell").await.unwrap();
        let mut buf = [0u8; 15];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(&buf, b"ping-stls-snell");
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn shadow_tls_fronting_with_obfs_still_stacks() {
        // The fronting wraps the RAW listener and obfs wraps the snell
        // codec (server.go:100-106 then 156-160): shadow-tls + http-obfs
        // + snell compose.
        let psk = fresh_psk();
        let front_password = format!("stls-{:016x}", rand::random::<u64>());
        let dest = spawn_tls_dest().await;
        let capture = Capture::new();
        let cfg = cfg_fronted(
            4,
            &psk,
            "http",
            Some((front_password.clone(), dest.to_string(), false)),
            None,
            None,
        );
        let addr = serve(&cfg, capture.clone()).await.expect("serve");

        let tcp = TcpStream::connect(addr).await.unwrap();
        let stls_cfg = crate::proto::shadowtls::ShadowTlsOut {
            server: "127.0.0.1".into(),
            port: addr.port(),
            password: front_password,
            sni: "127.0.0.1".into(),
            skip_verify: true,
        };
        let front = crate::proto::shadowtls::connect(&stls_cfg, Box::new(tcp))
            .await
            .expect("shadowtls client");
        let settings = crate::proto::obfs::ObfsSettings::new("cdn.example", addr.port());
        let obfs = crate::proto::obfs::http_obfs_client(front, &settings)
            .await
            .expect("http obfs client");
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream = handshake(obfs, &client(&psk, addr.port(), 4), &target, false)
            .await
            .expect("snell over the stack");
        stream.write_all(b"stls+obfs+snell").await.unwrap();
        let mut buf = [0u8; 15];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(&buf, b"stls+obfs+snell");
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn shadow_tls_wrong_password_lands_on_the_fallback_relay() {
        // verifyClientHello fails → relayFallback: the conn (recorded
        // ClientHello first) is relayed to the handshake dest, nothing
        // reaches the snell codec, and the client's own handshake then
        // fails (its v3 framing never appears).
        let psk = fresh_psk();
        let dest = spawn_tls_dest().await;
        let capture = Capture::new();
        let cfg = cfg_fronted(
            4,
            &psk,
            "",
            Some((format!("real-{:016x}", rand::random::<u64>()), dest.to_string(), false)),
            None,
            None,
        );
        let addr = serve(&cfg, capture.clone()).await.expect("serve");

        let target = NetAddr::domain("echo.test", 443).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            shadowtls_snell_dial(
                addr,
                &format!("wrong-{:016x}", rand::random::<u64>()),
                &psk,
                &target,
            ),
        )
        .await
        .expect("timeout");
        assert!(result.is_err(), "a wrong fronting password must not tunnel");
        assert_eq!(capture.relayed(), 0, "the fallback conn never relays");
    }

    #[tokio::test]
    async fn res_tls_fronting_roundtrips_with_engine_client_stack() {
        // res-tls fronting: restls::server (wave-8) below the snell
        // codec; the engine's restls client below the snell client.
        let psk = fresh_psk();
        let restls_password = format!("restls-{:016x}", rand::random::<u64>());
        let dest = spawn_tls_dest().await;
        let capture = Capture::new();
        let cfg = cfg_fronted(
            4,
            &psk,
            "",
            None,
            Some(crate::proto::restls::RestlsServerConfig {
                server_hostname: dest.to_string(),
                password: restls_password.clone(),
                restls_script: None,
                min_record_len: 15,
                rate_limit: 0,
            }),
            None,
        );
        let addr = serve(&cfg, capture.clone()).await.expect("serve");

        let tcp = TcpStream::connect(addr).await.unwrap();
        let restls_cfg = crate::proto::restls::RestlsOut {
            password: restls_password,
            sni: "restls.test".into(),
            version: "tls13".into(),
            restls_script: None,
            skip_cert_verify: true,
            udp: false,
        };
        let front = crate::proto::restls::connect(&restls_cfg, Box::new(tcp))
            .await
            .expect("restls client handshake");
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream = handshake(front, &client(&psk, addr.port(), 4), &target, false)
            .await
            .expect("snell over restls");
        stream.write_all(b"restls+snell").await.unwrap();
        let mut buf = [0u8; 12];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(&buf, b"restls+snell");
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn jls_fronting_roundtrips_with_engine_client_stack() {
        // jls fronting: proto::jls::server (wave-10) below the snell
        // codec; the engine's JLS client below the snell client. The
        // fronting's own dest is only the fallback target.
        let psk = fresh_psk();
        let (dest, _seen) = spawn_dest_echo().await;
        let capture = Capture::new();
        let cfg = cfg_fronted(
            4,
            &psk,
            "",
            None,
            None,
            Some((
                "jls.test".into(),
                dest.to_string(),
                vec![("user1".into(), "pass1".into())],
                Vec::new(),
                0,
            )),
        );
        let addr = serve(&cfg, capture.clone()).await.expect("serve");

        let tcp = TcpStream::connect(addr).await.unwrap();
        let jls_cfg = crate::proto::jls::JlsOut {
            username: "user1".into(),
            password: "pass1".into(),
            sni: "jls.test".into(),
            alpn: Vec::new(),
            skip_cert_verify: true,
            fingerprint: None,
        };
        let front = crate::proto::jls::connect(&jls_cfg, Box::new(tcp))
            .await
            .expect("jls client handshake");
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream = handshake(front, &client(&psk, addr.port(), 4), &target, false)
            .await
            .expect("snell over jls");
        stream.write_all(b"jls+snell").await.unwrap();
        let mut buf = [0u8; 9];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(&buf, b"jls+snell");
        assert_eq!(capture.targets(), vec![target]);
        assert_eq!(capture.relayed(), 1, "the jls fronting authenticated, not fell back");
    }

    #[tokio::test]
    async fn jls_fronting_wrong_password_falls_back_to_dest() {
        // The fronting's ClientHello auth fails with nothing written →
        // relayFallback toward the fronting's dest; the client errors
        // immediately (plain JLS path) and nothing relays.
        let psk = fresh_psk();
        let (dest, seen) = spawn_dest_echo().await;
        let capture = Capture::new();
        let cfg = cfg_fronted(
            4,
            &psk,
            "",
            None,
            None,
            Some((
                "jls.test".into(),
                dest.to_string(),
                vec![("user1".into(), "real-pass".into())],
                Vec::new(),
                0,
            )),
        );
        let addr = serve(&cfg, capture.clone()).await.expect("serve");

        let tcp = TcpStream::connect(addr).await.unwrap();
        let jls_cfg = crate::proto::jls::JlsOut {
            username: "user1".into(),
            password: "wrong-pass".into(),
            sni: "jls.test".into(),
            alpn: Vec::new(),
            skip_cert_verify: true,
            fingerprint: None,
        };
        let result = crate::proto::jls::connect(&jls_cfg, Box::new(tcp)).await;
        assert!(result.is_err(), "a wrong fronting password must not tunnel");
        // The recorded ClientHello reached the camouflage dest.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let len = seen.lock().unwrap().len();
            if len > 0 {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "dest never saw the fallback bytes");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(capture.relayed(), 0);
    }

    #[tokio::test]
    async fn frontings_are_mutually_exclusive() {
        // server.go:56-68, exact message and append order.
        let capture = Capture::new();
        let shadow = || Some((("pw").to_string(), "127.0.0.1:1".to_string(), false));
        let restls = || {
            Some(crate::proto::restls::RestlsServerConfig {
                server_hostname: "127.0.0.1:1".into(),
                password: "pw".into(),
                restls_script: None,
                min_record_len: 15,
                rate_limit: 0,
            })
        };
        let jls = || {
            Some((
                "jls.test".to_string(),
                "127.0.0.1:1".to_string(),
                vec![("u".to_string(), "p".to_string())],
                Vec::new(),
                0u32,
            ))
        };
        let err = serve(
            &cfg_fronted(4, "p", "", shadow(), restls(), None),
            capture.clone(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(
            err,
            "config: security modes are mutually exclusive: shadow-tls, res-tls"
        );
        let err = serve(
            &cfg_fronted(4, "p", "", None, restls(), jls()),
            capture.clone(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(err, "config: security modes are mutually exclusive: res-tls, jls");
        let err = serve(&cfg_fronted(4, "p", "", shadow(), restls(), jls()), capture.clone())
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "config: security modes are mutually exclusive: shadow-tls, res-tls, jls"
        );
    }

    #[tokio::test]
    async fn shadow_tls_fronting_config_gates() {
        // NewServerConfig (transport/shadowtls/server.go:73-84): a user
        // table and a default handshake dest.
        let capture = Capture::new();
        let err = serve(
            &cfg_fronted(4, "p", "", Some(("".into(), "127.0.0.1:1".into(), false)), None, None),
            capture.clone(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(err, "config: shadow-tls: at least one user is required");
        let err = serve(
            &cfg_fronted(4, "p", "", Some(("pw".into(), "".into(), false)), None, None),
            capture.clone(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(
            err,
            "config: shadow-tls: missing default handshake information"
        );
        // jls fronting gates: dest required, SplitHostPort, users.
        let err = serve(
            &cfg_fronted(4, "p", "", None, None, Some(("s".into(), "".into(), Vec::new(), Vec::new(), 0))),
            capture.clone(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(err, "config: jls: dest is required");
        let err = serve(
            &cfg_fronted(
                4,
                "p",
                "",
                None,
                None,
                Some(("s".into(), "camo.example".into(), Vec::new(), Vec::new(), 0)),
            ),
            capture,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("invalid dest"), "{err}");
    }
}
