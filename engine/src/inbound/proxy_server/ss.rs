//! Shadowsocks server stream (TCP) and relay socket (UDP): SIP004 legacy
//! AEAD and SIP022 2022.
//!
//! Inverts [`crate::proto::shadowsocks::SsStream`]: the server reads the
//! client salt, decrypts the request header (legacy: one address+payload
//! chunk; 2022: the sealed fixed header with type/timestamp/var-length,
//! then the sealed variable header carrying address, padding length,
//! padding and any initial payload), recovers the target and then speaks
//! the length-framed chunk dialect in both directions.
//!
//! The 2022 response header is sealed together with the first payload
//! chunk (SIP022: "the header is always sent along with payload") and
//! echoes the client salt, as the engine client — and mihomo/sing-box —
//! verify.
//!
//! UDP ([`SsUdpServer`]) is connectionless and independent of the TCP
//! sessions: one UDP socket per configured port, one relay session per
//! client source address.
//!
//! * Legacy AEAD (SIP004): a datagram is `salt || one AEAD block` over
//!   `socks-addr || payload` with an all-zero nonce, so each packet is
//!   self-contained; replies use a fresh salt the same way.
//! * 2022 (SIP022 §3.2): a 16-byte separate header (session id, packet
//!   id) is AES-ECB-encrypted with the PSK and the body is sealed with
//!   the per-session subkey. The client-to-server body is
//!   `type=0 | timestamp | padding-len | padding | socks-addr | payload`;
//!   the server-to-client body adds the echoed client session id after
//!   the timestamp. A repeated (session id, packet id) pair, a packet
//!   older than the replay window and a timestamp more than 30 s off are
//!   all dropped, and a datagram that does not authenticate is dropped
//!   silently (this is a connectionless relay: there is no one to reply
//!   an error to).

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use bytes::{Buf, BytesMut};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::addr::{decode_socks_addr, encode_socks_addr, NetAddr};
use crate::error::{Error, Result};
use crate::inbound::proxy_server::{
    hand_off, now_secs, read_exact_vec, serve_with, ServerConfig, ServerProtocol,
};
use crate::inbound::SharedRelay;
use crate::proto::aead::{ss2022_subkey, ss_subkey_legacy, Aead, AeadKind, SsNonce};
use crate::proto::shadowsocks::SsMethod;
use crate::stream::BoxProxyStream;

/// AEAD tag length for every supported method.
const TAG: usize = 16;
/// Largest plaintext chunk sealed per frame (the protocol allows 65535).
const MAX_CHUNK: usize = 16 * 1024;
/// SIP022 timestamp window. The spec's MUST is 30 s; the engine's client
/// accepts 60 s of drift on responses, so the server mirrors that.
const TS_WINDOW: u64 = 60;
/// SIP022 maximum request padding (`MaxPaddingLength`).
const MAX_PADDING: usize = 900;

/// A Shadowsocks TCP server: the parsed method and its derived main key.
#[derive(Clone)]
pub struct SsServer {
    method: SsMethod,
    key: Vec<u8>,
}

impl SsServer {
    /// Validate the config method/password once, before binding.
    pub fn new(method: &str, password: &str) -> Result<Self> {
        let method = SsMethod::parse(method)?;
        let key = method.derive_key(password)?;
        Ok(SsServer { method, key })
    }

    pub fn method(&self) -> SsMethod {
        self.method
    }

    /// Run the server handshake on an accepted connection and hand the
    /// framed stream to the relay.
    pub async fn handle(
        &self,
        stream: BoxProxyStream,
        peer: SocketAddr,
        port: u16,
        tag: &str,
        relay: SharedRelay,
    ) -> Result<()> {
        let (target, framed) = self.accept(stream).await?;
        hand_off(tag, "shadowsocks", port, peer, target, Box::new(framed), relay);
        Ok(())
    }

    /// Decrypt the request header; returns the target plus the framed
    /// stream, with any initial payload already queued for reading.
    async fn accept(&self, mut stream: BoxProxyStream) -> Result<(NetAddr, SsServerStream)> {
        let salt_len = self.method.key_len();
        let kind = aead_kind(self.method);
        let client_salt = read_exact_vec(&mut stream, salt_len).await?;
        let dec = Aead::new(kind, &subkey_for(self.method, &self.key, &client_salt))?;
        let mut dec_nonce = SsNonce::new();

        let (target, initial) = if self.method.is_2022() {
            // Fixed header (type, timestamp, var-header length) is one AEAD
            // block; its length field is the REAL length of the next chunk.
            let ct = read_exact_vec(&mut stream, 11 + TAG).await?;
            let fixed = dec
                .open(&dec_nonce.advance(), &[], &ct)
                .map_err(|e| Error::protocol(format!("ss2022 request header: {e}")))?;
            if fixed[0] != 0 {
                return Err(Error::protocol(
                    "ss2022 request: not a client stream header",
                ));
            }
            let ts = u64::from_be_bytes(fixed[1..9].try_into().expect("8 bytes"));
            let drift = now_secs().abs_diff(ts);
            if drift > TS_WINDOW {
                return Err(Error::protocol(format!(
                    "ss2022 request timestamp drift {drift}s exceeds replay window"
                )));
            }
            let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
            let ct = read_exact_vec(&mut stream, var_len + TAG).await?;
            let var = dec
                .open(&dec_nonce.advance(), &[], &ct)
                .map_err(|e| Error::protocol(format!("ss2022 request header: {e}")))?;
            let (target, used) = decode_socks_addr(&var)?;
            let rest = var
                .get(used..)
                .ok_or_else(|| Error::protocol("ss2022 request: header truncated"))?;
            if rest.len() < 2 {
                return Err(Error::protocol("ss2022 request: no padding length"));
            }
            let pad_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if pad_len > MAX_PADDING {
                return Err(Error::protocol(format!(
                    "ss2022 request: padding {pad_len} exceeds {MAX_PADDING}"
                )));
            }
            let body = rest
                .get(2 + pad_len..)
                .ok_or_else(|| Error::protocol("ss2022 request: padding overruns header"))?;
            if body.is_empty() && pad_len == 0 {
                // SIP022 3.1.4: a header carries payload or non-zero padding.
                return Err(Error::protocol(
                    "ss2022 request header carries neither payload nor padding",
                ));
            }
            if !claim_salt(&client_salt) {
                return Err(Error::protocol("ss2022 replay: duplicate client salt"));
            }
            (target, body.to_vec())
        } else {
            let ct = read_exact_vec(&mut stream, 2 + TAG).await?;
            let lp = dec
                .open(&dec_nonce.advance(), &[], &ct)
                .map_err(|e| Error::protocol(format!("shadowsocks request length: {e}")))?;
            let hlen = u16::from_be_bytes([lp[0], lp[1]]) as usize;
            let ct = read_exact_vec(&mut stream, hlen + TAG).await?;
            let hdr = dec
                .open(&dec_nonce.advance(), &[], &ct)
                .map_err(|e| Error::protocol(format!("shadowsocks request header: {e}")))?;
            let (target, used) = decode_socks_addr(&hdr)?;
            (target, hdr[used..].to_vec())
        };

        // Response direction: an independent salt/subkey, written lazily
        // before the first payload chunk.
        let resp_salt = fresh_salt(salt_len);
        let enc = Aead::new(kind, &subkey_for(self.method, &self.key, &resp_salt))?;
        let framed = SsServerStream {
            inner: stream,
            is_2022: self.method.is_2022(),
            client_salt,
            pending_salt: Some(resp_salt),
            enc,
            enc_nonce: SsNonce::new(),
            dec,
            dec_nonce,
            rbuf: BytesMut::with_capacity(16 * 1024),
            plain: BytesMut::from(&initial[..]),
            wbuf: BytesMut::new(),
            pending_plain: 0,
            state: ReadState::Len,
        };
        Ok((target, framed))
    }
}

/// Serve a Shadowsocks server listener; returns the bound address.
///
/// One configured port serves both transports: the UDP socket is bound
/// first and the TCP listener then takes its port number. With `port: 0`
/// the kernel only guarantees an ephemeral port for the family that
/// allocated it, so a clash on the other family is retried rather than
/// failing the listener.
pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let ServerProtocol::Shadowsocks { method, password } = &cfg.protocol else {
        return Err(Error::config(
            "ss::serve called with a non-shadowsocks protocol",
        ));
    };
    let server = SsServer::new(method, password)?;
    let attempts = if cfg.port == 0 { 16 } else { 1 };
    let mut last_err = None;
    for _ in 0..attempts {
        match serve_once(&server, cfg, relay.clone()).await {
            Ok(addr) => return Ok(addr),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| Error::network("shadowsocks: could not bind a port")))
}

/// One bind attempt: UDP socket, TCP listener on the same port, then the
/// relay loop.
async fn serve_once(server: &SsServer, cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let udp = SsUdpServer::bind(server, &cfg.bind, cfg.port, &cfg.tag, relay.clone()).await?;
    let udp_addr = udp
        .local_addr()
        .map_err(|e| Error::network(format!("shadowsocks udp local addr: {e}")))?;
    let tcp_cfg = ServerConfig {
        bind: udp_addr.ip().to_string(),
        port: udp_addr.port(),
        ..cfg.clone()
    };

    let tag = cfg.tag.clone();
    let tcp_server = server.clone();
    let addr = serve_with(&tcp_cfg, move |stream, peer, port| {
        let server = tcp_server.clone();
        let relay = relay.clone();
        let tag = tag.clone();
        async move { server.handle(stream, peer, port, &tag, relay).await }
    })
    .await?;
    tokio::spawn(Arc::new(udp).run());
    Ok(addr)
}

/// `SsMethod::kind()` is private to `proto::shadowsocks`; the mapping is
/// wire-visible (AES-128/256-GCM or ChaCha20-Poly1305 per method).
fn aead_kind(method: SsMethod) -> AeadKind {
    match method {
        SsMethod::Aes128Gcm | SsMethod::Blake3Aes128Gcm => AeadKind::Aes128Gcm,
        SsMethod::Aes256Gcm | SsMethod::Blake3Aes256Gcm => AeadKind::Aes256Gcm,
        SsMethod::Chacha20IetfPoly1305 => AeadKind::Chacha20Poly1305,
    }
}

fn subkey_for(method: SsMethod, key: &[u8], salt: &[u8]) -> Vec<u8> {
    if method.is_2022() {
        ss2022_subkey(key, salt, method.key_len())
    } else {
        ss_subkey_legacy(key, salt)
    }
}

fn fresh_salt(len: usize) -> Vec<u8> {
    let mut s = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut s);
    s
}

/// Random non-zero 2022 session id.
fn fresh_u64() -> u64 {
    loop {
        let v = rand::random::<u64>();
        if v != 0 {
            return v;
        }
    }
}

// ---------------------------------------------------------------------------
// UDP relay
// ---------------------------------------------------------------------------

/// SIP022 UDP timestamp window (`Messages with over 30 seconds of time
/// difference MUST be treated as replay`).
const UDP_TS_WINDOW: u64 = 30;
/// How long a client's relay session survives without traffic. SIP022
/// §3.2.4 requires remembering sessions for at least 60 s for replay
/// protection; the engine's own UDP sessions use the same TTL.
const UDP_SESSION_TTL: Duration = Duration::from_secs(60);
/// Accepted 2022 packet ids behind the highest one (SIP022 §3.2.4's
/// sliding-window replay protection).
const UDP_REPLAY_WINDOW: u64 = 1024;

/// The AES-ECB block cipher SIP022 encrypts the UDP separate header with.
enum BlockCipher {
    Aes128(Box<aes::Aes128>),
    Aes256(Box<aes::Aes256>),
}

impl BlockCipher {
    fn new(kind: AeadKind, key: &[u8]) -> Result<Self> {
        let cipher = match kind {
            AeadKind::Aes128Gcm => BlockCipher::Aes128(Box::new(
                aes::Aes128::new_from_slice(key)
                    .map_err(|e| Error::crypto(format!("ss2022 udp block cipher: {e}")))?,
            )),
            AeadKind::Aes256Gcm => BlockCipher::Aes256(Box::new(
                aes::Aes256::new_from_slice(key)
                    .map_err(|e| Error::crypto(format!("ss2022 udp block cipher: {e}")))?,
            )),
            other => {
                return Err(Error::crypto(format!(
                    "ss2022 udp needs an AES method, got {other:?}"
                )));
            }
        };
        Ok(cipher)
    }

    fn encrypt(&self, block: &mut [u8; 16]) {
        let b = aes::cipher::generic_array::GenericArray::from_mut_slice(&mut block[..]);
        match self {
            BlockCipher::Aes128(c) => c.encrypt_block(b),
            BlockCipher::Aes256(c) => c.encrypt_block(b),
        }
    }

    fn decrypt(&self, block: &mut [u8; 16]) {
        let b = aes::cipher::generic_array::GenericArray::from_mut_slice(&mut block[..]);
        match self {
            BlockCipher::Aes128(c) => c.decrypt_block(b),
            BlockCipher::Aes256(c) => c.decrypt_block(b),
        }
    }
}

/// How a 2022 client derives the per-session UDP subkey and nonce.
///
/// SIP022 §3.2.1 derives both from the DECRYPTED separate header, which
/// mihomo/sing-shadowsocks implement. The engine's own client
/// ([`crate::proto::shadowsocks::SsUdp`]) uses the ENCRYPTED header bytes
/// instead; the server accepts either and mirrors the one it saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum U2022Scheme {
    /// Spec form: subkey salt = plaintext session id, nonce = plaintext[4..16].
    Spec,
    /// The engine client's form: both taken from the header ciphertext.
    EngineClient,
}

impl U2022Scheme {
    fn other(self) -> Self {
        match self {
            U2022Scheme::Spec => U2022Scheme::EngineClient,
            U2022Scheme::EngineClient => U2022Scheme::Spec,
        }
    }
}

/// Sliding-window replay guard over 2022 client packet ids (the
/// sing-shadowsocks `SlidingWindow` semantics: ahead of the window is
/// fresh, more than [`UDP_REPLAY_WINDOW`] behind it cannot be told apart
/// from a replay, and a bit already set is a duplicate).
struct ReplayWindow {
    started: bool,
    highest: u64,
    seen: HashSet<u64>,
}

impl ReplayWindow {
    fn new() -> Self {
        ReplayWindow {
            started: false,
            highest: 0,
            seen: HashSet::new(),
        }
    }

    /// Record `packet_id`; false means it is a repeat or too old to tell
    /// apart from a replay.
    fn accept(&mut self, packet_id: u64) -> bool {
        if !self.started {
            // The session's first packet: any id, including 0.
            self.started = true;
            self.highest = packet_id;
            self.seen.insert(packet_id);
            return true;
        }
        let floor = self.highest.saturating_sub(UDP_REPLAY_WINDOW);
        if packet_id < floor || !self.seen.insert(packet_id) {
            return false;
        }
        if packet_id > self.highest {
            self.highest = packet_id;
        }
        let floor = self.highest.saturating_sub(UDP_REPLAY_WINDOW);
        self.seen.retain(|id| *id >= floor);
        true
    }
}

/// The 2022 half of a UDP session: the client construction in use, the
/// client's ids for the reply echo and the server's own ids for replies.
struct UdpCrypto {
    scheme: Option<U2022Scheme>,
    client_session_id: u64,
    server_session_id: u64,
    server_packet_id: u64,
    replay: ReplayWindow,
}

impl UdpCrypto {
    fn new() -> Self {
        UdpCrypto {
            scheme: None,
            client_session_id: 0,
            server_session_id: fresh_u64(),
            server_packet_id: 0,
            replay: ReplayWindow::new(),
        }
    }
}

/// One client's UDP relay session (pinned to its source address, like the
/// SOCKS5 association in [`crate::inbound::socks`]).
struct UdpSession {
    /// Uplink feed: dropping it ends the relay session.
    up: mpsc::Sender<(NetAddr, Vec<u8>)>,
    crypto: Mutex<UdpCrypto>,
}

/// The UDP side of a Shadowsocks listener: one socket per configured port,
/// one relay session per client source address.
pub struct SsUdpServer {
    method: SsMethod,
    key: Vec<u8>,
    /// 2022: AES-ECB over the main key for the separate header.
    block: Option<BlockCipher>,
    tag: String,
    relay: SharedRelay,
    socket: UdpSocket,
    sessions: Mutex<HashMap<SocketAddr, Arc<UdpSession>>>,
}

impl SsUdpServer {
    /// Bind the UDP socket; `server` supplies the validated method/key.
    async fn bind(
        server: &SsServer,
        bind: &str,
        port: u16,
        tag: &str,
        relay: SharedRelay,
    ) -> Result<Self> {
        let block = if server.method.is_2022() {
            Some(BlockCipher::new(aead_kind(server.method), &server.key)?)
        } else {
            None
        };
        let socket = UdpSocket::bind((bind, port))
            .await
            .map_err(|e| Error::network(format!("bind udp {bind}:{port}: {e}")))?;
        Ok(SsUdpServer {
            method: server.method,
            key: server.key.clone(),
            block,
            tag: tag.to_string(),
            relay,
            socket,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The socket loop: decrypt every datagram, relay it, and prune.
    async fn run(self: Arc<Self>) {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, source) = match self.socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(target: "engine", "shadowsocks udp recv: {e}");
                    continue;
                }
            };
            let session = self.session(source);
            // Authentication/replay work is synchronous: no lock is held
            // across the relay send below.
            let parsed = {
                let mut crypto = session.crypto.lock().unwrap_or_else(|e| e.into_inner());
                if self.method.is_2022() {
                    self.open_2022(&mut crypto, &buf[..n])
                } else {
                    self.open_legacy(&buf[..n])
                }
            };
            match parsed {
                Ok((target, payload)) => {
                    let _ = session.up.send((target, payload)).await;
                }
                Err(e) => {
                    // Connectionless: a bad packet is dropped, not answered.
                    tracing::debug!(target: "engine", "shadowsocks udp {source}: {e}");
                }
            }
        }
    }

    /// The session for `source`, opening a relay association on first use.
    fn session(self: &Arc<Self>, source: SocketAddr) -> Arc<UdpSession> {
        if let Some(session) = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&source)
        {
            return session.clone();
        }
        let (up, up_rx) = mpsc::channel(64);
        let (down, down_rx) = mpsc::channel(64);
        self.relay
            .clone()
            .handle_udp(source, self.tag.clone(), up_rx, down);
        let session = Arc::new(UdpSession {
            up,
            crypto: Mutex::new(UdpCrypto::new()),
        });
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(source, session.clone());
        tokio::spawn(downlink(self.clone(), session.clone(), source, down_rx));
        session
    }

    /// Decrypt one legacy AEAD datagram: `salt || AEAD(socks-addr || payload)`
    /// under the all-zero nonce.
    fn open_legacy(&self, datagram: &[u8]) -> Result<(NetAddr, Vec<u8>)> {
        let salt_len = self.method.key_len();
        if datagram.len() < salt_len + TAG {
            return Err(Error::protocol("shadowsocks udp: runt packet"));
        }
        let (salt, ct) = datagram.split_at(salt_len);
        let aead = Aead::new(aead_kind(self.method), &ss_subkey_legacy(&self.key, salt))?;
        let plain = aead
            .open(&[0u8; 12], &[], ct)
            .map_err(|_| Error::protocol("shadowsocks udp: packet does not authenticate"))?;
        split_socks_payload(&plain)
    }

    /// Encrypt one legacy AEAD reply: a fresh salt, then one AEAD block
    /// over `socks-addr || payload` under the all-zero nonce.
    fn seal_legacy(&self, target: &NetAddr, payload: &[u8]) -> Result<Vec<u8>> {
        let salt = fresh_salt(self.method.key_len());
        let aead = Aead::new(aead_kind(self.method), &ss_subkey_legacy(&self.key, &salt))?;
        let mut out = Vec::with_capacity(salt.len() + payload.len() + 48);
        out.extend_from_slice(&salt);
        let mut body = Vec::with_capacity(payload.len() + 48);
        encode_socks_addr(&mut body, &target.host, target.port);
        body.extend_from_slice(payload);
        aead.seal(&[0u8; 12], &[], &body, &mut out)?;
        Ok(out)
    }

    /// Decrypt one 2022 datagram: separate header, body, replay check.
    fn open_2022(&self, crypto: &mut UdpCrypto, datagram: &[u8]) -> Result<(NetAddr, Vec<u8>)> {
        if datagram.len() < 16 + TAG {
            return Err(Error::protocol(
                "ss2022 udp: packet shorter than a separate header plus tag",
            ));
        }
        let (sep_ct, body) = datagram.split_at(16);
        let sep_ct: &[u8; 16] = sep_ct
            .try_into()
            .map_err(|_| Error::protocol("ss2022 udp: bad separate header"))?;
        let block = self
            .block
            .as_ref()
            .ok_or_else(|| Error::crypto("ss2022 udp: missing block cipher"))?;
        let mut sep = [0u8; 16];
        sep.copy_from_slice(sep_ct);
        block.decrypt(&mut sep);
        let client_session_id = u64::from_be_bytes(sep[..8].try_into().expect("8 bytes"));
        let packet_id = u64::from_be_bytes(sep[8..].try_into().expect("8 bytes"));

        // Authenticate under the recorded construction first, then the
        // other one; only an authentic packet may touch the replay window.
        let candidates = match crypto.scheme {
            Some(scheme) => [scheme, scheme.other()],
            None => [U2022Scheme::Spec, U2022Scheme::EngineClient],
        };
        for scheme in candidates {
            let aead = self.aead_2022(scheme, &sep, sep_ct)?;
            let nonce = nonce_2022(scheme, &sep, sep_ct);
            let Ok(plain) = aead.open(&nonce, &[], body) else {
                continue;
            };
            crypto.scheme = Some(scheme);
            crypto.client_session_id = client_session_id;
            if crypto.server_session_id == client_session_id {
                // SIP022: servers MUST not use client session ids.
                crypto.server_session_id = fresh_u64();
            }
            if !crypto.replay.accept(packet_id) {
                return Err(Error::protocol(
                    "ss2022 udp replay: duplicate or stale (session, packet) id",
                ));
            }
            return parse_2022_body(&plain);
        }
        Err(Error::protocol(
            "ss2022 udp: packet does not authenticate (wrong key, replayed or corrupt)",
        ))
    }

    /// Encrypt one 2022 reply: a separate header with the server's own
    /// session id/packet id, then the sealed server body.
    fn seal_2022(&self, crypto: &mut UdpCrypto, target: &NetAddr, payload: &[u8]) -> Result<Vec<u8>> {
        crypto.server_packet_id = crypto.server_packet_id.wrapping_add(1);
        let mut sep = [0u8; 16];
        sep[..8].copy_from_slice(&crypto.server_session_id.to_be_bytes());
        sep[8..].copy_from_slice(&crypto.server_packet_id.to_be_bytes());
        let scheme = crypto.scheme.unwrap_or(U2022Scheme::Spec);
        let block = self
            .block
            .as_ref()
            .ok_or_else(|| Error::crypto("ss2022 udp: missing block cipher"))?;
        let mut sep_ct = sep;
        block.encrypt(&mut sep_ct);
        let aead = self.aead_2022(scheme, &sep, &sep_ct)?;
        let nonce = nonce_2022(scheme, &sep, &sep_ct);

        let mut body = Vec::with_capacity(payload.len() + 48);
        body.push(1u8); // server packet
        body.extend_from_slice(&now_secs().to_be_bytes());
        body.extend_from_slice(&crypto.client_session_id.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // no padding
        encode_socks_addr(&mut body, &target.host, target.port);
        body.extend_from_slice(payload);

        let mut out = Vec::with_capacity(16 + body.len() + TAG);
        out.extend_from_slice(&sep_ct);
        aead.seal(&nonce, &[], &body, &mut out)?;
        Ok(out)
    }

    fn aead_2022(&self, scheme: U2022Scheme, sep: &[u8; 16], sep_ct: &[u8; 16]) -> Result<Aead> {
        let salt = match scheme {
            U2022Scheme::Spec => &sep[..8],
            U2022Scheme::EngineClient => &sep_ct[..8],
        };
        Aead::new(
            aead_kind(self.method),
            &ss2022_subkey(&self.key, salt, self.method.key_len()),
        )
    }
}

fn nonce_2022(scheme: U2022Scheme, sep: &[u8; 16], sep_ct: &[u8; 16]) -> [u8; 12] {
    let source = match scheme {
        U2022Scheme::Spec => sep,
        U2022Scheme::EngineClient => sep_ct,
    };
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&source[4..16]);
    nonce
}

/// Reply pump for one client: encrypt downlink datagrams until the relay
/// closes or the session idles out.
async fn downlink(
    server: Arc<SsUdpServer>,
    session: Arc<UdpSession>,
    client: SocketAddr,
    mut down_rx: mpsc::Receiver<(NetAddr, Vec<u8>)>,
) {
    loop {
        let Ok(Some((target, data))) = tokio::time::timeout(UDP_SESSION_TTL, down_rx.recv()).await
        else {
            break;
        };
        let packet = {
            let mut crypto = session.crypto.lock().unwrap_or_else(|e| e.into_inner());
            if server.method.is_2022() {
                server.seal_2022(&mut crypto, &target, &data)
            } else {
                server.seal_legacy(&target, &data)
            }
        };
        match packet {
            Ok(packet) => {
                if server.socket.send_to(&packet, client).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                tracing::debug!(target: "engine", "shadowsocks udp reply {client}: {e}");
            }
        }
    }
    // Retire the session so a later datagram from the same client starts a
    // fresh association (the relay's own session ends with the channels).
    let mut sessions = server.sessions.lock().unwrap_or_else(|e| e.into_inner());
    if sessions
        .get(&client)
        .map(|s| Arc::ptr_eq(s, &session))
        .unwrap_or(false)
    {
        sessions.remove(&client);
    }
}

/// Split a decrypted payload into its socks address and payload (the
/// legacy/2022 common trailer).
fn split_socks_payload(data: &[u8]) -> Result<(NetAddr, Vec<u8>)> {
    let (target, used) = decode_socks_addr(data)?;
    Ok((target, data[used..].to_vec()))
}

/// Parse the decrypted client-to-server 2022 body:
/// `type | timestamp | padding-len | padding | socks-addr | payload`.
fn parse_2022_body(body: &[u8]) -> Result<(NetAddr, Vec<u8>)> {
    if body.len() < 11 || body[0] != 0 {
        return Err(Error::protocol("ss2022 udp: not a client packet"));
    }
    let ts = u64::from_be_bytes(body[1..9].try_into().expect("8 bytes"));
    let drift = now_secs().abs_diff(ts);
    if drift > UDP_TS_WINDOW {
        return Err(Error::protocol(format!(
            "ss2022 udp: timestamp drift {drift}s exceeds replay window"
        )));
    }
    let pad_len = u16::from_be_bytes([body[9], body[10]]) as usize;
    let rest = body
        .get(11 + pad_len..)
        .ok_or_else(|| Error::protocol("ss2022 udp: padding overruns packet"))?;
    split_socks_payload(rest)
}

/// Seal one length+payload chunk (legacy framing, and 2022 data chunks).
fn seal_chunk(aead: &Aead, nonce: &mut SsNonce, plain: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let len = u16::try_from(plain.len())
        .map_err(|_| Error::protocol("shadowsocks chunk exceeds 65535 bytes"))?;
    aead.seal(&nonce.advance(), &[], &len.to_be_bytes(), out)?;
    aead.seal(&nonce.advance(), &[], plain, out)?;
    Ok(())
}

/// Seen client salts with their first-seen time (pruned past the window).
type SaltPool = Mutex<Vec<(Vec<u8>, Instant)>>;

/// SIP022 replay guard: a client salt must be new within the 60 s window
/// (satisfies the spec's MUST without a false-positive bloom filter).
fn claim_salt(salt: &[u8]) -> bool {
    static SEEN: OnceLock<SaltPool> = OnceLock::new();
    let now = Instant::now();
    let mut seen = SEEN
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    seen.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(TS_WINDOW));
    if seen.iter().any(|(s, _)| s == salt) {
        return false;
    }
    seen.push((salt.to_vec(), now));
    true
}

/// Read states of a framed stream after the request header is consumed.
enum ReadState {
    Len,
    Payload(u16),
}

/// The server side of a Shadowsocks TCP session.
struct SsServerStream {
    inner: BoxProxyStream,
    is_2022: bool,
    /// Echoed in the 2022 response header.
    client_salt: Vec<u8>,
    /// Response salt not yet on the wire (see the module comment).
    pending_salt: Option<Vec<u8>>,
    enc: Aead,
    enc_nonce: SsNonce,
    dec: Aead,
    dec_nonce: SsNonce,
    rbuf: BytesMut,
    plain: BytesMut,
    wbuf: BytesMut,
    pending_plain: usize,
    state: ReadState,
}

impl SsServerStream {
    fn advance_state(&mut self) -> Result<()> {
        match self.state {
            ReadState::Len => {
                let pt = self
                    .dec
                    .open(&self.dec_nonce.advance(), &[], &self.rbuf[..2 + TAG])
                    .map_err(|e| Error::protocol(format!("shadowsocks length chunk: {e}")))?;
                self.rbuf.advance(2 + TAG);
                self.state = ReadState::Payload(u16::from_be_bytes([pt[0], pt[1]]));
            }
            ReadState::Payload(len) => {
                let n = len as usize + TAG;
                let pt = self
                    .dec
                    .open(&self.dec_nonce.advance(), &[], &self.rbuf[..n])
                    .map_err(|e| Error::protocol(format!("shadowsocks payload chunk: {e}")))?;
                self.rbuf.advance(n);
                self.plain.extend_from_slice(&pt);
                self.state = ReadState::Len;
            }
        }
        Ok(())
    }

    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.plain.is_empty() {
                let n = self.plain.len().min(dst.remaining());
                dst.put_slice(&self.plain[..n]);
                self.plain.advance(n);
                return Poll::Ready(Ok(()));
            }
            let need = match &self.state {
                ReadState::Len => 2 + TAG,
                ReadState::Payload(len) => *len as usize + TAG,
            };
            if self.rbuf.len() >= need {
                if let Err(e) = self.advance_state() {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)));
                }
                continue;
            }
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                if self.rbuf.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "shadowsocks: truncated stream",
                )));
            }
            self.rbuf.extend_from_slice(rb.filled());
        }
    }
}

impl AsyncRead for SsServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read_inner(cx, buf)
    }
}

impl AsyncWrite for SsServerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.wbuf.is_empty() {
            let take = buf.len().min(MAX_CHUNK);
            let mut out = Vec::with_capacity(take + 11 + 2 * TAG + 34);
            if let Some(salt) = this.pending_salt.take() {
                out.extend_from_slice(&salt);
                if this.is_2022 {
                    // The 2022 response fixed header IS the first length
                    // chunk: seal it, then the first payload as one block.
                    let mut fixed = Vec::with_capacity(11 + this.client_salt.len());
                    fixed.push(1u8); // server stream
                    fixed.extend_from_slice(&now_secs().to_be_bytes());
                    fixed.extend_from_slice(&this.client_salt);
                    fixed.extend_from_slice(&(take as u16).to_be_bytes());
                    this.enc
                        .seal(&this.enc_nonce.advance(), &[], &fixed, &mut out)
                        .map_err(to_io)?;
                    this.enc
                        .seal(&this.enc_nonce.advance(), &[], &buf[..take], &mut out)
                        .map_err(to_io)?;
                } else {
                    seal_chunk(&this.enc, &mut this.enc_nonce, &buf[..take], &mut out)
                        .map_err(to_io)?;
                }
            } else {
                seal_chunk(&this.enc, &mut this.enc_nonce, &buf[..take], &mut out).map_err(to_io)?;
            }
            this.wbuf = BytesMut::from(&out[..]);
            this.pending_plain = take;
        }
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "shadowsocks: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Poll::Ready(Ok(this.pending_plain))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn to_io(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Host;
    use crate::inbound::proxy_server::test_support::Capture;
    use crate::proto::shadowsocks::SsOut;
    use base64::Engine as _;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Fresh per-run credential: nothing usable is ever committed.
    fn fresh_password() -> String {
        let mut b = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Fresh base64 PSK for the 2022 methods.
    fn fresh_psk(len: usize) -> String {
        let mut b = vec![0u8; len];
        rand::rngs::OsRng.fill_bytes(&mut b);
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    async fn spawn_server(method: &str, password: &str) -> (Arc<Capture>, SocketAddr) {
        let cfg = ServerConfig {
            tag: "ss-test".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::Shadowsocks {
                method: method.into(),
                password: password.into(),
            },
        };
        let capture = Capture::new();
        let addr = serve(&cfg, capture.clone()).await.unwrap();
        (capture, addr)
    }

    fn client(password: &str, method: &str, port: u16) -> SsOut {
        SsOut {
            server: "127.0.0.1".into(),
            port,
            method: SsMethod::parse(method).unwrap(),
            password: password.into(),
        }
    }

    /// Full loop: engine client codec against this server.
    async fn roundtrip(method: &str, password: &str) {
        let (capture, addr) = spawn_server(method, password).await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let cfg = client(password, method, addr.port());
        let mut stream = crate::proto::shadowsocks::SsStream::handshake(
            Box::new(tcp),
            &cfg,
            &target,
            b"",
        )
        .await
        .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn legacy_tcp_roundtrip_all_methods() {
        for method in [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-ietf-poly1305",
        ] {
            roundtrip(method, &fresh_password()).await;
        }
    }

    #[tokio::test]
    async fn ss2022_tcp_roundtrip_both_key_sizes() {
        roundtrip("2022-blake3-aes-128-gcm", &fresh_psk(16)).await;
        roundtrip("2022-blake3-aes-256-gcm", &fresh_psk(32)).await;
    }

    #[tokio::test]
    async fn legacy_wrong_password_relays_nothing() {
        let (capture, addr) = spawn_server("aes-128-gcm", &fresh_password()).await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        // Client uses a password the server does not know.
        let cfg = client(&fresh_password(), "aes-128-gcm", addr.port());
        let mut stream =
            crate::proto::shadowsocks::SsStream::handshake(Box::new(tcp), &cfg, &target, b"")
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
    async fn ss2022_wrong_psk_relays_nothing() {
        let (capture, addr) = spawn_server("2022-blake3-aes-128-gcm", &fresh_psk(16)).await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let cfg = client(&fresh_psk(16), "2022-blake3-aes-128-gcm", addr.port());
        let mut stream =
            crate::proto::shadowsocks::SsStream::handshake(Box::new(tcp), &cfg, &target, b"")
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

    #[test]
    fn replay_guard_rejects_repeated_salt() {
        let salt = fresh_salt(16);
        assert!(claim_salt(&salt));
        assert!(!claim_salt(&salt));
        // A different salt is still fresh.
        assert!(claim_salt(&fresh_salt(16)));
    }

    // -- UDP -----------------------------------------------------------

    /// The engine's own client codec against the server's UDP side.
    async fn udp_roundtrip(method: &str, password: &str) {
        let (capture, addr) = spawn_server(method, password).await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let cfg = client(password, method, addr.port());
        let mut udp = crate::proto::shadowsocks::SsUdp::bind(&cfg).await.unwrap();
        udp.send(&target, b"ping").await.unwrap();
        let (from, data) = tokio::time::timeout(Duration::from_secs(5), udp.recv())
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(data, b"ping");
        assert_eq!(from, target);
        assert_eq!(capture.udp_targets(), vec![target]);
        assert_eq!(capture.udp_sessions().len(), 1);
    }

    #[tokio::test]
    async fn legacy_udp_roundtrip_all_methods() {
        for method in [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-ietf-poly1305",
        ] {
            udp_roundtrip(method, &fresh_password()).await;
        }
    }

    #[tokio::test]
    async fn ss2022_udp_roundtrip_both_key_sizes() {
        udp_roundtrip("2022-blake3-aes-128-gcm", &fresh_psk(16)).await;
        udp_roundtrip("2022-blake3-aes-256-gcm", &fresh_psk(32)).await;
    }

    /// A hand-rolled 2022 UDP client, so the raw datagram bytes can be
    /// replayed and so the spec construction can be exercised (the engine
    /// client's [`U2022Scheme::EngineClient`] one is covered above).
    struct Raw2022 {
        key: Vec<u8>,
        method: SsMethod,
        scheme: U2022Scheme,
        block: BlockCipher,
        session_id: u64,
        packet_id: u64,
    }

    impl Raw2022 {
        fn new(psk: &str, scheme: U2022Scheme) -> Self {
            let method = SsMethod::parse("2022-blake3-aes-256-gcm").unwrap();
            let key = method.derive_key(psk).unwrap();
            Raw2022 {
                block: BlockCipher::new(aead_kind(method), &key).unwrap(),
                key,
                method,
                scheme,
                session_id: fresh_u64(),
                packet_id: 0,
            }
        }

        fn keys(&self, sep: &[u8; 16], sep_ct: &[u8; 16]) -> (Aead, [u8; 12]) {
            let salt = match self.scheme {
                U2022Scheme::Spec => &sep[..8],
                U2022Scheme::EngineClient => &sep_ct[..8],
            };
            let source = match self.scheme {
                U2022Scheme::Spec => sep,
                U2022Scheme::EngineClient => sep_ct,
            };
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&source[4..16]);
            (
                Aead::new(
                    aead_kind(self.method),
                    &ss2022_subkey(&self.key, salt, self.method.key_len()),
                )
                .unwrap(),
                nonce,
            )
        }

        fn packet(&mut self, target: &NetAddr, data: &[u8]) -> Vec<u8> {
            self.packet_id += 1;
            let mut sep = [0u8; 16];
            sep[..8].copy_from_slice(&self.session_id.to_be_bytes());
            sep[8..].copy_from_slice(&self.packet_id.to_be_bytes());
            let mut sep_ct = sep;
            self.block.encrypt(&mut sep_ct);
            let (aead, nonce) = self.keys(&sep, &sep_ct);
            let mut body = vec![0u8];
            body.extend_from_slice(&now_secs().to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes());
            encode_socks_addr(&mut body, &target.host, target.port);
            body.extend_from_slice(data);
            let mut out = sep_ct.to_vec();
            aead.seal(&nonce, &[], &body, &mut out).unwrap();
            out
        }

        /// Open a server packet; asserts the spec's echoed client session id.
        fn open(&self, wire: &[u8]) -> (NetAddr, Vec<u8>) {
            let (sep_ct, ct) = wire.split_at(16);
            let mut sep = [0u8; 16];
            sep.copy_from_slice(sep_ct);
            self.block.decrypt(&mut sep);
            let sep: [u8; 16] = sep;
            let sep_ct: [u8; 16] = sep_ct.try_into().unwrap();
            let (aead, nonce) = self.keys(&sep, &sep_ct);
            let body = aead.open(&nonce, &[], ct).expect("server reply decrypts");
            assert_eq!(body[0], 1, "server packet type");
            let echoed = u64::from_be_bytes(body[9..17].try_into().unwrap());
            assert_eq!(echoed, self.session_id, "client session id is echoed");
            let pad_len = u16::from_be_bytes([body[17], body[18]]) as usize;
            let rest = &body[19 + pad_len..];
            let (target, used) = decode_socks_addr(rest).unwrap();
            (target, rest[used..].to_vec())
        }
    }

    async fn raw_socket(addr: SocketAddr) -> tokio::net::UdpSocket {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(addr).await.unwrap();
        socket
    }

    /// SIP022 §3.2.1 construction (decrypted header feeds subkey/nonce) —
    /// what mihomo and sing-shadowsocks speak.
    #[tokio::test]
    async fn ss2022_udp_spec_scheme_roundtrip() {
        let psk = fresh_psk(32);
        let (capture, addr) = spawn_server("2022-blake3-aes-256-gcm", &psk).await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut raw = Raw2022::new(&psk, U2022Scheme::Spec);
        let socket = raw_socket(addr).await;
        socket.send(&raw.packet(&target, b"ping")).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .expect("timeout")
            .unwrap();
        let (from, data) = raw.open(&buf[..n]);
        assert_eq!(from, target);
        assert_eq!(data, b"ping");
        assert_eq!(capture.udp_targets(), vec![target]);
    }

    /// The same (session id, packet id) pair twice: the replay is dropped,
    /// so only one datagram reaches the relay and one reply comes back.
    #[tokio::test]
    async fn ss2022_udp_replay_relays_once() {
        let psk = fresh_psk(32);
        let (capture, addr) = spawn_server("2022-blake3-aes-256-gcm", &psk).await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut raw = Raw2022::new(&psk, U2022Scheme::EngineClient);
        let packet = raw.packet(&target, b"ping");
        let socket = raw_socket(addr).await;
        socket.send(&packet).await.unwrap();
        socket.send(&packet).await.unwrap(); // byte-for-byte replay

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .expect("first reply")
            .unwrap();
        assert_eq!(raw.open(&buf[..n]).1, b"ping");
        let second = tokio::time::timeout(Duration::from_millis(400), socket.recv(&mut buf)).await;
        assert!(second.is_err(), "a replayed packet produced a second reply");
        assert_eq!(capture.udp_targets().len(), 1);
    }

    #[tokio::test]
    async fn legacy_udp_wrong_password_relays_nothing() {
        let (capture, addr) = spawn_server("aes-128-gcm", &fresh_password()).await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        // Client uses a password the server does not know.
        let cfg = client(&fresh_password(), "aes-128-gcm", addr.port());
        let mut udp = crate::proto::shadowsocks::SsUdp::bind(&cfg).await.unwrap();
        udp.send(&target, b"ping").await.unwrap();
        let reply = tokio::time::timeout(Duration::from_millis(400), udp.recv()).await;
        assert!(reply.is_err(), "wrong password must be dropped");
        assert_eq!(capture.relayed(), 0);
        assert!(capture.udp_targets().is_empty());
    }

    #[tokio::test]
    async fn ss2022_udp_wrong_psk_relays_nothing() {
        let (capture, addr) = spawn_server("2022-blake3-aes-128-gcm", &fresh_psk(16)).await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let cfg = client(&fresh_psk(16), "2022-blake3-aes-128-gcm", addr.port());
        let mut udp = crate::proto::shadowsocks::SsUdp::bind(&cfg).await.unwrap();
        udp.send(&target, b"ping").await.unwrap();
        let reply = tokio::time::timeout(Duration::from_millis(400), udp.recv()).await;
        assert!(reply.is_err(), "wrong PSK must be dropped");
        assert!(capture.udp_targets().is_empty());
    }

    #[test]
    fn replay_window_rejects_repeats_and_stale_ids() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(1));
        assert!(!window.accept(1), "the same packet id is a replay");
        assert!(window.accept(2));
        assert!(window.accept(0), "an out-of-order id inside the window is new");
        assert!(!window.accept(0));
        assert!(window.accept(UDP_REPLAY_WINDOW + 10));
        assert!(
            !window.accept(3),
            "ids behind the window cannot be told from replays"
        );
    }

    #[test]
    fn udp_reply_frame_layout_matches_the_client_parser() {
        // type(1) ts(8) client-session(8) padding-len(2) addr payload, which
        // is exactly what proto::shadowsocks parses as a server frame.
        let body = {
            let mut b = vec![1u8];
            b.extend_from_slice(&now_secs().to_be_bytes());
            b.extend_from_slice(&42u64.to_be_bytes());
            b.extend_from_slice(&0u16.to_be_bytes());
            let mut addr = Vec::new();
            encode_socks_addr(&mut addr, &Host::Domain("a.b".into()), 80);
            b.extend_from_slice(&addr);
            b.extend_from_slice(b"xyz");
            b
        };
        let pad_len = u16::from_be_bytes([body[17], body[18]]) as usize;
        let rest = &body[19 + pad_len..];
        let (addr, used) = decode_socks_addr(rest).unwrap();
        assert_eq!(addr.host, Host::Domain("a.b".into()));
        assert_eq!(addr.port, 80);
        assert_eq!(&rest[used..], b"xyz");
    }

    #[test]
    fn method_mapping_is_wire_correct() {
        assert_eq!(aead_kind(SsMethod::Blake3Aes128Gcm), AeadKind::Aes128Gcm);
        assert_eq!(aead_kind(SsMethod::Aes256Gcm), AeadKind::Aes256Gcm);
        assert_eq!(
            aead_kind(SsMethod::Chacha20IetfPoly1305),
            AeadKind::Chacha20Poly1305
        );
        assert!(SsServer::new("rc4-md5", "x").is_err());
        assert!(SsServer::new("2022-blake3-aes-128-gcm", "not-a-psk").is_err());
    }
}