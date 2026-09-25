//! The tailscale data plane: a WireGuard initiator session whose
//! datagrams ride either a direct UDP path or a DERP relay.
//!
//! This is the `tsnet`/`magicsock` shape of the data plane: every peer
//! packet is a WireGuard protocol message (`wgengine`'s device); what
//! varies is the carrier — magicsock sends the same ciphertexts to the
//! peer's UDP endpoints and, when those are unreachable, to the peer's
//! home DERP relay (`magicsock.Conn.sendAddr` / `sendDatagramsViaDERP`,
//! wgengine/magicsock/magicsock.go). This port keeps the carrier split
//! explicit ([`Carrier`]): a direct [`tokio::net::UdpSocket`] bound for
//! the peer's endpoint, or the wave-10 [`super::derp`] client relaying
//! frames by node key, or both at once while the path is being learned.
//!
//! # Why a session lives here (and not in `proto::wireguard`)
//!
//! The engine's WireGuard client (`proto/wireguard.rs`) binds its own
//! UDP socket inside `tunnel_for` and therefore cannot carry datagrams
//! through DERP. `proto::wireguard`'s internals are private to that
//! module — by design, this is the pattern the wave brief named "a new
//! tailscale-side session that reuses its noise primitives": the
//! handshake math below is the same Noise_IKpsk2 protocol, re-derived
//! over the wave-10 crypto primitives in [`super::noise`] (`blake2s`,
//! `hmac_blake2s`) plus what the tree already exposes from
//! `proto::wireguard` itself — [`crate::proto::wireguard::AntiReplay`],
//! [`crate::proto::wireguard::WgMsg`], and
//! [`crate::proto::wireguard::parse_wg_msg`]. Where the existing client
//! CAN be driven directly (a reachable UDP endpoint), [`super`] uses it
//! instead — see `super::dial_peer_direct`.
//!
//! # Netstack
//!
//! Like `proto/wireguard.rs` (its module docs, "Netstack" bullet), the
//! inner IP layer is a smoltcp `Interface` behind a queue-based
//! `Device` shim — the non-gVisor stand-in for tsnet's `Netstack`.
//! TCP dials become [`TsTcpStream`]; UDP-through-the-overlay is not
//! wired this wave (gap list in `super`).
//!
//! # Deltas vs upstream
//!
//! * No disco: modern tailscale peers speak the `disco` overlay (ping/
//!   call-me-maybe) inside the same WireGuard datagrams; a peer that
//!   requires disco before accepting transport will not come up
//!   (disco is on the gap list). Peers marked `IsWireGuardOnly` (and
//!   the engine's own endpoint) interoperate fully.
//! * No cookie retry: a responder under initiation load replies with a
//!   cookie request which this port drops (wireguard.rs:834-869 has the
//!   consume half; tests never trip the 64/s load threshold). MAC1 is
//!   always computed and MAC2 left zero, the unloaded-responder shape.
//! * Path learning is first-response-wins: handshakes go out on every
//!   configured carrier; the carrier that answers carries the session
//!   (magicsock maintains full endpoint state instead).
//! * Rekey timers mirror wireguard-go (REKEY_AFTER_TIME 120s,
//!   REJECT_AFTER_TIME 180s, REKEY_TIMEOUT 5s, KEEPALIVE 10s — the
//!   constants cross-checked in `proto/wireguard.rs:180-207`).

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};

use crate::error::{Error, Result};

use super::noise::{blake2s256, blake2s_into, hmac_blake2s};

// ---------------------------------------------------------------------------
// WireGuard protocol constants (proto/wireguard.rs:167-207 parity)
// ---------------------------------------------------------------------------

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1;
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HANDSHAKE_ATTEMPTS: u32 = 18;
const PADDING_MULTIPLE: usize = 16;
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const MSG_INITIATION_LEN: usize = 148;
const MSG_RESPONSE_LEN: usize = 92;
const TRANSPORT_HEADER_LEN: usize = 16;
const MSG_TYPE_INITIATION: u32 = 1;
const MSG_TYPE_RESPONSE: u32 = 2;
const MSG_TYPE_TRANSPORT: u32 = 4;

// ---------------------------------------------------------------------------
// The Noise_IKpsk2 math, initiator side (mirrors proto/wireguard.rs
// 369-505 KDF/MAC + 695-833 handshake; every formula cites the same
// whitepaper steps)
// ---------------------------------------------------------------------------

fn hash2(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(a.len() + b.len());
    buf.extend_from_slice(a);
    buf.extend_from_slice(b);
    blake2s256(&buf)
}

/// Keyed BLAKE2s 16-byte MAC (wireguard.rs:250-256 `blake2s_mac`): the
/// key is the full 32 bytes; only the OUTPUT is truncated to 16.
fn blake2s_mac16(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    blake2s_into(data, Some(key), &mut out);
    out
}

/// KDF2 (wireguard.rs:376-389): temp = HMAC(ck, x); ck' = HMAC(temp, 1);
/// key = HMAC(temp, ck' || 2).
fn kdf2(ck: &[u8; 32], x: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac_blake2s(ck, x);
    let ck2 = hmac_blake2s(&temp, &[1]);
    let mut mat = Vec::with_capacity(33);
    mat.extend_from_slice(&ck2);
    mat.push(2);
    let key = hmac_blake2s(&temp, &mat);
    (ck2, key)
}

/// KDF1 (wireguard.rs:371-373): ck' only.
fn kdf1(ck: &[u8; 32], x: &[u8]) -> [u8; 32] {
    let temp = hmac_blake2s(ck, x);
    hmac_blake2s(&temp, &[1])
}

/// KDF3 (wireguard.rs:391-408): the psk2 step.
fn kdf3(ck: &[u8; 32], x: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let temp = hmac_blake2s(ck, x);
    let ck2 = hmac_blake2s(&temp, &[1]);
    let mut mat = Vec::with_capacity(33);
    mat.extend_from_slice(&ck2);
    mat.push(2);
    let temp2 = hmac_blake2s(&temp, &mat);
    let mut mat2 = Vec::with_capacity(33);
    mat2.extend_from_slice(&temp2);
    mat2.push(3);
    let key = hmac_blake2s(&temp, &mat2);
    (ck2, temp2, key)
}

/// Transport keys (wireguard.rs:411-421): temp1 = HMAC(ck, ""); send =
/// HMAC(temp1, 1); recv = HMAC(temp1, send || 2) — initiator order.
fn derive_transport_keys(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let temp1 = hmac_blake2s(ck, &[]);
    let send = hmac_blake2s(&temp1, &[1]);
    let mut mat = Vec::with_capacity(33);
    mat.extend_from_slice(&send);
    mat.push(2);
    let recv = hmac_blake2s(&temp1, &mat);
    (send, recv)
}

/// MAC1 key: HASH(LABEL_MAC1 || responder static) (wireguard.rs:423-429).
fn mac1_key(peer_static: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(LABEL_MAC1.len() + 32);
    buf.extend_from_slice(LABEL_MAC1);
    buf.extend_from_slice(peer_static);
    blake2s256(&buf)
}

fn aead_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

fn aead_seal(key: &[u8; 32], counter: u64, plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::crypto("wg: bad AEAD key length"))?;
    cipher
        .encrypt((&aead_nonce(counter)).into(), Payload { msg: plain, aad })
        .map_err(|_| Error::crypto("wg: AEAD seal failed"))
}

fn aead_open(key: &[u8; 32], counter: u64, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::crypto("wg: bad AEAD key length"))?;
    cipher
        .decrypt((&aead_nonce(counter)).into(), Payload { msg: ct, aad })
        .map_err(|_| Error::crypto("wg: AEAD open failed"))
}

/// TAI64N now (wireguard.rs:502-507): BE seconds + BE nanos.
fn tai64n_now() -> [u8; 12] {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&(0x4000_0000_0000_0000u64 + d.as_secs()).to_be_bytes());
    out[8..].copy_from_slice(&d.subsec_nanos().to_be_bytes());
    out
}

fn x25519_pub(sk: &[u8; 32]) -> [u8; 32] {
    curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(*sk).0
}

fn x25519_dh(sk: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32]> {
    let shared = curve25519_dalek::montgomery::MontgomeryPoint(*peer)
        .mul_clamped(*sk)
        .0;
    if shared.iter().all(|&b| b == 0) {
        return Err(Error::crypto("wg: X25519 peer key is a low-order point"));
    }
    Ok(shared)
}

/// State between the initiation and the response
/// (wireguard.rs:674-693 InitiationPending).
struct PendingHandshake {
    local_index: u32,
    e_priv: [u8; 32],
    chaining_key: [u8; 32],
    hash: [u8; 32],
    attempts: u32,
}

/// Build the 148-byte initiation (wireguard.rs:695-752, whitepaper
/// "First Message").
fn build_initiation(
    static_priv: &[u8; 32],
    peer_pub: &[u8; 32],
    local_index: u32,
) -> Result<(Vec<u8>, PendingHandshake)> {
    let static_pub = x25519_pub(static_priv);
    let mut ck = blake2s256(CONSTRUCTION);
    let ident_hash = hash2(&ck, IDENTIFIER);
    let mut h = hash2(&ident_hash, peer_pub);

    let mut e_priv = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut e_priv);
    let e_pub = x25519_pub(&e_priv);
    h = hash2(&h, &e_pub);
    ck = kdf1(&ck, &e_pub);

    let es = x25519_dh(&e_priv, peer_pub)?;
    let (ck, key_es) = kdf2(&ck, &es);
    let enc_static = aead_seal(&key_es, 0, &static_pub, &h)?;
    h = hash2(&h, &enc_static);

    let ss = x25519_dh(static_priv, peer_pub)?;
    let (ck, key_ss) = kdf2(&ck, &ss);
    let enc_timestamp = aead_seal(&key_ss, 0, &tai64n_now(), &h)?;
    h = hash2(&h, &enc_timestamp);

    let mut msg = Vec::with_capacity(MSG_INITIATION_LEN);
    msg.extend_from_slice(&MSG_TYPE_INITIATION.to_le_bytes());
    msg.extend_from_slice(&local_index.to_le_bytes());
    msg.extend_from_slice(&e_pub);
    msg.extend_from_slice(&enc_static);
    msg.extend_from_slice(&enc_timestamp);
    let mac1 = blake2s_mac16(&mac1_key(peer_pub), &msg);
    msg.extend_from_slice(&mac1);
    msg.extend_from_slice(&[0u8; 16]); // MAC2: no cookie yet
    debug_assert_eq!(msg.len(), MSG_INITIATION_LEN);
    Ok((
        msg,
        PendingHandshake {
            local_index,
            e_priv,
            chaining_key: ck,
            hash: h,
            attempts: 1,
        },
    ))
}

/// The established session (wireguard.rs:754-833, 887-969).
struct Session {
    peer_index: u32,
    created: Instant,
    last_tx: Instant,
    send: (ChaCha20Poly1305, u64),
    recv: (ChaCha20Poly1305, u64, crate::proto::wireguard::AntiReplay),
}

/// Consume the 92-byte response (wireguard.rs:766-833, whitepaper
/// "Second Message") and derive the transport keys.
fn consume_response(
    static_priv: &[u8; 32],
    pending: &PendingHandshake,
    sender: u32,
    receiver: u32,
    ephemeral: &[u8; 32],
    enc_nothing: &[u8; 16],
    mac1: &[u8; 16],
) -> Result<Session> {
    if receiver != pending.local_index {
        return Err(Error::protocol("wg: response for a stale handshake"));
    }
    // MAC1 is keyed by the responder's view of our static — it learned
    // it from the initiation (wireguard.rs:785-794).
    let static_pub = x25519_pub(static_priv);
    let mut raw = Vec::with_capacity(MSG_RESPONSE_LEN);
    raw.extend_from_slice(&MSG_TYPE_RESPONSE.to_le_bytes());
    raw.extend_from_slice(&sender.to_le_bytes());
    raw.extend_from_slice(&receiver.to_le_bytes());
    raw.extend_from_slice(ephemeral);
    raw.extend_from_slice(enc_nothing);
    if blake2s_mac16(&mac1_key(&static_pub), &raw) != *mac1 {
        return Err(Error::crypto("wg: handshake response MAC1 mismatch"));
    }

    let mut h = pending.hash;
    let mut ck = pending.chaining_key;
    h = hash2(&h, ephemeral);
    ck = kdf1(&ck, ephemeral);
    let ee = x25519_dh(&pending.e_priv, ephemeral)?;
    ck = kdf1(&ck, &ee);
    let se = x25519_dh(static_priv, ephemeral)?;
    ck = kdf1(&ck, &se);
    // psk2 with a zero psk (tailscale does not use WireGuard PSKs).
    let (ck, temp2, key) = kdf3(&ck, &[0u8; 32]);
    h = hash2(&h, &temp2);
    aead_open(&key, 0, enc_nothing, &h)?;
    let (send_key, recv_key) = derive_transport_keys(&ck);

    let now = Instant::now();
    Ok(Session {
        peer_index: sender,
        created: now,
        last_tx: now,
        send: (ChaCha20Poly1305::new_from_slice(&send_key).expect("32-byte key"), 0),
        recv: (
            ChaCha20Poly1305::new_from_slice(&recv_key).expect("32-byte key"),
            0,
            crate::proto::wireguard::AntiReplay::new(),
        ),
    })
}

impl Session {
    /// Seal one inner IP packet (wireguard.rs:913-942 seal_transport).
    fn seal(&mut self, inner: &[u8]) -> Result<Vec<u8>> {
        if self.send.1 >= REJECT_AFTER_MESSAGES {
            return Err(Error::protocol("wg: session counter exhausted"));
        }
        let counter = self.send.1;
        self.send.1 += 1;
        let mut plain = inner.to_vec();
        while !plain.len().is_multiple_of(PADDING_MULTIPLE) {
            plain.push(0);
        }
        let ct = self
            .send
            .0
            .encrypt(
                (&aead_nonce(counter)).into(),
                Payload {
                    msg: &plain,
                    aad: &[],
                },
            )
            .map_err(|_| Error::crypto("wg: transport seal failed"))?;
        let mut msg = Vec::with_capacity(TRANSPORT_HEADER_LEN + ct.len());
        msg.extend_from_slice(&MSG_TYPE_TRANSPORT.to_le_bytes());
        msg.extend_from_slice(&self.peer_index.to_le_bytes());
        msg.extend_from_slice(&counter.to_le_bytes());
        msg.extend_from_slice(&ct);
        self.last_tx = Instant::now();
        Ok(msg)
    }

    /// Open a transport payload, tag first then the replay window
    /// (wireguard.rs:944-962).
    fn open(&mut self, counter: u64, data: &[u8]) -> Result<Vec<u8>> {
        let plain = self
            .recv
            .0
            .decrypt(
                (&aead_nonce(counter)).into(),
                Payload { msg: data, aad: &[] },
            )
            .map_err(|_| Error::crypto("wg: transport open failed"))?;
        if !self.recv.2.accept(counter) {
            return Err(Error::protocol("wg: replayed or too-old transport counter"));
        }
        Ok(plain)
    }
}

/// Trim AEAD padding off a decrypted packet by the IP total-length
/// field (wireguard.rs:971-982 handles v4; v6's payload length lives at
/// offset 4).
fn trim_ip_packet(pkt: &mut Vec<u8>) {
    if pkt.len() >= 20 && pkt[0] >> 4 == 4 {
        let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if total >= 20 && total <= pkt.len() {
            pkt.truncate(total);
        }
    } else if pkt.len() >= 40 && pkt[0] >> 4 == 6 {
        let total = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
        if total >= 40 && total <= pkt.len() {
            pkt.truncate(total);
        }
    }
}

// ---------------------------------------------------------------------------
// Carriers: direct UDP and DERP relay (magicsock's two paths)
// ---------------------------------------------------------------------------

/// The DERP leg of a peer: its home relay URL and its node key
/// (`PeerStatus.DERP` + the DERPMap's region, resolved by the caller).
#[derive(Debug, Clone)]
pub struct DerpRoute {
    /// `http(s)://host[:port]` of the peer's home DERP node.
    pub url: String,
    /// The peer's node key — DERP frames are addressed by it.
    pub peer_key: [u8; 32],
}

/// Events out of the DERP carrier task.
enum DerpEvent {
    Packet(Vec<u8>),
    Closed,
}

/// A running DERP relay leg: one background task owns the wave-10
/// [`super::derp::DerpClient`] (registered with OUR node key) and
/// relays frames addressed to `route.peer_key`.
struct DerpCarrier {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<DerpEvent>,
}

impl DerpCarrier {
    async fn spawn(route: &DerpRoute, our_node_key: &super::derp::NodePrivateKey) -> Result<Self> {
        let opts = super::derp::DerpHttpOptions {
            app_name: "rustcrash".into(),
            ..Default::default()
        };
        let mut client =
            super::derp::derp_connect(&route.url, our_node_key, &opts).await?;
        // First message is always ServerInfo (derp_client.go:447-462).
        match client.recv().await? {
            super::derp::DerpMessage::ServerInfo(_) => {}
            other => {
                return Err(Error::protocol(format!(
                    "derp: unexpected first message: {other:?}"
                )))
            }
        }
        let (pkt_tx, mut pkt_rx) = mpsc::channel::<Vec<u8>>(256);
        let (evt_tx, evt_rx) = mpsc::channel::<DerpEvent>(256);
        let dst = super::derp::NodePublicKey::from_bytes(route.peer_key);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    pkt = pkt_rx.recv() => {
                        match pkt {
                            Some(p) => {
                                if client.send(&dst, &p).await.is_err() {
                                    let _ = evt_tx.send(DerpEvent::Closed).await;
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    msg = client.recv() => {
                        match msg {
                            Ok(super::derp::DerpMessage::ReceivedPacket { data, .. }) => {
                                if evt_tx.send(DerpEvent::Packet(data)).await.is_err() {
                                    break;
                                }
                            }
                            Ok(_) => {}
                            Err(_) => {
                                let _ = evt_tx.send(DerpEvent::Closed).await;
                                break;
                            }
                        }
                    }
                }
            }
        });
        Ok(DerpCarrier {
            tx: pkt_tx,
            rx: evt_rx,
        })
    }
}

// ---------------------------------------------------------------------------
// Configuration + public API
// ---------------------------------------------------------------------------

/// Everything the tunnel task needs — derived by `super` from the
/// netmap (self node key + addresses, the routed peer's key, its UDP
/// endpoint if it advertises one, and its home DERP relay).
#[derive(Debug, Clone)]
pub struct TsTunnelConfig {
    /// Our node private key (raw 32 bytes).
    pub private_key: [u8; 32],
    /// The routed peer's node public key.
    pub peer_public: [u8; 32],
    /// Our tailnet IPv4 (`Node.Addresses` v4).
    pub local_ipv4: Ipv4Addr,
    /// Our tailnet IPv6, when assigned.
    pub local_ipv6: Option<Ipv6Addr>,
    /// Inner MTU; 0 = tailscale's default 1280.
    pub mtu: u16,
    /// The peer's direct UDP endpoint, when it advertises one.
    pub endpoint: Option<SocketAddr>,
    /// The peer's home DERP relay.
    pub derp: Option<DerpRoute>,
}

impl TsTunnelConfig {
    fn mtu(&self) -> usize {
        if self.mtu == 0 {
            1280
        } else {
            self.mtu.clamp(576, 65535) as usize
        }
    }
}

enum TsCmd {
    Connect {
        remote: SocketAddr,
        reply: oneshot::Sender<Result<Arc<StreamShared>>>,
    },
}

/// A live overlay tunnel: one background task owning the WireGuard
/// session, the carriers and the smoltcp netstack.
#[derive(Clone)]
pub struct TsTunnel {
    cmd: mpsc::Sender<TsCmd>,
}

impl TsTunnel {
    /// Bring the tunnel up: bind the UDP socket when a direct endpoint
    /// is configured, register with the peer's home DERP when routed
    /// via relay, then run the handshake + netstack task. The first
    /// handshake happens lazily on the first dial (like wireguard.rs's
    /// pre-session queue) so an unused tunnel costs nothing.
    pub async fn spawn(cfg: TsTunnelConfig) -> Result<Self> {
        if cfg.endpoint.is_none() && cfg.derp.is_none() {
            return Err(Error::config(
                "tailscale tunnel: peer has neither a UDP endpoint nor a home DERP",
            ));
        }
        let node_key = super::derp::NodePrivateKey::from_bytes(cfg.private_key);

        let udp = match cfg.endpoint {
            Some(ep) => {
                let bind = if ep.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                Some((Arc::new(UdpSocket::bind(bind).await?), ep))
            }
            None => None,
        };
        let derp = match &cfg.derp {
            Some(route) => Some(DerpCarrier::spawn(route, &node_key).await?),
            None => None,
        };

        let (tx, rx) = mpsc::channel::<TsCmd>(64);
        let wake = Arc::new(Notify::new());
        let stack = Tunnel::new(cfg, udp, derp, wake.clone())?;
        tokio::spawn(run_tunnel(stack, rx, wake));
        Ok(TsTunnel { cmd: tx })
    }

    /// Dial a TCP connection through the overlay to `target` (an IP the
    /// netmap routes to this tunnel's peer).
    pub async fn connect_tcp(&self, target: SocketAddr) -> Result<TsTcpStream> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd
            .send(TsCmd::Connect {
                remote: target,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::network("tailscale: tunnel task is gone"))?;
        let shared = tokio::time::timeout(TCP_CONNECT_TIMEOUT, reply_rx)
            .await
            .map_err(|_| Error::network("tailscale: tcp dial timed out"))?
            .map_err(|_| Error::network("tailscale: tunnel task dropped the dial"))??;
        Ok(TsTcpStream { shared })
    }
}

/// One TCP connection through the overlay, as the relay sees it — the
/// two-queue/one-mutex/two-waker shape of wireguard.rs's `WgStream`
/// (1006-1141).
pub struct TsTcpStream {
    shared: Arc<StreamShared>,
}

impl Drop for TsTcpStream {
    fn drop(&mut self) {
        let mut g = self.shared.lock();
        g.aborted = true;
        g.read_eof = true;
        g.write_closed = true;
        drop(g);
        self.shared.wake.notify_one();
    }
}

impl tokio::io::AsyncRead for TsTcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut g = self.shared.lock();
        if !g.to_proxy.is_empty() {
            let n = g.to_proxy.len().min(buf.remaining());
            let (front, back) = g.to_proxy.as_slices();
            let take_front = n.min(front.len());
            buf.put_slice(&front[..take_front]);
            if take_front < n {
                buf.put_slice(&back[..n - take_front]);
            }
            g.to_proxy.drain(..n);
            return Poll::Ready(Ok(()));
        }
        if g.read_eof {
            return Poll::Ready(Ok(()));
        }
        g.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl tokio::io::AsyncWrite for TsTcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut g = self.shared.lock();
        if g.aborted || g.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tailscale: stream is closed",
            )));
        }
        let space = STREAM_QUEUE_MAX.saturating_sub(g.to_stack.len());
        if space == 0 {
            g.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = space.min(buf.len());
        g.to_stack.extend(buf[..n].iter().copied());
        drop(g);
        self.shared.wake.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.lock().write_closed = true;
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

const STREAM_QUEUE_MAX: usize = 128 * 1024;
const TCP_RX_BYTES: usize = 64 * 1024;
const TCP_TX_BYTES: usize = 64 * 1024;
const MAX_CONNS: usize = 128;
const MIN_TICK: Duration = Duration::from_millis(1);
const MAX_TICK: Duration = Duration::from_secs(1);

#[derive(Default)]
struct StreamBufs {
    to_proxy: VecDeque<u8>,
    to_stack: VecDeque<u8>,
    read_eof: bool,
    write_closed: bool,
    aborted: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

struct StreamShared {
    bufs: Mutex<StreamBufs>,
    wake: Arc<Notify>,
}

impl StreamShared {
    fn new(wake: Arc<Notify>) -> Self {
        StreamShared {
            bufs: Mutex::new(StreamBufs::default()),
            wake,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, StreamBufs> {
        self.bufs.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// ---------------------------------------------------------------------------
// The smoltcp device shim (wireguard.rs:1143-1231)
// ---------------------------------------------------------------------------

struct Shim {
    ingress: VecDeque<Vec<u8>>,
    egress: VecDeque<Vec<u8>>,
    scratch: Vec<u8>,
    mtu: usize,
}

impl Shim {
    fn new(mtu: usize) -> Self {
        Shim {
            ingress: VecDeque::new(),
            egress: VecDeque::new(),
            scratch: Vec::new(),
            mtu,
        }
    }

    fn stage(&mut self, pkt: &[u8]) {
        if self.ingress.len() < 512 {
            self.ingress.push_back(pkt.to_vec());
        }
    }
}

impl Device for Shim {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(RxTok, TxTok<'_>)> {
        let pkt = self.ingress.pop_front()?;
        Some((
            RxTok { pkt },
            TxTok {
                egress: &mut self.egress,
                scratch: &mut self.scratch,
            },
        ))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<TxTok<'_>> {
        Some(TxTok {
            egress: &mut self.egress,
            scratch: &mut self.scratch,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct RxTok {
    pkt: Vec<u8>,
}

impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.pkt)
    }
}

struct TxTok<'a> {
    egress: &'a mut VecDeque<Vec<u8>>,
    scratch: &'a mut Vec<u8>,
}

impl TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        self.scratch.clear();
        self.scratch.resize(len, 0);
        let out = {
            let buf = &mut self.scratch[..len];
            f(buf)
        };
        self.egress.push_back(self.scratch[..len].to_vec());
        out
    }
}

// ---------------------------------------------------------------------------
// The tunnel task
// ---------------------------------------------------------------------------

struct Conn {
    handle: SocketHandle,
    shared: Arc<StreamShared>,
    fin_sent: bool,
    pending: Option<(oneshot::Sender<Result<Arc<StreamShared>>>, Instant)>,
}

struct Tunnel {
    iface: Interface,
    sockets: SocketSet<'static>,
    shim: Shim,
    private_key: [u8; 32],
    peer_pub: [u8; 32],
    local_ipv4: Ipv4Addr,
    local_ipv6: Option<Ipv6Addr>,
    udp: Option<(Arc<UdpSocket>, SocketAddr)>,
    derp: Option<DerpCarrier>,
    pending_hs: Option<PendingHandshake>,
    hs_retry_at: Option<Instant>,
    session: Option<Session>,
    local_index: u32,
    conns: Vec<Conn>,
    pre_session_tx: VecDeque<Vec<u8>>,
    wake: Arc<Notify>,
    start: Instant,
    /// Which carrier answered — set on the first authenticated packet
    /// (magicsock's learned path, first-response-wins).
    learned_derp: bool,
    pump: Vec<u8>,
}

impl Tunnel {
    fn new(
        cfg: TsTunnelConfig,
        udp: Option<(Arc<UdpSocket>, SocketAddr)>,
        derp: Option<DerpCarrier>,
        wake: Arc<Notify>,
    ) -> Result<Self> {
        let mtu = cfg.mtu();
        let mut shim = Shim::new(mtu);
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = rand::random();
        let mut iface = Interface::new(iface_cfg, &mut shim, SmolInstant::ZERO);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(cfg.local_ipv4), 32));
            if let Some(v6) = cfg.local_ipv6 {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(v6), 128));
            }
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(cfg.local_ipv4)
            .map_err(|_| Error::network("tailscale: route table full"))?;
        if let Some(v6) = cfg.local_ipv6 {
            iface
                .routes_mut()
                .add_default_ipv6_route(v6)
                .map_err(|_| Error::network("tailscale: route table full"))?;
        }
        Ok(Tunnel {
            iface,
            sockets: SocketSet::new(Vec::new()),
            shim,
            private_key: cfg.private_key,
            peer_pub: cfg.peer_public,
            local_ipv4: cfg.local_ipv4,
            local_ipv6: cfg.local_ipv6,
            udp,
            derp,
            pending_hs: None,
            hs_retry_at: None,
            session: None,
            local_index: rand::random(),
            conns: Vec::new(),
            pre_session_tx: VecDeque::new(),
            wake,
            start: Instant::now(),
            learned_derp: false,
            pump: vec![0u8; 32 * 1024],
        })
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
    }

    /// One pass: poll the stack, pump TCP conns, drain egress.
    fn step(&mut self) -> Vec<Vec<u8>> {
        let now = self.now();
        self.iface.poll(now, &mut self.shim, &mut self.sockets);
        self.pump_conns();
        self.shim.egress.drain(..).collect()
    }

    fn pump_conns(&mut self) {
        let mut dead: Vec<SocketHandle> = Vec::new();
        for c in self.conns.iter_mut() {
            let sock = self.sockets.get_mut::<tcp::Socket>(c.handle);
            if let Some((reply, deadline)) = c.pending.take() {
                let timed_out = deadline.elapsed() >= TCP_CONNECT_TIMEOUT;
                match sock.state() {
                    tcp::State::Established => {
                        let _ = reply.send(Ok(c.shared.clone()));
                    }
                    s if s == tcp::State::Closed || timed_out => {
                        let _ = reply.send(Err(Error::network(format!(
                            "tailscale: tcp dial failed (state {s:?})"
                        ))));
                        sock.abort();
                        dead.push(c.handle);
                        continue;
                    }
                    _ => {
                        c.pending = Some((reply, deadline));
                    }
                }
            }

            let mut g = c.shared.lock();
            while g.to_proxy.len() < STREAM_QUEUE_MAX && sock.can_recv() {
                let n = match sock.recv_slice(&mut self.pump) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                g.to_proxy.extend(self.pump[..n].iter().copied());
            }
            let dialing = matches!(sock.state(), tcp::State::SynSent | tcp::State::Listen);
            if !dialing && !sock.may_recv() && sock.recv_queue() == 0 {
                g.read_eof = true;
            }
            while !g.to_stack.is_empty() && sock.can_send() {
                let n = match sock.send_slice(g.to_stack.make_contiguous()) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                g.to_stack.drain(..n);
            }
            if g.write_closed && g.to_stack.is_empty() && !c.fin_sent {
                sock.close();
                c.fin_sent = true;
            }
            if g.aborted {
                sock.abort();
            }
            let gone = sock.state() == tcp::State::Closed;
            if gone {
                g.read_eof = true;
            }
            if (!g.to_proxy.is_empty() || g.read_eof) && g.read_waker.is_some() {
                if let Some(w) = g.read_waker.take() {
                    w.wake();
                }
            }
            if (gone || g.to_stack.len() < STREAM_QUEUE_MAX) && g.write_waker.is_some() {
                if let Some(w) = g.write_waker.take() {
                    w.wake();
                }
            }
        }
        if !dead.is_empty() {
            self.conns.retain(|c| !dead.contains(&c.handle));
            for h in dead {
                self.sockets.remove(h);
            }
        }
    }

    /// Send one WireGuard datagram on the active path(s): the learned
    /// carrier when a session exists, every carrier while handshaking
    /// (magicsock's parallel probing, simplified — see module deltas).
    async fn send_wg(&mut self, msg: &[u8]) -> Result<()> {
        let via_derp_only = self.learned_derp || self.udp.is_none();
        if let Some((sock, ep)) = &self.udp {
            if !via_derp_only {
                sock.send_to(msg, ep)
                    .await
                    .map_err(|e| Error::network(format!("tailscale: udp send: {e}")))?;
            }
        }
        if let Some(derp) = &mut self.derp {
            if via_derp_only || self.session.is_none() {
                derp.tx
                    .send(msg.to_vec())
                    .await
                    .map_err(|_| Error::network("tailscale: derp carrier is gone"))?;
            }
        }
        Ok(())
    }

    /// Encrypt an inner IP packet (queueing pre-handshake).
    async fn send_inner(&mut self, pkt: &[u8]) -> Result<()> {
        if let Some(session) = self.session.as_mut() {
            let msg = session.seal(pkt)?;
            self.send_wg(&msg).await
        } else {
            if self.pre_session_tx.len() >= 512 {
                return Ok(()); // drop, like wireguard.rs's bound
            }
            self.pre_session_tx.push_back(pkt.to_vec());
            self.initiate().await
        }
    }

    /// Start or retransmit the handshake (wireguard.rs::Stack::initiate,
    /// 1407-1450).
    async fn initiate(&mut self) -> Result<()> {
        if let Some(p) = &mut self.pending_hs {
            if p.attempts >= MAX_HANDSHAKE_ATTEMPTS {
                return Ok(());
            }
            p.attempts += 1;
        }
        let (msg, pending) = build_initiation(&self.private_key, &self.peer_pub, self.local_index)?;
        self.pending_hs = Some(pending);
        self.hs_retry_at = Some(Instant::now() + REKEY_TIMEOUT);
        self.send_wg(&msg).await
    }

    /// Handle one inbound WireGuard datagram.
    async fn on_datagram(&mut self, from_derp: bool, data: &[u8]) {
        let Some(msg) = crate::proto::wireguard::parse_wg_msg(data) else {
            return;
        };
        use crate::proto::wireguard::WgMsg;
        match msg {
            WgMsg::Response {
                sender,
                receiver,
                ephemeral,
                enc_nothing,
                mac1,
                ..
            } => {
                let Some(pending) = self.pending_hs.take() else {
                    return;
                };
                match consume_response(
                    &self.private_key,
                    &pending,
                    sender,
                    receiver,
                    &ephemeral,
                    &enc_nothing,
                    &mac1,
                ) {
                    Ok(session) => {
                        self.learned_derp = from_derp;
                        self.session = Some(session);
                        self.hs_retry_at = None;
                        let backlog: Vec<Vec<u8>> = self.pre_session_tx.drain(..).collect();
                        for pkt in backlog {
                            if let Err(e) = self.send_inner(&pkt).await {
                                tracing::debug!(target: "engine", "tailscale: backlog send: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        self.pending_hs = Some(pending);
                        tracing::debug!(target: "engine", "tailscale: response rejected: {e}");
                    }
                }
            }
            WgMsg::Transport {
                receiver: _,
                counter,
                data,
            } => {
                let Some(session) = self.session.as_mut() else {
                    return;
                };
                match session.open(counter, &data) {
                    Ok(mut pkt) => {
                        trim_ip_packet(&mut pkt);
                        if !pkt.is_empty() {
                            self.shim.stage(&pkt);
                        }
                    }
                    Err(_) => {
                        tracing::debug!(target: "engine", "tailscale: bad transport packet");
                    }
                }
            }
            WgMsg::Cookie { .. } => {
                // Cookie-under-load retry is not ported (module deltas);
                // drop and let REKEY_TIMEOUT retry the handshake.
            }
            WgMsg::Initiation { .. } => {
                // This port is initiator-only (the client side of an
                // outbound); inbound peers are not supported this wave.
            }
        }
    }

    /// Timer pass (wireguard.rs::Stack::on_timer, 1803-1843).
    async fn on_timer(&mut self) -> Result<()> {
        let now = Instant::now();
        enum Action {
            Expire,
            Rekey,
            Keepalive,
        }
        let action = match self.session.as_ref() {
            Some(s) if now.duration_since(s.created) >= REJECT_AFTER_TIME => Some(Action::Expire),
            Some(s)
                if now.duration_since(s.created) >= REKEY_AFTER_TIME
                    || s.send.1 >= (1 << 60) =>
            {
                Some(Action::Rekey)
            }
            Some(s) if now.duration_since(s.last_tx) >= KEEPALIVE_TIMEOUT => Some(Action::Keepalive),
            _ => None,
        };
        match action {
            Some(Action::Expire) => {
                self.session = None;
                self.learned_derp = false;
            }
            Some(Action::Rekey) => self.initiate().await?,
            Some(Action::Keepalive) => {
                let msg = self.session.as_mut().and_then(|s| s.seal(&[]).ok());
                if let Some(msg) = msg {
                    self.send_wg(&msg).await?;
                }
            }
            None => {}
        }
        if let Some(at) = self.hs_retry_at {
            if now >= at {
                self.hs_retry_at = None;
                self.initiate().await?;
            }
        }
        Ok(())
    }

    fn on_cmd(&mut self, cmd: TsCmd) {
        match cmd {
            TsCmd::Connect { remote, reply } => {
                if self.conns.len() >= MAX_CONNS {
                    let _ = reply.send(Err(Error::network("tailscale: too many conns")));
                    return;
                }
                let mut sock = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; TCP_RX_BYTES]),
                    tcp::SocketBuffer::new(vec![0; TCP_TX_BYTES]),
                );
                let local = smoltcp::wire::IpListenEndpoint {
                    addr: Some(match remote {
                        SocketAddr::V4(_) => IpAddress::Ipv4(self.local_ipv4),
                        SocketAddr::V6(_) => {
                            IpAddress::Ipv6(self.local_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED))
                        }
                    }),
                    // smoltcp refuses local port 0 (ConnectError::Unaddressable);
                    // pick an ephemeral port like wireguard.rs:1374-1381.
                    port: 32768 + rand::random::<u16>() % 28_000,
                };
                let remote_ep = match remote {
                    SocketAddr::V4(v4) => IpEndpoint::new(IpAddress::Ipv4(*v4.ip()), v4.port()),
                    SocketAddr::V6(v6) => IpEndpoint::new(IpAddress::Ipv6(*v6.ip()), v6.port()),
                };
                let cx = self.iface.context();
                if sock.connect(cx, remote_ep, local).is_err() {
                    let _ = reply.send(Err(Error::network("tailscale: connect refused")));
                    return;
                }
                let handle = self.sockets.add(sock);
                let shared = Arc::new(StreamShared::new(self.wake.clone()));
                self.conns.push(Conn {
                    handle,
                    shared: shared.clone(),
                    fin_sent: false,
                    pending: Some((reply, Instant::now())),
                });
                // The SYN rides the next step; wake the loop.
                self.wake.notify_one();
            }
        }
    }

    fn next_deadline(&mut self) -> Instant {
        let now = Instant::now();
        let poll = self
            .iface
            .poll_delay(self.now(), &self.sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(MAX_TICK)
            .max(MIN_TICK);
        let mut until = now + poll;
        if let Some(at) = self.hs_retry_at {
            until = until.min(at);
        }
        if let Some(s) = &self.session {
            until = until.min(s.created + REJECT_AFTER_TIME);
        }
        for c in &self.conns {
            if let Some((_, deadline)) = &c.pending {
                until = until.min(*deadline);
            }
        }
        until
    }
}

/// Drive the tunnel until the last handle drops
/// (wireguard.rs::run_stack, 1897-1948).
async fn run_tunnel(mut t: Tunnel, mut cmd_rx: mpsc::Receiver<TsCmd>, wake: Arc<Notify>) {
    let mut udp_buf = vec![0u8; 65_536];
    loop {
        let pkts = t.step();
        for pkt in pkts {
            if let Err(e) = t.send_inner(&pkt).await {
                tracing::debug!(target: "engine", "tailscale: send: {e}");
            }
        }

        let deadline = t.next_deadline();
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        let has_udp = t.udp.is_some();
        let has_derp = t.derp.is_some();
        tokio::select! {
            biased;
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(c) => t.on_cmd(c),
                    None => break,
                }
            }
            _ = wake.notified() => {}
            r = async {
                if has_udp {
                    let (sock, _) = t.udp.as_ref().expect("has_udp checked");
                    sock.recv_from(&mut udp_buf).await
                } else {
                    std::future::pending::<std::io::Result<(usize, SocketAddr)>>().await
                }
            } => {
                if let Ok((n, _)) = r {
                    t.on_datagram(false, &udp_buf[..n]).await;
                }
            }
            evt = async {
                if has_derp {
                    t.derp.as_mut().expect("has_derp checked").rx.recv().await
                } else {
                    std::future::pending::<Option<DerpEvent>>().await
                }
            } => {
                match evt {
                    Some(DerpEvent::Packet(pkt)) => t.on_datagram(true, &pkt).await,
                    _ => t.derp = None,
                }
            }
            _ = sleep => {
                if let Err(e) = t.on_timer().await {
                    tracing::debug!(target: "engine", "tailscale: timer: {e}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiation_shape_matches_the_whitepaper() {
        // 148 bytes: type(4) + sender(4) + ephemeral(32) + enc_static(48)
        // + enc_timestamp(28) + mac1(16) + mac2(16).
        let sk = [7u8; 32];
        let peer = x25519_pub(&[9u8; 32]);
        let (msg, pending) = build_initiation(&sk, &peer, 0x0102_0304).unwrap();
        assert_eq!(msg.len(), MSG_INITIATION_LEN);
        assert_eq!(&msg[..4], &1u32.to_le_bytes());
        assert_eq!(&msg[4..8], &0x0102_0304u32.to_le_bytes());
        assert_eq!(pending.local_index, 0x0102_0304);
        // MAC1 verifies against the responder-static-keyed hash.
        let expect = blake2s_mac16(&mac1_key(&peer), &msg[..116]);
        assert_eq!(&msg[116..132], &expect);
        assert_eq!(&msg[132..148], &[0u8; 16], "MAC2 zero without a cookie");
    }

    #[test]
    fn transport_padding_and_trim_round_trip() {
        // Padding to a 16-byte multiple (wireguard.rs:919-921) and the
        // IPv4/IPv6 total-length trim on the receive side. The v4 header
        // is well-formed: 20 bytes, total length 20+7.
        let total = 20 + 7;
        let mut pkt = vec![0x45u8, 0, 0, total as u8, 0, 0, 0, 0, 64, 6, 0, 0];
        pkt.extend(std::iter::repeat_n(0u8, 8)); // header bytes 12..20
        pkt.extend(std::iter::repeat_n(7u8, 7)); // 7 payload bytes
        assert_eq!(pkt.len(), total);
        let mut padded = pkt.clone();
        while padded.len() % PADDING_MULTIPLE != 0 {
            padded.push(0);
        }
        let mut got = padded.clone();
        trim_ip_packet(&mut got);
        assert_eq!(got, pkt, "the total-length field trims the padding");

        // v6: payload length at offset 4.
        let mut v6 = vec![0x60u8, 0, 0, 0, 0, 32, 6, 64];
        v6.extend(std::iter::repeat_n(0u8, 40 + 32));
        let mut padded6 = v6.clone();
        while padded6.len() % PADDING_MULTIPLE != 0 {
            padded6.push(0);
        }
        let mut got6 = padded6;
        trim_ip_packet(&mut got6);
        assert_eq!(got6, v6);
    }

    // The full data-plane proofs (direct UDP + DERP relay against the
    // engine's own WireGuard endpoint) live in `super`'s tests, where
    // the netmap-derived config is what gets exercised end to end.
}
