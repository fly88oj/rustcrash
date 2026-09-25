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
//! # Disco (wave 13)
//!
//! When the netmap gives the peer a disco key (`Node.DiscoKey` — every
//! modern tailscale peer has one), the tunnel speaks the disco overlay
//! over the same carriers before/alongside the WireGuard handshake: it
//! sends a disco Ping with each handshake attempt, and the peer's Pong
//! for a ping WE sent confirms the direct path ([`super::disco`] is the
//! codec; the flow is magicsock's `sendDiscoMessage` /
//! `handleDiscoMessage` / `handlePongConnLocked`, cached at
//! `/tmp/wave13-upstream/ms_*.go`). A CallMeMaybe received via DERP
//! adds the peer's advertised endpoints as candidates and pings them
//! ("the peer has already punched its firewall", endpoint.go:2134-2218)
//! — the direct path the peer requested. Carrier selection is then
//! disco-informed: a pong-confirmed address is trusted for
//! `trustUDPAddrDuration` (6.5s, magicsock.go:4012-4014) and carries
//! the traffic exclusively (upstream `addrForSendLocked` returns the
//! bestAddr alone while trusted, endpoint.go:632-649); a peer that
//! never ponged falls back to the DERP relay (the wave-11 behavior,
//! preserved exactly).
//!
//! The port of magicsock's disco loop is deliberately the bounded core;
//! what is simplified vs upstream (magicsock.go / endpoint.go unless
//! cited):
//!
//! * No heartbeat: upstream re-pings the best address every 3s
//!   (`heartbeatInterval`) to keep NAT mappings alive; this port pings
//!   only while a handshake is being (re)tried (one round per
//!   REKEY_TIMEOUT attempt) — a proxy re-handshakes on demand rather
//!   than holding idle paths open.
//! * One confirmed path, first pong wins: upstream ranks endpoints by
//!   pong latency with IPv6/private-IP bonuses (`betterAddr`,
//!   endpoint.go:2046-2132) and keeps per-endpoint pong history; this
//!   port keeps a single confirmed address per tunnel.
//! * No MTU probing (pings carry no padding), no pingCLI, no
//!   UDP-lifetime probes, no UDP-relay (Geneve/udprelay) messages, and
//!   none of magicsock's path debugging (lan-assertion/breakTCP).
//! * No disco pings over DERP: upstream's CLI ping can ride DERP; this
//!   port pings only direct candidates, so a DERP-only peer stays on
//!   DERP until IT sends a CallMeMaybe (which matches how upstream
//!   peers open direct paths — the peer that received traffic via DERP
//!   is the one that discovers the return path).
//! * Pings received via DERP are dropped instead of ponged back (this
//!   port is the initiator side of an outbound; the responder half of
//!   disco belongs to a server-side port). Pings received over UDP ARE
//!   ponged (handlePingLocked's reply, magicsock.go:2603-2608).
//! * The peer map is the tunnel itself: upstream's peerMap /
//!   `unambiguousNodeKeyOfPingLocked` (magicsock.go:2478-2508) resolve
//!   a disco key to node keys across a whole netmap; a tunnel here is
//!   bound to exactly one peer, so the sender-key check suffices.
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
//! TCP dials become [`TsTcpStream`]; UDP through the overlay becomes
//! [`TsUdp`] (the same channel-per-socket shape as wireguard.rs's
//! `WgUdp`, routed per destination by the overlay — see `super`).
//!
//! # Deltas vs upstream
//!
//! * Disco is the bounded core above; peers marked `IsWireGuardOnly`
//!   (and the engine's own endpoint, which carries no disco key) skip
//!   it entirely and interoperate as before.
//! * No cookie retry: a responder under initiation load replies with a
//!   cookie request which this port drops (wireguard.rs:834-869 has the
//!   consume half; tests never trip the 64/s load threshold). MAC1 is
//!   always computed and MAC2 left zero, the unloaded-responder shape.
//! * Path learning is first-response-wins except where disco confirms a
//!   path: handshakes go out on every configured carrier; the carrier
//!   that answers carries the session unless a Pong later proves a
//!   direct path (magicsock maintains full endpoint state instead).
//! * Rekey timers mirror wireguard-go (REKEY_AFTER_TIME 120s,
//!   REJECT_AFTER_TIME 180s, REKEY_TIMEOUT 5s, KEEPALIVE 10s — the
//!   constants cross-checked in `proto/wireguard.rs:180-207`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
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
use smoltcp::socket::udp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};

use crate::addr::NetAddr;
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

// Disco timing constants (magicsock.go:4010-4036, values from
// /tmp/wave13-upstream/tsconst_ping.go):
/// `pingTimeoutDuration = tsconst.DefaultPingTimeout` (5s): how long a
/// sent ping waits for its pong before it is forgotten.
const DISCO_PING_TIMEOUT: Duration = Duration::from_secs(5);
/// `discoPingInterval = tsconst.DefaultPingInterval` (5s): the minimum
/// time between pings to one endpoint.
const DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);
/// `trustUDPAddrDuration` (6.5s, magicsock.go:4012-4014): how long a
/// pong-confirmed UDP address is trusted as the exclusive path.
const TRUST_UDP_ADDR_DURATION: Duration = Duration::from_millis(6500);

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
// The disco endpoint state (magicsock's per-peer disco bookkeeping,
// bounded — see the module docs' simplification list)
// ---------------------------------------------------------------------------

/// A ping we sent and are waiting on (`endpoint.sentPing`,
/// endpoint.go:1398-1405): where it went and when, so the Pong's TxID
/// resolves to the path it proves.
struct SentPing {
    to: SocketAddr,
    at: Instant,
}

/// The per-tunnel disco state: our key, the peer's key, the pings in
/// flight, and the pong-confirmed path (upstream's `bestAddr` +
/// `trustBestAddrUntil`, endpoint.go:138-206).
struct DiscoState {
    our: super::disco::DiscoPrivateKey,
    peer: super::disco::DiscoPublicKey,
    /// Our node public, carried in Ping.NodeKey (sendDiscoPing,
    /// endpoint.go:1307).
    node_pub: [u8; 32],
    /// Pings awaiting their Pong, by TxID.
    sent: HashMap<[u8; 12], SentPing>,
    /// The pong-confirmed direct address and the instant its trust
    /// expires (None/elapsed = untrusted).
    confirmed: Option<(SocketAddr, Instant)>,
    /// Endpoints a CallMeMaybe supplied (in addition to the netmap's).
    call_me_numbers: Vec<SocketAddr>,
    /// Per-endpoint ping rate limit (discoPingInterval).
    last_ping: HashMap<SocketAddr, Instant>,
}

impl DiscoState {
    /// The trusted direct address, if a Pong confirmed one and its
    /// trust window (`trustUDPAddrDuration`) has not lapsed.
    fn trusted_direct(&self) -> Option<SocketAddr> {
        let (addr, until) = self.confirmed?;
        (Instant::now() < until).then_some(addr)
    }

    /// Forget pings whose pong can no longer arrive
    /// (`discoPingTimeout`, endpoint.go:1236-1252).
    fn expire_sent(&mut self) {
        let now = Instant::now();
        self.sent.retain(|_, sp| now.duration_since(sp.at) < DISCO_PING_TIMEOUT);
    }

    /// Every direct candidate to ping: the configured/learned endpoint
    /// plus the CallMeMaybe numbers (deduplicated, family order kept).
    fn candidates(&self, configured: Option<SocketAddr>) -> Vec<SocketAddr> {
        let mut out = Vec::with_capacity(1 + self.call_me_numbers.len());
        if let Some(ep) = configured {
            out.push(ep);
        }
        for ep in &self.call_me_numbers {
            if !out.contains(ep) {
                out.push(*ep);
            }
        }
        out
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
    /// Whether UDP may traverse this tunnel (the config's `udp:` flag;
    /// wireguard.rs's WgOut.udp gates UdpOpen the same way).
    pub udp_enabled: bool,
    /// The disco keys (ours + the peer's `Node.DiscoKey`); None when
    /// the peer has no disco (pre-1.16 or `IsWireGuardOnly`).
    pub disco: Option<DiscoKeys>,
}

/// The disco key pair a tunnel speaks under: our private key (one per
/// overlay) and the peer's public key from the netmap.
#[derive(Debug, Clone)]
pub struct DiscoKeys {
    /// Our overlay's disco private key.
    pub our_private: super::disco::DiscoPrivateKey,
    /// The peer's `Node.DiscoKey`.
    pub peer_public: [u8; 32],
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
    UdpOpen {
        reply: oneshot::Sender<Result<(u32, UdpDownlink)>>,
    },
    UdpSend {
        id: u32,
        dst: SocketAddr,
        data: Vec<u8>,
    },
    UdpClose {
        id: u32,
    },
}

/// Where a [`TsUdp`]'s inbound datagrams arrive.
type UdpDownlink = mpsc::Receiver<(NetAddr, Vec<u8>)>;

/// A live overlay tunnel: one background task owning the WireGuard
/// session, the carriers and the smoltcp netstack.
#[derive(Clone)]
pub struct TsTunnel {
    cmd: mpsc::Sender<TsCmd>,
}

impl TsTunnel {
    /// Bring the tunnel up: bind the UDP socket when a direct endpoint
    /// is configured OR disco is in play (a CallMeMaybe can open a
    /// direct path for an otherwise DERP-only peer), register with the
    /// peer's home DERP when routed via relay, then run the handshake +
    /// netstack task. The first handshake happens lazily on the first
    /// dial (like wireguard.rs's pre-session queue) so an unused tunnel
    /// costs nothing.
    pub async fn spawn(cfg: TsTunnelConfig) -> Result<Self> {
        if cfg.endpoint.is_none() && cfg.derp.is_none() {
            return Err(Error::config(
                "tailscale tunnel: peer has neither a UDP endpoint nor a home DERP",
            ));
        }
        let node_key = super::derp::NodePrivateKey::from_bytes(cfg.private_key);

        // The disco state, when the peer has a disco key.
        let disco = cfg.disco.as_ref().map(|keys| DiscoState {
            our: keys.our_private.clone(),
            peer: super::disco::DiscoPublicKey::from_bytes(keys.peer_public),
            node_pub: x25519_pub(&cfg.private_key),
            sent: HashMap::new(),
            confirmed: None,
            call_me_numbers: Vec::new(),
            last_ping: HashMap::new(),
        });

        let udp_sock = match (&cfg.endpoint, &disco) {
            (Some(ep), _) => {
                let bind = if ep.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                Some(Arc::new(UdpSocket::bind(bind).await?))
            }
            // A disco tunnel with no advertised endpoint still binds: a
            // CallMeMaybe may open the direct path later (the socket is
            // where the peer's return traffic must land).
            (None, Some(_)) => Some(Arc::new(UdpSocket::bind("0.0.0.0:0").await?)),
            (None, None) => None,
        };
        let derp = match &cfg.derp {
            Some(route) => Some(DerpCarrier::spawn(route, &node_key).await?),
            None => None,
        };

        let (tx, rx) = mpsc::channel::<TsCmd>(64);
        let wake = Arc::new(Notify::new());
        let stack = Tunnel::new(cfg, udp_sock, derp, disco, wake.clone())?;
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

    /// Open a UDP socket inside the tunnel (fails when the tunnel was
    /// configured with `udp_enabled: false`). `local_ipv6` is the
    /// tunnel's inner v6 address, carried for target validation.
    pub async fn udp_socket(&self, local_ipv6: Option<Ipv6Addr>) -> Result<TsUdp> {
        let (id, down) = self.udp_open().await?;
        Ok(TsUdp {
            tunnel: self.clone(),
            id,
            local_ipv6,
            down: Arc::new(tokio::sync::Mutex::new(down)),
        })
    }

    async fn udp_open(&self) -> Result<(u32, UdpDownlink)> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd
            .send(TsCmd::UdpOpen { reply: reply_tx })
            .await
            .map_err(|_| Error::network("tailscale: tunnel task is gone"))?;
        tokio::time::timeout(TCP_CONNECT_TIMEOUT, reply_rx)
            .await
            .map_err(|_| Error::network("tailscale: udp open timed out"))?
            .map_err(|_| Error::network("tailscale: tunnel task dropped the open"))?
    }
}

/// A UDP socket inside one peer tunnel — the WgUdp shape (wireguard.rs:
/// 2053-2110): send to any destination the tunnel's peer routes, receive
/// every reply that comes back to this socket's port. `Clone` shares the
/// socket (both halves send; the one receiver is shared, first reader
/// wins) — the overlay keeps one clone for sends and one in its reply
/// forwarder. The overlay-level handle that routes per destination
/// across peers is [`super::TailscaleOverlay::udp_socket`]; this one is
/// bound to a single peer's cryptokey.
#[derive(Clone)]
pub struct TsUdp {
    tunnel: TsTunnel,
    id: u32,
    /// The tunnel's inner v6 address, for target validation on send.
    local_ipv6: Option<Ipv6Addr>,
    down: Arc<tokio::sync::Mutex<UdpDownlink>>,
}

impl TsUdp {
    /// Send one datagram to `target` (a resolved IP; IPv6 needs the
    /// tunnel's inner v6 address).
    pub async fn send(&self, target: &NetAddr, data: &[u8]) -> Result<()> {
        let dst = udp_target_addr(target, "send", self.local_ipv6)?;
        self.tunnel
            .cmd
            .send(TsCmd::UdpSend {
                id: self.id,
                dst,
                data: data.to_vec(),
            })
            .await
            .map_err(|_| Error::network("tailscale: tunnel task is gone"))
    }

    /// Receive the next datagram addressed to this socket.
    pub async fn recv(&self) -> Result<(NetAddr, Vec<u8>)> {
        let mut down = self.down.lock().await;
        down.recv()
            .await
            .ok_or_else(|| Error::network("tailscale: udp socket is closed"))
    }
}

impl Drop for TsUdp {
    fn drop(&mut self) {
        let _ = self.tunnel.cmd.try_send(TsCmd::UdpClose { id: self.id });
    }
}

/// Resolve a [`NetAddr`] target to a socket address, refusing v6 targets
/// when no inner v6 address exists (wireguard.rs's target_addr,
/// 4638-4652).
fn udp_target_addr(
    target: &NetAddr,
    what: &str,
    local_ipv6: Option<Ipv6Addr>,
) -> Result<SocketAddr> {
    match &target.host {
        crate::addr::Host::Ip(IpAddr::V4(ip)) => Ok(SocketAddr::V4(SocketAddrV4::new(*ip, target.port))),
        crate::addr::Host::Ip(IpAddr::V6(ip)) => match local_ipv6 {
            Some(_) => Ok(SocketAddr::V6(SocketAddrV6::new(*ip, target.port, 0, 0))),
            None => Err(Error::network(format!(
                "tailscale: {what} to {ip}: the tunnel has no inner IPv6 address"
            ))),
        },
        crate::addr::Host::Domain(d) => Err(Error::network(format!(
            "tailscale: {what} to domain {d}: resolve before sending (the netstack routes IPs only)"
        ))),
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
            drop(g);
            // Freed queue space is stack input: the socket behind it may
            // hold data the service loop could not move (and a peer
            // waiting on the window this drain just re-opened). Wake the
            // tunnel task instead of letting the connection idle until
            // the driver's 1s tick (wave-13: the wave-12A wireguard.rs
            // fix, 1075-1079, mirrored here).
            self.shared.wake.notify_one();
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
/// The UDP socket budget, wireguard.rs parity (1130-1137).
const UDP_PACKETS: usize = 64;
const UDP_RX_BYTES: usize = 32 * 1024;
const UDP_TX_BYTES: usize = 32 * 1024;
const MAX_UDP_SOCKETS: usize = 64;
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

/// One open UDP socket inside the stack (wireguard.rs:1249-1256 UdpSock).
struct UdpSock {
    handle: SocketHandle,
    port: u16,
    down: mpsc::Sender<(NetAddr, Vec<u8>)>,
}

struct Tunnel {
    iface: Interface,
    sockets: SocketSet<'static>,
    shim: Shim,
    private_key: [u8; 32],
    peer_pub: [u8; 32],
    local_ipv4: Ipv4Addr,
    local_ipv6: Option<Ipv6Addr>,
    /// The direct-path socket (bound whenever an endpoint is configured
    /// or disco is in play).
    udp_sock: Option<Arc<UdpSocket>>,
    /// Where direct datagrams go: the configured endpoint, superseded by
    /// a pong-confirmed address.
    direct_dst: Option<SocketAddr>,
    derp: Option<DerpCarrier>,
    disco: Option<DiscoState>,
    udp_enabled: bool,
    udp_socks: HashMap<u32, UdpSock>,
    used_ports: HashSet<u16>,
    next_udp_id: u32,
    pending_hs: Option<PendingHandshake>,
    hs_retry_at: Option<Instant>,
    session: Option<Session>,
    local_index: u32,
    conns: Vec<Conn>,
    pre_session_tx: VecDeque<Vec<u8>>,
    wake: Arc<Notify>,
    start: Instant,
    /// Which carrier answered — set on the first authenticated packet
    /// (magicsock's learned path, first-response-wins). A pong-confirmed
    /// direct path overrides it for as long as the pong is trusted.
    learned_derp: bool,
    pump: Vec<u8>,
}

impl Tunnel {
    fn new(
        cfg: TsTunnelConfig,
        udp_sock: Option<Arc<UdpSocket>>,
        derp: Option<DerpCarrier>,
        disco: Option<DiscoState>,
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
        let direct_dst = cfg.endpoint;
        Ok(Tunnel {
            iface,
            sockets: SocketSet::new(Vec::new()),
            shim,
            private_key: cfg.private_key,
            peer_pub: cfg.peer_public,
            local_ipv4: cfg.local_ipv4,
            local_ipv6: cfg.local_ipv6,
            udp_sock,
            direct_dst,
            derp,
            disco,
            udp_enabled: cfg.udp_enabled,
            udp_socks: HashMap::new(),
            used_ports: HashSet::new(),
            next_udp_id: 0,
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

    /// An ephemeral inner port, unique within this stack (wireguard.rs:
    /// 1374-1381).
    fn ephemeral_port(&mut self) -> u16 {
        loop {
            let port = 32768 + rand::random::<u16>() % 28_000;
            if self.used_ports.insert(port) {
                return port;
            }
        }
    }

    /// Source-address selection by destination family (wireguard.rs:
    /// 1394-1403 local_address_for).
    fn local_address_for(&self, dst: &SocketAddr) -> IpAddress {
        match dst {
            SocketAddr::V4(_) => IpAddress::Ipv4(self.local_ipv4),
            SocketAddr::V6(_) => {
                IpAddress::Ipv6(self.local_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED))
            }
        }
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
    }

    /// One pass: poll the stack, pump TCP conns, pump UDP sockets,
    /// drain egress.
    fn step(&mut self) -> Vec<Vec<u8>> {
        let now = self.now();
        self.iface.poll(now, &mut self.shim, &mut self.sockets);
        self.pump_conns();
        self.drain_udp_rx();
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
                // Closed without our own graceful FIN = the peer reset (or
                // we aborted): writers must fail now instead of queuing
                // into a dead socket forever (wave-13: the wave-12A
                // wireguard.rs fix, 1762-1771, mirrored here — a mid-burst
                // RST hung write_all on a full to_stack queue).
                if !c.fin_sent && !g.write_closed {
                    g.aborted = true;
                }
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

    /// Deliver inbound datagrams from the smoltcp UDP sockets to their
    /// channels (wireguard.rs:1788-1815 drain_udp_rx).
    fn drain_udp_rx(&mut self) {
        let ids: Vec<u32> = self.udp_socks.keys().copied().collect();
        for id in ids {
            let (handle, down) = match self.udp_socks.get(&id) {
                Some(u) => (u.handle, &u.down),
                None => continue,
            };
            let sock = self.sockets.get_mut::<udp::Socket>(handle);
            while sock.can_recv() {
                let (n, meta) = match sock.recv_slice(&mut self.pump) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let from = match meta.endpoint.addr {
                    IpAddress::Ipv4(src) => NetAddr::ip(IpAddr::V4(src), meta.endpoint.port),
                    IpAddress::Ipv6(src) => NetAddr::ip(IpAddr::V6(src), meta.endpoint.port),
                };
                let _ = down.try_send((from, self.pump[..n].to_vec()));
            }
        }
    }

    /// Send one WireGuard datagram on the active path(s) — the
    /// disco-informed form of magicsock's `addrForSendLocked` +
    /// `sendUDPBatch`/`sendDatagramsViaDERP` (endpoint.go:632-649,
    /// magicsock.go:1137-1198): while a pong-confirmed direct path is
    /// trusted, it alone carries the traffic (even if the session first
    /// came up over DERP — the responder roams); without a confirmation,
    /// the learned carrier carries established sessions and every
    /// carrier is tried while handshaking (parallel probing).
    async fn send_wg(&mut self, msg: &[u8]) -> Result<()> {
        let confirmed = self.disco.as_ref().and_then(|d| d.trusted_direct());
        let via_derp_only =
            self.direct_dst.is_none() || (self.learned_derp && confirmed.is_none());
        if let Some(dst) = confirmed.or(self.direct_dst) {
            if !via_derp_only {
                let sock = self.udp_sock.as_ref().ok_or_else(|| {
                    Error::network("tailscale: disco path with no bound UDP socket")
                })?;
                sock.send_to(msg, dst)
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

    /// Send one disco Ping to every direct candidate, rate-limited per
    /// endpoint by DISCO_PING_INTERVAL — `sendDiscoPingsLocked`
    /// (endpoint.go:1415-1451) minus the heartbeat/MTU/relay legs. Each
    /// handshake attempt calls this, so REKEY_TIMEOUT bounds the retry
    /// cadence (see the module docs: no independent heartbeat).
    async fn send_disco_pings(&mut self) {
        let Some(d) = self.disco.as_mut() else {
            return;
        };
        d.expire_sent();
        let now = Instant::now();
        for ep in d.candidates(self.direct_dst) {
            // "the minimum time between pings to an endpoint"
            // (discoPingInterval; upstream resets this on CallMeMaybe).
            if d.last_ping.get(&ep).is_some_and(|at| now.duration_since(*at) < DISCO_PING_INTERVAL)
            {
                continue;
            }
            let ping = super::disco::Ping {
                txid: super::disco::new_txid(),
                node_key: Some(d.node_pub),
                padding: 0,
            };
            let Ok(pkt) = super::disco::seal(&d.our, &d.peer, &super::disco::DiscoMessage::Ping(ping.clone()))
            else {
                continue;
            };
            d.sent.insert(ping.txid, SentPing { to: ep, at: now });
            d.last_ping.insert(ep, now);
            tracing::debug!(target: "engine", "tailscale: disco: ping {} ({})", ep, super::disco::DiscoMessage::Ping(ping).summary());
            if let Some(sock) = &self.udp_sock {
                let _ = sock.send_to(&pkt, ep).await;
            }
        }
    }

    /// Handle one inbound disco frame — the bounded
    /// `handleDiscoMessage` (magicsock.go:2163-2469). `via_derp` tells
    /// which carrier delivered it; `from_udp` is the direct source
    /// address when it arrived over UDP (a Pong's proof and a Ping's
    /// reply address).
    async fn handle_disco(&mut self, via_derp: bool, from_udp: Option<SocketAddr>, data: &[u8]) {
        let Some(d) = self.disco.as_mut() else {
            return;
        };
        // The MAC check inside open() is the authentication; the sender
        // must then be the peer this tunnel belongs to (our stand-in
        // for peerMap.knownPeerDiscoKey, magicsock.go:2191-2199 — one
        // tunnel is one peer).
        let Ok((sender, msg)) = super::disco::open(&d.our, data) else {
            tracing::debug!(target: "engine", "tailscale: disco: unopenable frame dropped");
            return;
        };
        if sender != d.peer {
            return;
        }
        match msg {
            super::disco::DiscoMessage::Ping(ping) => {
                // handlePingLocked (magicsock.go:2512-2609): reply Pong
                // with the sender's view of its own source ("It includes
                // the sender's source IP + port, so it's effectively a
                // STUN response", disco.go:249-255). Only the UDP leg —
                // a DERP-carried ping has no source to echo and belongs
                // to the responder half we do not port (module deltas).
                let Some(from) = from_udp else {
                    return;
                };
                let pong = super::disco::Pong {
                    txid: ping.txid,
                    src: from,
                };
                tracing::debug!(
                    target: "engine",
                    "tailscale: disco: got ping tx={:02x?} -> ponging {}",
                    &ping.txid[..4],
                    from
                );
                if let Some(sock) = &self.udp_sock {
                    if let Ok(pkt) =
                        super::disco::seal(&d.our, &d.peer, &super::disco::DiscoMessage::Pong(pong))
                    {
                        let _ = sock.send_to(&pkt, from).await;
                    }
                }
            }
            super::disco::DiscoMessage::Pong(pong) => {
                // handlePongConnLocked (endpoint.go:1917-2010): a pong
                // for a ping we sent confirms the path it was sent to,
                // trusted for trustUDPAddrDuration.
                if let Some(sp) = d.sent.remove(&pong.txid) {
                    tracing::debug!(
                        target: "engine",
                        "tailscale: disco: pong confirmed {} (pong src {})",
                        sp.to,
                        pong.src
                    );
                    d.confirmed = Some((sp.to, Instant::now() + TRUST_UDP_ADDR_DURATION));
                    // The confirmed address becomes the direct
                    // destination (setBestAddrLocked).
                    self.direct_dst = Some(sp.to);
                }
            }
            super::disco::DiscoMessage::CallMeMaybe(cmm) => {
                // endpoint.go:2138-2218: "The contract for use of this
                // message is that the peer has already sent to us via
                // UDP, so their stateful firewall should be open. Now we
                // can Ping back and make it through." Only via DERP
                // (magicsock.go:2312-2315).
                if !via_derp {
                    return;
                }
                tracing::debug!(
                    target: "engine",
                    "tailscale: disco: call-me-maybe, {} endpoints",
                    cmm.my_number.len()
                );
                d.call_me_numbers = cmm.my_number;
                // "Zero out all the lastPing times to force
                // sendPingsLocked to send new ones" — then ping them.
                d.last_ping.clear();
                self.send_disco_pings().await;
                self.wake.notify_one();
            }
        }
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
    /// 1407-1450). A disco-configured tunnel probes its direct
    /// candidates first (upstream pings when sending without a trusted
    /// path, endpoint.send → sendDiscoPingsLocked, endpoint.go:1115-1120).
    async fn initiate(&mut self) -> Result<()> {
        if let Some(p) = &mut self.pending_hs {
            if p.attempts >= MAX_HANDSHAKE_ATTEMPTS {
                return Ok(());
            }
            p.attempts += 1;
        }
        self.send_disco_pings().await;
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
            TsCmd::UdpOpen { reply } => {
                // The udp flag gate (wireguard.rs:1607-1609).
                if !self.udp_enabled {
                    let _ = reply.send(Err(Error::network(
                        "tailscale: udp is disabled for this peer (the config's udp: flag)",
                    )));
                    return;
                }
                if self.udp_socks.len() >= MAX_UDP_SOCKETS {
                    let _ = reply.send(Err(Error::network("tailscale: udp socket limit reached")));
                    return;
                }
                let mut sock = udp::Socket::new(
                    udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                        vec![0; UDP_RX_BYTES],
                    ),
                    udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                        vec![0; UDP_TX_BYTES],
                    ),
                );
                let port = self.ephemeral_port();
                // Bound on both families like wireguard.rs:1622-1625 (addr
                // None), so replies of either family reach the socket.
                if let Err(e) = sock.bind(IpListenEndpoint { addr: None, port }) {
                    self.used_ports.remove(&port);
                    let _ = reply.send(Err(Error::network(format!(
                        "tailscale: udp bind: {e:?}"
                    ))));
                    return;
                }
                let handle = self.sockets.add(sock);
                let id = self.next_udp_id;
                self.next_udp_id += 1;
                let (tx, rx) = mpsc::channel::<(NetAddr, Vec<u8>)>(64);
                self.udp_socks.insert(id, UdpSock { handle, port, down: tx });
                let _ = reply.send(Ok((id, rx)));
                self.wake.notify_one();
            }
            TsCmd::UdpSend { id, dst, data } => {
                let Some(handle) = self.udp_socks.get(&id).map(|u| u.handle) else {
                    return;
                };
                let mut meta = udp::UdpMetadata::from(IpEndpoint::new(
                    match dst {
                        SocketAddr::V4(v4) => IpAddress::Ipv4(*v4.ip()),
                        SocketAddr::V6(v6) => IpAddress::Ipv6(*v6.ip()),
                    },
                    dst.port(),
                ));
                meta.local_address = Some(self.local_address_for(&dst));
                let sock = self.sockets.get_mut::<udp::Socket>(handle);
                if let Err(e) = sock.send_slice(&data, meta) {
                    tracing::debug!(target: "engine", "tailscale: udp send to {dst}: {e:?}");
                }
                self.wake.notify_one();
            }
            TsCmd::UdpClose { id } => {
                if let Some(u) = self.udp_socks.remove(&id) {
                    self.used_ports.remove(&u.port);
                    self.sockets.remove(u.handle);
                }
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
        let has_udp = t.udp_sock.is_some();
        let has_derp = t.derp.is_some();
        let has_disco = t.disco.is_some();
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
                    let sock = t.udp_sock.as_ref().expect("has_udp checked");
                    sock.recv_from(&mut udp_buf).await
                } else {
                    std::future::pending::<std::io::Result<(usize, SocketAddr)>>().await
                }
            } => {
                if let Ok((n, from)) = r {
                    // packetLooksLike (magicsock.go:2093-2141): disco
                    // frames and WireGuard datagrams share the socket.
                    if has_disco && super::disco::looks_like_disco(&udp_buf[..n]) {
                        t.handle_disco(false, Some(from), &udp_buf[..n]).await;
                    } else {
                        t.on_datagram(false, &udp_buf[..n]).await;
                    }
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
                    Some(DerpEvent::Packet(pkt)) => {
                        if has_disco && super::disco::looks_like_disco(&pkt) {
                            t.handle_disco(true, None, &pkt).await;
                        } else {
                            t.on_datagram(true, &pkt).await;
                        }
                    }
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

    #[test]
    fn udp_target_validation_refuses_domains_and_bare_v6() {
        // wireguard.rs's target_addr semantics: domains need resolving
        // first; v6 targets need an inner v6 address.
        let v4 = udp_target_addr(
            &NetAddr::ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 53),
            "send",
            None,
        )
        .unwrap();
        assert_eq!(v4.port(), 53);
        let dom = udp_target_addr(&NetAddr::domain("peer.tail-scale.ts.net", 53).unwrap(), "send", None)
            .unwrap_err();
        assert!(dom.to_string().contains("resolve before sending"), "{dom}");
        let v6 = udp_target_addr(
            &NetAddr::ip("fd7a:115c:a1e0::1".parse::<std::net::IpAddr>().unwrap(), 53),
            "send",
            None,
        )
        .unwrap_err();
        assert!(v6.to_string().contains("no inner IPv6 address"), "{v6}");
    }

    // -------------------------------------------------------------------
    // The wave-13 netstack stall repros: the engine's own WireGuard
    // endpoint (`proto::wireguard.rs::serve_endpoint`) is the routed
    // peer, reached over the direct UDP carrier — the same hermetic
    // shape tailscale.rs's e2e tests use for the overlay. They mirror
    // the wave-12A wireguard.rs repros
    // (`reset_mid_burst_fails_the_writer_not_hangs`,
    // `endpoint_accepts_concurrent_dials_to_one_port`,
    // `tcp_echo_slow_reader_closes_and_reopens_window` and its
    // `zero_window_reopens_promptly_after_drain` guard) against THIS
    // module's `pump_conns` + `TsTcpStream`.
    // -------------------------------------------------------------------

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::inbound::RelayHandler;

    const PEER_TUNNEL_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
    const OUR_TUNNEL_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    const EP_TCP_PORT: u16 = 9041;

    fn b64(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    /// The peer's relay: echo TCP both ways, loop UDP back (the same
    /// shape as tailscale.rs's EchoRelay).
    struct EchoRelay;
    impl RelayHandler for EchoRelay {
        fn handle_tcp(
            self: Arc<Self>,
            _meta: crate::inbound::TcpMeta,
            mut client: crate::stream::BoxProxyStream,
        ) {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match client.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if client.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
        fn handle_udp(
            self: Arc<Self>,
            _source: SocketAddr,
            _inbound: String,
            mut uplink: mpsc::Receiver<(NetAddr, Vec<u8>)>,
            downlink: mpsc::Sender<(NetAddr, Vec<u8>)>,
        ) {
            tokio::spawn(async move {
                while let Some((target, data)) = uplink.recv().await {
                    let _ = downlink.send((target, data)).await;
                }
            });
        }
    }

    /// A relay that drops the stream after the first read — the peer
    /// aborts its socket (RST) while the writer is still pushing.
    struct DropAfterFirstRead;
    impl RelayHandler for DropAfterFirstRead {
        fn handle_tcp(
            self: Arc<Self>,
            _meta: crate::inbound::TcpMeta,
            mut client: crate::stream::BoxProxyStream,
        ) {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16];
                let _ = client.read(&mut buf).await;
                // Drop: the endpoint aborts the connection (RST).
            });
        }
        fn handle_udp(
            self: Arc<Self>,
            _source: SocketAddr,
            _inbound: String,
            _uplink: mpsc::Receiver<(NetAddr, Vec<u8>)>,
            _downlink: mpsc::Sender<(NetAddr, Vec<u8>)>,
        ) {
        }
    }

    /// Spawn the production WireGuard endpoint as the routed peer and
    /// bring up a [`TsTunnel`] to it over the direct UDP carrier. All
    /// key material is generated in-test; nothing leaves loopback.
    async fn spawn_peer_tunnel(relay: Arc<dyn RelayHandler>) -> TsTunnel {
        let mut our_sk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut our_sk);
        let mut peer_sk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut peer_sk);
        let cfg = crate::proto::wireguard::WgEndpointCfg {
            tag: "ts-wg13-peer".into(),
            private_key: b64(&peer_sk),
            listen_port: 0,
            mtu: 0,
            address: Some((PEER_TUNNEL_IP, 24)),
            inet6_address: None,
            udp_timeout: None,
            peers: vec![crate::proto::wireguard::WgEndpointPeer {
                public_key: b64(&x25519_pub(&our_sk)),
                pre_shared_key: None,
                allowed_ips: vec![(IpAddr::V4(OUR_TUNNEL_IP), 32)],
                persistent_keepalive: None,
            }],
        };
        let sa = crate::proto::wireguard::serve_endpoint(&cfg, relay)
            .await
            .expect("peer endpoint starts");
        // The endpoint binds [::] dual-stack and reports the v6 wildcard;
        // address it over v4 loopback (tailscale.rs rewrites the same way).
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), sa.port());
        TsTunnel::spawn(TsTunnelConfig {
            private_key: our_sk,
            peer_public: x25519_pub(&peer_sk),
            local_ipv4: OUR_TUNNEL_IP,
            local_ipv6: None,
            mtu: 1280,
            endpoint: Some(endpoint),
            derp: None,
            udp_enabled: true,
            // The endpoint peer carries no disco key (IsWireGuardOnly
            // shape), so this harness stays on the plain WireGuard path.
            disco: None,
        })
        .await
        .expect("tunnel spawns")
    }

    fn peer_target() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(PEER_TUNNEL_IP), EP_TCP_PORT)
    }

    /// REPRO (wave-13, mirrors wireguard.rs's wave-12A repro): a relay
    /// that drops the stream after the first read — the peer aborts the
    /// socket (RST) while the client writer is still pushing a burst far
    /// bigger than every buffer. The writer must fail with BrokenPipe
    /// promptly, not hang on a `to_stack` queue nobody drains.
    #[tokio::test]
    async fn reset_mid_burst_fails_the_writer_not_hangs() {
        let tunnel = spawn_peer_tunnel(Arc::new(DropAfterFirstRead)).await;
        let mut stream =
            tokio::time::timeout(Duration::from_secs(30), tunnel.connect_tcp(peer_target()))
                .await
                .expect("dial must not stall")
                .expect("dial through the tunnel");
        let payload = vec![7u8; 512 * 1024];
        let outcome =
            tokio::time::timeout(Duration::from_secs(15), stream.write_all(&payload)).await;
        match outcome {
            Err(_elapsed) => panic!("writer hung on a reset connection (stall)"),
            // The write may complete into local queues before the RST
            // lands; then the failure must surface on the next read.
            Ok(Ok(())) => {
                let mut more = vec![0u8; 16];
                let read = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut more))
                    .await
                    .expect("read side must terminate after a reset");
                assert!(
                    matches!(read, Ok(0) | Err(_)),
                    "connection was reset: read must error or EOF, not data"
                );
            }
            Ok(Err(e)) => {
                assert!(
                    matches!(e.kind(), io::ErrorKind::BrokenPipe),
                    "writer must see BrokenPipe on reset, got {e:?}"
                );
            }
        }
    }

    /// REPRO (wave-13, mirrors wireguard.rs's wave-12A
    /// `endpoint_accepts_concurrent_dials_to_one_port`): several dials
    /// to one port over one tunnel session, each echoing interleaved
    /// bursts. The tailscale netstack is initiator-only — the listener
    /// re-arm race cannot exist on this side (the wave-12A
    /// spare-listener fix lives in the peer's endpoint) — so this pins
    /// the client-side half of the shape: every concurrent dial must
    /// establish and echo.
    #[tokio::test]
    async fn tunnel_accepts_concurrent_dials_to_one_port() {
        let tunnel = spawn_peer_tunnel(Arc::new(EchoRelay)).await;
        let mut streams = Vec::new();
        for _ in 0..4 {
            streams.push(
                tokio::time::timeout(Duration::from_secs(30), tunnel.connect_tcp(peer_target()))
                    .await
                    .expect("concurrent dial must not stall")
                    .expect("dial through the tunnel"),
            );
        }
        // Every stream echoes multi-segment bursts, interleaved.
        for round in 0..4u32 {
            for (i, stream) in streams.iter_mut().enumerate() {
                let chunk: Vec<u8> =
                    (0..8 * 1024).map(|k| (k as u32 + round + i as u32) as u8).collect();
                tokio::time::timeout(Duration::from_secs(30), stream.write_all(&chunk))
                    .await
                    .expect("concurrent stream write must not stall")
                    .unwrap();
                let mut back = vec![0u8; chunk.len()];
                tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut back))
                    .await
                    .expect("concurrent stream echo must not stall")
                    .unwrap();
                assert_eq!(back, chunk);
            }
        }
        for mut s in streams {
            s.shutdown().await.unwrap();
        }
    }

    /// REPRO (wave-13, mirrors wireguard.rs's wave-12A repro): a
    /// deliberately slow reader — 1 KiB reads with yields — forces the
    /// receive window to close and reopen (zero-window probing) while
    /// the write side keeps producing.
    #[tokio::test]
    async fn tcp_echo_slow_reader_closes_and_reopens_window() {
        let tunnel = spawn_peer_tunnel(Arc::new(EchoRelay)).await;
        let stream =
            tokio::time::timeout(Duration::from_secs(30), tunnel.connect_tcp(peer_target()))
                .await
                .expect("dial must not stall")
                .expect("dial through the tunnel");

        const TOTAL: usize = 256 * 1024;
        let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 249) as u8).collect();

        let (mut r, mut w) = tokio::io::split(stream);
        let tx_payload = payload.clone();
        let writer = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(60), w.write_all(&tx_payload))
                .await
                .expect("write side must survive a zero-window peer")
                .unwrap();
        });
        let mut echoed = Vec::with_capacity(TOTAL);
        let mut chunk = vec![0u8; 1024];
        while echoed.len() < TOTAL {
            let n = tokio::time::timeout(Duration::from_secs(60), r.read(&mut chunk))
                .await
                .expect("slow reader must not stall behind a closed window")
                .unwrap();
            assert!(n > 0, "premature EOF at {}", echoed.len());
            echoed.extend_from_slice(&chunk[..n]);
            tokio::task::yield_now().await;
        }
        writer.await.unwrap();
        assert_eq!(echoed, payload);
    }

    /// GUARD (wave-13, mirrors wireguard.rs's wave-12A guard): the
    /// zero-window stall-recovery shape. The reader drains in 16 KiB
    /// chunks with pauses, so the peer repeatedly hits our closed
    /// window; every drain must promptly re-open it — poll_read pings
    /// the tunnel task the moment queue space frees, instead of idling
    /// until the driver's 1s tick or the peer's next probe. Bound is
    /// generous (healthy: ~2s).
    #[tokio::test]
    async fn zero_window_reopens_promptly_after_drain() {
        let tunnel = spawn_peer_tunnel(Arc::new(EchoRelay)).await;
        let stream =
            tokio::time::timeout(Duration::from_secs(30), tunnel.connect_tcp(peer_target()))
                .await
                .expect("dial must not stall")
                .expect("dial through the tunnel");

        const TOTAL: usize = 256 * 1024;
        let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();

        let (mut r, mut w) = tokio::io::split(stream);
        let tx_payload = payload.clone();
        let writer = tokio::spawn(async move {
            w.write_all(&tx_payload).await.unwrap();
        });
        let started = Instant::now();
        let mut echoed = Vec::with_capacity(TOTAL);
        let mut chunk = vec![0u8; 16 * 1024];
        while echoed.len() < TOTAL {
            let n = tokio::time::timeout(Duration::from_secs(10), r.read(&mut chunk))
                .await
                .expect("a drained window must re-open without the 1s tick")
                .unwrap();
            assert!(n > 0, "premature EOF at {}", echoed.len());
            echoed.extend_from_slice(&chunk[..n]);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let elapsed = started.elapsed();
        writer.await.unwrap();
        assert_eq!(echoed, payload);
        assert!(
            elapsed < Duration::from_secs(8),
            "window re-opening dragged: {elapsed:?} for 256 KiB — read drain not waking the tunnel task"
        );
    }

    // The full data-plane proofs (direct UDP + DERP relay against the
    // engine's own WireGuard endpoint) live in `super`'s tests, where
    // the netmap-derived config is what gets exercised end to end.
}
