//! WireGuard: the Noise_IKpsk2 (Construction v1) handshake, the
//! ChaCha20Poly1305 transport with 64-bit counters and an anti-replay
//! window, a client-side smoltcp netstack that terminates TCP/UDP toward
//! targets inside the tunnel, and an ENDPOINT (server) mode — the handshake
//! responder with roaming, cookie-under-load and cryptokey routing that
//! bridges decrypted packets into the engine like a TUN inbound
//! ([`serve_endpoint`], sing-box's `endpoint` of type wireguard).
//!
//! # Scope and shape
//!
//! * **Protocol**: hand-implemented over the in-tree crypto crates
//!   (curve25519-dalek, chacha20poly1305, plus a hand-rolled BLAKE2s-256 —
//!   the one primitive WireGuard needs that nothing else in the tree
//!   provides, following the hand-rolled blake2b precedent in
//!   [`crate::proto::hysteria2`]). The formulas are transcribed from the
//!   canonical WireGuard protocol description (wireguard.com/protocol);
//!   every derivation step is cited in a comment next to the code.
//! * **Client**: a single fixed peer (mihomo `type: wireguard` /
//!   sing-box `type: wireguard` outbound), no endpoint roaming, cookie
//!   *consumption* so an under-load server can still be reached.
//! * **Endpoint (server)**: listens on UDP, answers initiations (promoted
//!   from the in-test noise responder into [`open_initiation`] /
//!   [`respond_initiation`]), tracks peers by receiver index with roaming
//!   on every authenticated packet, guards against initiation replays via
//!   TAI64N, replies with cookies when handshake load exceeds
//!   wireguard-go's 64/s trip point, and routes decrypted packets by
//!   allowed_ips into an accepting netstack whose TCP connections and UDP
//!   sessions are handed to the engine's relay exactly like the TUN
//!   inbound's.
//! * **Netstack**: one task owns the smoltcp `Interface`, the `SocketSet`
//!   and the UDP socket to the peer, mirroring the inbound TUN netstack's
//!   single-owner design. TCP dials become [`WgStream`] (an
//!   `AsyncRead + AsyncWrite` bridge over two bounded queues plus wakers),
//!   UDP dials become [`WgUdp`].
//! * **Dual-stack inner addresses**: the stack routes IPv4 always
//!   (`local_ip`) and IPv6 when `local_ipv6` is configured — the exact
//!   addresses the provider assigned, never derived (sing-wireguard's
//!   `StackDevice` adds precisely the configured prefixes, `device_stack.go`
//!   `NewStackDevice`/`AddProtocolAddress`, and dials bound to the family's
//!   own address, `DialContext`'s `addr4`/`addr6` choice). IPv6 targets are
//!   refused with a clear error when no inner v6 address is configured.
//!   Domain targets stay refused: mihomo/sing-box resolve the destination
//!   *outside* the tunnel and hand the stack an IP (the netstack routes IPs
//!   only) — the integrator resolves before dialing.
//!
//! # The `reserved` bytes (mihomo/sing-box compatibility)
//!
//! mihomo's `reserved: [a, b, c]` is NOT a port trick and NOT a prefix: it
//! overwrites the three `reserved_zero` header bytes at offsets 1..3 of
//! every outgoing WireGuard datagram (message type byte at offset 0 is
//! untouched), and inbound datagrams have bytes 1..3 zeroed before
//! parsing. Verified against `ClientBind.Send`/`.receive` in
//! MetaCubeX/sing-wireguard (`client_bind.go`, the bind mihomo's
//! `adapter/outbound/wireguard.go` constructs via `NewClientBind(...,
//! reserved)`): `b[1]=reserved[0]; b[2]=reserved[1]; b[3]=reserved[2]` on
//! send, `b[1]=0; b[2]=0; b[3]=0` on receive. MAC1/MAC2 are computed over
//! the zero-reserved form (upstream computes them inside wireguard-go
//! before the bind rewrites the bytes); this module does the same:
//! codecs build zero-reserved messages and [`apply_reserved`] /
//! [`strip_reserved`] run at the raw-socket boundary.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};

use crate::addr::NetAddr;
use crate::error::{Error, Result};
use crate::inbound::{SharedRelay, TcpMeta};
use crate::stream::BoxProxyStream;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// A WireGuard outbound, dialect-independent. The integrator maps mihomo
/// (`private-key`, `peers[].{server,port,public-key,pre-shared-key}`,
/// `reserved`, `mtu`, `ip`, `ipv6`, `udp`) and sing-box (`private_key`,
/// `peers[].{server,server_port,public_key,pre_shared_key,reserved}`,
/// `local_address`, `mtu`, `udp`) onto these fields; both dialects are the
/// same wire protocol.
#[derive(Debug, Clone)]
pub struct WgOut {
    /// Peer endpoint host (IP or domain; resolved once per tunnel).
    pub server: String,
    pub port: u16,
    /// Our static private key, base64 (32 bytes decoded).
    pub private_key: String,
    /// Peer static public key, base64 (32 bytes decoded).
    pub peer_public_key: String,
    /// Optional pre-shared key, base64 (32 bytes decoded); empty = none.
    pub pre_shared_key: Option<String>,
    /// Our address inside the tunnel (mihomo `ip`).
    pub local_ip: Ipv4Addr,
    /// Our IPv6 address inside the tunnel, if the provider assigned one
    /// (mihomo `ipv6`, sing-box `local_address` v6 entries). When set, the
    /// stack carries the address with a /128 and a default v6 route, dials
    /// v6 targets with it as the source, and accepts v6 UDP replies;
    /// sing-wireguard assigns exactly the configured addresses and derives
    /// nothing (`device_stack.go` `NewStackDevice`), so an absent v6 address
    /// means v6 targets are refused.
    pub local_ipv6: Option<Ipv6Addr>,
    /// Inner (TUN-side) MTU. 0 selects mihomo's default (1408).
    pub mtu: u16,
    /// Provider-specific bytes smuggled into the reserved header field of
    /// every datagram (see module docs).
    pub reserved: [u8; 3],
    /// Whether UDP may be relayed through the tunnel.
    pub udp: bool,
}

impl WgOut {
    /// Inner MTU clamped to sane bounds (mihomo defaults to 1408).
    fn effective_mtu(&self) -> usize {
        if self.mtu == 0 {
            1408
        } else {
            self.mtu.clamp(576, 65535) as usize
        }
    }

    /// Decode the key material (static pair, peer public, PSK).
    fn keys(&self) -> Result<(StaticKeys, [u8; 32], [u8; 32])> {
        let sk = b64key(&self.private_key, "private-key")?;
        let statics = StaticKeys::from_secret(sk);
        let peer = b64key(&self.peer_public_key, "public-key")?;
        let psk = match self.pre_shared_key.as_deref() {
            None | Some("") => [0u8; 32],
            Some(s) => b64key(s, "pre-shared-key")?,
        };
        Ok((statics, peer, psk))
    }
}

/// Decode a base64 WireGuard key (standard or unpadded) into 32 bytes.
fn b64key(s: &str, what: &str) -> Result<[u8; 32]> {
    let trimmed = s.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .map_err(|_| Error::config(format!("wg: {what} is not valid base64")))?;
    decoded
        .try_into()
        .map_err(|_| Error::config(format!("wg: {what} must decode to exactly 32 bytes")))
}

// ---------------------------------------------------------------------------
// Protocol constants (WireGuard protocol page + wireguard-go
// device/constants.go — values cross-checked between the two)
// ---------------------------------------------------------------------------

/// `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` (37 bytes).
const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// `WireGuard v1 zx2c4 Jason@zx2c4.com` (34 bytes).
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

/// Initiation messages after which the initiator rekeys (2^60).
const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// Counter at (or beyond) which transport messages are rejected:
/// 2^64 − 2^13 − 1 (wireguard-go `RejectAfterMessages`).
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1;
/// Rekey 120s after the session was created (initiator side).
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// Session keys older than this are dead (180s).
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// Handshake initiation retry interval / rate limit (5s).
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
/// Overall handshake attempt budget before giving up (90s).
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
/// Send a keepalive after this much transmit silence following a received
/// packet (10s).
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// A received cookie is valid for two minutes.
const COOKIE_REFRESH_TIME: Duration = Duration::from_secs(120);
/// Max handshake attempts = RekeyAttemptTime / RekeyTimeout = 18.
const MAX_HANDSHAKE_ATTEMPTS: u32 = 18;
/// Inner packets are zero-padded to a multiple of 16 on send
/// (wireguard-go `PaddingMultiple`).
const PADDING_MULTIPLE: usize = 16;

/// Wire sizes of the fixed messages.
const MSG_INITIATION_LEN: usize = 148;
const MSG_RESPONSE_LEN: usize = 92;
const MSG_COOKIE_LEN: usize = 64;
/// type(4) + receiver(4) + counter(8); ciphertext follows.
const TRANSPORT_HEADER_LEN: usize = 16;

const MSG_TYPE_INITIATION: u8 = 1;
const MSG_TYPE_RESPONSE: u8 = 2;
const MSG_TYPE_COOKIE: u8 = 3;
const MSG_TYPE_TRANSPORT: u8 = 4;

// ---------------------------------------------------------------------------
// BLAKE2s-256 (RFC 7693), unkeyed hash + keyed 16-byte MAC
// ---------------------------------------------------------------------------

const BLAKE2S_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Unkeyed BLAKE2s-256 — the protocol's HASH().
fn blake2s256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    blake2s_into(data, None, &mut out);
    out
}

/// HASH(a || b) — the handshake's dominant operation.
fn hash2(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(a.len() + b.len());
    buf.extend_from_slice(a);
    buf.extend_from_slice(b);
    blake2s256(&buf)
}

/// Keyed BLAKE2s with a 16-byte digest — the protocol's MAC(key, input).
/// Keys here are 32 bytes (MAC1) or the 16-byte cookie (MAC2).
fn blake2s_mac(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    blake2s_into(data, Some(key), &mut out);
    out
}

/// BLAKE2s over `data`, optionally keyed (the key occupies the first
/// message block, per RFC 7693 §3.2), writing `out.len()` digest bytes.
fn blake2s_into(data: &[u8], key: Option<&[u8]>, out: &mut [u8]) {
    debug_assert!(key.is_none_or(|k| k.len() <= 64));
    let out_len = out.len();
    let mut h = BLAKE2S_IV;
    // Parameter block word 0: digest length | key length << 8 | fanout 1
    // << 16 | depth 1 << 24.
    h[0] ^= 0x0101_0000 | ((key.map_or(0, |k| k.len()) as u32) << 8) | out_len as u32;

    // Keyed hashing: the zero-padded key is the first block. With an empty
    // message it is also the final block (single compression, t = 64).
    if let Some(k) = key {
        let mut block = [0u8; 64];
        block[..k.len()].copy_from_slice(k);
        if data.is_empty() {
            blake2s_compress(&mut h, &block, 64, true);
            for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(h.iter()) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
            return;
        }
        blake2s_compress(&mut h, &block, 64, false);
    }

    // t counts every compressed byte, the key block included.
    let mut t: u64 = u64::from(key.is_some()) * 64;
    let mut i = 0usize;
    while data.len() - i > 64 {
        let mut block = [0u8; 64];
        block.copy_from_slice(&data[i..i + 64]);
        t += 64;
        blake2s_compress(&mut h, &block, t, false);
        i += 64;
    }
    let mut block = [0u8; 64];
    let rem = &data[i..];
    block[..rem.len()].copy_from_slice(rem);
    t += rem.len() as u64;
    blake2s_compress(&mut h, &block, t, true);

    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(h.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
}

fn blake2s_compress(h: &mut [u32; 8], block: &[u8; 64], t: u64, last: bool) {
    let mut m = [0u32; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2S_IV);
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    if last {
        v[14] ^= u32::MAX;
    }
    for round in 0..10 {
        let s = &SIGMA[round % 10];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

// ---------------------------------------------------------------------------
// HMAC-BLAKE2s and the KDF chain (whitepaper "KDF1/KDF2/KDF3" formulas)
// ---------------------------------------------------------------------------

/// HMAC-BLAKE2s-256 (the protocol's HMAC(key, input, 32)); standard
/// HMAC over a 64-byte block.
fn hmac_blake2s(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k0 = [0u8; 64];
    if key.len() > 64 {
        k0[..32].copy_from_slice(&blake2s256(key));
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut ipad = Vec::with_capacity(64 + msg.len());
    let mut opad = Vec::with_capacity(96);
    for b in k0 {
        ipad.push(b ^ 0x36);
        opad.push(b ^ 0x5c);
    }
    ipad.extend_from_slice(msg);
    let inner = blake2s256(&ipad);
    opad.extend_from_slice(&inner);
    blake2s256(&opad)
}

/// temp = HMAC(ck, x); ck' = HMAC(temp, 0x1) — one chain-key advance.
/// Returns (new chain key, temp); the whitepaper's KDF1 discards temp.
fn kdf_advance(ck: &[u8; 32], x: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac_blake2s(ck, x);
    let ck2 = hmac_blake2s(&temp, &[1]);
    (ck2, temp)
}

/// KDF1: advance the chain key only.
fn kdf1(ck: &[u8; 32], x: &[u8]) -> [u8; 32] {
    kdf_advance(ck, x).0
}

/// KDF2: temp = HMAC(ck, x); ck' = HMAC(temp, 0x1); key = HMAC(temp, ck' || 0x2).
fn kdf2(ck: &[u8; 32], x: &[u8]) -> ([u8; 32], [u8; 32]) {
    let (ck2, temp) = kdf_advance(ck, x);
    let mut mat = Vec::with_capacity(33);
    mat.extend_from_slice(&ck2);
    mat.push(2);
    let key = hmac_blake2s(&temp, &mat);
    (ck2, key)
}

/// KDF3 (the psk2 step of the response message): temp = HMAC(ck, psk);
/// ck' = HMAC(temp, 0x1); temp2 = HMAC(temp, ck' || 0x2);
/// key = HMAC(temp, temp2 || 0x3). temp2 is additionally mixed into the
/// handshake hash.
fn kdf3(ck: &[u8; 32], x: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let (ck2, temp) = kdf_advance(ck, x);
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

/// Transport keys from the final chain key: temp1 = HMAC(ck, empty);
/// k_a = HMAC(temp1, 0x1); k_b = HMAC(temp1, k_a || 0x2). The initiator
/// sends with k_a and receives with k_b; the responder the other way
/// round.
fn derive_transport_keys(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let temp1 = hmac_blake2s(ck, &[]);
    let first = hmac_blake2s(&temp1, &[1]);
    let mut mat = Vec::with_capacity(33);
    mat.extend_from_slice(&first);
    mat.push(2);
    let second = hmac_blake2s(&temp1, &mat);
    (first, second)
}

/// MAC1 key: HASH(LABEL_MAC1 || static public key of the message's
/// recipient).
fn mac1_key(peer_static: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(LABEL_MAC1.len() + 32);
    buf.extend_from_slice(LABEL_MAC1);
    buf.extend_from_slice(peer_static);
    blake2s256(&buf)
}

/// Cookie-reply encryption key: HASH(LABEL_COOKIE || responder static).
fn cookie_key(peer_static: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(LABEL_COOKIE.len() + 32);
    buf.extend_from_slice(LABEL_COOKIE);
    buf.extend_from_slice(peer_static);
    blake2s256(&buf)
}

// ---------------------------------------------------------------------------
// X25519 + AEAD + TAI64N helpers
// ---------------------------------------------------------------------------

/// A static (or ephemeral) X25519 keypair.
struct StaticKeys {
    sk: [u8; 32],
    pk: [u8; 32],
}

impl StaticKeys {
    fn from_secret(sk: [u8; 32]) -> Self {
        let pk = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(sk).0;
        StaticKeys { sk, pk }
    }
}

fn x25519_keypair() -> StaticKeys {
    let mut sk = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut sk);
    StaticKeys::from_secret(sk)
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

/// AEAD nonce: 32 zero bits || 64-bit little-endian counter.
fn aead_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

fn aead_seal(key: &[u8; 32], counter: u64, plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::crypto("wg: bad AEAD key length"))?;
    cipher
        .encrypt(
            (&aead_nonce(counter)).into(),
            Payload { msg: plain, aad },
        )
        .map_err(|_| Error::crypto("wg: AEAD seal failed"))
}

fn aead_open(key: &[u8; 32], counter: u64, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::crypto("wg: bad AEAD key length"))?;
    cipher
        .decrypt(
            (&aead_nonce(counter)).into(),
            Payload { msg: ct, aad },
        )
        .map_err(|_| Error::crypto("wg: AEAD open failed"))
}

/// TAI64N timestamp of now: 0x4000... + unix seconds (8 bytes big-endian,
/// which makes memcmp equivalent to time comparison) + nanoseconds BE.
fn tai64n_now() -> [u8; 12] {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&(0x4000_0000_0000_0000u64 + d.as_secs()).to_be_bytes());
    out[8..].copy_from_slice(&d.subsec_nanos().to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// Anti-replay window (whitepaper: "a window of roughly 2000 prior values,
// checked after verifying the authentication tag")
// ---------------------------------------------------------------------------

/// Sliding replay window of 2048 counters (wireguard-go uses the same
/// size). Bit (c % 2048) is set for every accepted counter c; a counter
/// more than 2048 behind the highest is too old.
pub(crate) struct AntiReplay {
    last: u64,
    words: [u64; 32],
}

impl AntiReplay {
    pub(crate) fn new() -> Self {
        AntiReplay {
            last: 0,
            words: [0; 32],
        }
    }

    fn bit(c: u64) -> (usize, u64) {
        let b = (c % 2048) as usize;
        (b / 64, 1u64 << (b % 64))
    }

    /// Accept-and-mark; false for duplicates, too-old counters, and the
    /// reserved top values (REJECT_AFTER_MESSAGES and above).
    pub(crate) fn accept(&mut self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        if self.last >= counter {
            if self.last - counter >= 2048 {
                return false;
            }
        } else if counter - self.last >= 2048 {
            self.words = [0; 32];
            self.last = counter;
        }
        let (word, mask) = Self::bit(counter);
        if self.words[word] & mask != 0 {
            return false; // duplicate inside the window
        }
        while self.last < counter {
            self.last += 1;
            // The counter sliding out of the window frees its bit for a
            // future counter congruent modulo 2048.
            if self.last >= 2048 {
                let (w, m) = Self::bit(self.last - 2048);
                self.words[w] &= !m;
            }
        }
        self.words[word] |= mask;
        true
    }
}

impl Default for AntiReplay {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Wire codec
// ---------------------------------------------------------------------------

/// One parsed WireGuard message (reserved header bytes ignored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WgMsg {
    Initiation {
        sender: u32,
        ephemeral: [u8; 32],
        enc_static: [u8; 48],
        enc_timestamp: [u8; 28],
        mac1: [u8; 16],
        mac2: [u8; 16],
    },
    Response {
        sender: u32,
        receiver: u32,
        ephemeral: [u8; 32],
        enc_nothing: [u8; 16],
        mac1: [u8; 16],
        mac2: [u8; 16],
    },
    Cookie {
        receiver: u32,
        nonce: [u8; 24],
        enc_cookie: [u8; 32],
    },
    Transport {
        receiver: u32,
        counter: u64,
        data: Vec<u8>,
    },
}

/// Parse a (reserved-stripped) datagram. Lengths are exact.
pub(crate) fn parse_wg_msg(buf: &[u8]) -> Option<WgMsg> {
    if buf.len() < 4 {
        return None;
    }
    let msg_type = buf[0];
    match msg_type {
        MSG_TYPE_INITIATION if buf.len() == MSG_INITIATION_LEN => Some(WgMsg::Initiation {
            sender: le32(&buf[4..8]),
            ephemeral: buf[8..40].try_into().unwrap(),
            enc_static: buf[40..88].try_into().unwrap(),
            enc_timestamp: buf[88..116].try_into().unwrap(),
            mac1: buf[116..132].try_into().unwrap(),
            mac2: buf[132..148].try_into().unwrap(),
        }),
        MSG_TYPE_RESPONSE if buf.len() == MSG_RESPONSE_LEN => Some(WgMsg::Response {
            sender: le32(&buf[4..8]),
            receiver: le32(&buf[8..12]),
            ephemeral: buf[12..44].try_into().unwrap(),
            enc_nothing: buf[44..60].try_into().unwrap(),
            mac1: buf[60..76].try_into().unwrap(),
            mac2: buf[76..92].try_into().unwrap(),
        }),
        MSG_TYPE_COOKIE if buf.len() == MSG_COOKIE_LEN => Some(WgMsg::Cookie {
            receiver: le32(&buf[4..8]),
            nonce: buf[8..32].try_into().unwrap(),
            enc_cookie: buf[32..64].try_into().unwrap(),
        }),
        MSG_TYPE_TRANSPORT if buf.len() >= TRANSPORT_HEADER_LEN + 16 => Some(WgMsg::Transport {
            receiver: le32(&buf[4..8]),
            counter: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            data: buf[TRANSPORT_HEADER_LEN..].to_vec(),
        }),
        _ => None,
    }
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().unwrap())
}

/// mihomo `reserved` handling at the raw-socket boundary: bytes 1..3 of
/// every outgoing datagram carry the configured bytes (see module docs).
fn apply_reserved(msg: &mut [u8], reserved: [u8; 3]) {
    if msg.len() > 3 {
        msg[1..4].copy_from_slice(&reserved);
    }
}

/// Inbound dual: zero bytes 1..3 before parsing / MAC verification.
fn strip_reserved(msg: &mut [u8]) {
    if msg.len() > 3 {
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 0;
    }
}

// ---------------------------------------------------------------------------
// Noise_IKpsk2 handshake — initiator (client) side
// ---------------------------------------------------------------------------

/// State kept between sending an initiation and consuming the response.
struct InitiationPending {
    local_index: u32,
    e_priv: [u8; 32],
    chaining_key: [u8; 32],
    hash: [u8; 32],
    /// MAC1 of the initiation, the AAD of a cookie reply.
    last_mac1: [u8; 16],
    attempts: u32,
}

impl InitiationPending {
    fn zero(&mut self) {
        self.e_priv.iter_mut().for_each(|b| *b = 0);
        self.chaining_key.iter_mut().for_each(|b| *b = 0);
        self.hash.iter_mut().for_each(|b| *b = 0);
    }
}

/// Build a handshake initiation message (148 bytes) plus the state needed
/// to consume the response. Transcribed step-for-step from the protocol
/// page's "First Message" block.
fn build_initiation(
    statics: &StaticKeys,
    peer_pk: &[u8; 32],
    cookie: Option<[u8; 16]>,
    local_index: u32,
) -> Result<(Vec<u8>, InitiationPending)> {
    // initiator.chaining_key = HASH(CONSTRUCTION)
    let mut ck = blake2s256(CONSTRUCTION);
    // initiator.hash = HASH(HASH(chaining_key || IDENTIFIER) || responder static)
    let ident_hash = hash2(&ck, IDENTIFIER);
    let mut h = hash2(&ident_hash, peer_pk);

    let ephemeral = x25519_keypair();
    // hash = HASH(hash || ephemeral pub); ck = KDF1(ck, ephemeral pub)
    h = hash2(&h, &ephemeral.pk);
    ck = kdf1(&ck, &ephemeral.pk);

    // es: (ck, key) = KDF2(ck, DH(e_priv, responder static))
    let es = x25519_dh(&ephemeral.sk, peer_pk)?;
    let (ck, key_es) = kdf2(&ck, &es);
    let enc_static = aead_seal(&key_es, 0, &statics.pk, &h)?;
    h = hash2(&h, &enc_static);

    // ss: (ck, key) = KDF2(ck, DH(s_priv, responder static))
    let ss = x25519_dh(&statics.sk, peer_pk)?;
    let (ck, key_ss) = kdf2(&ck, &ss);
    let timestamp = tai64n_now();
    let enc_timestamp = aead_seal(&key_ss, 0, &timestamp, &h)?;
    h = hash2(&h, &enc_timestamp);

    let mut msg = Vec::with_capacity(MSG_INITIATION_LEN);
    msg.extend_from_slice(&1u32.to_le_bytes());
    msg.extend_from_slice(&local_index.to_le_bytes());
    msg.extend_from_slice(&ephemeral.pk);
    msg.extend_from_slice(&enc_static);
    msg.extend_from_slice(&enc_timestamp);
    // mac1 = MAC(HASH(LABEL_MAC1 || responder static), msg[..116])
    let mac1 = blake2s_mac(&mac1_key(peer_pk), &msg);
    msg.extend_from_slice(&mac1);
    // mac2 = MAC(last_received_cookie, msg[..132]) or zeros
    let mac2 = cookie.map(|c| blake2s_mac(&c, &msg));
    msg.extend_from_slice(&mac2.unwrap_or([0u8; 16]));
    debug_assert_eq!(msg.len(), MSG_INITIATION_LEN);

    Ok((
        msg,
        InitiationPending {
            local_index,
            e_priv: ephemeral.sk,
            chaining_key: ck,
            hash: h,
            last_mac1: mac1,
            attempts: 1,
        },
    ))
}

/// Result of a completed handshake: transport keys plus the peer's session
/// index for outbound message headers.
struct HandshakeDone {
    local_index: u32,
    peer_index: u32,
    /// Initiator sending key (temp2 in the whitepaper's derivation).
    send_key: [u8; 32],
    /// Initiator receiving key (temp3).
    recv_key: [u8; 32],
}

/// Consume a handshake response (92 bytes) against a pending initiation,
/// verifying MAC1, the receiver index and the encrypted-empty MAC, and
/// deriving the transport keys. Mirrors the "Second Message" block.
fn consume_response(
    statics: &StaticKeys,
    pending: &mut InitiationPending,
    msg: &WgMsg,
    psk: &[u8; 32],
) -> Result<HandshakeDone> {
    let WgMsg::Response {
        sender,
        receiver,
        ephemeral,
        enc_nothing,
        mac1,
        ..
    } = msg
    else {
        return Err(Error::protocol("wg: not a handshake response"));
    };
    if *receiver != pending.local_index {
        return Err(Error::protocol("wg: response for a stale handshake"));
    }
    // mac1 = MAC(HASH(LABEL_MAC1 || initiator static), msg[..60]) — the
    // responder learned our static from the initiation.
    let mut raw = Vec::with_capacity(MSG_RESPONSE_LEN);
    raw.extend_from_slice(&2u32.to_le_bytes());
    raw.extend_from_slice(&sender.to_le_bytes());
    raw.extend_from_slice(&receiver.to_le_bytes());
    raw.extend_from_slice(ephemeral);
    raw.extend_from_slice(enc_nothing);
    if blake2s_mac(&mac1_key(&statics.pk), &raw) != *mac1 {
        return Err(Error::crypto("wg: handshake response MAC1 mismatch"));
    }

    let mut h = pending.hash;
    let mut ck = pending.chaining_key;
    // e_r: hash = HASH(hash || e_r pub); ck = KDF1(ck, e_r pub)
    h = hash2(&h, ephemeral);
    ck = kdf1(&ck, ephemeral);
    // ee: ck = KDF1(ck, DH(e_i priv, e_r pub))
    let ee = x25519_dh(&pending.e_priv, ephemeral)?;
    ck = kdf1(&ck, &ee);
    // se: ck = KDF1(ck, DH(s_i priv, e_r pub))
    let se = x25519_dh(&statics.sk, ephemeral)?;
    ck = kdf1(&ck, &se);
    // psk2: (ck, temp2, key) = KDF3(ck, psk); hash = HASH(hash || temp2)
    let (ck, temp2, key) = kdf3(&ck, psk);
    h = hash2(&h, &temp2);
    // encrypted_nothing must open to the empty plaintext under `hash`.
    aead_open(&key, 0, enc_nothing, &h)?;
    // hash = HASH(hash || encrypted_nothing): the transcript step exists
    // on both sides, but the initiator's transport keys derive from the
    // chaining key alone, so its final hash is intentionally unread.
    let _ = hash2(&h, enc_nothing);
    // Transport keys: temp1 = HMAC(ck, empty); send = temp2', recv = temp3'.
    let (send_key, recv_key) = derive_transport_keys(&ck);

    let done = HandshakeDone {
        local_index: pending.local_index,
        peer_index: *sender,
        send_key,
        recv_key,
    };
    pending.zero();
    Ok(done)
}

/// Consume a cookie reply (64 bytes) for a pending initiation:
/// cookie = XAEAD_open(HASH(LABEL_COOKIE || responder static), nonce,
/// enc_cookie, last_sent_msg.mac1). Returns the 16-byte cookie for MAC2.
fn consume_cookie_reply(
    peer_pk: &[u8; 32],
    pending: &InitiationPending,
    msg: &WgMsg,
) -> Result<[u8; 16]> {
    let WgMsg::Cookie {
        receiver,
        nonce,
        enc_cookie,
    } = msg
    else {
        return Err(Error::protocol("wg: not a cookie reply"));
    };
    if *receiver != pending.local_index {
        return Err(Error::protocol("wg: cookie reply for a stale handshake"));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(&cookie_key(peer_pk))
        .map_err(|_| Error::crypto("wg: bad cookie key"))?;
    let plain = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: enc_cookie,
                aad: &pending.last_mac1,
            },
        )
        .map_err(|_| Error::crypto("wg: cookie reply failed to decrypt"))?;
    plain
        .try_into()
        .map_err(|_| Error::protocol("wg: cookie reply has wrong length"))
}

// ---------------------------------------------------------------------------
// Transport session
// ---------------------------------------------------------------------------

/// One direction's cipher state.
struct SendHalf {
    cipher: ChaCha20Poly1305,
    next: u64,
}

struct RecvHalf {
    cipher: ChaCha20Poly1305,
    replay: AntiReplay,
}

fn make_cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new_from_slice(key).expect("32-byte key")
}

/// An established transport session. The client is always the initiator,
/// so rekey timers run on our side.
struct Session {
    local_index: u32,
    peer_index: u32,
    created: Instant,
    last_tx: Instant,
    last_rx: Instant,
    send: SendHalf,
    recv: RecvHalf,
}

impl Session {
    fn from_handshake(done: HandshakeDone, now: Instant) -> Self {
        Session {
            local_index: done.local_index,
            peer_index: done.peer_index,
            created: now,
            last_tx: now,
            last_rx: now,
            send: SendHalf {
                cipher: make_cipher(&done.send_key),
                next: 0,
            },
            recv: RecvHalf {
                cipher: make_cipher(&done.recv_key),
                replay: AntiReplay::new(),
            },
        }
    }

    /// Encrypt one inner IP packet into a full transport datagram. The
    /// counter is claimed first (post-increment), the payload is
    /// zero-padded to a multiple of 16, the AAD is empty.
    fn seal_transport(&mut self, inner: &[u8]) -> Result<Vec<u8>> {
        if self.send.next >= REJECT_AFTER_MESSAGES {
            return Err(Error::protocol("wg: session counter exhausted (reject-after)"));
        }
        let counter = self.send.next;
        self.send.next += 1;
        let mut plain = inner.to_vec();
        while !plain.len().is_multiple_of(PADDING_MULTIPLE) {
            plain.push(0);
        }
        let ct = self
            .send
            .cipher
            .encrypt(
                (&aead_nonce(counter)).into(),
                Payload { msg: &plain, aad: &[] },
            )
            .map_err(|_| Error::crypto("wg: transport seal failed"))?;
        let mut msg = Vec::with_capacity(TRANSPORT_HEADER_LEN + ct.len());
        msg.extend_from_slice(&(MSG_TYPE_TRANSPORT as u32).to_le_bytes());
        msg.extend_from_slice(&self.peer_index.to_le_bytes());
        msg.extend_from_slice(&counter.to_le_bytes());
        msg.extend_from_slice(&ct);
        self.last_tx = Instant::now();
        Ok(msg)
    }

    /// Decrypt a transport payload: tag first, then the replay window
    /// (whitepaper: the window is "checked after verifying the
    /// authentication tag").
    fn open_transport(&mut self, counter: u64, data: &[u8]) -> Result<Vec<u8>> {
        let plain = self
            .recv
            .cipher
            .decrypt(
                (&aead_nonce(counter)).into(),
                Payload { msg: data, aad: &[] },
            )
            .map_err(|_| Error::crypto("wg: transport open failed"))?;
        if !self.recv.replay.accept(counter) {
            return Err(Error::protocol("wg: replayed or too-old transport counter"));
        }
        Ok(plain)
    }

    fn sent(&self) -> u64 {
        self.send.next
    }
}

/// Trim AEAD padding off a decrypted inner packet: peers pad to a
/// multiple of 16, and the IPv4 total-length field says how much is real.
fn trim_ip_packet(pkt: &mut Vec<u8>) {
    if pkt.len() >= 20 && pkt[0] >> 4 == 4 {
        let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if total >= 20 && total <= pkt.len() {
            pkt.truncate(total);
        }
    }
}

// --- pure timer decisions (unit-tested with synthetic instants) ----------

/// Initiator-side rekey trigger: REKEY_AFTER_TIME of session age or
/// REKEY_AFTER_MESSAGES of traffic, whichever comes first.
fn should_rekey(created: Instant, sent: u64, now: Instant) -> bool {
    now.duration_since(created) >= REKEY_AFTER_TIME || sent >= REKEY_AFTER_MESSAGES
}

/// REJECT_AFTER_TIME: keys older than this are dead.
fn session_expired(created: Instant, now: Instant) -> bool {
    now.duration_since(created) >= REJECT_AFTER_TIME
}

/// Keepalive: transmit silence of KEEPALIVE_TIMEOUT after a received
/// packet.
fn needs_keepalive(last_tx: Instant, now: Instant) -> bool {
    now.duration_since(last_tx) >= KEEPALIVE_TIMEOUT
}

// ---------------------------------------------------------------------------
// TCP bridge (mirrors inbound/tun's TunStream: two bounded queues, one
// mutex, two wakers, a Notify ping to the stack task)
// ---------------------------------------------------------------------------

const STREAM_QUEUE_MAX: usize = 128 * 1024;

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
            bufs: Mutex::new(StreamBufs {
                to_proxy: VecDeque::new(),
                to_stack: VecDeque::new(),
                read_eof: false,
                write_closed: false,
                aborted: false,
                read_waker: None,
                write_waker: None,
            }),
            wake,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, StreamBufs> {
        self.bufs.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One TCP connection through the WireGuard tunnel, as seen by the relay.
pub struct WgStream {
    shared: Arc<StreamShared>,
}

impl Drop for WgStream {
    fn drop(&mut self) {
        let mut g = self.shared.lock();
        g.aborted = true;
        g.read_eof = true;
        g.write_closed = true;
        drop(g);
        self.shared.wake.notify_one();
    }
}

impl AsyncRead for WgStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
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
            // Freed queue space is stack input: the socket behind it may hold
            // data the service loop could not move (and a peer waiting on the
            // window this drain just re-opened). Wake the stack task instead
            // of letting the connection idle until the driver's 1s tick.
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

impl AsyncWrite for WgStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut g = self.shared.lock();
        if g.aborted || g.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wg: stream is closed",
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

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.shared.lock().write_closed = true;
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// smoltcp device shim: egress IP packets are queued for encryption,
// ingress packets (decrypted by the task) are staged for the next poll
// ---------------------------------------------------------------------------

const TCP_RX_BYTES: usize = 64 * 1024;
const TCP_TX_BYTES: usize = 64 * 1024;
const UDP_RX_BYTES: usize = 32 * 1024;
const UDP_TX_BYTES: usize = 32 * 1024;
const UDP_PACKETS: usize = 64;
/// Egress packets queued while no session exists (pre-handshake SYNs and
/// first writes); once full, further egress is dropped.
const PRE_SESSION_QUEUE_MAX: usize = 512;
const MAX_CONNS: usize = 128;
const MAX_UDP_SOCKETS: usize = 64;
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_TICK: Duration = Duration::from_millis(1);
const MAX_TICK: Duration = Duration::from_secs(1);
const PUMP_CHUNK: usize = 32 * 1024;

struct Shim {
    ingress: VecDeque<Vec<u8>>,
    /// Raw IP packets emitted by the stack since the last drain.
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
        if self.ingress.len() < PRE_SESSION_QUEUE_MAX {
            self.ingress.push_back(pkt.to_vec());
        }
    }
}

impl Device for Shim {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(RxTok, TxTok<'_>)> {
        let pkt = self.ingress.pop_front()?;
        Some((
            RxTok { pkt },
            TxTok {
                egress: &mut self.egress,
                scratch: &mut self.scratch,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<TxTok<'_>> {
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
// The tunnel task: handshake + session + netstack, one owner
// ---------------------------------------------------------------------------

/// Where a WgUdp's inbound datagrams arrive.
type UdpDownlink = mpsc::Receiver<(NetAddr, Vec<u8>)>;

/// Commands from the public API to the tunnel task.
enum Cmd {
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

struct Conn {
    handle: SocketHandle,
    shared: Arc<StreamShared>,
    fin_sent: bool,
    /// Still awaiting ESTABLISHED: reply + deadline.
    pending: Option<(oneshot::Sender<Result<Arc<StreamShared>>>, Instant)>,
}

struct UdpSock {
    handle: SocketHandle,
    port: u16,
    down: mpsc::Sender<(NetAddr, Vec<u8>)>,
}

struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    shim: Shim,
    statics: StaticKeys,
    peer_pk: [u8; 32],
    psk: [u8; 32],
    local_ip: Ipv4Addr,
    local_ipv6: Option<Ipv6Addr>,
    reserved: [u8; 3],
    udp_enabled: bool,
    endpoint: SocketAddr,
    /// Outgoing handshake awaiting a response.
    pending_hs: Option<InitiationPending>,
    hs_retry_at: Option<Instant>,
    last_initiation: Option<Instant>,
    cookie: Option<([u8; 16], Instant)>,
    session: Option<Session>,
    local_index: u32,
    conns: Vec<Conn>,
    udp: HashMap<u32, UdpSock>,
    used_ports: HashSet<u16>,
    next_udp_id: u32,
    pre_session_tx: VecDeque<Vec<u8>>,
    wake: Arc<Notify>,
    start: Instant,
    pump_buf: Vec<u8>,
}

impl Stack {
    #[allow(clippy::too_many_arguments)]
    fn new(
        cfg: &WgOut,
        statics: StaticKeys,
        peer_pk: [u8; 32],
        psk: [u8; 32],
        endpoint: SocketAddr,
        wake: Arc<Notify>,
    ) -> Result<Self> {
        let mtu = cfg.effective_mtu();
        let mut shim = Shim::new(mtu);
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        // Random ISNs and ephemeral ports: two tunnels on one host must
        // not pick colliding sequence numbers.
        iface_cfg.random_seed = rand::random();
        let mut iface = Interface::new(iface_cfg, &mut shim, SmolInstant::ZERO);
        iface.update_ip_addrs(|addrs| {
            // Point-to-point /32 (and /128): the peer is reached through the
            // default routes below, and the local address doubles as the
            // route gateway — the same shape the TUN netstack uses. The v6
            // address is exactly what the provider assigned (sing-wireguard
            // `device_stack.go` `NewStackDevice` adds the configured
            // prefixes verbatim and derives nothing).
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(cfg.local_ip), 32));
            if let Some(v6) = cfg.local_ipv6 {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(v6), 128));
            }
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(cfg.local_ip)
            .map_err(|_| Error::network("wg: route table full"))?;
        // A default route per family in use (smoltcp's any_ip/route coupling,
        // as in the TUN netstack).
        if let Some(v6) = cfg.local_ipv6 {
            iface
                .routes_mut()
                .add_default_ipv6_route(v6)
                .map_err(|_| Error::network("wg: route table full"))?;
        }

        Ok(Stack {
            iface,
            sockets: SocketSet::new(Vec::new()),
            shim,
            statics,
            peer_pk,
            psk,
            local_ip: cfg.local_ip,
            local_ipv6: cfg.local_ipv6,
            reserved: cfg.reserved,
            udp_enabled: cfg.udp,
            endpoint,
            pending_hs: None,
            hs_retry_at: None,
            last_initiation: None,
            cookie: None,
            session: None,
            local_index: rand::random(),
            conns: Vec::new(),
            udp: HashMap::new(),
            used_ports: HashSet::new(),
            next_udp_id: 1,
            pre_session_tx: VecDeque::new(),
            wake,
            start: Instant::now(),
            pump_buf: vec![0u8; PUMP_CHUNK],
        })
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
    }

    fn std_now(&self) -> Instant {
        Instant::now()
    }

    fn ephemeral_port(&mut self) -> u16 {
        loop {
            let port = 32768 + rand::random::<u16>() % 28_000;
            if self.used_ports.insert(port) {
                return port;
            }
        }
    }

    /// The socket endpoint for a target, as smoltcp wants it.
    fn ip_endpoint(dst: &SocketAddr) -> IpEndpoint {
        match dst {
            SocketAddr::V4(v4) => IpEndpoint::new(IpAddress::Ipv4(*v4.ip()), v4.port()),
            SocketAddr::V6(v6) => IpEndpoint::new(IpAddress::Ipv6(*v6.ip()), v6.port()),
        }
    }

    /// Source-address selection: each dial binds to the configured address
    /// of the *destination's family* — sing-wireguard's `DialContext` does
    /// exactly this with its `addr4`/`addr6` (`device_stack.go:104-119`).
    fn local_address_for(&self, dst: &SocketAddr) -> IpAddress {
        match dst {
            SocketAddr::V4(_) => IpAddress::Ipv4(self.local_ip),
            // target_addr already refused v6 targets when no v6 address is
            // configured; the mirror keeps the lookup total.
            SocketAddr::V6(_) => {
                IpAddress::Ipv6(self.local_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED))
            }
        }
    }

    // -- handshake ----------------------------------------------------------

    /// Start (or restart) a handshake, honouring the REKEY_TIMEOUT rate
    /// limit. Retries reuse a fresh ephemeral and timestamp.
    async fn initiate(&mut self, socket: &UdpSocket, force: bool) {
        let now = self.std_now();
        if !force {
            if let Some(last) = self.last_initiation {
                if now.duration_since(last) < REKEY_TIMEOUT {
                    return;
                }
            }
        }
        if let Some(p) = &mut self.pending_hs {
            if p.attempts >= MAX_HANDSHAKE_ATTEMPTS {
                return; // give up until new traffic triggers us again
            }
            p.attempts += 1;
        }
        self.last_initiation = Some(now);
        let cookie = self
            .cookie
            .filter(|(_, at)| now.duration_since(*at) < COOKIE_REFRESH_TIME)
            .map(|(c, _)| c);
        match build_initiation(&self.statics, &self.peer_pk, cookie, self.local_index) {
            Ok((msg, mut pending)) => {
                if let Some(old) = self.pending_hs.as_mut() {
                    pending.attempts = old.attempts;
                }
                self.pending_hs = Some(pending);
                self.hs_retry_at = Some(now + REKEY_TIMEOUT);
                self.send_raw(socket, &msg).await;
                tracing::debug!(
                    target: "engine",
                    "wg: initiation sent to {} (index {})",
                    self.endpoint,
                    self.local_index
                );
            }
            Err(e) => {
                tracing::debug!(target: "engine", "wg: cannot build initiation: {e}");
            }
        }
    }

    /// Raw datagram out with the mihomo reserved-byte rewrite. Awaited so
    /// a momentarily full socket buffer back-pressures instead of dropping
    /// handshakes.
    async fn send_raw(&self, socket: &UdpSocket, msg: &[u8]) {
        let mut buf = msg.to_vec();
        apply_reserved(&mut buf, self.reserved);
        if let Err(e) = socket.send_to(&buf, self.endpoint).await {
            tracing::debug!(target: "engine", "wg: udp send to {} failed: {e}", self.endpoint);
        }
    }

    /// Encrypt and send one inner IP packet if a live session exists;
    /// otherwise queue it for the moment the handshake completes.
    async fn send_inner(&mut self, socket: &UdpSocket, pkt: &[u8]) {
        match self.session.as_mut().map(|s| s.seal_transport(pkt)) {
            Some(Ok(msg)) => self.send_raw(socket, &msg).await,
            Some(Err(e)) => tracing::debug!(target: "engine", "wg: seal failed: {e}"),
            None => {
                if self.pre_session_tx.len() < PRE_SESSION_QUEUE_MAX {
                    self.pre_session_tx.push_back(pkt.to_vec());
                }
            }
        }
    }

    async fn on_handshake_done(&mut self, socket: &UdpSocket, done: HandshakeDone) {
        let now = self.std_now();
        self.session = Some(Session::from_handshake(done, now));
        self.pending_hs = None;
        self.hs_retry_at = None;
        // A fresh local index for the next handshake.
        self.local_index = rand::random();
        tracing::debug!(target: "engine", "wg: session established with {}", self.endpoint);
        // Flush everything that piled up before the handshake, and give
        // the responder the key confirmation it waits for (whitepaper:
        // the initiator should send an empty packet if it has nothing
        // queued).
        let queued: Vec<Vec<u8>> = self.pre_session_tx.drain(..).collect();
        for pkt in queued {
            self.send_inner(socket, &pkt).await;
        }
        let confirm = self
            .session
            .as_mut()
            .and_then(|s| s.seal_transport(&[]).ok());
        if let Some(msg) = confirm {
            self.send_raw(socket, &msg).await;
        }
    }

    // -- inbound datagram ---------------------------------------------------

    async fn on_datagram(&mut self, socket: &UdpSocket, raw: &mut [u8]) {
        strip_reserved(raw);
        let Some(msg) = parse_wg_msg(raw) else {
            tracing::debug!(target: "engine", "wg: dropping malformed datagram");
            return;
        };
        match msg {
            WgMsg::Transport { receiver, counter, data } => {
                let Some(session) = self.session.as_mut() else {
                    return;
                };
                if session.local_index != receiver {
                    return; // stale session
                }
                match session.open_transport(counter, &data) {
                    Ok(mut inner) => {
                        session.last_rx = Instant::now();
                        if inner.is_empty() {
                            return; // keepalive
                        }
                        trim_ip_packet(&mut inner);
                        self.shim.stage(&inner);
                        self.wake_notify();
                    }
                    Err(e) => {
                        // Replays and corruption are dropped silently; a
                        // dead key schedules a re-handshake.
                        tracing::debug!(target: "engine", "wg: transport open failed: {e}");
                    }
                }
            }
            WgMsg::Response { .. } => {
                if let Some(mut pending) = self.pending_hs.take() {
                    match consume_response(&self.statics, &mut pending, &msg, &self.psk) {
                        Ok(done) => self.on_handshake_done(socket, done).await,
                        Err(e) => {
                            pending.zero();
                            tracing::debug!(target: "engine", "wg: rejecting handshake response: {e}");
                        }
                    }
                }
            }
            WgMsg::Cookie { .. } => {
                if let Some(pending) = &self.pending_hs {
                    match consume_cookie_reply(&self.peer_pk, pending, &msg) {
                        Ok(cookie) => {
                            tracing::debug!(target: "engine", "wg: cookie learned, retrying with MAC2");
                            self.cookie = Some((cookie, self.std_now()));
                            self.initiate(socket, true).await;
                        }
                        Err(e) => {
                            tracing::debug!(target: "engine", "wg: bad cookie reply: {e}")
                        }
                    }
                }
            }
            WgMsg::Initiation { .. } => {
                // We are a client with a fixed peer; initiations from the
                // peer are not a thing.
                tracing::debug!(target: "engine", "wg: unexpected initiation from peer, dropped");
            }
        }
    }

    fn wake_notify(&self) {
        self.wake.notify_one();
    }

    // -- commands ------------------------------------------------------------

    async fn on_cmd(&mut self, socket: &UdpSocket, cmd: Cmd) {
        match cmd {
            Cmd::Connect { remote, reply } => {
                self.ensure_session(socket).await;
                if self.conns.len() >= MAX_CONNS {
                    let _ = reply.send(Err(Error::network("wg: connection limit reached")));
                    return;
                }
                let mut sock = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; TCP_RX_BYTES]),
                    tcp::SocketBuffer::new(vec![0; TCP_TX_BYTES]),
                );
                let port = self.ephemeral_port();
                let local = IpListenEndpoint {
                    addr: Some(self.local_address_for(&remote)),
                    port,
                };
                let cx = self.iface.context();
                let res = sock.connect(cx, Self::ip_endpoint(&remote), local);
                if let Err(e) = res {
                    let _ = reply.send(Err(Error::network(format!("wg: connect: {e:?}"))));
                    return;
                }
                let handle = self.sockets.add(sock);
                let shared = Arc::new(StreamShared::new(self.wake.clone()));
                tracing::debug!(target: "engine", "wg: dialing {remote} through {}", self.endpoint);
                self.conns.push(Conn {
                    handle,
                    shared: shared.clone(),
                    fin_sent: false,
                    pending: Some((reply, self.std_now() + TCP_CONNECT_TIMEOUT)),
                });
            }
            Cmd::UdpOpen { reply } => {
                if !self.udp_enabled {
                    let _ = reply.send(Err(Error::network("wg: udp is disabled for this peer")));
                    return;
                }
                if self.udp.len() >= MAX_UDP_SOCKETS {
                    let _ = reply.send(Err(Error::network("wg: udp socket limit reached")));
                    return;
                }
                self.ensure_session(socket).await;
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
                if let Err(e) = sock.bind(IpListenEndpoint { addr: None, port }) {
                    let _ = reply.send(Err(Error::network(format!("wg: udp bind: {e:?}"))));
                    return;
                }
                let handle = self.sockets.add(sock);
                let id = self.next_udp_id;
                self.next_udp_id += 1;
                let (tx, rx) = mpsc::channel::<(NetAddr, Vec<u8>)>(64);
                self.udp.insert(
                    id,
                    UdpSock {
                        handle,
                        port,
                        down: tx,
                    },
                );
                let _ = reply.send(Ok((id, rx)));
            }
            Cmd::UdpSend { id, dst, data } => {
                let Some(handle) = self.udp.get(&id).map(|u| u.handle) else {
                    return;
                };
                self.ensure_session(socket).await;
                let mut meta = udp::UdpMetadata::from(Self::ip_endpoint(&dst));
                meta.local_address = Some(self.local_address_for(&dst));
                let sock = self.sockets.get_mut::<udp::Socket>(handle);
                if let Err(e) = sock.send_slice(&data, meta) {
                    tracing::debug!(target: "engine", "wg: udp send to {dst}: {e:?}");
                }
            }
            Cmd::UdpClose { id } => {
                if let Some(u) = self.udp.remove(&id) {
                    self.sockets.remove(u.handle);
                    self.used_ports.remove(&u.port);
                }
            }
        }
    }

    /// Make sure a handshake is in flight whenever there is traffic to
    /// send and no live session.
    async fn ensure_session(&mut self, socket: &UdpSocket) {
        let expired = self
            .session
            .as_ref()
            .is_some_and(|s| session_expired(s.created, self.std_now()));
        if expired {
            tracing::debug!(target: "engine", "wg: session rejected after time, rekeying");
            self.session = None;
        }
        if self.session.is_none() && self.pending_hs.is_none() {
            self.initiate(socket, false).await;
        }
    }

    // -- netstack service ---------------------------------------------------

    /// One pass: poll, service the bridge sockets, flush egress.
    async fn step(&mut self, socket: &UdpSocket) {
        let now = self.now();
        self.iface.poll(now, &mut self.shim, &mut self.sockets);

        self.service_conns();
        self.drain_udp_rx();

        let now = self.now();
        self.iface.poll(now, &mut self.shim, &mut self.sockets);
        self.drain_egress(socket).await;
    }

    /// Move bytes between smoltcp sockets and stream queues; finish or
    /// fail pending connects. Mirrors the TUN netstack's service_conns.
    fn service_conns(&mut self) {
        let now = Instant::now();
        let mut dead: Vec<SocketHandle> = Vec::new();
        for c in self.conns.iter_mut() {
            let sock = self.sockets.get_mut::<tcp::Socket>(c.handle);

            // Pending dial: report once the outcome is known.
            if let Some((reply, deadline)) = c.pending.take() {
                match sock.state() {
                    tcp::State::Established => {
                        let _ = reply.send(Ok(c.shared.clone()));
                    }
                    s if s == tcp::State::Closed || now >= deadline => {
                        let _ = reply.send(Err(Error::network(format!(
                            "wg: tcp dial failed (state {s:?})"
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

            // stack -> proxy
            while g.to_proxy.len() < STREAM_QUEUE_MAX && sock.can_recv() {
                let n = match sock.recv_slice(&mut self.pump_buf) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                g.to_proxy.extend(self.pump_buf[..n].iter().copied());
            }
            // EOF only once the connection is past dialing: `may_recv()`
            // is false in SynSent too, which is a pending dial, not EOF.
            let dialing = matches!(sock.state(), tcp::State::SynSent | tcp::State::Listen);
            if !dialing && !sock.may_recv() && sock.recv_queue() == 0 {
                g.read_eof = true;
            }

            // proxy -> stack
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
                // Closed without our own graceful FIN = the peer reset (or we
                // aborted): writers must fail now instead of queuing into a
                // dead socket forever (wave-12: mid-burst RST hung write_all).
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
            drop(g);
            if gone {
                dead.push(c.handle);
            }
        }
        if !dead.is_empty() {
            self.conns.retain(|c| !dead.contains(&c.handle));
            for handle in dead {
                if let Some(sock) = self.sockets.get::<tcp::Socket>(handle).local_endpoint() {
                    self.used_ports.remove(&sock.port);
                }
                self.sockets.remove(handle);
            }
        }
    }

    /// Deliver inbound datagrams from the smoltcp UDP sockets to their
    /// WgUdp channels.
    fn drain_udp_rx(&mut self) {
        let ids: Vec<u32> = self.udp.keys().copied().collect();
        for id in ids {
            let (handle, down) = match self.udp.get(&id) {
                Some(u) => (u.handle, &u.down),
                None => continue,
            };
            let sock = self.sockets.get_mut::<udp::Socket>(handle);
            while sock.can_recv() {
                let (n, meta) = match sock.recv_slice(&mut self.pump_buf) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let from = match meta.endpoint.addr {
                    IpAddress::Ipv4(src) => NetAddr::ip(IpAddr::V4(src), meta.endpoint.port),
                    IpAddress::Ipv6(src) => NetAddr::ip(IpAddr::V6(src), meta.endpoint.port),
                };
                let _ = down.try_send((from, self.pump_buf[..n].to_vec()));
            }
        }
    }

    /// Egress IP packets from the shim: encrypt into transport messages
    /// (or queue pre-handshake) and put on the wire.
    async fn drain_egress(&mut self, socket: &UdpSocket) {
        let pkts: Vec<Vec<u8>> = self.shim.egress.drain(..).collect();
        for pkt in pkts {
            self.send_inner(socket, &pkt).await;
        }
    }

    // -- timers --------------------------------------------------------------

    async fn on_timer(&mut self, socket: &UdpSocket) {
        let now = Instant::now();
        // Session lifetime: reject-after kills the keys, rekey-after (or a
        // message-count trigger) rotates them early, keepalive fills
        // transmit silence.
        enum Action {
            Expire,
            Rekey,
            Keepalive,
        }
        let action = match self.session.as_ref() {
            Some(s) if session_expired(s.created, now) => Some(Action::Expire),
            Some(s) if should_rekey(s.created, s.sent(), now) => Some(Action::Rekey),
            Some(s) if needs_keepalive(s.last_tx, now) => Some(Action::Keepalive),
            _ => None,
        };
        match action {
            Some(Action::Expire) => {
                tracing::debug!(target: "engine", "wg: session expired, dropping keys");
                self.session = None;
            }
            Some(Action::Rekey) => self.initiate(socket, false).await,
            Some(Action::Keepalive) => {
                // mihomo's persistent-keepalive shape: an empty transport
                // message every 10s of transmit silence.
                let msg = self
                    .session
                    .as_mut()
                    .and_then(|s| s.seal_transport(&[]).ok());
                if let Some(msg) = msg {
                    self.send_raw(socket, &msg).await;
                }
            }
            None => {}
        }
        if let Some(retry_at) = self.hs_retry_at {
            if now >= retry_at {
                self.hs_retry_at = None;
                self.initiate(socket, false).await;
            }
        }
    }

    /// When the loop should wake up on its own.
    fn next_deadline(&mut self) -> Instant {
        let now = self.std_now();
        let stack = self
            .iface
            .poll_delay(self.now(), &self.sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(MAX_TICK);
        let mut until = now + stack;
        if let Some(at) = self.hs_retry_at {
            until = until.min(at);
        }
        if let Some(session) = self.session.as_ref() {
            until = until.min(session.created + REJECT_AFTER_TIME);
            if should_rekey(session.created, session.sent(), now) {
                until = now; // rekey due right now
            }
            if needs_keepalive(session.last_tx, now) {
                until = now;
            }
        }
        for c in &self.conns {
            if let Some((_, deadline)) = &c.pending {
                until = until.min(*deadline);
            }
        }
        until
    }
}

/// Drive one tunnel until the last command sender is gone (the cache keeps
/// one, so in practice this is the outbound's lifetime).
async fn run_stack(
    mut stack: Stack,
    socket: Arc<UdpSocket>,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    wake: Arc<Notify>,
) {
    let mut rx = vec![0u8; 65_536];
    loop {
        stack.step(&socket).await;
        // Clamp the stack's own deadline so the loop always makes progress
        // without busy-spinning.
        let offset = stack
            .next_deadline()
            .saturating_duration_since(Instant::now())
            .clamp(MIN_TICK, MAX_TICK);
        let deadline = Instant::now() + offset;
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::select! {
            biased;
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(c) => stack.on_cmd(&socket, c).await,
                    None => break,
                }
            }
            _ = wake.notified() => {}
            r = socket.recv_from(&mut rx) => {
                match r {
                    Ok((n, peer)) => {
                        if peer == stack.endpoint {
                            stack.on_datagram(&socket, &mut rx[..n]).await;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(target: "engine", "wg: udp recv error: {e}");
                    }
                }
            }
            _ = sleep => {
                stack.on_timer(&socket).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// One shared tunnel per distinct WgOut identity (server, keys, addresses).
static TUNNELS: std::sync::OnceLock<tokio::sync::Mutex<HashMap<String, mpsc::Sender<Cmd>>>> =
    std::sync::OnceLock::new();

fn cache_key(cfg: &WgOut) -> String {
    [
        cfg.server.as_str(),
        &cfg.port.to_string(),
        &cfg.private_key,
        &cfg.peer_public_key,
        cfg.pre_shared_key.as_deref().unwrap_or(""),
        &cfg.local_ip.to_string(),
        cfg.local_ipv6
            .as_ref()
            .map(std::net::Ipv6Addr::to_string)
            .as_deref()
            .unwrap_or(""),
        &cfg.effective_mtu().to_string(),
        &format!("{:?}", cfg.reserved),
        &cfg.udp.to_string(),
    ]
    .join("\u{1f}")
}

async fn tunnel_for(cfg: &WgOut) -> Result<mpsc::Sender<Cmd>> {
    let key = cache_key(cfg);
    let cache = TUNNELS.get_or_init(Default::default);
    let mut map = cache.lock().await;
    if let Some(tx) = map.get(&key) {
        if !tx.is_closed() {
            return Ok(tx.clone());
        }
    }
    let (tx, rx) = mpsc::channel::<Cmd>(64);
    let (statics, peer_pk, psk) = cfg.keys()?;
    let endpoint = resolve_endpoint(&cfg.server, cfg.port).await?;
    let bind_addr = if endpoint.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = Arc::new(
        UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| Error::network(format!("wg: bind udp: {e}")))?,
    );
    let wake = Arc::new(Notify::new());
    let stack = Stack::new(cfg, statics, peer_pk, psk, endpoint, wake.clone())?;
    let task_socket = socket.clone();
    let task_wake = wake.clone();
    tokio::spawn(async move {
        run_stack(stack, task_socket, rx, task_wake).await;
    });
    map.insert(key, tx.clone());
    Ok(tx)
}

async fn resolve_endpoint(server: &str, port: u16) -> Result<SocketAddr> {
    let mut addrs = tokio::net::lookup_host((server, port))
        .await
        .map_err(|e| Error::dns(format!("wg: resolve {server}: {e}")))?;
    addrs
        .next()
        .ok_or_else(|| Error::dns(format!("wg: no address for {server}")))
}

/// Resolve a proxy target to the socket address the netstack dials.
///
/// * IPv4: always dialable.
/// * IPv6: dialable exactly when the tunnel has an inner v6 address
///   configured (`local_ipv6`); sing-wireguard derives no addresses, so an
///   unconfigured family is refused, not guessed.
/// * Domain: refused — upstream resolves destinations outside the tunnel and
///   hands the stack an IP (the netstack routes IPs only).
fn target_addr(target: &NetAddr, what: &str, local_ipv6: Option<Ipv6Addr>) -> Result<SocketAddr> {
    match &target.host {
        crate::addr::Host::Ip(IpAddr::V4(ip)) => Ok(SocketAddr::V4(SocketAddrV4::new(*ip, target.port))),
        crate::addr::Host::Ip(IpAddr::V6(ip)) => match local_ipv6 {
            Some(_) => Ok(SocketAddr::V6(SocketAddrV6::new(*ip, target.port, 0, 0))),
            None => Err(Error::network(format!(
                "wg: {what} to an IPv6 target: no inner IPv6 address configured \
                 (set the peer's ipv6 / local_address v6 entry)"
            ))),
        },
        crate::addr::Host::Domain(d) => Err(Error::network(format!(
            "wg: {what} to domain {d}: resolve before dialing (the netstack routes IPs only)"
        ))),
    }
}

/// Dial a TCP connection through the WireGuard tunnel described by `cfg`.
/// The tunnel (handshake + netstack) is created on first use and shared by
/// every later dial with the same configuration; the returned stream is a
/// plain `AsyncRead + AsyncWrite` the relay can splice.
pub async fn connect(cfg: &WgOut, target: &NetAddr) -> Result<BoxProxyStream> {
    let remote = target_addr(target, "connect", cfg.local_ipv6)?;
    let tunnel = tunnel_for(cfg).await?;
    let (tx, rx) = oneshot::channel();
    tunnel
        .send(Cmd::Connect { remote, reply: tx })
        .await
        .map_err(|_| Error::network("wg: tunnel task is gone"))?;
    let shared = tokio::time::timeout(REKEY_ATTEMPT_TIME, rx)
        .await
        .map_err(|_| Error::network("wg: tcp dial timed out"))?
        .map_err(|_| Error::network("wg: tunnel task dropped the dial"))??;
    Ok(Box::new(WgStream { shared }))
}

/// A UDP socket inside the WireGuard tunnel: send to any target, receive
/// from anyone who replies to this socket's port.
pub struct WgUdp {
    cmd: mpsc::Sender<Cmd>,
    id: u32,
    /// The tunnel's inner v6 address, for target validation on send (the
    /// stack performs the actual per-family source selection).
    local_ipv6: Option<Ipv6Addr>,
    down: tokio::sync::Mutex<UdpDownlink>,
}

impl WgUdp {
    /// Open a UDP socket through the tunnel (fails when the peer has
    /// `udp: false`).
    pub async fn bind(cfg: &WgOut) -> Result<Self> {
        let tunnel = tunnel_for(cfg).await?;
        let (tx, rx) = oneshot::channel();
        tunnel
            .send(Cmd::UdpOpen { reply: tx })
            .await
            .map_err(|_| Error::network("wg: tunnel task is gone"))?;
        let (id, down) = tokio::time::timeout(REKEY_ATTEMPT_TIME, rx)
            .await
            .map_err(|_| Error::network("wg: udp open timed out"))?
            .map_err(|_| Error::network("wg: tunnel task dropped the open"))??;
        Ok(WgUdp {
            cmd: tunnel,
            id,
            local_ipv6: cfg.local_ipv6,
            down: tokio::sync::Mutex::new(down),
        })
    }

    /// Send one datagram to `target` (a resolved IP address; IPv6 needs the
    /// tunnel's inner v6 address to be configured).
    pub async fn send(&self, target: &NetAddr, data: &[u8]) -> Result<()> {
        let dst = target_addr(target, "send", self.local_ipv6)?;
        self.cmd
            .send(Cmd::UdpSend {
                id: self.id,
                dst,
                data: data.to_vec(),
            })
            .await
            .map_err(|_| Error::network("wg: tunnel task is gone"))
    }

    /// Receive the next datagram addressed to this socket.
    pub async fn recv(&self) -> Result<(NetAddr, Vec<u8>)> {
        let mut down = self.down.lock().await;
        down.recv()
            .await
            .ok_or_else(|| Error::network("wg: udp socket is closed"))
    }
}

impl Drop for WgUdp {
    fn drop(&mut self) {
        let _ = self.cmd.try_send(Cmd::UdpClose { id: self.id });
    }
}

// ---------------------------------------------------------------------------
// ENDPOINT (server) mode: the responder side of the same protocol, a real
// UDP listener, and a packet-level bridge into the engine — sing-box's
// `endpoint` of type wireguard (protocol/wireguard/endpoint.go): the
// handshake responder (wireguard-go's device), transport with roaming, and
// the decrypted IP packets fed into a userspace stack whose TCP/UDP legs are
// handed to the engine exactly like the TUN inbound's.
// ---------------------------------------------------------------------------

/// One peer of the endpoint (sing-box `peers[]`: `public_key`,
/// `pre_shared_key`, `allowed_ips`, `persistent_keepalive`).
#[derive(Debug, Clone)]
pub struct WgEndpointPeer {
    /// The peer's static public key, base64 (32 bytes decoded).
    pub public_key: String,
    /// Optional pre-shared key, base64; empty/None = none.
    pub pre_shared_key: Option<String>,
    /// `allowed_ips`: the source ranges this peer may speak from and be
    /// routed to — `(address, prefix)` pairs, either family. On a server
    /// these double as cryptokey routing: the longest matching entry picks
    /// the peer an outbound packet is encrypted to.
    pub allowed_ips: Vec<(IpAddr, u8)>,
    /// Persistent keepalive interval, seconds (0/None = off): an empty
    /// transport message every interval while the session lives.
    pub persistent_keepalive: Option<u16>,
}

/// A WireGuard endpoint (server) inbound, dialect-independent. The
/// integrator maps sing-box's endpoint wireguard options (`private_key`,
/// `listen_port`, `mtu`, `address[]`, `peers[]`, `udp_timeout`) onto these
/// fields; mihomo has no WireGuard listener, so there is nothing to mirror.
#[derive(Debug, Clone)]
pub struct WgEndpointCfg {
    /// Inbound tag (routing / IN-TYPE like every listener).
    pub tag: String,
    /// Our static private key, base64 (32 bytes decoded).
    pub private_key: String,
    /// UDP listen port; 0 lets the kernel pick (the bound address is
    /// returned by [`serve_endpoint`]).
    pub listen_port: u16,
    /// Inner MTU; 0 selects the same 1408 default as the outbound.
    pub mtu: u16,
    /// The endpoint's own tunnel-side IPv4 address + prefix (sing-box
    /// `address` v4 entry) — the userspace stack's interface address.
    /// `None` falls back to `172.16.0.1/30`.
    pub address: Option<(Ipv4Addr, u8)>,
    /// The IPv6 twin (sing-box `address` v6 entry); `None` = v4-only peers.
    pub inet6_address: Option<(Ipv6Addr, u8)>,
    /// Idle UDP relay sessions are reaped after this long (sing-box
    /// `udp_timeout`); `None` = 300s.
    pub udp_timeout: Option<Duration>,
    /// The clients allowed to connect, matched by their static public key.
    pub peers: Vec<WgEndpointPeer>,
}

/// Cap on relayed TCP connections (mirrors the TUN netstack).
const EP_MAX_CONNS: usize = 256;
/// Cap on smoltcp UDP sockets (one per destination port in use).
const EP_MAX_UDP_SOCKETS: usize = 256;
/// Cap on UDP relay sessions (one per client source address).
const EP_MAX_UDP_SESSIONS: usize = 1024;
/// Cap on replies waiting to be handed to the stack in one batch.
const EP_MAX_PENDING_REPLIES: usize = 1024;
/// Default UDP session idle reap.
const EP_UDP_TIMEOUT: Duration = Duration::from_secs(300);
/// Cookie secret rotation (wireguard-go's CookieRefresh).
const EP_COOKIE_REFRESH: Duration = Duration::from_secs(120);
/// More initiations than this in one second switches the endpoint into
/// cookie mode (wireguard-go's ratelimiter trips at 64/s).
const EP_COOKIE_LOAD: u32 = 64;

// -- server-side handshake ---------------------------------------------------

/// Everything learned from an authenticated initiation, before the (peer
/// specific) PSK enters the math.
struct OpenInitiation {
    sender: u32,
    ephemeral: [u8; 32],
    client_static: [u8; 32],
    timestamp: [u8; 12],
    /// Chain key and hash after the encrypted-timestamp step.
    chaining_key: [u8; 32],
    hash: [u8; 32],
}

/// Verify a handshake initiation exactly as the responder does, up to (but
/// excluding) the psk2 step: MAC1 keyed by our own static, the initiator
/// static unsealed, the timestamp unsealed. Promoted from the in-test
/// responder; every derivation step cites the protocol page.
fn open_initiation(server_static: &StaticKeys, msg: &WgMsg) -> Result<OpenInitiation> {
    let WgMsg::Initiation {
        sender,
        ephemeral,
        enc_static,
        enc_timestamp,
        mac1,
        ..
    } = msg
    else {
        return Err(Error::protocol("endpoint: not an initiation"));
    };
    // MAC1 first, keyed by OUR static public key: no unauthenticated work
    // beyond the hash (whitepaper "First Message" + wireguard-go
    // ReceivedHandshakeInitiation).
    let mut covered = Vec::with_capacity(116);
    covered.extend_from_slice(&1u32.to_le_bytes());
    covered.extend_from_slice(&sender.to_le_bytes());
    covered.extend_from_slice(ephemeral);
    covered.extend_from_slice(enc_static);
    covered.extend_from_slice(enc_timestamp);
    if blake2s_mac(&mac1_key(&server_static.pk), &covered) != *mac1 {
        return Err(Error::crypto("endpoint: initiation MAC1 mismatch"));
    }

    // Mirror the initiator's derivation (build_initiation, step for step).
    let mut ck = blake2s256(CONSTRUCTION);
    let ident_hash = hash2(&ck, IDENTIFIER);
    let mut h = hash2(&ident_hash, &server_static.pk);
    h = hash2(&h, ephemeral);
    ck = kdf1(&ck, ephemeral);
    // es = DH(responder static, initiator ephemeral)
    let es = x25519_dh(&server_static.sk, ephemeral)?;
    let (ck, key_es) = kdf2(&ck, &es);
    let client_static: [u8; 32] = aead_open(&key_es, 0, enc_static, &h)?
        .try_into()
        .map_err(|_| Error::protocol("endpoint: static has wrong length"))?;
    h = hash2(&h, enc_static);
    // ss = DH(responder static, initiator static)
    let ss = x25519_dh(&server_static.sk, &client_static)?;
    let (ck, key_ss) = kdf2(&ck, &ss);
    let timestamp = aead_open(&key_ss, 0, enc_timestamp, &h)?;
    h = hash2(&h, enc_timestamp);
    if timestamp.len() != 12 {
        return Err(Error::protocol("endpoint: timestamp has wrong length"));
    }
    let timestamp: [u8; 12] = timestamp.try_into().unwrap();
    Ok(OpenInitiation {
        sender: *sender,
        ephemeral: *ephemeral,
        client_static,
        timestamp,
        chaining_key: ck,
        hash: h,
    })
}

/// Server-side session keys from a consumed initiation: (server index,
/// peer index, client-send key, client-recv key).
type ServerKeys = (u32, u32, [u8; 32], [u8; 32]);

/// Complete the handshake with the peer's PSK: the response message plus the
/// session keys (see [`ServerKeys`]). The server sends with the client-recv
/// key.
fn respond_initiation(
    open: OpenInitiation,
    psk: &[u8; 32],
    server_index: u32,
) -> Result<(Vec<u8>, ServerKeys)> {
    let OpenInitiation {
        sender,
        ephemeral,
        client_static,
        timestamp: _,
        chaining_key: mut ck,
        hash: mut h,
    } = open;

    // The responder's half of the "Second Message" block.
    let e = x25519_keypair();
    h = hash2(&h, &e.pk);
    ck = kdf1(&ck, &e.pk);
    // ee = DH(responder ephemeral, initiator ephemeral)
    let ee = x25519_dh(&e.sk, &ephemeral)?;
    ck = kdf1(&ck, &ee);
    // se = DH(responder ephemeral, initiator static)
    let se = x25519_dh(&e.sk, &client_static)?;
    ck = kdf1(&ck, &se);
    // psk2
    let (ck, temp2, key) = kdf3(&ck, psk);
    h = hash2(&h, &temp2);
    let enc_nothing = aead_seal(&key, 0, &[], &h)?;
    // Both sides take the transcript step; the transport keys derive from
    // the chain alone (matching note in consume_response).
    let _ = hash2(&h, &enc_nothing);

    let mut resp = Vec::with_capacity(MSG_RESPONSE_LEN);
    resp.extend_from_slice(&2u32.to_le_bytes());
    resp.extend_from_slice(&server_index.to_le_bytes());
    resp.extend_from_slice(&sender.to_le_bytes());
    resp.extend_from_slice(&e.pk);
    resp.extend_from_slice(&enc_nothing);
    // MAC1 keyed by the initiator's (now unsealed) static.
    let mac1 = blake2s_mac(&mac1_key(&client_static), &resp);
    resp.extend_from_slice(&mac1);
    // MAC2: only with a cookie in play; zeros otherwise.
    resp.extend_from_slice(&[0u8; 16]);
    debug_assert_eq!(resp.len(), MSG_RESPONSE_LEN);

    let (k_client_send, k_client_recv) = derive_transport_keys(&ck);
    Ok((resp, (server_index, sender, k_client_send, k_client_recv)))
}

impl Session {
    /// The responder's session: it sends with the initiator's receive key
    /// and receives with the initiator's send key
    /// (derive_transport_keys returns (initiator-send, initiator-recv)).
    fn from_responder(
        local_index: u32,
        peer_index: u32,
        k_peer_send: [u8; 32],
        k_peer_recv: [u8; 32],
        now: Instant,
    ) -> Self {
        Session {
            local_index,
            peer_index,
            created: now,
            last_tx: now,
            last_rx: now,
            send: SendHalf {
                cipher: make_cipher(&k_peer_recv),
                next: 0,
            },
            recv: RecvHalf {
                cipher: make_cipher(&k_peer_send),
                replay: AntiReplay::new(),
            },
        }
    }
}

/// Build a cookie reply (64 bytes) for an initiation we are too loaded to
/// answer: cookie = MAC16(secret, initiator endpoint), sealed with
/// XAEAD(HASH(LABEL_COOKIE || responder static), nonce, cookie) and the
/// initiation's MAC1 as AAD — the whitepaper's "Message 3: Cookie Reply"
/// and wireguard-go's SendHandshakeCookie. The client's
/// [`consume_cookie_reply`] is the exact inverse.
fn build_cookie_reply(
    server_static_pk: &[u8; 32],
    receiver_index: u32,
    initiation_mac1: &[u8; 16],
    cookie: [u8; 16],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let enc = XChaCha20Poly1305::new_from_slice(&cookie_key(server_static_pk))
        .map_err(|_| Error::crypto("endpoint: bad cookie key"))?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &cookie,
                aad: initiation_mac1,
            },
        )
        .map_err(|_| Error::crypto("endpoint: cookie seal failed"))?;
    let mut pkt = Vec::with_capacity(MSG_COOKIE_LEN);
    pkt.extend_from_slice(&3u32.to_le_bytes());
    pkt.extend_from_slice(&receiver_index.to_le_bytes());
    pkt.extend_from_slice(&nonce);
    pkt.extend_from_slice(&enc);
    debug_assert_eq!(pkt.len(), MSG_COOKIE_LEN);
    Ok(pkt)
}

/// The cookie for an initiator endpoint: MAC16(secret, endpoint bytes) —
/// wireguard-go's CookieGenerator hashes the endpoint address; a String form
/// is equivalent for the MAC input (the client only reflects it back).
fn make_cookie(secret: &[u8; 16], from: SocketAddr) -> [u8; 16] {
    let input = from.to_string();
    blake2s_mac(secret, input.as_bytes())
}

/// One-second initiation counter; past [`EP_COOKIE_LOAD`] the endpoint
/// answers initiations with cookies instead of doing the DH work
/// (wireguard-go's ratelimiter semantics, simplified to a fixed window).
#[derive(Default)]
struct HandshakeLoad {
    window_start: Option<Instant>,
    count: u32,
}

impl HandshakeLoad {
    fn bump(&mut self, now: Instant) {
        match self.window_start {
            Some(t) if now.duration_since(t) < Duration::from_secs(1) => self.count += 1,
            _ => {
                self.window_start = Some(now);
                self.count = 1;
            }
        }
    }

    fn under_load(&self) -> bool {
        self.count > EP_COOKIE_LOAD
    }
}

// -- cryptokey routing (pure) -------------------------------------------------

/// Does `ip` fall inside `net / prefix`? Family must match.
fn prefix_contains(net: &IpAddr, prefix: u8, ip: &IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            n.to_bits() & mask == i.to_bits() & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            if prefix > 128 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            n.to_bits() & mask == i.to_bits() & mask
        }
        _ => false,
    }
}

/// The peer whose allowed_ips contains `ip` with the longest prefix —
/// cryptokey routing (the whitepaper's "Allowed IPs" table lookup).
fn route_peer(peers: &[EpPeer], ip: &IpAddr) -> Option<(usize, u8)> {
    let mut best: Option<(usize, u8)> = None;
    for (i, p) in peers.iter().enumerate() {
        for (net, prefix) in &p.allowed {
            if prefix_contains(net, *prefix, ip) {
                let better = best.is_none_or(|(_, bp)| *prefix > bp);
                if better {
                    best = Some((i, *prefix));
                }
            }
        }
    }
    best
}

/// Is `ip` an allowed *source* for `peer`? (The server-side filter of the
/// same table.)
fn source_allowed(peer: &EpPeer, ip: &IpAddr) -> bool {
    peer.allowed
        .iter()
        .any(|(net, prefix)| prefix_contains(net, *prefix, ip))
}

// -- endpoint state -----------------------------------------------------------

/// Runtime state of one configured peer.
struct EpPeer {
    static_pk: [u8; 32],
    psk: [u8; 32],
    allowed: Vec<(IpAddr, u8)>,
    persistent_keepalive: Option<Duration>,
    /// The strictly-greatest TAI64N accepted from this peer (replay guard).
    last_timestamp: Option<[u8; 12]>,
    /// Roaming endpoint, updated by every authenticated packet.
    endpoint: Option<SocketAddr>,
    session: Option<Session>,
    next_persistent: Option<Instant>,
}

/// The endpoint: peers, sessions and the cookie machinery.
struct Endpoint {
    statics: StaticKeys,
    peers: Vec<EpPeer>,
    /// Transport receiver-index -> peer.
    by_index: HashMap<u32, usize>,
    cookie: ([u8; 16], Instant),
    load: HandshakeLoad,
}

impl Endpoint {
    fn new(cfg: &WgEndpointCfg) -> Result<Self> {
        let sk = b64key(&cfg.private_key, "private-key")?;
        let statics = StaticKeys::from_secret(sk);
        if cfg.peers.is_empty() {
            return Err(Error::config(
                "wg endpoint: at least one peer is required (who may connect?)",
            ));
        }
        let mut peers = Vec::with_capacity(cfg.peers.len());
        let mut seen = HashSet::new();
        for (i, p) in cfg.peers.iter().enumerate() {
            let pk = b64key(&p.public_key, "peers[].public-key")?;
            if !seen.insert(pk) {
                return Err(Error::config(format!(
                    "wg endpoint: peers[{i}] repeats a public key"
                )));
            }
            let psk = match p.pre_shared_key.as_deref() {
                None | Some("") => [0u8; 32],
                Some(s) => b64key(s, "peers[].pre-shared-key")?,
            };
            for (net, prefix) in &p.allowed_ips {
                let max = if net.is_ipv4() { 32 } else { 128 };
                if *prefix > max {
                    return Err(Error::config(format!(
                        "wg endpoint: peers[{i}] allowed-ip {net}/{prefix} is not a valid prefix"
                    )));
                }
            }
            if p.allowed_ips.is_empty() {
                return Err(Error::config(format!(
                    "wg endpoint: peers[{i}] has no allowed_ips (its packets could not be \
                     routed back)"
                )));
            }
            peers.push(EpPeer {
                static_pk: pk,
                psk,
                allowed: p.allowed_ips.clone(),
                persistent_keepalive: p
                    .persistent_keepalive
                    .filter(|&s| s > 0)
                    .map(|s| Duration::from_secs(u64::from(s))),
                last_timestamp: None,
                endpoint: None,
                session: None,
                next_persistent: None,
            });
        }
        let mut secret = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        Ok(Endpoint {
            statics,
            peers,
            by_index: HashMap::new(),
            cookie: (secret, Instant::now()),
            load: HandshakeLoad::default(),
        })
    }

    fn peer_by_pk(&self, pk: &[u8; 32]) -> Option<usize> {
        self.peers.iter().position(|p| &p.static_pk == pk)
    }

    /// A receiver index not currently in use.
    fn fresh_index(&self) -> u32 {
        loop {
            let idx = rand::random::<u32>();
            if !self.by_index.contains_key(&idx) && idx != 0 {
                return idx;
            }
        }
    }

    fn cookie_for(&mut self, now: Instant) -> [u8; 16] {
        if now.duration_since(self.cookie.1) >= EP_COOKIE_REFRESH {
            let mut secret = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut secret);
            self.cookie = (secret, now);
        }
        self.cookie.0
    }

    /// One datagram from the network.
    async fn on_datagram(
        &mut self,
        socket: &UdpSocket,
        from: SocketAddr,
        raw: &mut [u8],
        stack: &mut EpStack,
    ) {
        strip_reserved(raw);
        let Some(msg) = parse_wg_msg(raw) else {
            return;
        };
        let now = Instant::now();
        match msg {
            WgMsg::Initiation {
                sender, mac1, ..
            } => {
                self.load.bump(now);
                if self.load.under_load() {
                    // Too many handshakes: answer with a cookie instead of
                    // doing DH work (whitepaper "under load" + wireguard-go
                    // ratelimiter). Legitimate initiators retry with MAC2.
                    let secret = self.cookie_for(now);
                    let cookie = make_cookie(&secret, from);
                    if let Ok(reply) =
                        build_cookie_reply(&self.statics.pk, sender, &mac1, cookie)
                    {
                        let _ = socket.send_to(&reply, from).await;
                    }
                    return;
                }
                let Ok(open) = open_initiation(&self.statics, &msg) else {
                    return; // unauthenticated: silent
                };
                let Some(pi) = self.peer_by_pk(&open.client_static) else {
                    return; // unknown peer: silent
                };
                // Replay guard: strictly newer TAI64N only (memcmp order).
                if self.peers[pi]
                    .last_timestamp
                    .is_some_and(|t| open.timestamp <= t)
                {
                    return;
                }
                let ts = open.timestamp;
                let index = self.fresh_index();
                let Ok((resp, (_idx, peer_index, k_send, k_recv))) =
                    respond_initiation(open, &self.peers[pi].psk, index)
                else {
                    return;
                };
                // Replace the peer's session; the old receiver index dies
                // with it (by_index ops first, then the peer mutation, to
                // keep the borrows disjoint).
                if let Some(old) = self.peers[pi].session.as_ref().map(|s| s.local_index) {
                    self.by_index.remove(&old);
                }
                self.by_index.insert(index, pi);
                let peer = &mut self.peers[pi];
                peer.last_timestamp = Some(ts);
                peer.session =
                    Some(Session::from_responder(index, peer_index, k_send, k_recv, now));
                peer.endpoint = Some(from);
                peer.next_persistent = peer.persistent_keepalive.map(|iv| now + iv);
                tracing::debug!(
                    target: "engine",
                    "wg endpoint: session with peer {} from {from}",
                    key_id(&self.peers[pi].static_pk)
                );
                let _ = socket.send_to(&resp, from).await;
            }
            WgMsg::Transport { receiver, counter, data } => {
                let Some(&pi) = self.by_index.get(&receiver) else {
                    return;
                };
                let peer = &mut self.peers[pi];
                // Roaming happens on any authenticated transport packet:
                // update the endpoint before decrypting.
                if peer
                    .session
                    .as_ref()
                    .is_some_and(|s| s.local_index != receiver)
                {
                    return; // stale index after a rekey
                }
                let Some(sess) = peer.session.as_mut() else {
                    return;
                };
                if session_expired(sess.created, now) {
                    peer.session = None;
                    self.by_index.remove(&receiver);
                    return;
                }
                // Replays and corruption fail the tag or the window and
                // are dropped silently (no else branch, per the whitepaper).
                if let Ok(mut inner) = sess.open_transport(counter, &data) {
                    sess.last_rx = now;
                    peer.endpoint = Some(from);
                    if inner.is_empty() {
                        return; // keepalive
                    }
                    trim_ip_packet(&mut inner);
                    // Cryptokey routing's source filter: the packet must
                    // come from an address this peer owns (whitepaper
                    // Allowed IPs; sing-box/wireguard-go drop the rest).
                    let src_ok =
                        src_ip_of(&inner).is_some_and(|src| source_allowed(peer, &src));
                    if !src_ok {
                        tracing::debug!(
                            target: "engine",
                            "wg endpoint: packet from an address outside the peer's \
                             allowed_ips, dropped"
                        );
                        return;
                    }
                    stack.stage_packet(&inner);
                }
            }
            // A server never initiates, so responses and cookie replies from
            // peers are unexpected here.
            _ => {}
        }
    }

    /// Periodic work: expire sessions, send keepalives, rotate the cookie
    /// secret's schedule.
    async fn on_timer(&mut self, socket: &UdpSocket) {
        let now = Instant::now();
        for pi in 0..self.peers.len() {
            let expired = self.peers[pi]
                .session
                .as_ref()
                .is_some_and(|s| session_expired(s.created, now));
            if expired {
                if let Some(old) = self.peers[pi].session.take() {
                    self.by_index.remove(&old.local_index);
                }
                continue;
            }
            // Standard keepalive: transmit silence after a received packet
            // (wireguard-go sends one when receiving if we have been quiet).
            let want_keepalive = self.peers[pi]
                .session
                .as_ref()
                .is_some_and(|s| needs_keepalive(s.last_tx, now));
            // Configured persistent keepalive.
            let due_persistent = self.peers[pi]
                .next_persistent
                .is_some_and(|at| now >= at);
            if want_keepalive || due_persistent {
                let peer = &mut self.peers[pi];
                let dst = peer.endpoint;
                let msg = peer
                    .session
                    .as_mut()
                    .and_then(|s| s.seal_transport(&[]).ok());
                if let (Some(dst), Some(msg)) = (dst, msg) {
                    let _ = socket.send_to(&msg, dst).await;
                }
                if due_persistent {
                    if let Some(iv) = self.peers[pi].persistent_keepalive {
                        self.peers[pi].next_persistent = Some(now + iv);
                    }
                }
            }
        }
    }

    /// Encrypt one decrypted-side egress packet to the owning peer
    /// (cryptokey routing) and send it to that peer's current endpoint.
    async fn send_inner(&mut self, socket: &UdpSocket, pkt: &[u8]) {
        let Some(dst_ip) = dst_ip_of(pkt) else {
            return;
        };
        let Some((pi, _prefix)) = route_peer(&self.peers, &dst_ip) else {
            tracing::debug!(
                target: "engine",
                "wg endpoint: no peer route for {dst_ip}, packet dropped"
            );
            return;
        };
        let peer = &mut self.peers[pi];
        let dst = peer.endpoint;
        let msg = peer
            .session
            .as_mut()
            .and_then(|s| s.seal_transport(pkt).ok());
        if let (Some(dst), Some(msg)) = (dst, msg) {
            let _ = socket.send_to(&msg, dst).await;
        }
    }
}

/// Short identifying prefix of a key for logs.
fn key_id(pk: &[u8; 32]) -> String {
    pk[..4].iter().map(|x| format!("{x:02x}")).collect()
}

// -- packet classification + local ICMP answers (pure) ------------------------

/// What one decrypted inner packet is. A minimal mirror of the TUN
/// netstack's classifier — enough to drive listeners, UDP sockets and echo
/// answers; everything else (extension headers, non-TCP/UDP/ICMP) drops.
#[derive(Debug, PartialEq, Eq)]
enum EpIn {
    Tcp {
        src: SocketAddr,
        dst: SocketAddr,
        syn: bool,
    },
    Udp {
        src: SocketAddr,
        dst: SocketAddr,
        payload: (usize, usize),
    },
    IcmpEchoRequest {
        src: IpAddr,
        dst: IpAddr,
        v6: bool,
    },
    Skip,
}

/// Classify one inner packet (never panics; every slice is bounds-checked).
fn ep_classify(pkt: &[u8]) -> EpIn {
    let Some(&vihl) = pkt.first() else {
        return EpIn::Skip;
    };
    match vihl >> 4 {
        4 => {
            let ihl = (vihl & 0x0f) as usize * 4;
            if ihl < 20 || pkt.len() < ihl {
                return EpIn::Skip;
            }
            let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            let end = total.min(pkt.len());
            let src = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
            match pkt[9] {
                6 if end >= ihl + 20 => {
                    let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                    let flags = pkt[ihl + 13];
                    EpIn::Tcp {
                        src: SocketAddr::new(src, sport),
                        dst: SocketAddr::new(dst, dport),
                        syn: flags & 0x02 != 0,
                    }
                }
                17 if end >= ihl + 8 => {
                    let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                    let len = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]) as usize;
                    let payload_end = (ihl + len).min(end);
                    EpIn::Udp {
                        src: SocketAddr::new(src, sport),
                        dst: SocketAddr::new(dst, dport),
                        payload: (ihl + 8, payload_end),
                    }
                }
                1 => icmp_in(pkt, src, dst, false),
                _ => EpIn::Skip,
            }
        }
        6 => {
            if pkt.len() < 40 {
                return EpIn::Skip;
            }
            let src = IpAddr::V6(v6_addr(pkt, 8));
            let dst = IpAddr::V6(v6_addr(pkt, 24));
            match pkt[6] {
                6 if pkt.len() >= 60 => {
                    let sport = u16::from_be_bytes([pkt[40], pkt[41]]);
                    let dport = u16::from_be_bytes([pkt[42], pkt[43]]);
                    EpIn::Tcp {
                        src: SocketAddr::new(src, sport),
                        dst: SocketAddr::new(dst, dport),
                        syn: pkt[53] & 0x02 != 0,
                    }
                }
                17 if pkt.len() >= 48 => {
                    let sport = u16::from_be_bytes([pkt[40], pkt[41]]);
                    let dport = u16::from_be_bytes([pkt[42], pkt[43]]);
                    let len = u16::from_be_bytes([pkt[44], pkt[45]]) as usize;
                    let payload_end = (40 + len).min(pkt.len());
                    EpIn::Udp {
                        src: SocketAddr::new(src, sport),
                        dst: SocketAddr::new(dst, dport),
                        payload: (48, payload_end),
                    }
                }
                58 => icmp_in(pkt, src, dst, true),
                _ => EpIn::Skip, // extension headers not parsed
            }
        }
        _ => EpIn::Skip,
    }
}

/// The byte offset where the ICMP message starts (`ihl` for v4, 40 for v6).
fn icmp_offset(pkt: &[u8]) -> Option<usize> {
    match pkt.first()? >> 4 {
        4 => {
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            (ihl >= 20 && pkt.len() > ihl).then_some(ihl)
        }
        6 => (pkt.len() > 40).then_some(40),
        _ => None,
    }
}

fn icmp_in(pkt: &[u8], src: IpAddr, dst: IpAddr, v6: bool) -> EpIn {
    let Some(off) = icmp_offset(pkt) else {
        return EpIn::Skip;
    };
    let is_echo_request = if v6 {
        pkt[off] == 128
    } else {
        pkt[off] == 8
    };
    if is_echo_request {
        EpIn::IcmpEchoRequest { src, dst, v6 }
    } else {
        EpIn::Skip
    }
}

/// Bytes 8..24 / 24..40 of an IPv6 packet as an address.
fn v6_addr(pkt: &[u8], from: usize) -> Ipv6Addr {
    let octets: [u8; 16] = pkt[from..from + 16].try_into().expect("16 bytes");
    Ipv6Addr::from(octets)
}

/// The destination address of an IP packet, either family.
fn dst_ip_of(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            pkt[16], pkt[17], pkt[18], pkt[19],
        ))),
        6 if pkt.len() >= 40 => Some(IpAddr::V6(v6_addr(pkt, 24))),
        _ => None,
    }
}

/// The source address of an IP packet, either family.
fn src_ip_of(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            pkt[12], pkt[13], pkt[14], pkt[15],
        ))),
        6 if pkt.len() >= 40 => Some(IpAddr::V6(v6_addr(pkt, 8))),
        _ => None,
    }
}

/// Internet checksum (RFC 1071) over a byte slice with an odd-byte tail.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, tail) = data.as_chunks::<2>();
    for c in chunks {
        sum = sum.wrapping_add(u16::from_be_bytes(*c) as u32);
    }
    if let [b] = tail {
        sum = sum.wrapping_add((*b as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An ICMPv4 echo reply for a request: swap the addresses, type 0, recompute
/// the header checksum (RFC 792). `None` for anything malformed.
fn ep_icmpv4_echo_reply(pkt: &[u8]) -> Option<Vec<u8>> {
    let off = icmp_offset(pkt)?;
    if pkt[off] != 8 {
        return None;
    }
    let mut out = pkt.to_vec();
    // Swap v4 addresses.
    let (src, dst) = (
        [out[12], out[13], out[14], out[15]],
        [out[16], out[17], out[18], out[19]],
    );
    out[12..16].copy_from_slice(&dst);
    out[16..20].copy_from_slice(&src);
    out[off] = 0; // echo reply
    out[off + 2] = 0;
    out[off + 3] = 0;
    let sum = checksum(&out[off..]);
    out[off + 2] = sum.to_be_bytes()[0];
    out[off + 3] = sum.to_be_bytes()[1];
    Some(out)
}

/// An ICMPv6 echo reply: swap, type 129, recompute the checksum over the
/// whole ICMPv6 message with the IPv6 pseudo-header (RFC 4443).
fn ep_icmpv6_echo_reply(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() <= 40 || pkt[40] != 128 {
        return None;
    }
    let mut out = pkt.to_vec();
    let src: [u8; 16] = out[8..24].try_into().expect("16 bytes");
    let dst: [u8; 16] = out[24..40].try_into().expect("16 bytes");
    out[8..24].copy_from_slice(&dst);
    out[24..40].copy_from_slice(&src);
    out[40] = 129;
    out[42] = 0;
    out[43] = 0;
    let payload_len = (out.len() - 40) as u32;
    let mut pseudo = Vec::with_capacity(40 + out.len() - 40);
    pseudo.extend_from_slice(&out[8..24]);
    pseudo.extend_from_slice(&out[24..40]);
    pseudo.extend_from_slice(&payload_len.to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(&out[40..]);
    let sum = checksum(&pseudo);
    out[42] = sum.to_be_bytes()[0];
    out[43] = sum.to_be_bytes()[1];
    Some(out)
}

// -- the endpoint's userspace stack -------------------------------------------

/// A datagram to hand back into the tunnel: to `client`, appearing to come
/// from `local` (the destination the client dialled).
struct EpReply {
    client: SocketAddr,
    local: SocketAddr,
    data: Vec<u8>,
}

/// One accepted TCP connection bridged to a [`WgStream`].
struct EpConn {
    handle: SocketHandle,
    shared: Arc<StreamShared>,
    fin_sent: bool,
}

/// One UDP relay association (per client source address); dropping it aborts
/// the downlink pump.
struct EpUdpSession {
    uplink: mpsc::Sender<(NetAddr, Vec<u8>)>,
    last_activity: Instant,
    pump: tokio::task::JoinHandle<()>,
}

impl Drop for EpUdpSession {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// The packet-level half of the endpoint: a smoltcp stack that accepts the
/// TCP connections and UDP flows arriving over WireGuard and hands them to
/// the engine's [`RelayHandler`](crate::inbound::RelayHandler) — the same
/// bridge the TUN inbound runs, minus the kernel device (the "wire" is the
/// endpoint task) and the DNS hijack (an endpoint relays like sing-box's,
/// which hijacks nothing). Egress (the stack's replies plus ICMP answers) is
/// what the driver encrypts back to the peers.
struct EpStack {
    iface: Interface,
    sockets: SocketSet<'static>,
    shim: Shim,
    relay: SharedRelay,
    tag: String,
    udp_timeout: Duration,
    listeners: Vec<(SocketHandle, u16)>,
    conns: Vec<EpConn>,
    udp_sockets: HashMap<u16, SocketHandle>,
    sessions: HashMap<SocketAddr, EpUdpSession>,
    replies: Arc<Mutex<VecDeque<EpReply>>>,
    /// Locally generated packets (ICMP echo replies) to emit as egress.
    local_egress: VecDeque<Vec<u8>>,
    wake: Arc<Notify>,
    start: Instant,
    next_gc: Instant,
    pump_buf: Vec<u8>,
}

impl EpStack {
    fn new(cfg: &WgEndpointCfg, relay: SharedRelay, wake: Arc<Notify>) -> Result<Self> {
        let mtu = if cfg.mtu == 0 {
            1408
        } else {
            cfg.mtu.clamp(576, 65535) as usize
        };
        let mut shim = Shim::new(mtu);
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = rand::random();
        let mut iface = Interface::new(iface_cfg, &mut shim, SmolInstant::ZERO);
        let (v4, p4) = cfg
            .address
            .unwrap_or((Ipv4Addr::new(172, 16, 0, 1), 30));
        if p4 > 32 {
            return Err(Error::config(format!("wg endpoint: /{p4} is not a valid IPv4 prefix")));
        }
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(v4), p4));
            if let Some((inet6, p6)) = cfg.inet6_address {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(inet6), p6.min(128)));
            }
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(v4)
            .map_err(|_| Error::network("wg endpoint: route table full"))?;
        if let Some((inet6, _)) = cfg.inet6_address {
            iface
                .routes_mut()
                .add_default_ipv6_route(inet6)
                .map_err(|_| Error::network("wg endpoint: route table full"))?;
        }
        // Accept traffic to any destination: the peers' allowed_ips decide
        // the real reachability, exactly like the TUN stack's any_ip.
        iface.set_any_ip(true);
        let now = Instant::now();
        Ok(EpStack {
            iface,
            sockets: SocketSet::new(Vec::new()),
            shim,
            relay,
            tag: cfg.tag.clone(),
            udp_timeout: cfg.udp_timeout.unwrap_or(EP_UDP_TIMEOUT),
            listeners: Vec::new(),
            conns: Vec::new(),
            udp_sockets: HashMap::new(),
            sessions: HashMap::new(),
            replies: Arc::new(Mutex::new(VecDeque::new())),
            local_egress: VecDeque::new(),
            wake,
            start: now,
            next_gc: now + Duration::from_secs(10),
            pump_buf: vec![0u8; PUMP_CHUNK],
        })
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
    }

    /// One decrypted inner packet: pre-stage listeners/sessions, then hand
    /// the packet to smoltcp.
    fn stage_packet(&mut self, pkt: &[u8]) {
        match ep_classify(pkt) {
            EpIn::Tcp { dst, syn, .. } => {
                if syn && self.needs_listener(dst.port()) {
                    self.add_listener(dst.port());
                }
                self.shim.stage(pkt);
            }
            EpIn::Udp {
                src,
                dst,
                payload: (a, b),
            } => {
                self.ensure_udp_socket(dst.port());
                self.udp_uplink(src, dst, &pkt[a..b]);
                self.shim.stage(pkt);
            }
            EpIn::IcmpEchoRequest { v6, .. } => {
                let reply = if v6 {
                    ep_icmpv6_echo_reply(pkt)
                } else {
                    ep_icmpv4_echo_reply(pkt)
                };
                // Answered locally: the reply is egress, not stack input.
                if let Some(r) = reply {
                    self.local_egress.push_back(r);
                    self.wake.notify_one();
                }
            }
            EpIn::Skip => {}
        }
    }

    /// A port needs a fresh listener exactly when no LISTEN-state socket
    /// covers it anymore: the moment a SYN takes the existing listener into
    /// SynReceived, that socket only matches its own 4-tuple, so any further
    /// concurrent SYN to the same port would otherwise fall through to
    /// smoltcp's RST reply (wave-12: concurrent dials failing with
    /// "dial failed (state Closed)").
    fn needs_listener(&self, port: u16) -> bool {
        !self.listeners.iter().any(|(h, p)| {
            *p == port && self.sockets.get::<tcp::Socket>(*h).state() == tcp::State::Listen
        })
    }

    fn add_listener(&mut self, port: u16) {
        if self.listeners.len() + self.conns.len() >= EP_MAX_CONNS {
            tracing::debug!(target: "engine", "wg endpoint: connection limit reached, refusing port {port}");
            return;
        }
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_RX_BYTES]),
            tcp::SocketBuffer::new(vec![0; TCP_TX_BYTES]),
        );
        if let Err(e) = sock.listen(IpListenEndpoint { addr: None, port }) {
            tracing::debug!(target: "engine", "wg endpoint: cannot listen on {port}: {e:?}");
            return;
        }
        self.listeners.push((self.sockets.add(sock), port));
    }

    fn ensure_udp_socket(&mut self, port: u16) -> Option<SocketHandle> {
        if let Some(handle) = self.udp_sockets.get(&port) {
            return Some(*handle);
        }
        if self.udp_sockets.len() >= EP_MAX_UDP_SOCKETS {
            tracing::debug!(target: "engine", "wg endpoint: too many udp ports, dropping {port}");
            return None;
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
        if let Err(e) = sock.bind(IpListenEndpoint { addr: None, port }) {
            tracing::debug!(target: "engine", "wg endpoint: cannot bind udp {port}: {e:?}");
            return None;
        }
        let handle = self.sockets.add(sock);
        self.udp_sockets.insert(port, handle);
        Some(handle)
    }

    fn udp_uplink(&mut self, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
        let uplink = match self.sessions.get_mut(&src) {
            Some(s) => {
                s.last_activity = Instant::now();
                s.uplink.clone()
            }
            None => {
                if self.sessions.len() >= EP_MAX_UDP_SESSIONS {
                    tracing::debug!(target: "engine", "wg endpoint: udp session limit, dropping {src}");
                    return;
                }
                self.open_session(src)
            }
        };
        // UDP is lossy: a full queue drops rather than blocks.
        let _ = uplink.try_send((NetAddr::ip(dst.ip(), dst.port()), payload.to_vec()));
    }

    fn open_session(&mut self, src: SocketAddr) -> mpsc::Sender<(NetAddr, Vec<u8>)> {
        let (up_tx, up_rx) = mpsc::channel::<(NetAddr, Vec<u8>)>(64);
        let (down_tx, mut down_rx) = mpsc::channel::<(NetAddr, Vec<u8>)>(64);
        self.relay
            .clone()
            .handle_udp(src, self.tag.clone(), up_rx, down_tx);
        let replies = self.replies.clone();
        let wake = self.wake.clone();
        // Downlink pump: relay replies queue up as (client, from, data) and
        // wake the driver; it ends with the session (aborted on drop).
        let pump = tokio::spawn(async move {
            while let Some((from, data)) = down_rx.recv().await {
                let NetAddr {
                    host: crate::addr::Host::Ip(ip),
                    port,
                } = &from
                else {
                    continue;
                };
                let mut q = replies.lock().unwrap_or_else(|e| e.into_inner());
                if q.len() >= EP_MAX_PENDING_REPLIES {
                    continue;
                }
                q.push_back(EpReply {
                    client: src,
                    local: SocketAddr::new(*ip, *port),
                    data,
                });
                drop(q);
                wake.notify_one();
            }
        });
        self.sessions.insert(
            src,
            EpUdpSession {
                uplink: up_tx.clone(),
                last_activity: Instant::now(),
                pump,
            },
        );
        up_tx
    }

    /// One pass: poll, promote listeners to relayed connections, service
    /// the streams, drain replies, reap idle sessions. Returns egress
    /// packets (stack replies + locally generated ones).
    fn step(&mut self) -> Vec<Vec<u8>> {
        let now = self.now();
        self.iface.poll(now, &mut self.shim, &mut self.sockets);

        self.convert_listeners();
        self.drain_replies();
        self.service_conns();
        self.drain_udp_rx();

        let now = self.now();
        self.iface.poll(now, &mut self.shim, &mut self.sockets);
        self.gc_sessions();

        let mut out: Vec<Vec<u8>> = self.local_egress.drain(..).collect();
        out.extend(self.shim.egress.drain(..));
        out
    }

    fn convert_listeners(&mut self) {
        let mut keep = Vec::with_capacity(self.listeners.len());
        let mut dead: Vec<SocketHandle> = Vec::new();
        for (handle, port) in self.listeners.drain(..) {
            let sock = self.sockets.get_mut::<tcp::Socket>(handle);
            match sock.state() {
                tcp::State::Listen | tcp::State::SynReceived => keep.push((handle, port)),
                tcp::State::Established => {
                    let (local, remote) = (
                        sock.local_endpoint().map(ep_to_sockaddr),
                        sock.remote_endpoint().map(ep_to_sockaddr),
                    );
                    match (local, remote) {
                        (Some((lip, lport)), Some((rip, rport))) => {
                            let source = SocketAddr::new(rip, rport);
                            let target = NetAddr::ip(lip, lport);
                            tracing::debug!(
                                target: "engine",
                                "wg endpoint: new tcp {source} -> {target}"
                            );
                            let shared = Arc::new(StreamShared::new(self.wake.clone()));
                            self.relay.clone().handle_tcp(
                                TcpMeta {
                                    target,
                                    source,
                                    inbound: self.tag.clone(),
                                    inbound_port: None,
                                    inbound_kind: "tun",
                                },
                                Box::new(WgStream {
                                    shared: shared.clone(),
                                }),
                            );
                            self.conns.push(EpConn {
                                handle,
                                shared,
                                fin_sent: false,
                            });
                        }
                        _ => dead.push(handle),
                    }
                }
                _ => dead.push(handle),
            }
        }
        self.listeners = keep;
        for handle in dead {
            self.sockets.remove(handle);
        }
    }

    fn drain_replies(&mut self) {
        let items: Vec<EpReply> = {
            let mut q = self.replies.lock().unwrap_or_else(|e| e.into_inner());
            q.drain(..).collect()
        };
        for r in items {
            let Some(handle) = self.ensure_udp_socket(r.local.port()) else {
                continue;
            };
            let sock = self.sockets.get_mut::<udp::Socket>(handle);
            let mut meta = udp::UdpMetadata::from(IpEndpoint::new(
                smol_ip(r.client.ip()),
                r.client.port(),
            ));
            meta.local_address = Some(smol_ip(r.local.ip()));
            if let Err(e) = sock.send_slice(&r.data, meta) {
                tracing::debug!(target: "engine", "wg endpoint: udp reply to {}: {e:?}", r.client);
            }
        }
    }

    fn service_conns(&mut self) {
        let mut dead: Vec<SocketHandle> = Vec::new();
        for c in self.conns.iter_mut() {
            let sock = self.sockets.get_mut::<tcp::Socket>(c.handle);
            let mut g = c.shared.lock();

            while g.to_proxy.len() < STREAM_QUEUE_MAX && sock.can_recv() {
                let n = match sock.recv_slice(&mut self.pump_buf) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                g.to_proxy.extend(self.pump_buf[..n].iter().copied());
            }
            if !sock.may_recv() && sock.recv_queue() == 0 {
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
                // Closed without our own graceful FIN = the peer reset (or we
                // aborted): writers must fail now instead of queuing into a
                // dead socket forever (wave-12: mid-burst RST hung write_all).
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
            drop(g);
            if gone {
                dead.push(c.handle);
            }
        }
        if !dead.is_empty() {
            self.conns.retain(|c| !dead.contains(&c.handle));
            for handle in dead {
                self.sockets.remove(handle);
            }
        }
    }

    fn drain_udp_rx(&mut self) {
        for handle in self.udp_sockets.values() {
            let sock = self.sockets.get_mut::<udp::Socket>(*handle);
            while sock.can_recv() {
                if sock.recv_slice(&mut self.pump_buf).is_err() {
                    break;
                }
            }
        }
    }

    fn gc_sessions(&mut self) {
        let now = Instant::now();
        if now < self.next_gc {
            return;
        }
        self.next_gc = now + Duration::from_secs(10);
        self.sessions
            .retain(|_, s| now.duration_since(s.last_activity) < self.udp_timeout);
    }

    /// When the driver should wake on its own.
    fn poll_delay(&mut self) -> Duration {
        let stack = self
            .iface
            .poll_delay(self.now(), &self.sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(MAX_TICK);
        stack.clamp(MIN_TICK, MAX_TICK)
    }
}

/// smoltcp `IpEndpoint` -> `(IpAddr, u16)`.
fn ep_to_sockaddr(ep: IpEndpoint) -> (IpAddr, u16) {
    match ep.addr {
        IpAddress::Ipv4(a) => (IpAddr::V4(a), ep.port),
        IpAddress::Ipv6(a) => (IpAddr::V6(a), ep.port),
    }
}

fn smol_ip(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(a) => IpAddress::Ipv4(a),
        IpAddr::V6(a) => IpAddress::Ipv6(a),
    }
}

/// Drive the endpoint until the socket dies.
async fn run_endpoint(socket: Arc<UdpSocket>, mut ep: Endpoint, mut stack: EpStack, wake: Arc<Notify>) {
    let mut rx = vec![0u8; 65_536];
    loop {
        let egress = stack.step();
        for pkt in egress {
            ep.send_inner(&socket, &pkt).await;
        }
        let offset = stack
            .poll_delay()
            .clamp(MIN_TICK, MAX_TICK);
        let deadline = Instant::now() + offset;
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::select! {
            biased;
            r = socket.recv_from(&mut rx) => {
                match r {
                    Ok((n, from)) => {
                        ep.on_datagram(&socket, from, &mut rx[..n], &mut stack).await;
                    }
                    Err(e) => {
                        tracing::debug!(target: "engine", "wg endpoint: udp recv error: {e}");
                    }
                }
            }
            _ = wake.notified() => {}
            _ = sleep => {
                ep.on_timer(&socket).await;
            }
        }
    }
}

/// Bind, spawn the endpoint driver, and return the bound address plus the
/// driver's task handle (tests use the handle for teardown; production goes
/// through [`serve_endpoint`]).
async fn spawn_endpoint(
    cfg: &WgEndpointCfg,
    relay: SharedRelay,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let ep = Endpoint::new(cfg)?;
    let port = cfg.listen_port;
    // Dual-stack when the platform allows it, plain v4 otherwise (the
    // docker e2e hosts run v6-disabled kernels).
    let socket = match UdpSocket::bind(format!("[::]:{port}")).await {
        Ok(s) => s,
        Err(_) => UdpSocket::bind(format!("0.0.0.0:{port}"))
            .await
            .map_err(|e| Error::network(format!("wg endpoint: bind udp {port}: {e}")))?,
    };
    let local = socket.local_addr().map_err(|e| {
        Error::network(format!("wg endpoint: bound socket has no address: {e}"))
    })?;
    let socket = Arc::new(socket);
    let wake = Arc::new(Notify::new());
    let stack = EpStack::new(cfg, relay, wake.clone())?;
    let task_socket = socket.clone();
    let task = tokio::spawn(async move {
        run_endpoint(task_socket, ep, stack, wake).await;
    });
    tracing::info!(target: "engine", "wg endpoint {} listening on {local}", cfg.tag);
    Ok((local, task))
}

/// Start a WireGuard endpoint (server): bind the UDP listener, spawn the
/// handshake/transport driver, and return the bound address. The endpoint
/// runs until the runtime shuts down; the engine's other inbounds share the
/// shape (bind + spawn + report the address).
pub async fn serve_endpoint(cfg: &WgEndpointCfg, relay: SharedRelay) -> Result<SocketAddr> {
    let (local, _task) = spawn_endpoint(cfg, relay).await?;
    Ok(local)
}

// ---------------------------------------------------------------------------
// et_pump: the raw packet surface for the easytier wg:// transport
// ---------------------------------------------------------------------------
//
// easytier's `tunnel/wireguard.rs` (v2.6.4) is WireGuard-as-transport: it
// drives cloudflare/boringtun's `Tunn` (the Noise_IKpsk2 handshake + the
// ChaCha20Poly1305 transport sessions + the update_timers routine) as a
// plain datagram pump under its `WgPeer`. This module exposes exactly the
// pieces of the engine's hand-rolled implementation that the easytier
// port (proto/easytier.rs) needs, through additive pub(crate) wrappers
// over the existing machinery above — nothing here changes behaviour, it
// only makes the already-tested builders/sessions reachable from the
// sibling module. Timer constants are NOT re-exported: boringtun's
// `noise/timers.rs` (REKEY_AFTER_TIME 120s, REJECT_AFTER_TIME 180s,
// REKEY_ATTEMPT_TIME 90s, REKEY_TIMEOUT 5s, KEEPALIVE_TIMEOUT 10s) is
// byte-identical to this file's, and easytier.rs cites its own copies.

/// The pub(crate) facade consumed by `proto::easytier` (its `wg://`
/// peer transport). Every item is a thin wrapper around the private
/// handshake/session machinery of this module.
pub(crate) mod et_pump {
    use super::*;

    /// The static keypair of one wg:// node. easytier derives it from the
    /// network identity (`WgConfig::new_from_network_identity`,
    /// tunnel/wireguard.rs:62-79): `sk = generate_digest_from_str(name,
    /// secret)`, and BOTH nodes of a network run the SAME pair, so each
    /// peer's configured `peer_public == my_public` and the Noise ss
    /// shared secret is X25519(sk, sk·G) = sk²·G — deterministic on both
    /// sides without any exchange.
    pub(crate) struct EtStatic(StaticKeys);

    /// Wrap a 32-byte secret into the static pair (pk = clamped X25519
    /// base multiplication).
    pub(crate) fn static_from_secret(sk: [u8; 32]) -> EtStatic {
        EtStatic(StaticKeys::from_secret(sk))
    }

    impl EtStatic {
        /// Our static public key (= the peer's, on the easytier mesh).
        pub(crate) fn public(&self) -> [u8; 32] {
            self.0.pk
        }
    }

    /// An outbound initiation awaiting its response (opaque state).
    pub(crate) struct EtPending(InitiationPending);

    /// [`StaticKeys`]-level `build_initiation`: the 148-byte initiation
    /// plus the state to consume the response.
    pub(crate) fn build_initiation(
        statics: &EtStatic,
        peer_pk: &[u8; 32],
        cookie: Option<[u8; 16]>,
        local_index: u32,
    ) -> Result<(Vec<u8>, EtPending)> {
        let (msg, pending) = super::build_initiation(&statics.0, peer_pk, cookie, local_index)?;
        Ok((msg, EtPending(pending)))
    }

    /// The result of a completed handshake: transport keys plus the
    /// session indices.
    pub(crate) struct EtHandshakeDone {
        pub local_index: u32,
        pub peer_index: u32,
        /// Initiator-side send key.
        pub send_key: [u8; 32],
        /// Initiator-side receive key.
        pub recv_key: [u8; 32],
    }

    pub(crate) fn consume_response(
        statics: &EtStatic,
        pending: &mut EtPending,
        msg: &WgMsg,
    ) -> Result<EtHandshakeDone> {
        // easytier never configures a PSK (Tunn::new(.., None, ..)).
        let done = super::consume_response(&statics.0, &mut pending.0, msg, &[0u8; 32])?;
        Ok(EtHandshakeDone {
            local_index: done.local_index,
            peer_index: done.peer_index,
            send_key: done.send_key,
            recv_key: done.recv_key,
        })
    }

    /// Consume a cookie-reply datagram for a pending initiation.
    pub(crate) fn consume_cookie_reply(
        peer_pk: &[u8; 32],
        pending: &EtPending,
        msg: &WgMsg,
    ) -> Result<[u8; 16]> {
        super::consume_cookie_reply(peer_pk, &pending.0, msg)
    }

    /// An authenticated initiation awaiting the psk2/response step
    /// (`OpenInitiation`, opaque; the timestamp and initiator static are
    /// readable for the replay guard and the peer-key check).
    pub(crate) struct EtOpenInitiation(OpenInitiation);

    impl EtOpenInitiation {
        /// The initiation's TAI64N (memcmp-comparable; strictly greater
        /// than the last accepted one, boringtun handshake.rs:543-547).
        pub(crate) fn timestamp(&self) -> [u8; 12] {
            self.0.timestamp
        }

        /// The initiator's unsealed static public key — easytier requires
        /// it to equal the configured peer key (boringtun's
        /// `verify_slices_are_equal(peer_static_public, decrypted)`,
        /// handshake.rs:527-532 → `WrongKey`).
        pub(crate) fn initiator_static(&self) -> [u8; 32] {
            self.0.client_static
        }
    }

    /// Responder half: verify an initiation up to (excluding) psk2.
    pub(crate) fn open_initiation(statics: &EtStatic, msg: &WgMsg) -> Result<EtOpenInitiation> {
        Ok(EtOpenInitiation(super::open_initiation(&statics.0, msg)?))
    }

    /// Responder half: complete the handshake (PSK always zero on the
    /// easytier mesh), returning the 92-byte response plus the session
    /// keys from the responder's perspective (`send_key` = the key the
    /// initiator sends with, `recv_key` = the one it receives with).
    pub(crate) fn respond_initiation(
        open: EtOpenInitiation,
        server_index: u32,
    ) -> Result<(Vec<u8>, EtHandshakeDone)> {
        let (resp, (_server_index, peer_index, k_client_send, k_client_recv)) =
            super::respond_initiation(open.0, &[0u8; 32], server_index)?;
        Ok((
            resp,
            EtHandshakeDone {
                local_index: server_index,
                peer_index,
                send_key: k_client_send,
                recv_key: k_client_recv,
            },
        ))
    }

    /// One transport session (send + receive halves with the 64-bit
    /// counter and the anti-replay window).
    pub(crate) struct EtSession(Session);

    impl EtSession {
        /// The initiator's session (`Session::from_handshake`).
        pub(crate) fn from_initiator(done: EtHandshakeDone) -> Self {
            EtSession(Session::from_handshake(
                HandshakeDone {
                    local_index: done.local_index,
                    peer_index: done.peer_index,
                    send_key: done.send_key,
                    recv_key: done.recv_key,
                },
                Instant::now(),
            ))
        }

        /// The responder's session (`Session::from_responder` — sends
        /// with the initiator's receive key and vice versa).
        pub(crate) fn from_responder(
            local_index: u32,
            peer_index: u32,
            peer_send_key: [u8; 32],
            peer_recv_key: [u8; 32],
        ) -> Self {
            EtSession(Session::from_responder(
                local_index,
                peer_index,
                peer_send_key,
                peer_recv_key,
                Instant::now(),
            ))
        }

        /// Our receiver index (the peer's `receiver` field addressing us).
        pub(crate) fn local_index(&self) -> u32 {
            self.0.local_index
        }

        /// Seal one inner IP packet into a transport datagram (padded to
        /// a multiple of 16, counter claimed first).
        pub(crate) fn seal(&mut self, inner: &[u8]) -> Result<Vec<u8>> {
            self.0.seal_transport(inner)
        }

        /// Open a transport payload (tag, then replay window).
        pub(crate) fn open(&mut self, counter: u64, data: &[u8]) -> Result<Vec<u8>> {
            self.0.open_transport(counter, data)
        }
    }

    /// Trim AEAD padding off a decrypted inner packet via the IPv4
    /// total-length field (boringtun trims the same way in
    /// `decrypt_packet`, noise/mod.rs).
    pub(crate) fn trim_ip_packet(pkt: &mut Vec<u8>) {
        super::trim_ip_packet(pkt)
    }
}

// ---------------------------------------------------------------------------
// Tests: crypto vectors, handshake round-trips against an in-test
// responder, timer boundaries, and full loopback tunnels (real UDP
// sockets on 127.0.0.1, keys generated at runtime).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    // -- BLAKE2s / HMAC / KDF -----------------------------------------------

    #[test]
    fn blake2s_known_vectors() {
        // Cross-checked against Python hashlib.blake2s (RFC 7693 vectors
        // for the unkeyed hashes).
        assert_eq!(
            hex(&blake2s256(b"")),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        );
        assert_eq!(
            hex(&blake2s256(b"abc")),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
        // Multi-block (256 bytes > 64) exercises the counter path.
        assert_eq!(
            hex(&blake2s256(&(0..=255u8).collect::<Vec<u8>>())),
            "5fdeb59f681d975f52c8e69c5502e02a12a3afcc5836ba58f42784c439228781"
        );
    }

    #[test]
    fn blake2s_keyed_mac_vectors() {
        // Keyed BLAKE2s, digest 16 — the protocol's MAC(). Cross-checked
        // against Python hashlib.blake2s(key=..., digest_size=16).
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            hex(&blake2s_mac(&key, b"")),
            "9536f9b267655743dee97b8a670f9f53"
        );
        assert_eq!(
            hex(&blake2s_mac(&key, b"abc")),
            "61ba5f165c194692e09d12520cc4c74a"
        );
        assert_eq!(
            hex(&blake2s_mac(&key, &(0..=255u8).collect::<Vec<u8>>())),
            "d5a40ec316c751a63cd0d91157fa1ebb"
        );
    }

    #[test]
    fn hmac_blake2s_known_vectors() {
        // Cross-checked against Python hmac.new(key, msg, hashlib.blake2s).
        assert_eq!(
            hex(&hmac_blake2s(
                b"key",
                b"The quick brown fox jumps over the lazy dog"
            )),
            "f93215bb90d4af4c3061cd932fb169fb8bb8a91d0b4022baea1271e1323cd9a0"
        );
        assert_eq!(
            hex(&hmac_blake2s(
                &(0..=31u8).collect::<Vec<u8>>(),
                &(0..=255u8).collect::<Vec<u8>>()
            )),
            "66e8260777230a3a870fdec816d6487e9df792ddff3d542dab2d19123acaaa35"
        );
        // Keys longer than the 64-byte block are hashed first (HMAC rule).
        let long = vec![7u8; 100];
        assert_eq!(hmac_blake2s(&long, b"x"), {
            let hashed = blake2s256(&long);
            hmac_blake2s(&hashed, b"x")
        });
    }

    #[test]
    fn kdf_chain_matches_manual_formulas() {
        // KDF2 = temp/ck'/key exactly as the whitepaper spells them.
        let ck = blake2s256(b"chain");
        let x = blake2s256(b"input");
        let (ck2, key) = kdf2(&ck, &x);
        let temp = hmac_blake2s(&ck, &x);
        assert_eq!(ck2, hmac_blake2s(&temp, &[1]));
        let mut mat = ck2.to_vec();
        mat.push(2);
        assert_eq!(key, hmac_blake2s(&temp, &mat));
        // KDF3 adds temp2 (mixed into the hash) and key(temp, temp2 || 3).
        let (ck3, temp2, key3) = kdf3(&ck, &x);
        assert_eq!(ck3, ck2);
        assert_eq!(temp2, hmac_blake2s(&temp, &mat));
        let mut mat2 = temp2.to_vec();
        mat2.push(3);
        assert_eq!(key3, hmac_blake2s(&temp, &mat2));
        // Transport keys: HMAC chain off the empty message.
        let (a, b) = derive_transport_keys(&ck);
        let t1 = hmac_blake2s(&ck, &[]);
        assert_eq!(a, hmac_blake2s(&t1, &[1]));
        assert_ne!(a, b);
        assert_eq!(b, hmac_blake2s(&t1, &[a.as_slice(), &[2]].concat()));
    }

    // -- wire codec ----------------------------------------------------------

    #[test]
    fn message_sizes_and_reserved_bytes() {
        let (statics, peer, _) = test_keys();
        let (msg, _) = build_initiation(&statics, &peer, None, 0xdead_beef).unwrap();
        assert_eq!(msg.len(), MSG_INITIATION_LEN);
        assert_eq!(&msg[..4], &1u32.to_le_bytes());
        assert_eq!(le32(&msg[4..8]), 0xdead_beef);
        match parse_wg_msg(&msg).unwrap() {
            WgMsg::Initiation { sender, .. } => assert_eq!(sender, 0xdead_beef),
            other => panic!("expected initiation, got {other:?}"),
        }

        // The mihomo reserved rewrite: bytes 1..3 on the wire, byte 0
        // untouched, reversible by strip_reserved.
        let mut wire = msg.clone();
        apply_reserved(&mut wire, [0xAB, 0x03, 0x7F]);
        assert_eq!(wire[0], 1);
        assert_eq!(&wire[1..4], &[0xAB, 0x03, 0x7F]);
        assert_eq!(&wire[4..], &msg[4..]);
        strip_reserved(&mut wire);
        assert_eq!(wire, msg);

        // Transport parse: 16-byte header + at least a tag.
        let mut t = Vec::new();
        t.extend_from_slice(&4u32.to_le_bytes());
        t.extend_from_slice(&7u32.to_le_bytes());
        t.extend_from_slice(&9u64.to_le_bytes());
        t.extend_from_slice(&[0u8; 16]);
        match parse_wg_msg(&t).unwrap() {
            WgMsg::Transport { receiver, counter, data } => {
                assert_eq!((receiver, counter), (7, 9));
                assert_eq!(data.len(), 16);
            }
            other => panic!("expected transport, got {other:?}"),
        }
        // Cookie is exactly 64 bytes; a truncated anything is rejected.
        assert!(parse_wg_msg(&[3u8, 0, 0, 0]).is_none());
        assert!(parse_wg_msg(&msg[..147]).is_none());
    }

    // -- noise handshake against the in-test responder ------------------------

    fn test_keys() -> (StaticKeys, [u8; 32], [u8; 32]) {
        let statics = x25519_keypair();
        let peer_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        (statics, peer_keys.pk, psk)
    }

    /// Full client <-> responder round trip at the pure-crypto level: the
    /// responder consumes our initiation, replies, and both sides must
    /// land on mirrored transport keys with MAC1 verifying on the way.
    fn handshake_roundtrip(psk: &[u8; 32]) -> (Session, TestSession) {
        let client = x25519_keypair();
        let server = x25519_keypair();
        let (msg, mut pending) = build_initiation(&client, &server.pk, None, 42).unwrap();
        let parsed = parse_wg_msg(&msg).unwrap();
        let (resp, server_keys, _timestamp) =
            server::consume_initiation_and_respond(&server, &parsed, psk, 1000).unwrap();
        let resp_parsed = parse_wg_msg(&resp).unwrap();
        let done = consume_response(&client, &mut pending, &resp_parsed, psk).unwrap();
        let now = Instant::now();
        (
            Session::from_handshake(done, now),
            TestSession::from_handshake(server_keys, now),
        )
    }

    #[test]
    fn noise_handshake_roundtrip_psk() {
        let psk = blake2s256(b"a pre-shared key for tests");
        let (mut client, mut server) = handshake_roundtrip(&psk);
        // Keys must be mirrored: client send == server recv and back,
        // proven by an actual transport exchange in both directions.
        let payload = b"hello tunnel";
        let msg = client.seal_transport(payload).unwrap();
        match parse_wg_msg(&msg).unwrap() {
            WgMsg::Transport { receiver, counter, data } => {
                assert_eq!(receiver, 1000, "receiver must be the server's index");
                assert_eq!(counter, 0);
                let plain = server.open_transport(counter, &data).unwrap();
                assert_eq!(&plain[..payload.len()], payload);
                assert!(plain.len() >= payload.len());
                // And the reverse direction.
                let back = server.seal_transport(b"pong").unwrap();
                match parse_wg_msg(&back).unwrap() {
                    WgMsg::Transport { counter, data, .. } => {
                        let plain = client.open_transport(counter, &data).unwrap();
                        assert_eq!(&plain[..4], b"pong");
                    }
                    other => panic!("expected transport, got {other:?}"),
                }
            }
            other => panic!("expected transport, got {other:?}"),
        }
    }

    #[test]
    fn noise_handshake_without_psk() {
        // PSK-less mode is psk = 32 zero bytes; the round trip must work
        // exactly the same.
        let (mut client, mut server) = handshake_roundtrip(&[0u8; 32]);
        let msg = client.seal_transport(&[]).unwrap(); // keepalive
        match parse_wg_msg(&msg).unwrap() {
            WgMsg::Transport { data, .. } => {
                let plain = server.open_transport(0, &data).unwrap();
                assert!(plain.is_empty());
            }
            other => panic!("expected transport, got {other:?}"),
        }
    }

    #[test]
    fn wrong_psk_fails_the_response_verification() {
        let client = x25519_keypair();
        let server = x25519_keypair();
        let psk = blake2s256(b"correct psk");
        let (msg, mut pending) = build_initiation(&client, &server.pk, None, 7).unwrap();
        let parsed = parse_wg_msg(&msg).unwrap();
        let (resp, _, _) =
            server::consume_initiation_and_respond(&server, &parsed, &psk, 8).unwrap();
        let resp_parsed = parse_wg_msg(&resp).unwrap();
        // Client with the wrong PSK: the psk2 mix diverges and the
        // encrypted-empty MAC must not verify.
        let err = consume_response(&client, &mut pending, &resp_parsed, &[9u8; 32]);
        assert!(err.is_err());
    }

    #[test]
    fn tampered_mac1_initiation_is_silent() {
        // A server never responds to an unauthenticated initiation: MAC1
        // keyed by its own static must verify first.
        let client = x25519_keypair();
        let server = x25519_keypair();
        let (mut msg, _) = build_initiation(&client, &server.pk, None, 1).unwrap();
        msg[10] ^= 0x40; // corrupt the ephemeral (inside MAC1 coverage)
        let parsed = parse_wg_msg(&msg).unwrap();
        assert!(server::consume_initiation_and_respond(&server, &parsed, &[0u8; 32], 2).is_err());
    }

    #[test]
    fn cookie_reply_flow_sets_mac2() {
        let client = x25519_keypair();
        let server = x25519_keypair();
        let (msg, pending) = build_initiation(&client, &server.pk, None, 5).unwrap();
        let _ = msg;
        // Server under load: reply with a cookie encrypted to the
        // initiation's mac1 (exactly the whitepaper's cookie packet).
        let cookie = blake2s_mac(&blake2s256(b"server secret"), b"1.2.3.4:5678");
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let enc = XChaCha20Poly1305::new_from_slice(&cookie_key(&server.pk))
            .unwrap()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &cookie,
                    aad: &pending.last_mac1,
                },
            )
            .unwrap();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&3u32.to_le_bytes());
        pkt.extend_from_slice(&5u32.to_le_bytes());
        pkt.extend_from_slice(&nonce);
        pkt.extend_from_slice(&enc);
        assert_eq!(pkt.len(), MSG_COOKIE_LEN);
        let learned =
            consume_cookie_reply(&server.pk, &pending, &parse_wg_msg(&pkt).unwrap()).unwrap();
        assert_eq!(learned, cookie);
        // The next initiation carries MAC2 keyed by that cookie instead
        // of zeros.
        let (msg2, _) = build_initiation(&client, &server.pk, Some(learned), 6).unwrap();
        let expected = blake2s_mac(&learned, &msg2[..132]);
        assert_eq!(&msg2[132..148], &expected);
        assert_ne!(&msg2[132..148], &[0u8; 16]);
    }

    // -- transport session ----------------------------------------------------

    #[test]
    fn transport_counters_replay_and_trim() {
        let (mut client, mut server) = handshake_roundtrip(&[0u8; 32]);
        let mk = |n: usize| {
            // Minimal IPv4-shaped packet so trim_ip_packet bites: header
            // says 20 + n, body carries n + trailing padding.
            let total = 20 + n;
            let mut pkt = vec![0x45u8, 0, (total >> 8) as u8, total as u8];
            pkt.resize(20, 0);
            pkt.extend(std::iter::repeat_n(0xAA, n));
            pkt.extend(std::iter::repeat_n(
                0,
                PADDING_MULTIPLE - (total % PADDING_MULTIPLE),
            ));
            pkt
        };
        // Three exchanges: counters 0, 1, 2 — each trimmed back to the
        // IPv4 total length, proving padding is stripped on receive.
        let mut first: Option<(u64, Vec<u8>)> = None;
        for n in [1usize, 16, 40] {
            let pkt = mk(n);
            let msg = client.seal_transport(&pkt).unwrap();
            let WgMsg::Transport { counter, data, .. } = parse_wg_msg(&msg).unwrap() else {
                panic!()
            };
            let mut plain = server.open_transport(counter, &data).unwrap();
            trim_ip_packet(&mut plain);
            assert_eq!(plain.len(), 20 + n, "padding must be trimmed");
            assert_eq!(plain, &pkt[..20 + n]);
            if n == 1 {
                first = Some((counter, data));
            }
        }
        // A replayed (counter, ciphertext) pair is rejected after tag
        // verification.
        let (c, d) = first.unwrap();
        assert!(server.open_transport(c, &d).is_err());
        // Counters keep advancing past the exchanges above.
        let keepalive = client.seal_transport(&[]).unwrap();
        let WgMsg::Transport { counter, data, .. } =
            parse_wg_msg(&keepalive).unwrap()
        else {
            panic!()
        };
        assert_eq!(counter, 3);
        assert!(server.open_transport(counter, &data).is_ok());
    }

    #[test]
    fn keepalive_is_an_empty_transport_message() {
        let (mut client, _server) = handshake_roundtrip(&[0u8; 32]);
        let msg = client.seal_transport(&[]).unwrap();
        match parse_wg_msg(&msg).unwrap() {
            WgMsg::Transport { data, .. } => assert_eq!(data.len(), 16, "just the Poly1305 tag"),
            other => panic!("expected transport, got {other:?}"),
        }
        assert_eq!(msg.len(), TRANSPORT_HEADER_LEN + 16);
    }

    #[test]
    fn anti_replay_window_semantics() {
        let mut w = AntiReplay::new();
        assert!(w.accept(0));
        assert!(!w.accept(0), "duplicate");
        assert!(w.accept(1));
        assert!(w.accept(2));
        assert!(!w.accept(1), "duplicate inside window");
        // Reordering within the window is fine.
        assert!(w.accept(4));
        assert!(w.accept(3));
        // Window edges, tested from a high base so subtraction cannot
        // underflow: 2048 behind the highest is too old, 2047 is in.
        let base: u64 = 1 << 40;
        assert!(w.accept(base));
        assert!(!w.accept(base - 2048), "one past the window edge");
        assert!(w.accept(base - 2047), "exactly the window edge is in");
        assert!(!w.accept(base - 2047), "... but only once");
        // Jumping far ahead clears the window: the old bits are gone.
        let hi = base + 5000;
        assert!(w.accept(hi));
        assert!(w.accept(hi - 2047), "old highest slid out");
        assert!(!w.accept(hi - 2048));
        // The reserved top counters are rejected outright.
        assert!(!w.accept(u64::MAX));
        assert!(!w.accept(REJECT_AFTER_MESSAGES));
    }

    #[test]
    fn rekey_and_keepalive_boundaries() {
        let t0 = Instant::now();
        // Fresh session: no rekey, no keepalive.
        assert!(!should_rekey(t0, 0, t0 + REKEY_AFTER_TIME - Duration::from_millis(1)));
        assert!(should_rekey(t0, 0, t0 + REKEY_AFTER_TIME));
        // Message-count trigger (2^60) independent of time.
        assert!(should_rekey(t0, REKEY_AFTER_MESSAGES, t0));
        assert!(!should_rekey(t0, REKEY_AFTER_MESSAGES - 1, t0));
        // Reject-after is strictly later than rekey-after.
        assert!(!session_expired(t0, t0 + REJECT_AFTER_TIME - Duration::from_millis(1)));
        assert!(session_expired(t0, t0 + REJECT_AFTER_TIME));
        assert!(REJECT_AFTER_TIME > REKEY_AFTER_TIME);
        // Keepalive after 10s of transmit silence.
        assert!(!needs_keepalive(t0, t0 + KEEPALIVE_TIMEOUT - Duration::from_millis(1)));
        assert!(needs_keepalive(t0, t0 + KEEPALIVE_TIMEOUT));
        // The whitepaper's counter constants, pinned.
        assert_eq!(REKEY_AFTER_MESSAGES, 1 << 60);
        assert_eq!(REJECT_AFTER_MESSAGES, u64::MAX - (1 << 13) - 1);
        assert_eq!(REKEY_ATTEMPT_TIME, REKEY_TIMEOUT * 18);
    }

    #[test]
    fn tai64n_is_big_endian_comparable() {
        let a = tai64n_now();
        std::thread::sleep(Duration::from_millis(2));
        let b = tai64n_now();
        assert!(b > a, "TAI64N memcmp order follows time order");
        assert_eq!(a[0], 0x40, "TAI64 label byte");
        assert_eq!(a.len(), 12);
    }

    // -- config / address guards ----------------------------------------------

    #[tokio::test]
    async fn connect_rejects_domain_and_unconfigured_ipv6_targets() {
        let cfg = dummy_cfg("127.0.0.1", 1);
        // Domains are always refused: upstream resolves outside the tunnel
        // and hands the stack an IP.
        let err = match connect(&cfg, &NetAddr::domain("example.com", 443).unwrap()).await {
            Ok(_) => panic!("domain targets must be refused"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("resolve before dialing"));
        // IPv6 without a configured inner v6 address is refused too —
        // sing-wireguard derives no addresses, so the family is not guessed.
        let err = match connect(
            &cfg,
            &NetAddr::ip(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 443),
        )
        .await
        {
            Ok(_) => panic!("ipv6 targets must be refused without an inner v6 address"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("no inner IPv6 address"));
        // With a configured v6 address the same target passes the guard.
        let mut cfg6 = cfg;
        cfg6.local_ipv6 = Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
        assert!(target_addr(
            &NetAddr::ip(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 443),
            "connect",
            cfg6.local_ipv6
        )
        .is_ok());
    }

    fn dummy_cfg(server: &str, port: u16) -> WgOut {
        let (statics, peer, _) = test_keys();
        WgOut {
            server: server.to_string(),
            port,
            private_key: b64(&statics.sk),
            peer_public_key: b64(&peer),
            pre_shared_key: None,
            local_ip: Ipv4Addr::new(172, 16, 200, 2),
            local_ipv6: None,
            mtu: 0,
            reserved: [0; 3],
            udp: true,
        }
    }

    // ========================================================================
    // The in-test WireGuard server: noise responder + transport decryption +
    // a smoltcp stack terminating TCP/UDP inside the tunnel. Everything is
    // generated at runtime; nothing leaves loopback. The noise responder is
    // address-agnostic (WireGuard messages carry no IP addresses), so it
    // answers v4 and v6 handshakes identically — the IPv6 tunnel tests below
    // drive the very same handshake; only the inner IP layer differs.
    // ========================================================================

    mod server {
        use super::*;

        pub(crate) struct TestSession {
            pub local_index: u32,
            pub peer_index: u32,
            pub send_cipher: ChaCha20Poly1305,
            pub recv_cipher: ChaCha20Poly1305,
            pub replay: AntiReplay,
            pub next: u64,
        }

        impl TestSession {
            pub(crate) fn from_handshake(
                (local_index, peer_index, k1, k2): (u32, u32, [u8; 32], [u8; 32]),
                _now: Instant,
            ) -> Self {
                TestSession {
                    local_index,
                    peer_index,
                    send_cipher: make_cipher(&k2),
                    recv_cipher: make_cipher(&k1),
                    replay: AntiReplay::new(),
                    next: 0,
                }
            }

            pub(crate) fn seal(&mut self, inner: &[u8]) -> Vec<u8> {
                let counter = self.next;
                self.next += 1;
                let mut plain = inner.to_vec();
                while !plain.len().is_multiple_of(PADDING_MULTIPLE) {
                    plain.push(0);
                }
                let ct = self
                    .send_cipher
                    .encrypt(
                        (&aead_nonce(counter)).into(),
                        Payload { msg: &plain, aad: &[] },
                    )
                    .unwrap();
                let mut msg = Vec::with_capacity(TRANSPORT_HEADER_LEN + ct.len());
                msg.extend_from_slice(&(MSG_TYPE_TRANSPORT as u32).to_le_bytes());
                msg.extend_from_slice(&self.peer_index.to_le_bytes());
                msg.extend_from_slice(&counter.to_le_bytes());
                msg.extend_from_slice(&ct);
                msg
            }

            pub(crate) fn open(&mut self, counter: u64, data: &[u8]) -> Result<Vec<u8>> {
                let plain = self
                    .recv_cipher
                    .decrypt(
                        (&aead_nonce(counter)).into(),
                        Payload { msg: data, aad: &[] },
                    )
                    .map_err(|_| Error::crypto("server: transport open failed"))?;
                if !self.replay.accept(counter) {
                    return Err(Error::protocol("server: replay"));
                }
                Ok(plain)
            }

            /// Session-compatible aliases so tests can treat the server
            /// side and the client side identically.
            pub(crate) fn seal_transport(&mut self, inner: &[u8]) -> Result<Vec<u8>> {
                Ok(self.seal(inner))
            }

            pub(crate) fn open_transport(&mut self, counter: u64, data: &[u8]) -> Result<Vec<u8>> {
                self.open(counter, data)
            }
        }

        /// Server-side session keys from a consumed initiation:
        /// (server index, peer index, client-send key, client-recv key).
        type ServerKeys = (u32, u32, [u8; 32], [u8; 32]);

        /// Thin adapter over the production responder (open_initiation +
        /// respond_initiation) keeping the in-test call sites' shape.
        pub(crate) fn consume_initiation_and_respond(
            server_static: &StaticKeys,
            msg: &WgMsg,
            psk: &[u8; 32],
            server_index: u32,
        ) -> Result<(Vec<u8>, ServerKeys, [u8; 12])> {
            let open = open_initiation(server_static, msg)?;
            let timestamp = open.timestamp;
            let (resp, keys) = respond_initiation(open, psk, server_index)?;
            Ok((resp, keys, timestamp))
        }
    }

    use server::TestSession;

    /// The loopback WireGuard server: a real tokio UdpSocket plus a
    /// smoltcp stack whose TCP listener echoes bytes and whose UDP socket
    /// echoes datagrams. `expected_reserved` asserts the mihomo
    /// reserved-byte encoding on every datagram we receive.
    struct LoopbackServer {
        statics: StaticKeys,
        psk: [u8; 32],
        endpoint: SocketAddr,
        expected_reserved: Option<[u8; 3]>,
    }

    const SERVER_TUNNEL_IP: Ipv4Addr = Ipv4Addr::new(172, 16, 200, 1);
    const SERVER_TUNNEL_IP_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x1720, 0x16, 0x200, 0, 0, 0, 1);
    const CLIENT_TUNNEL_IP_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x1720, 0x16, 0x200, 0, 0, 0, 2);
    const ECHO_TCP_PORT: u16 = 9021;
    const ECHO_UDP_PORT: u16 = 9022;

    async fn spawn_wg_echo_server(expected_reserved: Option<[u8; 3]>) -> LoopbackServer {
        let statics = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap();
        let endpoint = socket.local_addr().unwrap();
        let socket = Arc::new(socket);

        let server_statics = StaticKeys::from_secret(statics.sk);
        tokio::spawn(async move {
            run_loopback_server(socket, server_statics, psk, expected_reserved).await;
        });
        LoopbackServer {
            statics,
            psk,
            endpoint,
            expected_reserved,
        }
    }

    impl LoopbackServer {
        fn cfg_for(&self, client: &StaticKeys) -> WgOut {
            self.cfg_with(client, false)
        }

        /// The same peer, dual-stack: v4 and v6 inner addresses (mihomo
        /// `ip` + `ipv6`, sing-box `local_address` with a v6 entry).
        fn cfg_for_dual(&self, client: &StaticKeys) -> WgOut {
            self.cfg_with(client, true)
        }

        fn cfg_with(&self, client: &StaticKeys, ipv6: bool) -> WgOut {
            WgOut {
                server: self.endpoint.ip().to_string(),
                port: self.endpoint.port(),
                private_key: b64(&client.sk),
                peer_public_key: b64(&self.statics.pk),
                pre_shared_key: Some(b64(&self.psk)),
                local_ip: Ipv4Addr::new(172, 16, 200, 2),
                local_ipv6: ipv6.then_some(CLIENT_TUNNEL_IP_V6),
                mtu: 0,
                reserved: self.expected_reserved.unwrap_or([0; 3]),
                udp: true,
            }
        }
    }

    /// The server's own smoltcp stack: address 172.16.200.1/24 plus
    /// fd00:172:16:200::1/64, with TCP echo listeners (re-armed on every
    /// accept, since a smoltcp listener becomes the accepted connection)
    /// and a UDP echo socket on both families.
    struct ServerStack {
        iface: Interface,
        sockets: SocketSet<'static>,
        shim: Shim,
        listener: SocketHandle,
        /// Accepted TCP connections being echoed.
        conns: Vec<SocketHandle>,
        udp_sock: SocketHandle,
        start: Instant,
        pump: Vec<u8>,
    }

    impl ServerStack {
        fn new() -> ServerStack {
            let mut shim = Shim::new(1408);
            let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
            cfg.random_seed = rand::random();
            let mut iface = Interface::new(cfg, &mut shim, SmolInstant::ZERO);
            iface.update_ip_addrs(|addrs| {
                let _ = addrs.push(IpCidr::new(
                    IpAddress::Ipv4(SERVER_TUNNEL_IP),
                    24,
                ));
                // Dual-stack listener side: the v6 prefix mirrors the /24 so
                // same-subnet replies need no route, plus a default v6 route.
                let _ = addrs.push(IpCidr::new(
                    IpAddress::Ipv6(SERVER_TUNNEL_IP_V6),
                    64,
                ));
            });
            iface
                .routes_mut()
                .add_default_ipv4_route(SERVER_TUNNEL_IP)
                .unwrap();
            iface
                .routes_mut()
                .add_default_ipv6_route(SERVER_TUNNEL_IP_V6)
                .unwrap();
            iface.set_any_ip(true);

            let mut sockets = SocketSet::new(Vec::new());
            let listener = Self::add_listener(&mut sockets);

            let mut udp_sock = udp::Socket::new(
                udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::EMPTY; 64],
                    vec![0; 32 * 1024],
                ),
                udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::EMPTY; 64],
                    vec![0; 32 * 1024],
                ),
            );
            udp_sock
                .bind(IpListenEndpoint {
                    addr: None,
                    port: ECHO_UDP_PORT,
                })
                .unwrap();
            let udp_sock = sockets.add(udp_sock);

            ServerStack {
                iface,
                sockets,
                shim,
                listener,
                conns: Vec::new(),
                udp_sock,
                start: Instant::now(),
                pump: vec![0u8; 32 * 1024],
            }
        }

        /// One more listening socket on the echo port (both families: the
        /// listen endpoint is address-agnostic).
        fn add_listener(sockets: &mut SocketSet<'static>) -> SocketHandle {
            let mut tcp_sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 64 * 1024]),
                tcp::SocketBuffer::new(vec![0; 64 * 1024]),
            );
            tcp_sock
                .listen(IpListenEndpoint {
                    addr: None,
                    port: ECHO_TCP_PORT,
                })
                .unwrap();
            sockets.add(tcp_sock)
        }

        fn now(&self) -> SmolInstant {
            SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
        }

        /// One server pass; returns egress IP packets to encrypt.
        fn step(&mut self) -> Vec<Vec<u8>> {
            let now = self.now();
            self.iface.poll(now, &mut self.shim, &mut self.sockets);

            // Promote accepted connections (a smoltcp listener socket becomes
            // the connection) and re-arm a fresh listener each time. Re-arm
            // as soon as the listener leaves Listen (not only once
            // Established): a second SYN racing the first handshake must find
            // a listening socket, or smoltcp answers it with an RST — the
            // same race fixed in the endpoint's needs_listener.
            match self.sockets.get::<tcp::Socket>(self.listener).state() {
                tcp::State::Listen => {}
                tcp::State::Closed => {
                    self.sockets.remove(self.listener);
                    self.listener = Self::add_listener(&mut self.sockets);
                }
                _ => {
                    self.conns.push(self.listener);
                    self.listener = Self::add_listener(&mut self.sockets);
                }
            }

            // TCP echo: whatever arrived on any connection goes straight back.
            let mut closed = Vec::new();
            for &handle in &self.conns {
                let sock = self.sockets.get_mut::<tcp::Socket>(handle);
                while sock.can_recv() {
                    let n = match sock.recv_slice(&mut self.pump) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    let mut off = 0;
                    while off < n {
                        match sock.send_slice(&self.pump[off..n]) {
                            Ok(w) => off += w,
                            Err(_) => break,
                        }
                    }
                }
                if sock.state() == tcp::State::Closed {
                    closed.push(handle);
                }
            }
            if !closed.is_empty() {
                self.conns.retain(|h| !closed.contains(h));
                for handle in closed {
                    self.sockets.remove(handle);
                }
            }

            // UDP echo: reply from the same endpoint, source address picked
            // by the requester's family (the client stack selects its source
            // the same way).
            {
                let sock = self.sockets.get_mut::<udp::Socket>(self.udp_sock);
                while sock.can_recv() {
                    let (n, meta) = match sock.recv_slice(&mut self.pump) {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    let mut reply_meta = meta;
                    reply_meta.local_address = match meta.endpoint.addr {
                        IpAddress::Ipv4(_) => Some(IpAddress::Ipv4(SERVER_TUNNEL_IP)),
                        IpAddress::Ipv6(_) => Some(IpAddress::Ipv6(SERVER_TUNNEL_IP_V6)),
                    };
                    if sock.send_slice(&self.pump[..n], reply_meta).is_err() {
                        break;
                    }
                }
            }

            let now = self.now();
            self.iface.poll(now, &mut self.shim, &mut self.sockets);
            self.shim.egress.drain(..).collect()
        }
    }

    async fn run_loopback_server(
        socket: Arc<UdpSocket>,
        statics: StaticKeys,
        psk: [u8; 32],
        expected_reserved: Option<[u8; 3]>,
    ) {
        let mut stack = ServerStack::new();
        let mut session: Option<TestSession> = None;
        // TAI64N replay guard: strictly newer timestamps only (the
        // whitepaper's DoS-mitigation rule; TAI64N memcmp == time order).
        let mut last_timestamp: Option<[u8; 12]> = None;
        let mut peer: Option<SocketAddr> = None;
        let mut rx = vec![0u8; 65_536];
        loop {
            for pkt in stack.step() {
                if let (Some(sess), Some(dst)) = (session.as_mut(), peer) {
                    let msg = sess.seal(&pkt);
                    let _ = socket.send_to(&msg, dst).await;
                }
            }
            let tick = tokio::time::sleep(Duration::from_millis(10));
            tokio::select! {
                r = socket.recv_from(&mut rx) => {
                    let Ok((n, from)) = r else { continue };
                    // mihomo's reserved encoding, server side: the three
                    // bytes must be what the test configured, and are
                    // zeroed before any parsing (MetaCubeX/sing-wireguard
                    // `receive`). A mismatched datagram is dropped — the
                    // handshake would then never complete and the test's
                    // connect() would fail loudly.
                    if let Some(expected) = expected_reserved {
                        if n < 4 || rx[1..4] != expected {
                            continue;
                        }
                    }
                    peer = Some(from);
                    strip_reserved(&mut rx[..n]);
                    let Some(msg) = parse_wg_msg(&rx[..n]) else { continue };
                    match msg {
                        WgMsg::Initiation { .. } => {
                            match server::consume_initiation_and_respond(
                                &statics, &msg, &psk, rand::random(),
                            ) {
                                Ok((resp, keys, timestamp)) => {
                                    let fresh = last_timestamp.as_ref().is_none_or(|t| timestamp > *t);
                                    if !fresh {
                                        continue; // replayed initiation: silent
                                    }
                                    last_timestamp = Some(timestamp);
                                    session = Some(TestSession::from_handshake(keys, Instant::now()));
                                    let _ = socket.send_to(&resp, from).await;
                                }
                                Err(_) => {
                                    // Unauthorized: stay silent (whitepaper).
                                }
                            }
                        }
                        WgMsg::Transport { receiver, counter, data } => {
                            let Some(sess) = session.as_mut() else { continue };
                            if sess.local_index != receiver { continue; }
                            if let Ok(mut inner) = sess.open(counter, &data) {
                                if inner.is_empty() { continue; } // keepalive
                                trim_ip_packet(&mut inner);
                                stack.shim.stage(&inner);
                            }
                        }
                        _ => {}
                    }
                }
                _ = tick => {}
            }
        }
    }

    // -- full loopback tunnels -------------------------------------------------

    #[tokio::test]
    async fn tcp_echo_through_loopback_wireguard() {
        let server = spawn_wg_echo_server(None).await;
        let client_keys = x25519_keypair();
        let cfg = server.cfg_for(&client_keys);
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);

        let mut stream = connect(&cfg, &target).await.expect("dial through the tunnel");
        let payload = b"hello over wireguard!".repeat(64);
        stream.write_all(&payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);

        // A second chunk in the same connection: the session stays up.
        stream.write_all(b"second chunk").await.unwrap();
        let mut more = vec![0u8; 12];
        stream.read_exact(&mut more).await.unwrap();
        assert_eq!(more, b"second chunk");

        stream.shutdown().await.unwrap();
    }

    /// REPRO (wave-12): a multi-segment write burst, then the full echo read
    /// back. 64 KiB spans ~48 segments at MSS 1368 — the burst that stalled
    /// scheduling-dependently in the wave-11 e2e environment. The timeout is
    /// the stall detector: on failure it names the phase.
    #[tokio::test]
    async fn tcp_echo_multisegment_burst_write_all_then_read() {
        let server = spawn_wg_echo_server(None).await;
        let client_keys = x25519_keypair();
        let cfg = server.cfg_for(&client_keys);
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);

        let mut stream = connect(&cfg, &target).await.expect("dial through the tunnel");
        let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        tokio::time::timeout(Duration::from_secs(30), stream.write_all(&payload))
            .await
            .expect("write-all of a 64 KiB burst must not stall")
            .unwrap();
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut echoed))
            .await
            .expect("read-back of a 64 KiB burst must not stall")
            .unwrap();
        assert_eq!(echoed, payload);
        stream.shutdown().await.unwrap();
    }

    /// REPRO (wave-12): 8 KiB chunks (6 segments each) with the echo read
    /// interleaved after every write — the request/response relay shape.
    #[tokio::test]
    async fn tcp_echo_multisegment_burst_interleaved_chunks() {
        let server = spawn_wg_echo_server(None).await;
        let client_keys = x25519_keypair();
        let cfg = server.cfg_for(&client_keys);
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);

        let mut stream = connect(&cfg, &target).await.expect("dial through the tunnel");
        for round in 0..8u32 {
            let chunk: Vec<u8> = (0..8 * 1024).map(|i| (i as u32 + round) as u8).collect();
            tokio::time::timeout(Duration::from_secs(30), stream.write_all(&chunk))
                .await
                .expect("interleaved 8 KiB write must not stall")
                .unwrap();
            let mut echoed = vec![0u8; chunk.len()];
            tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut echoed))
                .await
                .expect("interleaved 8 KiB read must not stall")
                .unwrap();
            assert_eq!(echoed, chunk);
        }
        stream.shutdown().await.unwrap();
    }

    /// REPRO (wave-12): a burst far beyond the bridge queue (128 KiB) and the
    /// socket buffers — write_all must block on the write waker and be
    /// released by ACK-driven draining; the read side chases it.
    #[tokio::test]
    async fn tcp_echo_burst_far_beyond_queue_blocks_and_drains() {
        let server = spawn_wg_echo_server(None).await;
        let client_keys = x25519_keypair();
        let cfg = server.cfg_for(&client_keys);
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);

        let stream = connect(&cfg, &target).await.expect("dial through the tunnel");
        const TOTAL: usize = 512 * 1024;
        let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 253) as u8).collect();
        let mut echoed = vec![0u8; TOTAL];

        // Full duplex: write everything while reading everything, as the
        // engine relay does (two tasks, one stream).
        let (mut r, mut w) = tokio::io::split(stream);
        let tx_payload = payload.clone();
        let writer = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(30), w.write_all(&tx_payload))
                .await
                .expect("512 KiB write_all must not stall behind the queue")
                .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(30), r.read_exact(&mut echoed))
            .await
            .expect("512 KiB read-back must not stall")
            .unwrap();
        writer.await.unwrap();
        assert_eq!(echoed, payload);
    }

    /// REPRO (wave-12): a deliberately slow reader — 1 KiB reads with yields
    /// — forces the receive window to close and reopen (zero-window probing)
    /// while the write side keeps producing.
    #[tokio::test]
    async fn tcp_echo_slow_reader_closes_and_reopens_window() {
        let server = spawn_wg_echo_server(None).await;
        let client_keys = x25519_keypair();
        let cfg = server.cfg_for(&client_keys);
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);

        let stream = connect(&cfg, &target).await.expect("dial through the tunnel");
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

    /// REPRO (wave-12): several concurrent multi-segment streams sharing one
    /// tunnel — the conns vector is serviced in one pass; each stream must
    /// still make progress under the others' bursts.
    #[tokio::test]
    async fn tcp_echo_concurrent_streams_multisegment() {
        let server = spawn_wg_echo_server(None).await;
        let client_keys = x25519_keypair();
        let cfg = server.cfg_for(&client_keys);

        const STREAMS: usize = 4;
        const TOTAL: usize = 64 * 1024;
        let mut handles = Vec::new();
        for s in 0..STREAMS {
            let cfg = cfg.clone();
            handles.push(tokio::spawn(async move {
                let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);
                let mut stream =
                    connect(&cfg, &target).await.expect("concurrent dial");
                for round in 0..8u32 {
                    let chunk: Vec<u8> = (0..TOTAL / 8)
                        .map(|i| (i as u32 + round + s as u32) as u8)
                        .collect();
                    tokio::time::timeout(Duration::from_secs(30), stream.write_all(&chunk))
                        .await
                        .expect("concurrent stream write must not stall")
                        .unwrap();
                    let mut echoed = vec![0u8; chunk.len()];
                    tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut echoed))
                        .await
                        .expect("concurrent stream read must not stall")
                        .unwrap();
                    assert_eq!(echoed, chunk);
                }
                stream.shutdown().await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    #[tokio::test]
    async fn udp_echo_through_loopback_wireguard() {
        let server = spawn_wg_echo_server(None).await;
        let client_keys = x25519_keypair();
        let cfg = server.cfg_for(&client_keys);
        let udp = WgUdp::bind(&cfg).await.expect("udp through the tunnel");
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_UDP_PORT);
        udp.send(&target, b"udp round trip").await.unwrap();
        let (from, data) = udp.recv().await.expect("echo datagram");
        assert_eq!(data, b"udp round trip");
        assert_eq!(from.to_string(), format!("{SERVER_TUNNEL_IP}:{ECHO_UDP_PORT}"));
        // And a second exchange on the same socket.
        udp.send(&target, b"again").await.unwrap();
        let (_, data2) = udp.recv().await.unwrap();
        assert_eq!(data2, b"again");
    }

    // -- IPv6 inner stack ------------------------------------------------------
    //
    // The noise responder is address-agnostic (WireGuard handshakes carry no
    // IP addresses), so these v6 tunnels run the very same
    // `consume_initiation_and_respond` handshake as the v4 tests; what
    // changes is the inner IP layer: the client stack carries
    // CLIENT_TUNNEL_IP_V6/128 with a default v6 route and dials with it as
    // the source, and the server stack answers from its v6 prefix.

    /// A TCP echo over the tunnel's IPv6 side, with the relay both ways.
    #[tokio::test]
    async fn tcp_echo_through_loopback_wireguard_ipv6() {
        let server = spawn_wg_echo_server(None).await;
        let client_keys = x25519_keypair();
        let cfg = server.cfg_for_dual(&client_keys);
        let target = NetAddr::ip(IpAddr::V6(SERVER_TUNNEL_IP_V6), ECHO_TCP_PORT);

        let mut stream = connect(&cfg, &target).await.expect("v6 dial through the tunnel");
        let payload = b"hello over wireguard v6!".repeat(64);
        stream.write_all(&payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload, "v6 TCP echo, both directions");
        stream.write_all(b"second v6 chunk").await.unwrap();
        let mut more = vec![0u8; 15];
        stream.read_exact(&mut more).await.unwrap();
        assert_eq!(more, b"second v6 chunk");
        stream.shutdown().await.unwrap();
    }

    /// A UDP echo over the tunnel's IPv6 side, including the NetAddr
    /// reporting a v6 source.
    #[tokio::test]
    async fn udp_echo_through_loopback_wireguard_ipv6() {
        let server = spawn_wg_echo_server(None).await;
        let client_keys = x25519_keypair();
        let cfg = server.cfg_for_dual(&client_keys);
        let udp = WgUdp::bind(&cfg).await.expect("udp through the v6 tunnel");
        let target = NetAddr::ip(IpAddr::V6(SERVER_TUNNEL_IP_V6), ECHO_UDP_PORT);
        udp.send(&target, b"udp v6 round trip").await.unwrap();
        let (from, data) = udp.recv().await.expect("v6 echo datagram");
        assert_eq!(data, b"udp v6 round trip");
        assert_eq!(
            from.to_string(),
            format!("[{SERVER_TUNNEL_IP_V6}]:{ECHO_UDP_PORT}"),
            "the v6 source address survives the stack"
        );
        udp.send(&target, b"again v6").await.unwrap();
        let (_, data2) = udp.recv().await.unwrap();
        assert_eq!(data2, b"again v6");
    }

    /// One peer, both families at once: the same tunnel (same handshake,
    /// same transport keys) carries a v4 TCP relay, a v6 TCP relay, v4 UDP
    /// and v6 UDP — source selection per destination family.
    #[tokio::test]
    async fn mixed_v4_and_v6_targets_share_one_tunnel() {
        let server = spawn_wg_echo_server(None).await;
        let client_keys = x25519_keypair();
        let cfg = server.cfg_for_dual(&client_keys);

        // v4 TCP.
        let mut v4 = connect(
            &cfg,
            &NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT),
        )
        .await
        .expect("v4 dial");
        v4.write_all(b"v4 tcp").await.unwrap();
        let mut back = vec![0u8; 6];
        v4.read_exact(&mut back).await.unwrap();
        assert_eq!(back, b"v4 tcp".to_vec());

        // v6 TCP on the same tunnel.
        let mut v6 = connect(
            &cfg,
            &NetAddr::ip(IpAddr::V6(SERVER_TUNNEL_IP_V6), ECHO_TCP_PORT),
        )
        .await
        .expect("v6 dial on the same tunnel");
        v6.write_all(b"v6 tcp").await.unwrap();
        let mut back = vec![0u8; 6];
        v6.read_exact(&mut back).await.unwrap();
        assert_eq!(back, b"v6 tcp".to_vec());

        // Both UDP families through one WgUdp socket.
        let udp = WgUdp::bind(&cfg).await.expect("udp");
        udp.send(
            &NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_UDP_PORT),
            b"u4",
        )
        .await
        .unwrap();
        udp.send(
            &NetAddr::ip(IpAddr::V6(SERVER_TUNNEL_IP_V6), ECHO_UDP_PORT),
            b"u6",
        )
        .await
        .unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2 {
            let (from, data) = tokio::time::timeout(Duration::from_secs(30), udp.recv())
                .await
                .expect("both udp echoes arrive")
                .expect("udp echo");
            seen.insert((from.to_string(), data));
        }
        assert_eq!(
            seen,
            {
                let mut s = std::collections::HashSet::new();
                s.insert((
                    format!("{SERVER_TUNNEL_IP}:{ECHO_UDP_PORT}"),
                    b"u4".to_vec(),
                ));
                s.insert((
                    format!("[{SERVER_TUNNEL_IP_V6}]:{ECHO_UDP_PORT}"),
                    b"u6".to_vec(),
                ));
                s
            },
            "both families echo back with their own source address"
        );

        // The v4 connection still relays after all of the above.
        v4.write_all(b"v4 still up").await.unwrap();
        let mut back = vec![0u8; 11];
        v4.read_exact(&mut back).await.unwrap();
        assert_eq!(back, b"v4 still up");
    }

    #[tokio::test]
    async fn reserved_bytes_travel_on_the_wire() {
        // mihomo's `reserved` encoding, proven end to end: the server must
        // see [1,2,3] in bytes 1..3 of every datagram, and the handshake
        // must still complete because MACs were computed zero-reserved.
        let server = spawn_wg_echo_server(Some([1, 2, 3])).await;
        let client_keys = x25519_keypair();
        let cfg = server.cfg_for(&client_keys);
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);
        let mut stream = connect(&cfg, &target).await.expect("dial with reserved bytes");
        stream.write_all(b"reserved smoke").await.unwrap();
        let mut echoed = vec![0u8; 14];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"reserved smoke");
    }

    #[tokio::test]
    async fn udp_disabled_peer_rejects_udp_bind() {
        let server = spawn_wg_echo_server(None).await;
        let client_keys = x25519_keypair();
        let mut cfg = server.cfg_for(&client_keys);
        cfg.udp = false;
        // The udp flag is checked when the tunnel task handles UdpOpen;
        // pointing at the real server creates the tunnel, then refuses.
        let err = match WgUdp::bind(&cfg).await {
            Ok(_) => panic!("udp must be refused when the peer disables it"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("disabled"));
    }

    // ========================================================================
    // ENDPOINT (server) tests. The engine's own client (the dual-stack
    // netstack above) drives the production endpoint over real loopback
    // UDP; a manual client (raw handshake + session) drives the paths the
    // engine client cannot trigger on demand: roaming, replay rejection,
    // the allowed-ips source filter, ICMP, cookie-under-load, keepalives.
    // ========================================================================

    use crate::inbound::RelayHandler;

    /// An engine relay: TCP bytes echoed, UDP datagrams echoed and recorded
    /// (the shapes the TUN netstack tests use).
    struct EpEchoRelay(std::sync::Mutex<Vec<(SocketAddr, NetAddr, Vec<u8>)>>);

    impl RelayHandler for EpEchoRelay {
        fn handle_tcp(self: Arc<Self>, _meta: TcpMeta, client: BoxProxyStream) {
            tokio::spawn(async move {
                let mut client = client;
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
            source: SocketAddr,
            _inbound: String,
            mut uplink: mpsc::Receiver<(NetAddr, Vec<u8>)>,
            downlink: mpsc::Sender<(NetAddr, Vec<u8>)>,
        ) {
            tokio::spawn(async move {
                while let Some((target, data)) = uplink.recv().await {
                    self.0
                        .lock()
                        .unwrap()
                        .push((source, target.clone(), data.clone()));
                    let _ = downlink.send((target, data)).await;
                }
            });
        }
    }

    const EP_TCP_PORT: u16 = 9021;
    const EP_UDP_PORT: u16 = 9022;

    fn endpoint_cfg(server_statics: &StaticKeys, client_pk: [u8; 32], psk: [u8; 32]) -> WgEndpointCfg {
        WgEndpointCfg {
            tag: "wg-ep".into(),
            private_key: b64(&server_statics.sk),
            listen_port: 0,
            mtu: 0,
            address: Some((SERVER_TUNNEL_IP, 24)),
            inet6_address: Some((SERVER_TUNNEL_IP_V6, 64)),
            udp_timeout: Some(Duration::from_secs(300)),
            peers: vec![WgEndpointPeer {
                public_key: b64(&client_pk),
                pre_shared_key: Some(b64(&psk)),
                allowed_ips: vec![
                    (IpAddr::V4(Ipv4Addr::new(172, 16, 200, 2)), 32),
                    (IpAddr::V6(CLIENT_TUNNEL_IP_V6), 128),
                ],
                persistent_keepalive: None,
            }],
        }
    }

    fn endpoint_client_cfg(
        endpoint: SocketAddr,
        client: &StaticKeys,
        server_pk: &[u8; 32],
        psk: &[u8; 32],
        ipv6: bool,
    ) -> WgOut {
        WgOut {
            server: "127.0.0.1".into(),
            port: endpoint.port(),
            private_key: b64(&client.sk),
            peer_public_key: b64(server_pk),
            pre_shared_key: Some(b64(psk)),
            local_ip: Ipv4Addr::new(172, 16, 200, 2),
            local_ipv6: ipv6.then_some(CLIENT_TUNNEL_IP_V6),
            mtu: 0,
            reserved: [0; 3],
            udp: true,
        }
    }

    /// The endpoint's v4 loopback address (it listens on the wildcard).
    fn v4_ep(addr: SocketAddr) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    }

    /// A manual (non-netstack) client: raw handshake against the endpoint,
    /// using the exact static identity the endpoint has configured (an
    /// unknown key would be answered with silence, by design).
    async fn manual_handshake(
        client: &StaticKeys,
        server_pk: &[u8; 32],
        psk: &[u8; 32],
        endpoint: SocketAddr,
    ) -> (tokio::net::UdpSocket, Session, Vec<u8>, InitiationPending) {
        let statics = StaticKeys::from_secret(client.sk);
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (msg, mut pending) = build_initiation(&statics, server_pk, None, 0xC0DE).unwrap();
        sock.send_to(&msg, endpoint).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut buf))
            .await
            .expect("endpoint answers the initiation")
            .unwrap();
        let resp = parse_wg_msg(&buf[..n]).expect("a well-formed response");
        let done = consume_response(&statics, &mut pending, &resp, psk)
            .expect("endpoint response verifies");
        let sess = Session::from_handshake(done, Instant::now());
        (sock, sess, msg, pending)
    }

    /// Receive the next decryptable inner packet (keepalives skipped);
    /// `None` on timeout or datagrams not for this session.
    async fn recv_transport(
        sock: &tokio::net::UdpSocket,
        sess: &mut Session,
        wait: Duration,
    ) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 65_536];
        loop {
            let Ok(Ok((n, _))) = tokio::time::timeout(wait, sock.recv_from(&mut buf)).await else {
                return None;
            };
            match parse_wg_msg(&buf[..n]) {
                Some(WgMsg::Transport { receiver, counter, data }) => {
                    if receiver != sess.local_index {
                        continue; // stale
                    }
                    let plain = sess.open_transport(counter, &data).ok()?;
                    if plain.is_empty() {
                        continue; // keepalive
                    }
                    let mut p = plain;
                    trim_ip_packet(&mut p);
                    return Some(p);
                }
                _ => continue,
            }
        }
    }

    /// Send one inner packet through a manual session and await the next
    /// decryptable inner packet back.
    async fn manual_roundtrip(
        sock: &tokio::net::UdpSocket,
        sess: &mut Session,
        endpoint: SocketAddr,
        inner: &[u8],
    ) -> Vec<u8> {
        let msg = sess.seal_transport(inner).unwrap();
        sock.send_to(&msg, endpoint).await.unwrap();
        manual_recv_inner(sock, sess).await
    }

    async fn manual_recv_inner(sock: &tokio::net::UdpSocket, sess: &mut Session) -> Vec<u8> {
        recv_transport(sock, sess, Duration::from_secs(10)).await.expect("a relayed reply")
    }

    /// A UDP/IPv4 packet with valid header + UDP checksums (smoltcp verifies
    /// both on input).
    fn udp4_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let (sport, dport) = (src.port(), dst.port());
        let (src, dst) = (match src.ip() {
            IpAddr::V4(v4) => v4,
            _ => panic!("v4 builder"),
        }, match dst.ip() {
            IpAddr::V4(v4) => v4,
            _ => panic!("v4 builder"),
        });
        let total = 20 + 8 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        p[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p[28..28 + payload.len()].copy_from_slice(payload);
        let hc = checksum(&p[..20]);
        p[10..12].copy_from_slice(&hc.to_be_bytes());
        // UDP checksum over the v4 pseudo-header.
        let mut pseudo = Vec::with_capacity(12 + 8 + payload.len());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pseudo.extend_from_slice(&p[20..]);
        let uc = checksum(&pseudo);
        let uc = if uc == 0 { 0xffff } else { uc };
        p[26..28].copy_from_slice(&uc.to_be_bytes());
        p
    }

    fn icmp4_echo_request(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[8] = 64;
        p[9] = 1;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20] = 8; // echo request
        p[24..26].copy_from_slice(&id.to_be_bytes());
        p[26..28].copy_from_slice(&seq.to_be_bytes());
        let hc = checksum(&p[..20]);
        p[10..12].copy_from_slice(&hc.to_be_bytes());
        let ic = checksum(&p[20..]);
        p[22..24].copy_from_slice(&ic.to_be_bytes());
        p
    }

    async fn spawn_test_endpoint(cfg: &WgEndpointCfg) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let relay = EpEchoRelay(std::sync::Mutex::new(Vec::new()));
        spawn_endpoint(cfg, Arc::new(relay)).await.expect("endpoint starts")
    }

    /// TCP relayed through the endpoint into the engine, driven by the
    /// module's own dual-stack client.
    #[tokio::test]
    async fn endpoint_relays_engine_client_tcp() {
        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        let (addr, task) = spawn_test_endpoint(&cfg).await;

        let out = endpoint_client_cfg(v4_ep(addr), &client_keys, &server_statics.pk, &psk, false);
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), EP_TCP_PORT);
        let mut stream = connect(&out, &target)
            .await
            .expect("engine client connects through the endpoint");
        let payload = b"endpoint relay!".repeat(64);
        stream.write_all(&payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload, "echo through the endpoint both ways");
        stream.write_all(b"again").await.unwrap();
        let mut more = vec![0u8; 5];
        stream.read_exact(&mut more).await.unwrap();
        assert_eq!(more, b"again");
        stream.shutdown().await.unwrap();
        task.abort();
    }

    /// REPRO (wave-12): the e2e pairing — engine client tunnel against the
    /// production endpoint, whose relayed connection echoes from a separate
    /// task (like the engine relay) — under a multi-segment burst. This is
    /// the exact shape that stalled scheduling-dependently in wave-11's e2e.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn endpoint_relays_engine_client_tcp_multisegment_burst() {
        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        let (addr, task) = spawn_test_endpoint(&cfg).await;

        let out = endpoint_client_cfg(v4_ep(addr), &client_keys, &server_statics.pk, &psk, false);
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), EP_TCP_PORT);
        let mut stream = connect(&out, &target)
            .await
            .expect("engine client connects through the endpoint");

        // 64 KiB write-all, then the full echo — multi-segment both ways.
        let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        tokio::time::timeout(Duration::from_secs(30), stream.write_all(&payload))
            .await
            .expect("64 KiB write through client+endpoint must not stall")
            .unwrap();
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut echoed))
            .await
            .expect("64 KiB echo through client+endpoint must not stall")
            .unwrap();
        assert_eq!(echoed, payload);

        // And the request/response shape: 8 KiB rounds.
        for round in 0..8u32 {
            let chunk: Vec<u8> = (0..8 * 1024).map(|i| (i as u32 + round) as u8).collect();
            tokio::time::timeout(Duration::from_secs(30), stream.write_all(&chunk))
                .await
                .expect("8 KiB round write must not stall")
                .unwrap();
            let mut back = vec![0u8; chunk.len()];
            tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut back))
                .await
                .expect("8 KiB round echo must not stall")
                .unwrap();
            assert_eq!(back, chunk);
        }
        stream.shutdown().await.unwrap();
        task.abort();
    }

    /// REPRO (wave-12): concurrent dials to one port through the production
    /// endpoint — the engine's real shape (a browser opening several
    /// connections to the same target). The second SYN used to hit the one
    /// listener mid-handshake and drew an RST ("dial failed (state Closed)").
    #[tokio::test]
    async fn endpoint_accepts_concurrent_dials_to_one_port() {
        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        let (addr, task) = spawn_test_endpoint(&cfg).await;

        let out = endpoint_client_cfg(v4_ep(addr), &client_keys, &server_statics.pk, &psk, false);
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), EP_TCP_PORT);
        let mut streams = Vec::new();
        for _ in 0..4 {
            streams.push(
                tokio::time::timeout(Duration::from_secs(30), connect(&out, &target))
                    .await
                    .expect("concurrent dial must not be RST by a mid-handshake listener")
                    .expect("dial through the endpoint"),
            );
        }
        // Every stream echoes multi-segment bursts, interleaved.
        for round in 0..4u32 {
            for (i, stream) in streams.iter_mut().enumerate() {
                let chunk: Vec<u8> =
                    (0..8 * 1024).map(|k| (k as u32 + round + i as u32) as u8).collect();
                stream.write_all(&chunk).await.unwrap();
                let mut back = vec![0u8; chunk.len()];
                stream.read_exact(&mut back).await.unwrap();
                assert_eq!(back, chunk);
            }
        }
        for mut s in streams {
            s.shutdown().await.unwrap();
        }
        task.abort();
    }

    /// REPRO (wave-12): a relay that drops the stream after the first read —
    /// the endpoint aborts the socket (RST) while the client writer is still
    /// pushing a burst far bigger than every buffer. The writer must fail
    /// with BrokenPipe promptly, not hang on a queue nobody drains.
    #[tokio::test]
    async fn reset_mid_burst_fails_the_writer_not_hangs() {
        struct DropAfterFirstRead;
        impl RelayHandler for DropAfterFirstRead {
            fn handle_tcp(self: Arc<Self>, _meta: TcpMeta, mut client: BoxProxyStream) {
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

        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        let relay = Arc::new(DropAfterFirstRead);
        let (addr, task) = spawn_endpoint(&cfg, relay).await.expect("endpoint starts");

        let out = endpoint_client_cfg(v4_ep(addr), &client_keys, &server_statics.pk, &psk, false);
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), EP_TCP_PORT);
        let mut stream = connect(&out, &target)
            .await
            .expect("dial through the endpoint");
        let payload = vec![7u8; 512 * 1024];
        let outcome = tokio::time::timeout(Duration::from_secs(15), stream.write_all(&payload)).await;
        match outcome {
            Err(_elapsed) => panic!("writer hung on a reset connection (stall)"),
            // The write may complete into local queues before the RST lands;
            // then the failure must surface on the next write or the read.
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
                    matches!(e.kind(), std::io::ErrorKind::BrokenPipe),
                    "writer must see BrokenPipe on reset, got {e:?}"
                );
            }
        }
        task.abort();
    }

    /// GUARD (wave-12): the zero-window stall-recovery shape. The reader
    /// drains in 16 KiB chunks with pauses, so the peer repeatedly hits our
    /// closed window; every drain must promptly re-open it — poll_read pings
    /// the stack task the moment queue space frees, instead of idling until
    /// the driver's 1s tick or the peer's next probe. Bound is generous
    /// (healthy: ~2s).
    #[tokio::test]
    async fn zero_window_reopens_promptly_after_drain() {
        let server = spawn_wg_echo_server(None).await;
        let client_keys = x25519_keypair();
        let cfg = server.cfg_for(&client_keys);
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);

        let stream = connect(&cfg, &target).await.expect("dial through the tunnel");
        const TOTAL: usize = 256 * 1024;
        let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();

        let (mut r, mut w) = tokio::io::split(stream);
        let tx_payload = payload.clone();
        let writer = tokio::spawn(async move {
            w.write_all(&tx_payload).await.unwrap();
        });
        let started = std::time::Instant::now();
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
            "window re-opening dragged: {elapsed:?} for 256 KiB — read drain not waking the stack"
        );
    }

    /// UDP relayed through the endpoint into the engine, same client.
    #[tokio::test]
    async fn endpoint_relays_engine_client_udp() {
        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        let (addr, task) = spawn_test_endpoint(&cfg).await;

        let out = endpoint_client_cfg(v4_ep(addr), &client_keys, &server_statics.pk, &psk, false);
        let udp = WgUdp::bind(&out).await.expect("udp through the endpoint");
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), EP_UDP_PORT);
        udp.send(&target, b"ep-udp").await.unwrap();
        let (from, data) = tokio::time::timeout(Duration::from_secs(30), udp.recv())
            .await
            .expect("echo datagram")
            .expect("udp echo");
        assert_eq!(data, b"ep-udp");
        assert_eq!(from.to_string(), format!("{SERVER_TUNNEL_IP}:{EP_UDP_PORT}"));
        udp.send(&target, b"ep-udp-2").await.unwrap();
        let (_, data2) = tokio::time::timeout(Duration::from_secs(30), udp.recv())
            .await
            .expect("second echo")
            .expect("udp echo 2");
        assert_eq!(data2, b"ep-udp-2");
        task.abort();
    }

    /// The v6 side of the same relay (dual-stack client, v6 inner address).
    #[tokio::test]
    async fn endpoint_relays_engine_client_tcp_ipv6() {
        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        let (addr, task) = spawn_test_endpoint(&cfg).await;

        let out = endpoint_client_cfg(v4_ep(addr), &client_keys, &server_statics.pk, &psk, true);
        let target = NetAddr::ip(IpAddr::V6(SERVER_TUNNEL_IP_V6), EP_TCP_PORT);
        let mut stream = connect(&out, &target)
            .await
            .expect("engine client connects over the endpoint's v6 side");
        stream.write_all(b"v6 via endpoint").await.unwrap();
        let mut echoed = vec![0u8; b"v6 via endpoint".len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"v6 via endpoint".to_vec());
        task.abort();
    }

    /// Roaming: transport from a new source port moves the session's
    /// endpoint; the old port goes silent.
    #[tokio::test]
    async fn endpoint_roaming_follows_the_peer_address() {
        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        let (addr, task) = spawn_test_endpoint(&cfg).await;
        let ep = v4_ep(addr);

        let (sock, mut sess, _init, _pending) =
            manual_handshake(&client_keys, &server_statics.pk, &psk, ep).await;
        let inner = udp4_packet(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 200, 2)), 5150),
            SocketAddr::new(IpAddr::V4(SERVER_TUNNEL_IP), EP_UDP_PORT),
            b"roam-probe",
        );
        // First from the handshake socket: proves the session works.
        let reply = manual_roundtrip(&sock, &mut sess, ep, &inner).await;
        assert_eq!(&reply[28..], b"roam-probe");

        // Now from a different source port: the endpoint must follow.
        let sock2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        manual_roundtrip(&sock2, &mut sess, ep, &inner).await;
        // Still answered on the new address for a second exchange.
        manual_roundtrip(&sock2, &mut sess, ep, &inner).await;

        // The old port hears nothing: the session lives on the new address
        // (a *valid new* packet from the old socket would roam it back —
        // that is WireGuard roaming — so only unsolicited traffic is
        // checked here).
        let mut buf = vec![0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(700), sock.recv_from(&mut buf))
                .await
                .is_err(),
            "the endpoint must answer on the new address only"
        );
        task.abort();
    }

    /// A replayed initiation (same bytes) is silently ignored: the TAI64N
    /// replay guard, not a second session.
    #[tokio::test]
    async fn endpoint_replayed_initiation_is_silent() {
        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        let (addr, task) = spawn_test_endpoint(&cfg).await;
        let ep = v4_ep(addr);

        let (sock, _sess, init_msg, _pending) =
            manual_handshake(&client_keys, &server_statics.pk, &psk, ep).await;
        sock.send_to(&init_msg, ep).await.unwrap();
        let mut buf = vec![0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(700), sock.recv_from(&mut buf))
                .await
                .is_err(),
            "a replayed initiation must not be answered"
        );
        task.abort();
    }

    /// A replayed transport datagram (same counter, same ciphertext) is
    /// rejected by the anti-replay window: the echo happens exactly once.
    #[tokio::test]
    async fn endpoint_replayed_transport_counter_is_silent() {
        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        let (addr, task) = spawn_test_endpoint(&cfg).await;
        let ep = v4_ep(addr);

        let (sock, mut sess, _init, _pending) =
            manual_handshake(&client_keys, &server_statics.pk, &psk, ep).await;
        let inner = udp4_packet(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 200, 2)), 5151),
            SocketAddr::new(IpAddr::V4(SERVER_TUNNEL_IP), EP_UDP_PORT),
            b"replay-me",
        );
        let wire = sess.seal_transport(&inner).unwrap();
        sock.send_to(&wire, ep).await.unwrap();
        let reply = manual_recv_inner(&sock, &mut sess).await;
        assert_eq!(&reply[28..], b"replay-me");

        // The replay: byte-for-byte the same datagram. The tag verifies but
        // the counter is spent, so the packet is dropped and no second echo
        // ever leaves the endpoint.
        sock.send_to(&wire, ep).await.unwrap();
        assert!(
            recv_transport(&sock, &mut sess, Duration::from_millis(700))
                .await
                .is_none(),
            "a replayed transport datagram must not be relayed twice"
        );
        task.abort();
    }

    /// Unknown static keys get no response at all (the whitepaper's silence).
    #[tokio::test]
    async fn endpoint_unknown_peer_is_silent() {
        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        let (addr, task) = spawn_test_endpoint(&cfg).await;
        let ep = v4_ep(addr);

        let stranger = x25519_keypair();
        let (msg, _pending) = build_initiation(&stranger, &server_statics.pk, None, 42).unwrap();
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(&msg, ep).await.unwrap();
        let mut buf = vec![0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(700), sock.recv_from(&mut buf))
                .await
                .is_err(),
            "unknown peers must be answered with silence"
        );
        task.abort();
    }

    /// The allowed-ips source filter: a decrypted packet whose source is not
    /// in the peer's list never reaches the engine.
    #[tokio::test]
    async fn endpoint_filters_sources_outside_allowed_ips() {
        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        let (addr, task) = spawn_test_endpoint(&cfg).await;
        let ep = v4_ep(addr);

        let (sock, mut sess, _init, _pending) =
            manual_handshake(&client_keys, &server_statics.pk, &psk, ep).await;

        // Outside the allowed 172.16.200.2/32: no echo.
        let rogue = udp4_packet(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 7)), 9000),
            SocketAddr::new(IpAddr::V4(SERVER_TUNNEL_IP), EP_UDP_PORT),
            b"let me in",
        );
        let msg = sess.seal_transport(&rogue).unwrap();
        sock.send_to(&msg, ep).await.unwrap();
        let mut buf = vec![0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(700), sock.recv_from(&mut buf))
                .await
                .is_err(),
            "a source outside allowed_ips must be dropped"
        );

        // Inside: echoed.
        let ok = udp4_packet(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 200, 2)), 9001),
            SocketAddr::new(IpAddr::V4(SERVER_TUNNEL_IP), EP_UDP_PORT),
            b"allowed",
        );
        let reply = manual_roundtrip(&sock, &mut sess, ep, &ok).await;
        assert_eq!(&reply[28..], b"allowed");
        task.abort();
    }

    /// ICMP echo requests toward the endpoint are answered locally (both
    /// families answered by the stack in the TUN inbound's image).
    #[tokio::test]
    async fn endpoint_answers_icmp_echo() {
        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        let (addr, task) = spawn_test_endpoint(&cfg).await;
        let ep = v4_ep(addr);

        let (sock, mut sess, _init, _pending) =
            manual_handshake(&client_keys, &server_statics.pk, &psk, ep).await;
        let req = icmp4_echo_request(
            Ipv4Addr::new(172, 16, 200, 2),
            SERVER_TUNNEL_IP,
            0xBEEF,
            7,
        );
        let reply = manual_roundtrip(&sock, &mut sess, ep, &req).await;
        assert_eq!(reply[20], 0, "echo reply type");
        assert_eq!(&reply[24..26], &0xBEEFu16.to_be_bytes(), "id preserved");
        assert_eq!(&reply[26..28], &7u16.to_be_bytes(), "seq preserved");
        // Swapped addresses.
        assert_eq!(&reply[12..16], &SERVER_TUNNEL_IP.octets());
        assert_eq!(&reply[16..20], &[172, 16, 200, 2]);
        // The recomputed checksum verifies (sum over the ICMP message is 0).
        assert_eq!(checksum(&reply[20..]), 0);
        task.abort();
    }

    /// Past 64 initiations in a second the endpoint answers with cookies
    /// (wireguard-go's under-load behaviour), and the client-side cookie
    /// consumer can open them.
    #[tokio::test]
    async fn endpoint_answers_with_cookies_under_load() {
        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        let (addr, task) = spawn_test_endpoint(&cfg).await;
        let ep = v4_ep(addr);

        let stranger = x25519_keypair();
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // 65 unknown-peer initiations all count toward the load window and
        // are silently discarded; from 65 on the reply is a cookie.
        let (msg, _pending) = build_initiation(&stranger, &server_statics.pk, None, 1).unwrap();
        for _ in 0..EP_COOKIE_LOAD {
            sock.send_to(&msg, ep).await.unwrap();
            tokio::task::yield_now().await;
        }
        let (msg2, pending) = build_initiation(&stranger, &server_statics.pk, None, 2).unwrap();
        sock.send_to(&msg2, ep).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut buf))
            .await
            .expect("a cookie reply arrives once under load")
            .unwrap();
        let parsed = parse_wg_msg(&buf[..n]).expect("parses");
        match parsed {
            WgMsg::Cookie { receiver, .. } => {
                assert_eq!(receiver, 2, "receiver is our sender index");
            }
            other => panic!("expected a cookie reply, got {other:?}"),
        }
        // The production client-side consumer opens it with the pending
        // initiation's MAC1 as AAD.
        let cookie = consume_cookie_reply(&server_statics.pk, &pending, &parsed)
            .expect("cookie decrypts");
        assert_ne!(cookie, [0u8; 16]);
        task.abort();
    }

    /// Persistent keepalive: an empty transport message every configured
    /// interval while the session lives.
    #[tokio::test]
    async fn endpoint_sends_persistent_keepalive() {
        let server_statics = x25519_keypair();
        let client_keys = x25519_keypair();
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let mut cfg = endpoint_cfg(&server_statics, client_keys.pk, psk);
        cfg.peers[0].persistent_keepalive = Some(1);
        let (addr, task) = spawn_test_endpoint(&cfg).await;
        let ep = v4_ep(addr);

        let (sock, mut sess, _init, _pending) =
            manual_handshake(&client_keys, &server_statics.pk, &psk, ep).await;
        let mut buf = vec![0u8; 2048];
        // The next datagram must be an empty transport message.
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("the keepalive fires within the interval")
            .unwrap();
        match parse_wg_msg(&buf[..n]).unwrap() {
            WgMsg::Transport { receiver, counter, data } => {
                assert_eq!(receiver, sess.local_index);
                let plain = sess.open_transport(counter, &data).unwrap();
                assert!(plain.is_empty(), "keepalive carries no payload");
            }
            other => panic!("expected a transport keepalive, got {other:?}"),
        }
        task.abort();
    }

    // -- pure endpoint pieces --------------------------------------------------

    #[test]
    fn endpoint_prefix_routing_picks_the_longest_match() {
        let peer = |allowed: Vec<(IpAddr, u8)>| EpPeer {
            static_pk: [1; 32],
            psk: [0; 32],
            allowed,
            persistent_keepalive: None,
            last_timestamp: None,
            endpoint: None,
            session: None,
            next_persistent: None,
        };
        let peers = vec![
            peer(vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)]),
            peer(vec![(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16)]),
        ];
        // Longest prefix wins.
        let (i, p) = route_peer(&peers, &IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))).unwrap();
        assert_eq!((i, p), (1, 16));
        let (i, p) = route_peer(&peers, &IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9))).unwrap();
        assert_eq!((i, p), (0, 8));
        // No match -> None; families never cross.
        assert!(route_peer(&peers, &IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).is_none());
        assert!(route_peer(&peers, &IpAddr::V6(Ipv6Addr::LOCALHOST)).is_none());

        let v6peers = vec![peer(vec![(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)), 64)])];
        assert!(
            route_peer(&v6peers, &IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 1, 2, 3, 4))).is_some()
        );
        assert!(route_peer(&v6peers, &IpAddr::V6(Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 0))).is_none());
        // Edge prefixes.
        assert!(prefix_contains(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0, &IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!prefix_contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 33, &IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn endpoint_classifier_reads_both_families() {
        let tcp_syn = {
            let mut p = vec![0x45u8, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0];
            p.extend_from_slice(&[172, 16, 200, 2]);
            p.extend_from_slice(&SERVER_TUNNEL_IP.octets());
            p.extend_from_slice(&5150u16.to_be_bytes());
            p.extend_from_slice(&9021u16.to_be_bytes());
            p.push(0); p.push(0); p.push(0); p.push(0); // seq
            p.push(0); p.push(0); p.push(0); p.push(0); // ack
            p.push(0x50); p.push(0x02); // data offset + SYN
            p.extend_from_slice(&[0x10, 0x00, 0, 0, 0, 0]); // window, checksum, urgent
            p
        };
        match ep_classify(&tcp_syn) {
            EpIn::Tcp { src, dst, syn } => {
                assert_eq!(src.port(), 5150);
                assert_eq!(dst.port(), 9021);
                assert!(syn);
            }
            other => panic!("tcp: {other:?}"),
        }
        let udp = udp4_packet(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 200, 2)), 5150),
            SocketAddr::new(IpAddr::V4(SERVER_TUNNEL_IP), EP_UDP_PORT),
            b"xyz",
        );
        match ep_classify(&udp) {
            EpIn::Udp { payload, .. } => assert_eq!(&udp[payload.0..payload.1], b"xyz"),
            other => panic!("udp: {other:?}"),
        }
        let icmp = icmp4_echo_request(Ipv4Addr::new(172, 16, 200, 2), SERVER_TUNNEL_IP, 1, 1);
        assert!(matches!(ep_classify(&icmp), EpIn::IcmpEchoRequest { v6: false, .. }));
        // v6 UDP.
        let mut v6 = vec![0x60u8, 0, 0, 0, 0, 11, 17, 64];
        v6.extend_from_slice(&CLIENT_TUNNEL_IP_V6.octets());
        v6.extend_from_slice(&SERVER_TUNNEL_IP_V6.octets());
        v6.extend_from_slice(&5152u16.to_be_bytes());
        v6.extend_from_slice(&EP_UDP_PORT.to_be_bytes());
        v6.extend_from_slice(&11u16.to_be_bytes());
        v6.extend_from_slice(&[0, 0]);
        v6.extend_from_slice(b"abc");
        match ep_classify(&v6) {
            EpIn::Udp { src, dst, payload } => {
                assert_eq!(src.port(), 5152);
                assert_eq!(dst.port(), EP_UDP_PORT);
                assert_eq!(&v6[payload.0..payload.1], b"abc");
            }
            other => panic!("v6 udp: {other:?}"),
        }
        // Garbage and non-TCP/UDP/ICMP skip.
        assert_eq!(ep_classify(&[]), EpIn::Skip);
        assert_eq!(ep_classify(&[0x45, 0, 0, 20]), EpIn::Skip);
        assert_eq!(ep_classify(&[0x71, 0, 0]), EpIn::Skip);
    }

    #[test]
    fn endpoint_icmp_replies_carry_valid_checksums() {
        let req = icmp4_echo_request(Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8), 9, 10);
        assert_eq!(checksum(&req[20..]), 0, "the builder's checksum verifies");
        let reply = ep_icmpv4_echo_reply(&req).unwrap();
        assert_eq!(checksum(&reply[20..]), 0);
        assert_eq!(reply[20], 0);

        // v6 echo reply, checksum over the pseudo-header.
        let mut req6 = vec![0x60u8, 0, 0, 0, 0, 12, 58, 64];
        req6.extend_from_slice(&CLIENT_TUNNEL_IP_V6.octets());
        req6.extend_from_slice(&SERVER_TUNNEL_IP_V6.octets());
        req6.extend_from_slice(&[129 - 1, 0, 0, 0]); // type 128
        req6.extend_from_slice(&0x1234u16.to_be_bytes());
        req6.extend_from_slice(&5u16.to_be_bytes());
        req6.extend_from_slice(&[0xAA; 4]);
        let rep6 = ep_icmpv6_echo_reply(&req6).unwrap();
        assert_eq!(rep6[40], 129);
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&rep6[8..24]);
        pseudo.extend_from_slice(&rep6[24..40]);
        pseudo.extend_from_slice(&((rep6.len() - 40) as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 58]);
        pseudo.extend_from_slice(&rep6[40..]);
        assert_eq!(checksum(&pseudo), 0, "v6 reply checksum verifies");
    }

    #[test]
    fn endpoint_cookie_roundtrip_with_the_client_consumer() {
        let server = x25519_keypair();
        let client = x25519_keypair();
        let (msg, pending) = build_initiation(&client, &server.pk, None, 5).unwrap();
        let mac1: [u8; 16] = msg[116..132].try_into().unwrap();
        let full = blake2s256(b"secret");
        let secret: [u8; 16] = full[..16].try_into().unwrap();
        let cookie = make_cookie(&secret, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234));
        let reply = build_cookie_reply(&server.pk, 5, &mac1, cookie).unwrap();
        assert_eq!(reply.len(), MSG_COOKIE_LEN);
        let learned =
            consume_cookie_reply(&server.pk, &pending, &parse_wg_msg(&reply).unwrap()).unwrap();
        assert_eq!(learned, cookie);
    }

    #[test]
    fn endpoint_load_counter_resets_each_second() {
        let mut load = HandshakeLoad::default();
        let t0 = Instant::now();
        for i in 1..=EP_COOKIE_LOAD {
            load.bump(t0);
            assert_eq!(load.under_load(), i > EP_COOKIE_LOAD);
        }
        load.bump(t0 + Duration::from_secs(2));
        assert!(!load.under_load(), "a new window starts at 1");
    }

    #[test]
    fn endpoint_config_validates_peers() {
        let base = || WgEndpointCfg {
            tag: "t".into(),
            private_key: b64(&[7u8; 32]),
            listen_port: 0,
            mtu: 0,
            address: None,
            inet6_address: None,
            udp_timeout: None,
            peers: vec![WgEndpointPeer {
                public_key: b64(&[9u8; 32]),
                pre_shared_key: None,
                allowed_ips: vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 32)],
                persistent_keepalive: None,
            }],
        };
        assert!(Endpoint::new(&base()).is_ok());
        let err = match Endpoint::new(&WgEndpointCfg { peers: vec![], ..base() }) { Err(e) => e.to_string(), Ok(_) => panic!("config must be rejected") };
        assert!(err.contains("at least one peer"), "{err}");
        let err = match Endpoint::new(&WgEndpointCfg {
            peers: vec![WgEndpointPeer {
                allowed_ips: vec![],
                ..base().peers.pop().unwrap()
            }],
            ..base()
        }) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("config must be rejected"),
        };
        assert!(err.contains("no allowed_ips"), "{err}");
        let err = match Endpoint::new(&WgEndpointCfg {
            peers: vec![WgEndpointPeer {
                allowed_ips: vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 33)],
                ..base().peers.pop().unwrap()
            }],
            ..base()
        }) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("config must be rejected"),
        };
        assert!(err.contains("not a valid prefix"), "{err}");
        // Bad base64 keys are config errors.
        let err = match Endpoint::new(&WgEndpointCfg {
            private_key: "!!".into(),
            ..base()
        }) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("config must be rejected"),
        };
        assert!(err.contains("base64"), "{err}");
    }

    #[test]
    fn checksum_known_vector() {
        // RFC 1071's worked example: 0x0001f203f4f5f6f7 over the first 12
        // bytes with the rest zero is 0x220d (little-endian pairs).
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let sum = checksum(&data);
        // Independent computation: big-endian words, folded manually.
        let mut acc: u32 = 0x0001 + 0xf203 + 0xf4f5 + 0xf6f7;
        assert_eq!(sum, 0x220D, "the RFC 1071 worked example");
        while acc >> 16 != 0 {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        assert_eq!(sum, !(acc as u16));
    }
}
