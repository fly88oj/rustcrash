//! WireGuard outbound: the Noise_IKpsk2 (Construction v1) handshake, the
//! ChaCha20Poly1305 transport with 64-bit counters and an anti-replay
//! window, and a client-side smoltcp netstack that terminates TCP/UDP
//! toward targets inside the tunnel.
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
//! * **Client only**: a single fixed peer (mihomo `type: wireguard` /
//!   sing-box `type: wireguard` outbound), no endpoint roaming, no cookie
//!   *generation* (that is a server-side under-load mechanism) — cookie
//!   *consumption* is implemented so an under-load server can still be
//!   reached.
//! * **Netstack**: one task owns the smoltcp `Interface`, the `SocketSet`
//!   and the UDP socket to the peer, mirroring the inbound TUN netstack's
//!   single-owner design. TCP dials become [`WgStream`] (an
//!   `AsyncRead + AsyncWrite` bridge over two bounded queues plus wakers),
//!   UDP dials become [`WgUdp`].
//! * **IPv4 only for now**: the smoltcp feature set in this crate is
//!   `proto-ipv4` (same as the TUN inbound), so the userspace stack routes
//!   IPv4 targets; `local_ipv6` is carried for the integrator and the
//!   handshake crypto is address-agnostic.
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
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
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
    /// Our IPv6 address inside the tunnel, if assigned. Carried for
    /// completeness; the userspace stack is built IPv4-only (see module
    /// docs).
    pub local_ipv6: Option<std::net::Ipv6Addr>,
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
        remote: SocketAddrV4,
        reply: oneshot::Sender<Result<Arc<StreamShared>>>,
    },
    UdpOpen {
        reply: oneshot::Sender<Result<(u32, UdpDownlink)>>,
    },
    UdpSend {
        id: u32,
        dst: SocketAddrV4,
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
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(cfg.local_ip), 32));
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(cfg.local_ip)
            .map_err(|_| Error::network("wg: route table full"))?;
        let _ = cfg.local_ipv6; // carried for the integrator; stack is IPv4 (see module docs)

        Ok(Stack {
            iface,
            sockets: SocketSet::new(Vec::new()),
            shim,
            statics,
            peer_pk,
            psk,
            local_ip: cfg.local_ip,
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
                    addr: Some(IpAddress::Ipv4(self.local_ip)),
                    port,
                };
                let cx = self.iface.context();
                let res = sock.connect(
                    cx,
                    IpEndpoint::new(IpAddress::Ipv4(*remote.ip()), remote.port()),
                    local,
                );
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
                let sock = self.sockets.get_mut::<udp::Socket>(handle);
                let mut meta = udp::UdpMetadata::from(IpEndpoint::new(
                    IpAddress::Ipv4(*dst.ip()),
                    dst.port(),
                ));
                meta.local_address = Some(IpAddress::Ipv4(self.local_ip));
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
                let IpAddress::Ipv4(src) = meta.endpoint.addr else {
                    continue;
                };
                let from = NetAddr::ip(IpAddr::V4(src), meta.endpoint.port);
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

fn target_v4(target: &NetAddr, what: &str) -> Result<SocketAddrV4> {
    match &target.host {
        crate::addr::Host::Ip(IpAddr::V4(ip)) => Ok(SocketAddrV4::new(*ip, target.port)),
        crate::addr::Host::Ip(IpAddr::V6(_)) => Err(Error::network(format!(
            "wg: {what} to an IPv6 target: the userspace netstack is built IPv4-only"
        ))),
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
    let remote = target_v4(target, "connect")?;
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
            down: tokio::sync::Mutex::new(down),
        })
    }

    /// Send one datagram to `target` (must be a resolved IPv4 address).
    pub async fn send(&self, target: &NetAddr, data: &[u8]) -> Result<()> {
        let dst = target_v4(target, "send")?;
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
    async fn connect_rejects_domain_and_ipv6_targets() {
        let cfg = dummy_cfg("127.0.0.1", 1);
        let err = match connect(&cfg, &NetAddr::domain("example.com", 443).unwrap()).await {
            Ok(_) => panic!("domain targets must be refused"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("resolve before dialing"));
        let err = match connect(
            &cfg,
            &NetAddr::ip(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 443),
        )
        .await
        {
            Ok(_) => panic!("ipv6 targets must be refused"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("IPv4-only"));
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
    // generated at runtime; nothing leaves loopback.
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

        /// Consume a handshake initiation exactly as a WireGuard responder
        /// does, and produce the response plus the server-side session
        /// keys and the decrypted TAI64N timestamp (for the replay guard).
        /// Returns Err for any unauthenticated/malformed initiation (the
        /// caller then stays silent, per the whitepaper).
        pub(crate) fn consume_initiation_and_respond(
            server_static: &StaticKeys,
            msg: &WgMsg,
            psk: &[u8; 32],
            server_index: u32,
        ) -> Result<(Vec<u8>, ServerKeys, [u8; 12])> {
            let WgMsg::Initiation {
                sender,
                ephemeral,
                enc_static,
                enc_timestamp,
                mac1,
                mac2,
            } = msg
            else {
                return Err(Error::protocol("server: not an initiation"));
            };
            // MAC1 first: keyed by the server's OWN static public key, and
            // the only unauthenticated work allowed before this point is
            // the hash. Rebuild the covered bytes (type..encrypted_timestamp).
            let mut covered = Vec::with_capacity(116);
            covered.extend_from_slice(&1u32.to_le_bytes());
            covered.extend_from_slice(&sender.to_le_bytes());
            covered.extend_from_slice(ephemeral);
            covered.extend_from_slice(enc_static);
            covered.extend_from_slice(enc_timestamp);
            if blake2s_mac(&mac1_key(&server_static.pk), &covered) != *mac1 {
                return Err(Error::crypto("server: initiation MAC1 mismatch"));
            }
            let _ = mac2; // not under load in tests; MAC2 stays zeros

            // Mirror the initiator's derivation.
            let mut ck = blake2s256(CONSTRUCTION);
            let ident_hash = hash2(&ck, IDENTIFIER);
            let mut h = hash2(&ident_hash, &server_static.pk);
            h = hash2(&h, ephemeral);
            ck = kdf1(&ck, ephemeral);
            let es = x25519_dh(&server_static.sk, ephemeral)?;
            let (ck, key_es) = kdf2(&ck, &es);
            let client_static: [u8; 32] = aead_open(&key_es, 0, enc_static, &h)?
                .try_into()
                .map_err(|_| Error::protocol("server: static has wrong length"))?;
            h = hash2(&h, enc_static);
            let ss = x25519_dh(&server_static.sk, &client_static)?;
            let (mut ck, key_ss) = kdf2(&ck, &ss);
            let timestamp = aead_open(&key_ss, 0, enc_timestamp, &h)?;
            h = hash2(&h, enc_timestamp);
            if timestamp.len() != 12 {
                return Err(Error::protocol("server: timestamp has wrong length"));
            }
            let timestamp: [u8; 12] = timestamp.try_into().unwrap();

            // Response message.
            let e = x25519_keypair();
            h = hash2(&h, &e.pk);
            ck = kdf1(&ck, &e.pk);
            let ee = x25519_dh(&e.sk, ephemeral)?;
            ck = kdf1(&ck, &ee);
            let se = x25519_dh(&e.sk, &client_static)?;
            ck = kdf1(&ck, &se);
            let (ck, temp2, key) = kdf3(&ck, psk);
            h = hash2(&h, &temp2);
            let enc_nothing = aead_seal(&key, 0, &[], &h)?;
            // Transcript-complete step; the transport keys derive from the
            // chaining key alone (see the client's matching note).
            let _ = hash2(&h, &enc_nothing);

            let mut resp = Vec::with_capacity(MSG_RESPONSE_LEN);
            resp.extend_from_slice(&2u32.to_le_bytes());
            resp.extend_from_slice(&server_index.to_le_bytes());
            resp.extend_from_slice(&sender.to_le_bytes());
            resp.extend_from_slice(&e.pk);
            resp.extend_from_slice(&enc_nothing);
            // MAC1 keyed by the initiator's (now known) static.
            let rmac1 = blake2s_mac(&mac1_key(&client_static), &resp);
            resp.extend_from_slice(&rmac1);
            resp.extend_from_slice(&[0u8; 16]); // MAC2: not under load
            debug_assert_eq!(resp.len(), MSG_RESPONSE_LEN);

            let (k_client_send, k_client_recv) = derive_transport_keys(&ck);
            Ok((
                resp,
                (server_index, *sender, k_client_send, k_client_recv),
                timestamp,
            ))
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
            WgOut {
                server: self.endpoint.ip().to_string(),
                port: self.endpoint.port(),
                private_key: b64(&client.sk),
                peer_public_key: b64(&self.statics.pk),
                pre_shared_key: Some(b64(&self.psk)),
                local_ip: Ipv4Addr::new(172, 16, 200, 2),
                local_ipv6: None,
                mtu: 0,
                reserved: self.expected_reserved.unwrap_or([0; 3]),
                udp: true,
            }
        }
    }

    /// The server's own smoltcp stack: address 172.16.200.1/24 with a TCP
    /// echo listener and a UDP echo socket.
    struct ServerStack {
        iface: Interface,
        sockets: SocketSet<'static>,
        shim: Shim,
        listener: SocketHandle,
        conn: Option<SocketHandle>,
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
            });
            iface
                .routes_mut()
                .add_default_ipv4_route(SERVER_TUNNEL_IP)
                .unwrap();
            iface.set_any_ip(true);

            let mut sockets = SocketSet::new(Vec::new());
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
            let listener = sockets.add(tcp_sock);

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
                conn: None,
                udp_sock,
                start: Instant::now(),
                pump: vec![0u8; 32 * 1024],
            }
        }

        fn now(&self) -> SmolInstant {
            SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
        }

        /// One server pass; returns egress IP packets to encrypt.
        fn step(&mut self) -> Vec<Vec<u8>> {
            let now = self.now();
            self.iface.poll(now, &mut self.shim, &mut self.sockets);

            // Promote an accepted connection to the echo socket.
            if self.conn.is_none() {
                let l = self.sockets.get::<tcp::Socket>(self.listener);
                if l.state() == tcp::State::Established {
                    // smoltcp listeners do not fork: the listener socket
                    // itself becomes the connection.
                    self.conn = Some(self.listener);
                }
            }

            // TCP echo: whatever arrived goes straight back.
            if let Some(handle) = self.conn {
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
            }

            // UDP echo: reply from the same endpoint.
            {
                let sock = self.sockets.get_mut::<udp::Socket>(self.udp_sock);
                while sock.can_recv() {
                    let (n, meta) = match sock.recv_slice(&mut self.pump) {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    let mut reply_meta = meta;
                    reply_meta.local_address = Some(IpAddress::Ipv4(SERVER_TUNNEL_IP));
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
}
