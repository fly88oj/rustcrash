//! `derp`: the Designated Encrypted Relay for Packets client.
//!
//! Port of `tailscale.com/derp` (derp.go = framing, derp_client.go =
//! client) and the `derp/derphttp` HTTP carrier (derphttp_client.go);
//! cached at `/tmp/wave10-upstream/derp_*.go`, upstream `main` as of
//! 2026-09.
//!
//! DERP is NOT protobuf: it is a 5-byte-framed binary protocol
//! (1 frame-type byte + big-endian u32 length, derp.go:54-53+209-216)
//! whose only structured payloads — `ClientInfo` and `ServerInfo` —
//! are JSON (derp.go:302-309, derp_client.go:194-219) sealed in a NaCl
//! `crypto_box` (curve25519xsalsa20poly1305; `key.NodePrivate.SealTo`,
//! types/key/node.go:130-143). The HTTP carrier is a
//! `GET /derp` + `Upgrade: DERP` → `101` dance
//! (derphttp_client.go:509-571).
//!
//! The NaCl box primitives (HSalsa20, Salsa20, Poly1305) are
//! hand-rolled here — the tree has no sodium/xsalsa20 dependency and
//! the musl-static rule forbids adding one — and proven against the
//! C-NaCl cross-checked `TestBox` vector from
//! `golang.org/x/crypto/nacl/box/box_test.go`.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;
use crate::transport::{tls_connect, TlsSettings};

// ===========================================================================
// NaCl box: curve25519xsalsa20poly1305 (golang.org/x/crypto/nacl/box)
// ===========================================================================

/// Salsa20 "expand 32-byte k" constants (djb Salsa20 spec).
const SALSA_SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// One Salsa20 doubleround on 16 words.
fn salsa20_rounds(x: &mut [u32; 16]) {
    fn qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
        x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
        x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
        x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
    }
    for _ in 0..10 {
        // column round: (0,4,8,12) (5,9,13,1) (10,14,2,6) (15,3,7,11)
        qr(x, 0, 4, 8, 12);
        qr(x, 5, 9, 13, 1);
        qr(x, 10, 14, 2, 6);
        qr(x, 15, 3, 7, 11);
        // row round: (0,1,2,3) (5,6,7,4) (10,11,8,9) (15,12,13,14)
        qr(x, 0, 1, 2, 3);
        qr(x, 5, 6, 7, 4);
        qr(x, 10, 11, 8, 9);
        qr(x, 15, 12, 13, 14);
    }
}

/// The Salsa20 core (djb `salsa20_wordtobyte`, libsodium
/// `crypto_core_salsa20`): 64 keystream bytes for `key` (8 words),
/// 8-byte nonce (2 words) and 8-byte block counter. State layout
/// (core_salsa_ref.c): `[σ0, k0..k3, σ1, n0, n1, b0, b1, σ2, k4..k7,
/// σ3]` — note σ2 sits at index 10, between the counter and the
/// second key half.
fn salsa20_block(key: &[u32; 8], nonce: &[u32; 2], counter: u64, out: &mut [u8; 64]) {
    let mut x = [
        SALSA_SIGMA[0],
        key[0],
        key[1],
        key[2],
        key[3],
        SALSA_SIGMA[1],
        nonce[0],
        nonce[1],
        counter as u32,
        (counter >> 32) as u32,
        SALSA_SIGMA[2],
        key[4],
        key[5],
        key[6],
        key[7],
        SALSA_SIGMA[3],
    ];
    let input = x;
    salsa20_rounds(&mut x);
    for i in 0..16 {
        let w = x[i].wrapping_add(input[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
}

/// HSalsa20 (djb spec §"Hashing with Salsa20"): the 20-round state
/// WITHOUT the feed-forward add, output words 0,5,10,15,6,7,8,9 —
/// used both by crypto_box_beforenm (with a zero nonce) and by the
/// XSalsa20 subkey derivation (with nonce[0..16]).
fn hsalsa20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let mut x = [0u32; 16];
    let le = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    x[0] = SALSA_SIGMA[0];
    x[1] = le(&key[0..4]);
    x[2] = le(&key[4..8]);
    x[3] = le(&key[8..12]);
    x[4] = le(&key[12..16]);
    x[5] = SALSA_SIGMA[1];
    x[6] = le(&nonce16[0..4]);
    x[7] = le(&nonce16[4..8]);
    x[8] = le(&nonce16[8..12]);
    x[9] = le(&nonce16[12..16]);
    x[10] = SALSA_SIGMA[2];
    x[11] = le(&key[16..20]);
    x[12] = le(&key[20..24]);
    x[13] = le(&key[24..28]);
    x[14] = le(&key[28..32]);
    x[15] = SALSA_SIGMA[3];
    salsa20_rounds(&mut x);
    let mut out = [0u8; 32];
    for (i, &w) in [x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9]].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Poly1305 (RFC 8439 §2.5) — the donna 32-bit-limb evaluation.
pub(crate) fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let le = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    // The r clamp (RFC 8439 §2.5): the 128-bit mask
    // 0x0ffffffc_0ffffffc_0ffffffc_0fffffff — the "fc" words are the
    // high words (w1..w3), the all-f low word is w0 (equivalently:
    // clear the top nibble of bytes 3/7/11/15 and the low 2 bits of
    // bytes 4/8/12). Limbs are then the exact 26-bit slices of the
    // clamped value.
    let mut rbytes = [0u8; 16];
    rbytes.copy_from_slice(&key[..16]);
    for w in 0..4 {
        let v = le(&rbytes[w * 4..w * 4 + 4]) & if w == 0 { 0x0fff_ffff } else { 0x0fff_fffc };
        rbytes[w * 4..w * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    let r_full = u128::from_le_bytes(rbytes);
    let r: [u32; 5] = [
        (r_full & 0x03ff_ffff) as u32,
        ((r_full >> 26) & 0x03ff_ffff) as u32,
        ((r_full >> 52) & 0x03ff_ffff) as u32,
        ((r_full >> 78) & 0x03ff_ffff) as u32,
        ((r_full >> 104) & 0x03ff_ffff) as u32,
    ];
    let pad = [le(&key[16..20]), le(&key[20..24]), le(&key[24..28]), le(&key[28..32])];
    let mut h = [0u32; 5];

    let mut blocks = |m: &[u8], hibit: u32| {
        let s1 = r[1].wrapping_mul(5);
        let s2 = r[2].wrapping_mul(5);
        let s3 = r[3].wrapping_mul(5);
        let s4 = r[4].wrapping_mul(5);
        for block in m.as_chunks::<16>().0 {
            let t0 = le(&block[0..4]);
            let t1 = le(&block[4..8]);
            let t2 = le(&block[8..12]);
            let t3 = le(&block[12..16]);
            // h += m (+ 2^128 for full blocks)
            h[0] += t0 & 0x03ff_ffff;
            h[1] += ((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff;
            h[2] += ((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff;
            h[3] += ((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff;
            h[4] += (t3 >> 8) | hibit;

            // h *= r, then fold carries (donna-32)
            let d0 = u64::from(h[0]) * u64::from(r[0])
                + u64::from(h[1]) * u64::from(s4)
                + u64::from(h[2]) * u64::from(s3)
                + u64::from(h[3]) * u64::from(s2)
                + u64::from(h[4]) * u64::from(s1);
            let mut d1 = u64::from(h[0]) * u64::from(r[1])
                + u64::from(h[1]) * u64::from(r[0])
                + u64::from(h[2]) * u64::from(s4)
                + u64::from(h[3]) * u64::from(s3)
                + u64::from(h[4]) * u64::from(s2);
            let mut d2 = u64::from(h[0]) * u64::from(r[2])
                + u64::from(h[1]) * u64::from(r[1])
                + u64::from(h[2]) * u64::from(r[0])
                + u64::from(h[3]) * u64::from(s4)
                + u64::from(h[4]) * u64::from(s3);
            let mut d3 = u64::from(h[0]) * u64::from(r[3])
                + u64::from(h[1]) * u64::from(r[2])
                + u64::from(h[2]) * u64::from(r[1])
                + u64::from(h[3]) * u64::from(r[0])
                + u64::from(h[4]) * u64::from(s4);
            let mut d4 = u64::from(h[0]) * u64::from(r[4])
                + u64::from(h[1]) * u64::from(r[3])
                + u64::from(h[2]) * u64::from(r[2])
                + u64::from(h[3]) * u64::from(r[1])
                + u64::from(h[4]) * u64::from(r[0]);

            let mut c = (d0 >> 26) as u32;
            h[0] = d0 as u32 & 0x03ff_ffff;
            d1 += u64::from(c);
            c = (d1 >> 26) as u32;
            h[1] = d1 as u32 & 0x03ff_ffff;
            d2 += u64::from(c);
            c = (d2 >> 26) as u32;
            h[2] = d2 as u32 & 0x03ff_ffff;
            d3 += u64::from(c);
            c = (d3 >> 26) as u32;
            h[3] = d3 as u32 & 0x03ff_ffff;
            d4 += u64::from(c);
            c = (d4 >> 26) as u32;
            h[4] = d4 as u32 & 0x03ff_ffff;
            // The 2^130 carry folds back as 5 (2^130 ≡ 5 mod p).
            h[0] += c.wrapping_mul(5);
            c = h[0] >> 26;
            h[0] &= 0x03ff_ffff;
            h[1] += c;
        }
    };

    let full = msg.len() - (msg.len() % 16);
    if full > 0 {
        blocks(&msg[..full], 1 << 24);
    }
    let rem = msg.len() % 16;
    if rem > 0 {
        let mut buf = [0u8; 16];
        buf[..rem].copy_from_slice(&msg[full..]);
        buf[rem] = 1;
        blocks(&buf, 0);
    }

    // finalize: fully carry h, compute h + -p, select, add pad
    let mut c = h[1] >> 26;
    h[1] &= 0x03ff_ffff;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 0x03ff_ffff;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 0x03ff_ffff;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= 0x03ff_ffff;
    h[0] += c;
    c = h[0] >> 26;
    h[0] &= 0x03ff_ffff;
    h[1] += c;

    let g0 = h[0].wrapping_add(5);
    let c = g0 >> 26;
    let g0 = g0 & 0x03ff_ffff;
    let g1 = h[1].wrapping_add(c);
    let c = g1 >> 26;
    let g1 = g1 & 0x03ff_ffff;
    let g2 = h[2].wrapping_add(c);
    let c = g2 >> 26;
    let g2 = g2 & 0x03ff_ffff;
    let g3 = h[3].wrapping_add(c);
    let c = g3 >> 26;
    let g3 = g3 & 0x03ff_ffff;
    let g4 = h[4].wrapping_add(c).wrapping_sub(1 << 26);

    // if g4 borrowed, keep h; else use g (h - 2^130+5)
    let mask = (g4 >> 31).wrapping_sub(1);
    let hh = [
        (h[0] & !mask) | (g0 & mask),
        (h[1] & !mask) | (g1 & mask),
        (h[2] & !mask) | (g2 & mask),
        (h[3] & !mask) | (g3 & mask),
        (h[4] & !mask) | (g4 & mask),
    ];

    // h = h % 2^128: repack the 26-bit limbs into four 32-bit words
    // (donna finish), then add the pad with carry.
    let w0 = (u64::from(hh[0]) | (u64::from(hh[1]) << 26)) as u32 as u64;
    let w1 = ((u64::from(hh[1] >> 6)) | (u64::from(hh[2]) << 20)) as u32 as u64;
    let w2 = ((u64::from(hh[2] >> 12)) | (u64::from(hh[3]) << 14)) as u32 as u64;
    let w3 = ((u64::from(hh[3] >> 18)) | (u64::from(hh[4]) << 8)) as u32 as u64;

    let mut out = [0u8; 16];
    let mut f = w0 + u64::from(pad[0]);
    out[0..4].copy_from_slice(&(f as u32).to_le_bytes());
    f = w1 + u64::from(pad[1]) + (f >> 32);
    out[4..8].copy_from_slice(&(f as u32).to_le_bytes());
    f = w2 + u64::from(pad[2]) + (f >> 32);
    out[8..12].copy_from_slice(&(f as u32).to_le_bytes());
    f = w3 + u64::from(pad[3]) + (f >> 32);
    out[12..16].copy_from_slice(&(f as u32).to_le_bytes());
    out
}

/// `crypto_secretbox` core over an XSalsa20 keystream: subkey =
/// HSalsa20(key, nonce[0..16]); stream = Salsa20(subkey, nonce[16..24]);
/// bytes 0..16 discarded, 16..32 are the Poly1305 key, the rest XORs
/// the message.
fn xsalsa20_xor(key: &[u8; 32], nonce: &[u8; 24], m: &[u8], out: &mut [u8]) -> [u8; 32] {
    debug_assert_eq!(m.len(), out.len());
    let mut nonce16 = [0u8; 16];
    nonce16.copy_from_slice(&nonce[..16]);
    let subkey = hsalsa20(key, &nonce16);
    let mut k = [0u32; 8];
    for (i, w) in k.iter_mut().enumerate() {
        *w = u32::from_le_bytes(subkey[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let n = [
        u32::from_le_bytes(nonce[16..20].try_into().unwrap()),
        u32::from_le_bytes(nonce[20..24].try_into().unwrap()),
    ];
    let mut mac_key = [0u8; 32];
    let mut block = [0u8; 64];
    let mut counter = 0u64;
    let mut pos = 0usize;
    let mut first = true;
    while pos < m.len() || first {
        salsa20_block(&k, &n, counter, &mut block);
        if first {
            // The first 32 stream bytes are the one-time Poly1305 key;
            // the message is XORed against the stream from byte 32 on
            // (NaCl crypto_secretbox: "The first 32 bytes of the
            // xsalsa20 output are the poly1305 key; the rest encrypt
            // the message").
            mac_key.copy_from_slice(&block[..32]);
            let take = m.len().min(32);
            for (i, mi) in m.iter().take(32).enumerate() {
                out[i] = mi ^ block[32 + i];
            }
            pos = take;
            first = false;
            counter += 1;
            continue;
        }
        let take = (m.len() - pos).min(64);
        for i in 0..take {
            out[pos + i] = m[pos + i] ^ block[i];
        }
        pos += take;
        counter += 1;
    }
    mac_key
}

/// `crypto_box_beforenm`: the NaCl shared key = HSalsa20(X25519(my
/// secret, peer public), zeros).
fn box_shared(my_secret: &[u8; 32], peer_public: &[u8; 32]) -> Result<[u8; 32]> {
    let shared = curve25519_dalek::montgomery::MontgomeryPoint(*peer_public)
        .mul_clamped(*my_secret)
        .0;
    if shared.iter().all(|&b| b == 0) {
        return Err(Error::crypto("derp: X25519 peer key is a low-order point"));
    }
    Ok(hsalsa20(&shared, &[0u8; 16]))
}

/// `box.Seal` layout as used by `NodePrivate.SealTo`
/// (types/key/node.go:136-143): `nonce(24) || MAC(16) || ciphertext`.
pub(crate) fn box_seal(
    my_secret: &[u8; 32],
    peer_public: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let shared = box_shared(my_secret, peer_public)?;
    let mut ct = vec![0u8; plaintext.len()];
    let mac_key = xsalsa20_xor(&shared, &nonce, plaintext, &mut ct);
    let tag = poly1305(&mac_key, &ct);
    let mut out = Vec::with_capacity(24 + 16 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// `box.Open` (`NodePrivate.OpenFrom`, types/key/node.go:148-157):
/// input `nonce(24) || MAC(16) || ciphertext`; constant-time tag check.
pub(crate) fn box_open(
    my_secret: &[u8; 32],
    peer_public: &[u8; 32],
    sealed: &[u8],
) -> Result<Vec<u8>> {
    if sealed.len() < 24 + 16 {
        return Err(Error::crypto("derp: nacl box too short"));
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&sealed[..24]);
    let tag = &sealed[24..40];
    let ct = &sealed[40..];
    let shared = box_shared(my_secret, peer_public)?;
    let mut pt = vec![0u8; ct.len()];
    let mac_key = xsalsa20_xor(&shared, &nonce, ct, &mut pt);
    let expect = poly1305(&mac_key, ct);
    let mut diff = 0u8;
    for (a, b) in tag.iter().zip(expect.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(Error::crypto("derp: nacl box authentication failed"));
    }
    Ok(pt)
}

// ===========================================================================
// Node keys (tailscale.com/types/key — NodePrivate/NodePublic)
// ===========================================================================

/// The node keypair DERP addresses packets by (a WireGuard-style key).
#[derive(Clone)]
pub struct NodePrivateKey([u8; 32]);

impl std::fmt::Debug for NodePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret half (the machine-key precedent in
        // noise.rs).
        f.write_str("NodePrivateKey([redacted])")
    }
}

impl NodePrivateKey {
    /// `key.NewNode()` — fresh random key.
    pub fn generate() -> Self {
        let mut sk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sk);
        NodePrivateKey(sk)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        NodePrivateKey(bytes)
    }

    pub fn public(&self) -> NodePublicKey {
        let pk = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(self.0).0;
        NodePublicKey(pk)
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The public half of a node key (32 raw bytes on the DERP wire).
#[derive(Clone, PartialEq, Eq)]
pub struct NodePublicKey([u8; 32]);

impl std::fmt::Debug for NodePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NodePublicKey({})",
            self.0.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    }
}

impl NodePublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        NodePublicKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ===========================================================================
// DERP framing (derp/derp.go)
// ===========================================================================

/// `MaxPacketSize` (derp.go:28): the biggest packet a Send/Recv frame
/// may carry.
pub const MAX_PACKET_SIZE: usize = 64 << 10;

/// `Magic` (derp.go:32): `"DERP🔑"`, 8 UTF-8 bytes.
pub const MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";

/// `NonceLen` (derp.go:35).
pub const NONCE_LEN: usize = 24;
/// `FrameHeaderLen` (derp.go:36): type byte + BE u32 length.
pub const FRAME_HEADER_LEN: usize = 1 + 4;
/// `KeyLen` (derp.go:37).
pub const KEY_LEN: usize = 32;
/// `MaxInfoLen` (derp.go:38).
pub const MAX_INFO_LEN: usize = 1 << 20;

/// `ProtocolVersion` (derp.go:49): v2 puts the source key in
/// FrameRecvPacket.
pub const PROTOCOL_VERSION: i32 = 2;

// Frame types (derp.go:71-134). The mesh/relay-management frames
// below are part of the wire surface this module documents but a
// non-mesh client never sends or consumes.
pub const FRAME_SERVER_KEY: u8 = 0x01;
pub const FRAME_CLIENT_INFO: u8 = 0x02;
pub const FRAME_SERVER_INFO: u8 = 0x03;
pub const FRAME_SEND_PACKET: u8 = 0x04;
pub const FRAME_RECV_PACKET: u8 = 0x05;
pub const FRAME_KEEP_ALIVE: u8 = 0x06;
pub const FRAME_NOTE_PREFERRED: u8 = 0x07;
pub const FRAME_PEER_GONE: u8 = 0x08;
#[allow(dead_code)]
pub const FRAME_PEER_PRESENT: u8 = 0x09;
#[allow(dead_code)]
pub const FRAME_FORWARD_PACKET: u8 = 0x0a;
pub const FRAME_WATCH_CONNS: u8 = 0x10;
#[allow(dead_code)]
pub const FRAME_CLOSE_PEER: u8 = 0x11;
pub const FRAME_PING: u8 = 0x12;
pub const FRAME_PONG: u8 = 0x13;
pub const FRAME_HEALTH: u8 = 0x14;
pub const FRAME_RESTARTING: u8 = 0x15;

/// Peer-gone reasons (derp.go:140-144).
pub const PEER_GONE_DISCONNECTED: u8 = 0x00;
#[allow(dead_code)]
pub const PEER_GONE_NOT_HERE: u8 = 0x01;

/// `WriteFrame` (derp.go:278-289): type, BE u32 length, payload.
pub(crate) async fn write_frame<S>(stream: &mut S, t: u8, payload: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    if payload.len() > 10 << 20 {
        return Err(Error::protocol("derp: unreasonably large frame write"));
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.push(t);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream
        .write_all(&frame)
        .await
        .map_err(|e| Error::network(format!("derp: writing frame: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::network(format!("derp: flushing frame: {e}")))
}

/// `ReadFrameHeader` (derp.go:209-216) + payload read: returns
/// `(type, payload)`. Frame lengths are capped like `Client.Recv`
/// (derp_client.go:556-558: >1 MiB is unexpected).
pub(crate) async fn read_frame<S>(stream: &mut S) -> Result<(u8, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| Error::network(format!("derp: reading frame header: {e}")))?;
    let t = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > 1 << 20 {
        return Err(Error::protocol(format!(
            "derp: unexpectedly large frame of {len} bytes"
        )));
    }
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| Error::network(format!("derp: reading frame body: {e}")))?;
    Ok((t, payload))
}

// ===========================================================================
// ClientInfo / ServerInfo JSON (derp_client.go:174-249)
// ===========================================================================

/// `derp.ClientInfo` (derp_client.go:196-219). Field names are Go's
/// exact JSON names (`Version` omitempty, `CanAckPings` always,
/// `IsProber`/`AppName` omitempty; meshKey only for mesh clients).
#[derive(Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ClientInfo {
    #[serde(rename = "meshKey", default, skip_serializing_if = "String::is_empty")]
    pub mesh_key: String,
    #[serde(rename = "version", default, skip_serializing_if = "is_zero_i32")]
    pub version: i32,
    #[serde(rename = "CanAckPings", default)]
    pub can_ack_pings: bool,
    #[serde(rename = "IsProber", default, skip_serializing_if = "std::ops::Not::not")]
    pub is_prober: bool,
    #[serde(rename = "AppName", default, skip_serializing_if = "String::is_empty")]
    pub app_name: String,
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

/// `derp.ServerInfo` (derp.go:302-309).
#[derive(Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ServerInfo {
    #[serde(rename = "version", default, skip_serializing_if = "is_zero_i32")]
    pub version: i32,
    #[serde(
        rename = "TokenBucketBytesPerSecond",
        default,
        skip_serializing_if = "is_zero_i32"
    )]
    pub token_bucket_bytes_per_second: i32,
    #[serde(
        rename = "TokenBucketBytesBurst",
        default,
        skip_serializing_if = "is_zero_i32"
    )]
    pub token_bucket_bytes_burst: i32,
}

/// `ServerInfoMessage` as surfaced by `Client.Recv`
/// (derp_client.go:447-462).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfoMessage {
    pub token_bucket_bytes_per_second: i32,
    pub token_bucket_bytes_burst: i32,
}

/// Everything `Client.Recv` can return (derp_client.go:392-517).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerpMessage {
    ServerInfo(ServerInfoMessage),
    KeepAlive,
    PeerGone { peer: [u8; 32], reason: u8 },
    ReceivedPacket { source: [u8; 32], data: Vec<u8> },
    Ping([u8; 8]),
    Pong([u8; 8]),
    Health { problem: String },
    ServerRestarting { reconnect_in_ms: u32, try_for_ms: u32 },
}

/// Options for [`DerpClient::new`] — the wire-relevant subset of
/// `derp.ClientOpt` (derp_client.go:49-95).
#[derive(Debug, Clone, Default)]
pub struct DerpClientOptions {
    /// Pre-known server key; skips the FrameServerKey exchange
    /// (`derp.ServerPublicKey`, derp_client.go:77-81).
    pub server_pub: Option<NodePublicKey>,
    /// `derp.CanAckPings`.
    pub can_ack_pings: bool,
    /// `derp.AppName` — max 32 printable ASCII bytes
    /// (`ValidAppName`, derp_client.go:97-112).
    pub app_name: String,
}

// ===========================================================================
// DerpClient (derp/derp_client.go)
// ===========================================================================

/// `ValidAppName` (derp_client.go:97-112): at most 32 bytes of
/// printable ASCII.
pub(crate) fn valid_app_name(name: &str) -> bool {
    name.len() <= 32 && name.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// A DERP protocol client over any async stream — the port of
/// `derp.Client` (derp_client.go:25-47) without the send rate limiter
/// (a local policy knob, not wire behavior; see module deltas).
pub struct DerpClient<S> {
    stream: S,
    server_key: NodePublicKey,
    private_key: NodePrivateKey,
    public_key: NodePublicKey,
    #[allow(dead_code)]
    can_ack_pings: bool,
    app_name: String,
}

impl<S> std::fmt::Debug for DerpClient<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerpClient")
            .field("server_key", &self.server_key)
            .field("public_key", &self.public_key)
            .field("app_name", &self.app_name)
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> DerpClient<S> {
    /// `NewClient` (derp_client.go:114-153): validate options, receive
    /// the server key (unless pre-known), send the client key. The
    /// `ServerInfo` frame arrives later on the first `recv`.
    pub async fn new(
        mut stream: S,
        private_key: NodePrivateKey,
        opts: DerpClientOptions,
    ) -> Result<Self> {
        if !valid_app_name(&opts.app_name) {
            return Err(Error::config(format!(
                "derp: invalid AppName {:?}",
                &opts.app_name[..opts.app_name.len().min(40)]
            )));
        }
        let public_key = private_key.public();
        let server_key = match opts.server_pub.clone() {
            Some(k) => k,
            None => recv_server_key(&mut stream).await?,
        };
        send_client_key(
            &mut stream,
            &private_key,
            &public_key,
            &server_key,
            &opts,
        )
        .await?;
        Ok(DerpClient {
            stream,
            server_key,
            private_key,
            public_key,
            can_ack_pings: opts.can_ack_pings,
            app_name: opts.app_name,
        })
    }

    /// `PublicKey` (derp_client.go:155).
    pub fn public_key(&self) -> &NodePublicKey {
        &self.public_key
    }

    /// `ServerPublicKey` (derp_client.go:252).
    pub fn server_public_key(&self) -> &NodePublicKey {
        &self.server_key
    }

    /// The private key, for callers that need to open boxes from this
    /// node's perspective (kept private-typed; never printed).
    pub fn private_key(&self) -> &NodePrivateKey {
        &self.private_key
    }

    /// `Send` (derp_client.go:254-288): `FrameSendPacket` with the
    /// 32-byte destination key followed by the packet. Errors above
    /// 64 KiB like upstream.
    pub async fn send(&mut self, dst: &NodePublicKey, pkt: &[u8]) -> Result<()> {
        if pkt.len() > MAX_PACKET_SIZE {
            return Err(Error::protocol(format!(
                "derp.Send: packet too big: {}",
                pkt.len()
            )));
        }
        let mut payload = Vec::with_capacity(KEY_LEN + pkt.len());
        payload.extend_from_slice(dst.as_bytes());
        payload.extend_from_slice(pkt);
        write_frame(&mut self.stream, FRAME_SEND_PACKET, &payload).await
    }

    /// `SendPing` (derp_client.go:327-329).
    pub async fn send_ping(&mut self, data: [u8; 8]) -> Result<()> {
        write_frame(&mut self.stream, FRAME_PING, &data).await
    }

    /// `SendPong` (derp_client.go:331-333).
    pub async fn send_pong(&mut self, data: [u8; 8]) -> Result<()> {
        write_frame(&mut self.stream, FRAME_PONG, &data).await
    }

    /// `NotePreferred` (derp_client.go:350-371): one byte, 0x01/0x00.
    pub async fn note_preferred(&mut self, preferred: bool) -> Result<()> {
        write_frame(
            &mut self.stream,
            FRAME_NOTE_PREFERRED,
            &[u8::from(preferred)],
        )
        .await
    }

    /// `WatchConnectionChanges` (derp_client.go:375-382) — mesh only.
    pub async fn watch_connection_changes(&mut self) -> Result<()> {
        write_frame(&mut self.stream, FRAME_WATCH_CONNS, &[]).await
    }

    /// `Recv` (derp_client.go:525-707): read frames and decode; the
    /// `FrameServerInfo` JSON is unsealed with the node key against
    /// the server key (`parseServerInfo`, derp_client.go:174-192).
    /// Unknown frame types are skipped (`default: continue`,
    /// derp_client.go:581-582).
    pub async fn recv(&mut self) -> Result<DerpMessage> {
        loop {
            let (t, payload) = read_frame(&mut self.stream).await?;
            match t {
                FRAME_SERVER_INFO => {
                    if payload.len() < NONCE_LEN {
                        return Err(Error::protocol("derp: short serverInfo frame"));
                    }
                    if payload.len() > NONCE_LEN + MAX_INFO_LEN {
                        return Err(Error::protocol("derp: long serverInfo frame"));
                    }
                    let msg = box_open(
                        self.private_key.secret(),
                        self.server_key.as_bytes(),
                        &payload,
                    )
                    .map_err(|e| {
                        Error::crypto(format!(
                            "derp: failed to open naclbox from server key {}: {e}",
                            self.server_key.as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>()
                        ))
                    })?;
                    let info: ServerInfo = serde_json::from_slice(&msg)
                        .map_err(|e| Error::protocol(format!("derp: invalid serverInfo JSON: {e}")))?;
                    return Ok(DerpMessage::ServerInfo(ServerInfoMessage {
                        token_bucket_bytes_per_second: info.token_bucket_bytes_per_second,
                        token_bucket_bytes_burst: info.token_bucket_bytes_burst,
                    }));
                }
                FRAME_KEEP_ALIVE => return Ok(DerpMessage::KeepAlive),
                FRAME_PEER_GONE => {
                    if payload.len() < KEY_LEN {
                        // log+drop, derp_client.go:605-607
                        continue;
                    }
                    let mut peer = [0u8; 32];
                    peer.copy_from_slice(&payload[..KEY_LEN]);
                    let reason = if payload.len() > KEY_LEN {
                        payload[KEY_LEN]
                    } else {
                        PEER_GONE_DISCONNECTED
                    };
                    return Ok(DerpMessage::PeerGone { peer, reason });
                }
                FRAME_RECV_PACKET => {
                    if payload.len() < KEY_LEN {
                        continue;
                    }
                    let mut source = [0u8; 32];
                    source.copy_from_slice(&payload[..KEY_LEN]);
                    return Ok(DerpMessage::ReceivedPacket {
                        source,
                        data: payload[KEY_LEN..].to_vec(),
                    });
                }
                FRAME_PING => {
                    if payload.len() < 8 {
                        continue;
                    }
                    let mut data = [0u8; 8];
                    data.copy_from_slice(&payload[..8]);
                    return Ok(DerpMessage::Ping(data));
                }
                FRAME_PONG => {
                    if payload.len() < 8 {
                        continue;
                    }
                    let mut data = [0u8; 8];
                    data.copy_from_slice(&payload[..8]);
                    return Ok(DerpMessage::Pong(data));
                }
                FRAME_HEALTH => {
                    return Ok(DerpMessage::Health {
                        problem: String::from_utf8_lossy(&payload).into_owned(),
                    });
                }
                FRAME_RESTARTING => {
                    if payload.len() < 8 {
                        continue;
                    }
                    return Ok(DerpMessage::ServerRestarting {
                        reconnect_in_ms: u32::from_be_bytes(
                            payload[0..4].try_into().unwrap(),
                        ),
                        try_for_ms: u32::from_be_bytes(payload[4..8].try_into().unwrap()),
                    });
                }
                _ => continue,
            }
        }
    }
}

/// `recvServerKey` (derp_client.go:157-172): a `FrameServerKey` frame
/// whose payload starts with the 8-byte magic followed by the 32-byte
/// server key; extra trailing bytes are allowed (future-proofing).
async fn recv_server_key<S>(stream: &mut S) -> Result<NodePublicKey>
where
    S: AsyncRead + Unpin,
{
    let (t, payload) = read_frame(stream).await?;
    if t != FRAME_SERVER_KEY || payload.len() < 40 || &payload[..8] != MAGIC {
        return Err(Error::protocol("derp: invalid server greeting"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&payload[8..40]);
    Ok(NodePublicKey::from_bytes(key))
}

/// `sendClientKey` (derp_client.go:232-249): JSON `ClientInfo`
/// (version 2) sealed in a NaCl box to the server key; frame payload
/// = 32-byte node public key + sealed box.
async fn send_client_key<S>(
    stream: &mut S,
    private_key: &NodePrivateKey,
    public_key: &NodePublicKey,
    server_key: &NodePublicKey,
    opts: &DerpClientOptions,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let info = ClientInfo {
        version: PROTOCOL_VERSION,
        can_ack_pings: opts.can_ack_pings,
        is_prober: false,
        app_name: opts.app_name.clone(),
        mesh_key: String::new(),
    };
    let msg = serde_json::to_vec(&info)
        .map_err(|e| Error::config(format!("derp: clientInfo JSON: {e}")))?;
    let msgbox = box_seal(private_key.secret(), server_key.as_bytes(), &msg)?;
    let mut payload = Vec::with_capacity(KEY_LEN + msgbox.len());
    payload.extend_from_slice(public_key.as_bytes());
    payload.extend_from_slice(&msgbox);
    write_frame(stream, FRAME_CLIENT_INFO, &payload).await
}

// ===========================================================================
// derphttp: the HTTP(S) carrier (derp/derphttp/derphttp_client.go)
// ===========================================================================

/// The DERP URL path (`urlString`, derphttp_client.go:306).
pub const DERP_PATH: &str = "/derp";

/// `IdealNodeHeader` (derp.go:164) — sent only by region-aware
/// clients; documented for wire parity.
#[allow(dead_code)]
pub const IDEAL_NODE_HEADER: &str = "Ideal-Node";
/// `Fast StartHeader` (derp.go:170) — the meta-cert fast-start
/// optimization, explicitly out of scope (see module deltas).
#[allow(dead_code)]
pub const FAST_START_HEADER: &str = "Derp-Fast-Start";

/// Options for [`derp_connect`] — the wire-relevant subset of
/// `derphttp.Client` (derphttp_client.go:64-116).
#[derive(Debug, Clone)]
pub struct DerpHttpOptions {
    /// Skip TLS verification on https URLs.
    pub skip_cert_verify: bool,
    /// `derp.CanAckPings`.
    pub can_ack_pings: bool,
    /// `derp.AppName`.
    pub app_name: String,
    /// Send `NotePreferred(true)` right after registration
    /// (derphttp_client.go:571-577).
    pub preferred: bool,
}

impl Default for DerpHttpOptions {
    fn default() -> Self {
        DerpHttpOptions {
            skip_cert_verify: false,
            can_ack_pings: true,
            app_name: String::new(),
            preferred: false,
        }
    }
}

/// The `derphttp.Client.connect` happy path (derphttp_client.go:
/// 338-599): TCP (+TLS for https), `GET /derp` with the DERP upgrade
/// headers (509-534), require `101` (551-557), then run the DERP
/// client handshake over the hijacked stream.
///
/// Deltas (documented in the module docs): no websocket fallback, no
/// meta-cert fast-start, no proxy/dial-plan machinery.
pub async fn derp_connect(
    url: &str,
    node_key: &NodePrivateKey,
    opts: &DerpHttpOptions,
) -> Result<DerpClient<BoxProxyStream>> {
    let (scheme, host, port) = parse_derp_url(url)?;
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| Error::network(format!("derphttp: connect {host}:{port}: {e}")))?;
    let stream: BoxProxyStream = if scheme == "https" {
        let settings = TlsSettings {
            enabled: true,
            server_name: Some(host.clone()),
            skip_cert_verify: opts.skip_cert_verify,
            alpn: Vec::new(),
        };
        tls_connect(Box::new(tcp), &host, &settings)
            .await
            .map_err(|e| Error::network(format!("derphttp: tls: {e}")))?
    } else {
        Box::new(tcp)
    };

    let stream = derp_upgrade_over(stream, &host).await?;
    let mut client = DerpClient::new(
        stream,
        node_key.clone(),
        DerpClientOptions {
            server_pub: None,
            can_ack_pings: opts.can_ack_pings,
            app_name: opts.app_name.clone(),
        },
    )
    .await?;
    if opts.preferred {
        client.note_preferred(true).await?;
    }
    Ok(client)
}

/// The HTTP upgrade half over a pre-connected stream: `GET /derp` +
/// `Upgrade: DERP` + `Connection: Upgrade` (derphttp_client.go:
/// 509-512), read the response head, require 101 (551-557). Generic
/// over the stream so tests drive it against in-test mimics.
pub async fn derp_upgrade_over<S>(mut stream: S, host: &str) -> Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!(
        "GET {DERP_PATH} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: DERP\r\n\
         Connection: Upgrade\r\n\
         \r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| Error::network(format!("derphttp: writing upgrade request: {e}")))?;

    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| Error::network(format!("derphttp: reading response: {e}")))?;
        if n == 0 {
            return Err(Error::protocol("derphttp: EOF before headers"));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(Error::protocol("derphttp: response head too large"));
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status = head.split("\r\n").next().unwrap_or_default();
    if !status.contains(" 101") {
        // derphttp_client.go:552-556.
        return Err(Error::protocol(format!(
            "derphttp: GET failed: {status}"
        )));
    }
    Ok(stream)
}

/// Parse a DERP URL (`https://derp.example[:port]`), defaulting ports
/// 443/80 (`urlPort`, derphttp_client.go:236-249).
fn parse_derp_url(url: &str) -> Result<(String, String, u16)> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| Error::config(format!("derp url {url:?}: missing scheme")))?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h, p.parse::<u16>().unwrap_or(0))
        }
        _ => (
            authority,
            match scheme.as_str() {
                "https" => 443,
                "http" => 80,
                _ => return Err(Error::config(format!("derp url {url:?}: bad scheme"))),
            },
        ),
    };
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_string();
    if host.is_empty() || port == 0 {
        return Err(Error::config(format!("derp url {url:?}: bad authority")));
    }
    Ok((scheme, host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn nacl_box_matches_the_c_nacl_vector() {
        // golang.org/x/crypto/nacl/box/box_test.go TestBox (itself
        // cross-checked against C NaCl): alice secret = 32x01, bob
        // secret = 32x02, message = 64x03, nonce = 24x04; box from
        // alice to bob.
        let alice = [1u8; 32];
        let bob_secret = [2u8; 32];
        let alice_public =
            curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(alice).0;
        let bob_public =
            curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(bob_secret).0;
        let msg = [3u8; 64];
        let nonce = [4u8; 24];

        // box via shared key (the crypto_box "afternm" path). The
        // shared key cross-checked with libsodium's
        // crypto_box_beforenm for this exact vector.
        let shared = box_shared(&alice, &bob_public).unwrap();
        assert_eq!(
            shared.as_slice(),
            hex("18a99320f3488fa18a04239715d8ee738065e65c3d4b2898522d6c3d4ead588c").as_slice()
        );
        let mut ct = vec![0u8; msg.len()];
        let mac_key = xsalsa20_xor(&shared, &nonce, &msg, &mut ct);
        let tag = poly1305(&mac_key, &ct);
        let mut sealed = Vec::new();
        sealed.extend_from_slice(&tag);
        sealed.extend_from_slice(&ct);
        assert_eq!(
            sealed,
            hex("78ea30b19d2341ebbdba54180f821eec265cf86312549bea8a37652a8bb94f07\
                b78a73ed1708085e6ddd0e943bbdeb8755079a37eb31d86163ce241164a4762\
                9c0539f330b4914cd135b3855bc2a2dfc"),
            "the whole chain (X25519, HSalsa20, Salsa20, Poly1305) must match NaCl"
        );

        // And bob can open it.
        let mut full = Vec::new();
        full.extend_from_slice(&nonce);
        full.extend_from_slice(&sealed);
        let opened = box_open(&bob_secret, &alice_public, &full).unwrap();
        assert_eq!(opened, msg.to_vec());

        // A flipped bit must fail authentication.
        let mut tampered = full.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(box_open(&bob_secret, &alice_public, &tampered).is_err());
    }

    #[test]
    fn salsa20_block_matches_libsodium() {
        // The canonical XSalsa20 vector chain (libsodium test/default
        // core2.exp + core3.c): subkey = HSalsa20(firstkey,
        // 69696ee9...73d6) = dc908d...; the Salsa20 block 0 under
        // that subkey with nonce suffix 8219e0036b7a0b37 (verified
        // against libsodium's construction via pycryptodome).
        let firstkey = unhex32(
            "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389",
        );
        let n16: [u8; 16] = hex("69696ee955b62b73cd62bda875fc73d6")
            .try_into()
            .unwrap();
        let sub = hsalsa20(&firstkey, &n16);
        assert_eq!(
            sub,
            unhex32("dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4")
        );
        let mut k = [0u32; 8];
        for i in 0..8 {
            k[i] = u32::from_le_bytes(sub[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let n8 = [0x82u8, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37];
        let n = [
            u32::from_le_bytes(n8[0..4].try_into().unwrap()),
            u32::from_le_bytes(n8[4..8].try_into().unwrap()),
        ];
        let mut block = [0u8; 64];
        salsa20_block(&k, &n, 0, &mut block);
        assert_eq!(
            block.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880\
             309e645a74e9e0a60d8243acd9177ab51a1beb8d5a2f5d700c093c5e55855796"
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
            "salsa20 block must match the reference stream"
        );
    }

    fn unhex32(s: &str) -> [u8; 32] {
        hex(s).try_into().unwrap()
    }

    #[test]
    fn poly1305_matches_rfc8439() {
        // RFC 8439 §2.5.2: the documented key/message/tag triple.
        let key: [u8; 32] = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .try_into()
            .unwrap();
        let tag = poly1305(&key, b"Cryptographic Forum Research Group");
        assert_eq!(
            tag,
            hex("a8061dc1305136c6c22b8baf0c0127a9").as_slice()
        );
        // §2.5.2's example spans two blocks plus a partial third (34
        // bytes), exercising every path; the empty-message tag is
        // structurally the pad half of the key (accumulator 0).
        assert_eq!(
            poly1305(&key, b""),
            key[16..32].to_vec().as_slice()
        );
    }

    #[test]
    fn client_info_json_field_names_match_go() {
        // Go json.Marshal(ClientInfo{Version: 2}) ->
        // {"version":2,"CanAckPings":false}
        let info = ClientInfo {
            version: 2,
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&info).unwrap(),
            r#"{"version":2,"CanAckPings":false}"#
        );
        let parsed: ClientInfo =
            serde_json::from_str(r#"{"version":2,"CanAckPings":true,"AppName":"x"}"#).unwrap();
        assert!(parsed.can_ack_pings);
        assert_eq!(parsed.app_name, "x");
        // ServerInfo (derp.go:302-309).
        let si: ServerInfo = serde_json::from_str(r#"{"version":2}"#).unwrap();
        assert_eq!(si.version, 2);
        assert_eq!(
            serde_json::to_string(&ServerInfo::default()).unwrap(),
            "{}"
        );
    }

    #[test]
    fn derp_constants_match_upstream() {
        // derp.go:28-49, 71-134; the magic is "DERP" + U+1F511.
        assert_eq!(MAGIC, "DERP🔑".as_bytes());
        assert_eq!(MAX_PACKET_SIZE, 64 << 10);
        assert_eq!(PROTOCOL_VERSION, 2);
        assert_eq!(FRAME_SERVER_KEY, 0x01);
        assert_eq!(FRAME_CLIENT_INFO, 0x02);
        assert_eq!(FRAME_SERVER_INFO, 0x03);
        assert_eq!(FRAME_SEND_PACKET, 0x04);
        assert_eq!(FRAME_RECV_PACKET, 0x05);
        assert_eq!(FRAME_PING, 0x12);
        assert_eq!(FRAME_PONG, 0x13);
        assert_eq!(FRAME_NOTE_PREFERRED, 0x07);
    }

    #[test]
    fn derp_url_parsing() {
        assert_eq!(
            parse_derp_url("https://derp1.example.com").unwrap(),
            ("https".into(), "derp1.example.com".into(), 443)
        );
        assert_eq!(
            parse_derp_url("http://127.0.0.1:3340").unwrap(),
            ("http".into(), "127.0.0.1".into(), 3340)
        );
        assert!(parse_derp_url("derp.example.com").is_err());
    }

    #[test]
    fn valid_app_name_matches_upstream() {
        // derp_client.go:97-112 (MaxAppNameLen 32, printable ASCII).
        assert!(valid_app_name(""));
        assert!(valid_app_name("rustcrash-engine"));
        assert!(!valid_app_name(&"x".repeat(33)));
        assert!(!valid_app_name("has\ttab"));
        assert!(!valid_app_name("caf\u{e9}"));
    }

    // ------------------------------------------------------------------
    // End-to-end against an in-test DERP server: registration, ping/pong
    // and relaying one "WireGuard" packet between two clients
    // (derp.go's protocol flow comment, lines 56-70).
    // ------------------------------------------------------------------

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Read one HTTP request head (through \r\n\r\n).
    async fn read_http_head<S: AsyncRead + Unpin>(s: &mut S) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            s.read_exact(&mut byte).await.unwrap();
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// The server side of the registration exchange for one peer:
    /// accept the upgrade, send FrameServerKey, read + verify the
    /// naclboxed ClientInfo, return the stream and the peer's key.
    async fn mimic_register(
        listener: &TcpListener,
        server_key: &NodePrivateKey,
    ) -> (tokio::net::TcpStream, NodePublicKey) {
        let (mut sock, _) = listener.accept().await.expect("mimic accept");
        let head = read_http_head(&mut sock).await;
        assert!(head.starts_with("GET /derp HTTP/1.1"), "{head}");
        assert!(head.contains("Upgrade: DERP"));
        assert!(head.contains("Connection: Upgrade"));
        sock.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
        )
        .await
        .unwrap();

        // FrameServerKey: magic + server public key (derp.go:72).
        let mut greeting = Vec::new();
        greeting.extend_from_slice(MAGIC);
        greeting.extend_from_slice(server_key.public().as_bytes());
        write_frame(&mut sock, FRAME_SERVER_KEY, &greeting).await.unwrap();

        // FrameClientInfo: peer key + naclbox(ClientInfo JSON).
        let (t, payload) = read_frame(&mut sock).await.unwrap();
        assert_eq!(t, FRAME_CLIENT_INFO);
        let mut peer = [0u8; 32];
        peer.copy_from_slice(&payload[..32]);
        let json = box_open(server_key.secret(), &peer, &payload[32..]).unwrap();
        let info: ClientInfo = serde_json::from_slice(&json).unwrap();
        assert_eq!(info.version, PROTOCOL_VERSION);
        assert!(info.mesh_key.is_empty());
        (sock, NodePublicKey::from_bytes(peer))
    }

    #[tokio::test]
    async fn derp_registration_ping_pong_and_packet_relay_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let server_key = NodePrivateKey::generate();

        // SECURITY: all keys are generated in-test, never literals.
        let key_a = NodePrivateKey::generate();
        let key_b = NodePrivateKey::generate();
        let pub_a = key_a.public();
        let pub_b = key_b.public();
        let pub_a2 = pub_a.clone();
        let pub_b2 = pub_b.clone();

        let mimic = tokio::spawn(async move {
            let server_key = &server_key;
            // Register both peers (the ClientInfo exchange, derp.go:73).
            // The test registers B before spawning A, so the first
            // accept is deterministically B. mimic_register's box_open
            // succeeding IS the proof both sides agreed on the server
            // key.
            let (mut sock_b, peer_b) = mimic_register(&listener, server_key).await;
            let (mut sock_a, peer_a) = mimic_register(&listener, server_key).await;

            // FrameServerInfo to both (derp.go:74; naclbox JSON).
            let info_json = br#"{"version":2}"#.to_vec();
            for (sock, peer) in [
                (&mut sock_b, &peer_b),
                (&mut sock_a, &peer_a),
            ] {
                let boxed = box_seal(server_key.secret(), peer.as_bytes(), &info_json).unwrap();
                write_frame(sock, FRAME_SERVER_INFO, &boxed).await.unwrap();
            }

            // Steady state (derp.go:66-69): serve A's ping, B's
            // NotePreferred, and relay A's SendPacket to B as
            // RecvPacket (v2 carries the source key, derp.go:77).
            let mut saw_pong_sent = false;
            let mut saw_note_preferred = None;
            let mut relayed_packet = None;
            while !saw_pong_sent || saw_note_preferred.is_none() || relayed_packet.is_none() {
                tokio::select! {
                    frame = read_frame(&mut sock_a) => {
                        let (t, payload) = frame.unwrap();
                        match t {
                            FRAME_PING => {
                                write_frame(&mut sock_a, FRAME_PONG, &payload[..8])
                                    .await
                                    .unwrap();
                                saw_pong_sent = true;
                            }
                            FRAME_SEND_PACKET => {
                                let mut out = Vec::new();
                                out.extend_from_slice(peer_a.as_bytes());
                                out.extend_from_slice(&payload[KEY_LEN..]);
                                write_frame(&mut sock_b, FRAME_RECV_PACKET, &out)
                                    .await
                                    .unwrap();
                                relayed_packet = Some(payload[KEY_LEN..].to_vec());
                            }
                            other => panic!("unexpected frame from A: {other:#x}"),
                        }
                    }
                    frame = read_frame(&mut sock_b) => {
                        let (t, payload) = frame.unwrap();
                        assert_eq!(t, FRAME_NOTE_PREFERRED);
                        assert_eq!(payload, [1u8], "note-preferred carries one 0x01 byte");
                        saw_note_preferred = Some(payload[0]);
                    }
                }
            }
            (peer_a, peer_b, saw_pong_sent, saw_note_preferred, relayed_packet)
        });

        // Peer B registers FIRST (deterministic accept order), then
        // notes itself preferred, then waits for the relayed packet.
        let mut b = derp_connect(&url, &key_b, &DerpHttpOptions::default())
            .await
            .expect("B registers");
        b.note_preferred(true).await.unwrap();

        // Peer A: register, wait for ServerInfo, ping, then send one
        // WG-shaped packet to B.
        let url_a = url.clone();
        let a = tokio::spawn(async move {
            let mut a = derp_connect(&url_a, &key_a, &DerpHttpOptions::default())
                .await
                .expect("A registers");
            match a.recv().await.unwrap() {
                DerpMessage::ServerInfo(_) => {}
                other => panic!("A first message: {other:?}"),
            }
            let ping = [0xA5u8; 8];
            a.send_ping(ping).await.unwrap();
            assert_eq!(a.recv().await.unwrap(), DerpMessage::Pong(ping));
            // A plausible WireGuard handshake initiation (type 1, 148
            // bytes) — the thing DERP exists to relay.
            let mut wg_packet = vec![1u8, 0, 0, 0];
            wg_packet.extend(std::iter::repeat_n(0x5a, 144));
            a.send(&pub_b2, &wg_packet).await.unwrap();
            wg_packet
        });

        match b.recv().await.unwrap() {
            DerpMessage::ServerInfo(_) => {}
            other => panic!("B first message: {other:?}"),
        }
        match b.recv().await.unwrap() {
            DerpMessage::ReceivedPacket { source, data } => {
                assert_eq!(source, *pub_a2.as_bytes());
                assert_eq!(&data[..4], &[1, 0, 0, 0]);
                assert_eq!(data.len(), 148);
            }
            other => panic!("B second message: {other:?}"),
        }

        let wg_packet = a.await.unwrap();
        assert_eq!(wg_packet.len(), 148);
        let (peer_a, peer_b, pong, note, relayed) = mimic.await.unwrap();
        assert_eq!(peer_a, pub_a);
        assert_eq!(peer_b, pub_b);
        assert!(pong);
        assert_eq!(note, Some(1));
        assert_eq!(relayed.as_deref(), Some(wg_packet.as_slice()));
    }

    #[tokio::test]
    async fn bad_server_greeting_is_rejected() {
        // recvServerKey (derp_client.go:167-169): wrong magic, wrong
        // type or a short frame are all "invalid server greeting".
        let (mut a, mut b) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            a.write_all(&[0u8; 5]).await.unwrap(); // empty ServerKey frame
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        let err = DerpClient::new(
            &mut b,
            NodePrivateKey::generate(),
            DerpClientOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("invalid server greeting"));

        let (mut a, mut b) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            // Right length, wrong magic.
            let mut payload = vec![0u8; 40];
            payload[..4].copy_from_slice(b"NOPE");
            let mut frame = vec![FRAME_SERVER_KEY];
            frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame.extend_from_slice(&payload);
            a.write_all(&frame).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        assert!(DerpClient::new(
            &mut b,
            NodePrivateKey::generate(),
            DerpClientOptions::default()
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn oversize_frame_from_server_is_refused() {
        // Client.Recv rejects frames > 1 MiB (derp_client.go:556-558).
        let (mut a, mut b) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut frame = vec![FRAME_KEEP_ALIVE];
            frame.extend_from_slice(&(2u32 << 20).to_be_bytes());
            a.write_all(&frame).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        let key = NodePrivateKey::generate();
        let mut client = DerpClient::new(
            &mut b,
            key,
            DerpClientOptions {
                server_pub: Some(NodePublicKey::from_bytes([9u8; 32])),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let err = client.recv().await.unwrap_err();
        assert!(err.to_string().contains("large frame"));
    }

    #[tokio::test]
    async fn send_rejects_oversize_packets() {
        // derp_client.go:266-268.
        let (mut a, _b) = tokio::io::duplex(1024);
        let key = NodePrivateKey::generate();
        let mut client = DerpClient::new(
            &mut a,
            key,
            DerpClientOptions {
                server_pub: Some(NodePublicKey::from_bytes([9u8; 32])),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let big = vec![0u8; MAX_PACKET_SIZE + 1];
        let err = client
            .send(&NodePublicKey::from_bytes([1u8; 32]), &big)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("packet too big"));
    }
}
