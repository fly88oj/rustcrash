//! `controlbase`: the Noise IK base transport of the Tailscale 2021
//! control protocol.
//!
//! Port of `tailscale.com/control/controlbase` (handshake.go,
//! messages.go, conn.go; cached at `/tmp/wave10-upstream/`
//! `control_controlbase_*.go`, upstream `main` as of 2026-09).
//!
//! The wire protocol is **Noise IK** — the upstream constant is
//! `Noise_IK_25519_ChaChaPoly_BLAKE2s` (handshake.go:31) — instantiated
//! with X25519, ChaCha20Poly1305 and BLAKE2s, run over a raw byte
//! stream (a hijacked HTTP connection; see `super::controlhttp`).
//! The handshake pattern is (handshake.go:75-95, 158-171):
//!
//! ```text
//! <- s   (the control server's static key is pre-known and hashed in)
//! ...
//! -> e, es, s, ss    (initiation: 101 bytes, messages.go:29-47)
//! <- e, ee, se       (response: 51 bytes, messages.go:64-71)
//! ```
//!
//! After Split (handshake.go:418-438) both directions carry
//! `msgTypeRecord` frames: 1 type byte + 2-byte big-endian ciphertext
//! length + ChaCha20Poly1305 ciphertext, nonce = 4 zero bytes +
//! big-endian u64 counter, no AAD (conn.go:162-175, 385-396).
//!
//! The BLAKE2s / HMAC / X25519 / ChaChaPoly primitives mirror the
//! hand-rolled ones in `crate::proto::wireguard` (they are private
//! there, so they are re-implemented here following the same
//! precedent; `proto/wireguard.rs:212-340, 344-365, 442-498`).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Protocol constants (controlbase/messages.go:8-27, conn.go:25-35)
// ---------------------------------------------------------------------------

/// The Noise instance name, hashed as the initial handshake state
/// (handshake.go:31, 346-348).
pub const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// The prologue prefix mixed into the handshake so both sides agree on
/// the control protocol version carried in the cleartext init header
/// (handshake.go:42, 46-50).
pub const PROTOCOL_VERSION_PREFIX: &[u8] = b"Tailscale Control Protocol v";

/// `msgTypeInitiation` — Noise IK handshake initiation (messages.go:10).
pub const MSG_TYPE_INITIATION: u8 = 1;
/// `msgTypeResponse` — Noise IK handshake response (messages.go:12).
pub const MSG_TYPE_RESPONSE: u8 = 2;
/// `msgTypeError` — unauthenticated cleartext error (messages.go:19).
pub const MSG_TYPE_ERROR: u8 = 3;
/// `msgTypeRecord` — encrypted session data (messages.go:21).
pub const MSG_TYPE_RECORD: u8 = 4;

/// Header size on all messages except initiation (messages.go:24).
pub const HEADER_LEN: usize = 3;
/// Header size on initiation messages: version(2)+type(1)+len(2)
/// (messages.go:26).
pub const INITIATION_HEADER_LEN: usize = 5;

/// Total initiation message size (messages.go:39).
pub const INITIATION_LEN: usize = 101;
/// Total response message size (messages.go:71).
pub const RESPONSE_LEN: usize = 51;

/// Maximum frame size on the wire (conn.go:28).
pub const MAX_MESSAGE_SIZE: usize = 4096;
/// Maximum ciphertext per frame (conn.go:31).
pub const MAX_CIPHERTEXT_SIZE: usize = MAX_MESSAGE_SIZE - HEADER_LEN;
/// Maximum plaintext per frame (conn.go:34); ChaChaPoly overhead is 16.
pub const MAX_PLAINTEXT_SIZE: usize = MAX_CIPHERTEXT_SIZE - 16;

/// The protocol version the ts2021 client negotiates by default:
/// upstream seeds the Noise dialer with `tailcfg.CurrentCapabilityVersion`
/// (`control/ts2021/client.go:253`; the constant is
/// `tailcfg/tailcfg.go:200`).
pub const CURRENT_PROTOCOL_VERSION: u16 = 148;

/// The prologue bytes for a protocol version (handshake.go:46-50):
/// `"Tailscale Control Protocol v" + strconv.Itoa(version)`.
pub fn protocol_version_prologue(version: u16) -> Vec<u8> {
    let mut ret = Vec::with_capacity(PROTOCOL_VERSION_PREFIX.len() + 5);
    ret.extend_from_slice(PROTOCOL_VERSION_PREFIX);
    ret.extend_from_slice(version.to_string().as_bytes());
    ret
}

// ---------------------------------------------------------------------------
// BLAKE2s-256 (RFC 7693) — same code as proto/wireguard.rs:215-340
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

/// Unkeyed BLAKE2s-256 (the handshake's `MixHash` hash).
pub(crate) fn blake2s256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    blake2s_into(data, None, &mut out);
    out
}

/// BLAKE2s over `data`, optionally keyed, writing `out.len()` digest
/// bytes (RFC 7693 §3.2). Same implementation as wireguard.rs:258-300.
pub(crate) fn blake2s_into(data: &[u8], key: Option<&[u8]>, out: &mut [u8]) {
    let out_len = out.len();
    let mut h = BLAKE2S_IV;
    h[0] ^= 0x0101_0000 | ((key.map_or(0, |k| k.len()) as u32) << 8) | out_len as u32;

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

/// HMAC-BLAKE2s-256 (standard HMAC, 64-byte block) — same as
/// wireguard.rs:348-365.
pub(crate) fn hmac_blake2s(key: &[u8], msg: &[u8]) -> [u8; 32] {
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

// ---------------------------------------------------------------------------
// HKDF-BLAKE2s — golang.org/x/crypto/hkdf instantiated with BLAKE2s,
// exactly as handshake.go:376 and 422 use it
// ---------------------------------------------------------------------------

/// HKDF extract: `PRK = HMAC-Hash(salt, IKM)` (RFC 5869 §2.2).
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_blake2s(salt, ikm)
}

/// HKDF expand: the output-keystream `T(1) || T(2) || ...` where
/// `T(i) = HMAC(PRK, T(i-1) || info || i)` (RFC 5869 §2.3). The Go
/// code reads 32-byte chunks from an `io.Reader` over this stream
/// (handshake.go:377-383, 422-428).
fn hkdf_expand_stream(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let mut block = Vec::with_capacity(t.len() + info.len() + 1);
        block.extend_from_slice(&t);
        block.extend_from_slice(info);
        block.push(counter);
        t = hmac_blake2s(prk, &block).to_vec();
        out.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// `HKDF(hash=BLAKE2s, ikm, salt, info)` -> `len` bytes — the
/// constructor used by `MixDH` and `Split` (handshake.go:376, 422).
fn hkdf_blake2s(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand_stream(&prk, info, len)
}

// ---------------------------------------------------------------------------
// Machine keys (tailscale.com/types/key — MachinePrivate/MachinePublic)
// ---------------------------------------------------------------------------

/// A private X25519 key used for the machine identity (the control
/// protocol's "s" of the client). Never printed by Debug.
#[derive(Clone)]
pub struct MachinePrivateKey([u8; 32]);

impl std::fmt::Debug for MachinePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MachinePrivateKey([redacted])")
    }
}

impl MachinePrivateKey {
    /// `key.NewMachine()` — a fresh random machine key.
    pub fn generate() -> Self {
        let mut sk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sk);
        MachinePrivateKey(sk)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        MachinePrivateKey(bytes)
    }

    /// This key's public half (`MachinePrivate.Public`).
    pub fn public(&self) -> MachinePublicKey {
        let pk = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(self.0).0;
        MachinePublicKey(pk)
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex serialization for state persistence (`UntypedHexString`,
    /// types/key/node.go — machine-key half).
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parse 64 hex chars back into a key.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex32(s)?;
        Ok(MachinePrivateKey(bytes))
    }
}

/// A public X25519 key — the control server's static key or a peer
/// machine key.
#[derive(Clone, PartialEq, Eq)]
pub struct MachinePublicKey([u8; 32]);

impl std::fmt::Debug for MachinePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MachinePublicKey({})", self.to_hex())
    }
}

impl MachinePublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        MachinePublicKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        Ok(MachinePublicKey(hex32(s)?))
    }
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(Error::crypto("keys must be 64 hex characters"));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = (bytes[2 * i] as char).to_digit(16);
        let lo = (bytes[2 * i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(hi), Some(lo)) => out[i] = ((hi << 4) | lo) as u8,
            _ => return Err(Error::crypto("keys must be hex")),
        }
    }
    Ok(out)
}

/// X25519 DH (handshake.go:371 `curve25519.X25519`); rejects the
/// all-zero shared secret like wireguard.rs:461-469.
fn dh(privkey: &[u8; 32], pubkey: &[u8; 32]) -> Result<[u8; 32]> {
    let shared = curve25519_dalek::montgomery::MontgomeryPoint(*pubkey)
        .mul_clamped(*privkey)
        .0;
    if shared.iter().all(|&b| b == 0) {
        return Err(Error::crypto(
            "controlbase: X25519 peer key is a low-order point",
        ));
    }
    Ok(shared)
}

// ---------------------------------------------------------------------------
// Symmetric state (handshake.go:328-438)
// ---------------------------------------------------------------------------

/// The in-flight Noise IK handshake state (`symmetricState`). Reuse
/// after `Split` is impossible by construction here: `split` consumes
/// `self` (upstream's `finished` flag exists only because Go has no
/// move semantics, handshake.go:330-340).
struct SymmetricState {
    h: [u8; 32],
    ck: [u8; 32],
}

impl SymmetricState {
    /// `Initialize` (handshake.go:344-348): h = ck = HASH(protocolName).
    fn new() -> Self {
        let h = blake2s256(PROTOCOL_NAME);
        SymmetricState { h, ck: h }
    }

    /// `MixHash` (handshake.go:352-358): h = BLAKE2s(h || data).
    fn mix_hash(&mut self, data: &[u8]) {
        let mut buf = Vec::with_capacity(32 + data.len());
        buf.extend_from_slice(&self.h);
        buf.extend_from_slice(data);
        self.h = blake2s256(&buf);
    }

    /// `MixDH` (handshake.go:369-385): ck, k = HKDF(BLAKE2s,
    /// ikm=X25519(priv,pub), salt=ck, info=nil) — first 32 bytes
    /// re-key the chain, next 32 are a one-time ChaChaPoly key.
    fn mix_dh(&mut self, privkey: &[u8; 32], pubkey: &[u8; 32]) -> Result<[u8; 32]> {
        let key_data = dh(privkey, pubkey)?;
        let okm = hkdf_blake2s(&key_data, &self.ck, &[], 64);
        self.ck.copy_from_slice(&okm[..32]);
        let mut k = [0u8; 32];
        k.copy_from_slice(&okm[32..]);
        Ok(k)
    }

    /// `EncryptAndHash` (handshake.go:390-397): ciphertext =
    /// ChaChaPoly(k, nonce 0, plaintext, AAD=h); h mixed with the
    /// ciphertext.
    fn encrypt_and_hash(&mut self, key: &[u8; 32], plaintext: &[u8], out: &mut [u8]) -> Result<()> {
        debug_assert_eq!(out.len(), plaintext.len() + 16);
        let ct = seal_once(key, plaintext, &self.h)?;
        out.copy_from_slice(&ct);
        self.mix_hash(&ct);
        Ok(())
    }

    /// `DecryptAndHash` (handshake.go:403-413): the inverse; on
    /// success h is mixed with the ciphertext.
    fn decrypt_and_hash(&mut self, key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let pt = open_once(key, ciphertext, &self.h)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    /// `Split` (handshake.go:418-438): k1, k2 = the first two 32-byte
    /// blocks of HKDF(BLAKE2s, ikm=nil, salt=ck, info=nil). The
    /// initiator transmits with k1 and receives with k2 (client side,
    /// handshake.go:177-188); the server is the mirror
    /// (handshake.go:313-324).
    fn split(self) -> ([u8; 32], [u8; 32]) {
        let okm = hkdf_blake2s(&[], &self.ck, &[], 64);
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1.copy_from_slice(&okm[..32]);
        k2.copy_from_slice(&okm[32..]);
        (k1, k2)
    }
}

/// The handshake-hash snapshot kept on the finished connection
/// (`Conn.handshakeHash`, conn.go:45).
fn handshake_hash(s: &SymmetricState) -> [u8; 32] {
    s.h
}

/// One-shot ChaCha20Poly1305 with an all-zero nonce (`singleUseCHP`,
/// handshake.go:468-494).
fn seal_once(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::crypto("controlbase: bad AEAD key length"))?;
    cipher
        .encrypt(
            &[0u8; 12].into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::crypto("controlbase: AEAD seal failed"))
}

fn open_once(key: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::crypto("controlbase: bad AEAD key length"))?;
    cipher
        .decrypt(
            &[0u8; 12].into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::crypto("controlbase: AEAD open failed"))
}

// ---------------------------------------------------------------------------
// Handshake messages (messages.go:29-87)
// ---------------------------------------------------------------------------

/// Build an initiation message header+body skeleton (mkInitiationMessage,
/// messages.go:41-47): version(2) type(1) length(2)=96, then the
/// handshake fills eph(32) + encMachinePub(48) + tag(16).
fn mk_initiation_message(version: u16) -> [u8; INITIATION_LEN] {
    let mut ret = [0u8; INITIATION_LEN];
    ret[..2].copy_from_slice(&version.to_be_bytes());
    ret[2] = MSG_TYPE_INITIATION;
    ret[3..5].copy_from_slice(&96u16.to_be_bytes());
    ret
}

/// Type byte of a 3-byte non-initiation header (messages.go:80-87).
fn frame_type(header: &[u8; HEADER_LEN]) -> u8 {
    header[0]
}

/// Payload length of a 3-byte non-initiation header (messages.go:84-87).
fn frame_length(header: &[u8; HEADER_LEN]) -> usize {
    u16::from_be_bytes([header[1], header[2]]) as usize
}

// ---------------------------------------------------------------------------
// Client handshake (handshake.go:68-101 + 120-190)
// ---------------------------------------------------------------------------

/// The first half of `ClientDeferred` (handshake.go:68-101): computes
/// the 101-byte initiation message for `machine_key` authenticating to
/// `control_key`, plus the continuation state needed to finish the
/// handshake once a (switched) stream is available.
///
/// Split like upstream so the initiation can ride inside the HTTP
/// upgrade request (controlhttp saves an RTT, client.go:347+545).
pub struct ClientHandshake {
    state: SymmetricState,
    machine_key: MachinePrivateKey,
    machine_ephemeral: MachinePrivateKey,
    control_key: MachinePublicKey,
    version: u16,
}

/// `ClientDeferred` (handshake.go:68-101).
pub fn client_deferred(
    machine_key: &MachinePrivateKey,
    control_key: &MachinePublicKey,
    protocol_version: u16,
) -> Result<(Vec<u8>, ClientHandshake)> {
    let mut s = SymmetricState::new();

    // prologue (handshake.go:72-73)
    s.mix_hash(&protocol_version_prologue(protocol_version));

    // <- s (handshake.go:75-77): the pre-known server static key.
    s.mix_hash(control_key.as_bytes());

    // -> e, es, s, ss (handshake.go:79-95)
    let mut init = mk_initiation_message(protocol_version);
    let machine_ephemeral = MachinePrivateKey::generate();
    init[INITIATION_HEADER_LEN..INITIATION_HEADER_LEN + 32]
        .copy_from_slice(machine_ephemeral.public().as_bytes());
    s.mix_hash(machine_ephemeral.public().as_bytes());
    let cipher = s.mix_dh(machine_ephemeral.secret(), control_key.as_bytes())?;
    s.encrypt_and_hash(
        &cipher,
        machine_key.public().as_bytes(),
        &mut init[INITIATION_HEADER_LEN + 32..INITIATION_HEADER_LEN + 32 + 48],
    )?;
    let cipher = s.mix_dh(machine_key.secret(), control_key.as_bytes())?;
    s.encrypt_and_hash(
        &cipher,
        &[],
        &mut init[INITIATION_HEADER_LEN + 32 + 48..],
    )?;

    Ok((
        init.to_vec(),
        ClientHandshake {
            state: s,
            machine_key: machine_key.clone(),
            machine_ephemeral,
            control_key: control_key.clone(),
            version: protocol_version,
        },
    ))
}

impl ClientHandshake {
    /// `continueClientHandshake` (handshake.go:120-190): read the 51-byte
    /// response (or a cleartext error frame), run `<- e, ee, se`,
    /// Split, and return the secured connection.
    pub async fn continue_handshake<S>(self, stream: S) -> Result<NoiseConn<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Self {
            mut state,
            machine_key,
            machine_ephemeral,
            control_key,
            version,
        } = self;

        let mut stream = stream;
        // Read the response header, rejecting error frames (handshake.go:
        // 137-156).
        let mut header = [0u8; HEADER_LEN];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| Error::network(format!("controlbase: reading response header: {e}")))?;
        let typ = frame_type(&header);
        if typ != MSG_TYPE_RESPONSE {
            if typ != MSG_TYPE_ERROR {
                return Err(Error::protocol(format!(
                    "controlbase: unexpected response message type {typ}"
                )));
            }
            let len = frame_length(&header);
            let mut msg = vec![0u8; len];
            stream
                .read_exact(&mut msg)
                .await
                .map_err(|e| Error::network(format!("controlbase: reading error body: {e}")))?;
            return Err(Error::protocol(format!(
                "controlbase: server error: {:?}",
                String::from_utf8_lossy(&msg)
            )));
        }
        let expected = RESPONSE_LEN - HEADER_LEN;
        if frame_length(&header) != expected {
            return Err(Error::protocol(format!(
                "controlbase: wrong length {} received for handshake response",
                frame_length(&header)
            )));
        }
        let mut payload = [0u8; RESPONSE_LEN - HEADER_LEN];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| Error::network(format!("controlbase: reading response body: {e}")))?;

        // <- e, ee, se (handshake.go:158-170)
        let mut control_ephemeral = [0u8; 32];
        control_ephemeral.copy_from_slice(&payload[..32]);
        state.mix_hash(&control_ephemeral);
        state.mix_dh(machine_ephemeral.secret(), &control_ephemeral)?;
        let cipher = state.mix_dh(machine_key.secret(), &control_ephemeral)?;
        state.decrypt_and_hash(&cipher, &payload[32..])?;

        // Split (handshake.go:172-175): client tx=k1, rx=k2.
        let hh = handshake_hash(&state);
        let (k1, k2) = state.split();
        Ok(NoiseConn {
            stream,
            version,
            peer: control_key,
            handshake_hash: hh,
            tx: CipherState::new(k1),
            rx: CipherState::new(k2),
        })
    }
}

/// `Client` (handshake.go:109-118): write the initiation, then finish
/// the handshake — the synchronous upgrade form.
pub async fn client_handshake<S>(
    mut stream: S,
    machine_key: &MachinePrivateKey,
    control_key: &MachinePublicKey,
    protocol_version: u16,
) -> Result<NoiseConn<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (init, cont) = client_deferred(machine_key, control_key, protocol_version)?;
    stream
        .write_all(&init)
        .await
        .map_err(|e| Error::network(format!("controlbase: writing initiation: {e}")))?;
    cont.continue_handshake(stream).await
}

// ---------------------------------------------------------------------------
// Server handshake (handshake.go:201-326) — the control-server half,
// needed by the in-test mimics (upstream keeps interop tests for the
// same reason, controlbase/interop_test.go)
// ---------------------------------------------------------------------------

/// The server error frame (`sendErr`, handshake.go:213-227): a
/// cleartext `msgTypeError` frame, then the error is returned.
async fn send_err<S>(stream: &mut S, msg: &str) -> Error
where
    S: AsyncWrite + Unpin,
{
    let msg = &msg[..msg.len().min(1 << 16)];
    let mut frame = Vec::with_capacity(HEADER_LEN + msg.len());
    frame.push(MSG_TYPE_ERROR);
    frame.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    frame.extend_from_slice(msg.as_bytes());
    let _ = stream.write_all(&frame).await;
    Error::protocol(format!("controlbase: refused client handshake: {msg:?}"))
}

/// `Server` (handshake.go:201-326): complete the Noise IK handshake as
/// the control server holding `control_key`. `optional_init` may carry
/// the client's initiation message (e.g. decoded from the HTTP
/// handshake header); otherwise it is read from the stream.
pub async fn server_handshake<S>(
    mut stream: S,
    control_key: &MachinePrivateKey,
    optional_init: Option<Vec<u8>>,
) -> Result<NoiseConn<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut s = SymmetricState::new();

    // Read (or accept) the initiation (handshake.go:229-258).
    let init: Vec<u8> = match optional_init {
        Some(init) => {
            if init.len() != INITIATION_LEN {
                return Err(send_err(&mut stream, "wrong handshake initiation size").await);
            }
            init
        }
        None => {
            let mut header = [0u8; INITIATION_HEADER_LEN];
            stream
                .read_exact(&mut header)
                .await
                .map_err(|e| Error::network(format!("controlbase: reading init header: {e}")))?;
            if header[2] != MSG_TYPE_INITIATION {
                return Err(send_err(&mut stream, "unexpected handshake message type").await);
            }
            let mut init = header.to_vec();
            if u16::from_be_bytes([header[3], header[4]]) as usize
                != INITIATION_LEN - INITIATION_HEADER_LEN
            {
                return Err(send_err(&mut stream, "wrong handshake initiation length").await);
            }
            init.resize(INITIATION_LEN, 0);
            stream
                .read_exact(&mut init[INITIATION_HEADER_LEN..])
                .await
                .map_err(|e| Error::network(format!("controlbase: reading init body: {e}")))?;
            init
        }
    };

    let client_version = u16::from_be_bytes([init[0], init[1]]);
    if init[2] != MSG_TYPE_INITIATION {
        return Err(send_err(&mut stream, "unexpected handshake message type").await);
    }
    if u16::from_be_bytes([init[3], init[4]]) as usize != INITIATION_LEN - INITIATION_HEADER_LEN {
        return Err(send_err(&mut stream, "wrong handshake initiation length").await);
    }

    // prologue + <- s (handshake.go:260-267)
    s.mix_hash(&protocol_version_prologue(client_version));
    s.mix_hash(control_key.public().as_bytes());

    // -> e, es, s, ss (handshake.go:269-287)
    let mut machine_ephemeral = [0u8; 32];
    machine_ephemeral.copy_from_slice(&init[INITIATION_HEADER_LEN..INITIATION_HEADER_LEN + 32]);
    s.mix_hash(&machine_ephemeral);
    let cipher = s.mix_dh(control_key.secret(), &machine_ephemeral)?;
    let machine_key_bytes = s
        .decrypt_and_hash(
            &cipher,
            &init[INITIATION_HEADER_LEN + 32..INITIATION_HEADER_LEN + 32 + 48],
        )
        .map_err(|e| Error::crypto(format!("controlbase: decrypting machine key: {e}")))?;
    let mut machine_key = [0u8; 32];
    machine_key.copy_from_slice(&machine_key_bytes);
    let cipher = s.mix_dh(control_key.secret(), &machine_key)?;
    s.decrypt_and_hash(&cipher, &init[INITIATION_HEADER_LEN + 32 + 48..])
        .map_err(|e| Error::crypto(format!("controlbase: decrypting initiation tag: {e}")))?;

    // <- e, ee, se (handshake.go:289-302)
    let mut resp = [0u8; RESPONSE_LEN];
    resp[0] = MSG_TYPE_RESPONSE;
    resp[1..3].copy_from_slice(&(48u16).to_be_bytes());
    let control_ephemeral = MachinePrivateKey::generate();
    resp[HEADER_LEN..HEADER_LEN + 32].copy_from_slice(control_ephemeral.public().as_bytes());
    s.mix_hash(control_ephemeral.public().as_bytes());
    s.mix_dh(control_ephemeral.secret(), &machine_ephemeral)?;
    let cipher = s.mix_dh(control_ephemeral.secret(), &machine_key)?;
    s.encrypt_and_hash(&cipher, &[], &mut resp[HEADER_LEN + 32..])?;

    // Split (handshake.go:304-307): server tx=k2, rx=k1 (mirror of
    // the client, handshake.go:313-324).
    let hh = handshake_hash(&s);
    let (k1, k2) = s.split();

    stream
        .write_all(&resp)
        .await
        .map_err(|e| Error::network(format!("controlbase: writing response: {e}")))?;

    Ok(NoiseConn {
        stream,
        version: client_version,
        peer: MachinePublicKey::from_bytes(machine_key),
        handshake_hash: hh,
        tx: CipherState::new(k2),
        rx: CipherState::new(k1),
    })
}

// ---------------------------------------------------------------------------
// The secured connection (conn.go)
// ---------------------------------------------------------------------------

/// Per-direction cipher state: a ChaCha20Poly1305 key plus the
/// big-endian counter nonce (conn.go:385-396; nonce = 4 zero bytes +
/// BE u64, `invalidNonce` = 2^64-1 refuses to wrap).
struct CipherState {
    cipher: Option<ChaCha20Poly1305>,
    counter: u64,
}

impl CipherState {
    fn new(key: [u8; 32]) -> Self {
        CipherState {
            cipher: Some(ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key")),
            counter: 0,
        }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.counter.to_be_bytes());
        n
    }
}

/// A secured Noise connection over any async stream — the port of
/// `controlbase.Conn` (conn.go:41-338) with tokio IO.
pub struct NoiseConn<S> {
    stream: S,
    version: u16,
    peer: MachinePublicKey,
    handshake_hash: [u8; 32],
    tx: CipherState,
    rx: CipherState,
}

impl<S> std::fmt::Debug for NoiseConn<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseConn")
            .field("version", &self.version)
            .field("peer", &self.peer)
            .field("handshake_hash", &self.handshake_hash.iter().map(|b| format!("{b:02x}")).collect::<String>())
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> NoiseConn<S> {
    /// `ProtocolVersion` (conn.go:72-74).
    pub fn protocol_version(&self) -> u16 {
        self.version
    }

    /// `HandshakeHash` (conn.go:80-82) — binds later messages to this
    /// exact connection.
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.handshake_hash
    }

    /// `Peer` (conn.go:85-87) — the peer's long-term public key.
    pub fn peer(&self) -> &MachinePublicKey {
        &self.peer
    }

    /// `Write` (conn.go:270-321): splits plaintext into
    /// `maxPlaintextSize` (4077-byte) `msgTypeRecord` frames and sends
    /// them — `for len(bs) > 0`, so an empty write sends nothing. Any
    /// error is fatal for the connection (sticky, like `txState.err`).
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut sent = 0usize;
        while sent < plaintext.len() {
            let end = plaintext.len().min(sent + MAX_PLAINTEXT_SIZE);
            let chunk = &plaintext[sent..end];
            let frame = self.encrypt_record(chunk)?;
            self.stream
                .write_all(&frame)
                .await
                .map_err(|e| Error::network(format!("controlbase: write: {e}")))?;
            sent = end;
        }
        self.stream
            .flush()
            .await
            .map_err(|e| Error::network(format!("controlbase: flush: {e}")))?;
        Ok(())
    }

    /// `encryptLocked` (conn.go:162-175): type(1)=4 + BE u16
    /// ciphertext length + AEAD(nonce, plaintext, AAD=nil).
    fn encrypt_record(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let state = &mut self.tx;
        let cipher = state
            .cipher
            .as_ref()
            .ok_or_else(|| Error::protocol("controlbase: cipher exhausted or desynced"))?;
        if state.counter == u64::MAX {
            return Err(Error::protocol(
                "controlbase: cipher exhausted, no more nonces available",
            ));
        }
        let ct = cipher
            .encrypt(
                (&state.nonce()).into(),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| Error::crypto("controlbase: AEAD seal failed"))?;
        state.counter += 1;
        let mut frame = Vec::with_capacity(HEADER_LEN + ct.len());
        frame.push(MSG_TYPE_RECORD);
        frame.extend_from_slice(&(ct.len() as u16).to_be_bytes());
        frame.extend_from_slice(&ct);
        Ok(frame)
    }

    /// `Read`-equivalent: decrypt one `msgTypeRecord` frame and return
    /// its plaintext (which may be empty — zero-byte frames are legal,
    /// conn.go:250-257). Sticky error like `rxState`: once decryption
    /// fails the connection is dead (conn.go:246-248 checks the nil
    /// cipher before touching the wire).
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        if self.rx.cipher.is_none() {
            return Err(Error::protocol(
                "controlbase: connection closed after decrypt failure",
            ));
        }
        let mut header = [0u8; HEADER_LEN];
        self.stream
            .read_exact(&mut header)
            .await
            .map_err(|e| Error::network(format!("controlbase: read: {e}")))?;
        if header[0] != MSG_TYPE_RECORD {
            return Err(Error::protocol(format!(
                "controlbase: received message with unexpected type {}, want {}",
                header[0], MSG_TYPE_RECORD
            )));
        }
        let len = u16::from_be_bytes([header[1], header[2]]) as usize;
        if HEADER_LEN + len > MAX_MESSAGE_SIZE {
            return Err(Error::protocol(format!(
                "controlbase: requested read of {} bytes exceeds max allowed Noise frame size",
                len
            )));
        }
        let mut frame = vec![0u8; len];
        self.stream
            .read_exact(&mut frame)
            .await
            .map_err(|e| Error::network(format!("controlbase: read: {e}")))?;

        let state = &mut self.rx;
        let cipher = match state.cipher.as_ref() {
            Some(c) => c,
            None => {
                return Err(Error::protocol(
                    "controlbase: connection closed after decrypt failure",
                ))
            }
        };
        if state.counter == u64::MAX {
            return Err(Error::protocol(
                "controlbase: cipher exhausted, no more nonces available",
            ));
        }
        let pt = cipher
            .decrypt(
                (&state.nonce()).into(),
                Payload {
                    msg: &frame,
                    aad: &[],
                },
            )
            .map_err(|_| {
                // Nuke the cipher state so no further decryption is
                // attempted (conn.go:149-155).
                state.cipher = None;
                Error::crypto("controlbase: AEAD open failed")
            })?;
        state.counter += 1;
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn blake2s_and_hmac_match_the_verified_vectors() {
        // The same implementation as proto/wireguard.rs (its
        // blake2s_known_vectors / hmac_blake2s_known_vectors, cross-
        // checked against Python hashlib): the canonical RFC 7693
        // digests anchor the hash the whole handshake chains on.
        assert_eq!(
            hex(&blake2s256(b"")),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        );
        assert_eq!(
            hex(&blake2s256(b"abc")),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
        assert_eq!(
            hex(&blake2s256(&(0..=255u8).collect::<Vec<u8>>())),
            "5fdeb59f681d975f52c8e69c5502e02a12a3afcc5836ba58f42784c439228781"
        );
        // HMAC-BLAKE2s long-key path (key > 64 bytes gets hashed).
        let long = vec![0x66u8; 200];
        assert_eq!(
            hex(&hmac_blake2s(&long, b"x")),
            { let hashed = blake2s256(&long); hex(&hmac_blake2s(&hashed, b"x")) }
        );
    }

    #[test]
    fn hkdf_blake2s_follows_rfc5869() {
        // HKDF = extract(salt, ikm) then the T(i) expansion chain
        // (RFC 5869 §2); golang.org/x/crypto/hkdf with the blake2s
        // hash (handshake.go:376) is exactly this over HMAC-BLAKE2s.
        let salt = b"salt-bytes";
        let ikm = b"input-key-material";
        let prk = hkdf_extract(salt, ikm);
        assert_eq!(prk, hmac_blake2s(salt, ikm));
        let okm = hkdf_blake2s(ikm, salt, b"info", 64);
        let t1 = hmac_blake2s(&prk, &[b"info".as_slice(), &[1]].concat());
        let t2 = hmac_blake2s(&prk, &[t1.as_slice(), b"info".as_slice(), &[2]].concat());
        assert_eq!(okm[..32], t1);
        assert_eq!(okm[32..], t2);
        // 33 bytes spans three T blocks without panicking.
        assert_eq!(hkdf_blake2s(ikm, salt, &[], 33).len(), 33);
    }

    #[test]
    fn machine_keys_roundtrip_and_redact() {
        let key = MachinePrivateKey::generate();
        let hexs = key.to_hex();
        assert_eq!(hexs.len(), 64);
        assert_eq!(MachinePrivateKey::from_hex(&hexs).unwrap().to_hex(), hexs);
        assert!(MachinePrivateKey::from_hex("zz").is_err());
        assert_eq!(key.public(), key.public());
        // Debug never leaks the secret half.
        assert!(!format!("{key:?}").contains(&hexs));
        assert!(format!("{:?}", key.public()).contains(&key.public().to_hex()));
    }

    #[test]
    fn prologue_matches_the_go_bytes() {
        // handshake.go:46-50: prefix + decimal version.
        assert_eq!(
            protocol_version_prologue(148),
            b"Tailscale Control Protocol v148".to_vec()
        );
        assert_eq!(PROTOCOL_NAME, b"Noise_IK_25519_ChaChaPoly_BLAKE2s");
    }

    #[test]
    fn initiation_message_skeleton_matches_messages_go() {
        // messages.go:41-47: version BE, type 1, length 96.
        let init = mk_initiation_message(148);
        assert_eq!(init.len(), 101);
        assert_eq!(u16::from_be_bytes([init[0], init[1]]), 148);
        assert_eq!(init[2], MSG_TYPE_INITIATION);
        assert_eq!(u16::from_be_bytes([init[3], init[4]]), 96);
    }

    #[tokio::test]
    async fn noise_ik_handshake_and_records_over_duplex() {
        // The client half (handshake.go:68-101, 120-190) against the
        // server half (handshake.go:201-326) over an in-memory pipe —
        // upstream's interop tests do the same pairing
        // (controlbase/interop_test.go).
        let control_key = MachinePrivateKey::generate();
        let machine_key = MachinePrivateKey::generate();
        let machine_pub = machine_key.public();
        let control_pub = control_key.public();
        let (client_stream, server_stream) = tokio::io::duplex(8192);

        let server = tokio::spawn(async move {
            let mut conn = server_handshake(server_stream, &control_key, None)
                .await
                .expect("server handshake");
            // The server sees the machine key the client authenticated
            // (handshake.go:276-280).
            assert_eq!(*conn.peer(), machine_pub);
            // Echo one small record back (Write/Read, conn.go:241-321).
            let got = conn.recv().await.expect("server recv small");
            conn.send(&got).await.expect("server send small");
            // Then relay a two-record payload: a >maxPlaintextSize
            // client Write chunks into 4077+100 (conn.go:300-305).
            let r1 = conn.recv().await.expect("server recv r1");
            assert_eq!(r1.len(), MAX_PLAINTEXT_SIZE);
            let r2 = conn.recv().await.expect("server recv r2");
            conn.send(&r1).await.expect("server send r1");
            conn.send(&r2).await.expect("server send r2");
            [r1, r2].concat()
        });

        let mut client = client_handshake(
            client_stream,
            &machine_key,
            &control_pub,
            148,
        )
        .await
        .expect("client handshake");
        assert_eq!(client.protocol_version(), 148);
        assert_eq!(*client.peer(), control_pub);
        let hh = client.handshake_hash();

        client.send(b"single record").await.expect("client send");
        assert_eq!(client.recv().await.unwrap(), b"single record");

        let mut big = vec![7u8; MAX_PLAINTEXT_SIZE + 100];
        big[0] = 0x42;
        client.send(&big).await.expect("client send big");
        let r1 = client.recv().await.expect("client recv r1");
        let r2 = client.recv().await.expect("client recv r2");
        assert_eq!(r1.len(), MAX_PLAINTEXT_SIZE);
        assert_eq!([r1, r2].concat(), big);

        // Handshake hash is stable and binding (conn.go:80-82).
        assert_eq!(client.handshake_hash(), hh);

        let server_got = server.await.expect("server task");
        assert_eq!(server_got, big);
    }

    #[tokio::test]
    async fn wrong_control_key_fails_the_handshake() {
        // Noise IK: the initiation is encrypted to the server's static
        // key; a server without it cannot proceed and simply drops the
        // connection (handshake.go:277-279 returns without a sendErr),
        // so the client sees EOF — the wire-level failure upstream
        // controlclient retries on.
        let control_key = MachinePrivateKey::generate();
        let other_key = MachinePrivateKey::generate();
        let machine_key = MachinePrivateKey::generate();
        let (client_stream, server_stream) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let res = server_handshake(server_stream, &other_key, None).await;
            assert!(res.is_err(), "server cannot decrypt the initiation");
        });

        let err = client_handshake(
            client_stream,
            &machine_key,
            &control_key.public(),
            148,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("reading response header"),
            "the client sees the dropped connection: {err}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn structural_handshake_errors_surface_as_error_frames() {
        // sendErr (handshake.go:213-227): bad initiation SIZE gets a
        // cleartext msgTypeError frame the client surfaces.
        let control_key = MachinePrivateKey::generate();
        let machine_key = MachinePrivateKey::generate();
        let control_pub = control_key.public();
        let (client_stream, server_stream) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let res = server_handshake(server_stream, &control_key, Some(vec![0u8; 10])).await;
            assert!(res.is_err());
        });

        // Run the client half manually: write a valid initiation, then
        // read what comes back (the error frame).
        let (init, _) = client_deferred(&machine_key, &control_pub, 148).unwrap();
        let mut client_stream = client_stream;
        use tokio::io::AsyncWriteExt;
        client_stream.write_all(&init).await.unwrap();

        let mut header = [0u8; HEADER_LEN];
        use tokio::io::AsyncReadExt;
        client_stream.read_exact(&mut header).await.unwrap();
        assert_eq!(frame_type(&header), MSG_TYPE_ERROR);
        let len = frame_length(&header);
        let mut msg = vec![0u8; len];
        client_stream.read_exact(&mut msg).await.unwrap();
        assert_eq!(msg, b"wrong handshake initiation size");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn corrupted_record_kills_the_connection() {
        // conn.go:149-155: a failed decryption nukes the rx cipher;
        // further reads are refused (conn.go:246-248) before any wire
        // read. The client half runs in a task so the inline server
        // handshake can read the initiation concurrently.
        let control_key = MachinePrivateKey::generate();
        let machine_key = MachinePrivateKey::generate();
        let control_pub = control_key.public();
        let (client_stream, mut server_stream) = tokio::io::duplex(4096);

        let client = tokio::spawn(async move {
            let mut c =
                client_handshake(client_stream, &machine_key, &control_pub, 148)
                    .await
                    .unwrap();
            c.send(b"first").await.unwrap();
            let got = c.recv().await.unwrap();
            (c, got)
        });

        let mut server = server_handshake(&mut server_stream, &control_key, None)
            .await
            .unwrap();
        assert_eq!(server.recv().await.unwrap(), b"first");
        server.send(b"ok-record").await.unwrap();
        drop(server);
        // Forge a type-4 frame with garbage ciphertext straight onto
        // the wire — the borrow on server_stream is released.
        use tokio::io::AsyncWriteExt;
        server_stream
            .write_all(&[MSG_TYPE_RECORD, 0, 5, 1, 2, 3, 4, 5])
            .await
            .unwrap();

        let (mut client, got) = client.await.unwrap();
        assert_eq!(got, b"ok-record");
        assert!(client.recv().await.is_err(), "tampered frame must fail");
        assert!(client.recv().await.is_err(), "connection stays dead");
    }

    #[test]
    fn max_frame_constants_match_conn_go() {
        // conn.go:28-35: 4096 total, 3 header, 16 AEAD overhead.
        assert_eq!(MAX_MESSAGE_SIZE, 4096);
        assert_eq!(MAX_CIPHERTEXT_SIZE, 4093);
        assert_eq!(MAX_PLAINTEXT_SIZE, 4077);
        assert_eq!(INITIATION_LEN, 101);
        assert_eq!(RESPONSE_LEN, 51);
        assert_eq!(CURRENT_PROTOCOL_VERSION, 148);
    }
}
