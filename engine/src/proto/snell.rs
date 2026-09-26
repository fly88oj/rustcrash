//! Snell v1..v4 outbound, ported from mihomo's `transport/snell`
//! (`snell.go`, `cipher.go`, `v4.go`, `pool.go`, plus
//! `adapter/outbound/snell.go` for the version/pool wiring) and the
//! Shadowsocks-AEAD framing v1..v3 reuse
//! (`transport/shadowsocks/shadowaead/stream.go`).
//!
//! Wire behaviour as the snell server sees it:
//!
//! * **v1/v2/v3** are the Shadowsocks AEAD stream with a snell-specific
//!   KDF: a random 16-byte salt prefixes each direction, subkey =
//!   `argon2id(psk, salt, t=3, m=8KiB, p=1, len=32)[:keySize]`
//!   (cipher.go `snellKDF`), then `[enc(len be16)][enc(chunk)]` frames
//!   with a little-endian counter nonce per direction. The only v1..v3
//!   delta is the cipher: v1 is Chacha20-Poly1305 (32-byte key), v2/v3
//!   are AES-128-GCM (16-byte key) — `StreamConn` (snell.go:156-168)
//!   routes `NewChacha20Poly1305` for Version1 and `NewAES128GCM`
//!   otherwise, and cipher.go:42-56 fixes the key sizes.
//! * **v4** (v4.go) drops the SS framing for its own: the first frame
//!   carries a random 16-byte salt, then per frame a sealed 7-byte header
//!   (`ver=4`, `be16 padding len`, `be16 payload len`), optional padding
//!   bytes (only on the very first frame, length `0x100 + rand(0x100)`)
//!   every-other-byte swapped with the sealed payload, then the sealed
//!   payload; the payload chunk size ramps from ~MTU to 0x3FFF
//!   (`nextPayloadLimit`).
//! * The request header (`WriteHeaderWithReuse`): `0x01 || cmd || 0x00 ||
//!   hostlen || host || port_be16` with cmd `0x01` (`CommandConnect`) or
//!   `0x05` (`CommandConnectV2`) when the version is 2 or the caller asked
//!   for a reusable pool conn (snell.go:103-126). UDP opens with
//!   `0x01 0x06 0x00` instead (v3+ only; v4 then also waits for the reply).
//! * The server's first decrypted byte is the reply: `0x00` tunnel,
//!   `0x02` error (`code u8 || msglen u8 || msg`), anything else
//!   "command not support" (snell.go `ReadReply`).
//!
//! ## In-module Argon2id
//!
//! Snell's KDF is Argon2id (RFC 9106) with tiny parameters — not HKDF —
//! and the crate carries no argon2 dependency, so a minimal RFC 9106
//! implementation (plus the BLAKE2b core it needs) lives in [`argon2id`],
//! validated against the RFC test vectors. It is pure Rust: no C, keeping
//! the musl-static shipping promise.
//!
//! ## Deferred (out of scope here)
//!
//! * **UDP relay**: one TCP transport carries every datagram
//!   (adapter/outbound/snell.go `ListenPacketContext` →
//!   `snell.PacketConn(c)`). The session opens with
//!   `handshake(_, _, _, true)` (v4 additionally awaits the tunnel reply
//!   there, adapter/outbound/snell.go:88-95); each datagram then rides its
//!   own AEAD frame — [`SnellStream::read_packet`] returns exactly one
//!   decrypted frame per call (snell.go `ReadPacket` does one `Read`, and
//!   one `Read` = one frame), and v4 writes each datagram as a single
//!   frame via the `WritePacketFrame` path (v4.go:81-96) instead of the
//!   stream chunk ramp. [`udp_session`] / [`SnellUdp`] wrap that into a
//!   `send_to`/`recv_from` channel shaped like `anytls::AnyTlsUdp`.
//! * **obfs plugins** (`obfs-opts`: http/tls/shadow-tls/restls/jls):
//!   `handshake` takes the post-dial stream, so the integrator wraps
//!   before calling, exactly like mihomo's `streamConnContext`. The
//!   [`SnellPool`] accepts an injected transport dialer for the same
//!   reason.
//! * **v2 SYNACK liveness watchdog**: not sent by the snell wire (that is
//!   an anytls concern); snell reuse is driven purely by the zero-chunk
//!   half-close (pool.go `writeZeroChunk` / `HalfClose`).

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Instant;

use bytes::{Buf, BytesMut};
use rand::Rng;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::addr::{Host, NetAddr};
use crate::error::{Error, Result};
use tracing::debug;
use crate::proto::aead::{Aead, AeadKind, SsNonce};
use crate::stream::BoxProxyStream;

/// `Version` byte that prefixes every snell request (snell.go:40,106).
const PROTOCOL_VERSION: u8 = 0x01;
/// `CommandConnect` (snell.go:31) — plain TCP request.
const CMD_CONNECT: u8 = 0x01;
/// `CommandConnectV2` (snell.go:32) — sent when version is 2 or the conn
/// is a pooled reuse (`WriteHeaderWithReuse`, snell.go:107-111).
const CMD_CONNECT_V2: u8 = 0x05;
/// `CommandUDP` (snell.go:33) — UDP session open (v3+).
const CMD_UDP: u8 = 0x06;
/// `CommandTunnel` (snell.go:36) — the successful reply byte.
const CMD_TUNNEL: u8 = 0x00;
/// `CommandError` (snell.go:38).
const CMD_ERROR: u8 = 0x02;
/// `CommondUDPForward` (snell.go:34) — snell UDP packet prefix.
const CMD_UDP_FORWARD: u8 = 0x01;

/// `maxLength` (snell.go:26): largest snell payload / v3 chunk.
pub const MAX_LENGTH: usize = 0x3FFF;
/// `DefaultSnellVersion` (snell.go:23) — v1, the backward-compatible
/// default when the config omits `version`.
pub const DEFAULT_SNELL_VERSION: u8 = 1;
/// v3 chunk cap, `payloadSizeMask` (shadowaead/stream.go:15).
const V3_CHUNK: usize = MAX_LENGTH;
/// AEAD tag size (AES-128-GCM overhead).
const TAG_SIZE: usize = 16;
/// v4 constants (v4.go:19-27).
const V4_SALT_SIZE: usize = 16;
const V4_HEADER_PLAIN: usize = 7;
const V4_HEADER_CIPHER: usize = V4_HEADER_PLAIN + TAG_SIZE;
const V4_FRAME_SIZE: i32 = 1460;
const V4_INITIAL_PADDING_MIN: u16 = 0x100;
const V4_INITIAL_PADDING_SPAN: u16 = 0x100;
/// Idle gap after which the v4 chunk ramp resets (v4.go:296).
const V4_IDLE_RESET: std::time::Duration = std::time::Duration::from_secs(30);

/// Client-side security fronting (adapter/outbound/snell.go:183-240):
/// `obfs-mode: shadow-tls | res-tls | jls` stacks a cover protocol
/// under the snell wire, exactly like the server side composes them.
#[derive(Debug, Clone)]
pub enum SnellFronting {
    /// `obfs-mode: shadow-tls` + `obfs-opts: {password, host}`.
    ShadowTls { password: String, host: String },
    /// `obfs-mode: res-tls` + the restls client options.
    ResTls(crate::proto::restls::RestlsOut),
    /// `obfs-mode: jls` + `obfs-opts: {host, username, password, alpn}`.
    Jls(crate::proto::jls::JlsOut),
}

/// Dial + fronting handshake: the client stack's `streamConnContext`
/// (outbound snell.go:44-67).
pub async fn fronting_connect(front: &SnellFronting, server: &str, port: u16) -> Result<BoxProxyStream> {
    let tcp = dial_tcp_transport(server, port).await?;
    match front {
        SnellFronting::ShadowTls { password, host } => {
            let cfg = crate::proto::shadowtls::ShadowTlsOut {
                server: server.to_string(),
                port,
                password: password.clone(),
                sni: host.clone(),
                skip_verify: true,
            };
            crate::proto::shadowtls::connect(&cfg, tcp).await
        }
        SnellFronting::ResTls(cfg) => crate::proto::restls::connect(cfg, tcp).await,
        SnellFronting::Jls(cfg) => crate::proto::jls::connect(cfg, tcp).await,
    }
}

/// Outbound Snell endpoint (mihomo `proxies: type: snell`).
#[derive(Debug, Clone)]
pub struct SnellOut {
    pub server: String,
    pub port: u16,
    /// `obfs-mode: shadow-tls|res-tls|jls` client fronting (None =
    /// plain / http-obfs as before).
    pub fronting: Option<SnellFronting>,
    /// Pre-shared key (`psk`).
    pub psk: String,
    /// Protocol version. Raw config accepts `0..=5` — [`parse_version`]
    /// applies mihomo's defaults/mapping and returns the wire version
    /// (`1..=4`).
    pub version: u8,
    /// Whether the outbound advertises UDP support.
    pub udp: bool,
}

/// Normalise a configured snell version exactly like `NewSnell`
/// (adapter/outbound/snell.go:244-261):
///
/// * `0` → [`DEFAULT_SNELL_VERSION`] (`1`) — the backward-compatible
///   default;
/// * `5` → `4` — "Snell v5 servers are backward-compatible with v4
///   clients", so v5 is v4 framing verbatim (`StreamConn` routes every
///   `version >= Version4` to `newV4Conn`, snell.go:157-158);
/// * `1..=4` pass through; anything else is
///   `snell version error: {v}` (adapter snell.go:260).
pub fn parse_version(raw: u8) -> Result<u8> {
    match raw {
        0 => Ok(DEFAULT_SNELL_VERSION),
        5 => Ok(4),
        1..=4 => Ok(raw),
        other => Err(Error::config(format!(
            "snell version error: {other}"
        ))),
    }
}

/// Validate the `udp` flag against the version like `NewSnell`
/// (adapter/outbound/snell.go:253-257): v1/v2 never support UDP.
pub fn validate_udp(version: u8, udp: bool) -> Result<()> {
    if udp && version < 3 {
        return Err(Error::config(format!(
            "snell version {version} not support UDP"
        )));
    }
    Ok(())
}

/// The TCP request header, `WriteHeaderWithReuse` (snell.go:103-126):
/// `version=1, cmd, clientID len=0, host len u8, host, port be16` with
/// cmd `CommandConnectV2` when `version == Version2 || reuse`
/// (snell.go:107-111), else `CommandConnect`. The host is
/// `metadata.String()` — the domain or IP text.
fn request_header(target: &NetAddr, version: u8, reuse: bool) -> Result<Vec<u8>> {
    let host = target.host.to_text();
    let bytes = host.as_bytes();
    if bytes.len() > 255 {
        return Err(Error::protocol(format!(
            "snell: target host exceeds 255 bytes: {host}"
        )));
    }
    let cmd = if version == 2 || reuse {
        CMD_CONNECT_V2
    } else {
        CMD_CONNECT
    };
    let mut buf = Vec::with_capacity(4 + bytes.len());
    buf.push(PROTOCOL_VERSION);
    buf.push(cmd);
    buf.push(0x00); // clientID length (snell.go:114)
    buf.push(bytes.len() as u8);
    buf.extend_from_slice(bytes);
    buf.extend_from_slice(&target.port.to_be_bytes());
    Ok(buf)
}

/// The UDP session header, `WriteUDPHeader` (snell.go:128-136):
/// `version=1, CommandUDP, clientID len=0`. No target travels here —
/// each packet carries its own ([`snell_udp_frame`]).
fn udp_header() -> [u8; 3] {
    [PROTOCOL_VERSION, CMD_UDP, 0x00]
}

// ---------------------------------------------------------------------------
// Argon2id (RFC 9106) — snell's KDF primitive
// ---------------------------------------------------------------------------

mod argon2id {
    //! Minimal Argon2id + BLAKE2b, ported from RFC 9106 (mirrors the
    //! structure of golang.org/x/crypto/argon2, which mihomo links).
    //! Snell only ever calls this with `t=3, m=8 (KiB), p=1, out=32`, but
    //! the full parameter space is implemented so the RFC 9106 test
    //! vector (p=4, secret+AD) validates it end to end.
    #![allow(clippy::too_many_arguments)]

    const BLOCK_WORDS: usize = 128; // one 1024-byte block
    const SYNC_POINTS: u32 = 4;
    const VERSION: u32 = 0x13;
    const ARGON2_ID: u64 = 2;

    type Block = [u64; BLOCK_WORDS];

    /// BLAKE2b IV (= SHA-512 IV, RFC 7693 section 2.5).
    const IV: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    /// BLAKE2b round constants (RFC 7693 section 2.7 sigma).
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

    /// Single-shot unkeyed BLAKE2b with a caller-chosen digest length
    /// (1..=64). Used for H0 and inside the H' variable-length hash.
    pub(super) fn blake2b(out_len: usize, input: &[u8]) -> Vec<u8> {
        debug_assert!((1..=64).contains(&out_len));
        let mut h = IV;
        // Parameter block: fanout=depth=1, no key, digest length (RFC 7693).
        h[0] ^= 0x0101_0000 | out_len as u64;

        let mut t: u64 = 0; // bytes compressed so far
        let mut rest = input;
        let mut block = [0u8; 128];
        // All complete blocks except the final one; the final block
        // (possibly partial, always zero-padded — a lone all-zero block
        // for the empty message) closes the hash.
        while rest.len() > 128 {
            block.copy_from_slice(&rest[..128]);
            t += 128;
            blake2b_compress(&mut h, &block, t, false);
            rest = &rest[128..];
        }
        let n = rest.len();
        block = [0u8; 128];
        block[..n].copy_from_slice(rest);
        t += n as u64;
        blake2b_compress(&mut h, &block, t, true);

        let mut out = Vec::with_capacity(out_len);
        for word in h {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.truncate(out_len);
        out
    }

    fn blake2b_compress(h: &mut [u64; 8], block: &[u8; 128], t: u64, last: bool) {
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= t;
        if last {
            v[14] = !v[14];
        }
        let mut m = [0u64; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[i * 8..i * 8 + 8]);
            *word = u64::from_le_bytes(b);
        }
        for round in 0..12 {
            let s = &SIGMA[round % 10];
            // column step
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            // diagonal step
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    /// BLAKE2b mixing function G (rotations 32/24/16/63, RFC 7693).
    #[inline(always)]
    fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    }

    /// Argon2 variable-length hash H' (RFC 9106 section 3.3; identical to
    /// Go's `blake2bHash`): 32-byte steps, final digest resized.
    fn h_prime(out: &mut [u8], input: &[u8]) {
        let out_len = out.len();
        let mut prefixed = Vec::with_capacity(4 + input.len());
        prefixed.extend_from_slice(&(out_len as u32).to_le_bytes());
        prefixed.extend_from_slice(input);
        if out_len < 64 {
            out.copy_from_slice(&blake2b(out_len, &prefixed));
            return;
        }
        if out_len == 64 {
            out.copy_from_slice(&blake2b(64, &prefixed));
            return;
        }
        let mut buffer = blake2b(64, &prefixed); // V_1
        out[..32].copy_from_slice(&buffer[..32]);
        let mut rest = &mut out[32..];
        while rest.len() > 64 {
            buffer = blake2b(64, &buffer);
            rest[..32].copy_from_slice(&buffer[..32]);
            rest = &mut rest[32..];
        }
        let r = out_len.div_ceil(32) - 2;
        let last_len = if out_len.is_multiple_of(64) { 64 } else { out_len - 32 * r };
        let tail = blake2b(last_len, &buffer);
        rest.copy_from_slice(&tail);
    }

    /// GB mixing (RFC 9106 section 3.6): BLAKE2b's G plus the 32x32-bit
    /// multiplications that make it "blamka". All arithmetic wraps, as in
    /// Go's uint64 code.
    #[inline(always)]
    fn gb(v: &mut [u64], a: usize, b: usize, c: usize, d: usize) {
        let trunc = |x: u64| x & 0xFFFF_FFFF;
        let mul = |x: u64, y: u64| 2u64.wrapping_mul(x).wrapping_mul(y);
        let (va, vb, vc, vd) = (v[a], v[b], v[c], v[d]);
        let va = va.wrapping_add(vb).wrapping_add(mul(trunc(va), trunc(vb)));
        let vd = (vd ^ va).rotate_right(32);
        let vc = vc.wrapping_add(vd).wrapping_add(mul(trunc(vc), trunc(vd)));
        let vb = (vb ^ vc).rotate_right(24);
        let va = va.wrapping_add(vb).wrapping_add(mul(trunc(va), trunc(vb)));
        let vd = (vd ^ va).rotate_right(16);
        let vc = vc.wrapping_add(vd).wrapping_add(mul(trunc(vc), trunc(vd)));
        let vb = (vb ^ vc).rotate_right(63);
        v[a] = va;
        v[b] = vb;
        v[c] = vc;
        v[d] = vd;
    }

    /// Permutation P over one row of eight 16-byte registers (RFC 9106
    /// Figure 18).
    #[inline(always)]
    fn blamka(t: &mut [u64]) {
        debug_assert_eq!(t.len(), 16);
        gb(t, 0, 4, 8, 12);
        gb(t, 1, 5, 9, 13);
        gb(t, 2, 6, 10, 14);
        gb(t, 3, 7, 11, 15);
        gb(t, 0, 5, 10, 15);
        gb(t, 1, 6, 11, 12);
        gb(t, 2, 7, 8, 13);
        gb(t, 3, 4, 9, 14);
    }

    /// Compression G(X, Y): rows, then columns, then xor the input
    /// (RFC 9106 section 3.5 / Go `processBlockGeneric`). `xor` folds the
    /// result into `out` (Go's `processBlockXOR`, used for every segment
    /// block — pass-0 blocks start zeroed, so the two coincide).
    fn process_block(out: &mut Block, in1: &Block, in2: &Block, xor: bool) {
        let mut t = [0u64; BLOCK_WORDS];
        for i in 0..BLOCK_WORDS {
            t[i] = in1[i] ^ in2[i];
        }
        // Rows.
        let mut row = [0u64; 16];
        let mut i = 0;
        while i < BLOCK_WORDS {
            row.copy_from_slice(&t[i..i + 16]);
            blamka(&mut row);
            t[i..i + 16].copy_from_slice(&row);
            i += 16;
        }
        // Columns (Go: t[i], t[i+1], t[16+i], t[16+i+1], ...).
        let mut col = [0u64; 16];
        let mut j = 0;
        while j < 16 {
            for k in 0..8 {
                col[2 * k] = t[j + 16 * k];
                col[2 * k + 1] = t[j + 16 * k + 1];
            }
            blamka(&mut col);
            for k in 0..8 {
                t[j + 16 * k] = col[2 * k];
                t[j + 16 * k + 1] = col[2 * k + 1];
            }
            j += 2;
        }
        for i in 0..BLOCK_WORDS {
            let v = in1[i] ^ in2[i] ^ t[i];
            out[i] = if xor { out[i] ^ v } else { v };
        }
    }

    /// `phi` / `indexAlpha` (RFC 9106 Figures 12-13 / Go argon2.go:262-288):
    /// nonuniform pick from the reference window.
    #[allow(clippy::too_many_arguments)]
    fn index_alpha(
        rand: u64,
        lanes: u32,
        segments: u32,
        threads: u32,
        n: u32,
        slice: u32,
        lane: u32,
        index: u32,
    ) -> usize {
        let mut ref_lane = ((rand >> 32) as u32) % threads;
        if n == 0 && slice == 0 {
            ref_lane = lane;
        }
        let mut m: u64 = u64::from(3 * segments);
        let mut s: u64 = u64::from(((slice + 1) % SYNC_POINTS) * segments);
        if lane == ref_lane {
            m += u64::from(index);
        }
        if n == 0 {
            m = u64::from(slice * segments);
            s = 0;
            if slice == 0 || lane == ref_lane {
                m += u64::from(index);
            }
        }
        if index == 0 || lane == ref_lane {
            m -= 1; // m >= 1 by construction (segments >= 2, index >= 2 in slice 0 pass 0)
        }
        let mut p = rand & 0xFFFF_FFFF;
        p = p.wrapping_mul(p) >> 32;
        p = p.wrapping_mul(m) >> 32;
        (u64::from(ref_lane * lanes) + ((s + m - (p + 1)) % u64::from(lanes))) as usize
    }

    /// H_0 = blake2b512(LE32(p)||LE32(T)||LE32(m)||LE32(t)||LE32(v)||
    /// LE32(y)||LE32(len P)||P||LE32(len S)||S||LE32(len K)||K||
    /// LE32(len X)||X) — RFC 9106 Figure 1 (Go initHash). Note the RAW
    /// memory parameter is hashed here, before rounding to m'.
    pub(super) fn h0(
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        data: &[u8],
        time: u32,
        memory_kib: u32,
        threads: u32,
        out_len: usize,
    ) -> [u8; 64] {
        let mut h0_input = Vec::with_capacity(24 + password.len() + salt.len());
        h0_input.extend_from_slice(&threads.to_le_bytes());
        h0_input.extend_from_slice(&(out_len as u32).to_le_bytes());
        h0_input.extend_from_slice(&memory_kib.to_le_bytes());
        h0_input.extend_from_slice(&time.to_le_bytes());
        h0_input.extend_from_slice(&VERSION.to_le_bytes());
        h0_input.extend_from_slice(&(ARGON2_ID as u32).to_le_bytes());
        h0_input.extend_from_slice(&(password.len() as u32).to_le_bytes());
        h0_input.extend_from_slice(password);
        h0_input.extend_from_slice(&(salt.len() as u32).to_le_bytes());
        h0_input.extend_from_slice(salt);
        h0_input.extend_from_slice(&(secret.len() as u32).to_le_bytes());
        h0_input.extend_from_slice(secret);
        h0_input.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h0_input.extend_from_slice(data);
        let digest = blake2b(64, &h0_input);
        digest.try_into().expect("blake2b-512 is 64 bytes")
    }

    /// Argon2id (RFC 9106). `memory_kib` is the m parameter in KiB; the
    /// block count is m' = 4*p*floor(m/4p) (minimum 8p). Data-independent
    /// addressing covers the first half of the first pass (section 3.4.1.3).
    pub(super) fn hash(
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        data: &[u8],
        time: u32,
        memory_kib: u32,
        threads: u32,
        out_len: usize,
    ) -> Vec<u8> {
        assert!(time >= 1 && threads >= 1);

        let mut h0 = h0(password, salt, secret, data, time, memory_kib, threads, out_len).to_vec();
        h0.resize(72, 0); // + LE32(block) || LE32(lane) scratch

        let mut memory = memory_kib / (SYNC_POINTS * threads) * (SYNC_POINTS * threads);
        if memory < 2 * SYNC_POINTS * threads {
            memory = 2 * SYNC_POINTS * threads;
        }
        let lanes = memory / threads;
        let segments = lanes / SYNC_POINTS;

        // Initial blocks B[i][0], B[i][1] (RFC Figures 3-4 / Go initBlocks).
        let mut blocks: Vec<Block> = vec![[0u64; BLOCK_WORDS]; memory as usize];
        let mut block_bytes = [0u8; 1024];
        for lane in 0..threads {
            let base = lane * lanes;
            for j in 0..2u32 {
                h0[68..72].copy_from_slice(&lane.to_le_bytes());
                h0[64..68].copy_from_slice(&j.to_le_bytes());
                h_prime(&mut block_bytes, &h0);
                for (i, word) in blocks[(base + j) as usize].iter_mut().enumerate() {
                    *word = u64::from_le_bytes(block_bytes[i * 8..i * 8 + 8].try_into().unwrap());
                }
            }
        }

        let zero = [0u64; BLOCK_WORDS];
        for n in 0..time {
            for slice in 0..SYNC_POINTS {
                for lane in 0..threads {
                    process_segment(
                        &mut blocks, n, slice, lane, lanes, segments, threads, memory, time, &zero,
                    );
                }
            }
        }

        // Final block C = xor of the last column, tag = H'^T(C)
        // (RFC Figures 7-8 / Go extractKey).
        for lane in 0..threads - 1 {
            let src = (lane * lanes + lanes - 1) as usize;
            let dst = (memory - 1) as usize;
            // split borrow: src < dst by construction (lane < threads-1).
            let (left, right) = blocks.split_at_mut(dst);
            for (dst_word, src_word) in right[0].iter_mut().zip(left[src]) {
                *dst_word ^= src_word;
            }
        }
        let mut final_block = [0u8; 1024];
        for (i, word) in blocks[(memory - 1) as usize].iter().enumerate() {
            final_block[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        let mut out = vec![0u8; out_len];
        h_prime(&mut out, &final_block);
        out
    }

    /// One lane-segment of block production (Go argon2.go `processSegment`).
    #[allow(clippy::too_many_arguments)]
    fn process_segment(
        blocks: &mut [Block],
        n: u32,
        slice: u32,
        lane: u32,
        lanes: u32,
        segments: u32,
        threads: u32,
        memory: u32,
        time: u32,
        zero: &Block,
    ) {
        // Argon2id: data-independent addressing for pass 0, slices 0-1.
        let data_independent = n == 0 && slice < SYNC_POINTS / 2;
        let mut inbuf = [0u64; BLOCK_WORDS];
        if data_independent {
            // Z = LE64(r)||LE64(l)||LE64(sl)||LE64(m')||LE64(t)||LE64(y)
            // (RFC 9106 Figure 11).
            inbuf[0] = u64::from(n);
            inbuf[1] = u64::from(lane);
            inbuf[2] = u64::from(slice);
            inbuf[3] = u64::from(memory);
            inbuf[4] = u64::from(time);
            inbuf[5] = ARGON2_ID;
        }

        let mut addresses = [0u64; BLOCK_WORDS];
        let mut index = 0u32;
        if n == 0 && slice == 0 {
            index = 2; // B[i][0..2] are precomputed
            if data_independent {
                // addresses = G(G(in, 0), 0) — Go's
                // processBlock(&addresses,&in,&zero) then
                // processBlock(&addresses,&addresses,&zero).
                inbuf[6] += 1;
                process_block(&mut addresses, &inbuf, zero, false);
                let prev_addr = addresses;
                process_block(&mut addresses, &prev_addr, zero, false);
            }
        }

        let mut offset = lane * lanes + slice * segments + index;
        while index < segments {
            let prev = if index == 0 && slice == 0 {
                (offset + lanes - 1) as usize // last block of the lane
            } else {
                (offset - 1) as usize
            };
            let random = if data_independent {
                if index.is_multiple_of(BLOCK_WORDS as u32) {
                    inbuf[6] += 1;
                    process_block(&mut addresses, &inbuf, zero, false);
                    let prev_addr = addresses;
                    process_block(&mut addresses, &prev_addr, zero, false);
                }
                addresses[(index % BLOCK_WORDS as u32) as usize]
            } else {
                blocks[prev][0]
            };
            let new_offset = index_alpha(random, lanes, segments, threads, n, slice, lane, index);
            // Copy the inputs to satisfy the borrow checker (1 KiB each;
            // mihomo aliases them in place, values are identical).
            let in1 = blocks[prev];
            let in2 = blocks[new_offset];
            process_block(&mut blocks[offset as usize], &in1, &in2, true);
            index += 1;
            offset += 1;
        }
    }
}

/// snell's KDF (cipher.go:29-32):
/// `argon2.IDKey(psk, salt, 3, 8, 1, 32)[:keySize]` — Argon2id with
/// t=3, m=8 KiB, p=1, truncated to the cipher key size (cipher.go:29-32).
/// `keySize` is 32 for v1's Chacha20-Poly1305 and 16 for v2/v3's
/// AES-128-GCM / v4 (cipher.go:42-56).
fn snell_kdf(psk: &[u8], salt: &[u8], key_size: usize) -> Result<Vec<u8>> {
    let full = argon2id::hash(psk, salt, &[], &[], 3, 8, 1, 32);
    if full.len() < key_size {
        return Err(Error::crypto("snell: argon2 tag shorter than key"));
    }
    Ok(full[..key_size].to_vec())
}

/// `snellCipher.Encrypter/Decrypter` (cipher.go:21-27): one AEAD per
/// direction, keyed by the KDF output for the direction's salt.
fn snell_aead(kind: AeadKind, psk: &[u8], salt: &[u8]) -> Result<Aead> {
    let key_size = kind.key_len();
    Aead::new(kind, &snell_kdf(psk, salt, key_size)?)
}

/// The pre-v4 cipher suite (`StreamConn`, snell.go:160-167): v1 is
/// Chacha20-Poly1305 with a 32-byte key; v2/v3 are AES-128-GCM with a
/// 16-byte key. The salt is 16 bytes for both (cipher.go:20).
fn v3_cipher_kind(version: u8) -> AeadKind {
    if version == 1 {
        AeadKind::Chacha20Poly1305
    } else {
        AeadKind::Aes128Gcm
    }
}

// ---------------------------------------------------------------------------
// v3 framing (shadowaead/stream.go)
// ---------------------------------------------------------------------------

/// v1..v3 connection: SS-AEAD framing with the snell KDF (v1 rides
/// Chacha20-Poly1305, v2/v3 AES-128-GCM — `StreamConn`, snell.go:156-168).
///
/// Write (stream.go:252-266, 31-62): the first write emits a fresh random
/// 16-byte salt, then per chunk `seal(len be16)` (2+16 bytes) and
/// `seal(payload)`; the 12-byte nonce is a LE counter per direction
/// (stream.go:200-207). An **empty** write is the snell half-close: one
/// sealed `0x0000` length and nothing else ("compatible with snell",
/// stream.go:38-45).
/// Read (stream.go:219-237, 106-137): read the peer's salt once, then
/// `[open(2+16)][open(len+16)]` chunks; a zero-length chunk is the
/// half-close signal (ErrZeroChunk, stream.go:122-125) — a framing
/// boundary, not a terminal error: the next read continues with the next
/// chunk (stream.go:140-161), which is what makes conn reuse work.
struct V3Conn {
    inner: BoxProxyStream,
    psk: Vec<u8>,
    kind: AeadKind,
    writer: Option<V3Crypto>,
    reader: Option<V3Crypto>,
    /// Read stage — like Go's blocking ReadFull sequence, no AEAD open
    /// happens until the stage's bytes are fully buffered (a nonce is
    /// consumed only when its ciphertext is consumed).
    stage: V3Stage,
    rbuf: BytesMut,
    out: BytesMut,
    /// A zero chunk was decoded and is pending as the consumer's EOF
    /// (Go returns ErrZeroChunk once per boundary, non-terminal).
    pending_zero: bool,
}

#[derive(Debug, PartialEq)]
enum V3Stage {
    Len,
    Payload(usize),
}

struct V3Crypto {
    aead: Aead,
    nonce: SsNonce,
}

impl V3Conn {
    fn new(inner: BoxProxyStream, psk: &[u8], kind: AeadKind) -> Self {
        V3Conn {
            inner,
            psk: psk.to_vec(),
            kind,
            writer: None,
            reader: None,
            stage: V3Stage::Len,
            rbuf: BytesMut::with_capacity(16 * 1024),
            out: BytesMut::with_capacity(16 * 1024),
            pending_zero: false,
        }
    }

    /// Append the wire form of `payload` to `wbuf` (chunks of 0x3FFF,
    /// each `seal(len)` then `seal(chunk)`). An empty payload writes the
    /// zero chunk — the sealed `0x0000` length alone (stream.go:38-45).
    fn frame(&mut self, payload: &[u8], wbuf: &mut BytesMut) -> Result<()> {
        if self.writer.is_none() {
            let mut salt = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            wbuf.extend_from_slice(&salt);
            self.writer = Some(V3Crypto {
                aead: snell_aead(self.kind, &self.psk, &salt)?,
                nonce: SsNonce::new(),
            });
        }
        let w = self.writer.as_mut().expect("initialized above");
        let mut chunk_out = Vec::with_capacity(V3_CHUNK + TAG_SIZE + 2 + TAG_SIZE);
        if payload.is_empty() {
            // writeZeroChunk → Write([]) — one sealed 2-byte length.
            let len_be = 0u16.to_be_bytes();
            w.aead.seal(&w.nonce.advance(), b"", &len_be, &mut chunk_out)?;
            wbuf.extend_from_slice(&chunk_out);
            return Ok(());
        }
        for chunk in payload.chunks(V3_CHUNK) {
            chunk_out.clear();
            let len_be = (chunk.len() as u16).to_be_bytes();
            w.aead.seal(&w.nonce.advance(), b"", &len_be, &mut chunk_out)?;
            w.aead.seal(&w.nonce.advance(), b"", chunk, &mut chunk_out)?;
            wbuf.extend_from_slice(&chunk_out);
        }
        Ok(())
    }

    /// Try to decrypt one chunk into `out`; `Ok(true)` when a chunk
    /// landed, `Ok(false)` when more wire bytes are needed (or a zero
    /// chunk is already pending). The stage machine consumes bytes AND a
    /// nonce tick together, so an open never happens twice for the same
    /// ciphertext; stage transitions loop internally so no inner read is
    /// needed to advance. A decoded zero chunk sets [`Self::pending_zero`]
    /// and the stage returns to `Len` — the stream stays readable, like
    /// Go's non-terminal ErrZeroChunk.
    fn try_parse(&mut self) -> Result<bool> {
        if self.reader.is_none() {
            if self.rbuf.len() < 16 {
                return Ok(false);
            }
            let salt = self.rbuf[..16].to_vec();
            self.rbuf.advance(16);
            self.reader = Some(V3Crypto {
                aead: snell_aead(self.kind, &self.psk, &salt)?,
                nonce: SsNonce::new(),
            });
            self.stage = V3Stage::Len;
        }
        loop {
            match self.stage {
                V3Stage::Len => {
                    if self.rbuf.len() < 2 + TAG_SIZE {
                        return Ok(false);
                    }
                    let len_ct = self.rbuf[..2 + TAG_SIZE].to_vec();
                    let r = self.reader.as_mut().expect("initialized above");
                    let len_pt = r.aead.open(&r.nonce.advance(), b"", &len_ct)?;
                    let size = (((len_pt[0] as usize) << 8) | len_pt[1] as usize) & MAX_LENGTH;
                    if size == 0 {
                        // ErrZeroChunk (stream.go:122-125) — a boundary,
                        // not an error; buffered chunks still drain first.
                        self.rbuf.advance(2 + TAG_SIZE);
                        self.pending_zero = true;
                        self.stage = V3Stage::Len;
                        return Ok(false);
                    }
                    self.rbuf.advance(2 + TAG_SIZE);
                    self.stage = V3Stage::Payload(size);
                }
                V3Stage::Payload(size) => {
                    if self.rbuf.len() < size + TAG_SIZE {
                        return Ok(false);
                    }
                    let payload_ct = self.rbuf[..size + TAG_SIZE].to_vec();
                    self.rbuf.advance(size + TAG_SIZE);
                    let r = self.reader.as_mut().expect("initialized above");
                    let payload = r.aead.open(&r.nonce.advance(), b"", &payload_ct)?;
                    self.out.extend_from_slice(&payload);
                    self.stage = V3Stage::Len;
                    return Ok(true);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// v4 framing (v4.go)
// ---------------------------------------------------------------------------

/// v4 connection: sealed 7-byte frame headers, salt on the first frame,
/// initial padding ramp. See the module docs for the wire shape.
struct V4Conn {
    inner: BoxProxyStream,
    psk: Vec<u8>,
    writer: V4Writer,
    reader: Option<V4Crypto>,
    /// Read stage (see V3Stage for why opens are tied to consumption).
    stage: V4Stage,
    rbuf: BytesMut,
    out: BytesMut,
    /// A zero chunk was decoded and is pending as the consumer's EOF
    /// (v4.go:201-206 `ErrZeroChunk` — non-terminal, like v3).
    pending_zero: bool,
}

#[derive(Debug, PartialEq)]
enum V4Stage {
    Header,
    /// Padding and payload ciphertext lengths from a consumed header.
    Body { padding_len: usize, payload_len: usize },
}

struct V4Crypto {
    aead: Aead,
    nonce: SsNonce,
}

struct V4Writer {
    aead: Aead,
    nonce: SsNonce,
    salt: [u8; V4_SALT_SIZE],
    salt_sent: bool,
    /// `initialPaddingLength` = 0x100 + rand(0x100) (v4.go:259).
    initial_padding_length: u16,
    /// Ramp state for `nextPayloadLimit` (v4.go:290-313).
    payload_limit: u16,
    last_write: Option<Instant>,
}

impl V4Conn {
    fn new(inner: BoxProxyStream, psk: &[u8]) -> Result<Self> {
        let mut salt = [0u8; V4_SALT_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        // v4AEAD (v4.go:155-157): AES-128-GCM over the snell KDF.
        let aead = snell_aead(AeadKind::Aes128Gcm, psk, &salt)?;
        let padding_delta = rand::rngs::OsRng.gen_range(0..u64::from(V4_INITIAL_PADDING_SPAN)) as u16;
        Ok(V4Conn {
            inner,
            psk: psk.to_vec(),
            writer: V4Writer {
                aead,
                nonce: SsNonce::new(),
                salt,
                salt_sent: false,
                initial_padding_length: V4_INITIAL_PADDING_MIN + padding_delta,
                payload_limit: 0,
                last_write: None,
            },
            reader: None,
            stage: V4Stage::Header,
            rbuf: BytesMut::with_capacity(16 * 1024),
            out: BytesMut::with_capacity(16 * 1024),
            pending_zero: false,
        })
    }

    /// `nextPayloadLimit` (v4.go:290-313): ~MTU-shaped first chunk, reset
    /// after 30s idle, ramping by frame increments up to maxLength.
    fn next_payload_limit(&mut self) -> i32 {
        let w = &mut self.writer;
        let now = Instant::now();
        let limit: i32 = match w.last_write {
            None => V4_FRAME_SIZE - 55 - i32::from(w.initial_padding_length),
            Some(last) if now.duration_since(last) > V4_IDLE_RESET => V4_FRAME_SIZE - 39,
            Some(_) => i32::from(w.payload_limit),
        };
        w.last_write = Some(now);
        if limit < MAX_LENGTH as i32 {
            let mut next = limit + V4_FRAME_SIZE - 39;
            if next > MAX_LENGTH as i32 {
                next = MAX_LENGTH as i32;
            }
            w.payload_limit = next as u16;
        } else {
            w.payload_limit = MAX_LENGTH as u16;
        }
        limit
    }

    /// `nextFramePaddingLength` (v4.go:315-320): only the first frame
    /// (before the salt is out) carries the initial padding.
    fn next_frame_padding_length(&self, payload_len: usize) -> usize {
        if self.writer.salt_sent || payload_len == 0 {
            0
        } else {
            usize::from(self.writer.initial_padding_length)
        }
    }

    /// `writeFrame` (v4.go:322-366). Wire: `[salt] || header_ct ||
    /// padding || payload_ct` — the padding is generated from the sealed
    /// payload, then every-other-byte swapped with it.
    fn write_frame(&mut self, payload: &[u8], padding_len: usize, wbuf: &mut BytesMut) -> Result<()> {
        if payload.len() > MAX_LENGTH || padding_len > MAX_LENGTH {
            return Err(Error::protocol("snell v4: frame too large"));
        }
        if payload.is_empty() && padding_len != 0 {
            return Err(Error::protocol("snell v4: zero chunk with padding"));
        }
        let mut header = [0u8; V4_HEADER_PLAIN];
        header[0] = 4; // version tag (v4.go:331)
        header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let w = &mut self.writer;
        if !w.salt_sent {
            wbuf.extend_from_slice(&w.salt);
            w.salt_sent = true;
        }
        let mut frame_out = Vec::with_capacity(V4_HEADER_CIPHER + padding_len + payload.len() + TAG_SIZE);
        let header_nonce = w.nonce.advance();
        w.aead.seal(&header_nonce, b"", &header, &mut frame_out)?;
        let mut payload_ct = Vec::with_capacity(payload.len() + TAG_SIZE);
        if !payload.is_empty() {
            let payload_nonce = w.nonce.advance();
            w.aead.seal(&payload_nonce, b"", payload, &mut payload_ct)?;
        }
        if padding_len > 0 {
            let mut padding = make_v4_padding(&payload_ct, padding_len);
            swap_padding(&mut padding, &mut payload_ct);
            frame_out.extend_from_slice(&padding);
        }
        frame_out.extend_from_slice(&payload_ct);
        wbuf.extend_from_slice(&frame_out);
        Ok(())
    }

    /// `v4Writer.Write` (v4.go:263-288): chunk by the ramp limit and emit
    /// each frame. An empty payload writes a zero chunk (half-close).
    fn frame(&mut self, payload: &[u8], wbuf: &mut BytesMut) -> Result<()> {
        if payload.is_empty() {
            return self.write_frame(&[], 0, wbuf);
        }
        let mut written = 0usize;
        while written < payload.len() {
            let mut limit = self.next_payload_limit();
            if limit <= 0 || limit > MAX_LENGTH as i32 {
                limit = MAX_LENGTH as i32;
            }
            let end = (written + limit as usize).min(payload.len());
            let padding_len = self.next_frame_padding_length(end - written);
            self.write_frame(&payload[written..end], padding_len, wbuf)?;
            written = end;
        }
        Ok(())
    }

    /// `readFrame` (v4.go:184-227): open the 23-byte header, sanity-check,
    /// read padding+payload, un-swap, open the payload. Staged so a nonce
    /// tick always accompanies consuming its ciphertext; transitions loop
    /// internally.
    fn try_parse(&mut self) -> Result<bool> {
        if self.reader.is_none() {
            if self.rbuf.len() < V4_SALT_SIZE {
                return Ok(false);
            }
            let salt = self.rbuf[..V4_SALT_SIZE].to_vec();
            self.rbuf.advance(V4_SALT_SIZE);
            self.reader = Some(V4Crypto {
                aead: snell_aead(AeadKind::Aes128Gcm, &self.psk, &salt)?,
                nonce: SsNonce::new(),
            });
            self.stage = V4Stage::Header;
        }
        loop {
            match self.stage {
                V4Stage::Header => {
                    if self.rbuf.len() < V4_HEADER_CIPHER {
                        return Ok(false);
                    }
                    let header_ct = self.rbuf[..V4_HEADER_CIPHER].to_vec();
                    let r = self.reader.as_mut().expect("initialized above");
                    let header = r.aead.open(&r.nonce.advance(), b"", &header_ct)?;
                    if header.len() != V4_HEADER_PLAIN || header[0] != 4 {
                        return Err(Error::protocol("snell v4: invalid frame header"));
                    }
                    let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
                    let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
                    if payload_len == 0 {
                        if padding_len != 0 {
                            return Err(Error::protocol("snell v4: zero chunk with padding"));
                        }
                        // ErrZeroChunk (v4.go:201-206) — a boundary; the
                        // reader continues with the next frame on reuse.
                        self.rbuf.advance(V4_HEADER_CIPHER);
                        self.pending_zero = true;
                        self.stage = V4Stage::Header;
                        return Ok(false);
                    }
                    if payload_len > MAX_LENGTH || padding_len > MAX_LENGTH {
                        return Err(Error::protocol("snell v4: frame too large"));
                    }
                    self.rbuf.advance(V4_HEADER_CIPHER);
                    self.stage = V4Stage::Body { padding_len, payload_len };
                }
                V4Stage::Body { padding_len, payload_len } => {
                    let total = padding_len + payload_len + TAG_SIZE;
                    if self.rbuf.len() < total {
                        return Ok(false);
                    }
                    let mut frame = self.rbuf[..total].to_vec();
                    self.rbuf.advance(total);
                    if padding_len > 0 {
                        let (padding, payload_ct) = frame.split_at_mut(padding_len);
                        swap_padding(padding, payload_ct);
                    }
                    let r = self.reader.as_mut().expect("initialized above");
                    let payload = r.aead.open(&r.nonce.advance(), b"", &frame[padding_len..])?;
                    self.out.extend_from_slice(&payload);
                    self.stage = V4Stage::Header;
                    return Ok(true);
                }
            }
        }
    }
}

/// `swapPadding` (v4.go:368-376): swap every OTHER byte (stride 2)
/// between the padding and the payload ciphertext.
fn swap_padding(padding: &mut [u8], payload_ct: &mut [u8]) {
    let limit = padding.len().min(payload_ct.len());
    let mut i = 0;
    while i < limit {
        core::mem::swap(&mut padding[i], &mut payload_ct[i]);
        i += 2;
    }
}

/// `countV4PayloadOnes` (v4.go:412-419): popcount over the first
/// `len & !3` bytes only.
fn count_payload_ones(payload_ct: &[u8]) -> usize {
    payload_ct[..payload_ct.len() & !3]
        .iter()
        .map(|b| b.count_ones() as usize)
        .sum()
}

/// `makeV4Padding` (v4.go:378-410): balance the ones-density of the
/// frame (padding + ciphertext) toward a 0.4..1.7 ratio, else random.
fn make_v4_padding(payload_ct: &[u8], padding_len: usize) -> Vec<u8> {
    let payload_ones = count_payload_ones(payload_ct);
    let payload_zeros = 8 * payload_ct.len().saturating_sub(payload_ones);
    if payload_zeros == 0 {
        return random_padding(padding_len);
    }
    let ratio = payload_ones as f64 / payload_zeros as f64;
    if ratio <= 0.5 || ratio >= 1.6 {
        return random_padding(padding_len);
    }
    let target_ratio_base = if payload_zeros < payload_ones { 0.4 } else { 1.6 };
    let jitter = random_unit_float();
    let target_ratio = target_ratio_base + jitter / 10.0;
    let total_bits = 8.0 * (padding_len + payload_ct.len()) as f64;
    let target_ones = (total_bits * (target_ratio / (target_ratio + 1.0)) - payload_ones as f64) as i64;
    if target_ones < 0 || target_ones > 8 * padding_len as i64 {
        return random_padding(padding_len);
    }
    bit_count_padding(padding_len, target_ones as usize)
}

/// `makeV4RandomPadding` (v4.go:421-425).
fn random_padding(len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut p);
    p
}

/// `makeV4BitCountPadding` (v4.go:427-452): a Fisher-Yates-shuffled
/// bitset with exactly `one_bits` ones, packed LSB-first.
fn bit_count_padding(len: usize, one_bits: usize) -> Vec<u8> {
    let total_bits = 8 * len;
    let mut bitset = vec![0u8; total_bits];
    for b in bitset.iter_mut().take(one_bits) {
        *b = 1;
    }
    for i in (1..total_bits).rev() {
        let j = rand::rngs::OsRng.gen_range(0..=i);
        bitset.swap(i, j);
    }
    let mut padding = vec![0u8; len];
    for (i, bit) in bitset.into_iter().enumerate() {
        if bit == 1 {
            padding[i / 8] |= 1 << (i % 8);
        }
    }
    padding
}

/// `randomUnitFloat64` (v4.go:462-468): uniform n/2^53.
fn random_unit_float() -> f64 {
    let n = rand::rngs::OsRng.gen_range(0..(1u64 << 53));
    (n as f64) / 2f64.powi(53)
}

// ---------------------------------------------------------------------------
// The snell stream
// ---------------------------------------------------------------------------

/// Reply state machine over the server's first decrypted bytes
/// (snell.go:62-97 `ReadReply`).
#[derive(Debug)]
enum Reply {
    /// No reply byte seen yet.
    Pending,
    /// `CommandTunnel` seen — the tunnel is up.
    Tunnel,
    /// `CommandError` — accumulating `code u8 || msglen u8 || msg`.
    Error(Vec<u8>),
}

impl Reply {
    /// Feed one decrypted byte; Err when the reply condemns the session.
    fn feed(&mut self, byte: u8) -> Result<()> {
        match self {
            Reply::Pending => {
                if byte == CMD_TUNNEL {
                    *self = Reply::Tunnel;
                } else if byte == CMD_ERROR {
                    *self = Reply::Error(vec![byte]);
                } else {
                    return Err(Error::protocol("snell: command not support"));
                }
            }
            Reply::Error(buf) => {
                buf.push(byte);
                if buf.len() < 3 {
                    return Ok(());
                }
                let msg_len = buf[2] as usize;
                if buf.len() < 3 + msg_len {
                    return Ok(());
                }
                let code = buf[1];
                let msg = String::from_utf8_lossy(&buf[3..3 + msg_len]).into_owned();
                return Err(Error::protocol(format!(
                    "snell: server reported code: {code}, message: {msg}"
                )));
            }
            Reply::Tunnel => {}
        }
        Ok(())
    }

    fn resolved(&self) -> bool {
        matches!(self, Reply::Tunnel)
    }
}

enum Conn {
    V3(V3Conn),
    V4(V4Conn),
}

impl Conn {
    /// Move decrypted bytes into `sink`; true when any moved.
    fn drain_out(&mut self, sink: &mut ReadBuf<'_>) -> bool {
        let out = match self {
            Conn::V3(c) => &mut c.out,
            Conn::V4(c) => &mut c.out,
        };
        if out.is_empty() || sink.remaining() == 0 {
            return false;
        }
        let n = out.len().min(sink.remaining());
        sink.put_slice(&out[..n]);
        out.advance(n);
        true
    }

    /// Consume decrypted bytes into the reply machine while it wants
    /// more; everything after a Tunnel reply stays for the consumer.
    fn feed_reply(&mut self, reply: &mut Reply) -> Result<()> {
        let out = match self {
            Conn::V3(c) => &mut c.out,
            Conn::V4(c) => &mut c.out,
        };
        while !reply.resolved() {
            let Some(&byte) = out.first() else { break };
            reply.feed(byte)?;
            out.advance(1);
        }
        Ok(())
    }

    /// The peer sent a zero chunk (its half-close) — pool.go's
    /// `peerClosed` marker; distinct from a transport close.
    fn peer_half_closed(&self) -> bool {
        match self {
            Conn::V3(c) => c.pending_zero,
            Conn::V4(c) => c.pending_zero,
        }
    }

    /// Clear the pending zero chunk for a pooled reuse (the snell server
    /// loops to the next request header after its zero chunk —
    /// listener/snell/server.go:166-171).
    fn reset_zero(&mut self) {
        match self {
            Conn::V3(c) => c.pending_zero = false,
            Conn::V4(c) => c.pending_zero = false,
        }
    }

    /// Read + decrypt until at least one chunk lands in `out` (or the
    /// peer half-closes / the transport closes).
    /// `Ok(true)` = progress, `Ok(false)` = EOF.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            let parsed = match self {
                Conn::V3(c) => c.try_parse(),
                Conn::V4(c) => c.try_parse(),
            }
            .map_err(io_invalid)?;
            if parsed {
                return Poll::Ready(Ok(true));
            }
            let (half_closed, rbuf, inner) = match self {
                Conn::V3(c) => (c.pending_zero, &mut c.rbuf, &mut c.inner),
                Conn::V4(c) => (c.pending_zero, &mut c.rbuf, &mut c.inner),
            };
            if half_closed {
                return Poll::Ready(Ok(false));
            }
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut *inner).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                return Poll::Ready(Ok(false));
            }
            rbuf.extend_from_slice(rb.filled());
        }
    }

    fn inner_mut(&mut self) -> &mut BoxProxyStream {
        match self {
            Conn::V3(c) => &mut c.inner,
            Conn::V4(c) => &mut c.inner,
        }
    }
}

fn io_invalid(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// A client snell stream: v3 or v4 framing plus the one-shot reply byte.
pub struct SnellStream {
    conn: Conn,
    reply: Reply,
    wbuf: BytesMut,
    pending_plain: usize,
    failed: bool,
}

impl SnellStream {
    fn new(inner: BoxProxyStream, cfg: &SnellOut) -> Result<Self> {
        let psk = cfg.psk.as_bytes();
        // StreamConn (snell.go:156-168): >= v4 uses the v4 codec; v1 is
        // Chacha20-Poly1305; v2/v3 are AES-128-GCM over the SS framing.
        let conn = match cfg.version {
            1..=3 => Conn::V3(V3Conn::new(inner, psk, v3_cipher_kind(cfg.version))),
            4 => Conn::V4(V4Conn::new(inner, psk)?),
            other => {
                return Err(Error::config(format!(
                    "snell: unsupported version {other} (wire versions are 1..=4; \
                     parse_version maps v5 down to 4)"
                )))
            }
        };
        Ok(SnellStream {
            conn,
            reply: Reply::Pending,
            wbuf: BytesMut::new(),
            pending_plain: 0,
            failed: false,
        })
    }

    /// Frame `buf` into `wbuf` (both the v3 and v4 write paths).
    fn frame(&mut self, buf: &[u8]) -> Result<()> {
        match &mut self.conn {
            Conn::V3(c) => c.frame(buf, &mut self.wbuf),
            Conn::V4(c) => c.frame(buf, &mut self.wbuf),
        }
    }

    /// Drive reads until the server's reply resolves. Decrypted tunnel
    /// bytes that arrive alongside stay buffered in the conn for the
    /// first user read. mihomo reads the reply eagerly only for v4 UDP
    /// (adapter/outbound/snell.go:88-95).
    async fn wait_reply(&mut self) -> Result<()> {
        let confirmed =
            std::future::poll_fn(|cx| self.poll_reply(cx)).await.map_err(Error::from)?;
        if !confirmed {
            return Err(Error::network(
                "snell: connection closed before the server reply",
            ));
        }
        Ok(())
    }

    /// `Ok(true)` = tunnel confirmed, `Ok(false)` = closed before it.
    fn poll_reply(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<bool, io::Error>> {
        loop {
            if let Err(e) = self.conn.feed_reply(&mut self.reply) {
                return Poll::Ready(Err(io_invalid(e)));
            }
            if self.reply.resolved() {
                return Poll::Ready(Ok(true));
            }
            match self.conn.poll_fill(cx) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(false)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// Frame one datagram as exactly one AEAD frame (the UDP write path,
    /// snell.go `writePacket` → `WritePacketFrame`, v4.go:81-96): v4 seals
    /// the whole packet with `nextFramePaddingLength` and skips the stream
    /// chunk ramp; v3 uses the plain stream write (its payload is already
    /// capped at one chunk by [`snell_udp_frame`]).
    fn frame_packet(&mut self, packet: &[u8]) -> Result<()> {
        match &mut self.conn {
            Conn::V3(c) => c.frame(packet, &mut self.wbuf),
            Conn::V4(c) => {
                let padding = c.next_frame_padding_length(packet.len());
                c.write_frame(packet, padding, &mut self.wbuf)
            }
        }
    }

    /// Write one whole datagram frame and flush it to the transport.
    async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        if self.failed {
            return Err(Error::network("snell: stream failed"));
        }
        if !self.wbuf.is_empty() {
            return Err(Error::protocol(
                "snell: previous packet still in flight during UDP write",
            ));
        }
        self.frame_packet(packet)?;
        AsyncWriteExt::flush(self).await.map_err(Error::from)?;
        Ok(())
    }

    /// The peer sent its zero chunk (pool.go `peerClosed`).
    fn peer_half_closed(&self) -> bool {
        self.conn.peer_half_closed()
    }

    /// Prepare the conn for a pooled reuse: the next request must consume
    /// a fresh reply byte and the pending zero chunk is spent
    /// (`pc.Snell.reply = false` + put, pool.go:116-118).
    fn reset_for_reuse(&mut self) {
        self.reply = Reply::Pending;
        self.conn.reset_zero();
    }

    /// Read exactly one decrypted AEAD frame payload — the packet view of
    /// the session (snell.go `ReadPacket` performs a single `Read`, and
    /// one `Read` on the snell conn yields exactly one frame's payload;
    /// v4Reader.Read keeps its own leftover, v3 chunks one `Write` per
    /// frame). This is what preserves datagram edges: consecutive frames
    /// are never merged. The server reply is consumed here if it has not
    /// been yet (v3 UDP; `packetConn.ReadFrom` → `Snell.Read` →
    /// `ReadReply`).
    pub async fn read_packet(&mut self) -> Result<Vec<u8>> {
        let packet = std::future::poll_fn(|cx| {
            loop {
                if self.failed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "snell: stream failed",
                    )));
                }
                if let Err(e) = self.conn.feed_reply(&mut self.reply) {
                    self.failed = true;
                    return Poll::Ready(Err(io_invalid(e)));
                }
                if self.reply.resolved() {
                    let out = match &mut self.conn {
                        Conn::V3(c) => &mut c.out,
                        Conn::V4(c) => &mut c.out,
                    };
                    if !out.is_empty() {
                        // Bytes left after the reply are the first packet.
                        let packet = out.to_vec();
                        out.clear();
                        return Poll::Ready(Ok(packet));
                    }
                }
                match self.conn.poll_fill(cx) {
                    Poll::Ready(Ok(true)) => continue, // a chunk landed; loop
                    Poll::Ready(Ok(false)) => {
                        self.failed = true;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "snell: session closed before a packet arrived",
                        )));
                    }
                    Poll::Ready(Err(e)) => {
                        self.failed = true;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await
        .map_err(Error::from)?;
        Ok(packet)
    }
}

impl AsyncWrite for SnellStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "snell: stream failed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.wbuf.is_empty() {
            this.frame(buf).map_err(|e| {
                this.failed = true;
                io_invalid(e)
            })?;
            this.pending_plain = buf.len();
        }
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(this.conn.inner_mut()).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                this.failed = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "snell: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Poll::Ready(Ok(this.pending_plain))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(this.conn.inner_mut()).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                this.failed = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "snell: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Pin::new(this.conn.inner_mut()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(self.get_mut().conn.inner_mut()).poll_shutdown(cx)
    }
}

impl AsyncRead for SnellStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if let Err(e) = this.conn.feed_reply(&mut this.reply) {
                this.failed = true;
                return Poll::Ready(Err(io_invalid(e)));
            }
            if this.reply.resolved() && this.conn.drain_out(buf) {
                return Poll::Ready(Ok(()));
            }
            match this.conn.poll_fill(cx) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => {
                    if this.reply.resolved() {
                        return Poll::Ready(Ok(())); // clean EOF
                    }
                    this.failed = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "snell: connection closed before the reply",
                    )));
                }
                Poll::Ready(Err(e)) => {
                    this.failed = true;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Perform the snell handshake over an established transport.
///
/// * TCP: writes the encrypted request header (`0x01 cmd 0x00 hostlen
///   host port_be16`, cmd = [`CMD_CONNECT`] or [`CMD_CONNECT_V2`] for
///   v2/reuse); the server's tunnel/error reply is consumed lazily on
///   the first read, like mihomo's `Snell.Read`.
/// * UDP (v3+): writes `0x01 0x06 0x00`; v4 additionally waits for the
///   reply here (adapter/outbound/snell.go:88-95). Packet bodies use
///   [`snell_udp_frame`] / [`parse_snell_udp_response`].
///
/// The version comes from [`parse_version`] (raw `0..=5` accepted; v5
/// rides the v4 wire). The dial sequence is the integrator's: TCP (plus
/// any obfs plugin) → this handshake → relay.
pub async fn handshake(
    stream: BoxProxyStream,
    cfg: &SnellOut,
    target: &NetAddr,
    is_udp: bool,
) -> Result<BoxProxyStream> {
    if cfg.psk.is_empty() {
        return Err(Error::config("snell: psk is required"));
    }
    let version = parse_version(cfg.version)?;
    let cfg = SnellOut {
        fronting: cfg.fronting.clone(),
        version,
        ..cfg.clone()
    };
    if is_udp && version < 3 {
        // WriteUDPHeader (snell.go:129-131) refuses below v3.
        return Err(Error::config("snell: unsupport UDP version"));
    }
    debug!(
        target: "engine",
        server = %cfg.server, port = cfg.port, version = cfg.version, udp = is_udp,
        "snell: starting handshake"
    );
    let mut snell = SnellStream::new(stream, &cfg)?;
    if is_udp {
        snell.write_all(&udp_header()).await?;
        snell.flush().await?;
        if cfg.version >= 4 {
            snell.wait_reply().await?;
        }
    } else {
        snell.write_all(&request_header(target, cfg.version, false)?).await?;
        snell.flush().await?;
    }
    debug!(target: "engine", "snell: request sent");
    Ok(Box::new(snell))
}

// ---------------------------------------------------------------------------
// Connection reuse pool (transport/snell/pool.go + adapter/outbound/snell.go)
// ---------------------------------------------------------------------------

/// A factory producing the (optionally obfs-wrapped) transport a pooled
/// snell conn rides on — `NewPool`'s factory closure
/// (adapter/outbound/snell.go:288-301): dial TCP, wrap obfs, return.
/// The default dials plain TCP to `(server, port)`.
pub type SnellDialFuture =
    Pin<Box<dyn std::future::Future<Output = Result<BoxProxyStream>> + Send>>;
pub type SnellTransportDialer =
    std::sync::Arc<dyn Fn() -> SnellDialFuture + Send + Sync>;

/// `NewPool`'s options (pool.go:123-136): `WithAge(15000)`,
/// `WithSize(10)`, evict = close.
pub const SNELL_POOL_MAX_AGE: std::time::Duration = std::time::Duration::from_millis(15_000);
pub const SNELL_POOL_MAX_IDLE: usize = 10;

async fn dial_tcp_transport(server: &str, port: u16) -> Result<BoxProxyStream> {
    let tcp = crate::mark::tcp_connect(server, port)
        .await
        .map_err(|e| Error::network(format!("dial {server}:{port}: {e}")))?;
    Ok(Box::new(tcp))
}

/// Shared pool state ([`SnellPool`] clones and pooled conns both hold it).
struct SnellPoolShared {
    cfg: SnellOut,
    dialer: SnellTransportDialer,
    /// The idle conns with their put-time (common/pool entry.time,
    /// pool.go:11-14). FIFO like the Go channel.
    idle: tokio::sync::Mutex<VecDeque<(std::time::Instant, SnellStream)>>,
    max_age: std::time::Duration,
    max_idle: usize,
}

impl SnellPoolShared {
    /// `pool.Put` (common/pool pool.go:75-91): non-blocking push; a full
    /// pool evicts (closes) the conn instead.
    async fn put(&self, conn: SnellStream) {
        let mut idle = self.idle.lock().await;
        if idle.len() >= self.max_idle {
            drop(conn); // evict → WithEvict(item.Close())
            return;
        }
        idle.push_back((std::time::Instant::now(), conn));
    }

    /// `pool.GetContext` (common/pool pool.go:51-69): pop entries until
    /// one is younger than `maxAge`; expired entries are evicted on the
    /// spot; an empty pool yields `None` (caller dials fresh).
    async fn get(&self) -> Option<SnellStream> {
        let mut idle = self.idle.lock().await;
        loop {
            let (put_at, conn) = idle.pop_front()?;
            if put_at.elapsed() > self.max_age {
                drop(conn); // expired → evict
                continue;
            }
            return Some(conn);
        }
    }
}

/// The adapter-level snell connection pool — mihomo `snell.Pool`
/// (transport/snell/pool.go) as wired by `NewSnell`
/// (adapter/outbound/snell.go:287-301).
///
/// Upstream pools only when `reuse` is on: v2 always
/// (`reuse := version == Version2 || (version == Version4 && Reuse)`,
/// adapter snell.go:252) and v4 with the `reuse` flag — so this pool
/// accepts versions 2 and 4 only.
///
/// * [`SnellPool::dial`] hands out a cached live conn (age-checked like
///   `GetContext`) or dials a fresh transport via the injected dialer,
///   then writes the request header with `reuse=true`
///   (`CommandConnectV2`, adapter snell.go:97-116).
/// * The returned [`PooledSnell`] recycles itself on drop exactly like
///   `PoolConn.Close` (pool.go:98-121): only after BOTH sides half-closed
///   (client `shutdown()` = `writeZeroChunk`, peer zero-chunk seen =
///   `peerClosed`) does it reset the reply state (`reply = false`) and
///   re-enter the pool; anything else closes the transport.
#[derive(Clone)]
pub struct SnellPool {
    shared: std::sync::Arc<SnellPoolShared>,
}

impl SnellPool {
    /// A pool dialing plain TCP to `cfg.server:cfg.port`.
    pub fn new(cfg: SnellOut) -> Result<Self> {
        let server = cfg.server.clone();
        let port = cfg.port;
        Self::with_dialer(cfg, move || {
            let server = server.clone();
            Box::pin(async move { dial_tcp_transport(&server, port).await })
        })
    }

    /// A pool whose transports come from `dialer` — the hook for obfs
    /// plugins (http/tls/shadow-tls/restls/jls wrap the TCP before the
    /// snell codec, like `streamConnContext`).
    pub fn with_dialer(
        cfg: SnellOut,
        dialer: impl Fn() -> SnellDialFuture + Send + Sync + 'static,
    ) -> Result<Self> {
        if cfg.psk.is_empty() {
            return Err(Error::config("snell: psk is required"));
        }
        let version = parse_version(cfg.version)?;
        if !matches!(version, 2 | 4) {
            // adapter/outbound/snell.go:252 — reuse exists only for v2
            // (always) and v4 (`reuse: true`); v5 already mapped to 4.
            return Err(Error::config(format!(
                "snell: connection reuse requires version 2 or 4, got {version}"
            )));
        }
        Ok(SnellPool {
            shared: std::sync::Arc::new(SnellPoolShared {
                cfg: SnellOut { version, ..cfg },
                dialer: std::sync::Arc::new(dialer),
                idle: tokio::sync::Mutex::new(VecDeque::new()),
                max_age: SNELL_POOL_MAX_AGE,
                max_idle: SNELL_POOL_MAX_IDLE,
            }),
        })
    }

    /// Override the idle policy (`NewPool`'s `WithAge`/`WithSize`).
    pub fn with_limits(
        mut self,
        max_age: std::time::Duration,
        max_idle: usize,
    ) -> Self {
        let shared = std::sync::Arc::get_mut(&mut self.shared)
            .expect("limits must be set before the pool is shared");
        shared.max_age = max_age;
        shared.max_idle = max_idle;
        self
    }

    /// Number of idle pooled conns (observability).
    pub async fn idle_len(&self) -> usize {
        self.shared.idle.lock().await.len()
    }

    /// `Snell.DialContext` with reuse on (adapter/outbound/snell.go:102-117):
    /// take a pooled conn (or make one), write the request header with
    /// `reuse=true` — `CommandConnectV2` — and mark the conn reusable so
    /// its later close returns it to this pool.
    pub async fn dial(&self, target: &NetAddr) -> Result<PooledSnell> {
        let mut snell = match self.shared.get().await {
            Some(conn) => conn,
            None => SnellStream::new((self.shared.dialer)().await?, &self.shared.cfg)?,
        };
        // WriteHeaderWithReuse(..., version, true) — the header write is
        // the "MarkReusable" gate (adapter snell.go:97-116).
        snell.write_all(&request_header(target, self.shared.cfg.version, true)?).await?;
        snell.flush().await.map_err(Error::from)?;
        Ok(PooledSnell {
            stream: Some(snell),
            shared: self.shared.clone(),
            zero_framed: false,
            half_closed: false,
            failed: false,
        })
    }
}

/// A checked-out pooled snell conn — `snell.PoolConn` (pool.go:51-121).
///
/// * `Read` surfaces the peer's zero chunk as a clean EOF while noting
///   `peerClosed` (pool.go:63-70).
/// * `shutdown()` is `CloseWrite` (pool.go:81-96): the reusable path
///   writes the zero-chunk half-close instead of closing.
/// * Drop is `Close` (pool.go:98-121): return to the pool only when the
///   request negotiated reuse AND both halves closed; otherwise the
///   transport is dropped (closed).
pub struct PooledSnell {
    stream: Option<SnellStream>,
    shared: std::sync::Arc<SnellPoolShared>,
    /// The zero chunk has been framed into the write buffer
    /// (`closeWriteOnce`'s once-guard).
    zero_framed: bool,
    /// The zero chunk was flushed to the transport
    /// (`closeWriteReusable`).
    half_closed: bool,
    failed: bool,
}

impl PooledSnell {
    /// Read access to the tunnel reply state for diagnostics.
    pub fn peer_half_closed(&self) -> bool {
        self.stream.as_ref().is_some_and(SnellStream::peer_half_closed)
    }
}

impl AsyncWrite for PooledSnell {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(stream) = this.stream.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "snell: pooled conn already closed",
            )));
        };
        Pin::new(stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_flush(cx),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "snell: pooled conn already closed",
            ))),
        }
    }

    /// `PoolConn.closeWrite` on the reusable path (pool.go:86-96):
    /// `writeZeroChunk` — the half-close that lets the server finish
    /// this request and wait for the next one. The zero chunk is framed
    /// once into the stream's write buffer (an empty sealed chunk), and
    /// `half_closed` latches only once the flush confirms it went out.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(stream) = this.stream.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        if !this.zero_framed {
            if let Err(e) = stream.frame(&[]) {
                this.failed = true;
                return Poll::Ready(Err(io_invalid(e)));
            }
            this.zero_framed = true;
        }
        match Pin::new(stream).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.half_closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                this.failed = true;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncRead for PooledSnell {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(stream) = this.stream.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        // pool.go:63-70 — peerClosed latches on the zero chunk (it may
        // do so while buffered data is still draining, which is
        // equivalent for the reuse decision); a transport error keeps it
        // unlatched so Drop closes instead of recycling.
        Pin::new(stream).poll_read(cx, buf)
    }
}

impl Drop for PooledSnell {
    /// `PoolConn.Close` (pool.go:98-121): reusable only when the request
    /// negotiated reuse (always true for pool dials), the local half
    /// closed via the zero chunk, AND the peer closed too; then reset
    /// the reply state and put the conn back. Otherwise the transport is
    /// dropped (closed).
    fn drop(&mut self) {
        let Some(mut stream) = self.stream.take() else { return };
        let reusable = self.half_closed && !self.failed && stream.peer_half_closed();
        if !reusable {
            return;
        }
        stream.reset_for_reuse();
        let shared = self.shared.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move { shared.put(stream).await });
        }
        // Without a runtime the conn is dropped → closed, like an
        // evicted pool entry (WithEvict → Close).
    }
}

// ---------------------------------------------------------------------------
// UDP session (adapter/outbound/snell.go:132-153 `ListenPacketContext`
// → snell.PacketConn(c), snell.go:411-443)
// ---------------------------------------------------------------------------

/// A snell UDP session: datagrams muxed over one framed TCP transport,
/// shaped like `anytls::AnyTlsUdp` for the integrator's UDP channel.
///
/// * [`SnellUdp::send_to`] frames each datagram with its target address
///   (snell.go `WritePacket`, 189-244) and seals it as exactly one AEAD
///   frame — v4 through the `WritePacketFrame` path (v4.go:81-96), v3 as
///   a single chunk.
/// * [`SnellUdp::recv_from`] reads one AEAD frame per call (snell.go
///   `ReadPacket`, 356-409: `0x04/0x06 || ip || port || payload`), so
///   packet edges survive the TCP transport.
pub struct SnellUdp {
    stream: SnellStream,
}

impl SnellUdp {
    /// Send one datagram toward `target` through the snell session.
    pub async fn send_to(&mut self, target: &NetAddr, payload: &[u8]) -> Result<()> {
        let frame = snell_udp_frame(target, payload)?;
        self.stream.write_packet(&frame).await
    }

    /// Receive one datagram; returns its origin address and the length
    /// written to `buf`. A buffer shorter than the datagram is an error
    /// (upstream `ReadPacket` would silently truncate; refusing is safer
    /// and matches `anytls::AnyTlsUdp`).
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(NetAddr, usize)> {
        let frame = self.stream.read_packet().await?;
        let (addr, payload) = parse_snell_udp_response(&frame)?;
        if buf.len() < payload.len() {
            return Err(Error::protocol(format!(
                "snell: udp read: {} byte datagram exceeds the {} byte buffer",
                payload.len(),
                buf.len()
            )));
        }
        buf[..payload.len()].copy_from_slice(&payload);
        Ok((addr, payload.len()))
    }
}

/// Open a snell UDP session over an established (optionally obfs-wrapped)
/// transport: writes the UDP command header (`0x01 0x06 0x00`,
/// snell.go:128-136) and, for v4, awaits the server's tunnel reply
/// eagerly (adapter/outbound/snell.go:88-95 — v3 keeps the lazy
/// first-read consumption of [`SnellStream::read_packet`]).
pub async fn udp_session(cfg: &SnellOut, transport: BoxProxyStream) -> Result<SnellUdp> {
    if cfg.psk.is_empty() {
        return Err(Error::config("snell: psk is required"));
    }
    let version = parse_version(cfg.version)?;
    let cfg = SnellOut {
        fronting: cfg.fronting.clone(),
        version,
        ..cfg.clone()
    };
    if version < 3 {
        // WriteUDPHeader (snell.go:129-131), verbatim; the adapter
        // config check is "snell version %d not support UDP"
        // (adapter/outbound/snell.go:254-257) — see validate_udp.
        return Err(Error::config("snell: unsupport UDP version"));
    }
    debug!(
        target: "engine",
        server = %cfg.server, port = cfg.port, version = cfg.version,
        "snell: starting UDP session"
    );
    let mut snell = SnellStream::new(transport, &cfg)?;
    snell.write_all(&udp_header()).await?;
    snell.flush().await?;
    if cfg.version >= 4 {
        snell.wait_reply().await?;
    }
    debug!(target: "engine", "snell: UDP session open");
    Ok(SnellUdp { stream: snell })
}

// ---------------------------------------------------------------------------
// UDP packet codecs (snell.go:189-244, 246-282, 291-335, 356-409)
// ---------------------------------------------------------------------------

/// Encode one outbound snell UDP packet (snell.go `writePacket`,
/// 189-233): `0x01 || hostlen || host || port` for domains,
/// `0x01 || 0x00 || 0x04/0x06 || ip || port` for IPs, then the payload.
/// Refuses payloads that would push the frame past `maxLength`
/// (`WritePacket`, snell.go:235-244).
pub fn snell_udp_frame(target: &NetAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let header_len = udp_request_header_len(target);
    let max_payload = MAX_LENGTH.saturating_sub(header_len);
    if header_len > MAX_LENGTH || payload.len() > max_payload {
        return Err(Error::protocol("snell: UDP payload too large"));
    }
    let mut buf = Vec::with_capacity(1 + header_len + payload.len());
    buf.push(CMD_UDP_FORWARD);
    match &target.host {
        Host::Domain(d) => {
            // socks5Addr[1 : 1+1+hostLen+2] — length byte, host, port.
            buf.push(d.len() as u8);
            buf.extend_from_slice(d.as_bytes());
        }
        Host::Ip(std::net::IpAddr::V4(v4)) => {
            buf.push(0x00);
            buf.push(0x04);
            buf.extend_from_slice(&v4.octets());
        }
        Host::Ip(std::net::IpAddr::V6(v6)) => {
            buf.push(0x00);
            buf.push(0x06);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&target.port.to_be_bytes());
    buf.extend_from_slice(payload);
    Ok(buf)
}

/// `UdpRequestHeaderLength` (snell.go:337-354).
fn udp_request_header_len(target: &NetAddr) -> usize {
    match &target.host {
        Host::Domain(d) => 3 + d.len() + 2,
        Host::Ip(std::net::IpAddr::V4(_)) => 1 + 2 + 4 + 2,
        Host::Ip(std::net::IpAddr::V6(_)) => 1 + 2 + 16 + 2,
    }
}

/// Parse an inbound snell UDP response packet (snell.go `ReadPacket`,
/// 356-409): `0x04 || ipv4 || port || payload` or `0x06 || ipv6 || port ||
/// payload`. Domains do not occur on the wire (the server's
/// `WritePacketResponse` only emits IPs).
pub fn parse_snell_udp_response(frame: &[u8]) -> Result<(NetAddr, Vec<u8>)> {
    let Some((&version, rest)) = frame.split_first() else {
        return Err(Error::protocol("snell: insufficient UDP length"));
    };
    let addr_len = match version {
        0x04 => 4usize,
        0x06 => 16usize,
        _ => return Err(Error::protocol("snell: ip version invalid")),
    };
    if rest.len() < addr_len + 2 {
        return Err(Error::protocol("snell: insufficient UDP length"));
    }
    let mut octets = [0u8; 16];
    octets[..addr_len].copy_from_slice(&rest[..addr_len]);
    let ip = if version == 0x04 {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            octets[0], octets[1], octets[2], octets[3],
        ))
    } else {
        std::net::IpAddr::V6(octets.into())
    };
    let port = u16::from_be_bytes([rest[addr_len], rest[addr_len + 1]]);
    Ok((NetAddr::ip(ip, port), rest[addr_len + 2..].to_vec()))
}

/// Parse an outbound request packet (snell.go `ParseUDPRequest`,
/// 291-335) — the server-side mirror of [`snell_udp_frame`]; the server
/// listener decodes every inbound datagram with it.
pub fn parse_snell_udp_request(frame: &[u8]) -> Result<(NetAddr, Vec<u8>)> {
    if frame.len() < 2 || frame[0] != CMD_UDP_FORWARD {
        return Err(Error::protocol("snell: invalid UDP request"));
    }
    let host_len = frame[1] as usize;
    if host_len != 0 {
        if frame.len() <= 2 + host_len + 2 {
            return Err(Error::protocol("snell: invalid UDP domain request"));
        }
        let host = std::str::from_utf8(&frame[2..2 + host_len])
            .map_err(|_| Error::protocol("snell: bad udp host"))?;
        let port = u16::from_be_bytes([frame[2 + host_len], frame[3 + host_len]]);
        return Ok((
            NetAddr::new(Host::Domain(host.to_string()), port),
            frame[4 + host_len..].to_vec(),
        ));
    }
    if frame.len() < 3 {
        return Err(Error::protocol("snell: invalid UDP IP request"));
    }
    let (addr_len, ip) = match frame[2] {
        0x04 => {
            if frame.len() < 3 + 4 + 2 {
                return Err(Error::protocol("snell: invalid UDP IPv4 request"));
            }
            (
                4usize,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    frame[3], frame[4], frame[5], frame[6],
                )),
            )
        }
        0x06 => {
            if frame.len() < 3 + 16 + 2 {
                return Err(Error::protocol("snell: invalid UDP IPv6 request"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&frame[3..19]);
            (16usize, std::net::IpAddr::V6(o.into()))
        }
        _ => return Err(Error::protocol("snell: invalid UDP address type")),
    };
    let port = u16::from_be_bytes([frame[3 + addr_len], frame[4 + addr_len]]);
    Ok((NetAddr::ip(ip, port), frame[5 + addr_len..].to_vec()))
}

/// Encode a server → client UDP response packet (snell.go
/// `WritePacketResponse`, 246-282): `0x04 || ipv4 || port_be16 || payload`
/// or `0x06 || ipv6 || port_be16 || payload`. Domains do not occur on
/// the response wire (upstream converts the reply address with
/// `socks5.ParseAddrToSocksAddr`, which is IP-only; a domain target must
/// be resolved by the relay before the reply) — a domain here is an
/// error, the caller drops the datagram.
pub fn snell_udp_response_frame(from: &NetAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(3 + 16 + payload.len());
    match &from.host {
        Host::Ip(std::net::IpAddr::V4(v4)) => {
            buf.push(0x04);
            buf.extend_from_slice(&v4.octets());
        }
        Host::Ip(std::net::IpAddr::V6(v6)) => {
            buf.push(0x06);
            buf.extend_from_slice(&v6.octets());
        }
        Host::Domain(_) => {
            return Err(Error::protocol(
                "snell: UDP response address must be an IP (resolve domain targets first)",
            ));
        }
    }
    buf.extend_from_slice(&from.port.to_be_bytes());
    buf.extend_from_slice(payload);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Server half (listener/snell/server.go + transport/snell ServerStreamConn)
// ---------------------------------------------------------------------------
//
// The server inverts the client codecs without duplicating them: the
// same `Conn` framing ([`Conn::V3`]/[`Conn::V4`], keyed by the same KDF)
// runs server-role, with the request/reply direction flipped:
//
// * `ServerStreamConn` (snell.go:170-174) is `StreamConn` + `reply=true`
//   — the server never *consumes* a reply byte, it *writes* one: the
//   first relay write prefixes `CommandTunnel` (tcpRequestConn.Write,
//   listener/snell/server.go:344-359).
// * the request header (`handleRequest` + `handleTCP`,
//   listener/snell/server.go:174-255) is read byte-wise off the
//   decrypted stream: version, command, clientID, then for connect the
//   host/port target; `CommandPing` gets a `CommandPong` frame and the
//   conn closes.
// * a request that negotiated reuse (`CommandConnectV2`) survives its
//   relay: on close the server writes the zero-chunk half-close (or a
//   `CommandError` frame when nothing was ever written —
//   tcpRequestConn.Close, server.go:327-385) and loops to the next
//   request header (server.go:166-171).
// * UDP (`handleUDP`, server.go:257-294): reply `CommandTunnel`, then
//   one AEAD frame per datagram in each direction (the client's
//   `ReadPacket`/`WritePacketFrame` mirrors).

/// `CommandPong` (snell.go:37) — the ping reply byte.
const CMD_PONG: u8 = 0x01;
/// `CommandPing` (snell.go:35) — numerically `CommandTunnel` (0); the
/// command byte's position (before the clientID) disambiguates.
const CMD_PING: u8 = 0x00;
/// `writeCommandError`'s code for "the remote closed before any reply"
/// (tcpRequestConn.Close, listener/snell/server.go:372).
const REMOTE_EOF_CODE: u8 = 0x65;

/// The server-side version default: `New` maps an unset version to
/// Version4 (listener/snell/server.go:37-39) — note the asymmetry with
/// the client, whose default is v1 ([`DEFAULT_SNELL_VERSION`]).
pub const SNELL_SERVER_DEFAULT_VERSION: u8 = 4;

impl Conn {
    /// Read exactly `buf.len()` decrypted bytes (the byte-stream view the
    /// server's bufio.Reader sees). A half-close or transport close
    /// mid-header is `UnexpectedEof`.
    async fn read_exact_dec(&mut self, buf: &mut [u8]) -> Result<()> {
        std::future::poll_fn(|cx| {
            let mut filled = 0usize;
            loop {
                {
                    let out = match self {
                        Conn::V3(c) => &mut c.out,
                        Conn::V4(c) => &mut c.out,
                    };
                    while filled < buf.len() && !out.is_empty() {
                        let n = out.len().min(buf.len() - filled);
                        buf[filled..filled + n].copy_from_slice(&out[..n]);
                        out.advance(n);
                        filled += n;
                    }
                }
                if filled == buf.len() {
                    return Poll::Ready(Ok(()));
                }
                match self.poll_fill(cx) {
                    Poll::Ready(Ok(true)) => continue,
                    Poll::Ready(Ok(false)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "snell: connection closed inside the request header",
                        )));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await
        .map_err(Error::from)
    }

    /// Frame `payload` and push it fully to the transport (the server's
    /// plain `Snell.Write`). An empty payload is the zero chunk.
    async fn write_framed(&mut self, payload: &[u8]) -> Result<()> {
        let mut wbuf = BytesMut::new();
        self.frame(payload, &mut wbuf)?;
        let inner = self.inner_mut();
        inner.write_all(&wbuf).await?;
        inner.flush().await?;
        Ok(())
    }

    /// Take everything currently decrypted (exactly one frame's payload
    /// after a successful [`Conn::poll_fill`]).
    fn take_decrypted(&mut self) -> Option<Vec<u8>> {
        let out = match self {
            Conn::V3(c) => &mut c.out,
            Conn::V4(c) => &mut c.out,
        };
        if out.is_empty() {
            None
        } else {
            Some(out.to_vec())
        }
    }

    /// Frame `payload` as exactly one AEAD frame (the server's
    /// `WritePacketFrame` path, snell.go:182-187): v4 seals the whole
    /// packet through `writeFrame` with the first-frame padding rule,
    /// v3 rides the plain chunk writer. Used for UDP response packets.
    fn frame_packet(&mut self, payload: &[u8], wbuf: &mut BytesMut) -> Result<()> {
        match self {
            Conn::V3(c) => c.frame(payload, wbuf),
            Conn::V4(c) => {
                let padding = c.next_frame_padding_length(payload.len());
                c.write_frame(payload, padding, wbuf)
            }
        }
    }

    /// The framing half shared by both conn roles.
    fn frame(&mut self, payload: &[u8], wbuf: &mut BytesMut) -> Result<()> {
        match self {
            Conn::V3(c) => c.frame(payload, wbuf),
            Conn::V4(c) => c.frame(payload, wbuf),
        }
    }
}

/// `writeCommandError` (listener/snell/server.go:315-325):
/// `CommandError || code || msglen || msg[0..255]`.
fn command_error_frame(code: u8, message: &str) -> Vec<u8> {
    let msg = message.as_bytes();
    let len = msg.len().min(255);
    let mut buf = Vec::with_capacity(3 + len);
    buf.push(CMD_ERROR);
    buf.push(code);
    buf.push(len as u8);
    buf.extend_from_slice(&msg[..len]);
    buf
}

/// Normalize a listener-configured version exactly like `New`
/// (listener/snell/server.go:37-44): `0` → Version4; `1..=5` pass (5
/// rides the v4 codec, like `StreamConn`'s `version >= Version4` route);
/// anything else is `snell inbound version %d is not supported`.
pub fn parse_server_version(raw: u8) -> Result<u8> {
    match raw {
        0 => Ok(SNELL_SERVER_DEFAULT_VERSION),
        1..=5 => Ok(raw),
        other => Err(Error::config(format!(
            "snell inbound version {other} is not supported"
        ))),
    }
}

/// One parsed request header (handleRequest + handleTCP,
/// listener/snell/server.go:174-255).
#[derive(Debug, Clone)]
pub enum SnellServerRequest {
    /// `CommandPing` — already answered with a `CommandPong` frame; the
    /// connection closes (server.go:188-191).
    Ping,
    /// `CommandConnect` / `CommandConnectV2` toward `target`;
    /// `reuse` is the V2 flag, which keeps the conn alive for the next
    /// request after the relay ends.
    Connect {
        target: NetAddr,
        client_id: String,
        reuse: bool,
    },
    /// `CommandUDP` (server.go:201-205).
    Udp { client_id: String },
}

/// Continuation for the request loop: handed back the conn whenever a
/// reusable request finishes (the listener's `for { handleRequest }`,
/// server.go:166-171). The listener closes over its relay context.
pub type SnellServerNext = std::sync::Arc<
    dyn Fn(SnellServerConn) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// A server-role snell connection over an established (optionally
/// obfs-wrapped) transport — `ServerStreamConn`
/// (transport/snell/snell.go:170-174) as driven by
/// `Listener.HandleConn` (listener/snell/server.go:146-172).
pub struct SnellServerConn {
    conn: Conn,
    psk: Vec<u8>,
    version: u8,
}

impl SnellServerConn {
    /// Wrap a transport with the server framing for `version` (raw
    /// listener value — [`parse_server_version`] has been applied).
    pub fn new(stream: BoxProxyStream, psk: &[u8], version: u8) -> Result<Self> {
        let conn = match version {
            1..=3 => Conn::V3(V3Conn::new(stream, psk, v3_cipher_kind(version))),
            4 | 5 => Conn::V4(V4Conn::new(stream, psk)?),
            other => {
                return Err(Error::config(format!(
                    "snell inbound version {other} is not supported"
                )))
            }
        };
        Ok(SnellServerConn {
            conn,
            psk: psk.to_vec(),
            version,
        })
    }

    /// Read one request header (handleRequest, server.go:174-209). Ping
    /// requests are answered inline with `CommandPong`, exactly like
    /// `handleRequest`'s first arm.
    pub async fn read_request(&mut self) -> Result<SnellServerRequest> {
        let mut b = [0u8; 1];
        self.conn.read_exact_dec(&mut b).await?;
        if b[0] != PROTOCOL_VERSION {
            return Err(Error::protocol(format!(
                "snell invalid protocol version: {}",
                b[0]
            )));
        }
        self.conn.read_exact_dec(&mut b).await?;
        let command = b[0];
        if command == CMD_PING {
            // server.go:188-191 — the only command answered before the
            // clientID is read (CommandPing == CommandTunnel == 0).
            self.conn.write_framed(&[CMD_PONG]).await?;
            return Ok(SnellServerRequest::Ping);
        }
        // readClientID (server.go:211-224).
        self.conn.read_exact_dec(&mut b).await?;
        let id_len = b[0] as usize;
        let mut id = vec![0u8; id_len];
        self.conn.read_exact_dec(&mut id).await?;
        let client_id = String::from_utf8_lossy(&id).into_owned();

        match command {
            CMD_CONNECT | CMD_CONNECT_V2 => {
                // handleTCP (server.go:226-255).
                self.conn.read_exact_dec(&mut b).await?;
                if b[0] == 0 {
                    return Err(Error::protocol("snell connect host is empty"));
                }
                let mut host = vec![0u8; b[0] as usize];
                self.conn.read_exact_dec(&mut host).await?;
                let mut port_bytes = [0u8; 2];
                self.conn.read_exact_dec(&mut port_bytes).await?;
                let port = u16::from_be_bytes(port_bytes);
                let host = String::from_utf8_lossy(&host).into_owned();
                // metadata() (server.go:296-313): a parseable IP becomes
                // DstIP, anything else the domain.
                let target = match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => NetAddr::ip(ip, port),
                    Err(_) => NetAddr::new(Host::Domain(host), port),
                };
                Ok(SnellServerRequest::Connect {
                    target,
                    client_id,
                    reuse: command == CMD_CONNECT_V2,
                })
            }
            CMD_UDP => Ok(SnellServerRequest::Udp { client_id }),
            other => Err(Error::protocol(format!("snell unknown command: {other}"))),
        }
    }

    /// Write the bare tunnel reply (handleUDP's first write,
    /// server.go:258-260); UDP only — TCP replies ride the relay's first
    /// payload frame.
    pub async fn write_tunnel_reply(&mut self) -> Result<()> {
        self.conn.write_framed(&[CMD_TUNNEL]).await
    }

    /// Consume the conn into the relay-facing TCP stream
    /// (`tcpRequestConn`, server.go:327-385): first write prefixes
    /// `CommandTunnel`, the peer's zero chunk reads as clean EOF, and
    /// Drop performs the close semantics — error frame when no reply was
    /// ever written, zero-chunk half-close on the reuse path, then the
    /// `next` continuation runs the next request.
    pub fn into_tcp(self, reuse: bool, next: Option<SnellServerNext>) -> SnellServerTcp {
        SnellServerTcp {
            conn: Some(self.conn),
            psk: Some(self.psk),
            version: self.version,
            wbuf: BytesMut::new(),
            pending_plain: 0,
            reply_written: false,
            reuse,
            failed: false,
            next,
        }
    }

    /// Consume the conn into the UDP datagram IO (after
    /// [`Self::write_tunnel_reply`]) — one AEAD frame per datagram in
    /// each direction (`handleUDP` + `udpPacket.WriteBack`,
    /// server.go:257-294, 399-410).
    pub fn into_udp(self) -> SnellServerUdp {
        SnellServerUdp {
            conn: self.conn,
            wbuf: BytesMut::new(),
            pending_plain: 0,
            failed: false,
            leftover: BytesMut::new(),
        }
    }
}

/// The relay-facing TCP stream of one snell request —
/// `tcpRequestConn` (listener/snell/server.go:327-385).
///
/// * `Read` maps the peer's zero chunk (and a transport EOF) to a clean
///   EOF (server.go:336-342).
/// * `Write` prefixes `CommandTunnel` to the first payload (the reply
///   byte shares that frame, server.go:344-359).
/// * Drop is `Close` (server.go:365-385): no reply yet → the
///   `CommandError`/`Remote EOF` frame; reuse → the zero-chunk
///   half-close and the `next` continuation (the listener's request
///   loop); otherwise the transport closes.
pub struct SnellServerTcp {
    conn: Option<Conn>,
    psk: Option<Vec<u8>>,
    version: u8,
    wbuf: BytesMut,
    pending_plain: usize,
    reply_written: bool,
    reuse: bool,
    failed: bool,
    next: Option<SnellServerNext>,
}

impl SnellServerTcp {
    /// Whether the reply byte has been sent (diagnostics/tests).
    pub fn reply_written(&self) -> bool {
        self.reply_written
    }
}

impl AsyncWrite for SnellServerTcp {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "snell: server stream failed",
            )));
        }
        let Some(conn) = this.conn.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "snell: server conn already finished",
            )));
        };
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.wbuf.is_empty() {
            let payload = if this.reply_written {
                buf.to_vec()
            } else {
                // payload[0] = CommandTunnel (server.go:349-355).
                let mut v = Vec::with_capacity(1 + buf.len());
                v.push(CMD_TUNNEL);
                v.extend_from_slice(buf);
                this.reply_written = true;
                v
            };
            if let Err(e) = conn.frame(&payload, &mut this.wbuf) {
                this.failed = true;
                return Poll::Ready(Err(io_invalid(e)));
            }
            this.pending_plain = buf.len();
        }
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(this.conn.as_mut().expect("checked above").inner_mut())
                .poll_write(cx, &this.wbuf))?;
            if n == 0 {
                this.failed = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "snell: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Poll::Ready(Ok(this.pending_plain))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(conn) = this.conn.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "snell: server conn already finished",
            )));
        };
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(conn.inner_mut()).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                this.failed = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "snell: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Pin::new(conn.inner_mut()).poll_flush(cx)
    }

    /// The write half-close is folded into Drop's close semantics (the
    /// zero chunk is a *request-end* signal here, not a TCP FIN).
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl AsyncRead for SnellServerTcp {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(conn) = this.conn.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        loop {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if conn.drain_out(buf) {
                return Poll::Ready(Ok(()));
            }
            match conn.poll_fill(cx) {
                // ErrZeroChunk → io.EOF (server.go:336-342); a clean
                // transport close reads the same.
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => {
                    this.failed = true;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for SnellServerTcp {
    /// tcpRequestConn.Close (server.go:365-385). The close semantics need
    /// the wire, so the continuation runs as a task (no runtime → the
    /// conn is dropped, i.e. closed).
    fn drop(&mut self) {
        let Some(conn) = self.conn.take() else { return };
        let reply_written = self.reply_written;
        let reuse = self.reuse && !self.failed;
        let psk = self.psk.take();
        let version = self.version;
        let next = self.next.take();
        if tokio::runtime::Handle::try_current().is_err() {
            return; // drop(conn) — closed
        }
        tokio::spawn(async move {
            let mut conn = conn;
            if !reply_written {
                // writeCommandError(0x65, "Remote EOF") — and unlike the
                // !reuse arm, the reuse path keeps the conn open.
                let _ = conn.write_framed(&command_error_frame(REMOTE_EOF_CODE, "Remote EOF")).await;
            }
            if reuse {
                // Conn.Write(nil) — the zero-chunk half-close (only after
                // a written reply; the error frame above already ended
                // this request's traffic).
                if reply_written {
                    let _ = conn.write_framed(&[]).await;
                }
                conn.reset_zero();
                if let Some(next) = next {
                    if let Some(psk) = psk {
                        next(SnellServerConn {
                            conn,
                            psk,
                            version,
                        })
                        .await;
                    }
                }
            }
            // else: dropped — the transport closes.
        });
    }
}

/// The UDP datagram IO of one snell session (`handleUDP` +
/// `udpPacket.WriteBack`, server.go:257-294, 387-410): each read yields
/// exactly one decrypted AEAD frame (a `snell_udp_frame` datagram), each
/// write seals one `snell_udp_response_frame` as one frame — datagram
/// edges survive the TCP transport exactly like the client's
/// `ReadPacket`/`WritePacketFrame` pair.
pub struct SnellServerUdp {
    conn: Conn,
    wbuf: BytesMut,
    pending_plain: usize,
    failed: bool,
    /// Remainder of a datagram larger than the caller's buffer.
    leftover: BytesMut,
}

impl AsyncRead for SnellServerUdp {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if !this.leftover.is_empty() {
                let n = this.leftover.len().min(buf.remaining());
                buf.put_slice(&this.leftover[..n]);
                this.leftover.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.failed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "snell: server udp stream failed",
                )));
            }
            match this.conn.poll_fill(cx) {
                // One frame landed per successful fill; take it whole so
                // the next read starts a fresh datagram.
                Poll::Ready(Ok(true)) => {
                    if let Some(frame) = this.conn.take_decrypted() {
                        this.leftover.extend_from_slice(&frame);
                    }
                }
                // EOF / zero chunk: the session ended cleanly
                // (server.go:267-272).
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => {
                    this.failed = true;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SnellServerUdp {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "snell: server udp stream failed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.wbuf.is_empty() {
            if let Err(e) = this.conn.frame_packet(buf, &mut this.wbuf) {
                this.failed = true;
                return Poll::Ready(Err(io_invalid(e)));
            }
            this.pending_plain = buf.len();
        }
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(this.conn.inner_mut()).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                this.failed = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "snell: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Poll::Ready(Ok(this.pending_plain))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(this.conn.inner_mut()).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                this.failed = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "snell: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Pin::new(this.conn.inner_mut()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(self.get_mut().conn.inner_mut()).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// http obfs, server half (transport/simple-obfs/http_server.go)
// ---------------------------------------------------------------------------

use base64::Engine as _;

/// Cap while accumulating the fake request head (parity with the client
/// side's response-head cap).
const MAX_HTTP_HEAD: usize = 16 * 1024;

/// The mihomo package-level random nginx version (http_server.go:76-77:
/// `randv2.IntN(11)` / `randv2.IntN(12)`, picked once per process).
fn nginx_version() -> (u8, u8) {
    use std::sync::OnceLock;
    static V: OnceLock<(u8, u8)> = OnceLock::new();
    *V.get_or_init(|| {
        let mut rng = rand::rngs::OsRng;
        (rng.gen_range(0..11), rng.gen_range(0..12))
    })
}

/// `time.Now().Format(time.RFC1123)` in GMT (http_server.go:83) — the
/// fake Date header. Civil-from-days per Hinnant's algorithm.
fn rfc1123_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    const WDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // 1970-01-01 was a Thursday (index 4).
    let wday = (days + 4).rem_euclid(7) as usize;
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        WDAYS[wday],
        d,
        MONTHS[(month - 1) as usize],
        year,
        h,
        m,
        s
    )
}

/// The `101 Switching Protocols` head (http_responseTemplate,
/// http_server.go:68-92), prefixing the server's first write.
fn http_response_head() -> String {
    let mut accept = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut accept);
    let (major, minor) = nginx_version();
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Server: nginx/1.{major}.{minor}\r\n\
         Date: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         \r\n",
        rfc1123_now(),
        base64::engine::general_purpose::URL_SAFE.encode(accept),
    )
}

/// A parsed fake request head: method + the headers the server gates on.
struct HttpRequestHead {
    method: String,
    connection_upgrade: bool,
    content_length: usize,
}

/// Minimal request-head parse: request line + case-insensitive header
/// scan (Go's `http.ReadRequest` gates on Method and Connection,
/// http_server.go:41-48; Content-Length bounds the first body).
fn parse_http_request_head(head: &[u8]) -> Result<HttpRequestHead> {
    let text = std::str::from_utf8(head)
        .map_err(|_| Error::protocol("snell obfs http: malformed request head"))?;
    let text = text.trim_end_matches(['\r', '\n']);
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| Error::protocol("snell obfs http: empty request head"))?;
    let mut parts = request_line.split(' ');
    let method = parts
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let _uri = parts.next();
    let version = parts.next().unwrap_or_default();
    if method.is_empty() || !version.starts_with("HTTP/") {
        return Err(Error::protocol("snell obfs http: malformed request line"));
    }
    let mut connection_upgrade = false;
    let mut content_length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "connection" => {
                connection_upgrade = value
                    .split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
            }
            "content-length" => {
                content_length = value.parse().map_err(|_| {
                    Error::protocol("snell obfs http: malformed content-length")
                })?;
            }
            _ => {}
        }
    }
    Ok(HttpRequestHead {
        method,
        connection_upgrade,
        content_length,
    })
}

/// Server-side http obfs stream (mihomo `NewHTTPObfsServer`,
/// transport/simple-obfs/http_server.go:16-103): the first read consumes
/// the fake `GET … Connection: Upgrade` request and yields its body (the
/// snell salt + first sealed header); the first write prefixes the
/// `101` response head; everything after is raw.
pub struct HttpObfsServerStream {
    inner: BoxProxyStream,
    rbuf: BytesMut,
    /// Bytes of the request body still to surface before raw reads.
    body_pending: usize,
    request_done: bool,
    response_sent: bool,
}

impl HttpObfsServerStream {
    /// Read the request head off the transport (http_server.go:40-62).
    async fn consume_request(&mut self) -> Result<()> {
        loop {
            if let Some(pos) = self.rbuf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = self.rbuf[..pos + 4].to_vec();
                self.rbuf.advance(pos + 4);
                let parsed = parse_http_request_head(&head)?;
                // http_server.go:46-47 — non-GET or non-Upgrade is io.EOF.
                if parsed.method != "GET" || !parsed.connection_upgrade {
                    return Err(Error::protocol(
                        "snell obfs http: request is not a websocket upgrade",
                    ));
                }
                self.body_pending = parsed.content_length;
                self.request_done = true;
                return Ok(());
            }
            if self.rbuf.len() > MAX_HTTP_HEAD {
                return Err(Error::protocol(
                    "snell obfs http: request head exceeds 16 KiB without a terminator",
                ));
            }
            let mut tmp = [0u8; 8 * 1024];
            let n = self.inner.read(&mut tmp).await?;
            if n == 0 {
                return Err(Error::protocol(
                    "snell obfs http: transport closed inside the request head",
                ));
            }
            self.rbuf.extend_from_slice(&tmp[..n]);
        }
    }
}

impl AsyncRead for HttpObfsServerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if this.request_done {
                if !this.rbuf.is_empty() {
                    // Buffered bytes first — the request body (up to
                    // body_pending) then any raw traffic beyond it.
                    let take = this.rbuf.len().min(buf.remaining());
                    let from_body = take.min(this.body_pending);
                    buf.put_slice(&this.rbuf[..take]);
                    this.body_pending -= from_body;
                    this.rbuf.advance(take);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let mut tmp = [0u8; 8 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
            this.rbuf.extend_from_slice(rb.filled());
            // Parse synchronously when the head is complete.
            if let Some(pos) = this.rbuf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = this.rbuf[..pos + 4].to_vec();
                this.rbuf.advance(pos + 4);
                match parse_http_request_head(&head) {
                    Ok(parsed) => {
                        if parsed.method != "GET" || !parsed.connection_upgrade {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "snell obfs http: request is not a websocket upgrade",
                            )));
                        }
                        this.body_pending = parsed.content_length;
                        this.request_done = true;
                    }
                    Err(e) => return Poll::Ready(Err(io_invalid(e))),
                }
            } else if this.rbuf.len() > MAX_HTTP_HEAD {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snell obfs http: request head exceeds 16 KiB without a terminator",
                )));
            }
        }
    }
}

impl AsyncWrite for HttpObfsServerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.response_sent {
            // http_server.go:79-92 — the 101 head prefixes the first
            // write, then raw bytes.
            let head = http_response_head();
            let mut out = Vec::with_capacity(head.len() + buf.len());
            out.extend_from_slice(head.as_bytes());
            out.extend_from_slice(buf);
            this.response_sent = true;
            // Write the head + payload as one unit (retry via inner
            // writes; the caller sees buf.len() once accepted).
            let mut wbuf = BytesMut::from(&out[..]);
            let total = buf.len();
            drop(out);
            while !wbuf.is_empty() {
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &wbuf))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "snell obfs http: transport accepted zero bytes",
                    )));
                }
                wbuf.advance(n);
            }
            Poll::Ready(Ok(total))
        } else {
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Wrap an accepted transport with the server-side http obfs
/// (mihomo `obfs.NewHTTPObfsServer`, listener/snell/server.go:156-158).
pub async fn http_obfs_server(transport: BoxProxyStream) -> Result<BoxProxyStream> {
    let mut stream = HttpObfsServerStream {
        inner: transport,
        rbuf: BytesMut::with_capacity(16 * 1024),
        body_pending: 0,
        request_done: false,
        response_sent: false,
    };
    // The snell codec reads immediately (the salt); pull the head now so
    // a malformed request fails the conn before any crypto work.
    stream.consume_request().await?;
    Ok(Box::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn test_psk() -> String {
        format!("psk-{:016x}", rand::random::<u64>())
    }

    // ------------------------------------------------------------ crypto

    #[test]
    fn blake2b_rfc_vectors() {
        // BLAKE2b-512("abc") and BLAKE2b-512(""), cross-checked with
        // Python hashlib.
        let abc = argon2id::blake2b(64, b"abc");
        assert_eq!(
            hex(&abc),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        let empty = argon2id::blake2b(64, b"");
        assert_eq!(
            hex(&empty),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
        // A short digest exercises the parameter-block digest length.
        assert_eq!(argon2id::blake2b(32, b"abc").len(), 32);
        // A multi-block input (two full blocks, then a partial one).
        let long = argon2id::blake2b(64, &[7u8; 300]);
        assert_eq!(long.len(), 64);
        assert_ne!(long, argon2id::blake2b(64, &[7u8; 301]));
    }

    #[test]
    fn argon2id_reference_vectors() {
        // Cross-checked against golang.org/x/crypto/argon2 (the exact
        // implementation mihomo links; IDKey passes no secret/AD).
        let tag = argon2id::hash(&[0x01u8; 32], &[0x02u8; 16], &[], &[], 3, 32, 4, 32);
        assert_eq!(
            hex(&tag),
            "03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e"
        );
        // Snell's exact parameters (cipher.go:31): t=3, m=8 KiB, p=1.
        let tag = argon2id::hash(b"unit-psk", &[0x42u8; 16], &[], &[], 3, 8, 1, 32);
        assert_eq!(
            hex(&tag),
            "1e48f634eb9b9d401d738b6b77b2524c00b1e943c060b456086e28ea075714f3"
        );
    }

    #[test]
    fn argon2id_h0_rfc9106_prehash() {
        // RFC 9106 section 5.3 publishes the pre-hashing digest for the
        // argon2id vector WITH secret (03*8) and associated data (04*12),
        // pinning the H0 construction including the K/X length fields.
        let h0 = argon2id::h0(
            &[0x01u8; 32],
            &[0x02u8; 16],
            &[0x03u8; 8],
            &[0x04u8; 12],
            3,
            32,
            4,
            32,
        );
        assert_eq!(
            hex(&h0),
            "2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b8\
             546a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997"
        );
    }

    #[test]
    fn snell_kdf_is_argon2id_truncated() {
        let psk = b"unit-psk";
        let salt = [0x42u8; 16];
        let full = argon2id::hash(psk, &salt, &[], &[], 3, 8, 1, 32);
        let key = snell_kdf(psk, &salt, 16).unwrap();
        assert_eq!(key.len(), 16);
        assert_eq!(key, full[..16]);
        // Different salt → different subkey (fresh subkey per connection
        // via the random salt).
        assert_ne!(key, snell_kdf(psk, &[0x43u8; 16], 16).unwrap());
    }

    // --------------------------------------------------------- framing

    #[test]
    fn request_header_layout() {
        // WriteHeaderWithReuse (snell.go:103-126):
        // 01 01 00 hostlen host port_be16 (v1/v3/v4, no reuse)
        let target = NetAddr::domain("example.com", 443).unwrap();
        assert_eq!(
            request_header(&target, 3, false).unwrap(),
            vec![
                0x01, 0x01, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
                b'm', 0x01, 0xbb
            ]
        );
        let target = NetAddr::ip("127.0.0.1".parse().unwrap(), 80);
        assert_eq!(
            request_header(&target, 1, false).unwrap(),
            vec![
                0x01, 0x01, 0x00, 9, b'1', b'2', b'7', b'.', b'0', b'.', b'0', b'.', b'1', 0x00,
                0x50
            ]
        );
        // v2 and any pooled reuse send CommandConnectV2 (snell.go:107-111).
        assert_eq!(
            request_header(&target, 2, false).unwrap(),
            vec![
                0x01, 0x05, 0x00, 9, b'1', b'2', b'7', b'.', b'0', b'.', b'0', b'.', b'1', 0x00,
                0x50
            ]
        );
        assert_eq!(
            request_header(&target, 4, true).unwrap()[1],
            CMD_CONNECT_V2
        );
        assert_eq!(request_header(&target, 4, false).unwrap()[1], CMD_CONNECT);
        // Hosts beyond a u8 length are refused (not silently truncated).
        let long = NetAddr::new(Host::Domain("a".repeat(256)), 80);
        let err = request_header(&long, 3, false).unwrap_err();
        assert!(err.to_string().contains("255"), "{err}");
    }

    #[test]
    fn version_parsing_matrix() {
        // adapter/outbound/snell.go:244-261.
        assert_eq!(parse_version(0).unwrap(), DEFAULT_SNELL_VERSION);
        assert_eq!(parse_version(1).unwrap(), 1);
        assert_eq!(parse_version(2).unwrap(), 2);
        assert_eq!(parse_version(3).unwrap(), 3);
        assert_eq!(parse_version(4).unwrap(), 4);
        // v5 servers accept v4 clients (adapter snell.go:248-251).
        assert_eq!(parse_version(5).unwrap(), 4);
        let err = parse_version(6).unwrap_err();
        assert!(err.to_string().contains("snell version error: 6"), "{err}");
        // UDP gating (adapter snell.go:253-257).
        assert!(validate_udp(1, true).is_err());
        assert!(validate_udp(2, true).is_err());
        let err = validate_udp(2, true).unwrap_err();
        assert!(err.to_string().contains("snell version 2 not support UDP"), "{err}");
        assert!(validate_udp(2, false).is_ok());
        assert!(validate_udp(3, true).is_ok());
    }

    #[test]
    fn swap_padding_touches_only_every_other_byte() {
        let mut padding = vec![0xAAu8; 8];
        let mut payload = vec![0x55u8; 4];
        swap_padding(&mut padding, &mut payload);
        // limit = min(8, 4): only indices 0 and 2 swap (v4.go:368-376);
        // padding bytes past the limit are untouched.
        assert_eq!(padding, vec![0x55, 0xAA, 0x55, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
        assert_eq!(payload, vec![0xAA, 0x55, 0xAA, 0x55]);
        swap_padding(&mut padding, &mut payload);
        assert_eq!(padding, vec![0xAAu8; 8]);
        assert_eq!(payload, vec![0x55u8; 4]);
    }

    #[test]
    fn bit_count_padding_has_exact_ones() {
        let p = bit_count_padding(16, 37);
        assert_eq!(p.len(), 16);
        assert_eq!(
            p.iter().map(|b| b.count_ones() as usize).sum::<usize>(),
            37
        );
        let p = bit_count_padding(5, 40);
        assert!(p.iter().all(|b| *b == 0xFF));
        let p = bit_count_padding(5, 0);
        assert!(p.iter().all(|b| *b == 0x00));
    }

    #[test]
    fn count_payload_ones_skips_tail() {
        // len & !3: the fifth byte of a 5-byte slice is excluded.
        assert_eq!(count_payload_ones(&[0xFF; 5]), 32);
        assert_eq!(count_payload_ones(&[0xFF; 4]), 32);
        assert_eq!(count_payload_ones(&[0xFF; 0]), 0);
    }

    #[test]
    fn udp_frame_layouts() {
        // Domain: 01 len host port (snell.go:196-202).
        let target = NetAddr::domain("dns.example", 53).unwrap();
        assert_eq!(
            snell_udp_frame(&target, b"pq").unwrap(),
            vec![
                0x01, 0x0b, b'd', b'n', b's', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00,
                0x35, b'p', b'q'
            ]
        );
        // IPv4: 01 00 04 ip port (snell.go:203-208).
        let target = NetAddr::ip("8.8.8.8".parse().unwrap(), 53);
        assert_eq!(
            snell_udp_frame(&target, b"xy").unwrap(),
            vec![0x01, 0x00, 0x04, 8, 8, 8, 8, 0x00, 0x35, b'x', b'y']
        );
        // Round-trips through the upstream request parser.
        let (parsed, payload) =
            parse_snell_udp_request(&snell_udp_frame(&target, b"xyz").unwrap()).unwrap();
        assert_eq!(parsed, target);
        assert_eq!(payload, b"xyz".to_vec());
        // Response parse (ReadPacket): 04 ip port payload.
        let (addr, payload) =
            parse_snell_udp_response(&[0x04, 1, 2, 3, 4, 0x00, 0x35, b'o', b'k']).unwrap();
        assert_eq!(addr.host, Host::Ip("1.2.3.4".parse().unwrap()));
        assert_eq!(addr.port, 53);
        assert_eq!(payload, b"ok".to_vec());
        // IPv6 response: 06 + 16 ip + port + payload.
        let mut v6 = vec![0x06];
        v6.extend_from_slice(&[0u8; 16]);
        v6.extend_from_slice(&53u16.to_be_bytes());
        v6.push(1);
        let (addr, payload) = parse_snell_udp_response(&v6).unwrap();
        assert!(matches!(addr.host, Host::Ip(std::net::IpAddr::V6(_))));
        assert_eq!(payload, vec![1u8]);
        // maxLength cap (snell.go:236-239).
        let target = NetAddr::domain(&"d".repeat(200), 53).unwrap();
        assert!(snell_udp_frame(&target, &vec![0u8; MAX_LENGTH]).is_err());
        assert!(snell_udp_frame(&target, &[0u8; 100]).is_ok());
    }

    // ------------------------------------------------------ loopback

    async fn read_n(rd: &mut (impl AsyncRead + Unpin), n: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        rd.read_exact(&mut buf).await?;
        Ok(buf)
    }

    /// Test-side v1..v3 crypto half (mirrors shadowaead Reader/Writer).
    struct V3Mimic {
        aead: Aead,
        nonce: SsNonce,
    }

    impl V3Mimic {
        fn new(kind: AeadKind, psk: &[u8], salt: &[u8]) -> Self {
            V3Mimic {
                aead: snell_aead(kind, psk, salt).unwrap(),
                nonce: SsNonce::new(),
            }
        }

        async fn read_chunk(&mut self, rd: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
            let len_ct = read_n(rd, 2 + TAG_SIZE).await?;
            let len_pt = self.aead.open(&self.nonce.advance(), b"", &len_ct).unwrap();
            let size = (((len_pt[0] as usize) << 8) | len_pt[1] as usize) & MAX_LENGTH;
            if size == 0 {
                // ErrZeroChunk — surfaced as the empty chunk (the
                // half-close boundary, stream.go:122-125).
                return Ok(Vec::new());
            }
            let payload_ct = read_n(rd, size + TAG_SIZE).await?;
            Ok(self.aead.open(&self.nonce.advance(), b"", &payload_ct).unwrap())
        }

        fn frame_chunk(&mut self, payload: &[u8], out: &mut Vec<u8>) {
            self.aead
                .seal(
                    &self.nonce.advance(),
                    b"",
                    &(payload.len() as u16).to_be_bytes(),
                    out,
                )
                .unwrap();
            self.aead.seal(&self.nonce.advance(), b"", payload, out).unwrap();
        }

        /// The zero chunk: the sealed `0x0000` length alone
        /// (stream.go:38-45).
        fn frame_zero_chunk(&mut self, out: &mut Vec<u8>) {
            self.aead
                .seal(&self.nonce.advance(), b"", &0u16.to_be_bytes(), out)
                .unwrap();
        }
    }

    /// v3 server mimic: verify the request header, reply tunnel, echo.
    async fn v3_server_mimic(io: DuplexStream, psk: Vec<u8>) -> Result<()> {
        let (mut rd, mut wr) = tokio::io::split(io);
        let salt = read_n(&mut rd, 16).await.map_err(Error::from)?;
        let mut dec = V3Mimic::new(AeadKind::Aes128Gcm, &psk, &salt);

        let header = dec.read_chunk(&mut rd).await.map_err(Error::from)?;
        assert_eq!(&header[..3], &[PROTOCOL_VERSION, CMD_CONNECT, 0x00]);
        let host_len = header[3] as usize;
        let host = String::from_utf8(header[4..4 + host_len].to_vec()).unwrap();
        let port = u16::from_be_bytes([header[4 + host_len], header[5 + host_len]]);
        assert_eq!((host.as_str(), port), ("echo.example", 443));

        let mut out_salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut out_salt);
        let mut enc = V3Mimic::new(AeadKind::Aes128Gcm, &psk, &out_salt);
        let mut wire = out_salt.to_vec();
        enc.frame_chunk(&[CMD_TUNNEL], &mut wire);
        wr.write_all(&wire).await.map_err(Error::from)?;
        loop {
            let data = match dec.read_chunk(&mut rd).await {
                Ok(d) => d,
                Err(_) => return Ok(()), // client closed
            };
            let mut wire = Vec::new();
            enc.frame_chunk(&data, &mut wire);
            wr.write_all(&wire).await.map_err(Error::from)?;
        }
    }

    async fn connect_v3(cfg: &SnellOut, psk: &str) -> Result<BoxProxyStream> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let psk = psk.to_string();
        tokio::spawn(async move {
            if let Err(e) = v3_server_mimic(server, psk.as_bytes().to_vec()).await {
                panic!("v3 mimic failed: {e}");
            }
        });
        let target = NetAddr::domain("echo.example", 443).unwrap();
        handshake(Box::new(client), cfg, &target, false).await
    }

    #[tokio::test]
    async fn v3_loopback_echo() {
        let psk = test_psk();
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: psk.clone(),
            version: 3,
            udp: false,
        };
        let mut stream = connect_v3(&cfg, &psk).await.unwrap();
        stream.write_all(b"ping-v3").await.unwrap();
        let mut buf = [0u8; 7];
        timeout_read(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-v3");

        // Multi-chunk payload (v3 chunks cap at 0x3FFF).
        let payload: Vec<u8> = (0..40 * 1024).map(|i| (i % 251) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let want = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; want.len()];
            rd.read_exact(&mut got).await.unwrap();
            got
        });
        wr.write_all(&payload).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(20), echo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn v3_wrong_psk_fails() {
        let psk = test_psk();
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: format!("wrong-{psk}"),
            version: 3,
            udp: false,
        };
        // The header write succeeds; the mimic cannot decrypt it, drops
        // the connection, and the client fails before any tunnel data.
        let mut stream = connect_v3(&cfg, &psk).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 8];
        let err = match timeout_read(&mut stream, &mut buf).await {
            Ok(0) | Ok(_) => panic!("a wrong PSK must not establish a tunnel"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("closed before the reply"), "{err}");
    }

    /// Test-side v4 crypto half.
    struct V4Mimic {
        aead: Aead,
        nonce: SsNonce,
    }

    impl V4Mimic {
        fn new(psk: &[u8], salt: &[u8]) -> Self {
            V4Mimic {
                aead: snell_aead(AeadKind::Aes128Gcm, psk, salt).unwrap(),
                nonce: SsNonce::new(),
            }
        }

        async fn read_frame(&mut self, rd: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
            let header_ct = read_n(rd, V4_HEADER_CIPHER).await?;
            let header = self.aead.open(&self.nonce.advance(), b"", &header_ct).unwrap();
            assert_eq!(header[0], 4);
            let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
            if payload_len == 0 {
                // The zero chunk is the header alone — no payload cipher
                // follows (v4.go:201-206, 339-342).
                assert_eq!(padding_len, 0);
                return Ok(Vec::new());
            }
            let mut frame = read_n(rd, padding_len + payload_len + TAG_SIZE).await?;
            if padding_len > 0 {
                let (padding, payload_ct) = frame.split_at_mut(padding_len);
                swap_padding(padding, payload_ct);
            }
            Ok(self
                .aead
                .open(&self.nonce.advance(), b"", &frame[padding_len..])
                .unwrap())
        }

        /// One frame without padding (the server's mirror of writeFrame).
        /// An empty payload seals the header alone (the zero chunk,
        /// v4.go:339-342).
        fn frame(&mut self, payload: &[u8], out: &mut Vec<u8>) {
            let mut header = [0u8; V4_HEADER_PLAIN];
            header[0] = 4;
            header[3..5].copy_from_slice(&(0u16).to_be_bytes());
            header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            self.aead.seal(&self.nonce.advance(), b"", &header, out).unwrap();
            if !payload.is_empty() {
                self.aead.seal(&self.nonce.advance(), b"", payload, out).unwrap();
            }
        }
    }

    async fn v4_server_mimic(io: DuplexStream, psk: Vec<u8>, expect_udp: bool) -> Result<()> {
        let (mut rd, mut wr) = tokio::io::split(io);
        let salt = read_n(&mut rd, V4_SALT_SIZE).await.map_err(Error::from)?;
        let mut dec = V4Mimic::new(&psk, &salt);

        let first = dec.read_frame(&mut rd).await.map_err(Error::from)?;
        if expect_udp {
            assert_eq!(first, vec![PROTOCOL_VERSION, CMD_UDP, 0x00]);
        } else {
            assert_eq!(&first[..3], &[PROTOCOL_VERSION, CMD_CONNECT, 0x00]);
            let host_len = first[3] as usize;
            assert_eq!(&first[4..4 + host_len], b"echo.example");
            assert_eq!(
                u16::from_be_bytes([first[4 + host_len], first[5 + host_len]]),
                443
            );
        }

        let mut out_salt = [0u8; V4_SALT_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut out_salt);
        let mut enc = V4Mimic::new(&psk, &out_salt);
        let mut wire = out_salt.to_vec();
        enc.frame(&[CMD_TUNNEL], &mut wire);
        wr.write_all(&wire).await.map_err(Error::from)?;

        if expect_udp {
            // Echo one UDP response packet (WritePacketResponse layout).
            let packet = dec.read_frame(&mut rd).await.map_err(Error::from)?;
            let (target, payload) = parse_snell_udp_request(&packet).unwrap();
            assert_eq!(target.host, Host::Domain("dns.example".into()));
            assert_eq!(target.port, 53);
            let mut resp = vec![0x04u8, 8, 8, 4, 4];
            resp.extend_from_slice(&53u16.to_be_bytes());
            resp.extend_from_slice(&payload);
            let mut wire = Vec::new();
            enc.frame(&resp, &mut wire);
            wr.write_all(&wire).await.map_err(Error::from)?;
        } else {
            loop {
                let data = match dec.read_frame(&mut rd).await {
                    Ok(d) => d,
                    Err(_) => return Ok(()),
                };
                let mut wire = Vec::new();
                enc.frame(&data, &mut wire);
                wr.write_all(&wire).await.map_err(Error::from)?;
            }
        }
        Ok(())
    }

    async fn connect_v4(cfg: &SnellOut, psk: &str, is_udp: bool) -> Result<BoxProxyStream> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let psk = psk.to_string();
        tokio::spawn(async move {
            if let Err(e) = v4_server_mimic(server, psk.as_bytes().to_vec(), is_udp).await {
                panic!("v4 mimic failed: {e}");
            }
        });
        let target = if is_udp {
            // The UDP handshake itself carries no target (snell.go:128-136).
            NetAddr::domain("unused.invalid", 0)?
        } else {
            NetAddr::domain("echo.example", 443)?
        };
        handshake(Box::new(client), cfg, &target, is_udp).await
    }

    #[tokio::test]
    async fn v4_loopback_echo() {
        let psk = test_psk();
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: psk.clone(),
            version: 4,
            udp: false,
        };
        let mut stream = connect_v4(&cfg, &psk, false).await.unwrap();
        stream.write_all(b"ping-v4").await.unwrap();
        let mut buf = [0u8; 7];
        timeout_read(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-v4");

        // A payload beyond the initial v4 payload limit forces multiple
        // frames and exercises the chunk ramp.
        let payload: Vec<u8> = (0..50 * 1024).map(|i| (i % 249) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let want = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; want.len()];
            rd.read_exact(&mut got).await.unwrap();
            got
        });
        wr.write_all(&payload).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(20), echo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn v4_wire_layout_salt_header_padding() {
        // Byte-level check of the first two frames on the wire:
        // frame 1 = salt || header_ct || initialPadding || payload_ct,
        // frame 2 = header_ct || payload_ct (padding only rides frame 1).
        let psk = test_psk();
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: psk.clone(),
            version: 4,
            udp: false,
        };
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut stream = handshake(Box::new(client), &cfg, &target, false)
            .await
            .unwrap();
        stream.write_all(b"tail").await.unwrap();
        stream.flush().await.unwrap();
        drop(stream);

        let salt = read_n(&mut server, V4_SALT_SIZE).await.unwrap();
        let mut dec = V4Mimic::new(psk.as_bytes(), &salt);
        let header_ct = read_n(&mut server, V4_HEADER_CIPHER).await.unwrap();
        let header = dec
            .aead
            .open(&dec.nonce.advance(), b"", &header_ct)
            .unwrap();
        assert_eq!(header[0], 4);
        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        assert_eq!(payload_len, 18, "header={header:?}"); // 3+1+12+2
        assert!(
            (usize::from(V4_INITIAL_PADDING_MIN)
                ..usize::from(V4_INITIAL_PADDING_MIN + V4_INITIAL_PADDING_SPAN))
                .contains(&padding_len),
            "initial padding outside the 0x100..0x1FF window: {padding_len}"
        );
        let mut frame =
            read_n(&mut server, padding_len + payload_len + TAG_SIZE).await.unwrap();
        let (padding, payload_ct) = frame.split_at_mut(padding_len);
        swap_padding(padding, payload_ct);
        let payload = dec.aead.open(&dec.nonce.advance(), b"", payload_ct).unwrap();
        assert_eq!(payload, request_header(&target, 4, false).unwrap());

        // Frame 2: no padding, plain "tail".
        let header_ct = read_n(&mut server, V4_HEADER_CIPHER).await.unwrap();
        let header = dec
            .aead
            .open(&dec.nonce.advance(), b"", &header_ct)
            .unwrap();
        assert_eq!(u16::from_be_bytes([header[3], header[4]]), 0);
        assert_eq!(u16::from_be_bytes([header[5], header[6]]), 4);
        let frame = read_n(&mut server, 4 + TAG_SIZE).await.unwrap();
        let payload = dec.aead.open(&dec.nonce.advance(), b"", &frame).unwrap();
        assert_eq!(payload, b"tail");
    }

    #[tokio::test]
    async fn v4_udp_handshake_and_packet_roundtrip() {
        let psk = test_psk();
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: psk.clone(),
            version: 4,
            udp: true,
        };
        let mut stream = connect_v4(&cfg, &psk, true).await.unwrap();
        // The v4 UDP handshake already consumed the tunnel reply
        // (adapter/outbound/snell.go:90-94).
        let target = NetAddr::domain("dns.example", 53).unwrap();
        let frame = snell_udp_frame(&target, b"query!").unwrap();
        stream.write_all(&frame).await.unwrap();
        // Read one frame back and parse it as a response packet. The
        // frame may arrive in pieces, so accumulate until the full
        // echoed payload is present.
        let mut raw = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = timeout_read(&mut stream, &mut byte).await.unwrap();
            assert_eq!(n, 1);
            raw.push(byte[0]);
            if let Ok((addr, payload)) = parse_snell_udp_response(&raw) {
                assert_eq!(addr.host, Host::Ip("8.8.4.4".parse().unwrap()));
                assert_eq!(addr.port, 53);
                if payload.len() == b"query!".len() {
                    assert_eq!(payload, b"query!".to_vec());
                    break;
                }
            }
            assert!(raw.len() < 64, "no response packet within 64 bytes");
        }
    }

    /// UDP echo mimic shared by v3/v4: verifies the UDP command header,
    /// replies tunnel, then echoes every request packet back as a
    /// response frame (server-side `WritePacketResponse` layout).
    async fn udp_echo_mimic(
        io: DuplexStream,
        psk: Vec<u8>,
        version: u8,
        packets_per_request: usize,
    ) -> Result<()> {
        let (mut rd, mut wr) = tokio::io::split(io);
        match version {
            3 => {
                let salt = read_n(&mut rd, 16).await.map_err(Error::from)?;
                let mut dec = V3Mimic::new(AeadKind::Aes128Gcm, &psk, &salt);
                let header = dec.read_chunk(&mut rd).await.map_err(Error::from)?;
                assert_eq!(header, vec![PROTOCOL_VERSION, CMD_UDP, 0x00]);
                let mut out_salt = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut out_salt);
                let mut enc = V3Mimic::new(AeadKind::Aes128Gcm, &psk, &out_salt);
                let mut wire = out_salt.to_vec();
                enc.frame_chunk(&[CMD_TUNNEL], &mut wire);
                wr.write_all(&wire).await.map_err(Error::from)?;
                loop {
                    let packet = match dec.read_chunk(&mut rd).await {
                        Ok(p) => p,
                        Err(_) => return Ok(()),
                    };
                    let (_, payload) = parse_snell_udp_request(&packet)?;
                    for _ in 0..packets_per_request {
                        let resp = udp_response_frame(&payload);
                        let mut wire = Vec::new();
                        enc.frame_chunk(&resp, &mut wire);
                        wr.write_all(&wire).await.map_err(Error::from)?;
                    }
                    wr.flush().await.map_err(Error::from)?;
                }
            }
            4 => {
                let salt = read_n(&mut rd, V4_SALT_SIZE).await.map_err(Error::from)?;
                let mut dec = V4Mimic::new(&psk, &salt);
                let header = dec.read_frame(&mut rd).await.map_err(Error::from)?;
                assert_eq!(header, vec![PROTOCOL_VERSION, CMD_UDP, 0x00]);
                let mut out_salt = [0u8; V4_SALT_SIZE];
                rand::rngs::OsRng.fill_bytes(&mut out_salt);
                let mut enc = V4Mimic::new(&psk, &out_salt);
                let mut wire = out_salt.to_vec();
                enc.frame(&[CMD_TUNNEL], &mut wire);
                wr.write_all(&wire).await.map_err(Error::from)?;
                loop {
                    let packet = match dec.read_frame(&mut rd).await {
                        Ok(p) => p,
                        Err(_) => return Ok(()),
                    };
                    let (target, payload) = parse_snell_udp_request(&packet)?;
                    assert_eq!(target.host, Host::Domain("dns.example".into()));
                    assert_eq!(target.port, 53);
                    for i in 0..packets_per_request {
                        let mut resp = udp_response_frame(&payload);
                        // Distinguish the copies in the edge test.
                        if packets_per_request > 1 {
                            let last = resp.len() - 1;
                            resp[last] = i as u8;
                        }
                        let mut wire = Vec::new();
                        enc.frame(&resp, &mut wire);
                        wr.write_all(&wire).await.map_err(Error::from)?;
                    }
                    wr.flush().await.map_err(Error::from)?;
                }
            }
            other => panic!("unsupported mimic version {other}"),
        }
    }

    /// Server-side `WritePacketResponse` (snell.go:246-282):
    /// `0x04 || ipv4 || port || payload`.
    fn udp_response_frame(payload: &[u8]) -> Vec<u8> {
        let mut resp = vec![0x04u8, 8, 8, 4, 4];
        resp.extend_from_slice(&53u16.to_be_bytes());
        resp.extend_from_slice(payload);
        resp
    }

    async fn connect_udp_mimic(
        cfg: &SnellOut,
        psk: &str,
        packets_per_request: usize,
    ) -> Result<SnellUdp> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let psk = psk.to_string();
        let version = cfg.version;
        tokio::spawn(async move {
            if let Err(e) =
                udp_echo_mimic(server, psk.as_bytes().to_vec(), version, packets_per_request).await
            {
                panic!("udp mimic failed: {e}");
            }
        });
        udp_session(cfg, Box::new(client)).await
    }

    #[tokio::test]
    async fn v4_udp_session_roundtrip_and_edges() {
        let psk = test_psk();
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: psk.clone(),
            version: 4,
            udp: true,
        };
        // Three response frames ride back-to-back on one transport; each
        // recv_from must return exactly one frame's payload — the frame
        // edges survive because read_packet never merges chunks.
        let mut udp = connect_udp_mimic(&cfg, &psk, 3).await.unwrap();
        let target = NetAddr::domain("dns.example", 53).unwrap();
        udp.send_to(&target, b"q1").await.unwrap();
        let mut buf = [0u8; 1500];
        let mut got = Vec::new();
        for _ in 0..3 {
            let (addr, n) = tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
                .await
                .expect("recv timed out")
                .unwrap();
            assert_eq!(addr.host, Host::Ip("8.8.4.4".parse().unwrap()));
            assert_eq!(addr.port, 53);
            assert_eq!(n, 2, "one snell frame per datagram");
            got.push(buf[..n].to_vec());
        }
        assert_eq!(
            got,
            vec![b"q\x00".to_vec(), b"q\x01".to_vec(), b"q\x02".to_vec()]
        );

        // Multiple client datagrams in flight keep their edges too: the
        // mimic stamps the copy index into the last byte, so the six
        // responses must arrive as first0..first2 then secon0..secon2 —
        // any frame merging would corrupt or glue them.
        udp.send_to(&target, b"first!").await.unwrap();
        udp.send_to(&target, b"second").await.unwrap();
        let mut frames = Vec::new();
        for _ in 0..6 {
            let (_, n) = tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
                .await
                .expect("recv timed out")
                .unwrap();
            assert_eq!(n, 6, "each datagram keeps its own frame");
            frames.push(buf[..n].to_vec());
        }
        for (i, frame) in frames.iter().take(3).enumerate() {
            assert_eq!(&frame[..5], b"first");
            assert_eq!(frame[5], i as u8);
        }
        for (i, frame) in frames.iter().skip(3).enumerate() {
            assert_eq!(&frame[..5], b"secon");
            assert_eq!(frame[5], i as u8);
        }
    }

    #[tokio::test]
    async fn v3_udp_session_lazy_reply_roundtrip() {
        let psk = test_psk();
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: psk.clone(),
            version: 3,
            udp: true,
        };
        // v3 does not await the reply in udp_session; the tunnel byte is
        // consumed lazily by the first recv_from, like packetConn.ReadFrom
        // → Snell.Read → ReadReply (adapter/outbound/snell.go:88-95).
        let mut udp = connect_udp_mimic(&cfg, &psk, 1).await.unwrap();
        let target = NetAddr::domain("dns.example", 53).unwrap();
        udp.send_to(&target, b"v3-query").await.unwrap();
        let mut buf = [0u8; 1500];
        let (addr, n) = tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
            .await
            .expect("recv timed out")
            .unwrap();
        assert_eq!(addr.host, Host::Ip("8.8.4.4".parse().unwrap()));
        assert_eq!(addr.port, 53);
        assert_eq!(&buf[..n], b"v3-query");
    }

    #[tokio::test]
    async fn udp_session_rejects_bad_version_and_empty_psk() {
        let mut cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: String::new(),
            version: 3,
            udp: true,
        };
        let err = match udp_session(&cfg, Box::new(tokio::io::duplex(16).0)).await {
            Ok(_) => panic!("empty psk must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("psk"), "{err}");
        cfg.psk = "p".into();
        cfg.version = 2;
        let err = match udp_session(&cfg, Box::new(tokio::io::duplex(16).0)).await {
            Ok(_) => panic!("version 2 must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("version"), "{err}");
    }

    #[tokio::test]
    async fn v4_wrong_psk_fails() {
        let psk = test_psk();
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: format!("wrong-{psk}"),
            version: 4,
            udp: false,
        };
        let mut stream = connect_v4(&cfg, &psk, false).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 8];
        let err = match timeout_read(&mut stream, &mut buf).await {
            Ok(0) | Ok(_) => panic!("a wrong PSK must not establish a tunnel"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("closed before the reply"), "{err}");
    }

    #[tokio::test]
    async fn bad_version_rejected() {
        // Raw version 6 is past every upstream constant
        // (adapter/outbound/snell.go:259-260).
        let cfg = SnellOut {
            fronting: None,
            server: "x".into(),
            port: 1,
            psk: "p".into(),
            version: 6,
            udp: false,
        };
        let target = NetAddr::domain("t.test", 80).unwrap();
        let err = match handshake(Box::new(tokio::io::duplex(16).0), &cfg, &target, false).await {
            Ok(_) => panic!("version 6 must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("version"), "{err}");
    }

    #[tokio::test]
    async fn udp_below_v3_rejected_with_upstream_message() {
        // WriteUDPHeader's verbatim error (snell.go:129-131).
        for version in [1u8, 2] {
            let cfg = SnellOut {
            fronting: None,
                server: "x".into(),
                port: 1,
                psk: "p".into(),
                version,
                udp: true,
            };
            let err = match udp_session(&cfg, Box::new(tokio::io::duplex(16).0)).await {
                Ok(_) => panic!("version {version} UDP must be rejected"),
                Err(e) => e,
            };
            assert!(err.to_string().contains("unsupport UDP version"), "{err}");
        }
    }

    // ------------------------------------------------- v1/v2/v5 loopback

    /// A v1/v2 server mimic: shadowaead framing with the version's
    /// cipher, asserting the request header's command byte, replying
    /// tunnel, echoing, and honouring the reuse loop (zero chunk →
    /// server zero chunk → next request header).
    async fn shadowaead_server_mimic(
        io: DuplexStream,
        psk: Vec<u8>,
        version: u8,
        expect_cmd: u8,
        mut requests: impl FnMut(&str, u16),
    ) -> Result<()> {
        let (mut rd, mut wr) = tokio::io::split(io);
        let salt = read_n(&mut rd, 16).await.map_err(Error::from)?;
        let kind = if version == 1 {
            AeadKind::Chacha20Poly1305
        } else {
            AeadKind::Aes128Gcm
        };
        let mut dec = V3Mimic::new(kind, &psk, &salt);
        // One AEAD writer for the whole conn — the salt prefixes the
        // first server write only (stream.go initWriter).
        let mut out_salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut out_salt);
        let mut enc = V3Mimic::new(kind, &psk, &out_salt);
        let mut reply_wire = out_salt.to_vec();
        enc.frame_chunk(&[CMD_TUNNEL], &mut reply_wire);
        loop {
            // request header
            let header = match dec.read_chunk(&mut rd).await {
                Ok(h) => h,
                Err(_) => return Ok(()), // transport closed
            };
            if header.is_empty() {
                return Ok(()); // stray zero chunk then close
            }
            assert_eq!(&header[..3], &[PROTOCOL_VERSION, expect_cmd, 0x00]);
            let host_len = header[3] as usize;
            let host = String::from_utf8(header[4..4 + host_len].to_vec()).unwrap();
            let port = u16::from_be_bytes([header[4 + host_len], header[5 + host_len]]);
            requests(&host, port);

            wr.write_all(&reply_wire).await.map_err(Error::from)?;
            // relay until the client's zero chunk, then half-close back
            loop {
                let data = match dec.read_chunk(&mut rd).await {
                    Ok(d) => d,
                    Err(_) => return Ok(()),
                };
                if data.is_empty() {
                    break;
                }
                let mut echo = Vec::new();
                enc.frame_chunk(&data, &mut echo);
                wr.write_all(&echo).await.map_err(Error::from)?;
            }
            let mut zero = Vec::new();
            enc.frame_zero_chunk(&mut zero);
            wr.write_all(&zero).await.map_err(Error::from)?;
            // reuse loop: the next request's tunnel reply reuses the
            // already-salted writer
            let mut next = Vec::new();
            enc.frame_chunk(&[CMD_TUNNEL], &mut next);
            reply_wire = next;
        }
    }

    #[tokio::test]
    async fn v1_loopback_echo() {
        // v1 = Chacha20-Poly1305 over the SS framing (StreamConn,
        // snell.go:160-167; cipher.go:50-56).
        let psk = test_psk();
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: psk.clone(),
            version: 1,
            udp: false,
        };
        let (client, server) = tokio::io::duplex(64 * 1024);
        let psk2 = psk.clone();
        tokio::spawn(async move {
            if let Err(e) =
                shadowaead_server_mimic(server, psk2.as_bytes().to_vec(), 1, CMD_CONNECT, |_, _| {})
                    .await
            {
                panic!("v1 mimic failed: {e}");
            }
        });
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut stream = handshake(Box::new(client), &cfg, &target, false)
            .await
            .unwrap();
        stream.write_all(b"ping-v1").await.unwrap();
        let mut buf = [0u8; 7];
        timeout_read(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-v1");
    }

    #[tokio::test]
    async fn v2_header_sends_command_connect_v2() {
        // v2 always negotiates reuse (adapter/outbound/snell.go:252), so
        // WriteHeaderWithReuse emits CommandConnectV2 (snell.go:107-111)
        // even on a plain (unpooled) handshake.
        let psk = test_psk();
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: psk.clone(),
            version: 2,
            udp: false,
        };
        let (client, server) = tokio::io::duplex(64 * 1024);
        let psk2 = psk.clone();
        tokio::spawn(async move {
            if let Err(e) = shadowaead_server_mimic(
                server,
                psk2.as_bytes().to_vec(),
                2,
                CMD_CONNECT_V2,
                |_, _| {},
            )
            .await
            {
                panic!("v2 mimic failed: {e}");
            }
        });
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut stream = handshake(Box::new(client), &cfg, &target, false)
            .await
            .unwrap();
        stream.write_all(b"ping-v2").await.unwrap();
        let mut buf = [0u8; 7];
        timeout_read(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-v2");
    }

    #[tokio::test]
    async fn v5_rides_the_v4_wire() {
        // parse_version maps v5 → 4 (adapter/outbound/snell.go:248-251),
        // so a v5 config handshakes and relays against a v4 server.
        let psk = test_psk();
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: psk.clone(),
            version: 5,
            udp: false,
        };
        let mut stream = connect_v4(&cfg, &psk, false).await.unwrap();
        stream.write_all(b"ping-v5").await.unwrap();
        let mut buf = [0u8; 7];
        timeout_read(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-v5");
    }

    // ------------------------------------------------------ snell pool

    async fn pool_transport(psk: &str, version: u8) -> Result<BoxProxyStream> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let psk = psk.as_bytes().to_vec();
        tokio::spawn(async move {
            let requests = |host: &str, port: u16| {
                assert_eq!((host, port), ("echo.example", 443));
            };
            let res = match version {
                2 => shadowaead_server_mimic(server, psk, 2, CMD_CONNECT_V2, requests).await,
                _ => v4_server_reuse_mimic(server, psk, requests).await,
            };
            if let Err(e) = res {
                panic!("pool mimic failed: {e}");
            }
        });
        Ok(Box::new(client))
    }

    /// v4 server with the reuse loop (listener/snell/server.go:166-171):
    /// every request opens with CommandConnectV2, echoes until the
    /// client's zero chunk, half-closes back, waits for the next header.
    async fn v4_server_reuse_mimic(
        io: DuplexStream,
        psk: Vec<u8>,
        mut requests: impl FnMut(&str, u16),
    ) -> Result<()> {
        let (mut rd, mut wr) = tokio::io::split(io);
        let salt = read_n(&mut rd, V4_SALT_SIZE).await.map_err(Error::from)?;
        let mut dec = V4Mimic::new(&psk, &salt);
        // One AEAD writer for the whole conn — the salt prefixes the
        // first server frame only (v4.go initWriter).
        let mut out_salt = [0u8; V4_SALT_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut out_salt);
        let mut enc = V4Mimic::new(&psk, &out_salt);
        let mut tunnel_wire = out_salt.to_vec();
        enc.frame(&[CMD_TUNNEL], &mut tunnel_wire);
        loop {
            let header = match dec.read_frame(&mut rd).await {
                Ok(h) => h,
                Err(_) => return Ok(()),
            };
            if header.is_empty() {
                return Ok(());
            }
            assert_eq!(&header[..3], &[PROTOCOL_VERSION, CMD_CONNECT_V2, 0x00]);
            let host_len = header[3] as usize;
            let host = String::from_utf8(header[4..4 + host_len].to_vec()).unwrap();
            let port = u16::from_be_bytes([header[4 + host_len], header[5 + host_len]]);
            requests(&host, port);

            wr.write_all(&tunnel_wire).await.map_err(Error::from)?;
            loop {
                let data = match dec.read_frame(&mut rd).await {
                    Ok(d) => d,
                    Err(_) => return Ok(()),
                };
                if data.is_empty() {
                    break;
                }
                let mut wire = Vec::new();
                enc.frame(&data, &mut wire);
                wr.write_all(&wire).await.map_err(Error::from)?;
            }
            let mut wire = Vec::new();
            enc.frame(&[], &mut wire); // server zero chunk (reuse close)
            wr.write_all(&wire).await.map_err(Error::from)?;
            // the next request's tunnel reply reuses the salted writer
            let mut next = Vec::new();
            enc.frame(&[CMD_TUNNEL], &mut next);
            tunnel_wire = next;
        }
    }

    fn pool_with_dial_counter(
        psk: &str,
        version: u8,
    ) -> (SnellPool, Arc<std::sync::atomic::AtomicUsize>) {
        let psk = psk.to_string();
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter2 = counter.clone();
        let pool = SnellPool::with_dialer(
            SnellOut {
                fronting: None,
                server: "127.0.0.1".into(),
                port: 0,
                psk: psk.clone(),
                version,
                udp: false,
            },
            move || {
                let psk = psk.clone();
                let counter = counter2.clone();
                Box::pin(async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    pool_transport(&psk, version).await
                })
            },
        )
        .unwrap();
        (pool, counter)
    }

    async fn pooled_request(conn: &mut PooledSnell, payload: &[u8]) -> Vec<u8> {
        conn.write_all(payload).await.unwrap();
        conn.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut got))
            .await
            .expect("pooled read timed out")
            .unwrap();
        got
    }

    /// Read from a pooled conn with a timeout; `Ok(0)` = clean EOF.
    async fn pooled_read_timeout(conn: &mut PooledSnell, buf: &mut [u8]) -> io::Result<usize> {
        tokio::time::timeout(Duration::from_secs(10), conn.read(buf))
            .await
            .expect("pooled read timed out")
    }

    #[tokio::test]
    async fn pool_reuses_one_conn_across_dials() {
        // Dial → relay → half-close both ways → drop: the conn returns to
        // the pool (PoolConn.Close, pool.go:98-121) and the next dial
        // reuses it (one transport, two requests, like DialContext with
        // reuse on, adapter/outbound/snell.go:102-117).
        let psk = test_psk();
        let (pool, counter) = pool_with_dial_counter(&psk, 4);
        let target = NetAddr::domain("echo.example", 443).unwrap();

        {
            let mut conn = pool.dial(&target).await.unwrap();
            assert_eq!(pooled_request(&mut conn, b"first").await, b"first");
            conn.shutdown().await.unwrap(); // writeZeroChunk
            let mut tail = [0u8; 4];
            let n = pooled_read_timeout(&mut conn, &mut tail).await.unwrap();
            assert_eq!(n, 0, "the peer zero chunk is a clean EOF");
            assert!(conn.peer_half_closed());
        } // Drop → put back to the pool
        tokio::time::sleep(Duration::from_millis(50)).await; // the put task lands
        assert_eq!(pool.idle_len().await, 1);
        {
            let mut conn = pool.dial(&target).await.unwrap();
            assert_eq!(pooled_request(&mut conn, b"seco").await, b"seco");
            conn.shutdown().await.unwrap();
            let mut tail = [0u8; 4];
            let n = pooled_read_timeout(&mut conn, &mut tail).await.unwrap();
            assert_eq!(n, 0);
        }
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn pool_without_peer_close_does_not_reuse() {
        // PoolConn.Close refuses to recycle when the peer never
        // half-closed (pool.go:110-113): dropping after a local
        // shutdown only (server hasn't answered yet) closes the conn.
        let psk = test_psk();
        let (pool, counter) = pool_with_dial_counter(&psk, 4);
        let target = NetAddr::domain("echo.example", 443).unwrap();
        {
            let mut conn = pool.dial(&target).await.unwrap();
            assert_eq!(pooled_request(&mut conn, b"ping").await, b"ping");
            conn.shutdown().await.unwrap();
        } // dropped without observing the peer's zero chunk
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(pool.idle_len().await, 0);
        {
            let mut conn = pool.dial(&target).await.unwrap();
            assert_eq!(pooled_request(&mut conn, b"aga").await, b"aga");
            conn.shutdown().await.unwrap();
        }
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn pool_expires_idle_conns() {
        // GetContext evicts entries older than maxAge (common/pool
        // pool.go:57-61): after the 15s default (shortened here), the
        // next dial makes a fresh transport.
        let psk = test_psk();
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let psk2 = psk.clone();
        let counter2 = counter.clone();
        let pool = SnellPool::with_dialer(
            SnellOut {
                fronting: None,
                server: "127.0.0.1".into(),
                port: 0,
                psk,
                version: 4,
                udp: false,
            },
            move || {
                let psk = psk2.clone();
                let counter = counter2.clone();
                Box::pin(async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    pool_transport(&psk, 4).await
                })
            },
        )
        .unwrap()
        .with_limits(Duration::from_millis(80), 10);
        let target = NetAddr::domain("echo.example", 443).unwrap();
        {
            let mut conn = pool.dial(&target).await.unwrap();
            assert_eq!(pooled_request(&mut conn, b"one").await, b"one");
            conn.shutdown().await.unwrap();
            let mut tail = [0u8; 3];
            let _ = pooled_read_timeout(&mut conn, &mut tail).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(pool.idle_len().await, 1, "conn parked");
        tokio::time::sleep(Duration::from_millis(200)).await; // past max_age
        {
            let mut conn = pool.dial(&target).await.unwrap();
            assert_eq!(pooled_request(&mut conn, b"two").await, b"two");
            conn.shutdown().await.unwrap();
            let mut tail = [0u8; 3];
            let _ = pooled_read_timeout(&mut conn, &mut tail).await;
        }
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn pool_concurrent_dials_each_get_a_conn() {
        // No pooled conn is handed to two users at once: concurrent
        // dials take the one cached conn plus fresh transports
        // (GetContext pops, never shares).
        let psk = test_psk();
        let (pool, counter) = pool_with_dial_counter(&psk, 4);
        let target = NetAddr::domain("echo.example", 443).unwrap();
        // Park one conn first.
        {
            let mut conn = pool.dial(&target).await.unwrap();
            assert_eq!(pooled_request(&mut conn, b"park").await, b"park");
            conn.shutdown().await.unwrap();
            let mut tail = [0u8; 4];
            let _ = pooled_read_timeout(&mut conn, &mut tail).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut a = pool.dial(&target).await.unwrap(); // reuses the parked one
        let mut b = pool.dial(&target).await.unwrap(); // fresh transport
        let mut c = pool.dial(&target).await.unwrap(); // fresh transport
        let (ra, rb, rc) = tokio::join!(
            pooled_request(&mut a, b"aaa"),
            pooled_request(&mut b, b"bbb"),
            pooled_request(&mut c, b"ccc"),
        );
        assert_eq!(ra, b"aaa".to_vec());
        assert_eq!(rb, b"bbb".to_vec());
        assert_eq!(rc, b"ccc".to_vec());
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn pool_v2_and_version_gates() {
        // v2 pools (reuse always on); v1/v3 never pool (adapter
        // snell.go:252).
        let psk = test_psk();
        let (pool, counter) = pool_with_dial_counter(&psk, 2);
        let target = NetAddr::domain("echo.example", 443).unwrap();
        {
            let mut conn = pool.dial(&target).await.unwrap();
            assert_eq!(pooled_request(&mut conn, b"v2-p").await, b"v2-p");
            conn.shutdown().await.unwrap();
            let mut tail = [0u8; 4];
            let _ = pooled_read_timeout(&mut conn, &mut tail).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        {
            let mut conn = pool.dial(&target).await.unwrap();
            assert_eq!(pooled_request(&mut conn, b"v2-q").await, b"v2-q");
            conn.shutdown().await.unwrap();
            let mut tail = [0u8; 4];
            let _ = pooled_read_timeout(&mut conn, &mut tail).await;
        }
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 1);
        for version in [1u8, 3] {
            let err = match SnellPool::new(SnellOut {
                fronting: None,
                server: "127.0.0.1".into(),
                port: 0,
                psk: psk.clone(),
                version,
                udp: false,
            }) {
                Ok(_) => panic!("version {version} must not pool"),
                Err(e) => e,
            };
            assert!(err.to_string().contains("version"), "{err}");
        }
        // v5 normalizes to 4 → pools fine (adapter snell.go:248-252).
        assert!(SnellPool::new(SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: psk.clone(),
            version: 5,
            udp: false,
        })
        .is_ok());
    }

    async fn timeout_read(stream: &mut BoxProxyStream, buf: &mut [u8]) -> io::Result<usize> {
        tokio::time::timeout(Duration::from_secs(10), stream.read(buf))
            .await
            .expect("snell read timed out")
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // ------------------------------------------------ server half (wave-10)

    /// A relay-side echo over the server stream (what the listener hands
    /// to `hand_off`): echo until the client half-closes, then drop —
    /// Drop runs the close semantics.
    async fn relay_echo(mut stream: SnellServerTcp) {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = stream.flush().await;
                }
            }
        }
    }

    /// Run the server request loop over one duplex conn, mirroring the
    /// listener's serve_loop (without the relay plumbing). One request
    /// per entry — reuse re-enters through the continuation.
    async fn server_loop(conn: SnellServerConn) -> Result<()> {
        let mut conn = conn;
        match conn.read_request().await? {
            SnellServerRequest::Ping => Ok(()),
            SnellServerRequest::Udp { .. } => {
                conn.write_tunnel_reply().await?;
                let mut udp = conn.into_udp();
                let mut buf = vec![0u8; MAX_LENGTH + 32];
                loop {
                    let n = match udp.read(&mut buf).await {
                        Ok(0) | Err(_) => return Ok(()),
                        Ok(n) => n,
                    };
                    let (target, payload) = parse_snell_udp_request(&buf[..n])?;
                    let from = NetAddr::ip(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 4, 4)),
                        target.port,
                    );
                    let frame = snell_udp_response_frame(&from, &payload)?;
                    if udp.write_all(&frame).await.is_err() {
                        return Ok(());
                    }
                    let _ = udp.flush().await;
                }
            }
            SnellServerRequest::Connect { reuse, .. } => {
                let next: SnellServerNext = std::sync::Arc::new(move |conn| {
                    // Standalone boxing: an inline async block here
                    // makes the loop's own generator prove its own
                    // Send (the same recursion the listener breaks
                    // with continue_serve_loop).
                    fn reenter(
                        conn: SnellServerConn,
                    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
                        Box::pin(async move {
                            let _ = server_loop(conn).await;
                        })
                    }
                    reenter(conn)
                });
                let tcp = conn.into_tcp(reuse, Some(next));
                relay_echo(tcp).await;
                Ok(())
            }
        }
    }

    async fn spawn_server(version: u8, psk: &str) -> tokio::io::DuplexStream {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let psk = psk.as_bytes().to_vec();
        tokio::spawn(async move {
            let conn = SnellServerConn::new(Box::new(server), &psk, version).unwrap();
            if let Err(e) = server_loop(conn).await {
                panic!("snell server loop failed: {e}");
            }
        });
        client
    }

    #[tokio::test]
    async fn server_tcp_roundtrip_all_versions() {
        // The engine's own client (each wire version) relays through the
        // server half: request → tunnel-prefixed echo.
        for version in [1u8, 2, 3, 4] {
            let psk = test_psk();
            let transport = spawn_server(version, &psk).await;
            let cfg = SnellOut {
            fronting: None,
                server: "127.0.0.1".into(),
                port: 0,
                psk: psk.clone(),
                version,
                udp: false,
            };
            let target = NetAddr::domain("echo.example", 443).unwrap();
            let mut stream = handshake(Box::new(transport), &cfg, &target, false)
                .await
                .unwrap();
            let ping = format!("ping-v{version}");
            stream.write_all(ping.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; ping.len()];
            timeout_read(&mut stream, &mut buf).await.unwrap();
            assert_eq!(&buf, ping.as_bytes());
        }
    }

    #[tokio::test]
    async fn server_v5_accepts_v4_wire() {
        // A v5 server rides the v4 codec (StreamConn's >= Version4
        // route); a v4 client interops (listener/snell/server.go:41).
        let psk = test_psk();
        let transport = spawn_server(5, &psk).await;
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: psk.clone(),
            version: 4,
            udp: false,
        };
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut stream = handshake(Box::new(transport), &cfg, &target, false)
            .await
            .unwrap();
        stream.write_all(b"v4-to-v5").await.unwrap();
        let mut buf = [0u8; 8];
        timeout_read(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"v4-to-v5");
    }

    #[tokio::test]
    async fn server_reuse_loop_serves_second_request() {
        // The pooled client (CommandConnectV2 + zero-chunk close) gets a
        // second request served over the SAME server conn — the Drop
        // continuation back into the request loop
        // (listener/snell/server.go:166-171).
        let psk = test_psk();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let psk2 = psk.clone();
        tokio::spawn(async move {
            let conn = SnellServerConn::new(Box::new(server), psk2.as_bytes(), 4).unwrap();
            if let Err(e) = server_loop(conn).await {
                panic!("snell server loop failed: {e}");
            }
        });
        let client = std::sync::Mutex::new(Some(client));
        let pool = SnellPool::with_dialer(
            SnellOut {
                fronting: None,
                server: "127.0.0.1".into(),
                port: 0,
                psk,
                version: 4,
                udp: false,
            },
            move || {
                let c = client.lock().unwrap().take().expect("only one transport");
                Box::pin(async move { Ok(Box::new(c) as BoxProxyStream) })
            },
        )
        .unwrap();
        let target = NetAddr::domain("echo.example", 443).unwrap();
        {
            let mut conn = pool.dial(&target).await.unwrap();
            assert_eq!(pooled_request(&mut conn, b"first").await, b"first");
            conn.shutdown().await.unwrap();
            let mut tail = [0u8; 4];
            let n = pooled_read_timeout(&mut conn, &mut tail).await.unwrap();
            assert_eq!(n, 0, "the server's zero chunk is a clean EOF");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(pool.idle_len().await, 1, "the conn recycled");
        {
            let mut conn = pool.dial(&target).await.unwrap();
            assert_eq!(pooled_request(&mut conn, b"seco").await, b"seco");
            conn.shutdown().await.unwrap();
            let mut tail = [0u8; 4];
            let _ = pooled_read_timeout(&mut conn, &mut tail).await;
        }
    }

    #[tokio::test]
    async fn server_wrong_psk_rejects_before_reply() {
        // The server cannot decrypt the request header; the conn dies
        // with no tunnel data (wrong PSK ⇒ no reply).
        let psk = test_psk();
        let transport = spawn_server(4, &psk).await;
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: format!("wrong-{psk}"),
            version: 4,
            udp: false,
        };
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut stream = handshake(Box::new(transport), &cfg, &target, false)
            .await
            .unwrap();
        let _ = stream.write_all(b"ping").await;
        let mut buf = [0u8; 8];
        match timeout_read(&mut stream, &mut buf).await {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("a wrong PSK must not produce tunnel data ({n} bytes)"),
        }
    }

    #[tokio::test]
    async fn server_udp_session_roundtrip_v3_v4() {
        // The engine's UDP client through the server session: request
        // packets are parsed, responses sealed one frame per datagram.
        for version in [3u8, 4] {
            let psk = test_psk();
            let transport = spawn_server(version, &psk).await;
            let cfg = SnellOut {
            fronting: None,
                server: "127.0.0.1".into(),
                port: 0,
                psk: psk.clone(),
                version,
                udp: true,
            };
            let mut udp = udp_session(&cfg, Box::new(transport)).await.unwrap();
            let target = NetAddr::ip("8.8.8.8".parse().unwrap(), 53);
            udp.send_to(&target, b"query").await.unwrap();
            let mut buf = [0u8; 1500];
            let (from, n) =
                tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
                    .await
                    .expect("udp response timeout")
                    .unwrap();
            assert_eq!(from.host, Host::Ip("8.8.4.4".parse().unwrap()));
            assert_eq!(from.port, 53);
            assert_eq!(&buf[..n], b"query");
        }
    }

    #[tokio::test]
    async fn server_udp_handles_domain_requests() {
        // A domain request packet parses on the uplink
        // (ParseUDPRequest's socks-domain form); responses are IP-only
        // by design (snell_udp_response_frame errors on domains).
        let psk = test_psk();
        let transport = spawn_server(4, &psk).await;
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk: psk.clone(),
            version: 4,
            udp: true,
        };
        let mut udp = udp_session(&cfg, Box::new(transport)).await.unwrap();
        let target = NetAddr::domain("dns.example", 53).unwrap();
        udp.send_to(&target, b"dom").await.unwrap();
        let mut buf = [0u8; 1500];
        let (from, n) =
            tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
                .await
                .expect("udp response timeout")
                .unwrap();
        assert_eq!(from.port, 53);
        assert_eq!(&buf[..n], b"dom");
        let err = snell_udp_response_frame(&target, b"x").unwrap_err();
        assert!(err.to_string().contains("must be an IP"), "{err}");
    }

    #[test]
    fn server_version_gate_and_error_frames() {
        // parse_server_version (listener/snell/server.go:37-44).
        assert_eq!(parse_server_version(0).unwrap(), 4);
        for v in [1u8, 2, 3, 4, 5] {
            assert_eq!(parse_server_version(v).unwrap(), v);
        }
        let err = parse_server_version(6).unwrap_err();
        assert!(
            err.to_string().contains("snell inbound version 6 is not supported"),
            "{err}"
        );
        // writeCommandError layout: CommandError || code || msglen || msg.
        let frame = command_error_frame(REMOTE_EOF_CODE, "Remote EOF");
        assert_eq!(&frame[..3], &[CMD_ERROR, 0x65, 10]);
        assert_eq!(&frame[3..], b"Remote EOF");
        // Long messages truncate at 255.
        let long = command_error_frame(1, &"x".repeat(300));
        assert_eq!(long.len(), 258);
    }

    #[tokio::test]
    async fn server_ping_gets_pong() {
        // CommandPing (0) is answered with a CommandPong frame and the
        // conn closes (listener/snell/server.go:188-191). Drive the
        // wire by hand with the v3 mimic.
        let psk = test_psk();
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let psk2 = psk.clone();
        tokio::spawn(async move {
            let mut conn =
                SnellServerConn::new(Box::new(server), psk2.as_bytes(), 3).unwrap();
            match conn.read_request().await {
                Ok(SnellServerRequest::Ping) => {} // answered inline
                other => panic!("expected Ping, got {other:?}"),
            }
        });
        // Client side: salt + one chunk holding [Version, CommandPing].
        let mut out_salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut out_salt);
        client.write_all(&out_salt).await.unwrap();
        let mut enc = V3Mimic::new(AeadKind::Aes128Gcm, psk.as_bytes(), &out_salt);
        let mut wire = Vec::new();
        enc.frame_chunk(&[PROTOCOL_VERSION, CMD_PING], &mut wire);
        client.write_all(&wire).await.unwrap();
        // Server: fresh salt + one chunk == [CommandPong].
        let salt = read_n(&mut client, 16).await.unwrap();
        let mut dec = V3Mimic::new(AeadKind::Aes128Gcm, psk.as_bytes(), &salt);
        let pong = dec.read_chunk(&mut client).await.unwrap();
        assert_eq!(pong, vec![CMD_PONG]);
    }

    #[tokio::test]
    async fn http_obfs_server_accepts_engine_client() {
        // The engine's http-obfs client (proto::obfs) through the server
        // wrapper: request head + body, 101 response head, then raw.
        let (client, server) = tokio::io::duplex(64 * 1024);
        let settings = crate::proto::obfs::ObfsSettings::new("cdn.example", 443);
        let client = crate::proto::obfs::http_obfs_client(Box::new(client), &settings)
            .await
            .unwrap();
        let psk = test_psk();
        let psk2 = psk.clone();
        tokio::spawn(async move {
            let wrapped = http_obfs_server(Box::new(server)).await.unwrap();
            let conn = SnellServerConn::new(wrapped, psk2.as_bytes(), 4).unwrap();
            if let Err(e) = server_loop(conn).await {
                panic!("obfs server loop failed: {e}");
            }
        });
        let cfg = SnellOut {
            fronting: None,
            server: "127.0.0.1".into(),
            port: 0,
            psk,
            version: 4,
            udp: false,
        };
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut stream = handshake(client, &cfg, &target, false).await.unwrap();
        stream.write_all(b"obfs-echo").await.unwrap();
        let mut buf = [0u8; 9];
        timeout_read(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"obfs-echo");
    }

    #[tokio::test]
    async fn http_obfs_server_rejects_plain_http() {
        // http_server.go:46-47 — a non-upgrade GET is rejected before
        // any snell work.
        let (mut client, server) = tokio::io::duplex(4 * 1024);
        let handle = tokio::spawn(async move { http_obfs_server(Box::new(server)).await });
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let res = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("timeout")
            .unwrap();
        let err = res.err().expect("a plain GET must be rejected").to_string();
        assert!(err.contains("websocket upgrade"), "{err}");
    }

    #[test]
    fn http_obfs_server_head_pieces() {
        // The 101 head shape (http_server.go:68-74).
        let head = http_response_head();
        assert!(head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(head.contains("Server: nginx/1."));
        assert!(head.contains("Upgrade: websocket\r\n"));
        assert!(head.contains("Connection: Upgrade\r\n"));
        assert!(head.contains("Sec-WebSocket-Accept: "));
        assert!(head.ends_with("\r\n\r\n"));
        // nginx versions stay in the upstream ranges.
        let (major, minor) = nginx_version();
        assert!(major < 11 && minor < 12);
        // The Date is an RFC1123 GMT timestamp.
        let date = rfc1123_now();
        assert!(date.ends_with("GMT"), "{date}");
        assert_eq!(date.len(), 29, "RFC1123 length: {date}");
        // Request-head parsing: method + connection + content-length.
        let parsed = parse_http_request_head(
            b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 7\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();
        assert_eq!(parsed.method, "GET");
        assert!(parsed.connection_upgrade);
        assert_eq!(parsed.content_length, 7);
        // Malformed request lines are parse errors; a valid non-GET
        // method parses (the GET gate lives in consume_request).
        assert!(parse_http_request_head(b"garbage\r\n\r\n").is_err());
        assert_eq!(
            parse_http_request_head(b"POST / HTTP/1.1\r\n\r\n")
                .unwrap()
                .method,
            "POST"
        );
        let parsed =
            parse_http_request_head(b"GET / HTTP/1.1\r\nconnection: keep-alive\r\n\r\n").unwrap();
        assert!(!parsed.connection_upgrade);
    }

    #[test]
    fn server_udp_response_frame_layouts() {
        // WritePacketResponse (snell.go:246-282): 04/06 + ip + port +
        // payload.
        let from = NetAddr::ip("1.2.3.4".parse().unwrap(), 53);
        assert_eq!(
            snell_udp_response_frame(&from, b"ok").unwrap(),
            vec![0x04, 1, 2, 3, 4, 0, 53, b'o', b'k']
        );
        let from = NetAddr::ip("::1".parse().unwrap(), 53);
        let frame = snell_udp_response_frame(&from, b"z").unwrap();
        assert_eq!(frame[0], 0x06);
        assert_eq!(&frame[1..16], &[0u8; 15]);
        assert_eq!(frame[16], 1);
        assert_eq!(u16::from_be_bytes([frame[17], frame[18]]), 53);
        assert_eq!(&frame[19..], b"z");
        // The client's response parser round-trips it (ReadPacket).
        let (addr, payload) = parse_snell_udp_response(&frame).unwrap();
        assert_eq!(addr.host, Host::Ip("::1".parse().unwrap()));
        assert_eq!(payload, b"z".to_vec());
    }
}
