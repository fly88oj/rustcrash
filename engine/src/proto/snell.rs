//! Snell v3/v4 outbound, ported from mihomo's `transport/snell`
//! (`snell.go`, `v4.go`, `cipher.go`) and the Shadowsocks-AEAD framing it
//! reuses for v3 (`transport/shadowsocks/shadowaead/stream.go`).
//!
//! Wire behaviour as the snell server sees it:
//!
//! * **v3** is the Shadowsocks AEAD stream with a snell-specific KDF: a
//!   random 16-byte salt prefixes each direction, subkey =
//!   `argon2id(psk, salt, t=3, m=8KiB, p=1, len=32)[:16]`
//!   (cipher.go `snellKDF`), then `[enc(len be16)][enc(chunk)]` frames
//!   under AES-128-GCM with a little-endian counter nonce per direction.
//! * **v4** (v4.go) drops the SS framing for its own: the first frame
//!   carries a random 16-byte salt, then per frame a sealed 7-byte header
//!   (`ver=4`, `be16 padding len`, `be16 payload len`), optional padding
//!   bytes (only on the very first frame, length `0x100 + rand(0x100)`)
//!   every-other-byte swapped with the sealed payload, then the sealed
//!   payload; the payload chunk size ramps from ~MTU to 0x3FFF
//!   (`nextPayloadLimit`).
//! * The request header (`WriteHeaderWithReuse`): `0x01 || cmd || 0x00 ||
//!   hostlen || host || port_be16` with cmd `0x01` (TCP connect; v2/reuse
//!   would send `0x05`, out of scope). UDP opens with `0x01 0x06 0x00`
//!   instead (v3+ only; v4 then also waits for the reply).
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
//! * **Connection reuse pool** (`pool.go`, v2 / v4 `reuse`): half-close
//!   zero-chunks, `CommandConnectV2` and idle pooling are the outbound
//!   layer's job; this module always sends `CommandConnect` (mihomo's
//!   default without `reuse: true`).
//! * **UDP relay glue**: [`snell_udp_frame`] /
//!   [`parse_snell_udp_response`] implement the packet codecs (snell.go
//!   `writePacket` / `ReadPacket`); muxing datagrams over one session is
//!   the integrator's UDP path (`handshake(_, _, _, true)` opens the UDP
//!   session).
//! * **obfs plugins** (`obfs-opts`: http/tls/shadow-tls/restls/jls):
//!   `handshake` takes the post-dial stream, so the integrator wraps
//!   before calling, exactly like mihomo's `streamConnContext`.
//! * **v1/v2** (chacha20 v1, pooling v2) and v5 servers (mihomo maps v5
//!   clients down to v4).

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Instant;

use bytes::{Buf, BytesMut};
use rand::Rng;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

use crate::addr::{Host, NetAddr};
use crate::error::{Error, Result};
use crate::proto::aead::{Aead, AeadKind, SsNonce};
use crate::stream::BoxProxyStream;

/// `Version` byte that prefixes every snell request (snell.go:40,106).
const PROTOCOL_VERSION: u8 = 0x01;
/// `CommandConnect` (snell.go:31) — plain TCP request.
const CMD_CONNECT: u8 = 0x01;
/// `CommandUDP` (snell.go:33) — UDP session open (v3+).
const CMD_UDP: u8 = 0x06;
/// `CommandTunnel` (snell.go:36) — the successful reply byte.
const CMD_TUNNEL: u8 = 0x00;
/// `CommandError` (snell.go:38).
const CMD_ERROR: u8 = 0x02;
/// `CommondUDPForward` (snell.go:34) — snell UDP packet prefix.
const CMD_UDP_FORWARD: u8 = 0x01;

/// `maxLength` (snell.go:26): largest snell payload / v3 chunk.
const MAX_LENGTH: usize = 0x3FFF;
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

/// Outbound Snell endpoint (mihomo `proxies: type: snell`).
#[derive(Debug, Clone)]
pub struct SnellOut {
    pub server: String,
    pub port: u16,
    /// Pre-shared key (`psk`).
    pub psk: String,
    /// Protocol version, `3` or `4` (mihomo maps v5 servers down to v4).
    pub version: u8,
    /// Whether the outbound advertises UDP support.
    pub udp: bool,
}

/// The TCP request header, `WriteHeaderWithReuse` with `reuse=false`
/// (snell.go:103-126): `version=1, CommandConnect, clientID len=0,
/// host len u8, host, port be16`. The host is `metadata.String()` — the
/// domain or IP text.
fn request_header(target: &NetAddr) -> Result<Vec<u8>> {
    let host = target.host.to_text();
    let bytes = host.as_bytes();
    if bytes.len() > 255 {
        return Err(Error::protocol(format!(
            "snell: target host exceeds 255 bytes: {host}"
        )));
    }
    let mut buf = Vec::with_capacity(4 + bytes.len());
    buf.push(PROTOCOL_VERSION);
    buf.push(CMD_CONNECT);
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
/// t=3, m=8 KiB, p=1, truncated to the cipher key size (16 bytes for
/// both v3 AES-128-GCM and v4).
fn snell_kdf(psk: &[u8], salt: &[u8], key_size: usize) -> Result<Vec<u8>> {
    let full = argon2id::hash(psk, salt, &[], &[], 3, 8, 1, 32);
    if full.len() < key_size {
        return Err(Error::crypto("snell: argon2 tag shorter than key"));
    }
    Ok(full[..key_size].to_vec())
}

fn snell_aead(psk: &[u8], salt: &[u8]) -> Result<Aead> {
    Aead::new(AeadKind::Aes128Gcm, &snell_kdf(psk, salt, 16)?)
}

// ---------------------------------------------------------------------------
// v3 framing (shadowaead/stream.go)
// ---------------------------------------------------------------------------

/// v3 connection: SS-AEAD framing with the snell KDF.
///
/// Write (stream.go:252-266, 31-62): the first write emits a fresh random
/// 16-byte salt, then per chunk `seal(len be16)` (2+16 bytes) and
/// `seal(payload)`; the 12-byte nonce is a LE counter per direction
/// (stream.go:200-207).
/// Read (stream.go:219-237, 106-137): read the peer's salt once, then
/// `[open(2+16)][open(len+16)]` chunks; a zero-length chunk is the
/// half-close signal (ErrZeroChunk → clean EOF here).
struct V3Conn {
    inner: BoxProxyStream,
    psk: Vec<u8>,
    writer: Option<V3Crypto>,
    reader: Option<V3Crypto>,
    /// Read stage — like Go's blocking ReadFull sequence, no AEAD open
    /// happens until the stage's bytes are fully buffered (a nonce is
    /// consumed only when its ciphertext is consumed).
    stage: V3Stage,
    rbuf: BytesMut,
    out: BytesMut,
    eof: bool,
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
    fn new(inner: BoxProxyStream, psk: &[u8]) -> Self {
        V3Conn {
            inner,
            psk: psk.to_vec(),
            writer: None,
            reader: None,
            stage: V3Stage::Len,
            rbuf: BytesMut::with_capacity(16 * 1024),
            out: BytesMut::with_capacity(16 * 1024),
            eof: false,
        }
    }

    /// Append the wire form of `payload` to `wbuf` (chunks of 0x3FFF,
    /// each `seal(len)` then `seal(chunk)`).
    fn frame(&mut self, payload: &[u8], wbuf: &mut BytesMut) -> Result<()> {
        if self.writer.is_none() {
            let mut salt = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            wbuf.extend_from_slice(&salt);
            self.writer = Some(V3Crypto {
                aead: snell_aead(&self.psk, &salt)?,
                nonce: SsNonce::new(),
            });
        }
        let w = self.writer.as_mut().expect("initialized above");
        let mut chunk_out = Vec::with_capacity(V3_CHUNK + TAG_SIZE + 2 + TAG_SIZE);
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
    /// landed, `Ok(false)` when more wire bytes are needed (or EOF).
    /// The stage machine consumes bytes AND a nonce tick together, so an
    /// open never happens twice for the same ciphertext; stage
    /// transitions loop internally so no inner read is needed to advance.
    fn try_parse(&mut self) -> Result<bool> {
        if self.reader.is_none() {
            if self.rbuf.len() < 16 {
                return Ok(false);
            }
            let salt = self.rbuf[..16].to_vec();
            self.rbuf.advance(16);
            self.reader = Some(V3Crypto {
                aead: snell_aead(&self.psk, &salt)?,
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
                        self.eof = true; // ErrZeroChunk (stream.go:123-125)
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
    eof: bool,
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
        let aead = snell_aead(psk, &salt)?;
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
            eof: false,
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
                aead: snell_aead(&self.psk, &salt)?,
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
                        self.eof = true; // ErrZeroChunk (v4.go:201-206)
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

    /// Read + decrypt until at least one chunk lands in `out` (or EOF).
    /// `Ok(true)` = progress, `Ok(false)` = stream at EOF.
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
            let (eof, rbuf, inner) = match self {
                Conn::V3(c) => (c.eof, &mut c.rbuf, &mut c.inner),
                Conn::V4(c) => (c.eof, &mut c.rbuf, &mut c.inner),
            };
            if eof {
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
        let conn = match cfg.version {
            3 => Conn::V3(V3Conn::new(inner, psk)),
            4 => Conn::V4(V4Conn::new(inner, psk)?),
            other => {
                return Err(Error::config(format!(
                    "snell: unsupported version {other} (mihomo supports 3 and 4)"
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
/// * TCP: writes the encrypted request header (`0x01 0x01 0x00 hostlen
///   host port_be16`); the server's tunnel/error reply is consumed
///   lazily on the first read, like mihomo's `Snell.Read`.
/// * UDP (v3+): writes `0x01 0x06 0x00`; v4 additionally waits for the
///   reply here (adapter/outbound/snell.go:88-95). Packet bodies use
///   [`snell_udp_frame`] / [`parse_snell_udp_response`].
///
/// The dial sequence is the integrator's: TCP (plus any obfs plugin)
/// → this handshake → relay.
pub async fn handshake(
    stream: BoxProxyStream,
    cfg: &SnellOut,
    target: &NetAddr,
    is_udp: bool,
) -> Result<BoxProxyStream> {
    if cfg.psk.is_empty() {
        return Err(Error::config("snell: psk is required"));
    }
    if !matches!(cfg.version, 3 | 4) {
        return Err(Error::config(format!(
            "snell: unsupported version {} (expected 3 or 4)",
            cfg.version
        )));
    }
    debug!(
        target: "engine",
        server = %cfg.server, port = cfg.port, version = cfg.version, udp = is_udp,
        "snell: starting handshake"
    );
    let mut snell = SnellStream::new(stream, cfg)?;
    if is_udp {
        snell.write_all(&udp_header()).await?;
        snell.flush().await?;
        if cfg.version >= 4 {
            snell.wait_reply().await?;
        }
    } else {
        snell.write_all(&request_header(target)?).await?;
        snell.flush().await?;
    }
    debug!(target: "engine", "snell: request sent");
    Ok(Box::new(snell))
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
/// 291-335) — the server-side mirror; exercised by the loopback mimic.
#[cfg(test)]
fn parse_snell_udp_request(frame: &[u8]) -> Result<(NetAddr, Vec<u8>)> {
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

#[cfg(test)]
mod tests {
    use super::*;
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
        // 01 01 00 hostlen host port_be16
        let target = NetAddr::domain("example.com", 443).unwrap();
        assert_eq!(
            request_header(&target).unwrap(),
            vec![
                0x01, 0x01, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
                b'm', 0x01, 0xbb
            ]
        );
        let target = NetAddr::ip("127.0.0.1".parse().unwrap(), 80);
        assert_eq!(
            request_header(&target).unwrap(),
            vec![
                0x01, 0x01, 0x00, 9, b'1', b'2', b'7', b'.', b'0', b'.', b'0', b'.', b'1', 0x00,
                0x50
            ]
        );
        // Hosts beyond a u8 length are refused (not silently truncated).
        let long = NetAddr::new(Host::Domain("a".repeat(256)), 80);
        let err = request_header(&long).unwrap_err();
        assert!(err.to_string().contains("255"), "{err}");
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

    /// Test-side v3 crypto half (mirrors shadowaead Reader/Writer).
    struct V3Mimic {
        aead: Aead,
        nonce: SsNonce,
    }

    impl V3Mimic {
        fn new(psk: &[u8], salt: &[u8]) -> Self {
            V3Mimic {
                aead: snell_aead(psk, salt).unwrap(),
                nonce: SsNonce::new(),
            }
        }

        async fn read_chunk(&mut self, rd: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
            let len_ct = read_n(rd, 2 + TAG_SIZE).await?;
            let len_pt = self.aead.open(&self.nonce.advance(), b"", &len_ct).unwrap();
            let size = (((len_pt[0] as usize) << 8) | len_pt[1] as usize) & MAX_LENGTH;
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
    }

    /// v3 server mimic: verify the request header, reply tunnel, echo.
    async fn v3_server_mimic(io: DuplexStream, psk: Vec<u8>) -> Result<()> {
        let (mut rd, mut wr) = tokio::io::split(io);
        let salt = read_n(&mut rd, 16).await.map_err(Error::from)?;
        let mut dec = V3Mimic::new(&psk, &salt);

        let header = dec.read_chunk(&mut rd).await.map_err(Error::from)?;
        assert_eq!(&header[..3], &[PROTOCOL_VERSION, CMD_CONNECT, 0x00]);
        let host_len = header[3] as usize;
        let host = String::from_utf8(header[4..4 + host_len].to_vec()).unwrap();
        let port = u16::from_be_bytes([header[4 + host_len], header[5 + host_len]]);
        assert_eq!((host.as_str(), port), ("echo.example", 443));

        let mut out_salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut out_salt);
        let mut enc = V3Mimic::new(&psk, &out_salt);
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
                aead: snell_aead(psk, salt).unwrap(),
                nonce: SsNonce::new(),
            }
        }

        async fn read_frame(&mut self, rd: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
            let header_ct = read_n(rd, V4_HEADER_CIPHER).await?;
            let header = self.aead.open(&self.nonce.advance(), b"", &header_ct).unwrap();
            assert_eq!(header[0], 4);
            let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
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
        fn frame(&mut self, payload: &[u8], out: &mut Vec<u8>) {
            let mut header = [0u8; V4_HEADER_PLAIN];
            header[0] = 4;
            header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            self.aead.seal(&self.nonce.advance(), b"", &header, out).unwrap();
            self.aead.seal(&self.nonce.advance(), b"", payload, out).unwrap();
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
        assert_eq!(payload, request_header(&target).unwrap());

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

    #[tokio::test]
    async fn v4_wrong_psk_fails() {
        let psk = test_psk();
        let cfg = SnellOut {
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
        let cfg = SnellOut {
            server: "x".into(),
            port: 1,
            psk: "p".into(),
            version: 2,
            udp: false,
        };
        let target = NetAddr::domain("t.test", 80).unwrap();
        let err = match handshake(Box::new(tokio::io::duplex(16).0), &cfg, &target, false).await {
            Ok(_) => panic!("version 2 must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("version"), "{err}");
    }

    async fn timeout_read(stream: &mut BoxProxyStream, buf: &mut [u8]) -> io::Result<usize> {
        tokio::time::timeout(Duration::from_secs(10), stream.read(buf))
            .await
            .expect("snell read timed out")
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
