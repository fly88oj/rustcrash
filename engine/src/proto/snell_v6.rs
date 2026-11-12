//! Snell v6 record layer, ported from mihomo's `transport/snell/v6.go`
//! and `transport/snell/v6_profile.go` (upstream f1f640b), wired by
//! `StreamConnV6`/`ServerStreamConnV6` (transport/snell/snell.go:180-190)
//! and the listener's v6 gates (listener/snell/server.go:60-72).
//!
//! Wire behaviour as the snell server sees it:
//!
//! * **v6 keeps the v4 record layout** — a 7-byte plaintext header
//!   (`ver=4` — yes, still 4, v6.go:63 — `rsv`, `rsv`, `padLen be16`,
//!   `payloadLen be16`) sealed with AES-128-GCM (23 bytes with the tag),
//!   then the sealed payload — but wraps it in a PSK-derived "profile":
//!   the 16-byte salt is scattered inside a padded first block
//!   (`saltBlockLen = 16 + PRF(0x10..0x80)`), every record carries an
//!   unencrypted prefix (8..0x80 bytes, per-sequence, used as the
//!   header's AAD), padding is interleaved with the payload ciphertext
//!   and record sizes follow a shaped chunk schedule (v6.go:17-23).
//! * **`default` (shaped)**: everything above. The reserved header bytes
//!   are IGNORED by the reader (v6.go:511-512).
//! * **`unshaped`**: drops the profile layer — a v4-like 16-byte random
//!   salt prefix, then sealed records with no padding and a STRICT
//!   reserved-byte check (v6.go:273-284, 376-381).
//! * **`unsafe-raw`**: drops the crypto as well — plaintext header +
//!   payload, still strict, still no padding (v6.go:286-343).
//! * A zero-payload record is the end-of-stream marker in every mode
//!   (`shadowaead.ErrZeroChunk`, v6.go:304-306/383-385/519-526) — the
//!   same half-close the v1..v5 pool rides. The request/reply layer
//!   above the record stream is UNCHANGED from v4 (same bytes).
//! * `writePacketFrame` emits one UDP datagram as EXACTLY ONE record
//!   regardless of the chunk limit (v6.go:651-657) — the shaped writer
//!   still advances the chunk schedule first.
//! * Crypto: AES-128-GCM keyed by `snellKDF(psk, salt, 16)` (the shared
//!   argon2id KDF, v6.go:253-255), 12-byte nonce incremented per
//!   Seal/Open (`incrementV4Nonce`, the LE counter already used by v4).
//! * The profile derivation follows the protocol notes published by
//!   SagerNet/sing-snell, referencing Surge 6.7.0 (11520) — every
//!   constant below is transcribed byte-for-byte from v6_profile.go
//!   with its Go line cited; a one-bit drift changes the wire.
//!
//! Both peers derive the same profile from the PSK, so the module is
//! self-contained: [`V6Profile`] (pure functions of the PSK) plus
//! [`V6Conn`], which mirrors the `Conn` interface `proto::snell`'s
//! v3/v4 codecs expose (framing a write buffer into records, `try_parse`
//! on the read buffer, salt exchange init).

use bytes::{Buf, BytesMut};

use crate::error::{Error, Result};
use crate::proto::aead::{Aead, AeadKind, SsNonce};
use crate::stream::BoxProxyStream;

// ---------------------------------------------------------------------------
// Mode + config gates (v6.go:25-83, adapter/outbound/snell.go:258-285)
// ---------------------------------------------------------------------------

/// `V6Mode` (v6.go:25-31): Default = shaped (the profile layer),
/// Unshaped = sealed records without the profile, UnsafeRaw = plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum V6Mode {
    #[default]
    Default,
    Unshaped,
    UnsafeRaw,
}

impl std::fmt::Display for V6Mode {
    /// `V6Mode.String` (v6.go:46-57).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            V6Mode::Default => "default",
            V6Mode::Unshaped => "unshaped",
            V6Mode::UnsafeRaw => "unsafe-raw",
        })
    }
}

/// `ParseV6Mode` (v6.go:33-44): "" and "default" are the shaped mode.
/// Unknown values name the three accepted ones.
pub fn parse_v6_mode(name: &str) -> Result<V6Mode> {
    match name {
        "" | "default" => Ok(V6Mode::Default),
        "unshaped" => Ok(V6Mode::Unshaped),
        "unsafe-raw" => Ok(V6Mode::UnsafeRaw),
        other => Err(Error::config(format!(
            "snell v6 unknown mode: {other} (expected one of: default, unshaped, unsafe-raw)"
        ))),
    }
}

/// The official server rejects PSKs outside this range (v6.go:67-69).
pub const V6_MIN_PSK_LENGTH: usize = 12;
pub const V6_MAX_PSK_LENGTH: usize = 255;

/// `ValidateV6PSK` (v6.go:78-83).
pub fn validate_v6_psk(psk: &[u8]) -> Result<()> {
    if psk.len() < V6_MIN_PSK_LENGTH || psk.len() > V6_MAX_PSK_LENGTH {
        return Err(Error::config(format!(
            "snell v6 psk length must be between {V6_MIN_PSK_LENGTH} and {V6_MAX_PSK_LENGTH} bytes"
        )));
    }
    Ok(())
}

/// `mode` is only a v6 setting: versions 1..=5 reject any non-empty
/// value ("snell inbound mode is only supported on version 6",
/// listener/snell/server.go:42-45; the outbound's
/// "snell %s mode is only supported on version 6",
/// adapter/outbound/snell.go:283-285). `what` is the "inbound" /
/// proxy-name prefix of the message.
pub fn validate_mode_for_version(version: u8, mode: &str, what: &str) -> Result<()> {
    if !mode.is_empty() && version != 6 {
        return Err(Error::config(format!(
            "snell {what} mode is only supported on version 6"
        )));
    }
    Ok(())
}

/// v6 replaced the simple-obfs layer with PSK-derived traffic shaping:
/// http/tls are rejected on v6 both sides (adapter/outbound/snell.go
/// :270-274 "snell %s version 6 does not support obfs mode %s" with the
/// proxy address; listener/snell/server.go:64-67 with "inbound").
pub fn validate_v6_obfs(obfs_mode: &str, what: &str) -> Result<()> {
    if matches!(obfs_mode, "http" | "tls") {
        return Err(Error::config(format!(
            "snell {what} version 6 does not support obfs mode {obfs_mode}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Record-layer constants (v6.go:59-76)
// ---------------------------------------------------------------------------

/// `v6SaltSize` (v6.go:60).
const V6_SALT_SIZE: usize = 16;
/// `v6TagSize` (v6.go:62) — the GCM tag.
const V6_TAG_SIZE: usize = 16;
/// `v6HeaderVersion` (v6.go:63) — still 4 on the v6 wire.
const V6_HEADER_VERSION: u8 = 4;
/// `v6HeaderPlainSize` (v6.go:64).
const V6_HEADER_PLAIN: usize = 7;
/// `v6HeaderCipherSize` (v6.go:65) — header + tag = 23.
const V6_HEADER_CIPHER: usize = V6_HEADER_PLAIN + V6_TAG_SIZE;
/// `v6MaxPayload` (v6.go:66) — 0xffff, NOT the 0x3fff snell maxLength;
/// the record header length fields are u16.
const V6_MAX_PAYLOAD: usize = 0xffff;

/// `errV6BadHeader` (v6.go:73).
fn err_v6_bad_header() -> Error {
    Error::protocol("snell v6 invalid record header")
}

/// `errV6RecordPadding` (v6.go:74).
fn err_v6_record_padding() -> Error {
    Error::protocol("snell v6 unexpected padding in record")
}

/// `errV6PayloadTooLong` (v6.go:75).
fn err_v6_payload_too_long() -> Error {
    Error::protocol("snell v6 payload too large")
}

/// `v6AEAD` (v6.go:253-255): AES-128-GCM over the shared snell KDF
/// (`snellKDF(psk, salt, 16)`, cipher.go:29-32).
fn v6_aead(psk: &[u8], salt: &[u8]) -> Result<Aead> {
    crate::proto::snell::snell_aead(AeadKind::Aes128Gcm, psk, salt)
}

/// `v6PutHeader` (v6.go:265-271): ver, two reserved zeros, padLen be16,
/// payloadLen be16.
fn v6_put_header(header: &mut [u8; V6_HEADER_PLAIN], padding_length: usize, payload_length: usize) {
    header[0] = V6_HEADER_VERSION;
    header[1] = 0;
    header[2] = 0;
    header[3..5].copy_from_slice(&(padding_length as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload_length as u16).to_be_bytes());
}

/// `v6ParseHeader` (v6.go:273-284). `strict` additionally requires the
/// two reserved bytes to be zero — only checked outside the default
/// mode (the shaped writer/reader tolerate any reserved bytes).
fn v6_parse_header(header: &[u8], strict: bool) -> Result<(usize, usize)> {
    debug_assert_eq!(header.len(), V6_HEADER_PLAIN);
    if header[0] != V6_HEADER_VERSION {
        return Err(err_v6_bad_header());
    }
    if strict && (header[1] != 0 || header[2] != 0) {
        return Err(err_v6_bad_header());
    }
    Ok((
        u16::from_be_bytes([header[3], header[4]]) as usize,
        u16::from_be_bytes([header[5], header[6]]) as usize,
    ))
}

/// `time.Now().Unix()` — the shaped writer's idle reset is
/// second-granular (v6.go:569-571).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Profile: PRF core (v6_profile.go:19-151)
// ---------------------------------------------------------------------------

/// `v6GoldenGamma` (v6_profile.go:20) — the splitmix64 golden gamma.
const V6_GOLDEN_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;

// Label indices (v6_profile.go:22-62). v6LabelSalt aliases
// v6LabelMixOffset (both 3) and v6LabelChunkFirstCap aliases
// v6LabelChunkInitial (both 22) — kept verbatim; the labels partition
// `forLabel`'s namespace buckets below.
const LABEL_PADDING: u32 = 0; // v6LabelPadding (v6_profile.go:22)
const LABEL_BIT_PERCENT: u32 = 1; // v6LabelBitPercent (:23)
const LABEL_MOTIF: u32 = 2; // v6LabelMotif (:24)
const LABEL_MIX_OFFSET: u32 = 3; // v6LabelMixOffset == v6LabelSalt (:25-26)
const LABEL_PROFILE_ID: u32 = 5; // v6LabelProfileID (:27)
const LABEL_GENERATOR: u32 = 6; // v6LabelGenerator (:28)
const LABEL_PAD_MIN: u32 = 7; // v6LabelPadMin (:29)
const LABEL_PAD_MAX: u32 = 8; // v6LabelPadMax (:30)
const LABEL_PAD_COUNT: u32 = 9; // v6LabelPadCount (:31)
const LABEL_PAD_INTERVAL: u32 = 10; // v6LabelPadInterval (:32)
const LABEL_SMALL_LIMIT: u32 = 11; // v6LabelSmallLimit (:33)
const LABEL_BIT_MIN: u32 = 12; // v6LabelBitMin (:34)
const LABEL_BIT_MAX: u32 = 13; // v6LabelBitMax (:35)
const LABEL_PREFIX_MIN: u32 = 14; // v6LabelPrefixMin (:36)
const LABEL_PREFIX_MAX: u32 = 15; // v6LabelPrefixMax (:37)
const LABEL_MIX_MODE: u32 = 16; // v6LabelMixMode (:38)
const LABEL_MIX_ROUNDS: u32 = 17; // v6LabelMixRounds (:39)
const LABEL_MIX_STRIDE: u32 = 18; // v6LabelMixStride (:40)
const LABEL_MIX_OFFSET_BASE: u32 = 19; // v6LabelMixOffsetBase (:41)
const LABEL_MIX_BLOCK: u32 = 20; // v6LabelMixBlock (:42)
const LABEL_CHUNK_POLICY: u32 = 21; // v6LabelChunkPolicy (:43)
const LABEL_CHUNK_INITIAL: u32 = 22; // v6LabelChunkInitial (:44)
const LABEL_CHUNK_FIRST_CAP: u32 = 22; // v6LabelChunkFirstCap (:45, alias)
const LABEL_CHUNK_MAX: u32 = 23; // v6LabelChunkMax (:46)
const LABEL_CHUNK_STEP: u32 = 24; // v6LabelChunkStep (:47)
const LABEL_CHUNK_JITTER: u32 = 25; // v6LabelChunkJitter (:48)
const LABEL_CHUNK_BUCKET: u32 = 26; // v6LabelChunkBucket (:49)
const LABEL_IDLE_RESET: u32 = 27; // v6LabelIdleReset (:50)
const LABEL_WRITE_POLICY: u32 = 28; // v6LabelWritePolicy (:51)
const LABEL_WRITE_FIRST: u32 = 29; // v6LabelWriteFirst (:52)
const LABEL_WRITE_BUCKET: u32 = 30; // v6LabelWriteBucket (:53)
const LABEL_WRITE_SEQ: u32 = 31; // v6LabelWriteSeq (:54)
const LABEL_WRITE_JITTER: u32 = 32; // v6LabelWriteJitter (:55)
const LABEL_RECORD_PREFIX: u32 = 33; // v6LabelRecordPrefix (:56)
const LABEL_PAYLOAD_PAD: u32 = 34; // v6LabelPayloadPad (:57)
const LABEL_WRITE_TARGET: u32 = 35; // v6LabelWriteTarget (:58)
const LABEL_WRITE_JITTER_V: u32 = 36; // v6LabelWriteJitterV (:59)
const LABEL_WRITE_NEXT: u32 = 37; // v6LabelWriteNext (:60)
const LABEL_CHUNK_SIZE: u32 = 38; // v6LabelChunkSize (:61)
const LABEL_CHUNK_JITTER_V: u32 = 39; // v6LabelChunkJitterV (:62)

/// `v6HandshakeDomain` (v6_profile.go:65) — domain separator for the
/// salt-block handshake profile values.
const V6_HANDSHAKE_DOMAIN: u32 = 0x7053;
/// `v6MixHandshakeDomain` (v6_profile.go:66).
const V6_MIX_HANDSHAKE_DOMAIN: u32 = 0x51a7;
/// `v6ChunkInitialDomain` (v6_profile.go:67).
const V6_CHUNK_INITIAL_DOMAIN: u32 = 0xf17c;

// Namespace seeds (v6_profile.go:70-76).
const NS_SEED_PROFILE: u64 = 0xb46c_2e7d_9a15_38f1;
const NS_SEED_PREFIX: u64 = 0x5d92_17c0_83e6_4ab9;
const NS_SEED_MOTIF: u64 = 0xa71f_0c54_d839_6e2b;
const NS_SEED_SALT: u64 = 0x3e8a_91b5_2740_f6cd;
const NS_SEED_MIX: u64 = 0xc9f4_260b_7d1e_835a;
const NS_SEED_CHUNK: u64 = 0x62d0_b5e1_9c4a_783f;
const NS_SEED_WRITE: u64 = 0x917b_3c48_e6a2_05d4;

// Arithmetic constants of the profile PRFs (v6_profile.go:79-84).
const V6_DOMAIN_MUL: u64 = 0xd6e8_feb8_6659_fd93;
const V6_NAMESPACE_ADD: u64 = 0xa076_1d64_78bd_642f;
const V6_COEF_B: u64 = 0x5899_65cc_7537_4cc3;
const V6_ADD_B: u64 = 0x33a2_13ec_50ff_e2e9;
const V6_COEF_A: u64 = 0xe703_7ed1_a0b4_28db;
const V6_ADD_A: u64 = 0x8f39_07f7_b2b8_0c35;

/// `v6SaltNSXor` (v6_profile.go:87) — the salt shuffle/mask namespace xor.
const V6_SALT_NS_XOR: u64 = 0xdaa6_6d2c_7ddf_743f;

/// `v6MaxExtraPadding` (v6_profile.go:89) — the write-target shaping
/// may add at most this much padding on top of the profile padding.
const V6_MAX_EXTRA_PADDING: i64 = 0x02da;

/// `v6ProfileSeed` (v6_profile.go:93-96) — the BLAKE2b prefix mixed
/// with the PSK to derive the profile secret. No personalization or
/// key: plain unkeyed BLAKE2b-256 over seed || psk
/// (`v6ProfileSecret`, v6_profile.go:274-279).
const V6_PROFILE_SEED: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e,
    0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];

/// `v6BitRotateTable` (v6_profile.go:99-108) — 128 entries mapping low
/// nibbles through bit rotations for padding generator 0; transcribed
/// byte-for-byte (row r at `16*r..16*r+15`).
const V6_BIT_ROTATE_TABLE: [u8; 128] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // row 0
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, // row 1
    0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18,
    0x24, // row 2
    0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70,
    0xe0, // row 3
    0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78,
    0xf0, // row 4
    0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f,
    0x1f, // row 5
    0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7,
    0xdb, // row 6
    0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf,
    0x7f, // row 7
];

/// `v6SplitMix64` (v6_profile.go:124-131) — the standard splitmix64
/// finalizer with its two golden multipliers.
#[inline]
fn v6_split_mix_64(x: u64) -> u64 {
    let mut x = x;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x
}

/// `v6PRF32Fold` (v6_profile.go:133-137): fold a namespace through the
/// two affine maps and the golden gamma, then splitmix and fold to 32
/// bits. All arithmetic wraps (Go uint64).
#[inline]
fn v6_prf32_fold(namespace: u64, label: u32, a: u64, b: u64) -> u32 {
    let x = namespace
        ^ b.wrapping_mul(V6_COEF_B).wrapping_add(V6_ADD_B)
        ^ u64::from(label).wrapping_mul(V6_GOLDEN_GAMMA)
        ^ a.wrapping_mul(V6_COEF_A).wrapping_add(V6_ADD_A);
    let y = v6_split_mix_64(x);
    (y ^ (y >> 32)) as u32
}

/// `v6Pick` (v6_profile.go:139-144): inclusive uniform pick over a
/// signed range (Go panics on hi < lo; every profile range is a
/// compile-time constant with lo <= hi, and no untrusted input reaches
/// this — the debug_assert documents the invariant).
#[inline]
fn v6_pick(raw: u32, lo: i64, hi: i64) -> i64 {
    debug_assert!(hi >= lo);
    lo + (u64::from(raw) % ((hi - lo + 1) as u64)) as i64
}

/// `v6PickU32` (v6_profile.go:146-151).
#[inline]
fn v6_pick_u32(raw: u32, lo: u32, hi: u32) -> u32 {
    debug_assert!(hi >= lo);
    lo + raw % (hi - lo + 1)
}

// ---------------------------------------------------------------------------
// Profile: namespaces (v6_profile.go:153-228)
// ---------------------------------------------------------------------------

/// `v6Namespaces` (v6_profile.go:153-161) — seven per-purpose u64
/// namespaces derived from the profile secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct V6Namespaces {
    profile: u64,
    prefix: u64,
    motif: u64,
    salt: u64,
    mix: u64,
    chunk: u64,
    write: u64,
}

/// `v6DeriveNamespace` (v6_profile.go:163-175): the four LE u64s of the
/// secret mixed with the label, the namespace seed and rotations
/// (RotateLeft64(s2, 17) and RotateLeft64(s3, -11) == rotate right 11).
fn v6_derive_namespace(secret: &[u8; 32], label: u32, seed_const: u64) -> u64 {
    let s0 = u64::from_le_bytes(secret[0..8].try_into().expect("8 bytes"));
    let s1 = u64::from_le_bytes(secret[8..16].try_into().expect("8 bytes"));
    let s2 = u64::from_le_bytes(secret[16..24].try_into().expect("8 bytes"));
    let s3 = u64::from_le_bytes(secret[24..32].try_into().expect("8 bytes"));
    let mixed = u64::from(label).wrapping_mul(V6_DOMAIN_MUL)
        ^ seed_const.wrapping_add(V6_NAMESPACE_ADD)
        ^ s0
        ^ s1.wrapping_add(V6_GOLDEN_GAMMA)
        ^ s2.rotate_left(17)
        ^ s3.rotate_right(11);
    v6_split_mix_64(mixed)
}

/// `newV6Namespaces` (v6_profile.go:177-187) — the exact label each
/// namespace is seeded from: profile:5, prefix:0, motif:2, salt:3,
/// mix:16, chunk:21, write:28.
fn v6_new_namespaces(secret: &[u8; 32]) -> V6Namespaces {
    V6Namespaces {
        profile: v6_derive_namespace(secret, LABEL_PROFILE_ID, NS_SEED_PROFILE),
        prefix: v6_derive_namespace(secret, LABEL_PADDING, NS_SEED_PREFIX),
        motif: v6_derive_namespace(secret, LABEL_MOTIF, NS_SEED_MOTIF),
        salt: v6_derive_namespace(secret, LABEL_MIX_OFFSET, NS_SEED_SALT),
        mix: v6_derive_namespace(secret, LABEL_MIX_MODE, NS_SEED_MIX),
        chunk: v6_derive_namespace(secret, LABEL_CHUNK_POLICY, NS_SEED_CHUNK),
        write: v6_derive_namespace(secret, LABEL_WRITE_POLICY, NS_SEED_WRITE),
    }
}

impl V6Namespaces {
    /// `forLabel` (v6_profile.go:189-204) — the namespace bucket each
    /// label draws from (unlisted labels fall to the profile namespace).
    fn for_label(&self, label: u32) -> u64 {
        match label {
            LABEL_PADDING | LABEL_BIT_PERCENT | LABEL_PREFIX_MIN | LABEL_PREFIX_MAX
            | LABEL_RECORD_PREFIX | LABEL_PAYLOAD_PAD => self.prefix,
            LABEL_MOTIF => self.motif,
            LABEL_MIX_OFFSET
            | LABEL_MIX_MODE
            | LABEL_MIX_ROUNDS
            | LABEL_MIX_STRIDE
            | LABEL_MIX_OFFSET_BASE
            | LABEL_MIX_BLOCK => self.mix,
            LABEL_CHUNK_POLICY | LABEL_CHUNK_INITIAL | LABEL_CHUNK_MAX | LABEL_CHUNK_STEP
            | LABEL_CHUNK_JITTER | LABEL_CHUNK_BUCKET | LABEL_CHUNK_SIZE | LABEL_CHUNK_JITTER_V => {
                self.chunk
            }
            LABEL_WRITE_POLICY | LABEL_WRITE_FIRST | LABEL_WRITE_BUCKET | LABEL_WRITE_SEQ
            | LABEL_WRITE_JITTER | LABEL_WRITE_TARGET | LABEL_WRITE_JITTER_V | LABEL_WRITE_NEXT => {
                self.write
            }
            _ => self.profile,
        }
    }

    /// `prf32` (v6_profile.go:206-208).
    #[inline]
    fn prf32(&self, label: u32, a: u32, b: u32) -> u32 {
        v6_prf32_fold(self.for_label(label), label, u64::from(a), u64::from(b))
    }

    /// `prfBytes` (v6_profile.go:210-224): a gamma-stepped splitmix
    /// stream over the namespace-seeded state (seed mix at :211-214),
    /// LSB-first per 64-bit block.
    fn prf_bytes(&self, label: u32, a: u32, output: &mut [u8]) {
        let mut seed = self.for_label(label)
            ^ (u64::from(a)
                .wrapping_mul(V6_DOMAIN_MUL)
                .wrapping_add(0xb57d_e1f3_f82c_b33f))
            ^ u64::from(label).wrapping_mul(0xa24b_aed4_963e_e407)
            ^ ((output.len() as u64)
                .wrapping_mul(0x1656_67b1_9e37_79f9)
                .wrapping_add(0x0d4c_d3e7_b14a_36d7));
        let mut offset = 0usize;
        while offset < output.len() {
            seed = seed.wrapping_add(V6_GOLDEN_GAMMA);
            let block = v6_split_mix_64(seed);
            let mut shift = 0u32;
            while shift < 64 && offset < output.len() {
                output[offset] = (block >> shift) as u8;
                offset += 1;
                shift += 8;
            }
        }
    }

    /// `prfStatic` (v6_profile.go:226-228) — a domain-only PRF draw.
    #[inline]
    fn prf_static(&self, label: u32, domain: u32) -> u32 {
        v6_prf32_fold(self.for_label(label), label, 0, u64::from(domain))
    }
}

// ---------------------------------------------------------------------------
// Profile (v6_profile.go:230-465)
// ---------------------------------------------------------------------------

/// `v6Profile` (v6_profile.go:230-272). Go ints are ported as i64 so
/// every intermediate (including the chunk-jitter deltas that can dip
/// negative before the 0x40 clamp) matches upstream exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
struct V6Profile {
    namespaces: V6Namespaces,

    generator: u32,
    pad_min: i64,
    pad_max: i64,
    pad_count: u32,
    pad_interval: u32,
    small_limit: i64,
    bit_min: u32,
    bit_max: u32,
    prefix_min_record: i64,
    prefix_max_record: i64,
    mix_mode: u32,
    mix_rounds: u32,
    mix_stride: i64,
    mix_offset_base: i64,
    mix_block: i64,
    chunk_policy: u32,
    chunk_initial: i64,
    first_record_cap: i64,
    chunk_max: i64,
    chunk_step: i64,
    chunk_jitter: i64,
    idle_reset_sec: i64,
    write_policy: u32,
    write_first: u32,
    chunk_buckets: [i64; 8],
    write_buckets: [i64; 8],
    write_seq: [i64; 8],
    write_jitter: i64,
    write_jitter_pct: i64,
    g1: i64,
    g2: i64,
    g3: i64,
    g4: i64,
    g5: i64,
    g6: i64,

    salt_block_len: usize,
    mix_stride_handshake: u32,
    mix_rounds_handshake: u32,
}

/// `v6ProfileSecret` (v6_profile.go:274-279): unkeyed BLAKE2b-256 over
/// `v6ProfileSeed || psk` (Go `blake2b.Sum256`; no personalization).
fn v6_profile_secret(psk: &[u8]) -> [u8; 32] {
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = blake2::Blake2bVar::new(32).expect("32 <= BLAKE2b max digest");
    hasher.update(&V6_PROFILE_SEED);
    hasher.update(psk);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("buffer matches the 32-byte output");
    out
}

impl V6Profile {
    /// `newV6Profile` (v6_profile.go:281-351) — every pick range and
    /// clamp below is upstream-verbatim, cited per line.
    fn new(psk: &[u8]) -> V6Profile {
        let secret = v6_profile_secret(psk);
        let ns = v6_new_namespaces(&secret);

        // v6_profile.go:285-286.
        let pad_min = v6_pick(ns.prf_static(LABEL_PAD_MIN, 0), 0x18, 0xa0);
        let pad_max = (pad_min + v6_pick(ns.prf_static(LABEL_PAD_MAX, 0), 0xa0, 0x3c0))
            .min(V6_MAX_EXTRA_PADDING);

        // v6_profile.go:288-292 — the salt block's prefix window
        // (handshake domain 0x7053).
        let mut prefix_min_hs = v6_pick(
            ns.prf_static(LABEL_PREFIX_MIN, V6_HANDSHAKE_DOMAIN),
            0x10,
            0x60,
        );
        let prefix_max_hs = (prefix_min_hs
            + v6_pick(
                ns.prf_static(LABEL_PREFIX_MAX, V6_HANDSHAKE_DOMAIN),
                0x10,
                0xa0,
            ))
        .min(0x80);
        prefix_min_hs = prefix_min_hs.min(prefix_max_hs);
        let salt_prefix_len = v6_pick(
            ns.prf_static(LABEL_RECORD_PREFIX, V6_HANDSHAKE_DOMAIN),
            prefix_min_hs,
            prefix_max_hs,
        );
        let salt_block_len = V6_SALT_SIZE + salt_prefix_len as usize;

        // v6_profile.go:294-295 — the handshake mix parameters
        // (domain 0x51a7).
        let mix_rounds_hs = v6_pick_u32(
            ns.prf_static(LABEL_MIX_ROUNDS, V6_MIX_HANDSHAKE_DOMAIN),
            1,
            4,
        );
        let mix_stride_hs = v6_pick(
            ns.prf_static(LABEL_MIX_STRIDE, V6_MIX_HANDSHAKE_DOMAIN),
            0x11,
            0xfb,
        );

        // v6_profile.go:297-299 — the per-record prefix window.
        let mut prefix_min_record = v6_pick(ns.prf_static(LABEL_PREFIX_MIN, 0), 0x08, 0x50);
        let prefix_max_record =
            (prefix_min_record + v6_pick(ns.prf_static(LABEL_PREFIX_MAX, 0), 0x10, 0xa0)).min(0x80);
        prefix_min_record = prefix_min_record.min(prefix_max_record);

        // v6_profile.go:301-303 — chunkInitial >= 0x60, the first-record
        // cap over the 0xf17c domain, chunkMax >= chunkInitial.
        let chunk_initial =
            0x60.max(v6_pick(ns.prf_static(LABEL_CHUNK_INITIAL, 0), 0x200, 0x05b4).min(0x05b4));
        let first_record_cap = 0x100.max(
            v6_pick(
                ns.prf_static(LABEL_CHUNK_FIRST_CAP, V6_CHUNK_INITIAL_DOMAIN),
                0x100,
                0x300,
            )
            .min(chunk_initial.min(0x300)),
        );
        let chunk_max =
            v6_pick(ns.prf_static(LABEL_CHUNK_MAX, 0), 0x2000, 0x3fff).max(chunk_initial);

        let mut profile = V6Profile {
            namespaces: ns,
            generator: ns.prf_static(LABEL_GENERATOR, 0) & 3, // v6_profile.go:307
            pad_min,
            pad_max,
            pad_count: v6_pick_u32(ns.prf_static(LABEL_PAD_COUNT, 0), 2, 8), // :310
            pad_interval: v6_pick_u32(ns.prf_static(LABEL_PAD_INTERVAL, 0), 2, 0x0b), // :311
            small_limit: v6_pick(ns.prf_static(LABEL_SMALL_LIMIT, 0), 0x60, 0x300), // :312
            bit_min: v6_pick_u32(ns.prf_static(LABEL_BIT_MIN, 0), 0x18, 0x29), // :313
            bit_max: v6_pick_u32(ns.prf_static(LABEL_BIT_MAX, 0), 0x3a, 0x4c), // :314
            prefix_min_record,
            prefix_max_record,
            mix_mode: ns.prf_static(LABEL_MIX_MODE, 0) % 3, // :317
            mix_rounds: v6_pick_u32(ns.prf_static(LABEL_MIX_ROUNDS, 0), 1, 3), // :318
            mix_stride: v6_pick(ns.prf_static(LABEL_MIX_STRIDE, 0), 2, 13), // :319
            mix_offset_base: v6_pick(ns.prf_static(LABEL_MIX_OFFSET_BASE, 0), 0, 15), // :320
            mix_block: v6_pick(ns.prf_static(LABEL_MIX_BLOCK, 0), 8, 0x40), // :321
            chunk_policy: ns.prf_static(LABEL_CHUNK_POLICY, 0) % 3, // :322
            chunk_initial,
            first_record_cap,
            chunk_max,
            chunk_step: v6_pick(ns.prf_static(LABEL_CHUNK_STEP, 0), 0x400, 0x1000).min(0x0b68), // :326
            chunk_jitter: v6_pick(ns.prf_static(LABEL_CHUNK_JITTER, 0), 0x10, 0xc0).min(0x0b6), // :327
            idle_reset_sec: v6_pick(ns.prf_static(LABEL_IDLE_RESET, 0), 0x0c, 0x5a), // :328
            write_policy: ns.prf_static(LABEL_WRITE_POLICY, 0) % 3,                  // :329
            write_first: v6_pick_u32(ns.prf_static(LABEL_WRITE_FIRST, 0), 4, 8),     // :330
            write_jitter: v6_pick(ns.prf_static(LABEL_WRITE_JITTER, 0), 0x08, 0x60), // :331
            // :332 — note the SECOND WritePolicy draw, domain 0x504c.
            write_jitter_pct: v6_pick(ns.prf_static(LABEL_WRITE_POLICY, 0x504c), 8, 0x30),
            g1: v6_pick(ns.prf_static(LABEL_GENERATOR, 1), 0x18, 0x80), // :333
            g2: v6_pick(ns.prf_static(LABEL_GENERATOR, 2), 0x10, 0x60), // :334
            g3: v6_pick(ns.prf_static(LABEL_GENERATOR, 3), 0x10, 0x60), // :335
            g4: v6_pick(ns.prf_static(LABEL_GENERATOR, 4), 0x00, 0x09), // :336
            g5: v6_pick(ns.prf_static(LABEL_GENERATOR, 5), 0x01, 0x08), // :337
            g6: v6_pick(ns.prf_static(LABEL_GENERATOR, 6), 0x07, 0x17), // :338
            salt_block_len,
            mix_stride_handshake: mix_stride_hs as u32,
            mix_rounds_handshake: mix_rounds_hs,
            chunk_buckets: [0; 8],
            write_buckets: [0; 8],
            write_seq: [0; 8],
        };

        // v6_profile.go:344-348 — the eight bucket entries.
        for index in 0u32..8 {
            profile.chunk_buckets[index as usize] =
                v6_pick(ns.prf_static(LABEL_CHUNK_BUCKET, index), 0x1000, chunk_max);
            profile.write_buckets[index as usize] =
                v6_pick(ns.prf_static(LABEL_WRITE_BUCKET, index), 0x140, 0x05b4);
            profile.write_seq[index as usize] =
                v6_pick(ns.prf_static(LABEL_WRITE_SEQ, index), 0x168, 0x05b4);
        }

        profile
    }

    /// `recordPrefixLen` (v6_profile.go:355-357): the unencrypted
    /// prefix length in front of record `seq`'s header (it doubles as
    /// the header's AAD).
    fn record_prefix_len(&self, seq: u32) -> usize {
        v6_pick(
            self.namespaces.prf32(LABEL_RECORD_PREFIX, seq, 0),
            self.prefix_min_record,
            self.prefix_max_record,
        ) as usize
    }

    /// `chunkPayloadLimit` (v6_profile.go:359-371): policy 1 buckets by
    /// PRF, policy 2 jitters around the current size, then the 0x40 /
    /// chunkMax clamp.
    fn chunk_payload_limit(&self, seq: u32, chunk_size: i64) -> i64 {
        let mut chunk_size = if chunk_size == 0 {
            self.chunk_initial
        } else {
            chunk_size
        };
        match self.chunk_policy {
            1 => {
                chunk_size = self.chunk_buckets[(self.namespaces.prf32(
                    LABEL_CHUNK_SIZE,
                    seq,
                    chunk_size as u32,
                ) % self.chunk_buckets.len() as u32)
                    as usize];
            }
            2 => {
                let raw_jitter =
                    self.namespaces
                        .prf32(LABEL_CHUNK_JITTER_V, seq, chunk_size as u32);
                chunk_size +=
                    (raw_jitter % (self.chunk_jitter as u32 * 2 + 1)) as i64 - self.chunk_jitter;
            }
            _ => {}
        }
        0x40.max(chunk_size.min(self.chunk_max))
    }

    /// `nextChunkSize` (v6_profile.go:373-378).
    fn next_chunk_size(&self, chunk_size: i64) -> i64 {
        if chunk_size == 0 {
            return self.chunk_initial;
        }
        (chunk_size + self.chunk_step).min(self.chunk_max)
    }

    /// `paddingLen` (v6_profile.go:382-400): the profile padding rule,
    /// then the write-target shaping (+ at most 0x2da), then the
    /// first-record floor. `total_len` is the salt block length when
    /// this is the first record.
    fn padding_len(
        &self,
        seq: u32,
        payload_len: usize,
        prefix_len: usize,
        salt_prefix_len: usize,
        total_len: usize,
    ) -> usize {
        let mut padding_len = 0i64;
        let payload_len = payload_len as i64;
        if seq < self.pad_count
            || (payload_len > 0 && payload_len <= self.small_limit)
            || (self.pad_interval > 0 && seq.is_multiple_of(self.pad_interval))
        {
            padding_len = v6_pick(
                self.namespaces
                    .prf32(LABEL_PAYLOAD_PAD, seq, payload_len as u32),
                self.pad_min,
                self.pad_max,
            );
        }
        let payload_tag_len = if payload_len > 0 {
            V6_TAG_SIZE as i64
        } else {
            0
        };
        let frame_len = total_len as i64
            + prefix_len as i64
            + V6_HEADER_CIPHER as i64
            + padding_len
            + payload_len
            + payload_tag_len;
        let target_len = self.write_target(seq, frame_len);
        if target_len > frame_len {
            padding_len += (target_len - frame_len).min(V6_MAX_EXTRA_PADDING);
        }
        if total_len > 0 {
            padding_len = self.first_record_padding_len(
                padding_len,
                prefix_len as i64,
                salt_prefix_len as i64,
                payload_len,
            );
        }
        padding_len.min(0xffff) as usize
    }

    /// `writeTarget` (v6_profile.go:402-444): frame lengths above
    /// 0x05b3 pass through (capped at 0xffff); below, the seq-indexed
    /// write schedule with the jitter policy, the half-spread coin and
    /// the bucket walk-up.
    fn write_target(&self, seq: u32, frame_len: i64) -> i64 {
        if frame_len > 0x05b3 {
            if frame_len <= 0xffff {
                return frame_len;
            }
            return 0xffff;
        }
        let mut target_len = if seq < self.write_first {
            self.write_seq[seq as usize]
        } else {
            self.write_buckets[(self
                .namespaces
                .prf32(LABEL_WRITE_TARGET, seq, frame_len as u32)
                % self.write_buckets.len() as u32) as usize]
        };
        if self.write_policy == 2 {
            let raw_jitter = self.namespaces.prf32(LABEL_WRITE_JITTER_V, seq, 0);
            let jitter =
                (raw_jitter % (self.write_jitter as u32 * 2 + 1)) as i64 - self.write_jitter;
            target_len = (target_len + jitter).max(1);
        }
        let spread = V6_MAX_EXTRA_PADDING
            .min((frame_len as u64 * self.write_jitter_pct as u64 / 100) as i64);
        if self
            .namespaces
            .prf32(LABEL_WRITE_TARGET, seq, spread as u32)
            & 1
            == 0
        {
            if target_len + spread <= 0xffff {
                target_len += spread;
            } else {
                target_len = 0xffff;
            }
        } else {
            let half_spread = spread >> 1;
            if target_len > half_spread {
                target_len -= half_spread;
            }
        }
        while target_len >= 0 && frame_len > target_len {
            let mut next_len =
                self.write_buckets[(self
                    .namespaces
                    .prf32(LABEL_WRITE_NEXT, seq, target_len as u32)
                    % self.write_buckets.len() as u32) as usize];
            if next_len <= target_len {
                next_len = target_len + self.pad_max;
                if next_len > 0xffff {
                    return 0xffff;
                }
            }
            target_len = next_len;
        }
        target_len
    }

    /// `firstRecordPaddingLen` (v6_profile.go:446-465): the salt block's
    /// record pads up to `max((input*25+0x4a)/75, 0xc0)` — input
    /// payloadLen+0x37 (or +0x27 for the zero record).
    fn first_record_padding_len(
        &self,
        padding_len: i64,
        prefix_len: i64,
        salt_prefix_len: i64,
        payload_len: i64,
    ) -> i64 {
        let overhead_len = salt_prefix_len + prefix_len + padding_len;
        let mut threshold_input = payload_len + 0x37;
        if payload_len == 0 {
            threshold_input = payload_len + 0x27;
        }
        let threshold = ((threshold_input * 25 + 0x4a) / 75).max(0xc0);
        if overhead_len >= threshold {
            return padding_len;
        }
        let mut target_padding_len = threshold - salt_prefix_len - prefix_len;
        let max_padding_len = self.pad_max + V6_MAX_EXTRA_PADDING;
        if max_padding_len <= target_padding_len {
            target_padding_len = max_padding_len;
        }
        if target_padding_len > 0xfffe {
            return padding_len;
        }
        target_padding_len
    }

    /// `fillPadding` (v6_profile.go:468-536): a PRF stream
    /// (`prfBytes(Padding, seq, …)`) post-processed by one of the 4
    /// deterministic generators (generator 0 = the bit-rotate table,
    /// 1 = printable buckets, 2 = ASCII digits, 3 = the motif).
    fn fill_padding(&self, seq: u32, output: &mut [u8]) {
        if output.is_empty() {
            return;
        }
        self.namespaces.prf_bytes(LABEL_PADDING, seq, output);
        match self.generator {
            0 => {
                // v6_profile.go:475-489.
                let bit_count = v6_pick_u32(
                    self.namespaces.prf32(LABEL_BIT_PERCENT, seq, 0),
                    self.bit_min,
                    self.bit_max,
                );
                let mut rotate = 1i64;
                let scaled = bit_count as i64 * 8;
                if scaled > 0x31 {
                    rotate = 7;
                    if scaled <= 0x02ed {
                        rotate = (scaled + 0x32) / 100;
                    }
                }
                let table_row = rotate.max(1) as usize;
                for (index, slot) in output.iter_mut().enumerate() {
                    let value = *slot;
                    // raw = byte(int(value) + index) — wraps like Go's
                    // int add + byte truncation.
                    let raw = value.wrapping_add(index as u8);
                    let table_value =
                        V6_BIT_ROTATE_TABLE[table_row * 16 + ((raw ^ value) & 0x0f) as usize];
                    *slot = table_value.rotate_left(((raw ^ (value >> 4)) & 7) as u32);
                }
            }
            1 => {
                // v6_profile.go:491-502 — the byte/index mixes are
                // truncated to a byte before being reduced into the
                // printable ranges.
                for (index, slot) in output.iter_mut().enumerate() {
                    let value = *slot;
                    let bucket = value as i64 % (self.g1 + self.g2 + self.g3);
                    *slot = if bucket < self.g1 {
                        v6_pick(value.wrapping_add(index as u8) as u32, 0x20, 0x7e) as u8
                    } else if bucket < self.g1 + self.g2 {
                        v6_pick((value ^ index as u8) as u32, 0x80, 0xbf) as u8
                    } else {
                        v6_pick(
                            value.wrapping_add((index as u8).wrapping_mul(7)) as u32,
                            0xc0,
                            0xff,
                        ) as u8
                    };
                }
            }
            2 => {
                // v6_profile.go:504-508 — ASCII-digit shaping.
                for (index, slot) in output.iter_mut().enumerate() {
                    let value = *slot;
                    let low = ((value & 0x0f) as i64 + self.g4 + (index as i64 & 1)) % 10;
                    let high = (value as i64 + ((index as i64 & 3) << 4) + 0x30) & 0xf0;
                    *slot = (high | low) as u8;
                }
            }
            3 => {
                // v6_profile.go:510-534 — the motif generator: a PRF
                // motif XORed on a period, with ASCII digits in the
                // last two slots of each period.
                let mut motif = [0u8; 32];
                self.namespaces.prf_bytes(LABEL_MOTIF, seq, &mut motif);
                let motif_len = if self.g5 * 4 == 0 {
                    4
                } else {
                    (self.g5 * 4) as usize
                };
                let period = self.g6.max(5) as usize;
                let mut block_offset = 0usize;
                let mut motif_offset = 0usize;
                for (index, slot) in output.iter_mut().enumerate() {
                    if block_offset < period - 3 {
                        *slot = ((self.g5 + 3) as u64 * index as u64) as u8
                            ^ motif[motif_offset % motif.len()];
                    } else if block_offset < period - 1 {
                        *slot = 0x30 | (*slot as i64 % 10) as u8;
                    }
                    block_offset += 1;
                    if block_offset == period {
                        block_offset = 0;
                    }
                    motif_offset += 1;
                    if motif_offset == motif_len {
                        motif_offset = 0;
                    }
                }
            }
            _ => {}
        }
    }

    // --- salt block (v6_profile.go:540-593) ---

    /// `v6SaltShufflePRF` (v6_profile.go:540-546).
    fn v6_salt_shuffle_prf(ns_salt: u64, domain: u32, index: u32) -> u32 {
        let rdx = u64::from(index)
            .wrapping_mul(V6_COEF_B)
            .wrapping_add(V6_ADD_B);
        let rdi = ns_salt ^ V6_SALT_NS_XOR;
        let rsi = u64::from(domain)
            .wrapping_mul(V6_COEF_A)
            .wrapping_add(V6_ADD_A);
        let y = v6_split_mix_64((rdx ^ rdi) ^ rsi);
        (y ^ (y >> 32)) as u32
    }

    /// `v6ShufflePerm` (v6_profile.go:548-569): a rounds-stacked
    /// Fisher-Yates scatter over the identity permutation (domain
    /// 0x51a7 + round; zero rounds count as one).
    fn v6_shuffle_perm(ns_salt: u64, rounds: u8, length: usize) -> Vec<u8> {
        let mut out: Vec<u8> = (0..length).map(|i| i as u8).collect();
        if length == 0 {
            return out;
        }
        let rounds = if rounds == 0 { 1 } else { u32::from(rounds) };
        for round in 0..rounds {
            let domain = V6_MIX_HANDSHAKE_DOMAIN + round;
            for i in 0..length {
                let span = (length - i) as u64;
                let raw = u64::from(Self::v6_salt_shuffle_prf(ns_salt, domain, i as u32));
                let j = i + (raw % span) as usize;
                out.swap(i, j);
            }
        }
        out
    }

    /// `v6SaltMask` (v6_profile.go:571-574): `index*stride ^ PRF` in
    /// u8 arithmetic (wrapping).
    fn v6_salt_mask(ns_salt: u64, mix_stride: u8, index: u32) -> u8 {
        let prf = v6_prf32_fold(
            ns_salt,
            LABEL_MOTIF,
            u64::from(V6_MIX_HANDSHAKE_DOMAIN),
            u64::from(index),
        );
        (index as u8).wrapping_mul(mix_stride) ^ prf as u8
    }

    /// `extractSalt` (v6_profile.go:577-584): recover the 16-byte salt
    /// scattered inside the first block.
    fn extract_salt(&self, block: &[u8]) -> [u8; V6_SALT_SIZE] {
        let perm = Self::v6_shuffle_perm(
            self.namespaces.salt,
            self.mix_rounds_handshake as u8,
            block.len(),
        );
        let mut out = [0u8; V6_SALT_SIZE];
        for i in 0..V6_SALT_SIZE {
            out[i] = Self::v6_salt_mask(
                self.namespaces.salt,
                self.mix_stride_handshake as u8,
                i as u32,
            ) ^ block[perm[i] as usize];
        }
        out
    }

    /// `writeSaltBlock` (v6_profile.go:588-593): scatter the salt into
    /// `block`, which must already hold the shaped padding generated
    /// for the sentinel sequence 0xffffffff.
    fn write_salt_block(&self, salt: &[u8; V6_SALT_SIZE], block: &mut [u8]) {
        let perm = Self::v6_shuffle_perm(
            self.namespaces.salt,
            self.mix_rounds_handshake as u8,
            block.len(),
        );
        for i in 0..V6_SALT_SIZE {
            block[perm[i] as usize] = Self::v6_salt_mask(
                self.namespaces.salt,
                self.mix_stride_handshake as u8,
                i as u32,
            ) ^ salt[i];
        }
    }

    // --- padding / ciphertext interleave (v6_profile.go:599-650) ---

    /// `mixPaddingPayload` (v6_profile.go:599-614): swaps bytes between
    /// the padding and the payload ciphertext — the operation is its
    /// own inverse, so the reader applies it before decrypting.
    fn mix_padding_payload(&self, seq: u32, padding: &mut [u8], payload_ct: &mut [u8]) {
        let n = padding.len().min(payload_ct.len());
        if n == 0 {
            return;
        }
        for round in 0..self.mix_rounds {
            match self.mix_mode {
                0 => self.mix_fixed_stride(round, padding, payload_ct, n),
                1 => self.mix_alternating_block(round, padding, payload_ct, n),
                2 => self.mix_prf_stride(seq, round, padding, payload_ct, n),
                _ => {}
            }
        }
    }

    /// `mixFixedStride` (v6_profile.go:616-627).
    fn mix_fixed_stride(&self, round: u32, padding: &mut [u8], payload_ct: &mut [u8], n: usize) {
        let stride = (self.mix_stride + (round % 3) as i64).max(1) as usize;
        if stride == 1 {
            for i in 0..n {
                core::mem::swap(&mut padding[i], &mut payload_ct[i]);
            }
            return;
        }
        let mut off = self.mix_offset_base as usize % stride;
        while off < n {
            core::mem::swap(&mut padding[off], &mut payload_ct[off]);
            off += stride;
        }
    }

    /// `mixAlternatingBlock` (v6_profile.go:629-636).
    fn mix_alternating_block(
        &self,
        round: u32,
        padding: &mut [u8],
        payload_ct: &mut [u8],
        n: usize,
    ) {
        let block = self.mix_block as usize;
        let mut off = (round & 1) as usize * block;
        while off + block <= n {
            for i in off..off + block {
                core::mem::swap(&mut padding[i], &mut payload_ct[i]);
            }
            off += block * 2;
        }
    }

    /// `mixPRFStride` (v6_profile.go:638-650).
    fn mix_prf_stride(
        &self,
        seq: u32,
        round: u32,
        padding: &mut [u8],
        payload_ct: &mut [u8],
        n: usize,
    ) {
        let stride = (self.mix_stride + (round % 3) as i64).max(1) as usize;
        let mut off = ((u64::from(self.namespaces.prf32(LABEL_MIX_OFFSET, seq, round))
            + self.mix_offset_base as u64)
            % stride as u64) as usize;
        if stride == 1 {
            for i in 0..n {
                core::mem::swap(&mut padding[i], &mut payload_ct[i]);
            }
            return;
        }
        while off < n {
            core::mem::swap(&mut padding[off], &mut payload_ct[off]);
            off += stride;
        }
    }
}

// ---------------------------------------------------------------------------
// V6Conn — the three-mode record layer (v6.go:99-663)
// ---------------------------------------------------------------------------

/// The v6 connection: one of three record codecs over the same 7-byte
/// header format (see the module docs). Mirrors the `Conn` interface
/// `proto::snell`'s v3/v4 codecs expose: [`V6Conn::frame`] turns a
/// write buffer into records, [`V6Conn::try_parse`] decodes the read
/// buffer into `out`, and the salt exchange initializes lazily on both
/// firsts (the writer's random salt is drawn at construction, like
/// `newV6UnshapedWriter`/`newV6ShapedWriter`, v6.go:407-417/555-565).
pub(crate) struct V6Conn {
    pub(crate) inner: BoxProxyStream,
    psk: Vec<u8>,
    mode: V6Mode,
    /// `c.profile` (v6.go:103) — only in Default mode.
    profile: Option<V6Profile>,

    writer: V6Writer,
    reader: Option<V6Reader>,
    /// Read stage — a nonce tick always accompanies consuming its
    /// ciphertext (see V3Stage/V4Stage in proto::snell).
    stage: V6Stage,
    pub(crate) rbuf: BytesMut,
    pub(crate) out: BytesMut,
    /// A zero-payload record was decoded and is pending as the
    /// consumer's EOF (`shadowaead.ErrZeroChunk` — a boundary, not a
    /// terminal error: the next read continues with the next record).
    pub(crate) pending_zero: bool,
}

struct V6Writer {
    /// `None` in UnsafeRaw mode.
    aead: Option<Aead>,
    nonce: SsNonce,
    salt: [u8; V6_SALT_SIZE],
    salt_sent: bool,
    /// `w.seq` (v6.go:550) — the record counter (prefix, padding and
    /// mix are per-sequence).
    seq: u32,
    /// `w.chunkSize` (v6.go:551) — the shaped chunk ramp state.
    chunk_size: i64,
    /// `w.lastWriteUnix` (v6.go:552) — 0 = never written.
    last_write_unix: i64,
}

struct V6Reader {
    /// `None` in UnsafeRaw mode.
    aead: Option<Aead>,
    nonce: SsNonce,
    /// `r.seq` (v6.go:482) — the shaped record counter.
    seq: u32,
}

#[derive(Debug, PartialEq)]
enum V6Stage {
    /// Awaiting the next record header (plus its shaped prefix).
    Header,
    /// Padding and payload lengths from a consumed header; `seq` is
    /// that record's sequence for the shaped mix.
    Body {
        padding_len: usize,
        payload_len: usize,
        seq: u32,
    },
    /// A zero-payload record whose padding must be discarded before the
    /// half-close surfaces (shaped zero chunks may carry padding,
    /// v6.go:519-525).
    ZeroPadding { discard: usize },
}

impl V6Conn {
    /// `newV6Conn` (v6.go:113-119) + the writer constructions
    /// (v6.go:407-417, 555-565): the profile exists only in Default
    /// mode; the random salt is drawn once and the AEAD keyed off it.
    pub(crate) fn new(inner: BoxProxyStream, psk: &[u8], mode: V6Mode) -> Result<Self> {
        let profile = (mode == V6Mode::Default).then(|| V6Profile::new(psk));
        let (salt, aead) = match mode {
            V6Mode::UnsafeRaw => ([0u8; V6_SALT_SIZE], None),
            _ => {
                let mut salt = [0u8; V6_SALT_SIZE];
                rand::fill(&mut salt);
                (salt, Some(v6_aead(psk, &salt)?))
            }
        };
        Ok(V6Conn {
            inner,
            psk: psk.to_vec(),
            mode,
            profile,
            writer: V6Writer {
                aead,
                nonce: SsNonce::new(),
                salt,
                salt_sent: false,
                seq: 0,
                chunk_size: 0,
                last_write_unix: 0,
            },
            reader: None,
            stage: V6Stage::Header,
            rbuf: BytesMut::with_capacity(16 * 1024),
            out: BytesMut::with_capacity(16 * 1024),
            pending_zero: false,
        })
    }

    /// `payloadLimitFor` (v6.go:569-584): the shaped chunk schedule —
    /// the second-granular idle reset, the policy limit, the
    /// first-record cap, then the ramp advance. Returns 1..=0xffff.
    fn payload_limit_for(&mut self, now_unix: i64) -> usize {
        let profile = self
            .profile
            .as_ref()
            .expect("v6 profile exists in default mode");
        let w = &mut self.writer;
        if w.last_write_unix == 0 || now_unix - w.last_write_unix > profile.idle_reset_sec {
            w.chunk_size = profile.chunk_initial;
        }
        if w.chunk_size == 0 {
            w.chunk_size = profile.chunk_initial;
        }
        let mut payload_limit = profile.chunk_payload_limit(w.seq, w.chunk_size);
        if w.seq == 0 {
            payload_limit = payload_limit.min(profile.first_record_cap);
        }
        w.chunk_size = profile.next_chunk_size(w.chunk_size);
        w.last_write_unix = now_unix;
        payload_limit.clamp(1, V6_MAX_PAYLOAD as i64) as usize
    }

    /// `v6Conn.Write` (v6.go:173-189): an empty payload writes the zero
    /// chunk (half-close); otherwise `write` chunks by mode — the
    /// shaped writer by the schedule (one `now` for the whole call,
    /// v6.go:639-649), the others by v6MaxPayload.
    pub(crate) fn frame(&mut self, payload: &[u8], wbuf: &mut BytesMut) -> Result<()> {
        if payload.is_empty() {
            return self.frame_zero(wbuf);
        }
        match self.mode {
            V6Mode::UnsafeRaw => {
                for chunk in payload.chunks(V6_MAX_PAYLOAD) {
                    self.append_record(chunk, wbuf)?;
                }
            }
            V6Mode::Unshaped => {
                self.ensure_salt(wbuf);
                for chunk in payload.chunks(V6_MAX_PAYLOAD) {
                    self.append_record(chunk, wbuf)?;
                }
            }
            V6Mode::Default => {
                let now = unix_now();
                let mut rest = payload;
                while !rest.is_empty() {
                    let limit = self.payload_limit_for(now);
                    let end = rest.len().min(limit);
                    self.append_record(&rest[..end], wbuf)?;
                    rest = &rest[end..];
                }
            }
        }
        Ok(())
    }

    /// `WritePacketFrame` / `writePacket` (v6.go:191-207, 651-657): a
    /// UDP datagram is EXACTLY ONE record regardless of the chunk
    /// limit; the shaped writer still advances the schedule first.
    /// Payloads beyond v6MaxPayload are refused (errV6PayloadTooLong).
    pub(crate) fn frame_packet(&mut self, packet: &[u8], wbuf: &mut BytesMut) -> Result<()> {
        if packet.len() > V6_MAX_PAYLOAD {
            return Err(err_v6_payload_too_long());
        }
        match self.mode {
            V6Mode::UnsafeRaw => self.append_record(packet, wbuf),
            V6Mode::Unshaped => {
                self.ensure_salt(wbuf);
                self.append_record(packet, wbuf)
            }
            V6Mode::Default => {
                self.payload_limit_for(unix_now());
                self.append_record(packet, wbuf)
            }
        }
    }

    /// `writeZeroChunk` (v6.go:341-343, 470-472, 659-663): one
    /// zero-payload record (shaped: the schedule advances and the
    /// record may carry padding).
    fn frame_zero(&mut self, wbuf: &mut BytesMut) -> Result<()> {
        match self.mode {
            V6Mode::UnsafeRaw => self.append_record(&[], wbuf),
            V6Mode::Unshaped => {
                self.ensure_salt(wbuf);
                self.append_record(&[], wbuf)
            }
            V6Mode::Default => {
                self.payload_limit_for(unix_now());
                self.append_record(&[], wbuf)
            }
        }
    }

    /// The unshaped writer prefixes its salt exactly once
    /// (`writeRecords`, v6.go:433-454).
    fn ensure_salt(&mut self, wbuf: &mut BytesMut) {
        if !self.writer.salt_sent {
            wbuf.extend_from_slice(&self.writer.salt);
            self.writer.salt_sent = true;
        }
    }

    /// One record, per mode: `v6RawWriter.writeRecord` (v6.go:318-324),
    /// `v6UnshapedWriter.appendRecord` (v6.go:420-431) or the shaped
    /// `appendRecord` (v6.go:587-637).
    fn append_record(&mut self, payload: &[u8], wbuf: &mut BytesMut) -> Result<()> {
        match self.mode {
            V6Mode::UnsafeRaw => {
                // v6.go:318-324 — plaintext header + payload.
                let mut record = Vec::with_capacity(V6_HEADER_PLAIN + payload.len());
                let mut header = [0u8; V6_HEADER_PLAIN];
                v6_put_header(&mut header, 0, payload.len());
                record.extend_from_slice(&header);
                record.extend_from_slice(payload);
                wbuf.extend_from_slice(&record);
                Ok(())
            }
            V6Mode::Unshaped => {
                // v6.go:420-431 — the sealed header, then the sealed
                // payload (only when non-empty; the zero chunk is the
                // header alone, v6.go:426-429).
                let aead = self
                    .writer
                    .aead
                    .as_ref()
                    .expect("v6 unshaped writer carries an aead");
                let mut record = Vec::with_capacity(V6_HEADER_CIPHER + payload.len() + V6_TAG_SIZE);
                let mut header = [0u8; V6_HEADER_PLAIN];
                v6_put_header(&mut header, 0, payload.len());
                aead.seal(&self.writer.nonce.advance(), &[], &header, &mut record)?;
                if !payload.is_empty() {
                    aead.seal(&self.writer.nonce.advance(), &[], payload, &mut record)?;
                }
                wbuf.extend_from_slice(&record);
                Ok(())
            }
            V6Mode::Default => self.append_record_shaped(payload, wbuf),
        }
    }

    /// The shaped `appendRecord` (v6.go:587-637). Wire:
    /// `[salt block] || prefix || header_ct || padding || payload_ct`
    /// where the salt block's padding is generated for the sentinel
    /// sequence 0xffffffff with the salt bytes scattered over it, the
    /// prefix doubles as the header's AAD, and the padding doubles as
    /// the payload's AAD — the mix runs AFTER the seal (and before the
    /// reader's open, being self-inverse).
    fn append_record_shaped(&mut self, payload: &[u8], wbuf: &mut BytesMut) -> Result<()> {
        let profile = self
            .profile
            .as_ref()
            .expect("v6 profile exists in default mode");
        let prefix_len = profile.record_prefix_len(self.writer.seq);
        let (salt_block_len, salt_prefix_len) = if !self.writer.salt_sent {
            (
                profile.salt_block_len,
                profile.salt_block_len - V6_SALT_SIZE,
            )
        } else {
            (0, 0)
        };
        let padding_len = profile.padding_len(
            self.writer.seq,
            payload.len(),
            prefix_len,
            salt_prefix_len,
            salt_block_len,
        );
        if salt_block_len > 0 {
            let mut block = vec![0u8; salt_block_len];
            profile.fill_padding(u32::MAX, &mut block);
            profile.write_salt_block(&self.writer.salt, &mut block);
            wbuf.extend_from_slice(&block);
            self.writer.salt_sent = true;
        }
        let mut prefix = vec![0u8; prefix_len];
        profile.fill_padding(self.writer.seq, &mut prefix);

        let mut header = [0u8; V6_HEADER_PLAIN];
        v6_put_header(&mut header, padding_len, payload.len());
        let mut header_ct = Vec::with_capacity(V6_HEADER_CIPHER);
        let aead = self
            .writer
            .aead
            .as_ref()
            .expect("v6 shaped writer carries an aead");
        aead.seal(
            &self.writer.nonce.advance(),
            &prefix,
            &header,
            &mut header_ct,
        )?;

        let mut padding = vec![0u8; padding_len];
        profile.fill_padding(self.writer.seq, &mut padding);

        wbuf.extend_from_slice(&prefix);
        wbuf.extend_from_slice(&header_ct);
        if payload.is_empty() {
            wbuf.extend_from_slice(&padding);
        } else {
            let mut payload_ct = Vec::with_capacity(payload.len() + V6_TAG_SIZE);
            aead.seal(
                &self.writer.nonce.advance(),
                &padding,
                payload,
                &mut payload_ct,
            )?;
            profile.mix_padding_payload(self.writer.seq, &mut padding, &mut payload_ct);
            wbuf.extend_from_slice(&padding);
            wbuf.extend_from_slice(&payload_ct);
        }
        self.writer.seq += 1;
        Ok(())
    }

    /// `readRecord` (v6.go:292-312 raw, 354-397 unshaped, 485-541
    /// shaped), staged so a nonce tick always accompanies consuming its
    /// ciphertext. `Ok(true)` = a payload landed in `out`; `Ok(false)`
    /// = more wire bytes are needed, or a zero chunk is pending as EOF.
    pub(crate) fn try_parse(&mut self) -> Result<bool> {
        if self.reader.is_none() {
            match self.mode {
                V6Mode::UnsafeRaw => {
                    // No salt, no crypto (v6.go:288-290).
                    self.reader = Some(V6Reader {
                        aead: None,
                        nonce: SsNonce::new(),
                        seq: 0,
                    });
                }
                V6Mode::Unshaped => {
                    // v6.go:355-365 — the bare 16-byte salt prefix.
                    if self.rbuf.len() < V6_SALT_SIZE {
                        return Ok(false);
                    }
                    let salt: [u8; V6_SALT_SIZE] =
                        self.rbuf[..V6_SALT_SIZE].try_into().expect("16 bytes");
                    self.rbuf.advance(V6_SALT_SIZE);
                    self.reader = Some(V6Reader {
                        aead: Some(v6_aead(&self.psk, &salt)?),
                        nonce: SsNonce::new(),
                        seq: 0,
                    });
                }
                V6Mode::Default => {
                    // v6.go:486-497 — the shaped salt block.
                    let profile = self
                        .profile
                        .as_ref()
                        .expect("v6 profile exists in default mode");
                    if self.rbuf.len() < profile.salt_block_len {
                        return Ok(false);
                    }
                    let block = self.rbuf[..profile.salt_block_len].to_vec();
                    self.rbuf.advance(profile.salt_block_len);
                    let salt = profile.extract_salt(&block);
                    self.reader = Some(V6Reader {
                        aead: Some(v6_aead(&self.psk, &salt)?),
                        nonce: SsNonce::new(),
                        seq: 0,
                    });
                }
            }
        }
        loop {
            match self.stage {
                V6Stage::Header => {
                    // Shaped records carry a per-seq unencrypted prefix
                    // in front of the sealed header (v6.go:499-505).
                    let prefix_len = match (self.mode, self.reader.as_ref()) {
                        (V6Mode::Default, Some(r)) => self
                            .profile
                            .as_ref()
                            .expect("v6 profile exists in default mode")
                            .record_prefix_len(r.seq),
                        _ => 0,
                    };
                    let wire_len = match self.mode {
                        V6Mode::UnsafeRaw => V6_HEADER_PLAIN,
                        _ => prefix_len + V6_HEADER_CIPHER,
                    };
                    if self.rbuf.len() < wire_len {
                        return Ok(false);
                    }
                    let (padding_len, payload_len, seq) = match self.mode {
                        V6Mode::UnsafeRaw => {
                            // v6.go:292-312 — strict plaintext parse;
                            // raw records never carry padding.
                            let header: [u8; V6_HEADER_PLAIN] =
                                self.rbuf[..V6_HEADER_PLAIN].try_into().expect("7 bytes");
                            let (padding_len, payload_len) = v6_parse_header(&header, true)?;
                            if padding_len != 0 {
                                return Err(err_v6_record_padding());
                            }
                            self.rbuf.advance(V6_HEADER_PLAIN);
                            (padding_len, payload_len, 0)
                        }
                        _ => {
                            let prefix = self.rbuf[..prefix_len].to_vec();
                            let header_ct =
                                self.rbuf[prefix_len..prefix_len + V6_HEADER_CIPHER].to_vec();
                            self.rbuf.advance(wire_len);
                            let r = self.reader.as_mut().expect("initialized above");
                            let header = r
                                .aead
                                .as_ref()
                                .expect("sealed modes carry an aead")
                                .open(&r.nonce.advance(), &prefix, &header_ct)?;
                            // v6.go:511-512 — the reserved header bytes
                            // are IGNORED in default mode; strict
                            // everywhere else.
                            let strict = self.mode == V6Mode::Unshaped;
                            let (padding_len, payload_len) = v6_parse_header(&header, strict)?;
                            if strict && padding_len != 0 {
                                return Err(err_v6_record_padding());
                            }
                            let seq = r.seq;
                            r.seq += 1;
                            (padding_len, payload_len, seq)
                        }
                    };
                    if payload_len == 0 {
                        if padding_len > 0 {
                            // v6.go:519-525 — discard the padding first.
                            self.stage = V6Stage::ZeroPadding {
                                discard: padding_len,
                            };
                            continue;
                        }
                        self.pending_zero = true;
                        self.stage = V6Stage::Header;
                        return Ok(false);
                    }
                    self.stage = V6Stage::Body {
                        padding_len,
                        payload_len,
                        seq,
                    };
                }
                V6Stage::ZeroPadding { discard } => {
                    if self.rbuf.len() < discard {
                        return Ok(false);
                    }
                    self.rbuf.advance(discard);
                    self.pending_zero = true;
                    self.stage = V6Stage::Header;
                    return Ok(false);
                }
                V6Stage::Body {
                    padding_len,
                    payload_len,
                    seq,
                } => {
                    let tag = match self.mode {
                        V6Mode::UnsafeRaw => 0,
                        _ => V6_TAG_SIZE,
                    };
                    let total = padding_len + payload_len + tag;
                    if self.rbuf.len() < total {
                        return Ok(false);
                    }
                    let mut body = self.rbuf[..total].to_vec();
                    self.rbuf.advance(total);
                    let payload = match self.mode {
                        V6Mode::UnsafeRaw => {
                            // padding_len == 0 was enforced at the
                            // header; the body is the raw payload.
                            body
                        }
                        V6Mode::Unshaped => {
                            let r = self.reader.as_mut().expect("initialized above");
                            r.aead.as_ref().expect("sealed modes carry an aead").open(
                                &r.nonce.advance(),
                                &[],
                                &body,
                            )?
                        }
                        V6Mode::Default => {
                            // v6.go:528-540 — un-mix, then open with the
                            // (restored) padding as AAD.
                            let profile = self
                                .profile
                                .as_ref()
                                .expect("v6 profile exists in default mode");
                            let (padding, payload_ct) = body.split_at_mut(padding_len);
                            profile.mix_padding_payload(seq, padding, payload_ct);
                            let r = self.reader.as_mut().expect("initialized above");
                            r.aead.as_ref().expect("sealed modes carry an aead").open(
                                &r.nonce.advance(),
                                padding,
                                payload_ct,
                            )?
                        }
                    };
                    self.out.extend_from_slice(&payload);
                    self.stage = V6Stage::Header;
                    return Ok(true);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::NetAddr;
    use crate::proto::snell::{handshake, SnellOut, SnellServerConn, SnellServerRequest};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// `v6TestPSK` (v6_test.go:24) — 25 bytes, inside the v6 PSK range.
    const V6_TEST_PSK: &[u8] = b"snell-v6-test-psk-0123456789";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ------------------------------------------------------ mode + gates

    /// GOLDEN VECTORS — derived by compiling the ACTUAL upstream
    /// v6_profile.go (mihomo 12b81d4) in a scratch Go harness and
    /// printing the profile for psk "snell-v6-test-psk-0123456789".
    /// A one-digit typo in any transcribed constant breaks these
    /// assertions — the executable trace the port-time diff lacked.
    #[test]
    fn v6_profile_golden_vectors() {
        let psk = b"snell-v6-test-psk-0123456789";
        let p = V6Profile::new(psk);
        // go_out.txt: generator=1 padMin=87 padMax=578 padCount=7
        // padInterval=4 smallLimit=570
        assert_eq!(p.generator, 1);
        assert_eq!(p.pad_min, 87);
        assert_eq!(p.pad_max, 578);
        assert_eq!(p.pad_count, 7);
        assert_eq!(p.pad_interval, 4);
        assert_eq!(p.small_limit, 570);
        assert_eq!(p.bit_min, 26);
        assert_eq!(p.bit_max, 76);
        assert_eq!(p.prefix_min_record, 16);
        assert_eq!(p.prefix_max_record, 57);
        // mixMode=0 mixRounds=2 mixStride=7 mixOffsetBase=4 mixBlock=57
        assert_eq!(p.mix_mode, 0);
        assert_eq!(p.mix_rounds, 2);
        assert_eq!(p.mix_stride, 7);
        assert_eq!(p.mix_offset_base, 4);
        assert_eq!(p.mix_block, 57);
        // chunkPolicy=2 chunkInitial=515 firstRecordCap=515 chunkMax=13054
        // chunkStep=2920 chunkJitter=27 idleResetSec=76
        assert_eq!(p.chunk_policy, 2);
        assert_eq!(p.chunk_initial, 515);
        assert_eq!(p.first_record_cap, 515);
        assert_eq!(p.chunk_max, 13054);
        assert_eq!(p.chunk_step, 2920);
        assert_eq!(p.chunk_jitter, 27);
        assert_eq!(p.idle_reset_sec, 76);
        // writePolicy=1 writeFirst=7 writeJitter=24 writeJitterPct=20
        assert_eq!(p.write_policy, 1);
        assert_eq!(p.write_first, 7);
        assert_eq!(p.write_jitter, 24);
        assert_eq!(p.write_jitter_pct, 20);
        // g1..g6, salt block, handshake mixing
        assert_eq!(p.g1, 59);
        assert_eq!(p.g2, 47);
        assert_eq!(p.g3, 45);
        assert_eq!(p.g4, 4);
        assert_eq!(p.g5, 3);
        assert_eq!(p.g6, 11);
        assert_eq!(p.salt_block_len, 122);
        assert_eq!(p.mix_stride_handshake, 19);
        assert_eq!(p.mix_rounds_handshake, 2);
        // chunkBuckets=[4601 6500 9133 10624 6077 10142 6261 4850]
        assert_eq!(
            p.chunk_buckets,
            [4601, 6500, 9133, 10624, 6077, 10142, 6261, 4850]
        );
        // writeBuckets=[584 884 672 611 960 456 635 1228]
        assert_eq!(p.write_buckets, [584, 884, 672, 611, 960, 456, 635, 1228]);
        // writeSeq=[409 672 377 811 1438 1221 1018 1111]
        assert_eq!(p.write_seq, [409, 672, 377, 811, 1438, 1221, 1018, 1111]);
        // secret= b6f5438a…
        let secret = v6_profile_secret(psk);
        assert_eq!(
            secret,
            [
                0xb6, 0xf5, 0x43, 0x8a, 0xc8, 0x6d, 0xea, 0xfa, 0x46, 0xaf, 0x47, 0x73, 0x17, 0x78,
                0x9b, 0xa0, 0xd1, 0x09, 0x06, 0xef, 0x7c, 0xfa, 0x46, 0xde, 0xd1, 0x7c, 0x50, 0xcf,
                0x99, 0x81, 0xbf, 0x00,
            ]
        );
        // Per-seq prefix lengths and first padding blocks.
        assert_eq!(p.record_prefix_len(0), 33);
        assert_eq!(p.record_prefix_len(1), 42);
        assert_eq!(p.record_prefix_len(2), 41);
        assert_eq!(p.record_prefix_len(3), 51);
        let mut pad = [0u8; 24];
        p.fill_padding(0, &mut pad);
        assert_eq!(
            pad,
            [
                0xf8, 0xa0, 0x88, 0x30, 0x94, 0x82, 0x9d, 0xfa, 0x8b, 0x68, 0x4e, 0x49, 0x55, 0xbd,
                0x6d, 0xf9, 0x8d, 0x5b, 0x6b, 0xb1, 0x2a, 0x23, 0x5c, 0x37,
            ]
        );
    }

    #[test]
    fn v6_parse_mode() {
        // TestV6ParseMode (v6_test.go:26-34).
        for name in ["", "default", "unshaped", "unsafe-raw"] {
            assert!(parse_v6_mode(name).is_ok(), "{name}");
        }
        assert_eq!(parse_v6_mode("").unwrap(), V6Mode::Default);
        assert_eq!(parse_v6_mode("default").unwrap(), V6Mode::Default);
        assert_eq!(parse_v6_mode("unshaped").unwrap(), V6Mode::Unshaped);
        assert_eq!(parse_v6_mode("unsafe-raw").unwrap(), V6Mode::UnsafeRaw);
        let err = parse_v6_mode("bogus").unwrap_err().to_string();
        assert!(err.contains("snell v6 unknown mode: bogus"), "{err}");
        // The error lists the three accepted values.
        for want in ["default", "unshaped", "unsafe-raw"] {
            assert!(err.contains(want), "{err} must list {want}");
        }
        assert_eq!(V6Mode::Unshaped.to_string(), "unshaped");
        assert_eq!(V6Mode::Default.to_string(), "default");
        assert_eq!(V6Mode::UnsafeRaw.to_string(), "unsafe-raw");
    }

    #[test]
    fn v6_validate_psk_boundaries() {
        // TestValidateV6PSK (v6_test.go:200-204) + the exact
        // 11/12/255/256 boundaries around V6MinPSKLength/V6MaxPSKLength.
        assert!(validate_v6_psk(b"short").is_err());
        assert!(validate_v6_psk(&[0u8; 11]).is_err());
        assert!(validate_v6_psk(&[0u8; 12]).is_ok());
        assert!(validate_v6_psk(&[0u8; 255]).is_ok());
        assert!(validate_v6_psk(&[0u8; 256]).is_err());
        assert!(validate_v6_psk(V6_TEST_PSK).is_ok());
        let err = validate_v6_psk(b"short").unwrap_err().to_string();
        assert!(
            err.contains("snell v6 psk length must be between 12 and 255 bytes"),
            "{err}"
        );
    }

    #[test]
    fn v6_config_gates() {
        // The cross-version rules: listener/snell/server.go:42-45 and
        // adapter/outbound/snell.go:270-274, 283-285.
        let err = validate_mode_for_version(5, "default", "inbound")
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "config: snell inbound mode is only supported on version 6"
        );
        assert!(validate_mode_for_version(6, "default", "inbound").is_ok());
        assert!(validate_mode_for_version(5, "", "inbound").is_ok());
        let err = validate_v6_obfs("http", "inbound").unwrap_err().to_string();
        assert_eq!(
            err,
            "config: snell inbound version 6 does not support obfs mode http"
        );
        let err = validate_v6_obfs("tls", "proxy-0").unwrap_err().to_string();
        assert_eq!(
            err,
            "config: snell proxy-0 version 6 does not support obfs mode tls"
        );
        assert!(validate_v6_obfs("", "inbound").is_ok());
        assert!(validate_v6_obfs("shadow-tls", "inbound").is_ok());
    }

    // ------------------------------------------------------ profile core

    #[test]
    fn v6_blake2b256_reference_vectors() {
        // Pin the profile-secret primitive (v6ProfileSecret,
        // v6_profile.go:274-279 = Go blake2b.Sum256) against the
        // official BLAKE2b-256 test vectors.
        use blake2::digest::{Update, VariableOutput};
        let sum256 = |input: &[u8]| -> [u8; 32] {
            let mut hasher = blake2::Blake2bVar::new(32).unwrap();
            hasher.update(input);
            let mut out = [0u8; 32];
            hasher.finalize_variable(&mut out).unwrap();
            out
        };
        assert_eq!(
            hex(&sum256(b"abc")),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
        assert_eq!(
            hex(&sum256(b"")),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
        // The seed prefix is exactly v6_profile.go:93-96.
        assert_eq!(
            hex(&V6_PROFILE_SEED),
            "8d41a7135ce209bb702fd6943318c06e4a9125fdb80377ac"
        );
    }

    #[test]
    fn v6_profile_deterministic() {
        // TestV6ProfileDeterministic (v6_test.go:36-43): same psk → the
        // same profile; a different psk → different namespaces.
        let a = V6Profile::new(V6_TEST_PSK);
        let b = V6Profile::new(V6_TEST_PSK);
        assert_eq!(a, b, "same psk must derive the same profile");
        let c = V6Profile::new(b"snell-v6-test-psk-0123456789x");
        assert_ne!(
            a.namespaces, c.namespaces,
            "different psk must derive a different profile"
        );
        // Same psk → the same prefix/padding schedule.
        for seq in [0u32, 1, 2, 7, 1000] {
            assert_eq!(a.record_prefix_len(seq), b.record_prefix_len(seq));
            let mut pa = [0u8; 64];
            let mut pb = [0u8; 64];
            a.fill_padding(seq, &mut pa);
            b.fill_padding(seq, &mut pb);
            assert_eq!(pa, pb);
        }
    }

    #[test]
    fn v6_salt_block_round_trip() {
        // TestV6SaltBlockRoundTrip (v6_test.go:45-60).
        for i in 0..32 {
            let mut psk = [0u8; 24];
            rand::fill(&mut psk);
            let profile = V6Profile::new(&psk);

            let mut salt = [0u8; V6_SALT_SIZE];
            rand::fill(&mut salt);
            let mut block = vec![0u8; profile.salt_block_len];
            profile.fill_padding(u32::MAX, &mut block);
            profile.write_salt_block(&salt, &mut block);
            let extracted = profile.extract_salt(&block);
            assert_eq!(salt, extracted, "iteration {i}");
        }
    }

    #[test]
    fn v6_mix_round_trip() {
        // TestV6MixRoundTrip (v6_test.go:62-81) — the interleave is its
        // own inverse for every profile the PRFs produce.
        for i in 0..32 {
            let mut psk = [0u8; 16];
            rand::fill(&mut psk);
            let profile = V6Profile::new(&psk);

            let mut padding = [0u8; 300];
            let mut payload = [0u8; 700];
            rand::fill(&mut padding);
            rand::fill(&mut payload);
            let orig_padding = padding;
            let orig_payload = payload;

            profile.mix_padding_payload(i, &mut padding, &mut payload);
            profile.mix_padding_payload(i, &mut padding, &mut payload);
            assert_eq!(padding, orig_padding, "iteration {i}");
            assert_eq!(payload, orig_payload, "iteration {i}");
        }
    }

    #[test]
    fn v6_profile_ranges_respect_constraints() {
        // The invariants the upstream clamps guarantee (v6_profile.go
        // :285-348) hold for every profile drawn from any in-range psk.
        for len in [12usize, 16, 24, 64, 255] {
            let psk = vec![0x5au8; len];
            let p = V6Profile::new(&psk);
            assert!((0x18..=0xa0).contains(&p.pad_min), "padMin {len}");
            assert!(p.pad_max <= V6_MAX_EXTRA_PADDING, "padMax {len}");
            assert!((0x08..=0x80).contains(&p.prefix_min_record), "{len}");
            assert!(p.prefix_max_record <= 0x80, "{len}");
            assert!(p.prefix_min_record <= p.prefix_max_record, "{len}");
            assert!(p.chunk_initial >= 0x60, "{len}");
            assert!(p.first_record_cap >= 0x100, "{len}");
            assert!(p.chunk_max >= p.chunk_initial, "{len}");
            assert!(p.chunk_max <= 0x3fff, "{len}");
            assert!(p.chunk_step <= 0x0b68, "{len}");
            assert!(p.chunk_jitter <= 0x0b6, "{len}");
            assert!((0x0c..=0x5a).contains(&p.idle_reset_sec), "{len}");
            assert!(
                p.salt_block_len >= V6_SALT_SIZE + 0x10 && p.salt_block_len <= V6_SALT_SIZE + 0x80,
                "{len}"
            );
            assert!(p.mix_block >= 8, "{len}");
            assert!(p.generator <= 3, "{len}");
            assert!(
                p.mix_mode < 3 && p.chunk_policy < 3 && p.write_policy < 3,
                "{len}"
            );
            assert!((4..=8).contains(&p.write_first), "{len}");
            // The prefix schedule stays inside the record window.
            for seq in 0u32..64 {
                let prefix = p.record_prefix_len(seq);
                assert!(prefix >= p.prefix_min_record as usize, "{len}/{seq}");
                assert!(prefix <= p.prefix_max_record as usize, "{len}/{seq}");
            }
            // The chunk schedule never yields < 0x40 or > chunkMax.
            let mut size = 0i64;
            for seq in 0u32..64 {
                size = p.next_chunk_size(size);
                let limit = p.chunk_payload_limit(seq, size);
                assert!(limit >= 0x40 && limit <= p.chunk_max, "{len}/{seq}");
            }
            // The padding targets stay inside a u16 (v6.go:399).
            for payload_len in [0usize, 1, 0x60, 0x400, 0x2000] {
                let padding = p.padding_len(3, payload_len, 0x20, 0, 0);
                assert!(padding <= 0xffff, "{len}/{payload_len}");
                let first = p.padding_len(0, payload_len, 0x20, 0x30, p.salt_block_len);
                assert!(first <= 0xffff, "{len}/{payload_len}");
            }
        }
    }

    // ------------------------------------------------------ record layer

    /// Drive one `read` off a raw V6Conn (the test-side mirror of
    /// `v6Conn.Read`, v6.go:154-171): Ok(0) = the zero chunk / EOF.
    async fn conn_read(c: &mut V6Conn, buf: &mut [u8]) -> std::io::Result<usize> {
        // Conn::poll_fill's loop order: parse the buffered bytes first,
        // hit the transport only when the buffer cannot yield a record.
        loop {
            if !c.out.is_empty() {
                let n = buf.len().min(c.out.len());
                buf[..n].copy_from_slice(&c.out[..n]);
                c.out.advance(n);
                return Ok(n);
            }
            if c.pending_zero {
                return Ok(0);
            }
            if c.try_parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
            {
                continue;
            }
            if c.pending_zero {
                return Ok(0);
            }
            let mut tmp = [0u8; 16 * 1024];
            let n = c.inner.read(&mut tmp).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "v6: transport closed inside a record",
                ));
            }
            c.rbuf.extend_from_slice(&tmp[..n]);
        }
    }

    async fn conn_read_exact(c: &mut V6Conn, want: usize) -> std::io::Result<Vec<u8>> {
        let mut got = vec![0u8; want];
        let mut filled = 0;
        while filled < want {
            let n = conn_read(c, &mut got[filled..]).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "v6: zero chunk before the expected bytes",
                ));
            }
            filled += n;
        }
        Ok(got)
    }

    async fn conn_write(c: &mut V6Conn, payload: &[u8]) -> Result<()> {
        let mut wbuf = BytesMut::new();
        c.frame(payload, &mut wbuf)?;
        c.inner.write_all(&wbuf).await?;
        c.inner.flush().await?;
        Ok(())
    }

    async fn conn_write_packet(c: &mut V6Conn, packet: &[u8]) -> Result<()> {
        let mut wbuf = BytesMut::new();
        c.frame_packet(packet, &mut wbuf)?;
        c.inner.write_all(&wbuf).await?;
        c.inner.flush().await?;
        Ok(())
    }

    /// `v6Pair` (v6_test.go:85-109) over a duplex — the record layer
    /// only needs a byte pipe.
    fn v6_pair(mode: V6Mode, psk: &[u8]) -> (V6Conn, V6Conn) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        (
            V6Conn::new(Box::new(client_io), psk, mode).unwrap(),
            V6Conn::new(Box::new(server_io), psk, mode).unwrap(),
        )
    }

    #[tokio::test]
    async fn v6_stream_round_trip_all_modes() {
        // TestV6ConnStream (v6_test.go:111-150): 300 KiB uplink, the
        // zero chunk ends the stream, the downlink works independently.
        for mode in [V6Mode::Default, V6Mode::Unshaped, V6Mode::UnsafeRaw] {
            let (mut client, mut server) = v6_pair(mode, V6_TEST_PSK);
            let payload: Vec<u8> = (0..300 * 1024).map(|i| (i % 251) as u8).collect();

            // The reader task owns `server` and hands it back.
            let want = payload.clone();
            let reader = tokio::spawn(async move {
                let got = conn_read_exact(&mut server, want.len()).await;
                (server, got)
            });
            conn_write(&mut client, &payload).await.unwrap();
            conn_write(&mut client, &[]).await.unwrap(); // HalfClose
            let (mut server, got) =
                tokio::time::timeout(std::time::Duration::from_secs(30), reader)
                    .await
                    .expect("timeout")
                    .unwrap();
            assert_eq!(got.unwrap(), payload, "payload mismatch ({mode})");

            // The zero chunk ends the stream (ErrZeroChunk → EOF).
            let mut one = [0u8; 1];
            assert_eq!(
                conn_read(&mut server, &mut one).await.unwrap(),
                0,
                "expected the zero chunk after the payload ({mode})"
            );

            // And the other direction works independently.
            let reply = b"hello from server";
            conn_write(&mut server, reply).await.unwrap();
            let got = conn_read_exact(&mut client, reply.len()).await.unwrap();
            assert_eq!(got, reply, "reply mismatch ({mode})");
        }
    }

    #[tokio::test]
    async fn v6_packet_frames_one_record_per_datagram() {
        // TestV6ConnPacketFrames (v6_test.go:152-173): sizes above the
        // shaped chunk limit must still arrive as ONE record.
        for mode in [V6Mode::Default, V6Mode::Unshaped, V6Mode::UnsafeRaw] {
            let (mut client, mut server) = v6_pair(mode, V6_TEST_PSK);
            for round in 0..20usize {
                let packet: Vec<u8> = (0..1400 + round * 97)
                    .map(|i| (i * 31 % 251) as u8)
                    .collect();
                conn_write_packet(&mut client, &packet).await.unwrap();

                let mut buf = vec![0u8; 64 * 1024];
                let n = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    conn_read(&mut server, &mut buf),
                )
                .await
                .expect("timeout")
                .unwrap();
                assert_eq!(
                    n,
                    packet.len(),
                    "a packet frame must be read back in one piece ({mode}, round {round})"
                );
                assert_eq!(&buf[..n], &packet[..], "{mode}, round {round}");
            }
            // Beyond v6MaxPayload the packet frame is refused
            // (errV6PayloadTooLong, v6.go:192-194).
            let mut wbuf = BytesMut::new();
            assert!(
                client
                    .frame_packet(&vec![0u8; V6_MAX_PAYLOAD + 1], &mut wbuf)
                    .is_err(),
                "oversized datagram must be refused ({mode})"
            );
        }
    }

    #[tokio::test]
    async fn v6_wrong_psk_is_not_readable() {
        // TestV6ConnWrongPSK (v6_test.go:175-198): with a different
        // server psk the record layer never yields readable plaintext.
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let mut client = V6Conn::new(Box::new(client_io), V6_TEST_PSK, V6Mode::Default).unwrap();
        let mut server = V6Conn::new(
            Box::new(server_io),
            b"snell-v6-test-psk-012345678-",
            V6Mode::Default,
        )
        .unwrap();
        conn_write(&mut client, b"hello").await.unwrap();
        let mut buf = [0u8; 16];
        let err = conn_read(&mut server, &mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    }

    #[test]
    fn v6_reserved_bytes_unshaped_strict_default_ignores() {
        // v6ParseHeader's strict flag (v6.go:273-284): a set reserved
        // byte is rejected by the unshaped/raw readers and IGNORED by
        // the shaped reader (v6.go:511-512). Craft both wire forms by
        // hand at the AEAD level.
        let psk = V6_TEST_PSK;

        // --- unshaped: strict → the record is rejected.
        let salt = [7u8; V6_SALT_SIZE];
        let aead = v6_aead(psk, &salt).unwrap();
        let (client_io, server_io) = tokio::io::duplex(4096);
        let mut server = V6Conn::new(Box::new(server_io), psk, V6Mode::Unshaped).unwrap();
        server.rbuf.extend_from_slice(&salt);
        let mut header = [0u8; V6_HEADER_PLAIN];
        v6_put_header(&mut header, 0, 2);
        header[1] = 1; // reserved byte set
        let mut wire = Vec::new();
        let mut nonce = SsNonce::new();
        aead.seal(&nonce.advance(), &[], &header, &mut wire)
            .unwrap();
        aead.seal(&nonce.advance(), &[], b"ab", &mut wire).unwrap();
        server.rbuf.extend_from_slice(&wire);
        drop(client_io);
        let err = server.try_parse().unwrap_err().to_string();
        assert!(err.contains("snell v6 invalid record header"), "{err}");

        // --- default (shaped): the same reserved byte is ignored.
        let profile = V6Profile::new(psk);
        let salt = [9u8; V6_SALT_SIZE];
        let aead = v6_aead(psk, &salt).unwrap();
        let (client_io, server_io) = tokio::io::duplex(4096);
        let mut server = V6Conn::new(Box::new(server_io), psk, V6Mode::Default).unwrap();
        let mut block = vec![0u8; profile.salt_block_len];
        profile.fill_padding(u32::MAX, &mut block);
        profile.write_salt_block(&salt, &mut block);
        server.rbuf.extend_from_slice(&block);
        let mut prefix = vec![0u8; profile.record_prefix_len(0)];
        profile.fill_padding(0, &mut prefix);
        server.rbuf.extend_from_slice(&prefix);
        let mut header = [0u8; V6_HEADER_PLAIN];
        v6_put_header(&mut header, 0, 2);
        header[2] = 1; // the other reserved byte
        let mut wire = Vec::new();
        let mut nonce = SsNonce::new();
        aead.seal(&nonce.advance(), &prefix, &header, &mut wire)
            .unwrap();
        aead.seal(&nonce.advance(), &[], b"cd", &mut wire).unwrap();
        server.rbuf.extend_from_slice(&wire);
        drop(client_io);
        assert!(server.try_parse().unwrap(), "shaped reader ignores rsv");
        assert_eq!(server.out.to_vec(), b"cd");
    }

    // ------------------------------------------------ full-stack (v4 layers on top)

    /// An echo server over the real server codec: one connect request,
    /// tunnel reply, echo until the client goes away
    /// (listener/snell/server.go's relay shape, compressed).
    async fn v6_echo_server(io: DuplexStream, psk: Vec<u8>, mode: V6Mode) {
        let mut conn = SnellServerConn::new(Box::new(io), &psk, 6, mode).unwrap();
        match conn.read_request().await.unwrap() {
            SnellServerRequest::Connect { target, .. } => {
                assert_eq!(target.host.to_text(), "echo.example");
                assert_eq!(target.port, 443);
            }
            other => panic!("expected connect, got {other:?}"),
        }
        // into_tcp prefixes the tunnel reply on the first relay write
        // (tcpRequestConn.Write, server.go:344-359) — no explicit
        // write_tunnel_reply here, or the reply byte would double.
        let mut tcp = conn.into_tcp(false, None);
        let mut buf = [0u8; 8192];
        loop {
            match tcp.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => tcp.write_all(&buf[..n]).await.unwrap(),
            }
        }
    }

    #[tokio::test]
    async fn v6_full_stack_round_trip_all_modes() {
        // The unchanged request/reply layer over the v6 record codec:
        // handshake (request header + lazy tunnel reply) + echo, for
        // every mode.
        for mode in [V6Mode::Default, V6Mode::Unshaped, V6Mode::UnsafeRaw] {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let psk = V6_TEST_PSK.to_vec();
            tokio::spawn(v6_echo_server(server_io, psk.clone(), mode));
            let cfg = SnellOut {
                server: "127.0.0.1".into(),
                port: 0,
                fronting: None,
                psk: String::from_utf8_lossy(&psk).into_owned(),
                version: 6,
                udp: false,
                v6_mode: mode,
            };
            let target = NetAddr::domain("echo.example", 443).unwrap();
            let mut stream = handshake(Box::new(client_io), &cfg, &target, false)
                .await
                .unwrap();

            let payload: Vec<u8> = (0..64 * 1024 + 137).map(|i| (i % 251) as u8).collect();
            stream.write_all(&payload).await.unwrap();
            let mut got = vec![0u8; payload.len()];
            tokio::time::timeout(
                std::time::Duration::from_secs(20),
                stream.read_exact(&mut got),
            )
            .await
            .expect("echo timeout")
            .unwrap();
            assert_eq!(got, payload, "echo mismatch ({mode})");
        }
    }
}
