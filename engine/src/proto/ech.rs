//! Encrypted Client Hello (ECH) core for the engine's own TLS 1.3 stack,
//! ported from the TLS fork mihomo links (`github.com/metacubex/tls`,
//! branch `main` — file `ech.go`, plus the client pieces of
//! `handshake_client.go` / `handshake_client_tls13.go`) and its HPKE
//! dependency `github.com/metacubex/hpke` (RFC 9180).
//!
//! # Provenance and versions
//!
//! * **ECHConfigList wire format**: `parseECHConfigList` /
//!   `parseECHConfig` are ported 1:1 from metacubex/tls `ech.go:56-150`
//!   (byte-identical twin: mihomo `component/ech/echparser/echparser.go`).
//!   The format comment there pins the version: *"parseECHConfigList
//!   parses a draft-ietf-tls-esni-18 ECHConfigList"* — draft 18 is the
//!   final draft that shipped as **RFC 9460**; the extension id
//!   `0xfe0d` (`ech.go` via `common.go:128`) is the draft-13+ / RFC 9460
//!   value, NOT the older draft-esi-13 `0xff02`.
//! * **HPKE**: base-mode Sender only (RFC 9180 §5.1.1 / §6), the
//!   `DHKEM(X25519, HKDF-SHA256)` KEM (id `0x0020`), `HKDF-SHA256` KDF
//!   (id `0x0001`) and the `AES-128-GCM` / `AES-256-GCM` /
//!   `ChaCha20-Poly1305` AEADs (ids `0x0001`/`0x0002`/`0x0003`) — the
//!   exact suite surface mihomo's `component/ech/key.go:22-34` declares
//!   and `pickECHConfig` (`ech.go:152-195`) selects from. Primitives
//!   come from `ring` 0.17 (HKDF/AES-GCM/ChaCha20-Poly1305) and
//!   `curve25519-dalek` (X25519), mirroring the Go code's
//!   `crypto/ecdh` + `cipher.AEAD` structure; KDFs other than
//!   HKDF-SHA256 and KEMs other than X25519 are skipped exactly where
//!   upstream `continue`s.
//!
//! # The wiring seam (read this before wiring)
//!
//! **rustls has no ECH and quinn uses rustls, so runtime ECH on the
//! engine's rustls paths is impossible.** The consumer of this module is
//! the engine's own TLS 1.3 client stack (`engine/src/proto/reality/`
//! tls13 layer), which is expected to call, in order:
//!
//! 1. [`parse_ech_config_list`] → [`pick_ech_config`] on the
//!    ECHConfigList bytes (from config or DNS discovery);
//! 2. [`ech_hpke_info`] → [`HpkeSender::setup`] to build the HPKE
//!    context (`info = "tls ech\x00" ‖ config.raw`,
//!    metacubex/tls `handshake_client.go:193-194`);
//! 3. [`encode_inner_client_hello`] for the padded encoded inner hello,
//!    then [`compute_outer_ech_ext`] — the standalone form of
//!    `computeAndUpdateOuterECHExtension` (`ech.go:418-449`): the outer
//!    hello is first serialized with an all-zero placeholder payload of
//!    `len(encoded_inner) + 16` bytes, that serialization (minus the
//!    4-byte handshake header) is the AEAD AAD, and the final
//!    `encrypted_client_hello` extension body carries the ciphertext;
//! 4. [`server_hello_accept_confirmation`] / [`hrr_accept_confirmation`]
//!    against the last 8 bytes of the ServerHello random
//!    (`handshake_client_tls13.go:86-116` and `:255-279`) to decide
//!    acceptance vs. rejection (alert `ech_required` + retry configs).
//!
//! The config surface mirrors mihomo `adapter/outbound/ech.go`
//! `ECHOptions` (`enable`, `config` base64 ECHConfigList,
//! `query-server-name`) — see [`EchOptions`].

use curve25519_dalek::montgomery::MontgomeryPoint;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::Prk;
use ring::{aead, digest, hkdf};

use crate::error::{Error, Result};

/// `extensionEncryptedClientHello` (metacubex/tls `common.go:128`); the
/// draft-ietf-tls-esni-18 / RFC 9460 value.
pub const EXTENSION_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
/// `extensionECHOuterExtensions` (metacubex/tls `common.go:127`) — the
/// inner-hello compression reference to outer extensions (RFC 9460 §6.1).
pub const EXTENSION_ECH_OUTER_EXTENSIONS: u16 = 0xfd00;

/// `DHKEM(X25519, HKDF-SHA256)` (HPKE KEM id; mihomo `component/ech/key.go:28`).
pub const KEM_DH_X25519_HKDF_SHA256: u16 = 0x0020;
/// `KDF_HKDF_SHA256` (HPKE KDF id; mihomo `component/ech/key.go:29`).
pub const KDF_HKDF_SHA256: u16 = 0x0001;
/// `AEAD_AES_128_GCM` (mihomo `component/ech/key.go:22`).
pub const AEAD_AES_128_GCM: u16 = 0x0001;
/// `AEAD_AES_256_GCM` (mihomo `component/ech/key.go:23`).
pub const AEAD_AES_256_GCM: u16 = 0x0002;
/// `AEAD_ChaCha20Poly1305` (mihomo `component/ech/key.go:24`).
pub const AEAD_CHACHA20_POLY1305: u16 = 0x0003;

// ---------------------------------------------------------------------------
// ECHConfigList parsing (metacubex/tls ech.go:17-150)
// ---------------------------------------------------------------------------

/// One symmetric cipher suite of an ECHConfig (`echCipher`, ech.go:17-20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchCipher {
    pub kdf_id: u16,
    pub aead_id: u16,
}

/// One ECHConfig extension (`echExtension`, ech.go:22-25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchExtension {
    pub typ: u16,
    pub data: Vec<u8>,
}

/// A parsed ECHConfig (`echConfig`, ech.go:27-41). `raw` includes the
/// 4-byte `version ‖ length` header — it is the HPKE `info` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchConfig {
    pub raw: Vec<u8>,
    pub version: u16,
    pub config_id: u8,
    pub kem_id: u16,
    pub public_key: Vec<u8>,
    pub cipher_suites: Vec<EchCipher>,
    pub max_name_length: u8,
    pub public_name: Vec<u8>,
    pub extensions: Vec<EchExtension>,
}

/// The upstream error string for a bad list (`errMalformedECHConfigList`).
fn err_malformed_list() -> Error {
    Error::protocol("tls: malformed ECHConfigList")
}

/// `echConfigErr` — `tls: malformed ECHConfig, invalid <field> field`.
fn err_config_field(field: &str) -> Error {
    Error::protocol(format!("tls: malformed ECHConfig, invalid {field} field"))
}

/// Minimal big-endian cursor with the cryptobyte reads the parser uses.
struct Cursor<'a> {
    data: &'a [u8],
}

impl Cursor<'_> {
    fn u8(&mut self) -> Option<u8> {
        let (b, rest) = self.data.split_first()?;
        self.data = rest;
        Some(*b)
    }

    fn u16(&mut self) -> Option<u16> {
        let (bytes, rest) = self.data.split_at_checked(2)?;
        self.data = rest;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// `ReadUint16LengthPrefixed` — u16 length then that many bytes.
    fn u16_bytes(&mut self) -> Option<&[u8]> {
        let len = self.u16()? as usize;
        let (bytes, rest) = self.data.split_at_checked(len)?;
        self.data = rest;
        Some(bytes)
    }

    /// `ReadUint8LengthPrefixed`.
    fn u8_bytes(&mut self) -> Option<&[u8]> {
        let len = self.u8()? as usize;
        let (bytes, rest) = self.data.split_at_checked(len)?;
        self.data = rest;
        Some(bytes)
    }
}

/// `parseECHConfig` (ech.go:56-120). `Ok(None)` = skipped (a config with
/// an unknown version, which the list parser steps over).
fn parse_ech_config(enc: &[u8]) -> Result<Option<EchConfig>> {
    let ec_raw_all = enc;
    let mut s = Cursor { data: enc };
    let version = s.u16().ok_or_else(|| err_config_field("version"))?;
    let length = s.u16().ok_or_else(|| err_config_field("length"))?;
    if ec_raw_all.len() < length as usize + 4 {
        return Err(err_config_field("length"));
    }
    let raw = ec_raw_all[..length as usize + 4].to_vec();
    if version != EXTENSION_ENCRYPTED_CLIENT_HELLO {
        return Ok(None);
    }
    let config_id = s.u8().ok_or_else(|| err_config_field("config_id"))?;
    let kem_id = s.u16().ok_or_else(|| err_config_field("kem_id"))?;
    let public_key = s
        .u16_bytes()
        .ok_or_else(|| err_config_field("public_key"))?
        .to_vec();
    let mut suites = Cursor {
        data: s
            .u16_bytes()
            .ok_or_else(|| err_config_field("cipher_suites"))?,
    };
    let mut cipher_suites = Vec::new();
    while !suites.data.is_empty() {
        let kdf_id = suites
            .u16()
            .ok_or_else(|| err_config_field("cipher_suites kdf_id"))?;
        let aead_id = suites
            .u16()
            .ok_or_else(|| err_config_field("cipher_suites aead_id"))?;
        cipher_suites.push(EchCipher { kdf_id, aead_id });
    }
    let max_name_length = s
        .u8()
        .ok_or_else(|| err_config_field("maximum_name_length"))?;
    let public_name = s
        .u8_bytes()
        .ok_or_else(|| err_config_field("public_name"))?
        .to_vec();
    let mut exts = Cursor {
        data: s
            .u16_bytes()
            .ok_or_else(|| err_config_field("extensions"))?,
    };
    let mut extensions = Vec::new();
    while !exts.data.is_empty() {
        let typ = exts
            .u16()
            .ok_or_else(|| err_config_field("extensions type"))?;
        let data = exts
            .u16_bytes()
            .ok_or_else(|| err_config_field("extensions data"))?
            .to_vec();
        extensions.push(EchExtension { typ, data });
    }
    Ok(Some(EchConfig {
        raw,
        version,
        config_id,
        kem_id,
        public_key,
        cipher_suites,
        max_name_length,
        public_name,
        extensions,
    }))
}

/// `parseECHConfigList` (ech.go:125-150): `u16 total_length` then the
/// concatenation of ECHConfig blobs, in order. Unknown-version configs
/// are skipped, everything else must parse.
pub fn parse_ech_config_list(data: &[u8]) -> Result<Vec<EchConfig>> {
    let mut s = Cursor { data };
    let length = s.u16().ok_or_else(err_malformed_list)?;
    if length as usize != data.len().saturating_sub(2) {
        return Err(err_malformed_list());
    }
    let mut configs = Vec::new();
    while !s.data.is_empty() {
        if s.data.len() < 4 {
            return Err(Error::protocol("tls: malformed ECHConfig"));
        }
        let config_len = u16::from_be_bytes([s.data[2], s.data[3]]) as usize;
        let ec = parse_ech_config(s.data)?;
        let step = config_len + 4;
        if step > s.data.len() {
            // parse_ech_config already validated raw ≥ length+4, so this
            // cannot trip for a well-formed blob; keep it defensive.
            return Err(err_malformed_list());
        }
        s.data = &s.data[step..];
        if let Some(ec) = ec {
            configs.push(ec);
        }
    }
    Ok(configs)
}

/// `validDNSName` (ech.go:455-478): ≤253 bytes, ≥2 labels, LDH + `-`
/// labels with no leading/trailing `-`. Used only for config selection.
fn valid_dns_name(name: &[u8]) -> bool {
    if name.len() > 253 {
        return false;
    }
    let labels: Vec<&[u8]> = name.split(|&b| b == b'.').collect();
    if labels.len() <= 1 {
        return false;
    }
    for label in labels {
        if label.is_empty() {
            return false;
        }
        for (i, &b) in label.iter().enumerate() {
            let c = b as char;
            if c == '-' && (i == 0 || i == label.len() - 1) {
                return false;
            }
            if !c.is_ascii_alphanumeric() && c != '-' {
                return false;
            }
        }
    }
    true
}

/// `pickECHConfig` (ech.go:152-195): the first config with a valid public
/// name, no mandatory (high-bit) extensions, a supported KEM and a
/// supported (kdf, aead) pair. Only X25519 + HKDF-SHA256 + the three
/// AEADs above are supported, mirroring what mihomo's ring-backed
/// dependency set actually implements; unsupported entries are skipped.
pub fn pick_ech_config(configs: &[EchConfig]) -> Result<(&EchConfig, HpkeAead)> {
    for ec in configs {
        if !valid_dns_name(&ec.public_name) {
            continue;
        }
        // A mandatory extension (high bit) means "skip this config".
        if ec.extensions.iter().any(|e| e.typ & (1 << 15) != 0) {
            continue;
        }
        // hpke.NewKEM(ec.KemID): only X25519 is implemented here.
        if ec.kem_id != KEM_DH_X25519_HKDF_SHA256 {
            continue;
        }
        // kem.NewPublicKey(ec.PublicKey): X25519 keys are 32 bytes.
        if ec.public_key.len() != 32 {
            continue;
        }
        for cs in &ec.cipher_suites {
            if cs.kdf_id != KDF_HKDF_SHA256 {
                continue;
            }
            if let Some(aead) = HpkeAead::from_id(cs.aead_id) {
                return Ok((ec, aead));
            }
        }
    }
    Err(Error::crypto(
        "tls: EncryptedClientHelloConfigList contains no valid configs",
    ))
}

/// The ECHConfig + HPKE suite a client seals its inner hello with — the
/// `echClientContext{config, kdfID, aeadID}` triple built by `makeClientHello`
/// (metacubex/tls handshake_client.go:175-183). Owned so a caller can hold it
/// across an ECH retry that swaps in the server's retry configs.
#[derive(Debug, Clone)]
pub struct EchConfigSelection {
    pub config: EchConfig,
    pub aead: HpkeAead,
}

/// `parseECHConfigList` + `pickECHConfig` in one step (the ECH block of
/// `makeClientHello`, handshake_client.go:175-183): parse the raw
/// ECHConfigList wire bytes and pick the first usable config. The exact
/// upstream error strings surface on failure.
pub fn select_ech_config(list: &[u8]) -> Result<EchConfigSelection> {
    let configs = parse_ech_config_list(list)?;
    let (config, aead) = pick_ech_config(&configs)?;
    Ok(EchConfigSelection {
        config: config.clone(),
        aead,
    })
}

// ---------------------------------------------------------------------------
// HPKE base mode (metacubex/hpke: hpke.go, kdf.go, kem.go, aead.go)
// ---------------------------------------------------------------------------

/// The HPKE AEADs this module supports (aead.go:29-42 + key.go:22-24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeAead {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl HpkeAead {
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            AEAD_AES_128_GCM => Some(HpkeAead::Aes128Gcm),
            AEAD_AES_256_GCM => Some(HpkeAead::Aes256Gcm),
            AEAD_CHACHA20_POLY1305 => Some(HpkeAead::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub fn id(self) -> u16 {
        match self {
            HpkeAead::Aes128Gcm => AEAD_AES_128_GCM,
            HpkeAead::Aes256Gcm => AEAD_AES_256_GCM,
            HpkeAead::ChaCha20Poly1305 => AEAD_CHACHA20_POLY1305,
        }
    }

    /// `aead.keySize()` (aead.go:66-85).
    fn key_len(self) -> usize {
        match self {
            HpkeAead::Aes128Gcm => 16,
            HpkeAead::Aes256Gcm | HpkeAead::ChaCha20Poly1305 => 32,
        }
    }

    fn ring_alg(self) -> &'static aead::Algorithm {
        match self {
            HpkeAead::Aes128Gcm => &aead::AES_128_GCM,
            HpkeAead::Aes256Gcm => &aead::AES_256_GCM,
            HpkeAead::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }
}

/// Nonce size of every supported AEAD (`nN = 96/8`, aead.go:66-85).
pub const HPKE_NONCE_LEN: usize = 12;
/// Tag size of every supported AEAD (16).
pub const HPKE_TAG_LEN: usize = 16;
/// `Nsecret` of DHKEM(X25519, HKDF-SHA256) (kem.go:136).
const KEM_SECRET_LEN: usize = 32;
/// `Nsk`/`Nsecret` of the X25519 KEM.
const X25519_KEY_LEN: usize = 32;
/// `kdf.size()` — the Nh of HKDF-SHA256 (kdf.go:66).
const KDF_HKDF_SHA256_SIZE: usize = 32;

/// `suiteID` for the HPKE context (hpke.go:255-262):
/// `"HPKE" ‖ kem_id ‖ kdf_id ‖ aead_id`.
fn hpke_suite_id(kem_id: u16, aead_id: u16) -> [u8; 10] {
    let mut sid = [0u8; 10];
    sid[..4].copy_from_slice(b"HPKE");
    sid[4..6].copy_from_slice(&kem_id.to_be_bytes());
    sid[6..8].copy_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
    sid[8..10].copy_from_slice(&aead_id.to_be_bytes());
    sid
}

/// A KeyType whose len() is the requested HKDF output length
/// (`labeledExpand` callers, kdf.go:95-103).
struct HkdfLen(u16);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0 as usize
    }
}

/// HKDF-Extract (RFC 5869 §2.2) with SHA-256:
/// `HMAC-SHA256(salt ‖ zeros-to-block, ikm)`; an empty salt is the
/// HashLen zero bytes (ring's `Salt`/`Prk` are opaque, so the extract
/// step runs through `ring::hmac` and the expand step re-imports the
/// raw PRK bytes).
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; KDF_HKDF_SHA256_SIZE] {
    let zero_salt = [0u8; KDF_HKDF_SHA256_SIZE];
    let key = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        if salt.is_empty() { &zero_salt } else { salt },
    );
    ring::hmac::sign(&key, ikm)
        .as_ref()
        .try_into()
        .expect("HMAC-SHA256 outputs 32 bytes")
}

/// `labeledExtract` (kdf.go:86-93):
/// `Extract(salt, "HPKE-v1" ‖ suite_id ‖ label ‖ ikm)`.
fn labeled_extract(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> [u8; KDF_HKDF_SHA256_SIZE] {
    let mut labeled = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    hkdf_extract(salt, &labeled)
}

/// `labeledExpand` (kdf.go:95-103):
/// `Expand(prk, I2OSP(len,2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info, len)`.
fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: u16,
) -> Result<Vec<u8>> {
    let mut labeled_info = Vec::with_capacity(2 + 7 + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&len.to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    let prk = Prk::new_less_safe(hkdf::HKDF_SHA256, prk);
    let info_slices = [&labeled_info[..]];
    let okm = prk
        .expand(&info_slices, HkdfLen(len))
        .map_err(|_| Error::crypto("ech: hpke expand length out of range"))?;
    let mut out = vec![0u8; len as usize];
    okm.fill(&mut out)
        .map_err(|_| Error::crypto("ech: hpke expand length out of range"))?;
    Ok(out)
}

/// DHKEM suite id: `"KEM" ‖ kem_id` (kem.go:117).
fn kem_suite_id(kem_id: u16) -> [u8; 5] {
    let mut sid = [0u8; 5];
    sid[..3].copy_from_slice(b"KEM");
    sid[3..5].copy_from_slice(&kem_id.to_be_bytes());
    sid
}

/// `dhKEM.extractAndExpand` (kem.go:116-123):
/// `eae_prk = LabeledExtract("", "eae_prk", dh)`;
/// `shared = LabeledExpand(eae_prk, "shared_secret", kem_context, 32)`.
fn kem_extract_and_expand(kem_id: u16, dh: &[u8], kem_context: &[u8]) -> [u8; KEM_SECRET_LEN] {
    let sid = kem_suite_id(kem_id);
    let eae_prk = labeled_extract(&sid, b"", b"eae_prk", dh);
    labeled_expand(
        &sid,
        &eae_prk,
        b"shared_secret",
        kem_context,
        KEM_SECRET_LEN as u16,
    )
    .expect("32 bytes is a valid HKDF-SHA256 output")
    .try_into()
    .expect("labeled_expand honors the requested length")
}

/// X25519 (clamped on use, as `crypto/ecdh` does; RFC 7748).
fn x25519(scalar: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32]> {
    let shared = MontgomeryPoint(*peer).mul_clamped(*scalar).0;
    if shared.iter().all(|&b| b == 0) {
        return Err(Error::crypto(
            "ech: X25519 produced an all-zero shared secret",
        ));
    }
    Ok(shared)
}

/// `dhKEMPublicKey.encap` (kem.go:234-255): fresh (or caller-fixed)
/// ephemeral X25519 key, `dh = X25519(skE, pkR)`,
/// `kem_context = enc ‖ pkR`, shared secret via extract-and-expand.
/// Returns `(shared_secret, enc)`.
pub fn hpke_encap(sk_e: &[u8; 32], pk_r: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let dh = x25519(sk_e, pk_r)?;
    let enc: [u8; 32] = MontgomeryPoint::mul_base_clamped(*sk_e).0;
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(pk_r);
    Ok((
        kem_extract_and_expand(KEM_DH_X25519_HKDF_SHA256, &dh, &kem_context),
        enc,
    ))
}

/// `dhKEMPrivateKey.decap` (kem.go:371-382) — the recipient mirror, used
/// by tests and by any future server-side ECH.
pub fn hpke_decap(sk_r: &[u8; 32], enc: &[u8; 32]) -> Result<[u8; 32]> {
    let dh = x25519(sk_r, enc)?;
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(&MontgomeryPoint::mul_base_clamped(*sk_r).0);
    Ok(kem_extract_and_expand(
        KEM_DH_X25519_HKDF_SHA256,
        &dh,
        &kem_context,
    ))
}

/// `DeriveKeyPair` for X25519 (RFC 9180 §7.1.3; kem.go:303-316):
/// `dkp_prk = LabeledExtract("", "dkp_prk", ikm)`;
/// `sk = LabeledExpand(dkp_prk, "sk", "", 32)`. The scalar is clamped at
/// use time by the DH function, per RFC 9180 §7.1.2's deserialize rule.
pub fn derive_key_pair_x25519(ikm: &[u8]) -> [u8; 32] {
    let sid = kem_suite_id(KEM_DH_X25519_HKDF_SHA256);
    let dkp_prk = labeled_extract(&sid, b"", b"dkp_prk", ikm);
    labeled_expand(&sid, &dkp_prk, b"sk", b"", X25519_KEY_LEN as u16)
        .expect("32 bytes is a valid HKDF-SHA256 output")
        .try_into()
        .expect("labeled_expand honors the requested length")
}

/// The derived key material of `newContext` (hpke.go:83-123).
#[derive(Debug, Clone)]
pub struct HpkeKeys {
    pub key: Vec<u8>,
    pub base_nonce: [u8; HPKE_NONCE_LEN],
    pub exporter_secret: Vec<u8>,
}

/// `newContext`'s two-stage KDF path (hpke.go:83-123, `oneStage() ==
/// false` for HKDF): `psk_id_hash`/`info_hash` both empty-psk, then
/// `secret`, `key`, `base_nonce` and `exp` labeled derives.
pub fn hpke_key_schedule(shared_secret: &[u8], aead: HpkeAead, info: &[u8]) -> Result<HpkeKeys> {
    let sid = hpke_suite_id(KEM_DH_X25519_HKDF_SHA256, aead.id());
    let psk_id_hash = labeled_extract(&sid, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&sid, b"", b"info_hash", info);
    let mut ks_context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    ks_context.push(0); // mode_base (hpke.go:91)
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);

    // RFC 9180 §5.1 / hpke.go:94: secret = LabeledExtract(shared_secret,
    // "secret", psk) — the shared secret is the SALT and the (empty,
    // base-mode) psk is the ikm.
    let secret = labeled_extract(&sid, shared_secret, b"secret", b"");
    let key = labeled_expand(&sid, &secret, b"key", &ks_context, aead.key_len() as u16)?;
    let base_nonce = labeled_expand(
        &sid,
        &secret,
        b"base_nonce",
        &ks_context,
        HPKE_NONCE_LEN as u16,
    )?;
    let exporter_secret = labeled_expand(
        &sid,
        &secret,
        b"exp",
        &ks_context,
        KDF_HKDF_SHA256_SIZE as u16,
    )?;
    Ok(HpkeKeys {
        key,
        base_nonce: base_nonce.try_into().expect("12 bytes requested"),
        exporter_secret,
    })
}

/// A sending HPKE context (`hpke.Sender`, hpke.go:32-34): stateful nonce
/// counter, incremented per `Seal`.
pub struct HpkeSender {
    key: LessSafeKey,
    pub base_nonce: [u8; HPKE_NONCE_LEN],
    seq: u64,
    exporter_secret: Vec<u8>,
    suite_id: [u8; 10],
}

impl HpkeSender {
    /// `NewSender` (hpke.go:135-145) with an explicit ephemeral secret
    /// (`hpke_encap` performs the encapsulation). The upstream signature
    /// draws `skE` from the system RNG; [`HpkeSender::setup`] does that.
    pub fn setup_with(
        pk_r: &[u8; 32],
        aead: HpkeAead,
        info: &[u8],
        sk_e: &[u8; 32],
    ) -> Result<([u8; 32], HpkeSender)> {
        let (shared_secret, enc) = hpke_encap(sk_e, pk_r)?;
        let sender = HpkeSender::from_shared_secret(&shared_secret, aead, info)?;
        Ok((enc, sender))
    }

    /// `NewSender` with a random ephemeral X25519 key (hpke.go:135-145,
    /// `pk.encap()` drawing from `rand.Reader`).
    pub fn setup(pk_r: &[u8; 32], aead: HpkeAead, info: &[u8]) -> Result<([u8; 32], HpkeSender)> {
        let mut sk_e = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut sk_e);
        Self::setup_with(pk_r, aead, info, &sk_e)
    }

    /// Context construction from a known shared secret (`newContext`).
    pub fn from_shared_secret(
        shared_secret: &[u8],
        aead: HpkeAead,
        info: &[u8],
    ) -> Result<HpkeSender> {
        let keys = hpke_key_schedule(shared_secret, aead, info)?;
        let unbound = UnboundKey::new(aead.ring_alg(), &keys.key)
            .map_err(|_| Error::crypto("ech: hpke aead key rejected"))?;
        Ok(HpkeSender {
            key: LessSafeKey::new(unbound),
            base_nonce: keys.base_nonce,
            seq: 0,
            exporter_secret: keys.exporter_secret,
            suite_id: hpke_suite_id(KEM_DH_X25519_HKDF_SHA256, aead.id()),
        })
    }

    /// `Sender.Seal` (hpke.go:171-178): nonce = base_nonce ⊕ seq,
    /// counter increments per call.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(self.nonce(), Aad::from(aad), &mut buf)
            .map_err(|_| Error::crypto("ech: hpke seal failed"))?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::crypto("ech: hpke sequence overflow"))?;
        Ok(buf)
    }

    /// `Recipient.Open` (hpke.go:209-219) — the mirror direction of the
    /// same context (Go's `Sender`/`Recipient` share one `context`
    /// struct): opens, then increments the counter. A context built from
    /// the decapsulated secret acts as the recipient.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = ciphertext.to_vec();
        self.key
            .open_in_place(self.nonce(), Aad::from(aad), &mut buf)
            .map_err(|_| Error::crypto("ech: hpke open failed"))?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::crypto("ech: hpke sequence overflow"))?;
        let len = buf.len() - HPKE_TAG_LEN;
        buf.truncate(len);
        Ok(buf)
    }

    /// `Sender.Export` (hpke.go:197-202):
    /// `LabeledExpand(exp_secret, "sec", exporter_context, len)`.
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>> {
        if len > 0xffff {
            return Err(Error::crypto("ech: invalid export length"));
        }
        labeled_expand(
            &self.suite_id,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            len as u16,
        )
    }

    /// `context.nextNonce` (hpke.go:246-253): `base_nonce ⊕ seq_be64` in
    /// the last 8 bytes, big-endian.
    pub fn nonce(&self) -> Nonce {
        let mut nonce = [0u8; HPKE_NONCE_LEN];
        nonce[HPKE_NONCE_LEN - 8..].copy_from_slice(&self.seq.to_be_bytes());
        for (n, b) in nonce.iter_mut().zip(self.base_nonce.iter()) {
            *n ^= b;
        }
        Nonce::assume_unique_for_key(nonce)
    }

    /// Force the sequence counter (the RFC 9180 vectors exercise
    /// non-contiguous sequences; also usable for transcript replay).
    pub fn set_sequence(&mut self, seq: u64) {
        self.seq = seq;
    }
}

// ---------------------------------------------------------------------------
// Outer/inner ECH extension payloads (metacubex/tls ech.go)
// ---------------------------------------------------------------------------

/// `echExtType` (ech.go:497-502): outer = 0, inner = 1.
const OUTER_ECH_EXT: u8 = 0;
const INNER_ECH_EXT: u8 = 1;

/// The parsed `encrypted_client_hello` extension body (`parseECHExt`,
/// ech.go:504-549).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchExt {
    /// Inner hello marker: the single byte `0x01`.
    Inner,
    /// Outer hello: `0x00 ‖ kdf_id ‖ aead_id ‖ config_id ‖ enc ‖ payload`.
    Outer {
        kdf_id: u16,
        aead_id: u16,
        config_id: u8,
        enc: Vec<u8>,
        payload: Vec<u8>,
    },
}

/// `generateOuterECHExt` (ech.go:407-416):
/// `type=0 ‖ kdf_id u16 ‖ aead_id u16 ‖ config_id u8 ‖ enc(u16-prefixed)
/// ‖ payload(u16-prefixed)` — the RFC 9460 outer extension body (not the
/// older draft-13 `HpkeSymmetricCipherSuites` list form).
pub fn generate_outer_ech_ext(
    config_id: u8,
    kdf_id: u16,
    aead_id: u16,
    enc: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if enc.len() > u16::MAX as usize || payload.len() > u16::MAX as usize {
        return Err(Error::protocol(
            "tls: ech outer extension field exceeds u16 length",
        ));
    }
    let mut out = Vec::with_capacity(9 + enc.len() + payload.len());
    out.push(OUTER_ECH_EXT);
    out.extend_from_slice(&kdf_id.to_be_bytes());
    out.extend_from_slice(&aead_id.to_be_bytes());
    out.push(config_id);
    out.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    out.extend_from_slice(enc);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// `parseECHExt` (ech.go:504-549).
pub fn parse_ech_ext(ext: &[u8]) -> Result<EchExt> {
    let mut s = Cursor { data: ext };
    let ech_type = s
        .u8()
        .ok_or_else(|| Error::protocol("tls: malformed encrypted_client_hello extension"))?;
    if ech_type == INNER_ECH_EXT {
        if !s.data.is_empty() {
            return Err(Error::protocol(
                "tls: malformed encrypted_client_hello extension",
            ));
        }
        return Ok(EchExt::Inner);
    }
    if ech_type != OUTER_ECH_EXT {
        return Err(Error::protocol(
            "tls: client sent invalid encrypted_client_hello extension",
        ));
    }
    let kdf_id = s
        .u16()
        .ok_or_else(|| Error::protocol("tls: malformed encrypted_client_hello extension"))?;
    let aead_id = s
        .u16()
        .ok_or_else(|| Error::protocol("tls: malformed encrypted_client_hello extension"))?;
    let config_id = s
        .u8()
        .ok_or_else(|| Error::protocol("tls: malformed encrypted_client_hello extension"))?;
    let enc = s
        .u16_bytes()
        .ok_or_else(|| Error::protocol("tls: malformed encrypted_client_hello extension"))?
        .to_vec();
    let payload = s
        .u16_bytes()
        .ok_or_else(|| Error::protocol("tls: malformed encrypted_client_hello extension"))?
        .to_vec();
    Ok(EchExt::Outer {
        kdf_id,
        aead_id,
        config_id,
        enc,
        payload,
    })
}

/// The HPKE `info` for ECH: `"tls ech\x00" ‖ ECHConfig.raw`
/// (`handshake_client.go:193`).
pub fn ech_hpke_info(config: &EchConfig) -> Vec<u8> {
    let mut info = Vec::with_capacity(8 + config.raw.len());
    info.extend_from_slice(b"tls ech\x00");
    info.extend_from_slice(&config.raw);
    info
}

/// `encodeInnerClientHello` (ech.go:197-216): the marshaled inner
/// ClientHello body (4-byte handshake header stripped) plus zero padding
/// so the total is a multiple of 32. The pre-padding target depends on
/// the inner SNI: `maxNameLength - len(serverName)` when an SNI is
/// present, `maxNameLength + 9` otherwise.
pub fn encode_inner_client_hello(
    inner_hello_body: &[u8],
    server_name: Option<&[u8]>,
    max_name_length: usize,
) -> Vec<u8> {
    let mut padding_len = match server_name {
        Some(name) if !name.is_empty() => max_name_length.saturating_sub(name.len()),
        _ => max_name_length + 9,
    };
    padding_len = 31 - ((inner_hello_body.len() + padding_len).saturating_sub(1) % 32);
    let mut out = Vec::with_capacity(inner_hello_body.len() + padding_len);
    out.extend_from_slice(inner_hello_body);
    out.resize(out.len() + padding_len, 0);
    out
}

/// `computeAndUpdateOuterECHExtension` (ech.go:418-449) as a standalone:
/// builds the placeholder outer extension (all-zero payload of
/// `encoded_inner.len() + 16`, the note at ech.go:428-430 hardcoding the
/// AEAD tag length), lets the caller serialize the outer hello around
/// it, seals the encoded inner hello with that serialization (minus the
/// 4-byte handshake header) as AAD, and returns the final extension
/// body. `include_enc == false` mirrors the `useKey == false` HRR flight
/// where `enc` is omitted.
#[allow(clippy::too_many_arguments)]
pub fn compute_outer_ech_ext(
    sender: &mut HpkeSender,
    config_id: u8,
    kdf_id: u16,
    aead_id: u16,
    enc: &[u8],
    encoded_inner: &[u8],
    include_enc: bool,
    serialize_outer: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Result<Vec<u8>> {
    let enc_bytes: &[u8] = if include_enc { enc } else { &[] };
    let placeholder_payload = vec![0u8; encoded_inner.len() + HPKE_TAG_LEN];
    let placeholder_ext =
        generate_outer_ech_ext(config_id, kdf_id, aead_id, enc_bytes, &placeholder_payload)?;
    let aad = serialize_outer(&placeholder_ext);
    let ciphertext = sender.seal(&aad, encoded_inner)?;
    generate_outer_ech_ext(config_id, kdf_id, aead_id, enc_bytes, &ciphertext)
}

/// `extractRawExtensions` (ech.go:235-263): the `(type, body)` entries of a
/// ClientHello's extension block, parsed off the raw hello message.
fn extract_raw_extensions(hello: &[u8]) -> Result<Vec<(u16, Vec<u8>)>> {
    let bad = || Error::protocol("tls: malformed outer client hello");
    let mut s = Cursor { data: hello };
    if s.data.len() < 4 + 2 + 32 {
        return Err(bad());
    }
    s.data = s.data.get(4 + 2 + 32..).ok_or_else(bad)?;
    let _session_id = s.u8_bytes().ok_or_else(bad)?;
    let _cipher_suites = s.u16_bytes().ok_or_else(bad)?;
    let _compression = s.u8_bytes().ok_or_else(bad)?;
    let block = s.u16_bytes().ok_or_else(bad)?;
    let mut out = Vec::new();
    let mut c = Cursor { data: block };
    while !c.data.is_empty() {
        let typ = c.u16().ok_or_else(bad)?;
        let body = c.u16_bytes().ok_or_else(bad)?.to_vec();
        out.push((typ, body));
    }
    Ok(out)
}

/// `decodeInnerClientHello` (ech.go:264-345) — the server-side reconstruction
/// of the *transcript form* of the inner ClientHello from its decrypted
/// encoded form. The encoded form is missing its 4-byte handshake header and
/// legacy_session_id (always empty on the wire, handshake_messages.go:353-357)
/// and may compress outer-mirrored extensions into `ech_outer_extensions`;
/// the reconstruction restores the OUTER hello's session id and expands the
/// compressed references from the outer's extension block, in the exact
/// upstream wire order. Returns the complete handshake message the server
/// must hash into its transcript.
///
/// Also ports the upstream validity checks: trailing padding must be zero,
/// the `0xfe0d` marker must be the inner form, and the inner
/// supported_versions must offer TLS 1.3 with nothing (non-GREASE) below it.
pub fn decode_inner_client_hello(outer_msg: &[u8], encoded: &[u8]) -> Result<Vec<u8>> {
    let invalid = || Error::protocol("tls: invalid inner client hello");
    let mut s = Cursor { data: encoded };
    let version_and_random = s.data.get(..2 + 32).ok_or_else(invalid)?.to_vec();
    s.data = &s.data[2 + 32..];
    let sid = s.u8_bytes().ok_or_else(invalid)?;
    if !sid.is_empty() {
        return Err(invalid());
    }
    let cipher_suites = s.u16_bytes().ok_or_else(invalid)?.to_vec();
    let compression = s.u8_bytes().ok_or_else(invalid)?.to_vec();
    let exts = s.u16_bytes().ok_or_else(invalid)?.to_vec();
    // The padding after the encoded hello must be all zeros (ech.go:284-289).
    if !s.data.iter().all(|&b| b == 0) {
        return Err(invalid());
    }

    let raw_outer_exts = extract_raw_extensions(outer_msg)?;
    // The outer hello's legacy_session_id (restored into the inner form).
    let outer_sid = outer_msg
        .get(4 + 2 + 32 + 1..4 + 2 + 32 + 1 + 32)
        .ok_or_else(|| Error::protocol("tls: malformed outer client hello"))?;

    // Expand `ech_outer_extensions` references in place (ech.go:324-358):
    // each referenced type is looked up in the outer's list with a
    // forward-moving cursor, exactly like the upstream loop.
    let mut expanded: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut c = Cursor { data: &exts };
    while !c.data.is_empty() {
        let typ = c.u16().ok_or_else(invalid)?;
        let body = c.u16_bytes().ok_or_else(invalid)?.to_vec();
        if typ != EXTENSION_ECH_OUTER_EXTENSIONS {
            expanded.push((typ, body));
            continue;
        }
        let mut refs = Cursor { data: &body };
        let refs = refs.u8_bytes().ok_or_else(invalid)?;
        let mut search_from = 0usize;
        let mut r = Cursor { data: refs };
        while !r.data.is_empty() {
            let want = r.u16().ok_or_else(invalid)?;
            if want == EXTENSION_ENCRYPTED_CLIENT_HELLO {
                return Err(Error::protocol("tls: invalid outer extensions"));
            }
            let found = raw_outer_exts[search_from..]
                .iter()
                .position(|(t, _)| *t == want)
                .map(|i| i + search_from)
                .ok_or_else(|| Error::protocol("tls: invalid outer extensions"))?;
            search_from = found + 1;
            expanded.push((want, raw_outer_exts[found].1.clone()));
        }
    }
    // The reconstructed inner must carry the `0x01` inner marker
    // (ech.go:370-372).
    let marker_ok = expanded
        .iter()
        .any(|(t, b)| *t == EXTENSION_ENCRYPTED_CLIENT_HELLO && b.as_slice() == [INNER_ECH_EXT]);
    if !marker_ok {
        return Err(Error::protocol(
            "tls: client sent invalid encrypted_client_hello extension",
        ));
    }

    // supported_versions: skip GREASE (0x?A0A with equal octets), require
    // 0x0304, and refuse anything non-GREASE below it (ech.go:374-394).
    const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
    let mut has_tls13 = false;
    if let Some((_, body)) = expanded.iter().find(|(t, _)| *t == EXT_SUPPORTED_VERSIONS) {
        let mut v = Cursor { data: body };
        let list = v.u8_bytes().ok_or_else(invalid)?;
        let mut l = Cursor { data: list };
        while !l.data.is_empty() {
            let ver = l.u16().ok_or_else(invalid)?;
            if ver & 0x0f0f == 0x0a0a && ver & 0xff == ver >> 8 {
                continue;
            }
            if ver == 0x0304 {
                has_tls13 = true;
            } else if ver < 0x0304 {
                return Err(Error::protocol(
                    "tls: client sent encrypted_client_hello extension with unsupported versions",
                ));
            }
        }
    }
    if !has_tls13 {
        return Err(Error::protocol(
            "tls: client sent encrypted_client_hello extension but did not offer TLS 1.3",
        ));
    }

    // Rebuild the message (ech.go:296-345 recon builder).
    let mut ext_bytes = Vec::new();
    for (typ, body) in &expanded {
        ext_bytes.extend_from_slice(&typ.to_be_bytes());
        ext_bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext_bytes.extend_from_slice(body);
    }
    let mut body = Vec::with_capacity(
        version_and_random.len()
            + 1
            + outer_sid.len()
            + 2
            + cipher_suites.len()
            + 1
            + compression.len()
            + 2
            + ext_bytes.len(),
    );
    body.extend_from_slice(&version_and_random);
    body.push(outer_sid.len() as u8);
    body.extend_from_slice(outer_sid);
    body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_suites);
    body.push(compression.len() as u8);
    body.extend_from_slice(&compression);
    body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_bytes);
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(1); // handshake type: client_hello
    let len = body.len();
    msg.push((len >> 16) as u8);
    msg.push((len >> 8) as u8);
    msg.push(len as u8);
    msg.extend_from_slice(&body);
    Ok(msg)
}

// ---------------------------------------------------------------------------
// ECH accept confirmation (metacubex/tls handshake_client_tls13.go)
// ---------------------------------------------------------------------------

/// `tls13ExpandLabel` (metacubex/tls tls13.go:21-45, RFC 8446 §7.1):
/// HKDF-Expand with
/// `I2OSP(len,2) ‖ u8(len("tls13 ")+len(label)) ‖ "tls13 " ‖ label ‖
/// I2OSP(ctx_len,1) ‖ context`.
fn tls13_expand_label(prk: &[u8], label: &[u8], context: &[u8], len: u8) -> Result<Vec<u8>> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    info.extend_from_slice(&[0, len]);
    // The label is u8-length-prefixed, counted over "tls13 " + label.
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let prk = Prk::new_less_safe(hkdf::HKDF_SHA256, prk);
    let info_slices = [&info[..]];
    let okm = prk
        .expand(&info_slices, HkdfLen(len as u16))
        .map_err(|_| Error::crypto("ech: expand label failed"))?;
    let mut out = vec![0u8; len as usize];
    okm.fill(&mut out)
        .map_err(|_| Error::crypto("ech: expand label failed"))?;
    Ok(out)
}

/// The ECH accept confirmation for a normal ServerHello
/// (`handshake_client_tls13.go:86-98`): the transcript keeps running
/// over `server_hello_msg[..30] ‖ 8 zero bytes ‖ server_hello_msg[38..]`
/// (bytes 30..38 are the confirmation slot inside the 32-byte random),
/// the PRK is `Extract(inner_hello.random)` and the label is
/// `"ech accept confirmation"`. Compare against the final 8 bytes of the
/// ServerHello random in constant time.
pub fn server_hello_accept_confirmation(
    inner_transcript: &digest::Context,
    server_hello_msg: &[u8],
    inner_client_random: &[u8; 32],
) -> Result<[u8; 8]> {
    if server_hello_msg.len() < 38 {
        return Err(Error::protocol(
            "tls: malformed encrypted_client_hello extension",
        ));
    }
    let mut conf = inner_transcript.clone();
    conf.update(&server_hello_msg[..30]);
    conf.update(&[0u8; 8]);
    conf.update(&server_hello_msg[38..]);
    let transcript_digest = conf.finish();
    let prk = hkdf_extract(b"", inner_client_random);
    let out = tls13_expand_label(
        &prk,
        b"ech accept confirmation",
        transcript_digest.as_ref(),
        8,
    )?;
    out.try_into()
        .map_err(|_| Error::crypto("ech: confirmation length"))
}

/// The HRR variant (`handshake_client_tls13.go:261-272`): the whole HRR
/// message with its 8-byte ECH extension value replaced by zeros is
/// appended to the inner transcript (already folded to a `message_hash`
/// by the caller), the label is `"hrr ech accept confirmation"`.
pub fn hrr_accept_confirmation(
    inner_transcript: &digest::Context,
    hrr_msg: &[u8],
    ech_ext_value: &[u8],
    inner_client_random: &[u8; 32],
) -> Result<[u8; 8]> {
    if ech_ext_value.len() != 8 {
        return Err(Error::protocol(
            "tls: malformed encrypted_client_hello extension",
        ));
    }
    // bytes.Replace(hello, ech, zeros, 1): first occurrence only.
    let mut hrr = hrr_msg.to_vec();
    let pos = hrr
        .windows(8)
        .position(|w| w == ech_ext_value)
        .ok_or_else(|| Error::protocol("tls: hrr without the ECH extension value"))?;
    hrr[pos..pos + 8].fill(0);
    let mut conf = inner_transcript.clone();
    conf.update(&hrr);
    let transcript_digest = conf.finish();
    let prk = hkdf_extract(b"", inner_client_random);
    let out = tls13_expand_label(
        &prk,
        b"hrr ech accept confirmation",
        transcript_digest.as_ref(),
        8,
    )?;
    out.try_into()
        .map_err(|_| Error::crypto("ech: confirmation length"))
}

/// Constant-time equality of two 8-byte confirmation values
/// (`subtle.ConstantTimeCompare`, handshake_client_tls13.go:98).
pub fn confirmation_matches(a: &[u8; 8], b: &[u8; 8]) -> bool {
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

// ---------------------------------------------------------------------------
// mihomo ECHOptions (adapter/outbound/ech.go:12-41, component/ech/ech.go)
// ---------------------------------------------------------------------------

/// mihomo `ECHOptions` (adapter/outbound/ech.go:12-17): YAML fields
/// `ech.enable`, `ech.config`, `ech.query-server-name`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EchOptions {
    pub enable: bool,
    /// `config`: base64 (std) ECHConfigList wire bytes.
    pub config: String,
    /// `query-server-name`: overrides the domain used for ECH HTTPS RR
    /// queries when no static config is set.
    pub query_server_name: String,
}

/// Where an ECHConfigList comes from (`ECHOptions.Parse`,
/// adapter/outbound/ech.go:19-41).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchConfigSource {
    /// The decoded `config` string, returned unvalidated exactly like
    /// upstream (the TLS layer's `parse_ech_config_list` is the validator).
    Static(Vec<u8>),
    /// No static config: query the DNS HTTPS RR of the TLS server name
    /// (overridden by `query-server-name`) and take the first
    /// `SVCBECHConfig` param value — mihomo `dns/resolver.go:129-149`
    /// (`ResolveECH`: qtype HTTPS(65), answer scan) and
    /// `dns/util.go:340-380` (`msgToHTTPSRRInfo` validating the param
    /// through the same `parse_ech_config_list`). The engine's DNS layer
    /// has no type-65/SVCB query yet — **integrator hook**: resolve this
    /// variant with `dns::upstream::Upstream::exchange` on a hand-built
    /// HTTPS query and extract SvcParamKey 5 (`ech`), then hand the
    /// bytes to [`parse_ech_config_list`].
    DnsHttpsQuery { server_name: Option<String> },
}

impl EchOptions {
    /// `ECHOptions.Parse` (adapter/outbound/ech.go:19-41): `Ok(None)`
    /// when disabled; a static list from `config`; otherwise the DNS
    /// HTTPS RR query descriptor.
    pub fn parse(&self) -> Result<Option<EchConfigSource>> {
        if !self.enable {
            return Ok(None);
        }
        if !self.config.is_empty() {
            use base64::Engine as _;
            let list = base64::engine::general_purpose::STANDARD
                .decode(self.config.as_bytes())
                .map_err(|e| {
                    Error::config(format!("base64 decode ech config string failed: {e}"))
                })?;
            return Ok(Some(EchConfigSource::Static(list)));
        }
        Ok(Some(EchConfigSource::DnsHttpsQuery {
            server_name: (!self.query_server_name.is_empty())
                .then(|| self.query_server_name.clone()),
        }))
    }
}

/// `buildRetryConfigList` (ech.go:637-653) — the server-side retry list:
/// `u16 length ‖ concat(configs marked SendAsRetry)`.
pub fn build_retry_config_list(configs: &[&[u8]]) -> Option<Vec<u8>> {
    if configs.is_empty() {
        return None;
    }
    let total: usize = configs.iter().map(|c| c.len()).sum();
    if total > u16::MAX as usize {
        return None;
    }
    let mut out = Vec::with_capacity(2 + total);
    out.extend_from_slice(&(total as u16).to_be_bytes());
    for c in configs {
        out.extend_from_slice(c);
    }
    Some(out)
}

/// A lazily-built SHA-256 transcript helper for callers that do not keep
/// a running hash: folds `messages` into a fresh context.
pub fn transcript_context(messages: &[&[u8]]) -> digest::Context {
    let mut ctx = digest::Context::new(&digest::SHA256);
    for m in messages {
        ctx.update(m);
    }
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ------------------------------------------------------ config lists

    /// The two lists from metacubex/tls `ech_test.go:17-18`
    /// (`TestDecodeECHConfigLists`).
    #[test]
    fn config_lists_parse_upstream_vectors() {
        let list = unhex(
            "0045fe0d0041590020002092a01233db2218518ccbbbbc24df20686af417b37388de6460e94011974777090004000100010012636c6f7564666c6172652d6563682e636f6d0000",
        );
        let configs = parse_ech_config_list(&list).unwrap();
        assert_eq!(configs.len(), 1);
        let c = &configs[0];
        assert_eq!(c.version, 0xfe0d);
        assert_eq!(c.kem_id, KEM_DH_X25519_HKDF_SHA256);
        // Field order per parseECHConfig (ech.go:78-99): after the
        // `0004 0001 0001` cipher suites come MaxNameLength = 0x00 and the
        // u8-length-prefixed public_name (length 0x12,
        // "cloudflare-ech.com"); the upstream test only pins the config
        // COUNT, so these field values are read straight off the wire.
        assert_eq!(c.max_name_length, 0x00);
        assert_eq!(c.public_name, b"cloudflare-ech.com".to_vec());
        assert_eq!(
            c.cipher_suites,
            vec![EchCipher {
                kdf_id: 1,
                aead_id: 1
            }]
        );
        assert_eq!(c.raw.len(), 4 + 0x41);
        // raw covers exactly version+length+body.
        assert_eq!(hex(&c.raw), hex(&list[2..]));

        // Three configs, one of them an unknown version (skipped).
        let list = unhex(
            "0105badd00050504030201fe0d0066000010004104e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1000c000100010001000200010003400e7075626c69632e6578616d706c650000fe0d003d00002000207d661615730214aeee70533366f36a609ead65c0c208e62322346ab5bcd8de1c000411112222400e7075626c69632e6578616d706c650000fe0d004d000020002085bd6a03277c25427b52e269e0c77a8eb524ba1eb3d2f132662d4b0ac6cb7357000c000100010001000200010003400e7075626c69632e6578616d706c650008aaaa000474657374",
        );
        let configs = parse_ech_config_list(&list).unwrap();
        assert_eq!(configs.len(), 3);
        // First: P-256 KEM (0x0010) — parses fine, unsupported by pick.
        assert_eq!(configs[0].kem_id, 0x0010);
        assert_eq!(configs[0].public_key.len(), 65);
        // Second: X25519, no cipher suites accepted by pick? kdf 1/aead 1/2/3.
        assert_eq!(configs[1].kem_id, KEM_DH_X25519_HKDF_SHA256);
        assert_eq!(configs[2].extensions.len(), 1);
        assert_eq!(configs[2].extensions[0].typ, 0xaaaa);
    }

    /// `TestSkipBadConfigs` (ech_test.go:36-48): the unknown-version
    /// `badd` config plus configs with bad public keys / KDFs — pick
    /// must find nothing usable.
    #[test]
    fn skip_bad_configs_pick_finds_nothing() {
        let list = unhex(
            "00c8badd00050504030201fe0d0029006666000401020304000c000100010001000200010003400e7075626c69632e6578616d706c650000fe0d003d000020002072e8a23b7aef67832bcc89d652e3870a60f88ca684ec65d6eace6b61f136064c000411112222400e7075626c69632e6578616d706c650000fe0d004d00002000200ce95810a81d8023f41e83679bc92701b2acd46c75869f95c72bc61c6b12297c000c000100010001000200010003400e7075626c69632e6578616d706c650008aaaa000474657374",
        );
        let configs = parse_ech_config_list(&list).unwrap();
        // 0x6666 KEM, a 4-byte public key with KEM 0x0020, and a
        // mandatory 0xaaaa extension: nothing is pickable.
        assert!(pick_ech_config(&configs).is_err());
    }

    #[test]
    fn pick_ech_config_prefers_first_valid() {
        // Configs 1-3 of the second upstream vector: a P-256 KEM (skipped
        // by pick — only X25519 is implemented), an X25519 whose single
        // suite is the bogus (0x1111, 0x2222) pair, and an X25519 with
        // all three supported suites.
        let p256 = unhex(
            "fe0d0066000010004104e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1000c000100010001000200010003400e7075626c69632e6578616d706c650000",
        );
        let x25519_one = unhex(
            "fe0d003d00002000207d661615730214aeee70533366f36a609ead65c0c208e62322346ab5bcd8de1c000411112222400e7075626c69632e6578616d706c650000",
        );
        // As transcribed, the third config carries extension type 0xaaaa —
        // the high bit marks it MANDATORY and upstream pickECHConfig skips
        // the whole config (ech.go:162-169), exactly like TestSkipBadConfigs
        // expects. Clearing the high bit (0x2aaa) makes the same config
        // pickable, isolating the "first valid suite" behavior.
        let x25519_all_mandatory = unhex(
            "fe0d004d000020002085bd6a03277c25427b52e269e0c77a8eb524ba1eb3d2f132662d4b0ac6cb7357000c000100010001000200010003400e7075626c69632e6578616d706c650008aaaa000474657374",
        );
        let x25519_all = unhex(
            "fe0d004d000020002085bd6a03277c25427b52e269e0c77a8eb524ba1eb3d2f132662d4b0ac6cb7357000c000100010001000200010003400e7075626c69632e6578616d706c6500082aaa000474657374",
        );
        let build = |parts: &[Vec<u8>]| -> Vec<u8> {
            let total: usize = parts.iter().map(|p| p.len()).sum();
            let mut list = (total as u16).to_be_bytes().to_vec();
            for p in parts {
                list.extend_from_slice(p);
            }
            list
        };
        // [P-256, all-suites-with-mandatory-ext]: the first config is
        // skipped (only X25519 implemented), the second for its mandatory
        // 0xaaaa extension — nothing is pickable.
        let configs =
            parse_ech_config_list(&build(&[p256.clone(), x25519_all_mandatory.clone()])).unwrap();
        assert!(pick_ech_config(&configs).is_err());
        // [P-256, pickable-all-suites]: the second config is picked with
        // its FIRST suite (pick takes the first valid pair).
        let configs = parse_ech_config_list(&build(&[p256, x25519_all])).unwrap();
        let (picked, aead) = pick_ech_config(&configs).unwrap();
        assert_eq!(picked.public_key.len(), 32);
        assert_eq!(aead, HpkeAead::Aes128Gcm);
        // The x25519_one config carries a single (0x1111, 0x2222) suite —
        // parseable but unsupported, so nothing is pickable behind a
        // mandatory-ext config either.
        let configs = parse_ech_config_list(&build(&[x25519_all_mandatory, x25519_one])).unwrap();
        assert!(pick_ech_config(&configs).is_err());
    }

    #[test]
    fn malformed_lists_rejected() {
        // Bad outer length.
        assert!(parse_ech_config_list(&[0x00, 0x45, 0x00]).is_err());
        let good = unhex(
            "0045fe0d0041590020002092a01233db2218518ccbbbbc24df20686af417b37388de6460e94011974777090004000100010012636c6f7564666c6172652d6563682e636f6d0000",
        );
        // Length not matching the payload.
        let mut bad = good.clone();
        bad[0] = 0x00;
        bad[1] = 0x44;
        assert!(parse_ech_config_list(&bad).is_err());
        // Truncations at every cut either error or never claim a config
        // beyond the data (upstream: short blob → field error).
        for cut in 0..good.len() {
            let r = parse_ech_config_list(&good[..cut]);
            if let Ok(cs) = r {
                assert!(cs.is_empty() || cut >= good.len() - 1, "cut {cut}");
            }
        }
        // A trailing fragment shorter than 4 bytes.
        let mut short = good.clone();
        short.extend_from_slice(&[0xfe, 0x0d]);
        assert!(parse_ech_config_list(&short).is_err());
    }

    // ------------------------------------------------------ HPKE vectors

    /// RFC 9180 appendix A.1 (`A.1.1 Base Setup` +
    /// `A.1.1.1 Encryptions` + `A.1.1.2 Exported Values`): base mode
    /// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM.
    #[test]
    fn rfc9180_a1_x25519_aes128_base() {
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        let ikm_e = unhex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
        let pk_rm: [u8; 32] =
            unhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
                .try_into()
                .unwrap();
        let sk_em_want = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";
        let enc_want = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
        let shared_want = "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc";
        let key_want = "4531685d41d65f03dc48f6b8302c05b0";
        let nonce_want = "56d890e5accaaf011cff4b7d";
        let exp_want = "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8";

        // DeriveKeyPair(ikmE) — the derandomized encap of the vectors.
        let sk_e = derive_key_pair_x25519(&ikm_e);
        assert_eq!(hex(&sk_e), sk_em_want);

        let (shared, enc) = hpke_encap(&sk_e, &pk_rm).unwrap();
        assert_eq!(hex(&enc), enc_want);
        assert_eq!(hex(&shared), shared_want);

        let keys = hpke_key_schedule(&shared, HpkeAead::Aes128Gcm, &info).unwrap();
        assert_eq!(hex(&keys.key), key_want);
        assert_eq!(hex(&keys.base_nonce), nonce_want);
        assert_eq!(hex(&keys.exporter_secret), exp_want);

        let (_, mut sender) =
            HpkeSender::setup_with(&pk_rm, HpkeAead::Aes128Gcm, &info, &sk_e).unwrap();
        let pt = unhex("4265617574792069732074727574682c20747275746820626561757479");
        // Sequence 0/1/2 with matching AADs.
        for (seq, aad, ct) in [
            (
                0u64,
                "436f756e742d30",
                "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
            ),
            (
                1,
                "436f756e742d31",
                "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
            ),
            (
                2,
                "436f756e742d32",
                "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
            ),
            (
                4,
                "436f756e742d34",
                "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d",
            ),
            (
                255,
                "436f756e742d323535",
                "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a",
            ),
            (
                256,
                "436f756e742d323536",
                "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2",
            ),
        ] {
            sender.set_sequence(seq);
            let ct_got = sender.seal(&unhex(aad), &pt).unwrap();
            assert_eq!(hex(&ct_got), ct, "seq {seq}");
        }

        // Exported values (A.1.1.2).
        assert_eq!(
            hex(&sender.export(b"", 32).unwrap()),
            "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee"
        );
        assert_eq!(
            hex(&sender.export(&[0u8], 32).unwrap()),
            "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5"
        );
        assert_eq!(
            hex(&sender.export(b"TestContext", 32).unwrap()),
            "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931"
        );
    }

    /// The X25519 + HKDF-SHA256 + AES-256-GCM vector from the
    /// metacubex/hpke testdata (`testdata/rfc9180.json`, kem 32 / kdf 1
    /// / aead 2): pins the KEM path for the 32-byte-key AEAD and
    /// round-trips seal/decap with the recipient side.
    #[test]
    fn rfc9180_x25519_aes256_enc_and_recipient_roundtrip() {
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        let ikm_e = unhex("2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9");
        let sk_rm: [u8; 32] =
            unhex("497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d")
                .try_into()
                .unwrap();
        let pk_rm: [u8; 32] =
            unhex("430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c")
                .try_into()
                .unwrap();
        let enc_want = "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256";

        let sk_e = derive_key_pair_x25519(&ikm_e);
        let (enc, mut sender) =
            HpkeSender::setup_with(&pk_rm, HpkeAead::Aes256Gcm, &info, &sk_e).unwrap();
        assert_eq!(hex(&enc), enc_want);

        // Recipient side (hpke_decap + the shared key schedule).
        let shared_r = hpke_decap(&sk_rm, &enc).unwrap();
        let mut recipient =
            HpkeSender::from_shared_secret(&shared_r, HpkeAead::Aes256Gcm, &info).unwrap();
        let aad = b"ech-aad";
        let ct = sender.seal(aad, b"inner hello bytes").unwrap();
        let pt = recipient
            .open(aad, &ct)
            .expect("recipient opens sender ciphertext");
        assert_eq!(pt, b"inner hello bytes".to_vec());
        // A second seal/open pair advances both counters in lockstep.
        let ct = sender.seal(aad, b"second").unwrap();
        assert_eq!(recipient.open(aad, &ct).unwrap(), b"second".to_vec());
    }

    // ------------------------------------------------------ ext payloads

    #[test]
    fn outer_ext_build_and_parse_roundtrip() {
        let enc = [7u8; 32];
        let payload = [9u8; 40];
        let ext = generate_outer_ech_ext(0x5a, KDF_HKDF_SHA256, AEAD_AES_256_GCM, &enc, &payload)
            .unwrap();
        assert_eq!(ext[0], 0); // outer marker
        assert_eq!(&ext[1..3], &KDF_HKDF_SHA256.to_be_bytes());
        assert_eq!(&ext[3..5], &AEAD_AES_256_GCM.to_be_bytes());
        assert_eq!(ext[5], 0x5a);
        assert_eq!(u16::from_be_bytes([ext[6], ext[7]]), 32);
        match parse_ech_ext(&ext).unwrap() {
            EchExt::Outer {
                kdf_id,
                aead_id,
                config_id,
                enc,
                payload,
            } => {
                assert_eq!((kdf_id, aead_id, config_id), (1, 2, 0x5a));
                assert_eq!(enc, vec![7u8; 32]);
                assert_eq!(payload, vec![9u8; 40]);
            }
            other => panic!("wrong ext {other:?}"),
        }
        // The inner marker: exactly one byte.
        assert_eq!(parse_ech_ext(&[1]).unwrap(), EchExt::Inner);
        assert!(parse_ech_ext(&[1, 0]).is_err());
        assert!(parse_ech_ext(&[2]).is_err());
        assert!(parse_ech_ext(&[]).is_err());
        assert!(parse_ech_ext(&[0, 0, 1]).is_err());
    }

    #[test]
    fn inner_hello_padding_matches_upstream_formula() {
        let body = vec![0xab; 100];
        let sni = b"example.com";
        // The upstream formula (ech.go:197-216): with an SNI,
        // p0 = max(0, max_name_length - len(sni)); without (or with an
        // empty SNI), p0 = max_name_length + 9; the appended padding is
        // 31 - ((len(h) + p0 - 1) % 32), so the padded total is
        // roundup32(len(h) + p0) - p0 — the 32-multiple hides
        // len(h) - len(sni), and the TOTAL is not itself a multiple of 32
        // unless p0 ≡ 0 (mod 32).
        for (max_name, with_sni, no_sni) in [
            (0usize, 128usize, 119usize),
            (4, 128, 115),
            (12, 127, 107),
            (32, 107, 119),
            (255, 108, 120),
        ] {
            let enc = encode_inner_client_hello(&body, Some(sni), max_name);
            assert_eq!(enc.len(), with_sni, "max {max_name}");
            assert_eq!(&enc[..100], &body[..]);
            assert!(enc[100..].iter().all(|&b| b == 0), "zero padding");
            let no = encode_inner_client_hello(&body, None, max_name);
            assert_eq!(no.len(), no_sni, "max {max_name}");
            // An empty SNI counts as "no server name" (paddingLen = max+9).
            let empty = encode_inner_client_hello(&body, Some(b""), max_name);
            assert_eq!(empty.len(), no.len());
        }
        // One fully hand-computed case: len=100, sni=11, max=32 → p0=21;
        // padding = 31 - ((100+21-1) % 32) = 31 - 24 = 7 → 107 bytes.
        assert_eq!(
            encode_inner_client_hello(&body, Some(b"example.com"), 32).len(),
            107
        );
        // A pre-aligned input still pads for the no-SNI offset:
        // len=128, p0=9 → 31 - ((136) % 32) = 23 → 151 bytes.
        let aligned = vec![0u8; 128];
        assert_eq!(encode_inner_client_hello(&aligned, None, 0).len(), 151);
    }

    #[test]
    fn compute_outer_ech_ext_seals_against_zero_payload_aad() {
        let sk_r = derive_key_pair_x25519(b"recipient-seed");
        let pk_r: [u8; 32] = MontgomeryPoint::mul_base_clamped(sk_r).0;
        let info = b"info";
        let (enc, mut sender) = HpkeSender::setup(&pk_r, HpkeAead::Aes128Gcm, info).unwrap();
        let config_id = 0x33;
        let encoded_inner = encode_inner_client_hello(&[0x11; 77], Some(b"sni.test"), 32);

        let final_ext = compute_outer_ech_ext(
            &mut sender,
            config_id,
            KDF_HKDF_SHA256,
            AEAD_AES_128_GCM,
            &enc,
            &encoded_inner,
            true,
            |placeholder| {
                // The caller's serialization of the outer hello BODY —
                // upstream seals against outer.marshal()[4:]
                // (ech.go:436-439), so the 4-byte handshake header is
                // already stripped here.
                let mut body = vec![0xde, 0xad];
                body.extend_from_slice(placeholder);
                // generateOuterECHExt layout: 1 type + 2 kdf + 2 aead +
                // 1 config id + 2 enc length + 2 payload length = 10
                // fixed bytes, plus enc and the placeholder payload of
                // len(encoded_inner) + 16 (the AEAD tag).
                assert_eq!(placeholder.len(), 10 + enc.len() + encoded_inner.len() + 16);
                body
            },
        )
        .unwrap();
        // Placeholder payload replaced by real ciphertext of len+16.
        match parse_ech_ext(&final_ext).unwrap() {
            EchExt::Outer {
                payload, enc: e, ..
            } => {
                assert_eq!(e, enc);
                assert_eq!(payload.len(), encoded_inner.len() + 16);
                // The recipient reconstructs the AAD from the FULL hello:
                // decryptECHPayload zeroes the payload inside hello[4:]
                // (ech.go:402-405), so give the fake hello a 4-byte
                // handshake header like outer.original.
                let mut full = vec![0x01, 0, 0, 0];
                full.push(0xde);
                full.push(0xad);
                full.extend_from_slice(&final_ext);
                let shared = hpke_decap(&sk_r, &enc).unwrap();
                let mut recipient =
                    HpkeSender::from_shared_secret(&shared, HpkeAead::Aes128Gcm, info).unwrap();
                let aad = zero_first_payload(&full, &payload);
                let pt = recipient.open(&aad, &payload).unwrap();
                assert_eq!(pt, encoded_inner);
            }
            other => panic!("wrong ext {other:?}"),
        }
    }

    /// `bytes.Replace(hello[4:], payload, zeros, 1)` (ech.go:403).
    fn zero_first_payload(hello: &[u8], payload: &[u8]) -> Vec<u8> {
        let body = &hello[4..];
        let pos = body
            .windows(payload.len())
            .position(|w| w == payload)
            .expect("payload present");
        let mut out = body.to_vec();
        out[pos..pos + payload.len()].fill(0);
        out
    }

    // ------------------------------------------------- accept confirmation

    #[test]
    fn accept_confirmation_matches_manual_derivation() {
        let inner_random = [0x42u8; 32];
        let inner_hello_body = vec![0x55; 64];
        let sh: Vec<u8> = (0..96u16).map(|i| (i % 251) as u8).collect();
        let ctx = transcript_context(&[&inner_hello_body]);
        let got = server_hello_accept_confirmation(&ctx, &sh, &inner_random).unwrap();

        // Independent inline re-derivation straight from the Go code
        // (handshake_client_tls13.go:87-97 + tls13.go:33-39): SHA-256
        // transcript with the random's last 8 bytes zeroed,
        // HKDF-Extract(inner_random) and the RFC 8446 §7.1 tls13 label,
        // all spelled out byte for byte.
        let mut conf = digest::Context::new(&digest::SHA256);
        conf.update(&inner_hello_body);
        conf.update(&sh[..30]);
        conf.update(&[0u8; 8]);
        conf.update(&sh[38..]);
        let digest_bytes = conf.finish();
        let prk = hkdf_extract(b"", &inner_random);
        let mut info = Vec::new();
        info.extend_from_slice(&[0, 8]);
        // u8 length of "tls13 " + label, then the label itself.
        info.push((b"tls13 ".len() + b"ech accept confirmation".len()) as u8);
        info.extend_from_slice(b"tls13 ech accept confirmation");
        info.push(digest_bytes.as_ref().len() as u8);
        info.extend_from_slice(digest_bytes.as_ref());
        let want_prk = Prk::new_less_safe(hkdf::HKDF_SHA256, &prk);
        let want_info = [&info[..]];
        let want = want_prk.expand(&want_info, HkdfLen(8)).unwrap();
        let mut want_bytes = [0u8; 8];
        want.fill(&mut want_bytes).unwrap();
        assert_eq!(got, want_bytes);

        // Structural pins: the confirmation slot is the last 8 bytes of
        // the ServerHello random — message bytes [30..38], because
        // `serverHello.original` includes the 4-byte handshake header
        // (random = original[6..38]; handshake_client_tls13.go:86-88).
        // Bytes inside the slot must NOT influence the value.
        let mut sh2 = sh.clone();
        sh2[33] ^= 1; // inside the slot
        assert_eq!(
            server_hello_accept_confirmation(&ctx, &sh2, &inner_random).unwrap(),
            got
        );
        let mut sh3 = sh.clone();
        sh3[6] ^= 1; // random[0] — inside random, before the slot
        assert_ne!(
            server_hello_accept_confirmation(&ctx, &sh3, &inner_random).unwrap(),
            got
        );
        let mut sh4 = sh.clone();
        sh4[40] ^= 1; // after the random
        assert_ne!(
            server_hello_accept_confirmation(&ctx, &sh4, &inner_random).unwrap(),
            got
        );
        // Short ServerHello → malformed.
        assert!(server_hello_accept_confirmation(&ctx, &sh[..37], &inner_random).is_err());
        // Constant-time compare helper.
        assert!(confirmation_matches(&got, &got));
        assert!(!confirmation_matches(&got, &[0u8; 8]));
    }

    #[test]
    fn hrr_confirmation_zeroes_the_ech_ext_value() {
        let inner_random = [7u8; 32];
        let mut hrr = vec![2u8, 0, 0, 60];
        hrr.extend_from_slice(&[0u8; 40]);
        let ech_value = [0x99u8; 8];
        hrr.extend_from_slice(&ech_value);
        hrr.extend_from_slice(&[1u8; 12]);
        let ctx = transcript_context(&[&[0x33; 50]]);
        let got = hrr_accept_confirmation(&ctx, &hrr, &ech_value, &inner_random).unwrap();

        // The zeroing targets the first byte-exact occurrence of the
        // value (bytes.Replace, handshake_client_tls13.go:268-269):
        // different value bytes at the same position still zero to the
        // same transcript, so only the POSITION matters...
        let other_value = [0x77u8; 8];
        let mut hrr2 = hrr.clone();
        hrr2[44..52].copy_from_slice(&other_value);
        assert_eq!(
            hrr_accept_confirmation(&ctx, &hrr2, &other_value, &inner_random).unwrap(),
            got
        );
        // ...while mutating the message without the matching value bytes
        // leaves the occurrence unfindable (an error in this standalone
        // API; Go's bytes.Replace would silently keep the bytes).
        let mut hrr_lost = hrr.clone();
        hrr_lost[44] ^= 0xff;
        assert!(hrr_accept_confirmation(&ctx, &hrr_lost, &ech_value, &inner_random).is_err());
        let mut hrr3 = hrr.clone();
        hrr3[10] ^= 1;
        assert_ne!(
            hrr_accept_confirmation(&ctx, &hrr3, &ech_value, &inner_random).unwrap(),
            got
        );
        // A wrong-length ext value is rejected.
        assert!(hrr_accept_confirmation(&ctx, &hrr, &[1u8; 7], &inner_random).is_err());
        // The ext value must occur in the message.
        assert!(hrr_accept_confirmation(&ctx, &[0u8; 8], &ech_value, &inner_random).is_err());
    }

    // ------------------------------------------------------ options

    #[test]
    fn ech_options_parse_mirrors_upstream() {
        let o = EchOptions::default();
        assert_eq!(o.parse().unwrap(), None);
        let mut o = EchOptions {
            enable: true,
            ..Default::default()
        };
        assert_eq!(
            o.parse().unwrap(),
            Some(EchConfigSource::DnsHttpsQuery { server_name: None })
        );
        o.query_server_name = "ech.example".into();
        assert_eq!(
            o.parse().unwrap(),
            Some(EchConfigSource::DnsHttpsQuery {
                server_name: Some("ech.example".into())
            })
        );
        o.config = "!!!not base64!!!".into();
        let err = o.parse().unwrap_err().to_string();
        assert!(
            err.contains("base64 decode ech config string failed"),
            "{err}"
        );
        let list = unhex(
            "0045fe0d0041590020002092a01233db2218518ccbbbbc24df20686af417b37388de6460e94011974777090004000100010012636c6f7564666c6172652d6563682e636f6d0000",
        );
        use base64::Engine as _;
        o.config = base64::engine::general_purpose::STANDARD.encode(&list);
        assert_eq!(o.parse().unwrap(), Some(EchConfigSource::Static(list)));
    }

    #[test]
    fn retry_config_list_shape() {
        assert_eq!(build_retry_config_list(&[]), None);
        let a = vec![1u8, 2];
        let b = vec![3u8];
        let out = build_retry_config_list(&[&a, &b]).unwrap();
        assert_eq!(out, vec![0, 3, 1, 2, 3]);
    }

    // ---------------------------------------------- selection + inner decode

    /// An ECHConfigList with one X25519/HKDF-SHA256/AES-128-GCM config, built
    /// by hand (the same shape the test server in reality::tls13 dials with).
    fn test_config_list(config_id: u8, public_name: &[u8], pk: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(config_id);
        body.extend_from_slice(&KEM_DH_X25519_HKDF_SHA256.to_be_bytes());
        body.extend_from_slice(&(pk.len() as u16).to_be_bytes());
        body.extend_from_slice(pk);
        let mut suites = Vec::new();
        for (kdf, aead) in [
            (KDF_HKDF_SHA256, AEAD_AES_128_GCM),
            (KDF_HKDF_SHA256, AEAD_AES_256_GCM),
        ] {
            suites.extend_from_slice(&kdf.to_be_bytes());
            suites.extend_from_slice(&aead.to_be_bytes());
        }
        // The cipher_suites length prefix is a BYTE count (4 per suite).
        body.extend_from_slice(&((suites.len() / 4 * 4) as u16).to_be_bytes());
        body.extend_from_slice(&suites);
        body.push(0x20); // max_name_length
        body.push(public_name.len() as u8);
        body.extend_from_slice(public_name);
        body.extend_from_slice(&0u16.to_be_bytes()); // no extensions
        let mut list = Vec::with_capacity(4 + body.len());
        list.extend_from_slice(&((4 + body.len() - 2) as u16).to_be_bytes());
        list.extend_from_slice(&EXTENSION_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
        list.extend_from_slice(&(body.len() as u16).to_be_bytes());
        list.extend_from_slice(&body);
        // The list length prefix covers everything after the first two bytes.
        let total = (list.len() - 2) as u16;
        list[0..2].copy_from_slice(&total.to_be_bytes());
        list
    }

    #[test]
    fn select_ech_config_parses_and_picks() {
        let pk = [7u8; 32];
        let list = test_config_list(0xab, b"public.example", &pk);
        let sel = select_ech_config(&list).unwrap();
        assert_eq!(sel.config.config_id, 0xab);
        assert_eq!(sel.config.public_name, b"public.example".to_vec());
        assert_eq!(sel.aead, HpkeAead::Aes128Gcm);
        // A list whose only config has an unsupported KEM picks nothing —
        // the makeClientHello error text surfaces verbatim.
        let mut bad = test_config_list(1, b"public.example", &[7u8; 32]);
        // KEM id is at: 2 (list len) + 4 (config hdr) + 1 (config id).
        bad[2 + 4 + 1..2 + 4 + 3].copy_from_slice(&0x0010u16.to_be_bytes());
        let err = select_ech_config(&bad).unwrap_err().to_string();
        assert!(err.contains("no valid configs"), "{err}");
        // Truncated list: the malformed-list error.
        assert!(select_ech_config(&list[..5]).is_err());
    }

    /// `decodeInnerClientHello` (ech.go:264-345): round-trip with an
    /// `ech_outer_extensions` reference list, plus every upstream rejection.
    #[test]
    fn decode_inner_client_hello_roundtrip_and_rejections() {
        // An outer hello carrying the referenced extensions.
        let outer_sid = [0x5eu8; 32];
        let mut outer = vec![0x01, 0, 0, 0, 0x03, 0x03];
        outer.extend_from_slice(&[0x11u8; 32]); // random
        outer.push(32);
        outer.extend_from_slice(&outer_sid);
        outer.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x03]); // suites
        outer.push(0x01);
        outer.push(0x00); // compression
        let groups = vec![0x00, 0x02, 0x00, 0x1d];
        let alpn = vec![0x00, 0x03, 0x02, 0x68, 0x32];
        let versions = vec![0x02, 0x03, 0x04];
        let mut exts = Vec::new();
        for (typ, body) in [
            (0x000au16, groups.clone()),
            (0x0010, alpn.clone()),
            (0x002b, versions.clone()),
        ] {
            exts.extend_from_slice(&typ.to_be_bytes());
            exts.extend_from_slice(&(body.len() as u16).to_be_bytes());
            exts.extend_from_slice(&body);
        }
        outer.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        outer.extend_from_slice(&exts);
        let body_len = (outer.len() - 4) as u32;
        outer[1..4].copy_from_slice(&body_len.to_be_bytes()[1..]);

        // The encoded inner: vers+random, empty session id, suites+comp, the
        // SNI and the ECH marker in the clear, and groups/alpn/versions
        // referenced through ech_outer_extensions (0xfd00).
        let sni_body = {
            let mut b = vec![0x00, 0x00, 0x00, 0x0b];
            b.extend_from_slice(b"inner.test");
            b
        };
        let mut refs = Vec::new();
        for t in [0x000au16, 0x0010, 0x002b] {
            refs.extend_from_slice(&t.to_be_bytes());
        }
        let mut compressed = vec![refs.len() as u8];
        compressed.extend_from_slice(&refs);
        let mut inner_exts = Vec::new();
        inner_exts.extend_from_slice(&0x0000u16.to_be_bytes());
        inner_exts.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        inner_exts.extend_from_slice(&sni_body);
        inner_exts.extend_from_slice(&EXTENSION_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
        inner_exts.extend_from_slice(&1u16.to_be_bytes());
        inner_exts.push(1);
        inner_exts.extend_from_slice(&EXTENSION_ECH_OUTER_EXTENSIONS.to_be_bytes());
        inner_exts.extend_from_slice(&(compressed.len() as u16).to_be_bytes());
        inner_exts.extend_from_slice(&compressed);

        let mut encoded = vec![0x03, 0x03];
        encoded.extend_from_slice(&[0x22u8; 32]);
        encoded.push(0); // empty session id
        encoded.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        encoded.push(1);
        encoded.push(0);
        encoded.extend_from_slice(&(inner_exts.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&inner_exts);
        encoded.extend_from_slice(&[0u8; 7]); // padding

        let recon = decode_inner_client_hello(&outer, &encoded).unwrap();
        assert_eq!(recon[0], 1);
        // The OUTER session id is restored into the transcript form.
        assert_eq!(recon[4 + 2 + 32], 32);
        assert_eq!(&recon[4 + 2 + 32 + 1..4 + 2 + 32 + 1 + 32], &outer_sid[..]);
        // The referenced extensions expanded to the outer's bodies, in the
        // referenced order, at the position of the 0xfd00 extension.
        let off = 4 + 2 + 32 + 1 + 32 + 2 + 2 + 1 + 1 + 2;
        let expanded_block = &recon[off..];
        let mut expect = Vec::new();
        for (typ, body) in [
            (0x0000u16, sni_body.clone()),
            (EXTENSION_ENCRYPTED_CLIENT_HELLO, vec![1]),
            (0x000a, groups),
            (0x0010, alpn),
            (0x002b, versions),
        ] {
            expect.extend_from_slice(&typ.to_be_bytes());
            expect.extend_from_slice(&(body.len() as u16).to_be_bytes());
            expect.extend_from_slice(&body);
        }
        assert_eq!(expanded_block, expect);

        // Rejections.
        let mut bad = encoded.clone();
        *bad.last_mut().unwrap() = 1; // non-zero padding
        assert!(decode_inner_client_hello(&outer, &bad).is_err());
        let mut with_sid = encoded.clone();
        with_sid[34] = 2; // a non-empty encoded session id
        with_sid.splice(35..35, [1, 2]);
        assert!(decode_inner_client_hello(&outer, &with_sid).is_err());
        // A reference list naming an extension the outer does not carry.
        let mut bad_ref = encoded.clone();
        let fd_pos = bad_ref
            .windows(2)
            .position(|w| w == EXTENSION_ECH_OUTER_EXTENSIONS.to_be_bytes())
            .unwrap();
        bad_ref[fd_pos + 4] = 8; // u8 count past the real payload
        assert!(decode_inner_client_hello(&outer, &bad_ref).is_err());
        // A missing inner marker: an extension block with only the SNI.
        let block_off = 2 + 32 + 1 + 2 + 2 + 1 + 1;
        let mut no_marker = encoded[..block_off].to_vec();
        let mut tail = Vec::new();
        tail.extend_from_slice(&0x0000u16.to_be_bytes());
        tail.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        tail.extend_from_slice(&sni_body);
        no_marker.extend_from_slice(&(tail.len() as u16).to_be_bytes());
        no_marker.extend_from_slice(&tail);
        assert!(decode_inner_client_hello(&outer, &no_marker).is_err());
        // supported_versions below TLS 1.3 (uncompressed, in the clear).
        let mut old = encoded.clone();
        let mut own = Vec::new();
        own.extend_from_slice(&0x002bu16.to_be_bytes());
        own.extend_from_slice(&3u16.to_be_bytes());
        own.extend_from_slice(&[2, 0x03, 0x03]);
        // Replace the whole extension block: SNI + the marker + 0x002b
        // (TLS 1.2 only — the marker must still be present so the failure
        // isolates the version check).
        let block_off = 2 + 32 + 1 + 2 + 2 + 1 + 1;
        let mut tail = Vec::new();
        tail.extend_from_slice(&0x0000u16.to_be_bytes());
        tail.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        tail.extend_from_slice(&sni_body);
        tail.extend_from_slice(&EXTENSION_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
        tail.extend_from_slice(&1u16.to_be_bytes());
        tail.push(1);
        tail.extend_from_slice(&own);
        let mut head = old[..block_off].to_vec();
        head.extend_from_slice(&(tail.len() as u16).to_be_bytes());
        head.extend_from_slice(&tail);
        old = head;
        let err = decode_inner_client_hello(&outer, &old)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("encrypted_client_hello extension with unsupported versions"),
            "{err}"
        );
    }
}
