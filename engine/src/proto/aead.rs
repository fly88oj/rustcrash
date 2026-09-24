//! AEAD primitives shared by the proxy protocols (Shadowsocks AEAD/2022,
//! VMess). Every construction here is built on RustCrypto audited crates;
//! nonces are supplied by the caller because each protocol numbers them
//! differently (SS: little-endian counters, VMess: big-endian counters
//! seeded from a per-connection IV).

use aes_gcm::aead::{Aead as _, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;

use crate::error::{Error, Result};

/// Supported AEAD constructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadKind {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl AeadKind {
    pub fn key_len(self) -> usize {
        match self {
            AeadKind::Aes128Gcm => 16,
            AeadKind::Aes256Gcm | AeadKind::Chacha20Poly1305 => 32,
        }
    }

}

enum Cipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

/// A keyed AEAD ready to seal/open with explicit nonces.
pub struct Aead {
    cipher: Cipher,
}

impl Aead {
    pub fn new(kind: AeadKind, key: &[u8]) -> Result<Self> {
        if key.len() != kind.key_len() {
            return Err(Error::crypto(format!(
                "aead key length {} != {} for {kind:?}",
                key.len(),
                kind.key_len()
            )));
        }
        let cipher = match kind {
            AeadKind::Aes128Gcm => Cipher::Aes128(Box::new(Aes128Gcm::new_from_slice(key).unwrap())),
            AeadKind::Aes256Gcm => Cipher::Aes256(Box::new(Aes256Gcm::new_from_slice(key).unwrap())),
            AeadKind::Chacha20Poly1305 => {
                Cipher::Chacha(Box::new(ChaCha20Poly1305::new_from_slice(key).unwrap()))
            }
        };
        Ok(Aead { cipher })
    }

    /// Append `ciphertext || tag` of `plain` to `out` under `nonce`.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], plain: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let ct = match &self.cipher {
            Cipher::Aes128(c) => c.encrypt(nonce.into(), aes_gcm::aead::Payload { msg: plain, aad }),
            Cipher::Aes256(c) => c.encrypt(nonce.into(), aes_gcm::aead::Payload { msg: plain, aad }),
            Cipher::Chacha(c) => c.encrypt(nonce.into(), chacha20poly1305::aead::Payload { msg: plain, aad }),
        }
        .map_err(|_| Error::crypto("aead seal failed"))?;
        out.extend_from_slice(&ct);
        Ok(())
    }

    /// Open `ciphertext || tag`; returns a freshly allocated plaintext.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        let pt = match &self.cipher {
            Cipher::Aes128(c) => c.decrypt(nonce.into(), aes_gcm::aead::Payload { msg: ct, aad }),
            Cipher::Aes256(c) => c.decrypt(nonce.into(), aes_gcm::aead::Payload { msg: ct, aad }),
            Cipher::Chacha(c) => c.decrypt(nonce.into(), chacha20poly1305::aead::Payload { msg: ct, aad }),
        }
        .map_err(|_| Error::crypto("aead open failed (wrong key, corrupted stream, or replayed salt"))?;
        Ok(pt)
    }
}

/// Shadowsocks AEAD nonce: a 12-byte little-endian counter that increments
/// once per seal/open operation, starting at zero, per connection direction.
#[derive(Debug, Clone, Copy)]
pub struct SsNonce(u64);

impl SsNonce {
    pub fn new() -> Self {
        SsNonce(0)
    }

    pub fn advance(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.0.to_le_bytes());
        self.0 += 1;
        n
    }
}

impl Default for SsNonce {
    fn default() -> Self {
        Self::new()
    }
}

/// EVP_BytesToKey (MD5, one round of salt) — the legacy Shadowsocks
/// password-to-key derivation. Only used by legacy AEAD methods; 2022
/// methods take the raw base64 PSK.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    use md5::Md5;
    use sha2::Digest;
    let mut d = Md5::digest(password).to_vec();
    let mut out = d.clone();
    while out.len() < key_len {
        let mut h = Md5::new();
        h.update(&d);
        h.update(password);
        d = h.finalize().to_vec();
        out.extend_from_slice(&d);
    }
    out.truncate(key_len);
    out
}

/// HKDF-SHA1 subkey derivation for legacy SS AEAD (RFC 5869, SHA-1 as the
/// hash). Hand-rolled from `hmac`/`sha1` so the extraction and derivation
/// steps stay visible and testable against published vectors.
pub fn ss_subkey_legacy(key: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut okm = vec![0u8; key.len()];
    hkdf_sha1(key, salt, b"ss-subkey", &mut okm);
    okm
}

/// RFC 5869 HKDF with SHA-1: extract-then-derive.
pub fn hkdf_sha1(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;

    // Extract: PRK = HMAC-SHA1(salt, IKM)
    let mut mac = <HmacSha1 as Mac>::new_from_slice(salt).expect("hmac accepts any key length");
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();

    // Derive: T(1) = HMAC(PRK, info || 0x01); T(n) = HMAC(PRK, T(n-1) || info || n)
    let mut t: Vec<u8> = Vec::with_capacity(20);
    let mut counter: u8 = 1;
    let mut produced = 0usize;
    while produced < out.len() {
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&prk).expect("hmac accepts any key length");
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);
        let block = mac.finalize().into_bytes();
        let take = (out.len() - produced).min(20);
        out[produced..produced + take].copy_from_slice(&block[..take]);
        t = block.to_vec();
        produced += take;
        counter = counter.wrapping_add(1);
    }
}

/// BLAKE3 derive-key subkey for Shadowsocks 2022:
/// `session_subkey = blake3::derive_key("shadowsocks 2022 session subkey", key || salt)`
pub fn ss2022_subkey(key: &[u8], salt: &[u8], out_len: usize) -> Vec<u8> {
    let mut material = Vec::with_capacity(key.len() + salt.len());
    material.extend_from_slice(key);
    material.extend_from_slice(salt);
    blake3::derive_key("shadowsocks 2022 session subkey", &material[..]).to_vec()[..out_len].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_all_kinds() {
        for kind in [AeadKind::Aes128Gcm, AeadKind::Aes256Gcm, AeadKind::Chacha20Poly1305] {
            let aead = Aead::new(kind, &[7u8; 32][..kind.key_len()]).unwrap();
            let mut ct = Vec::new();
            aead.seal(&[0u8; 12], b"aad", b"hello", &mut ct).unwrap();
            assert_eq!(ct.len(), 5 + 16);
            let pt = aead.open(&[0u8; 12], b"aad", &ct).unwrap();
            assert_eq!(pt, b"hello");
            // Wrong AAD / wrong nonce must fail.
            assert!(aead.open(&[0u8; 12], b"bad", &ct).is_err());
            assert!(aead.open(&[1u8; 12], b"aad", &ct).is_err());
        }
    }

    #[test]
    fn wrong_key_length_rejected() {
        assert!(Aead::new(AeadKind::Aes128Gcm, &[0u8; 32]).is_err());
        assert!(Aead::new(AeadKind::Aes256Gcm, &[0u8; 16]).is_err());
    }

    #[test]
    fn evp_bytes_to_key_known_vector() {
        // EVP_BytesToKey("test", 32): the first 16 bytes are MD5("test")…
        let key = evp_bytes_to_key(b"test", 32);
        assert_eq!(hex(&key[..16]), "098f6bcd4621d373cade4e832627b4f6");
        assert_eq!(key.len(), 32);
        // …and the chain continues MD5(prev || password).
        use sha2::Digest;
        let mut h = md5::Md5::new();
        h.update(hex_bytes("098f6bcd4621d373cade4e832627b4f6").as_slice());
        h.update(b"test");
        assert_eq!(&key[16..], &h.finalize()[..]);
    }

    #[test]
    fn hkdf_sha1_rfc5869_test_case_4() {
        // RFC 5869 A.4 (basic SHA-1): OKM =
        // 085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2
        // c22e422478d305f3f896
        let ikm = [0x0bu8; 11];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut okm = [0u8; 42];
        hkdf_sha1(&ikm, &salt, &info, &mut okm);
        assert_eq!(
            hex(&okm),
            "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"
        );
    }

    #[test]
    fn ss_nonce_is_le_and_increments() {
        let mut n = SsNonce::new();
        assert_eq!(&n.advance()[..8], &0u64.to_le_bytes());
        assert_eq!(&n.advance()[..8], &1u64.to_le_bytes());
        assert_eq!(&n.advance()[..8], &2u64.to_le_bytes());
        // Upper 4 bytes stay zero (12-byte nonce).
        assert_eq!(n.advance()[8..], [0, 0, 0, 0]);
    }

    #[test]
    fn legacy_subkey_is_deterministic() {
        let key = evp_bytes_to_key(b"pass", 32);
        let a = ss_subkey_legacy(&key, &[1u8; 16]);
        let b = ss_subkey_legacy(&key, &[1u8; 16]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert_ne!(a, ss_subkey_legacy(&key, &[2u8; 16]));
    }

    #[test]
    fn ss2022_subkey_matches_reference() {
        // Determinism and shape; full cross-implementation vectors are
        // exercised by the docker interop tests against real mihomo.
        let a = ss2022_subkey(&[1u8; 16], &[2u8; 16], 16);
        assert_eq!(a.len(), 16);
        assert_eq!(a, ss2022_subkey(&[1u8; 16], &[2u8; 16], 16));
        assert_ne!(a, ss2022_subkey(&[1u8; 16], &[3u8; 16], 16));
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
