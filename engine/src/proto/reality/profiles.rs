//! uTLS-style ClientHello templates (Chrome / Firefox shapes).
//!
//! Hand-built from refraction-networking/utls `u_parrots.go` so the hello
//! bytes are ours (rustls cannot emit a chosen extension order). The two
//! profiles here are the ones every mihomo/sing-box user can select via
//! `client-fingerprint: chrome|firefox`; the REALITY handshake uses them too
//! (Xray's uTLS client always sends a Chrome hello).
//!
//! Ported upstream source: <https://github.com/refraction-networking/utls>,
//! `u_parrots.go` (`case HelloChrome_120`, `case HelloFirefox_120`) plus the
//! GREASE value rule of RFC 8701 and BoringSSL's ClientHello padding style
//! (`u_tls_extensions.go::BoringPaddingStyle`).
//!
//! Deliberate deviations from the parrots (all documented in the module
//! report, none of them change the REALITY handshake):
//!
//! * `encrypted_client_hello` (0xfe0d) GREASE slots are omitted. Both parrots
//!   carry one (`BoringGREASEECH()` / `GREASEEncryptedClientHelloExtension`);
//!   a fake ECH body is parsed by strict peers (Xray's REALITY server has its
//!   own ECH code path) and buys nothing here, since we never send ECH.
//! * Firefox's `delegated_credentials` (0x0022) is omitted: advertising it
//!   asks a DC-capable CDN to answer with a delegated-credential chain, which
//!   webpki/rustls cannot validate.
//! * Firefox's `key_share` carries only X25519 (the parrot also sends a
//!   P-256 share). This stack implements X25519 only.
//! * Chrome's extension shuffle is seeded from the hello `random` (itself
//!   CSPRNG bytes) instead of a fresh entropy draw, so the byte layout is
//!   reproducible in tests. Untouched: GREASE and padding stay pinned.

/// Reserved GREASE value (`GREASE_PLACEHOLDER` in uTLS / RFC 8701).
const GREASE: u16 = 0x0a0a;

// Extension codepoints used by the templates.
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SIGNED_CERT_TIMESTAMP: u16 = 0x0012;
const EXT_PADDING: u16 = 0x0015;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_RECORD_SIZE_LIMIT: u16 = 0x001c;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
/// Chrome's ALPS (`application_settings`).
const EXT_APPLICATION_SETTINGS: u16 = 0x4469;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// `named_group` codepoints.
pub(crate) const GROUP_X25519: u16 = 0x001d;
const GROUP_P256: u16 = 0x0017;
const GROUP_P384: u16 = 0x0018;
const GROUP_P521: u16 = 0x0019;
const GROUP_FFDHE2048: u16 = 0x0100;
const GROUP_FFDHE3072: u16 = 0x0101;

/// Version codepoints.
pub(crate) const VERSION_TLS13: u16 = 0x0304;
pub(crate) const VERSION_TLS12: u16 = 0x0303;

/// The 32-byte session id lives at this fixed offset of every ClientHello
/// handshake message (4-byte handshake header + 2 version + 32 random +
/// 1 session-id length). REALITY seals its auth material into these bytes;
/// uTLS hardcodes the same offset (`hello.Raw[39:]` in Xray's reality.go).
pub const SESSION_ID_OFFSET: usize = 39;

/// ClientHello fingerprints this stack can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtslProfile {
    /// Chrome 120 shape (uTLS `HelloChrome_120`).
    Chrome,
    /// Firefox 120 shape (uTLS `HelloFirefox_120`).
    Firefox,
}

impl UtslProfile {
    /// Stable name for logs and config round-tripping.
    pub fn as_str(self) -> &'static str {
        match self {
            UtslProfile::Chrome => "chrome",
            UtslProfile::Firefox => "firefox",
        }
    }

    /// Parse mihomo's `client-fingerprint` spellings.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "chrome" => Some(UtslProfile::Chrome),
            "firefox" => Some(UtslProfile::Firefox),
            _ => None,
        }
    }

    /// Extension codepoints in canonical (pre-shuffle) order. Tests pin the
    /// built hello against this.
    pub fn extension_template(self) -> &'static [u16] {
        match self {
            UtslProfile::Chrome => &[
                GREASE, // UtlsGREASEExtension (empty body), pinned first
                EXT_SERVER_NAME,
                EXT_EXTENDED_MASTER_SECRET,
                EXT_RENEGOTIATION_INFO,
                EXT_SUPPORTED_GROUPS,
                EXT_EC_POINT_FORMATS,
                EXT_SESSION_TICKET,
                EXT_ALPN,
                EXT_STATUS_REQUEST,
                EXT_SIGNATURE_ALGORITHMS,
                EXT_SIGNED_CERT_TIMESTAMP,
                EXT_KEY_SHARE,
                EXT_PSK_KEY_EXCHANGE_MODES,
                EXT_SUPPORTED_VERSIONS,
                EXT_COMPRESS_CERTIFICATE,
                EXT_APPLICATION_SETTINGS,
                GREASE, // second GREASE (1-byte body), pinned second-to-last
                EXT_PADDING, // BoringSSL padding, pinned last
            ],
            UtslProfile::Firefox => &[
                EXT_SERVER_NAME,
                EXT_EXTENDED_MASTER_SECRET,
                EXT_RENEGOTIATION_INFO,
                EXT_SUPPORTED_GROUPS,
                EXT_EC_POINT_FORMATS,
                EXT_SESSION_TICKET,
                EXT_ALPN,
                EXT_STATUS_REQUEST,
                EXT_KEY_SHARE,
                EXT_SUPPORTED_VERSIONS,
                EXT_SIGNATURE_ALGORITHMS,
                EXT_PSK_KEY_EXCHANGE_MODES,
                EXT_RECORD_SIZE_LIMIT,
            ],
        }
    }

    /// Cipher suite list in wire order (`u_parrots.go` verbatim).
    pub fn cipher_suites(self) -> &'static [u16] {
        match self {
            UtslProfile::Chrome => &[
                GREASE,
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
                0x002f, 0x0035,
            ],
            UtslProfile::Firefox => &[
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a,
                0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
        }
    }
}

/// The GREASE values of one ClientHello, one per slot.
///
/// uTLS (like BoringSSL) keeps a per-slot `greaseSeed` and folds each seed
/// into the RFC 8701 form `0xωaωa` (`GetBoringGREASEValue`: `(seed & 0xf0) |
/// 0x0a`, then `ret |= ret << 8`). Using *one* value everywhere is wrong on
/// two counts: it is not what Chrome emits, and two extensions carrying the
/// same id are a duplicate that strict peers (rustls) abort with
/// `illegal_parameter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grease {
    /// First entry of `cipher_suites` (`ssl_grease_cipher`).
    pub cipher: u16,
    /// `supported_groups[0]` and the GREASE `key_share` entry
    /// (`ssl_grease_group` — the same value in both places, since a key share
    /// must appear in supported_groups).
    pub group: u16,
    /// First GREASE extension, empty body (`ssl_grease_extension1`).
    pub extension1: u16,
    /// Second GREASE extension, one zero byte (`ssl_grease_extension2`).
    pub extension2: u16,
    /// First entry of `supported_versions` (`ssl_grease_version`).
    pub version: u16,
}

/// GREASE values for this hello. uTLS draws `2 * 5` fresh random bytes for
/// the seeds and forces the two extension slots apart (`greaseSeed[1] ^=
/// 0x1010`) when a draw collides; we seed the same draw from the hello random
/// (itself CSPRNG bytes) so a given hello stays byte-reproducible.
pub fn grease_values(random: &[u8; 32]) -> Grease {
    use rand::{RngCore, SeedableRng};

    let mut rng = rand::rngs::StdRng::from_seed(*random);
    let mut seeds = [0u8; 10];
    rng.fill_bytes(&mut seeds);
    let slot = |i: usize| {
        let raw = u16::from_le_bytes([seeds[2 * i], seeds[2 * i + 1]]);
        // (raw & 0xf0) | 0x0a == 0xωa, duplicated into both octets.
        ((raw & 0xf0) | 0x0a) * 0x0101
    };
    let mut grease = Grease {
        cipher: slot(0),
        group: slot(1),
        extension1: slot(2),
        extension2: slot(3),
        version: slot(4),
    };
    if grease.extension1 == grease.extension2 {
        grease.extension2 ^= 0x1010;
    }
    grease
}

/// Build the ClientHello handshake message for `profile`.
///
/// Returns the complete handshake message (`0x01 || u24 length || body`),
/// *not* wrapped in a record — REALITY must rewrite the session id in place
/// before the record is framed (see [`client_hello_record`]).
///
/// `session_id` is copied verbatim (Chrome/Firefox both send a 32-byte
/// legacy session id; REALITY replaces it afterwards). `key_share_public` is
/// the 32-byte X25519 public key offered for group 0x001d.
pub fn build_client_hello(
    profile: UtslProfile,
    sni: &str,
    random: &[u8; 32],
    session_id: &[u8; 32],
    key_share_public: &[u8; 32],
) -> Vec<u8> {
    build_client_hello_alpn(profile, sni, random, session_id, key_share_public, None)
}

/// [`build_client_hello`] with an explicit ALPN list (default: the profile's
/// own list — h2 + http/1.1 for both).
pub fn build_client_hello_alpn(
    profile: UtslProfile,
    sni: &str,
    random: &[u8; 32],
    session_id: &[u8; 32],
    key_share_public: &[u8; 32],
    alpn: Option<&[String]>,
) -> Vec<u8> {
    build_client_hello_opts(profile, sni, random, session_id, key_share_public, alpn, None, true)
}

/// The full builder every wrapper above funnels into.
///
/// Two extra knobs beyond [`build_client_hello_alpn`], both needed by JLS
/// (`proto/jls.rs`, ported from mihomo `transport/jls/utls.go`):
///
/// * `structure_seed` — the GREASE values and (for Chrome) the extension
///   shuffle are normally derived from the hello `random`. JLS *replaces*
///   the random after the hello structure is built (uTLS `SetClientRandom`,
///   `utls.go:95-97`), so it must pin the structure to the original random
///   draw: `None` derives from `random` (the parrot behavior), `Some(seed)`
///   keeps GREASE and the shuffle fixed while `random` changes. A rebuild
///   that only swaps the random then differs from the first pass in exactly
///   the 32 random bytes — the property JLS' authData (random-zeroed hello)
///   depends on.
/// * `alps` — Chrome's `application_settings` (0x4469) extension. mihomo's
///   uTLS path keeps ALPS only while `h2` stays advertised
///   (`overrideUTLSALPN`, `utls.go:208-241`); callers whose ALPN list drops
///   h2 pass `false`. Firefox never sends ALPS; the flag is ignored there.
#[allow(clippy::too_many_arguments)]
pub fn build_client_hello_opts(
    profile: UtslProfile,
    sni: &str,
    random: &[u8; 32],
    session_id: &[u8; 32],
    key_share_public: &[u8; 32],
    alpn: Option<&[String]>,
    structure_seed: Option<&[u8; 32]>,
    alps: bool,
) -> Vec<u8> {
    let structure_seed: [u8; 32] = structure_seed.copied().unwrap_or(*random);
    let grease = grease_values(&structure_seed);
    let default_alpn = ["h2".to_string(), "http/1.1".to_string()];
    let alpn: &[String] = alpn.unwrap_or(&default_alpn);

    let mut exts: Vec<(bool, Vec<u8>)> = Vec::with_capacity(18);
    match profile {
        UtslProfile::Chrome => {
            // `ShuffleChromeTLSExtensions` keeps GREASE/padding pinned; every
            // other extension is shuffled per connection.
            exts.push((true, grease_extension(grease.extension1, &[])));
            exts.push((false, sni_extension(sni)));
            exts.push((false, ext(EXT_EXTENDED_MASTER_SECRET, &[])));
            exts.push((false, ext(EXT_RENEGOTIATION_INFO, &[0x00])));
            exts.push((
                false,
                supported_groups_extension(&[grease.group, GROUP_X25519, GROUP_P256, GROUP_P384]),
            ));
            exts.push((false, ext(EXT_EC_POINT_FORMATS, &[0x01, 0x00])));
            exts.push((false, ext(EXT_SESSION_TICKET, &[])));
            exts.push((false, alpn_extension(EXT_ALPN, alpn)));
            exts.push((false, ext(EXT_STATUS_REQUEST, &[0x01, 0x00, 0x00, 0x00, 0x00])));
            exts.push((false, signature_algorithms_extension(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ])));
            exts.push((false, ext(EXT_SIGNED_CERT_TIMESTAMP, &[])));
            exts.push((false, key_share_extension(key_share_public, grease.group, true)));
            exts.push((false, ext(EXT_PSK_KEY_EXCHANGE_MODES, &[0x01, 0x01])));
            exts.push((
                false,
                supported_versions_extension(&[grease.version, VERSION_TLS13, VERSION_TLS12]),
            ));
            // brotli (Chrome also offers zlib on some builds; the parrot
            // matches Chrome 120 with brotli only). RFC 8879's list length is
            // a BYTE count, as uTLS writes it (`extLen = 2 * len(Algorithms)`):
            // a count-of-1 body makes strict parsers reject the hello.
            exts.push((false, ext(EXT_COMPRESS_CERTIFICATE, &[0x02, 0x00, 0x02])));
            if alps {
                exts.push((false, alpn_extension(EXT_APPLICATION_SETTINGS, &["h2".to_string()])));
            }
            exts.push((true, grease_extension(grease.extension2, &[0x00])));
            shuffle_chrome_extensions(&mut exts, &structure_seed);
        }
        UtslProfile::Firefox => {
            exts.push((true, sni_extension(sni)));
            exts.push((true, ext(EXT_EXTENDED_MASTER_SECRET, &[])));
            exts.push((true, ext(EXT_RENEGOTIATION_INFO, &[0x00])));
            exts.push((
                true,
                supported_groups_extension(&[
                    GROUP_X25519,
                    GROUP_P256,
                    GROUP_P384,
                    GROUP_P521,
                    GROUP_FFDHE2048,
                    GROUP_FFDHE3072,
                ]),
            ));
            exts.push((true, ext(EXT_EC_POINT_FORMATS, &[0x01, 0x00])));
            exts.push((true, ext(EXT_SESSION_TICKET, &[])));
            exts.push((true, alpn_extension(EXT_ALPN, alpn)));
            exts.push((true, ext(EXT_STATUS_REQUEST, &[0x01, 0x00, 0x00, 0x00, 0x00])));
            exts.push((true, key_share_extension(key_share_public, 0, false)));
            exts.push((
                true,
                supported_versions_extension(&[VERSION_TLS13, VERSION_TLS12]),
            ));
            exts.push((true, signature_algorithms_extension(&[
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201,
            ])));
            exts.push((true, ext(EXT_PSK_KEY_EXCHANGE_MODES, &[0x01, 0x01])));
            // `FakeRecordSizeLimitExtension{Limit: 0x4001}`.
            exts.push((true, ext(EXT_RECORD_SIZE_LIMIT, &[0x40, 0x01])));
        }
    }

    let mut body: Vec<u8> = Vec::with_capacity(512);
    body.extend_from_slice(&VERSION_TLS12.to_be_bytes()); // legacy_version
    body.extend_from_slice(random);
    body.push(32);
    body.extend_from_slice(session_id);
    let mut suites = profile.cipher_suites().to_vec();
    if suites.first() == Some(&GREASE) {
        suites[0] = grease.cipher;
    }
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        body.extend_from_slice(&s.to_be_bytes());
    }
    body.push(0x01);
    body.push(0x00); // compression: null only

    // Chrome pads the *handshake message* to 512 bytes (BoringSSL), computed
    // before the padding extension itself is appended (uTLS
    // `paddingExt.Update(headerLength + 4 + extensionsLen + 2)`).
    if profile == UtslProfile::Chrome {
        let unpadded = 4 + body.len() + 2 + exts.iter().map(|(_, e)| e.len()).sum::<usize>();
        if let Some(n) = boring_padding_body_len(unpadded) {
            exts.push((true, ext(EXT_PADDING, &vec![0u8; n])));
        }
    }

    let mut ext_bytes = Vec::with_capacity(512);
    for (_, e) in &exts {
        ext_bytes.extend_from_slice(e);
    }
    body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_bytes);

    let mut msg = Vec::with_capacity(body.len() + 4);
    msg.push(0x01); // handshake type: client_hello
    let len = body.len();
    msg.push((len >> 16) as u8);
    msg.push((len >> 8) as u8);
    msg.push(len as u8);
    msg.extend_from_slice(&body);
    debug_assert_eq!(msg.len(), 4 + len);
    debug_assert_eq!(&msg[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32], session_id);
    msg
}

/// Frame a ClientHello handshake message as its own TLS record with the
/// 0x0301 legacy record version every browser uses for the first flight.
pub fn client_hello_record(hello: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hello.len() + 5);
    out.push(0x16); // content type: handshake
    out.extend_from_slice(&[0x03, 0x01]); // legacy record version (TLS 1.0)
    out.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    out.extend_from_slice(hello);
    out
}

/// `ShuffleChromeTLSExtensions` (u_parrots.go): GREASE and padding keep their
/// slots, everything else is permuted. Seeded from the hello random.
fn shuffle_chrome_extensions(exts: &mut [(bool, Vec<u8>)], random: &[u8; 32]) {
    use rand::seq::SliceRandom;
    use rand::SeedableRng;

    let movable: Vec<usize> = exts
        .iter()
        .enumerate()
        .filter(|(_, (pinned, _))| !pinned)
        .map(|(i, _)| i)
        .collect();
    let mut blobs: Vec<Vec<u8>> = movable.iter().map(|&i| exts[i].1.clone()).collect();
    let mut rng = rand::rngs::StdRng::from_seed(*random);
    blobs.shuffle(&mut rng);
    for (slot, blob) in movable.iter().zip(blobs) {
        exts[*slot].1 = blob;
    }
}

/// `BoringPaddingStyle(unpaddedLen)`: pad the ClientHello to exactly 512
/// bytes when it lands in (255, 511). Returns the padding extension body
/// length (the extension adds 4 more bytes of header).
///
/// The `4 + 1` literal is uTLS's (`u_tls_extensions.go`), kept verbatim.
#[allow(clippy::int_plus_one)]
fn boring_padding_body_len(unpadded: usize) -> Option<usize> {
    if unpadded > 0xff && unpadded < 0x200 {
        let mut padding_len = 0x200 - unpadded;
        if padding_len >= 4 + 1 {
            padding_len -= 4;
        } else {
            padding_len = 1;
        }
        Some(padding_len)
    } else {
        None
    }
}

// --- extension encoders -------------------------------------------------

fn ext(typ: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn grease_extension(value: u16, body: &[u8]) -> Vec<u8> {
    ext(value, body)
}

fn sni_extension(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut body = Vec::with_capacity(5 + name.len());
    body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // server_name_list
    body.push(0x00); // host_name
    body.extend_from_slice(&(name.len() as u16).to_be_bytes());
    body.extend_from_slice(name);
    ext(EXT_SERVER_NAME, &body)
}

fn supported_groups_extension(groups: &[u16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + groups.len() * 2);
    body.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for g in groups {
        body.extend_from_slice(&g.to_be_bytes());
    }
    ext(EXT_SUPPORTED_GROUPS, &body)
}

fn signature_algorithms_extension(algs: &[u16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + algs.len() * 2);
    body.extend_from_slice(&((algs.len() * 2) as u16).to_be_bytes());
    for a in algs {
        body.extend_from_slice(&a.to_be_bytes());
    }
    ext(EXT_SIGNATURE_ALGORITHMS, &body)
}

/// ALPN-shaped protocol list (also used by Chrome's ALPS extension, which
/// marshals exactly like ALPN under its own codepoint).
fn alpn_extension(typ: u16, protocols: &[String]) -> Vec<u8> {
    let mut list = Vec::new();
    for p in protocols {
        let bytes = p.as_bytes();
        list.push(bytes.len() as u8);
        list.extend_from_slice(bytes);
    }
    let mut body = Vec::with_capacity(2 + list.len());
    body.extend_from_slice(&(list.len() as u16).to_be_bytes());
    body.extend_from_slice(&list);
    ext(typ, &body)
}

fn supported_versions_extension(versions: &[u16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + versions.len() * 2);
    body.push((versions.len() * 2) as u8);
    for v in versions {
        body.extend_from_slice(&v.to_be_bytes());
    }
    ext(EXT_SUPPORTED_VERSIONS, &body)
}

/// Chrome offers a GREASE key share (1 byte) before the real X25519 share.
fn key_share_extension(public: &[u8; 32], grease: u16, with_grease: bool) -> Vec<u8> {
    let mut list = Vec::with_capacity(64);
    if with_grease {
        list.extend_from_slice(&grease.to_be_bytes());
        list.extend_from_slice(&1u16.to_be_bytes());
        list.push(0x00);
    }
    list.extend_from_slice(&GROUP_X25519.to_be_bytes());
    list.extend_from_slice(&32u16.to_be_bytes());
    list.extend_from_slice(public);
    let mut body = Vec::with_capacity(2 + list.len());
    body.extend_from_slice(&(list.len() as u16).to_be_bytes());
    body.extend_from_slice(&list);
    ext(EXT_KEY_SHARE, &body)
}

// --- test-only parsing helpers -----------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal ClientHello parser used to pin the built bytes.
    struct Parsed {
        legacy_version: u16,
        random: [u8; 32],
        session_id: Vec<u8>,
        suites: Vec<u16>,
        compression: Vec<u8>,
        extensions: Vec<(u16, Vec<u8>)>,
    }

    fn u16_at(b: &[u8], i: usize) -> u16 {
        u16::from_be_bytes([b[i], b[i + 1]])
    }

    fn u24_at(b: &[u8], i: usize) -> usize {
        ((b[i] as usize) << 16) | ((b[i + 1] as usize) << 8) | b[i + 2] as usize
    }

    fn parse(msg: &[u8]) -> Parsed {
        assert_eq!(msg[0], 0x01, "handshake type");
        assert_eq!(u24_at(msg, 1), msg.len() - 4, "handshake length");
        let b = &msg[4..];
        let mut p = Parsed {
            legacy_version: u16_at(b, 0),
            random: b[2..34].try_into().unwrap(),
            session_id: Vec::new(),
            suites: Vec::new(),
            compression: Vec::new(),
            extensions: Vec::new(),
        };
        let sid_len = b[34] as usize;
        p.session_id = b[35..35 + sid_len].to_vec();
        let mut off = 35 + sid_len;
        let cs_len = u16_at(b, off) as usize;
        off += 2;
        for i in 0..cs_len / 2 {
            p.suites.push(u16_at(b, off + i * 2));
        }
        off += cs_len;
        let cm_len = b[off] as usize;
        p.compression = b[off + 1..off + 1 + cm_len].to_vec();
        off += 1 + cm_len;
        let ext_total = u16_at(b, off) as usize;
        off += 2;
        assert_eq!(off + ext_total, b.len(), "extensions block length");
        let end = off + ext_total;
        while off < end {
            let typ = u16_at(b, off);
            let len = u16_at(b, off + 2) as usize;
            p.extensions
                .push((typ, b[off + 4..off + 4 + len].to_vec()));
            off += 4 + len;
        }
        p
    }

    fn fixed() -> ([u8; 32], [u8; 32], [u8; 32]) {
        let mut random = [0u8; 32];
        for (i, b) in random.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut sid = [0u8; 32];
        for (i, b) in sid.iter_mut().enumerate() {
            *b = 0xa0 + i as u8;
        }
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = 0x10 + i as u8;
        }
        (random, sid, key)
    }

    #[test]
    fn hello_record_has_the_browser_prefix() {
        let (random, sid, key) = fixed();
        let hello = build_client_hello(UtslProfile::Chrome, "www.example.com", &random, &sid, &key);
        let record = client_hello_record(&hello);
        assert_eq!(&record[..3], &[0x16, 0x03, 0x01]);
        assert_eq!(u16_at(&record, 3) as usize, hello.len());
        assert_eq!(&record[5..], &hello[..]);
    }

    #[test]
    fn session_id_lands_at_the_fixed_offset() {
        let (random, sid, key) = fixed();
        for profile in [UtslProfile::Chrome, UtslProfile::Firefox] {
            let hello = build_client_hello(profile, "a.test", &random, &sid, &key);
            assert_eq!(
                &hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32],
                &sid[..],
                "{profile:?}"
            );
            assert_eq!(parse(&hello).session_id, sid.to_vec(), "{profile:?}");
        }
    }

    #[test]
    fn chrome_shape_matches_the_parrot() {
        let (random, sid, key) = fixed();
        let hello = build_client_hello(UtslProfile::Chrome, "www.example.com", &random, &sid, &key);
        let p = parse(&hello);

        assert_eq!(p.legacy_version, VERSION_TLS12);
        assert_eq!(p.random, random);
        assert_eq!(p.session_id.len(), 32);
        assert_eq!(p.compression, vec![0x00]);

        // GREASE: one value per slot, all reserved, extensions distinct.
        let g = grease_values(&random);
        let mut want_suites = UtslProfile::Chrome.cipher_suites().to_vec();
        want_suites[0] = g.cipher; // the template's GREASE placeholder
        assert_eq!(p.suites, want_suites);

        let types: Vec<u16> = p.extensions.iter().map(|(t, _)| *t).collect();
        assert_eq!(types.len(), 18);
        assert_eq!(types[0], g.extension1, "first extension is GREASE");
        assert_eq!(types[17], EXT_PADDING, "padding is pinned last");
        assert_eq!(types[16], g.extension2, "second GREASE is pinned second-to-last");
        assert_ne!(g.extension1, g.extension2, "two extensions may not share an id");

        // Everything in between is the template set, only reordered.
        let mut got = types[1..16].to_vec();
        let mut want = UtslProfile::Chrome.extension_template()[1..16].to_vec();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(got, want, "shuffled middle block");

        // GREASE extension bodies: first empty, second a single zero byte.
        assert_eq!(p.extensions[0].1.len(), 0);
        assert_eq!(p.extensions[16].1, vec![0x00]);

        // supported_groups / key_share lead with GREASE.
        let (gb, gs) = ((g.group >> 8) as u8, (g.group & 0xff) as u8);
        let curves = &p.extensions.iter().find(|(t, _)| *t == EXT_SUPPORTED_GROUPS).unwrap().1;
        assert_eq!(
            curves,
            &[0x00, 0x08, gb, gs, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18][..]
        );
        let ks = &p.extensions.iter().find(|(t, _)| *t == EXT_KEY_SHARE).unwrap().1;
        assert_eq!(u16_at(ks, 0) as usize, ks.len() - 2);
        let mut koff = 2;
        assert_eq!(u16_at(ks, koff), g.group, "key share agrees with supported_groups");
        assert_eq!(u16_at(ks, koff + 2), 1);
        assert_eq!(ks[koff + 4], 0x00);
        koff += 5;
        assert_eq!(u16_at(ks, koff), GROUP_X25519);
        assert_eq!(u16_at(ks, koff + 2), 32);
        assert_eq!(&ks[koff + 4..koff + 36], &key[..]);

        // supported_versions = [GREASE, 1.3, 1.2]
        let sv = &p.extensions.iter().find(|(t, _)| *t == EXT_SUPPORTED_VERSIONS).unwrap().1;
        assert_eq!(sv[0] as usize, sv.len() - 1);
        assert_eq!(u16_at(sv, 1), g.version);
        assert_eq!(u16_at(sv, 3), VERSION_TLS13);
        assert_eq!(u16_at(sv, 5), VERSION_TLS12);

        // signature_algorithms: Chrome's exact list (no Ed25519).
        let sa = &p.extensions.iter().find(|(t, _)| *t == EXT_SIGNATURE_ALGORITHMS).unwrap().1;
        assert_eq!(
            &sa[2..],
            &[0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01]
        );

        // ALPN body: h2 + http/1.1.
        let alpn = &p.extensions.iter().find(|(t, _)| *t == EXT_ALPN).unwrap().1;
        assert_eq!(alpn, &[0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'][..]);
        // ALPS body: h2 only.
        let alps = &p.extensions.iter().find(|(t, _)| *t == EXT_APPLICATION_SETTINGS).unwrap().1;
        assert_eq!(alps, &[0x00, 0x03, 0x02, b'h', b'2'][..]);
        // SNI: server_name_list length, name_type, name length, then the host.
        let sni = &p.extensions.iter().find(|(t, _)| *t == EXT_SERVER_NAME).unwrap().1;
        assert_eq!(&sni[..2], &[0x00, 0x12]);
        assert_eq!(sni[2], 0x00);
        assert_eq!(&sni[3..5], &[0x00, 0x0f]);
        assert_eq!(&sni[5..], b"www.example.com");
        // compress_certificate: brotli.
        let cc = &p.extensions.iter().find(|(t, _)| *t == EXT_COMPRESS_CERTIFICATE).unwrap().1;
        assert_eq!(cc, &[0x02, 0x00, 0x02], "brotli, byte-counted list");
    }

    #[test]
    fn chrome_padding_hits_the_boring_block_size() {
        let (random, sid, key) = fixed();
        for sni in ["www.example.com", "a.test", "cdn.example.org"] {
            let hello = build_client_hello(UtslProfile::Chrome, sni, &random, &sid, &key);
            let p = parse(&hello);
            let pad = &p.extensions.last().unwrap().1;
            match boring_padding_body_len(hello.len() - 4 - pad.len()) {
                Some(n) => {
                    assert_eq!(pad.len(), n);
                    assert_eq!(hello.len(), 512, "padded to the BoringSSL block size");
                }
                None => assert!(pad.is_empty(), "no padding extension outside the window"),
            }
        }
        // The rule itself, straight from uTLS.
        assert_eq!(boring_padding_body_len(0xff), None);
        assert_eq!(boring_padding_body_len(0x100), Some(0x200 - 0x100 - 4));
        assert_eq!(boring_padding_body_len(0x1ff), Some(1));
        assert_eq!(boring_padding_body_len(0x200), None);
    }

    #[test]
    fn chrome_extension_shuffle_is_deterministic_and_complete() {
        let (random, sid, key) = fixed();
        let a = build_client_hello(UtslProfile::Chrome, "www.example.com", &random, &sid, &key);
        let b = build_client_hello(UtslProfile::Chrome, "www.example.com", &random, &sid, &key);
        assert_eq!(a, b, "same random => same bytes");

        // A different random keeps the pinned GREASE slots but may permute the
        // middle block: the extension multiset must survive the shuffle.
        let mut other = random;
        other[0] = 0xff;
        let c = build_client_hello(UtslProfile::Chrome, "www.example.com", &other, &sid, &key);
        let norm = |v: u16| {
            if v >> 8 == v & 0xff && v & 0x0f == 0x0a {
                GREASE
            } else {
                v
            }
        };
        let exts_a = parse(&a).extensions;
        let exts_c = parse(&c).extensions;
        let mut sa: Vec<u16> = exts_a.iter().map(|(t, _)| norm(*t)).collect();
        let mut sc: Vec<u16> = exts_c.iter().map(|(t, _)| norm(*t)).collect();
        sa.sort_unstable();
        sc.sort_unstable();
        assert_eq!(sa, sc, "same extension set (GREASE normalized)");
        assert_ne!(grease_values(&random).extension1, grease_values(&other).extension1);
        assert_eq!(
            exts_c[0].0,
            grease_values(&other).extension1,
            "GREASE leads the changed hello"
        );
        assert_eq!(exts_a[0].0, grease_values(&random).extension1);
    }

    #[test]
    fn firefox_shape_has_no_grease_and_the_parrot_order() {
        let (random, sid, key) = fixed();
        let hello = build_client_hello(UtslProfile::Firefox, "www.example.com", &random, &sid, &key);
        let p = parse(&hello);
        assert_eq!(p.legacy_version, VERSION_TLS12);
        assert_eq!(p.session_id.len(), 32);
        assert_eq!(p.suites, UtslProfile::Firefox.cipher_suites());
        let types: Vec<u16> = p.extensions.iter().map(|(t, _)| *t).collect();
        assert_eq!(types, UtslProfile::Firefox.extension_template().to_vec());
        assert!(
            !types.iter().any(|t| *t >> 8 == *t & 0xff && *t & 0x0f == 0x0a),
            "Firefox does not GREASE"
        );
        // X25519-only key share.
        let ks = &p.extensions.iter().find(|(t, _)| *t == EXT_KEY_SHARE).unwrap().1;
        assert_eq!(u16_at(ks, 2), GROUP_X25519);
        assert_eq!(u16_at(ks, 4), 32);
        assert_eq!(ks.len(), 2 + 4 + 32, "no second share");
        // delegated_credentials and encrypted_client_hello are not offered.
        assert!(!types.contains(&0x0022));
        assert!(!types.contains(&0xfe0d));
        let rsl = &p.extensions.iter().find(|(t, _)| *t == EXT_RECORD_SIZE_LIMIT).unwrap().1;
        assert_eq!(rsl, &[0x40, 0x01]);
        let sv = &p.extensions.iter().find(|(t, _)| *t == EXT_SUPPORTED_VERSIONS).unwrap().1;
        assert_eq!(sv, &[0x04, 0x03, 0x04, 0x03, 0x03]);
    }

    #[test]
    fn alpn_override_replaces_the_template_list() {
        let (random, sid, key) = fixed();
        let hello = build_client_hello_alpn(
            UtslProfile::Chrome,
            "x.test",
            &random,
            &sid,
            &key,
            Some(&["http/1.1".to_string()]),
        );
        let p = parse(&hello);
        let alpn = &p.extensions.iter().find(|(t, _)| *t == EXT_ALPN).unwrap().1;
        assert_eq!(
            alpn,
            &[0x00, 0x09, 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'][..]
        );
    }

    #[test]
    fn grease_values_are_the_rfc8701_reserved_set() {
        let check = |v: u16| {
            let w = (v >> 12) & 0x0f;
            assert_eq!(v, (w << 12) | 0x0a00 | (w << 4) | 0x0a, "{v:#06x}");
            assert_eq!(v >> 8, v & 0xff, "both octets are 0x{w}a");
        };
        for n in 0..64u8 {
            let mut random = [0u8; 32];
            random[0] = n;
            random[31] = n.wrapping_mul(7);
            let g = grease_values(&random);
            for v in [g.cipher, g.group, g.extension1, g.extension2, g.version] {
                check(v);
            }
            assert_ne!(g.extension1, g.extension2);
            assert_eq!(grease_values(&random), g, "deterministic");
        }
        assert_eq!(grease_values(&[0u8; 32]), grease_values(&[0u8; 32]));
    }

    #[test]
    fn profile_names_parse_like_mihomo() {
        assert_eq!(UtslProfile::parse("Chrome"), Some(UtslProfile::Chrome));
        assert_eq!(UtslProfile::parse("firefox "), Some(UtslProfile::Firefox));
        assert_eq!(UtslProfile::parse("random"), None);
        assert_eq!(UtslProfile::Chrome.as_str(), "chrome");
    }

    #[test]
    fn pinned_structure_seed_swaps_only_the_random() {
        // JLS' stamping contract (mihomo transport/jls/utls.go:70-101): the
        // hello is built once, the random is replaced, and everything else —
        // GREASE values, shuffle, padding — must stay byte-identical, so the
        // random-zeroed authData of the two passes is the same message.
        let (random, sid, key) = fixed();
        let mut fake = [0x5au8; 32];
        fake[31] = 0x01;
        for profile in [UtslProfile::Chrome, UtslProfile::Firefox] {
            let pass1 = build_client_hello_opts(
                profile, "www.example.com", &random, &sid, &key, None, None, true,
            );
            let pass2 = build_client_hello_opts(
                profile,
                "www.example.com",
                &fake,
                &sid,
                &key,
                None,
                Some(&random),
                true,
            );
            assert_eq!(pass1.len(), pass2.len(), "{profile:?}");
            assert_eq!(&pass1[..6], &pass2[..6], "{profile:?}");
            assert_eq!(&pass1[38..], &pass2[38..], "{profile:?}");
            assert_eq!(&pass2[6..38], &fake[..], "{profile:?}");
            assert_eq!(&pass1[6..38], &random[..], "{profile:?}");
        }
    }

    #[test]
    fn alps_is_droppable_and_alpn_override_pins_the_list() {
        let (random, sid, key) = fixed();
        let http1 = vec!["http/1.1".to_string()];
        let hello = build_client_hello_opts(
            UtslProfile::Chrome,
            "x.test",
            &random,
            &sid,
            &key,
            Some(&http1),
            None,
            false,
        );
        let p = parse(&hello);
        let types: Vec<u16> = p.extensions.iter().map(|(t, _)| *t).collect();
        // overrideUTLSALPN (utls.go:222-231): no h2 in the list → ALPS (0x4469)
        // is dropped from the template.
        assert!(!types.contains(&EXT_APPLICATION_SETTINGS));
        let alpn = &p.extensions.iter().find(|(t, _)| *t == EXT_ALPN).unwrap().1;
        assert_eq!(
            alpn,
            &[0x00, 0x09, 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'][..]
        );
        // Default knobs reproduce build_client_hello_alpn exactly.
        assert_eq!(
            build_client_hello_opts(
                UtslProfile::Chrome,
                "x.test",
                &random,
                &sid,
                &key,
                Some(&http1),
                None,
                true,
            ),
            build_client_hello_alpn(UtslProfile::Chrome, "x.test", &random, &sid, &key, Some(&http1))
        );
    }
}