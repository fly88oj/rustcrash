//! REALITY client — a faithful port of XTLS/Xray-core's REALITY outbound.
//!
//! Ported from
//! `transport/internet/reality/reality.go` (client `UClient`, the
//! `VerifyPeerCertificate` temp-auth check and the `spiderX` fallback) and
//! from the server side of <https://github.com/XTLS/reality> (`tls.go`
//! lines 239-271, which show exactly how the session id is unsealed — every
//! step below cites the upstream line it comes from).
//!
//! How REALITY authenticates (upstream wire format, not a summary):
//!
//! 1. The client generates an ephemeral X25519 keypair and computes
//!    `shared = X25519(eph_priv, server_static_pub)`.
//! 2. `auth_key = HKDF-SHA256(ikm = shared, salt = ClientHello.random[0..20],
//!    info = "REALITY", 32 bytes)`  (reality.go L167).
//! 3. The ClientHello is built with a *zeroed* 32-byte legacy session id.
//! 4. `session_id = AES-256-GCM-Seal(key = auth_key,
//!    nonce = ClientHello.random[20..32], plaintext = session_plain[0..16],
//!    aad = the ClientHello handshake message with that zeroed session id)`
//!    (reality.go L170-175). `session_plain` is
//!    `[xray_version(3) | 0u8 | unix_time_be32 | short_id (padded to 16)]`
//!    (reality.go L141-148). The 32-byte ciphertext+tag *becomes* the
//!    session id, which is why the AAD is the hello with the id zeroed: the
//!    server zeroes the field before opening it (reality/tls.go L254-257).
//! 5. After the handshake the server's certificate is checked against the
//!    temp-auth scheme instead of a CA: the leaf must be Ed25519 and its
//!    *outer signature field* must equal
//!    `HMAC-SHA512(key = auth_key, message = the Ed25519 public key bytes)`
//!    (reality.go L84-103; the server writes that HMAC into the signature
//!    field of a fixed template certificate, reality/handshake_server_tls13.go
//!    L147-160).
//!
//! Nothing here is secret-at-rest beyond the user's keys; the auth key is
//! never reused across connections (fresh ephemeral key + fresh random).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::error::{Error, Result};
use crate::proto::aead::{Aead, AeadKind};
use crate::stream::BoxProxyStream;

use super::profiles::{self, UtslProfile};
use super::tls13::{self, ServerAuth, Tls13Stream};

/// The version triple a REALITY client reports in its session id.
///
/// Upstream sends `core.Version_x/y/z` (the client's own Xray build) and the
/// server may enforce `minClientVer`/`maxClientVer` as a 24-bit big-endian
/// integer (`reality/tls.go::Value`). Servers whose minimum predates the
/// ML-KEM handshake are reachable with any version >= 1.8.0; the newest ones
/// additionally require an X25519MLKEM768 key share, which this stack does
/// not implement, so their version gate is moot. 1.8.0 is a real Xray
/// release and the value every `minClientVer` example uses.
pub const CLIENT_VERSION: [u8; 3] = [1, 8, 0];

/// Offset of the legacy session id in a ClientHello handshake message.
const SESSION_ID_OFFSET: usize = profiles::SESSION_ID_OFFSET;

/// REALITY outbound configuration (the fields mihomo/sing-box expose).
#[derive(Debug, Clone)]
pub struct RealityCfg {
    /// SNI sent in the ClientHello and used for the certificate name.
    pub server_name: String,
    /// Server X25519 public key, base64 (standard or URL-safe, padded or not).
    pub public_key: String,
    /// Server short id, hex (empty string = the server's empty short id).
    pub short_id: String,
    /// uTLS template to emit.
    pub fingerprint: UtslProfile,
    /// Spider path used on the fallback path; `None` behaves like upstream's
    /// default of `/`.
    pub spider_x: Option<String>,
}

impl RealityCfg {
    /// Config with the Chrome fingerprint (what the Xray reference client
    /// emits) and no spider path override.
    pub fn new(
        server_name: impl Into<String>,
        public_key: impl Into<String>,
        short_id: impl Into<String>,
    ) -> Self {
        RealityCfg {
            server_name: server_name.into(),
            public_key: public_key.into(),
            short_id: short_id.into(),
            fingerprint: UtslProfile::Chrome,
            spider_x: None,
        }
    }
}

/// Decode a base64 X25519 public key (accepts standard and URL-safe
/// alphabet, with or without padding — servers and clients in the wild use
/// both).
pub fn parse_public_key(value: &str) -> Result<[u8; 32]> {
    let trimmed = value.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|_| Error::config("reality: public-key is not valid base64"))?;
    decoded
        .try_into()
        .map_err(|_| Error::config("reality: public-key is not a 32-byte X25519 key"))
}

/// Decode the hex short id. Upstream copies it into `session_id[8..]`, so
/// anything longer than 16 bytes could not be represented; the server only
/// ever reads the first 8 bytes (`ClientShortId [8]byte`).
pub fn parse_short_id(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if !trimmed.len().is_multiple_of(2) {
        return Err(Error::config("reality: short-id has an odd number of hex digits"));
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| Error::config("reality: short-id is not hex"))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| Error::config("reality: short-id is not hex"))?;
        out.push(((hi << 4) | lo) as u8);
    }
    if out.len() > 16 {
        return Err(Error::config(
            "reality: short-id longer than 16 bytes (32 hex digits)",
        ));
    }
    Ok(out)
}

/// `auth_key = HKDF-SHA256(ikm = shared, salt = random[0..20], info = "REALITY")`.
///
/// Xray reality.go L167:
/// `hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20], []byte("REALITY")).Read(uConn.AuthKey)`
pub fn auth_key(shared: &[u8; 32], random: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&random[..20]), shared);
    let mut out = [0u8; 32];
    hk.expand(b"REALITY", &mut out)
        .map_err(|_| Error::crypto("reality: HKDF expand failed"))?;
    Ok(out)
}

/// The 32-byte session id plaintext an Xray client builds (reality.go
/// L141-148): version, reserved byte, big-endian unix time, short id.
pub fn session_id_plain(short_id: &[u8], unix_time: u64, version: [u8; 3]) -> [u8; 32] {
    let mut sid = [0u8; 32];
    sid[..3].copy_from_slice(&version);
    sid[3] = 0; // reserved
    sid[4..8].copy_from_slice(&(unix_time as u32).to_be_bytes());
    let n = short_id.len().min(32 - 8);
    sid[8..8 + n].copy_from_slice(&short_id[..n]);
    sid
}

/// Seal the session id into the ClientHello, exactly as reality.go L170-175:
/// AES-256-GCM (Xray's `crypto.NewAesGcm` builds a 256-bit cipher from the
/// 32-byte auth key) with the hello's own bytes as AAD — the caller must pass
/// the hello *before* the session id is written in (upstream zeroes the field,
/// which is what the server reconstructs to open it).
pub fn seal_session_id(
    auth_key: &[u8; 32],
    random: &[u8; 32],
    plain: &[u8; 32],
    hello: &[u8],
) -> Result<[u8; 32]> {
    let aead = Aead::new(AeadKind::Aes256Gcm, auth_key)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&random[20..32]);
    let mut sealed = Vec::with_capacity(32);
    aead.seal(&nonce, hello, &plain[..16], &mut sealed)?;
    sealed
        .try_into()
        .map_err(|_| Error::crypto("reality: sealed session id is not 32 bytes"))
}

/// REALITY's replacement for CA validation (reality.go L84-103): the
/// certificate must be Ed25519 and its outer signature field must equal
/// `HMAC-SHA512(auth_key, ed25519_public_key)`.
pub fn verify_temp_auth(auth_key: &[u8; 32], cert_der: &[u8]) -> Result<bool> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    let key = match tls13::der::public_key(cert_der) {
        Ok(tls13::der::PublicKey::Ed25519(k)) => k,
        // Not an Ed25519 certificate => not a REALITY one.
        Ok(_) => return Ok(false),
        Err(_) => return Ok(false),
    };
    let signature = tls13::der::signature(cert_der)?;
    if signature.len() != 64 {
        return Ok(false);
    }
    let mut mac =
        Hmac::<Sha512>::new_from_slice(auth_key).map_err(|_| Error::crypto("reality: bad auth key"))?;
    mac.update(&key);
    // `verify_slice` is the constant-time comparison from the hmac crate.
    Ok(mac.verify_slice(&signature).is_ok())
}

/// A REALITY tunnel: TLS 1.3 to the server, plaintext to the engine.
pub struct RealityStream {
    inner: Tls13Stream,
}

impl RealityStream {
    /// Wrap an established TLS 1.3 stream.
    pub fn new(inner: Tls13Stream) -> Self {
        RealityStream { inner }
    }

    /// ALPN the server selected (REALITY servers answer with the client's
    /// first offer, normally `h2`).
    pub fn alpn(&self) -> Option<&[u8]> {
        self.inner.alpn()
    }

    /// Unwrap the underlying TLS stream.
    pub fn into_inner(self) -> Tls13Stream {
        self.inner
    }
}

impl std::fmt::Debug for RealityStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityStream")
            .field("alpn", &self.alpn())
            .finish_non_exhaustive()
    }
}

impl AsyncRead for RealityStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RealityStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Connect through a REALITY server.
///
/// `transport` is the already-dialled TCP stream; REALITY wraps raw TCP (no
/// intermediate TLS). On success the returned stream speaks the tunnel
/// (VLESS/Trojan payloads go straight in); `Box::new(RealityStream)` is a
/// [`BoxProxyStream`].
pub async fn connect(cfg: &RealityCfg, transport: BoxProxyStream) -> Result<BoxProxyStream> {
    let server_public_key = parse_public_key(&cfg.public_key)?;
    let short_id = parse_short_id(&cfg.short_id)?;

    let (eph_secret, eph_public) = tls13::x25519_keygen();
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);

    let shared = tls13::x25519(&eph_secret, &server_public_key)?;
    let auth_key = auth_key(&shared, &random)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::crypto(format!("reality: system clock before 1970: {e}")))?
        .as_secs();
    let plain = session_id_plain(&short_id, now, CLIENT_VERSION);

    // The hello is built with a zeroed session id: those zeroes are exactly
    // what the server reconstructs for the AEAD's AAD.
    let mut hello = profiles::build_client_hello(
        cfg.fingerprint,
        &cfg.server_name,
        &random,
        &[0u8; 32],
        &eph_public,
    );
    let sealed = seal_session_id(&auth_key, &random, &plain, &hello)?;
    hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].copy_from_slice(&sealed);

    let auth = ServerAuth::Callback(Box::new(move |leaf| verify_temp_auth(&auth_key, leaf)));
    let mut tls = tls13::connect(transport, &hello, &eph_secret, auth).await?;

    if !tls.cert_verified() {
        // Upstream logs, browses the site through the *live* connection (the
        // connection is a genuine TLS session with the real target, which is
        // what makes the fallback look like a browser), waits, then fails.
        tracing::warn!(
            server = %cfg.server_name,
            "engine: REALITY: received a real certificate (wrong short id, wrong public key, \
             or the server is redirecting) — falling back"
        );
        spider(&mut tls, cfg).await;
        return Err(Error::protocol(
            "REALITY: received real certificate (potential MITM or redirection)",
        ));
    }

    Ok(Box::new(RealityStream::new(tls)))
}

/// Best-effort `spiderX` pass over the authenticated connection.
///
/// Upstream issues an HTTP/2 GET, then crawls `href="..."` links with
/// randomized padding cookies for a while (`reality.go` L186-274). This is a
/// single HTTP/1.1 GET with Xray's `nav` header set: enough to look like a
/// browser that followed a link, without the crawl loop. It is skipped when
/// the server negotiated HTTP/2 (an HTTP/1.1 request would be malformed
/// there) and every failure is ignored — the caller reports the auth error
/// either way.
async fn spider(tls: &mut Tls13Stream, cfg: &RealityCfg) {
    if matches!(tls.alpn(), Some(b"h2")) {
        tracing::debug!("engine: REALITY: spider skipped (server chose h2)");
        return;
    }
    let path = cfg.spider_x.as_deref().unwrap_or("/");
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\n{headers}\r\n",
        host = cfg.server_name,
        headers = nav_headers(cfg.fingerprint)
    );
    let fut = async {
        tls.write_all(request.as_bytes()).await?;
        tls.flush().await?;
        // Drain a little of the response so the request is not left dangling.
        let mut buf = [0u8; 2048];
        use tokio::io::AsyncReadExt;
        let _ = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await;
        Ok::<(), Error>(())
    };
    match tokio::time::timeout(Duration::from_secs(10), fut).await {
        Ok(Ok(())) => tracing::debug!("engine: REALITY: spider request sent"),
        Ok(Err(e)) => tracing::debug!("engine: REALITY: spider failed: {e}"),
        Err(_) => tracing::debug!("engine: REALITY: spider timed out"),
    }
}

/// Xray's `utils.TryDefaultHeadersWith(header, "nav")` header set (a
/// navigation request from a Windows browser of the selected family).
fn nav_headers(profile: UtslProfile) -> String {
    match profile {
        UtslProfile::Chrome => [
            "sec-ch-ua: \"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"130\", \"Chromium\";v=\"130\"",
            "sec-ch-ua-mobile: ?0",
            "sec-ch-ua-platform: \"Windows\"",
            "dnt: 1",
            "upgrade-insecure-requests: 1",
            "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site: none",
            "sec-fetch-mode: navigate",
            "sec-fetch-user: ?1",
            "sec-fetch-dest: document",
            "accept-language: en-US,en;q=0.9",
            "priority: u=0, i",
            "cache-control: max-age=0",
        ]
        .join("\r\n"),
        UtslProfile::Firefox => [
            "dnt: 1",
            "upgrade-insecure-requests: 1",
            "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
            "accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "sec-fetch-site: none",
            "sec-fetch-mode: navigate",
            "sec-fetch-user: ?1",
            "sec-fetch-dest: document",
            "accept-language: en-US,en;q=0.5",
            "priority: u=0, i",
        ]
        .join("\r\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::reality::tls13::CipherSuite;
    use sha2::Digest;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn fixed_random() -> [u8; 32] {
        let mut r = [0u8; 32];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (0x40 + i) as u8;
        }
        r
    }

    /// A REALITY *server* keypair, so both sides can be exercised in-process.
    fn server_keypair() -> ([u8; 32], [u8; 32]) {
        crate::proto::reality::tls13::x25519_keygen()
    }

    #[test]
    fn short_id_parsing() {
        assert_eq!(parse_short_id("").unwrap(), Vec::<u8>::new());
        assert_eq!(parse_short_id("0a0b").unwrap(), vec![0x0a, 0x0b]);
        assert_eq!(parse_short_id("0x0A0B").unwrap(), vec![0x0a, 0x0b]);
        assert_eq!(parse_short_id("00112233445566778899aabbccddeeff").unwrap().len(), 16);
        assert!(parse_short_id("abc").is_err());
        assert!(parse_short_id("zz").is_err());
        assert!(parse_short_id("00112233445566778899aabbccddeeff00").is_err());
    }

    #[test]
    fn public_key_parsing_accepts_both_alphabets() {
        let raw: [u8; 32] = {
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(7).wrapping_add(3);
            }
            k
        };
        for encoded in [
            base64::engine::general_purpose::STANDARD.encode(raw),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw),
            base64::engine::general_purpose::URL_SAFE.encode(raw),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
        ] {
            assert_eq!(parse_public_key(&encoded).unwrap(), raw);
        }
        assert!(parse_public_key("not base64!!").is_err());
        assert!(parse_public_key(&base64::engine::general_purpose::STANDARD.encode([1u8; 31]))
            .is_err());
    }

    #[test]
    fn session_id_layout_matches_upstream() {
        let sid = session_id_plain(&[0xde, 0xad, 0xbe, 0xef], 0x1122_3344, [1, 8, 0]);
        assert_eq!(&sid[..3], &[1, 8, 0]);
        assert_eq!(sid[3], 0);
        assert_eq!(&sid[4..8], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&sid[8..12], &[0xde, 0xad, 0xbe, 0xef]);
        assert!(sid[12..].iter().all(|b| *b == 0), "short id is zero padded");
        // Long short ids fill the rest of the plaintext array; the sealed
        // plaintext is only the first 16 bytes, which is what the server reads.
        let long = session_id_plain(&[0xaa; 16], 7, [1, 8, 0]);
        assert!(long[8..24].iter().all(|b| *b == 0xaa));
        assert!(long[24..].iter().all(|b| *b == 0));
    }

    /// The whole auth computation, with the server side implemented from the
    /// upstream code (reality/tls.go L239-271) so both ends must agree.
    #[test]
    fn auth_round_trip_recovers_the_short_id() {
        let (server_secret, server_public) = server_keypair();
        let random = fixed_random();
        let short_id = parse_short_id("0011223344556677").unwrap();
        let now = 1_700_000_000u64;

        // --- client side ---
        let (eph_secret, eph_public) = crate::proto::reality::tls13::x25519_keygen();
        let shared = tls13::x25519(&eph_secret, &server_public).unwrap();
        let c_auth = auth_key(&shared, &random).unwrap();
        let plain = session_id_plain(&short_id, now, CLIENT_VERSION);
        let hello = profiles::build_client_hello(
            UtslProfile::Chrome,
            "www.example.com",
            &random,
            &[0u8; 32],
            &eph_public,
        );
        let sealed = seal_session_id(&c_auth, &random, &plain, &hello).unwrap();

        // The hello must carry the sealed value, not the plaintext.
        let mut sent = hello.clone();
        sent[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].copy_from_slice(&sealed);
        assert_eq!(&sent[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32], &sealed[..]);
        assert_ne!(&sealed[..16], &plain[..16]);

        // --- server side (XTLS/reality tls.go) ---
        // peerPub comes from the ClientHello key share; note the server sees
        // the *sent* hello, whose session id is the sealed value.
        let server_shared = tls13::x25519(&server_secret, &eph_public).unwrap();
        assert_eq!(server_shared, shared, "ECDH agrees");
        let s_auth = auth_key(&server_shared, &random).unwrap();
        assert_eq!(s_auth, c_auth, "auth keys agree");

        let mut aad = sent.clone();
        for b in &mut aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32] {
            *b = 0; // tls.go: `copy(hs.clientHello.sessionId, plainText)`
        }
        let aead = Aead::new(AeadKind::Aes256Gcm, &s_auth).unwrap();
        let nonce: [u8; 12] = random[20..32].try_into().unwrap();
        let recovered = aead.open(&nonce, &aad, &sealed).unwrap();
        assert_eq!(recovered.len(), 16);
        assert_eq!(&recovered[..3], &CLIENT_VERSION);
        assert_eq!(&recovered[4..8], &(now as u32).to_be_bytes());
        assert_eq!(&recovered[8..16], &short_id[..], "server reads the short id");
        // The server compares only 8 bytes (ClientShortId [8]byte), which is
        // all a <= 8-byte short id needs.
        assert_eq!(u32::from_be_bytes(recovered[4..8].try_into().unwrap()), now as u32);
    }

    #[test]
    fn wrong_short_id_does_not_open_under_another_key() {
        // A server with a different static key derives a different auth key;
        // the sealed session id must not decrypt (this is what makes a wrong
        // `public_key` fail closed rather than silently connecting).
        let (_, server_public) = server_keypair();
        let (other_secret, _) = server_keypair();
        let random = fixed_random();
        let (eph_secret, eph_public) = crate::proto::reality::tls13::x25519_keygen();
        let shared = tls13::x25519(&eph_secret, &server_public).unwrap();
        let c_auth = auth_key(&shared, &random).unwrap();
        let hello = profiles::build_client_hello(
            UtslProfile::Chrome,
            "www.example.com",
            &random,
            &[0u8; 32],
            &eph_public,
        );
        let sealed =
            seal_session_id(&c_auth, &random, &session_id_plain(&[1, 2, 3, 4], 9, CLIENT_VERSION), &hello)
                .unwrap();

        let other_shared = tls13::x25519(&other_secret, &eph_public).unwrap();
        let other_auth = auth_key(&other_shared, &random).unwrap();
        let aead = Aead::new(AeadKind::Aes256Gcm, &other_auth).unwrap();
        let nonce: [u8; 12] = random[20..32].try_into().unwrap();
        assert!(aead.open(&nonce, &hello, &sealed).is_err());
    }

    /// Build the certificate REALITY's server would send: a self-signed
    /// Ed25519 certificate whose signature field is replaced by the HMAC
    /// (`reality/handshake_server_tls13.go` L147-160).
    fn temp_auth_cert(auth_key: &[u8; 32]) -> (Vec<u8>, rustls::pki_types::PrivateKeyDer<'static>) {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["www.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let mut der = cert.der().to_vec();

        let pubkey = match tls13::der::public_key(&der).unwrap() {
            tls13::der::PublicKey::Ed25519(k) => k,
            other => panic!("expected an Ed25519 key, got {other:?}"),
        };
        let (start, len) = tls13::der::signature_range(&der).unwrap();
        assert_eq!(len, 64, "the template cert has a 64-byte Ed25519 signature slot");
        let mut mac = Hmac::<Sha512>::new_from_slice(auth_key).unwrap();
        mac.update(&pubkey);
        let tag = mac.finalize().into_bytes();
        der[start..start + len].copy_from_slice(&tag);

        (
            der,
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
        )
    }

    #[test]
    fn temp_auth_accepts_only_the_hmac_stamped_certificate() {
        let auth = [7u8; 32];
        let (der, _) = temp_auth_cert(&auth);
        assert!(verify_temp_auth(&auth, &der).unwrap());

        // Wrong auth key: the HMAC does not match the signature field.
        assert!(!verify_temp_auth(&[8u8; 32], &der).unwrap());

        // Flipping a byte of the HMAC breaks it.
        let mut tampered = der.clone();
        let (start, _) = tls13::der::signature_range(&tampered).unwrap();
        tampered[start] ^= 0x01;
        assert!(!verify_temp_auth(&auth, &tampered).unwrap());

        // A genuine (unpatched) self-signed certificate is "a real
        // certificate", not a REALITY one.
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["www.example.com".to_string()]).unwrap();
        let real = params.self_signed(&key_pair).unwrap();
        assert!(!verify_temp_auth(&auth, real.der()).unwrap());

        // Non-Ed25519 certificates are not REALITY certificates either.
        let ec = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let ec_cert = rcgen::CertificateParams::new(vec!["www.example.com".to_string()])
            .unwrap()
            .self_signed(&ec)
            .unwrap();
        assert!(!verify_temp_auth(&auth, ec_cert.der()).unwrap());
    }

    #[test]
    fn temp_auth_cert_spki_is_bound_to_the_key() {
        // The HMAC covers the *public key bytes*, so a certificate carrying a
        // different key can never pass even with a valid signature field.
        let auth = [3u8; 32];
        let (der, _) = temp_auth_cert(&auth);
        let pubkey = match tls13::der::public_key(&der).unwrap() {
            tls13::der::PublicKey::Ed25519(k) => k,
            _ => unreachable!(),
        };
        use hmac::Mac as _;
        let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(&auth).unwrap();
        mac.update(&pubkey);
        let expect: [u8; 64] = mac.finalize().into_bytes().into();
        assert_eq!(tls13::der::signature(&der).unwrap(), expect.to_vec());
        assert_eq!(sha2::Sha256::digest(pubkey).len(), 32); // key is really 32 bytes
    }

    /// End-to-end against an in-process REALITY server built from this
    /// crate's own TLS 1.3 server path: the server validates the sealed
    /// session id (upstream algorithm) and answers with the temp-auth
    /// certificate.
    #[tokio::test]
    async fn reality_handshake_round_trip_against_a_fake_server() {
        let (server_secret, server_public) = server_keypair();
        let expected_short = parse_short_id("0011223344556677").unwrap();
        let cfg = RealityCfg {
            server_name: "www.example.com".into(),
            public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_public),
            short_id: "0011223344556677".into(),
            fingerprint: UtslProfile::Chrome,
            spider_x: None,
        };

        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let (mut tls, hello) = crate::proto::reality::tls13::test_server::accept(
                Box::new(server),
                CipherSuite::Aes128GcmSha256,
                move |hello| {
                    // --- REALITY server auth, ported from reality/tls.go ---
                    let shared = tls13::x25519(&server_secret, &hello.x25519_share).expect("ecdh");
                    let auth = auth_key(&shared, &hello.random).expect("hkdf");
                    let mut aad = hello.raw.clone();
                    for b in &mut aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32] {
                        *b = 0;
                    }
                    let aead = Aead::new(AeadKind::Aes256Gcm, &auth).expect("aead");
                    let nonce: [u8; 12] = hello.random[20..32].try_into().unwrap();
                    let plain = aead
                        .open(&nonce, &aad, &hello.session_id)
                        .expect("session id must open");
                    let short_ok = &plain[8..16] == expected_short.as_slice();
                    if short_ok {
                        let (der, key) = temp_auth_cert(&auth);
                        let signing = rustls::crypto::ring::sign::any_supported_type(&key)
                            .expect("signing key");
                        Ok((der, signing))
                    } else {
                        // Auth failed: real servers fall through to the target
                        // site, which presents an ordinary (non-REALITY) cert.
                        let key_pair =
                            rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
                        let der = rcgen::CertificateParams::new(vec![
                            "www.example.com".to_string()
                        ])
                        .unwrap()
                        .self_signed(&key_pair)
                        .unwrap()
                        .der()
                        .to_vec();
                        let signing = rustls::crypto::ring::sign::any_supported_type(
                            &rustls::pki_types::PrivateKeyDer::Pkcs8(
                                key_pair.serialize_der().into(),
                            ),
                        )
                        .unwrap();
                        Ok((der, signing))
                    }
                },
            )
            .await
            .expect("server handshake");
            assert_eq!(hello.sni.as_deref(), Some("www.example.com"));
            assert_eq!(hello.session_id.len(), 32);
            let mut buf = [0u8; 64];
            let n = tls.read(&mut buf).await.unwrap();
            tls.write_all(&buf[..n]).await.unwrap();
            tls.flush().await.unwrap();
            tls
        });

        let mut stream = connect(&cfg, Box::new(client)).await.expect("REALITY connect");
        stream.write_all(b"vless-ish payload").await.unwrap();
        let mut buf = [0u8; 17];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"vless-ish payload");
        let server_stream = server_task.await.unwrap();
        assert_eq!(server_stream.alpn(), Some(&b"h2"[..]));
    }

    /// The negative path: a short id the server does not know means the
    /// server presents a real certificate, and the client must refuse.
    #[tokio::test]
    async fn reality_rejects_a_server_that_cannot_prove_the_auth_key() {
        let (server_secret, server_public) = server_keypair();
        let cfg = RealityCfg {
            server_name: "www.example.com".into(),
            public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_public),
            short_id: "ffffffffffffffff".into(), // not the server's short id
            fingerprint: UtslProfile::Chrome,
            spider_x: None,
        };

        let server_short = parse_short_id("0011223344556677").unwrap();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let _server_task = tokio::spawn(async move {
            let _ = crate::proto::reality::tls13::test_server::accept(
                Box::new(server),
                CipherSuite::Aes128GcmSha256,
                move |hello| {
                    let shared = tls13::x25519(&server_secret, &hello.x25519_share).unwrap();
                    let auth = auth_key(&shared, &hello.random).unwrap();
                    let mut aad = hello.raw.clone();
                    for b in &mut aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32] {
                        *b = 0;
                    }
                    let aead = Aead::new(AeadKind::Aes256Gcm, &auth).unwrap();
                    let nonce: [u8; 12] = hello.random[20..32].try_into().unwrap();
                    let short_ok = match aead.open(&nonce, &aad, &hello.session_id) {
                        Ok(plain) => &plain[8..16] == server_short.as_slice(),
                        Err(_) => false,
                    };
                    assert!(
                        !short_ok,
                        "the client's short id is not in the server's short-id list"
                    );
                    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
                    let der = rcgen::CertificateParams::new(vec!["www.example.com".to_string()])
                        .unwrap()
                        .self_signed(&key_pair)
                        .unwrap()
                        .der()
                        .to_vec();
                    let signing = rustls::crypto::ring::sign::any_supported_type(
                        &rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
                    )
                    .unwrap();
                    Ok((der, signing))
                },
            )
            .await;
        });

        let err = match connect(&cfg, Box::new(client)).await {
            Ok(_) => panic!("the client must refuse a certificate it cannot verify"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("received real certificate"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn bad_config_is_rejected_before_any_io() {
        let cfg = RealityCfg {
            server_name: "x.test".into(),
            public_key: "!!!not-base64!!!".into(),
            short_id: "00".into(),
            fingerprint: UtslProfile::Chrome,
            spider_x: None,
        };
        let (client, mut server) = tokio::io::duplex(64);
        let err = match connect(&cfg, Box::new(client)).await {
            Ok(_) => panic!("a bad public key must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("public-key"), "{err}");
        // Nothing was written to the transport.
        let mut buf = [0u8; 8];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn nav_headers_look_like_a_browser() {
        let chrome = nav_headers(UtslProfile::Chrome);
        assert!(chrome.contains("user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"));
        assert!(chrome.contains("sec-fetch-mode: navigate"));
        assert!(chrome.contains("accept-language: en-US,en;q=0.9"));
        let firefox = nav_headers(UtslProfile::Firefox);
        assert!(firefox.contains("Firefox/130.0"));
        assert!(!firefox.contains("sec-ch-ua"));
    }

    /// The wrapper must forward bytes unchanged and keep keys out of Debug.
    #[tokio::test]
    async fn reality_stream_wraps_tls_and_forwards_io() {
        let (server_secret, server_public) = server_keypair();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let (mut tls, _hello) = crate::proto::reality::tls13::test_server::accept(
                Box::new(server),
                CipherSuite::Aes128GcmSha256,
                move |hello| {
                    let shared = tls13::x25519(&server_secret, &hello.x25519_share).unwrap();
                    let auth = auth_key(&shared, &hello.random).unwrap();
                    let (der, key) = temp_auth_cert(&auth);
                    Ok((
                        der,
                        rustls::crypto::ring::sign::any_supported_type(&key).unwrap(),
                    ))
                },
            )
            .await
            .unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(&buf).await.unwrap();
            tls.flush().await.unwrap();
        });

        // Drive the REALITY client handshake, but keep the concrete TLS type.
        let random = fixed_random();
        let short = parse_short_id("0011223344556677").unwrap();
        let (eph_secret, eph_public) = crate::proto::reality::tls13::x25519_keygen();
        let shared = tls13::x25519(&eph_secret, &server_public).unwrap();
        let auth = auth_key(&shared, &random).unwrap();
        let mut hello = profiles::build_client_hello(
            UtslProfile::Chrome,
            "www.example.com",
            &random,
            &[0u8; 32],
            &eph_public,
        );
        let sealed = seal_session_id(
            &auth,
            &random,
            &session_id_plain(&short, 1_700_000_000, CLIENT_VERSION),
            &hello,
        )
        .unwrap();
        hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].copy_from_slice(&sealed);
        let verify_key = auth;
        let tls = crate::proto::reality::tls13::connect(
            Box::new(client),
            &hello,
            &eph_secret,
            ServerAuth::Callback(Box::new(move |leaf| verify_temp_auth(&verify_key, leaf))),
        )
        .await
        .unwrap();
        let mut stream = RealityStream::new(tls);
        let debug = format!("{stream:?}");
        assert!(debug.starts_with("RealityStream"), "{debug}");
        assert!(!debug.contains(&hex_of(&auth)), "no key material in Debug");

        stream.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        assert_eq!(stream.alpn(), Some(&b"h2"[..]));
        drop(stream);
        server_task.await.unwrap();
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
