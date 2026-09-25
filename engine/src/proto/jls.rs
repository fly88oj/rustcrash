//! JLS client (ShadowQUIC's "JLS" TLS camouflage + authentication layer),
//! ported source-level from mihomo `transport/jls` and metacubex/jls-tls.
//!
//! mihomo embeds `jls-opts: {username, password}` on the vless/trojan/
//! vmess/anytls outbounds (`adapter/outbound/jls.go:5-15`,
//! `adapter/outbound/trojan.go:321`, `transport/vmess/tls.go:84-90`):
//! when set, the plain TLS dial is replaced by `jls.NewClient(ctx, conn,
//! config)` (`transport/jls/jls.go:82-119`) — a genuine TLS 1.3 handshake
//! whose ClientHello **random** carries the client's credentials and whose
//! ServerHello **random** is verified the same way. After the handshake
//! the tunnel is ordinary TLS: JLS adds no post-handshake framing
//! (unlike restls).
//!
//! ## The wire, exactly as jls-tls defines it
//!
//! 1. **Key material** (`jls-tls/jls.go:138-160 jlsBuildFakeRandom`,
//!    mirrored by `transport/jls/utls.go:315-332 newJLSAEAD/jlsHash`):
//!    `nonce = SHA256(username ‖ authData)`, `key = SHA256(password ‖
//!    authData)` (both 32 bytes), AEAD = AES-256-GCM with a **32-byte
//!    nonce** (Go `cipher.NewGCMWithNonceSize(block, sha256.Size)`, so
//!    J0 = GHASH(nonce ‖ pad ‖ len) per NIST SP 800-38D §7.2; reproduced
//!    with the RustCrypto `aes-gcm` generic-nonce instantiation, which
//!    implements the identical J0 construction — byte-equality is pinned
//!    by golden vectors generated from Go in the tests).
//! 2. **fakeRandom** = `AEAD.Seal(nil, nonce, seed16, nil)` — 16 random
//!    seed bytes sealed with no AAD → 32 bytes, exactly a TLS hello
//!    random (`jls-tls/jls.go:160-171`). The seed is redrawn while the
//!    result ends with a TLS downgrade canary or the HelloRetryRequest
//!    random suffix (`jls-tls/jls.go:161-171`; canaries from Go
//!    crypto/tls, spelled out at `utls.go:33-35`: `DOWNGRD\x01`,
//!    `DOWNGRD\x00`, HRR tail `079e09e2c8a8339c`). Verification
//!    (`jlsCheckFakeRandom`, `jls-tls/jls.go:185-209`) opens the 32-byte
//!    random and requires a 16-byte plaintext.
//! 3. **ClientHello authData** (`jlsClientHelloAuthData`,
//!    `jls-tls/jls.go:258-266`; raw-wire form `jlsClientHelloWireAuthData`
//!    `jls.go:333-350` and `utls.go:243-250`): the serialized ClientHello
//!    handshake message (`type ‖ len24 ‖ body`) with the 32 random bytes
//!    at offset `4 + 2 = 6` zeroed (and any PSK binders zeroed — never
//!    present here: this client offers no sessions, exactly like
//!    mihomo's plain path which builds a fresh `tls.Config` per dial,
//!    `transport/jls/jls.go:102-111`). `applyJLSClientHelloRandom`
//!    (`jls.go:232-256`) then replaces `hello.random` with the
//!    fakeRandom computed over the seed `hello.random[:16]`.
//! 4. **ServerHello authData** (`jlsServerHelloAuthData`,
//!    `jls-tls/jls.go:287-304`; raw-wire form `utls.go:252-259`): the
//!    serialized ServerHello with the random zeroed; the client requires
//!    `jlsCheckFakeRandom(user, serverHello.random, authData)`
//!    (`authenticateJLSServerHello jls.go:268-285`; on the uTLS path the
//!    check runs in `VerifyConnection`, `utls.go:169-188`). Failure is
//!    upstream `ErrJLSAuthFailed` = `"tls: jls authentication failed"`
//!    (`jls-tls/jls.go:69`).
//!
//! ## How this port stamps the randoms (rustls mechanics)
//!
//! rustls offers no ClientHello-random hook (uTLS' `SetClientRandom` has
//! no equivalent), so the stamp uses the fixed-key-exchange + scripted
//! random machinery this crate already uses in `proto/restls.rs`, in two
//! passes:
//!
//! * A custom `SecureRandom` plus a fixed X25519 key-exchange group (the
//!   key share must be identical across passes) make the marshaled hello
//!   a deterministic function of the random draws. Pass one draws
//!   (session id 32 B, extension-order u16, client random 32 B — draw
//!   order verified against rustls-0.23.37 `src/client/hs.rs:96-133`,
//!   where `SessionId::random` `msgs/handshake.rs:170-174` and
//!   `Random::new` both fill via the provider) and its flight is
//!   inspected to compute `authData` + `fakeRandom`; pass two replays
//!   every draw verbatim except the client random, which becomes the
//!   fakeRandom. rustls hashes the *stamped* hello into its own
//!   transcript, so client and server transcripts stay consistent — no
//!   post-hoc patching. The two flights are verified byte-equal outside
//!   the random before anything is sent.
//! * The ServerHello is verified by intercepting the first server record
//!   in the handshake drive loop (the drive-over-records pattern of
//!   `proto/restls.rs`).
//!
//! ## Scope and deviations
//!
//! * **uTLS fingerprints** (`client-fingerprint`,
//!   `transport/jls/utls.go`): ported — see "The fingerprint path" below.
//!   When [`JlsOut::fingerprint`] is set, the cover ClientHello is the
//!   Chrome/Firefox template from `proto/reality/profiles.rs` (uTLS
//!   `HelloChrome_120` / `HelloFirefox_120` parrots) instead of rustls'
//!   own hello, and the TLS 1.3 session runs on the engine's own record
//!   stack (`proto/reality/tls13.rs`) so the JLS stamping happens on hello
//!   bytes we fully control. Without a fingerprint the plain rustls
//!   two-pass path above runs (mihomo's non-uTLS branch,
//!   `transport/jls/jls.go:95-119`).
//! * **Server-side JLS / fallback relay** (`transport/jls/jls.go:176-197
//!   Server`, rate limiter `jls.go:226-336`, handshake recorder
//!   `jls.go:338-389`): listener-side; out of scope for an outbound
//!   engine. The loopback tests transcribe the server-side checks
//!   (`authenticateJLSClientHello`, `jls-tls/jls.go:306-331`) instead.
//! * **0-RTT / session tickets**: never offered (resumption disabled;
//!   the JLS session marker `jls-tls/jls.go:84-121` is a client-ticket
//!   optimization only), so `jlsZeroPSKBinders` (`jls.go:352-376`) never
//!   fires and PSK binders never appear in the authData — exactly like
//!   the uTLS path, which sets `SessionTicketsDisabled: true`
//!   (`utls.go:52-54,61`).
//! * **Client auth-failure camouflage HTTP request** (`utls.go:107-117`,
//!   `jlsClientHTTPFallback utls.go:120-150`): scope-out inherited from
//!   the plain path — on a non-JLS server this port fails the dial
//!   immediately with [`ERR_AUTH_FAILED`] instead of completing the TLS
//!   handshake against the fallback certificate, issuing a plausible HTTP
//!   request, and only then returning `ErrJLSAuthFailed`
//!   (`utls.go:106-112`). The observable dial result is the same error.
//!
//! ## The fingerprint path (mihomo `transport/jls/utls.go`)
//!
//! `newUTLSClient` (`utls.go:38-118`) drives uTLS through a fingerprint
//! template; this port reproduces it over the engine's own TLS 1.3 stack
//! (`proto/reality/tls13::connect`), which takes a fully-formed hello:
//!
//! 1. Build the profile hello from `reality::profiles` with a fresh random
//!    (`BuildHandshakeState`, `utls.go:70-78`). The GREASE values and the
//!    Chrome extension shuffle stay pinned to that first random draw
//!    (`build_client_hello_opts`'s `structure_seed`) — uTLS' `SetClientRandom`
//!    (`utls.go:95-97`) also leaves the rest of the fingerprint untouched.
//! 2. `authData` = the serialized hello with the random zeroed
//!    (`jlsClientHelloAuthData`, `utls.go:243-250`); `fakeRandom` is sealed
//!    over the first 16 bytes of the drawn random
//!    (`jlsBuildFakeRandom`, `utls.go:270-290`).
//! 3. Rebuild the hello with the random replaced by the fakeRandom and
//!    verify the two passes differ in exactly the 32 random bytes — the
//!    byte-compatibility contract the server's authData check depends on.
//! 4. ALPN: `config.ALPN` or [`DEFAULT_ALPN`] (`utls.go:48-51`), with
//!    Chrome's ALPS extension kept only while `h2` is advertised
//!    (`overrideUTLSALPN`, `utls.go:208-241`).
//! 5. The templates always offer TLS 1.3 first, so upstream's
//!    `utlsClientHelloSupportsTLS13` gate (`utls.go:81-83,152-159`)
//!    cannot fail here; `tls13.rs` is TLS 1.3-only by construction, which
//!    also preserves the post-handshake version check (`utls.go:113-116`).
//! 6. The ServerHello random is verified by a transparent transport guard
//!    that inspects the first handshake message — `VerifyConnection`
//!    (`utls.go:169-188`) — using the same `hello_auth_data` /
//!    `check_fake_random` codec as the plain path. On failure the dial
//!    returns [`ERR_AUTH_FAILED`] (see the fallback scope-out above).
//!    Certificate-chain trust is *not* enforced on the success path — JLS
//!    itself authenticates the peer and the JLS server's camouflage
//!    certificate is generated at random (`utls.go:58-60`
//!    `InsecureSkipVerify: true`; the CertificateVerify *signature* is
//!    still verified by `tls13.rs`, like uTLS). HelloRetryRequest is
//!    rejected outright by `tls13.rs` (JLS v3 does not permit HRR,
//!    `utls.go:170-174`); upstream instead falls back to certificate
//!    verification, which for a JLS server cannot succeed either.

use std::cell::{Cell, RefCell};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{ready, Context, Poll};

use aes::Aes256;
use aes_gcm::aead::consts::U32;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::AesGcm;
use bytes::{Buf, BufMut, BytesMut};
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as ring_provider;
use rustls::crypto::{CryptoProvider, GetRandomFailed, SecureRandom};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

use crate::error::{Error, Result};
use crate::proto::reality::profiles::{self, UtslProfile};
use crate::proto::reality::tls13::{self as engine_tls13, ServerAuth};
use crate::stream::BoxProxyStream;

/// `transport/jls/jls.go:28 DefaultALPN`.
pub const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];

/// `jls-tls/jls.go:69 ErrJLSAuthFailed` — kept verbatim so callers can
/// match the upstream sentinel text.
pub const ERR_AUTH_FAILED: &str = "tls: jls authentication failed";

/// `jls-tls/jls.go:60-63`: the handshake header is type(1)+len24, the
/// random follows the 2-byte legacy version.
const HELLO_HEADER_LEN: usize = 4;
const HELLO_RANDOM_OFFSET: usize = HELLO_HEADER_LEN + 2;
/// `jls-tls/jls.go:61 jlsHelloRandomLen`.
const HELLO_RANDOM_LEN: usize = 32;
/// `jls-tls/jls.go:64 jlsRandomSeedLen = jlsHelloRandomLen / 2`.
const RANDOM_SEED_LEN: usize = HELLO_RANDOM_LEN / 2;

/// `utls.go:33-35`: forbidden fake-random tails — the TLS 1.2/1.1
/// downgrade canaries and the last 8 bytes of the HelloRetryRequest
/// random (RFC 8446 §4.1.2).
const DOWNGRADE_CANARY_TLS12: &[u8] = b"DOWNGRD\x01";
const DOWNGRADE_CANARY_TLS11: &[u8] = b"DOWNGRD\x00";
const HRR_RANDOM_SUFFIX: &[u8] = &[0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c];

/// TLS record constants (same layout constants as `proto/restls.rs`).
const RECORD_HEADER_LEN: usize = 5;
const REC_HANDSHAKE: u8 = 22;
const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
/// Largest record accepted from the peer (record header + 16384 + margin).
const MAX_RECORD_LEN: usize = RECORD_HEADER_LEN + 16384 + 2048;
/// Offset of the hello random inside a record (5-byte record header).
const RECORD_RANDOM_OFFSET: usize = RECORD_HEADER_LEN + HELLO_RANDOM_OFFSET;

/// A JLS credential pair — `jls-tls/jls.go:18-21 JLSUser` ("Username maps
/// to rustls-jls user_iv, and Password maps to rustls-jls user_pwd").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JlsUser {
    pub username: String,
    pub password: String,
}

impl JlsUser {
    /// `transport/jls/jls.go:54-62 NewConfig`: both fields are required.
    pub fn new(username: &str, password: &str) -> Result<Self> {
        if username.is_empty() {
            return Err(Error::config("jls: username is required"));
        }
        if password.is_empty() {
            return Err(Error::config("jls: password is required"));
        }
        Ok(JlsUser {
            username: username.to_owned(),
            password: password.to_owned(),
        })
    }
}

/// `adapter/outbound/jls.go:10-15 JLSOptions.Parse`: `Ok(None)` when both
/// fields are empty (JLS disabled — the plain TLS dial runs instead),
/// otherwise a validated user. The integrator calls this on the parsed
/// `jls-opts` and, when it yields `Some`, dials TLS through [`connect`].
pub fn parse(username: &str, password: &str) -> Result<Option<JlsUser>> {
    if username.is_empty() && password.is_empty() {
        return Ok(None);
    }
    JlsUser::new(username, password).map(Some)
}

// ------------------------------------------------------------------ codec

/// AES-256-GCM with a 32-byte nonce — Go's
/// `cipher.NewGCMWithNonceSize(aes.NewCipher(key), sha256.Size)`
/// (`jls-tls/jls.go:152-159`). The RustCrypto generic instantiation
/// implements the identical J0 = GHASH(nonce ‖ pad ‖ len) construction
/// (aes-gcm 0.10 `init_ctr`, NIST SP 800-38D §7.2), so seals are
/// byte-compatible; the tests pin Go-generated golden vectors.
type JlsAead = AesGcm<Aes256, U32>;

/// `utls.go:326-332 jlsHash` = SHA256(value ‖ authData).
fn jls_hash(value: &str, auth_data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    h.update(auth_data);
    h.finalize().into()
}

/// `utls.go:315-324 newJLSAEAD`: the key comes from the password, the
/// nonce from the username, both bound to the hello authData.
fn jls_aead(user: &JlsUser, auth_data: &[u8]) -> JlsAead {
    let key = jls_hash(&user.password, auth_data);
    JlsAead::new_from_slice(&key).expect("32-byte AES-256 key")
}

/// `jlsHasForbiddenRandomSuffix` (`jls-tls/jls.go:174-183`).
pub fn has_forbidden_random_suffix(random: &[u8]) -> bool {
    let suffix_len = DOWNGRADE_CANARY_TLS12.len();
    if random.len() < suffix_len {
        return false;
    }
    let suffix = &random[random.len() - suffix_len..];
    suffix == DOWNGRADE_CANARY_TLS12
        || suffix == DOWNGRADE_CANARY_TLS11
        || suffix == HRR_RANDOM_SUFFIX
}

/// `jlsBuildFakeRandom` (`jls-tls/jls.go:138-172`): seal the 16-byte seed
/// under the (key, nonce) pair derived from (username, password,
/// authData); redraw the seed while the result carries a forbidden
/// suffix.
pub fn build_fake_random(user: &JlsUser, random16: &[u8], auth_data: &[u8]) -> Result<[u8; 32]> {
    if random16.len() != RANDOM_SEED_LEN {
        return Err(Error::crypto("tls: jls random seed must be 16 bytes"));
    }
    let aead = jls_aead(user, auth_data);
    let nonce = jls_hash(&user.username, auth_data);
    let nonce = aes_gcm::Nonce::<U32>::from_slice(&nonce);
    let mut seed = random16.to_vec();
    loop {
        let sealed = aead
            .encrypt(nonce, Payload { msg: &seed, aad: &[] })
            .map_err(|_| Error::crypto("jls: fake random seal failed"))?;
        let fake: [u8; 32] = sealed
            .try_into()
            .map_err(|_| Error::crypto("jls: fake random is not 32 bytes"))?;
        if !has_forbidden_random_suffix(&fake) {
            return Ok(fake);
        }
        // Regenerate N instead of emitting a FakeRandom ending in one of
        // the reserved suffixes (jls-tls/jls.go:162-171).
        rand::rngs::OsRng.fill_bytes(&mut seed);
    }
}

/// `jlsCheckFakeRandom` (`jls-tls/jls.go:185-209`): the 32-byte random
/// must open to a 16-byte plaintext under the derived key/nonce.
pub fn check_fake_random(user: &JlsUser, fake_random: &[u8], auth_data: &[u8]) -> bool {
    if fake_random.len() != HELLO_RANDOM_LEN {
        return false;
    }
    let aead = jls_aead(user, auth_data);
    let nonce = jls_hash(&user.username, auth_data);
    let nonce = aes_gcm::Nonce::<U32>::from_slice(&nonce);
    match aead.decrypt(nonce, Payload { msg: fake_random, aad: &[] }) {
        Ok(plain) => plain.len() == RANDOM_SEED_LEN,
        Err(_) => false,
    }
}

/// `cloneJLSHello` + zero (`utls.go:243-268`): validate a serialized
/// hello handshake message (type ‖ len24 must match) and return it with
/// the 32-byte random zeroed — the authData. `message_type` is 1 for a
/// ClientHello and 2 for a ServerHello. PSK binders would be zeroed as
/// well (`jlsClientHelloWireAuthData`, `jls-tls/jls.go:352-376`), but
/// this client/server pair never offers or requests sessions.
pub fn hello_auth_data(hello_wire: &[u8], message_type: u8) -> Result<Vec<u8>> {
    let len24 = (usize::from(hello_wire[1]) << 16)
        | (usize::from(hello_wire[2]) << 8)
        | usize::from(hello_wire[3]);
    if hello_wire.len() < HELLO_RANDOM_OFFSET + HELLO_RANDOM_LEN
        || hello_wire.first() != Some(&message_type)
        || len24 != hello_wire.len() - HELLO_HEADER_LEN
    {
        return Err(Error::protocol("jls: invalid hello message"));
    }
    let mut msg = hello_wire.to_vec();
    msg[HELLO_RANDOM_OFFSET..HELLO_RANDOM_OFFSET + HELLO_RANDOM_LEN].fill(0);
    Ok(msg)
}

/// Extract the 32-byte random from a hello record (the handshake message
/// starts right after the 5-byte record header).
fn record_random(record: &[u8]) -> Option<[u8; 32]> {
    record
        .get(RECORD_RANDOM_OFFSET..RECORD_RANDOM_OFFSET + HELLO_RANDOM_LEN)
        .and_then(|r| r.try_into().ok())
}

// ------------------------------------------- fixed X25519 + scripted random

thread_local! {
    /// Per-connection fixed X25519 key pair, installed while a hello is
    /// stamped. Every stamping window is fully synchronous (no awaits),
    /// so client and server tasks on one runtime thread never interleave
    /// inside it.
    static FIXED_KEY: Cell<Option<([u8; 32], [u8; 32])>> = const { Cell::new(None) };
    /// Replay script for the active pass; a draw whose length does not
    /// match the script head falls through to system entropy and is
    /// recorded for the next pass.
    static DRAW_SCRIPT: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    static DRAWN: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

fn system_random() -> &'static dyn SecureRandom {
    static FALLBACK: OnceLock<&'static dyn SecureRandom> = OnceLock::new();
    *FALLBACK.get_or_init(|| ring_provider::default_provider().secure_random)
}

/// The random source of the JLS TLS configs: replays the recorded draws
/// of a previous pass (with the hello random replaced) so two
/// `Connection::new` calls marshal byte-identical hellos. Unscripted
/// draws go to system entropy and are recorded (`DRAWN`) for the next
/// pass.
#[derive(Debug)]
struct JlsRandom;

static JLS_RANDOM: JlsRandom = JlsRandom;

impl SecureRandom for JlsRandom {
    fn fill(&self, buf: &mut [u8]) -> std::result::Result<(), GetRandomFailed> {
        let scripted = DRAW_SCRIPT.with_borrow_mut(|s| {
            if s.first().map(|front| front.len() == buf.len()).unwrap_or(false) {
                let front = s.remove(0);
                buf.copy_from_slice(&front);
                true
            } else {
                false
            }
        });
        if scripted {
            return Ok(());
        }
        system_random().fill(buf)?;
        DRAWN.with_borrow_mut(|d| d.push(buf.to_vec()));
        Ok(())
    }
}

/// A key-exchange group returning a fixed, pre-generated key pair: the
/// marshaled hello must be identical across the two stamping passes
/// (same pattern as `proto/restls.rs`).
#[derive(Debug)]
struct FixedX25519;

static FIXED_X25519: FixedX25519 = FixedX25519;

#[derive(Debug)]
struct FixedExchange {
    scalar: [u8; 32],
    public: [u8; 32],
}

impl rustls::crypto::SupportedKxGroup for FixedX25519 {
    fn start(
        &self,
    ) -> std::result::Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
        FIXED_KEY.with(Cell::get)
            .map(|(scalar, public)| {
                Box::new(FixedExchange { scalar, public })
                    as Box<dyn rustls::crypto::ActiveKeyExchange>
            })
            .ok_or_else(|| rustls::Error::General("jls: no fixed key installed".into()))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

impl rustls::crypto::ActiveKeyExchange for FixedExchange {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> std::result::Result<rustls::crypto::SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| rustls::Error::General("jls: bad X25519 key share".into()))?;
        let shared =
            curve25519_dalek::montgomery::MontgomeryPoint(peer).mul_clamped(self.scalar).0;
        if shared.iter().all(|b| *b == 0) {
            return Err(rustls::Error::General(
                "jls: X25519 peer key share is a low-order point".into(),
            ));
        }
        Ok(rustls::crypto::SharedSecret::from(shared.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

/// Accept-anything verifier for `skip-cert-verify` (mihomo's
/// `InsecureSkipVerify` — JLS itself authenticates the peer).
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Outbound JLS endpoint — the client-relevant fields of mihomo's
/// `jls.ClientConfig` (`transport/jls/jls.go:35-41`); the TCP transports
/// fill ServerName/ALPN from the proxy's TLS settings
/// (`transport/vmess/tls.go:84-90`).
#[derive(Debug, Clone)]
pub struct JlsOut {
    pub username: String,
    pub password: String,
    pub sni: String,
    /// Empty selects [`DEFAULT_ALPN`] (`transport/jls/jls.go:98-101`).
    pub alpn: Vec<String>,
    pub skip_cert_verify: bool,
    /// `client-fingerprint` (`jls.ClientConfig.ClientFingerprint`,
    /// `transport/jls/jls.go:40`): `Some(profile)` selects the uTLS-path
    /// branch of `NewClient` (`transport/jls/utls.go:38-118`) — the cover
    /// hello is the Chrome/Firefox template and the session runs on the
    /// engine's TLS 1.3 stack. `None` keeps mihomo's plain rustls path.
    pub fingerprint: Option<UtslProfile>,
}

/// TLS 1.3-only client config with the JLS crypto provider (scripted
/// random + fixed X25519). The server side of the pair is TLS 1.3-only
/// too (`transport/jls/jls.go:162` sets `MinVersion: VersionTLS13`), and
/// JLS v3 rejects non-1.3 client handshakes (`utls.go:113-115`).
fn jls_client_config(cfg: &JlsOut) -> Result<Arc<ClientConfig>> {
    let mut provider = ring_provider::default_provider();
    provider.secure_random = &JLS_RANDOM;
    provider.kx_groups = vec![&FIXED_X25519];
    let provider = Arc::new(provider);
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::config(format!("jls: tls: {e}")))?;
    let mut config = if cfg.skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    } else {
        // Same policy as transport::tls_client_config.
        let mut roots = RootCertStore::empty();
        let mut loaded = 0usize;
        let certs = rustls_native_certs::load_native_certs()
            .map_err(|e| Error::config(format!("jls: native cert store: {e}")))?;
        for cert in certs {
            roots
                .add(cert)
                .map_err(|e| Error::config(format!("jls: bad native cert: {e}")))?;
            loaded += 1;
        }
        if loaded == 0 {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        builder
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    let alpn: Vec<String> = if cfg.alpn.is_empty() {
        DEFAULT_ALPN.iter().map(|s| s.to_string()).collect()
    } else {
        cfg.alpn.clone()
    };
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    // No session tickets: a fresh hello per dial (the upstream plain path
    // builds a fresh tls.Config, and JLS forbids PSK binders it cannot
    // recompute after the random swap — utls.go:52-54).
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

/// Drain everything rustls has queued for the socket.
fn drain_tls(tls: &mut ClientConnection) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while tls.wants_write() {
        if tls
            .write_tls(&mut out)
            .map_err(|e| Error::config(format!("jls: tls write: {e}")))?
            == 0
        {
            break;
        }
    }
    Ok(out)
}

/// Build a fresh rustls client connection and drain its initial flight.
fn new_client_connection(
    config: &Arc<ClientConfig>,
    sni: &str,
) -> Result<(ClientConnection, Vec<u8>)> {
    let name = rustls::pki_types::ServerName::try_from(sni.to_owned())
        .map_err(|_| Error::config(format!("jls: invalid SNI {sni:?}")))?;
    let mut tls = ClientConnection::new(config.clone(), name)
        .map_err(|e| Error::config(format!("jls: TLS client init: {e}")))?;
    let mut flight = drain_tls(&mut tls)?;
    if flight.is_empty() {
        let _ = tls.process_new_packets();
        flight = drain_tls(&mut tls)?;
    }
    Ok((tls, flight))
}

/// The two-pass ClientHello stamp — the rustls equivalent of
/// `applyJLSClientHelloRandom` (`jls-tls/jls.go:232-256`). Pass one
/// marshals the hello and derives `authData` + `fakeRandom` from its wire
/// form; pass two replays the same draws with the client random replaced
/// by the fakeRandom. Returns the connection (whose transcript covers
/// the stamped hello) and the flight to send.
fn build_stamped_client_hello(
    config: &Arc<ClientConfig>,
    sni: &str,
    user: &JlsUser,
) -> Result<(ClientConnection, Vec<u8>)> {
    // Fixed X25519 pair shared by both passes.
    let mut scalar = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut scalar);
    let public = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(scalar).0;
    FIXED_KEY.with(|k| k.set(Some((scalar, public))));

    let result = (|| {
        // Pass 1: record the draws, marshal the hello.
        DRAW_SCRIPT.with_borrow_mut(|s| s.clear());
        DRAWN.with_borrow_mut(|d| d.clear());
        let (_tls1, flight1) = new_client_connection(config, sni)?;
        if flight1.len() < RECORD_RANDOM_OFFSET + HELLO_RANDOM_LEN
            || flight1[0] != REC_HANDSHAKE
            || flight1[RECORD_HEADER_LEN] != HS_CLIENT_HELLO
        {
            return Err(Error::crypto(
                "jls: could not build a ClientHello (unexpected flight shape)",
            ));
        }
        let auth_data = hello_auth_data(&flight1[RECORD_HEADER_LEN..], HS_CLIENT_HELLO)?;
        // The seed is the first half of the drawn client random — the
        // LAST 32-byte draw (rustls client/hs.rs: session id, u16, then
        // Random::new).
        let drawn = DRAWN.with_borrow(|d| d.clone());
        let random_pos = drawn
            .iter()
            .rposition(|d| d.len() == HELLO_RANDOM_LEN)
            .ok_or_else(|| Error::crypto("jls: no client random recorded"))?;
        let mut seed = [0u8; RANDOM_SEED_LEN];
        seed.copy_from_slice(&drawn[random_pos][..RANDOM_SEED_LEN]);
        let fake_random = build_fake_random(user, &seed, &auth_data)?;

        // Pass 2: replay every draw with the client random replaced.
        let mut script = drawn;
        script[random_pos] = fake_random.to_vec();
        DRAW_SCRIPT.with_borrow_mut(|s| *s = script);
        let (tls2, flight2) = new_client_connection(config, sni)?;
        DRAW_SCRIPT.with_borrow_mut(|s| s.clear());

        // The flights must match outside the random, or the stamp did not
        // land where the server reads it.
        if flight2.len() != flight1.len()
            || flight2[..RECORD_RANDOM_OFFSET] != flight1[..RECORD_RANDOM_OFFSET]
            || flight2[RECORD_RANDOM_OFFSET + HELLO_RANDOM_LEN..]
                != flight1[RECORD_RANDOM_OFFSET + HELLO_RANDOM_LEN..]
            || flight2[RECORD_RANDOM_OFFSET..RECORD_RANDOM_OFFSET + HELLO_RANDOM_LEN]
                != fake_random
        {
            return Err(Error::crypto(
                "jls: could not stamp the ClientHello random (rustls ClientHello layout changed)",
            ));
        }
        Ok((tls2, flight2))
    })();
    FIXED_KEY.with(|k| k.set(None));
    DRAW_SCRIPT.with_borrow_mut(|s| s.clear());
    DRAWN.with_borrow_mut(|d| d.clear());
    result
}

/// Feed raw wire bytes into a rustls connection's deframer. rustls'
/// `read_tls` copies at most 4096 bytes per call (rustls-0.23.37
/// `src/msgs/deframer/buffers.rs:220 READ_SIZE`), so a larger record
/// needs repeated calls before `process_new_packets` sees it whole.
fn feed_records<D>(
    tls: &mut rustls::ConnectionCommon<D>,
    bytes: &[u8],
) -> std::result::Result<(), rustls::Error> {
    let mut rest = bytes;
    while !rest.is_empty() {
        let mut cursor = std::io::Cursor::new(rest);
        let n = tls
            .read_tls(&mut cursor)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        if n == 0 {
            break;
        }
        rest = &rest[n..];
    }
    Ok(())
}

/// Read exactly one TLS record from `rbuf`, refilling from `transport`.
async fn read_one_record<R: AsyncRead + Unpin>(
    transport: &mut R,
    rbuf: &mut BytesMut,
) -> Result<Vec<u8>> {
    let want = |rbuf: &BytesMut| -> Option<usize> {
        if rbuf.len() < RECORD_HEADER_LEN {
            return None;
        }
        let len = usize::from(u16::from_be_bytes([rbuf[3], rbuf[4]]));
        if RECORD_HEADER_LEN + len > MAX_RECORD_LEN {
            return Some(usize::MAX);
        }
        Some(RECORD_HEADER_LEN + len)
    };
    loop {
        match want(rbuf) {
            Some(usize::MAX) => return Err(Error::protocol("jls: oversized record")),
            Some(total) if rbuf.len() >= total => return Ok(rbuf.split_to(total).to_vec()),
            _ => {}
        }
        let mut tmp = [0u8; 16 * 1024];
        let n = transport.read(&mut tmp).await?;
        if n == 0 {
            return Err(Error::network("jls: EOF mid-record"));
        }
        rbuf.extend_from_slice(&tmp[..n]);
    }
}

// ------------------------------------------------------------------ stream

/// A rustls TLS session driven over a boxed proxy stream, returned by
/// [`connect`] once the JLS-authenticated handshake completes. The
/// standard complete-io adapter (tokio-rustls' `TlsStream` has no public
/// constructor for an already-handshaked session).
pub struct JlsTlsStream {
    tls: ClientConnection,
    io: BoxProxyStream,
    /// Wire bytes queued for the transport.
    wbuf: BytesMut,
    close_sent: bool,
}

impl JlsTlsStream {
    /// Move rustls' pending output into `wbuf`, then out to the transport.
    fn drain_pending(this: &mut Self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while this.tls.wants_write() {
            let mut chunk = Vec::new();
            if this
                .tls
                .write_tls(&mut chunk)
                .map_err(std::io::Error::other)?
                == 0
            {
                break;
            }
            this.wbuf.put(&chunk[..]);
        }
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.io).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "jls: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for JlsTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match std::io::Read::read(&mut this.tls.reader(), buf.initialize_unfilled()) {
                Ok(n) if n > 0 => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(_) => return Poll::Ready(Ok(())), // clean EOF (close_notify)
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut this.io).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                // Transport EOF without close_notify: surface whatever
                // rustls has buffered, then EOF.
                return Poll::Ready(Ok(()));
            }
            if let Err(e) = feed_records(&mut this.tls, rb.filled()) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)));
            }
            if let Err(e) = this.tls.process_new_packets() {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)));
            }
        }
    }
}

impl AsyncWrite for JlsTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = std::io::Write::write(&mut this.tls.writer(), buf)?;
        if n == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "jls: tls buffer accepted zero bytes",
            )));
        }
        ready!(Self::drain_pending(this, cx))?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(Self::drain_pending(this, cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.close_sent {
            this.tls.send_close_notify();
            this.close_sent = true;
        }
        ready!(Self::drain_pending(this, cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

// ------------------------------------------------ fingerprint (uTLS) path

/// Build the JLS-stamped profile ClientHello — the hello half of
/// `newUTLSClient` (`transport/jls/utls.go:70-101`). Returns the wire
/// hello (random = fakeRandom) plus the X25519 private half of its key
/// share, which `engine_tls13::connect` needs to complete the handshake.
///
/// uTLS builds the fingerprint, derives the authData + fakeRandom from the
/// *serialized* hello, then calls `SetClientRandom` and rebuilds
/// (`utls.go:70-101`); the rebuild must differ in exactly the 32 random
/// bytes. The engine equivalent pins the GREASE values and the Chrome
/// extension shuffle to the first random draw
/// (`profiles::build_client_hello_opts`'s `structure_seed`) and verifies
/// the byte-compatibility contract before anything is sent.
fn build_profile_hello(
    profile: UtslProfile,
    sni: &str,
    alpn: &[String],
    user: &JlsUser,
) -> Result<(Vec<u8>, [u8; 32])> {
    // The fingerprint's single real key share (X25519).
    let mut scalar = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut scalar);
    let public = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(scalar).0;
    // A browser's 32-byte legacy session id (middlebox compatibility);
    // uTLS draws it per connection. JLS leaves it untouched (REALITY's
    // sealed session id is a different protocol).
    let mut session_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut session_id);

    // Pass 1 — `BuildHandshakeState` (`utls.go:70-78`): the hello as the
    // fingerprint engine emits it, with a fresh random.
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    // `overrideUTLSALPN` (`utls.go:208-241`): ALPS stays only with h2.
    let alps = alpn.iter().any(|a| a == "h2");
    let hello1 = profiles::build_client_hello_opts(
        profile,
        sni,
        &random,
        &session_id,
        &public,
        Some(alpn),
        None,
        alps,
    );
    // `jlsClientHelloAuthData` (`utls.go:243-250`) +
    // `jlsBuildFakeRandom` over the first half of the drawn random
    // (`utls.go:84-94`).
    let auth_data = hello_auth_data(&hello1, HS_CLIENT_HELLO)?;
    let fake_random = build_fake_random(user, &random[..RANDOM_SEED_LEN], &auth_data)?;

    // Pass 2 — `SetClientRandom` + rebuild (`utls.go:95-100`).
    let hello2 = profiles::build_client_hello_opts(
        profile,
        sni,
        &fake_random,
        &session_id,
        &public,
        Some(alpn),
        Some(&random),
        alps,
    );
    if hello2.len() != hello1.len()
        || hello2[..HELLO_RANDOM_OFFSET] != hello1[..HELLO_RANDOM_OFFSET]
        || hello2[HELLO_RANDOM_OFFSET + HELLO_RANDOM_LEN..]
            != hello1[HELLO_RANDOM_OFFSET + HELLO_RANDOM_LEN..]
        || hello2[HELLO_RANDOM_OFFSET..HELLO_RANDOM_OFFSET + HELLO_RANDOM_LEN] != fake_random
    {
        return Err(Error::crypto(
            "jls: could not stamp the fingerprint ClientHello random",
        ));
    }
    Ok((hello2, scalar))
}

/// Transparent transport guard performing the ServerHello half of
/// `utlsJLSVerifier.VerifyConnection` (`utls.go:169-188`): the first
/// handshake message on the wire must be a ServerHello whose random
/// verifies as the JLS fakeRandom over the message's own random-zeroed
/// bytes. Bytes are inspected, never modified — `engine_tls13::connect`
/// consumes them unchanged.
struct JlsServerHelloGuard {
    io: BoxProxyStream,
    user: JlsUser,
    /// Bytes read ahead of the TLS state machine, served first.
    pending: BytesMut,
    /// First handshake message authenticated (or moot: alert/EOF seen).
    verified: bool,
    /// Sticky auth failure, surfaced on every later operation.
    failed: Option<String>,
}

impl JlsServerHelloGuard {
    fn new(io: BoxProxyStream, user: JlsUser) -> Self {
        JlsServerHelloGuard {
            io,
            user,
            pending: BytesMut::new(),
            verified: false,
            failed: None,
        }
    }

    /// Walk the buffered records until the first handshake message is
    /// complete. `Ok(true)` = the guard is satisfied (ServerHello
    /// authenticated, or the peer is already failing — alert / unexpected
    /// record — and `tls13.rs` will surface the error); `Ok(false)` = more
    /// bytes needed; `Err` = JLS authentication failed.
    fn inspect(&mut self) -> Result<bool> {
        let mut handshake = Vec::new();
        let mut off = 0usize;
        loop {
            let rest = &self.pending[off..];
            if rest.len() < RECORD_HEADER_LEN {
                return Ok(false);
            }
            let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            if rest.len() < RECORD_HEADER_LEN + len {
                return Ok(false);
            }
            match rest[0] {
                // RFC 8446 §D.4 middlebox compatibility: skip.
                20 => {}
                // An alert can never precede a ServerHello we must
                // authenticate; hand it to the TLS state machine.
                21 => {
                    self.verified = true;
                    return Ok(true);
                }
                22 => {
                    handshake.extend_from_slice(&rest[RECORD_HEADER_LEN..RECORD_HEADER_LEN + len]);
                    if handshake.len() >= HELLO_HEADER_LEN {
                        let mlen = (usize::from(handshake[1]) << 16)
                            | (usize::from(handshake[2]) << 8)
                            | usize::from(handshake[3]);
                        if handshake.len() >= HELLO_HEADER_LEN + mlen {
                            let msg = &handshake[..HELLO_HEADER_LEN + mlen];
                            if msg.first() != Some(&HS_SERVER_HELLO) {
                                return Err(Error::protocol(
                                    "jls: first server handshake message is not a ServerHello",
                                ));
                            }
                            let auth_data = hello_auth_data(msg, HS_SERVER_HELLO)?;
                            let random = &msg[HELLO_RANDOM_OFFSET..][..HELLO_RANDOM_LEN];
                            if !check_fake_random(&self.user, random, &auth_data) {
                                return Err(Error::crypto(ERR_AUTH_FAILED));
                            }
                            self.verified = true;
                            return Ok(true);
                        }
                    }
                }
                // Anything else: let the TLS state machine judge it.
                _ => {
                    self.verified = true;
                    return Ok(true);
                }
            }
            off += RECORD_HEADER_LEN + len;
        }
    }
}

impl AsyncRead for JlsServerHelloGuard {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(ref err) = this.failed {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err.clone())));
            }
            if !this.verified {
                match this.inspect() {
                    Ok(true) => {}
                    Ok(false) => {
                        let mut tmp = [0u8; 16 * 1024];
                        let mut rb = ReadBuf::new(&mut tmp);
                        ready!(Pin::new(&mut this.io).poll_read(cx, &mut rb))?;
                        if rb.filled().is_empty() {
                            // EOF before any ServerHello: the handshake is
                            // over; pass the EOF through.
                            this.verified = true;
                            return Poll::Ready(Ok(()));
                        }
                        this.pending.extend_from_slice(rb.filled());
                        continue;
                    }
                    Err(e) => {
                        this.failed = Some(e.to_string());
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                }
            }
            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                let chunk: Vec<u8> = this.pending.split_to(n).to_vec();
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            return Pin::new(&mut this.io).poll_read(cx, buf);
        }
    }
}

impl AsyncWrite for JlsServerHelloGuard {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// The fingerprint branch of `NewClient` (`transport/jls/jls.go:95-97` →
/// `newUTLSClient`, `utls.go:38-118`): JLS over the engine's own TLS 1.3
/// stack with a profile ClientHello.
async fn connect_fingerprint(
    cfg: &JlsOut,
    profile: UtslProfile,
    user: &JlsUser,
    transport: BoxProxyStream,
) -> Result<BoxProxyStream> {
    // `utls.go:48-51`: nil ALPN selects DefaultALPN.
    let alpn: Vec<String> = if cfg.alpn.is_empty() {
        DEFAULT_ALPN.iter().map(|s| s.to_string()).collect()
    } else {
        cfg.alpn.clone()
    };
    let (hello, secret) = build_profile_hello(profile, &cfg.sni, &alpn, user)?;
    let guard = JlsServerHelloGuard::new(transport, user.clone());
    debug!(
        target: "engine",
        sni = %cfg.sni, profile = profile.as_str(),
        "jls: TLS 1.3 fingerprint handshake starting"
    );
    // `utls.go:58-60`: the fingerprint path runs with
    // InsecureSkipVerify — JLS authenticates the peer and the camouflage
    // certificate is random; the CertificateVerify *signature* is still
    // checked inside tls13.rs. `skip_cert_verify` has no effect here,
    // matching upstream.
    let stream = engine_tls13::connect(
        Box::new(guard),
        &hello,
        &secret,
        ServerAuth::AcceptAny,
    )
    .await?;
    debug!(
        target: "engine",
        sni = %cfg.sni, profile = profile.as_str(),
        "jls: authenticated fingerprint tunnel established"
    );
    Ok(Box::new(stream))
}

// ----------------------------------------------------------------- connect

/// Perform the JLS-authenticated TLS 1.3 client handshake over
/// `transport` (the raw connection to the JLS server — this function
/// dials nothing) and return the live TLS tunnel. Mirrors
/// `transport/jls/jls.go:82-119 NewClient`: SNI/username/password are
/// required, the ClientHello random carries the credentials, and the
/// ServerHello random must verify or the dial fails with
/// [`ERR_AUTH_FAILED`]. `JlsOut::fingerprint` selects the uTLS branch
/// (`newUTLSClient`, `utls.go:38-118`); without it mihomo's plain
/// TLS branch (`jls.go:98-119`) runs.
pub async fn connect(cfg: &JlsOut, transport: BoxProxyStream) -> Result<BoxProxyStream> {
    if cfg.sni.is_empty() {
        return Err(Error::config("jls: server name is required"));
    }
    let user = JlsUser::new(&cfg.username, &cfg.password)?;
    match cfg.fingerprint {
        Some(profile) => connect_fingerprint(cfg, profile, &user, transport).await,
        None => connect_plain(cfg, &user, transport).await,
    }
}

/// mihomo's plain TLS branch (`transport/jls/jls.go:98-119`): JLS stamped
/// onto a stock rustls hello via the two-pass machinery above.
async fn connect_plain(
    cfg: &JlsOut,
    user: &JlsUser,
    transport: BoxProxyStream,
) -> Result<BoxProxyStream> {
    let config = jls_client_config(cfg)?;
    let (mut tls, flight) = build_stamped_client_hello(&config, &cfg.sni, user)?;
    let mut transport = transport;
    let mut rbuf = BytesMut::with_capacity(16 * 1024);

    debug!(target: "engine", sni = %cfg.sni, "jls: TLS 1.3 handshake starting");
    transport.write_all(&flight).await?;
    transport.flush().await?;

    let mut server_hello_checked = false;
    loop {
        if !tls.wants_write() && !tls.is_handshaking() {
            break;
        }
        while tls.wants_write() {
            let out = drain_tls(&mut tls)?;
            if out.is_empty() {
                break;
            }
            transport.write_all(&out).await?;
        }
        transport.flush().await?;
        if !tls.is_handshaking() {
            break;
        }
        let record = read_one_record(&mut transport, &mut rbuf).await?;
        // authenticateJLSServerHello (jls-tls/jls.go:268-285): the first
        // server record is the ServerHello whose random must verify.
        if !server_hello_checked {
            server_hello_checked = true;
            let random = record_random(&record)
                .ok_or_else(|| Error::protocol("jls: server flight shorter than a ServerHello"))?;
            let auth_data =
                hello_auth_data(&record[RECORD_HEADER_LEN..], HS_SERVER_HELLO)
                    .map_err(|_| Error::protocol("jls: malformed ServerHello"))?;
            if !check_fake_random(user, &random, &auth_data) {
                return Err(Error::crypto(ERR_AUTH_FAILED));
            }
        }
        feed_records(&mut tls, &record)
            .map_err(|e| Error::network(format!("jls: tls read: {e}")))?;
        tls.process_new_packets().map_err(|e| {
            Error::network(format!("jls: TLS handshake with {} failed: {e}", cfg.sni))
        })?;
    }
    // The client's Finished flight may still be queued.
    while tls.wants_write() {
        let out = drain_tls(&mut tls)?;
        if out.is_empty() {
            break;
        }
        transport.write_all(&out).await?;
    }
    transport.flush().await?;
    debug!(target: "engine", sni = %cfg.sni, "jls: authenticated tunnel established");

    Ok(Box::new(JlsTlsStream {
        tls,
        io: transport,
        wbuf: BytesMut::new(),
        close_sent: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::crypto::ring as ring_provider;
    use rustls::ServerConnection;
    use tokio::io::DuplexStream;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ------------------------------------------------------------ codec

    #[test]
    fn fake_random_matches_go_golden_vectors() {
        // Vectors generated by a Go program running the exact upstream
        // construction (cipher.NewGCMWithNonceSize(aes.NewCipher(
        // SHA256(pass‖auth)), 32) over SHA256(user‖auth) as the nonce):
        // the RustCrypto generic-nonce instantiation must agree
        // byte-for-byte.
        let cases: &[(&str, &str, &str, &str, &str)] = &[
            // user, password, seed, authData, sealed fakeRandom
            (
                "user1",
                "pass1",
                "00000000000000000000000000000000",
                "",
                "7321a0700b4fa3ee05d6ad819aa98f15f0a5859ed3f75944b7291a1d2b11e0a5",
            ),
            (
                "user1",
                "pass1",
                "30313233343536373839616263646566",
                "636c69656e742068656c6c6f20617574682064617461206279746573",
                "0be3adb6e3d421124fbf4b8808cc012aebf7ad493f27ba8226122d87d5deae57",
            ),
            (
                "long-username-32-chars-abcd",
                "pw",
                "0102030405060708090a0b0c0d0e0f10",
                "7365727665722068656c6c6f206175746820646174612078797a",
                "a435fd62ff6f0a593b68f2e82cb210e42f20717cc6fb023290daa633ca2711a8",
            ),
        ];
        for (user, pass, seed, auth, want) in cases {
            let user = JlsUser::new(user, pass).unwrap();
            let got = build_fake_random(&user, &unhex(seed), &unhex(auth)).unwrap();
            assert_eq!(hex(&got), *want, "seal mismatch for {user:?}");
            // The check function accepts exactly the sealed form.
            assert!(check_fake_random(&user, &got, &unhex(auth)));
            // Any single flipped bit must fail the open.
            let mut bad = got;
            bad[7] ^= 1;
            assert!(!check_fake_random(&user, &bad, &unhex(auth)));
        }
    }

    #[test]
    fn fake_random_binds_all_inputs() {
        let user = JlsUser::new("user1", "pass1").unwrap();
        let auth = b"client hello bytes".as_slice();
        let fake = build_fake_random(&user, &[7u8; 16], auth).unwrap();
        assert_eq!(fake.len(), 32);
        assert!(check_fake_random(&user, &fake, auth));
        // Wrong password, wrong username, wrong authData: all rejected.
        let other_pw = JlsUser::new("user1", "pass2").unwrap();
        assert!(!check_fake_random(&other_pw, &fake, auth));
        let other_user = JlsUser::new("user2", "pass1").unwrap();
        assert!(!check_fake_random(&other_user, &fake, auth));
        assert!(!check_fake_random(&user, &fake, b"other auth data"));
        // Wrong sizes are rejected without touching the AEAD.
        assert!(!check_fake_random(&user, &fake[..31], auth));
        assert!(build_fake_random(&user, &[7u8; 15], auth).is_err());
        assert!(build_fake_random(&user, &[7u8; 17], auth).is_err());
        // Different seeds produce different fake randoms.
        let fake2 = build_fake_random(&user, &[8u8; 16], auth).unwrap();
        assert_ne!(fake, fake2);
    }

    #[test]
    fn forbidden_suffix_detection() {
        // Transcription of mihomo TestJLSForbiddenRandomSuffix
        // (transport/jls/jls_test.go:22-32).
        for suffix in [
            DOWNGRADE_CANARY_TLS12,
            DOWNGRADE_CANARY_TLS11,
            HRR_RANDOM_SUFFIX,
        ] {
            let mut random = vec![0u8; 32 - suffix.len()];
            random.extend_from_slice(suffix);
            assert!(
                has_forbidden_random_suffix(&random),
                "JLS accepted forbidden random suffix {}",
                hex(suffix)
            );
        }
        assert!(!has_forbidden_random_suffix(&[0u8; 32]));
        assert!(!has_forbidden_random_suffix(&[0u8; 7]));
    }

    #[test]
    fn hello_auth_data_zeroes_only_the_random() {
        // A synthetic ClientHello handshake message: type 1, len24, then
        // version(2) random(32) body.
        let mut hello = vec![HS_CLIENT_HELLO, 0, 0, 0];
        hello.extend_from_slice(&[0x03, 0x03]);
        let mut random: [u8; 32] = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random);
        hello.extend_from_slice(&random);
        hello.extend_from_slice(b"rest of the hello");
        let body_len = (hello.len() - HELLO_HEADER_LEN) as u32;
        hello[1..4].copy_from_slice(&body_len.to_be_bytes()[1..]);
        let hello = hello;
        let auth = hello_auth_data(&hello, HS_CLIENT_HELLO).unwrap();
        assert_eq!(auth.len(), hello.len());
        assert_eq!(auth[..6], hello[..6]);
        assert_eq!(auth[6..38], [0u8; 32]);
        assert_eq!(auth[38..], hello[38..]);
        // The zeroed authData changes the seal: wrong-type and short
        // messages are rejected (cloneJLSHello, utls.go:261-268).
        assert!(hello_auth_data(&hello, HS_SERVER_HELLO).is_err());
        assert!(hello_auth_data(&hello[..39], HS_CLIENT_HELLO).is_err());
        let mut bad_len = hello.clone();
        bad_len[3] = 37; // length no longer matches
        assert!(hello_auth_data(&bad_len, HS_CLIENT_HELLO).is_err());
        // Two different randoms produce the SAME authData — the codec
        // binds everything but the random itself.
        let mut hello_b = hello.clone();
        hello_b[6..38].fill(0xab);
        assert_eq!(
            hello_auth_data(&hello, HS_CLIENT_HELLO).unwrap(),
            hello_auth_data(&hello_b, HS_CLIENT_HELLO).unwrap()
        );
    }

    #[test]
    fn options_parse_mirrors_mihomo() {
        // adapter/outbound/jls.go:10-15: both empty -> disabled.
        assert!(parse("", "").unwrap().is_none());
        // Partial credentials are rejected (NewConfig).
        assert!(parse("user1", "").is_err());
        assert!(parse("", "pass1").is_err());
        let user = parse("user1", "pass1").unwrap().unwrap();
        assert_eq!(user.username, "user1");
        assert_eq!(user.password, "pass1");
    }

    #[tokio::test]
    async fn config_requires_sni_and_credentials() {
        let mut cfg = test_cfg("user1", "pass1");
        cfg.sni = String::new();
        let (client, _server) = tokio::io::duplex(64);
        let err = match connect(&cfg, Box::new(client) as BoxProxyStream).await {
            Ok(_) => panic!("an empty sni must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("server name"), "{err}");
        let cfg = test_cfg("", "pass1");
        let (client, _server) = tokio::io::duplex(64);
        let err = match connect(&cfg, Box::new(client) as BoxProxyStream).await {
            Ok(_) => panic!("an empty username must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("username"), "{err}");
        let cfg = test_cfg("user1", "");
        let (client, _server) = tokio::io::duplex(64);
        let err = match connect(&cfg, Box::new(client) as BoxProxyStream).await {
            Ok(_) => panic!("an empty password must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("password"), "{err}");
    }

    // ------------------------------------------------------ loopback mimic

    fn test_server_config() -> Arc<rustls::ServerConfig> {
        let certified = rcgen::generate_simple_self_signed(vec!["jls.test".to_string()])
            .expect("rcgen self-signed cert");
        let cert = CertificateDer::from(certified.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        // The JLS provider: scripted random + the fixed X25519 group, so
        // the two server passes marshal identical ServerHellos.
        let mut provider = ring_provider::default_provider();
        provider.secure_random = &JLS_RANDOM;
        provider.kx_groups = vec![&FIXED_X25519];
        let provider = Arc::new(provider);
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server config");
        config.alpn_protocols = DEFAULT_ALPN.iter().map(|a| a.as_bytes().to_vec()).collect();
        Arc::new(config)
    }

    fn drain_server_tls(tls: &mut ServerConnection) -> Vec<u8> {
        let mut out = Vec::new();
        while tls.wants_write() {
            if tls.write_tls(&mut out).unwrap_or(0) == 0 {
                break;
            }
        }
        out
    }

    /// The JLS server side, transcribed from `authenticateJLSClientHello`
    /// (jls-tls/jls.go:306-331) and the ServerHello stamping implied by
    /// `jlsBuildFakeRandom`: the ClientHello random must verify, and the
    /// ServerHello random is replaced by a fresh fake random — here via
    /// the same two-pass replay used by the client (the server's first
    /// 32-byte draw is the ServerHello random, rustls
    /// src/server/hs.rs:495-498). Runs behind a genuine rustls server
    /// and echoes decrypted application data.
    async fn jls_server_mimic(
        mut io: impl AsyncRead + AsyncWrite + Unpin,
        user: JlsUser,
        config: Arc<rustls::ServerConfig>,
    ) -> std::result::Result<(), String> {
        let (mut rd, mut wr) = tokio::io::split(&mut io);

        // 1. Read and authenticate the ClientHello
        //    (authenticateJLSClientHello, jls-tls/jls.go:306-331).
        let mut rbuf = BytesMut::new();
        let hello_record = read_one_record(&mut rd, &mut rbuf)
            .await
            .map_err(|e| e.to_string())?;
        if hello_record[RECORD_HEADER_LEN] != HS_CLIENT_HELLO {
            return Err("first client record is not a ClientHello".into());
        }
        let auth_data =
            hello_auth_data(&hello_record[RECORD_HEADER_LEN..], HS_CLIENT_HELLO)
                .map_err(|e| e.to_string())?;
        let client_random = record_random(&hello_record).ok_or("short ClientHello")?;
        if !check_fake_random(&user, &client_random, &auth_data) {
            return Err("ClientHello random failed JLS authentication".into());
        }

        // 2. Stamp the ServerHello random: pass one marshals the flight,
        //    pass two replays its draws with the random replaced.
        let mut scalar = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut scalar);
        let public = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(scalar).0;
        FIXED_KEY.with(|k| k.set(Some((scalar, public))));

        let stamp = (|| {
            DRAW_SCRIPT.with_borrow_mut(|s| s.clear());
            DRAWN.with_borrow_mut(|d| d.clear());
            let mut cursor = hello_record.as_slice();
            let mut pass1 = ServerConnection::new(config.clone()).map_err(|e| e.to_string())?;
            pass1
                .read_tls(&mut cursor)
                .map_err(|e| e.to_string())?;
            pass1
                .process_new_packets()
                .map_err(|e| e.to_string())?;
            let flight1 = drain_server_tls(&mut pass1);
            if flight1.len() < RECORD_RANDOM_OFFSET + HELLO_RANDOM_LEN
                || flight1[RECORD_HEADER_LEN] != HS_SERVER_HELLO
            {
                return Err("unexpected server flight shape".to_string());
            }
            // The ServerHello is the flight's first record; later
            // records are already encrypted.
            let sh_len = usize::from(u16::from_be_bytes([flight1[3], flight1[4]]));
            let sh_auth = hello_auth_data(
                &flight1[RECORD_HEADER_LEN..RECORD_HEADER_LEN + sh_len],
                HS_SERVER_HELLO,
            )
            .map_err(|e| e.to_string())?;
            let mut seed = [0u8; RANDOM_SEED_LEN];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
            let fake = build_fake_random(&user, &seed, &sh_auth).map_err(|e| e.to_string())?;

            let drawn = DRAWN.with_borrow(|d| d.clone());
            let pos = drawn
                .iter()
                .position(|d| d.len() == HELLO_RANDOM_LEN)
                .ok_or("no server random recorded")?;
            let mut script = drawn;
            script[pos] = fake.to_vec();
            DRAW_SCRIPT.with_borrow_mut(|s| *s = script);

            let mut cursor = hello_record.as_slice();
            let mut pass2 = ServerConnection::new(config.clone()).map_err(|e| e.to_string())?;
            pass2
                .read_tls(&mut cursor)
                .map_err(|e| e.to_string())?;
            pass2
                .process_new_packets()
                .map_err(|e| e.to_string())?;
            let flight2 = drain_server_tls(&mut pass2);
            DRAW_SCRIPT.with_borrow_mut(|s| s.clear());
            // The ServerHello record must match outside the random. The
            // later (encrypted) records may differ legitimately: the
            // CertificateVerify signature randomizes its ECDSA nonce.
            let sh_len2 = usize::from(u16::from_be_bytes([flight2[3], flight2[4]]));
            if sh_len2 != sh_len
                || flight2[..RECORD_RANDOM_OFFSET] != flight1[..RECORD_RANDOM_OFFSET]
                || flight2[RECORD_RANDOM_OFFSET + HELLO_RANDOM_LEN..RECORD_HEADER_LEN + sh_len]
                    != flight1[RECORD_RANDOM_OFFSET + HELLO_RANDOM_LEN..RECORD_HEADER_LEN + sh_len]
            {
                return Err("server stamping drifted outside the random".to_string());
            }
            Ok((pass2, flight2))
        })();
        let (mut tls, flight) = stamp.inspect_err(|_| {
            FIXED_KEY.with(|k| k.set(None));
            DRAW_SCRIPT.with_borrow_mut(|s| s.clear());
            DRAWN.with_borrow_mut(|d| d.clear());
        })?;
        FIXED_KEY.with(|k| k.set(None));
        DRAWN.with_borrow_mut(|d| d.clear());

        wr.write_all(&flight)
            .await
            .map_err(|e| e.to_string())?;
        wr.flush().await.map_err(|e| e.to_string())?;

        // 3. Drive the TLS handshake to completion.
        while tls.is_handshaking() {
            let record =
                read_one_record(&mut rd, &mut rbuf).await.map_err(|e| e.to_string())?;
            feed_records(&mut tls, &record).map_err(|e| e.to_string())?;
            tls.process_new_packets().map_err(|e| e.to_string())?;
            let out = drain_server_tls(&mut tls);
            if !out.is_empty() {
                wr.write_all(&out).await.map_err(|e| e.to_string())?;
                wr.flush().await.map_err(|e| e.to_string())?;
            }
        }

        // 4. Echo decrypted application data.
        let mut plain = [0u8; 16 * 1024];
        loop {
            let record = match read_one_record(&mut rd, &mut rbuf).await {
                Ok(r) => r,
                Err(_) => return Ok(()), // client closed the tunnel
            };
            feed_records(&mut tls, &record).map_err(|e| e.to_string())?;
            tls.process_new_packets().map_err(|e| e.to_string())?;
            loop {
                match std::io::Read::read(&mut tls.reader(), &mut plain) {
                    Ok(0) => break,
                    Ok(n) => {
                        std::io::Write::write_all(&mut tls.writer(), &plain[..n])
                            .map_err(|e| e.to_string())?;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.to_string()),
                }
            }
            let out = drain_server_tls(&mut tls);
            if !out.is_empty() {
                wr.write_all(&out).await.map_err(|e| e.to_string())?;
                wr.flush().await.map_err(|e| e.to_string())?;
            }
        }
    }

    fn test_cfg(username: &str, password: &str) -> JlsOut {
        JlsOut {
            username: username.into(),
            password: password.into(),
            sni: "jls.test".into(),
            alpn: Vec::new(),
            skip_cert_verify: true,
            fingerprint: None,
        }
    }

    async fn connect_through_mimic(cfg: &JlsOut, user: &JlsUser) -> Result<BoxProxyStream> {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let server_config = test_server_config();
        let user = user.clone();
        tokio::spawn(async move {
            if let Err(e) = jls_server_mimic(server, user, server_config).await {
                panic!("jls mimic failed: {e}");
            }
        });
        tokio::time::timeout(
            Duration::from_secs(20),
            connect(cfg, Box::new(client) as BoxProxyStream),
        )
        .await
        .expect("jls connect timed out")
    }

    #[tokio::test]
    async fn jls_handshake_and_tunnel_roundtrip() {
        // Fake credentials only (loopback, never a real secret).
        let cfg = test_cfg("user1", "pass1");
        let user = JlsUser::new("user1", "pass1").unwrap();
        let mut stream = connect_through_mimic(&cfg, &user).await.unwrap();

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"ping through jls").await.unwrap();
        let mut buf = [0u8; 16];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping through jls");

        // A payload spanning many TLS records.
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let expected = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; expected.len()];
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
    async fn wrong_password_is_rejected_by_the_server() {
        // The client's ClientHello random will not verify server-side;
        // the mimic aborts and the client dial must fail.
        let cfg = test_cfg("user1", "real-pass");
        let server_user = JlsUser::new("user1", "other-pass").unwrap();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_config = test_server_config();
        let mimic = tokio::spawn(async move {
            // Auth failure is expected: end quietly.
            let _ = jls_server_mimic(server, server_user, server_config).await;
        });
        let err = match connect(&cfg, Box::new(client) as BoxProxyStream).await {
            Ok(_) => panic!("a wrong password must not authenticate"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("EOF")
                || err.to_string().contains("jls")
                || err.to_string().contains("handshake"),
            "{err}"
        );
        mimic.abort();
    }

    #[tokio::test]
    async fn plain_tls_server_reports_auth_failure() {
        // A genuine rustls server WITHOUT the JLS stamp: its random is
        // ordinary entropy, so authenticateJLSServerHello fails and the
        // client must return exactly ErrJLSAuthFailed.
        let cfg = test_cfg("user1", "pass1");
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_config = plain_tls_server_config();
        tokio::spawn(async move {
            plain_tls_echo_server(server, server_config).await;
        });
        let err = match connect(&cfg, Box::new(client) as BoxProxyStream).await {
            Ok(_) => panic!("a plain TLS server must not pass JLS authentication"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains(ERR_AUTH_FAILED),
            "{err}"
        );
    }

    /// A rustls server with the stock provider (ordinary randoms).
    fn plain_tls_server_config() -> Arc<rustls::ServerConfig> {
        let certified = rcgen::generate_simple_self_signed(vec!["jls.test".to_string()])
            .expect("rcgen self-signed cert");
        let cert = CertificateDer::from(certified.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            ring_provider::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server config");
        config.alpn_protocols = DEFAULT_ALPN.iter().map(|a| a.as_bytes().to_vec()).collect();
        Arc::new(config)
    }

    /// Drive a plain rustls server until the peer gives up.
    async fn plain_tls_echo_server(mut io: DuplexStream, config: Arc<rustls::ServerConfig>) {
        let mut tls = ServerConnection::new(config).expect("server conn");
        let mut rbuf = BytesMut::new();
        // The client aborts as soon as it inspects the ServerHello; just
        // keep the server responsive until then.
        while tls.is_handshaking() {
            match read_one_record(&mut io, &mut rbuf).await {
                Ok(record) => {
                    let mut cursor = record.as_slice();
                    if tls.read_tls(&mut cursor).is_err() {
                        return;
                    }
                    if tls.process_new_packets().is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
            let out = drain_server_tls(&mut tls);
            if io.write_all(&out).await.is_err() {
                return;
            }
            let _ = io.flush().await;
        }
    }

    // ---------------------------------------------- fingerprint (uTLS) path

    /// Server-side transport that records the first complete TLS record it
    /// sees (the ClientHello flight) and forwards it, so tests can pin the
    /// cover hello's profile shape.
    struct PeekFirstRecord {
        io: DuplexStream,
        buf: BytesMut,
        first: Option<Vec<u8>>,
        tx: Option<tokio::sync::oneshot::Sender<Vec<u8>>>,
    }

    impl PeekFirstRecord {
        fn new(io: DuplexStream, tx: tokio::sync::oneshot::Sender<Vec<u8>>) -> Self {
            PeekFirstRecord {
                io,
                buf: BytesMut::new(),
                first: None,
                tx: Some(tx),
            }
        }
    }

    impl AsyncRead for PeekFirstRecord {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.buf.is_empty() {
                let mut tmp = [0u8; 16 * 1024];
                let mut rb = ReadBuf::new(&mut tmp);
                ready!(Pin::new(&mut this.io).poll_read(cx, &mut rb))?;
                if rb.filled().is_empty() {
                    return Poll::Ready(Ok(()));
                }
                this.buf.extend_from_slice(rb.filled());
            }
            if this.first.is_none() && this.buf.len() >= RECORD_HEADER_LEN {
                let len = usize::from(u16::from_be_bytes([this.buf[3], this.buf[4]]));
                if this.buf.len() >= RECORD_HEADER_LEN + len {
                    let record = this.buf[..RECORD_HEADER_LEN + len].to_vec();
                    this.first = Some(record.clone());
                    if let Some(tx) = this.tx.take() {
                        let _ = tx.send(record);
                    }
                }
            }
            let n = this.buf.len().min(buf.remaining());
            let chunk = this.buf.split_to(n).to_vec();
            buf.put_slice(&chunk);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for PeekFirstRecord {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
        }
    }

    fn fp_cfg(username: &str, password: &str, profile: UtslProfile) -> JlsOut {
        // The selection API the integrator wires from `client-fingerprint`.
        JlsOut {
            fingerprint: Some(profile),
            ..test_cfg(username, password)
        }
    }

    /// Spawn the JLS mimic behind a first-record capture and connect the
    /// fingerprint client to it.
    async fn connect_fp_through_mimic(
        cfg: &JlsOut,
    ) -> (
        BoxProxyStream,
        tokio::sync::oneshot::Receiver<Vec<u8>>,
    ) {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let server_config = test_server_config();
        let user = JlsUser::new(&cfg.username, &cfg.password).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let peek = PeekFirstRecord::new(server, tx);
            if let Err(e) = jls_server_mimic(peek, user, server_config).await {
                panic!("jls mimic failed: {e}");
            }
        });
        let stream = tokio::time::timeout(
            Duration::from_secs(20),
            connect(cfg, Box::new(client) as BoxProxyStream),
        )
        .await
        .expect("jls fingerprint connect timed out")
        .expect("jls fingerprint connect failed");
        (stream, rx)
    }

    #[tokio::test]
    async fn fingerprint_chrome_roundtrip_against_jls_server() {
        // Fake credentials only (loopback, never a real secret).
        let cfg = fp_cfg("user1", "pass1", UtslProfile::parse("chrome").unwrap());
        let (mut stream, rx) = connect_fp_through_mimic(&cfg).await;

        // The cover flight must be the Chrome parrot: handshake-shaped,
        // GREASE-led cipher list, ALPS + compress_certificate, 32-byte
        // legacy session id, and a fingerprint-scale hello.
        let record = tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .expect("no ClientHello captured")
            .unwrap();
        assert_eq!(&record[..3], &[0x16, 0x03, 0x01], "handshake record");
        let hello = &record[RECORD_HEADER_LEN..];
        assert_eq!(hello[0], HS_CLIENT_HELLO);
        let len24 = (usize::from(hello[1]) << 16)
            | (usize::from(hello[2]) << 8)
            | usize::from(hello[3]);
        assert_eq!(len24, hello.len() - 4, "handshake length");
        // Handshake message layout: 4 header + 2 version + 32 random +
        // 1 sid length + 32 session id + 2 cipher-list length.
        assert_eq!(hello[38], 32, "32-byte legacy session id");
        let cs0 = [hello[73], hello[74]];
        assert!(
            cs0[0] == cs0[1] && cs0[0] & 0x0f == 0x0a,
            "cipher list leads with GREASE {cs0:02x?}"
        );
        // The random is the fakeRandom (sealed), never plain zero bytes.
        assert!(hello[HELLO_RANDOM_OFFSET..HELLO_RANDOM_OFFSET + HELLO_RANDOM_LEN]
            .iter()
            .any(|b| *b != 0));
        assert!(hello.windows(2).any(|w| w == [0x44, 0x69]), "ALPS present");
        assert!(
            hello.windows(2).any(|w| w == [0x00, 0x1b]),
            "compress_certificate present"
        );
        assert!(hello.len() >= 400, "fingerprint-scale hello");

        // Authenticated tunnel + echo, small and multi-record payloads.
        stream.write_all(b"ping via chrome jls").await.unwrap();
        let mut buf = [0u8; 19];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping via chrome jls");
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let expected = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; expected.len()];
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
    async fn fingerprint_firefox_roundtrip_against_jls_server() {
        let cfg = fp_cfg("user1", "pass1", UtslProfile::parse("firefox").unwrap());
        let (mut stream, rx) = connect_fp_through_mimic(&cfg).await;
        let record = tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .expect("no ClientHello captured")
            .unwrap();
        let hello = &record[RECORD_HEADER_LEN..];
        // Firefox: no GREASE anywhere in the cipher list (0x1301 first).
        assert_eq!(&hello[73..75], &[0x13, 0x01], "TLS_AES_128_GCM first");
        // record_size_limit 0x4001: ext type ‖ u16 len ‖ limit.
        assert!(
            hello.windows(6).any(|w| w == [0x00, 0x1c, 0x00, 0x02, 0x40, 0x01]),
            "record_size_limit 0x4001 present"
        );
        assert!(
            !hello.windows(2).any(|w| w == [0x44, 0x69]),
            "no ALPS in the Firefox parrot"
        );

        stream.write_all(b"ping via firefox jls").await.unwrap();
        let mut buf = [0u8; 20];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping via firefox jls");
    }

    #[tokio::test]
    async fn fingerprint_plain_tls_server_reports_auth_failure() {
        // Same contract as the plain path: a genuine rustls server without
        // the JLS stamp cannot authenticate, so the dial must fail with
        // exactly ErrJLSAuthFailed (utls.go:106-112 — minus the scoped-out
        // camouflage HTTP request).
        let cfg = fp_cfg("user1", "pass1", UtslProfile::Chrome);
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_config = plain_tls_server_config();
        tokio::spawn(async move {
            plain_tls_echo_server(server, server_config).await;
        });
        let err = match connect(&cfg, Box::new(client) as BoxProxyStream).await {
            Ok(_) => panic!("a plain TLS server must not pass JLS authentication"),
            Err(e) => e,
        };
        assert!(err.to_string().contains(ERR_AUTH_FAILED), "{err}");
    }

    #[tokio::test]
    async fn fingerprint_wrong_password_is_rejected_by_the_server() {
        // The server-side mimic cannot verify the ClientHello fakeRandom;
        // it aborts before answering and the client dial must fail.
        let cfg = fp_cfg("user1", "real-pass", UtslProfile::Chrome);
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_config = test_server_config();
        let server_user = JlsUser::new("user1", "other-pass").unwrap();
        tokio::spawn(async move {
            let _ = jls_server_mimic(server, server_user, server_config).await;
        });
        let err = match connect(&cfg, Box::new(client) as BoxProxyStream).await {
            Ok(_) => panic!("a wrong password must not authenticate"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("handshake")
                || err.to_string().contains("closed")
                || err.to_string().contains("EOF")
                || err.to_string().contains(ERR_AUTH_FAILED),
            "{err}"
        );
    }

    #[test]
    fn fingerprint_selection_api_defaults_to_plain() {
        // test_cfg (plain path) carries no fingerprint; the parse spellings
        // match mihomo's client-fingerprint option.
        assert!(test_cfg("u", "p").fingerprint.is_none());
        assert_eq!(UtslProfile::parse("chrome"), Some(UtslProfile::Chrome));
        assert_eq!(UtslProfile::parse("Firefox"), Some(UtslProfile::Firefox));
    }
}

