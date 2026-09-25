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
//!   `jls.go:338-389`): ported — see "The server half" below. The
//!   camouflage certificate upstream generates per server config
//!   (`ca.NewRandomTLSKeyPair`, jls.go:154-161) is built in-module with
//!   ring (a minimal self-signed P-256 X.509 — `rcgen` is test-only).
//! * **0-RTT / session tickets**: never offered (resumption disabled;
//!   the JLS session marker `jls-tls/jls.go:84-121` is a client-ticket
//!   optimization only), so `jlsZeroPSKBinders` (`jls.go:352-376`) never
//!   fires and PSK binders never appear in the authData — exactly like
//!   the uTLS path, which sets `SessionTicketsDisabled: true`
//!   (`utls.go:52-54,61`).
//! * **Client auth-failure camouflage HTTP request** (`utls.go:107-117`,
//!   `jlsClientHTTPFallback utls.go:120-150`): PORTED for the
//!   fingerprint path — when the FINGERPRINT handshake completes but the
//!   ServerHello random does not verify, the client issues one plausible
//!   `GET https://<sni>` over the established (non-JLS) tunnel — h2c
//!   when the peer negotiated h2, HTTP/1.1 otherwise, `User-Agent` =
//!   the fingerprint's client string, a `padding` cookie of 30..=61
//!   zeros — and only then returns [`ERR_AUTH_FAILED`]
//!   ([`jls_client_http_fallback`]). The plain (rustls) path keeps
//!   erroring immediately at the ServerHello check, matching upstream's
//!   plain branch (`transport/jls/jls.go:98-119` has no fallback there).
//!   Deviation: upstream gates the round on `verifyUTLSCertificate`
//!   (utls.go:190-206 — a cert failing system-pool verification fails
//!   the handshake without the round); this port's fingerprint path
//!   carries no trust store, so the round runs for every completed
//!   handshake.
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
//!
//! ## The server half (`transport/jls/jls.go` + jls-tls hooks)
//!
//! `jls.Server(ctx, conn, config)` runs a TLS 1.3 SERVER whose
//! ClientHello random is authenticated against the user table
//! (`authenticateJLSClientHello`, jls-tls/jls.go:306-331 — SNI must
//! match, then any user's `jlsCheckFakeRandom` must open the random)
//! and whose ServerHello random is stamped with the same construction
//! (`sendServerParameters`, jls-tls handshake_server_tls13.go:728-742).
//! Nothing is written to the client until the ClientHello authenticated,
//! so on failure the recorded prefix can be relayed to the camouflage
//! `dest` (`canFallbackJLS` jls-tls/jls.go:133-137 keeps pre-write
//! failures silent and discards the buffered flight, conn.go:856-863 /
//! 1584-1592; `relayFallback` jls.go:199-212 dials dest, replays the
//! prefix — `NewCachedConn` — and rate-limits the upstream side,
//! `newRateLimitedConn` jls.go:226-265 with the 10 ms-cycle burst
//! limiter `bitRateLimiter` jls.go:322-335). A wrong password is
//! therefore NOT a hard close: the client lands on the fallback relay
//! and the uTLS client's camouflage HTTP round
//! (`jlsClientHTTPFallback`, utls.go:120-150 — ported in
//! [`jls_client_http_fallback`]) answers it.

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

/// The rustls connection kinds [`JlsSession`] can drive (both deref to
/// their `ConnectionCommon`).
pub trait RlsConn:
    std::ops::DerefMut<Target = rustls::ConnectionCommon<Self::Data>> + Unpin + Send + 'static
{
    type Data: rustls::SideData;
}

impl RlsConn for rustls::ClientConnection {
    type Data = rustls::client::ClientConnectionData;
}

impl RlsConn for rustls::ServerConnection {
    type Data = rustls::server::ServerConnectionData;
}

/// A rustls TLS session driven over a boxed proxy stream, returned by
/// [`connect`] (client) and [`server`](server()) (server half) once the
/// JLS-authenticated handshake completes. The standard complete-io
/// adapter (tokio-rustls' `TlsStream` has no public constructor for an
/// already-handshaked session).
pub struct JlsSession<C: RlsConn> {
    tls: C,
    io: BoxProxyStream,
    /// Wire bytes queued for the transport.
    wbuf: BytesMut,
    close_sent: bool,
}

/// The client-side session ([`connect`]'s return).
pub type JlsTlsStream = JlsSession<rustls::ClientConnection>;

impl<C: RlsConn> JlsSession<C> {
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

impl<C: RlsConn> AsyncRead for JlsSession<C> {
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

impl<C: RlsConn> AsyncWrite for JlsSession<C> {
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
///
/// On a random that does NOT verify the guard does not fail the stream:
/// upstream's failure branch (`verifyUTLSCertificate`, utls.go:183-185,
/// 190-206) decides between "the fallback site is real — complete the
/// handshake" and "fail now". This port's fingerprint path carries no
/// trust store (`InsecureSkipVerify`, utls.go:58-60), so the handshake
/// is always allowed to complete and the shared
/// [`Self::authenticated`] flag tells [`connect_fingerprint`] to run
/// the camouflage HTTP round before surfacing [`ERR_AUTH_FAILED`]
/// (utls.go:106-112).
struct JlsServerHelloGuard {
    io: BoxProxyStream,
    user: JlsUser,
    /// Bytes read ahead of the TLS state machine, served first.
    pending: BytesMut,
    /// First handshake message authenticated (or moot: alert/EOF seen).
    verified: bool,
    /// Sticky hard failure, surfaced on every later operation.
    failed: Option<String>,
    /// Set when the ServerHello random failed JLS authentication while
    /// the handshake itself proceeds (shared with the caller).
    auth_failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl JlsServerHelloGuard {
    fn new(
        io: BoxProxyStream,
        user: JlsUser,
    ) -> (Self, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        let auth_failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        (
            JlsServerHelloGuard {
                io,
                user,
                pending: BytesMut::new(),
                verified: false,
                failed: None,
                auth_failed: auth_failed.clone(),
            },
            auth_failed,
        )
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
                                // VerifyConnection's failure branch
                                // (utls.go:183-185): record it, let the
                                // handshake proceed — the caller runs the
                                // camouflage round (utls.go:106-112).
                                self.auth_failed
                                    .store(true, std::sync::atomic::Ordering::Release);
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
    let (guard, auth_failed) = JlsServerHelloGuard::new(transport, user.clone());
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
    if auth_failed.load(std::sync::atomic::Ordering::Acquire) {
        // `utls.go:106-112`: the handshake completed but the ServerHello
        // random did not verify — finish with a plausible HTTP request
        // over the (non-JLS) tunnel, then return ErrJLSAuthFailed.
        debug!(
            target: "engine",
            sni = %cfg.sni, profile = profile.as_str(),
            "jls: server not JLS-authenticated; running the camouflage HTTP round"
        );
        jls_client_http_fallback(stream, &cfg.sni, profile).await;
        return Err(Error::crypto(ERR_AUTH_FAILED));
    }
    // `utls.go:113-116`'s post-handshake TLS 1.3 check cannot fire:
    // tls13.rs is TLS 1.3-only by construction.
    debug!(
        target: "engine",
        sni = %cfg.sni, profile = profile.as_str(),
        "jls: authenticated fingerprint tunnel established"
    );
    Ok(Box::new(stream))
}

// ------------------------------------------- camouflage HTTP fallback round

/// The uTLS `ClientHelloID.Client` user-agent strings
/// (metacubex/utls u_common.go:158-159: `helloFirefox = "Firefox"`,
/// `helloChrome = "Chrome"`) — what upstream's
/// `request.Header.Set("User-Agent", fingerprint.Client)` sends.
fn fingerprint_user_agent(profile: UtslProfile) -> &'static str {
    match profile {
        UtslProfile::Chrome => "Chrome",
        UtslProfile::Firefox => "Firefox",
    }
}

/// `jlsClientHTTPFallback` (`transport/jls/utls.go:120-150`): after a
/// completed TLS handshake whose ServerHello failed JLS authentication,
/// issue one plausible `GET https://<server-name>` over the established
/// tunnel so the server's fallback relay serves a real-looking page,
/// then close. Errors are swallowed (`if err != nil { return }`); the
/// caller surfaces [`ERR_AUTH_FAILED`] regardless of what happened here.
///
/// Request shape, exactly as upstream builds it:
///
/// * `GET` with URL `https://<server-name>` → request target `/`,
///   authority `<server-name>` (no port in the URL);
/// * `User-Agent: <fingerprint.Client>` (Chrome/Firefox);
/// * `Cookie: padding=<N zeros>` with `N = rand(32)+30` (30..=61);
/// * HTTP/1.1 when the server did not negotiate h2, unencrypted HTTP/2
///   (h2c prior knowledge — the TLS layer is already established) when
///   it did (utls.go:123-129). The engine's minimal h2c client mirrors
///   the one `proto/tlsmirror.rs` built for its enrolment round.
/// * Go's transport transparently adds `Accept-Encoding: gzip`
///   (net/http, no DisableCompression here) — included.
///
/// Upstream branches on `verifyUTLSCertificate` (utls.go:190-206)
/// BEFORE this round: a certificate that fails system-pool verification
/// fails the handshake outright with no HTTP request. This port's
/// fingerprint path has no trust store (`InsecureSkipVerify`,
/// utls.go:58-60), so the round runs for every completed handshake —
/// the precise deviation.
async fn jls_client_http_fallback(
    mut conn: engine_tls13::Tls13Stream,
    server_name: &str,
    profile: UtslProfile,
) {
    use tokio::io::AsyncWriteExt;
    // `defer uConn.Close()`: the conn is dropped when this returns.
    let alpn_h2 = conn.alpn() == Some(b"h2".as_slice());
    use rand::Rng;
    let mut padding = String::with_capacity(61);
    padding.push_str(
        &(0..rand::rngs::OsRng.gen_range(30..=61))
            .map(|_| '0')
            .collect::<String>(),
    );
    let user_agent = fingerprint_user_agent(profile);
    // `ConnectionState().NegotiatedProtocol == "h2"` (utls.go:125):
    // h2c when the tunnel negotiated h2, HTTP/1 otherwise.
    let result: Result<()> = if alpn_h2 {
        h2_camo_get(&mut conn, server_name, user_agent, &padding).await
    } else {
        http1_camo_get(&mut conn, server_name, user_agent, &padding).await
    };
    // response.Body.Close() + client.CloseIdleConnections(): the conn is
    // simply closed here; every error is silent (utls.go:144-149).
    let _ = result;
    let _ = conn.shutdown().await;
}

/// `http1_camo_get`: the HTTP/1.1 form of the camouflage request.
async fn http1_camo_get<W>(
    conn: &mut W,
    server_name: &str,
    user_agent: &str,
    padding: &str,
) -> Result<()>
where
    W: tokio::io::AsyncRead + Unpin + tokio::io::AsyncWrite + Unpin,
{
    tokio::io::AsyncWriteExt::write_all(
        conn,
        format!(
            "GET / HTTP/1.1\r\n\
             Host: {server_name}\r\n\
             User-Agent: {user_agent}\r\n\
             Accept-Encoding: gzip\r\n\
             Cookie: padding={padding}\r\n\
             \r\n"
        )
        .as_bytes(),
    )
    .await?;
    tokio::io::AsyncWriteExt::flush(conn).await?;
    // `client.Do`: the response head must arrive; the body is closed
    // unread. Read to the end of the headers (bounded), then stop.
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = tokio::io::AsyncReadExt::read(conn, &mut chunk).await?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() > 64 * 1024 {
            break;
        }
    }
    Ok(())
}

/// The h2c form (utls.go:123-129 `SetUnencryptedHTTP2(true)`): a
/// prior-knowledge HTTP/2 GET over the already-established tunnel. The
/// minimal client mirrors `proto/tlsmirror.rs`'s `h2c_post` (preface +
/// SETTINGS + one literal-HPACK HEADERS; the response head is awaited,
/// the body closed).
async fn h2_camo_get<W>(
    conn: &mut W,
    server_name: &str,
    user_agent: &str,
    padding: &str,
) -> Result<()>
where
    W: tokio::io::AsyncRead + Unpin + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // The h2c helpers (frame/HPACK) are local to tlsmirror; the shapes
    // are re-implemented here for a GET.
    fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        out.push(kind);
        out.push(flags);
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }
    /// HPACK literal-without-indexing, new name, no Huffman
    /// (RFC 7541 §6.2.2 — tlsmirror's `hpack_literal_header`).
    fn hpack_header(out: &mut Vec<u8>, name: &str, value: &str) {
        fn hpack_integer(out: &mut Vec<u8>, value: usize, prefix_bits: u32, first_byte: u8) {
            let max = (1usize << prefix_bits) - 1;
            if value < max {
                out.push(first_byte | value as u8);
                return;
            }
            out.push(first_byte | max as u8);
            let mut rest = value - max;
            while rest >= 0x80 {
                out.push(rest as u8 | 0x80);
                rest >>= 7;
            }
            out.push(rest as u8);
        }
        fn hpack_string(out: &mut Vec<u8>, value: &[u8]) {
            hpack_integer(out, value.len(), 7, 0x00);
            out.extend_from_slice(value);
        }
        out.push(0x00);
        hpack_string(out, name.as_bytes());
        hpack_string(out, value.as_bytes());
    }

    conn.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await?;
    // SETTINGS_INITIAL_WINDOW_SIZE (0x4) = 1 MiB, like tlsmirror's.
    let mut settings = Vec::new();
    settings.extend_from_slice(&0x4u16.to_be_bytes());
    settings.extend_from_slice(&(1u32 << 20).to_be_bytes());
    conn.write_all(&h2_frame(0x4 /* SETTINGS */, 0, 0, &settings))
        .await?;

    let mut block = Vec::new();
    hpack_header(&mut block, ":method", "GET");
    hpack_header(&mut block, ":scheme", "https");
    hpack_header(&mut block, ":authority", server_name);
    hpack_header(&mut block, ":path", "/");
    hpack_header(&mut block, "user-agent", user_agent);
    hpack_header(&mut block, "accept-encoding", "gzip");
    hpack_header(&mut block, "cookie", &format!("padding={padding}"));
    conn.write_all(&h2_frame(
        0x1, /* HEADERS */
        0x4 | 0x1, /* END_HEADERS | END_STREAM (no body on a GET) */
        1,
        &block,
    ))
    .await?;
    conn.flush().await?;

    // Await the response head (HEADERS on stream 1); SETTINGS get an
    // ACK, everything else is read and discarded until then.
    let mut head = [0u8; 9];
    loop {
        conn.read_exact(&mut head).await?;
        let len =
            usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
        let kind = head[3];
        let flags = head[4];
        let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]);
        let mut payload = vec![0u8; len];
        conn.read_exact(&mut payload).await?;
        match kind {
            0x4 /* SETTINGS */ if flags & 0x1 == 0 => {
                let _ = conn.write_all(&h2_frame(0x4, 0x1, 0, &[])).await;
            }
            0x1 /* HEADERS */ if stream == 1 => return Ok(()),
            0x7 /* GOAWAY */ => return Ok(()),
            _ => {}
        }
    }
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

// ------------------------------------------------------------------ server
// transport/jls/jls.go:121-197 (NewServerConfig/Server) + the jls-tls
// server hooks (authenticateJLSClientHello / ServerHello stamping /
// canFallbackJLS).

/// `rateLimitCycle` (jls.go:31): the limiter's refill cycle.
const RATE_LIMIT_CYCLE_DIVISOR: u64 = 100; // 1s / 10ms
/// `maxRateLimitBurstBytes` (jls.go:32).
const MAX_RATE_LIMIT_BURST_BYTES: u64 = 64 * 1024;

/// The server half of `NewServerConfig` (transport/jls/jls.go:121-174):
/// the validated user table, the SNI the ClientHello must carry
/// (`JLSConfig.ServerName`, checked by `checkServerName`,
/// jls-tls/jls.go:378-383) and the ALPN to negotiate. The camouflage
/// certificate is generated at random once per config — upstream
/// `ca.NewRandomTLSKeyPair` (jls.go:154-161, "JLS authenticates the
/// peer, so this generated certificate only carries the TLS handshake");
/// here a minimal self-signed P-256 X.509 built with `ring` (`rcgen` is
/// a dev-only dependency).
#[derive(Debug, Clone)]
pub struct JlsServerConfig {
    /// Empty = accept any SNI (`checkServerName` with a cfg-less name).
    pub sni: String,
    pub users: Vec<JlsUser>,
    pub alpn: Vec<String>,
    tls: Arc<rustls::ServerConfig>,
}

impl JlsServerConfig {
    /// `NewServerConfig` (jls.go:121-174): at least one fully-specified
    /// user; `alpn` defaults to [`DEFAULT_ALPN`] (jls.go:166-168); the
    /// server is TLS 1.3-only (`MinVersion: VersionTLS13`, jls.go:169).
    pub fn new(sni: &str, users: Vec<JlsUser>, alpn: Vec<String>) -> Result<Self> {
        if users.is_empty() {
            return Err(Error::config("jls: at least one user is required"));
        }
        for user in &users {
            if user.username.is_empty() {
                return Err(Error::config("jls: username is required"));
            }
            if user.password.is_empty() {
                return Err(Error::config("jls: password is required"));
            }
        }
        let alpn = if alpn.is_empty() {
            DEFAULT_ALPN.iter().map(|s| s.to_string()).collect()
        } else {
            alpn
        };
        let tls = Arc::new(jls_server_tls_config(sni, &alpn)?);
        Ok(JlsServerConfig {
            sni: sni.to_string(),
            users,
            alpn,
            tls,
        })
    }
}

/// The rustls server config behind a [`JlsServerConfig`]: the JLS crypto
/// provider (scripted random + the fixed X25519 group — the ServerHello
/// stamping needs the two passes to marshal identical flights, same
/// machinery as the client) with the random camouflage certificate.
fn jls_server_tls_config(sni: &str, alpn: &[String]) -> Result<rustls::ServerConfig> {
    let (cert, key) = generate_camouflage_cert()?;
    let mut provider = ring_provider::default_provider();
    provider.secure_random = &JLS_RANDOM;
    provider.kx_groups = vec![&FIXED_X25519];
    let provider = Arc::new(provider);
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::config(format!("jls: tls: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| Error::config(format!("jls: camouflage certificate: {e}")))?;
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    let _ = sni; // checked against the ClientHello directly (checkServerName)
    Ok(config)
}

// -- minimal self-signed P-256 camouflage certificate (DER by hand) -------

/// `der_put`: one DER TLV (length forms up to 2 bytes — every field of a
/// minimal cert fits).
fn der_put(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else if body.len() <= 0xff {
        out.push(0x81);
        out.push(body.len() as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(body);
}

/// `Name (SEQUENCE{SET{SEQUENCE{OID commonName, UTF8String}}})`.
fn der_name(cn: &str) -> Vec<u8> {
    let mut attr = Vec::new();
    der_put(&mut attr, 0x06, &[0x55, 0x04, 0x03]); // 2.5.4.3 commonName
    der_put(&mut attr, 0x0c, cn.as_bytes()); // UTF8String
    let mut rdn = Vec::new();
    der_put(&mut rdn, 0x30, &attr);
    let mut set = Vec::new();
    der_put(&mut set, 0x31, &rdn);
    let mut name = Vec::new();
    der_put(&mut name, 0x30, &set);
    name
}

/// `UTCTime "YYMMDDHHMMSSZ"` for `days`-after/before-epoch civil dates
/// (Howard Hinnant's civil-from-days).
fn der_utctime(unix_secs: i64) -> Vec<u8> {
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let (h, mi, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    // UTCTime carries a two-digit year (RFC 5280 §4.1.2.5.1).
    format!("{:02}{m:02}{d:02}{h:02}{mi:02}{s:02}Z", y.rem_euclid(100)).into_bytes()
}

/// `ca.NewRandomTLSKeyPair` equivalent (jls.go:154-161): a fresh
/// self-signed ECDSA P-256 certificate with a random common name and
/// serial. The engine's own client paths never verify the chain (JLS
/// authenticates the peer), so the minimal shape suffices.
fn generate_camouflage_cert(
) -> Result<(
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rng,
    )
    .map_err(|_| Error::crypto("jls: camouflage key generation failed"))?;
    let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .map_err(|_| Error::crypto("jls: camouflage key parse failed"))?;

    // SubjectPublicKeyInfo: ecPublicKey + prime256v1, uncompressed point.
    let mut alg = Vec::new();
    der_put(&mut alg, 0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]); // 1.2.840.10045.2.1
    der_put(&mut alg, 0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]); // prime256v1
    let mut alg_id = Vec::new();
    der_put(&mut alg_id, 0x30, &alg);
    let mut spki_bitstring = Vec::new();
    spki_bitstring.push(0x00); // unused bits
    spki_bitstring.extend_from_slice(ring::signature::KeyPair::public_key(&pair).as_ref());
    let mut spki_body = alg_id;
    let mut bit = Vec::new();
    der_put(&mut bit, 0x03, &spki_bitstring);
    spki_body.extend_from_slice(&bit);
    let mut spki = Vec::new();
    der_put(&mut spki, 0x30, &spki_body);

    // Signature algorithm: ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
    let mut sig_alg = Vec::new();
    der_put(
        &mut sig_alg,
        0x30,
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
    );

    // Random common name (hex) and a positive, minimally-encoded serial.
    let mut cn_bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut cn_bytes);
    let cn: String = cn_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let name = der_name(&cn);
    let mut serial_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut serial_bytes);
    let mut serial: Vec<u8> = serial_bytes.to_vec();
    while serial.first() == Some(&0) {
        serial.remove(0);
    }
    if serial.is_empty() || serial[0] & 0x80 != 0 {
        serial.insert(0, 0x00); // keep positive, minimally
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut validity = Vec::new();
    der_put(&mut validity, 0x17, &der_utctime(now - 86_400)); // UTCTime notBefore
    der_put(&mut validity, 0x17, &der_utctime(now + 8 * 365 * 86_400)); // ~8y

    // tbsCertificate.
    let mut tbs = Vec::with_capacity(512);
    der_put(&mut tbs, 0xa0, &[0x02, 0x01, 0x02]); // [0] EXPLICIT version v3
    der_put(&mut tbs, 0x02, &serial);
    tbs.extend_from_slice(&sig_alg);
    tbs.extend_from_slice(&name); // issuer (self-signed)
    let mut validity_seq = Vec::new();
    der_put(&mut validity_seq, 0x30, &validity);
    tbs.extend_from_slice(&validity_seq);
    tbs.extend_from_slice(&name); // subject
    tbs.extend_from_slice(&spki);

    let signature = pair
        .sign(&rng, &tbs)
        .map_err(|_| Error::crypto("jls: camouflage certificate signing failed"))?;
    let mut sig_bit = Vec::new();
    sig_bit.push(0x00);
    sig_bit.extend_from_slice(signature.as_ref());
    let mut sig_field = Vec::new();
    der_put(&mut sig_field, 0x03, &sig_bit);

    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm,
    //                             signatureValue BIT STRING } — the TBS gets
    // its own wrapper and the signature covers exactly its content.
    let mut tbs_seq = Vec::with_capacity(tbs.len() + 4);
    der_put(&mut tbs_seq, 0x30, &tbs);
    let mut body = tbs_seq;
    body.extend_from_slice(&sig_alg);
    body.extend_from_slice(&sig_field);
    let mut cert = Vec::with_capacity(body.len() + 4);
    der_put(&mut cert, 0x30, &body);

    Ok((
        rustls::pki_types::CertificateDer::from(cert),
        rustls::pki_types::PrivateKeyDer::Pkcs8(
            pkcs8.as_ref().to_vec().into(),
        ),
    ))
}

// -- ClientHello sniffing (the handshakeRecorderConn prefix) --------------

/// `clientHelloSNI`: the `server_name` extension of a serialized
/// ClientHello handshake message (after its 4-byte header).
fn client_hello_sni(hello: &[u8]) -> Option<String> {
    let mut off = HELLO_HEADER_LEN;
    let skip = |hello: &[u8], off: &mut usize, len_len: usize| -> Option<()> {
        let end = off.checked_add(len_len)?;
        let mut len = 0usize;
        for &b in hello.get(*off..end)? {
            len = (len << 8) | usize::from(b);
        }
        *off = end.checked_add(len)?;
        Some(())
    };
    // legacy_version(2, fixed) random(32) session_id(1+len)
    // cipher_suites(2+len) compression_methods(1+len) extensions(2+len)
    off = off.checked_add(2)?;
    off = off.checked_add(HELLO_RANDOM_LEN)?;
    let sid_len = usize::from(*hello.get(off)?);
    off = off.checked_add(1 + sid_len)?;
    skip(hello, &mut off, 2)?;
    skip(hello, &mut off, 1)?;
    let ext_end = hello.len();
    let mut ext_len = 0usize;
    for &b in hello.get(off..off.checked_add(2)?)? {
        ext_len = (ext_len << 8) | usize::from(b);
    }
    off += 2;
    let ext_end = (off + ext_len).min(ext_end);
    while off + 4 <= ext_end {
        let etype = u16::from_be_bytes([hello[off], hello[off + 1]]);
        let elen = u16::from_be_bytes([hello[off + 2], hello[off + 3]]) as usize;
        let body = off + 4;
        if etype == 0x0000 && elen >= 2 {
            // ServerNameList: list length (2), then (type(1), len(2),
            // name)*; host_name = type 0 (RFC 6066 §3).
            let list_end = (body + elen).min(ext_end);
            let mut list_len = 0usize;
            for &b in hello.get(body..body.checked_add(2)?)? {
                list_len = (list_len << 8) | usize::from(b);
            }
            let mut p = body + 2;
            let walk_end = (p + list_len).min(list_end);
            while p + 3 <= walk_end {
                let ntype = hello[p];
                let nlen = u16::from_be_bytes([hello[p + 1], hello[p + 2]]) as usize;
                let name_start = p + 3;
                if ntype == 0
                    && name_start + nlen <= walk_end
                    && std::str::from_utf8(&hello[name_start..name_start + nlen]).is_ok()
                {
                    return Some(
                        String::from_utf8_lossy(&hello[name_start..name_start + nlen])
                            .into_owned(),
                    );
                }
                p = name_start + nlen;
            }
        }
        off = body.checked_add(elen)?;
    }
    None
}

/// Read records until the first handshake message (the ClientHello) is
/// whole — the `handshakeRecorderConn` recording window
/// (transport/jls/jls.go:338-389). Returns every raw byte consumed (the
/// fallback prefix, `recorder.stop()`) and the serialized handshake
/// message (empty/None = the client never sent a parsable ClientHello;
/// every byte read is still recorded into `prefix`, like the recorder).
async fn read_client_hello(
    io: &mut BoxProxyStream,
    rbuf: &mut BytesMut,
    prefix: &mut Vec<u8>,
) -> Option<Vec<u8>> {
    let mut handshake: Vec<u8> = Vec::new();
    // EOF / non-TLS garbage mid-sniff: record what arrived and fail —
    // Go's record parser errors the same way ("first record does not
    // look like a TLS handshake") and the fallback still gets the bytes.
    let bail = |rbuf: &mut BytesMut, prefix: &mut Vec<u8>| {
        prefix.extend_from_slice(rbuf);
    };
    loop {
        while rbuf.len() < RECORD_HEADER_LEN {
            let mut tmp = [0u8; 16 * 1024];
            match io.read(&mut tmp).await {
                Ok(0) | Err(_) => {
                    bail(rbuf, prefix);
                    return None;
                }
                Ok(n) => rbuf.extend_from_slice(&tmp[..n]),
            }
        }
        let rtype = rbuf[0];
        let rlen = usize::from(u16::from_be_bytes([rbuf[3], rbuf[4]]));
        if !(20..=23).contains(&rtype)
            || rbuf[1] != 0x03
            || RECORD_HEADER_LEN + rlen > MAX_RECORD_LEN
        {
            bail(rbuf, prefix);
            return None;
        }
        while rbuf.len() < RECORD_HEADER_LEN + rlen {
            let mut tmp = [0u8; 16 * 1024];
            match io.read(&mut tmp).await {
                Ok(0) | Err(_) => {
                    bail(rbuf, prefix);
                    return None;
                }
                Ok(n) => rbuf.extend_from_slice(&tmp[..n]),
            }
        }
        let record = rbuf.split_to(RECORD_HEADER_LEN + rlen).to_vec();
        prefix.extend_from_slice(&record);
        if rtype == REC_HANDSHAKE {
            handshake.extend_from_slice(&record[RECORD_HEADER_LEN..]);
            if handshake.len() >= HELLO_HEADER_LEN {
                let mlen = (usize::from(handshake[1]) << 16)
                    | (usize::from(handshake[2]) << 8)
                    | usize::from(handshake[3]);
                if handshake.len() >= HELLO_HEADER_LEN + mlen {
                    handshake.truncate(HELLO_HEADER_LEN + mlen);
                    if handshake.first() == Some(&HS_CLIENT_HELLO) {
                        return Some(handshake);
                    }
                    bail(rbuf, prefix);
                    return None; // a handshake message that is not a ClientHello
                }
            }
        }
        // ChangeCipherSpec (compat) or an early alert before the hello
        // completes: keep recording, keep waiting.
    }
}

/// `authenticateJLSClientHello` (jls-tls/jls.go:306-331): SNI must match
/// `sni` when set (`checkServerName`, jls.go:378-383), then some user's
/// `jlsCheckFakeRandom` must open the hello random. `None` = the
/// authentication failed (upstream `errJLSAuthFailed`).
fn authenticate_client_hello(cfg: &JlsServerConfig, hello: &[u8]) -> Option<JlsUser> {
    let auth_data = hello_auth_data(hello, HS_CLIENT_HELLO).ok()?;
    let random = hello.get(HELLO_RANDOM_OFFSET..HELLO_RANDOM_OFFSET + HELLO_RANDOM_LEN)?;
    let sni = client_hello_sni(hello);
    if !cfg.sni.is_empty() && sni.as_deref().unwrap_or("") != cfg.sni {
        return None;
    }
    cfg.users
        .iter()
        .find(|user| check_fake_random(user, random, &auth_data))
        .cloned()
}

/// The outcome of `jls.Server`'s handshake phase
/// (transport/jls/jls.go:176-197).
pub enum JlsServerHandshake {
    /// `ErrJLSAuthFailed`-free path: the authenticated user
    /// (`ConnectionState().JLS.User`, jls.go:192-196) and the plaintext
    /// TLS stream.
    Authenticated {
        stream: BoxProxyStream,
        user: String,
    },
    /// The handshake failed with NOTHING written to the client
    /// (`canFallbackJLS`, jls-tls/jls.go:133-137 — the alert is
    /// suppressed, conn.go:856-863, and the buffered flight discarded,
    /// conn.go:1584-1592): upstream runs `relayFallback` here and
    /// reports `ErrFallbackCompleted`; this port hands the conn + the
    /// recorded prefix to the listener, which relays toward `dest`.
    Fallback { conn: BoxProxyStream, prefix: Vec<u8> },
}

/// `jls.Server` (transport/jls/jls.go:176-197): run the JLS-authenticated
/// TLS 1.3 server handshake over `conn` (this function dials nothing).
///
/// * [`JlsServerHandshake::Authenticated`] — the ClientHello random
///   verified for one of `cfg.users`; the returned stream is the
///   plaintext TLS session whose ServerHello random carries the same
///   authentication (`sendServerParameters`,
///   jls-tls/handshake_server_tls13.go:728-742 — reproduced with the
///   two-pass random-stamp below).
/// * [`JlsServerHandshake::Fallback`] — the client is not an
///   authenticated JLS client for this table (plain TLS, wrong
///   password, wrong SNI, non-TLS bytes, or a JLS client that would
///   need HelloRetryRequest, which JLS v3 forbids —
///   handshake_server_tls13.go:242-247); nothing has been written.
/// * `Err` — the handshake failed AFTER a flight reached the client
///   (`recorder.wroteToClient()`, jls.go:183-186): the caller closes.
pub async fn server(
    cfg: &JlsServerConfig,
    conn: BoxProxyStream,
) -> Result<JlsServerHandshake> {
    let mut conn = conn;
    let mut rbuf = BytesMut::with_capacity(16 * 1024);
    let mut prefix = Vec::new();
    let hello = read_client_hello(&mut conn, &mut rbuf, &mut prefix).await;
    let Some(hello) = hello else {
        return Ok(JlsServerHandshake::Fallback { conn, prefix });
    };
    let Some(user) = authenticate_client_hello(cfg, &hello) else {
        return Ok(JlsServerHandshake::Fallback { conn, prefix });
    };

    // The authenticated rustls server with the stamped ServerHello.
    let (mut tls, flight) = stamped_server_handshake(&cfg.tls, &prefix, &user)?;
    conn.write_all(&flight).await?;
    conn.flush().await?;
    while tls.is_handshaking() {
        let record = read_one_record(&mut conn, &mut rbuf).await?;
        feed_records(&mut tls, &record).map_err(|e| Error::network(format!("jls: tls read: {e}")))?;
        tls.process_new_packets().map_err(|e| {
            // A flight already reached the client: hard failure, no
            // fallback (recorder.wroteToClient, jls.go:183-186).
            Error::network(format!("jls: TLS handshake failed: {e}"))
        })?;
        let out = drain_server_tls(&mut tls);
        if !out.is_empty() {
            conn.write_all(&out).await?;
            conn.flush().await?;
        }
    }
    debug!(
        target: "engine",
        user = %user.username,
        "jls: server authenticated {} ({} users)",
        user.username,
        cfg.users.len()
    );
    // Records that arrived together with the Finished (early app data,
    // or this rustls server's session tickets) may still sit in the
    // read buffer — replay them into the session's transport.
    let leftover: Vec<u8> = rbuf.to_vec();
    let io: BoxProxyStream = if leftover.is_empty() {
        conn
    } else {
        Box::new(crate::inbound::PrependStream::new(conn, leftover))
    };
    Ok(JlsServerHandshake::Authenticated {
        stream: Box::new(JlsSession {
            tls,
            io,
            wbuf: BytesMut::new(),
            close_sent: false,
        }),
        user: user.username,
    })
}

fn drain_server_tls(tls: &mut rustls::ServerConnection) -> Vec<u8> {
    let mut out = Vec::new();
    while tls.wants_write() {
        if tls.write_tls(&mut out).unwrap_or(0) == 0 {
            break;
        }
    }
    out
}

/// The ServerHello random stamp — `sendServerParameters`'s JLS hook
/// (jls-tls/handshake_server_tls13.go:728-742): the server's hello
/// random becomes `jlsBuildFakeRandom(user, random[:16],
/// serverHelloAuthData)`. rustls offers no random hook, so two passes
/// run under the scripted-random/fixed-key machinery (the mirror of the
/// client's [`build_stamped_client_hello`]): pass one marshals the
/// flight and derives the authData; pass two replays its draws with the
/// ServerHello random replaced. The bytes the client hashes into its
/// transcript are exactly flight2's.
fn stamped_server_handshake(
    config: &Arc<rustls::ServerConfig>,
    client_flight: &[u8],
    user: &JlsUser,
) -> Result<(rustls::ServerConnection, Vec<u8>)> {
    // Fixed X25519 pair shared by both passes (a fresh ephemeral per
    // connection, like the Go server).
    let mut scalar = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut scalar);
    let public = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(scalar).0;
    FIXED_KEY.with(|k| k.set(Some((scalar, public))));

    let stamp = (|| {
        // Pass 1: record the draws, marshal the flight.
        DRAW_SCRIPT.with_borrow_mut(|s| s.clear());
        DRAWN.with_borrow_mut(|d| d.clear());
        let mut cursor = client_flight;
        let mut pass1 = rustls::ServerConnection::new(config.clone())
            .map_err(|e| Error::config(format!("jls: TLS server init: {e}")))?;
        pass1
            .read_tls(&mut cursor)
            .map_err(|e| Error::network(format!("jls: tls read: {e}")))?;
        pass1
            .process_new_packets()
            .map_err(|e| Error::network(format!("jls: TLS handshake failed: {e}")))?;
        let flight1 = drain_server_tls(&mut pass1);
        if flight1.len() < RECORD_RANDOM_OFFSET + HELLO_RANDOM_LEN
            || flight1[RECORD_HEADER_LEN] != HS_SERVER_HELLO
        {
            return Err(Error::crypto(
                "jls: unexpected server flight shape (rustls ServerHello layout changed)",
            ));
        }
        let sh_len = usize::from(u16::from_be_bytes([flight1[3], flight1[4]]));
        let random1 = record_random(&flight1[..RECORD_HEADER_LEN + sh_len])
            .ok_or_else(|| Error::crypto("jls: short ServerHello"))?;
        // JLS v3 forbids HelloRetryRequest (handshake_server_tls13.go:
        // 242-247): an authenticated client forcing HRR fails BEFORE
        // anything is written — the caller falls back.
        if random1[random1.len() - HRR_RANDOM_SUFFIX.len()..] == *HRR_RANDOM_SUFFIX {
            return Err(Error::protocol(
                "jls: client requires HelloRetryRequest (JLS v3 forbids it)",
            ));
        }
        let sh_auth = hello_auth_data(
            &flight1[RECORD_HEADER_LEN..RECORD_HEADER_LEN + sh_len],
            HS_SERVER_HELLO,
        )?;
        let mut seed = [0u8; RANDOM_SEED_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let fake = build_fake_random(user, &seed, &sh_auth)?;

        // Pass 2: replay every draw with the server random replaced (the
        // server's first 32-byte draw is the ServerHello random).
        let drawn = DRAWN.with_borrow(|d| d.clone());
        let pos = drawn
            .iter()
            .position(|d| d.len() == HELLO_RANDOM_LEN)
            .ok_or_else(|| Error::crypto("jls: no server random recorded"))?;
        let mut script = drawn;
        script[pos] = fake.to_vec();
        DRAW_SCRIPT.with_borrow_mut(|s| *s = script);

        let mut cursor = client_flight;
        let mut pass2 = rustls::ServerConnection::new(config.clone())
            .map_err(|e| Error::config(format!("jls: TLS server init: {e}")))?;
        pass2
            .read_tls(&mut cursor)
            .map_err(|e| Error::network(format!("jls: tls read: {e}")))?;
        pass2
            .process_new_packets()
            .map_err(|e| Error::network(format!("jls: TLS handshake failed: {e}")))?;
        let flight2 = drain_server_tls(&mut pass2);
        DRAW_SCRIPT.with_borrow_mut(|s| s.clear());
        // The ServerHello record must match outside the random; the
        // later (encrypted) records may differ legitimately — the
        // CertificateVerify signature randomizes its ECDSA nonce.
        let sh_len2 = usize::from(u16::from_be_bytes([flight2[3], flight2[4]]));
        if sh_len2 != sh_len
            || flight2[..RECORD_RANDOM_OFFSET] != flight1[..RECORD_RANDOM_OFFSET]
            || flight2[RECORD_RANDOM_OFFSET + HELLO_RANDOM_LEN..RECORD_HEADER_LEN + sh_len]
                != flight1[RECORD_RANDOM_OFFSET + HELLO_RANDOM_LEN..RECORD_HEADER_LEN + sh_len]
        {
            return Err(Error::crypto(
                "jls: server stamping drifted outside the random (rustls ServerHello layout changed)",
            ));
        }
        Ok((pass2, flight2))
    })();
    FIXED_KEY.with(|k| k.set(None));
    DRAW_SCRIPT.with_borrow_mut(|s| s.clear());
    DRAWN.with_borrow_mut(|d| d.clear());
    stamp
}

// -- the fallback relay (relayFallback + rateLimitedConn, jls.go:199-335) --

/// `bitRateLimiter` (transport/jls/jls.go:322-335): a reserveN pacer —
/// every `n` bytes reserve `n * 8 / rateBps` seconds, starting at
/// `max(next, now)`.
struct BitRateLimiter {
    rate_bps: u64,
    next: Option<tokio::time::Instant>,
}

impl BitRateLimiter {
    fn new(rate_bps: u64) -> Self {
        BitRateLimiter {
            rate_bps,
            next: None,
        }
    }

    async fn wait_n(&mut self, n: usize) {
        if self.rate_bps == 0 {
            return;
        }
        // interval = n * 8 * Second / rateBps, in microseconds.
        let interval_us = (n as u64).saturating_mul(8).saturating_mul(1_000_000)
            / self.rate_bps.max(1);
        let now = tokio::time::Instant::now();
        let ready = self.next.map_or(now, |t| t.max(now));
        self.next = Some(ready + std::time::Duration::from_micros(interval_us));
        let delay = ready.saturating_duration_since(now);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

/// `newRateLimitedConn`'s burst (jls.go:237-247):
/// `rateBps / 8 / (Second / rateLimitCycle)`, clamped to
/// `1..=maxRateLimitBurstBytes`.
fn rate_limit_burst(rate_bps: u64) -> usize {
    let burst = rate_bps / 8 / RATE_LIMIT_CYCLE_DIVISOR;
    burst.clamp(1, MAX_RATE_LIMIT_BURST_BYTES) as usize
}

/// `relayFallback` (transport/jls/jls.go:199-212): relay the raw client
/// conn — the recorded prefix replayed first (`N.NewCachedConn`) —
/// toward the camouflage `dest`, the upstream side rate-limited
/// (`newRateLimitedConn`, jls.go:226-265: reads capped at the burst and
/// paced after n bytes; writes paced per burst chunk before writing).
///
/// Upstream's `DialContext` routes the camouflage conn through
/// `inner.HandleTcp`; the engine's [`crate::inbound::RelayHandler`] is
/// receive-only, so the caller dials `dest` directly — the same
/// adaptation as the restls/tlsmirror listeners. A completed relay
/// surfaces upstream's `ErrFallbackCompleted` sentinel; here the plain
/// `Ok(())` return IS the sentinel (the caller logs and closes).
pub async fn relay_fallback(
    conn: BoxProxyStream,
    prefix: Vec<u8>,
    dest: crate::addr::NetAddr,
    rate_limit_bps: u64,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = dial_fallback_dest(&dest).await?;
    let inbound = crate::inbound::PrependStream::new(conn, prefix);
    let (mut client_rd, mut client_wr) = tokio::io::split(inbound);
    let (mut up_rd, mut up_wr) = tokio::io::split(upstream);

    if rate_limit_bps == 0 {
        // N.RelayContext, unthrottled. Each direction closes its write
        // half the moment it ends (otherwise a half-closed client would
        // hold the dest — and the other direction — open forever).
        let a = async {
            let _ = tokio::io::copy(&mut client_rd, &mut up_wr).await;
            let _ = up_wr.shutdown().await;
        };
        let b = async {
            let _ = tokio::io::copy(&mut up_rd, &mut client_wr).await;
            let _ = client_wr.shutdown().await;
        };
        let _ = tokio::join!(a, b);
        return Ok(());
    }
    let burst = rate_limit_burst(rate_limit_bps);
    // client → dest: the upstream Write side (WaitN before each chunk).
    let c2d = async move {
        let mut limiter = BitRateLimiter::new(rate_limit_bps);
        let mut buf = vec![0u8; burst];
        loop {
            match client_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    limiter.wait_n(n).await;
                    if up_wr.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = up_wr.shutdown().await;
    };
    // dest → client: the upstream Read side (WaitN after n bytes).
    let d2c = async move {
        let mut limiter = BitRateLimiter::new(rate_limit_bps);
        let mut buf = vec![0u8; burst];
        loop {
            match up_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    limiter.wait_n(n).await;
                    if client_wr.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = client_wr.shutdown().await;
    };
    let _ = tokio::join!(c2d, d2c);
    Ok(())
}

/// Dial the camouflage dest (`config.DialContext(ctx, "tcp",
/// config.Dest)`).
async fn dial_fallback_dest(dest: &crate::addr::NetAddr) -> Result<tokio::net::TcpStream> {
    let stream = match &dest.host {
        crate::addr::Host::Ip(ip) => {
            tokio::net::TcpStream::connect(std::net::SocketAddr::new(*ip, dest.port))
                .await
                .map_err(|e| Error::network(format!("jls: fallback dial {}: {e}", dest)))?
        }
        crate::addr::Host::Domain(domain) => {
            tokio::net::TcpStream::connect((domain.as_str(), dest.port))
                .await
                .map_err(|e| Error::network(format!("jls: fallback dial {}: {e}", dest)))?
        }
    };
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{Duration, Instant};

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

    /// A production [`JlsServerConfig`] for the loopback pair (the test
    /// credentials below are fake, never real secrets).
    fn test_server_cfg(users: &[JlsUser]) -> JlsServerConfig {
        JlsServerConfig::new("jls.test", users.to_vec(), Vec::new()).expect("server config")
    }

    /// The JLS server side, now the production [`server`] half: the
    /// ClientHello random must verify against the user table
    /// (authenticateJLSClientHello, jls-tls/jls.go:306-331) and the
    /// ServerHello random is stamped server-side. Falls back quietly on
    /// a non-JLS/wrong-credential client; echoes decrypted application
    /// data once authenticated.
    async fn jls_server_mimic(
        io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        user: JlsUser,
        config: JlsServerConfig,
    ) -> std::result::Result<(), String> {
        match server(&config, Box::new(io)).await {
            Ok(JlsServerHandshake::Authenticated { mut stream, user: who }) => {
                // UserFromConn (transport/jls/jls.go:192-196): the
                // authenticated user is recoverable per conn.
                assert_eq!(who, user.username);
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return Ok(()), // client closed the tunnel
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return Ok(());
                            }
                        }
                    }
                }
            }
            Ok(JlsServerHandshake::Fallback { .. }) => {
                Err("ClientHello random failed JLS authentication".into())
            }
            Err(e) => Err(e.to_string()),
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
        let server_config = test_server_cfg(std::slice::from_ref(user));
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
        let server_config = test_server_cfg(std::slice::from_ref(&server_user));
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
        let user = JlsUser::new(&cfg.username, &cfg.password).unwrap();
        let server_config = test_server_cfg(std::slice::from_ref(&user));
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
        let server_user = JlsUser::new("user1", "other-pass").unwrap();
        let server_config = test_server_cfg(std::slice::from_ref(&server_user));
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

    // ------------------------------------------------------ server half

    #[test]
    fn server_config_validations_mirror_new_server_config() {
        // NewServerConfig (transport/jls/jls.go:121-150): users required.
        assert!(JlsServerConfig::new("jls.test", Vec::new(), Vec::new()).is_err());
        assert!(JlsServerConfig::new(
            "jls.test",
            vec![JlsUser {
                username: String::new(),
                password: "pw".into()
            }],
            Vec::new()
        )
        .is_err());
        assert!(JlsServerConfig::new(
            "jls.test",
            vec![JlsUser {
                username: "u".into(),
                password: String::new()
            }],
            Vec::new()
        )
        .is_err());
        let cfg = JlsServerConfig::new(
            "jls.test",
            vec![JlsUser::new("user1", "pass1").unwrap()],
            Vec::new(),
        )
        .unwrap();
        // alpn == nil → DefaultALPN (jls.go:166-168).
        assert_eq!(cfg.alpn, DEFAULT_ALPN.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let cfg = JlsServerConfig::new(
            "jls.test",
            vec![JlsUser::new("user1", "pass1").unwrap()],
            vec!["h2".into()],
        )
        .unwrap();
        assert_eq!(cfg.alpn, vec!["h2".to_string()]);
    }

    #[test]
    fn camouflage_certificate_parses_as_p256_x509() {
        // The ring-built camouflage cert must be a well-formed X.509 with
        // an ECDSA P-256 SPKI (what the client paths parse out of it).
        let (cert, key) = generate_camouflage_cert().unwrap();
        let pk = crate::proto::reality::tls13::der::public_key(cert.as_ref()).unwrap();
        assert!(
            matches!(pk, crate::proto::reality::tls13::der::PublicKey::EcdsaP256(_)),
            "camouflage SPKI is not P-256"
        );
        // The signing key parses with the same PKCS#8 (rustls accepted it
        // in JlsServerConfig::new; the DER shape is checked here).
        assert!(matches!(key, rustls::pki_types::PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn client_hello_sni_extraction() {
        // A synthetic ClientHello carrying server_name (ext 0x0000).
        let mut hello = vec![HS_CLIENT_HELLO, 0, 0, 0];
        hello.extend_from_slice(&[0x03, 0x03]); // legacy_version
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session id
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        hello.push(1); // compression methods length
        hello.push(0); // null
        let name = b"jls.test";
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&(name.len() as u16 + 3).to_be_bytes()); // list length
        sni_ext.push(0); // host_name
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);
        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        ext.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext);
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);
        let body_len = (hello.len() - 4) as u32;
        hello[1..4].copy_from_slice(&body_len.to_be_bytes()[1..]);
        assert_eq!(client_hello_sni(&hello).as_deref(), Some("jls.test"));
        // The random at offset 6 and everything past the session id is
        // walked correctly for a longer session id too.
        let mut hello2 = hello.clone();
        hello2[38] = 4; // session id length grows to 4
        hello2.splice(39..39, [1, 2, 3, 4]);
        let body_len = (hello2.len() - 4) as u32;
        hello2[1..4].copy_from_slice(&body_len.to_be_bytes()[1..]);
        assert_eq!(client_hello_sni(&hello2).as_deref(), Some("jls.test"));
        // No extensions → None.
        let mut bare = vec![HS_CLIENT_HELLO, 0, 0, 0];
        bare.extend_from_slice(&[0x03, 0x03]);
        bare.extend_from_slice(&[0u8; 32]);
        bare.push(0);
        bare.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        bare.push(1);
        bare.push(0);
        bare.extend_from_slice(&[0x00, 0x00]); // empty extensions
        let body_len = (bare.len() - 4) as u32;
        bare[1..4].copy_from_slice(&body_len.to_be_bytes()[1..]);
        assert!(client_hello_sni(&bare).is_none());
    }

    /// Drive [`server`] against the engine's own client over a duplex.
    async fn server_half(
        users: Vec<JlsUser>,
        client_end: BoxProxyStream,
    ) -> std::result::Result<(String, BoxProxyStream), String> {
        let cfg = JlsServerConfig::new("jls.test", users, Vec::new()).unwrap();
        match server(&cfg, client_end).await {
            Ok(JlsServerHandshake::Authenticated { stream, user }) => Ok((user, stream)),
            Ok(JlsServerHandshake::Fallback { .. }) => Err("fallback".into()),
            Err(e) => Err(e.to_string()),
        }
    }

    #[tokio::test]
    async fn server_multi_user_table_picks_the_authenticating_user() {
        // Both users in the table; the SECOND one authenticates and the
        // server reports exactly her (UserFromConn semantics,
        // jls.go:192-196).
        let cfg = test_cfg("user2", "pass2");
        let users = vec![
            JlsUser::new("user1", "pass1").unwrap(),
            JlsUser::new("user2", "pass2").unwrap(),
        ];
        let (client, server_end) = tokio::io::duplex(256 * 1024);
        let task = tokio::spawn(server_half(users, Box::new(server_end)));
        let mut stream = tokio::time::timeout(
            Duration::from_secs(20),
            connect(&cfg, Box::new(client) as BoxProxyStream),
        )
        .await
        .expect("timeout")
        .expect("client handshake");
        let (user, mut server_stream) = task.await.unwrap().expect("server half");
        assert_eq!(user, "user2");
        // The tunnel echoes through both halves.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"multi-user").await.unwrap();
        let mut buf = [0u8; 10];
        server_stream.read_exact(&mut buf).await.unwrap();
        server_stream.write_all(&buf).await.unwrap();
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"multi-user");
    }

    #[tokio::test]
    async fn server_wrong_sni_falls_back_with_the_recorded_hello() {
        // checkServerName (jls-tls/jls.go:316-318, 378-383): the SNI must
        // match the configured one or authentication fails → fallback.
        let mut cfg = test_cfg("user1", "pass1");
        cfg.sni = "other.test".into();
        let (client, server_end) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            let users = vec![JlsUser::new("user1", "pass1").unwrap()];
            let server_cfg = JlsServerConfig::new("jls.test", users, Vec::new()).unwrap();
            server(&server_cfg, Box::new(server_end)).await
        });
        // The client starts its (never-to-complete) handshake.
        let client_task = tokio::spawn(async move {
            let _ = connect(&cfg, Box::new(client) as BoxProxyStream).await;
        });
        let outcome = tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .expect("timeout")
            .unwrap()
            .expect("server must not hard-fail");
        match outcome {
            JlsServerHandshake::Fallback { prefix, .. } => {
                // Everything the client sent was recorded (the recorder).
                assert!(!prefix.is_empty());
                assert_eq!(prefix[0], REC_HANDSHAKE);
                assert_eq!(prefix[RECORD_HEADER_LEN], HS_CLIENT_HELLO);
                // And nothing was written back (canFallbackJLS).
            }
            JlsServerHandshake::Authenticated { .. } => {
                panic!("a wrong SNI must not authenticate")
            }
        }
        client_task.abort();
    }

    #[tokio::test]
    async fn server_plain_bytes_fall_back_with_every_byte_recorded() {
        // A non-TLS client (plain HTTP) is relayed, bytes intact — the
        // handshakeRecorderConn prefix. The sniffer bails on the bogus
        // record header once the client closes (EOF), with everything
        // read still recorded.
        use tokio::io::AsyncWriteExt;
        let (client, server_end) = tokio::io::duplex(64 * 1024);
        let request = b"POST /x HTTP/1.1\r\n\r\n".to_vec();
        let mut client = client;
        client.write_all(&request).await.unwrap();
        let server_cfg =
            JlsServerConfig::new("jls.test", vec![JlsUser::new("u", "p").unwrap()], Vec::new())
                .unwrap();
        let task = tokio::spawn(async move { server(&server_cfg, Box::new(server_end)).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(client);
        let outcome = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("timeout")
            .unwrap()
            .expect("server must not hard-fail");
        match outcome {
            JlsServerHandshake::Fallback { prefix, .. } => {
                assert!(prefix.starts_with(b"POST /x"), "{prefix:?}");
            }
            JlsServerHandshake::Authenticated { .. } => panic!("plain bytes must not authenticate"),
        }
    }

    #[tokio::test]
    async fn relay_fallback_replays_prefix_and_relays_bidirectionally() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // The camouflage dest: a plain TCP echo.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let (client, server_end) = tokio::io::duplex(64 * 1024);
        let dest = crate::addr::NetAddr::ip(dest.ip(), dest.port());
        let prefix = b"already-sniffed-bytes".to_vec();
        let relay = tokio::spawn(relay_fallback(
            Box::new(server_end),
            prefix.clone(),
            dest,
            0,
        ));
        // The dest sees the prefix first, then live traffic both ways.
        let mut client = client;
        client.write_all(b"-and-live").await.unwrap();
        let mut expect = prefix.clone();
        expect.extend_from_slice(b"-and-live");
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while seen.len() < expect.len() {
            assert!(Instant::now() < deadline, "echo incomplete: {seen:?}");
            let mut buf = [0u8; 1024];
            let n = client.read(&mut buf).await.unwrap();
            seen.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&seen[..expect.len()], &expect[..]);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(10), relay)
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(10), echo).await;
    }

    #[tokio::test]
    async fn relay_fallback_rate_limit_paces_the_upstream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // A sink dest that reads and discards: only the client→dest
        // (upstream Write) limiter runs — newRateLimitedConn's WaitN
        // before each burst chunk (jls.go:289-313).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest = listener.local_addr().unwrap();
        let sink = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        let dest = crate::addr::NetAddr::ip(dest.ip(), dest.port());
        let push = |rate: u64| {
            let dest = dest.clone();
            async move {
                let (mut client, server_end) = tokio::io::duplex(256 * 1024);
                let relay = tokio::spawn(relay_fallback(
                    Box::new(server_end),
                    Vec::new(),
                    dest,
                    rate,
                ));
                let payload = vec![0x61u8; 12_000];
                let start = Instant::now();
                client.write_all(&payload).await.unwrap();
                drop(client);
                let _ = tokio::time::timeout(Duration::from_secs(30), relay)
                    .await
                    .unwrap()
                    .unwrap();
                start.elapsed()
            }
        };
        // 12 KB at 64000 bps ≈ 1.5 s; unlimited finishes immediately.
        let limited = push(64_000).await;
        let unlimited = push(0).await;
        assert!(
            limited >= Duration::from_millis(1_000),
            "rate limit did not pace: {limited:?} (unlimited {unlimited:?})"
        );
        assert!(
            unlimited < Duration::from_millis(900),
            "unlimited relay was slow: {unlimited:?}"
        );
        sink.abort();
    }

    #[test]
    fn rate_limit_burst_semantics() {
        // newRateLimitedConn (jls.go:237-247):
        // burst = rateBps / 8 / (Second / rateLimitCycle), clamped.
        assert_eq!(rate_limit_burst(8_000_000), 10_000);
        assert_eq!(rate_limit_burst(1_000), 1); // clamped up
        assert_eq!(rate_limit_burst(1), 1);
        assert_eq!(rate_limit_burst(u64::MAX / 8), MAX_RATE_LIMIT_BURST_BYTES as usize);
    }

    #[tokio::test]
    async fn bit_rate_limiter_reserves_like_reserve_n() {
        // bitRateLimiter.reserveN (jls.go:322-335): the first reserve is
        // free (empty bucket → ready = now), the next accumulates the
        // interval before returning (interval-based, not per-call).
        let mut limiter = BitRateLimiter::new(64_000);
        let start = Instant::now();
        // 1000 bytes at 64 kbps = 125 ms.
        limiter.wait_n(1000).await;
        assert!(start.elapsed() < Duration::from_millis(80), "first wait slept");
        limiter.wait_n(1000).await;
        assert!(
            start.elapsed() >= Duration::from_millis(100),
            "second wait did not accumulate: {:?}",
            start.elapsed()
        );
    }

    // --------------------------------------- client camouflage HTTP fallback
    // jlsClientHTTPFallback (transport/jls/utls.go:120-150), exercised
    // against the wave-10 JLS server LISTENER in fallback mode: a
    // fingerprint client with the WRONG password completes the TLS
    // handshake against the camouflage dest, issues the plausible GET,
    // and only then fails with ErrJLSAuthFailed.

    /// The plaintext a camouflage dest received.
    type SeenPlaintext = std::sync::Arc<std::sync::Mutex<Vec<u8>>>;

    /// A fake camouflage site: a real TLS server (self-signed P-256)
    /// that negotiates `alpn` and answers HTTP/1.1 with a plausible
    /// page, recording every plaintext byte.
    async fn spawn_camo_site_http1() -> (std::net::SocketAddr, SeenPlaintext) {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["jls.test".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert = CertificateDer::from(cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: SeenPlaintext = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    continue;
                };
                let config = config.clone();
                let seen = seen2.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut tls =
                        match tokio_rustls::TlsAcceptor::from(config).accept(sock).await {
                            Ok(t) => t,
                            Err(_) => return,
                        };
                    let mut buf = [0u8; 2048];
                    loop {
                        match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                seen.lock().unwrap().extend_from_slice(&buf[..n]);
                                let _ = tls
                                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                                    .await;
                            }
                        }
                    }
                });
            }
        });
        (addr, seen)
    }

    /// The h2 flavor: negotiates `h2` and answers the one GET with a
    /// static-indexed 200 over a minimal h2 server (the mirror of the
    /// engine's own h2c client shapes).
    async fn spawn_camo_site_h2() -> (std::net::SocketAddr, SeenPlaintext) {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["jls.test".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert = CertificateDer::from(cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let config = Arc::new(config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: SeenPlaintext = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    continue;
                };
                let config = config.clone();
                let seen = seen2.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut tls =
                        match tokio_rustls::TlsAcceptor::from(config).accept(sock).await {
                            Ok(t) => t,
                            Err(_) => return,
                        };
                    // h2c server: preface, SETTINGS, then the one request.
                    let mut preface = vec![0u8; 24];
                    if tls.read_exact(&mut preface).await.is_err()
                        || &preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                    {
                        return;
                    }
                    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
                        let mut out = Vec::with_capacity(9 + payload.len());
                        out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
                        out.push(kind);
                        out.push(flags);
                        out.extend_from_slice(&stream.to_be_bytes());
                        out.extend_from_slice(payload);
                        out
                    }
                    let _ = tls.write_all(&frame(0x4 /* SETTINGS */, 0, 0, &[])).await;
                    let mut head = [0u8; 9];
                    loop {
                        if tls.read_exact(&mut head).await.is_err() {
                            return;
                        }
                        let len = usize::from(head[0]) << 16
                            | usize::from(head[1]) << 8
                            | usize::from(head[2]);
                        let kind = head[3];
                        let flags = head[4];
                        let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]);
                        let mut payload = vec![0u8; len];
                        if tls.read_exact(&mut payload).await.is_err() {
                            return;
                        }
                        if kind == 0x4 && flags & 0x1 == 0 {
                            // ACK the client's SETTINGS.
                            let _ = tls.write_all(&frame(0x4, 0x1, 0, &[])).await;
                            continue;
                        }
                        if kind == 0x1 && stream == 1 {
                            // The request HEADERS block (literal HPACK,
                            // no Huffman): record it and answer 200
                            // (:status 200 = static index 8, END_STREAM).
                            seen.lock().unwrap().extend_from_slice(&payload);
                            let _ = tls.write_all(&frame(0x1, 0x4 | 0x1, 1, &[0x88])).await;
                            return;
                        }
                    }
                });
            }
        });
        (addr, seen)
    }

    /// The wave-10 JLS server listener in fallback mode: one user with
    /// a REAL password, dest = the fake camouflage site.
    async fn spawn_jls_listener(dest: std::net::SocketAddr) -> std::net::SocketAddr {
        let capture = crate::inbound::proxy_server::test_support::Capture::new();
        let cfg = crate::inbound::proxy_server::ServerConfig {
            tag: "jls-fallback-test".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: crate::inbound::proxy_server::ServerProtocol::Jls {
                sni: "jls.test".into(),
                dest: dest.to_string(),
                users: vec![("user1".into(), "real-pass".into())],
                alpn: Vec::new(),
                rate_limit: 0,
            },
        };
        crate::inbound::proxy_server::jls::serve(&cfg, capture)
            .await
            .expect("jls listener")
    }

    /// The observable shape of the padding cookie (utls.go:143):
    /// `padding=` followed by 30..=61 zeros.
    fn padding_len(line: &str) -> Option<usize> {
        let value = line.strip_prefix("Cookie: padding=")?;
        let zeros = value.trim_end_matches('\r');
        if !zeros.bytes().all(|b| b == b'0') {
            return None;
        }
        Some(zeros.len())
    }

    #[tokio::test]
    async fn fingerprint_auth_failure_performs_the_http1_camouflage_round() {
        // utls.go:106-112 + jlsClientHTTPFallback over HTTP/1.1: the
        // wrong-password fingerprint client completes the handshake
        // against the camouflage dest (through the listener's fallback
        // relay), sends the plausible GET, then errors with
        // ErrJLSAuthFailed.
        let (dest, seen) = spawn_camo_site_http1().await;
        let addr = spawn_jls_listener(dest).await;

        let cfg = fp_cfg("user1", "wrong-pass", UtslProfile::parse("chrome").unwrap());
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let err = match connect(&cfg, Box::new(tcp) as BoxProxyStream).await {
            Ok(_) => panic!("a wrong password must not authenticate"),
            Err(e) => e,
        };
        assert!(err.to_string().contains(ERR_AUTH_FAILED), "{err}");

        // The camouflage site saw exactly the upstream request shape.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            assert!(Instant::now() < deadline, "camouflage site never saw the GET");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let request = String::from_utf8_lossy(&seen.lock().unwrap().clone()).into_owned();
        let mut lines = request.split("\r\n");
        assert_eq!(lines.next(), Some("GET / HTTP/1.1"), "{request}");
        assert!(lines.clone().any(|l| l == "Host: jls.test"), "{request}");
        assert!(lines.clone().any(|l| l == "User-Agent: Chrome"), "{request}");
        assert!(lines.clone().any(|l| l == "Accept-Encoding: gzip"), "{request}");
        let cookie = lines
            .clone()
            .find(|l| l.starts_with("Cookie: padding="))
            .unwrap_or_else(|| panic!("no padding cookie in {request}"));
        let n = padding_len(cookie).unwrap_or_else(|| panic!("bad cookie line {cookie:?}"));
        assert!((30..=61).contains(&n), "padding cookie out of range: {n}");
    }

    #[tokio::test]
    async fn fingerprint_auth_failure_performs_the_h2_camouflage_round() {
        // utls.go:123-129: when the camouflage site negotiated h2, the
        // round speaks unencrypted HTTP/2 over the tunnel.
        let (dest, seen) = spawn_camo_site_h2().await;
        let addr = spawn_jls_listener(dest).await;

        let cfg = fp_cfg("user1", "wrong-pass", UtslProfile::parse("firefox").unwrap());
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let err = match connect(&cfg, Box::new(tcp) as BoxProxyStream).await {
            Ok(_) => panic!("a wrong password must not authenticate"),
            Err(e) => e,
        };
        assert!(err.to_string().contains(ERR_AUTH_FAILED), "{err}");

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            assert!(Instant::now() < deadline, "camouflage site never saw the request");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // The request HEADERS block (literal HPACK, no Huffman): the
        // pseudo-headers, the fingerprint user agent and the cookie are
        // all plain greppable.
        let block = seen.lock().unwrap().clone();
        let has = |needle: &[u8]| block.windows(needle.len()).any(|w| w == needle);
        assert!(has(b":method"), "{block:?}");
        assert!(has(b"GET"), "{block:?}");
        assert!(has(b":authority"), "{block:?}");
        assert!(has(b"jls.test"), "{block:?}");
        assert!(has(b"user-agent"), "{block:?}");
        assert!(has(b"Firefox"), "{block:?}");
        assert!(has(b"cookie"), "{block:?}");
        assert!(has(b"padding="), "{block:?}");
        assert!(has(b":path"), "{block:?}");
    }

    #[tokio::test]
    async fn plain_path_auth_failure_still_errors_immediately() {
        // The plain (non-fingerprint) branch keeps failing at the
        // ServerHello check (transport/jls/jls.go:98-119 has no fallback
        // round): a wrong-password plain client against the fallback
        // listener errors without any HTTP bytes reaching the dest.
        let (dest, seen) = spawn_camo_site_http1().await;
        let addr = spawn_jls_listener(dest).await;

        let cfg = test_cfg("user1", "wrong-pass");
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let err = match connect(&cfg, Box::new(tcp) as BoxProxyStream).await {
            Ok(_) => panic!("a wrong password must not authenticate"),
            Err(e) => e,
        };
        assert!(err.to_string().contains(ERR_AUTH_FAILED), "{err}");
        assert!(
            seen.lock().unwrap().is_empty(),
            "the plain path performs no camouflage round"
        );
    }
}
