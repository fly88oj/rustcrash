//! REALITY + uTLS-style TLS fingerprinting (Rust-native TLS 1.3).
//!
//! The pieces:
//!
//! * [`tls13`] — a minimal, hand-rolled TLS 1.3 client (RFC 8446). It exists
//!   because the ClientHello must be byte-exactly ours: REALITY hides its
//!   authentication inside the hello's session id, and uTLS fingerprint
//!   mimicry is nothing but the hello's bytes.
//! * [`profiles`] — Chrome / Firefox ClientHello templates ported from
//!   uTLS `u_parrots.go` (extension order, GREASE, ALPN, padding).
//! * [`reality`] — the REALITY client: X25519 auth, the sealed session id,
//!   the temp-auth certificate check, and the `spiderX` fallback.
//! * [`stream`] — plain fingerprint TLS (`utls_connect`) with real webpki
//!   certificate verification.
//!
//! No BoringSSL/uTLS C dependency: everything is rustls' ring backend plus
//! RustCrypto (aes-gcm, chacha20poly1305, hkdf, sha2) and curve25519-dalek,
//! so the musl-static builds keep working.

pub mod profiles;
// `reality::reality` mirrors the upstream file layout (Xray's
// `transport/internet/reality`); clippy's module-inception lint is fine here.
#[allow(clippy::module_inception)]
pub mod reality;
pub mod stream;
pub mod tls13;

pub use profiles::UtslProfile;
pub use reality::{connect as reality_connect, RealityCfg, RealityStream};
pub use stream::{utls_connect, UtlsCfg};