//! OpenVPN 2.x outbound client — the port of mihomo's in-tree
//! `transport/openvpn` Go library (MetaCubeX/mihomo, branch Alpha), as
//! driven by `adapter/outbound/openvpn.go`.
//!
//! # Architecture
//!
//! * **Control channel** (`packet.go`, `control.go`): P_CONTROL_V1 /
//!   P_ACK_V1 / hard-reset packet framing with a reliable transport on
//!   top — per-direction message ids, out-of-order buffering bounded by
//!   OpenVPN's RELIABLE_CAPACITY (12), piggybacked ACK MRU
//!   (RELIABLE_ACK_SIZE 8, CONTROL_SEND_ACK_MAX 4), 1s retransmission on
//!   UDP and the tls-auth/tls-crypt packet-id anti-replay window
//!   (REPLAY_WINDOW 64, 15s time backtrack).
//! * **Auth layers** (`tlsauth.go`, `tlscrypt.go`, `tlscrypt_v2.go`):
//!   tls-auth (HMAC over `pid‖time‖header‖plain` with the static key's
//!   digest-sized HMAC half and key-direction slot selection), tls-crypt
//!   (HMAC-SHA256 tag + AES-256-CTR stream keyed by the tag prefix) and
//!   tls-crypt-v2 (client PEM: 256 bytes of key material + wrapped client
//!   key appended to the P_CONTROL_HARD_RESET_CLIENT_V3 flight).
//! * **TLS inside the control channel** (`client.go startTLSEpoch`): a
//!   rustls TLS 1.3 client whose records ride chunked P_CONTROL_V1
//!   messages (`control.go maxTLSControlPayload` 1100), verified against
//!   the configured CA chain (no server-name check — mihomo's
//!   `VerifyConnection` with empty DNSNames, client.go:1744-1781).
//! * **Key method 2** (`keymethod.go`): the client record
//!   (`premaster‖random1‖random2‖options‖user‖pass‖peer-info`), the
//!   server record parse (including OpenVPN 2.6 trailing-string
//!   shortening) and the TLS1.0-style PRF (MD5‖SHA1 halves) that expands
//!   `master secret` / `key expansion` into the 256-byte key block
//!   (`DeriveClientKeyMaterial`).
//! * **Data channel** (`data.go`): P_DATA_V1 / P_DATA_V2 (peer-id)
//!   packets, AES-GCM AEADs (implicit IV = first 8 bytes of the HMAC
//!   key, nonce pid-XORed into it, AD = V2 header + pid) or AES-CBC +
//!   HMAC (explicit IV, padding), CHACHA20-POLY1305, a 64-slot replay
//!   window and the 0xFF000000 rekey threshold.
//! * **Push** (`push.go`): PUSH_REPLY / AUTH_FAILED / AUTH_PENDING
//!   parsing with push-continuation merging, cipher negotiation
//!   (`config.go NegotiateCipher`) and auth-token capture.
//! * **L3 data plane**: a smoltcp userspace netstack exactly like
//!   [`crate::proto::wireguard`] — the addresses come from the pushed
//!   `ifconfig`/`ifconfig-ipv6` prefixes; TCP dials become
//!   [`OvpnStream`], UDP dials become [`OvpnUdp`]. One tunnel task owns
//!   the link, the control state, the data epochs and the netstack
//!   (mihomo runs the same single `PacketMux` reader; here the whole
//!   client is single-owner, which also replaces upstream's
//!   `priorityWriteGate` write serialization).
//!
//! # Scope and deviations (all deliberate, each with the upstream reason)
//!
//! * **Rekey (soft reset)**: ported as a single renegotiation state
//!   machine (`watchControl`/`renegotiate`): the server's
//!   P_CONTROL_SOFT_RESET_V1 triggers a fresh TLS epoch + key-method-2
//!   exchange on the same control channel; the previous data epoch stays
//!   decryptable for the transition window (default 3600s, `tran-window`)
//!   and outbound traffic keeps using it until the peer activates the
//!   new epoch, the 60s no-evidence window lapses or the retiring epoch
//!   expires (`installDataChannel`, `authDeferredExpire`). Upstream's
//!   AUTH_PENDING deferral matrix (per-epoch staged deadlines, token
//!   probes) is reduced to: AUTH_PENDING,timeout N extends the push
//!   wait (capped 30min, `authPendingMaxTimeout`); AUTH_FAILED fails the
//!   tunnel.
//! * **TLS 1.3 only** for the control-channel TLS (rustls cannot
//!   renegotiate, and the engine has no TLS 1.2 stack hook); the initial
//!   handshake offers TLS 1.3 like modern OpenVPN servers expect.
//! * **comp-lzo**: config-rejected unless `yes`/`adaptive`/`no`. With
//!   lzo enabled the client frames every packet with the 0xFA
//!   (uncompressed) header exactly like upstream's `lzo1xCompressSafe`
//!   (mihomo never compresses either) and strips 0xFA on receive; a peer
//!   0x66 (really-compressed) packet fails with a precise error — the
//!   engine has no LZO decompressor (upstream vendors `rasky/go-lzo`).
//! * **ip-stack**: the same `IPStackOption` surface as the wireguard
//!   outbound (`auto`/`gvisor`/`mips` + congestion-controller);
//!   `gvisor` is rejected with the upstream build-tag string and every
//!   accepted mode is served by the in-process smoltcp stack (mihomo's
//!   `auto` resolves to the gVisor/mips in-process stacks — the engine
//!   never creates a host TUN device).
//! * **Pushed `route`/`route-ipv6` options are parsed and carried** (see
//!   [`PushReply::routes`]) but not installed in the userspace stack:
//!   the pushed-prefix default routes already cover all egress, and
//!   smoltcp's `Routes` keeps only default gateways.
//! * **DNS** (`remote-dns-resolve` + `dns`): validated and carried as an
//!   integrator hook, mirroring the masque outbound; the engine resolves
//!   through its own resolver.
//! * **Domains as dial targets are refused** — the netstack routes IPs
//!   only, and upstream resolves outside the tunnel
//!   (`DialContext`'s `metadata.Resolved()` branch).
//! * UDP send failures close the tunnel (upstream's `errPacketDropped`
//!   distinguishes datagram loss; a single-owner tunnel has no second
//!   writer to race with, so a hard error is reported instead).

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Payload};
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::RngCore;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, Notify};

use crate::addr::NetAddr;
use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

// ---------------------------------------------------------------------------
// Configuration (mihomo adapter/outbound/openvpn.go OpenVPNOption)
// ---------------------------------------------------------------------------

/// `IPStackOption` (mihomo adapter/outbound/wireguard.go:143-172 — the
/// same struct the OpenVPN adapter reuses): `mode`
/// (`auto`/`gvisor`/`mips`) and `congestion-controller`
/// (`cubic`/`reno`/`bbr`/`bbr3`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpStackOption {
    pub mode: String,
    pub congestion_controller: String,
}

impl IpStackOption {
    /// `normalize` (wireguard.go:148-154): lowercase + default `auto`.
    pub fn normalize(&mut self) {
        self.mode = self.mode.to_lowercase();
        if self.mode.is_empty() {
            self.mode = "auto".into();
        }
        self.congestion_controller = self.congestion_controller.to_lowercase();
    }

    /// `validate` (wireguard.go:156-172) with the exact upstream error
    /// strings. `gvisor` additionally needs the (Go-only) gVisor
    /// netstack, so it is rejected like a non-with_gvisor build.
    pub fn validate(&self) -> Result<()> {
        match self.mode.as_str() {
            "auto" | "mips" => {}
            "gvisor" => {
                return Err(Error::config(
                    "gVisor IP stack requires the with_gvisor build tag",
                ))
            }
            other => {
                return Err(Error::config(format!(
                    "invalid IP stack mode {other:?}; expected auto, gvisor, or mips"
                )))
            }
        }
        match self.congestion_controller.as_str() {
            "" | "cubic" | "reno" | "bbr" | "bbr3" => Ok(()),
            other => Err(Error::config(format!(
                "invalid IP stack congestion controller {other:?}; expected cubic, reno, bbr, or bbr3"
            ))),
        }
    }
}

/// An OpenVPN outbound — every field of mihomo's `OpenVPNOption`
/// (adapter/outbound/openvpn.go:40-73). The YAML tag names are in the
/// doc comments for the config integrator.
#[derive(Debug, Clone)]
pub struct OpenVpnOut {
    /// `name`
    pub name: String,
    /// `server`
    pub server: String,
    /// `port`
    pub port: u16,
    /// `proto`: `udp` (default) / `tcp`.
    pub proto: Option<String>,
    /// `dev`: only `tun` (upstream `ValidateInstallScriptSubset`).
    pub dev: String,
    /// `cipher` (default `AES-128-GCM`).
    pub cipher: String,
    /// `data-ciphers`: the offered list (`OpenVPN --data-ciphers`).
    pub data_ciphers: Vec<String>,
    /// `data-ciphers-fallback`
    pub data_cipher_fallback: String,
    /// `auth` (default `SHA256`).
    pub auth: String,
    /// `comp-lzo`: `yes`/`adaptive`/`no`.
    pub comp_lzo: String,
    /// `ca`: inline `<ca>` PEM (required).
    pub ca: String,
    /// `cert`: inline `<cert>` PEM (client certificate auth).
    pub cert: Option<String>,
    /// `key`: inline `<key>` PEM.
    pub key: Option<String>,
    /// `tls-auth`: inline OpenVPN Static key V1 block.
    pub tls_auth: Option<String>,
    /// `key-direction`: `0` / `1` / unset.
    pub key_direction: Option<String>,
    /// `tls-crypt`: inline OpenVPN Static key V1 block.
    pub tls_crypt: Option<String>,
    /// `tls-crypt-v2`: inline `OpenVPN tls-crypt-v2 client key` PEM.
    pub tls_crypt_v2: Option<String>,
    /// `username` (auth-user-pass).
    pub username: Option<String>,
    /// `password`
    pub password: Option<String>,
    /// `peer-info`: extra `KEY=VALUE` lines in the key-method-2 record.
    pub peer_info: Vec<(String, String)>,
    /// `ping`: keepalive interval in seconds (0 = off).
    pub ping: u64,
    /// `ping-restart`: restart the tunnel after this much receive
    /// silence, seconds (0 = off).
    pub ping_restart: u64,
    /// `tran-window`: lame-duck data-epoch window, seconds (upstream
    /// default 3600 when unset).
    pub tran_window: Option<i64>,
    /// `handshake-timeout`: seconds bounding the whole handshake
    /// (upstream `renegotiateTimeout` 30s when unset/0).
    pub handshake_timeout: i64,
    /// `mtu` (0 → 1500).
    pub mtu: u32,
    /// `ip-stack` map (see [`IpStackOption`]).
    pub ip_stack: IpStackOption,
    /// `remote-dns-resolve` — integrator hook (the engine's own resolver
    /// serves lookups).
    pub remote_dns_resolve: bool,
    /// `dns`: nameserver URLs for `remote-dns-resolve`.
    pub dns: Vec<String>,
}

const PROTO_UDP: &str = "udp";
const PROTO_TCP: &str = "tcp";
const CIPHER_AES128GCM: &str = "AES-128-GCM";
const CIPHER_AES192GCM: &str = "AES-192-GCM";
const CIPHER_AES256GCM: &str = "AES-256-GCM";
const CIPHER_AES128CBC: &str = "AES-128-CBC";
const CIPHER_AES192CBC: &str = "AES-192-CBC";
const CIPHER_AES256CBC: &str = "AES-256-CBC";
const CIPHER_CHACHA20POLY1305: &str = "CHACHA20-POLY1305";
const AUTH_MD5: &str = "MD5";
const AUTH_SHA1: &str = "SHA1";
const AUTH_SHA256: &str = "SHA256";
const AUTH_SHA384: &str = "SHA384";
const AUTH_SHA512: &str = "SHA512";

/// mihomo's supported-cipher list, for the config error
/// (config.go:282-283). BF-CBC is NOT supported upstream either.
const SUPPORTED_CIPHERS: [&str; 7] = [
    CIPHER_AES128GCM,
    CIPHER_AES192GCM,
    CIPHER_AES256GCM,
    CIPHER_AES128CBC,
    CIPHER_AES192CBC,
    CIPHER_AES256CBC,
    CIPHER_CHACHA20POLY1305,
];

fn normalize_proto(proto: &str) -> String {
    match proto.to_lowercase().trim() {
        "" => PROTO_UDP.into(),
        "udp" | "udp4" => PROTO_UDP.into(),
        "tcp" | "tcp-client" | "tcp4" | "tcp4-client" => PROTO_TCP.into(),
        other => other.into(),
    }
}

/// `config.go:196-205 normalizeCipher`: `""` → AES-128-GCM,
/// `AES-CBC` → AES-128-CBC, else uppercased.
fn normalize_cipher(cipher: &str) -> String {
    match cipher.to_uppercase().trim() {
        "" => CIPHER_AES128GCM.into(),
        "AES-CBC" => CIPHER_AES128CBC.into(),
        other => other.into(),
    }
}

/// `config.go:207-216 normalizeAuth`: `""` → SHA256, `SHA-1` → SHA1.
fn normalize_auth(auth: &str) -> String {
    match auth.to_uppercase().trim() {
        "" => AUTH_SHA256.into(),
        "SHA-1" => AUTH_SHA1.into(),
        other => other.into(),
    }
}

/// `config.go:91-100 CipherKeyLength`.
fn cipher_key_length(cipher: &str) -> usize {
    match cipher {
        CIPHER_AES256GCM | CIPHER_AES256CBC | CIPHER_CHACHA20POLY1305 => 32,
        CIPHER_AES192GCM | CIPHER_AES192CBC => 24,
        _ => 16,
    }
}

/// `config.go:169-177 isSupportedCipher`.
fn is_supported_cipher(cipher: &str) -> bool {
    SUPPORTED_CIPHERS.contains(&cipher)
}

/// The validated, normalized runtime settings
/// (`ClientConfig.Prepare` + `ValidateInstallScriptSubset`).
#[derive(Debug, Clone)]
struct Settings {
    server: String,
    port: u16,
    proto: String,
    cipher: String,
    data_ciphers: Vec<String>,
    fallback_cipher: String,
    auth: String,
    comp_lzo: bool,
    ca: Vec<u8>,
    cert: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
    tls_auth_key: Option<[u8; 256]>,
    key_direction: String,
    tls_crypt_key: Option<[u8; 256]>,
    tls_crypt_v2_key: Option<[u8; 256]>,
    tls_crypt_v2_wrapped: Option<Vec<u8>>,
    username: String,
    password: String,
    peer_info: Vec<(String, String)>,
    ping: Duration,
    ping_restart: Duration,
    transition_window: Duration,
    handshake_timeout: Duration,
    mtu: usize,
    remote_dns_resolve: bool,
    dns: Vec<String>,
}

impl OpenVpnOut {
    /// `ClientConfig.Prepare` + `ValidateInstallScriptSubset`
    /// (config.go:227-333), with mihomo's exact error strings.
    fn prepare(&self) -> Result<Settings> {
        if self.handshake_timeout < 0 {
            return Err(Error::config("openvpn handshake timeout must be non-negative"));
        }
        let tran_window_set = self.tran_window.is_some();
        let transition_window = match self.tran_window {
            None | Some(0) => Duration::ZERO,
            Some(secs) if secs < 0 => {
                return Err(Error::config("openvpn tran-window must be non-negative"))
            }
            Some(secs) => Duration::from_secs(secs as u64),
        };
        let mut ip_stack = self.ip_stack.clone();
        ip_stack.normalize();
        ip_stack.validate()?;

        let proto = normalize_proto(self.proto.as_deref().unwrap_or(""));
        let dev = self.dev.to_lowercase().trim().to_string();
        let cipher = normalize_cipher(&self.cipher);
        let auth = normalize_auth(&self.auth);
        let comp_raw = self.comp_lzo.to_lowercase().trim().to_string();
        let comp_lzo = match comp_raw.as_str() {
            "" | "no" => false,
            "yes" | "adaptive" => true,
            other => {
                return Err(Error::config(format!(
                    "unsupported openvpn comp-lzo {other:?}: only yes, adaptive and no are \
                     supported (yes/adaptive frame packets uncompressed, as upstream's \
                     lzo1xCompressSafe does)"
                )))
            }
        };

        if self.server.trim().is_empty() || self.port == 0 {
            return Err(Error::config("openvpn config requires remote host and port"));
        }
        if dev != "tun" {
            return Err(Error::config(format!(
                "unsupported openvpn dev {dev:?}: only dev tun is supported"
            )));
        }
        if proto != PROTO_UDP && proto != PROTO_TCP {
            return Err(Error::config(format!(
                "unsupported openvpn proto {proto:?}: only udp and tcp are supported"
            )));
        }
        if !is_supported_cipher(&cipher) {
            return Err(Error::config(format!(
                "unsupported openvpn cipher {cipher:?}: only AES-128-GCM, AES-192-GCM, \
                 AES-256-GCM, AES-128-CBC, AES-192-CBC, AES-256-CBC and CHACHA20-POLY1305 \
                 are supported"
            )));
        }
        if ![AUTH_MD5, AUTH_SHA1, AUTH_SHA256, AUTH_SHA384, AUTH_SHA512].contains(&auth.as_str()) {
            return Err(Error::config(format!(
                "unsupported openvpn auth {auth:?}: only MD5, SHA1, SHA256, SHA384 and \
                 SHA512 are supported"
            )));
        }
        let key_direction = self.key_direction.clone().unwrap_or_default();
        if key_direction != "1" && key_direction != "0" && !key_direction.is_empty() {
            return Err(Error::config(format!(
                "unsupported openvpn key-direction {key_direction:?}: only '1' and '0' are \
                 supported"
            )));
        }
        let tls_auth = self.tls_auth.as_deref().unwrap_or("");
        let tls_crypt = self.tls_crypt.as_deref().unwrap_or("");
        let tls_crypt_v2 = self.tls_crypt_v2.as_deref().unwrap_or("");
        if !tls_auth.trim().is_empty() && !tls_crypt.trim().is_empty() {
            return Err(Error::config(
                "openvpn tls-auth and tls-crypt are mutually exclusive",
            ));
        }
        if !tls_crypt_v2.trim().is_empty()
            && (!tls_auth.trim().is_empty() || !tls_crypt.trim().is_empty())
        {
            return Err(Error::config(
                "openvpn tls-crypt-v2 is mutually exclusive with tls-auth and tls-crypt",
            ));
        }
        let ca = self.ca.as_bytes().to_vec();
        if ca.iter().all(|b| b.is_ascii_whitespace()) {
            return Err(Error::config("openvpn config requires inline <ca> block"));
        }
        if pem_first_block(&ca).is_none() {
            return Err(Error::config("inline <ca> block is not PEM"));
        }
        let cert = self.cert.as_deref().map(|c| c.as_bytes().to_vec());
        let key = self.key.as_deref().map(|k| k.as_bytes().to_vec());
        let has_cert = cert.as_ref().is_some_and(|c| !c.iter().all(|b| b.is_ascii_whitespace()));
        let has_key = key.as_ref().is_some_and(|k| !k.iter().all(|b| b.is_ascii_whitespace()));
        if has_cert || has_key {
            if !has_cert || !has_key {
                return Err(Error::config(
                    "openvpn cert and key must both be set when using client certificate auth",
                ));
            }
            if pem_first_block(cert.as_ref().unwrap()).is_none() {
                return Err(Error::config("inline <cert> block is not PEM"));
            }
            if pem_first_block(key.as_ref().unwrap()).is_none() {
                return Err(Error::config("inline <key> block is not PEM"));
            }
        } else if self.username.as_deref().unwrap_or("").trim().is_empty() {
            return Err(Error::config(
                "openvpn requires either cert+key or username (auth-user-pass)",
            ));
        }

        let tls_auth_key = if !tls_auth.trim().is_empty() {
            Some(decode_static_key(tls_auth.as_bytes()).map_err(|e| {
                Error::config(format!("parse tls-auth key: {e}"))
            })?)
        } else {
            None
        };
        let tls_crypt_key = if !tls_crypt.trim().is_empty() {
            Some(decode_static_key(tls_crypt.as_bytes()).map_err(|e| {
                Error::config(format!("parse tls-crypt key: {e}"))
            })?)
        } else {
            None
        };
        let (tls_crypt_v2_key, tls_crypt_v2_wrapped) = if !tls_crypt_v2.trim().is_empty() {
            let (k, w) = decode_tls_crypt_v2_client_key(tls_crypt_v2.as_bytes())
                .map_err(|e| Error::config(format!("parse tls-crypt-v2 client key: {e}")))?;
            (Some(k), Some(w))
        } else {
            (None, None)
        };

        if self.remote_dns_resolve && !self.dns.is_empty() {
            // dns.ParseNameServer parity: every entry needs scheme://host.
            for url in &self.dns {
                let Some((scheme, _)) = url.split_once("://") else {
                    return Err(Error::config(format!(
                        "openvpn dns URL {url:?} requires a scheme (e.g. udp://1.1.1.1)"
                    )));
                };
                if !matches!(scheme, "udp" | "tcp" | "tls" | "https" | "h3" | "quic" | "dhcp" | "system") {
                    return Err(Error::config(format!(
                        "openvpn dns URL {url:?}: unsupported scheme {scheme:?}"
                    )));
                }
            }
        }

        Ok(Settings {
            server: self.server.trim().to_string(),
            port: self.port,
            proto,
            cipher,
            data_ciphers: self.data_ciphers.iter().map(|c| normalize_cipher(c)).collect(),
            fallback_cipher: normalize_cipher(&self.data_cipher_fallback),
            auth,
            comp_lzo,
            ca,
            cert,
            key,
            tls_auth_key,
            key_direction,
            tls_crypt_key,
            tls_crypt_v2_key,
            tls_crypt_v2_wrapped,
            username: self.username.as_deref().unwrap_or("").trim().to_string(),
            password: self.password.clone().unwrap_or_default(),
            peer_info: self.peer_info.clone(),
            ping: Duration::from_secs(self.ping),
            ping_restart: Duration::from_secs(self.ping_restart),
            transition_window: if tran_window_set {
                transition_window
            } else {
                // client.go:31-33 transitionWindow default.
                Duration::from_secs(3600)
            },
            handshake_timeout: if self.handshake_timeout > 0 {
                Duration::from_secs(self.handshake_timeout as u64)
            } else {
                Duration::from_secs(30) // renegotiateTimeout
            },
            mtu: if self.mtu == 0 { 1500 } else { self.mtu as usize },
            remote_dns_resolve: self.remote_dns_resolve,
            dns: self.dns.clone(),
        })
    }
}

/// The body of the first `-----BEGIN ...-----` PEM block (structural
/// check only — `pem.Decode` parity).
fn pem_first_block(input: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(input).ok()?;
    let begin = text.find("-----BEGIN")?;
    // The body starts after the BEGIN line's newline.
    let line_end = begin + text[begin..].find('\n')?;
    let end = line_end + text[line_end..].find("-----END")?;
    let body: String = text[line_end..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD.decode(&body).ok()
}

/// `config.go:335-356 DecodeStaticKey`: the "OpenVPN Static key V1"
/// hex-body format (header/footer/comment lines stripped).
fn decode_static_key(block: &[u8]) -> Result<[u8; 256]> {
    let mut hex_lines: Vec<&str> = Vec::new();
    for raw in std::str::from_utf8(block)
        .map_err(|e| Error::config(e.to_string()))?
        .split('\n')
    {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("-----BEGIN OpenVPN Static key")
            || line.starts_with("-----END OpenVPN Static key")
        {
            continue;
        }
        hex_lines.push(line);
    }
    let encoded: String = hex_lines.concat();
    let key = hex_decode(&encoded).map_err(|e| Error::config(format!("static key hex: {e}")))?;
    key.try_into().map_err(|v: Vec<u8>| {
        Error::config(format!(
            "invalid static key length {}, expected 256 bytes",
            v.len()
        ))
    })
}

/// Minimal hex decode (no new dependency).
fn hex_decode(s: &str) -> std::result::Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("odd length".into());
    }
    fn val(c: u8) -> std::result::Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("bad hex byte {c:#x}")),
        }
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks(2) {
        out.push(val(pair[0])? << 4 | val(pair[1])?);
    }
    Ok(out)
}

/// `tlscrypt_v2.go:49-59 DecodeTLSCryptV2ClientKey`: base64 PEM body,
/// first 256 bytes key material, remainder the wrapped client key.
fn decode_tls_crypt_v2_client_key(input: &[u8]) -> Result<([u8; 256], Vec<u8>)> {
    const LABEL_BEGIN: &str = "-----BEGIN OpenVPN tls-crypt-v2 client key-----";
    const LABEL_END: &str = "-----END OpenVPN tls-crypt-v2 client key-----";
    let text = std::str::from_utf8(input).map_err(|e| Error::config(e.to_string()))?;
    let begin = text
        .find(LABEL_BEGIN)
        .ok_or_else(|| Error::config("invalid tls-crypt-v2 client PEM"))?;
    let end = text
        .find(LABEL_END)
        .ok_or_else(|| Error::config("invalid tls-crypt-v2 client PEM"))?;
    let body: String = text[begin + LABEL_BEGIN.len()..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&body)
        .map_err(|e| Error::config(format!("tls-crypt-v2 base64: {e}")))?;
    if bytes.len() <= 256 {
        return Err(Error::config("tls-crypt-v2 client PEM missing wrapped key"));
    }
    let mut key = [0u8; 256];
    key.copy_from_slice(&bytes[..256]);
    Ok((key, bytes[256..].to_vec()))
}

// ---------------------------------------------------------------------------
// Packet framing (packet.go)
// ---------------------------------------------------------------------------

const KEY_ID_MASK: u8 = 0x07;
const OPCODE_SHIFT: u8 = 3;

const P_CONTROL_HARD_RESET_SERVER_V1: u8 = 2;
const P_CONTROL_SOFT_RESET_V1: u8 = 3;
const P_CONTROL_V1: u8 = 4;
const P_ACK_V1: u8 = 5;
const P_DATA_V1: u8 = 6;
const P_CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
const P_CONTROL_HARD_RESET_SERVER_V2: u8 = 8;
const P_DATA_V2: u8 = 9;
const P_CONTROL_HARD_RESET_CLIENT_V3: u8 = 10;

const SESSION_ID_SIZE: usize = 8;
/// `tlscrypt.go:14 TLSCryptHeaderSize` (opcode byte + session id).
const TLS_CRYPT_HEADER_SIZE: usize = 1 + SESSION_ID_SIZE;

fn opcode_is_control(opcode: u8) -> bool {
    matches!(
        opcode,
        1 | P_CONTROL_HARD_RESET_SERVER_V1
            | P_CONTROL_SOFT_RESET_V1
            | P_CONTROL_V1
            | P_ACK_V1
            | P_CONTROL_HARD_RESET_CLIENT_V2
            | P_CONTROL_HARD_RESET_SERVER_V2
            | P_CONTROL_HARD_RESET_CLIENT_V3
            | 11 /* P_CONTROL_WKC_V1 */
    )
}

/// `packet.go:66-74 HasMessageID`: control opcodes except P_ACK_V1.
fn opcode_has_message_id(opcode: u8) -> bool {
    opcode_is_control(opcode) && opcode != P_ACK_V1
}

fn opcode_key_id(opcode: u8, key_id: u8) -> u8 {
    opcode << OPCODE_SHIFT | (key_id & KEY_ID_MASK)
}

fn parse_opcode_key_id(b: u8) -> (u8, u8) {
    (b >> OPCODE_SHIFT, b & KEY_ID_MASK)
}

/// `packet.go:88-101 ControlPacket`.
#[derive(Debug, Clone)]
struct ControlPacket {
    opcode: u8,
    key_id: u8,
    local_session: [u8; SESSION_ID_SIZE],
    ack_ids: Vec<u32>,
    ack_remote_session: [u8; SESSION_ID_SIZE],
    message_id: u32,
    payload: Vec<u8>,
}

/// `packet.go:111-143 EncodePlain`.
fn control_encode_plain(p: &ControlPacket) -> Result<Vec<u8>> {
    if !opcode_is_control(p.opcode) {
        return Err(Error::protocol(format!(
            "opcode {} is not a control opcode",
            p.opcode
        )));
    }
    if p.ack_ids.len() > RELIABLE_ACK_SIZE {
        return Err(Error::protocol(format!(
            "too many ack ids: {}",
            p.ack_ids.len()
        )));
    }
    let mut out =
        Vec::with_capacity(1 + p.ack_ids.len() * 4 + SESSION_ID_SIZE + 4 + p.payload.len());
    out.push(p.ack_ids.len() as u8);
    for id in &p.ack_ids {
        out.extend_from_slice(&id.to_be_bytes());
    }
    if !p.ack_ids.is_empty() {
        out.extend_from_slice(&p.ack_remote_session);
    }
    if opcode_has_message_id(p.opcode) {
        out.extend_from_slice(&p.message_id.to_be_bytes());
        out.extend_from_slice(&p.payload);
    }
    Ok(out)
}

/// The decoded reliable-control fields of `DecodeControlPlain`.
type PlainControl = (Vec<u32>, [u8; SESSION_ID_SIZE], u32, Vec<u8>);

/// `packet.go:145-180 DecodeControlPlain`.
fn control_decode_plain(opcode: u8, plain: &[u8]) -> Result<PlainControl> {
    if plain.is_empty() {
        return Err(Error::protocol("control payload too short"));
    }
    let ack_len = plain[0] as usize;
    if ack_len > RELIABLE_ACK_SIZE {
        return Err(Error::protocol(format!(
            "control ack array exceeds {RELIABLE_ACK_SIZE} entries"
        )));
    }
    let mut offset = 1usize;
    if plain.len() < offset + ack_len * 4 {
        return Err(Error::protocol("control ack array truncated"));
    }
    let mut ack_ids = Vec::with_capacity(ack_len);
    for _ in 0..ack_len {
        ack_ids.push(u32::from_be_bytes(
            plain[offset..offset + 4].try_into().expect("u32 slice"),
        ));
        offset += 4;
    }
    let mut ack_remote = [0u8; SESSION_ID_SIZE];
    if ack_len > 0 {
        if plain.len() < offset + SESSION_ID_SIZE {
            return Err(Error::protocol("control ack remote session truncated"));
        }
        ack_remote.copy_from_slice(&plain[offset..offset + SESSION_ID_SIZE]);
        offset += SESSION_ID_SIZE;
    }
    if opcode_has_message_id(opcode) {
        if plain.len() < offset + 4 {
            return Err(Error::protocol("control message id truncated"));
        }
        let message_id =
            u32::from_be_bytes(plain[offset..offset + 4].try_into().expect("u32 slice"));
        offset += 4;
        return Ok((ack_ids, ack_remote, message_id, plain[offset..].to_vec()));
    }
    if plain.len() != offset {
        return Err(Error::protocol("ack packet has trailing payload"));
    }
    Ok((ack_ids, ack_remote, 0, Vec::new()))
}

// ---------------------------------------------------------------------------
// HMAC digests + the control-channel auth layers
// ---------------------------------------------------------------------------

/// `data.go:180-195 newDataChannelAuth` digest selection (also the
/// tls-auth hash, tlsauth.go:38).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthDigest {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl AuthDigest {
    fn parse(name: &str) -> Result<Self> {
        match name {
            AUTH_MD5 => Ok(AuthDigest::Md5),
            AUTH_SHA1 => Ok(AuthDigest::Sha1),
            AUTH_SHA256 => Ok(AuthDigest::Sha256),
            AUTH_SHA384 => Ok(AuthDigest::Sha384),
            AUTH_SHA512 => Ok(AuthDigest::Sha512),
            other => Err(Error::config(format!(
                "unsupported openvpn auth {other:?}"
            ))),
        }
    }

    fn size(&self) -> usize {
        match self {
            AuthDigest::Md5 => 16,
            AuthDigest::Sha1 => 20,
            AuthDigest::Sha256 => 32,
            AuthDigest::Sha384 => 48,
            AuthDigest::Sha512 => 64,
        }
    }

    /// HMAC over the concatenated parts (tlsauth.go:112-118).
    fn mac(&self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        // Monomorphic per digest: the tree carries two crypto-common
        // versions, so a generic `Hmac<M>: Mac` bound is ambiguous.
        let md5 = |key: &[u8], parts: &[&[u8]]| {
            let mut mac = <Hmac<Md5> as Mac>::new_from_slice(key).expect("hmac key");
            for p in parts {
                mac.update(p);
            }
            mac.finalize().into_bytes().to_vec()
        };
        match self {
            AuthDigest::Md5 => md5(key, parts),
            AuthDigest::Sha1 => {
                let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("hmac key");
                for p in parts {
                    mac.update(p);
                }
                mac.finalize().into_bytes().to_vec()
            }
            AuthDigest::Sha256 => {
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
                for p in parts {
                    mac.update(p);
                }
                mac.finalize().into_bytes().to_vec()
            }
            AuthDigest::Sha384 => {
                let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("hmac key");
                for p in parts {
                    mac.update(p);
                }
                mac.finalize().into_bytes().to_vec()
            }
            AuthDigest::Sha512 => {
                let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("hmac key");
                for p in parts {
                    mac.update(p);
                }
                mac.finalize().into_bytes().to_vec()
            }
        }
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `packet.go:11-13 ControlCryptor`.
enum ControlCrypt {
    TlsAuth {
        digest: AuthDigest,
        tag_size: usize,
        encrypt_key: Vec<u8>,
        decrypt_key: Vec<u8>,
    },
    TlsCrypt {
        encrypt: TlsCryptKeys,
        decrypt: TlsCryptKeys,
    },
    /// tls-crypt-v2: v1 wrapping with inverse direction + the wrapped
    /// client key appended to the V3 hard reset.
    TlsCryptV2 {
        encrypt: TlsCryptKeys,
        decrypt: TlsCryptKeys,
        wrapped_client_key: Vec<u8>,
    },
}

struct TlsCryptKeys {
    cipher_key: [u8; 32],
    hmac_key: [u8; 32],
}

impl ControlCrypt {
    /// tlsauth.go:31-64 NewTLSAuth + tlscrypt.go:31-52 NewTLSCrypt +
    /// tlscrypt_v2.go:23-38 NewTLSCryptV2 (client.go:120-139 selection).
    fn new(settings: &Settings) -> Result<Option<ControlCrypt>> {
        if let Some(material) = settings.tls_crypt_v2_key {
            let wrapped = settings
                .tls_crypt_v2_wrapped
                .clone()
                .ok_or_else(|| Error::config("missing wrapped tls-crypt-v2 client key"))?;
            let (encrypt, decrypt) = tls_crypt_slots(&material, true);
            return Ok(Some(ControlCrypt::TlsCryptV2 {
                encrypt,
                decrypt,
                wrapped_client_key: wrapped,
            }));
        }
        if let Some(key) = settings.tls_crypt_key {
            let (encrypt, decrypt) = tls_crypt_slots(&key, true);
            return Ok(Some(ControlCrypt::TlsCrypt { encrypt, decrypt }));
        }
        if let Some(key) = settings.tls_auth_key {
            let digest = AuthDigest::parse(&settings.auth)?;
            let key0 = &key[..128];
            let key1 = &key[128..];
            // tlsauth.go:46-56: key-direction 1 → encrypt slot 1, 0/""
            // → slot 0 (both directions when unset).
            let (encrypt, decrypt) = match settings.key_direction.as_str() {
                "1" => (key1, key0),
                "0" => (key0, key1),
                _ => (key0, key0),
            };
            // A static key slot is 64 cipher bytes + 64 HMAC bytes; the
            // tag uses the first digest-size bytes of the HMAC half.
            let tag_size = digest.size();
            return Ok(Some(ControlCrypt::TlsAuth {
                digest,
                tag_size,
                encrypt_key: encrypt[64..64 + tag_size].to_vec(),
                decrypt_key: decrypt[64..64 + tag_size].to_vec(),
            }));
        }
        Ok(None)
    }

    fn is_v2(&self) -> bool {
        matches!(self, ControlCrypt::TlsCryptV2 { .. })
    }

    fn wrapped_client_key(&self) -> &[u8] {
        match self {
            ControlCrypt::TlsCryptV2 {
                wrapped_client_key, ..
            } => wrapped_client_key,
            _ => &[],
        }
    }

    /// `packet.go:182-198 Encode` / the three Wrap implementations.
    fn wrap(
        &self,
        header: &[u8],
        packet_id: u32,
        unix_time: u32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        if header.len() != TLS_CRYPT_HEADER_SIZE {
            return Err(Error::protocol(format!(
                "invalid tls-auth header length {}, expected {TLS_CRYPT_HEADER_SIZE}",
                header.len()
            )));
        }
        match self {
            ControlCrypt::TlsAuth {
                digest,
                tag_size,
                encrypt_key,
                ..
            } => {
                // tlsauth.go:71-87: header ‖ tag ‖ pid ‖ plaintext.
                let pid = [packet_id.to_be_bytes(), unix_time.to_be_bytes()].concat();
                let tag = digest.mac(encrypt_key, &[&pid, header, plaintext]);
                debug_assert_eq!(tag.len(), *tag_size);
                let mut out = Vec::with_capacity(header.len() + tag.len() + 8 + plaintext.len());
                out.extend_from_slice(header);
                out.extend_from_slice(&tag);
                out.extend_from_slice(&pid);
                out.extend_from_slice(plaintext);
                Ok(out)
            }
            ControlCrypt::TlsCrypt { encrypt, .. } | ControlCrypt::TlsCryptV2 { encrypt, .. } => {
                Ok(tls_crypt_wrap(encrypt, header, packet_id, unix_time, plaintext))
            }
        }
    }

    /// `packet.go:200-253 DecodeControlPacket` / the Unwrap trio.
    fn unwrap(&self, packet: &[u8]) -> Result<(Vec<u8>, u32, u32, Vec<u8>)> {
        match self {
            ControlCrypt::TlsAuth {
                digest,
                tag_size,
                decrypt_key,
                ..
            } => {
                // tlsauth.go:89-110.
                if packet.len() < TLS_CRYPT_HEADER_SIZE + tag_size + 8 + 1 {
                    return Err(Error::protocol("tls-auth packet too short"));
                }
                let header_end = TLS_CRYPT_HEADER_SIZE;
                let tag_end = header_end + tag_size;
                let pid_end = tag_end + 8;
                let header = packet[..header_end].to_vec();
                let tag = &packet[header_end..tag_end];
                let pid = &packet[tag_end..pid_end];
                let plaintext = packet[pid_end..].to_vec();
                let check = digest.mac(decrypt_key, &[pid, &header, &plaintext]);
                if !ct_eq(tag, &check) {
                    return Err(Error::protocol("tls-auth authentication failed"));
                }
                let packet_id = u32::from_be_bytes(pid[..4].try_into().expect("u32"));
                let unix_time = u32::from_be_bytes(pid[4..8].try_into().expect("u32"));
                Ok((header, packet_id, unix_time, plaintext))
            }
            ControlCrypt::TlsCrypt { decrypt, .. } | ControlCrypt::TlsCryptV2 { decrypt, .. } => {
                tls_crypt_unwrap(decrypt, packet)
            }
        }
    }
}

/// tlscrypt.go:31-52: the client encrypts with slot 1 / decrypts with
/// slot 0 (each slot: 32 cipher bytes then 32 HMAC bytes at offset 64).
fn tls_crypt_slots(static_key: &[u8; 256], client: bool) -> (TlsCryptKeys, TlsCryptKeys) {
    let slot = |bytes: &[u8]| TlsCryptKeys {
        cipher_key: bytes[..32].try_into().expect("32 bytes"),
        hmac_key: bytes[64..96].try_into().expect("32 bytes"),
    };
    let key0 = slot(&static_key[..128]);
    let key1 = slot(&static_key[128..]);
    if client {
        (key1, key0)
    } else {
        (key0, key1)
    }
}

/// tlscrypt.go:54-77 Wrap: ad = header‖pid, tag = HMAC-SHA256(ad,
/// plaintext), ciphertext = AES-256-CTR(key, iv=tag[:16]).
fn tls_crypt_wrap(
    keys: &TlsCryptKeys,
    header: &[u8],
    packet_id: u32,
    unix_time: u32,
    plaintext: &[u8],
) -> Vec<u8> {
    let ad = [header, &packet_id.to_be_bytes(), &unix_time.to_be_bytes()].concat();
    let tag = AuthDigest::Sha256.mac(&keys.hmac_key, &[&ad, plaintext]);
    let mut ciphertext = plaintext.to_vec();
    let iv: [u8; 16] = tag[..16].try_into().expect("16 bytes");
    aes256_ctr(&keys.cipher_key, &iv, &mut ciphertext);
    [ad, tag, ciphertext].concat()
}

/// tlscrypt.go:79-104 Unwrap.
fn tls_crypt_unwrap(keys: &TlsCryptKeys, packet: &[u8]) -> Result<(Vec<u8>, u32, u32, Vec<u8>)> {
    if packet.len() < TLS_CRYPT_HEADER_SIZE + 8 + 32 {
        return Err(Error::protocol("tls-crypt packet too short"));
    }
    let ad_end = TLS_CRYPT_HEADER_SIZE + 8;
    let tag_end = ad_end + 32;
    let ad = &packet[..ad_end];
    let tag = &packet[ad_end..tag_end];
    let ciphertext = &packet[tag_end..];
    let mut plaintext = ciphertext.to_vec();
    let iv: [u8; 16] = tag[..16].try_into().expect("16 bytes");
    aes256_ctr(&keys.cipher_key, &iv, &mut plaintext);
    let check = AuthDigest::Sha256.mac(&keys.hmac_key, &[ad, &plaintext]);
    if !ct_eq(tag, &check) {
        return Err(Error::protocol("tls-crypt authentication failed"));
    }
    let packet_id = u32::from_be_bytes(ad[9..13].try_into().expect("u32"));
    let unix_time = u32::from_be_bytes(ad[13..17].try_into().expect("u32"));
    Ok((
        ad[..TLS_CRYPT_HEADER_SIZE].to_vec(),
        packet_id,
        unix_time,
        plaintext,
    ))
}

/// AES-256-CTR (tlscrypt.go:114-122): the one stream mode ring does not
/// expose; built on the `aes` crate block cipher.
fn aes256_ctr(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) {
    let cipher = Aes256::new(key.into());
    use aes::cipher::generic_array::GenericArray;
    let mut counter = *iv;
    for chunk in data.chunks_mut(16) {
        let mut keystream = GenericArray::from(counter);
        cipher.encrypt_block(&mut keystream);
        for (b, k) in chunk.iter_mut().zip(keystream.iter()) {
            *b ^= k;
        }
        for b in counter.iter_mut().rev() {
            let (v, overflow) = b.overflowing_add(1);
            *b = v;
            if !overflow {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Key method 2 (keymethod.go)
// ---------------------------------------------------------------------------

const KEY_SOURCE_PRE_MASTER_SIZE: usize = 48;
const KEY_SOURCE_RANDOM_SIZE: usize = 32;
const MAX_CIPHER_KEY_LENGTH: usize = 64;
const MAX_HMAC_KEY_LENGTH: usize = 64;
const KEY_BLOCK_SIZE: usize = 2 * (MAX_CIPHER_KEY_LENGTH + MAX_HMAC_KEY_LENGTH);

#[derive(Debug, Clone)]
struct KeySource {
    pre_master: [u8; KEY_SOURCE_PRE_MASTER_SIZE],
    random1: [u8; KEY_SOURCE_RANDOM_SIZE],
    random2: [u8; KEY_SOURCE_RANDOM_SIZE],
}

/// The server record carries no pre-master (only the two randoms).
#[derive(Debug, Clone)]
struct ServerKeySource {
    random1: [u8; KEY_SOURCE_RANDOM_SIZE],
    random2: [u8; KEY_SOURCE_RANDOM_SIZE],
}

#[derive(Debug, Clone)]
struct KeyMaterial {
    send_cipher_key: Vec<u8>,
    send_hmac_key: Vec<u8>,
    recv_cipher_key: Vec<u8>,
    recv_hmac_key: Vec<u8>,
}

/// `keymethod.go:56-89 NewClientKeyMethod2Record` + `MarshalClient`.
fn client_km2_record(
    options: &str,
    peer_info: &str,
    username: &str,
    password: &str,
) -> (Vec<u8>, KeySource) {
    let mut client = KeySource {
        pre_master: [0; KEY_SOURCE_PRE_MASTER_SIZE],
        random1: [0; KEY_SOURCE_RANDOM_SIZE],
        random2: [0; KEY_SOURCE_RANDOM_SIZE],
    };
    rand::rngs::OsRng.fill_bytes(&mut client.pre_master);
    rand::rngs::OsRng.fill_bytes(&mut client.random1);
    rand::rngs::OsRng.fill_bytes(&mut client.random2);

    let mut out = Vec::with_capacity(5 + 48 + 64 + options.len() + 16);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.push(2); // key method 2
    out.extend_from_slice(&client.pre_master);
    out.extend_from_slice(&client.random1);
    out.extend_from_slice(&client.random2);
    append_openvpn_string(&mut out, options);
    append_openvpn_string(&mut out, username);
    append_openvpn_string(&mut out, password);
    append_openvpn_string(&mut out, peer_info);
    (out, client)
}

/// keymethod.go:314-325 appendOpenVPNString (length includes the NUL).
fn append_openvpn_string(out: &mut Vec<u8>, s: &str) {
    if s.is_empty() {
        out.extend_from_slice(&0u16.to_be_bytes());
        return;
    }
    let s = &s[..s.len().min(0xfffe)];
    out.extend_from_slice(&((s.len() + 1) as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

/// keymethod.go:327-344 readOpenVPNString; `None` = truncated.
fn read_openvpn_string(packet: &[u8], offset: usize) -> Option<(String, usize)> {
    if offset + 2 > packet.len() {
        return None;
    }
    let size = u16::from_be_bytes(packet[offset..offset + 2].try_into().expect("u16")) as usize;
    if size == 0 {
        return Some((String::new(), offset + 2));
    }
    if offset + 2 + size > packet.len() {
        return None;
    }
    let mut raw = &packet[offset + 2..offset + 2 + size];
    if raw.last() == Some(&0) {
        raw = &raw[..raw.len() - 1];
    }
    Some((String::from_utf8_lossy(raw).into_owned(), offset + 2 + size))
}

#[derive(Debug, Clone)]
struct ServerKm2Record {
    sources: ServerKeySource,
    /// The server's options string (logged, like the adapter's handshake
    /// debug line).
    #[allow(dead_code)]
    options: String,
}

/// keymethod.go:192-209 looksLikeFollowingTLSControl.
fn looks_like_following_tls_control(mut b: &[u8]) -> bool {
    while !b.is_empty() && b[0] == 0 {
        b = &b[1..];
    }
    if b.is_empty() {
        return false;
    }
    for prefix in [
        &b"PUSH_REPLY"[..],
        b"AUTH_FAILED",
        b"PUSH_REQUEST",
        b"AUTH_PENDING",
        b"INFO_PRE",
        b"INFO",
        b"RESTART",
        b"HALT",
        b"EXIT",
        b"CR_RESPONSE",
    ] {
        if b.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// keymethod.go:104-140 ParseServerKeyMethod2RecordConsumed. Returns
/// `(record, consumed)`; error strings mirror upstream.
fn parse_server_km2(packet: &[u8]) -> Result<(ServerKm2Record, usize)> {
    if packet.len() < 4 + 1 + KEY_SOURCE_RANDOM_SIZE * 2 {
        return Err(Error::protocol("key method 2 packet too short"));
    }
    if u32::from_be_bytes(packet[..4].try_into().expect("u32")) != 0 {
        return Err(Error::protocol("invalid key method 2 prefix"));
    }
    if packet[4] & 0x0f != 2 {
        return Err(Error::protocol(format!(
            "unsupported key method {}",
            packet[4] & 0x0f
        )));
    }
    let mut offset = 5usize;
    let mut random1 = [0u8; KEY_SOURCE_RANDOM_SIZE];
    random1.copy_from_slice(&packet[offset..offset + KEY_SOURCE_RANDOM_SIZE]);
    offset += KEY_SOURCE_RANDOM_SIZE;
    let mut random2 = [0u8; KEY_SOURCE_RANDOM_SIZE];
    random2.copy_from_slice(&packet[offset..offset + KEY_SOURCE_RANDOM_SIZE]);
    offset += KEY_SOURCE_RANDOM_SIZE;

    let (options, mut offset) = read_openvpn_string(packet, offset)
        .ok_or_else(|| Error::protocol("read options: openvpn string truncated"))?;
    // Username / password / peer-info: OpenVPN 2.6 may omit them when the
    // following TLS control message is already visible.
    for _ in 0..3 {
        match read_openvpn_string(packet, offset) {
            Some((_, next)) => offset = next,
            None => {
                if looks_like_following_tls_control(&packet[offset..]) {
                    break;
                }
                return Err(Error::protocol("openvpn string truncated"));
            }
        }
    }
    Ok((
        ServerKm2Record {
            sources: ServerKeySource { random1, random2 },
            options,
        },
        offset,
    ))
}

/// keymethod.go:157-179 RecordComplete: all four strings present.
fn km2_record_complete(packet: &[u8]) -> Option<usize> {
    if packet.len() < 4 + 1 + KEY_SOURCE_RANDOM_SIZE * 2 {
        return None;
    }
    if u32::from_be_bytes(packet[..4].try_into().expect("u32")) != 0 {
        return None;
    }
    if packet[4] & 0x0f != 2 {
        return None;
    }
    let mut offset = 5 + KEY_SOURCE_RANDOM_SIZE * 2;
    for _ in 0..4 {
        if offset + 2 > packet.len() {
            return None;
        }
        let size = u16::from_be_bytes(packet[offset..offset + 2].try_into().expect("u16")) as usize;
        if size != 0 && offset + 2 + size > packet.len() {
            return None;
        }
        offset += 2 + size;
    }
    Some(offset)
}

/// keymethod.go:211-249 DeriveClientKeyMaterial + openvpnPRF
/// (348-385): the TLS 1.0 PRF (MD5 ‖ SHA1 halves).
fn derive_client_key_material(
    client: &KeySource,
    server: &ServerKeySource,
    client_session: &[u8; SESSION_ID_SIZE],
    server_session: &[u8; SESSION_ID_SIZE],
    cipher_key_len: usize,
) -> Result<KeyMaterial> {
    if ![16usize, 24, 32].contains(&cipher_key_len) {
        return Err(Error::protocol(format!(
            "unsupported data cipher key length {cipher_key_len}"
        )));
    }
    let master = openvpn_prf(
        &client.pre_master,
        "OpenVPN master secret",
        &client.random1,
        &server.random1,
        &[],
        &[],
        48,
    );
    let key_block = openvpn_prf(
        &master,
        "OpenVPN key expansion",
        &client.random2,
        &server.random2,
        client_session,
        server_session,
        KEY_BLOCK_SIZE,
    );
    let client_to_server = &key_block[..MAX_CIPHER_KEY_LENGTH + MAX_HMAC_KEY_LENGTH];
    let server_to_client = &key_block[MAX_CIPHER_KEY_LENGTH + MAX_HMAC_KEY_LENGTH..];
    Ok(KeyMaterial {
        send_cipher_key: client_to_server[..cipher_key_len].to_vec(),
        send_hmac_key: client_to_server
            [MAX_CIPHER_KEY_LENGTH..MAX_CIPHER_KEY_LENGTH + MAX_HMAC_KEY_LENGTH]
            .to_vec(),
        recv_cipher_key: server_to_client[..cipher_key_len].to_vec(),
        recv_hmac_key: server_to_client
            [MAX_CIPHER_KEY_LENGTH..MAX_CIPHER_KEY_LENGTH + MAX_HMAC_KEY_LENGTH]
            .to_vec(),
    })
}

/// openvpnPRF: seed = label‖clientSeed‖serverSeed‖sessions; the secret
/// splits in halves (overlapping when odd), MD5-pHash XOR SHA1-pHash.
fn openvpn_prf(
    secret: &[u8],
    label: &str,
    client_seed: &[u8],
    server_seed: &[u8],
    client_session: &[u8],
    server_session: &[u8],
    size: usize,
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(label.len() + client_seed.len() + server_seed.len() + 16);
    seed.extend_from_slice(label.as_bytes());
    seed.extend_from_slice(client_seed);
    seed.extend_from_slice(server_seed);
    seed.extend_from_slice(client_session);
    seed.extend_from_slice(server_session);

    let split = secret.len().div_ceil(2);
    let s1 = &secret[..split];
    let s2 = &secret[secret.len() - split..];
    let md5_out = p_hash_md5(s1, &seed, size);
    let sha1_out = p_hash_sha1(s2, &seed, size);
    md5_out.iter().zip(sha1_out.iter()).map(|(a, b)| a ^ b).collect()
}

/// pHash (keymethod.go:368-379): the TLS A(n) expansion, HMAC-MD5 half.
fn p_hash_md5(secret: &[u8], seed: &[u8], size: usize) -> Vec<u8> {
    let new = || <Hmac<Md5> as Mac>::new_from_slice(secret).expect("hmac key");
    let mut mac = new();
    mac.update(seed);
    let mut a = mac.finalize().into_bytes().to_vec();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        let mut mac = new();
        mac.update(&a);
        mac.update(seed);
        out.extend_from_slice(&mac.finalize().into_bytes());
        let mut next = new();
        next.update(&a);
        a = next.finalize().into_bytes().to_vec();
    }
    out.truncate(size);
    out
}

/// pHash, HMAC-SHA1 half.
fn p_hash_sha1(secret: &[u8], seed: &[u8], size: usize) -> Vec<u8> {
    let new = || <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("hmac key");
    let mut mac = new();
    mac.update(seed);
    let mut a = mac.finalize().into_bytes().to_vec();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        let mut mac = new();
        mac.update(&a);
        mac.update(seed);
        out.extend_from_slice(&mac.finalize().into_bytes());
        let mut next = new();
        next.update(&a);
        a = next.finalize().into_bytes().to_vec();
    }
    out.truncate(size);
    out
}

/// keymethod.go:251-267 InstallScriptOptionsString.
fn install_script_options_string(proto: &str, cipher: &str, auth: &str, comp_lzo: bool) -> String {
    let proto_name = if proto == PROTO_TCP {
        "TCPv4_CLIENT"
    } else {
        "UDPv4"
    };
    let keysize = match cipher {
        CIPHER_AES256GCM | CIPHER_AES256CBC | CIPHER_CHACHA20POLY1305 => "256",
        _ => "128",
    };
    let (mtu, comp) = if comp_lzo { ("1544", "comp-lzo,") } else { ("1550", "") };
    format!(
        "V4,dev-type tun,link-mtu {mtu},tun-mtu 1500,proto {proto_name},{comp}cipher {cipher},\
         auth {auth},keysize {keysize},key-method 2,tls-client"
    )
}

/// keymethod.go:269-312 InstallScriptPeerInfo.
fn install_script_peer_info(
    cipher: &str,
    data_ciphers: &[String],
    comp_lzo: bool,
    peer_info: &[(String, String)],
) -> String {
    let iv_ver = peer_info
        .iter()
        .find(|(k, _)| k == "IV_VER")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "mihomo-openvpn".into());
    let lzo = if comp_lzo { "IV_LZO=1\n" } else { "" };
    let iv_ciphers = if data_ciphers.is_empty() {
        cipher.to_string()
    } else {
        data_ciphers.join(":")
    };
    // IV_PROTO: DATA_V2 | REQUEST_PUSH | AUTH_PENDING keyword (22).
    let mut info = format!("IV_VER={iv_ver}\nIV_PROTO=22\n{lzo}IV_CIPHERS={iv_ciphers}\n");
    let mut keys: Vec<&(String, String)> = peer_info
        .iter()
        .filter(|(k, _)| {
            !matches!(k.as_str(), "IV_VER" | "IV_PROTO" | "IV_CIPHERS")
                && !(k == "IV_LZO" && comp_lzo)
        })
        .collect();
    keys.sort();
    for (k, v) in keys {
        info.push_str(&format!("{k}={v}\n"));
    }
    info
}

// ---------------------------------------------------------------------------
// Data channel (data.go)
// ---------------------------------------------------------------------------

const DATA_CHANNEL_TAG_SIZE: usize = 16;
const DATA_CHANNEL_IV_SIZE: usize = 12;
const DATA_CHANNEL_REPLAY_WINDOW: u32 = 64;
const PEER_ID_UNSET: u32 = 0x00ff_ffff;

/// data.go:33-38: the PING_STRING keepalive payload.
const OPENVPN_PING_PACKET: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];

type AesBlock16 = aes::cipher::generic_array::GenericArray<u8, aes::cipher::generic_array::typenum::U16>;

enum AesBlock {
    A128(Aes128),
    A192(Aes192),
    A256(Aes256),
}

impl AesBlock {
    fn new(key: &[u8]) -> Result<Self> {
        match key.len() {
            16 => Ok(AesBlock::A128(Aes128::new(key.into()))),
            24 => Ok(AesBlock::A192(Aes192::new(key.into()))),
            32 => Ok(AesBlock::A256(Aes256::new(key.into()))),
            n => Err(Error::crypto(format!("invalid AES key length {n}"))),
        }
    }

    fn encrypt_block(&self, block: &mut AesBlock16) {
        match self {
            AesBlock::A128(c) => c.encrypt_block(block),
            AesBlock::A192(c) => c.encrypt_block(block),
            AesBlock::A256(c) => c.encrypt_block(block),
        }
    }

    fn decrypt_block(&self, block: &mut AesBlock16) {
        match self {
            AesBlock::A128(c) => c.decrypt_block(block),
            AesBlock::A192(c) => c.decrypt_block(block),
            AesBlock::A256(c) => c.decrypt_block(block),
        }
    }
}

enum DataAead {
    A128(aes_gcm::Aes128Gcm),
    A192(aes_gcm::AesGcm<Aes192, aes::cipher::generic_array::typenum::U12>),
    A256(aes_gcm::Aes256Gcm),
    Chacha(chacha20poly1305::ChaCha20Poly1305),
}

impl DataAead {
    fn seal(&self, nonce: &[u8; 12], msg: &[u8], aad: &[u8]) -> Vec<u8> {
        let payload = Payload { msg, aad };
        match self {
            DataAead::A128(a) => a.encrypt(nonce.into(), payload).expect("gcm seal"),
            DataAead::A192(a) => a.encrypt(nonce.into(), payload).expect("gcm seal"),
            DataAead::A256(a) => a.encrypt(nonce.into(), payload).expect("gcm seal"),
            DataAead::Chacha(a) => a.encrypt(nonce.into(), payload).expect("gcm seal"),
        }
    }

    fn open(&self, nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload { msg: ct, aad };
        let res = match self {
            DataAead::A128(a) => a.decrypt(nonce.into(), payload),
            DataAead::A192(a) => a.decrypt(nonce.into(), payload),
            DataAead::A256(a) => a.decrypt(nonce.into(), payload),
            DataAead::Chacha(a) => a.decrypt(nonce.into(), payload),
        };
        res.map_err(|_| Error::crypto("openvpn data packet authentication failed"))
    }
}

enum DataCipher {
    Aead(DataAead),
    Cbc { block: AesBlock, mac: AuthDigest },
}

struct DataDirection {
    cipher: DataCipher,
    hmac_key: Vec<u8>,
    implicit_iv: [u8; DATA_CHANNEL_IV_SIZE],
}

/// data.go:44-145 DataChannel (single-task owner: no locks needed). The
/// peer id only feeds the header shape at construction time
/// (`dataHeader`), so it is not carried as state.
struct DataChannel {
    send: DataDirection,
    recv: DataDirection,
    key_id: u8,
    header: Vec<u8>,
    send_packet_id: u32,
    /// `recvEvidence` — the peer labeled a packet with this key id.
    peer_active: bool,
    recv_highest: u32,
    recv_window: u64,
    recv_seen: bool,
}

impl DataChannel {
    /// NewDataChannel + newDataChannelAEAD/CBC/Auth.
    fn new(
        keys: &KeyMaterial,
        cipher_name: &str,
        auth_name: &str,
        peer_id: u32,
        key_id: u8,
    ) -> Result<Self> {
        let digest = AuthDigest::parse(auth_name)?;
        let mk_aead = |key: &[u8]| -> Result<DataAead> {
            match cipher_name {
                CIPHER_AES128GCM => Ok(DataAead::A128(aes_gcm::Aes128Gcm::new(key.into()))),
                CIPHER_AES192GCM => Ok(DataAead::A192(<aes_gcm::AesGcm<
                    Aes192,
                    aes::cipher::generic_array::typenum::U12,
                >>::new(key.into()))),
                CIPHER_AES256GCM => Ok(DataAead::A256(aes_gcm::Aes256Gcm::new(key.into()))),
                CIPHER_CHACHA20POLY1305 => Ok(DataAead::Chacha(
                    chacha20poly1305::ChaCha20Poly1305::new(key.into()),
                )),
                other => Err(Error::protocol(format!(
                    "unsupported openvpn cipher {other:?}"
                ))),
            }
        };
        let (send, recv) =
            match cipher_name {
                CIPHER_AES128GCM | CIPHER_AES192GCM | CIPHER_AES256GCM
                | CIPHER_CHACHA20POLY1305 => {
                    // The AEAD implicit IV is the first 8 bytes of the
                    // HMAC half (data.go:97-109).
                    if keys.send_hmac_key.len() < 8 || keys.recv_hmac_key.len() < 8 {
                        return Err(Error::crypto("openvpn implicit IV keys are too short"));
                    }
                    let mut s = DataDirection {
                        cipher: DataCipher::Aead(mk_aead(&keys.send_cipher_key)?),
                        hmac_key: keys.send_hmac_key.clone(),
                        implicit_iv: [0; DATA_CHANNEL_IV_SIZE],
                    };
                    s.implicit_iv[4..].copy_from_slice(&keys.send_hmac_key[..8]);
                    let mut r = DataDirection {
                        cipher: DataCipher::Aead(mk_aead(&keys.recv_cipher_key)?),
                        hmac_key: keys.recv_hmac_key.clone(),
                        implicit_iv: [0; DATA_CHANNEL_IV_SIZE],
                    };
                    r.implicit_iv[4..].copy_from_slice(&keys.recv_hmac_key[..8]);
                    (s, r)
                }
                _ => {
                    let auth_size = digest.size();
                    if keys.send_hmac_key.len() < auth_size || keys.recv_hmac_key.len() < auth_size
                    {
                        return Err(Error::crypto("openvpn HMAC keys are too short"));
                    }
                    let s = DataDirection {
                        cipher: DataCipher::Cbc {
                            block: AesBlock::new(&keys.send_cipher_key)?,
                            mac: digest,
                        },
                        hmac_key: keys.send_hmac_key[..auth_size].to_vec(),
                        implicit_iv: [0; DATA_CHANNEL_IV_SIZE],
                    };
                    let r = DataDirection {
                        cipher: DataCipher::Cbc {
                            block: AesBlock::new(&keys.recv_cipher_key)?,
                            mac: digest,
                        },
                        hmac_key: keys.recv_hmac_key[..auth_size].to_vec(),
                        implicit_iv: [0; DATA_CHANNEL_IV_SIZE],
                    };
                    (s, r)
                }
            };
        Ok(DataChannel {
            send,
            recv,
            key_id: key_id & KEY_ID_MASK,
            header: data_header(peer_id, key_id),
            send_packet_id: 0,
            peer_active: false,
            recv_highest: 0,
            recv_window: 0,
            recv_seen: false,
        })
    }

    /// data.go:362-374 nextPacketID.
    fn next_packet_id(&mut self) -> Result<u32> {
        if self.send_packet_id >= 0xFF00_0000 {
            return Err(Error::network(
                "openvpn data packet id reached rekey threshold",
            ));
        }
        self.send_packet_id += 1;
        Ok(self.send_packet_id)
    }

    /// data.go:197-258 Encrypt/encryptAEAD/encryptCBC.
    fn encrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let packet_id = self.next_packet_id()?;
        match &self.send.cipher {
            DataCipher::Aead(aead) => {
                let pid_bytes = packet_id.to_be_bytes();
                let nonce = nonce_of(packet_id, &self.send.implicit_iv);
                let ad = aead_additional_data(&self.header, &pid_bytes);
                let sealed = aead.seal(&nonce, packet, &ad);
                // Wire: header ‖ pid ‖ tag ‖ ciphertext (the tag precedes
                // the ciphertext — data.go:226-231).
                let (ct, tag) = sealed.split_at(sealed.len() - DATA_CHANNEL_TAG_SIZE);
                let mut out = Vec::with_capacity(self.header.len() + 4 + 16 + ct.len());
                out.extend_from_slice(&self.header);
                out.extend_from_slice(&pid_bytes);
                out.extend_from_slice(tag);
                out.extend_from_slice(ct);
                Ok(out)
            }
            DataCipher::Cbc { block, mac } => {
                let block_size = 16usize;
                let plain_len = 4 + packet.len();
                let padding = block_size - plain_len % block_size;
                let mut out =
                    vec![0u8; self.header.len() + mac.size() + block_size + plain_len + padding];
                out[..self.header.len()].copy_from_slice(&self.header);
                let authenticated = &mut out[self.header.len() + mac.size()..];
                let (iv, ciphertext) = authenticated.split_at_mut(block_size);
                rand::rngs::OsRng.fill_bytes(iv);
                ciphertext[..4].copy_from_slice(&packet_id.to_be_bytes());
                ciphertext[4..4 + packet.len()].copy_from_slice(packet);
                for b in &mut ciphertext[plain_len..] {
                    *b = padding as u8;
                }
                cbc_encrypt_blocks(block, iv, ciphertext);
                let tag = mac.mac(&self.send.hmac_key, &[authenticated]);
                out[self.header.len()..self.header.len() + mac.size()].copy_from_slice(&tag);
                Ok(out)
            }
        }
    }

    /// data.go:260-356 Decrypt/decryptAEAD/decryptCBC +
    /// dataPacketHeaderSize.
    fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.is_empty() {
            return Err(Error::protocol("empty openvpn data packet"));
        }
        let (opcode, _) = parse_opcode_key_id(packet[0]);
        let header_size = match opcode {
            P_DATA_V1 => 1,
            P_DATA_V2 => {
                if packet.len() < 4 {
                    return Err(Error::protocol("openvpn P_DATA_V2 packet missing peer id"));
                }
                4
            }
            other => {
                return Err(Error::protocol(format!(
                    "not an openvpn data packet: {other}"
                )))
            }
        };
        match &self.recv.cipher {
            DataCipher::Aead(aead) => {
                if packet.len() < header_size + 4 + DATA_CHANNEL_TAG_SIZE + 1 {
                    return Err(Error::protocol("openvpn data packet too short"));
                }
                let header = &packet[..header_size];
                let pid_bytes = &packet[header_size..header_size + 4];
                let packet_id = u32::from_be_bytes(pid_bytes.try_into().expect("u32"));
                let tag = &packet[header_size + 4..header_size + 4 + DATA_CHANNEL_TAG_SIZE];
                let ciphertext = &packet[header_size + 4 + DATA_CHANNEL_TAG_SIZE..];
                let mut combined = ciphertext.to_vec();
                combined.extend_from_slice(tag);
                let nonce = nonce_of(packet_id, &self.recv.implicit_iv);
                let ad = aead_additional_data(header, pid_bytes);
                let plain = aead.open(&nonce, &combined, &ad)?;
                self.accept_packet_id(packet_id)?;
                Ok(plain)
            }
            DataCipher::Cbc { block, mac } => {
                let block_size = 16usize;
                let min = header_size + mac.size() + block_size + block_size;
                if packet.len() < min {
                    return Err(Error::protocol("openvpn CBC data packet too short"));
                }
                let body = &packet[header_size..];
                let tag = &body[..mac.size()];
                let authenticated = &body[mac.size()..];
                let expected = mac.mac(&self.recv.hmac_key, &[authenticated]);
                if !ct_eq(tag, &expected) {
                    return Err(Error::protocol(
                        "openvpn CBC data packet HMAC authentication failed",
                    ));
                }
                let (iv, ciphertext) = authenticated.split_at(block_size);
                if ciphertext.is_empty() || ciphertext.len() % block_size != 0 {
                    return Err(Error::protocol("invalid openvpn CBC ciphertext length"));
                }
                let mut buf = ciphertext.to_vec();
                cbc_decrypt_blocks(block, iv, &mut buf);
                let padding = buf[buf.len() - 1] as usize;
                if padding == 0 || padding > block_size || padding > buf.len() {
                    return Err(Error::protocol("invalid openvpn CBC padding"));
                }
                if buf[buf.len() - padding..].iter().any(|b| *b as usize != padding) {
                    return Err(Error::protocol("invalid openvpn CBC padding"));
                }
                let plain = &buf[..buf.len() - padding];
                if plain.len() < 4 {
                    return Err(Error::protocol("openvpn CBC plaintext missing packet id"));
                }
                let packet_id = u32::from_be_bytes(plain[..4].try_into().expect("u32"));
                self.accept_packet_id(packet_id)?;
                Ok(plain[4..].to_vec())
            }
        }
    }

    /// data.go:391-423 acceptPacketID (the 64-slot window).
    fn accept_packet_id(&mut self, packet_id: u32) -> Result<()> {
        if !self.recv_seen {
            self.recv_highest = packet_id;
            self.recv_window = 1;
            self.recv_seen = true;
            return Ok(());
        }
        if packet_id > self.recv_highest {
            let shift = packet_id - self.recv_highest;
            if shift >= DATA_CHANNEL_REPLAY_WINDOW {
                self.recv_window = 1;
            } else {
                self.recv_window = (self.recv_window << shift) | 1;
            }
            self.recv_highest = packet_id;
            return Ok(());
        }
        let diff = self.recv_highest - packet_id;
        if diff >= DATA_CHANNEL_REPLAY_WINDOW {
            return Err(Error::protocol(format!(
                "openvpn replayed data packet id {packet_id}"
            )));
        }
        let mask = 1u64 << diff;
        if self.recv_window & mask != 0 {
            return Err(Error::protocol(format!(
                "openvpn replayed data packet id {packet_id}"
            )));
        }
        self.recv_window |= mask;
        Ok(())
    }
}

/// data.go:454-458 nonce: implicit IV with the pid XORed into the first
/// four bytes.
fn nonce_of(packet_id: u32, implicit: &[u8; DATA_CHANNEL_IV_SIZE]) -> [u8; DATA_CHANNEL_IV_SIZE] {
    let mut nonce = *implicit;
    let mut head = u32::from_be_bytes(nonce[..4].try_into().expect("u32"));
    head ^= packet_id;
    nonce[..4].copy_from_slice(&head.to_be_bytes());
    nonce
}

/// data.go:432-440 aeadAdditionalData.
fn aead_additional_data(header: &[u8], packet_id: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(header.len() + 4);
    if header.first().is_some_and(|first| parse_opcode_key_id(*first).0 == P_DATA_V2) {
        ad.extend_from_slice(header);
    }
    ad.extend_from_slice(packet_id);
    ad
}

/// data.go:442-452 dataHeader.
fn data_header(peer_id: u32, key_id: u8) -> Vec<u8> {
    if peer_id != PEER_ID_UNSET {
        vec![
            opcode_key_id(P_DATA_V2, key_id),
            (peer_id >> 16) as u8,
            (peer_id >> 8) as u8,
            peer_id as u8,
        ]
    } else {
        vec![opcode_key_id(P_DATA_V1, key_id)]
    }
}

fn cbc_encrypt_blocks(block: &AesBlock, iv: &[u8], data: &mut [u8]) {
    let mut prev = AesBlock16::clone_from_slice(iv);
    for chunk in data.chunks_mut(16) {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        let g = AesBlock16::from_mut_slice(chunk);
        block.encrypt_block(g);
        prev = *g;
    }
}

fn cbc_decrypt_blocks(block: &AesBlock, iv: &[u8], data: &mut [u8]) {
    let mut prev = AesBlock16::clone_from_slice(iv);
    for chunk in data.chunks_mut(16) {
        let g = AesBlock16::from_mut_slice(chunk);
        let old = *g;
        block.decrypt_block(g);
        for (b, p) in g.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        prev = old;
    }
}

/// lzo.go:19-52: 0xFA framing (upstream never compresses either).
fn lzo_frame(packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + packet.len());
    out.push(0xFA);
    out.extend_from_slice(packet);
    out
}

fn lzo_unframe(packet: &[u8]) -> Result<Vec<u8>> {
    match packet.first() {
        None => Ok(Vec::new()),
        Some(0xFA) => Ok(packet[1..].to_vec()),
        Some(0x66) => Err(Error::protocol(
            "openvpn: comp-lzo compressed packet (0x66) received, but the engine has no LZO \
             decompressor (upstream vendors rasky/go-lzo); the port frames uncompressed \
             packets with 0xFA like upstream's lzo1xCompressSafe",
        )),
        Some(other) => Err(Error::protocol(format!(
            "openvpn: bad comp-lzo framing byte {other:#x}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Push replies (push.go) + control messages (client.go)
// ---------------------------------------------------------------------------

/// push.go:15-55 PushReply.
#[derive(Debug, Clone, Default)]
struct PushReply {
    prefixes: Vec<(IpAddr, u8)>,
    routes: Vec<(IpAddr, u8)>,
    dns: Vec<IpAddr>,
    peer_id: u32,
    redirect: bool,
    block_ipv6: bool,
    data_ciphers: Vec<String>,
    cipher: String,
    auth_token_user: String,
    auth_token_pass: String,
    push_continuation: usize,
    has_push_reply: bool,
    /// AUTH_PENDING,timeout N (seconds, capped at 30min).
    auth_pending_secs: u64,
}

/// push.go:258-274 ipv4MaskSize.
fn ipv4_mask_size(mask: &Ipv4Addr) -> Option<u8> {
    let mut ones = 0u8;
    let mut seen_zero = false;
    for b in mask.octets() {
        for i in (0..8).rev() {
            if b & (1 << i) == 0 {
                seen_zero = true;
                continue;
            }
            if seen_zero {
                return None;
            }
            ones += 1;
        }
    }
    Some(ones)
}

/// splitPushOptions (push.go:200-214).
fn split_push_options(message: &str) -> Vec<String> {
    let message = message.trim_end_matches('\0');
    let parts: Vec<&str> = message.split(',').collect();
    let parts = if !parts.is_empty() && parts[0].trim() == "PUSH_REPLY" {
        &parts[1..]
    } else {
        &parts[..]
    };
    parts
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

/// push.go:68-171 parsePushReplyInner.
fn parse_push_reply_inner(message: &str) -> Result<PushReply> {
    let message = message.trim_end_matches('\0');
    if !message.starts_with("PUSH_REPLY") {
        return Err(Error::protocol(format!(
            "unexpected openvpn push message {message:?}"
        )));
    }
    let mut reply = PushReply {
        peer_id: PEER_ID_UNSET,
        has_push_reply: true,
        ..Default::default()
    };
    for option in split_push_options(message) {
        let fields: Vec<&str> = option.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        match fields[0] {
            "ifconfig" if fields.len() >= 3 => {
                let addr: IpAddr = fields[1].parse().map_err(|e| {
                    Error::protocol(format!("parse pushed ipv4 address {:?}: {e}", fields[1]))
                })?;
                let mask: IpAddr = fields[2].parse().map_err(|e| {
                    Error::protocol(format!("parse pushed ipv4 mask {:?}: {e}", fields[2]))
                })?;
                match (addr, mask) {
                    (IpAddr::V4(_), IpAddr::V4(m)) => {
                        // A non-contiguous or peer-shaped second address
                        // collapses to a host prefix (SoftEther p2p).
                        let bits = ipv4_mask_size(&m).unwrap_or(32);
                        reply.prefixes.push((addr, bits));
                    }
                    _ => {
                        return Err(Error::protocol(
                            "openvpn ifconfig requires ipv4 address and mask",
                        ))
                    }
                }
            }
            "ifconfig-ipv6" if fields.len() >= 2 => {
                let (addr, bits) = parse_cidr(fields[1]).map_err(|e| {
                    Error::protocol(format!("parse pushed ipv6 address {:?}: {e}", fields[1]))
                })?;
                reply.prefixes.push((addr, bits));
            }
            "route" if fields.len() >= 3 => {
                if let (Ok(addr), Ok(IpAddr::V4(m))) =
                    (fields[1].parse::<IpAddr>(), fields[2].parse::<IpAddr>())
                {
                    if let Some(ones) = ipv4_mask_size(&m) {
                        reply.routes.push((addr, ones));
                    }
                }
            }
            "route-ipv6" if fields.len() >= 2 => {
                if let Ok((addr, bits)) = parse_cidr(fields[1]) {
                    reply.routes.push((addr, bits));
                }
            }
            "dhcp-option" if fields.len() >= 3 && fields[1] == "DNS" => {
                if let Ok(addr) = fields[2].parse::<IpAddr>() {
                    reply.dns.push(addr);
                }
            }
            "peer-id" if fields.len() >= 2 => {
                if let Ok(id) = fields[1].parse::<u32>() {
                    reply.peer_id = id.min(PEER_ID_UNSET);
                }
            }
            "redirect-gateway" => reply.redirect = true,
            "block-ipv6" => reply.block_ipv6 = true,
            "data-ciphers" | "ncp-ciphers" if fields.len() >= 2 => {
                for c in fields[1].split(':') {
                    let c = c.trim();
                    if !c.is_empty() {
                        reply.data_ciphers.push(c.to_string());
                    }
                }
            }
            "cipher" if fields.len() >= 2 => {
                reply.cipher = fields[1].trim().to_string();
            }
            "auth-token" if fields.len() >= 2 => {
                reply.auth_token_pass = fields[1].trim().to_string();
            }
            "auth-token-user" if fields.len() >= 2 => {
                let raw = fields[1].trim();
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(raw)
                    .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(raw));
                if let Ok(bytes) = decoded {
                    reply.auth_token_user = String::from_utf8_lossy(&bytes).into_owned();
                }
            }
            "push-continuation" => {
                if fields.len() != 2 {
                    return Err(Error::protocol("invalid push-continuation"));
                }
                let n: usize = fields[1].parse().map_err(|_| {
                    Error::protocol(format!("invalid push-continuation {:?}", fields[1]))
                })?;
                if n > 2 {
                    return Err(Error::protocol(format!(
                        "invalid push-continuation {:?}",
                        fields[1]
                    )));
                }
                reply.push_continuation = n;
            }
            _ => {}
        }
    }
    Ok(reply)
}

fn parse_cidr(s: &str) -> std::result::Result<(IpAddr, u8), String> {
    let (addr, bits) = s
        .split_once('/')
        .ok_or_else(|| format!("expected addr/prefix, got {s:?}"))?;
    let addr: IpAddr = addr.parse().map_err(|e| format!("{e}"))?;
    let bits: u8 = bits.parse().map_err(|e| format!("{e}"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if bits > max {
        return Err(format!("prefix {bits} too long"));
    }
    Ok((addr, bits))
}

/// client.go:1508-1570 takePushReply: walks complete NUL-delimited
/// control messages; returns `(reply-so-far, rest, complete)`.
fn take_push_reply(buf: &[u8]) -> (Option<PushReply>, Vec<u8>, bool) {
    let (msgs, rest) = split_control_messages(buf);
    if msgs.is_empty() {
        return (None, rest, false);
    }
    let mut auth_failed = false;
    let mut reply: Option<PushReply> = None;
    let mut parsed = false;
    let mut continuation_pending = false;
    for m in msgs {
        if m.starts_with(b"AUTH_FAILED") {
            auth_failed = true;
            continue;
        }
        if m.starts_with(b"AUTH_PENDING") {
            if let Ok(r) = parse_auth_pending_timeout(&String::from_utf8_lossy(&m)) {
                reply = merge_push_reply(reply.take(), r);
            }
            continue;
        }
        if m.starts_with(b"PUSH_REPLY") {
            if let Ok(r) = parse_push_reply_inner(&String::from_utf8_lossy(&m)) {
                continuation_pending = r.push_continuation == 2;
                reply = merge_push_reply(reply.take(), r);
                parsed = true;
                continue;
            }
        }
        // INFO_PRE, INFO, RESTART, HALT, EXIT, CR_RESPONSE: consumed.
    }
    if auth_failed {
        return (None, rest, false);
    }
    if !parsed || continuation_pending {
        return (reply, rest, false);
    }
    (reply, rest, true)
}

/// client.go:1574-1604 parseAuthPendingTimeout (cap 30min).
fn parse_auth_pending_timeout(msg: &str) -> Result<PushReply> {
    let mut reply = PushReply {
        peer_id: PEER_ID_UNSET,
        ..Default::default()
    };
    let rest = msg.strip_prefix("AUTH_PENDING").unwrap_or(msg);
    let rest = rest.strip_prefix(',').unwrap_or(rest);
    for part in rest.split(',') {
        let fields: Vec<&str> = part.split_whitespace().collect();
        if fields.len() == 2 && fields[0] == "timeout" {
            match fields[1].parse::<u64>() {
                Ok(mut secs) => {
                    if secs > 1800 {
                        secs = 1800;
                    }
                    reply.auth_pending_secs = secs;
                }
                Err(_) => reply.auth_pending_secs = 1800,
            }
        }
    }
    Ok(reply)
}

/// client.go:1629-1674 mergePushReply (dedup, wire order).
fn merge_push_reply(prev: Option<PushReply>, next: PushReply) -> Option<PushReply> {
    let Some(mut prev) = prev else { return Some(next) };
    let mut next = next;
    fn push_unique<T: PartialEq>(list: &mut Vec<T>, add: Vec<T>) {
        for v in add {
            if !list.contains(&v) {
                list.push(v);
            }
        }
    }
    // Upstream mutates `next` to hold prev+next's items and returns it
    // (mergePushReply); mirror exactly that.
    push_unique(&mut prev.prefixes, std::mem::take(&mut next.prefixes));
    next.prefixes = std::mem::take(&mut prev.prefixes);
    push_unique(&mut prev.routes, std::mem::take(&mut next.routes));
    next.routes = std::mem::take(&mut prev.routes);
    push_unique(&mut prev.dns, std::mem::take(&mut next.dns));
    next.dns = std::mem::take(&mut prev.dns);
    push_unique(
        &mut prev.data_ciphers,
        std::mem::take(&mut next.data_ciphers),
    );
    next.data_ciphers = std::mem::take(&mut prev.data_ciphers);
    if next.peer_id == PEER_ID_UNSET {
        next.peer_id = prev.peer_id;
    }
    if next.cipher.is_empty() {
        next.cipher = prev.cipher;
    }
    next.redirect |= prev.redirect;
    next.block_ipv6 |= prev.block_ipv6;
    if next.auth_token_pass.is_empty() {
        next.auth_token_pass = prev.auth_token_pass;
    }
    if next.auth_token_user.is_empty() {
        next.auth_token_user = prev.auth_token_user;
    }
    if !next.has_push_reply {
        next.push_continuation = prev.push_continuation;
        next.auth_pending_secs = prev.auth_pending_secs;
    }
    next.has_push_reply |= prev.has_push_reply;
    Some(next)
}

/// client.go:1613-1627 splitControlMessages.
fn split_control_messages(buf: &[u8]) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut msgs = Vec::new();
    let mut rest = buf;
    while let Some(idx) = rest.iter().position(|b| *b == 0) {
        msgs.push(rest[..idx].to_vec());
        rest = &rest[idx + 1..];
    }
    (msgs, rest.to_vec())
}

/// client.go:1450-1492 controlMessageError (AUTH_FAILED / RESTART /
/// HALT / EXIT).
fn control_message_error(buf: &[u8]) -> Result<()> {
    let (msgs, _) = split_control_messages(buf);
    for m in msgs {
        let s = String::from_utf8_lossy(&m);
        if m.starts_with(b"AUTH_FAILED") {
            return Err(Error::protocol(format!(
                "openvpn authentication failed: {}",
                s.trim()
            )));
        }
        for prefix in ["RESTART", "HALT", "EXIT"] {
            if m.starts_with(prefix.as_bytes()) {
                return Err(Error::protocol(format!(
                    "openvpn server terminated the control session: {}",
                    s.trim()
                )));
            }
        }
        if m.starts_with(b"PUSH_REPLY") {
            parse_push_reply_inner(&s)
                .map_err(|e| Error::protocol(format!("invalid openvpn push reply: {e}")))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Link transports (packetio.go)
// ---------------------------------------------------------------------------

/// packetio.go streamPacketIO / datagramPacketIO: TCP frames with a
/// 2-byte big-endian length prefix; UDP is one datagram per packet.
enum Link {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl Link {
    async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Link::Tcp(stream) => {
                use tokio::io::AsyncReadExt;
                let mut len = [0u8; 2];
                stream
                    .read_exact(&mut len)
                    .await
                    .map_err(|e| Error::network(e.to_string()))?;
                let size = usize::from(u16::from_be_bytes(len));
                if size == 0 {
                    return Err(Error::network("empty openvpn TCP packet"));
                }
                if size > buf.len() {
                    return Err(Error::network("openvpn TCP packet too large"));
                }
                stream
                    .read_exact(&mut buf[..size])
                    .await
                    .map_err(|e| Error::network(e.to_string()))?;
                Ok(size)
            }
            Link::Udp(socket) => {
                let n = socket
                    .recv(buf)
                    .await
                    .map_err(|e| Error::network(e.to_string()))?;
                Ok(n)
            }
        }
    }

    async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        match self {
            Link::Tcp(stream) => {
                use tokio::io::AsyncWriteExt;
                if packet.len() > 0xffff {
                    return Err(Error::network(format!(
                        "openvpn TCP packet too large: {}",
                        packet.len()
                    )));
                }
                let mut frame = Vec::with_capacity(2 + packet.len());
                frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
                frame.extend_from_slice(packet);
                stream
                    .write_all(&frame)
                    .await
                    .map_err(|e| Error::network(e.to_string()))?;
                stream
                    .flush()
                    .await
                    .map_err(|e| Error::network(e.to_string()))?;
                Ok(())
            }
            Link::Udp(socket) => {
                socket
                    .send(packet)
                    .await
                    .map(|_| ())
                    .map_err(|e| Error::network(e.to_string()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reliable control state (control.go)
// ---------------------------------------------------------------------------

/// control.go:373-383: RELIABLE_ACK_SIZE, RELIABLE_CAPACITY and
/// CONTROL_SEND_ACK_MAX.
const RELIABLE_ACK_SIZE: usize = 8;
const RELIABLE_CAPACITY: usize = 12;
const CONTROL_SEND_ACK_MAX: usize = 4;
/// client.go:24 ControlRetransmitDelay.
const CONTROL_RETRANSMIT_DELAY: Duration = Duration::from_secs(1);
/// control.go:977 maxTLSControlPayload.
const MAX_TLS_CONTROL_PAYLOAD: usize = 1100;
/// client.go:1176 maxTLSControlBuffer.
const MAX_TLS_CONTROL_BUFFER: usize = 1 << 20;
const CONTROL_REPLAY_WINDOW: usize = 64;
const CONTROL_REPLAY_TIME_BACKTRACK: Duration = Duration::from_secs(15);

/// control.go:70-77 replayState + checkReplayLocked: slots hold
/// acceptance times; 0 unseen, 1 expired.
struct RecReplay {
    time: u32,
    high_id: u32,
    slots: [i64; CONTROL_REPLAY_WINDOW],
    seen: bool,
}

impl RecReplay {
    fn new() -> Self {
        RecReplay {
            time: 0,
            high_id: 0,
            slots: [0; CONTROL_REPLAY_WINDOW],
            seen: false,
        }
    }

    fn check(&mut self, packet_id: u32, unix_time: u32) -> bool {
        if packet_id == 0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        if !self.seen || unix_time > self.time {
            *self = RecReplay {
                time: unix_time,
                high_id: packet_id,
                seen: true,
                slots: [0; CONTROL_REPLAY_WINDOW],
            };
            self.slots[0] = now.as_nanos() as i64;
            return true;
        }
        if unix_time < self.time {
            return false; // timestamp backtrack
        }
        self.reap(now);
        if packet_id > self.high_id {
            let shift = (packet_id - self.high_id) as usize;
            if shift >= CONTROL_REPLAY_WINDOW {
                self.slots = [0; CONTROL_REPLAY_WINDOW];
            } else {
                for i in (shift..CONTROL_REPLAY_WINDOW).rev() {
                    self.slots[i] = self.slots[i - shift];
                }
                for slot in &mut self.slots[..shift] {
                    *slot = 0;
                }
            }
            self.high_id = packet_id;
            self.slots[0] = now.as_nanos() as i64;
            return true;
        }
        let diff = (self.high_id - packet_id) as usize;
        if diff >= CONTROL_REPLAY_WINDOW || self.slots[diff] != 0 {
            return false;
        }
        self.slots[diff] = now.as_nanos() as i64;
        true
    }

    /// control.go:145-158 reap.
    fn reap(&mut self, now: std::time::Duration) {
        let mut expire = false;
        for slot in &mut self.slots {
            let accepted = *slot;
            if accepted == 1 {
                break;
            }
            if !expire
                && accepted > 1
                && std::time::Duration::from_nanos(accepted as u64) + CONTROL_REPLAY_TIME_BACKTRACK
                    < now
            {
                expire = true;
            }
            if expire {
                *slot = 1;
            }
        }
    }
}

/// control.go:87-92.
fn recv_window_ok(recv_message: u32, message_id: u32, buffered: usize) -> bool {
    message_id.wrapping_sub(recv_message) < RELIABLE_CAPACITY as u32 && buffered < RELIABLE_CAPACITY
}

/// control.go:91-93 reliableMessageBefore.
fn reliable_message_before(message_id: u32, recv_message: u32) -> bool {
    message_id.wrapping_sub(recv_message) >= 1u32 << 31
}

/// control.go:203-209 NextKeyID (0 → 1 → … → 7 → 1).
fn next_key_id(current: u8) -> u8 {
    let next = (current + 1) & KEY_ID_MASK;
    if next == 0 {
        1
    } else {
        next
    }
}

/// control.go:964-971 appendAck.
fn append_ack(acks: &mut Vec<u32>, ack: u32) {
    if !acks.contains(&ack) {
        acks.push(ack);
    }
}

/// The reliable-control half of `ControlChannel` (single owner: the
/// mutexes/goroutines of upstream collapse into task locality).
struct Reliable {
    local: [u8; SESSION_ID_SIZE],
    remote: Option<[u8; SESSION_ID_SIZE]>,
    key_id: u8,
    send_message: u32,
    recv_message: u32,
    ack_pending: Vec<u32>,
    lru_acks: Vec<u32>,
    pending: Vec<ControlPacket>,
    recv_pending: HashMap<u32, ControlPacket>,
    replay: RecReplay,
}

/// The result of one inbound control datagram.
enum ControlOutcome {
    /// In-order delivery.
    Deliver(ControlPacket),
    /// A server soft reset for the next key epoch.
    SoftReset(ControlPacket),
    /// Dropped (loss / wrong session / replay).
    Dropped,
}

impl Reliable {
    fn new(local: [u8; SESSION_ID_SIZE]) -> Self {
        Reliable {
            local,
            remote: None,
            key_id: 0,
            send_message: 0,
            recv_message: 0,
            ack_pending: Vec::new(),
            lru_acks: Vec::new(),
            pending: Vec::new(),
            recv_pending: HashMap::new(),
            replay: RecReplay::new(),
        }
    }

    /// control.go:217-226 beginEpochLocked.
    fn begin_epoch(&mut self, key_id: u8) {
        self.key_id = key_id & KEY_ID_MASK;
        self.send_message = 0;
        self.recv_message = 0;
        self.ack_pending.clear();
        self.lru_acks.clear();
        self.pending.clear();
        self.recv_pending.clear();
    }

    /// control.go:327-370 takeAcksLocked.
    fn take_acks(&mut self, max: usize) -> Vec<u32> {
        let n = self.ack_pending.len().min(max);
        // Move ack_pending[:n] into the MRU front (backwards loop).
        let mut i = n;
        while i > 0 {
            i -= 1;
            let id = self.ack_pending[i];
            let mut moving = id;
            let mut found = false;
            for slot in self.lru_acks.iter_mut() {
                std::mem::swap(slot, &mut moving);
                if moving == id {
                    found = true;
                    break;
                }
            }
            if !found && self.lru_acks.len() < RELIABLE_ACK_SIZE {
                self.lru_acks.push(moving);
            }
        }
        self.ack_pending.drain(..n);
        if self.lru_acks.len() > RELIABLE_ACK_SIZE {
            self.lru_acks.truncate(RELIABLE_ACK_SIZE);
        }
        let k = self.lru_acks.len().min(max);
        self.lru_acks[..k].to_vec()
    }

    /// One inbound raw control datagram (control.go:515-713 read).
    fn handle_raw(&mut self, crypt: Option<&ControlCrypt>, raw: &[u8]) -> ControlOutcome {
        let (packet, packet_id, unix_time) = match Self::decode_packet(crypt, raw) {
            Ok(v) => v,
            // Invalid control datagrams are packet loss, not TLS stream
            // errors (control.go:546-552).
            Err(_) => return ControlOutcome::Dropped,
        };
        if packet.local_session == [0u8; SESSION_ID_SIZE] {
            return ControlOutcome::Dropped;
        }
        if !packet.ack_ids.is_empty() && packet.ack_remote_session != self.local {
            return ControlOutcome::Dropped;
        }
        let mut replay_checked = false;
        if self.remote.is_none() {
            let initial_reset = matches!(
                packet.opcode,
                P_CONTROL_HARD_RESET_SERVER_V2 | P_CONTROL_HARD_RESET_SERVER_V1
            ) && packet.key_id == self.key_id
                && packet.message_id == 0;
            if initial_reset {
                if crypt.is_some() && !self.replay.check(packet_id, unix_time) {
                    return ControlOutcome::Dropped;
                }
                replay_checked = true;
                self.remote = Some(packet.local_session);
            }
        }
        if self.remote != Some(packet.local_session) {
            return ControlOutcome::Dropped;
        }

        // Soft resets park for the rekey state machine (the packet-id
        // replay belongs to the outer session and survives rekeys).
        if packet.opcode == P_CONTROL_SOFT_RESET_V1 {
            if packet.key_id == next_key_id(self.key_id)
                && packet.message_id == 0
                && crypt.is_some()
                && !self.replay.check(packet_id, unix_time)
            {
                return ControlOutcome::Dropped;
            }
            for ack in &packet.ack_ids {
                self.pending.retain(|p| p.message_id != *ack);
            }
            return ControlOutcome::SoftReset(packet);
        }
        if packet.key_id != self.key_id {
            return ControlOutcome::Dropped; // retiring epoch
        }
        if crypt.is_some() && !replay_checked && !self.replay.check(packet_id, unix_time) {
            return ControlOutcome::Dropped;
        }

        for ack in &packet.ack_ids {
            self.pending.retain(|p| p.message_id != *ack);
        }

        match packet.opcode {
            P_ACK_V1 => ControlOutcome::Dropped,
            op if !opcode_has_message_id(op) => ControlOutcome::Deliver(packet),
            _ if reliable_message_before(packet.message_id, self.recv_message) => {
                // In-window replay of a delivered packet: re-ACK.
                append_ack(&mut self.ack_pending, packet.message_id);
                ControlOutcome::Dropped
            }
            _ if packet.message_id == self.recv_message => {
                append_ack(&mut self.ack_pending, packet.message_id);
                self.recv_message += 1;
                ControlOutcome::Deliver(packet)
            }
            _ => {
                if self.recv_pending.contains_key(&packet.message_id) {
                    append_ack(&mut self.ack_pending, packet.message_id);
                } else if recv_window_ok(
                    self.recv_message,
                    packet.message_id,
                    self.recv_pending.len(),
                ) {
                    append_ack(&mut self.ack_pending, packet.message_id);
                    self.recv_pending.insert(packet.message_id, packet);
                }
                ControlOutcome::Dropped
            }
        }
    }

    /// Clean decode used by `handle_raw` (plain or crypt-unwrapped).
    fn decode_packet(
        crypt: Option<&ControlCrypt>,
        raw: &[u8],
    ) -> Result<(ControlPacket, u32, u32)> {
        let (opcode, key_id, local, acks, ack_remote, message_id, payload, pid, time) =
            match crypt {
                None => {
                    if raw.len() < TLS_CRYPT_HEADER_SIZE + 1 {
                        return Err(Error::protocol("control packet too short"));
                    }
                    let (opcode, key_id) = parse_opcode_key_id(raw[0]);
                    if !opcode_is_control(opcode) {
                        return Err(Error::protocol(format!(
                            "opcode {opcode} is not a control opcode"
                        )));
                    }
                    let mut local = [0u8; SESSION_ID_SIZE];
                    local.copy_from_slice(&raw[1..TLS_CRYPT_HEADER_SIZE]);
                    let (acks, ack_remote, message_id, payload) =
                        control_decode_plain(opcode, &raw[TLS_CRYPT_HEADER_SIZE..])?;
                    (opcode, key_id, local, acks, ack_remote, message_id, payload, 0, 0)
                }
                Some(crypt) => {
                    let (header, pid, time, plain) = crypt.unwrap(raw)?;
                    if header.len() != TLS_CRYPT_HEADER_SIZE {
                        return Err(Error::protocol(format!(
                            "invalid control header length {}",
                            header.len()
                        )));
                    }
                    let (opcode, key_id) = parse_opcode_key_id(header[0]);
                    if !opcode_is_control(opcode) {
                        return Err(Error::protocol(format!(
                            "opcode {opcode} is not a control opcode"
                        )));
                    }
                    let mut local = [0u8; SESSION_ID_SIZE];
                    local.copy_from_slice(&header[1..]);
                    let (acks, ack_remote, message_id, payload) =
                        control_decode_plain(opcode, &plain)?;
                    (opcode, key_id, local, acks, ack_remote, message_id, payload, pid, time)
                }
            };
        Ok((
            ControlPacket {
                opcode,
                key_id,
                local_session: local,
                ack_ids: acks,
                ack_remote_session: ack_remote,
                message_id,
                payload,
            },
            pid,
            time,
        ))
    }

    /// Build the next outgoing reliable control packet
    /// (control.go:291-319 Send).
    fn build_send(
        &mut self,
        opcode: u8,
        payload: Vec<u8>,
        remote: [u8; SESSION_ID_SIZE],
    ) -> ControlPacket {
        let message_id = self.send_message;
        self.send_message += 1;
        let ack_ids = self.take_acks(CONTROL_SEND_ACK_MAX);
        ControlPacket {
            opcode,
            key_id: self.key_id,
            local_session: self.local,
            ack_ids,
            ack_remote_session: remote,
            message_id,
            payload,
        }
    }
}

// ---------------------------------------------------------------------------
// The tunnel client (client.go)
// ---------------------------------------------------------------------------

/// client.go:555 authDeferredExpire.
const AUTH_DEFERRED_EXPIRE: Duration = Duration::from_secs(60);

type UdpDownlink = mpsc::Receiver<(NetAddr, Vec<u8>)>;

enum Cmd {
    Connect {
        remote: SocketAddr,
        reply: oneshot::Sender<Result<Arc<StreamShared>>>,
    },
    UdpOpen {
        reply: oneshot::Sender<Result<(u32, UdpDownlink)>>,
    },
    UdpSend {
        id: u32,
        dst: SocketAddr,
        data: Vec<u8>,
    },
    UdpClose {
        id: u32,
    },
}

struct Conn {
    handle: SocketHandle,
    shared: Arc<StreamShared>,
    fin_sent: bool,
    pending: Option<(oneshot::Sender<Result<Arc<StreamShared>>>, Instant)>,
}

struct UdpSock {
    handle: SocketHandle,
    port: u16,
    down: mpsc::Sender<(NetAddr, Vec<u8>)>,
}

/// The rekey state machine (client.go:882-1022 watchControl/renegotiate).
enum Phase {
    Established,
    /// Fresh TLS epoch driving toward the KM2 record.
    RekeyTls { sent_km2: bool },
    RekeyKm2 { buf: Vec<u8> },
    Failed,
}

struct Client {
    settings: Settings,
    crypt: Option<ControlCrypt>,
    reliable: Reliable,
    send_packet_id: u32,
    send_packet_time: u32,
    /// TLS epoch riding the control channel.
    tls: Option<rustls::ClientConnection>,
    /// Plaintext read past the server KM2 record.
    leftover_tls: Vec<u8>,
    /// The client KM2 source (pre-master + randoms) of this epoch.
    km2_client_source: Option<KeySource>,
    /// Accumulated intermediate push segments (AUTH_PENDING /
    /// push-continuation).
    pending_push: Option<PushReply>,
    pending_soft_reset: Option<ControlPacket>,
    phase: Phase,
    /// The cached push (addresses, routes, peer-id, cipher) — rekey input.
    push: Option<PushReply>,
    negotiated_cipher: String,
    /// Data epochs: current + retiring (lame-duck), by key id.
    data: HashMap<u8, DataChannel>,
    current_key: Option<u8>,
    outbound_key: Option<u8>,
    outbound_start: Instant,
    retiring: Option<(u8, Instant)>,
    /// Egress queued before the handshake completed.
    pre_session_tx: VecDeque<Vec<u8>>,
    // netstack
    iface: Interface,
    sockets: SocketSet<'static>,
    shim: Shim,
    conns: Vec<Conn>,
    udp: HashMap<u32, UdpSock>,
    used_ports: HashSet<u16>,
    next_udp_id: u32,
    wake: Arc<Notify>,
    start: Instant,
    pump_buf: Vec<u8>,
    last_send: Instant,
    last_receive: Instant,
    rekey_deadline: Option<Instant>,
    fail: Option<Error>,
}

// netstack buffer sizes (wireguard.rs parity).
const TCP_RX_BYTES: usize = 64 * 1024;
const TCP_TX_BYTES: usize = 64 * 1024;
const UDP_RX_BYTES: usize = 32 * 1024;
const UDP_TX_BYTES: usize = 32 * 1024;
const UDP_PACKETS: usize = 64;
const PRE_SESSION_QUEUE_MAX: usize = 512;
const MAX_CONNS: usize = 128;
const MAX_UDP_SOCKETS: usize = 64;
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_TICK: Duration = Duration::from_millis(1);
const MAX_TICK: Duration = Duration::from_secs(1);
const PUMP_CHUNK: usize = 32 * 1024;
const STREAM_QUEUE_MAX: usize = 256 * 1024;

impl Client {
    fn new(settings: Settings, wake: Arc<Notify>) -> Result<Self> {
        let crypt = ControlCrypt::new(&settings)?;
        let mut local = [0u8; SESSION_ID_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut local);
        let reliable = Reliable::new(local);
        let mut shim = Shim::new(settings.mtu);
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = rand::random();
        let iface = Interface::new(iface_cfg, &mut shim, SmolInstant::ZERO);
        Ok(Client {
            crypt,
            reliable,
            send_packet_id: 0,
            send_packet_time: 0,
            tls: None,
            leftover_tls: Vec::new(),
            km2_client_source: None,
            pending_push: None,
            pending_soft_reset: None,
            phase: Phase::Established,
            push: None,
            negotiated_cipher: String::new(),
            data: HashMap::new(),
            current_key: None,
            outbound_key: None,
            outbound_start: Instant::now(),
            retiring: None,
            pre_session_tx: VecDeque::new(),
            iface,
            sockets: SocketSet::new(Vec::new()),
            shim,
            conns: Vec::new(),
            udp: HashMap::new(),
            used_ports: HashSet::new(),
            next_udp_id: 1,
            wake,
            start: Instant::now(),
            pump_buf: vec![0u8; PUMP_CHUNK],
            last_send: Instant::now(),
            last_receive: Instant::now(),
            rekey_deadline: None,
            fail: None,
            settings,
        })
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
    }

    fn established(&self) -> bool {
        self.current_key.is_some() && self.fail.is_none()
    }

    // -- control send ------------------------------------------------------

    /// control.go:786-835 writeControlPacketGranted: wraps with the
    /// cryptor (advancing the outer packet id) and appends the wrapped
    /// client key to the V3 reset.
    async fn write_control_packet(&mut self, link: &mut Link, packet: ControlPacket) -> Result<()> {
        if self.crypt.is_some() && self.send_packet_id == u32::MAX {
            return Err(Error::network(
                "openvpn control packet id exhausted; new session required",
            ));
        }
        if self.crypt.is_some() && self.send_packet_time == 0 {
            self.send_packet_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
        }
        self.send_packet_id += 1;
        let packet_id = self.send_packet_id;
        let unix_time = self.send_packet_time;

        let mut header = Vec::with_capacity(TLS_CRYPT_HEADER_SIZE);
        header.push(opcode_key_id(packet.opcode, packet.key_id));
        header.extend_from_slice(&packet.local_session);
        let plain = control_encode_plain(&packet)?;
        let mut encoded = match &self.crypt {
            None => [header, plain].concat(),
            Some(crypt) => crypt.wrap(&header, packet_id, unix_time, &plain)?,
        };
        // client.go:816-819: the wrapped client key rides the first V3
        // hard reset.
        if let Some(crypt) = &self.crypt {
            if crypt.is_v2()
                && packet.opcode == P_CONTROL_HARD_RESET_CLIENT_V3
                && packet.message_id == 0
            {
                encoded.extend_from_slice(crypt.wrapped_client_key());
            }
        }
        link.write_packet(&encoded).await?;
        self.last_send = Instant::now();
        Ok(())
    }

    /// control.go:291-319 Send.
    async fn send_control(&mut self, link: &mut Link, opcode: u8, payload: Vec<u8>) -> Result<u32> {
        if !opcode_has_message_id(opcode) {
            return Err(Error::protocol(format!(
                "opcode {opcode} cannot carry a reliable message"
            )));
        }
        let remote = self.reliable.remote.unwrap_or([0u8; SESSION_ID_SIZE]);
        let packet = self.reliable.build_send(opcode, payload, remote);
        let message_id = packet.message_id;
        self.reliable.pending.push(packet.clone());
        self.write_control_packet(link, packet).await?;
        Ok(message_id)
    }

    /// control.go:397-429 SendAck (dedicated P_ACK_V1, SoftEther cap 4
    /// when unprotected).
    async fn send_ack(&mut self, link: &mut Link) -> Result<()> {
        if self.reliable.ack_pending.is_empty() {
            return Ok(());
        }
        let max = if self.crypt.is_none() {
            CONTROL_SEND_ACK_MAX
        } else {
            RELIABLE_ACK_SIZE
        };
        let ack_ids = self.reliable.take_acks(max);
        if ack_ids.is_empty() {
            return Ok(());
        }
        let remote = self.reliable.remote.unwrap_or([0u8; SESSION_ID_SIZE]);
        let packet = ControlPacket {
            opcode: P_ACK_V1,
            key_id: self.reliable.key_id,
            local_session: self.reliable.local,
            ack_ids,
            ack_remote_session: remote,
            message_id: 0,
            payload: Vec::new(),
        };
        self.write_control_packet(link, packet).await
    }

    /// control.go:740-768 RetransmitPending (re-encoded: tls-auth /
    /// tls-crypt packet ids advance).
    async fn retransmit_pending(&mut self, link: &mut Link) -> Result<()> {
        if self.reliable.pending.is_empty() {
            return Ok(());
        }
        let remote = self.reliable.remote.unwrap_or([0u8; SESSION_ID_SIZE]);
        let ack_ids = self.reliable.take_acks(CONTROL_SEND_ACK_MAX);
        let packets: Vec<ControlPacket> = self
            .reliable
            .pending
            .iter()
            .map(|p| ControlPacket {
                ack_ids: ack_ids.clone(),
                ack_remote_session: remote,
                ..p.clone()
            })
            .collect();
        for packet in packets {
            self.write_control_packet(link, packet).await?;
        }
        Ok(())
    }

    /// client.go:191-198 SendReset.
    async fn send_reset(&mut self, link: &mut Link) -> Result<()> {
        let opcode = match &self.crypt {
            Some(c) if c.is_v2() => P_CONTROL_HARD_RESET_CLIENT_V3,
            _ => P_CONTROL_HARD_RESET_CLIENT_V2,
        };
        self.send_control(link, opcode, Vec::new()).await?;
        Ok(())
    }

    // -- packet dispatch ---------------------------------------------------

    /// One raw packet off the link: control → reliable handling + phase
    /// dispatch; data → epoch decrypt → netstack.
    async fn on_packet(&mut self, link: &mut Link, raw: &[u8]) {
        if raw.is_empty() {
            return;
        }
        let (opcode, _) = parse_opcode_key_id(raw[0]);
        if opcode_is_control(opcode) {
            self.last_receive = Instant::now();
            let outcome = self.reliable.handle_raw(self.crypt.as_ref(), raw);
            if !self.reliable.ack_pending.is_empty() && self.send_ack(link).await.is_err() {
                self.fail_tunnel(Error::network("openvpn: control ACK write failed"));
                return;
            }
            match outcome {
                ControlOutcome::Deliver(packet) => self.on_control_payload(link, packet).await,
                ControlOutcome::SoftReset(packet) => {
                    // Park; the run loop starts the renegotiation.
                    if self.pending_soft_reset.is_none() {
                        self.pending_soft_reset = Some(packet);
                    }
                }
                ControlOutcome::Dropped => {}
            }
        } else {
            self.on_data_packet(raw);
        }
    }

    /// Data-plane packet: route by key id (current or retiring epoch).
    fn on_data_packet(&mut self, packet: &[u8]) {
        let (_, key_id) = parse_opcode_key_id(packet[0]);
        // The retiring epoch is rejected once the transition window ends.
        if let Some((kid, expiry)) = self.retiring {
            if kid == key_id && Instant::now() > expiry {
                tracing::debug!(target: "engine", "openvpn: data packet from expired retiring epoch");
                return;
            }
        }
        let is_newest = Some(key_id) == self.current_key;
        let plain = {
            let Some(channel) = self.data.get_mut(&key_id) else {
                tracing::debug!(target: "engine", "openvpn: data packet with unknown key id {key_id}");
                return;
            };
            match channel.decrypt(packet) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(target: "engine", "openvpn: data decrypt: {e}");
                    return;
                }
            }
        };
        if is_newest {
            // Peer evidence: the epoch is active for outbound selection.
            if let Some(channel) = self.data.get_mut(&key_id) {
                channel.peer_active = true;
            }
        }
        self.last_receive = Instant::now();
        let plain = if self.settings.comp_lzo && !plain.is_empty() {
            match lzo_unframe(&plain) {
                Ok(p) => p,
                Err(e) => {
                    self.fail_tunnel(e);
                    return;
                }
            }
        } else {
            plain
        };
        if plain == OPENVPN_PING_PACKET {
            return;
        }
        self.shim.stage(&plain);
        self.wake.notify_one();
    }

    /// A delivered in-order control packet (P_CONTROL_V1 payload or a
    /// reset-family message).
    async fn on_control_payload(&mut self, link: &mut Link, packet: ControlPacket) {
        if packet.opcode != P_CONTROL_V1 || packet.payload.is_empty() {
            return;
        }
        let rekeying = matches!(self.phase, Phase::RekeyTls { .. } | Phase::RekeyKm2 { .. });
        if rekeying {
            let payload = packet.payload.clone();
            self.feed_tls_and_pump(link, &payload).await;
            return;
        }
        // Post-handshake TLS control messages: scan for terminal
        // failures; token-only pushes are consumed like upstream's
        // parked-TLS path.
        self.leftover_tls.extend_from_slice(&packet.payload);
        if self.leftover_tls.len() > MAX_TLS_CONTROL_BUFFER {
            self.fail_tunnel(Error::protocol("openvpn TLS control buffer overflow"));
            return;
        }
        if let Err(e) = control_message_error(&self.leftover_tls) {
            self.fail_tunnel(e);
        }
    }

    // -- TLS over the control channel ---------------------------------------

    /// Drain the rustls connection's pending output into chunked
    /// P_CONTROL_V1 messages (ControlConn.Write + maxTLSControlPayload).
    async fn tls_flush_writes(&mut self, link: &mut Link) -> Result<()> {
        loop {
            let Some(tls) = self.tls.as_mut() else {
                return Ok(());
            };
            if !tls.wants_write() {
                return Ok(());
            }
            let mut chunk = Vec::new();
            if tls
                .write_tls(&mut chunk)
                .map_err(|e| Error::network(e.to_string()))?
                == 0
            {
                return Ok(());
            }
            for piece in chunk.chunks(MAX_TLS_CONTROL_PAYLOAD) {
                if !self.reliable.ack_pending.is_empty() {
                    // ControlConn.Write: flush ACKs first so the record's
                    // own control message stays pure TLS bytes.
                    self.send_ack(link).await?;
                }
                self.send_control(link, P_CONTROL_V1, piece.to_vec()).await?;
            }
        }
    }

    /// Feed wire bytes into the rustls connection, then pump both
    /// directions and the phase state machine.
    async fn feed_tls_and_pump(&mut self, link: &mut Link, wire: &[u8]) {
        if let Err(e) = self.tls_feed(wire) {
            self.fail_tunnel(Error::network(format!("openvpn tls: {e}")));
            return;
        }
        self.pump_tls(link).await;
    }

    fn tls_feed(&mut self, wire: &[u8]) -> std::result::Result<(), rustls::Error> {
        let Some(tls) = self.tls.as_mut() else { return Ok(()) };
        let mut rest = wire;
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
        tls.process_new_packets().map(|_| ())
    }

    /// Pull available plaintext into the phase buffer, flush writes, and
    /// advance the rekey phases.
    async fn pump_tls(&mut self, link: &mut Link) {
        if let Err(e) = self.tls_flush_writes(link).await {
            self.fail_tunnel(e);
            return;
        }
        let mut got = Vec::new();
        {
            let Some(tls) = self.tls.as_mut() else { return };
            let mut tmp = [0u8; 4096];
            loop {
                match std::io::Read::read(&mut tls.reader(), &mut tmp) {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&tmp[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        self.fail_tunnel(Error::network(format!("openvpn tls read: {e}")));
                        return;
                    }
                }
            }
        }
        let handshaking = self.tls.as_ref().is_some_and(|t| t.is_handshaking());
        match &mut self.phase {
            Phase::RekeyTls { sent_km2 } => {
                if !handshaking {
                    if !got.is_empty() {
                        self.leftover_tls.extend_from_slice(&got);
                    }
                    if !*sent_km2 {
                        *sent_km2 = true;
                        // Send our KM2 record over the fresh epoch.
                        let options = install_script_options_string(
                            &self.settings.proto,
                            &self.settings.cipher,
                            &self.settings.auth,
                            self.settings.comp_lzo,
                        );
                        let peer_info = install_script_peer_info(
                            &self.settings.cipher,
                            &self.settings.data_ciphers,
                            self.settings.comp_lzo,
                            &self.settings.peer_info,
                        );
                        let (record, source) = client_km2_record(
                            &options,
                            &peer_info,
                            &self.settings.username,
                            &self.settings.password,
                        );
                        self.km2_client_source = Some(source);
                        let phase = Phase::RekeyKm2 {
                            buf: std::mem::take(&mut self.leftover_tls),
                        };
                        if let Err(e) = self.tls_write_all(link, &record).await {
                            self.fail_tunnel(e);
                            return;
                        }
                        self.phase = phase;
                    }
                }
            }
            Phase::RekeyKm2 { buf } => {
                buf.extend_from_slice(&got);
                if buf.len() > MAX_TLS_CONTROL_BUFFER {
                    self.fail_tunnel(Error::protocol("openvpn TLS control buffer overflow"));
                    return;
                }
                if let Err(e) = control_message_error(buf) {
                    self.fail_tunnel(e);
                    return;
                }
                let ready = km2_record_complete(buf).is_some()
                    || parse_server_km2(buf)
                        .map(|(_, consumed)| consumed < buf.len())
                        .unwrap_or(false);
                if ready {
                    let buf = std::mem::take(buf);
                    match self.finish_km2(&buf) {
                        Ok(()) => self.phase = Phase::Established,
                        Err(e) => self.fail_tunnel(e),
                    }
                }
            }
            _ => {}
        }
    }

    async fn tls_write_all(&mut self, link: &mut Link, bytes: &[u8]) -> Result<()> {
        {
            let Some(tls) = self.tls.as_mut() else { return Ok(()) };
            use std::io::Write;
            tls.writer()
                .write_all(bytes)
                .map_err(|e| Error::network(format!("openvpn tls write: {e}")))?;
        }
        self.tls_flush_writes(link).await
    }

    // -- key exchange --------------------------------------------------------

    /// Parse the server KM2 out of `buf`, derive keys, negotiate the
    /// cipher against the cached push and install the new epoch.
    fn finish_km2(&mut self, buf: &[u8]) -> Result<()> {
        let (record, consumed) = parse_server_km2(buf)?;
        self.leftover_tls = buf[consumed..].to_vec();
        let client = self
            .km2_client_source
            .take()
            .ok_or_else(|| Error::protocol("openvpn: no client key source"))?;
        let key_id = self.reliable.key_id;
        let (client_session, server_session) = (
            self.reliable.local,
            self.reliable.remote.unwrap_or([0u8; SESSION_ID_SIZE]),
        );
        // Derive with the maximum cipher key length, slice after the
        // cipher is negotiated (client.go:313-316, 373-376).
        let mut keys = derive_client_key_material(
            &client,
            &record.sources,
            &client_session,
            &server_session,
            32,
        )
        .map_err(|e| Error::network(format!("derive data channel keys: {e}")))?;

        let push = self
            .push
            .clone()
            .ok_or_else(|| Error::protocol("openvpn: no cached push for key exchange"))?;
        let negotiated = negotiate_cipher(&self.settings, &push.data_ciphers, &push.cipher)
            .map_err(|e| Error::network(format!("negotiate data cipher: {e}")))?;
        self.negotiated_cipher = negotiated.clone();
        let key_len = cipher_key_length(&negotiated);
        keys.send_cipher_key.truncate(key_len);
        keys.recv_cipher_key.truncate(key_len);
        let channel = DataChannel::new(&keys, &negotiated, &self.settings.auth, push.peer_id, key_id)?;
        self.install_data_channel(channel);
        Ok(())
    }

    /// client.go:604-662 installDataChannel: keep the retiring epoch
    /// for the transition window; outbound stays on the old epoch until
    /// peer evidence / the no-evidence window / retiring expiry.
    fn install_data_channel(&mut self, new_data: DataChannel) {
        let new_key = new_data.key_id;
        if let Some(old_key) = self.current_key.replace(new_key) {
            if old_key != new_key {
                self.retiring = Some((old_key, Instant::now() + self.settings.transition_window));
            }
            self.outbound_key = Some(old_key);
        } else {
            self.outbound_key = Some(new_key);
        }
        self.outbound_start = Instant::now();
        self.data.insert(new_key, new_data);
        // Keep at most current + retiring.
        let keep: Vec<u8> = [self.current_key, self.retiring.map(|(k, _)| k)]
            .into_iter()
            .flatten()
            .collect();
        self.data.retain(|k, _| keep.contains(k));
    }

    /// client.go:951-1022 renegotiate (single-shot state machine): the
    /// caller sends the soft-reset reply and starts the fresh TLS epoch.
    fn begin_rekey(&mut self) {
        let Some(reset) = self.pending_soft_reset.take() else {
            return;
        };
        let key_id = reset.key_id & KEY_ID_MASK;
        self.reliable.begin_epoch(key_id);
        // The watcher already consumed message 0 of the new epoch
        // (MarkReceived + QueueAck).
        let mid = reset.message_id;
        let next = mid.wrapping_add(1);
        if next != self.reliable.recv_message
            && !reliable_message_before(next, self.reliable.recv_message)
        {
            self.reliable.recv_message = next;
        }
        self.reliable.recv_pending.remove(&mid);
        append_ack(&mut self.reliable.ack_pending, mid);
        self.leftover_tls.clear();
        self.km2_client_source = None;
        self.rekey_deadline = Some(Instant::now() + self.settings.handshake_timeout);
    }

    async fn send_soft_reset(&mut self, link: &mut Link) -> Result<()> {
        self.send_control(link, P_CONTROL_SOFT_RESET_V1, Vec::new())
            .await?;
        Ok(())
    }

    // -- data path ------------------------------------------------------------

    /// client.go:686-795 writeDataPacket: comp-lzo framing, epoch
    /// selection, encrypt, send.
    async fn write_data_packet(&mut self, link: &mut Link, packet: &[u8], compress: bool) -> Result<()> {
        let packet = if compress && self.settings.comp_lzo {
            lzo_frame(packet)
        } else {
            packet.to_vec()
        };
        loop {
            let (current, outbound, promote) = self.select_outbound();
            let Some(current) = current else {
                return Err(Error::network("openvpn data channel is not ready"));
            };
            let Some(outbound) = outbound else {
                return Err(Error::network("openvpn data channel is not ready"));
            };
            if promote {
                self.outbound_key = Some(current);
                self.outbound_start = Instant::now();
                continue;
            }
            let Some(channel) = self.data.get_mut(&outbound) else {
                return Err(Error::network("openvpn data epoch vanished mid-write"));
            };
            let encrypted = channel.encrypt(&packet)?;
            link.write_packet(&encrypted).await?;
            self.last_send = Instant::now();
            return Ok(());
        }
    }

    /// Outbound epoch selection (writeDataPacket's promotion checks).
    fn select_outbound(&self) -> (Option<u8>, Option<u8>, bool) {
        let current = self.current_key;
        let outbound = self.outbound_key.or(current);
        let Some(cur) = current else { return (None, None, false) };
        let Some(out) = outbound else { return (current, None, false) };
        if out == cur {
            return (current, outbound, false);
        }
        let peer_active = self.data.get(&cur).is_some_and(|d| d.peer_active);
        let selection_expired = Instant::now() > self.outbound_start + AUTH_DEFERRED_EXPIRE;
        let retiring_expired = self
            .retiring
            .is_some_and(|(k, expiry)| Some(k) == outbound && Instant::now() > expiry);
        (current, outbound, peer_active || selection_expired || retiring_expired)
    }

    async fn write_ping(&mut self, link: &mut Link) -> Result<()> {
        self.write_data_packet(link, &OPENVPN_PING_PACKET, false)
            .await
    }

    // -- netstack service (wireguard.rs parity) -------------------------------

    async fn step(&mut self, link: &mut Link) {
        let now = self.now();
        self.iface.poll(now, &mut self.shim, &mut self.sockets);
        self.service_conns();
        self.drain_udp_rx();
        let now = self.now();
        self.iface.poll(now, &mut self.shim, &mut self.sockets);
        self.drain_egress(link).await;
    }

    fn service_conns(&mut self) {
        let now = Instant::now();
        let mut dead: Vec<SocketHandle> = Vec::new();
        for c in self.conns.iter_mut() {
            let sock = self.sockets.get_mut::<tcp::Socket>(c.handle);
            if let Some((reply, deadline)) = c.pending.take() {
                match sock.state() {
                    tcp::State::Established => {
                        let _ = reply.send(Ok(c.shared.clone()));
                    }
                    s if s == tcp::State::Closed || now >= deadline => {
                        let _ = reply.send(Err(Error::network(format!(
                            "openvpn: tcp dial failed (state {s:?})"
                        ))));
                        sock.abort();
                        dead.push(c.handle);
                        continue;
                    }
                    _ => {
                        c.pending = Some((reply, deadline));
                    }
                }
            }
            let mut g = c.shared.lock();
            while g.to_proxy.len() < STREAM_QUEUE_MAX && sock.can_recv() {
                let n = match sock.recv_slice(&mut self.pump_buf) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                g.to_proxy.extend(self.pump_buf[..n].iter().copied());
            }
            let dialing = matches!(sock.state(), tcp::State::SynSent | tcp::State::Listen);
            if !dialing && !sock.may_recv() && sock.recv_queue() == 0 {
                g.read_eof = true;
            }
            while !g.to_stack.is_empty() && sock.can_send() {
                let n = match sock.send_slice(g.to_stack.make_contiguous()) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                g.to_stack.drain(..n);
            }
            if g.write_closed && g.to_stack.is_empty() && !c.fin_sent {
                sock.close();
                c.fin_sent = true;
            }
            if g.aborted {
                sock.abort();
            }
            let gone = sock.state() == tcp::State::Closed;
            if gone {
                g.read_eof = true;
                // Closed without our own graceful FIN = the peer reset (or
                // we aborted): writers must fail now instead of queuing
                // into a dead socket forever (wave-13: the wave-12A
                // wireguard.rs fix, 1762-1771, mirrored here — a
                // mid-burst RST hung write_all on a full to_stack queue).
                if !c.fin_sent && !g.write_closed {
                    g.aborted = true;
                }
            }
            if (!g.to_proxy.is_empty() || g.read_eof) && g.read_waker.is_some() {
                if let Some(w) = g.read_waker.take() {
                    w.wake();
                }
            }
            if (gone || g.to_stack.len() < STREAM_QUEUE_MAX) && g.write_waker.is_some() {
                if let Some(w) = g.write_waker.take() {
                    w.wake();
                }
            }
            drop(g);
            if gone {
                dead.push(c.handle);
            }
        }
        if !dead.is_empty() {
            self.conns.retain(|c| !dead.contains(&c.handle));
            for handle in dead {
                if let Some(sock) = self.sockets.get::<tcp::Socket>(handle).local_endpoint() {
                    self.used_ports.remove(&sock.port);
                }
                self.sockets.remove(handle);
            }
        }
    }

    fn drain_udp_rx(&mut self) {
        let ids: Vec<u32> = self.udp.keys().copied().collect();
        for id in ids {
            let Some((handle, down)) = self.udp.get(&id).map(|u| (u.handle, &u.down)) else {
                continue;
            };
            let sock = self.sockets.get_mut::<udp::Socket>(handle);
            while sock.can_recv() {
                let (n, meta) = match sock.recv_slice(&mut self.pump_buf) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let from = match meta.endpoint.addr {
                    IpAddress::Ipv4(src) => NetAddr::ip(IpAddr::V4(src), meta.endpoint.port),
                    IpAddress::Ipv6(src) => NetAddr::ip(IpAddr::V6(src), meta.endpoint.port),
                };
                let _ = down.try_send((from, self.pump_buf[..n].to_vec()));
            }
        }
    }

    async fn drain_egress(&mut self, link: &mut Link) {
        let pkts: Vec<Vec<u8>> = self.shim.egress.drain(..).collect();
        for pkt in pkts {
            if self.established() {
                if let Err(e) = self.write_data_packet(link, &pkt, true).await {
                    self.fail_tunnel(e);
                    return;
                }
            } else if self.pre_session_tx.len() < PRE_SESSION_QUEUE_MAX {
                self.pre_session_tx.push_back(pkt);
            }
        }
    }

    fn ephemeral_port(&mut self) -> u16 {
        loop {
            let port = 32768 + rand::random::<u16>() % 28_000;
            if self.used_ports.insert(port) {
                return port;
            }
        }
    }

    /// Source-address selection: the pushed address of the family.
    fn local_address_for(&self, dst: &SocketAddr) -> Result<IpAddress> {
        for (addr, _) in self.push.as_ref().map(|p| p.prefixes.as_slice()).unwrap_or(&[]) {
            match (addr, dst) {
                (IpAddr::V4(a), SocketAddr::V4(_)) => return Ok(IpAddress::Ipv4(*a)),
                (IpAddr::V6(a), SocketAddr::V6(_)) => return Ok(IpAddress::Ipv6(*a)),
                _ => {}
            }
        }
        Err(Error::network(match dst {
            SocketAddr::V4(_) => "openvpn: no pushed IPv4 address".to_string(),
            SocketAddr::V6(_) => {
                "openvpn: connect to an IPv6 target: no inner IPv6 address pushed".to_string()
            }
        }))
    }

    fn on_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Connect { remote, reply } => {
                if let Some(e) = &self.fail {
                    let _ = reply.send(Err(Error::network(e.to_string())));
                    return;
                }
                if !self.established() {
                    let _ = reply.send(Err(Error::network(
                        "openvpn: tunnel is not established yet",
                    )));
                    return;
                }
                if self.conns.len() >= MAX_CONNS {
                    let _ = reply.send(Err(Error::network("openvpn: connection limit reached")));
                    return;
                }
                let mut sock = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; TCP_RX_BYTES]),
                    tcp::SocketBuffer::new(vec![0; TCP_TX_BYTES]),
                );
                let port = self.ephemeral_port();
                let Ok(local_addr) = self.local_address_for(&remote) else {
                    let _ = reply.send(Err(Error::network(
                        "openvpn: no inner address for the target family",
                    )));
                    return;
                };
                let local = IpListenEndpoint {
                    addr: Some(local_addr),
                    port,
                };
                let endpoint = IpEndpoint::new(
                    match remote {
                        SocketAddr::V4(v4) => IpAddress::Ipv4(*v4.ip()),
                        SocketAddr::V6(v6) => IpAddress::Ipv6(*v6.ip()),
                    },
                    remote.port(),
                );
                let cx = self.iface.context();
                if let Err(e) = sock.connect(cx, endpoint, local) {
                    let _ = reply.send(Err(Error::network(format!(
                        "openvpn: connect: {e:?}"
                    ))));
                    return;
                }
                let handle = self.sockets.add(sock);
                let shared = Arc::new(StreamShared::new(self.wake.clone()));
                tracing::debug!(target: "engine", "openvpn: dialing {remote} through the tunnel");
                self.conns.push(Conn {
                    handle,
                    shared: shared.clone(),
                    fin_sent: false,
                    pending: Some((reply, Instant::now() + TCP_CONNECT_TIMEOUT)),
                });
            }
            Cmd::UdpOpen { reply } => {
                if let Some(e) = &self.fail {
                    let _ = reply.send(Err(Error::network(e.to_string())));
                    return;
                }
                if !self.established() {
                    let _ = reply.send(Err(Error::network(
                        "openvpn: tunnel is not established yet",
                    )));
                    return;
                }
                if self.udp.len() >= MAX_UDP_SOCKETS {
                    let _ = reply.send(Err(Error::network("openvpn: udp socket limit reached")));
                    return;
                }
                let mut sock = udp::Socket::new(
                    udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                        vec![0; UDP_RX_BYTES],
                    ),
                    udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                        vec![0; UDP_TX_BYTES],
                    ),
                );
                let port = self.ephemeral_port();
                if let Err(e) = sock.bind(IpListenEndpoint { addr: None, port }) {
                    let _ = reply.send(Err(Error::network(format!("openvpn: udp bind: {e:?}"))));
                    return;
                }
                let handle = self.sockets.add(sock);
                let id = self.next_udp_id;
                self.next_udp_id += 1;
                let (tx, rx) = mpsc::channel(64);
                self.udp.insert(id, UdpSock { handle, port, down: tx });
                let _ = reply.send(Ok((id, rx)));
            }
            Cmd::UdpSend { id, dst, data } => {
                let Some(handle) = self.udp.get(&id).map(|u| u.handle) else {
                    return;
                };
                let Ok(local_addr) = self.local_address_for(&dst) else {
                    return;
                };
                let mut meta = udp::UdpMetadata::from(IpEndpoint::new(
                    match dst {
                        SocketAddr::V4(v4) => IpAddress::Ipv4(*v4.ip()),
                        SocketAddr::V6(v6) => IpAddress::Ipv6(*v6.ip()),
                    },
                    dst.port(),
                ));
                meta.local_address = Some(local_addr);
                let sock = self.sockets.get_mut::<udp::Socket>(handle);
                if let Err(e) = sock.send_slice(&data, meta) {
                    tracing::debug!(target: "engine", "openvpn: udp send to {dst}: {e:?}");
                }
            }
            Cmd::UdpClose { id } => {
                if let Some(u) = self.udp.remove(&id) {
                    self.sockets.remove(u.handle);
                    self.used_ports.remove(&u.port);
                }
            }
        }
    }

    fn fail_tunnel(&mut self, e: Error) {
        if self.fail.is_none() {
            tracing::debug!(target: "engine", "openvpn: tunnel failed: {e}");
            self.fail = Some(e);
            self.phase = Phase::Failed;
            for c in &mut self.conns {
                if let Some((reply, _)) = c.pending.take() {
                    let _ = reply.send(Err(Error::network("openvpn: tunnel failed")));
                }
            }
            self.wake.notify_one();
        }
    }

    /// When the loop should wake on its own.
    fn next_deadline(&mut self) -> Instant {
        let mut until = Instant::now()
            + self
                .iface
                .poll_delay(self.now(), &self.sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(MAX_TICK)
                .clamp(MIN_TICK, MAX_TICK);
        for c in &self.conns {
            if let Some((_, deadline)) = &c.pending {
                until = until.min(*deadline);
            }
        }
        if let Some(deadline) = self.rekey_deadline {
            until = until.min(deadline);
        }
        if self.settings.ping.as_secs() > 0 {
            until = until.min(self.last_send + self.settings.ping);
        }
        if self.settings.ping_restart.as_secs() > 0 {
            until = until.min(self.last_receive + self.settings.ping_restart);
        }
        until
    }

    /// Retransmissions / ping / ping-restart / rekey timeouts.
    async fn on_timer(&mut self, link: &mut Link) {
        if self.settings.proto == PROTO_UDP
            && self.last_send.elapsed() >= CONTROL_RETRANSMIT_DELAY
            && !self.reliable.pending.is_empty()
            && self.retransmit_pending(link).await.is_err()
        {
            self.fail_tunnel(Error::network("retransmit openvpn control packet"));
        }
        if self.settings.ping.as_secs() > 0 && self.last_send.elapsed() >= self.settings.ping {
            if let Err(e) = self.write_ping(link).await {
                self.fail_tunnel(e);
            }
        }
        if self.settings.ping_restart.as_secs() > 0
            && self.last_receive.elapsed() >= self.settings.ping_restart
        {
            self.fail_tunnel(Error::network(format!(
                "openvpn ping-restart timeout: no packet received for {}s",
                self.settings.ping_restart.as_secs()
            )));
        }
        if let Some(deadline) = self.rekey_deadline {
            if Instant::now() >= deadline {
                if !self.established() || !matches!(self.phase, Phase::Established) {
                    self.fail_tunnel(Error::network("openvpn rekey did not complete in time"));
                }
                self.rekey_deadline = None;
            }
        }
    }

    // -- handshake (client.go Handshake / doKeyExchange) ---------------------

    /// client.go:186-236 Handshake: reset exchange, TLS epoch, key
    /// method 2, push request; installs the first data epoch and the
    /// netstack addresses.
    async fn handshake(&mut self, link: &mut Link) -> Result<()> {
        let deadline = Instant::now() + self.settings.handshake_timeout;
        // 1. Hard reset (client.go:190-195).
        self.send_reset(link).await?;
        // 2. Wait for the server reset with UDP retransmission
        //    (client.go:1147-1174 waitServerReset).
        let is_udp = self.settings.proto == PROTO_UDP;
        loop {
            if Instant::now() >= deadline {
                return Err(Error::network("openvpn handshake timed out"));
            }
            let mut buf = vec![0u8; 65_536];
            let read = if is_udp {
                tokio::time::timeout(CONTROL_RETRANSMIT_DELAY, link.read_packet(&mut buf)).await
            } else {
                Ok(link.read_packet(&mut buf).await)
            };
            let n = match read {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    self.retransmit_pending(link).await?;
                    continue;
                }
            };
            let (opcode, _) = parse_opcode_key_id(buf[0]);
            if !opcode_is_control(opcode) {
                continue;
            }
            self.reliable.handle_raw(self.crypt.as_ref(), &buf[..n]);
            if !self.reliable.ack_pending.is_empty() {
                let _ = self.send_ack(link).await;
            }
            if self.reliable.remote.is_some() {
                match opcode {
                    P_CONTROL_HARD_RESET_SERVER_V2 => break,
                    P_CONTROL_HARD_RESET_SERVER_V1 => {
                        return Err(Error::protocol(
                            "openvpn server replied with unsupported key method 1 reset",
                        ))
                    }
                    _ => continue,
                }
            }
        }

        // 3. TLS epoch (client.go:238-266 startTLSEpoch).
        let tls = self.build_tls_connection()?;
        self.tls = Some(tls);
        self.tls_flush_writes(link).await?;
        loop {
            if Instant::now() >= deadline {
                return Err(Error::network("openvpn tls handshake timed out"));
            }
            let (handshaking, wants_write) = {
                let tls = self.tls.as_ref().expect("tls epoch");
                (tls.is_handshaking(), tls.wants_write())
            };
            if !handshaking && !wants_write {
                break;
            }
            self.tls_flush_writes(link).await?;
            if !handshaking {
                break;
            }
            let payload = self.read_control_payload(link, Some(deadline)).await?;
            if let Err(e) = self.tls_feed(&payload) {
                return Err(Error::network(format!("openvpn tls handshake: {e}")));
            }
        }

        // 4. Key method 2 client record (client.go:289-304).
        let options = install_script_options_string(
            &self.settings.proto,
            &self.settings.cipher,
            &self.settings.auth,
            self.settings.comp_lzo,
        );
        let peer_info = install_script_peer_info(
            &self.settings.cipher,
            &self.settings.data_ciphers,
            self.settings.comp_lzo,
            &self.settings.peer_info,
        );
        let (record, client_source) = client_km2_record(
            &options,
            &peer_info,
            &self.settings.username,
            &self.settings.password,
        );
        self.km2_client_source = Some(client_source);
        self.tls_write_all(link, &record).await?;

        // 5. Server KM2 record (client.go:1185-1235 readServerKeyMethod).
        let mut buf = std::mem::take(&mut self.leftover_tls);
        let server_record = loop {
            if Instant::now() >= deadline {
                return Err(Error::network("openvpn key exchange timed out"));
            }
            if km2_record_complete(&buf).is_some() {
                let (record, consumed) = parse_server_km2(&buf)?;
                self.leftover_tls = buf[consumed..].to_vec();
                break record;
            }
            match parse_server_km2(&buf) {
                Ok((record, consumed)) => {
                    self.leftover_tls = buf[consumed..].to_vec();
                    break record;
                }
                Err(e) => {
                    let msg = e.to_string();
                    if !msg.contains("too short") && !msg.contains("truncated") {
                        return Err(e);
                    }
                }
            }
            let got = self.read_tls_plaintext(link, Some(deadline)).await?;
            if got.is_empty() {
                return Err(Error::network(
                    "openvpn tls stream closed during key exchange",
                ));
            }
            buf.extend_from_slice(&got);
            if buf.len() > MAX_TLS_CONTROL_BUFFER {
                return Err(Error::protocol("openvpn TLS control buffer exceeds 1 MiB"));
            }
        };

        // 6. PUSH_REQUEST (client.go:353-386).
        self.tls_write_all(link, b"PUSH_REQUEST\0").await?;
        let push = self.read_push_reply(link, deadline).await?;

        // 7. Derive + negotiate + install (client.go:313-386).
        let client_source = self.km2_client_source.take().expect("client km2 source");
        let mut keys = derive_client_key_material(
            &client_source,
            &server_record.sources,
            &self.reliable.local,
            &self.reliable.remote.unwrap_or([0u8; SESSION_ID_SIZE]),
            32,
        )
        .map_err(|e| Error::network(format!("derive data channel keys: {e}")))?;
        let negotiated = negotiate_cipher(&self.settings, &push.data_ciphers, &push.cipher)
            .map_err(|e| Error::network(format!("negotiate data cipher: {e}")))?;
        self.negotiated_cipher = negotiated.clone();
        let key_len = cipher_key_length(&negotiated);
        keys.send_cipher_key.truncate(key_len);
        keys.recv_cipher_key.truncate(key_len);
        let channel = DataChannel::new(
            &keys,
            &negotiated,
            &self.settings.auth,
            push.peer_id,
            self.reliable.key_id,
        )?;

        // Capture the auth token (client.go:664-676 captureAuthToken).
        if !push.auth_token_pass.is_empty() {
            if !push.auth_token_user.is_empty() {
                self.settings.username = push.auth_token_user.clone();
            }
            self.settings.password = push.auth_token_pass.clone();
        }
        self.push = Some(push.clone());
        self.install_data_channel(channel);

        // 8. Netstack addresses from the pushed prefixes (the adapter's
        //    newIPStack(push.Prefixes, mtu)). The default routes ride the
        //    local address of each family.
        if push.prefixes.is_empty() {
            return Err(Error::protocol("openvpn push reply missing ifconfig address"));
        }
        self.iface.update_ip_addrs(|addrs| {
            for (addr, bits) in &push.prefixes {
                let cidr = match addr {
                    IpAddr::V4(a) => IpCidr::new(IpAddress::Ipv4(*a), *bits),
                    IpAddr::V6(a) => IpCidr::new(IpAddress::Ipv6(*a), *bits),
                };
                let _ = addrs.push(cidr);
            }
        });
        for (addr, _) in &push.prefixes {
            match addr {
                IpAddr::V4(a) => {
                    let _ = self.iface.routes_mut().add_default_ipv4_route(*a);
                }
                IpAddr::V6(a) => {
                    let _ = self.iface.routes_mut().add_default_ipv6_route(*a);
                }
            }
        }

        self.phase = Phase::Established;
        self.last_send = Instant::now();
        self.last_receive = Instant::now();
        tracing::debug!(
            target: "engine",
            "openvpn: handshake complete: cipher={} peer-id={} prefixes={:?} routes={:?} remote-dns={} dns={:?}",
            self.negotiated_cipher,
            push.peer_id,
            push.prefixes,
            push.routes,
            self.settings.remote_dns_resolve,
            self.settings.dns,
        );
        Ok(())
    }

    /// The next in-order P_CONTROL_V1 payload (reliable receive).
    async fn read_control_payload(
        &mut self,
        link: &mut Link,
        deadline: Option<Instant>,
    ) -> Result<Vec<u8>> {
        loop {
            if let Some(deadline) = deadline {
                if Instant::now() >= deadline {
                    return Err(Error::network("openvpn control read timed out"));
                }
            }
            let mut buf = vec![0u8; 65_536];
            let n = link.read_packet(&mut buf).await?;
            let raw = buf[..n].to_vec();
            let (opcode, _) = parse_opcode_key_id(raw[0]);
            if !opcode_is_control(opcode) {
                continue;
            }
            let outcome = self.reliable.handle_raw(self.crypt.as_ref(), &raw);
            if !self.reliable.ack_pending.is_empty() {
                self.send_ack(link).await?;
            }
            if let ControlOutcome::Deliver(packet) = outcome {
                if packet.opcode == P_CONTROL_V1 && !packet.payload.is_empty() {
                    return Ok(packet.payload);
                }
            }
        }
    }

    /// Plaintext bytes out of the live TLS epoch, reading the control
    /// channel as needed (readServerKeyMethod's conn.Read loop).
    async fn read_tls_plaintext(
        &mut self,
        link: &mut Link,
        deadline: Option<Instant>,
    ) -> Result<Vec<u8>> {
        loop {
            let mut got = Vec::new();
            if let Some(tls) = self.tls.as_mut() {
                let mut tmp = [0u8; 4096];
                loop {
                    match std::io::Read::read(&mut tls.reader(), &mut tmp) {
                        Ok(0) => break,
                        Ok(n) => got.extend_from_slice(&tmp[..n]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(Error::network(format!("openvpn tls read: {e}"))),
                    }
                }
            }
            if !got.is_empty() {
                return Ok(got);
            }
            let payload = self.read_control_payload(link, deadline).await?;
            if let Err(e) = self.tls_feed(&payload) {
                return Err(Error::network(format!("openvpn tls: {e}")));
            }
        }
    }

    /// client.go:1237-1298 readPushReply.
    async fn read_push_reply(&mut self, link: &mut Link, deadline: Instant) -> Result<PushReply> {
        let mut buf = std::mem::take(&mut self.leftover_tls);
        loop {
            if Instant::now() >= deadline {
                return Err(Error::network("openvpn push reply timed out"));
            }
            control_message_error(&buf)?;
            let (reply, rest, complete) = take_push_reply(&buf);
            buf = rest;
            if complete {
                self.leftover_tls = buf;
                let merged = merge_push_reply(self.pending_push.take(), reply.unwrap_or_default())
                    .unwrap_or_default();
                return Ok(merged);
            }
            if let Some(r) = reply {
                self.pending_push = merge_push_reply(self.pending_push.take(), r);
            }
            let got = self.read_tls_plaintext(link, Some(deadline)).await?;
            if got.is_empty() {
                return Err(Error::network("openvpn tls stream closed before PUSH_REPLY"));
            }
            buf.extend_from_slice(&got);
            if buf.len() > MAX_TLS_CONTROL_BUFFER {
                return Err(Error::protocol("openvpn TLS control buffer exceeds 1 MiB"));
            }
        }
    }

    /// The TLS client config: CA chain verification (no server-name
    /// check — client.go:1744-1781), optional client certificate.
    fn build_tls_connection(&mut self) -> Result<rustls::ClientConnection> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = OpenVpnCaVerifier::new(&self.settings.ca, provider.clone())?;
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::config(format!("openvpn tls config: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier));
        let config = if let (Some(cert), Some(key)) = (&self.settings.cert, &self.settings.key) {
            let certs: std::result::Result<Vec<_>, _> =
                rustls_pemfile::certs(&mut std::io::Cursor::new(cert.as_slice())).collect();
            let certs =
                certs.map_err(|e| Error::config(format!("parse client certificate: {e}")))?;
            let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key.as_slice()))
                .map_err(|e| Error::config(format!("parse client key: {e}")))?
                .ok_or_else(|| {
                    Error::config("parse client certificate/key: no PRIVATE KEY block")
                })?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| Error::config(format!("parse client certificate/key: {e}")))?
        } else {
            builder.with_no_client_auth()
        };
        let config = Arc::new(config);
        // The verifier ignores the name; the server host is the natural
        // SNI for peers that expect one.
        let name = rustls::pki_types::ServerName::try_from(self.settings.server.clone())
            .or_else(|_| rustls::pki_types::ServerName::try_from("openvpn".to_string()))
            .expect("static name");
        rustls::ClientConnection::new(config, name)
            .map_err(|e| Error::config(format!("openvpn tls client init: {e}")))
    }
}

/// config.go:114-165 NegotiateCipher.
fn negotiate_cipher(
    settings: &Settings,
    pushed_ciphers: &[String],
    pushed_cipher: &str,
) -> Result<String> {
    if pushed_ciphers.is_empty() && pushed_cipher.is_empty() {
        return Ok(settings.cipher.clone());
    }
    if !settings.data_ciphers.is_empty() {
        let mut server_list: Vec<String> = pushed_ciphers.to_vec();
        if server_list.is_empty() && !pushed_cipher.is_empty() {
            server_list.push(pushed_cipher.to_string());
        }
        for server_cipher in &server_list {
            let normalized = normalize_cipher(server_cipher);
            for local in &settings.data_ciphers {
                if normalize_cipher(local) == normalized {
                    return Ok(normalized);
                }
            }
        }
        if !settings.fallback_cipher.is_empty() {
            return Ok(normalize_cipher(&settings.fallback_cipher));
        }
        return Err(Error::protocol(format!(
            "no common data cipher between client {:?} and server {server_list:?}",
            settings.data_ciphers
        )));
    }
    if !pushed_cipher.is_empty() {
        let normalized = normalize_cipher(pushed_cipher);
        if normalized == settings.cipher {
            return Ok(normalized);
        }
        if !settings.fallback_cipher.is_empty() {
            return Ok(normalize_cipher(&settings.fallback_cipher));
        }
        if is_supported_cipher(&normalized) {
            return Ok(normalized);
        }
        return Err(Error::protocol(format!(
            "server pushed unsupported cipher {pushed_cipher:?}"
        )));
    }
    for sc in pushed_ciphers {
        let normalized = normalize_cipher(sc);
        if is_supported_cipher(&normalized) {
            if !settings.fallback_cipher.is_empty() {
                return Ok(normalize_cipher(&settings.fallback_cipher));
            }
            return Ok(normalized);
        }
    }
    Ok(settings.cipher.clone())
}

// ---------------------------------------------------------------------------
// CA chain verification (client.go:1744-1781 tlsConfig)
// ---------------------------------------------------------------------------

/// Minimal DER walk: top-level TLV triplet.
fn der_tlv(input: &[u8]) -> Option<(u8, &[u8], usize)> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let mut len = input[1] as usize;
    let mut hdr = 2usize;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 4 || input.len() < 2 + n {
            return None;
        }
        len = 0;
        for b in &input[2..2 + n] {
            len = (len << 8) | *b as usize;
        }
        hdr = 2 + n;
    }
    if input.len() < hdr + len {
        return None;
    }
    Some((tag, &input[hdr..hdr + len], hdr + len))
}

fn der_reencode(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.push(tag);
    let l = body.len();
    if l < 0x80 {
        out.push(l as u8);
    } else if l < 0x100 {
        out.push(0x81);
        out.push(l as u8);
    } else {
        out.push(0x82);
        out.push((l >> 8) as u8);
        out.push(l as u8);
    }
    out.extend_from_slice(body);
    out
}

/// (tbsCertificate, signatureAlgorithm OID, signature bits, SPKI DER).
type CertParts<'a> = (&'a [u8], &'a [u8], &'a [u8], Vec<u8>);

fn cert_parts(cert: &[u8]) -> Option<CertParts<'_>> {
    let (_, body, _) = der_tlv(cert)?;
    let (_, tbs, tbs_total) = der_tlv(body)?;
    let mut rest = &body[tbs_total..];
    let (_, sig_alg, alg_total) = der_tlv(rest)?;
    let oid = der_tlv(sig_alg)?.1;
    rest = &rest[alg_total..];
    let (_, sig, _) = der_tlv(rest)?;
    let sig = sig.get(1..)?; // BIT STRING: skip the unused-bits byte.
    // SPKI: the tbs SEQUENCE child that parses as
    // SEQUENCE { AlgorithmIdentifier, BIT STRING }.
    let mut t = tbs;
    while let Some((tag, val, consumed)) = der_tlv(t) {
        if tag == 0x30 {
            if let Some((a_tag, _, a_len)) = der_tlv(val) {
                if a_tag == 0x30 {
                    if let Some((b_tag, _, _)) = der_tlv(&val[a_len..]) {
                        if b_tag == 0x03 {
                            return Some((tbs, oid, sig, der_reencode(tag, val)));
                        }
                    }
                }
            }
        }
        t = &t[consumed..];
    }
    None
}

/// Verify `cert` was signed by `signer`'s public key (ring, by family).
fn cert_signed_by(cert: &[u8], signer: &[u8]) -> bool {
    let Some((tbs, _oid, sig, _)) = cert_parts(cert) else { return false };
    let Some((_, _, _, signer_spki)) = cert_parts(signer) else { return false };
    let Some((_, spki_body, _)) = der_tlv(&signer_spki) else { return false };
    let Some((_, _, alg_len)) = der_tlv(spki_body) else { return false };
    let Some((_, alg_oid, _)) = der_tlv(spki_body) else { return false };
    let Some((_, key_bits_raw, _)) = der_tlv(&spki_body[alg_len..]) else { return false };
    let key_bits = key_bits_raw.get(1..).unwrap_or(key_bits_raw);
    match alg_oid {
        // rsaEncryption
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] => {
            let Some((_, n_body, n_len)) = der_tlv(key_bits) else { return false };
            let n = n_body.get(1..).unwrap_or(n_body); // skip leading zero
            let Some((_, e_body, _)) = der_tlv(&key_bits[n_len..]) else { return false };
            // Signature OID → algorithm selection.
            let alg = match _oid {
                [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b] => {
                    &ring::signature::RSA_PKCS1_2048_8192_SHA256
                }
                [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c] => {
                    &ring::signature::RSA_PKCS1_2048_8192_SHA384
                }
                [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d] => {
                    &ring::signature::RSA_PKCS1_2048_8192_SHA512
                }
                _ => return false,
            };
            ring::signature::RsaPublicKeyComponents {
                n: n.to_vec(),
                e: e_body.to_vec(),
            }
            .verify(alg, tbs, sig)
            .is_ok()
        }
        // ecPublicKey
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01] => {
            let alg = match key_bits.len() {
                65 => &ring::signature::ECDSA_P256_SHA256_ASN1,
                97 => &ring::signature::ECDSA_P384_SHA384_ASN1,
                _ => return false,
            };
            ring::signature::UnparsedPublicKey::new(alg, key_bits)
                .verify(tbs, sig)
                .is_ok()
        }
        // Ed25519
        [0x2b, 0x65, 0x70] => ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            key_bits,
        )
        .verify(tbs, sig)
        .is_ok(),
        _ => false,
    }
}

/// Chain verification against the configured CA set: a presented cert is
/// accepted when it IS a configured CA (SPKI match) or is signed by a
/// chain rooted there (upstream: x509 pool verify with ServerAuth usage
/// and no name check; EKU enforcement is not re-implemented).
#[derive(Debug)]
struct OpenVpnCaVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    roots: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl OpenVpnCaVerifier {
    fn new(ca_pem: &[u8], provider: Arc<rustls::crypto::CryptoProvider>) -> Result<Self> {
        let certs: std::result::Result<Vec<_>, _> =
            rustls_pemfile::certs(&mut std::io::Cursor::new(ca_pem)).collect();
        let certs = certs.map_err(|_| Error::config("parse openvpn ca certificate"))?;
        if certs.is_empty() {
            return Err(Error::config("parse openvpn ca certificate"));
        }
        Ok(OpenVpnCaVerifier {
            provider,
            roots: certs,
        })
    }

    fn rooted(&self, chain: &[&[u8]]) -> bool {
        for cert in chain {
            for root in &self.roots {
                let same_spki = match (cert_parts(cert), cert_parts(root.as_ref())) {
                    (Some((_, _, _, a)), Some((_, _, _, b))) => a == b,
                    _ => false,
                };
                if same_spki || cert_signed_by(cert, root.as_ref()) {
                    return true;
                }
            }
        }
        false
    }
}

impl rustls::client::danger::ServerCertVerifier for OpenVpnCaVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // leaf signed by an intermediate that is itself rooted (or a
        // configured CA presented directly).
        let mut chain: Vec<&[u8]> = vec![end_entity.as_ref()];
        chain.extend(intermediates.iter().map(|c| c.as_ref()));
        if self.rooted(&chain)
            || (!intermediates.is_empty()
                && intermediates
                    .iter()
                    .any(|i| cert_signed_by(end_entity.as_ref(), i.as_ref()) && self.rooted(&[i.as_ref()])))
        {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        Err(rustls::Error::General(
            "openvpn server certificate is not signed by the configured CA".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// smoltcp device shim + stream (wireguard.rs parity)
// ---------------------------------------------------------------------------

struct Shim {
    ingress: VecDeque<Vec<u8>>,
    egress: VecDeque<Vec<u8>>,
    scratch: Vec<u8>,
    mtu: usize,
}

impl Shim {
    fn new(mtu: usize) -> Self {
        Shim {
            ingress: VecDeque::new(),
            egress: VecDeque::new(),
            scratch: Vec::new(),
            mtu,
        }
    }

    fn stage(&mut self, pkt: &[u8]) {
        if self.ingress.len() < PRE_SESSION_QUEUE_MAX {
            self.ingress.push_back(pkt.to_vec());
        }
    }
}

impl Device for Shim {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(RxTok, TxTok<'_>)> {
        let pkt = self.ingress.pop_front()?;
        Some((
            RxTok { pkt },
            TxTok {
                egress: &mut self.egress,
                scratch: &mut self.scratch,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<TxTok<'_>> {
        Some(TxTok {
            egress: &mut self.egress,
            scratch: &mut self.scratch,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct RxTok {
    pkt: Vec<u8>,
}

impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.pkt)
    }
}

struct TxTok<'a> {
    egress: &'a mut VecDeque<Vec<u8>>,
    scratch: &'a mut Vec<u8>,
}

impl TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        self.scratch.clear();
        self.scratch.resize(len, 0);
        let out = {
            let buf = &mut self.scratch[..len];
            f(buf)
        };
        self.egress.push_back(self.scratch[..len].to_vec());
        out
    }
}

struct StreamBufs {
    to_proxy: VecDeque<u8>,
    to_stack: VecDeque<u8>,
    read_eof: bool,
    write_closed: bool,
    aborted: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

struct StreamShared {
    bufs: Mutex<StreamBufs>,
    wake: Arc<Notify>,
}

impl StreamShared {
    fn new(wake: Arc<Notify>) -> Self {
        StreamShared {
            bufs: Mutex::new(StreamBufs {
                to_proxy: VecDeque::new(),
                to_stack: VecDeque::new(),
                read_eof: false,
                write_closed: false,
                aborted: false,
                read_waker: None,
                write_waker: None,
            }),
            wake,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, StreamBufs> {
        self.bufs.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One TCP connection through the OpenVPN tunnel, as seen by the relay.
pub struct OvpnStream {
    shared: Arc<StreamShared>,
}

impl Drop for OvpnStream {
    fn drop(&mut self) {
        let mut g = self.shared.lock();
        g.aborted = true;
        g.read_eof = true;
        g.write_closed = true;
        drop(g);
        self.shared.wake.notify_one();
    }
}

impl AsyncRead for OvpnStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut g = self.shared.lock();
        if !g.to_proxy.is_empty() {
            let n = g.to_proxy.len().min(buf.remaining());
            let (front, back) = g.to_proxy.as_slices();
            let take_front = n.min(front.len());
            buf.put_slice(&front[..take_front]);
            if take_front < n {
                buf.put_slice(&back[..n - take_front]);
            }
            g.to_proxy.drain(..n);
            drop(g);
            // Freed queue space is stack input: the socket behind it may
            // hold data the service loop could not move (and a peer
            // waiting on the window this drain just re-opened). Wake the
            // tunnel task instead of letting the connection idle until
            // the driver's 1s tick (wave-13: the wave-12A wireguard.rs
            // fix, 1075-1079, mirrored here).
            self.shared.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if g.read_eof {
            return Poll::Ready(Ok(()));
        }
        g.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for OvpnStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut g = self.shared.lock();
        if g.aborted || g.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "openvpn: stream is closed",
            )));
        }
        let space = STREAM_QUEUE_MAX.saturating_sub(g.to_stack.len());
        if space == 0 {
            g.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = space.min(buf.len());
        g.to_stack.extend(buf[..n].iter().copied());
        drop(g);
        self.shared.wake.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.lock().write_closed = true;
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// Public API: one shared tunnel per config identity (wireguard.rs parity)
// ---------------------------------------------------------------------------

/// A UDP relay session through the OpenVPN tunnel.
pub struct OvpnUdp {
    tx: mpsc::Sender<Cmd>,
    id: u32,
    rx: tokio::sync::Mutex<UdpDownlink>,
}

impl Drop for OvpnUdp {
    fn drop(&mut self) {
        let _ = self.tx.try_send(Cmd::UdpClose { id: self.id });
    }
}

impl OvpnUdp {
    /// Open a UDP socket inside the tunnel described by `cfg`.
    pub async fn bind(cfg: &OpenVpnOut) -> Result<Self> {
        let tunnel = tunnel_for(cfg).await?;
        let (tx, rx) = oneshot::channel();
        tunnel
            .send(Cmd::UdpOpen { reply: tx })
            .await
            .map_err(|_| Error::network("openvpn: tunnel task is gone"))?;
        let (id, down) = tokio::time::timeout(Duration::from_secs(45), rx)
            .await
            .map_err(|_| Error::network("openvpn: udp bind timed out"))?
            .map_err(|_| Error::network("openvpn: tunnel task dropped the bind"))??;
        Ok(OvpnUdp {
            tx: tunnel,
            id,
            rx: tokio::sync::Mutex::new(down),
        })
    }

    /// Send one datagram to `target` through the tunnel.
    pub async fn send(&self, target: &NetAddr, data: &[u8]) -> Result<()> {
        let dst = target_addr(target, "udp send")?;
        self.tx
            .send(Cmd::UdpSend {
                id: self.id,
                dst,
                data: data.to_vec(),
            })
            .await
            .map_err(|_| Error::network("openvpn: tunnel task is gone"))
    }

    /// Receive the next datagram (and its sender) from the tunnel.
    pub async fn recv(&self) -> Result<(NetAddr, Vec<u8>)> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| Error::network("openvpn: udp session closed"))
    }
}

/// Resolve a proxy target to the socket address the netstack dials
/// (domains are refused — upstream resolves outside the tunnel).
fn target_addr(target: &NetAddr, what: &str) -> Result<SocketAddr> {
    match &target.host {
        crate::addr::Host::Ip(IpAddr::V4(ip)) => {
            Ok(SocketAddr::V4(SocketAddrV4::new(*ip, target.port)))
        }
        crate::addr::Host::Ip(IpAddr::V6(ip)) => {
            Ok(SocketAddr::V6(SocketAddrV6::new(*ip, target.port, 0, 0)))
        }
        crate::addr::Host::Domain(d) => Err(Error::network(format!(
            "openvpn: {what} to domain {d}: resolve before dialing (the netstack routes IPs only)"
        ))),
    }
}

static TUNNELS: std::sync::OnceLock<tokio::sync::Mutex<HashMap<String, mpsc::Sender<Cmd>>>> =
    std::sync::OnceLock::new();

fn cache_key(cfg: &OpenVpnOut) -> String {
    [
        cfg.name.as_str(),
        &cfg.server,
        &cfg.port.to_string(),
        cfg.proto.as_deref().unwrap_or(""),
        &cfg.cipher,
        &cfg.auth,
        &cfg.ca,
        cfg.tls_auth.as_deref().unwrap_or(""),
        cfg.tls_crypt.as_deref().unwrap_or(""),
        cfg.tls_crypt_v2.as_deref().unwrap_or(""),
        cfg.username.as_deref().unwrap_or(""),
        &cfg.mtu.to_string(),
    ]
    .join("\u{1f}")
}

async fn tunnel_for(cfg: &OpenVpnOut) -> Result<mpsc::Sender<Cmd>> {
    let settings = cfg.prepare()?;
    let key = cache_key(cfg);
    let cache = TUNNELS.get_or_init(Default::default);
    let mut map = cache.lock().await;
    if let Some(tx) = map.get(&key) {
        if !tx.is_closed() {
            return Ok(tx.clone());
        }
    }
    let (tx, rx) = mpsc::channel::<Cmd>(64);
    let link = dial_link(&settings).await?;
    let wake = Arc::new(Notify::new());
    let client = Client::new(settings, wake.clone())?;
    tokio::spawn(async move {
        run_client(client, link, rx, wake).await;
    });
    map.insert(key, tx.clone());
    Ok(tx)
}

async fn dial_link(settings: &Settings) -> Result<Link> {
    let mut addrs = tokio::net::lookup_host((settings.server.as_str(), settings.port))
        .await
        .map_err(|e| Error::dns(format!("openvpn: resolve {}: {e}", settings.server)))?;
    let addr = addrs
        .next()
        .ok_or_else(|| Error::dns(format!("openvpn: no address for {}", settings.server)))?;
    match settings.proto.as_str() {
        PROTO_UDP => {
            let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let socket = UdpSocket::bind(bind)
                .await
                .map_err(|e| Error::network(format!("openvpn: bind udp: {e}")))?;
            socket
                .connect(addr)
                .await
                .map_err(|e| Error::network(format!("openvpn: connect udp: {e}")))?;
            Ok(Link::Udp(socket))
        }
        PROTO_TCP => {
            let stream = TcpStream::connect(addr)
                .await
                .map_err(|e| Error::network(format!("openvpn: connect tcp: {e}")))?;
            let _ = stream.set_nodelay(true);
            Ok(Link::Tcp(stream))
        }
        other => Err(Error::config(format!(
            "unsupported openvpn proto {other:?}: only udp and tcp are supported"
        ))),
    }
}

/// Drive one tunnel until the last command sender is gone: the handshake
/// runs on the first command, then the established select loop serves
/// control + data + netstack + timers.
async fn run_client(
    mut client: Client,
    mut link: Link,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    wake: Arc<Notify>,
) {
    let mut rx = vec![0u8; 65_536];
    let mut handshaken = false;
    loop {
        client.step(&mut link).await;
        let deadline = client.next_deadline();
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::select! {
            biased;
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(cmd) => {
                        if !handshaken {
                            match client.handshake(&mut link).await {
                                Ok(()) => {
                                    handshaken = true;
                                    let queued: Vec<Vec<u8>> =
                                        client.pre_session_tx.drain(..).collect();
                                    for pkt in queued {
                                        if let Err(e) = client.write_data_packet(&mut link, &pkt, true).await {
                                            client.fail_tunnel(e);
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(target: "engine", "openvpn: handshake: {e}");
                                    client.fail_tunnel(e);
                                }
                            }
                        }
                        client.on_cmd(cmd);
                    }
                    None => break,
                }
            }
            _ = wake.notified() => {}
            r = link.read_packet(&mut rx) => {
                match r {
                    Ok(n) => client.on_packet(&mut link, &rx[..n]).await,
                    Err(e) => {
                        if client.fail.is_none() {
                            tracing::debug!(target: "engine", "openvpn: link closed: {e}");
                            client.fail_tunnel(e);
                        }
                        break;
                    }
                }
            }
            _ = sleep => {
                client.on_timer(&mut link).await;
            }
        }
        // Soft-reset-driven rekey (watchControl): start when parked and
        // established.
        if handshaken
            && matches!(client.phase, Phase::Established)
            && client.pending_soft_reset.is_some()
        {
            client.begin_rekey();
            if client.send_soft_reset(&mut link).await.is_err() {
                client.fail_tunnel(Error::network("openvpn: send soft reset"));
                continue;
            }
            match client.build_tls_connection() {
                Ok(tls) => {
                    client.tls = Some(tls);
                    client.phase = Phase::RekeyTls { sent_km2: false };
                    if let Err(e) = client.tls_flush_writes(&mut link).await {
                        client.fail_tunnel(e);
                    }
                }
                Err(e) => client.fail_tunnel(e),
            }
        }
    }
}

/// Dial a TCP connection through the OpenVPN tunnel described by `cfg`.
/// The tunnel (handshake + netstack) is created on first use and shared
/// by every later dial with the same configuration.
pub async fn connect(cfg: &OpenVpnOut, target: &NetAddr) -> Result<BoxProxyStream> {
    let remote = target_addr(target, "connect")?;
    let settings = cfg.prepare()?;
    let timeout = settings.handshake_timeout + TCP_CONNECT_TIMEOUT;
    let tunnel = tunnel_for(cfg).await?;
    let (tx, rx) = oneshot::channel();
    tunnel
        .send(Cmd::Connect { remote, reply: tx })
        .await
        .map_err(|_| Error::network("openvpn: tunnel task is gone"))?;
    let shared = tokio::time::timeout(timeout, rx)
        .await
        .map_err(|_| Error::network("openvpn: tcp dial timed out"))?
        .map_err(|_| Error::network("openvpn: tunnel task dropped the dial"))??;
    Ok(Box::new(OvpnStream { shared }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ========================================================================
    // The in-test OpenVPN server: control-channel responder (reset, TLS via
    // a real rustls server, key-method-2, PUSH_REPLY) + data-channel echo
    // through a smoltcp stack. Transcribed from the packet layouts of
    // packet.go / keymethod.go / push.go / data.go; nothing leaves
    // loopback and every credential is generated per run.
    // ========================================================================

    const SERVER_TUNNEL_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);
    const CLIENT_TUNNEL_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
    const ECHO_TCP_PORT: u16 = 9031;
    const ECHO_UDP_PORT: u16 = 9032;

    fn hex_encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len() * 2);
        for b in data {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    fn static_key_pem(material: &[u8; 256]) -> String {
        let mut out = String::from("-----BEGIN OpenVPN Static key V1-----\n");
        for chunk in material.chunks(32) {
            out.push_str(&hex_encode(chunk));
            out.push('\n');
        }
        out.push_str("-----END OpenVPN Static key V1-----\n");
        out
    }

    fn tls_crypt_v2_client_pem(material: &[u8; 256], wrapped: &[u8]) -> String {
        let mut body = material.to_vec();
        body.extend_from_slice(wrapped);
        format!(
            "-----BEGIN OpenVPN tls-crypt-v2 client key-----\n{}\n-----END OpenVPN tls-crypt-v2 client key-----\n",
            base64::engine::general_purpose::STANDARD.encode(&body)
        )
    }

    fn random_static_key() -> [u8; 256] {
        let mut key = [0u8; 256];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    }

    /// The mimic's knobs (cipher/auth must mirror what it pushes).
    struct MimicOpts {
        proto: &'static str,
        cipher: String,
        auth: String,
        comp_lzo: bool,
        /// Extra push options appended to ifconfig (",cipher X", ",peer-id 5"...).
        push_extra: String,
        auth_failed: bool,
        tls_auth: Option<[u8; 256]>,
        /// The CLIENT's key-direction (the server uses the opposite slot).
        key_direction: String,
        tls_crypt: Option<[u8; 256]>,
        tls_crypt_v2: Option<([u8; 256], Vec<u8>)>,
        /// Testing knob: abort (RST) the first echo connection once this
        /// many payload bytes have been received in total — the wave-13
        /// mid-burst reset repro.
        reset_after_bytes: Option<usize>,
    }

    impl MimicOpts {
        fn plain(proto: &'static str) -> Self {
            MimicOpts {
                proto,
                cipher: CIPHER_AES128GCM.into(),
                auth: AUTH_SHA256.into(),
                comp_lzo: false,
                push_extra: ",peer-id 5".into(),
                auth_failed: false,
                tls_auth: None,
                key_direction: String::new(),
                tls_crypt: None,
                tls_crypt_v2: None,
                reset_after_bytes: None,
            }
        }

        fn server_crypt(&self) -> Option<ControlCrypt> {
            if let Some((material, wrapped)) = &self.tls_crypt_v2 {
                let (encrypt, decrypt) = tls_crypt_slots(material, false);
                return Some(ControlCrypt::TlsCryptV2 {
                    encrypt,
                    decrypt,
                    wrapped_client_key: wrapped.clone(),
                });
            }
            if let Some(key) = self.tls_crypt {
                let (encrypt, decrypt) = tls_crypt_slots(&key, false);
                return Some(ControlCrypt::TlsCrypt { encrypt, decrypt });
            }
            if let Some(key) = self.tls_auth {
                let digest = AuthDigest::parse(&self.auth).expect("auth");
                let tag_size = digest.size();
                // Server-side slots: the inverse of the client's
                // key-direction selection (tlsauth.go:46-56): the client
                // with direction 1 encrypts with slot 1, so the server
                // encrypts with slot 0 and decrypts with slot 1.
                let (encrypt, decrypt) = match self.key_direction.as_str() {
                    "1" => (&key[..128], &key[128..]),
                    "0" => (&key[128..], &key[..128]),
                    _ => (&key[..128], &key[..128]),
                };
                return Some(ControlCrypt::TlsAuth {
                    digest,
                    tag_size,
                    encrypt_key: encrypt[64..64 + tag_size].to_vec(),
                    decrypt_key: decrypt[64..64 + tag_size].to_vec(),
                });
            }
            None
        }

        fn push_message(&self) -> String {
            if self.auth_failed {
                return "AUTH_FAILED\0".into();
            }
            format!(
                "PUSH_REPLY,ifconfig {CLIENT_TUNNEL_IP} 255.255.255.0{}",
                self.push_extra
            )
        }
    }

    enum MimicLink {
        Tcp(TcpStream),
        Udp { socket: UdpSocket, peer: Option<SocketAddr> },
    }

    impl MimicLink {
        async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
            match self {
                MimicLink::Tcp(stream) => {
                    use tokio::io::AsyncReadExt;
                    let mut len = [0u8; 2];
                    stream.read_exact(&mut len).await.map_err(|e| Error::network(e.to_string()))?;
                    let size = usize::from(u16::from_be_bytes(len));
                    stream
                        .read_exact(&mut buf[..size])
                        .await
                        .map_err(|e| Error::network(e.to_string()))?;
                    Ok(size)
                }
                MimicLink::Udp { socket, peer } => {
                    let (n, from) = socket
                        .recv_from(buf)
                        .await
                        .map_err(|e| Error::network(e.to_string()))?;
                    // The first datagram identifies the client.
                    if peer.is_none() {
                        *peer = Some(from);
                    }
                    Ok(n)
                }
            }
        }

        async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
            match self {
                MimicLink::Tcp(stream) => {
                    use tokio::io::AsyncWriteExt;
                    let mut frame = Vec::with_capacity(2 + packet.len());
                    frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
                    frame.extend_from_slice(packet);
                    stream.write_all(&frame).await.map_err(|e| Error::network(e.to_string()))?;
                    stream.flush().await.map_err(|e| Error::network(e.to_string()))?;
                    Ok(())
                }
                MimicLink::Udp { socket, peer } => {
                    let peer = peer.ok_or_else(|| Error::network("udp peer unknown"))?;
                    socket
                        .send_to(packet, peer)
                        .await
                        .map(|_| ())
                        .map_err(|e| Error::network(e.to_string()))
                }
            }
        }
    }

    /// Minimal IPv4 TCP SYN classifier for the mimic's spare-listener
    /// arming (no IP options on the paths the client's stack emits):
    /// protocol TCP (offset 9), destination port (offset 22), SYN set
    /// and ACK clear (flag byte at offset 33).
    fn is_syn_to_port(pkt: &[u8], port: u16) -> bool {
        if pkt.len() < 40 || pkt[0] >> 4 != 4 || pkt[9] != 6 {
            return false;
        }
        let dst = u16::from_be_bytes([pkt[22], pkt[23]]);
        let flags = pkt[33];
        dst == port && (flags & 0x02) != 0 && (flags & 0x10) == 0
    }

    /// The mimic's own smoltcp stack (wireguard.rs test parity): echo
    /// TCP listeners plus a UDP echo socket. The listener shape mirrors
    /// the production endpoint's wave-12A fix: a smoltcp listener is
    /// consumed by the first handshake, so a SPARE Listen-state socket
    /// is kept armed for concurrent SYNs (arm-before-stage, exactly the
    /// endpoint's stage_packet/needs_listener pair).
    struct ServerStack {
        iface: Interface,
        sockets: SocketSet<'static>,
        shim: Shim,
        /// Every armed listener on ECHO_TCP_PORT.
        listeners: Vec<SocketHandle>,
        conns: Vec<SocketHandle>,
        udp_sock: SocketHandle,
        start: Instant,
        pump: Vec<u8>,
        /// Testing knob: abort (RST) a connection once this many payload
        /// bytes have been received in total (the wave-13 mid-burst
        /// reset repro).
        reset_after_bytes: Option<usize>,
        seen_bytes: usize,
    }

    impl ServerStack {
        fn new() -> ServerStack {
            let mut shim = Shim::new(1500);
            let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
            cfg.random_seed = rand::random();
            let mut iface = Interface::new(cfg, &mut shim, SmolInstant::ZERO);
            iface.update_ip_addrs(|addrs| {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(SERVER_TUNNEL_IP), 24));
            });
            iface
                .routes_mut()
                .add_default_ipv4_route(SERVER_TUNNEL_IP)
                .unwrap();

            let mut sockets = SocketSet::new(Vec::new());
            let listeners = vec![Self::add_listener(&mut sockets)];

            let mut udp_sock = udp::Socket::new(
                udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::EMPTY; 64],
                    vec![0; 32 * 1024],
                ),
                udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::EMPTY; 64],
                    vec![0; 32 * 1024],
                ),
            );
            udp_sock
                .bind(IpListenEndpoint { addr: None, port: ECHO_UDP_PORT })
                .unwrap();
            let udp_sock = sockets.add(udp_sock);

            ServerStack {
                iface,
                sockets,
                shim,
                listeners,
                conns: Vec::new(),
                udp_sock,
                start: Instant::now(),
                pump: vec![0u8; 32 * 1024],
                reset_after_bytes: None,
                seen_bytes: 0,
            }
        }

        /// One more listening socket on the echo port (both families: the
        /// listen endpoint is address-agnostic).
        fn add_listener(sockets: &mut SocketSet<'static>) -> SocketHandle {
            let mut tcp_sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 64 * 1024]),
                tcp::SocketBuffer::new(vec![0; 64 * 1024]),
            );
            tcp_sock
                .listen(IpListenEndpoint { addr: None, port: ECHO_TCP_PORT })
                .unwrap();
            sockets.add(tcp_sock)
        }

        /// A port needs a fresh listener exactly when no LISTEN-state
        /// socket covers it anymore: the moment a SYN takes the existing
        /// listener into SynReceived, that socket only matches its own
        /// 4-tuple, so any further concurrent SYN to the same port would
        /// otherwise fall through to smoltcp's RST reply (the wave-12A
        /// endpoint fix — wireguard.rs:3164-3174 needs_listener — applied
        /// to this mimic's accept path).
        fn needs_listener(&self) -> bool {
            !self.listeners.iter().any(|h| {
                self.sockets.get::<tcp::Socket>(*h).state() == tcp::State::Listen
            })
        }

        /// Stage one decrypted inner IP packet, arming a spare
        /// Listen-state listener FIRST when the packet is a fresh SYN to
        /// the echo port (the endpoint's stage_packet order: arm, then
        /// stage — wireguard.rs:3131-3137).
        fn stage_inner(&mut self, pkt: &[u8]) {
            if is_syn_to_port(pkt, ECHO_TCP_PORT) && self.needs_listener() {
                self.listeners.push(Self::add_listener(&mut self.sockets));
            }
            self.shim.stage(pkt);
        }

        fn now(&self) -> SmolInstant {
            SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
        }

        /// One server pass; returns egress IP packets to encrypt.
        fn step(&mut self) -> Vec<Vec<u8>> {
            let now = self.now();
            self.iface.poll(now, &mut self.shim, &mut self.sockets);

            // Promote listeners that left Listen (the socket became an
            // accepted connection — or died); each was already replaced
            // at stage time, so concurrent SYNs never found a missing
            // listener. Re-arm on leaving Listen, not only once
            // Established: a SYN racing the first handshake must find a
            // listening socket, or smoltcp answers it with an RST — the
            // same race fixed in the endpoint's needs_listener (and in
            // wireguard.rs's own test harness, 4293-4309).
            self.listeners.retain(|h| {
                match self.sockets.get::<tcp::Socket>(*h).state() {
                    tcp::State::Listen => true,
                    tcp::State::Closed => {
                        self.sockets.remove(*h);
                        false
                    }
                    _ => {
                        self.conns.push(*h);
                        false
                    }
                }
            });

            // TCP echo: whatever arrived on any connection goes straight
            // back — unless the reset knob fires: abort (RST) mid-burst.
            let mut closed = Vec::new();
            for &handle in &self.conns {
                let sock = self.sockets.get_mut::<tcp::Socket>(handle);
                while sock.can_recv() {
                    let n = match sock.recv_slice(&mut self.pump) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    self.seen_bytes += n;
                    if self.reset_after_bytes.is_some_and(|limit| self.seen_bytes >= limit) {
                        // Mid-burst abort: the server resets the connection
                        // while the client writer is still pushing (the
                        // wave-12A reset_mid_burst shape).
                        sock.abort();
                        break;
                    }
                    let mut off = 0;
                    while off < n {
                        match sock.send_slice(&self.pump[off..n]) {
                            Ok(w) => off += w,
                            Err(_) => break,
                        }
                    }
                }
                if sock.state() == tcp::State::Closed {
                    closed.push(handle);
                }
            }
            if !closed.is_empty() {
                self.conns.retain(|h| !closed.contains(h));
                for handle in closed {
                    self.sockets.remove(handle);
                }
            }

            {
                let sock = self.sockets.get_mut::<udp::Socket>(self.udp_sock);
                while sock.can_recv() {
                    let (n, mut meta) = match sock.recv_slice(&mut self.pump) {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    meta.local_address = Some(IpAddress::Ipv4(SERVER_TUNNEL_IP));
                    if sock.send_slice(&self.pump[..n], meta).is_err() {
                        break;
                    }
                }
            }

            let now = self.now();
            self.iface.poll(now, &mut self.shim, &mut self.sockets);
            self.shim.egress.drain(..).collect()
        }
    }

    struct Mimic {
        opts: MimicOpts,
        server_config: Arc<rustls::ServerConfig>,
        crypt: Option<ControlCrypt>,
        tls: Option<rustls::ServerConnection>,
        local: [u8; SESSION_ID_SIZE],
        remote: Option<[u8; SESSION_ID_SIZE]>,
        send_message: u32,
        send_packet_id: u32,
        send_packet_time: u32,
        recv_next: u32,
        acks: Vec<u32>,
        data: Option<DataChannel>,
        stack: ServerStack,
    }

    /// One shared (certificate, server config) pair per test: the client's
    /// `<ca>` IS the self-signed server certificate, so the CA check
    /// exercises the SPKI-equality path.
    #[derive(Clone)]
    struct TestCa {
        cert_pem: String,
        server_config: Arc<rustls::ServerConfig>,
    }

    fn test_ca() -> TestCa {
        let certified =
            rcgen::generate_simple_self_signed(vec!["openvpn.test".to_string()]).expect("rcgen");
        let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key)
                .expect("server config"),
        );
        TestCa {
            cert_pem: certified.cert.pem(),
            server_config,
        }
    }

    /// The four-string completeness walk for the CLIENT key-method-2
    /// record (pre-master + two randoms precede the strings).
    fn km2_client_str_complete(packet: &[u8], mut offset: usize) -> bool {
        for _ in 0..4 {
            if offset + 2 > packet.len() {
                return false;
            }
            let size =
                u16::from_be_bytes(packet[offset..offset + 2].try_into().unwrap()) as usize;
            if size != 0 && offset + 2 + size > packet.len() {
                return false;
            }
            offset += 2 + size;
        }
        true
    }

    impl Mimic {
        fn new(opts: MimicOpts, server_config: Arc<rustls::ServerConfig>) -> Self {
            let crypt = opts.server_crypt();
            let mut local = [0u8; SESSION_ID_SIZE];
            rand::rngs::OsRng.fill_bytes(&mut local);
            let mut stack = ServerStack::new();
            stack.reset_after_bytes = opts.reset_after_bytes;
            Mimic {
                server_config,
                crypt,
                tls: None,
                local,
                remote: None,
                send_message: 0,
                send_packet_id: 0,
                send_packet_time: 0,
                recv_next: 0,
                acks: Vec::new(),
                data: None,
                stack,
                opts,
            }
        }

        async fn send_control(&mut self, link: &mut MimicLink, opcode: u8, payload: Vec<u8>) -> Result<()> {
            let mut acks = std::mem::take(&mut self.acks);
            acks.truncate(CONTROL_SEND_ACK_MAX);
            let packet = ControlPacket {
                opcode,
                key_id: 0,
                local_session: self.local,
                ack_ids: acks,
                ack_remote_session: self.remote.unwrap_or([0u8; 8]),
                message_id: self.send_message,
                payload,
            };
            if opcode_has_message_id(opcode) {
                self.send_message += 1;
            }
            self.send_packet_id += 1;
            if self.send_packet_time == 0 {
                self.send_packet_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32;
            }
            let mut header = Vec::with_capacity(TLS_CRYPT_HEADER_SIZE);
            header.push(opcode_key_id(packet.opcode, packet.key_id));
            header.extend_from_slice(&packet.local_session);
            let plain = control_encode_plain(&packet)?;
            let encoded = match &self.crypt {
                None => [header, plain].concat(),
                Some(crypt) => crypt.wrap(&header, self.send_packet_id, self.send_packet_time, &plain)?,
            };
            link.write_packet(&encoded).await
        }

        /// Read the next in-order client P_CONTROL_V1 payload (acking on
        /// the way); data packets are surfaced for the data phase.
        async fn read_control(&mut self, link: &mut MimicLink) -> Result<Vec<u8>> {
            loop {
                let mut buf = vec![0u8; 65_536];
                let n = link.read_packet(&mut buf).await?;
                let (opcode, _) = parse_opcode_key_id(buf[0]);
                if !opcode_is_control(opcode) {
                    continue;
                }
                let (packet, _, _) = match Reliable::decode_packet(self.crypt.as_ref(), &buf[..n]) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if packet.local_session == [0u8; 8] {
                    continue;
                }
                if let Some(remote) = self.remote {
                    if packet.local_session != remote {
                        continue;
                    }
                }
                if opcode_has_message_id(packet.opcode) && !self.acks.contains(&packet.message_id) {
                    self.acks.push(packet.message_id);
                }
                if packet.opcode != P_CONTROL_V1 || packet.payload.is_empty() {
                    continue;
                }
                if packet.message_id == self.recv_next {
                    self.recv_next += 1;
                    return Ok(packet.payload);
                }
                // A retransmission of an already-delivered message.
            }
        }

        async fn tls_flush(&mut self, link: &mut MimicLink) -> Result<()> {
            loop {
                let Some(tls) = self.tls.as_mut() else { return Ok(()) };
                if !tls.wants_write() {
                    return Ok(());
                }
                let mut chunk = Vec::new();
                if tls.write_tls(&mut chunk).map_err(|e| Error::network(e.to_string()))? == 0 {
                    return Ok(());
                }
                for piece in chunk.chunks(MAX_TLS_CONTROL_PAYLOAD) {
                    self.send_control(link, P_CONTROL_V1, piece.to_vec()).await?;
                }
            }
        }

        fn tls_feed(&mut self, wire: &[u8]) -> std::result::Result<(), rustls::Error> {
            let Some(tls) = self.tls.as_mut() else { return Ok(()) };
            let mut rest = wire;
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
            tls.process_new_packets().map(|_| ())
        }

        /// Plaintext out of the server TLS session, reading the control
        /// channel as needed.
        async fn read_plaintext(&mut self, link: &mut MimicLink) -> Result<Vec<u8>> {
            loop {
                let mut got = Vec::new();
                if let Some(tls) = self.tls.as_mut() {
                    let mut tmp = [0u8; 4096];
                    loop {
                        match std::io::Read::read(&mut tls.reader(), &mut tmp) {
                            Ok(0) => break,
                            Ok(n) => got.extend_from_slice(&tmp[..n]),
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => return Err(Error::network(format!("mimic tls read: {e}"))),
                        }
                    }
                }
                if !got.is_empty() {
                    return Ok(got);
                }
                let payload = self.read_control(link).await?;
                if let Err(e) = self.tls_feed(&payload) {
                    return Err(Error::network(format!("mimic tls: {e}")));
                }
            }
        }

        async fn tls_write_all(&mut self, link: &mut MimicLink, bytes: &[u8]) -> Result<()> {
            {
                let Some(tls) = self.tls.as_mut() else { return Ok(()) };
                use std::io::Write;
                tls.writer()
                    .write_all(bytes)
                    .map_err(|e| Error::network(format!("mimic tls write: {e}")))?;
            }
            self.tls_flush(link).await
        }

        async fn serve(mut self, mut link: MimicLink) -> Result<()> {
            // 1. The client's hard reset (V2, or V3 + wrapped client key).
            //    For tls-crypt-v2 the wrapped client key trails the
            //    tls-crypt-wrapped reset (client.go:816-819) and must be
            //    split off before the v1-style unwrap.
            let mut buf = vec![0u8; 65_536];
            let n = link.read_packet(&mut buf).await?;
            let mut packet_end = n;
            if let Some((_, wrapped)) = &self.opts.tls_crypt_v2 {
                packet_end = n.saturating_sub(wrapped.len());
            }
            let (reset, _, _) = Reliable::decode_packet(self.crypt.as_ref(), &buf[..packet_end])
                .map_err(|e| Error::network(format!("mimic: client reset: {e}")))?;
            assert!(
                reset.opcode == P_CONTROL_HARD_RESET_CLIENT_V2
                    || reset.opcode == P_CONTROL_HARD_RESET_CLIENT_V3,
                "expected a client hard reset, got opcode {}",
                reset.opcode
            );
            if self.crypt.as_ref().is_some_and(|c| c.is_v2()) {
                assert_eq!(reset.opcode, P_CONTROL_HARD_RESET_CLIENT_V3, "tls-crypt-v2 uses the V3 reset");
                // Beyond the v1-wrapped reset there must be trailing
                // bytes: the wrapped client key.
                assert!(
                    n > packet_end,
                    "V3 reset must carry the wrapped client key"
                );
            }
            self.remote = Some(reset.local_session);
            // The reset consumed message id 0 of the client's stream.
            self.recv_next = reset.message_id + 1;
            self.acks.push(reset.message_id);

            // 2. Server reset (key epoch 0, message 0).
            self.send_control(&mut link, P_CONTROL_HARD_RESET_SERVER_V2, Vec::new())
                .await?;

            // 3. TLS handshake over the control channel.
            let tls = rustls::ServerConnection::new(self.server_config.clone())
                .map_err(|e| Error::config(format!("mimic tls init: {e}")))?;
            self.tls = Some(tls);
            self.tls_flush(&mut link).await?;
            loop {
                let (hs, ww) = {
                    let t = self.tls.as_ref().unwrap();
                    (t.is_handshaking(), t.wants_write())
                };
                if !hs && !ww {
                    break;
                }
                self.tls_flush(&mut link).await?;
                if !hs {
                    break;
                }
                let payload = self.read_control(&mut link).await?;
                if let Err(e) = self.tls_feed(&payload) {
                    return Err(Error::network(format!("mimic tls handshake: {e}")));
                }
            }

            // 4. Key method 2: read the client record, send ours. The
            //    CLIENT record carries a 48-byte pre-master before the
            //    randoms (keymethod.go:74-89), so its completeness walk
            //    starts at 4+1+48+32+32 = 117, not the server's 69.
            let mut km2 = Vec::new();
            while !(km2.len() >= 117 && km2_client_str_complete(&km2, 117)) {
                let got = self.read_plaintext(&mut link).await?;
                km2.extend_from_slice(&got);
            }
            assert_eq!(u32::from_be_bytes(km2[..4].try_into().unwrap()), 0);
            assert_eq!(km2[4] & 0x0f, 2);
            let mut client_source = KeySource {
                pre_master: [0; KEY_SOURCE_PRE_MASTER_SIZE],
                random1: [0; KEY_SOURCE_RANDOM_SIZE],
                random2: [0; KEY_SOURCE_RANDOM_SIZE],
            };
            client_source.pre_master.copy_from_slice(&km2[5..53]);
            client_source.random1.copy_from_slice(&km2[53..85]);
            client_source.random2.copy_from_slice(&km2[85..117]);

            let mut server_random1 = [0u8; 32];
            let mut server_random2 = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut server_random1);
            rand::rngs::OsRng.fill_bytes(&mut server_random2);
            let mut server_record = Vec::with_capacity(128);
            server_record.extend_from_slice(&0u32.to_be_bytes());
            server_record.push(2);
            server_record.extend_from_slice(&server_random1);
            server_record.extend_from_slice(&server_random2);
            append_openvpn_string(
                &mut server_record,
                &install_script_options_string(
                    self.opts.proto,
                    &self.opts.cipher,
                    &self.opts.auth,
                    self.opts.comp_lzo,
                ),
            );
            append_openvpn_string(&mut server_record, "");
            append_openvpn_string(&mut server_record, "");
            append_openvpn_string(&mut server_record, "");
            self.tls_write_all(&mut link, &server_record).await?;

            // 5. PUSH exchange.
            let mut push_req = Vec::new();
            while !push_req.starts_with(b"PUSH_REQUEST") {
                push_req = self.read_plaintext(&mut link).await?;
            }
            assert!(push_req.starts_with(b"PUSH_REQUEST"));
            let push = self.opts.push_message();
            self.tls_write_all(&mut link, format!("{push}\0").as_bytes())
                .await?;

            if self.opts.auth_failed {
                // Let the client observe the failure, then end.
                tokio::time::sleep(Duration::from_millis(200)).await;
                return Ok(());
            }

            // 6. Derive the server-side data keys (send/recv swapped) and
            //    open the data epoch.
            let client_keys = derive_client_key_material(
                &client_source,
                &ServerKeySource {
                    random1: server_random1,
                    random2: server_random2,
                },
                &self.remote.unwrap(),
                &self.local,
                32,
            )?;
            let key_len = cipher_key_length(&self.opts.cipher);
            let mut server_keys = KeyMaterial {
                send_cipher_key: client_keys.recv_cipher_key,
                send_hmac_key: client_keys.recv_hmac_key.clone(),
                recv_cipher_key: client_keys.send_cipher_key,
                recv_hmac_key: client_keys.send_hmac_key.clone(),
            };
            server_keys.send_cipher_key.truncate(key_len);
            server_keys.recv_cipher_key.truncate(key_len);
            let peer_id = if self.opts.push_extra.contains("peer-id") {
                5
            } else {
                PEER_ID_UNSET
            };
            self.data = Some(DataChannel::new(
                &server_keys,
                &self.opts.cipher,
                &self.opts.auth,
                peer_id,
                0,
            )?);

            // 7. Data loop: decrypt, echo through the stack, encrypt.
            loop {
                for pkt in self.stack.step() {
                    let pkt = if self.opts.comp_lzo {
                        lzo_frame(&pkt)
                    } else {
                        pkt
                    };
                    let encrypted = self
                        .data
                        .as_mut()
                        .expect("data channel")
                        .encrypt(&pkt)?;
                    link.write_packet(&encrypted).await?;
                }
                let mut buf = vec![0u8; 65_536];
                match tokio::time::timeout(Duration::from_millis(10), link.read_packet(&mut buf))
                    .await
                {
                    Ok(Ok(n)) => {
                        let (opcode, _) = parse_opcode_key_id(buf[0]);
                        if opcode_is_control(opcode) {
                            let (packet, _, _) =
                                match Reliable::decode_packet(self.crypt.as_ref(), &buf[..n]) {
                                    Ok(v) => v,
                                    Err(_) => continue,
                                };
                            if opcode_has_message_id(packet.opcode)
                                && !self.acks.contains(&packet.message_id)
                            {
                                self.acks.push(packet.message_id);
                            }
                            if !self.acks.is_empty() {
                                self.send_control(&mut link, P_ACK_V1, Vec::new()).await?;
                            }
                            continue;
                        }
                        let Some(data) = self.data.as_mut() else { continue };
                        let plain = match data.decrypt(&buf[..n]) {
                            Ok(p) => p,
                            Err(e) => return Err(Error::network(format!("mimic decrypt: {e}"))),
                        };
                        let plain = if self.opts.comp_lzo && !plain.is_empty() {
                            lzo_unframe(&plain)?
                        } else {
                            plain
                        };
                        if plain == OPENVPN_PING_PACKET {
                            continue;
                        }
                        self.stack.stage_inner(&plain);
                    }
                    Ok(Err(_)) => return Ok(()),
                    Err(_) => {}
                }
            }
        }
    }

    async fn spawn_mimic_tcp(opts: MimicOpts, ca: &TestCa) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ca = ca.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { continue };
                let mimic = Mimic::new(opts_plain_clone(&opts), ca.server_config.clone());
                let link = MimicLink::Tcp(stream);
                tokio::spawn(async move {
                    if let Err(e) = mimic.serve(link).await {
                        tracing::debug!(target: "engine", "openvpn mimic: {e}");
                    }
                });
            }
        });
        addr
    }

    fn opts_plain_clone(opts: &MimicOpts) -> MimicOpts {
        MimicOpts {
            proto: opts.proto,
            cipher: opts.cipher.clone(),
            auth: opts.auth.clone(),
            comp_lzo: opts.comp_lzo,
            push_extra: opts.push_extra.clone(),
            auth_failed: opts.auth_failed,
            tls_auth: opts.tls_auth,
            key_direction: opts.key_direction.clone(),
            tls_crypt: opts.tls_crypt,
            tls_crypt_v2: opts.tls_crypt_v2.clone(),
            reset_after_bytes: opts.reset_after_bytes,
        }
    }

    async fn spawn_mimic_udp(opts: MimicOpts, ca: &TestCa) -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let mimic = Mimic::new(opts_plain_clone(&opts), ca.server_config.clone());
        tokio::spawn(async move {
            let link = MimicLink::Udp { socket, peer: None };
            if let Err(e) = mimic.serve(link).await {
                tracing::debug!(target: "engine", "openvpn mimic: {e}");
            }
        });
        addr
    }

    fn test_cfg(addr: SocketAddr, proto: &str) -> OpenVpnOut {
        OpenVpnOut {
            name: format!("ovpn-test-{}", rand::random::<u32>()),
            server: addr.ip().to_string(),
            port: addr.port(),
            proto: Some(proto.into()),
            dev: "tun".into(),
            cipher: String::new(),
            data_ciphers: Vec::new(),
            data_cipher_fallback: String::new(),
            auth: String::new(),
            comp_lzo: String::new(),
            ca: String::new(),
            cert: None,
            key: None,
            tls_auth: None,
            key_direction: None,
            tls_crypt: None,
            tls_crypt_v2: None,
            username: Some(format!("user-{:08x}", rand::random::<u32>())),
            password: Some(format!("pass-{:08x}", rand::random::<u32>())),
            peer_info: Vec::new(),
            ping: 0,
            ping_restart: 0,
            tran_window: None,
            handshake_timeout: 10,
            mtu: 0,
            ip_stack: IpStackOption::default(),
            remote_dns_resolve: false,
            dns: Vec::new(),
        }
    }

    // ------------------------------------------------------------ unit tests

    #[test]
    fn hmac_rfc2202_vectors() {
        // RFC 2202 test case 1: the MD5 vectors use a 16-byte key, the
        // SHA-1 vectors a 20-byte key, data "Hi There".
        let md5_key = [0x0bu8; 16];
        let sha1_key = [0x0bu8; 20];
        assert_eq!(
            AuthDigest::Md5.mac(&md5_key, &[b"Hi There"]),
            hex_decode("9294727a3638bb1c13f48ef8158bfc9d").unwrap()
        );
        assert_eq!(
            AuthDigest::Sha1.mac(&sha1_key, &[b"Hi There"]),
            hex_decode("b617318655057264e28bc0b6fb378c8ef146be00").unwrap()
        );
        assert_eq!(AuthDigest::Sha256.size(), 32);
        assert_eq!(AuthDigest::Sha512.size(), 64);
    }

    #[test]
    fn prf_splits_secret_halves_and_mirrors_keys() {
        let client = KeySource {
            pre_master: [7u8; 48],
            random1: [1u8; 32],
            random2: [2u8; 32],
        };
        let server = ServerKeySource {
            random1: [3u8; 32],
            random2: [4u8; 32],
        };
        let cs = [0xaau8; 8];
        let ss = [0xbbu8; 8];
        let keys = derive_client_key_material(&client, &server, &cs, &ss, 32).unwrap();
        assert_eq!(keys.send_cipher_key.len(), 32);
        assert_eq!(keys.send_hmac_key.len(), 64);
        assert_eq!(keys.recv_hmac_key.len(), 64);
        // The key block is directional: client send ≠ client recv.
        assert_ne!(keys.send_cipher_key, keys.recv_cipher_key);
        // Odd-length secrets split with overlap (openvpnPRF's split).
        let out = openvpn_prf(&[9u8; 47], "label", &[1u8; 4], &[2u8; 4], &[], &[], 64);
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn control_packet_codec_roundtrip() {
        let packet = ControlPacket {
            opcode: P_CONTROL_V1,
            key_id: 3,
            local_session: [9u8; 8],
            ack_ids: vec![7, 8],
            ack_remote_session: [1u8; 8],
            message_id: 44,
            payload: b"payload bytes".to_vec(),
        };
        let plain = control_encode_plain(&packet).unwrap();
        let (acks, remote, mid, payload) =
            control_decode_plain(P_CONTROL_V1, &plain).unwrap();
        assert_eq!(acks, vec![7, 8]);
        assert_eq!(remote, [1u8; 8]);
        assert_eq!(mid, 44);
        assert_eq!(payload, b"payload bytes".to_vec());

        // Each cryptor round-trips, and a wrong static key fails.
        let settings = Settings {
            auth: AUTH_SHA256.into(),
            key_direction: "1".into(),
            tls_auth_key: Some(random_static_key()),
            ..settings_for_crypt()
        };
        let crypt = ControlCrypt::new(&settings).unwrap().unwrap();
        let mut header = Vec::new();
        header.push(opcode_key_id(packet.opcode, packet.key_id));
        header.extend_from_slice(&packet.local_session);
        let wrapped = crypt.wrap(&header, 9, 1000, &plain).unwrap();
        // The server's cryptor uses the opposite key-direction slot.
        let mut server_settings = settings.clone();
        server_settings.key_direction = "0".into();
        let server_crypt = ControlCrypt::new(&server_settings).unwrap().unwrap();
        let (h2, pid, time, p2) = server_crypt.unwrap(&wrapped).unwrap();
        assert_eq!(h2, header);
        assert_eq!((pid, time), (9, 1000));
        assert_eq!(p2, plain);

        let wrong = {
            let mut s = settings.clone();
            s.tls_auth_key = Some(random_static_key());
            ControlCrypt::new(&s).unwrap().unwrap()
        };
        assert!(wrong.unwrap(&wrapped).is_err());

        // tls-crypt round-trip + wrong key: the SERVER cryptor (inverse
        // direction) unwraps what the client wrapped.
        let key = random_static_key();
        let mut s = settings_for_crypt();
        s.tls_crypt_key = Some(key);
        let client_crypt = ControlCrypt::new(&s).unwrap().unwrap();
        let (encrypt, decrypt) = tls_crypt_slots(&key, false);
        let server_crypt = ControlCrypt::TlsCrypt { encrypt, decrypt };
        let wrapped = client_crypt.wrap(&header, 3, 77, &plain).unwrap();
        let (_, pid, time, p2) = server_crypt.unwrap(&wrapped).unwrap();
        assert_eq!((pid, time, p2), (3, 77, plain));
        let mut bad = settings_for_crypt();
        bad.tls_crypt_key = Some(random_static_key());
        assert!(ControlCrypt::new(&bad).unwrap().unwrap().unwrap(&wrapped).is_err());

        // tls-crypt-v2 PEM decode + selection.
        let material = random_static_key();
        let mut wrapped_key = vec![0x51u8; 72];
        rand::rngs::OsRng.fill_bytes(&mut wrapped_key);
        let pem = tls_crypt_v2_client_pem(&material, &wrapped_key);
        let (m2, w2) = decode_tls_crypt_v2_client_key(pem.as_bytes()).unwrap();
        assert_eq!(m2, material);
        assert_eq!(w2, wrapped_key);
        let mut s = settings_for_crypt();
        s.tls_crypt_v2_key = Some(material);
        s.tls_crypt_v2_wrapped = Some(wrapped_key.clone());
        let v2 = ControlCrypt::new(&s).unwrap().unwrap();
        assert!(v2.is_v2());
        assert_eq!(v2.wrapped_client_key(), wrapped_key.as_slice());
    }

    fn settings_for_crypt() -> Settings {
        Settings {
            server: "127.0.0.1".into(),
            port: 1,
            proto: PROTO_UDP.into(),
            cipher: CIPHER_AES128GCM.into(),
            data_ciphers: Vec::new(),
            fallback_cipher: String::new(),
            auth: AUTH_SHA256.into(),
            comp_lzo: false,
            ca: Vec::new(),
            cert: None,
            key: None,
            tls_auth_key: None,
            key_direction: String::new(),
            tls_crypt_key: None,
            tls_crypt_v2_key: None,
            tls_crypt_v2_wrapped: None,
            username: "u".into(),
            password: "p".into(),
            peer_info: Vec::new(),
            ping: Duration::ZERO,
            ping_restart: Duration::ZERO,
            transition_window: Duration::from_secs(3600),
            handshake_timeout: Duration::from_secs(10),
            mtu: 1500,
            remote_dns_resolve: false,
            dns: Vec::new(),
        }
    }

    #[test]
    fn static_key_pem_decodes() {
        let key = random_static_key();
        let pem = static_key_pem(&key);
        assert_eq!(decode_static_key(pem.as_bytes()).unwrap(), key);
        // A 255-byte body is rejected with the upstream length error.
        let mut short = key.to_vec();
        short.truncate(255);
        let mut short_pem = String::from("-----BEGIN OpenVPN Static key V1-----\n");
        short_pem.push_str(&hex_encode(&short));
        short_pem.push_str("\n-----END OpenVPN Static key V1-----\n");
        assert!(decode_static_key(short_pem.as_bytes()).is_err());
    }

    #[test]
    fn km2_records_lay_out_and_parse() {
        let (bytes, source) =
            client_km2_record("V4,dev-type tun", "IV_VER=mihomo-openvpn", "user", "pass");
        assert_eq!(u32::from_be_bytes(bytes[..4].try_into().unwrap()), 0);
        assert_eq!(bytes[4], 2);
        assert_eq!(&bytes[5..53], &source.pre_master[..]);
        assert_eq!(&bytes[53..85], &source.random1[..]);
        assert_eq!(&bytes[85..117], &source.random2[..]);
        // options string: len 16 + 1 NUL
        let opts_len = u16::from_be_bytes(bytes[117..119].try_into().unwrap()) as usize;
        assert_eq!(opts_len, "V4,dev-type tun".len() + 1);
        assert_eq!(&bytes[119..119 + opts_len - 1], b"V4,dev-type tun");
        assert_eq!(bytes[119 + opts_len - 1], 0);

        // Server record with all four strings.
        let mut rec = Vec::new();
        rec.extend_from_slice(&0u32.to_be_bytes());
        rec.push(2);
        rec.extend_from_slice(&[7u8; 32]);
        rec.extend_from_slice(&[8u8; 32]);
        append_openvpn_string(&mut rec, "V4,dev-type tun");
        append_openvpn_string(&mut rec, "");
        append_openvpn_string(&mut rec, "");
        append_openvpn_string(&mut rec, "");
        assert_eq!(km2_record_complete(&rec), Some(rec.len()));
        let (parsed, consumed) = parse_server_km2(&rec).unwrap();
        assert_eq!(consumed, rec.len());
        assert_eq!(parsed.sources.random1, [7u8; 32]);
        assert_eq!(parsed.sources.random2, [8u8; 32]);

        // OpenVPN 2.6 trailing-shortened record: options then PUSH_REPLY.
        let mut short_rec = rec[..5 + 64].to_vec();
        append_openvpn_string(&mut short_rec, "V4,dev-type tun");
        short_rec.extend_from_slice(b"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\0");
        let (parsed2, consumed2) = parse_server_km2(&short_rec).unwrap();
        assert_eq!(parsed2.sources.random1, [7u8; 32]);
        assert!(consumed2 < short_rec.len(), "PUSH_REPLY stays in leftover");
        assert!(short_rec[consumed2..].starts_with(b"PUSH_REPLY"));

        assert!(parse_server_km2(&rec[..60]).is_err());
        let mut bad = rec.clone();
        bad[4] = 1;
        assert!(parse_server_km2(&bad).is_err());
    }

    fn test_keys() -> KeyMaterial {
        let client = KeySource {
            pre_master: [5u8; 48],
            random1: [1u8; 32],
            random2: [2u8; 32],
        };
        let server = ServerKeySource {
            random1: [3u8; 32],
            random2: [4u8; 32],
        };
        derive_client_key_material(&client, &server, &[1u8; 8], &[2u8; 8], 32).unwrap()
    }

    /// `test_keys` truncated to the cipher's key length.
    fn test_keys_for(cipher: &str) -> KeyMaterial {
        let mut keys = test_keys();
        let len = cipher_key_length(cipher);
        keys.send_cipher_key.truncate(len);
        keys.recv_cipher_key.truncate(len);
        keys
    }

    #[test]
    fn data_channel_aead_roundtrip_all_variants() {
        for cipher in [
            CIPHER_AES128GCM,
            CIPHER_AES192GCM,
            CIPHER_AES256GCM,
            CIPHER_CHACHA20POLY1305,
        ] {
            let mut keys = test_keys();
            let key_len = cipher_key_length(cipher);
            keys.send_cipher_key.truncate(key_len);
            keys.recv_cipher_key.truncate(key_len);
            let mut client = DataChannel::new(&keys, cipher, AUTH_SHA256, 5, 0).unwrap();
            let mut server_keys = KeyMaterial {
                send_cipher_key: keys.recv_cipher_key.clone(),
                send_hmac_key: keys.recv_hmac_key.clone(),
                recv_cipher_key: keys.send_cipher_key.clone(),
                recv_hmac_key: keys.send_hmac_key.clone(),
            };
            server_keys.send_cipher_key.truncate(key_len);
            server_keys.recv_cipher_key.truncate(key_len);
            let mut server = DataChannel::new(&server_keys, cipher, AUTH_SHA256, 5, 0).unwrap();

            // P_DATA_V2 header with the peer id.
            assert_eq!(client_header(&client), opcode_key_id(P_DATA_V2, 0));

            let pkt = client.encrypt(b"ip packet bytes").unwrap();
            assert_eq!(&pkt[..4], &client_header_vec(&client)[..4]);
            assert_eq!(server.decrypt(&pkt).unwrap(), b"ip packet bytes".to_vec());
            // Replay rejected.
            assert!(server.decrypt(&pkt).is_err());
            // Tamper rejected.
            let mut tampered = client.encrypt(b"another").unwrap();
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            assert!(server.decrypt(&tampered).is_err());
        }

        // No peer id → P_DATA_V1.
        let mut keys = test_keys();
        keys.send_cipher_key.truncate(16);
        keys.recv_cipher_key.truncate(16);
        let mut client = DataChannel::new(&keys, CIPHER_AES128GCM, AUTH_SHA256, PEER_ID_UNSET, 2).unwrap();
        let pkt = client.encrypt(b"x").unwrap();
        assert_eq!(pkt[0], opcode_key_id(P_DATA_V1, 2));
    }

    fn client_header(c: &DataChannel) -> u8 {
        c.header[0]
    }

    fn client_header_vec(c: &DataChannel) -> Vec<u8> {
        c.header.clone()
    }

    #[test]
    fn data_channel_cbc_roundtrip() {
        for cipher in [CIPHER_AES128CBC, CIPHER_AES192CBC, CIPHER_AES256CBC] {
            let keys = test_keys_for(cipher);
            let mut client = DataChannel::new(&keys, cipher, AUTH_SHA256, 5, 0).unwrap();
            let mut server_keys = KeyMaterial {
                send_cipher_key: keys.recv_cipher_key.clone(),
                send_hmac_key: keys.recv_hmac_key.clone(),
                recv_cipher_key: keys.send_cipher_key.clone(),
                recv_hmac_key: keys.send_hmac_key.clone(),
            };
            server_keys.send_cipher_key.truncate(cipher_key_length(cipher));
            server_keys.recv_cipher_key.truncate(cipher_key_length(cipher));
            let mut server = DataChannel::new(&server_keys, cipher, AUTH_SHA256, 5, 0).unwrap();
            let pkt = client.encrypt(b"cbc payload").unwrap();
            assert_eq!(server.decrypt(&pkt).unwrap(), b"cbc payload".to_vec());
            assert!(server.decrypt(&pkt).is_err(), "replay");
            let mut tampered = client.encrypt(b"z").unwrap();
            let mid = 4 + 32; // header + HMAC tag region
            tampered[mid] ^= 1;
            assert!(server.decrypt(&tampered).is_err(), "HMAC covers the body");
        }
    }

    #[test]
    fn lzo_framing() {
        assert_eq!(lzo_frame(b"abc"), [0xFA, b'a', b'b', b'c']);
        assert_eq!(lzo_unframe(&[0xFA, 1, 2]).unwrap(), vec![1, 2]);
        let err = lzo_unframe(&[0x66, 9]).unwrap_err().to_string();
        assert!(err.contains("no LZO decompressor"), "{err}");
        assert!(lzo_unframe(&[0x11]).is_err());
    }

    #[test]
    fn negotiate_cipher_matrix() {
        let mut s = settings_for_crypt();
        s.cipher = CIPHER_AES128GCM.into();
        // No push → local cipher.
        assert_eq!(negotiate_cipher(&s, &[], "").unwrap(), CIPHER_AES128GCM);
        // data-ciphers list: first common entry wins.
        s.data_ciphers = vec![CIPHER_AES256GCM.into(), CIPHER_AES128GCM.into()];
        assert_eq!(
            negotiate_cipher(&s, &[CIPHER_AES128GCM.into(), CIPHER_CHACHA20POLY1305.into()], "")
                .unwrap(),
            CIPHER_AES128GCM
        );
        // No intersection + fallback.
        s.fallback_cipher = CIPHER_AES256CBC.into();
        assert_eq!(
            negotiate_cipher(&s, &[CIPHER_CHACHA20POLY1305.into()], "").unwrap(),
            CIPHER_AES256CBC
        );
        // No intersection, no fallback → error.
        s.fallback_cipher = String::new();
        assert!(negotiate_cipher(&s, &[CIPHER_CHACHA20POLY1305.into()], "").is_err());
        // No data-ciphers: pushed cipher accepted when supported.
        s.data_ciphers = Vec::new();
        s.fallback_cipher = String::new();
        assert_eq!(
            negotiate_cipher(&s, &[], CIPHER_AES256GCM).unwrap(),
            CIPHER_AES256GCM
        );
        // Unsupported pushed cipher without fallback → error.
        assert!(negotiate_cipher(&s, &[], "BF-CBC").is_err());
    }

    #[test]
    fn push_reply_parsing() {
        let push = parse_push_reply_inner(
            "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,route 192.168.0.0 255.255.0.0,\
             dhcp-option DNS 10.8.0.1,peer-id 7,redirect-gateway,block-ipv6,\
             data-ciphers AES-256-GCM:AES-128-GCM,cipher AES-256-GCM,\
             auth-token AT,auth-token-user dXNlcg==,push-continuation 1",
        )
        .unwrap();
        assert_eq!(push.prefixes, vec![(IpAddr::V4(CLIENT_TUNNEL_IP), 24)]);
        assert_eq!(push.routes, vec![(IpAddr::V4("192.168.0.0".parse().unwrap()), 16)]);
        assert_eq!(push.dns, vec![IpAddr::V4(SERVER_TUNNEL_IP)]);
        assert_eq!(push.peer_id, 7);
        assert!(push.redirect && push.block_ipv6);
        assert_eq!(push.data_ciphers, vec!["AES-256-GCM", "AES-128-GCM"]);
        assert_eq!(push.cipher, "AES-256-GCM");
        assert_eq!(push.auth_token_pass, "AT");
        assert_eq!(push.auth_token_user, "user");
        assert_eq!(push.push_continuation, 1);

        // Continuation merge: intermediate 2 then final 1.
        let first = parse_push_reply_inner("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,push-continuation 2").unwrap();
        let second = parse_push_reply_inner("PUSH_REPLY,peer-id 3,push-continuation 1").unwrap();
        let merged = merge_push_reply(Some(first), second).unwrap();
        assert_eq!(merged.prefixes.len(), 1);
        assert_eq!(merged.peer_id, 3);

        // AUTH_FAILED / RESTART surface as errors.
        assert!(control_message_error(b"AUTH_FAILED,rate\0").is_err());
        assert!(control_message_error(b"RESTART\0").is_err());
        // AUTH_PENDING timeout cap (30min).
        let pending = parse_auth_pending_timeout("AUTH_PENDING,timeout 99999").unwrap();
        assert_eq!(pending.auth_pending_secs, 1800);
    }

    #[test]
    fn config_validation_errors() {
        let mut cfg = test_cfg(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1)), "udp");
        cfg.ca = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n".into();

        // Happy path.
        cfg.prepare().unwrap();

        let mut bad = cfg.clone();
        bad.proto = Some("sctp".into());
        assert!(bad.prepare().unwrap_err().to_string().contains("only udp and tcp"));

        let mut bad = cfg.clone();
        bad.dev = "tap".into();
        assert!(bad.prepare().unwrap_err().to_string().contains("only dev tun"));

        let mut bad = cfg.clone();
        bad.cipher = "BF-CBC".into();
        let err = bad.prepare().unwrap_err().to_string();
        assert!(err.contains("unsupported openvpn cipher \"BF-CBC\""), "{err}");

        let mut bad = cfg.clone();
        bad.auth = "SHA3".into();
        assert!(bad.prepare().unwrap_err().to_string().contains("unsupported openvpn auth"));

        let mut bad = cfg.clone();
        bad.key_direction = Some("2".into());
        bad.tls_auth = Some(static_key_pem(&random_static_key()));
        assert!(bad.prepare().unwrap_err().to_string().contains("key-direction"));

        let mut bad = cfg.clone();
        bad.tls_auth = Some(static_key_pem(&random_static_key()));
        bad.tls_crypt = Some(static_key_pem(&random_static_key()));
        assert!(bad.prepare().unwrap_err().to_string().contains("mutually exclusive"));

        let mut bad = cfg.clone();
        bad.ca = String::new();
        assert!(bad.prepare().unwrap_err().to_string().contains("<ca>"));

        let mut bad = cfg.clone();
        bad.username = None;
        bad.cert = None;
        assert!(bad.prepare().unwrap_err().to_string().contains("cert+key or username"));

        let mut bad = cfg.clone();
        bad.comp_lzo = "sometimes".into();
        assert!(bad.prepare().unwrap_err().to_string().contains("comp-lzo"));

        let mut bad = cfg.clone();
        bad.ip_stack.mode = "gvisor".into();
        assert!(bad.prepare().unwrap_err().to_string().contains("with_gvisor build tag"));

        let mut bad = cfg.clone();
        bad.ip_stack.mode = "bogus".into();
        assert!(bad.prepare().unwrap_err().to_string().contains("invalid IP stack mode"));

        let mut bad = cfg.clone();
        bad.remote_dns_resolve = true;
        bad.dns = vec!["1.1.1.1".into()];
        assert!(bad.prepare().unwrap_err().to_string().contains("requires a scheme"));

        let mut bad = cfg;
        bad.handshake_timeout = -1;
        assert!(bad.prepare().unwrap_err().to_string().contains("handshake timeout"));
    }

    // ------------------------------------------------- full loopback tunnels

    async fn tunnel_roundtrip(proto: &str, mut opts: MimicOpts, mut cfg_extra: impl FnMut(&mut OpenVpnOut)) {
        let ca = test_ca();
        let addr = if proto == "tcp" {
            spawn_mimic_tcp(opts_plain_clone(&opts), &ca).await
        } else {
            spawn_mimic_udp(opts_plain_clone(&opts), &ca).await
        };
        let mut cfg = test_cfg(addr, proto);
        cfg.ca = ca.cert_pem.clone();
        if let Some(key) = opts.tls_auth.take() {
            cfg.tls_auth = Some(static_key_pem(&key));
            cfg.key_direction = Some(opts.key_direction.clone());
        }
        if let Some(key) = opts.tls_crypt.take() {
            cfg.tls_crypt = Some(static_key_pem(&key));
        }
        if let Some((material, wrapped)) = opts.tls_crypt_v2.take() {
            cfg.tls_crypt_v2 = Some(tls_crypt_v2_client_pem(&material, &wrapped));
        }
        cfg.comp_lzo = if opts.comp_lzo { "yes".into() } else { String::new() };
        if !opts.cipher.is_empty() {
            cfg.cipher = opts.cipher.clone();
        }
        cfg_extra(&mut cfg);

        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);
        let mut stream = tokio::time::timeout(
            Duration::from_secs(20),
            connect(&cfg, &target),
        )
        .await
        .expect("dial timeout")
        .expect("dial through the tunnel");

        let payload = b"hello over openvpn!".repeat(64);
        stream.write_all(&payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut echoed))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(echoed, payload);

        stream.write_all(b"second chunk").await.unwrap();
        let mut more = vec![0u8; 12];
        tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut more))
            .await
            .expect("echo timeout 2")
            .unwrap();
        assert_eq!(more, b"second chunk");
        let _ = stream.shutdown().await;
    }

    #[tokio::test]
    async fn tcp_echo_over_tcp_transport() {
        tunnel_roundtrip("tcp", MimicOpts::plain("tcp"), |_| {}).await;
    }

    #[tokio::test]
    async fn tcp_echo_over_udp_transport() {
        tunnel_roundtrip("udp", MimicOpts::plain("udp"), |_| {}).await;
    }

    #[tokio::test]
    async fn tcp_echo_with_tls_auth() {
        let key = random_static_key();
        for dir in ["", "0", "1"] {
            let mut opts = MimicOpts::plain("tcp");
            opts.tls_auth = Some(key);
            opts.key_direction = dir.into();
            tunnel_roundtrip("tcp", opts, |cfg| {
                cfg.key_direction = if dir.is_empty() { None } else { Some(dir.into()) };
            })
            .await;
        }
    }

    #[tokio::test]
    async fn tcp_echo_with_tls_crypt() {
        let key = random_static_key();
        let mut opts = MimicOpts::plain("udp");
        opts.tls_crypt = Some(key);
        tunnel_roundtrip("udp", opts, |_| {}).await;
    }

    #[tokio::test]
    async fn tcp_echo_with_tls_crypt_v2() {
        let material = random_static_key();
        let mut wrapped = vec![0u8; 72];
        rand::rngs::OsRng.fill_bytes(&mut wrapped);
        let mut opts = MimicOpts::plain("tcp");
        opts.tls_crypt_v2 = Some((material, wrapped));
        tunnel_roundtrip("tcp", opts, |_| {}).await;
    }

    #[tokio::test]
    async fn tcp_echo_with_comp_lzo_framing() {
        let mut opts = MimicOpts::plain("tcp");
        opts.comp_lzo = true;
        tunnel_roundtrip("tcp", opts, |_| {}).await;
    }

    #[tokio::test]
    async fn tcp_echo_with_negotiated_cipher() {
        // The server pushes AES-256-GCM; the client offers both in
        // data-ciphers → the negotiated cipher is AES-256-GCM.
        let mut opts = MimicOpts::plain("tcp");
        opts.cipher = CIPHER_AES256GCM.into();
        opts.push_extra = ",peer-id 5,cipher AES-256-GCM".into();
        tunnel_roundtrip("tcp", opts, |cfg| {
            cfg.data_ciphers = vec!["AES-128-GCM".into(), "AES-256-GCM".into()];
        })
        .await;
    }

    // ------------------------------------------------- wave-13 stall repros
    //
    // Mirrors of the wave-12A wireguard.rs repros against THIS module's
    // `service_conns` + `OvpnStream`: the mid-burst reset, the
    // concurrent-dials listener race (in the mimic's accept path — the
    // production stack here is client-only, so the re-arm lives in the
    // test server exactly as wireguard.rs's harness re-arms its echo
    // listener), and the slow-reader window close/reopen pair.

    /// REPRO (wave-13, mirrors wireguard.rs's wave-12A
    /// `reset_mid_burst_fails_the_writer_not_hangs`): the mimic resets
    /// the connection (RST) after the first data segment while the
    /// client writer is still pushing a burst far bigger than every
    /// buffer. The writer must fail with BrokenPipe promptly, not hang
    /// on a `to_stack` queue nobody drains.
    #[tokio::test]
    async fn reset_mid_burst_fails_the_writer_not_hangs() {
        let ca = test_ca();
        let mut opts = MimicOpts::plain("udp");
        opts.reset_after_bytes = Some(16);
        let addr = spawn_mimic_udp(opts, &ca).await;
        let mut cfg = test_cfg(addr, "udp");
        cfg.ca = ca.cert_pem.clone();

        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);
        let mut stream = tokio::time::timeout(Duration::from_secs(20), connect(&cfg, &target))
            .await
            .expect("dial timeout")
            .expect("dial through the tunnel");
        let payload = vec![7u8; 512 * 1024];
        let outcome =
            tokio::time::timeout(Duration::from_secs(15), stream.write_all(&payload)).await;
        match outcome {
            Err(_elapsed) => panic!("writer hung on a reset connection (stall)"),
            // The write may complete into local queues before the RST
            // lands; then the failure must surface on the read side.
            Ok(Ok(())) => {
                let mut more = vec![0u8; 16];
                let read = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut more))
                    .await
                    .expect("read side must terminate after a reset");
                assert!(
                    matches!(read, Ok(0) | Err(_)),
                    "connection was reset: read must error or EOF, not data"
                );
            }
            Ok(Err(e)) => {
                assert!(
                    matches!(e.kind(), io::ErrorKind::BrokenPipe),
                    "writer must see BrokenPipe on reset, got {e:?}"
                );
            }
        }
    }

    /// REPRO (wave-13, mirrors wireguard.rs's wave-12A
    /// `endpoint_accepts_concurrent_dials_to_one_port`): several dials
    /// to one port through one tunnel — the browser shape. The mimic's
    /// single smoltcp listener is consumed by the first handshake, so a
    /// second SYN racing it while the listener is still mid-handshake
    /// (SynReceived — the mimic steps between datagrams, so the dials
    /// must be concurrent, not sequential) draws an RST ("dial failed
    /// (state Closed)") until the spare-listener re-arm.
    #[tokio::test]
    async fn tunnel_accepts_concurrent_dials_to_one_port() {
        let ca = test_ca();
        let addr = spawn_mimic_udp(MimicOpts::plain("udp"), &ca).await;
        let mut cfg = test_cfg(addr, "udp");
        cfg.ca = ca.cert_pem.clone();

        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);
        let mut dials = Vec::new();
        for _ in 0..4 {
            let cfg = cfg.clone();
            let target = target.clone();
            dials.push(tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(30), connect(&cfg, &target))
                    .await
                    .expect("concurrent dial must not be RST by a mid-handshake listener")
            }));
        }
        let mut streams = Vec::new();
        for dial in dials {
            streams.push(dial.await.unwrap().expect("dial through the tunnel"));
        }
        // Every stream echoes multi-segment bursts, interleaved.
        for round in 0..4u32 {
            for (i, stream) in streams.iter_mut().enumerate() {
                let chunk: Vec<u8> =
                    (0..8 * 1024).map(|k| (k as u32 + round + i as u32) as u8).collect();
                tokio::time::timeout(Duration::from_secs(30), stream.write_all(&chunk))
                    .await
                    .expect("concurrent stream write must not stall")
                    .unwrap();
                let mut back = vec![0u8; chunk.len()];
                tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut back))
                    .await
                    .expect("concurrent stream echo must not stall")
                    .unwrap();
                assert_eq!(back, chunk);
            }
        }
        for mut s in streams {
            let _ = s.shutdown().await;
        }
    }

    /// REPRO (wave-13, mirrors wireguard.rs's wave-12A
    /// `tcp_echo_slow_reader_closes_and_reopens_window`): a deliberately
    /// slow reader — 1 KiB reads with yields — forces the receive window
    /// to close and reopen (zero-window probing) while the write side
    /// keeps producing.
    #[tokio::test]
    async fn tcp_echo_slow_reader_closes_and_reopens_window() {
        let ca = test_ca();
        let addr = spawn_mimic_udp(MimicOpts::plain("udp"), &ca).await;
        let mut cfg = test_cfg(addr, "udp");
        cfg.ca = ca.cert_pem.clone();

        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);
        let stream = tokio::time::timeout(Duration::from_secs(20), connect(&cfg, &target))
            .await
            .expect("dial timeout")
            .expect("dial through the tunnel");

        const TOTAL: usize = 256 * 1024;
        let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 249) as u8).collect();

        let (mut r, mut w) = tokio::io::split(stream);
        let tx_payload = payload.clone();
        let writer = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(60), w.write_all(&tx_payload))
                .await
                .expect("write side must survive a zero-window peer")
                .unwrap();
        });
        let mut echoed = Vec::with_capacity(TOTAL);
        let mut chunk = vec![0u8; 1024];
        while echoed.len() < TOTAL {
            let n = tokio::time::timeout(Duration::from_secs(60), r.read(&mut chunk))
                .await
                .expect("slow reader must not stall behind a closed window")
                .unwrap();
            assert!(n > 0, "premature EOF at {}", echoed.len());
            echoed.extend_from_slice(&chunk[..n]);
            tokio::task::yield_now().await;
        }
        writer.await.unwrap();
        assert_eq!(echoed, payload);
    }

    /// GUARD (wave-13, mirrors wireguard.rs's wave-12A
    /// `zero_window_reopens_promptly_after_drain`): the zero-window
    /// stall-recovery shape. The reader drains in 16 KiB chunks with
    /// pauses, so the peer repeatedly hits our closed window; every
    /// drain must promptly re-open it — poll_read pings the tunnel task
    /// the moment queue space frees, instead of idling until the
    /// driver's 1s tick or the peer's next probe. Bound is generous
    /// (healthy: ~2s).
    #[tokio::test]
    async fn zero_window_reopens_promptly_after_drain() {
        let ca = test_ca();
        let addr = spawn_mimic_udp(MimicOpts::plain("udp"), &ca).await;
        let mut cfg = test_cfg(addr, "udp");
        cfg.ca = ca.cert_pem.clone();

        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);
        let stream = tokio::time::timeout(Duration::from_secs(20), connect(&cfg, &target))
            .await
            .expect("dial timeout")
            .expect("dial through the tunnel");

        const TOTAL: usize = 256 * 1024;
        let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();

        let (mut r, mut w) = tokio::io::split(stream);
        let tx_payload = payload.clone();
        let writer = tokio::spawn(async move {
            w.write_all(&tx_payload).await.unwrap();
        });
        let started = Instant::now();
        let mut echoed = Vec::with_capacity(TOTAL);
        let mut chunk = vec![0u8; 16 * 1024];
        while echoed.len() < TOTAL {
            let n = tokio::time::timeout(Duration::from_secs(10), r.read(&mut chunk))
                .await
                .expect("a drained window must re-open without the 1s tick")
                .unwrap();
            assert!(n > 0, "premature EOF at {}", echoed.len());
            echoed.extend_from_slice(&chunk[..n]);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let elapsed = started.elapsed();
        writer.await.unwrap();
        assert_eq!(echoed, payload);
        assert!(
            elapsed < Duration::from_secs(8),
            "window re-opening dragged: {elapsed:?} for 256 KiB — read drain not waking the tunnel task"
        );
    }

    #[tokio::test]
    async fn udp_associate_echo() {
        let ca = test_ca();
        let addr = spawn_mimic_udp(MimicOpts::plain("udp"), &ca).await;
        let mut cfg = test_cfg(addr, "udp");
        cfg.ca = ca.cert_pem.clone();
        let udp = tokio::time::timeout(Duration::from_secs(20), OvpnUdp::bind(&cfg))
            .await
            .expect("bind timeout")
            .expect("udp through the tunnel");
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_UDP_PORT);
        udp.send(&target, b"udp round trip").await.unwrap();
        let (from, data) = tokio::time::timeout(Duration::from_secs(20), udp.recv())
            .await
            .expect("echo timeout")
            .expect("echo datagram");
        assert_eq!(data, b"udp round trip");
        assert_eq!(from.to_string(), format!("{SERVER_TUNNEL_IP}:{ECHO_UDP_PORT}"));
        udp.send(&target, b"again").await.unwrap();
        let (_, data2) = tokio::time::timeout(Duration::from_secs(20), udp.recv())
            .await
            .expect("echo timeout 2")
            .expect("echo datagram 2");
        assert_eq!(data2, b"again");
    }

    async fn expect_handshake_failure(proto: &str, opts: MimicOpts, mut cfg: OpenVpnOut) {
        let ca = test_ca();
        let addr = if proto == "tcp" {
            spawn_mimic_tcp(opts, &ca).await
        } else {
            spawn_mimic_udp(opts, &ca).await
        };
        cfg.ca = ca.cert_pem.clone();
        let mut cfg = cfg;
        cfg.server = addr.ip().to_string();
        cfg.port = addr.port();
        cfg.proto = Some(proto.into());
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);
        let err = match tokio::time::timeout(Duration::from_secs(20), connect(&cfg, &target)).await
        {
            Ok(Ok(_)) => panic!("a wrong key must not connect"),
            Ok(Err(e)) => e,
            Err(_) => panic!("timeout"),
        };
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("timed out")
                || msg.contains("authentication")
                || msg.contains("tls")
                || msg.contains("failed")
                || msg.contains("connection refused")
                || msg.contains("eof")
                || msg.contains("closed"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn tls_auth_wrong_key_fails() {
        let mut opts = MimicOpts::plain("tcp");
        opts.tls_auth = Some(random_static_key());
        let mut cfg = test_cfg(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1)), "tcp");
        cfg.ca = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n".into();
        cfg.tls_auth = Some(static_key_pem(&random_static_key()));
        cfg.handshake_timeout = 4;
        expect_handshake_failure("tcp", opts, cfg).await;
    }

    #[tokio::test]
    async fn tls_crypt_wrong_key_fails() {
        let mut opts = MimicOpts::plain("udp");
        opts.tls_crypt = Some(random_static_key());
        let mut cfg = test_cfg(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1)), "udp");
        cfg.ca = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n".into();
        cfg.tls_crypt = Some(static_key_pem(&random_static_key()));
        cfg.handshake_timeout = 4;
        expect_handshake_failure("udp", opts, cfg).await;
    }

    #[tokio::test]
    async fn tls_crypt_v2_wrong_key_fails() {
        let mut wrapped = vec![0u8; 72];
        rand::rngs::OsRng.fill_bytes(&mut wrapped);
        let mut opts = MimicOpts::plain("tcp");
        opts.tls_crypt_v2 = Some((random_static_key(), wrapped.clone()));
        let mut cfg = test_cfg(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1)), "tcp");
        cfg.ca = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n".into();
        cfg.tls_crypt_v2 = Some(tls_crypt_v2_client_pem(&random_static_key(), &wrapped));
        cfg.handshake_timeout = 4;
        expect_handshake_failure("tcp", opts, cfg).await;
    }

    #[tokio::test]
    async fn auth_failed_is_surfaced() {
        let ca = test_ca();
        let mut opts = MimicOpts::plain("tcp");
        opts.auth_failed = true;
        let addr = spawn_mimic_tcp(opts, &ca).await;
        let mut cfg = test_cfg(addr, "tcp");
        cfg.ca = ca.cert_pem.clone();
        let target = NetAddr::ip(IpAddr::V4(SERVER_TUNNEL_IP), ECHO_TCP_PORT);
        let err = match tokio::time::timeout(Duration::from_secs(20), connect(&cfg, &target)).await
        {
            Ok(Ok(_)) => panic!("AUTH_FAILED must not connect"),
            Ok(Err(e)) => e,
            Err(_) => panic!("timeout"),
        };
        // The AUTH_FAILED is read either during the push wait (fast) or
        // surfaced by the post-handshake control scan; both carry the
        // upstream wording.
        let msg = err.to_string();
        assert!(
            msg.contains("authentication failed") || msg.contains("timed out"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn domain_targets_are_refused() {
        let mut cfg = test_cfg(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1)), "tcp");
        cfg.ca = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n".into();
        let err = match connect(&cfg, &NetAddr::domain("example.com", 443).unwrap()).await {
            Ok(_) => panic!("domain targets must be refused"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("resolve before dialing"));
    }
}
