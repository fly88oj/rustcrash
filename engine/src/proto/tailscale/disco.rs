//! The disco overlay: peer-to-peer path discovery messages.
//!
//! Port of `tailscale.com/disco` (disco/disco.go, cached at
//! `/tmp/wave13-upstream/disco_disco.go`, upstream `main` as of 2026-09)
//! plus the sealing of `types/key.DiscoPrivate.Shared`
//! (types/key/disco.go, cached `key_disco.go`).
//!
//! # The message framing (disco.go:6-19)
//!
//! A disco message rides the same UDP/DERP channel as WireGuard
//! datagrams and is told apart by its magic prefix:
//!
//! ```text
//! magic          [6]byte  // "TS💬" (0x54 53 f0 9f 92 ac)
//! senderDiscoPub [32]byte // the sender's disco public key
//! nonce          [24]byte
//! naclbox(payload)         // box.SealAfterPrecomputation: ct || MAC(16)
//! ```
//!
//! The inner payload (after the box opens) is:
//!
//! ```text
//! messageType     byte  // the MessageType constants
//! messageVersion  byte  // 0; receivers ignore trailing bytes
//! message-payload [...]byte
//! ```
//!
//! Only the three core messages are ported (the wave's bounded core):
//! **Ping** (0x01), **Pong** (0x02), **CallMeMaybe** (0x03). The
//! BindUDPRelayEndpoint / CallMeMaybeVia family (0x04-0x09, the
//! third-party UDP relay handshake) is out of scope; `parse` refuses
//! those types exactly like Go refuses unknown ones, so a relay-capable
//! peer's messages are dropped rather than misread.
//!
//! # Where the state machine lives
//!
//! magicsock's disco loop (handleDiscoMessage, the endpoint ping/pong
//! bookkeeping and CallMeMaybe handling) is ported as the bounded subset
//! inside [`super::wg`]'s tunnel — see that module's "Disco" section for
//! precisely what is simplified vs magicsock. This module is the pure
//! codec + seal/open every consumer shares.

use std::net::{IpAddr, SocketAddr};

use rand::RngCore;

use super::derp::{box_shared, poly1305, xsalsa20_xor};
use crate::error::{Error, Result};

/// `disco.Magic` (disco.go:35): `"TS💬"` — 6 bytes 0x54 53 f0 9f 92 ac.
pub const MAGIC: [u8; 6] = [0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac];

/// `keyLen` (disco.go:37).
pub const KEY_LEN: usize = 32;
/// `NonceLen` (disco.go:40): the nacl box nonce.
pub const NONCE_LEN: usize = 24;
/// `discoHeaderLen` (magicsock.go:2053): magic + sender disco public.
pub const DISCO_HEADER_LEN: usize = MAGIC.len() + KEY_LEN;
/// `MessageHeaderLen` (disco.go:119): type + version.
pub const MESSAGE_HEADER_LEN: usize = 2;
/// `v0` (disco.go:56).
const V0: u8 = 0;

// The MessageType constants (disco.go:44-54) — only the ported three.
const TYPE_PING: u8 = 0x01;
const TYPE_PONG: u8 = 0x02;
const TYPE_CALL_ME_MAYBE: u8 = 0x03;

/// `PingLen` (disco.go:152): TxID + optional NodeKey.
const PING_LEN: usize = 12 + KEY_LEN;
/// `pongLen` (disco.go:260): TxID + 16-byte IP + 2-byte port.
const PONG_LEN: usize = 12 + 16 + 2;
/// `epLength` (disco.go:219): 16-byte IP + 2-byte port per endpoint.
const EP_LENGTH: usize = 16 + 2;

/// `LooksLikeDiscoWrapper` (disco.go:62-67): does `p` carry the disco
/// magic (plus enough bytes for the fixed header)? magicsock's receive
/// path uses exactly this to split disco frames from WireGuard ones
/// (`packetLooksLike`, magicsock.go:2093-2141).
pub fn looks_like_disco(p: &[u8]) -> bool {
    if p.len() < DISCO_HEADER_LEN + NONCE_LEN {
        return false;
    }
    p.starts_with(&MAGIC)
}

/// `Source` (disco.go:72-77): the sender's disco public key out of the
/// wrapper header.
pub fn source(p: &[u8]) -> Option<[u8; 32]> {
    if !looks_like_disco(p) {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&p[MAGIC.len()..DISCO_HEADER_LEN]);
    Some(key)
}

// ---------------------------------------------------------------------------
// Keys (types/key/disco.go)
// ---------------------------------------------------------------------------

/// `key.DiscoPrivate` (disco.go:31-34): a clamped X25519 private key
/// (`NewDisco` clamps, disco.go:38-43 — "Key used for nacl seal/open, so
/// needs to be clamped"). One per overlay start, like magicsock.Conn's
/// (`RotateDiscoKey` on start, magicsock.go:1248); never persisted — a
/// restarted node simply speaks disco under a new key and peers relearn
/// the disco↔node relation from the netmap.
#[derive(Clone)]
pub struct DiscoPrivateKey([u8; 32]);

impl std::fmt::Debug for DiscoPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Secret half never printed (the NodePrivateKey precedent).
        f.write_str("DiscoPrivateKey([redacted])")
    }
}

impl DiscoPrivateKey {
    /// `key.NewDisco()` (disco.go:37-43): fresh random + clamp.
    pub fn generate() -> Self {
        let mut sk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        DiscoPrivateKey(sk)
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        DiscoPrivateKey(bytes)
    }

    /// `DiscoPrivate.Public` (disco.go:67-74).
    pub fn public(&self) -> DiscoPublicKey {
        DiscoPublicKey(
            curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(self.0).0,
        )
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `key.DiscoPublic` (disco.go:125-127): 32 raw bytes; the text form
/// (`"discokey:<64 hex>"`, disco.go:23) is [`super::tailcfg::DiscoKeyText`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoPublicKey(pub [u8; 32]);

impl DiscoPublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        DiscoPublicKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `DiscoPrivate.Shared` (disco.go:77-84): the nacl box precomputation
/// `box.Precompute(&ret, peer, sk)` = crypto_box_beforenm.
pub fn shared(sk: &DiscoPrivateKey, peer: &DiscoPublicKey) -> Result<[u8; 32]> {
    box_shared(sk.secret(), peer.as_bytes())
}

// ---------------------------------------------------------------------------
// The box: `DiscoShared.Seal` / `.Open` (disco.go:219-240)
// ---------------------------------------------------------------------------

/// `DiscoShared.Seal` (disco.go:219-226): a random nonce, then
/// `box.SealAfterPrecomputation` — the wire form is
/// `nonce(24) || ciphertext || MAC(16)` (the Go nacl box layout, NOT the
/// `nonce || MAC || ct` of `NodePrivate.SealTo` the DERP client info
/// uses — same primitive, different framing).
fn seal_shared(shared: &[u8; 32], cleartext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut ct = vec![0u8; cleartext.len()];
    let mac_key = xsalsa20_xor(shared, &nonce, cleartext, &mut ct);
    let tag = poly1305(&mac_key, &ct);
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len() + 16);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    out
}

/// `DiscoShared.Open` (disco.go:231-240): the constant-time counterpart.
fn open_shared(shared: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < NONCE_LEN + 16 {
        return None;
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[..NONCE_LEN]);
    let ct = &sealed[NONCE_LEN..sealed.len() - 16];
    let tag = &sealed[sealed.len() - 16..];
    let mut pt = vec![0u8; ct.len()];
    let mac_key = xsalsa20_xor(shared, &nonce, ct, &mut pt);
    let expect = poly1305(&mac_key, ct);
    let mut diff = 0u8;
    for (a, b) in tag.iter().zip(expect.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return None;
    }
    Some(pt)
}

/// Build a full disco wrapper to `peer`: the framing `sendDiscoMessage`
/// assembles (magicsock.go:1991-2001) — `Magic || our pub || box`.
pub fn seal(
    sk: &DiscoPrivateKey,
    peer: &DiscoPublicKey,
    msg: &DiscoMessage,
) -> Result<Vec<u8>> {
    let shared = shared(sk, peer)?;
    let mut out = Vec::with_capacity(DISCO_HEADER_LEN + NONCE_LEN + 16 + 64);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(sk.public().as_bytes());
    out.extend_from_slice(&seal_shared(&shared, &msg.marshal()));
    Ok(out)
}

/// Open a full disco wrapper addressed to our key: the receive half of
/// `handleDiscoMessage` (magicsock.go:2164-2253) — read the sender off
/// the header, precompute against it, open the box, parse the payload.
/// The MAC check IS the authentication (there is no second signature).
pub fn open(
    sk: &DiscoPrivateKey,
    wrapper: &[u8],
) -> Result<(DiscoPublicKey, DiscoMessage)> {
    let sender =
        source(wrapper).ok_or_else(|| Error::protocol("disco: not a disco wrapper"))?;
    let shared = shared(sk, &DiscoPublicKey::from_bytes(sender))?;
    let payload = open_shared(&shared, &wrapper[DISCO_HEADER_LEN..])
        .ok_or_else(|| Error::protocol("disco: nacl box authentication failed"))?;
    let msg = parse(&payload)?;
    Ok((DiscoPublicKey::from_bytes(sender), msg))
}

// ---------------------------------------------------------------------------
// The messages (disco.go:134-284)
// ---------------------------------------------------------------------------

/// A random per-ping transaction ID — `stun.NewTxID()` at the call site
/// (endpoint.go:1397; 12 bytes like a stun TxID, Ping.TxID's own type).
pub fn new_txid() -> [u8; 12] {
    let mut txid = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut txid);
    txid
}

/// The 16+2 wire form of an address (Pong.Src / CallMeMaybe.MyNumber):
/// Go writes `ipp.Addr().As16()` — an IPv4 address goes out as its
/// v4-mapped v6 form — and parses back with `AddrFrom16(...).Unmap()`
/// (disco.go:224-226, 277-283).
fn write_ep(out: &mut Vec<u8>, ap: &SocketAddr) {
    let sixteen = match ap.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    out.extend_from_slice(&sixteen);
    out.extend_from_slice(&ap.port().to_be_bytes());
}

/// The decode side of [`write_ep`] (`Unmap`).
fn read_ep(p: &[u8]) -> Option<SocketAddr> {
    if p.len() < EP_LENGTH {
        return None;
    }
    let mut sixteen = [0u8; 16];
    sixteen.copy_from_slice(&p[..16]);
    let port = u16::from_be_bytes([p[16], p[17]]);
    let mapped = std::net::Ipv6Addr::from(sixteen);
    let ip = match mapped.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(mapped),
    };
    Some(SocketAddr::new(ip, port))
}

/// The bounded message set: Ping, Pong, CallMeMaybe (see the module
/// docs for what the full upstream set adds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoMessage {
    /// `disco.Ping` (disco.go:134-148): probe a path; the receiver's
    /// Pong proves it viable.
    Ping(Ping),
    /// `disco.Pong` (disco.go:249-255): the reply; `src` is the
    /// receiver's view of the pinger — "effectively a STUN response".
    Pong(Pong),
    /// `disco.CallMeMaybe` (disco.go:191-217): sent only over DERP; the
    /// sender has already punched its firewall and lists the endpoints
    /// the receiver should ping back.
    CallMeMaybe(CallMeMaybe),
}

/// `disco.Ping`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ping {
    /// A random per-ping transaction ID.
    pub txid: [u8; 12],
    /// "allegedly the ping sender's wireguard public key" (post-1.16
    /// clients send it; `None` marshals as omitted — Go omits zero
    /// keys, disco.go:157-159).
    pub node_key: Option<[u8; 32]>,
    /// Trailing zero bytes (path-MTU probing; upstream sizes pings with
    /// it, this port always sends 0).
    pub padding: usize,
}

/// `disco.Pong`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pong {
    pub txid: [u8; 12],
    /// The pong sender's view of the pinger's source address.
    pub src: SocketAddr,
}

/// `disco.CallMeMaybe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallMeMaybe {
    /// `MyNumber`: "what the peer believes its endpoints are"
    /// (disco.go:201-217) — fresher than the netmap's Endpoints can be.
    pub my_number: Vec<SocketAddr>,
}

impl DiscoMessage {
    /// `AppendMarshal` of each type (disco.go:154-167, 221-230, 262-268):
    /// the two-byte header (`appendMsgHeader`) then the payload.
    pub fn marshal(&self) -> Vec<u8> {
        let mut out = match self {
            // PingLen sizes the no-padding ping (disco.go:152).
            DiscoMessage::Ping(p) => {
                Vec::with_capacity(MESSAGE_HEADER_LEN + PING_LEN + p.padding)
            }
            DiscoMessage::Pong(_) => Vec::with_capacity(MESSAGE_HEADER_LEN + PONG_LEN),
            DiscoMessage::CallMeMaybe(m) => {
                Vec::with_capacity(MESSAGE_HEADER_LEN + m.my_number.len() * EP_LENGTH)
            }
        };
        match self {
            DiscoMessage::Ping(p) => {
                out.push(TYPE_PING);
                out.push(V0);
                out.extend_from_slice(&p.txid);
                if let Some(nk) = &p.node_key {
                    out.extend_from_slice(nk);
                }
                // Padding: zero bytes at the end (disco.go:161).
                out.resize(out.len() + p.padding, 0);
            }
            DiscoMessage::Pong(p) => {
                out.push(TYPE_PONG);
                out.push(V0);
                out.extend_from_slice(&p.txid);
                write_ep(&mut out, &p.src);
            }
            DiscoMessage::CallMeMaybe(m) => {
                out.push(TYPE_CALL_ME_MAYBE);
                out.push(V0);
                for ep in &m.my_number {
                    write_ep(&mut out, ep);
                }
            }
        }
        out
    }

    /// A log summary, `MessageSummary`-shaped (disco.go:287-310).
    pub fn summary(&self) -> String {
        match self {
            DiscoMessage::Ping(p) => {
                let short: String = p.txid[..6].iter().map(|b| format!("{b:02x}")).collect();
                format!("ping tx={short} padding={}", p.padding)
            }
            DiscoMessage::Pong(p) => {
                let short: String = p.txid[..6].iter().map(|b| format!("{b:02x}")).collect();
                format!("pong tx={short}")
            }
            DiscoMessage::CallMeMaybe(m) => {
                format!("call-me-maybe ({} endpoints)", m.my_number.len())
            }
        }
    }
}

/// `Parse` (disco.go:81-109) over the inner payload. Unknown types
/// (including the UDP-relay family) error out — "unknown message type"
/// — exactly like Go; the caller drops the frame.
pub fn parse(payload: &[u8]) -> Result<DiscoMessage> {
    if payload.len() < MESSAGE_HEADER_LEN {
        return Err(Error::protocol("disco: short message"));
    }
    let t = payload[0];
    let ver = payload[1];
    let p = &payload[MESSAGE_HEADER_LEN..];
    match t {
        TYPE_PING => {
            if p.len() < 12 {
                return Err(Error::protocol("disco: short ping"));
            }
            let mut ping = Ping {
                txid: [0u8; 12],
                node_key: None,
                padding: p.len() - 12,
            };
            ping.txid.copy_from_slice(&p[..12]);
            let rest = &p[12..];
            // "Deliberately lax on longer-than-expected messages" — and
            // an all-zero trailing 32 bytes is padding, not a NodeKey
            // (disco.go:179-188).
            if rest.len() >= KEY_LEN && rest[..KEY_LEN] != [0u8; KEY_LEN] {
                let mut nk = [0u8; KEY_LEN];
                nk.copy_from_slice(&rest[..KEY_LEN]);
                ping.node_key = Some(nk);
                ping.padding -= KEY_LEN;
            }
            Ok(DiscoMessage::Ping(ping))
        }
        TYPE_PONG => {
            if p.len() < PONG_LEN {
                return Err(Error::protocol("disco: short pong"));
            }
            let mut pong = Pong {
                txid: [0u8; 12],
                src: SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    0,
                ),
            };
            pong.txid.copy_from_slice(&p[..12]);
            pong.src = read_ep(&p[12..]).ok_or_else(|| Error::protocol("disco: bad pong src"))?;
            Ok(DiscoMessage::Pong(pong))
        }
        TYPE_CALL_ME_MAYBE => {
            // parseCallMeMaybe (disco.go:232-247): ver != 0, an odd
            // length, or an EMPTY payload all yield an empty message
            // (not an error — future-compat).
            let mut m = CallMeMaybe {
                my_number: Vec::new(),
            };
            if ver == V0 && !p.is_empty() && p.len().is_multiple_of(EP_LENGTH) {
                for chunk in p.as_chunks::<EP_LENGTH>().0 {
                    if let Some(ep) = read_ep(chunk) {
                        m.my_number.push(ep);
                    }
                }
            }
            Ok(DiscoMessage::CallMeMaybe(m))
        }
        other => Err(Error::protocol(format!(
            "disco: unknown message type 0x{other:02x}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical vectors derived in-test from generated keys — never a
    /// literal secret (repo rule; disco keys are ephemeral anyway).
    #[test]
    fn magic_and_wrapper_detection_match_the_go_layout() {
        assert_eq!(MAGIC.len(), 6, "TS💬 is six bytes");
        assert_eq!(&MAGIC[..2], b"TS");
        // LooksLikeDiscoWrapper: magic + a minimum of key+nonce bytes.
        let mut pkt = vec![0u8; DISCO_HEADER_LEN + NONCE_LEN - 1];
        assert!(!looks_like_disco(&pkt));
        pkt.resize(DISCO_HEADER_LEN + NONCE_LEN, 0);
        pkt[..MAGIC.len()].copy_from_slice(&MAGIC);
        assert!(looks_like_disco(&pkt));
        // Source reads bytes 6..38.
        pkt[MAGIC.len()..DISCO_HEADER_LEN].copy_from_slice(&[7u8; 32]);
        assert_eq!(source(&pkt), Some([7u8; 32]));
        assert_eq!(source(b"not disco at all"), None);
        // A WireGuard transport message never trips the detector: type
        // 4 LE has a zero second byte, and 0x54 != 0x04.
        let wg = [4u8, 0, 0, 0, 1, 2, 3, 4];
        assert!(!looks_like_disco(&wg));
    }

    #[test]
    fn ping_marshal_parse_round_trip_like_go() {
        // With a node key: header(2) + txid(12) + key(32) = 46.
        let ping = Ping {
            txid: new_txid(),
            node_key: Some(*DiscoPrivateKey::generate().public().as_bytes()),
            padding: 0,
        };
        let wire = DiscoMessage::Ping(ping.clone()).marshal();
        assert_eq!(wire.len(), MESSAGE_HEADER_LEN + PING_LEN);
        assert_eq!(&wire[..2], &[TYPE_PING, V0]);
        assert_eq!(&wire[2..14], &ping.txid[..]);
        assert_eq!(parse(&wire).unwrap(), DiscoMessage::Ping(ping.clone()));

        // Without a node key (old clients): 14 bytes, None on parse.
        let bare = Ping {
            txid: new_txid(),
            node_key: None,
            padding: 0,
        };
        let wire = DiscoMessage::Ping(bare.clone()).marshal();
        assert_eq!(wire.len(), 14);
        assert_eq!(parse(&wire).unwrap(), DiscoMessage::Ping(bare));

        // Padding: trailing zeros counted on parse (MTU probing shape).
        let padded = Ping {
            txid: new_txid(),
            node_key: None,
            padding: 32,
        };
        let wire = DiscoMessage::Ping(padded.clone()).marshal();
        assert_eq!(wire.len(), 14 + 32);
        assert_eq!(parse(&wire).unwrap(), DiscoMessage::Ping(padded));

        // Lax parse: an all-zero 32-byte trailer is padding, not a key.
        let mut extended = DiscoMessage::Ping(Ping {
            txid: new_txid(),
            node_key: None,
            padding: 0,
        })
        .marshal();
        extended.extend_from_slice(&[0u8; 32]);
        match parse(&extended).unwrap() {
            DiscoMessage::Ping(p) => {
                assert!(p.node_key.is_none(), "zero key is padding");
                assert_eq!(p.padding, 32);
            }
            other => panic!("wrong message: {other:?}"),
        }
    }

    #[test]
    fn pong_and_call_me_maybe_wire_forms() {
        // Pong: txid + src; a v4 src goes out v4-mapped (As16) and comes
        // back unmapped (Unmap) — disco.go:262-284.
        let pong = Pong {
            txid: new_txid(),
            src: "203.0.113.9:41641".parse().unwrap(),
        };
        let wire = DiscoMessage::Pong(pong.clone()).marshal();
        assert_eq!(wire.len(), MESSAGE_HEADER_LEN + PONG_LEN);
        // Bytes 14..16 of the IP are 0xff 0xff for a mapped v4.
        assert_eq!(&wire[14 + 10..14 + 12], &[0xff, 0xff]);
        assert_eq!(&wire[14 + 12..14 + 16], &[203, 0, 113, 9]);
        assert_eq!(&wire[30..32], &41641u16.to_be_bytes());
        assert_eq!(parse(&wire).unwrap(), DiscoMessage::Pong(pong));

        // A v6 src round-trips unmapped.
        let pong6 = Pong {
            txid: new_txid(),
            src: "[fd7a:115c:a1e0::1]:1234".parse().unwrap(),
        };
        let wire = DiscoMessage::Pong(pong6.clone()).marshal();
        assert_eq!(parse(&wire).unwrap(), DiscoMessage::Pong(pong6));
        // Short is refused.
        assert!(parse(&[TYPE_PONG, V0, 1, 2]).is_err());

        // CallMeMaybe: n * 18-byte endpoints.
        let cmm = CallMeMaybe {
            my_number: vec![
                "203.0.113.9:41641".parse().unwrap(),
                "[2001:db8::2]:59".parse().unwrap(),
            ],
        };
        let wire = DiscoMessage::CallMeMaybe(cmm.clone()).marshal();
        assert_eq!(wire.len(), MESSAGE_HEADER_LEN + 2 * EP_LENGTH);
        assert_eq!(parse(&wire).unwrap(), DiscoMessage::CallMeMaybe(cmm));
        // Empty and malformed payloads parse as an EMPTY message (Go's
        // lenient branch, disco.go:234-236).
        assert_eq!(
            parse(&[TYPE_CALL_ME_MAYBE, V0]).unwrap(),
            DiscoMessage::CallMeMaybe(CallMeMaybe { my_number: vec![] })
        );
        let mut odd = vec![TYPE_CALL_ME_MAYBE, V0];
        odd.extend_from_slice(&[0u8; 5]);
        assert_eq!(
            parse(&odd).unwrap(),
            DiscoMessage::CallMeMaybe(CallMeMaybe { my_number: vec![] })
        );
        // Unknown types (the UDP-relay family 0x04+) are refused.
        assert!(parse(&[0x04, V0, 0, 0]).is_err());
        assert!(parse(&[0x07, V0, 0, 0]).is_err());
        assert!(parse(&[0x99, V0, 0, 0]).is_err());
        assert!(parse(&[TYPE_PING]).is_err(), "header alone is short");
    }

    #[test]
    fn seal_open_between_two_disco_keys() {
        // The full wrapper: magic || sender pub || nonce || ct || MAC.
        let alice = DiscoPrivateKey::generate();
        let bob = DiscoPrivateKey::generate();
        let msg = DiscoMessage::Ping(Ping {
            txid: new_txid(),
            node_key: Some(*bob.public().as_bytes()),
            padding: 0,
        });
        let wrapper = seal(&alice, &bob.public(), &msg).unwrap();
        assert!(looks_like_disco(&wrapper));
        assert_eq!(source(&wrapper), Some(*alice.public().as_bytes()));
        assert_eq!(wrapper.len(), DISCO_HEADER_LEN + NONCE_LEN + msg.marshal().len() + 16);

        // Bob opens it and sees Alice as the sender.
        let (sender, got) = open(&bob, &wrapper).unwrap();
        assert_eq!(sender, alice.public());
        assert_eq!(got, msg);

        // The reverse direction shares the same precomputation.
        let reply = DiscoMessage::Pong(Pong {
            txid: [9u8; 12],
            src: "192.0.2.1:1".parse().unwrap(),
        });
        let back = seal(&bob, &alice.public(), &reply).unwrap();
        let (sender2, got2) = open(&alice, &back).unwrap();
        assert_eq!(sender2, bob.public());
        assert_eq!(got2, reply);

        // A third key cannot open it (the box IS the authentication).
        let mallory = DiscoPrivateKey::generate();
        assert!(open(&mallory, &wrapper).is_err());
        // Tampering with the payload or the tag fails the MAC.
        let mut tampered = wrapper.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(open(&bob, &tampered).is_err());
        let mut garbage = vec![0u8; DISCO_HEADER_LEN + NONCE_LEN + 16];
        garbage[..MAGIC.len()].copy_from_slice(&MAGIC);
        garbage[MAGIC.len()..DISCO_HEADER_LEN]
            .copy_from_slice(alice.public().as_bytes());
        assert!(open(&bob, &garbage).is_err());
        // Wrong-key plaintext is not parseable even if the box somehow
        // were (the parse layer refuses nonsense payloads).
        assert!(parse(&[0u8; 3]).is_err());
    }

    #[test]
    fn summaries_are_go_shaped() {
        // MessageSummary (disco.go:287-310): "ping tx=... padding=...",
        // "pong tx=...", "call-me-maybe".
        let m = DiscoMessage::Ping(Ping {
            txid: [0xab; 12],
            node_key: None,
            padding: 7,
        });
        assert_eq!(m.summary(), "ping tx=abababababab padding=7");
        let m = DiscoMessage::Pong(Pong {
            txid: [0xcd; 12],
            src: "192.0.2.1:1".parse().unwrap(),
        });
        assert_eq!(m.summary(), "pong tx=cdcdcdcdcdcd");
        let m = DiscoMessage::CallMeMaybe(CallMeMaybe { my_number: vec![] });
        assert_eq!(m.summary(), "call-me-maybe (0 endpoints)");
    }
}
