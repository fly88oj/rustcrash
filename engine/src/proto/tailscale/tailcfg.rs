//! `tailcfg`: the control-server protocol messages — JSON, not protobuf.
//!
//! Port of the message shapes of `tailscale.com/tailcfg` (tailcfg.go +
//! derpmap.go; cached at `/tmp/wave11-upstream/tailcfg_*.go`, upstream
//! `main` as of 2026-09).
//!
//! # The wire encoding is JSON
//!
//! Despite the `proto`-flavored package name, every tailcfg message is
//! `encoding/json`: the RegisterRequest body is `json.Marshal`ed
//! (control/controlclient/direct.go:1522-1533 `encode`), the response is
//! `json.Unmarshal`ed (direct.go:1438-1448 `decode`), and the map poll
//! body is a stream of little-endian-u32-length-prefixed JSON messages
//! (direct.go:1467-1485 `readMapResponseMessage`, direct.go:1487-1519
//! `decodeMsg`). The JSON field names are Go's struct field names unless
//! a tag renames them (e.g. `Node.LegacyDERPString` is `"DERP"`).
//!
//! # Keys on the wire
//!
//! `key.NodePublic`/`MachinePublic`/`DiscoPublic` implement
//! `MarshalText` with fixed prefixes — `nodekey:`, `mkey:`, `discokey:`,
//! and private keys `privkey:` (types/key/node.go:29-37,
//! types/key/machine.go:24-31, types/key/disco.go:18-23) — and
//! encoding/json uses `MarshalText` for struct fields, so a Node's key
//! appears as `"nodekey:<64 hex>"`. [`NodeKey`]/[`MachineKeyText`] are
//! typed wrappers that enforce exactly that form.
//!
//! # Scope
//!
//! Only the fields this port sends or consumes are carried; everything
//! else is ignored on decode (serde `default`) and omitted on encode,
//! which is forward-compatible the same way Go's `omitempty` is.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use super::derp::{NodePrivateKey, NodePublicKey};
use super::noise::MachinePublicKey;

/// `CurrentCapabilityVersion` (tailcfg/tailcfg.go:200) — the value the
/// ts2021 client negotiates; kept in lockstep with
/// [`super::noise::CURRENT_PROTOCOL_VERSION`].
pub const CURRENT_CAPABILITY_VERSION: u32 = 148;

// ---------------------------------------------------------------------------
// Typed key wrappers (MarshalText parity)
// ---------------------------------------------------------------------------

fn parse_key_text(s: &str, prefix: &str) -> Option<[u8; 32]> {
    let hex = s.strip_prefix(prefix)?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        *byte = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

fn key_text(prefix: &str, key: &[u8; 32]) -> String {
    let mut s = String::with_capacity(prefix.len() + 64);
    s.push_str(prefix);
    for b in key {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `key.NodePublic` on the wire: `"nodekey:<64 hex>"` (node.go:36).
/// The default is Go's zero key (all-zero bytes, marshals as
/// `"nodekey:000..."`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NodeKey(pub [u8; 32]);

impl NodeKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_node_public_key(&self) -> NodePublicKey {
        NodePublicKey::from_bytes(self.0)
    }
}

impl Serialize for NodeKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&key_text("nodekey:", &self.0))
    }
}

impl<'de> Deserialize<'de> for NodeKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse_key_text(&s, "nodekey:")
            .map(NodeKey)
            .ok_or_else(|| serde::de::Error::custom(format!("bad nodekey: {s:?}")))
    }
}

/// `key.MachinePublic` on the wire: `"mkey:<64 hex>"` (machine.go:29-31).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MachineKeyText(pub [u8; 32]);

impl MachineKeyText {
    pub fn to_machine_public_key(&self) -> MachinePublicKey {
        MachinePublicKey::from_bytes(self.0)
    }
}

impl Serialize for MachineKeyText {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&key_text("mkey:", &self.0))
    }
}

impl<'de> Deserialize<'de> for MachineKeyText {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse_key_text(&s, "mkey:")
            .map(MachineKeyText)
            .ok_or_else(|| serde::de::Error::custom(format!("bad mkey: {s:?}")))
    }
}

/// `key.NodePrivate`'s text form: `"privkey:<64 hex>"` (node.go:29) —
/// used by the state store, never on the control wire.
pub fn node_private_text(k: &NodePrivateKey) -> String {
    key_text("privkey:", k.secret())
}

/// Parse a `privkey:` node private key text form.
pub fn node_private_from_text(s: &str) -> Option<NodePrivateKey> {
    let raw = parse_key_text(s, "privkey:")?;
    Some(NodePrivateKey::from_bytes(raw))
}

/// `discokey:` — `key.DiscoPublic`'s text form (disco.go:23): the wire
/// form of [`Node.DiscoKey`](Node::disco_key) in the map and of
/// [`MapRequest::disco_key`] (see [`super::disco`] for the data plane
/// that consumes it).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DiscoKeyText(pub [u8; 32]);

impl Serialize for DiscoKeyText {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&key_text("discokey:", &self.0))
    }
}

impl<'de> Deserialize<'de> for DiscoKeyText {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse_key_text(&s, "discokey:")
            .map(DiscoKeyText)
            .ok_or_else(|| serde::de::Error::custom(format!("bad discokey: {s:?}")))
    }
}

// ---------------------------------------------------------------------------
// netip.Prefix / netip.AddrPort as JSON (Go marshals both as strings)
// ---------------------------------------------------------------------------

/// `netip.Prefix` — `"100.64.0.1/32"` (bits required for v4; v6 allows
/// 0..=128). Go's `MarshalText` always prints the bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub addr: IpAddr,
    pub bits: u8,
}

impl Prefix {
    pub fn new(addr: IpAddr, bits: u8) -> Self {
        Prefix { addr, bits }
    }

    /// Longest-prefix match (cryptokey routing).
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                if self.bits > 32 {
                    return false;
                }
                let mask = if self.bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.bits as u32)
                };
                u32::from(net) & mask == u32::from(*ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                if self.bits > 128 {
                    return false;
                }
                let net = u128::from_be_bytes(net.octets());
                let ip = u128::from_be_bytes(ip.octets());
                let mask = if self.bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.bits as u32)
                };
                net & mask == ip & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

impl Serialize for Prefix {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let (addr, bits) = s
            .split_once('/')
            .ok_or_else(|| serde::de::Error::custom(format!("bad prefix: {s:?}")))?;
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| serde::de::Error::custom(format!("bad prefix addr: {s:?}")))?;
        let bits: u8 = bits
            .parse()
            .map_err(|_| serde::de::Error::custom(format!("bad prefix bits: {s:?}")))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(serde::de::Error::custom(format!("prefix bits too large: {s:?}")));
        }
        Ok(Prefix { addr, bits })
    }
}

/// `netip.AddrPort` — `"127.0.0.1:1234"` / `"[::1]:1234"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrPort(pub SocketAddr);

impl Serialize for AddrPort {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for AddrPort {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let sa: SocketAddr = s
            .parse()
            .map_err(|_| serde::de::Error::custom(format!("bad addr:port: {s:?}")))?;
        Ok(AddrPort(sa))
    }
}

// ---------------------------------------------------------------------------
// Hostinfo (tailcfg.go:890-987) — the fields a node sets about itself
// ---------------------------------------------------------------------------

/// The subset of `tailcfg.Hostinfo` this client sends. `BackendLogID`
/// must be non-empty or control registration refuses the request
/// (direct.go:755-757 "hostinfo: BackendLogID missing").
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hostinfo {
    #[serde(rename = "IPNVersion", default, skip_serializing_if = "String::is_empty")]
    pub ipn_version: String,
    #[serde(rename = "BackendLogID", default, skip_serializing_if = "String::is_empty")]
    pub backend_log_id: String,
    #[serde(rename = "OS", default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(rename = "OSVersion", default, skip_serializing_if = "String::is_empty")]
    pub os_version: String,
    /// "App is used to disambiguate Tailscale clients that run using
    /// tsnet" (tailcfg.go:925) — exactly this port's case.
    #[serde(rename = "App", default, skip_serializing_if = "String::is_empty")]
    pub app: String,
    #[serde(rename = "Hostname", default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    /// Userspace (netstack) mode — always true for this port.
    #[serde(rename = "Userspace", default, skip_serializing_if = "Option::is_none")]
    pub userspace: Option<bool>,
    #[serde(rename = "UserspaceRouter", default, skip_serializing_if = "Option::is_none")]
    pub userspace_router: Option<bool>,
}

// ---------------------------------------------------------------------------
// Registration (tailcfg.go:1304-1386)
// ---------------------------------------------------------------------------

/// `tailcfg.RegisterResponseAuth` (tailcfg.go:1304-1312): the auth-key
/// branch of the register request.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterResponseAuth {
    #[serde(rename = "Oauth2Token", default, skip_serializing_if = "Option::is_none")]
    pub oauth2_token: Option<serde_json::Value>,
    #[serde(rename = "AuthKey", default, skip_serializing_if = "String::is_empty")]
    pub auth_key: String,
}

/// `tailcfg.RegisterRequest` (tailcfg.go:1318-1369) — "JSON-encoded and
/// sent over the control plane connection to /machine/register".
/// Timestamp/DeviceCert/Signature (Windows attestation) are not ported.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterRequest {
    /// The client's capability version (must be `CurrentCapabilityVersion`
    /// on the noise transport, direct.go:804).
    #[serde(rename = "Version", default)]
    pub version: u32,
    #[serde(rename = "NodeKey", default)]
    pub node_key: NodeKey,
    #[serde(rename = "OldNodeKey", default)]
    pub old_node_key: NodeKey,
    /// The network-lock key this port never provisions; sent as the zero
    /// key (wire presence required).
    #[serde(rename = "NLKey", default)]
    pub nl_key: DiscoKeyText,
    #[serde(rename = "Auth", default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<RegisterResponseAuth>,
    /// RFC3339 like Go's `time.Time`; pass-through (we never request an
    /// expiry).
    #[serde(rename = "Expiry", default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    #[serde(rename = "Followup", default, skip_serializing_if = "String::is_empty")]
    pub followup: String,
    #[serde(rename = "Hostinfo", default, skip_serializing_if = "Option::is_none")]
    pub hostinfo: Option<Hostinfo>,
    #[serde(rename = "Ephemeral", default, skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
    #[serde(rename = "Tailnet", default, skip_serializing_if = "String::is_empty")]
    pub tailnet: String,
}

impl RegisterRequest {
    /// The zero-value old node key (a real `key.NodePublic` zero — Go's
    /// zero marshals as `"nodekey:0000..."`).
    pub fn zero_node_key() -> NodeKey {
        NodeKey([0u8; 32])
    }
}

/// `tailcfg.RegisterResponse` (tailcfg.go:1372-1386).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterResponse {
    #[serde(rename = "User", default)]
    pub user: serde_json::Value,
    #[serde(rename = "Login", default)]
    pub login: serde_json::Value,
    /// "if true, the NodeKey needs to be replaced".
    #[serde(rename = "NodeKeyExpired", default)]
    pub node_key_expired: bool,
    #[serde(rename = "MachineAuthorized", default)]
    pub machine_authorized: bool,
    /// "if set, authorization pending" — the interactive-login branch.
    #[serde(rename = "AuthURL", default, skip_serializing_if = "String::is_empty")]
    pub auth_url: String,
    /// "indicates that authorization failed. If this is non-empty, other
    /// status fields should be ignored" (tailcfg.go:1383-1385).
    #[serde(rename = "Error", default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// `tailcfg.OverTLSPublicKeyResponse` (tailcfg.go:2967-2987) — the JSON
/// answer of `GET /key?v=<capver>` over regular HTTPS (NOT noise; the
/// struct doc says so loudly). Field names from the json tags.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OverTlsPublicKeyResponse {
    #[serde(rename = "legacyPublicKey", default)]
    pub legacy_public_key: Option<MachineKeyText>,
    #[serde(rename = "publicKey", default)]
    pub public_key: Option<MachineKeyText>,
}

// ---------------------------------------------------------------------------
// Node / profiles (tailcfg.go:307-330, 370-...)
// ---------------------------------------------------------------------------

/// `tailcfg.UserProfile` (tailcfg.go:307-325).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserProfile {
    #[serde(rename = "ID", default)]
    pub id: i64,
    #[serde(rename = "LoginName", default)]
    pub login_name: String,
    #[serde(rename = "DisplayName", default)]
    pub display_name: String,
    #[serde(rename = "ProfilePicURL", default, skip_serializing_if = "String::is_empty")]
    pub profile_pic_url: String,
}

/// `tailcfg.Node` (tailcfg.go:370-605) — the fields the data plane reads
/// (identity, addresses, allowed IPs, endpoints, DERP home, expiry).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node {
    #[serde(rename = "ID", default)]
    pub id: i64,
    #[serde(rename = "StableID", default)]
    pub stable_id: String,
    /// FQDN with trailing dot (the MagicDNS name).
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "User", default)]
    pub user: i64,
    #[serde(rename = "Key", default)]
    pub key: NodeKey,
    /// RFC3339 pass-through; "zero value if this node does not expire".
    #[serde(rename = "KeyExpiry", default, skip_serializing_if = "Option::is_none")]
    pub key_expiry: Option<String>,
    #[serde(rename = "Machine", default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<MachineKeyText>,
    #[serde(rename = "DiscoKey", default, skip_serializing_if = "Option::is_none")]
    pub disco_key: Option<DiscoKeyText>,
    /// The node's tailnet IPs.
    #[serde(rename = "Addresses", default)]
    pub addresses: Vec<Prefix>,
    /// "IP ranges to route to this node" — the cryptokey-routing table.
    #[serde(rename = "AllowedIPs", default)]
    pub allowed_ips: Vec<Prefix>,
    /// "IP+port (public via STUN, and local LANs)" — direct UDP paths.
    #[serde(rename = "Endpoints", default)]
    pub endpoints: Vec<AddrPort>,
    /// `DERP` — the deprecated DERP-in-IP:port form
    /// ("127.3.3.40:<region>", tailcfg.go:421-431), canonicalized to
    /// [`Node::home_derp`] by the map session (map.go upgradeNode).
    #[serde(rename = "DERP", default, skip_serializing_if = "String::is_empty")]
    pub legacy_derp_string: String,
    /// "DERP region ID of the node's home DERP" (tailcfg.go:433-438).
    #[serde(rename = "HomeDERP", default)]
    pub home_derp: i64,
    #[serde(rename = "Created", default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// "if non-zero, the node's capability version".
    #[serde(rename = "Cap", default)]
    pub cap: u32,
    #[serde(rename = "MachineAuthorized", default)]
    pub machine_authorized: bool,
    /// RFC3339; None = unknown.
    #[serde(rename = "LastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// None = unknown online state.
    #[serde(rename = "Online", default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    /// "whether this node's key has expired".
    #[serde(rename = "Expired", default)]
    pub expired: bool,
    /// Non-Tailscale WireGuard peer — no disco, no DERP, must have
    /// endpoints (tailcfg.go:565-568).
    #[serde(rename = "IsWireGuardOnly", default)]
    pub is_wire_guard_only: bool,
}

// ---------------------------------------------------------------------------
// DERP map (tailcfg/derpmap.go:19-262)
// ---------------------------------------------------------------------------

/// `tailcfg.DERPNode` (derpmap.go:187-262) — the fields needed to dial.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerpNode {
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "RegionID", default)]
    pub region_id: i64,
    #[serde(rename = "HostName", default)]
    pub host_name: String,
    #[serde(rename = "CertName", default, skip_serializing_if = "String::is_empty")]
    pub cert_name: String,
    /// Forces an IPv4 dial target instead of DNS.
    #[serde(rename = "IPv4", default, skip_serializing_if = "String::is_empty")]
    pub ipv4: String,
    #[serde(rename = "IPv6", default, skip_serializing_if = "String::is_empty")]
    pub ipv6: String,
    /// Zero = 443.
    #[serde(rename = "DERPPort", default)]
    pub derp_port: u16,
    #[serde(rename = "STUNOnly", default)]
    pub stun_only: bool,
    #[serde(rename = "InsecureForTests", default)]
    pub insecure_for_tests: bool,
}

/// `tailcfg.DERPRegion` (derpmap.go:117-170).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerpRegion {
    #[serde(rename = "RegionID", default)]
    pub region_id: i64,
    #[serde(rename = "RegionCode", default)]
    pub region_code: String,
    #[serde(rename = "RegionName", default)]
    pub region_name: String,
    /// The nodes of the region; embedded (Go `Nodes []*DERPNode`, JSON
    /// "Nodes").
    #[serde(rename = "Nodes", default)]
    pub nodes: Vec<DerpNode>,
    /// "whether the client should avoid picking this as its home region".
    #[serde(rename = "Avoid", default)]
    pub avoid: bool,
}

/// `tailcfg.DERPMap` (derpmap.go:19-45) — "the set of geographic regions
/// running DERP node(s)", keyed by region ID.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerpMap {
    #[serde(rename = "Regions", default)]
    pub regions: BTreeMap<i64, DerpRegion>,
    /// "specifies to not use Tailscale's DERP servers".
    #[serde(rename = "omitDefaultRegions", default)]
    pub omit_default_regions: bool,
}

impl DerpMap {
    /// Resolve a region to a dialable URL: the first non-STUN-only node,
    /// honoring `IPv4` overrides and `DERPPort` (derphttp's
    /// `node.RegionalRelayURL`-equivalent: `https://host[:port]`).
    pub fn region_url(&self, region_id: i64) -> Option<String> {
        let region = self.regions.get(&region_id)?;
        for node in &region.nodes {
            if node.stun_only || node.host_name.is_empty() {
                continue;
            }
            let host = if !node.ipv4.is_empty() && node.ipv4 != "none" {
                node.ipv4.clone()
            } else {
                node.host_name.clone()
            };
            let scheme = if node.insecure_for_tests { "http" } else { "https" };
            return Some(match node.derp_port {
                0 | 443 => format!("{scheme}://{host}"),
                port => format!("{scheme}://{host}:{port}"),
            });
        }
        None
    }
}

// ---------------------------------------------------------------------------
// MapRequest / MapResponse (tailcfg.go:1436-1530, 2006-2200)
// ---------------------------------------------------------------------------

/// `tailcfg.MapRequest` (tailcfg.go:1436-1530) — the fields this client
/// sets (mirroring direct.go's sendMapRequest fill, 1083-1094).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MapRequest {
    #[serde(rename = "Version", default)]
    pub version: u32,
    /// `""` (no compression) — see the module delta note in `super`.
    #[serde(rename = "Compress", default, skip_serializing_if = "String::is_empty")]
    pub compress: String,
    /// "whether server should send keep-alives back to us".
    #[serde(rename = "KeepAlive", default)]
    pub keep_alive: bool,
    #[serde(rename = "NodeKey", default)]
    pub node_key: NodeKey,
    /// Our disco public key — how peers learn which disco key speaks
    /// for this node (wave 13; the zero key when disco is not in play).
    #[serde(rename = "DiscoKey", default)]
    pub disco_key: DiscoKeyText,
    /// "whether the client wants to receive multiple MapResponses over
    /// the same HTTP connection" — the long-poll.
    #[serde(rename = "Stream", default)]
    pub stream: bool,
    #[serde(rename = "Hostinfo", default, skip_serializing_if = "Option::is_none")]
    pub hostinfo: Option<Hostinfo>,
    #[serde(rename = "Endpoints", default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<AddrPort>,
    /// "whether the client is okay with the Peers list being omitted".
    #[serde(rename = "OmitPeers", default)]
    pub omit_peers: bool,
}

/// `tailcfg.PeerChange` (tailcfg.go:3031-3097) — the delta patch shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerChange {
    #[serde(rename = "NodeID", default)]
    pub node_id: i64,
    /// "if non-zero, means that NodeID's home DERP region ID is now this
    /// number".
    #[serde(rename = "DERPRegion", default)]
    pub derp_region: i64,
    /// "if non-empty, means that NodeID's UDP Endpoints have changed".
    #[serde(rename = "Endpoints", default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<AddrPort>,
    /// "if non-nil, means that the NodeID's wireguard public key changed".
    #[serde(rename = "Key", default, skip_serializing_if = "Option::is_none")]
    pub key: Option<NodeKey>,
    /// "if non-nil, means that the NodeID's online status changed".
    #[serde(rename = "Online", default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    #[serde(rename = "LastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// "if non-nil, changes the NodeID's key expiry".
    #[serde(rename = "KeyExpiry", default, skip_serializing_if = "Option::is_none")]
    pub key_expiry: Option<String>,
}

/// `tailcfg.DNSConfig` (tailcfg.go:1787-1853) — "the DNS configuration".
/// Only the fields MagicDNS resolution consumes are carried (see the
/// module scope note): `Domains` ("the search domains to use. Search
/// domains must be FQDNs, but *without* the trailing dot", tailcfg.go:
/// 1810-1811) and `Proxied` ("turns on automatic resolution of hostnames
/// for devices in the network map, aka MagicDNS", tailcfg.go:1812-1815).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsConfig {
    /// Search domains, FQDNs WITHOUT the trailing dot.
    #[serde(rename = "Domains", default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    /// MagicDNS on/off.
    #[serde(rename = "Proxied", default)]
    pub proxied: bool,
}

/// `tailcfg.MapResponse` (tailcfg.go:2006-2200) — the fields the session
/// applies; everything else ignored on decode.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MapResponse {
    /// "an empty message just to keep the connection alive. When true,
    /// all other fields except PingRequest, ControlTime, and
    /// PopBrowserURL are ignored" (tailcfg.go:2020-2022).
    #[serde(rename = "KeepAlive", default)]
    pub keep_alive: bool,
    /// "a URL for the client to open to complete an action".
    #[serde(rename = "PopBrowserURL", default, skip_serializing_if = "String::is_empty")]
    pub pop_browser_url: String,
    /// "describes the node making the map request" (self).
    #[serde(rename = "Node", default, skip_serializing_if = "Option::is_none")]
    pub node: Option<Node>,
    /// "describe the set of DERP servers available" (nil = unchanged).
    #[serde(rename = "DERPMap", default, skip_serializing_if = "Option::is_none")]
    pub derp_map: Option<DerpMap>,
    /// "the complete list of peers ... precludes all other delta
    /// operations" (map.go:558-570).
    #[serde(rename = "Peers", default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<Node>,
    /// "the Nodes ... that have changed or been added since the past
    /// update" (map.go:584-591).
    #[serde(rename = "PeersChanged", default, skip_serializing_if = "Vec::is_empty")]
    pub peers_changed: Vec<Node>,
    /// "the NodeIDs that are no longer in the peer list".
    #[serde(rename = "PeersRemoved", default, skip_serializing_if = "Vec::is_empty")]
    pub peers_removed: Vec<i64>,
    /// "a lighter version of the older PeersChanged support" (patches).
    #[serde(rename = "PeersChangedPatch", default, skip_serializing_if = "Vec::is_empty")]
    pub peers_changed_patch: Vec<PeerChange>,
    /// "how to update peers' LastSeen times ... If the value is false,
    /// the peer is gone".
    #[serde(rename = "PeerSeenChange", default, skip_serializing_if = "Option::is_none")]
    pub peer_seen_change: Option<BTreeMap<i64, bool>>,
    /// "changes the value of a Peer Node.Online value".
    #[serde(rename = "OnlineChange", default, skip_serializing_if = "Option::is_none")]
    pub online_change: Option<BTreeMap<i64, bool>>,
    /// "the user profiles of nodes in the network".
    #[serde(rename = "UserProfiles", default, skip_serializing_if = "Vec::is_empty")]
    pub user_profiles: Vec<UserProfile>,
    /// "the name of the network that this node is in".
    #[serde(rename = "Domain", default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    /// "DNSConfig contains the DNS settings for the client to use"
    /// (tailcfg.go:2081-2083). nil means unchanged, exactly like the
    /// other whole-map fields (capability 15: "client treats nil
    /// MapResponse.DNSConfig as meaning unchanged", tailcfg.go:66).
    #[serde(rename = "DNSConfig", default, skip_serializing_if = "Option::is_none")]
    pub dns_config: Option<DnsConfig>,
    /// "the firewall rules" — carried for a future filter port, not
    /// enforced (see the gap list).
    #[serde(rename = "PacketFilter", default, skip_serializing_if = "Option::is_none")]
    pub packet_filter: Option<serde_json::Value>,
    /// "if non-zero, is the current timestamp according to the control
    /// server" (RFC3339 pass-through).
    #[serde(rename = "ControlTime", default, skip_serializing_if = "Option::is_none")]
    pub control_time: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::noise::MachinePrivateKey;

    /// Keys are generated in-test, never literals (repo rule); the hex
    /// strings below are derived at runtime from random keys.
    #[test]
    fn node_key_json_is_the_nodekey_prefix_form() {
        let key = NodePrivateKey::generate();
        let pub_hex: String = key.public().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let wire = format!("\"nodekey:{pub_hex}\"");
        let parsed: NodeKey = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed.as_bytes(), key.public().as_bytes());
        assert_eq!(serde_json::to_string(&parsed).unwrap(), wire);
        // Wrong prefix / short hex refused.
        assert!(serde_json::from_str::<NodeKey>(&format!("\"mkey:{pub_hex}\"")).is_err());
        assert!(serde_json::from_str::<NodeKey>("\"nodekey:abcd\"").is_err());
    }

    #[test]
    fn machine_and_disco_key_text_forms() {
        let k = MachinePublicKey::from_bytes([7u8; 32]);
        let m = MachineKeyText([7u8; 32]);
        let expect = format!("\"mkey:{}\"", "07".repeat(32));
        assert_eq!(serde_json::to_string(&m).unwrap(), expect);
        assert_eq!(m.to_machine_public_key(), k);
        // Short / wrong-prefixed disco keys are refused.
        assert!(serde_json::from_str::<DiscoKeyText>("\"discokey:ab\"").is_err());
        assert!(serde_json::from_str::<DiscoKeyText>("\"nodekey:ab\"").is_err());
        let ok: DiscoKeyText =
            serde_json::from_str(&format!("\"discokey:{}\"", "ab".repeat(32))).unwrap();
        assert_eq!(ok.0, [0xabu8; 32]);
        // privkey: round trip for the state store.
        let node = NodePrivateKey::generate();
        let text = node_private_text(&node);
        assert!(text.starts_with("privkey:"));
        assert_eq!(
            node_private_from_text(&text).unwrap().public(),
            node.public()
        );
    }

    #[test]
    fn prefix_and_addrport_json_round_trip() {
        let p: Prefix = serde_json::from_str("\"100.64.12.34/32\"").unwrap();
        assert_eq!(p.to_string(), "100.64.12.34/32");
        let p: Prefix = serde_json::from_str("\"fd7a:115c:a1e0::1/128\"").unwrap();
        assert_eq!(p.to_string(), "fd7a:115c:a1e0::1/128");
        assert!(serde_json::from_str::<Prefix>("\"100.64.0.1/33\"").is_err());
        let a: AddrPort = serde_json::from_str("\"127.0.0.1:41234\"").unwrap();
        assert_eq!(a.0.port(), 41234);
        let a: AddrPort = serde_json::from_str("\"[::1]:443\"").unwrap();
        assert_eq!(serde_json::to_string(&a).unwrap(), "\"[::1]:443\"");
        assert!(serde_json::from_str::<AddrPort>("\"nope\"").is_err());
    }

    #[test]
    fn prefix_contains_covers_both_families() {
        let v4 = Prefix::new("100.64.0.0".parse().unwrap(), 24);
        assert!(v4.contains(&"100.64.0.99".parse().unwrap()));
        assert!(!v4.contains(&"100.64.1.99".parse().unwrap()));
        let host = Prefix::new("100.64.0.1".parse().unwrap(), 32);
        assert!(host.contains(&"100.64.0.1".parse().unwrap()));
        assert!(!host.contains(&"100.64.0.2".parse().unwrap()));
        let any = Prefix::new("0.0.0.0".parse().unwrap(), 0);
        assert!(any.contains(&"203.0.113.9".parse().unwrap()));
        let v6 = Prefix::new("fd7a:115c:a1e0::".parse().unwrap(), 48);
        assert!(v6.contains(&"fd7a:115c:a1e0:ab::1".parse().unwrap()));
        assert!(!v6.contains(&"fd7a:115c:a1e1::1".parse().unwrap()));
        // Cross-family never matches.
        assert!(!v4.contains(&"fd7a:115c:a1e0::1".parse().unwrap()));
    }

    #[test]
    fn register_request_json_matches_the_go_field_names() {
        // The exact shape direct.go builds (759-782): Version, OldNodeKey,
        // NodeKey, NLKey, Hostinfo, Followup, Timestamp..., Ephemeral,
        // and Auth.AuthKey when an auth key is in play (786-789).
        let node = NodePrivateKey::generate();
        let node_hex: String =
            node.public().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let req = RegisterRequest {
            version: CURRENT_CAPABILITY_VERSION,
            node_key: NodeKey(*node.public().as_bytes()),
            old_node_key: NodeKey([0u8; 32]),
            nl_key: DiscoKeyText([0u8; 32]),
            auth: Some(RegisterResponseAuth {
                oauth2_token: None,
                auth_key: "generated-in-test".into(),
            }),
            expiry: None,
            followup: String::new(),
            hostinfo: Some(Hostinfo {
                backend_log_id: "logid-test".into(),
                os: "linux".into(),
                hostname: "rustcrash-node".into(),
                app: "rustcrash".into(),
                userspace: Some(true),
                ..Default::default()
            }),
            ephemeral: true,
            tailnet: String::new(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["Version"], 148);
        assert_eq!(json["NodeKey"], format!("nodekey:{node_hex}"));
        assert_eq!(json["OldNodeKey"], format!("nodekey:{}", "00".repeat(32)));
        assert_eq!(json["NLKey"], format!("discokey:{}", "00".repeat(32)));
        assert_eq!(json["Auth"]["AuthKey"], "generated-in-test");
        assert_eq!(json["Hostinfo"]["BackendLogID"], "logid-test");
        assert_eq!(json["Hostinfo"]["App"], "rustcrash");
        assert_eq!(json["Ephemeral"], true);
        // Parse-back round trip.
        let back: RegisterRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn map_response_parses_a_go_shaped_netmap_message() {
        // A hand-written MapResponse in the exact Go JSON shape (field
        // names + key prefixes), like headscale emits (keys filled at
        // runtime — no literal key material).
        let self_key = NodePrivateKey::generate();
        let peer_key = NodePrivateKey::generate();
        let self_hex: String =
            self_key.public().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let peer_hex: String =
            peer_key.public().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let raw = format!(
            r#"{{
              "Node": {{
                "ID": 1, "StableID": "n1", "Name": "self.tail-scale.ts.net.",
                "User": 10, "Key": "nodekey:{self_hex}",
                "Addresses": ["100.64.0.1/32"],
                "AllowedIPs": ["100.64.0.1/32"],
                "DERP": "127.3.3.40:1"
              }},
              "DERPMap": {{
                "Regions": {{
                  "1": {{
                    "RegionID": 1, "RegionCode": "tst", "RegionName": "Test",
                    "Nodes": [{{ "Name": "1a", "RegionID": 1, "HostName": "127.0.0.1",
                                "IPv4": "127.0.0.1", "DERPPort": 3340,
                                "InsecureForTests": true }}]
                  }}
                }}
              }},
              "Peers": [{{
                "ID": 2, "Name": "peer.tail-scale.ts.net.", "User": 10,
                "Key": "nodekey:{peer_hex}",
                "Addresses": ["100.64.0.2/32"],
                "AllowedIPs": ["100.64.0.2/32"],
                "Endpoints": ["127.0.0.1:9999"],
                "HomeDERP": 1, "Online": true, "MachineAuthorized": true
              }}],
              "UserProfiles": [{{ "ID": 10, "LoginName": "test@example.com",
                                   "DisplayName": "Test" }}],
              "Domain": "tail-scale.ts.net"
            }}"#
        );
        let resp: MapResponse = serde_json::from_str(&raw).unwrap();
        let node = resp.node.as_ref().unwrap();
        assert_eq!(node.id, 1);
        assert_eq!(node.addresses, vec![Prefix::new("100.64.0.1".parse().unwrap(), 32)]);
        assert_eq!(node.legacy_derp_string, "127.3.3.40:1");
        assert_eq!(resp.peers.len(), 1);
        let peer = &resp.peers[0];
        assert_eq!(peer.key.as_bytes(), peer_key.public().as_bytes());
        assert_eq!(peer.endpoints[0].0.port(), 9999);
        assert_eq!(peer.home_derp, 1);
        assert_eq!(resp.user_profiles[0].login_name, "test@example.com");
        // The DERPMap URL resolves through IPv4 + DERPPort, http because
        // InsecureForTests.
        assert_eq!(
            resp.derp_map.as_ref().unwrap().region_url(1).as_deref(),
            Some("http://127.0.0.1:3340")
        );
        // And the keepalive fast-path literal parses.
        let ka: MapResponse = serde_json::from_str(r#"{"KeepAlive":true}"#).unwrap();
        assert!(ka.keep_alive && ka.peers.is_empty());
    }

    #[test]
    fn peer_change_patch_json_shape() {
        let peer_key = NodePrivateKey::generate();
        let peer_hex: String =
            peer_key.public().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let raw = format!(
            r#"{{"NodeID": 7, "DERPRegion": 2, "Endpoints": ["127.0.0.1:1234"],
                 "Online": false, "Key": "nodekey:{peer_hex}"}}"#
        );
        let pc: PeerChange = serde_json::from_str(&raw).unwrap();
        assert_eq!(pc.node_id, 7);
        assert_eq!(pc.derp_region, 2);
        assert_eq!(pc.endpoints.len(), 1);
        assert_eq!(pc.online, Some(false));
        assert_eq!(pc.key.as_ref().unwrap().as_bytes(), peer_key.public().as_bytes());
    }

    #[test]
    fn over_tls_key_response_shape() {
        let k = MachinePrivateKey::generate();
        let hexs: String = k.public().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let resp: OverTlsPublicKeyResponse =
            serde_json::from_str(&format!(r#"{{"publicKey":"mkey:{hexs}"}}"#)).unwrap();
        assert_eq!(resp.public_key.unwrap().0, *k.public().as_bytes());
        assert!(resp.legacy_public_key.is_none());
    }

    #[test]
    fn hostinfo_omits_empty_fields_like_omitzero() {
        let hi = Hostinfo {
            backend_log_id: "b".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&hi).unwrap();
        assert_eq!(json, r#"{"BackendLogID":"b"}"#);
    }
}
