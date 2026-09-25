//! Binary rule-set readers and the mihomo `.mrs` writer: sing-box `.srs`
//! and mihomo `.mrs`.
//!
//! Both formats (mirrored from the upstream sources, byte for byte):
//!
//! * `.srs` (sing-box `common/srs/binary.go`, versions 1-2): `SRS` magic +
//!   1-byte version + a zlib stream holding `uvarint rule-count` followed by
//!   typed rules. A default rule is a stream of 1-byte item types (domain
//!   trie, keyword/regex string lists, IP-CIDR range lists, ports, process
//!   names, ...) terminated by `0xFF` + an invert byte; logical rules nest
//!   sub-rules under an AND/OR mode. Domains live in a LOUDS succinct trie
//!   (leaves/labelBitmap/labels, keys stored reversed, `'\r'`/`'\n'` suffix
//!   markers) exactly as serialized by `sagernet/sing`'s `domain.Matcher`.
//! * `.mrs` (mihomo `rules/provider/mrs_reader.go` + `component/trie` /
//!   `component/cidr`): the whole file is a zstd stream holding `MRS\1`
//!   magic, a behavior byte (0=domain, 1=ipcidr; 2=classical is never
//!   produced upstream), int64-BE rule count, int64-BE extra length (+
//!   skipped bytes), then the behavior payload: the domain payload is the
//!   same LOUDS trie with int64-BE array counts (keys reversed, trailing
//!   `+` marking suffix entries), the ipcidr payload is int64-BE range
//!   count + per-range 16-byte v4-mapped `from`/`to` addresses.
//!
//! [`write_mrs`] produces `.mrs` files with the same payload layout as
//! mihomo's `rules/provider/mrs_converter.go` (domain and ipcidr
//! behaviors; classical stays read-only, exactly like upstream which never
//! writes it). The one intentional byte-level difference: the zstd framing
//! is a hand-rolled store frame (raw blocks, see [`zstd_store_frame`]) —
//! the engine's zstd dependency is decode-only `ruzstd`, and a C encoder
//! is not an option under the musl-static/no-C constraint. The
//! *decompressed* stream is byte-identical to upstream's writer.
//!
//! Decoded subset (everything else is consumed and discarded or rejected):
//! srs keeps domain/suffix/keyword/regex entries, flattens logical rules'
//! entries (AND/OR/invert semantics are dropped), decodes `ip_cidr` ranges
//! into CIDR strings, and structurally skips query_type, network, ports,
//! process/wifi/package and `source_ip_cidr` items; unknown item types
//! error out. mrs keeps domain exact/suffix entries (a `*.x` single-label
//! wildcard is approximated as the suffix `x`) and ipcidr ranges as CIDR
//! strings; classical `.mrs` is rejected with a clear error.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use flate2::read::ZlibDecoder;

use crate::error::{Error, Result};

/// `.srs` magic bytes (`SRS`).
const SRS_MAGIC: [u8; 3] = [0x53, 0x52, 0x53];
/// Highest `.srs` format version this reader understands.
const SRS_VERSION_MAX: u8 = 2;
/// sing-box logical-rule nesting limit (`maxLogicalRuleDepth`).
const SRS_MAX_LOGICAL_DEPTH: usize = 100;

// sing-box rule item types (`common/srs/binary.go`, versions 1-2).
const SRS_ITEM_QUERY_TYPE: u8 = 0;
const SRS_ITEM_NETWORK: u8 = 1;
const SRS_ITEM_DOMAIN: u8 = 2;
const SRS_ITEM_DOMAIN_KEYWORD: u8 = 3;
const SRS_ITEM_DOMAIN_REGEX: u8 = 4;
const SRS_ITEM_SOURCE_IP_CIDR: u8 = 5;
const SRS_ITEM_IP_CIDR: u8 = 6;
const SRS_ITEM_SOURCE_PORT: u8 = 7;
const SRS_ITEM_SOURCE_PORT_RANGE: u8 = 8;
const SRS_ITEM_PORT: u8 = 9;
const SRS_ITEM_PORT_RANGE: u8 = 10;
const SRS_ITEM_PROCESS_NAME: u8 = 11;
const SRS_ITEM_PROCESS_PATH: u8 = 12;
const SRS_ITEM_PACKAGE_NAME: u8 = 13;
const SRS_ITEM_WIFI_SSID: u8 = 14;
const SRS_ITEM_WIFI_BSSID: u8 = 15;
const SRS_ITEM_FINAL: u8 = 0xFF;

/// Domain-trie key markers (`sagernet/sing/common/domain`): a stored key
/// ending in (reversed: starting with) one of these marks a suffix entry.
const SRS_PREFIX_LABEL: u8 = b'\r';
const SRS_ROOT_LABEL: u8 = b'\n';

/// `.mrs` magic bytes (`MRS` + version 1).
const MRS_MAGIC: [u8; 4] = [b'M', b'R', b'S', 1];
const MRS_BEHAVIOR_DOMAIN: u8 = 0;
const MRS_BEHAVIOR_IPCIDR: u8 = 1;
const MRS_BEHAVIOR_CLASSICAL: u8 = 2;

// ---------------------------------------------------------------------------
// Shared cursor
// ---------------------------------------------------------------------------

/// Bounds-checked byte cursor (same style as the geosite reader).
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn uvarint(&mut self) -> Option<u64> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = *self.data.get(self.pos)?;
            self.pos += 1;
            value |= ((b & 0x7F) as u64) << shift;
            if b & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
    }

    fn be_u16(&mut self) -> Option<u16> {
        let bytes = self.bytes(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn be_u64(&mut self) -> Option<u64> {
        let bytes = self.bytes(8)?;
        let mut out = [0u8; 8];
        out.copy_from_slice(bytes);
        Some(u64::from_be_bytes(out))
    }

    fn be_i64(&mut self) -> Option<i64> {
        self.be_u64().map(|v| v as i64)
    }

    fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let out = self.data.get(self.pos..self.pos.checked_add(len)?)?;
        self.pos += len;
        Some(out)
    }

    /// Skip `len` bytes, bounded by what actually remains.
    fn skip(&mut self, len: u64) -> Option<()> {
        let remaining = (self.data.len() - self.pos) as u64;
        if len > remaining {
            return None;
        }
        self.pos += len as usize;
        Some(())
    }
}

fn truncated(what: &str) -> Error {
    Error::config(format!("{what}: truncated data"))
}

// ---------------------------------------------------------------------------
// LOUDS succinct trie (shared by both formats)
// ---------------------------------------------------------------------------

/// A LOUDS-encoded byte trie: `label_bitmap` holds one 0-bit per edge (plus
/// a 1-bit terminating every node's child list), `labels` holds the edge
/// bytes for the 0-bits, `leaves` marks terminal nodes by node id. Both
/// sing-box and mihomo serialize exactly this structure (they only differ
/// in array-length framing), so one walker serves both readers.
struct LoudsTrie {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    /// Per-word prefix popcount of `label_bitmap` (len = words + 1).
    rank1_prefix: Vec<u32>,
    /// Positions of every 1-bit in `label_bitmap` (select index).
    ones_positions: Vec<u32>,
    bit_len: usize,
}

impl LoudsTrie {
    /// Validates the LOUDS invariants the same way upstream readers do:
    /// ones(zeros + 1) and `labels.len() == zeros`. Leaves are zero-padded
    /// to cover every node id (upstream pads on read for `.srs`; mihomo
    /// files always carry enough words for valid tries).
    fn new(mut leaves: Vec<u64>, label_bitmap: Vec<u64>, labels: Vec<u8>) -> Result<Self> {
        let ones: u64 = label_bitmap.iter().map(|w| w.count_ones() as u64).sum();
        let last_one = label_bitmap
            .iter()
            .enumerate()
            .rev()
            .find(|(_, w)| **w != 0)
            .map(|(i, w)| (i << 6) + (63 - w.leading_zeros() as usize));
        let zeros = match last_one {
            Some(pos) => pos as u64 + 1 - ones,
            None => 0,
        };
        if ones != zeros + 1 || labels.len() != zeros as usize {
            return Err(Error::config(
                "malformed domain trie: labels do not match the LOUDS bitmap",
            ));
        }
        let words_needed = ((ones + 63) >> 6) as usize;
        while leaves.len() < words_needed {
            leaves.push(0);
        }
        let mut rank1_prefix = Vec::with_capacity(label_bitmap.len() + 1);
        let mut ones_positions = Vec::new();
        let mut acc = 0u32;
        for word in &label_bitmap {
            rank1_prefix.push(acc);
            for i in 0..64 {
                if word & (1 << i) != 0 {
                    ones_positions.push(((rank1_prefix.len() - 1) << 6 | i) as u32);
                }
            }
            acc += word.count_ones();
        }
        rank1_prefix.push(acc);
        Ok(LoudsTrie {
            leaves,
            labels,
            bit_len: label_bitmap.len() * 64,
            label_bitmap,
            rank1_prefix,
            ones_positions,
        })
    }

    fn bit(&self, i: usize) -> Option<u64> {
        self.label_bitmap.get(i >> 6).map(|w| (w >> (i & 63)) & 1)
    }

    fn leaf(&self, node: usize) -> Option<bool> {
        self.leaves
            .get(node >> 6)
            .map(|w| (w >> (node & 63)) & 1 == 1)
    }

    /// Number of 0-bits (edges) before bit `i`.
    fn rank0_before(&self, i: usize) -> Option<usize> {
        if i > self.bit_len {
            return None;
        }
        let word = i >> 6;
        let off = i & 63;
        let mut ones = *self.rank1_prefix.get(word)? as usize;
        if off > 0 {
            let w = self.label_bitmap[word];
            ones += (w & ((1u64 << off) - 1)).count_ones() as usize;
        }
        Some(i - ones)
    }

    /// Position of the (i+1)-th 1-bit.
    fn select1(&self, i: usize) -> Option<usize> {
        self.ones_positions.get(i).map(|p| *p as usize)
    }

    /// Recover every stored key (a port of sing's `succinctSet.keys()` /
    /// mihomo's `DomainSet.keys()` DFS; both walk the same encoding).
    fn keys(&self) -> Result<Vec<Vec<u8>>> {
        let mut result = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        if self.leaf(0).ok_or_else(|| truncated("domain trie"))? {
            result.push(Vec::new());
        }
        // (node id, first-edge bitmap index) frames.
        let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
        // Valid tries walk in O(labels + nodes); malformed bitmaps could
        // otherwise loop, so cap the work and fail cleanly.
        let step_cap = 8 * (self.labels.len() + self.ones_positions.len() + 64);
        let mut steps = 0usize;
        while let Some(frame) = stack.last_mut() {
            steps += 1;
            if steps > step_cap {
                return Err(Error::config("malformed domain trie: walk does not terminate"));
            }
            if self.bit(frame.1).ok_or_else(|| truncated("domain trie"))? == 1 {
                stack.pop();
                if let Some(parent) = stack.last_mut() {
                    current.pop();
                    parent.1 += 1;
                }
                continue;
            }
            let (node_id, bm_idx) = *frame;
            let label_idx = bm_idx
                .checked_sub(node_id)
                .filter(|i| *i < self.labels.len())
                .ok_or_else(|| Error::config("malformed domain trie: bad label index"))?;
            current.push(self.labels[label_idx]);
            let next_node = self
                .rank0_before(bm_idx + 1)
                .ok_or_else(|| truncated("domain trie"))?;
            let next_bm = self
                .select1(next_node.checked_sub(1).ok_or_else(|| {
                    Error::config("malformed domain trie: bad child node id")
                })?)
                .map(|p| p + 1)
                .ok_or_else(|| truncated("domain trie"))?;
            if self.leaf(next_node).ok_or_else(|| truncated("domain trie"))? {
                result.push(current.clone());
            }
            stack.push((next_node, next_bm));
        }
        Ok(result)
    }
}

/// Undo the rune-wise reversal both writers apply before trie insertion.
fn unreverse_key(key: &[u8]) -> Result<String> {
    let s = std::str::from_utf8(key)
        .map_err(|_| Error::config("malformed domain trie: key is not utf-8"))?;
    Ok(s.chars().rev().collect())
}

// ---------------------------------------------------------------------------
// IP ranges -> CIDR strings (port of netipx `IPRange.Prefixes()`)
// ---------------------------------------------------------------------------

fn ip_range_to_cidrs(from: IpAddr, to: IpAddr) -> Result<Vec<String>> {
    let (lo, hi, bits) = match (from, to) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) as u128, u32::from(b) as u128, 32u32),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128u32),
        _ => {
            return Err(Error::config(format!(
                "invalid ip range: {from}..{to} mixes address families"
            )))
        }
    };
    if lo > hi {
        return Err(Error::config(format!("invalid ip range: {from} > {to}")));
    }
    let mut out = Vec::new();
    let mut cur = lo;
    while cur <= hi {
        let span = hi - cur;
        // Largest block aligned at `cur` that still fits under `hi`.
        // `span + 1` cannot be formed when the range covers the whole
        // 128-bit space (`::/0`), so that case is the explicit `k ==
        // bits` below instead of an overflowing add.
        let mut k = if span == u128::MAX {
            128
        } else if span == 0 {
            0
        } else {
            127u32 - (span + 1).leading_zeros()
        };
        let tz = if cur == 0 { bits } else { cur.trailing_zeros().min(bits) };
        k = k.min(tz);
        let plen = bits - k;
        let addr = match bits {
            32 => IpAddr::V4(Ipv4Addr::from(cur as u32)),
            _ => IpAddr::V6(Ipv6Addr::from(cur)),
        };
        out.push(format!("{addr}/{plen}"));
        // A `k == 128` block consumed the entire remaining space (and any
        // final step off the top of the range must not overflow `cur`).
        if k >= 128 {
            return Ok(out);
        }
        match cur.checked_add(1u128 << k) {
            Some(next) => cur = next,
            None => return Ok(out),
        }
    }
    Ok(out)
}

/// Decode a 16-byte big-endian address, unmaping IPv4-mapped form (mihomo
/// stores every ipcidr range as `Addr.As16()`; Go's reader calls `Unmap`).
fn addr_from_16(bytes: &[u8]) -> Result<IpAddr> {
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|_| truncated("ip range address"))?;
    if arr[..10].iter().all(|b| *b == 0) && arr[10] == 0xff && arr[11] == 0xff {
        Ok(IpAddr::V4(Ipv4Addr::new(arr[12], arr[13], arr[14], arr[15])))
    } else {
        Ok(IpAddr::V6(Ipv6Addr::from(arr)))
    }
}

/// Decode a 4- or 16-byte `netip.Addr.MarshalBinary` payload (4 = IPv4,
/// 16 = IPv6 or IPv4-mapped, which is unmapped like Go's reader).
fn addr_from_marshal(bytes: &[u8]) -> Result<IpAddr> {
    match bytes.len() {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => addr_from_16(bytes),
        n => Err(Error::config(format!(
            "invalid ip range address length {n} (expected 4 or 16)"
        ))),
    }
}

// ---------------------------------------------------------------------------
// sing-box .srs
// ---------------------------------------------------------------------------

/// One domain entry from an `.srs` rule set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrsDomain {
    /// `domain: [...]` exact match.
    Exact(String),
    /// `domain_suffix: [...]` (leading dot stripped, like
    /// [`crate::rule::DomainMatcher::add_suffix`]).
    Suffix(String),
    Keyword(String),
    Regex(String),
}

/// Parsed contents of an `.srs` file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SrsRuleSet {
    pub domains: Vec<SrsDomain>,
    /// `ip_cidr` ranges, converted back to CIDR strings (`a.b.c.d/pl`).
    pub ip_cidrs: Vec<String>,
}

/// Parse a sing-box `.srs` rule-set file (format versions 1-2).
pub fn parse_srs(bytes: &[u8]) -> Result<SrsRuleSet> {
    if bytes.len() < 4 {
        return Err(truncated("srs: file shorter than the magic + version header"));
    }
    if bytes[..3] != SRS_MAGIC {
        return Err(Error::config("srs: bad magic bytes (expected \"SRS\")"));
    }
    let version = bytes[3];
    if version == 0 || version > SRS_VERSION_MAX {
        return Err(Error::config(format!(
            "srs: unsupported version {version} (supported: 1-{SRS_VERSION_MAX})"
        )));
    }
    let mut zlib = ZlibDecoder::new(&bytes[4..]);
    let mut raw = Vec::new();
    zlib.read_to_end(&mut raw)
        .map_err(|e| Error::config(format!("srs: bad zlib stream: {e}")))?;
    let mut cur = Cursor::new(&raw);
    let rule_count = cur
        .uvarint()
        .ok_or_else(|| truncated("srs: rule count"))?;
    let mut out = SrsRuleSet::default();
    for _ in 0..rule_count {
        read_srs_rule(&mut cur, &mut out, 0)?;
    }
    Ok(out)
}

/// One rule: type byte 0 = default item list, 1 = logical (AND/OR) nest.
fn read_srs_rule(cur: &mut Cursor<'_>, out: &mut SrsRuleSet, depth: usize) -> Result<()> {
    if depth > SRS_MAX_LOGICAL_DEPTH {
        return Err(Error::config("srs: logical rule nested too deep"));
    }
    match cur.byte().ok_or_else(|| truncated("srs: rule type"))? {
        0 => read_srs_default_rule(cur, out),
        1 => {
            let mode = cur.byte().ok_or_else(|| truncated("srs: logical mode"))?;
            if mode > 1 {
                return Err(Error::config(format!(
                    "srs: unknown logical mode {mode} (expected 0=and or 1=or)"
                )));
            }
            let sub_count = cur
                .uvarint()
                .ok_or_else(|| truncated("srs: logical rule count"))?;
            for _ in 0..sub_count {
                // Logical sub-rules are flattened: their domain/ip entries
                // are collected, the AND/OR/invert semantics are dropped.
                read_srs_rule(cur, out, depth + 1)?;
            }
            cur.byte().ok_or_else(|| truncated("srs: logical invert"))?;
            Ok(())
        }
        t => Err(Error::config(format!(
            "srs: unknown rule type {t} (expected 0 or 1)"
        ))),
    }
}

fn read_srs_default_rule(cur: &mut Cursor<'_>, out: &mut SrsRuleSet) -> Result<()> {
    loop {
        let item = cur.byte().ok_or_else(|| truncated("srs: rule item type"))?;
        match item {
            SRS_ITEM_DOMAIN => {
                let (exacts, suffixes) = read_srs_domain_matcher(cur)?;
                out.domains
                    .extend(exacts.into_iter().map(SrsDomain::Exact));
                out.domains
                    .extend(suffixes.into_iter().map(SrsDomain::Suffix));
            }
            SRS_ITEM_DOMAIN_KEYWORD => {
                for kw in read_srs_string_list(cur)? {
                    out.domains.push(SrsDomain::Keyword(kw));
                }
            }
            SRS_ITEM_DOMAIN_REGEX => {
                for re in read_srs_string_list(cur)? {
                    out.domains.push(SrsDomain::Regex(re));
                }
            }
            SRS_ITEM_IP_CIDR => {
                let cidrs = read_srs_ip_set(cur)?;
                out.ip_cidrs.extend(cidrs);
            }
            // Consumed structurally, discarded: srs rule-sets in a clash
            // engine only carry domain/ip payloads we can act on.
            SRS_ITEM_QUERY_TYPE | SRS_ITEM_SOURCE_PORT | SRS_ITEM_PORT => {
                read_srs_u16_list(cur)?;
            }
            SRS_ITEM_NETWORK
            | SRS_ITEM_SOURCE_PORT_RANGE
            | SRS_ITEM_PORT_RANGE
            | SRS_ITEM_PROCESS_NAME
            | SRS_ITEM_PROCESS_PATH
            | SRS_ITEM_PACKAGE_NAME
            | SRS_ITEM_WIFI_SSID
            | SRS_ITEM_WIFI_BSSID => {
                read_srs_string_list(cur)?;
            }
            SRS_ITEM_SOURCE_IP_CIDR => {
                read_srs_ip_set(cur)?;
            }
            SRS_ITEM_FINAL => {
                cur.byte().ok_or_else(|| truncated("srs: rule invert"))?;
                return Ok(());
            }
            t => {
                return Err(Error::config(format!(
                    "srs: unknown rule item type {t}"
                )))
            }
        }
    }
}

/// `uvarint count` + `count` uvarint-length-prefixed utf-8 strings.
fn read_srs_string_list(cur: &mut Cursor<'_>) -> Result<Vec<String>> {
    let count = cur
        .uvarint()
        .ok_or_else(|| truncated("srs: string list count"))?;
    let mut out = Vec::new();
    for _ in 0..count {
        let len = cur
            .uvarint()
            .ok_or_else(|| truncated("srs: string length"))?;
        let bytes = cur
            .bytes(len as usize)
            .ok_or_else(|| truncated("srs: string body"))?;
        out.push(
            String::from_utf8(bytes.to_vec())
                .map_err(|_| Error::config("srs: string is not utf-8"))?,
        );
    }
    Ok(out)
}

/// `uvarint count` + `count` big-endian u16s.
fn read_srs_u16_list(cur: &mut Cursor<'_>) -> Result<Vec<u16>> {
    let count = cur
        .uvarint()
        .ok_or_else(|| truncated("srs: u16 list count"))?;
    let mut out = Vec::new();
    for _ in 0..count {
        out.push(cur.be_u16().ok_or_else(|| truncated("srs: u16 item"))?);
    }
    Ok(out)
}

/// The `domain.Matcher` payload: a reserved 0 byte + three uvarint-counted
/// arrays (u64 words / u64 words / raw bytes). Returns (exacts, suffixes)
/// using sing's `Dump()` semantics, including the legacy v1 marker merge.
fn read_srs_domain_matcher(cur: &mut Cursor<'_>) -> Result<(Vec<String>, Vec<String>)> {
    cur.byte().ok_or_else(|| truncated("srs: domain trie version"))?;
    let leaves = read_srs_u64_words(cur)?;
    let label_bitmap = read_srs_u64_words(cur)?;
    let labels_len = cur
        .uvarint()
        .ok_or_else(|| truncated("srs: labels count"))?;
    let labels = cur
        .bytes(labels_len as usize)
        .ok_or_else(|| truncated("srs: labels body"))?
        .to_vec();
    let trie = LoudsTrie::new(leaves, label_bitmap, labels)?;

    let mut exacts: BTreeSet<String> = BTreeSet::new();
    let mut prefix_map: BTreeSet<String> = BTreeSet::new();
    let mut prefix_list: Vec<String> = Vec::new();
    for key in trie.keys()? {
        let key = unreverse_key(&key)?;
        if key.is_empty() {
            continue;
        }
        match key.as_bytes().first() {
            Some(&SRS_PREFIX_LABEL) => {
                prefix_map.insert(key[1..].to_string());
            }
            Some(&SRS_ROOT_LABEL) => prefix_list.push(key[1..].to_string()),
            _ => {
                exacts.insert(key);
            }
        }
    }
    // Legacy v1 files store a bare reversed suffix domain alongside the
    // `'\r'`-marked entry; Dump() merges those back into a suffix.
    for raw in prefix_map {
        if let Some(root) = raw.strip_prefix('.') {
            if exacts.remove(root) {
                prefix_list.push(root.to_string());
                continue;
            }
        }
        prefix_list.push(raw);
    }
    let suffixes = prefix_list
        .into_iter()
        .map(|s| s.trim_start_matches('.').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Ok((exacts.into_iter().collect(), suffixes))
}

fn read_srs_u64_words(cur: &mut Cursor<'_>) -> Result<Vec<u64>> {
    let count = cur
        .uvarint()
        .ok_or_else(|| truncated("srs: bitmap word count"))?;
    let mut out = Vec::new();
    for _ in 0..count {
        out.push(cur.be_u64().ok_or_else(|| truncated("srs: bitmap word"))?);
    }
    Ok(out)
}

/// The `readIPSet` payload: version byte, u64-BE range count, then per
/// range a uvarint-length-prefixed `from` and `to` address (4/16 bytes).
fn read_srs_ip_set(cur: &mut Cursor<'_>) -> Result<Vec<String>> {
    cur.byte().ok_or_else(|| truncated("srs: ip set version"))?;
    let count = cur
        .be_u64()
        .ok_or_else(|| truncated("srs: ip range count"))?;
    let mut out = Vec::new();
    for _ in 0..count {
        let mut addr = || -> Result<IpAddr> {
            let len = cur
                .uvarint()
                .ok_or_else(|| truncated("srs: ip address length"))?;
            let bytes = cur
                .bytes(len as usize)
                .ok_or_else(|| truncated("srs: ip address body"))?;
            addr_from_marshal(bytes)
        };
        let from = addr()?;
        let to = addr()?;
        out.extend(ip_range_to_cidrs(from, to)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// mihomo .mrs
// ---------------------------------------------------------------------------

/// Parsed contents of an `.mrs` file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MrsRuleSet {
    /// Suffix entries (`+.domain` / `.domain` patterns; leading markers
    /// stripped). `*.domain` single-label wildcards land here too.
    pub suffixes: Vec<String>,
    pub exacts: Vec<String>,
    /// IPCIDR behavior ranges converted back to CIDR strings.
    pub ip_cidrs: Vec<String>,
}

/// Parse a mihomo `.mrs` rule-set file (domain and ipcidr behaviors).
pub fn parse_mrs(bytes: &[u8]) -> Result<MrsRuleSet> {
    let mut zstd = ruzstd::decoding::StreamingDecoder::new(bytes)
        .map_err(|e| Error::config(format!("mrs: bad zstd stream: {e}")))?;
    let mut raw = Vec::new();
    zstd.read_to_end(&mut raw)
        .map_err(|e| Error::config(format!("mrs: bad zstd stream: {e}")))?;
    let mut cur = Cursor::new(&raw);
    let magic = cur
        .bytes(4)
        .ok_or_else(|| truncated("mrs: magic header"))?;
    if magic != MRS_MAGIC {
        return Err(Error::config(
            "mrs: bad magic bytes (expected \"MRS\" + version 1)",
        ));
    }
    let behavior = cur.byte().ok_or_else(|| truncated("mrs: behavior"))?;
    let count = cur.be_i64().ok_or_else(|| truncated("mrs: count"))?;
    if count < 0 {
        return Err(Error::config(format!(
            "mrs: invalid count {count}"
        )));
    }
    let extra_len = cur
        .be_i64()
        .ok_or_else(|| truncated("mrs: extra length"))?;
    if extra_len < 0 {
        return Err(Error::config(format!(
            "mrs: invalid extra length {extra_len}"
        )));
    }
    cur.skip(extra_len as u64)
        .ok_or_else(|| truncated("mrs: extra block"))?;
    match behavior {
        MRS_BEHAVIOR_DOMAIN => read_mrs_domain_payload(&mut cur),
        MRS_BEHAVIOR_IPCIDR => read_mrs_ipcidr_payload(&mut cur),
        MRS_BEHAVIOR_CLASSICAL => Err(Error::config(
            "mrs: classical behavior is not supported (upstream mihomo never writes it)",
        )),
        b => Err(Error::config(format!(
            "mrs: unknown behavior byte {b} (expected 0=domain or 1=ipcidr)"
        ))),
    }
}

/// `trie.ReadDomainSetBin`: version byte 1 + three int64-BE-counted arrays
/// (u64 leaves words, u64 labelBitmap words, raw label bytes). Stored keys
/// are reversed; a trailing `+` marks a suffix entry, a `*` label marks a
/// single-label wildcard.
fn read_mrs_domain_payload(cur: &mut Cursor<'_>) -> Result<MrsRuleSet> {
    let version = cur.byte().ok_or_else(|| truncated("mrs: domain-set version"))?;
    if version != 1 {
        return Err(Error::config(format!(
            "mrs: invalid domain-set version {version} (expected 1)"
        )));
    }
    let leaves = read_mrs_u64_words(cur)?;
    let label_bitmap = read_mrs_u64_words(cur)?;
    let labels_len = cur
        .be_i64()
        .ok_or_else(|| truncated("mrs: labels count"))?;
    if labels_len < 1 {
        return Err(Error::config("mrs: invalid labels count"));
    }
    let labels = cur
        .bytes(labels_len as usize)
        .ok_or_else(|| truncated("mrs: labels body"))?
        .to_vec();
    let trie = LoudsTrie::new(leaves, label_bitmap, labels)?;

    let mut exacts = BTreeSet::new();
    let mut suffixes = BTreeSet::new();
    for key in trie.keys()? {
        let (suffix_marker, body) = match key.last() {
            Some(b'+') => (true, &key[..key.len() - 1]),
            _ => (false, &key[..]),
        };
        let domain = unreverse_key(body)?;
        if suffix_marker {
            // "+.x" / ".x" patterns; the reversal yields a leading dot.
            if let Some(s) = domain.strip_prefix('.') {
                if !s.is_empty() {
                    suffixes.insert(s.to_string());
                }
            } else if !domain.is_empty() {
                suffixes.insert(domain);
            }
        } else if domain == "*" {
            return Err(Error::config(
                "mrs: bare '*' wildcard pattern is not supported",
            ));
        } else if let Some(rest) = domain.strip_prefix("*.") {
            if !rest.is_empty() {
                suffixes.insert(rest.to_string());
            }
        } else if domain.contains('*') {
            return Err(Error::config(format!(
                "mrs: unsupported wildcard pattern {domain:?}"
            )));
        } else if !domain.is_empty() {
            exacts.insert(domain);
        }
    }
    Ok(MrsRuleSet {
        suffixes: suffixes.into_iter().collect(),
        exacts: exacts.into_iter().collect(),
        ip_cidrs: Vec::new(),
    })
}

fn read_mrs_u64_words(cur: &mut Cursor<'_>) -> Result<Vec<u64>> {
    let count = cur
        .be_i64()
        .ok_or_else(|| truncated("mrs: bitmap word count"))?;
    if count < 1 {
        return Err(Error::config("mrs: invalid bitmap word count"));
    }
    let mut out = Vec::new();
    for _ in 0..count {
        out.push(cur.be_u64().ok_or_else(|| truncated("mrs: bitmap word"))?);
    }
    Ok(out)
}

/// `cidr.ReadIpCidrSet`: version byte 1 + int64-BE range count + per range
/// a 16-byte `from` and 16-byte `to` (v4-mapped) address.
fn read_mrs_ipcidr_payload(cur: &mut Cursor<'_>) -> Result<MrsRuleSet> {
    let version = cur.byte().ok_or_else(|| truncated("mrs: ipcidr-set version"))?;
    if version != 1 {
        return Err(Error::config(format!(
            "mrs: invalid ipcidr-set version {version} (expected 1)"
        )));
    }
    let count = cur
        .be_i64()
        .ok_or_else(|| truncated("mrs: ip range count"))?;
    if count < 1 {
        return Err(Error::config("mrs: invalid ip range count"));
    }
    let mut out = Vec::new();
    for _ in 0..count {
        let from = addr_from_16(
            cur.bytes(16)
                .ok_or_else(|| truncated("mrs: ip range from-address"))?,
        )?;
        let to = addr_from_16(
            cur.bytes(16)
                .ok_or_else(|| truncated("mrs: ip range to-address"))?,
        )?;
        out.extend(ip_range_to_cidrs(from, to)?);
    }
    Ok(MrsRuleSet {
        suffixes: Vec::new(),
        exacts: Vec::new(),
        ip_cidrs: out,
    })
}

// ---------------------------------------------------------------------------
// mihomo .mrs writer (port of rules/provider/mrs_converter.go +
// trie.DomainSetBuilder/WriteBin + cidr.IpCidrSet::WriteBin)
// ---------------------------------------------------------------------------

/// Which payload layout [`write_mrs`] serializes. Mirrors
/// `P.RuleBehavior` for the two behaviors upstream ever writes
/// (`rules/provider/mrs_converter.go`: classical is read-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MrsWriteBehavior {
    /// `behavior: domain` — rules are domain patterns (`a.b` exact,
    /// `+.b` / `.b` subdomain-suffix, `*.b` single-label wildcard).
    Domain,
    /// `behavior: ipcidr` — rules are CIDR strings (`a.b.c.d/pl`).
    IpCidr,
}

/// Serialize a rule set as a mihomo `.mrs` file, the Rust mirror of
/// `ConvertToMrs` (`rules/provider/mrs_converter.go:17-87`).
///
/// Invalid rules are skipped with a warning and do not count (upstream's
/// provider `Insert` semantics, `rules/provider/domain_strategy.go:40-51`
/// and `ipcidr_strategy.go:44-52`); if nothing valid remains the function
/// fails with upstream's "empty rule" error. The returned bytes decompress
/// to exactly the stream mihomo writes: `MRS\1` magic, behavior byte,
/// int64-BE count of valid rules, int64-BE extra length (always 0), then
/// the behavior payload. The zstd framing itself is a store frame
/// ([`zstd_store_frame`]); mihomo's `klauspost/compress` writer emits
/// Huffman-compressed blocks, so the compressed bytes differ while the
/// payload is byte-identical.
pub fn write_mrs(behavior: MrsWriteBehavior, rules: &[&str]) -> Result<Vec<u8>> {
    let mut count: i64 = 0;
    let payload = match behavior {
        MrsWriteBehavior::Domain => {
            // domainStrategy.Insert: a slash can never appear in a domain;
            // anything else goes through ValidAndSplitDomain.
            let mut keys: Vec<Vec<u8>> = Vec::new();
            for rule in rules {
                if rule.contains('/') {
                    tracing::warn!("mrs writer: skip invalid domain {rule:?}: slash is not allowed");
                    continue;
                }
                match domain_set_keys(rule) {
                    Ok(mut derived) => {
                        keys.append(&mut derived);
                        count += 1;
                    }
                    Err(e) => tracing::warn!("mrs writer: skip invalid domain {rule:?}: {e}"),
                }
            }
            if count == 0 {
                return Err(Error::config("empty rule"));
            }
            mrs_domain_payload_from_keys(keys)
        }
        MrsWriteBehavior::IpCidr => {
            let mut ranges: Vec<IpRange> = Vec::new();
            for rule in rules {
                match parse_cidr_range(rule) {
                    Ok(r) => {
                        ranges.push(r);
                        count += 1;
                    }
                    Err(e) => tracing::warn!("mrs writer: invalid ipcidr {rule:?}: {e}"),
                }
            }
            if count == 0 {
                return Err(Error::config("empty rule"));
            }
            mrs_ipcidr_payload_from_ranges(merge_ranges(ranges))
        }
    };

    let mut raw = Vec::with_capacity(payload.len() + 24);
    raw.extend_from_slice(&MRS_MAGIC);
    raw.push(match behavior {
        MrsWriteBehavior::Domain => MRS_BEHAVIOR_DOMAIN,
        MrsWriteBehavior::IpCidr => MRS_BEHAVIOR_IPCIDR,
    });
    raw.extend_from_slice(&count.to_be_bytes());
    // extra: reserved for future use, always empty (mrs_converter.go:53-61).
    raw.extend_from_slice(&0i64.to_be_bytes());
    raw.extend_from_slice(&payload);
    Ok(zstd_store_frame(&raw))
}

// --- domain payload (component/trie) ---

/// Port of `trie.ValidAndSplitDomain` (`component/trie/domain.go:27-92`):
/// lower-case, split on `.`, reject trailing dot / leading or trailing
/// whitespace / empty labels / misplaced `+`- and `*`-wildcards. Go checks
/// `unicode.IsSpace`; Rust's `char::is_whitespace` is the equivalent set
/// for every practically relevant codepoint.
fn valid_and_split_domain(domain: &str) -> Result<Vec<String>> {
    let invalid = |why: &str| Error::config(format!("invalid domain {domain:?}: {why}"));
    if domain.is_empty() {
        return Err(invalid("domain is empty"));
    }
    if domain.ends_with('.') {
        return Err(invalid("trailing dot is not allowed"));
    }
    if domain
        .chars()
        .next()
        .is_some_and(char::is_whitespace)
    {
        return Err(invalid("leading whitespace is not allowed"));
    }
    if domain
        .chars()
        .next_back()
        .is_some_and(char::is_whitespace)
    {
        return Err(invalid("trailing whitespace is not allowed"));
    }
    let parts: Vec<String> = domain.to_lowercase().split('.').map(str::to_string).collect();
    if parts.len() == 1 {
        if parts[0].is_empty() {
            return Err(invalid("domain is empty"));
        }
    } else {
        for (i, part) in parts[1..].iter().enumerate() {
            if part.is_empty() {
                return Err(invalid(&format!("label {} is empty", i + 2)));
            }
        }
    }
    for (i, part) in parts.iter().enumerate() {
        if part.contains('+') {
            if part != "+" {
                return Err(invalid(&format!(
                    "\"+\" wildcard must occupy the entire label {}",
                    i + 1
                )));
            }
            if i != 0 {
                return Err(invalid("\"+\" wildcard is only allowed in the first label"));
            }
            if parts.len() == 1 {
                return Err(invalid("\"+\" wildcard must be followed by another label"));
            }
        }
        if part.contains('*') && part != "*" {
            return Err(invalid(&format!(
                "\"*\" wildcard must occupy the entire label {}",
                i + 1
            )));
        }
    }
    Ok(parts)
}

/// Port of `DomainSetBuilder::Insert` + `insert`
/// (`component/trie/domain_set.go:38-58`): `+.x` inserts both `x` and
/// `+.x` (exact plus subdomain-suffix); `.x` becomes `+.x`; keys are the
/// rune-wise-reversed joined domain (`common/utils.Reverse`).
fn domain_set_keys(rule: &str) -> Result<Vec<Vec<u8>>> {
    let parts = valid_and_split_domain(rule)?;
    let mut keys = Vec::with_capacity(2);
    if parts[0] == "+" {
        let mut rest = parts[1..].to_vec();
        domain_set_push_key(&mut keys, &mut rest);
        let mut whole = parts;
        domain_set_push_key(&mut keys, &mut whole);
    } else {
        let mut whole = parts;
        domain_set_push_key(&mut keys, &mut whole);
    }
    Ok(keys)
}

/// `DomainSetBuilder::insert`: an empty first label (the `.x` dot-wildcard
/// splits to `["", "x"]`) becomes `+`, then the joined domain is reversed
/// rune-wise and stored.
fn domain_set_push_key(keys: &mut Vec<Vec<u8>>, parts: &mut [String]) {
    if parts[0].is_empty() {
        parts[0] = "+".to_string();
    }
    let joined = parts.join(".");
    keys.push(joined.chars().rev().collect::<String>().into_bytes());
}

/// Production sibling of the reader's LOUDS structure: port of
/// `buildDomainSet` (`component/trie/domain_set.go:96-143`). Keys are
/// sorted (Go `sort.Strings` is byte order), deduplicated (`Compact`), then
/// consumed level by level: one node per queue frame, a terminal bit when
/// the frame's first key ends at this column, one 0-bit + label byte per
/// run of equal next-bytes, and a terminating 1-bit per node.
fn build_domain_set(mut keys: Vec<Vec<u8>>) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
    keys.sort_unstable();
    keys.dedup();
    let mut leaves: Vec<u64> = Vec::new();
    let mut label_bitmap: Vec<u64> = Vec::new();
    let mut labels: Vec<u8> = Vec::new();
    let mut l_idx = 0usize;
    let mut node_id = 0usize;
    let mut queue: Vec<(usize, usize)> = vec![(0, keys.len())];
    let mut col = 0usize;
    while !queue.is_empty() {
        let mut next: Vec<(usize, usize)> = Vec::new();
        for &(s0, e) in &queue {
            let mut s = s0;
            if keys[s].len() == col {
                s += 1;
                set_bit(&mut leaves, node_id);
            }
            let mut j = s;
            while j < e {
                let frm = j;
                while j < e && keys[j][col] == keys[frm][col] {
                    j += 1;
                }
                next.push((frm, j));
                labels.push(keys[frm][col]);
                // Edge bits stay 0 (Go setBit(.., 0)); only the node
                // terminator below writes a 1.
                l_idx += 1;
            }
            set_bit(&mut label_bitmap, l_idx);
            l_idx += 1;
            node_id += 1;
        }
        queue = next;
        col += 1;
    }
    (leaves, label_bitmap, labels)
}

/// `setBit(bm, i, v)` from `component/trie/domain_set.go:300-305`: grow
/// with zero words, then set bit `i`.
fn set_bit(words: &mut Vec<u64>, i: usize) {
    while i >> 6 >= words.len() {
        words.push(0);
    }
    words[i >> 6] |= 1u64 << (i & 63);
}

/// Port of `DomainSet::WriteBin` (`component/trie/domain_set_bin.go:9-51`):
/// version byte 1, int64-BE count + u64-BE words for leaves and
/// labelBitmap, int64-BE count + raw bytes for labels.
fn mrs_domain_payload_from_keys(keys: Vec<Vec<u8>>) -> Vec<u8> {
    let (leaves, label_bitmap, labels) = build_domain_set(keys);
    let mut out = Vec::with_capacity(labels.len() + 24 + 16 * (leaves.len() + label_bitmap.len()));
    out.push(1u8);
    out.extend_from_slice(&(leaves.len() as i64).to_be_bytes());
    for w in &leaves {
        out.extend_from_slice(&w.to_be_bytes());
    }
    out.extend_from_slice(&(label_bitmap.len() as i64).to_be_bytes());
    for w in &label_bitmap {
        out.extend_from_slice(&w.to_be_bytes());
    }
    out.extend_from_slice(&(labels.len() as i64).to_be_bytes());
    out.extend_from_slice(&labels);
    out
}

// --- ipcidr payload (component/cidr) ---

/// One parsed CIDR as an inclusive numeric range within its address
/// family (the Rust form of `netipx.RangeOfPrefix`; host bits masked).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpRange {
    v6: bool,
    lo: u128,
    hi: u128,
}

/// Parse `a.b.c.d/pl` (or v6) masking the host bits, like
/// `cidr.IpCidrSet::AddIpCidrForString` → `netipx.RangeOfPrefix`.
fn parse_cidr_range(rule: &str) -> Result<IpRange> {
    let (addr, plen) = rule
        .split_once('/')
        .ok_or_else(|| Error::config(format!("missing /prefix length in {rule:?}")))?;
    let plen: u32 = plen
        .parse()
        .map_err(|_| Error::config(format!("bad prefix length {plen:?}")))?;
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            if plen > 32 {
                return Err(Error::config(format!("prefix length {plen} exceeds 32 for v4")));
            }
            let mask = if plen == 0 { 0 } else { u32::MAX << (32 - plen) };
            let lo = u32::from(a) & mask;
            Ok(IpRange {
                v6: false,
                lo: lo as u128,
                hi: (lo | !mask) as u128,
            })
        }
        Ok(IpAddr::V6(a)) => {
            if plen > 128 {
                return Err(Error::config(format!("prefix length {plen} exceeds 128 for v6")));
            }
            let mask = if plen == 0 { 0 } else { u128::MAX << (128 - plen) };
            let lo = u128::from(a) & mask;
            Ok(IpRange {
                v6: true,
                lo,
                hi: lo | !mask,
            })
        }
        Err(_) => Err(Error::config(format!("bad address {addr:?}"))),
    }
}

/// Port of `ipcidrStrategy::FinishInsert` → `IpCidrSet::Merge` →
/// `netipx.IPSetBuilder` normalize/`mergeIPRanges` (`go4.org/netipx`
/// `ipset.go`): sort by family then range, then coalesce every pair that
/// overlaps or is exactly adjacent (`to + 1 >= next.from`), keeping the
/// wider `to`. v4 and v6 ranges never merge.
fn merge_ranges(mut ranges: Vec<IpRange>) -> Vec<IpRange> {
    ranges.sort_by_key(|r| (r.v6, r.lo, r.hi));
    let mut out: Vec<IpRange> = Vec::new();
    for r in ranges {
        match out.last_mut() {
            Some(last) if last.v6 == r.v6 && r.lo <= last.hi.saturating_add(1) => {
                last.hi = last.hi.max(r.hi);
            }
            _ => out.push(r),
        }
    }
    out
}

/// Port of `IpCidrSet::WriteBin` (`component/cidr/ipcidr_set_bin.go:12-36`):
/// version byte 1, int64-BE range count, then per range the 16-byte
/// big-endian `From().As16()` and `To().As16()` — v4 ranges stored in
/// v4-mapped form.
fn mrs_ipcidr_payload_from_ranges(ranges: Vec<IpRange>) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + ranges.len() * 32);
    out.push(1u8);
    out.extend_from_slice(&(ranges.len() as i64).to_be_bytes());
    for r in ranges {
        out.extend_from_slice(&addr_as_16_prod(r.lo, r.v6));
        out.extend_from_slice(&addr_as_16_prod(r.hi, r.v6));
    }
    out
}

/// `netip.Addr.As16` for an inclusive range endpoint: v6 in full, v4
/// embedded as `::ffff:a.b.c.d`.
fn addr_as_16_prod(v: u128, v6: bool) -> [u8; 16] {
    if v6 {
        v.to_be_bytes()
    } else {
        let mut out = [0u8; 16];
        out[10] = 0xff;
        out[11] = 0xff;
        out[12..].copy_from_slice(&(v as u32).to_be_bytes());
        out
    }
}

// --- zstd store-frame encoder ---
//
// The engine's zstd dependency is ruzstd (decode-only), so .mrs writing
// needs a minimal encoder. A frame of Raw_Block stores (RFC 8878 / the
// upstream zstd spec §3.1, "Compressed Block format") is a valid zstd
// stream every decoder accepts: frame header, then every block verbatim
// with a 3-byte header. No XXH64 content checksum is written — it is
// optional (descriptor bit 2 stays 0) and mihomo's reader does not require
// one.

/// Maximum bytes per block. The spec caps `Block_Size` at
/// `min(Window_Size, 128 KiB)`; 64 KiB sits well inside the 1 MiB window
/// declared below and matches the block size the reader's test fixtures
/// already exercise.
const MRS_ZSTD_BLOCK_MAX: usize = 64 * 1024;

/// Frame_Content_Size field: always the full 8-byte form (descriptor flag
/// `0b11`), little-endian per the spec ("Frame_Content_Size ... uses
/// little-endian convention"; this is also exactly how ruzstd's reader at
/// `decoding/frame.rs:75-83` and klauspost/compress decode it).
fn zstd_store_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 3 * (payload.len() / MRS_ZSTD_BLOCK_MAX + 1) + 18);
    // Magic_Number 0xFD2FB528, little-endian (spec §3.1.1.1).
    out.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
    // Frame_Header_Descriptor (spec §3.1.1.1.1): FCS_Field_Size flag
    // 0b11 (8 bytes), Single_Segment 0, Content_Checksum 0, Dictionary_ID
    // flag 0.
    out.push(0b1100_0000);
    // Window_Descriptor (spec §3.1.1.1.2): Exponent 10, Mantissa 0 →
    // windowLog 20 → 1 MiB window.
    out.push(0x50);
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    let mut chunks = payload.chunks(MRS_ZSTD_BLOCK_MAX).peekable();
    if payload.is_empty() {
        // A frame must contain at least one block; an empty last Raw
        // block (Block_Size 0) is the minimal legal encoding.
        out.extend_from_slice(&1u32.to_le_bytes()[..3]);
        return out;
    }
    while let Some(chunk) = chunks.next() {
        let last = chunks.peek().is_none() as u32;
        // Block_Header (spec §3.1.1.4): bit 0 Last_Block, bits 1-2
        // Block_Type (0 = Raw_Block), bits 3-23 Block_Size.
        let header = ((chunk.len() as u32) << 3) | last;
        out.extend_from_slice(&header.to_le_bytes()[..3]);
        out.extend_from_slice(chunk);
    }
    out
}

// ---------------------------------------------------------------------------
// Tests — fixtures are synthesized in-test by porting the upstream writers
// (sing-box `binary.go` + sing `domain.Matcher` for .srs, mihomo
// `mrs_converter.go` + `trie/cidr` for .mrs), so nothing is downloaded.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- primitive encoders (varbin / binary.BigEndian mirrors) ---

    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
        out
    }

    fn put_varint(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&varint(v));
    }

    /// sing `writeUint64Slice`: uvarint count + big-endian u64 words.
    fn put_u64_slice(out: &mut Vec<u8>, words: &[u64]) {
        put_varint(out, words.len() as u64);
        for w in words {
            out.extend_from_slice(&w.to_be_bytes());
        }
    }

    /// sing `writeByteSlice`: uvarint count + raw bytes.
    fn put_byte_slice(out: &mut Vec<u8>, bytes: &[u8]) {
        put_varint(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }

    /// mihomo `WriteBin` framing: int64-BE count + payload words/bytes.
    fn put_i64_counted_words(out: &mut Vec<u8>, words: &[u64]) {
        out.extend_from_slice(&(words.len() as i64).to_be_bytes());
        for w in words {
            out.extend_from_slice(&w.to_be_bytes());
        }
    }

    fn put_i64_counted_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as i64).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    /// Rune-wise reversal, like `utils.Reverse` / `reverseDomain`.
    fn reverse(s: &str) -> Vec<u8> {
        s.chars().rev().collect::<String>().into_bytes()
    }

    // --- LOUDS trie builders ---

    /// Port of sing's `newSuccinctSet` (growing BFS queue with (start,
    /// end, column) frames).
    fn build_trie_sing(mut keys: Vec<Vec<u8>>) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
        keys.sort();
        let mut leaves: Vec<u64> = Vec::new();
        let mut bitmap: Vec<u64> = Vec::new();
        let mut labels: Vec<u8> = Vec::new();
        let mut l_idx = 0usize;
        let mut queue: Vec<(usize, usize, usize)> = vec![(0, keys.len(), 0)];
        let mut i = 0;
        while i < queue.len() {
            let (mut s, e, col) = queue[i];
            if col == keys[s].len() {
                s += 1;
                set_bit(&mut leaves, i);
            }
            let mut j = s;
            while j < e {
                let frm = j;
                while j < e && keys[j][col] == keys[frm][col] {
                    j += 1;
                }
                queue.push((frm, j, col + 1));
                labels.push(keys[frm][col]);
                // Edge bits stay 0 (Go's setBit(.., 0)); only the node
                // terminator below writes a 1.
                l_idx += 1;
            }
            set_bit(&mut bitmap, l_idx);
            l_idx += 1;
            i += 1;
        }
        (leaves, bitmap, labels)
    }

    /// Port of mihomo's `buildDomainSet` (level-by-level queue + explicit
    /// node id counter; keys sorted and compacted first).
    fn build_trie_mrs(mut keys: Vec<Vec<u8>>) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
        keys.sort();
        keys.dedup();
        let mut leaves: Vec<u64> = Vec::new();
        let mut bitmap: Vec<u64> = Vec::new();
        let mut labels: Vec<u8> = Vec::new();
        let mut l_idx = 0usize;
        let mut node_id = 0usize;
        let mut queue: Vec<(usize, usize)> = vec![(0, keys.len())];
        let mut col = 0usize;
        while !queue.is_empty() {
            let mut next: Vec<(usize, usize)> = Vec::new();
            for &(s0, e) in &queue {
                let mut s = s0;
                if col == keys[s].len() {
                    s += 1;
                    set_bit(&mut leaves, node_id);
                }
                let mut j = s;
                while j < e {
                    let frm = j;
                    while j < e && keys[j][col] == keys[frm][col] {
                        j += 1;
                    }
                    next.push((frm, j));
                    labels.push(keys[frm][col]);
                    l_idx += 1;
                }
                set_bit(&mut bitmap, l_idx);
                l_idx += 1;
                node_id += 1;
            }
            queue = next;
            col += 1;
        }
        (leaves, bitmap, labels)
    }

    // --- .srs fixture assembly ---

    /// Mirror `domain.NewMatcher(domains, suffixes, legacy)` key derivation:
    /// exact domains are stored bare-reversed; suffixes get a marker char
    /// prepended before reversal ('\n' in v2+, '\r' + ".x" in legacy v1).
    fn srs_domain_payload(exacts: &[&str], suffixes: &[&str], legacy: bool) -> Vec<u8> {
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for s in suffixes {
            if s.starts_with('.') {
                keys.push(reverse(&format!("\r{s}")));
            } else if legacy {
                keys.push(reverse(s));
                keys.push(reverse(&format!("\r.{s}")));
            } else {
                keys.push(reverse(&format!("\n{s}")));
            }
        }
        for d in exacts {
            keys.push(reverse(d));
        }
        keys.sort();
        let (leaves, bitmap, labels) = build_trie_sing(keys);
        let mut out = vec![SRS_ITEM_DOMAIN, 0u8]; // item type + reserved version
        put_u64_slice(&mut out, &leaves);
        put_u64_slice(&mut out, &bitmap);
        put_byte_slice(&mut out, &labels);
        out
    }

    fn srs_string_item(item: u8, values: &[&str]) -> Vec<u8> {
        let mut out = vec![item];
        put_varint(&mut out, values.len() as u64);
        for v in values {
            put_varint(&mut out, v.len() as u64);
            out.extend_from_slice(v.as_bytes());
        }
        out
    }

    fn srs_u16_item(item: u8, values: &[u16]) -> Vec<u8> {
        let mut out = vec![item];
        put_varint(&mut out, values.len() as u64);
        for v in values {
            out.extend_from_slice(&v.to_be_bytes());
        }
        out
    }

    /// A parsed CIDR as an inclusive numeric range.
    fn cidr_range(cidr: &str) -> (u128, u128, u32) {
        let (addr, plen) = cidr.split_once('/').unwrap();
        let plen: u32 = plen.parse().unwrap();
        match addr.parse::<IpAddr>().unwrap() {
            IpAddr::V4(a) => {
                let mask = if plen == 0 { 0 } else { u32::MAX << (32 - plen) };
                let lo = u32::from(a) & mask;
                (lo as u128, (lo | !mask) as u128, 32)
            }
            IpAddr::V6(a) => {
                let mask = if plen == 0 { 0 } else { u128::MAX << (128 - plen) };
                let lo = u128::from(a) & mask;
                (lo, lo | !mask, 128)
            }
        }
    }

    /// Mirror `writeRuleItemCIDR`: ranges sorted and (naively) merged, then
    /// `writeIPSet` framing with uvarint-length-prefixed marshal bytes.
    fn srs_ip_item(item: u8, cidrs: &[&str]) -> Vec<u8> {
        let mut ranges: Vec<(u128, u128, u32)> = cidrs.iter().map(|c| cidr_range(c)).collect();
        ranges.sort();
        let mut merged: Vec<(u128, u128, u32)> = Vec::new();
        for r in ranges {
            match merged.last_mut() {
                Some(last) if r.0 <= last.1.saturating_add(1) && r.2 == last.2 => {
                    last.1 = last.1.max(r.1)
                }
                _ => merged.push(r),
            }
        }
        let mut out = vec![item, 1]; // item type + ip-set version
        out.extend_from_slice(&(merged.len() as u64).to_be_bytes());
        for (lo, hi, bits) in merged {
            for addr in [lo, hi] {
                match bits {
                    32 => {
                        put_varint(&mut out, 4);
                        out.extend_from_slice(&(addr as u32).to_be_bytes());
                    }
                    _ => {
                        put_varint(&mut out, 16);
                        out.extend_from_slice(&addr.to_be_bytes());
                    }
                }
            }
        }
        out
    }

    fn srs_default_rule(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![0u8]; // rule type: default
        for item in items {
            out.extend_from_slice(item);
        }
        out.extend_from_slice(&[SRS_ITEM_FINAL, 0]); // final + invert
        out
    }

    fn srs_logical_rule(mode: u8, sub_rules: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![1u8, mode]; // rule type: logical + and/or
        put_varint(&mut out, sub_rules.len() as u64);
        for r in sub_rules {
            out.extend_from_slice(r);
        }
        out.push(0); // invert
        out
    }

    fn make_srs(rules: &[Vec<u8>], version: u8) -> Vec<u8> {
        let mut body = Vec::new();
        put_varint(&mut body, rules.len() as u64);
        for r in rules {
            body.extend_from_slice(r);
        }
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(9));
        std::io::Write::write_all(&mut zlib, &body).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&SRS_MAGIC);
        out.push(version);
        out.extend_from_slice(&zlib.finish().unwrap());
        out
    }

    // --- .mrs fixture assembly ---

    /// Hand-built zstd frame made only of Raw blocks (max 64 KiB each, 1 MiB
    /// window): magic + descriptor (unknown content size) + window + blocks.
    fn zstd_raw_frame(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x50];
        let mut chunks = payload.chunks(64 * 1024).peekable();
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none() as u32;
            let header = ((chunk.len() as u32) << 3) | last; // block type 0 = Raw
            out.extend_from_slice(&header.to_le_bytes()[..3]);
            out.extend_from_slice(chunk);
        }
        out
    }

    fn make_mrs(behavior: u8, count: i64, payload: &[u8], extra: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&MRS_MAGIC);
        raw.push(behavior);
        raw.extend_from_slice(&count.to_be_bytes());
        raw.extend_from_slice(&(extra.len() as i64).to_be_bytes());
        raw.extend_from_slice(extra);
        raw.extend_from_slice(payload);
        zstd_raw_frame(&raw)
    }

    /// Mirror `DomainSetBuilder.Insert` key derivation: `+.x` inserts both
    /// `x` and `+.x`; `.x` becomes `+.x`; everything else is stored as-is.
    fn mrs_keys(patterns: &[&str]) -> Vec<Vec<u8>> {
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for p in patterns {
            if let Some(rest) = p.strip_prefix("+.") {
                keys.push(reverse(rest));
                keys.push(reverse(&format!("+.{rest}")));
            } else if let Some(rest) = p.strip_prefix('.') {
                keys.push(reverse(&format!("+.{rest}")));
            } else {
                keys.push(reverse(p));
            }
        }
        keys
    }

    fn mrs_domain_payload(patterns: &[&str]) -> Vec<u8> {
        let (leaves, bitmap, labels) = build_trie_mrs(mrs_keys(patterns));
        let mut out = vec![1u8]; // domain-set version
        put_i64_counted_words(&mut out, &leaves);
        put_i64_counted_words(&mut out, &bitmap);
        put_i64_counted_bytes(&mut out, &labels);
        out
    }

    /// 16-byte big-endian form with IPv4 embedded v4-mapped (`Addr.As16`).
    fn addr_as_16(v: u128, bits: u32) -> [u8; 16] {
        match bits {
            32 => {
                let mut out = [0u8; 16];
                out[10] = 0xff;
                out[11] = 0xff;
                out[12..].copy_from_slice(&(v as u32).to_be_bytes());
                out
            }
            _ => v.to_be_bytes(),
        }
    }

    fn mrs_ipcidr_payload(cidrs: &[&str]) -> Vec<u8> {
        let mut ranges: Vec<(u128, u128, u32)> = cidrs.iter().map(|c| cidr_range(c)).collect();
        ranges.sort();
        let mut out = vec![1u8]; // ipcidr-set version
        out.extend_from_slice(&(ranges.len() as i64).to_be_bytes());
        for (lo, hi, bits) in ranges {
            out.extend_from_slice(&addr_as_16(lo, bits));
            out.extend_from_slice(&addr_as_16(hi, bits));
        }
        out
    }

    // --- .srs tests ---

    #[test]
    fn srs_multi_rule_set_round_trip() {
        let rule1 = srs_default_rule(&[
            srs_domain_payload(&["example.com", "a.b.c"], &["google.com"], false),
            srs_string_item(SRS_ITEM_DOMAIN_KEYWORD, &["analytics"]),
            srs_string_item(SRS_ITEM_DOMAIN_REGEX, &["^re\\d+\\.test$"]),
        ]);
        let rule2 = srs_default_rule(&[srs_ip_item(
            SRS_ITEM_IP_CIDR,
            &["192.168.0.0/16", "2001:db8::/32"],
        )]);
        let rule3 = srs_logical_rule(
            1, // or
            &[srs_default_rule(&[srs_domain_payload(&[], &["sub.example"], false)])],
        );
        let file = make_srs(&[rule1, rule2, rule3], 2);

        let set = parse_srs(&file).unwrap();
        assert!(set
            .domains
            .contains(&SrsDomain::Exact("example.com".into())));
        assert!(set.domains.contains(&SrsDomain::Exact("a.b.c".into())));
        assert!(set.domains.contains(&SrsDomain::Suffix("google.com".into())));
        assert!(set
            .domains
            .contains(&SrsDomain::Keyword("analytics".into())));
        assert!(set
            .domains
            .contains(&SrsDomain::Regex("^re\\d+\\.test$".into())));
        // Logical sub-rule entries are flattened into the same lists.
        assert!(set
            .domains
            .contains(&SrsDomain::Suffix("sub.example".into())));
        assert!(set.ip_cidrs.contains(&"192.168.0.0/16".to_string()));
        assert!(set.ip_cidrs.contains(&"2001:db8::/32".to_string()));
    }

    #[test]
    fn srs_version1_legacy_suffix_merge() {
        // Legacy v1 stores suffix "google.com" as a bare reversed key plus
        // a '\r'-marked ".google.com"; Dump() must merge them back into one
        // suffix and not report a bogus exact "google.com".
        let rule = srs_default_rule(&[srs_domain_payload(
            &["example.com"],
            &["google.com"],
            true,
        )]);
        let set = parse_srs(&make_srs(&[rule], 1)).unwrap();
        assert!(set.domains.contains(&SrsDomain::Exact("example.com".into())));
        assert!(set.domains.contains(&SrsDomain::Suffix("google.com".into())));
        assert!(!set.domains.contains(&SrsDomain::Exact("google.com".into())));
    }

    #[test]
    fn srs_skips_unhandled_items() {
        let rule = srs_default_rule(&[
            srs_u16_item(SRS_ITEM_QUERY_TYPE, &[1, 28]),
            srs_string_item(SRS_ITEM_NETWORK, &["tcp"]),
            srs_u16_item(SRS_ITEM_PORT, &[80, 443]),
            srs_string_item(SRS_ITEM_PORT_RANGE, &["1000-2000"]),
            srs_string_item(SRS_ITEM_PROCESS_NAME, &["curl"]),
            srs_ip_item(SRS_ITEM_SOURCE_IP_CIDR, &["10.0.0.0/8"]),
            srs_domain_payload(&["kept.example"], &[], false),
        ]);
        let set = parse_srs(&make_srs(&[rule], 2)).unwrap();
        assert_eq!(set.domains, vec![SrsDomain::Exact("kept.example".into())]);
        assert!(set.ip_cidrs.is_empty()); // source cidrs are decoded, not kept
    }

    #[test]
    fn srs_empty_rule_set() {
        let set = parse_srs(&make_srs(&[], 1)).unwrap();
        assert_eq!(set, SrsRuleSet::default());
    }

    #[test]
    fn srs_rejects_bad_magic_version_and_truncation() {
        let good = srs_default_rule(&[srs_domain_payload(&["a.com"], &[], false)]);
        let file = make_srs(&[good], 1);

        let mut bad_magic = file.clone();
        bad_magic[0] = b'X';
        let err = parse_srs(&bad_magic).unwrap_err();
        assert!(err.to_string().contains("magic"), "{err}");

        for version in [0u8, 3, 9] {
            let mut bad_version = file.clone();
            bad_version[3] = version;
            let err = parse_srs(&bad_version).unwrap_err();
            assert!(
                err.to_string().contains("unsupported version"),
                "version {version}: {err}"
            );
        }

        let err = parse_srs(&file[..3]).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");

        // Cut inside the zlib stream: either a zlib or truncation error,
        // but never a panic or a successful empty parse.
        for cut in [5, 8, file.len() / 2] {
            assert!(parse_srs(&file[..cut]).is_err());
        }

        let mut corrupt = file.clone();
        corrupt[10] ^= 0xFF;
        let err = parse_srs(&corrupt).unwrap_err();
        assert!(err.to_string().contains("zlib"), "{err}");
    }

    #[test]
    fn srs_rejects_unknown_rule_and_item_types() {
        let mut bad_item = srs_default_rule(&[]);
        bad_item[1] = 0x42; // unknown item type right after the rule type
        let err = parse_srs(&make_srs(&[bad_item], 1)).unwrap_err();
        assert!(err.to_string().contains("unknown rule item type"), "{err}");

        let err = parse_srs(&make_srs(&[vec![7]], 1)).unwrap_err();
        assert!(err.to_string().contains("unknown rule type"), "{err}");
    }

    #[test]
    fn srs_rejects_malformed_trie() {
        // Labels array shorter than the bitmap's 0-bit count.
        let mut payload = vec![SRS_ITEM_DOMAIN, 0u8];
        put_u64_slice(&mut payload, &[1]); // leaves
        put_u64_slice(&mut payload, &[0b10]); // bitmap: one edge + terminator
        put_byte_slice(&mut payload, &[]); // but zero labels
        let rule = srs_default_rule(&[payload]);
        let err = parse_srs(&make_srs(&[rule], 1)).unwrap_err();
        assert!(err.to_string().contains("malformed domain trie"), "{err}");
    }

    // --- .mrs tests ---

    #[test]
    fn mrs_domain_round_trip() {
        let patterns = ["example.com", "+.google.com", ".dot.org", "*.wild.net"];
        let file = make_mrs(MRS_BEHAVIOR_DOMAIN, patterns.len() as i64, &mrs_domain_payload(&patterns), &[]);
        let set = parse_mrs(&file).unwrap();
        assert_eq!(set.exacts, vec!["example.com".to_string(), "google.com".to_string()]);
        assert_eq!(
            set.suffixes,
            vec![
                "dot.org".to_string(),
                "google.com".to_string(),
                "wild.net".to_string(),
            ]
        );
        assert!(set.ip_cidrs.is_empty());
    }

    #[test]
    fn mrs_ipcidr_round_trip() {
        let cidrs = ["10.0.0.0/8", "192.168.1.1/32", "2001:db8::/32"];
        let file = make_mrs(MRS_BEHAVIOR_IPCIDR, cidrs.len() as i64, &mrs_ipcidr_payload(&cidrs), &[]);
        let set = parse_mrs(&file).unwrap();
        assert!(set.ip_cidrs.contains(&"10.0.0.0/8".to_string()));
        assert!(set.ip_cidrs.contains(&"192.168.1.1/32".to_string()));
        assert!(set.ip_cidrs.contains(&"2001:db8::/32".to_string()));
        assert!(set.exacts.is_empty() && set.suffixes.is_empty());
    }

    #[test]
    fn mrs_skips_extra_block() {
        let patterns = ["example.com"];
        let payload = mrs_domain_payload(&patterns);
        let file = make_mrs(MRS_BEHAVIOR_DOMAIN, 1, &payload, &[0xEE, 0xEE, 0xEE]);
        let set = parse_mrs(&file).unwrap();
        assert_eq!(set.exacts, vec!["example.com".to_string()]);
    }

    #[test]
    fn mrs_rejects_bad_magic_behavior_and_versions() {
        let payload = mrs_domain_payload(&["example.com"]);
        let file = make_mrs(MRS_BEHAVIOR_DOMAIN, 1, &payload, &[]);

        // Corrupt the (decompressed) magic inside the zstd frame: rebuild
        // the frame over a patched raw stream via a raw-frame round trip.
        let mut zstd = ruzstd::decoding::StreamingDecoder::new(&file[..]).unwrap();
        let mut raw = Vec::new();
        zstd.read_to_end(&mut raw).unwrap();
        raw[0] = b'X';
        let err = parse_mrs(&zstd_raw_frame(&raw)).unwrap_err();
        assert!(err.to_string().contains("magic"), "{err}");

        let err = parse_mrs(&make_mrs(MRS_BEHAVIOR_CLASSICAL, 1, &payload, &[])).unwrap_err();
        assert!(err.to_string().contains("classical"), "{err}");

        let err = parse_mrs(&make_mrs(9, 1, &payload, &[])).unwrap_err();
        assert!(err.to_string().contains("unknown behavior"), "{err}");

        // Payload version byte 2 instead of 1.
        let mut bad_version = payload.clone();
        bad_version[0] = 2;
        let err = parse_mrs(&make_mrs(MRS_BEHAVIOR_DOMAIN, 1, &bad_version, &[])).unwrap_err();
        assert!(err.to_string().contains("version"), "{err}");
    }

    #[test]
    fn mrs_rejects_truncation_and_bad_zstd() {
        let payload = mrs_domain_payload(&["example.com"]);
        let file = make_mrs(MRS_BEHAVIOR_DOMAIN, 1, &payload, &[]);

        for cut in [3, 10, file.len() / 2] {
            assert!(parse_mrs(&file[..cut]).is_err(), "cut at {cut}");
        }
        let err = parse_mrs(&[0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x50, 0x99, 0x99]).unwrap_err();
        assert!(err.to_string().contains("zstd"), "{err}");
    }

    // --- shared helpers ---

    #[test]
    fn ip_range_to_cidrs_splits_unaligned_ranges() {
        // 10.1.2.3..10.1.2.7 needs three prefixes to cover exactly.
        let cidrs = ip_range_to_cidrs(
            "10.1.2.3".parse().unwrap(),
            "10.1.2.7".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            cidrs,
            vec![
                "10.1.2.3/32".to_string(),
                "10.1.2.4/30".to_string(),
            ]
        );
        // Full v4 space collapses to one /0.
        let cidrs = ip_range_to_cidrs(
            "0.0.0.0".parse().unwrap(),
            "255.255.255.255".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(cidrs, vec!["0.0.0.0/0".to_string()]);
        // Mixed families and inverted ranges are rejected.
        assert!(ip_range_to_cidrs(
            "1.2.3.4".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        )
        .is_err());
        assert!(ip_range_to_cidrs(
            "10.0.0.5".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        )
        .is_err());
    }

    #[test]
    fn louds_walk_matches_builder() {
        // Cross-check the shared reader's walk against both builders over
        // the same key set: recovered keys equal the sorted input keys.
        let keys: Vec<Vec<u8>> = ["example.com", "a.b.c", "google.com", "sub.google.com"]
            .iter()
            .map(|s| reverse(s))
            .collect();
        let mut expected = keys.clone();
        expected.sort();

        for built in [build_trie_sing(keys.clone()), build_trie_mrs(keys)] {
            let (leaves, bitmap, labels) = built;
            let trie = LoudsTrie::new(leaves, bitmap, labels).unwrap();
            let mut recovered = trie.keys().unwrap();
            recovered.sort();
            assert_eq!(recovered, expected);
        }
    }

    // --- .mrs writer tests ---

    /// Decompress a store frame exactly like `parse_mrs` does, so the raw
    /// payload bytes can be pinned against the hand-built fixtures.
    fn decompress(frame: &[u8]) -> Vec<u8> {
        let mut dec = ruzstd::decoding::StreamingDecoder::new(frame).unwrap();
        let mut raw = Vec::new();
        dec.read_to_end(&mut raw).unwrap();
        raw
    }

    /// (frame body byte offset, is_last, block_size) for every block after
    /// the fixed-size header (4 magic + 1 descriptor + 1 window + 8 FCS).
    fn frame_blocks(frame: &[u8]) -> Vec<(usize, bool, usize)> {
        assert_eq!(&frame[..4], &[0x28, 0xB5, 0x2F, 0xFD]);
        assert_eq!(frame[4], 0b1100_0000);
        assert_eq!(frame[5], 0x50);
        assert_eq!(
            u64::from_le_bytes(frame[6..14].try_into().unwrap()) as usize,
            decompress(frame).len()
        );
        let mut out = Vec::new();
        let mut pos = 14usize;
        loop {
            let h = u32::from_le_bytes([
                frame[pos],
                frame[pos + 1],
                frame[pos + 2],
                0,
            ]);
            let last = h & 1 == 1;
            let btype = (h >> 1) & 0b11;
            let size = (h >> 3) as usize;
            assert_eq!(btype, 0, "store frame must only contain Raw blocks");
            pos += 3;
            out.push((pos, last, size));
            pos += size;
            if last {
                assert_eq!(pos, frame.len());
                break;
            }
        }
        out
    }

    #[test]
    fn mrs_write_domain_payload_matches_upstream_layout() {
        let patterns = [
            "example.com",
            "+.google.com",
            ".dot.org",
            "*.wild.net",
            "sub.google.com",
        ];
        let file = write_mrs(MrsWriteBehavior::Domain, &patterns).unwrap();

        // Byte-level pin: the decompressed stream must equal the
        // hand-assembled mrs_converter.go + WriteBin layout exactly.
        let mut expected = Vec::new();
        expected.extend_from_slice(&MRS_MAGIC);
        expected.push(MRS_BEHAVIOR_DOMAIN);
        expected.extend_from_slice(&(patterns.len() as i64).to_be_bytes());
        expected.extend_from_slice(&0i64.to_be_bytes());
        expected.extend_from_slice(&mrs_domain_payload(&patterns));
        assert_eq!(decompress(&file), expected);

        // And it must read back through the unchanged reader.
        let set = parse_mrs(&file).unwrap();
        assert_eq!(
            set.exacts,
            vec![
                "example.com".to_string(),
                "google.com".to_string(),
                "sub.google.com".to_string(),
            ]
        );
        assert_eq!(
            set.suffixes,
            vec![
                "dot.org".to_string(),
                "google.com".to_string(),
                "wild.net".to_string(),
            ]
        );
        assert!(set.ip_cidrs.is_empty());
    }

    #[test]
    fn mrs_write_count_counts_valid_rules_not_trie_keys() {
        // "+.a.com" derives two trie keys ("a.com" and "+.a.com") but is
        // ONE inserted rule: the header count is 1 (domain_strategy.go
        // increments count once per successful Insert).
        let file = write_mrs(MrsWriteBehavior::Domain, &["+.a.com"]).unwrap();
        let raw = decompress(&file);
        let count = i64::from_be_bytes(raw[5..13].try_into().unwrap());
        assert_eq!(count, 1);
        let set = parse_mrs(&file).unwrap();
        assert_eq!(set.exacts, vec!["a.com".to_string()]);
        assert_eq!(set.suffixes, vec!["a.com".to_string()]);
    }

    #[test]
    fn mrs_write_ipcidr_payload_matches_upstream_layout() {
        // Non-overlapping input so the hand fixture (which sorts but does
        // not merge) matches the writer's merged output byte for byte.
        let cidrs = ["192.168.0.0/16", "10.0.0.0/8", "2001:db8::/32"];
        let file = write_mrs(MrsWriteBehavior::IpCidr, &cidrs).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&MRS_MAGIC);
        expected.push(MRS_BEHAVIOR_IPCIDR);
        expected.extend_from_slice(&(cidrs.len() as i64).to_be_bytes());
        expected.extend_from_slice(&0i64.to_be_bytes());
        expected.extend_from_slice(&mrs_ipcidr_payload(&cidrs));
        assert_eq!(decompress(&file), expected);

        let set = parse_mrs(&file).unwrap();
        assert_eq!(
            set.ip_cidrs,
            vec![
                "10.0.0.0/8".to_string(),
                "192.168.0.0/16".to_string(),
                "2001:db8::/32".to_string(),
            ]
        );
    }

    #[test]
    fn mrs_write_ipcidr_merges_overlapping_adjacent_and_keeps_families() {
        // Overlapping: 10.1.0.0/16 is inside 10.0.0.0/8.
        let file = write_mrs(MrsWriteBehavior::IpCidr, &["10.1.0.0/16", "10.0.0.0/8"]).unwrap();
        let set = parse_mrs(&file).unwrap();
        assert_eq!(set.ip_cidrs, vec!["10.0.0.0/8".to_string()]);

        // Adjacent: two /25s coalesce into the covering /24.
        let file = write_mrs(MrsWriteBehavior::IpCidr, &["10.0.0.128/25", "10.0.0.0/25"]).unwrap();
        let set = parse_mrs(&file).unwrap();
        assert_eq!(set.ip_cidrs, vec!["10.0.0.0/24".to_string()]);

        // v4 and v6 never merge, even at the edges of their spaces (the
        // v6 /0 exercises the reader's whole-space range path too).
        let file = write_mrs(MrsWriteBehavior::IpCidr, &["::/0", "255.255.255.255/32"]).unwrap();
        let set = parse_mrs(&file).unwrap();
        assert_eq!(
            set.ip_cidrs,
            vec!["255.255.255.255/32".to_string(), "::/0".to_string()]
        );

        // Host bits are masked like RangeOfPrefix.
        let file = write_mrs(MrsWriteBehavior::IpCidr, &["10.1.2.99/24"]).unwrap();
        let set = parse_mrs(&file).unwrap();
        assert_eq!(set.ip_cidrs, vec!["10.1.2.0/24".to_string()]);
    }

    #[test]
    fn mrs_write_large_domain_set_spans_multiple_raw_blocks() {
        // 30k hosts over 97 shared suffixes: the trie shares almost every
        // label, yet the payload still crosses the 64 KiB single-block
        // budget several times over.
        let owned: Vec<String> = (0..30000)
            .map(|i| format!("host{}.example{}.com", i, i % 97))
            .collect();
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        let file = write_mrs(MrsWriteBehavior::Domain, &refs).unwrap();

        let blocks = frame_blocks(&file);
        assert!(blocks.len() > 1, "expected a multi-block frame");
        assert!(blocks.iter().all(|(_, _, size)| *size <= 128 * 1024));
        assert!(blocks[..blocks.len() - 1].iter().all(|(_, _, size)| *size > 0));

        let set = parse_mrs(&file).unwrap();
        assert_eq!(set.exacts.len(), owned.len());
        assert!(set.exacts.contains(&"host29999.example26.com".to_string()));
    }

    #[test]
    fn mrs_write_skips_invalid_rules_and_rejects_empty_sets() {
        // Mixed: valid rules counted, invalid ones skipped with the same
        // semantics as the provider Insert path.
        let file = write_mrs(
            MrsWriteBehavior::Domain,
            &["ok.com", "bad..com", "trail.com/", "no+plus.x", "par*t.x", " lead.com"],
        )
        .unwrap();
        let raw = decompress(&file);
        assert_eq!(i64::from_be_bytes(raw[5..13].try_into().unwrap()), 1);
        let set = parse_mrs(&file).unwrap();
        assert_eq!(set.exacts, vec!["ok.com".to_string()]);

        let file = write_mrs(MrsWriteBehavior::IpCidr, &["10.0.0.0/8", "bogus", "10.0.0.300/24", ":::/32"]).unwrap();
        let set = parse_mrs(&file).unwrap();
        assert_eq!(set.ip_cidrs, vec!["10.0.0.0/8".to_string()]);

        // Upstream's "empty rule" (mrs_converter.go) when nothing is valid.
        let err = write_mrs(MrsWriteBehavior::Domain, &["/"]).unwrap_err();
        assert!(err.to_string().contains("empty rule"), "{err}");
        let err = write_mrs(MrsWriteBehavior::IpCidr, &[]).unwrap_err();
        assert!(err.to_string().contains("empty rule"), "{err}");
    }

    #[test]
    fn mrs_write_domain_validation_mirrors_valid_and_split_domain() {
        // Direct unit pins for the ported validator.
        assert!(valid_and_split_domain("a.b.c").unwrap() == vec!["a", "b", "c"]);
        assert_eq!(
            valid_and_split_domain("ExAmPlE.COM").unwrap(),
            vec!["example", "com"],
            "domains are lower-cased before splitting"
        );
        // ".example.com" splits with an empty first label (dot-wildcard).
        assert_eq!(
            valid_and_split_domain(".example.com").unwrap(),
            vec!["", "example", "com"]
        );
        for bad in [
            "", "a.com.", " a.com", "a.com ", "..", "a..b", "+", "+.a+x.com", "a+.com", "*a.com",
            "a.*b.com", "+a.com",
        ] {
            assert!(valid_and_split_domain(bad).is_err(), "{bad:?} must be rejected");
        }
        // Whole-label wildcards are accepted (DomainSet::Has interprets them).
        assert_eq!(
            valid_and_split_domain("*.a.com").unwrap(),
            vec!["*", "a", "com"]
        );
        assert_eq!(
            valid_and_split_domain("+.a.com").unwrap(),
            vec!["+", "a", "com"]
        );
    }

    #[test]
    fn mrs_write_key_derivation_matches_builder_insert() {
        // "+.x" -> {x, +.x}; ".x" -> {+.x}; "*.x" -> {*.x}; plain -> itself.
        // (reversed encodings compared as recovered strings).
        let recover = |keys: Vec<Vec<u8>>| -> Vec<String> {
            let mut out: Vec<String> = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap().chars().rev().collect())
                .collect();
            out.sort();
            out
        };
        let mut expected_plus: Vec<String> = vec!["x.com".into(), "+.x.com".into()];
        expected_plus.sort();
        assert_eq!(recover(domain_set_keys("+.x.com").unwrap()), expected_plus);
        assert_eq!(
            recover(domain_set_keys(".x.com").unwrap()),
            vec!["+.x.com".to_string()]
        );
        assert_eq!(
            recover(domain_set_keys("*.x.com").unwrap()),
            vec!["*.x.com".to_string()]
        );
        assert_eq!(
            recover(domain_set_keys("x.com").unwrap()),
            vec!["x.com".to_string()]
        );
    }

    #[test]
    fn zstd_store_frame_layout_is_pinned() {
        // Empty payload: exactly one last Raw block of size 0.
        let empty = zstd_store_frame(&[]);
        assert_eq!(
            &empty,
            &[0x28, 0xB5, 0x2F, 0xFD, 0xC0, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]
        );
        assert_eq!(decompress(&empty), Vec::<u8>::new());

        // Small payload: single last block carrying the bytes verbatim.
        let payload = b"mrs-payload-bytes".to_vec();
        let frame = zstd_store_frame(&payload);
        assert_eq!(&frame[..4], &[0x28, 0xB5, 0x2F, 0xFD]);
        assert_eq!(frame[4], 0b1100_0000, "FCS flag 0b11, nothing else set");
        assert_eq!(frame[5], 0x50, "1 MiB window (Exponent 10)");
        assert_eq!(
            u64::from_le_bytes(frame[6..14].try_into().unwrap()),
            payload.len() as u64,
            "FCS is little-endian"
        );
        let block_header = (1u32 | (payload.len() as u32) << 3).to_le_bytes();
        assert_eq!(&frame[14..17], &block_header[..3]);
        assert_eq!(&frame[17..], &payload[..]);
        assert_eq!(decompress(&frame), payload);

        // Exactly one block at the cap, two one byte past it.
        let cap = vec![0xAB; MRS_ZSTD_BLOCK_MAX];
        assert_eq!(frame_blocks(&zstd_store_frame(&cap)).len(), 1);
        let over = vec![0xCD; MRS_ZSTD_BLOCK_MAX + 1];
        let blocks = frame_blocks(&zstd_store_frame(&over));
        assert_eq!(blocks.len(), 2);
        assert!(!blocks[0].1);
        assert_eq!(blocks[0].2, MRS_ZSTD_BLOCK_MAX);
        assert!(blocks[1].1);
        assert_eq!(blocks[1].2, 1);
    }
}
