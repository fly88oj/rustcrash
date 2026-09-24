//! geosite.dat reader (the v2ray `GeoSiteList` protobuf format). A
//! hand-rolled varint reader keeps the build free of protoc/prost-build
//! while the format itself is tiny: nested length-delimited messages with
//! one string and one enum field.

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::rule::DomainMatcher;

/// Domain entry types in the v2ray schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainType {
    Plain,
    Regex,
    Domain,
    Full,
}

impl DomainType {
    fn from_varint(v: u64) -> Option<Self> {
        match v {
            0 => Some(DomainType::Plain),
            1 => Some(DomainType::Regex),
            2 => Some(DomainType::Domain),
            3 => Some(DomainType::Full),
            _ => None,
        }
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn varint(&mut self) -> Option<u64> {
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

    fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let out = self.data.get(self.pos..self.pos + len)?;
        self.pos += len;
        Some(out)
    }
}

/// One protobuf field header: (field number, wire type).
fn field_header(cur: &mut Cursor<'_>) -> Option<(u32, u8)> {
    let key = cur.varint()?;
    Some(((key >> 3) as u32, (key & 0x7) as u8))
}

/// Parse the whole file into name → matcher entries.
pub fn parse_geosite(data: &[u8]) -> Result<HashMap<String, DomainMatcher>> {
    let mut out: HashMap<String, DomainMatcher> = HashMap::new();
    let mut top = Cursor::new(data);
    while !top.eof() {
        let Some((field, wire)) = field_header(&mut top) else {
            return Err(Error::config("geosite.dat: truncated field header"));
        };
        match (field, wire) {
            (1, 2) => {
                let Some(len) = top.varint() else {
                    return Err(Error::config("geosite.dat: bad entry length"));
                };
                let Some(entry) = top.bytes(len as usize) else {
                    return Err(Error::config("geosite.dat: entry overruns file"));
                };
                parse_entry(entry, &mut out)?;
            }
            _ => {
                return Err(Error::config(format!(
                    "geosite.dat: unexpected top-level field {field} wire {wire}"
                )))
            }
        }
    }
    Ok(out)
}

/// One GeoSite entry: field 1 = code (string), field 2 = Domain (message).
fn parse_entry(entry: &[u8], out: &mut HashMap<String, DomainMatcher>) -> Result<()> {
    let mut code: Option<String> = None;
    let mut cur = Cursor::new(entry);
    while !cur.eof() {
        let Some((field, wire)) = field_header(&mut cur) else {
            return Err(Error::config("geosite.dat: truncated entry"));
        };
        match (field, wire) {
            (1, 2) => {
                let Some(len) = cur.varint() else {
                    return Err(Error::config("geosite.dat: bad code length"));
                };
                let Some(bytes) = cur.bytes(len as usize) else {
                    return Err(Error::config("geosite.dat: code overruns entry"));
                };
                code = Some(
                    String::from_utf8(bytes.to_vec())
                        .map_err(|_| Error::config("geosite.dat: code not utf-8"))?
                        .to_ascii_lowercase(),
                );
            }
            (2, 2) => {
                let Some(len) = cur.varint() else {
                    return Err(Error::config("geosite.dat: bad domain length"));
                };
                let Some(domain) = cur.bytes(len as usize) else {
                    return Err(Error::config("geosite.dat: domain overruns entry"));
                };
                let code = code
                    .clone()
                    .ok_or_else(|| Error::config("geosite.dat: domain before code"))?;
                let (dtype, value) = parse_domain(domain)?;
                let matcher = out.entry(code).or_default();
                match dtype {
                    DomainType::Full => matcher.add_exact(&value),
                    DomainType::Domain => matcher.add_suffix(&value),
                    DomainType::Plain => matcher.add_keyword(&value),
                    DomainType::Regex => matcher.add_regex(&value)?,
                }
            }
            _ => return Err(Error::config("geosite.dat: unexpected entry field")),
        }
    }
    Ok(())
}

/// One Domain message: field 1 = type varint, field 2 = value string.
fn parse_domain(domain: &[u8]) -> Result<(DomainType, String)> {
    let mut dtype = DomainType::Plain;
    let mut value = String::new();
    let mut cur = Cursor::new(domain);
    while !cur.eof() {
        let Some((field, wire)) = field_header(&mut cur) else {
            return Err(Error::config("geosite.dat: truncated domain"));
        };
        match (field, wire) {
            (1, 0) => {
                let Some(v) = cur.varint() else {
                    return Err(Error::config("geosite.dat: bad type varint"));
                };
                dtype = DomainType::from_varint(v)
                    .ok_or_else(|| Error::config(format!("geosite.dat: unknown domain type {v}")))?;
            }
            (2, 2) => {
                let Some(len) = cur.varint() else {
                    return Err(Error::config("geosite.dat: bad value length"));
                };
                let Some(bytes) = cur.bytes(len as usize) else {
                    return Err(Error::config("geosite.dat: value overruns"));
                };
                value = String::from_utf8(bytes.to_vec())
                    .map_err(|_| Error::config("geosite.dat: value not utf-8"))?
                    .to_ascii_lowercase();
            }
            _ => return Err(Error::config("geosite.dat: unexpected domain field")),
        }
    }
    Ok((dtype, value))
}

/// Load a subset of entries by name (loading every entry of the real
/// ~10 MB file costs memory; the engine loads only referenced names, or
/// all when `names` is None).
pub fn load_filtered(data: &[u8], names: Option<&[String]>) -> Result<HashMap<String, DomainMatcher>> {
    let all = parse_geosite(data)?;
    match names {
        None => Ok(all),
        Some(want) => {
            let want: std::collections::HashSet<&str> =
                want.iter().map(|s| s.as_str()).collect();
            Ok(all
                .into_iter()
                .filter(|(k, _)| want.contains(k.as_str()))
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal protobuf encoder for fixtures.
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

    fn tag(field: u32, wire: u8) -> Vec<u8> {
        varint(((field as u64) << 3) | wire as u64)
    }

    fn len_delimited(field: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = tag(field, 2);
        out.extend_from_slice(&varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    fn domain_msg(dtype: u64, value: &str) -> Vec<u8> {
        let mut msg = tag(1, 0);
        msg.extend_from_slice(&varint(dtype));
        msg.extend_from_slice(&len_delimited(2, value.as_bytes()));
        msg
    }

    fn geosite_msg(code: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut msg = len_delimited(1, code.as_bytes());
        for d in domains {
            msg.extend_from_slice(&len_delimited(2, d));
        }
        msg
    }

    #[test]
    fn parses_all_domain_types() {
        let mut file = Vec::new();
        let entry = geosite_msg(
            "cn",
            &[
                domain_msg(3, "full.example"),   // Full
                domain_msg(2, "suffix.example"), // Domain (suffix)
                domain_msg(0, "plain-key"),      // Plain (keyword)
                domain_msg(1, "^re\\d+\\.test$"), // Regex
            ],
        );
        file.extend_from_slice(&len_delimited(1, &entry));
        let other = geosite_msg("ads", &[domain_msg(2, "ads.example")]);
        file.extend_from_slice(&len_delimited(1, &other));

        let parsed = parse_geosite(&file).unwrap();
        assert_eq!(parsed.len(), 2);
        let cn = &parsed["cn"];
        assert!(cn.matches("full.example"));
        assert!(!cn.matches("x.full.example"));
        assert!(cn.matches("a.suffix.example"));
        assert!(cn.matches("suffix.example"));
        assert!(cn.matches("has-plain-key.test"));
        assert!(cn.matches("re42.test"));
        assert!(!cn.matches("nope.test"));
        assert!(parsed["ads"].matches("ads.example"));
    }

    #[test]
    fn load_filtered_keeps_only_wanted() {
        let mut file = Vec::new();
        file.extend_from_slice(&len_delimited(1, &geosite_msg("keep", &[domain_msg(2, "keep.test")])));
        file.extend_from_slice(&len_delimited(1, &geosite_msg("drop", &[domain_msg(2, "drop.test")])));
        let want = vec!["keep".to_string()];
        let filtered = load_filtered(&file, Some(&want)).unwrap();
        assert!(filtered.contains_key("keep"));
        assert!(!filtered.contains_key("drop"));
        let all = load_filtered(&file, None).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn rejects_truncated_files() {
        assert!(parse_geosite(&[]).is_ok()); // empty file = empty map
        assert!(parse_geosite(&[0x0A]).is_err()); // tag then EOF
        assert!(parse_geosite(&[0x0A, 0x05, b'a']).is_err()); // length overrun
    }
}
