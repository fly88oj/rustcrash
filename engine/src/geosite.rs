//! geosite.dat reader (the v2ray `GeoSiteList` protobuf format). A
//! hand-rolled varint reader keeps the build free of protoc/prost-build
//! while the format itself is tiny: nested length-delimited messages with
//! one string and one enum field.
//!
//! Forward compatibility follows protobuf semantics (and what v2fly's
//! published files already exercise): UNKNOWN field numbers are SKIPPED
//! by wire type instead of failing the whole file — the real
//! domain-list-community files carry `Domain.attributes` (field 3) which
//! this schema predates — and an unknown DomainType value drops only that
//! domain. Structural corruption (truncated headers, lengths overrunning
//! their container, impossible wire types) still errors.

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
        // checked_add: a corrupt/huge length varint must error, not
        // overflow the index arithmetic (release builds would wrap).
        let end = self.pos.checked_add(len)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }
}

/// One protobuf field header: (field number, wire type).
fn field_header(cur: &mut Cursor<'_>) -> Option<(u32, u8)> {
    let key = cur.varint()?;
    Some(((key >> 3) as u32, (key & 0x7) as u8))
}

/// Skip a field value of the given wire type (protobuf forward-compat:
/// unknown fields are skipped, never fatal). Group markers (3/4) and the
/// reserved wire types (6/7) have no skippable encoding — the file is
/// malformed, not merely newer.
fn skip_field(cur: &mut Cursor<'_>, wire: u8) -> bool {
    match wire {
        0 => cur.varint().is_some(),
        1 => cur.bytes(8).is_some(),
        2 => match cur.varint().and_then(|len| usize::try_from(len).ok()) {
            Some(len) => cur.bytes(len).is_some(),
            None => false,
        },
        5 => cur.bytes(4).is_some(),
        _ => false,
    }
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
            // Unknown top-level fields (a newer GeoSiteList revision):
            // skip by wire type.
            _ => {
                if !skip_field(&mut top, wire) {
                    return Err(Error::config(format!(
                        "geosite.dat: unreadable top-level field {field} wire {wire}"
                    )));
                }
            }
        }
    }
    Ok(out)
}

/// One GeoSite entry: field 1 = code (string), field 2 = Domain (message).
/// A duplicate `code` later in the file merges into the same matcher —
/// v2fly ships `cn` split across several entries in some releases.
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
                // Unknown domain types (a newer schema value) drop only
                // this domain; the rest of the category survives. So do
                // value-less entries — a keyword "" would match every
                // domain (str::contains("")), poisoning the category.
                if let Some((dtype, value)) = parse_domain(domain)?.filter(|(_, v)| !v.is_empty()) {
                    let matcher = out.entry(code).or_default();
                    match dtype {
                        DomainType::Full => matcher.add_exact(&value),
                        DomainType::Domain => matcher.add_suffix(&value),
                        DomainType::Plain => matcher.add_keyword(&value),
                        DomainType::Regex => matcher.add_regex(&value)?,
                    }
                }
            }
            // Unknown entry fields: skip by wire type.
            _ => {
                if !skip_field(&mut cur, wire) {
                    return Err(Error::config(format!(
                        "geosite.dat: unreadable entry field {field} wire {wire}"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// One Domain message: field 1 = type varint, field 2 = value string,
/// field 3 = attributes (v2fly, unread here). Absent field 1 means the
/// proto3 default (Plain) — real files omit it for keyword entries.
/// Returns None for a domain carrying a type value this reader does not
/// know, so the caller skips just that entry.
fn parse_domain(domain: &[u8]) -> Result<Option<(DomainType, String)>> {
    let mut dtype: Option<DomainType> = None;
    let mut dtype_seen = false;
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
                dtype_seen = true;
                dtype = DomainType::from_varint(v);
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
            // Field 3 (attributes) and any future field: skip by wire
            // type.
            _ => {
                if !skip_field(&mut cur, wire) {
                    return Err(Error::config(format!(
                        "geosite.dat: unreadable domain field {field} wire {wire}"
                    )));
                }
            }
        }
    }
    // An explicit type value this schema doesn't know: skip the domain.
    if dtype_seen && dtype.is_none() {
        return Ok(None);
    }
    Ok(Some((dtype.unwrap_or(DomainType::Plain), value)))
}

/// Load a subset of entries by name (loading every entry of the real
/// ~10 MB file costs memory; the engine loads only referenced names, or
/// all when `names` is None).
pub fn load_filtered(
    data: &[u8],
    names: Option<&[String]>,
) -> Result<HashMap<String, DomainMatcher>> {
    let all = parse_geosite(data)?;
    match names {
        None => Ok(all),
        Some(want) => {
            let want: std::collections::HashSet<&str> = want.iter().map(|s| s.as_str()).collect();
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
                domain_msg(3, "full.example"),    // Full
                domain_msg(2, "suffix.example"),  // Domain (suffix)
                domain_msg(0, "plain-key"),       // Plain (keyword)
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
        file.extend_from_slice(&len_delimited(
            1,
            &geosite_msg("keep", &[domain_msg(2, "keep.test")]),
        ));
        file.extend_from_slice(&len_delimited(
            1,
            &geosite_msg("drop", &[domain_msg(2, "drop.test")]),
        ));
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

    // ------------------------------------------------------------------
    // Robustness / forward-compat corpus
    // ------------------------------------------------------------------

    #[test]
    fn unknown_top_level_fields_are_skipped_not_fatal() {
        let mut file = Vec::new();
        // A future GeoSiteList revision's fields between/around known
        // entries: varint, fixed64, fixed32 and length-delimited shapes.
        file.extend_from_slice(&tag(7, 0));
        file.extend_from_slice(&varint(300));
        file.extend_from_slice(&tag(8, 1));
        file.extend_from_slice(&[0xAA; 8]);
        file.extend_from_slice(&tag(9, 5));
        file.extend_from_slice(&[0x00, 0x00, 0x80, 0x3F]);
        file.extend_from_slice(&len_delimited(10, b"future-blob"));
        let entry = geosite_msg("cn", &[domain_msg(2, "skip.example")]);
        file.extend_from_slice(&len_delimited(1, &entry));
        file.extend_from_slice(&tag(5, 0));
        file.extend_from_slice(&varint(1));

        let parsed = parse_geosite(&file).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed["cn"].matches("x.skip.example"));
    }

    #[test]
    fn unknown_entry_fields_are_skipped_not_fatal() {
        // Entry-level future field (varint) after the known pair.
        let mut entry = geosite_msg("geo", &[domain_msg(3, "exact.example")]);
        entry.extend_from_slice(&tag(5, 0));
        entry.extend_from_slice(&varint(42));
        entry.extend_from_slice(&len_delimited(6, b"meta"));

        let file = len_delimited(1, &entry);
        let parsed = parse_geosite(&file).unwrap();
        assert!(parsed["geo"].matches("exact.example"));
    }

    /// The REAL forward-compat case: v2fly's published geosite.dat
    /// files carry `Domain.attributes` (field 3, length-delimited) for
    /// annotated domains like `google.com @cn` — the old reader errored
    /// the whole file on it.
    #[test]
    fn v2fly_domain_attributes_field3_is_skipped() {
        let mut attrs = Vec::new(); // Attribute message: field 1 = name
        attrs.extend_from_slice(&len_delimited(1, b"cn"));
        let mut with_attrs = domain_msg(2, "attr.example");
        with_attrs.extend_from_slice(&len_delimited(3, &attrs));

        let file = len_delimited(
            1,
            &geosite_msg("cn", &[with_attrs, domain_msg(3, "plain.example")]),
        );
        let parsed = parse_geosite(&file).unwrap();
        let cn = &parsed["cn"];
        assert!(cn.matches("attr.example"));
        assert!(cn.matches("plain.example"));
    }

    #[test]
    fn zero_length_entries_and_domains_parse_cleanly() {
        let mut file = Vec::new();
        file.extend_from_slice(&len_delimited(1, &[])); // empty entry
        file.extend_from_slice(&len_delimited(1, &geosite_msg("empty-dom", &[]))); // no domains
                                                                                   // zero-length domain message → proto3 defaults; the empty value
                                                                                   // is dropped (a "" keyword would match everything)
        file.extend_from_slice(&len_delimited(1, &geosite_msg("zl", &[Vec::new()])));
        // Categories with no surviving domains carry no matcher — the
        // observable behavior (matches nothing) is identical to an
        // empty category in v2ray.
        let parsed = parse_geosite(&file).unwrap();
        assert!(!parsed.contains_key("empty-dom"));
        assert!(!parsed.contains_key("zl"));
        // A well-formed category after the empty ones still parses.
        file.extend_from_slice(&len_delimited(
            1,
            &geosite_msg("ok", &[domain_msg(2, "ok.example")]),
        ));
        let parsed = parse_geosite(&file).unwrap();
        assert!(parsed["ok"].matches("x.ok.example"));
    }

    #[test]
    fn zero_length_code_is_kept_but_harmless() {
        let entry = geosite_msg("", &[domain_msg(2, "x.example")]);
        let parsed = parse_geosite(&len_delimited(1, &entry)).unwrap();
        assert!(parsed.contains_key(""));
        assert!(parsed[""].matches("x.example"));
    }

    /// A duplicate category name merges both entries into one matcher
    /// (v2fly splits some categories across multiple top-level entries).
    #[test]
    fn duplicate_category_names_merge() {
        let mut file = Vec::new();
        file.extend_from_slice(&len_delimited(
            1,
            &geosite_msg("dup", &[domain_msg(3, "first.example")]),
        ));
        file.extend_from_slice(&len_delimited(
            1,
            &geosite_msg("DUP", &[domain_msg(2, "second.example")]),
        ));
        // Note: "DUP" upper-case — codes are lowercased, still the same
        // category.
        let parsed = parse_geosite(&file).unwrap();
        assert_eq!(parsed.len(), 1, "duplicate category must merge");
        let m = &parsed["dup"];
        assert!(m.matches("first.example"));
        assert!(m.matches("a.second.example"));
    }

    /// Unknown DomainType value (schema evolved): the domain is skipped,
    /// the file and the rest of the category survive.
    #[test]
    fn unknown_domain_type_skips_only_that_domain() {
        let mut newer = tag(1, 0);
        newer.extend_from_slice(&varint(9)); // a future type value
        newer.extend_from_slice(&len_delimited(2, b"future.example"));

        let file = len_delimited(
            1,
            &geosite_msg("cat", &[newer, domain_msg(2, "known.example")]),
        );
        let parsed = parse_geosite(&file).unwrap();
        let m = &parsed["cat"];
        assert!(m.matches("known.example"));
        assert!(!m.matches("future.example"));
    }

    #[test]
    fn truncated_nested_structures_error() {
        // Tag byte with no length varint.
        let entry = geosite_msg("cn", &[]);
        let mut file = len_delimited(1, &entry);
        file.extend_from_slice(&[0x12]); // field 2 wire 2, then EOF
        assert!(parse_geosite(&file).is_err());

        // Length varint that overruns the nested message.
        let mut domain = Vec::new();
        domain.extend_from_slice(&tag(2, 2));
        domain.extend_from_slice(&varint(50)); // needs 50 bytes…
        domain.extend_from_slice(b"short"); // …has 5
        let file = len_delimited(1, &geosite_msg("cn", &[domain]));
        assert!(parse_geosite(&file).is_err());
    }

    #[test]
    fn malformed_field_headers_error() {
        // Varint that never terminates (11 continuation bytes).
        assert!(parse_geosite(&[0xFE; 11]).is_err());
        // Reserved wire types 6/7 are unreadable, not skippable.
        assert!(parse_geosite(&[0x06]).is_err()); // field 0 wire 6
        assert!(parse_geosite(&[tag(1, 7).as_slice()[0]]).is_err());
        // Deprecated group markers (wire 3) cannot be skipped safely.
        assert!(parse_geosite(&[tag(1, 3).as_slice()[0]]).is_err());
        // Field number 0 is invalid protobuf.
        assert!(parse_geosite(&[0x00]).is_err());
        // A field-1 entry with the wrong wire type (varint) is treated
        // as unknown and skipped — but a truncated varint still errors.
        assert!(parse_geosite(&[0x08]).is_err());
    }

    /// A huge length varint pointing far past EOF must error, not
    /// allocate or hang.
    #[test]
    fn huge_length_varint_errors_instead_of_allocating() {
        let mut file = Vec::new();
        file.extend_from_slice(&tag(1, 2));
        file.extend_from_slice(&varint(u32::MAX as u64 + 1));
        assert!(parse_geosite(&file).is_err());
    }

    /// Unknown-field skip with a huge length is bounded by the file
    /// (bytes() bounds-checks) — error, not OOM.
    #[test]
    fn unknown_field_with_huge_length_errors() {
        let mut file = Vec::new();
        file.extend_from_slice(&tag(9, 2)); // unknown field, len-delimited
        file.extend_from_slice(&varint(u64::MAX));
        assert!(parse_geosite(&file).is_err());
    }

    /// Real-file smoke shape: several categories, mixed entry types,
    /// one with regex; all reachable via load_filtered.
    #[test]
    fn multi_category_file_roundtrip() {
        let mut file = Vec::new();
        file.extend_from_slice(&len_delimited(
            1,
            &geosite_msg(
                "cn",
                &[
                    domain_msg(2, "cn"),
                    domain_msg(3, "www.baidu.com"),
                    domain_msg(0, "taobao"),
                ],
            ),
        ));
        file.extend_from_slice(&len_delimited(
            1,
            &geosite_msg(
                "category-ads-all",
                &[domain_msg(2, "doubleclick.net"), domain_msg(1, "^ads?\\.")],
            ),
        ));
        file.extend_from_slice(&len_delimited(
            1,
            &geosite_msg("private", &[domain_msg(3, "localhost")]),
        ));

        let want = vec!["cn".to_string(), "private".to_string()];
        let got = load_filtered(&file, Some(&want)).unwrap();
        assert_eq!(got.len(), 2);
        assert!(got["cn"].matches("www.baidu.com"));
        assert!(got["cn"].matches("x.taobao.com"));
        assert!(got["private"].matches("localhost"));
        assert!(!got.contains_key("category-ads-all"));
    }
}
