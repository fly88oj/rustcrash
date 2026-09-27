#!/usr/bin/env python3
"""Generate the MINIMAL geodata pair the matrix suite needs, at test
time (nothing binary is committed):

  country.mmdb  a hand-rolled MaxMind DB the engine's maxminddb reader
                parses, mapping four LOOPBACK ranges (the suite's probe
                IPs — everything stays on 127.0.0.0/8 so the relays are
                hermetic) plus the reserved TEST-NET-3 block:
                    127.0.0.99/32, 127.0.127.9/32, 127.126.0.0/16 ->
                        {"country": {"iso_code": "CN"},
                         "autonomous_system": {"number": 65000}}
                    203.0.113.0/24 -> same CN record (the spec's
                        TEST-NET row; never dialed)
                    127.0.128.0/17 -> ASN-only record (no country) so
                        the IP-ASN rule can match something GEOIP,CN
                        does not swallow first.
  geosite.dat   the v2ray GeoSiteList protobuf (the format the engine's
                hand-rolled varint reader parses): one category `cn`
                with two domains (full `cn-full.test`, suffix
                `cn-suffix.test`).

MMDB wire format recap (this is the whole format we need):
  [search tree: node_count nodes x 2 records x record_size bits]
  [16-byte data separator]
  [data section: type-size control bytes; maps, strings, uints]
  [metadata marker \xab\xcd\xefMaxMind.com + metadata map]
Record value v:  v < node_count -> next node;  v == node_count -> miss;
  v > node_count -> data offset = v - node_count - 16.
Control byte: (type << 5) | size_code (3-bit type in the high bits, the
5-bit size in the low ones); types: 2=utf8 string, 5=uint16, 7=map,
9=uint64, 11=array. size_code < 29 is the size; 29/30/31 mean the size
is 29 + the next 1/2/3 bytes.
"""
import struct
import sys

# ---- data section encoding -------------------------------------------------

def ctrl(t: int, size: int) -> bytes:
    assert size < 29
    return bytes([((t & 0x07) << 5) | size])

def mm_str(s: str) -> bytes:
    b = s.encode()
    return ctrl(2, len(b)) + b

def mm_uint(v: int) -> bytes:
    # uint16 when it fits (mihomo's own writer behavior), else uint64
    if v < 1 << 16:
        out = v.to_bytes(2, "big")
        return ctrl(5, 2) + out
    out = v.to_bytes(8, "big")
    return ctrl(9, 8) + out

def mm_map(pairs) -> bytes:
    body = b"".join(mm_str(k) + v for k, v in pairs)
    assert len(pairs) < 29
    return ctrl(7, len(pairs)) + body

def record_cn() -> bytes:
    return mm_map([
        ("country", mm_map([("iso_code", mm_str("CN"))])),
        ("autonomous_system", mm_map([("number", mm_uint(65000))])),
    ])

def record_asn_only() -> bytes:
    # GeoLite2-ASN shape: autonomous_system_number at the TOP level
    # (engine rule.rs GeoLookups::asn reads val["autonomous_system_number"]).
    return mm_map([("autonomous_system_number", mm_uint(65000))])

# ---- search tree -----------------------------------------------------------

def build_tree(prefixes, node_count_hint=None):
    """prefixes: list of (network int, prefix len, data offset).
    Builds a binary trie over the v4 space (ip_version=4). Returns
    (tree bytes, node_count). Every non-matching branch points at
    node_count (miss)."""
    # Collect nodes: dict node_id -> (left, right). Build top-down with
    # an explicit recursive constructor over bit positions 0..31.
    nodes = []  # list of [left, right]

    def insert(net: int, plen: int, value: int):
        # path bits
        path = [(net >> (31 - i)) & 1 for i in range(plen)]
        if not path:
            raise ValueError("empty prefix unsupported")
        # walk/create
        cur = 0
        for i, bit in enumerate(path):
            last = i == len(path) - 1
            while len(nodes) <= cur:
                nodes.append([MISS, MISS])
            if last:
                nodes[cur][bit] = value
            else:
                nxt = nodes[cur][bit]
                if nxt is MISS or nxt >= NODE_DATA_BASE:
                    nxt = len(nodes)
                    nodes.append([MISS, MISS])
                    nodes[cur][bit] = nxt
                cur = nxt

    # two passes: node_count must be known for MISS; do it iteratively —
    # reserve a generous count first, then rewrite. Simpler: build with a
    # placeholder, count, then fix. We do the count math here once.
    return nodes

MISS = -1  # placeholder, replaced once node_count is known
NODE_DATA_BASE = 1 << 30  # placeholder

def build_mmdb(prefixes: list) -> bytes:
    """prefixes: list of (dotted-net-as-int, plen, data-bytes-fn)."""
    # Data section first (offsets are relative to its start).
    data = b""
    placements = []  # (net, plen, record_value) filled after node_count
    offsets = []
    for net, plen, dbytes in prefixes:
        offsets.append((net, plen, len(data), dbytes))
        data += dbytes

    # Build the trie structure with symbolic node ids.
    nodes: list[list] = []

    def miss():
        return ("miss",)

    def ensure(cur):
        while len(nodes) <= cur:
            nodes.append([miss(), miss()])

    for net, plen, doff, _ in offsets:
        cur = 0
        for i in range(plen):
            bit = (net >> (31 - i)) & 1
            ensure(cur)
            last = i == plen - 1
            if last:
                nodes[cur][bit] = ("data", doff)
            else:
                nxt = nodes[cur][bit]
                if not isinstance(nxt, tuple):
                    cur = nxt
                    continue
                # miss or data placeholder -> branch node
                new = len(nodes)
                nodes.append([miss(), miss()])
                nodes[cur][bit] = new
                cur = new

    node_count = len(nodes)
    # record size 24 bits => 6 bytes per node
    tree = bytearray()
    for left, right in nodes:
        for side in (left, right):
            if isinstance(side, tuple):
                if side[0] == "miss":
                    val = node_count
                else:
                    val = node_count + 16 + side[1]
            else:
                val = side
            assert val < (1 << 24)
            tree += val.to_bytes(3, "big")
    assert len(tree) == node_count * 6

    metadata = mm_map([
        ("node_count", mm_uint(node_count)),
        ("record_size", mm_uint(24)),
        ("ip_version", mm_uint(4)),
        ("binary_format_major_version", mm_uint(2)),
        ("binary_format_minor_version", mm_uint(0)),
        ("build_epoch", mm_uint(1)),
        ("database_type", mm_str("GeoLite2-Country")),
        # empty array; types > 7 use the extended form: control byte with
        # type 0, then one byte carrying (real type - 7) — the rust
        # maxminddb reader computes byte + 7, so array (11) is 0x04.
        ("languages", b"\x00\x04"),
        ("description", mm_map([("en", mm_str("matrix test"))])),
    ])
    out = bytes(tree) + b"\x00" * 16 + data + b"\xab\xcd\xefMaxMind.com" + metadata
    return out

def ip_int(s: str) -> int:
    a, b, c, d = (int(x) for x in s.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d

def build_geosite() -> bytes:
    """v2ray GeoSiteList protobuf:
    message GeoSiteList { repeated GeoSite entry = 1; }
    message GeoSite { string country_code = 1; repeated Domain domain = 2; }
    message Domain { Type type = 1; string value = 2; }
    Type: 0 Plain, 1 Regex, 2 Domain(suffix), 3 Full."""
    def varint(v: int) -> bytes:
        out = b""
        while True:
            b7 = v & 0x7F
            v >>= 7
            out += bytes([b7 | (0x80 if v else 0)])
            if not v:
                return out

    def ld_field(num: int, payload: bytes) -> bytes:
        return varint((num << 3) | 2) + varint(len(payload)) + payload

    def vi_field(num: int, v: int) -> bytes:
        return varint((num << 3) | 0) + varint(v)

    def domain(dtype: int, value: str) -> bytes:
        return vi_field(1, dtype) + ld_field(2, value.encode())

    # ONE Domain message per field-2 entry — the engine's parse_domain
    # keeps only one (type, value) pair per submessage.
    geosite = (
        ld_field(1, b"cn")
        + ld_field(2, domain(3, "cn-full.test"))
        + ld_field(2, domain(2, "cn-suffix.test"))
    )
    return ld_field(1, geosite)

def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/geo"
    import os
    os.makedirs(outdir, exist_ok=True)

    prefixes = [
        (ip_int("127.0.0.99"), 32, record_cn()),
        (ip_int("127.0.127.9"), 32, record_cn()),
        (ip_int("127.126.0.0"), 16, record_cn()),
        (ip_int("203.0.113.0"), 24, record_cn()),
        (ip_int("127.0.128.0"), 17, record_asn_only()),
    ]
    mmdb = build_mmdb(prefixes)
    with open(os.path.join(outdir, "country.mmdb"), "wb") as f:
        f.write(mmdb)
    with open(os.path.join(outdir, "geosite.dat"), "wb") as f:
        f.write(build_geosite())
    print(f"generated {outdir}/country.mmdb ({len(mmdb)} bytes) "
          f"and {outdir}/geosite.dat")
    return 0

if __name__ == "__main__":
    sys.exit(main())
