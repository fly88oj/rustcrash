# Porting Audit — mihomo / sing-box → rustcrash-engine

File-by-file comparison of upstream feature surface against the Rust engine,
performed against `MetaCubeX/mihomo` (branch `Alpha`) and `SagerNet/sing-box`
(branch `testing`), 2026-09-23.

Status legend:

- ✅ ported (Rust-native, behavior-equivalent for the supported subset)
- 🟡 partial (core path works; listed sub-features missing)
- ⛔ deliberate rejection — fails loudly at config load with a precise error
  (policy from phase 1: never silently ignore an unsupported option)
- ❌ missing (candidate for a future pass)
- ➖ out of scope (platform/manager plumbing that has no engine equivalent)

## 1. mihomo (`MetaCubeX/mihomo`, 982 Go files)

### adapter/outbound/ (protocol clients)

| Upstream file | Engine module | Status |
|---|---|---|
| shadowsocks.go | `proto/shadowsocks.rs` (AEAD + 2022 BLAKE3) | ✅ |
| vmess.go | `proto/vmess.rs` (AEAD, ws/httpupgrade transport) | ✅ |
| vless.go | `proto/vless.rs` | ✅ |
| trojan.go | `proto/trojan.rs` | ✅ |
| socks5.go | `proto/socks.rs` + `outbound.rs` | ✅ |
| http.go | `proto/httpx.rs` | ✅ |
| direct.go, reject.go | `outbound.rs` (DIRECT/REJECT/REJECT-DROP/PASS/COMPATIBLE) | ✅ |
| base.go, util.go, rematch.go | `outbound.rs` Registry | ✅ (no rematch hook) |
| dns.go | `dns/resolver.rs` (dns-out via engine DNS) | 🟡 no `dns` as a *proxied outbound* — resolved in-process |
| hysteria.go, hysteria2.go | — | ❌ QUIC stack (planned) |
| tuic.go | — | ❌ QUIC stack (planned) |
| wireguard.go, tailscale.go, easytier.go, zerotier.go | — | ❌ (wireguard = `boringtun`-class work; others niche) |
| ssh.go, snell.go, mieru.go, anytls.go, jls.go, restls.go, shadowquic.go, shadowtls.go, sudoku.go, gost_relay.go, masque.go, openvpn.go, tlsmirror.go, trusttunnel.go, ech.go | — | ⛔/❌ niche transports; ssh/snell configs fail with "not supported yet" |
| reality.go (utls/reality) | — | ⛔ explicit config error (`reality-opts` rejected — no TLS-fingerprint mimicry in rustls) |

### adapter/outboundgroup/

| Upstream | Engine | Status |
|---|---|---|
| selector, urltest, fallback, loadbalance | `outbound.rs` GroupPolicy | ✅ |
| groupbase (health-check URL, expected-status, lazy) | url-test prober | 🟡 no lazy/expected-status filters |

### listener/ (inbounds)

| Upstream | Engine | Status |
|---|---|---|
| mixed, http, socks | `inbound/{mixed,http,socks}.rs` | ✅ |
| redir (Linux NAT) | `inbound/redir.rs` (SO_ORIGINAL_DST) | ✅ |
| tproxy (Linux) | `inbound/tproxy.rs` (TCP+UDP transparent) | ✅ |
| sing_tun (TUN device) | — | ⛔ config-time hard error (needs a netlink/wintun layer; documented) |
| sing_shadowsocks / sing_hysteria2 / anytls / vless / vmess / trojan / tuic / shadowtls / snell / jls / restls server listeners | — | ❌ server-side inbounds (acting as proxy server) out of current scope |
| hysteria2_realm | — | ❌ (same) |

### dns/

| Upstream | Engine | Status |
|---|---|---|
| resolver/client (cache, fallback, policy) | `dns/resolver.rs` | 🟡 cache + ordered upstreams ✅; `nameserver-policy` per-domain routing ❌; fallback geoip-verification ❌ |
| udp/tcp upstream | `dns/upstream.rs` | ✅ |
| dot.go | `dns/upstream.rs` `tls://` | ✅ |
| doh.go | `dns/upstream.rs` `https://` (RFC 8488, h1.1, Content-Length + chunked) | ✅ |
| doq.go (QUIC), DoH3 | — | ❌ QUIC stack |
| dhcp.go, system.go, mdx | — | ❌ |
| enhancer (fake-ip) | `dns/fakeip.rs` | ✅ (pool + reverse + filter) |
| hosts | `config.rs` DnsConfig.hosts + resolver override | ✅ |
| edns0_subnet.go | — | ❌ |
| rcode/filters | wire.rs | 🟡 NOERROR/NXDOMAIN only |

### rules/

| Upstream | Engine (`rule.rs`) | Status |
|---|---|---|
| domain / suffix / keyword / regex | Domain*, DomainRegex | ✅ |
| domain_wildcard | DomainWildcard → anchored regex (`*` any run, `?` one char) | ✅ |
| ipcidr (+src), geoip, geosite, rule-set | IpCidr/GeoIp/Geosite/RuleSet | ✅ (IP-CIDR now pre-resolves domain targets like mihomo unless no-resolve; rule-set yaml/text; **mrs binary** ❌) |
| port.go (SRC/DST ranges) | PortSrc/PortDst | ✅ |
| process.go | Process (name/path; PATH matches exactly) via `process.rs` /proc walk (TCP+UDP tables) | ✅ |
| in_name.go | InName | ✅ |
| in_type/in_user/uid/dscp/ipasn/ipsuffix/network_type | — | ❌ (IN-TYPE/UID/DSCP/IP-ASN/IP-SUFFIX in flight) |
| logic/logic.go AND/OR/NOT (+SUB-RULE bundles) | Logic{And,Or,Not} — NOT takes exactly one sub-rule | ✅; ✅ SUB-RULE with mihomo's real `SUB-RULE,<condition>,<bundle>` syntax (each bundle rule gated by the condition, keeping its own outbound) |
| final.go (MATCH) | MatchAll | ✅ |
| provider/ classical+domain+ipcidr strategies | RuleSets Classical/Domain/IpCidr | ✅ (srs/mrs binary readers in flight) |

### transport/ (outbound wire transports)

| Upstream | Engine (`transport.rs`) | Status |
|---|---|---|
| v2raywebsocket (ws + early-data) | `ws_connect` | 🟡 no 0-RTT early-data path |
| **httpupgrade** (via ws-opts convention) | `httpupgrade_connect` | ✅ (this audit pass) |
| gun / v2raygrpc | — | ❌ gRPC |
| simple-obfs / sip003 plugins | — | ⛔ config error |
| vmess AEAD ciphers | `proto/vmess.rs` | ✅ aes-128-gcm / chacha20-poly1305 / none / auto |
| shadowtls / snell / hysteria core | — | ❌ |

### component/sniffer/

| Upstream | Engine (`sniffer.rs`) | Status |
|---|---|---|
| tls_sniffer | `sniff_tls` (ClientHello SNI walk) | ✅ |
| http_sniffer | `sniff_http` (method + Host, port strip) | ✅ |
| quic_sniffer | — | ❌ (needs QUIC Initial decryption; planned) |
| dispatcher (override-destination, skip-domain, force-domain, ports) | `app.rs` relay_tcp + SniffConfig | 🟡 override+skip ✅; force-domain/ports-gating ❌ |

### tunnel/ + config/

| Upstream | Engine | Status |
|---|---|---|
| tunnel.go (mode rule/global/direct) | app.rs route_with + RuleMode | ✅ |
| statistic | `stats.rs` + Clash API connections | ✅ |
| config/config.go (YAML dialect) | `config_mihomo.rs` | 🟡 supported subset; unknown keys ignored, unsupported features hard-error |
| external-controller API | `api.rs` | 🟡 proxies/connections/rules/traffic/mode/logs/configs subset |

## 2. sing-box (`SagerNet/sing-box`)

### protocol/ (inbound+outbound halves)

| Upstream | Engine | Status |
|---|---|---|
| shadowsocks/outbound | ✅ (2022 + AEAD) |
| vmess / vless / trojan / socks / http / mixed outbound | ✅ |
| direct / block (=REJECT) / dns outbounds | ✅ (dns answered in-process) |
| group (selector/urltest) | ✅ |
| hysteria / hysteria2 / tuic | ❌ QUIC (planned) |
| anytls / shadowtls / naive / snell / ssh / tor / wireguard / tailscale / bridge / cloudflare / tun | ❌/⛔ niche or platform |
| all `inbound.go` server halves | ❌ server-side scope |

### transport/

| Upstream | Engine | Status |
|---|---|---|
| v2raywebsocket | ✅ | |
| v2rayhttpupgrade | ✅ (this audit pass) | |
| v2raygrpc / v2raygrpclite / v2rayquic (gun) | ❌ | |
| simple-obfs / sip003 | ⛔ | |
| wireguard | ❌ | |

### route/ + option/rule*.go

| Upstream | Engine | Status |
|---|---|---|
| domain family, ip_cidr, source_ip_cidr, port, source_port, ip_is_private | `rule.rs` + `config_singbox.rs` conversion | ✅ |
| network / inbound (tag) / process_name / process_path | Network/InName/Process | ✅ (this audit pass) |
| clash_mode | ClashMode | ✅ |
| invert | NOT-wrapping in conversion | ✅ (this audit pass) |
| logical and/or (nested) | Logic via nested_eval | ✅ (this audit pass) |
| cross-field AND / in-field OR semantics | combine_groups | ✅ (this audit pass — was previously wrong: plain OR lines) |
| rule_set (.srs binary) | ⛔ explicit error (inline domains/ip_cidr instead) |
| user / package_name (android) / network_type (wifi/cellular) | ❌ |
| rule *actions* (sniff/resolve/hijack-dns/route-options/reject variants) | 🟡 route+reject only; sniff is config-level |
| dns rules (per-server routing, rewrite_ttl, client_subnet, disable_cache) | ❌ |
| fakeip store persistence (bbolt) | memory-only | 🟡 |

### dns/

| Upstream | Engine | Status |
|---|---|---|
| udp/tcp (with `tcp://` scheme), DoT `tls://`, DoH `https://` | `dns/upstream.rs` | ✅ |
| hosts (string or array) | ✅ | |
| fakeip transport | ✅ | |
| dhcp / local / quad100/resolved | ❌ | |
| DoH3/DoQ | ❌ QUIC | |
| edns0 client_subnet | ❌ | |

### common/sniff/

| Upstream | Engine | Status |
|---|---|---|
| tls.go / http.go | `sniffer.rs` | ✅ |
| quic.go (+internal/qtls) | ❌ planned | |
| dtls.go / bittorrent.go / dns.go sniffers | ❌ (protocol-classification rules not supported) |

### experimental/clashapi

Proxies/connections/rules/traffic/mode/logs subset ✅; websocket traffic streaming 🟡 (polling only); v2rayapi ❌.

## 3. Rust-native advantages over the Go originals (deliberate design deltas)

1. **One binary, two dialects** — cargo features `engine-mihomo` / `engine-singbox`
   compile the same data plane under either config language; upstream needs two programs.
2. **Memory safety without GC** — protocol parsers (`vmess`, `ss2022`, `vless`,
   `wire.rs`, TLS/HTTP sniffers) are hand-rolled zero-copy byte parsers the
   compiler proves exhaustively; no `net.Conn` interface boxing per hop
   (a single `BoxProxyStream` per relay side).
3. **Async without goroutine-per-packet** — tokio tasks per connection; UDP
   sessions multiplex one socket per outbound with mpsc fan-out (Go originals
   allocate a goroutine + timer per UDP NAT entry).
4. **Typestate config** — unsupported options are *rejected by the type/parser*
   with precise errors instead of Go's `interface{}` + runtime `if` chains that
   silently default.
5. **No cgo, no CGO_TLS** — rustls + ring; static musl binaries cross-compile
   for every target the CI matrix ships.
6. **Hermetic verification** — 128 engine unit tests (636 workspace-wide
   per feature set) + dual e2e suites (29 engine-interop + 35
   external-kernel/firewall checks, all green) against real mihomo
   binaries as protocol oracles run per-commit in one container.

## 4. Prioritized remaining gaps

| Priority | Gap | Size |
|---|---|---|
| P0 | QUIC stack (quinn): hysteria2 + tuic outbounds, DoH3/DoQ, quic sniffer | large |
| P0 | gRPC (gun) transport | medium |
| P1 | nameserver-policy + dns rules; edns0 client_subnet | medium |
| P1 | IN-TYPE/UID/DSCP/IP-ASN matchers | small each |
| P1 | sniffer force-domain/ports; ws early-data; QUIC sniffer | small/medium |
| P2 | .srs / .mrs binary rule-set readers | medium |
| P2 | server-side inbounds (act as a proxy server) | large |
| P3 | wireguard / ssh / snell / anytls / shadowtls ecosystem | large |
| P3 | utls fingerprint mimicry, reality | rejected (rustls policy) |
| P3 | TUN device inbounds | rejected for now (netlink layer) |
