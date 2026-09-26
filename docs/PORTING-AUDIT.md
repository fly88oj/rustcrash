# Porting Audit — mihomo / sing-box → rustcrash-engine

File-by-file comparison of upstream feature surface against the Rust engine,
performed against `MetaCubeX/mihomo` (branch `Alpha`) and `SagerNet/sing-box`
(branch `testing`), 2026-09-23.

**Product framing: this project is a drop-in replacement for ShellCrash +
mihomo/sing-box.** Every upstream feature a user may rely on is therefore
in scope — nothing is permanently "rejected"; unimplemented features are
PRIORITY items (§4) that fail loudly at config load in the meantime so a
migration never silently changes behavior.

Status legend:

- ✅ ported (Rust-native, behavior-equivalent for the supported subset)
- 🟡 partial (core path works; listed sub-features missing)
- ⏳ not yet implemented — fails loudly at config load with a precise error
  naming the alternative or the tracking priority (never silently ignored)
- ❌ missing (candidate for a future pass)
- ➖ out of scope (platform/manager plumbing that has no engine equivalent)

## 1. mihomo (`MetaCubeX/mihomo`, 982 Go files)

### adapter/outbound/ (protocol clients)

| Upstream file | Engine module | Status |
|---|---|---|
| shadowsocks.go | `proto/shadowsocks.rs` (AEAD + 2022 BLAKE3) | ✅ |
| vmess.go | `proto/vmess.rs` (AEAD, ws/httpupgrade transport) | ✅ |
| vless.go | `proto/vless.rs` + `proto/vision.rs` (xtls-rprx-vision framing; **full direct splice on reality outers**: `Tls13Stream` rebind API drains read-ahead + re-binds both directions to the raw transport, Xray `proxy/proxy.go` direct-copy parity; opaque rustls outers keep framing mode) — wave-12 LIVE-FIX: the splice path now consumes the VLESS response header (version+addons) before the vision frames (e2e 4g against real Xray) | ✅ |
| trojan.go | `proto/trojan.rs` | ✅ |
| socks5.go | `proto/socks.rs` + `outbound.rs` | ✅ |
| http.go | `proto/httpx.rs` | ✅ |
| direct.go, reject.go | `outbound.rs` (DIRECT/REJECT/REJECT-DROP/PASS/COMPATIBLE) | ✅ |
| base.go, util.go, rematch.go | `outbound.rs` Registry | ✅ (no rematch hook) |
| dns.go | `dns/resolver.rs` + the `type: dns` OUTBOUND (wave-12: an in-process duplex answered by the engine resolver + the UDP datagram echo — mihomo's RelayDnsConn/RelayDnsPacket) | ✅ |
| hysteria2.go | `proto/hysteria2.rs` over quinn (HTTP/3-style auth, salamander obfs, datagram UDP) | ✅ + wave-12 LIVE-FIX: the TCP response frame is consumed lazily on first read (the sing server writes it together with the first data — blocking up front deadlocks); QPACK dynamic machinery added (RFC 9204) after the real server's Date header exposed a T-bit misread |
| tuic.go | `proto/tuic.rs` v5 (TLS-exporter token auth, native/quic UDP relay, heartbeats, dissociate) | ✅ this pass |
| wireguard.go | `proto/wireguard.rs` — hand-rolled Noise_IKpsk2 handshake (KDF/MAC1/2 step-cited from the whitepaper), transport keys, anti-replay, cookie consumption, keepalive/rekey timers, smoltcp client stack for TCP+UDP, mihomo `reserved` bytes per sing-wireguard `client_bind.go` | ✅ this pass (self-consistent: verified against an in-test noise responder; IPv6 inner stack ✅ wave-7 (dual-stack interface, per-family source selection, v4/v6 share one tunnel) |
| tailscale.go | `proto/tailscale.rs` + `tailscale/{noise,controlhttp,derp,tailcfg,state,control,wg}.rs` — wave-11: the ipn layer (machine/node key state store, /key fetch, RegisterRequest auth-key login, the /map long-poll with delta application, NetMap cryptokey routing) + the data plane (WireGuard session over direct UDP or DERP relay, smoltcp stack; e2e TCP relay via both paths against the engine's own WG endpoint). tailcfg is JSON, not protobuf (wire fact from controlclient/direct.go) | 🟡 wave-13: disco IN (the bounded magicsock subset — ping/pong path confirmation, call-me-maybe via DERP, pong-confirmed addresses override DERP sessions) + key-expiry renewal IN (OldNodeKey re-register flow, RFC3339 expiry detection, tunnel cache re-key); remaining: the tailnet packet filter (inbound ACLs — no traffic to filter on an outbound) + browser login (headless) — both out of scope for a proxy outbound |
| easytier.go | `proto/easytier.rs` — wave-10 config surface + component port; wave-11 MILESTONE 1: the direct-TCP peer tunnel (framing, plain-mode handshake with network digest, AES-GCM/ChaCha packet encryption byte-parity-proven against upstream's NIST vector, keepalive/backoff, IP-frame seam) — connect() now joins one peer for real | 🟡 wave-14 M4 IN: the QUIC transport (the quinn-plaintext seam re-implemented in-tree — SeaHash-tagged, no TLS; wire-identical vs the real binary) + the WS/WSS transport (RFC 6455 hand-rolled, PMH-framed binary messages, in-process P-256 DER cert) — **8/8 real-binary interop tests pass** (TCP/UDP/QUIC/WS × dial/listen). Remaining: wg transport (boringtun recipe mapped), secure mode payload layer, relay/foreign networks, multi-hop SPF, IPv6 overlay |
| zerotier.go | `proto/zerotier.rs` — wave-14: the RUST CORE MILESTONE 1 LANDED (no C): identity generation/validation (memory-hard hashcash, cross-validated vs zerotier-go's known-good identity), the armored packet codec (hand-rolled Salsa20/12+Poly1305, eSTREAM/BouncyCastle-pinned; AES-GMAC-SIV avoided by advertising protocol 11), HELLO/OK identity handshake, the controller netconf conversation (LZ4 decode + chunk reassembly + controller Ed25519 verify — ZeroTier's sig is RFC-8032 over a SHA-512 pre-digest, ring covers it). PoW identity = 0.71s release. Config bugs fixed: hex10 addresses, 0xff ad-hoc | 🟡 (connect() still NOT_PORTED: node runtime — UDP loop/WHOIS/fragmentation/planet parse — staged in the map; none of it needs C) |
| tor | — | N/A upstream: neither mihomo (adapter/outbound/tor.go 404) nor sing-box (outbound/tor.go + protocol/tor/outbound.go 404) ships a tor outbound (probed 2026-09-24); nothing to port for 1:1 |
| ssh.go | `proto/ssh.rs` via russh (password/PEM keys, direct-tcpip channels, known host keys) | ✅ this pass |
| shadowtls.go (v3) | `proto/shadowtls.rs` (Hello-HMAC auth, record XOR chains, inner `proxy:` nesting in the mihomo dialect) | ✅ this pass (v1/v2 rejected with a clear error) |
| snell.go | `proto/snell.rs` — v3+v4 (Argon2id KDF hand-rolled per RFC 9106 with Go cross-vectors, v4 stride-2 padding/bit-ratio/chunk-ramp) | ✅ v1–v5 + TCP/UDP + SnellPool (wave-9: v1 chacha/v2 reuse-header wire, v5→v4 mapping per adapter, zero-chunk half-close recycling, 15s/10-idle pool; wave-8 UDP reader) |
| anytls.go | `proto/anytls.rs` — auth sha256(pw), padding-scheme session, uot-v2 UDP; wave-9: session multiplexing (sid registry, writer/recv tasks, FIN on drop) + AnyTlsSessionPool (idle preference, janitor, max-streams) wired per-outbound | ✅ |
| mieru.go | `proto/mieru.rs` — hashed password, PBKDF2 time-key, XChaCha20-Poly1305 implicit-nonce sessions; wave-8: the UDP PACKET transport (stateless cipher, retransmit/window/ACK engine with RTT+CUBIC, heartbeats, reorder delivery) + SOCKS5 UDP-ASSOCIATE relay over either underlay | ✅ TCP + UDP + port-ranges + multiplexing (wave-9: MieruMux with weighted underlay reuse/clean/traffic-disable, per-session demux both underlays; port-range picker FlatPortBindings) |
| restls.go | `proto/restls.rs` — TLS1.3 session-id BLAKE3 MAC stamping (rustls SecureRandom trick), XOR auth record, script-driven padding | ✅ this pass (tls12 version-hint rejected: rustls has no KEX hook — error names it) |
| jls.go | `proto/jls.rs` — JLS cover over TLS 1.3: hello randoms replaced by AES-256-GCM seeds keyed by SHA256(user/pw‖authData) (two-pass rustls hello stamping; Go golden vectors), wired as `jls-opts` on vless/trojan/vmess/anytls | ✅ wave-7 + uTLS-fingerprint hello (wave-9: profile hellos ride the engine's own TLS 1.3 stack — structure_seed two-pass stamping, utls.go parity; server-side fallback relay remains scoped out) |
| shadowquic.go | `proto/shadowquic.rs` — TCP + UDP over quinn, control-stream id registration, ≤32 pending demux, Brutal codec; wave-11: JLS credentials ACTIVATE via the own-stack QUIC crypto (the jls-quic-go `tls.QUICClient` equivalent) — the wave-7 blocker is gone | ✅ (v2/RFC9369 unsupported by quinn; uTLS client-fingerprint field does not exist upstream) |
| sudoku.go | `proto/sudoku.rs` — KIP framing, X25519+nonce-echo+rekey handshake, RecordConn epoch AEAD, full table obfs (bit-exact Go math/rand transcription, directional/custom/rotation), HTTP mask, UoT UDP, session mux | ✅ wave-8: http-mask tunnel modes stream/poll/auto/ws landed (early-handshake KIP in `ed` query/base64/body, chunked sequenced uploads, poll lines, WS upgrade + HMAC token, TLS carriers) |
| gost_relay.go | `proto/gost_relay.rs` — relay v1 features (userauth/addr-port-LAST/network), TCP + UDP associations, TLS, forward mode | ✅ wave-7 (mux:true rejected citing smux; TLS cert extras carried) |
| tlsmirror.go | `proto/tlsmirror.rs` — mirror carrier (CH/SH random + cipher capture, XOR-nonce AES-GCM with counter-retry, HKDF labels, TLS1.2 explicit-nonce path, watermarking ChaCha20, padding, traffic generator) as `tlsmirror-opts` on vmess; wave-8: connection-enrolment (server-identifier host, protobuf confirmation over h2c, ServeConnReady server half + listener) | ✅ (h2 generator steps → precise error) |
| trusttunnel.go | `proto/trusttunnel.rs` — pool client; in-tree minimal HTTP/2 (full HPACK incl. Huffman + dynamic table, flow control) and HTTP/3-over-quinn CONNECT tunnels, both UDP framings | ✅ wave-7 (ECH composed at TLS layer; ICMP refused citing icmp.go) |
| masque.go | `proto/masque.rs` — Cloudflare-flavoured MASQUE: ECDSA cert auth + public-key pinning, minimal in-module H3, `cf-connect-ip` extended CONNECT + capsule ADDRESS_ASSIGN/ROUTE_ADVERTISEMENT, L4 proxy plain-CONNECT TCP | ✅ wave-7 (TUN/ip-stack mode + L4 UDP → precise errors citing upstream lines) |
| openvpn.go | `proto/openvpn.rs` — full 2.x client: control channel (reliable transport, ack MRU, replay window), tls-auth/tls-crypt/tls-crypt-v2 auth layers, rustls TLS-1.3 epoch over chunked P_CONTROL_V1, hand-rolled DER chain verify, key-method-2 PRF, data channel (AES-GCM/CHACHA20/AES-CBC+HMAC, implicit-IV, replay), push parsing (ifconfig/route/dns/cipher-negotiation), soft-reset rekey, smoltcp userspace stack (wireguard pattern) | ✅ wave-8 (BF-CBC upstream-unsupported too; LZO-decompress precise error; TLS1.2 control servers unreachable-rustls; host-TUN ip-stack modes precise-error like masque) |
| ech.go | `proto/ech.rs` + `reality/tls13.rs::connect_ech` + `quic/tls13.rs` — full runtime on the engine's own TLS 1.3 stack, TCP AND QUIC (wave-11: a quinn `crypto::ClientConfig` over the own stack — RFC 9001 key schedule, rustls-parity initial keys via the public Suite::keys, exporter chain — so hysteria2/tuic/trusttunnel(quic) dial with ECH and shadowquic carries JLS inside the QUIC handshake) | ✅ TCP-TLS + QUIC (h2-only trusttunnel arm precise-error; HTTPS-RR discovery needs DNS type-65, precise error) |
| simple-obfs | `proto/obfs.rs` (http/tls obfs client; mihomo `plugin: obfs` + sing-box `obfs-local` plugin_opts) | ✅ this pass |
| reality.go (utls/reality) | `proto/reality/` — Rust-native TLS 1.3 (byte-controlled ClientHello, SHA-256 + SHA-384 key schedules), Chrome/Firefox uTLS templates, REALITY auth + temp-auth cert verify | ✅ **live-validated against a real Xray server** (tests/docker-reality, 19 checks): handshake+relay, firefox profile, wrong short-id/key refusals, fallback, camo negotiation incl. the 0x1302/SHA-384 path. Vision framing ✅ (`proto/vision.rs`); direct splice ✅ — wave-12 LIVE-FIX: the splice path now consumes the VLESS response header (version+addons) before the vision frames; verified against real Xray (e2e 4g) |

### adapter/outboundgroup/

| Upstream | Engine | Status |
|---|---|---|
| selector, urltest, fallback, loadbalance | `outbound.rs` GroupPolicy | ✅ |
| groupbase (health-check URL, expected-status, lazy) | url-test prober + wave-14: `lazy` (default true; healthcheck.go's touch-gate) + `expected-status` (full IntRanges forms — lists/ranges/`*`, max 28) parsed per group | ✅ (application glue: health loop gates + probe status match — the parse/validate/expose landed with the GroupHealth API) |

### listener/ (inbounds)

| Upstream | Engine | Status |
|---|---|---|
| mixed, http, socks | `inbound/{mixed,http,socks}.rs` | ✅ |
| redir (Linux NAT) | `inbound/redir.rs` (SO_ORIGINAL_DST) | ✅ |
| tproxy (Linux) | `inbound/tproxy.rs` (TCP+UDP transparent) | ✅ |
| sing_tun (TUN device) | `inbound/tun/` — /dev/net/tun + smoltcp netstack + DNS hijack + ICMP echo (v4+v6) + inet6-address (in6_ifreq ioctl, kernel-source-verified), both dialects parse into TunConfig | ✅ Linux (e2e) + Windows(WinTUN)/macOS(utun) SERVING ✅ wave-10 (netstack rewritten over a platform TunIo pump — wireguard-go's reader-thread shape; in-memory LoopbackTun double drives the full netstack in tests) + IPv6 extension headers ✅ wave-10 (full chain walker per gvisor, DNS hijack/ICMP through chains, chained TCP handled per smoltcp staging policy) |
| sing_shadowsocks / sing_trojan / sing_vless / sing_vmess / sing_hysteria2 / tuic server listeners | `inbound/proxy_server/` — TCP + UDP for ss (legacy/2022, SIP022 replay window), trojan, vless, vmess, hysteria2 (H3 auth 233 + datagrams) and TUIC v5 (exporter token auth, native UDP, dissociate); both dialects parse them | ✅ + restls & tlsmirror camouflage listeners ✅ wave-8 (server halves in the proto modules; tlsmirror incl. connection-enrolment control connections) + jls listener ✅ wave-10 (multi-user auth, dest fallback relay with rate limiting, camouflage cert) + snell listener ✅ wave-10 (v1-v5 server wire, reuse loop, http-obfs server, UDP command) + anytls listener ✅ wave-10 (multi-user auth, session server with padding push, uot bridge) + wave-11 FRONTINGS: snell shadow-tls/res-tls/jls stacking (mutual exclusion + the shadow-tls v3 server half) and anytls TLS fronting, client-side too (obfs-mode fronting on the outbound). Wave-8 correction retracted: listener/{snell,anytls}/server.go exist |
| hysteria2_realm | — | ❌ (server-side hy2, same family) |

### dns/

| Upstream | Engine | Status |
|---|---|---|
| resolver/client (cache, fallback, policy) | `dns/resolver.rs` + `dns/policy.rs` | ✅ cache + ordered upstreams + `nameserver-policy` per-domain routing (this pass); fallback geoip-verification ❌ |
| udp/tcp upstream (hostnames resolve at load) | `dns/upstream.rs` | ✅ |
| dot.go | `dns/upstream.rs` `tls://` | ✅ |
| doh.go | `dns/upstream.rs` `https://` (RFC 8488, h1.1, Content-Length + chunked) | ✅ |
| doq.go (QUIC), DoH3 | `dns/upstream.rs` `quic://`/`doq://` (RFC 9250) and `h3://` (DoH3 via the quinn stack) | ✅ this pass |
| dhcp.go, system.go | `dns/upstream.rs` `system`/`local` (resolv.conf) and `dhcp://iface` (systemd-networkd + dhclient leases, default-route autodetect) | ✅ this pass |
| mdx | — | ❌ |
| enhancer (fake-ip) | `dns/fakeip.rs` | ✅ (pool + reverse + filter) |
| hosts | `config.rs` DnsConfig.hosts + resolver override | ✅ |
| edns0_subnet.go | `dns/edns.rs` RFC 7871 (query-side ECS, sing-box `client_subnet`) | ✅ this pass |
| rcode/filters | wire.rs + upstream.rs — all six rcode:// pseudo-nameservers (success…refused, config.go tokens) answer with build_response | ✅ wave-12 |

### rules/

| Upstream | Engine (`rule.rs`) | Status |
|---|---|---|
| domain / suffix / keyword / regex | Domain*, DomainRegex | ✅ |
| domain_wildcard | DomainWildcard → anchored regex (`*` any run, `?` one char) | ✅ |
| ipcidr (+src), geoip, geosite, rule-set | IpCidr/GeoIp/Geosite/RuleSet | ✅ (IP-CIDR now pre-resolves domain targets like mihomo unless no-resolve; rule-set yaml/text; **mrs binary** ❌) |
| port.go (SRC/DST ranges) | PortSrc/PortDst | ✅ |
| process.go | Process (name/path; PATH matches exactly) via `process.rs` /proc walk (TCP+UDP tables) | ✅ |
| in_name.go | InName | ✅ |
| in_type/in_user/uid/dscp/ipasn/ipsuffix | `rule.rs` InType/InUser/Uid/Dscp/IpAsn/IpSuffix (`process.rs` returns uid+user) | ✅ this pass |
| network_type (wifi/cellular) | — | ❌ mobile-only upstream |
| logic/logic.go AND/OR/NOT (+SUB-RULE bundles) | Logic{And,Or,Not} — NOT takes exactly one sub-rule | ✅; ✅ SUB-RULE with mihomo's real `SUB-RULE,<condition>,<bundle>` syntax (each bundle rule gated by the condition, keeping its own outbound) |
| final.go (MATCH) | MatchAll | ✅ |
| provider/ classical+domain+ipcidr strategies | RuleSets Classical/Domain/IpCidr | ✅ + binary readers: sing-box `.srs` (LOUDS trie, zlib) and mihomo `.mrs` (zstd) via `ruleset_bin.rs` (this pass) |

### transport/ (outbound wire transports)

| Upstream | Engine (`transport.rs`) | Status |
|---|---|---|
| v2raywebsocket (ws + early-data) | `ws_connect_early` (≤757B rides `Sec-WebSocket-Protocol`) | ✅ this pass |
| **httpupgrade** (via ws-opts convention) | `httpupgrade_connect` | ✅ |
| gun / v2raygrpc | `grpc.rs` — hand-rolled HTTP/2 + HPACK (huffman decode, flow control), TLS ALPN h2 | ✅ this pass |
| simple-obfs | `proto/obfs.rs` (http/tls) + `proto/sip003.rs` (external SIP003 child processes: obfs-local/v2ray-plugin/raw programs, spec env table, PATH resolution; `plugin: obfs` stays in-process like mihomo) | ✅ wave-9 |
| vmess AEAD ciphers | `proto/vmess.rs` | ✅ aes-128-gcm / chacha20-poly1305 / none / auto |
| shadowtls / snell / hysteria core | — | ❌ |

### component/sniffer/

| Upstream | Engine (`sniffer.rs`) | Status |
|---|---|---|
| tls_sniffer | `sniff_tls` (ClientHello SNI walk) | ✅ |
| http_sniffer | `sniff_http` (method + Host, port strip) | ✅ |
| quic_sniffer | RFC 9001 Initial decryption (HKDF key schedule, header protection, CRYPTO reassembly) | ✅ this pass (RFC A.1/A.2 vectors pinned) |
| dispatcher (override-destination, skip-domain, force-domain, ports) | `apply_sniffed` + SniffConfig | ✅ override + skip + force-domain (skip wins over force) + per-protocol port gates (`sniff: {TLS: {ports}}`) |

### tunnel/ + config/

| Upstream | Engine | Status |
|---|---|---|
| tunnel.go (mode rule/global/direct) | app.rs route_with + RuleMode | ✅ |
| statistic | `stats.rs` + Clash API connections | ✅ |
| config/config.go (YAML dialect) | `config_mihomo.rs` | 🟡 supported subset; unknown keys ignored, unsupported features hard-error |
| external-controller API | `api.rs` — wave-12 surface + wave-13: DELETE /connections{,/id} real (CancelToken per ConnEntry observed by the relay select), /cache/dns/flush (resolver.clear_cache), PUT+PATCH /configs (mode hot-swaps; listener fields 400-with-reason) | 🟡 (PUT /providers/rules 503-named-gap: runtime provider reload; DELETE /proxies honest 400; /logs needs a tracing broadcast layer) |

## 2. sing-box (`SagerNet/sing-box`)

### protocol/ (inbound+outbound halves)

| Upstream | Engine | Status |
|---|---|---|
| shadowsocks/outbound | ✅ (2022 + AEAD) |
| vmess / vless / trojan / socks / http / mixed outbound | ✅ |
| direct / block (=REJECT) / dns outbounds | ✅ (dns answered in-process) |
| group (selector/urltest) | ✅ |
| hysteria / hysteria2 / tuic | ❌ QUIC (planned) |
| anytls / snell / mieru / restls / ssh / shadowtls / wireguard | `proto/{anytls,snell,mieru,restls,ssh,shadowtls,wireguard}.rs` | ✅ (scopes noted per file). naive / tor / bridge / cloudflare / series: NOT in current upstream (mihomo adapter/outbound 404s; sing-box dev outbound 404s incl. naive — removed upstream; probed 2026-09-24) — nothing to port for 1:1 | N/A |
| all `inbound.go` server halves | ❌ server-side scope |

### transport/

| Upstream | Engine | Status |
|---|---|---|
| v2raywebsocket | ✅ | |
| v2rayhttpupgrade | ✅ (this audit pass) | |
| v2raygrpc / v2raygrpclite / v2rayquic (gun) | ❌ | |
| simple-obfs | ✅ (this pass) | |
| wireguard | ✅ (this pass) | |

### route/ + option/rule*.go

| Upstream | Engine | Status |
|---|---|---|
| domain family, ip_cidr, source_ip_cidr, port, source_port, ip_is_private | `rule.rs` + `config_singbox.rs` conversion | ✅ |
| network / inbound (tag) / process_name / process_path | Network/InName/Process | ✅ (this audit pass) |
| clash_mode | ClashMode | ✅ |
| invert | NOT-wrapping in conversion | ✅ (this audit pass) |
| logical and/or (nested) | Logic via nested_eval | ✅ (this audit pass) |
| cross-field AND / in-field OR semantics | combine_groups | ✅ (this audit pass — was previously wrong: plain OR lines) |
| rule_set (.srs binary) | ✅ `ruleset_bin.rs` + provider wiring | |
| user / package_name (android) / network_type (wifi/cellular) | ❌ |
| rule *actions* | wave-14: the SING-BOX action surface (verified: mihomo has only no-resolve/src params — the old row overclaimed): sniff{sniffer-subset}/resolve/hijack-dns parsed with continue-from-next-rule semantics (route.go matchRule), reject→block, logical rules too; mihomo `lazy`/`expected-status` groups + the action RuleTable landed | 🟡 (route-options/reject-method variants warned+dropped with reasons; the app.rs re-entry loop glue is staged — MatchOutcome/resume_at exposed) |
| dns rules (per-server routing, rewrite_ttl, client_subnet, disable_cache) | ❌ |
| fakeip store persistence | fakeip.rs — JSON store with load_from/persist_to (atomic), range-mismatch reset, corrupt-store loud errors; `profile.store-fake-ip` wires the path | ✅ wave-12 |

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

Proxies/connections/rules/traffic/mode/logs/configs/providers ✅; /logs live via a hand-rolled tracing Subscriber broadcast (wave-14); providers runtime reload ✅ (RwLock-swapped rule sets); v2rayapi: N/A upstream (probed — no handler exists in Alpha; code search 0 hits).

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

## 4. Roadmap — everything upstream is in scope

This project's mandate is to be a drop-in replacement for ShellCrash +
mihomo/sing-box, so there is no permanent "rejected" bucket: features not
yet implemented are prioritized below, and until they land they fail
loudly at config load (never silently degrade). External-kernel modes
stay available as the escape hatch during migration.

| Priority | Gap | Implementation path |
|---|---|---|
| **P1** | vless Vision DIRECT splice — FULL (raw-transport rebind) | ✅ wave-7: `Tls13Stream::take_read_ahead/into_raw_transport` + half-splice flags; `VisionConn::connect_tls13` re-binds each direction at the `02` transition (reality outers) |
| **P1** | TUN on Windows (WinTUN) / macOS (utun) | same netstack, different device backends |

| P2 | hy2/tuic server listeners; SS-2022 multi-user server | hy2 server reuses the quinn plumbing; ss UDP server ✅ landed (legacy + 2022) |
| P1 | WireGuard (outbound + endpoint) | outbound ✅ (dual-stack, wave-8); ENDPOINT ✅ wave-9; the multi-segment TCP stall ✅ FIXED wave-12 (writer-hang on un-graceful close + listener re-arm race + read-side wake; 9 repro/soak tests, 20× stable). Same latent shapes remain in tailscale/wg.rs + openvpn.rs service_conns (noted for the next pass) |
| P2 | DHCP / system / hosts-file DNS upstreams; DoH server | small, one module each |
| P2 | snell / anytls / mieru / jls / restls / shadowquic transports | ✅ waves 6-8 (client side incl. snell UDP + mieru UDP); anytls/snell listeners do not exist upstream (audit corrected) |
| P3 | series; overlay mesh cores (easytier Rust crates / zerotier libzt) | tor N/A upstream (probed); tailscale noise+derp+controlhttp ✅ wave-10, ipn remains; openvpn ✅ wave-8 |
| P2 | ECH runtime on the engine's own TLS 1.3 stack | core ✅ (`proto/ech`: HPKE + ECHConfig + outer-CH builder); inner-handshake rebind wiring after the vision rebind API stabilizes |
| P2 | easytier milestone 2 (OSPF routes + smoltcp attach); tailscale remaining ipn features (MagicDNS/subnet routes/disco); tailscale outbound wiring to TailscaleOverlay::dial | ECH-on-QUIC ✅ + snell frontings ✅ + anytls TLS ✅ + tailscale ipn core ✅ (wave-11) |
| P3 | misc polish | .mrs writing ✅ wave-9 (write_mrs: byte-identical upstream payload + hand-rolled pure-Rust zstd store-frame encoder — ruzstd is decode-only; also fixed a reader u128 overflow on ::/0) |

Cluster e2e note (tests/docker-cluster, 10 checks): the dev machine's
host TUN transparent proxy intercepts SOME forwarded docker UDP flows
(cross-container ss-UDP dies while plain cross-container UDP works and
the identical loopback path passes); the suite detects this and falls
back to the same binary running inside the server container on loopback.
