# Benchmark Report

Suite: `cargo test --release -p rustcrash-core --test bench -- --nocapture`
(`core/tests/bench.rs`; 1000-node workloads, warm cache).

| Benchmark | Result |
|---|---|
| parse_uri_list (1000 trojan URIs) | 275 µs/op |
| apply_filters include+sort (1000) | 203 µs/op |
| apply_filters country_keep (1000) | 1288 µs/op |
| generate_kernel_config (1000 nodes) | 504–581 µs/op |
| generate_full_nft_script (TUN+IPv6+ports) | 1.0 µs/op |
| generate_full_iptables_script | 1.5 µs/op |
| Config YAML parse | 23.6 µs first load / ~0 cached on the API hot path |

## Implementation notes

1. **Country filter** — `detect_country` is allocation-free: a lazy
   token iterator with `eq_ignore_ascii_case`, an ASCII
   case-insensitive `contains` for long aliases, plain `contains` for
   CJK/emoji; the want side is prepared once before the node loop and
   the fallback lowercase copy only runs when some want is a long
   alias.
2. **API config hot path** — `ApiServer` keys a config cache on the
   file's mtime: repeated requests (status polling, dashboards) skip
   the YAML parse; `POST /api/config` drops the cache so writes are
   always reflected (also correct on coarse-mtime filesystems).

## Not optimized (measured cheap)

Firewall script generation (~1 µs) and URI parsing (275 µs for 1000
nodes, NFR-1.1 target is <500 ms — 3 orders of margin). Binary size
stays the priority for router targets (`opt-level=z`).
