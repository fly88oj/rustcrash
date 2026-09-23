//! Performance benchmarks for RustCrash hot paths.
//!
//! Run with: `cargo test --release -p rustcrash-core --test bench -- --nocapture`
//! Prints per-op timings suitable for before/after comparison.

use rustcrash_core::config::{Config, ConfigManager};
use rustcrash_core::platform::Platform;
use rustcrash_core::rules::generate_kernel_config;
use rustcrash_core::subconverter::filters::{apply_filters, FilterOptions};
use rustcrash_core::subconverter::uri::parse_uri_list;
use rustcrash_core::Firewall;
use rustcrash_core::FirewallConfig;
use std::path::Path;
use std::time::Instant;

fn timed(name: &str, iters: usize, mut f: impl FnMut()) {
    // Warmup
    f();
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    println!(
        "{:<44} {:>8.1} µs/op   ({} iters, {:.1} ms total)",
        name,
        elapsed.as_micros() as f64 / iters as f64,
        iters,
        elapsed.as_secs_f64() * 1000.0
    );
}

#[test]
fn bench_hot_paths() {
    println!("\n=== RustCrash benchmarks ===\n");

    // URI parsing: 1000 nodes. Plain-text-name protocols (trojan) make
    // per-node name variation trivial; vmess names live inside base64.
    let uris: Vec<String> = (0..1000)
        .map(|i| format!("trojan://pass123@example.com:443#Node-{i}"))
        .collect();
    let joined = uris.join("\n");
    timed("parse_uri_list (1000 trojan)", 20, || {
        let nodes = parse_uri_list(&joined);
        assert_eq!(nodes.len(), 1000);
    });

    // Filter pipeline on 1000 nodes.
    let nodes = parse_uri_list(&joined);
    timed("apply_filters include+sort (1000)", 20, || {
        let opts = FilterOptions {
            include: regex::Regex::new("Node-").ok(),
            sort: true,
            ..Default::default()
        };
        let out = apply_filters(&nodes, &opts);
        assert!(!out.is_empty());
    });
    timed("apply_filters country_keep (1000)", 20, || {
        let opts = FilterOptions {
            country_keep: vec!["US".to_string()],
            ..Default::default()
        };
        let _ = apply_filters(&nodes, &opts);
    });

    // Kernel-config generation (full pipeline incl. general section).
    let config = Config {
        subscriptions: vec![rustcrash_core::Subscription {
            name: "bench".into(),
            url: "https://example.com/sub".into(),
            updated_at: None,
            raw_config: Some(joined.clone()),
        }],
        ..Default::default()
    };
    timed("generate_kernel_config (1000 nodes)", 20, || {
        let out =
            generate_kernel_config(&config, rustcrash_core::ProxyKernel::Mihomo, "/tmp/bench")
                .unwrap();
        assert!(out.contains("mixed-port"));
    });

    // Firewall script generation (nft, TUN+IPv6 worst case).
    let platform = Platform::for_crash_dir("/tmp/bench");
    let fw = Firewall::new(&platform);
    let fw_config = FirewallConfig {
        tun_port: Some(7893),
        ipv6_enabled: true,
        quic_reject: true,
        common_ports: vec![80, 443],
        ..FirewallConfig::default()
    };
    timed("generate_full_nft_script (TUN+IPv6+ports)", 200, || {
        let _ = fw.generate_full_nft_script(&fw_config).unwrap();
    });
    let fw_default = FirewallConfig::default();
    timed("generate_full_iptables_script (default)", 200, || {
        let _ = fw.generate_full_iptables_script(&fw_default);
    });

    // Config load (YAML parse of the default config).
    let tmp = tempfile::tempdir().unwrap();
    let cm = ConfigManager::new(&Platform::for_crash_dir(tmp.path().to_str().unwrap()));
    cm.save(&Config::default()).unwrap();
    let config_path = Path::new(tmp.path()).join("config.yaml");
    timed("Config YAML parse (from disk)", 500, || {
        let _ = cm.load().unwrap();
    });
    let _ = config_path;

    println!("\n=== end benchmarks ===\n");
}
