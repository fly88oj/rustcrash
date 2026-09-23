//! Integration tests for the crash binary's CLI surface.
//!
//! These run the built binary the way users do — argv in, exit code and
//! files out — with each test using its own crash dir (`-c`), never the
//! process environment (env mutation races between tests).
//!
//! Requires `cargo build` first. cargo runs package tests with the
//! package root as cwd, so the binary is the literal relative path below.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Path to the built crash binary (cwd is tests/integration at test time).
fn crash_bin() -> PathBuf {
    let bin = PathBuf::from("../../target/debug/crash");
    assert!(
        bin.exists(),
        "crash binary not built: {} (run cargo build)",
        bin.display()
    );
    bin
}

struct CrashDir {
    #[allow(dead_code)]
    tmp: TempDir,
    dir: PathBuf,
}

impl CrashDir {
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("rc");
        CrashDir { tmp, dir }
    }

    fn run(&self, args: &[&str]) -> (bool, String, String) {
        // Literal program path; the crash dir rides in argv (-c).
        let out = Command::new("../../target/debug/crash")
            .arg("-c")
            .arg(&self.dir)
            .args(args)
            .output()
            .expect("failed to spawn crash");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }
}

#[test]
fn version_reports_binary() {
    let _ = crash_bin();
    let out = Command::new("../../target/debug/crash")
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("crash"));
}

#[test]
fn init_creates_expected_layout() {
    let rc = CrashDir::new();
    let (ok, _, stderr) = rc.run(&["init", "--force"]);
    assert!(ok, "crash init failed: {stderr}");
    for dir in [
        "bin",
        "bin/geodata",
        "configs",
        "configs/ruleset",
        "data",
        "run",
        "logs",
        "backup",
    ] {
        assert!(rc.dir.join(dir).exists(), "missing {dir}");
    }
    // The typed management config is written at the root, not config/.
    assert!(rc.dir.join("config.yaml").exists(), "config.yaml missing");
    assert!(
        !rc.dir.join("config").exists(),
        "legacy config/ dir must not be created"
    );
}

#[test]
fn config_show_round_trip() {
    let rc = CrashDir::new();
    rc.run(&["init", "--force"]);
    let (ok, stdout, stderr) = rc.run(&["config", "show"]);
    assert!(ok, "config show failed: {stderr}");
    assert!(
        stdout.contains("mihomo"),
        "expected kernel in output:\n{stdout}"
    );
}

#[test]
fn config_validate_on_fresh_init() {
    let rc = CrashDir::new();
    rc.run(&["init", "--force"]);
    let (ok, stdout, stderr) = rc.run(&["config", "validate"]);
    assert!(ok, "config validate failed: {stderr}");
    assert!(stdout.to_lowercase().contains("valid"));
}

#[test]
fn start_status_without_kernel() {
    let rc = CrashDir::new();
    rc.run(&["init", "--force"]);
    let (ok, stdout, stderr) = rc.run(&["start", "status"]);
    assert!(ok, "start status failed: {stderr}");
    assert!(
        stdout.contains("not installed") || stdout.contains("STOPPED"),
        "expected stopped/not-installed status:\n{stdout}"
    );
}

#[test]
fn kernel_config_path_is_configs_mihomo_yaml() {
    // Regression: the kernel config must not collide with config.yaml.
    let rc = CrashDir::new();
    rc.run(&["init", "--force"]);
    let (ok, _, stderr) = rc.run(&["config", "generate"]);
    // No subscription yet — generate must fail cleanly, not create files.
    assert!(!ok, "generate without subscription should fail: {stderr}");
    assert!(!rc.dir.join("configs/mihomo.yaml").exists());
}

#[test]
fn firewall_generate_emits_script() {
    let rc = CrashDir::new();
    rc.run(&["init", "--force"]);
    let (ok, stdout, stderr) = rc.run(&["firewall", "generate", "--backend", "iptables"]);
    assert!(ok, "firewall generate failed: {stderr}");
    assert!(stdout.contains("iptables"), "no iptables rules in output");
}

#[test]
fn sub_convert_known_uri() {
    let rc = CrashDir::new();
    rc.run(&["init", "--force"]);
    let vmess = "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjIiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidGxzIjoidGxzIn0=";
    let (ok, stdout, stderr) = rc.run(&[
        "sub", "convert", "--input", vmess, "--target", "clash", "--sort",
    ]);
    assert!(ok, "sub convert failed: {stderr}");
    assert!(
        stdout.contains("proxies:"),
        "no proxies in output:\n{stdout}"
    );
    assert!(stdout.contains("url-test"), "no url-test group");
}

#[test]
fn sub_convert_rejects_bad_sort_algorithm() {
    let rc = CrashDir::new();
    rc.run(&["init", "--force"]);
    let vmess = "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjIiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidGxzIjoidGxzIn0=";
    let (ok, _, _) = rc.run(&[
        "sub",
        "convert",
        "--input",
        vmess,
        "--sort-algorithm",
        "bogus",
    ]);
    assert!(!ok, "invalid sort algorithm must be rejected");
}

#[test]
fn task_list_on_fresh_dir() {
    let rc = CrashDir::new();
    rc.run(&["init", "--force"]);
    let (ok, _, stderr) = rc.run(&["task", "list"]);
    assert!(ok, "task list failed: {stderr}");
}

#[test]
fn exec_status_shortcut() {
    let rc = CrashDir::new();
    rc.run(&["init", "--force"]);
    let (ok, stdout, stderr) = rc.run(&["--exec", "status"]);
    assert!(ok, "--exec status failed: {stderr}");
    assert!(!stdout.is_empty());
}
