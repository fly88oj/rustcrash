//! TUI Integration Tests for rustcrash-crash
//!
//! Uses ratatui-testlib for PTY-based testing.
//! Run with: cargo test -p rustcrash-crash --test tui_test -- --test-threads=1
//!
//! NOTE: These tests are ignored by default because they require portable-pty system
//! library (libutempter-dev). To run: cargo test -p rustcrash-crash --test tui_test
//! Or in CI with proper system dependencies.

use portable_pty::CommandBuilder;
use ratatui_testlib::{KeyCode, TuiTestHarness};
use std::time::Duration;

fn crash_binary() -> String {
    let manifest_dir = std::env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .unwrap() // cmd/crash
        .parent()
        .unwrap(); // workspace root
    workspace_root
        .join("target/debug/rustcrash-crash")
        .to_string_lossy()
        .to_string()
}

#[test]
#[ignore = "requires portable-pty system library (libutempter-dev)"]
fn test_tui_launches_and_shows_main_menu() {
    let mut harness = TuiTestHarness::new(80, 24).expect("failed to create harness");
    let cmd = CommandBuilder::new(crash_binary());
    harness.spawn(cmd).expect("failed to spawn TUI");

    harness.wait_for_text("RustCrash").ok();
    harness.wait_for_text("主菜单").ok();
    harness.wait_for_text("Main Menu").ok();
    let contents = harness.screen_contents();
    assert!(
        contents.contains("RustCrash")
            || contents.contains("主菜单")
            || contents.contains("Main Menu"),
        "TUI should show main menu, got: {}",
        contents
    );
}

#[test]
#[ignore = "requires portable-pty system library (libutempter-dev)"]
fn test_key_down_navigates_menu() {
    let mut harness = TuiTestHarness::new(80, 24).expect("failed to create harness");
    let cmd = CommandBuilder::new(crash_binary());
    harness.spawn(cmd).expect("failed to spawn TUI");

    std::thread::sleep(Duration::from_millis(300));
    let before = harness.screen_contents();

    harness.send_key(KeyCode::Down).ok();
    std::thread::sleep(Duration::from_millis(200));

    let after = harness.screen_contents();
    assert_ne!(before, after, "Screen should change after Down key");
}

#[test]
#[ignore = "requires portable-pty system library (libutempter-dev)"]
fn test_number_key_jumps_to_settings() {
    let mut harness = TuiTestHarness::new(80, 24).expect("failed to create harness");
    let cmd = CommandBuilder::new(crash_binary());
    harness.spawn(cmd).expect("failed to spawn TUI");

    std::thread::sleep(Duration::from_millis(300));

    harness.send_key(KeyCode::Char('2')).ok();
    std::thread::sleep(Duration::from_millis(300));

    let contents = harness.screen_contents();
    assert!(
        contents.contains("Settings") || contents.contains("配置管理"),
        "Should navigate to Settings: {}",
        contents
    );
}

#[test]
#[ignore = "requires portable-pty system library (libutempter-dev)"]
fn test_escape_returns_to_main() {
    let mut harness = TuiTestHarness::new(80, 24).expect("failed to create harness");
    let cmd = CommandBuilder::new(crash_binary());
    harness.spawn(cmd).expect("failed to spawn TUI");

    std::thread::sleep(Duration::from_millis(300));

    harness.send_key(KeyCode::Char('2')).ok();
    std::thread::sleep(Duration::from_millis(300));

    harness.send_key(KeyCode::Esc).ok();
    std::thread::sleep(Duration::from_millis(300));

    let contents = harness.screen_contents();
    assert!(
        contents.contains("Main Menu") || contents.contains("主菜单"),
        "Should return to main: {}",
        contents
    );
}

#[test]
#[ignore = "requires portable-pty system library (libutempter-dev)"]
fn test_q_key_exits_tui() {
    let mut harness = TuiTestHarness::new(80, 24).expect("failed to create harness");
    let cmd = CommandBuilder::new(crash_binary());
    harness.spawn(cmd).expect("failed to spawn TUI");

    std::thread::sleep(Duration::from_millis(300));

    harness.send_key(KeyCode::Char('q')).ok();
    std::thread::sleep(Duration::from_millis(300));

    // wait_exit returns ExitStatus
    let result = harness.wait_exit();
    assert!(
        result.is_ok(),
        "TUI should exit cleanly on 'q' key, got: {:?}",
        result
    );
}
