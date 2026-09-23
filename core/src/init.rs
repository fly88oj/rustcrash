//! Init-system script generators for the crash supervisor.
//!
//! Pure functions returning the script text for each platform; the CLI
//! writes them and registers boot integration. Paths must be absolute
//! (the caller resolves them from `current_exe`).

/// systemd unit for the supervisor. `exe` must be an absolute path to the
/// crash binary (resolved from current_exe at generation time).
/// network-online + a boot connectivity wait mirror ShellCrash's fix for
/// "boot autostart fails on devices whose network isn't up yet" — the
/// kernel and subscription fetch both need a route before start().
pub fn systemd_unit(exe: &str, crash_dir: &str) -> String {
    format!(
        r#"[Unit]
Description=RustCrash mihomo/sing-box Manager
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
# Wait for a default route before starting (bounded; boot-time network
# races were a top community autostart failure). systemd expands $ itself
# (man systemd.service: use $$ for a literal $) — single quotes do NOT
# protect, so every $ below is doubled.
ExecStartPre=/bin/sh -c 'i=0; while [ $$i -lt 30 ] && ! ip route show default 2>/dev/null | grep -q .; do sleep 1; i=$$((i+1)); done'
ExecStart={exe} -c "{crash_dir}" start serve
ExecStop={exe} -c "{crash_dir}" start stop
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
"#
    )
}

/// OpenRC init script driving the supervisor.
pub fn openrc_script(exe: &str, crash_dir: &str) -> String {
    format!(
        r#"#!/bin/sh
# RustCrash OpenRC init script
name=rustcrash
command="{exe}"
pidfile="/var/run/rustcrash.pid"
depend() {{
    need net
    after firewall
}}
start() {{
    ebegin "Starting RustCrash"
    start-stop-daemon --background --start --exec "${{command}}" -- -c "{crash_dir}" start serve
    eend $?
}}
stop() {{
    ebegin "Stopping RustCrash"
    start-stop-daemon --stop --exec "${{command}}" -- -c "{crash_dir}" start stop
    eend $?
}}
"#
    )
}

/// SysV/init.d script driving the supervisor.
pub fn initd_script(exe: &str, crash_dir: &str) -> String {
    format!(
        r#"#!/bin/sh
# RustCrash init.d script
CRASH="{exe}"
CRASHDIR="{crash_dir}"
wait_net() {{
    i=0
    while [ $i -lt 30 ] && ! ip route show default 2>/dev/null | grep -q .; do
        sleep 1; i=$((i+1))
    done
}}
case "$1" in
    start) wait_net; "$CRASH" -c "$CRASHDIR" start serve >/dev/null 2>&1 & ;;
    stop)  "$CRASH" -c "$CRASHDIR" start stop ;;
    restart) "$0" stop; sleep 1; "$0" start ;;
    *) echo "Usage: $0 {{start|stop|restart}}" ;;
esac
"#
    )
}

/// rc.local bootstrap line for systems without a real init system.
pub fn rc_local_line(exe: &str, crash_dir: &str) -> String {
    // Bounded connectivity wait — boot-time network races were a top
    // community autostart failure.
    format!(
        "\ni=0; while [ $i -lt 30 ] && ! ip route show default 2>/dev/null | grep -q .; do sleep 1; i=$((i+1)); done\n{exe} -c '{crash_dir}' start serve >/dev/null 2>&1 &\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_unit_invokes_supervisor_with_quoted_dir() {
        let unit = systemd_unit("/usr/local/bin/crash", "/opt/my crash");
        assert!(unit.contains("ExecStart=/usr/local/bin/crash -c \"/opt/my crash\" start serve"));
        assert!(unit.contains("ExecStop=/usr/local/bin/crash -c \"/opt/my crash\" start stop"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=multi-user.target"));
        // Boot readiness (community autostart failures).
        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("ip route show default"));
        // systemd expands $ itself — a literal $ must be $$, or the wait
        // loop silently no-ops (round-20 finding: the "fix" hadn't landed).
        assert!(unit.contains("$$i -lt 30"));
        assert!(unit.contains("$$((i+1))"));
        assert!(!unit.contains("[ $i"));
    }

    #[test]
    fn openrc_script_quotes_both_paths() {
        let script = openrc_script("/opt/crash bin/crash", "/etc/rc dir");
        assert!(script.contains("command=\"/opt/crash bin/crash\""));
        // The supervisor args ride inline in the daemon invocation — an
        // unquoted `command_args=` assignment would be parsed as a command.
        assert!(!script.contains("command_args="));
        assert!(script.contains("--exec \"${command}\" -- -c \"/etc/rc dir\" start serve"));
        assert!(script.contains("start-stop-daemon"));
    }

    #[test]
    fn initd_script_handles_start_stop_restart() {
        let script = initd_script("/usr/local/bin/crash", "/etc/rustcrash");
        assert!(script.contains("CRASH=\"/usr/local/bin/crash\""));
        assert!(script.contains("start serve"));
        assert!(script.contains("start stop"));
        assert!(script.contains("restart)"));
        // Quoted dir survives paths with spaces.
        let spaced = initd_script("/x/crash", "/a b");
        assert!(spaced.contains("CRASHDIR=\"/a b\""));
    }

    #[test]
    fn rc_local_line_is_quoted_and_backgrounded() {
        let line = rc_local_line("/usr/local/bin/crash", "/opt/dir with space");
        assert!(line.contains("-c '/opt/dir with space' start serve"));
        assert!(line.trim_end().ends_with('&'));
    }

    #[test]
    fn generated_scripts_use_the_supervisor_not_bare_start() {
        // Regression: scripts used to invoke the invalid `crash start`
        // (missing subcommand). Every entry point must name a real command.
        for text in [
            systemd_unit("/x/crash", "/d"),
            openrc_script("/x/crash", "/d"),
            initd_script("/x/crash", "/d"),
            rc_local_line("/x/crash", "/d"),
        ] {
            assert!(text.contains("start serve") || text.contains("start stop"));
            assert!(!text
                .contains("start\n")
                .to_string()
                .contains("crash start\n"));
        }
    }
}
