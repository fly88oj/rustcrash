//! SIP003 external Shadowsocks plugins (obfs-local / v2ray-plugin style).
//!
//! # What SIP003 is
//!
//! A Shadowsocks client side-channel obfuscation extension where the
//! obfuscation is an *external process* the SS client spawns
//! (shadowsocks.org, "SIP003: A simplified plugin design for
//! shadowsocks"). The plugin is a local port forwarder, not a stdio pipe:
//! the SS client reserves `SS_LOCAL_HOST:SS_LOCAL_PORT`, spawns the plugin
//! binary, and then dials that local endpoint instead of the server —
//! every Shadowsocks stream (salt + encrypted address header first) rides
//! the plugin's tunnel to `SS_REMOTE_HOST:SS_REMOTE_PORT`. TCP only;
//! plugin-over-plugin is out of scope. (The task brief sketched the child
//! being piped over stdin/stdout; per the spec and every reference
//! implementation the transport is the plugin's local TCP listener — the
//! child's stdio only carries its logs.)
//!
//! # Spawn semantics (ported)
//!
//! * environment: the four MUST-HAVE vars `SS_REMOTE_HOST`, `SS_REMOTE_PORT`,
//!   `SS_LOCAL_HOST`, `SS_LOCAL_PORT` plus the optional `SS_PLUGIN_OPTIONS`
//!   (SIP003 §"Plugin over environment variables"; the same set as
//!   shadowsocks-libev `src/plugin.c:start_ss_plugin` and
//!   go-shadowsocks2 `plugin.go:execPlugin`). The frequently-cited
//!   `SS_PLUGIN_METHOD` does not exist in SIP003 — the method never leaves
//!   the SS client.
//! * `SS_PLUGIN_OPTIONS` format: `k=v;k2=v2`, where `;`, `=` and `\` MUST
//!   be backslash-escaped (SIP003 spec; parsed back by
//!   shadowsocks/v2ray-plugin `args.go:parsePluginOptions`, which also
//!   gives a bare key the value `"1"` — [`encode_plugin_options`] does the
//!   same on encode).
//! * binary resolution, like go-shadowsocks2 `execPlugin`: a name
//!   containing a path separator is used as-is; otherwise the current
//!   directory is searched first (shadowsocks-libev prepends `.` to
//!   `PATH` for exactly this) and then each `PATH` entry, matching only
//!   executable regular files.
//! * free-port pick, like `getFreePort`/`startPlugin`: bind
//!   `127.0.0.1:0`, read the assigned port, drop the socket, hand the port
//!   to the plugin. The usual TOCTOU race exists upstream too.
//! * the client retries the local dial until the child's listener appears
//!   (bounded), and bails out early if the child dies first.
//! * teardown: the returned [`Sip003Stream`] owns the child with
//!   `kill_on_drop`, so dropping the stream kills the plugin; [`Sip003Stream::close`]
//!   kills and *reaps* it synchronously.
//!
//! # Option mapping (mihomo `plugin-opts` -> `SS_PLUGIN_OPTIONS`)
//!
//! mihomo itself implements the well-known plugins *in-process*
//! (`adapter/outbound/shadowsocks.go::NewShadowSocks`, the `obfs`,
//! `v2ray-plugin`, `gost-plugin`, `shadow-tls`, `restls`, `jls`, `kcptun`
//! branches). This module is the *external-binary* path mihomo does not
//! have, so the option tables below translate mihomo's `plugin-opts` keys
//! to each binary's documented SIP003 keys:
//!
//! * `plugin: obfs` + `{mode, host}` — mihomo `simpleObfsOption`
//!   (shadowsocks.go:47-50, 259-270). The `obfs-local` binary reads
//!   `obfs=<mode>;obfs-host=<host>` (SIP003 spec example
//!   `obfs=http;obfs-host=www.baidu.com`; simple-obfs README). Mode must
//!   be `tls` or `http`, enforced exactly like the upstream constructor.
//! * `plugin: v2ray-plugin` (also `xray-plugin`, same CLI) +
//!   `{mode, host, path, tls, mux, loglevel}` — the subset of mihomo's
//!   `v2rayObfsOption` (shadowsocks.go:52-68) that v2ray-plugin's SIP003
//!   env interface can carry (v2ray-plugin `main.go:startV2Ray` consumes
//!   the `mode`, `mux`, `tls`, `host`, `path`, `loglevel` keys). mihomo-only
//!   extras (headers, ech-opts, fingerprints, ...) have no SIP003
//!   representation and belong to the in-process transports this engine
//!   already ships (`proto::obfs`, `proto::shadowtls`, `proto::restls`).
//!
//! # Wiring point for the integrator
//!
//! In `outbound.rs`'s Shadowsocks dial path, replace the
//! `TcpStream::connect(server)` step with
//! `Sip003Plugin::connect(plugin, server_host, server_port).await` and run
//! the existing SS stream (`proto::shadowsocks::SsStream` handshake: the
//! salt plus encrypted target address) over the returned stream — the same
//! layering as mihomo's `StreamConnContext`, which wraps the obfuscation
//! *under* the cipher. UDP through a plugin is not supported (SIP003 is
//! TCP-only); reject it like mihomo rejects simple-obfs UDP.
//!
//! # Tests
//!
//! Hermetic: everything except the actual `fork/exec` is unit-tested (env
//! table, option encoding and per-plugin mapping, PATH resolution against
//! tempdirs, dial-retry plumbing against a loopback listener standing in
//! for the child). The crate has no self-exe test-child convention yet
//! (no `current_exe` test helper exists anywhere in `engine/`), so the
//! spawn path itself is documented here instead of exercised live.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::time::{sleep, Duration};

use crate::error::{Error, Result};

/// The four MUST-HAVE SIP003 environment variables plus the optional
/// `SS_PLUGIN_OPTIONS` (SIP003 spec; shadowsocks-libev `plugin.c`).
pub const SS_REMOTE_HOST: &str = "SS_REMOTE_HOST";
pub const SS_REMOTE_PORT: &str = "SS_REMOTE_PORT";
pub const SS_LOCAL_HOST: &str = "SS_LOCAL_HOST";
pub const SS_LOCAL_PORT: &str = "SS_LOCAL_PORT";
pub const SS_PLUGIN_OPTIONS: &str = "SS_PLUGIN_OPTIONS";

/// Loopback the plugin's listener is expected to bind (go-shadowsocks2
/// hardcodes `localHost := "127.0.0.1"` in `startPlugin`).
pub const SIP003_LOCAL_HOST: &str = "127.0.0.1";

/// How long [`Sip003Plugin::connect`] waits for the child's listener.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);
/// Retry cadence while waiting for the child's listener.
const LISTEN_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// Escape one byte for `SS_PLUGIN_OPTIONS` (SIP003: `;`, `=` and `\` MUST
/// be escaped with a backslash).
fn escape_options_byte(b: u8, out: &mut String) {
    match b {
        b';' | b'=' | b'\\' => {
            out.push('\\');
            out.push(b as char);
        }
        _ => out.push(b as char),
    }
}

/// Encode a `k=v;k2=v2` `SS_PLUGIN_OPTIONS` string. `None` values (and
/// `Some("1")`, which round-trips identically) emit a bare key, exactly
/// what v2ray-plugin's parser (`args.go:parsePluginOptions`) reads back
/// as the value `"1"`.
pub fn encode_plugin_options(opts: &[(&str, Option<&str>)]) -> String {
    let mut out = String::new();
    for (i, (key, value)) in opts.iter().enumerate() {
        if i > 0 {
            out.push(';');
        }
        for &b in key.as_bytes() {
            escape_options_byte(b, &mut out);
        }
        match value {
            None => {}
            Some(v) if *v == "1" => {}
            Some(v) => {
                out.push('=');
                for &b in v.as_bytes() {
                    escape_options_byte(b, &mut out);
                }
            }
        }
    }
    out
}

/// The full SIP003 environment for one plugin invocation (the exact table
/// from shadowsocks-libev `plugin.c:start_ss_plugin` / go-shadowsocks2
/// `execPlugin`): the four address vars plus `SS_PLUGIN_OPTIONS` when
/// non-empty. The caller inherits the rest of its environment, like
/// `append(os.Environ(), ...)`.
pub fn sip003_envs(
    remote_host: &str,
    remote_port: u16,
    local_host: &str,
    local_port: u16,
    plugin_options: &str,
) -> Vec<(String, String)> {
    let mut envs = vec![
        (SS_REMOTE_HOST.to_string(), remote_host.to_string()),
        (SS_REMOTE_PORT.to_string(), remote_port.to_string()),
        (SS_LOCAL_HOST.to_string(), local_host.to_string()),
        (SS_LOCAL_PORT.to_string(), local_port.to_string()),
    ];
    if !plugin_options.is_empty() {
        envs.push((SS_PLUGIN_OPTIONS.to_string(), plugin_options.to_string()));
    }
    envs
}

/// Resolve a plugin program the way go-shadowsocks2's `execPlugin` plus
/// shadowsocks-libev's PATH augmentation do: names containing a path
/// separator are taken as-is; bare names are searched in `dirs` (caller
/// passes `["."] + PATH`) for the first executable regular file named
/// exactly `name` (or `name.exe` on Windows, like `exec.LookPath`).
pub fn resolve_plugin_in(name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    if name.contains('/') || name.contains('\\') {
        return Some(PathBuf::from(name));
    }
    let candidates = if cfg!(windows) {
        vec![name.to_string(), format!("{name}.exe")]
    } else {
        vec![name.to_string()]
    };
    for dir in dirs {
        for cand in &candidates {
            let path = dir.join(cand);
            if is_executable_file(&path) {
                return Some(path);
            }
        }
    }
    None
}

/// The production resolver: current directory first, then `PATH`.
pub fn resolve_plugin(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = vec![PathBuf::from(".")];
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    resolve_plugin_in(name, &dirs)
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    matches!(std::fs::metadata(path), Ok(m) if m.is_file())
}

/// Options of a `v2ray-plugin` / `xray-plugin` child: the SIP003-expressible
/// subset of mihomo's `v2rayObfsOption`
/// (`adapter/outbound/shadowsocks.go:52-68`). Defaults mirror mihomo's
/// constructor (`Mux: true`, shadowsocks.go:272) and v2ray-plugin's own
/// flags (`main.go:47-56`): mode `websocket`, path `/`, mux on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2rayPluginOpts {
    /// `mode=<websocket|quic>` transport mode.
    pub mode: Option<String>,
    /// `host=<sni>` hostname for the websocket/TLS layer.
    pub host: Option<String>,
    /// `path=<p>` URL path (default `/`).
    pub path: Option<String>,
    /// bare `tls` flag.
    pub tls: bool,
    /// `mux=<0|1>` connection multiplexing (default on).
    pub mux: bool,
    /// `loglevel=<debug|info|warning|error|none>`.
    pub loglevel: Option<String>,
}

impl Default for V2rayPluginOpts {
    fn default() -> Self {
        V2rayPluginOpts {
            mode: None,
            host: None,
            path: None,
            tls: false,
            mux: true,
            loglevel: None,
        }
    }
}

/// A configured SIP003 external plugin: the binary to spawn and the
/// `SS_PLUGIN_OPTIONS` payload it will read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sip003Plugin {
    program: String,
    options: String,
}

impl Sip003Plugin {
    /// A plugin by raw program name/path and pre-encoded
    /// `SS_PLUGIN_OPTIONS` string (the `--plugin` / `--plugin-opts` CLI
    /// surface of ss-local).
    pub fn raw(program: &str, options: &str) -> Result<Self> {
        if program.is_empty() {
            return Err(Error::config("sip003: plugin name must not be empty"));
        }
        Ok(Sip003Plugin {
            program: program.to_string(),
            options: options.to_string(),
        })
    }

    /// mihomo `plugin: obfs` + `plugin-opts: {mode, host}` mapped to the
    /// `obfs-local` (simple-obfs) binary: `obfs=<mode>;obfs-host=<host>`.
    /// Mode must be `tls` or `http` — the same validation as mihomo's
    /// constructor (shadowsocks.go:266-268).
    pub fn obfs(mode: &str, host: Option<&str>) -> Result<Self> {
        if mode != "tls" && mode != "http" {
            return Err(Error::config(format!(
                "sip003: obfs mode error: {mode:?} (expected tls or http)"
            )));
        }
        let mut opts = vec![("obfs", Some(mode))];
        if let Some(host) = host.filter(|h| !h.is_empty()) {
            opts.push(("obfs-host", Some(host)));
        }
        Ok(Sip003Plugin {
            program: "obfs-local".to_string(),
            options: encode_plugin_options(&opts),
        })
    }

    /// mihomo `plugin: v2ray-plugin` mapped to the `v2ray-plugin` /
    /// `xray-plugin` binary (identical CLI): the option keys v2ray-plugin
    /// consumes from `SS_PLUGIN_OPTIONS` (`main.go:startV2ray`:
    /// `mode`, `mux`, `tls`, `host`, `path`, `loglevel`).
    pub fn v2ray(program: &str, opts: &V2rayPluginOpts) -> Result<Self> {
        if program.is_empty() {
            return Err(Error::config("sip003: plugin name must not be empty"));
        }
        let mut pairs: Vec<(&str, Option<&str>)> = Vec::new();
        if let Some(mode) = opts.mode.as_deref() {
            if !mode.is_empty() {
                pairs.push(("mode", Some(mode)));
            }
        }
        if opts.tls {
            pairs.push(("tls", None));
        }
        if let Some(host) = opts.host.as_deref() {
            if !host.is_empty() {
                pairs.push(("host", Some(host)));
            }
        }
        if let Some(path) = opts.path.as_deref() {
            if !path.is_empty() && path != "/" {
                pairs.push(("path", Some(path)));
            }
        }
        // v2ray-plugin's mux is an int flag; "0" disables it, bare "1" (the
        // default concurrency marker) enables it.
        pairs.push(("mux", if opts.mux { None } else { Some("0") }));
        if let Some(level) = opts.loglevel.as_deref() {
            if !level.is_empty() {
                pairs.push(("loglevel", Some(level)));
            }
        }
        Ok(Sip003Plugin {
            program: program.to_string(),
            options: encode_plugin_options(&pairs),
        })
    }

    /// The configured program name/path.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// The encoded `SS_PLUGIN_OPTIONS` value.
    pub fn options(&self) -> &str {
        &self.options
    }

    /// Spawn the plugin and return a stream to it: reserve a loopback
    /// port, fork/exec the child with the SIP003 environment, then dial
    /// the child's local listener (bounded retries, early-out if the child
    /// exits first). The returned stream owns the child; dropping it kills
    /// the plugin.
    pub async fn connect(&self, remote_host: &str, remote_port: u16) -> Result<Sip003Stream> {
        let program = resolve_plugin(&self.program).ok_or_else(|| {
            Error::config(format!(
                "sip003: plugin binary {:?} not found in . or PATH",
                self.program
            ))
        })?;
        let port = reserve_local_port().await?;
        let mut cmd = Command::new(&program);
        cmd.envs(sip003_envs(
            remote_host,
            remote_port,
            SIP003_LOCAL_HOST,
            port,
            &self.options,
        ))
        // The plugin's logs are not our protocol; piped stdio would fill
        // OS buffers and wedge the child once nothing drains them
        // (go-shadowsocks2 wires them to a logger instead).
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .map_err(|e| Error::config(format!("sip003: spawn {}: {e}", program.display())))?;
        let addr = format!("{SIP003_LOCAL_HOST}:{port}");
        let stream = match wait_and_dial(&addr, Some(&mut child), LISTEN_TIMEOUT).await {
            Ok(stream) => stream,
            Err(e) => {
                // Never leave the child behind on a failed handshake.
                let _ = child.start_kill();
                return Err(e);
            }
        };
        Ok(Sip003Stream { stream, child })
    }
}

/// Bind `127.0.0.1:0`, read the assigned port, drop the socket —
/// go-shadowsocks2's `getFreePort` (same TOCTOU window as upstream: the
/// plugin rebinds it a moment later).
async fn reserve_local_port() -> Result<u16> {
    let listener = TcpListener::bind((SIP003_LOCAL_HOST, 0u16))
        .await
        .map_err(|e| Error::network(format!("sip003: reserve local port: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::network(format!("sip003: local port: {e}")))?
        .port();
    drop(listener);
    Ok(port)
}

/// Dial `addr` until it answers or `deadline` passes, checking between
/// attempts that the child (if given) is still alive. `child: None` is the
/// in-memory path used by tests with a loopback listener standing in for
/// the plugin.
async fn wait_and_dial(
    addr: &str,
    mut child: Option<&mut Child>,
    deadline: Duration,
) -> Result<TcpStream> {
    let start = tokio::time::Instant::now();
    loop {
        if let TcpAttempt::Connected(stream) = try_dial(addr, &mut child).await? {
            return Ok(stream);
        }
        if start.elapsed() >= deadline {
            return Err(Error::network(format!(
                "sip003: plugin did not start listening on {addr} within {}s",
                deadline.as_secs()
            )));
        }
        sleep(LISTEN_RETRY_INTERVAL).await;
    }
}

/// One dial attempt: a refused connection is "not yet", a dead child is a
/// hard error, a live socket is success.
async fn try_dial(addr: &str, child: &mut Option<&mut Child>) -> Result<TcpAttempt> {
    if let Some(c) = child.as_mut() {
        if let Some(status) = c.try_wait().map_err(Error::Io)? {
            return Err(Error::network(format!(
                "sip003: plugin exited before listening (status {status})"
            )));
        }
    }
    match TcpStream::connect(addr).await {
        Ok(stream) => Ok(TcpAttempt::Connected(stream)),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Ok(TcpAttempt::Refused),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(TcpAttempt::Refused),
        Err(e) => Err(Error::network(format!("sip003: dial plugin at {addr}: {e}"))),
    }
}

enum TcpAttempt {
    Connected(TcpStream),
    Refused,
}

/// A Shadowsocks stream carried through a spawned SIP003 plugin: the TCP
/// connection to the plugin's local listener plus the child process. The
/// SS layer (salt + address header) writes through [`AsyncWrite`] as it
/// would over a plain server socket.
pub struct Sip003Stream {
    stream: TcpStream,
    child: Child,
}

impl Sip003Stream {
    /// The plugin's local address this stream is connected to.
    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }

    /// Shut the stream down, kill the plugin and reap it.
    pub async fn close(mut self) -> Result<()> {
        self.stream.shutdown().await.map_err(Error::Io)?;
        self.child.start_kill().map_err(Error::Io)?;
        self.child.wait().await.map_err(Error::Io)?;
        Ok(())
    }
}

impl AsyncRead for Sip003Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Sip003Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- option encoding ---

    #[test]
    fn options_encoding_follows_sip003() {
        // Plain pairs, bare keys, and the mandatory escaping of ; = \.
        assert_eq!(encode_plugin_options(&[]), "");
        assert_eq!(
            encode_plugin_options(&[("obfs", Some("http")), ("obfs-host", Some("bing.com"))]),
            "obfs=http;obfs-host=bing.com"
        );
        assert_eq!(encode_plugin_options(&[("tls", None)]), "tls");
        // A "1" value is emitted bare: it parses back identically.
        assert_eq!(encode_plugin_options(&[("mux", Some("1"))]), "mux");
        assert_eq!(encode_plugin_options(&[("mux", Some("0"))]), "mux=0");
        assert_eq!(
            encode_plugin_options(&[("k", Some("a;b=c\\d"))]),
            "k=a\\;b\\=c\\\\d"
        );
        assert_eq!(
            encode_plugin_options(&[("a;b", Some("x")), ("c=d", None)]),
            "a\\;b=x;c\\=d"
        );
        // Round trip through v2ray-plugin's parser semantics (args.go:
        // indexUnescaped): split on *unescaped* ';', key/value split at
        // the first *unescaped* '=', backslash unescape, bare -> "1".
        fn parse(s: &str) -> Vec<(String, String)> {
            let mut pairs = Vec::new();
            let mut key = String::new();
            let mut value: Option<String> = None;
            let mut escaped = false;
            for c in s.chars().chain(std::iter::once(';')) {
                if escaped {
                    match &mut value {
                        Some(v) => v.push(c),
                        None => key.push(c),
                    }
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == ';' {
                    let v = value.take().unwrap_or_else(|| "1".to_string());
                    if !key.is_empty() {
                        pairs.push((std::mem::take(&mut key), v));
                    } else {
                        key.clear();
                    }
                } else if c == '=' && value.is_none() {
                    value = Some(String::new());
                } else if let Some(v) = &mut value {
                    v.push(c);
                } else {
                    key.push(c);
                }
            }
            pairs
        }
        let encoded = encode_plugin_options(&[
            ("obfs", Some("http")),
            ("host", Some("a;b=c")),
            ("tls", None),
            ("we\\ird", Some("x")),
        ]);
        assert_eq!(
            parse(&encoded),
            vec![
                ("obfs".into(), "http".into()),
                ("host".into(), "a;b=c".into()),
                ("tls".into(), "1".into()),
                ("we\\ird".into(), "x".into()),
            ]
        );
    }

    // --- env table ---

    #[test]
    fn env_table_is_exactly_the_sip003_five() {
        let envs = sip003_envs("server.example", 8388, "127.0.0.1", 51000, "obfs=http");
        assert_eq!(
            envs,
            vec![
                ("SS_REMOTE_HOST".to_string(), "server.example".to_string()),
                ("SS_REMOTE_PORT".to_string(), "8388".to_string()),
                ("SS_LOCAL_HOST".to_string(), "127.0.0.1".to_string()),
                ("SS_LOCAL_PORT".to_string(), "51000".to_string()),
                ("SS_PLUGIN_OPTIONS".to_string(), "obfs=http".to_string()),
            ]
        );
        // SS_PLUGIN_OPTIONS is optional and omitted when empty.
        let envs = sip003_envs("s", 1, "127.0.0.1", 2, "");
        assert_eq!(envs.len(), 4);
        assert!(!envs.iter().any(|(k, _)| k == "SS_PLUGIN_OPTIONS"));
    }

    // --- per-plugin option mapping ---

    #[test]
    fn obfs_mapping_mirrors_simple_obfs() {
        let p = Sip003Plugin::obfs("http", Some("www.baidu.com")).unwrap();
        assert_eq!(p.program(), "obfs-local");
        assert_eq!(p.options(), "obfs=http;obfs-host=www.baidu.com");

        let p = Sip003Plugin::obfs("tls", None).unwrap();
        assert_eq!(p.options(), "obfs=tls");

        // Host default: mihomo seeds bing.com but does not require it; a
        // None host simply omits obfs-host.
        for bad in ["quic", "", "websocket"] {
            let err = Sip003Plugin::obfs(bad, None).unwrap_err();
            assert!(err.to_string().contains("obfs mode error"), "{err}");
        }
    }

    #[test]
    fn v2ray_mapping_mirrors_v2ray_plugin_flags() {
        // The README's canonical client forms.
        let p = Sip003Plugin::v2ray("v2ray-plugin", &V2rayPluginOpts::default()).unwrap();
        assert_eq!(p.program(), "v2ray-plugin");
        assert_eq!(p.options(), "mux");

        let p = Sip003Plugin::v2ray(
            "v2ray-plugin",
            &V2rayPluginOpts {
                tls: true,
                host: Some("mydomain.me".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p.options(), "tls;host=mydomain.me;mux");

        let p = Sip003Plugin::v2ray(
            "xray-plugin",
            &V2rayPluginOpts {
                mode: Some("quic".into()),
                host: Some("mydomain.me".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p.options(), "mode=quic;host=mydomain.me;mux");

        // path, mux off, loglevel.
        let p = Sip003Plugin::v2ray(
            "v2ray-plugin",
            &V2rayPluginOpts {
                host: Some("h".into()),
                path: Some("/ws".into()),
                mux: false,
                loglevel: Some("none".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p.options(), "host=h;path=/ws;mux=0;loglevel=none");

        // The default path "/" is v2ray-plugin's own default: omitted.
        let p = Sip003Plugin::v2ray(
            "v2ray-plugin",
            &V2rayPluginOpts {
                path: Some("/".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p.options(), "mux");
    }

    #[test]
    fn raw_plugin_and_validation() {
        let p = Sip003Plugin::raw("/usr/local/bin/custom-plugin", "secret=nou").unwrap();
        assert_eq!(p.program(), "/usr/local/bin/custom-plugin");
        assert_eq!(p.options(), "secret=nou");
        assert!(Sip003Plugin::raw("", "x").is_err());
        assert!(Sip003Plugin::v2ray("", &V2rayPluginOpts::default()).is_err());
    }

    // --- binary resolution (tempdir, no processes) ---

    #[test]
    fn resolve_plugin_searches_cwd_then_path_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("obfs-local");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        make_executable(&bin);

        // Not found anywhere.
        assert_eq!(resolve_plugin_in("obfs-local", &[]), None);
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_plugin_in("obfs-local", &[empty.path().to_path_buf()]),
            None
        );
        // Non-executable files never match (LookPath semantics).
        let plain = tempfile::tempdir().unwrap();
        std::fs::write(plain.path().join("obfs-local"), b"").unwrap();
        assert_eq!(
            resolve_plugin_in("obfs-local", &[plain.path().to_path_buf()]),
            None
        );
        // First executable hit wins in directory order.
        let other = tempfile::tempdir().unwrap();
        let bin2 = other.path().join("obfs-local");
        std::fs::write(&bin2, b"").unwrap();
        make_executable(&bin2);
        assert_eq!(
            resolve_plugin_in("obfs-local", &[dir.path().to_path_buf(), other.path().to_path_buf()]),
            Some(bin.clone())
        );
        assert_eq!(
            resolve_plugin_in("obfs-local", &[empty.path().to_path_buf(), other.path().to_path_buf()]),
            Some(bin2)
        );
        // A name with a separator is used verbatim.
        assert_eq!(
            resolve_plugin_in("./sub/obfs-local", &[dir.path().to_path_buf()]),
            Some(PathBuf::from("./sub/obfs-local"))
        );
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}

    // --- stream plumbing against a fake plugin (loopback, no processes) ---

    #[tokio::test]
    async fn wait_and_dial_connects_once_listener_appears() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // The fake plugin: listener comes up after a short delay, then it
        // echoes bytes back (a stand-in for the obfuscation tunnel).
        let listener = TcpListener::bind((SIP003_LOCAL_HOST, 0u16)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            sleep(Duration::from_millis(200)).await;
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });

        // No child: the retry loop must keep dialing through the delay.
        let mut stream = wait_and_dial(&addr.to_string(), None, Duration::from_secs(5))
            .await
            .unwrap();
        stream.write_all(b"salt-and-addr").await.unwrap();
        let mut got = [0u8; 64];
        let n = stream.read(&mut got).await.unwrap();
        assert_eq!(&got[..n], b"salt-and-addr");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wait_and_dial_times_out_when_nothing_listens() {
        // Reserve then abandon a port so nothing answers it.
        let port = reserve_local_port().await.unwrap();
        let addr = format!("{SIP003_LOCAL_HOST}:{port}");
        let err = wait_and_dial(&addr, None, Duration::from_millis(250))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("did not start listening"), "{err}");
    }

    #[tokio::test]
    async fn reserve_local_port_yields_distinct_usable_ports() {
        let a = reserve_local_port().await.unwrap();
        let b = reserve_local_port().await.unwrap();
        assert_ne!(a, b);
        // The port must be rebindable (the plugin rebinds it next).
        let l = TcpListener::bind((SIP003_LOCAL_HOST, a)).await.unwrap();
        assert_eq!(l.local_addr().unwrap().port(), a);
    }
}
