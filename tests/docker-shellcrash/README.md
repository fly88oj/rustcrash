# docker-shellcrash — the ShellCrash migration e2e

The user story under test: **"I run ShellCrash on my box; I replace the
kernel with RustCrash's crash binary; everything keeps working."**

The suite installs the **REAL ShellCrash manager** (juewuy/ShellCrash dev
branch, `1.9.5beta3` — its own `install.sh`, its own release tarball)
inside the shared engine container, drives it the way a user does
(subscription import, `setconfig` settings, `start.sh start/stop`), proves
a full baseline with the **real mihomo kernel**, then performs the kernel
swap to the **Rust engine** and re-proves the same behaviors against
ShellCrash's OWN generated config — plus the CLI-compat surface of the
migrated box.

Everything runs inside one container's network namespace on `127.0.0.1`
(hermetic; the host's own transparent proxy on 7890 & co is never
touched). The ShellCrash payload tarball is **committed** under
`fixtures/` (174 KB — the scripts tree, not the 226 MB repo with kernels),
and the mihomo kernel comes from the host cache shared with
`tests/docker-interop` or the copy baked into the engine image, so a warm
host needs **no network at all**.

```
bash tests/docker-shellcrash/run.sh
```

## The migration matrix

| Phase | What | Kernel |
|---|---|---|
| A | `bash install.sh` (real installer, in-container payload server stands in for jsdelivr; stdin answers for dir/confirm/alias) | — |
| B | user configuration: `yamls/config.yaml` subscription + `setconfig` overrides (`firewall_area=2`, `dns_mod=redir_host`, `authentication`, hermetic `dns_nameserver`) | — |
| 1 | baseline: `start.sh start`, nft `inet shellcrash` table, DNS hijack, per-node relay (ss / vmess / vmess-ws against an in-container mihomo server), panel API, negatives, stop | real mihomo |
| 2 | migration: raw drop-in probe (pinned engine gap A), then the CLI adapter as `$TMPDIR/CrashCore` and the SAME start flow — engine identity, listeners, validation, firewall, DNS hijack, relay matrix, negatives, stop, restart | Rust engine |
| 3 | CLI compat: `/usr/bin/crash` still wraps ShellCrash's menu; `crash engine version/test`, `crash firewall show` on the migrated layout; the manager-config collision (gap H) | both |
| 4 | the SAME converter-shaped subscription relays identically through both kernels | both |

## How the kernel swap actually works (and why the adapter exists)

ShellCrash stores its kernel as `$BINDIR/CrashCore.*` archives and
re-materializes `$TMPDIR/CrashCore` from them on every start
(`starts/check_core.sh` → `libs/core_tools.sh` `core_find`). It then
invokes the kernel with **mihomo's CLI convention**, hardcoded in its own
scripts:

```
CrashCore -t -d $BINDIR -f $TMPDIR/config.yaml    # starts/clash_modify.sh test_yaml
CrashCore    -d $BINDIR -f $TMPDIR/config.yaml    # configs/command.env COMMAND
CrashCore -v / -h                                 # core_check() kernel probes
```

The RustCrash binary speaks `crash engine run|test --flavor rust-mihomo
--config FILE` instead, so the raw drop-in fails at the very first probe
(pinned as **gap A**). The committed migration adapter
`fixtures/rustcrash-kernel-adapter.sh` bridges the two conventions and
additionally re-spells the three mihomo-dialect forms of ShellCrash's
generator the engine cannot parse yet (**gaps B, C, E**); with it in
place, ShellCrash's stock kernel invocation works unchanged. The adapter
is padded past `check_core`'s `find -size +2000` threshold so ShellCrash
recognizes it as a kernel file.

## Engine gaps pinned (EXPECTED-FAIL, counted as SKIP)

| Gap | Symptom (reproduced on isolated instances where noted) |
|---|---|
| A | raw binary drop-in: `CrashCore -t/-d/-f` and `-v` are rejected with clap's `unexpected argument '-t'/'-v'`; `core_check()` greps `-h` for `-t` and would classify the binary as "not a kernel" |
| B | `mode: Rule` (mihomo lowercases mode; ShellCrash's set.yaml hardcodes the capitalized form) → `config: bad mode "Rule"` — every ShellCrash-generated config is refused without normalization |
| C | dns `listen: :1053` (mihomo's all-interfaces shorthand, what ShellCrash's dns.yaml always emits) → `config: bad dns listen ":1053"` (`engine/src/app.rs` `spawn_dns_server` requires a full SocketAddr) |
| E | `external-controller: :9999` (set.yaml form) → `network: api bind :9999: failed to lookup address information` at run time |
| D | `fake-ip-filter: ['+.*']` (ShellCrash's redir_host emulation) is accepted but not implemented as match-all (`engine/src/rule.rs` `add_domain_line` maps it to suffix `*`) → DNS answers become fake-ips instead of real upstream answers |
| F | set.yaml `authentication` is silently ignored → wrong/absent proxy credentials still relay; mihomo refuses them (open-proxy regression) |
| G | one direct connection to the tproxy port is relayed back to the tproxy port — ~1000 half-closed connections and FD exhaustion in seconds; the engine ignores set.yaml's `routing-mark`, so the firewall's `meta mark 7894 return` loop-guard never exempts the engine's own dials (isolated repro on ports 47xxx) |
| H | `crash -c /etc/ShellCrash config show` fails `missing field kernel`: RustCrash's ConfigManager expects its own manager format at `$CRASHDIR/config.yaml`, which on a ShellCrash layout is the KERNEL config symlink |
| I | (conditional) SIGTERM shutdown can linger: the engine logs `shutting down` but the process races its own tasks; the stop check allows a 15s window and pins the gap only when the process is still alive past it — ShellCrash's `stop` (TERM + `killall CrashCore`, which cannot match the engine's comm) provides no fallback |

## Fixtures

* `ShellCrash.tar.gz`, `version`, `install.sh` — the upstream dev-branch
  release payload (committing it keeps the suite offline; byte-identical
  to what `install.sh` would fetch).
* `fetch-shellcrash.sh` — resolves the payload (committed fixture → host
  cache `~/.cache/rustcrash-e2e` → GitHub raw fallback) and the mihomo
  kernel (interop host cache → the image's `/usr/local/bin/mihomo`).
* `subscription-config.yaml` — the converter-emitted multi-proxy shape
  (incl. junk keys ShellCrash must discard); imported to
  `yamls/config.yaml` like a real subscription.
* `mihomo-server.yaml` — the in-container "remote" (ss / vmess / vmess-ws
  listeners, TLS-free), same listener syntax the interop suite verified
  against the real binary.
* `rustcrash-kernel-adapter.sh` — the migration adapter (see above).
* `webroot/hello.txt` — the relay body oracle.

## Notes

* The engine image is the shared `docker-engine-rustcrash`
  (`tests/docker-engine/Dockerfile.engine`), built from committed HEAD
  (`git archive`), with the interop suite's `E2E_FORCE_BUILD` /
  `E2E_WORKING_TREE_BUILD` knobs.
* The install alias is `sc`, not `crash`: on the migrated box a `crash`
  command already exists (the RustCrash binary at `/usr/local/bin/crash`)
  and `install.sh` refuses conflicting aliases. Both coexist afterwards:
  `crash` on PATH is the engine binary, `/usr/bin/crash` is ShellCrash's
  menu wrapper.
* Never connect to the tproxy port (7893) while the engine runs — that is
  gap G's trigger; listener checks use `ss -tln` instead.
* All credentials are fake test values; no real endpoints are contacted.
