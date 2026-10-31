# Contributing to RustCrash

Thanks for your interest! RustCrash is a Rust rewrite of
[ShellCrash](https://github.com/juewuy/ShellCrash) — a cross-platform
manager for the mihomo and sing-box proxy kernels.

## Getting started

```bash
git clone <your-fork>
cd rustcrash
cargo build                 # debug build of the single `crash` binary
cargo test --workspace      # unit + integration tests (no network needed
                            # beyond GitHub API mocks via wiremock)
cargo clippy --workspace --all-targets   # must be warning-free for new code
```

The workspace layout:

| Path | Contents |
|------|----------|
| `core/` | `rustcrash-core` library: platform detection, config, firewall, service lifecycle, bot, notify, API server, geo/rules updaters, subconverter |
| `cmd/crash/` | the single `crash` binary (CLI + TUI) |
| `tests/integration/` | cross-crate integration tests |
| `scripts/` | cross-compilation and e2e helpers |

## Test suites

`cargo test --workspace` runs the unit + integration tests, but the
blessed way to run everything is the orchestrator:

```bash
scripts/run-all-tests.sh             # all suites, three parallel lanes
scripts/run-all-tests.sh --unit-only # just the cargo feature matrix
scripts/run-all-tests.sh --list      # what runs where
```

- **unit lane** — the feature matrix (workspace default features,
  `rustcrash-engine` with mihomo+singbox, `rustcrash-core` with the
  engine features, then doctests), on cargo-nextest when installed.
  nextest runs every test in its own process, so env-var and
  global-state mutations cannot leak between concurrently running
  tests. Plain `cargo test` still works (same tests, thread-parallel
  inside each test binary).
- **docker lane** — the hermetic container suites (docker,
  docker-cluster, docker-engine, docker-interop, docker-reality,
  docker-shellcrash) through a bounded pool (`PARALLEL_DOCKER`,
  default 4). Each suite owns its compose project and loopback netns;
  none bind host ports, so they run side by side safely.
- **heavy lane** — musl-verify then docker-matrix, sequentially: both
  drive the same host-side artifacts (`/tmp/rustcrash-musl`, the
  aarch64 cross target, `/tmp/qemu-aarch64`), guarded by flocks and
  content tags, so ordering only affects speed, not correctness.

Parallel-safety rules for new tests:

1. Bind listeners on port 0 (kernel-assigned) whenever the code path
   allows it; when the port must be known before the bind
   (config-driven listeners), draw it from
   `engine::test_support::unique_test_port()` — a host-wide,
   file-locked counter below the ephemeral port range. Never bind a
   literal port on the host. Exception class: a `:0` bind lands the
   LISTENER inside the kernel's ephemeral range, where a concurrent
   process's outbound connect can draw the same number as its source
   port; byte-level mock peers that assert on connection endings
   (strace-verified: stray RSTs) should therefore use
   `unique_test_port()` directly.
2. Never mutate process env vars or global statics in tests (build
   platforms with `Platform::for_crash_dir`); the few legacy
   exceptions survive only because nextest isolates each test in its
   own process.
3. Container suites must stay hermetic: their own compose project, no
   host `ports:` mappings, images tagged through
   `scripts/e2e-image-tag.sh` (content-addressed, so a stale image is
   impossible and parallel suites share one build).

## Ground rules

1. **Keep the public surface small.** New modules should hide behaviour
   behind a narrow interface (see `docs/ARCHITECTURE.md` for the module
   map). Prefer extending `core` over growing the binary.
2. **No shell commands built from strings.** Spawn with argument vectors;
   use `libc`/`nix` for signals. Validate paths interpolated into
   process spawns or URLs.
3. **No credentials in code, examples or tests.** Read secrets from
   config or environment variables; use placeholder values in tests.
4. **Tests required** for new behaviour. Unit tests live in the same file
   under `#[cfg(test)]`; HTTP-dependent code is tested against
   `wiremock`, never live services.
5. **Hermetic tests.** Build test platforms with
   `Platform::for_crash_dir(dir)` instead of mutating `CRASHDIR` —
   environment-variable mutation races between parallel tests.
6. **English comments and docs.** `//!` module docs for every new module.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`, …), wrapped at
72 characters, body explains *why*.

## Pull requests

- One logical change per PR.
- `cargo test --workspace` and `cargo clippy --workspace --all-targets`
  clean (pre-existing warnings may remain, new ones may not).
- Update `docs/` when user-facing behaviour changes.

## License

Dual MIT OR Apache-2.0. By contributing
you agree your work is licensed under both, at the recipient's option.
