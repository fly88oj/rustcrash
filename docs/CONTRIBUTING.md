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
