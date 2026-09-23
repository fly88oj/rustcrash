# Installation

RustCrash ships as a **single static binary** named `crash`. One file, no
runtime dependencies beyond `iptables` or `nftables` on the host.

## Platforms

| Platform | Target | Typical devices |
|----------|--------|-----------------|
| Linux x86_64 | `x86_64-unknown-linux-musl` | x86 boxes, containers (6.0 MB) |
| Linux ARM64 | `aarch64-unknown-linux-musl` | 64-bit routers, Raspberry Pi 3/4/5 (64-bit OS) (4.8 MB) |
| Linux ARMv7 HF | `armv7-unknown-linux-musleabihf` | 32-bit routers, Raspberry Pi 2/3/4 (32-bit OS) (4.2 MB) |
| Linux ARMv6 HF | `arm-unknown-linux-musleabihf` | Raspberry Pi Zero/1, legacy routers (4.2 MB) |
| Linux MIPS LE | `mipsel-unknown-linux-musl` | little-endian WiFi routers (MTK/Ath) — tier-3 (7.0 MB) |
| Linux MIPS BE | `mips-unknown-linux-musl` | big-endian routers (some Broadcom/Atheros) — tier-3 (7.1 MB) |
| Docker | any of the above | `docker build` from the repo Dockerfile |
| macOS / Windows | — | **Not supported**: the firewall layer drives iptables/nftables (Linux netfilter); macOS would need pf and Windows a WSL2/Docker host |

All targets are fully static (musl); the binary runs on any matching
CPU without runtime libraries.

## Quick install from a release (no toolchain needed)

1. Find out which file to download: run `uname -m` **on the target
   device** and match it below. On OpenWrt `opkg print-architecture`
   also works (`mipsel_*` = little-endian, `mips_*` = big-endian;
   plain `uname -m` on MIPS does not tell you the endianness).

   | `uname -m` says | Download the `…-<this>` target |
   |---|---|
   | `aarch64` or `arm64` | `aarch64-unknown-linux-musl` |
   | `armv7l` (also `armv8l` in 32-bit userland) | `armv7-unknown-linux-musleabihf` |
   | `armv6l` | `arm-unknown-linux-musleabihf` |
   | `x86_64` | `x86_64-unknown-linux-musl` |
   | `mips` / `mipsel` (endianness via opkg, see above) | `mips-…` / `mipsel-…` |

2. From the [Releases page](https://github.com/fly88oj/rustcrash/releases)
   download `rustcrash-<version>-<target>.tar.gz` and `SHA256SUMS`.

3. Verify, extract, install (on the device):

   ```bash
   sha256sum -c SHA256SUMS --ignore-missing
   tar -xzf rustcrash-*-<target>.tar.gz
   sudo install -m755 rustcrash-*/crash /usr/local/bin/crash
   ```

4. Continue with [First run](#first-run) below.

**No GitHub access from the device?** The later `crash install` step
downloads the mihomo kernel from GitHub (no mirror option there yet);
geo/rule updates do honor the `geo_mirror` config. As a workaround,
download the mihomo release on another machine, copy it to
`/etc/rustcrash/bin/mihomo` (OpenWrt: `/etc/ShellCrash/bin/mihomo`)
and `chmod +x` it — `crash start status` will then show it as
installed and `crash install` can be skipped.

## From source (release build)

Requires Rust 1.75+.

```bash
cargo build --release --bin crash
install -m 755 target/release/crash /usr/local/bin/crash
```

## Cross-compiling for a router or Raspberry Pi

The bundled script builds every target (tier-2 targets in Docker via
[cross-rs]; the two MIPS tier-3 targets on the host via
[cargo-zigbuild], since no cross-rs image exists for them):

```bash
bash scripts/cross-compile.sh          # all targets
bash scripts/cross-compile.sh aarch64  # one target (shorthand ok)
```

Binaries land in `target/cross/<target>/crash`.

Prerequisites:

- **Tier-2 targets** (aarch64/armv7/arm/x86_64): Docker only — the
  builds run inside `ghcr.io/cross-rs/cross:edge` (set `CROSS_IMAGE` to
  a digest-pinned ref for reproducible, supply-chain-locked builds).
- **MIPS targets**: Rust nightly with `rust-src` (`rustup toolchain
  install nightly --component rust-src`), plus
  `cargo install cargo-zigbuild --locked` and
  `python3 -m pip install --user ziglang==0.14.1`. Zig is pinned to
  0.14.x on purpose: 0.13 rejects the `musleabi` target spelling and
  0.16+ fails the link step.

To produce a full release directory (every target as a `.tar.gz` with
`SHA256SUMS`, each binary ELF-verified and smoke-run — emulated for the
cross-arch targets):

```bash
bash scripts/release.sh        # → dist/release-<version>/
```

Tag pushes (`v*`) build the same matrix in CI and attach the archives
to a GitHub release (`.github/workflows/release-build.yml`). Both
pipelines derive the version from `[workspace.package] version` in
`Cargo.toml` — bump it and add a `docs/CHANGELOG.md` entry for the new
version **before** pushing the tag, or the tag name and the artifact
versions will disagree.

[cross-rs]: https://github.com/cross-rs/cross
[cargo-zigbuild]: https://github.com/rust-cross/cargo-zigbuild

## Docker

```bash
docker build -t rustcrash .
docker run --rm --cap-add NET_ADMIN rustcrash crash --version
```

The image is Alpine-based, contains iptables/nftables, and runs the
single `crash` binary as its entrypoint.

## First run

```bash
sudo crash init --init       # directories + init-system integration
sudo crash install           # download the mihomo kernel (checksum verified)
crash config import <subscription-url>
sudo crash start serve       # supervisor: kernel watchdog + bot + API
```

Upgrades replace the single binary; state under `/etc/rustcrash` (or
`/etc/ShellCrash` on OpenWrt) is preserved.
