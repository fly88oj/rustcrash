# RustCrash

[![CI](https://img.shields.io/badge/tests-500%2B-green)]() [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)]() [![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)]()

**单二进制、跨平台的 [mihomo](https://github.com/MetaCubeX/mihomo) / [sing-box](https://github.com/SagerNet/sing-box) 代理内核管理器 —— [ShellCrash](https://github.com/juewuy/ShellCrash) 的 Rust 重写版。**

[English](README.md) | 简体中文 | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md) | [Português](README.pt.md) | [Русский](README.ru.md)

## 为什么选择 RustCrash

ShellCrash 是经过长期验证的路由器透明代理脚本工具。RustCrash 完整保留其功能，但以**一个静态二进制**交付：无 shell 依赖、强类型配置、下载完整性校验，以及一整套测试用例。

- **单二进制** —— 所有功能（初始化、安装、防火墙、内核生命周期、订阅、定时任务、机器人、API）都是 `crash` 的子命令。
- **真实平台** —— Linux x86_64/ARM64/ARMv6/ARMv7/MIPS（musl 静态），覆盖路由器与树莓派；OpenWrt、Docker；iptables 与 nftables；systemd、OpenWrt init、OpenRC。
- **安装可验证** —— 内核下载先对照官方发布的 SHA-256 校验文件核验，再落盘。
- **原生订阅转换** —— 内置 8 种协议 URI 解析（VMess、VLESS、SS、SSR、Trojan、Hysteria2、TUIC、WireGuard）与 16 种输出格式（Clash、sing-box、Quantumult(X)、Loon、Surge、Surfboard、Stash、V2Ray 等），无需外部 subconverter。
- **远程管理** —— 内联菜单的 Telegram 机器人、带令牌鉴权的 REST API、7 个推送渠道的通知。

## 快速开始

第一次用？先看[安装指南](docs/INSTALL.md)——里面有 `uname -m` 与预编译二进制的对照表，**不需要装 Rust**。你还需要提前准备一条**机场订阅链接**（`config import` 那一步要用）。

```bash
sudo crash init --init        # 创建 /etc/rustcrash 并注册开机自启
sudo crash install            # 下载 mihomo 内核（SHA-256 校验；需要能访问 GitHub）
crash config import https://example.com/sub   # 换成你的订阅链接
crash config generate         # 根据订阅生成内核配置
sudo crash start serve        # 常驻进程：内核 + 看门狗 + 机器人 + REST API

# 确认跑起来了：
sudo crash start status       # 查看平台、内核与安装状态
sudo crash start logs         # 查看内核日志尾部
```

设备连不上 GitHub？内核可以离线安装：在别的机器下载 mihomo 发布包，放到 `/etc/rustcrash/bin/mihomo`（OpenWrt 为 `/etc/ShellCrash/bin/mihomo`）并 `chmod +x`，即可跳过 `crash install`。

想自己编译？`cargo build --release --bin crash` 后
`sudo install -m755 target/release/crash /usr/local/bin/`；路由器/树莓派交叉编译用 `bash scripts/cross-compile.sh`（详见安装指南）。

Docker：

```bash
docker build -t rustcrash .
docker run --rm --cap-add NET_ADMIN rustcrash crash --version
```

## 命令一览

| 功能 | 示例 |
|------|------|
| 内核生命周期 | `crash start start/stop/restart/status/logs/watchdog` |
| 监督进程 | `crash start serve`（REST API + Telegram 机器人 + 看门狗） |
| 防火墙 | `crash firewall setup --tun --ipv6 --quic-reject` / `cleanup` |
| 订阅 | `crash config import/list/select/generate`、`crash sub convert -t clash` |
| 更新任务 | `crash task enable --interval 12h`、`crash task geo`、`crash task rules` |
| Telegram 机器人 | 在 `config.yaml` 配置后执行 `crash start bot` |

完整参考：[CLI](docs/CLI.md) · [REST API](docs/API.md) · [Telegram 机器人](docs/BOT.md) · [配置说明](docs/CONFIGURATION.md)（英文）

## 安全性

在路由器上以 root 运行，因此规则很严格：进程仅以参数数组方式启动（不经 shell、不拼接命令字符串）；API 仅监听回环地址并支持令牌鉴权；机器人按聊天 ID 白名单过滤；下载原子写入并对文件名消毒；密钥只来自配置或环境变量。详见 [docs/SECURITY.md](docs/SECURITY.md)。

## 构建与测试

```bash
cargo test --workspace                 # 500+ 测试，无需外网
cargo clippy --workspace --all-targets
bash scripts/cross-compile.sh          # 6 个目标：ARM/ARM64/MIPS 路由器、树莓派、x86
bash scripts/release.sh                # 发布目录：各目标 tar.gz + SHA256SUMS
bash tests/docker/run.sh               # 多容器端到端实测
```

## 许可证

采用 [MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE) 双协议，任选其一。
