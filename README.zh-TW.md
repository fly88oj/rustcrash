# RustCrash

[![CI](https://img.shields.io/badge/tests-500%2B-green)]() [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)]() [![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)]()

**單一二進位檔、跨平台的 [mihomo](https://github.com/MetaCubeX/mihomo) / [sing-box](https://github.com/SagerNet/sing-box) 代理核心管理器 —— [ShellCrash](https://github.com/juewuy/ShellCrash) 的 Rust 重寫版。**

[English](README.md) | [简体中文](README.zh-CN.md) | 繁體中文 | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md) | [Português](README.pt.md) | [Русский](README.ru.md)

## 為什麼選擇 RustCrash

ShellCrash 是一套久經考驗、在路由器上執行透明代理的 shell 工具組。RustCrash 完整保留其功能，但以**單一靜態二進位檔**交付：無 shell 相依、強型別設定、下載完整性校驗，並附完整測試套件。

- **單一二進位檔** —— 所有功能（初始化、安裝、防火牆、生命週期、訂閱、排程、機器人、API）都是 `crash` 的子命令。
- **真實平台** —— Linux x86_64/ARM64/ARMv6/ARMv7/MIPS（musl 靜態），支援路由器與樹莓派；OpenWrt、Docker；iptables 與 nftables；systemd、OpenWrt init、OpenRC。
- **可驗證的安裝** —— 核心下載先對照官方發布的 SHA-256 校驗檔核驗，才會落碟。
- **原生訂閱轉換** —— 內建 8 種協定 URI 解析（VMess、VLESS、SS、SSR、Trojan、Hysteria2、TUIC、WireGuard）與 16 種輸出格式（Clash、sing-box、Quantumult(X)、Loon、Surge、Surfboard、Stash、V2Ray 等），無需外部 subconverter。
- **遠端管理** —— 內嵌選單的 Telegram 機器人、帶權杖鑑權的 REST API、7 個推送通道的通知。

## 快速開始

第一次使用？先看[安裝指南](docs/INSTALL.md)——內有 `uname -m` 與預編譯二進位檔的對照表，**不需要安裝 Rust**。你還需要先準備一條**代理訂閱連結**（`config import` 那一步要用）。

```bash
sudo crash init --init        # 建立 /etc/rustcrash 並註冊開機自啟
sudo crash install            # 下載 mihomo 核心（SHA-256 校驗；需要能存取 GitHub）
crash config import https://example.com/sub   # 換成你的訂閱連結
crash config generate         # 根據訂閱產生核心設定
sudo crash start serve        # 常駐程序：核心 + 看門狗 + 機器人 + REST API

# 確認跑起來了：
sudo crash start status       # 查看平台、核心與安裝狀態
sudo crash start logs         # 查看核心日誌尾端
```

裝置連不上 GitHub？核心可以離線安裝：在其他機器下載 mihomo 發布包，放到 `/etc/rustcrash/bin/mihomo`（OpenWrt 為 `/etc/ShellCrash/bin/mihomo`）並 `chmod +x`，即可略過 `crash install`。

想自行編譯？`cargo build --release --bin crash` 後執行
`sudo install -m755 target/release/crash /usr/local/bin/`；路由器／樹莓派交叉編譯用 `bash scripts/cross-compile.sh`（詳見安裝指南）。

Docker：

```bash
docker build -t rustcrash .
docker run --rm --cap-add NET_ADMIN rustcrash crash --version
```

## 命令一覽

| 功能 | 範例 |
|------|------|
| 核心生命週期 | `crash start start/stop/restart/status/logs/watchdog` |
| 常駐監督 | `crash start serve`（REST API + Telegram 機器人 + 看門狗） |
| 防火牆 | `crash firewall setup --tun --ipv6 --quic-reject` / `cleanup` |
| 訂閱 | `crash config import/list/select/generate`、`crash sub convert -t clash` |
| 更新任務 | `crash task enable --interval 12h`、`crash task geo`、`crash task rules` |
| Telegram 機器人 | 在 `config.yaml` 設定後執行 `crash start bot` |

完整參考：[CLI](docs/CLI.md) · [REST API](docs/API.md) · [Telegram 機器人](docs/BOT.md) · [設定說明](docs/CONFIGURATION.md)（英文）

## 安全性

在路由器上以 root 執行，因此規則很嚴格：程序僅以參數陣列方式啟動（不經 shell、不拼接命令字串）；API 僅監聽回環位址並支援權杖鑑權；機器人按聊天 ID 白名單過濾；下載原子寫入並對檔名消毒；密鑰只來自設定或環境變數。詳見 [docs/SECURITY.md](docs/SECURITY.md)。

## 建置與測試

```bash
cargo test --workspace                 # 500+ 測試，無需外網
cargo clippy --workspace --all-targets
bash scripts/cross-compile.sh          # 6 個目標：ARM/ARM64/MIPS 路由器、樹莓派、x86
bash scripts/release.sh                # 發布目錄：各目標 tar.gz + SHA256SUMS
bash tests/docker/run.sh               # 多容器端到端實測
```

## 專案結構

```
core/            rustcrash-core 函式庫（platform、service、bot、notify、
                 api、geo、rules、firewall、subconverter、…）
cmd/crash/       單一 crash 二進位檔（CLI + TUI）
tests/           整合測試 + Docker 端到端測試
docs/            CLI / API / 機器人 / 設定 / 架構 / 安全文件
```

架構細節：[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 路線圖與相容性

與 ShellCrash 核心的功能對齊已涵蓋其進階功能（TUN、IPv6、VM/Docker 處理、任務掛鉤、Telegram 機器人、推送通道）。暫不納入：PAC 模式、SSH 工具、DDNS。

## 授權條款

採 [MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE) 雙授權，任選其一。
