# RustCrash

[![CI](https://img.shields.io/badge/tests-500%2B-green)]() [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)]() [![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)]()

**mihomo / sing-box プロキシカーネル向けシングルバイナリ・クロスプラットフォーム管理ツール —— [ShellCrash](https://github.com/juewuy/ShellCrash) の Rust 書き直し版。**

[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | 日本語 | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md) | [Português](README.pt.md) | [Русский](README.ru.md)

## RustCrash について

ShellCrash はルーター上で透過プロキシを運用するための長年実績のあるシェルツールキットです。RustCrash はその機能セットを保ちつつ、**静的リンクの単一バイナリ**として提供します。シェル依存なし・型付き設定・ダウンロード整合性検証・テストスイート付き。

- **ワンバイナリ** —— 初期化・インストール・ファイアウォール・カーネル操作・サブスクリプション・定期タスク・ボット・API のすべてが `crash` のサブコマンド。
- **実プラットフォーム対応** —— Linux x86_64 / ARM64 / ARMv6 / ARMv7 / MIPS（musl 静的リンク）。ルーターと Raspberry Pi 向け。OpenWrt、Docker。iptables と nftables、systemd / OpenWrt init / OpenRC に対応。
- **検証済みインストール** —— カーネルのダウンロードはリリース公開の SHA-256 チェックサムと照合してから導入。
- **ネイティブなサブスクリプション変換** —— 8 プロトコルの URI パーサー（VMess・VLESS・SS・SSR・Trojan・Hysteria2・TUIC・WireGuard）と 16 種の出力フォーマット（Clash、sing-box、Quantumult(X)、Loon、Surge、Surfboard、Stash、V2Ray など）。外部 subconverter 不要。
- **リモート管理** —— インラインメニューの Telegram ボット、トークン認証付き REST API、7 種のプッシュ通知プロバイダー。

## クイックスタート

初めての方はまず[インストールガイド](docs/INSTALL.md)へ —— `uname -m` と
プリビルドバイナリの対応表があり、**Rust の導入は不要**です。また
`config import` のステップで使う**プロバイダーのサブスクリプション URL**
を事前に用意してください。

```bash
sudo crash init --init        # /etc/rustcrash 作成 + 自動起動登録
sudo crash install            # mihomo カーネルのダウンロード（SHA-256 検証、GitHub へのアクセスが必要）
crash config import https://example.com/sub   # 自分のサブスクリプション URL に置き換える
crash config generate         # サブスクリプションからカーネル設定を生成
sudo crash start serve        # 常駐プロセス：カーネル + watchdog + ボット + REST API

# 動作確認：
sudo crash start status       # プラットフォーム・カーネル・インストール状態
sudo crash start logs         # カーネルログの末尾
```

デバイスが GitHub に接続できない場合：別のマシンで mihomo のリリースを
ダウンロードし、`/etc/rustcrash/bin/mihomo`（OpenWrt は
`/etc/ShellCrash/bin/mihomo`）に置いて `chmod +x` すれば
`crash install` は省略できます。

自分でビルドする場合：`cargo build --release --bin crash` の後
`sudo install -m755 target/release/crash /usr/local/bin/`。ルーター /
Raspberry Pi 用のクロスコンパイルは `bash scripts/cross-compile.sh`
（詳細はインストールガイド）。

Docker：

```bash
docker build -t rustcrash .
docker run --rm --cap-add NET_ADMIN rustcrash crash --version
```

## 主なコマンド

| 機能 | 例 |
|------|-----|
| カーネル操作 | `crash start start/stop/restart/status/logs/watchdog` |
| スーパーバイザー | `crash start serve`（REST API + Telegram ボット + ウォッチドッグ） |
| ファイアウォール | `crash firewall setup --tun --ipv6 --quic-reject` / `cleanup` |
| サブスクリプション | `crash config import/list/select/generate`、`crash sub convert -t clash` |
| 更新タスク | `crash task enable --interval 12h`、`crash task geo`、`crash task rules` |
| Telegram ボット | `config.yaml` で設定して `crash start bot` |

完全なリファレンス：[CLI](docs/CLI.md) · [REST API](docs/API.md) · [Telegram ボット](docs/BOT.md) · [設定](docs/CONFIGURATION.md)（英語）

## セキュリティ

ルーター上で root 権限で動作するため、ルールは厳格です。プロセス起動は引数配列のみ（シェルなし・コマンド文字列の組み立てなし）。API はループバック専用でトークン認証に対応。ボットはチャット ID のホワイトリストで制限。ダウンロードはアトミックに書き込み、ファイル名をサニタイズ。シークレットは設定ファイルまたは環境変数のみから読み込み。詳細は [docs/SECURITY.md](docs/SECURITY.md)。

## ビルドとテスト

```bash
cargo test --workspace                 # 500 以上のテスト（外部ネットワーク不要）
cargo clippy --workspace --all-targets
bash scripts/cross-compile.sh          # 6 ターゲット：ARM/ARM64/MIPS ルーター・Pi・x86
bash scripts/release.sh                # リリース用ディレクトリ：ターゲット別 tar.gz + SHA256SUMS
bash tests/docker/run.sh               # マルチコンテナ E2E テスト
```

## ライセンス

[MIT](LICENSE-MIT) または [Apache-2.0](LICENSE-APACHE) のデュアルライセンスです（どちらかを選択）。
