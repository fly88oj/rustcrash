# RustCrash

[![CI](https://img.shields.io/badge/tests-500%2B-green)]() [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)]() [![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)]()

**Um gerenciador multiplataforma de binário único para os kernels de proxy [mihomo](https://github.com/MetaCubeX/mihomo) e [sing-box](https://github.com/SagerNet/sing-box) — uma reescrita em Rust do [ShellCrash](https://github.com/juewuy/ShellCrash).**

[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md) | Português | [Русский](README.ru.md)

## Por que o RustCrash

O ShellCrash é um kit shell testado em combate para rodar proxies
transparentes em roteadores. O RustCrash mantém o conjunto de
funcionalidades dele, mas é entregue como **um único binário estático**:
sem dependências de shell, configuração tipada, downloads verificados e
uma suíte de testes completa.

- **Um binário só** — cada função (init, install, firewall, ciclo de
  vida, assinaturas, agendamento, bot, API) é um subcomando de `crash`.
- **Plataformas reais** — Linux x86_64/ARM64/ARMv6/ARMv7/MIPS (musl,
  estático) para roteadores e Raspberry Pi, OpenWrt, Docker; iptables e
  nftables; systemd, OpenWrt init e OpenRC.
- **Instalações verificadas** — os downloads do kernel são conferidos
  por SHA-256 contra os checksums oficiais antes de tocar o disco.
- **Conversão de assinaturas nativa** — 8 parsers de URI de protocolo
  (VMess, VLESS, SS, SSR, Trojan, Hysteria2, TUIC, WireGuard) e 16
  formatos de saída (Clash, sing-box, Quantumult(X), Loon, Surge,
  Surfboard, Stash, V2Ray, …), sem binário subconverter externo.
- **Gerenciamento remoto** — bot do Telegram com menus inline, API REST
  com autenticação por token, notificações push para 7 provedores.

## Início rápido

Primeira vez? Abra o [guia de instalação](docs/INSTALL.md) — ele mapeia
o seu dispositivo (`uname -m`) para o binário pré-compilado certo, então
você não precisa de toolchain Rust. Você também vai precisar de uma
**URL de assinatura de proxy** do seu provedor para a etapa
`config import`.

```bash
sudo crash init --init        # cria /etc/rustcrash + registra no init system
sudo crash install            # baixa o kernel mihomo (SHA-256 verificado; requer acesso ao GitHub)
crash config import https://example.com/sub   # a sua URL de assinatura
crash config generate         # escreve a config do kernel a partir da assinatura
sudo crash start serve        # supervisor: kernel + watchdog + bot + API REST

# confirmar que está vivo:
sudo crash start status       # plataforma, kernel escolhido, estado da instalação
sudo crash start logs         # fim do log do kernel
```

O dispositivo não acessa o GitHub? O kernel pode ser instalado offline:
baixe o release do mihomo em outra máquina, copie para
`/etc/rustcrash/bin/mihomo` (no OpenWrt: `/etc/ShellCrash/bin/mihomo`)
e dê `chmod +x` — assim você pode pular o `crash install`.

Prefere compilar? `cargo build --release --bin crash` e depois
`sudo install -m755 target/release/crash /usr/local/bin/`; para
roteadores e Raspberry Pi use `bash scripts/cross-compile.sh` (veja o
guia de instalação).

Docker:

```bash
docker build -t rustcrash .
docker run --rm --cap-add NET_ADMIN rustcrash crash --version
```

## Comandos

| Área | Exemplos |
|------|----------|
| Ciclo de vida | `crash start start/stop/restart/status/logs/watchdog` |
| Supervisor | `crash start serve` (API REST + bot do Telegram + watchdog) |
| Firewall | `crash firewall setup --tun --ipv6 --quic-reject` / `cleanup` |
| Assinaturas | `crash config import/list/select/generate`, `crash sub convert -t clash` |
| Atualizações | `crash task enable --interval 12h`, `crash task geo`, `crash task rules` |
| Bot do Telegram | configure no `config.yaml`, depois `crash start bot` |

Referência completa: [CLI](docs/CLI.md) · [API REST](docs/API.md) ·
[Bot do Telegram](docs/BOT.md) · [Configuração](docs/CONFIGURATION.md) (em inglês)

## Segurança

Roda como root em roteadores, então as regras são rígidas: processos
lançados apenas com vetor de argumentos (sem shell, sem comandos montados
como strings), API apenas em loopback com token, whitelist de chat-IDs
para o bot, downloads atômicos e sanitizados, segredos somente de
config ou variáveis de ambiente. Veja [docs/SECURITY.md](docs/SECURITY.md).

## Build e testes

```bash
cargo test --workspace                 # 500+ testes, sem rede
cargo clippy --workspace --all-targets
bash scripts/cross-compile.sh          # 6 alvos: roteadores ARM/ARM64/MIPS, Pi, x86
bash scripts/release.sh                # diretório de release: tar.gz por alvo + SHA256SUMS
bash tests/docker/run.sh               # e2e multicontêiner (binário real)
```

## Estrutura do projeto

```
core/            biblioteca rustcrash-core (platform, service, bot, notify,
                 api, geo, rules, firewall, subconverter, …)
cmd/crash/       o binário único crash (CLI + TUI)
tests/           suítes de integração + e2e Docker
docs/            docs de CLI / API / bot / config / arquitetura / segurança
```

Detalhes de arquitetura: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Roadmap e compatibilidade

A paridade de funcionalidades com o núcleo do ShellCrash está completa
até os recursos avançados dele (TUN, IPv6, tratamento de VM/Docker,
hooks de tarefas, bot do Telegram, canais push). Fora do escopo inicial:
modo PAC, ferramentas SSH, DDNS.

## Licença

Duplamente licenciado sob [MIT](LICENSE-MIT) ou [Apache-2.0](LICENSE-APACHE), à sua escolha.
