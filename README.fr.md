# RustCrash

[![CI](https://img.shields.io/badge/tests-500%2B-green)]() [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)]() [![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)]()

**Un gestionnaire multiplateforme à binaire unique pour les noyaux de proxy [mihomo](https://github.com/MetaCubeX/mihomo) et [sing-box](https://github.com/SagerNet/sing-box) — une réécriture en Rust de [ShellCrash](https://github.com/juewuy/ShellCrash).**

[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | Français | [Deutsch](README.de.md) | [Português](README.pt.md) | [Русский](README.ru.md)

## Pourquoi RustCrash

ShellCrash est une boîte à outils shell éprouvée pour faire tourner des
proxys transparents sur des routeurs. RustCrash conserve ses
fonctionnalités mais se présente sous forme d'**un unique binaire
statique** : aucune dépendance shell, configuration typée, téléchargements
vérifiés, et une suite de tests complète.

- **Un seul binaire** — chaque fonction (init, install, pare-feu, cycle
  de vie, abonnements, planification, bot, API) est une sous-commande de
  `crash`.
- **De vraies plateformes** — Linux x86_64/ARM64/ARMv6/ARMv7/MIPS (musl,
  statique) pour routeurs et Raspberry Pi, OpenWrt, Docker ; iptables et
  nftables ; systemd, OpenWrt init et OpenRC.
- **Installations vérifiées** — les téléchargements du noyau sont
  contrôlés par SHA-256 contre les checksums officiels avant toute
  écriture sur disque.
- **Conversion d'abonnements native** — 8 analyseurs d'URI de protocole
  (VMess, VLESS, SS, SSR, Trojan, Hysteria2, TUIC, WireGuard) et 16
  formats de sortie (Clash, sing-box, Quantumult(X), Loon, Surge,
  Surfboard, Stash, V2Ray, …), sans binaire subconverter externe.
- **Administration à distance** — bot Telegram à menus inline, API REST
  avec authentification par token, notifications push vers 7 fournisseurs.

## Démarrage rapide

Première fois ? Ouvrez le [guide d'installation](docs/INSTALL.md) — il
associe votre appareil (`uname -m`) au bon binaire précompilé, vous
n'avez donc pas besoin de toolchain Rust. Il vous faudra aussi une
**URL d'abonnement de proxy** de votre fournisseur pour l'étape
`config import`.

```bash
sudo crash init --init        # crée /etc/rustcrash + enregistre le système d'init
sudo crash install            # télécharge le noyau mihomo (SHA-256 vérifié ; accès GitHub requis)
crash config import https://example.com/sub   # votre URL d'abonnement
crash config generate         # écrit la config du noyau à partir de l'abonnement
sudo crash start serve        # superviseur : noyau + watchdog + bot + API REST

# vérifier que ça tourne :
sudo crash start status       # plateforme, noyau choisi, état d'installation
sudo crash start logs         # fin du journal du noyau
```

L'appareil n'a pas accès à GitHub ? Le noyau peut s'installer hors
ligne : téléchargez la release de mihomo sur une autre machine, copiez-la
dans `/etc/rustcrash/bin/mihomo` (OpenWrt : `/etc/ShellCrash/bin/mihomo`)
puis `chmod +x` ; vous pouvez ainsi ignorer `crash install`.

Vous préférez compiler ? `cargo build --release --bin crash` puis
`sudo install -m755 target/release/crash /usr/local/bin/` ; pour les
routeurs et Raspberry Pi, utilisez `bash scripts/cross-compile.sh`
(voir le guide d'installation).

Docker :

```bash
docker build -t rustcrash .
docker run --rm --cap-add NET_ADMIN rustcrash crash --version
```

## Commandes

| Domaine | Exemples |
|---------|----------|
| Cycle de vie | `crash start start/stop/restart/status/logs/watchdog` |
| Superviseur | `crash start serve` (API REST + bot Telegram + watchdog) |
| Pare-feu | `crash firewall setup --tun --ipv6 --quic-reject` / `cleanup` |
| Abonnements | `crash config import/list/select/generate`, `crash sub convert -t clash` |
| Mises à jour | `crash task enable --interval 12h`, `crash task geo`, `crash task rules` |
| Bot Telegram | à configurer dans `config.yaml`, puis `crash start bot` |

Référence complète : [CLI](docs/CLI.md) · [API REST](docs/API.md) ·
[Bot Telegram](docs/BOT.md) · [Configuration](docs/CONFIGURATION.md) (en anglais)

## Sécurité

Le programme tourne en root sur les routeurs, donc les règles sont
strictes : processus lancés uniquement par vecteur d'arguments (pas de
shell, pas de commandes assemblées en chaînes), API en loopback uniquement
avec token, liste blanche de chat-IDs pour le bot, téléchargements
atomiques et assainis, secrets uniquement depuis la config ou des
variables d'environnement. Voir [docs/SECURITY.md](docs/SECURITY.md).

## Compilation et tests

```bash
cargo test --workspace                 # 500+ tests, sans réseau
cargo clippy --workspace --all-targets
bash scripts/cross-compile.sh          # 6 cibles : routeurs ARM/ARM64/MIPS, Pi, x86
bash scripts/release.sh                # répertoire de release : tar.gz par cible + SHA256SUMS
bash tests/docker/run.sh               # e2e multi-conteneurs (vrai binaire)
```

## Structure du projet

```
core/            bibliothèque rustcrash-core (platform, service, bot, notify,
                 api, geo, rules, firewall, subconverter, …)
cmd/crash/       le binaire unique crash (CLI + TUI)
tests/           suites d'intégration + e2e Docker
docs/            docs CLI / API / bot / config / architecture / sécurité
```

Détails d'architecture : [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Feuille de route et compatibilité

La parité fonctionnelle avec le cœur de ShellCrash est complète jusqu'à
ses fonctions avancées (TUN, IPv6, gestion VM/Docker, hooks de tâches,
bot Telegram, canaux push). Hors périmètre initial : mode PAC, outils
SSH, DDNS.

## Licence

Sous double licence [MIT](LICENSE-MIT) ou [Apache-2.0](LICENSE-APACHE), au choix.
