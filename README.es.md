# RustCrash

[![CI](https://img.shields.io/badge/tests-500%2B-green)]() [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)]() [![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)]()

**Un gestor multiplataforma de un solo binario para los núcleos de proxy [mihomo](https://github.com/MetaCubeX/mihomo) y [sing-box](https://github.com/SagerNet/sing-box) — una reescritura en Rust de [ShellCrash](https://github.com/juewuy/ShellCrash).**

[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | Español | [Français](README.fr.md) | [Deutsch](README.de.md) | [Português](README.pt.md) | [Русский](README.ru.md)

## Por qué RustCrash

ShellCrash es un kit shell probado en batalla para ejecutar proxies
transparentes en routers. RustCrash conserva todo su conjunto de
funciones, pero se distribuye como **un único binario estático**: sin
dependencias de shell, configuración tipada, descargas verificadas y
una suite de tests completa.

- **Un solo binario** — cada función (init, install, firewall, ciclo de
  vida, suscripciones, programación, bot, API) es un subcomando de
  `crash`.
- **Plataformas reales** — Linux x86_64/ARM64/ARMv6/ARMv7/MIPS (musl,
  estático) para routers y Raspberry Pi, OpenWrt, Docker; iptables y
  nftables; systemd, OpenWrt init y OpenRC.
- **Instalaciones verificadas** — las descargas del núcleo se comprueban
  con SHA-256 contra los checksums oficiales antes de tocar el disco.
- **Conversión de suscripciones nativa** — 8 parsers de URI de protocolo
  (VMess, VLESS, SS, SSR, Trojan, Hysteria2, TUIC, WireGuard) y 16
  formatos de salida (Clash, sing-box, Quantumult(X), Loon, Surge,
  Surfboard, Stash, V2Ray, …), sin binario subconverter externo.
- **Gestión remota** — bot de Telegram con menús inline, API REST con
  autenticación por token, notificaciones push a 7 proveedores.

## Inicio rápido

¿Primera vez? Abre la [guía de instalación](docs/INSTALL.md) — relaciona
tu dispositivo (`uname -m`) con el binario precompilado correcto, así no
necesitas toolchain de Rust. También necesitarás una **URL de
suscripción de proxy** de tu proveedor para el paso `config import`.

```bash
sudo crash init --init        # crea /etc/rustcrash + registra el init system
sudo crash install            # descarga el núcleo mihomo (SHA-256 verificado; requiere acceso a GitHub)
crash config import https://example.com/sub   # tu URL de suscripción
crash config generate         # escribe la config del núcleo desde la suscripción
sudo crash start serve        # supervisor: núcleo + watchdog + bot + API REST

# confirmar que está vivo:
sudo crash start status       # plataforma, núcleo elegido, estado de instalación
sudo crash start logs         # cola del log del núcleo
```

¿El dispositivo no puede acceder a GitHub? El núcleo puede instalarse
sin conexión: descarga el release de mihomo en otra máquina, cópialo a
`/etc/rustcrash/bin/mihomo` (en OpenWrt: `/etc/ShellCrash/bin/mihomo`)
y haz `chmod +x`; así puedes omitir `crash install`.

¿Prefieres compilar? `cargo build --release --bin crash` y luego
`sudo install -m755 target/release/crash /usr/local/bin/`; para routers
y Raspberry Pi usa `bash scripts/cross-compile.sh` (ver la guía de
instalación).

Docker:

```bash
docker build -t rustcrash .
docker run --rm --cap-add NET_ADMIN rustcrash crash --version
```

## Comandos

| Área | Ejemplos |
|------|----------|
| Ciclo de vida | `crash start start/stop/restart/status/logs/watchdog` |
| Supervisor | `crash start serve` (API REST + bot de Telegram + watchdog) |
| Firewall | `crash firewall setup --tun --ipv6 --quic-reject` / `cleanup` |
| Suscripciones | `crash config import/list/select/generate`, `crash sub convert -t clash` |
| Actualizaciones | `crash task enable --interval 12h`, `crash task geo`, `crash task rules` |
| Bot de Telegram | configúralo en `config.yaml`, luego `crash start bot` |

Referencia completa: [CLI](docs/CLI.md) · [API REST](docs/API.md) ·
[Bot de Telegram](docs/BOT.md) · [Configuración](docs/CONFIGURATION.md) (en inglés)

## Seguridad

Se ejecuta como root en routers, así que las reglas son estrictas:
procesos lanzados solo con vector de argumentos (sin shell, sin comandos
montados como cadenas), API solo en loopback con token, lista blanca de
chat-IDs para el bot, descargas atómicas y sanitizadas, secretos
únicamente desde config/variables de entorno. Ver
[docs/SECURITY.md](docs/SECURITY.md).

## Compilación y tests

```bash
cargo test --workspace                 # 500+ tests, sin red
cargo clippy --workspace --all-targets
bash scripts/cross-compile.sh          # 6 objetivos: routers ARM/ARM64/MIPS, Pi, x86
bash scripts/release.sh                # directorio de release: tar.gz por objetivo + SHA256SUMS
bash tests/docker/run.sh               # e2e multicontenedor (binario real)
```

## Estructura del proyecto

```
core/            librería rustcrash-core (platform, service, bot, notify,
                 api, geo, rules, firewall, subconverter, …)
cmd/crash/       el binario único crash (CLI + TUI)
tests/           suites de integración + e2e Docker
docs/            docs de CLI / API / bot / config / arquitectura / seguridad
```

Detalles de arquitectura: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Hoja de ruta y compatibilidad

La paridad de funciones con el núcleo de ShellCrash está completa hasta
sus funciones avanzadas (TUN, IPv6, manejo de VM/Docker, hooks de tareas,
bot de Telegram, canales push). Fuera del alcance inicial: modo PAC,
herramientas SSH, DDNS.

## Licencia

Bajo doble licencia [MIT](LICENSE-MIT) o [Apache-2.0](LICENSE-APACHE), a tu elección.
