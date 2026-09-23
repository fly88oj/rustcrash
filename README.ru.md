# RustCrash

[![CI](https://img.shields.io/badge/tests-500%2B-green)]() [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)]() [![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)]()

**Кроссплатформенный менеджер в одном бинарном файле для прокси-ядер [mihomo](https://github.com/MetaCubeX/mihomo) и [sing-box](https://github.com/SagerNet/sing-box) — переписывание [ShellCrash](https://github.com/juewuy/ShellCrash) на Rust.**

[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md) | [Português](README.pt.md) | Русский

## Почему RustCrash

ShellCrash — проверенный временем набор shell-скриптов для запуска
прозрачных прокси на маршрутизаторах. RustCrash сохраняет его
функциональность, но распространяется как **один статический бинарный
файл**: без shell-зависимостей, типизированная конфигурация,
проверяемые загрузки и полный набор тестов.

- **Один бинарный файл** — каждая функция (init, install, файрвол,
  жизненный цикл, подписки, планировщик, бот, API) — это подкоманда
  `crash`.
- **Реальные платформы** — Linux x86_64/ARM64/ARMv6/ARMv7/MIPS (musl,
  статическая линковка) для маршрутизаторов и Raspberry Pi, OpenWrt,
  Docker; iptables и nftables; systemd, OpenWrt init и OpenRC.
- **Проверяемые установки** — загружаемые ядра проверяются по SHA-256
  против официальных контрольных сумм ещё до записи на диск.
- **Нативная конвертация подписок** — 8 парсеров URI протоколов
  (VMess, VLESS, SS, SSR, Trojan, Hysteria2, TUIC, WireGuard) и 16
  форматов вывода (Clash, sing-box, Quantumult(X), Loon, Surge,
  Surfboard, Stash, V2Ray, …), без внешнего subconverter.
- **Удалённое управление** — Telegram-бот с inline-меню, REST API с
  токен-аутентификацией, push-уведомления в 7 сервисов.

## Быстрый старт

Впервые здесь? Откройте [руководство по установке](docs/INSTALL.md) —
в нём есть таблица соответствия устройства (`uname -m`) и готового
бинарного файла, так что toolchain Rust не понадобится. Также вам
нужна **URL-ссылка на прокси-подписку** от вашего провайдера для шага
`config import`.

```bash
sudo crash init --init        # создать /etc/rustcrash + зарегистрировать в init-системе
sudo crash install            # скачать ядро mihomo (SHA-256 проверяется; нужен доступ к GitHub)
crash config import https://example.com/sub   # ваша ссылка на подписку
crash config generate         # записать конфиг ядра на основе подписки
sudo crash start serve        # супервизор: ядро + watchdog + бот + REST API

# убедиться, что работает:
sudo crash start status       # платформа, выбранное ядро, состояние установки
sudo crash start logs         # хвост журнала ядра
```

Устройство не имеет доступа к GitHub? Ядро можно установить офлайн:
скачайте релиз mihomo на другой машине, скопируйте в
`/etc/rustcrash/bin/mihomo` (на OpenWrt: `/etc/ShellCrash/bin/mihomo`)
и выполните `chmod +x` — тогда `crash install` можно пропустить.

Предпочитаете собрать сами? `cargo build --release --bin crash`, затем
`sudo install -m755 target/release/crash /usr/local/bin/`; для
маршрутизаторов и Raspberry Pi используйте
`bash scripts/cross-compile.sh` (см. руководство по установке).

Docker:

```bash
docker build -t rustcrash .
docker run --rm --cap-add NET_ADMIN rustcrash crash --version
```

## Команды

| Область | Примеры |
|---------|---------|
| Жизненный цикл | `crash start start/stop/restart/status/logs/watchdog` |
| Супервизор | `crash start serve` (REST API + Telegram-бот + watchdog) |
| Файрвол | `crash firewall setup --tun --ipv6 --quic-reject` / `cleanup` |
| Подписки | `crash config import/list/select/generate`, `crash sub convert -t clash` |
| Обновления | `crash task enable --interval 12h`, `crash task geo`, `crash task rules` |
| Telegram-бот | настроить в `config.yaml`, затем `crash start bot` |

Полная справка: [CLI](docs/CLI.md) · [REST API](docs/API.md) ·
[Telegram-бот](docs/BOT.md) · [Конфигурация](docs/CONFIGURATION.md) (на английском)

## Безопасность

Работает от root на маршрутизаторах, поэтому правила строгие: процессы
запускаются только вектором аргументов (без shell и сборки команд из
строк), API только на loopback с токеном, белый список chat-ID для
бота, атомарные и очищенные загрузки, секреты только из конфига или
переменных окружения. См. [docs/SECURITY.md](docs/SECURITY.md).

## Сборка и тесты

```bash
cargo test --workspace                 # 500+ тестов, без сети
cargo clippy --workspace --all-targets
bash scripts/cross-compile.sh          # 6 целей: ARM/ARM64/MIPS-роутеры, Pi, x86
bash scripts/release.sh                # каталог релиза: tar.gz на цель + SHA256SUMS
bash tests/docker/run.sh               # e2e в нескольких контейнерах (реальный бинарный файл)
```

## Структура проекта

```
core/            библиотека rustcrash-core (platform, service, bot, notify,
                 api, geo, rules, firewall, subconverter, …)
cmd/crash/       единственный бинарный файл crash (CLI + TUI)
tests/           интеграционные + Docker e2e наборы
docs/            документация CLI / API / бот / конфиг / архитектура / безопасность
```

Подробности архитектуры: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Планы и совместимость

Функциональная совместимость с ядром ShellCrash полная, включая
продвинутые возможности (TUN, IPv6, работа с VM/Docker, хуки задач,
Telegram-бот, push-каналы). Вне начальных рамок: режим PAC, SSH-инструменты,
DDNS.

## Лицензия

Двойная лицензия [MIT](LICENSE-MIT) или [Apache-2.0](LICENSE-APACHE) на выбор.
