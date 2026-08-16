[English](/README.md) | [فارسی](/README_FA.md) | [العربية](/README_AR.md) | [中文](/README_ZH.md) | [Español](/README_ES.md) | [Русский](/README_RU.md) | [Türkçe](/README_TR.md)

<p align="center">
  <img src="https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/logo.png" alt="PRO-UI Logo" width="260">
</p>

Этот проект — улучшенная версия панели **[3X-UI](https://github.com/MHSanaei/3x-ui)** (версии 2.9.3). Цель проекта — добавить различные протоколы и реализовать её как комплексную панель с поддержкой возможностей **Xray-core**.

![Общий вид](https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/overview.png)

## Новые возможности

- **Мультиадмин** с доступом к отдельным Inbound: каждый администратор видит только назначенные ему
- Аккаунты **реселлеров** с лимитом трафика, который пополняет администратор и который тратится только на выданные Inbound
- Функция **Client to Client**, даже в режиме **Cross Inbound** (внутреннее соединение пользователя L2TP с пользователем OpenVPN)
- Добавление **Encryption** **AES-256-GCM** и **AES-128-GCM** в протокол **Shadowsocks**
- Поддержка **XHTTP Object** в **Inbound** и **Outbound**
- Скрипт автоматической установки **[WARP-CLI](https://github.com/Sir-MmD/warp-cli)** (официальная версия Cloudflare)
- [Пропатченное ядро **Xray-core**](https://github.com/Sir-MmD/Xray-core) для устранения ошибки «Unsupported Cipher» в протоколе **Shadowsocks**
- Объединение всех файлов (Geofile, Xray-core и ядер Backend) в один единый бинарный файл
- Экспорт ссылок аккаунтов в форматах **TXT** и **PDF**
- Возможность **заморозки (Freeze)** аккаунтов
- Добавление **checkbox** к клиентам и Inbound
- Функция **Bulk Operation**:
    * Групповое изменение объёма трафика аккаунтов
    * Групповое изменение срока аккаунтов
    * Групповое включение/отключение аккаунтов
    * Групповое удаление аккаунтов
    * Групповое удаление Inbound
    * Групповая **заморозка/разморозка** аккаунтов

## Новые протоколы

- PPTP
- L2TP (RAW)
- L2TP/IPsec
- OpenVPN
- OpenConnect (cisco)
- SSTP
- IKEv2
- WireGuard (C)
- AmneziaWG (обфусцированный WireGuard)
- GRE (туннели site-to-site между роутерами, при желании поверх IPsec)
- MTProto Proxy (Telegram)
- SSH

Три протокола добавлены непосредственно в пропатченное ядро Xray-core, поэтому они обслуживаются ядром, а не демоном, и работают как **inbounds и outbounds**:

- AnyTLS
- TUIC (v5)
- NaiveProxy

## Что исправлено

- **Гонка данных в логгере** — `logBuffer` защищён `sync.Mutex` для предотвращения сбоев при одновременной записи
- **Паника в LDAP sync** — вспомогательные функции `panic()` рефакторингнуты для возврата ошибок; разделены `splitCsv`/`splitCsvOrDefault`
- **TLS guard** — исправлен `||` на `&&` в проверке сертификатов TLS
- **Права директории БД** — изменены с `0777` на `0750`
- **Недостижимый код** — удалены мёртвые return после `log.Fatalf` в 3 местах (main.go)
- **Переменная cron entry** — исправлена неинициализированная переменная в планировщике задач
- **Побочный эффект GetSecret()** — удалена мутация БД из функции getter
- **Рекомпиляция regex** — предкомпилирован `md5Re` вместо рекомпиляции при каждом вызове
- **Затенение переменной шаблона** — переименована конфликтующая переменная в web.go
- **Валидация порта** — добавлена проверка нижней границы (минимум 1)
- **GetAllSetting** — исправлено молчаливое отбрасывание неизвестных настроек
- **Затенение переменной** — исправлен `t` shadow в setting.go
- **Запуск Telegram бота** — объединена дублирующая проверка бота в `startTask()`
- **Сообщение лога в runSeeders** — исправлен неправильный текст сообщения
- **splitCsv** — исправлен возврат `DefaultTruthyValues` при пустом входе
- **Порядок AllPermissions** — исправлено несоответствие порядка списка разрешений
- **.gitignore** — обновлена ссылка `x-ui` на `vpn-ui`
- **Неиспользуемые импорты** — удалены импорты `unsafe` из main.go и global.go
- **RADIUS secret** — удалён захардкоженный фоллбэк, используется пустая строка
- **Реактивность Vue 2** — исправлены поля учётных данных клиента, не обновляющиеся в модальном окне редактирования
- **Имя config** — изменено с `x-ui` на `vpn-ui`
- **Куки сессии** — используется `config.GetName()` вместо захардкоженного имени
- **Гонка в LocalizerWeb** — добавлен `sync.RWMutex` для предотвращения гонок в карте перевода
- **Исправления i18n** — диакритика вьетнамского, утечка между языками в zh_TW, недостающие разделы на арабском, недостающие разделы на персидском

## Протестированные операционные системы


| | Дистрибутив |Версия |Версия |
|:---:|:---|:---:|:---:|
| <img src="https://cdn.simpleicons.org/ubuntu" width="32" height="32" alt="Ubuntu"> | **Ubuntu** | `24.04` | `26.04` |
| <img src="https://cdn.simpleicons.org/debian" width="32" height="32" alt="Debian"> | **Debian** | `12` | `13` |
| <img src="https://cdn.simpleicons.org/fedora" width="32" height="32" alt="Fedora"> | **Fedora** | `43` | `44` |
| <img src="https://cdn.simpleicons.org/almalinux/2F80ED" width="32" height="32" alt="AlmaLinux"> | **AlmaLinux** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/rockylinux" width="32" height="32" alt="Rocky Linux"> | **Rocky Linux** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/centos" width="32" height="32" alt="CentOS Stream"> | **CentOS Stream** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/archlinux" width="32" height="32" alt="Arch Linux"> | **Arch Linux** | `Rolling` | |


> [!IMPORTANT]
> Настоятельно рекомендуется устанавливать панель только на протестированные операционные системы, так как высока вероятность, что новые ядра не будут корректно работать на других ОС!

> [!NOTE]
> **AmneziaWG работает только на Debian 12/13 и Ubuntu 24.04/26.04.**
> В отличие от всех остальных протоколов, AmneziaWG не входит в ядро ни одного дистрибутива: панель сама собирает его модуль ядра на вашем сервере во время первоначальной настройки. Сейчас этот модуль не собирается в двух случаях. На **ядре 7.1 и новее** (Fedora 43/44, Arch) из ядра удалён символ `ipv6_stub`, который модуль по-прежнему использует. На **AlmaLinux, Rocky Linux и CentOS Stream** бэкпортированные ядра RHEL конфликтуют со слоем совместимости модуля, а EL10 он не распознаёт вовсе. И то и другое является ограничением самого модуля AmneziaWG, исправления для них всё ещё не приняты в основном проекте, поэтому обойти их настройками панели невозможно.
> Настройка обнаруживает это и сообщает вам, вместо того чтобы молча завершиться с ошибкой. **Все остальные протоколы нормально работают на всех протестированных операционных системах.**

## Установка панели

```bash
curl -Ls https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/deploy.sh | sudo bash
```

## Удаление панели

```bash
sudo /opt/vpn-ui/vpn-ui-amd64 --uninstall
```

> [!NOTE]
> Путь к базе данных, служба systemd и все порты по умолчанию были изменены, поэтому вы можете без каких-либо проблем установить эту панель рядом с другими вашими панелями.

## Как новые протоколы взаимодействуют с ядром Xray-core

```mermaid
flowchart TB
  Client["VPN Client<br/>(L2TP/IPsec · PPTP · OpenVPN · OpenConnect · SSTP · IKEv2 · WireGuard (C) · AmneziaWG)"]
  TGC["Telegram Client<br/>(MTProto Proxy)"]
  SSHC["SSH Client<br/>(ssh -D dynamic SOCKS · badvpn-udpgw for UDP)"]
  GREC["Customer Router<br/>(GRE · IP protocol 47 · optional IPsec / FOU)"]

  subgraph PANEL["pro-ui panel — root process"]
    PROC["procmgr<br/>supervises the daemons"]
    RAD["in-binary RADIUS<br/>127.0.0.1:1812 auth · :1813 acct"]
    HOOK["OpenVPN hooks<br/>auth / connect / disconnect / evict"]
    CONF["writes Xray config:<br/>dokodemo-door inbound +<br/>per-account source-IP routing"]
    STAT["reads Xray stats (gRPC)<br/>enforces traffic / device limits"]
    SSHSRV["in-binary SSH gateway (x/crypto/ssh)<br/>no daemon, no bundle: direct-tcpip + udpgw"]
  end

  subgraph DAEMON["Bundled VPN daemons (panel children)"]
    D["xl2tpd + strongSwan/charon · pptpd · openvpn · ocserv · accel-ppp<br/>(pppd for L2TP/PPTP · accel-ppp for SSTP · charon for IKEv2 and GRE-over-IPsec)"]
    MT["telemt (MTProto Proxy)<br/>userspace relay: no tunnel, no pool IP"]
  end

  subgraph KERNEL["Linux kernel data plane"]
    IFACE["ppp0 / tun0 / wgc0 / awg0 / gre-*<br/>client is assigned a pool IP"]
    NFT["nftables mark:<br/>UDP → TPROXY · TCP → REDIRECT"]
    RULE["ip rule fwmark 1 → table 100"]
  end

  subgraph XRAY["Xray-core (bundled, panel-managed)"]
    DOKO["dokodemo-door inbound<br/>sockopt tproxy, mark 255"]
    SOCKS["socks inbound (loopback)<br/>tag = MTProto / SSH inbound<br/>username = account"]
    ROUTE{"routing:<br/>match source IP → account<br/>or socks username → account"}
    OUT["outbound<br/>freedom / proxy / WARP"]
  end

  NET["Internet"]

  %% control plane
  Client -->|"tunnel + credentials"| D
  Client -.->|"WireGuard (C): in-kernel wgc, no daemon"| IFACE
  Client -.->|"AmneziaWG: in-kernel awg (DKMS module), no daemon<br/>obfuscated handshake: Jc/Jmin/Jmax · S1/S2 · H1-H4"| IFACE
  GREC -.->|"GRE: in-kernel tunnel, no daemon and no credentials<br/>peer pinned by its public IP, or learned from its first packets<br/>optional ESP transport on the shared charon · FOU for peers behind NAT"| IFACE
  TGC -->|"obfuscated2 / dd / FakeTLS secret"| MT
  SSHC -->|"username + password (checked in-process, no RADIUS)"| SSHSRV
  D -.->|"MS-CHAPv2 Access-Request"| RAD
  RAD -.->|"Accept + pool IP"| D
  D -.->|"user-pass / client-connect"| HOOK
  HOOK -.->|"lease per-account IP"| D
  PROC --- D
  CONF --> DOKO
  CONF --> ROUTE

  %% data plane
  D -->|"decapsulated packets"| IFACE
  IFACE --> NFT --> RULE --> DOKO
  DOKO --> ROUTE --> OUT --> NET
  MT -->|"relayed TCP, socks user = account"| SOCKS
  SSHSRV -->|"direct-tcpip → socks CONNECT · udpgw → socks UDP ASSOCIATE<br/>socks user = account"| SOCKS
  SOCKS --> ROUTE

  %% accounting + return
  OUT -.->|"per-account counters"| STAT
  MT -.->|"per-account octets (Prometheus scrape)"| STAT
  SSHSRV -.->|"per-account octets (in-process counters)"| STAT
  STAT -.->|"disconnect over-limit"| RAD
  NET -.->|"replies (symmetric path back)"| OUT
```

## Как RBridge работает с протоколами без RADIUS

WireGuard (C), AmneziaWG и режимы **PSK** / **EAP-TLS** протокола IKEv2 аутентифицируются по открытому ключу или сертификату, поэтому не выполняют обмен с RADIUS и иначе не получили бы ни записи о сессии, ни учёта трафика, ни применения **User Limit**. **RBridge** (Radius Bridge) закрывает этот пробел: раз за каждый цикл сбора трафика его **Sweeper** опрашивает (poll) активные туннели каждого протокола, применяет квоту (quota), отключение и **User Limit** K для каждого аккаунта (вытесняя лишних через evict), а затем сводит выживших в тот же встроенный реестр сессий **RADIUS** и тот же учёт на **nftables**, которые уже используют RADIUS-протоколы. В итоге протокол на основе ключей ведёт себя точно так же по расходу, квоте и лимиту устройств и выходит в интернет через тот же data plane **dokodemo-door** в Xray.

Для двух туннельных протоколов на основе ключей, **WireGuard (C)** и **AmneziaWG**, значение K в **User Limit** выделяет каждому аккаунту K слотов под устройства: K пар ключей, K конфигов и K различных туннельных IP, по одному конфигу на устройство. Это та же модель, что используют коммерческие сервисы, и именно она позволяет одному аккаунту одновременно работать на телефоне, ноутбуке и роутере, а устройствам не бороться за один ключ.

```mermaid
flowchart TB
  subgraph SRC["Non-RADIUS protocols (public-key / certificate auth, no RADIUS round-trip)"]
    WG["WireGuard (C)<br/>in-kernel, wgctrl-managed"]
    AWG["AmneziaWG<br/>in-kernel amneziawg (DKMS), obfuscated"]
    IKE["IKEv2 PSK / EAP-TLS<br/>strongSwan charon"]
  end

  subgraph BRIDGE["RBridge, the Radius Bridge (one pass per traffic tick)"]
    SWEEP["Sweeper.Tick()"]
    P1["1 · Poll live tunnels via each Adapter"]
    P2["2 · Enforce quota + disable<br/>+ User-Limit K + strategy"]
    P3["3 · Reconcile survivors into the Sink"]
  end

  subgraph SINK["Sink, the existing RADIUS session model"]
    REG["in-binary RADIUS<br/>session registry"]
    ACCT["nftables per-account counters<br/>→ client_traffics (usage / quota)"]
  end

  XRAY["Xray-core<br/>source-IP routing → outbound → Internet"]

  %% control plane
  WG -.->|"peers + last-handshake"| P1
  AWG -.->|"peers + last-handshake"| P1
  IKE -.->|"active SAs + Framed-IP"| P1
  SWEEP --> P1 --> P2 --> P3
  P2 -.->|"evict: remove peer / terminate SA"| WG
  P2 -.->|"evict: remove peer"| AWG
  P2 -.->|"evict: terminate SA"| IKE
  P3 -->|"tunnel IP → account"| REG
  P3 -->|"add / remove counters"| ACCT
  ACCT -.->|"disabled / over-quota"| P2

  %% data plane
  WG ==> XRAY
  AWG ==> XRAY
  IKE ==> XRAY
  ACCT -.- XRAY
```

## Компиляция из исходного кода

```bash
git clone https://github.com/hasan1808/vpn-ui.git && cd vpn-ui
./build.sh
```

## E2E-тест

![Тест E2E](https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/test_unit.png)

Для этого проекта разработан полноценный **E2E**-тест на Python в папке `test_unit`, которым вы можете воспользоваться. Порядок действий следующий:

1. Перейдите в папку `test_unit` и укажите нужные вам настройки в файле `config.toml`.
2. Запустите скрипт `setup.sh`.
3. Поместите скомпилированный бинарный файл в папку `test_subject`.
4. Запустите `run.sh` с правами `sudo`.

> [!IMPORTANT]
> Полный E2E-тест занимает очень много времени; если вы внесли в проект лишь небольшое изменение, лучше протестировать только соответствующую часть с помощью ключа `--tests`:

| Test ID | Description |
| :--- | :--- |
| `core-init` | provision kernel modules + packages + xray core |
| `server-setup` | create inbounds + accounts + source-IP routing rules |
| `openvpn` | connect variants + checks + peer reachability (OpenVPN) |
| `l2tp` | connect variants + checks + peer reachability (L2TP/IPsec) |
| `pptp` | connect variants + checks + peer reachability (PPTP) |
| `openconnect` | connect variants + checks + peer reachability + same-NAT user-limit (OpenConnect/ocserv) |
| `sstp` | connect variants + checks + peer reachability (SSTP/accel-ppp, PPP-over-TLS) |
| `ikev2` | connect + checks + peer reachability (IKEv2/IPsec, strongSwan charon; eap-mschapv2 + psk + eap-tls) |
| `wg-c` | connect + checks + peer reachability + per-account usage/termination (WireGuard C, in-kernel wgctrl, gateway /29, + preshared-key mode) |
| `awg` | connect + checks + peer reachability + per-account usage/termination (AmneziaWG, in-kernel amneziawg DKMS module, obfuscation params, + preshared-key mode) |
| `gre` | connect + checks + peer reachability + per-account usage/termination (GRE site-to-site, in-kernel ip_gre; raw / IPsec / FOU peer modes, static and dynamic peers) |
| `mtproto` | alias: runs every MTProto phase below (MTProto Proxy, telemt) |
| `mtproto-classic` | handshake + relay to a real Telegram DC + wrong-secret control + usage (obfuscated2) |
| `mtproto-secure` | same, "dd" random-padding secret |
| `mtproto-tls` | same + FakeTLS ServerHello HMAC verified, "ee" secret |
| `mtproto-toggle` | editing an account's modes takes effect on the RUNNING daemon (no restart) |
| `mtproto-termination` | quota auto-disables the account AND the proxy stops relaying for it |
| `mtproto-adtag` | an ad tag forces middle-proxy egress and drops the inbound's Xray routing, and clearing it restores both |
| `ssh` | connect + checks + routing + user-limit + both strategies + per-account usage/termination (SSH relay, in-binary Go gateway) |
| `ssh-udp` | UDP through the relay: udpgw terminated in-process and bridged to Xray via SOCKS5 UDP ASSOCIATE, plus accounting |
| `bulk-ops` | bulk client add/sub/enable/disable + TXT/PDF export via API |
| `backup-restore` | DB export + import round-trip |
| `warp-socks` | Cloudflare warp-cli SOCKS install + egress |
| `random-cfg` | `--random` switch: randomize port + creds + webpath, then restore |
| `systemd` | `--systemd` switch: install + run the panel as a systemd unit |
| `uninstall` | `--uninstall` switch: install everything, tear down, assert clean host |
| `export-js` | host-side Node TXT/PDF export test (no VM) |

Чтобы протестировать только на одной конкретной операционной системе, вы можете воспользоваться ключом `--only`:

```bash
sudo ./run.sh --only ubuntu-24
```

## Пожертвования

🔹USDC-Polygon: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-BEP20: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-TRC20: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹TRX: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹LTC: ```ltc1qmapmnuf6cq9x679nmu0k4uyq779mxxcwnkgdll```

🔹BTC: ```bc1q62w7lyndzndsp74vj4dsayvun8xnapzq6hx5ea```

🔹ETH: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```
