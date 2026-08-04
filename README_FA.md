[English](/README.md) | [فارسی](/README_FA.md) | [العربية](/README_AR.md) | [中文](/README_ZH.md) | [Español](/README_ES.md) | [Русский](/README_RU.md) | [Türkçe](/README_TR.md)

<p align="center">
  <img src="https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/logo.png" alt="VPN-UI Logo" width="260">
</p>

این پروژه، یک نسخه‌ی ارتقایافته از پنل **[3X-UI](https://github.com/MHSanaei/3x-ui)** (نسخه‌ی 2.9.3) هستش.  هدف این پروژه اضافه کردن پروتکل های مختلف و راه اندازی بصورت یک پنل جامعه با پشتیبانی از قابلیت های **Xray-core**  هستش

![نمای کلی](https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/overview.png)

## امکانات جدید

- **چند مدیره** با دسترسی جداگانه به هر Inbound، هر مدیر فقط Inbound هایی را می‌بیند که به او داده‌اید
- حساب‌های **نماینده** با اعتبار ترافیک که مدیر آن را شارژ می‌کند و فقط روی Inbound های داده‌شده خرج می‌شود
- قابلیت **Client to Client** حتی بصورت **Cross Inbound** (اتصال داخلی کاربر L2TP به کاربر OpenVPN)
- اضافه‌شدن **Encryption** های **AES-256-GCM** و **AES-128-GCM** به پروتکل **Shadowsocks**
- پشتیبانی از **XHTTP Object** در **Inbound** و **Outbound**
- اسکریپت نصب خودکار **[WARP-CLI](https://github.com/Sir-MmD/warp-cli)** (نسخه‌ی رسمی Cloudflare)
- هسته‌ی [**Xray-core** پچ‌شده](https://github.com/Sir-MmD/Xray-core) برای رفع خطای «Unsupported Cipher» در پروتکل **Shadowsocks**
- باندل‌شدن همه‌ی فایل‌ها (Geofile، Xray-core و هسته‌های Backend) داخل یک فایل باینریِ واحد
- خروجی گرفتن لینک اکانت ها بصورت **TXT** و **PDF**
- قابلیت **Freez** کردن اکانت هات
- اضافه شدن **checkbox** به کلاینت و Inbound ها
- قابلیت **Bulk Operation**: 

    * تغییر گروهی حجم اکانت ها
    * تغییر گروهی روز اکانت ها
    * فعال سازی/غیر فعال سازی گروهی اکانت ها
    * حذف گروهی اکانت ها
    * حذف گروهی Inbound ها
    * قابلیت Freez/Un-Freez کردن گروهی اکانت ها

## پروتکل‌های جدید

- PPTP
- L2TP (RAW)
- L2TP/IPsec
- OpenVPN
- OpenConnect (cisco)
- SSTP
- IKEv2
- WireGuard (C)
- AmneziaWG (نسخه‌ی مبهم‌سازی‌شده‌ی WireGuard)
- GRE (تونل‌های site-to-site بین روترها، در صورت نیاز روی IPsec)
- MTProto Proxy (Telegram)
- SSH

سه پروتکل دیگر نیز به خودِ هسته‌ی Xray-core پچ‌شده اضافه شده‌اند و توسط هسته سرو می‌شوند (نه توسط دیمون) و به‌صورت **inbound و outbound** عمل می‌کنند:

- AnyTLS
- TUIC (v5)
- NaiveProxy

## موارد اصلاح‌شده

- **Race condition در Logger** — محافظت `logBuffer` با `sync.Mutex` برای جلوگیری از کرش هنگام نوشتن همزمان
- **Panic در LDAP sync** — بازنویسی توابع `panic()` به خروجی خطا؛ جداسازی `splitCsv`/`splitCsvOrDefault`
- **TLS guard** — اصلاح `||` به `&&` در اعتبارسنجی گواهی TLS
- **مجوزهای دایرکتوری دیتابیس** — تغییر از `0777` به `0750`
- **کد غیرقابل دسترس** — حذف return های مرده بعد از `log.Fatalf` در 3 جا (main.go)
- **متغیر cron entry** — اصلاح متغیر initialization نشده در زمان‌بند وظایف
- **Side effect در GetSecret()** — حذف جهش دیتابیس از تابع getter
- **بازکامپایل regex** — پیش‌کامپایل regex `md5Re` به جای بازکامپایل در هر فراخوانی
- **Sadowing متغیر template** — تغییر نام متغیر template متعارض در web.go
- **اعتبارسنجی پورت** — اضافه شدن بررسی حد پایین (حداقل 1)
- **GetAllSetting** — اصلاح حذف سکوت تنظیمات ناشناخته
- **Sadowing متغیر** — اصلاح `t` shadow در setting.go
- **شروع ربات تلگرام** — یکپارچه‌سازی بررسی تکراری ربات در `startTask()`
- **پیام log در runSeeders** — اصلاح متن پیام log اشتباه
- **splitCsv** — اصلاح بازگشت `DefaultTruthyValues` روی ورودی خالی
- **ترتیب AllPermissions** — اصلاح عدم تطابق ترتیب لیست مجوزها
- **.gitignore** — بروزرسانی ارجاع `x-ui` به `vpn-ui`
- **ایمپورت‌های استفاده‌نشده** — حذف ایمپورت‌های `unsafe` از main.go و global.go
- **RADIUS secret** — حذف fallback سخت‌کد شده، از رشته خالی استفاده می‌شود
- **Reactivity در Vue 2** — اصلاح بروز نشدن فیلدهای credential کلاینت در مodal ویرایش
- **نام config** — تغییر از `x-ui` به `vpn-ui`
- **کوکی session** — استفاده از `config.GetName()` به جای نام سخت‌کد شده
- **Race condition در LocalizerWeb** — اضافه شدن `sync.RWMutex` برای جلوگیری از race در نقشه ترجمه
- **اصلاحات i18n** — لهجه‌های ویتنامی، نشت بین‌زبانی zh_TW، بخش‌های گمشده عربی، بخش‌های گمشده فارسی
- **پشتیبانی از Windows** — اضافه شدن `sys_windows.go` برای توابع TCP/UDP/CPU

## سیستم‌عامل‌های تست شده


| | توزیع |نسخه |نسخه |
|:---:|:---|:---:|:---:|
| <img src="https://cdn.simpleicons.org/ubuntu" width="32" height="32" alt="Ubuntu"> | **Ubuntu** | `24.04` | `26.04` |
| <img src="https://cdn.simpleicons.org/debian" width="32" height="32" alt="Debian"> | **Debian** | `12` | `13` |
| <img src="https://cdn.simpleicons.org/fedora" width="32" height="32" alt="Fedora"> | **Fedora** | `43` | `44` |
| <img src="https://cdn.simpleicons.org/almalinux/2F80ED" width="32" height="32" alt="AlmaLinux"> | **AlmaLinux** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/rockylinux" width="32" height="32" alt="Rocky Linux"> | **Rocky Linux** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/centos" width="32" height="32" alt="CentOS Stream"> | **CentOS Stream** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/archlinux" width="32" height="32" alt="Arch Linux"> | **Arch Linux** | `Rolling` | |


> [!IMPORTANT]
> پیشنهاد می‌شه حتماً پنل رو روی سیستم‌عامل‌های تست‌شده نصب کنید؛ چون احتمال این‌که هسته‌های جدید روی بقیه‌ی سیستم‌عامل‌ها درست کار نکنن بالاست!

> [!NOTE]
> **پروتکل AmneziaWG فقط روی Debian 12/13 و Ubuntu 24.04/26.04 کار می‌کنه.**
> برخلاف بقیه‌ی پروتکل‌ها، AmneziaWG توی هسته‌ی هیچ توزیعی نیست: پنل موقع راه‌اندازی، ماژول هسته‌اش رو روی سرور خودتون کامپایل می‌کنه. این ماژول فعلاً توی دو حالت بیلد نمی‌شه. روی **هسته‌ی 7.1 و بالاتر** (Fedora 43/44 و Arch) هسته سمبل `ipv6_stub` رو که ماژول هنوز ازش استفاده می‌کنه حذف کرده. روی **AlmaLinux، Rocky Linux و CentOS Stream** هم هسته‌های بک‌پورت‌شده‌ی RHEL با لایه‌ی سازگاری ماژول تداخل دارن و EL10 اصلاً براش شناخته‌شده نیست. هر دوی این‌ها محدودیت خودِ ماژول AmneziaWG هستن و رفعشون هنوز سمت پروژه‌ی اصلی بازه، پس چیزی نیست که پنل بتونه با تنظیمات دورش بزنه.
> فرایند راه‌اندازی این رو تشخیص می‌ده و بهتون خبر می‌ده، به‌جای این‌که بی‌صدا شکست بخوره. **بقیه‌ی پروتکل‌ها روی همه‌ی سیستم‌عامل‌های تست‌شده به‌طور عادی کار می‌کنن.**

## نصب پنل

```bash
curl -Ls https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/deploy.sh | sudo bash
```

## حذف پنل

```bash
sudo /opt/vpn-ui/vpn-ui-amd64 --uninstall
```

> [!NOTE]
> مسیر دیتابیس، سرویس systemd و همه‌ی پورت‌های پیش‌فرض تغییر کرده‌اند، پس می‌تونید این پنل رو بدون هیچ مشکلی کنار پنل‌های دیگه‌تون نصب کنید.

## نحوه‌ی تعامل پروتکل‌های جدید با هسته‌ی Xray-core

```mermaid
flowchart TB
  Client["VPN Client<br/>(L2TP/IPsec · PPTP · OpenVPN · OpenConnect · SSTP · IKEv2 · WireGuard (C) · AmneziaWG)"]
  TGC["Telegram Client<br/>(MTProto Proxy)"]
  SSHC["SSH Client<br/>(ssh -D dynamic SOCKS · badvpn-udpgw for UDP)"]
  GREC["Customer Router<br/>(GRE · IP protocol 47 · optional IPsec / FOU)"]

  subgraph PANEL["vpn-ui panel — root process"]
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

## نحوه‌ی کار RBridge با پروتکل‌های بدون RADIUS

برای دو پروتکل tunnel مبتنی بر کلید، یعنی **WireGuard (C)** و **AmneziaWG**، مقدار K در **User Limit** به هر اکانت تعداد K جای دستگاه می‌دهد: K جفت‌کلید، K فایل config و K آدرس IP متفاوت داخل tunnel، یعنی برای هر دستگاه یک config جداگانه. این همان مدلی است که سرویس‌های تجاری استفاده می‌کنند و باعث می‌شود یک اکانت همزمان روی موبایل، لپ‌تاپ و روتر کار کند، بدون اینکه دستگاه‌ها سر یک کلید با هم تداخل پیدا کنند.

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

## کامپایل از سورس

```bash
git clone https://github.com/hasan1808/vpn-ui.git && cd vpn-ui
./build.sh
```

## تست E2E

![تست E2E](https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/test_unit.png)

یک تست **E2E** کامل با Python داخل فولدر `test_unit` برای این پروژه طراحی شده که می‌تونید ازش استفاده کنید. مراحلش این‌طوریه:

1. وارد فولدر `test_unit` بشید و تنظیمات دلخواه‌تون رو توی `config.toml` وارد کنید.
2. اسکریپت `setup.sh` رو اجرا کنید.
3. فایل باینریِ کامپایل‌شده رو داخل فولدر `test_subject` قرار بدید.
4. `run.sh` رو با دسترسی `sudo` اجرا کنید.

> [!IMPORTANT]
> تست کامل E2E به‌شدت زمان‌بره؛ اگه فقط یه تغییر کوچیک توی پروژه دادید، بهتره با سویچ `--tests` فقط همون بخش رو تست کنید:

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

برای تست روی فقط یک سیستم‌عامل خاص هم می‌تونید از سویچ `--only` استفاده کنید:

```bash
sudo ./run.sh --only ubuntu-24
```

## دونیت

🔹USDC-Polygon: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-BEP20: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-TRC20: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹TRX: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹LTC: ```ltc1qmapmnuf6cq9x679nmu0k4uyq779mxxcwnkgdll```

🔹BTC: ```bc1q62w7lyndzndsp74vj4dsayvun8xnapzq6hx5ea```

🔹ETH: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```
