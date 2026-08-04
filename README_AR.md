[English](/README.md) | [فارسی](/README_FA.md) | [العربية](/README_AR.md) | [中文](/README_ZH.md) | [Español](/README_ES.md) | [Русский](/README_RU.md) | [Türkçe](/README_TR.md)

<p align="center">
  <img src="https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/logo.png" alt="VPN-UI Logo" width="260">
</p>

هذا المشروع هو نسخة مُطوّرة من لوحة **[3X-UI](https://github.com/MHSanaei/3x-ui)** (الإصدار 2.9.3). يهدف هذا المشروع إلى إضافة بروتوكولات مختلفة وتقديمه كلوحة شاملة مع دعم إمكانيات **Xray-core**.

![نظرة عامة](https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/overview.png)

## الميزات الجديدة

- **تعدد المشرفين** بصلاحية لكل Inbound، فكل مشرف ما يشوفش غير الـ Inbounds اللي خصصتهالوه
- حسابات **الموزّعين** برصيد ترافيك محسوب يشحنه المشرف، ما يتصرفش غير على الـ Inbounds اللي اتدّت له
- إمكانية **Client to Client** حتى بصيغة **Cross Inbound** (اتصال داخلي بين مستخدم L2TP ومستخدم OpenVPN)
- إضافة **Encryption** من نوعَي **AES-256-GCM** و **AES-128-GCM** إلى بروتوكول **Shadowsocks**
- دعم **XHTTP Object** في **Inbound** و **Outbound**
- سكربت التثبيت التلقائي لـ **[WARP-CLI](https://github.com/Sir-MmD/warp-cli)** (النسخة الرسمية من Cloudflare)
- نواة [**Xray-core** المُعدَّلة](https://github.com/Sir-MmD/Xray-core) لإصلاح خطأ «Unsupported Cipher» في بروتوكول **Shadowsocks**
- تجميع جميع الملفات (Geofile و Xray-core ونوى الـ Backend) داخل ملف ثنائي (binary) واحد
- تصدير روابط الحسابات بصيغة **TXT** و **PDF**
- إمكانية **تجميد (Freeze)** الحسابات
- إضافة **checkbox** إلى الـ client والـ Inbound
- إمكانية **Bulk Operation**:
    * تغيير حجم الحسابات بشكل جماعي
    * تغيير مدة الحسابات بشكل جماعي
    * تفعيل/تعطيل الحسابات بشكل جماعي
    * حذف الحسابات بشكل جماعي
    * حذف الـ Inbound بشكل جماعي
    * **تجميد/إلغاء تجميد (Freeze/Un-Freeze)** الحسابات بشكل جماعي

## البروتوكولات الجديدة

- PPTP
- L2TP (RAW)
- L2TP/IPsec
- OpenVPN
- OpenConnect (cisco)
- SSTP
- IKEv2
- WireGuard (C)
- AmneziaWG (WireGuard مموّه)
- GRE (أنفاق site-to-site بين الراوترات، مع إمكانية تشغيلها فوق IPsec)
- MTProto Proxy (Telegram)
- SSH

ثلاثة بروتوكولات أخرى أُضيفت إلى نواة Xray-core المُعدَّلة نفسها، لذا تُقدَّم بواسطة النواة وليس بواسطة守护 (daemon)، وتعمل كـ **inbounds و outbounds**:

- AnyTLS
- TUIC (v5)
- NaiveProxy

## ما تم إصلاحه

- **سباق (Race condition) في الـ Logger** — حماية `logBuffer` بـ `sync.Mutex` لمنع اصطدام الكتابة المتزامنة
- **انهيار LDAP sync** — إعادة كتابة دوال `panic()` لإرجاع أخطاء؛ فصل `splitCsv`/`splitCsvOrDefault`
- **Guard TLS** — إصلاح `||` إلى `&&` في التحقق من شهادة TLS
- **أذونات مجلد قاعدة البيانات** — تغيير من `0777` إلى `0750`
- **كود غير قابل للوصول** — حذف عبارات return الميتة بعد `log.Fatalf` في 3 أماكن (main.go)
- **متغير cron entry** — إصلاح متغير غير مهيأ في جدولة المهام
- **副作用 في GetSecret()** — حذف قفز قاعدة البيانات من دالة getter
- **إعادة تجميع regex** — تجميع مسبق لـ `md5Re` بدلاً من إعادة التجميع في كل استدعاء
- **تعتيم متغير القالب** — تغيير اسم المتغير المتعارض في web.go
- **التحقق من البورت** — إضافة فحص الحد الأدنى (الحد الأدنى 1)
- **GetAllSetting** — إصلاح حذف الإعدادات غير المعروفة بصمت
- **تعتيم المتغير** — إصلاح `t` shadow في setting.go
- **تشغيل بوت تيليجرام** — دمج فحص البوت المكرر في `startTask()`
- **رسالة log في runSeeders** — إصلاح نص رسالة log الخاطئ
- **splitCsv** — إصلاح إرجاع `DefaultTruthyValues` عند الإدخال الفارغ
- **ترتيب AllPermissions** — إصلاح عدم تطابق ترتيب قائمة الأذونات
- **.gitignore** — تحديث إشارة `x-ui` إلى `vpn-ui`
- **استيرادات غير مستخدمة** — حذف استيرادات `unsafe` من main.go و global.go
- **RADIUS secret** — حذف القيمة الافتراضية المثبتة، يستخدم سلسلة فارغة
- **تفاعل Vue 2** — إصلاح عدم تحديث حقول بيانات اعتماد العميل في نافذة التعديل
- **اسم config** — تغيير من `x-ui` إلى `vpn-ui`
- **쿠키 الجلسة** — استخدام `config.GetName()` بدلاً من الاسم المثبت
- **سباق في LocalizerWeb** — إضافة `sync.RWMutex` لمنع سباق خريطة الترجمة
- **إصلاحات i18n** — حروف فيتنامية، تسريب بين اللغات في zh_TW، أقسام مفقودة بالعربية، أقسام مفقودة بالفارسية

## أنظمة التشغيل المُختبَرة


| | التوزيعة |الإصدار |الإصدار |
|:---:|:---|:---:|:---:|
| <img src="https://cdn.simpleicons.org/ubuntu" width="32" height="32" alt="Ubuntu"> | **Ubuntu** | `24.04` | `26.04` |
| <img src="https://cdn.simpleicons.org/debian" width="32" height="32" alt="Debian"> | **Debian** | `12` | `13` |
| <img src="https://cdn.simpleicons.org/fedora" width="32" height="32" alt="Fedora"> | **Fedora** | `43` | `44` |
| <img src="https://cdn.simpleicons.org/almalinux/2F80ED" width="32" height="32" alt="AlmaLinux"> | **AlmaLinux** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/rockylinux" width="32" height="32" alt="Rocky Linux"> | **Rocky Linux** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/centos" width="32" height="32" alt="CentOS Stream"> | **CentOS Stream** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/archlinux" width="32" height="32" alt="Arch Linux"> | **Arch Linux** | `Rolling` | |


> [!IMPORTANT]
> يُوصى بشدّة بتثبيت اللوحة على أنظمة التشغيل المُختبَرة؛ لأن احتمال ألّا تعمل النوى الجديدة بشكل صحيح على بقية أنظمة التشغيل مرتفع!

> [!NOTE]
> **يعمل AmneziaWG على Debian 12/13 وUbuntu 24.04/26.04 فقط.**
> على خلاف بقية البروتوكولات، AmneziaWG غير موجود في نواة أي توزيعة: فاللوحة تُجمِّع (compile) وحدة النواة الخاصة به على خادمك أثناء الإعداد. وهذه الوحدة تفشل حالياً في البناء في حالتين. على **النواة 7.1 أو أحدث** (Fedora 43/44 وArch) أزالت النواة الرمز `ipv6_stub` الذي ما زالت الوحدة تستخدمه. وعلى **AlmaLinux وRocky Linux وCentOS Stream** تتعارض نوى RHEL المنقولة (backported) مع طبقة التوافق في الوحدة، كما أن EL10 غير معروف لها إطلاقاً. وكلتا الحالتين قيدٌ في وحدة AmneziaWG الأصلية، وإصلاحهما ما زال مفتوحاً لدى المشروع الأصلي، لذا لا يمكن للوحة تجاوزهما بأي إعداد.
> يكتشف الإعداد ذلك ويُخبرك به بدلاً من أن يفشل بصمت. **أما بقية البروتوكولات فتعمل بشكل طبيعي على كل أنظمة التشغيل المُختبَرة.**

## تثبيت اللوحة

```bash
curl -Ls https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/deploy.sh | sudo bash
```

## إزالة اللوحة

```bash
sudo /opt/vpn-ui/vpn-ui-amd64 --uninstall
```

> [!NOTE]
> تم تغيير مسار قاعدة البيانات وخدمة systemd وجميع المنافذ الافتراضية، لذا يمكنك تثبيت هذه اللوحة بجانب لوحاتك الأخرى دون أي مشكلة.

## كيفية تفاعل البروتوكولات الجديدة مع نواة Xray-core

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

## كيف يدمج RBridge البروتوكولات بدون RADIUS

يعتمد WireGuard (C) و AmneziaWG وأوضاع **PSK** / **EAP-TLS** في IKEv2 على مصادقة بمفتاح عام أو شهادة، لذا لا تُجري أي جولة تبادل مع RADIUS، وكانت لولا ذلك ستبقى بلا سجل جلسة ولا محاسبة حركة ولا فرض لحدّ **User Limit**. يسدّ **RBridge** (جسر RADIUS) هذه الفجوة: مرة واحدة في كل دورة جمع للحركة، يقوم **Sweeper** باستطلاع الأنفاق الحيّة لكل بروتوكول (poll)، ويطبّق الحصة (quota) والتعطيل وحدّ **User Limit** لكل حساب (K) مع طرد الزائدين (evict)، ثم يوفّق الناجين داخل نفس سجلّ جلسات **RADIUS** المدمج ونفس محاسبة **nftables** التي تستخدمها بروتوكولات RADIUS أصلاً. وبذلك يحصل البروتوكول القائم على المفاتيح على نفس سلوك الاستهلاك والحصة وحدّ الأجهزة تمامًا، ويخرج عبر نفس مستوى بيانات **dokodemo-door** الخاص بـ Xray.

وفي بروتوكولَي الأنفاق القائمين على المفاتيح، **WireGuard (C)** و **AmneziaWG**، يخصّص **User Limit** بقيمة K عددًا K من فتحات الأجهزة لكل حساب: K من أزواج المفاتيح، وK من ملفات الإعداد، وK من عناوين IP مختلفة داخل النفق، بواقع ملف إعداد واحد لكل جهاز. وهو نفس النموذج الذي تستخدمه الخدمات التجارية، وهو ما يتيح استعمال حساب واحد على الهاتف والحاسوب والراوتر في آن واحد دون أن تتنازع الأجهزة على مفتاح واحد.

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

## البناء من المصدر

```bash
git clone https://github.com/hasan1808/vpn-ui.git && cd vpn-ui
./build.sh
```

## اختبار E2E

![اختبار E2E](https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/test_unit.png)

صُمِّم لهذا المشروع اختبار **E2E** كامل بلغة Python داخل مجلد `test_unit` يمكنك استخدامه. وخطواته كالتالي:

1. ادخل إلى مجلد `test_unit` وأدخِل الإعدادات المطلوبة في `config.toml`.
2. شغّل سكربت `setup.sh`.
3. ضع الملف الثنائي (binary) المُجمَّع داخل مجلد `test_subject`.
4. شغّل `run.sh` بصلاحيات `sudo`.

> [!IMPORTANT]
> اختبار E2E الكامل يستغرق وقتاً طويلاً جداً؛ إذا أجريت تغييراً صغيراً فقط في المشروع، فمن الأفضل اختبار ذلك الجزء فقط باستخدام الخيار `--tests`:

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

ولاختبار نظام تشغيل واحد محدّد فقط، يمكنك أيضاً استخدام الخيار `--only`:

```bash
sudo ./run.sh --only ubuntu-24
```

## التبرّع

🔹USDC-Polygon: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-BEP20: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-TRC20: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹TRX: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹LTC: ```ltc1qmapmnuf6cq9x679nmu0k4uyq779mxxcwnkgdll```

🔹BTC: ```bc1q62w7lyndzndsp74vj4dsayvun8xnapzq6hx5ea```

🔹ETH: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```
