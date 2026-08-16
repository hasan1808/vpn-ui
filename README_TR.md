[English](/README.md) | [فارسی](/README_FA.md) | [العربية](/README_AR.md) | [中文](/README_ZH.md) | [Español](/README_ES.md) | [Русский](/README_RU.md) | [Türkçe](/README_TR.md)

<p align="center">
  <img src="https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/logo.png" alt="PRO-UI Logo" width="260">
</p>

Bu proje, **[3X-UI](https://github.com/MHSanaei/3x-ui)** panelinin (2.9.3 sürümü) geliştirilmiş bir versiyonudur. Projenin amacı; çeşitli protokoller eklemek ve **Xray-core** özelliklerini destekleyen kapsamlı bir panel olarak hayata geçirmektir.

![Genel Görünüm](https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/overview.png)

## Yeni Özellikler

- Inbound bazlı erişimle **Çoklu Yönetici**: her yönetici yalnızca kendisine atadığınız Inbound'ları görür
- Yöneticinin yüklediği ölçülü trafik bakiyesiyle **Bayi** hesapları, yalnızca kendisine verilen Inbound'larda harcanır
- **Client to Client** özelliği, hatta **Cross Inbound** biçiminde bile (bir L2TP kullanıcısının bir OpenVPN kullanıcısına dahili bağlantısı)
- **Shadowsocks** protokolüne **AES-256-GCM** ve **AES-128-GCM** **Encryption** yöntemlerinin eklenmesi
- **Inbound** ve **Outbound** içinde **XHTTP Object** desteği
- **[WARP-CLI](https://github.com/Sir-MmD/warp-cli)** (Cloudflare'in resmi sürümü) için otomatik kurulum betiği
- **Shadowsocks** protokolündeki «Unsupported Cipher» hatasını gidermek için [yamalanmış **Xray-core**](https://github.com/Sir-MmD/Xray-core) çekirdeği
- Tüm dosyaların (Geofile, Xray-core ve Backend çekirdekleri) tek bir binary dosyası içinde paketlenmesi
- Hesap bağlantılarının **TXT** ve **PDF** olarak dışa aktarılması
- Hesapları **dondurma (Freeze)** özelliği
- İstemcilere ve Inbound'lara **checkbox** eklenmesi
- **Bulk Operation** özelliği:
    * Hesapların trafiğini toplu değiştirme
    * Hesapların süresini toplu değiştirme
    * Hesapları toplu etkinleştirme/devre dışı bırakma
    * Hesapları toplu silme
    * Inbound'ları toplu silme
    * Hesapları toplu **dondurma/çözme (Freeze/Un-Freeze)**

## Yeni Protokoller

- PPTP
- L2TP (RAW)
- L2TP/IPsec
- OpenVPN
- OpenConnect (cisco)
- SSTP
- IKEv2
- WireGuard (C)
- AmneziaWG (gizlenmiş WireGuard)
- GRE (yönlendiriciler arası site-to-site tüneller, isteğe bağlı olarak IPsec üzerinden)
- MTProto Proxy (Telegram)
- SSH

Yamalanmış Xray-core'a üç protokol daha eklendi; bunlar bir daemon tarafından değil doğrudan çekirdek tarafından sunulur ve **inbounds ile outbounds** olarak çalışır:

- AnyTLS
- TUIC (v5)
- NaiveProxy

## Düzeltmeler

- **Logger veri yarışması** — eşzamanlı yazma hatalarını önlemek için `logBuffer` `sync.Mutex` ile korundu
- **LDAP sync panic** — `panic()` yardımcıları hata döndürecek şekilde yeniden düzenlendi; `splitCsv`/`splitCsvOrDefault` ayrıldı
- **TLS koruması** — TLS sertifika doğrulamasında `||` yerine `&&` düzeltildi
- **DB dizin izinleri** — `0777` yerine `0750` olarak değiştirildi
- **Ulaşılamaz kod** — main.go'da 3 yerde `log.Fatalf` sonrasında ölü return'ler kaldırıldı
- **Cron entry değişkeni** — görev zamanlayıcısında başlatılmamış değişken düzeltildi
- **GetSecret() yan etkisi** — getter fonksiyonundan DB mutasyonu kaldırıldı
- **Regex yeniden derleme** — her çağrída yeniden derleme yerine `md5Re` önceden derlendi
- **Şablon değişken gölgeleme** — web.go'daki çelişkili şablon değişkeni yeniden adlandırıldı
- **Port doğrulama** — eksik alt sınır kontrolü eklendi (minimum 1)
- **GetAllSetting** — bilinmeyen ayarları sessizce bırakma düzeltildi
- **Değişken gölgeleme** — setting.go'daki `t` shadow düzeltildi
- **Telegram bot başlatma** — `startTask()` içindeki çift bot kontrolü birleştirildi
- **runSeeders log mesajı** — yanlış log metni düzeltildi
- **splitCsv** — boş girişte `DefaultTruthyValues` dönüşü düzeltildi
- **AllPermissions sırası** — izin listesi sırası uyumsuzluğu düzeltildi
- **.gitignore** — `x-ui` referansı `vpn-ui` olarak güncellendi
- **Kullanılmayan import'lar** — main.go ve global.go'dan `unsafe` import'ları kaldırıldı
- **RADIUS secret** — hardcoded fallback kaldırıldı, boş string kullanılıyor
- **Vue 2 reaktivitesi** — düzenleme modalında müşteri kimlik bilgilerinin güncellenmemesi düzeltildi
- **Config adı** — `x-ui` yerine `vpn-ui` olarak değiştirildi
- **Oturum çerezi** — hardcoded yerine `config.GetName()` kullanılıyor
- **LocalizerWeb yarışması** — çeviri haritası yarışlarını önlemek için `sync.RWMutex` eklendi
- **i18n düzeltmeleri** — Vietnamca aksanları, zh_TW diller arası sızma, Arapça eksik bölümler, Farsça eksik bölümler

## Test Edilen İşletim Sistemleri


| | Dağıtım |Sürüm |Sürüm |
|:---:|:---|:---:|:---:|
| <img src="https://cdn.simpleicons.org/ubuntu" width="32" height="32" alt="Ubuntu"> | **Ubuntu** | `24.04` | `26.04` |
| <img src="https://cdn.simpleicons.org/debian" width="32" height="32" alt="Debian"> | **Debian** | `12` | `13` |
| <img src="https://cdn.simpleicons.org/fedora" width="32" height="32" alt="Fedora"> | **Fedora** | `43` | `44` |
| <img src="https://cdn.simpleicons.org/almalinux/2F80ED" width="32" height="32" alt="AlmaLinux"> | **AlmaLinux** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/rockylinux" width="32" height="32" alt="Rocky Linux"> | **Rocky Linux** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/centos" width="32" height="32" alt="CentOS Stream"> | **CentOS Stream** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/archlinux" width="32" height="32" alt="Arch Linux"> | **Arch Linux** | `Rolling` | |


> [!IMPORTANT]
> Paneli mutlaka test edilen işletim sistemlerine kurmanız önerilir; çünkü yeni çekirdeklerin diğer işletim sistemlerinde düzgün çalışmama ihtimali yüksektir!

> [!NOTE]
> **AmneziaWG yalnızca Debian 12/13 ve Ubuntu 24.04/26.04 üzerinde çalışır.**
> Diğer tüm protokollerin aksine AmneziaWG hiçbir dağıtımın çekirdeğinde yer almaz: panel, kurulum sırasında çekirdek modülünü sizin sunucunuzda derler. Bu modül şu anda iki durumda derlenemiyor. **Çekirdek 7.1 ve üzerinde** (Fedora 43/44, Arch) çekirdek, modülün hâlâ kullandığı `ipv6_stub` sembolünü kaldırdı. **AlmaLinux, Rocky Linux ve CentOS Stream** üzerinde ise geriye uyarlanmış (backport) RHEL çekirdekleri modülün uyumluluk katmanıyla çakışıyor; EL10 ise bu katman tarafından hiç tanınmıyor. Her ikisi de AmneziaWG modülünün kendi sınırlamalarıdır ve düzeltmeleri ana projede hâlâ beklemektedir, dolayısıyla panelin ayarlarla aşabileceği şeyler değildir.
> Kurulum bunu tespit edip size bildirir, sessizce başarısız olmaz. **Diğer tüm protokoller, test edilen tüm işletim sistemlerinde normal şekilde çalışır.**

## Panel Kurulumu

```bash
curl -Ls https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/deploy.sh | sudo bash
```

## Panel Kaldırma

```bash
sudo /opt/vpn-ui/vpn-ui-amd64 --uninstall
```

> [!NOTE]
> Veritabanı yolu, systemd servisi ve tüm varsayılan portlar değiştirildi; bu yüzden bu paneli hiçbir sorun yaşamadan diğer panellerinizin yanına kurabilirsiniz.

## Yeni Protokollerin Xray-core Çekirdeği ile Etkileşimi

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

## RBridge, RADIUS Kullanmayan Protokolleri Nasıl Entegre Eder

WireGuard (C), AmneziaWG ve IKEv2'nin **PSK** / **EAP-TLS** modları açık anahtar veya sertifika ile kimlik doğrular; bu yüzden RADIUS ile gidiş-geliş yapmazlar ve aksi hâlde ne oturum kaydı, ne trafik muhasebesi, ne de **User Limit** uygulaması olurdu. **RBridge** (Radius Bridge) bu boşluğu kapatır: her trafik döngüsünde bir kez, **Sweeper** her protokolün canlı tünellerini yoklar (poll), kotayı (quota), devre dışı bırakmayı ve hesap başına **User Limit** K'yı uygular (fazlalıkları evict ile atarak), ardından hayatta kalanları RADIUS protokollerinin zaten kullandığı aynı gömülü **RADIUS** oturum kayıt defterine ve aynı **nftables** muhasebesine reconcile eder. Böylece anahtar tabanlı bir protokol kullanım, kota ve cihaz limiti açısından tıpatıp aynı davranır ve aynı Xray **dokodemo-door** veri düzleminden internete çıkar.

Anahtar tabanlı iki tünel protokolünde, **WireGuard (C)** ve **AmneziaWG**, K değerindeki bir **User Limit** her hesaba K adet cihaz yuvası ayırır: K anahtar çifti, K yapılandırma dosyası ve K farklı tünel IP'si, yani her cihaz için ayrı bir yapılandırma. Bu, ticari sağlayıcıların kullandığı modelin aynısıdır ve tek bir hesabın telefonda, dizüstünde ve router'da aynı anda, cihazlar tek bir anahtar için çekişmeden kullanılabilmesini sağlar.

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

## Kaynaktan Derleme

```bash
git clone https://github.com/hasan1808/vpn-ui.git && cd vpn-ui
./build.sh
```

## E2E Testi

![E2E Testi](https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/test_unit.png)

Bu proje için `test_unit` klasörü içinde Python ile tam bir **E2E** testi tasarlandı; bunu kullanabilirsiniz. Adımları şöyledir:

1. `test_unit` klasörüne girin ve istediğiniz ayarları `config.toml` içine girin.
2. `setup.sh` betiğini çalıştırın.
3. Derlenmiş binary dosyasını `test_subject` klasörünün içine koyun.
4. `run.sh` betiğini `sudo` yetkisiyle çalıştırın.

> [!IMPORTANT]
> Tam E2E testi son derece zaman alıcıdır; eğer projede yalnızca küçük bir değişiklik yaptıysanız, `--tests` switch'i ile yalnızca o bölümü test etmeniz daha iyi olur:

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

Yalnızca belirli bir işletim sisteminde test yapmak için de `--only` switch'ini kullanabilirsiniz:

```bash
sudo ./run.sh --only ubuntu-24
```

## Bağış

🔹USDC-Polygon: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-BEP20: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-TRC20: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹TRX: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹LTC: ```ltc1qmapmnuf6cq9x679nmu0k4uyq779mxxcwnkgdll```

🔹BTC: ```bc1q62w7lyndzndsp74vj4dsayvun8xnapzq6hx5ea```

🔹ETH: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```
