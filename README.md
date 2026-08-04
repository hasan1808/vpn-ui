[English](/README.md) | [فارسی](/README_FA.md) | [العربية](/README_AR.md) | [中文](/README_ZH.md) | [Español](/README_ES.md) | [Русский](/README_RU.md) | [Türkçe](/README_TR.md)

<p align="center">
  <img src="https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/logo.png" alt="VPN-UI Logo" width="260">
</p>

This project is an enhanced version of the **[3X-UI](https://github.com/MHSanaei/3x-ui)** panel (version 2.9.3). The goal of this project is to add various protocols and set it up as an all-in-one panel with support for **Xray-core** features.

![Overview](https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/overview.png)

## New Features

- **Multi-Admin** with per-inbound access, so each admin only sees the inbounds you assign it
- **Reseller** accounts with a metered traffic balance an admin recharges, spent only on the inbounds it was given
- **Client to Client** support, even as **Cross Inbound** (an internal connection between an L2TP user and an OpenVPN user)
- Added **AES-256-GCM** and **AES-128-GCM** **Encryption** to the **Shadowsocks** protocol
- Support for **XHTTP Object** in **Inbound** and **Outbound**
- Automatic installation script for **[WARP-CLI](https://github.com/Sir-MmD/warp-cli)** (Cloudflare's official version)
- A [patched **Xray-core**](https://github.com/Sir-MmD/Xray-core) that fixes the "Unsupported Cipher" error in the **Shadowsocks** protocol, and adds **AnyTLS**, **TUIC** and **NaiveProxy** as native protocols, so they inherit per-account traffic accounting, speed limits, device limits and online detection instead of needing a second core
- Bundling all files (**Geofile**, **Xray-core**, and **Backend** cores) into a single binary
- **Real SSL for a bare server IP**, for a host with no domain at all (Let's Encrypt issues these; the certificate names the address itself)
- Certificate renewals are picked up **without restarting the panel**, so nobody is disconnected when a certificate rolls over
- Exporting account links as **TXT** and **PDF**
- Ability to **Freeze** accounts
- Added **checkboxes** to clients and **Inbound**s
- **Bulk Operation** support:
    * Bulk change of accounts' traffic
    * Bulk change of accounts' days
    * Bulk enable/disable of accounts
    * Bulk delete of accounts
    * Bulk delete of Inbounds
    * Bulk **Freeze/Un-Freeze** of accounts

## New Protocols

- PPTP
- L2TP (RAW)
- L2TP/IPsec
- OpenVPN
- OpenConnect (cisco)
- SSTP
- IKEv2
- WireGuard (C)
- AmneziaWG (obfuscated WireGuard)
- GRE (site-to-site router tunnels, optionally over IPsec)
- MTProto Proxy (Telegram)
- SSH

Plus three protocols added to the patched Xray-core itself, so they are served by
the core rather than by a daemon, and they work as **inbounds and outbounds**:

- AnyTLS
- TUIC (v5)
- NaiveProxy

## What's Fixed

- **Logger data race** — `logBuffer` protected with `sync.Mutex` to prevent concurrent write crashes
- **LDAP sync panic** — refactored `panic()` helpers to return errors; split `splitCsv`/`splitCsvOrDefault`
- **TLS guard** — fixed `||` to `&&` in TLS certificate validation
- **DB directory permissions** — changed from `0777` to `0750`
- **Unreachable code** — removed dead returns after `log.Fatalf` in 3 places (main.go)
- **Cron entry variable** — fixed uninitialized entry variable in task scheduler
- **GetSecret() side effect** — removed DB mutation from getter function
- **Regex recompile** — precompiled `md5Re` regex instead of recompiling on every call
- **Template variable shadowing** — renamed conflicting template variable in web.go
- **Port validation** — added missing lower bound check (min 1)
- **GetAllSetting** — fixed silently dropping unknown settings
- **Variable shadowing** — fixed `t` shadow in setting.go
- **TG bot startup** — consolidated duplicate bot check into single `startTask()`
- **runSeeders log message** — fixed wrong log message text
- **splitCsv** — fixed returning `DefaultTruthyValues` on empty input
- **AllPermissions order** — corrected permission list order mismatch
- **.gitignore** — updated `x-ui` reference to `vpn-ui`
- **Unused imports** — removed `unsafe` imports from main.go and global.go
- **RADIUS secret** — removed hardcoded fallback, uses empty string
- **Vue 2 reactivity** — fixed client credential fields not updating in edit modal
- **Config name** — changed from `x-ui` to `vpn-ui`
- **Session cookie** — uses `config.GetName()` instead of hardcoded name
- **LocalizerWeb race** — added `sync.RWMutex` to prevent translation map races
- **i18n fixes** — Vietnamese diacritics, zh_TW cross-locale leak, Arabic missing sections, Persian missing sections

## Tested Operating Systems


| | Distribution |Version |Version |
|:---:|:---|:---:|:---:|
| <img src="https://cdn.simpleicons.org/ubuntu" width="32" height="32" alt="Ubuntu"> | **Ubuntu** | `24.04` | `26.04` |
| <img src="https://cdn.simpleicons.org/debian" width="32" height="32" alt="Debian"> | **Debian** | `12` | `13` |
| <img src="https://cdn.simpleicons.org/fedora" width="32" height="32" alt="Fedora"> | **Fedora** | `43` | `44` |
| <img src="https://cdn.simpleicons.org/almalinux/2F80ED" width="32" height="32" alt="AlmaLinux"> | **AlmaLinux** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/rockylinux" width="32" height="32" alt="Rocky Linux"> | **Rocky Linux** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/centos" width="32" height="32" alt="CentOS Stream"> | **CentOS Stream** | `9` | `10` |
| <img src="https://cdn.simpleicons.org/archlinux" width="32" height="32" alt="Arch Linux"> | **Arch Linux** | `Rolling` | |


> [!IMPORTANT]
> It is strongly recommended that you install the panel on one of the tested operating systems, because there is a high chance that the new cores will not work correctly on other operating systems!

> [!NOTE]
> **AmneziaWG runs on Debian 12/13 and Ubuntu 24.04/26.04 only.**
> Unlike every other protocol, AmneziaWG is not in any distribution's kernel: the panel compiles its kernel module on your server during setup. That module currently fails to build in two cases. On **kernel 7.1 or newer** (Fedora 43/44, Arch) the kernel removed the `ipv6_stub` symbol the module still uses. On **AlmaLinux, Rocky Linux and CentOS Stream** the backported RHEL kernels collide with the module's compatibility layer, and EL10 is not recognised by it at all. Both are limitations of the upstream AmneziaWG module, with fixes still open upstream, so they are not something the panel can configure around.
> Setup detects this and tells you, rather than failing silently. **Every other protocol works normally on all tested operating systems.**

## Installing the Panel

```bash
curl -Ls https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/deploy.sh | sudo bash
```

## Uninstalling the Panel

```bash
sudo /opt/vpn-ui/vpn-ui-amd64 --uninstall
```

> [!NOTE]
> The database path, the **systemd** service, and all default ports have been changed, so you can install this panel alongside your other panels without any issues.

## How the New Protocols Interact with Xray-core

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

## How RBridge Handles Non-RADIUS Protocols

WireGuard (C), AmneziaWG and the IKEv2 **PSK** / **EAP-TLS** modes authenticate with a public key or a certificate, so they never make a RADIUS round-trip. On their own they would get no session record, no traffic accounting, and no **User Limit** enforcement. **RBridge** (Radius Bridge) closes that gap: once per traffic tick its **Sweeper** polls each protocol's live tunnels, enforces quota, disable, and the per-account **User Limit** K (evicting the losers), then reconciles the survivors into the very same in-binary **RADIUS** session registry and **nftables** accounting the RADIUS protocols already use. A key-based protocol therefore behaves identically for usage, quota, and device limits, and egresses through the same Xray **dokodemo-door** data plane.

For the two key-based tunnel protocols, **WireGuard (C)** and **AmneziaWG**, a **User Limit** of K provisions K device slots per account: K keypairs, K configs and K distinct tunnel IPs, one config per device. That is the same model the commercial providers use, and it is what makes a single account usable on a phone, a laptop and a router at once without the devices fighting over one key.

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

## Building from Source

```bash
git clone https://github.com/hasan1808/vpn-ui.git && cd vpn-ui
./build.sh
```

## E2E Testing

![E2E Test](https://raw.githubusercontent.com/hasan1808/vpn-ui/refs/heads/main/media/test_unit.png)

A complete **E2E** test written in Python has been designed for this project inside the `test_unit` folder, which you are welcome to use. The steps are as follows:

1. Go into the `test_unit` folder and enter your desired settings in `config.toml`.
2. Run the `setup.sh` script.
3. Place the compiled binary inside the `test_subject` folder.
4. Run `run.sh` with `sudo` privileges.

> [!IMPORTANT]
> The full E2E test is extremely time-consuming; if you have only made a small change to the project, it is better to test only that specific part using the `--tests` switch:

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

To test on only one specific operating system, you can use the `--only` switch:

```bash
sudo ./run.sh --only ubuntu-24
```

## Donate

🔹USDC-Polygon: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-BEP20: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-TRC20: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹TRX: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹LTC: ```ltc1qmapmnuf6cq9x679nmu0k4uyq779mxxcwnkgdll```

🔹BTC: ```bc1q62w7lyndzndsp74vj4dsayvun8xnapzq6hx5ea```

🔹ETH: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```
