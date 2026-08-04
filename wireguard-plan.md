# WireGuard - research and implementation plan

Adding **WireGuard** (the in-kernel **C** implementation, not Xray's userspace Go wireguard)
as an 8th first-class VPN protocol with real, panel-integrated account management. This
document is the research record and proposed implementation contract, produced from a 7-agent
recon (4 codebase + 3 web). Mirrors the style of `ikev2-plan.md` / `sstp-plan.md`.

STATUS: RESEARCH ONLY - HOLD FOR REVIEW. Nothing built yet.

## Decisions proposed (2026-07-15) - need sign-off

The user asked for "the official C version with a real account management" and explicitly
rejected "the go version [whose] account management is terrible". That is a precise scope
statement, decoded below into locked recommendations plus 3 open product decisions.

1. **This is Path B, not Path A.** "Official C version" = the in-kernel WireGuard module.
   "Real account management" = full integration into this fork's data plane (per-account
   peers, User-Limit, quota/expiry, accounting, Core Settings row), exactly like ikev2/sstp.
   The existing Xray-native `wireguard` inbound (userspace Go, no account management) is the
   thing being rejected, so we do NOT build on it. (Path A = polish that inbound; cheap but
   it is literally the rejected option. Kept in Part 1 only as a documented fallback.)
2. **Protocol id = `wgvpn`** (display label "WireGuard"). The string `wireguard` is ALREADY
   taken (Part 1); reusing it routes our inbound into Xray-core as a native proxy. OPEN
   DECISION: what to do with the inherited native `wireguard` inbound (relabel / hide / leave).
3. **Data path = in-kernel WireGuard module on all 12 supported targets** (Part 2). Detect
   with the existing `modprobe -nq wireguard` pattern. **boringtun** (Rust, musl-static,
   `go:embed`) as a userspace fallback only when the module is absent.
4. **Peer/account management = `wgctrl-go` in-process** over netlink (Part 3). No shelling to
   `wg`, no `wg-quick` (it needs bash + nft + resolvconf). `ip` (iproute2, already a host dep)
   only for interface create/up/addr.
5. **Auth = none in-band.** WireGuard authenticates by static public key; there is no login
   event (Part 4). The account keeps its username/password as PANEL/subscription identity and
   a label; the WireGuard credential is a generated keypair bound to the account in the DB.
   **The in-binary RADIUS server is not involved at all** - WireGuard is the first fork
   protocol that does not touch `radius.go`.
6. **Address base = 7 -> `10.7.0.0/16`** - the last /16 inside the covering `10.0.0.0/13`.
   No nftables widening (a future base-8 protocol would force /13 -> /12).
7. **Data-plane routing is reused unchanged** (Part 5). Kernel WG decrypts, the peer's tunnel
   IP (`10.7.x.x`) becomes the packet source, and the existing `nftables saddr /24 -> dokodemo
   -> Xray` source-IP routing works as-is.
8. **Accounting = reuse the existing nftables per-IP read-and-reset counters** (Part 6),
   uniform with the other 6 protocols, which sidesteps WireGuard's cumulative-counter-reset
   problem entirely. `wgctrl` `latest-handshake` is used only for liveness/online status.
9. **Control plane = a periodic reconcile sweep** (Part 7), cloning the IKEv2-local model
   `ReconcileLocalAuthSessions` (`ikev2.go:932`). The DB is the source of truth; the live wg
   device is reconciled to the DB each traffic tick and on config change. There is no
   connect/disconnect hook and no accept-evict-at-connect.
10. **User-Limit K = K provisioned peers/keypairs per account** (structural cap; Part 7).
    OPEN DECISION: keep the exact current "K simultaneous online out of many" semantics
    (needs a handshake-liveness watcher) vs the simpler structural cap.
11. **Client key generation = server-side** (panel mints the keypair, can re-show `.conf` +
    QR anytime). OPEN DECISION vs client-side (more secure, panel cannot re-display config).

---

# Part 0 - Executive summary

- **WireGuard is the lightest protocol to add on the bundling axis and the heaviest on the
  control-plane axis.** The in-kernel C data path already ships in every one of the 12
  supported OSes (vendors backported it below Linux 5.6; EL9 has it; dropping EL8 last release
  removed the one host that needed DKMS). So there is **no musl daemon to build and bundle** in
  the primary path - the opposite of every prior protocol. The cost moves entirely to the
  control plane, which must be redesigned rather than cloned.
- **The clean split: reuse the bottom half of the stack, redesign the top half.** The bottom
  half (10.7/16 addressing, `nftables saddr -> dokodemo -> Xray` source-IP routing, per-IP nft
  accounting into `client_traffics`) ports over essentially unchanged. The top half (RADIUS
  username/password auth, Framed-IP assignment, connect-time User-Limit, Acct-driven sessions)
  does not apply at all and is replaced by a reconcile sweep.
- **The correct template is IKEv2 PSK/EAP-TLS "local auth"** (`ReconcileLocalAuthSessions`),
  not the RADIUS daemon protocols. That code already proves the pattern: a keyless,
  sweep-reconciled protocol grafted onto the RADIUS-centric data plane, enforcing
  usage/quota/User-Limit by killing sessions on a timer instead of at an auth event.
- **Peer management is a Go library call, not a subprocess.** `wgctrl-go`
  (`golang.zx2c4.com/wireguard/wgctrl`) configures the kernel device (or a userspace boringtun
  device, identical code) over netlink: generate keys, add/remove peers, read per-peer byte
  counters and last-handshake. This is a much better fit than the RADIUS-daemon pattern -
  per-client state lives entirely in the device peer list, which wgctrl owns.
- **Two hard gotchas, both already surfaced by recon:** (1) the `wireguard` protocol-string
  collision with Xray-native WG - must use a distinct id; (2) counter resets - avoided by
  accounting through the existing nft counters instead of `wg show transfer`.
- **Biggest new cost:** a new control-plane sweep service and the account<->keypair data model
  (a "client" is a pubkey, not a username/password). Everything else is clone-and-adapt.
- **Client onboarding is a partial freebie:** the inherited native-WG frontend already builds
  per-peer `.conf` files and QR codes (`genWireguardConfigs`/`genWireguardLinks`,
  `inbound.js:2262`); that code is reusable for the new protocol's config export.

---

# Part 1 - Which "WireGuard"? The collision

`wireguard` / `WireGuard` is **already a protocol id in this codebase** - the Xray-native
userspace WireGuard inbound inherited from the 3x-ui upstream. It is wired end to end and is
exactly what the user is rejecting:

- Enum `WireGuard Protocol = "wireguard"` at `database/model/model.go:23`.
- Frontend `Protocols.WIREGUARD` + `ProtocolLabels.wireguard` (`inbound.js:6,28`), settings
  class `Inbound.WireguardSettings` (`inbound.js:4310`, peers/secretKey/pubKey), form partial
  `web/html/form/protocol/wireguard.html`, per-peer `.conf`+link+QR already built by
  `genWireguardConfigs`/`genWireguardLinks` (`inbound.js:2262`) and rendered in
  `inbound_info_modal.html:512` + `qrcode_modal.html:117`.
- i18n `[pages.xray.wireguard]` at `translate.en_US.toml:740`.
- Backend: NO special handling - it is NOT in `isVpnProtocol()` (`inbound.go:262`), Xray
  terminates the tunnel itself. It does not route through TPROXY/dokodemo and has none of the
  fork's account management. It is also used as an Xray OUTBOUND for WARP (`outbound.js`).

**Consequence: we cannot reuse the string `wireguard` for the new protocol.** Every data-plane
switch keys on the protocol string; a `wireguard` inbound would be handed to Xray-core as a
native proxy (`xray.go:115` skips it from the VPN path), the exact opposite of what we want.
The new first-class protocol needs a distinct id - recommend **`wgvpn`** with display label
**"WireGuard"**.

**Open decision - the inherited native inbound:** it stays functional as an Xray outbound
(WARP) regardless. For the inbound dropdown, options are (a) relabel it "WireGuard (Xray)" so
the two are distinguishable, (b) hide it from the inbound dropdown (keep the outbound), or
(c) leave it as-is. Recommend (a) or (b) to avoid two dropdown entries both reading
"WireGuard".

---

# Part 2 - Data path: kernel module vs userspace

"The official C version" is the **in-kernel WireGuard module** (`wireguard.ko`), the reference
C implementation Jason Donenfeld upstreamed into Linux 5.6. Contrast:

| Thing | Lang | Role | Moves packets? |
|---|---|---|---|
| In-kernel module | **C** | Canonical data plane (mainline >= 5.6) | Yes - the data path |
| wireguard-tools (`wg`, `wg-quick`) | C | Configuration tools only | No |
| wireguard-go | Go | Userspace data plane (what Xray uses) | Yes (rejected by user) |
| boringtun / wireguard-rs | Rust | Userspace data plane | Yes (fallback candidate) |

**Kernel-module availability across our 12-target matrix - it is present on 100% of them.**
A kernel-version check is the wrong gate (vendors backported the module below 5.6); probe for
the module instead.

| Target | Kernel | In-kernel WireGuard |
|---|---|---|
| Ubuntu 18.04 / 20.04 | 4.15-HWE5.4 / 5.4 | Yes (Canonical backport; the "5.4 < 5.6 but works" case) |
| Ubuntu 22.04 / 24.04 / 26.04 | 5.15 / 6.8 / newer | Yes (mainline) |
| Debian 11 / 12 / 13 | 5.10 / 6.1 / 6.x | Yes (mainline) |
| Fedora (current) | 6.x | Yes (mainline) |
| AlmaLinux / Rocky 9 | 5.14 | Yes (in-kernel; only `wireguard-tools` from EPEL, no DKMS) |
| Arch | rolling 6.x | Yes (mainline) |

This is the payoff of having dropped EL8 in v1.4: EL8's 4.18 kernel is the only case that would
have needed `kmod-wireguard` DKMS from ELRepo. It is gone.

**Runtime detection** (reuse the `moduleAvailable` pattern already in `bootloader.go`):
`modprobe -nq wireguard` (dry-run, exit 0 = loadable), or attempt `ip link add dev wgX type
wireguard` and treat `Operation not supported` as "module absent".

**Userspace fallback (rare - minimal containers / locked-down kernels):** `go:embed` a
static-musl **boringtun** (Rust - honors the user's "not Go" preference) and run
`boringtun-cli -f wgX` as a procmgr child. It creates the TUN interface plus the
`/var/run/wireguard/wgX.sock` UAPI socket, after which **the same wgctrl code configures it
unchanged**. Build: `cargo build --release --target x86_64-unknown-linux-musl --bin
boringtun-cli`. This is the only binary we would ever bundle, and only for the edge case.

We do **not** bundle `wg-quick` (bash + iproute2 + nft/iptables + resolvconf). We likely do
not bundle `wg` either, since wgctrl replaces it; a static-musl `wg` (trivial Alpine build,
`make -C src WITH_WGQUICK=no LDFLAGS=-static`) is optional as a manual debug aid.

---

# Part 3 - Peer management: `wgctrl-go` vs shelling to `wg`

**Recommendation: `wgctrl-go` in-process.** It configures the kernel device OR a userspace
device over netlink/UAPI with no subprocess, and it is the same upstream MIT org.

```go
import (
    "golang.zx2c4.com/wireguard/wgctrl"
    "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

c, _ := wgctrl.New()                    // talks netlink (kernel) OR the UAPI socket (userspace)
defer c.Close()
d, _ := c.Device("wgvpn0")              // *wgtypes.Device; errors.Is(err, os.ErrNotExist) if absent
err  = c.ConfigureDevice("wgvpn0", cfg) // apply a wgtypes.Config

priv, _ := wgtypes.GeneratePrivateKey()  // server or client private key (no `wg genkey`)
pub     := priv.PublicKey()
psk, _  := wgtypes.GenerateKey()         // optional preshared key
```

Types used:

```go
type Config struct {                     // device level
    PrivateKey *Key; ListenPort *int; FirewallMark *int
    ReplacePeers bool                    // false = merge peers, true = replace whole set
    Peers []PeerConfig
}
type PeerConfig struct {                 // per client/device
    PublicKey Key                        // mandatory
    Remove bool                          // delete this peer
    UpdateOnly bool                      // act only if the peer already exists
    PresharedKey *Key
    Endpoint *net.UDPAddr
    PersistentKeepaliveInterval *time.Duration
    ReplaceAllowedIPs bool               // see footgun below
    AllowedIPs []net.IPNet               // the device's tunnel IP(s), e.g. 10.7.0.2/32
}
type Peer struct {                       // read-back / accounting / liveness
    PublicKey Key; Endpoint *net.UDPAddr
    LastHandshakeTime time.Time          // -> online detection (< ~180s)
    ReceiveBytes int64; TransmitBytes int64
    AllowedIPs []net.IPNet
}
```

**Division of labour** (wgctrl is explicitly out of scope for device creation + IP/routes):
- Create device: `ip link add dev wgvpn0 type wireguard` (kernel) OR spawn `boringtun-cli -f
  wgvpn0` (fallback).
- Address + up: `ip address add dev wgvpn0 10.7.0.1/24`, `ip link set up dev wgvpn0`.
- Private key, listen port, add/remove/update every peer, read counters + handshake: `wgctrl`.
  Per-peer `/32` routes are auto-installed by the kernel from `AllowedIPs`.

**Footgun (wgctrl-go issue #88):** on a bulk `ConfigureDevice`, set `ReplaceAllowedIPs`
correctly per peer or you can wipe other peers' allowed-ips. Prefer `UpdateOnly` + explicit
per-peer configs when reconciling.

**Persistence:** `wg set`/`ConfigureDevice` changes are in-kernel memory only and vanish on
reboot/interface restart. The panel DB is the source of truth; the device is rebuilt from the
DB on start and reconciled each tick. Do NOT rely on `wg-quick save` or an on-disk `wg0.conf`
as canonical (this matches wg-portal/Firezone/defguard, which are all DB/control-plane driven).

---

# Part 4 - Auth and account model (the redesigned half)

**WireGuard has no in-band user authentication - by design, not a gap.** Identity is the static
Curve25519 public key; the Noise_IK handshake validates it by a local lookup ("is this pubkey a
configured peer?"), and there is no username/password, EAP, challenge-response, or RADIUS hook.
The preshared key is an optional per-peer symmetric secret for post-quantum resistance, not user
auth. Confirmed dead-ends: SoftEther's RADIUS does not work for its WireGuard listener; MikroTik
RADIUS authenticates PPPoE/hotspot running ALONGSIDE WireGuard, never the WG tunnel itself.

**The industry-standard reconciliation (Tailscale/Firezone/defguard/wg-portal): out-of-band
provisioning.** A user authenticates once to a portal (here: the panel), a keypair is issued and
bound to the account, and the keypair is the long-lived credential thereafter. Per packet there
is no user auth.

**Model for this panel:**
- The account row keeps its **username/password** for panel login / subscription / labelling.
  That username/password is **not** a VPN data-plane credential.
- The WireGuard credential is a **generated keypair** (one per device) bound to the account in
  the DB. The account<->pubkey mapping in our DB IS the identity layer that RADIUS provides for
  the other 6 protocols.
- No `parseNASIdentifier`, `handleAuth`, `handleAcct`, `lookupClient`, PAP/CHAP/EAP, Framed-IP,
  NAS-Port, or `allocateBlockIP` involvement. `radius.go` is untouched by WireGuard.

**Panel client-object shape:** a WireGuard "client" is `{email, enable, publicKey,
(optional) privateKey, presharedKey, address}`, not `{id, password, email}`. This diverges from
every existing `*User` JS class and from `client.html`'s username/password fields - the client
form needs a WireGuard variant (pubkey / generated-config, not password).

---

# Part 5 - Data-plane fit (the reused half)

This is where WireGuard slots in cleanly, because the fork's data plane is 100% protocol-blind
below the daemon: it keys entirely on source IP.

- Each account/device is pinned to a deterministic tunnel IP in `10.7.0.0/16` via the peer's
  server-side `AllowedIPs = <ip>/32` (the cryptokey-routing source-IP lock - the enforcement
  point that binds a device to its IP, analogous to OpenVPN CCD, not RADIUS Framed-IP).
- Kernel WireGuard decrypts; the packet emerges on `wgvpn0` with source `10.7.x.x`.
- The existing nftables rule `ip saddr <10.7.id.0/24> ... tproxy to :<12300+id>` steers it into
  the per-inbound Xray dokodemo-door (`GetDokodemoConfig`), exactly like charon/ocserv.
- Xray routes by source IP; `translateVpnRoutingRules` (`xray.go:270`) rewrites email-based
  rules into source-IP rules via `BuildVpnEmailToIPMap` (`radius.go:1339`) - we add a WireGuard
  branch that derives the email->IP map from the account<->pubkey<->IP DB mapping (not RADIUS).
- `vpnAddrSpace = 10.0.0.0/13` (`nftables.go:22`) already covers 10.7. Base 7 fits at the top
  edge. No widening.

**Server vs client `AllowedIPs` (the classic confusion):** server-side per peer = a source-IP
allowlist (`/32` per device). Client-side (the config we hand out) = a route selector
(`0.0.0.0/0, ::/0` for full tunnel). Same keyword, opposite meaning per side.

---

# Part 6 - Accounting

Two options; recommend the first for uniformity.

1. **Reuse the existing nftables per-IP read-and-reset counters (RECOMMENDED).** WireGuard
   traffic traverses the same TPROXY path, so the `{proto}_acct` chains
   (`ip saddr`/`ip daddr` named counters, `AddClientAccounting` `nftables.go:469`,
   `CollectAndResetTraffic` `nftables.go:556`) already capture per-IP bytes. This is identical
   to the other 6 protocols, folds into `client_traffics` via the existing
   `xray_traffic_job.go`, and - crucially - has **no counter-reset problem** because nft
   counters are read-and-reset each tick. WireGuard's own `wg show transfer` counters are
   cumulative and reset to zero whenever a peer is removed/re-added (which quota/expiry
   enforcement does constantly), requiring a delta-with-reset-detection accumulator. Reusing
   nft counters sidesteps all of that.
2. `wgctrl` `Peer.ReceiveBytes/TransmitBytes` (the idiomatic WireGuard way). Only needed if we
   ever want to account encrypted-side bytes (including handshakes/keepalives). Not recommended
   for quota; it double-counts overhead and carries the reset gotcha.

**`wgctrl` `LastHandshakeTime` is still used** - but only for liveness/online status and for
choosing an eviction victim, not for byte accounting.

---

# Part 7 - User-Limit / quota / expiry via a reconcile sweep

There is no connect/disconnect event and no session object to kill. Everything is a periodic
reconcile, cloning `ReconcileLocalAuthSessions` (`ikev2.go:932`), run each traffic tick from
`xray_traffic_job.go`:

1. Read live peers via `wgctrl` `Device.Peers`.
2. Map each `Peer.PublicKey` -> account/email (DB) -> deterministic `10.7` IP.
3. Feed the IP->email map into the accounting layer (a WireGuard analogue of
   `ReconcileIkev2LocalSessions` `radius.go:514`) so the nft counters attribute bytes to the
   right account.
4. Enforce disabled / over-quota / expired: remove those accounts' peers from the device
   (`ConfigureDevice` with `PeerConfig{Remove:true}`); re-add on renewal. Removing a peer cuts
   traffic instantly - the kernel drops its crypto state, no active "kick" needed.
5. The DB is authoritative; the device is reconciled to the DB (this also rebuilds peers after a
   reboot, since kernel peer state is not persistent).

**User-Limit K (open decision):**
- **K provisioned peers (RECOMMENDED, simpler and structurally sound).** An account owns exactly
  K keypairs = K peers, each with its own `/32` from the account's K-consecutive block (reuse
  `vpnAccountDeviceIPs` `vpnrange.go:725`). The account cannot exceed K devices because only K
  keys exist. No accept-evict race, no `Calling-Station-Id`/`NAS-Port` disambiguation (each
  device already has a distinct key + IP). This is what wg-portal's `limit_additional_user_peers`
  does. It also makes the recurring same-NAT-K>1 collapse bug (ocserv/sstp/ikev2) impossible
  here.
- **K simultaneous online out of many provisioned** (matches the current RADIUS accept-evict
  semantics exactly). Needs a `latest-handshake` liveness watcher in the sweep: count peers with
  a handshake < ~180s; over K, evict the oldest-handshake peer via `PeerConfig{Remove:true}`
  (Strategy reject = leave it removed / do not provision; accept = remove the oldest). More
  code, and semantically odd for WireGuard.

The strategy field (reject / accept-evict-oldest) is largely moot under the recommended model
and only meaningful under the second.

---

# Part 8 - Client config and onboarding

The client config is a standard wg-quick `.conf`:

```
[Interface]
PrivateKey = <device_priv>
Address    = 10.7.0.2/32
DNS        = 10.7.0.1
[Peer]
PublicKey    = <server_pub>
PresharedKey = <optional psk>
Endpoint     = <panel-access-host>:51820
AllowedIPs   = 0.0.0.0/0, ::/0        # full tunnel
PersistentKeepalive = 25
```

- **Endpoint host** should default to the panel-access host (reuse `controller.browserHost()`,
  the same default we use for the `.ovpn` `remote`).
- **QR** = the entire `.conf` text encoded verbatim (the mobile apps import it directly). The
  frontend already has this: `genWireguardConfigs`/`genWireguardLinks` (`inbound.js:2262`) +
  `qrcode_modal.html:117` (QRious). Adapt it for the new protocol's per-device config.
- Backend generator: a `GenerateClientConfig`-style method + a download route mirroring
  `downloadOvpn` (`inbound.go:843`, `GET /:id/ovpn/:proto`) and a keypair-generation route
  mirroring `generateIkev2Cert` (`inbound.go:964+`).

**Open decision - key generation:**
- **Server-side (RECOMMENDED for UX parity).** Panel generates the keypair, stores both keys,
  can re-show the `.conf` + QR anytime (the panel already re-shows configs for other protocols).
  Cost: the DB now holds client private keys - a DB/admin compromise can impersonate clients.
  Weigh DB-at-rest encryption. Path of least resistance.
- **Client-side (more secure).** The client generates the keypair and uploads only the public
  key; the private key never touches the server. Cost: the panel can never re-display a working
  config, only the public/peer side. Diverges from the current re-show-config UX.

---

# Part 9 - Bundling and provisioning

- **No musl daemon bundle in the primary path** (kernel module). This is unique among the fork's
  protocols and removes the entire `build/backend/<proto>-bundle.sh` +
  `backend/<proto>.go` extract-tree machinery from the critical path.
- **New Go dependency:** `golang.zx2c4.com/wireguard/wgctrl` (+ its `mdlayher/netlink` deps).
  Vendored/`go.mod` add; builds with the normal `./build.sh` cgo build.
- **Optional bundled binary:** static-musl `boringtun` for the userspace fallback, embedded via
  the existing `//go:embed all:bin` (`backend/backend.go:26`) and run as a procmgr child. Add a
  `backend/wireguard.go` only if we ship the fallback (mirrors `backend/accel.go` but for a flat
  binary, like ocserv, not a tree bundle).
- **Kernel module provisioning:** add `wireguard` to `vpnKernelModules` (`core.go`) and the
  cross-distro module path (`bootloader.go`). On all 12 targets this is just `modprobe
  wireguard`; no package install for the data path (unlike ppp/xl2tpd). `ip` (iproute2) is
  already a declared host dependency.
- **procmgr orphan reaping:** only relevant if the boringtun fallback runs; add it to the reap
  list (`procmgr.go`). The kernel-module path has no daemon process to reap - the `wgvpn0`
  interface is torn down with `ip link del wgvpn0` on stop.

---

# Architecture fit and the hidden costs

- **New: a WireGuard control-plane service + reconcile sweep.** The one genuinely new subsystem.
  Everything else is clone-and-adapt from ikev2-local.
- **New: account<->keypair data model.** The client object is a pubkey, not a username/password.
  Touches the client JS models, `client.html`/`client_modal.html`, and the settings class.
- **Reused free:** addressing (base 7), nft TPROXY routing + accounting, `client_traffics`
  usage/quota/expiry job, Core Settings row (data-driven), the `.conf`/QR frontend.
- **Not applicable (must be bypassed, per recon):** RADIUS auth/acct path, Framed-IP assignment,
  NAS-Port/Calling-Station-Id keying, pppd/daemon child-process-per-session, connect-hook,
  accept-evict-at-connect, RADIUS dictionary attrs, EAP. WireGuard is the first protocol that
  fits the data plane but not the RADIUS control plane.
- **Watch items:** the `wireguard` string collision (use `wgvpn`); the wgctrl `ReplaceAllowedIPs`
  footgun; kernel peer state is non-persistent (rebuild from DB on start); server-side keys mean
  private-key-at-rest exposure.

---

# Proposed phasing (research-first, like ikev2-plan.md)

Build/verify gate at each step: `./build.sh` (never bare `go build`) + `go test ./web/...
-count=1` green. Never auto-run incus E2E (author only; project rule).

- **Phase 0 - feasibility gate.** Prove the load-bearing unknowns on one box: `ip link add type
  wireguard` + `wgctrl` add-peer + a client handshake + traffic through TPROXY -> Xray on a
  distinct source IP, AND the boringtun fallback path with the same wgctrl code. Add the
  `wgctrl` dependency. This is the "does the core idea even work end to end" gate.
- **Phase 1 - addressing.** `wgvpn` const, `protocolBase` case 7, `usedVpnSubnets` list,
  `normalizeBlockRanges(base, mirror=-1)` branch (single contiguous UDP block, clone
  openconnect/ikev2).
- **Phase 2 - core service + Go wiring.** New `web/service/wireguard.go` (device lifecycle via
  `ip`+wgctrl, peer add/remove, `GenerateAllConfigs`, `GetDokodemoConfig`, `GetTproxyPort`,
  `SetupRouting`/`SetupAllTproxy`, `RestartServices`/`StopServices`, the reconcile sweep). Wire
  into `core.go` (status/restart/stop/logs/provision), `xray.go:115,202-260` (skip-list +
  dokodemo injection), `nftables.go` (acct chain + `CollectAndResetTraffic` arity 6->7),
  `vpnrange.go`, `inbound.go` (`isVpnProtocol` + client-id switches), `web.go`,
  `xray_traffic_job.go`. NO `radius.go` changes.
- **Phase 2fe - UI.** `Protocols.WGVPN` + label, `WgSettings`/`WgUser` JS classes (accounts +
  User-Limit from `Ikev2Settings`, key/allowedIPs from `WireguardSettings.Peer`),
  `getSettings`/`fromJson`/`get clients`, `dbinbound.js` getters, new
  `form/protocol/wgvpn.html`, `inbound.html` include, `client.html`/`client_modal.html`
  pubkey/generate-config variant, `core.html` `coreTitle`/`coreBackend`, reuse the `.conf`/QR
  builders. Controller: `onWgvpnChanged`/`onWgvpnClientChanged`, dispatch arms, provision gate,
  key-gen + config-download routes.
- **Phase 3 - control plane.** The reconcile sweep + account<->keypair mapping + User-Limit K +
  quota/expiry peer removal/re-add. This is the redesigned half; do it deliberately, not by
  cloning RADIUS.
- **Phase 5 - E2E harness.** `PHASE_WGVPN` in `test_unit/harness/model.py:ALL_PHASES`,
  orchestrator tags/loops, `server_setup.py` inbound + User-Limit + second-inbound,
  `clients/wireguard.py` driver (`wg`/wg-quick client, handshake via `wg show
  latest-handshakes`, iface `wgvpn0` into `checks.py`), shared suite runs unchanged. Never
  auto-run.
- **Phase 6 - live verify** on a real box with real clients (mobile app QR import, desktop).
- **Docs** (separate commit): all-language READMEs, flowchart, `--tests` switch, tested-OS
  table.
- **Release:** bump version, `gh release create`.

---

# Reference - interface bring-up (no wg-quick)

```sh
ip link add dev wgvpn0 type wireguard        # kernel; OR: boringtun-cli -f wgvpn0 (fallback)
ip address add dev wgvpn0 10.7.0.1/24
# private key + listen port + peers via wgctrl ConfigureDevice (preferred), or:
#   wg set wgvpn0 listen-port 51820 private-key /run/vpn-ui/wgvpn0.key
ip link set up dev wgvpn0
# per-peer add (wgctrl PeerConfig, or):
#   wg set wgvpn0 peer <client-pub> allowed-ips 10.7.0.2/32 persistent-keepalive 25
# per-peer /32 routes are auto-installed from allowed-ips
# accounting/liveness: wgctrl Device.Peers (LastHandshakeTime); bytes via nft counters
# teardown: ip link del wgvpn0
```

---

# Build / test commands

```sh
./build.sh                         # canonical build (never bare `go build`)
go test ./web/... -count=1         # unit + i18n key-parity + template-parse
# E2E (author only, never auto-run):
# sudo test_unit/run.sh --tests wgvpn
```

---

# Key files (from recon - anchors drift, re-verify against current line numbers)

- Template to clone: `web/service/ikev2.go` (esp. `ReconcileLocalAuthSessions:932`,
  `GetDokodemoConfig:181`, `SetupRouting:694`), `web/service/charon.go` (device lifecycle
  shape), `web/service/openconnect.go`/`sstp.go` (service template), `web/service/radius.go:514`
  (`ReconcileIkev2LocalSessions`, the accounting-map hook - clone, do not add RADIUS auth).
- Data plane: `xray.go:115,202-260,270`, `nftables.go:22,469,556,593`,
  `vpnrange.go:137-153,283,367,725`, `job/xray_traffic_job.go`.
- Wiring: `core.go:299,479,569,633,663,675,708`, `inbound.go:262,425`, `web.go`,
  `procmgr.go:16` (+ reap list only if fallback), `backend/backend.go:26,35`.
- Controller: `controller/inbound.go:20-29,79-209,298,334-732` + routes `39-76`,`843,964+`.
- Frontend: `assets/js/model/inbound.js:1-40,1657,2262,2385,2407,3968,4310`,
  `assets/js/model/dbinbound.js:157,198`, `html/form/protocol/*.html`,
  `html/form/inbound.html:319`, `html/core.html:629,633`, `html/modals/inbound_info_modal.html`,
  `html/modals/qrcode_modal.html:117`.
- i18n: `translation/translate.*.toml`, `i18n_toml_test.go:45-88` (knownMissing),
  `template_parse_test.go`.
- E2E: `test_unit/harness/{model.py,orchestrator.py,server_setup.py,protocols.py,checks.py,
  panel.py}` + new `clients/wireguard.py` + `clients/base.py`.
- Collision reference: `database/model/model.go:23`, `assets/js/model/inbound.js:4310`,
  `html/form/protocol/wireguard.html`.

---

# External references

- WireGuard protocol/auth (no in-band auth): https://www.wireguard.com/protocol/
- WireGuard cross-platform / UAPI + `wg show dump` fields: https://www.wireguard.com/xplatform/
- WireGuard quickstart (`ip link add type wireguard` bring-up): https://www.wireguard.com/quickstart/
- wireguard-tools (no deps beyond libc; skip wg-quick): https://git.zx2c4.com/wireguard-tools/about/
- wgctrl-go API: https://pkg.go.dev/golang.zx2c4.com/wireguard/wgctrl and .../wgtypes
- wgctrl AllowedIPs footgun: https://github.com/WireGuard/wgctrl-go/issues/88
- boringtun (Rust userspace, musl): https://github.com/cloudflare/boringtun
- wg-portal (closest reference panel: peer/user model, expiry, K-cap, QR): https://github.com/h44z/wg-portal
- Firezone / defguard (portal auth + device model): https://github.com/firezone/firezone , https://docs.defguard.net/in-depth/architecture
- Counter-reset delta accounting (why we avoid it): https://github.com/snaeim/wgstat
- EL9 ships in-kernel WireGuard: https://computingforgeeks.com/setup-wireguard-vpn-on-rocky-linux-almalinux/
