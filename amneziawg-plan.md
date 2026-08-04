# AmneziaWG - research and implementation plan

Adding **AmneziaWG** (obfuscated WireGuard, in-kernel **C** module) as a new first-class VPN
protocol, as a sibling of the existing kernel-WireGuard `wg-c` protocol. This document is the
research record and proposed implementation contract, produced from an 8-agent codebase recon
(build/bundling, provisioning/kernel, wg-c account+limits, xray/speed-limit/routing, frontend,
export, dashboard/core-settings, e2e) plus web research on AmneziaWG. Mirrors the style of
`wireguard-plan.md` / `ikev2-plan.md`.

STATUS: RESEARCH ONLY - HOLD FOR REVIEW. Nothing built yet.

DECISIONS LOG: 2026-07-18 - all open decisions resolved. OD1: **AWG 1.0** (official kernel
module, Jc/Jmin/Jmax/S1/S2/H1-H4). OD2: H1-H4 minted, read-only + Regenerate. OD3: default port
51821. OD4: kernel module on the E2E client VMs too. OD5: `wg-c` stays on upstream `wgctrl`
(only `awg` uses the fork).

## PHASE 0 RESULTS (2026-07-18) - feasibility gate GREEN, all load-bearing unknowns proven

Validated on two ubuntu-24 incus VMs (kernel 6.8.0-134-generic), Secure Boot off:

1. **DKMS build works headers-only.** `make dkms-install` + `dkms add/build/install` from the
   official module source (`master`, PACKAGE_VERSION 1.0.0) built + loaded `amneziawg` against
   the running kernel using only `linux-headers-$(uname -r)` (no full kernel source tree) —
   confirming issue #147 and the entire provisioning assumption. Deps: `dkms build-essential
   linux-headers-$(uname -r)` (apt). Module reports version 1.0.20260611, installs to
   `/lib/modules/.../updates/dkms/amneziawg.ko.zst`, dkms registered the kernel-upgrade rebuild
   hook automatically.
2. **`netlink.GenericLink{LinkType:"amneziawg"}` creates the link from Go** via
   vishvananda/netlink v1.3.1 (the exact version the repo pins) — NOT the `ip` fallback. This
   is the one deviation from wg-c's `netlink.Wireguard{}` and it is a clean in-process call.
3. **The `Jipok/wgctrl-go` fork (v1.2.0) configures the device incl. all AWG 1.0 obfuscation
   params.** `ConfigureDevice` set PrivateKey/ListenPort + Jc/Jmin/Jmax/S1/S2/H1-H4; `awg show`
   independently confirmed them in-kernel (`jc:4 jmin:8 jmax:80 s1:77 s2:90 h1:1234567 ...`).
   The fork's `wgtypes.Config` is a drop-in superset of upstream (compiled with zero API edits).
4. **Full end-to-end tunnel with obfuscation.** Server (configured via the Go/fork path) +
   client (`awg-quick up`, matching obfuscation) completed a real handshake and passed a
   cross-tunnel ping (3/3 packets, 0% loss); both ends showed fresh handshakes + byte transfer.

GO for Phase 1+. The spike code is in scratchpad; the shipped implementation is `web/service/
awg.go` + `web/service/amneziawg_dkms.go` + `awgsrc/` (vendored source) + the wiring across
model/vpnrange/nftables/xray/radius/inbound/core/job/web/controller.

## E2E RESULTS (2026-07-18) - ubuntu-24, AmneziaWG only: 1/1 GREEN, zero failures

`sudo test_unit/run.sh --only ubuntu-24 --tests awg` -> `1/1 distros fully passed`
(core-init [pass], server-setup [pass], awg [pass]). All 17 awg subtests:

PASS (13): connect (tunnel ip 10.8.8.8), dns-resolve, tunnel-egress (`dev awg src 10.8.8.8`),
internet (HTTP 204), dns-leak, client-to-client (peer 10.8.8.16), routing (A freedom online /
B blackhole cut off), cross-inbound (peer 10.2.1.4 on the openvpn inbound), psk-mode
(preshared-key tunnel 10.8.11.2 + internet), multi-inbound-same-proto (`:51825/10.8.8.8` +
`:51823/10.8.12.2` on distinct pools), account-usage (~12MB counted for 15MB), traffic-multiplier
(65MB counted for 10MB, policy 10x), account-termination (auto-disabled past 15MB, cannot
reconnect).
N/A (4, correct gateway-model overrides identical to wg-c): user-limit, strategy-reject,
strategy-accept, multi-user-total.

Harness note: the awg PRIMARY test inbound uses port 51825 (not the product default 51821)
because 51821 is already wg-c's `SECOND_PORTS` entry; a full-matrix run with both protocols
would otherwise fail wg-c's multi-inbound subtest. Ports: wgc 51820/51821/51822,
awg 51825(primary)/51823(2nd)/51824(psk).

## LIVE-BOX RESULTS (2026-07-18) - 65.109.217.240, real internet: GREEN

Bare Ubuntu 24.04.4 (kernel 6.8.0-111-generic) with NO dkms/gcc/kernel-headers and no panel.
Deployed the built binary (md5 verified), started it via the box's manual `setsid` convention,
and ran provisioning from the panel API:

1. **`ensureAmneziawg()` succeeded from scratch in ~80s**: step reported
   `"AmneziaWG (amneziawg kernel module) via apt", ok:true, "amneziawg module built + loaded
   (DKMS 1.0.0)"`. It installed dkms + build-essential (81 pkgs) + `linux-headers-6.8.0-111-generic`,
   extracted the vendored source to `/usr/src/vpn-ui-amneziawg`, ran `make dkms-install` ->
   `dkms add/build/install` -> `modprobe`. `dkms status`: `amneziawg/1.0.0, 6.8.0-111-generic,
   x86_64: installed`; module version 1.0.20260611. Coexists with the in-tree `wireguard` module.
2. **Inbound + data plane**: creating an awg inbound brought up `awg1` at `10.8.1.1/24` (base 8)
   listening on UDP 51821.
3. **Config render**: `awg-configs` returned `Address = 10.8.1.4/30` (userLimit 4 -> /30 gateway
   block) with Jc/Jmin/Jmax/S1/S2 and four unique minted magic headers (H1-H4).
4. **Real internet handshake**: a separate ubuntu-24 VM (kernel amneziawg module + awg-quick)
   connected to `65.109.217.240:51821` over the public internet: handshake completed, `HTTP 204`
   through the tunnel, DNS resolved, and the **egress IP seen externally was 65.109.217.240**
   (proving traffic traverses the live server's TPROXY -> Xray path). Route: `dev awg0 src 10.8.1.4`.
5. **Accounting**: 3,107,518 bytes billed to the account (matching the 3.07 MiB transferred);
   nft `awg_acct` chain held the correct `/30`-keyed counters; core status `awg: running,
   version 1.0.20260611, inbounds 1`.

Client tooling note: `awg-quick` needs `iptables` present for its 0.0.0.0/0 kill-switch rules.

## POST-REVIEW FIXES (2026-07-19)

### 1. AmneziaWG User Limit default -> 0 (DONE)
`Inbound.AwgSettings` constructor default flipped 1 -> 0, so a new awg inbound shows 0 =
the MAXIMUM block (64 devices, a /26) per `wgcEffectiveK`. The `fromJson` fallback stays 1
deliberately: the Go side reads an ABSENT userLimit as 1 (legacy single-IP), so matching it
keeps JS and Go in agreement for settings blobs written outside the UI.

### 2. Speed limit did nothing for ANY dokodemo VPN protocol (ROOT-CAUSED + FIXED + VERIFIED)
NOT awg-specific and NOT a regression from this work: it affected l2tp, pptp, openvpn,
openconnect, sstp, ikev2, wg-c and awg alike, since v1.7.2.

Root cause, in the patched core: `proxy.CopyRawConnIfExist` takes a zero-copy splice path
(`tc.ReadFrom`) whenever the inbound and every outbound report `CanSpliceCopy == 1`.
`dokodemo-door` sets exactly that (dokodemo.go:140) and `freedom` sets it on the outbound
(freedom.go:148) - which is precisely how every VPN tunnel protocol here arrives and
egresses. Splice moves bytes kernel-to-kernel and NEVER touches the `buf.Reader`/
`buf.Writer` wrappers where the limiter installs its pacing, so a spliced connection was
silently unlimited. vmess/vless/trojan were unaffected because they must decrypt and so
never splice - which is why the feature looked like it worked.

Everything else was already correct and was verified individually: the panel publishes the
right document (`speedlimits.json` carried the account with `downBps` and its source prefix,
e.g. `10.8.2.2/31`), `XRAY_SPEEDLIMIT_FILE` was set on the xray process, the file predated
the process, and the core's own lookup (empty dokodemo email -> source-IP prefix match)
is sound.

Fix: `speedlimit.DisableSplice(sessionInbound)` (new, in `common/speedlimit/speedlimit.go`)
sets `CanSpliceCopy = 3` and is called from BOTH dispatcher seams (`getLink` and `WrapLink`)
only when a limit actually applies, so unlimited accounts keep the fast path. Committed to
the Xray fork as `8e8581e1`, with `common/speedlimit/splice_test.go` as the regression test.

Live verification on 65.109.217.240 (same tunnel, same account):
  BEFORE: 1,090,033 B/s against a 512,000 B/s cap (unlimited)
  AFTER : 526,047 B/s against a 512,000 B/s cap (at the cap, incl. 1s burst)
  AFTER : 45,859 and 48,313 B/s against a 51,200 B/s cap, on a link whose floor was
          ~131,000 B/s - i.e. pinned to the configured value, not to the link.

BUILD CAVEAT: the fix lives in the `third_party/Xray-core` submodule. `build.sh` re-syncs
submodules and REWINDS a submodule that is ahead of the recorded gitlink, which would
silently drop this patch (the same trap documented for telemt). Until the gitlink is
committed in the parent AND `8e8581e1` is pushed to `Sir-MmD/Xray-core`, build with
`SKIP_SUBMODULES=1` (add `CORE_FORCE=1` to force a core rebuild).

### 3. User Limit K>1 gave every device the SAME tunnel IP (FIXED - per-device keypairs)

RESOLVED by moving awg from the gateway model to ONE KEYPAIR PER DEVICE SLOT. Reported
symptom: User Limit 2 produced a /31 config that, imported into two Windows VMs, assigned
both the same IPv4. Worse than cosmetic - the two VMs also shared a keypair, and since the
server keeps a single endpoint per peer, only whichever handshook last could actually pass
traffic. "User Limit 2" therefore could not deliver 2 working devices at all.

Implementation (`web/service/awg.go`):
  - new `awgDevice{privKey,pubKey,psk}` + `awgClient.Devices[]`, one entry per device slot;
    `deviceList()` seeds device 0 from the legacy single-keypair fields so inbounds created
    before this change keep working.
  - `ReconcileKeys` grows the array to K, TRIMS beyond K (lowering the limit revokes the
    surplus keys, which is what makes the limit enforceable), and mints/clears PSKs per device.
  - `awgDeviceIPs` hands device d the d-th address of the account's block.
  - `buildPeers` emits one peer per device pinned to its own /32 (not the whole block), so a
    device cannot source another's address.
  - `RenderClientConfigs` emits one config per device, labelled "Device N", each carrying its
    own PrivateKey and /32 Address.
  - `Poll` maps every device key back to its account, still billing against the account's
    block CIDR so usage/quota stay aggregated per account, not per device.
Regression tests: `web/service/awg_devices_test.go` (K=2 -> 2 configs, distinct IPs and
distinct keys; lowering K trims; K=1 unchanged).

CONSEQUENCE FOR FIX 1: with one keypair+config per device, `userLimit 0` would mean 64
keypairs and 64 rendered configs for EVERY account (and ~3 accounts per /24), so the default
is 1, not 0. The two requests are mutually exclusive under this model and the earlier default
change was reverted accordingly; the form tooltip now states the per-device meaning.

wg-c GOT THE SAME FIX (2026-07-19, confirmed by the user to have the identical collision):
`wgcDevice` + `wgcClient.Devices[]`, `wgcDeviceIPs`, per-device peers/configs, per-device key
minting + trimming in `ReconcileKeys`, and `Poll` mapping every device key. This finally makes
the code match its own long-standing doc comment ("device keypairs sized to K").

MIGRATION: `deviceList()` adopts an account's pre-existing keypair as device 0, so configs
already deployed on customers' machines keep working across the upgrade
(`TestWgcLegacyKeyAdoptedAsDeviceZero` pins this).

BEHAVIOUR CHANGE TO WATCH on wg-c: a peer's AllowedIPs narrows from the account's whole block
to the device's own /32. A router that NATs its LAN behind the tunnel is unaffected (its
source is its own tunnel IP), but a ROUTED (non-NAT) site-to-site setup, where LAN hosts
reached the server with the block's other addresses, will have those dropped. That use case
now needs one device slot per host, or NAT on the router.

WHY NOT "one config, different IP per device": impossible in WireGuard/AmneziaWG, and not an
allocator bug. (1) The protocol has NO address assignment - no DHCP/IPCP/config payload - so a
client's tunnel IP comes only from its own config's `Address` line and the server cannot
override it; this is exactly what differs from l2tp/pptp/sstp/ikev2, where the server assigns
the IP and User Limit K therefore yields K distinct IPs. (2) A peer is keyed by public key and
holds ONE endpoint, updated to the last authenticated packet's source, so two devices on one
keypair cannot both be online - the second steals the tunnel. Commercial providers work the
same way and merely hide it in their apps: Windscribe's generator has a "New Key Pair" button
(one config per device) and Mullvad allows 5 WireGuard KEYS per account, naming each device and
telling users to add an account or use a router beyond that.

### 3b. Original diagnosis (for reference)
Reproduced and isolated on the live box. It is NOT an allocator bug: two ACCOUNTS on one
K=2 inbound correctly get distinct blocks (`10.8.2.2/31` and `10.8.2.4/31`). The cause is
the gateway model itself - `ReconcileKeys` mints exactly ONE keypair per account and
`RenderClientConfigs` therefore returns exactly ONE config (verified: `configs: 1` at K=2),
whose `Address` is the account's whole block. Two devices given that one config both
present the block's first address.

Note the shipped `wgc.go` doc comment already claims "device keypairs sized to K /
trimming devices beyond K" - the CODE never did that, so wg-c has the same behavior and
this is a long-standing divergence from the documented intent, inherited by awg.

The fix (K keypairs -> K configs -> K distinct /32s, as `wireguard-plan.md` originally
recommended) CONFLICTS with fix 1 above and so was NOT applied unilaterally:
  - Gateway model (today): userLimit 0 = a 64-address block behind ONE link is coherent,
    and a router behind that link hands distinct addresses to its LAN. Default 0 makes sense.
  - K-keypair model: userLimit K = K devices = K keypairs = K configs. A default of 0 would
    then mean 64 keypairs and 64 rendered configs per account, which is not a sane default.
Both readings cannot hold at once; the choice also affects wg-c, and would make the
E2E's user-limit / multi-user-total subtests applicable instead of N/A.

Box restored: panel stopped (killed by PID per the box's safety rules), `awg1` removed, no
listeners/processes left. Still on the box: the binary, a DB with the one test inbound, and the
DKMS-installed amneziawg module (harmless; auto-rebuilds on kernel upgrade).
Restart with: `cd /opt/vpn-ui && setsid ./vpn-ui-amd64 >>/var/log/vpn-ui/vpn-ui.log 2>&1 </dev/null &`

## What AmneziaWG is (one paragraph)

AmneziaWG is WireGuard plus DPI-evasion obfuscation. With all obfuscation parameters set to
zero it is byte-identical to WireGuard. It adds junk packets (Jc/Jmin/Jmax), random padding on
handshake/cookie/data packets (S1/S2, and in 2.0 S3/S4), and magic header values that replace
the 32-bit message type (H1-H4). All obfuscation params must be IDENTICAL between client and
server EXCEPT Jc/Jmin/Jmax (junk counts may differ per peer). It is the leading fix for the
exact DPI environments this panel targets, where plain WireGuard is trivially fingerprinted and
blocked.

## The decisive external fact: the kernel module is AWG 1.0 only

The **official** `amnezia-vpn/amneziawg-linux-kernel-module` master branch supports only the
**AWG 1.0** parameter set: **Jc, Jmin, Jmax, S1, S2, H1, H2, H3, H4**. The 2.0 parameters
(S3, S4, and I1-I5 "custom protocol signature" hex blobs) are in PR #165 (under testing),
in userspace `amneziawg-go`, and in third-party PPAs, but are NOT merged into the official
kernel module. Since we are committed to the kernel module (Solution A, below), "every mode and
obfuscation" on the stable kernel path means the full AWG 1.0 set. This is honest and it is the
whole obfuscation surface the stable kernel module exposes. See OPEN DECISION 1.

Authoritative parameter ranges (kernel module README):

| Param | Range | Constraint | Recommended |
|---|---|---|---|
| Jc | 1..128 | junk packet count; may differ client/server | 4..12 |
| Jmin | < Jmax, < 1280 | junk min size; may differ | 8 |
| Jmax | Jmin < Jmax <= 1280 | junk max size; may differ | 80 |
| S1 | <= 1132 | init junk; S1+56 != S2; must match | 15..150 |
| S2 | <= 1188 | response junk; must match | 15..150 |
| H1..H4 | 5..2147483647 | must be unique among each other; must match | random |

---

## Decisions proposed - need sign-off

Locked recommendations plus open product decisions, matching the `wireguard-plan.md` convention.

1. **This is a SIBLING of `wg-c`, not a variant of it.** Plain `wg-c` keeps using the mainline
   in-kernel `wireguard` module (fast, zero host deps). AmneziaWG is a separate protocol using
   the separate `amneziawg` kernel module. Keeping them distinct means a `wg-c` inbound never
   drags in the DKMS build, and an AmneziaWG inbound is opt-in obfuscation. ~70% of the code is
   cloned from `wg-c` with a new slug threaded through; the genuinely new work is three items:
   the on-target DKMS build, the obfuscation params, and widening `vpnAddrSpace`.
2. **Data path = the in-kernel `amneziawg` module, built from vendored source via DKMS on the
   target (Solution A).** No userspace `amneziawg-go`. This is the project's FIRST on-host
   compilation; everything else ships prebuilt. Justified because the module is not mainline and
   cannot be prebuilt per-kernel across the supported matrix.
3. **Protocol id = `awg`** (display label "AmneziaWG"). Interface prefix `awg` -> `awg<id>`
   (well under the 15-char IFNAMSIZ limit). Go/JS identifiers `Awg`/`awg`. nft chain
   `awg_acct`. Grep confirmed zero existing `amnezia`/`awg` references, so the slug is free. The
   SAME string `awg` must appear in every dispatch switch, label map, and status row.
4. **Address base = 8 -> `10.8.0.0/16`, AND `vpnAddrSpace` widened `10.0.0.0/13` -> `/12`.**
   This is load-bearing and non-negotiable; see Part 5. `wg-c` already occupies base 7 (the last
   slot in the current /13). Base 8 falls outside `vpnAddrSpace` and silently breaks firewalld
   trust (no-internet on Fedora/RHEL) and the routing blackhole backstop (User-Limit becomes
   cosmetic) unless the space is widened.
5. **Control library = an AmneziaWG-aware `wgctrl` fork.** The stock
   `golang.zx2c4.com/wireguard/wgctrl` speaks the `wireguard` genetlink family and cannot see or
   configure an `amneziawg` device, nor set the obfuscation params. Use `Jipok/wgctrl-go`
   (a drop-in fork adding `Jc/Jmin/Jmax/S1-S4/H1-H4` to `wgtypes.Config` and an `IsAmnezia`
   device flag), forked into `Sir-MmD/wgctrl-go` and pinned per project convention. The `awg`
   service uses the fork; `wg-c` stays on upstream `wgctrl` (OD5 DECIDED: no `wg-c` migration this
   release).
6. **Obfuscation params are PER-INBOUND** (they live in `[Interface]` and must match all the
   inbound's clients), stored on the `awgSettings` struct, exactly like `wg-c`'s server keys.
   Keys stay per-client. H1-H4 are backend-minted-and-viewable (random, unique, in range) with a
   "regenerate" action, mirroring the "keys are never generated in the browser" model; Jc/Jmin/
   Jmax/S1/S2 are operator-editable numbers with the recommended defaults and range validation.
7. **User-Limit K = the same gateway model as `wg-c`** (one keypair per account addressing the
   account's K-sized CIDR block; K sizes the block, does not create K peers; `wgcEffectiveK`
   maps 0 -> 64). Reused wholesale.
8. **DKMS-failure behavior = warn and hard-degrade, NOT userspace fallback.** If the module
   cannot be built (missing headers, locked kernel, Secure Boot), the AmneziaWG core reports
   `CoreNotInstalled` with a clear reason and its inbounds cannot come up. There is no userspace
   floor, by your explicit instruction. This is surfaced honestly rather than silently degraded.

### OPEN DECISIONS (need your call)

1. **DECIDED (2026-07-18): AWG 1.0** (official kernel module: Jc/Jmin/Jmax/S1/S2/H1-H4), which
   builds via DKMS on all 7 supported distros and is officially maintained. The settings model +
   form are structured forward-compatibly so S3/S4/I1-I5 (2.0) can drop in when upstream merges
   PR #165 (add fields + a mode bump). No unofficial 2.0 fork is vendored.
2. **DECIDED (2026-07-18): H1-H4 backend-minted, read-only + Regenerate button** (random, unique,
   in range), visible in the config/QR. The must-match magic values stay correct by construction.
   Jc/Jmin/Jmax/S1/S2 remain operator-editable with range validation.
3. **DECIDED (2026-07-18): default listen port `51821`** (still editable, still collision-checked),
   so a box running both `wg-c` (51820) and AmneziaWG does not collide by default.
4. **DECIDED (2026-07-18): kernel module on the E2E client VMs too.** The Ubuntu-26 client VMs
   build the same `amneziawg` module via DKMS (from the same vendored source, or `amneziawg-dkms`
   from the Amnezia PPA), keeping the whole test kernel-based and faithful on both ends. No
   userspace `amneziawg-go` anywhere, including the test tree.
5. **DECIDED (2026-07-18): keep `wg-c` on upstream `wgctrl` for this release.** Only the new `awg`
   service uses the `Sir-MmD/wgctrl-go` fork. Two near-identical libs are vendored, but the
   shipped `wg-c` data plane is untouched. Revisit consolidation after Phase 0 proves the fork.

---

# Part 0 - Executive summary

- **The clean split (same as `wg-c`): reuse the whole data plane and account model, add three
  new things.** The reused half is enormous and comes essentially free once the `awg` slug is
  threaded: addressing/pools, `nftables saddr -> dokodemo -> Xray` source-IP routing, per-IP nft
  accounting into `client_traffics`, the `rbridge` sweep, the gateway User-Limit model, speed
  limit, traffic multiplier, client-to-client, cross-inbound, external proxy, config/QR/TXT/PDF
  export, the shared client add/edit form, and the dashboard/core-settings rows.
- **The three genuinely new things:** (1) a DKMS build of the `amneziawg` kernel module on the
  target host, the project's first on-host compile; (2) the obfuscation parameters
  (Jc/Jmin/Jmax/S1/S2/H1-H4) as new settings fields, rendered into `[Interface]` and pushed to
  the device via the AmneziaWG-aware `wgctrl` fork; (3) widening `vpnAddrSpace` to `/12` to make
  room at base 8.
- **The one wire that must not be missed:** AmneziaWG emails must be in `BuildVpnEmailToIPMap`
  (`radius.go:1352`, add the `awg` protocol and a `wg-c`-style block branch). That single map
  drives routing translation, the blackhole backstop, AND the speed-limit `ips[]`. Miss it and
  routing, User-Limit enforcement, and speed limit all silently fail for AmneziaWG.
- **The correct template is `wg-c` itself** (`web/service/wgc.go` and its wiring), not the RADIUS
  protocols. AmneziaWG is a keyless, sweep-reconciled, gateway-model protocol exactly like `wg-c`.
- **The heavy axis is provisioning, not code.** DKMS-on-target reintroduces a C toolchain +
  matching kernel headers as host deps and a rebuild-on-kernel-upgrade requirement, which the
  project has otherwise avoided. This must be engineered carefully (headers metapackage, keep
  toolchain, DKMS registration, EPEL on EL, Secure Boot detection) because there is no userspace
  safety net.

---

# Part 1 - Data path: kernel module via DKMS (Solution A)

AmneziaWG's data plane is an **out-of-tree** kernel module (`amneziawg.ko`), distinct from the
mainline `wireguard` module that `wg-c` uses. There is no prebuilt x86_64 `.ko` upstream; every
distro path is DKMS (compile from source). Solution A vendors the module source and builds it on
the target at provision time.

**Interface lifecycle (mirrors `wgc.go:427-468` but with the amneziawg link kind):**
- Create: `ip link add dev awg<id> type amneziawg` (kernel). In Go, `netlink.LinkAdd` with a
  generic link of kind `"amneziawg"` (verify `vishvananda/netlink` `GenericLink{LinkType:
  "amneziawg"}` creates it; the module registers an rtnl link kind, since `awg-quick` uses
  `ip link add type amneziawg`). This is the one deviation from `wgc.go:435`
  (`&netlink.Wireguard{}`).
- Address + up: assign block `.1`, `LinkSetUp` (identical to `wgc.go:445-453`).
- Device config (private key, listen port, peers, AND obfuscation params): via the AmneziaWG-
  aware `wgctrl` fork's `ConfigureDevice` against the `amneziawg` genetlink family. The stock
  `wgctrl` cannot do this.
- Teardown: `ip link del awg<id>` (mirrors `removeStaleLinks` `wgc.go:457-468`).

**PHASE 0 FEASIBILITY GATE (do this first, on one box).** Prove the load-bearing unknowns before
building anything else:
1. DKMS-build + load the vendored `amneziawg` module on one supported distro.
2. `netlink.LinkAdd` a `type amneziawg` device from Go (confirm `vishvananda/netlink` handles the
   link kind, or fall back to shelling `ip link add type amneziawg`).
3. Configure it with the `Jipok/wgctrl-go` fork: private key, listen port, one peer with the
   account block as AllowedIPs, and the obfuscation params (Jc/Jmin/Jmax/S1/S2/H1-H4).
4. Connect a real AmneziaWG client, confirm a handshake, and confirm traffic flows through the
   existing TPROXY -> dokodemo -> Xray path on the account's source IP.
This is the "does the core idea work end to end" gate, exactly like `wireguard-plan.md` Phase 0.

---

# Part 2 - Bundling and build.sh

Today every backend is prebuilt in an Alpine container and shipped via `go:embed`; nothing is
compiled on the target. AmneziaWG's artifact is a kernel module that must match the target's
running kernel, so it must be built on the target. That splits into a build-time "package the
source" step and a runtime "compile it" step (Part 3).

**Vendoring the source (build-time):**
- Add `third_party/amneziawg-linux-kernel-module` as a git submodule (mirror the `Xray-core` /
  `telemt` entries in `.gitmodules`), pinned to a specific SHA. Fork into `Sir-MmD/` if we carry
  patches (OPEN DECISION 1: official 1.0 vs a 2.0 fork).
- Add `build/backend/amneziawg-bundle.sh` that just `tar czf /out/amneziawg-src.tgz` the source
  tree with a `dkms.conf` (NO compile - it is arch/kernel-independent source). If patches are
  carried, add a patch-sentinel guard modeled on `build/backend/telemt-bundle.sh:71-86`, which
  aborts the build if the submodule was silently rewound (the exact `build.sh` submodule-sync
  trap that has bitten telemt).
- Add the `.tgz` to the staleness gate at `build.sh:77` (the `-f backend/bin/$ARCH/*` check) or a
  fresh checkout will not produce it.

**Embedding + extraction (mirrors `corebundle` / `backend/libreswan.go`):**
- A new `backend/amneziawg.go` with `//go:embed` of the source `.tgz` and an
  `ExtractAmneziawgSource()` that untars to `/usr/src/amneziawg-<ver>/`, using the atomic
  `WriteFileAtomic` pattern (`backend/backend.go:143-176`). Model on
  `backend/libreswan.go:80` (tar-to-a-dir) rather than the flat-binary extractor.

Nothing here departs from `build.sh`'s structure; `CGO_ENABLED=1 go build` at `build.sh:84-89`
is unchanged and the new embed rides the existing build. `./build.sh` stays the canonical build.

---

# Part 3 - Provisioning: the on-target DKMS build (new capability)

This is the one genuinely new subsystem. It lives beside the existing provisioning flow
(`runProvisionSteps` `core.go:875-1043`), reuses the package-manager and ensure-command
machinery, and returns a `ProvisionStep` that Warns (not hard-fails) so other protocols keep
working.

**New `web/service/amneziawg_dkms.go` with `ensureAmneziawg() ProvisionStep`, modeled on
`ensureLibreswan()` (`pkgmgr.go:116-170`).** Pipeline, per distro:
1. **EPEL on EL only** - new `ensureEpel()` in `pkgmgr.go` (detect alma/rocky/centos via
   `osReleaseField("ID")`, `installPackage("epel-release")`). Needed because `dkms` on EL comes
   from EPEL. No EPEL/CRB enablement exists today; this is new.
2. **Toolchain** - `ensureCommand("gcc",...)`, `ensureCommand("make",...)`, `ensureCommand
   ("dkms",...)` reusing `pkgmgr.go:327-350` (no-ops when present). New resolvers
   `gccPackage()/makePackage()/dkmsPackage()` beside `nftablesPackage()` (`pkgmgr.go:476`).
3. **Kernel headers for the RUNNING kernel** - new `KernelHeadersPackage()` in `pkgmgr.go`, an
   almost line-for-line copy of `KernelModulesPackage()` (`pkgmgr.go:569-591`), which already has
   the running-kernel-suffix logic. Install the **metapackage** where possible so DKMS rebuilds
   keep working across kernel upgrades.
4. **Extract source + `dkms add/build/install`**, capturing combined output into the
   `ProvisionStep.Log` (live-log the build like `warpsocks.go:83-155` does for warpcli.sh).
5. **`modprobe amneziawg`** and write `/etc/modules-load.d/amneziawg.conf`.
6. On any failure: return the step as **Warn** with the real error surfaced (mirrors
   `ensureLibreswan`), and let `amneziawgStatus()` report `CoreNotInstalled`.

**Concrete package names per distro:**

| Distro | toolchain | dkms | kernel headers (running) |
|---|---|---|---|
| Ubuntu 24/26 | `build-essential` | `dkms` | `linux-headers-$(uname -r)` (meta `linux-headers-generic`) |
| Debian 12/13 | `build-essential` | `dkms` | `linux-headers-$(uname -r)` (meta `linux-headers-amd64`) |
| Fedora 43/44 | `gcc make` | `dkms` | `kernel-devel-$(uname -r)` (meta `kernel-devel`) |
| Alma/Rocky/CentOS 9/10 | `gcc make` | `dkms` (after `epel-release`) | `kernel-devel-$(uname -r)` |
| Arch | `base-devel` | `dkms` | `linux-headers` (best-effort, like Arch/AUR libreswan) |

**Wiring (all mirror existing `wgc`/protocol sites):**
- Append `"awg"` to `provisionProtocols` (`core.go:648`) so `MissingProtocols()` re-flags setup on
  upgrade.
- Emit `ensureAmneziawg()` from `runProvisionSteps` near the kernel-module block (`core.go:1011`
  vicinity), inside the `backend.Available()` guard after the source is extracted.
- **CRITICAL, from the provisioning recon:** do NOT add `amneziawg` to `vpnKernelModules`
  (`core.go:21`). `MissingKernelModules()` (`pkgmgr.go:619`) would then always list it (it is
  never in a stock kernel, never modprobe-available before the build), which would trigger
  `provisionKernelModules` (`core.go:1061`) to try installing a distro kernel package that cannot
  provide it and wrongly trip the reboot/bootloader-pin path. Keep AmneziaWG entirely inside
  `ensureAmneziawg()`. Adding it to `vpnOptionalKernelModules` (`core.go:45`) is acceptable only
  for the status/persist row, and only knowing that loop runs before the build (so it shows "not
  on this kernel" until the build later succeeds); cleaner to keep it self-contained.
- Provisioning is NOT gated on `DistroSupported()` today (that is a dashboard-only advisory); gate
  the DKMS step on `detectPackageManager() != nil` and Warn per-step, like `ensureLibreswan`.

**Availability + status (mirror `WgcService.WireguardAvailable()` `wgc.go:504-507`):** an
`amneziawgAvailable()` = `moduleAvailable("amneziawg")`; module version from
`/sys/module/amneziawg/version` if exposed.

**Kernel-upgrade survival (must-engineer, no fallback):** register with `dkms install` (not a
one-shot `make insmod`), install the headers metapackage, and keep `gcc/make/dkms` installed, so
the DKMS kernel-postinst hook rebuilds the module on the next kernel. Detect Secure Boot and Warn
clearly (an unsigned module will not load and there is no floor beneath it).

---

# Part 4 - Data-plane fit (the reused half)

AmneziaWG is wire-compatible with WireGuard downstream of decryption, so the entire protocol-blind
data plane applies unchanged once the `awg` slug is threaded. Each item below is confirmed against
the current `wg-c` implementation.

- **Addressing / multi-inbound.** `protocolBase("awg") = 8` (`vpnrange.go:137-155`). Interface
  `awg<id>`, listen `inbound.Port`, block from `10.8.0.0/16`, TPROXY/dokodemo port `12300+id`
  (globally unique per inbound id, so no collision with `wg-c`). Add `awg` to `usedVpnSubnets`
  (`vpnrange.go:285`), `normalizeRanges` (`:369,402`), `maxVpnAccounts` (`:760,790`). Multiple
  AmneziaWG inbounds coexist collision-free exactly like multiple `wg-c` inbounds.
- **Xray-core routing.** Inject a dokodemo-door with `Tag=inbound.Tag` on port `12300+id`
  (`xray.go:287-294`), emit nft TPROXY rules for the block CIDR (`nftables.go:450-465`), and
  **add `awg` to `BuildVpnEmailToIPMap` (`radius.go:1370` list + a `wg-c`-style block branch at
  `:1410-1425`).** `translateVpnRoutingRules` (`xray.go:340-478`) then rewrites `user:[email]`
  rules to `source:[block CIDR]` and the blackhole backstop covers AmneziaWG IPs automatically.
- **Speed limit.** Works for `wg-c` today via the out-of-band sidecar `bin/speedlimits.json`
  (`speedlimit.go`), which maps source-IP -> email -> token bucket. AmneziaWG inherits it
  automatically because `loadSpeedLimitPolicies` reads every enabled inbound's clients, and the
  `ips[]` array is populated from `BuildVpnEmailToIPMap`. This is the same map as the routing
  wire above; getting that one branch right lights up routing AND speed limit.
- **IP limit.** Deliberately excluded for VPN protocols. Add `awg` to `isVpnProtocol`
  (`inbound.go:364-366`) so `ipLimitEnforcedInCore` (`speedlimit.go:210-215`) excludes it; device
  count is governed by User-Limit K instead (a gateway account owns a whole CIDR block, so an
  in-core per-IP cap would wrongly refuse legitimate LAN addresses).
- **User-Limit K + strategy.** Reuse `wgcEffectiveK`/`wgcAccountBlock` (gateway model: one keypair
  per account, K sizes the block, 0 -> 64). Real enforcement is the peer-set rebuild in
  `GenerateAllConfigs` each tick; the `rbridge` sweep `Limit`/`Evict` is wired for conformance but
  largely inert under the gateway model (one peer per account). Register the `awg` service with
  `sweeper.Register` (`xray_traffic_job.go:59`) and add `awg` to the `vpnSessions` map (`:112`).
- **Traffic multiplier.** Applies to `wg-c` today with zero protocol-specific code: it lives as
  three columns on the Inbound model (`model.go:117-123`) and is applied protocol-agnostically at
  the accounting choke points (`trafficmultiplier.go`, `inbound.go:2119-2128`). AmneziaWG inherits
  it automatically because its `client_traffics` rows carry the owning InboundId.
- **Client-to-client + cross-inbound.** nft-enforced, not WireGuard AllowedIPs. Add `awg` to the
  `allNets` assembly (`nftables.go:300`) and the accounting chain (`nftAcctChain("awg")` ->
  `awg_acct`, `nftables.go:518-520`). `writeClientToClientRules` / `writeCrossInboundRules` then
  apply uniformly.
- **External proxy.** Settings-JSON `awgSettings.ExternalProxy` (clone `wgcExternalProxy`), used
  ONLY in config rendering (Part 6). No data-plane code reads it.
- **Accounting.** Per-account nft counter keyed on the block CIDR, folded via
  `ReconcileLocalSessions("awg", ...)` (clone `radius.go:516-558`) and `CollectAndResetTraffic`.

---

# Part 5 - Addressing: base 8 and the `vpnAddrSpace` widening (CRITICAL)

`vpnAddrSpace = "10.0.0.0/13"` (`nftables.go:22`) covers only bases 0-7 (10.0.0.0-10.7.255.255).
`wg-c` is base 7, the last slot. AmneziaWG at base 8 (`10.8.x`) falls OUTSIDE `vpnAddrSpace`,
which silently breaks two things:
1. **firewalld trust** (`ensureVpnHostNetworking`, `nftables.go:52-75`): the TPROXY'd data plane
   would not be trusted on Fedora/RHEL, giving the classic "connects but no internet".
2. **Routing blackhole backstop** (`xray.go:465`): `{source:[vpnAddrSpace] -> blackhole}` would
   not cover 10.8.x, so over-limit AmneziaWG devices would leak to `direct`, making User-Limit K
   cosmetic.

**Fix: widen `vpnAddrSpace` to `10.0.0.0/12`** (covers 10.0-10.15, room for bases 8-15). The
constant's own comment says it must remain a superset of every protocolBase /16. This is a
one-line change plus a re-verification that the firewalld-trust and backstop paths pick up the
wider space. It must ship in the same change as base 8.

---

# Part 6 - Config, QR, TXT, PDF export

The export path is protocol-agnostic once the config text is produced; only the config assembly
and a few dispatch cases are new.

- **Config assembly.** Clone `RenderClientConfigs` (`wgc.go:572-637`). Inject the obfuscation
  lines into `[Interface]` (between `wgc.go:619` and `:624`), reading them from `awgSettings`.
  The exact emitted `[Interface]` for AmneziaWG:
  ```
  [Interface]
  PrivateKey = <client priv>
  Jc = <n>            Jmin = <n>    Jmax = <n>
  S1 = <n>            S2 = <n>
  H1 = <n>  H2 = <n>  H3 = <n>  H4 = <n>
  Address = <account block CIDR, e.g. 10.8.8.8/29>
  DNS = <dnsList()>
  MTU = <mtu()>
  [Peer]
  PublicKey = <server pub>
  PresharedKey = <optional>
  Endpoint = <host>:<port>
  AllowedIPs = 0.0.0.0/0
  PersistentKeepalive = 25
  ```
  The endpoint-target machinery (external proxies -> multiple configs), `dnsList()`, and `mtu()`
  are reused verbatim. NO `[Peer]` changes.
- **Route + handler.** Clone `getWgcConfigs` -> `getAwgConfigs`; register
  `g.GET("/:id/awg-configs", read, owns, a.getAwgConfigs)` (`inbound.go:98`).
- **Config modal.** Clone `web/html/modals/wgc_config_modal.html` -> `awg_config_modal.html`
  (`awgConfigModalApp`, `#awg-config-modal`, fetch `/awg-configs`), register in `inbounds.html:922`.
  QRious encodes the AmneziaWG `.conf` the same way.
- **Bulk TXT/PDF.** Add `AWG:'awg'` to `Protocols`, an `isAwg` flag (`export.js:54`), and a
  `buildCards` branch mirroring `isWgc` (`export.js:109-120`) that calls `_fetchConfigs(id, email,
  'awg-configs')` with `qr`/`configText = dev.config`. Add cases to `_protocolLabel` (~`:215`),
  `_isVpnProto` (`:188`), and `_psk` (if PSK kept). The TXT and PDF renderers need no changes.
- **Single-client button.** Clone `showWgcConfig` -> `showAwgConfig` and the dedicated per-row QR
  button (`aClientTable.html:22,195-198`); AmneziaWG, like `wg-c`, does not use the shared link
  modal (`dbinbound.js hasLink()` default false).
- **Identity = email throughout** (filename, fetch key, card title), same as `wg-c`.
- **A client must be an AmneziaWG-aware app** (the Amnezia AmneziaWG app for Android/iOS/Windows,
  the Amnezia VPN app, WG Tunnel on Android, DefaultVPN on iOS). Standard WireGuard apps reject
  configs carrying the obfuscation lines. The config modal should say so.

---

# Part 7 - Frontend UI (inbound form, obfuscation params, client, dashboard, core settings)

Confirmed: the add/edit flow mirrors `wg-c`. The obfuscation params are per-inbound, so they live
in a new `AwgSettings` class + `form/awg.html`; the client side needs only a dispatch case.

**Model (`web/assets/js/model/inbound.js`), clone `WgcSettings` (`:4235-4309`):**
- `Protocols.AWG:'awg'` (`:18`) + `ProtocolLabels['awg']:'AmneziaWG'` (`:43`). The dropdown is
  `v-for p in Protocols`, so this auto-adds the entry; the display label "AmneziaWG" satisfies the
  uppercase-casing requirement, matching "WireGuard (C)" / "OpenConnect (cisco)".
- New `AwgSettings` = `WgcSettings` fields plus `jc, jmin, jmax, s1, s2, h1, h2, h3, h4` (and,
  forward-compat for 2.0: `s3, s4, i1..i5` kept in the model but hidden until the module supports
  them). Keep the exact `?? default` / `Array.isArray` guards.
- New `AwgUser` = `WgUser` verbatim, INCLUDING `get id(){return this.email}` (`:4353`) - without
  it, edits POST to `/updateClient/undefined` (the `panel-client-id-getter` footgun that shipped
  `wg-c` broken in v1.4).
- Dispatch cases: `get clients()` (`:1676`), `getSettings()` (`:2425`), `fromJson()` (`:2450`).

**Inbound form (`web/html/form/protocol/awg.html`), clone `form/wgc.html` head verbatim** (IP
Range, DNS1/2, MTU, User Limit, Strategy, Client-to-Client, Cross Inbound, Preshared Key, Server
Public Key, External Proxy), then add the obfuscation section. Per the antd-vue 1.7.8 gotchas
(a-space has no wrap; bare a-row is float grid), and mirroring the openvpn.html Ciphers panel
(`:156-207`):
- An **`a-collapse` "Obfuscation" panel** (16 numeric fields stacked full-width would be far too
  tall).
- Inside, `a-divider orientation="left"` group headers: "Junk packets" (Jc/Jmin/Jmax), "Padding"
  (S1/S2), "Magic headers" (H1-H4, read-only if backend-minted, with a Regenerate button).
- The multi-column grid uses `<a-row type="flex" :gutter="8">` + explicit `<a-col :xs="12"
  :md="8">` per field (NOT bare a-row, NOT a-space), each an `a-input-number` for Jc/Jmin/Jmax/
  S1/S2 with the ranges from the table above, and read-only `a-input` for H1-H4.
- A **"Generate recommended" button** that fills randomized in-range values (the equivalent of the
  fork's `GenerateAmneziaParams()`), so an operator gets a working obfuscated inbound in one click
  while still being able to see and edit every parameter (satisfies "every mode and obfuscation in
  the add/edit inbound").
- Wire the form include in `inbound.html` (clone `:599-602`), the port tooltip (clone `:107-114`),
  `onProtocolChange` default port (clone `inbound_modal.html:409-410`, default 51821 per OPEN
  DECISION 3), and an `awgExternalProxy` computed (or reuse the shared `vpnExternalProxy`).

**Client add/edit.** The shared `form/client.html` needs NO structural change (AmneziaWG accounts
are email-identity and show only the shared quota fields, like `wg-c`). Add dispatch cases only:
`client_modal.html addClient` (`:143-146`), `client_bulk_modal.html addClient` (`:351-352`). If
per-client junk-count overrides are ever wanted, add a `v-if Protocols.AWG` block modeled on the
MTProto client block (`form/client.html:314-521`) - not needed for v1.

**Dashboard Overview "VPN Services" card (`web/html/index.html`).** The card already wraps text
natively (a raw flex div with `whiteSpace:'normal'; wordBreak:'break-word'`, `:99-102`), so the
AmneziaWG label wraps automatically with no layout work. Two edits only: add `'awg'` to the
`order` array (`:1276`, right after `'wgc'`) and `awg:'AmneziaWG'` to `coreLabel()` (`:1282`).

**Core Settings panel (`web/html/core.html`).** Cards render automatically from the shared status
endpoint once `GetCoresStatus()` includes AmneziaWG. Two edits: `coreTitle()` (`:629`, add
`awg:'AmneziaWG'`) and `coreBackend()` (`:633`, add `awg:'AmneziaWG (kernel)'`, mirroring
`wgc:'WireGuard (kernel)'`). Controls/logs/version/missing-alert are all automatic.

---

# Part 8 - Backend status registration (dashboard + core settings source)

The dashboard card and Core Settings panel both render off `CoreService.GetCoresStatus()`. Mirror
every `wgc` spot in `web/service/core.go`:
- Service field on `CoreService` (`:118`): add `amneziawgService AmneziawgService`.
- Master status list (`:307-322`, `wgc` at `:317`): add `s.amneziawgStatus(),`.
- `amneziawgStatus()` (clone `wgcStatus()` `:517-536`): `Name:"awg"`, inbounds count, module
  availability check, module version, running/idle/stopped/not_installed state.
- `RestartCore` (`:728`), `RestartAll` list (`:748`), `StopCore` (`:781`), `CoreLogs` (`:813-821`,
  synthetic in-kernel log text like `wg-c`).

CoreStatus/CoreState structs and the controller routes are reused unchanged.

---

# Part 9 - Account management / control plane

Clone the `wg-c` control plane (`web/service/wgc.go`) into a new `web/service/awg.go` with an
`AwgService`:
- Service struct, `awgSettings` (the `wgcSettings` fields + obfuscation params), `awgClient`
  (= `wgcClient`), `awgExternalProxy`.
- Interface lifecycle (`ensureLink` with the `amneziawg` link kind), `reconcilePeers`
  (incremental, `ReplacePeers:false`, hot-add without restart), `buildPeers`, `GenerateAllConfigs`,
  `removeStaleLinks`.
- Key reconciliation (`ReconcileKeys`/`ReconcileAllKeys`) plus **obfuscation-param reconciliation**
  (mint H1-H4 unique-in-range on first save if empty, default Jc/Jmin/Jmax/S1/S2 to recommended if
  unset), operating on raw JSON to preserve unknown UI fields.
- `rbridge.Adapter` (`Protocol()="awg"`, `Poll`, `Limit`, `Evict`), `SetupRouting`.
- Controller dispatch: `onAwgChanged`/`onAwgClientChanged` -> `awgChanged` (clone
  `inbound.go:314-329`), wired into add/update/del inbound + add/update/del client + reset-traffic
  switches (`inbound.go:476,524,692,769,823,883,929,960,987`). Both paths run the cheap sequence
  `AutoExpandVpnRanges("awg")` -> `ReconcileAllKeys` -> `GenerateAllConfigs` -> `SetupRouting` ->
  `SetToNeedRestart`.
- Startup init `InitAwg()` from `web.go:336` + service field on the web server.
- `isVpnProtocol` (`inbound.go:364-366`), `isVpnProtocol` guards in add/update/del
  (`inbound.go:600,1102,1539`).

---

# Part 10 - E2E harness (identical to wg-c)

AmneziaWG runs the generic tunnel path with the same gateway-model NA overrides as `wg-c`
(user-limit, strategy, and multi-user-total are NA under one-keypair-per-account) plus psk-mode.

**Phase registry + dispatch:**
- `model.py`: `PHASE_AWG="awg"` (mirror `:128`), add to `ALL_PHASES` (`:180`).
- `orchestrator.py`: `"awg":"AWG"` in `_PHASE_TAG` (`:44`), add `awg` to `need_clients` (`:152`)
  and the tunnel-proto loop (`:259`).
- `protocols.py`: `from .clients import awg as awg_mod`; add `awg` to `PEER`/`PHASE`/
  `_SECOND_VARIANT`/`_connect`/`_disconnect`; widen every `if proto == "wg-c":` to
  `in ("wg-c","awg")` (user-limit NA `:1179`, strategy NA `:1294`, multi-user-total NA `:1336`,
  psk-mode `:1309`).

**Server setup (`server_setup.py`):** `BASE`: `"awg": 8`; `AWG_USER_LIMIT = 6`; `SECOND_PORTS:
{"awg": {"udp": 51823}}`; build primary + second inbound (clone the `wg-c` blocks `:653-685`,
`:245-259`) INCLUDING obfuscation settings; widen the power-of-two `client_ip()` branch
(`:389-395`) to `in ("wg-c","awg")`; **add `"awg"` to the fatal "did any inbound build" list
(`:875-876`)** or an awg-only run is wrongly a total failure.

**Checks + teardown (the two "literally the same" allowlists):**
- `checks.py`: add `"awg"` to `tunnel_egress` ifaces (`:15`) and `_tunnel_dns_state` (`:74-75`) or
  tunnel-egress and dns-leak FAIL.
- `base.py`: add `awg-quick down awg; ip link del awg` to `disconnect_all()` (`:200`).

**Client module `clients/awg.py`** (clone `clients/wgc.py`): `IFACE="awg"`, write config to
`/etc/amnezia/amneziawg/awg.conf`, rewrite `Endpoint`, `awg-quick up awg`, wait for iface, apply
DNS, confirm a handshake via `awg show awg latest-handshakes` (`_recent_handshake` reusable
verbatim). `ok=True` only after a real handshake, so disable/quota enforcement stays observable.

**Client tooling (DECIDED, OD4): kernel module on the client VMs too.** AmneziaWG is not in
Ubuntu 26 apt, so the Ubuntu-26 client VMs build the same `amneziawg` module via DKMS (from the
same vendored source, or `amneziawg-dkms` from the Amnezia PPA), keeping the E2E kernel-based and
faithful on both ends. No userspace in the test tree.

**Host-side model test:** add an `AwgUser` case to `export_test/model.test.js` (`:45-53`, mirror
the `WgUser` case) so `.id===email`, id-follows-rename, and the add-path are covered (guards the
`get id()` footgun host-side, where the panel E2E cannot catch it).

Shared phases (usage/multiplier/termination, bulk/backup, multi-inbound, routing) pick AmneziaWG
up automatically once it is in `sc.inbounds` and the registrations above are in place.

---

# Requirements coverage (your checklist)

| Requirement | Where addressed | Status |
|---|---|---|
| Solution A for the kernel | Parts 1-3 (vendored source + on-target DKMS) | Locked |
| "AmneziaWG" uppercase like others | Part 7 (`ProtocolLabels['awg']='AmneziaWG'`) | Covered |
| Overview VPN Services card (wrap text) | Part 7 (card already wraps; 2 edits) | Covered |
| Core Settings | Parts 7-8 (`coreTitle`/`coreBackend` + status row) | Covered |
| Bundled with the binary | Part 2 (submodule -> `.tgz` -> `go:embed`) | Covered |
| Needs a kernel module? | YES, `amneziawg.ko` via DKMS (Parts 1-3) | Answered |
| Multi-inbound | Part 4 (id-derived iface/port/block) | Free |
| Client-to-client | Part 4 (nft `writeClientToClientRules`) | Free |
| Cross-inbound | Part 4 (nft `writeCrossInboundRules`) | Free |
| Xray-core routing | Part 4 (`BuildVpnEmailToIPMap` + dokodemo) | Free* |
| User limit | Parts 4, 0-decision 7 (gateway model K) | Free |
| User limit strategy | Part 4 (rbridge sweep, inert under gateway) | Free |
| Speed limit | Part 4 (sidecar source-IP->email, same map) | Free* |
| Traffic multiplier | Part 4 (Inbound columns, accounting layer) | Free |
| External proxy | Parts 4, 6 (`awgSettings.ExternalProxy`) | Free |
| Config/QR/TXT/PDF | Part 6 (clone route+modal, `export.js` branch) | Covered |
| Panel account management | Part 9 (clone `wg-c` control plane) | Covered |
| build.sh compatible | Part 2 (embed rides existing cgo build) | Covered |
| E2E, same as others | Part 10 (clone `clients/wgc.py`, same phases) | Covered |
| Style/flow like wg-c | Confirmed: it IS the `wg-c` clone | Confirmed |
| Every mode/obfuscation in add/edit | Part 7 (all AWG 1.0 params + generate) | Locked: AWG 1.0 |

\* "Free" for routing and speed limit is gated on the single must-not-miss wire: adding `awg` to
`BuildVpnEmailToIPMap`. Miss it and both silently break.

---

# Proposed phasing

Build/verify gate at each step: `./build.sh` (never bare `go build`) + `go test ./web/...
-count=1` green. Never auto-run incus E2E (author only; project rule).

- **Phase 0 - feasibility gate.** DKMS-build + load `amneziawg` on one box; create a `type
  amneziawg` link from Go; configure it (keys, port, peer, obfuscation params) with the
  `Jipok/wgctrl-go` fork; connect a real AmneziaWG client; confirm handshake + traffic through
  TPROXY -> Xray. Add + pin the fork. This proves the load-bearing unknowns.
- **Phase 1 - bundling + provisioning.** `third_party` submodule + `amneziawg-bundle.sh` +
  staleness gate + `backend/amneziawg.go` embed/extract. `ensureAmneziawg()` DKMS step +
  `KernelHeadersPackage()` + `ensureEpel()` + toolchain resolvers. Warn-and-degrade status.
- **Phase 2 - addressing.** `protocolBase` case 8, **`vpnAddrSpace` -> `/12`**, `usedVpnSubnets`/
  `normalizeRanges`/`maxVpnAccounts` branches.
- **Phase 3 - core service + Go wiring.** `web/service/awg.go` (device lifecycle, peers,
  `GenerateAllConfigs`, dokodemo, tproxy, SetupRouting, rbridge adapter, key + obfuscation-param
  reconcile). Wire `core.go` (status/restart/stop/logs/provision), `xray.go`, `nftables.go`,
  `vpnrange.go`, `radius.go` (`BuildVpnEmailToIPMap` + `ReconcileLocalSessions`), `inbound.go`
  controller dispatch, `web.go`, `xray_traffic_job.go`.
- **Phase 4 - UI.** `Protocols.AWG` + label, `AwgSettings`/`AwgUser` JS, `form/awg.html` (with the
  obfuscation `a-collapse` + generate button), `inbound.html` include + port tooltip,
  `onProtocolChange`, client-modal + bulk-modal dispatch, `awg_config_modal.html`, `export.js`
  branch, dashboard card + core-settings labels, i18n keys.
- **Phase 5 - E2E.** `PHASE_AWG`, `clients/awg.py`, all `server_setup.py`/`orchestrator.py`/
  `protocols.py` registrations, the two `checks.py` allowlists, `base.py` teardown,
  `model.test.js` case, client tooling per OPEN DECISION 4. Never auto-run.
- **Phase 6 - live verify** on a real box with real AmneziaWG clients (mobile app QR import,
  desktop), across at least one Debian-family and one EL-family and Arch to exercise the DKMS
  paths.
- **Docs + release:** all-language READMEs, flowchart, `--tests awg`, tested-OS table, version
  bump, `gh release create` (draft until the 199MB asset upload is confirmed; release notes
  mention the in-panel updater).

---

# Key files (from recon - re-verify line numbers before editing)

- Clone target: `web/service/wgc.go` (whole file), `web/controller/inbound.go` (dispatch +
  `getWgcConfigs` `:1345`), `web/assets/js/model/inbound.js:4235-4403`,
  `web/html/form/protocol/wgc.html`, `web/html/modals/wgc_config_modal.html`,
  `test_unit/harness/clients/wgc.py`.
- Data plane: `web/service/xray.go:287-478`, `web/service/nftables.go:22,52-75,300,450-465,
  518-520,775-779`, `web/service/vpnrange.go:137-155,278-298,696-740,790-822`,
  `web/service/speedlimit.go:210-215,270-283,313-393,538`, `web/service/radius.go:516-558,
  1352,1410-1425`, `web/service/trafficmultiplier.go`, `web/job/xray_traffic_job.go:59,89,112`.
- Bundling/provisioning: `build.sh:47-89`, `build/backend/{build.sh,libreswan-bundle.sh,
  telemt-bundle.sh}`, `backend/{backend.go,libreswan.go}`, `corebundle/corebundle.go`,
  `.gitmodules`, `.gitignore`, `web/service/{core.go:21-54,307-322,517-536,648,875-1043,1061},
  pkgmgr.go:32-97,116-170,327-350,476,569-591}`, `web/service/bootloader.go`, `web/service/
  warpsocks.go:83-155`.
- Frontend/dashboard/core: `web/html/form/inbound.html:22,107-114,599-602`,
  `web/html/form/protocol/openvpn.html:156-207` (obfuscation-panel pattern),
  `web/html/modals/{inbound_modal.html:207-234,386-420,client_modal.html:143-146,
  client_bulk_modal.html:351-352}`, `web/html/index.html:97-107,1276-1287`,
  `web/html/core.html:107-162,629-633`, `web/assets/js/util/export.js:54,109-120,171-180`,
  `web/html/component/aClientTable.html:22,195-198`.
- E2E: `test_unit/{run.sh,config.toml}`, `test_unit/harness/{model.py:128,177,orchestrator.py:44,
  152,259,protocols.py,server_setup.py:25,60,131,389,653,875,checks.py:15,74,base.py:200,17}`,
  `test_unit/harness/clients/{wgc.py,ssh.py:45-101}`, `test_unit/export_test/model.test.js:45`.

---

# External references

- AmneziaWG docs: https://docs.amnezia.org/documentation/amnezia-wg/
- Kernel module (1.0 params, DKMS): https://github.com/amnezia-vpn/amneziawg-linux-kernel-module
- 2.0-in-kernel status (PR #165, master is 1.0): https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/issues/169
- AmneziaWG-aware wgctrl fork: https://pkg.go.dev/github.com/Jipok/wgctrl-go
- amneziawg-tools (awg / awg-quick, for the client + optional server CLI): https://github.com/amnezia-vpn/amneziawg-tools
- Official COPR (EL/Fedora reference builds): https://copr.fedorainfracloud.org/coprs/amneziavpn/amneziawg/
- Param ranges/constraints (wg-easy reference): https://wg-easy.github.io/wg-easy/v15.3/advanced/config/amnezia/
