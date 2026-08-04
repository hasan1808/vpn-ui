# GRE - research and feasibility assessment

Can **GRE** (Generic Routing Encapsulation, IP protocol 47) be added as a new protocol?
(It shipped as the 11th, after l2tp, pptp, openvpn, openconnect, sstp, ikev2, wg-c, awg,
mtproto and ssh.)
This document is the research record, produced from a 9-agent codebase recon (touch points,
accounts/auth, data plane, existing GRE plumbing, provisioning/bundling, frontend,
subscription layer, controller layer, E2E) plus a live kernel spike and web research.
Mirrors the style of `ssh-plan.md` / `amneziawg-plan.md` / `wireguard-plan.md`.

STATUS: **BUILT 2026-07-30** as the 11th protocol, base 9 (10.9/16). The research below stands
except where the "As built" section at the end corrects it: several of its assumptions were
tested against the real kernel during implementation and three came back different.

---

## The framing that matters: GRE is a ROUTER protocol

**GRE's customer is a router, not a phone.** That is the correct framing, and it changes the
answer. Nearly every router ships GRE, including cheap and old ones; some support GRE while
lacking L2TP or PPTP, and most lack WireGuard unless the firmware is recent. So the "no client
exists" objection, which is fatal for a phone product, does not apply here at all.

Two consequences fall out immediately, and both are favourable:

1. **User Limit K=1 stops being a limitation and becomes the correct model.** One router is one
   account is one tunnel. The customer's LAN sits behind it, source-NAT'd by their own router
   to its single tunnel IP. From the panel's side that is exactly one address per account,
   which is what every existing subsystem (accounting, speed limit, routing rules, reseller
   billing) already keys on. Nothing has to be weakened to accommodate it.
2. **The customer's public IP is static and known**, because that is how site-to-site tunnels
   are always deployed. That collapses the hardest part of the design (see Part 4): with a
   fixed remote there is no peer to learn, so no NFQUEUE, no conntrack, no packet sniffer, no
   `ip neigh` bookkeeping. **Verified working end to end.**

What remains genuinely true about GRE, and must be handled rather than hand-waved:

- **No encryption.** Every byte is cleartext. This is the one real problem, and it has a real
  answer for router customers: GRE over IPsec is a standard, well-documented MikroTik recipe,
  and this panel **already bundles strongSwan charon** for IKEv2 and L2TP. See OD2.
- **No ports**, so it is IP protocol 47. A router that is itself the NAT device originates GRE
  fine; the failure case is a customer behind CGNAT, who cannot use this at all.
- **Trivially filtered**, being one well-known protocol number with no obfuscation. One source
  reports GRE is among the tunnelling protocols dropped in Iran. Weigh this against your own
  market knowledge; it is the strongest remaining argument against.

So the question is no longer "is there a client". It is **which multiplexing scheme**, and
**whether the encryption gap is closed**.

---

## Part 0 - The multiplexing problem, and why it decides the design

One server IP must host many router customers. How you tell them apart is the single most
important design choice, and it is constrained by what routers can actually do.

**The GRE key (RFC 2890) is the obvious answer, and MikroTik cannot use it.** Setting a key
lets many tunnels share one `(local, remote)` pair. But RouterOS plain GRE exposes no key
field: it has been an open feature request since at least 2015 and was still being asked for
in 2023. Only MikroTik's proprietary **EoIP** carries one, as `tunnel-id`. Since MikroTik is
the dominant router in this market, **a key-based design excludes the main audience.**
OpenWrt does support `ikey`/`okey`, as do Cisco (`tunnel key`) and most enterprise gear.

**So the base design must demultiplex by customer source IP, not by key.** That is exactly
what classic point-to-point GRE does, it works on every platform including MikroTik, and it
needs no key at all. The cost is that each account needs a static customer IP.

Corroborated by what the router UIs actually expose. The typical field set is:

```
IP Address            <- the router's own WAN address (our "remote")
Peer IP Address       <- our server's address       (their "remote")
Local Tunnel Address  <- their inner address
Local Tunnel Netmask
```

Four fields, **no key field anywhere**. That is textbook point-to-point GRE and it maps exactly
onto `ip link add greN type gre local <server> remote <customer>` plus an inner address on our
side. It also confirms the customer is expected to know and enter a fixed peer address, which
is the assumption the whole static design rests on. Keenetic is a documented example of a
consumer platform shipping IPIP/GRE/EoIP, optionally combined with IPsec.

The alternatives, for completeness:

- **EoIP** (MikroTik-native, keyed by tunnel-id, tolerates dynamic customer IPs). Wire format
  is GRE with flags `0x2001` and protocol type `0x6400`, which stock Linux `gretap` (type
  `0x6558`) is **not** compatible with. Terminating it needs third-party code, of which there
  is plenty: userspace TAP implementations (`amphineko/eoiptapd`, `chrisandreae/meoip`,
  `Nat-Lab/eoip`) and kernel modules (`bbonev/eoip`, `inste/eoip-linux`, `ndmsystems/eoip-kernel`),
  plus a Debian ITP. But EoIP is **L2**, i.e. bridging the customer's LAN to the server, which
  is the wrong shape for a routed VPN exit and would drag in a new out-of-tree module or a
  userspace packet copy.
- **L2TPv3.** MikroTik added it in RouterOS 7.1, and Linux has native `l2tp_eth`/`ip l2tp` with
  `tunnel_id`/`session_id`, so **both ends are in-kernel and it multiplexes cleanly without
  needing static IPs**. Genuinely the most elegant option on paper. Caveats: L2 pseudowire
  semantics, RouterOS requires "unmanaged mode" plus "use L2 specific sublayer" against Linux,
  MikroTik does not support its simple IPsec mode for L2TPv3-to-Linux, and it would sit
  confusingly beside the panel's existing PPP-based L2TPv2. Worth a look, but it is a different
  protocol, not GRE.
- **IPIP.** Even simpler than GRE and widely supported, but no key at all, so it multiplexes
  strictly worse.

**Recommendation: plain point-to-point GRE keyed on source IP as the base**, with optional
`ikey`/`okey` support for platforms that have it (which additionally buys dynamic-IP tolerance
and multiple tunnels per customer). The spike confirms a keyed remote-any device coexists with
per-account point-to-point devices on the same local IP, so the hybrid is available later
without redesign.

---

## The three shapes, and what each costs

### Shape A - per-account GRE inbound (a real 12th protocol) - RECOMMENDED

One account is one router. Reuses roughly 90% of the existing machinery, with K=1 as the
natural model rather than a compromise. Details in Part 3. Requires a static customer IP, and
needs OD2 (encryption) answered.

### Shape B - accountless site-to-site inbound (Tunnel-shaped)

Sits in the existing `model.Tunnel` (dokodemo) slot: no `clients[]` array, billed purely on
the inbound's own `Up/Down/Total/ExpiryTime/Enable`. Verified to be a real, working, shippable
shape today, not a degraded corner. But it is **architecturally unsellable by resellers**:
every reseller charge/ownership path keys on `(inboundId, email)` and `ResellerClient.Email`
is a unique column, so there is no whole-inbound sale path anywhere. Admin-only, forever.

### Shape C - server-to-server transit / uplink (recommended if the goal is the Iran bridge)

A new small subsystem, not an extension of an existing one. This is the shape that matches
what the market actually buys. Details in Part 6.

---

## Part 1 - What I verified directly (live kernel spike)

Run locally in a netns (`unshare -rn`), kernel 7.1.5, iproute2 7.1.0, plus a throwaway Go
program against the repo's pinned `vishvananda/netlink v1.3.1`. These were the load-bearing
unknowns and all of them came back GREEN:

1. **A keyed remote-less GRE tunnel is effectively a listener.**
   `ip link add greN type gre local <SERVER> key K` (no `remote`) yields
   `gre remote any local <SERVER> ... ikey K okey K`. One netdev accepts GRE from **any**
   source IP, demultiplexed purely on the key. This kills the obvious objection that you
   would need each client's static public IP in advance. You do not.
2. **The kernel enforces key uniqueness.** A second device with the same
   `(local, remote=any, ikey, okey)` tuple is rejected with `EEXIST`, even under a different
   interface name. So the GRE key is a collision-free per-account handle by construction, and
   a bad hot-add fails cleanly and detectably.
3. **`netlink.Gretun` does all of this from Go, and sets the GRE_KEY flags for you.**
   Setting `IKey`/`OKey` causes the library to OR in `nl.GRE_KEY (0x2000)` on `IFlags`/`OFlags`
   during `LinkAdd`. The classic "key set but flag missing, so the key is silently ignored"
   footgun does **not** apply here. Confirmed by round-tripping through `ip -d link show`.
4. **A real footgun that does apply: `PMtuDisc`.** `addGretunAttrs` sends `IFLA_GRE_PMTUDISC`
   unconditionally with no nil-guard, so a zero-value `Gretun{}` explicitly disables PMTU
   discovery, which is the **opposite** of the `ip` CLI's own default. It must be set to `1`
   explicitly if PMTUD-on is wanted.
5. **The device is NOARP and needs a learned return path.** `ip neigh add <inner-ip> lladdr
   <client-public-ip> dev greN` maps inner to outer. Linux does not auto-learn this; NHRP
   daemons do it in userspace. This is the single hardest new piece of work (Part 4).
6. **GRE-over-FOU/GUE (UDP encapsulation) is supported** by both the kernel and the pinned
   library (`EncapType`/`EncapSport`/`EncapDport`, plus a separate genl `FouAdd`/`FouDel` API).
   Creation fails with `EINVAL` if the `fou` module is not loaded, so `modprobe fou` must
   happen before `LinkAdd`. This is the concrete route to NAT traversal, since raw protocol 47
   has no ports for a NAT to rewrite.
7. **Per-tunnel byte counters exist** via both `netlink.LinkByName(...).Attrs().Statistics`
   and `/sys/class/net/<dev>/statistics/{rx,tx}_bytes`. MTU defaults to 1472 keyed, 1476
   unkeyed.

---

## Part 2 - What already exists in the repo

**Zero GRE plumbing today**, but the surrounding machinery is generic and would pick it up
nearly free:

- `ip_gre` and `nf_conntrack_pptp` are **already required and provisioned** for PPTP
  (`web/service/core.go:24-25`, `corecatalog.go:108`, `pptp.go:285-286`). A GRE netdev needs
  the same `ip_gre`, so the cross-distro kernel-module pipeline (`pkgmgr.go:558-591`, the
  Ubuntu/Debian/RHEL/openSUSE/Arch package table) needs **no new code at all**.
- `vishvananda/netlink v1.3.1` is already a dependency and already used to create interfaces
  from Go in exactly the pattern needed (`wgc.go:502-518`, `awg.go:506-511`).
- **Base 9 is free.** `protocolBase()` (`vpnrange.go:137-157`) has 0 l2tp, 1 pptp, 2 openvpn
  UDP, 3 openvpn TCP mirror, 4 openconnect, 5 sstp, 6 ikev2, 7 wg-c, 8 awg. `vpnAddrSpace` is
  `10.0.0.0/12` (`nftables.go:25`), so bases 9-15 fit with no widening.
- **No nftables rule anywhere matches protocol 47.** Every TPROXY rule is `ip protocol tcp`
  or `udp`. That is fine, because the kernel decapsulates GRE before nftables sees the inner
  packet, exactly as it already does for PPTP. But there is also no precedent for a
  protocol-47 rule, and no firewalld `--add-protocol` plumbing exists (the panel only ever
  does `--add-source` for the VPN address space).
- **`wg-c`/`awg` prove the shape**: a daemon-less, pure kernel/netlink protocol is fully
  supported. Neither touches `procmgr`; status is derived by probing the module and interface
  (`core.go:552-601`). The whole `backend/` bundling layer, `build.sh`, and `corebundle/` are
  **skipped entirely** for such a protocol.

---

## Part 3 - Does a stateless protocol fit the account model?

This was the decisive question, because every other protocol has either a RADIUS round-trip
or a cryptographic handshake to hang identity on. GRE has neither. The answer is better than
expected:

- **Disable / quota / expiry: works with no session concept.** This is not actually enforced
  by rbridge for wg-c/awg either. `xray_traffic_job.go:111-117` calls `GenerateAllConfigs()`
  *before* the sweep, and that function (`wgc.go:329-389`) reads `client_traffics.enable` plus
  `settings.Clients` from the DB and reconciles kernel state to match. A disabled account has
  no peer by the time anything polls. A GRE equivalent (create/destroy netdevs from DB state
  each tick) gives identical hard enforcement with zero session concept.
- **Traffic accounting: works with no session concept.** `AddClientAccounting` /
  `CollectAndResetTraffic` (`nftables.go:610-676`, `719-789`) are pure address-match
  primitives; the only session dependency is the final ip-to-email lookup, and that map does
  not have to come from `RadiusService.GetSessions()`. `BuildVpnEmailToIPMap`
  (`radius.go:1364-1507`) is already **purely static** - it computes each account's
  deterministic IP from `Client.Slot` and the inbound's ranges. Adding `"gre"` to its protocol
  list is a one-line change.
- **Online / last-seen: works for free.** "Online" already means, for every protocol,
  "this email's counter moved during the last tick" (`inbound.go:2530-2557`). Interface byte
  deltas satisfy that exactly as credibly as L2TP does.
- **TPROXY, client-to-client, cross-inbound, routing rules, speed limit: all work unchanged.**
  Confirmed by grep: **not one rule in `nftables.go` matches on `iif`/`oif`/`iifname`** - every
  rule is `saddr`/`daddr` plus `meta mark`. Inner GRE traffic is plain TCP/UDP from `10.9.x.x`
  and is indistinguishable from ppp0 or wg0 traffic at the mangle hook. The claim that
  decapsulated tunnel traffic re-enters `prerouting` is not an assumption: all eight existing
  tunnel protocols' TPROXY rules already depend on exactly that behaviour, in production,
  across the validated distro matrix. GRE's driver is architecturally the same shape as
  ppp/tun/wg here. Still worth a one-line counter-rule check in the netns rig before building.
- **MTU: no worse than what already ships.** GRE has no MTU negotiation, so the client guesses.
  That is precisely the category wg-c and awg already occupy (they only set the server netdev's
  MTU, default 1420; WireGuard the protocol has no MTU field). The PPP protocols negotiate via
  LCP, OpenVPN and ocserv push a value. There is **no TCPMSS or clamp-mss rule anywhere in the
  repo** (grepped: the only "clamp" hits are unrelated reseller quota arithmetic). GRE would be
  the third protocol sharing an existing, unaddressed gap, not a new one. A single generic
  clamp-mss-to-pmtu rule would fix wg-c, awg and GRE at once, and is worth doing on its own
  merits.
- **User Limit K > 1: does not fit, and cannot be made to fit cheaply.** The only per-device
  discriminator GRE offers is the client's outer public IP. That is exactly the known,
  documented OpenConnect/SSTP degenerate case (`radius.go:1099-1118`: two devices behind one
  NAT collapse to one session) **minus** their one mitigant, since those at least get a
  discrete auth event per device and GRE gets no event at all. Building it would mean new
  nftables dynamic-set machinery that exists nowhere in this codebase, and even then only
  reject-only, never accept-evict-oldest.

**Verdict for Shape A: viable with K pinned to 1**, documented as unsupported rather than
half-built. That buys full reseller-sellability, subscription cards, billing, and per-user
speed limits, because all of those key on email, not on any live session.

---

## Part 4 - The return path: solved by the router framing

**In the recommended static-remote design there is no return-path problem at all.** Verified
in the netns rig: two mirrored point-to-point tunnels
(`ip link add greA type gre local <server> remote <customer> ttl 64`, and the mirror on the
client) passed a real ping 2/2 with 0% loss and 0.025ms average, with **no `ip neigh` entries,
no NFQUEUE, no conntrack and no packet sniffer**. The kernel knows the remote because it was
configured. Multiple such tunnels to different remotes coexist on one server IP, and a
duplicate `(local, remote)` tuple is cleanly rejected with `EEXIST`.

That deletes what was previously the largest risk in this plan, and it deletes the need for
any new dependency.

**The learner is only needed if you later support dynamic customer IPs** via the keyed
remote-any variant. Keeping the options here for that case, in order of preference:

- **Raw `AF_PACKET` sniffer (recommended).** Passive, copy-only, no verdict, so it adds no
  latency and no failure mode to live traffic. `golang.org/x/net` is already an indirect
  dependency (`go.mod:99`), so `x/net/bpf` plus a raw socket crosses no new module boundary.
  You hand-parse the GRE header (4-8 fixed bytes) and the inner IPv4 header, which is trivial.
  Crucially it is the **only** option that yields *both* the GRE key and the outer source IP,
  which is exactly the pair needed to map a packet to an account.
- **Conntrack via netlink.** Superficially the cheapest: `vishvananda/netlink v1.3.1` (already
  linked) ships `ConntrackTableList` and `ConntrackFilter.AddProtocol(47)`, and the GRE tracker
  turns out to be compiled **into** `nf_conntrack.ko` rather than being a separate module
  (verified: `gre_pkt_to_tuple` is an exported symbol inside it), so it is active whenever
  conntrack is. **But it probably does not carry the key.** The keymap machinery
  (`nf_ct_gre_keymap_add`) is driven by the PPTP helper, and the tracker falls back to generic
  handling for non-PPP GRE, which zeroes the tuple's port fields. If that holds, conntrack
  gives you "someone is sending GRE from IP X" but **not which account**, making it useless
  here on its own. NEEDS EMPIRICAL VERIFICATION before anyone builds on it; I read the header
  and symbols but did not generate real GRE traffic through a conntrack table.
- **NFQUEUE.** Correcting the record: this codebase **did** ship an NFQUEUE responder, in
  v1.7.4 (`c9e9fe29`), and reverted it in v1.7.5 (`1c9a0838`). The revert reasons were
  ICMP-specific (a server-side fabricated reply cannot hit sub-millisecond RTT, and is a
  latency fingerprint) and do not apply to a learner. But one lesson does transfer directly:
  the NFQUEUE rule was installed *before* `ApplyNftRules` flushes `prerouting`, so it was
  wiped on every regeneration. Any new nft rule must go in *after* the flush. Inherent
  downside: NFQUEUE is verdict-based and sits **in** the packet path, so it must be scoped
  narrowly or it becomes a new latency and failure point.
- **tc / eBPF with `gre external` (collect_metadata).** How OVS and Cilium do multi-tenant GRE
  at scale, and the right *send*-side primitive (`ip route ... encap ip id <key> dst <client>`
  beats juggling `ip neigh`). But its receive side is designed to be consumed by an eBPF
  program, and it needs BTF/CO-RE or a clang toolchain, which does not fit a single static Go
  binary. Heaviest lift, weakest fit.

**If you do go dynamic, note the learner is needed for client-to-client too**, not just for
internet-bound replies: traffic between two GRE accounts must be re-encapsulated out through
the *other* account's device, which needs that peer's current outer IP. wg-c never hits this
(one shared device, cryptokey routing picks the peer) and the PPP protocols never hit it
(their daemon owns the session), so there is no precedent to copy. In the static design this
is a non-issue: both remotes are already configured.

---

## Part 5 - Cost, measured against a real precedent

AmneziaWG was the **cheapest possible** new protocol here: a near-clone of the existing wg-c,
same gateway model, same kernel/netlink shape. Commit `8d9ed7e0` still touched:

- **52 non-vendored files, ~3,050 hand-written lines** (plus a vendored kernel module)
- ~23 Go files, ~15 frontend files, 1 new `form/protocol/<name>.html`, 1 new config modal
- **29 controller touch points** (`inbound.go` alone: one struct field, an `onXChanged` /
  `onXClientChanged` hook pair, six near-identical if/else-if dispatch chains, a bulk switch,
  three unconditional call-all sites)
- ~200-300 lines of E2E harness for a protocol reusing an existing shape

A full touch-point audit puts a **daemon-less, non-RADIUS protocol** (the wg-c/awg kernel
shape, which is what GRE would be) at roughly **90-110 discrete path:line edits across 33-37
existing files**, versus 220-230 for a worst-case daemon+RADIUS protocol. The floor is high
because the controller layer, the frontend, and core registration are almost entirely
shape-independent boilerplate:

- **Core registration alone needs the same new service field added to four separate structs**
  (`CoreService`, `App`, `XrayService`, `XrayTrafficJob`), plus switch cases in
  `RestartCore`/`StopCore`/`CoreLogs`.
- **`xray.go:208` and `:216`** carry the native-protocol skip-list as *two* literal
  occurrences; missing one means the whole core fails to boot.
- **`subService.go:140`** is a cross-cutting SQL allowlist: miss it and the protocol is
  invisible to every subscription endpoint.
- The frontend has **two duplicate "add a blank client" switches** (`client_modal.html` and
  `client_bulk_modal.html`) and a `getClientIdentity()` that must stay logically identical to
  Go's `clientIdentityKey()`, a pair that has drifted before.

A GRE inbound lands near the low end of that range, **plus** the return-path learner from
Part 4, **minus** all the `backend/`, `build.sh` and `corebundle/` work (daemon-less protocols
skip those entirely, and `corebundle/` is Xray-core plus geo only, never protocol-aware) and
minus any new i18n (the established convention hardcodes English in the new form partial; awg
and sstp each added zero new keys, and `mtproto.html` has no i18n calls at all).

---

## Part 6 - Shape C: GRE as transit, and why it does not fit "outbounds"

If the goal is the Iran-to-foreign-server bridge, this is the right shape, and it is **a new
subsystem, not an extension of an existing one**. The reason is specific:

`ssh` and `warp-cli` are panel-side facades that work because they stand up a local process
speaking a protocol Xray understands (SOCKS), and point a `socks` outbound at
`127.0.0.1:<port>`. **GRE has nothing for an outbound to dial.** Once the netdev exists it is
an ordinary kernel interface, indistinguishable from a NIC; Xray's existing `freedom` outbound
rides it automatically the moment the routing table sends traffic that way. Modelling it as a
synthesized socks outbound would be actively wrong.

There is also **no existing precedent for a kernel interface used purely for egress**: wg-c
and awg look similar but are inbound-side, and their decrypted traffic is deliberately fed
*back into* Xray via a paired TPROXY dokodemo inbound.

What it would need: a `coreSpec` catalog entry (kernel module already covered), a wg-c-shaped
status probe, a **new** fwmark + routing-table mechanism (not the TPROXY table), a settings-row
config store shaped like `sshOutbounds` (`sshoutbound.go:47-226`), and its own UI surface
("Network Tunnels" / "Uplinks"). It does not belong on the Outbounds tab, because half its job
happens below Xray and would be invisible there.

Confirmed: there is **no notion of a peer server anywhere in the codebase today**. Multi-node
was studied and never implemented; grep finds no `PeerServer`/`RemoteNode`/node service.

---

---

## Part 6b - Does unencrypted GRE behave like "L2TP raw"?

Asked because L2TP raw (no IPsec) demonstrably works in Iran today, and filtered sites resolve
and open through it. Short answer: **functionally identical, but strictly more exposed to DPI.**

**Why L2TP raw works, mechanically.** It is not encryption. `l2tp.go:250-256` pushes DNS
servers to the client (default 8.8.8.8/8.8.4.4). The client's query travels *through the
tunnel* as ordinary UDP/53, is TPROXY'd into Xray with everything else, and is resolved from
the server's vantage point. Iran's poisoned resolvers never see it. The DNS is **relocated,
not encrypted** - anyone on the path between client and server can read those queries in
cleartext today. Worth stating plainly so the property is not over-trusted.

**GRE would inherit this identically.** Confirmed: no nftables rule matches on `iif`/`oif`, so
a GRE-decapsulated packet with a `10.9.x.x` source hits the same TPROXY rule, the same Xray
instance, the same outbound. Same DNS behaviour, same sites open.

**But the encapsulation is much easier to see through:**

```
L2TP raw:  IP | UDP:1701 | L2TP hdr | PPP hdr | IP | TCP | TLS(SNI)
GRE:       IP | GRE (4 bytes)                 | IP | TCP | TLS(SNI)
```

Reading the inner SNI under L2TP raw means parsing UDP, then L2TP, then **PPP** - an awkward
stack many DPI engines never implement. Under GRE the inner IP packet is **four bytes in**, and
GRE decapsulation is standard in every DPI engine and most routers. A plausible reason L2TP raw
still works is precisely that PPP wrapping is annoying to parse; GRE removes that accidental
protection. If SNI filtering inside tunnels is ever enabled, GRE fails first.

GRE is also easier to block wholesale: one protocol number, no ports. L2TP raw at least rides
UDP, which NATs and transit paths handle normally.

**Cheap decisive test before building anything:** bring up one GRE tunnel from a real Iranian
endpoint to a live box and check whether protocol 47 arrives at all. If it does not pass, the
rest of this plan is moot. If it does, OD2 (IPsec) is what restores the inner-traffic
protection that L2TP's PPP wrapping currently provides by accident.

---

## Part 7 - A pre-existing bug found along the way (unrelated to GRE)

Worth fixing on its own merits, and a new protocol would inherit it as-is:

`hasDerivedXrayInbound()` (`inbound.go:680-682`) exists because a VPN/relay inbound's paired
dokodemo or socks inbound must not be live-patched: the Add path (`inbound.go:941-946`) and
the Update path (`inbound.go:1209-1214`) both check it and force a restart instead, with
identical comments explaining that the live del/add API would drop the derived inbound and be
unable to recreate it.

**`DelInbound` (`inbound.go:971-1019`) has no such check.** It unconditionally calls
`s.xrayApi.DelInbound(tag)` for any enabled inbound (line 986), and since the derived
dokodemo/socks companion carries that same tag, the call succeeds and leaves
`needRestart = false`. That is the asymmetric twin of the exact bug class the helper's own doc
comment describes. Not traced further: whether the controller routes VPN deletes down another
path, or whether a protocol's `on<Proto>Changed` heals it within a tick. Flagging it as a
precisely located gap, not a confirmed live defect.

---

## Part 8 - Open decisions needing sign-off

- **OD1. Which shape?** Recommend A (per-account router inbound). B (accountless) and C
  (operator transit) remain available and are not mutually exclusive with A.
- **OD2. Encryption. The one that actually matters.** Ship bare GRE with a blunt warning, offer
  GRE-over-IPsec via the already-bundled charon as an option, or require it? Recommend offering
  it, defaulting to on.
- **OD3. Multiplexing.** Source-IP point-to-point only (works everywhere including MikroTik), or
  also expose `ikey`/`okey` for platforms that support it (adds dynamic-IP tolerance and
  multiple tunnels per customer)? Recommend source-IP first, keys as a later additive option.
- **OD4. Dynamic customer IPs.** Out of scope for v1, or add a DDNS-style update endpoint so a
  customer can push their current IP? This is the main thing separating "business customers"
  from "everyone with a router".
- **OD5. MSS clamping.** GRE has no MTU negotiation and a whole LAN now sits behind the tunnel,
  which makes the existing repo-wide absence of any clamp-mss rule more consequential than it
  is for wg-c today. Mitigating factor: the router side can handle it itself (RouterOS exposes
  `clamp-tcp-mss=yes`, and `keepalive` for tunnel liveness, so a documented client-side recipe
  covers most of it). Still worth one generic server-side rule fixing wg-c, awg and GRE at once.
- **OD6. Is protocol 47 viable in your market at all?** The one question the research cannot
  answer for you.

---

## Recommendation

**Ship it as Shape A, a real 12th protocol, scoped to router customers.** With the router
framing the objections that would have killed a phone product do not apply, and the design
gets *simpler*, not harder:

- one netdev per account, `local <server> remote <customer-static-ip>`, no key required, so it
  works on MikroTik and essentially every other router
- **no learner, no new dependency, no packet-path code** - the single biggest risk in the
  original plan is gone, verified by a working ping across a real tunnel
- K=1 is the natural model rather than a compromise, because one router is one account
- the customer NATs their LAN behind one tunnel IP, so accounting, speed limits, routing rules
  and reseller billing all work through the existing email-keyed machinery unchanged
- `ip_gre` is already provisioned for PPTP, base 9 is free, and `wg-c`/`awg` already prove the
  daemon-less kernel-protocol shape

Cost lands at the low end of the 90-110 edit range, minus all the `backend/`, `build.sh` and
`corebundle/` work, minus the learner.

**Two conditions before this is a good product:**

1. **Close the encryption gap (OD2).** Plaintext to a censored country is hard to defend, and
   GRE-over-IPsec is a standard MikroTik recipe that the already-bundled charon can terminate.
   Offering GRE with an IPsec option is a materially better product than offering it bare.
2. **Be honest about the static-IP requirement.** Customers behind CGNAT cannot use this. That
   is a real segment limit, and the account form should ask for the customer's public IP as a
   first-class field rather than surfacing it as a mysterious failure.

**Also weigh, but do not treat as decisive:** one source reports GRE is among the tunnelling
protocols dropped in Iran, and protocol 47 is trivially filtered. If that is true in your
market today, IPsec-wrapped GRE or the L2TPv3 route may survive better than bare GRE. You know
this better than the search results do.

**Not recommended:** EoIP (needs an out-of-tree module or a userspace packet copy, and is L2),
and key-based-only multiplexing (excludes MikroTik).

## Sources

- https://www.azion.com/en/learning/network-layer/what-is-gre-tunneling/
- https://learn.microsoft.com/en-in/windows-server/remote/remote-access/ras-gateway/gre-tunneling-windows-server
- https://www.justanswer.com/computer-networking/2qcn6-set-gre-protocol-47-forward-vpn-port.html
- https://github.com/mazyaar/Gre_Tunnel_bash
- https://github.com/raminol12/6to4
- https://forum.mikrotik.com/viewtopic.php?t=190729
- https://en.wikipedia.org/wiki/Carrier-grade_NAT
- https://www.damow.net/dealing-with-cellular-broadband-cgnat/
- https://github.com/MHSanaei/3x-ui/issues/4373
- https://help.mikrotik.com/docs/spaces/ROS/pages/24805531/GRE
- https://forum.mikrotik.com/t/feature-request-gre-tunnel-key/93085 (GRE key still unsupported)
- https://github.com/openwrt/openwrt/blob/master/package/network/config/gre/files/gre.sh (ikey/okey)
- https://help.mikrotik.com/docs/spaces/ROS/pages/2031631/L2TP (L2TPv3 since RouterOS 7.1)
- https://blog.erben.sk/2022/11/07/layer-2-vpn-from-mikrotik-to-linux-proxmox-pve/ (L2TPv3 to Linux)
- https://www.ms8.com/configuring-mikrotik-routeros-gre-tunnel-over-ipsec/
- https://github.com/chrisandreae/meoip , https://github.com/bbonev/eoip (EoIP on Linux)

## Build / test commands

`./build.sh` (repo root, no flags). `go test ./web/... -count=1`. Never auto-run the incus E2E.

---

## As built (2026-07-30)

Shipped as Shape A, a real 11th protocol, with all six open decisions resolved:

- **OD1 shape:** A (per-account router inbound).
- **OD2 encryption:** both, as an L2TP-shaped `ipsecEnable` + `allowRaw` pair (three states:
  raw only, IPsec only, both). GRE-over-IPsec is ESP **transport** mode on the shared charon,
  one `conf.d/gre-<id>.conf` per inbound.
- **OD3 multiplexing:** source-IP point-to-point, **plus** an unkeyed catch-all for peers whose
  address is not known. No GRE keys in the base design, so MikroTik works.
- **OD4 dynamic IPs:** supported, via the catch-all and a learner. This is the big change from
  the research recommendation, which had deferred it.
- **OD5 MSS clamping:** not added server-side. The rendered RouterOS recipe sets
  `clamp-tcp-mss=yes` on the client, which is where it belongs for a router protocol. The
  repo-wide absence of a generic clamp rule remains a separate, pre-existing gap.
- **OD6 market viability:** the operator's call, unchanged.

### Where the research was wrong

1. **The learner is NOT the hardest part, and needs no new dependency.** A raw
   `AF_INET/IPPROTO_GRE` socket receives a copy of every protocol-47 packet *including ones a
   tunnel netdev also decapsulates*, and delivers nothing else. That is the entire learner in
   ~40 lines: no AF_PACKET, no BPF, no conntrack, no NFQUEUE in the packet path. Part 4's
   ranked option list was solving a harder problem than exists.
2. **A key-based design is not the only way to tolerate dynamic addresses.** An *unkeyed*
   `remote any` device works as a catch-all, demultiplexed on the inner address the panel
   assigned, so MikroTik peers on dynamic addresses are supported after all. Part 0 assumed
   this required RFC 2890 keys.
3. **`xray.go` carries the native-protocol skip list ONCE, not twice** (`:217`). Part 5's
   warning about two literal occurrences no longer holds.

Also corrected: `vpnAddrSpace` is already `10.0.0.0/12` (Part 2 said the /13 comment), so base
9 needed no widening; bases 10-15 are still spare.

### The two rule sets GRE needs that no other protocol here does

Both exist because GRE has **no cryptographic handshake**, which every other tunnel protocol
in this panel quietly relies on for two properties:

- **A disabled account cannot be stopped by refusing a handshake.** Withdrawing its route and
  neighbour entry is necessary but NOT sufficient: the promiscuous catch-all still
  decapsulates its packets and the TPROXY rule (keyed on the whole inbound block) still
  matches, so it could push traffic one-way. `GreNftView.Blocked` emits an explicit per-account
  drop.
- **A peer can source another peer's inner address.** With no per-peer crypto identity there is
  nothing to contradict it, so one customer could have traffic billed to another or bypass
  their own quota. `GreNftView.Allowed` emits per-netdev anti-spoof rules; for a
  point-to-point device that is exactly one address, making it complete.

### Known boundary: FOU is for peers with a known address

FOU-encapsulated GRE arrives as UDP, so the raw IPPROTO_GRE learner never sees it, and an
unkeyed FOU catch-all would collide with the raw one on the kernel's
`(local, remote, ikey, okey)` tuple. A dynamic peer therefore always falls back to raw GRE,
which the catch-all already accepts, so enabling FOU takes nothing away. Surfaced in the form
help rather than left silent.

### Kernel facts established by spike

See the `gre-kernel-findings` memory. The load-bearing ones: an exact `(local, remote)` tunnel
beats the wildcard (so static and dynamic peers coexist safely); `modprobe ip_gre` auto-creates
`gre0` which owns `(any, any)`, so a catch-all must bind a concrete local address; `ip neigh
add` fails EEXIST and `netlink.NeighSet` (replace) is required; `netlink.Gretun{}`'s zero
`PMtuDisc` *disables* PMTU discovery; `netlink.Fou` needs `EncapType: FOU_ENCAP_DIRECT`.

### Cost, against Part 5's estimate

37 existing files touched, 8 new (`web/service/gre.go`, `grelearn.go`, `greipsec.go`,
`gre_test.go`, `web/html/form/protocol/gre.html`, `web/html/modals/gre_config_modal.html`,
`test_unit/harness/clients/gre.py`, this record). Inside the predicted 90-110 edit-site range,
and as predicted it needed zero `backend/`, `build.sh` or `corebundle/` work and zero new i18n
keys.

### E2E result: 68 pass / 5 na / 1 fail (ubuntu-24)

`sudo ./run.sh --only ubuntu-24 --tests gre`.

Five real bugs were found by these runs, all in the new code, all now fixed with regression
tests:

1. **`net.IP.Equal(nil)` is false**, so the catch-all (built with `Remote: nil`, read back as
   `0.0.0.0`) looked changed every tick and was deleted and recreated about every ten seconds,
   wiping the neighbour table the learner keeps every dynamic peer's reverse path in. This was
   the root cause of every intermittent dynamic-peer failure and masqueraded convincingly as a
   learner timing race. Fixed by `greIPEqual`.
2. **Anti-spoof emitted per inbound.** Two GRE inbounds necessarily share one catch-all, so
   each inbound's `saddr != {own addresses} drop` dropped every other inbound's accounts and a
   second inbound could pass nothing. Fixed by `mergeGreViews` (union per netdev).
3. **PSK unresolvable on the shared charon.** strongSwan needs an owner match for BOTH ends, so
   a single-owner `id` made the secret unusable and charon signed with L2TP's key. Also a
   regression risk FOR L2TP. Fixed with `id_local` + `id_any = %any` and a distinct
   `gre-<id>.vpn-ui` identity.
4. **Learner slept up to 55s** before looking for a newly added peer. Fixed with a wake channel.
5. **`FouAdd` reports EADDRINUSE**, not EEXIST, for an already-registered port, so every tick
   logged a spurious warning once FOU was enabled.

The one remaining failure is `gre-ipsec-mode`: the SA installs correctly (TRANSPORT, ESP
AES-GCM-256, traffic selectors `<a>/32[gre] === <b>/32[gre]`) but carries no data, because
charon negotiates NAT-T on the incus bridge and UDP-encapsulated ESP in transport mode wrapping
a non-TCP/UDP inner protocol does not pass. NOT verified on a real no-NAT public path, where
NAT-T would not be negotiated. The enforcement half (bare GRE dropped when IPsec is required)
passes every run, so the gate itself is sound. One phase covers both demux paths (account A a
static peer, account B blank/dynamic) so client-to-client crosses a point-to-point device and a
catch-all device, plus `gre-ipsec-mode` (asserts bare GRE is DROPPED and ESP-wrapped GRE passes
-- checking only the second half would pass with the gate disabled) and `gre-fou-mode`. Joining
the shared suite brings usage, traffic multiplier, termination, user-limit and cross-inbound.

## Live customer diagnosis, 2026-07-30 (real CPE + real Android handset)

Reported as "tunnel comes up, curl showip works, Telegram works, nothing loads". Bisected with a
real handset on the router's wifi (adb) and a wired host on the same router.

**Root cause: the customer's upstream drops IP protocol 47 under load.** Not the panel, not the
CPE. Same source, same server, same path, same offered rate (12,605 x 1300B over 8s), counted on
the server's NIC:

| encapsulation         | arrived      |
|-----------------------|--------------|
| raw GRE (protocol 47) | 0            |
| GRE inside UDP (FOU)  | 12,625 100%  |
| plain UDP, no tunnel  | 12,599 100%  |

A trickle of protocol 47 leaks through, so the tunnel establishes and small requests succeed --
which is precisely why it looks like a panel bug. Off-tunnel the same link does 12-19 MB/s and a
5MB download completes in 1.2s; through the tunnel it stalls after 50-250KB in both directions.

`fouEnable` is the escape hatch for such networks and is not optional. This CPE speaks raw GRE
only (its API's GRE settings carry no MTU, FOU or IPsec fields), so it cannot use it.

### Two real bugs found and fixed on the way

1. **MSS was clamped in one direction only.** `ip daddr <cidr> ... size set rt mtu` constrains
   what the client UPLOADS. The client's own SYN went out unclamped (`mss=1436` into a 1388
   tunnel), so remote servers sized DOWNLOADS to 1476. The request direction cannot use
   `rt mtu` (it resolves to the WAN MTU there), so it clamps to a value computed from the
   inbound: `greSettings.clampMss`. Covered by `TestClampMssCoversBothDirections`.
   Note this fixes the FORWARDED paths (client-to-client, cross-inbound); internet traffic is
   TPROXY'd and already capped by the route MTU.
2. **`ensureCatchAll` passed MTU 0**, so an inbound's MTU setting was a no-op for every dynamic
   peer (`grePlan.catMtu`, smallest wins). Covered by `TestCatchAllHonoursSmallestInboundMtu`.

### Measurement traps that produced wrong answers first

- **`ping` cannot measure tunnel capacity.** `-i 0.001` never achieved its rate (5000 packets
  took 36s, ~140pps) and keeps 1-2 packets in flight. It reported "0.5% loss at 1.4MB/s" on a
  path that could not carry 100KB/s. Use a paced UDP blast counted at the far end.
- **Downloading from the tunnel endpoint's public address is not an off-tunnel baseline.** With
  `greDefaultGW=1` it still traverses the tunnel (arrived `from 10.9.0.2`). Toggle the router's
  GRE switch instead.
- The router must NAT its LAN behind the account address; un-NAT'd LAN sources hit
  `gre-antispoof`. Real, but only ~2 packets/sec here and not the cause of the stalls.

## Mode matrix verified on a clean-network peer, 2026-07-30

Client: a Hetzner Debian 13 VM with a public IP and no NAT (91.107.250.175), against the live
server. A dedicated test inbound was used so the live router's account was never touched.
Steered with a SOURCE policy route on the inner address, so the driving ssh session could not be
cut off by `ip route replace default`.

| mode | peer | result | 10MB | DF |
|------|------|--------|------|-----|
| raw GRE | dynamic (shared catch-all) | PASS | 23,199 KB/s | 1476 |
| raw GRE | pinned (point-to-point) | PASS | 24,159 KB/s | 1476 |
| FOU on, dynamic peer | dynamic -> served raw | PASS | 24,584 KB/s | 1464 |
| FOU (GRE in UDP) | pinned | PASS | 22,643 KB/s | 1464 |
| IPsec + raw both allowed | pinned | PASS | 19,872 KB/s | 1428 |
| IPsec ONLY (raw refused) | pinned | PASS | 24,867 KB/s | 1428 |

Every mode reached wire speed. GRE-over-IPsec carried a real data path for the first time
(`INSTALLED, TRANSPORT, ESP:AES_GCM_16-256`), confirming the one red E2E case is NAT-T-specific
and not a data-plane defect. IPsec-only enforcement verified from both sides: bare GRE from the
pinned peer was dropped (counter 88 packets/18112 bytes) while ESP from the same peer passed.

### Six bugs this found and fixed

1. **FOU was unusable at any volume, both directions.** GRO on the RECEIVING interface does not
   decapsulate coalesced UDP correctly, so nearly every segment is lost while a trickle survives.
   Measured: 10MB download 28 KB/s and never finishing, a 20MB upload delivering 557KB. With GRO
   off, 11-25 MB/s. The server now turns GRO off itself whenever an inbound enables FOU
   (`disableGroForFou`), and the rendered recipe carries the matching `ethtool -K ... gro off`
   line for the peer. The server half is not optional: the customer cannot fix the upload
   direction from their end. No narrower knob exists (`rx-gro-list`, `rx-udp-gro-forwarding` are
   already off and change nothing; the GRO happens on the physical NIC before the tunnel device).
2. **IPsec-only on one inbound killed every other inbound's raw peers.** The gate was a blanket
   `ip protocol 47 drop`. Verified live: a healthy peer on another inbound went 0% -> 100% loss
   the moment it was set, and recovered when cleared. Now scoped to the pinned peer's outer
   address, with the blanket rule used only when NO enabled inbound allows raw. Enforcing it
   after decapsulation is impossible: **`meta secpath exists` does NOT survive GRE decap**
   (measured: 11 inner packets from an ESP peer, 0 matching). An IPsec-only inbound with dynamic
   peers alongside a raw inbound now logs that it cannot be enforced, instead of pretending.
3. **Client-to-client OFF blocked the tunnel's own gateway.** The gateway address lives inside
   the client subnet, so the deny swallowed the very address the recipe tells the customer to
   route through: gateway ping 100% loss, which reads as a dead tunnel although forwarding was
   fine. Fixed in the SHARED helper, so all nine protocols get it, scoped to
   `fib daddr type local` with daddr still inside the subnet so nothing else changes.
4. **An unset MTU used the raw default on IPsec/FOU inbounds.** ESP transport leaves 1428 usable,
   so a fresh IPsec inbound black-holed. `effectiveMtu` now resolves per encapsulation with IPsec
   beating FOU (both overheads apply when both are on).
5. **A dynamic peer was handed a FOU port it could not use.** Dynamic peers are deliberately
   served by the shared raw catch-all, so the recipe told the customer to configure an
   encapsulation the server would never speak back to them.
6. **FOU port registration was a one-way door.** Disabling FOU, changing the port or deleting the
   inbound left the UDP listener bound until reboot. `reconcileFouPorts` now unregisters stale
   GRE-carrying ports and leaves other protocols' registrations alone.

Not a bug: no ICMP to internet hosts. That is by design for every protocol (the responder was
built in v1.7.4 and removed in v1.7.5, see the icmp-local-responder note).

## Feature-compatibility matrix verified live, 2026-07-30

Ten requirements, checked against observed state (kernel routes, nft counters, recorded traffic,
measured throughput, forwarding captures) rather than what the panel claims. Client was the
public-IP Debian 13 VM; the live customer router served as a second peer where two were needed.

| requirement | result | evidence |
|---|---|---|
| client to client | PASS | c2c OFF: 4 packets arrived, 0 forwarded. ON: 4 forwarded. Gateway stays reachable in both. |
| cross inbound | PASS | OFF emits drop both ways and the far inbound is unreachable; ON emits accept both ways and the server forwards (`gre52_0_0 In` -> `grecata1b6 Out`, every packet) |
| xray-core routing | PASS | a source-scoped `domain -> blocked` rule lands at rules[0], ahead of the generated per-account rule, and blocks that domain (http=000) while others stay 200 |
| user limit | PASS | K=3 -> 3 consecutive addresses, ONE aligned /30 accounting key, pinned peer gets its own exact-address anti-spoof, dynamic slots in the shared allow-set, an address outside the block is refused |
| speed limit | PASS | 24,972 KB/s -> 1,149 KB/s under a 1024 KB/s cap -> 21,039 KB/s after removal; the account appears in `bin/speedlimits.json` with its tunnel IPs |
| traffic multiplier | PASS | 5,000,000 transferred -> 5,036,450 recorded (x1.01); with x3 -> 15,106,383 (x3.02) |
| txt & pdf export | PASS | full router recipe embedded under the divider, `n/a (IP proto 47)` for port, no QR, and no spurious Password/UUID/PSK rows (GreUser carries no credential) |
| panel account management | PASS | add/edit/reset/delete all drive the data plane: per-account p2p device, route, accounting chain; delete tears all three down and does NOT renumber the surviving account |
| local ipv4 expansion | PASS | 90 accounts x /30 exhausted one /24 and the pool grew to two (`10.9.52.0/24` + `10.9.53.0/24`); 273 routes installed, zero stale routes left behind |
| account termination | PASS | quota exhaustion, past expiry and manual disable each cut traffic off, withdraw the route and tear down the p2p device; every one restores within a tick when cleared |

### Three more bugs this found and fixed

7. **Pinned peer addresses were silently dropped when an inbound was CREATED.** AddInbound
   round-trips every client through `model.Client`, which had no `peers` field, so a GRE account
   posted with a pinned peer came up as a DYNAMIC one: wrong device, wrong reverse path, no error
   anywhere. Editing an existing inbound never showed it, because that path mutates the settings
   map in place and keeps keys it does not know. `model.Client.Peers` now mirrors the service-side
   `grePeer`, exactly as the MTProto block above it documents.
8. **Route withdrawal never happened.** `reconcileRoutes` deleted with a hand-built
   `netlink.Route{LinkIndex, Dst}`, which carries scope UNIVERSE and table 0 and therefore does
   not match a scope-link route: the kernel answered ESRCH on every tick and the error was
   discarded. Reproduced against a real kernel (hand-built "no such process", kernel object nil).
   Stale host routes accumulated for every account whose addresses changed or that was deleted
   while served by the shared catch-all. Fixed by deleting the object the kernel returned; the
   fix immediately cleaned 253 stale routes left by the expansion test.
9. **FOU ports were never unregistered** (fixed earlier the same day, verified here: both stale
   listeners were removed on restart).

### Not bugs, confirmed by reading the code or the design notes

- No ICMP to internet hosts: by design for every protocol (responder built in v1.7.4, removed in
  v1.7.5).
- An over-quota or expired PINNED peer gets no `gre-blocked` nft rule, because its device is
  deleted outright; the drop rule is what covers DYNAMIC peers, whose catch-all persists.
- Writing `totalGB`/`expiryTime` through the whole-inbound settings blob does not re-sync
  `client_traffics`; the UI's own `updateClient` endpoint does, and enforcement follows it.
- The client-to-client and cross-inbound rules carry no `counter`, so they cannot be measured
  from nft alone. Verified by observing forwarding instead. Adding counters there would make
  future diagnosis cheaper.

## Deeper verification, 2026-07-30: speed limit both directions, all termination modes, accounting accuracy

### Traffic accounting is accurate to within 0.4%

| transfer | payload | recorded | ratio |
|---|---|---|---|
| 100MB download (direct, nc) | 104,857,600 | 105,015,688 down | **100.15%** |
| 100MB upload (nc to the gateway) | 104,857,600 | 105,264,320 up | **100.39%** |
| 60MB download via the internet (TPROXY through Xray) | 60,000,000 | 60,172,364 down | **100.29%** |

The overhead is IP+TCP headers, exactly as expected. Direction attribution is correct: a download
lands in `down` (up carries only ACKs, ~0.2%) and an upload lands in `up`.

Cloudflare's `__down` endpoint refuses `bytes=100000000` (returns 1 byte), which is why the 100MB
figures use an exact `nc` push rather than the speed test.

### Speed limit works in BOTH directions, independently

With `speedLimitSeparate=true`, `down=3072 KB/s`, `up=768 KB/s` -- deliberately asymmetric, since
only a genuinely per-direction implementation can produce both numbers:

| direction | baseline | capped | limit removed |
|---|---|---|---|
| download | 35,223 KB/s | **3,519** (cap 3072) | 32,399 KB/s |
| upload | 16,442 KB/s | **820** (cap 768) | 25,250 KB/s |

The sidecar carries both rates distinctly (`downBps: 3145728`, `upBps: 786432`).

**IMPORTANT property, measured not assumed:** the limiter lives in the patched Xray core, so it
only applies to traffic that TRAVERSES Xray. An upload aimed at the server's own inner gateway
address is accepted locally and came back UNLIMITED (7,187 KB/s against a 768 KB/s cap) -- that
was a flaw in the first test, not in the product, and re-measuring against an internet endpoint
gave 820 KB/s. Accounting behaves the opposite way: it is nft-based and counts every path,
including client-to-client and gateway-local traffic. So on a GRE inbound, traffic that never
leaves the box is billed but not shaped.

### Every termination mode enforces, and every one reverses

| mode | how it is expressed | result |
|---|---|---|
| manual disable | `enable=false` | cut off, route withdrawn, p2p device torn down, drop rule installed |
| **freeze** (reseller) | `enable=false` AND `expiryTime<0` | cut off; the negative expiry PRESERVES the remaining days |
| **unfreeze** | `enable=true`, expiry still negative | restored, and the negative expiry is correctly read as "not started", not as expired |
| days quota | `expiryTime` in the past (`>0`) | cut off, route withdrawn |
| traffic quota | `up+down >= total` | cut off, route withdrawn, device torn down |
| restore | reset traffic + clear the limit | service back within one tick, every time |

The delayed-start mechanism was observed working end to end: a frozen account's
`expiry=-604800000` became `expiry=1786028564000` on unfreeze, i.e. the 7-day countdown was
stamped from when service resumed rather than being burned while frozen. `disableInvalidClients`
requires `expiry_time > 0`, which is what keeps a negative expiry from ever reading as expired.
