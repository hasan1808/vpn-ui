# SSH (VPN) - research and implementation plan

Adding **SSH** as a 10th first-class VPN protocol with real, panel-integrated account
management. This document is the research record and proposed implementation contract,
produced from an 8-agent recon (4 codebase + 4 web). Mirrors the style of
`ikev2-plan.md` / `wireguard-plan.md` / `sstp-plan.md`.

STATUS: RESEARCH ONLY - HOLD FOR REVIEW. Nothing built yet.

---

## The strategic reality check (read this before the decisions)

The research turned up one finding the maintainer should weigh before committing, because
it was not obvious going in:

**For this panel's stated audience (Iran, plus the Persian/Arabic/Chinese/Russian locales),
plain SSH is a weak and largely redundant circumvention tool.** SSH's cleartext `SSH-2.0-`
version banner is a first-class DPI fingerprint (the tool `sslh` routes traffic by reading
exactly that banner). Iran has throttled SSH to roughly 15% bandwidth since 2013, and the
Jan/May 2026 shutdowns ran a protocol allowlist that dropped everything not whitelisted.
The stack that actually works there (VLESS+REALITY, Hysteria) is already in this panel and
is strictly better against Iranian DPI than raw SSH on a port.

The large, real "SSH account" client scene (HTTP Injector, HA Tunnel, TLS Tunnel, etc.) is
overwhelmingly a **mobile-carrier free-internet / zero-rating** phenomenon in Southeast Asia,
Africa and India, not a censorship story. Its whole value is the "payload / bug host" trick
that fools a **mobile carrier's billing**, which is irrelevant to a paid VPS. Worse, those
apps' config formats (`.ehi` / `.hat` / `.tls`) are proprietary and encrypted, so the panel
**cannot generate them**.

So the honest case for shipping SSH is:
1. **Product/market completeness.** "SSH" is a recognized checklist item, and Hiddify Manager
   already ships an "SSH proxy" protocol, so a competing panel arguably should too.
2. **Occasional real wins.** There is mixed but genuine field evidence (net4people#191) of plain
   SSH getting through on some Iranian ISPs at times when even VLESS+XTLS is flagged. It is a
   weak parallel path, not an upgrade.
3. **It is cheap.** Because of the architecture below, SSH costs almost nothing to add: no
   bundled binary, no new dependency, no kernel module, no new addressing.

This plan assumes the maintainer still wants SSH for reasons 1-3. If the goal were a censorship
capability the current stack lacks, SSH is not it, and that should be an explicit, eyes-open
decision. Everything below is the cheapest, cleanest way to ship it well.

---

## Decisions proposed (2026-07-16) - need sign-off

1. **Ship shape = RELAY (the MTProto twin), not TUNNEL.** SSH's natural VPN mode is a SOCKS
   proxy (`ssh -D`, i.e. `direct-tcpip` channels). Real tun mode (`ssh -w` / `PermitTunnel`)
   is non-viable at scale (root both ends, one tun device per connection, no address-pool
   manager, Dropbear does not support it, OpenSSH's own docs say use IPsec instead). Relay
   shape means SSH does **not** touch `vpnrange.go`, does **not** get a `protocolBase`, does
   **not** widen `vpnAddrSpace`, and does **not** use nftables or the rbridge Sink, exactly
   like mtproto. See Part 1.

2. **Server = a custom in-binary Go server on `golang.org/x/crypto/ssh`.** NOT a bundled
   OpenSSH/Dropbear + PAM glue. `golang.org/x/crypto v0.50.0` is already a direct dependency
   (`go.mod:27`) and `golang.org/x/crypto/ssh` exposes `NewServerConn(net.Conn, *ServerConfig)`,
   so this adds **zero new dependencies, zero bundled binary, zero submodule/fork, zero kernel
   module**, ~0 MB of binary bloat, and is the only VPN protocol that is **arm64-clean** (no
   `backend/bin/arm64` bundle needed). A second, independent reason clinches it: **OpenSSH cannot
   do virtual users at all** (`sshd` calls `getpwnam()` and refuses any login without a matching
   OS account, by design, bug 1215), so bundling it would force either one `useradd` per account
   or a custom NSS module. The Go server authenticates entirely in-process against the panel DB,
   so there are no OS users, no NSS, no `getpwnam`. See Part 2.

3. **Proxy-only lockdown.** Auth password (and optionally a public key) against the client DB
   in the SSH auth callback (no OS users, no RADIUS). Reject pty/shell/exec/subsystem; allow
   **only** `direct-tcpip` channels. This makes every credential a tunnel-only credential with
   zero shell exposure, matching Hiddify's restricted SSH-proxy design. See Part 3.

4. **Xray routing = reuse the mtproto SOCKS-username handoff verbatim.** For each `direct-tcpip`
   channel, dial the panel's loopback SOCKS inbound (`GetSocksConfig`, port `12300+inboundId`,
   tagged `inbound.Tag`) with SOCKS5 username = the account, and forward. Xray surfaces the
   username as the connection's `user`, so operator `user:[email]` rules resolve per client with
   no per-client IP. Zero new routing code. Unlike mtproto there is **no adtag/middle-proxy
   constraint**, so SSH is always routable through Xray. See Part 5.

5. **Accounting = in-process byte counters.** The Go server owns every byte via `io.Copy`, so
   wrap the copies with atomic per-account up/down counters and expose `CollectTraffic() []*xray.ClientTraffic`
   folded into `client_traffics` at `xray_traffic_job.go:111`, exactly where mtproto's scrape
   lands. Simpler and more exact than mtproto's Prometheus scrape (no endpoint, no text parsing,
   no counter-reset guessing). See Part 7.

6. **User Limit K + BOTH strategies, enforced in-process.** This is the capability MTProto could
   not have. Because the server owns every `net.Conn`, it can enumerate live sessions per account
   (count, arrival time, stable handle) and kill a chosen one. So SSH supports **reject** and
   **accept-evict-oldest**, reusing the pure `rbridge.TrimToLimit` ordering function even though
   it does not use the rbridge Sink. See Part 6.

7. **UDP = TCP-only in v1, with a cheap UDP fast-follow.** SSH channels are TCP-only. The good
   news from the recon: the ecosystem's UDP helper (badvpn-udpgw) listens on loopback and the
   client reaches it *through* the SOCKS proxy, so the udpgw stream is itself a `direct-tcpip`
   channel. That means once we terminate that channel (either by forwarding to a small bundled
   udpgw, or by implementing udpgw's simple length-prefixed protocol in-process), UDP is
   **automatically byte-counted and User-Limited** like any other channel, no special case. The
   only thing deferred is *Xray-routing* the UDP (per-client outbound selection), which needs the
   in-process udpgw handler to forward via Xray's SOCKS UDP ASSOCIATE. So: ship TCP-only v1, add
   direct-egress UDP as a cheap fast-follow, Xray-routed UDP as v2. See Part 8.

8. **Obfuscation = two tiers; design for tier 2, ship tier 1.** Tier 1: raw SSH on a port, client
   config = a sing-box `ssh` outbound (Hiddify-consumable). Tier 2: front the local SSH listener
   with an Xray `dokodemo-door` inbound doing WS/TLS/Reality, giving SSH-over-WS/TLS/Reality for
   free with the banner never on the wire. Tier 2 client needs the SSH-over-WS tooling and does
   not combine with the clean sing-box outbound, so it is a separate client profile. See Part 9.

9. **Identity lane = username/password, `clientId = password` (the l2tp lane).** SSH accounts model
   as the existing l2tp/ikev2 `*User` shape (`id`=username, `password`, `email`=label). This lane
   needs **no** `get id()` getter (unlike the email-identity mtproto/wg-c). The one hazard is
   keeping the `clientId` switch identical across all six code sites (Go + JS); the current
   openconnect/sstp/ikev2 divergence is a live warning not to copy. See Part 4.

10. **Client artifact = sing-box `ssh` outbound JSON + plaintext host/port/user/pass + QR of that
    text.** Do NOT build an `.ehi`/`.hat`/`.tls` generator (proprietary, encrypted, wrong audience).
    No `sub/` change (all VPN protocols are already excluded from subscription URLs). See Part 11.

---

## Part 0 - Executive summary

- SSH is the **cheapest protocol this panel can add**: an in-process Go server on an already-present
  dependency, no bundle, no fork, no kernel module, no new IP space, arm64-clean.
- It is a **relay**, the MTProto twin, and reuses MTProto's exact Xray routing plumbing
  (`GetSocksConfig` + SOCKS username) and traffic-fold point verbatim.
- It **beats MTProto on control**: owning the `net.Conn` in-process gives it live-session
  enumeration and kill, so it supports **both** User-Limit strategies (reject and accept-evict-oldest),
  which MTProto could not.
- It is **fully compatible** with all six required subsystems (account management, Xray routing,
  User Limit K, User-Limit strategy, multi-inbound, multi-client); see the scorecard at the end.
- Its two real weaknesses are **UDP** (TCP-only in v1) and **censorship value** (weak vs the panel's
  existing Reality/Hysteria for the Iran audience). Both are acceptable if SSH is shipped for
  product completeness rather than as a circumvention upgrade.

---

## Part 1 - Why relay, not tunnel

Two data-plane families exist in the panel:

- **Tunnel (Tier-B):** the client emerges on the host with a real source IP in `10.N.x.x`;
  nftables TPROXYs that source into a per-inbound Xray dokodemo; Xray routes by source IP.
  Members: l2tp, pptp, openvpn, openconnect, sstp, ikev2, wg-c.
- **Relay:** a userspace proxy terminates the client; there is no tunnel IP; accounting comes
  from the daemon's own counters; routing uses the SOCKS username. Member: mtproto.

SSH's natural mode is a SOCKS proxy, so it is a relay. Choosing relay avoids a large, load-bearing
cost that the tunnel path would force:

- A tunnel SSH would need `protocolBase(ssh) = 8` = `10.8.0.0/16`, but `vpnAddrSpace = "10.0.0.0/13"`
  (`nftables.go:22`) only covers `10.0`-`10.7`. Base 8 is **outside** it, so adding it would force
  widening `vpnAddrSpace` to `/12`. That constant is the firewalld trusted-source AND the routing
  blackhole backstop, so getting it wrong yields "connects, no internet". wg-c deliberately took the
  last slot (base 7) precisely to avoid this.
- A tunnel SSH would also need deterministic per-client IP assignment matching the panel's
  `computeVpnClientIP`/`vpnAccountDeviceIPs`, plus per-client tun devices with procmgr-style
  lifecycle and orphan reaping. `ssh -w` cannot do this cleanly.

Relay SSH sidesteps all of it: no base, no `vpnAddrSpace` change, no nft, no per-client IP.

---

## Part 2 - Why in-binary Go, not a bundled daemon

The bundling recon compared "bundle a C daemon (OpenSSH/Dropbear) + PAM glue" against "in-binary
Go server" and the Go server wins on every axis:

| Dimension | Bundle C daemon | In-binary Go (`x/crypto/ssh`) |
|---|---|---|
| New dependency | new Alpine musl build recipe; sshd dlopens PAM/NSS so likely a `.tgz` tree bundle | none; `x/crypto v0.50.0` already in `go.mod:27` |
| Binary size | +1-4 MB | ~0 MB (already linked) |
| Fork maintenance | if patched-from-source, inherits the submodule-rewind trap | none; upstream go.mod dep |
| Host deps | tree extraction + patchelf + symlink dance | none (userspace TCP) |
| procmgr | new child `ssh-server-*`, orphan-reap pass (sshd retitles like ocserv) | none; in-process goroutine |
| Uninstall | stop child + remove tree + host-key files | ~nothing (keys in DB, listener in-process) |
| arm64 | inherits the gap (no arm64 bundle exists) | **closes it** (compiled with the panel) |
| Auth model | OS users, no hot-add API (the core problem) | DB-backed callback, hot add/remove |

The in-binary precedents to clone are the **RADIUS server** (`radius.go:97-149`: build state,
`radius.PacketServer` + `go ListenAndServe()`, package-global for Stop/Restart, `Shutdown(ctx)` with
a 5s timeout) and **wg-c** (validates credentials live from the DB on every change, so add/edit/disable
never restarts). Note: MTProto's `telemt` is Rust, not Go, so it is not a Go in-process precedent;
RADIUS and wg-c are.

The reference implementation to study is **Chisel** (`jpillora/chisel`, MIT, active): it is literally
`crypto/ssh` over WebSocket with SOCKS5 and per-user auth via a users file, i.e. ~90% of "modern Go
SSH VPN server" already written. `gliderlabs/ssh` (a friendlier wrapper over `x/crypto/ssh`) is the
recommended API surface: `net/http`-style handlers, easy to deny pty/exec and allow only `direct-tcpip`.

---

## Part 3 - The SSH server (auth, lockdown, lifecycle)

New file `web/service/ssh.go`, package `service`, struct `SshService` (zero-value usable, like
`MtprotoService`). One in-process server owning one `net.Listener` per enabled SSH inbound.

- **Auth:** an `ssh.ServerConfig` per inbound with `PasswordCallback` (and optionally
  `PublicKeyCallback`) that looks the account up in that inbound's `settings.clients[]`, checks the
  password/secret, checks `client.Enable`, and re-checks `client_traffics.enable` for quota/expiry
  (the same gate `radius.lookupClient` applies). No OS users, no RADIUS round-trip. Credentials are
  read live from the DB per connection, so add/edit/disable needs no restart (the wg-c property).
- **Host key:** one server keypair per inbound (or one panel-wide), generated on first use and
  persisted (mirrors wg-c's `ReconcileAllKeys`; the host key is what the client pins).
- **Lockdown (make it a purpose-built VPN gateway):** reject `session` channels (pty/shell/exec/
  subsystem) AND `tcpip-forward` (reverse) requests; allow only `direct-tcpip` to non-loopback
  destinations, plus the one loopback udpgw port if/when UDP is enabled. This turns the entire
  restricted-shell / ForceCommand problem into a non-issue. `gliderlabs/ssh` ships a built-in
  `DirectTCPIPHandler` (accept channel, dial, `io.Copy` both ways) so `ssh -D` SOCKS works out of
  the box, gated by `LocalPortForwardingCallback`.
- **Lifecycle:** `InitSsh()` at `web.go` startup (like `InitWgc`/`InitMtproto`), `RestartServices()`
  and `StopServices()` that (re)bind the listeners and are wired into `core.go` RestartCore/StopCore.
  Graceful shutdown closes listeners and drains sessions, RADIUS-style. `SetupRouting()` is a no-op
  (no tunnel), present only for shape parity.
- **Security posture:** `x/crypto v0.50.0` is already past both relevant CVEs (Terrapin
  CVE-2023-48795 fixed in v0.17.0; the `PublicKeyCallback` authorization-bypass CVE-2024-45337 fixed
  in v0.31.0). The rule the second CVE encodes: record identity via the returned
  `Permissions.Extensions` and read it back from `ServerConn.Permissions` after the handshake; never
  trust the last key seen. `gliderlabs/ssh`'s bool-returning `PublicKeyHandler` avoids that footgun
  by construction, a further reason to use the wrapper over raw `x/crypto/ssh`.

---

## Part 4 - Account management

- **Model:** SSH accounts are the existing username/password shape. `model.Client` already carries
  `ID` (=username), `Password`, `Email`, `Enable`, `TotalGB`, `ExpiryTime`, `SubID`, so **no new
  `model.Client` field is required** for the basic protocol. (A future pubkey variant would add a
  `pubKey omitempty` field; note that a field absent from `model.Client` is silently dropped no
  matter what the UI posts, `model.go:166-171`.)
- **Credential generation:** JS mints on "add" like l2tp (`password = randomSeq(10)`, `id =
  randomLowerAndNum(8)`), so the panel can render the config immediately. No server-side reconcile
  needed for username/password.
- **Identity lane (the one hazard):** the `clientId` used by updateClient/delClient/table-row-key is
  chosen by a per-protocol switch duplicated in ~6 sites. SSH should follow the **l2tp lane
  (`clientId = password`)** and be set **identically** in all of them: JS `getClientId`
  (`client_modal.html:88-105` and `inbounds.html:2094-2107`), Go `UpdateInboundClient`
  (`inbound.go:1277-1290`), `DelInboundClient` (`inbound.go:1171-1178`), and the three toggle/tgId
  switches (`inbound.go:2293,2374,2456`). The current openconnect/sstp/ikev2 rows **disagree** (JS
  says password, Go says id), which is a latent "empty client ID" bug the E2E cannot catch; do not
  copy it. A username/password SSH needs **no** `get id()` getter (that is only for email-identity
  protocols).
- **Auth read:** because the SSH server authenticates against the DB itself, it does not use
  `radius.go`. Disable/quota is enforced by the server's own `getDisabledEmails()` +
  `KillDisabledSessions()`, wired into the traffic job (Part 7).

---

## Part 5 - Xray routing (the SOCKS handoff, reused verbatim)

MTProto already does exactly what the SSH server must do, and it is E2E-green. Reuse it:

1. The panel injects a loopback SOCKS **inbound** per SSH inbound via a `GetSocksConfig`-style helper:
   `{listen:127.0.0.1, port:12300+inboundId, protocol:"socks", settings:{auth:"password",
   accounts:[{user:email,pass:email}...], udp:false}, tag:inbound.Tag}` (mtproto.go:271-317), appended
   to the Xray inbounds like `xray.go:293`.
2. For each authenticated `direct-tcpip` channel, the SSH server dials `127.0.0.1:(12300+inboundId)`
   SOCKS5 with **username = account email** and CONNECTs to the channel's requested target, then
   `io.Copy` both ways.
3. Xray surfaces the SOCKS username as the connection's `user`, so an operator's `user:[email]`
   routing rule resolves per client. `translateVpnRoutingRules` (`xray.go:321`) leaves relay `user`
   rules native (it only rewrites tunnel protocols' rules to source-IP), and SSH stays **out** of
   `BuildVpnEmailToIPMap` (`radius.go:1382`), exactly like mtproto. Inbound-level routing works via
   the `inbound.Tag` on the socks inbound.

No new routing code. And unlike mtproto there is no adtag/middle-proxy path, so SSH never has to give
up Xray routing.

---

## Part 6 - User Limit K + strategy (the capability MTProto lacked)

MTProto delegates K to `telemt` and supports **reject only**, because the panel had no addressable
per-device handle to evict. A custom Go SSH server does not have that limitation: it owns every
`net.Conn`, so it can maintain an in-memory table of live sessions per account (email -> list of
{sessionHandle, clientSourceIP, since}). That makes both strategies trivial:

- **K definition:** K distinct client source IPs per account (the mtproto-equivalent "device"
  definition), K from `effectiveUserLimit(client.UserLimit)` (`vpnrange.go:684`; nil->1, 0->no-limit,
  else 1..64).
- **reject:** when a new session would exceed K distinct source IPs, refuse it at connect.
- **accept-evict-oldest:** admit the new session and kill the oldest session (close its `net.Conn`),
  ordered by `since`. The pure ordering function `rbridge.TrimToLimit` (`rbridge.go:140`) can be
  reused for the reject/accept keep-set math even though SSH does not use the rbridge Sink.

Enforcement runs both at connect (synchronous, immediate) and as a level-triggered sweep in the
traffic job (catches accounts that went over after a settings change), reusing the server's own
session table.

---

## Part 7 - Accounting

- The server wraps each channel's `io.Copy` with atomic per-account up/down counters.
- `SshService.CollectTraffic() []*xray.ClientTraffic{Email,Up,Down}` returns per-account deltas since
  the last tick, appended into `clientTraffics` at `xray_traffic_job.go:111` (the mtproto line) and
  landed by `inboundService.AddTraffic`, which also flips over-quota accounts to disabled.
- `getDisabledEmails()` reads `client_traffics` where `enable=false`; `KillDisabledSessions()` closes
  the live sessions of any disabled account (trivial: the server owns them), wired into
  `xray_traffic_job.go:121-130` like every other protocol.
- SSH is deliberately absent from the nft path (no per-client IP), the same reason mtproto avoids it.

This is strictly simpler and more exact than mtproto's scrape: no Prometheus endpoint, no metric
parsing, no cumulative-counter-reset handling.

---

## Part 8 - UDP (the biggest limitation, but cheaper than it first looks)

SSH channels are TCP-only. `ssh -D` SOCKS5 rejects UDP ASSOCIATE, and sing-box's ssh outbound is
TCP-only. So the UDP story is a staged roadmap, not a single blocker:

- **v1 (ship): TCP-only.** All TCP apps work (web browsing, most usage). UDP (DNS-over-UDP,
  QUIC/HTTP3, VoIP, gaming) does not; browsers fall back from QUIC to TCP, so it is survivable, but
  it must be stated plainly in the UI and docs.

- **The key insight that makes UDP cheap:** the ecosystem's UDP helper, badvpn-udpgw, listens on
  loopback and the client reaches it *through* the SOCKS proxy, so the udpgw stream is itself a
  `direct-tcpip` channel to `127.0.0.1:7300`. Because our Go server proxies every channel with its
  own `io.Copy`, udpgw traffic is therefore **automatically byte-counted and User-Limited** with no
  special case, unlike a shared-OpenSSH + global-udpgw setup which would be blind to per-account UDP.

- **v1.5 (cheap fast-follow): direct-egress UDP.** Terminate that udpgw channel in the Go server,
  either by forwarding to a tiny bundled udpgw or (preferred, keeps the no-bundle win) by
  implementing udpgw's simple length-prefixed protocol in-process. UDP then works and is accounted +
  User-Limited, but egresses from the server's own IP (not per-client Xray-routed).

- **v2 (full parity): Xray-routed UDP.** Have the in-process udpgw handler forward decoded UDP via a
  SOCKS5 UDP ASSOCIATE against the Xray socks inbound (Xray socks supports `udp:true`; the injected
  inbound would flip it on). UDP then rides the same per-client Xray routing and accounting as TCP.
  This is the non-trivial part and is deferred, but no external daemon is required for it.

---

## Part 9 - Obfuscation (two tiers)

- **Tier 1 (ship first, Hiddify parity):** raw SSH on a port. The client is a sing-box `ssh` outbound
  (below). The `SSH-2.0-` banner is on the wire and is fingerprintable, but this matches exactly what
  Hiddify's SSH-proxy ships, and it is the clean, cross-platform, per-user path.
- **Tier 2 (differentiator, design-for):** front the local SSH listener with an Xray `dokodemo-door`
  inbound whose streamSettings do WS + TLS (and Reality), forwarding the raw inner stream to
  `127.0.0.1:sshPort`. This yields SSH-over-WS/TLS/Reality for free, reusing the panel's Reality
  stack, with the SSH banner never appearing on the wire (prior art: computerscot's ssh-over-xray).
  The catch is symmetric: the client must speak the same transport (HTTP Injector on Android;
  `stunnel`/`websocat` + `ProxyCommand` on desktop), which does not combine with the clean sing-box
  outbound. So Tier 2 is a **separate client profile**, chosen per user, not a strict upgrade of Tier 1.

Ship Tier 1; leave the wiring seams so Tier 2 can be added without a redesign.

---

## Part 10 - Multi-inbound + multi-client

- **Multi-inbound:** one Go server, one `net.Listener` per enabled SSH inbound (the RADIUS pattern of
  owning listeners). Each inbound gets its own socks egress port `12300+inboundId`. `inbound.Id` is
  globally unique, so ports never collide. No shared-daemon config, so no l2tp/pptp-style collision.
- **Multi-client:** many accounts per inbound live in `settings.clients[]`, each a username/password
  row. The socks inbound's account list is the union of the inbound's client emails. Each live SSH
  session carries a distinct handle, so two devices behind one NAT are two distinct sessions (avoids
  the openconnect same-NAT K collapse).

---

## Part 11 - Client delivery artifact

- **Primary:** a sing-box `ssh` outbound JSON, e.g.
  `{"type":"ssh","server":<host>,"server_port":<port>,"user":<username>,"password":<password>,
  "host_key_algorithms":[...]}`. This drops into Hiddify (sing-box based), which the Iran audience
  already runs. This is the one openly-generatable artifact that lands on an installed client.
- **Secondary:** a plaintext block (host / port / username / password / optional host-key fingerprint)
  plus a QR of that text, with short per-app import steps for Bitvise (Windows), NapsternetV/HTTP
  Injector (Android manual entry), and `ssh -D` (desktop).
- **Do not build** an `.ehi`/`.hat`/`.tls`/`.npv4` generator: proprietary, encrypted, undocumented,
  and aimed at the wrong (carrier-bypass) audience.
- **No `sub/` change:** all VPN protocols are already excluded from subscription URLs
  (`sub/subService.go:168` handles only the 5 Xray protocols), and mtproto chose not to add itself.
  SSH follows suit unless subscription inclusion is explicitly wanted.

---

## Part 12 - Panel/UI wiring checklist (relay shape)

Ordered, tagged [SI]=shape-independent, [R]=relay-specific. This is the mtproto path.

1. `database/model/model.go` [SI]: add `SSH Protocol = "ssh"`. (No new client field for username/password.)
2. `web/assets/js/model/inbound.js` [SI]: `Protocols` enum + `ProtocolLabels` (auto-adds to the
   dropdown); `get clients()` arm; `isMultiUser` true; `hasLink` true (it has a sing-box config link);
   `getSettings`/`fromJson` factory arms; `Inbound.SshSettings` + `SshUser` classes. No `get id()`
   (username/password identity).
3. `web/html/form/protocol/ssh.html` [SI]: new `{{define "form/ssh"}}` (auto-discovered), inbound-level
   fields = port + User Limit + **User Limit Strategy (accept|reject)** + optional obfuscation-tier
   toggle. Add the include arm in `form/inbound.html`.
4. `web/html/form/client.html` [SI]: show Username + Password for ssh; add User Limit per client.
5. `web/html/modals/client_modal.html` [SI, CRITICAL]: `getClientId` arm (= password, l2tp lane) +
   `addClient` `new SshUser()` arm.
6. `web/html/inbounds.html` [SI]: the second `getClientId` copy (must match #5); client-count arm;
   setup-required submit gate (only if SSH is made provisioning-gated, which as a daemonless in-binary
   server it need not be).
7. `web/html/modals/inbound_modal.html` [SI]: `onProtocolChange` default port.
8. `web/html/modals/client_bulk_modal.html` [SI]: bulk-add `new SshUser()` arm.
9. `web/html/component/aClientTable.html` [SI/R]: QR / config-download action-icon gating for ssh.
10. `web/assets/js/util/export.js` [SI]: identity/username branch (`client.id||client.email`, l2tp
    family) + `_network`/`_port` arms. (Pre-existing em-dashes at lines 5/180/206 should be fixed to
    honor the no-em-dash rule when this file is touched.)
11. `web/controller/inbound.go` [SI]: `SshService` field; `onSshChanged`/`onSshClientChanged`
    (clientOnly skips restart because auth reads the DB live) wired at all ~11 mutation sites; a route
    for the sing-box config download if not rendered client-side.
12. `web/service/inbound.go` [SI, CRITICAL]: SSH arm in the `UpdateInboundClient`/`DelInboundClient`/
    `AddInboundClient`/toggle clientId switches, kept identical to JS `getClientId`; duplicate-username
    check via `checkPPPUsernamesForDuplicates`. Do NOT add SSH to `isVpnProtocol` (that is tunnel-only).
13. New `web/service/ssh.go` [SI]: the server (Parts 3-7): `GetSshInbounds`, `parseSettings`,
    `GetSocksConfig`/`GetSocksPort`, `RestartServices`, `StopServices`, `InitSsh`, `CollectTraffic`,
    `getDisabledEmails`, `KillDisabledSessions`, `Available`, no-op `SetupRouting`, and the in-process
    session table + User-Limit enforcement.
14. `web/service/xray.go` [SI]: inject the SSH socks inbound (mirror the mtproto block at `xray.go:293`);
    add "ssh" to the native-protocol skip list if needed.
15. `web/job/xray_traffic_job.go` [SI]: call `sshService.CollectTraffic()` (append at the mtproto line)
    and `KillDisabledSessions()`. No `sweeper.Register` (SSH enforces in-process, not via the rbridge Sink).
16. `web/service/core.go` [SI]: `sshStatus()` (installed = `Available()`; running = listener bound,
    the radius/wgc archetype) + `GetCoresStatus` + RestartCore/StopCore/CoreLogs arms. `core.html`
    `coreTitle: 'SSH'` + `coreBackend: 'Built-in (vpn-ui)'`. `index.html` `vpnCoreStatuses` + `coreLabel`.
17. i18n [SI, optional]: ship English-inline like mtproto/wg-c, or add keys to all 13
    `translate.*.toml` (parity ratchet `i18n_toml_test.go:125`).
18. `web/template_parse_test.go` [SI]: it asserts each protocol form is defined; `form/ssh` must parse.

---

## Part 13 - E2E (author-run only, never auto-run)

Relay-shaped harness work, cloning the mtproto path in `test_unit/`:

- `clients/ssh.py`: a client driver that opens an `ssh -D`/`direct-tcpip` session as an account and
  proves a routed TCP fetch; no tunnel `connect()` contract.
- `protocols.py`: a dedicated `_run_ssh` special-cased in `run()`, returning before the tunnel suite;
  record dns-leak/routing-by-source-IP as NA-by-construction (relay has no tunnel IP), assert
  accounting via `traffic._counted` (drive bytes, assert `client_traffics` grows), and assert
  User-Limit K (open K+1 sessions, assert reject or evict-oldest per strategy) - the one relay check
  mtproto could not do that SSH can.
- `server_setup.py`: build an SSH inbound + accounts; `client_ip()` guarded like mtproto.
- `model.py`/`orchestrator.py`/`run.sh`: phase constant + selection alias + docs.
- `export_test/model.test.js`: only needed if SSH is made email-identity (it is not, so skip).

---

## Part 14 - Phasing (each phase: `./build.sh` + `go test ./web/... -count=1` green)

- **Phase 1 - server core, isolated.** `web/service/ssh.go`: `x/crypto/ssh` server, DB auth callback,
  proxy-only lockdown, direct-tcpip -> SOCKS handoff, in-process session table. Unit tests for the
  User-Limit trim (reuse `rbridge.TrimToLimit`) and the auth callback. Not wired into the panel yet.
- **Phase 2 - data plane.** Inject the socks inbound in `xray.go`; wire `CollectTraffic` +
  `KillDisabledSessions` into `xray_traffic_job.go`; `InitSsh` at startup; core.go status/restart.
- **Phase 3 - account management + UI.** model const, controller `onSshChanged`, the clientId switch
  arms (all six sites consistent), the inbound/client forms, dashboard + Core Settings rows.
- **Phase 4 - client artifact.** sing-box `ssh` JSON generator + plaintext/QR; export.js arm.
- **Phase 5 - E2E** (author-run): the relay harness above, including the User-Limit both-strategies check.
- **v2 (later):** Tier-2 Xray WS/TLS/Reality front; the udpgw-to-SOCKS-UDP bridge; optional pubkey auth.

---

## Part 15 - Open decisions needing sign-off

1. **Ship at all?** Given the strategic reality check, confirm SSH is wanted for product completeness,
   accepting it is a weak censorship path for the Iran audience.
2. **Obfuscation tier for v1.** Tier 1 raw SSH + sing-box config (recommended, cheapest, Hiddify parity)
   vs investing in Tier 2 (Xray WS/TLS/Reality front) up front.
3. **UDP.** Accept TCP-only v1 (recommended) vs blocking on the v2 udpgw-to-SOCKS bridge.
4. **Auth methods.** Password-only v1 (recommended) vs password + public key.
5. **i18n.** English-inline like mtproto/wg-c (cheapest) vs proper keys in all 13 locales.

---

## Compatibility scorecard vs the six required subsystems

| Requirement | Fit | How |
|---|---|---|
| **Account management** | Full | `model.Client` username/password (l2tp shape); DB auth in the SSH callback; hot add/edit/disable (creds read live). No RADIUS, no OS users. |
| **Xray routing** | Full | mtproto SOCKS-username handoff reused verbatim; per-client (`user:[email]`) and per-inbound (`tag`). No adtag constraint, so always routable. |
| **User Limit (K)** | Full | In-process count of K distinct client source IPs per account; K from `effectiveUserLimit`. |
| **User-Limit strategy** | Full (both) | In-process session ownership -> **reject** and **accept-evict-oldest** (reuse `rbridge.TrimToLimit`). Better than mtproto (reject-only). |
| **Multi-inbound** | Full | One Go server, one listener per inbound; per-inbound socks port `12300+id`; no shared-daemon collision. |
| **Multi-client** | Full | Many accounts per inbound in `settings.clients[]`; distinct session handle per device (no same-NAT collapse). |

Net: SSH is compatible with all six, and on strategy it is strictly better than the existing relay
(mtproto). The tradeoffs are UDP (TCP-only v1) and censorship value (weak for the primary audience),
both product decisions rather than technical blockers.

---

## Build / test commands

```sh
./build.sh                         # canonical build (never bare `go build`)
go test ./web/... -count=1         # unit + i18n parity + template-parse
# E2E (author only, never auto-run): sudo test_unit/run.sh --tests ssh
```

## Key files

- New: `web/service/ssh.go` (+ `ssh_test.go`), `web/html/form/protocol/ssh.html`.
- Edit: `database/model/model.go`, `web/assets/js/model/inbound.js`, `web/controller/inbound.go`,
  `web/service/inbound.go`, `web/service/xray.go`, `web/job/xray_traffic_job.go`, `web/service/core.go`,
  `web/html/form/client.html`, `web/html/modals/{client_modal,inbound_modal,client_bulk_modal}.html`,
  `web/html/component/aClientTable.html`, `web/html/{inbounds,index,core}.html`,
  `web/assets/js/util/export.js`, `web/template_parse_test.go`.
- Reference (do not fork): MTProto (`web/service/mtproto.go`, the relay design spec at lines 25-70),
  RADIUS (`web/service/radius.go:97-149`, in-binary listener), wg-c (`web/service/wgc.go`, live-DB
  reconcile). External: `jpillora/chisel` (crypto/ssh-over-WS reference), Hiddify Manager SSH-proxy
  (closest shipped precedent).
```
