# Per-user speed limiting

Question asked: is it possible to limit a user's speed (e.g. 5 Mbit down /
2 Mbit up per account) across our protocols?

Answer: yes, and this fork is in an unusually strong position to do it. Nothing
exists today (`grep` for speedLimit/rateLimit/bandwidth across the repo: zero
hits outside vendored code). This is greenfield.

## The one fact that decides the design

Every protocol converges on Xray, carrying a per-account identity:

- The 7 tunnel protocols (l2tp, pptp, openvpn, openconnect, sstp, ikev2, wg-c)
  are TPROXY'd into paired dokodemo-door inbounds. Identity = the client's
  source IP, which we ASSIGN ourselves.
- mtproto and ssh egress through a paired SOCKS inbound whose username is the
  account email (`mtproto.go:271-291`, `ssh_socks.go:25`).
- Native Xray protocols (vless/vmess/trojan/ss) carry the user natively.

`BuildVpnEmailToIPMap()` (`radius.go:1352`) is already the canonical, DB-derived
email -> IPs/CIDRs map, and already drives Xray's routing
(`translateVpnRoutingRules`, `xray.go:352`). A speed limiter needs exactly that
map and nothing more.

This matters because per-account IP OWNERSHIP is what makes IP-keyed shaping
exact here. The best-known 3x-ui community tool (myxeni64b/xui-bw-guard, bash +
tc + HTB + IFB) states its own fatal flaw in its README: it shapes per PUBLIC
IP, so it "does not solve fairness for many users behind the same NAT IP". We
do not have that problem, because we hand out the addresses.

## Prior art (researched, not assumed)

- Xray-core has NO native rate limiting, in any version. `policy.levels`
  `uplinkOnly`/`downlinkOnly` are half-close linger timeouts, NOT rate limits
  and NOT idle timeouts (`connIdle` is the idle timeout). Feature requests
  #415, #3667, #4567, #4643 all closed "not planned". PR #6050 (speed limiter)
  is OPEN, reopened by RPRX, but his stated motivation is per-app throttling in
  the Xray CLIENT, not server-side per-user limits for panels. Do not
  architect around it landing.
- 3x-ui has no speed limit and has declined it repeatedly (#2934, #3368, #5195,
  all "not planned"). `limitIp`/`totalGB`/`expiryTime`/`reset` are all quota or
  ACL, never rate.
- Marzban, Marzneshin, sing-box: none. (Hiddify doing tc could NOT be confirmed;
  treat that belief as unsubstantiated.)
- XrayR / V2bX ARE the real prior art and they do exactly what is proposed
  below: fork Xray's dispatcher and wrap the link writers with a token bucket.

## Recommended design: patch the dispatcher in our Xray fork

We already maintain `Sir-MmD/Xray-core` as a pinned submodule with a custom
patch, built by `build/core/build.sh`. The seam is stable and tiny.

### TWO seams, not one. This is the thing to get right.

The dispatcher has two independent entry points, and the protocol set is split
almost evenly between them. Patching only one silently misses half of
everything, including VLESS and every VPN protocol.

| Entry point | Wrapper | Used by |
|---|---|---|
| `Dispatch()` :267 -> `getLink()` :140 | `getLink` | vmess :281, trojan :333, shadowsocks :240 |
| `DispatchLink()` :324 -> `WrapLink()` :189 | `WrapLink` | **vless :633**, **socks :163**, **dokodemo :193**, mux :64, wireguard :161, hysteria :141, http :195 |

Consequences worth stating plainly:

- **dokodemo uses ONLY `DispatchLink`** (`dokodemo.go:193`, no `Dispatch` call
  anywhere in the file). So ALL 7 VPN tunnel protocols flow through `WrapLink`.
- **vless, the flagship Xray protocol, also uses `DispatchLink`.** So does socks,
  which is how ssh and mtproto arrive.
- V2bX / PR-6050 patch `getLink` ONLY. Ported verbatim to this Xray version,
  that limiter would not fire for vless, socks, dokodemo, or mux. It would cover
  vmess/trojan/shadowsocks and nothing else. Do not copy it blindly.

Both functions carry the IDENTICAL guard `if user != nil && len(user.Email) > 0`
(`:161` and `:197`), so the patch is symmetric. Only the wrap points differ:

- `getLink` wraps two Writers: `inboundLink.Writer` (uplink) and
  `outboundLink.Writer` (downlink).
- `WrapLink` is asymmetric: uplink is counted on the READER
  (`link.Reader.(*buf.TimeoutWrapperReader).Counter`), downlink on the WRITER
  (`link.Writer` via `SizeStatWriter`).

So the patch needs BOTH a rate-limited `buf.Writer` and a rate-limited
`buf.Reader`, not just a writer. Direction semantics in `DispatchLink` are:
`link.Reader` = client -> upstream = UPLOAD, `link.Writer` = upstream -> client
= DOWNLOAD.

MUX caveat to test, not assume: muxed traffic may traverse `Dispatch` for the
outer connection and `DispatchLink` per inner substream, with the same user in
both contexts. Limiting at both seams could then throttle muxed users twice.
Same rate applied twice is not catastrophic (the outer binds first) but it is
wasteful and risks head-of-line stalls. Measure before shipping.

### The seams

`third_party/Xray-core/app/dispatcher/default.go`, `getLink()`:

    sessionInbound := session.InboundFromContext(ctx)
    var user *protocol.MemoryUser
    if sessionInbound != nil { user = sessionInbound.User }
    if user != nil && len(user.Email) > 0 {   // <- line 161, the whole hook
        ... statsUserUplink / statsUserDownlink wrapping ...
    }

`inboundLink.Writer` (uplink, client->upstream) and `outboundLink.Writer`
(downlink, upstream->client) are the wrap points, exactly where the existing
per-user stats counters attach. Both directions are already separated, which
maps 1:1 onto "5 down / 2 up".

### The key is EMAIL, for every protocol

The limiter bucket is keyed by account email, universally. Source IP is only a
LOOKUP STEP for the tunnel protocols, never the bucket key. Consequence: an
account's K devices share ONE bucket, so the limit is per account, which is the
honest reading of "limit this user to 5 Mbit".

What makes this cheap is that dokodemo ALREADY allocates the user object:

    // proxy/dokodemo/dokodemo.go:138-142
    inbound := session.InboundFromContext(ctx)
    inbound.Name = "dokodemo-door"
    inbound.CanSpliceCopy = 1
    inbound.User = &protocol.MemoryUser{
        Level: d.config.UserLevel,
    }

So `user` is NOT nil for tunnel traffic. What is empty is `user.Email`. The
dispatcher guard `if user != nil && len(user.Email) > 0` (line 161) fails on the
EMAIL check, not the nil check. And socks already fills the email in
(`proxy/socks/server.go:142`: `inbound.User.Email = request.User.Email`), which
is how ssh and mtproto arrive.

So the resolution is:

- email already present (native Xray, ssh, mtproto) -> use it.
- email empty (the 7 tunnel protocols) -> resolve
  `sessionInbound.Source.Address.IP()` through the IP/CIDR -> email map, then
  key by the resolved email.

`sessionInbound.Source.Address` is already available in `getLink` (line 185 uses
it for `trackOnlineIP`), so this costs no new plumbing inside Xray.

Lookup must be prefix-based, not exact-match: ikev2 psk/eap-tls maps the account
to a whole block CIDR (`radius.go:1401`), and wg-c owns an aligned block
(`radius.go:1409`). Both are still 1:1 with an account (`ikev2.go:1073`:
`settings.Clients[0] // psk/eap-tls = exactly one account per inbound`), so
CIDR granularity is correct there, not a compromise.

### Resolve in the limiter, do NOT write the email back onto the user

Tempting alternative: patch dokodemo to SET `inbound.User.Email` from the map,
so the existing `user != nil && Email != ""` block lights up and everything
downstream "just works" with no second lane. Rejected. It has real blast radius:

- Policy level 0 has `statsUserUplink/statsUserDownlink: true`
  (`web/service/config.json:44-49`). A non-empty Email would make Xray start
  emitting `user>>>email>>>traffic>>>uplink` counters for VPN accounts, which
  `web/job/xray_traffic_job.go` would then ADD to `client_traffics` on top of
  the nft/RADIUS-derived usage. Silent DOUBLE COUNTING of every VPN user's
  quota. (Containable via a dedicated dokodemo `userLevel` with stats off, but
  it is a trap waiting for whoever forgets.)
- It changes routing semantics. Routing `user` rules would start matching VPN
  clients natively, which is the exact thing `translateVpnRoutingRules`
  (`xray.go:352`) exists to work around.

Keep the resolution INSIDE the limiter: read the email, never assign it. Zero
blast radius on stats, routing, or the access log.

Related trap if this is ever revisited: do NOT set `Email` on the
`log.AccessMessage` either. dokodemo deliberately does not
(`dokodemo.go:145-150`), and `web/job/check_client_ip_job.go` tails the access
log counting IPs per email to drive fail2ban for `limitIp`. Emitting emails
there would start applying limitIp/fail2ban bans to VPN accounts, which already
have their own User-Limit K mechanism.

### Feeding limits into Xray

One new config section in the fork's `infra/conf`, built directly from
`BuildVpnEmailToIPMap()` + the client model. Email is the primary key, so the
IPs are just an index onto it:

    {
      "users": [
        {"email": "a@x", "downBps": 655360, "upBps": 262144,
         "ips": ["10.0.0.5/32", "10.0.0.6/32"]},
        {"email": "b@x", "downBps": 1310720, "upBps": 0,
         "ips": ["10.7.8.8/29"]}
      ]
    }

Rates are BYTES PER SECOND (converted once at the panel edge from the UI's
KB/s). `0` means that direction is unlimited, so `b@x` above is
download-limited only. An account that is entirely unlimited is simply ABSENT
from the file.

Xray builds two indexes from it: `email -> *limiter`, and a prefix trie
`IP/CIDR -> email`. Accounts with no limit are simply absent (nil = unlimited),
so the common case allocates nothing and the hot path is one map miss.

Entries with no `ips` (ssh, mtproto, native) still work: their email arrives on
the session, so they never touch the trie.

### Delivery: a hot-reloaded sidecar file (DECIDED)

The sidecar path is passed by ENV VAR, not through the Xray config:

    XRAY_SPEEDLIMIT_FILE=<bindir>/speedlimits.json

This is deliberate and it matters for rebase cost. Adding a top-level
`"speedLimit"` section to the config would mean touching `infra/conf` (the
`Config` struct + `Build()`), and Xray's app configs are protobuf `Any` values,
so a non-protobuf side-channel there is awkward and drags in codegen. An env var
touches NOTHING in `infra/conf`. The panel already builds Xray's command line in
`xray/process.go` `Start()`, so setting `cmd.Env` is a one-line panel change.

Net effect: the entire fork patch is ONE new self-contained package plus TWO
small edits in `app/dispatcher/default.go`. That is the whole divergence to
rebase on every Xray bump, which is the deciding constraint (the fork currently
carries a single 8-line patch, `0e9ecf66`).

The patched core loads that file at startup and RELOADS it when its mtime
changes (poll on a short interval; no fsnotify dependency). The panel rewrites
it atomically (`backend.WriteFileAtomic`, `backend/backend.go:158`) whenever the
effective limits change.

Writing the sidecar MUST NOT mark the Xray config dirty, or every threshold
crossing triggers the debounced restart this design exists to avoid. Check
`isNeedXrayRestart` / `SetToNeedRestart` and keep the sidecar write off that path.

Rejected alternatives:

1. Limits inline in the Xray config. Every "Limit After" crossing would rewrite
   the config and restart Xray, dropping every connection on the box. Fatal for
   this feature specifically.
2. gRPC `SetSpeedLimit` on the existing API (62790). Correct and idiomatic, but
   needs a .proto, protoc codegen in `build/core/build.sh`, and service
   registration, i.e. real toolchain risk in the build for no user-visible gain
   over a watched file. Revisit only if the file proves inadequate.

Note the panel, not Xray, evaluates "Limit After". Xray receives only the
already-resolved effective rate and stays dumb. This keeps quota semantics
(resets, VPN usage sourced from nft/RADIUS rather than Xray stats) in the one
place that already understands them.

## Why not the alternatives

### Kernel tc / HTB (rejected as the primary mechanism)

Structurally wrong for this data plane, not merely complex:

- UPLOAD never egresses. TPROXY delivers the client's packets to a LOCAL socket,
  so there is no egress qdisc to attach to. Upload would need ingress + IFB
  redirect, per interface.
- DOWNLOAD egresses PER-SESSION interfaces. `ppp0..N` is one netdev per
  connected device (l2tp/pptp/sstp), plus `tun*`, `ocserv-<id>`, `wgc<id>`.
  IKEv2 has NO netdev at all (XFRM/charon, `ikev2.go:812`). A static tc setup
  cannot cover that; it needs dynamic per-interface hooks (ip-up scripts).
- No tc infrastructure exists in the repo today (zero hits), and it would need a
  new teardown path in `uninstall.go`.

If it were ever revisited, the right shape (from the research) is an nft map
setting `meta priority` in POSTROUTING plus HTB leaf classes and ZERO tc
filters, since `htb_classify()` shortcuts on `skb->priority`. Two traps: use a
plain hash set (NOT `flags interval`, which forces rbtree/pipapo and O(log n)),
and note `net.ipv4.ip_forward_update_priority` defaults to 1 and clobbers
`skb->priority` in `ip_forward()` (this does not hit the Xray path, which never
forwards, but DOES hit the Cross-Inbound rules that deliberately bypass TPROXY).
Also: marks `0x1` and `0xff` are already taken (`nftables.go`, `l2tp.go:124`).

Note the real ceiling is not the classifier: sch_htb/tbf/cake all serialize on
the global qdisc root lock and do not scale across cores (netdev 0x19, 2025).
Xray's userspace crypto would hit that wall first anyway.

### nft `limit rate over ... drop` (viable MVP, rejected as primary)

A pure-nft policer keyed on `ip saddr`/`ip daddr` in the EXISTING `*_acct`
chains would be ~50 lines, mirror `AddClientAccounting` (`nftables.go:525`)
exactly, and need zero new dependencies (nft 1.1.6 present). It is genuinely
tempting as a first cut.

Rejected as primary because it POLICES (drops) rather than SHAPES (queues),
giving TCP sawtooth behaviour, and it covers only the 7 tunnel protocols, so
ssh/mtproto/native still need a second mechanism.

### Per-daemon native shapers (rejected as primary, but see below)

Real, and closer than expected. Verified against the actual bundles:

- accel-ppp (SSTP): has a native `shaper` module using netlink directly (no tc
  binary needed). `libshaper.so` IS ALREADY in
  `backend/bin/amd64/accel-ppp-bundle.tgz`; the live config just does not load
  it. Driven by RADIUS Filter-Id (its default attr), which our in-binary Go
  RADIUS can set today via `rfc2865.FilterID_SetString`. Rate changes
  mid-session via CoA or `accel-cmd shaper change`, which fits the accel-cmd
  plumbing already used for eviction.
- ocserv (OpenConnect): native RADIUS speed limit since 1.2.4; we bundle 1.3.0.
  It is implemented in the radius supplemental-config module, so it requires
  `groupconfig=true`, which `openconnect.go:296` ALREADY sets.
- pppd (l2tp/pptp), OpenVPN 2.6, strongSwan, WireGuard: NO native rate limiting.
  (OpenVPN's `--shaper` is a hard error in server mode.)

So the native route reaches 2 of 10 protocols, with mutually inconsistent
semantics (accel-ppp queues via tbf/htb, ocserv drops), and would leave three
different mechanisms to support. Since ALL of that traffic ALSO transits Xray,
one limiter in the dispatcher supersedes both.

Traps recorded for whoever revisits this:
- ocserv's RADIUS units are undocumented and 1000x off the config file:
  `sup-config/radius.c` assigns the integer straight through with no division,
  while `config.c` divides by 1000. So `RP-Upstream-Speed-Limit` is kB/s while
  `rx-data-per-sec` is B/s. Verify empirically.
- radcli SILENTLY drops undefined VSAs. Our generated dictionary
  (`radius.go:1589`) defines only Microsoft/311; vendor 10055 attrs 1/2 must be
  added or they vanish with no error (same class of bug as the Connect-Info/77
  one already documented there).
- accel-ppp's `G` suffix looks like a 10x upstream bug (`G=10000000.0`, should
  be 1e6). Use `M`.
- `libl2tp.so` and `libpptp.so` are ALSO already in the accel-ppp bundle. If
  l2tp/pptp ever migrate off xl2tpd/pptpd+pppd onto accel-ppp, they inherit
  native shaping for free. Worth noting, out of scope here.

## Coverage under the recommended design

Bucket key is ALWAYS the account email. The middle column is only how the email
is obtained.

Bucket key is ALWAYS the account email. This covers the Xray-native protocols
and the 10 VPN protocols with ONE mechanism, because the dispatcher is
downstream of every inbound.

Panel numbering: protocol 1 is Xray itself, then 2 l2tp, 3 pptp, 4 openvpn,
5 openconnect, 6 sstp, 7 ikev2, 8 wg-c, 9 mtproto, 10 ssh.

Xray-native family (`model.go:16-38`):

| Protocol | Seam | Email | Identity |
|---|---|---|---|
| vmess | `getLink` | already set | native |
| trojan | `getLink` | already set | native |
| shadowsocks | `getLink` | already set | native |
| vless | `WrapLink` | already set | native |
| http, mixed | both | already set | native |
| tunnel (dokodemo) | `WrapLink` | already set / n/a | operator-created |
| wireguard (Xray's own) | `WrapLink` | already set | native |
| hysteria, hysteria2 | `WrapLink` | already set | native |

The 9 VPN protocols this fork adds:

| Protocol | Seam | Email obtained via | Identity |
|---|---|---|---|
| ssh, mtproto | `WrapLink` (socks) | already set | SOCKS username |
| l2tp, pptp, openvpn, openconnect, sstp | `WrapLink` (dokodemo) | IP lookup | K owned /32s |
| ikev2 (eap-mschapv2) | `WrapLink` (dokodemo) | IP lookup | K owned /32s |
| ikev2 (psk, eap-tls) | `WrapLink` (dokodemo) | CIDR lookup | block CIDR, 1 account/inbound |
| wg-c | `WrapLink` (dokodemo) | CIDR lookup | aligned CIDR, `wgcEffectiveK` 0 = /26 |

Xray-native protocols are NOT an afterthought here: they carry the email already,
so they need no lookup and come out of the same patch for free. The extra work is
entirely on the VPN side (the IP -> email trie).

`Dispatch` + `DispatchLink` together are the universal funnel: EVERY inbound
proxy in the tree calls one or the other. That is what makes "one mechanism, all
protocols" true rather than aspirational.

Caveat (mtproto): adtag XOR xray-routing. An mtproto inbound using adtag does
NOT route through Xray, so it cannot be limited this way. Document it.

Caveat (all tunnel protocols): Cross-Inbound and client-to-client rules
deliberately bypass TPROXY (`nftables.go:87`, `:118`), so user-to-user LAN
traffic is not shaped. Acceptable; it never leaves the box.

## SSH: a cheaper independent option

`ssh_server.go:352` `copyCount()` is an in-process io.Copy with up/down already
split (`:334` upload, `:341` download), plus two UDP sites that bypass it
(`ssh_udpgw.go:184`, `:224`). A shared `*rate.Limiter` on `sshAcct`
(`ssh_server.go:44`, resolved per email by `acctFor`, `:426`) is ~20 lines and
needs no fork patch at all.

Worth doing regardless, as a way to validate the UI/model end to end before
touching the Xray fork. But long term, one mechanism beats two.

## Direction semantics: SPLIT, not combined

The two directions are physically separate objects at BOTH seams, so separate
down/up limits are the natural design and cost nothing extra:

- `getLink`: `inboundLink.Writer` = uplink, `outboundLink.Writer` = downlink.
  Two distinct writers.
- `WrapLink`: `link.Reader` = uplink, `link.Writer` = downlink. Two distinct
  objects (this is the asymmetric one, see above).

So: TWO limiters per account, keyed `"up:"+email` and `"down:"+email`. Each is
independently nil = unlimited. That gives all four states for free:

- down set, up nil  -> download-limited only
- up set, down nil  -> upload-limited only
- both set          -> limited separately, at different rates
- both nil          -> unlimited (allocates nothing, one map miss on the hot path)

Do NOT copy V2bX here: it shares ONE bucket across both directions, so its
"limit" is the COMBINED up+down throughput. That surprises people and cannot
express "5 down / 2 up". PR-6050 keys `direction + ":" + email`, which is what
we want.

### Not per connection

The bucket is per ACCOUNT, shared across every connection that account has open.
A user opening 50 TCP streams still gets one 5 Mbit ceiling, not 50 of them.
That sharing IS the feature, and it is why the limiter must be a long-lived
`map[key]*rate.Limiter`, not something constructed per connection (one of the
two V2bX bugs listed below).

## Data model (FINAL, as specified)

PER-INBOUND ONLY. There are no per-client speed fields in this iteration. The
limiter is CONFIGURED per inbound and ENFORCED per email: every account on that
inbound gets its OWN bucket at that rate. It is not a shared pool for the
inbound.

### DB COLUMNS, not settings JSON. `trafficMultiplier` is the precedent.

`userLimit` is the WRONG model to copy. The right one is `trafficMultiplier*`
(`database/model/model.go:121-123`), which is already a per-inbound, panel-only,
protocol-agnostic setting with an enable toggle + an apply-after threshold + a
value:

    TrafficMultiplierEnable bool    `json:"..." form:"..." gorm:"default:0"`
    TrafficMultiplierAfter  int64   `json:"..." form:"..." gorm:"default:0"`
    TrafficMultiplier       float64 `json:"..." form:"..." gorm:"default:1"`

So, new columns on `model.Inbound` beside them:

    SpeedLimitEnable   bool  `gorm:"default:0"` // master toggle
    SpeedLimitSeparate bool  `gorm:"default:0"` // false = one box for both
    SpeedLimitDown     int   `gorm:"default:0"` // KB/s, 0 = unlimited
    SpeedLimitUp       int   `gorm:"default:0"` // KB/s, 0 = unlimited
    SpeedLimitAfter    int64 `gorm:"default:0"` // BYTES, 0 = apply immediately

Why columns and not settings JSON, which is what an earlier draft said:

- This must cover the Xray-NATIVE protocols too, and those have no shared
  per-protocol form. `trafficMultiplier` renders in ONE shared block in
  `web/html/form/inbound.html:208-252`, above the per-protocol includes
  (`:380-430`). Columns get all 13 protocols from one form. The settings-JSON
  route would mean editing 8+ per-protocol forms and 8+ JS `fromJson`/`toJson`
  triplets in `web/assets/js/model/inbound.js`.
- Inbound settings are passed VERBATIM to Xray for native protocols
  (`model.go:170`). `web/service/xray.go:137` skips the 9 VPN protocols entirely,
  which is the only reason `userLimit`-in-settings is safe for those and nowhere
  else. Top-level settings keys are NOT stripped for native protocols (only
  `settings["clients"]` is rewritten, `xray.go:174-181`), so a top-level
  `speedLimitEnable` on a vless inbound would reach Xray raw. It would not be
  rejected (Xray never sets `DisallowUnknownFields`, `serial/loader.go:52`), but
  relying on decoder leniency is not a contract, and it pollutes the config.
- Schema lands via `AutoMigrate` (`database/db.go:45`), no manual migration,
  PROVIDED every column has a `gorm:"default:"`.

`SpeedLimitAfter` is stored in BYTES and exposed as GB by a UI-only computed
accessor, exactly like `trafficMultiplierAfter`. Precedent to copy verbatim:
`web/assets/js/model/dbinbound.js:43-49` (`get/set trafficMultiplierAfterGB`),
with the raw column defaults declared in the ctor at `dbinbound.js:15-17`.

### The trap that will silently eat these fields

The inbound POST payload is enumerated BY HAND in five JS places plus one Go
place. Missing any one means the field vanishes with NO error:

1. `web/html/modals/inbound_modal.html:765-767`
2. `web/html/inbounds.html:1839-1841` (clone)
3. `web/html/inbounds.html:1904-1906`
4. `web/html/inbounds.html:1933-1935`
5. `web/html/inbounds.html:2183-2185`
6. `web/service/inbound.go:719-721` (`UpdateInbound` copies field-by-field onto
   `oldInbound`; omit it and edits never persist)

`speedLimitSeparate == false`: the single box value applies to EACH direction
independently (down and up are each capped at it). It does NOT mean a combined
up+down bucket. Store it in `speedLimitDown` and mirror to up at resolve time,
so the wire format stays one shape.

Resolution per email (`effectiveSpeedLimit`, mirroring `effectiveUserLimit`
`vpnrange.go:684`):

1. inbound `speedLimitEnable` false -> unlimited, stop.
2. usage < `speedLimitAfterGB` -> unlimited (not yet armed).
3. else -> {down, up}, with 0 in either meaning that direction is unlimited.

### Units

UI is KB/s (as specified). 1 KB = 1024 bytes. Convert ONCE at the panel edge to
bytes/s and keep every internal type and the sidecar file in bytes/s, so the
1024-vs-1000 question lives in exactly one function. `speedLimitAfterGB` is GB
= 1024^3 bytes, matching how `totalGB` is already handled.

### Limit After

The threshold is the account's CUMULATIVE used traffic (up+down) as the panel
already knows it in `client_traffics`. Below the threshold the account is
unlimited; at or above it, the limit applies. It MUST re-arm on traffic reset
(the per-client `reset` field / the periodic reset job), because a reset zeroes
usage and should restore full speed.

This is why the limits are delivered by a hot-reloaded sidecar file rather than
the Xray config: threshold crossings happen continuously as users consume data,
and an Xray restart per crossing would drop every connection on the box.

### The conflict to decide: one email, several inbounds

### The conflict to decide: one email, several inbounds

`BuildVpnEmailToIPMap` aggregates by email ACROSS inbounds
(`result[client.Email] = append(...)`, `radius.go:1352`). So the same email can
legitimately exist on two inbounds (e.g. one l2tp account and one vless config
for the same person) with DIFFERENT per-inbound limits, while the bucket is
per-email and therefore shared.

Options:
- (a) MINIMUM non-zero wins (most restrictive). Simple, predictable, and matches
  V2bX's `determineSpeedLimit` precedent. RECOMMENDED.
- (b) Per `(email, inbound)` bucket. Rejected: a user on two inbounds would then
  get 2x their intended bandwidth, which defeats the per-account key.
- (c) Per-email only, inbound toggle merely gates whether that inbound's traffic
  is subject to the limiter. Rejected: makes the per-inbound values meaningless.

Go with (a) and document it in the UI helptext. Note the common case (an email
on exactly one inbound) has no conflict at all.

### UI

One shared block in `web/html/form/inbound.html`, appended after `:252`. Copy
the `trafficMultiplier` idiom at `:208-252` verbatim: an `a-form-item` whose
label slot is an `a-tooltip`, holding an `a-switch v-model=...`, followed by a
`<template v-if="...">` wrapping sibling `a-form-item`s for the reveal.

That idiom uses NO `a-row` and NO `a-space`, which sidesteps both known
antd-vue-1.7.8 layout gotchas (a-space has no wrap prop; a default a-row is a
float grid, not flex). Do not introduce either. Nesting `speedLimitSeparate`
inside `speedLimitEnable` is just a nested `<template v-if>`.

Bind with `v-model` on `a-switch` and `v-model.number` on `a-input-number`.
(Note the per-protocol `userLimit` rows use the `:value` + `@change` clamping
idiom instead; that is for clamping to a 1..64 range and is not needed here.)

Panel POSTs are form-urlencoded (axios Qs.stringify + `c.ShouldBind`), not JSON,
so every column needs a `form:` tag.

### i18n: the ratchet WILL fail the build

`web/i18n_toml_test.go:126` `TestTranslationKeyParity` fails for any en_US key
missing from a non-en_US locale and not baselined in `knownMissing` (`:45`).
There are 13 locales. So adding `pages.inbounds.speedLimit*` to en_US ALONE
breaks 12 locales.

Translate all 13. `trafficMultiplier*` is the model: it is present in every
locale (en_US block at `web/translation/translate.en_US.toml:407-412`), and the
convention is flat camelCase keys under `[pages.inbounds]` with paired `X` /
`XDesc` for label + tooltip.

Note the 8 per-protocol forms have ZERO i18n (hardcoded English). Do not take
that as license: `form/inbound.html` is fully i18n'd, and this block lives there.

## Implementation traps (Go side)

1. `golang.org/x/time/rate` is the right library (BSD-3, maintained,
   goroutine-safe, `SetLimit`/`SetBurst` at runtime). NOT `juju/ratelimit`,
   which V2bX uses: LGPL-3.0, unmaintained since 2019, and has no SetRate.
2. `WaitN` RETURNS AN ERROR if `n > burst`; it does not block and drain. Xray
   writes `buf.MultiBuffer`, so a large write against a small limit errors on
   every call. Set `burst >= max(1s of bytes, largest write)` or chunk writes.
   This is the single most common way this implementation goes wrong.
3. UDP must DROP, not delay: use `AllowN` and discard on false. Blocking a UDP
   path builds unbounded latency and reorders. (Xray's `bufferSize` already
   discards UDP on overflow, so this is consistent.)
4. One shared limiter per account across all its conns: `map[key]*rate.Limiter`
   under a mutex. V2bX has two bugs not to copy: it builds a throwaway bucket on
   every call, and it never re-rates a user when their limit changes.
5. Decide up/down semantics deliberately. V2bX shares ONE bucket for both
   directions, so its limit is combined, which surprises people. We want split
   (down and up are separate fields), i.e. key on `direction + account`.
6. Shaping counts payload bytes; wire overhead (encryption, padding, headers) is
   invisible at this layer, so a "10 Mbit" limit measures a few percent under
   true wire rate.

## Duplicate emails must be rejected

Email is the ENFORCEMENT KEY, so two clients sharing an email silently share one
bucket and one identity.

RESOLVED: global, case-insensitive uniqueness across ALL inbounds is ALREADY the
intended invariant. This is gap-closing, not a behavior change:

- `xray/client_traffic.go:9`: `Email string ... gorm:"unique"`. The index is on
  email ALONE, not `(inbound_id, email)`. Cross-inbound duplicates are already
  structurally impossible at the DB layer.
- `checkEmailsExistForClients` (`inbound.go:239`) and `getAllEmails`
  (`inbound.go:180`) are unscoped by design: no `WHERE inbound_id`.
- `nextAvailableCopiedEmail` (`inbound.go:1096`) DELIBERATELY renames a client to
  `email_<targetID>` when copying it to another inbound. The one first-class
  "same person, two inbounds" workflow in the codebase refuses to reuse the
  email. That settles it.
- Every traffic accessor is unscoped by inbound (`UpdateClientStat` `:2278`,
  `DelClientStat` `:2296`), so a collision would MERGE and clobber, not coexist.

Earlier worry, now retired: `BuildVpnEmailToIPMap`'s `append` is multi-value
WITHIN one inbound (one IP per enabled OpenVPN transport, K device IPs under
User Limit K>=2). It is not cross-inbound aggregation, so it is not evidence that
duplicate emails are a feature.

The gaps to close:

1. `UpdateInbound` (`inbound.go:615`) has NO email check at all, only a port
   check (`:627`). This is the main hole.
2. `checkEmailExistForInbound` (`:259`) is correct only for NEW inbounds: it
   compares an inbound's clients against all DB emails INCLUDING its own
   persisted row. Needs an ignore-id variant for the update path.
3. `UpdateInboundClient` (`:1363`) guards with a case-SENSITIVE `!=` while
   `contains` (`:194`) is case-INSENSITIVE, so renaming `Bob` -> `bob` self-
   collides and errors spuriously.
4. No `TrimSpace` anywhere, so `"bob"` and `"bob "` are distinct. Normalize ON
   WRITE, not compare-only: compare-only leaves both as distinct keys in
   `client_traffics`, which the unique index accepts, defeating the point.
5. `ImportDB` (`server.go:863`) replaces the SQLite file wholesale and is out of
   reach of any service hook. The `client_traffics.email` unique index is the
   only thing guarding it. Leave the index as the last line of defense.
6. Zero tests exist for email uniqueness. `admin_test.go:134-137`
   (`ErrAdminUsernameTaken`) is the style precedent and asserts exactly the
   case-folded-duplicate-refused case that is missing for clients.

`BulkUpdateClients` (`:1552`) needs NO hook: it never mutates email (verified).

## Build order

1. Data model + UI + `effectiveSpeedLimit` resolver, with the per-protocol
   decoder views updated.
2. SSH in-process limiter (`copyCount` + the 2 udpgw sites). Validates the model
   end to end with no fork patch.
3. Xray fork: patch BOTH `getLink` and `WrapLink`. Email key; resolve the email
   from source IP/CIDR when it is blank. Needs a rate-limited `buf.Writer` AND a
   rate-limited `buf.Reader` (WrapLink counts uplink on the Reader). Config
   field first.
4. Feed the IP/CIDR -> limit map from `BuildVpnEmailToIPMap`.
5. gRPC `SetSpeedLimit` if the restart-on-change proves annoying.
6. E2E per protocol (measure actual throughput, do not trust the config).
   Do NOT run incus E2E unless explicitly asked.

## Open questions to answer before building

- DECIDED: per ACCOUNT, keyed by email. An account's K devices share one bucket.
  Matches how totalGB behaves. If per-device is ever wanted, it becomes a
  secondary bucket keyed by `email + source IP`, nested under the account
  bucket, not a replacement for it.
- Xray fork rebase burden: the fork currently carries ONE 8-line patch
  (`0e9ecf66`, Shadowsocks cipher fallback) on v26.4.17. This adds a second,
  larger one to rebase on every core bump. Known cost, but real.
- Watch the documented submodule trap: `build.sh`'s `git submodule update` can
  silently rewind the fork and delete patches from an otherwise "successful"
  build.
