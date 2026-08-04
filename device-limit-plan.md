# Per-account device limits: analysis and solutions

Question: can we count an account's devices reliably (like RADIUS does) for the
Xray-native protocols, including when devices share one public IP behind NAT?

Short answer: **not by inspecting traffic. Not hard, foreclosed.** But the
picture is worse and more interesting than that, in three ways: the feature we
have today does nothing at all, three of our protocols have the exact flaw we
object to, and there is one real per-device field in VLESS nobody uses.

## 1. What is actually shipping today (all verified in-tree)

### limitIp is not a bad limiter. It is not a limiter.

- `web/service/config.json:3` ships `"access": "none"`.
- `web/service/setting.go:689`: `return (accessLogPath != "none" && accessLogPath != ""), nil`.
  So `GetIpLimitEnable` is FALSE on a default install and the whole UI is off.
- **No fail2ban jail ships.** Zero hits for `failregex` / `filter.d` /
  `jail.local` anywhere outside a Go comment. Upstream's `x-ui.sh iplimit`
  installer does not exist in `vpn-ui.sh`.
- **The kill path cannot kill.** `disconnectClientTemporarily`
  (`web/job/check_client_ip_job.go:451`) calls `RemoveUser` -> `validator.Del`,
  but the validator is consulted exactly once per connection, at handshake
  (`proxy/vless/encoding/encoding.go` `DecodeRequestHeader`). Established
  connections are untouched, and the user is re-added 100ms later.

Net: a log line nothing reads, plus a no-op, switched off by default.

### Three protocols already have the flaw we are objecting to

- `web/service/ssh_server.go:368`: *"A device is a distinct client source IP."*
- `web/service/mtproto.go:634`: *"The device cap IS delegated: telemt counts
  distinct client source IPs."*
- Xray-native: `check_client_ip_job.go` regexes the access log into
  `email -> IP -> timestamp`, discarding the source port.

### wg-c has no device limit at all, and its comments claim otherwise

- `wgc.go:114-120`: `wgcClient` has ONE keypair (`PrivKey`/`PubKey`/`Psk`,
  singular strings, no slice).
- `wgc.go:320-325` `buildPeers`: *"ONE peer per enabled, non-disabled account
  (gateway model)"*, AllowedIPs = the whole block.
- `wgc.go:796-805`: `byPub` is keyed by `client.PubKey`, one entry per account,
  so `Poll` can never return more than one live session per account.

But:

- `wgc.go:41-43` claims *"User Limit K materializes as K device peers (K
  keypairs...)"*.
- `wgc.go:748-750` claims *"K-limit is structural here (an account has exactly K
  device peers), so TrimToLimit rarely acts"*.

Both are FALSE against the code 280 lines below them. `TrimToLimit` cannot
"rarely act"; it can never act. K only SIZES the CIDR (User Limit 0 = a /26 =
64 devices). Devices behind the customer's router are structurally invisible.
The gateway model is a deliberate delivery choice (one config for a router, per
commit `0a7ddf2b`), but the comments assert an enforcement property that does
not exist. **Fix the comments regardless of what else is decided.**

## 2. The honest reframe: sessions, not devices

Our tunnel protocols do NOT count devices either. They count SESSIONS that the
server itself assigned (a pppd unit via NAS-Port, or a distinct tunnel IP out of
the account's block). A travel router NATs 20 devices through ONE L2TP session
and we count 1.

So the real contrast is not "devices vs IPs". It is:

- **unforgeable server-assigned session counting** (works, NAT-immune), vs
- **client-observed IP counting** (broken in both directions).

That distinction is the whole result. Everything reliable in this codebase sits
on the first line; everything broken sits on the second.

## 3. Why traffic inspection cannot recover it

IP counting fails in BOTH directions, and the second is the dangerous one for a
CGNAT userbase:

- **Undercount**: K devices behind one NAT = 1 IP.
- **Overcount**: one phone roaming wifi -> LTE -> CGNAT looks like 3-5 devices,
  and fail2ban bans by address, so banning a carrier CGNAT egress **bans
  unrelated paying customers**.

Every alternative signal is dead:

- **IP ID (Bellovin, IMW 2002)**: RFC 6864 says implementations MUST ignore the
  ID of atomic datagrams and explicitly notes this *"can defeat the ability to
  count devices behind a NAT"*. Linux removed the global counter in 2014
  (`73f156a6e8c1`, `04ca6973f7c1`). Bellovin's own best case was "off by no more
  than one", on synthetic data, and Figure 4 shows 2 hosts counted as 3.
- **TCP timestamp clock skew (Kohno, TDSC 2005)**: Linux 4.10 randomizes the
  timestamp offset per 4-tuple (`95a22caee396`), and the commit message states
  the motive verbatim: *"jiffies based timestamps allow for easy inference of
  number of devices behind NAT translators"*. Apple XNU does the same
  (`t_ts_offset; /* Randomized timestamp offset to hide on-the-wire timestamp */`).
  Windows 10/11 do not send timestamps on client-initiated connections at all.
  Even where it survives: 4.87-6.41 bits of entropy, while one device's own skew
  drifts up to 7.33 ppm over 12h against 1 ppm bins.
- **p0f / TCP stack fingerprinting**: identifies the OS/stack, never the device.
  Two same-model iPhones on one wifi are byte-identical. Not hard: impossible.
  (`TCP_SAVE_SYN` does hand a Go server the raw SYN unprivileged, but it is one
  sample per connection of stack identity.)
- **JA3/JA4**: identify the application, not the device. And OUR OWN default
  makes this self-defeating: `transport/internet/tls/tls.go:181` returns
  `&utls.HelloChrome_Auto` for the empty fingerprint, so every default client
  emits a byte-identical ClientHello. Conversely `randomized` seeds a PRNG in
  `init()` (`tls.go:156-174`), so one device mints a fresh identity on every
  client restart. Both error directions ship today, and the panel exposes the
  choice as a user-facing dropdown.

**Nobody in the ecosystem does better, and one of them lies about it.** V2bX:
`IPLimit int \`json:"DeviceLimit"\`` (the config key says DeviceLimit, the field
is IPLimit). XrayR: email -> IP set. Hiddify: `devices` always empty, dead code.
Marzban/sing-box: nothing. Xray's own `OnlineMap` is `AddIP`/`RemoveIP`/`Count`,
with no device concept at all.

**Commercial practice confirms it**: Mullvad issues a WireGuard keypair per
device and refuses the 6th at LOGIN (`MAX_DEVICES_REACHED`); Tailscale registers
a keypair per node. The most privacy-focused providers, running their own
infrastructure, enforce at key registration and never infer from traffic.

## 4. The one real counterexample: VLESS `vlessRoute`

This is genuine, upstream, and NAT-immune. Verified:

    // proxy/vless/validator.go:21
    func ProcessUUID(id [16]byte) [16]byte { id[6] = 0; id[7] = 0; return id }
    // :42  v.users.Store(ProcessUUID(...), u)
    // :63  u, _ := v.users.Load(ProcessUUID(id))

    // proxy/vless/inbound/inbound.go:538
    inbound.VlessRoute = net.PortFromBytes(userSentID[6:8])

    // common/session/session.go:50-51
    VlessRoute net.Port

Bytes 6-7 of the UUID are zeroed BEFORE the account lookup but RETAINED on the
session. So one VLESS account has 65536 sub-identities, all authenticating as
that account, each visible per connection and reachable at the dispatcher (where
our speed limiter already hooks). Upstream, RPRX, PR #5009, Aug 2025, intended
for routing. `common/uuid` does no version/variant validation, so arbitrary
values parse.

**But it is CLIENT-ASSERTED, not server-assigned.** That is exactly the property
our tunnel protocols rely on: pppd hands out a NAS-Port and the client cannot
refuse it. A user who wants to beat a `vlessRoute` cap sets both devices to the
same bytes 6-7 and collapses to one. It counts HONEST devices; it does not
enforce against dishonest ones.

Ship it as honest per-device ACCOUNTING for cooperative clients if we want it.
Do not call it a device limit. That naming drift is exactly what Hiddify's and
V2bX's history documents.

Untested: whether third-party clients (v2rayN, Nekobox) accept non-standard
UUIDs. Xray's own parser does.

## 5. Solutions, ranked

### 1. Shared per-account speed bucket (SHIPPED, keep as the primary lever)

NAT-invariant, zero false positives, zero cost, already enforced per email. It
does not detect sharing, it PRICES it: 5 people splitting 5 Mbit is
self-limiting, and behaves identically behind NAT and not. Sell K-device tiers
as BANDWIDTH tiers.

Weakness, stated plainly: it does not stop a reseller happy with 1 Mbit/head. It
is a business model, not enforcement. It is also the only option with a zero
false-positive rate and zero implementation cost.

### 2. Per-account concurrent-stream cap (NEW, small)

NAT-proof, precisely countable, and the same shape as the speed limiter: same
sidecar, same two dispatcher hooks, no panel data model. Set it generously
(~200) and advertise it as an ABUSE cap, never a device limit.

Caveats: it counts mux SUB-STREAMS, not TCP connections, so a mux client
inflates it; one browser is ~50-150 concurrent streams, so the threshold needs
instrumenting before it is chosen. `config.json:75-79` already blocks bittorrent,
which removes the biggest legitimate outlier.

### 3. Per-device credentials under one subId (~80% already built)

K credentials, K emails, one subId. NAT-correct because it never looks at an IP,
and zero false positives because nothing is inferred. Measures DISTINCT
CREDENTIALS IN CONCURRENT USE, not devices: copying config #1 to 5 phones defeats
it. It caps the convenient case, not the adversarial one.

Already exists: `subId` is a real one-to-many key (`sub/subService.go:117-131`
returns every inbound containing a client with that subId; `:63-89` emits a link
per client); `web/html/modals/inbound_modal.html`'s bulk modal already mints N
clients (min 1, max 500) sharing ONE subId with 5 naming schemes;
`CopyInboundClients` (`inbound.go:1231`) is a second prototype that even mints a
subId and writes it back; `genRemark` already labels each config; subscriptions
already deliver N configs to stock clients.

Missing: shared ENFORCEMENT.

- **MANDATORY PREREQUISITE**: our speed limiter keys buckets by email, so K
  emails = K buckets = **K x the bandwidth**. This silently REGRESSES solution 1.
  The fix is cheap because `index.byEmail` is `map[string]*Limits` (a map to a
  POINTER): add a `bucket` field to the sidecar and point all K emails at ONE
  `*Limits`. Empty = fall back to email, so it stays backward-compatible.
  **GOTCHA**: the vanished-account loop re-rates `prev.byEmail` entries to 0 and
  would visit the same `*Limits` K times. It must dedupe by pointer, or a
  departed sibling opens a still-active bucket to unlimited.
- Quota/expiry must aggregate: `disableInvalidClients` (`inbound.go:2364`) is a
  row-local SQL predicate (`up + down >= total`), `autoRenewClients` (`:2185`)
  renews each row independently, and the traffic multiplier is fed per-row usage.
- **The genuine gap**: there is NO accounts table. `totalGB`/`expiryTime` live
  per-client inside settings JSON. A parent quota needs a new table or an
  authoritative-member convention.
- Do NOT relax `client_traffics.email UNIQUE` (`xray/client_traffic.go:13`); it
  is the only thing guarding `ImportDB`. Add an indexed non-unique `parent_id`
  beside it. Usage stays per-email (correct); only LIMITS move to the parent.
- `subId` is currently unvalidated and unindexed: a typo silently merges a client
  into someone else's subscription. Validate and index it first.

### 4. VLESS vlessRoute sub-UUIDs (accounting, not enforcement)

See section 4. Honest per-device visibility for cooperative clients. Beats IP
counting, survives NAT, forgeable. Needs a patch to count it (not logged, not in
stats).

### 5. Protocols that assign identity (wg-c device peers / IKEv2 EAP)

Structurally correct, same reason our tunnels work. WireGuard has a property
credentials lack: a peer has ONE current endpoint, so two devices sharing a
keypair flap the endpoint and both degrade to unusable. De facto, not
cryptographic, but it is why per-peer keys limit devices while per-device UUIDs
limit only credentials.

The decisive objection is not technical: WireGuard and IKEv2 are DPI-identified
and blocked on the networks our users are on, which is the entire reason
VLESS/REALITY exists in this panel. Correct answer, wrong country. Offer it; do
not plan on uptake. (Xray's own WG inbound is NOT the path: its `PeerConfig` has
no email, so no quota keying at all.)

### 6. Behavioural detection: admin FLAG only, never an automatic action

No threshold has a false-positive rate low enough to disconnect a paying
customer, and "impossible travel" is meaningless when CGNAT already teleports one
phone across ASNs. Legitimate as "this account looks shared, review it".

### 7. In-core IP counting to replace fail2ban: DELETE instead

The core already exposes `GetStatsOnlineIpList` / `GetAllOnlineUsers`
(`app/stats/command/command.go:63,82`) over gRPC, fed by a refcounted OnlineMap,
needing only `statsUserOnline` in the policy template. So this is cheap, needs no
core patch, and is EXACTLY as wrong. It is a strictly better implementation of a
broken idea. Port it as telemetry if we want the log scraper gone; never wire it
to a ban.

### 8. Client-side device ID: reject

Impossible with stock clients (v2rayN/v2rayNG/Streisand send the credential and
nothing else; there is no field to carry a device ID and no plugin surface). It
means shipping and maintaining a custom client per platform, and the ID would
still be client-asserted and forgeable.

## 6. The prerequisite nobody noticed

**We cannot currently kick a live connection.** The validator is read once at
handshake, so `RemoveUser` only prevents NEW connections. Any enforcement story
at all (including today's limitIp, and any future stream cap) needs a real kill
path first, and that is a core patch. Worth knowing before promising anyone
enforcement.

## 7. Recommendation

**Hybrid: 1 + 2 + 3.** Do not build a "device limit" for Xray-native protocols;
build a sharing-cost curve.

K credentials give a NAT-proof, zero-false-positive PRODUCT boundary. The shared
bucket and the stream cap make copying one credential onto 5 devices
self-defeating rather than punished: the 6th device is not banned, it gets 1/6th
of the pipe and competes for streams. Nobody is ever wrongly disconnected,
because nothing ever disconnects.

Then fix the untruths, which cost nothing and are the root of the distrust:

- `wgc.go:41` and `wgc.go:749` claim a K-peer enforcement that does not exist.
- SSH and mtproto call an IP count a "device" cap.
- limitIp is presented as a limit while being off by default, jail-less, and
  unable to disconnect anyone.

**Impossible (do not re-litigate)**: counting devices behind one NAT for
stock-client proxy protocols. Foreclosed by RFC 6864 and by kernel commits
written specifically to prevent it.

**Merely hard**: a shared quota/speed/expiry pool across K credentials; a
per-account stream cap; device-model wg-c peers; a working kill path.

## 8. Open questions before building

- Concurrent-stream distribution for OUR users. The ~50-150/browser and ~200 cap
  numbers are engineering estimates, not measurements. Instrument first.
- Mux adoption among our users, which directly scales any stream cap.
- Whether stock clients accept non-standard-version UUIDs (for vlessRoute).
