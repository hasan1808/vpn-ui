# Control-plane framework (cplane) - research and implementation plan

A light, parallel control-plane framework so non-RADIUS VPN protocols (WireGuard, later SSH-VPN,
MTProto, etc.) plug in by implementing a tiny adapter, instead of each one cloning the ~150-line
ikev2-local reconcile/enforce/account path. Mirrors the style of `ikev2-plan.md`.

STATUS: RESEARCH ONLY - HOLD FOR REVIEW. Nothing built yet.

## Decisions (proposed 2026-07-15)

1. **Light + parallel, not a rewrite.** New `web/service/cplane` package that runs ALONGSIDE an
   untouched RADIUS server, feeding the SAME session registry (`radius.s.sessions`) and the SAME
   accounting sinks (`client_traffics`, nft counters). The 6 RADIUS protocols are behavior-
   unchanged. RADIUS is NOT folded into the framework in this phase (that is the future "full
   unification", deferred until a 3rd non-RADIUS protocol proves the interface).
2. **Scope = the PULL / reconcile-sweep protocols only.** ikev2-local (psk/eap-tls) migrates onto
   the framework as the proof; ikev2-eap-mschapv2 stays on RADIUS + `killByUser`, untouched.
   WireGuard is adapter #1. RADIUS protocols (l2tp/pptp/openvpn/openconnect/sstp) keep their own
   synchronous auth + `KillDisabledSessions`/`DisableClients`.
3. **The framework owns the tick, the registry merge, quota/disable enforcement, and User-Limit
   K + strategy.** The adapter owns only: enumerate my live tunnels, tell me an inbound's limit,
   kill one tunnel. Three thin methods.
4. **One behavior-preserving cleanup rides along:** `NftService.CollectAndResetTraffic` becomes
   map-based (protocol-generic) instead of the current 6-arg/6-return signature, so adding a
   protocol never again grows that signature. Same nft chains, same logic, just iterated.

---

# Part 0 - Executive summary

- Today the per-tick control plane is hardcoded protocol-by-protocol in `web/job/xray_traffic_job.go`
  (`Run`): one `ReconcileLocalAuthSessions()` call, six `GetSessions()` calls, a 6-arg
  `CollectAndResetTraffic`, six `KillDisabledSessions()` calls. Adding a protocol edits all of it.
- Three things are duplicated or hardcoded and want extracting: (a) `getDisabledEmails()` is
  byte-identical in all 6 services; (b) the User-Limit K + strategy trim lives inline in
  `ikev2.ReconcileLocalAuthSessions`; (c) the registry-merge + nft fold-on-vanish lives in
  `radius.ReconcileIkev2LocalSessions`, hardcoded to `"ikev2"` and the `"ike:"` key prefix.
- The framework is mostly an EXTRACTION of these three, plus a small `Sweeper` that iterates
  registered adapters. Net new logic is small; the value is one tested enforcement engine instead
  of N copies, and a stable 3-method interface for every future non-RADIUS protocol.
- Risk is low because RADIUS and the 6 shipping protocols are untouched; the only shared-code edit
  is the behavior-preserving `CollectAndResetTraffic` generalization, which is unit-testable.
- Validation is built in: migrating ikev2-local onto the framework must reproduce its exact current
  behavior (same sessions billed, same evictions), which is the acceptance test for the extraction.

---

# Part 1 - The seams being extracted (current code -> framework)

| Current | Location | Becomes |
|---|---|---|
| `ikev2.ReconcileLocalAuthSessions` (poll SAs, attribute, quota-drop, K-trim, hand to registry) | `ikev2.go:932-1001` | split: adapter `Poll`/`Evict` + framework `Sweeper.Tick` |
| inline User-Limit K + strategy trim | `ikev2.go:978-995` | `cplane.TrimToLimit` (pure, unit-tested) |
| `radius.ReconcileIkev2LocalSessions` (registry merge + nft add/remove + fold-on-vanish) | `radius.go:514-558` | generalized `radius.ReconcileLocalSessions(protocol, desired)` |
| `getDisabledEmails` (identical x6) | `l2tp.go:286`, `ikev2.go:1073`, +4 | one `cplane` helper `DisabledEmails()` |
| `killIkev2ByID` / `ikev2ListSAs` (SA parser + kill) | `ikev2.go:896-922` | stays in ikev2 adapter (per-daemon, never clones) |
| `CollectAndResetTraffic(6 args) -> (6 returns)` | `nftables.go:556` | `CollectAndResetTraffic(map[proto]ipToEmail) -> []ClientTraffic` |
| hardcoded tick body | `xray_traffic_job.go:70-100` | `sweeper.Tick()` over registered adapters + map-based collect |

Reused as-is (already shared / protocol-generic): `effectiveUserLimit` (`vpnrange.go:674`),
`normUserLimitStrategy` (`vpnrange.go:245`), `nft.AddClientAccounting`/`RemoveClientAccounting`/
`ReadAndResetClientCounters` (`nftables.go:469/492/525`), `radiusSession` (`radius.go:75`),
`vpnrange.go` IP allocation, the whole Tier-B nft TPROXY -> dokodemo -> Xray data plane.

---

# Part 2 - The `cplane` package API

```go
package cplane // web/service/cplane

// Adapter is what a non-RADIUS, sweep-reconciled VPN protocol implements. Three thin methods.
// The framework owns the tick, registry merge, quota/disable enforcement, User-Limit + strategy.
type Adapter interface {
    Protocol() string                              // "ikev2", "wireguard"
    Poll() ([]Live, error)                         // live tunnels this tick, attributed to inbound+account
    Limit(inboundID int) (k int, strategy string)  // adapter parses its own settings for one inbound
    Evict(Live) error                              // terminate exactly one live tunnel (by DeviceKey)
}

// Live is one live tunnel the framework reconciles.
type Live struct {
    Protocol  string
    InboundID int
    Email     string    // account identity (attributes usage + routing)
    IP        string    // tunnel IP 10.N.x.x - the registry key AND the nft-counter key
    DeviceKey string    // opaque adapter handle for Evict (charon SA-id, wg pubkey, ...)
    Since     time.Time // arrival order, for oldest-first eviction
}

// Sink is the framework's write side into the EXISTING plane. Implemented by the current
// RadiusService (session registry + nft accounting), so ownership does NOT move in this phase.
type Sink interface {
    // ip->email survivors for one protocol: adds nft counters for new IPs, folds+removes for
    // vanished IPs (mirrors Acct-Stop), updates s.sessions. Generalized ReconcileIkev2LocalSessions.
    ReconcileLocalSessions(protocol string, desired map[string]string)
    // client_traffics.enable=false set (quota/expiry/disabled). The former per-service getDisabledEmails.
    DisabledEmails() map[string]bool
}

// Sweeper is registered with the traffic job and ticked once per collection cycle.
type Sweeper struct { /* adapters []Adapter; sink Sink */ }

func New(sink Sink) *Sweeper
func (sw *Sweeper) Register(a Adapter)

// Tick: for each adapter, poll live tunnels, enforce disable/quota + User-Limit K/strategy by
// calling Evict, then hand survivors to the sink. Runs in the traffic-job goroutine (never an
// auth handler), so adapters may call their daemon CLIs synchronously.
func (sw *Sweeper) Tick() {
    disabled := sw.sink.DisabledEmails()
    for _, a := range sw.adapters {
        live, err := a.Poll()
        if err != nil { continue }
        desired := map[string]string{}
        for inboundID, group := range groupByInbound(live) {
            // 1. disabled/over-quota account -> evict all, bill nothing further
            keep := group[:0]
            for _, s := range group {
                if disabled[s.Email] { _ = a.Evict(s); continue }
                keep = append(keep, s)
            }
            // 2. User-Limit K + strategy
            k, strat := a.Limit(inboundID)
            survivors, evicted := TrimToLimit(keep, k, strat)
            for _, s := range evicted { _ = a.Evict(s) }
            // 3. survivors -> registry/accounting
            for _, s := range survivors { desired[s.IP] = s.Email }
        }
        sw.sink.ReconcileLocalSessions(a.Protocol(), desired)
    }
}

// TrimToLimit is the pure, unit-tested User-Limit trim extracted verbatim from the ikev2 sweep:
// reject keeps the oldest K (kills newest); accept keeps the newest K (evicts oldest). k<=0 = no limit.
func TrimToLimit(sessions []Live, k int, strategy string) (survivors, evicted []Live)
```

Notes:
- The `Sink` is implemented by `RadiusService` (it already owns `s.sessions` and calls
  `nftService`), so this phase keeps session/accounting ownership exactly where it is. Only one
  method is generalized (`ReconcileIkev2LocalSessions` -> `ReconcileLocalSessions(protocol,...)`,
  parameterizing the `"ikev2"`/`"ike:"` constants by protocol).
- `DisabledEmails` on the sink is the single copy that replaces 6 `getDisabledEmails`.
- Live sessions are billed the normal way: their IPs are in `s.sessions` after
  `ReconcileLocalSessions`, so the map-based `CollectAndResetTraffic` reads their nft counters like
  any other protocol. The sink's fold-on-vanish captures the final bytes of a tunnel that
  disappears between ticks (same mechanism ikev2-local uses today).

---

# Part 3 - The one shared-code change (behavior-preserving)

`NftService.CollectAndResetTraffic` today is `(l2tp, pptp, ovpn, ocserv, sstp, ikev2 maps) ->
(6 slices)`. Generalize to:

```go
func (s *NftService) CollectAndResetTraffic(byProto map[string]map[string]string) []*xray.ClientTraffic
```

It loops the existing per-IP read-and-reset over each protocol's `{proto}_acct` chain exactly as
now. Behavior is identical for the 6 current protocols (same chains, same counters, same
`ClientTraffic` records); the only change is the call shape. This removes the arity growth forever
and lets the tick pass `{"l2tp":..., ..., "wireguard":...}` in one call. Covered by a unit test
that asserts the same records out for the same counters in.

Everything else in the data plane (`vpnrange.go`, `nftables.go` TPROXY rules, `xray.go` dokodemo,
`radius.go` auth/acct for the 6) is untouched.

---

# Part 4 - Migrating ikev2-local (the proof)

This is the acceptance test for the extraction: same behavior, less code.

- `Ikev2Service` implements `cplane.Adapter`:
  - `Protocol()` -> `"ikev2"`.
  - `Poll()` -> `ikev2ListSAs()` filtered to psk/eap-tls inbounds, mapping each SA to
    `Live{InboundID, Email: account.Email, IP: sa.vip, DeviceKey: sa.id, Since: ...}`. (Reuses the
    existing parser; the attribution loop from `ReconcileLocalAuthSessions` moves here, minus the
    enforcement.)
  - `Limit(inboundID)` -> `effectiveUserLimit`, `normUserLimitStrategy` from that inbound's settings.
  - `Evict(l)` -> `killIkev2ByID(swanctl, l.DeviceKey)`.
- Delete `ReconcileLocalAuthSessions` (its quota-drop + K-trim + hand-off now come from the
  Sweeper). Delete the ikev2 copy of `getDisabledEmails`.
- Register the adapter with the Sweeper at wire-up.
- ikev2-eap-mschapv2 is unaffected: `KillDisabledSessions`/`DisableClients`/`killByUser` and the
  RADIUS auth path stay. (The adapter's `Poll` returns only psk/eap-tls SAs.)

Acceptance: run the ikev2 E2E psk + eap-tls modes; usage, quota, User-Limit reject/accept must
match pre-refactor exactly.

---

# Part 5 - WireGuard as adapter #1

With the framework in place, WireGuard's control plane is just the adapter (the rest of WireGuard
is the Part-1-through-9 work in `wireguard-plan.md`: bundling, addressing base 7, data-plane
wiring, UI):

- `Protocol()` -> `"wireguard"` (protocol id `wgvpn`, per `wireguard-plan.md`).
- `Poll()` -> `wgctrl` `Device("wgvpn0").Peers`; for each peer with a recent handshake, map its
  pubkey -> account/IP (from the DB peer<->account mapping) -> `Live{IP, Email, DeviceKey: pubkey,
  Since: firstSeen}`. Liveness = `LastHandshakeTime` within ~180s. No text parsing.
- `Limit(inboundID)` -> that inbound's K + strategy (or the structural "K provisioned" model,
  per the open decision in `wireguard-plan.md`).
- `Evict(l)` -> `wgctrl.ConfigureDevice(dev, {Peers: [{PublicKey: l.DeviceKey, Remove: true}]})`.

No reconcile, no enforcement, no accounting code to write. Usage is billed via the same map-based
`CollectAndResetTraffic` (WireGuard's decrypted traffic on `10.7.x.x` hits its `wireguard_acct`
chain). This is the payoff: WireGuard's hardest historical part (the ikev2 deadlock/parser/attribution)
never has to be rewritten.

---

# Part 6 - Phasing (each phase: `./build.sh` + `go test ./web/... -count=1` green)

- **Phase 1 - the package, isolated (zero shipping-code risk).** Create `web/service/cplane` with
  `Adapter`/`Live`/`Sink`/`Sweeper` + `TrimToLimit`, plus unit tests for `TrimToLimit` (reject/accept/
  K<=0/ties). Nothing wired in yet. Pure new code.
- **Phase 2 - generalize the sink.** In `radius.go`, add `ReconcileLocalSessions(protocol, desired)`
  (rename+parameterize `ReconcileIkev2LocalSessions`; keep a thin wrapper if anything else calls it)
  and `DisabledEmails()`. Make `RadiusService` satisfy `cplane.Sink`. Behavior-preserving.
- **Phase 3 - map-based accounting.** Refactor `CollectAndResetTraffic` to the map signature +
  unit test; update its single call site. Behavior-preserving for the 6.
- **Phase 4 - migrate ikev2-local + wire the Sweeper into the tick.** Implement the ikev2 adapter,
  delete `ReconcileLocalAuthSessions` + ikev2 `getDisabledEmails`, register the adapter, replace the
  hardcoded ikev2 reconcile in `xray_traffic_job.go` with `sweeper.Tick()`. Acceptance = ikev2 psk/
  eap-tls E2E parity (author only; never auto-run).
- **Phase 5 - WireGuard adapter** lands as part of the WireGuard protocol work.
- (Future, out of scope) Phase 6 - migrate RADIUS protocols' `getDisabledEmails`/`KillDisabledSessions`
  onto the framework, and consider RADIUS-as-a-push-adapter. Only after a 3rd non-RADIUS protocol.

---

# Part 7 - What stays untouched (risk containment)

- The RADIUS server auth + accounting handlers (`handleAuth`/`handleAcct`), and the 6 RADIUS
  protocols' auth path. Zero changes.
- `s.sessions` ownership stays in `RadiusService`; the framework writes through the `Sink`.
- Tier-B data plane: `vpnrange.go`, nft TPROXY rules, `xray.go` dokodemo, per-IP acct chains.
- ikev2-eap-mschapv2 (`killByUser`, `KillDisabledSessions`, `DisableClients`).
- Only two shared functions change signature, both behavior-preserving and unit-tested:
  `ReconcileIkev2LocalSessions` -> `ReconcileLocalSessions(protocol,...)` and
  `CollectAndResetTraffic` -> map-based.

---

# Build / test commands

```sh
./build.sh                         # canonical build (never bare `go build`)
go test ./web/... -count=1         # unit (incl. new cplane TrimToLimit tests) + i18n + template-parse
# E2E (author only, never auto-run): sudo test_unit/run.sh --tests ikev2   # parity check post-refactor
```

# Key files

- New: `web/service/cplane/cplane.go` (+ `cplane_test.go`).
- Edit: `web/service/radius.go` (`ReconcileIkev2LocalSessions`->`ReconcileLocalSessions`, add
  `DisabledEmails`, satisfy `Sink`), `web/service/nftables.go:556` (`CollectAndResetTraffic` map),
  `web/service/ikev2.go` (implement adapter, delete reconcile + `getDisabledEmails`),
  `web/job/xray_traffic_job.go` (Sweeper wire-in + map collect).
- Later: `web/service/wireguard.go` (adapter #1), and per-service cleanup in Phase 6.
