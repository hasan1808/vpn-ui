# One client, multiple inbounds - research and implementation plan

Making ONE account usable across SEVERAL inbounds of DIFFERENT protocols, with one
quota, one expiry, one edit, and one subscription link. This document is the research
record and proposed implementation contract, produced from a 7-agent codebase recon plus a
direct read of upstream 3x-ui at tag v3.5.0. Mirrors the style of `ikev2-plan.md` /
`wireguard-plan.md` / `account-slot-plan.md`.

STATUS: RESEARCH ONLY - HOLD FOR REVIEW. Nothing built yet.

---

## 0. Headline

**More than half of this is already shipping, and the missing half is not in `sub/`.**

1. **One subscription link across many inbounds and protocols already works.**
   `getInboundsBySubId` (`sub/subService.go:130-147`) is a DB-wide `JSON_EACH` scan that
   returns EVERY enabled inbound holding a client with that `subId`, across 16 protocols.
   `GetSubs` (`:52-128`) fans out over all of them, and `getLink` (`:181-214`) renders all
   18 protocols. The `subId` field is free-text editable in the client form
   (`web/html/form/client.html:143`).
2. **Provisioning one person onto several inbounds already ships too**, as "Copy clients":
   `POST /panel/api/inbounds/:id/copyClients` (`web/controller/inbound.go:83`),
   `CopyInboundClientsScoped` (`web/service/inbound.go:1671`). It deliberately PRESERVES
   `SubID` and mints one on the source first if absent (`:1733-1744`).
3. **The data plane is already keyed by email and already merges across inbounds.**
   Xray's stat name is `user>>><email>>>>traffic>>>...` with NO inbound component
   (`xray/api.go:283`); speed and IP limits merge per email with min-non-zero
   (`web/service/speedlimit.go:336-364`); `BuildVpnEmailToIPMap` unions a single email's
   tunnel IPs across inbounds AND protocols (`web/service/radius.go:1450`); the routing
   translator emits ONE rule with that union (`web/service/xray.go:501-515`); RADIUS
   quota checks are globally email-scoped with no inbound filter (`radius.go:641-644`).

What is missing is a single thing, and it is not a link format:

> **There is no account. `totalGB`, `expiryTime`, `enable` and the credentials live per
> client-entry inside each inbound's `settings.clients` JSON, and `client_traffics.email`
> is globally UNIQUE - so "the same person on N inbounds" is forced to be N separate
> accounts with N emails, N quotas and N expiries.**

`device-limit-plan.md:207-209` already named it in the same words: *"The genuine gap:
there is NO accounts table."*

---

## 1. Decisions proposed - need sign-off

1. **Add an accounts layer ABOVE the existing settings JSON; do not replace it.**
   A new `clients` table (the account: identity, credentials, quota, expiry) plus a
   `client_inbounds` join table (memberships). The per-inbound `settings.clients` JSON
   stays, maintained as a **projection** of the account onto each member inbound. This is
   also exactly what upstream v3 does (Part 3), and it is the only option that leaves
   RADIUS, the slot allocator, the wg/ocserv/accel-ppp/charon config writers, the routing
   translator and `GetXrayConfig` working unchanged - all of them parse
   `settings.clients` and none of them need to learn a new source of truth.
2. **Keep `client_traffics.email` UNIQUE and keep email as the global account identity.**
   Per `speed-limit-plan.md:586-632` and `device-limit-plan.md:212-214`. The account row
   owns the email; the projected entries on all N inbounds carry that SAME email. One
   email, one traffic row, one quota - which is the semantics being asked for.
3. **Credentials are per-account but per-FIELD, with wg-c/awg the deliberate exception.**
   Following v3's `ClientRecord`: separate `uuid`, `password`, `auth`, `secret` and a
   distinct `vpn_username` column, each member inbound's projection picking the field its
   protocol keys on (`clientIdentityKey`, `inbound.go:1520-1536`). This is REQUIRED here
   because `Client.ID` is overloaded today: a UUID for vmess/vless, a login name for the
   six credential VPNs and ssh, and the email for wg-c/awg/mtproto.

   **The exception:** v3 puts one WireGuard keypair on the account row, but this fork
   mints a keypair **per device** and stores them in the inbound's settings JSON
   (`wgcClient.Devices[]`, `wgc.go:114-137`, minted by `ReconcileKeys` `wgc.go:865`), then
   installs one kernel peer per device with `AllowedIPs = <deviceIP>/32` on the
   per-inbound interface `wgc{inboundId}` (`wgc.go:397-435`). Those addresses come from
   the membership's slot in **that** inbound's pool, so the keys are inherently
   per-membership. They belong on `AccountInbound`, not on the account.
4. **`Slot` stays per-membership.** It is defined as "the account's index into ITS
   inbound's address pool" (`database/model/model.go:374-386`) and one email on N pool
   inbounds legitimately consumes N slots. The slot lives on the projected entry, exactly
   as now; the account row never carries one.
5. **`subId` moves onto the account and becomes the natural subscription key.** One
   account = one `subId`, projected identically onto every member. This makes the existing
   `sub/` aggregation correct by construction instead of by operator discipline.
   `subId` must also be **validated and indexed** first - it is currently free-text and
   unindexed, so a typo silently merges someone into another subscription
   (`device-limit-plan.md:215-217`).
6. **Enforcement must be fixed BEFORE the feature ships, not after.** Quota depletion is
   currently inbound-scoped in three places and would leave a depleted account serving on
   N-1 inbounds (Part 5.1). This is a free-traffic bug, and it is the one part of this
   work that is not optional.
7. **Same-protocol multi-membership is OUT of scope for v1.** One account on l2tp + pptp
   + vless is supported; one account on TWO l2tp inbounds is refused at the API, because
   `findClientInbound` (`radius.go:900-923`) resolves a username to the lowest-id inbound
   and its own comment says *"the first match wins"*. Lifting that needs per-inbound
   NAS-Identifiers, which is a separate piece of work (Part 8).
8. **Resellers get the feature, priced.** Today `copyClients` is refused outright for
   resellers with a standing TODO (`controller/inbound.go:880-888`) precisely because N
   copies are N unpriced accounts. With ONE account carrying ONE quota that objection
   disappears: the charge is on the account, and memberships are free.
9. **The migration is additive-only, and ships a full release before anything depends on
   it.** Upgrading operators have sold accounts on live boxes; the upgrade must not move a
   single address or invalidate a single installed config. `MigrationAccounts` therefore
   never writes to any existing table (Part 6.0), which makes a failure a no-op rather than
   a corruption, and makes a binary rollback clean. Build order steps 1-2 are shippable
   alone and change no behaviour, so the migration gets validated on real data before any
   code reads what it wrote.

---

## 2. What exists today, precisely

### 2.1 A client is not a row

`GetClients` (`web/service/inbound.go:436-448`) unmarshals `Inbound.Settings` into
`map[string][]model.Client`. `model.Client` (`database/model/model.go:358-406`) is a flat
struct carrying, in one place: the credential (`ID`/`Password`/`Auth`/`Flow`/`Secret`),
the identity (`Email`, `SubID`), the quota (`TotalGB`, `ExpiryTime`, `Enable`, `Reset`),
the address-pool `Slot`, and the mtproto per-account block.

Its own comment is load-bearing (`model.go:390-393`): *"every client posted to the panel
is normalized through THIS struct, so a field missing here is silently dropped no matter
what the UI sent."*

### 2.2 Identity is the email, globally

- `xray.ClientTraffic.Email` is `gorm:"unique"` (`xray/client_traffic.go:14`) - on email
  ALONE, not `(inbound_id, email)`. `InboundId` has no index and no FK.
- Service-level: `checkEmailsExistExcludingInbound` (`inbound.go:616-633`) over
  `getAllEmailsExcludingInbound` (`:531-551`), which `JSON_EACH`es every inbound.
- The rationale block at `inbound.go:450-455` states it outright: *"A client's email is
  the panel's GLOBAL account identity, not a per-inbound label: it is the unique key of
  client_traffics, the name RADIUS authenticates and the selector the per-account routing
  rules are built from."*
- `AdminService.CanAccessClientEmail` (`web/service/admin.go:397-404`) authorizes by
  joining `inbound_accesses.inbound_id = client_traffics.inbound_id` - i.e. through the
  single denormalized back-pointer.

### 2.3 The existing workaround: Copy clients

`CopyInboundClientsScoped` (`inbound.go:1671-1779`):

```go
if sourceClient.SubID == "" {
    newSubID := uuid.NewString()
    subNeedRestart, subErr := s.writeBackClientSubID(sourceInbound.Id, sourceInbound.Protocol, sourceClient, newSubID)
    ...
    sourceClient.SubID = newSubID
}
targetEmail := s.nextAvailableCopiedEmail(originalEmail, targetInboundID, occupiedEmails)
targetClient, buildErr := s.buildTargetClientFromSource(sourceClient, targetInbound.Protocol, targetEmail, flow)
```

`buildTargetClientFromSource` (`:1588-1640`) starts from the source, clears
`ID`/`Password`/`Auth`/`Flow`/`Slot`, then re-mints protocol-correct credentials:
uuid for vmess/vless, password for trojan/ss, `auth` for hysteria, username+password for
the six credential VPNs, `ID = email` for wg-c/awg/mtproto/ssh.

`nextAvailableCopiedEmail` (`:1642-1654`) mints `<email>_<targetInboundId>`.

So the shipped shape is: **one subscription, N accounts, N emails, N quotas.** The rename
is the tell - `speed-limit-plan.md:601-604` cites it as the clinching argument that global
email uniqueness is intended: *"The one first-class 'same person, two inbounds' workflow
in the codebase refuses to reuse the email. That settles it."*

### 2.4 Dead code that already anticipated this

`getSubGroupClients(dbInbounds, currentClient)` (`web/html/inbounds.html:2302-2331`) walks
every inbound and collects `{inbounds:[], clients:[], editIds:[]}` for every client sharing
the current one's `subId`, stamping each sibling with its `inboundId` and its protocol-
correct `clientId`. **Nothing calls it.** It is exactly the primitive an "edit this account
everywhere" fan-out needs.

---

## 3. What upstream 3x-ui v3 actually does

Read at tag **v3.5.0** via the GitHub API. Two things matter, and they point in opposite
directions.

### 3.1 The design is confirmed and is the one proposed here

`internal/database/model/model.go` at v3.5.0:

```go
type ClientRecord struct {
	Id           int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Email        string `json:"email" gorm:"uniqueIndex;not null"`
	SubID        string `json:"subId" gorm:"index;column:sub_id"`
	UUID         string `json:"uuid" gorm:"column:uuid"`
	Password     string `json:"password"`
	Auth         string `json:"auth"`
	Flow         string `json:"flow"`
	Security     string `json:"security"`
	PrivateKey   string `json:"privateKey" gorm:"column:wg_private_key"`
	PublicKey    string `json:"publicKey" gorm:"column:wg_public_key"`
	AllowedIPs   string `json:"allowedIPs" gorm:"column:wg_allowed_ips"`
	PreSharedKey string `json:"preSharedKey" gorm:"column:wg_pre_shared_key"`
	KeepAlive    int    `json:"keepAlive" gorm:"column:wg_keep_alive;default:0"`
	Secret       string `json:"secret" gorm:"column:secret"`
	AdTag        string `json:"adTag" gorm:"column:ad_tag;default:''"`
	LimitIP      int    `json:"limitIp" gorm:"column:limit_ip"`
	TotalGB      int64  `json:"totalGB" gorm:"column:total_gb"`
	ExpiryTime   int64  `json:"expiryTime" gorm:"column:expiry_time"`
	Enable       bool   `json:"enable" gorm:"default:true"`
	TgID         int64  `json:"tgId" gorm:"column:tg_id"`
	Group        string `json:"group" gorm:"column:group_name;default:'';index:idx_client_record_group"`
	Comment      string `json:"comment"`
	Reset        int    `json:"reset" gorm:"default:0"`
	CreatedAt    int64  `json:"createdAt" gorm:"autoCreateTime:milli"`
	UpdatedAt    int64  `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}
func (ClientRecord) TableName() string { return "clients" }

type ClientInbound struct {
	ClientId     int    `json:"clientId" gorm:"primaryKey;column:client_id;index"`
	InboundId    int    `json:"inboundId" gorm:"primaryKey;column:inbound_id;index"`
	FlowOverride string `json:"flowOverride" gorm:"column:flow_override"`
	CreatedAt    int64  `json:"createdAt" gorm:"autoCreateTime:milli"`
}
func (ClientInbound) TableName() string { return "client_inbounds" }
```

Five facts worth lifting verbatim:

- **Credentials are per-FIELD on one account row**, not per-inbound. One `uuid` serves
  every vmess/vless membership, one `password` every trojan membership. Only `flow` is
  overridable per membership (`FlowOverride`).
- **`Email` stays `uniqueIndex`.** v3 did not relax it either.
- **`xray.ClientTraffic` is UNCHANGED in shape**: `Email string gorm:"unique"`,
  `InboundId` a plain non-unique index, `Inbound.ClientStats` still a has-many on
  `InboundId` (`internal/database/model/model.go:58`). v3 did NOT move to per-inbound
  traffic rows - one account, one counter, exactly as here.
- **The settings JSON survives as a projection.** `client_inbound_apply.go` and
  `db.go:439/:565` read and rewrite `settings["clients"]`; membership edits rewrite each
  member inbound's settings and then sync. Matching is by email: *"Match by email - the
  client's stable identity (see Delete). Removes every entry carrying a wanted email,
  independent of credential drift."*
- Supporting tables: `client_groups` (named groups with shared reset counters),
  `client_external_links` (extra links / remote subscriptions merged into a client's sub),
  and `ClientMergeConflict` for reconciling duplicates during migration.

### 3.2 But v3 is a ground-up rewrite and CANNOT be merged

At v3.5.0 the repo root is `frontend/`, `internal/`, `docs/`, `deploy/`, `Makefile`,
`.nvmrc` - a Next.js docs site, a separate SPA frontend, and a Go `internal/` layout. The
v2 tree this fork is built on (`web/html` Go templates + Vue 2 + antd 1.7.8,
`web/service`, `database/model`) does not exist there any more.

And v3's inbound protocol enum is:

```
vmess vless trojan shadowsocks wireguard hysteria http mixed tunnel tun mtproto
```

**None of this fork's ten added VPN protocols exist upstream** - no l2tp, pptp, openvpn,
openconnect, sstp, ikev2, wg-c, awg, ssh; no RADIUS server; no address pools; no slots.
The fork is a superset in exactly the area this feature touches hardest.

### 3.3 How much of v3's client code is liftable: measured

v3's client layer is **6,715 lines** across 14 files in `internal/web/service/`:

| file | lines | liftable here |
|---|---|---|
| `client_bulk.go` | 1673 | No. This fork's bulk ops carry a reseller ledger v3 has no concept of |
| `client_inbound_apply.go` | 1318 | Design yes, code no. Threaded with `runtime.Runtime` / `SyncInbound` / node push |
| `client_crud.go` | 763 | Partly - the validation helpers, verbatim |
| `client_paging.go` | 584 | No. v3 has a paged clients page; here clients are the inbounds table's expanded row |
| `inbound_clients.go` | 461 | Shape only |
| `client_groups.go` | 436 | Out of scope (v3 feature) |
| `client_locks.go` | 221 | The idea: `lockInbound(inboundId)` around a settings rewrite |
| `client_lookup.go` | 227 | Shape only |
| `client_portable.go` | 224 | Maybe, for export/import |
| `client_traffic.go` | 214 | No |
| `client_wireguard.go` | 182 | No. v3 puts one keypair on the account; this fork mints them per device |
| `client_link.go` | 236 | No. This fork's link generators cover 18 protocols |
| `client_external_link.go` | 103 | Out of scope (v3 feature) |
| `client.go` | 73 | Shape only |

Three reasons essentially none of it drops in:

1. **Protocol coverage.** Every protocol switch in v3's client code handles six -
   `client_crud.go:142-159` and `inbound_clients.go:197-231` are both
   `VMESS / VLESS / Trojan / Shadowsocks / Hysteria / MTProto`. This fork has eighteen, and
   the twelve extra are the hard ones.
2. **Node coupling.** `Node` appears 34 times and `SyncInbound` 16 times, concentrated in
   the four largest files. v3's client layer is written for the master/node topology this
   fork already assessed and rejected.
3. **Layout.** `v3/internal/...` against `v2/web/...`, and a Vue 3 SPA against Vue 2 with
   antd 1.7.8 Go templates.

**Worth lifting, concretely:**

- The schema (Part 3.1), about 50 lines.
- `client_crud.go:22-40` - `hasForbiddenClientChar`, `validateClientEmail`,
  `validateClientSubID`. Roughly 20 lines, and they close the exact gap
  `device-limit-plan.md:215-217` flagged: *"`subId` is currently unvalidated and unindexed:
  a typo silently merges a client into someone else's subscription."*
- The per-inbound lock around a settings rewrite (`client_locks.go`). This fork rewrites
  `settings.clients` without one.
- `ClientMergeConflict{Field, Old, New, Kept}` as the migration's conflict type (Part 6.6).
- The matching rule from `client_inbound_apply.go`: match by email, *"the client's stable
  identity, independent of credential drift."*

So: **borrow v3's schema and its projection strategy; write the code here.** A merge or a
cherry-pick is not on the table.

---

## 4. Proposed data model

```go
// Account is one sellable identity. It owns the quota, the expiry and every
// credential; membership of an inbound is a separate row.
type Account struct {
	Id    int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Email string `json:"email" gorm:"uniqueIndex;not null"`   // the global identity, unchanged
	SubID string `json:"subId" gorm:"index;column:sub_id"`    // NOW INDEXED (see 1.5)

	// Credentials, one per FIELD not per inbound. The projection picks the one
	// its member inbound's protocol keys on (clientIdentityKey).
	UUID        string `gorm:"column:uuid"`          // vmess / vless
	VpnUsername string `gorm:"column:vpn_username"`  // l2tp/pptp/openvpn/openconnect/sstp/ikev2/ssh
	Password    string `gorm:"column:password"`      // trojan/ss + all credential VPNs
	Auth        string `gorm:"column:auth"`          // hysteria
	Security    string `gorm:"column:security"`      // vmess
	Secret      string `gorm:"column:secret"`        // mtproto
	// mtproto per-account block: modes, tlsDomain, adtag, userLimit, externalProxy

	// Quota / lifecycle - the whole point of the table.
	TotalGB    int64 `gorm:"column:total_gb"`
	ExpiryTime int64 `gorm:"column:expiry_time"`
	Enable     bool  `gorm:"default:true"`
	Reset      int   `gorm:"default:0"`
	LimitIP    int   `gorm:"column:limit_ip"`
	TgID       int64 `gorm:"column:tg_id"`
	Comment    string
	CreatedAt  int64 `gorm:"autoCreateTime:milli"`
	UpdatedAt  int64 `gorm:"autoUpdateTime:milli"`
}

// AccountInbound is one membership. Composite PK, mirroring v3's ClientInbound.
type AccountInbound struct {
	AccountId int    `gorm:"primaryKey;column:account_id;index"`
	InboundId int    `gorm:"primaryKey;column:inbound_id;index"`
	Slot      *int   `gorm:"column:slot"`           // per-inbound address-pool index
	Flow      string `gorm:"column:flow"`          // per-membership override (vless)
	CreatedAt int64  `gorm:"autoCreateTime:milli"`
}
```

Deliberately NOT changed:

- `xray.ClientTraffic` keeps `Email gorm:"unique"`. It is the usage counter and the
  `ImportDB` backstop (`client_traffic.go:9-13`). `InboundId` degrades to "the account's
  home inbound" and stops being consulted for enforcement (Part 5.1).
- `Inbound.Settings` keeps its `clients` array. It remains what every daemon, allocator
  and config generator reads.
- `model.Client` keeps its shape. It is now a **projection type**, not a storage type.

### 4.1 The projection

One function, called after every account or membership write:

```
projectAccount(accountId) →
  for each membership m:
      inbound  := GetInbound(m.InboundId)
      entry    := renderClient(account, inbound.Protocol, m)  // picks credential field, carries m.Slot
      splice entry into inbound.settings.clients by EMAIL
      save inbound
  for each inbound the account is NO LONGER a member of:
      remove the entry carrying that email
```

`renderClient` is the inverse of `buildTargetClientFromSource` (`inbound.go:1588-1640`) and
should reuse its per-protocol switch verbatim - that switch is already the tested,
correct answer to "what credential does protocol P need".

Slot allocation stays where it is: `assignSlotsToClientMaps` (`vpnrange.go:855-899`) runs
per inbound and already preserves a slot across a save by matching on email, so a
projection that keeps the email stable keeps the address stable.

---

## 5. What breaks, and what must be fixed

### 5.1 Quota enforcement is inbound-scoped - MUST FIX, free traffic otherwise

**Three** places, all of which would leave a depleted account serving on N-1 inbounds.

`disableInvalidClients` (`inbound.go:2789-2792`):

```go
err := tx.Table("inbounds").
    Select("inbounds.tag, inbounds.protocol, client_traffics.email").
    Joins("JOIN client_traffics ON inbounds.id = client_traffics.inbound_id").
    Where("((client_traffics.total > 0 AND client_traffics.up + client_traffics.down >= client_traffics.total) OR ...")
```

One traffic row carries one `inbound_id`, so `RemoveUser(tag, email)` fires for exactly one
tag. Fix: join through `account_inbounds` instead, and remove the user from every member
tag. (Note there is **no index on `client_traffics.inbound_id`** despite this join running
every 10 seconds - worth adding while touching it.)

`GetXrayConfig` (`web/service/xray.go:225-229`) builds its `enableMap` from
`inbound.ClientStats`, a has-many on `InboundId`. Both filters are written
`if enable, exists := enableMap[email]; exists && !enable` - so on every inbound that does
not own the row, `exists` is **false** and the depleted client is rendered into the config
as **enabled**. A restart does not repair the leak; it re-creates it.

`buildRuntimeInboundForAPI` (`inbound.go:1263-1291`), the live no-restart path, has the
same hole and is even more explicit about it:

```go
err := tx.Model(xray.ClientTraffic{}).
    Where("inbound_id = ?", inbound.Id).
    Select("email", "enable").
    Find(&clientStats).Error
```

Fix for both: resolve the account's enable state by email, not through the per-inbound
association.

Combined effect on a depleted account: it keeps passing traffic on the non-owning inbounds
**and keeps billing into the same row**, so `up + down` grows past `total` forever while
`enable` stays false.

Note the asymmetry: **the ten non-Xray protocols are already correct.** `lookupClient`
(`radius.go:641-644`) checks `client_traffics` with `WHERE email = ?` and no inbound
filter, and every `getDisabledEmails()` is a panel-wide `WHERE enable = false`
(`l2tp.go:293-295`, `pptp.go:266`, `openvpn.go:1099-1101`, `openconnect.go:636`,
`ssh.go:221`, `radius.go:570`). Only the Xray-native path leaks.

### 5.1b Delayed-start and auto-renew convert on the owning inbound only

`adjustTraffics` (`inbound.go:2575-2631`) turns a negative `expiryTime` ("N days from first
use") into an absolute deadline. It collects the inbounds to rewrite from
`dbClientTraffic.InboundId` (`:2579`) and then `Where("id IN (?)", inboundIds)` (`:2585`).

So inbound A's settings JSON gets the absolute time, while B's and C's keep the **negative
value forever** - which the UI renders as "delayed start" (`aClientTable.html:172`) on an
account whose clock is actually running. `autoRenewClients` has the identical shape at
`:2657-2660`.

Fix: rewrite every member inbound's projection, which the projection function does anyway.

### 5.1c The traffic multiplier resolves through the home inbound

`inbound.go:2540` bills through `multiplierInbounds[dbClientTraffics[i].InboundId]`, and
`foldClientTraffic` (`trafficmultiplier.go:145-154`) does the same for teardown folds. Bytes
an account moves on inbounds B and C are therefore billed at **inbound A's** multiplier.

Unlike the speed limit, there is no established merge rule here. **Open question for
sign-off:** apply the multiplier of the inbound the bytes actually came from (correct, but
the nft/relay collectors emit `InboundId: 0` - `nftables.go:782`, `mtproto.go:880`,
`ssh_server.go:452` - so the source inbound is not currently carried), or take the maximum
across memberships (safe, simple, over-bills), or refuse a membership on an inbound whose
multiplier differs. Recommend **max across memberships** for v1, with a UI warning.

### 5.2 The subscription header collapses to "unlimited, never expires"

`GetSubs` (`subService.go:106-126`):

```go
if traffic.Total == 0 || clientTraffic.Total == 0 {
    traffic.Total = 0
} else {
    traffic.Total += clientTraffic.Total
}
if clientTraffic.ExpiryTime != traffic.ExpiryTime {
    traffic.ExpiryTime = 0
}
```

and `getClientTraffics` (`:149-156`) returns a **zero-value** `ClientTraffic` when the
email has no row on that inbound. With one shared traffic row pinned to one inbound, the
other N-1 members each contribute a zero → `Total` collapses to 0 (renders `"∞"`) and
`ExpiryTime` collapses to 0 (renders "no expiry"), while the account genuinely expires.

Fix: with a real account, stop summing. Read the account's quota and expiry once, and use
the single `client_traffics` row for usage. The aggregation loop becomes dead code for
account-backed subscriptions.

### 5.3 Duplicate remarks in the subscription

`genRemark` (`subService.go:1162-1245`) composes `inbound.Remark`, email and extras. With
one email across N inbounds, two members whose `Remark` is equal or empty produce
**byte-identical** node names, and subscription clients key nodes by name - later entries
overwrite earlier ones. Fix: fall back to the inbound tag or id in the `-i` slot when the
remark is empty or already used within one response. (v3 solved the ordering half of this
with `Inbound.SubSortIndex`; worth adopting.)

### 5.4 Admin visibility is decided by whichever inbound the traffic row names

`AdminService.CanAccessClientEmail` (`admin.go:397-404`):

```go
err := database.GetDB().Model(&xray.ClientTraffic{}).
    Joins("JOIN inbound_accesses ON inbound_accesses.inbound_id = client_traffics.inbound_id").
    Where("client_traffics.email = ? AND inbound_accesses.user_id = ?", email, userId).
    Count(&n).Error
```

Syntactically this is an EXISTS over a join and would be multi-inbound-correct **if**
`client_traffics` held one row per (email, inbound). It does not. So the effective
semantics are: email → the single traffic row → its `inbound_id` → grant check.

Consequence for an account on inbound A (admin1) and inbound B (admin2), with the traffic
row naming A: **admin2 is denied every `:email` route for a client sitting in their own
inbound** - `getClientTraffics`, `clientIps`, `clearClientIps`, `updateClientTraffic`,
`:id/resetClientTraffic/:email`, `:id/delClientByEmail/:email`. The client renders in
admin2's table (it is in their settings blob) with no traffic, no expiry and no enable
state, because `ClientStats` is preloaded per inbound.

The batch form is already the right shape - `ClientEmailAccess()` (`admin.go:450-473`)
returns `map[string]map[int]bool`, email → SET of admins. Only the one-row table collapses
it. Fix: resolve access through `account_inbounds`.

Also note `UpdateClientStat` (`inbound.go:2875-2882`) is an unqualified
`Where("email = ?")` update, so a save on inbound B overwrites the row admin1's page is
reading.

### 5.5 The reseller ledger is one row per email, frozen to one inbound

`model.ResellerClient` (`model.go:164-190`) is `Email uniqueIndex` + `InboundId index`
(plain, not composite). One row per account panel-wide - already account-shaped, which is
the good news. Four things are not:

**(a) `InboundId` is stamped at create and never moves.** `reserve` writes it only in the
`t.Create` branch (`reseller.go:764`); the update branch touches `charged_bytes` alone
(`:770-771`). So the ledger permanently names whichever inbound the account was first sold
on.

**(b) The cascade visits one membership.** `reseller.go:1372-1382`:

```go
for _, rc := range rows {
    inbound, err := inboundService.GetInbound(rc.InboundId)
    ...
    needRestart, err := inboundService.DelInboundClientByEmail(rc.InboundId, rc.Email)
```

Deleting a reseller removes the account from `rc.InboundId` only and then drops the ledger
row (`:1404`), leaving N-1 live memberships that are now **house-owned** - absence of a row
IS "the house owns it" (`model.go:168-170`). A working account nobody is billed for.

**(c) `RefundDeleted` (`reseller_bulk.go:759-791`) deletes the row keyed on email alone**
and refunds `ChargedBytes - consumed` in full. Removing membership #1 of 3 therefore
refunds the entire remaining charge while memberships #2 and #3 keep serving. The same
delete runs `DelClientStat` (`inbound.go:2892-2895`), destroying the one shared accounting
row for all three at once.

**(d) `DropInbound` (`reseller.go:382-396`) is `WHERE inbound_id = ?`.** Delete inbound B
while the row names A: nothing found, nothing refunded, the client vanishes from B and the
ledger keeps charging. Delete inbound A: full refund and row dropped while the account
keeps running on B and C.

Fixes: cascade and refund over memberships; drop the ledger row only when the **last**
membership goes; make `DropInbound` remove a membership rather than an account.

**Upside, and it is large.** With one account = one quota, the ledger's core is already
right: `Quote` (`reseller.go:198-237`) reads and writes exactly one `OldCharged`/
`NewCharged` pair, `AllTimeBase` is one number against one monotonic `AllTime`, and
`addSpent`'s atomic headroom re-check (`reseller.go:841-872`) is unaffected. And the
copyClients reseller refusal (`controller/inbound.go:889`) can be lifted - its stated
reason was *"Every copy is a NEW account carrying the source's quota, so an unpriced copy
is free traffic"*, which stops being true when a membership carries no quota of its own.

**The bulk pricer already anticipated this.** `reseller_bulk.go:353-358`:

```go
// One charge per account. Two settings entries sharing an email are
// one account to the ledger (there is one row), so pricing both would
// debit twice for a single row that can only record one charge.
if seen[key] { continue }
```

Correct already. But the applier it fronts (`BulkUpdateClients`) iterates the request
targets, not the priced list, so the second membership is **mutated but unpriced**. And
`ApplyBulkExpiry` (`reseller_bulk.go:628`) joins
`client_traffics.inbound_id = inbounds.id`, so it patches the home inbound's settings only.

### 5.6 The `*ByEmail` family resolves to exactly one inbound

`GetClientInboundByEmail` (`inbound.go:2916-2929`) returns `traffics[0].InboundId`. It
feeds `GetClientByEmail`, `checkIsEnabledByEmail`, `ToggleClientEnableByEmail`,
`ResetClientIpLimitByEmail`, `ResetClientExpiryTimeByEmail`,
`ResetClientTrafficLimitByEmail` - i.e. most of the Telegram bot's surface
(`tgbot.go:2342`, `:3222`, `:1517`, `:1104`, `:1301`, ...).

These become "read the account, write the account, re-project". Semantically they get
*more* correct: today `ToggleClientEnableByEmail` disables the account on one inbound.

### 5.7 Same-protocol multi-membership resolves to the lowest-id inbound

`findClientInbound` (`radius.go:900-923`), reached whenever the NAS-Identifier is
protocol-level (which is what the shared xl2tpd/pptpd/ocserv/accel-ppp/charon configs
send):

```go
// "Usernames are expected to be unique across a protocol's inbounds; the first match wins."
for _, inbound := range inbounds {
    for _, c := range settings.Clients {
        if c.ID == username || c.Email == username { return inbound, nil }
    }
}
```

An account on two l2tp inbounds always authenticates against the lower id, taking that
inbound's ranges, K, strategy and slot. Silently. `getClientIP` (`radius.go:929-943`)
repeats the identical branch, so the IP, K, strategy and ranges all come from that one
inbound. Hence decision 1.7: refuse the second same-protocol membership at the API for v1.

Which protocols land on this path (`radius.go:871-892`): **l2tp, pptp and ikev2** send a
bare protocol-level NAS-Identifier and resolve first-match-wins. openvpn, openconnect and
sstp already send `<proto>-<inboundId>` (`main.go:1758`, `openconnect.go:419`,
`sstp.go:464`) and resolve exactly - so **same-protocol multi-membership is already safe
for those three**, and the v1 refusal only needs to cover l2tp/pptp/ikev2.

`sshManager` is worse: `m.sessions[sess.email]` (`ssh_server.go:376`), `m.counters[email]`
(`:429`) - **email-keyed with no inbound at all**, and `enforce` picks which inbound's K to
apply by arbitrary map iteration (`:473-481`, last one wins). Two SSH memberships would
share one session set under a nondeterministic cap.

Related, and separate: the shared-daemon settings (DNS, MTU, IPsec PSK) are still
first-inbound-wins in the generators (`l2tp.go:167-170`, `pptp.go:146-148` -
`GeneratePPPOptions(inbounds[0])`), but a save that would create the disagreement is now
**rejected** by `CheckSharedDaemonConflicts` (`web/service/sharedconfig.go:146`, called from
`inbound.go:1062`) for l2tp (PSK, dns1, MTU) and ikev2 (dns1). **PPTP has no such check** -
two PPTP inbounds with different DNS/MTU save cleanly and `inbounds[0]` silently wins. That
is a live bug today, independent of this feature.

### 5.7b Mixing an Xray protocol with a VPN protocol silently breaks Xray-native routing

This one is already in the tree and is triggered by exactly the configuration the feature
exists to create. `translateVpnRoutingRules` (`xray.go:479-492`):

```go
for _, u := range usersRaw {
    email, ok := u.(string)
    if !ok { regularEmails = append(regularEmails, u); continue }
    if ips, found := vpnMap[email]; found {
        for _, ip := range ips { vpnIPs = append(vpnIPs, ip) }
    } else {
        regularEmails = append(regularEmails, u)
    }
}
```

The moment an email appears in `vpnMap` - i.e. the moment it has ANY pool-protocol
membership - it is moved out of the rule's `user` list entirely and replaced by a source-IP
match. For an account that is on vless **and** l2tp, the vless traffic no longer matches
its own routing rule: the source-IP rule only covers the tunnel addresses, and the native
`user` match is gone.

Fix: keep the email in BOTH lists when the account also has a non-pool membership - emit
the source rule and retain the `user` rule, rather than choosing.

### 5.8 Address pool consumption multiplies by N

`Slot` is per-inbound, so one account on N pool inbounds burns N slots and
`sum(K_i)` addresses. Concretely (from `vpnrange.go:959-969` and `radius.go:1485-1494`):
one email on l2tp + pptp + openvpn + openconnect at K=1 consumes 4 slots and **5**
addresses - openvpn contributes two, its UDP address and its TCP mirror in `10.3`. At
K=16 the same account consumes 4 slots and 80 addresses.

Not a bug, but the capacity guard message ("IP pool full for this %s inbound",
`inbound.go:1398-1409`) will start firing sooner, and the UI should say so when a
membership is ticked.

### 5.9 Things that need NO change

Worth stating, because they are the reason this is tractable:

- **Every daemon config generator reads `inbound.Settings` → `clients[]` and nothing
  else.** No generator reads a clients table, because there isn't one. Verified across all
  ten: `wgc.go:399`, `awg.go:393`, `openvpn.go:515`, `openconnect.go`/`sstp.go`/`ikev2.go`
  (via RADIUS at `radius.go:632`), `mtproto.go:620`, `ssh.go:370`. This is what makes the
  projection strategy work: keep writing that array and every backend is already correct.
- Only **openvpn** has a genuine per-client on-disk artifact -
  `/etc/openvpn/server-{inboundId}/blocks-{udp|tcp}/{client.ID}` (`openvpn.go:539`) - and
  it is **already keyed by (inbound, username)**, so it needs nothing.
- `xray/api.go:283` - traffic stat is per email, aggregated across inbounds already.
- `inbound.go:2501` + `:2524-2529` - `addClientTraffic` matches on `email IN (?)` and
  deliberately applies EVERY matching record: *"A tick can legitimately carry more than
  one record for an account (a client billed under two protocols...)"*.
- `speedlimit.go:336-364` - one bucket per email, min-non-zero across inbounds. The
  `K x bandwidth` hazard `device-limit-plan.md:196-203` warned about **does not apply**,
  because there is one email, not K.
- `radius.go:1450` / `xray.go:501-515` - one routing rule with the union of the account's
  IPs across every inbound and protocol.
- `radius.go:641-644` - RADIUS quota check is already global by email.
- `model.InboundClientIps` (`model.go:306-310`) - `ClientEmail uniqueIndex`, no inbound
  column. Already account-scoped.
- Xray-core itself: `proxy/vless/inbound/inbound.go:60` and `proxy/trojan/server.go:46`
  construct a validator **per inbound handler**, so the `"User %s already exists"` check
  (`proxy/vless/validator.go:37`) is per-inbound. The same email on two inbounds is fine.
- `MigrationRemoveOrphanedTraffics` (`inbound.go:2848-2858`) deletes rows whose email is in
  NO inbound's settings, ignoring `inbound_id` entirely. Safe for this shape.
- `reseller_bulk.go:353-358` - the "one charge per account" guard for two settings entries
  sharing an email already exists and is already correct.

### 5.10 Small traps to remember while implementing

- `AddClientStat`'s dedup at `inbound.go:3867` is
  `Count(&count); if count == 0 { AddClientStat(...) }` - it would silently skip creating
  a stats row and read as success. Right behaviour for a second membership, wrong reason;
  make it explicit.
- `addClientTraffic` returns early when no row matches (`inbound.go:2506-2509`) - and by
  then `GetTraffic(true)` and `nft -j reset counters` have already zeroed the source. Bytes
  for an email with no row are **gone**, not deferred. A projection that creates the
  membership before the account row exists would lose traffic.
- `tx.Save(dbClientTraffics)` (`inbound.go:2567`) writes back EVERY column of the rows read
  at `:2501`, including `enable`/`total`/`expiry_time`/`reset`. A concurrent quota edit
  landing between the read and that save is silently reverted. Widening the tick to N
  memberships widens that window.
- `postedClient` (`reseller.go:415-433`) enforces exactly one client per request:
  *"more than one would let a single reservation pay for several accounts."* An accounts
  API must keep that property.
- `DelInboundClient` refuses to remove the last client of an inbound
  (`inbound.go:1826-1828`, `"no client remained in Inbound"`), and the row UI mirrors it
  (`isRemovable`, `inbounds.html:2700`). Removing a membership must not inherit that rule.
- `Client.ID` for SSH is a real login username, not the email - `ssh.go:371` compares
  `c.ID != username`. Two in-tree comments claim otherwise (`inbound.go:1532-1533` and
  `web/assets/js/model/inbound.js:49-50`); they contradict `inbound.js:5586-5590` and are
  wrong. Worth fixing while the credential mapping is being touched.
- `checkPPPUsernamesForDuplicates` (`inbound.go:587`) covers l2tp, pptp, openvpn, sstp,
  ikev2, wg-c, awg, ssh - but **not openconnect or mtproto** (`inbound.go:1429`). Harmless
  today because openconnect resolves by per-inbound NAS-Identifier and mtproto's identity
  is the email, but the omission should be deliberate rather than accidental.
- `findIndexOfClient` (`inbounds.html:2229-2245`) partitions protocols differently from
  `getClientIdentity` (`inbound.js:32-53`) - shadowsocks and hysteria fall on different
  sides. Two switches that look like one.

---

## 6. Migration

An operator upgrading a live panel with hundreds of sold accounts must end the upgrade
with every account intact, every config still valid, and every address unmoved. This
section is the contract for that.

### 6.0 The one property everything else rests on

> **`MigrationAccounts` is ADDITIVE ONLY. It never writes to `inbounds`, `client_traffics`,
> `reseller_clients` or `inbound_client_ips`. It only INSERTs into the two new tables.**

That single constraint buys all of the following, for free:

- A failure at any point leaves the database **byte-identical** to before it ran.
- There is no user-visible half-migrated state. `settings.clients` remains the truth the
  whole time, and every daemon, generator and allocator keeps reading it unchanged.
- An old binary rolled back onto the migrated database **ignores the two new tables** and
  behaves exactly as it did before (GORM's AutoMigrate never drops unknown tables).
- The migration can be aborted, retried, or skipped entirely without consequence.

Any design that requires rewriting `settings.clients` during the migration forfeits all
four. Do not.

### 6.1 Safety properties, as a checklist

1. **Additive only** (6.0).
2. **Idempotent.** Safe to run on every start, safe after a crash mid-pass, safe on an
   already-migrated database.
3. **Ordered.** After `MigrationSubIds()` and `MigrationAccountSlots()`, so every account
   already has its subId and its slot stamped before anything reads them.
4. **Non-fatal.** A failure logs and leaves the panel serving. It must never block startup;
   the legacy path is fully functional without the accounts layer.
5. **No-op projection.** The first projection write after migration must be byte-identical
   to what is stored, so nothing moves. Same property `MigrationAccountSlots` was built for
   (`inbound.go:3934-3939`) and verified live in `account-slot-plan.md:22-38`.
6. **Verified before authoritative.** The accounts layer is only allowed to drive writes
   after the invariant check in 6.4 passes.

### 6.2 Pre-flight backup

Reuse the shape of `backupPanelDBForUpdate` (`main.go:1188-1234`), which already does the
right things: `PRAGMA wal_checkpoint(TRUNCATE)` first so the copy is as close to a
point-in-time snapshot as a file copy gets, then copies the `-wal`/`-shm` sidecars
alongside, into `<dbdir>/backups/vpn-ui_<version>_<timestamp>.db`.

Take one tagged `pre-accounts` snapshot before the **first** migration run only, guarded by
the settings key from 6.5. Adopt the update path's rule verbatim (`main.go:1135`):

> *"Aborting before replacing the binary: an update without a good backup is not worth it."*

If the backup fails, **skip the migration** and log at error. The panel starts normally on
the legacy path; the operator fixes the disk and restarts.

Do **not** reuse `service.backupPanelDB` - `main.go:1193-1195` records why: it is
best-effort and single-slot (`vpn-ui_<version>.db`), so a second upgrade from the same
version silently overwrites the only copy you would want back.

### 6.3 The pass

Mirrors `MigrationSubIds` (`inbound.go:4002-4050`) in structure. Inbounds are walked in
**ascending id order**, so "first wins" is deterministic rather than whatever the query
planner returns.

```
for each inbound (ORDER BY id ASC):
    settings, err := json.Unmarshal(inbound.Settings)
    if err != nil:
        log, SKIP THIS INBOUND, continue     // stays legacy-only, which is safe
    for listIndex, c := range settings.clients:
        email := strings.TrimSpace(c.email)
        if email == "":
            skipped++; continue              // no email, no account identity
        key := accountKey(email)             // lower+trim, matches vpnrange.go:903-905

        if acct, exists := byKey[key]; exists:
            recordConflicts(acct, c)         // keep the FIRST, never merge silently
        else:
            acct = newAccount(email, c)      // quota, expiry, enable, reset, limitIp,
                                             // tgId, comment, subId
            acct.setCredential(inbound.Protocol, c)   // uuid | vpn_username | password |
                                             // auth | secret, per clientIdentityKey
            insert(acct); byKey[key] = acct

        m := AccountInbound{AccountId: acct.Id, InboundId: inbound.Id}
        if slotPoolProtocol(inbound.Protocol):
            m.Slot = ptr(slotOr(c.slot, listIndex))   // vpnrange.go:798-803
        if inbound.Protocol == VLESS:
            m.Flow = c.flow
        if inbound.Protocol in (WGC, AWG):
            m.Devices = c.devices             // per-device keypairs stay per-membership
        insert(m)
```

`slotOr(c.slot, listIndex)` is the important detail: rows written before slots existed
carry none, and the effective slot **is** the list index for them. Stamping that into the
membership is what keeps their tunnel address where it already is.

### 6.4 Verification, and what happens when it fails

Run inside the same transaction, before commit:

1. Every `settings.clients` entry with a non-empty email has **exactly one** account and
   **exactly one** membership on that inbound.
2. Every account has **at least one** membership (no orphans).
3. **The projection round-trips.** For every inbound, rendering its member accounts through
   `renderClient` produces a `clients` array byte-identical to what is stored.

Check 3 is the whole safety argument in one assertion, and it is cheap. If any check
fails: **ROLLBACK**, log at error with the offending inbound and email, and leave the
`accountsMigrated` flag unset. The panel then runs on the legacy path exactly as before.
Half-enabling is not an option.

### 6.5 Re-run guard and cost

Called from `main.go` right after `MigrationAccountSlots()` (`main.go:202`), on **every**
start. Not from `MigrateDB()` - `main.go:189-194` gives the reason:

> *"This runs on every start rather than only from MigrateDB, because MigrateDB is reached
> only by the `migrate` subcommand and the DB-import path: a panel that is simply upgraded
> and restarted never calls it, which is the normal way this fix arrives."*

That matters here too: an inbound added by an older binary, or a DB restored from backup,
must be picked up. Guard the cost, not the correctness - compare `COUNT(accounts)` against
the distinct-email count from one `JSON_EACH` query (same shape as
`getAllEmailsExcludingInbound`, `inbound.go:531-551`) and only do the full pass when they
disagree. Store `accountsMigratedAt` and the 6.6 report in the `settings` table.

### 6.6 The report

Counts, surfaced in the panel once and kept in settings: accounts created, memberships
created, inbounds skipped (unparseable settings), clients skipped (no email), conflicts
recorded. Use v3's type for the conflicts - `ClientMergeConflict{Field, Old, New, Kept}` -
because surfacing a divergence beats silently picking one.

Precedent for advisory output: `PreviewBulk` (`reseller_bulk.go:499-580`), which is
explicitly *"ADVICE, never authorization."*

### 6.7 Cases the pass must get right

| case | reachable how | handling |
|---|---|---|
| Empty email | always allowed today | skip, count. Same rule as `MigrationSubIds` (`inbound.go:4028-4030`) |
| `"bob "` vs `"bob"` | rows predating `normalizeClientEmails` (`inbound.go:487-520`) | fold with `accountKey`; one account |
| Same email on two inbounds | `ImportDB` (`server.go:1154`) or a hand-edited DB only - the service layer refuses it at four call sites | first inbound wins, conflict recorded, **both** memberships created |
| Copied accounts `bob`, `bob_5` | `nextAvailableCopiedEmail` (`inbound.go:1642`) | **separate accounts.** They have separate emails and separate quotas, which is what they are. Do not guess a merge from the `_<id>` suffix; offer an explicit merge action later |
| Unparseable settings JSON | hand-edited DB | skip that inbound, log. It stays legacy-only and keeps working |
| Client with no `slot` | rows predating `MigrationAccountSlots` | `slotOr(nil, listIndex)` |
| mtproto / ssh / Xray protocols | normal | membership slot stays nil (`slotPoolProtocols`, `vpnrange.go:829-830`) |
| IKEv2 psk / eap-tls | normal | single-account by construction (`inbound.go:1414-1419`); one account, one membership |
| Orphaned `client_traffics` rows | deleted inbound | left alone; `MigrationRemoveOrphanedTraffics` (`inbound.go:2848`) already handles them and ignores `inbound_id` |

### 6.8 Rollback, three levels

1. **Binary rollback.** The two new tables are additive, so an old binary ignores them and
   reads `settings.clients` unchanged. Clean right up until the first multi-membership
   account is created; lossy after that, because the non-home inbounds lose quota
   enforcement (Part 5.1). State this plainly in the release notes rather than implying the
   rollback is unconditional.
2. **`vpn-ui --revert-accounts`.** Drops the two tables. Refuses when any account holds more
   than one membership, because there is no non-destructive answer there - the operator must
   choose explicitly between splitting into renamed accounts and dropping the extra
   memberships.
3. **The pre-accounts backup** from 6.2.

### 6.9 Failure modes and outcomes

| failure | outcome |
|---|---|
| Backup copy fails | migration skipped, panel starts on legacy path, error logged |
| Crash mid-pass | transaction rolls back, nothing written, retried next start |
| Verification check fails | rollback, flag unset, panel runs legacy, offending row named in the log |
| One inbound has broken settings JSON | that inbound skipped, the rest migrate, it keeps working legacy |
| Duplicate emails from an imported DB | first wins, both memberships created, conflict reported |
| Old binary put back afterwards | reads `settings.clients`, ignores new tables, works |
| Disk full mid-pass | SQLite fails the transaction, rollback, retried next start |

---

## 7. API and UI

### 7.1 API

The wire type for a client write today is `model.Inbound` with only `id` + `settings`
populated (`controller/inbound.go:803`, `:991`), form-urlencoded via `Qs.stringify`. Two
options:

- (a) Keep `POST /addClient` and `POST /updateClient/:clientId` and add a repeated
  `inboundIds` field. Minimal churn; `Qs.stringify` emits repeated keys with
  `arrayFormat:'repeat'`, and the empty-array case needs the `['']` sentinel the admin
  modal already uses (`admin_modal.html:185`).
- (b) New account routes (`POST /panel/api/accounts`, `PUT /:id`, `PUT /:id/inbounds`).
  Cleaner, but every caller moves: the Vue page, the Telegram bot, the bulk ops, the
  reseller flows, and any external script hitting the documented API.

**Recommend (a) for v1**, with `id` (the target inbound) retained as "the inbound the
modal was opened from" and `inboundIds` as the full membership set. It keeps
`callerOwnsInbound` (`:814`) meaningful and does not break existing integrations.

Ownership: the handler must check `callerOwnsInbound` for **every** id in `inboundIds`,
not just `data.Id`. This is the exact shape of the bug the copy handler documents at
`controller/inbound.go:908-911` - the source arrives in the body, so the `:id` middleware
never sees it. `idor_test.go:149` already pins the single-id version of this.

**The protocol fan-out has to become a loop.** Today both `addInboundClient`
(`controller/inbound.go:843-871`) and `updateInboundClient` (`:1044-1066`) end in a single
`if/else if` chain on ONE protocol, resolved from `data.Id`'s inbound. An account spanning
l2tp + wg-c + vless needs `onL2tpClientChanged()`, `wgcChanged()` **and**
`SetToNeedRestart()` from one request. The precedent already exists: the reset-traffic
routes call all ten hooks unconditionally (`controller/inbound.go:1247-1256`, `:1286-1295`,
`:1320-1329`). Drive the loop off the membership set and dedupe by protocol.

### 7.2 UI

The picker already exists twice and should be copied a third time: the admin inbound-access
checklist (`web/html/modals/admin_modal.html:47-81`) - a select-all checkbox with
indeterminate state, an `a-divider`, and a `maxHeight: 180px; overflowY: auto` scroll box
holding an `a-checkbox-group` of `remark + protocol tag + :port`. The reseller modal has a
near-identical copy (`reseller_modal.html:133-157`).

Slot it into `web/html/form/client.html` behind an `<a-divider>` - the precedent is the
MTProto block at `:335`. Constraints: the client modal is antd's default 520px with no
`width` prop (`client_modal.html:2-13`), and the form is `label-col 8 / wrapper-col 14`, so
a wide control belongs **outside** an `a-form-item`, exactly as the external-proxy rows do
(`form/client.html:498-504`).

Also worth doing:

- Revive `getSubGroupClients` (`inbounds.html:2302-2331`) or delete it; it currently
  advertises an intent the panel does not implement.
- The per-client row already has a protocol-independent subscription icon gated on
  `app.subSettings?.enable && client.subId` (`aClientTable.html:39`). With accounts, one
  row per account per inbound still renders - decide whether the client table should
  dedupe by account or keep showing the membership. **Recommend keeping the membership
  view** (it is the inbounds page, not an accounts page) and adding a badge showing "on N
  inbounds".
- i18n: 13 locales, `[pages.client]` table in `web/translation/translate.en_US.toml:493`.
  New keys must land in all 13 or be baselined in `knownMissing`
  (`web/i18n_toml_test.go:45-126`), which the parity ratchet enforces.

---

## 8. Out of scope for v1

- **Two inbounds of the SAME protocol** (Part 5.6). Needs per-inbound NAS-Identifiers, so
  the shared xl2tpd/pptpd/ocserv/accel-ppp/charon configs can name the inbound. The
  per-inbound form (`"l2tp-3"`) already parses (`radius.go:876-890`); nothing generates it.
- **Per-membership quota.** The whole point is one quota; a per-inbound sub-cap can come
  later as a column on `AccountInbound`.
- **Client groups / shared reset counters** (v3's `client_groups`).
- **External links merged into a subscription** (v3's `client_external_links`).
- **Multi-node.** v3's `ClientGlobalTraffic` is about masters pushing usage to nodes;
  see `multinode-feasibility-analysis` in memory for why that shape is wrong here.

---

## 8b. Rejected alternatives

Recorded so they are not re-argued later, in the style of `wireguard-plan.md:121-131` and
`account-slot-plan.md:121-131`.

**A panel-wide "client model" toggle (current vs multi-inbound), switching the model at
runtime and deleting all accounts on switch, with a confirmation prompt.**

Rejected. The wipe does solve the data-interop problem: only one model ever holds data, so
there is no reconciliation and no ambiguous reverse direction. The cost is elsewhere.

- **The data holds one model; the code would carry both forever.** The binary must run in
  either mode, so every consumer needs a permanent branch: `disableInvalidClients`,
  `GetXrayConfig`, `buildRuntimeInboundForAPI`, `adjustTraffics`, `autoRenewClients`, the
  ten protocol hooks, six reseller ledger methods, `CanAccessClientEmail`, the six
  `*ByEmail` methods, the sub layer, the tgbot, bulk ops, the client modal. Plus a doubled
  test matrix on a subsystem where `GetSubs`, `getInboundsBySubId` and the traffic
  aggregation loop have no coverage at all.
- **This codebase has already been burned by exactly that.** The client-identity switch was
  copy-pasted into five Go sites and two browser sites, two fell out of sync, and every
  edit returned "empty client ID" while deletes silently removed nobody
  (`inbound.go:1508-1519`). Parity now needs a test that parses the JS
  (`client_identity_test.go:95-108`).
- **Nobody with data can use it.** An operator with live accounts will not press a button
  that deletes them, so the toggle stays off for exactly the people it was meant to
  protect, while a fresh install picks one model on day one and never touches it. The dual
  path would be maintained for nobody.
- **The old model offers nothing the new one does not.** An account with exactly one
  membership *is* today's client, byte-identical in `settings.clients`. Even "sell 50 GB on
  vless and a separate 50 GB on l2tp to one person" is two one-membership accounts, which
  is what the old model already is.

What the toggle was reaching for - an escape hatch if the migration goes wrong on a live
box - is delivered instead by Part 6: an additive-only migration that cannot corrupt
anything, a pre-accounts DB backup, binary rollback, and a standalone "reset all accounts"
action carrying the same confirmation prompt without forking a single code path.

**Relaxing `client_traffics.email UNIQUE` to `(inbound_id, email)`.**

Rejected, and it was already rejected twice before this plan. `speed-limit-plan.md:586-632`
established global uniqueness as the intended invariant, and `device-limit-plan.md:212-214`
is explicit: *"Do NOT relax `client_traffics.email UNIQUE`; it is the only thing guarding
`ImportDB`. Add an indexed non-unique `parent_id` beside it."* Per-inbound rows would also
re-fragment the one thing that is already correct: usage is per account, and Xray's own
counter (`user>>><email>>>>traffic`) has no inbound component to split on.

## 9. Build order

Staged so that **every step up to 4 is shippable on its own and changes no behaviour**.
That is deliberate: it means the migration reaches real panels, and gets validated on real
data, long before anything depends on it.

1. `subId` validation + index (lifting `client_crud.go:22-40`), and the
   `Account`/`AccountInbound` models registered in `initModels` (`database/db.go:32-53`).
   No behaviour change.
2. **`MigrationAccounts()`** (Part 6) - the pre-flight backup, the pass, the verification,
   the report, the re-run guard, and the call from `main.go` after
   `MigrationAccountSlots()`. **Ship this alone and let it run in production for a
   release.** It is additive-only, so the worst case is that it does nothing. Verify on a
   real DB that it is a no-op: no address moves, no config changes, `client_traffics`
   untouched.
3. `projectAccount` + `renderClient`, reusing `buildTargetClientFromSource`'s per-protocol
   switch. Route the existing add/update/delete paths through it, still single-membership.
   Behaviour unchanged; the existing test suite is the regression net.
4. **The enforcement fixes** (Parts 5.1, 5.1b, 5.7b) - `disableInvalidClients`,
   `GetXrayConfig`, `buildRuntimeInboundForAPI`, `adjustTraffics`/`autoRenewClients` over
   memberships, and the vless+l2tp routing rule. Independently valuable: 5.7b is a live bug
   today, and 5.1 is a prerequisite for anything after this point.
5. Multi-membership: the `inboundIds` API field, the ownership check over **every** id, the
   protocol fan-out loop, the same-protocol refusal for l2tp/pptp/ikev2, the reseller
   cascade and refund over memberships, `CanAccessClientEmail` over memberships.
6. Subscription: account-backed quota/expiry instead of the summing loop (Part 5.2), and
   remark disambiguation (Part 5.3).
7. UI: the checklist, the membership badge, i18n across 13 locales.
8. `vpn-ui --revert-accounts` and the standalone "reset all accounts" action (Part 6.8).
9. Lift the reseller `copyClients` refusal; consider replacing copyClients with
   "add memberships" entirely.

## 10. Tests to write

The subscription layer is notably under-tested: **`GetSubs` end-to-end,
`getInboundsBySubId`, the traffic/expiry aggregation loop, and the `Subscription-Userinfo`
header have no coverage at all** - and the aggregation loop is precisely the fragile code
in Part 5.2.

**Migration** (the heaviest coverage, because it runs unattended on other people's live
panels). Mirror `inbound_subid_test.go` for structure:

- Idempotent: two consecutive runs produce identical tables and identical settings JSON.
- **Additive-only, asserted:** snapshot `inbounds.settings`, `client_traffics`,
  `reseller_clients` and `inbound_client_ips` before and after; every one must be
  byte-identical. This is the property from Part 6.0 and it deserves a test that fails
  loudly.
- Projection round-trip: re-rendering every migrated account reproduces the stored
  `settings.clients` byte for byte (Part 6.4 check 3).
- Slots do not move, measured the way `account-slot-plan.md:22-38` measured them: read the
  address back from the real consumer, before and after.
- A malformed `settings` blob on one inbound skips that inbound and migrates the rest.
- A duplicate email across two inbounds (seeded directly, since the service layer refuses
  it) yields one account, two memberships, and a recorded conflict.
- Clients with an empty email are skipped and counted, not given an account.
- `"bob "` and `"bob"` fold to one account.
- A client with no `slot` gets `slotOr(nil, listIndex)` stamped on its membership.
- Copied accounts `bob` / `bob_5` stay two accounts.
- A failing verification check rolls the whole pass back and leaves `accountsMigrated`
  unset.
- A failed pre-flight backup skips the migration entirely and the panel still starts.
- Round-trip through `ImportDB`: import a pre-migration DB into a migrated panel and the
  pass re-runs cleanly.
- Projection round-trip: for each of the 18 protocols, `renderClient` produces an entry
  whose `clientIdentity` is non-empty and matches `clientIdentityKey`. Extend the existing
  `client_identity_test.go` parity harness.
- A depleted account is removed from EVERY member inbound's generated Xray config, and
  refused by RADIUS (the second half already passes today).
- One account on three inbounds reports its real `total` and `expire` in
  `Subscription-Userinfo`, not `0`.
- An account on vless + l2tp keeps BOTH its `user` routing rule and its source-IP rule
  (Part 5.7b).
- Deleting a reseller removes the account from every membership and leaves no live copy;
  deleting one membership of three refunds nothing and leaves the ledger row intact.
- An admin who holds inbound B but not A can still read and edit an account whose traffic
  row happens to name A (Part 5.4).
- An admin holding only some of the ticked inbounds is refused the whole request (IDOR;
  mirror `web/controller/idor_test.go:164`, and follow its thesis at `:28-41` - *"`owns` on
  a path :id proves nothing until you read the service it fronts"*). Run it as a
  non-super admin, for the reason stated at `:37-39`.
- Slots do not move when a membership is added or removed (mirror the before/after
  measurement in `account-slot-plan.md:22-38`).
