# Resellers: a quota-bounded, client-scoped role

A reseller logs into the same panel as an admin, sees only the inbounds they were
assigned, and inside those inbounds sees only the accounts **they themselves
created**. They may create, top up, deduct from and delete those accounts, and
every gigabyte they hand out is debited from a balance an admin recharges.

Spec as agreed (the two ambiguities are resolved here, not left open):

| Lever | Meaning | 0 means |
| --- | --- | --- |
| total traffic | the balance, in GB, that accounts are sold out of | no limit |
| days per gb | **forced**: an account's duration IS `GB x factor` days. The reseller has no expiry field at all | no coupling, reseller picks freely |
| minimum create gb | smallest account they may create | no floor |
| minimum add gb | smallest top-up in one edit | no floor |

Plus two toggles that are not quota: **enabled/disabled** (same semantics as an
admin's) and **allow external proxy**. And one new permission bit for admins,
`manageResellers`.

Refund rule, from the spec: deleting an account or deducting its traffic credits
the **unused** part back to the reseller. Consumed bytes are gone for good.

---

## 1. A reseller is a role, not a permission bit

The obvious cheap implementation is a 12th `Permission` bit plus some filtering.
That is wrong, and it is worth saying why before the schema.

`Permission` answers *what may this account do*. Every bit is orthogonal and
additive, and `User.Can` (`database/model/permission.go:79`) is a pure mask test.
A reseller changes something else: *which objects exist* for that account. Two
admins with identical masks see the same clients on a shared inbound; a reseller
and an admin never do. That is not expressible as a bit, and trying makes every
`Can` call site a place where someone must remember to also ask "...but is this a
reseller?".

So: a new column `is_reseller` on `users`, alongside `is_super_admin`, and the
mask becomes **derived** rather than stored:

```go
// database/model/permission.go
var resellerPerms = PermAccessInbounds | PermCreateClient | PermEditClient | PermDeleteClient

func (u *User) Can(perm Permission) bool {
	if u == nil || !u.Enable {
		return false
	}
	if u.IsSuperAdmin {
		return true
	}
	if u.IsReseller {
		return resellerPerms.Has(perm) // NOT u.Permissions
	}
	return u.Permissions.Has(perm)
}
```

Derived, not stored, on purpose. A stored mask drifts: an `ImportDB` of a
hand-edited backup, or a save path that forgets to clamp, leaves a reseller
holding `PermPanelSettings` and nothing in the code notices. Deriving makes the
role the single source of truth, and it is what the "no need for permission list"
in the spec actually means.

Three invariants fall out and must be enforced in `AdminService`:

- `IsSuperAdmin && IsReseller` is never true. A reseller cannot be promoted.
- A reseller's stored `permissions` column stays 0, so a future demotion to plain
  admin lands them with nothing rather than with a stale grant.
- `AdminService.GetAdmins` (`web/service/admin.go:60`) currently lists **every**
  row in `users`. It must gain `WHERE is_reseller = 0`, or resellers appear on the
  Admins page where a super admin can tick `isSuperAdmin` on one. This is a real
  escalation, not a cosmetic leak.

---

## 2. Schema

Two new tables, one new column, one new permission bit. All via
`database/db.go:32` `initModels`, which AutoMigrates; no hand-written migration.

### 2.1 `users` gains one column

```go
IsReseller bool `json:"isReseller" gorm:"default:0"`
```

On `users` rather than inferred from the profile row below, because
`session.loadLoginUser` (`web/session/session.go:77`) reads exactly one row from
`users` on every request and `Can()` needs the role on every gate. A join there
would be paid thousands of times per session to save one column.

### 2.2 `reseller_profiles`

Separate from `users` because these eight fields are meaningless for every admin
row, and because the balance is written under transaction on every account
create/edit/delete: keeping those writes off the row that every request reads is
worth one join on the rare page that needs it.

```go
type ResellerProfile struct {
	Id     int `json:"id" gorm:"primaryKey;autoIncrement"`
	UserId int `json:"userId" gorm:"uniqueIndex"`

	// AllowanceBytes is the cumulative traffic an admin has granted. SpentBytes is
	// what is currently committed to live accounts plus what past accounts burned.
	// Available = Allowance - Spent. Both in BYTES, never GB: the client quota this
	// is debited against is bytes (model.Client.TotalGB is a byte count despite the
	// name, see below), and a unit mismatch here is free traffic.
	AllowanceBytes int64 `json:"allowanceBytes" gorm:"default:0"`
	SpentBytes     int64 `json:"spentBytes" gorm:"default:0"`

	DaysPerGB   int `json:"daysPerGb" gorm:"default:0"`
	MinCreateGB int `json:"minCreateGb" gorm:"default:0"`
	MinAddGB    int `json:"minAddGb" gorm:"default:0"`

	AllowExternalProxy bool `json:"allowExternalProxy" gorm:"default:0"`

	// CreatedBy is the admin who owns this reseller. A non-super admin holding
	// manageResellers sees and edits only their own; see section 5.
	CreatedBy int `json:"createdBy" gorm:"index"`
}
```

**Check `model.Client.TotalGB`'s real unit before writing a line of this.** The
field is named GB (`database/model/model.go:262`) but the panel stores and
compares it against `ClientTraffic.Total`, which is bytes. The plan assumes bytes
throughout; confirm at the top of implementation and adjust the two conversion
points, not the ledger.

`AllowanceBytes == 0` means unlimited, per spec. It skips the *check* but not the
*accrual*: `SpentBytes` keeps climbing for an unlimited reseller. That is
deliberate, and it has one surprising consequence worth a line in the UI: turning
a limit on for a reseller who has been unlimited counts everything they already
sold. The alternative (accrue nothing while unlimited) hands them their entire
back catalogue free the moment a limit is applied.

### 2.3 `reseller_clients`

Client ownership and the per-account charge, in one row. They are 1:1 on the
account, so two tables would only be two things to keep in sync.

```go
type ResellerClient struct {
	Id int `json:"id" gorm:"primaryKey;autoIncrement"`
	// Email is the panel-wide account identity. xray.ClientTraffic.Email carries
	// gorm:"unique" (xray/client_traffic.go:14) and AdminService.CanAccessClientEmail
	// already keys on it, so this matches the seam that exists rather than inventing
	// a second notion of "which client".
	Email     string `json:"email" gorm:"uniqueIndex"`
	InboundId int    `json:"inboundId" gorm:"index"`
	UserId    int    `json:"userId" gorm:"index"`

	// ChargedBytes is what this account currently holds against its reseller's
	// balance. Raised on create and top-up, lowered on deduct and delete.
	ChargedBytes int64 `json:"chargedBytes" gorm:"default:0"`
	// AllTimeBase is ClientTraffic.AllTime at the moment of the charge, so
	// consumption is measured from the charge and not from the account's whole life.
	AllTimeBase int64 `json:"allTimeBase" gorm:"default:0"`
}
```

Absence of a row means "the house owns this account". Admins and super admins
never get rows: they have no balance, so there is nothing to charge, and making
absence the admin case means the existing admin paths need no ledger awareness at
all.

### 2.4 The new permission bit

```go
PermManageResellers        // appended to the iota block, database/model/permission.go:22
{PermManageResellers, "manageResellers"}   // AllPermissions, :43
```

Appended, never inserted: the bit values are positional and inserting shifts
every stored mask in the database by one.

---

## 3. The ledger

This is the part that has to be right. Everything else is plumbing.

### 3.1 Measuring consumption

Refunds need "how much of what I sold has been used", and it must survive a
traffic reset. `ClientTraffic.Up`/`Down` do not: `ResetClientTrafficByEmail`
(`web/service/inbound.go:2910`) zeroes both.

`ClientTraffic.AllTime` (`xray/client_traffic.go:19`) does. It is incremented
raw in the accounting loop (`web/service/inbound.go:2190`, *"AllTime stays raw:
it's the lifetime record of bytes actually moved"*) and there is a test asserting
a reset must not rewind it (`web/service/traffic_accounting_test.go:107`).

So:

```
consumed = max(0, ClientTraffic.AllTime - ResellerClient.AllTimeBase)
unused   = max(0, ResellerClient.ChargedBytes - consumed)
```

This gives the ledger a property worth stating: **an admin resetting a
reseller's account does not corrupt the ledger.** The reseller is still charged
for the reset bytes, which is correct, because the customer got to use them.

### 3.2 The four operations

Let `A` = available = `AllowanceBytes - SpentBytes` (or infinite when
`AllowanceBytes == 0`), `Q` = the account's current `totalGB`, `Q'` = the
requested new value, `C` = `ChargedBytes`.

**Create** with quota `Q`:
- reject `Q < MinCreateGB`
- reject `Q == 0` when the reseller is limited. An unlimited account out of a
  limited balance is the whole feature bypassed in one click, and it is the first
  thing anyone will try.
- reject `Q > A`
- `SpentBytes += Q`; insert row with `ChargedBytes = Q`, `AllTimeBase = 0`

**Top up** (`Q' > Q`), delta `d = Q' - Q`:
- reject `d < MinAddGB`
- reject `d > A`
- `SpentBytes += d`; `ChargedBytes += d`

**Deduct** (`Q' < Q`):
- new charge `C' = max(Q', consumed)`; refund `r = C - C'` (never negative)
- `SpentBytes -= r`; `ChargedBytes = C'`
- The clamp at `consumed` is the whole refund rule: a reseller cannot claw back
  bytes the customer already moved.

**Delete**:
- refund `r = unused`; `SpentBytes -= r`; drop the row

**Reset traffic**: denied for resellers. `resetClientTraffic`
(`web/controller/inbound.go:78`) is gated on `PermEditClient`, which a reseller
holds, so this needs an *explicit* block, not an absent bit. Reasoning: a reset
lets an account keep passing traffic past the quota its reseller paid for, so the
reseller would be giving away bytes off the house's balance, not their own.
`resetAllClientTraffics` and `resetAllTraffics` need `PermBulkOperation`, which a
reseller does not hold, so those are already closed.

### 3.3 Reserve first, create second

The check and the write are separate statements, so two concurrent creates can
both see the same `A` and both pass. SQLite serializes writes but not this
read-then-write pair.

Debit inside a transaction **before** the client is created, and release on
failure:

```
tx: read profile FOR UPDATE-equivalent, verify A >= Q, SpentBytes += Q, insert reseller_client
   -> AddInboundClient(...)
      -> on error: tx2 rolls the debit back
```

Deliberate failure direction: a crash between the debit and the create loses the
reseller some balance, which an admin can recharge. The reverse order loses the
panel real traffic with no record. Pick the one an operator can fix.

The alternative shape (thread the caller through `InboundService.AddInboundClient`
so it all happens in one transaction) is cleaner but touches a method with eleven
protocol branches and a large call graph. Recommend starting with reserve-first
in a new `ResellerService`, and only folding it inward if the two-phase seam
proves leaky under test.

### 3.4 Forced days per GB

With factor `F > 0` and a change of `dGB` gigabytes, the backend **overwrites**
whatever expiry the form posted:

```
expiryTime = max(now, currentExpiry) + dGB * F days
```

`max(now, ...)` handles both cases with one rule: an expired account restarts
from now, a live one extends from its existing deadline.

Two encodings exist for expiry in this codebase and the choice matters. A
**negative** `expiryTime` is the "delayed start" form: the magnitude is a
duration in ms and `adjustTraffics` (`web/service/inbound.go:2220`) converts it
to an absolute deadline on the account's first traffic. It is also what "freeze"
writes, so a frozen account is recognisable as `enable=false AND expiryTime<0`.

Recommendation: forced mode writes **absolute** expiry (positive), for two
reasons. Delayed-start collides with the freeze convention, and an account sold
today that starts counting whenever the customer feels like it is not what "3
days per GB" means to the person selling it. Flagged as a decision, not a
certainty; see section 9.

When `F == 0` the reseller picks the expiry freely and the field is shown
normally.

---

## 4. Where the enforcement goes

The scoping seam is `InboundService.GetInboundsFor` (`web/service/inbound.go:44`),
which today branches super-admin / granted-ids. A reseller needs a third branch
that also **strips the client list**, because the Inbounds page builds its table
by parsing `inbound.settings` client-side. Two things must be filtered:

1. `inbound.Settings` -> the `clients` array only. Everything else in that blob
   (protocol settings, `externalProxy`, and so on) stays.
2. `inbound.ClientStats`, the preloaded `ClientTraffic` rows.

Everything else is the leak checklist. Each of these is a separate route in
`web/controller/inbound.go:56-102` that a reseller can reach with the bits they
hold, and each needs a decision. This list is the deliverable of this section:

| Route | Gate today | Reseller reaches it? | Needed |
| --- | --- | --- | --- |
| `GET /list` | `accessInbounds` | yes | filter clients (above) |
| `GET /getClientTraffics/:email` | `requireClientAccess` | yes | make the middleware reseller-aware |
| `GET /getClientTrafficsById/:id` | `accessInbounds` | yes | extend the existing in-handler scoping |
| `POST /clientIps/:email`, `/clearClientIps/:email` | `requireClientAccess` | yes | same middleware fix |
| `POST /addClient` | `createClient` + body-inbound check (`:688`) | yes | + quota gate, + write ownership row |
| `POST /updateClient/:clientId` | `editClient` + body-inbound check (`:823`) | yes | + ownership check, + ledger delta, + carry ownership across email rename |
| `POST /:id/delClient/:clientId` | `deleteClient` + `owns` | yes | + ownership check, + refund |
| `POST /:id/delClientByEmail/:email` | `deleteClient` + `owns` | yes | same |
| `POST /:id/delDepletedClients/:id` | `deleteClient` + `owns` | **yes** | scope to own clients, or deny. As written a reseller deletes admins' depleted accounts |
| `POST /:id/copyClients` | `createClient` + `owns` | **yes** | scope source to own clients, and charge the copies |
| `POST /:id/resetClientTraffic/:email` | `editClient` + `owns` | **yes** | deny for resellers (section 3.2) |
| `POST /updateClientTraffic/:email` | `editClient` + `ownsClient` | **yes** | deny for resellers, same reasoning |
| `POST /onlines`, `/lastOnline` | `accessInbounds` | yes | scope the returned email list |
| `POST /bulkUpdateClients` | `bulkOperation` | no | closed by the derived mask |
| `POST /resetAllTraffics`, `/resetAllClientTraffics/:id` | `bulkOperation` | no | closed |
| inbound add/edit/delete/import | `createInbound` etc. | no | closed |

Two of those rows are the ones that would ship as bugs if this table were not
written out: `delDepletedClients` and `copyClients` both pass their existing
gates for a reseller and both reach across into admin-owned accounts.

`requireClientAccess` (`web/controller/permission.go:174`) becomes:

```go
if user.IsReseller {
    ok, err := resellerService.OwnsClientEmail(email, user.Id)
    ...
}
// existing inbound-grant check for everyone else
```

Note it must **replace**, not supplement, the grant check for a reseller: a
reseller does hold the inbound grant (that is how they see the inbound at all),
so the existing check passes and would let them straight through to an admin's
client on that same inbound.

### The rename hazard

`UpdateInboundClient` lets the email change. `ResellerClient` is keyed on email,
so a rename orphans the ownership row: the reseller loses the account from their
own view and the refund path can never find it again. The update path must carry
the row across, in the same transaction as the settings write. Worth a dedicated
test.

### Inbound deletion

`RevokeInboundEverywhere` (`web/service/admin.go:428`) exists precisely because
stale grants would be inherited by a recycled inbound id. `reseller_clients`
needs the mirror: drop every row for a deleted inbound. Whether the reseller is
refunded for accounts an admin deleted out from under them is section 9.

---

## 5. The escalation path in `manageResellers`

The Admins page is `requireSuperAdmin()`. The Resellers page will be
`requirePerm(PermManageResellers)`, so a **non-super admin** can hold it. That
opens a path that must be closed at design time:

> Admin A holds `manageResellers`. A creates reseller R, sets R's password, and
> assigns R an inbound belonging to admin B. A logs in as R and now sees B's
> inbound.

Two clamps, both required, both on the service and not the UI:

1. When the caller is not a super admin, the assignable inbound set is
   intersected with the caller's own `AccessibleInboundIds`
   (`web/service/admin.go:337`). On the GET that builds the checklist **and** on
   the POST that saves it. A checklist that only *renders* the intersection is
   cosmetic; the save is one crafted form away.
2. `ResellerProfile.CreatedBy`. A non-super admin lists, edits, recharges and
   deletes only resellers they created. Without it, admin A edits admin B's
   reseller's balance, or reassigns their inbounds.

This is the shape the `multi-admin-idor-seam` note warns about: the middleware
proves the caller may reach the *page*, and the ownership question lives in the
service, one layer down, where it is easy to not write.

---

## 6. Backend surface

New file `web/service/reseller.go`:

```go
type ResellerService struct{}

// profile CRUD
GetResellers(caller *model.User) ([]ResellerView, error)
AddReseller(caller *model.User, spec ResellerSpec) (*model.User, error)
UpdateReseller(caller *model.User, id int, spec ResellerSpec) error
DeleteReseller(caller *model.User, id int) error
Recharge(caller *model.User, id int, deltaBytes int64) error

// ownership
OwnsClientEmail(email string, userId int) (bool, error)
OwnedEmails(userId int) ([]string, error)
FilterInboundsForReseller(inbounds []*model.Inbound, userId int) error

// ledger
Quote(userId int, oldQ, newQ int64) (ChargeQuote, error)  // pure arithmetic, testable alone
Reserve(userId int, q ChargeQuote) error
Release(userId int, q ChargeQuote) error
CommitCreate(userId int, email string, inboundId int, charged int64) error
RefundAndDrop(email string) error
```

`Quote` being pure and separately testable is the point: the arithmetic in
section 3.2 is where the money is, and it should be provable without a database.

New file `web/controller/reseller.go`, group `/panel/resellers`, gated by
`requirePerm(model.PermManageResellers)`:

```
GET  /list          GET  /inbounds
POST /add           POST /update/:id      POST /del/:id
POST /recharge/:id
```

Bodies are **form-urlencoded** (`ShouldBind` with `form:` tags, never
`ShouldBindJSON`) and array fields arrive as repeated keys, exactly as
`adminForm` (`web/controller/admin.go:17-29`) documents.

Page route in `web/controller/xui.go`, beside `:38`:

```go
g.GET("/resellers", requirePerm(model.PermManageResellers), a.resellers)
```

---

## 7. UI

**Resellers page** (`web/html/resellers.html`), modeled directly on
`admins.html`: toolbar with Add + reload, one `a-table`, one modal. Columns:
username, enabled, inbounds, **balance** (used / total, with a progress bar),
days-per-GB, minimums, external proxy, actions.

Balance is displayed as `used of total` plus available, never as a raw editable
number. Recharge is its own action (`+N GB`), not an edit of the allowance
field: an admin typing over the total would silently rewrite history and either
free or strand every outstanding account.

**Sidebar** (`web/html/component/aSidebar.html:79`), a new entry after Admins:

```
{{ if .perms.manageResellers }} ... panel/resellers ... {{ end }}
```

`templatePerms` (`web/controller/util.go:151`) already emits every slug in
`AllPermissions`, so the new bit appears in `.perms` with no change there.

**The reseller's own view** is the ordinary Inbounds page with fewer rows. Three
additions:

- a balance chip in the toolbar (available GB), so they find out before the save
  fails rather than after
- the client modal hides the expiry control entirely when `daysPerGB > 0`, and
  shows the derived duration instead
- the client modal enforces `minCreateGB` / `minAddGB` client-side for the error
  message, with the backend as the truth

The sidebar entries for Settings, Xray, Core, Admins and Resellers all gate on
permission bits the derived reseller mask does not include, so they disappear for
a reseller with no template change. Verify rather than assume.

---

## 8. i18n and tests

**i18n.** New `[pages.resellers]` block in `web/translation/translate.en_US.toml`.
`TestTranslationKeyParity` (`web/i18n_toml_test.go`) fails on any en-only key not
listed in `knownMissing`, so either translate into all ten locales or add the new
keys to that set in the same commit. The English fallback in `web/locale.I18n`
means an untranslated key renders readable English, not a blank, so adding to
`knownMissing` is an acceptable first pass.

**Tests**, roughly in the order they should be written:

1. `Quote` arithmetic, table-driven, no DB: create / top-up / deduct-with-clamp /
   delete-refund / minimums / the `Q == 0` rejection / unlimited.
2. `AllTime`-based consumption survives a traffic reset (mirror the existing
   `traffic_accounting_test.go` shape).
3. Ownership: a reseller cannot read, edit or delete an admin's client on an
   inbound they share, per route. This is the `idor_test.go` pattern already in
   `web/controller/`; extend that file rather than starting a new one.
4. Email rename carries the ownership row.
5. `GetInboundsFor` strips other people's clients from both `Settings` and
   `ClientStats`.
6. A non-super admin with `manageResellers` cannot assign an inbound they do not
   hold, on the POST and not just the GET.
7. `GetAdmins` does not list resellers.
8. `Can()` for a reseller ignores a non-zero stored `permissions` column.
9. Concurrent creates cannot overshoot the balance.

---

## 9. Build order

1. Model + migration + derived `Can()` + `GetAdmins` exclusion. Nothing user
   visible; the panel must still behave identically. (tests 7, 8)
2. `ResellerService.Quote` and the profile CRUD. (test 1)
3. Resellers page, sidebar, i18n. An admin can create a reseller who cannot yet
   log in usefully.
4. Ownership table, `GetInboundsFor` filtering, `requireClientAccess`. A reseller
   can log in and sees an empty but correct panel. (tests 3, 5)
5. The ledger wired into create / update / delete, reserve-first. (tests 2, 4, 9)
6. The leak checklist in section 4, route by route.
7. Forced days-per-GB and the client modal changes.
8. The escalation clamps in section 5. (test 6)

Steps 1 and 4 are the ones that can break the existing panel; both are behind
`is_reseller = 0` for every existing row, so a panel with no resellers takes the
same code paths it does today.

---

## 10. Open questions, as resolved when this was built

All seven were decided during implementation rather than left blocking. The
recommendations below are what shipped; the reasoning is preserved so a later
change is a decision and not a discovery.

7 was the only one that could have invalidated the ledger, and it was settled
first: **`model.Client.TotalGB` is BYTES**, not gigabytes.
`web/assets/js/model/inbound.js:2577` divides it by `ONE_GB` purely for display,
and `web/service/inbound.go:2506` assigns it straight to `ClientTraffic.Total`,
which is bytes. The plan's assumption held.

Also found and fixed while building, none of which the plan anticipated:

- **A negative `totalGB` minted balance.** `NewTotal` is read straight off the
  request body, so a negative one priced as a negative charge and `reserve()`
  wrote it into `SpentBytes`: creating an account paid the reseller. Now refused
  outright (`ErrInvalidQuota`), first check in `Quote`.
- **The unlimited flag could uncap an already-sold account.** The zero-quota rule
  keyed on the reseller's flag, so an account sold out of a limited balance could
  be deducted to zero during any window in which its reseller was unlimited: the
  full refund landed AND the customer kept an uncapped account. The rule now also
  keys on the account (`in.OldCharged > 0`).
- **`gbToBytes` wrapped**, and a wrapped negative reads as "no floor set", so an
  absurd minimum silently disabled the limit it was setting. Now saturates.
- **Forced expiry overflowed** into an already-expired account, because an
  out-of-range float64 to int64 conversion is undefined in Go and wraps in
  practice. Now saturates at a century.
- A negative `SpentBytes` read as balance on top of the allowance. Now clamped.

## 11. Original open questions

Each is followed by what was decided.

1. **Absolute or delayed-start expiry** under forced days-per-GB (section 3.4).
   Recommend absolute. Delayed-start collides with the freeze encoding.
   **SHIPPED: absolute.**
2. **Expired accounts**: refund the unused portion, or not? Recommend **not**.
   The reseller sold a time-boxed account and the time is what expired. Refunds
   stay tied to an explicit delete or deduct.
   **SHIPPED: no refund on expiry.**
3. **Admin deletes a reseller's account**: refund the reseller, or not? Recommend
   yes, refund, since the reseller did not choose it.
   **SHIPPED: refunded, via ResellerService.DropInbound.**
4. **Deleting a reseller who still has live accounts.** `DeleteAdmin`
   (`web/service/admin.go:279`) refuses while the admin owns inbounds. Mirror
   that (refuse, tell them to delete the accounts first), or offer a cascade that
   deletes the accounts too? Recommend refusing, for the same reason: the
   accounts keep working and their customers keep connecting either way, so the
   deletion should be deliberate.
   **SHIPPED: refused, with the account count in the message.**
5. **Does a reseller see traffic totals** for their own accounts? Assumed yes,
   they need it to sell. Confirm.
   **SHIPPED: yes. ClientStats is filtered to their own accounts, not hidden.**
6. **`allow external proxy`** is inbound-level in this codebase
   (`model.ClientExternalProxy`, `database/model/model.go:52`, "affects generated
   links only: no daemon ever reads it"). Reading the toggle as "the configs and
   links this reseller generates may carry the inbound's external-proxy
   endpoints". Confirm that is the intent, rather than "the reseller may edit the
   endpoint list".
   **SHIPPED as the former: when the toggle is off, PrepareClientCreate/Update
   strips `externalProxy` from the posted client before it is stored.**
7. **`model.Client.TotalGB`'s unit** (section 2.2). Verify before implementing.
   **RESOLVED: bytes. See section 10.**
