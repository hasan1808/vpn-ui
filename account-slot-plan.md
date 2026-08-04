# Stable account slots: fixing "deleting one account moves everyone else's IP"

> **Status: implemented** (2026-07-25). `model.Client.Slot` + `slotOr`/`slotsForNewAccounts`/
> `assignSlotsToClientMaps` in `web/service/vpnrange.go`, allocation wired into AddInbound /
> AddInboundClient / UpdateInbound / UpdateInboundClient, reads switched in `openvpn.go`,
> `radius.go` (auth, device-lease key, both routing maps), `wgc.go` and `awg.go`,
> `MigrationAccountSlots` called from `runWebServer`, `slot` added to the eight pool-protocol
> browser models (the existing `TestWireguardClientModelsRoundTripEveryStoredField` guard
> caught that omission), covered by `web/service/account_slot_test.go`.
>
> **Verified live** on the incus box (ubuntu-24 server + 3 ubuntu-24 clients): the two
> scenarios that failed on every prior run now pass, with no regression in the allocator.
>
> ```
> openvpn  delete-middle        pass   (was: "address moved from 10.2.0.4 to 10.2.0.3")
> openvpn  delete-middle-accept pass   (was: same)
> openvpn  creation-order / five-accounts / user-limit-2   pass
> wg-c     delete B of A,B,C -> A on 10.7.0.2 and C on 10.7.0.4 both keep passing traffic
>          with their ORIGINAL installed configs (was: C at zero traffic, code 000)
> ```
>
> **Verified again on a real panel** (2026-07-25, box 65, Debian 13), as a before/after on the
> same machine: three accounts per protocol, address read from the real consumer (RADIUS
> `Framed-IP-Address` via a bare Access-Request for the PPP family, the `*-configs` endpoint
> for awg/wg-c, `blocks-udp/<email>` for openvpn), middle account deleted, re-read.
>
> ```
>                       v1.8.2 (pre-slot)          this change
> l2tp                  10.0.2.4 -> 10.0.2.3       .4 -> .4
> pptp                  10.1.2.4 -> 10.1.2.3       .4 -> .4
> openconnect           10.4.0.4 -> 10.4.0.3       .4 -> .4
> sstp                  10.5.2.4 -> 10.5.2.3       .4 -> .4
> ikev2 (eap-mschapv2)  10.6.1.4 -> 10.6.1.3       .4 -> .4
> awg                   10.8.0.4 -> 10.8.0.3       .4 -> .4
> openvpn               10.2.0.4 -> 10.2.0.3       .4 -> .4
> wg-c                  10.7.0.4 -> 10.7.0.3       .4 -> .4
>                       survivors moved: 8/8       survivors moved: 0/8
> ```
>
> Also on that box: `MigrationAccountSlots` ran against two genuinely pre-slot inbounds
> (a wg-c and an ikev2 written by an older binary), stamped `slot = current index`, and moved
> nothing — the wg peer kept `10.7.1.2/32` and its traffic counters. Single delete, bulk
> delete, and a panel restart all hold. A new account added after a delete reuses the freed
> slot while a later-created account keeps its higher one, so list position and address are
> decoupled in both directions. The User-Limit residual reproduces exactly as documented
> below: raising an inbound's User Limit 1->2 keeps the slots and moves slot 2 from `.4` to
> `.6` (base + slot*K), and lowering it back restores `.4`.
>
> One thing the sweep turned up that is NOT about slots: a client delete does not rewrite
> openvpn's `blocks-*` files. `RestartServices` only starts processes, and the write lives in
> `GenerateAllConfigs`, which is called from `InitOpenVpn` — so the CCD is refreshed at panel
> startup, not on the delete. Harmless for the address (the connect hook re-reads it), but any
> test that reads the CCD without restarting is measuring a stale file.
>
> The research below is the record of why it is shaped this way.

## The defect

A VPN account's tunnel address is derived from its **position in `settings.clients`**. Nothing
persists the mapping, so the address is only stable while the list is. Deleting an account
compacts the array, and every account after it silently moves to a new address.

```go
// web/service/openvpn.go:522, web/service/radius.go:963/1404/1471,
// web/service/wgc.go:394/700/808/1055, web/service/awg.go:390/655/770/1016
for i, client := range settings.Clients {
    ips := ...(subnets, i, k)   // i IS the account's identity on the data plane
}
```

Every consumer agrees on "raw list position" (the loops `continue` rather than counting, so
enable/disable does not shift anything), which is why this has never produced a visible
inconsistency *between* subsystems. The problem is the scheme itself.

## What the index feeds, per protocol

| protocol | the index decides | consumed by | severity when it shifts |
|---|---|---|---|
| openvpn | the account's block in `blocks-<proto>/<username>` (`ovpnBlockClientIP`, `vpnAccountDeviceIPs`) | the client-connect hook's `ifconfig-push`, the routing map, nft accounting | **medium.** The address is pushed on each dial, so a client recovers by redialling; until it does, its live session sits on an address the panel now attributes to another account. Verified: survivor moved `10.2.0.4` -> `10.2.0.3`, and the panel logged `acct-stop stale — ip=… reassigned to a live session` across accounts. |
| l2tp, pptp, openconnect, sstp, ikev2 (eap-mschapv2) | the RADIUS Framed-IP handed out at auth (`computeVpnClientIP(..., clientIndex, ...)` / `vpnAccountDeviceIPs`) **and** the device-lease key `proto:inbound:clientIndex:station:nasPort` (radius.go:1043) | the daemon's tunnel IP, User Limit enforcement, the routing map | **medium-high.** Next auth gets a different address; live sessions keep the old one and are attributed to whoever now owns that index. The lease key changing means an account's device bookkeeping is orphaned and can inherit the freed keys of the account that used to hold the slot, so the User Limit can over- or under-count. |
| ikev2 (psk, eap-tls) | nothing (single account, whole-block CIDR) | — | none |
| wg-c, awg | the account block -> the peer's `AllowedIPs` **and** the `Address =` line written into the client's `.conf` | kernel cryptokey routing; the config the subscriber already installed | **highest, verified.** WireGuard has no push, so the installed file keeps the old address while the server routes the peer to the new one. Three accounts on `10.7.0.2/.3/.4`, all with internet; deleting the middle one left the third with a completed handshake and **zero traffic** (`internet=fail, code 000`) because the panel had moved it to `10.7.0.3` while its config still said `10.7.0.4`. Only re-downloading the config recovers it. |
| mtproto, ssh | nothing (relays, identity is the secret / username) | — | none |

## What actually shifts the list

Shifts it:
- `DelInboundClient` / `DelInboundClientByEmail` (single delete) — rebuilds `clients` from the survivors.
- `DelDepletedClients` / `DelDepletedClientsScoped` — same, and removes many at once.
- `BulkUpdateClients` with a delete operation.
- the reseller cascade delete.
- any whole-inbound save that posts `clients` in a different order (not reachable from today's
  UI, but the API allows it).

Does **not** shift it (checked, so the fix does not need to cover them):
- adding a client — appended at the end.
- editing a client — `UpdateInboundClient` replaces the entry at its existing index in place.
- enabling/disabling — the allocators `continue` past a client, they do not renumber.
- sorting the client table in the UI — view-only; the drag-reorder component
  (`component/aTableSortable`) is used for Xray routing rules only.

## The fix: a persisted slot per account

Give each account a slot number that is allocated once, stored with the account, and never
derived from list order again.

### 1. Storage

```go
// database/model/model.go
Slot *int `json:"slot,omitempty"` // data-plane slot: the account's index into its
                                 // inbound's address pool. Absent on rows written
                                 // before slots existed; see MigrationAccountSlots.
```

A pointer, so "absent" is distinguishable from slot 0. `omitempty` keeps every other
protocol's client JSON byte-identical. Precedent: wg-c/awg already persist per-account
allocation state on the client (`devices[]`, each with its own keypair), so this is the same
shape, not a new concept.

Rejected alternatives:

- **A side table keyed by (inbound id, email).** It would need its own consistency rules
  against a settings blob that every allocator already parses, and backup / import / reseller
  flows would each have to carry it.
- **Leaving a tombstone entry in `clients` on delete** so nothing shifts. Cheap at the delete
  site and nowhere else: every consumer that walks the client list would have to learn to skip
  tombstones (RADIUS auth, the subscription service, the traffic jobs, the client table, bulk
  ops, quota reporting, the reseller ledger), and a missed one silently resurrects a deleted
  account. The slot field touches only the allocators, which is a much smaller blast radius
  than "everything that reads clients".

### 2. Allocation

One helper, used by every path that creates accounts (`AddInbound`, `AddInboundClient`,
bulk add, `CopyInboundClients`, DB import):

```go
// the slots the next n accounts would take: the lowest free ones
func slotsForNewAccounts(existing []model.Client, n int) []int
// stamps them onto the raw client maps an add/update posted
func assignSlotsToClientMaps(protocol model.Protocol, existing []model.Client, clients []any)
```

Lowest-free (not monotonic) so a pool cannot leak capacity on a panel that churns accounts.
The consequence is deliberate: a new account may inherit a deleted account's addresses. That
is safe here because every client change already rebuilds the routing rules and the nft
accounting chains from scratch, so nothing of the old account survives to collide — but the
new account must be created in the same transaction that drops the old rules, which is the
existing `onXxxClientChanged` ordering.

### 3. Reading

```go
func slotOr(slot *int, listIndex int) int {
    if slot != nil && *slot >= 0 { return *slot }
    return listIndex // a row the migration has not reached; keeps today's behaviour
}
```

Then replace `i` with `slotOr(client.Slot, i)` at exactly these sites:

- `web/service/openvpn.go`: `writeClientConfigDir` (the blocks loop), `ovpnClientIP`.
- `web/service/radius.go`: the auth path (`clientIndex`), the device-lease key, and both
  routing-map loops (PPP family + openvpn).
- `web/service/wgc.go`: `wgcDeviceIPs`, `wgcAccountCIDR`, and the reconcile/config loops.
- `web/service/awg.go`: the same four.

### 4. Migration

A startup pass beside `MigrationSubIds` (already called from `runWebServer`, see
[the note in main.go] — `MigrateDB` alone is not enough, it only runs for the `migrate`
subcommand and DB import):

```go
func (s *InboundService) MigrationAccountSlots()
```

For every inbound of the affected protocols, stamp `slot = current list index` on any client
without one. Idempotent, and it must run **before** the servers start so no allocator can
observe a half-stamped inbound. Nothing moves on upgrade: every account keeps the address it
has today.

### 5. Capacity guard

`maxVpnAccounts` currently compares a **count** against the pool. With sparse slots the
question becomes "does the slot I am about to allocate fit the pool", so:

- `AddInboundClient`'s guard checks the allocated slot against capacity, not `len(clients)`.
- when the lowest free slot exceeds capacity, `AutoExpandVpnRanges` runs first (as it does
  now) and the guard is re-evaluated.

### 6. Tests

- unit: `slotsForNewAccounts` (empty, contiguous, with holes), `slotOr` fallback,
  `MigrationAccountSlots` (stamps the current index, idempotent, leaves other protocols
  alone), and the capacity guard against a sparse inbound.
- E2E, in the drivers written for this investigation: `ovpn_accounts_matrix.py`'s
  `delete-middle` already asserts "the address did not move" and currently fails on it — it
  becomes the regression test. Add the same assertion for the wg-c path
  (`ovpn_accounts_wgc.py`) and one for the bulk `delete-depleted` route.

## Risks

- **Slot reuse hands a new account an old account's address.** Mitigated by the existing
  rebuild-everything-on-change ordering; worth an explicit test that a freshly created
  account gets no traffic attributed from the deleted one.
- **Changing an inbound's User Limit still moves every address**, because the block size
  changes. Out of scope: it is an explicit admin action on a settings page, not a side effect
  of unrelated account management. Worth a UI warning.
- **Rows written by an old binary while the new one runs** (mixed-version panels) land
  without a slot; `slotOr`'s fallback keeps them on today's behaviour until the next startup
  migration stamps them.
- ~~**A reused slot inherits the RADIUS device-lease keys** of the account that held it
  (`proto:inbound:slot:station:nasPort`), so for as long as those entries live a new account
  behind the same NAT and pppd unit could be counted against a departed one.~~
  **Measured on box 65 (2026-07-25): this does not happen.** The key does collide (it carries
  the slot, and the slot is reused), but `delInboundClient` calls the full `onL2tpChanged()`
  hook — not the `clientOnly` variant used for edits — so `ResetAllocations(protocol)` drops
  the whole protocol's `stationIP` cache and every pending lease before the new account can
  authenticate. Verified with a discriminating probe: an account that fills slot 1's two-IP
  block on keys 71/72 has key 72 pinned to `.5` on re-auth (the idempotent-redial cache is
  demonstrably live), yet the replacement account authenticating on that same key 72 three
  seconds later gets `.4` — the lowest free IP, i.e. a fresh allocation — and its User Limit
  still counts correctly (2 devices accepted, the 3rd rejected). `client_traffics` is keyed
  by email, so usage attribution was never at risk either way.

## Effort

Model + migration + 4 allocator files + the capacity guard + tests: roughly 300-400 lines,
one focused change set. No UI work required.

## How to verify (the drivers already exist)

```sh
# 1 ubuntu-24 server + 3 ubuntu-24 clients, kept for reuse
sudo python3 -m test_unit.harness.ovpn_accounts_test --keep

# openvpn: delete-middle asserts the survivors' addresses do not move (fails today)
sudo python3 -m test_unit.harness.ovpn_accounts_matrix delete-middle delete-middle-accept

# wg-c: the survivors' INSTALLED configs must keep working after a delete
sudo python3 -m test_unit.harness.ovpn_accounts_wgc

# regression net for the allocator, all currently green
sudo python3 -m test_unit.harness.ovpn_accounts_matrix creation-order simultaneous \
    user-limit-2 five-accounts reconnect-fast
```
