# Upgrading to the accounts model

What happens to a live panel when this version starts, what it does to your data,
and how to get back if you want to.

Written for the case that matters: a panel with hundreds of sold accounts, being
upgraded by an operator who cannot afford to move a single address or invalidate a
single installed client config.

---

## 0. The short version

**Nothing about your existing accounts changes.** The upgrade adds two index
tables beside your data and writes nothing else. Every account keeps its email,
its credentials, its quota, its expiry and its tunnel address. Every installed
client config keeps working.

The new capability is opt-in per account: until you tick a second inbound on
somebody, every account behaves exactly as it did before.

---

## 1. What actually runs on first start

In order, on every start (not only the first):

1. `MigrationSubIds` and `MigrationAccountSlots`, which already ran in previous
   versions.
2. **A tagged database backup**, once, to
   `<db dir>/backups/vpn-ui_pre-accounts_<timestamp>.db` (with its `-wal`/`-shm`
   sidecars). The WAL is checkpointed first so the copy is as close to a
   point-in-time snapshot as a file copy gets.
   **If this fails, the migration does not run at all.** The panel starts
   normally on the legacy model and logs an error. An upgrade without a good
   backup is not worth it.
3. **`MigrationAccounts`**, the backfill.

### The one property everything rests on

> `MigrationAccounts` is **additive only**. It inserts into `accounts` and
> `account_inbounds`. It never writes to `inbounds`, `client_traffics`,
> `reseller_clients` or `inbound_client_ips`.

That single constraint is what makes the upgrade safe, and it buys four things
for free:

- A failure at any point leaves the database **byte-identical** to before it ran.
- There is no half-migrated state you could be left serving from.
  `settings.clients` stays the truth the whole time, and every daemon, config
  generator and address allocator keeps reading it unchanged.
- An **older binary put back afterwards ignores both new tables** and behaves
  exactly as it did before.
- The pass can be aborted, retried or skipped with no consequence.

There is a test that snapshots all four of those tables before and after the pass
and fails loudly if a single byte moved (`TestMigrationAccountsIsAdditiveOnly`).

### The verification gate

Before the transaction commits, three invariants are checked:

1. Every client entry with an email has exactly one account and exactly one
   membership on that inbound.
2. Every account has at least one membership.
3. **The projection round-trips.** Re-rendering each account back into a client
   entry reproduces the entry that is stored.

If any check fails the **whole pass rolls back**, the migrated flag stays unset,
and the panel runs on the legacy model exactly as before. Half-enabling is not an
option.

Check 3 compares *effective meaning*, not stored bytes, and the difference is
deliberate. An absent JSON key equals its zero value (`model.Client` declares
`totalGB`, `subId`, `comment` and friends without `omitempty`, so entries written
by older binaries are simply missing keys the projection now writes as zeros);
`email` folds through the same lower-and-trim rule identity is compared by
everywhere else; and a missing `slot` falls back to the list index, which is the
address the account is on right now. A byte-identity gate would have rolled the
migration back on essentially every upgraded panel.

---

## 2. Cases it handles, and how

| Case | What happens |
|---|---|
| Client with no email | Skipped and counted. No email, no account identity. |
| `"bob "` and `"bob"` | Folded into ONE account. They were always the same person. |
| Same email on two inbounds, same values | One account, two memberships. This is the feature. |
| Same email on two inbounds, DIFFERENT quotas | First inbound (lowest id) wins, both memberships created, the divergence is **recorded in the report**. Reachable only through a DB import or a hand-edited DB; the service layer refuses it. |
| Copied accounts `bob` and `bob_5` | Stay **two separate accounts**. They have separate emails and separate quotas, which is what they are. No merge is guessed from the suffix. |
| Unparseable settings JSON on one inbound | That inbound is skipped and listed in the report. It stays on the legacy path and keeps working. The rest migrate. |
| Client with no `slot` | Stamped with its list index, which is the address it is already on. |
| wg-c / awg per-device keypairs | Preserved verbatim. See section 5. |
| Orphaned `client_traffics` rows | Left alone. |

The report (accounts created, memberships created, inbounds skipped, clients
skipped, conflicts) is stored in the settings table under
`accountsMigrationReport`.

---

## 3. Using the feature

An account is put on several inbounds by sending a repeated `inboundIds` field to
the existing routes:

```
POST /panel/api/inbounds/addClient
POST /panel/api/inbounds/updateClient/:clientId
```

Bodies are **form-urlencoded**, not JSON (the panel posts everything through
`Qs.stringify`, and Gin binds with `ShouldBind`).

```
id=3&inboundIds=3&inboundIds=7&inboundIds=9&settings={"clients":[{...}]}
```

Semantics, and the distinction matters:

- **`inboundIds` absent** means "just the inbound in the body". This is what every
  existing caller sends, so the Telegram bot, the bulk paths and any script you
  already wrote keep behaving exactly as before.
- **`inboundIds` present** means "these inbounds and no others". Unticking one
  **removes** the account from it.

### What it refuses, and why

**Two inbounds of the same protocol, for l2tp, pptp and ikev2.** Those three
authenticate through a shared daemon that sends a bare NAS-Identifier (`l2tp`,
not `l2tp-3`), so the RADIUS server cannot tell which inbound a login belongs to
and resolves it to whichever has the lower id. The account would be created,
appear on both, log in fine, and always be served by one of them, silently taking
that inbound's address range and user limit.

`openvpn`, `openconnect` and `sstp` already send `<proto>-<inboundId>` and
resolve exactly, so two memberships on those are allowed.

### Ownership

Every id in `inboundIds` is checked against the caller's grants, not just the
target. Adding and removing are authorized separately: you may only remove an
account from an inbound you own, so editing a shared account without ticking an
inbound you cannot see leaves it alone rather than unprovisioning it.

---

## 4. What this fixes on the way

These were live bugs before the accounts layer and are fixed by it. If you have
ever used **Copy Clients**, you have been exposed to them.

- **Quota depletion was inbound-scoped.** One traffic row names one inbound, so
  when an account ran out of traffic it was removed from that inbound only and
  **kept passing traffic on every other one**, while still billing into the same
  row. `up + down` grew past `total` forever with `enable` already false. Free
  traffic, silently. (Three separate code paths had this: the disable sweep, the
  generated Xray config, and the live no-restart push.)
- **Delayed start and auto-renew converted on one inbound only**, so the others
  kept a negative expiry forever and rendered as "delayed start" on an account
  whose clock had been running since its first connection.
- **An account on vless AND l2tp lost its vless routing rule.** The moment an
  email had any tunnel address it was moved out of the rule's `user` list and
  replaced by a source-IP match, which covers tunnel addresses only.
- **Admin visibility was decided by whichever inbound the traffic row named.** An
  admin holding inbound B but not A was denied every per-client route for a
  client sitting in their own inbound.
- **No validation existed on emails, subIds or VPN usernames.** The credential
  VPNs authenticate out of whitespace-delimited, line-oriented files (so a
  newline in a username appends a record the operator never created), the
  openvpn per-client block is a file *named* after the username (so a `/` or
  `..` escapes the directory), the subId is used directly as the `/sub/<subId>`
  path component, and Xray's counter is named `user>>><email>>>>traffic` (so a
  `>` misattributes traffic between accounts). None of it was rejected anywhere.

  Now enforced on all four write paths: `AddInbound`, `UpdateInbound`,
  `AddInboundClient` and `UpdateInboundClient`. Each is separately reachable from
  the API, so any one left out would be a hole the whole class walks through.

  **The upgrade itself cannot strand anyone, and neither can a legacy account.**
  Only entries that actually CHANGED are held to the rules. The whole-inbound
  save posts every client on the inbound, so without that exemption a single
  account created years ago with a space in its username would fail validation on
  every later save, and the operator could not change the inbound's DNS, rename
  it, or add an unrelated account until they first fixed that one row. On a panel
  with hundreds of sold accounts that would be an upgrade that bricks an inbound.

  So: a pre-existing bad value keeps working, stays deletable, and can still have
  its quota or expiry edited. What it cannot do is be edited into a *different*
  bad value, because the exemption is on the exact (email, subId, username)
  triple: touch any part of it and the whole triple is new and is held to the
  current rules. Creating a bad value is refused outright.

---

## 5. Why the projection cannot lose your data

`settings.clients` remains the only thing every daemon, allocator and config
generator reads. Accounts are rendered back *into* it. Two rules make that safe:

1. **Overlay, never rebuild.** Rendering starts from the entry that is already
   there and writes only the fields the account owns. This is load-bearing:
   `model.Client` does not model wg-c/awg `devices[]` at all, so a
   rebuild-from-known-fields would have destroyed **every per-device WireGuard
   keypair on first write**, invalidating configs already installed on your
   users' devices. The membership row also keeps the original entry verbatim.
2. **Splice in place, never reorder.** Position is load-bearing: an account with
   no explicit slot falls back to its index in `clients[]`, so compacting the
   array would move live sessions onto other accounts' tunnel addresses. Every
   pool-protocol entry is written with an explicit slot so this cannot happen.

---

## 6. Getting back out

Three levels, in increasing order of bluntness.

### 6.1 Binary rollback

The two tables are additive, so an older binary ignores them and reads
`settings.clients` unchanged. Clean right up until you create your first
multi-inbound account; lossy after that, because the non-home inbounds lose quota
enforcement again.

### 6.2 `vpn-ui revert-accounts`

Drops the accounts layer and clears the migrated flag.

On a panel where every account is on ONE inbound this is **exactly a no-op for
the data plane**: every account keeps its entry, credentials and address, and
only the two index tables go.

It **refuses** while any account is on several inbounds, and names them. That
refusal is the point, not an inconvenience: dropping the tables there would leave
several settings entries sharing one email and one `client_traffics` row, which
is the shape that leaks quota between inbounds. Put those accounts back on a
single inbound first (edit the client, untick the extras), then re-run it.

### 6.3 The pre-accounts backup

`<db dir>/backups/vpn-ui_pre-accounts_<timestamp>.db`, taken before the first
pass. Stop the panel, put the file back, start it.

---

## 7. Known limits

- **Two inbounds of the same protocol** are refused for l2tp, pptp and ikev2 (see
  section 3). Lifting it needs per-inbound NAS-Identifiers in those three shared
  daemon configs.
- **Traffic multipliers cannot be attributed for the Xray-native protocols.** The
  core's own counter is named `user>>><email>>>>traffic>>>uplink` with no inbound
  component, so an account on vless *and* trojan gets one number covering both
  and there is nothing to attribute it by. Those bytes bill at the **highest**
  multiplier among the account's inbounds, so the ambiguity can only over-bill,
  never hand out free traffic. The tunnel protocols and the two relays are billed
  at their real source.
- **Address pool consumption multiplies.** One account on l2tp + pptp + openvpn +
  openconnect at K=1 consumes 4 slots and 5 addresses (openvpn contributes two,
  its UDP address and its TCP mirror). At K=16 it consumes 4 slots and 80. The
  pool capacity guard will fire sooner than it used to.
- **Per-membership quotas do not exist.** The whole point is one quota per
  account. A per-inbound sub-cap would be a new column on the membership row.
