# In-core IP limiter (replacing the fail2ban path)

Goal: a per-account limit on concurrent client source IPs that actually works,
enforced inside the patched Xray core, with no fail2ban, no access-log parsing,
and no collateral damage.

## Scope, stated honestly up front

This is an **IP limiter, not a device limiter**. K devices behind one NAT still
present one source IP and will still count as 1. That is irreducible and is not
a defect of this design: see `device-limit-plan.md` for why counting devices
behind NAT is foreclosed (RFC 6864, the Linux 4.10 tsoffset commit, and our own
uTLS default that makes every client's ClientHello byte-identical).

Keep the existing name `LimitIP` / "IP Limit". It is already honest. Do NOT
rename it to anything with "device" in it. That naming drift is exactly what
V2bX shipped (`IPLimit int \`json:"DeviceLimit"\``) and what makes operators
distrust the feature.

So the value here is NOT better counting. It is that every failure mode OTHER
than the NAT undercount goes away.

## Why the current implementation must go (all verified in-tree)

The existing feature does nothing on a default install:

1. **Off by default.** `web/service/config.json:3` ships `"access": "none"`, and
   `web/service/setting.go:689` is
   `return (accessLogPath != "none" && accessLogPath != ""), nil`. So
   `GetIpLimitEnable` is false and the whole UI is hidden.
2. **No jail ships.** Zero hits for `failregex` / `filter.d` / `jail.local`
   anywhere in the repo outside a Go comment. Upstream's `x-ui.sh iplimit`
   installer does not exist in `vpn-ui.sh`. So even with the log enabled, the
   log line at `check_client_ip_job.go` is read by nothing.
3. **It cannot disconnect anyone.** `disconnectClientTemporarily` calls
   `RemoveUser` -> `validator.Del`, but the VLESS validator is consulted exactly
   once per connection, in `DecodeRequestHeader`
   (`third_party/Xray-core/proxy/vless/encoding/encoding.go`). Established
   connections are untouched, and the user is re-added 100ms later.
4. **It guesses.** `check_client_ip_job.go:54` `ipStaleAfterSeconds = 30 * 60`
   plus `mergeClientIps` (`:381`) exist because a log scrape cannot know when an
   IP went idle. That guess caused the documented #4077 continuous ban loop: the
   IP actually in use got classified as "new excess" and banned every run.
5. **It bans by address.** fail2ban's action is an iptables ban on `<ADDR>`. On
   carrier CGNAT that bans **unrelated paying customers** who share the egress.

## Why in-core, not the Go backend

- The backend **cannot kick**. See point 3 above. Whatever it decides, it cannot
  act on a live connection.
- The backend would have to **poll**. The core does expose the data already
  (`GetStatsOnlineIpList`, `GetAllOnlineUsers` in
  `third_party/Xray-core/app/stats/command/command.go`, fed by a refcounted
  `OnlineMap` at `app/stats/online_map.go:23`, gated behind `statsUserOnline`
  which is absent from our template at `config.json:44-50`). But polling is
  always late, and it still has nothing to act with.
- The core sees **admission**. It can refuse before a byte flows.
- We already own the seam. `common/speedlimit/` + two dispatcher hooks +
  a hot-reloaded sidecar is exactly the shape this needs.

## The design

### Refuse at admission, do not kill

Both dispatcher entry points return an error:

- `Dispatch(ctx, destination) (*transport.Link, error)` (`default.go:285`)
- `DispatchLink(ctx, destination, outbound) error` (`default.go:324`)

Returning an error makes the inbound proxy close the client connection. This is
why phase 1 needs **no kill path** (which we do not have). It is also cleaner
than V2bX's approach of closing the link pipes by hand.

Note these are the same two functions that reach our existing `getLink` (`:140`)
and `WrapLink` (`:189`) hooks, so the protocol coverage is identical to the
speed limiter's: vmess/trojan/shadowsocks via `Dispatch`, and vless/socks/
dokodemo/mux/http via `DispatchLink`.

### State

In `common/speedlimit` (same package, same sidecar, same hot reload):

    email -> map[ip]int   // refcount of live connections per IP
    email -> map[ip]time  // first-seen, for phase 2 (evict-oldest)

Admission, per connection:

1. Resolve the email via the existing `LookupSession` (`speedlimit.go:151`):
   email if present, else resolved from `sessionInbound.Source.Address` through
   the IP/CIDR index.
2. No `ipLimit` for that email -> allow, allocate nothing.
3. IP already known for that email -> refcount++, allow. (A known device opening
   its 50th connection is always allowed.)
4. Under K distinct IPs -> refcount=1, allow.
5. At K -> **reject** (phase 1): return an error from Dispatch/DispatchLink.

Release via `context.AfterFunc(ctx, ...)`, exactly as `trackOnlineIP`
(`default.go:243`) already does: refcount--, delete the IP at zero.

### Refcounting is the point

An IP frees the instant its last connection closes. There is no staleness
window, no `mergeClientIps`, no guess. That single property removes the entire
class of bug that produced #4077.

Consequence to document: with `connIdle` at its 300s default, a roamed-away IP
can hold its slot until its last idle connection times out. That is bounded and
correct (the connections really are still open), unlike the current 30-minute
guess.

## Sidecar

Add one field per user to the existing `bin/speedlimits.json`
(`XRAY_SPEEDLIMIT_FILE`):

    {"users":[{"email":"a@x","downBps":655360,"upBps":0,"ipLimit":2,"ips":[]}]}

`ipLimit` absent or 0 = unlimited. Same writer, same compare-then-write, same
deterministic ordering, same mtime reload. No new file, no new env var, no new
delivery mechanism.

## Panel side: almost nothing to build

**`LimitIP` already exists per client** (`database/model/model.go:226`,
`LimitIP int \`json:"limitIp"\``), and the UI is already wired
(`web/html/modals/client_bulk_modal.html:136` gated on `app.ipLimitEnable`,
`web/html/inbounds.html:1296,1354`). So:

- No model change. No migration. No new form. No i18n.
- `web/service/speedlimit.go` just populates `ipLimit` from `client.LimitIP`
  alongside the rates it already resolves per email.

Three things to fix:

1. **`GetIpLimitEnable` (`web/service/setting.go:688`) must stop deriving from
   the access log path.** That derivation is precisely why the feature is
   invisible on a default install. Once enforcement is in-core, the access log is
   irrelevant to it. Replace with a real setting (default on, or simply always
   true since a 0 limit is already "off").
2. **Delete the scraper.** `web/job/check_client_ip_job.go` in its entirety:
   the regex log parse, `mergeClientIps`, `ipStaleAfterSeconds`,
   `checkFail2BanInstalled`, `disconnectClientTemporarily`, and the
   `[LIMIT_IP]` log line. Also drop the fail2ban warning at panel startup.
3. **Keep `InboundClientIps`?** Decide. `database/model/model.go` has an
   `InboundClientIps` table (`ClientEmail gorm:"unique"`) that the job maintains
   for the UI's "IPs" view. If the UI still wants to show live IPs, feed it from
   the core instead (see "Visibility" below) rather than keeping the scraper
   alive just for display.

## Scope: which protocol is enforced WHERE

The feature is wanted for ssh and mtproto too. It is the same USER-FACING
feature, but it CANNOT be the same enforcement point, and this is not a
preference:

### ssh and mtproto: the core is blind. Enforce in the relay.

`web/service/ssh_socks.go:26` dials the socks inbound at **`127.0.0.1`**, and
mtproto's socks inbound listens on `127.0.0.1` (`web/service/mtproto.go:310`).
So **Xray sees source = 127.0.0.1 for every ssh and mtproto user.** The real
client IP never reaches the core. An in-core IP cap would see one IP for the
entire protocol and either never fire or reject everyone.

The real client IP is known only to the relay that terminated the client
connection. So enforcement stays there, where it ALREADY is:

- **ssh**: `web/service/ssh_server.go:372` `admit()`. Already IP-based, already
  supports both strategies. Nothing to move.
- **mtproto**: telemt's `[access.user_max_unique_ips]`
  (`web/service/mtproto.go:637`). Already IP-based. Reject-only
  (`mtproto.go:47`: *"not configurable: telemt rejects the excess device"*).

#### mtproto `accept` is a project, not a patch. Deferred.

Investigated. telemt (Rust) has `UserMaxUniqueIpsMode` but its variants are
`ActiveWindow` / `TimeWindow` / `Combined` (`src/ip_tracker.rs:122-132`), which
select WHICH WINDOW to count, not reject-vs-evict. Admission denies by returning
`Err(...)` (`src/ip_tracker/admission.rs:98`) and there is **no session-kill path
anywhere in the tracker or maestro** (grepped for kill/close_session/disconnect/
abort: nothing).

So `accept` for mtproto means building a kill path INSIDE a Rust fork and wiring
it into admission. That is the same problem Xray had, in a different language,
plus the documented submodule trap (`git submodule update` silently rewinding the
fork and deleting patches from a "successful" build).

Leave mtproto reject-only. Revisit as its own piece of work if operators ask.
Note this asymmetry in any release notes: ssh has both strategies, mtproto has
reject only, and native gets both in phase 2.

So for ssh/mtproto this task is UNIFICATION, not relocation: one name, one
field, one set of strategy words, three enforcement points. Do not try to fold
them into the core; the information is not there.

### The 7 tunnel protocols: leave them alone

Do NOT populate `ipLimit` for them:

- **wg-c and ikev2 psk/eap-tls would BREAK.** The account owns a whole CIDR block
  and a router behind the single link legitimately presents MANY source IPs. An
  IP cap would reject real devices. (`web/service/wgc.go:320-325` is one peer per
  account with the whole block as AllowedIPs.)
- **They already enforce K at RADIUS auth** via the IP allocator
  (`web/service/radius.go:246,319` call `getClientIP` inside the Access-Accept
  path, keyed by Calling-Station-Id + NAS-Port). Their source IP as seen by Xray
  IS the assigned tunnel IP, so an in-core IP cap would either never fire or
  fight the allocator. RADIUS is the reliable mechanism; leave it.

So the panel writes `ipLimit` into the sidecar only for clients on Xray-NATIVE
inbounds. The core needs no protocol awareness: absent `ipLimit` = unlimited.

## Naming and UI

Rename **User Limit -> IP Limit for ssh and mtproto**, because that is what they
actually count (distinct client source IPs). This is the honesty rule from
`device-limit-plan.md` applied to our own UI.

**Do NOT rename it for the 7 tunnel protocols.** There, "User Limit" is a real
per-device limit: each device authenticates separately and is assigned its own
tunnel IP, discriminated by NAS-Port, so K genuinely means K devices even behind
one NAT. Calling that "IP Limit" would understate a mechanism that is device-
accurate, which is the same naming drift in the opposite direction.

Result: three labels, each true.

| Protocol | Label | Counts |
|---|---|---|
| l2tp, pptp, sstp, openconnect, ikev2, openvpn | User Limit (unchanged) | server-assigned device sessions |
| ssh, mtproto | **IP Limit** (renamed) | distinct client source IPs |
| vless, vmess, trojan, shadowsocks | IP Limit (existing `LimitIP`) | distinct client source IPs |

### Open decision: the storage field

The label change is easy; the FIELD is the real question.

- **mtproto** already stores its cap per CLIENT (`client.userLimit`,
  `web/html/form/client.html:417`). The native `LimitIP` is also per client
  (`database/model/model.go:226`). So mtproto can simply switch to `LimitIP` and
  the two agree. Clean.
- **ssh** stores its cap per INBOUND (`settings.userLimit`,
  `web/html/form/protocol/ssh.html:19`). `LimitIP` has no per-inbound form.

Three options for ssh, pick before building:

1. Move ssh to per-client `LimitIP`. Most consistent (one field everywhere,
   keyed per email exactly like enforcement), but it is a data migration:
   existing inbounds carry `settings.userLimit` and would need it copied onto
   each client.
2. Keep ssh per-inbound, rename the LABEL only, keep the `userLimit` JSON key.
   Zero risk, zero migration, but the field name then lies in the opposite
   direction and the next reader has to learn a mapping.
3. Add a per-inbound `ipLimit` default alongside the per-client override,
   mirroring how the speed limiter is per-inbound. More surface, but it matches
   the pattern just shipped.

Recommendation: (1) for consistency IF we are willing to write the migration;
otherwise (2) and revisit. Do not do (3) yet: it doubles the UI without a
requested use case.

### The mtproto client-id trap

mtproto is an email-identity protocol. Its JS client model needs `get id()` or
edits POST to `/updateClient/undefined` ("empty client ID"). This already shipped
broken once for wg-c in v1.4. Any change to the mtproto client form must be
tested through the REAL UI, not just the E2E, which posts ids explicitly and can
therefore never catch this class of bug.

## Strategies: reject and accept (evict-oldest)

Both are wanted, matching the VPN User Limit's existing vocabulary
(`reject` / `accept`). Do not invent new words. Current state per enforcement
point:

| Where | reject | accept (evict oldest) |
|---|---|---|
| Xray-native (in-core, NEW) | Phase 1. Trivial: return an error from `Dispatch`/`DispatchLink`. | Phase 2. Needs a kill path (below). |
| ssh (panel Go gateway) | **Already implemented** | **Already implemented** |
| mtproto (telemt) | Already implemented | **Missing.** Needs a telemt patch. |

### The kill path for in-core "accept" is cheaper than it first looks

We do not need `pipe.Interrupt()` or to own the connection context. We ALREADY
wrap both directions at both seams for the speed limiter
(`common/speedlimit/io.go`): `getLink` wraps two Writers, `WrapLink` wraps a
Reader and a Writer. Add a kill flag to those wrappers: once set, the next
`Read`/`WriteMultiBuffer` returns an error, the proxy's copy loop exits, the
connection closes, its ctx is done, and `context.AfterFunc` releases the
refcount. One mechanism, both seams, no new plumbing.

Two consequences to design for:

- The wrappers are currently installed ONLY when a rate limit exists. With
  `ipLimit` set but no speed limit, we must still install a pass-through wrapper
  carrying just the kill flag.
- Eviction lands on the next I/O. A fully idle connection holds its slot until it
  reads or writes (or `connIdle`, 300s, closes it). Bounded and honest; document
  it rather than pretend it is instant.

Ship phase 1 (reject, native protocols) first. It is useful alone and unblocks
deleting fail2ban.

### ssh already does exactly this, and is the reference implementation

`web/service/ssh_server.go:372` `admit(sess, k, strategy)` already groups an
account's sessions by source IP, admits a known IP unconditionally, admits a new
IP while under K, and on `accept` evicts the oldest device (all of its sessions).
That is the semantics to mirror in-core, including "a known IP is always
admitted", which is what stops one device's 50th connection from being refused.

## Visibility (optional, later)

The panel's "online IPs" view can be fed from the core rather than from a log
scrape. Two options:

- Enable `statsUserOnline` in the policy template and poll `GetStatsOnlineIpList`
  over the existing gRPC API (`xray/api.go` already talks to port 62790).
  Cheap, but note it is gated on the operator-editable `xrayTemplateConfig`
  setting, so an operator could silently turn the display off.
- Or surface our own limiter map, which is the enforcement truth and cannot drift
  from it.

Prefer the second if we build it at all. Do not block phase 1 on this.

## Traps

1. **Do not enable `statsUserOnline` just for enforcement.** Our own map is the
   enforcement truth; hanging enforcement off an operator-editable policy flag
   means an operator can disable their own limits with a config edit.
2. **Do not touch `user.Email`.** Same rule as the speed limiter: read the
   resolved email, never assign it back, or per-user stats switch on for VPN
   accounts and the panel double-counts their quota.
3. **The refcount must be released on EVERY exit path**, including a rejected
   connection that never allocated. Only release what you allocated.
4. **`context.AfterFunc` fires on ctx done.** Confirm the dispatch ctx is
   actually cancelled when the client connection closes for both seams; if the
   ctx outlives the connection anywhere, the refcount leaks and the account
   locks itself out. This is the single highest-risk detail: a leak here is
   indistinguishable from the current fail2ban lockout bug from the user's side.
   Test it explicitly.
5. **Mux.** One muxed TCP connection carries many sub-streams. `DispatchLink` is
   called per sub-stream, so the refcount will count sub-streams, not
   connections. Harmless for an IP limit (they share one IP, so it is one entry
   with a high refcount) but it must not be confused with a connection count.
6. **CORE_FORCE=1.** `./build.sh` caches the core by submodule SHA. Uncommitted
   fork changes are silently NOT rebuilt and the panel ships the old core. Verify
   the artifact: `strings corebundle/core/amd64/xray | grep <symbol>`.

## Build order

Status as of this revision: 1-4 DONE, 5 DEFERRED (see above), 6 in progress,
7 is the operator's runtime test.

1. **Core, phase 1 (reject)**: `ipLimit` + `strategy` in the sidecar schema, the
   refcounted map, admission checks at `Dispatch` and `DispatchLink`. Unit tests:
   a known IP is ALWAYS admitted (the 50th connection of device 1 must not be
   refused); the K+1th distinct IP is rejected; the refcount releases on ctx
   done; absent limit = zero overhead and no allocation; a reload changes K in
   place without dropping live connections.
2. **Panel**: populate `ipLimit` + `strategy` from `client.LimitIP` in
   `web/service/speedlimit.go`, NATIVE protocols only. Tests mirroring the
   existing speedlimit ones.
3. **Panel**: fix `GetIpLimitEnable` (`web/service/setting.go:688`), delete
   `web/job/check_client_ip_job.go` and the fail2ban plumbing.
4. **UI**: rename User Limit -> IP Limit for ssh + mtproto only, per the field
   decision above. Remember the 13-locale i18n ratchet
   (`web/i18n_toml_test.go:126`) and the mtproto `get id()` trap.
5. **mtproto `accept`**: DEFERRED. telemt has no kill path; see above.
6. **Core, phase 2 (accept)**: the kill flag on the existing io wrappers, plus a
   per-inbound `IPLimitStrategy` column, the sidecar `strategy` field, and the
   UI radio gated to native protocols.
7. **Verify at runtime.** This is exactly what the speed limiter still lacks.
   The operator's test, and the only thing that proves any of this:
   - reject: open K+1 connections from K+1 distinct addresses, watch the K+1th be
     refused, close one, watch the slot free.
   - known-IP rule: from ONE address with K=1, open many concurrent connections
     and confirm NONE are refused. This is the regression that would break normal
     browsing.
   - accept: at K, connect from a new address and watch the OLDEST address get
     torn down rather than the newcomer refused.
   - the leak: churn connections hard, then confirm the account can still connect
     (a refcount leak would lock it out, which looks exactly like the fail2ban bug
     this feature replaces).

## Open questions

- **The ssh storage field** (see "Open decision" above). Needed before step 4.
- **"IP Limit" scope in the UI**: this plan renames it for ssh + mtproto only.
  If the intent was to rename it on EVERY inbound form, say so, but note the
  objection above: for the tunnel protocols it is genuinely a device limit and
  the rename would make our own UI less true, not more.
- Does the panel still need a live "IPs per client" view? If yes, decide the
  source (see Visibility) before deleting `InboundClientIps` and the job.
- Whether ssh/mtproto should also gain a shared "Limit After"-style arming. Out
  of scope; noting it so it is a decision, not an omission.
