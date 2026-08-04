# OpenConnect (ocserv) — remaining bugs & handoff

Branch: `feat/openconnect-ocserv`. Written 2026-07-12 after the auth+data-plane
debugging marathon. OpenConnect went from **0/9 E2E (every login 401)** to
**core + most edge cases green**. This is the state to resume from.

---

## RESOLUTION (2026-07-12, session 2) — Bug 1 FIXED, Bug 2 addressed

Both open bugs traced to the same root: **OpenConnect sessions were never recorded
in `s.sessions`**, because ocserv's accounting can identify neither the device nor its
IP. Fix: record the session at **AUTH** (in `allocateBlockIP`), not at Acct-Start.

Empirically verified this session (local ocserv + mock-RADIUS repro, `cmd/radmockacct`):
- **`groupconfig=true` DOES honor our Framed-IP** — return Framed-IP `10.4.1.99` →
  `occtl show users` reports `IPv4: 10.4.1.99` (not a pool IP). So the block IP the
  panel assigns == the real ocserv tunnel IP == what occtl/nft see. This is what makes
  auth-time recording correct.
- ocserv's Access-Request carries **no Framed-IP and no NAS-Port** (only User-Name,
  User-Password/PAP, NAS-Id, Calling-Station-Id=client-ip, Connect-Info). Auth's only
  per-device discriminator is Calling-Station-Id.

Code changes (`web/service/radius.go`):
1. `allocateBlockIP` gains an `email` arg and a `recordOC(ip)` closure: for
   `protocol=="openconnect"` it records/refreshes `s.sessions["oc:"+ip]` and CLEARS the
   transient `pending` lease (auth IS the confirmation for ocserv — leaving pending set
   would let ghost-reclaim steal a live device's IP). Called from `assign()` and the
   idempotent-redial path. No-op for l2tp/pptp/openvpn.
2. `handleAuth` PAP/openconnect branch calls `AddClientAccounting` at auth (off-lock) so
   the nft counters exist from connection start — previously nothing created them.
3. `handleAcct` now `return`s early for openconnect (auth owns the lifecycle; ocserv
   accounting can't identify the device and its octets are unused). Still ACKs.
4. `KillSessionsByEmail` skips openconnect (ppp-only teardown; oc uses occtl).
5. `getClientIP` reads the client email and threads it to `allocateBlockIP`.
6. Cleanup of oc sessions is via `CleanStaleSessions` (route-through-ocserv), not
   Acct-Stop.

Verification: `go build ./...` + `go test ./web/...` green, incl. new
`TestAllocateBlockIPOpenconnectRecordsSession` and `...AcceptEvict`.

**E2E (ubuntu-24, `--tests openconnect`) — 16/17 subtests pass; the 1 red was a harness
bug, now fixed:**
- **account-termination → PASS** ("account disabled after exceeding 100MB; can no longer
  connect/use the VPN"). Bug 2 resolved by the auth-time nft counters — the full 120MB is
  counted now, not just the post-60s-interim ~51MB.
- account-usage, user-limit(K=2), strategy-reject, multi-user-total, multi-inbound,
  connect dtls+tls, dns, tunnel-egress, internet, dns-leak, c2c, routing, cross-inbound →
  all PASS.
- **strategy-accept → product is correct** (`server-evicted=True` = panel logged
  `evicted oldest device proto=openconnect`; `dev1 dropped(client)=True` = victim's tunnel
  really dropped), but the E2E FAILED it on a **harness assertion bug**: accept-strategy
  reuses the victim's IP for the incoming device (`assign(victimIP)`), so the server-side
  `ip addr | grep 'peer <ip>/'` probe (`link_gone`) reads False the instant dev3 takes that
  IP over — a false negative. Fixed `test_unit/harness/protocols.py` `_strategy_check`:
  `evicted = server_evicted and (dropped["v"] or link_gone is not False)` (adds the OR —
  strictly more lenient, cannot regress l2tp/pptp). **Re-run CONFIRMED green:**
  `strategy-accept [✓ pass] 3rd admitted (10.4.4.2); oldest device (dev1) disconnected`
  and `openconnect:[✓ pass]`, `1/1 distros fully passed`.

**account-termination flakiness → fixed (config).** It is throughput-bound: the VM's
Xray-TPROXY tunnel pushes ~30MB–100MB+ through `curl --max-time 240` depending on the
mirror/contention, so the old 100MB quota sometimes wasn't reached → `[• n/a]` (a
non-failure, but flaky). Lowered `test_unit/config.toml [traffic_test]` `limit_mb 100→15`,
`over_mb 120→50` — 15MB is comfortably below the observed slow-case floor, so the quota
reliably trips. This tests the enforcement MECHANISM (disable + reject reconnect), which is
size-independent; a broken limit fails to disable at any magnitude, so a low threshold can't
mask a bug.

Known limitation (pre-existing, out of scope; noted in the ocserv plan): multiple
OpenConnect devices on ONE account behind the SAME NAT share a Calling-Station-Id and
NAS-Port=0, so they collapse to one K-slot. The E2E tests avoid this by using 3 client
VMs with distinct source IPs. Real same-NAT K>1 is not achievable from auth alone
(ocserv gives no per-device id at auth).

### Full ubuntu-24 E2E (all phases) — after the openconnect fixes

Green: core-init, server-setup, **openvpn, l2tp, openconnect** (all fully green),
bulk-ops, backup-restore, **warp-socks**, systemd, uninstall. Two phases surfaced issues:

- **`random-cfg` → `--random` SIGSEGV → FIXED.** `vpn-ui --random` panicked (nil gorm DB)
  because `randomizeSetting()` (main.go) called `svc.GetServiceName()` (a DB read) BEFORE
  `database.InitDB()`. The `GetServiceName` call was added above the pre-existing InitDB by
  commit `ae4e7b36c` ("safer --random"), so `--random` has crashed since then. Fix: move
  `InitDB` to the top of `randomizeSetting`. Verified: `sudo vpn-ui --random` exit 0; the
  focused `--tests random-cfg` E2E is 6/6 green (randomize + restart-on-new-port + login +
  restore). **Not caused by the openconnect work.**

- **`pptp` multi-user-total → FAIL (counted delta 0) — PRE-EXISTING, left unfixed.** Only
  pptp with 2 *simultaneous* downloading devices counts 0; single-device pptp account-usage
  passes (~16MB) and l2tp multi-user (identical allocator/accounting code) passes (~16MB).
  Root: pptp tunnel instability → tunnel drops → new pppd → churned NAS-Port → the redial
  looks like a "new" device at the K=2 cap → accept-strategy evicts the other device →
  `RemoveClientAccounting` drops the counters without folding bytes → 0 counted. l2tp's
  tunnel is stable so it never churns. Historically this SKIPs (device2 download fails →
  NA-guard); this run device2's slow download *succeeded*, exposing the counting=0 as FAIL.
  Matches the memory note "pptp multi-user residual SKIP = pptp tunnel instability, not the
  allocator". Candidate mitigation (fold bytes on eviction, mirroring Acct-Stop) is a change
  to the shared, mutex-held eviction path — deferred as risky/out-of-scope; not masked
  either. **Decision for the maintainer: fix pptp tunnel stability, accept as a known pptp
  limitation, or make the harness tolerate it (SKIP) as originally intended.**

---

## Current state

### Committed this session (on `feat/openconnect-ocserv`)
- `fe789bdd` fix(openconnect): working ocserv auth + data plane end-to-end
- `52fbea52` feat(openvpn+panel): TLS cert-path option, shared TCP/UDP port, self-signed HTTPS
- `753213c6` fix(openconnect): honor RADIUS Framed-IP so per-device routing + limits work

### E2E on ubuntu-24 (`sudo test_unit/run.sh --only ubuntu-24 --tests openconnect`)
PASS: connect (DTLS + TLS), DNS-through-tunnel, User-Limit **reject**,
multi-user aggregation, multi-inbound coexistence, account-usage.
FAIL: **strategy-accept** (see Bug 1).
n/a: **account-termination** (see Bug 2).

### What was wrong originally (all fixed — background for the fixes above)
1. RADIUS secret written EMPTY into ocserv's radcli `servers` file — controller
   holds its own zero-value `OcservService`, `SetRadius` only ran on the web
   server's copy → `writeRadiusClientConfig` saw `radiusSecret == ""`. radcli
   then "couldn't find RADIUS server 127.0.0.1" and never sent. Fix:
   `OcservService.getRadiusSecret()` DB fallback (mirrors L2tpService).
2. RADIUS dictionary missing attrs 77 (Connect-Info, auth) and 49/52/53/55
   (accounting) — radcli `rc_avpair_new` fails hard on any missing attr.
3. procmgr relaunched ocserv before the old instance freed its port →
   "bind: Address in use" → 5s restart loop. Fix: `waitProcessExit()`.
4. PAP branch sent a keyless Accept — openconnect needs Framed-IP-Address +
   User-Limit gate. Fixed in `handleAuth`.
5. `groupconfig=true` had been removed (chasing the 401, which was really #1) —
   without it ocserv IGNORES Framed-IP and assigns from its own pool, breaking
   routing + per-device tracking. Restored.

---

## OPEN BUGS

### Bug 1 — strategy-accept eviction  [FAIL, root cause known, HAS a clean fix]
**Symptom:** at User-Limit K with strategy=accept, the (K+1)th device is admitted
but the account's oldest device is NOT evicted (over-admit). E2E `strategy-accept
[✗ fail] ... server-evicted=False`.

**Root cause:** ocserv's Accounting-Request (Acct-Start) **omits
Framed-IP-Address**. So `RadiusService.handleAcct` (web/service/radius.go, the
`AcctStatusType_Value_Start` case) bails with "acct-start missing Framed-IP" and
never records the session in `s.sessions`. Accept-eviction
(`allocateBlockIP` → `oldestBlockSession(s.sessions)`) then has no session to
evict. Reject strategy works because it counts pending AUTH leases
(`s.pending`/`s.stationIP`), not `s.sessions`.

**Ruled out (don't re-chase):**
- occtl is fine — verified live: `occtl -s <sock> -j show users` returns
  `"ID"` + `"IPv4"`, and `disconnect id <ID>` works. Matches `killOcservByIP`.
- Framed-IP honoring is fixed (groupconfig=true) — tunnel IP now == the RADIUS
  Framed-IP (e.g. 10.4.4.2), so once a session is recorded, occtl CAN match it.

**Tried and REVERTED:** recovering the IP on Acct-Start by scanning `s.stationIP`
for the Calling-Station-Id → regressed multi-user (two devices sharing a station
got the same IP; the scan picked the wrong lease). Reverted in `753213c6`; a NOTE
is left at the Acct-Start case in radius.go.

**Clean fix (do this):** record the openconnect session at **AUTH** time, where
the IP is actually known — in `getClientIP`/`allocateBlockIP` when the block IP is
assigned (it already writes `s.pending[ip]` + `s.stationIP[skey]`). ocserv drops
BOTH NAS-Port and Framed-IP in accounting, so accounting can't be trusted to
carry per-device identity for openconnect; auth is the only reliable point.
Care needed: session lifecycle (create at auth, still remove on Acct-Stop /
timeout), and don't regress l2tp/pptp (which DO carry Framed-IP in Acct-Start —
gate any change on `protocol == "openconnect"`).
Files: `web/service/radius.go` (`handleAuth` PAP branch → getClientIP; `handleAcct`
Start/Stop; the `s.sessions` map).

### Bug 2 — account-termination  [UNVERIFIED, not a found code bug]
**Symptom:** E2E `account-termination [• n/a] couldn't drive enough traffic to
exceed 100MB (counted ~51MB)`.
**Status:** the harness can't push >100 MB through the tunnel fast enough to trip
the quota cutoff, so openconnect's traffic-limit → disconnect path is simply
**untested** — not confirmed working or broken. Either speed up / shrink the test
threshold, or verify manually on the live box.

---

## Pre-existing (from auto-memory, NOT touched this session — verify before trusting)
- **OpenVPN strategy-reject over-admit** — status read-during-write race can admit
  a (K+1)th device. (memory: `k-limit-allocator-fixes`)
- **pptp multi-user SKIP on all distros** — tolerated by design; pptp tunnel
  instability, not the allocator. (memory: `incus-test-unit` / `e2e-full-green`)

---

## Housekeeping (left as-is)
- `test_unit/config.toml` has `keep_failed_vms = true` (uncommitted debug toggle).
  Revert to `false` before committing config, or leave for post-mortem.
- Kept VMs `vpnt0-srv / -cla / -clb / -clc` may still be running — `incus delete
  --force <name>` to clean, or let the next run's startup sweep clear them.
- Untracked scratch/plan docs in repo root: `openconnect-plan.md`, `flowchart*.md`,
  `table.md`, `.\*.kate-swp` (editor swaps — safe to delete).

---

## How to resume
- Build (canonical, no flags): `./build.sh` → `build/out/vpn-ui-amd64`. Then stage:
  `cp build/out/vpn-ui-amd64 test_unit/test_subject/vpn-ui`.
  (Daemons/core are cached; a Go-only change just recompiles the panel.)
- Unit tests: `CGO_ENABLED=1 go test ./web/service/ -count=1`. Relevant:
  `TestHandleAuthOpenconnectPAP` (web/service/radius_openconnect_test.go) drives a
  PAP Access-Request against a temp-DB inbound and asserts Accept + Framed-IP.
- E2E (needs root; incus): `sudo test_unit/run.sh --only ubuntu-24 --tests openconnect`
  (~25 min). Set `keep_failed_vms = true` in config.toml to inspect a failed run's
  VM (run.sh now honors it — the exit-sweep is gated).

### Debug tooling built this session (reuse it)
- `cmd/radmock` — logging mock RADIUS server (dumps every attribute). Point
  ocserv's radcli at it to see exactly what ocserv sends on the wire.
- Local repro pattern: real bundled ocserv (`backend/bin/amd64/ocserv`) + radmock
  + the `openconnect` CLI, all on localhost, ocserv `-d 9`. Cracked the auth flow
  without a VM. (scratchpad dir; recreate if gone.)

### Gotchas learned (save a re-discovery)
- ocserv logs auth to **SYSLOG** in the VM (`journalctl` / `/var/log/syslog`), NOT
  the procmgr ring buffer (which only holds the MAIN process's startup). The panel
  RADIUS Info logs are in `/var/log/vpn-ui/vpn-ui.log` (timestamps UTC; host +3:30).
  ocserv ring buffer via API: `GET /panel/core/logs/openconnect` (admin/admin).
- incus bridges can lose their IPv4 (firewalld reload flushes `incusbr0` →
  dnsmasq "no address" → VMs get no IPv4). Fix: `systemctl restart incus`.
- `keep_failed_vms` only survives if run.sh's exit-sweep is gated (fixed in
  753213c6); a SIGKILL of the harness still triggers its cleanup trap and sweeps.
