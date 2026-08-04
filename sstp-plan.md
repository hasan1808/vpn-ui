# SSTP (accel-ppp) — implementation contract & progress

Adding **SSTP** as a 6th VPN protocol. This doc is the FROZEN CONTRACT every
implementer follows so parallel work stays consistent (mirrors the style of
`openconnect-plan.md`). Written after a 7-agent recon of the exact seams.

## Decision (locked)
- **Server = bundled `accel-ppp`** (ISP-grade SSTP; native crypto binding; proven
  Windows interop). NOT a hand-rolled Go terminator (no production-grade Go MS-SSTP
  server exists) and NOT Python sstp-server (breaks static-musl pattern).
- **Bundle = harvest Alpine musl `accel-ppp` into a relocatable tree** (`apk add
  accel-ppp` → copy daemon + `/usr/lib/accel-ppp/*.so` modules + `/usr/share/accel-ppp`
  dicts + ldd deps + musl loader → loader-wrapper). SAME pattern as
  `build/backend/pppd-bundle.sh` / `backend/pppd.go`. musl can't dlopen a static
  binary, so this is a tree+`.tgz`, not a flat static ELF.
- **Kernel module: `ppp_generic` ONLY** (already provisioned for pptp/l2tp). accel-ppp
  runs SSTP + PPP in userspace; `/dev/ppp` for the netdevs. Set `mppe=deny` (TLS already
  encrypts; our RADIUS returns MS-MPPE-Encryption-Policy=Required, so deny at the link).
- **Protocol string = `"sstp"`; protocolBase = 5 → `10.5.0.0/16`** (inside vpnAddrSpace
  10.0.0.0/13 = 10.0–10.7, so NO nftables widening).
- **UI = clone of OpenConnect** (TLS cert: path | inline | self-signed | Set Default
  Cert). Label **all-caps `SSTP`** (like PPTP/L2TP). Self-signed button shows a Windows
  warning modal first.

## THE HYBRID RULE (critical — do not blindly follow "pure pptp")
SSTP authenticates via MSCHAPv2 and accel-ppp sends PROPER RADIUS (Framed-IP + NAS-Port
in both Access-Request and Acct-Start). Therefore:
- **AUTH / ACCT / session-recording / Framed-IP / device-keying → behave EXACTLY like
  `pptp`** (NOT like openconnect). No special-casing in handleAuth/handleAcct/
  allocateBlockIP. sstp must NOT be added to any `protocol == "openconnect"` branch that
  skips accounting or does auth-time session recording.
- **EVICTION / KILL → native `accel-cmd terminate`** (like ocserv uses `occtl`), NOT
  `killPPPByIP` (there is no per-connection pppd to kill — accel-ppp is one daemon) and
  NOT `killOcservByIP`. sstp gets its OWN eviction path calling into `SstpService`.

## SstpService API (frozen — G1 implements exactly this; G2 calls exactly this)
New file `web/service/sstp.go`, package `service`. Struct `SstpService` (zero-value
usable, like `OcservService{}`). Per-inbound native daemon model (mirror
`web/service/openconnect.go`). Methods:
```
func (s *SstpService) SetRadius(rs *RadiusService, secret string)
func (s *SstpService) getRadiusSecret() string                      // DB fallback like OcservService
func (s *SstpService) GetSstpInbounds() ([]*model.Inbound, error)   // WHERE protocol='sstp'
func (s *SstpService) parseSettings(*model.Inbound) (*sstpSettings, error)
func (s *SstpService) effectiveRanges(*sstpSettings) []string
func (s *SstpService) GetSubnetsForInbound(*model.Inbound) []string // PPP-family, like pptp
func (s *SstpService) GetSubnetForInbound(*model.Inbound) string
func (s *SstpService) GetTproxyPort(*model.Inbound) int             // 12300 + id
func (s *SstpService) GetDokodemoConfig(*model.Inbound) *xray.InboundConfig  // identical clone
func (s *SstpService) GenerateAllConfigs() error                    // per-inbound accel-ppp.conf + certs
func (s *SstpService) SetupRouting() error                          // modprobe+ip rule+ApplyNftRules (like ocserv)
func (s *SstpService) RestartServices() error                      // procMgr child "sstp-server-<id>" per inbound
func (s *SstpService) StopServices() error                          // StopByPrefix("sstp-server-")
func (s *SstpService) InitSstp()                                    // generate->route->restart
func (s *SstpService) KillDisabledSessions()                        // accel-cmd terminate disabled users
func (s *SstpService) DisableClients(emails []string)               // accel-cmd terminate those users
func (s *SstpService) KillClientIP(inbound *model.Inbound, ip string) error // accel-cmd terminate ip <ip> (for eviction)
func (s *SstpService) GenerateSelfSignedCert() (certPEM, keyPEM string, err error) // ECDSA P-384, clone ocserv
func (s *SstpService) hasUsableCert(*sstpSettings, id int) bool
```
`sstpSettings` clones ocserv's settings struct (cert fields + PPP fields):
```
Dns1, Dns2 string; Mtu int
TlsUseFile bool; CertificateFile, KeyFile string            // path mode
Certificate, Key, CaCert string                             // inline PEM mode
Clients []model.Client                                      // JSON "clients" (same as ocserv)
ClientToClient, CrossInbound bool
IpRanges []string; IpRange string (legacy)
LocalIp string
UserLimit int; UserLimitStrategy string
```

### Config/process conventions (G1)
- config dir: `/etc/vpn-ui-sstp/server-<id>/` holding `accel-ppp.conf`, `server.crt`,
  `server.key`, optional `ca.crt`, and the accel-cmd control socket `cli.sock`.
- proc name: `sstp-server-<id>` (per enabled inbound); reconcile/stop by prefix
  `sstp-server-` (mirror ocserv). `daemonBin("accel-pppd")`. Pass `pppdEnv()`? NO —
  accel-ppp doesn't use our pppd; pass its own env if needed (openssl libs via the
  bundle loader-wrapper). Use `procMgr.Start("sstp-server-<id>", daemonBin("accel-pppd"),
  []string{"-c", confPath}, nil, dir)`; add `waitProcessExit` bind-race guard behavior
  is inside procMgr.Start already.
- accel-ppp.conf (STARTER — G1 verify against accel-ppp docs via WebFetch; harvest the
  bundled `/usr/share/accel-ppp/dictionary` for the RADIUS dict which must contain the
  MS-CHAP/MS-MPPE attrs):
  ```
  [modules]
  log_file
  sstp
  auth_mschap_v2
  auth_mschap_v1
  radius
  ippool
  [core]
  thread-count=4
  [log]
  log-file=<dir>/accel.log
  level=3
  [sstp]
  verbose=1
  accept=ssl
  ssl-pemfile=<dir>/server.crt
  ssl-keyfile=<dir>/server.key
  port=<inbound.Port>            # default 443
  ppp-max-mtu=<mtu>
  [ppp]
  verbose=1
  mtu=<mtu>
  mppe=deny
  ipv4=require
  lcp-echo-interval=30
  lcp-echo-failure=3
  [radius]
  dictionary=<bundled accel-ppp dict>
  nas-identifier=sstp
  nas-ip-address=127.0.0.1
  gw-ip-address=<block .1>
  server=127.0.0.1,<secret>,auth-port=1812,acct-port=1813,req-limit=0,fail-time=0
  acct-interim-interval=60
  [cli]
  sock=<dir>/cli.sock
  ```
- eviction: `accel-cmd -f <dir>/cli.sock terminate ip <ip>` (G1 confirm exact flags;
  fallback `terminate username <u>`).

## Address/protocol base (locked)
- `protocolBase("sstp") = 5`. PPP-family → `normalizePppRanges` (arbitrary /24 list,
  like pptp). NOT the block model. localIp = first range .1 (pptp-like).

---

# WORK PARTITION (disjoint file sets — no two concurrent agents touch the same file)

## G1 — SSTP core service + accel-ppp bundle backend  (build FIRST)
Files (NEW/edit; nobody else touches these):
- NEW `web/service/sstp.go` — the `SstpService` above. Clone `web/service/openconnect.go`
  for structure (per-inbound daemon, TLS cert handling `certPaths`/`writeCertFiles`/
  `hasUsableCert`/`GenerateSelfSignedCert`) and `web/service/pptp.go` for
  `GetSubnetsForInbound`/`effectiveRanges`/`GetDokodemoConfig`. Generate accel-ppp.conf
  (above). Eviction/kill via accel-cmd.
- NEW `backend/accel.go` — clone `backend/pppd.go`: `HasAccelBundle()`,
  `ExtractAccelBundle()` (untar `accel-ppp-bundle.tgz` to `/`), and a link helper if the
  module dir needs a fixed path (accel-ppp `libtriton` module search path). Constants for
  the bundle root (e.g. `/usr/libexec/vpn-ui-accel`), the `accel-pppd`/`accel-cmd` paths.
- EDIT `database/model/model.go` — add `SSTP Protocol = "sstp"` to the const block
  (`:24-27`).
- EDIT `backend/backend.go` — the `.tgz` rides the existing `//go:embed all:bin`; Extract
  skips `.tgz`, so do NOT add to `Daemons`. (No edit likely needed beyond confirming.)
- EDIT `web/service/procmgr.go` — add `"accel-pppd"` to the `pkill -KILL -f` orphan list
  (`:438`); it does NOT retitle, so NOT the `-x` list. Ensure `daemonBin("accel-pppd")`
  resolves via `backend.DaemonPath`/bundle.
- Provisioning extract/link: wire `backend.ExtractAccelBundle()` (+link) into the
  provisioning bring-up next to the pppd extract (`web/service/core.go` ~`:730`, behind
  `backend.HasAccelBundle()`). (This one line in core.go — do it here in G1 to keep the
  backend-extraction cohesive; G2 owns the rest of core.go, so ONLY touch that single
  extract/link block, clearly commented.)  <-- coordination: G1 adds the extract block,
  G2 adds status/switch/init. Different regions of core.go. If risky, G1 instead exposes
  nothing in core.go and documents that G2 must add the extract call — but default: G1
  does the extract block.
- After writing, run `CGO_ENABLED=1 go build ./...` — G1's additions must compile
  standalone (unused exported symbols are fine in Go).
Report: the final `SstpService` method signatures actually implemented, the accel-cmd
eviction command used, the config dir layout, and any deviation from this contract.

## G2 — Go shared-machinery wiring  (build AFTER G1)
Files (nobody else touches these): `web/service/radius.go`, `web/service/vpnrange.go`,
`web/service/nftables.go`, `web/service/xray.go`, `web/service/core.go` (except the single
extract block G1 added), `web/service/inbound.go`, `web/web.go`,
`web/job/xray_traffic_job.go`, `web/controller/inbound.go`, `web/controller/core.go`.
Checklist (exact anchors from recon):
- **vpnrange.go**: `protocolBase` add `case "sstp": return 5` (`:137-149`);
  `usedVpnSubnets` slice add `"sstp"` (`:277`); `normalizeRanges` guard add
  `&& proto != "sstp"` (`:356`) → falls to `normalizePppRanges` default.
- **radius.go** (HYBRID RULE): `parseNASIdentifier` add `"sstp"`/`"sstp-<id>"` (`:693`,
  `:703`); `BuildVpnEmailToIPMap` ppp query slice add `"sstp"` (`:1183`). AUTH/ACCT/
  device-keying: NO change (flows like pptp). EVICTION: study how ocserv injects
  `killOcservByIP` and mirror for sstp calling `SstpService.KillClientIP` — specifically
  (a) `KillSessionsByEmail` (`:586` skip / `:600` teardown): sstp must NOT use
  killPPPByIP; route to accel-cmd (mirror the openconnect handling but via SstpService);
  (b) accept-evict teardown (`:1041` `killOcservByIP` vs `killPPPByIP`): add an sstp
  branch → `SstpService.KillClientIP`. `isIPActive` (`:659`): accel-ppp assigns the peer
  IP on a `ppp*` iface → default `ip addr show` branch likely matches; if accel-ppp names
  its ifaces differently, add an sstp case using `accel-cmd show sessions`. VERIFY iface
  naming; conservative default = treat like pptp (default branch). Document choice.
- **nftables.go**: `sstp_acct` chain create + prerouting/postrouting jumps (`:183/:197/
  :201`); SSTP TPROXY loop after the pptp loop (`:285`, PPP-family via
  `subnetCIDRs(sstp.GetSubnetsForInbound(...))`); `ApplyNftRules` instantiate `sstp :=
  SstpService{}`, fetch `sstpInbounds`, extend the teardown-guard `len==0` condition, add
  cross-inbound gather block; **`CollectAndResetTraffic` 4→5 arity** (add
  `sstpIPToEmail map[string]string` arg + 5th return; `:479` def, `:482`/`:488` nil
  returns, `:520-534` dispatch branch `else if protocol == "sstp"`, `:571` toSlice,
  `:586` return). No `sstpCIDRs` helper (reuse generic subnetCIDRs).
- **xray.go**: dokodemo native-skip list add `|| inbound.Protocol == "sstp"` (`:109`);
  `XrayService` struct add `sstpService SstpService` (`:30`); dokodemo injection loop for
  sstp after the ocserv block (`:233`).
- **core.go**: struct field `sstpService SstpService` (`:102`); `sstpStatus()` (clone
  `ocservStatus` using `AnyRunningWithPrefix("sstp-server-")`, `daemonInstalled("accel-
  pppd")`, `Name:"sstp"`); add to `GetCoresStatus` after ocserv (`:266-276`); `RestartCore`
  case (`:535`), `RestartAll` list add `"sstp"` after `"openconnect"` (`:560`),
  `StopCore` (`:573`), `CoreLogs` case → `procMgr.LogsByPrefix("sstp-server-")` (`:601`);
  `provisionProtocols` APPEND `"sstp"` (`:470`) — do NOT touch `provisionBaseline`
  (`:477`); `InitSstp()` in the StartProvision Init fan-out (`:924`); `MissingDokodemoPorts`
  add an sstp block (`:255-260`). DO NOT duplicate the backend-extract block G1 added.
- **inbound.go** (service): `isVpnProtocol` add `|| p == model.SSTP` (`:261`); secure
  client-ID `case "trojan","l2tp","pptp":` add `"sstp"` (`:358-377`); the 3 PPP
  duplicate-username checks add `"sstp"` (`:380`, `:812`, `:1239`); `validateInboundConfig`
  add a cert-required guard for sstp mirroring the openvpn block (`:273-306`).
- **web.go**: struct field (`:112`); `SetRadius` fan-out add
  `s.sstpService.SetRadius(&s.radiusService, radiusSecret)` (`:316-319`); Init fan-out add
  `s.sstpService.InitSstp()` (`:323-326`).
- **xray_traffic_job.go**: struct field `sstpService service.SstpService` (`:23`);
  `j.sstpService.SetRadius(rs, "")` (`:42`); `sstpSessions := j.radiusService.GetSessions(
  "sstp")` (`:66`); the `CollectAndResetTraffic` 5-arg call + extended guard + append
  (`:67-71`); `j.sstpService.KillDisabledSessions()` (`:85`).
- **controller/inbound.go**: struct field `sstpService service.SstpService` (`:24`); add
  `onSstpChanged()` cloning `onOcservChanged` (AutoExpandVpnRanges("sstp") →
  GenerateAllConfigs → SetupRouting → RestartServices → ResetAllocations("sstp") →
  KillDisabledSessions → xrayService.SetToNeedRestart); add the sstp branch to EVERY
  dispatch site (`:252,:277-280+293,:331,:427,:486,:524,:562-570 switch,:599,:615,:637`);
  setup gate add `|| inbound.Protocol == model.SSTP` (`:216-226`); routes
  `POST /:id/generate-sstp-cert` + `/generate-sstp-cert` (`:63-68`); handler
  `generateSstpCert` cloning `generateOcservCert` (`:809-845`) → calls
  `a.sstpService.GenerateSelfSignedCert()` + `a.onSstpChanged()`.
- **controller/core.go**: generic (by :core param) — NO change once core.go switches gain
  "sstp".
After: `CGO_ENABLED=1 go build ./...` + `go test ./web/... -count=1` must be green.

## G3 — Frontend (Vue/AntD templates + JS)  (parallel with G1)
Files: `web/assets/js/model/inbound.js`, `web/assets/js/model/dbinbound.js`,
NEW `web/html/form/protocol/sstp.html`, `web/html/form/inbound.html`,
`web/html/form/client.html`, `web/html/modals/inbound_modal.html`,
`web/html/modals/client_modal.html`, `web/html/modals/client_bulk_modal.html`,
`web/html/core.html`, `web/html/index.html`, `web/html/inbounds.html`.
- inbound.js: `Protocols.SSTP='sstp'`; `ProtocolLabels` add `sstp:'SSTP'` (all-caps, like
  PPTP); `clients` getter, `getSettings`, `fromJson` add SSTP cases; NEW
  `Inbound.SstpSettings` + `SstpSettings.SstpUser` cloning `OcservSettings`/`OcservUser`
  (users field `sstpUsers`).
- NEW `web/html/form/protocol/sstp.html` `{{define "form/sstp"}}` — near-verbatim clone
  of `openconnect.html` (all hardcoded English, so NO i18n keys). Rename handlers:
  `ocservSetDefaultCert`→`sstpSetDefaultCert`, `generateOcservCert`→`generateSstpCert`.
- inbound.html: add the `<template v-if="inbound.protocol === Protocols.SSTP">{{template
  "form/sstp"}}</template>` include after the openconnect block (`:290-293`).
- inbound_modal.html: `generateSstpCert` (clone `generateOcservCert` `:553`, but WRAP the
  request in a `this.$confirm({...})` Windows warning — content: "The built-in Windows
  SSTP client rejects self-signed certificates unless you import the CA into the machine's
  Trusted Root Certification Authorities store AND set NoCertRevocationCheck=1 in the
  registry — there is no 'ignore certificate' option in the native client. For real users
  prefer a CA-signed cert bound to a hostname. Generate a self-signed cert anyway?",
  okText "Generate anyway"); `sstpSetDefaultCert` (clone `:565`); onProtocolChange add
  `else if (protocol === 'sstp') { inModal.inbound.port = 443; }` (`:304-317`); `isValid`
  add sstp cert guard (`:226-247`).
- core.html: `coreTitle` add `sstp:'SSTP'` (`:625`); `coreIcon` add `sstp:'windows'`
  (`:628`).
- index.html: `vpnCoreStatuses()` order add `'sstp'` (`:1104`); `coreLabel` add
  `sstp:'SSTP'` (`:1110`). WRAP-TEXT requirement: the card already has flexWrap+wordBreak;
  with 7 services reduce each cell `minWidth` from `84px` to `72px` so labels wrap cleanly
  (`:94-102`).
- inbounds.html: add `Protocols.SSTP` at `:1365` (clientCount), `:1957-1963`
  (getClientIndex password/email match), `:2053-2059` (getClientId → client.password),
  `:2201` (setup-required submit guard).
- dbinbound.js: `getClientId` (`:88-95`), `addClient` (`:104-136` → push
  `new Inbound.SstpSettings.SstpUser()`), `isMultiUser` (`:157-172` → true) add SSTP.
- client.html: username `:28`, password `:45`, randomize `:59` v-if add SSTP.
- client_modal.html: `getClientId` `:90`, `addClient` `:129` add SSTP.
- client_bulk_modal.html: `:345` add `case Protocols.SSTP: return new
  Inbound.SstpSettings.SstpUser();`.
- i18n: add NO new keys (hardcoded English like ocserv) → the parity ratchet
  (`web/i18n_toml_test.go`) stays green. Optionally append "SSTP" to the existing English
  VALUES of `pages.core.rebootImpact` + `pages.inbounds.toasts.setupRequired` (keys
  unchanged → no parity impact).

## G4 — E2E harness (test_unit/, python+bash)  (parallel with G1)
Files: `test_unit/harness/model.py`, `test_unit/harness/orchestrator.py`,
`test_unit/harness/server_setup.py`, `test_unit/harness/clients/base.py`,
NEW `test_unit/harness/clients/sstp.py`, `test_unit/harness/protocols.py`,
`test_unit/run.sh`.
- model.py: `PHASE_SSTP="sstp"` (`:116`); into `ALL_PHASES` after `PHASE_OPENCONNECT`
  (`:124`). This makes `--tests sstp` work.
- orchestrator.py: `_PHASE_TAG["sstp"]="SSTP"` (`:42`); `need_clients` add `"sstp"`
  (`:135`); proto loop add `"sstp"` after openconnect (`:240`).
- server_setup.py: `BASE["sstp"]=5` (`:24`); `SSTP_USER_LIMIT=2` (`:35`);
  `SECOND_PORTS["sstp"]` (`:47`); `build_second_inbound` sstp branch (`:113`, TLS cert via
  `panel.generate_ocserv_cert()` OR `panel.generate_sstp_cert()` if the backend route
  exists — prefer sstp); SSTP inbound block in `run()` after openconnect (`:296`), port
  443, TLS cert, 2 accounts, userLimit=SSTP_USER_LIMIT.
- clients/base.py: add `sstp-client` to `CLIENT_PKGS_APT` (`:17`); add `pkill sstpc` to
  `disconnect_all` (`:167`).
- NEW clients/sstp.py: `connect(client, inbound, which, server_ip=...)` + `disconnect` —
  drive `sstpc --cert-warn --user <u> --password <p> <server>:443 file <peers>` (MSCHAPv2,
  no MPPE), detect `ppp0`, `apply_tunnel_dns`. Mirror `clients/pptp.py` + the cert-ignore
  of `clients/openconnect.py`.
- protocols.py: import `sstp_mod`; import `PHASE_SSTP`; `PEER["sstp"]="openvpn"`;
  `PHASE["sstp"]=PHASE_SSTP`; `_SECOND_VARIANT["sstp"]=None`; `_connect`/`_disconnect`
  branches; leave `_variants` on default single-variant. The shared suite (dns, egress,
  user-limit reject+accept, multi-user-total, multi-inbound, usage, termination, routing,
  cross-inbound) runs unchanged — `_iface_up`/`_strategy_check` already give sstp `ppp0`.
- run.sh: add a `sstp` line to the `--help` Tests block (`:65`, docs only).
NOTE: per `no-auto-e2e`, DO NOT run the incus harness. Author only.

## G5 — Build / bundling  (parallel with G1)
Files: NEW `build/backend/accel-ppp-bundle.sh`, `build/backend/build.sh`, root `build.sh`.
- NEW `build/backend/accel-ppp-bundle.sh` — clone `build/backend/pppd-bundle.sh`
  structure: in alpine:3.22, `apk add accel-ppp`, copy `/usr/sbin/accel-pppd` +
  `/usr/bin/accel-cmd` + `/usr/lib/accel-ppp/*.so` (incl. `libsstp.so`, `libradius.so`,
  `libauth_mschap_v2.so`, `libippool.so`, `libtriton.so`) + `/usr/share/accel-ppp/*`
  (RADIUS dictionaries) + ldd deps (libssl/libcrypto, libnl-3/libnl-genl, pcre/pcre2,
  zlib) + musl loader into `$PREFIX` (= backend accel bundle root); emit loader-wrapper
  `sbin/accel-pppd` + `bin/accel-cmd`; `tar czf /out/accel-ppp-bundle.tgz`. FIRST STEP:
  verify `apk add accel-ppp` succeeds and `libsstp.so` is present (fail fast otherwise).
- build/backend/build.sh: add a `docker run … alpine:3.22 … -v …/accel-ppp-bundle.sh:ro …
  -e ARCH=$muslarch -v $outdir:/out` block after the ocserv block (`~:138`).
- root build.sh: extend the cache guard (`:75-80`) to also require
  `backend/bin/$ARCH/accel-ppp-bundle.tgz` so a stale cache rebuilds.
Report whether `apk add accel-ppp` actually provides `libsstp.so` on alpine:3.22 (this is
the load-bearing fact for the whole approach).

---

# Progress
- [x] Recon (7 agents) — DONE
- [x] Contract frozen — DONE (this doc)
- [x] G1 SSTP core service + accel bundle backend — DONE (`go build ./...` green)
- [x] G3 Frontend / G4 E2E / G5 Build — DONE (node --check / py_compile / bash -n green)
- [x] G2 Go wiring — DONE (`go build ./...` + `go test ./web/...` green)
- [x] Integrate — `go build ./...` (exit 0), full 170M binary, `go test ./web/...` all green
- [x] Fixed cross-agent mismatches: AccelDictPath radius/ subdir + bundle assertion;
      sstp.html tooltip 10.4→10.5; added TestAllTemplatesParseAndProtocolFormsDefined
      (verifies form/sstp parses + is defined in the production template set)
- [x] Review pass — 2 adversarial agents (Go wiring + frontend/harness): NO logic defects;
      11/11 dispatch parity, hybrid rule honored, 4→5 arity complete. Fixed the 1 nit
      (server_setup.py fatal-guard tuple + "sstp").
- [x] **Phase-0 build gate PASSED** — `podman ... accel-ppp-bundle.sh` built
      accel-ppp-bundle.tgz (3.2M): libsstp.so + all modules + libtriton + musl loader +
      libssl/crypto/pcre + RADIUS dicts + wrappers; dict-path assertion passed.
- [x] `./build.sh` canonical build embeds the bundle → build/out/vpn-ui (174M); cache
      guard correctly skips daemon rebuild. Staged to test_unit/test_subject/.
- [x] Local accel-pppd sanity: musl binary EXECUTES on glibc host via loader wrapper;
      starts with an sstp.go-format accel-ppp.conf and runs stably (exit 124 = ran till
      killed, clean terminate) → config syntax + module load validated.
- [x] E2E run 1 (ubuntu-24): core-init + server-setup FULLY GREEN (accel-ppp bundle
      extracts on VM, module dir links, daemon runs, binds :443, inbound+routing+xray ok).
      **sstp connect FAILED** → root-caused from the VM's accel.log:
      `warn: sstp: no IP address range defined in section [client-ip-range] ...` +
      `sstp: IP is out of client-ip-range, droping connection`. accel-ppp's sstp module
      requires a **[client-ip-range]** accept-ACL for the assigned Framed-IP; our config
      omitted it → every client rejected post-auth. (My earlier mppe=deny hypothesis was
      WRONG — auth + MPPE passed; the drop was purely the missing ACL.)
- [x] E2E run 2 (fix v1 = `[client-ip-range] 10.5.0.0/16`) — STILL failed connect. The
      accel.log flipped to `IP is out of client-ip-range` with a 10.5/16 range → the "IP"
      it checks is the CLIENT'S SOURCE address (10.100.0.x test net), NOT the tunnel pool.
      [client-ip-range] is accel-ppp's source-address ACL, not the assigned-IP range.
- [x] FIX v2 (correct): `web/service/sstp.go` emits `[client-ip-range]\n0.0.0.0/0`
      (accept clients from anywhere — a public VPN; accel-ppp logs "iprange module
      disabled"). RADIUS Framed-IP still pins each device's tunnel IP.
- [x] **HAND-VERIFIED on the live VM (real sstpc + panel RADIUS): FULL FLOW WORKS.**
      `ppp0 inet 10.5.2.2 peer 10.5.2.1`; `pppd: CHAP authentication succeeded`;
      `RADIUS: auth accepted user=sstpa nas=sstp-5 ip=10.5.2.2`;
      `RADIUS: acct-start ... proto=sstp session=...`. So connect + MSCHAPv2-via-RADIUS +
      Framed-IP + accounting all correct. mppe=deny is FINE (auth+IPCP completed) — the
      earlier mppe worry was a red herring.
- [x] Rebuilt via ./build.sh with fix v2, re-staged.
- [x] **E2E run 4 (ubuntu-24, fixed binary) — 1/1 DISTROS FULLY PASSED.** Every sstp
      subtest green: connect, dns-resolve, tunnel-egress, internet, dns-leak, user-limit
      (K=2 → 10.5.2.2+10.5.2.3), client-to-client, routing (A freedom / B blackhole),
      cross-inbound, strategy-reject (3rd refused), strategy-accept (3rd admitted, oldest
      evicted via accel-cmd — server-evicted=True), multi-user-total (aggregated ~16MB),
      multi-inbound-same-proto (2nd inbound :8443/10.5.3.x coexists), account-usage,
      account-termination (quota-disable + reconnect blocked). results/20260713-003100.
- [x] Reset `keep_failed_vms=false`; go build + go test ./web/... green; debug logs removed.
- [ ] Runtime verify on live box (real Windows SSTP client + same-NAT K>1) — deferred
      (like ocserv Phase 7). Note: accel-ppp sends a distinct NAS-Port per session (unlike
      ocserv), so same-NAT K>1 SHOULD work — E2E only covered distinct-IP devices.
- [ ] Commit — NOT done (awaiting user).

## Live-box (65.109.217.240, Fedora 44) findings — 2nd real bug the E2E MISSED
- **tgId unmarshal bug (core stays Stopped):** `sstpSettings.Clients` was `[]model.Client`,
  and `model.Client.TgID` is `int64`. The panel UI posts `tgId` as a STRING ("") →
  parseSettings fails `cannot unmarshal string into Go struct field Client.clients.tgId of
  type int64` → inbound SKIPPED every restart → accel-pppd never starts → SSTP core
  "Stopped", client can't connect. E2E missed it because it builds clients programmatically
  without a string tgId. **FIX:** give SSTP its own MINIMAL `sstpClient{ID,Password,Email,
  Enable}` struct (exactly like `ocservClient`) so unmarshal drops the UI's extra fields
  (tgId/totalGB/expiryTime/…). web/service/sstp.go. Rebuilt, deployed, verified: log now
  `SSTP: initializing services for 1 inbound(s)`, accel-pppd running, :443 bound.
- **Deploy gotcha (not a code bug):** the box was running a MANUAL `./vpn-ui` (retitled proc
  "vpn-ui", /opt/vpn-ui/vpn-ui) holding :35816 alongside the systemd `vpn-ui-amd64` unit →
  new binary crash-looped `bind: address already in use`. Killing it orphaned its xray
  (held :21111 = x-ui-coexist API port) → xray crash-loop. Reaped both by PID → clean.
  Deploy = gzip→scp→gunzip→replace /opt/vpn-ui/vpn-ui-amd64→chmod755→systemctl restart, AND
  ensure no stray `./vpn-ui` / orphan xray remain.
- Also carried the modal fix (setupRequiredForProtocol now a window prompt) in this deploy.

## STATUS: COMPLETE & E2E-VERIFIED (ubuntu-24) + live-box core running. Client test in progress. Not committed.

## accel-ppp SSTP runtime gotchas (learned)
- **[client-ip-range] is MANDATORY** for the sstp module — without it every connection is
  dropped post-auth ("IP is out of client-ip-range"). Whitelist the protocol /16.
- accel-pppd runs foreground with just `-c` (no daemonize); binds the SSTP port (443) +
  the [cli] tcp control port (13300+id). Musl loader-wrapper runs fine on the glibc VM.
- accel.log lives at the per-inbound configDir (`/etc/vpn-ui-sstp/server-<id>/accel.log`),
  level=3. RADIUS auth/acct logs are in the panel log `/var/log/vpn-ui/vpn-ui.log`.

## Runtime-UNVERIFIED (nail down at live-verify, like ocserv Phase 7)
- accel-ppp.conf exact syntax vs accel-ppp 1.13.0 (Alpine): module `path=` fallback via
  LinkAccelModuleDir symlink; `dictionary=` at share/accel-ppp/radius/dictionary; `mppe=deny`
  vs RADIUS MS-MPPE-Encryption-Policy=Required; `accel-cmd -H 127.0.0.1 -p <13300+id>
  terminate ip <ip>` flags; `[cli] tcp=` port.
- Real Windows SSTP client connect (native client, cert-trust flow).
- The accel-ppp bundle itself must be built (`build/backend/build.sh amd64`) on a
  docker/podman host and staged before the SSTP daemon can run.

# Build/test commands
- Quick compile: `CGO_ENABLED=1 go build -o /tmp/vpn-ui-sstp main.go`
- Unit: `CGO_ENABLED=1 go test ./web/... -count=1`
- Full bundled binary: `./build.sh` → `build/out/vpn-ui-amd64` (rebuilds daemons incl. accel-ppp)
