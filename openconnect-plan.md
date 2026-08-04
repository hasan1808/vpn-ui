# OpenConnect (ocserv) — implementation plan & progress

Branch: `feat/openconnect-ocserv` (off `main`). Self-contained record so work can
resume after a reboot without `/resume`. Mirrors the auto-memory
`openconnect-ocserv-plan.md`.

## Goal
Add OpenConnect (ocserv) as a 5th VPN protocol, fully compatible with the existing
bundling, RADIUS, Xray-core routing, User-Limit, IPv4 auto-expansion, and E2E test
infrastructure. ocserv is tun-based, closest to OpenVPN; sits on the same substrate
(per-inbound /24 source IP → nft `ip vpn` prerouting → TPROXY → dokodemo `12300+id`
→ Xray). Data plane is 100% subnet-keyed / protocol-blind.

## Locked design decisions
- **Bundled** static musl binary (like openvpn/xl2tpd/pptpd). Kernel: only `/dev/net/tun`.
- **RADIUS = server-authoritative** (L2TP-style): ocserv auths natively via radcli,
  honors `Framed-IP-Address` to pin the tun IP. No per-connection hook scripts.
- **TLS = Xray-core model**: path OR inline content, "Set Default Cert" pulls the
  panel's `webCertFile`/`webKeyFile`, plus a Generate-Self-Signed-Cert button.
  ocserv cert = server cert+key only (distinct from openvpn's CA+tls-crypt).
- Addressing: protocol base 4 = `10.4.0.0/16`, single contiguous block, no TCP mirror.

## Progress

### Phase 0 — Build (DONE, commit 611187c8)
- `build/backend/ocserv-bundle.sh`: static musl ocserv 1.3.0 + occtl, from source
  (autotools, NOT meson). RADIUS via Alpine `libradcli.a`; only GnuTLS is
  source-built static (`--with-included-libtasn1/unistring --without-p11-kit`).
- Gotchas solved in the recipe: readline static link needs `LIBS="-Wl,--start-group
  -lreadline -lncurses -Wl,--end-group"`; gnutls needs `libidn2-static
  libunistring-static`; static `libseccomp.a` gperf `in_word_set` clash →
  `--disable-seccomp`.
- Wired into `build/backend/build.sh` (docker run, alpine:3.22). Output
  `backend/bin/<arch>/ocserv` — NOT committed (`.gitignore` excludes `backend/bin/*`).
- VERIFIED: static ELF, `Compiled with: radius, PKCS#11, AnyConnect`; runs, binds
  TCP+UDP (DTLS) same port. Local build host: docker daemon down → use **podman**
  (`podman run --platform linux/amd64 -v vol:/usr/local -v out:/out ...`).

### Phase 1 — Addressing (DONE, commit d3f837f6)
- `database/model/model.go`: `OPENCONNECT = "openconnect"`.
- `web/service/vpnrange.go`: `protocolBase("openconnect")=4`; generalized
  `allocateAlignedBlock`/`normalizeBlockRanges(base, mirrorBase)` (openvpn now a
  base-2/mirror-3 wrapper, byte-identical); openconnect dispatch (base 4, no mirror);
  added to `usedVpnSubnets` IN-list; localIp sync skips openconnect.
- `web/service/nftables.go`: `vpnAddrSpace` **/14 → /13** (10.4 was outside the /14 →
  would break firewalld trust + Xray blackhole backstop → Fedora "no internet").
- Test `TestNormalizeBlockRangesOpenconnect`.

### Phase 2 backend — Service + wiring (DONE, commit 9a134180)
- `web/service/openconnect.go` (new): procMgr child `ocserv-server-{id}`, configDir
  `/etc/ocserv/server-{id}`, `GetTproxyPort`=12300+id, `GetDokodemoConfig`. Generates
  `ocserv.conf` (`auth=radius`+`acct=radius` native, `max-same-clients=K`,
  `use-occtl`+`occtl-socket-file`, `ipv4-network` from `vpnBlock(base 4)`,
  `isolate-workers=false`, `route=default` full-tunnel, `cisco-client-compat`,
  `dtls-legacy`) + per-inbound `radiusclient.conf` (radcli uses `nas-identifier`
  hyphen, `openconnect-{id}`) + reused `generateRadiusDictionary`. TLS path|content|
  self-signed. `GenerateSelfSignedCert` (ECDSA P-384). `KillClient`/`KillDisabled
  Sessions`/`DisableClients` via `occtl -s <sock> disconnect user`.
- Wiring: `backend/backend.go` (ocserv+occtl in Daemons); `web/service/xray.go`
  (dokodemo inject + native skip); `web/service/nftables.go` (`openconnect_acct`
  chain, cross-inbound gather, TPROXY block, `ocservCIDRs`, `CollectAndResetTraffic`
  gains 4th proto); `web/service/core.go` (`ocservStatus`, restart/stop/logs/dokodemo/
  Init); `web/service/inbound.go` (`isVpnProtocol` + openconnect); `web/web.go`
  (SetRadius + InitOcserv); `web/controller/inbound.go` (`onOcservChanged` + every
  dispatch site + `generate-ocserv-cert` route); `web/job/xray_traffic_job.go`
  (SetRadius + GetSessions("openconnect") + collect + KillDisabledSessions).
- VERIFIED: the generated `ocserv.conf` parses in the real static ocserv, binds
  TCP+UDP, RADIUS active for auth AND accounting.

### Phase 2 frontend — UI (DONE, commit 613129b2)
- `web/assets/js/model/inbound.js`: `Protocols.OPENCONNECT` + `OcservSettings` /
  `OcservUser`; wired into newSettings/fromJson/getClients.
- `web/html/form/protocol/openconnect.html` (new): stripped openvpn form (no
  ciphers, no udp/tcp, no .ovpn); TLS path|content|self-signed + connection info.
  Registered in `web/html/form/inbound.html`.
- `web/html/modals/inbound_modal.html`: `generateOcservCert` + `ocservSetDefaultCert`.
- `web/html/inbounds.html`: openconnect in VPN client groupings / password match /
  field / setup-required guard.
- `web/html/core.html`: OpenConnect label + icon.
- `web/translation/translate.en_US.toml`: setupRequired / rebootImpact mention.

### Phase 3 — RADIUS server-side (DONE, commit 91df7ba7)
`web/service/radius.go` + `openconnect.go`: parseNASIdentifier whitelists
openconnect(+`-{id}`); getClientIP already routed non-openvpn through the Framed-IP
block allocator (openconnect works for free, K==1 and K>=2); allocateBlockIP accept-
eviction → `killOcservByIP` (occtl show users → match IPv4 → disconnect id) instead
of killPPPByIP; isIPActive openconnect → `ip route get` contains "ocserv";
BuildVpnEmailToIPMap ppp query now includes openconnect. NAS-Port gotcha: ocserv
drops it, device key degrades to Calling-Station-Id (2-behind-one-NAT known edge).
occtl JSON field names (ID/IPv4) UNVERIFIED — confirm live in Phase 7.

## TODO (Phase 6 E2E + Phase 7 live)
BLOCKER for both: build `backend/bin/amd64/ocserv` first (`build/backend/build.sh
amd64`) and stage into `test_unit/test_subject/`; until then daemonInstalled=false.

### Phase 3 — DONE (details above)
Original notes kept for reference:
Edit `web/service/radius.go` (verify line numbers, they drift):
1. `parseNASIdentifier` (~:604, ~:614): accept `"openconnect"` and `"openconnect-N"`
   (add to the whitelist).
2. `getClientIP` (~:660, branch ~:715 `protocol != "openvpn"`): ensure openconnect
   returns `Framed-IP-Address` by client index (K==1 → `computeVpnClientIP`; K>=2 →
   `vpnAccountDeviceIPs` + block alloc). NOTE eviction path `killPPPByIP` is pppd-only
   and no-ops on ocserv tun — for accept-strategy use `occtl disconnect id` instead
   (OcservService.KillClient exists; may need a device-specific evict).
3. `BuildVpnEmailToIPMap` (~:945): add an openconnect section (email→[]IP over the
   10.4 block, single transport — mirror the l2tp/pptp block, not openvpn's dual).
4. `isIPActive` (~:578): add an ocserv case (its tun is `ocserv-{id}`, not `pppN`);
   or check `occtl show users`.
5. `findClientInbound` / `lookupEmail` / `lookupClient`: make sure they query
   `openconnect` inbounds (they load by NAS-Id-derived protocol; whitelist gates it).
6. **NAS-Port gotcha**: ocserv >=1.0 stopped sending NAS-Port, so the User-Limit
   device key `proto:inbound:idx:Calling-Station-Id:NAS-Port` (~:772) collapses for
   K>1. Key openconnect on Acct-Session-Id (or Calling-Station-Id) instead.
Phase 2 already provides: `max-same-clients=K` (native cap), `acct=radius` (native
accounting), occtl KillClient. So reject-strategy may already work via Access-Reject
+ native cap; accept-evict needs the occtl device eviction.

### Phase 6 — E2E test (test_unit/)
- `model.py`: `PHASE_OPENCONNECT` + ALL_PHASES. `orchestrator.py:239`: proto loop +
  `need_clients`. `server_setup.py`: openconnect inbound builder (base 4, no mirror).
  `clients/base.py:17`: `openconnect` in CLIENT_PKGS_APT. New
  `clients/openconnect.py` (`openconnect --protocol=anyconnect --passwd-on-stdin
  --no-cert-check --background`, tun0, `--no-dtls`=TLS variant). `protocols.py`:
  PEER/PHASE/_connect/_disconnect/_variants. tun already in EXPECTED_MODULES.
  Must-pass all distros (bundled). `test_subject/` currently empty — build+stage
  binary first. Per memory `no-auto-e2e`: never run incus E2E unless user asks.

### Phase 7 — Live verify (box in memory `vpn-ui-live-test-box`)
Real openconnect client connects → 10.4.{id} block → egress via Xray → Framed-IP
pin by index → K-limit reject+evict → accounting. Delete test inbound after.

## Build / test commands
- Backend build: `CGO_ENABLED=1 go build -o vpn-ui main.go`
- Tests: `CGO_ENABLED=1 go test ./web/... -count=1`
- Daemon bundle (needs docker/podman): `build/backend/build.sh amd64` (or run
  `build/backend/ocserv-bundle.sh` in alpine:3.22 with `-v vol:/usr/local -v out:/out`).
- All 5 commits so far are build + vet + web/service + i18n-parity green.
