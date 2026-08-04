# vpn-ui test unit

Automated end-to-end test harness for the vpn-ui panel across a matrix of Linux
distros, driven over the panel's real HTTP API and exercised with live VPN
clients. Backend: **incus VMs**, **Python**, **bash**.

## What it tests

Per server distro (own isolated incus bridge, run in parallel):

1. **core-init** — push binary, start panel, run panel-driven provisioning
   (kernel modules + packages + daemons), reboot if required, assert every step
   ok/warn, modules loaded, cores not in error.
2. **server-setup** — create one inbound each for **openvpn / l2tp / pptp**
   (2 accounts each, `clientToClient` + `crossInbound` enabled), add the
   external **outbound** (non-default, parsed from a user-supplied Xray share
   link — vless/vmess/ss/trojan) and an email-based routing rule for
   `route_domain`, then assert the panel auto-translated `user`→`source-IP`.
3. **per protocol** (openvpn, l2tp, pptp), using 2 Ubuntu-26 client VMs:
   - **connect variants**
     - openvpn: tcp & udp × new & old cipher (server `cipherMode=all`)
     - l2tp: raw & ipsec (PSK)
     - pptp: single
   - **dns-resolve** (per connect variant) — `dig +short` a domain through the
     tunnel; PASS on an A record. Proves tunnel DNS works on every
     transport/cipher, not just once.
   - **internet** through the tunnel
   - **dns leak** (public bash.ws service; fail if a local-bridge resolver leaks)
   - **xray routing** — `route_domain` exits via the external outbound while
     `control_domain` uses the default; both exit IPs read from Cloudflare's
     `/cdn-cgi/trace`, a split (routed ≠ direct) proves routing. Exit country is
     not asserted (outbound is user-supplied).
   - **client-to-client** — client A pings client B on the same inbound
   - **cross-inbound** — client A pings a client on the *peer* protocol's inbound
     (cross-inbound is an IP/inbound-level gate, so cross-protocol exercises it)
4. **awg** (AmneziaWG) - connect, dns-resolve, internet, dns-leak, xray routing,
   client-to-client and per-account usage/termination, the same shape as the
   `wg-c` phase. AmneziaWG is obfuscated WireGuard, so both ends need the
   out-of-tree `amneziawg` kernel module: the panel DKMS-builds it on the server
   during `core-init`, and this phase DKMS-builds it on the client VM as well
   (idempotent, a fast no-op once present) before it dials the tunnel.
5. **anytls / tuic / naive** - the Xray-**native** protocols. Everything above is
   served by a bundled daemon or an in-binary Go server with xray only downstream
   of it; here xray *is* the server, so account matching, per-user stats and the
   limiter all run on the core's own path. The client is xray as well: the harness
   lifts the **server's live core** onto the client VM (the panel overwrites
   `bin/xray-linux-amd64` from its embedded copy on every start, so the file in
   `test_subject/bin/` can easily predate the protocol), runs it with a local socks
   inbound plus the matching outbound, and puts `badvpn-tun2socks` on `tun0` in
   front of it, the same system-tunnel trick `clients/ssh.py` uses. So they run the
   full shared suite (connect, dns-resolve, tunnel-egress, internet, dns-leak,
   routing, multi-inbound, usage, multiplier, termination) **minus**
   client-to-client and cross-inbound, which need a client tunnel address that a
   proxy never hands out. `routing` is the sharpest per-client proof in the harness
   for these: xray puts the matched account on the session, so the panel's `user`
   rules split A (freedom) from B (blackhole) with no source-IP translation at all.
   Per protocol, UDP is where each is most likely to be quietly broken, so it is
   asserted separately:
   - **tuic** - both relay carriers (`udpRelayMode` `native` = one QUIC datagram per
     packet, `quic` = UDP over a QUIC stream), dialed separately against one inbound
   - **anytls** - has no UDP transport; UDP is wrapped in the TLS stream (UoT), and
     DNS is deliberately *not* routed around it so the check is real
   - **naive** - HTTP CONNECT, proxies no UDP at all: its UDP subtests are N/A with
     that reason, and DNS goes over TCP through the proxy (what a real naive
     deployment must do) rather than leaking to the physical route

### Routing test note
The panel auto-translates a routing rule authored by client **email**
(`user:[…]`) into a per-client **source-IP** rule (dokodemo-door carries no
per-user identity; each account gets a deterministic tunnel IP fed to Xray via
tproxy+nftables). So the rule is authored by email exactly per spec, and the
harness both asserts the translation (`getConfigJson`) and proves it live.

## Requirements

- **root** (VM launch + provisioning need it)
- a supported host package manager — **apt / dnf / yum / pacman**
- image remotes reachable (`images:`); a missing distro image is **skipped**, not fatal
- outbound internet from the host/VMs (package installs, external outbound, leak service)
- host resources for `concurrency × 3` VMs (1 server + 2 clients per job)

The backend itself — **incus** (installed + `incus admin init`) and **python3 +
requests** (the TOML config is read with the stdlib `tomllib`) — is bootstrapped
for you: on every start `run.sh` checks
it and installs/inits anything missing via `setup.sh` before running (see
[Backend setup](#backend-setup)). On a ready host this check is a no-op.

### Firewall
Each test job runs on its own managed incus bridge, which the host firewall must
let through. The harness opens each bridge in whatever firewall is active:
- **firewalld** — bridge added to the `trusted` zone (no polkit dialog: root,
  desktop agent stripped)
- **ufw** — `ufw route allow` in/out on the bridge + input for DHCP/DNS
- **plain nftables / iptables** (or no firewall) — nothing to do; incus manages
  its own bridge rules

## Backend setup

`run.sh` runs this for you; call it directly only to provision a host ahead of
time:

```bash
sudo ./setup.sh          # install + init incus, python3, deps (idempotent)
```

`setup.sh` detects the package manager (apt/dnf/yum/pacman) and installs incus
(Zabbly upstream repo fallback on older host distros like Debian 12; EPEL on RHEL-family),
python3 + pip and the python deps, starts the incus daemon, and runs
`incus admin init --minimal` if no storage pool exists. Re-running is safe.

## Usage

```bash
# place the prebuilt amd64 binary named `vpn-ui` (+ its bin/ dir) in test_subject/
sudo ./run.sh                          # full 13-distro matrix (auto-setup if needed)
sudo ./run.sh --only ubuntu-24,arch    # subset
sudo ./run.sh -c /path/to/other.toml
```

Live output: parallel jobs stream to one terminal, each line tagged with its
distro **and phase** — `04:38:29 ubuntu-24 [PPTP]  -> A connect [✓ pass] …` — so
interleaved jobs stay readable. An apt-style **progress bar** stays pinned to
the bottom row (finished/total distros + what each in-flight distro is doing);
it disappears when output isn't a TTY.

**Stopping a run** — press **Ctrl+C** once: the harness stops scheduling new
distros, in-flight jobs unwind at the next checkpoint (polling loops bail
immediately) and tear down their own VMs + bridges + firewall entries, then a
safety-net sweep removes anything left by deterministic name. A second Ctrl+C
force-sweeps everything and exits now. Either way no VMs are left behind.

Output per run: `results/<timestamp>/`
- `results.json` — machine-readable full results
- `report.html` — interactive matrix (distro × phase); click a row for the
  per-subtest drilldown with full logs
- `<distro>.log` — per-job log file (phase-tagged, ANSI-stripped)

## Config (`config.toml`)

| key | meaning |
|-----|---------|
| `binary` | path to prebuilt vpn-ui panel binary (amd64, static, embedded daemons); default `test_subject/vpn-ui`, pushed with its sibling `bin/` dir |
| `concurrency` | how many distros to test at once (each = 3 VMs on its own bridge) |
| `panel.*` | port / creds / base_path / scheme (defaults match the binary) |
| `vless_outbound.link` | external outbound as an Xray share link (vless/vmess/ss/trojan); `OUTBOUND_LINK` in run.sh overrides it |
| `vless_outbound.tag` | tag forced onto the parsed outbound (routing rule references it) |
| `vless_outbound.route_domain` / `.control_domain` | routed-vs-direct domains for the trace split |
| `dns_resolve.domain` | domain `dig +short`'d through the tunnel per connect variant |
| `servers[]` | distro matrix; set `enabled:false` or use `--only` to trim |
| `keep_failed_vms` | keep a failed job's VMs for post-mortem instead of deleting |

**Outbound link** — set once at the top of `run.sh` (`OUTBOUND_LINK="vless://…"`)
or leave empty to use `vless_outbound.link` in `config.toml`. Any Xray share
link works: `vless://` `vmess://` `ss://` `trojan://`, over tcp/ws/grpc/h2 with
none/tls/reality. Parsed by `harness/xraylink.py`.

## Layout

```
run.sh                     root entrypoint (auto-bootstraps backend, then runs)
setup.sh                   host backend installer (apt/dnf/yum/pacman + incus init)
config.toml                everything tunable
test_subject/              the vpn-ui binary under test + its bin/ (xray + geo)
  vpn-ui                   prebuilt panel binary (amd64, static, embedded daemons)
  bin/                     xray core + geo*.dat + config.json (pushed with binary)
harness/
  orchestrator.py          parallel job pool; per-job VM lifecycle + phase-tagged logger
  console.py               bottom-pinned apt-style progress bar + serialized log output
  abort.py                 global Ctrl+C flag; polling loops + phase boundaries check it
  incus.py                 incus CLI wrapper (net + VM, exec/push)
  panel.py                 panel HTTP client (form-encoded, cookie session)
  provision.py             core-init phase
  server_setup.py          inbounds + accounts + outbound + routing
  protocols.py             per-protocol test driver (+ per-variant dns-resolve)
  checks.py                dns-resolve / internet / dns-leak / xray-route / peer-ping
  xraylink.py              parse vless/vmess/ss/trojan share link -> Xray outbound
  probes.py                one-time preflight (external outbound reachability)
  clients/{base,openvpn,l2tp,pptp,openconnect,sstp,ikev2,wgc,awg,mtproto,ssh}.py
                           client VM tooling + connect scripts
  clients/xraytun.py       shared system tunnel for the Xray-native protocols (lifts
                           the server's core to the client, socks + tun2socks on tun0)
  clients/{anytls,tuic,naive}.py
                           their per-protocol outbound + UDP behaviour
  model.py                 result model (JobResult/Phase/SubTest/Status)
report/report.py           results.json + self-contained report.html
```

## Status semantics
`pass` · `fail` (product issue) · `error` (harness/infra) · `skip` (prereq
failed / not run) · `na` (external dependency unavailable, e.g. VLESS down).
A distro is "fully passed" only when every phase is pass.

## Known client-side caveats (tune on real hardware)
- **l2tp/ipsec** uses strongswan's legacy `ipsec.conf` starter
  (`strongswan-starter`). If a future Ubuntu client drops it, the `connect-ipsec`
  subtest fails while `connect-raw` still validates L2TP.
- Package names in `clients/base.py::CLIENT_PKGS_APT` may drift across Ubuntu
  releases; install is best-effort per-package and only hard-fails if `openvpn`
  is missing.
