"""Shared client driver for the Xray-NATIVE proxy protocols (anytls / tuic / naive).

These three are not tunnels at the wire level: the panel writes them straight into
the xray config as inbounds, xray terminates the connection itself, matches the
account (`session.Inbound.User.Email`) and dispatches. There is no ppp0/tun0 and no
server-assigned address. To make them run the SAME shared check suite as the tunnel
protocols, this driver builds a client-side tunnel (the exact trick clients/ssh.py
uses), with the `ssh -D` half swapped for xray:

  1. `xray run -c /etc/xray-<proto>-client.json` on the CLIENT VM: a socks inbound on
     127.0.0.1:<port> whose default outbound is the anytls/tuic/naive client. So the
     client of the protocol under test IS xray, the same build that serves it (see
     `ensure_core`), which is the only way to be sure the two ends agree.
  2. `badvpn-tun2socks` on a `tun0` device -> pushes ALL of the VM's traffic into that
     socks proxy. TCP natively; UDP via `--socks5-udp` (SOCKS5 UDP ASSOCIATE against
     the local xray, which then carries the datagram over the protocol's own UDP
     path). NOT udpgw: udpgw needs a udpgw server at the far end, which the SSH relay
     provides in-process and xray does not.
  3. split-default routes (0.0.0.0/1 + 128.0.0.0/1) via tun0, with the server /32
     pinned off-tunnel (via the original gateway) so the proxy's own connection does
     not loop. DNS is pointed at the pushed resolver on tun0 (apply_tunnel_dns), so
     name lookups traverse the UDP path and dns-leak is testable.

The interface is named `tun0` on purpose: checks.tunnel_egress and checks.dns_leak
already accept tun0, so no change to checks.py.

UDP: deliberately left to each protocol's own machinery rather than papered over.
tuic has native UDP (both carriers, see clients/tuic.py); anytls has NO UDP transport
and tunnels UoT inside the TLS stream, so its UDP path is a real test of that
interception; naive is HTTP CONNECT and proxies NO UDP at all, so clients/naive.py is
the one spec that sets `dns_over_proxy` (an xray `dns` outbound answering UDP:53
locally from an internal resolver that queries over TCP THROUGH the proxy). That is
what a real naive client must do, and it keeps DNS inside the tunnel instead of
leaking it to make the suite green.

RETURNED tunnel_ip: the tun device's own client-side address, made distinct per client
VM (10.<proto base>.<A|B|C=0|1|2>.2). The panel assigns no address, so this is purely
a client-side label; the per-client ROUTING test is the real per-account proof (xray
routes by the account email carried on the session, so A egresses `direct` and B is
blackholed with no source IP involved at all).

`ok` is True once the local xray is running, its socks port is listening AND tun0 is
up. Deliberately NOT gated on internet, because the blackhole-routed account B must
come up as a working tunnel yet reach nothing (that contrast is what checks.routing
reads). NOTE the difference from ssh.py: `ssh -D` dies on a refused password, so its
`ok` also proved authentication; here the proxy session is established LAZILY on the
first dial, so a disabled / over-quota / unknown account still yields a listening
socks port. Authentication therefore shows up one step later, as "tunnel up but no
internet", which is exactly what account-termination and strategy-reject assert, and
why neither of them keys on `ok` alone.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field

from .base import Client
# Same bundled static badvpn-tun2socks the SSH relay pushes, same reason (the `badvpn`
# apt package was dropped from recent Ubuntu). Imported rather than re-derived so
# there is ONE path to keep right if test_subject/ ever moves.
from .ssh import _BADVPN_LOCAL, _BADVPN_REMOTE

# Where the client-side core lands, and where the panel keeps the one it actually
# runs (provision.REMOTE_DIR + xray.GetBinaryName()).
CORE_REMOTE = "/usr/local/bin/xray"
SERVER_CORE = "/root/vpn-ui/bin/xray-linux-amd64"
# Fallback only: the core shipped in test_subject/bin/. It is whatever was last copied
# there by hand, so it can easily PREDATE the protocol under test. Using it is
# reported loudly rather than silently.
_LOCAL_CORE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "test_subject", "bin", "xray-linux-amd64")

IFACE = "tun0"
# Distinct client-side tun subnet per client VM so simultaneous devices on ONE account
# present distinct tunnel_ip values. A->0, B->1, C->2 (see _net).
_LABEL_OCTET = {"A": 0, "B": 1, "C": 2}

# host-side cache of the core lifted off a server VM: sha256 -> local path. Jobs run in
# parallel threads and all normally share one build, so this makes it one pull total.
_CORE_CACHE: dict = {}
_CORE_LOCK = threading.Lock()


@dataclass
class Spec:
    """Everything that differs between the three protocols."""
    name: str                     # "anytls" | "tuic" | "naive"
    socks_port: int               # local socks port (distinct per protocol on purpose)
    net_base: int                 # second octet of the client-side tun subnet
    outbound: object              # fn(server_ip, port, acct, spec) -> xray outbound dict
    default_port: int             # server port when the Inbound carries none
    dns_over_proxy: bool = False  # answer UDP:53 locally via an xray `dns` outbound
    sni: str = "e2e.vpn-ui.test"  # TLS SNI; the inbound's cert is self-signed anyway
    extra: dict = field(default_factory=dict)   # per-connect knobs (e.g. tuic udp mode)

    @property
    def conf(self) -> str:
        return f"/etc/xray-{self.name}-client.json"

    @property
    def logf(self) -> str:
        return f"/var/log/xray-{self.name}.log"

    @property
    def pidf(self) -> str:
        return f"/run/xray-{self.name}.pid"


def tuic_uuid(email: str) -> str:
    """The UUID a TUIC account is created with, derived from its email.

    TUIC's client identity is `id` (a UUID) alongside the password, so the harness
    needs the same value on both ends. Deriving it removes the plumbing entirely: the
    inbound is built with it in server_setup and the client config re-derives it, so
    the two can never drift (a stored field would have to be threaded through
    build_second_inbound as well)."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, "tuic." + email))


def _net(spec: Spec, label: str):
    """(device_ip, gateway_ip) for this client VM's tun. device_ip is returned as the
    tunnel_ip; gateway_ip is tun2socks's virtual router address (the route next-hop)."""
    o = _LABEL_OCTET.get(label, 0)
    return f"10.{spec.net_base}.{o}.2", f"10.{spec.net_base}.{o}.1"


def _ensure_badvpn(client: Client):
    """Push the bundled static badvpn-tun2socks if absent (idempotent). Same helper as
    clients/ssh.py; a missing local binary is reported by _tools_present, not here."""
    _, out = client.sh("command -v badvpn-tun2socks >/dev/null 2>&1 && echo HAVE || echo MISSING")
    if "HAVE" in out:
        return
    if not os.path.isfile(_BADVPN_LOCAL):
        return
    try:
        client.incus.push(client.vm, _BADVPN_LOCAL, _BADVPN_REMOTE, mode="0755")
    except Exception:  # noqa: BLE001
        pass


def _sha(text: str) -> str:
    """Last 64-hex-char token in a sha256sum output ('' when there is none)."""
    for line in reversed((text or "").splitlines()):
        tok = line.strip().split(" ")[0].strip()
        if len(tok) == 64 and all(c in "0123456789abcdef" for c in tok.lower()):
            return tok.lower()
    return ""


def ensure_core(client: Client) -> tuple[bool, str]:
    """Put the SERVER's live xray core on the client VM (idempotent).

    Both ends MUST run the same build: these protocols are new, and the core the panel
    actually runs is the one embedded in the vpn-ui binary (corebundle overwrites
    bin/xray-linux-amd64 on every start), which is NOT necessarily the copy sitting in
    test_subject/bin/. Pushing that stale copy would fail with "unknown protocol" in a
    log nobody reads; lifting the server's own core makes the two agree by
    construction. Falls back to the local copy, saying so, if the pull fails."""
    srv = f"{client.incus.prefix}-srv"
    want = ""
    try:
        _, out, _ = client.incus.exec(srv, f"sha256sum {SERVER_CORE} 2>/dev/null")
        want = _sha(out)
    except Exception:  # noqa: BLE001
        pass
    _, have_out = client.sh(f"sha256sum {CORE_REMOTE} 2>/dev/null")
    have = _sha(have_out)
    if have and want and have == want:
        return True, f"client core matches the server core ({want[:12]})"

    src, note = "", ""
    if want:
        with _CORE_LOCK:
            cached = _CORE_CACHE.get(want)
            if not cached or not os.path.isfile(cached):
                dst = os.path.join(tempfile.gettempdir(), f"vpnui-e2e-xray-{want[:12]}")
                if client.incus.pull_file(srv, SERVER_CORE, dst):
                    _CORE_CACHE[want] = dst
                    cached = dst
            src = cached or ""
        note = f"lifted the server's live core ({want[:12]})"
    if not src:
        if not os.path.isfile(_LOCAL_CORE):
            return False, (f"could not read the server core at {SERVER_CORE} and no local "
                           f"fallback at {_LOCAL_CORE}")
        src = _LOCAL_CORE
        note = (f"WARNING: could not lift the server core from {srv}:{SERVER_CORE}; using the "
                f"local {_LOCAL_CORE}, which may PREDATE this protocol")
    try:
        client.incus.push(client.vm, src, CORE_REMOTE, mode="0755")
    except Exception as e:  # noqa: BLE001
        return False, f"pushing the xray core to the client failed: {e}"
    _, ver = client.sh(f"{CORE_REMOTE} version 2>&1 | head -1")
    return True, f"{note}; client core: {ver.strip()[:80]}"


def _tools_present(client: Client) -> tuple[bool, str]:
    """Both client tools must exist: the xray core (pushed by ensure_core) and
    badvpn-tun2socks (pushed by _ensure_badvpn). A missing one is a loud failure, not a
    silent skip, so a broken image or a failed core lift is obvious in the report."""
    _, out = client.sh(
        f"test -x {CORE_REMOTE} && command -v badvpn-tun2socks >/dev/null 2>&1 "
        "&& echo TOOLSOK || echo TOOLSMISSING")
    if "TOOLSOK" in out:
        return True, ""
    _, which = client.sh(f"ls -l {CORE_REMOTE} 2>&1; command -v badvpn-tun2socks; true")
    return False, ("client VM lacks the xray core and/or badvpn-tun2socks "
                   f"(pushed from test_subject/); have:\n{which}")


def _pin_tls(outbound: dict, sha256_hex: str) -> None:
    """Rewrite an outbound's TLS block from allowInsecure to certificate pinning.

    Xray REMOVED allowInsecure. Up to 2026-06-01 a config carrying it started with a
    warning; after that date infra/conf refuses it outright ("The feature allowInsecure
    has been removed and migrated to pinnedPeerCertSha256"), so the core never starts,
    the local socks port never opens, and every TLS-based driver here reports the same
    opaque "tunnel did not come up". That is a harness expiry date, not a product bug:
    the panel already strips the field from what it feeds its own core.

    Pinning is the better answer anyway. It verifies the EXACT certificate the panel
    minted for this inbound instead of accepting any, and the core sets
    InsecureSkipVerify itself when a pin is present (tls/config.go:398), so the SNI
    still does not have to match the self-signed cert's names.

    Done centrally rather than in each driver: anytls, tuic, naive and the four classic
    protocols all reach TLS through this one config builder, and a per-driver copy is
    exactly how three of them would drift apart again. With no fingerprint known the
    outbound is left as it was, so a driver serving a non-TLS inbound is untouched."""
    tls = (outbound.get("streamSettings") or {}).get("tlsSettings")
    if not isinstance(tls, dict):
        return
    if sha256_hex:
        tls.pop("allowInsecure", None)
        tls["pinnedPeerCertSha256"] = sha256_hex


def client_config(spec: Spec, server_ip: str, port: int, acct,
                  tls_sha256: str = "") -> dict:
    """The full xray CLIENT config: a local socks inbound in front of the protocol's
    own outbound. `dns_over_proxy` adds the naive-shaped DNS path (see the module
    docstring); the others leave UDP:53 to travel the protocol's real UDP path so the
    shared dns-resolve / dns-leak checks actually exercise it."""
    proxy = spec.outbound(server_ip, port, acct, spec)
    _pin_tls(proxy, tls_sha256)
    outbounds = [proxy]
    rules = []
    conf = {
        # access log off (a 100MB usage download would otherwise write a line per
        # connection); info level keeps the outbound's own dial errors, which is where
        # a rejected account or a handshake mismatch actually surfaces.
        "log": {"access": "none", "loglevel": "info"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": spec.socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
            # tun2socks dials by IP, so without sniffing the server would only ever see
            # addresses. Recovering the SNI/Host is what a real client does and what
            # makes the server-side path (its own DNS, its own routing) realistic.
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        }],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    if spec.dns_over_proxy:
        outbounds.append({"tag": "dns-out", "protocol": "dns", "settings": {}})
        # UDP:53 from tun2socks is answered by xray's own resolver. That resolver's
        # servers are `tcp://` and NOT `+local`, so its queries go through the
        # dispatcher -> the routing rules -> the (default) proxy outbound. The rule is
        # pinned to network=udp precisely so those TCP:53 queries do NOT match it and
        # loop back into dns-out.
        rules.append({"type": "field", "inboundTag": ["socks-in"],
                      "network": "udp", "port": 53, "outboundTag": "dns-out"})
        conf["dns"] = {"servers": ["tcp://1.1.1.1", "tcp://8.8.8.8"],
                       "queryStrategy": "UseIPv4"}
    return conf


def connect(client: Client, inbound, which: str, server_ip: str,
            spec: Spec) -> tuple[bool, str, str]:
    """Bring up the system tunnel for account A/B/... Returns (ok, tunnel_ip, log)."""
    acct = inbound.accounts[which]
    port = inbound.udp_port or spec.default_port
    dev_ip, gw_ip = _net(spec, client.label)
    log = []

    _ensure_badvpn(client)
    core_ok, core_note = ensure_core(client)
    log.append("== core ==\n" + core_note)
    if not core_ok:
        return False, "", "\n".join(log)
    ok, why = _tools_present(client)
    if not ok:
        return False, "", why + "\n" + "\n".join(log)

    # Clean slate: kill a prior xray/tun2socks and drop a stale tun0.
    _kill(client, spec)
    client.pin_server_route(server_ip)   # keep the proxy's own connection off-tunnel

    conf = client_config(spec, server_ip, port, acct,
                         tls_sha256=getattr(inbound, "tls_sha256", ""))
    client.push(json.dumps(conf, indent=2), spec.conf)

    # 1. config preflight. `xray run -test` parses and BUILDS the config without
    #    listening, so an outbound this core does not know (a stale client core, or a
    #    settings shape the conf parser rejects) fails HERE with the core's own error
    #    message, instead of silently coming up as a socks proxy that can never dial.
    _, tout = client.sh(f"{CORE_REMOTE} run -test -c {spec.conf} 2>&1")
    if "Configuration OK" not in tout:
        return False, "", (f"the client xray core rejected the {spec.name} outbound config:\n"
                           f"{tout.strip()[-800:]}\n" + "\n".join(log))

    # 2. run it. setsid + `&` so it survives the incus-exec shell exiting: `incus.exec`
    #    is a blocking call whose process group is reaped when it returns, and nohup
    #    (SIGHUP only) is NOT enough to save a backgrounded child from that reap (the
    #    same trap clients/ssh.py and clients/ikev2.py document).
    client.sh(f"setsid {CORE_REMOTE} run -c {spec.conf} >{spec.logf} 2>&1 & "
              f"echo $! >{spec.pidf}; true")

    # 3. wait for the socks port to listen: proof the core started and bound. (It does
    #    NOT prove the account is valid: the proxy session is lazy; see the module
    #    docstring.)
    socks_up = False
    for _ in range(12):
        _, out = client.sh(
            f"ss -ltnH 'sport = :{spec.socks_port}' 2>/dev/null | grep -q . && echo UP || echo DOWN")
        if "UP" in out:
            socks_up = True
            break
        _, alive = client.sh(f"kill -0 $(cat {spec.pidf} 2>/dev/null) 2>/dev/null "
                             "&& echo ALIVE || echo DEAD")
        if "DEAD" in alive:
            break
        time.sleep(2)
    _, xlog = client.sh(f"tail -n 25 {spec.logf} 2>/dev/null")
    log.append(f"== xray {spec.name} client ==\n" + xlog)
    if not socks_up:
        _kill(client, spec)
        return False, "", (f"the local xray never opened its socks port {spec.socks_port} "
                           f"(core failed to start)\n" + "\n".join(log))

    # 4. tun2socks on tun0: TCP + UDP through the socks proxy. Pre-create the tun
    #    (tun2socks opens an EXISTING device) so the name is deterministic.
    client.sh(
        f"ip tuntap add dev {IFACE} mode tun 2>/dev/null; "
        f"ip addr flush dev {IFACE} 2>/dev/null; "
        f"ip addr add {dev_ip}/24 dev {IFACE}; ip link set {IFACE} up")
    client.sh(
        f"setsid badvpn-tun2socks --tundev {IFACE} --netif-ipaddr {gw_ip} "
        f"--netif-netmask 255.255.255.0 --socks-server-addr 127.0.0.1:{spec.socks_port} "
        f"--socks5-udp "
        ">/var/log/tun2socks.log 2>&1 & echo $! >/run/tun2socks.pid; true")

    # tun2socks LIVENESS, not just the interface: the tun already has its IP from the
    # pre-assign above, so wait_iface would read "up" even if tun2socks crashed. Poll
    # the process instead so that failure surfaces here with its log.
    t2s_alive = False
    for _ in range(6):
        time.sleep(1)
        _, av = client.sh("kill -0 $(cat /run/tun2socks.pid 2>/dev/null) 2>/dev/null "
                          "&& echo ALIVE || echo DEAD")
        if "ALIVE" in av:
            t2s_alive = True
            break
    _, t2log = client.sh("tail -n 25 /var/log/tun2socks.log 2>/dev/null")
    tip = client.wait_iface(IFACE, timeout=10) if t2s_alive else ""
    if not t2s_alive or not tip:
        log.append("== tun2socks ==\n" + t2log)
        _kill(client, spec)
        return False, "", (f"badvpn-tun2socks did not stay up on {IFACE} (account {which}; "
                           f"alive={t2s_alive}, iface_ip={tip!r})\n" + "\n".join(log))

    # 5. route everything except the pinned server through tun0, and point DNS at the
    #    pushed resolver on tun0. Split-default (openvpn's redirect-gateway def1 trick)
    #    leaves the physical default intact for the pinned server /32.
    client.sh(
        f"ip route replace 0.0.0.0/1 via {gw_ip} dev {IFACE}; "
        f"ip route replace 128.0.0.0/1 via {gw_ip} dev {IFACE}; true")
    client.apply_tunnel_dns(IFACE)

    # 6. warm the path for the freedom-routed account (A) so the immediate per-variant
    #    dns-resolve / dns-leak checks don't race a cold data plane. Account B is
    #    blackholed and legitimately cannot resolve, so this never gates ok.
    warm = ""
    if which == "A":
        for _ in range(8):
            _, warm = client.sh(
                "getent hosts cloudflare.com >/dev/null 2>&1 && echo WARM || echo COLD")
            if "WARM" in warm:
                break
            time.sleep(2)

    _, alive = client.sh(f"kill -0 $(cat {spec.pidf} 2>/dev/null) 2>/dev/null "
                         "&& echo ALIVE || echo DEAD")
    ok = "ALIVE" in alive
    _, rg = client.sh("ip route get 1.1.1.1 2>/dev/null | head -1")
    _, xlog2 = client.sh(f"tail -n 25 {spec.logf} 2>/dev/null")
    log.append(f"account={which} dev_ip={dev_ip} gw={gw_ip} server={server_ip}:{port} "
               f"socks=127.0.0.1:{spec.socks_port} xray_alive={ok} dns_warm={warm.strip()}\n"
               f"route get 1.1.1.1: {rg.strip()}\n== xray {spec.name} client (post) ==\n{xlog2}")
    if not ok:
        _kill(client, spec)
        return False, dev_ip, ("the local xray exited right after tun2socks came up\n"
                               + "\n".join(log))
    return True, dev_ip, "\n".join(log)


def disconnect(client: Client, spec: Spec):
    """Kill tun2socks + the local xray and drop tun0 (which also drops its
    split-default routes, restoring the physical default)."""
    _kill(client, spec)
    time.sleep(1)


def _kill(client: Client, spec: Spec):
    client.sh(
        f"kill $(cat {spec.pidf} 2>/dev/null) 2>/dev/null; "
        "kill $(cat /run/tun2socks.pid 2>/dev/null) 2>/dev/null; "
        # orphan sweep for a leftover from a crashed prior run. The [x] brackets keep
        # the `pkill -f` pattern from matching the very shell that carries it (a real
        # xray/tun2socks cmdline has no brackets, so it still matches those).
        f"pkill -f '[x]ray run -c {spec.conf}' 2>/dev/null; "
        "pkill -f '[b]advpn-tun2socks' 2>/dev/null; "
        f"ip link del {IFACE} 2>/dev/null; "
        f"rm -f /run/tun2socks.pid {spec.pidf} 2>/dev/null; true")


def core_log(client: Client, spec: Spec, lines: int = 40) -> str:
    """Tail of the client-side core log: the only place a rejected account, a TLS
    mismatch or a UDP-unsupported error is written down."""
    _, out = client.sh(f"tail -n {lines} {spec.logf} 2>/dev/null")
    return out
